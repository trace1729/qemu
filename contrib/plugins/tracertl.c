// SPDX-License-Identifier: MIT
// Author: Enhanced plugin with proper TraceInstruction handling
//
// Build: gcc -shared -fPIC -o tracertl.so tracertl.c -lzstd
// Run:   -plugin ./tracertl.so,tracefile=out.zst,traceinst=100000

#include <glib.h>
#include <inttypes.h>
#include <qemu-plugin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct TraceInstruction {
  uint64_t instr_pc_va;
  uint64_t instr_pc_pa;
  union {
    uint64_t memory_address;
    struct {
      uint64_t src1;
      uint64_t src2;
    } arthi_src;
  } exu_data;
  uint64_t target;
  uint32_t instr;
  uint8_t memory_type : 4;
  uint8_t memory_size : 4;
  uint8_t branch_type;
  uint8_t taken;
  uint8_t exception;
} TraceInstruction;

// Global variables
static const char *outfile = "tracefile.zst";
static uint64_t max_inst = 500;
static FILE *out_fp = NULL;
static ZSTD_CCtx *cctx = NULL;
static uint64_t n_traced = 0;

// Trace buffer for batch processing
static TraceInstruction *trace_buffer = NULL;
static size_t trace_buffer_capacity = 0;
static size_t trace_buffer_count = 0;

// locks for thread safety
static GMutex trace_buffer_lock;

/********************  Helper functions  ********************/
static void init_trace_buffer(void) {
  if (!trace_buffer) {
    trace_buffer_capacity = 4096;
    trace_buffer = malloc(trace_buffer_capacity * sizeof(TraceInstruction));
    if (!trace_buffer) {
      fprintf(stderr, "Failed to allocate trace buffer\n");
      exit(1);
    }
    trace_buffer_count = 0;
  }
}

static void flush_trace_buffer(void) {

  printf(
      "flush error=======================================================\n");
  printf("ntraced, trace_buffer_count: %lu, %lu\n", n_traced,
         trace_buffer_count);

  if (!out_fp || !trace_buffer || trace_buffer_count == 0) {
    return;
  }

  size_t total_size = trace_buffer_count * sizeof(TraceInstruction);
  size_t max_compressed = ZSTD_compressBound(total_size);
  void *compressed_buf = malloc(max_compressed);

  if (compressed_buf && cctx) {
    size_t compressed_size = ZSTD_compressCCtx(
        cctx, compressed_buf, max_compressed, trace_buffer, total_size, 3);
    if (!ZSTD_isError(compressed_size)) {
      fwrite(compressed_buf, 1, compressed_size, out_fp);
      printf("Compressed %zu records (%zu KB -> %zu KB, %.1f%%)\n",
             trace_buffer_count, total_size / 1024, compressed_size / 1024,
             100.0 * compressed_size / total_size);
    } else {
      fprintf(stderr, "ZSTD compression failed: %s\n",
              ZSTD_getErrorName(compressed_size));
      fwrite(trace_buffer, sizeof(TraceInstruction), trace_buffer_count,
             out_fp);
    }
  } else {
    // Fallback: write uncompressed
    fwrite(trace_buffer, sizeof(TraceInstruction), trace_buffer_count, out_fp);
  }

  if (compressed_buf) {
    free(compressed_buf);
  }

  trace_buffer_count = 0;
  fflush(out_fp);
}

static void add_trace_record(const TraceInstruction *rec) {
  if (n_traced >= max_inst) {
    return;
  }

  // Expand buffer if needed
  if (trace_buffer_count >= trace_buffer_capacity) {
    trace_buffer_capacity *= 2;
    TraceInstruction *new_buffer =
        realloc(trace_buffer, trace_buffer_capacity * sizeof(TraceInstruction));
    if (!new_buffer) {
      fprintf(stderr, "Failed to expand trace buffer\n");
      return;
    }
    trace_buffer = new_buffer;
  }

  // Add record to buffer

  trace_buffer[trace_buffer_count++] = *rec;
  n_traced++;

  // Flush if buffer is getting full or we've reached the limit
  if (n_traced >= max_inst) {
    printf("n_traced %lu,  max_inst %lu flush_trace_buffer\n", n_traced,
           max_inst);
    flush_trace_buffer();
  }
}

/********************  Memory callback  ********************/
static void mem_cb(unsigned int vcpu, qemu_plugin_meminfo_t info,
                   uint64_t vaddr, void *userdata) {

  if (n_traced >= max_inst) {
    return;
  }

  TraceInstruction *rec = (TraceInstruction *)userdata;

  // Update memory information
  rec->exu_data.memory_address = vaddr;
  rec->memory_size = (1u << qemu_plugin_mem_size_shift(info));
  rec->memory_type = qemu_plugin_mem_is_store(info) ? 1 : 0;

  // Get physical address if available
  struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
  if (hwaddr) {
    rec->instr_pc_pa = qemu_plugin_hwaddr_phys_addr(hwaddr);
  }

  g_mutex_lock(&trace_buffer_lock);
  if (trace_buffer_count - 1 <= 0) {
    printf("mem_cb "
           "error=======================================================\n");
    printf("ntraced, trace_buffer_count: %lu, %lu\n", n_traced,
           trace_buffer_count);
  }
  trace_buffer[trace_buffer_count - 1] = *rec;
  g_mutex_unlock(&trace_buffer_lock);
  // add_trace_record(rec); // Pre-add to count towards max_inst
}

/********************  Instruction execution callback  ********************/
static void insn_exec_cb(unsigned int vcpu, void *userdata) {

  if (n_traced >= max_inst) {
    return;
  }

  TraceInstruction *rec = (TraceInstruction *)userdata;

  // The record was pre-populated during translation, now we can get runtime
  // info
  // check whether last instr is marked taken or not
  g_mutex_lock(&trace_buffer_lock);
  if (trace_buffer_count - 1 <= 0) {
    printf("insn_exec_cb "
           "error=======================================================\n");
  }
  // 可能会有压缩指令，x86不定长
  TraceInstruction *last_rec = &trace_buffer[trace_buffer_count - 1];
  if (last_rec->instr_pc_va + 4 == rec->instr_pc_va) {
    last_rec->taken = 0; // not taken
  } else {
    //
    last_rec->taken = 1;                 // taken
    last_rec->target = rec->instr_pc_va; // set target
  }
  add_trace_record(rec);
  g_mutex_unlock(&trace_buffer_lock);
}

/********************  TB translation callback  ********************/
static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
  size_t n_insns = qemu_plugin_tb_n_insns(tb);

  for (size_t i = 0; i < n_insns; i++) {
    struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

    // 🎯 Create a TraceInstruction record for this instruction
    g_mutex_lock(&trace_buffer_lock);
    TraceInstruction *rec = malloc(sizeof(TraceInstruction));
    if (!rec) {
      continue;
    }

    // Initialize the record
    memset(rec, 0, sizeof(TraceInstruction));
    g_mutex_unlock(&trace_buffer_lock);

    // Fill in basic information available during translation
    rec->instr_pc_va = qemu_plugin_insn_vaddr(insn);
    rec->instr_pc_pa = rec->instr_pc_va; // Fallback

    // Get instruction bytes
    qemu_plugin_insn_data(insn, &rec->instr, sizeof(rec->instr));

    // Register memory callback for load/store instructions
    qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec_cb,
                                           QEMU_PLUGIN_CB_NO_REGS, rec);
    qemu_plugin_register_vcpu_mem_cb(insn, mem_cb, QEMU_PLUGIN_CB_NO_REGS,
                                     QEMU_PLUGIN_MEM_RW, rec);
  }
}

/********************  Plugin lifecycle callbacks  ********************/
static void exit_cb(qemu_plugin_id_t id, void *userdata) {
  // Flush any remaining traces
  flush_trace_buffer();

  // Cleanup
  if (cctx) {
    ZSTD_freeCCtx(cctx);
    cctx = NULL;
  }
  if (out_fp) {
    fclose(out_fp);
    out_fp = NULL;
  }
  if (trace_buffer) {
    free(trace_buffer);
    trace_buffer = NULL;
  }

  printf("Trace collection completed: %lu instructions traced\n", n_traced);
}

/********************  Plugin install  ********************/
QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc,
                        char **argv) {
  // Parse arguments
  for (int i = 0; i < argc; i++) {
    if (strncmp(argv[i], "tracefile=", 10) == 0) {
      outfile = argv[i] + 10;
    } else if (strncmp(argv[i], "traceinst=", 10) == 0) {
      max_inst = strtoull(argv[i] + 10, NULL, 10);
    }
  }

  // Open output file
  out_fp = fopen(outfile, "wb");
  if (!out_fp) {
    fprintf(stderr, "Cannot open tracefile %s\n", outfile);
    return -1;
  }

  // Initialize compression
  cctx = ZSTD_createCCtx();
  if (!cctx) {
    fprintf(stderr, "Failed to create ZSTD context\n");
    fclose(out_fp);
    return -1;
  }

  // Initialize trace buffer
  init_trace_buffer();

  // Register callbacks
  qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
  qemu_plugin_register_atexit_cb(id, exit_cb, NULL);

  printf("Trace plugin loaded: target=%s, max_inst=%lu, output=%s\n",
         info->target_name, max_inst, outfile);

  return 0;
}

/********************  Plugin uninstall  ********************/
QEMU_PLUGIN_API
void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb) {
  exit_cb(id, NULL);
  if (cb) {
    cb(id);
  }
}
