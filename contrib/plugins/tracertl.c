/*
 * TracerTL - Cross-ISA Trace Collection Plugin
 *
 * Copyright (c) 2026 Institute of Computing Technology, CAS
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <glib.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

#include "plugin_icount_range.h"
#include "trace_format_c.h"
#include "tracertl_guest_branch.h"
#include "tracertl_pc_tag_sidecar.h"
#include "tracertl_runtime_helpers.h"
#include "trace_writer.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef enum {
    TRACERTL_MODE_COLD = 0,
    TRACERTL_MODE_RESETTING,
    TRACERTL_MODE_HOT,
} TracertlMode;

static char *output_path = NULL;
static char *sidecar_output_path = NULL;
static char *stats_output_path = NULL;
static int compression_level = 3;
static bool is_riscv_guest = false;
static bool is_riscv32_guest = false;
static bool is_x86_guest = false;
static bool is_x86_64_guest = false;
static bool is_aarch64_guest = false;
static bool is_system_emulation = false;
static qemu_plugin_id_t tracertl_plugin_id;
static bool writer_failed = false;
static PluginIcountRange trace_range;
static TracertlMode tracertl_mode = TRACERTL_MODE_HOT;
static uint64_t activation_margin = UINT64_C(20000000);
static uint64_t hot_begin;
static bool reset_requested = false;
static bool hot_begin_logged = false;
static bool range_end_logged = false;

static TraceWriter *trace_writer;
static TracertlPcTagSidecarWriter *sidecar_writer;
static uint64_t next_sidecar_pc;
static GMutex writer_lock;
static struct qemu_plugin_scoreboard *vcpu_sb;

typedef struct {
    uint64_t guest_instructions;
    uint64_t guest_executed_bytes;
    uint64_t emitting_tcg_ops;
    uint64_t trace_emitted_rv_records;
    uint64_t range_start_icount;
    uint64_t range_end_icount;
    uint64_t entry_pc;
    bool entry_from_outside;
} TracertlTraceStats;

static TracertlTraceStats trace_stats;

/* Track allocated InsnData objects so they can be freed on TB flush/exit */
static GPtrArray *insn_data_list;
static GMutex insn_data_lock;
static qemu_plugin_u64 retired_exec_count_entry;

static void tracertl_trace_stats_reset(void)
{
    memset(&trace_stats, 0, sizeof(trace_stats));
    hot_begin_logged = false;
    range_end_logged = false;
    if (trace_range.enabled) {
        trace_stats.range_start_icount = trace_range.start_icount;
        trace_stats.range_end_icount = trace_range.end_icount;
    }
}

static bool tracertl_should_start_hot_immediately(void)
{
    return !trace_range.enabled || hot_begin <= 1;
}

static bool tracertl_parse_u64_option(const char *name,
                                      const char *value,
                                      uint64_t *out)
{
    char *end = NULL;
    guint64 parsed;

    if (!value || value[0] == '\0') {
        fprintf(stderr, "tracertl: option '%s' requires a value\n", name);
        return false;
    }

    errno = 0;
    parsed = g_ascii_strtoull(value, &end, 0);
    if (errno != 0 || !end || *end != '\0') {
        fprintf(stderr, "tracertl: option '%s' expects an unsigned integer, got '%s'\n",
                name, value);
        return false;
    }

    *out = (uint64_t)parsed;
    return true;
}

static void tracertl_cleanup_global_state(void)
{
    if (insn_data_list) {
        g_ptr_array_free(insn_data_list, TRUE);
        insn_data_list = NULL;
    }
    if (vcpu_sb) {
        qemu_plugin_scoreboard_free(vcpu_sb);
        vcpu_sb = NULL;
        retired_exec_count_entry = (qemu_plugin_u64){ 0 };
    }
    g_free(output_path);
    output_path = NULL;
    g_free(sidecar_output_path);
    sidecar_output_path = NULL;
    g_free(stats_output_path);
    stats_output_path = NULL;
}

static int tracertl_prepare_output_paths(void)
{
    if (!output_path) {
        output_path = g_strdup("trace.trace.zstd");
    }
    if (!output_path) {
        return -1;
    }

    g_free(sidecar_output_path);
    sidecar_output_path = g_strdup_printf("%s.pc-tags.csv", output_path);
    g_free(stats_output_path);
    stats_output_path = g_strdup_printf("%s.stats.json", output_path);

    return sidecar_output_path && stats_output_path ? 0 : -1;
}

static int tracertl_open_writer_locked(void)
{
    if (trace_writer || sidecar_writer) {
        return 0;
    }

    trace_writer = trace_writer_open(output_path, compression_level);
    if (!trace_writer) {
        return -1;
    }

    sidecar_writer = tracertl_pc_tag_sidecar_open(sidecar_output_path);
    if (!sidecar_writer) {
        trace_writer_close(trace_writer);
        trace_writer = NULL;
        return -1;
    }

    next_sidecar_pc = 0;
    return 0;
}

static int tracertl_open_writer(void)
{
    int ret;

    g_mutex_lock(&writer_lock);
    ret = tracertl_open_writer_locked();
    g_mutex_unlock(&writer_lock);
    return ret;
}

static void
vcpu_exit_cb(qemu_plugin_id_t id, unsigned int vcpu_index);
static void
vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index);
static void
plugin_exit_cb(qemu_plugin_id_t id, void *userdata);
static void tracertl_register_cold_callbacks(qemu_plugin_id_t id);
static int tracertl_enter_hot_mode(qemu_plugin_id_t id);

static int tracertl_write_stats_file(const char *path)
{
    uint64_t trace_emitted_rv_bytes;
    double code_inflation_rate;
    FILE *fp;

    if (!path) {
        return -1;
    }

    trace_emitted_rv_bytes = trace_stats.trace_emitted_rv_records * 4;
    code_inflation_rate = trace_stats.emitting_tcg_ops == 0
        ? 0.0
        : (double)trace_stats.trace_emitted_rv_records /
          (double)trace_stats.emitting_tcg_ops;

    fp = fopen(path, "w");
    if (!fp) {
        return -1;
    }

    if (fprintf(fp,
                "{\n"
                "  \"metric_mode\": \"rv-per-emitting-tcg-op\",\n"
                "  \"guest_instructions\": %" PRIu64 ",\n"
                "  \"guest_executed_bytes\": %" PRIu64 ",\n"
                "  \"emitting_tcg_ops\": %" PRIu64 ",\n"
                "  \"trace_emitted_rv_records\": %" PRIu64 ",\n"
                "  \"trace_emitted_rv_bytes\": %" PRIu64 ",\n"
                "  \"code_inflation_rate\": %.12f,\n"
                "  \"range_guest_instructions\": %" PRIu64 ",\n"
                "  \"range_start_icount\": %" PRIu64 ",\n"
                "  \"range_end_icount\": %" PRIu64 ",\n"
                "  \"entry_from_outside\": %s,\n"
                "  \"entry_pc\": %" PRIu64 "\n"
                "}\n",
                trace_stats.guest_instructions,
                trace_stats.guest_executed_bytes,
                trace_stats.emitting_tcg_ops,
                trace_stats.trace_emitted_rv_records,
                trace_emitted_rv_bytes,
                code_inflation_rate,
                trace_stats.guest_instructions,
                trace_stats.range_start_icount,
                trace_stats.range_end_icount,
                trace_stats.entry_from_outside ? "true" : "false",
                trace_stats.entry_pc) < 0) {
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0) {
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  RISC-V opcode classification (for native guest path)              */
/* ------------------------------------------------------------------ */

#define RV_OPCODE(insn)  ((insn) & 0x7f)
#define TRACE_EXCEPTION_SYNC_TRAP 0x01
#define TRACERTL_TERMINAL_TARGET_BASE UINT64_C(0xf000000000000000)
#define TRACERTL_TERMINAL_TARGET_MASK UINT64_C(0x0ffffffffffffffc)

static bool rvc_is_mem(uint16_t insn);

static bool rv_is_load(uint32_t insn)
{
    uint32_t opc = RV_OPCODE(insn);
    return opc == 0x03    /* LOAD   (lb, lh, lw, ld, lbu, lhu, lwu) */
        || opc == 0x07;   /* LOAD-FP (flw, fld) */
}

static bool rv_is_store(uint32_t insn)
{
    uint32_t opc = RV_OPCODE(insn);
    return opc == 0x23    /* STORE  (sb, sh, sw, sd) */
        || opc == 0x27;   /* STORE-FP (fsw, fsd) */
}

static bool rv_is_amo(uint32_t insn)
{
    return RV_OPCODE(insn) == 0x2f;  /* AMO (lr, sc, amoswap, ...) */
}

static bool rv_is_branch(uint32_t insn)
{
    return RV_OPCODE(insn) == 0x63;  /* BRANCH (beq, bne, blt, bge, ...) */
}

static bool rv_is_jal(uint32_t insn)
{
    return RV_OPCODE(insn) == 0x6f;  /* JAL */
}

static bool rv_is_jalr(uint32_t insn)
{
    return RV_OPCODE(insn) == 0x67;  /* JALR */
}

static bool rv_is_mem(uint32_t insn)
{
    if ((insn & 0x3) != 0x3 && insn != 0) {
        return rvc_is_mem((uint16_t)(insn & 0xffff));
    }
    return rv_is_load(insn) || rv_is_store(insn) || rv_is_amo(insn);
}

static uint32_t tracertl_rv_memory_placeholder(uint8_t mtype, uint8_t msize)
{
    bool is_store = mtype == TRACE_MEM_TYPE_STORE;

    switch (msize) {
    case 0:
        return is_store ? 0x00000023 : 0x00000003; /* sb/lb x0, 0(x0) */
    case 1:
        return is_store ? 0x00001023 : 0x00001003; /* sh/lh x0, 0(x0) */
    case 2:
        return is_store ? 0x00002023 : 0x00002003; /* sw/lw x0, 0(x0) */
    default:
        return is_store ? 0x00003023 : 0x00003003; /* sd/ld x0, 0(x0) */
    }
}

static void tracertl_ensure_memory_opcode(struct TraceInstructionC *rec,
                                          uint8_t mtype, uint8_t msize)
{
    if (!rv_is_mem(rec->instr)) {
        rec->instr = tracertl_rv_memory_placeholder(mtype, msize);
    }
}

static bool rv_is_cflow(uint32_t insn)
{
    return rv_is_branch(insn) || rv_is_jal(insn) || rv_is_jalr(insn);
}

static size_t x86_opcode_offset(const uint8_t *bytes, size_t len)
{
    size_t off = 0;

    while (off < len) {
        switch (bytes[off]) {
        case 0x26:
        case 0x2e:
        case 0x36:
        case 0x3e:
        case 0x64:
        case 0x65:
        case 0x66:
        case 0x67:
        case 0xf0:
        case 0xf2:
        case 0xf3:
            off++;
            continue;
        default:
            if (is_x86_64_guest &&
                bytes[off] >= 0x40 && bytes[off] <= 0x4f) {
                off++;
                continue;
            }
            return off;
        }
    }

    return off;
}

static uint8_t x86_guest_branch_type(const uint8_t *bytes, size_t len)
{
    size_t off;

    if (len == 0) {
        return 0;
    }

    off = x86_opcode_offset(bytes, len);
    if (off >= len) {
        return 0;
    }

    switch (bytes[off]) {
    case 0x70 ... 0x7f: /* Jcc rel8 */
    case 0xe0:          /* LOOPNE rel8 */
    case 0xe1:          /* LOOPE rel8 */
    case 0xe2:          /* LOOP rel8 */
    case 0xe3:          /* JECXZ/JRCXZ rel8 */
        return 1;
    case 0xe8: /* CALL rel16/32 */
    case 0xe9: /* JMP rel16/32 */
    case 0xeb: /* JMP rel8 */
    case 0x9a: /* CALL ptr16:16/32 */
    case 0xea: /* JMP ptr16:16/32 */
        return 2;
    case 0xc2: /* RET imm16 */
    case 0xc3: /* RET */
    case 0xcf: /* IRET/IRETD/IRETQ */
    case 0xca: /* RETF imm16 */
    case 0xcb: /* RETF */
        return 3;
    case 0xff:
        if (off + 1 < len) {
            uint8_t reg = (bytes[off + 1] >> 3) & 0x07;

            if (reg == 2 || reg == 3 || reg == 4 || reg == 5) {
                return 3;
            }
        }
        return 0;
    case 0x0f:
        if (off + 1 < len) {
            if (bytes[off + 1] >= 0x80 && bytes[off + 1] <= 0x8f) {
                return 1;
            }
            switch (bytes[off + 1]) {
            case 0x07: /* SYSRET */
            case 0x35: /* SYSEXIT */
                return 3;
            default:
                return 0;
            }
        }
        return 0;
    default:
        return 0;
    }
}

static qemu_plugin_rv_trace_tag x86_guest_semantic_tag(const uint8_t *bytes,
                                                       size_t len)
{
    size_t off;

    if (len == 0) {
        return QEMU_PLUGIN_RV_TAG_NONE;
    }

    off = x86_opcode_offset(bytes, len);
    if (off + 1 >= len || bytes[off] != 0x0f) {
        return QEMU_PLUGIN_RV_TAG_NONE;
    }

    if (bytes[off + 1] >= 0x40 && bytes[off + 1] <= 0x4f) {
        return QEMU_PLUGIN_RV_TAG_MOVCOND;
    }

    return QEMU_PLUGIN_RV_TAG_NONE;
}

static uint8_t x86_guest_exception_code(const uint8_t *bytes, size_t len)
{
    size_t off;

    if (len == 0) {
        return 0;
    }

    off = x86_opcode_offset(bytes, len);
    if (off >= len) {
        return 0;
    }

    switch (bytes[off]) {
    case 0xcc: /* INT3 */
    case 0xcd: /* INT imm8 */
    case 0xce: /* INTO */
    case 0xf1: /* ICEBP */
        return TRACE_EXCEPTION_SYNC_TRAP;
    case 0xf4: /* HLT */
        return is_system_emulation ? 0 : TRACE_EXCEPTION_SYNC_TRAP;
    case 0x0f:
        if (off + 1 >= len) {
            return 0;
        }
        switch (bytes[off + 1]) {
        case 0x05: /* SYSCALL */
        case 0x0b: /* UD2 */
        case 0x34: /* SYSENTER */
            return TRACE_EXCEPTION_SYNC_TRAP;
        default:
            return 0;
        }
    default:
        return 0;
    }
}

static uint8_t aarch64_guest_exception_code(const uint8_t *bytes, size_t len)
{
    uint32_t insn;

    if (len < 4) {
        return 0;
    }

    insn = tracertl_guest_ldl_le_p(bytes, 4);
    if ((insn & 0xffe0001f) == 0xd4000001 || /* SVC */
        (insn & 0xffe0001f) == 0xd4000002 || /* HVC */
        (insn & 0xffe0001f) == 0xd4000003 || /* SMC */
        (insn & 0xffe0001f) == 0xd4200000 || /* BRK */
        (insn & 0xffe0001f) == 0xd4400000) { /* HLT */
        return TRACE_EXCEPTION_SYNC_TRAP;
    }

    return 0;
}

/*
 * branch_type values matching TracerTL/ChampSim convention:
 *   0 = not a branch
 *   1 = conditional branch  (BRANCH/C.BEQZ/C.BNEZ)
 *   2 = direct unconditional jump (JAL/C.J)
 *   3 = indirect jump (JALR/C.JR/C.JALR)
 */
static uint8_t rv_branch_type(uint32_t insn)
{
    /* 16-bit compressed */
    if ((insn & 0x3) != 0x3 && insn != 0) {
        uint8_t op    = insn & 0x03;
        uint8_t funct3 = (insn >> 13) & 0x07;
        if (op == 0x01) {
            if (funct3 == 0x01 && is_riscv32_guest) return 2; /* C.JAL */
            if (funct3 == 0x05) return 2; /* C.J */
            if (funct3 == 0x06 || funct3 == 0x07) return 1; /* C.BEQZ, C.BNEZ */
        }
        if (op == 0x02 && funct3 == 0x04) {
            uint8_t rs2 = (insn >> 2) & 0x1f;
            uint8_t rs1 = (insn >> 7) & 0x1f;
            if (rs2 == 0 && rs1 != 0) return 3; /* C.JR / C.JALR */
        }
        return 0;
    }
    /* 32-bit */
    if (rv_is_branch(insn)) return 1;
    if (rv_is_jal(insn))    return 2;
    if (rv_is_jalr(insn))   return 3;
    return 0;
}

/* Classify compressed (16-bit) RV-C instructions */

/*
 * rvc_is_mem: returns true for load/store RVC ops.
 *
 * op=00 (CL/CS quadrant):
 *   funct3=001  C.FLD  (FP load 64-bit)
 *   funct3=010  C.LW
 *   funct3=011  C.LD   (RV64)
 *   funct3=100  RESERVED — excluded
 *   funct3=101  C.FSD  (FP store 64-bit)
 *   funct3=110  C.SW
 *   funct3=111  C.SD   (RV64)
 *   funct3=000  C.ADDI4SPN — NOT memory
 *
 * op=10 (CI/CSS quadrant):
 *   funct3=001  C.FLDSP (FP load-SP 64-bit)
 *   funct3=010  C.LWSP
 *   funct3=011  C.LDSP  (RV64)
 *   funct3=101  C.FSDSP (FP store-SP 64-bit)
 *   funct3=110  C.SWSP
 *   funct3=111  C.SDSP  (RV64)
 */
static bool rvc_is_mem(uint16_t insn)
{
    uint8_t op    = insn & 0x03;
    uint8_t funct3 = (insn >> 13) & 0x07;
    if (op == 0x00)
        return funct3 == 0x01 || funct3 == 0x02 || funct3 == 0x03
            || funct3 == 0x05 || funct3 == 0x06 || funct3 == 0x07;
    if (op == 0x02)
        return funct3 == 0x01 || funct3 == 0x02 || funct3 == 0x03
            || funct3 == 0x05 || funct3 == 0x06 || funct3 == 0x07;
    return false;
}

/*
 * rvc_is_cflow: returns true only for actual unconditional/conditional jump ops.
 *
 * op=01 (CI quadrant):
 *   funct3=101  C.J    (unconditional jump)
 *   funct3=110  C.BEQZ
 *   funct3=111  C.BNEZ
 *
 * op=10 (CR quadrant), funct3=100:
 *   The whole funct3=100 class also contains C.MV, C.ADD, and C.EBREAK.
 *   Distinguish by rs2 and rs1 fields (bits [6:2] and [11:7]):
 *     C.JR   (bit12=0, rs2=0, rs1!=0) — indirect jump
 *     C.JALR (bit12=1, rs2=0, rs1!=0) — indirect call
 *     C.MV   (bit12=0, rs2!=0)        — register move, NOT cflow
 *     C.ADD  (bit12=1, rs2!=0)        — register add,  NOT cflow
 *     C.EBREAK (bit12=1, rs1=0, rs2=0) — exception,   NOT cflow
 */
static bool rvc_is_cflow(uint16_t insn)
{
    uint8_t op    = insn & 0x03;
    uint8_t funct3 = (insn >> 13) & 0x07;
    if (op == 0x01)
        return (is_riscv32_guest && funct3 == 0x01)
            || funct3 == 0x05 || funct3 == 0x06 || funct3 == 0x07;
    if (op == 0x02 && funct3 == 0x04) {
        uint8_t rs2 = (insn >> 2) & 0x1f;  /* bits [6:2]  */
        uint8_t rs1 = (insn >> 7) & 0x1f;  /* bits [11:7] */
        return rs2 == 0 && rs1 != 0;        /* C.JR or C.JALR only */
    }
    return false;
}

static uint8_t rvc_exception_code(uint16_t insn)
{
    uint8_t op = insn & 0x03;
    uint8_t funct3 = (insn >> 13) & 0x07;

    if (op == 0x02 && funct3 == 0x04) {
        uint8_t bit12 = (insn >> 12) & 0x01;
        uint8_t rs2 = (insn >> 2) & 0x1f;
        uint8_t rs1 = (insn >> 7) & 0x1f;

        if (bit12 == 1 && rs1 == 0 && rs2 == 0) {
            return TRACE_EXCEPTION_SYNC_TRAP;
        }
    }

    return 0;
}

static uint8_t rv_exception_code(uint32_t insn)
{
    uint32_t imm12;

    if ((insn & 0x3) != 0x3 && insn != 0) {
        return rvc_exception_code((uint16_t)(insn & 0xffff));
    }

    if (RV_OPCODE(insn) != 0x73 ||
        ((insn >> 12) & 0x7) != 0 ||
        ((insn >> 7) & 0x1f) != 0 ||
        ((insn >> 15) & 0x1f) != 0) {
        return 0;
    }

    imm12 = insn >> 20;
    if (imm12 == 0x000 || imm12 == 0x001) { /* ECALL / EBREAK */
        return TRACE_EXCEPTION_SYNC_TRAP;
    }

    return 0;
}

static int find_exception_rv_idx(const uint32_t *insns, uint16_t n_rv)
{
    uint16_t i;

    if (insns == NULL) {
        return -1;
    }

    for (i = 0; i < n_rv; i++) {
        if (rv_exception_code(insns[i]) != 0) {
            return i;
        }
    }

    return -1;
}

static uint64_t tracertl_insn_paddr(uint64_t vaddr)
{
    uint64_t pa;

    if (!is_system_emulation) {
        return vaddr;
    }

    if (qemu_plugin_translate_vaddr(vaddr, &pa)) {
        return pa;
    }

    return vaddr;
}

static uint64_t tracertl_mem_paddr(qemu_plugin_meminfo_t info, uint64_t vaddr)
{
    struct qemu_plugin_hwaddr *hwaddr;

    hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
    if (hwaddr) {
        return qemu_plugin_hwaddr_phys_addr(hwaddr);
    }

    return vaddr;
}

/* ------------------------------------------------------------------ */
/*  Per-instruction metadata                                          */
/* ------------------------------------------------------------------ */

/*
 * Translation-time summary for one guest instruction.
 * Runtime exec/mem callbacks only receive this object, so it carries the
 * emitted RV words plus enough indices to patch memory/control-flow fields.
 */
typedef struct {
    uint64_t pc;
    uint16_t size;
    uint16_t n_rv;                                /* number of emitted RV words */
    uint16_t rv_cap;
    uint16_t emitting_tcg_ops;                    /* emitting TCGOp count for this guest insn */
    int8_t   n_mem_rv;                            /* number of designated mem slots */
    int8_t   mem_rv_idxs[QEMU_PLUGIN_RV_MAX_MEM]; /* indices of ld/st records */
    int8_t   branch_rv_idx;                       /* record holding branch metadata */
    int8_t   exception_rv_idx;                    /* record holding exception metadata */
    uint8_t  branch_type_rv;                      /* branch_type for branch_rv_idx */
    uint8_t  exception_code_rv;                   /* exception code for exception_rv_idx */
    uint8_t  guest_branch_type;
    uint8_t  guest_exception_code;
    uint8_t  fallback_rv_tag;
    uint32_t fallback_rv_insn;
    uint8_t *rv_tags;
    uint32_t *rv_insns;
} InsnData;

typedef struct {
    GPtrArray *idata;
} TracertlDeferredTB;

static void insn_data_destroy(gpointer ptr)
{
    InsnData *d = ptr;

    if (!d) {
        return;
    }

    g_free(d->rv_insns);
    g_free(d->rv_tags);
    g_free(d);
}

static void insn_data_reset_trace(InsnData *d)
{
    d->n_rv = 0;
    d->n_mem_rv = 0;
    memset(d->mem_rv_idxs, -1, sizeof(d->mem_rv_idxs));
    d->branch_rv_idx = -1;
    d->exception_rv_idx = -1;
    d->branch_type_rv = 0;
    d->exception_code_rv = 0;
}

static void insn_data_reserve(InsnData *d, uint16_t n_rv)
{
    if (n_rv <= d->rv_cap) {
        return;
    }

    d->rv_insns = g_realloc_n(d->rv_insns, n_rv, sizeof(*d->rv_insns));
    d->rv_tags = g_realloc_n(d->rv_tags, n_rv, sizeof(*d->rv_tags));
    memset(d->rv_tags + d->rv_cap, 0, n_rv - d->rv_cap);
    d->rv_cap = n_rv;
}

static InsnData *insn_data_new(uint16_t n_rv)
{
    InsnData *d = g_new0(InsnData, 1);

    insn_data_reset_trace(d);
    insn_data_reserve(d, n_rv);
    d->n_rv = n_rv;

    g_mutex_lock(&insn_data_lock);
    g_ptr_array_add(insn_data_list, d);
    g_mutex_unlock(&insn_data_lock);

    return d;
}

static void tracertl_install_translated_fallback(InsnData *idata)
{
    g_assert(idata != NULL);

    if (idata->fallback_rv_insn == 0) {
        return;
    }

    insn_data_reserve(idata, 1);
    idata->n_rv = 1;
    idata->rv_insns[0] = idata->fallback_rv_insn;
    idata->rv_tags[0] = idata->fallback_rv_tag;

    if (idata->guest_branch_type != 0) {
        idata->branch_rv_idx = 0;
        idata->branch_type_rv = idata->guest_branch_type;
    }

    if (idata->guest_exception_code != 0) {
        if (rv_exception_code(idata->rv_insns[0]) == 0) {
            idata->rv_insns[0] = 0x00000073U; /* ecall */
            idata->rv_tags[0] = QEMU_PLUGIN_RV_TAG_NONE;
        }
        idata->exception_rv_idx = 0;
        idata->exception_code_rv = idata->guest_exception_code;
    }
}

static void insn_data_free_all(void)
{
    g_mutex_lock(&insn_data_lock);
    if (insn_data_list && insn_data_list->len > 0) {
        g_ptr_array_remove_range(insn_data_list, 0, insn_data_list->len);
    }
    g_mutex_unlock(&insn_data_lock);
}

static void insn_data_discard(InsnData *d)
{
    if (!d) {
        return;
    }

    g_mutex_lock(&insn_data_lock);
    if (insn_data_list) {
        g_ptr_array_remove_fast(insn_data_list, d);
    }
    g_mutex_unlock(&insn_data_lock);
}

static void vcpu_tb_flush_cb(qemu_plugin_id_t id)
{
    insn_data_free_all();
}

static TracertlDeferredTB *tracertl_deferred_tb_new(size_t n_insns)
{
    TracertlDeferredTB *deferred = g_new0(TracertlDeferredTB, 1);

    deferred->idata = g_ptr_array_sized_new(n_insns);
    return deferred;
}

static void tracertl_deferred_tb_destroy(gpointer ptr)
{
    TracertlDeferredTB *deferred = ptr;

    if (!deferred) {
        return;
    }

    for (guint i = 0; i < deferred->idata->len; i++) {
        insn_data_discard(g_ptr_array_index(deferred->idata, i));
    }
    g_ptr_array_free(deferred->idata, true);
    g_free(deferred);
}

/* ------------------------------------------------------------------ */
/*  Per-vCPU state                                                    */
/* ------------------------------------------------------------------ */

/*
 * Per-vCPU runtime state.
 * The core idea is "one pending guest instruction group": exec callback N
 * finalizes and flushes callback N-1, then installs callback N as the new
 * pending expansion. Memory callbacks patch that pending group in between.
 */
typedef struct {
    uint64_t retired_exec_count; /* 1-based count at insn exec callback time */
    uint64_t expected_next; /* sequential successor guest PC for branch resolution */
    uint16_t pending_guest_size; /* executed guest bytes for the pending group */
    uint16_t pending_emitting_tcg_ops; /* emitting TCGOp count for the pending group */

    /* Memory callback queue: each callback patches the next slot */
    uint64_t last_mem_vaddr;
    uint64_t last_mem_paddr;
    uint8_t  last_mem_type;
    uint8_t  last_mem_size;
    bool     has_mem;

    /* Pending expansion waiting for successor info before it can be flushed. */
    struct TraceInstructionC *pending_recs;
    uint8_t *pending_tags;
    int      pending_cap;
    int      n_pending;

    /* Per-record metadata for the pending expansion */
    int8_t   n_mem_slots;
    int8_t   mem_slot_idxs[QEMU_PLUGIN_RV_MAX_MEM];
    int8_t   mem_cursor;  /* next mem slot to fill */
    int8_t   branch_rec_idx;
    int8_t   exception_rec_idx;
    bool     current_insn_traced;
    bool     has_pending;
} VCPUState;

static VCPUState *get_vcpu_state(unsigned int vcpu_index)
{
    return (VCPUState *)qemu_plugin_scoreboard_find(vcpu_sb, vcpu_index);
}

static void vcpu_state_ensure_cap(VCPUState *state, int need)
{
    if (need <= state->pending_cap) {
        return;
    }
    int cap = need < 64 ? 64 : need;
    state->pending_recs = g_realloc(state->pending_recs,
                                     cap * sizeof(struct TraceInstructionC));
    state->pending_tags = g_realloc(state->pending_tags,
                                    cap * sizeof(uint8_t));
    state->pending_cap = cap;
}

static void tracertl_discard_pending_state(VCPUState *state)
{
    state->has_pending = false;
    state->current_insn_traced = false;
    state->n_pending = 0;
    state->pending_guest_size = 0;
    state->pending_emitting_tcg_ops = 0;
    state->n_mem_slots = 0;
    state->mem_cursor = 0;
    state->branch_rec_idx = -1;
    state->exception_rec_idx = -1;
    state->has_mem = false;
    state->last_mem_vaddr = 0;
    state->last_mem_paddr = 0;
    state->last_mem_type = 0;
    state->last_mem_size = 0;
}

static void tracertl_reset_runtime_state(VCPUState *state)
{
    state->expected_next = 0;
    tracertl_discard_pending_state(state);
}

/* ------------------------------------------------------------------ */
/*  Flush pending expansion                                           */
/* ------------------------------------------------------------------ */

static void apply_mem_to_slot(VCPUState *state, int slot_idx)
{
    if (slot_idx >= 0 && slot_idx < state->n_pending) {
        struct TraceInstructionC *mrec = &state->pending_recs[slot_idx];
        tracertl_ensure_memory_opcode(mrec, state->last_mem_type,
                                      state->last_mem_size);
        trace_set_memory_type_size(mrec, state->last_mem_type,
                                   state->last_mem_size);
        mrec->exu_data.memory_address.va = state->last_mem_vaddr;
        mrec->exu_data.memory_address.pa = state->last_mem_paddr;
    }
}

static int pending_mem_overflow_template_idx(const VCPUState *state)
{
    if (state->n_mem_slots > 0) {
        int slot_idx = state->mem_slot_idxs[state->n_mem_slots - 1];

        if (slot_idx >= 0 && slot_idx < state->n_pending) {
            return slot_idx;
        }
    }

    return state->n_pending > 0 ? 0 : -1;
}

static void apply_mem_to_overflow_slot(VCPUState *state,
                                       uint8_t mtype, uint8_t msize,
                                       uint64_t vaddr, uint64_t paddr)
{
    struct TraceInstructionC *rec;
    int template_idx = pending_mem_overflow_template_idx(state);
    int slot_idx;

    g_assert(template_idx >= 0);

    vcpu_state_ensure_cap(state, state->n_pending + 1);
    slot_idx = state->n_pending++;
    rec = &state->pending_recs[slot_idx];
    tracertl_init_overflow_memory_record(rec, &state->pending_recs[template_idx],
                                         mtype, msize, vaddr, paddr);
    state->pending_tags[slot_idx] = QEMU_PLUGIN_RV_TAG_NONE;
}

static void finalize_pending_branch(VCPUState *state,
                                    uint64_t actual_next_pc,
                                    uint64_t actual_next_trace_pc)
{
    uint64_t resolved_branch_target = 0;

    if (!state->has_pending) {
        return;
    }

    if (is_riscv_guest &&
        state->branch_rec_idx >= 0 &&
        state->branch_rec_idx < state->n_pending) {
        struct TraceInstructionC *branch_rec =
            &state->pending_recs[state->branch_rec_idx];

        if (branch_rec->branch_type == 1) {
            tracertl_resolve_riscv_conditional_branch_target(
                branch_rec->instr_pc_va,
                branch_rec->instr,
                &resolved_branch_target);
        }
    }

    tracertl_finalize_branch(state->pending_recs, state->n_pending,
                             state->branch_rec_idx, state->expected_next,
                             actual_next_pc, actual_next_trace_pc,
                             resolved_branch_target);
}

static void finalize_pending_exception(VCPUState *state,
                                       uint64_t actual_next_trace_pc)
{
    struct TraceInstructionC *exception_rec;

    if (!state->has_pending ||
        state->exception_rec_idx < 0 ||
        state->exception_rec_idx >= state->n_pending ||
        actual_next_trace_pc == 0) {
        return;
    }

    exception_rec = &state->pending_recs[state->exception_rec_idx];
    if (exception_rec->exception != 0 && exception_rec->target == 0) {
        exception_rec->target = actual_next_trace_pc;
    }
}

static bool pending_branch_target_unresolved(VCPUState *state)
{
    struct TraceInstructionC *branch_rec;

    if (!state->has_pending ||
        state->branch_rec_idx < 0 ||
        state->branch_rec_idx >= state->n_pending) {
        return false;
    }

    branch_rec = &state->pending_recs[state->branch_rec_idx];
    return branch_rec->branch_taken != 0 && branch_rec->target == 0;
}

static bool pending_exception_target_unresolved(VCPUState *state)
{
    struct TraceInstructionC *exception_rec;

    if (!state->has_pending ||
        state->exception_rec_idx < 0 ||
        state->exception_rec_idx >= state->n_pending) {
        return false;
    }

    exception_rec = &state->pending_recs[state->exception_rec_idx];
    return exception_rec->exception != 0 && exception_rec->target == 0;
}

static bool pending_control_target_unresolved(VCPUState *state)
{
    return pending_branch_target_unresolved(state) ||
           pending_exception_target_unresolved(state);
}

static uint64_t tracertl_terminal_unresolved_target(VCPUState *state)
{
    uint64_t site_pc;
    uint64_t seed;

    if (!state->has_pending || state->n_pending <= 0) {
        return 0;
    }

    site_pc = state->pending_recs[0].instr_pc_va;
    seed = site_pc ^ (state->expected_next << 17) ^
           ((uint64_t)(uint8_t)state->n_pending << 9);

    if (state->branch_rec_idx >= 0 && state->branch_rec_idx < state->n_pending) {
        seed ^= (uint64_t)(state->pending_recs[state->branch_rec_idx].branch_type + 1) << 2;
    }
    if (state->exception_rec_idx >= 0 &&
        state->exception_rec_idx < state->n_pending) {
        seed ^= (uint64_t)(state->pending_recs[state->exception_rec_idx].exception + 1) << 6;
    }

    seed &= TRACERTL_TERMINAL_TARGET_MASK;
    if (seed == 0) {
        seed = 4;
    }

    return TRACERTL_TERMINAL_TARGET_BASE | seed;
}

static void finalize_pending_exception_without_successor(VCPUState *state,
                                                         uint64_t terminal_target)
{
    struct TraceInstructionC *exception_rec;

    if (!pending_exception_target_unresolved(state)) {
        return;
    }

    if (terminal_target == 0) {
        return;
    }

    exception_rec = &state->pending_recs[state->exception_rec_idx];
    exception_rec->target = terminal_target;
}

static int tracertl_close_writer_locked(void)
{
    int ret;

    if (!trace_writer && !sidecar_writer) {
        return 0;
    }

    ret = 0;
    if (trace_writer) {
        if (trace_writer_close(trace_writer) < 0) {
            ret = -1;
        }
        trace_writer = NULL;
    }
    if (sidecar_writer) {
        if (tracertl_pc_tag_sidecar_close(sidecar_writer) < 0) {
            ret = -1;
        }
        sidecar_writer = NULL;
    }
    return ret;
}

static int tracertl_close_writer(void)
{
    int ret;

    g_mutex_lock(&writer_lock);
    ret = tracertl_close_writer_locked();
    g_mutex_unlock(&writer_lock);
    return ret;
}

static void tracertl_mark_writer_failed(void)
{
    int ret;

    if (writer_failed) {
        return;
    }

    writer_failed = true;
    fprintf(stderr, "tracertl: error writing trace output, disabling plugin\n");
    ret = tracertl_close_writer_locked();
    if (ret < 0) {
        fprintf(stderr, "tracertl: error closing trace output\n");
    }
    qemu_plugin_uninstall(tracertl_plugin_id, NULL);
}

static void write_pending_records(VCPUState *state)
{
    if (writer_failed) {
        tracertl_discard_pending_state(state);
        return;
    }

    if (trace_stats.entry_pc == 0 && state->n_pending > 0) {
        trace_stats.entry_pc = state->pending_recs[0].instr_pc_va;
        trace_stats.entry_from_outside =
            trace_range.enabled && trace_range.start_icount > 0;
    }

    for (int i = 0; i < state->n_pending; i++) {
        uint64_t sidecar_pc = next_sidecar_pc;

        if (trace_writer_write(trace_writer, &state->pending_recs[i]) < 0) {
            tracertl_mark_writer_failed();
            break;
        }
        if (sidecar_writer &&
            state->pending_tags[i] != QEMU_PLUGIN_RV_TAG_NONE &&
            tracertl_pc_tag_sidecar_note(sidecar_writer,
                                         sidecar_pc,
                                         (qemu_plugin_rv_trace_tag)state->pending_tags[i]) < 0) {
            tracertl_mark_writer_failed();
            break;
        }
        next_sidecar_pc += 4;
    }
    if (!writer_failed) {
        trace_stats.guest_instructions++;
        trace_stats.guest_executed_bytes += state->pending_guest_size;
        trace_stats.emitting_tcg_ops += state->pending_emitting_tcg_ops;
        trace_stats.trace_emitted_rv_records += (uint64_t)state->n_pending;
    }
    tracertl_discard_pending_state(state);
}

static void flush_pending(VCPUState *state)
{
    uint64_t terminal_target;

    if (!state->has_pending) {
        return;
    }
    /* Apply any remaining mem callback to next designated slot */
    if (state->has_mem && state->mem_cursor < state->n_mem_slots) {
        apply_mem_to_slot(state,
                          state->mem_slot_idxs[state->mem_cursor]);
        state->has_mem = false;
    }
    terminal_target = tracertl_terminal_unresolved_target(state);
    tracertl_finalize_branch_without_successor(state->pending_recs,
                                               state->n_pending,
                                               state->branch_rec_idx,
                                               state->expected_next,
                                               terminal_target);
    finalize_pending_exception_without_successor(state, terminal_target);
    write_pending_records(state);
}

/* ------------------------------------------------------------------ */
/*  Memory callback                                                   */
/* ------------------------------------------------------------------ */

static void vcpu_mem_cb(unsigned int vcpu_index,
                        qemu_plugin_meminfo_t info,
                        uint64_t vaddr, void *udata)
{
    InsnData *idata = (InsnData *)udata;
    VCPUState *state = get_vcpu_state(vcpu_index);
    uint8_t mtype = qemu_plugin_mem_is_store(info)
                    ? TRACE_MEM_TYPE_STORE : TRACE_MEM_TYPE_LOAD;
    uint8_t msize = qemu_plugin_mem_size_shift(info);
    uint64_t paddr = tracertl_mem_paddr(info, vaddr);

    if (is_riscv_guest && idata && idata->n_rv == 1) {
        mtype = tracertl_riscv_mem_type(idata->rv_insns[0], mtype);
    }

    if (!state->current_insn_traced) {
        return;
    }

    /*
     * The translation pass records which emitted RV records correspond to
     * memory operations. At runtime we either patch the next designated slot,
     * append an overflow memory record cloned from the current visible
     * expansion, or buffer one final callback for flush_pending().
     */
    if (state->has_pending &&
        state->mem_cursor < state->n_mem_slots) {
        int slot = state->mem_slot_idxs[state->mem_cursor];
        if (slot >= 0 && slot < state->n_pending) {
            struct TraceInstructionC *mrec = &state->pending_recs[slot];
            tracertl_ensure_memory_opcode(mrec, mtype, msize);
            trace_set_memory_type_size(mrec, mtype, msize);
            mrec->exu_data.memory_address.va = vaddr;
            mrec->exu_data.memory_address.pa = paddr;
        }
        state->mem_cursor++;
    } else if (state->has_pending && !is_riscv_guest) {
        apply_mem_to_overflow_slot(state, mtype, msize, vaddr, paddr);
    } else {
        /* Buffer for flush_pending fallback */
        state->last_mem_vaddr = vaddr;
        state->last_mem_paddr = paddr;
        state->last_mem_type = mtype;
        state->last_mem_size = msize;
        state->has_mem = true;
    }
}

/* ------------------------------------------------------------------ */
/*  Instruction execution callback                                    */
/*                                                                    */
/*  Mental model: delayed commit.                                     */
/*  1. The current callback gives us the successor of the previous     */
/*     pending guest instruction, so we can resolve its branch/target. */
/*  2. We flush that previous pending expansion to the writer.         */
/*  3. We turn the current instruction's RV expansion into the new     */
/*     pending group, which will be finalized by the next callback.    */
/* ------------------------------------------------------------------ */
static void vcpu_insn_exec_cb(unsigned int vcpu_index, void *udata)
{
    InsnData *idata = (InsnData *)udata;
    VCPUState *state = get_vcpu_state(vcpu_index);
    uint16_t n = idata->n_rv;
    uint64_t pc_pa = tracertl_insn_paddr(idata->pc);
    uint64_t actual_next_trace_pc = 0;
    uint64_t exec_count;
    bool current_in_range;
    bool previous_in_range;
    bool entering_range;
    bool keep_pending = false;

    state->retired_exec_count++;
    exec_count = state->retired_exec_count;
    if (trace_range.enabled &&
        !hot_begin_logged &&
        hot_begin > 0 &&
        exec_count == hot_begin) {
        hot_begin_logged = true;
        fprintf(stderr,
                "tracertl: reached hot begin at guest icount=%" PRIu64 "\n",
                exec_count);
    }
    if (trace_range.enabled &&
        !range_end_logged &&
        exec_count == trace_range.end_icount) {
        range_end_logged = true;
        fprintf(stderr,
                "tracertl: reached range end at guest icount=%" PRIu64 "\n",
                exec_count);
    }
    current_in_range = plugin_icount_range_contains_exec(&trace_range,
                                                         exec_count);
    previous_in_range = exec_count > 1 &&
        plugin_icount_range_contains_exec(&trace_range, exec_count - 1);
    entering_range = current_in_range && !previous_in_range;
    state->current_insn_traced = false;

    if (entering_range) {
        tracertl_discard_pending_state(state);
    }

    g_mutex_lock(&writer_lock);

    if (state->has_pending) {
        if (current_in_range) {
            actual_next_trace_pc = n > 0 ? idata->pc : 0;
        } else if (trace_range.enabled) {
            /*
             * Interval exit keeps the real guest successor visible to the
             * last in-range instruction even though the successor itself is
             * no longer recorded.
             */
            actual_next_trace_pc = idata->pc;
        } else {
            actual_next_trace_pc = n > 0 ? idata->pc : 0;
        }

        finalize_pending_branch(state, idata->pc,
                                actual_next_trace_pc);
        finalize_pending_exception(state, actual_next_trace_pc);

        if (current_in_range &&
            n == 0 &&
            pending_control_target_unresolved(state)) {
            keep_pending = true;
        } else {
            write_pending_records(state);
        }
    }

    g_mutex_unlock(&writer_lock);

    /* Install the current instruction's emitted RV records as the new pending
     * group. Branch, exception, and memory fields are completed later. */
    if (!current_in_range) {
        tracertl_discard_pending_state(state);
        return;
    }

    if (n == 0) {
        if (!keep_pending) {
            tracertl_discard_pending_state(state);
        }
        return;
    }

    vcpu_state_ensure_cap(state, n);
    state->n_pending = n;
    state->pending_guest_size = idata->size;
    state->pending_emitting_tcg_ops = idata->emitting_tcg_ops;
    state->branch_rec_idx = idata->branch_rv_idx;
    state->exception_rec_idx = idata->exception_rv_idx;

    /* Copy mem slot metadata */
    state->n_mem_slots = idata->n_mem_rv;
    memcpy(state->mem_slot_idxs, idata->mem_rv_idxs,
           sizeof(state->mem_slot_idxs));
    state->mem_cursor = 0;
    state->has_mem = false;

    for (uint16_t j = 0; j < n; j++) {
        struct TraceInstructionC *rec = &state->pending_recs[j];

        trace_instruction_init(rec);
        rec->instr_pc_va = idata->pc;
        rec->instr_pc_pa = pc_pa;
        rec->instr = idata->rv_insns[j];
        state->pending_tags[j] = idata->rv_tags[j];
        /* Pre-populate branch_type for the designated branch record */
        if (idata->branch_rv_idx >= 0 && j == (uint16_t)idata->branch_rv_idx) {
            rec->branch_type = idata->branch_type_rv;
        }
        if (idata->exception_rv_idx >= 0 &&
            j == (uint16_t)idata->exception_rv_idx) {
            rec->exception = idata->exception_code_rv;
        }
    }
    state->current_insn_traced = true;
    state->has_pending = true;
    state->expected_next = idata->pc + idata->size;
}

static void tracertl_fill_translated_insn(
    InsnData *idata,
    const uint32_t *rv_buf,
    const uint8_t *rv_tags,
    const int *offsets,
    const qemu_plugin_rv_insn_meta *meta,
    int total_rv,
    int n_guest,
    size_t insn_idx)
{
    int count = 0;
    uint16_t emitted_n = 0;

    insn_data_reset_trace(idata);

    if (!(rv_buf && rv_tags && offsets && meta &&
          total_rv > 0 && (int)insn_idx < n_guest)) {
        tracertl_install_translated_fallback(idata);
        return;
    }

    {
        int start = offsets[insn_idx];
        int end = ((int)insn_idx + 1 < n_guest) ? offsets[insn_idx + 1]
                                                : total_rv;

        count = end - start;
        if (count <= 0) {
            tracertl_install_translated_fallback(idata);
            return;
        }

        emitted_n = (uint16_t)count;
        insn_data_reserve(idata, emitted_n);
        memset(idata->rv_tags, 0, emitted_n);
        idata->n_rv = emitted_n;

        memcpy(idata->rv_insns, &rv_buf[start], count * sizeof(uint32_t));
        memcpy(idata->rv_tags, &rv_tags[start], count * sizeof(uint8_t));
        if (idata->fallback_rv_tag != QEMU_PLUGIN_RV_TAG_NONE) {
            bool have_tag = false;

            for (int j = 0; j < count; j++) {
                if (idata->rv_tags[j] != QEMU_PLUGIN_RV_TAG_NONE) {
                    have_tag = true;
                    break;
                }
            }
            if (!have_tag) {
                memset(idata->rv_tags, idata->fallback_rv_tag, emitted_n);
            }
        }

        idata->n_mem_rv = meta[insn_idx].n_mem;
        memcpy(idata->mem_rv_idxs, meta[insn_idx].mem_idxs,
               sizeof(idata->mem_rv_idxs));
        idata->branch_rv_idx = meta[insn_idx].branch_idx;

        if (is_x86_guest || is_aarch64_guest) {
            if (idata->guest_branch_type != 0 &&
                idata->branch_rv_idx >= 0 &&
                idata->branch_rv_idx < count) {
                idata->branch_type_rv = idata->guest_branch_type;
            } else {
                idata->branch_rv_idx = -1;
                idata->branch_type_rv = 0;
            }

            if (idata->guest_exception_code != 0) {
                idata->exception_rv_idx =
                    find_exception_rv_idx(idata->rv_insns, emitted_n);
                if (idata->exception_rv_idx < 0) {
                    idata->rv_insns[0] = 0x00000073; /* ecall */
                    idata->rv_tags[0] = QEMU_PLUGIN_RV_TAG_NONE;
                    idata->exception_rv_idx = 0;
                }
                idata->exception_code_rv = idata->guest_exception_code;
            }
        } else if (meta[insn_idx].branch_idx >= 0 &&
                   meta[insn_idx].branch_idx < count) {
            idata->branch_type_rv =
                rv_branch_type(rv_buf[start + meta[insn_idx].branch_idx]);
        }
    }
}

static void tracertl_fill_emitting_tcg_ops(
    InsnData *idata,
    const qemu_plugin_rv_insn_meta *meta,
    int n_guest,
    size_t insn_idx)
{
    if (idata == NULL) {
        return;
    }

    if (is_riscv_guest) {
        /*
         * Native RISC-V currently writes one visible trace record per final
         * guest instruction record rather than the full backend-emitted RV
         * bundle. Keep the denominator aligned with that write-side contract
         * so the native RV inflation metric remains 1.0.
         */
        idata->emitting_tcg_ops = idata->n_rv;
        return;
    }

    if (meta == NULL || (int)insn_idx >= n_guest) {
        idata->emitting_tcg_ops = 0;
        return;
    }

    idata->emitting_tcg_ops = meta[insn_idx].emitting_tcg_ops;
}

static void tracertl_tb_codegen_cb(struct qemu_plugin_tb *tb, void *udata)
{
    TracertlDeferredTB *deferred = udata;
    const uint32_t *rv_buf = NULL;
    const uint8_t *rv_tags = NULL;
    const int *offsets = NULL;
    const qemu_plugin_rv_insn_meta *meta = NULL;
    int total_rv = 0;
    int n_guest = 0;

    qemu_plugin_tb_get_rv_trace(tb, &rv_buf, &rv_tags, &offsets, &meta,
                                &total_rv, &n_guest);

    for (guint i = 0; i < deferred->idata->len; i++) {
        InsnData *idata = g_ptr_array_index(deferred->idata, i);

        tracertl_fill_emitting_tcg_ops(idata, meta, n_guest, i);
        if (!is_riscv_guest) {
            tracertl_fill_translated_insn(idata,
                                          rv_buf, rv_tags, offsets, meta,
                                          total_rv, n_guest, i);
        }
    }

    /*
     * Successful codegen leaves InsnData ownership with the exec/mem callback
     * registrations and the global flush list. Keep the destroy hook focused
     * on abandoned translations only.
     */
    g_ptr_array_set_size(deferred->idata, 0);
}

/* ------------------------------------------------------------------ */
/*  TB translation callback                                           */
/* ------------------------------------------------------------------ */

static void after_hot_reset_cb(qemu_plugin_id_t id);

static void request_hot_reset_cb(unsigned int vcpu_index G_GNUC_UNUSED,
                                 void *udata G_GNUC_UNUSED)
{
    if (tracertl_mode != TRACERTL_MODE_COLD || reset_requested) {
        return;
    }

    reset_requested = true;
    tracertl_mode = TRACERTL_MODE_RESETTING;
    qemu_plugin_reset(tracertl_plugin_id, after_hot_reset_cb);
}

static void cold_vcpu_tb_trans_cb(qemu_plugin_id_t id G_GNUC_UNUSED,
                                  struct qemu_plugin_tb *tb)
{
    size_t n_insns = qemu_plugin_tb_n_insns(tb);
    uint64_t trigger_icount;

    g_assert(trace_range.enabled);
    g_assert(hot_begin > 1);

    trigger_icount = hot_begin - 1;
    for (size_t i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
            insn, QEMU_PLUGIN_INLINE_ADD_U64, retired_exec_count_entry, 1);
        qemu_plugin_register_vcpu_insn_exec_cond_cb(
            insn, request_hot_reset_cb,
            QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_COND_EQ,
            retired_exec_count_entry, trigger_icount, NULL);
    }
}

static void hot_vcpu_tb_trans_cb(qemu_plugin_id_t id G_GNUC_UNUSED,
                                 struct qemu_plugin_tb *tb)
{
    size_t n_insns = qemu_plugin_tb_n_insns(tb);
    TracertlDeferredTB *deferred = tracertl_deferred_tb_new(n_insns);

    for (size_t i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        uint16_t insn_size = (uint16_t)qemu_plugin_insn_size(insn);

        InsnData *idata;

        if (is_riscv_guest) {
            /* Native RISC-V: use guest bytes, classify opcode */
            idata = insn_data_new(1);
            idata->pc = pc;
            idata->size = insn_size;

            uint8_t insn_bytes[4] = {0};
            size_t copy_size = insn_size < 4 ? insn_size : 4;
            qemu_plugin_insn_data(insn, insn_bytes, copy_size);

            uint32_t encoding = tracertl_guest_ldl_le_p(insn_bytes, copy_size);
            idata->rv_insns[0] = encoding;

            /* Classify for metadata attribution */
            if (insn_size >= 4) {
                /* 32-bit instruction */
                if (rv_is_mem(encoding)) {
                    idata->n_mem_rv = 1;
                    idata->mem_rv_idxs[0] = 0;
                }
                if (rv_is_cflow(encoding)) {
                    idata->branch_rv_idx = 0;
                    idata->branch_type_rv = rv_branch_type(encoding);
                }
            } else {
                /* 16-bit compressed instruction */
                uint16_t c_insn = (uint16_t)(encoding & 0xffff);
                if (rvc_is_mem(c_insn)) {
                    idata->n_mem_rv = 1;
                    idata->mem_rv_idxs[0] = 0;
                }
                if (rvc_is_cflow(c_insn)) {
                    idata->branch_rv_idx = 0;
                    idata->branch_type_rv = rv_branch_type(encoding);
                }
            }
            idata->exception_code_rv = rv_exception_code(encoding);
            if (idata->exception_code_rv != 0) {
                idata->exception_rv_idx = 0;
            }
            g_ptr_array_add(deferred->idata, idata);

        } else {
            uint8_t insn_bytes[16] = { 0 };
            size_t copy_size = MIN(sizeof(insn_bytes), (size_t)insn_size);
            bool designate_mem_slot = false;
            bool helper_backed = false;
            bool prefer_core_placeholder = false;
            uint32_t fallback_insn;
            qemu_plugin_rv_trace_tag semantic_tag = QEMU_PLUGIN_RV_TAG_NONE;

            idata = insn_data_new(0);
            idata->pc = pc;
            idata->size = insn_size;
            qemu_plugin_insn_data(insn, insn_bytes, copy_size);
            if (is_x86_guest) {
                size_t opcode_off = x86_opcode_offset(insn_bytes, copy_size);

                helper_backed = opcode_off < copy_size &&
                    insn_bytes[opcode_off] >= 0xd8 &&
                    insn_bytes[opcode_off] <= 0xdf;
                prefer_core_placeholder = opcode_off + 2 < copy_size &&
                    insn_bytes[opcode_off] == 0x0f &&
                    insn_bytes[opcode_off + 1] == 0x38 &&
                    insn_bytes[opcode_off + 2] == 0x00;
                idata->guest_branch_type =
                    x86_guest_branch_type(insn_bytes, copy_size);
                idata->guest_exception_code =
                    x86_guest_exception_code(insn_bytes, copy_size);
                semantic_tag = x86_guest_semantic_tag(insn_bytes, copy_size);
            } else if (is_aarch64_guest) {
                idata->guest_branch_type =
                    tracertl_aarch64_branch_type(insn_bytes, copy_size);
                idata->guest_exception_code =
                    aarch64_guest_exception_code(insn_bytes, copy_size);
            }

            fallback_insn = tracertl_guest_semantic_stub_insn(
                insn_bytes, copy_size, is_x86_guest, is_aarch64_guest,
                idata->guest_branch_type, idata->guest_exception_code,
                &designate_mem_slot);
            if (helper_backed &&
                semantic_tag == QEMU_PLUGIN_RV_TAG_NONE) {
                /*
                 * Helper-backed translated x87 instructions still need a
                 * visible guest-origin placeholder in the emitted trace.
                 */
                fallback_insn = 0x01e080b3U; /* add x1, x1, x30 */
                semantic_tag = QEMU_PLUGIN_RV_TAG_HELPER_PLACEHOLDER;
            }
            if (prefer_core_placeholder &&
                semantic_tag == QEMU_PLUGIN_RV_TAG_NONE) {
                fallback_insn = 0x01e080b3U; /* add x1, x1, x30 */
                semantic_tag =
                    QEMU_PLUGIN_RV_TAG_GENERIC_DEPENDENCY_PLACEHOLDER;
            }
            idata->fallback_rv_insn = fallback_insn;
            idata->fallback_rv_tag = semantic_tag;
            if (!prefer_core_placeholder &&
                idata->guest_branch_type == 0 &&
                idata->guest_exception_code == 0 &&
                !designate_mem_slot &&
                fallback_insn != 0) {
                qemu_plugin_tb_set_rv_guest_semantic_fallback(tb, i,
                                                              fallback_insn);
            }
            if (semantic_tag != QEMU_PLUGIN_RV_TAG_NONE) {
                qemu_plugin_tb_set_rv_guest_semantic_tag(tb, i, semantic_tag);
            }
            g_ptr_array_add(deferred->idata, idata);
        }

        qemu_plugin_register_vcpu_insn_exec_cb(
            insn, vcpu_insn_exec_cb,
            QEMU_PLUGIN_CB_NO_REGS, (void *)idata);

        qemu_plugin_register_vcpu_mem_cb(
            insn, vcpu_mem_cb,
            QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW,
            (void *)idata);
    }

    qemu_plugin_tb_register_codegen_cb(tb, tracertl_tb_codegen_cb,
                                       deferred,
                                       tracertl_deferred_tb_destroy);
}

static void tracertl_register_cold_callbacks(qemu_plugin_id_t id)
{
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, cold_vcpu_tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit_cb, NULL);
}

static void tracertl_register_hot_callbacks(qemu_plugin_id_t id)
{
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, hot_vcpu_tb_trans_cb);
    qemu_plugin_register_flush_cb(id, vcpu_tb_flush_cb);
    qemu_plugin_register_vcpu_exit_cb(id, vcpu_exit_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit_cb, NULL);
}

static int tracertl_enter_hot_mode(qemu_plugin_id_t id)
{
    int n_vcpus;

    tracertl_trace_stats_reset();
    if (tracertl_open_writer() < 0) {
        return -1;
    }

    if (!insn_data_list) {
        insn_data_list = g_ptr_array_new_with_free_func(insn_data_destroy);
    } else {
        insn_data_free_all();
    }

    n_vcpus = qemu_plugin_num_vcpus();
    for (int i = 0; i < n_vcpus; i++) {
        tracertl_reset_runtime_state(get_vcpu_state((unsigned int)i));
    }

    tracertl_register_hot_callbacks(id);
    reset_requested = false;
    tracertl_mode = TRACERTL_MODE_HOT;
    return 0;
}

static void after_hot_reset_cb(qemu_plugin_id_t id)
{
    if (tracertl_mode != TRACERTL_MODE_RESETTING) {
        return;
    }

    if (tracertl_enter_hot_mode(id) < 0) {
        fprintf(stderr,
                "tracertl: failed to activate hot tracing for %s\n",
                output_path ? output_path : "(null)");
        tracertl_cleanup_global_state();
        qemu_plugin_uninstall(tracertl_plugin_id, NULL);
        return;
    }

    fprintf(stderr,
            "tracertl: activated full tracing at guest icount=%" PRIu64 "\n",
            qemu_plugin_u64_sum(retired_exec_count_entry));
}

/* ------------------------------------------------------------------ */
/*  Lifecycle callbacks                                               */
/* ------------------------------------------------------------------ */

static void vcpu_exit_cb(qemu_plugin_id_t id G_GNUC_UNUSED,
                         unsigned int vcpu_index)
{
    VCPUState *state = get_vcpu_state(vcpu_index);
    g_mutex_lock(&writer_lock);
    flush_pending(state);
    g_mutex_unlock(&writer_lock);
}

static void vcpu_init_cb(qemu_plugin_id_t id G_GNUC_UNUSED,
                         unsigned int vcpu_index)
{
    VCPUState *state = get_vcpu_state(vcpu_index);

    tracertl_reset_runtime_state(state);
    if (qemu_plugin_num_vcpus() > 1) {
        int ret;

        if (!writer_failed) {
            writer_failed = true;
            fprintf(stderr,
                    "tracertl: multiple vCPU contexts are unsupported; disabling plugin\n");
            ret = tracertl_close_writer();
            if (ret < 0) {
                fprintf(stderr, "tracertl: error closing trace file\n");
            }
            qemu_plugin_uninstall(tracertl_plugin_id, NULL);
        }
    }
}

static void plugin_exit_cb(qemu_plugin_id_t id G_GNUC_UNUSED,
                           void *userdata G_GNUC_UNUSED)
{
    int ret = 0;

    if (!trace_writer && !sidecar_writer) {
        goto cleanup;
    }

    g_mutex_lock(&writer_lock);
    int n = qemu_plugin_num_vcpus();
    for (int i = 0; i < n; i++) {
        flush_pending(get_vcpu_state((unsigned int)i));
    }
    ret = tracertl_close_writer_locked();
    g_mutex_unlock(&writer_lock);

    if (writer_failed || ret < 0) {
        fprintf(stderr, "tracertl: error closing trace output\n");
    } else if (tracertl_write_stats_file(stats_output_path) < 0) {
        fprintf(stderr, "tracertl: failed to write stats file %s\n",
                stats_output_path ? stats_output_path : "(null)");
    } else {
        fprintf(stderr, "tracertl: trace written to %s (sidecar=%s, stats=%s)\n",
                output_path, sidecar_output_path, stats_output_path);
    }

cleanup:
    tracertl_cleanup_global_state();
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    PluginIcountRangeParseState range_parse_state;

    is_riscv_guest = (strstr(info->target_name, "riscv") != NULL);
    is_riscv32_guest = (strstr(info->target_name, "riscv32") != NULL);
    is_x86_64_guest = (strstr(info->target_name, "x86_64") != NULL);
    is_x86_guest = (is_x86_64_guest ||
                    strstr(info->target_name, "i386") != NULL);
    is_aarch64_guest = (strstr(info->target_name, "aarch64") != NULL);
    is_system_emulation = info->system_emulation;
    tracertl_plugin_id = id;
    writer_failed = false;
    trace_writer = NULL;
    sidecar_writer = NULL;
    next_sidecar_pc = 0;
    tracertl_mode = TRACERTL_MODE_HOT;
    activation_margin = UINT64_C(20000000);
    hot_begin = 0;
    reset_requested = false;
    plugin_icount_range_parse_state_init(&range_parse_state);
    memset(&trace_range, 0, sizeof(trace_range));

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        char *range_err = NULL;
        PluginIcountRangeParseResult range_rc;

        range_rc = plugin_icount_range_parse_option(&range_parse_state,
                                                    tokens[0], tokens[1],
                                                    &range_err);
        if (range_rc == PLUGIN_ICOUNT_RANGE_PARSE_ERROR) {
            fprintf(stderr, "tracertl: %s\n", range_err);
            g_free(range_err);
            return -1;
        }
        if (range_rc == PLUGIN_ICOUNT_RANGE_PARSE_HANDLED) {
            continue;
        }

        if (g_strcmp0(tokens[0], "output") == 0 && tokens[1]) {
            g_free(output_path);
            output_path = g_strdup(tokens[1]);
        } else if (g_strcmp0(tokens[0], "level") == 0 && tokens[1]) {
            compression_level = atoi(tokens[1]);
        } else if (g_strcmp0(tokens[0], "activation_margin") == 0) {
            if (!tracertl_parse_u64_option("activation_margin", tokens[1],
                                           &activation_margin)) {
                tracertl_cleanup_global_state();
                return -1;
            }
        } else {
            fprintf(stderr, "tracertl: unknown option '%s'\n", opt);
            tracertl_cleanup_global_state();
            return -1;
        }
    }

    {
        char *range_err = NULL;

        if (plugin_icount_range_finalize(&range_parse_state, &trace_range,
                                         &range_err) < 0) {
            fprintf(stderr, "tracertl: %s\n", range_err);
            g_free(range_err);
            tracertl_cleanup_global_state();
            return -1;
        }
    }
    tracertl_trace_stats_reset();

    if (info->system_emulation && info->system.smp_vcpus > 1) {
        fprintf(stderr,
                "tracertl: multi-vCPU system emulation is unsupported; use a single vCPU\n");
        tracertl_cleanup_global_state();
        return -1;
    }

    if (trace_range.enabled) {
        if (trace_range.start_icount <= activation_margin) {
            hot_begin = 1;
        } else {
            hot_begin = trace_range.start_icount - activation_margin;
        }
    }

    if (tracertl_prepare_output_paths() < 0) {
        fprintf(stderr, "tracertl: failed to prepare output paths for %s\n",
                output_path ? output_path : "(null)");
        tracertl_cleanup_global_state();
        return -1;
    }

    vcpu_sb = qemu_plugin_scoreboard_new(sizeof(VCPUState));
    if (!vcpu_sb) {
        fprintf(stderr, "tracertl: failed to allocate vcpu scoreboard\n");
        tracertl_cleanup_global_state();
        return -1;
    }
    retired_exec_count_entry =
        qemu_plugin_scoreboard_u64_in_struct(vcpu_sb, VCPUState,
                                             retired_exec_count);

    if (tracertl_should_start_hot_immediately()) {
        if (tracertl_enter_hot_mode(id) < 0) {
            fprintf(stderr, "tracertl: failed to open %s\n", output_path);
            tracertl_cleanup_global_state();
            return -1;
        }
    } else {
        tracertl_mode = TRACERTL_MODE_COLD;
        tracertl_register_cold_callbacks(id);
    }

    if (trace_range.enabled) {
        if (tracertl_should_start_hot_immediately()) {
            fprintf(stderr,
                    "tracertl: writing trace to %s (level=%d, guest=%s, interval=[%" PRIu64 ",%" PRIu64 "), hot_begin=%" PRIu64 ")\n",
                    output_path, compression_level,
                    is_riscv_guest ? "riscv" : info->target_name,
                    trace_range.start_icount, trace_range.end_icount,
                    hot_begin);
        } else {
            fprintf(stderr,
                    "tracertl: cold counting until hot_begin=%" PRIu64 " for %s (level=%d, guest=%s, interval=[%" PRIu64 ",%" PRIu64 "))\n",
                    hot_begin, output_path, compression_level,
                    is_riscv_guest ? "riscv" : info->target_name,
                    trace_range.start_icount, trace_range.end_icount);
        }
    } else {
        fprintf(stderr, "tracertl: writing trace to %s (level=%d, guest=%s)\n",
                output_path, compression_level,
                is_riscv_guest ? "riscv" : info->target_name);
    }
    return 0;
}
