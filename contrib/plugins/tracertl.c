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

typedef struct VCPUState {
	uint64_t last_pc; // 上一条指令PC
	TraceInstruction* current; // 当前正在处理的记录
} VCPUState;

typedef struct {
	GArray* vcpu_states; // 每个vCPU的状态数组
	GRWLock state_lock; // 状态访问锁
	FILE* output_file; // 输出文件
	GMutex output_lock; // 输出锁
	uint64_t trace_count; // 总跟踪数量
} GlobalState;

// Global variables
static const char* outfile = "tracefile.zst";
static uint64_t max_inst = 500;
static FILE* out_fp = NULL;
static ZSTD_CCtx* cctx = NULL;
static uint64_t n_traced = 0;

// locks for thread safety
static GMutex trace_buffer_lock;

static void plugin_init(void) { return; }

/********************  Memory callback  ********************/
static void mem_cb(unsigned int vcpu, qemu_plugin_meminfo_t info, uint64_t vaddr, void* userdata) {
}

/********************  Instruction execution callback  ********************/
static void insn_exec_cb(unsigned int vcpu, void* userdata) { }

/********************  TB translation callback  ********************/
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb* tb)
{
	size_t n_insns = qemu_plugin_tb_n_insns(tb);

	for (size_t i = 0; i < n_insns; i++) {
		struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);

		// TODO leave for later
		TraceInstruction* rec = NULL;

		// Get instruction bytes
		qemu_plugin_insn_data(insn, &rec->instr, sizeof(rec->instr));

		// Register memory callback for load/store instructions
		qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec_cb, QEMU_PLUGIN_CB_NO_REGS, rec);
		qemu_plugin_register_vcpu_mem_cb(
			insn, mem_cb, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, rec);
	}
}

/********************  Plugin lifecycle callbacks  ********************/
static void exit_cb(qemu_plugin_id_t id, void* userdata) { }

/********************  Plugin install  ********************/
QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t* info, int argc, char** argv)
{

	for (int i = 0; i < argc; i++) {
		char* opt = argv[i];
		// g_auto means automatic cleanup for declared type, like RALL in c++
		g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
		if (g_strcmp0(tokens[0], "traceinst") == 0) {
			max_inst = g_ascii_strtoull(tokens[1], NULL, 10);
			if (max_inst == 0) {
				fprintf(stderr, "Invalid traceinst value: %s\n", opt);
			}
		} else {
			fprintf(stderr, "Invalid option: %s\n", opt);
		}
	}

	plugin_init();

	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
	qemu_plugin_register_atexit_cb(id, exit_cb, NULL);

	return 0;
}

/********************  Plugin uninstall  ********************/
QEMU_PLUGIN_API
void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
	exit_cb(id, NULL);
	if (cb) {
		cb(id);
	}
}
