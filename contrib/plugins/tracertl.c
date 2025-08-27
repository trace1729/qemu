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
#include <sys/types.h>
#include <zstd.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

// Global variables
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
// static const char* outfile = "tracefile.zst";
static uint64_t max_inst = 500; // default max instructions to trace

/*
 * CONTROL FLOW */
/* We use this to track the current execution state */
typedef struct {
	/* address of current translated block */
	uint64_t tb_pc;
	/* address of end of block */
	uint64_t end_block;
	/* next pc after end of block */
	uint64_t pc_after_block;
	/* address of last executed PC */
	uint64_t last_pc;
} VCPUScoreBoard;
// 用来跟踪当前 cpu 的运行状态

static qemu_plugin_u64 tb_pc;
static qemu_plugin_u64 end_block;
static qemu_plugin_u64 pc_after_block;
static qemu_plugin_u64 last_pc;
// handle for Scoreboard

struct qemu_plugin_scoreboard* state; // handle for manipulating the socreboard

/*
 * instruction meta_data */
typedef struct CPU {
	/* Store last executed instruction on each vCPU as a GString */
	TraceInstruction last_inst;
    bool valid;
} CPU;

// 该数组保存了每一个cpu的运行状态
static GArray* cpus;
// 保护 cpus 数组读写的 线程安全
static GRWLock expand_array_lock;


/**
    IPC datastructure
*/
typedef struct {
    uint64_t total_insn;
    uint64_t elapesd_time;
} vCPUTime;

struct qemu_plugin_scoreboard* cpu_time;
#define USEC_IN_ONE_SEC (1000 * 1000)


static CPU* get_cpu(int cpu_index)
{
	CPU* c;
	g_rw_lock_reader_lock(&expand_array_lock);
	c = &g_array_index(cpus, CPU, cpu_index);
	g_rw_lock_reader_unlock(&expand_array_lock);

	return c;
}

static void plugin_init(void)
{
	state = qemu_plugin_scoreboard_new(sizeof(VCPUScoreBoard));
    cpu_time = qemu_plugin_scoreboard_new(sizeof(vCPUTime));

	/* score board declarations */
	tb_pc = qemu_plugin_scoreboard_u64_in_struct(state, VCPUScoreBoard, tb_pc);
	end_block = qemu_plugin_scoreboard_u64_in_struct(state, VCPUScoreBoard, end_block);
	pc_after_block = qemu_plugin_scoreboard_u64_in_struct(state, VCPUScoreBoard, pc_after_block);
	last_pc = qemu_plugin_scoreboard_u64_in_struct(state, VCPUScoreBoard, last_pc);
	return;
}


/********************  Plugin lifecycle callbacks  ********************/
static void plugin_exit(qemu_plugin_id_t id, void* userdata) { 
    guint i;
    g_rw_lock_reader_lock(&expand_array_lock);
    for (i = 0; i < cpus->len; i++) {
        CPU *c = get_cpu(i);
        char* output = g_strdup_printf("0x%" PRIx64 ", 0x%" PRIx32 ", 0x%" PRIx64 ", 0x%" PRIx64,
        c->last_inst.instr_pc_va, c->last_inst.instr, c->last_inst.exu_data.memory_address,
        c->last_inst.target);
        qemu_plugin_outs(output);
        qemu_plugin_outs("\n");

        vCPUTime *local_cpu_time = qemu_plugin_scoreboard_find(cpu_time, i);

        uint64_t time_secs = (g_get_real_time() - local_cpu_time->elapesd_time) / USEC_IN_ONE_SEC;
        output = g_strdup_printf("elapsed_time %" PRIdPTR ", total instruction %" PRIdPTR ", ips:%f", time_secs, local_cpu_time->total_insn,  (local_cpu_time->total_insn) * 1.0 / time_secs);

        qemu_plugin_outs(output);
        qemu_plugin_outs("\n");
     
    }
    g_rw_lock_reader_unlock(&expand_array_lock);
}


static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
	CPU* c;
    
    qemu_plugin_outs("vcpu_init================");

	g_rw_lock_writer_lock(&expand_array_lock);
	// If the current cpu index is larger than the size of cpus array, expand it
	if (vcpu_index >= cpus->len) {
		g_array_set_size(cpus, vcpu_index + 1);
	}
	g_rw_lock_writer_unlock(&expand_array_lock);

	c = get_cpu(vcpu_index);
	c->last_inst = (TraceInstruction) { 0 };
    c-> valid = false;

    vCPUTime * local_cpu_time = qemu_plugin_scoreboard_find(cpu_time, vcpu_index);
    local_cpu_time->elapesd_time = g_get_real_time();
    uint64_t start_time = local_cpu_time->elapesd_time / USEC_IN_ONE_SEC;
    char* output = g_strdup_printf("elapsed_time %" PRIdPTR ", total instruction %" PRIdPTR, start_time, local_cpu_time->total_insn);

    qemu_plugin_outs(output);
    qemu_plugin_outs("\n");

}



/********************  Memory callback  ********************/
static void vcpu_mem(unsigned int vcpu, qemu_plugin_meminfo_t info, uint64_t vaddr, void* userdata)
{
	CPU* c = get_cpu(vcpu);
	if (qemu_plugin_mem_is_store(info)) {
		c->last_inst.memory_type = 1; // store
	} else {
		c->last_inst.memory_type = 0; // load
	}
	c->last_inst.memory_size = qemu_plugin_mem_size_shift(info);
	c->last_inst.exu_data.memory_address = vaddr;
}

/********************  Instruction execution callback  ********************/
static void vcpu_insn_exec(unsigned int vcpu, void* userdata)
{
	// using qemu_plugin_outs to print last_inst, and initialize a new last_inst
	CPU* c = get_cpu(vcpu);
    // if (c->valid) {
    //     char* output = g_strdup_printf("0x%" PRIx64 ", 0x%" PRIx32 ", 0x%" PRIx64 ", 0x%" PRIx64,
	// 	c->last_inst.instr_pc_va, c->last_inst.instr, c->last_inst.exu_data.memory_address,
	// 	c->last_inst.target);
	//     qemu_plugin_outs(output);
	//     qemu_plugin_outs("\n");
    // }
	
	// reset last_inst
	TraceInstruction* data = (TraceInstruction*)userdata;
	c->last_inst = *data;
    c->valid = true;
}

static void vcpu_tb_branched_exec(unsigned int cpu_index, void* udata)
{
	// uint64_t lpc = qemu_plugin_u64_get(last_pc, cpu_index);
	// uint64_t ebpc = qemu_plugin_u64_get(end_block, cpu_index);
	uint64_t pc = qemu_plugin_u64_get(tb_pc, cpu_index);

	CPU* c = get_cpu(cpu_index);
    c->last_inst.taken = 1; // mark taken branch
	c->last_inst.target = pc;
    
	// if (lpc != ebpc) {
	// 	c->last_inst.exception = 1; // mark exception
	// } else {

	// }
}

/********************  TB translation callback  ********************/
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb* tb)
{
	uint64_t pc = qemu_plugin_tb_vaddr(tb);
	size_t insns = qemu_plugin_tb_n_insns(tb);
	struct qemu_plugin_insn* first_insn = qemu_plugin_tb_get_insn(tb, 0);
	struct qemu_plugin_insn* last_insn = qemu_plugin_tb_get_insn(tb, insns - 1);

	/*
	 * check if we are executing linearly after the last block. We can
	 * handle both early block exits and normal branches in the
	 * callback if we hit it.
	 */
    
	// update the pc for current block
	qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(tb, QEMU_PLUGIN_INLINE_STORE_U64, tb_pc, pc);
	// based on the pc_after_block and current pc to determine if there is a branch or an early exit
	qemu_plugin_register_vcpu_tb_exec_cond_cb(tb, vcpu_tb_branched_exec, QEMU_PLUGIN_CB_NO_REGS,
		QEMU_PLUGIN_COND_NE, pc_after_block, pc, NULL);

	// update the end_block and pc_after_block for the current block
	qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
		first_insn, QEMU_PLUGIN_INLINE_STORE_U64, end_block, qemu_plugin_insn_vaddr(last_insn));
	qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
		pc_after_block, qemu_plugin_insn_vaddr(last_insn) + qemu_plugin_insn_size(last_insn));

	/**
	 * After operations on block level, we can now register callbacks on instruction level
	 *
	 */
	size_t n_insns = qemu_plugin_tb_n_insns(tb);

    qemu_plugin_u64 total_insn = qemu_plugin_scoreboard_u64_in_struct(cpu_time, vCPUTime, total_insn);
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(tb, QEMU_PLUGIN_INLINE_ADD_U64, total_insn, n_insns);

    
	for (size_t i = 0; i < n_insns; i++) {
		struct qemu_plugin_insn* insn = qemu_plugin_tb_get_insn(tb, i);
		uint64_t ipc = qemu_plugin_insn_vaddr(insn);
		TraceInstruction* userdata = g_new0(TraceInstruction, 1);
		uint32_t opcode;
		qemu_plugin_insn_data(insn, &opcode, sizeof(opcode));
		userdata->instr = opcode;
		userdata->instr_pc_pa = ipc;
		userdata->instr_pc_va = ipc;
		// register instruction execution callback

		// ok all the data for the current instruction is ready
		// register memory access callback
		qemu_plugin_register_vcpu_mem_cb(
			insn, vcpu_mem, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, NULL);

		// then we pass the information by execution callback
		qemu_plugin_register_vcpu_insn_exec_cb(
			insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, userdata);

		// executed instruction (exception can happens)
		// since we do not know whether the current inst will cause exception or not
		// we register the last_pc update on every instruction
		qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
			insn, QEMU_PLUGIN_INLINE_STORE_U64, last_pc, ipc);
	}
}



// shared by all cpus
/********************  Plugin install  ********************/
QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t* info, int argc, char** argv)
{

	cpus = g_array_sized_new(
		true, true, sizeof(CPU), info->system_emulation ? info->system.max_vcpus : 1);
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

	// initialize static and global variables (visible to all threads(cpus))
	plugin_init();

	// initialize the variable that is local to each thread(cpu)
	qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    
    // vcpu_exit does not execute, probabaly because the program does not end normally
    // qemu_plugin_register_vcpu_exit_cb(id, vcpu_exit); 

    // for all vcpu
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

	return 0;
}

/********************  Plugin uninstall  ********************/
QEMU_PLUGIN_API
void qemu_plugin_uninstall(qemu_plugin_id_t id, qemu_plugin_simple_cb_t cb)
{
	plugin_exit(id, NULL);
	if (cb) {
		cb(id);
	}
}
