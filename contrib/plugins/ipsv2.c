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


/**
    IPC datastructure
*/
typedef struct {
    uint64_t total_insn;
    uint64_t elapesd_time;
} vCPUTime;

struct qemu_plugin_scoreboard* cpu_time;
#define USEC_IN_ONE_SEC (1000 * 1000)


static void plugin_init(void)
{
    cpu_time = qemu_plugin_scoreboard_new(sizeof(vCPUTime));
}


/********************  Plugin lifecycle callbacks  ********************/
static void plugin_exit(qemu_plugin_id_t id, void* userdata) 
{ 
   

    vCPUTime *local_cpu_time = qemu_plugin_scoreboard_find(cpu_time, 0);

    uint64_t time_secs = (g_get_real_time() - local_cpu_time->elapesd_time) / USEC_IN_ONE_SEC;
    char* output = g_strdup_printf("elapsed_time %" PRIdPTR ", total instruction %" PRIdPTR ", ips:%f", time_secs, local_cpu_time->total_insn,  (local_cpu_time->total_insn) * 1.0 / time_secs);
    qemu_plugin_outs(output);
    qemu_plugin_outs("\n");
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) 
{
    vCPUTime* local_cpu_time = qemu_plugin_scoreboard_find(cpu_time, vcpu_index);
    local_cpu_time->elapesd_time = g_get_real_time();
    local_cpu_time->total_insn = 0;
}


/********************  TB translation callback  ********************/
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb* tb)
{
	size_t n_insns = qemu_plugin_tb_n_insns(tb);
    qemu_plugin_u64 total_insn = qemu_plugin_scoreboard_u64_in_struct(cpu_time, vCPUTime, total_insn);
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(tb, QEMU_PLUGIN_INLINE_ADD_U64, total_insn, n_insns);

}


// shared by all cpus
/********************  Plugin install  ********************/
QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t* info, int argc, char** argv)
{

	plugin_init();
	// initialize the variable that is local to each thread(cpu)
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

	return 0;
}
