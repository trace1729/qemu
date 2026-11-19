/*
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#ifndef QEMU_PLUGIN_H
#define QEMU_PLUGIN_H

#include "qemu/config-file.h"
#include "qemu/qemu-plugin.h"
#include "qemu/error-report.h"
#include "qemu/queue.h"
#include "qemu/option.h"
#include "qemu/plugin-event.h"
#include "qemu/bitmap.h"
#include "exec/memopidx.h"
#include "exec/translator.h"
#include "hw/core/cpu.h"

/*
 * Option parsing/processing.
 * Note that we can load an arbitrary number of plugins.
 */
struct qemu_plugin_desc;
typedef QTAILQ_HEAD(, qemu_plugin_desc) QemuPluginList;

/*
 * Construct a qemu_plugin_meminfo_t.
 */
static inline qemu_plugin_meminfo_t
make_plugin_meminfo(MemOpIdx oi, enum qemu_plugin_mem_rw rw)
{
    return oi | (rw << 16);
}

/*
 * Extract the memory operation direction from a qemu_plugin_meminfo_t.
 * Other portions may be extracted via get_memop and get_mmuidx.
 */
static inline enum qemu_plugin_mem_rw
get_plugin_meminfo_rw(qemu_plugin_meminfo_t i)
{
    return i >> 16;
}

typedef enum QemuPluginTbRvOrigin {
    QEMU_PLUGIN_TB_RV_ORIGIN_GUEST = 0,
    QEMU_PLUGIN_TB_RV_ORIGIN_ALLOCATOR_PRIVATE,
    QEMU_PLUGIN_TB_RV_ORIGIN_HELPER_PRIVATE,
} QemuPluginTbRvOrigin;

#ifdef CONFIG_PLUGIN
extern QemuOptsList qemu_plugin_opts;

static inline void qemu_plugin_add_opts(void)
{
    qemu_add_opts(&qemu_plugin_opts);
}

void qemu_plugin_opt_parse(const char *optstr, QemuPluginList *head);
int qemu_plugin_load_list(QemuPluginList *head, Error **errp);

union qemu_plugin_cb_sig {
    qemu_plugin_simple_cb_t          simple;
    qemu_plugin_udata_cb_t           udata;
    qemu_plugin_vcpu_simple_cb_t     vcpu_simple;
    qemu_plugin_vcpu_udata_cb_t      vcpu_udata;
    qemu_plugin_vcpu_tb_trans_cb_t   vcpu_tb_trans;
    qemu_plugin_vcpu_mem_cb_t        vcpu_mem;
    qemu_plugin_vcpu_syscall_cb_t    vcpu_syscall;
    qemu_plugin_vcpu_syscall_ret_cb_t vcpu_syscall_ret;
    void *generic;
};

enum plugin_dyn_cb_type {
    PLUGIN_CB_REGULAR,
    PLUGIN_CB_COND,
    PLUGIN_CB_MEM_REGULAR,
    PLUGIN_CB_INLINE_ADD_U64,
    PLUGIN_CB_INLINE_STORE_U64,
};

typedef void (*qemu_plugin_tb_codegen_cb_t)(struct qemu_plugin_tb *tb,
                                            void *userdata);

struct qemu_plugin_tb_codegen_hook {
    qemu_plugin_tb_codegen_cb_t cb;
    GDestroyNotify destroy;
    void *userdata;
};

struct qemu_plugin_tb_rv_trace {
    uint32_t *insns;
    uint8_t *tags;
    uint8_t *origins;
    int *insn_offsets;
    qemu_plugin_rv_insn_meta *insn_meta;
    int total_insns;
    int n_guest_insns;
};

struct qemu_plugin_regular_cb {
    union qemu_plugin_cb_sig f;
    TCGHelperInfo *info;
    void *userp;
    enum qemu_plugin_mem_rw rw;
};

struct qemu_plugin_inline_cb {
    qemu_plugin_u64 entry;
    uint64_t imm;
    enum qemu_plugin_mem_rw rw;
};

struct qemu_plugin_conditional_cb {
    union qemu_plugin_cb_sig f;
    TCGHelperInfo *info;
    void *userp;
    qemu_plugin_u64 entry;
    enum qemu_plugin_cond cond;
    uint64_t imm;
};

/*
 * A dynamic callback has an insertion point that is determined at run-time.
 * Usually the insertion point is somewhere in the code cache; think for
 * instance of a callback to be called upon the execution of a particular TB.
 */
struct qemu_plugin_dyn_cb {
    enum plugin_dyn_cb_type type;
    union {
        struct qemu_plugin_regular_cb regular;
        struct qemu_plugin_conditional_cb cond;
        struct qemu_plugin_inline_cb inline_insn;
    };
};

struct qemu_plugin_tb;

/* Internal context for instrumenting an instruction */
struct qemu_plugin_insn {
    struct qemu_plugin_tb *tb;
    uint64_t vaddr;
    GArray *insn_cbs;
    GArray *mem_cbs;
    uint8_t len;
    uint8_t data_len;
    uint8_t data[16];
    bool calls_helpers;

    /* if set, the instruction calls helpers that might access guest memory */
    bool mem_helper;
};

/* A scoreboard is an array of values, indexed by vcpu_index */
struct qemu_plugin_scoreboard {
    GArray *data;
    QLIST_ENTRY(qemu_plugin_scoreboard) entry;
};

/* Internal context for this TranslationBlock */
struct qemu_plugin_tb {
    GPtrArray *insns;
    size_t n;
    CPUState *cpu;
    DisasContextBase codegen_db;
    bool have_codegen_db;

    /* if set, the TB calls helpers that might access guest memory */
    bool mem_helper;

    GArray *cbs;
    GArray *codegen_cbs;
    GArray *rv_guest_semantic_fallbacks;
    GArray *rv_guest_semantic_tags;
    struct qemu_plugin_tb_rv_trace rv_trace;
};

/**
 * struct CPUPluginState - per-CPU state for plugins
 * @event_mask: plugin event bitmap. Modified only via async work.
 */
struct CPUPluginState {
    DECLARE_BITMAP(event_mask, QEMU_PLUGIN_EV_MAX);
};

/**
 * qemu_plugin_create_vcpu_state: allocate plugin state
 *
 * The returned data must be released with g_free()
 * when no longer required.
 */
CPUPluginState *qemu_plugin_create_vcpu_state(void);

void qemu_plugin_vcpu_init_hook(CPUState *cpu);
void qemu_plugin_vcpu_exit_hook(CPUState *cpu);
void qemu_plugin_tb_trans_cb(CPUState *cpu, struct qemu_plugin_tb *tb);
void qemu_plugin_vcpu_idle_cb(CPUState *cpu);
void qemu_plugin_vcpu_resume_cb(CPUState *cpu);
void
qemu_plugin_vcpu_syscall(CPUState *cpu, int64_t num, uint64_t a1,
                         uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8);
void qemu_plugin_vcpu_syscall_ret(CPUState *cpu, int64_t num, int64_t ret);

void qemu_plugin_vcpu_mem_cb(CPUState *cpu, uint64_t vaddr,
                             uint64_t value_low,
                             uint64_t value_high,
                             MemOpIdx oi, enum qemu_plugin_mem_rw rw);

void qemu_plugin_flush_cb(void);

void qemu_plugin_atexit_cb(void);

void qemu_plugin_add_dyn_cb_arr(GArray *arr);
#ifndef QEMU_PLUGIN_TB_CODEGEN_API_DECLS
void qemu_plugin_tb_register_codegen_cb(struct qemu_plugin_tb *tb,
                                        qemu_plugin_tb_codegen_cb_t cb,
                                        void *userdata,
                                        GDestroyNotify destroy);
bool qemu_plugin_tb_get_rv_trace(const struct qemu_plugin_tb *tb,
                                 const uint32_t **insns,
                                 const uint8_t **tags,
                                 const int **insn_offsets,
                                 const qemu_plugin_rv_insn_meta **insn_meta,
                                 int *total_insns,
                                 int *n_guest_insns);
#endif
size_t qemu_plugin_insn_data_cached(const struct qemu_plugin_insn *insn,
                                    void *dest, size_t len);
void qemu_plugin_tb_codegen_cb(struct qemu_plugin_tb *tb);
void qemu_plugin_tb_reset_codegen(struct qemu_plugin_tb *tb);
void qemu_plugin_tb_set_rv_trace(struct qemu_plugin_tb *tb,
                                 uint32_t *insns, uint8_t *tags,
                                 uint8_t *origins,
                                 int *insn_offsets,
                                 qemu_plugin_rv_insn_meta *insn_meta,
                                 int total_insns, int n_guest_insns);

static inline void qemu_plugin_disable_mem_helpers(CPUState *cpu)
{
    cpu->neg.plugin_mem_cbs = NULL;
}

/**
 * qemu_plugin_user_exit(): clean-up callbacks before calling exit callbacks
 *
 * This is a user-mode only helper that ensure we have fully cleared
 * callbacks from all threads before calling the exit callbacks. This
 * is so the plugins themselves don't have to jump through hoops to
 * guard against race conditions.
 */
void qemu_plugin_user_exit(void);

/**
 * qemu_plugin_user_prefork_lock(): take plugin lock before forking
 *
 * This is a user-mode only helper to take the internal plugin lock
 * before a fork event. This is ensure a consistent lock state
 */
void qemu_plugin_user_prefork_lock(void);

/**
 * qemu_plugin_user_postfork(): reset the plugin lock
 * @is_child: is this thread the child
 *
 * This user-mode only helper resets the lock state after a fork so we
 * can continue using the plugin interface.
 */
void qemu_plugin_user_postfork(bool is_child);

enum qemu_plugin_cb_flags tcg_call_to_qemu_plugin_cb_flags(int flags);

static inline void qemu_plugin_set_cb_flags(CPUState *cpu,
                                            enum qemu_plugin_cb_flags flags)
{
    assert(cpu);
    cpu->neg.plugin_cb_flags = flags;
}

static inline enum qemu_plugin_cb_flags qemu_plugin_get_cb_flags(void)
{
    assert(current_cpu);
    return current_cpu->neg.plugin_cb_flags;
}

#else /* !CONFIG_PLUGIN */

static inline void qemu_plugin_add_opts(void)
{ }

static inline void qemu_plugin_opt_parse(const char *optstr,
                                         QemuPluginList *head)
{
    error_report("plugin interface not enabled in this build");
    exit(1);
}

static inline int qemu_plugin_load_list(QemuPluginList *head, Error **errp)
{
    return 0;
}

static inline void qemu_plugin_vcpu_init_hook(CPUState *cpu)
{ }

static inline void qemu_plugin_vcpu_exit_hook(CPUState *cpu)
{ }

static inline void qemu_plugin_tb_trans_cb(CPUState *cpu,
                                           struct qemu_plugin_tb *tb)
{ }

static inline void qemu_plugin_vcpu_idle_cb(CPUState *cpu)
{ }

static inline void qemu_plugin_vcpu_resume_cb(CPUState *cpu)
{ }

static inline void
qemu_plugin_vcpu_syscall(CPUState *cpu, int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                         uint64_t a7, uint64_t a8)
{ }

static inline
void qemu_plugin_vcpu_syscall_ret(CPUState *cpu, int64_t num, int64_t ret)
{ }

static inline void qemu_plugin_vcpu_mem_cb(CPUState *cpu, uint64_t vaddr,
                                           uint64_t value_low,
                                           uint64_t value_high,
                                           MemOpIdx oi,
                                           enum qemu_plugin_mem_rw rw)
{ }

static inline void qemu_plugin_flush_cb(void)
{ }

static inline void qemu_plugin_atexit_cb(void)
{ }

static inline
void qemu_plugin_add_dyn_cb_arr(GArray *arr)
{ }

static inline void qemu_plugin_disable_mem_helpers(CPUState *cpu)
{ }

static inline void qemu_plugin_user_exit(void)
{ }

static inline void qemu_plugin_user_prefork_lock(void)
{ }

static inline void qemu_plugin_user_postfork(bool is_child)
{ }

#endif /* !CONFIG_PLUGIN */

#endif /* QEMU_PLUGIN_H */
