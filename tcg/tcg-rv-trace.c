/*
 * TCG-core RISC-V trace emission
 *
 * Synthetic RISC-V instruction stream emission for TracerTL.
 * Plugin-facing wrappers live in plugins/api.c.
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019, Linaro
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <dlfcn.h>
#include "exec/memopidx.h"
#include "qemu/plugin.h"
#include "qemu/qemu-plugin.h"
#include "qemu/target-info.h"
#include "tcg/tcg.h"
#include "tcg/tcg-internal.h"
#include "plugins/tracertl_rv_helpers.h"
#include "plugins/tracertl_rv_vector_lowering.h"

/*
 * RISC-V instruction encoding helpers for trace emission.
 * These are stateless pure functions copied from tcg/riscv/tcg-target.c.inc.
 */

/* RISC-V opcodes used for trace emission */
enum {
    /* R-type arithmetic */
    RV_OPC_ADD   = 0x33,       RV_OPC_SUB   = 0x40000033,
    RV_OPC_MUL   = 0x2000033,  RV_OPC_MULH  = 0x2001033,
    RV_OPC_MULHU = 0x2003033,  RV_OPC_MULHSU = 0x2002033,
    RV_OPC_DIV   = 0x2004033,
    RV_OPC_DIVU  = 0x2005033,  RV_OPC_REM   = 0x2006033,
    RV_OPC_REMU  = 0x2007033,
    RV_OPC_AND   = 0x7033,     RV_OPC_OR    = 0x6033,
    RV_OPC_XOR   = 0x4033,     RV_OPC_SLL   = 0x1033,
    RV_OPC_SRL   = 0x5033,     RV_OPC_SRA   = 0x40005033,
    RV_OPC_SLT   = 0x2033,     RV_OPC_SLTU  = 0x3033,
    /* I-type arithmetic */
    RV_OPC_ADDI  = 0x13,       RV_OPC_XORI  = 0x4013,
    RV_OPC_ORI   = 0x6013,     RV_OPC_ANDI  = 0x7013,
    RV_OPC_SLTIU = 0x3013,     RV_OPC_SLTI  = 0x2013,
    /* I-type immediate shifts (RV64I) */
    RV_OPC_SLLI  = 0x1013,     RV_OPC_SRLI  = 0x5013,
    /* SRAI: use RV_OPC_SRLI with imm | 0x400 */
    /* RV64 W-suffix */
    RV_OPC_ADDW  = 0x3b,       RV_OPC_SUBW  = 0x4000003b,
    RV_OPC_MULW  = 0x200003b,  RV_OPC_DIVW  = 0x200403b,
    RV_OPC_DIVUW = 0x200503b,  RV_OPC_REMW  = 0x200603b,
    RV_OPC_REMUW = 0x200703b,
    RV_OPC_SLLW  = 0x103b,     RV_OPC_SRLW  = 0x503b,
    RV_OPC_SRAW  = 0x4000503b, RV_OPC_ADDIW = 0x1b,
    RV_OPC_SLLIW = 0x101b,     RV_OPC_SRLIW = 0x501b,
    RV_OPC_SRAIW = 0x4000501b,
    /* Load/store */
    RV_OPC_LB    = 0x3,        RV_OPC_LBU   = 0x4003,
    RV_OPC_LH    = 0x1003,     RV_OPC_LHU   = 0x5003,
    RV_OPC_LW    = 0x2003,     RV_OPC_LWU   = 0x6003,
    RV_OPC_LD    = 0x3003,
    RV_OPC_SB    = 0x23,       RV_OPC_SH    = 0x1023,
    RV_OPC_SW    = 0x2023,     RV_OPC_SD    = 0x3023,
    /* Branch */
    RV_OPC_BEQ   = 0x63,       RV_OPC_BNE   = 0x1063,
    RV_OPC_BLT   = 0x4063,     RV_OPC_BGE   = 0x5063,
    RV_OPC_BLTU  = 0x6063,     RV_OPC_BGEU  = 0x7063,
    RV_OPC_JAL   = 0x6f,
    RV_OPC_FENCE = 0x0f,
    RV_OPC_ECALL = 0x73,
};

static uint32_t rv_encode_r(uint32_t opc, int rd, int rs1, int rs2)
{
    return tracertl_rv_encode_r(opc, rd, rs1, rs2);
}

static uint32_t rv_encode_i(uint32_t opc, int rd, int rs1, uint32_t imm)
{
    return tracertl_rv_encode_i(opc, rd, rs1, imm);
}

static uint32_t rv_encode_s(uint32_t opc, int rs1, int rs2, uint32_t imm)
{
    return opc | (rs1 & 0x1f) << 15 | (rs2 & 0x1f) << 20
         | ((imm & 0xFE0) << 20) | ((imm & 0x1F) << 7);
}

static uint32_t rv_encode_sb(uint32_t opc, int rs1, int rs2, uint32_t imm)
{
    return opc | (rs1 & 0x1f) << 15 | (rs2 & 0x1f) << 20
         | ((imm & 0x1000) << 19) | ((imm & 0x7e0) << 20)
         | ((imm & 0x1e) << 7)    | ((imm & 0x800) >> 4);
}

static uint32_t rv_encode_uj(uint32_t opc, int rd, uint32_t imm)
{
    return opc | (rd & 0x1f) << 7
         | (imm & 0x000ff000)
         | ((imm & 0x00000800) << 9)
         | ((imm & 0x000007fe) << 20)
         | ((imm & 0x00100000) << 11);
}

typedef struct RvTraceHelperCounter {
    uint64_t count;
} RvTraceHelperCounter;

static bool rv_trace_counter_init_done;
static const char *rv_trace_counter_path;
static bool rv_trace_counter_dirty;
static uint64_t rv_trace_unsupported_counts[NB_OPS];
static uint64_t rv_trace_generic_placeholder_counts[NB_OPS];
static uint64_t rv_trace_emitted_generic_placeholder_counts[NB_OPS];
static GHashTable *rv_trace_helper_counts;

static const char *rv_trace_helper_name(const tcg_insn_unit *target,
                                        const TCGHelperInfo *info)
{
    const char *name = info != NULL ? info->name : NULL;

    if (name != NULL) {
        return name;
    }

    if (info != NULL && info->func != NULL) {
        Dl_info dli = { 0 };

        if (dladdr(info->func, &dli) != 0 && dli.dli_sname != NULL) {
            return dli.dli_sname;
        }
    }

    if (target != NULL) {
        Dl_info dli = { 0 };

        if (dladdr((const void *)target, &dli) != 0 && dli.dli_sname != NULL) {
            return dli.dli_sname;
        }
    }

    return NULL;
}

static const char *rv_trace_helper_counter_fallback_name(
    const tcg_insn_unit *target, const TCGHelperInfo *info,
    const char *fallback_name)
{
    static __thread char buf[4][128];
    static __thread unsigned next_buf;
    const char *label = fallback_name != NULL ? fallback_name : "(anon)";
    const void *ptrs[2] = {
        info != NULL ? info->func : NULL,
        target != NULL ? (const void *)target : NULL,
    };
    const char *kinds[2] = { "func", "target" };

    for (int i = 0; i < ARRAY_SIZE(ptrs); i++) {
        const void *ptr = ptrs[i];
        Dl_info dli = { 0 };
        uintptr_t off;
        const char *mod;
        unsigned slot = next_buf++ % ARRAY_SIZE(buf);

        if (ptr == NULL || dladdr(ptr, &dli) == 0 || dli.dli_fbase == NULL) {
            continue;
        }

        off = (uintptr_t)ptr - (uintptr_t)dli.dli_fbase;
        mod = dli.dli_fname != NULL ? strrchr(dli.dli_fname, '/') : NULL;
        mod = mod != NULL ? mod + 1 : dli.dli_fname;
        snprintf(buf[slot], sizeof(buf[slot]),
                 "%s@%s:%s+0x%" PRIxPTR, label, kinds[i],
                 mod != NULL ? mod : "(module)", off);
        return buf[slot];
    }

    {
        unsigned slot = next_buf++ % ARRAY_SIZE(buf);

        snprintf(buf[slot], sizeof(buf[slot]), "%s@(unresolved)", label);
        return buf[slot];
    }
}

static const char *rv_trace_guest_bytes_counter_name(const char *prefix,
                                                     const uint8_t *bytes,
                                                     size_t len)
{
    static __thread char buf[4][128];
    static __thread unsigned next_buf;
    unsigned slot = next_buf++ % ARRAY_SIZE(buf);
    size_t pos = 0;

    pos += snprintf(buf[slot], sizeof(buf[slot]), "%s", prefix);
    for (size_t i = 0; i < len && pos + 3 < sizeof(buf[slot]); i++) {
        pos += snprintf(buf[slot] + pos, sizeof(buf[slot]) - pos,
                        i == 0 ? ":%02x" : "-%02x", bytes[i]);
    }
    return buf[slot];
}

static void rv_trace_counter_dump(void)
{
    FILE *fp;
    GHashTableIter iter;
    gpointer key;
    gpointer value;

    if (rv_trace_counter_path == NULL) {
        return;
    }

    fp = fopen(rv_trace_counter_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "rv-trace: failed to open counter dump path %s\n",
                rv_trace_counter_path);
        return;
    }

    fprintf(fp, "[unsupported]\n");
    for (int opc = 0; opc < NB_OPS; opc++) {
        uint64_t total = rv_trace_unsupported_counts[opc];
        uint64_t generic = rv_trace_generic_placeholder_counts[opc];

        if (total == 0 && generic == 0) {
            continue;
        }
        fprintf(fp, "%s total=%" PRIu64 " generic=%" PRIu64 " emitted=%" PRIu64 "\n",
                tcg_op_defs[opc].name, total, generic,
                rv_trace_emitted_generic_placeholder_counts[opc]);
    }

    fprintf(fp, "[helper]\n");
    if (rv_trace_helper_counts != NULL) {
        g_hash_table_iter_init(&iter, rv_trace_helper_counts);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            const char *name = key;
            const RvTraceHelperCounter *counter = value;

            fprintf(fp, "%s total=%" PRIu64 "\n", name, counter->count);
        }
    }

    fclose(fp);
}

static void rv_trace_counter_maybe_dump(void)
{
    if (rv_trace_counter_path == NULL || !rv_trace_counter_dirty) {
        return;
    }
    rv_trace_counter_dump();
    rv_trace_counter_dirty = false;
}

static void rv_trace_counter_init(void)
{
    if (rv_trace_counter_init_done) {
        return;
    }

    rv_trace_counter_init_done = true;
    rv_trace_counter_path = getenv("TRACERTL_RV_TRACE_COUNTER_PATH");
    if (rv_trace_counter_path == NULL || rv_trace_counter_path[0] == '\0') {
        rv_trace_counter_path = NULL;
        return;
    }

    rv_trace_helper_counts = g_hash_table_new_full(g_str_hash, g_str_equal,
                                                   g_free, g_free);
    atexit(rv_trace_counter_dump);
}

static void rv_trace_counter_note_unsupported(TCGOpcode opc)
{
    rv_trace_counter_init();
    if (rv_trace_counter_path == NULL || opc >= NB_OPS) {
        return;
    }
    rv_trace_unsupported_counts[opc]++;
    rv_trace_counter_dirty = true;
}

static void rv_trace_counter_note_generic_placeholder(TCGOpcode opc)
{
    rv_trace_counter_init();
    if (rv_trace_counter_path == NULL || opc >= NB_OPS) {
        return;
    }
    rv_trace_generic_placeholder_counts[opc]++;
    rv_trace_counter_dirty = true;
}

static void rv_trace_counter_note_emitted_generic_placeholder(TCGOpcode opc)
{
    rv_trace_counter_init();
    if (rv_trace_counter_path == NULL || opc >= NB_OPS) {
        return;
    }
    rv_trace_emitted_generic_placeholder_counts[opc]++;
    rv_trace_counter_dirty = true;
}

static void rv_trace_counter_note_helper_name(const char *name)
{
    RvTraceHelperCounter *counter;

    rv_trace_counter_init();
    if (rv_trace_counter_path == NULL || rv_trace_helper_counts == NULL) {
        return;
    }

    if (name == NULL) {
        name = "(anon)";
    }
    counter = g_hash_table_lookup(rv_trace_helper_counts, name);
    if (counter == NULL) {
        counter = g_new0(RvTraceHelperCounter, 1);
        g_hash_table_insert(rv_trace_helper_counts, g_strdup(name), counter);
    }
    counter->count++;
    rv_trace_counter_dirty = true;
}

static void rv_trace_counter_note_helper(const tcg_insn_unit *target,
                                         const TCGHelperInfo *info,
                                         const char *fallback_name)
{
    const char *name = rv_trace_helper_name(target, info);

    if (name == NULL || name[0] == '\0') {
        name = fallback_name;
    }
    rv_trace_counter_note_helper_name(name);
}

/*
 * TB-local mapping between TCG temps and synthetic RV trace registers.
 * The map only lives while qemu_plugin_tb_emit_rv() walks one translated TB.
 * It also carries the current vector configuration so later vector ops can
 * reuse or restore the right vtype state.
 */
typedef struct {
    int temp_regs[TCG_MAX_TEMPS]; /* temp idx -> xN/vN */
    int reg_temps[64];            /* xN/vN -> temp idx */
    TCGType cur_vtype_type;
    MemOp cur_vtype_vsew;
    bool have_vtype;
} RvTempMapState;

/* Active TB-local temp map for the current translation thread. */
static __thread RvTempMapState *rv_temp_map_state;

static const int rv_trace_regs[] = {
    10, 11, 12, 13, 14, 15, 16, 17,
     5,  6,  7, 28, 29,
     9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
     2,  3,  4,  8,
};

static const int rv_trace_vregs[] = {
    33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56,
    57, 58, 59, 60, 61, 62, 63,
};

static void rv_temp_map_init(RvTempMapState *state)
{
    for (int i = 0; i < TCG_MAX_TEMPS; i++) {
        state->temp_regs[i] = -1;
    }
    for (int i = 0; i < ARRAY_SIZE(state->reg_temps); i++) {
        state->reg_temps[i] = -1;
    }
    state->cur_vtype_type = TCG_TYPE_I32;
    state->cur_vtype_vsew = MO_64;
    state->have_vtype = false;
}

static int rv_alloc_trace_reg(RvTempMapState *state, unsigned int idx)
{
    int preferred = tracertl_rv_temp_to_reg(idx);

    /* Prefer a deterministic temp->register mapping, then fall back to the
     * first free trace register in the shared pool. */
    if (preferred >= 0 && state->reg_temps[preferred] < 0) {
        return preferred;
    }

    for (int i = 0; i < ARRAY_SIZE(rv_trace_regs); i++) {
        int reg = rv_trace_regs[i];

        if (state->reg_temps[reg] < 0) {
            return reg;
        }
    }

    return -1;
}

static int rv_alloc_trace_vreg(RvTempMapState *state, unsigned int idx)
{
    int preferred = tracertl_rv_temp_to_vreg(idx);

    if (preferred >= 0 && preferred < ARRAY_SIZE(state->reg_temps) &&
        state->reg_temps[preferred] < 0) {
        return preferred;
    }

    for (int i = 0; i < ARRAY_SIZE(rv_trace_vregs); i++) {
        int reg = rv_trace_vregs[i];

        if (state->reg_temps[reg] < 0) {
            return reg;
        }
    }

    return -1;
}

static int rv_temp_to_reg(TCGArg a)
{
    TCGTemp *ts = arg_temp(a);
    unsigned int idx;
    int reg;
    bool is_vector;

    g_assert(ts != NULL);
    idx = (unsigned int)temp_idx(ts);
    is_vector = ts->base_type >= TCG_TYPE_V64;

    if (!rv_temp_map_state) {
        return is_vector ? tracertl_rv_temp_to_vreg(idx)
                         : tracertl_rv_temp_to_reg(idx);
    }

    /* Once a temp is assigned a trace register within this TB, keep reusing it
     * until rv_release_dead_temps() frees the mapping. */
    reg = rv_temp_map_state->temp_regs[idx];
    if (reg >= 0) {
        return reg;
    }

    reg = is_vector ? rv_alloc_trace_vreg(rv_temp_map_state, idx)
                    : rv_alloc_trace_reg(rv_temp_map_state, idx);
    if (reg >= 0) {
        rv_temp_map_state->temp_regs[idx] = reg;
        if (reg < ARRAY_SIZE(rv_temp_map_state->reg_temps)) {
            rv_temp_map_state->reg_temps[reg] = (int)idx;
        }
        return reg;
    }

    /* Returning -1 forces the caller onto a placeholder path. */
    return -1;
}

static int rv_emit(uint32_t *buf, int *pos, int buf_size, uint32_t insn);
static void rv_emit_shared_sequence(uint32_t *buf, int *pos, int buf_size,
                                    int n, const uint32_t *insns);
static void rv_emit_dependency_placeholder(uint32_t *buf, int *pos,
                                           int buf_size, const TCGOp *op,
                                           int rd, int first_input,
                                           int nb_inputs);
static uint32_t rv_placeholder_signature(TCGOpcode opc, unsigned int salt);
static void rv_note_mem_slot(qemu_plugin_rv_insn_meta *insn_meta,
                             int guest_idx, const int *insn_offsets, int pos);
static void rv_set_mem_slot(uint32_t *buf,
                            qemu_plugin_rv_insn_meta *insn_meta,
                            int guest_idx, const int *insn_offsets, int pos);
static void rv_emit_indirect_branch_placeholder(uint32_t *buf, int *pos,
                                                int buf_size,
                                                qemu_plugin_rv_insn_meta *insn_meta,
                                                int guest_idx,
                                                const int *insn_offsets,
                                                TCGArg reg_arg);
static void rv_emit_vector_placeholder(uint32_t *buf, int *pos, int buf_size,
                                       qemu_plugin_rv_insn_meta *insn_meta,
                                       int guest_idx,
                                       const int *insn_offsets,
                                       const TCGOp *op);
static void rv_trace_note_helper_slot_current(void);
static void rv_trace_note_branch_slot_current(void);
static bool rv_trace_emit_guest_semantic_fallback(void);
static void rv_trace_promote_branch_slot_to_terminal_record(void);
static void rv_trace_tgen_add(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, TCGReg rs2);
static void rv_trace_tgen_sub(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, TCGReg rs2);
static void rv_trace_tgen_or(TCGContext *s, TCGType type,
                             TCGReg rd, TCGReg rs1, TCGReg rs2);
static void rv_trace_tgen_shr(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, TCGReg rs2);
static void rv_trace_tgen_divs(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, TCGReg rs2);
static void rv_trace_tgen_divu(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, TCGReg rs2);
static void rv_backend_guest_qemu_ld(TCGContext *s, TCGType type,
                                     TCGReg rd, TCGReg addr, MemOpIdx oi);
static void rv_backend_guest_qemu_st(TCGContext *s, TCGType type,
                                     TCGReg rs, TCGReg addr, MemOpIdx oi);

typedef struct RvTraceBuildState RvTraceBuildState;

typedef enum PendingBranchKind {
    PENDING_BRANCH_NONE,
    PENDING_BRANCH_DIRECT,
    PENDING_BRANCH_INDIRECT,
} PendingBranchKind;

struct RvTraceBuildState {
    uint32_t *buf;
    uint8_t *tags;
    int buf_size;
    struct qemu_plugin_tb *plugin_tb;
    int *insn_offsets;
    qemu_plugin_rv_insn_meta *insn_meta;
    int pos;
    int guest_idx;
    int n_guest_insns;
    bool guest_has_branch;
    bool guest_helper_emitted;
    bool guest_translated_helper_emitted;
    bool guest_semantic_emitted;
    PendingBranchKind pending_branch;
    TCGArg pending_branch_arg;
    bool current_tcg_op_active;
    bool current_tcg_op_emitted_guest;
    bool current_tcg_op_deferred_guest_output;
};

static __thread RvTraceBuildState *rv_trace_build_state;

static __thread uint8_t *rv_emit_tags;
static __thread uint8_t *rv_emit_origins;
static __thread qemu_plugin_rv_trace_tag rv_current_tag;
static __thread QemuPluginTbRvOrigin rv_current_origin;

static qemu_plugin_rv_trace_tag rv_set_current_tag(qemu_plugin_rv_trace_tag tag)
{
    qemu_plugin_rv_trace_tag prev = rv_current_tag;

    rv_current_tag = tag;
    return prev;
}

static void rv_restore_current_tag(qemu_plugin_rv_trace_tag prev)
{
    rv_current_tag = prev;
}

QemuPluginTbRvOrigin tcg_rv_trace_set_origin(QemuPluginTbRvOrigin origin)
{
    QemuPluginTbRvOrigin prev = rv_current_origin;

    if (rv_trace_build_state != NULL) {
        rv_current_origin = origin;
    }
    return prev;
}

void tcg_rv_trace_restore_origin(QemuPluginTbRvOrigin prev)
{
    if (rv_trace_build_state != NULL) {
        rv_current_origin = prev;
    }
}

static bool rv_helper_name_is_lookup_tb_ptr(const char *name)
{
    return name && strcmp(name, "lookup_tb_ptr") == 0;
}

static bool rv_helper_name_is_private(const char *name)
{
    static const char *const prefixes[] = {
        "cc_compute_",
        "rechecking_",
    };

    if (!name) {
        return false;
    }

    for (size_t i = 0; i < G_N_ELEMENTS(prefixes); i++) {
        if (g_str_has_prefix(name, prefixes[i])) {
            return true;
        }
    }

    return false;
}

static bool rv_helper_target_is_shared_object(const tcg_insn_unit *target)
{
    Dl_info dli = { 0 };
    const char *mod;

    if (target == NULL || dladdr((const void *)target, &dli) == 0 ||
        dli.dli_fname == NULL) {
        return false;
    }

    mod = strrchr(dli.dli_fname, '/');
    mod = mod != NULL ? mod + 1 : dli.dli_fname;
    return mod != NULL && strstr(mod, ".so") != NULL;
}

static bool rv_target_is_native_riscv_guest(void)
{
    const char *name = target_name();

    return name != NULL &&
           (!strcmp(name, "riscv32") || !strcmp(name, "riscv64"));
}

static bool rv_target_is_x86_guest(void)
{
    const char *name = target_name();

    return name != NULL &&
           (!strcmp(name, "i386") || !strcmp(name, "x86_64"));
}

static bool rv_target_is_aarch64_guest(void)
{
    const char *name = target_name();

    return name != NULL &&
           (!strcmp(name, "aarch64") || !strcmp(name, "arm"));
}

static bool rv_target_is_system_emulation(void)
{
#ifdef CONFIG_USER_ONLY
    return false;
#else
    return true;
#endif
}

static size_t rv_trace_copy_current_guest_bytes(uint8_t *bytes, size_t buf_size)
{
    RvTraceBuildState *st = rv_trace_build_state;
    struct qemu_plugin_insn *insn;

    if (st == NULL || st->plugin_tb == NULL || st->guest_idx < 0) {
        return 0;
    }

    insn = qemu_plugin_tb_get_insn(st->plugin_tb, st->guest_idx);
    if (insn == NULL) {
        return 0;
    }

    return qemu_plugin_insn_data_cached(
        insn, bytes,
        MIN(buf_size, (size_t)qemu_plugin_insn_size(insn)));
}

static TracertlRvCoreTraceSink rv_trace_core_sink_current(RvTraceBuildState *st)
{
    return (TracertlRvCoreTraceSink) {
        .buf = st->buf,
        .tags = rv_emit_tags,
        .origins = rv_emit_origins,
        .pos = &st->pos,
        .buf_size = st->buf_size,
        .meta = (st->insn_meta != NULL && st->guest_idx >= 0)
            ? &st->insn_meta[st->guest_idx] : NULL,
        .insn_offset = (st->insn_offsets != NULL && st->guest_idx >= 0)
            ? st->insn_offsets[st->guest_idx] : 0,
        .guest_has_branch = &st->guest_has_branch,
    };
}

static void rv_trace_note_unhandled_translated_helper(const char *name,
                                                      const uint8_t *bytes,
                                                      size_t len)
{
    const char *byte_name = len > 0
        ? rv_trace_guest_bytes_counter_name("translated_helper_guard",
                                            bytes, len)
        : "translated_helper_guard:(no-bytes)";

    if (name != NULL) {
        rv_trace_counter_note_helper_name(name);
    }
    rv_trace_counter_note_helper_name(byte_name);
}

static void rv_trace_note_exception_slot_current(void)
{
    RvTraceBuildState *st = rv_trace_build_state;

    if (st && st->insn_meta && st->guest_idx >= 0 &&
        st->insn_meta[st->guest_idx].exception_idx < 0) {
        st->insn_meta[st->guest_idx].exception_idx =
            (int8_t)(st->pos - st->insn_offsets[st->guest_idx]);
    }
}

static void rv_trace_begin_current_tcg_op(void)
{
    RvTraceBuildState *st = rv_trace_build_state;

    if (st == NULL) {
        return;
    }

    st->current_tcg_op_active = true;
    st->current_tcg_op_emitted_guest = false;
    st->current_tcg_op_deferred_guest_output = false;
}

static void rv_trace_note_current_tcg_op_guest_output(void)
{
    RvTraceBuildState *st = rv_trace_build_state;

    if (st != NULL && st->current_tcg_op_active) {
        st->current_tcg_op_emitted_guest = true;
    }
}

static void rv_trace_note_current_tcg_op_deferred_guest_output(void)
{
    RvTraceBuildState *st = rv_trace_build_state;

    if (st != NULL && st->current_tcg_op_active) {
        st->current_tcg_op_deferred_guest_output = true;
    }
}

static void rv_trace_finish_current_tcg_op(void)
{
    RvTraceBuildState *st = rv_trace_build_state;

    if (st == NULL || !st->current_tcg_op_active) {
        return;
    }

    if ((st->current_tcg_op_emitted_guest ||
         st->current_tcg_op_deferred_guest_output) &&
        st->insn_meta != NULL &&
        st->guest_idx >= 0 &&
        st->insn_meta[st->guest_idx].emitting_tcg_ops < UINT16_MAX) {
        st->insn_meta[st->guest_idx].emitting_tcg_ops++;
    }

    st->current_tcg_op_active = false;
    st->current_tcg_op_emitted_guest = false;
    st->current_tcg_op_deferred_guest_output = false;
}

static MemOp rv_backend_translated_x86_memop(uint8_t mem_size, bool is_store)
{
    switch (mem_size) {
    case 0:
        return is_store ? MO_8 : MO_UB;
    case 1:
        return is_store ? MO_16 : MO_UW;
    case 2:
        return is_store ? MO_32 : MO_UL;
    default:
        return is_store ? MO_64 : MO_UQ;
    }
}

static void rv_backend_emit_translated_x86_tail(
    TCGContext *s, TracertlRvTranslatedX86EmitKind emit_kind)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
    RvTraceBuildState *st = rv_trace_build_state;

    g_assert(st != NULL);

    switch (emit_kind) {
    case TRACERTL_RV_TRANSLATED_X86_EMIT_TRAP:
        rv_emit(st->buf, &st->pos, st->buf_size, RV_OPC_ECALL);
        break;
    case TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE:
        rv_emit(st->buf, &st->pos, st->buf_size, RV_OPC_FENCE);
        break;
    case TRACERTL_RV_TRANSLATED_X86_EMIT_SUB:
        rv_trace_tgen_sub(s, TCG_TYPE_I64, TRACERTL_RV_SCRATCH_REG,
                          TRACERTL_RV_SCRATCH_REG,
                          TRACERTL_RV_ALT_SCRATCH_REG);
        break;
    case TRACERTL_RV_TRANSLATED_X86_EMIT_OR:
        rv_trace_tgen_or(s, TCG_TYPE_I64, TRACERTL_RV_SCRATCH_REG,
                         TRACERTL_RV_SCRATCH_REG,
                         TRACERTL_RV_ALT_SCRATCH_REG);
        break;
    case TRACERTL_RV_TRANSLATED_X86_EMIT_SRL:
        rv_trace_tgen_shr(s, TCG_TYPE_I64, TRACERTL_RV_SCRATCH_REG,
                          TRACERTL_RV_SCRATCH_REG,
                          TRACERTL_RV_ALT_SCRATCH_REG);
        break;
    case TRACERTL_RV_TRANSLATED_X86_EMIT_DIV:
        rv_trace_tgen_divs(s, TCG_TYPE_I64, TRACERTL_RV_SCRATCH_REG,
                           TRACERTL_RV_SCRATCH_REG,
                           TRACERTL_RV_ALT_SCRATCH_REG);
        break;
    case TRACERTL_RV_TRANSLATED_X86_EMIT_DIVU:
        rv_trace_tgen_divu(s, TCG_TYPE_I64, TRACERTL_RV_SCRATCH_REG,
                           TRACERTL_RV_SCRATCH_REG,
                           TRACERTL_RV_ALT_SCRATCH_REG);
        break;
    case TRACERTL_RV_TRANSLATED_X86_EMIT_STORE:
    case TRACERTL_RV_TRANSLATED_X86_EMIT_NONE:
    default:
        break;
    }

    tcg_rv_trace_restore_origin(prev);
}

static bool rv_backend_emit_translated_x86_spec(
    TCGContext *s, const TracertlRvTranslatedX86Spec *spec)
{
    RvTraceBuildState *st = rv_trace_build_state;
    bool is_store;

    if (st == NULL || spec == NULL) {
        return false;
    }

    rv_trace_note_helper_slot_current();
    if (spec->helper_exception) {
        rv_trace_note_exception_slot_current();
    }

    if (spec->has_mem_operand) {
        is_store = spec->emit_kind == TRACERTL_RV_TRANSLATED_X86_EMIT_STORE;
        MemOpIdx oi = make_memop_idx(
            rv_backend_translated_x86_memop(spec->mem_size, is_store),
            0);

        if (is_store) {
            rv_backend_guest_qemu_st(s, TCG_TYPE_I64,
                                     TRACERTL_RV_ALT_SCRATCH_REG,
                                     TRACERTL_RV_SCRATCH_REG, oi);
        } else {
            rv_backend_guest_qemu_ld(s, TCG_TYPE_I64,
                                     TRACERTL_RV_ALT_SCRATCH_REG,
                                     TRACERTL_RV_SCRATCH_REG, oi);
        }
    }

    if (spec->emit_kind != TRACERTL_RV_TRANSLATED_X86_EMIT_STORE) {
        rv_backend_emit_translated_x86_tail(s, spec->emit_kind);
    }

    return true;
}

static void rv_backend_emit_translated_helper_from_guest(
    TCGContext *s, const char *name, const uint8_t *bytes, size_t len,
    bool is_x86_guest, bool is_aarch64_guest,
    bool is_system_emulation)
{
    RvTraceBuildState *st = rv_trace_build_state;
    TracertlRvTranslatedX86Spec spec;
    TracertlRvTranslatedX86DecodeStatus status;

    g_assert(st != NULL);

    if (is_x86_guest) {
        status = tracertl_rv_decode_translated_x86(bytes, len,
                                                   is_system_emulation,
                                                   &spec);
        if (status == TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED &&
            rv_backend_emit_translated_x86_spec(s, &spec)) {
            st->guest_helper_emitted = true;
            st->guest_translated_helper_emitted = true;
            return;
        }
    }

    /*
     * Some translated guest helpers are still outside the explicit lowering
     * table. Degrade to the existing guest helper placeholder path instead of
     * aborting the whole translation.
     */
    (void)is_aarch64_guest;
    rv_trace_note_unhandled_translated_helper(name, bytes, len);
    st->guest_helper_emitted = true;
    st->guest_translated_helper_emitted = true;
    rv_trace_note_current_tcg_op_deferred_guest_output();
}

static TracertlRvOperand rv_reg_or_const_operand(TCGArg arg, bool is_const)
{
    TracertlRvOperand op = {
        .reg = is_const ? -1 : arg,
        .is_const = is_const,
        .imm = is_const ? arg : 0,
    };

    return op;
}

/* Emit one RISC-V instruction into buf, return 1 if space, 0 if full */
static int rv_emit(uint32_t *buf, int *pos, int buf_size, uint32_t insn)
{
    if (*pos >= buf_size) {
        *pos = buf_size + 1;
        return 0;
    }
    if (rv_emit_tags) {
        rv_emit_tags[*pos] = (uint8_t)rv_current_tag;
    }
    if (rv_emit_origins) {
        rv_emit_origins[*pos] = (uint8_t)rv_current_origin;
    }
    if (rv_current_origin == QEMU_PLUGIN_TB_RV_ORIGIN_GUEST) {
        rv_trace_note_current_tcg_op_guest_output();
    }
    buf[(*pos)++] = insn;
    return 1;
}

static void rv_emit_carry_sequence(uint32_t *buf, int *pos, int buf_size,
                                   TracertlRvCarryOp op, bool is_32bit,
                                   int rd, int rs1, int rs2)
{
    uint32_t insns[5];
    int n = tracertl_rv_emit_carry_sequence(insns, ARRAY_SIZE(insns),
                                            op, is_32bit, rd, rs1, rs2);
    int i;

    g_assert_cmpint(n, >, 0);
    for (i = 0; i < n; i++) {
        rv_emit(buf, pos, buf_size, insns[i]);
    }
}

static void rv_emit_shared_sequence(uint32_t *buf, int *pos, int buf_size,
                                    int n, const uint32_t *insns)
{
    int i;

    g_assert_cmpint(n, >, 0);
    for (i = 0; i < n; i++) {
        rv_emit(buf, pos, buf_size, insns[i]);
    }
}

static TracertlRvVectorState rv_snapshot_vector_state(void)
{
    TracertlRvVectorState state = { 0 };

    if (!rv_temp_map_state) {
        return state;
    }

    state.have_vtype = rv_temp_map_state->have_vtype;
    state.cur_vtype_type = rv_temp_map_state->cur_vtype_type;
    state.cur_vtype_vsew = rv_temp_map_state->cur_vtype_vsew;
    return state;
}

static void rv_restore_vector_state(const TracertlRvVectorState *state)
{
    if (!rv_temp_map_state || !state) {
        return;
    }

    rv_temp_map_state->have_vtype = state->have_vtype;
    rv_temp_map_state->cur_vtype_type = state->cur_vtype_type;
    rv_temp_map_state->cur_vtype_vsew = state->cur_vtype_vsew;
}

#define RV_TCG_CT_CONST_S12    0x100
#define RV_TCG_CT_CONST_M12    0x200
#define RV_TCG_CT_CONST_S5     0x400
#define RV_TCG_CT_CONST_CMP_VI 0x800
#define RV_TCG_CT_CONST_ZERO   0x1000

#define RV_ALL_GENERAL_REGS MAKE_64BIT_MASK(0, 32)
#define RV_ALL_VECTOR_REGS  MAKE_64BIT_MASK(32, 32)

#define RV_C_PFX1(P, A)                P##A
#define RV_C_PFX2(P, A, B)             P##A##_##B
#define RV_C_PFX3(P, A, B, C)          P##A##_##B##_##C
#define RV_C_PFX4(P, A, B, C, D)       P##A##_##B##_##C##_##D
#define RV_C_PFX5(P, A, B, C, D, E)    P##A##_##B##_##C##_##D##_##E
#define RV_C_PFX6(P, A, B, C, D, E, F) P##A##_##B##_##C##_##D##_##E##_##F

#define C_O0_I1(I1)                     RV_C_PFX1(c_o0_i1_, I1),
#define C_O0_I2(I1, I2)                 RV_C_PFX2(c_o0_i2_, I1, I2),
#define C_O0_I3(I1, I2, I3)             RV_C_PFX3(c_o0_i3_, I1, I2, I3),
#define C_O0_I4(I1, I2, I3, I4)         RV_C_PFX4(c_o0_i4_, I1, I2, I3, I4),
#define C_O1_I1(O1, I1)                 RV_C_PFX2(c_o1_i1_, O1, I1),
#define C_O1_I2(O1, I1, I2)             RV_C_PFX3(c_o1_i2_, O1, I1, I2),
#define C_O1_I3(O1, I1, I2, I3)         RV_C_PFX4(c_o1_i3_, O1, I1, I2, I3),
#define C_O1_I4(O1, I1, I2, I3, I4)     RV_C_PFX5(c_o1_i4_, O1, I1, I2, I3, I4),
#define C_N1_I2(O1, I1, I2)             RV_C_PFX3(c_n1_i2_, O1, I1, I2),
#define C_N1O1_I1(O1, O2, I1)           RV_C_PFX3(c_n1o1_i1_, O1, O2, I1),
#define C_N2_I1(O1, O2, I1)             RV_C_PFX3(c_n2_i1_, O1, O2, I1),
#define C_O2_I1(O1, O2, I1)             RV_C_PFX3(c_o2_i1_, O1, O2, I1),
#define C_O2_I2(O1, O2, I1, I2)         RV_C_PFX4(c_o2_i2_, O1, O2, I1, I2),
#define C_O2_I3(O1, O2, I1, I2, I3)     RV_C_PFX5(c_o2_i3_, O1, O2, I1, I2, I3),
#define C_O2_I4(O1, O2, I1, I2, I3, I4) RV_C_PFX6(c_o2_i4_, O1, O2, I1, I2, I3, I4),
#define C_N1_O1_I4(O1, O2, I1, I2, I3, I4) RV_C_PFX6(c_n1_o1_i4_, O1, O2, I1, I2, I3, I4)
enum {
#include "tcg/riscv/tcg-target-con-set.h"
    c_o2_i1_r_r_r_trace,
    c_o2_i2_r_r_r_r_trace,
    c_o0_i3_rz_rz_r_trace,
};
#undef C_O0_I1
#undef C_O0_I2
#undef C_O0_I3
#undef C_O0_I4
#undef C_O1_I1
#undef C_O1_I2
#undef C_O1_I3
#undef C_O1_I4
#undef C_N1_I2
#undef C_N1O1_I1
#undef C_N2_I1
#undef C_O2_I1
#undef C_O2_I2
#undef C_O2_I3
#undef C_O2_I4
#undef C_N1_O1_I4

#define C_O0_I1(I1)                     { 0, 1, { #I1 } },
#define C_O0_I2(I1, I2)                 { 0, 2, { #I1, #I2 } },
#define C_O0_I3(I1, I2, I3)             { 0, 3, { #I1, #I2, #I3 } },
#define C_O0_I4(I1, I2, I3, I4)         { 0, 4, { #I1, #I2, #I3, #I4 } },
#define C_O1_I1(O1, I1)                 { 1, 1, { #O1, #I1 } },
#define C_O1_I2(O1, I1, I2)             { 1, 2, { #O1, #I1, #I2 } },
#define C_O1_I3(O1, I1, I2, I3)         { 1, 3, { #O1, #I1, #I2, #I3 } },
#define C_O1_I4(O1, I1, I2, I3, I4)     { 1, 4, { #O1, #I1, #I2, #I3, #I4 } },
#define C_N1_I2(O1, I1, I2)             { 1, 2, { "&" #O1, #I1, #I2 } },
#define C_N1O1_I1(O1, O2, I1)           { 2, 1, { "&" #O1, #O2, #I1 } },
#define C_N2_I1(O1, O2, I1)             { 2, 1, { "&" #O1, "&" #O2, #I1 } },
#define C_O2_I1(O1, O2, I1)             { 2, 1, { #O1, #O2, #I1 } },
#define C_O2_I2(O1, O2, I1, I2)         { 2, 2, { #O1, #O2, #I1, #I2 } },
#define C_O2_I3(O1, O2, I1, I2, I3)     { 2, 3, { #O1, #O2, #I1, #I2, #I3 } },
#define C_O2_I4(O1, O2, I1, I2, I3, I4) { 2, 4, { #O1, #O2, #I1, #I2, #I3, #I4 } },
#define C_N1_O1_I4(O1, O2, I1, I2, I3, I4) { 2, 4, { "&" #O1, #O2, #I1, #I2, #I3, #I4 } },
static const TCGConstraintSet rv_backend_constraint_sets[] = {
#include "tcg/riscv/tcg-target-con-set.h"
    { 2, 1, { "r", "r", "r" } },
    { 2, 2, { "r", "r", "r", "r" } },
    { 0, 3, { "rz", "rz", "r" } },
};
#undef C_O0_I1
#undef C_O0_I2
#undef C_O0_I3
#undef C_O0_I4
#undef C_O1_I1
#undef C_O1_I2
#undef C_O1_I3
#undef C_O1_I4
#undef C_N1_I2
#undef C_N1O1_I1
#undef C_N2_I1
#undef C_O2_I1
#undef C_O2_I2
#undef C_O2_I3
#undef C_O2_I4
#undef C_N1_O1_I4
#undef RV_C_PFX1
#undef RV_C_PFX2
#undef RV_C_PFX3
#undef RV_C_PFX4
#undef RV_C_PFX5
#undef RV_C_PFX6

static TCGArgConstraint
rv_backend_all_cts[ARRAY_SIZE(rv_backend_constraint_sets)][TCG_MAX_OP_ARGS];

static bool rv_backend_parse_constraint(TCGArgConstraint *arg_ct, char ch)
{
    switch (ch) {
    case 'r':
        arg_ct->regs |= RV_ALL_GENERAL_REGS;
        return true;
    case 'v':
        arg_ct->regs |= RV_ALL_VECTOR_REGS;
        return true;
    case 'I':
        arg_ct->ct |= RV_TCG_CT_CONST_S12;
        return true;
    case 'K':
        arg_ct->ct |= RV_TCG_CT_CONST_S5;
        return true;
    case 'L':
        arg_ct->ct |= RV_TCG_CT_CONST_CMP_VI;
        return true;
    case 'M':
        arg_ct->ct |= RV_TCG_CT_CONST_M12;
        return true;
    case 'z':
        /*
         * The trace backend always targets RISC-V semantics even when the host
         * build lacks TCG_REG_ZERO. Track this locally so shared regalloc can
         * still accept literal zero operands for rz constraints.
         */
        arg_ct->ct |= RV_TCG_CT_CONST_ZERO;
        return true;
    default:
        return false;
    }
}

static void rv_trace_out_opc_reg(TCGContext *s, uint32_t opc,
                                 TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    RvTraceBuildState *st = rv_trace_build_state;

    (void)s;
    g_assert(st != NULL);
    rv_emit(st->buf, &st->pos, st->buf_size, rv_encode_r(opc, rd, rs1, rs2));
}

static void rv_trace_out_opc_imm(TCGContext *s, uint32_t opc,
                                 TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    RvTraceBuildState *st = rv_trace_build_state;

    (void)s;
    g_assert(st != NULL);
    rv_emit(st->buf, &st->pos, st->buf_size, rv_encode_i(opc, rd, rs1, imm));
}

static void rv_trace_out_opc_store(TCGContext *s, uint32_t opc,
                                   TCGReg rs1, TCGReg rs2, uint32_t imm)
{
    RvTraceBuildState *st = rv_trace_build_state;

    (void)s;
    g_assert(st != NULL);
    rv_emit(st->buf, &st->pos, st->buf_size, rv_encode_s(opc, rs1, rs2, imm));
}

static void rv_trace_tgen_add(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, type == TCG_TYPE_I32 ? RV_OPC_ADDW : RV_OPC_ADD,
                         rd, rs1, rs2);
}

static void rv_trace_tgen_addi(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    rv_trace_out_opc_imm(s, type == TCG_TYPE_I32 ? RV_OPC_ADDIW : RV_OPC_ADDI,
                         rd, rs1, imm);
}

static void rv_trace_tgen_sub(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, type == TCG_TYPE_I32 ? RV_OPC_SUBW : RV_OPC_SUB,
                         rd, rs1, rs2);
}

static void rv_trace_tgen_mul(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, type == TCG_TYPE_I32 ? RV_OPC_MULW : RV_OPC_MUL,
                         rd, rs1, rs2);
}

static void rv_trace_tgen_and(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, RV_OPC_AND, rd, rs1, rs2);
    if (type == TCG_TYPE_I32) {
        rv_trace_out_opc_imm(s, RV_OPC_ADDIW, rd, rd, 0);
    }
}

static void rv_trace_tgen_andi(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    rv_trace_out_opc_imm(s, RV_OPC_ANDI, rd, rs1, imm);
    if (type == TCG_TYPE_I32) {
        rv_trace_out_opc_imm(s, RV_OPC_ADDIW, rd, rd, 0);
    }
}

static void rv_trace_tgen_or(TCGContext *s, TCGType type,
                             TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, RV_OPC_OR, rd, rs1, rs2);
    if (type == TCG_TYPE_I32) {
        rv_trace_out_opc_imm(s, RV_OPC_ADDIW, rd, rd, 0);
    }
}

static void rv_trace_tgen_ori(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    rv_trace_out_opc_imm(s, RV_OPC_ORI, rd, rs1, imm);
    if (type == TCG_TYPE_I32) {
        rv_trace_out_opc_imm(s, RV_OPC_ADDIW, rd, rd, 0);
    }
}

static void rv_trace_tgen_xor(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, RV_OPC_XOR, rd, rs1, rs2);
    if (type == TCG_TYPE_I32) {
        rv_trace_out_opc_imm(s, RV_OPC_ADDIW, rd, rd, 0);
    }
}

static void rv_trace_tgen_xori(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    rv_trace_out_opc_imm(s, RV_OPC_XORI, rd, rs1, imm);
    if (type == TCG_TYPE_I32) {
        rv_trace_out_opc_imm(s, RV_OPC_ADDIW, rd, rd, 0);
    }
}

static void rv_trace_tgen_shl(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, type == TCG_TYPE_I32 ? RV_OPC_SLLW : RV_OPC_SLL,
                         rd, rs1, rs2);
}

static void rv_trace_tgen_shli(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    unsigned mask = type == TCG_TYPE_I32 ? 31 : 63;

    rv_trace_out_opc_imm(s, type == TCG_TYPE_I32 ? RV_OPC_SLLIW : RV_OPC_SLLI,
                         rd, rs1, imm & mask);
}

static void rv_trace_tgen_shr(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, type == TCG_TYPE_I32 ? RV_OPC_SRLW : RV_OPC_SRL,
                         rd, rs1, rs2);
}

static void rv_trace_tgen_shri(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    unsigned mask = type == TCG_TYPE_I32 ? 31 : 63;

    rv_trace_out_opc_imm(s, type == TCG_TYPE_I32 ? RV_OPC_SRLIW : RV_OPC_SRLI,
                         rd, rs1, imm & mask);
}

static void rv_trace_tgen_sar(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, type == TCG_TYPE_I32 ? RV_OPC_SRAW : RV_OPC_SRA,
                         rd, rs1, rs2);
}

static void rv_trace_tgen_sari(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    unsigned mask = type == TCG_TYPE_I32 ? 31 : 63;

    rv_trace_out_opc_imm(s, type == TCG_TYPE_I32 ? RV_OPC_SRAIW : RV_OPC_SRLI,
                         rd, rs1,
                         type == TCG_TYPE_I32 ? (imm & mask)
                                              : ((imm & mask) | 0x400));
}

static void rv_trace_tgen_divs(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, type == TCG_TYPE_I32 ? RV_OPC_DIVW : RV_OPC_DIV,
                         rd, rs1, rs2);
}

static void rv_trace_tgen_divu(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, type == TCG_TYPE_I32 ? RV_OPC_DIVUW : RV_OPC_DIVU,
                         rd, rs1, rs2);
}

static void rv_trace_tgen_rems(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, type == TCG_TYPE_I32 ? RV_OPC_REMW : RV_OPC_REM,
                         rd, rs1, rs2);
}

static void rv_trace_tgen_remu(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_out_opc_reg(s, type == TCG_TYPE_I32 ? RV_OPC_REMUW : RV_OPC_REMU,
                         rd, rs1, rs2);
}

static void rv_trace_emit_rotate_sequence(TCGContext *s, bool is_32bit,
                                          bool is_left, TCGReg rd, TCGReg rs,
                                          TCGArg sh, bool c_sh)
{
    uint32_t insns[24];
    int n = 0;
    int sh_reg = sh;

    if (c_sh) {
        sh_reg = TRACERTL_RV_ALT_SCRATCH_REG;
        n = tracertl_rv_emit_load_imm_sequence(insns, ARRAY_SIZE(insns),
                                               sh_reg, sh);
        g_assert_cmpint(n, >, 0);
    }
    n += tracertl_rv_emit_rotate_sequence(insns + n, ARRAY_SIZE(insns) - n,
                                          is_32bit, is_left, rd, rs, sh_reg);
    g_assert_cmpint(n, >, 0);
    rv_emit_shared_sequence(rv_trace_build_state->buf, &rv_trace_build_state->pos,
                            rv_trace_build_state->buf_size, n, insns);
    (void)s;
}

static void rv_trace_tgen_rotl(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_emit_rotate_sequence(s, type == TCG_TYPE_I32, true,
                                  rd, rs1, rs2, false);
}

static void rv_trace_tgen_rotli(TCGContext *s, TCGType type,
                                TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    rv_trace_emit_rotate_sequence(s, type == TCG_TYPE_I32, true,
                                  rd, rs1, imm, true);
}

static void rv_trace_tgen_rotr(TCGContext *s, TCGType type,
                               TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_emit_rotate_sequence(s, type == TCG_TYPE_I32, false,
                                  rd, rs1, rs2, false);
}

static void rv_trace_tgen_rotri(TCGContext *s, TCGType type,
                                TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    rv_trace_emit_rotate_sequence(s, type == TCG_TYPE_I32, false,
                                  rd, rs1, imm, true);
}

static void rv_trace_tgen_neg(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs)
{
    rv_trace_out_opc_reg(s, type == TCG_TYPE_I32 ? RV_OPC_SUBW : RV_OPC_SUB,
                         rd, 0, rs);
}

static void rv_trace_tgen_not(TCGContext *s, TCGType type,
                              TCGReg rd, TCGReg rs)
{
    rv_trace_out_opc_imm(s, RV_OPC_XORI, rd, rs, -1);
    if (type == TCG_TYPE_I32) {
        rv_trace_out_opc_imm(s, RV_OPC_ADDIW, rd, rd, 0);
    }
}

static void rv_trace_tgen_cltz_common(TCGContext *s, TCGType type,
                                      uint32_t opc32, uint32_t opc64,
                                      TCGReg rd, TCGReg rs1,
                                      TCGArg src2, bool c_src2)
{
    RvTraceBuildState *st = rv_trace_build_state;
    uint32_t zero_insns[16];
    int zero_n;
    int zero_result = type == TCG_TYPE_I32 ? 32 : 64;

    g_assert(st != NULL);

    if (c_src2 && src2 == zero_result) {
        rv_trace_out_opc_imm(s, type == TCG_TYPE_I32 ? opc32 : opc64,
                             rd, rs1, 0);
        return;
    }

    /*
     * TCG clz/ctz carry an explicit fallback result for zero inputs.
     * RISC-V Zbb returns XLEN directly, so synthesize the fallback path when
     * the requested zero-result differs from the architectural default.
     */
    zero_n = tracertl_rv_emit_move_sequence(zero_insns, ARRAY_SIZE(zero_insns),
                                            rd,
                                            rv_reg_or_const_operand(src2,
                                                                    c_src2));
    g_assert_cmpint(zero_n, >, 0);

    rv_emit(st->buf, &st->pos, st->buf_size,
            rv_encode_sb(RV_OPC_BEQ, rs1, 0, 12));
    rv_trace_out_opc_imm(s, type == TCG_TYPE_I32 ? opc32 : opc64, rd, rs1, 0);
    rv_emit(st->buf, &st->pos, st->buf_size,
            rv_encode_uj(RV_OPC_JAL, 0, (zero_n + 1) * 4));
    rv_emit_shared_sequence(st->buf, &st->pos, st->buf_size, zero_n,
                            zero_insns);
}

static void rv_trace_tgen_clz_rrr(TCGContext *s, TCGType type,
                                  TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_tgen_cltz_common(s, type, 0x6000101b, 0x60001013,
                              rd, rs1, rs2, false);
}

static void rv_trace_tgen_clz_rri(TCGContext *s, TCGType type,
                                  TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    rv_trace_tgen_cltz_common(s, type, 0x6000101b, 0x60001013,
                              rd, rs1, imm, true);
}

static void rv_trace_tgen_ctz_rrr(TCGContext *s, TCGType type,
                                  TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    rv_trace_tgen_cltz_common(s, type, 0x6010101b, 0x60101013,
                              rd, rs1, rs2, false);
}

static void rv_trace_tgen_ctz_rri(TCGContext *s, TCGType type,
                                  TCGReg rd, TCGReg rs1, tcg_target_long imm)
{
    rv_trace_tgen_cltz_common(s, type, 0x6010101b, 0x60101013,
                              rd, rs1, imm, true);
}

static void rv_trace_tgen_ctpop(TCGContext *s, TCGType type,
                                TCGReg rd, TCGReg rs)
{
    rv_trace_out_opc_imm(s, type == TCG_TYPE_I32 ? 0x6020101b : 0x60201013,
                         rd, rs, 0);
}

static void rv_trace_tgen_ext32s(TCGContext *s, TCGType type,
                                 TCGReg rd, TCGReg rs)
{
    (void)type;
    rv_trace_out_opc_imm(s, RV_OPC_ADDIW, rd, rs, 0);
}

static void rv_trace_tgen_ext32u(TCGContext *s, TCGType type,
                                 TCGReg rd, TCGReg rs)
{
    (void)type;
    rv_trace_out_opc_imm(s, RV_OPC_SLLI, rd, rs, 32);
    rv_trace_out_opc_imm(s, RV_OPC_SRLI, rd, rd, 32);
}

static void rv_trace_tgen_extrh(TCGContext *s, TCGType type,
                                TCGReg rd, TCGReg rs)
{
    (void)type;
    rv_trace_out_opc_imm(s, RV_OPC_SRLI, rd, rs, 32);
}

static void rv_trace_tgen_qemu_ld(TCGContext *s, TCGType type,
                                  TCGReg rd, TCGReg addr, MemOpIdx oi)
{
    uint32_t load_opc;
    MemOp mop = get_memop(oi);

    (void)type;
    switch (mop & MO_SIZE) {
    case MO_8:
        load_opc = (mop & MO_SIGN) ? RV_OPC_LB : RV_OPC_LBU;
        break;
    case MO_16:
        load_opc = (mop & MO_SIGN) ? RV_OPC_LH : RV_OPC_LHU;
        break;
    case MO_32:
        load_opc = (mop & MO_SIGN) ? RV_OPC_LW : RV_OPC_LWU;
        break;
    case MO_64:
    default:
        load_opc = RV_OPC_LD;
        break;
    }
    rv_trace_out_opc_imm(s, load_opc, rd, addr, 0);
}

static void rv_trace_tgen_qemu_st(TCGContext *s, TCGType type,
                                  TCGReg rs, TCGReg addr, MemOpIdx oi)
{
    uint32_t store_opc;
    MemOp mop = get_memop(oi);

    (void)type;
    switch (mop & MO_SIZE) {
    case MO_8:
        store_opc = RV_OPC_SB;
        break;
    case MO_16:
        store_opc = RV_OPC_SH;
        break;
    case MO_32:
        store_opc = RV_OPC_SW;
        break;
    case MO_64:
    default:
        store_opc = RV_OPC_SD;
        break;
    }
    rv_trace_out_opc_store(s, store_opc, addr, rs, 0);
}

static bool rv_backend_const_match(int64_t val, int ct, TCGType type,
                                   TCGCond cond, int vece)
{
    (void)cond;
    if (ct & TCG_CT_CONST) {
        return true;
    }
    if (type >= TCG_TYPE_V64) {
        val >>= (-8 << vece) & 63;
    }
    if ((ct & RV_TCG_CT_CONST_S12) && val >= -0x800 && val <= 0x7ff) {
        return true;
    }
    if ((ct & RV_TCG_CT_CONST_M12) && val >= -0x7ff && val <= 0x7ff) {
        return true;
    }
    if ((ct & RV_TCG_CT_CONST_S5) && val >= -0x10 && val <= 0x0f) {
        return true;
    }
    if ((ct & RV_TCG_CT_CONST_CMP_VI) && val >= -0x10 && val <= 0x10) {
        return true;
    }
    if ((ct & RV_TCG_CT_CONST_ZERO) && val == 0) {
        return true;
    }
    return false;
}

static void rv_trace_emit_insn_words(const uint32_t *words, int nwords,
                                     qemu_plugin_rv_trace_tag tag,
                                     QemuPluginTbRvOrigin origin)
{
    qemu_plugin_rv_trace_tag saved_tag = rv_current_tag;
    QemuPluginTbRvOrigin saved_origin = rv_current_origin;
    RvTraceBuildState *st = rv_trace_build_state;

    g_assert(st != NULL);
    rv_current_tag = tag;
    rv_current_origin = origin;
    for (int i = 0; i < nwords; i++) {
        rv_emit(st->buf, &st->pos, st->buf_size, words[i]);
    }
    rv_current_tag = saved_tag;
    rv_current_origin = saved_origin;
}

static bool rv_backend_out_mov(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    (void)type;
    if (ret == arg) {
        return true;
    }
    rv_trace_out_opc_imm(s, RV_OPC_ADDI, ret, arg, 0);
    return true;
}

static void rv_backend_out_movi(TCGContext *s, TCGType type,
                                TCGReg ret, tcg_target_long arg)
{
    uint32_t words[16];
    int nwords;

    (void)s;
    (void)type;
    nwords = tracertl_rv_emit_load_imm_sequence(words, ARRAY_SIZE(words),
                                                ret, (uint64_t)arg);
    rv_trace_emit_insn_words(words, nwords, QEMU_PLUGIN_RV_TAG_NONE,
                             rv_current_origin);
}

static void rv_backend_out_ext8s(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    (void)type;
    rv_trace_out_opc_imm(s, RV_OPC_SLLIW, ret, arg, 24);
    rv_trace_out_opc_imm(s, RV_OPC_SRAIW, ret, ret, 24);
}

static void rv_backend_out_ext16s(TCGContext *s, TCGType type, TCGReg ret, TCGReg arg)
{
    (void)type;
    rv_trace_out_opc_imm(s, RV_OPC_SLLIW, ret, arg, 16);
    rv_trace_out_opc_imm(s, RV_OPC_SRAIW, ret, ret, 16);
}

static void rv_backend_out_ext8u(TCGContext *s, TCGReg ret, TCGReg arg)
{
    rv_trace_out_opc_imm(s, RV_OPC_ANDI, ret, arg, 0xff);
}

static void rv_backend_out_ext16u(TCGContext *s, TCGReg ret, TCGReg arg)
{
    rv_trace_out_opc_imm(s, RV_OPC_SLLIW, ret, arg, 16);
    rv_trace_out_opc_imm(s, RV_OPC_SRLIW, ret, ret, 16);
}

static void rv_backend_out_ext32s(TCGContext *s, TCGReg ret, TCGReg arg)
{
    rv_trace_out_opc_imm(s, RV_OPC_ADDIW, ret, arg, 0);
}

static void rv_backend_out_ext32u(TCGContext *s, TCGReg ret, TCGReg arg)
{
    rv_trace_out_opc_imm(s, RV_OPC_SLLI, ret, arg, 32);
    rv_trace_out_opc_imm(s, RV_OPC_SRLI, ret, ret, 32);
}

static void rv_backend_out_exts_i32_i64(TCGContext *s, TCGReg ret, TCGReg arg)
{
    if (ret != arg) {
        rv_backend_out_ext32s(s, ret, arg);
    }
}

static void rv_backend_out_extu_i32_i64(TCGContext *s, TCGReg ret, TCGReg arg)
{
    rv_backend_out_ext32u(s, ret, arg);
}

static void rv_backend_out_extrl_i64_i32(TCGContext *s, TCGReg ret, TCGReg arg)
{
    rv_backend_out_ext32s(s, ret, arg);
}

static void rv_backend_out_addi_ptr(TCGContext *s, TCGReg ret, TCGReg arg1,
                                    tcg_target_long arg2)
{
    if (tracertl_rv_imm12_p(arg2)) {
        rv_trace_out_opc_imm(s, RV_OPC_ADDI, ret, arg1, arg2);
        return;
    }
    rv_backend_out_movi(s, TCG_TYPE_PTR, TRACERTL_RV_SCRATCH_REG, arg2);
    rv_trace_out_opc_reg(s, RV_OPC_ADD, ret, arg1, TRACERTL_RV_SCRATCH_REG);
}

static void rv_backend_out_ld(TCGContext *s, TCGType type, TCGReg ret,
                              TCGReg arg1, intptr_t arg2)
{
    uint32_t opc = type == TCG_TYPE_I32 ? RV_OPC_LW : RV_OPC_LD;

    if (tracertl_rv_imm12_p(arg2)) {
        rv_trace_out_opc_imm(s, opc, ret, arg1, arg2);
        return;
    }
    rv_backend_out_movi(s, TCG_TYPE_PTR, TRACERTL_RV_SCRATCH_REG, arg2);
    rv_trace_out_opc_reg(s, RV_OPC_ADD, TRACERTL_RV_SCRATCH_REG, arg1,
                         TRACERTL_RV_SCRATCH_REG);
    rv_trace_out_opc_imm(s, opc, ret, TRACERTL_RV_SCRATCH_REG, 0);
}

static void rv_backend_out_st(TCGContext *s, TCGType type, TCGReg arg,
                              TCGReg arg1, intptr_t arg2)
{
    uint32_t opc = type == TCG_TYPE_I32 ? RV_OPC_SW : RV_OPC_SD;

    if (tracertl_rv_imm12_p(arg2)) {
        rv_trace_out_opc_store(s, opc, arg1, arg, arg2);
        return;
    }
    rv_backend_out_movi(s, TCG_TYPE_PTR, TRACERTL_RV_SCRATCH_REG, arg2);
    rv_trace_out_opc_reg(s, RV_OPC_ADD, TRACERTL_RV_SCRATCH_REG, arg1,
                         TRACERTL_RV_SCRATCH_REG);
    rv_trace_out_opc_store(s, opc, TRACERTL_RV_SCRATCH_REG, arg, 0);
}

static bool rv_backend_out_sti(TCGContext *s, TCGType type, TCGArg val,
                               TCGReg base, intptr_t ofs)
{
    if (!tracertl_rv_imm12_p((tcg_target_long)val)) {
        return false;
    }
    rv_backend_out_movi(s, type, TRACERTL_RV_SCRATCH_REG, val);
    rv_backend_out_st(s, type, TRACERTL_RV_SCRATCH_REG, base, ofs);
    return true;
}

static void rv_backend_out_ld_opc(TCGContext *s, uint32_t opc, TCGReg ret,
                                  TCGReg base, intptr_t ofs)
{
    if (tracertl_rv_imm12_p(ofs)) {
        rv_trace_out_opc_imm(s, opc, ret, base, ofs);
        return;
    }
    rv_backend_out_movi(s, TCG_TYPE_PTR, TRACERTL_RV_SCRATCH_REG, ofs);
    rv_trace_out_opc_reg(s, RV_OPC_ADD, TRACERTL_RV_SCRATCH_REG, base,
                         TRACERTL_RV_SCRATCH_REG);
    rv_trace_out_opc_imm(s, opc, ret, TRACERTL_RV_SCRATCH_REG, 0);
}

static void rv_backend_out_st_opc(TCGContext *s, uint32_t opc, TCGReg data,
                                  TCGReg base, intptr_t ofs)
{
    if (tracertl_rv_imm12_p(ofs)) {
        rv_trace_out_opc_store(s, opc, base, data, ofs);
        return;
    }
    rv_backend_out_movi(s, TCG_TYPE_PTR, TRACERTL_RV_SCRATCH_REG, ofs);
    rv_trace_out_opc_reg(s, RV_OPC_ADD, TRACERTL_RV_SCRATCH_REG, base,
                         TRACERTL_RV_SCRATCH_REG);
    rv_trace_out_opc_store(s, opc, TRACERTL_RV_SCRATCH_REG, data, 0);
}

static void rv_backend_out_store_const_opc(TCGContext *s, TCGType type,
                                           tcg_target_long val, TCGReg base,
                                           intptr_t ofs, uint32_t opc)
{
    TCGReg data = 0;

    if (val != 0) {
        data = TRACERTL_RV_SCRATCH_REG;
        rv_backend_out_movi(s, type, data, val);
    }
    rv_backend_out_st_opc(s, opc, data, base, ofs);
}

static void rv_backend_out_ld8u(TCGContext *s, TCGType type, TCGReg ret,
                                TCGReg base, intptr_t ofs)
{
    (void)type;
    rv_backend_out_ld_opc(s, RV_OPC_LBU, ret, base, ofs);
}

static void rv_backend_out_ld8s(TCGContext *s, TCGType type, TCGReg ret,
                                TCGReg base, intptr_t ofs)
{
    (void)type;
    rv_backend_out_ld_opc(s, RV_OPC_LB, ret, base, ofs);
}

static void rv_backend_out_ld16u(TCGContext *s, TCGType type, TCGReg ret,
                                 TCGReg base, intptr_t ofs)
{
    (void)type;
    rv_backend_out_ld_opc(s, RV_OPC_LHU, ret, base, ofs);
}

static void rv_backend_out_ld16s(TCGContext *s, TCGType type, TCGReg ret,
                                 TCGReg base, intptr_t ofs)
{
    (void)type;
    rv_backend_out_ld_opc(s, RV_OPC_LH, ret, base, ofs);
}

static void rv_backend_out_ld32u(TCGContext *s, TCGType type, TCGReg ret,
                                 TCGReg base, intptr_t ofs)
{
    (void)type;
    rv_backend_out_ld_opc(s, RV_OPC_LWU, ret, base, ofs);
}

static void rv_backend_out_ld32s(TCGContext *s, TCGType type, TCGReg ret,
                                 TCGReg base, intptr_t ofs)
{
    (void)type;
    rv_backend_out_ld_opc(s, RV_OPC_LW, ret, base, ofs);
}

static void rv_backend_out_st8_r(TCGContext *s, TCGType type, TCGReg data,
                                 TCGReg base, intptr_t ofs)
{
    (void)type;
    rv_backend_out_st_opc(s, RV_OPC_SB, data, base, ofs);
}

static void rv_backend_out_st8_i(TCGContext *s, TCGType type,
                                 tcg_target_long val, TCGReg base,
                                 intptr_t ofs)
{
    rv_backend_out_store_const_opc(s, type, val, base, ofs, RV_OPC_SB);
}

static void rv_backend_out_st16_r(TCGContext *s, TCGType type, TCGReg data,
                                  TCGReg base, intptr_t ofs)
{
    (void)type;
    rv_backend_out_st_opc(s, RV_OPC_SH, data, base, ofs);
}

static void rv_backend_out_st16_i(TCGContext *s, TCGType type,
                                  tcg_target_long val, TCGReg base,
                                  intptr_t ofs)
{
    rv_backend_out_store_const_opc(s, type, val, base, ofs, RV_OPC_SH);
}

static void rv_backend_out_st_i(TCGContext *s, TCGType type,
                                tcg_target_long val, TCGReg base,
                                intptr_t ofs)
{
    uint32_t opc = type == TCG_TYPE_I32 ? RV_OPC_SW : RV_OPC_SD;

    rv_backend_out_store_const_opc(s, type, val, base, ofs, opc);
}

static bool rv_backend_out_xchg(TCGContext *s, TCGType type, TCGReg r1, TCGReg r2)
{
    (void)s;
    (void)type;
    (void)r1;
    (void)r2;
    return false;
}

static void rv_trace_note_helper_slot_current(void)
{
    RvTraceBuildState *st = rv_trace_build_state;

    if (st && st->insn_meta && st->guest_idx >= 0 &&
        st->insn_meta[st->guest_idx].helper_idx < 0) {
        st->insn_meta[st->guest_idx].helper_idx =
            (int8_t)(st->pos - st->insn_offsets[st->guest_idx]);
    }
}

static void rv_trace_note_branch_slot_current(void)
{
    RvTraceBuildState *st = rv_trace_build_state;

    if (st && st->insn_meta && st->guest_idx >= 0 &&
        st->insn_meta[st->guest_idx].branch_idx < 0) {
        st->insn_meta[st->guest_idx].branch_idx =
            (int8_t)(st->pos - st->insn_offsets[st->guest_idx]);
    }
    if (st) {
        st->guest_has_branch = true;
    }
}

typedef struct RvTraceBrcondInfo {
    uint32_t opc;
    bool swap;
} RvTraceBrcondInfo;

static const RvTraceBrcondInfo rv_trace_brcond_info[] = {
    [TCG_COND_EQ] =  { RV_OPC_BEQ,  false },
    [TCG_COND_NE] =  { RV_OPC_BNE,  false },
    [TCG_COND_LT] =  { RV_OPC_BLT,  false },
    [TCG_COND_GE] =  { RV_OPC_BGE,  false },
    [TCG_COND_LE] =  { RV_OPC_BGE,  true  },
    [TCG_COND_GT] =  { RV_OPC_BLT,  true  },
    [TCG_COND_LTU] = { RV_OPC_BLTU, false },
    [TCG_COND_GEU] = { RV_OPC_BGEU, false },
    [TCG_COND_LEU] = { RV_OPC_BGEU, true  },
    [TCG_COND_GTU] = { RV_OPC_BLTU, true  },
};

static TCGReg rv_backend_call_oarg_reg(int kind, int slot);

static void rv_backend_emit_helper_slot_origin(TCGContext *s,
                                               QemuPluginTbRvOrigin origin)
{
    QemuPluginTbRvOrigin prev_origin = tcg_rv_trace_set_origin(origin);
    RvTraceBuildState *st = rv_trace_build_state;

    (void)s;
    g_assert(st != NULL);

    rv_trace_note_helper_slot_current();
    rv_emit(st->buf, &st->pos, st->buf_size,
            rv_encode_i(RV_OPC_ADDI, TRACERTL_RV_SCRATCH_REG,
                        TRACERTL_RV_SCRATCH_REG, 0));
    tcg_rv_trace_restore_origin(prev_origin);
}

static void rv_backend_emit_helper_slot(TCGContext *s)
{
    rv_backend_emit_helper_slot_origin(s,
                                       QEMU_PLUGIN_TB_RV_ORIGIN_HELPER_PRIVATE);
}

static void rv_backend_emit_translated_callback_slot(TCGContext *s)
{
    rv_backend_emit_helper_slot(s);
}

static void rv_backend_emit_lookup_tb_ptr(TCGContext *s)
{
    RvTraceBuildState *st = rv_trace_build_state;
    TracertlRvCoreTraceSink sink;
    int target_reg = rv_backend_call_oarg_reg(TCG_CALL_RET_NORMAL, 0);
    int start;

    (void)s;
    g_assert(st != NULL);
    start = st->pos;
    sink = rv_trace_core_sink_current(st);
    tracertl_rv_core_emit_lookup_tb_ptr(&sink, target_reg);
    if (st->pos > start) {
        rv_trace_note_current_tcg_op_guest_output();
    }
    st->guest_helper_emitted = true;
}

static void rv_backend_out_call(TCGContext *s, const tcg_insn_unit *target,
                                const TCGHelperInfo *info)
{
    const char *name = rv_trace_helper_name(target, info);
    RvTraceBuildState *st = rv_trace_build_state;
    uint8_t bytes[16] = { 0 };
    size_t copy_size = 0;
    const char *counter_name = name;
    bool is_x86_guest = rv_target_is_x86_guest();
    bool is_aarch64_guest = rv_target_is_aarch64_guest();
    bool is_system_emulation = rv_target_is_system_emulation();

    /* Plugin calls use a template TCGHelperInfo with a different function
     * pointer (the same distinction used by tcg_dump_ops). They must never
     * replace guest semantics or suppress subsequent guest temp definitions.
     */
    if (info != NULL && (const void *)target != info->func) {
        rv_backend_emit_helper_slot(s);
        return;
    }

    if (!rv_target_is_native_riscv_guest()) {
        copy_size = rv_trace_copy_current_guest_bytes(bytes, sizeof(bytes));
        if (counter_name == NULL) {
            counter_name = rv_trace_helper_counter_fallback_name(
                target, info, "translated_residual");
        }
    }

    if (!(name == NULL && rv_helper_target_is_shared_object(target))) {
        rv_trace_counter_note_helper(target, info, counter_name);
    }

    if (rv_helper_name_is_lookup_tb_ptr(name)) {
        rv_backend_emit_lookup_tb_ptr(s);
        return;
    }

    if (rv_helper_name_is_private(name)) {
        rv_backend_emit_helper_slot(s);
        return;
    }

    if (!rv_target_is_native_riscv_guest() && st != NULL &&
        !st->guest_helper_emitted) {
        if (st->guest_idx < 0) {
            return;
        }
        if (copy_size == 0 &&
            name == NULL && rv_helper_target_is_shared_object(target)) {
            rv_backend_emit_translated_callback_slot(s);
            st->guest_helper_emitted = true;
            return;
        }
        rv_backend_emit_translated_helper_from_guest(s, name, bytes, copy_size,
                                                     is_x86_guest,
                                                     is_aarch64_guest,
                                                     is_system_emulation);
    }
}

static void rv_backend_out_goto_ptr(TCGContext *s, TCGReg dest)
{
    QemuPluginTbRvOrigin prev_origin =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
    qemu_plugin_rv_trace_tag prev_tag =
        rv_set_current_tag(QEMU_PLUGIN_RV_TAG_INDIRECT_BRANCH_PLACEHOLDER);
    RvTraceBuildState *st = rv_trace_build_state;

    (void)s;
    g_assert(st != NULL);

    rv_trace_note_branch_slot_current();
    rv_emit(st->buf, &st->pos, st->buf_size,
            rv_encode_i(0x67 /* JALR */, 0, dest, 0));
    rv_restore_current_tag(prev_tag);
    tcg_rv_trace_restore_origin(prev_origin);
}

static void rv_backend_unreachable_set_carry(TCGContext *s)
{
    (void)s;
    g_assert_not_reached();
}

static void rv_backend_unreachable_set_borrow(TCGContext *s)
{
    (void)s;
    g_assert_not_reached();
}

static bool rv_backend_unreachable_dup_vec(TCGContext *s, TCGType type,
                                           unsigned vece, TCGReg dst, TCGReg src)
{
    (void)s;
    (void)type;
    (void)vece;
    (void)dst;
    (void)src;
    g_assert_not_reached();
}

static bool rv_backend_unreachable_dupm_vec(TCGContext *s, TCGType type,
                                            unsigned vece, TCGReg dst,
                                            TCGReg base, intptr_t offset)
{
    (void)s;
    (void)type;
    (void)vece;
    (void)dst;
    (void)base;
    (void)offset;
    g_assert_not_reached();
}

static void rv_backend_unreachable_dupi_vec(TCGContext *s, TCGType type,
                                            unsigned vece, TCGReg dst, int64_t arg)
{
    (void)s;
    (void)type;
    (void)vece;
    (void)dst;
    (void)arg;
    g_assert_not_reached();
}

static void rv_backend_unreachable_vec_op(TCGContext *s, TCGOpcode opc,
                                          unsigned vecl, unsigned vece,
                                          const TCGArg *args,
                                          const int *const_args)
{
    (void)s;
    (void)opc;
    (void)vecl;
    (void)vece;
    (void)args;
    (void)const_args;
    g_assert_not_reached();
}

static TCGReg rv_backend_call_oarg_reg(int kind, int slot)
{
    g_assert(kind == TCG_CALL_RET_NORMAL);
    g_assert(slot >= 0 && slot <= 1);
    return 10 + slot;
}

static TCGConstraintSetIndex rv_backend_target_op_def(TCGOpcode op,
                                                      TCGType type,
                                                      unsigned flags)
{
    (void)op;
    (void)type;
    (void)flags;
    return C_NotImplemented;
}

#define DEFINE_RV_BACKEND_GUEST_BINARY(NAME)                                 \
    static void rv_backend_guest_##NAME##_rrr(TCGContext *s, TCGType type,   \
                                              TCGReg rd, TCGReg rs1,          \
                                              TCGReg rs2)                     \
    {                                                                        \
        QemuPluginTbRvOrigin prev =                                          \
            tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);         \
        rv_trace_tgen_##NAME(s, type, rd, rs1, rs2);                         \
        tcg_rv_trace_restore_origin(prev);                                   \
    }                                                                        \
    static void rv_backend_guest_##NAME##_rri(TCGContext *s, TCGType type,   \
                                              TCGReg rd, TCGReg rs1,          \
                                              tcg_target_long imm)            \
    {                                                                        \
        QemuPluginTbRvOrigin prev =                                          \
            tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);         \
        rv_trace_tgen_##NAME##i(s, type, rd, rs1, imm);                      \
        tcg_rv_trace_restore_origin(prev);                                   \
    }

#define DEFINE_RV_BACKEND_GUEST_RRR(NAME)                                    \
    static void rv_backend_guest_##NAME##_rrr(TCGContext *s, TCGType type,   \
                                              TCGReg rd, TCGReg rs1,          \
                                              TCGReg rs2)                     \
    {                                                                        \
        QemuPluginTbRvOrigin prev =                                          \
            tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);         \
        rv_trace_tgen_##NAME(s, type, rd, rs1, rs2);                         \
        tcg_rv_trace_restore_origin(prev);                                   \
    }

#define DEFINE_RV_BACKEND_GUEST_UNARY(NAME)                                  \
    static void rv_backend_guest_##NAME(TCGContext *s, TCGType type,         \
                                        TCGReg rd, TCGReg rs)                \
    {                                                                        \
        QemuPluginTbRvOrigin prev =                                          \
            tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);         \
        rv_trace_tgen_##NAME(s, type, rd, rs);                               \
        tcg_rv_trace_restore_origin(prev);                                   \
    }

DEFINE_RV_BACKEND_GUEST_BINARY(add)
DEFINE_RV_BACKEND_GUEST_RRR(sub)
DEFINE_RV_BACKEND_GUEST_RRR(mul)
DEFINE_RV_BACKEND_GUEST_BINARY(and)
DEFINE_RV_BACKEND_GUEST_BINARY(or)
DEFINE_RV_BACKEND_GUEST_BINARY(xor)
DEFINE_RV_BACKEND_GUEST_BINARY(shl)
DEFINE_RV_BACKEND_GUEST_BINARY(shr)
DEFINE_RV_BACKEND_GUEST_BINARY(sar)
DEFINE_RV_BACKEND_GUEST_RRR(divs)
DEFINE_RV_BACKEND_GUEST_RRR(divu)
DEFINE_RV_BACKEND_GUEST_RRR(rems)
DEFINE_RV_BACKEND_GUEST_RRR(remu)
DEFINE_RV_BACKEND_GUEST_BINARY(rotl)
DEFINE_RV_BACKEND_GUEST_BINARY(rotr)
DEFINE_RV_BACKEND_GUEST_UNARY(neg)
DEFINE_RV_BACKEND_GUEST_UNARY(not)
DEFINE_RV_BACKEND_GUEST_UNARY(ctpop)
DEFINE_RV_BACKEND_GUEST_UNARY(ext32s)
DEFINE_RV_BACKEND_GUEST_UNARY(ext32u)
DEFINE_RV_BACKEND_GUEST_UNARY(extrh)

static void rv_backend_guest_andc(TCGContext *s, TCGType type,
                                  TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
    TCGReg tmp = rd == rs1 ? TRACERTL_RV_ALT_SCRATCH_REG : rd;

    rv_trace_tgen_not(s, type, tmp, rs2);
    rv_trace_tgen_and(s, type, rd, rs1, tmp);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_orc(TCGContext *s, TCGType type,
                                 TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
    TCGReg tmp = rd == rs1 ? TRACERTL_RV_ALT_SCRATCH_REG : rd;

    rv_trace_tgen_not(s, type, tmp, rs2);
    rv_trace_tgen_or(s, type, rd, rs1, tmp);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_eqv(TCGContext *s, TCGType type,
                                 TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    rv_trace_tgen_xor(s, type, rd, rs1, rs2);
    rv_trace_tgen_not(s, type, rd, rd);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_nand(TCGContext *s, TCGType type,
                                  TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    rv_trace_tgen_and(s, type, rd, rs1, rs2);
    rv_trace_tgen_not(s, type, rd, rd);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_nor(TCGContext *s, TCGType type,
                                 TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    rv_trace_tgen_or(s, type, rd, rs1, rs2);
    rv_trace_tgen_not(s, type, rd, rd);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_mulsh_rrr(TCGContext *s, TCGType type,
                                       TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)type;
    rv_trace_out_opc_reg(s, RV_OPC_MULH, rd, rs1, rs2);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_muluh_rrr(TCGContext *s, TCGType type,
                                       TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)type;
    rv_trace_out_opc_reg(s, RV_OPC_MULHU, rd, rs1, rs2);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_muls2(TCGContext *s, TCGType type,
                                   TCGReg dlo, TCGReg dhi,
                                   TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)type;
    rv_trace_out_opc_reg(s, RV_OPC_MUL, dlo, rs1, rs2);
    rv_trace_out_opc_reg(s, RV_OPC_MULH, dhi, rs1, rs2);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_mulu2(TCGContext *s, TCGType type,
                                   TCGReg dlo, TCGReg dhi,
                                   TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)type;
    rv_trace_out_opc_reg(s, RV_OPC_MUL, dlo, rs1, rs2);
    rv_trace_out_opc_reg(s, RV_OPC_MULHU, dhi, rs1, rs2);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_clz_rrr(TCGContext *s, TCGType type,
                                     TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    rv_trace_tgen_clz_rrr(s, type, rd, rs1, rs2);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_clz_rri(TCGContext *s, TCGType type,
                                     TCGReg rd, TCGReg rs1,
                                     tcg_target_long imm)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    rv_trace_tgen_clz_rri(s, type, rd, rs1, imm);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_ctz_rrr(TCGContext *s, TCGType type,
                                     TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    rv_trace_tgen_ctz_rrr(s, type, rd, rs1, rs2);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_ctz_rri(TCGContext *s, TCGType type,
                                     TCGReg rd, TCGReg rs1,
                                     tcg_target_long imm)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    rv_trace_tgen_ctz_rri(s, type, rd, rs1, imm);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_qemu_ld(TCGContext *s, TCGType type,
                                     TCGReg rd, TCGReg addr, MemOpIdx oi)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
    RvTraceBuildState *st = rv_trace_build_state;

    if (st) {
        rv_note_mem_slot(st->insn_meta, st->guest_idx, st->insn_offsets,
                         st->pos);
    }
    rv_trace_tgen_qemu_ld(s, type, rd, addr, oi);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_qemu_st(TCGContext *s, TCGType type,
                                     TCGReg rs, TCGReg addr, MemOpIdx oi)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
    RvTraceBuildState *st = rv_trace_build_state;

    if (st) {
        rv_note_mem_slot(st->insn_meta, st->guest_idx, st->insn_offsets,
                         st->pos);
    }
    rv_trace_tgen_qemu_st(s, type, rs, addr, oi);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_qemu_ld2(TCGContext *s, TCGType type,
                                      TCGReg dlo, TCGReg dhi,
                                      TCGReg addr, MemOpIdx oi)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
    RvTraceBuildState *st = rv_trace_build_state;

    if (st) {
        rv_note_mem_slot(st->insn_meta, st->guest_idx, st->insn_offsets,
                         st->pos);
    }
    rv_trace_tgen_qemu_ld(s, type, dlo, addr, oi);
    rv_trace_out_opc_imm(s, RV_OPC_ADDI, dhi, dlo,
                         rv_placeholder_signature(INDEX_op_qemu_ld2, 1));
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_qemu_st2(TCGContext *s, TCGType type,
                                      TCGReg dlo, TCGReg dhi,
                                      TCGReg addr, MemOpIdx oi)
{
    TCGReg dep_rd;
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
    RvTraceBuildState *st = rv_trace_build_state;

    if (st) {
        rv_note_mem_slot(st->insn_meta, st->guest_idx, st->insn_offsets,
                         st->pos);
    }
    rv_trace_tgen_qemu_st(s, type, dlo, addr, oi);
    dep_rd = dhi == TRACERTL_RV_ALT_SCRATCH_REG
             ? TRACERTL_RV_SCRATCH_REG
             : TRACERTL_RV_ALT_SCRATCH_REG;
    rv_trace_out_opc_imm(s, RV_OPC_ADDI, dep_rd, dhi,
                         rv_placeholder_signature(INDEX_op_qemu_st2, 3));
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_brcond_rr(TCGContext *s, TCGType type, TCGCond cond,
                                       TCGReg a1, TCGReg a2, TCGLabel *label)
{
    const RvTraceBrcondInfo *info;
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)type;
    (void)label;
    if (is_tst_cond(cond)) {
        rv_trace_out_opc_reg(s, RV_OPC_AND, TRACERTL_RV_SCRATCH_REG, a1, a2);
        a1 = TRACERTL_RV_SCRATCH_REG;
        a2 = 0;
        cond = tcg_tst_eqne_cond(cond);
    }
    tcg_debug_assert(cond < ARRAY_SIZE(rv_trace_brcond_info));
    info = &rv_trace_brcond_info[cond];
    tcg_debug_assert(info->opc != 0);
    if (info->swap) {
        TCGReg t = a1;
        a1 = a2;
        a2 = t;
    }
    rv_trace_note_branch_slot_current();
    rv_emit(rv_trace_build_state->buf, &rv_trace_build_state->pos,
            rv_trace_build_state->buf_size,
            rv_encode_sb(info->opc, a1, a2, 0));
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_brcond_ri(TCGContext *s, TCGType type, TCGCond cond,
                                       TCGReg a1, tcg_target_long a2,
                                       TCGLabel *label)
{
    TCGReg rhs = 0;
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)type;
    if (a2 != 0) {
        rhs = TRACERTL_RV_SCRATCH_REG;
        rv_backend_out_movi(s, TCG_TYPE_REG, rhs, a2);
    }
    tcg_rv_trace_restore_origin(prev);
    rv_backend_guest_brcond_rr(s, type, cond, a1, rhs, label);
}

static void rv_backend_emit_setcond(TCGContext *s, TCGCond cond, TCGReg rd,
                                    TCGReg rs1, TCGReg rs2, bool neg)
{
    switch (cond) {
    case TCG_COND_LT:
        rv_trace_out_opc_reg(s, RV_OPC_SLT, rd, rs1, rs2);
        break;
    case TCG_COND_LTU:
        rv_trace_out_opc_reg(s, RV_OPC_SLTU, rd, rs1, rs2);
        break;
    case TCG_COND_GT:
        rv_trace_out_opc_reg(s, RV_OPC_SLT, rd, rs2, rs1);
        break;
    case TCG_COND_GTU:
        rv_trace_out_opc_reg(s, RV_OPC_SLTU, rd, rs2, rs1);
        break;
    case TCG_COND_GE:
        rv_trace_out_opc_reg(s, RV_OPC_SLT, rd, rs1, rs2);
        rv_trace_out_opc_imm(s, RV_OPC_XORI, rd, rd, 1);
        break;
    case TCG_COND_GEU:
        rv_trace_out_opc_reg(s, RV_OPC_SLTU, rd, rs1, rs2);
        rv_trace_out_opc_imm(s, RV_OPC_XORI, rd, rd, 1);
        break;
    case TCG_COND_LE:
        rv_trace_out_opc_reg(s, RV_OPC_SLT, rd, rs2, rs1);
        rv_trace_out_opc_imm(s, RV_OPC_XORI, rd, rd, 1);
        break;
    case TCG_COND_LEU:
        rv_trace_out_opc_reg(s, RV_OPC_SLTU, rd, rs2, rs1);
        rv_trace_out_opc_imm(s, RV_OPC_XORI, rd, rd, 1);
        break;
    case TCG_COND_EQ:
        rv_trace_out_opc_reg(s, RV_OPC_XOR, rd, rs1, rs2);
        rv_trace_out_opc_imm(s, RV_OPC_SLTIU, rd, rd, 1);
        break;
    case TCG_COND_NE:
        rv_trace_out_opc_reg(s, RV_OPC_XOR, rd, rs1, rs2);
        rv_trace_out_opc_reg(s, RV_OPC_SLTU, rd, 0, rd);
        break;
    default:
        rv_trace_out_opc_reg(s, RV_OPC_SLT, rd, rs1, rs2);
        break;
    }
    if (neg) {
        rv_trace_out_opc_reg(s, RV_OPC_SUB, rd, 0, rd);
    }
}

static void rv_backend_guest_setcond_rr(TCGContext *s, TCGType type, TCGCond cond,
                                        TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)type;
    rv_backend_emit_setcond(s, cond, rd, rs1, rs2, false);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_setcond_ri(TCGContext *s, TCGType type, TCGCond cond,
                                        TCGReg rd, TCGReg rs1,
                                        tcg_target_long imm)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)type;
    rv_backend_out_movi(s, TCG_TYPE_REG, TRACERTL_RV_SCRATCH_REG, imm);
    rv_backend_emit_setcond(s, cond, rd, rs1, TRACERTL_RV_SCRATCH_REG, false);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_negsetcond_rr(TCGContext *s, TCGType type,
                                           TCGCond cond, TCGReg rd,
                                           TCGReg rs1, TCGReg rs2)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)type;
    rv_backend_emit_setcond(s, cond, rd, rs1, rs2, true);
    tcg_rv_trace_restore_origin(prev);
}

static void rv_backend_guest_negsetcond_ri(TCGContext *s, TCGType type,
                                           TCGCond cond, TCGReg rd,
                                           TCGReg rs1, tcg_target_long imm)
{
    QemuPluginTbRvOrigin prev =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)type;
    rv_backend_out_movi(s, TCG_TYPE_REG, TRACERTL_RV_SCRATCH_REG, imm);
    rv_backend_emit_setcond(s, cond, rd, rs1, TRACERTL_RV_SCRATCH_REG, true);
    tcg_rv_trace_restore_origin(prev);
}

static TracertlRvOperand rv_backend_value_operand(TCGArg arg, bool is_const)
{
    return rv_reg_or_const_operand(arg, is_const);
}

static void rv_backend_guest_movcond(TCGContext *s, TCGType type, TCGCond cond,
                                     TCGReg ret, TCGReg cmp1, TCGArg cmp2,
                                     bool c_cmp2, TCGArg val1, bool c_val1,
                                     TCGArg val2, bool c_val2)
{
    uint32_t false_insns[16];
    uint32_t true_insns[16];
    int false_n;
    int true_n;
    TCGReg cmp2_reg = c_cmp2 ? TRACERTL_RV_SCRATCH_REG : cmp2;
    uint32_t br_opc;
    qemu_plugin_rv_trace_tag prev_tag;
    QemuPluginTbRvOrigin prev_origin =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)s;
    (void)type;

    prev_tag = rv_set_current_tag(QEMU_PLUGIN_RV_TAG_MOVCOND);
    if (c_cmp2) {
        rv_backend_out_movi(s, TCG_TYPE_REG, cmp2_reg, cmp2);
    }

    false_n = tracertl_rv_emit_move_sequence(false_insns, ARRAY_SIZE(false_insns),
                                             ret,
                                             rv_backend_value_operand(val2, c_val2));
    true_n = tracertl_rv_emit_move_sequence(true_insns, ARRAY_SIZE(true_insns),
                                            ret,
                                            rv_backend_value_operand(val1, c_val1));
    g_assert_cmpint(false_n, >, 0);
    g_assert_cmpint(true_n, >, 0);

    switch (cond) {
    case TCG_COND_EQ:    br_opc = RV_OPC_BEQ;  break;
    case TCG_COND_NE:    br_opc = RV_OPC_BNE;  break;
    case TCG_COND_LT:    br_opc = RV_OPC_BLT;  break;
    case TCG_COND_GE:    br_opc = RV_OPC_BGE;  break;
    case TCG_COND_LTU:   br_opc = RV_OPC_BLTU; break;
    case TCG_COND_GEU:   br_opc = RV_OPC_BGEU; break;
    case TCG_COND_GT:    br_opc = RV_OPC_BLT;
                         { TCGReg t = cmp1; cmp1 = cmp2_reg; cmp2_reg = t; }
                         break;
    case TCG_COND_LE:    br_opc = RV_OPC_BGE;
                         { TCGReg t = cmp1; cmp1 = cmp2_reg; cmp2_reg = t; }
                         break;
    case TCG_COND_GTU:   br_opc = RV_OPC_BLTU;
                         { TCGReg t = cmp1; cmp1 = cmp2_reg; cmp2_reg = t; }
                         break;
    case TCG_COND_LEU:   br_opc = RV_OPC_BGEU;
                         { TCGReg t = cmp1; cmp1 = cmp2_reg; cmp2_reg = t; }
                         break;
    case TCG_COND_ALWAYS:
        rv_emit_shared_sequence(rv_trace_build_state->buf, &rv_trace_build_state->pos,
                                rv_trace_build_state->buf_size,
                                true_n, true_insns);
        rv_restore_current_tag(prev_tag);
        tcg_rv_trace_restore_origin(prev_origin);
        return;
    case TCG_COND_NEVER:
        rv_emit_shared_sequence(rv_trace_build_state->buf, &rv_trace_build_state->pos,
                                rv_trace_build_state->buf_size,
                                false_n, false_insns);
        rv_restore_current_tag(prev_tag);
        tcg_rv_trace_restore_origin(prev_origin);
        return;
    default:
        br_opc = RV_OPC_BEQ;
        break;
    }

    rv_trace_note_branch_slot_current();
    rv_emit(rv_trace_build_state->buf, &rv_trace_build_state->pos,
            rv_trace_build_state->buf_size,
            rv_encode_sb(br_opc, cmp1, cmp2_reg, (false_n + 2) * 4));
    rv_emit_shared_sequence(rv_trace_build_state->buf, &rv_trace_build_state->pos,
                            rv_trace_build_state->buf_size,
                            false_n, false_insns);
    rv_emit(rv_trace_build_state->buf, &rv_trace_build_state->pos,
            rv_trace_build_state->buf_size,
            rv_encode_uj(RV_OPC_JAL, 0, (true_n + 1) * 4));
    rv_emit_shared_sequence(rv_trace_build_state->buf, &rv_trace_build_state->pos,
                            rv_trace_build_state->buf_size,
                            true_n, true_insns);
    rv_restore_current_tag(prev_tag);
    tcg_rv_trace_restore_origin(prev_origin);
}

static void rv_backend_guest_extract_common(TCGContext *s, TCGType type,
                                            TCGReg rd, TCGReg rs,
                                            unsigned ofs, unsigned len,
                                            bool sign)
{
    uint32_t insns[2];
    int n;

    (void)s;
    n = tracertl_rv_emit_extract_sequence(insns, ARRAY_SIZE(insns),
                                          type == TCG_TYPE_I32, sign,
                                          rd, rs, ofs, len);
    rv_trace_emit_insn_words(insns, n, QEMU_PLUGIN_RV_TAG_NONE,
                             QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
}

static void rv_backend_guest_extract(TCGContext *s, TCGType type,
                                     TCGReg rd, TCGReg rs,
                                     unsigned ofs, unsigned len)
{
    rv_backend_guest_extract_common(s, type, rd, rs, ofs, len, false);
}

static void rv_backend_guest_sextract(TCGContext *s, TCGType type,
                                      TCGReg rd, TCGReg rs,
                                      unsigned ofs, unsigned len)
{
    rv_backend_guest_extract_common(s, type, rd, rs, ofs, len, true);
}

static const TCGOutOpBinary rv_backend_outop_add = {
    .base.static_constraint = c_o1_i2_r_r_ri,
    .out_rrr = rv_backend_guest_add_rrr,
    .out_rri = rv_backend_guest_add_rri,
};
static const TCGOutOpSubtract rv_backend_outop_sub = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_sub_rrr,
};
static const TCGOutOpBinary rv_backend_outop_mul = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_mul_rrr,
};
static const TCGOutOpMul2 rv_backend_outop_muls2 = {
    .base.static_constraint = c_o2_i2_r_r_r_r_trace,
    .out_rrrr = rv_backend_guest_muls2,
};
static const TCGOutOpBinary rv_backend_outop_mulsh = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_mulsh_rrr,
};
static const TCGOutOpMul2 rv_backend_outop_mulu2 = {
    .base.static_constraint = c_o2_i2_r_r_r_r_trace,
    .out_rrrr = rv_backend_guest_mulu2,
};
static const TCGOutOpBinary rv_backend_outop_muluh = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_muluh_rrr,
};
static const TCGOutOpBinary rv_backend_outop_and = {
    .base.static_constraint = c_o1_i2_r_r_rI,
    .out_rrr = rv_backend_guest_and_rrr,
    .out_rri = rv_backend_guest_and_rri,
};
static const TCGOutOpBinary rv_backend_outop_andc = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_andc,
};
static const TCGOutOpBinary rv_backend_outop_or = {
    .base.static_constraint = c_o1_i2_r_r_rI,
    .out_rrr = rv_backend_guest_or_rrr,
    .out_rri = rv_backend_guest_or_rri,
};
static const TCGOutOpBinary rv_backend_outop_orc = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_orc,
};
static const TCGOutOpBinary rv_backend_outop_xor = {
    .base.static_constraint = c_o1_i2_r_r_rI,
    .out_rrr = rv_backend_guest_xor_rrr,
    .out_rri = rv_backend_guest_xor_rri,
};
static const TCGOutOpBinary rv_backend_outop_eqv = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_eqv,
};
static const TCGOutOpBinary rv_backend_outop_nand = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_nand,
};
static const TCGOutOpBinary rv_backend_outop_nor = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_nor,
};
static const TCGOutOpBinary rv_backend_outop_shl = {
    .base.static_constraint = c_o1_i2_r_r_ri,
    .out_rrr = rv_backend_guest_shl_rrr,
    .out_rri = rv_backend_guest_shl_rri,
};
static const TCGOutOpBinary rv_backend_outop_shr = {
    .base.static_constraint = c_o1_i2_r_r_ri,
    .out_rrr = rv_backend_guest_shr_rrr,
    .out_rri = rv_backend_guest_shr_rri,
};
static const TCGOutOpBinary rv_backend_outop_sar = {
    .base.static_constraint = c_o1_i2_r_r_ri,
    .out_rrr = rv_backend_guest_sar_rrr,
    .out_rri = rv_backend_guest_sar_rri,
};
static const TCGOutOpBinary rv_backend_outop_divs = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_divs_rrr,
};
static const TCGOutOpBinary rv_backend_outop_divu = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_divu_rrr,
};
static const TCGOutOpBinary rv_backend_outop_rems = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_rems_rrr,
};
static const TCGOutOpBinary rv_backend_outop_remu = {
    .base.static_constraint = c_o1_i2_r_r_r,
    .out_rrr = rv_backend_guest_remu_rrr,
};
static const TCGOutOpBinary rv_backend_outop_rotl = {
    .base.static_constraint = c_o1_i2_r_r_ri,
    .out_rrr = rv_backend_guest_rotl_rrr,
    .out_rri = rv_backend_guest_rotl_rri,
};
static const TCGOutOpBinary rv_backend_outop_rotr = {
    .base.static_constraint = c_o1_i2_r_r_ri,
    .out_rrr = rv_backend_guest_rotr_rrr,
    .out_rri = rv_backend_guest_rotr_rri,
};
static const TCGOutOpUnary rv_backend_outop_neg = {
    .base.static_constraint = c_o1_i1_r_r,
    .out_rr = rv_backend_guest_neg,
};
static const TCGOutOpUnary rv_backend_outop_not = {
    .base.static_constraint = c_o1_i1_r_r,
    .out_rr = rv_backend_guest_not,
};
static const TCGOutOpBinary rv_backend_outop_clz = {
    .base.static_constraint = c_n1_i2_r_r_rM,
    .out_rrr = rv_backend_guest_clz_rrr,
    .out_rri = rv_backend_guest_clz_rri,
};
static const TCGOutOpBinary rv_backend_outop_ctz = {
    .base.static_constraint = c_n1_i2_r_r_rM,
    .out_rrr = rv_backend_guest_ctz_rrr,
    .out_rri = rv_backend_guest_ctz_rri,
};
static const TCGOutOpUnary rv_backend_outop_ctpop = {
    .base.static_constraint = c_o1_i1_r_r,
    .out_rr = rv_backend_guest_ctpop,
};
static const TCGOutOpUnary rv_backend_outop_ext32s = {
    .base.static_constraint = c_o1_i1_r_r,
    .out_rr = rv_backend_guest_ext32s,
};
static const TCGOutOpUnary rv_backend_outop_ext32u = {
    .base.static_constraint = c_o1_i1_r_r,
    .out_rr = rv_backend_guest_ext32u,
};
static const TCGOutOpUnary rv_backend_outop_extrh = {
    .base.static_constraint = c_o1_i1_r_r,
    .out_rr = rv_backend_guest_extrh,
};
static const TCGOutOpExtract rv_backend_outop_extract = {
    .base.static_constraint = c_o1_i1_r_r,
    .out_rr = rv_backend_guest_extract,
};
static const TCGOutOpExtract rv_backend_outop_sextract = {
    .base.static_constraint = c_o1_i1_r_r,
    .out_rr = rv_backend_guest_sextract,
};
static const TCGOutOpLoad rv_backend_outop_ld = {
    .base.static_constraint = c_o1_i1_r_r,
    .out = rv_backend_out_ld,
};
static const TCGOutOpLoad rv_backend_outop_ld8u = {
    .base.static_constraint = c_o1_i1_r_r,
    .out = rv_backend_out_ld8u,
};
static const TCGOutOpLoad rv_backend_outop_ld8s = {
    .base.static_constraint = c_o1_i1_r_r,
    .out = rv_backend_out_ld8s,
};
static const TCGOutOpLoad rv_backend_outop_ld16u = {
    .base.static_constraint = c_o1_i1_r_r,
    .out = rv_backend_out_ld16u,
};
static const TCGOutOpLoad rv_backend_outop_ld16s = {
    .base.static_constraint = c_o1_i1_r_r,
    .out = rv_backend_out_ld16s,
};
static const TCGOutOpLoad rv_backend_outop_ld32u = {
    .base.static_constraint = c_o1_i1_r_r,
    .out = rv_backend_out_ld32u,
};
static const TCGOutOpLoad rv_backend_outop_ld32s = {
    .base.static_constraint = c_o1_i1_r_r,
    .out = rv_backend_out_ld32s,
};
static const TCGOutOpStore rv_backend_outop_st = {
    .base.static_constraint = c_o0_i2_rz_r,
    .out_r = rv_backend_out_st,
    .out_i = rv_backend_out_st_i,
};
static const TCGOutOpStore rv_backend_outop_st8 = {
    .base.static_constraint = c_o0_i2_rz_r,
    .out_r = rv_backend_out_st8_r,
    .out_i = rv_backend_out_st8_i,
};
static const TCGOutOpStore rv_backend_outop_st16 = {
    .base.static_constraint = c_o0_i2_rz_r,
    .out_r = rv_backend_out_st16_r,
    .out_i = rv_backend_out_st16_i,
};
static const TCGOutOp rv_backend_outop_goto_ptr = {
    .static_constraint = c_o0_i1_r,
};
static const TCGOutOpBrcond rv_backend_outop_brcond = {
    .base.static_constraint = c_o0_i2_r_rz,
    .out_rr = rv_backend_guest_brcond_rr,
    .out_ri = rv_backend_guest_brcond_ri,
};
static const TCGOutOpSetcond rv_backend_outop_setcond = {
    .base.static_constraint = c_o1_i2_r_r_rI,
    .out_rrr = rv_backend_guest_setcond_rr,
    .out_rri = rv_backend_guest_setcond_ri,
};
static const TCGOutOpSetcond rv_backend_outop_negsetcond = {
    .base.static_constraint = c_o1_i2_r_r_rI,
    .out_rrr = rv_backend_guest_negsetcond_rr,
    .out_rri = rv_backend_guest_negsetcond_ri,
};
static const TCGOutOpMovcond rv_backend_outop_movcond = {
    .base.static_constraint = c_o1_i4_r_r_rI_rM_rM,
    .out = rv_backend_guest_movcond,
};
static const TCGOutOpQemuLdSt rv_backend_outop_qemu_ld = {
    .base.static_constraint = c_o1_i1_r_r,
    .out = rv_backend_guest_qemu_ld,
};
static const TCGOutOpQemuLdSt2 rv_backend_outop_qemu_ld2 = {
    .base.static_constraint = c_o2_i1_r_r_r_trace,
    .out = rv_backend_guest_qemu_ld2,
};
static const TCGOutOpQemuLdSt rv_backend_outop_qemu_st = {
    .base.static_constraint = c_o0_i2_rz_r,
    .out = rv_backend_guest_qemu_st,
};
static const TCGOutOpQemuLdSt2 rv_backend_outop_qemu_st2 = {
    .base.static_constraint = c_o0_i3_rz_rz_r_trace,
    .out = rv_backend_guest_qemu_st2,
};

static const TCGOutOp *const rv_backend_outops[NB_OPS] = {
    [INDEX_op_add] = &rv_backend_outop_add.base,
    [INDEX_op_sub] = &rv_backend_outop_sub.base,
    [INDEX_op_mul] = &rv_backend_outop_mul.base,
    [INDEX_op_muls2] = &rv_backend_outop_muls2.base,
    [INDEX_op_mulsh] = &rv_backend_outop_mulsh.base,
    [INDEX_op_mulu2] = &rv_backend_outop_mulu2.base,
    [INDEX_op_muluh] = &rv_backend_outop_muluh.base,
    [INDEX_op_and] = &rv_backend_outop_and.base,
    [INDEX_op_andc] = &rv_backend_outop_andc.base,
    [INDEX_op_or] = &rv_backend_outop_or.base,
    [INDEX_op_orc] = &rv_backend_outop_orc.base,
    [INDEX_op_xor] = &rv_backend_outop_xor.base,
    [INDEX_op_eqv] = &rv_backend_outop_eqv.base,
    [INDEX_op_nand] = &rv_backend_outop_nand.base,
    [INDEX_op_nor] = &rv_backend_outop_nor.base,
    [INDEX_op_shl] = &rv_backend_outop_shl.base,
    [INDEX_op_shr] = &rv_backend_outop_shr.base,
    [INDEX_op_sar] = &rv_backend_outop_sar.base,
    [INDEX_op_divs] = &rv_backend_outop_divs.base,
    [INDEX_op_divu] = &rv_backend_outop_divu.base,
    [INDEX_op_rems] = &rv_backend_outop_rems.base,
    [INDEX_op_remu] = &rv_backend_outop_remu.base,
    [INDEX_op_rotl] = &rv_backend_outop_rotl.base,
    [INDEX_op_rotr] = &rv_backend_outop_rotr.base,
    [INDEX_op_brcond] = &rv_backend_outop_brcond.base,
    [INDEX_op_setcond] = &rv_backend_outop_setcond.base,
    [INDEX_op_negsetcond] = &rv_backend_outop_negsetcond.base,
    [INDEX_op_movcond] = &rv_backend_outop_movcond.base,
    [INDEX_op_neg] = &rv_backend_outop_neg.base,
    [INDEX_op_not] = &rv_backend_outop_not.base,
    [INDEX_op_clz] = &rv_backend_outop_clz.base,
    [INDEX_op_ctz] = &rv_backend_outop_ctz.base,
    [INDEX_op_ctpop] = &rv_backend_outop_ctpop.base,
    [INDEX_op_ext_i32_i64] = &rv_backend_outop_ext32s.base,
    [INDEX_op_extrl_i64_i32] = &rv_backend_outop_ext32s.base,
    [INDEX_op_extu_i32_i64] = &rv_backend_outop_ext32u.base,
    [INDEX_op_extrh_i64_i32] = &rv_backend_outop_extrh.base,
    [INDEX_op_extract] = &rv_backend_outop_extract.base,
    [INDEX_op_sextract] = &rv_backend_outop_sextract.base,
    [INDEX_op_ld8u] = &rv_backend_outop_ld8u.base,
    [INDEX_op_ld8s] = &rv_backend_outop_ld8s.base,
    [INDEX_op_ld16u] = &rv_backend_outop_ld16u.base,
    [INDEX_op_ld16s] = &rv_backend_outop_ld16s.base,
    [INDEX_op_ld32u] = &rv_backend_outop_ld32u.base,
    [INDEX_op_ld32s] = &rv_backend_outop_ld32s.base,
    [INDEX_op_ld] = &rv_backend_outop_ld.base,
    [INDEX_op_st8] = &rv_backend_outop_st8.base,
    [INDEX_op_st16] = &rv_backend_outop_st16.base,
    [INDEX_op_st32] = &rv_backend_outop_st.base,
    [INDEX_op_st] = &rv_backend_outop_st.base,
    [INDEX_op_goto_ptr] = &rv_backend_outop_goto_ptr,
    [INDEX_op_qemu_ld] = &rv_backend_outop_qemu_ld.base,
    [INDEX_op_qemu_ld2] = &rv_backend_outop_qemu_ld2.base,
    [INDEX_op_qemu_st] = &rv_backend_outop_qemu_st.base,
    [INDEX_op_qemu_st2] = &rv_backend_outop_qemu_st2.base,
};

static const int rv_backend_reg_alloc_order[] = {
    9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    5, 6, 7, 28, 29, 30, 31,
    10, 11, 12, 13, 14, 15, 16, 17,
    33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56,
    57, 58, 59, 60, 61, 62, 63,
};

static const int rv_backend_call_iarg_regs[] = {
    10, 11, 12, 13, 14, 15, 16, 17,
};

static const TCGBackendDispatch rv_backend_dispatch = {
    .constraint_sets = rv_backend_constraint_sets,
    .constraint_set_count = ARRAY_SIZE(rv_backend_constraint_sets),
    .all_cts = rv_backend_all_cts,
    .all_outop = rv_backend_outops,
    .target_op_def = rv_backend_target_op_def,
    .parse_constraint = rv_backend_parse_constraint,
};

typedef struct RvTraceBackendProviderState {
    TCGBackendState backend;
    bool initialized;
} RvTraceBackendProviderState;

static bool rv_backend_dispatch_ready;
static __thread RvTraceBackendProviderState rv_trace_backend_provider;
static void rv_trace_backend_prepare(TCGContext *s);

static void rv_release_dead_temps(const TCGOp *op)
{
    const TCGOpDef *def = &tcg_op_defs[op->opc];
    TCGLifeData life = op->life;
    int nb_oargs;
    int nb_iargs;

    if (!rv_temp_map_state || life == 0) {
        return;
    }

    if (op->opc == INDEX_op_call) {
        nb_oargs = TCGOP_CALLO(op);
        nb_iargs = TCGOP_CALLI(op);
    } else {
        nb_oargs = def->nb_oargs;
        nb_iargs = def->nb_iargs;
    }

    /* Keep the temp map TB-local and finite by returning registers as soon as
     * TCG liveness marks an operand dead after this op. */
    for (int i = 0; i < nb_oargs + nb_iargs; i++) {
        TCGTemp *ts;
        unsigned int idx;
        int reg;

        if (!(life & (DEAD_ARG << i))) {
            continue;
        }

        ts = arg_temp(op->args[i]);
        if (!ts || ts->val_type == TEMP_VAL_CONST) {
            continue;
        }

        idx = (unsigned int)temp_idx(ts);
        reg = rv_temp_map_state->temp_regs[idx];
        if (reg < 0) {
            continue;
        }

        rv_temp_map_state->temp_regs[idx] = -1;
        if (reg < ARRAY_SIZE(rv_temp_map_state->reg_temps) &&
            rv_temp_map_state->reg_temps[reg] == (int)idx) {
            rv_temp_map_state->reg_temps[reg] = -1;
        }
    }
}

static void rv_emit_load_imm_value(uint32_t *buf, int *pos, int buf_size,
                                   int rd, uint64_t value)
{
    uint32_t insns[16];
    int n = tracertl_rv_emit_load_imm_sequence(insns, ARRAY_SIZE(insns),
                                               rd, value);

    g_assert_cmpint(n, >, 0);
    rv_emit_shared_sequence(buf, pos, buf_size, n, insns);
}

static uint32_t rv_placeholder_signature(TCGOpcode opc, unsigned int salt)
{
    uint32_t sig = (((uint32_t)opc + 1U) * 73U + salt * 37U) & 0x7ffU;

    return sig != 0 ? sig : salt + 1U;
}

static int rv_materialize_placeholder_arg(uint32_t *buf, int *pos, int buf_size,
                                          TCGArg arg, int scratch_reg,
                                          uint32_t sig)
{
    TCGTemp *ts = arg_temp(arg);

    if (!ts) {
        rv_emit_load_imm_value(buf, pos, buf_size, scratch_reg, sig);
        return scratch_reg;
    }

    if (ts->val_type == TEMP_VAL_CONST) {
        rv_emit_load_imm_value(buf, pos, buf_size, scratch_reg,
                               (uint64_t)ts->val ^ sig);
        return scratch_reg;
    }

    {
        int reg = rv_temp_to_reg(arg);

        if (reg >= 0) {
            return reg;
        }
    }

    rv_emit_load_imm_value(buf, pos, buf_size, scratch_reg,
                           ((uint64_t)temp_idx(ts) << 16) | sig);
    return scratch_reg;
}

static void rv_emit_dependency_placeholder(uint32_t *buf, int *pos,
                                           int buf_size, const TCGOp *op,
                                           int rd, int first_input,
                                           int nb_inputs)
{
    uint32_t seed_sig = rv_placeholder_signature(op->opc, 0);
    uint32_t mix_sig = rv_placeholder_signature(op->opc, 1);
    int scratch = rd == TRACERTL_RV_SCRATCH_REG
                  ? TRACERTL_RV_ALT_SCRATCH_REG
                  : TRACERTL_RV_SCRATCH_REG;

    if (nb_inputs > 0) {
        int seed = rv_materialize_placeholder_arg(buf, pos, buf_size,
                                                  op->args[first_input],
                                                  scratch, seed_sig);

        rv_emit(buf, pos, buf_size, rv_encode_i(RV_OPC_ADDI, rd, seed, seed_sig));
        for (int i = 1; i < nb_inputs; i++) {
            int rs = rv_materialize_placeholder_arg(buf, pos, buf_size,
                                                    op->args[first_input + i],
                                                    scratch, seed_sig + i);
            rv_emit(buf, pos, buf_size, rv_encode_r(RV_OPC_XOR, rd, rd, rs));
        }
    } else {
        rv_emit_load_imm_value(buf, pos, buf_size, rd,
                               ((uint64_t)op->opc << 16) | seed_sig);
    }

    rv_emit(buf, pos, buf_size, rv_encode_i(RV_OPC_XORI, rd, rd, mix_sig));
}

static int rv_map_vector_arg(TCGArg arg, void *opaque)
{
    TCGTemp *ts = arg_temp(arg);
    unsigned int idx;
    int vreg;

    (void)opaque;
    if (!ts) {
        return rv_temp_to_reg(arg);
    }
    idx = (unsigned int)temp_idx(ts);

    if (ts->base_type >= TCG_TYPE_V64) {
        vreg = tracertl_rv_temp_to_vreg(idx);
        if (vreg >= 0) {
            return vreg;
        }
    }

    return rv_temp_to_reg(arg);
}

static void rv_emit_vector_placeholder(uint32_t *buf, int *pos, int buf_size,
                                       qemu_plugin_rv_insn_meta *insn_meta,
                                       int guest_idx,
                                       const int *insn_offsets,
                                       const TCGOp *op)
{
    const TCGOpDef *def = &tcg_op_defs[op->opc];
    bool is_guest_vector_mem =
        op->opc == INDEX_op_ld_vec ||
        op->opc == INDEX_op_st_vec ||
        op->opc == INDEX_op_dupm_vec;
    bool is_internal_vector_mem =
        is_guest_vector_mem &&
        op->args[1] == tcgv_ptr_arg(tcg_env);
    int rd = TRACERTL_RV_SCRATCH_REG;
    TracertlRvVectorEmitMeta vector_meta = { 0 };
    TracertlRvVectorState vector_state = rv_snapshot_vector_state();
    int emitted_n = 0;

    if (def->nb_oargs > 0) {
        rd = rv_temp_to_reg(op->args[0]);
        if (rd < 0) {
            rd = TRACERTL_RV_SCRATCH_REG;
        }
    }

    if (is_internal_vector_mem) {
        rv_restore_vector_state(&vector_state);
        return;
    }

    emitted_n = tracertl_rv_lower_vector_tcg_op(buf + *pos,
                                                buf_size - *pos,
                                                &vector_state, op,
                                                rv_map_vector_arg, NULL,
                                                &vector_meta);
    if (emitted_n > 0) {
        if (vector_meta.note_mem_slot) {
            rv_set_mem_slot(buf, insn_meta, guest_idx, insn_offsets,
                            *pos + vector_meta.mem_slot_rel_idx);
        }
        rv_trace_note_current_tcg_op_guest_output();
        *pos += emitted_n;
        rv_restore_vector_state(&vector_state);
        return;
    }

    {
        qemu_plugin_rv_trace_tag prev =
            rv_set_current_tag(QEMU_PLUGIN_RV_TAG_GENERIC_DEPENDENCY_PLACEHOLDER);

        rv_trace_counter_note_emitted_generic_placeholder(op->opc);
        rv_emit_dependency_placeholder(buf, pos, buf_size, op, rd,
                                       def->nb_oargs, def->nb_iargs);
        if (!is_internal_vector_mem && is_guest_vector_mem) {
            rv_note_mem_slot(insn_meta, guest_idx, insn_offsets, *pos - 1);
        }
        rv_restore_current_tag(prev);
    }
}

static void rv_get_op_io_counts(const TCGOp *op, int *nb_oargs, int *nb_iargs)
{
    const TCGOpDef *def = &tcg_op_defs[op->opc];

    if (op->opc == INDEX_op_call) {
        *nb_oargs = TCGOP_CALLO(op);
        *nb_iargs = TCGOP_CALLI(op);
    } else {
        *nb_oargs = def->nb_oargs;
        *nb_iargs = def->nb_iargs;
    }
}

static bool rv_prepare_exact_temps(const TCGOp *op)
{
    int nb_oargs;
    int nb_iargs;

    if (!rv_temp_map_state) {
        return true;
    }

    rv_get_op_io_counts(op, &nb_oargs, &nb_iargs);

    for (int i = 0; i < nb_oargs + nb_iargs; i++) {
        TCGTemp *ts = arg_temp(op->args[i]);

        if (!ts) {
            continue;
        }
        if (ts->val_type == TEMP_VAL_CONST) {
            if (i >= nb_oargs) {
                return false;
            }
            continue;
        }
        if (rv_temp_to_reg(op->args[i]) < 0) {
            return false;
        }
    }

    return true;
}

static bool rv_has_unmapped_nonconst_temps(const TCGOp *op)
{
    int nb_oargs;
    int nb_iargs;

    if (!rv_temp_map_state) {
        return false;
    }

    rv_get_op_io_counts(op, &nb_oargs, &nb_iargs);
    for (int i = 0; i < nb_oargs + nb_iargs; i++) {
        TCGTemp *ts = arg_temp(op->args[i]);

        if (!ts || ts->val_type == TEMP_VAL_CONST) {
            continue;
        }
        if (rv_temp_to_reg(op->args[i]) < 0) {
            return true;
        }
    }

    return false;
}

static bool rv_call_has_dead_input_temps(const TCGOp *op)
{
    int nb_oargs;
    int nb_iargs;

    if (op->opc != INDEX_op_call) {
        return false;
    }

    nb_oargs = TCGOP_CALLO(op);
    nb_iargs = TCGOP_CALLI(op);
    for (int i = 0; i < nb_iargs; i++) {
        TCGTemp *ts = arg_temp(op->args[nb_oargs + i]);

        if (ts != NULL && ts->val_type == TEMP_VAL_DEAD) {
            return true;
        }
    }

    return false;
}

static bool rv_trace_current_tcg_op_has_guest_output(void)
{
    RvTraceBuildState *st = rv_trace_build_state;

    return st != NULL &&
           (st->current_tcg_op_emitted_guest ||
            st->current_tcg_op_deferred_guest_output);
}

static void rv_note_mem_slot(qemu_plugin_rv_insn_meta *insn_meta,
                             int guest_idx, const int *insn_offsets, int pos)
{
    if (insn_meta && guest_idx >= 0) {
        /* Store the record index relative to this guest instruction's first
         * emitted RV word so runtime can patch the right pending slot. */
        int8_t mi = (int8_t)(pos - insn_offsets[guest_idx]);
        int nm = insn_meta[guest_idx].n_mem;

        if (nm < QEMU_PLUGIN_RV_MAX_MEM) {
            insn_meta[guest_idx].mem_idxs[nm] = mi;
            insn_meta[guest_idx].n_mem = nm + 1;
        }
    }
}

static void rv_set_mem_slot(uint32_t *buf,
                            qemu_plugin_rv_insn_meta *insn_meta,
                            int guest_idx, const int *insn_offsets, int pos)
{
    if (insn_meta && guest_idx >= 0) {
        int nm = insn_meta[guest_idx].n_mem;
        int8_t mi = (int8_t)(pos - insn_offsets[guest_idx]);

        for (int i = 0; i < nm; i++) {
            int8_t prev = insn_meta[guest_idx].mem_idxs[i];

            if (prev >= 0) {
                buf[insn_offsets[guest_idx] + prev] = 0x00000013;
            }
        }
        memset(insn_meta[guest_idx].mem_idxs, -1,
               sizeof(insn_meta[guest_idx].mem_idxs));
        insn_meta[guest_idx].mem_idxs[0] = mi;
        insn_meta[guest_idx].n_mem = 1;
    }
}

static void rv_emit_indirect_branch_placeholder(uint32_t *buf, int *pos,
                                                int buf_size,
                                                qemu_plugin_rv_insn_meta *insn_meta,
                                                int guest_idx,
                                                const int *insn_offsets,
                                                TCGArg reg_arg)
{
    qemu_plugin_rv_trace_tag prev =
        rv_set_current_tag(QEMU_PLUGIN_RV_TAG_INDIRECT_BRANCH_PLACEHOLDER);
    int rs1 = rv_materialize_placeholder_arg(buf, pos, buf_size, reg_arg,
                                             TRACERTL_RV_SCRATCH_REG,
                                             rv_placeholder_signature(INDEX_op_goto_ptr, 0));

    rv_emit(buf, pos, buf_size,
            rv_encode_i(0x67 /* JALR */, 0, rs1, 0));
    if (insn_meta && guest_idx >= 0) {
        insn_meta[guest_idx].branch_idx =
            (int8_t)(*pos - insn_offsets[guest_idx] - 1);
    }
    rv_restore_current_tag(prev);
}

static void rv_emit_direct_branch_placeholder(uint32_t *buf, int *pos,
                                              int buf_size,
                                              qemu_plugin_rv_insn_meta *insn_meta,
                                              int guest_idx,
                                              const int *insn_offsets)
{
    rv_emit(buf, pos, buf_size,
            rv_encode_uj(0x6f /* JAL */, 0, 0));
    if (insn_meta && guest_idx >= 0) {
        insn_meta[guest_idx].branch_idx =
            (int8_t)(*pos - insn_offsets[guest_idx] - 1);
    }
}

static void rv_trace_emit_generic_placeholder_op(const TCGOp *op)
{
    RvTraceBuildState *st = rv_trace_build_state;
    int nb_oargs;
    int nb_iargs;
    int rd = TRACERTL_RV_SCRATCH_REG;
    bool is_vector = op->opc < tcg_op_defs_max &&
                     (tcg_op_defs[op->opc].flags & TCG_OPF_VECTOR);

    g_assert(st != NULL);

    rv_get_op_io_counts(op, &nb_oargs, &nb_iargs);
    if (nb_oargs > 0) {
        rd = rv_temp_to_reg(op->args[0]);
        if (rd < 0) {
            rd = TRACERTL_RV_SCRATCH_REG;
        }
    }

    if (is_vector) {
        rv_emit_vector_placeholder(st->buf, &st->pos, st->buf_size,
                                   st->insn_meta, st->guest_idx,
                                   st->insn_offsets, op);
        return;
    }

    {
        qemu_plugin_rv_trace_tag prev =
            rv_set_current_tag(QEMU_PLUGIN_RV_TAG_GENERIC_DEPENDENCY_PLACEHOLDER);

        rv_trace_counter_note_emitted_generic_placeholder(op->opc);
        rv_emit_dependency_placeholder(st->buf, &st->pos, st->buf_size, op,
                                       rd, nb_oargs, nb_iargs);
        rv_restore_current_tag(prev);
    }
}

static void rv_trace_begin_guest_insn(void)
{
    RvTraceBuildState *st = rv_trace_build_state;

    g_assert(st != NULL);

    if (st->pending_branch == PENDING_BRANCH_DIRECT) {
        rv_emit_direct_branch_placeholder(st->buf, &st->pos, st->buf_size,
                                          st->insn_meta, st->guest_idx,
                                          st->insn_offsets);
        st->pending_branch = PENDING_BRANCH_NONE;
    } else if (st->pending_branch == PENDING_BRANCH_INDIRECT) {
        rv_emit_indirect_branch_placeholder(st->buf, &st->pos, st->buf_size,
                                            st->insn_meta, st->guest_idx,
                                            st->insn_offsets,
                                            st->pending_branch_arg);
        st->pending_branch = PENDING_BRANCH_NONE;
    }

    if (st->guest_idx >= 0) {
        rv_trace_emit_guest_semantic_fallback();
        if (st->guest_helper_emitted) {
            rv_trace_promote_branch_slot_to_terminal_record();
        }
    }

    st->guest_idx++;
    st->insn_offsets[st->guest_idx] = st->pos;
    st->guest_has_branch = false;
    st->guest_helper_emitted = false;
    st->guest_translated_helper_emitted = false;
    st->guest_semantic_emitted = false;
    if (st->insn_meta) {
        st->insn_meta[st->guest_idx].n_mem = 0;
        memset(st->insn_meta[st->guest_idx].mem_idxs, -1,
               sizeof(st->insn_meta[st->guest_idx].mem_idxs));
        st->insn_meta[st->guest_idx].branch_idx = -1;
        st->insn_meta[st->guest_idx].exception_idx = -1;
        st->insn_meta[st->guest_idx].helper_idx = -1;
    }
}

static void rv_trace_note_special_op(TCGOp *op)
{
    RvTraceBuildState *st = rv_trace_build_state;

    g_assert(st != NULL);

    switch (op->opc) {
    case INDEX_op_goto_tb:
    case INDEX_op_exit_tb:
        if (!st->guest_has_branch &&
            st->pending_branch == PENDING_BRANCH_NONE) {
            st->pending_branch = PENDING_BRANCH_DIRECT;
            rv_trace_note_current_tcg_op_deferred_guest_output();
        }
        break;
    case INDEX_op_br:
        break;
    case INDEX_op_mb: {
        QemuPluginTbRvOrigin prev =
            tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

        rv_emit(st->buf, &st->pos, st->buf_size, RV_OPC_FENCE);
        tcg_rv_trace_restore_origin(prev);
        break;
    }
    default:
        g_assert_not_reached();
    }
}

static bool rv_trace_guest_has_visible_output(const RvTraceBuildState *st)
{
    int start;

    if (st == NULL || st->guest_idx < 0 || st->insn_offsets == NULL) {
        return false;
    }

    start = st->insn_offsets[st->guest_idx];
    if (start < 0 || start >= st->pos) {
        return false;
    }
    if (rv_emit_origins == NULL) {
        return true;
    }

    for (int i = start; i < st->pos; i++) {
        if (rv_emit_origins[i] == QEMU_PLUGIN_TB_RV_ORIGIN_GUEST) {
            return true;
        }
    }
    return false;
}

static bool rv_trace_emit_x86_cmov_fallback(void)
{
    RvTraceBuildState *st = rv_trace_build_state;
    uint32_t fallback_insn =
        tracertl_rv_encode_r(RV_OPC_ADD,
                             TRACERTL_RV_SCRATCH_REG,
                             TRACERTL_RV_SCRATCH_REG,
                             TRACERTL_RV_ALT_SCRATCH_REG);
    qemu_plugin_rv_trace_tag semantic_tag = QEMU_PLUGIN_RV_TAG_NONE;
    QemuPluginTbRvOrigin prev_origin;
    qemu_plugin_rv_trace_tag prev_tag;

    if (st == NULL || st->plugin_tb == NULL) {
        return false;
    }

    if (!qemu_plugin_tb_get_rv_guest_semantic_tag(st->plugin_tb,
                                                  st->guest_idx,
                                                  &semantic_tag) ||
        semantic_tag != QEMU_PLUGIN_RV_TAG_MOVCOND) {
        return false;
    }

    qemu_plugin_tb_get_rv_guest_semantic_fallback(st->plugin_tb,
                                                  st->guest_idx,
                                                  &fallback_insn);

    prev_origin = tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
    prev_tag = rv_set_current_tag(QEMU_PLUGIN_RV_TAG_MOVCOND);
    rv_trace_note_branch_slot_current();
    rv_emit(st->buf, &st->pos, st->buf_size,
            rv_encode_sb(RV_OPC_BEQ, 0, 0, 12));
    rv_emit(st->buf, &st->pos, st->buf_size, fallback_insn);
    rv_emit(st->buf, &st->pos, st->buf_size,
            rv_encode_uj(RV_OPC_JAL, 0, 8));
    rv_emit(st->buf, &st->pos, st->buf_size, fallback_insn);
    rv_restore_current_tag(prev_tag);
    tcg_rv_trace_restore_origin(prev_origin);
    st->guest_semantic_emitted = true;
    return true;
}

static bool rv_trace_emit_guest_helper_placeholder(void)
{
    RvTraceBuildState *st = rv_trace_build_state;
    uint32_t helper_insn =
        tracertl_rv_encode_r(RV_OPC_ADD,
                             TRACERTL_RV_SCRATCH_REG,
                             TRACERTL_RV_SCRATCH_REG,
                             TRACERTL_RV_ALT_SCRATCH_REG);
    QemuPluginTbRvOrigin prev_origin;
    qemu_plugin_rv_trace_tag prev_tag;

    if (st == NULL || !st->guest_helper_emitted) {
        return false;
    }

    prev_origin = tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
    prev_tag = rv_set_current_tag(QEMU_PLUGIN_RV_TAG_HELPER_PLACEHOLDER);
    if (st->insn_meta && st->guest_idx >= 0 &&
        st->insn_meta[st->guest_idx].branch_idx >= 0) {
        st->insn_meta[st->guest_idx].branch_idx =
            (int8_t)(st->pos - st->insn_offsets[st->guest_idx]);
    }
    rv_trace_note_helper_slot_current();
    rv_emit(st->buf, &st->pos, st->buf_size, helper_insn);
    rv_restore_current_tag(prev_tag);
    tcg_rv_trace_restore_origin(prev_origin);
    st->guest_semantic_emitted = true;
    return true;
}

static void rv_trace_promote_branch_slot_to_terminal_record(void)
{
    RvTraceBuildState *st = rv_trace_build_state;
    int start;

    if (st == NULL || st->insn_meta == NULL || st->guest_idx < 0 ||
        st->insn_offsets == NULL ||
        st->insn_meta[st->guest_idx].branch_idx < 0) {
        return;
    }

    start = st->insn_offsets[st->guest_idx];
    for (int i = st->pos - 1; i >= start; i--) {
        if (rv_emit_origins != NULL &&
            rv_emit_origins[i] != QEMU_PLUGIN_TB_RV_ORIGIN_GUEST) {
            continue;
        }
        st->insn_meta[st->guest_idx].branch_idx = (int8_t)(i - start);
        return;
    }
}

static bool rv_trace_emit_guest_semantic_fallback(void)
{
    RvTraceBuildState *st = rv_trace_build_state;
    uint32_t fallback_insn;
    QemuPluginTbRvOrigin prev;
    qemu_plugin_rv_trace_tag semantic_tag = QEMU_PLUGIN_RV_TAG_NONE;
    qemu_plugin_rv_trace_tag prev_tag = QEMU_PLUGIN_RV_TAG_NONE;
    bool restore_tag = false;

    if (st == NULL || st->guest_idx < 0 ||
        st->guest_semantic_emitted ||
        rv_trace_guest_has_visible_output(st)) {
        return false;
    }

    if (rv_trace_emit_x86_cmov_fallback()) {
        return true;
    }

    if (st->guest_translated_helper_emitted) {
        return rv_trace_emit_guest_helper_placeholder();
    }

    if (st->plugin_tb != NULL &&
        qemu_plugin_tb_get_rv_guest_semantic_fallback(st->plugin_tb,
                                                      st->guest_idx,
                                                      &fallback_insn)) {
        qemu_plugin_tb_get_rv_guest_semantic_tag(st->plugin_tb,
                                                 st->guest_idx,
                                                 &semantic_tag);
        prev = tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
        if (semantic_tag != QEMU_PLUGIN_RV_TAG_NONE &&
            semantic_tag != QEMU_PLUGIN_RV_TAG_MOVCOND) {
            prev_tag = rv_set_current_tag(semantic_tag);
            restore_tag = true;
        }
        if (st->insn_meta && st->guest_idx >= 0 &&
            st->insn_meta[st->guest_idx].branch_idx >= 0) {
            st->insn_meta[st->guest_idx].branch_idx =
                (int8_t)(st->pos - st->insn_offsets[st->guest_idx]);
        }
        rv_emit(st->buf, &st->pos, st->buf_size, fallback_insn);
        if (restore_tag) {
            rv_restore_current_tag(prev_tag);
        }
        tcg_rv_trace_restore_origin(prev);
        st->guest_semantic_emitted = true;
        return true;
    }

    return false;
}

static void rv_trace_emit_unsupported_op(TCGContext *s, TCGOp *op)
{
    RvTraceBuildState *st = rv_trace_build_state;
    uint32_t *buf = st->buf;
    int *pos = &st->pos;
    int buf_size = st->buf_size;
    TCGOpcode opc = op->opc;
    bool is_32bit = TCGOP_TYPE(op) == TCG_TYPE_I32;
    QemuPluginTbRvOrigin prev_origin =
        tcg_rv_trace_set_origin(QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);

    (void)s;
    g_assert(st != NULL);

    if (st->guest_semantic_emitted || rv_trace_emit_guest_semantic_fallback()) {
        goto out;
    }

    rv_trace_counter_note_unsupported(opc);
    rv_current_tag = QEMU_PLUGIN_RV_TAG_NONE;
    if (opc != INDEX_op_deposit &&
        (rv_has_unmapped_nonconst_temps(op) || !rv_prepare_exact_temps(op))) {
        rv_trace_counter_note_generic_placeholder(opc);
        rv_trace_emit_generic_placeholder_op(op);
        goto out;
    }

    switch (opc) {
    case INDEX_op_addco:
    case INDEX_op_addc1o:
    case INDEX_op_addci:
    case INDEX_op_addcio:
    case INDEX_op_subbo:
    case INDEX_op_subb1o:
    case INDEX_op_subbi:
    case INDEX_op_subbio: {
        TracertlRvCarryOp carry_op;
        int rd  = rv_temp_to_reg(op->args[0]);
        int rs1 = rv_temp_to_reg(op->args[1]);
        int rs2 = rv_temp_to_reg(op->args[2]);

        switch (opc) {
        case INDEX_op_addco:  carry_op = TRACERTL_RV_CARRY_ADDCO;  break;
        case INDEX_op_addc1o: carry_op = TRACERTL_RV_CARRY_ADDC1O; break;
        case INDEX_op_addci:  carry_op = TRACERTL_RV_CARRY_ADDCI;  break;
        case INDEX_op_addcio: carry_op = TRACERTL_RV_CARRY_ADDCIO; break;
        case INDEX_op_subbo:  carry_op = TRACERTL_RV_CARRY_SUBBO;  break;
        case INDEX_op_subb1o: carry_op = TRACERTL_RV_CARRY_SUBB1O; break;
        case INDEX_op_subbi:  carry_op = TRACERTL_RV_CARRY_SUBBI;  break;
        default:              carry_op = TRACERTL_RV_CARRY_SUBBIO; break;
        }
        rv_emit_carry_sequence(buf, pos, buf_size, carry_op,
                               is_32bit, rd, rs1, rs2);
        break;
    }
    case INDEX_op_deposit: {
        int rd  = rv_temp_to_reg(op->args[0]);
        TCGTemp *arg1 = arg_temp(op->args[1]);
        TCGTemp *arg2 = arg_temp(op->args[2]);
        TracertlRvOperand base;
        TracertlRvOperand insert;
        uint32_t ofs = op->args[3];
        uint32_t len = op->args[4];
        int emitted_n;

        if (rd < 0) {
            rv_trace_counter_note_generic_placeholder(opc);
            rv_trace_emit_generic_placeholder_op(op);
            break;
        }

        base = arg1 && arg1->val_type == TEMP_VAL_CONST
            ? rv_reg_or_const_operand(arg1->val, true)
            : rv_reg_or_const_operand(rv_temp_to_reg(op->args[1]), false);
        insert = arg2 && arg2->val_type == TEMP_VAL_CONST
            ? rv_reg_or_const_operand(arg2->val, true)
            : rv_reg_or_const_operand(rv_temp_to_reg(op->args[2]), false);
        if ((!base.is_const && base.reg < 0) ||
            (!insert.is_const && insert.reg < 0)) {
            rv_trace_counter_note_generic_placeholder(opc);
            rv_trace_emit_generic_placeholder_op(op);
            break;
        }

        emitted_n = tracertl_rv_emit_deposit_sequence(buf + *pos,
                                                      buf_size - *pos,
                                                      rd, base, insert,
                                                      ofs, len,
                                                      TRACERTL_RV_SCRATCH_REG,
                                                      TRACERTL_RV_ALT_SCRATCH_REG);
        if (emitted_n <= 0) {
            rv_trace_counter_note_generic_placeholder(opc);
            rv_trace_emit_generic_placeholder_op(op);
            break;
        }
        rv_trace_note_current_tcg_op_guest_output();
        *pos += emitted_n;
        break;
    }
    case INDEX_op_extract2: {
        uint32_t insns[5];
        int rd = rv_temp_to_reg(op->args[0]);
        int al = rv_temp_to_reg(op->args[1]);
        int ah = rv_temp_to_reg(op->args[2]);
        uint32_t ofs = op->args[3];
        int n = tracertl_rv_emit_extract2_sequence(insns, ARRAY_SIZE(insns),
                                                   is_32bit, rd, al, ah, ofs);

        rv_emit_shared_sequence(buf, pos, buf_size, n, insns);
        break;
    }
    case INDEX_op_bswap16:
    case INDEX_op_bswap32:
    case INDEX_op_bswap64: {
        uint32_t insns[2];
        int rd = rv_temp_to_reg(op->args[0]);
        int rs = rv_temp_to_reg(op->args[1]);
        unsigned bits = opc == INDEX_op_bswap64 ? 64
                      : opc == INDEX_op_bswap32 ? 32 : 16;
        int n = tracertl_rv_emit_bswap_sequence(insns, ARRAY_SIZE(insns),
                                                bits, rd, rs,
                                                opc == INDEX_op_bswap64
                                                ? 0 : op->args[2]);

        rv_emit_shared_sequence(buf, pos, buf_size, n, insns);
        break;
    }
    default:
        rv_trace_counter_note_generic_placeholder(opc);
        rv_trace_emit_generic_placeholder_op(op);
        break;
    }

out:
    rv_release_dead_temps(op);
    tcg_rv_trace_restore_origin(prev_origin);
}

static int rv_trace_codegen_begin(TCGContext *s, TranslationBlock *tb)
{
    g_assert(rv_trace_build_state != NULL);
    (void)tb;
    return tcg_rv_trace_shared_begin(s);
}

static void rv_trace_codegen_tb_start(TCGContext *s)
{
    (void)s;
}

static bool rv_trace_codegen_skip_current_guest(TCGOp *op)
{
    return rv_trace_build_state->guest_has_branch &&
           op->opc != INDEX_op_insn_start;
}

static bool rv_trace_skip_after_translated_helper(void)
{
    return !rv_target_is_native_riscv_guest() &&
           rv_trace_build_state->guest_translated_helper_emitted;
}

static void rv_trace_codegen_mov(TCGContext *s, TCGOp *op)
{
    rv_trace_begin_current_tcg_op();
    if (rv_trace_codegen_skip_current_guest(op)) {
        goto out;
    }
    if (rv_trace_skip_after_translated_helper()) {
        goto out;
    }
    tcg_rv_trace_shared_mov(s, op);
out:
    rv_trace_finish_current_tcg_op();
}

static void rv_trace_codegen_dup(TCGContext *s, TCGOp *op)
{
    rv_trace_begin_current_tcg_op();
    if (rv_trace_codegen_skip_current_guest(op)) {
        goto out;
    }
    if (rv_trace_skip_after_translated_helper()) {
        goto out;
    }
    tcg_rv_trace_shared_dup(s, op);
out:
    rv_trace_finish_current_tcg_op();
}

static bool rv_trace_codegen_dup2(TCGContext *s, TCGOp *op)
{
    rv_trace_begin_current_tcg_op();
    if (rv_trace_codegen_skip_current_guest(op)) {
        goto out;
    }
    if (rv_trace_skip_after_translated_helper()) {
        goto out;
    }
    if (!tcg_rv_trace_shared_dup2(s, op)) {
        rv_trace_emit_unsupported_op(s, op);
    }
out:
    rv_trace_finish_current_tcg_op();
    return true;
}

static void rv_trace_codegen_insn_start(TCGContext *s, TCGOp *op,
                                        int *num_insns)
{
    rv_trace_begin_guest_insn();
    rv_current_tag = QEMU_PLUGIN_RV_TAG_NONE;
    (void)s;
    (void)op;
    (void)num_insns;
}

static void rv_trace_codegen_discard(TCGContext *s, TCGOp *op)
{
    rv_trace_begin_current_tcg_op();
    if (rv_trace_codegen_skip_current_guest(op)) {
        goto out;
    }
    if (rv_trace_skip_after_translated_helper()) {
        goto out;
    }
    tcg_rv_trace_shared_discard(s, op);
out:
    rv_trace_finish_current_tcg_op();
}

static void rv_trace_codegen_set_label(TCGContext *s, TCGOp *op)
{
    rv_trace_begin_current_tcg_op();
    if (rv_trace_codegen_skip_current_guest(op)) {
        goto out;
    }
    tcg_rv_trace_shared_set_label(s, op);
out:
    rv_trace_finish_current_tcg_op();
}

static void rv_trace_codegen_call(TCGContext *s, TCGOp *op)
{
    const tcg_insn_unit *target;
    const TCGHelperInfo *info;
    bool dead_input_temps;

    rv_trace_begin_current_tcg_op();
    if (rv_trace_codegen_skip_current_guest(op)) {
        goto out;
    }
    target = tcg_call_func(op);
    info = tcg_call_info(op);
    dead_input_temps = rv_call_has_dead_input_temps(op);
    if (!rv_target_is_native_riscv_guest()) {
        if (!rv_trace_skip_after_translated_helper()) {
            rv_backend_out_call(s, target, info);
            if (rv_trace_skip_after_translated_helper()) {
                /*
                 * The translated-helper path already emitted the guest-visible
                 * semantics (or arranged for the guest fallback placeholder).
                 * Do not force the generic helper-call regalloc path, which
                 * can observe dead input temps and abort on some helper-heavy
                 * x86 workloads after delayed HOT activation.
                 */
                rv_release_dead_temps(op);
                goto out;
            }
        }
        if (dead_input_temps) {
            if (!rv_trace_current_tcg_op_has_guest_output()) {
                rv_trace_counter_note_generic_placeholder(op->opc);
                rv_trace_emit_generic_placeholder_op(op);
            }
            rv_release_dead_temps(op);
            goto out;
        }
        if (TCGOP_CALLO(op) == 0) {
            tcg_rv_trace_shared_noreturn_call(s, op);
        } else {
            tcg_rv_trace_shared_call(s, op);
        }
        goto out;
    }
    if (rv_trace_skip_after_translated_helper()) {
        goto out;
    }
    if (dead_input_temps) {
        rv_trace_counter_note_generic_placeholder(op->opc);
        rv_trace_emit_generic_placeholder_op(op);
        rv_release_dead_temps(op);
        goto out;
    }
    tcg_rv_trace_shared_call(s, op);
out:
    rv_trace_finish_current_tcg_op();
}

static void rv_trace_codegen_special(TCGContext *s, TCGOp *op)
{
    rv_trace_begin_current_tcg_op();
    if (rv_trace_codegen_skip_current_guest(op)) {
        goto out;
    }
    rv_trace_note_special_op(op);
    (void)s;
out:
    rv_trace_finish_current_tcg_op();
}

static void rv_trace_codegen_default(TCGContext *s, TCGOp *op)
{
    RvTraceBuildState *st = rv_trace_build_state;
    bool can_handle;
    bool is_vector = op->opc < tcg_op_defs_max &&
                     (tcg_op_defs[op->opc].flags & TCG_OPF_VECTOR);

    rv_trace_begin_current_tcg_op();
    if (rv_trace_codegen_skip_current_guest(op)) {
        goto out;
    }
    if (rv_trace_skip_after_translated_helper()) {
        goto out;
    }
    if (st != NULL && st->guest_semantic_emitted) {
        goto out;
    }
    if (is_vector) {
        rv_trace_emit_generic_placeholder_op(op);
        goto out;
    }
    can_handle = tcg_rv_trace_shared_can_handle(s, op);
    if (can_handle) {
        tcg_rv_trace_shared_default(s, op);
        goto out;
    }
    rv_trace_emit_unsupported_op(s, op);
out:
    rv_trace_finish_current_tcg_op();
}

static int rv_trace_codegen_finish(TCGContext *s, int num_insns)
{
    RvTraceBuildState *st = rv_trace_build_state;

    (void)s;
    (void)num_insns;

    if (st->pending_branch == PENDING_BRANCH_DIRECT) {
        rv_emit_direct_branch_placeholder(st->buf, &st->pos, st->buf_size,
                                          st->insn_meta, st->guest_idx,
                                          st->insn_offsets);
    } else if (st->pending_branch == PENDING_BRANCH_INDIRECT) {
        rv_emit_indirect_branch_placeholder(st->buf, &st->pos, st->buf_size,
                                            st->insn_meta, st->guest_idx,
                                            st->insn_offsets,
                                            st->pending_branch_arg);
    }

    rv_trace_emit_guest_semantic_fallback();
    if (st->guest_helper_emitted) {
        rv_trace_promote_branch_slot_to_terminal_record();
    }

    if (st->guest_idx >= 0) {
        st->insn_offsets[st->guest_idx + 1] = st->pos;
    }
    st->n_guest_insns = st->guest_idx + 1;
    return st->pos > st->buf_size ? -1 : st->pos;
}

static const TCGCodeGenOps rv_trace_codegen_ops = {
    .begin = rv_trace_codegen_begin,
    .tb_start = rv_trace_codegen_tb_start,
    .mov = rv_trace_codegen_mov,
    .dup = rv_trace_codegen_dup,
    .dup2 = rv_trace_codegen_dup2,
    .insn_start = rv_trace_codegen_insn_start,
    .discard = rv_trace_codegen_discard,
    .set_label = rv_trace_codegen_set_label,
    .call = rv_trace_codegen_call,
    .exit_tb = rv_trace_codegen_special,
    .goto_tb = rv_trace_codegen_special,
    .br = rv_trace_codegen_special,
    .mb = rv_trace_codegen_special,
    .default_op = rv_trace_codegen_default,
    .finish = rv_trace_codegen_finish,
};

static int tcg_tb_emit_rv_tagged_live(uint32_t *buf, uint8_t *tags, int buf_size,
                                      int *insn_offsets,
                                      qemu_plugin_rv_insn_meta *insn_meta,
                                      int *n_guest_insns, int *unwind)
{
    TCGContext *s = tcg_ctx;
    sigjmp_buf saved_jmp;
    RvTempMapState temp_map;
    RvTempMapState *saved_temp_map = rv_temp_map_state;
    uint8_t *saved_emit_tags = rv_emit_tags;
    qemu_plugin_rv_trace_tag saved_tag = rv_current_tag;
    QemuPluginTbRvOrigin saved_origin = rv_current_origin;
    RvTraceBuildState state = {
        .buf = buf,
        .tags = tags,
        .buf_size = buf_size,
        .plugin_tb = s->plugin_tb,
        .insn_offsets = insn_offsets,
        .insn_meta = insn_meta,
        .pos = 0,
        .guest_idx = -1,
        .n_guest_insns = 0,
        .guest_has_branch = false,
        .guest_helper_emitted = false,
        .guest_translated_helper_emitted = false,
        .guest_semantic_emitted = false,
        .pending_branch = PENDING_BRANCH_NONE,
        .pending_branch_arg = 0,
        .current_tcg_op_active = false,
        .current_tcg_op_emitted_guest = false,
        .current_tcg_op_deferred_guest_output = false,
    };
    RvTraceBuildState *saved_build_state = rv_trace_build_state;
    int ret;

    if (!s || QTAILQ_EMPTY(&s->ops)) {
        *n_guest_insns = 0;
        return 0;
    }

    rv_temp_map_init(&temp_map);
    rv_temp_map_state = &temp_map;
    rv_emit_tags = tags;
    rv_current_origin = QEMU_PLUGIN_TB_RV_ORIGIN_GUEST;
    rv_current_tag = QEMU_PLUGIN_RV_TAG_NONE;
    rv_trace_build_state = &state;
    rv_trace_backend_prepare(s);
    /* Frame exhaustion must not bypass the temporary backend's cleanup.
     * Return the unwind code to the owner of the allocator snapshot; it
     * restores host state and frees trace buffers before propagating it.
     */
    memcpy(saved_jmp, s->jmp_trans, sizeof(saved_jmp));
    *unwind = sigsetjmp(s->jmp_trans, 0);
    if (*unwind == 0) {
        ret = tcg_gen_code_common(s, NULL, &rv_trace_codegen_ops);
    } else {
        ret = -1;
    }
    memcpy(s->jmp_trans, saved_jmp, sizeof(saved_jmp));
    rv_trace_build_state = saved_build_state;

    rv_emit_tags = saved_emit_tags;
    rv_temp_map_state = saved_temp_map;
    rv_current_tag = saved_tag;
    rv_current_origin = saved_origin;
    *n_guest_insns = *unwind ? 0 : state.n_guest_insns;
    return ret;
}

typedef struct RvTraceTempSnapshot {
    TCGReg reg;
    TCGTempVal val_type;
    unsigned int mem_coherent;
    unsigned int mem_allocated;
    TCGTemp *mem_base;
    intptr_t mem_offset;
} RvTraceTempSnapshot;

typedef struct RvTraceAllocSnapshot {
    RvTraceTempSnapshot *temps;
    TCGTemp *reg_to_temp[TCG_MAX_CODEGEN_REGS];
    intptr_t current_frame_offset;
    TCGBackendState backend;
    TCGRegSet reserved_regs;
    MemOp riscv_cur_vsew;
    TCGType riscv_cur_type;
} RvTraceAllocSnapshot;

static void rv_trace_backend_init_indirect_order(TCGBackendState *backend)
{
    unsigned int n;
    unsigned int i;

    for (n = 0; n < backend->reg_alloc_order_len; ++n) {
        int r = backend->reg_alloc_order[n];

        if (tcg_regset_test_reg(backend->call_clobber_regs, r)) {
            break;
        }
    }
    for (i = 0; i < n; ++i) {
        backend->indirect_reg_alloc_order[i] =
            backend->reg_alloc_order[n - 1 - i];
    }
    for (; i < backend->reg_alloc_order_len; ++i) {
        backend->indirect_reg_alloc_order[i] = backend->reg_alloc_order[i];
    }
}

static void rv_trace_backend_prepare(TCGContext *s)
{
    TCGBackendState *backend = &rv_trace_backend_provider.backend;

    if (!rv_backend_dispatch_ready) {
        tcg_process_backend_constraint_sets(&rv_backend_dispatch);
        rv_backend_dispatch_ready = true;
    }

    if (!rv_trace_backend_provider.initialized) {
        memset(backend, 0, sizeof(*backend));
        backend->nb_regs = 64;
        backend->available_regs[TCG_TYPE_I32] = RV_ALL_GENERAL_REGS;
        backend->available_regs[TCG_TYPE_I64] = RV_ALL_GENERAL_REGS;
        backend->available_regs[TCG_TYPE_V64] = RV_ALL_VECTOR_REGS;
        backend->available_regs[TCG_TYPE_V128] = RV_ALL_VECTOR_REGS;
        backend->available_regs[TCG_TYPE_V256] = RV_ALL_VECTOR_REGS;
        backend->call_clobber_regs = ~((TCGRegSet)0);
        tcg_regset_reset_reg(backend->call_clobber_regs, 8);
        tcg_regset_reset_reg(backend->call_clobber_regs, 9);
        tcg_regset_reset_reg(backend->call_clobber_regs, 18);
        tcg_regset_reset_reg(backend->call_clobber_regs, 19);
        tcg_regset_reset_reg(backend->call_clobber_regs, 20);
        tcg_regset_reset_reg(backend->call_clobber_regs, 21);
        tcg_regset_reset_reg(backend->call_clobber_regs, 22);
        tcg_regset_reset_reg(backend->call_clobber_regs, 23);
        tcg_regset_reset_reg(backend->call_clobber_regs, 24);
        tcg_regset_reset_reg(backend->call_clobber_regs, 25);
        tcg_regset_reset_reg(backend->call_clobber_regs, 26);
        tcg_regset_reset_reg(backend->call_clobber_regs, 27);
        backend->reg_alloc_order = rv_backend_reg_alloc_order;
        backend->reg_alloc_order_len = ARRAY_SIZE(rv_backend_reg_alloc_order);
        backend->call.iarg_regs = rv_backend_call_iarg_regs;
        backend->call.iarg_regs_len = ARRAY_SIZE(rv_backend_call_iarg_regs);
        backend->call.oarg_reg = rv_backend_call_oarg_reg;
        backend->call.stack_reg = 2;
        backend->call.stack_offset = 0;
        backend->call.stack_align = 16;
        backend->call.arg_kind_i32 = TCG_CALL_ARG_NORMAL;
        backend->call.arg_kind_i64 = TCG_CALL_ARG_NORMAL;
        backend->call.arg_kind_i128 = TCG_CALL_ARG_NORMAL;
        backend->call.ret_kind_i128 = TCG_CALL_RET_NORMAL;
        tcg_backend_call_state_init(&backend->call);
        backend->emit.const_match = rv_backend_const_match;
        backend->emit.out_ld = rv_backend_out_ld;
        backend->emit.out_mov = rv_backend_out_mov;
        backend->emit.out_movi = rv_backend_out_movi;
        backend->emit.out_ext8s = rv_backend_out_ext8s;
        backend->emit.out_ext16s = rv_backend_out_ext16s;
        backend->emit.out_ext8u = rv_backend_out_ext8u;
        backend->emit.out_ext16u = rv_backend_out_ext16u;
        backend->emit.out_ext32s = rv_backend_out_ext32s;
        backend->emit.out_ext32u = rv_backend_out_ext32u;
        backend->emit.out_exts_i32_i64 = rv_backend_out_exts_i32_i64;
        backend->emit.out_extu_i32_i64 = rv_backend_out_extu_i32_i64;
        backend->emit.out_extrl_i64_i32 = rv_backend_out_extrl_i64_i32;
        backend->emit.out_addi_ptr = rv_backend_out_addi_ptr;
        backend->emit.out_xchg = rv_backend_out_xchg;
        backend->emit.out_st = rv_backend_out_st;
        backend->emit.out_sti = rv_backend_out_sti;
        backend->emit.out_call = rv_backend_out_call;
        backend->emit.out_goto_ptr = rv_backend_out_goto_ptr;
        backend->emit.out_set_carry = rv_backend_unreachable_set_carry;
        backend->emit.out_set_borrow = rv_backend_unreachable_set_borrow;
        backend->emit.out_dup_vec = rv_backend_unreachable_dup_vec;
        backend->emit.out_dupm_vec = rv_backend_unreachable_dupm_vec;
        backend->emit.out_dupi_vec = rv_backend_unreachable_dupi_vec;
        backend->emit.out_vec_op = rv_backend_unreachable_vec_op;
        backend->dispatch = &rv_backend_dispatch;
        rv_trace_backend_init_indirect_order(backend);
        rv_trace_backend_provider.initialized = true;
    }

    s->backend = *backend;
    s->reserved_regs = 0;
    tcg_regset_set_reg(s->reserved_regs, 0);
    tcg_regset_set_reg(s->reserved_regs, 2);
    tcg_regset_set_reg(s->reserved_regs, 29);
    tcg_regset_set_reg(s->reserved_regs, 30);
    tcg_regset_set_reg(s->reserved_regs, 31);
    s->riscv_cur_vsew = MO_64;
    s->riscv_cur_type = TCG_TYPE_I32;
}

static void rv_trace_snapshot_save(TCGContext *s,
                                   RvTraceAllocSnapshot *snapshot)
{
    snapshot->temps = g_new(RvTraceTempSnapshot, s->nb_temps);
    for (int i = 0; i < s->nb_temps; i++) {
        TCGTemp *ts = &s->temps[i];

        snapshot->temps[i].reg = ts->reg;
        snapshot->temps[i].val_type = ts->val_type;
        snapshot->temps[i].mem_coherent = ts->mem_coherent;
        snapshot->temps[i].mem_allocated = ts->mem_allocated;
        snapshot->temps[i].mem_base = ts->mem_base;
        snapshot->temps[i].mem_offset = ts->mem_offset;
    }

    memcpy(snapshot->reg_to_temp, s->reg_to_temp, sizeof(s->reg_to_temp));
    snapshot->current_frame_offset = s->current_frame_offset;
    snapshot->backend = s->backend;
    snapshot->reserved_regs = s->reserved_regs;
    snapshot->riscv_cur_vsew = s->riscv_cur_vsew;
    snapshot->riscv_cur_type = s->riscv_cur_type;
}

static void rv_trace_snapshot_restore(TCGContext *s,
                                      const RvTraceAllocSnapshot *snapshot)
{
    for (int i = 0; i < s->nb_temps; i++) {
        TCGTemp *ts = &s->temps[i];
        const RvTraceTempSnapshot *saved = &snapshot->temps[i];

        ts->reg = saved->reg;
        ts->val_type = saved->val_type;
        ts->mem_coherent = saved->mem_coherent;
        ts->mem_allocated = saved->mem_allocated;
        ts->mem_base = saved->mem_base;
        ts->mem_offset = saved->mem_offset;
    }

    memcpy(s->reg_to_temp, snapshot->reg_to_temp, sizeof(s->reg_to_temp));
    s->current_frame_offset = snapshot->current_frame_offset;
    s->backend = snapshot->backend;
    s->reserved_regs = snapshot->reserved_regs;
    s->riscv_cur_vsew = snapshot->riscv_cur_vsew;
    s->riscv_cur_type = snapshot->riscv_cur_type;
}

int tcg_tb_emit_rv_tagged(uint32_t *buf, uint8_t *tags, int buf_size,
                          int *insn_offsets,
                          qemu_plugin_rv_insn_meta *insn_meta,
                          int *n_guest_insns)
{
    TCGContext *s = tcg_ctx;
    RvTraceAllocSnapshot snapshot;
    int unwind = 0;
    int ret;

    if (!s || QTAILQ_EMPTY(&s->ops)) {
        *n_guest_insns = 0;
        return 0;
    }

    rv_trace_snapshot_save(s, &snapshot);
    ret = tcg_tb_emit_rv_tagged_live(buf, tags, buf_size,
                                     insn_offsets, insn_meta,
                                     n_guest_insns, &unwind);
    rv_trace_snapshot_restore(s, &snapshot);
    g_free(snapshot.temps);
    if (unwind) {
        siglongjmp(s->jmp_trans, unwind);
    }
    return ret;
}

int tcg_tb_emit_rv(uint32_t *buf, int buf_size,
                   int *insn_offsets,
                   qemu_plugin_rv_insn_meta *insn_meta,
                   int *n_guest_insns)
{
    return tcg_tb_emit_rv_tagged(buf, NULL, buf_size,
                                 insn_offsets, insn_meta,
                                 n_guest_insns);
}

static bool rv_trace_buf_grow(size_t *buf_size)
{
    if (*buf_size > INT_MAX / 2) {
        return false;
    }

    *buf_size = MAX(*buf_size * 2, (size_t)64);
    return true;
}

static void rv_trace_debug_zero_filtered_guest(const struct qemu_plugin_tb *ptb,
                                               int guest_idx,
                                               const int *raw_offsets,
                                               int raw_total_insns,
                                               const uint8_t *raw_origins,
                                               int n_guest_insns)
{
    uint8_t bytes[16] = { 0 };
    size_t copy_size = 0;
    uint64_t pc = 0;
    size_t insn_size = 0;
    int guest = 0;
    int helper_private = 0;
    int allocator_private = 0;
    int start;
    int end;

    if (ptb == NULL || raw_offsets == NULL || raw_origins == NULL ||
        guest_idx < 0 || guest_idx >= n_guest_insns) {
        return;
    }

    start = raw_offsets[guest_idx];
    end = (guest_idx + 1 < n_guest_insns) ? raw_offsets[guest_idx + 1]
                                          : raw_total_insns;
    for (int i = start; i < end; i++) {
        switch (raw_origins[i]) {
        case QEMU_PLUGIN_TB_RV_ORIGIN_GUEST:
            guest++;
            break;
        case QEMU_PLUGIN_TB_RV_ORIGIN_HELPER_PRIVATE:
            helper_private++;
            break;
        case QEMU_PLUGIN_TB_RV_ORIGIN_ALLOCATOR_PRIVATE:
            allocator_private++;
            break;
        default:
            break;
        }
    }

    {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(ptb, guest_idx);

        if (insn != NULL) {
            pc = qemu_plugin_insn_vaddr(insn);
            insn_size = qemu_plugin_insn_size(insn);
            copy_size = qemu_plugin_insn_data_cached(
                insn, bytes, MIN(sizeof(bytes), insn_size));
        }
    }

    fprintf(stderr,
            "rv-trace: zero filtered guest idx=%d pc=0x%" PRIx64
            " size=%zu raw_span=%d guest=%d helper=%d alloc=%d bytes=%s\n",
            guest_idx, pc, insn_size,
            MAX(end - start, 0), guest, helper_private,
            allocator_private,
            copy_size > 0
                ? rv_trace_guest_bytes_counter_name("zero_filtered", bytes,
                                                    copy_size)
                : "zero_filtered:(no-bytes)");
    fflush(stderr);
}

void tcg_plugin_tb_build_rv_trace(TCGContext *s, TranslationBlock *tb)
{
    struct qemu_plugin_tb *ptb = s->plugin_tb;
    RvTraceAllocSnapshot snapshot;
    size_t buf_size;
    size_t n_insns;
    uint32_t *rv_buf = NULL;
    uint8_t *rv_tags = NULL;
    uint8_t *rv_origins = NULL;
    uint32_t *filtered_rv_buf = NULL;
    uint8_t *filtered_rv_tags = NULL;
    uint8_t *filtered_rv_origins = NULL;
    int *offsets = NULL;
    int *filtered_offsets = NULL;
    qemu_plugin_rv_insn_meta *meta = NULL;
    qemu_plugin_rv_insn_meta *filtered_meta = NULL;
    int total_rv = 0;
    int filtered_total_rv = 0;
    int n_guest = 0;
    int unwind = 0;

    (void)tb;

    if (!ptb) {
        return;
    }

    qemu_plugin_tb_set_rv_trace(ptb, NULL, NULL, NULL, NULL, NULL, 0, 0);

    if (QTAILQ_EMPTY(&s->ops)) {
        return;
    }

    n_insns = ptb->n;
    if (n_insns > INT_MAX / 64) {
        return;
    }

    rv_trace_snapshot_save(s, &snapshot);

    buf_size = MAX(n_insns * 64, (size_t)64);
    while (true) {
        rv_buf = g_new(uint32_t, buf_size);
        rv_tags = g_new0(uint8_t, buf_size);
        rv_origins = g_new0(uint8_t, buf_size);
        offsets = g_new(int, n_insns + 1);
        meta = g_new0(qemu_plugin_rv_insn_meta, n_insns);

        rv_trace_snapshot_restore(s, &snapshot);
        rv_emit_origins = rv_origins;
        total_rv = tcg_tb_emit_rv_tagged_live(rv_buf, rv_tags, (int)buf_size,
                                              offsets, meta, &n_guest, &unwind);
        rv_emit_origins = NULL;
        if (unwind) {
            goto out;
        }
        if (total_rv >= 0) {
            break;
        }

        g_free(rv_buf);
        g_free(rv_tags);
        g_free(rv_origins);
        g_free(offsets);
        g_free(meta);
        rv_buf = NULL;
        rv_tags = NULL;
        rv_origins = NULL;
        offsets = NULL;
        meta = NULL;
        n_guest = 0;

        if (!rv_trace_buf_grow(&buf_size)) {
            goto out;
        }
    }

    tracertl_rv_core_filter_bundle(rv_buf, rv_tags, rv_origins, total_rv,
                                   offsets, meta, n_guest,
                                   &filtered_rv_buf, &filtered_rv_tags,
                                   &filtered_rv_origins, &filtered_offsets,
                                   &filtered_meta, &filtered_total_rv);

    for (int i = 0; i < n_guest; i++) {
        if (filtered_offsets[i] == filtered_offsets[i + 1]) {
            rv_trace_debug_zero_filtered_guest(ptb, i, offsets, total_rv,
                                               rv_origins, n_guest);
            break;
        }
    }

    qemu_plugin_tb_set_rv_trace(ptb, filtered_rv_buf, filtered_rv_tags,
                                filtered_rv_origins, filtered_offsets,
                                filtered_meta, filtered_total_rv, n_guest);
    filtered_rv_buf = NULL;
    filtered_rv_tags = NULL;
    filtered_rv_origins = NULL;
    filtered_offsets = NULL;
    filtered_meta = NULL;

out:
    rv_trace_counter_maybe_dump();
    rv_trace_snapshot_restore(s, &snapshot);
    g_free(snapshot.temps);
    g_free(rv_buf);
    g_free(rv_tags);
    g_free(rv_origins);
    g_free(filtered_rv_buf);
    g_free(filtered_rv_tags);
    g_free(filtered_rv_origins);
    g_free(offsets);
    g_free(meta);
    g_free(filtered_offsets);
    g_free(filtered_meta);
    if (unwind) {
        siglongjmp(s->jmp_trans, unwind);
    }
}
