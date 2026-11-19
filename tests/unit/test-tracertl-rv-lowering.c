/*
 * Focused regression test for TracerTL RISC-V lowering helpers.
 *
 * The helpers are shared with plugins/api.c so exact instruction-shape
 * regressions fail here before they can corrupt emitted traces.
 */
#include "qemu/osdep.h"
#include "exec/memop.h"
#include "contrib/plugins/trace_format_c.h"
#include "plugins/tracertl_rv_helpers.h"
#define TRACERTL_RV_VECTOR_LOWERING_UNIT_TEST
#include "plugins/tracertl_rv_vector_lowering.h"

__thread TCGContext *tcg_ctx;

#include "../../plugins/tracertl_rv_vector_lowering.c"

#define MAX_EMIT 4
#define RV_SCRATCH_REG 1

enum {
    RV_OPC_LUI  = 0x37,
    TCG_BSWAP_OS = 4,
    RV_OPC_AND  = 0x7033,
    RV_OPC_OR   = 0x6033,
    RV_OPC_SUB  = 0x40000033U,
    RV_OPC_DIV  = 0x02004033U,
    RV_OPC_DIVU = 0x02005033U,
    RV_OPC_ORI  = 0x6013,
    RV_OPC_SLL  = 0x1033,
    RV_OPC_SRL  = 0x5033,
    RV_OPC_SLLI = 0x1013,
    RV_OPC_SRLI = 0x5013,
    RV_OPC_XORI = 0x4013,
    RV_OPC_SLLW = 0x103b,
    RV_OPC_SRLW = 0x503b,
    RV_OPC_LWU = 0x6003U,
    RV_OPC_LD = 0x3003U,
    RV_OPC_SH = 0x1023U,
    RV_OPC_SD = 0x3023U,
    RV_OPC_JALR = 0x67U,
    RV_OPC_FENCE = 0x0000000fU,
    RV_OPC_ECALL = 0x00000073U,
    RV_OPC_VSETVLI = 0x7057,
    RV_OPC_VADD_VV = 0x57,
    RV_OPC_VADD_VI = 0x3057,
};

typedef struct TracertlRvLoweringFixture {
    TCGContext tcg_ctx_storage;
    TCGTemp temps[8];
} TracertlRvLoweringFixture;

static int test_lowering_map_arg(TCGArg arg, void *opaque)
{
    (void)opaque;
    TCGTemp *ts = arg_temp(arg);
    unsigned int idx = (unsigned int)temp_idx(ts);

    if (ts->base_type >= TCG_TYPE_V64) {
        return tracertl_rv_temp_to_vreg(idx);
    }
    return tracertl_rv_temp_to_reg(idx);
}

static int test_scalar_only_map_arg(TCGArg arg, void *opaque)
{
    (void)opaque;
    return tracertl_rv_temp_to_reg((unsigned int)temp_idx(arg_temp(arg)));
}

static void init_lowering_fixture(TracertlRvLoweringFixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->tcg_ctx_storage.temps = fixture->temps;
    tcg_ctx = &fixture->tcg_ctx_storage;
}

static TCGArg init_temp(TracertlRvLoweringFixture *fixture, size_t idx,
                        TCGType type)
{
    fixture->temps[idx].base_type = type;
    fixture->temps[idx].type = type;
    fixture->temps[idx].val_type = TEMP_VAL_DEAD;
    return temp_arg(&fixture->temps[idx]);
}

static TCGArg init_const_temp(TracertlRvLoweringFixture *fixture, size_t idx,
                              TCGType type, int64_t val)
{
    TCGArg arg = init_temp(fixture, idx, type);

    fixture->temps[idx].val_type = TEMP_VAL_CONST;
    fixture->temps[idx].val = val;
    return arg;
}

static TCGOp *alloc_test_op(TCGOpcode opc, unsigned int nargs)
{
    TCGOp *op = g_malloc0(sizeof(*op) + sizeof(TCGArg) * nargs);

    op->opc = opc;
    op->nargs = nargs;
    return op;
}

static void free_test_op(TCGOp *op)
{
    g_free(op);
}

static uint64_t sign_extend(uint64_t value, unsigned bits)
{
    uint64_t sign = 1ULL << (bits - 1);
    uint64_t mask = (sign << 1) - 1;

    value &= mask;
    return (value ^ sign) - sign;
}

static void exec_load_imm_insn(uint64_t regs[32], uint32_t insn)
{
    uint32_t opc = insn & 0x7f;
    int rd = (insn >> 7) & 0x1f;
    int rs1 = (insn >> 15) & 0x1f;
    uint32_t funct3 = (insn >> 12) & 0x7;
    uint64_t result = 0;

    switch (opc) {
    case RV_OPC_LUI:
        result = sign_extend(insn & 0xfffff000U, 32);
        break;
    case 0x13:
        switch (funct3) {
        case 0x0:
            result = regs[rs1] + sign_extend(insn >> 20, 12);
            break;
        case 0x1:
            result = regs[rs1] << ((insn >> 20) & 0x3f);
            break;
        case 0x6:
            result = regs[rs1] | sign_extend(insn >> 20, 12);
            break;
        default:
            g_assert_not_reached();
        }
        break;
    default:
        g_assert_not_reached();
    }

    if (rd != 0) {
        regs[rd] = result;
    }
    regs[0] = 0;
}

static uint32_t expect_vsetvli(unsigned int type, unsigned int vece)
{
    unsigned int lmul = type - TCG_TYPE_V64;
    unsigned int vtype = (1u << 7) | (1u << 6) | (vece << 3) | lmul;

    return RV_OPC_VSETVLI | (vtype << 20);
}

static uint32_t expect_masked_vi(uint32_t opc, int vd, int32_t imm, int vs2,
                                 bool vm)
{
    return opc | (uint32_t)((vd & 0x1f) << 7)
               | (uint32_t)((imm & 0x1f) << 15)
               | (uint32_t)((vs2 & 0x1f) << 20)
               | (uint32_t)(vm ? 1U : 0U) << 25;
}

static uint32_t expect_memory_placeholder(uint8_t mtype, uint8_t msize)
{
    bool is_store = mtype == TRACE_MEM_TYPE_STORE;

    switch (msize) {
    case 0:
        return is_store ? 0x00000023U : 0x00000003U;
    case 1:
        return is_store ? 0x00001023U : 0x00001003U;
    case 2:
        return is_store ? 0x00002023U : 0x00002003U;
    default:
        return is_store ? 0x00003023U : 0x00003003U;
    }
}

static void exec_shift_or_insn(uint64_t regs[32], uint32_t insn)
{
    uint32_t opc = insn & 0x7f;
    int rd = (insn >> 7) & 0x1f;
    int rs1 = (insn >> 15) & 0x1f;
    uint32_t funct3 = (insn >> 12) & 0x7;
    uint64_t result = 0;

    switch (opc) {
    case 0x13:
        switch (funct3) {
        case 0x1:
            result = regs[rs1] << ((insn >> 20) & 0x3f);
            break;
        case 0x5:
            if (insn & 0x40000000U) {
                result = (uint64_t)((int64_t)regs[rs1] >> ((insn >> 20) & 0x3f));
            } else {
                result = regs[rs1] >> ((insn >> 20) & 0x3f);
            }
            break;
        default:
            g_assert_not_reached();
        }
        break;
    case 0x33:
        g_assert_cmphex(insn & 0xfe00707fU, ==, RV_OPC_OR);
        result = regs[rs1] | regs[(insn >> 20) & 0x1f];
        break;
    default:
        g_assert_not_reached();
    }

    if (rd != 0) {
        regs[rd] = result;
    }
    regs[0] = 0;
}

enum {
    MAX_CORE_TRACE_WORDS = 8,
};

typedef struct TracertlRvTranslatedX86DecodeCase {
    const char *path;
    const uint8_t *bytes;
    size_t len;
    bool is_system_emulation;
    TracertlRvTranslatedX86DecodeStatus status;
    TracertlRvGuestSemanticKind semantic_kind;
    TracertlRvTranslatedX86EmitKind emit_kind;
    bool has_mem_operand;
    uint8_t mem_type;
    uint8_t mem_size;
    bool helper_exception;
    const char *counter_name;
} TracertlRvTranslatedX86DecodeCase;

typedef struct TracertlRvCoreEmitResult {
    uint32_t words[MAX_CORE_TRACE_WORDS];
    uint8_t tags[MAX_CORE_TRACE_WORDS];
    uint8_t origins[MAX_CORE_TRACE_WORDS];
    qemu_plugin_rv_insn_meta meta;
    int total;
    bool guest_has_branch;
} TracertlRvCoreEmitResult;

static uint32_t expect_translated_x86_fallback(
    TracertlRvTranslatedX86EmitKind emit_kind)
{
    switch (emit_kind) {
    case TRACERTL_RV_TRANSLATED_X86_EMIT_TRAP:
        return RV_OPC_ECALL;
    case TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE:
        return RV_OPC_FENCE;
    case TRACERTL_RV_TRANSLATED_X86_EMIT_SUB:
        return tracertl_rv_encode_r(RV_OPC_SUB,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    case TRACERTL_RV_TRANSLATED_X86_EMIT_OR:
        return tracertl_rv_encode_r(RV_OPC_OR,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    case TRACERTL_RV_TRANSLATED_X86_EMIT_SRL:
        return tracertl_rv_encode_r(RV_OPC_SRL,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    case TRACERTL_RV_TRANSLATED_X86_EMIT_DIV:
        return tracertl_rv_encode_r(RV_OPC_DIV,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    case TRACERTL_RV_TRANSLATED_X86_EMIT_DIVU:
        return tracertl_rv_encode_r(RV_OPC_DIVU,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    case TRACERTL_RV_TRANSLATED_X86_EMIT_STORE:
    case TRACERTL_RV_TRANSLATED_X86_EMIT_NONE:
    default:
        return tracertl_rv_encode_r(TRACERTL_RV_OPC_ADD,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    }
}

static void init_core_emit_result(TracertlRvCoreEmitResult *result)
{
    memset(result, 0, sizeof(*result));
    tracertl_rv_core_trace_meta_reset(&result->meta);
}

static void emit_lookup_tb_ptr_result(bool add_private_prefix,
                                      bool add_private_suffix,
                                      TracertlRvCoreEmitResult *result)
{
    int pos = 0;
    TracertlRvCoreTraceSink sink;

    init_core_emit_result(result);
    if (add_private_prefix) {
        result->words[pos] = 0x00000013U;
        result->origins[pos] = QEMU_PLUGIN_TB_RV_ORIGIN_HELPER_PRIVATE;
        pos++;
    }

    sink = (TracertlRvCoreTraceSink) {
        .buf = result->words,
        .tags = result->tags,
        .origins = result->origins,
        .pos = &pos,
        .buf_size = G_N_ELEMENTS(result->words),
        .meta = &result->meta,
        .insn_offset = 0,
        .guest_has_branch = &result->guest_has_branch,
    };

    tracertl_rv_core_emit_lookup_tb_ptr(&sink, 10);

    if (add_private_suffix) {
        result->words[pos] = 0x00000013U;
        result->origins[pos] = QEMU_PLUGIN_TB_RV_ORIGIN_ALLOCATOR_PRIVATE;
        pos++;
    }

    result->total = pos;
}

static void test_lookup_tb_ptr_emit_and_filter(void)
{
    TracertlRvCoreEmitResult raw;
    TracertlRvCoreEmitResult expected;
    int raw_offsets[2];
    qemu_plugin_rv_insn_meta raw_meta[1];
    uint32_t *filtered_words = NULL;
    uint8_t *filtered_tags = NULL;
    uint8_t *filtered_origins = NULL;
    int *filtered_offsets = NULL;
    qemu_plugin_rv_insn_meta *filtered_meta = NULL;
    int filtered_total = 0;

    emit_lookup_tb_ptr_result(false, false, &expected);
    emit_lookup_tb_ptr_result(true, true, &raw);
    raw_offsets[0] = 0;
    raw_offsets[1] = raw.total;
    raw_meta[0] = raw.meta;

    tracertl_rv_core_filter_bundle(raw.words, raw.tags, raw.origins, raw.total,
                                   raw_offsets, raw_meta, 1,
                                   &filtered_words, &filtered_tags,
                                   &filtered_origins, &filtered_offsets,
                                   &filtered_meta, &filtered_total);

    g_assert_cmpint(filtered_total, ==, expected.total);
    g_assert_cmpint(filtered_offsets[0], ==, 0);
    g_assert_cmpint(filtered_offsets[1], ==, expected.total);
    g_assert_cmphex(filtered_words[0], ==,
                    tracertl_rv_encode_i(RV_OPC_JALR, 0, 10, 0));
    g_assert_cmpuint(filtered_tags[0], ==,
                     QEMU_PLUGIN_RV_TAG_INDIRECT_BRANCH_PLACEHOLDER);
    g_assert_cmpuint(filtered_origins[0], ==,
                     QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
    g_assert_cmpint(filtered_meta[0].n_mem, ==, 0);
    g_assert_cmpint(filtered_meta[0].mem_idxs[0], ==, -1);
    g_assert_cmpint(filtered_meta[0].helper_idx, ==, expected.meta.helper_idx);
    g_assert_cmpint(filtered_meta[0].branch_idx, ==, expected.meta.branch_idx);
    g_assert_cmpint(filtered_meta[0].exception_idx, ==,
                    expected.meta.exception_idx);

    g_free(filtered_words);
    g_free(filtered_tags);
    g_free(filtered_origins);
    g_free(filtered_offsets);
    g_free(filtered_meta);
}

static void test_translated_x86_decode_case(gconstpointer data)
{
    const TracertlRvTranslatedX86DecodeCase *test_case = data;
    TracertlRvTranslatedX86Spec spec;
    TracertlRvGuestSemanticPlan plan;

    g_assert_cmpint(tracertl_rv_decode_translated_x86(
                        test_case->bytes, test_case->len,
                        test_case->is_system_emulation, &spec),
                    ==, test_case->status);

    tracertl_rv_build_guest_semantic_plan(test_case->bytes, test_case->len,
                                          true, false,
                                          test_case->is_system_emulation,
                                          &plan);

    if (test_case->status != TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED) {
        g_assert_cmpint(plan.kind, ==, TRACERTL_RV_GUEST_SEM_DEFAULT);
        g_assert_cmpint(plan.n_mem, ==, 0);
        g_assert_cmpstr(plan.counter_name, ==, "translated_default");
        g_assert_cmphex(plan.insns[0], ==,
                        tracertl_rv_encode_r(TRACERTL_RV_OPC_ADD,
                                             TRACERTL_RV_SCRATCH_REG,
                                             TRACERTL_RV_SCRATCH_REG,
                                             TRACERTL_RV_ALT_SCRATCH_REG));
        return;
    }

    g_assert_cmpint(spec.semantic_kind, ==, test_case->semantic_kind);
    g_assert_cmpint(spec.emit_kind, ==, test_case->emit_kind);
    g_assert_cmpint(spec.has_mem_operand, ==, test_case->has_mem_operand);
    g_assert_cmpuint(spec.mem_type, ==, test_case->mem_type);
    g_assert_cmpuint(spec.mem_size, ==, test_case->mem_size);
    g_assert_cmpint(spec.helper_exception, ==, test_case->helper_exception);
    g_assert_cmpstr(spec.counter_name, ==, test_case->counter_name);

    g_assert_cmpint(plan.kind, ==, test_case->semantic_kind);
    g_assert_cmpint(plan.helper_exception, ==, test_case->helper_exception);
    g_assert_cmpstr(plan.counter_name, ==, test_case->counter_name);

    if (test_case->has_mem_operand) {
        g_assert_cmpint(plan.n_mem, ==, 1);
        g_assert_cmpint(plan.mem_idxs[0], ==, 0);
        g_assert_cmpuint(plan.mem_size, ==, test_case->mem_size);
        if (test_case->emit_kind == TRACERTL_RV_TRANSLATED_X86_EMIT_STORE) {
            g_assert_cmpint(plan.n_insns, ==, 1);
            g_assert_cmphex(plan.insns[0], ==,
                            expect_memory_placeholder(test_case->mem_type,
                                                      test_case->mem_size));
        } else {
            g_assert_cmpint(plan.n_insns, ==, 2);
            g_assert_cmphex(plan.insns[0], ==,
                            expect_memory_placeholder(test_case->mem_type,
                                                      test_case->mem_size));
            g_assert_cmphex(plan.insns[1], ==,
                            expect_translated_x86_fallback(
                                test_case->emit_kind));
        }
    } else {
        g_assert_cmpint(plan.n_mem, ==, 0);
        g_assert_cmpint(plan.n_insns, ==, 1);
        g_assert_cmphex(plan.insns[0], ==,
                        expect_translated_x86_fallback(
                            test_case->emit_kind));
    }
}

static void test_rotl_i32_preserves_count(void)
{
    uint32_t buf[MAX_EMIT];
    int n = tracertl_rv_emit_rotate_sequence(buf, MAX_EMIT, true, true,
                                             10, 11, 12);

    g_assert_cmpint(n, ==, 4);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_r(RV_OPC_SLLW, 10, 11, 12));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_SUBW,
                                         RV_SCRATCH_REG, 0, 12));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_r(RV_OPC_SRLW,
                                         RV_SCRATCH_REG, 11, RV_SCRATCH_REG));
    g_assert_cmphex(buf[3], ==,
                    tracertl_rv_encode_r(RV_OPC_OR, 10, 10, RV_SCRATCH_REG));
}

static void test_rotr_i64_preserves_count(void)
{
    uint32_t buf[MAX_EMIT];
    int n = tracertl_rv_emit_rotate_sequence(buf, MAX_EMIT, false, false,
                                             13, 14, 15);

    g_assert_cmpint(n, ==, 4);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_r(RV_OPC_SRL, 13, 14, 15));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_SUB,
                                         RV_SCRATCH_REG, 0, 15));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_r(RV_OPC_SLL,
                                         RV_SCRATCH_REG, 14, RV_SCRATCH_REG));
    g_assert_cmphex(buf[3], ==,
                    tracertl_rv_encode_r(RV_OPC_OR, 13, 13, RV_SCRATCH_REG));
}

static void test_extract_i32_uses_32bit_lane(void)
{
    uint32_t buf[2];
    int n = tracertl_rv_emit_extract_sequence(buf, G_N_ELEMENTS(buf),
                                              true, false,
                                              10, 11, 8, 8);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_i(RV_OPC_SLLI, 10, 11, 48));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_i(RV_OPC_SRLI, 10, 10, 56));
}

static void test_sextract_i32_uses_32bit_lane(void)
{
    uint32_t buf[2];
    int n = tracertl_rv_emit_extract_sequence(buf, G_N_ELEMENTS(buf),
                                              true, true,
                                              10, 11, 8, 8);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_i(RV_OPC_SLLI, 10, 11, 48));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_i(RV_OPC_SRLI, 10, 10, 56 | 0x400));
}

static void test_extract_i32_ignores_upper_xlen_bits(void)
{
    uint32_t buf[2];
    uint64_t regs[32] = { 0 };
    int n = tracertl_rv_emit_extract_sequence(buf, G_N_ELEMENTS(buf),
                                              true, false,
                                              10, 11, 8, 8);

    regs[11] = UINT64_C(0xffffffff80000000);
    g_assert_cmpint(n, ==, 2);
    for (int i = 0; i < n; i++) {
        exec_shift_or_insn(regs, buf[i]);
    }

    g_assert_cmphex(regs[10], ==, 0);
}

static void test_extract2_i32_preserves_high_half(void)
{
    uint32_t buf[5];
    int n = tracertl_rv_emit_extract2_sequence(buf, G_N_ELEMENTS(buf),
                                               true, 10, 11, 12, 8);

    g_assert_cmpint(n, ==, 5);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_i(RV_OPC_SLLI, 10, 11, 32));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_i(RV_OPC_SRLI, 10, 10, 40));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_i(RV_OPC_SLLI, RV_SCRATCH_REG, 12, 32));
    g_assert_cmphex(buf[3], ==,
                    tracertl_rv_encode_i(RV_OPC_SRLI, RV_SCRATCH_REG,
                                         RV_SCRATCH_REG, 8));
    g_assert_cmphex(buf[4], ==,
                    tracertl_rv_encode_r(RV_OPC_OR, 10, 10, RV_SCRATCH_REG));
}

static void test_extract2_i32_ignores_upper_xlen_bits(void)
{
    uint32_t buf[8];
    uint64_t regs[32] = { 0 };
    int n = tracertl_rv_emit_extract2_sequence(buf, G_N_ELEMENTS(buf),
                                               true, 10, 11, 12, 8);

    regs[11] = UINT64_C(0xffffffff00000000);
    regs[12] = UINT64_C(0xffffffff00000001);
    g_assert_cmpint(n, >, 0);
    for (int i = 0; i < n; i++) {
        exec_shift_or_insn(regs, buf[i]);
    }

    g_assert_cmphex(regs[10], ==, UINT64_C(0x0000000001000000));
}

static void test_bswap16_i64_sign_extends(void)
{
    uint32_t buf[2];
    int n = tracertl_rv_emit_bswap_sequence(buf, G_N_ELEMENTS(buf),
                                            16, 10, 11, TCG_BSWAP_OS);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_i(RV_OPC_SRLI, 10, 11, 0x6B8));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_i(RV_OPC_SRLI, 10, 10, 48 | 0x400));
}

static void test_bswap32_i64_sign_extends(void)
{
    uint32_t buf[2];
    int n = tracertl_rv_emit_bswap_sequence(buf, G_N_ELEMENTS(buf),
                                            32, 10, 11, TCG_BSWAP_OS);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_i(RV_OPC_SRLI, 10, 11, 0x6B8));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_i(RV_OPC_SRLI, 10, 10, 32 | 0x400));
}

static void test_move_const_uses_addi_from_x0(void)
{
    uint32_t buf[1];
    TracertlRvOperand src = {
        .is_const = true,
        .imm = 17,
    };
    int n = tracertl_rv_emit_move_sequence(buf, G_N_ELEMENTS(buf), 10, src);

    g_assert_cmpint(n, ==, 1);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI, 10, 0, 17));
}

static void test_add_rhs_const_uses_addi(void)
{
    uint32_t buf[1];
    TracertlRvOperand lhs = {
        .reg = 11,
    };
    TracertlRvOperand rhs = {
        .is_const = true,
        .imm = 9,
    };
    int n = tracertl_rv_emit_add_sequence(buf, G_N_ELEMENTS(buf),
                                          false, 10, lhs, rhs);

    g_assert_cmpint(n, ==, 1);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI, 10, 11, 9));
}

static void test_add_lhs_const_uses_addi(void)
{
    uint32_t buf[1];
    TracertlRvOperand lhs = {
        .is_const = true,
        .imm = -4,
    };
    TracertlRvOperand rhs = {
        .reg = 12,
    };
    int n = tracertl_rv_emit_add_sequence(buf, G_N_ELEMENTS(buf),
                                          true, 10, lhs, rhs);

    g_assert_cmpint(n, ==, 1);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDIW, 10, 12, -4));
}

static void test_add_i32_const_fold_wraps_to_zero(void)
{
    uint32_t buf[16];
    uint64_t regs[32] = { 0 };
    TracertlRvOperand lhs = {
        .is_const = true,
        .imm = 0xffffffffLL,
    };
    TracertlRvOperand rhs = {
        .is_const = true,
        .imm = 1,
    };
    int n = tracertl_rv_emit_add_sequence(buf, G_N_ELEMENTS(buf),
                                          true, 10, lhs, rhs);

    g_assert_cmpint(n, >, 0);
    for (int i = 0; i < n; i++) {
        exec_load_imm_insn(regs, buf[i]);
    }

    g_assert_cmphex(regs[10], ==, 0);
}

static void test_add_i32_const_fold_sign_extends_result(void)
{
    uint32_t buf[16];
    uint64_t regs[32] = { 0 };
    TracertlRvOperand lhs = {
        .is_const = true,
        .imm = 0x7fffffffLL,
    };
    TracertlRvOperand rhs = {
        .is_const = true,
        .imm = 1,
    };
    int n = tracertl_rv_emit_add_sequence(buf, G_N_ELEMENTS(buf),
                                          true, 10, lhs, rhs);

    g_assert_cmpint(n, >, 0);
    for (int i = 0; i < n; i++) {
        exec_load_imm_insn(regs, buf[i]);
    }

    g_assert_cmphex(regs[10], ==, UINT64_C(0xffffffff80000000));
}

static void test_deposit_sequence_masks_and_inserts_bits(void)
{
    uint32_t buf[16];
    TracertlRvOperand base = {
        .reg = 11,
    };
    TracertlRvOperand insert = {
        .reg = 12,
    };
    int n = tracertl_rv_emit_deposit_sequence(buf, G_N_ELEMENTS(buf),
                                              10, base, insert,
                                              16, 8,
                                              TRACERTL_RV_SCRATCH_REG,
                                              TRACERTL_RV_ALT_SCRATCH_REG);

    g_assert_cmpint(n, ==, 11);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI, 10, 11, 0));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI,
                                         TRACERTL_RV_SCRATCH_REG, 0, 1));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_i(RV_OPC_SLLI,
                                         TRACERTL_RV_SCRATCH_REG,
                                         TRACERTL_RV_SCRATCH_REG, 8));
    g_assert_cmphex(buf[3], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI,
                                         TRACERTL_RV_SCRATCH_REG,
                                         TRACERTL_RV_SCRATCH_REG, -1));
    g_assert_cmphex(buf[4], ==,
                    tracertl_rv_encode_i(RV_OPC_SLLI,
                                         TRACERTL_RV_ALT_SCRATCH_REG,
                                         TRACERTL_RV_SCRATCH_REG, 16));
    g_assert_cmphex(buf[5], ==,
                    tracertl_rv_encode_i(RV_OPC_XORI,
                                         TRACERTL_RV_ALT_SCRATCH_REG,
                                         TRACERTL_RV_ALT_SCRATCH_REG, 0xfff));
    g_assert_cmphex(buf[6], ==,
                    tracertl_rv_encode_r(RV_OPC_AND, 10, 10,
                                         TRACERTL_RV_ALT_SCRATCH_REG));
    g_assert_cmphex(buf[7], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI,
                                         TRACERTL_RV_ALT_SCRATCH_REG,
                                         12, 0));
    g_assert_cmphex(buf[8], ==,
                    tracertl_rv_encode_r(RV_OPC_AND,
                                         TRACERTL_RV_ALT_SCRATCH_REG,
                                         TRACERTL_RV_ALT_SCRATCH_REG,
                                         TRACERTL_RV_SCRATCH_REG));
    g_assert_cmphex(buf[9], ==,
                    tracertl_rv_encode_i(RV_OPC_SLLI,
                                         TRACERTL_RV_ALT_SCRATCH_REG,
                                         TRACERTL_RV_ALT_SCRATCH_REG, 16));
    g_assert_cmphex(buf[10], ==,
                    tracertl_rv_encode_r(RV_OPC_OR, 10, 10,
                                         TRACERTL_RV_ALT_SCRATCH_REG));
}

static void test_zero_compare_uses_x0(void)
{
    TracertlRvOperand zero = {
        .is_const = true,
        .imm = 0,
    };
    TracertlRvOperand reg = {
        .reg = 13,
    };

    g_assert_cmpint(tracertl_rv_cmp_operand_reg(zero), ==, 0);
    g_assert_cmpint(tracertl_rv_cmp_operand_reg(reg), ==, 13);
}

static void test_nonzero_compare_const_requires_fallback(void)
{
    TracertlRvOperand imm = {
        .is_const = true,
        .imm = 5,
    };

    g_assert_cmpint(tracertl_rv_cmp_operand_reg(imm), ==, -1);
}

static void test_load_large_const_materializes_bytes(void)
{
    uint32_t buf[16];
    int n = tracertl_rv_emit_load_imm_sequence(buf, G_N_ELEMENTS(buf), 10,
                                               0x123456789abcdef0ULL);

    g_assert_cmpint(n, ==, 15);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI, 10, 0, 0x12));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_i(RV_OPC_SLLI, 10, 10, 8));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_i(RV_OPC_ORI, 10, 10, 0x34));
    g_assert_cmphex(buf[14], ==,
                    tracertl_rv_encode_i(RV_OPC_ORI, 10, 10, 0xf0));
}

static void test_load_uint32_mask_keeps_zero_extension(void)
{
    uint32_t buf[16];
    uint64_t regs[32] = { 0 };
    int n = tracertl_rv_emit_load_imm_sequence(buf, G_N_ELEMENTS(buf), 10,
                                               0x00000000ffffffffULL);

    g_assert_cmpint(n, >, 0);
    for (int i = 0; i < n; i++) {
        exec_load_imm_insn(regs, buf[i]);
    }

    g_assert_cmphex(regs[10], ==, 0x00000000ffffffffULL);
}

static void test_nonzero_compare_const_materializes_scratch(void)
{
    uint32_t buf[16];
    TracertlRvOperand imm = {
        .is_const = true,
        .imm = 0x1234,
    };
    int reg_out = -1;
    int n = tracertl_rv_emit_cmp_operand_sequence(buf, G_N_ELEMENTS(buf), imm,
                                                  TRACERTL_RV_SCRATCH_REG,
                                                  &reg_out);

    g_assert_cmpint(n, >, 0);
    g_assert_cmpint(reg_out, ==, TRACERTL_RV_SCRATCH_REG);
    g_assert_cmphex(buf[0], ==, 0x000010b7);
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI,
                                         TRACERTL_RV_SCRATCH_REG,
                                         TRACERTL_RV_SCRATCH_REG, 0x234));
}

static void test_guest_semantic_plan_syscall_is_ecall(void)
{
    static const uint8_t bytes[] = { 0x0f, 0x05 };
    TracertlRvGuestSemanticPlan plan;

    tracertl_rv_build_guest_semantic_plan(bytes, sizeof(bytes),
                                          true, false, false, &plan);

    g_assert_cmpint(plan.n_insns, ==, 1);
    g_assert_cmphex(plan.insns[0], ==, RV_OPC_ECALL);
    g_assert_cmpint(plan.n_mem, ==, 0);
    g_assert_cmpint(plan.branch_idx, ==, -1);
    g_assert_cmpint(plan.kind, ==, TRACERTL_RV_GUEST_SEM_TRAP);
    g_assert_true(plan.helper_exception);
    g_assert_cmpstr(plan.counter_name, ==, "x86_trap");
}

static void test_guest_semantic_plan_cpuid_is_fence(void)
{
    static const uint8_t bytes[] = { 0x0f, 0xa2 };
    TracertlRvGuestSemanticPlan plan;

    tracertl_rv_build_guest_semantic_plan(bytes, sizeof(bytes),
                                          true, false, false, &plan);

    g_assert_cmpint(plan.n_insns, ==, 1);
    g_assert_cmphex(plan.insns[0], ==, RV_OPC_FENCE);
    g_assert_cmpint(plan.n_mem, ==, 0);
    g_assert_cmpint(plan.kind, ==, TRACERTL_RV_GUEST_SEM_SERIALIZE);
    g_assert_false(plan.helper_exception);
    g_assert_cmpstr(plan.counter_name, ==, "x86_serialize");
}

static void test_guest_semantic_plan_mfence_is_fence(void)
{
    static const uint8_t bytes[] = { 0x0f, 0xae, 0xf0 };
    TracertlRvGuestSemanticPlan plan;

    tracertl_rv_build_guest_semantic_plan(bytes, sizeof(bytes),
                                          true, false, false, &plan);

    g_assert_cmpint(plan.n_insns, ==, 1);
    g_assert_cmphex(plan.insns[0], ==, RV_OPC_FENCE);
    g_assert_cmpint(plan.n_mem, ==, 0);
    g_assert_cmpint(plan.kind, ==, TRACERTL_RV_GUEST_SEM_SERIALIZE);
    g_assert_false(plan.helper_exception);
    g_assert_cmpstr(plan.counter_name, ==, "x86_serialize");
}

static void test_guest_semantic_plan_div_mem_adds_mem_slot(void)
{
    static const uint8_t bytes[] = { 0xf7, 0x38 };
    TracertlRvGuestSemanticPlan plan;

    tracertl_rv_build_guest_semantic_plan(bytes, sizeof(bytes),
                                          true, false, false, &plan);

    g_assert_cmpint(plan.n_insns, ==, 2);
    g_assert_cmphex(plan.insns[0], ==,
                    expect_memory_placeholder(TRACE_MEM_TYPE_LOAD, 2));
    g_assert_cmphex(plan.insns[1], ==,
                    tracertl_rv_encode_r(RV_OPC_DIV,
                                         TRACERTL_RV_SCRATCH_REG,
                                         TRACERTL_RV_SCRATCH_REG,
                                         TRACERTL_RV_ALT_SCRATCH_REG));
    g_assert_cmpint(plan.n_mem, ==, 1);
    g_assert_cmpint(plan.mem_idxs[0], ==, 0);
    g_assert_cmpuint(plan.mem_size, ==, 2);
    g_assert_cmpint(plan.kind, ==, TRACERTL_RV_GUEST_SEM_DIV_SIGNED);
    g_assert_cmphex(tracertl_rv_guest_semantic_fallback_insn(&plan), ==,
                    plan.insns[1]);
    g_assert_cmpstr(plan.counter_name, ==, "x86_idiv_mem");
}

static void test_guest_semantic_plan_compare_mem_adds_mem_slot(void)
{
    static const uint8_t bytes[] = { 0x66, 0x0f, 0x2e, 0x08 };
    TracertlRvGuestSemanticPlan plan;

    tracertl_rv_build_guest_semantic_plan(bytes, sizeof(bytes),
                                          true, false, false, &plan);

    g_assert_cmpint(plan.n_insns, ==, 2);
    g_assert_cmphex(plan.insns[0], ==,
                    expect_memory_placeholder(TRACE_MEM_TYPE_LOAD, 3));
    g_assert_cmphex(plan.insns[1], ==,
                    tracertl_rv_encode_r(RV_OPC_SUB,
                                         TRACERTL_RV_SCRATCH_REG,
                                         TRACERTL_RV_SCRATCH_REG,
                                         TRACERTL_RV_ALT_SCRATCH_REG));
    g_assert_cmpint(plan.n_mem, ==, 1);
    g_assert_cmpint(plan.mem_idxs[0], ==, 0);
    g_assert_cmpuint(plan.mem_size, ==, 3);
    g_assert_cmpint(plan.kind, ==, TRACERTL_RV_GUEST_SEM_FP_COMPARE);
    g_assert_cmpstr(plan.counter_name, ==, "x86_fp_compare_mem");
}

static void test_guest_semantic_plan_vector_mem_splits_anon_family(void)
{
    static const uint8_t bytes[] = { 0x66, 0x0f, 0x62, 0x08 };
    TracertlRvGuestSemanticPlan plan;

    tracertl_rv_build_guest_semantic_plan(bytes, sizeof(bytes),
                                          true, false, false, &plan);

    g_assert_cmpint(plan.n_insns, ==, 2);
    g_assert_cmphex(plan.insns[0], ==,
                    expect_memory_placeholder(TRACE_MEM_TYPE_LOAD, 3));
    g_assert_cmphex(plan.insns[1], ==,
                    tracertl_rv_encode_r(RV_OPC_OR,
                                         TRACERTL_RV_SCRATCH_REG,
                                         TRACERTL_RV_SCRATCH_REG,
                                         TRACERTL_RV_ALT_SCRATCH_REG));
    g_assert_cmpint(plan.n_mem, ==, 1);
    g_assert_cmpint(plan.mem_idxs[0], ==, 0);
    g_assert_cmpuint(plan.mem_size, ==, 3);
    g_assert_cmpint(plan.kind, ==, TRACERTL_RV_GUEST_SEM_VECTOR_UNPACK);
    g_assert_cmpstr(plan.counter_name, ==, "x86_vector_unpack_mem");
}

static void test_guest_semantic_plan_fnstcw_is_store(void)
{
    static const uint8_t bytes[] = { 0xd9, 0x38 };
    TracertlRvGuestSemanticPlan plan;

    tracertl_rv_build_guest_semantic_plan(bytes, sizeof(bytes),
                                          true, false, false, &plan);

    g_assert_cmpint(plan.n_insns, ==, 1);
    g_assert_cmphex(plan.insns[0], ==,
                    expect_memory_placeholder(TRACE_MEM_TYPE_STORE, 1));
    g_assert_cmpint(plan.n_mem, ==, 1);
    g_assert_cmpint(plan.mem_idxs[0], ==, 0);
    g_assert_cmpuint(plan.mem_size, ==, 1);
    g_assert_cmpint(plan.kind, ==, TRACERTL_RV_GUEST_SEM_X87_STORE);
    g_assert_cmpstr(plan.counter_name, ==, "x86_x87_store");
}

static const uint8_t core_helper_bytes_syscall[] = { 0x0f, 0x05 };
static const uint8_t core_helper_bytes_cpuid[] = { 0x0f, 0xa2 };
static const uint8_t core_helper_bytes_xgetbv[] = { 0x0f, 0x01, 0xd0 };
static const uint8_t core_helper_bytes_lfence[] = { 0x0f, 0xae, 0xe8 };
static const uint8_t core_helper_bytes_mfence[] = { 0x0f, 0xae, 0xf0 };
static const uint8_t core_helper_bytes_sfence[] = { 0x0f, 0xae, 0xf8 };
static const uint8_t core_helper_bytes_divl_mem[] = { 0xf7, 0x30 };
static const uint8_t core_helper_bytes_idivq_mem[] = { 0x48, 0xf7, 0x38 };
static const uint8_t core_helper_bytes_ucomisd_mem[] = { 0x66, 0x0f, 0x2e, 0x08 };
static const uint8_t core_helper_bytes_punpckldq_mem[] = { 0x66, 0x0f, 0x62, 0x08 };
static const uint8_t core_helper_bytes_psrldq[] = { 0x66, 0x0f, 0x73, 0xd8, 0x08 };
static const uint8_t core_helper_bytes_divsd_mem[] = { 0xf2, 0x0f, 0x5e, 0x08 };
static const uint8_t core_helper_bytes_cvtsq2sd_mem[] = { 0xf2, 0x48, 0x0f, 0x2a, 0x08 };
static const uint8_t core_helper_bytes_cvttsd2sq_mem[] = { 0xf2, 0x48, 0x0f, 0x2c, 0x08 };
static const uint8_t core_helper_bytes_fnstcw[] = { 0xd9, 0x38 };
static const uint8_t residual_x87_bytes_fldt[] = { 0xdb, 0x28 };
static const uint8_t residual_x87_bytes_fistpll[] = { 0xdf, 0x38 };

static const TracertlRvTranslatedX86DecodeCase translated_x86_decode_cases[] = {
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/syscall",
        .bytes = core_helper_bytes_syscall,
        .len = G_N_ELEMENTS(core_helper_bytes_syscall),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_TRAP,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_TRAP,
        .helper_exception = true,
        .counter_name = "x86_trap",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/cpuid",
        .bytes = core_helper_bytes_cpuid,
        .len = G_N_ELEMENTS(core_helper_bytes_cpuid),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_SERIALIZE,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE,
        .counter_name = "x86_serialize",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/lfence",
        .bytes = core_helper_bytes_lfence,
        .len = G_N_ELEMENTS(core_helper_bytes_lfence),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_SERIALIZE,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE,
        .counter_name = "x86_serialize",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/mfence",
        .bytes = core_helper_bytes_mfence,
        .len = G_N_ELEMENTS(core_helper_bytes_mfence),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_SERIALIZE,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE,
        .counter_name = "x86_serialize",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/sfence",
        .bytes = core_helper_bytes_sfence,
        .len = G_N_ELEMENTS(core_helper_bytes_sfence),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_SERIALIZE,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE,
        .counter_name = "x86_serialize",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/xgetbv",
        .bytes = core_helper_bytes_xgetbv,
        .len = G_N_ELEMENTS(core_helper_bytes_xgetbv),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_SERIALIZE,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE,
        .counter_name = "x86_serialize",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/divl-mem",
        .bytes = core_helper_bytes_divl_mem,
        .len = G_N_ELEMENTS(core_helper_bytes_divl_mem),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_DIV_UNSIGNED,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_DIVU,
        .has_mem_operand = true,
        .mem_type = TRACE_MEM_TYPE_LOAD,
        .mem_size = 2,
        .counter_name = "x86_div_mem",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/idivq-mem",
        .bytes = core_helper_bytes_idivq_mem,
        .len = G_N_ELEMENTS(core_helper_bytes_idivq_mem),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_DIV_SIGNED,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_DIV,
        .has_mem_operand = true,
        .mem_type = TRACE_MEM_TYPE_LOAD,
        .mem_size = 3,
        .counter_name = "x86_idiv_mem",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/ucomisd-mem",
        .bytes = core_helper_bytes_ucomisd_mem,
        .len = G_N_ELEMENTS(core_helper_bytes_ucomisd_mem),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_FP_COMPARE,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_SUB,
        .has_mem_operand = true,
        .mem_type = TRACE_MEM_TYPE_LOAD,
        .mem_size = 3,
        .counter_name = "x86_fp_compare_mem",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/punpckldq-mem",
        .bytes = core_helper_bytes_punpckldq_mem,
        .len = G_N_ELEMENTS(core_helper_bytes_punpckldq_mem),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_VECTOR_UNPACK,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_OR,
        .has_mem_operand = true,
        .mem_type = TRACE_MEM_TYPE_LOAD,
        .mem_size = 3,
        .counter_name = "x86_vector_unpack_mem",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/psrldq",
        .bytes = core_helper_bytes_psrldq,
        .len = G_N_ELEMENTS(core_helper_bytes_psrldq),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_SHIFT,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_SRL,
        .counter_name = "x86_shift",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/divsd-mem",
        .bytes = core_helper_bytes_divsd_mem,
        .len = G_N_ELEMENTS(core_helper_bytes_divsd_mem),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_FP_DIV,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_DIV,
        .has_mem_operand = true,
        .mem_type = TRACE_MEM_TYPE_LOAD,
        .mem_size = 3,
        .counter_name = "x86_fp_div_mem",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/cvtsq2sd-mem",
        .bytes = core_helper_bytes_cvtsq2sd_mem,
        .len = G_N_ELEMENTS(core_helper_bytes_cvtsq2sd_mem),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_CONVERT,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_OR,
        .has_mem_operand = true,
        .mem_type = TRACE_MEM_TYPE_LOAD,
        .mem_size = 3,
        .counter_name = "x86_convert_mem",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/cvttsd2sq-mem",
        .bytes = core_helper_bytes_cvttsd2sq_mem,
        .len = G_N_ELEMENTS(core_helper_bytes_cvttsd2sq_mem),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_CONVERT,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_OR,
        .has_mem_operand = true,
        .mem_type = TRACE_MEM_TYPE_LOAD,
        .mem_size = 3,
        .counter_name = "x86_convert_mem",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/fnstcw-user",
        .bytes = core_helper_bytes_fnstcw,
        .len = G_N_ELEMENTS(core_helper_bytes_fnstcw),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_X87_STORE,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_STORE,
        .has_mem_operand = true,
        .mem_type = TRACE_MEM_TYPE_STORE,
        .mem_size = 1,
        .counter_name = "x86_x87_store",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/fnstcw-system",
        .bytes = core_helper_bytes_fnstcw,
        .len = G_N_ELEMENTS(core_helper_bytes_fnstcw),
        .is_system_emulation = true,
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
        .semantic_kind = TRACERTL_RV_GUEST_SEM_X87_STORE,
        .emit_kind = TRACERTL_RV_TRANSLATED_X86_EMIT_STORE,
        .has_mem_operand = true,
        .mem_type = TRACE_MEM_TYPE_STORE,
        .mem_size = 3,
        .counter_name = "x86_x87_store",
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/residual-fldt",
        .bytes = residual_x87_bytes_fldt,
        .len = G_N_ELEMENTS(residual_x87_bytes_fldt),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_RESIDUAL_UNSUPPORTED,
    },
    {
        .path = "/tracertl/rv-lowering/translated-x86-decode/residual-fistpll",
        .bytes = residual_x87_bytes_fistpll,
        .len = G_N_ELEMENTS(residual_x87_bytes_fistpll),
        .status = TRACERTL_RV_TRANSLATED_X86_DECODE_RESIDUAL_UNSUPPORTED,
    },
};

static void test_temp_to_reg_keeps_first_pool_unique(void)
{
    bool seen[32] = { false };

    for (unsigned int i = 0; i < 28; i++) {
        int reg = tracertl_rv_temp_to_reg(i);

        g_assert_cmpint(reg, !=, 0);
        g_assert_cmpint(reg, !=, TRACERTL_RV_SCRATCH_REG);
        g_assert_cmpint(reg, !=, TRACERTL_RV_ALT_SCRATCH_REG);
        g_assert_cmpint(reg, !=, TRACERTL_RV_CARRY_REG);
        g_assert_false(seen[reg]);
        seen[reg] = true;
    }
}

static void test_alt_scratch_and_carry_regs_are_distinct(void)
{
    g_assert_cmpint(TRACERTL_RV_ALT_SCRATCH_REG, !=, TRACERTL_RV_CARRY_REG);
}

static void test_temp_to_reg_spreads_overflow_slots(void)
{
    g_assert_cmpint(tracertl_rv_temp_to_reg(28), ==, -1);
    g_assert_cmpint(tracertl_rv_temp_to_reg(37), ==, -1);
}

static void test_encode_vv_sets_field_positions(void)
{
    uint32_t insn = tracertl_rv_encode_v(RV_OPC_VADD_VV, 9, 10, 11);

    g_assert_cmphex(insn, ==,
                    RV_OPC_VADD_VV | (9u << 7) | (10u << 15) |
                    (11u << 20) | (1u << 25));
}

static void test_encode_vi_sets_field_positions(void)
{
    uint32_t insn = tracertl_rv_encode_vi(RV_OPC_VADD_VI, 12, -1, 13);

    g_assert_cmphex(insn, ==,
                    RV_OPC_VADD_VI | (12u << 7) | (31u << 15) |
                    (13u << 20) | (1u << 25));
}

static void test_vsetvli_v64_e32_uses_m1(void)
{
    uint32_t buf[1];
    int n = tracertl_rv_emit_vsetvli(buf, G_N_ELEMENTS(buf),
                                     TCG_TYPE_V64, MO_32);

    g_assert_cmpint(n, ==, 1);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V64, MO_32));
}

static void test_vsetvli_v256_e64_uses_wider_lmul(void)
{
    uint32_t buf[1];
    int n = tracertl_rv_emit_vsetvli(buf, G_N_ELEMENTS(buf),
                                     TCG_TYPE_V256, MO_64);

    g_assert_cmpint(n, ==, 1);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_64));
}

static void test_temp_to_vreg_reserves_v0_and_limits_pool(void)
{
    g_assert_cmpint(tracertl_rv_temp_to_vreg(0), ==, 33);
    g_assert_cmpint(tracertl_rv_temp_to_vreg(30), ==, 63);
    g_assert_cmpint(tracertl_rv_temp_to_vreg(31), ==, -1);
}

static void test_vector_sequence_reuses_vsetvli_for_same_shape(void)
{
    uint32_t buf[8];
    TracertlRvVectorState state = { 0 };
    TracertlRvVectorOp add = {
        .opc = TRACERTL_RV_VECOP_ADD,
        .type = TCG_TYPE_V256,
        .vece = MO_32,
        .rd = 33,
        .rs1 = 34,
        .rs2 = 35,
    };
    TracertlRvVectorOp xor = {
        .opc = TRACERTL_RV_VECOP_XOR,
        .type = TCG_TYPE_V256,
        .vece = MO_32,
        .rd = 36,
        .rs1 = 37,
        .rs2 = 38,
    };
    int n0 = tracertl_rv_emit_vector_sequence(buf, G_N_ELEMENTS(buf),
                                              &state, &add, NULL);
    int n1 = tracertl_rv_emit_vector_sequence(buf + n0,
                                              G_N_ELEMENTS(buf) - n0,
                                              &state, &xor, NULL);

    g_assert_cmpint(n0, ==, 2);
    g_assert_cmpint(n1, ==, 1);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_32));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VADD_VV, 33, 35, 34));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VXOR_VV, 36, 38, 37));
}

static void test_vector_sequence_rotlv_keeps_order(void)
{
    uint32_t buf[8];
    TracertlRvVectorState state = { 0 };
    TracertlRvVectorOp rot = {
        .opc = TRACERTL_RV_VECOP_ROTLV,
        .type = TCG_TYPE_V256,
        .vece = MO_32,
        .rd = 33,
        .rs1 = 34,
        .rs2 = 35,
    };
    int n = tracertl_rv_emit_vector_sequence(buf, G_N_ELEMENTS(buf),
                                             &state, &rot, NULL);

    g_assert_cmpint(n, ==, 5);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_32));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_vi(TRACERTL_RV_OPC_VRSUB_VI,
                                          TRACERTL_RV_V0_REG, 0, 35));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VSRL_VV,
                                         TRACERTL_RV_V0_REG,
                                         TRACERTL_RV_V0_REG, 34));
    g_assert_cmphex(buf[3], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VSLL_VV,
                                         33, 35, 34));
    g_assert_cmphex(buf[4], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VOR_VV,
                                         33, TRACERTL_RV_V0_REG, 33));
}

static void test_vector_sequence_ld_vec_reserves_guest_mem_slot(void)
{
    uint32_t buf[4];
    TracertlRvVectorState state = { 0 };
    TracertlRvVectorOp ld = {
        .opc = TRACERTL_RV_VECOP_LD,
        .type = TCG_TYPE_V256,
        .vece = MO_64,
        .rd = 33,
        .rs1 = 10,
    };
    TracertlRvVectorEmitMeta meta = { .note_mem_slot = true };
    int n = tracertl_rv_emit_vector_sequence(buf, G_N_ELEMENTS(buf),
                                             &state, &ld, &meta);

    g_assert_cmpint(n, ==, 2);
    g_assert_true(meta.note_mem_slot);
    g_assert_cmpint(meta.mem_slot_rel_idx, ==, 1);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_64));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_v(tracertl_rv_vector_ld_opc(MO_64),
                                         33, 10, 0));
}

static void test_vector_sequence_shli_accepts_uimm5_31(void)
{
    uint32_t buf[4];
    TracertlRvVectorState state = { 0 };
    TracertlRvVectorOp shli = {
        .opc = TRACERTL_RV_VECOP_SHLI,
        .type = TCG_TYPE_V256,
        .vece = MO_32,
        .rd = 33,
        .rs1 = 34,
        .arg2_is_const = true,
        .arg2_imm = 31,
    };
    int n = tracertl_rv_emit_vector_sequence(buf, G_N_ELEMENTS(buf),
                                             &state, &shli, NULL);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_32));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_vi(TRACERTL_RV_OPC_VSLL_VI,
                                          33, 31, 34));
}

static void test_vector_sequence_rotli_accepts_uimm5_31(void)
{
    uint32_t buf[8];
    TracertlRvVectorState state = { 0 };
    TracertlRvVectorOp rotli = {
        .opc = TRACERTL_RV_VECOP_ROTLI,
        .type = TCG_TYPE_V256,
        .vece = MO_32,
        .rd = 33,
        .rs1 = 34,
        .arg2_is_const = true,
        .arg2_imm = 31,
    };
    int n = tracertl_rv_emit_vector_sequence(buf, G_N_ELEMENTS(buf),
                                             &state, &rotli, NULL);

    g_assert_cmpint(n, ==, 4);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_32));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_vi(TRACERTL_RV_OPC_VSLL_VI,
                                          TRACERTL_RV_V0_REG, 31, 34));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_vi(TRACERTL_RV_OPC_VSRL_VI,
                                          33, 1, 34));
    g_assert_cmphex(buf[3], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VOR_VV,
                                         33, TRACERTL_RV_V0_REG, 33));
}

static void test_plugin_vector_lowering_reuses_vsetvli_for_same_shape(void)
{
    uint32_t buf[8];
    TracertlRvLoweringFixture fixture;
    TracertlRvVectorState state = { 0 };
    TCGOp *add;
    TCGOp *xor;
    int n0;
    int n1;

    init_lowering_fixture(&fixture);
    add = alloc_test_op(INDEX_op_add_vec, 3);
    xor = alloc_test_op(INDEX_op_xor_vec, 3);
    TCGOP_TYPE(add) = TCG_TYPE_V256;
    TCGOP_TYPE(xor) = TCG_TYPE_V256;
    TCGOP_VECE(add) = MO_32;
    TCGOP_VECE(xor) = MO_32;
    add->args[0] = init_temp(&fixture, 0, TCG_TYPE_V256);
    add->args[1] = init_temp(&fixture, 1, TCG_TYPE_V256);
    add->args[2] = init_temp(&fixture, 2, TCG_TYPE_V256);
    xor->args[0] = init_temp(&fixture, 3, TCG_TYPE_V256);
    xor->args[1] = init_temp(&fixture, 4, TCG_TYPE_V256);
    xor->args[2] = init_temp(&fixture, 5, TCG_TYPE_V256);

    n0 = tracertl_rv_lower_vector_tcg_op(buf, G_N_ELEMENTS(buf), &state, add,
                                         test_lowering_map_arg, NULL, NULL);
    n1 = tracertl_rv_lower_vector_tcg_op(buf + n0, G_N_ELEMENTS(buf) - n0,
                                         &state, xor, test_lowering_map_arg,
                                         NULL, NULL);

    g_assert_cmpint(n0, ==, 2);
    g_assert_cmpint(n1, ==, 1);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_32));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VADD_VV, 33, 35, 34));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VXOR_VV, 36, 38, 37));
    g_assert_cmpint((buf[1] >> 7) & 0x1f, !=, 0);
    g_assert_cmpint((buf[2] >> 7) & 0x1f, !=, 0);

    free_test_op(add);
    free_test_op(xor);
}

static void test_plugin_vector_lowering_maps_vector_positions_to_vregs(void)
{
    uint32_t buf[4];
    TracertlRvLoweringFixture fixture;
    TracertlRvVectorState state = { 0 };
    TCGOp *add;
    int n;

    init_lowering_fixture(&fixture);
    add = alloc_test_op(INDEX_op_add_vec, 3);
    TCGOP_TYPE(add) = TCG_TYPE_V256;
    TCGOP_VECE(add) = MO_32;
    add->args[0] = init_temp(&fixture, 0, TCG_TYPE_V256);
    add->args[1] = init_temp(&fixture, 1, TCG_TYPE_V256);
    add->args[2] = init_temp(&fixture, 2, TCG_TYPE_V256);

    n = tracertl_rv_lower_vector_tcg_op(buf, G_N_ELEMENTS(buf), &state, add,
                                        test_scalar_only_map_arg, NULL, NULL);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_32));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VADD_VV, 33, 35, 34));

    free_test_op(add);
}

static void test_plugin_vector_lowering_rotlv_keeps_order(void)
{
    uint32_t buf[8];
    TracertlRvLoweringFixture fixture;
    TracertlRvVectorState state = { 0 };
    TCGOp *rot;
    int n;

    init_lowering_fixture(&fixture);
    rot = alloc_test_op(INDEX_op_rotlv_vec, 3);
    TCGOP_TYPE(rot) = TCG_TYPE_V256;
    TCGOP_VECE(rot) = MO_32;
    rot->args[0] = init_temp(&fixture, 0, TCG_TYPE_V256);
    rot->args[1] = init_temp(&fixture, 1, TCG_TYPE_V256);
    rot->args[2] = init_temp(&fixture, 2, TCG_TYPE_V256);

    n = tracertl_rv_lower_vector_tcg_op(buf, G_N_ELEMENTS(buf), &state, rot,
                                        test_lowering_map_arg, NULL, NULL);

    g_assert_cmpint(n, ==, 5);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_32));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_vi(TRACERTL_RV_OPC_VRSUB_VI,
                                          TRACERTL_RV_V0_REG, 0, 35));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VSRL_VV,
                                         TRACERTL_RV_V0_REG,
                                         TRACERTL_RV_V0_REG, 34));
    g_assert_cmphex(buf[3], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VSLL_VV,
                                         33, 35, 34));
    g_assert_cmphex(buf[4], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VOR_VV,
                                         33, TRACERTL_RV_V0_REG, 33));

    free_test_op(rot);
}

static void test_plugin_vector_lowering_ld_vec_reserves_guest_mem_slot(void)
{
    uint32_t buf[4];
    TracertlRvLoweringFixture fixture;
    TracertlRvVectorState state = { 0 };
    TracertlRvVectorEmitMeta meta = { .note_mem_slot = true };
    TCGOp *ld;
    int base_reg;
    int n;

    init_lowering_fixture(&fixture);
    ld = alloc_test_op(INDEX_op_ld_vec, 2);
    TCGOP_TYPE(ld) = TCG_TYPE_V256;
    TCGOP_VECE(ld) = MO_64;
    ld->args[0] = init_temp(&fixture, 0, TCG_TYPE_V256);
    ld->args[1] = init_temp(&fixture, 1, TCG_TYPE_I64);
    base_reg = test_lowering_map_arg(ld->args[1], NULL);

    n = tracertl_rv_lower_vector_tcg_op(buf, G_N_ELEMENTS(buf), &state, ld,
                                        test_lowering_map_arg, NULL, &meta);

    g_assert_cmpint(n, ==, 2);
    g_assert_true(meta.note_mem_slot);
    g_assert_cmpint(meta.mem_slot_rel_idx, ==, 1);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_64));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_v(tracertl_rv_vector_ld_opc(MO_64),
                                         33, base_reg, 0));

    free_test_op(ld);
}

static void test_plugin_vector_lowering_shli_accepts_uimm5_31(void)
{
    uint32_t buf[4];
    TracertlRvLoweringFixture fixture;
    TracertlRvVectorState state = { 0 };
    TCGOp *shli;
    int src_reg;
    int n;

    init_lowering_fixture(&fixture);
    shli = alloc_test_op(INDEX_op_shli_vec, 3);
    TCGOP_TYPE(shli) = TCG_TYPE_V256;
    TCGOP_VECE(shli) = MO_32;
    shli->args[0] = init_temp(&fixture, 0, TCG_TYPE_V256);
    shli->args[1] = init_temp(&fixture, 1, TCG_TYPE_V256);
    shli->args[2] = 31;
    src_reg = test_lowering_map_arg(shli->args[1], NULL);

    n = tracertl_rv_lower_vector_tcg_op(buf, G_N_ELEMENTS(buf), &state, shli,
                                        test_lowering_map_arg, NULL, NULL);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_32));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_vi(TRACERTL_RV_OPC_VSLL_VI,
                                          33, 31, src_reg));

    free_test_op(shli);
}

static void test_plugin_vector_lowering_add_vec_extracts_lane_const(void)
{
    uint32_t buf[4];
    TracertlRvLoweringFixture fixture;
    TracertlRvVectorState state = { 0 };
    TCGOp *add;
    int n;

    init_lowering_fixture(&fixture);
    add = alloc_test_op(INDEX_op_add_vec, 3);
    TCGOP_TYPE(add) = TCG_TYPE_V256;
    TCGOP_VECE(add) = MO_32;
    add->args[0] = init_temp(&fixture, 0, TCG_TYPE_V256);
    add->args[1] = init_temp(&fixture, 1, TCG_TYPE_V256);
    add->args[2] = init_const_temp(&fixture, 2, TCG_TYPE_V256,
                                   INT64_C(15) << 32);

    n = tracertl_rv_lower_vector_tcg_op(buf, G_N_ELEMENTS(buf), &state, add,
                                        test_lowering_map_arg, NULL, NULL);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_32));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_vi(TRACERTL_RV_OPC_VADD_VI,
                                          33, 15, 34));

    free_test_op(add);
}

static void test_plugin_vector_lowering_andc_vec_materializes_large_const(void)
{
    uint32_t buf[16];
    uint32_t expected_imm[16];
    TracertlRvLoweringFixture fixture;
    TracertlRvVectorState state = { 0 };
    TCGOp *andc;
    int imm_n;
    int n;

    init_lowering_fixture(&fixture);
    andc = alloc_test_op(INDEX_op_andc_vec, 3);
    TCGOP_TYPE(andc) = TCG_TYPE_V256;
    TCGOP_VECE(andc) = MO_32;
    andc->args[0] = init_temp(&fixture, 0, TCG_TYPE_V256);
    andc->args[1] = init_temp(&fixture, 1, TCG_TYPE_V256);
    andc->args[2] = init_const_temp(&fixture, 2, TCG_TYPE_V256,
                                    INT64_C(0x12345678) << 32);

    n = tracertl_rv_lower_vector_tcg_op(buf, G_N_ELEMENTS(buf), &state, andc,
                                        test_lowering_map_arg, NULL, NULL);
    imm_n = tracertl_rv_emit_load_imm_sequence(expected_imm,
                                               G_N_ELEMENTS(expected_imm),
                                               TRACERTL_RV_SCRATCH_REG,
                                               UINT64_C(0xffffffffedcba987));

    g_assert_cmpint(imm_n, ==, 2);
    g_assert_cmpint(n, ==, 1 + imm_n + 2);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_32));
    g_assert_cmphex(buf[1], ==, expected_imm[0]);
    g_assert_cmphex(buf[2], ==, expected_imm[1]);
    g_assert_cmphex(buf[3], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VMV_V_X,
                                         TRACERTL_RV_V0_REG,
                                         TRACERTL_RV_SCRATCH_REG, 0));
    g_assert_cmphex(buf[4], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VAND_VV, 33,
                                         TRACERTL_RV_V0_REG, 34));

    free_test_op(andc);
}

static void test_plugin_vector_lowering_cmp_vec_const_uses_vx_path(void)
{
    uint32_t buf[16];
    uint32_t expected_imm[16];
    TracertlRvLoweringFixture fixture;
    TracertlRvVectorState state = { 0 };
    TCGOp *cmp;
    int imm_n;
    int n;

    init_lowering_fixture(&fixture);
    cmp = alloc_test_op(INDEX_op_cmp_vec, 4);
    TCGOP_TYPE(cmp) = TCG_TYPE_V256;
    TCGOP_VECE(cmp) = MO_16;
    cmp->args[0] = init_temp(&fixture, 0, TCG_TYPE_V256);
    cmp->args[1] = init_temp(&fixture, 1, TCG_TYPE_V256);
    cmp->args[2] = init_const_temp(&fixture, 2, TCG_TYPE_V256,
                                   INT64_C(0x1234) << 48);
    cmp->args[3] = TCG_COND_EQ;

    n = tracertl_rv_lower_vector_tcg_op(buf, G_N_ELEMENTS(buf), &state, cmp,
                                        test_lowering_map_arg, NULL, NULL);
    imm_n = tracertl_rv_emit_load_imm_sequence(expected_imm,
                                               G_N_ELEMENTS(expected_imm),
                                               TRACERTL_RV_SCRATCH_REG,
                                               0x1234);

    g_assert_cmpint(imm_n, ==, 2);
    g_assert_cmpint(n, ==, 1 + imm_n + 3);
    g_assert_cmphex(buf[0], ==, expect_vsetvli(TCG_TYPE_V256, MO_16));
    g_assert_cmphex(buf[1], ==, expected_imm[0]);
    g_assert_cmphex(buf[2], ==, expected_imm[1]);
    g_assert_cmphex(buf[3], ==,
                    tracertl_rv_encode_v(TRACERTL_RV_OPC_VMSEQ_VX,
                                         TRACERTL_RV_V0_REG,
                                         TRACERTL_RV_SCRATCH_REG, 34));
    g_assert_cmphex(buf[4], ==,
                    tracertl_rv_encode_vi(TRACERTL_RV_OPC_VMV_V_I,
                                          33, 0, 0));
    g_assert_cmphex(buf[5], ==,
                    expect_masked_vi(TRACERTL_RV_OPC_VMERGE_VIM,
                                     33, -1, 33, false));

    free_test_op(cmp);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/tracertl/rv-lowering/rotl-i32-preserves-count",
                    test_rotl_i32_preserves_count);
    g_test_add_func("/tracertl/rv-lowering/rotr-i64-preserves-count",
                    test_rotr_i64_preserves_count);
    g_test_add_func("/tracertl/rv-lowering/extract-i32-lane-width",
                    test_extract_i32_uses_32bit_lane);
    g_test_add_func("/tracertl/rv-lowering/sextract-i32-lane-width",
                    test_sextract_i32_uses_32bit_lane);
    g_test_add_func("/tracertl/rv-lowering/extract-i32-ignores-upper-xlen-bits",
                    test_extract_i32_ignores_upper_xlen_bits);
    g_test_add_func("/tracertl/rv-lowering/extract2-i32-preserves-high-half",
                    test_extract2_i32_preserves_high_half);
    g_test_add_func("/tracertl/rv-lowering/extract2-i32-ignores-upper-xlen-bits",
                    test_extract2_i32_ignores_upper_xlen_bits);
    g_test_add_func("/tracertl/rv-lowering/bswap16-i64-sign-extends",
                    test_bswap16_i64_sign_extends);
    g_test_add_func("/tracertl/rv-lowering/bswap32-i64-sign-extends",
                    test_bswap32_i64_sign_extends);
    g_test_add_func("/tracertl/rv-lowering/move-const-uses-addi",
                    test_move_const_uses_addi_from_x0);
    g_test_add_func("/tracertl/rv-lowering/add-rhs-const-uses-addi",
                    test_add_rhs_const_uses_addi);
    g_test_add_func("/tracertl/rv-lowering/add-lhs-const-uses-addi",
                    test_add_lhs_const_uses_addi);
    g_test_add_func("/tracertl/rv-lowering/add-i32-const-fold-wraps-to-zero",
                    test_add_i32_const_fold_wraps_to_zero);
    g_test_add_func("/tracertl/rv-lowering/add-i32-const-fold-sign-extends-result",
                    test_add_i32_const_fold_sign_extends_result);
    g_test_add_func("/tracertl/rv-lowering/deposit-masks-and-inserts-bits",
                    test_deposit_sequence_masks_and_inserts_bits);
    g_test_add_func("/tracertl/rv-lowering/zero-compare-uses-x0",
                    test_zero_compare_uses_x0);
    g_test_add_func("/tracertl/rv-lowering/nonzero-compare-needs-fallback",
                    test_nonzero_compare_const_requires_fallback);
    g_test_add_func("/tracertl/rv-lowering/load-large-const-materializes-bytes",
                    test_load_large_const_materializes_bytes);
    g_test_add_func("/tracertl/rv-lowering/load-uint32-mask-keeps-zero-extension",
                    test_load_uint32_mask_keeps_zero_extension);
    g_test_add_func("/tracertl/rv-lowering/nonzero-compare-materializes-scratch",
                    test_nonzero_compare_const_materializes_scratch);
    g_test_add_func("/tracertl/rv-lowering/guest-plan-syscall-ecall",
                    test_guest_semantic_plan_syscall_is_ecall);
    g_test_add_func("/tracertl/rv-lowering/guest-plan-cpuid-fence",
                    test_guest_semantic_plan_cpuid_is_fence);
    g_test_add_func("/tracertl/rv-lowering/guest-plan-mfence-fence",
                    test_guest_semantic_plan_mfence_is_fence);
    g_test_add_func("/tracertl/rv-lowering/guest-plan-div-mem-slot",
                    test_guest_semantic_plan_div_mem_adds_mem_slot);
    g_test_add_func("/tracertl/rv-lowering/guest-plan-compare-mem-slot",
                    test_guest_semantic_plan_compare_mem_adds_mem_slot);
    g_test_add_func("/tracertl/rv-lowering/guest-plan-vector-mem-family",
                    test_guest_semantic_plan_vector_mem_splits_anon_family);
    g_test_add_func("/tracertl/rv-lowering/guest-plan-fnstcw-store",
                    test_guest_semantic_plan_fnstcw_is_store);
    g_test_add_func("/tracertl/rv-lowering/core-helper/lookup-tb-ptr-filter",
                    test_lookup_tb_ptr_emit_and_filter);
    for (size_t i = 0; i < G_N_ELEMENTS(translated_x86_decode_cases); i++) {
        g_test_add_data_func(translated_x86_decode_cases[i].path,
                             &translated_x86_decode_cases[i],
                             test_translated_x86_decode_case);
    }
    g_test_add_func("/tracertl/rv-lowering/temp-to-reg-keeps-first-pool-unique",
                    test_temp_to_reg_keeps_first_pool_unique);
    g_test_add_func("/tracertl/rv-lowering/alt-scratch-and-carry-regs-are-distinct",
                    test_alt_scratch_and_carry_regs_are_distinct);
    g_test_add_func("/tracertl/rv-lowering/temp-to-reg-spreads-overflow-slots",
                    test_temp_to_reg_spreads_overflow_slots);
    g_test_add_func("/tracertl/rv-lowering/encode-vv-sets-field-positions",
                    test_encode_vv_sets_field_positions);
    g_test_add_func("/tracertl/rv-lowering/encode-vi-sets-field-positions",
                    test_encode_vi_sets_field_positions);
    g_test_add_func("/tracertl/rv-lowering/vsetvli-v64-e32-uses-m1",
                    test_vsetvli_v64_e32_uses_m1);
    g_test_add_func("/tracertl/rv-lowering/vsetvli-v256-e64-uses-wider-lmul",
                    test_vsetvli_v256_e64_uses_wider_lmul);
    g_test_add_func("/tracertl/rv-lowering/temp-to-vreg-reserves-v0-and-limits-pool",
                    test_temp_to_vreg_reserves_v0_and_limits_pool);
    g_test_add_func("/tracertl/rv-lowering/vector-sequence-reuses-vsetvli-for-same-shape",
                    test_vector_sequence_reuses_vsetvli_for_same_shape);
    g_test_add_func("/tracertl/rv-lowering/vector-sequence-rotlv-keeps-order",
                    test_vector_sequence_rotlv_keeps_order);
    g_test_add_func("/tracertl/rv-lowering/vector-sequence-ld-vec-reserves-guest-mem-slot",
                    test_vector_sequence_ld_vec_reserves_guest_mem_slot);
    g_test_add_func("/tracertl/rv-lowering/vector-sequence-shli-accepts-uimm5-31",
                    test_vector_sequence_shli_accepts_uimm5_31);
    g_test_add_func("/tracertl/rv-lowering/vector-sequence-rotli-accepts-uimm5-31",
                    test_vector_sequence_rotli_accepts_uimm5_31);
    g_test_add_func("/tracertl/rv-lowering/plugin-vector-lowering-reuses-vsetvli-for-same-shape",
                    test_plugin_vector_lowering_reuses_vsetvli_for_same_shape);
    g_test_add_func("/tracertl/rv-lowering/plugin-vector-lowering-maps-vector-positions-to-vregs",
                    test_plugin_vector_lowering_maps_vector_positions_to_vregs);
    g_test_add_func("/tracertl/rv-lowering/plugin-vector-lowering-rotlv-keeps-order",
                    test_plugin_vector_lowering_rotlv_keeps_order);
    g_test_add_func("/tracertl/rv-lowering/plugin-vector-lowering-ld-vec-reserves-guest-mem-slot",
                    test_plugin_vector_lowering_ld_vec_reserves_guest_mem_slot);
    g_test_add_func("/tracertl/rv-lowering/plugin-vector-lowering-shli-accepts-uimm5-31",
                    test_plugin_vector_lowering_shli_accepts_uimm5_31);
    g_test_add_func("/tracertl/rv-lowering/plugin-vector-lowering-add-vec-extracts-lane-const",
                    test_plugin_vector_lowering_add_vec_extracts_lane_const);
    g_test_add_func("/tracertl/rv-lowering/plugin-vector-lowering-andc-vec-materializes-large-const",
                    test_plugin_vector_lowering_andc_vec_materializes_large_const);
    g_test_add_func("/tracertl/rv-lowering/plugin-vector-lowering-cmp-vec-const-uses-vx-path",
                    test_plugin_vector_lowering_cmp_vec_const_uses_vx_path);

    return g_test_run();
}
