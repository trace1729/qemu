/*
 * Focused regression tests for TracerTL runtime helpers.
 */
#include "qemu/osdep.h"
#include "contrib/plugins/trace_format_c.h"
#include "contrib/plugins/tracertl_runtime_helpers.h"

enum {
    RV_OPC_DIV = 0x02004033U,
    RV_OPC_DIVU = 0x02005033U,
    RV_OPC_SUB = 0x40000033U,
    RV_SCRATCH_REG = 1,
    RV_ALT_SCRATCH_REG = 30,
};

static uint32_t encode_r(uint32_t opc, int rd, int rs1, int rs2)
{
    return opc | (uint32_t)(rd << 7)
               | (uint32_t)(rs1 << 15)
               | (uint32_t)(rs2 << 20);
}

static void test_riscv_mem_type_preserves_atomic_kinds(void)
{
    const uint32_t lr_w = 0x1000202f;
    const uint32_t sc_w = 0x1800202f;
    const uint32_t amoswap_w = 0x0800202f;

    g_assert_cmpuint(tracertl_riscv_mem_type(lr_w, TRACE_MEM_TYPE_LOAD),
                     ==, TRACE_MEM_TYPE_LR);
    g_assert_cmpuint(tracertl_riscv_mem_type(sc_w, TRACE_MEM_TYPE_STORE),
                     ==, TRACE_MEM_TYPE_SC);
    g_assert_cmpuint(tracertl_riscv_mem_type(amoswap_w, TRACE_MEM_TYPE_STORE),
                     ==, TRACE_MEM_TYPE_AMO);
}

static void test_riscv_mem_type_keeps_regular_load_store(void)
{
    const uint32_t lw = 0x00002003;
    const uint32_t sw = 0x00002023;

    g_assert_cmpuint(tracertl_riscv_mem_type(lw, TRACE_MEM_TYPE_LOAD),
                     ==, TRACE_MEM_TYPE_LOAD);
    g_assert_cmpuint(tracertl_riscv_mem_type(sw, TRACE_MEM_TYPE_STORE),
                     ==, TRACE_MEM_TYPE_STORE);
}

static void test_finalize_branch_marks_taken_target(void)
{
    struct TraceInstructionC recs[2];

    memset(recs, 0, sizeof(recs));
    tracertl_finalize_branch(recs, G_N_ELEMENTS(recs), 1,
                             0x1004, 0x2000, 0x3000, 0);

    g_assert_cmpuint(recs[1].branch_taken, ==, 1);
    g_assert_cmphex(recs[1].target, ==, 0x3000);
}

static void test_finalize_branch_marks_direct_next_pc_taken(void)
{
    struct TraceInstructionC recs[1];

    memset(recs, 0, sizeof(recs));
    recs[0].branch_type = 2;
    tracertl_finalize_branch(recs, G_N_ELEMENTS(recs), 0,
                             0x1005, 0x1005, 0x3000, 0);

    g_assert_cmpuint(recs[0].branch_taken, ==, 1);
    g_assert_cmphex(recs[0].target, ==, 0x3000);
}

static void test_finalize_branch_without_successor_uses_terminal_target(void)
{
    struct TraceInstructionC recs[1];

    memset(recs, 0, sizeof(recs));
    recs[0].branch_type = 2;
    tracertl_finalize_branch_without_successor(recs, G_N_ELEMENTS(recs), 0,
                                               0x1005, 0x3000);

    g_assert_cmpuint(recs[0].branch_taken, ==, 1);
    g_assert_cmphex(recs[0].target, ==, 0x3000);
}

static void test_finalize_branch_keeps_fallthrough_clear(void)
{
    struct TraceInstructionC recs[1];

    memset(recs, 0, sizeof(recs));
    recs[0].branch_type = 1;
    tracertl_finalize_branch(recs, G_N_ELEMENTS(recs), 0,
                             0x1004, 0x1004, 0x1004, 0);

    g_assert_cmpuint(recs[0].branch_taken, ==, 0);
    g_assert_cmphex(recs[0].target, ==, 0);
}

static void test_finalize_branch_sets_resolved_not_taken_target(void)
{
    struct TraceInstructionC recs[1];

    memset(recs, 0, sizeof(recs));
    recs[0].branch_type = 1;
    tracertl_finalize_branch(recs, G_N_ELEMENTS(recs), 0,
                             0x1004, 0x1004, 0x1004, 0x1010);

    g_assert_cmpuint(recs[0].branch_taken, ==, 0);
    g_assert_cmphex(recs[0].target, ==, 0x1010);
}

static void test_guest_conditional_branch_placeholder_matches_direction(void)
{
    g_assert_cmphex(tracertl_guest_conditional_branch_placeholder(true),
                    ==, 0x00000063U);
    g_assert_cmphex(tracertl_guest_conditional_branch_placeholder(false),
                    ==, 0x00001063U);
}

static void test_demote_sequential_branch_clears_metadata(void)
{
    struct TraceInstructionC rec;

    trace_instruction_init(&rec);
    rec.instr_pc_va = 0x1000;
    rec.instr = 0x0040006fU;
    rec.target = 0x1004;
    rec.branch_type = 2;
    rec.branch_taken = 1;

    g_assert_true(tracertl_demote_branch_if_sequential(&rec, 0x1004));
    g_assert_cmphex(rec.instr, ==, tracertl_guest_non_branch_placeholder());
    g_assert_cmpuint(rec.branch_type, ==, 0);
    g_assert_cmpuint(rec.branch_taken, ==, 0);
    g_assert_cmphex(rec.target, ==, 0);
}

static void test_demote_sequential_branch_preserves_nonseq(void)
{
    struct TraceInstructionC rec;

    trace_instruction_init(&rec);
    rec.instr = 0x0080006fU;
    rec.target = 0x1008;
    rec.branch_type = 2;
    rec.branch_taken = 1;

    g_assert_false(tracertl_demote_branch_if_sequential(&rec, 0x1004));
    g_assert_cmphex(rec.instr, ==, 0x0080006fU);
    g_assert_cmpuint(rec.branch_type, ==, 2);
    g_assert_cmpuint(rec.branch_taken, ==, 1);
    g_assert_cmphex(rec.target, ==, 0x1008);
}

static void test_encode_branch_placeholder_targets_forward_and_backward(void)
{
    uint32_t insn = 0;
    uint64_t target = 0;

    g_assert_true(tracertl_rv_encode_branch_to_target(0x1000, 0x1010,
                                                      true, &insn));
    g_assert_cmphex(insn, ==, 0x00000863U);
    g_assert_true(tracertl_resolve_riscv_conditional_branch_target(
        0x1000, insn, &target));
    g_assert_cmphex(target, ==, 0x1010);

    g_assert_true(tracertl_rv_encode_branch_to_target(0x1010, 0x1000,
                                                      false, &insn));
    g_assert_cmphex(insn, ==, 0xfe0018e3U);
    g_assert_true(tracertl_resolve_riscv_conditional_branch_target(
        0x1010, insn, &target));
    g_assert_cmphex(target, ==, 0x1000);
}

static void test_encode_branch_placeholder_rejects_out_of_range(void)
{
    uint32_t insn = 0xdeadbeefU;

    g_assert_false(tracertl_rv_encode_branch_to_target(0x1000, 0x3000,
                                                       true, &insn));
    g_assert_cmphex(insn, ==, 0xdeadbeefU);
}

static void test_encode_jal_placeholder_target(void)
{
    uint32_t insn = 0;

    g_assert_true(tracertl_rv_encode_jal_to_target(0x1000, 0x3000, &insn));
    g_assert_cmphex(insn, ==, 0x0000206fU);
}

static void test_finalize_branch_ignores_missing_record(void)
{
    struct TraceInstructionC recs[1];

    memset(recs, 0, sizeof(recs));
    tracertl_finalize_branch(recs, G_N_ELEMENTS(recs), -1,
                             0x1004, 0x2000, 0x3000, 0);

    g_assert_cmpuint(recs[0].branch_taken, ==, 0);
    g_assert_cmphex(recs[0].target, ==, 0);
}

static void test_resolve_riscv_conditional_branch_target_branch(void)
{
    uint64_t target = 0;

    g_assert_true(tracertl_resolve_riscv_conditional_branch_target(
        0x80002178, 0x02a7ec63, &target));
    g_assert_cmphex(target, ==, 0x800021b0);
}

static void test_rv_buf_grow_doubles_capacity(void)
{
    size_t buf_size = 64;

    g_assert_true(tracertl_rv_buf_grow(&buf_size));
    g_assert_cmpuint(buf_size, ==, 128);
}

static void test_rv_buf_grow_rejects_int_overflow(void)
{
    size_t buf_size = INT_MAX;

    g_assert_false(tracertl_rv_buf_grow(&buf_size));
    g_assert_cmpuint(buf_size, ==, INT_MAX);
}

static void test_guest_stub_syscall_is_ecall(void)
{
    static const uint8_t bytes[] = { 0x0f, 0x05 };
    bool mem_slot = true;
    uint32_t insn =
        tracertl_guest_semantic_stub_insn(bytes, sizeof(bytes), true, false,
                                          0, 0, &mem_slot);

    g_assert_cmphex(insn, ==, 0x00000073U);
    g_assert_false(mem_slot);
}

static void test_guest_stub_cpuid_is_fence(void)
{
    static const uint8_t bytes[] = { 0x0f, 0xa2 };
    bool mem_slot = true;
    uint32_t insn =
        tracertl_guest_semantic_stub_insn(bytes, sizeof(bytes), true, false,
                                          0, 0, &mem_slot);

    g_assert_cmphex(insn, ==, 0x0000000fU);
    g_assert_false(mem_slot);
}

static void test_guest_stub_div_mem_sets_mem_slot(void)
{
    static const uint8_t bytes[] = { 0xf7, 0x30 };
    bool mem_slot = false;
    uint32_t insn =
        tracertl_guest_semantic_stub_insn(bytes, sizeof(bytes), true, false,
                                          0, 0, &mem_slot);

    g_assert_cmphex(insn, ==,
                    encode_r(RV_OPC_DIVU, RV_SCRATCH_REG,
                             RV_SCRATCH_REG, RV_ALT_SCRATCH_REG));
    g_assert_true(mem_slot);
}

static void test_guest_stub_compare_mem_sets_mem_slot(void)
{
    static const uint8_t bytes[] = { 0x66, 0x0f, 0x2e, 0x08 };
    bool mem_slot = false;
    uint32_t insn =
        tracertl_guest_semantic_stub_insn(bytes, sizeof(bytes), true, false,
                                          0, 0, &mem_slot);

    g_assert_cmphex(insn, ==,
                    encode_r(RV_OPC_SUB, RV_SCRATCH_REG,
                             RV_SCRATCH_REG, RV_ALT_SCRATCH_REG));
    g_assert_true(mem_slot);
}

static void test_guest_stub_default_is_nop(void)
{
    static const uint8_t bytes[] = { 0x90 };
    bool mem_slot = true;
    uint32_t insn =
        tracertl_guest_semantic_stub_insn(bytes, sizeof(bytes), true, false,
                                          0, 0, &mem_slot);

    g_assert_cmphex(insn, ==, 0x00000013U);
    g_assert_false(mem_slot);
}

static void test_overflow_memory_record_clones_visible_pc(void)
{
    struct TraceInstructionC template_rec;
    struct TraceInstructionC overflow_rec;

    trace_instruction_init(&template_rec);
    template_rec.instr_pc_va = 0x1234;
    template_rec.instr_pc_pa = 0x5678;

    tracertl_init_overflow_memory_record(&overflow_rec, &template_rec,
                                         TRACE_MEM_TYPE_STORE, 2,
                                         0xaaa0, 0xbbb0);

    g_assert_cmphex(overflow_rec.instr_pc_va, ==, 0x1234);
    g_assert_cmphex(overflow_rec.instr_pc_pa, ==, 0x5678);
    g_assert_cmpuint(trace_get_memory_type(&overflow_rec), ==,
                     TRACE_MEM_TYPE_STORE);
    g_assert_cmpuint(trace_get_memory_size(&overflow_rec), ==, 2);
    g_assert_cmphex(overflow_rec.exu_data.memory_address.va, ==, 0xaaa0);
    g_assert_cmphex(overflow_rec.exu_data.memory_address.pa, ==, 0xbbb0);
    g_assert_cmphex(overflow_rec.instr, ==, 0x00002023U);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/tracertl/runtime/riscv-mem-type-atomic",
                    test_riscv_mem_type_preserves_atomic_kinds);
    g_test_add_func("/tracertl/runtime/riscv-mem-type-regular",
                    test_riscv_mem_type_keeps_regular_load_store);
    g_test_add_func("/tracertl/runtime/finalize-branch-taken",
                    test_finalize_branch_marks_taken_target);
    g_test_add_func("/tracertl/runtime/finalize-branch-direct-next-pc-taken",
                    test_finalize_branch_marks_direct_next_pc_taken);
    g_test_add_func("/tracertl/runtime/finalize-branch-without-successor-uses-terminal-target",
                    test_finalize_branch_without_successor_uses_terminal_target);
    g_test_add_func("/tracertl/runtime/finalize-branch-fallthrough",
                    test_finalize_branch_keeps_fallthrough_clear);
    g_test_add_func("/tracertl/runtime/finalize-branch-not-taken-target",
                    test_finalize_branch_sets_resolved_not_taken_target);
    g_test_add_func("/tracertl/runtime/guest-conditional-branch-placeholder",
                    test_guest_conditional_branch_placeholder_matches_direction);
    g_test_add_func("/tracertl/runtime/demote-sequential-branch",
                    test_demote_sequential_branch_clears_metadata);
    g_test_add_func("/tracertl/runtime/demote-sequential-branch-preserves-nonseq",
                    test_demote_sequential_branch_preserves_nonseq);
    g_test_add_func("/tracertl/runtime/encode-branch-placeholder-targets",
                    test_encode_branch_placeholder_targets_forward_and_backward);
    g_test_add_func("/tracertl/runtime/encode-branch-placeholder-rejects-out-of-range",
                    test_encode_branch_placeholder_rejects_out_of_range);
    g_test_add_func("/tracertl/runtime/encode-jal-placeholder-target",
                    test_encode_jal_placeholder_target);
    g_test_add_func("/tracertl/runtime/finalize-branch-missing-record",
                    test_finalize_branch_ignores_missing_record);
    g_test_add_func("/tracertl/runtime/resolve-riscv-conditional-branch-target",
                    test_resolve_riscv_conditional_branch_target_branch);
    g_test_add_func("/tracertl/runtime/rv-buf-grow-doubles-capacity",
                    test_rv_buf_grow_doubles_capacity);
    g_test_add_func("/tracertl/runtime/rv-buf-grow-rejects-int-overflow",
                    test_rv_buf_grow_rejects_int_overflow);
    g_test_add_func("/tracertl/runtime/guest-stub-syscall-ecall",
                    test_guest_stub_syscall_is_ecall);
    g_test_add_func("/tracertl/runtime/guest-stub-cpuid-fence",
                    test_guest_stub_cpuid_is_fence);
    g_test_add_func("/tracertl/runtime/guest-stub-div-mem-slot",
                    test_guest_stub_div_mem_sets_mem_slot);
    g_test_add_func("/tracertl/runtime/guest-stub-compare-mem-slot",
                    test_guest_stub_compare_mem_sets_mem_slot);
    g_test_add_func("/tracertl/runtime/guest-stub-default-nop",
                    test_guest_stub_default_is_nop);
    g_test_add_func("/tracertl/runtime/overflow-memory-record-clones-visible-pc",
                    test_overflow_memory_record_clones_visible_pc);

    return g_test_run();
}
