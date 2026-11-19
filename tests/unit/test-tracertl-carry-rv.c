/*
 * Focused regression test for TracerTL carry/borrow RISC-V lowering.
 *
 * This test exercises the shared implementation used by plugins/api.c so
 * emitter regressions fail here immediately instead of drifting behind a
 * mirrored copy.
 */
#include "qemu/osdep.h"
#include "plugins/tracertl_rv_helpers.h"

#define MAX_EMIT 6

enum {
    TRACERTL_RV_OPC_OR   = 0x6033,
    TRACERTL_RV_OPC_XORI = 0x4013,
    TRACERTL_RV_OPC_SLTIU = 0x3013,
};

static int rd_of(uint32_t insn)
{
    return (insn >> 7) & 0x1f;
}

static int rs2_of(uint32_t insn)
{
    return (insn >> 20) & 0x1f;
}

static bool is_w_insn(uint32_t insn)
{
    return (insn & 0x7f) == 0x3b || (insn & 0x7f) == 0x1b;
}

static bool writes_carry_reg(uint32_t insn)
{
    return rd_of(insn) == TRACERTL_RV_CARRY_REG;
}

static int emit_case(uint32_t *buf, TracertlRvCarryOp op, bool is32)
{
    return tracertl_rv_emit_carry_sequence(buf, MAX_EMIT, op, is32, 10, 11, 12);
}

static uint64_t sign_extend(uint64_t value, unsigned bits)
{
    uint64_t sign = 1ULL << (bits - 1);
    uint64_t mask = (sign << 1) - 1;

    value &= mask;
    return (value ^ sign) - sign;
}

static uint64_t sext32(uint64_t value)
{
    return sign_extend(value, 32);
}

static uint64_t imm_i(uint32_t insn)
{
    return sign_extend(insn >> 20, 12);
}

static void exec_insn(uint64_t regs[32], uint32_t insn)
{
    uint32_t opc = insn & 0x7f;
    int rd = rd_of(insn);
    int rs1 = (insn >> 15) & 0x1f;
    int rs2 = rs2_of(insn);
    uint32_t funct3 = (insn >> 12) & 0x7;
    uint32_t funct7 = insn >> 25;
    uint64_t result = 0;

    switch (opc) {
    case 0x33:
    case 0x3b:
        switch (funct3) {
        case 0x0:
            if (funct7 == 0x20) {
                result = regs[rs1] - regs[rs2];
            } else {
                result = regs[rs1] + regs[rs2];
            }
            if (opc == 0x3b) {
                result = sext32(result);
            }
            break;
        case 0x3:
            result = regs[rs1] < regs[rs2];
            break;
        case 0x6:
            result = regs[rs1] | regs[rs2];
            break;
        default:
            g_assert_not_reached();
        }
        break;
    case 0x13:
    case 0x1b:
        switch (funct3) {
        case 0x0:
            result = regs[rs1] + imm_i(insn);
            if (opc == 0x1b) {
                result = sext32(result);
            }
            break;
        case 0x3:
            result = regs[rs1] < (uint64_t)imm_i(insn);
            break;
        case 0x4:
            result = regs[rs1] ^ imm_i(insn);
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

static void assert_carry_case(TracertlRvCarryOp op, uint64_t rs1,
                              uint64_t rs2, uint64_t carry_in,
                              uint64_t expected_rd,
                              uint64_t expected_carry)
{
    uint32_t buf[MAX_EMIT];
    uint64_t regs[32] = { 0 };
    int n = emit_case(buf, op, false);
    int i;

    regs[11] = rs1;
    regs[12] = rs2;
    regs[TRACERTL_RV_CARRY_REG] = carry_in;

    for (i = 0; i < n; i++) {
        exec_insn(regs, buf[i]);
    }

    g_assert_cmphex(regs[10], ==, expected_rd);
    g_assert_cmpuint(regs[TRACERTL_RV_CARRY_REG], ==, expected_carry);
}

typedef struct CarryTest {
    const char *name;
    TracertlRvCarryOp op;
    bool has_carry_in;
    bool has_carry_out;
} CarryTest;

static void test_temp_to_reg_excludes_x31(void)
{
    unsigned int i;

    for (i = 0; i < 512; i++) {
        g_assert_cmpint(tracertl_rv_temp_to_reg(i), !=, TRACERTL_RV_CARRY_REG);
    }
}

static void test_carry_width(void)
{
    uint32_t buf[MAX_EMIT];
    int n;
    size_t c;
    int i;
    CarryTest cases[] = {
        { "addco",  TRACERTL_RV_CARRY_ADDCO,  false, true  },
        { "addc1o", TRACERTL_RV_CARRY_ADDC1O, false, true  },
        { "addci",  TRACERTL_RV_CARRY_ADDCI,  true,  false },
        { "addcio", TRACERTL_RV_CARRY_ADDCIO, true,  true  },
        { "subbo",  TRACERTL_RV_CARRY_SUBBO,  false, true  },
        { "subb1o", TRACERTL_RV_CARRY_SUBB1O, false, true  },
        { "subbi",  TRACERTL_RV_CARRY_SUBBI,  true,  false },
        { "subbio", TRACERTL_RV_CARRY_SUBBIO, true,  true  },
    };

    for (c = 0; c < G_N_ELEMENTS(cases); c++) {
        n = emit_case(buf, cases[c].op, true);
        g_assert_cmpint(n, >=, 2);
        g_assert_cmpint(n, <=, MAX_EMIT);
        g_assert_true(is_w_insn(buf[0]));

        if (cases[c].has_carry_in) {
            bool found_carry_input = false;

            for (i = 1; i < n; i++) {
                found_carry_input |= rs2_of(buf[i]) == TRACERTL_RV_CARRY_REG;
            }
            g_assert_true(found_carry_input);
        }
        if (cases[c].has_carry_out) {
            bool found_carry_write = false;

            for (i = 1; i < n; i++) {
                found_carry_write |= writes_carry_reg(buf[i]);
            }
            g_assert_true(found_carry_write);
        }

        n = emit_case(buf, cases[c].op, false);
        g_assert_cmpint(n, >=, 2);
        g_assert_cmpint(n, <=, MAX_EMIT);
        g_assert_false(is_w_insn(buf[0]));

        if (cases[c].has_carry_in) {
            bool found_carry_input = false;

            for (i = 1; i < n; i++) {
                found_carry_input |= rs2_of(buf[i]) == TRACERTL_RV_CARRY_REG;
            }
            g_assert_true(found_carry_input);
        }
        if (cases[c].has_carry_out) {
            bool found_carry_write = false;

            for (i = 1; i < n; i++) {
                found_carry_write |= writes_carry_reg(buf[i]);
            }
            g_assert_true(found_carry_write);
        }
    }
}

static void test_addco_i32_exact(void)
{
    uint32_t buf[MAX_EMIT];
    int n = emit_case(buf, TRACERTL_RV_CARRY_ADDCO, true);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_ADDW, 10, 11, 12));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU, 31, 10, 11));
}

static void test_addco_i64_exact(void)
{
    uint32_t buf[MAX_EMIT];
    int n = emit_case(buf, TRACERTL_RV_CARRY_ADDCO, false);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_ADD, 10, 11, 12));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU, 31, 10, 11));
}

static void test_addc1o_i32_exact(void)
{
    uint32_t buf[MAX_EMIT];
    int n = emit_case(buf, TRACERTL_RV_CARRY_ADDC1O, true);

    g_assert_cmpint(n, ==, 4);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_ADDW, 10, 11, 12));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDIW, 10, 10, 1));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU, 31, 11, 10));
    g_assert_cmphex(buf[3], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_XORI, 31, 31, 1));
}

static void test_addc1o_i64_exact(void)
{
    uint32_t buf[MAX_EMIT];
    int n = emit_case(buf, TRACERTL_RV_CARRY_ADDC1O, false);

    g_assert_cmpint(n, ==, 4);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_ADD, 10, 11, 12));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI, 10, 10, 1));
    g_assert_cmphex(buf[2], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU, 31, 11, 10));
    g_assert_cmphex(buf[3], ==,
                    tracertl_rv_encode_i(TRACERTL_RV_OPC_XORI, 31, 31, 1));
}

static void test_addcio_preserves_first_step_carry(void)
{
    assert_carry_case(TRACERTL_RV_CARRY_ADDCIO,
                      1, UINT64_MAX, 1, 1, 1);
}

static void test_subb1o_preserves_second_step_borrow(void)
{
    assert_carry_case(TRACERTL_RV_CARRY_SUBB1O,
                      0, UINT64_MAX, 0, 0, 1);
}

static void test_subbio_preserves_first_and_second_step_borrow(void)
{
    assert_carry_case(TRACERTL_RV_CARRY_SUBBIO,
                      0, UINT64_MAX, 1, 0, 1);
}

static void test_subbi_i32_exact(void)
{
    uint32_t buf[MAX_EMIT];
    int n = emit_case(buf, TRACERTL_RV_CARRY_SUBBI, true);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_SUBW, 10, 11, 12));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_SUBW, 10, 10, 31));
}

static void test_subbi_i64_exact(void)
{
    uint32_t buf[MAX_EMIT];
    int n = emit_case(buf, TRACERTL_RV_CARRY_SUBBI, false);

    g_assert_cmpint(n, ==, 2);
    g_assert_cmphex(buf[0], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_SUB, 10, 11, 12));
    g_assert_cmphex(buf[1], ==,
                    tracertl_rv_encode_r(TRACERTL_RV_OPC_SUB, 10, 10, 31));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/tracertl/carry-rv/temp-to-reg-no-x31",
                    test_temp_to_reg_excludes_x31);
    g_test_add_func("/tracertl/carry-rv/width-correctness",
                    test_carry_width);
    g_test_add_func("/tracertl/carry-rv/addco-i32-exact",
                    test_addco_i32_exact);
    g_test_add_func("/tracertl/carry-rv/addco-i64-exact",
                    test_addco_i64_exact);
    g_test_add_func("/tracertl/carry-rv/addc1o-i32-exact",
                    test_addc1o_i32_exact);
    g_test_add_func("/tracertl/carry-rv/addc1o-i64-exact",
                    test_addc1o_i64_exact);
    g_test_add_func("/tracertl/carry-rv/addcio-preserves-first-step-carry",
                    test_addcio_preserves_first_step_carry);
    g_test_add_func("/tracertl/carry-rv/subb1o-preserves-second-step-borrow",
                    test_subb1o_preserves_second_step_borrow);
    g_test_add_func("/tracertl/carry-rv/subbi-i32-exact",
                    test_subbi_i32_exact);
    g_test_add_func("/tracertl/carry-rv/subbi-i64-exact",
                    test_subbi_i64_exact);
    g_test_add_func("/tracertl/carry-rv/subbio-preserves-first-and-second-step-borrow",
                    test_subbio_preserves_first_and_second_step_borrow);

    return g_test_run();
}
