#include "qemu/osdep.h"
#include "exec/memop.h"
#include "contrib/plugins/trace_format_c.h"
#include "plugins/tracertl_rv_helpers.h"

enum {
    TRACERTL_RV_OPC_LUI  = 0x37,
    TRACERTL_RV_OPC_AND  = 0x7033,
    TRACERTL_RV_OPC_OR   = 0x6033,
    TRACERTL_RV_OPC_ORI  = 0x6013,
    TRACERTL_RV_OPC_DIV  = 0x02004033U,
    TRACERTL_RV_OPC_DIVU = 0x02005033U,
    TRACERTL_RV_OPC_SLTIU = 0x3013,
    TRACERTL_RV_OPC_SLL  = 0x1033,
    TRACERTL_RV_OPC_SRL  = 0x5033,
    TRACERTL_RV_OPC_SLLI = 0x1013,
    TRACERTL_RV_OPC_SRLI = 0x5013,
    TRACERTL_RV_OPC_XORI = 0x4013,
    TRACERTL_RV_OPC_SLLW = 0x103b,
    TRACERTL_RV_OPC_SRLW = 0x503b,
    TRACERTL_RV_OPC_ECALL = 0x00000073U,
    TRACERTL_RV_OPC_FENCE = 0x0000000fU,
    TRACERTL_RV_OPC_LB   = 0x3,
    TRACERTL_RV_OPC_LBU  = 0x4003,
    TRACERTL_RV_OPC_LH   = 0x1003,
    TRACERTL_RV_OPC_LHU  = 0x5003,
    TRACERTL_RV_OPC_LW   = 0x2003,
    TRACERTL_RV_OPC_LWU  = 0x6003,
    TRACERTL_RV_OPC_LD   = 0x3003,
    TRACERTL_RV_OPC_SB   = 0x23,
    TRACERTL_RV_OPC_SH   = 0x1023,
    TRACERTL_RV_OPC_SW   = 0x2023,
    TRACERTL_RV_OPC_SD   = 0x3023,
    TRACERTL_RV_OPC_JALR = 0x67,
};

#define TRACERTL_RV_BSWAP_OS    4

uint32_t tracertl_rv_encode_r(uint32_t opc, int rd, int rs1, int rs2)
{
    return opc | (uint32_t)((rd & 0x1f) << 7)
               | (uint32_t)((rs1 & 0x1f) << 15)
               | (uint32_t)((rs2 & 0x1f) << 20);
}

uint32_t tracertl_rv_encode_i(uint32_t opc, int rd, int rs1, uint32_t imm)
{
    return opc | (uint32_t)((rd & 0x1f) << 7)
               | (uint32_t)((rs1 & 0x1f) << 15)
               | ((imm & 0xfffU) << 20);
}

static inline uint32_t tracertl_rv_encode_v_masked(uint32_t opc, int vd,
                                                   int vs1, int vs2, bool vm)
{
    return opc | (uint32_t)((vd & 0x1f) << 7)
               | (uint32_t)((vs1 & 0x1f) << 15)
               | (uint32_t)((vs2 & 0x1f) << 20)
               | (uint32_t)(vm ? 1U : 0U) << 25;
}

static inline uint32_t tracertl_rv_encode_vi_masked(uint32_t opc, int vd,
                                                    int32_t imm, int vs2,
                                                    bool vm)
{
    return opc | (uint32_t)((vd & 0x1f) << 7)
               | (uint32_t)((imm & 0x1f) << 15)
               | (uint32_t)((vs2 & 0x1f) << 20)
               | (uint32_t)(vm ? 1U : 0U) << 25;
}

uint32_t tracertl_rv_encode_v(uint32_t opc, int vd, int vs1, int vs2)
{
    return tracertl_rv_encode_v_masked(opc, vd, vs1, vs2, true);
}

uint32_t tracertl_rv_encode_vi(uint32_t opc, int vd, int32_t imm, int vs2)
{
    return tracertl_rv_encode_vi_masked(opc, vd, imm, vs2, true);
}

int tracertl_rv_temp_to_reg(unsigned int a)
{
    /*
     * Map TCG temporaries to RISC-V architectural registers.
     *
     * x0 is the zero register, x1 is TRACERTL_RV_SCRATCH_REG, x30 is
     * TRACERTL_RV_ALT_SCRATCH_REG, and x31 is TRACERTL_RV_CARRY_REG —
     * those four are excluded. The remaining 28 registers are available
     * for temp mapping.
     *
     * When a temp index exceeds the architectural pool, report that
     * explicitly instead of silently aliasing it onto another live temp.
     * The TB emitter decides how to reuse or synthesize overflow temps.
     */
    static const int regs[] = {
        10, 11, 12, 13, 14, 15, 16, 17,
         5,  6,  7, 28, 29,
         9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
         2,  3,  4,  8,
    };
    if (a >= ARRAY_SIZE(regs)) {
        return -1;
    }
    return regs[a];
}

int tracertl_rv_temp_to_vreg(unsigned int a)
{
    return a < 31 ? TRACERTL_RV_V1_REG + (int)a : -1;
}

bool tracertl_rv_imm12_p(int64_t imm)
{
    return imm >= -2048 && imm <= 2047;
}

static inline uint32_t tracertl_rv_encode_u(uint32_t opc, int rd, uint32_t imm)
{
    return opc | (uint32_t)((rd & 0x1f) << 7) | (imm & 0xfffff000U);
}

static inline uint32_t tracertl_rv_encode_vset(uint32_t opc, int rd,
                                               int rs1, uint32_t vtype)
{
    return opc | (uint32_t)((rd & 0x1f) << 7)
               | (uint32_t)((rs1 & 0x1f) << 15)
               | ((vtype & 0x7ffU) << 20);
}

static inline uint32_t tracertl_rv_encode_vtype(unsigned int vece,
                                                unsigned int vlmul)
{
    return (1u << 7) | (1u << 6) | ((vece & 0x7u) << 3) | (vlmul & 0x7u);
}

uint32_t tracertl_rv_vector_ld_opc(unsigned int vece)
{
    static const uint32_t load_opcs[] = {
        TRACERTL_RV_OPC_VLE8_V,
        TRACERTL_RV_OPC_VLE16_V,
        TRACERTL_RV_OPC_VLE32_V,
        TRACERTL_RV_OPC_VLE64_V,
    };

    return vece < ARRAY_SIZE(load_opcs) ? load_opcs[vece] : 0;
}

uint32_t tracertl_rv_vector_st_opc(unsigned int vece)
{
    static const uint32_t store_opcs[] = {
        TRACERTL_RV_OPC_VSE8_V,
        TRACERTL_RV_OPC_VSE16_V,
        TRACERTL_RV_OPC_VSE32_V,
        TRACERTL_RV_OPC_VSE64_V,
    };

    return vece < ARRAY_SIZE(store_opcs) ? store_opcs[vece] : 0;
}

int tracertl_rv_cmp_operand_reg(TracertlRvOperand op)
{
    if (!op.is_const) {
        return op.reg;
    }

    return op.imm == 0 ? 0 : -1;
}

static inline int tracertl_rv_emit_one(uint32_t *buf, int buf_size,
                                       int pos, uint32_t insn)
{
    if (pos >= buf_size) {
        return -1;
    }
    buf[pos] = insn;
    return pos + 1;
}

int tracertl_rv_emit_vsetvli(uint32_t *buf, int buf_size,
                             unsigned int type, unsigned int vece)
{
    unsigned int vlmul;

    if (buf_size <= 0 || type < 3 || type > 5 || vece > 3) {
        return -1;
    }

    vlmul = type - 3;
    return tracertl_rv_emit_one(buf, buf_size, 0,
                                tracertl_rv_encode_vset(TRACERTL_RV_OPC_VSETVLI,
                                                        0, 0,
                                                        tracertl_rv_encode_vtype(vece,
                                                                                 vlmul)));
}

static const struct {
    uint32_t opc;
    bool swap;
} tracertl_rv_cmpcond_to_vv[] = {
    [TCG_COND_EQ] =  { TRACERTL_RV_OPC_VMSEQ_VV,  false },
    [TCG_COND_NE] =  { TRACERTL_RV_OPC_VMSNE_VV,  false },
    [TCG_COND_LT] =  { TRACERTL_RV_OPC_VMSLT_VV,  false },
    [TCG_COND_GE] =  { TRACERTL_RV_OPC_VMSLE_VV,  true  },
    [TCG_COND_GT] =  { TRACERTL_RV_OPC_VMSLT_VV,  true  },
    [TCG_COND_LE] =  { TRACERTL_RV_OPC_VMSLE_VV,  false },
    [TCG_COND_LTU] = { TRACERTL_RV_OPC_VMSLTU_VV, false },
    [TCG_COND_GEU] = { TRACERTL_RV_OPC_VMSLEU_VV, true  },
    [TCG_COND_GTU] = { TRACERTL_RV_OPC_VMSLTU_VV, true  },
    [TCG_COND_LEU] = { TRACERTL_RV_OPC_VMSLEU_VV, false },
};

static const struct {
    uint32_t opc;
    int min;
    int max;
    bool adjust;
} tracertl_rv_cmpcond_to_vi[] = {
    [TCG_COND_EQ]  = { TRACERTL_RV_OPC_VMSEQ_VI,  -16, 15, false },
    [TCG_COND_NE]  = { TRACERTL_RV_OPC_VMSNE_VI,  -16, 15, false },
    [TCG_COND_GT]  = { TRACERTL_RV_OPC_VMSGT_VI,  -16, 15, false },
    [TCG_COND_LE]  = { TRACERTL_RV_OPC_VMSLE_VI,  -16, 15, false },
    [TCG_COND_LT]  = { TRACERTL_RV_OPC_VMSLE_VI,  -15, 16, true  },
    [TCG_COND_GE]  = { TRACERTL_RV_OPC_VMSGT_VI,  -15, 16, true  },
    [TCG_COND_LEU] = { TRACERTL_RV_OPC_VMSLEU_VI,   0, 15, false },
    [TCG_COND_GTU] = { TRACERTL_RV_OPC_VMSGTU_VI,   0, 15, false },
    [TCG_COND_LTU] = { TRACERTL_RV_OPC_VMSLEU_VI,   1, 16, true  },
    [TCG_COND_GEU] = { TRACERTL_RV_OPC_VMSGTU_VI,   1, 16, true  },
};

static const struct {
    uint32_t opc;
    bool invert;
} tracertl_rv_cmpcond_to_vx[] = {
    [TCG_COND_EQ]  = { TRACERTL_RV_OPC_VMSEQ_VX,  false },
    [TCG_COND_NE]  = { TRACERTL_RV_OPC_VMSNE_VX,  false },
    [TCG_COND_LT]  = { TRACERTL_RV_OPC_VMSLT_VX,  false },
    [TCG_COND_GE]  = { TRACERTL_RV_OPC_VMSLT_VX,  true  },
    [TCG_COND_LE]  = { TRACERTL_RV_OPC_VMSLE_VX,  false },
    [TCG_COND_GT]  = { TRACERTL_RV_OPC_VMSGT_VX,  false },
    [TCG_COND_LTU] = { TRACERTL_RV_OPC_VMSLTU_VX, false },
    [TCG_COND_GEU] = { TRACERTL_RV_OPC_VMSLTU_VX, true  },
    [TCG_COND_LEU] = { TRACERTL_RV_OPC_VMSLEU_VX, false },
    [TCG_COND_GTU] = { TRACERTL_RV_OPC_VMSGTU_VX, false },
};

static uint64_t tracertl_rv_fold_add_constants(bool is_32bit,
                                               int64_t lhs,
                                               int64_t rhs)
{
    if (!is_32bit) {
        return (uint64_t)lhs + (uint64_t)rhs;
    }

    return (uint64_t)(int64_t)(int32_t)((uint32_t)lhs + (uint32_t)rhs);
}

int tracertl_rv_emit_load_imm_sequence(uint32_t *buf, int buf_size,
                                       int rd, uint64_t imm)
{
    int first = 7;
    int pos = 0;
    int64_t simm = (int64_t)imm;

    if (imm == 0) {
        return tracertl_rv_emit_one(buf, buf_size, 0,
                                    tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI,
                                                         rd, 0, 0));
    }

    if (simm >= INT32_MIN && simm <= INT32_MAX) {
        int64_t lo = simm & 0xfff;
        int64_t hi;

        if (lo & 0x800) {
            lo -= 0x1000;
        }

        if (tracertl_rv_imm12_p(simm)) {
            return tracertl_rv_emit_one(buf, buf_size, 0,
                                        tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI,
                                                             rd, 0, simm));
        }

        hi = simm - lo;
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_u(TRACERTL_RV_OPC_LUI,
                                                        rd, hi));
        if (lo != 0) {
            pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                       tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI,
                                                            rd, rd, lo));
        }
        return pos;
    }

    while (first > 0 && ((imm >> (first * 8)) & 0xff) == 0) {
        first--;
    }

    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI, rd,
                                                    0,
                                                    (imm >> (first * 8)) & 0xff));
    for (int i = first - 1; i >= 0; i--) {
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_i(TRACERTL_RV_OPC_SLLI,
                                                        rd, rd, 8));
        if (((imm >> (i * 8)) & 0xff) != 0) {
            pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                       tracertl_rv_encode_i(TRACERTL_RV_OPC_ORI,
                                                            rd, rd,
                                                            (imm >> (i * 8)) & 0xff));
        }
    }

    return pos;
}

static int tracertl_rv_emit_load_imm_at(uint32_t *buf, int buf_size, int pos,
                                        int rd, uint64_t imm)
{
    int n = tracertl_rv_emit_load_imm_sequence(buf + pos, buf_size - pos,
                                               rd, imm);

    if (n <= 0 || n > buf_size - pos) {
        return -1;
    }
    return pos + n;
}

int tracertl_rv_emit_move_sequence(uint32_t *buf, int buf_size,
                                   int rd, TracertlRvOperand src)
{
    if (src.is_const) {
        return tracertl_rv_emit_load_imm_sequence(buf, buf_size, rd,
                                                  (uint64_t)src.imm);
    }

    return tracertl_rv_emit_one(buf, buf_size, 0,
                                tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI,
                                                     rd, src.reg, 0));
}

int tracertl_rv_emit_cmp_operand_sequence(uint32_t *buf, int buf_size,
                                          TracertlRvOperand op,
                                          int scratch_reg, int *reg_out)
{
    if (!op.is_const) {
        *reg_out = op.reg;
        return 0;
    }

    if (op.imm == 0) {
        *reg_out = 0;
        return 0;
    }

    *reg_out = scratch_reg;
    return tracertl_rv_emit_load_imm_sequence(buf, buf_size, scratch_reg,
                                              (uint64_t)op.imm);
}

int tracertl_rv_emit_add_sequence(uint32_t *buf, int buf_size,
                                  bool is_32bit, int rd,
                                  TracertlRvOperand lhs,
                                  TracertlRvOperand rhs)
{
    uint32_t add_op = is_32bit ? TRACERTL_RV_OPC_ADDW : TRACERTL_RV_OPC_ADD;
    uint32_t addi_op = is_32bit ? TRACERTL_RV_OPC_ADDIW : TRACERTL_RV_OPC_ADDI;
    int pos = 0;

    if (!lhs.is_const && !rhs.is_const) {
        return tracertl_rv_emit_one(buf, buf_size, pos,
                                    tracertl_rv_encode_r(add_op, rd,
                                                         lhs.reg, rhs.reg));
    }

    if (lhs.is_const && rhs.is_const) {
        return tracertl_rv_emit_load_imm_sequence(buf, buf_size, rd,
                                                  tracertl_rv_fold_add_constants(
                                                      is_32bit,
                                                      lhs.imm,
                                                      rhs.imm));
    }

    if (rhs.is_const && tracertl_rv_imm12_p(rhs.imm)) {
        return tracertl_rv_emit_one(buf, buf_size, pos,
                                    tracertl_rv_encode_i(addi_op, rd,
                                                         lhs.reg, rhs.imm));
    }

    if (lhs.is_const && tracertl_rv_imm12_p(lhs.imm)) {
        return tracertl_rv_emit_one(buf, buf_size, pos,
                                    tracertl_rv_encode_i(addi_op, rd,
                                                         rhs.reg, lhs.imm));
    }

    if (lhs.is_const) {
        pos = tracertl_rv_emit_load_imm_sequence(buf, buf_size,
                                                 TRACERTL_RV_SCRATCH_REG,
                                                 (uint64_t)lhs.imm);
        return tracertl_rv_emit_one(buf, buf_size, pos,
                                    tracertl_rv_encode_r(add_op, rd, rhs.reg,
                                                         TRACERTL_RV_SCRATCH_REG));
    }

    pos = tracertl_rv_emit_load_imm_sequence(buf, buf_size,
                                             TRACERTL_RV_SCRATCH_REG,
                                             (uint64_t)rhs.imm);
    return tracertl_rv_emit_one(buf, buf_size, pos,
                                tracertl_rv_encode_r(add_op, rd, lhs.reg,
                                                     TRACERTL_RV_SCRATCH_REG));
}

int tracertl_rv_emit_deposit_sequence(uint32_t *buf, int buf_size,
                                      int rd,
                                      TracertlRvOperand base,
                                      TracertlRvOperand insert,
                                      uint32_t ofs, uint32_t len,
                                      int mask_reg, int tmp_reg)
{
    int pos;

    g_assert_cmpuint(len, >, 0);
    g_assert_cmpuint(ofs + len, <=, 64);

    pos = tracertl_rv_emit_move_sequence(buf, buf_size, rd, base);
    if (pos < 0) {
        return -1;
    }

    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI,
                                                    mask_reg, 0, 1));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_SLLI,
                                                    mask_reg, mask_reg, len));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI,
                                                    mask_reg, mask_reg, -1));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_SLLI,
                                                    tmp_reg, mask_reg, ofs));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_XORI,
                                                    tmp_reg, tmp_reg, 0xfff));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_r(TRACERTL_RV_OPC_AND,
                                                    rd, rd, tmp_reg));
    if (insert.is_const) {
        pos = tracertl_rv_emit_load_imm_at(buf, buf_size, pos, tmp_reg,
                                           (uint64_t)insert.imm);
    } else if (insert.reg != tmp_reg) {
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI,
                                                        tmp_reg, insert.reg, 0));
    }
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_r(TRACERTL_RV_OPC_AND,
                                                    tmp_reg, tmp_reg,
                                                    mask_reg));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_SLLI,
                                                    tmp_reg, tmp_reg, ofs));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_r(TRACERTL_RV_OPC_OR,
                                                    rd, rd, tmp_reg));
    return pos;
}

int tracertl_rv_emit_carry_sequence(uint32_t *buf, int buf_size,
                                    TracertlRvCarryOp op, bool is_32bit,
                                    int rd, int rs1, int rs2)
{
    const uint32_t add_op = is_32bit ? TRACERTL_RV_OPC_ADDW : TRACERTL_RV_OPC_ADD;
    const uint32_t sub_op = is_32bit ? TRACERTL_RV_OPC_SUBW : TRACERTL_RV_OPC_SUB;
    const uint32_t addi_op = is_32bit ? TRACERTL_RV_OPC_ADDIW : TRACERTL_RV_OPC_ADDI;
    int pos = 0;

    switch (op) {
    case TRACERTL_RV_CARRY_ADDCO:
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(add_op, rd, rs1, rs2));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU,
                                                        TRACERTL_RV_CARRY_REG,
                                                        rd, rs1));
        break;
    case TRACERTL_RV_CARRY_ADDC1O:
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(add_op, rd, rs1, rs2));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_i(addi_op, rd, rd, 1));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU,
                                                        TRACERTL_RV_CARRY_REG,
                                                        rs1, rd));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_i(TRACERTL_RV_OPC_XORI,
                                                        TRACERTL_RV_CARRY_REG,
                                                        TRACERTL_RV_CARRY_REG,
                                                        1));
        break;
    case TRACERTL_RV_CARRY_ADDCI:
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(add_op, rd, rs1, rs2));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(add_op, rd, rd,
                                                        TRACERTL_RV_CARRY_REG));
        break;
    case TRACERTL_RV_CARRY_ADDCIO:
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(add_op, rd, rs1, rs2));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU,
                                                        TRACERTL_RV_SCRATCH_REG,
                                                        rd, rs1));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(add_op, rd, rd,
                                                        TRACERTL_RV_CARRY_REG));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU,
                                                        TRACERTL_RV_CARRY_REG,
                                                        rd,
                                                        TRACERTL_RV_CARRY_REG));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_OR,
                                                        TRACERTL_RV_CARRY_REG,
                                                        TRACERTL_RV_SCRATCH_REG,
                                                        TRACERTL_RV_CARRY_REG));
        break;
    case TRACERTL_RV_CARRY_SUBBO:
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(sub_op, rd, rs1, rs2));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU,
                                                        TRACERTL_RV_CARRY_REG,
                                                        rs1, rs2));
        break;
    case TRACERTL_RV_CARRY_SUBB1O:
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(sub_op, rd, rs1, rs2));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU,
                                                        TRACERTL_RV_SCRATCH_REG,
                                                        rs1, rs2));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_i(TRACERTL_RV_OPC_SLTIU,
                                                        TRACERTL_RV_CARRY_REG,
                                                        rd, 1));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_i(addi_op, rd, rd,
                                                        (uint32_t)-1));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_OR,
                                                        TRACERTL_RV_CARRY_REG,
                                                        TRACERTL_RV_CARRY_REG,
                                                        TRACERTL_RV_SCRATCH_REG));
        break;
    case TRACERTL_RV_CARRY_SUBBI:
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(sub_op, rd, rs1, rs2));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(sub_op, rd, rd,
                                                        TRACERTL_RV_CARRY_REG));
        break;
    case TRACERTL_RV_CARRY_SUBBIO:
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(sub_op, rd, rs1, rs2));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU,
                                                        TRACERTL_RV_SCRATCH_REG,
                                                        rd,
                                                        TRACERTL_RV_CARRY_REG));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(sub_op, rd, rd,
                                                        TRACERTL_RV_CARRY_REG));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_SLTU,
                                                        TRACERTL_RV_CARRY_REG,
                                                        rs1, rs2));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_OR,
                                                        TRACERTL_RV_CARRY_REG,
                                                        TRACERTL_RV_CARRY_REG,
                                                        TRACERTL_RV_SCRATCH_REG));
        break;
    default:
        return -1;
    }

    return pos;
}

int tracertl_rv_emit_rotate_sequence(uint32_t *buf, int buf_size,
                                     bool is_32bit, bool is_left,
                                     int rd, int rs, int sh)
{
    const uint32_t left_op = is_32bit ? TRACERTL_RV_OPC_SLLW
                                      : TRACERTL_RV_OPC_SLL;
    const uint32_t right_op = is_32bit ? TRACERTL_RV_OPC_SRLW
                                       : TRACERTL_RV_OPC_SRL;
    const uint32_t sub_op = is_32bit ? TRACERTL_RV_OPC_SUBW
                                     : TRACERTL_RV_OPC_SUB;
    int pos = 0;

    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_r(is_left ? left_op : right_op,
                                                    rd, rs, sh));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_r(sub_op,
                                                    TRACERTL_RV_SCRATCH_REG,
                                                    0, sh));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_r(is_left ? right_op : left_op,
                                                    TRACERTL_RV_SCRATCH_REG,
                                                    rs,
                                                    TRACERTL_RV_SCRATCH_REG));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_r(TRACERTL_RV_OPC_OR,
                                                    rd, rd,
                                                    TRACERTL_RV_SCRATCH_REG));
    return pos;
}

int tracertl_rv_emit_extract_sequence(uint32_t *buf, int buf_size,
                                      bool is_32bit, bool sign_extend,
                                      int rd, int rs,
                                      uint32_t ofs, uint32_t len)
{
    uint32_t lane_width = is_32bit ? 32 : 64;
    uint32_t shift_width = 64;
    int pos = 0;

    g_assert_cmpuint(len, >, 0);
    g_assert_cmpuint(ofs + len, <=, lane_width);

    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_SLLI,
                                                    rd, rs, shift_width - ofs - len));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_SRLI,
                                                    rd, rd,
                                                    (shift_width - len) |
                                                    (sign_extend ? 0x400 : 0)));
    return pos;
}

int tracertl_rv_emit_extract2_sequence(uint32_t *buf, int buf_size,
                                       bool is_32bit,
                                       int rd, int al, int ah,
                                       uint32_t ofs)
{
    uint32_t lane_width = is_32bit ? 32 : 64;
    int pos = 0;

    g_assert_cmpuint(ofs, >, 0);
    g_assert_cmpuint(ofs, <, lane_width);

    if (is_32bit) {
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_i(TRACERTL_RV_OPC_SLLI,
                                                        rd, al, 32));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_i(TRACERTL_RV_OPC_SRLI,
                                                        rd, rd, 32 + ofs));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_i(TRACERTL_RV_OPC_SLLI,
                                                        TRACERTL_RV_SCRATCH_REG,
                                                        ah, 32));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_i(TRACERTL_RV_OPC_SRLI,
                                                        TRACERTL_RV_SCRATCH_REG,
                                                        TRACERTL_RV_SCRATCH_REG,
                                                        ofs));
        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_r(TRACERTL_RV_OPC_OR,
                                                        rd, rd,
                                                        TRACERTL_RV_SCRATCH_REG));
        return pos;
    }

    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_SRLI,
                                                    rd, al, ofs));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_SLLI,
                                                    TRACERTL_RV_SCRATCH_REG,
                                                    ah, lane_width - ofs));
    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_r(TRACERTL_RV_OPC_OR,
                                                    rd, rd,
                                                    TRACERTL_RV_SCRATCH_REG));
    return pos;
}

int tracertl_rv_emit_bswap_sequence(uint32_t *buf, int buf_size,
                                    unsigned bits,
                                    int rd, int rs,
                                    unsigned flags)
{
    int pos = 0;

    g_assert(bits == 16 || bits == 32 || bits == 64);

    pos = tracertl_rv_emit_one(buf, buf_size, pos,
                               tracertl_rv_encode_i(TRACERTL_RV_OPC_SRLI,
                                                    rd, rs, 0x6B8));
    if (bits != 64) {
        uint32_t shift = bits == 32 ? 32 : 48;
        uint32_t imm = shift | ((flags & TRACERTL_RV_BSWAP_OS) ? 0x400 : 0);

        pos = tracertl_rv_emit_one(buf, buf_size, pos,
                                   tracertl_rv_encode_i(TRACERTL_RV_OPC_SRLI,
                                                        rd, rd, imm));
    }

    return pos;
}

static bool tracertl_rv_vector_imm5_p(int64_t imm)
{
    return imm >= -16 && imm < 16;
}

static bool tracertl_rv_vector_uimm5_p(int64_t imm)
{
    return imm >= 0 && imm < 32;
}

static bool tracertl_rv_is_vector_reg(int reg)
{
    return reg >= TRACERTL_RV_V0_REG && reg <= 63;
}

static int tracertl_rv_emit_vec_vv(uint32_t *buf, int buf_size, int pos,
                                   uint32_t opc, int vd, int vs2, int vs1)
{
    return tracertl_rv_emit_one(buf, buf_size, pos,
                                tracertl_rv_encode_v(opc, vd, vs1, vs2));
}

static int tracertl_rv_emit_vec_vx(uint32_t *buf, int buf_size, int pos,
                                   uint32_t opc, int vd, int vs2, int rs1)
{
    return tracertl_rv_emit_one(buf, buf_size, pos,
                                tracertl_rv_encode_v(opc, vd, rs1, vs2));
}

static int tracertl_rv_emit_vec_vi(uint32_t *buf, int buf_size, int pos,
                                   uint32_t opc, int vd, int vs2, int32_t imm)
{
    return tracertl_rv_emit_one(buf, buf_size, pos,
                                tracertl_rv_encode_vi(opc, vd, imm, vs2));
}

static int tracertl_rv_emit_vec_vim_mask(uint32_t *buf, int buf_size, int pos,
                                         uint32_t opc, int vd, int vs2,
                                         int32_t imm)
{
    return tracertl_rv_emit_one(buf, buf_size, pos,
                                tracertl_rv_encode_vi_masked(opc, vd, imm,
                                                             vs2, false));
}

static int tracertl_rv_emit_dup_scalar_vec(uint32_t *buf, int buf_size, int pos,
                                           int vd, int scratch_reg,
                                           int64_t imm)
{
    int n;

    if (tracertl_rv_vector_imm5_p(imm)) {
        return tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                       TRACERTL_RV_OPC_VMV_V_I, vd, 0, imm);
    }

    n = tracertl_rv_emit_load_imm_sequence(buf + pos, buf_size - pos,
                                           scratch_reg, (uint64_t)imm);
    if (n <= 0 || n > buf_size - pos) {
        return -1;
    }
    pos += n;
    return tracertl_rv_emit_vec_vx(buf, buf_size, pos,
                                   TRACERTL_RV_OPC_VMV_V_X, vd, 0,
                                   scratch_reg);
}

static unsigned int tracertl_rv_vector_mem_vsew(const TracertlRvVectorOp *op)
{
    if (op->opc == TRACERTL_RV_VECOP_DUPM) {
        return op->vece;
    }

    /*
     * ld_vec/st_vec encode register-group width in the vector type, not in a
     * separate lane-size field. Match the backend's default memory shape.
     */
    return MO_64;
}

static int tracertl_rv_emit_vec_mem(uint32_t *buf, int buf_size, int pos,
                                    uint32_t opc, int vreg, int base_reg)
{
    return tracertl_rv_emit_one(buf, buf_size, pos,
                                tracertl_rv_encode_v(opc, vreg, base_reg, 0));
}

static int tracertl_rv_emit_cached_vsetvli(uint32_t *buf, int buf_size, int pos,
                                           TracertlRvVectorState *state,
                                           unsigned int type,
                                           unsigned int vsew)
{
    int n;

    if (state && state->have_vtype &&
        state->cur_vtype_type == type &&
        state->cur_vtype_vsew == vsew) {
        return pos;
    }

    n = tracertl_rv_emit_vsetvli(buf + pos, buf_size - pos, type, vsew);
    if (n < 0) {
        return -1;
    }

    if (state) {
        state->have_vtype = true;
        state->cur_vtype_type = type;
        state->cur_vtype_vsew = vsew;
    }
    return pos + n;
}

int tracertl_rv_emit_vector_sequence(uint32_t *buf, int buf_size,
                                     TracertlRvVectorState *state,
                                     const TracertlRvVectorOp *op,
                                     TracertlRvVectorEmitMeta *meta)
{
    int pos = 0;
    uint32_t vv_opc;
    uint32_t vi_opc;

#define TRY_VECTOR_EMIT(expr) \
    do { \
        pos = (expr); \
        if (pos < 0) { \
            return 0; \
        } \
    } while (0)

    if (!buf || buf_size <= 0 || !op) {
        return 0;
    }
    if (meta) {
        *meta = (TracertlRvVectorEmitMeta){ 0 };
    }

    switch (op->opc) {
    case TRACERTL_RV_VECOP_LD:
    case TRACERTL_RV_VECOP_ST:
    case TRACERTL_RV_VECOP_DUPM: {
        unsigned int vsew = tracertl_rv_vector_mem_vsew(op);
        uint32_t mem_opc;
        int vreg;

        if (vsew > MO_64) {
            return 0;
        }
        if (op->opc == TRACERTL_RV_VECOP_ST) {
            if (!tracertl_rv_is_vector_reg(op->rs2) || op->rs1 < 0) {
                return 0;
            }
            mem_opc = tracertl_rv_vector_st_opc(vsew);
            vreg = op->rs2;
        } else {
            if (!tracertl_rv_is_vector_reg(op->rd) || op->rs1 < 0) {
                return 0;
            }
            mem_opc = tracertl_rv_vector_ld_opc(vsew);
            vreg = op->rd;
        }
        if (mem_opc == 0) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        vsew));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_mem(buf, buf_size, pos,
                                                 mem_opc, vreg, op->rs1));
        if (meta) {
            meta->note_mem_slot = true;
            meta->mem_slot_rel_idx = pos - 1;
        }
        return pos;
    }
    case TRACERTL_RV_VECOP_ADD:
        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        if (op->arg2_is_const) {
            if (!tracertl_rv_vector_imm5_p(op->arg2_imm)) {
                return 0;
            }
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                    TRACERTL_RV_OPC_VADD_VI,
                                                    op->rd, op->rs1,
                                                    op->arg2_imm));
        } else {
            if (!tracertl_rv_is_vector_reg(op->rs2)) {
                return 0;
            }
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                    TRACERTL_RV_OPC_VADD_VV,
                                                    op->rd, op->rs1,
                                                    op->rs2));
        }
        return pos;
    case TRACERTL_RV_VECOP_SUB:
        if (!tracertl_rv_is_vector_reg(op->rd)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        if (op->arg1_is_const) {
            if (!tracertl_rv_vector_imm5_p(op->arg1_imm) ||
                !tracertl_rv_is_vector_reg(op->rs2)) {
                return 0;
            }
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                    TRACERTL_RV_OPC_VRSUB_VI,
                                                    op->rd, op->rs2,
                                                    op->arg1_imm));
        } else {
            if (!tracertl_rv_is_vector_reg(op->rs1) ||
                !tracertl_rv_is_vector_reg(op->rs2)) {
                return 0;
            }
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                    TRACERTL_RV_OPC_VSUB_VV,
                                                    op->rd, op->rs1,
                                                    op->rs2));
        }
        return pos;
    case TRACERTL_RV_VECOP_MUL:
        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1) ||
            !tracertl_rv_is_vector_reg(op->rs2)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                TRACERTL_RV_OPC_VMUL_VV,
                                                op->rd, op->rs1, op->rs2));
        return pos;
    case TRACERTL_RV_VECOP_NEG:
        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                TRACERTL_RV_OPC_VRSUB_VI,
                                                op->rd, op->rs1, 0));
        return pos;
    case TRACERTL_RV_VECOP_AND:
    case TRACERTL_RV_VECOP_ANDC:
    case TRACERTL_RV_VECOP_OR:
    case TRACERTL_RV_VECOP_XOR:
    case TRACERTL_RV_VECOP_NOT:
        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        switch (op->opc) {
        case TRACERTL_RV_VECOP_AND:
            vv_opc = TRACERTL_RV_OPC_VAND_VV;
            vi_opc = TRACERTL_RV_OPC_VAND_VI;
            break;
        case TRACERTL_RV_VECOP_ANDC:
            if (op->arg2_is_const) {
                int64_t not_imm = ~op->arg2_imm;

                if (tracertl_rv_vector_imm5_p(not_imm)) {
                    TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                            TRACERTL_RV_OPC_VAND_VI,
                                                            op->rd, op->rs1,
                                                            not_imm));
                    return pos;
                }
                TRY_VECTOR_EMIT(tracertl_rv_emit_dup_scalar_vec(buf, buf_size,
                                                                pos,
                                                                TRACERTL_RV_V0_REG,
                                                                TRACERTL_RV_SCRATCH_REG,
                                                                not_imm));
            } else {
                if (!tracertl_rv_is_vector_reg(op->rs2)) {
                    return 0;
                }
                TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                        TRACERTL_RV_OPC_VXOR_VI,
                                                        TRACERTL_RV_V0_REG,
                                                        op->rs2, -1));
            }
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                    TRACERTL_RV_OPC_VAND_VV,
                                                    op->rd, op->rs1,
                                                    TRACERTL_RV_V0_REG));
            return pos;
        case TRACERTL_RV_VECOP_OR:
            vv_opc = TRACERTL_RV_OPC_VOR_VV;
            vi_opc = TRACERTL_RV_OPC_VOR_VI;
            break;
        case TRACERTL_RV_VECOP_XOR:
            vv_opc = TRACERTL_RV_OPC_VXOR_VV;
            vi_opc = TRACERTL_RV_OPC_VXOR_VI;
            break;
        case TRACERTL_RV_VECOP_NOT:
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                    TRACERTL_RV_OPC_VXOR_VI,
                                                    op->rd, op->rs1, -1));
            return pos;
        default:
            g_assert_not_reached();
        }
        if (op->arg2_is_const) {
            if (tracertl_rv_vector_imm5_p(op->arg2_imm)) {
                TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                        vi_opc, op->rd, op->rs1,
                                                        op->arg2_imm));
            } else {
                TRY_VECTOR_EMIT(tracertl_rv_emit_dup_scalar_vec(buf, buf_size,
                                                                pos,
                                                                TRACERTL_RV_V0_REG,
                                                                TRACERTL_RV_SCRATCH_REG,
                                                                op->arg2_imm));
                TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                        vv_opc, op->rd, op->rs1,
                                                        TRACERTL_RV_V0_REG));
            }
        } else {
            if (!tracertl_rv_is_vector_reg(op->rs2)) {
                return 0;
            }
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                    vv_opc, op->rd, op->rs1,
                                                    op->rs2));
        }
        return pos;
    case TRACERTL_RV_VECOP_SMAX:
    case TRACERTL_RV_VECOP_SMIN:
    case TRACERTL_RV_VECOP_UMAX:
    case TRACERTL_RV_VECOP_UMIN:
        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        switch (op->opc) {
        case TRACERTL_RV_VECOP_SMAX:
            vv_opc = TRACERTL_RV_OPC_VMAX_VV;
            vi_opc = TRACERTL_RV_OPC_VMAX_VI;
            break;
        case TRACERTL_RV_VECOP_SMIN:
            vv_opc = TRACERTL_RV_OPC_VMIN_VV;
            vi_opc = TRACERTL_RV_OPC_VMIN_VI;
            break;
        case TRACERTL_RV_VECOP_UMAX:
            vv_opc = TRACERTL_RV_OPC_VMAXU_VV;
            vi_opc = TRACERTL_RV_OPC_VMAXU_VI;
            break;
        case TRACERTL_RV_VECOP_UMIN:
            vv_opc = TRACERTL_RV_OPC_VMINU_VV;
            vi_opc = TRACERTL_RV_OPC_VMINU_VI;
            break;
        default:
            g_assert_not_reached();
        }
        if (op->arg2_is_const) {
            if (!tracertl_rv_vector_imm5_p(op->arg2_imm)) {
                return 0;
            }
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                    vi_opc, op->rd, op->rs1,
                                                    op->arg2_imm));
        } else {
            if (!tracertl_rv_is_vector_reg(op->rs2)) {
                return 0;
            }
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                    vv_opc, op->rd, op->rs1,
                                                    op->rs2));
        }
        return pos;
    case TRACERTL_RV_VECOP_SHLS:
    case TRACERTL_RV_VECOP_SHRS:
    case TRACERTL_RV_VECOP_SARS:
        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1) ||
            op->rs2 < 0 || tracertl_rv_is_vector_reg(op->rs2)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vx(buf, buf_size, pos,
                                                op->opc == TRACERTL_RV_VECOP_SHLS
                                                ? TRACERTL_RV_OPC_VSLL_VX
                                                : op->opc == TRACERTL_RV_VECOP_SHRS
                                                ? TRACERTL_RV_OPC_VSRL_VX
                                                : TRACERTL_RV_OPC_VSRA_VX,
                                                op->rd, op->rs1, op->rs2));
        return pos;
    case TRACERTL_RV_VECOP_SHLV:
    case TRACERTL_RV_VECOP_SHRV:
    case TRACERTL_RV_VECOP_SARV:
        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1) ||
            !tracertl_rv_is_vector_reg(op->rs2)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                op->opc == TRACERTL_RV_VECOP_SHLV
                                                ? TRACERTL_RV_OPC_VSLL_VV
                                                : op->opc == TRACERTL_RV_VECOP_SHRV
                                                ? TRACERTL_RV_OPC_VSRL_VV
                                                : TRACERTL_RV_OPC_VSRA_VV,
                                                op->rd, op->rs1, op->rs2));
        return pos;
    case TRACERTL_RV_VECOP_SHLI:
    case TRACERTL_RV_VECOP_SHRI:
    case TRACERTL_RV_VECOP_SARI:
        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1) ||
            !op->arg2_is_const ||
            !tracertl_rv_vector_uimm5_p(op->arg2_imm)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                op->opc == TRACERTL_RV_VECOP_SHLI
                                                ? TRACERTL_RV_OPC_VSLL_VI
                                                : op->opc == TRACERTL_RV_VECOP_SHRI
                                                ? TRACERTL_RV_OPC_VSRL_VI
                                                : TRACERTL_RV_OPC_VSRA_VI,
                                                op->rd, op->rs1,
                                                op->arg2_imm));
        return pos;
    case TRACERTL_RV_VECOP_ROTLI:
        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1) ||
            !op->arg2_is_const ||
            !tracertl_rv_vector_uimm5_p(op->arg2_imm)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                TRACERTL_RV_OPC_VSLL_VI,
                                                TRACERTL_RV_V0_REG,
                                                op->rs1,
                                                op->arg2_imm));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                TRACERTL_RV_OPC_VSRL_VI,
                                                op->rd, op->rs1,
                                                (-op->arg2_imm) &
                                                ((8U << op->vece) - 1)));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                TRACERTL_RV_OPC_VOR_VV,
                                                op->rd, op->rd,
                                                TRACERTL_RV_V0_REG));
        return pos;
    case TRACERTL_RV_VECOP_ROTLS:
        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1) ||
            op->rs2 < 0 || tracertl_rv_is_vector_reg(op->rs2)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vx(buf, buf_size, pos,
                                                TRACERTL_RV_OPC_VSLL_VX,
                                                TRACERTL_RV_V0_REG,
                                                op->rs1, op->rs2));
        TRY_VECTOR_EMIT(tracertl_rv_emit_one(buf, buf_size, pos,
                                             tracertl_rv_encode_r(TRACERTL_RV_OPC_SUBW,
                                                                  TRACERTL_RV_CARRY_REG,
                                                                  0, op->rs2)));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vx(buf, buf_size, pos,
                                                TRACERTL_RV_OPC_VSRL_VX,
                                                op->rd, op->rs1,
                                                TRACERTL_RV_CARRY_REG));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                TRACERTL_RV_OPC_VOR_VV,
                                                op->rd, op->rd,
                                                TRACERTL_RV_V0_REG));
        return pos;
    case TRACERTL_RV_VECOP_ROTLV:
    case TRACERTL_RV_VECOP_ROTRV:
        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1) ||
            !tracertl_rv_is_vector_reg(op->rs2)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                TRACERTL_RV_OPC_VRSUB_VI,
                                                TRACERTL_RV_V0_REG,
                                                op->rs2, 0));
        if (op->opc == TRACERTL_RV_VECOP_ROTLV) {
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                    TRACERTL_RV_OPC_VSRL_VV,
                                                    TRACERTL_RV_V0_REG,
                                                    op->rs1,
                                                    TRACERTL_RV_V0_REG));
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                    TRACERTL_RV_OPC_VSLL_VV,
                                                    op->rd, op->rs1,
                                                    op->rs2));
        } else {
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                    TRACERTL_RV_OPC_VSLL_VV,
                                                    TRACERTL_RV_V0_REG,
                                                    op->rs1,
                                                    TRACERTL_RV_V0_REG));
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                    TRACERTL_RV_OPC_VSRL_VV,
                                                    op->rd, op->rs1,
                                                    op->rs2));
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                TRACERTL_RV_OPC_VOR_VV,
                                                op->rd, op->rd,
                                                TRACERTL_RV_V0_REG));
        return pos;
    case TRACERTL_RV_VECOP_CMP: {
        bool invert_result = false;

        if (!tracertl_rv_is_vector_reg(op->rd) ||
            !tracertl_rv_is_vector_reg(op->rs1)) {
            return 0;
        }
        TRY_VECTOR_EMIT(tracertl_rv_emit_cached_vsetvli(buf, buf_size, pos,
                                                        state, op->type,
                                                        op->vece));
        if (op->cond == TCG_COND_ALWAYS || op->cond == TCG_COND_NEVER) {
            TRY_VECTOR_EMIT(tracertl_rv_emit_dup_scalar_vec(buf, buf_size, pos,
                                                            op->rd,
                                                            TRACERTL_RV_SCRATCH_REG,
                                                            op->cond == TCG_COND_ALWAYS
                                                            ? -1 : 0));
            return pos;
        }
        if (op->arg2_is_const) {
            if (op->cond < ARRAY_SIZE(tracertl_rv_cmpcond_to_vi) &&
                tracertl_rv_cmpcond_to_vi[op->cond].opc != 0 &&
                op->arg2_imm >= tracertl_rv_cmpcond_to_vi[op->cond].min &&
                op->arg2_imm <= tracertl_rv_cmpcond_to_vi[op->cond].max) {
                TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vi(buf, buf_size, pos,
                                                        tracertl_rv_cmpcond_to_vi[op->cond].opc,
                                                        TRACERTL_RV_V0_REG,
                                                        op->rs1,
                                                        op->arg2_imm -
                                                        tracertl_rv_cmpcond_to_vi[op->cond].adjust));
            } else if (op->cond < ARRAY_SIZE(tracertl_rv_cmpcond_to_vx) &&
                       tracertl_rv_cmpcond_to_vx[op->cond].opc != 0) {
                TRY_VECTOR_EMIT(tracertl_rv_emit_load_imm_at(buf, buf_size, pos,
                                                             TRACERTL_RV_SCRATCH_REG,
                                                             (uint64_t)op->arg2_imm));
                invert_result = tracertl_rv_cmpcond_to_vx[op->cond].invert;
                TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vx(buf, buf_size, pos,
                                                        tracertl_rv_cmpcond_to_vx[op->cond].opc,
                                                        TRACERTL_RV_V0_REG,
                                                        op->rs1,
                                                        TRACERTL_RV_SCRATCH_REG));
            } else {
                return 0;
            }
        } else {
            if (!tracertl_rv_is_vector_reg(op->rs2) ||
                op->cond >= ARRAY_SIZE(tracertl_rv_cmpcond_to_vv) ||
                tracertl_rv_cmpcond_to_vv[op->cond].opc == 0) {
                return 0;
            }
            if (tracertl_rv_cmpcond_to_vv[op->cond].swap) {
                TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                        tracertl_rv_cmpcond_to_vv[op->cond].opc,
                                                        TRACERTL_RV_V0_REG,
                                                        op->rs2, op->rs1));
            } else {
                TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vv(buf, buf_size, pos,
                                                        tracertl_rv_cmpcond_to_vv[op->cond].opc,
                                                        TRACERTL_RV_V0_REG,
                                                        op->rs1, op->rs2));
            }
        }

        if (invert_result) {
            TRY_VECTOR_EMIT(tracertl_rv_emit_dup_scalar_vec(buf, buf_size, pos,
                                                            op->rd,
                                                            TRACERTL_RV_SCRATCH_REG,
                                                            -1));
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vim_mask(buf, buf_size, pos,
                                                          TRACERTL_RV_OPC_VMERGE_VIM,
                                                          op->rd, op->rd, 0));
        } else {
            TRY_VECTOR_EMIT(tracertl_rv_emit_dup_scalar_vec(buf, buf_size, pos,
                                                            op->rd,
                                                            TRACERTL_RV_SCRATCH_REG,
                                                            0));
            TRY_VECTOR_EMIT(tracertl_rv_emit_vec_vim_mask(buf, buf_size, pos,
                                                          TRACERTL_RV_OPC_VMERGE_VIM,
                                                          op->rd, op->rd, -1));
        }
        return pos;
    }
    default:
        return 0;
    }

#undef TRY_VECTOR_EMIT
}

typedef struct TracertlX86PrefixInfo {
    size_t off;
    bool p66;
    bool pf2;
    bool pf3;
    bool rex_w;
} TracertlX86PrefixInfo;

static uint32_t tracertl_rv_memory_placeholder(uint8_t mtype, uint8_t msize)
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

static void tracertl_rv_guest_semantic_plan_reset(
    TracertlRvGuestSemanticPlan *plan)
{
    g_assert(plan != NULL);

    memset(plan, 0, sizeof(*plan));
    memset(plan->mem_idxs, -1, sizeof(plan->mem_idxs));
    plan->branch_idx = -1;
    plan->kind = TRACERTL_RV_GUEST_SEM_DEFAULT;
    plan->mem_size = 3;
}

void tracertl_rv_guest_semantic_plan_default(
    TracertlRvGuestSemanticPlan *plan)
{
    tracertl_rv_guest_semantic_plan_reset(plan);
    plan->n_insns = 1;
    plan->insns[0] = tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI, 0, 0, 0);
    plan->kind = TRACERTL_RV_GUEST_SEM_DEFAULT;
    plan->counter_name = "translated_default";
}

static void tracertl_rv_guest_plan_set_single(
    TracertlRvGuestSemanticPlan *plan,
    uint32_t insn,
    const char *counter_name)
{
    tracertl_rv_guest_semantic_plan_reset(plan);
    plan->n_insns = 1;
    plan->insns[0] = insn;
    plan->counter_name = counter_name;
}

static void tracertl_rv_guest_plan_set_mem_only(
    TracertlRvGuestSemanticPlan *plan,
    uint8_t mtype,
    uint8_t msize,
    const char *counter_name)
{
    tracertl_rv_guest_semantic_plan_reset(plan);
    plan->n_insns = 1;
    plan->insns[0] = tracertl_rv_memory_placeholder(mtype, msize);
    plan->n_mem = 1;
    plan->mem_idxs[0] = 0;
    plan->mem_size = msize;
    plan->counter_name = counter_name;
}

static void tracertl_rv_guest_plan_set_mem_then(
    TracertlRvGuestSemanticPlan *plan,
    uint8_t mtype,
    uint8_t msize,
    uint32_t insn,
    const char *counter_name)
{
    tracertl_rv_guest_semantic_plan_reset(plan);
    plan->n_insns = 2;
    plan->insns[0] = tracertl_rv_memory_placeholder(mtype, msize);
    plan->insns[1] = insn;
    plan->n_mem = 1;
    plan->mem_idxs[0] = 0;
    plan->mem_size = msize;
    plan->counter_name = counter_name;
}

static TracertlX86PrefixInfo tracertl_x86_prefix_info(const uint8_t *bytes,
                                                      size_t len)
{
    TracertlX86PrefixInfo info = { 0 };

    while (info.off < len) {
        switch (bytes[info.off]) {
        case 0x26:
        case 0x2e:
        case 0x36:
        case 0x3e:
        case 0x64:
        case 0x65:
        case 0x67:
        case 0xf0:
            info.off++;
            continue;
        case 0x66:
            info.p66 = true;
            info.off++;
            continue;
        case 0xf2:
            info.pf2 = true;
            info.off++;
            continue;
        case 0xf3:
            info.pf3 = true;
            info.off++;
            continue;
        default:
            if (bytes[info.off] >= 0x40 && bytes[info.off] <= 0x4f) {
                info.rex_w |= (bytes[info.off] & 0x8) != 0;
                info.off++;
                continue;
            }
            return info;
        }
    }

    return info;
}

static bool tracertl_x86_modrm_is_mem(const uint8_t *bytes, size_t len,
                                      size_t modrm_off)
{
    return modrm_off < len && ((bytes[modrm_off] >> 6) & 0x3) != 0x3;
}

static uint8_t tracertl_x86_scalar_size(const TracertlX86PrefixInfo *info,
                                        bool byte_op)
{
    if (byte_op) {
        return 0;
    }
    if (info->p66) {
        return 1;
    }
    return info->rex_w ? 3 : 2;
}

static void tracertl_rv_translated_x86_spec_reset(
    TracertlRvTranslatedX86Spec *spec)
{
    if (spec == NULL) {
        return;
    }

    memset(spec, 0, sizeof(*spec));
    spec->semantic_kind = TRACERTL_RV_GUEST_SEM_DEFAULT;
    spec->mem_size = 3;
}

static TracertlRvTranslatedX86DecodeStatus
tracertl_rv_translated_x86_spec_set(TracertlRvTranslatedX86Spec *spec,
                                    TracertlRvGuestSemanticKind semantic_kind,
                                    TracertlRvTranslatedX86EmitKind emit_kind,
                                    bool has_mem_operand,
                                    uint8_t mem_type,
                                    uint8_t mem_size,
                                    bool helper_exception,
                                    const char *counter_name)
{
    if (spec != NULL) {
        tracertl_rv_translated_x86_spec_reset(spec);
        spec->semantic_kind = semantic_kind;
        spec->emit_kind = emit_kind;
        spec->has_mem_operand = has_mem_operand;
        spec->mem_type = mem_type;
        spec->mem_size = mem_size;
        spec->helper_exception = helper_exception;
        spec->counter_name = counter_name;
    }

    return TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED;
}

static uint32_t tracertl_rv_translated_x86_fallback_insn(
    const TracertlRvTranslatedX86Spec *spec)
{
    if (spec == NULL) {
        return tracertl_rv_encode_r(TRACERTL_RV_OPC_ADD,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    }

    switch (spec->emit_kind) {
    case TRACERTL_RV_TRANSLATED_X86_EMIT_TRAP:
        return TRACERTL_RV_OPC_ECALL;
    case TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE:
        return TRACERTL_RV_OPC_FENCE;
    case TRACERTL_RV_TRANSLATED_X86_EMIT_SUB:
        return tracertl_rv_encode_r(TRACERTL_RV_OPC_SUB,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    case TRACERTL_RV_TRANSLATED_X86_EMIT_OR:
        return tracertl_rv_encode_r(TRACERTL_RV_OPC_OR,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    case TRACERTL_RV_TRANSLATED_X86_EMIT_SRL:
        return tracertl_rv_encode_r(TRACERTL_RV_OPC_SRL,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    case TRACERTL_RV_TRANSLATED_X86_EMIT_DIV:
        return tracertl_rv_encode_r(TRACERTL_RV_OPC_DIV,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    case TRACERTL_RV_TRANSLATED_X86_EMIT_DIVU:
        return tracertl_rv_encode_r(TRACERTL_RV_OPC_DIVU,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    case TRACERTL_RV_TRANSLATED_X86_EMIT_STORE:
        return tracertl_rv_memory_placeholder(TRACE_MEM_TYPE_STORE,
                                              spec->mem_size);
    case TRACERTL_RV_TRANSLATED_X86_EMIT_NONE:
    default:
        return tracertl_rv_encode_r(TRACERTL_RV_OPC_ADD,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_SCRATCH_REG,
                                    TRACERTL_RV_ALT_SCRATCH_REG);
    }
}

TracertlRvTranslatedX86DecodeStatus tracertl_rv_decode_translated_x86(
    const uint8_t *bytes, size_t len,
    bool is_system_emulation,
    TracertlRvTranslatedX86Spec *spec)
{
    TracertlX86PrefixInfo info;
    size_t off;

    tracertl_rv_translated_x86_spec_reset(spec);

    if (bytes == NULL || len == 0) {
        return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
    }

    info = tracertl_x86_prefix_info(bytes, len);
    off = info.off;
    if (off >= len) {
        return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
    }

    switch (bytes[off]) {
    case 0x0f:
        if (off + 1 >= len) {
            return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
        }
        switch (bytes[off + 1]) {
        case 0x05:
        case 0x0b:
            return tracertl_rv_translated_x86_spec_set(
                spec, TRACERTL_RV_GUEST_SEM_TRAP,
                TRACERTL_RV_TRANSLATED_X86_EMIT_TRAP,
                false, 0, 0, true, "x86_trap");
        case 0xa2:
            return tracertl_rv_translated_x86_spec_set(
                spec, TRACERTL_RV_GUEST_SEM_SERIALIZE,
                TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE,
                false, 0, 0, false, "x86_serialize");
        case 0xae:
            if (off + 2 >= len) {
                return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
            }
            switch (bytes[off + 2]) {
            case 0xe8:
            case 0xf0:
            case 0xf8:
                return tracertl_rv_translated_x86_spec_set(
                    spec, TRACERTL_RV_GUEST_SEM_SERIALIZE,
                    TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE,
                    false, 0, 0, false, "x86_serialize");
            default:
                return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
            }
        case 0x01:
            if (off + 2 < len && bytes[off + 2] == 0xd0) {
                return tracertl_rv_translated_x86_spec_set(
                    spec, TRACERTL_RV_GUEST_SEM_SERIALIZE,
                    TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE,
                    false, 0, 0, false, "x86_serialize");
            }
            return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
        case 0x2e:
        case 0x2f:
            if (!info.p66 || off + 2 >= len) {
                return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
            }
            return tracertl_rv_translated_x86_spec_set(
                spec, TRACERTL_RV_GUEST_SEM_FP_COMPARE,
                TRACERTL_RV_TRANSLATED_X86_EMIT_SUB,
                tracertl_x86_modrm_is_mem(bytes, len, off + 2),
                TRACE_MEM_TYPE_LOAD, 3, false,
                tracertl_x86_modrm_is_mem(bytes, len, off + 2)
                    ? "x86_fp_compare_mem" : "x86_fp_compare");
        case 0x62:
        case 0x6a:
        case 0x6c:
            if (!info.p66 || off + 2 >= len) {
                return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
            }
            return tracertl_rv_translated_x86_spec_set(
                spec, TRACERTL_RV_GUEST_SEM_VECTOR_UNPACK,
                TRACERTL_RV_TRANSLATED_X86_EMIT_OR,
                tracertl_x86_modrm_is_mem(bytes, len, off + 2),
                TRACE_MEM_TYPE_LOAD, 3, false,
                tracertl_x86_modrm_is_mem(bytes, len, off + 2)
                    ? "x86_vector_unpack_mem" : "x86_vector_unpack");
        case 0x73:
            if (!info.p66 || off + 2 >= len ||
                ((bytes[off + 2] >> 3) & 0x7) != 0x3) {
                return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
            }
            return tracertl_rv_translated_x86_spec_set(
                spec, TRACERTL_RV_GUEST_SEM_SHIFT,
                TRACERTL_RV_TRANSLATED_X86_EMIT_SRL,
                false, 0, 0, false, "x86_shift");
        case 0x5e:
            if (!info.pf2 || off + 2 >= len) {
                return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
            }
            return tracertl_rv_translated_x86_spec_set(
                spec, TRACERTL_RV_GUEST_SEM_FP_DIV,
                TRACERTL_RV_TRANSLATED_X86_EMIT_DIV,
                tracertl_x86_modrm_is_mem(bytes, len, off + 2),
                TRACE_MEM_TYPE_LOAD, 3, false,
                tracertl_x86_modrm_is_mem(bytes, len, off + 2)
                    ? "x86_fp_div_mem" : "x86_fp_div");
        case 0x2a:
        case 0x2c: {
            bool valid = bytes[off + 1] == 0x2a ? (info.p66 || info.pf2)
                                                : info.pf2;
            uint8_t mem_size;

            if (!valid || off + 2 >= len) {
                return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
            }
            mem_size = (info.p66 || info.rex_w) ? 3 : 2;
            return tracertl_rv_translated_x86_spec_set(
                spec, TRACERTL_RV_GUEST_SEM_CONVERT,
                TRACERTL_RV_TRANSLATED_X86_EMIT_OR,
                tracertl_x86_modrm_is_mem(bytes, len, off + 2),
                TRACE_MEM_TYPE_LOAD, mem_size, false,
                tracertl_x86_modrm_is_mem(bytes, len, off + 2)
                    ? "x86_convert_mem" : "x86_convert");
        }
        default:
            return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
        }
    case 0xcc:
    case 0xcd:
    case 0xce:
    case 0xf1:
        return tracertl_rv_translated_x86_spec_set(
            spec, TRACERTL_RV_GUEST_SEM_TRAP,
            TRACERTL_RV_TRANSLATED_X86_EMIT_TRAP,
            false, 0, 0, true, "x86_trap");
    case 0xf4:
        return is_system_emulation
            ? TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED
            : tracertl_rv_translated_x86_spec_set(
                  spec, TRACERTL_RV_GUEST_SEM_TRAP,
                  TRACERTL_RV_TRANSLATED_X86_EMIT_TRAP,
                  false, 0, 0, true, "x86_trap");
    case 0xf6:
    case 0xf7:
        if (off + 1 < len) {
            uint8_t modrm = bytes[off + 1];
            uint8_t reg = (modrm >> 3) & 0x7;
            bool is_signed = reg == 0x7;

            if (reg == 0x6 || reg == 0x7) {
                return tracertl_rv_translated_x86_spec_set(
                    spec,
                    is_signed ? TRACERTL_RV_GUEST_SEM_DIV_SIGNED
                              : TRACERTL_RV_GUEST_SEM_DIV_UNSIGNED,
                    is_signed ? TRACERTL_RV_TRANSLATED_X86_EMIT_DIV
                              : TRACERTL_RV_TRANSLATED_X86_EMIT_DIVU,
                    tracertl_x86_modrm_is_mem(bytes, len, off + 1),
                    TRACE_MEM_TYPE_LOAD,
                    tracertl_x86_scalar_size(&info, bytes[off] == 0xf6),
                    false,
                    tracertl_x86_modrm_is_mem(bytes, len, off + 1)
                        ? (is_signed ? "x86_idiv_mem" : "x86_div_mem")
                        : (is_signed ? "x86_idiv" : "x86_div"));
            }
        }
        return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
    case 0xd8 ... 0xdf:
        if (off + 1 >= len || !tracertl_x86_modrm_is_mem(bytes, len, off + 1)) {
            return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
        }
        if (bytes[off] == 0xd9 && ((bytes[off + 1] >> 3) & 0x7) == 0x7) {
            return tracertl_rv_translated_x86_spec_set(
                spec, TRACERTL_RV_GUEST_SEM_X87_STORE,
                TRACERTL_RV_TRANSLATED_X86_EMIT_STORE,
                true, TRACE_MEM_TYPE_STORE,
                is_system_emulation ? 3 : 1, false, "x86_x87_store");
        }
        return TRACERTL_RV_TRANSLATED_X86_DECODE_RESIDUAL_UNSUPPORTED;
    default:
        return TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED;
    }
}

static void tracertl_rv_build_x86_guest_semantic_plan(
    const uint8_t *bytes, size_t len,
    bool is_system_emulation,
    TracertlRvGuestSemanticPlan *plan)
{
    TracertlRvTranslatedX86Spec spec;

    tracertl_rv_guest_semantic_plan_default(plan);
    if (tracertl_rv_decode_translated_x86(bytes, len, is_system_emulation,
                                          &spec) !=
        TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED) {
        return;
    }

    if (spec.has_mem_operand) {
        if (spec.emit_kind == TRACERTL_RV_TRANSLATED_X86_EMIT_STORE) {
            tracertl_rv_guest_plan_set_mem_only(plan, spec.mem_type,
                                                spec.mem_size,
                                                spec.counter_name);
        } else {
            tracertl_rv_guest_plan_set_mem_then(
                plan, spec.mem_type, spec.mem_size,
                tracertl_rv_translated_x86_fallback_insn(&spec),
                spec.counter_name);
        }
    } else {
        tracertl_rv_guest_plan_set_single(
            plan, tracertl_rv_translated_x86_fallback_insn(&spec),
            spec.counter_name);
    }

    plan->kind = spec.semantic_kind;
    plan->helper_exception = spec.helper_exception;
}

void tracertl_rv_build_guest_semantic_plan(
    const uint8_t *bytes, size_t len,
    bool is_x86_guest,
    bool is_aarch64_guest,
    bool is_system_emulation,
    TracertlRvGuestSemanticPlan *plan)
{
    tracertl_rv_guest_semantic_plan_default(plan);

    if (bytes == NULL || len == 0) {
        return;
    }

    if (is_x86_guest) {
        tracertl_rv_build_x86_guest_semantic_plan(bytes, len,
                                                  is_system_emulation,
                                                  plan);
        return;
    }

    if (is_aarch64_guest) {
        plan->counter_name = "aarch64_default";
        return;
    }

    plan->counter_name = "translated_default";
}

uint32_t tracertl_rv_guest_semantic_fallback_insn(
    const TracertlRvGuestSemanticPlan *plan)
{
    if (plan == NULL || plan->n_insns == 0) {
        return tracertl_rv_encode_i(TRACERTL_RV_OPC_ADDI, 0, 0, 0);
    }

    return plan->insns[plan->n_insns - 1];
}

static bool tracertl_rv_core_trace_emit_word(TracertlRvCoreTraceSink *sink,
                                             uint32_t insn,
                                             qemu_plugin_rv_trace_tag tag,
                                             QemuPluginTbRvOrigin origin)
{
    if (*sink->pos >= sink->buf_size) {
        *sink->pos = sink->buf_size + 1;
        return false;
    }

    if (sink->tags != NULL) {
        sink->tags[*sink->pos] = (uint8_t)tag;
    }
    if (sink->origins != NULL) {
        sink->origins[*sink->pos] = (uint8_t)origin;
    }
    sink->buf[(*sink->pos)++] = insn;
    return true;
}

static void tracertl_rv_core_trace_note_branch_slot(
    TracertlRvCoreTraceSink *sink)
{
    if (sink->meta != NULL && sink->meta->branch_idx < 0) {
        sink->meta->branch_idx = (int8_t)(*sink->pos - sink->insn_offset);
    }
    if (sink->guest_has_branch != NULL) {
        *sink->guest_has_branch = true;
    }
}

void tracertl_rv_core_trace_meta_reset(qemu_plugin_rv_insn_meta *meta)
{
    if (meta == NULL) {
        return;
    }

    meta->n_mem = 0;
    memset(meta->mem_idxs, -1, sizeof(meta->mem_idxs));
    meta->branch_idx = -1;
    meta->exception_idx = -1;
    meta->helper_idx = -1;
    meta->emitting_tcg_ops = 0;
}

void tracertl_rv_core_emit_lookup_tb_ptr(TracertlRvCoreTraceSink *sink,
                                         int target_reg)
{
    if (sink == NULL) {
        return;
    }

    tracertl_rv_core_trace_note_branch_slot(sink);
    tracertl_rv_core_trace_emit_word(
        sink, tracertl_rv_encode_i(TRACERTL_RV_OPC_JALR, 0, target_reg, 0),
        QEMU_PLUGIN_RV_TAG_INDIRECT_BRANCH_PLACEHOLDER,
        QEMU_PLUGIN_TB_RV_ORIGIN_GUEST);
}

void tracertl_rv_core_filter_bundle(
    uint32_t *raw_insns, uint8_t *raw_tags,
    uint8_t *raw_origins, int raw_total_insns,
    int *raw_offsets,
    qemu_plugin_rv_insn_meta *raw_meta,
    int n_guest_insns,
    uint32_t **filtered_insns,
    uint8_t **filtered_tags,
    uint8_t **filtered_origins,
    int **filtered_offsets,
    qemu_plugin_rv_insn_meta **filtered_meta,
    int *filtered_total_insns)
{
    uint32_t *insns = g_new(uint32_t, MAX(raw_total_insns, 1));
    uint8_t *tags = g_new0(uint8_t, MAX(raw_total_insns, 1));
    uint8_t *origins = g_new0(uint8_t, MAX(raw_total_insns, 1));
    int *offsets = g_new(int, n_guest_insns + 1);
    qemu_plugin_rv_insn_meta *meta = g_new0(qemu_plugin_rv_insn_meta,
                                            MAX(n_guest_insns, 1));
    int out_pos = 0;

    for (int i = 0; i < n_guest_insns; i++) {
        int start = raw_offsets[i];
        int end = (i + 1 < n_guest_insns) ? raw_offsets[i + 1]
                                          : raw_total_insns;
        int span = MAX(end - start, 0);
        int *map = g_new(int, MAX(span, 1));

        memset(map, -1, MAX(span, 1) * sizeof(*map));
        offsets[i] = out_pos;
        tracertl_rv_core_trace_meta_reset(&meta[i]);
        meta[i].emitting_tcg_ops = raw_meta[i].emitting_tcg_ops;

        for (int j = start; j < end; j++) {
            if (raw_origins[j] != QEMU_PLUGIN_TB_RV_ORIGIN_GUEST) {
                continue;
            }

            insns[out_pos] = raw_insns[j];
            tags[out_pos] = raw_tags[j];
            origins[out_pos] = raw_origins[j];
            map[j - start] = out_pos - offsets[i];
            out_pos++;
        }

        for (int j = 0; j < raw_meta[i].n_mem; j++) {
            int raw_idx = raw_meta[i].mem_idxs[j];

            if (raw_idx < 0 || raw_idx >= span) {
                continue;
            }
            if (map[raw_idx] < 0 || meta[i].n_mem >= QEMU_PLUGIN_RV_MAX_MEM) {
                continue;
            }
            meta[i].mem_idxs[meta[i].n_mem++] = map[raw_idx];
        }

        if (raw_meta[i].branch_idx >= 0 &&
            raw_meta[i].branch_idx < span &&
            map[raw_meta[i].branch_idx] >= 0) {
            meta[i].branch_idx = map[raw_meta[i].branch_idx];
        }

        if (raw_meta[i].exception_idx >= 0 &&
            raw_meta[i].exception_idx < span &&
            map[raw_meta[i].exception_idx] >= 0) {
            meta[i].exception_idx = map[raw_meta[i].exception_idx];
        }

        if (raw_meta[i].helper_idx >= 0 &&
            raw_meta[i].helper_idx < span &&
            map[raw_meta[i].helper_idx] >= 0) {
            meta[i].helper_idx = map[raw_meta[i].helper_idx];
        }

        g_free(map);
    }

    offsets[n_guest_insns] = out_pos;
    *filtered_insns = insns;
    *filtered_tags = tags;
    *filtered_origins = origins;
    *filtered_offsets = offsets;
    *filtered_meta = meta;
    *filtered_total_insns = out_pos;
}
