#include "qemu/osdep.h"
#include "plugins/tracertl_rv_vector_lowering.h"

static bool rv_arg_is_const(TCGArg arg)
{
    TCGTemp *ts = arg_temp(arg);

    return ts && ts->val_type == TEMP_VAL_CONST;
}

static int64_t rv_arg_const_value(TCGArg arg)
{
    TCGTemp *ts = arg_temp(arg);

    g_assert(ts && ts->val_type == TEMP_VAL_CONST);
    return ts->val;
}

static int64_t rv_arg_lane_const_value(TCGArg arg, unsigned int vece)
{
    int64_t value = rv_arg_const_value(arg);
    unsigned int shift = 64U - (8U << vece);

    return shift < 64 ? value >> shift : value;
}

static int rv_map_vector_reg_arg(TCGArg arg,
                                 TracertlRvMapArgFn map_arg,
                                 void *map_opaque)
{
    TCGTemp *ts = arg_temp(arg);

    if (ts && ts->val_type != TEMP_VAL_CONST) {
        int vreg = tracertl_rv_temp_to_vreg((unsigned int)temp_idx(ts));

        if (vreg >= 0) {
            return vreg;
        }
    }

    return map_arg(arg, map_opaque);
}

int tracertl_rv_lower_vector_tcg_op(uint32_t *buf, int buf_size,
                                    TracertlRvVectorState *state,
                                    const TCGOp *op,
                                    TracertlRvMapArgFn map_arg,
                                    void *map_opaque,
                                    TracertlRvVectorEmitMeta *meta)
{
    TracertlRvVectorOp vector_op;

    if (!buf || buf_size <= 0 || !state || !op || !map_arg) {
        return 0;
    }

    vector_op = (TracertlRvVectorOp) {
        .type = TCGOP_TYPE(op),
        .vece = TCGOP_VECE(op),
    };

    switch (op->opc) {
    case INDEX_op_ld_vec:
        vector_op.opc = TRACERTL_RV_VECOP_LD;
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = map_arg(op->args[1], map_opaque);
        break;
    case INDEX_op_st_vec:
        vector_op.opc = TRACERTL_RV_VECOP_ST;
        vector_op.rs1 = map_arg(op->args[1], map_opaque);
        vector_op.rs2 = rv_map_vector_reg_arg(op->args[0], map_arg,
                                              map_opaque);
        break;
    case INDEX_op_dupm_vec:
        vector_op.opc = TRACERTL_RV_VECOP_DUPM;
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = map_arg(op->args[1], map_opaque);
        break;
    case INDEX_op_add_vec:
        vector_op.opc = TRACERTL_RV_VECOP_ADD;
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        if (rv_arg_is_const(op->args[2])) {
            vector_op.arg2_is_const = true;
            vector_op.arg2_imm = rv_arg_lane_const_value(op->args[2],
                                                         vector_op.vece);
        } else {
            vector_op.rs2 = rv_map_vector_reg_arg(op->args[2], map_arg,
                                                  map_opaque);
        }
        break;
    case INDEX_op_sub_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SUB;
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        if (rv_arg_is_const(op->args[1])) {
            vector_op.arg1_is_const = true;
            vector_op.arg1_imm = rv_arg_lane_const_value(op->args[1],
                                                         vector_op.vece);
        } else {
            vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                                  map_opaque);
        }
        vector_op.rs2 = rv_map_vector_reg_arg(op->args[2], map_arg,
                                              map_opaque);
        break;
    case INDEX_op_mul_vec:
        vector_op.opc = TRACERTL_RV_VECOP_MUL;
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        vector_op.rs2 = rv_map_vector_reg_arg(op->args[2], map_arg,
                                              map_opaque);
        break;
    case INDEX_op_neg_vec:
        vector_op.opc = TRACERTL_RV_VECOP_NEG;
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        break;
    case INDEX_op_and_vec:
        vector_op.opc = TRACERTL_RV_VECOP_AND;
        goto fill_logic_rhs;
    case INDEX_op_andc_vec:
        vector_op.opc = TRACERTL_RV_VECOP_ANDC;
        goto fill_logic_rhs;
    case INDEX_op_or_vec:
        vector_op.opc = TRACERTL_RV_VECOP_OR;
        goto fill_logic_rhs;
    case INDEX_op_xor_vec:
        vector_op.opc = TRACERTL_RV_VECOP_XOR;
        goto fill_logic_rhs;
    case INDEX_op_not_vec:
        vector_op.opc = TRACERTL_RV_VECOP_NOT;
fill_logic_rhs:
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        if (op->opc != INDEX_op_not_vec) {
            if (rv_arg_is_const(op->args[2])) {
                vector_op.arg2_is_const = true;
                vector_op.arg2_imm = rv_arg_lane_const_value(op->args[2],
                                                             vector_op.vece);
            } else {
                vector_op.rs2 = rv_map_vector_reg_arg(op->args[2], map_arg,
                                                      map_opaque);
            }
        }
        break;
    case INDEX_op_smax_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SMAX;
        goto fill_minmax_rhs;
    case INDEX_op_smin_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SMIN;
        goto fill_minmax_rhs;
    case INDEX_op_umax_vec:
        vector_op.opc = TRACERTL_RV_VECOP_UMAX;
        goto fill_minmax_rhs;
    case INDEX_op_umin_vec:
        vector_op.opc = TRACERTL_RV_VECOP_UMIN;
fill_minmax_rhs:
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        if (rv_arg_is_const(op->args[2])) {
            vector_op.arg2_is_const = true;
            vector_op.arg2_imm = rv_arg_lane_const_value(op->args[2],
                                                         vector_op.vece);
        } else {
            vector_op.rs2 = rv_map_vector_reg_arg(op->args[2], map_arg,
                                                  map_opaque);
        }
        break;
    case INDEX_op_shls_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SHLS;
        goto fill_shift_regs;
    case INDEX_op_shrs_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SHRS;
        goto fill_shift_regs;
    case INDEX_op_sars_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SARS;
fill_shift_regs:
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        vector_op.rs2 = map_arg(op->args[2], map_opaque);
        break;
    case INDEX_op_shlv_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SHLV;
        goto fill_shift_vec;
    case INDEX_op_shrv_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SHRV;
        goto fill_shift_vec;
    case INDEX_op_sarv_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SARV;
fill_shift_vec:
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        vector_op.rs2 = rv_map_vector_reg_arg(op->args[2], map_arg,
                                              map_opaque);
        break;
    case INDEX_op_shli_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SHLI;
        goto fill_shift_imm;
    case INDEX_op_shri_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SHRI;
        goto fill_shift_imm;
    case INDEX_op_sari_vec:
        vector_op.opc = TRACERTL_RV_VECOP_SARI;
fill_shift_imm:
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        vector_op.arg2_is_const = true;
        vector_op.arg2_imm = op->args[2];
        break;
    case INDEX_op_rotli_vec:
        vector_op.opc = TRACERTL_RV_VECOP_ROTLI;
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        vector_op.arg2_is_const = true;
        vector_op.arg2_imm = op->args[2];
        break;
    case INDEX_op_rotls_vec:
        vector_op.opc = TRACERTL_RV_VECOP_ROTLS;
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        vector_op.rs2 = map_arg(op->args[2], map_opaque);
        break;
    case INDEX_op_rotlv_vec:
        vector_op.opc = TRACERTL_RV_VECOP_ROTLV;
        goto fill_rot_vec;
    case INDEX_op_rotrv_vec:
        vector_op.opc = TRACERTL_RV_VECOP_ROTRV;
fill_rot_vec:
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        vector_op.rs2 = rv_map_vector_reg_arg(op->args[2], map_arg,
                                              map_opaque);
        break;
    case INDEX_op_cmp_vec:
        vector_op.opc = TRACERTL_RV_VECOP_CMP;
        vector_op.cond = op->args[3];
        vector_op.rd = rv_map_vector_reg_arg(op->args[0], map_arg, map_opaque);
        vector_op.rs1 = rv_map_vector_reg_arg(op->args[1], map_arg,
                                              map_opaque);
        if (rv_arg_is_const(op->args[2])) {
            vector_op.arg2_is_const = true;
            vector_op.arg2_imm = rv_arg_lane_const_value(op->args[2],
                                                         vector_op.vece);
        } else {
            vector_op.rs2 = rv_map_vector_reg_arg(op->args[2], map_arg,
                                                  map_opaque);
        }
        break;
    default:
        return 0;
    }

    return tracertl_rv_emit_vector_sequence(buf, buf_size, state, &vector_op,
                                            meta);
}
