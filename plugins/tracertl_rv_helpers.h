#ifndef TRACERTL_RV_HELPERS_H
#define TRACERTL_RV_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "qemu/plugin.h"
#include "tcg/tcg-cond.h"

enum {
    TRACERTL_RV_OPC_ADD   = 0x33,
    TRACERTL_RV_OPC_SUB   = 0x40000033U,
    TRACERTL_RV_OPC_ADDI  = 0x13,
    TRACERTL_RV_OPC_ADDW  = 0x3b,
    TRACERTL_RV_OPC_SUBW  = 0x4000003bU,
    TRACERTL_RV_OPC_ADDIW = 0x1b,
    TRACERTL_RV_OPC_SLTU  = 0x3033,
    TRACERTL_RV_OPC_VSETVLI = 0x7057,
    TRACERTL_RV_OPC_VMERGE_VIM = 0x5c003057,
    TRACERTL_RV_OPC_VLE8_V = 0x7,
    TRACERTL_RV_OPC_VLE16_V = 0x5007,
    TRACERTL_RV_OPC_VLE32_V = 0x6007,
    TRACERTL_RV_OPC_VLE64_V = 0x7007,
    TRACERTL_RV_OPC_VSE8_V = 0x27,
    TRACERTL_RV_OPC_VSE16_V = 0x5027,
    TRACERTL_RV_OPC_VSE32_V = 0x6027,
    TRACERTL_RV_OPC_VSE64_V = 0x7027,
    TRACERTL_RV_OPC_VADD_VV = 0x57,
    TRACERTL_RV_OPC_VADD_VI = 0x3057,
    TRACERTL_RV_OPC_VSUB_VV = 0x8000057,
    TRACERTL_RV_OPC_VRSUB_VI = 0xc000057,
    TRACERTL_RV_OPC_VAND_VV = 0x24000057,
    TRACERTL_RV_OPC_VAND_VI = 0x24003057,
    TRACERTL_RV_OPC_VOR_VV = 0x28000057,
    TRACERTL_RV_OPC_VOR_VI = 0x28003057,
    TRACERTL_RV_OPC_VXOR_VV = 0x2c000057,
    TRACERTL_RV_OPC_VXOR_VI = 0x2c003057,
    TRACERTL_RV_OPC_VMUL_VV = 0x94002057,
    TRACERTL_RV_OPC_VMAX_VV = 0x1c000057,
    TRACERTL_RV_OPC_VMAX_VI = 0x1c003057,
    TRACERTL_RV_OPC_VMAXU_VV = 0x18000057,
    TRACERTL_RV_OPC_VMAXU_VI = 0x18003057,
    TRACERTL_RV_OPC_VMIN_VV = 0x14000057,
    TRACERTL_RV_OPC_VMIN_VI = 0x14003057,
    TRACERTL_RV_OPC_VMINU_VV = 0x10000057,
    TRACERTL_RV_OPC_VMINU_VI = 0x10003057,
    TRACERTL_RV_OPC_VSLL_VV = 0x94000057,
    TRACERTL_RV_OPC_VSLL_VI = 0x94003057,
    TRACERTL_RV_OPC_VSLL_VX = 0x94004057,
    TRACERTL_RV_OPC_VSRL_VV = 0xa0000057,
    TRACERTL_RV_OPC_VSRL_VI = 0xa0003057,
    TRACERTL_RV_OPC_VSRL_VX = 0xa0004057,
    TRACERTL_RV_OPC_VSRA_VV = 0xa4000057,
    TRACERTL_RV_OPC_VSRA_VI = 0xa4003057,
    TRACERTL_RV_OPC_VSRA_VX = 0xa4004057,
    TRACERTL_RV_OPC_VMV_V_I = 0x5e003057,
    TRACERTL_RV_OPC_VMV_V_X = 0x5e004057,
    TRACERTL_RV_OPC_VMSEQ_VV = 0x60000057,
    TRACERTL_RV_OPC_VMSEQ_VI = 0x60003057,
    TRACERTL_RV_OPC_VMSEQ_VX = 0x60004057,
    TRACERTL_RV_OPC_VMSNE_VV = 0x64000057,
    TRACERTL_RV_OPC_VMSNE_VI = 0x64003057,
    TRACERTL_RV_OPC_VMSNE_VX = 0x64004057,
    TRACERTL_RV_OPC_VMSLTU_VV = 0x68000057,
    TRACERTL_RV_OPC_VMSLTU_VX = 0x68004057,
    TRACERTL_RV_OPC_VMSLT_VV = 0x6c000057,
    TRACERTL_RV_OPC_VMSLT_VX = 0x6c004057,
    TRACERTL_RV_OPC_VMSLEU_VV = 0x70000057,
    TRACERTL_RV_OPC_VMSLEU_VI = 0x70003057,
    TRACERTL_RV_OPC_VMSLEU_VX = 0x70004057,
    TRACERTL_RV_OPC_VMSLE_VV = 0x74000057,
    TRACERTL_RV_OPC_VMSLE_VI = 0x74003057,
    TRACERTL_RV_OPC_VMSLE_VX = 0x74004057,
    TRACERTL_RV_OPC_VMSGTU_VI = 0x78003057,
    TRACERTL_RV_OPC_VMSGTU_VX = 0x78004057,
    TRACERTL_RV_OPC_VMSGT_VI = 0x7c003057,
    TRACERTL_RV_OPC_VMSGT_VX = 0x7c004057,
};

#define TRACERTL_RV_SCRATCH_REG 1
#define TRACERTL_RV_ALT_SCRATCH_REG 30
#define TRACERTL_RV_CARRY_REG 31
#define TRACERTL_RV_V0_REG 32
#define TRACERTL_RV_V1_REG 33

typedef enum TracertlRvCarryOp {
    TRACERTL_RV_CARRY_ADDCO,
    TRACERTL_RV_CARRY_ADDC1O,
    TRACERTL_RV_CARRY_ADDCI,
    TRACERTL_RV_CARRY_ADDCIO,
    TRACERTL_RV_CARRY_SUBBO,
    TRACERTL_RV_CARRY_SUBB1O,
    TRACERTL_RV_CARRY_SUBBI,
    TRACERTL_RV_CARRY_SUBBIO,
} TracertlRvCarryOp;

typedef struct TracertlRvOperand {
    bool is_const;
    int reg;
    int64_t imm;
} TracertlRvOperand;

typedef enum TracertlRvVectorOpcode {
    TRACERTL_RV_VECOP_LD,
    TRACERTL_RV_VECOP_ST,
    TRACERTL_RV_VECOP_DUPM,
    TRACERTL_RV_VECOP_ADD,
    TRACERTL_RV_VECOP_SUB,
    TRACERTL_RV_VECOP_MUL,
    TRACERTL_RV_VECOP_NEG,
    TRACERTL_RV_VECOP_AND,
    TRACERTL_RV_VECOP_ANDC,
    TRACERTL_RV_VECOP_OR,
    TRACERTL_RV_VECOP_XOR,
    TRACERTL_RV_VECOP_NOT,
    TRACERTL_RV_VECOP_SMAX,
    TRACERTL_RV_VECOP_SMIN,
    TRACERTL_RV_VECOP_UMAX,
    TRACERTL_RV_VECOP_UMIN,
    TRACERTL_RV_VECOP_SHLS,
    TRACERTL_RV_VECOP_SHRS,
    TRACERTL_RV_VECOP_SARS,
    TRACERTL_RV_VECOP_SHLV,
    TRACERTL_RV_VECOP_SHRV,
    TRACERTL_RV_VECOP_SARV,
    TRACERTL_RV_VECOP_SHLI,
    TRACERTL_RV_VECOP_SHRI,
    TRACERTL_RV_VECOP_SARI,
    TRACERTL_RV_VECOP_ROTLI,
    TRACERTL_RV_VECOP_ROTLS,
    TRACERTL_RV_VECOP_ROTLV,
    TRACERTL_RV_VECOP_ROTRV,
    TRACERTL_RV_VECOP_CMP,
} TracertlRvVectorOpcode;

typedef struct TracertlRvVectorState {
    bool have_vtype;
    unsigned int cur_vtype_type;
    unsigned int cur_vtype_vsew;
} TracertlRvVectorState;

typedef struct TracertlRvVectorOp {
    TracertlRvVectorOpcode opc;
    unsigned int type;
    unsigned int vece;
    int rd;
    int rs1;
    int rs2;
    bool arg1_is_const;
    int64_t arg1_imm;
    bool arg2_is_const;
    int64_t arg2_imm;
    TCGCond cond;
} TracertlRvVectorOp;

typedef struct TracertlRvVectorEmitMeta {
    bool note_mem_slot;
    int mem_slot_rel_idx;
} TracertlRvVectorEmitMeta;

#define TRACERTL_RV_GUEST_SEM_MAX_INSNS 2
#define TRACERTL_RV_GUEST_SEM_MAX_MEM   1

typedef enum TracertlRvGuestSemanticKind {
    TRACERTL_RV_GUEST_SEM_DEFAULT = 0,
    TRACERTL_RV_GUEST_SEM_TRAP,
    TRACERTL_RV_GUEST_SEM_SERIALIZE,
    TRACERTL_RV_GUEST_SEM_FP_COMPARE,
    TRACERTL_RV_GUEST_SEM_VECTOR_UNPACK,
    TRACERTL_RV_GUEST_SEM_SHIFT,
    TRACERTL_RV_GUEST_SEM_FP_DIV,
    TRACERTL_RV_GUEST_SEM_CONVERT,
    TRACERTL_RV_GUEST_SEM_DIV_UNSIGNED,
    TRACERTL_RV_GUEST_SEM_DIV_SIGNED,
    TRACERTL_RV_GUEST_SEM_X87_STORE,
} TracertlRvGuestSemanticKind;

typedef enum TracertlRvTranslatedX86EmitKind {
    TRACERTL_RV_TRANSLATED_X86_EMIT_NONE = 0,
    TRACERTL_RV_TRANSLATED_X86_EMIT_TRAP,
    TRACERTL_RV_TRANSLATED_X86_EMIT_SERIALIZE,
    TRACERTL_RV_TRANSLATED_X86_EMIT_SUB,
    TRACERTL_RV_TRANSLATED_X86_EMIT_OR,
    TRACERTL_RV_TRANSLATED_X86_EMIT_SRL,
    TRACERTL_RV_TRANSLATED_X86_EMIT_DIV,
    TRACERTL_RV_TRANSLATED_X86_EMIT_DIVU,
    TRACERTL_RV_TRANSLATED_X86_EMIT_STORE,
} TracertlRvTranslatedX86EmitKind;

typedef enum TracertlRvTranslatedX86DecodeStatus {
    TRACERTL_RV_TRANSLATED_X86_DECODE_UNSUPPORTED = 0,
    TRACERTL_RV_TRANSLATED_X86_DECODE_SUPPORTED,
    TRACERTL_RV_TRANSLATED_X86_DECODE_RESIDUAL_UNSUPPORTED,
} TracertlRvTranslatedX86DecodeStatus;

typedef struct TracertlRvTranslatedX86Spec {
    TracertlRvGuestSemanticKind semantic_kind;
    TracertlRvTranslatedX86EmitKind emit_kind;
    bool has_mem_operand;
    uint8_t mem_type;
    uint8_t mem_size;
    bool helper_exception;
    const char *counter_name;
} TracertlRvTranslatedX86Spec;

typedef struct TracertlRvGuestSemanticPlan {
    uint8_t n_insns;
    uint32_t insns[TRACERTL_RV_GUEST_SEM_MAX_INSNS];
    int8_t n_mem;
    int8_t mem_idxs[TRACERTL_RV_GUEST_SEM_MAX_MEM];
    uint8_t mem_size;
    int8_t branch_idx;
    TracertlRvGuestSemanticKind kind;
    bool helper_exception;
    const char *counter_name;
} TracertlRvGuestSemanticPlan;

typedef struct TracertlRvCoreTraceSink {
    uint32_t *buf;
    uint8_t *tags;
    uint8_t *origins;
    int *pos;
    int buf_size;
    qemu_plugin_rv_insn_meta *meta;
    int insn_offset;
    bool *guest_has_branch;
} TracertlRvCoreTraceSink;

uint32_t tracertl_rv_encode_r(uint32_t opc, int rd, int rs1, int rs2);
uint32_t tracertl_rv_encode_i(uint32_t opc, int rd, int rs1, uint32_t imm);
uint32_t tracertl_rv_encode_v(uint32_t opc, int vd, int vs1, int vs2);
uint32_t tracertl_rv_encode_vi(uint32_t opc, int vd, int32_t imm, int vs2);
int tracertl_rv_temp_to_reg(unsigned int a);
int tracertl_rv_temp_to_vreg(unsigned int a);
bool tracertl_rv_imm12_p(int64_t imm);
int tracertl_rv_emit_vsetvli(uint32_t *buf, int buf_size,
                             unsigned int type, unsigned int vece);
uint32_t tracertl_rv_vector_ld_opc(unsigned int vece);
uint32_t tracertl_rv_vector_st_opc(unsigned int vece);
int tracertl_rv_emit_load_imm_sequence(uint32_t *buf, int buf_size,
                                       int rd, uint64_t imm);
int tracertl_rv_cmp_operand_reg(TracertlRvOperand op);
int tracertl_rv_emit_cmp_operand_sequence(uint32_t *buf, int buf_size,
                                          TracertlRvOperand op,
                                          int scratch_reg, int *reg_out);
int tracertl_rv_emit_move_sequence(uint32_t *buf, int buf_size,
                                   int rd, TracertlRvOperand src);
int tracertl_rv_emit_add_sequence(uint32_t *buf, int buf_size,
                                  bool is_32bit, int rd,
                                  TracertlRvOperand lhs,
                                  TracertlRvOperand rhs);
int tracertl_rv_emit_deposit_sequence(uint32_t *buf, int buf_size,
                                      int rd,
                                      TracertlRvOperand base,
                                      TracertlRvOperand insert,
                                      uint32_t ofs, uint32_t len,
                                      int mask_reg, int tmp_reg);
int tracertl_rv_emit_carry_sequence(uint32_t *buf, int buf_size,
                                    TracertlRvCarryOp op, bool is_32bit,
                                    int rd, int rs1, int rs2);
int tracertl_rv_emit_rotate_sequence(uint32_t *buf, int buf_size,
                                     bool is_32bit, bool is_left,
                                     int rd, int rs, int sh);
int tracertl_rv_emit_extract_sequence(uint32_t *buf, int buf_size,
                                      bool is_32bit, bool sign_extend,
                                      int rd, int rs,
                                      uint32_t ofs, uint32_t len);
int tracertl_rv_emit_extract2_sequence(uint32_t *buf, int buf_size,
                                       bool is_32bit,
                                       int rd, int al, int ah,
                                       uint32_t ofs);
int tracertl_rv_emit_bswap_sequence(uint32_t *buf, int buf_size,
                                    unsigned bits,
                                    int rd, int rs,
                                    unsigned flags);
int tracertl_rv_emit_vector_sequence(uint32_t *buf, int buf_size,
                                     TracertlRvVectorState *state,
                                     const TracertlRvVectorOp *op,
                                     TracertlRvVectorEmitMeta *meta);
void tracertl_rv_guest_semantic_plan_default(
    TracertlRvGuestSemanticPlan *plan);
TracertlRvTranslatedX86DecodeStatus tracertl_rv_decode_translated_x86(
    const uint8_t *bytes, size_t len,
    bool is_system_emulation,
    TracertlRvTranslatedX86Spec *spec);
void tracertl_rv_build_guest_semantic_plan(
    const uint8_t *bytes, size_t len,
    bool is_x86_guest,
    bool is_aarch64_guest,
    bool is_system_emulation,
    TracertlRvGuestSemanticPlan *plan);
uint32_t tracertl_rv_guest_semantic_fallback_insn(
    const TracertlRvGuestSemanticPlan *plan);
void tracertl_rv_core_trace_meta_reset(qemu_plugin_rv_insn_meta *meta);
void tracertl_rv_core_emit_lookup_tb_ptr(TracertlRvCoreTraceSink *sink,
                                         int target_reg);
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
    int *filtered_total_insns);

#endif
