/*
 * TCGOp → RISC-V Emission Engine for Trace Collection
 *
 * This module reuses QEMU's RISC-V TCG backend encoding functions to emit
 * RISC-V instruction encodings from TCGOps, regardless of the guest ISA.
 * The emitted RISC-V instructions are collected into trace records instead
 * of being executed.
 *
 * Key components:
 * - Minimal TCGContext shim (only fields needed by encoding functions)
 * - RISC-V encoding function imports from tcg/riscv/tcg-target.c.inc
 * - TCGOp→RISC-V emission loop
 *
 * Copyright (c) 2026 Institute of Computing Technology, CAS
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TCG_RISCV_EMIT_H
#define TCG_RISCV_EMIT_H

#include <stdint.h>
#include <stdbool.h>

/* Maximum RISC-V instructions that can result from one guest instruction */
#define MAX_RISCV_INSNS_PER_GUEST 32

/*
 * Minimal TCGContext shim for RISC-V emission.
 *
 * The RISC-V encoding functions (encode_r, encode_i, etc.) are stateless,
 * but the emission functions (tcg_out_opc_reg, etc.) call tcg_out32(s, v)
 * which writes to s->code_ptr.
 *
 * We provide a minimal shim with just the fields needed:
 * - code_ptr: write pointer into our trace buffer
 * - riscv_cur_vsew / riscv_cur_type: for vector instruction state
 */
typedef uint32_t tcg_insn_unit;

typedef struct {
    tcg_insn_unit *code_ptr;       /* Write pointer for emitted RISC-V insns */
    uint8_t riscv_cur_vsew;         /* Current vector element width (for V ext) */
    uint8_t riscv_cur_type;         /* Current TCG type (for V ext) */
} TCGContextShim;

/*
 * Initialize a TCGContext shim with a buffer to collect RISC-V encodings.
 */
static inline void tcg_context_shim_init(TCGContextShim *ctx, tcg_insn_unit *buf)
{
    ctx->code_ptr = buf;
    ctx->riscv_cur_vsew = 0;  /* Default: no vector state */
    ctx->riscv_cur_type = 0;
}

/*
 * Get the number of RISC-V instructions emitted into the buffer.
 */
static inline int tcg_context_shim_count(TCGContextShim *ctx, tcg_insn_unit *buf)
{
    return (int)(ctx->code_ptr - buf);
}

/*
 * tcg_out32: Write a 32-bit RISC-V instruction to the buffer.
 * This is the interface expected by tcg_out_opc_* functions.
 */
static inline void tcg_out32(TCGContextShim *s, uint32_t v)
{
    *s->code_ptr++ = v;
}

/*
 * Import RISC-V register and opcode definitions.
 * These are used by the encoding functions from tcg/riscv/tcg-target.c.inc.
 */

/* RISC-V register numbers (ABI names) */
typedef enum {
    TCG_REG_ZERO = 0,
    TCG_REG_RA   = 1,
    TCG_REG_SP   = 2,
    TCG_REG_GP   = 3,
    TCG_REG_TP   = 4,
    TCG_REG_T0   = 5,
    TCG_REG_T1   = 6,
    TCG_REG_T2   = 7,
    TCG_REG_S0   = 8,   /* FP */
    TCG_REG_S1   = 9,
    TCG_REG_A0   = 10,
    TCG_REG_A1   = 11,
    TCG_REG_A2   = 12,
    TCG_REG_A3   = 13,
    TCG_REG_A4   = 14,
    TCG_REG_A5   = 15,
    TCG_REG_A6   = 16,
    TCG_REG_A7   = 17,
    TCG_REG_S2   = 18,
    TCG_REG_S3   = 19,
    TCG_REG_S4   = 20,
    TCG_REG_S5   = 21,
    TCG_REG_S6   = 22,
    TCG_REG_S7   = 23,
    TCG_REG_S8   = 24,
    TCG_REG_S9   = 25,
    TCG_REG_S10  = 26,
    TCG_REG_S11  = 27,
    TCG_REG_T3   = 28,
    TCG_REG_T4   = 29,
    TCG_REG_T5   = 30,
    TCG_REG_T6   = 31
} TCGReg;

/* RISC-V instruction opcodes (from tcg/riscv/tcg-target.c.inc) */
typedef enum {
    OPC_ADD   = 0x33,
    OPC_ADDI  = 0x13,
    OPC_AND   = 0x7033,
    OPC_ANDI  = 0x7013,
    OPC_AUIPC = 0x17,
    OPC_BEQ   = 0x63,
    OPC_BGE   = 0x5063,
    OPC_BGEU  = 0x7063,
    OPC_BLT   = 0x4063,
    OPC_BLTU  = 0x6063,
    OPC_BNE   = 0x1063,
    OPC_DIV   = 0x2004033,
    OPC_DIVU  = 0x2005033,
    OPC_JAL   = 0x6f,
    OPC_JALR  = 0x67,
    OPC_LB    = 0x3,
    OPC_LBU   = 0x4003,
    OPC_LD    = 0x3003,
    OPC_LH    = 0x1003,
    OPC_LHU   = 0x5003,
    OPC_LUI   = 0x37,
    OPC_LW    = 0x2003,
    OPC_LWU   = 0x6003,
    OPC_MUL   = 0x2000033,
    OPC_MULH  = 0x2001033,
    OPC_MULHSU = 0x2002033,
    OPC_MULHU = 0x2003033,
    OPC_OR    = 0x6033,
    OPC_ORI   = 0x6013,
    OPC_REM   = 0x2006033,
    OPC_REMU  = 0x2007033,
    OPC_SB    = 0x23,
    OPC_SD    = 0x3023,
    OPC_SH    = 0x1023,
    OPC_SLL   = 0x1033,
    OPC_SLLI  = 0x1013,
    OPC_SLT   = 0x2033,
    OPC_SLTI  = 0x2013,
    OPC_SLTIU = 0x3013,
    OPC_SLTU  = 0x3033,
    OPC_SRA   = 0x40005033,
    OPC_SRAI  = 0x40005013,
    OPC_SRL   = 0x5033,
    OPC_SRLI  = 0x5013,
    OPC_SUB   = 0x40000033,
    OPC_SW    = 0x2023,
    OPC_XOR   = 0x4033,
    OPC_XORI  = 0x4013,
    OPC_NOP   = OPC_ADDI,  /* nop = addi x0, x0, 0 */

    /* RV64I */
    OPC_ADDIW = 0x1b,
    OPC_ADDW  = 0x3b,
    OPC_DIVUW = 0x200503b,
    OPC_DIVW  = 0x200403b,
    OPC_MULW  = 0x200003b,
    OPC_REMUW = 0x200703b,
    OPC_REMW  = 0x200603b,
    OPC_SLLIW = 0x101b,
    OPC_SLLW  = 0x103b,
    OPC_SRAIW = 0x4000501b,
    OPC_SRAW  = 0x4000503b,
    OPC_SRLIW = 0x501b,
    OPC_SRLW  = 0x503b,
    OPC_SUBW  = 0x4000003b
} RISCVInsn;

/*
 * RISC-V encoding functions (stateless, pure).
 * These are copy-pasted from tcg/riscv/tcg-target.c.inc for use in the plugin.
 */

/* Type-R: register-register ops */
static inline int32_t encode_r(RISCVInsn opc, TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    return opc | (rd & 0x1f) << 7 | (rs1 & 0x1f) << 15 | (rs2 & 0x1f) << 20;
}

/* Type-I: immediate ops */
static inline int32_t encode_imm12(uint32_t imm)
{
    return (imm & 0xfff) << 20;
}

static inline int32_t encode_i(RISCVInsn opc, TCGReg rd, TCGReg rs1, uint32_t imm)
{
    return opc | (rd & 0x1f) << 7 | (rs1 & 0x1f) << 15 | encode_imm12(imm);
}

/* Type-S: store ops */
static inline int32_t encode_simm12(uint32_t imm)
{
    int32_t ret = 0;
    ret |= (imm & 0xFE0) << 20;
    ret |= (imm & 0x1F) << 7;
    return ret;
}

static inline int32_t encode_s(RISCVInsn opc, TCGReg rs1, TCGReg rs2, uint32_t imm)
{
    return opc | (rs1 & 0x1f) << 15 | (rs2 & 0x1f) << 20 | encode_simm12(imm);
}

/* Type-SB: branch ops */
static inline int32_t encode_sbimm12(uint32_t imm)
{
    int32_t ret = 0;
    ret |= (imm & 0x1000) << 19;
    ret |= (imm & 0x7e0) << 20;
    ret |= (imm & 0x1e) << 7;
    ret |= (imm & 0x800) >> 4;
    return ret;
}

static inline int32_t encode_sb(RISCVInsn opc, TCGReg rs1, TCGReg rs2, uint32_t imm)
{
    return opc | (rs1 & 0x1f) << 15 | (rs2 & 0x1f) << 20 | encode_sbimm12(imm);
}

/* Type-U: upper immediate ops */
static inline int32_t encode_uimm20(uint32_t imm)
{
    return imm & 0xfffff000;
}

static inline int32_t encode_u(RISCVInsn opc, TCGReg rd, uint32_t imm)
{
    return opc | (rd & 0x1f) << 7 | encode_uimm20(imm);
}

/* Type-UJ: jump ops */
static inline int32_t encode_ujimm20(uint32_t imm)
{
    int32_t ret = 0;
    ret |= (imm & 0x0007fe) << (21 - 1);
    ret |= (imm & 0x000800) << (20 - 11);
    ret |= (imm & 0x0ff000) << (12 - 12);
    ret |= (imm & 0x100000) << (31 - 20);
    return ret;
}

static inline int32_t encode_uj(RISCVInsn opc, TCGReg rd, uint32_t imm)
{
    return opc | (rd & 0x1f) << 7 | encode_ujimm20(imm);
}

/*
 * High-level emission functions (tcg_out_opc_*).
 * These wrap the encoding functions and write to the shim's buffer.
 */

static inline void tcg_out_opc_reg(TCGContextShim *s, RISCVInsn opc,
                                   TCGReg rd, TCGReg rs1, TCGReg rs2)
{
    tcg_out32(s, encode_r(opc, rd, rs1, rs2));
}

static inline void tcg_out_opc_imm(TCGContextShim *s, RISCVInsn opc,
                                   TCGReg rd, TCGReg rs1, uint32_t imm)
{
    tcg_out32(s, encode_i(opc, rd, rs1, imm));
}

static inline void tcg_out_opc_store(TCGContextShim *s, RISCVInsn opc,
                                     TCGReg rs1, TCGReg rs2, uint32_t imm)
{
    tcg_out32(s, encode_s(opc, rs1, rs2, imm));
}

static inline void tcg_out_opc_branch(TCGContextShim *s, RISCVInsn opc,
                                      TCGReg rs1, TCGReg rs2, uint32_t imm)
{
    tcg_out32(s, encode_sb(opc, rs1, rs2, imm));
}

static inline void tcg_out_opc_upper(TCGContextShim *s, RISCVInsn opc,
                                     TCGReg rd, uint32_t imm)
{
    tcg_out32(s, encode_u(opc, rd, imm));
}

static inline void tcg_out_opc_jump(TCGContextShim *s, RISCVInsn opc,
                                    TCGReg rd, uint32_t imm)
{
    tcg_out32(s, encode_uj(opc, rd, imm));
}

#endif /* TCG_RISCV_EMIT_H */
