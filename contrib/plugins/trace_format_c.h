/*
 * C-compatible TraceInstruction format
 *
 * This header provides a C-compatible version of the TraceInstruction struct
 * from /nfs/home/gongkaichen/tracertl/trace_format.h (which is C++).
 *
 * Binary layout contract (48 bytes, little-endian):
 *   <QQQQQI4B>:
 *   instr_pc_va, instr_pc_pa, payload0, payload1, target, instr,
 *   packed(memory_size:4,memory_type:4), branch_type, branch_taken, exception
 *
 * Copyright (c) 2026 Institute of Computing Technology, CAS
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TRACE_FORMAT_C_H
#define TRACE_FORMAT_C_H

#include <stdint.h>

#define TRACE_PADDRBITS 36
#define TRACE_VADDRBITS 39
#define TRACE_FETCH_WIDTH 16

enum TraceMemoryType {
    TRACE_MEM_TYPE_NONE  = 0,
    TRACE_MEM_TYPE_LOAD  = 1,
    TRACE_MEM_TYPE_STORE = 2,
    TRACE_MEM_TYPE_AMO   = 3,
    TRACE_MEM_TYPE_LR    = 4,
    TRACE_MEM_TYPE_SC    = 5
};

struct TraceMemoryAddr {
    uint64_t va;
    uint64_t pa;
};

struct TraceArthiSrc {
    uint64_t src0;
    uint64_t src1;
};

/*
 * TraceInstructionC: C-compatible version of TraceInstruction.
 *
 * Exactly 48 bytes in little-endian field order. The exu_data union
 * overlays MemoryAddr and ArthiSrc at the same offset.
 *
 * When memory_type != TRACE_MEM_TYPE_NONE, exu_data contains memory
 * addresses. Otherwise, it may contain arithmetic source operands
 * (or zeros).
 */
struct TraceInstructionC {
    uint64_t instr_pc_va;
    uint64_t instr_pc_pa;
    union {
        struct TraceMemoryAddr memory_address;
        struct TraceArthiSrc arthi_src;
    } exu_data;
    uint64_t target;
    uint32_t instr;
    uint8_t memory_type_and_size; /* low 4 bits: memory_type, high 4 bits: memory_size */
    uint8_t branch_type;
    uint8_t branch_taken;
    uint8_t exception;
};

/* Verify the struct is exactly 48 bytes */
_Static_assert(sizeof(struct TraceInstructionC) == 48,
               "TraceInstructionC must be exactly 48 bytes");

/* Helper macros for memory_type_and_size field */
static inline uint8_t trace_get_memory_type(const struct TraceInstructionC *t)
{
    return t->memory_type_and_size & 0x0F;
}

static inline uint8_t trace_get_memory_size(const struct TraceInstructionC *t)
{
    return (t->memory_type_and_size >> 4) & 0x0F;
}

static inline void trace_set_memory_type_size(struct TraceInstructionC *t,
                                              uint8_t type, uint8_t size)
{
    t->memory_type_and_size = (size << 4) | (type & 0x0F);
}

/* Initialize a trace record to zeros */
static inline void trace_instruction_init(struct TraceInstructionC *t)
{
    t->instr_pc_va = 0;
    t->instr_pc_pa = 0;
    t->exu_data.memory_address.va = 0;
    t->exu_data.memory_address.pa = 0;
    t->target = 0;
    t->instr = 0;
    t->memory_type_and_size = 0;
    t->branch_type = 0;
    t->branch_taken = 0;
    t->exception = 0;
}

static inline void trace_store_u32_le(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)value;
    dst[1] = (uint8_t)(value >> 8);
    dst[2] = (uint8_t)(value >> 16);
    dst[3] = (uint8_t)(value >> 24);
}

static inline void trace_store_u64_le(uint8_t *dst, uint64_t value)
{
    trace_store_u32_le(dst, (uint32_t)value);
    trace_store_u32_le(dst + 4, (uint32_t)(value >> 32));
}

static inline void trace_instruction_write_le(uint8_t *dst,
                                              const struct TraceInstructionC *t)
{
    trace_store_u64_le(dst + 0, t->instr_pc_va);
    trace_store_u64_le(dst + 8, t->instr_pc_pa);
    trace_store_u64_le(dst + 16, t->exu_data.memory_address.va);
    trace_store_u64_le(dst + 24, t->exu_data.memory_address.pa);
    trace_store_u64_le(dst + 32, t->target);
    trace_store_u32_le(dst + 40, t->instr);
    dst[44] = t->memory_type_and_size;
    dst[45] = t->branch_type;
    dst[46] = t->branch_taken;
    dst[47] = t->exception;
}

#endif /* TRACE_FORMAT_C_H */
