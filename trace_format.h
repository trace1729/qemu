/***************************************************************************************
* Copyright (c) 2020-2023 Institute of Computing Technology, Chinese Academy of Sciences
* Copyright (c) 2020-2021 Peng Cheng Laboratory
*
* DiffTest is licensed under Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*          http://license.coscl.org.cn/MulanPSL2
*
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
* EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
* MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
*
* See the Mulan PSL v2 for more details.
***************************************************************************************/
#ifndef __TRACE_FORMAT_H__
#define __TRACE_FORMAT_H__

#include <cstdint>
#include <stdio.h>

#if defined(__has_include)
# if __has_include("spikedasm.h")
#  include "spikedasm.h"
#  define TRACE_FORMAT_HAVE_SPIKE_DASM 1
# endif
#endif

#ifndef TRACE_FORMAT_HAVE_SPIKE_DASM
static inline const char *spike_dasm(uint64_t) {
  return "?";
}
#endif

#define TraceFetchWidth 16

#define PADDRBITS 36
#define VADDRBITS 39

inline uint64_t paddr_mask() {
  uint64_t mask = (uint64_t) -1;
  return mask >> (64 - PADDRBITS);
};
inline uint64_t vaddr_mask() {
  uint64_t mask = (uint64_t) -1;
  return mask >> (64 - VADDRBITS);
};

enum MemoryType {
  MEM_TYPE_None = 0,
  MEM_TYPE_Load = 1,
  MEM_TYPE_Store = 2,
  MEM_TYPE_AMO = 3,
  MEM_TYPE_LR = 4,
  MEM_TYPE_SC = 5
};

struct MemoryAddr {
  uint64_t va;
  uint64_t pa;
};

// union doest allow non-trivial constructor
struct ArthiSrc {
  uint64_t src0;
  uint64_t src1;
};


// TODO : pack it
// TODO : mv instr and instr_pc to map(or more ca, icache)
//
// Canonical tracertl record contract:
// - Serialized layout is exactly 48 bytes in little-endian field order
//   <QQQQQI4B>:
//   instr_pc_va, instr_pc_pa, payload0, payload1, target, instr,
//   packed(memory_size:4,memory_type:4), branch_type, branch_taken, exception.
// - Traces are stored as ordered streams of these records inside a zstd-compressed
//   artifact. Readers must reject payloads whose decompressed size is not a whole
//   number of TraceInstruction records.
// - Non-exception records require non-zero instr_pc_va and instr.
// - Synchronous exceptions require non-zero instr_pc_va and target.
// - Interrupts require non-zero target.
// - memory_type == MEM_TYPE_None permits dummy arithmetic payload values, but
//   semantic metadata such as branch, memory, and exception fields must remain
//   truthful.
// - Expanded semantic subevents from a single source instruction use deterministic
//   synthetic PCs:
//   base_pc, base_pc + 4, base_pc + 8, ...
//   A straight-line run must not reorder or alias those PCs.
struct TraceInstruction {
  uint64_t instr_pc_va;
  uint64_t instr_pc_pa;
  union {
    MemoryAddr memory_address;
    ArthiSrc arthi_src;
  } exu_data;
  uint64_t target = 0;
  uint32_t instr;
  uint8_t memory_type_and_size;
  uint8_t branch_type;
  uint8_t branch_taken;
  uint8_t exception;

  uint8_t memory_type() const {
    return memory_type_and_size & 0x0f;
  }

  uint8_t memory_size() const {
    return (memory_type_and_size >> 4) & 0x0f;
  }

  void set_memory_type_size(uint8_t type, uint8_t size) {
    memory_type_and_size = (size << 4) | (type & 0x0f);
  }

  void setToForceJump(uint64_t o_pc, uint64_t o_target) {
    instr_pc_va = o_pc;
    instr_pc_pa = o_pc;
    exu_data.memory_address.pa = 0;
    exu_data.memory_address.va = 0;
    target = o_target;
    instr = 0;
    set_memory_type_size(0, 0);
    branch_taken = 0;
    branch_type = 0;
    exception = 0x81;
  }

  bool pc_va_match(uint64_t pc_va) {
    return (instr_pc_va & vaddr_mask()) == (pc_va & vaddr_mask());
  }
  bool pc_pa_match(uint64_t pc_pa) {
    return (instr_pc_pa & paddr_mask()) == (pc_pa & paddr_mask());
  }

  bool legalInst() {
    // when not exception, pc_va and inst should not be zero (when pc_pa is zero, vm not enable)
    if (exception == 0) return (instr_pc_va != 0) && (instr != 0);
    // when interrupt, target should not be zero
    else if (isInterrupt()) return target != 0;
    // when synchronous exception, pc_va & target should not be zero
    return (instr_pc_va != 0) && (target != 0);
  }

  bool isCtrlForceJump() {
    return exception != 0;
  }

  bool isTrap() {
    return (exception != 0);
  }

  bool isInterrupt() {
    return (exception != 0) && ((exception & 0x80) != 0);
  }

  bool isException() {
    return (exception != 0) && ((exception & 0x80) == 0);
  }

  bool isInstException() {
    uint8_t exceptionCode = (exception & 0x7f);
    bool instException = (exceptionCode == 0) || (exceptionCode == 1) || (exceptionCode == 2) || (exceptionCode == 12);
    return isException() && instException;
  }

  void dump() {
    // printf("Instr: TraceSize %ld memSize %02x PC 0x%016lx instr 0x%04x memAddr 0x%016lx\n", sizeof(TraceInstruction), memory_size, instr_pc, instr, memory_address);
    printf("PC 0x%08lx|%08lx instr 0x%08x(%s)", instr_pc_va, instr_pc_pa, instr, spike_dasm(instr));
    if (memory_type() != MEM_TYPE_None) {
      printf(" is_mem %d addr %08lx|%08lx", memory_type(), exu_data.memory_address.va, exu_data.memory_address.pa);
    } else {
      printf(" arthi(for fp/div) src0 %016lx src1 %016lx", exu_data.arthi_src.src0, exu_data.arthi_src.src1);
    }
    if (branch_type != 0) {
      printf(" is_branch %d taken %d target 0x%08lx", branch_type, branch_taken, target);
    }
    if (exception != 0) {
      printf(" is_exception 0x%02x target 0x%08lx", exception, target);
    }
    printf("\n");
    fflush(stdout);
  }
};

struct Instruction : TraceInstruction {
  // TraceInstruction static_inst;
  uint64_t inst_id;
  // currently, only used for fast warmup
  uint8_t fast_simulation = 0;
  bool is_squashed = false;

  void dump() {
    printf("[0x%08lx]: fs %d sq %d ", inst_id, fast_simulation, is_squashed);
    TraceInstruction::dump();
    fflush(stdout);
  }

  inline void fromTraceInst(TraceInstruction t) {
    instr_pc_va = t.instr_pc_va;
    instr_pc_pa = (t.instr_pc_pa != 0) ? t.instr_pc_pa : t.instr_pc_va;
    exu_data.memory_address.va = t.exu_data.memory_address.va;
    exu_data.memory_address.pa = (t.exu_data.memory_address.pa != 0) ? t.exu_data.memory_address.pa : t.exu_data.memory_address.va;
    target = t.target;
    instr = t.instr;
    set_memory_type_size(t.memory_type(), t.memory_size());
    branch_type = t.branch_type;
    branch_taken = t.branch_taken;
    exception = t.exception;
  }

  inline void setFastWarmup() {
    fast_simulation = 1;
  }

  bool legalInst() {
    if (inst_id == 0) {
      return false;
    }
    return TraceInstruction::legalInst();
  }
};

struct ManyInstruction_t {
  Instruction insts[TraceFetchWidth]; // 16 is traceFetchWidth
};

static_assert(sizeof(TraceInstruction) == 48,
              "TraceInstruction must stay 48 bytes");

struct Control {
  uint8_t type;
  uint8_t data;
  // TODO: placeholder, not implemented
};

struct TraceCollectInstruction {
  uint64_t instr_pc;
  uint32_t instr;
  uint8_t instNum;
  uint64_t instID;

  void dump() {
    if (instNum == 1 || instNum == 0) {
        printf("[0x%08lx]: PC 0x%08lx instr 0x%08x(%s)\n", instID, instr_pc, instr, spike_dasm(instr));
    } else {
        printf("[0x%08lx]: PC 0x%08lx instr 0x%08x(%s) Merge %d\n", instID, instr_pc, instr, spike_dasm(instr), instNum);
    }
  }
};

#endif
