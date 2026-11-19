#ifndef TRACERTL_RUNTIME_HELPERS_H
#define TRACERTL_RUNTIME_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "contrib/plugins/trace_format_c.h"

bool tracertl_rv_buf_grow(size_t *buf_size);
uint32_t tracertl_guest_semantic_stub_insn(const uint8_t *bytes,
                                           size_t len,
                                           bool is_x86_guest,
                                           bool is_aarch64_guest,
                                           uint8_t guest_branch_type,
                                           uint8_t guest_exception_code,
                                           bool *designate_mem_slot);
uint8_t tracertl_riscv_mem_type(uint32_t insn, uint8_t fallback_type);
void tracertl_init_overflow_memory_record(struct TraceInstructionC *dst,
                                          const struct TraceInstructionC *template_rec,
                                          uint8_t mtype,
                                          uint8_t msize,
                                          uint64_t vaddr,
                                          uint64_t paddr);
void tracertl_finalize_branch(struct TraceInstructionC *pending_recs,
                              int n_pending, int branch_rec_idx,
                              uint64_t expected_next,
                              uint64_t actual_next_pc,
                              uint64_t actual_next_trace_pc,
                              uint64_t resolved_branch_target);
void tracertl_finalize_branch_without_successor(
    struct TraceInstructionC *pending_recs,
    int n_pending, int branch_rec_idx,
    uint64_t expected_next,
    uint64_t terminal_target);
bool tracertl_resolve_riscv_conditional_branch_target(uint64_t pc,
                                                      uint32_t insn,
                                                      uint64_t *target);

#endif
