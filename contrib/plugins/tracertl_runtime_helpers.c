#include "qemu/osdep.h"
#include "contrib/plugins/trace_format_c.h"
#include "contrib/plugins/tracertl_runtime_helpers.h"
#include "plugins/tracertl_rv_helpers.h"

#define RV_OPCODE(insn) ((insn) & 0x7f)

static bool rv_is_amo(uint32_t insn)
{
    return RV_OPCODE(insn) == 0x2f;
}

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

static int64_t tracertl_sign_extend_u64(uint64_t value, unsigned int bits)
{
    return (int64_t)(value << (64 - bits)) >> (64 - bits);
}

bool tracertl_rv_buf_grow(size_t *buf_size)
{
    g_assert(buf_size != NULL);

    if (*buf_size > INT_MAX / 2) {
        return false;
    }

    *buf_size = MAX(*buf_size * 2, (size_t)64);
    return true;
}

uint32_t tracertl_guest_conditional_branch_placeholder(bool branch_taken)
{
    return branch_taken ? 0x00000063U  /* beq x0, x0, 0 */
                        : 0x00001063U; /* bne x0, x0, 0 */
}

uint32_t tracertl_guest_non_branch_placeholder(void)
{
    return 0x01e080b3U; /* add x1, x1, x30 */
}

bool tracertl_demote_branch_if_sequential(struct TraceInstructionC *branch_rec,
                                          uint64_t sequential_target)
{
    g_assert(branch_rec != NULL);

    if (branch_rec->branch_type == 0 ||
        branch_rec->branch_taken == 0 ||
        branch_rec->target == 0 ||
        branch_rec->target != sequential_target) {
        return false;
    }

    branch_rec->instr = tracertl_guest_non_branch_placeholder();
    branch_rec->branch_type = 0;
    branch_rec->branch_taken = 0;
    branch_rec->target = 0;
    return true;
}

bool tracertl_rv_encode_branch_to_target(uint64_t pc, uint64_t target,
                                         bool branch_taken,
                                         uint32_t *insn)
{
    int64_t delta;
    uint32_t imm;
    uint32_t funct3;

    g_assert(insn != NULL);

    delta = (int64_t)(target - pc);
    if ((delta & 1) != 0 || delta < -4096 || delta > 4094) {
        return false;
    }

    imm = (uint32_t)delta & 0x1fffU;
    funct3 = branch_taken ? 0x0U : 0x1U; /* beq/bne x0, x0 */
    *insn = ((imm >> 12) & 0x1U) << 31 |
            ((imm >> 5) & 0x3fU) << 25 |
            funct3 << 12 |
            ((imm >> 1) & 0xfU) << 8 |
            ((imm >> 11) & 0x1U) << 7 |
            0x63U;
    return true;
}

bool tracertl_rv_encode_jal_to_target(uint64_t pc, uint64_t target,
                                      uint32_t *insn)
{
    int64_t delta;
    uint32_t imm;

    g_assert(insn != NULL);

    delta = (int64_t)(target - pc);
    if ((delta & 1) != 0 || delta < -(INT64_C(1) << 20) ||
        delta > ((INT64_C(1) << 20) - 2)) {
        return false;
    }

    imm = (uint32_t)delta & 0x1fffffU;
    *insn = ((imm >> 20) & 0x1U) << 31 |
            ((imm >> 1) & 0x3ffU) << 21 |
            ((imm >> 11) & 0x1U) << 20 |
            ((imm >> 12) & 0xffU) << 12 |
            0x6fU; /* jal x0, imm */
    return true;
}

uint32_t tracertl_guest_semantic_stub_insn(const uint8_t *bytes,
                                           size_t len,
                                           bool is_x86_guest,
                                           bool is_aarch64_guest,
                                           uint8_t guest_branch_type,
                                           uint8_t guest_exception_code,
                                           bool *designate_mem_slot)
{
    TracertlRvGuestSemanticPlan plan;
    bool mem_slot = false;

    if (designate_mem_slot == NULL) {
        designate_mem_slot = &mem_slot;
    }
    *designate_mem_slot = false;

    if (guest_exception_code != 0) {
        return 0x00000073U;
    }

    switch (guest_branch_type) {
    case 1:
        return tracertl_guest_conditional_branch_placeholder(true);
    case 2:
        return 0x0000006fU;
    case 3:
        return 0x00000067U;
    default:
        break;
    }

    tracertl_rv_build_guest_semantic_plan(bytes, len,
                                          is_x86_guest,
                                          is_aarch64_guest,
                                          false,
                                          &plan);
    *designate_mem_slot = plan.n_mem > 0;
    return tracertl_rv_guest_semantic_fallback_insn(&plan);
}

uint8_t tracertl_riscv_mem_type(uint32_t insn, uint8_t fallback_type)
{
    if (!rv_is_amo(insn)) {
        return fallback_type;
    }

    switch ((insn >> 27) & 0x1f) {
    case 0x02:
        return TRACE_MEM_TYPE_LR;
    case 0x03:
        return TRACE_MEM_TYPE_SC;
    default:
        return TRACE_MEM_TYPE_AMO;
    }
}

void tracertl_init_overflow_memory_record(struct TraceInstructionC *dst,
                                          const struct TraceInstructionC *template_rec,
                                          uint8_t mtype,
                                          uint8_t msize,
                                          uint64_t vaddr,
                                          uint64_t paddr)
{
    g_assert(dst != NULL);
    g_assert(template_rec != NULL);

    trace_instruction_init(dst);
    dst->instr_pc_va = template_rec->instr_pc_va;
    dst->instr_pc_pa = template_rec->instr_pc_pa;
    dst->instr = tracertl_rv_memory_placeholder(mtype, msize);
    trace_set_memory_type_size(dst, mtype, msize);
    dst->exu_data.memory_address.va = vaddr;
    dst->exu_data.memory_address.pa = paddr;
}

void tracertl_finalize_branch(struct TraceInstructionC *pending_recs,
                              int n_pending, int branch_rec_idx,
                              uint64_t expected_next,
                              uint64_t actual_next_pc,
                              uint64_t actual_next_trace_pc,
                              uint64_t resolved_branch_target)
{
    struct TraceInstructionC *branch_rec;
    bool branch_taken;

    if (branch_rec_idx < 0 || branch_rec_idx >= n_pending) {
        return;
    }

    branch_rec = &pending_recs[branch_rec_idx];
    branch_taken = actual_next_pc != expected_next || branch_rec->branch_type > 1;

    if (branch_taken) {
        branch_rec->branch_taken = 1;
        branch_rec->target = actual_next_trace_pc;
    } else if (resolved_branch_target != 0) {
        branch_rec->target = resolved_branch_target;
    }
}

void tracertl_finalize_branch_without_successor(
    struct TraceInstructionC *pending_recs,
    int n_pending, int branch_rec_idx,
    uint64_t expected_next,
    uint64_t terminal_target)
{
    tracertl_finalize_branch(pending_recs, n_pending, branch_rec_idx,
                             expected_next, terminal_target, terminal_target,
                             0);
}

bool tracertl_resolve_riscv_conditional_branch_target(uint64_t pc,
                                                      uint32_t insn,
                                                      uint64_t *target)
{
    int64_t imm;

    g_assert(target != NULL);

    if ((insn & 0x3) != 0x3 && insn != 0) {
        uint16_t c_insn = (uint16_t)(insn & 0xffff);
        uint8_t op = c_insn & 0x03;
        uint8_t funct3 = (c_insn >> 13) & 0x07;
        uint64_t imm_u;

        if (op != 0x01 || (funct3 != 0x06 && funct3 != 0x07)) {
            return false;
        }

        imm_u = (((uint64_t)(c_insn >> 3) & 0x03) << 1) |
                (((uint64_t)(c_insn >> 10) & 0x03) << 3) |
                (((uint64_t)(c_insn >> 2) & 0x01) << 5) |
                (((uint64_t)(c_insn >> 5) & 0x03) << 6) |
                (((uint64_t)(c_insn >> 12) & 0x01) << 8);
        imm = tracertl_sign_extend_u64(imm_u, 9);
        *target = (uint64_t)((int64_t)pc + imm);
        return true;
    }

    if (RV_OPCODE(insn) != 0x63) {
        return false;
    }

    imm = tracertl_sign_extend_u64(
        (((uint64_t)(insn >> 8) & 0x0f) << 1) |
        (((uint64_t)(insn >> 25) & 0x3f) << 5) |
        (((uint64_t)(insn >> 7) & 0x01) << 11) |
        (((uint64_t)(insn >> 31) & 0x01) << 12),
        13);
    *target = (uint64_t)((int64_t)pc + imm);
    return true;
}
