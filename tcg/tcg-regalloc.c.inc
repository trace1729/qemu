/*
 * Shared temp/regalloc helpers for TCG code generation.
 *
 * Included by tcg/tcg.c today and intended to be reused by additional
 * codegen consumers that need the same allocator substrate.
 */

static void temp_allocate_frame(TCGContext *s, TCGTemp *ts)
{
    intptr_t off;
    int size, align;

    /* When allocating an object, look at the full type. */
    size = tcg_type_size(ts->base_type);
    switch (ts->base_type) {
    case TCG_TYPE_I32:
        align = 4;
        break;
    case TCG_TYPE_I64:
    case TCG_TYPE_V64:
        align = 8;
        break;
    case TCG_TYPE_I128:
    case TCG_TYPE_V128:
    case TCG_TYPE_V256:
        /*
         * Note that we do not require aligned storage for V256,
         * and that we provide alignment for I128 to match V128,
         * even if that's above what the host ABI requires.
         */
        align = 16;
        break;
    default:
        g_assert_not_reached();
    }

    /*
     * Assume the stack is sufficiently aligned.
     * This affects e.g. ARM NEON, where we have 8 byte stack alignment
     * and do not require 16 byte vector alignment.  This seems slightly
     * easier than fully parameterizing the above switch statement.
     */
    align = MIN(s->backend.call.stack_align, align);
    off = ROUND_UP(s->current_frame_offset, align);

    /* If we've exhausted the stack frame, restart with a smaller TB. */
    if (off + size > s->frame_end) {
        tcg_raise_tb_overflow(s);
    }
    s->current_frame_offset = off + size;
#if defined(__sparc__)
    off += TCG_TARGET_STACK_BIAS;
#endif

    /* If the object was subdivided, assign memory to all the parts. */
    if (ts->base_type != ts->type) {
        int part_size = tcg_type_size(ts->type);
        int part_count = size / part_size;

        /*
         * Each part is allocated sequentially in tcg_temp_new_internal.
         * Jump back to the first part by subtracting the current index.
         */
        ts -= ts->temp_subindex;
        for (int i = 0; i < part_count; ++i) {
            ts[i].mem_offset = off + i * part_size;
            ts[i].mem_base = s->frame_temp;
            ts[i].mem_allocated = 1;
        }
    } else {
        ts->mem_offset = off;
        ts->mem_base = s->frame_temp;
        ts->mem_allocated = 1;
    }
}

/* Assign @reg to @ts, and update reg_to_temp[]. */
static void set_temp_val_reg(TCGContext *s, TCGTemp *ts, TCGReg reg)
{
    if (ts->val_type == TEMP_VAL_REG) {
        TCGReg old = ts->reg;
        tcg_debug_assert(s->reg_to_temp[old] == ts);
        if (old == reg) {
            return;
        }
        s->reg_to_temp[old] = NULL;
    }
    tcg_debug_assert(s->reg_to_temp[reg] == NULL);
    s->reg_to_temp[reg] = ts;
    ts->val_type = TEMP_VAL_REG;
    ts->reg = reg;
}

/* Assign a non-register value type to @ts, and update reg_to_temp[]. */
static void set_temp_val_nonreg(TCGContext *s, TCGTemp *ts, TCGTempVal type)
{
    tcg_debug_assert(type != TEMP_VAL_REG);
    if (ts->val_type == TEMP_VAL_REG) {
        TCGReg reg = ts->reg;
        tcg_debug_assert(s->reg_to_temp[reg] == ts);
        s->reg_to_temp[reg] = NULL;
    }
    ts->val_type = type;
}

static void temp_load(TCGContext *, TCGTemp *, TCGRegSet, TCGRegSet,
                      TCGRegSet);

/* Mark a temporary as free or dead.  If 'free_or_dead' is negative,
   mark it free; otherwise mark it dead.  */
static void temp_free_or_dead(TCGContext *s, TCGTemp *ts, int free_or_dead)
{
    TCGTempVal new_type;

    switch (ts->kind) {
    case TEMP_FIXED:
        return;
    case TEMP_GLOBAL:
    case TEMP_TB:
        new_type = TEMP_VAL_MEM;
        break;
    case TEMP_EBB:
        new_type = free_or_dead < 0 ? TEMP_VAL_MEM : TEMP_VAL_DEAD;
        break;
    case TEMP_CONST:
        new_type = TEMP_VAL_CONST;
        break;
    default:
        g_assert_not_reached();
    }
    set_temp_val_nonreg(s, ts, new_type);
}

/* Mark a temporary as dead.  */
static inline void temp_dead(TCGContext *s, TCGTemp *ts)
{
    temp_free_or_dead(s, ts, 1);
}

/* Sync a temporary to memory. 'allocated_regs' is used in case a temporary
   registers needs to be allocated to store a constant.  If 'free_or_dead'
   is non-zero, subsequently release the temporary; if it is positive, the
   temp is dead; if it is negative, the temp is free.  */
static void temp_sync(TCGContext *s, TCGTemp *ts, TCGRegSet allocated_regs,
                      TCGRegSet preferred_regs, int free_or_dead)
{
    if (!temp_readonly(ts) && !ts->mem_coherent) {
        if (!ts->mem_allocated) {
            temp_allocate_frame(s, ts);
        }
        switch (ts->val_type) {
        case TEMP_VAL_CONST:
            /* If we're going to free the temp immediately, then we won't
               require it later in a register, so attempt to store the
               constant to memory directly.  */
            if (free_or_dead
                && backend_out_sti(s, ts->type, ts->val,
                                   ts->mem_base->reg, ts->mem_offset)) {
                break;
            }
            temp_load(s, ts, s->backend.available_regs[ts->type],
                      allocated_regs, preferred_regs);
            /* fallthrough */

        case TEMP_VAL_REG:
            backend_out_st(s, ts->type, ts->reg,
                           ts->mem_base->reg, ts->mem_offset);
            break;

        case TEMP_VAL_MEM:
            break;

        case TEMP_VAL_DEAD:
        default:
            g_assert_not_reached();
        }
        ts->mem_coherent = 1;
    }
    if (free_or_dead) {
        temp_free_or_dead(s, ts, free_or_dead);
    }
}

/* free register 'reg' by spilling the corresponding temporary if necessary */
static void tcg_reg_free(TCGContext *s, TCGReg reg, TCGRegSet allocated_regs)
{
    TCGTemp *ts = s->reg_to_temp[reg];
    if (ts != NULL) {
        temp_sync(s, ts, allocated_regs, 0, -1);
    }
}

/**
 * tcg_reg_alloc:
 * @required_regs: Set of registers in which we must allocate.
 * @allocated_regs: Set of registers which must be avoided.
 * @preferred_regs: Set of registers we should prefer.
 * @rev: True if we search the registers in "indirect" order.
 *
 * The allocated register must be in @required_regs & ~@allocated_regs,
 * but if we can put it in @preferred_regs we may save a move later.
 */
static TCGReg tcg_reg_alloc(TCGContext *s, TCGRegSet required_regs,
                            TCGRegSet allocated_regs,
                            TCGRegSet preferred_regs, bool rev)
{
    int i, j, f, n = s->backend.reg_alloc_order_len;
    TCGRegSet reg_ct[2];
    const int *order;

    reg_ct[1] = required_regs & ~allocated_regs;
    tcg_debug_assert(reg_ct[1] != 0);
    reg_ct[0] = reg_ct[1] & preferred_regs;

    /* Skip the preferred_regs option if it cannot be satisfied,
       or if the preference made no difference.  */
    f = reg_ct[0] == 0 || reg_ct[0] == reg_ct[1];

    order = rev ? s->backend.indirect_reg_alloc_order
                : s->backend.reg_alloc_order;

    /* Try free registers, preferences first.  */
    for (j = f; j < 2; j++) {
        TCGRegSet set = reg_ct[j];

        if (tcg_regset_single(set)) {
            /* One register in the set.  */
            TCGReg reg = tcg_regset_first(set);
            if (s->reg_to_temp[reg] == NULL) {
                return reg;
            }
        } else {
            for (i = 0; i < n; i++) {
                TCGReg reg = order[i];
                if (s->reg_to_temp[reg] == NULL &&
                    tcg_regset_test_reg(set, reg)) {
                    return reg;
                }
            }
        }
    }

    /* We must spill something.  */
    for (j = f; j < 2; j++) {
        TCGRegSet set = reg_ct[j];

        if (tcg_regset_single(set)) {
            /* One register in the set.  */
            TCGReg reg = tcg_regset_first(set);
            tcg_reg_free(s, reg, allocated_regs);
            return reg;
        } else {
            for (i = 0; i < n; i++) {
                TCGReg reg = order[i];
                if (tcg_regset_test_reg(set, reg)) {
                    tcg_reg_free(s, reg, allocated_regs);
                    return reg;
                }
            }
        }
    }

    g_assert_not_reached();
}

static TCGReg tcg_reg_alloc_pair(TCGContext *s, TCGRegSet required_regs,
                                 TCGRegSet allocated_regs,
                                 TCGRegSet preferred_regs, bool rev)
{
    int i, j, k, fmin, n = s->backend.reg_alloc_order_len;
    TCGRegSet reg_ct[2];
    const int *order;

    /* Ensure that if I is not in allocated_regs, I+1 is not either. */
    reg_ct[1] = required_regs & ~(allocated_regs | (allocated_regs >> 1));
    tcg_debug_assert(reg_ct[1] != 0);
    reg_ct[0] = reg_ct[1] & preferred_regs;

    order = rev ? s->backend.indirect_reg_alloc_order
                : s->backend.reg_alloc_order;

    /*
     * Skip the preferred_regs option if it cannot be satisfied,
     * or if the preference made no difference.
     */
    k = reg_ct[0] == 0 || reg_ct[0] == reg_ct[1];

    /*
     * Minimize the number of flushes by looking for 2 free registers first,
     * then a single flush, then two flushes.
     */
    for (fmin = 2; fmin >= 0; fmin--) {
        for (j = k; j < 2; j++) {
            TCGRegSet set = reg_ct[j];

            for (i = 0; i < n; i++) {
                TCGReg reg = order[i];

                if (tcg_regset_test_reg(set, reg)) {
                    int f = !s->reg_to_temp[reg] + !s->reg_to_temp[reg + 1];
                    if (f >= fmin) {
                        tcg_reg_free(s, reg, allocated_regs);
                        tcg_reg_free(s, reg + 1, allocated_regs);
                        return reg;
                    }
                }
            }
        }
    }
    g_assert_not_reached();
}

/* Make sure the temporary is in a register.  If needed, allocate the register
   from DESIRED while avoiding ALLOCATED.  */
static void temp_load(TCGContext *s, TCGTemp *ts, TCGRegSet desired_regs,
                      TCGRegSet allocated_regs, TCGRegSet preferred_regs)
{
    TCGReg reg;

    switch (ts->val_type) {
    case TEMP_VAL_REG:
        return;
    case TEMP_VAL_CONST:
        reg = tcg_reg_alloc(s, desired_regs, allocated_regs,
                            preferred_regs, ts->indirect_base);
        if (ts->type <= TCG_TYPE_I64) {
            backend_out_movi(s, ts->type, reg, ts->val);
        } else {
            uint64_t val = ts->val;
            MemOp vece = MO_64;

            /*
             * Find the minimal vector element that matches the constant.
             * The targets will, in general, have to do this search anyway,
             * do this generically.
             */
            if (val == dup_const(MO_8, val)) {
                vece = MO_8;
            } else if (val == dup_const(MO_16, val)) {
                vece = MO_16;
            } else if (val == dup_const(MO_32, val)) {
                vece = MO_32;
            }

            backend_out_dupi_vec(s, ts->type, vece, reg, ts->val);
        }
        ts->mem_coherent = 0;
        break;
    case TEMP_VAL_MEM:
        if (!ts->mem_allocated) {
            temp_allocate_frame(s, ts);
        }
        reg = tcg_reg_alloc(s, desired_regs, allocated_regs,
                            preferred_regs, ts->indirect_base);
        backend_out_ld(s, ts->type, reg, ts->mem_base->reg, ts->mem_offset);
        ts->mem_coherent = 1;
        break;
    case TEMP_VAL_DEAD:
    default:
        g_assert_not_reached();
    }
    set_temp_val_reg(s, ts, reg);
}

/* Save a temporary to memory. 'allocated_regs' is used in case a
   temporary registers needs to be allocated to store a constant.  */
static void temp_save(TCGContext *s, TCGTemp *ts, TCGRegSet allocated_regs)
{
    /* The liveness analysis already ensures that globals are back
       in memory. Keep an tcg_debug_assert for safety. */
    tcg_debug_assert(ts->val_type == TEMP_VAL_MEM || temp_readonly(ts));
}

/* save globals to their canonical location and assume they can be
   modified be the following code. 'allocated_regs' is used in case a
   temporary registers needs to be allocated to store a constant. */
static void save_globals(TCGContext *s, TCGRegSet allocated_regs)
{
    int i, n;

    for (i = 0, n = s->nb_globals; i < n; i++) {
        temp_save(s, &s->temps[i], allocated_regs);
    }
}

/* sync globals to their canonical location and assume they can be
   read by the following code. 'allocated_regs' is used in case a
   temporary registers needs to be allocated to store a constant. */
static void sync_globals(TCGContext *s, TCGRegSet allocated_regs)
{
    int i, n;

    for (i = 0, n = s->nb_globals; i < n; i++) {
        TCGTemp *ts = &s->temps[i];
        tcg_debug_assert(ts->val_type != TEMP_VAL_REG
                         || ts->kind == TEMP_FIXED
                         || ts->mem_coherent);
    }
}

/* at the end of a basic block, we assume all temporaries are dead and
   all globals are stored at their canonical location. */
static void tcg_reg_alloc_bb_end(TCGContext *s, TCGRegSet allocated_regs)
{
    assert_carry_dead(s);
    for (int i = s->nb_globals; i < s->nb_temps; i++) {
        TCGTemp *ts = &s->temps[i];

        switch (ts->kind) {
        case TEMP_TB:
            temp_save(s, ts, allocated_regs);
            break;
        case TEMP_EBB:
            /* The liveness analysis already ensures that temps are dead.
               Keep an tcg_debug_assert for safety. */
            tcg_debug_assert(ts->val_type == TEMP_VAL_DEAD);
            break;
        case TEMP_CONST:
            /* Similarly, we should have freed any allocated register. */
            tcg_debug_assert(ts->val_type == TEMP_VAL_CONST);
            break;
        default:
            g_assert_not_reached();
        }
    }

    save_globals(s, allocated_regs);
}

/*
 * At a conditional branch, we assume all temporaries are dead unless
 * explicitly live-across-conditional-branch; all globals and local
 * temps are synced to their location.
 */
static void tcg_reg_alloc_cbranch(TCGContext *s, TCGRegSet allocated_regs)
{
    assert_carry_dead(s);
    sync_globals(s, allocated_regs);

    for (int i = s->nb_globals; i < s->nb_temps; i++) {
        TCGTemp *ts = &s->temps[i];
        /*
         * The liveness analysis already ensures that temps are dead.
         * Keep tcg_debug_asserts for safety.
         */
        switch (ts->kind) {
        case TEMP_TB:
            tcg_debug_assert(ts->val_type != TEMP_VAL_REG || ts->mem_coherent);
            break;
        case TEMP_EBB:
        case TEMP_CONST:
            break;
        default:
            g_assert_not_reached();
        }
    }
}

/*
 * Specialized code generation for INDEX_op_mov_* with a constant.
 */
static void tcg_reg_alloc_do_movi(TCGContext *s, TCGTemp *ots,
                                  tcg_target_ulong val, TCGLifeData arg_life,
                                  TCGRegSet preferred_regs)
{
    /* ENV should not be modified.  */
    tcg_debug_assert(!temp_readonly(ots));

    /* The movi is not explicitly generated here.  */
    set_temp_val_nonreg(s, ots, TEMP_VAL_CONST);
    ots->val = val;
    ots->mem_coherent = 0;
    if (NEED_SYNC_ARG(0)) {
        temp_sync(s, ots, s->reserved_regs, preferred_regs, IS_DEAD_ARG(0));
    } else if (IS_DEAD_ARG(0)) {
        temp_dead(s, ots);
    }
}
