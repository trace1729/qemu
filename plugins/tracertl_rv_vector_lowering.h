#ifndef TRACERTL_RV_VECTOR_LOWERING_H
#define TRACERTL_RV_VECTOR_LOWERING_H

#include "plugins/tracertl_rv_helpers.h"

#ifdef TRACERTL_RV_VECTOR_LOWERING_UNIT_TEST
typedef uintptr_t TCGArg;

typedef enum TCGOpcode {
#define DEF(name, oargs, iargs, cargs, flags) INDEX_op_##name,
#include "tcg/tcg-opc.h"
#undef DEF
    NB_OPS,
} TCGOpcode;

typedef enum TCGType {
    TCG_TYPE_I32,
    TCG_TYPE_I64,
    TCG_TYPE_I128,
    TCG_TYPE_V64,
    TCG_TYPE_V128,
    TCG_TYPE_V256,
    TCG_TYPE_COUNT,
} TCGType;

typedef enum TCGTempVal {
    TEMP_VAL_DEAD,
    TEMP_VAL_REG,
    TEMP_VAL_MEM,
    TEMP_VAL_CONST,
} TCGTempVal;

typedef struct TCGTemp {
    TCGTempVal val_type;
    TCGType base_type;
    TCGType type;
    int64_t val;
} TCGTemp;

typedef struct TCGContext {
    TCGTemp *temps;
} TCGContext;

typedef struct TCGOp {
    TCGOpcode opc;
    unsigned nargs;
    unsigned param1;
    unsigned param2;
    TCGArg args[];
} TCGOp;

extern __thread TCGContext *tcg_ctx;

#define TCGOP_TYPE(X) ((X)->param1)
#define TCGOP_VECE(X) ((X)->param2)

static inline TCGArg temp_arg(TCGTemp *ts)
{
    return (uintptr_t)ts;
}

static inline TCGTemp *arg_temp(TCGArg a)
{
    return (TCGTemp *)(uintptr_t)a;
}

static inline size_t temp_idx(TCGTemp *ts)
{
    return ts - tcg_ctx->temps;
}
#else
#include "tcg/tcg.h"
#endif

typedef int (*TracertlRvMapArgFn)(TCGArg arg, void *opaque);

int tracertl_rv_lower_vector_tcg_op(uint32_t *buf, int buf_size,
                                    TracertlRvVectorState *state,
                                    const TCGOp *op,
                                    TracertlRvMapArgFn map_arg,
                                    void *map_opaque,
                                    TracertlRvVectorEmitMeta *meta);

#endif
