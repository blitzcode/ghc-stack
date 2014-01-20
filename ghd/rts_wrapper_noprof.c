
#include "rts_wrapper.h"

// GHC RTS header, profiling disabled
#define THREADED
#include <Rts.h>

int GetClosureTypeAndSize(
    mach_port_name_t task,
    target_ptr_t closure_addr,
    uint32_t *closure_type_out,
    uint32_t *closure_size_out,
    target_ptr_t *fun_ref_out) // Optional closure referenced by closure_addr
{
    // Retrieve information about a closure stack object. We use this code during STG
    // stack traversal, which we only do on a non-profiling RTS, hence the reason why
    // it is located here

    (* fun_ref_out) = 0;

    // Copy closure
    StgClosure closure;
    if (ReadMemory(task, closure_addr, sizeof(StgClosure), &closure) != KERN_SUCCESS)
        return 1;

    // Copy info table for closure
    StgRetInfoTable info;
    const target_ptr_t info_addr = (target_ptr_t) get_ret_itbl(&closure);
    if (ReadMemory(task, info_addr, sizeof(StgRetInfoTable), &info) != KERN_SUCCESS)
        return 1;

    // Type
    (* closure_type_out) = info.i.type;

    // Compute closure size. Adapted from this code from 'ClosureMacros.h':

    // EXTERN_INLINE StgWord stack_frame_sizeW( StgClosure *frame )
    // {
    //     StgRetInfoTable *info;
    // 
    //     info = get_ret_itbl(frame);
    //     switch (info->i.type) {
    // 
    //     case RET_DYN:
    //     {
    //         StgRetDyn *dyn = (StgRetDyn *)frame;
    //         return  sizeofW(StgRetDyn) + RET_DYN_BITMAP_SIZE + 
    //             RET_DYN_NONPTR_REGS_SIZE +
    //             RET_DYN_PTRS(dyn->liveness) + RET_DYN_NONPTRS(dyn->liveness);
    //     }
    //             
    //     case RET_FUN:
    //         return sizeofW(StgRetFun) + ((StgRetFun *)frame)->size;
    // 
    //     case RET_BIG:
    //         return 1 + GET_LARGE_BITMAP(&info->i)->size;
    // 
    //     case RET_BCO:
    //         return 2 + BCO_BITMAP_SIZE((StgBCO *)((P_)frame)[1]);
    // 
    //     default:
    //         return 1 + BITMAP_SIZE(info->i.layout.bitmap);
    //     }
    // }

    switch (info.i.type)
    {
        case RET_DYN:
        {
            // typedef struct {
            //     const StgInfoTable* info;
            //     StgWord        liveness;
            //     StgWord        ret_addr;
            //     StgClosure *   payload[FLEXIBLE_ARRAY];
            // } StgRetDyn;
            StgRetDyn dyn;
            if (ReadMemory(task, closure_addr, sizeof(StgRetDyn), &dyn) != KERN_SUCCESS)
                return 1;
            (* closure_size_out) = sizeofW(StgRetDyn) + RET_DYN_BITMAP_SIZE + 
                RET_DYN_NONPTR_REGS_SIZE +
                RET_DYN_PTRS(dyn.liveness) + RET_DYN_NONPTRS(dyn.liveness);
            break;
        }
                
        case RET_FUN:
        {
            // typedef struct {
            //     const StgInfoTable* info;
            //     StgWord        size;
            //     StgClosure *   fun;
            //     StgClosure *   payload[FLEXIBLE_ARRAY];
            // } StgRetFun;
            StgRetFun fun;
            if (ReadMemory(task, closure_addr, sizeof(StgRetFun), &fun) != KERN_SUCCESS)
                return 1;
            (* closure_size_out) = sizeofW(StgRetFun) + fun.size;
            break;
        }

        case RET_BIG:
        {
            // #define GET_LARGE_BITMAP(info) ((StgLargeBitmap*) (((StgWord) ((info)+1))
            //     + (info)->layout.large_bitmap_offset))
            // return 1 + GET_LARGE_BITMAP(&info->i)->size;
            StgLargeBitmap bm;
            const target_ptr_t bm_addr =
                (info_addr + sizeof(StgRetInfoTable)) +
                info.i.layout.large_bitmap_offset;
            if (ReadMemory(task, bm_addr, sizeof(StgLargeBitmap), &bm) != KERN_SUCCESS)
                return 1;
            (* closure_size_out) = 1 + bm.size;
            break;
        }

        case RET_BCO:
            // #define BCO_BITMAP(bco) ((StgLargeBitmap *)((StgBCO *)(bco))->bitmap)
            // #define BCO_BITMAP_SIZE(bco) (BCO_BITMAP(bco)->size)
            //
            // typedef struct {
            //     StgHeader      header;
            //     StgArrWords   *instrs;	/* a pointer to an ArrWords */
            //     StgArrWords   *literals;	/* a pointer to an ArrWords */
            //     StgMutArrPtrs *ptrs;	/* a pointer to a  MutArrPtrs */
            //     StgHalfWord   arity;        /* arity of this BCO */
            //     StgHalfWord   size;         /* size of this BCO (in words) */
            //     StgWord       bitmap[FLEXIBLE_ARRAY];  /* an StgLargeBitmap */
            // } StgBCO;
            //
            // typedef struct {
            //   StgWord size;
            //   StgWord bitmap[FLEXIBLE_ARRAY];
            // } StgLargeBitmap;
            //
            // (* closure_size_out) = 2 + BCO_BITMAP_SIZE((StgBCO *)((P_)frame)[1]);
            //
            (* closure_size_out) = 2; // TODO: Implement me
            break;
        
        default:
            (* closure_size_out) = 1 + BITMAP_SIZE(info.i.layout.bitmap);
            break;
    }

    (* closure_size_out) *= sizeof(StgWord);

    // TODO: We could do a lot more than just follow up a single reference
    switch (info.i.type)
    {
        case CATCH_FRAME:
        {
            StgCatchFrame cframe;
            if (ReadMemory(task, closure_addr, sizeof(StgCatchFrame), &cframe) != KERN_SUCCESS)
                return 1;
            (* fun_ref_out) = (target_ptr_t) UNTAG_CLOSURE(cframe.handler);
            break;
        }
    }

    return 0;
}

uint32_t wrapper_STOP_FRAME = STOP_FRAME;
uint32_t wrapper_UNDERFLOW_FRAME = UNDERFLOW_FRAME;

// Copied from GHC's 'Printer.c'

static const char *closure_type_names[] = {
 [INVALID_OBJECT]        = "INVALID_OBJECT",
 [CONSTR]                = "CONSTR",
 [CONSTR_1_0]            = "CONSTR_1_0",
 [CONSTR_0_1]            = "CONSTR_0_1",
 [CONSTR_2_0]            = "CONSTR_2_0",
 [CONSTR_1_1]            = "CONSTR_1_1",
 [CONSTR_0_2]            = "CONSTR_0_2",
 [CONSTR_STATIC]         = "CONSTR_STATIC",
 [CONSTR_NOCAF_STATIC]   = "CONSTR_NOCAF_STATIC",
 [FUN]                   = "FUN",
 [FUN_1_0]               = "FUN_1_0",
 [FUN_0_1]               = "FUN_0_1",
 [FUN_2_0]               = "FUN_2_0",
 [FUN_1_1]               = "FUN_1_1",
 [FUN_0_2]               = "FUN_0_2",
 [FUN_STATIC]            = "FUN_STATIC",
 [THUNK]                 = "THUNK",
 [THUNK_1_0]             = "THUNK_1_0",
 [THUNK_0_1]             = "THUNK_0_1",
 [THUNK_2_0]             = "THUNK_2_0",
 [THUNK_1_1]             = "THUNK_1_1",
 [THUNK_0_2]             = "THUNK_0_2",
 [THUNK_STATIC]          = "THUNK_STATIC",
 [THUNK_SELECTOR]        = "THUNK_SELECTOR",
 [BCO]                   = "BCO",
 [AP]                    = "AP",
 [PAP]                   = "PAP",
 [AP_STACK]              = "AP_STACK",
 [IND]                   = "IND",
 [IND_PERM]              = "IND_PERM",
 [IND_STATIC]            = "IND_STATIC",
 [RET_BCO]               = "RET_BCO",
 [RET_SMALL]             = "RET_SMALL",
 [RET_BIG]               = "RET_BIG",
 [RET_DYN]               = "RET_DYN",
 [RET_FUN]               = "RET_FUN",
 [UPDATE_FRAME]          = "UPDATE_FRAME",
 [CATCH_FRAME]           = "CATCH_FRAME",
 [UNDERFLOW_FRAME]       = "UNDERFLOW_FRAME",
 [STOP_FRAME]            = "STOP_FRAME",
 [BLOCKING_QUEUE]        = "BLOCKING_QUEUE",
 [BLACKHOLE]             = "BLACKHOLE",
 [MVAR_CLEAN]            = "MVAR_CLEAN",
 [MVAR_DIRTY]            = "MVAR_DIRTY",
 [ARR_WORDS]             = "ARR_WORDS",
 [MUT_ARR_PTRS_CLEAN]    = "MUT_ARR_PTRS_CLEAN",
 [MUT_ARR_PTRS_DIRTY]    = "MUT_ARR_PTRS_DIRTY",
 [MUT_ARR_PTRS_FROZEN0]  = "MUT_ARR_PTRS_FROZEN0",
 [MUT_ARR_PTRS_FROZEN]   = "MUT_ARR_PTRS_FROZEN",
 [MUT_VAR_CLEAN]         = "MUT_VAR_CLEAN",
 [MUT_VAR_DIRTY]         = "MUT_VAR_DIRTY",
 [WEAK]                  = "WEAK",
 [PRIM]	                 = "PRIM",
 [MUT_PRIM]              = "MUT_PRIM",
 [TSO]                   = "TSO",
 [STACK]                 = "STACK",
 [TREC_CHUNK]            = "TREC_CHUNK",
 [ATOMICALLY_FRAME]      = "ATOMICALLY_FRAME",
 [CATCH_RETRY_FRAME]     = "CATCH_RETRY_FRAME",
 [CATCH_STM_FRAME]       = "CATCH_STM_FRAME",
 [WHITEHOLE]             = "WHITEHOLE"
};

const char * ClosureTypeToString(unsigned int type)
{
    static const char unknown[] = "(Unknown Type)";
    if (type >= N_CLOSURE_TYPES)
        return unknown;
    else
        return closure_type_names[type];
}

