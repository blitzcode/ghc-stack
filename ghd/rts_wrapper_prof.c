
#include "rts_wrapper.h"

// GHC RTS header, profiling enabled
#define PROFILING
#define THREADED
#include <Rts.h>

// We use those offsets during CCS traversal, so they need to be in the implementation
// file where the profiling RTS
target_ptr_t OFFSET_StgRegTable_rCCCS          = offsetof(StgRegTable    , rCCCS    );
target_ptr_t OFFSET_ConstCentreStack_cc        = offsetof(CostCentreStack, cc       );
target_ptr_t OFFSET_ConstCentreStack_prevStack = offsetof(CostCentreStack, prevStack);
target_ptr_t OFFSET_ConstCentre_label          = offsetof(CostCentre     , label    );
target_ptr_t OFFSET_ConstCentre_module         = offsetof(CostCentre     , module   );
target_ptr_t OFFSET_ConstCentre_srcloc         = offsetof(CostCentre     , srcloc   );
target_ptr_t OFFSET_StgClosure_header          = offsetof(StgClosure     , header   );
target_ptr_t OFFSET_StgHeader_prof             = offsetof(StgHeader      , prof     );
target_ptr_t OFFSET_StgProfHeader_ccs          = offsetof(StgProfHeader  , ccs      );

kern_return_t ReadMemory(mach_port_name_t task, target_ptr_t address, target_ptr_t size, void *out)
{
    mach_vm_size_t inout_size = size;
    kern_return_t ret = mach_vm_read_overwrite(
        task,
        address,
        inout_size,
        (mach_vm_address_t) (uintptr_t) out,
        &inout_size);
    if (ret != KERN_SUCCESS)
        return ret;
    if (inout_size != size)
        return KERN_FAILURE;
    return KERN_SUCCESS;
}

