
#ifndef RTS_WRAPPER_H
#define RTS_WRAPPER_H

//
// Since we can't include GHC's RTS headers from C++ code
// (https://ghc.haskell.org/trac/ghc/ticket/8676#ticket)
// we're writing a small C wrapper around the bits we need
//

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stdint.h>

#include <mach/mach.h>
#include <mach/mach_vm.h> // for mach_vm_ instead of vm_

typedef uint32_t target_ptr_t;

kern_return_t ReadMemory(mach_port_name_t task, target_ptr_t address, target_ptr_t size, void *out);

const char * ClosureTypeToString(unsigned int type);
int GetClosureTypeAndSize(
    mach_port_name_t task,
    target_ptr_t closure_addr,
    uint32_t *closure_type_out,
    uint32_t *closure_size_out,
    target_ptr_t *fun_ref_out);

// Structure field offsets so we can traverse them in the memory space of the target process
extern target_ptr_t OFFSET_StgRegTable_rCCCS;
extern target_ptr_t OFFSET_ConstCentreStack_cc;
extern target_ptr_t OFFSET_ConstCentreStack_prevStack;
extern target_ptr_t OFFSET_ConstCentre_label;
extern target_ptr_t OFFSET_ConstCentre_module;
extern target_ptr_t OFFSET_ConstCentre_srcloc;
extern target_ptr_t OFFSET_StgClosure_header;
extern target_ptr_t OFFSET_StgHeader_prof;
extern target_ptr_t OFFSET_StgProfHeader_ccs;

// Selected closure types
extern uint32_t wrapper_STOP_FRAME;
extern uint32_t wrapper_UNDERFLOW_FRAME;

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // RTS_WRAPPER_H

