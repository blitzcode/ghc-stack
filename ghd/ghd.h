
#ifndef GHD_H
#define GHD_H

#include <string>

#include <mach/mach.h>
#include <mach/mach_vm.h> // for mach_vm_ instead of vm_

class SymbolManager;

#include "rts_wrapper.h"

class TargetInfo
{
public:
    TargetInfo(pid_t pid, const char *executable);
    ~TargetInfo();

    void * ReadMemoryReturn(target_ptr_t address, target_ptr_t size) const;
    bool ReadMemoryArg(target_ptr_t address, target_ptr_t size, void *buf) const;
    target_ptr_t ReadMemoryPtr(target_ptr_t address) const;
    bool ReadMemoryString(target_ptr_t address, char *buf_out, size_t buf_size) const;

    std::string m_executable;
    std::string m_module; // Module name for our executable
    bool m_threaded_rts;
    bool m_profiling_rts;
    pid_t m_pid;
    bool m_is_64_bit;
    mach_port_name_t m_task_port;

protected:
    TargetInfo() { };
};

bool DoesSymbolExist(const char *executable, const char *symbol);
bool IsProfilingRTS(const char *exe);
bool IsThreadedRTS (const char *exe);
bool IsProcess64Bit(pid_t pid);

void DebugLoop(const TargetInfo& ti);
void PTraceContinue(pid_t pid);
void TraceProcessState(const TargetInfo& ti);
void DeallocateThreadList(
    thread_act_port_array_t thread_list,
    mach_msg_type_number_t thread_count);
const char * SignalToString(int sig);
void Indent(unsigned int starting_depth);
void StackTrace(
    const TargetInfo& ti,
    SymbolManager *symbol,
    target_ptr_t fp,
    target_ptr_t ip);
bool IsHaskellSymbol(
    const TargetInfo& ti,
    SymbolManager *symbol,
    uint32_t sym_id,
    uint16_t file_name_id);
void DumpCCS(const TargetInfo& ti, target_ptr_t ccs, uint32_t starting_depth);
void DumpSTG(const TargetInfo& ti, SymbolManager *symbol, target_ptr_t sp, uint32_t starting_depth);
target_ptr_t CCSPtrFromBaseReg(const TargetInfo& ti, target_ptr_t base_reg);
target_ptr_t CCSPtrFromTopOfStack(const TargetInfo& ti, target_ptr_t sp_reg);

#endif // GHD_H

