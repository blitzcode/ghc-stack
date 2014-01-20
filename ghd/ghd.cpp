
#include "ghd.h"

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>

#include <signal.h>

#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <stdint.h>

#include <vector>
#include <string>
#include <map>

#include "atos.h"

int main(int argc, char* argv[])
{
    if (argc == 1)
    {
        std::printf("Usage: %s executable [arguments]\n", argv[0]);
        return -1;
    }

    // Are we root?
    //
    // TODO: We could be a bit smarter about this, like explained here
    //       http://os-tres.net/blog/2010/02/17/mac-os-x-and-task-for-pid-mach-call/
    //       or just launch the child process with a Mach call, but for this simple
    //       proof-of-concept it is easiest just to require running as root to get
    //       the required access
    if (geteuid() != 0)
        assert(!"Need to run as root - forgot 'sudo'?");

    // We expect to be 32bit, like our target. Supporting all combinations of 32 and 64 bit
    // is absolutely possible, just this proof-of-concept debugger is fixed to a single
    // architecture to simplify things
    assert(sizeof(void *) == 4);

    // Launch process to be debugged, forward all arguments
    pid_t child = fork();
    if (child == 0)
    {
        // Let parent trace us
        //
        // TODO: We could alternatively also handle all of this entirely without ptrace()
        //       and rely entirely on Mach exception handling
        ptrace(PT_TRACE_ME, 0, NULL, NULL);

        if (execv(argv[1], &argv[1]) == -1)
            assert("execl() failed, can't load child executable");
    }
    else if (child == -1)
        assert(!"fork() failed");
    else
    {
        TargetInfo ti(child, argv[1]);

        if (ti.m_is_64_bit)
            assert(!"ghd: Expected 32bit executable");

        std::printf("ghd: Debugging '%s', PID %i\n", argv[1], child);

        std::printf("ghd: RTS - Threaded: %s | Profiling: %s\n",
            IsThreadedRTS(argv[1]) ? "Yes" : "No",
            IsProfilingRTS(argv[1]) ? "Yes" : "No");

        DebugLoop(ti);
        kill(child, SIGKILL);
    }

    return 0;
}

// Since we can't call rts_isProfiled() or such, check the flavor of the RTS by checking
// for the presence of symbols
//
// TODO: Could maybe just check for the library 'ribHSrts_thr_p.a(darwin.o)' etc.?
//
bool IsProfilingRTS(const char *exe) { return DoesSymbolExist(exe, "_CCS_MAIN"      ); }
bool IsThreadedRTS (const char *exe) { return DoesSymbolExist(exe, "_createOSThread"); }
bool DoesSymbolExist(const char *executable, const char *symbol)
{
    // Use nm to check if a symbol exists
    char buf[1024];
    std::snprintf(buf, sizeof(buf), "nm %s | grep %s", executable, symbol);
    std::FILE *pipe = popen(buf, "r");
    assert(pipe != NULL);
    bool ret = std::fread(buf, 1, sizeof(buf), pipe) != 0;
    pclose(pipe);
    return ret;
}

bool IsProcess64Bit(pid_t pid)
{
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, 0 };
    mib[3] = pid;
    size_t len = sizeof(kinfo_proc);
    kinfo_proc kp;

    if (sysctl(mib, 4, &kp, &len, NULL, 0) == -1)
        assert(!"sysctl() failed");

    return kp.kp_proc.p_flag & P_LP64 != 0;
}

TargetInfo::TargetInfo(pid_t pid, const char *executable)
{
    // Process
    m_pid = pid;
    m_executable = executable;
    // Configuration
    m_threaded_rts = IsThreadedRTS(executable);
    m_profiling_rts = IsProfilingRTS(executable);
    m_is_64_bit = IsProcess64Bit(pid);
    // Extract name of the executable module
    const char *module_name = &executable[std::strlen(executable) - 1];
    while (module_name != executable)
    {
        if (* module_name == '/')
        {
            module_name++;
            break;
        }
        module_name--;
    }
    m_module = module_name;
    // We need a port for the task to be debugged
    if (task_for_pid(mach_task_self(), pid, &m_task_port) != KERN_SUCCESS)
        assert(!"Can't get port for task");
}

TargetInfo::~TargetInfo()
{
    if (mach_port_deallocate(mach_task_self(), m_task_port) != KERN_SUCCESS)
        assert(!"Can't deallocate port");
}

bool TargetInfo::ReadMemoryArg(target_ptr_t address, target_ptr_t size, void *buf) const
{
    kern_return_t ret = ::ReadMemory(m_task_port, address, size, buf);
    return (ret == KERN_SUCCESS);
}

void * TargetInfo::ReadMemoryReturn(target_ptr_t address, target_ptr_t size) const
{
    static char buf[65536];
    if (size > sizeof(buf))
        return NULL;
    bool ret = ReadMemoryArg(address, size, buf);
    return ret ? buf : NULL;
}

target_ptr_t TargetInfo::ReadMemoryPtr(target_ptr_t address) const
{
    // Return the pointer value at the given address. Returns 0 both in case of
    // a pointer to a null pointer and an actual failure to read the pointer value
    // in the first place
    target_ptr_t *ptr_val =
        reinterpret_cast<target_ptr_t *> (ReadMemoryReturn(address, sizeof(target_ptr_t)));
    return (ptr_val == NULL) ? 0 : (* ptr_val);
}

bool TargetInfo::ReadMemoryString(target_ptr_t address, char *buf_out, size_t buf_size) const
{   
    unsigned int i;
    for (i=0; i<buf_size; i++)
    {
        // TODO: Very slow, shouldn't matter for debugging, though
        if (ReadMemoryArg(address + i, 1, &buf_out[i]) == false)
           return false; 
        if (buf_out[i] == 0)
            break;
        if (i == buf_size - 1) // Null terminate and fail if we're out of space
        {
            buf_out[buf_size - 1] = 0;
            return false;
        }
    }
    return true;
}

void PTraceContinue(pid_t pid)
{
    // Child process stopped after signalling us, let it proceed
    ptrace(PT_CONTINUE, pid, (caddr_t) 1, 0);
}

void DebugLoop(const TargetInfo& ti)
{
    while (true)
    {
        // Wait for the child to exit or generate a signal requiring our attention
        int status;
        if (waitpid(ti.m_pid, &status, 0) == -1)
        {
            assert(!"waitpid() failed");
            break;
        }

        // Handle signal
        if (WIFEXITED(status))
        {
            std::printf("ghd: Child done (%i), exiting\n", WEXITSTATUS(status));
            break;
        }
        else if (WIFSIGNALED(status))
        {
            std::printf("ghd: Child terminated (%s), exiting\n",
                SignalToString(WTERMSIG(status)));
            break;
        }
        else if (WIFSTOPPED(status))
        {
            // Child has stopped, forwarding us some a signal. Stack trace on fault or continue
            const int sig = WSTOPSIG(status);
            switch (sig)
            {
                // Fault?
                case SIGSEGV:
                case SIGBUS:
                case SIGILL:
                case SIGFPE:
                case SIGSYS:
                    std::printf("ghd: Child stopped on fault '%s'\n", SignalToString(sig));
                    TraceProcessState(ti);
                    return;
                case SIGALRM:
                    // Just ignore this one silently
                    PTraceContinue(ti.m_pid);
                    break;
                // Continue
                default:
                    std::printf(
                        "ghd: Received signal '%s' from child, continuing\n",
                        SignalToString(sig));
                    PTraceContinue(ti.m_pid);
                    break;
            }
        }
        else
            std::printf("ghd: Unknown event from child\n");
    }
}

void TraceProcessState(const TargetInfo& ti)
{
    std::printf("ghd: Attempting to run stack trace\n");

    // Initialize atos late to reduce startup time and make sure our child
    // has actually run exec()
    std::auto_ptr<SymbolManager> symbol =
        std::auto_ptr<SymbolManager>(new SymbolManager(ti.m_pid));

    // List of threads
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    if (task_threads(ti.m_task_port, &thread_list, &thread_count) != KERN_SUCCESS)
        assert(!"Can't obtain thread list");

    for (uint thread_idx=0; thread_idx<thread_count; thread_idx++)
    {
        // Query thread scheduling etc. information
        thread_basic_info tbi;
        mach_msg_type_number_t thread_info_count = THREAD_BASIC_INFO_COUNT;
        if (thread_info(thread_list[thread_idx],
                        THREAD_BASIC_INFO,
                        (thread_info_t) &tbi,
                        &thread_info_count) != KERN_SUCCESS)
        {
            assert(!"thread_info() failed");
        }

        // Only show threads which were running, remove to show all threads
        if (tbi.flags & TH_FLAGS_SWAPPED)
            continue;

        std::printf("ghd: ---------------\n");
        std::printf("ghd: Thread %i of %i\n", thread_idx + 1, thread_count);
        std::printf("ghd: ---------------\n");

        std::printf("ghd: Status - ");
        switch (tbi.run_state)
        {
            case TH_STATE_RUNNING:         std::printf("Running");         break;
            case TH_STATE_STOPPED:         std::printf("Stopped");         break;
            case TH_STATE_WAITING:         std::printf("Waiting");         break;
            case TH_STATE_UNINTERRUPTIBLE: std::printf("Uninterruptible"); break;
            case TH_STATE_HALTED:          std::printf("Halted");          break;
            default:                       std::printf("(Unknown)");       break;
        }
        if (tbi.flags & TH_FLAGS_SWAPPED)
            std::printf(" (swapped out)");
        if (tbi.flags & TH_FLAGS_IDLE)
            std::printf(" (idle)");
        std::printf("\n");

        // Query thread exception information
        x86_exception_state32_t x86es32;
        mach_msg_type_number_t exception_state_count32 = x86_EXCEPTION_STATE32_COUNT;
        if (thread_get_state(thread_list[thread_idx],
                             x86_EXCEPTION_STATE32,
                             (thread_state_t) &x86es32,
                             &exception_state_count32) != KERN_SUCCESS)
        {
            assert(!"thread_get_state() failed");
        }
        const char *trap_err_str = "";
        switch (x86es32.__trapno)
        {
            case EXC_I386_DIVERR   :
                trap_err_str = " (EXC_I386_DIVERR - divide by 0 error)"; break;
            case EXC_I386_SGLSTP   :
                trap_err_str = " (EXC_I386_SGLSTP - single step)"; break;
            case EXC_I386_NMIFLT   :
                trap_err_str = " (EXC_I386_NMIFLT - NMI)"; break;
            case EXC_I386_BPTFLT   :
                trap_err_str = " (EXC_I386_BPTFLT - breakpoint fault)"; break;
            case EXC_I386_INTOFLT  :
                trap_err_str = " (EXC_I386_INTOFLT - INTO overflow fault)"; break;
            case EXC_I386_BOUNDFLT :
                trap_err_str = " (EXC_I386_BOUNDFLT - BOUND instruction fault)"; break;
            case EXC_I386_INVOPFLT :
                trap_err_str = " (EXC_I386_INVOPFLT - invalid opcode fault)"; break;
            case EXC_I386_NOEXTFLT :
                trap_err_str = " (EXC_I386_NOEXTFLT - extension not available fault)"; break;
            case EXC_I386_DBLFLT   :
                trap_err_str = " (EXC_I386_DBLFLT - double fault)"; break;
            case EXC_I386_EXTOVRFLT:
                trap_err_str = " (EXC_I386_EXTOVRFLT - extension overrun fault)"; break;
            case EXC_I386_INVTSSFLT:
                trap_err_str = " (EXC_I386_INVTSSFLT - invalid TSS fault)"; break;
            case EXC_I386_SEGNPFLT :
                trap_err_str = " (EXC_I386_SEGNPFLT - segment not present fault)"; break;
            case EXC_I386_STKFLT   :
                trap_err_str = " (EXC_I386_STKFLT - stack fault)"; break;
            case EXC_I386_GPFLT    :
                trap_err_str = " (EXC_I386_GPFLT - general protection fault)"; break;
            case EXC_I386_PGFLT    :
                trap_err_str = " (EXC_I386_PGFLT - page fault)"; break;
            case EXC_I386_EXTERRFLT:
                trap_err_str = " (EXC_I386_EXTERRFLT - extension error fault)"; break;
            case EXC_I386_ALIGNFLT :
                trap_err_str = " (EXC_I386_ALIGNFLT - alignment fault)"; break;
            case EXC_I386_ENDPERR  :
                trap_err_str = " (EXC_I386_ENDPERR - emulated extension error flt)"; break;
            case EXC_I386_ENOEXTFLT:
                trap_err_str = " (EXC_I386_ENOEXTFLT - emulated ext not present)"; break;
        }
        std::printf("ghd: ExceptionState - trapno: %u%s, err: %u, faultvaddr: 0x%x\n",
            x86es32.__trapno,
            trap_err_str,
            x86es32.__err,
            x86es32.__faultvaddr);

        // Query thread registers
        x86_thread_state32_t x86ts32;
        mach_msg_type_number_t thread_state_count32 = x86_THREAD_STATE32_COUNT;
        if (thread_get_state(thread_list[thread_idx],
                             x86_THREAD_STATE32,
                             (thread_state_t) &x86ts32,
                             &thread_state_count32) != KERN_SUCCESS)
        {
            assert(!"thread_get_state() failed");
        }
        std::printf("ghd: Registers\n" \
                    "ghd:   eax: %u, ebx: %u, ecx: %u, edx: %u, edi: %u, esi: %u, ebp: 0x%x\n" \
                    "ghd:   esp: 0x%x, ss: %u, eflags: %u, eip: 0x%x <%s>, cs: %u, ds: %u\n" \
                    "ghd:   es: %u, fs: %u, gs: %u\n",
            x86ts32.__eax,
            x86ts32.__ebx,
            x86ts32.__ecx,
            x86ts32.__edx,
            x86ts32.__edi,
            x86ts32.__esi,
            x86ts32.__ebp,
            x86ts32.__esp,
            x86ts32.__ss,
            x86ts32.__eflags,
            x86ts32.__eip,
            symbol->SymbolIDToName(symbol->AddressToSymbolID(x86ts32.__eip)),
            x86ts32.__cs,
            x86ts32.__ds,
            x86ts32.__es,
            x86ts32.__fs,
            x86ts32.__gs);

        // Traverse stack
        StackTrace(ti, symbol.get(), x86ts32.__ebp, x86ts32.__eip);
    }

    // Cleanup
    std::printf("ghd: Stack trace done, exiting\n");
    DeallocateThreadList(thread_list, thread_count);
}

void Indent(unsigned int depth)
{
    std::printf("ghd: ");
    for (unsigned int i=0; i<depth; i++)
        std::printf(" ");
}

void StackTrace(
    const TargetInfo& ti,
    SymbolManager *symbol,
    target_ptr_t fp, // Frame pointer (or STG Sp register when we're in Haskell code)
    target_ptr_t ip) // Instruction pointer
{
    std::printf("ghd: Stack Trace\n");

    // Frame pointer x86 stack traversal
    struct StackFrame
    {
        target_ptr_t next;
        target_ptr_t ret;
    };
    StackFrame frame = { fp, ip };
    target_ptr_t old_fp = fp - 1;
    for (unsigned int depth=1; depth<64; depth++)
    {
        uint16_t file_name_id, line_number;
        const uint32_t sym_id =
            symbol->AddressToSymbolID(frame.ret, &file_name_id, &line_number);

        // Are we in Haskell code now?
        if (IsHaskellSymbol(ti, symbol, sym_id, file_name_id))
        {
            Indent(depth);
            std::printf("0x%x <%s> [Haskell%s]\n",
                frame.ret,
                symbol->SymbolIDToName(sym_id),
                ti.m_profiling_rts ? ", switching to CCS" : ", switching to STG stack");

            if (ti.m_profiling_rts)
            {
                // We have a CCS, pick it up from the Sp in the frame
                const target_ptr_t ccs = CCSPtrFromTopOfStack(ti, frame.next);
                if (ccs == 0)
                {
                    Indent(depth + 1);
                    std::printf("(Can't access CCS from STG stack at Sp = 0x%x)\n", frame.next);
                }
                else
                    DumpCCS(ti, ccs, depth + 1);
            }
            else
            {
                // No profiling RTS, proceed with the STG stack
                DumpSTG(ti, symbol, frame.next, depth + 1);
            }
            break; // Done, we don't handle any potential Haskell -> C transition yet
        }

        // Current frame's function
        Indent(depth);
        std::printf("0x%x <%s> from %s (%s:%i)\n",
            frame.ret,
            symbol->SymbolIDToName(sym_id),
            symbol->SymbolIDToModule(sym_id),
            symbol->FileIDToName(file_name_id),
            line_number);

        // Some sanity checks for the frame link pointer
        bool stop_traversal = false;
        if (frame.next < 1024)
        {
            Indent(depth + 1);
            std::printf("(Next frame near zero)\n");
            stop_traversal = true;
        }
        if (frame.next % sizeof(void *) != 0) // IIRC, OS X actually requires 16b alignment
        {
            Indent(depth + 1);
            std::printf("(Next frame improperly aligned)\n");
            stop_traversal = true;
        }
        if (frame.next == old_fp)
        {
            Indent(depth + 1);
            std::printf("(Next frame identical to current)\n");
            stop_traversal = true;
        }
        if (frame.next < old_fp)
        {
            Indent(depth + 1);
            std::printf("(Next frame before current)\n");
            stop_traversal = true;
        }
        if (frame.next - old_fp > 32 * 1024 * 1024)
        {
            Indent(depth + 1);
            std::printf("(Next frame >32MB away from current)\n");
            stop_traversal = true;
        }

        // Next frame
        old_fp = frame.next;
        if (ti.ReadMemoryArg(frame.next, sizeof(StackFrame), &frame) == false)
        {
            // Likely a bad address, stop traversing
            Indent(depth + 1);
            std::printf("(Can't access next frame)\n");
            stop_traversal = true;
        }

        if (stop_traversal)
            break;
    }
}

// Get a Cost Center Stack pointer from either the base register or the STG stack pointer
target_ptr_t CCSPtrFromBaseReg(const TargetInfo& ti, target_ptr_t base_reg)
{
    return ti.ReadMemoryPtr(base_reg + OFFSET_StgRegTable_rCCCS);
}
target_ptr_t CCSPtrFromTopOfStack(const TargetInfo& ti, target_ptr_t sp_reg)
{
    return ti.ReadMemoryPtr
        (sp_reg + OFFSET_StgClosure_header + OFFSET_StgHeader_prof + OFFSET_StgProfHeader_ccs);
}

bool IsHaskellSymbol(
    const TargetInfo& ti,
    SymbolManager *symbol,
    uint32_t sym_id,
    uint16_t file_name_id)
{
    // One challenge with inspecting a stopped target process is figuring out if we're
    // inside a Haskell function and need to do CCS / STG stack traversal, or inside
    // a C/C++/ObjC function and need to do x86 frame pointer stack traversal.
    //
    // Here we simply look at the symbol information and decide based upon that. If
    // our function has a matching name, comes from the executable (main module) and lacks
    // source file debug information, we assume it's a Haskell function. This is rather
    // crummy, but works well enough. We could also look at some other bits of machine
    // state to make the decision, i.e.:
    //
    // C <- C
    // -----------------------------
    // ebp: Frame pointer (pointing to next + ret pointers)
    // esp: Top of x86 stack
    // 
    // C <- Haskell
    // -----------------------------
    // ebp: Frame pointer (pointing to Haskell Sp + ret pointers)
    // esp: Top of x86 stack
    // 
    // Haskell <- Haskell
    // -----------------------------
    // ebx: BaseReg
    // edi: Hp
    // ebp: Sp, Top of STG stack
    // esp: Top of C stack? (Not used as a STG register)
    // 
    // Haskell <- C
    // -----------------------------
    // ebx: BaseReg
    // edi: Hp
    // ebp: Sp, Top of STG stack
    // esp: Top of C stack? (Not used as a STG register)

    // Haskell functions don't have source file debug information
    if (std::strcmp(symbol->FileIDToName(file_name_id), symbol->GetUnresolvedSymbolName()) != 0) 
        return false;
    // Assume that all Haskell functions come from our executable
    if (strcasecmp(symbol->SymbolIDToModule(sym_id), ti.m_module.c_str()) != 0)
        return false;
    // Assume that all Haskell functions have certain tokens in their name
    if (std::strstr(symbol->SymbolIDToName(sym_id), "_info") == NULL)
        return false;

    return true;
}

void DumpCCS(const TargetInfo& ti, target_ptr_t ccs, uint32_t starting_depth)
{
    // Traverse and print the passed Cost Center Stack
    for (unsigned int depth=starting_depth; depth<64; depth++) 
    {
        Indent(depth);

        // Get CC pointer from CCS
        const target_ptr_t cc = ti.ReadMemoryPtr(ccs + OFFSET_ConstCentreStack_cc);
        if (cc == 0)
        {
            std::printf("(Can't read CC pointer)\n");
            break;
        }

        // Retrieve symbol information from CC
        const target_ptr_t label_ptr  = ti.ReadMemoryPtr(cc + OFFSET_ConstCentre_label);
        const target_ptr_t module_ptr = ti.ReadMemoryPtr(cc + OFFSET_ConstCentre_module);
        const target_ptr_t srcloc_ptr = ti.ReadMemoryPtr(cc + OFFSET_ConstCentre_srcloc);
        char label[256], module[256], srcloc[256];
        if (ti.ReadMemoryString(label_ptr, label, sizeof(label)) == false)
            std::strcpy(label, "(can't read label)");
        if (ti.ReadMemoryString(module_ptr, module, sizeof(module)) == false)
            std::strcpy(module, "(can't read module)");
        if (ti.ReadMemoryString(srcloc_ptr, srcloc, sizeof(srcloc)) == false)
            std::strcpy(srcloc, "(can't read srcloc)");
        std::printf("CCS:0x%x <%s> from %s (%s)\n", ccs, label, module, srcloc);

        // Walk the CC stack
        ccs = ti.ReadMemoryPtr(ccs + OFFSET_ConstCentreStack_prevStack);
        if (ccs == 0)
            break;
    }
}

void DumpSTG(
    const TargetInfo& ti,
    SymbolManager *symbol,
    target_ptr_t sp,
    uint32_t starting_depth)
{
    // TODO: See GHC's 'Printer.c' on how we could print more information about what's on
    //       the stack

    // Traverse and print the passed STG stack
    for (unsigned int depth=starting_depth; depth<128; depth++) 
    {
        // Top closure
        const target_ptr_t info = ti.ReadMemoryPtr(sp);
        const uint32_t sym_id = symbol->AddressToSymbolID(info);

        Indent(depth);

        // Let our wrapper collect the required information
        uint32_t closure_type, closure_size;
        target_ptr_t fun_ref;
        if (GetClosureTypeAndSize(ti.m_task_port, sp, &closure_type, &closure_size, &fun_ref) != 0)
        {
            std::printf("0x%x (Can't read stack frame)\n", sp);
            break;
        }

        // Referenced closure
        char ref_buf[256] = { 0 };
        if (fun_ref != 0)
        {
            std::snprintf(
                ref_buf,
                sizeof(ref_buf),
                ", <%s>",
                symbol->SymbolIDToName(symbol->AddressToSymbolID(ti.ReadMemoryPtr(fun_ref))));
        }

        std::printf("0x%x <%s> (%s, %ib%s)\n",
            sp,
            symbol->SymbolIDToName(sym_id),
            ClosureTypeToString(closure_type),
            closure_size,
            ref_buf);

        if (closure_type == wrapper_STOP_FRAME)
            break;

        // TODO: Handle underflow frames
        if (closure_type == wrapper_UNDERFLOW_FRAME)
            break;

        sp += closure_size;
    }
}

const char * SignalToString(int sig)
{
    switch (sig)
    {
        case SIGHUP   : return "SIGHUP - terminal line hangup";
        case SIGINT   : return "SIGINT - interrupt program";
        case SIGQUIT  : return "SIGQUIT - quit program";
        case SIGILL   : return "SIGILL - illegal instruction";
        case SIGTRAP  : return "SIGTRAP - trace trap";
        case SIGABRT  : return "SIGABRT - abort program (formerly SIGIOT)";
        case SIGEMT   : return "SIGEMT - emulate instruction executed";
        case SIGFPE   : return "SIGFPE - floating-point exception";
        case SIGKILL  : return "SIGKILL - kill program";
        case SIGBUS   : return "SIGBUS - bus error";
        case SIGSEGV  : return "SIGSEGV - segmentation violation";
        case SIGSYS   : return "SIGSYS - non-existent system call invoked";
        case SIGPIPE  : return "SIGPIPE - write on a pipe with no reader";
        case SIGALRM  : return "SIGALRM - real-time timer expired";
        case SIGTERM  : return "SIGTERM - software termination signal";
        case SIGURG   : return "SIGURG - urgent condition present on socket";
        case SIGSTOP  : return "SIGSTOP - stop (cannot be caught or ignored)";
        case SIGTSTP  : return "SIGTSTP - stop signal generated from keyboard";
        case SIGCONT  : return "SIGCONT - continue after stop";
        case SIGCHLD  : return "SIGCHLD - child status has changed";
        case SIGTTIN  : return "SIGTTIN - background read attempted from control terminal";
        case SIGTTOU  : return "SIGTTOU - background write attempted to control terminal";
        case SIGIO    : return "SIGIO - I/O is possible on a descriptor (see fcntl(2))";
        case SIGXCPU  : return "SIGXCPU - cpu time limit exceeded (see setrlimit(2))";
        case SIGXFSZ  : return "SIGXFSZ - file size limit exceeded (see setrlimit(2))";
        case SIGVTALRM: return "SIGVTALRM - virtual time alarm (see setitimer(2))";
        case SIGPROF  : return "SIGPROF - profiling timer alarm (see setitimer(2))";
        case SIGWINCH : return "SIGWINCH - window size change";
        case SIGINFO  : return "SIGINFO - status request from keyboard";
        case SIGUSR1  : return "SIGUSR1 - user defined signal 1";
        case SIGUSR2  : return "SIGUSR2 - user defined signal 2";
        default       : return "unknown";
    }
}

void DeallocateThreadList(
    thread_act_port_array_t thread_list,
    mach_msg_type_number_t thread_count)
{
    for (uint i=0; i<thread_count; i++)
        if (mach_port_deallocate(mach_task_self(), thread_list[i]) != KERN_SUCCESS)
            assert(!"Error while deallocating thread port");

    if (vm_deallocate(mach_task_self(),
                      (vm_offset_t) thread_list,
                      sizeof(* thread_list) * thread_count) != KERN_SUCCESS)
    {
        assert(!"Error while deallocating thread list");
    }
}

