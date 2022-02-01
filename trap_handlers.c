#include "syscalls.h"  // where kernel syscall subroutines are defined

/*
Trap handlers are functions pointed to by pointers in the interrupt vector table
*/

/*
 *  ===================
 *  === TRAP KERNEL ===
 *  ===================
 *
 *  OS response (manual, p. 36):
 *      Execute the requested syscall, as indicated by the syscall number
 *      in the code field of the UserContext passed by reference to this
 *      trap handler function.
 *      The arguments to the syscall will be found in the registers, starting
 *      with regs[0].
 *      The return value from the syscall should be returned to the user process
 *      in the regs[0] field of the UserContext.
 *
 *  - The code numbers are found in include/yalnix.h
 *
 *  This handler really only needs to call the appropriate kernel syscall subroutine, based on the
 *  kernel code received in user_context->code field. The only implementation design of significance
 *  is how arguments are parsed from *user_context and passed into the syscall, and how the syscall
 *  return value is passed back to userland via user_context.
 *
 */

int TrapKernelHandler(UserContext *user_context) {
    int syscall_code = user_context->code;

    void **args = user_context->regs;

    // for syscall functions that need arguments, look for args in user_context->regs[0...]
    switch (syscall_code) {

        case 1:
            kFork();
            break;
        case 2:
            kExec();
            break;
        case 3:
            kExit();
            break;
        case 4:
            kWait();
            break;
        case 5:
            kGetPid();
            break;
        case 6:
            kBrk();
            break;
        case 7:
            kDelay();
            break;

            // ... and so on
    }
}

/*
 *  =================
 *  === TRAPCLOCK ===
 *  =================
 *
 *  OS response (manual, p. 36):
 *      If there are other runnable processes on the ready queue, perform
 *      a context switch to the next runnable process. (The Yalnix kernel
 *      should implement round-robin process scheduling with a CPU quantum
 *      per process of 1 clock tick.)
 *      If there are no runnable processes, dispatch idle.
 *
 */

int TrapClock(UserContext *user_context) {
}

/*
 *  ===================
 *  === TRAPILLEGAL ===
 *  ===================
 *
 *  OS response (manual, p. 36):
 *      Abort the currently running Yalnix user process but continue running
 *      other processes.
 *
 */

int TrapIllegal(UserContext *user_context) {
}

/*
 *  ==================
 *  === TRAPMEMORY ===
 *  ==================
 *
 *  OS response (manual, p. 36):
 *      The kernel must determine if this exception represents an implicit
 *      request by the current process to enlarge the amount of memory allocated
 *      to the process’s stack. If so, the kernel enlarges the process’s stack
 *      to “cover” the address that was being referenced that caused the exception
 *      (the addr field in the UserContext) and then returns from the exception,
 *      allowing the process to continue execution with the larger stack. (For
 *      more discussion, see Section 3.5.2 below.)
 *      Otherwise, abort the currently running Yalnix user process but continue
 *      running other processes.
 *
 */

int TrapMemory(UserContext *user_context) {

    // If user_context->addr < currently_allocated_memory_stack and
    // user_context->addr > brk: grow stack to cover user_context->addr

    // Else abort currently running user propcess but continue running other processes

    // Note: Maintain at least one page between top of heap and bottom of stack

    // If COW implemented, and trying to write into a readonly page, the exception
    // should not kill the process. Instead, should allocate a free frame to
    // the page trying to be written into.
}

/*
 *  ================
 *  === TRAPMATH ===
 *  ================
 *
 *  From manual (p. 36):
 *
 */

int TrapMath(UserContext *user_context) {
}

/*
 *  ======================
 *  === TRAPTTYRECEIVE ===
 *  ======================
 *
 *  OS response (manual, p. 36):
 *      This interrupt signifies that a new line of input is available
 *      from the terminal indicated by the code field in the UserContext
 *      passed by reference to this interrupt handler func- tion. The
 *      kernel should read the input from the terminal using a TtyReceive
 *      hardware operation and if necessary buffer the input line for a
 *      subsequent TtyRead syscall by some user process.
 *
 */

int TrapTTYReceive(UserContext *user_context) {
}

/*
 *  =======================
 *  === TRAPTTYTRANSMIT ===
 *  =======================
 *
 *  OS response (manual, p. 36):
 *      This interrupt signifies that a previous TtyTransmit hardware
 *      operation on some terminal has completed. The specific terminal is
 *      indicated by the code field in the UserContext passed by reference
 *      to this interrupt handler function. The kernel should complete the
 *      blocked process that started this terminal output from a TtyWrite
 *      syscall, as necessary; also start the next terminal output on this
 *      terminal, if any.
 *
 */

int TrapTTYTransmit(UserContext *user_context) {
}

/*
 *  ================
 *  === TRAPDISK ===
 *  ================
 *
 *  OS response (manual, p. 36):
 *      Your OS can ignore these traps, unless you’ve decided to implement
 *      extra functionality involving the disk.
 *
 */

int TrapDisk(UserContext *user_context) {
}
