#include "ykernel.h"

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
 *  This handler really only needs to call the appropriate kernel syscall subroutine,
 * based on the kernel code received in user_context->code field. The only implementation
 * design of significance is how arguments are parsed from *user_context and passed into
 * the syscall, and how the syscall return value is passed back to userland via
 * user_context.
 *
 */

int TrapKernelHandler(UserContext *user_context) {
    int syscall_code = user_context->code;

    TracePrintf(1, "syscall code is: %d\n", syscall_code);

    // void **args = user_context->regs;

    // // TrapKernelHandler: work out how to get the args to the syscall handlers...and
    // the return value back

    // // for syscall functions that need arguments, look for args in
    // user_context->regs[0...] switch (syscall_code) {

    //     case 1:
    //         kFork();
    //         break;
    //     case 2:
    //         kExec();
    //         break;
    //     case 3:
    //         kExit();
    //         break;
    //     case 4:
    //         kWait();
    //         break;
    //     case 5:
    //         kGetPid();
    //         break;
    //     case 6:
    //         kBrk();
    //         break;
    //     case 7:
    //         kDelay();
    //         break;

    //         // ... and so on
    // }
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

int TrapClock(UserContext *user_context) { TracePrintf(1, "Clock trap happening!\n"); }

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

int TrapIllegal(UserContext *user_context) { ; }

/*
 *  ==================
 *  === TRAPMEMORY ===
 *  ==================
 *
 *  OS response (manual, p. 36):
 *      The kernel must determine if this exception represents an implicit
 *      request by the current process to enlarge the amount of memory allocated
 *      to the process???s stack. If so, the kernel enlarges the process???s stack
 *      to ???cover??? the address that was being referenced that caused the exception
 *      (the addr field in the UserContext) and then returns from the exception,
 *      allowing the process to continue execution with the larger stack. (For
 *      more discussion, see Section 3.5.2 below.)
 *      Otherwise, abort the currently running Yalnix user process but continue
 *      running other processes.
 *
 * Cases that don't lead to error/program exitting
 * - Page fault
 *      - In case you're trying to access a page that's on disk
 * - Trying to access empty space below stack
 *      - Indicator for growing stack size
 * - COW stuff
 *      - If trying to write to COW frame
 *
 * From manual:
 * This exception results from a disallowed memory access by the current user process.
 * The access may be disallowed because the address is outside the virtual address range
 * of the hardware (outside Region 0 and Region 1), because the address is not mapped in
 * the current page tables, or because the access violates the page protection specified
 * in the corresponding page table entry
 *
 *  user_context->code tells us some context around the trap
 *  code = 0 means addr is outside virtual address range
 *  code = 1 means addr is not mapped in current page tables
 *  code = 2 means access violates the page protection specified in ptable
 *
 */

int TrapMemory(UserContext *user_context) {
    TracePrintf(1, "CALLING MEMORY TRAP HANDLER!!\n");

    // TracePrintf(1, "Address of user context: %p; page: %x\n", user_context->addr,
    //             (unsigned int)(user_context->addr) >> PAGESHIFT);

    // // TODO: handle other codes
    // if (user_context->code == 0 || user_context->code == 2) {
    //     TracePrintf(1, "TrapMemory() called with unsupported code %d.\n",
    //                 user_context->code);
    // }

    // // If user_context->addr < currently_allocated_memory_stack and
    // // user_context->addr > brk: grow stack to cover user_context->addr
    // int page_of_uctx_addr = (unsigned int)(user_context->addr) >> PAGESHIFT;

    // pte_t *reg1_pagetable = g_running_pcb->pagetable;

    // // Allocate one more page to user stack of currently running process
    // // Need to allocate a free frame, and update R1 page table
    // for (int i = g_len_pagetable - 1; i > 0; i--) {  // TODO: add red zone
    //     if (reg1_pagetable[i].valid = 1) {
    //         continue;
    //     }

    //     int free_frame_idx = find_free_frame();
    //     reg1_pagetable[i].valid = 1;
    //     reg1_pagetable[i].prot = PROT_READ | PROT_WRITE;
    //     reg1_pagetable[i].pfn = free_frame_idx;

    //     g_running_pcb->sp = i << PAGESHIFT;
    //     break;
    // }

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

int TrapMath(UserContext *user_context) { ; }

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

int TrapTTYReceive(UserContext *user_context) { ; }

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

int TrapTTYTransmit(UserContext *user_context) { ; }

/*
 *  ================
 *  === TRAPDISK ===
 *  ================
 *
 *  OS response (manual, p. 36):
 *      Your OS can ignore these traps, unless you???ve decided to implement
 *      extra functionality involving the disk.
 *
 */

int TrapDisk(UserContext *user_context) { ; }

int GenericHandler(UserContext *user_context) { ; }