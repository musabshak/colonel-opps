#include "address_validation.h"
#include "kernel_data_structs.h"
#include "queue.h"
#include "syscalls.h"
#include "ykernel.h"

extern pcb_t *g_running_pcb;
extern pcb_t *g_idle_pcb;
extern queue_t *g_ready_procs_queue;
extern queue_t *g_delay_blocked_procs_queue;
extern int *g_frametable;
extern unsigned int g_len_pagetable;

int schedule(enum CallerFunc caller_id);

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
    TracePrintf(2, "Entering TrapKernelHandler\n");
    int syscall_code = user_context->code;

    int rc;
    switch (syscall_code) {
        int pid;          // for kGetPid()
        int clock_ticks;  // for kDelay()
        void *addr;       // for kBrk()
        int child_pid;    // for kWait()
        int *status_ptr;  // for kWait()
        int exit_code;    // for kExit()

        // `kExec()` args
        char *filename;
        char **argvec;

        case YALNIX_GETPID:
            pid = kGetPid();
            user_context->regs[0] = pid;
            break;
        case YALNIX_BRK:
            addr = (void *)user_context->regs[0];
            rc = kBrk(addr);
            user_context->regs[0] = rc;
            break;
        case YALNIX_DELAY:
            clock_ticks = user_context->regs[0];
            rc = kDelay(clock_ticks);
            break;
        case YALNIX_FORK:
            kFork();
            user_context->regs[0] = g_running_pcb->uctxt.regs[0];
            break;
        case YALNIX_EXEC:
            filename = (char *)user_context->regs[0];
            argvec = (char **)user_context->regs[1];
            rc = kExec(filename, argvec);

            if (rc == ERROR) {
                user_context->regs[0] = ERROR;
                break;
            } else {
                *user_context = g_running_pcb->uctxt;
                break;
            }
        case YALNIX_WAIT:
            status_ptr = (int *)(user_context->regs[0]);
            child_pid = kWait(status_ptr);
            user_context->regs[0] = child_pid;
            break;
        case YALNIX_EXIT:
            exit_code = user_context->regs[0];
            kExit(exit_code);
            break;
    }
    TracePrintf(2, "Exiting TrapKernelHandler\n");
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

    TracePrintf(2, "Entering TrapClock\n");

    int rc = schedule(F_clockTrap);

    TracePrintf(2, "Exiting TrapClock\n");

    return rc;
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

int TrapIllegal(UserContext *user_context) { ; }

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
    TracePrintf(2, "CALLING MEMORY TRAP HANDLER!!\n");

    TracePrintf(2, "Address of user context: %p; page: %d\n", user_context->addr,
                (unsigned int)(user_context->addr) >> PAGESHIFT);
    TracePrintf(2, "TrapMemory() called with code %d.\n", user_context->code);

    /**
     * Determine if the trap is an implicit request to grow the user's stack. This
     * happens when the address is
     *      - in region 1
     *      - below the currently allocated memory for the user's stack
     *      - above the current break for the executing process
     */

    void *addr = user_context->addr;
    pte_t *r1_ptable = g_running_pcb->r1_ptable;
    unsigned int relative_addr_page = get_page_of_addr(addr) - g_len_pagetable;
    unsigned int last_stack_page = get_last_allocated_ustack_page(r1_ptable);

    if (is_r1_addr(addr) && is_below_userstack_allocation(r1_ptable, addr) &&
        is_above_ubrk(g_running_pcb, addr)) {
        // this IS an implicit request

        // Don't grow into the redzone!
        if (get_page_of_addr(addr) == get_page_of_addr(g_running_pcb->user_brk) + 1) {
            // failure
            TracePrintf(1, "Failed to grow user stack (redzone error).\n");
        } else {
            int num_pages_to_grow = last_stack_page - relative_addr_page;

            int *frames_found = malloc(num_pages_to_grow * sizeof(int));
            int rc = find_n_free_frames(g_frametable, num_pages_to_grow, frames_found);
            if (rc < 0) {
                // failure
                TracePrintf(1, "Failed to grow user stack (ran out of physical memory).\n");
                free(frames_found);
            } else {
                // success
                for (int i = 0; i < num_pages_to_grow; i++) {
                    int page_idx = last_stack_page - 1 - i;

                    r1_ptable[page_idx].valid = 1;
                    r1_ptable[page_idx].prot = PROT_READ | PROT_WRITE;
                    r1_ptable[page_idx].pfn = frames_found[i];

                    unsigned int addr_to_flush = ((page_idx + g_len_pagetable) << PAGESHIFT);
                    WriteRegister(REG_TLB_FLUSH, addr_to_flush);
                }

                free(frames_found);

                return SUCCESS;
            }
        }
    }

    // Abort the current process-- how to do this? Call `schedule()`?
    // REVIEW THIS
    kExit(-1);
    // schedule(F_TrapMemory);
    // *user_context = g_running_pcb->uctxt;

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
 *      Your OS can ignore these traps, unless you’ve decided to implement
 *      extra functionality involving the disk.
 *
 */

int TrapDisk(UserContext *user_context) { ; }

int GenericHandler(UserContext *user_context) { ; }