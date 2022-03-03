#include "address_validation.h"
#include "kernel_data_structs.h"
#include "printing.h"
#include "queue.h"
#include "syscalls.h"
#include "ykernel.h"

// didn't work when this was in [kernel_data_structs.h]
extern term_buf_t *g_term_bufs[NUM_TERMINALS];

/**
 * Used as "search" fxn in qremove_all (in clock trap handler).
 *
 * If process has completed its delay time
 *      - returns true
 *      - Puts the process in the ready queue
 * Otherwise
 *      - returns false
 */
bool pcb_delay_finished(void *elementp, const void *key) {

    pcb_t *pcb = (pcb_t *)elementp;

    // increment clock_ticks for the specified pcb
    pcb->elapsed_clock_ticks += 1;

    TracePrintf(2, "pid: %d, elapsed: %d, delay_ticks: %d\n", pcb->pid, pcb->elapsed_clock_ticks,
                pcb->delay_clock_ticks);

    if (pcb->elapsed_clock_ticks < pcb->delay_clock_ticks) {
        return false;  // false
    }

    /**
     * This process has paid its dues; time to move it to ready queue and to indicate to q_remove_all
     * to remove it from g_delay_blocked_procs_queue.
     */

    TracePrintf(2, "DUES HAVE BEEN PAID\n");

    // move to ready queue
    qput(g_ready_procs_queue, (void *)pcb);

    // tell qremove_all to remove this pcb from g_delay_blocked_procs_queue
    return true;
}

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
        int tty_id;       // for kTtyRead() / kTtyWrite()
        int bytes_read;
        int *pipe_idp;  // for kPipeInit()
        int pipe_id;    // for kPipeRead/Write()
        void *buf;      // for kPipeRead/Write()
        int len;        // for kPipeRead/Write()

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
        case YALNIX_TTY_READ:
            tty_id = (int)user_context->regs[0];
            buf = (void *)user_context->regs[1];
            len = (int)user_context->regs[2];
            bytes_read = kTtyRead(tty_id, buf, len);
            user_context->regs[0] = bytes_read;
            break;
        case YALNIX_TTY_WRITE:
            tty_id = (int)user_context->regs[0];
            buf = (void *)user_context->regs[1];
            len = (int)user_context->regs[2];
            kTtyWrite(tty_id, buf, len);
        case YALNIX_PIPE_INIT:
            pipe_idp = (int *)user_context->regs[0];
            rc = kPipeInit(pipe_idp);
            user_context->regs[0] = rc;
            break;
        case YALNIX_PIPE_READ:
            pipe_id = user_context->regs[0];
            buf = (void *)user_context->regs[1];
            len = user_context->regs[2];
            rc = kPipeRead(pipe_id, buf, len);
            user_context->regs[0] = rc;

            break;
        case YALNIX_PIPE_WRITE:
            pipe_id = user_context->regs[0];
            buf = (void *)user_context->regs[1];
            len = user_context->regs[2];
            rc = kPipeWrite(pipe_id, buf, len);
            user_context->regs[0] = rc;
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

    /**
     * If trap_clock called schedule() (meaning that a clock trap has happened), iterate through the
     * blocked processes associated with the kDelay syscall and increment each process'
     * pcb->elapsed_clock_ticks. If pcb->elapsed_clock_ticks >= pcb->delay_clock_ticks, remove process
     * from blocked queue and add to the ready queue.
     *
     * This is done using the qremove_all method. qremove_all takes a search function and a key. The search
     * function is applied to every queue node. If the search function returns true, then that node is removed
     * from the queue.
     *
     * The "search" function supplied to the following qremove_all call is not strictly/purely a "search"
     * function. The function pcb_delay_finished for each PCB first increments the elapsed_clock_ticks
     * attribute. Then, the function checks if the elapsed_clock_ticks are >= the delay_clock_ticks. If they
     * are, then the function adds the PCB to the g_ready_procs_queue, while also returning 1, indicating to
     * the qremove_all caller to delete the node from the g_delay_blocked_procs_queue.
     */

    TracePrintf(2, "calling qremove_all\n");
    qremove_all(g_delay_blocked_procs_queue, pcb_delay_finished, NULL);

    TracePrintf(2, "ready queue: \n");
    qapply(g_ready_procs_queue, print_pcb);
    TracePrintf(2, "\n");

    TracePrintf(2, "blocked queue: \n");
    qapply(g_delay_blocked_procs_queue, print_pcb);
    TracePrintf(2, "\n");

    int rc = schedule(g_ready_procs_queue);

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

    bool is_in_region1 = is_r1_addr(addr);
    bool is_below_ustack_allocation = is_below_userstack_allocation(r1_ptable, addr);
    bool is_above_uredzone = is_above_ubrk_redzone(g_running_pcb, addr);

    if (!(is_in_region1 && is_below_ustack_allocation && is_above_uredzone)) {
        // Not an implicit request to grow user stack-- abort
        kExit(-1);
        return ERROR;
    }

    int num_pages_to_grow = last_stack_page - relative_addr_page;
    // TODO: use malloc builder here (!!)
    int *frames_found = find_n_free_frames(g_frametable, num_pages_to_grow);
    if (frames_found == NULL) {
        TP_ERROR("Failed to grow user stack (ran out of physical memory).\n");
        kExit(-1);
    }

    for (int i = 0;; i++) {
        int frame_idx = frames_found[i];
        if (frame_idx == -1) {
            break;
        }

        int page_idx = last_stack_page - 1 - i;

        r1_ptable[page_idx].valid = 1;
        r1_ptable[page_idx].prot = PROT_READ | PROT_WRITE;
        r1_ptable[page_idx].pfn = frame_idx;

        unsigned int addr_to_flush = ((page_idx + g_len_pagetable) << PAGESHIFT);
        WriteRegister(REG_TLB_FLUSH, addr_to_flush);
    }

    free(frames_found);

    // Update PCB to reflect this change
    // varun: do we do this even if we haven't put anything on the newly allocated pages?
    // (or are we only going to reach this code if those pages are going to be populated
    // right away)
    g_running_pcb->user_stack_base = (void *)DOWN_TO_PAGE((unsigned int)addr);

    return SUCCESS;

    // musab: can get this via pcb->user_stack_base. also need to update pcb->user_stack_base
    // (need to b/c kBrk needs to know the updated user_stack_base, and it finds the stack base from
    // pcb->user_stack_base)

    // musab: general comment - ideally, reduce if/else nesting (at the very least, the outter most
    // if statement can be separated with a NOT, resulting in exit at the beginning)
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

/**
 * Helper for terminal trap handlers to wake up waiting procs
 */
bool is_waiting_for_term_id(void *elt, const void *key) {
    pcb_t *pcb = (pcb_t *)elt;
    int tty_id = *((int *)key);
    return (pcb->blocked_term == tty_id);
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

// If more than `TERMINAL_MAX_LEN` bytes are typed into the terminal, we do not support
// reading every byte. All we support is reading `TERMINAL_MAX_LEN` bytes. For instance,
// manual testing of typing an excessive amonut of characters and pressing return resulted
// in reading far fewer characters, which seems on first inspection to be `TERMINAL_MAX_LEN`
// number of characters.

int TrapTTYReceive(UserContext *user_context) {
    TracePrintf(2, "Entering `TrapTTYReceive()`...\n");

    int *tty_id = malloc(sizeof(int));
    if (tty_id == NULL) {
        TP_ERROR("`malloc()` failed.\n");
        return ERROR;
    }
    *tty_id = user_context->code;
    term_buf_t *k_buf = g_term_bufs[*tty_id];

    /**
     * Copy terminal data into kernel buffer. This will overwrite the contents of that
     * kernel buffer (e.g. from a previous trap). TODO: is this the right behavior?
     */

    // allocate kernel buffer, if necessary
    if (k_buf->ptr == NULL) {
        k_buf->ptr = malloc(TERMINAL_MAX_LINE);
        if (k_buf->ptr == NULL) {
            TP_ERROR("`malloc()` for kernel buffer failed.\n");
            free(tty_id);
            return ERROR;
        }
        k_buf->curr_pos_offset, k_buf->end_pos_offset = 0;  // not really necessary, I think
    }

    // receive from terminal. This will overwrite whatever is in the kernel buf
    int bytes_received = TtyReceive(*tty_id, k_buf->ptr, TERMINAL_MAX_LINE);
    k_buf->end_pos_offset = bytes_received;

    /**
     * Alert any blocked process waiting on this terminal that it has new input
     */

    pcb_t *pcb = (pcb_t *)qremove(g_term_blocked_read_queue, is_waiting_for_term_id, (void *)tty_id);
    if (pcb != NULL) {
        qput(g_ready_procs_queue, (void *)pcb);
    }

    free(tty_id);

    TracePrintf(2, "Exiting `TrapTTYReceive()`...\n");
    return SUCCESS;
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
    // Place the process that was blocking for this terminal back on the ready queue
    // so that when it starts running, it will pick up where it left off (e.g. in
    // 'TtyWrite()`).
    int *tty_id = malloc(sizeof(int));
    if (tty_id == NULL) {
        TP_ERROR("`malloc()` failed.\n");
        return ERROR;
    }
    *tty_id = user_context->code;

    pcb_t *pcb = (pcb_t *)(qremove(g_term_blocked_transmit_queue, is_waiting_for_term_id, tty_id));
    if (pcb == NULL) {
        TP_ERROR("Couldn't find process the terminal was waiting on.\n");
        free(tty_id);
        return ERROR;
    } else {
        free(tty_id);
    }

    qput(g_ready_procs_queue, pcb);

    // Scheduling doesn't need to happen in this trap-- just return
    return SUCCESS;
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

int TrapDisk(UserContext *user_context) { ; }

int GenericHandler(UserContext *user_context) { ; }