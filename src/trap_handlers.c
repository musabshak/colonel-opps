/**
 * trap_handlers.c
 *
 * Authors: Varun Malladi and Musab Shakeel
 * Date: 2/5/2022
 *
 * This file defines trap handlers used in colonel-opps, and any associated helper functions.
 *
 * Trap handlers are functions pointed to by pointers in the interrupt vector table
 *
 */

#include "address_validation.h"
#include "k_common.h"
#include "printing.h"
#include "queue.h"
#include "syscalls.h"
#include "ykernel.h"

// didn't work when this was in [k_common.h]
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

/**
 * This handler really only needs to call the appropriate kernel syscall subroutine,
 * based on the kernel code received in user_context->code field. The only implementation
 * design of significance is how arguments are parsed from *user_context and passed into
 * the syscall, and how the syscall return value is passed back to userland via
 * user_context.
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
        int bytes_read;   // for kTTyRead()
        int *pipe_idp;    // for kPipeInit()
        int pipe_id;      // for kPipeRead/Write()
        void *buf;        // for kPipeRead/Write()
        int len;          // for kPipeRead/Write()
        int *lock_idp;    // for kLockInit()
        int lock_id;      // for kAcquire/kRelease()
        int *cvar_idp;    // for kCvarInit()
        int cvar_id;      // for cvar syscalls
        int id;           // for kReclaim()
        char *filename;   // for kExec()
        char **argvec;    // for kExec()

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
            if (kFork() == ERROR) {
                user_context->regs[0] = ERROR;
            } else {
                // the running pcb was updated in `kFork()`
                user_context->regs[0] = g_running_pcb->uctxt.regs[0];
            }
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
            break;
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
        case YALNIX_LOCK_INIT:
            lock_idp = (int *)user_context->regs[0];
            rc = kLockInit(lock_idp);
            user_context->regs[0] = rc;
            break;
        case YALNIX_LOCK_ACQUIRE:
            lock_id = user_context->regs[0];
            rc = kAcquire(lock_id);
            user_context->regs[0] = rc;
            break;
        case YALNIX_LOCK_RELEASE:
            lock_id = user_context->regs[0];
            rc = kRelease(lock_id);
            user_context->regs[0] = rc;
            break;
        case YALNIX_CVAR_INIT:
            cvar_idp = (int *)user_context->regs[0];
            rc = kCvarInit(cvar_idp);
            user_context->regs[0] = rc;
            break;
        case YALNIX_CVAR_SIGNAL:
            cvar_id = user_context->regs[0];
            rc = kCvarSignal(cvar_id);
            user_context->regs[0] = rc;
            break;
        case YALNIX_CVAR_BROADCAST:
            cvar_id = user_context->regs[0];
            rc = kCvarBroadcast(cvar_id);
            user_context->regs[0] = rc;
            break;
        case YALNIX_CVAR_WAIT:
            cvar_id = user_context->regs[0];
            lock_id = user_context->regs[1];
            rc = kCvarWait(cvar_id, lock_id);
            user_context->regs[0] = rc;
            break;
        case YALNIX_RECLAIM:
            id = user_context->regs[0];
            rc = kReclaim(id);
            user_context->regs[0] = rc;
            break;
    }
    TracePrintf(2, "Exiting TrapKernelHandler\n");
}

/**
 * Schedule, but also check waiting queues and handle delayed processes
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

/**
 * Handles the case where this might be an implicit request to grow user stack
 */
int TrapMemory(UserContext *user_context) {
    TracePrintf(2, "CALLING MEMORY TRAP HANDLER!!\n");

    TracePrintf(2, "Address of user context: %p; page: %d\n", user_context->addr,
                (unsigned int)(user_context->addr) >> PAGESHIFT);
    TracePrintf(2, "TrapMemory() called with code %d.\n", user_context->code);

    // Immediately return error if code is not 1
    unsigned int code = user_context->code;
    if (code == 0 || code == 2) {
        TP_ERROR(
            "trap memory given a code 0 (addr outside virtual address range) or 2 (access violates page "
            "protections)\n");
        kExit(-1);
        return ERROR;
    }

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
    int *frames_found = find_n_free_frames(g_frametable, num_pages_to_grow);
    if (frames_found == NULL) {
        TP_ERROR("Failed to grow user stack (ran out of physical memory). Exiting process now.\n");
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
    g_running_pcb->user_stack_base = (void *)DOWN_TO_PAGE((unsigned int)addr);

    return SUCCESS;
}

/*
 * Exit the process that trapped here, unless it is `init`, in which case halt the CPU.
 */
int TrapIllegal(UserContext *user_context) {
    TracePrintf(2, "Entering `TrapIllegal()`...\n");
    int caller_pid = g_running_pcb->pid;
    if (caller_pid != 0) {
        TP_ERROR("Killing PID %d.\n", caller_pid);
        kExit(ERROR);
    } else {
        // this is init that trapped here
        TP_ERROR("`init` process error, halting CPU.\n");
        Halt();
    }
}

/*
 * Exit the process that trapped here, unless it is `init`, in which case halt the CPU.
 */
int TrapMath(UserContext *user_context) {
    TracePrintf(2, "Entering `TrapMath()`...\n");
    int caller_pid = g_running_pcb->pid;
    if (caller_pid != 0) {
        TP_ERROR("Killing PID %d.\n", caller_pid);
        kExit(ERROR);
    } else {
        // this is init that trapped here
        TP_ERROR("`init` process error, halting CPU.\n");
        Halt();
    }
}

/**
 * Helper for terminal trap handlers to wake up waiting procs
 */
bool is_waiting_for_term_id(void *elt, const void *key) {
    pcb_t *pcb = (pcb_t *)elt;
    int tty_id = *((int *)key);
    return (pcb->blocked_term == tty_id);
}

/**
 * If more than `TERMINAL_MAX_LEN` bytes are typed into the terminal, we do not support
 * reading every byte. All we support is reading `TERMINAL_MAX_LEN` bytes. For instance,
 * manual testing of typing an excessive amonut of characters and pressing return resulted
 * in reading far fewer characters, which seems on first inspection to be `TERMINAL_MAX_LEN`
 * number of characters.
 */
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
     * kernel buffer (e.g. from a previous trap).
     */

    // Allocate kernel buffer, if necessary
    if (k_buf->ptr == NULL) {
        k_buf->ptr = malloc(TERMINAL_MAX_LINE);
        if (k_buf->ptr == NULL) {
            TP_ERROR("`malloc()` for kernel buffer failed.\n");
            free(tty_id);
            return ERROR;
        }
        k_buf->curr_pos_offset, k_buf->end_pos_offset = 0;
    }

    // Receive from terminal. This will overwrite whatever is in the kernel buf
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
 * We get here when a call to `TtyTransmit()` has concluded. Recall that the process that
 * called it doesn't wait for it to finish, and doesn't get back on the ready queue, so we
 * need to do that here.
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

/**
 * Exit the process that trapped here, unless it is `init`, in which case halt the CPU.
 */
int TrapDisk(UserContext *user_context) {
    TracePrintf(2, "Entering `TrapDisk()`...\n");
    int caller_pid = g_running_pcb->pid;
    if (caller_pid != 0) {
        TP_ERROR("Killing PID %d.\n", caller_pid);
        kExit(ERROR);
    } else {
        // this is init that trapped here
        TP_ERROR("`init` process error, halting CPU.\n");
        Halt();
    }
}

int GenericHandler(UserContext *user_context) { ; }