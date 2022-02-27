#include <stdbool.h>

#include "kernel_data_structs.h"
#include "load_program.h"
#include "printing.h"
#include "ykernel.h"

// putting this in [kernel_data_structs.h] caused issues
extern term_buf_t g_term_bufs[NUM_TERMINALS];

void kExit(int status);

/**
 * Checks if the address lies in region 1. (1 means it does, 0 means it doesn't)
 */
bool is_r1_addr(void *addr) {
    unsigned int addr_page = ((unsigned int)(addr) >> PAGESHIFT);
    if (addr_page < g_len_pagetable || addr_page >= 2 * MAX_PT_LEN) {
        // the address points to r0 (kernel) memory, or past r1 memory

        return false;
    }

    TracePrintf(2, "is an R1 address!\n");
    return true;
}

/**
 * Check that the address pointed to by a pointer passed from userland, is write-able.
 */

bool is_writeable_addr(pte_t *r1_ptable, void *addr) {

    // Check that pointer is a valid R1 pointer
    if (!is_r1_addr(addr)) {
        TracePrintf(1, "Pointer is not pointing to an R1 addr\n");
        return false;
    }

    // Check for write permissions in the pagetable
    unsigned int addr_page = ((unsigned int)addr) >> PAGESHIFT;

    // It is safe to do this because we know the address in in region 1
    addr_page = addr_page % g_len_pagetable;

    if (r1_ptable[addr_page].prot & PROT_WRITE == PROT_WRITE) {
        TracePrintf(2, "is a writeable address!\n");
        return true;
    }

    TracePrintf(2, "is not a writeable address!\n");
    return false;
}

/**
 * Similar to `is_valid_array()`, but for strings, and for read-only access.
 */
bool is_readable_str(pte_t *r1_ptable, char *str) {
    // We iterate in this way so that we even validate the terminating character
    for (char *pointer_to_char = str;; pointer_to_char++) {
        int should_break = 0;
        if (*pointer_to_char == '\0') {
            should_break = 1;
        }

        if (is_r1_addr((void *)pointer_to_char) == false) {
            return false;
        }

        unsigned int addr_page = ((unsigned int)(str) >> PAGESHIFT);
        addr_page = addr_page % g_len_pagetable;

        if (r1_ptable[addr_page].prot & PROT_READ != PROT_READ) {
            return false;
        }

        if (should_break == 1) {
            break;
        }
    }

    return true;
}

/**
 * Given an array (a pointer to the first element of an array), with length `array_len`,
 * check if each address in the array is accessible by the user under protection `prot`.
 *
 * For instance, if the user is trying to (just) write to this array, we might call this
 * with `prot = PROT_WRITE`. Note that this just checks if the permissions include `prot`,
 * not that the permissions are exactly `prot`. In this example, acessing a page with
 * protection `PROT_READ | PROT_WRITE` would still be valid, as it includes `PROT_WRITE`.
 *
 * Note that buffers are just character arrays.
 */
bool is_valid_array(pte_t *r1_ptable, void *array, int array_len, int prot) {
    for (int i = 0; i < array_len; i++) {
        void *addr = array + i;
        if (is_r1_addr(addr) == false) {
            // address is not in region 1
            return false;
        }

        unsigned int addr_page = ((unsigned int)(addr) >> PAGESHIFT);
        // It is safe to do this because we know the address in in region 1
        addr_page = addr_page % g_len_pagetable;

        // See if the pagetable has the same protections the user is asking the kernel to
        // to utilize. We do this by checking if adding the protections in `prot` to the
        // existing one in the pagetable will result in the same protection that the pagetable
        // originally had. If it is the same, then that page must have already included
        // `prot` (potentially it may have included more permissions).
        if (r1_ptable[addr_page].prot & prot != prot) {
            return false;
        }
    }

    return true;
}

int kGetPid() {
    // Confirm that there is a process that is currently running
    if (g_running_pcb == NULL) {
        return ERROR;
    }

    return g_running_pcb->pid;
}

int kBrk(void *new_brk) {
    TracePrintf(2, "Calling Brk w/ arg: 0x%x (page: %d)\n", new_brk, (unsigned int)new_brk >> PAGESHIFT);

    pte_t *ptable = g_running_pcb->r1_ptable;
    void *user_brk = g_running_pcb->user_brk;
    void *user_data_end = g_running_pcb->user_data_end;
    unsigned int user_stack_base = (unsigned int)(g_running_pcb->user_stack_base);

    unsigned int new_brk_int = (unsigned int)new_brk;
    unsigned int last_addr_above_data = (unsigned int)(user_data_end);

    TracePrintf(2, "user_stack_base_page: %d\n", user_stack_base >> PAGESHIFT);
    TracePrintf(2, "user_brk_page: %d\n", (unsigned int)user_brk >> PAGESHIFT);

    // Fail if new_brk lies anywhere but the region above kernel data and below kernel stack.
    // Leave 1 page between kernel heap and stack (red zone!)
    if (!(new_brk_int <= (user_stack_base - PAGESIZE) && new_brk_int >= last_addr_above_data)) {
        TracePrintf(1,
                    "oh no .. trying to extend user brk into user stack (or user "
                    "data/text)\n");
        return ERROR;
    }

    // Determine whether raising brk or lowering brk
    int bytes_to_raise = new_brk - user_brk;

    int rc = ERROR;

    if (bytes_to_raise == 0) {
        rc = 0;
    }
    // raising brk
    else if (bytes_to_raise > 0) {
        rc = raise_brk_user(new_brk, user_brk, ptable);
    }
    // reducing brk
    else {
        rc = lower_brk_user(new_brk, user_brk, ptable);
    }

    g_running_pcb->user_brk = (void *)(UP_TO_PAGE(new_brk_int));

    return rc;
}

/**  =============
 *  === DELAY ===
 *  =============
 *
 *  From manual (p. 33):
 *      The calling process is blocked until at least clock ticks clock interrupts
 *      have occurred after the call. Upon completion of the delay, the value 0 is
 *      returned.
 *      If clock ticks is 0, return is immediate. If clock ticks is less than 0,
 *      time travel is not carried out, and ERROR is returned instead.
 */
int kDelay(int clock_ticks) {
    if (clock_ticks < 0) {
        return ERROR;
    }
    if (clock_ticks == 0) {
        return 0;
    }

    int rc;

    g_running_pcb->elapsed_clock_ticks = 0;
    g_running_pcb->delay_clock_ticks = clock_ticks;

    // Call the scheduler
    rc = schedule(g_delay_blocked_procs_queue);

    return rc;
}

int kFork() {
    TracePrintf(2, "Entering kFork\n");

    pcb_t *parent_pcb = g_running_pcb;
    pte_t *parent_r1_ptable = parent_pcb->r1_ptable;

    // Allocate a PCB for child process. Returns virtual address in kernel heap.
    pcb_t *child_pcb = malloc(sizeof(*child_pcb));
    if (child_pcb == NULL) {
        TracePrintf(1, "malloc for kFork()'s PCB failed.\n");
        return ERROR;
    }

    // Allocate a new R1 ptable for child process. Will later copy contents of parent's R1 pable
    // into this ptable.
    pte_t *child_r1_ptable = malloc(sizeof(pte_t) * g_len_pagetable);
    if (child_r1_ptable == NULL) {
        TracePrintf(1, "Malloc failed for `kFork()`'s pagetable.\n");
        return ERROR;
    }

    // Initialize child's r1 pagetable to fully copy (not COW) parent's R1 pagetable.
    for (int i = 0; i < g_len_pagetable; i++) {
        child_r1_ptable[i] = parent_r1_ptable[i];  // COW but ...

        if (parent_r1_ptable[i].valid == 0) {
            continue;
        }

        // Allocate new frame for the child's R1 page
        int free_frame_idx = find_free_frame(g_frametable);
        if (free_frame_idx == -1) {
            TracePrintf(1, "Couldn't find free frame while forking.\n");
            return ERROR;
        }
        g_frametable[free_frame_idx] = 1;

        /**
         * Note that the child's R1 ptable, although allocated, has not been "mounted". That is,
         * the child's R1 ptable is not active (we haven't written the address of the new ptable in
         * the registers).
         *
         * This means that for copying the contents of the parent's R1 page, we need to utilize the
         * trick of temporarily mapping the page under the kernel stack to the newly allocated frame,
         * and then copying into this special page.
         *
         * Remember to flush the TLB for this special page, and also to set this special page as invalid
         * after use!
         */

        // Write to newly allocated frame by mapping it to the page below kernel stack and writing to that
        // page.
        unsigned int page_below_kstack = MAX_PT_LEN - g_num_kernel_stack_pages - 1;
        g_reg0_ptable[page_below_kstack].valid = 1;
        g_reg0_ptable[page_below_kstack].prot = PROT_READ | PROT_WRITE;
        g_reg0_ptable[page_below_kstack].pfn = free_frame_idx;

        WriteRegister(REG_TLB_FLUSH, page_below_kstack << PAGESHIFT);

        memcpy((void *)(page_below_kstack << PAGESHIFT), (void *)((MAX_PT_LEN + i) << PAGESHIFT), PAGESIZE);

        g_reg0_ptable[page_below_kstack].valid = 0;

        // Assign this new frame to the new pagetable
        child_r1_ptable[i].pfn = free_frame_idx;
    }

    // Now clone parent pcb into the child pcb allocated at the top. Note that the user context of the parent
    // is copied into the child's PCB with this memcpy call (since we're storing the user context as a struct
    // and not as a pointer to a struct).
    memcpy(child_pcb, parent_pcb, sizeof(pcb_t));

    /**
     * After cloning parent_pcb into child_pcb, need to change the following pcb->*:
     *      - pid
     *      - parent
     *      - r1_ptable
     *      - children_procs
     */
    child_pcb->pid = helper_new_pid(child_r1_ptable);  // hardware defined function for generating PID
    child_pcb->parent = parent_pcb;
    child_pcb->r1_ptable = child_r1_ptable;

    /**
     * Need to initialize the following new pcb attributes:
     *      - zombie_procs
     *      - children_procs
     *      - exit_status
     *      - is_wait_blocked
     */

    child_pcb->zombie_procs = qopen();
    child_pcb->children_procs = qopen();
    child_pcb->exit_status = -1;
    child_pcb->is_wait_blocked = 0;

    // Indicate in the parent PCB that a child has been born
    if (parent_pcb->children_procs == NULL) {
        parent_pcb->children_procs = qopen();
    }
    qput(parent_pcb->children_procs, child_pcb);

    // Get free frames for idle's kernel stack
    for (int i = 0; i < g_num_kernel_stack_pages; i++) {
        int idx = find_free_frame(g_frametable);
        if (idx == -1) {
            TracePrintf(
                1, "In `kFork()`, `find_free_frame()` failed while allocating frames for kernel_stack\n");
            return ERROR;
        }
        g_frametable[idx] = 1;

        child_pcb->kstack_frame_idxs[i] = idx;
    }

    // uctxt->pc = g_running_pcb->uctxt.pc;  // !!!!!!!!!!
    // uctxt->sp = g_running_pcb->uctxt.sp;  // !!!!!!!!!!

    // Return value of 0 for the child, parent receives pid of child
    child_pcb->uctxt.regs[0] = 0;
    parent_pcb->uctxt.regs[0] = child_pcb->pid;

    // Put child on ready queue
    qput(g_ready_procs_queue, (void *)child_pcb);

    // Copy current kernel stack contents into child pcb's kernel stack frames
    int rc = KernelContextSwitch(KCCopy, child_pcb, NULL);

    TracePrintf(2, "Exiting kFork\n");
    return SUCCESS;
}

/**
 * `argvec` must be null-terminated. Regardless of if there are any arguments or not,
 * or even if `argvec == NULL`, this function passes the `filename` as the first
 * argument to `LoadProgram`. Now if `filename == NULL`, this will return `ERROR`.
 */
int kExec(char *filename, char **argvec) {

    /* Verify that pointers passed by userland Exec call are legit */

    /**
     * Validate `filename`
     */
    if (filename == NULL) {
        // TP_ERROR("`NULL` was passed as a file name to `kExec()` %d %s.\n", 1, "hi");
        TracePrintf(1, "`NULL` was passed as a file name to `kExec()`.\n");
        return ERROR;
    } else if (is_readable_str(g_running_pcb->r1_ptable, filename) == false) {
        TracePrintf(1, "`filename` passed to `kExec()` was invalid.\n");
        return ERROR;
    }

    /**
     * Validate `argvec` and each `char *` contained inside
     */
    int num_args = 0;

    // The user must provide at least one argument in the argvec array (the file name)
    if (argvec == NULL) {
        TP_ERROR("`Exec()` called with null pointer as pointer to arguments.\n");
        // TracePrintf(1, "Error: `Exec()` called with null pointer as pointer to arguments.\n");
        return ERROR;
    } else {
        for (char **argi = argvec; *argi != NULL; argi++) {
            num_args++;
        }
    }

    if (num_args == 0) {
        // nothing to validate
        TracePrintf(1, "Error: `Exec()` called with no arguments.\n");
        return ERROR;
    } else {
        // We validate `num_args + 1` since technically the user is attempting to read even the
        // `NULL` argument.
        if (is_valid_array(g_running_pcb->r1_ptable, (void *)argvec, num_args + 1, PROT_READ) == false) {
            TracePrintf(1, "Invalid `argvec` passed to `kExec()`.\n");
            return ERROR;
        }
    }

    // Validate each char * contained in argvec
    for (int i = 0; i < num_args; i++) {
        if (is_readable_str(g_running_pcb->r1_ptable, argvec[i]) == false) {
            TracePrintf(1, "In `kExec()`, `argvec` contains invalid string.\n");
            return ERROR;
        }
    }

    int rc = LoadProgram(filename, argvec, g_running_pcb);

    if (rc != SUCCESS) {
        // We need to decide what to do here-- the caller pcb has been destroyed

        // Completely destroy the calling PCB and reschedule processes
        TracePrintf(1, "`kExec()` failed! Killing process (PID %d).\n", g_running_pcb->pid);
        kExit(ERROR);
        // not reached
    }

    return SUCCESS;
}

/**
 * Returns
 *      - pid of child process
 *      - exit status of child is copied to the address (status_ptr) passed to kWait as an argument, if
 *        status_ptr is valid. If it is not valid nothing bad happens but the exit code is not written into
 *        the pointer.
 */
int kWait(int *status_ptr) {

    bool is_valid_ptr = true;
    /**
     * Verify that user-given pointer is valid (user has permissions to write
     * to what the pointer is pointing to
     */
    if (!is_r1_addr(status_ptr) || !is_writeable_addr(g_running_pcb->r1_ptable, (void *)status_ptr)) {
        TracePrintf(
            1, "kWait passed an invalid pointer -- kWait will not write exit status into passed address\n");
        is_valid_ptr = false;
    }

    /**
     * "If the caller has an exited child whose information has not yet been collected via Wait, then this
     * call will return immediately with that information".
     *
     * Check if g_running_pcb->zombie_procs is empty. If it is not empty (that is, there exists an exited
     * child whose information has not yet been collected), then return information of first child process
     * from zombie_procs. Also, destroy the ZombiePCB of the child process.
     */

    if (g_running_pcb->zombie_procs == NULL) {
        g_running_pcb->zombie_procs = qopen();
    }

    queue_t *zombie_procs = g_running_pcb->zombie_procs;
    queue_t *children_procs = g_running_pcb->children_procs;
    if (!qis_empty(zombie_procs)) {
        zombie_pcb_t *child_zombie_pcb = (zombie_pcb_t *)qget(zombie_procs);

        // Destroy zombie PCB
        free(child_zombie_pcb);

        if (is_valid_ptr) {
            *status_ptr = child_zombie_pcb->exit_status;
        }
        return child_zombie_pcb->pid;
    }

    /**
     * "If the caller has no remaining child processes (exited or running) then return ERROR".
     */

    if (qlen(zombie_procs) == 0 && qlen(children_procs) == 0) {
        return ERROR;
    }

    /**
     * "Otherwise the calling process blocks until its next child calls exit or is aborted; then the call
     * returns with the exit information of the child".
     *
     * - Move g_running_pcb into g_wait_blocked_procs_queue;
     * - Mark g_running_pcb->is_wait_blocked = 1
     */

    g_running_pcb->is_wait_blocked = 1;

    // Parent needs to block
    schedule(NULL);

    if (is_valid_ptr) {
        *status_ptr = g_running_pcb->last_dying_child_exit_code;
    }
    return g_running_pcb->last_dying_child_pid;
}

/**
 * If init exits, the system should be halted.
 */
void kExit(int status) {
    pcb_t *caller = g_running_pcb;
    pcb_t *parent = caller->parent;

    TracePrintf(2, "PID %d exiting with status %d.\n", caller->pid, status);

    if (g_running_pcb->pid == 0) {
        TracePrintf(1, "Oh no, init process exited; the CPU will now halt\n");
        Halt();
    }

    // See `destroy_pcb()` for details. Essentially, this frees all memory associated with the
    // pcb (except its parent and children). If the parent is not `NULL`, it adds the exit
    // status and its pid as a zombie to the parent's zombie queue.
    int rc = destroy_pcb(caller, status);

    if (parent == NULL) {  // orphan process
        ;
    } else if (parent->is_wait_blocked == 1) {
        zombie_pcb_t *exit_info = qget(parent->zombie_procs);
        parent->last_dying_child_exit_code = exit_info->exit_status;
        parent->last_dying_child_pid = exit_info->pid;
        free(exit_info);

        parent->is_wait_blocked = 0;
        qput(g_ready_procs_queue, parent);
    }

    g_running_pcb = NULL;  // the pcb g_running_pcb was previosuly pointing to, has been destroyed
    schedule(NULL);

    /**
     * For every child pcb in g_running_pcb->children_procs, mark child_pcb->parent = NULL.
     */

    /**
     * If g_running_pcb->parent == NULL (orphan process), do not need to save or report exit status.
     * Proceed to freeing all resources associated with process.
     */

    /**
     * If g_running_pcb->parent->is_wait_blocked == 0:
     *      - Put g_running_pcb into parent->zombie_procs
     *      - Free all resources other than pcb->exit_status and pcb->pid
     *      - The remaining pcb resources are freed when parent calls kWait eventually
     */

    /**
     * If g_running_pcb->parent->is_wait_blocked == 1:
     *      - (parent is actively waiting to hear news about child dying)
     *      - (doesn't make sense to put child in zombie queue)
     *      - Somehow need to wake up parent and tell parent the pid and the exit status
     *          - Populate parent->last_dying_child_pid, parent->last_dying_child_status
     *          - Remove parent from g_wait_blocked_queue
     *          - Put parent into g_ready_procs_queue
     *      - Free all resources associated with g_running_pcb
     */
}

/**
 * (From manual)
 *
 * Read the next line of input from terminal `tty_id`, copying it into the buffer
 * referenced by `buf`. The maximum length of the line to be returned is given by `len`.
 *
 * Note: The line returned in the buffer is not null-terminated.
 *
 * Return behavior:
 *  - If there are sufficient unread bytes already waiting, the call will return right away,
 *  with those.
 *  - Otherwise, the calling process is blocked until a line of input is available to be
 *  returned.
 *      - If the length of the next available input line is longer than `len` bytes, only the
 *      first `len` bytes of the line are copied to the calling process, and the remaining
 *      bytes of the line are saved by the kernel for the next `TtyRead()` (by this or another
 *      process).
 *      - If the length of the next available input line is shorter than len bytes, only as
 *      many bytes are copied to the calling process as are available in the input line; On
 *      success, the number of bytes actually copied into the calling process’s buffer is
 *      returned; in case of any error, the value ERROR is returned.
 */

/**
 * If there bytes left in the buffer from the previous read, do we still need to
 * receive from the terminal? This implementation assumes we do NOT.
 *
 * If I understand correctly, WRITING more than `TERMINAL_MAX_LINE` is valid and should
 * be supported, but READING more than `TERMINAL_MAX_LINE` is undefined. So here I
 * exit with error if that is attempted.
 */
int kTtyRead(int tty_id, void *buf, int len) {
    TracePrintf(2, "Entering `TtyRead()`...\n");

    /**
     * Validate user inputs
     */

    if (!(tty_id >= 0 && tty_id < NUM_TERMINALS)) {
        TP_ERROR("tried to read from an invalid terminal.\n");
        return ERROR;
    }

    if (!(is_valid_array(g_running_pcb->r1_ptable, buf, len, PROT_READ | PROT_WRITE))) {
        TP_ERROR("the `buf` that was passed was not valid.\n");
        return ERROR;
    }

    if (len > TERMINAL_MAX_LINE) {
        TP_ERROR("attempted to read more than `TERMINAL_MAX_LINE` from terminal.\n");
        return ERROR;
    }

    /**
     * If there isn't an input line from the terminal ready to go, block this process
     * until there is. We detect this by seeing if the corresponding kernel buf for this
     * terminal is `NULL`.
     */
    term_buf_t k_buf = g_term_bufs[tty_id];

    if (k_buf.ptr == NULL) {
        g_running_pcb->blocked_term = tty_id;
        schedule(g_term_blocked_procs_queue);
    }

    /**
     * There is now an input line ready to be read. So copy that over.
     */

    int bytes_remaining_in_kbuf = k_buf.end_pos_offset - k_buf.curr_pos_offset;

    // Copy over to user buf, clear kernel buf, and return
    if (bytes_remaining_in_kbuf <= len) {
        memcpy(buf, k_buf.ptr + k_buf.curr_pos_offset, len);
        free(k_buf.ptr);  // TODO: abstract this "clearing" into a function
        k_buf.ptr = NULL;
        k_buf.curr_pos_offset, k_buf.end_pos_offset = 0;
        return len;
    }

    // Copy over `len` bytes from the kernel buf, update kernel buf accordingly
    // to make it available for future reading. Return.
    else if (bytes_remaining_in_kbuf > len) {
        memcpy(buf, k_buf.ptr + k_buf.curr_pos_offset, len);
        k_buf.curr_pos_offset += len;
        return len;
    }

    /**
     * Block until more lines are received
     *
     */

    //     This now lives in TrapTtyReceive, which I think(?) is the right place for it
    //
    //     /**
    //      * Copy terminal data into kernel buffer
    //      */

    //     // allocate kernel buffer, if necessary
    //     if (k_buf.ptr == NULL) {
    //         k_buf.ptr = malloc(TERMINAL_MAX_LINE);
    //         if (k_buf.ptr == NULL) {
    //             TP_ERROR("`malloc()` for kernel buffer failed.\n");
    //             return ERROR;
    //         }
    //         k_buf.curr_pos_offset, k_buf.end_pos_offset = 0;  // not really necessary, I think
    //     }

    //     // receive from terminal. This will overwrite whatever is in the kernel buf
    //     int bytes_received = TtyReceive(tty_id, k_buf.ptr, TERMINAL_MAX_LINE);
    //     k_buf.end_pos_offset = bytes_received;

    //     /**
    //      * Now we wish to copy from the kernel buffer to the user buffer. Possible cases:
    //      *  - bytes received from terminal < `len` requested by user
    //      *  - `bytes_received` == `len`
    //      *  - `bytes_received` > `len`
    //      */

    //     // Copy `bytes_received` bytes into `buf`, and return the number of bytes copied
    //     if (bytes_received == len) {
    //         memcpy(buf, k_buf.ptr, len);
    //         // No need to keep the kernel buf since all of its data has been copied
    //         free(k_buf.ptr);
    //         k_buf.ptr = NULL;
    //         k_buf.curr_pos_offset, k_buf.end_pos_offset = 0;
    //         return len;
    //     }
    //     // Copy `bytes_received` bytes into `buf`, and return the number of bytes copied
    //     else if (bytes_received < len) {
    //         memcpy(buf, k_buf.ptr, bytes_received);
    //         // No need to keep the kernel buf since all of its data has been copied
    //         free(k_buf.ptr);
    //         k_buf.ptr = NULL;
    //         k_buf.curr_pos_offset, k_buf.end_pos_offset = 0;
    //         return bytes_received;
    //     }
    //     // Copy `len` bytes into `buf`, keep the rest in the kernel buf
    //     else if (bytes_received > len) {
    //         memcpy(buf, k_buf.ptr, len);
    //         // adjust the start position of the kernel buffer to indicate where we should
    //         // start reading from upon the next call to ready from this terminal.
    //         k_buf.curr_pos_offset += len;
    //         return len;
    //     }
    //
}

/**
 * Write the contents of the buffer referenced by buf to the terminal tty id. The length
 * of the buffer in bytes is given by `len`. The calling process is blocked until all
 * characters from the buffer have been written on the terminal. On success, the number of
 * bytes written (`len`) is returned; in case of any error, the value `ERROR` is returned.
 *
 * Calls to TtyWrite for more than TERMINAL MAX LINE bytes should be supported.
 */
int kTtyWrite(int tty_id, void *buf, int len) {
    void *current_byte = buf;
    int bytes_remaining = len;

    while (bytes_remaining > 0) {
        if (bytes_remaining < TERMINAL_MAX_LINE) {
            TtyTransmit(tty_id, current_byte, bytes_remaining);
            // Block until this operation completes
            g_running_pcb->blocked_term = tty_id;
            schedule(g_term_blocked_procs_queue);
            break;
        }

        TtyTransmit(tty_id, current_byte, TERMINAL_MAX_LINE);
        // Block until this operation completes
        g_running_pcb->blocked_term = tty_id;
        schedule(g_term_blocked_procs_queue);

        current_byte += TERMINAL_MAX_LINE;
        bytes_remaining -= TERMINAL_MAX_LINE;
    }

    return len;
}
