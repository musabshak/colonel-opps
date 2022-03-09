#include <stdbool.h>

#include "address_validation.h"
#include "k_common.h"
#include "load_program.h"
#include "mbuilder.h"
#include "trap_handlers.h"
#include "ykernel.h"

void kExit(int status);

/**
 * Returns the number of pages in `ptable` marked as valid.
 */
int get_num_valid_pages(pte_t *ptable) {
    int num_valid_pages = 0;

    for (int i = 0; i < g_len_pagetable; i++) {
        if (ptable[i].valid == 1) {
            num_valid_pages++;
        }
    }

    return num_valid_pages;
}

int kFork() {
    TracePrintf(2, "Entering kFork\n");

    pcb_t *parent_pcb = g_running_pcb;
    pte_t *parent_r1_ptable = parent_pcb->r1_ptable;

    // Helps with error handling successive `malloc()` calls
    m_builder_t *malloc_builder = m_builder_init();
    if (malloc_builder == NULL) {
        TP_ERROR("`malloc()` failed for `malloc_builder`.\n");
        return ERROR;
    }

    // Allocate a PCB for child process. Returns virtual address in kernel heap.
    pcb_t *child_pcb = m_builder_malloc(malloc_builder, RawPerm, sizeof(*child_pcb));
    if (child_pcb == NULL) {
        TP_ERROR("`malloc()` failed for new PCB.\n");
        m_builder_unwind(malloc_builder);
        return ERROR;
    }

    // Allocate a new R1 ptable for child process. Will later copy contents of parent's R1 pable
    // into this ptable.
    pte_t *child_r1_ptable =
        (pte_t *)m_builder_malloc(malloc_builder, RawPerm, sizeof(pte_t) * g_len_pagetable);
    if (child_r1_ptable == NULL) {
        TP_ERROR("`malloc()` failed for new R1 pagetable.\n");
        m_builder_unwind(malloc_builder);
        return ERROR;
    }

    // Ensure there are enough frames in physical memory to copy the current
    // process. If there are not, then abort the process.

    int num_frames_needed = get_num_valid_pages(parent_r1_ptable);
    int *frames_for_r1 = m_builder_malloc(malloc_builder, FrameArr, num_frames_needed);
    if (frames_for_r1 == NULL) {
        TP_ERROR("Failed to find free frames.\n");
        m_builder_unwind(malloc_builder);
        return ERROR;
    }

    // Initialize child's r1 pagetable to fully copy (not COW) parent's R1 pagetable.
    int num_frames_assigned = 0;
    for (int i = 0; i < g_len_pagetable; i++) {
        child_r1_ptable[i] = parent_r1_ptable[i];  // COW but ...

        if (parent_r1_ptable[i].valid == 0) {
            // nothing to copy
            continue;
        }

        int free_frame_idx = frames_for_r1[num_frames_assigned];

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
        num_frames_assigned++;
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

    child_pcb->zombie_procs = (queue_t *)m_builder_malloc(malloc_builder, QueuePerm, 0);
    if (child_pcb->zombie_procs == NULL) {
        TP_ERROR("`malloc()` failed for zombie process queue.\n");
        // clean up before returning
        helper_retire_pid(child_pcb->pid);
        m_builder_unwind(malloc_builder);

        return ERROR;
    }

    child_pcb->children_procs = (queue_t *)m_builder_malloc(malloc_builder, QueuePerm, 0);
    if (child_pcb->children_procs == NULL) {
        TP_ERROR("`malloc()` failed for child process queue.\n");
        // clean up before returning
        helper_retire_pid(child_pcb->pid);
        m_builder_unwind(malloc_builder);
        return ERROR;
    }

    child_pcb->exit_status = -1;
    child_pcb->is_wait_blocked = 0;

    // Indicate in the parent PCB that a child has been born
    if (parent_pcb->children_procs == NULL) {
        parent_pcb->children_procs = qopen();
        if (parent_pcb->children_procs == NULL) {
            TP_ERROR("`malloc()` failed for parent child process queue.\n");
            // clean up before returning
            helper_retire_pid(child_pcb->pid);
            m_builder_unwind(malloc_builder);
            return ERROR;
        }
    }
    qput(parent_pcb->children_procs, child_pcb);

    // Get free frames for child's kernel stack
    int *frames_for_kstack = m_builder_malloc(malloc_builder, FrameArr, g_num_kernel_stack_pages);
    if (frames_for_kstack == NULL) {
        TP_ERROR("Failed to find frames for child's kernel stack.\n");
        // clean up before returning
        helper_retire_pid(child_pcb->pid);
        m_builder_unwind(malloc_builder);
        return ERROR;
    }

    for (int i = 0; i < g_num_kernel_stack_pages; i++) {
        child_pcb->kstack_frame_idxs[i] = frames_for_kstack[i];
    }

    // uctxt->pc = g_running_pcb->uctxt.pc;  // !!!!!!!!!!
    // uctxt->sp = g_running_pcb->uctxt.sp;  // !!!!!!!!!!

    // Return value of 0 for the child, parent receives pid of child
    child_pcb->uctxt.regs[0] = 0;
    parent_pcb->uctxt.regs[0] = child_pcb->pid;

    // Put child on ready queue
    qput(g_ready_procs_queue, (void *)child_pcb);

    // Clean up
    m_builder_conclude(malloc_builder);

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
 * If init exits, the system should be halted.
 */
void kExit(int status) {

    // TODO: should check if `status` here is valid? Someone could try passing an address here
    // disguised as an int?

    pcb_t *caller = g_running_pcb;
    pcb_t *parent = caller->parent;

    TracePrintf(1, "PID %d exiting with status %d.\n", caller->pid, status);

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
     * to what the pointer is pointing to)
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

/** =============
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
