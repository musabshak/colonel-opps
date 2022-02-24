#include <stdbool.h>

#include "kernel_data_structs.h"
#include "load_program.h"
#include "ykernel.h"

extern pcb_t *g_running_pcb;
extern queue_t *g_delay_blocked_procs_queue;
extern queue_t *g_ready_procs_queue;
extern pcb_t *g_idle_pcb;
extern unsigned int g_len_pagetable;
extern unsigned int g_num_kernel_stack_pages;
extern pte_t *g_reg0_ptable;
extern int *g_frametable;

int schedule(enum CallerFunc caller_id);
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
    TracePrintf(1, "Calling Brk w/ arg: 0x%x (page: %d)\n", new_brk, (unsigned int)new_brk >> PAGESHIFT);

    pte_t *ptable = g_running_pcb->r1_ptable;
    void *user_brk = g_running_pcb->user_brk;
    void *user_data_end = g_running_pcb->user_data_end;
    unsigned int user_stack_base = (unsigned int)(g_running_pcb->user_stack_base);

    unsigned int new_brk_int = (unsigned int)new_brk;
    unsigned int last_addr_above_data = (unsigned int)(user_data_end);

    TracePrintf(1, "user_stack_base_page: %d\n", user_stack_base >> PAGESHIFT);
    TracePrintf(1, "user_brk_page: %d\n", (unsigned int)user_brk >> PAGESHIFT);

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
    rc = schedule(F_kDelay);

    return rc;
}

int kFork() {
    TracePrintf(1, "Entering kFork\n");

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

    TracePrintf(1, "Exiting kFork\n");
    return SUCCESS;
}

/**
 * `argvec` must be null-terminated. Regardless of if there are any arguments or not,
 * or even if `argvec == NULL`, this function passes the `filename` as the first
 * argument to `LoadProgram`. Now if `filename == NULL`, this will return `ERROR`.
 */
int kExec(char *filename, char **argvec) {

    /* Verify that pointers passed by userland Exec call are legit */

    // TODO: Do we need to check that the pointer is valid, or just that it doesn't point
    // to kernel memory?

    /**
     * Validate `filename`
     */
    if (filename == NULL) {
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
    if (argvec == NULL) {
        // this is allowed, see comment above definition of `argv` below.
        TracePrintf(1, "Error: `Exec()` called with null pointer as pointer to arguments.\n");
        return ERROR;
    } else {
        for (char **argi = argvec; *argi != NULL; argi++) {
            num_args++;
        }
    }
    // should it be num_args += 1 (to check for space occupied by the NULL at the end?)

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
 *      - if status_ptr is not null and is valid, exit status of child is copied to that address
 */
int kWait(int *status_ptr) {

    /**
     * Verify that user-given pointer is valid (user has permissions to write
     * to what the pointer is pointing to
     */
    if (!is_r1_addr(status_ptr) || !is_writeable_addr(g_running_pcb->r1_ptable, (void *)status_ptr)) {
        TracePrintf(1, "kWait passed an invalid pointer!\n");
        return ERROR;
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

        *status_ptr = child_zombie_pcb->exit_status;
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
    schedule(F_kWait);

    *status_ptr = g_running_pcb->last_dying_child_exit_code;
    return g_running_pcb->last_dying_child_pid;
}

void kExit(int status) {
    pcb_t *caller = g_running_pcb;
    pcb_t *parent = caller->parent;

    TracePrintf(1, "PID %d exiting with status %d.\n", caller->pid, status);

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
    schedule(F_kExit);

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
