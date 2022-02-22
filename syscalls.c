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

int schedule(int is_caller_clocktrap);
int is_r0_addr(void *addr);
int r1ptable_buf_is_valid(pte_t *r1_ptable, void *buf, int buf_len, int prot);
int r1ptable_string_is_readable(pte_t *r1_ptable, char *str);

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
    rc = schedule(0);

    return rc;
}

int kFork() {
    TracePrintf(1, "Entering kFork\n");

    pcb_t *parent_pcb = g_running_pcb;
    pte_t *parent_r1_ptable = parent_pcb->r1_ptable;

    // Allocate a PCB for child process. Returns virtual address in kernel heap.
    pcb_t *child_pcb = malloc(sizeof(*g_idle_pcb));
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
    child_pcb->children_procs = NULL;

    // Indicate in the parent PCB that a child has been born
    // qput(parent_pcb->children_procs, child_pcb);

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

int kExec(char *filename, char **argvec) {

    /* Verify that pointers passed by userland Exec call are legit */

    // Do we need to check that the pointer is valid, or just that it doesn't point
    // to kernel memory?

    // Validate `filename`
    // for (char *addr = filename; *addr != '\0'; addr++) {
    //     if (is_r0_addr((void *)addr) == 1) {
    //         TracePrintf(1, "Caller to `kExec()` tried to access kernel memory!\n");
    //         return ERROR;
    //     }
    // }
    if (r1ptable_string_is_readable(g_running_pcb->r1_ptable, filename) == 0) {
        TracePrintf(1, "`filename` passed to `kExec()` was invalid.\n");
        return ERROR;
    }

    // Validate `argvec` and each `char *` it points to
    // for (char **argi = argvec; argi != NULL; argi++) {
    //     if (is_r0_addr((void *)argi) == 1) {
    //         TracePrintf(1, "Caller to `kExec()` tried to access kernel memory!\n");
    //         return ERROR;
    //     }

    //     // Check if this is the last argument
    //     if (*argi == NULL) {
    //         break;
    //     }

    //     for (char *argi_addr = *argi; *argi_addr != '\0'; argi_addr++) {
    //         if (is_r0_addr((void *)argi_addr) == 1) {
    //             TracePrintf(1, "Caller to `kExec()` tried to access kernel memory!\n");
    //             return ERROR;
    //         }
    //     }
    // }
    int num_args = 0;
    for (char **argi = argvec; *argi != NULL; argi++) {
        num_args++;
    }

    if (r1ptable_buf_is_valid(g_running_pcb->r1_ptable, (void *)argvec, num_args, PROT_READ) == 0) {
        TracePrintf(1, "Invalid `argvec` passed to `kExec()`.\n");
        return ERROR;
    }

    for (int i = 0; i < num_args; i++) {
        if (r1ptable_string_is_readable(g_running_pcb->r1_ptable, argvec[i]) == 0) {
            TracePrintf(1, "In `kExec()`, `argvec` contains invalid string.\n");
            return ERROR;
        }
    }

    int rc = LoadProgram(filename, argvec, g_running_pcb);
    if (rc != SUCCESS) {
        // We need to decide what to do here-- the caller pcb has been destroyed
    }

    return SUCCESS;
}

int kWait(int *status_ptr) {

    /**
     * Verify that user-given pointer is valid (user has permissions to write
     * to what the pointer is pointing to
     */

    /**
     * "If the caller has an exited child whose information has not yet been collected via Wait, then this
     * call will return immediately with that information".
     *
     * Check if g_running_pcb->zombie_procs is empty. If it is not empty (that is, there exists and exited
     * child whose information has not yet been collected), then return information of first child process
     * from zombie_procs. Also destroy the pcb of the child process completely.
     */

    /**
     * "If the caller has no remaining child processes (exited or running) then return ERROR".
     *
     * If len(g_running_pcb->zombie_procs) == 0 and len(g_running_pcb->children_procs) == 0:
     *      return ERROR
     */

    /**
     * "Otherwise the calling process blocks until its next child calls exit or is aborted; then the call
     * returns with the exit information of the child".
     *
     * - Move g_running_pcb into g_wait_blocked_procs_queue;
     * - Mark g_running_pcb->is_wait_blocked = 1
     */

    /**
     * Return
     *      - pid of child process
     *      - if status_ptr is not null and is valid, exit status of child is copied to that address
     */
}

void kExit(int status) {

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

int is_r0_addr(void *addr) {
    unsigned int addr_page = ((unsigned int)(addr) >> PAGESHIFT);
    if (addr_page < g_len_pagetable) {
        // the address points to region 0 (kernel) memory
        return 1;
    }

    return 0;
}

int addr_is_in_r1(void *addr) {
    unsigned int addr_page = ((unsigned int)(addr) >> PAGESHIFT);
    if (addr_page < g_len_pagetable || addr_page >= 2 * MAX_PT_LEN) {
        // the address points to r0 (kernel) memory, or past r1 memory
        return 0;
    }

    return 1;
}

/**
 * 0 is invalid, 1 is valid
 */
int r1ptable_buf_is_valid(pte_t *r1_ptable, void *buf, int buf_len, int prot) {
    for (int i = 0; i < buf_len; i++) {
        void *addr = buf + i;
        if (addr_is_in_r1(addr) == 0) {
            // address is not in region 1
            return 0;
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
            return 0;
        }
    }

    return 1;
}

/**
 * Similar to `r1ptable_buf_is_valid()`, but for strings.
 */
int r1ptable_string_is_readable(pte_t *r1_ptable, char *str) {
    for (char *pointer_to_char = str; *pointer_to_char != '\0'; pointer_to_char++) {
        if (addr_is_in_r1((void *)pointer_to_char) == 0) {
            return 0;
        }

        unsigned int addr_page = ((unsigned int)(str) >> PAGESHIFT);
        addr_page = addr_page % g_len_pagetable;

        if (r1_ptable[addr_page].prot & PROT_READ != PROT_READ) {
            return 0;
        }
    }
    // still check the last '\0'?

    return 1;
}
