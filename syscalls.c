#include <stdbool.h>

#include "kernel_data_structs.h"
#include "load_program.h"
#include "printing.h"
#include "trap_handlers.h"
#include "ykernel.h"

/**
 * This is how we handle "locked" access to terminals (only one process can use a terminal
 * at a time). This method only works because we are the kernel.
 *
 * Each entry in the array represents the terminal with id corresponding to its index.
 * `0` indicates that no process is using the terminal. A nonzero value should represent
 * that the process with that PID is using the terminal, e.g. if `term_status[0] == 2` then
 * this means PID 2 is using terminal 0.
 */
int term_read_status[NUM_TERMINALS] = {0, 0, 0, 0};
int term_write_status[NUM_TERMINALS] = {0, 0, 0, 0};

// putting this in [kernel_data_structs.h] caused issues
extern term_buf_t *g_term_bufs[NUM_TERMINALS];

void kExit(int status);

/**
 * Used as "search" fxn in qremove_all (in kPipeWrite).
 *
 * Does two things
 *      - Puts process on ready queue
 *      - returns true
 * Otherwise
 *      - returns false
 */
bool put_proc_on_ready_queue(void *elementp, const void *key) {

    pcb_t *proc = (pcb_t *)elementp;

    qput(g_ready_procs_queue, proc);
    return true;
}

/**
 * Pipe buffer enqueue.
 *
 * Returns ERROR if anythign goes wrong, and success if everything goes right.
 *
 * Idea: https://www.geeksforgeeks.org/circular-queue-set-1-introduction-array-implementation/
 */

int circular_enqueue(pipe_t *pipe, char byte_to_write) {

    // Just to be safe, check this
    if (pipe->curr_num_bytes == PIPE_BUFFER_LEN) {
        TP_ERROR("Trying to enqueue into a full pipe!\n");
        return ERROR;
    }

    if (pipe->front == -1) {  // insert first element
        pipe->front = 0;
        pipe->back = 0;
    } else if (pipe->back == PIPE_BUFFER_LEN - 1) {
        pipe->back = 0;
    } else {
        pipe->back += 1;
    }

    pipe->buffer[pipe->back] = byte_to_write;
    pipe->curr_num_bytes += 1;

    return SUCCESS;
}

/**
 * Pipe buffer dequeue.
 *
 * Writes byte into address pointed to by char_addr.
 *
 * Returns ERROR if anything goes wrong, and SUCCESS if everything goes right.
 *
 * Idea: https://www.geeksforgeeks.org/circular-queue-set-1-introduction-array-implementation/
 */

int circular_dequeue(pipe_t *pipe, char *char_addr) {

    // Check that the pipe buffer is not empty, just to be safe
    if (pipe->curr_num_bytes == 0) {
        TP_ERROR("Trying to dequeue from an empty pipe!\n");
        return ERROR;
    }

    *char_addr = pipe->buffer[pipe->front];  // dequeued char
    pipe->buffer[pipe->front] = '\0';        // mark dequeued char as NULL
    pipe->curr_num_bytes--;

    // Update front
    if (pipe->front == pipe->back) {  // means queue is now empty
        pipe->front = -1;
        pipe->back = -1;
    } else if (pipe->front == PIPE_BUFFER_LEN - 1) {  // circle back to the start of queue
        pipe->front = 0;
    } else {
        pipe->front += 1;
    }

    return SUCCESS;
}

/**
 * Used by hsearch()
 */

bool search_pipe(void *elementp, const void *searchkeyp) {
    pipe_t *pipe = (pipe_t *)elementp;
    const char *search_key_str = searchkeyp;

    char pipe_key[MAX_KEYLEN];
    sprintf(pipe_key, "pipe%d\0", pipe->pipe_id);

    TracePrintf(2, "Comparing strings: %s =? %s\n", pipe_key, search_key_str);
    if (strcmp(pipe_key, search_key_str) == 0) {
        TracePrintf(2, "Strings are the same!\n");
        return true;
    } else {
        return false;
    }
}

/**
 * Used by hsearch()
 */

bool search_lock(void *elementp, const void *searchkeyp) {
    lock_t *lock = (lock_t *)elementp;
    const char *search_key_str = searchkeyp;

    char lock_key[MAX_KEYLEN];
    sprintf(lock_key, "lock%d\0", lock->lock_id);

    TracePrintf(2, "Comparing strings: %s =? %s\n", lock_key, search_key_str);
    if (strcmp(lock_key, search_key_str) == 0) {
        TracePrintf(2, "Strings are the same!\n");
        return true;
    } else {
        return false;
    }
}

/**
 * Used by hsearch()
 */

bool search_cvar(void *elementp, const void *searchkeyp) {
    cvar_t *cvar = (cvar_t *)elementp;
    const char *search_key_str = searchkeyp;

    char cvar_key[MAX_KEYLEN];
    sprintf(cvar_key, "cvar%d\0", cvar->cvar_id);

    TracePrintf(2, "Comparing strings: %s =? %s\n", cvar_key, search_key_str);
    if (strcmp(cvar_key, search_key_str) == 0) {
        TracePrintf(2, "Strings are the same!\n");
        return true;
    } else {
        return false;
    }
}

/**
 * Used by happly()
 */

void print_lock(void *elementp) {
    lock_t *lock = elementp;
    TracePrintf(2, "Lock id: %d\n", lock->lock_id);
}

/**
 * Used by happly()
 */

void print_cvar(void *elementp) {
    cvar_t *cvar = elementp;
    TracePrintf(2, "Cvar id: %d\n", cvar->cvar_id);
}

/**
 * Used by happly()
 */

void print_pipe(void *elementp) {
    pipe_t *pipe = elementp;
    TracePrintf(2, "Pipe id: %d\n", pipe->pipe_id);
}

/**
 * Checks if the address lies in region 1. (1 means it does, 0 means it doesn't)
 */
bool is_r1_addr(void *addr) {
    unsigned int addr_page = ((unsigned int)(addr) >> PAGESHIFT);
    if (addr_page < g_len_pagetable || addr_page >= 2 * MAX_PT_LEN) {
        // the address points to r0 (kernel) memory, or past r1 memory

        return false;
    }

    // TracePrintf(2, "is an R1 address!\n");
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

/**
 * If init exits, the system should be halted.
 */
void kExit(int status) {

    // TODO: should check if `status` here is valid? Someone could try passing an address here
    // disguised as an int?

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

enum TermAccessKind { Read, Write };

int term_queue_get(int idx, enum TermAccessKind queue_kind) {
    if (queue_kind == Read) {
        return term_read_status[idx];
    } else if (queue_kind == Write) {
        return term_write_status[idx];
    }
}

void term_queue_set(int idx, enum TermAccessKind queue_kind, int val) {
    if (queue_kind == Read) {
        term_read_status[idx] = val;
    } else if (queue_kind == Write) {
        term_write_status[idx] = val;
    }
}

/**
 * Check if terminal is being used by another process. If so, sleep.
 */
void gain_access_to_term(int tty_id, enum TermAccessKind access_kind) {
    // Sleep if the terminal is marked with a different PID than the one of this process,
    // and if it is not not being used
    while (term_queue_get(tty_id, access_kind) != g_running_pcb->pid &&
           term_queue_get(tty_id, access_kind) != 0) {
        g_running_pcb->blocked_term = tty_id;

        if (access_kind == Read) {
            TracePrintf(2, "PID %d tried to read from terminal %d, but it was in use. Sleeping...\n",
                        g_running_pcb->pid, tty_id);
            schedule(g_term_blocked_read_queue);
        } else if (access_kind == Write) {
            TracePrintf(2, "PID %d tried to write to terminal %d, but it was in use. Sleeping...\n",
                        g_running_pcb->pid, tty_id);
            schedule(g_term_blocked_write_queue);
        }
    }
    // woke up with access to terminal-- free to continue
    if (access_kind == Read) {
        TracePrintf(2, "PID %d has read access to terminal %d.\n", g_running_pcb->pid, tty_id);
        term_read_status[tty_id] = g_running_pcb->pid;
    } else if (access_kind == Write) {
        TracePrintf(2, "PID %d has write access to terminal %d.\n", g_running_pcb->pid, tty_id);
        term_write_status[tty_id] = g_running_pcb->pid;
    }
}

/**
 * Mark terminal as available and wake up next process waiting on it.
 */
int release_access_to_term(int tty_id, enum TermAccessKind access_kind) {

    /**
     * Mark terminal in appropriate queue as unused
     */

    if (access_kind == Read) {
        TracePrintf(2, "PID %d releasing read access to terminal %d.\n", g_running_pcb->pid, tty_id);
        term_read_status[tty_id] = 0;
    } else if (access_kind == Write) {
        TracePrintf(2, "PID %d releasing write access to terminal %d.\n", g_running_pcb->pid, tty_id);
        term_write_status[tty_id] = 0;
    }

    /**
     * Wake up any processes waiting for this kind of access on this terminal
     */

    int *key = malloc(sizeof(int));
    if (key == NULL) {
        TP_ERROR("`malloc()` failed.\n");
        return ERROR;
    }
    *key = tty_id;

    if (access_kind == Read) {
        pcb_t *pcb = qremove(g_term_blocked_read_queue, is_waiting_for_term_id, (void *)key);
        if (pcb != NULL) {
            TracePrintf(2, "PID %d woke up from terminal read blocked queue.\n", pcb->pid);
            qput(g_ready_procs_queue, (void *)pcb);
        }
    } else if (access_kind == Write) {
        pcb_t *pcb = qremove(g_term_blocked_write_queue, is_waiting_for_term_id, (void *)key);
        if (pcb != NULL) {
            TracePrintf(2, "PID %d woke up from terminal write blocked queue.\n", pcb->pid);
            qput(g_ready_procs_queue, (void *)pcb);
        }
    }

    free(key);
    return SUCCESS;
}
/**
 * Buffer implementation:
 *      - Easy way: use currently existing Queue code (linked list implementation).
 *      - Slicker way: implement a circular array implementation of FIFO queue for pipe buffers.
 *
 * We do it the slicker way. That is, The pipe is really a Queue ADT implemented as a circular array.
 *
 * Passing an invalid pointer to kPipeInit() does not result in the user program exiting; the syscall
 * just returns with an ERROR.
 *
 *
 */
int kPipeInit(int *pipe_idp) {

    /**
     * Verify that user-given pointer is valid (user has permissions to write
     * to what the pointer is pointing to)
     */
    if (!is_r1_addr(pipe_idp) || !is_writeable_addr(g_running_pcb->r1_ptable, (void *)pipe_idp)) {
        TracePrintf(1, "`kPipeInit()` passed an invalid pointer -- syscall now returning ERROR\n");
        return ERROR;
    }

    /**
     * Allocate a pipe on kernel heap and initialize it.
     */
    pipe_t *new_pipe = malloc(sizeof(*new_pipe));
    if (new_pipe == NULL) {
        TracePrintf(1, "malloc failed in `kPipeInit`()\n");
        return ERROR;
    }

    // Initialize pipe
    new_pipe->pipe_id = assign_pipe_id();

    // Check that max pipe limit has not been reached
    if (new_pipe->pipe_id == ERROR) {
        free(new_pipe);
        return ERROR;
    }

    new_pipe->curr_num_bytes = 0;
    new_pipe->front = -1;
    new_pipe->back = -1;
    new_pipe->blocked_procs_queue = qopen();

    /**
     * Put newly created pipe in global pipes hashtable
     */
    char pipe_key[MAX_KEYLEN];  // 12 should be more than enough to cover a billion pipes (even though
                                // g_max_pipes will probably be less)

    sprintf(pipe_key, "pipe%d\0", new_pipe->pipe_id);

    TracePrintf(2, "pipe key: %s; pipe key length: %d\n", pipe_key, strlen(pipe_key));

    int rc = hput(g_pipes_htable, (void *)new_pipe, pipe_key, strlen(pipe_key));
    if (rc != 0) {
        TracePrintf(1, "error occurred while putting pipe into hashtable\n");
        free(new_pipe);
        return ERROR;
    }

    TracePrintf(2, "printing pipes hash table\n");
    happly(g_pipes_htable, print_pipe);

    *pipe_idp = new_pipe->pipe_id;

    return SUCCESS;
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
     * Check if terminal is being used by another process. If so, sleep.
     */
    gain_access_to_term(tty_id, Read);

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

    term_buf_t *k_buf = g_term_bufs[tty_id];

    if (k_buf->ptr == NULL) {
        g_running_pcb->blocked_term = tty_id;
        schedule(g_term_blocked_read_queue);
    }

    /**
     * There is now an input line ready to be read. So copy that over.
     */

    int bytes_remaining_in_kbuf = k_buf->end_pos_offset - k_buf->curr_pos_offset;

    // TODO: Handle if above is 0

    // Copy over to user buf, clear kernel buf, and return
    if (bytes_remaining_in_kbuf <= len) {
        memcpy(buf, k_buf->ptr + k_buf->curr_pos_offset, len);
        free(k_buf->ptr);  // TODO: abstract this "clearing" into a function
        k_buf->ptr = NULL;
        k_buf->curr_pos_offset, k_buf->end_pos_offset = 0;
        return len;
    }

    // Copy over `len` bytes from the kernel buf, update kernel buf accordingly
    // to make it available for future reading. Return.
    else if (bytes_remaining_in_kbuf > len) {
        memcpy(buf, k_buf->ptr + k_buf->curr_pos_offset, len);
        k_buf->curr_pos_offset += len;
        return len;
    }

    /**
     * Wake up any processes waiting on this terminal.
     */

    if (release_access_to_term(tty_id, Read) == ERROR) {
        return ERROR;
    }

    return len;
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
    TracePrintf(2, "Entering `kTtyWrite()`...\n");

    /**
     * Check if terminal is being used by another process. If so, sleep.
     */

    gain_access_to_term(tty_id, Write);

    /**
     * Valid user input
     */

    if (!(tty_id >= 0 && tty_id < NUM_TERMINALS)) {
        TP_ERROR("tried to read from an invalid terminal.\n");
        return ERROR;
    }

    if (!(is_valid_array(g_running_pcb->r1_ptable, buf, len, PROT_READ | PROT_WRITE))) {
        TP_ERROR("the `buf` that was passed was not valid.\n");
        return ERROR;
    }

    /**
     * Copy user buf to kernel buf
     */

    void *kbuf = malloc(len);
    if (kbuf == NULL) {
        TP_ERROR("`malloc()` failed.\n");
        return ERROR;
    }

    memcpy(kbuf, buf, len);

    /**
     * Write from kernel buffer to terminal
     */

    void *current_byte = kbuf;
    int bytes_remaining = len;

    while (bytes_remaining > 0) {
        if (bytes_remaining < TERMINAL_MAX_LINE) {
            TtyTransmit(tty_id, current_byte, bytes_remaining);
            // Block until this operation completes
            g_running_pcb->blocked_term = tty_id;
            schedule(g_term_blocked_transmit_queue);
            break;
        }

        TtyTransmit(tty_id, current_byte, TERMINAL_MAX_LINE);
        // Block until this operation completes
        g_running_pcb->blocked_term = tty_id;
        schedule(g_term_blocked_transmit_queue);

        current_byte += TERMINAL_MAX_LINE;
        bytes_remaining -= TERMINAL_MAX_LINE;
    }

    free(kbuf);

    /**
     * Wake up next process waiting on this terminal
     */

    release_access_to_term(tty_id, Write);

    TracePrintf(2, "Exiting `kTtyWrite()`...\n");
    return len;
}
/**
 * Returns the number of bytes read.
 *
 * If syscall fails, some pipe contents may have been partly written into the buffer.
 */
int kPipeRead(int pipe_id, void *buffer, int len) {

    /**
     * Check that the args are legit (pipe_id, buffer, len).
     *
     * Buffer (living in R1 land) needs to have write permissions (it is going to be written into).
     */
    if (!is_valid_array(g_running_pcb->r1_ptable, buffer, len, PROT_WRITE)) {
        TP_ERROR("buffer not valid\n");
        return ERROR;
    }

    char *buffer_str = (char *)buffer;

    /**
     * Get pipe from hashtable
     */
    char pipe_key[MAX_KEYLEN];
    sprintf(pipe_key, "pipe%d\0", pipe_id);

    pipe_t *pipe = (pipe_t *)hsearch(g_pipes_htable, search_pipe, pipe_key, strlen(pipe_key));
    if (pipe == NULL) {
        TP_ERROR("Failed retrieving pipe %d from pipes hashtable\n", pipe_id);
        return ERROR;
    }

    int curr_num_bytes = pipe->curr_num_bytes;

    /**
     * If pipe is empty, block the caller
     */
    while (curr_num_bytes == 0) {
        TracePrintf(2, "pipe is empty, blocking caller\n");
        schedule(pipe->blocked_procs_queue);
        curr_num_bytes = pipe->curr_num_bytes;  // need to update after process wakes back up
    }

    curr_num_bytes = pipe->curr_num_bytes;  // for if process wakes up again

    /**
     * If pipe->curr_num_bytes <= len, give all to the caller and return.
     * If pipe->curr_num_bytes > len, give the first len to caller and return.
     *
     */
    int num_bytes_to_read;  // = min(curr_num_bytes, len)
    if (curr_num_bytes <= len) {
        num_bytes_to_read = curr_num_bytes;
    } else {
        num_bytes_to_read = len;
    }

    int rc;

    /**
     * Call circular_dequeue() num_bytes_to_read times
     */
    for (int i = 0; i < num_bytes_to_read; i++) {
        rc = circular_dequeue(pipe, &buffer_str[i]);

        if (rc != 0) {
            TP_ERROR("Dequeue failed\n");
            return ERROR;
        }
    }

    return num_bytes_to_read;
}

/**
 * If a writer tries to write and the buffer is full, the syscall returns ERROR.
 *
 * All blocked processes waiting for bytes on the pipe are woken up by kPipeWrite.
 */
int kPipeWrite(int pipe_id, void *buffer, int len) {

    /**
     * Check that the args are legit (pipe_id, buffer, len).
     *
     * Buffer (living in R1 land) needs to have read permissions (it's going to be read from).
     */
    if (!is_valid_array(g_running_pcb->r1_ptable, buffer, len, PROT_READ | PROT_WRITE)) {
        TP_ERROR("buffer not valid\n");
        return ERROR;
    }

    char *buffer_str = (char *)buffer;

    /**
     * Get pipe from hashtable
     */
    char pipe_key[MAX_KEYLEN];
    sprintf(pipe_key, "pipe%d\0", pipe_id);

    pipe_t *pipe = (pipe_t *)hsearch(g_pipes_htable, search_pipe, pipe_key, strlen(pipe_key));
    if (pipe == NULL) {
        TP_ERROR("Failed retrieving pipe %d from pipes hashtable\n", pipe_id);
        return ERROR;
    }

    int num_free_bytes = PIPE_BUFFER_LEN - pipe->curr_num_bytes;

    /**
     * If pipe is full, fail the syscall
     */
    if (num_free_bytes == 0) {
        TP_ERROR("Trying to write to a full pipe\n");
        return ERROR;
    }

    /**
     * Otherwise, write as many as possible
     */

    int num_bytes_to_write;  // = min(num_free_bytes, len)
    if (num_free_bytes <= len) {
        num_bytes_to_write = num_free_bytes;
    } else {
        num_bytes_to_write = len;
    }

    int rc;

    /**
     * Write into pipe's buffer from input buffer.
     * Call circular_enqueue(byte) num_bytes_to_write times.
     */
    for (int i = 0; i < num_bytes_to_write; i++) {
        rc = circular_enqueue(pipe, buffer_str[i]);

        if (rc != 0) {
            TP_ERROR("Enqueue failed\n");
            return ERROR;
        }
    }

    /**
     * Wake up all processes that were waiting for bytes on this pipe.
     *
     * (done similarly as in clockTrap where blocked queue needed to be iterated, and processes
     * needed to be removed during iteration if they had paid their dues in waiting).
     */

    qremove_all(pipe->blocked_procs_queue, put_proc_on_ready_queue, NULL);
    return num_bytes_to_write;
}

/*
 *
 *  From manual (p. 34):
 *      Create a new lock; save its identifier at *lock idp. In case
 *      of any error, the value ERROR is returned.
 *
 *  Pseudocode
 *  - Malloc a new lock struct onto the kernel heap
 *      - Need to malloc, as opposed to just storing lock as local variable in kernel stack because
 *       need lock to persist in virtual memory even as processes are switched; kernel stack is unique
 *       per process
 *  - Add newly created lock to global lock_list_qp (linked list)
 *      - qadd(lock_list_qp, lock)
 *  - Initilize lock struct
 *      - Allocate a unique lock_id for the lock
 *          - lock_id determined by global lock_id counter (kernel.c)
 *      - set lock.locked = 0
 *      - set lock.owner = -1
 *  - Set *lock_idp = lock.lock_id
 *  - Return 0 if everything went successfully, ERROR otherwise
 */

int kLockInit(int *lock_idp) {
    TracePrintf(2, "Entering `kLockInit`\n");
    /**
     * Verify that user-given pointer is valid (user has permissions to write
     * to what the pointer is pointing to)
     */
    if (!is_r1_addr(lock_idp) || !is_writeable_addr(g_running_pcb->r1_ptable, (void *)lock_idp)) {
        TracePrintf(1, "`kLockInit()` passed an invalid pointer -- syscall now returning ERROR\n");
        return ERROR;
    }

    /**
     * Allocate a lock on kernel heap and initialize it.
     */
    lock_t *new_lock = malloc(sizeof(*new_lock));
    if (new_lock == NULL) {
        TracePrintf(1, "malloc failed in `kLockInit`()\n");
        return ERROR;
    }

    /**
     * Initialize lock.
     */
    new_lock->lock_id = assign_lock_id();

    // Check that max lock limit has not been reached
    if (new_lock->lock_id == ERROR) {
        free(new_lock);
        return ERROR;
    }

    new_lock->locked = false;
    new_lock->corrupted = false;
    new_lock->owner_proc = NULL;
    new_lock->blocked_procs_queue = qopen();

    /**
     * Put newly created lock in global locks hashtable
     */
    char lock_key[MAX_KEYLEN];  // 12 should be more than enough to cover a billion locks (even though
                                // g_max_locks will probably be less)

    sprintf(lock_key, "lock%d\0", new_lock->lock_id);

    TracePrintf(2, "lock key: %s; lock key length: %d\n", lock_key, strlen(lock_key));

    int rc = hput(g_locks_htable, (void *)new_lock, lock_key, strlen(lock_key));
    if (rc != 0) {
        TracePrintf(1, "error occurred while putting lock into hashtable\n");
        free(new_lock);
        return ERROR;
    }

    TracePrintf(2, "printing locks hash table\n");
    happly(g_locks_htable, print_lock);

    *lock_idp = new_lock->lock_id;

    return SUCCESS;
}

/*
 *  From manual (p. 34):
 *      Acquire the lock identified by lock id. In case of any error,
 *      the value ERROR is returned.
 *
 *  Pseudocode
 *  - Traverse lock_list_qp to find the lock referenced by lock_id
 *  - if lock.locked == 0
 *      - lock.locked = 1
 *      - lock.owner = running_process.pid;
 *      - return 0
 *  - elif lock.locked == 1
 *      - if lock.owner == running_procces.pid
 *          - return ERROR (you already have the lock!)
 *      - else
 *          - add running_process to blocked_processes queue
 *              - qadd(lock.blocked_processes, running_process)
 *          - return 0
 *
 */

int kAcquire(int lock_id) {
    /**
     * TODO: validate arg
     */

    /**
     * Get lock from hashtable
     */
    char lock_key[MAX_KEYLEN];
    sprintf(lock_key, "lock%d\0", lock_id);

    lock_t *lock = (lock_t *)hsearch(g_locks_htable, search_lock, lock_key, strlen(lock_key));
    if (lock == NULL) {
        TP_ERROR("Failed retrieving lock %d from locks hashtable\n", lock_id);
        return ERROR;
    }

    /**
     * If lock isn't locked, lock it, set the owner process, and return.
     */
    if (!lock->locked) {
        lock->locked = true;
        lock->owner_proc = g_running_pcb;
        return 0;
    }

    /**
     * If lock is already locked, check that the acquiring process is not the lock
     * owner. If it is, return ERROR. If not, add the process to the blocked queue
     * associated with the lock, and call the scheduler.
     */
    if (lock->owner_proc == g_running_pcb) {
        TP_ERROR("Process %d already owns lock %d!\n", g_running_pcb->pid, lock->lock_id);
        return ERROR;
    }

    qput(lock->blocked_procs_queue, g_running_pcb);
    schedule(NULL);

    return 0;
}

/*
 *  From manual (p. 35):
 *      Release the lock identified by lock id. The caller must currently
 *      hold this lock. In case of any error, the value ERROR is returned.
 *
 *  Pseudocode
 *  - Traverse lock_list_qp to find the lock referenced by lock_id
 *  - if lock.locked == 0 (cannot release an unacquired lock)
 *      - return ERROR
 *  - if lock.owner != running_process.pid
 *      - return ERROR
 *  - else
 *      - if qsize(lock.blocked_processes) != 0
 *          - proc = qget(lock.blocked_processes)
 *          - MOVE proc to READY_PROCESSES
 *          - lock.owner = proc.id
 *          - lock.locked = 1 (lock stays locked)
 *      - else
 *          - lock.owner = -1
 *          - lock.locked = 0
 */

int kRelease(int lock_id) {
    /**
     * TODO: validate arg
     */

    /**
     * Get lock from hashtable
     */
    char lock_key[MAX_KEYLEN];
    sprintf(lock_key, "lock%d\0", lock_id);

    lock_t *lock = (lock_t *)hsearch(g_locks_htable, search_lock, lock_key, strlen(lock_key));
    if (lock == NULL) {
        TP_ERROR("Failed retrieving lock %d from locks hashtable\n", lock_id);
        return ERROR;
    }

    /**
     * Check that we're not trying to release an unacquired lock.
     */

    if (!lock->locked) {
        TP_ERROR("Cannot release an un-locked lock!\n");
        return ERROR;
    }

    /**
     * If there is a process waiting to get this lock (blocked process queue
     * associated with the lock is not empty), move that process out of the blocked
     * queue into the ready queue, and transfer lock ownership here directly.
     *
     * If not, unnlock the lock and set attributes accordingly.
     */

    if (qlen(lock->blocked_procs_queue) > 0) {
        pcb_t *proc = qget(lock->blocked_procs_queue);
        qput(g_ready_procs_queue, proc);
        lock->owner_proc = proc;
        lock->locked = true;  // stays locked
        return 0;
    }

    lock->locked = false;
    lock->owner_proc = NULL;

    return 0;
}

/*
 *  ================
 *  === CVARINIT ===
 *  ================
 *
 *  From manual (p. 35):
 *      Create a new condition variable; save its identifier at *cvar_idp.
 *      In case of any error, the value ERROR is returned.
 *
 *
 *  Pseudocode
 *  - Malloc a new cvar struct onto the kernel heap
 *  - Add newly created cvar to global cvar_list_qp (linked list)
 *  - Initilize cvar struct
 *      - Allocate a unique cvar_id for the lock
 *          - cvar_id determined by global cvar_id counter (kernel.c)
 *  - Set *cvar_idp = cvar.cvar_id
 *  - Return 0 if everything went successfully, ERROR otherwise
 *
 */
int kCvarInit(int *cvar_idp) {
    TracePrintf(2, "Entering `kCvarInit`\n");
    /**
     * Verify that user-given pointer is valid (user has permissions to write
     * to what the pointer is pointing to).
     */
    if (!is_r1_addr(cvar_idp) || !is_writeable_addr(g_running_pcb->r1_ptable, (void *)cvar_idp)) {
        TracePrintf(1, "`kCvarInit()` passed an invalid pointer -- syscall now returning ERROR\n");
        return ERROR;
    }

    /**
     * Allocate a cvar on kernel heap and initialize it.
     */
    cvar_t *new_cvar = malloc(sizeof(*new_cvar));
    if (new_cvar == NULL) {
        TracePrintf(1, "malloc failed in `kCvarInit`()\n");
        return ERROR;
    }

    /**
     * Initialize cvar.
     */
    new_cvar->cvar_id = assign_cvar_id();

    // Check that max cvar limit has not been reached
    if (new_cvar->cvar_id == ERROR) {
        free(new_cvar);
        return ERROR;
    }

    new_cvar->blocked_procs_queue = qopen();

    /**
     * Put newly created cvar in global cvars hashtable
     */
    char cvar_key[MAX_KEYLEN];  // 12 should be more than enough to cover a billion cvars (even though
                                // g_max_cvars will probably be less)

    sprintf(cvar_key, "cvar%d\0", new_cvar->cvar_id);

    TracePrintf(2, "cvar key: %s; cvar key length: %d\n", cvar_key, strlen(cvar_key));

    int rc = hput(g_cvars_htable, (void *)new_cvar, cvar_key, strlen(cvar_key));
    if (rc != 0) {
        TracePrintf(1, "error occurred while putting cvar into hashtable\n");
        free(new_cvar);
        return ERROR;
    }

    TracePrintf(2, "printing cvars hash table\n");
    happly(g_cvars_htable, print_cvar);

    *cvar_idp = new_cvar->cvar_id;

    return SUCCESS;
}

/*
 *  ================
 *  === CVARWAIT ===
 *  ================
 *
 *  From manual (p. 35):
 *      The kernel-level process releases the lock identified by lock id and
 *      waits on the condition variable indentified by cvar id. When the
 *      kernel-level process wakes up (e.g., because the condition variable was
 *      signaled), it re-acquires the lock. (Use Mesa-style semantics.)
 *      When the lock is finally acquired, the call returns to userland. In case
 *      of any error, the value ERROR is returned.
 *
 *  Pseudocode
 *  - Traverse cvar_list_qp to find cvar associated with cvar_id
 *  - Set the following
 *      - cvar.lock_id = lock_id (don't need this either)
 *      - cvar.pid = running_process.pid (don't need this - have the blocked queue)
 *  - Call kRelease(lock_id)
 *  - Add running_process to cvar.blocked_processes queue
 *  - ** at this time, cvar_wait method is blocked because the calling process was just
 *      put into the blocked queue **
 *  - ** signal wakes up process **
 *  - Call kAcquire(lock_id)
 *  - return 0
 */
int kCvarWait(int cvar_id, int lock_id) {
    /**
     * TODO: validate arguments
     */

    /**
     * Get cvar from hashtable
     */
    char cvar_key[MAX_KEYLEN];
    sprintf(cvar_key, "cvar%d\0", cvar_id);

    cvar_t *cvar = (cvar_t *)hsearch(g_cvars_htable, search_cvar, cvar_key, strlen(cvar_key));
    if (cvar == NULL) {
        TP_ERROR("Failed retrieving cvar %d from cvars hashtable\n", cvar_id);
        return ERROR;
    }

    /**
     * Get lock from hashtable
     */
    char lock_key[MAX_KEYLEN];
    sprintf(lock_key, "lock%d\0", lock_id);

    lock_t *lock = (lock_t *)hsearch(g_locks_htable, search_lock, lock_key, strlen(lock_key));
    if (lock == NULL) {
        TP_ERROR("Failed retrieving lock %d from locks hashtable\n", lock_id);
        return ERROR;
    }

    /**
     * Release the lock
     */
    int rc;
    rc = kRelease(lock_id);
    if (rc != 0) {
        TP_ERROR("Failed releasing the lock in kCvarWait\n");
    }

    /**
     * Make the current process go to sleep, "waiting" for things to change.
     */
    schedule(cvar->blocked_procs_queue);

    // Now the process is sleeping. Will be "woken up" by a signal() or broadcast() call.

    /**
     * Acquire the lock after the process wakes up.
     */
    rc = kAcquire(lock_id);
    if (rc != 0) {
        TP_ERROR("Failed acquiring the lock in kCvarWait\n");
    }

    return 0;
}

/*
 *  ==================
 *  === CVARSIGNAL ===
 *  ==================
 *
 *  From manual (p. 35):
 *      Signal the condition variable identified by cvar id. (Use Mesa-style
 *      semantics.) In case of any error, the value ERROR is returned.
 *
 *  Pseudocode
 *  - Traverse cvar_list_qp to find cvar associated with cvar_id
 *  - Find and remove one blocked process associated with the cvar
 *      - proc = qget(cvar.blocked_process)
 *  - Add proc to the ready_processes queue
 *  - return 0
 */
int kCvarSignal(int cvar_id) {
    /**
     * TODO: validate arguments
     */

    /**
     * Get cvar from hashtable
     */
    char cvar_key[MAX_KEYLEN];
    sprintf(cvar_key, "cvar%d\0", cvar_id);

    cvar_t *cvar = (cvar_t *)hsearch(g_cvars_htable, search_cvar, cvar_key, strlen(cvar_key));
    if (cvar == NULL) {
        TP_ERROR("Failed retrieving cvar %d from cvars hashtable\n", cvar_id);
        return ERROR;
    }

    /**
     * Find one blocked process associated with cvar and move it to the ready queue.
     */
    pcb_t *proc = (pcb_t *)qget(cvar->blocked_procs_queue);
    if (proc == NULL) {
        TP_ERROR("Trying to signal a cvar that has no blocked processes associated with it!\n");
        return ERROR;
    }

    qput(g_ready_procs_queue, proc);

    return 0;
}

/*
 *  =====================
 *  === CVARBROADCAST ===
 *  =====================
 *
 *  From manual (p. 35):
 *      Broadcast the condition variable identified by cvar id. (Use Mesa-style
 *      semantics.) In case of any error, the value ERROR is returned.
 *
 *  Pseudocode
 *  - Traverse cvar_list_qp to find cvar associated with cvar_id
 *  - Go through cvar.blocked_processes and pop all PCBs from this list
 *  - Add each popped list to the ready_processes queue
 *  - return 0
 *
 */
int kCvarBroadcast(int cvar_id) {
    /**
     * TODO: validate arguments
     */

    /**
     * Get cvar from hashtable
     */
    char cvar_key[MAX_KEYLEN];
    sprintf(cvar_key, "cvar%d\0", cvar_id);

    cvar_t *cvar = (cvar_t *)hsearch(g_cvars_htable, search_cvar, cvar_key, strlen(cvar_key));
    if (cvar == NULL) {
        TP_ERROR("Failed retrieving cvar %d from cvars hashtable\n", cvar_id);
        return ERROR;
    }

    /**
     * Remove ALL blocked process associated with cvar and move them ALL to the ready queue.
     */
    pcb_t *proc = (pcb_t *)qget(cvar->blocked_procs_queue);
    if (proc == NULL) {
        TP_ERROR("Trying to broadcast a cvar that has no blocked processes associated with it!\n");
        return ERROR;
    }

    while (proc != NULL) {
        qput(g_ready_procs_queue, proc);
        proc = (pcb_t *)qget(cvar->blocked_procs_queue);
    }

    return 0;
}

/*
 *  ===============
 *  === RECLAIM ===
 *  ===============
 *
 *  From manual (p. 35):
 *      Destroy the lock, condition variable, or pipe indentified by id,
 *      and release any associated resources.
 *      In case of any error, the value ERROR is returned.
 *      If you feel additional specification is necessary to handle unusual
 *      scenarios, then create and document it.
 *
 *  Thoughts
 *  - Not sure how to determine whether its a lock/cvar/pipe being reclaimed, based on id alone
 *  since we're maintaing separate counters for
 *      - Suggestions: increment lock_id in multiples of 3, cvar_id in multiples of 5, pipe_id in multiples of
 * 7
 *
 *  Pseudocode
 *  - Determine whether to look in the lock_list_qp or cvar_list_qp or pipe_list_qp
 *      - if id % 3 == 0: look in lock_qp
 *      - elif id % 5 == 0: look in cvar_list_qp
 *      - elif id % 7 == 0: look in pipe_list_qp
 *  - If lock
 *      - Go through lock.blocked_processes, remove each process from queue, and kill process?
 *
 */
int kReclaim(int id) {}
