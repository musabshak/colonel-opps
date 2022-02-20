#include "kernel_data_structs.h"
#include "ykernel.h"

extern pcb_t *g_running_pcb;
extern queue_t *g_delay_blocked_procs_queue;
extern queue_t *g_ready_procs_queue;
extern pcb_t *g_idle_pcb;
extern unsigned int g_len_pagetable;
extern unsigned int g_num_kernel_stack_pages;
extern pte_t *g_reg0_ptable;

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

    // Put current process in blocked processes queue
    qput(g_delay_blocked_procs_queue, (void *)g_running_pcb);

    // // Get a new process from ready queue
    // pcb_t *new_pcb = (pcb_t *)qget(g_ready_procs_queue);

    // // If there are no runnable processes, dispatch idle
    // if (new_pcb == NULL) {
    //     new_pcb = g_idle_pcb;
    // }

    // Invoke KCSwitch()
    rc = KernelContextSwitch(KCSwitch, g_running_pcb, g_idle_pcb);
    if (rc != 0) {
        TracePrintf(1, "Failed to switch kernel context.\n");
        return ERROR;
    }

    return 0;
}

int kFork() {
    TracePrintf(1, "Forking.\n");

    pcb_t *parent_pcb = g_running_pcb;

    // Allocate a PCB for child process. Returns virtual address in kernel heap
    child_pcb = malloc(sizeof(*g_idle_pcb));
    if (child_pcb == NULL) {
        TracePrintf(1, "malloc for `kFork()`'s PCB failed.\n");
        return ERROR;
    }

    pte_t *child_r1_ptable = malloc(sizeof(pte_t) * g_len_pagetable);
    if (child_r1_ptable == NULL) {
        TracePrintf(1, "Malloc failed for `kFork()`'s pagetable.\n");
        return ERROR;
    }

    // Initialize child's r1 pagetable to fully copy (not COW) parent's r1 
    // pagetable
    for (int i = 0; i < g_len_pagetable; i++) {
        int free_frame_idx = find_free_frame(g_frametable);
        if (free_frame_idx == -1) {
            TracePrintf(1, "Couldn't find free frame while forking.\n");
            return ERROR;
        }

        // Write to this new frame by assigning it to the page below kernel stack
        // and writing to that page
        page_below_kstack = MAX_PT_LEN - g_num_kernel_stack_pages - 1;
        g

        memcpy(child_r1_ptable[i], parent_pcb->r1_ptable[i], size);
    }

    // Populate idlePCB
    g_idle_pcb->r1_ptable = idle_r1_ptable;
    // g_idle_pcb->uctxt = *uctxt;
    memcpy(&(g_idle_pcb->uctxt), uctxt,
           sizeof(UserContext));  // !!!! On the way into a handler (Transition 5), copy the current
                                  // UserContext into the PCB of the current proceess.
    g_idle_pcb->pid = helper_new_pid(idle_r1_ptable);  // hardware defined function for generating PID
    g_idle_pcb->user_text_pg0 = 0;
    g_idle_pcb->user_data_pg0 = 0;

    TracePrintf(1, "Just populated idle's uctxt\n");

    int idx = find_free_frame(g_frametable);
    if (idx == -1) {
        TracePrintf(1, "find_free_frame() failed while allocating frames for idle's user_stack\n");
        return;
    }

    // Allocate user stack for idle's r1 ptable
    idle_r1_ptable[g_len_pagetable - 1].valid = 1;
    idle_r1_ptable[g_len_pagetable - 1].prot = PROT_READ | PROT_WRITE;
    idle_r1_ptable[g_len_pagetable - 1].pfn = idx;
    g_frametable[idx] = 1;

    // Get free frames for idle's kernel stack
    for (int i = 0; i < g_num_kernel_stack_pages; i++) {
        int idx = find_free_frame(g_frametable);

        if (idx == -1) {
            TracePrintf(1, "find_free_frame() failed while allocating frames for idle's kernel_stack\n");
            return;
        }
        g_idle_pcb->kstack_frame_idxs[i] = idx;
        g_frametable[idx] = 1;
    }

    // // Stack values increment in 4 bytes. Intel is little-endian; sp needs to point to
    // // 0x1ffffc (and not 0x1fffff)
    g_idle_pcb->uctxt.sp = (void *)(VMEM_LIMIT - 4);  // !!!!!!!!!!
    g_idle_pcb->uctxt.pc = doIdle;                    // !!!!!!!!!!

    // print_r1_page_table(idle_r1_ptable, g_len_pagetable);

    g_ready_procs_queue = qopen();
    g_delay_blocked_procs_queue = qopen();

    TracePrintf(1, "Just finished KCCopy\n");

    /* E=================== SETUP IDLE PROCESS ==================== */

    g_running_pcb = init_pcb;

    int rc = KernelContextSwitch(KCCopy, g_idle_pcb, NULL);

    uctxt->pc = g_running_pcb->uctxt.pc;  // !!!!!!!!!!
    uctxt->sp = g_running_pcb->uctxt.sp;  // !!!!!!!!!!

    TracePrintf(1, "g_running_pcb's pid: %d\n", g_running_pcb->pid);
    TracePrintf(1, "Exiting KernelStart\n");
}
