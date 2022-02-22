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

int kGetPid()
{
    // Confirm that there is a process that is currently running
    if (g_running_pcb == NULL)
    {
        return ERROR;
    }

    return g_running_pcb->pid;
}

int kBrk(void *new_brk)
{
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
    if (!(new_brk_int <= (user_stack_base - PAGESIZE) && new_brk_int >= last_addr_above_data))
    {
        TracePrintf(1,
                    "oh no .. trying to extend user brk into user stack (or user "
                    "data/text)\n");
        return ERROR;
    }

    // Determine whether raising brk or lowering brk
    int bytes_to_raise = new_brk - user_brk;

    int rc = ERROR;

    if (bytes_to_raise == 0)
    {
        rc = 0;
    }
    // raising brk
    else if (bytes_to_raise > 0)
    {
        rc = raise_brk_user(new_brk, user_brk, ptable);
    }
    // reducing brk
    else
    {
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
int kDelay(int clock_ticks)
{
    if (clock_ticks < 0)
    {
        return ERROR;
    }
    if (clock_ticks == 0)
    {
        return 0;
    }

    int rc;

    g_running_pcb->elapsed_clock_ticks = 0;
    g_running_pcb->delay_clock_ticks = clock_ticks;

    // Call the scheduler
    rc = schedule(0);

    return rc;
}

int kFork()
{
    TracePrintf(1, "Forking.\n");

    pcb_t *parent_pcb = g_running_pcb;

    // Allocate a PCB for child process. Returns virtual address in kernel heap
    pcb_t *child_pcb = malloc(sizeof(*g_idle_pcb));
    if (child_pcb == NULL)
    {
        TracePrintf(1, "malloc for `kFork()`'s PCB failed.\n");
        return ERROR;
    }
    memcpy(child_pcb, parent_pcb, sizeof(pcb_t));

    pte_t *child_r1_ptable = malloc(sizeof(pte_t) * g_len_pagetable);
    if (child_r1_ptable == NULL)
    {
        TracePrintf(1, "Malloc failed for `kFork()`'s pagetable.\n");
        return ERROR;
    }

    // Initialize child's r1 pagetable to fully copy (not COW) parent's r1
    // pagetable
    pte_t *parent_r1_ptable = parent_pcb->r1_ptable;
    for (int i = 0; i < g_len_pagetable; i++)
    {
        child_r1_ptable[i] = parent_r1_ptable[i];

        if (parent_r1_ptable[i].valid == 0)
        {
            continue;
        }

        int free_frame_idx = find_free_frame(g_frametable);
        if (free_frame_idx == -1)
        {
            TracePrintf(1, "Couldn't find free frame while forking.\n");
            return ERROR;
        }
        g_frametable[free_frame_idx] = 1;

        // Write to this new frame by assigning it to the page below kernel stack
        // and writing to that page
        unsigned int page_below_kstack = MAX_PT_LEN - g_num_kernel_stack_pages - 1;
        g_reg0_ptable[page_below_kstack].valid = 1;
        g_reg0_ptable[page_below_kstack].prot = PROT_READ | PROT_WRITE;
        g_reg0_ptable[page_below_kstack].pfn = free_frame_idx;

        memcpy((void *)(page_below_kstack << PAGESHIFT), (void *)((MAX_PT_LEN + i) << PAGESHIFT), PAGESIZE);

        g_reg0_ptable[page_below_kstack].valid = 0;

        // Assign this new frame to the new pagetable
        child_r1_ptable[i].pfn = free_frame_idx;
    }

    // Populate child PCB
    child_pcb->r1_ptable = child_r1_ptable;

    memcpy(&(child_pcb->uctxt), &(parent_pcb->uctxt),
           sizeof(UserContext));                      // !!!! On the way into a handler (Transition 5), copy the current
                                                      // UserContext into the PCB of the current proceess.
    child_pcb->pid = helper_new_pid(child_r1_ptable); // hardware defined function for generating PID

    // int idx = find_free_frame(g_frametable);
    // if (idx == -1) {
    //     TracePrintf(1, "find_free_frame() failed while allocating frames for idle's user_stack\n");
    //     return;
    // }

    // // Allocate user stack for idle's r1 ptable
    // idle_r1_ptable[g_len_pagetable - 1].valid = 1;
    // idle_r1_ptable[g_len_pagetable - 1].prot = PROT_READ | PROT_WRITE;
    // idle_r1_ptable[g_len_pagetable - 1].pfn = idx;
    // g_frametable[idx] = 1;

    // Get free frames for idle's kernel stack
    for (int i = 0; i < g_num_kernel_stack_pages; i++)
    {
        int idx = find_free_frame(g_frametable);
        if (idx == -1)
        {
            TracePrintf(
                1, "In `kFork()`, `find_free_frame()` failed while allocating frames for kernel_stack\n");
            return ERROR;
        }
        g_frametable[idx] = 1;

        child_pcb->kstack_frame_idxs[i] = idx;
    }

    // // // Stack values increment in 4 bytes. Intel is little-endian; sp needs to point to
    // // // 0x1ffffc (and not 0x1fffff)
    // g_idle_pcb->uctxt.sp = (void *)(VMEM_LIMIT - 4);  // !!!!!!!!!!
    // g_idle_pcb->uctxt.pc = doIdle;                    // !!!!!!!!!!

    // print_r1_page_table(idle_r1_ptable, g_len_pagetable);

    int rc = KernelContextSwitch(KCCopy, child_pcb, NULL);

    // uctxt->pc = g_running_pcb->uctxt.pc;  // !!!!!!!!!!
    // uctxt->sp = g_running_pcb->uctxt.sp;  // !!!!!!!!!!

    // Return value of 0 for the child, parent receives pid of child
    child_pcb->uctxt.regs[0] = 0;
    parent_pcb->uctxt.regs[0] = child_pcb->pid;
    ;

    return SUCCESS;
}

int kExec(char *filename, char **argvec)
{
    // Clear out current r1 pagetable, as LoadProgram will rebuild it
    // pte_t *r1_ptable = g_running_pcb->r1_ptable;
    // for (int i = 0; i < MAX_PT_LEN; i++) {
    //     if (r1_ptable[i].valid == 0) {
    //         continue;
    //     }

    //     int pfn_idx = r1_ptable[i].pfn;
    //     g_frametable[pfn_idx] = 0;

    //     r1_ptable[i].valid = 0;
    // }

    // Verify pointers?

    // Copy args
    int num_args = 0;
    while (argvec[num_args] != NULL)
    {
        num_args++;
    }

    // extra space in array is for a NULL argument
    char **argvec_cpy = malloc(num_args * sizeof(char *) + 1);
    for (int i = 0; i < num_args; i++)
    {
        // not `strnlen`, should check this is null-terminated
        int length_of_arg = strlen(argvec[i]);
        argvec_cpy[i] = malloc((length_of_arg + 1) * sizeof(char));
        strncpy(argvec_cpy[i], argvec[i], length_of_arg);
    }
    argvec_cpy[num_args] = NULL;

    int filename_len = strlen(filename);
    char *filename_cpy = malloc(filename_len * sizeof(char) + 1);
    strcpy(filename_cpy, filename);

    LoadProgram(filename, argvec, g_running_pcb);

    return SUCCESS;
}
