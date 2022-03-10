/**
 * kernel.c
 *
 * Authors: Varun Malladi and Musab Shakeel
 * Date: 2/5/2022
 *
 * This file contains the executable kernel code for the colonel-opps OS.
 *
 */

#include "hash.h"
#include "k_common.h"
#include "load_program.h"
#include "queue.h"
#include "trap_handlers.h"
#include "ykernel.h"

/* ================ */
/* S=== GLOBALS === */
/* ================ */

int g_virtual_mem_enabled = 0;              // If virtual memory enabled: 1. Otherwise: 0.
void *g_kernel_brk;                         // Global variable storing kernel brk
unsigned int g_len_frametable;              // Number of frames in physical memory, populated by KernelStart
unsigned int g_len_pagetable = MAX_PT_LEN;  // Number of pages in R0 or R1 pagetable
unsigned int *g_frametable;                 // Bitvector containing info on used/unused physical
                                            // memory frames.
pte_t *g_reg0_ptable;                       // Pagetable for kernel structures shared accross processes
pcb_t *g_running_pcb;                       // Pcb of process that is currently running
pcb_t *g_idle_pcb;
unsigned int g_num_kernel_stack_pages = KERNEL_STACK_MAXSIZE / PAGESIZE;

// process queues
queue_t *g_ready_procs_queue;
queue_t *g_delay_blocked_procs_queue;

// terminal queues
queue_t *g_term_blocked_read_queue;
queue_t *g_term_blocked_write_queue;
queue_t *g_term_blocked_transmit_queue;

// terminals
term_buf_t *g_term_bufs[NUM_TERMINALS];
hashtable_t *g_pipes_htable;
int g_max_pipes = 50 * PIPE_ID_K;  // max number of pipes that can be created in one session of the kernel
int g_pipe_id = PIPE_ID_K;         // next pipe created should have this id
int g_pipe_id_constant = PIPE_ID_K;

// locks
hashtable_t *g_locks_htable;
int g_max_locks = 50 * LOCK_ID_K;
int g_lock_id = LOCK_ID_K;
int g_lock_id_constant = LOCK_ID_K;

// cvars
hashtable_t *g_cvars_htable;
int g_max_cvars = 50 * CVAR_ID_K;
int g_cvar_id = CVAR_ID_K;
int g_cvar_id_constant = CVAR_ID_K;

/* E=== GLOBALS === */

// Imitate a userland program for checkpoint 2.
void doIdle(void) {
    while (1) {
        TracePrintf(1, "DOIDLE RUNNING!\n");
        Pause();
    }
}

/**
 * Helper function called by SetKernelBrk(void *addr) in the case that addr > g_kernel_brk.
 *
 * Modifies (if need be)
 *      - The global R0 pagetable (allocates new pages)
 *      - g_kernel_brk
 */
int h_raise_brk(void *new_brk) {
    TracePrintf(2, "Calling h_raise_brk w/ arg: %x (page %d)\n", new_brk, (unsigned int)new_brk >> PAGESHIFT);

    unsigned int current_page = (unsigned int)g_kernel_brk >> PAGESHIFT;
    unsigned int new_page = (unsigned int)new_brk >> PAGESHIFT;

    unsigned int num_pages_to_raise = new_page - current_page;
    unsigned int new_brk_int = (unsigned int)new_brk;

    // Check if `new_brk` is not 0th byte of page. Then, since we are rounding the
    // brk up to the next page we want to allocate the page the new_brk is
    // on.
    if (new_brk_int != (new_brk_int & PAGEMASK)) {
        num_pages_to_raise += 1;
    }

    // Allocate new pages in R0 ptable (find free frames for each page etc.)
    for (int i = 0; i < num_pages_to_raise; i++) {
        int free_frame_idx = find_free_frame(g_frametable);

        // If physical memory runs out during setKernelBrk(), halt the CPU.
        // Don't care about the "memory leak".
        if (free_frame_idx < 0) {
            Halt();
            return ERROR;
        }

        g_frametable[free_frame_idx] = 1;  // mark frame as used

        // !!! Fixed bug: (current_page + i + 1) => assumes current_page has already been allocated
        // But we no longer make that assumption
        unsigned int next_page = current_page + i;
        g_reg0_ptable[next_page].valid = 1;
        g_reg0_ptable[next_page].prot = PROT_READ | PROT_WRITE;
        g_reg0_ptable[next_page].pfn = free_frame_idx;
    }

    g_kernel_brk = (void *)(UP_TO_PAGE(new_brk_int));

    return 0;
}

/**
 * Helper function called by SetKernelBrk(void *addr) in the case that addr < g_kernel_brk.
 *
 * Modifies (if need be)
 *      - The global R0 pagetable (allocates new pages)
 *      - g_kernel_brk
 */
int h_lower_brk(void *new_brk) {
    TracePrintf(2, "Calling h_lower_brk\n");

    unsigned int current_page = (unsigned int)g_kernel_brk >> PAGESHIFT;
    unsigned int new_page = (unsigned int)new_brk >> PAGESHIFT;

    unsigned int num_pages_to_lower = current_page - new_page;
    unsigned int new_brk_int = (unsigned int)new_brk;

    if (new_brk_int != (new_brk_int & PAGEMASK)) {
        num_pages_to_lower -= 1;
    }

    // "Frees" pages from R0 pagetable (marks those frames as unused, etc.)
    // Need to start deallocating a page below current brk page
    for (int i = 0; i < num_pages_to_lower; i++) {
        unsigned int prev_page = current_page - i - 1;
        unsigned int idx_to_free = g_reg0_ptable[prev_page].pfn;
        g_frametable[idx_to_free] = 0;  // mark frame as un-used

        g_reg0_ptable[prev_page].valid = 0;
        g_reg0_ptable[prev_page].prot = PROT_NONE;
        g_reg0_ptable[prev_page].pfn = 0;  // should never be touched
    }

    g_kernel_brk = (void *)(UP_TO_PAGE(new_brk_int));

    return 0;
}

/**
 *  Changes g_kernel_brk to new_brk. Handles case when virtual memory is not
 *  enabled and also the case when it is enabled. Also does associated tasks,
 *  such as allocating frames, updating R0 pagetable, etc.
 *
 *  Returns 0 if successful, ERROR if not.
 */
int SetKernelBrk(void *new_brk) {

    TracePrintf(2, "Calling SetKernelBrk w/ arg: %x (page %d)\n", new_brk,
                (unsigned int)new_brk >> PAGESHIFT);

    unsigned int new_brk_int = (unsigned int)new_brk;
    unsigned int last_addr_above_data = (unsigned int)(_kernel_data_end);

    // Fail if new_brk lies anywhere but the region above kernel data and below kernel stack.
    // Leave 1 page between kernel heap and stack (red zone!)
    if (!(new_brk_int <= (KERNEL_STACK_BASE - PAGESIZE) && new_brk_int >= last_addr_above_data)) {
        TracePrintf(1,
                    "oh no .. trying to extend kernel brk into kernel stack (or kernel "
                    "data/text)\n");
        return ERROR;
    }

    // If virtual memory is not enabled, safe to just change brk number,
    // no need to update tables or anything
    if (g_virtual_mem_enabled == 0) {
        g_kernel_brk = new_brk;
        return 0;
    }

    // Determine whether raising brk or lowering brk
    int bytes_to_raise = new_brk - g_kernel_brk;

    int rc = ERROR;

    if (bytes_to_raise == 0) {
        rc = 0;
    }
    // raising brk
    else if (bytes_to_raise > 0) {
        rc = h_raise_brk(new_brk);
    }
    // reducing brk
    else {
        rc = h_lower_brk(new_brk);
    }

    return rc;
}

/**
 *
 *  Parameters (manual p.70):
 *      - The cmd args argument is a vector of strings (in the same format
 *      as argv for normal Unix main programs), containing a pointer to each
 *      argument from the boot command line (what you typed at your Unix terminal)
 *      to start the machine and thus the kernel. The cmd args vector is terminated
 *      by a NULL pointer. (Recall Section 5.4.1.)
 *      - The pmem size argument is the size of the physical memory of the machine
 *      you are running on, as determined dynamically by the bootstrap firmware.
 *      The size of physical memory is given in units of bytes.
 *      - The uctxt argument is a pointer to an initial UserContext structure.
 *
 *  Initializing virtual memory:
 *      There are two things we need to do before enabling virtual memory.
 *          1. Create region 0 page table
 *          2. Create region 1 page table
 *      At this point, we do not need to create a PCB to hold these.
 *
 *      Now, the function is passed, in particular, the address of its initial
 *      (kernel) brk. Let the frame this address resides in be denoted `M`.
 *      So the next free memory starts after this value of brk, so we write
 *      the region 0 and region 1 pagetables contiguously starting here.
 *
 *      Suppose these two pagetables take up `d` bytes, for which we will need `D`
 *      more frames. Then we can set the pages 0 through M+D as valid in the
 *      region 0 pagetable, and make the frames they point to themselves, i.e.
 *      page 0 points to frame 0, etc. We remember also to set the kernel brk
 *      accordingly.
 *
 *      The region 1 pagetable will only have one valid page for the user stack.
 *      Let 'Z' be the maximum possible page in virtual memory. Then in the
 *      region 1 pagetable, set page `Z` to valid, and let it point to frame
 *      `M+D+1`. All other pages are not valid.
 *
 *      Now load page table locations into
 *      registers and THEN enable virtual memory.
 */
void KernelStart(char *cmd_args[], unsigned int pmem_size, UserContext *uctxt) {
    // Parse arguments
    TracePrintf(2, "Entering KernelStart\n");

    g_len_frametable = pmem_size / PAGESIZE;
    g_kernel_brk = _kernel_orig_brk;  // _k_orig_brk is populated by hardware
    g_virtual_mem_enabled = 0;

    // Debugging
    TracePrintf(2, "kernel orig brk: %x (p#: %d)\n", _kernel_orig_brk,
                (unsigned int)_kernel_orig_brk >> PAGESHIFT);
    TracePrintf(2, "kernel data start (lowest address in use): %x (p#: %d)\n", _kernel_data_start,
                (unsigned int)_kernel_data_start >> PAGESHIFT);
    TracePrintf(2, "kernel data end (lowest address not in use): %x (p#: %d)\n\n", _kernel_data_end,
                (unsigned int)_kernel_data_end >> PAGESHIFT);

    /* S=================== ALLOCATE + INITIALIZE PAGETABLES ==================== */
    /* Creating R0, R1 pagetables, and frametable. Put all these in kernel heap */

    g_reg0_ptable = malloc(sizeof(pte_t) * MAX_PT_LEN);
    if (g_reg0_ptable == NULL) {
        TracePrintf(1, "Malloc failed\n");
        return;
    }

    pte_t *init_r1_ptable = malloc(sizeof(pte_t) * MAX_PT_LEN);
    if (init_r1_ptable == NULL) {
        TracePrintf(1, "Malloc failed\n");
        return;
    }

    g_frametable = malloc(sizeof(int) * g_len_frametable);
    if (g_frametable == NULL) {
        TracePrintf(1, "Malloc failed\n");
        return;
    }

    // We allocated R0, R1 page tables above; loop through all pages in the page tables
    // and initialize the page table entries (pte) to invalid.
    pte_t empty_pte = {.valid = 0, .prot = 0, .pfn = 0};

    for (int i = 0; i < g_len_pagetable; i++) {
        g_reg0_ptable[i] = empty_pte;
        init_r1_ptable[i] = empty_pte;
    }

    // Also initialize frametable (to all 0; all free).
    for (int i = 0; i < g_len_frametable; i++) {
        g_frametable[i] = 0;
    }

    /* S=================== POPULATE PAGETABLES ==================== */

    // NO LONGER TRUE: If kernel brk is on 0th byte of new page initially, we allocate that page too.

    // the frame below the one kernel brk is on in physical memory.
    unsigned int last_used_reg0_frame = ((unsigned int)g_kernel_brk >> PAGESHIFT) - 1;

    unsigned int last_text_page = ((unsigned int)(_kernel_data_start) >> PAGESHIFT) - 1;
    unsigned int last_data_page = (unsigned int)(_kernel_data_end - 1) >> PAGESHIFT;

    /* Populate R0 ptable */
    for (int i = 0; i <= last_used_reg0_frame; i++) {

        int permission;

        // kernel text
        if (i <= last_text_page) {
            permission = PROT_READ | PROT_EXEC;
        }
        // kernel data
        else if (last_text_page < i && i <= last_data_page) {
            permission = PROT_READ | PROT_WRITE;
        }
        // kernel heap
        else {
            permission = PROT_READ | PROT_WRITE;
        }

        g_reg0_ptable[i].valid = 1;
        g_reg0_ptable[i].prot = permission;
        g_reg0_ptable[i].pfn = i;

        // Importaint: update frametable to mark assigned frame as occupied
        g_frametable[i] = 1;
    }

    /* Populate kernel stack part of R0 ptable. */

    // Set kernel stack page table entries to be valid.
    for (int i = 0; i < g_num_kernel_stack_pages; i++) {
        int idx = g_len_pagetable - 1 - i;
        g_reg0_ptable[idx].valid = 1;
        g_reg0_ptable[idx].prot = PROT_READ | PROT_WRITE;
        g_reg0_ptable[idx].pfn = idx;
        g_frametable[idx] = 1;  // mark frame as used
    }

    /* S=================== ENABLE VIRTUAL MEMORY ==================== */

    // Tell hardware where page tables are stored
    WriteRegister(REG_PTBR0, (unsigned int)g_reg0_ptable);
    WriteRegister(REG_PTLR0, MAX_PT_LEN);
    WriteRegister(REG_PTBR1, (unsigned int)init_r1_ptable);
    WriteRegister(REG_PTLR1, MAX_PT_LEN);

    //  Enable virtual memory
    g_virtual_mem_enabled = 1;
    WriteRegister(REG_VM_ENABLE, 1);

    /* S=================== TEST SetKernelBrk ==================== */

    // TracePrintf(2, "current brk: %x (p#: %d)\n", g_kernel_brk, (unsigned int)g_kernel_brk >> PAGESHIFT);

    // TracePrintf(2, "mallocing\n");
    // print_r0_page_table(g_reg0_ptable, g_len_pagetable, g_frametable);
    // void *my_p = malloc(PAGESIZE * 40);

    // TracePrintf(2, "freeing\n");
    // free(my_p);
    // print_r0_page_table(g_reg0_ptable, g_len_pagetable, g_frametable);

    // TracePrintf(2, "current brk: %x (p#: %d)\n", g_kernel_brk, (unsigned int)g_kernel_brk >> PAGESHIFT);

    /* E=================== TEST SetKernelBrk ==================== */

    /* S=================== SETUP PROCESS FOR FIRST PROGRAM ==================== */
    /**
     * The first program may be specified by the user as a command line argument,
     * for example `./yalnix my_program arg1 arg2`. If no program specified, e.g.
     * `./yalnix`, then find and run ./init in kernel.
     */

    pcb_t *init_pcb = malloc(sizeof(*init_pcb));

    /**
     * Need to initialize the following new pcb attributes:
     *      - zombie_procs
     *      - children_procs
     *      - exit_status
     *      - is_wait_blocked
     *      - term_bufs
     */

    init_pcb->zombie_procs = qopen();
    init_pcb->children_procs = qopen();
    init_pcb->exit_status = -1;
    init_pcb->is_wait_blocked = 0;
    // for (int i = 0; i < NUM_TERMINALS; i++) {
    //     init_pcb->term_bufs[i] = NULL;
    // }
    for (int i = 0; i < NUM_TERMINALS; i++) {
        g_term_bufs[i] = malloc(sizeof(term_buf_t));
        g_term_bufs[i]->ptr = NULL;
        g_term_bufs[i]->curr_pos_offset = 0;
        g_term_bufs[i]->end_pos_offset = 0;
    }

    init_pcb->pid = helper_new_pid(init_r1_ptable);
    init_pcb->r1_ptable = init_r1_ptable;

    // !!!! On the way into a handler (Transition 5), copy the current
    // UserContext into the PCB of the current proceess.
    memcpy(&(init_pcb->uctxt), uctxt, sizeof(UserContext));

    // TODO: convert to for loop
    init_pcb->kstack_frame_idxs[0] = g_len_pagetable - 1;
    init_pcb->kstack_frame_idxs[1] = g_len_pagetable - 2;

    /* Parse cmd_args to figure out which process to init with */
    unsigned int num_args = 0;

    char **tmp = cmd_args;
    while (*tmp != NULL) {
        num_args += 1;
        tmp++;
    }

    TracePrintf(2, "num args: %d\n", num_args);

    // Can't give too many arguments
    if (num_args > 20) {
        TracePrintf(1, "Can't give more than 20 arguments to your program!\n");
        return;
    }

    // TODO: check argument name length

    // If no arguments specified, load default ./init program
    char *first_process_name = num_args == 0 ? "tests/init" : cmd_args[0];
    TracePrintf(2, "first process name: %s\n", first_process_name);

    LoadProgram(first_process_name, cmd_args, init_pcb);

    // print_r0_page_table(g_reg0_ptable, g_len_pagetable, g_frametable);
    // print_r1_page_table(init_r1_ptable, g_len_pagetable);

    /* S=================== SETUP IVT ==================== */
    TracePrintf(2, "Setting up IVT\n");

    // Setup interrupt vector table (IVT). IVT is an array of function pointers. Each function
    // takes in a UserContext *, and returns an int
    int (**interrupt_vector_table_p)(UserContext *) =
        malloc(TRAP_VECTOR_SIZE * sizeof(*interrupt_vector_table_p));
    if (interrupt_vector_table_p == NULL) {
        TracePrintf(1, "malloc for IVT failed.\n");
        return;
    }

    // Populate IVT
    interrupt_vector_table_p[TRAP_KERNEL] = TrapKernelHandler;
    interrupt_vector_table_p[TRAP_CLOCK] = TrapClock;
    interrupt_vector_table_p[TRAP_ILLEGAL] = TrapIllegal;
    interrupt_vector_table_p[TRAP_MEMORY] = TrapMemory;
    interrupt_vector_table_p[TRAP_MATH] = TrapMath;
    interrupt_vector_table_p[TRAP_TTY_RECEIVE] = TrapTTYReceive;
    interrupt_vector_table_p[TRAP_TTY_TRANSMIT] = TrapTTYTransmit;
    interrupt_vector_table_p[TRAP_DISK] = TrapDisk;  // TRAP_DISK == 7

    // Many IVT entries are assigned a generic handler
    for (int i = 8; i < TRAP_VECTOR_SIZE; i++) {
        interrupt_vector_table_p[i] = GenericHandler;
    }

    // Tell hardware where IVT is
    WriteRegister(REG_VECTOR_BASE, (unsigned int)interrupt_vector_table_p);

    /* E=================== SETUP IVT ==================== */

    /* S=================== SETUP IDLE PROCESS ==================== */
    TracePrintf(2, "Setting up idle process\n");

    // Allocate an idlePCB for idle process. Returns virtual address in kernel heap
    g_idle_pcb = malloc(sizeof(*g_idle_pcb));
    if (g_idle_pcb == NULL) {
        TracePrintf(1, "malloc for idlePCB failed.\n");
        return;
    }

    /**
     * Need to initialize the following new pcb attributes:
     *      - zombie_procs
     *      - children_procs
     *      - exit_status
     *      - is_wait_blocked
     */

    g_idle_pcb->zombie_procs = qopen();
    g_idle_pcb->children_procs = qopen();
    g_idle_pcb->exit_status = -1;
    g_idle_pcb->is_wait_blocked = 0;

    pte_t *idle_r1_ptable = malloc(sizeof(pte_t) * g_len_pagetable);
    if (idle_r1_ptable == NULL) {
        TracePrintf(1, "Malloc failed for idle_r1_ptable\n");
        return;
    }

    // Initialize idle's r1 ptable to all zeros
    for (int i = 0; i < g_len_pagetable; i++) {
        idle_r1_ptable[i] = empty_pte;
    }

    // Populate idlePCB
    g_idle_pcb->r1_ptable = idle_r1_ptable;

    // !!!! On the way into a handler (Transition 5), copy the current
    // UserContext into the PCB of the current proceess.
    memcpy(&(g_idle_pcb->uctxt), uctxt, sizeof(UserContext));
    g_idle_pcb->pid = helper_new_pid(idle_r1_ptable);  // hardware defined function for generating PID
    g_idle_pcb->user_text_pg0 = 0;
    g_idle_pcb->user_data_pg0 = 0;

    TracePrintf(2, "Just populated idle's uctxt\n");

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
    g_term_blocked_read_queue = qopen();
    g_term_blocked_write_queue = qopen();
    g_term_blocked_transmit_queue = qopen();
    // g_wait_blocked_procs_queue = qopen();
    g_pipes_htable = hopen(30);
    g_locks_htable = hopen(30);
    g_cvars_htable = hopen(30);

    /* E=================== SETUP IDLE PROCESS ==================== */

    g_running_pcb = init_pcb;

    int rc = KernelContextSwitch(KCCopy, g_idle_pcb, NULL);
    TracePrintf(2, "Just finished KCCopy\n");

    // Should the following copy the entire saved user_context (and not just the pc and sp pointers?)
    // I think it doesn't matter here because the context-switching is between init and idle
    uctxt->pc = g_running_pcb->uctxt.pc;  // !!!!!!!!!!
    uctxt->sp = g_running_pcb->uctxt.sp;  // !!!!!!!!!!

    TracePrintf(2, "g_running_pcb's pid: %d\n", g_running_pcb->pid);
    TracePrintf(2, "Exiting KernelStart\n");
}
