/**
 * Authors: Varun Malladi and Musab Shakeel
 * Date: 2/5/2022
 *
 * This file contains the executable kernel code for the colonel-opps OS.
 *
 * Global variables are prepended
 */

// #include "kernel_data_structs.h"
#include "kernel_data_structs.h"
#include "load_program.h"
#include "queue.h"
#include "trap_handlers.h"
#include "ykernel.h"

/* ================ */
/* S=== GLOBALS === */
/* ================ */

int g_virtual_mem_enabled;  // 1 if virtual memory enabled, 0 otherwise

void *g_kernel_brk;  // global variable storing kernel brk

int CVAR_ID;  // Cvar id counter

unsigned int g_len_frametable;  // number of frames in physical memory, populated by KernelStart

unsigned int g_len_pagetable = MAX_PT_LEN;  // number of pages in R0 or R1 pagetable

unsigned int *g_frametable;  // bitvector containing info on used/unused physical
                             // memory frames

pte_t *g_reg0_ptable;  // pagetable for kernel structures shared accross processes

pcb_t *g_running_pcb;  // pcb of process that is currently running
pcb_t *g_idle_pcb;

unsigned int g_num_kernel_stack_pages = KERNEL_STACK_MAXSIZE / PAGESIZE;

queue_t *g_ready_procs_queue;

/* E=== GLOBALS === */

/* ========================= */
/* S== UTILITY FUNCTIONS === */
/* ========================= */

void print_r0_page_table(pte_t *ptable, int size, int *frametable) {

    TracePrintf(1, "Printing R0 page table\n\n");

    TracePrintf(1, "%3s  %2s    %s|%s|%s\t  F used?\n", "Idx", "P#", "Valid", "Prot", "PFN#");
    for (int i = size - 1; i >= 0; i--) {
        TracePrintf(1, "%3d  %2x -->%5x|%4d|%4x\t  %d\n", i, i, ptable[i].valid, ptable[i].prot,
                    ptable[i].pfn, frametable[i]);
    }
    TracePrintf(1, "\n");
}

void print_r1_page_table(pte_t *ptable, int size) {

    TracePrintf(1, "Printing R1 page table\n\n");

    TracePrintf(1, "%3s  %2s    %s|%s|%s\n", "Idx", "P#", "Valid", "Prot", "PFN#");
    for (int i = size - 1; i >= 0; i--) {
        TracePrintf(1, "%3d  %2x -->%5x|%4d|%4x\n", i, i + size, ptable[i].valid, ptable[i].prot,
                    ptable[i].pfn);
    }
    TracePrintf(1, "\n");
}

/* E== UTILITY FUNCTIONS === */

// Imitate a userland program for checkpoint 2.
void doIdle(void) {
    while (1) {
        TracePrintf(1, "DoIdle\n");
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
    // TracePrintf(1, "Calling h_raise_brk\n");

    unsigned int current_page = (unsigned int)g_kernel_brk >> PAGESHIFT;
    unsigned int new_page = (unsigned int)new_brk >> PAGESHIFT;
    unsigned int num_pages_to_raise = new_page - current_page;

    // Allocate new pages in R0 ptable (find free frames for each page etc.)
    for (int i = 0; i < num_pages_to_raise; i++) {
        int free_frame_idx = find_free_frame(g_frametable);
        g_frametable[free_frame_idx] = 1;  // mark frame as used

        // no free frames were found
        if (free_frame_idx < 0) {
            return ERROR;
        }

        // (current_page + i + 1) => assumes current_page has already been allocated
        unsigned int next_page = current_page + i + 1;
        g_reg0_ptable[next_page].valid = 1;
        g_reg0_ptable[next_page].prot = PROT_READ | PROT_WRITE;
        g_reg0_ptable[next_page].pfn = free_frame_idx;
    }

    g_kernel_brk = new_brk;

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
    // TracePrintf(1, "Calling h_lower_brk\n");

    unsigned int current_page = (unsigned int)g_kernel_brk >> PAGESHIFT;
    unsigned int new_page = (unsigned int)new_brk >> PAGESHIFT;
    unsigned int num_pages_to_lower = current_page - new_page;

    // "Frees" pages from R0 pagetable (marks those frames as unused, etc.)
    for (int i = 0; i < num_pages_to_lower; i++) {
        unsigned int prev_page = current_page - i;
        unsigned int idx_to_free = g_reg0_ptable[prev_page].pfn;
        g_frametable[idx_to_free] = 0;  // mark frame as un-used

        g_reg0_ptable[prev_page].valid = 0;
        g_reg0_ptable[prev_page].prot = PROT_NONE;
        g_reg0_ptable[prev_page].pfn = 0;  // should never be touched
    }

    g_kernel_brk = new_brk;

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

    TracePrintf(1, "Calling SetKernelBrk w/ arg: %x\n", new_brk);

    unsigned int new_brk_int = (unsigned int)new_brk;
    unsigned int last_addr_above_data = (unsigned int)(_kernel_data_end);

    // Fail if new_brk lies anywhere but the region above kernel data and below kernel stack.
    // Leave 1 page between kernel heap and stack (red zone!)
    if (!(new_brk_int < (KERNEL_STACK_BASE - PAGESIZE) && new_brk_int >= last_addr_above_data)) {
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

int copy_page_contents(unsigned int source_page, unsigned int target_page) {

    memcpy((void *)(target_page << PAGESHIFT), (void *)(source_page << PAGESHIFT), PAGESIZE);

    return SUCCESS;
}

KernelContext *KCCopy(KernelContext *kc_in, void *new_pcb_p, void *not_used) {
    // Copy the kernel context of old process into the new process
    pcb_t *new_pcb = ((pcb_t *)new_pcb_p);
    new_pcb->kctxt = *kc_in;

    unsigned int page_below_kstack = g_len_pagetable - g_num_kernel_stack_pages;

    // Copy contents of current kernel stack (g_r0_ptable) into frames allocated for the new process's
    // kernel stack
    for (int i = 0; i < g_num_kernel_stack_pages; i++) {

        // Map page below kernel stack to allocated free frame for new kernel stack. This is a hack for
        // copying pages into unmapped frames (unmapped frames for new kernel stack).
        g_reg0_ptable[page_below_kstack].valid = 1;
        g_reg0_ptable[page_below_kstack].prot = PROT_READ | PROT_WRITE;
        g_reg0_ptable[page_below_kstack].pfn = new_pcb->kstack_frame_idxs[i];

        // Copy page contents
        unsigned int source_page = g_len_pagetable - 1 - i;
        unsigned int target_page = page_below_kstack;
        int rc = copy_page_contents(source_page, target_page);

        if (rc != 0) {
            TracePrintf(1, "Error occurred in copy_page_contents in KCCopy()\n");
            return NULL;
        }
    }

    // Make redzone page invalid again
    g_reg0_ptable[page_below_kstack].valid = 0;
    g_reg0_ptable[page_below_kstack].prot = PROT_NONE;

    return kc_in;
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

    g_len_frametable = pmem_size / PAGESIZE;
    g_kernel_brk = _kernel_orig_brk;  // _k_orig_brk is populated by hardware

    // Debugging
    // TracePrintf(1, "kernel orig brk: %x (p#: %x)\n", _kernel_orig_brk,
    //             (unsigned int)_kernel_orig_brk >> PAGESHIFT);
    // TracePrintf(1, "kernel data start (lowest address in use): %x (p#: %x)\n", _kernel_data_start,
    //             (unsigned int)_kernel_data_start >> PAGESHIFT);
    // TracePrintf(1, "kernel data end (lowest address not in use): %x (p#: %x)\n\n", _kernel_data_end,
    //             (unsigned int)_kernel_data_end >> PAGESHIFT);

    // TracePrintf(1, "size of pte_t: %d bytes\n", sizeof(pte_t));
    // TracePrintf(1, "size of int: %d bytes\n\n", sizeof(int));
    // TracePrintf(1, "frametable size: %d entries\n", g_len_frametable);

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
        TracePrintf(2, "Malloc failed\n");
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

    // Debugging
    // print_r0_page_table(g_reg0_ptable, g_len_pagetable, g_frametable);
    // print_r1_page_table(init_r1_ptable, g_len_pagetable);

    /* S=================== POPULATE PAGETABLES ==================== */

    // NOTE: If kernel brk is on 0th byte of new page initially, we allocate that page too.

    // the frame that kernel brk is on in physical memory.
    unsigned int last_used_reg0_frame = (unsigned int)g_kernel_brk >> PAGESHIFT;

    unsigned int last_text_page = ((unsigned int)(_kernel_data_start) >> PAGESHIFT) - 1;
    unsigned int last_data_page = (unsigned int)(_kernel_data_end - 1) >> PAGESHIFT;

    // Debugging
    // TracePrintf(1, "last_used_reg0_frame: %x\n", last_used_reg0_frame);

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

    // /* Populate R1 ptable. */

    // //  Set one valid page in R1 page table for idle's user stack.
    // init_r1_ptable[g_len_pagetable - 1].valid = 1;
    // init_r1_ptable[g_len_pagetable - 1].prot = PROT_READ | PROT_WRITE;

    // int free_frame_idx = find_free_frame(g_frametable);

    // if (free_frame_idx == -1) {
    //     TracePrintf(1, "No free frame found!\n");
    //     return;
    // }

    // init_r1_ptable[g_len_pagetable - 1].pfn = free_frame_idx;
    // g_frametable[free_frame_idx] = 1;  // mark frame as used

    // Debugging
    // Print ptables after populating
    // print_r0_page_table(g_reg0_ptable, g_len_pagetable, g_frametable);
    // print_r1_page_table(init_r1_ptable, g_len_pagetable);

    /* S=================== ENABLE VIRTUAL MEMORY ==================== */

    // Tell hardware where page tables are stored
    WriteRegister(REG_PTBR0, (unsigned int)g_reg0_ptable);
    WriteRegister(REG_PTLR0, MAX_PT_LEN);
    WriteRegister(REG_PTBR1, (unsigned int)init_r1_ptable);
    WriteRegister(REG_PTLR1, MAX_PT_LEN);

    //  Enable virtual memory
    g_virtual_mem_enabled = 1;
    WriteRegister(REG_VM_ENABLE, 1);

    /* S=================== SETUP PROCESS FOR FIRST PROGRAM ==================== */
    /**
     * The first program may be specified by the user as a command line argument,
     * for example `./yalnix my_program arg1 arg2`. If no program specified, e.g.
     * `./yalnix`, then find and run ./init in kernel.
     */

    pcb_t *init_pcb = malloc(sizeof(*init_pcb));

    init_pcb->pid = helper_new_pid(init_r1_ptable);
    init_pcb->r1_ptable = init_r1_ptable;
    init_pcb->uctxt = *uctxt;
    init_pcb->kstack_frame_idxs[0] = g_len_pagetable - 1;
    init_pcb->kstack_frame_idxs[1] = g_len_pagetable - 2;

    // Get free frames for init's kernel stack
    // for (int i = 0; i < g_num_kernel_stack_pages; i++) {
    //     int idx = find_free_frame(g_frametable);

    //     if (idx != 0) {
    //         TracePrintf(1, "find_free_frame() failed\n");
    //         return;
    //     }
    //     init_pcb->kstack_frame_idxs[i] = idx;
    //     g_frametable[idx] = 1;
    // }

    /* Parse cmd_args to figure out which process to init with */
    unsigned int num_args = 0;

    char **tmp = cmd_args;
    while (tmp != NULL) {
        tmp++;
        num_args += 1;
    }

    // Can't give too many arguments
    if (num_args > 10) {
        TracePrintf(1, "Can't give more than 9 arguments to your program!\n");
        return;
    }

    // TODO: check argument name length

    // If no arguments specified, load default ./init program
    char *first_process_name = num_args == 0 ? "init" : cmd_args[0];

    LoadProgram(first_process_name, cmd_args, init_pcb);

    /* S=================== SETUP IVT ==================== */

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
    interrupt_vector_table_p[TRAP_MATH] = GenericHandler;
    interrupt_vector_table_p[TRAP_TTY_RECEIVE] = GenericHandler;
    interrupt_vector_table_p[TRAP_TTY_TRANSMIT] = GenericHandler;
    interrupt_vector_table_p[TRAP_DISK] = GenericHandler;  // TRAP_DISK == 7

    // Many IVT entries are assigned a generic handler
    for (int i = 8; i < TRAP_VECTOR_SIZE; i++) {
        interrupt_vector_table_p[i] = GenericHandler;
    }

    // Tell hardware where IVT is
    WriteRegister(REG_VECTOR_BASE, (unsigned int)interrupt_vector_table_p);

    /* E=================== SETUP IVT ==================== */

    /* S=================== SETUP IDLE PROCESS ==================== */

    // Allocate an idlePCB for idle process. Returns virtual address in kernel heap
    g_idle_pcb = malloc(sizeof(*g_idle_pcb));
    if (g_idle_pcb == NULL) {
        TracePrintf(1, "malloc for idlePCB failed.\n");
        return;
    }

    pte_t *idle_r1_ptable = malloc(sizeof(pte_t) * g_len_pagetable);
    if (idle_r1_ptable == NULL) {
        TracePrintf(1, "Malloc failed for idle_r1_ptable\n");
        return;
    }

    // Populate idlePCB
    g_idle_pcb->r1_ptable = idle_r1_ptable;
    g_idle_pcb->uctxt = *uctxt;
    g_idle_pcb->pid = helper_new_pid(idle_r1_ptable);  // hardware defined function for generating PID

    int rc = KernelContextSwitch(KCCopy, g_idle_pcb, NULL);
    /* E=================== SETUP IDLE PROCESS ==================== */

    /* S=================== PREPARE TO RETURN CONTROL TO USERLAND ==================== */

    /* Modify UserContext to point pc to doIdle, and sp to point to top of user stack */

    uctxt->pc = init_pcb->uctxt.pc;
    uctxt->sp = init_pcb->uctxt.sp;

    // // Stack values increment in 4 bytes. Intel is little-endian; sp needs to point to
    // // 0x1ffffc (and not 0x1fffff)
    // uctxt->sp = (void *)(VMEM_LIMIT - 4);

    /* S=================== PREPARE TO RETURN CONTROL TO USERLAND ==================== */

    g_running_pcb = init_pcb;
}
