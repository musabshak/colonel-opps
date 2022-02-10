/**
 * Authors: Varun Malladi and Musab Shakeel
 * Date: 2/5/2022
 *
 * This file contains the executable kernel code for the colonel-opps OS.
 *
 * Global variables are prepended
 */

// #include "kernel_data_structs.h"
#include "queue.h"
#include "trap_handlers.h"
#include "ykernel.h"

typedef struct ProcessControlBlock pcb_t;

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

pte_t *reg0_ptable;  // pagetable for kernel structures shared accross processes

pcb_t *g_running_pcb;  // pcb of process that is currently running

/* E=== GLOBALS === */

/* ======================= */
/* S== DATA STRUCTURES === */
/* ======================= */

typedef struct ProcessControlBlock {
    unsigned int pid;
    // --- userland
    UserContext *uctxt;
    void *user_brk;
    void *user_data;
    void *user_text;

    KernelContext kctxt;
    // --- metadata
    pcb_t *parent;
    queue_t *children_procs;
    pte_t *ptable;
} pcb_t;

/* E== DATA STRUCTURES === */

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

/**
 * Returns index of first free frame in given frame table. Returns -1 if no free frames
 * available.
 *
 * Note that this function does *not* mark the frame as "used" in the frametable.
 */
int find_free_frame(unsigned int *frametable) {
    for (int idx = 0; idx < g_len_frametable; idx++) {
        if (frametable[idx] == 0) {
            return idx;
        }
    }
    return -1;
}

// Imitate a userland program for checkpoint 2.
void doIdle(void) {
    while (1) {
        TracePrintf(1, "DoIdle\n");
        Pause();
    }
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

    /* S=================== ALLOCATE + INITIALIZE PAGETABLES ==================== */
    /* Creating R0, R1 pagetables, and frametable. Put all these in kernel heap */

    reg0_ptable = malloc(sizeof(pte_t) * MAX_PT_LEN);
    if (reg0_ptable == NULL) {
        TracePrintf(1, "Malloc failed\n");
        return;
    }

    pte_t *reg1_table = malloc(sizeof(pte_t) * MAX_PT_LEN);
    if (reg1_table == NULL) {
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
        reg0_ptable[i] = empty_pte;
        reg1_table[i] = empty_pte;
    }

    // Also initialize frametable (to all 0; all free).
    for (int i = 0; i < g_len_frametable; i++) {
        g_frametable[i] = 0;
    }

    /* S=================== POPULATE PAGETABLES ==================== */

    // NOTE: If kernel brk is on 0th byte of new page initially, we allocate that page too.

    // the frame that kernel brk is on in physical memory.
    unsigned int last_used_reg0_frame = (unsigned int)g_kernel_brk >> PAGESHIFT;

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

        reg0_ptable[i].valid = 1;
        reg0_ptable[i].prot = permission;
        reg0_ptable[i].pfn = i;

        // Importaint: update frametable to mark assigned frame as occupied
        g_frametable[i] = 1;
    }

    /* Populate kernel stack part of R0 ptable. */

    // Set kernel stack page table entries to be valid.
    int num_kernel_stack_pages = KERNEL_STACK_MAXSIZE / PAGESIZE;

    for (int i = 0; i < num_kernel_stack_pages; i++) {
        int idx = g_len_pagetable - 1 - i;
        reg0_ptable[idx].valid = 1;
        reg0_ptable[idx].prot = PROT_READ | PROT_WRITE;
        reg0_ptable[idx].pfn = idx;
        g_frametable[idx] = 1;  // mark frame as used
    }

    /* Populate R1 ptable. */

    //  Set one valid page in R1 page table for idle's user stack.
    reg1_table[g_len_pagetable - 1].valid = 1;
    reg1_table[g_len_pagetable - 1].prot = PROT_READ | PROT_WRITE;

    int free_frame_idx = find_free_frame(g_frametable);

    if (free_frame_idx == -1) {
        TracePrintf(1, "No free frame found!\n");
        return;
    }

    reg1_table[g_len_pagetable - 1].pfn = free_frame_idx;
    g_frametable[free_frame_idx] = 1;  // mark frame as used

    /* S=================== ENABLE VIRTUAL MEMORY ==================== */

    // Tell hardware where page tables are stored
    WriteRegister(REG_PTBR0, (unsigned int)reg0_ptable);
    WriteRegister(REG_PTLR0, MAX_PT_LEN);
    WriteRegister(REG_PTBR1, (unsigned int)reg1_table);
    WriteRegister(REG_PTLR1, MAX_PT_LEN);

    //  Enable virtual memory
    g_virtual_mem_enabled = 1;
    WriteRegister(REG_VM_ENABLE, 1);

    /* S=================== SETUP IDLE PROCESS ==================== */

    // Allocate an idlePCB for idle process. Returns virtual address in kernel heap
    pcb_t *idlePCB = malloc(sizeof(*idlePCB));
    if (idlePCB == NULL) {
        TracePrintf(1, "malloc for idlePCB failed.\n");
        return;
    }

    // Populate idlePCB
    idlePCB->ptable = reg1_table;
    idlePCB->uctxt = uctxt;
    idlePCB->pid = helper_new_pid(reg1_table);  // hardware defined function for generating PID

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

    /* Modify UserContext to point pc to doIdle, and sp to point to top of user stack */

    uctxt->pc = doIdle;

    // Stack values increment in 4 bytes. Intel is little-endian; sp needs to point to
    // 0x1ffffc (and not 0x1fffff)
    uctxt->sp = (void *)(VMEM_LIMIT - 4);

    // return from KernelStart running idle process
    g_running_pcb = idlePCB;
}

/**
 * Helper function called by SetKernelBrk(void *addr) in the case that addr > g_kernel_brk.
 *
 * Modifies (if need be)
 *      - The global R0 pagetable (allocates new pages)
 *      - g_kernel_brk
 */
int h_raise_brk(void *new_brk) {

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
        reg0_ptable[next_page].valid = 1;
        reg0_ptable[next_page].prot = PROT_READ | PROT_WRITE;
        reg0_ptable[next_page].pfn = free_frame_idx;
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

    unsigned int current_page = (unsigned int)g_kernel_brk >> PAGESHIFT;
    unsigned int new_page = (unsigned int)new_brk >> PAGESHIFT;
    unsigned int num_pages_to_lower = current_page - new_page;

    // "Frees" pages from R0 pagetable (marks those frames as unused, etc.)
    for (int i = 0; i < num_pages_to_lower; i++) {
        unsigned int prev_page = current_page - i;
        unsigned int idx_to_free = reg0_ptable[prev_page].pfn;
        g_frametable[idx_to_free] = 0;  // mark frame as un-used

        reg0_ptable[prev_page].valid = 0;
        reg0_ptable[prev_page].prot = PROT_NONE;
        reg0_ptable[prev_page].pfn = 0;  // should never be touched
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
