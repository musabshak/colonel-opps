/**
 * Authors: Varun Malladi and Musab Shakeel
 *
 */

// #include "kernel_data_structs.h"
#include "queue.h"
#include "trap_handlers.h"
#include "ykernel.h"

/*
 * =================================
 * === INITIALIZE VIRTUAL MEMORY ===
 * =================================
 * From the manual (p. 22):
 *      In order to initialize the virtual memory subsystem, the kernel
 *      must, for example, create an initial set of page table entries
 *      and must write the page table base and limit registers to tell the
 *      hardware where the page tables are located in memory.
 *
 * Functions:
 *      init_pagetable_entries();
 *      write_pagetable_bounds();
 *      enable_virtualmem();
 *
 * Initial virtual memory should be the same as physical memory, so that
 * addresses in use by the kernel before virtual memory was enabled are
 * still valid (p. 23).
 */

// ================= GLOBALS ===================//

// See if virtual memory enabled
int virtual_mem_enabled;

void *g_kernel_brk;

// Keep track of process numbers
int PID;

// Lock id counter
int LOCK_ID;

// Cvar id counter
int CVAR_ID;

// Currently running process
// pcb_t RUNNING_PROCESS;

// Shared kernel stuff, i.e. kernel heap, data, text
// kershared_t *kershared;

unsigned int g_len_frametable;
unsigned int g_len_pagetable = MAX_PT_LEN;

unsigned int *g_frametable;
pte_t *reg0_ptable;

// ==============================================//

typedef struct ProcessControlBlock pcb_t;

pcb_t *g_running_pcb;

typedef struct ProcessControlBlock {
    unsigned int pid;
    // --- userland
    UserContext *uctxt;
    void *user_brk;
    void *user_data;
    void *user_text;
    // --- kernelland (don't need to keep track of heap/data/text because same for all
    // processes)
    KernelContext kctxt;
    // --- metadata
    pcb_t *parent;
    queue_t *children_procs;
    pte_t *ptable;
} pcb_t;

// Utility function
void print_r0_page_table(pte_t *ptable, int size, int *frametable) {

    TracePrintf(1, "Printing R0 page table\n\n");

    TracePrintf(1, "%3s  %2s    %s|%s|%s\t  F used?\n", "Idx", "P#", "Valid", "Prot", "PFN#");
    for (int i = size - 1; i >= 0; i--) {
        TracePrintf(1, "%3d  %2x -->%5x|%4d|%4x\t  %d\n", i, i, ptable[i].valid, ptable[i].prot,
                    ptable[i].pfn, frametable[i]);
    }
    TracePrintf(1, "\n");
}

// Utility function
void print_r1_page_table(pte_t *ptable, int size) {

    TracePrintf(1, "Printing R1 page table\n\n");

    TracePrintf(1, "%3s  %2s    %s|%s|%s\n", "Idx", "P#", "Valid", "Prot", "PFN#");
    for (int i = size - 1; i >= 0; i--) {
        TracePrintf(1, "%3d  %2x -->%5x|%4d|%4x\n", i, i + size, ptable[i].valid, ptable[i].prot,
                    ptable[i].pfn);
    }
    TracePrintf(1, "\n");
}

// Given a frametable, return an index of a free frame
// Return -1 if error or if no free frame could be found
int find_free_frame(unsigned int *frametable) {

    for (int idx = 0; idx < g_len_frametable; idx++) {
        if (frametable[idx] == 0) {
            return idx;
        }
    }

    return -1;
}

void doIdle(void);

/**
 * ===================
 * === KERNELSTART ===
 * ===================
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
    g_kernel_brk = _kernel_orig_brk;

    // For debugging
    TracePrintf(1, "kernel orig brk: %x (p#: %x)\n", _kernel_orig_brk,
                (unsigned int)_kernel_orig_brk >> PAGESHIFT);
    TracePrintf(1, "kernel data start (lowest address in use): %x (p#: %x)\n", _kernel_data_start,
                (unsigned int)_kernel_data_start >> PAGESHIFT);
    TracePrintf(1, "kernel data end (lowest address not in use): %x (p#: %x)\n\n", _kernel_data_end,
                (unsigned int)_kernel_data_end >> PAGESHIFT);

    TracePrintf(1, "size of pte_t: %d bytes\n", sizeof(pte_t));
    TracePrintf(1, "size of int: %d bytes\n\n", sizeof(int));
    TracePrintf(1, "frametable size: %d entries\n", g_len_frametable);

    // Creating reg0 pagetable, reg1 pagetable, frametable and putting them in kernel heap
    reg0_ptable = malloc(sizeof(pte_t) * MAX_PT_LEN);

    // Check that malloc was successful
    if (reg0_ptable == NULL) {
        TracePrintf(2, "Malloc failed\n");
        return;
    }

    pte_t *reg1_table = malloc(sizeof(pte_t) * MAX_PT_LEN);

    // Check that malloc was successful
    if (reg1_table == NULL) {
        TracePrintf(2, "Malloc failed\n");
        return;
    }

    g_frametable = malloc(sizeof(int) * g_len_frametable);

    if (g_frametable == NULL) {
        TracePrintf(2, "Malloc failed\n");
        return;
    }

    pte_t empty_pte = {.valid = 0, .prot = 0, .pfn = 0};

    // We allocated r0, r1 page tables above; loop through all pages in the page tables
    // and initialize the page table entries (ptes) to invalid.
    for (int i = 0; i < g_len_pagetable; i++) {
        reg0_ptable[i] = empty_pte;
        reg1_table[i] = empty_pte;
    }

    // Also initialize frametable (to all 0; all free)
    for (int i = 0; i < g_len_frametable; i++) {
        g_frametable[i] = 0;
    }

    // print_r0_page_table(reg0_ptable, MAX_PT_LEN, g_frametable);
    // print_r1_page_table(reg1_table, MAX_PT_LEN);

    // Populate region 0 pagetable
    // unsigned int last_address_used = (unsigned int)(g_kernel_brk - 1);

    // NOTE: If kernel brk is on 0th byte of new page initially, we allocate that page too
    // the frame that kernel brk is on
    unsigned int last_used_reg0_frame = (unsigned int)g_kernel_brk >> PAGESHIFT;  // in physical memory

    unsigned int last_text_page = ((unsigned int)(_kernel_data_start) >> PAGESHIFT) - 1;
    unsigned int last_data_page = (unsigned int)(_kernel_data_end - 1) >> PAGESHIFT;

    TracePrintf(1, "last_used_reg0_frame: %x\n", last_used_reg0_frame);

    // Permission
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

        // kernel heap
        reg0_ptable[i].valid = 1;
        reg0_ptable[i].prot = permission;
        reg0_ptable[i].pfn = i;

        // Update frametable to mark assigned frame as occupied
        g_frametable[i] = 1;
    }

    // Set kernel stack page table entries to be valid
    int num_kernel_stack_pages = KERNEL_STACK_MAXSIZE / PAGESIZE;

    for (int i = 0; i < num_kernel_stack_pages; i++) {
        int idx = g_len_pagetable - 1 - i;
        reg0_ptable[idx].valid = 1;
        reg0_ptable[idx].prot = PROT_READ | PROT_WRITE;
        reg0_ptable[idx].pfn = idx;
    }

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

    // Print ptables after populating
    print_r0_page_table(reg0_ptable, g_len_pagetable, g_frametable);
    // print_r1_page_table(reg1_table, g_len_pagetable);

    //  --- Tell hardware where page tables are stored
    WriteRegister(REG_PTBR0, (unsigned int)reg0_ptable);
    WriteRegister(REG_PTLR0, MAX_PT_LEN);
    WriteRegister(REG_PTBR1, (unsigned int)reg1_table);
    WriteRegister(REG_PTLR1, MAX_PT_LEN);

    //  --- Enable virtual memory
    virtual_mem_enabled = 1;
    WriteRegister(REG_VM_ENABLE, 1);

    // Create an idlePCB for idle process
    pcb_t *idlePCB = malloc(sizeof(*idlePCB));  // kernel heap virtual address

    idlePCB->ptable = reg1_table;
    idlePCB->uctxt = uctxt;
    idlePCB->pid = helper_new_pid(reg1_table);

    // Set up interrupt vector table (IVT)
    int (**interrupt_vector_table_p)(UserContext *) =
        malloc(TRAP_VECTOR_SIZE * sizeof(*interrupt_vector_table_p));

    // Populate IVT
    interrupt_vector_table_p[TRAP_KERNEL] = TrapKernelHandler;
    interrupt_vector_table_p[TRAP_CLOCK] = TrapClock;
    interrupt_vector_table_p[TRAP_ILLEGAL] = TrapIllegal;
    interrupt_vector_table_p[TRAP_MEMORY] = TrapMemory;
    interrupt_vector_table_p[TRAP_MATH] = GenericHandler;
    interrupt_vector_table_p[TRAP_TTY_RECEIVE] = GenericHandler;
    interrupt_vector_table_p[TRAP_TTY_TRANSMIT] = GenericHandler;
    interrupt_vector_table_p[TRAP_DISK] = GenericHandler;  // 7

    for (int i = 8; i < TRAP_VECTOR_SIZE; i++) {
        interrupt_vector_table_p[i] = GenericHandler;
    }

    // Write address of IVT into REG_VECTOR_BASE
    WriteRegister(REG_VECTOR_BASE, (unsigned int)interrupt_vector_table_p);

    // Modify UserContext to point pc to doIdle, and sp to point to top of user stack
    uctxt->pc = doIdle;

    // Stack values increment in 4 bytes; Intel is little-endian; sp needs to point to
    // 0x1ffffc
    uctxt->sp = (void *)(VMEM_LIMIT - 4);

    int addr_last_vpn = (unsigned int)MAX_VPN << PAGESHIFT;

    // TracePrintf(1, "VMEM_LIMIT: 0x%x == %d\n", VMEM_LIMIT, VMEM_LIMIT);
    // TracePrintf(1, "VMEM_LIMIT - 1: 0x%x == %d\n", VMEM_LIMIT - 1, VMEM_LIMIT - 1);
    // TracePrintf(1, "addr of 0th byte of last page: 0x%x == %d\n", addr_last_vpn,
    //             addr_last_vpn);
    // TracePrintf(1, "addr of last byte of last page: 0x%x == %d\n",
    //             addr_last_vpn + PAGESIZE - 1, addr_last_vpn + PAGESIZE - 1);

    g_running_pcb = idlePCB;
}

int h_raise_brk(void *new_brk) {
    // ERROR checking
    TracePrintf(1, "Calling h_raise_brk\n");

       unsigned int current_page = (unsigned int)g_kernel_brk >> PAGESHIFT;
    unsigned int new_page = (unsigned int)new_brk >> PAGESHIFT;
    unsigned int pages_requested = new_page - current_page;

    for (int i = 0; i < pages_requested; i++) {
        int free_frame_idx = find_free_frame(g_frametable);
        if (free_frame_idx < 0) {
            return ERROR;
        }

        unsigned int next_page = ((unsigned int)g_kernel_brk >> PAGESHIFT) + i + 1;
        reg0_ptable[next_page].valid = 1;
        reg0_ptable[next_page].prot = PROT_READ | PROT_WRITE;
        reg0_ptable[next_page].pfn = free_frame_idx;
    }

    g_kernel_brk = new_brk;

    return 0;
}
/**
 *  From manual (p. 71):
 *      The argument addr here is similar to that used by user processes in
 *      calls to Brk and indicates the lowest location not used (not yet needed
 *      by malloc) in your kernel.
 *      In your kernel, you should keep a flag to indicate if you have yet enabled
 *      virtual memory. Before enabling virtual memory, SetKernelBrk only needs
 *      to track if and by how much the kernel brk is being raised beyond kernel
 *      orig brk. After VM is enabled, SetKernelBrk acts like the standard Brk,
 *      but for userland.
 *      SetKernelBrk should return 0 if successful, and ERROR if not.
 *      (But be warned: that ERROR may lead to a kernel malloc call returning NULL.)
 */
int SetKernelBrk(void *new_brk) {

    TracePrintf(1, "CALLING KERNEL BRK w/ arg: %x\n", new_brk);

    // leave 1 page between kernel heap and stack (red zone!)
    if (!((unsigned int)new_brk < (KERNEL_STACK_BASE - PAGESIZE) &&
          (unsigned int)new_brk > (unsigned int)(_kernel_data_end))) {
        TracePrintf(1,
                    "oh no .. trying to extend kernel brk into kernel stack (or kernel "
                    "data/text)\n");
        return ERROR;
    }

    if (virtual_mem_enabled == 0) {
        // safe to just change brk number, no need to update tables or anything
        g_kernel_brk = new_brk;
        return 0;
    }

    // --- Calculate how many frames you need using diff
    // --- Hunt down available frames from the frame data structure
    // --- Update all process pagetables, either by going through each one or
    // by keeping a global kernel pagetable that is shared by all process, includes
    // stuff from region 0 not including kernel stack.
    int bytes_to_raise = new_brk - g_kernel_brk;

    if (bytes_to_raise == 0) {
        return 0;
    }
    // raising brk
    else if (bytes_to_raise > 0) {
        h_raise_brk(new_brk);
    }
    // reducing brk
    else {
    }
}

// Imitate a userland program
void doIdle(void) {
    while (1) {
        TracePrintf(1, "DoIdle\n");
        Pause();
    }
}