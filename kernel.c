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

void *kernel_brk;

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

// ==============================================//

typedef struct ProcessControlBlock pcb_t;

typedef struct ProcessControlBlock {
    unsigned int pid;
    // --- userland
    UserContext *uctxt;
    void *user_brk;
    void *user_data;
    void *user_text;
    // --- kernelland (don't need to keep track of heap/data/text because same for all processes)
    KernelContext kctxt;
    // --- metadata
    pcb_t *parent;
    queue_t *children_procs;
    pte_t *ptable;
} pcb_t;

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
    unsigned int frametable_size = pmem_size / PAGESIZE;

    // We will be allocating stuff on the kernel heap (brk will change in the next few operations)
    void *working_brk = _kernel_orig_brk;

    // Creating reg0 pagetable, reg1 pagetable, frametable and putting them in kernel heap
    pte_t *reg0_table = working_brk;
    working_brk += sizeof(pte_t) * MAX_PT_LEN + 1;

    pte_t *reg1_table = working_brk;
    working_brk += sizeof(pte_t) * MAX_PT_LEN + 1;

    unsigned int *frametable = working_brk;
    working_brk += sizeof(int) * frametable_size + 1;

    pte_t empty_pte = {
        .valid = 0,
        .prot = 0,
        .pfn = 0};

    // We allocated r0, r1 page tables above; loop through all pages in the page tables
    // and initialize the page table entries (ptes) to invalid.
    for (int i = 0; i < MAX_PT_LEN; i++) {
        reg0_table[i] = empty_pte;
        reg1_table[i] = empty_pte;
    }

    // Also initialize frametable (to all 0; all free)
    for (int i = 0; i < frametable_size; i++) {
        frametable[i] = 0;
    }

    // Populate region 0 pagetable
    unsigned int last_address_used = (unsigned int)(working_brk - 1);
    unsigned int last_used_reg0_frame = last_address_used >> PAGESHIFT;  // in physical memory

    unsigned int last_text_page = ((unsigned int)(_kernel_data_start) >> PAGESHIFT) - 1;
    unsigned int last_data_page = (unsigned int)(_kernel_data_end - 1) >> PAGESHIFT;

    // Note that permissions are in order: XWR
    // Permissions:
    // - Kernel text 5 = 101
    // - Kernel data 3 = 011
    // - Kernel heap 7 = 111
    for (int i = 0; i <= last_used_reg0_frame; i++) {
        int permission;

        // kernel text
        if (i <= last_text_page) {
            permission = 5;
        }
        // kernel data
        else if (last_text_page < i && i <= last_data_page) {
            permission = 3;
        }
        // kernel heap
        else {
            permission = 7;  // 111 == all
        }

        // kernel heap
        reg0_table[i].valid = 1;
        reg0_table[i].prot = permission;  // xrw= 111
        reg0_table[i].pfn = i;

        // Update frametable to mark assigned frame as occupied
        frametable[i] = 1;
    }

    // Set kernel stack page table entries to be valid
    reg0_table[127].valid = 1;
    reg0_table[127].prot = 3;
    reg0_table[127].pfn = 127;
    frametable[127] = 1;

    reg0_table[126].valid = 1;
    reg0_table[126].prot = 3;
    reg0_table[126].pfn = 126;
    frametable[126] = 1;

    //  --- Set one valid page (last page; bottom of user stack) in region 1 page table (for idle's user stack)
    reg1_table[MAX_PT_LEN - 1].valid = 1;
    reg1_table[MAX_PT_LEN - 1].prot = 6;                        // rwx = 110
    reg1_table[MAX_PT_LEN - 1].pfn = last_used_reg0_frame + 1;  // allocate next available free frame
    frametable[last_used_reg0_frame + 1] = 1;                   // mark frame as used

    //  --- If pagetable_new() (or something else) has changed kernel's brk, i.e. by
    // calling SetKernelBrk(), then adjust page table
    SetKernelBrk(working_brk);

    // TracePrintf(1, "Current page: %d\n", (unsigned int)working_brk >> PAGESqHIFT);

    //  --- Tell hardware where page tables are stored
    WriteRegister(REG_PTBR0, (unsigned int)reg0_table);
    WriteRegister(REG_PTLR0, MAX_PT_LEN);
    WriteRegister(REG_PTBR1, (unsigned int)reg1_table);
    WriteRegister(REG_PTLR1, MAX_PT_LEN);

    //  --- Enable virtual memory
    WriteRegister(REG_VM_ENABLE, 1);

    virtual_mem_enabled = 1;

    return 0;

    // // Create an idlePCB for idle process
    // pcb_t *idlePCB = malloc(sizeof(*idlePCB));  // kernel heap virtual address

    // idlePCB->ptable = reg1_table;
    // idlePCB->uctxt = uctxt;
    // idlePCB->pid = helper_new_pid(reg1_table);

    // // Set up interrupt vector table (IVT)
    // int (**interrupt_vector_table_p)(UserContext *) = malloc(TRAP_VECTOR_SIZE * sizeof(*interrupt_vector_table_p));

    // // Populate IVT
    // interrupt_vector_table_p[TRAP_KERNEL] = TrapKernelHandler;
    // interrupt_vector_table_p[TRAP_CLOCK] = TrapClock;
    // interrupt_vector_table_p[TRAP_ILLEGAL] = TrapIllegal;
    // interrupt_vector_table_p[TRAP_MEMORY] = TrapMemory;
    // interrupt_vector_table_p[TRAP_MATH] = GenericHandler;
    // interrupt_vector_table_p[TRAP_TTY_RECEIVE] = GenericHandler;
    // interrupt_vector_table_p[TRAP_TTY_TRANSMIT] = GenericHandler;
    // interrupt_vector_table_p[TRAP_DISK] = GenericHandler;  // 7

    // for (int i = 8; i < TRAP_VECTOR_SIZE; i++) {
    //     interrupt_vector_table_p[i] = GenericHandler;
    // }

    // // Write address of IVT into REG_VECTOR_BASE
    // WriteRegister(REG_VECTOR_BASE, (unsigned int)interrupt_vector_table_p);

    // // Modify UserContext to point pc to doIdle, and sp to point to top of user stack
    // uctxt->pc = doIdle;
    // uctxt->sp = (void *)(MAX_VPN << PAGESHIFT);  // same as VMEM1_LIMIT - 1
    // TracePrintf(2, "%d =? %d\n", MAX_VPN << PAGESHIFT, VMEM_1_LIMIT - 1);
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
int SetKernelBrk(void *addr) {
    // leave 1 page between kernel heap and stack (red zone!)
    if (!((unsigned int)addr < (KERNEL_STACK_BASE - PAGESIZE) && (unsigned int)addr > (unsigned int)(_kernel_data_end))) {
        TracePrintf(1, "oh no .. trying to extend kernel brk into kernel stack (or kernel data/text);");
        return ERROR;
    }

    if (virtual_mem_enabled == 0) {
        // safe to just change brk number, no need to update tables or anything
        kernel_brk = addr;
        return 0;
    }

    TracePrintf(1, "NOT ENOUGH MEMORY IN KERNEL HEAP; kernel brk happening\n");

    // --- Calculate how many frames you need using diff
    // --- Hunt down available frames from the frame data structure
    // --- Update all process pagetables, either by going through each one or
    // by keeping a global kernel pagetable that is shared by all process, includes
    // stuff from region 0 not including kernel stack.
    return 0;
}

void doIdle(void) {
    while (1) {
        TracePrintf(1, "DoIdle\n");
        Pause();
    }
}