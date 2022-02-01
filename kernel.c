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
bool virtual_mem_enabled;

// Keep track of process numbers
int pid;

// Lock id counter
int lock_id;

// Cvar id counter
int cvar_id;

// ProcessControlBlock
pcb_t;

// Currently running process
pcb_t running_process;

// Queue of ready, blocked, zombie processes
ready_procs_t;
blocked_procs_t;
zombie_procs_t;

// ==============================================//

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
 */
void KernelStart(char *cmg_args[], unsigned int pmem_size, UserContext *uctxt) {
    //  --- Create a (bit?) vector to track free frames
    // (function def in kernel_data_structs.c)
    frametable_init(pmem_size, PAGE_SIZE, 0);

    //  --- Set up initial Region 0
    _kernel_data_start = TODO;  // lowest address in kernel data region
    _kernel_data_end = TODO;    // lowest address not in use by kernel's instructions 
                                // and global data at boot time
    _kernel_orig_brk = TODO;    // the address the kernel library believes is its brk
                                // at boot time

    //  --- Set up Region 1 page table for idle
    // should only have one valid page, for idle's user stack
    // (function def in kernel_data_structs.c)
    pagetable_new();

    //  --- If pagetable_new() (or something else) has changed kernel's brk, i.e. by 
    // calling SetKernelBrk(), then adjust page table

    //  --- Enable virtual memory
    virtual_mem_enabled = true;
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
    int diff = addr - orig_brk;

    if (virtual_mem_enabled == false) {
        // safe to just change brk number, no need to update tables or anything
        return 0;
    }

    // --- Calculate how many frames you need using diff
    // --- Hunt down available frames from the frame data structure
    // --- Update all process pagetables, either by going through each one or
    // by keeping a global kernel pagetable that is shared by all process, includes 
    // stuff from region 0 not including kernel stack.
}
