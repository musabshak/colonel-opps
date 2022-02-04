
#include "hardware.h"
#include "kernel_data_structs.h"
#include "yalnix.h"

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

// Keep track of process numbers
int PID;

// Lock id counter
int LOCK_ID;

// Cvar id counter
int CVAR_ID;

// Currently running process
// pcb_t RUNNING_PROCESS;

// Shared kernel stuff, i.e. kernel heap, data, text
kershared_t *kershared;

// Frame table
frametable_t *frametable;

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
 *      Now we can enable virtual memory (??) and load page table locations into 
 *      registers.
 */
void KernelStart(char *cmd_args[], unsigned int pmem_size, UserContext *uctxt) {
    //  --- Create a (bit?) vector to track free frames
    // (function def in kernel_data_structs.c)
    frametable = frametable_init(pmem_size);

    // //  --- Set up initial Region 0 (see 8.2.2)
    // _kernel_data_start = TODO;  // lowest address in kernel data region
    // _kernel_data_end = TODO;    // lowest address not in use by kernel's instructions
    //                             // and global data at boot time
    // _kernel_orig_brk = TODO;    // the address the kernel library believes is its brk
    //                             // at boot time

    kershared = kershared_init(_kernel_data_start, _kernel_data_end, _kernel_orig_brk);

    //  --- Set up Region 1 page table for idle
    // should only have one valid page, for idle's user stack
    // (function def in kernel_data_structs.c)
    // pagetable_new();

    //  --- If pagetable_new() (or something else) has changed kernel's brk, i.e. by
    // calling SetKernelBrk(), then adjust page table

    //  --- Enable virtual memory
    virtual_mem_enabled = 1;
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
    void *diff = addr - kershared->brk;

    // if (virtual_mem_enabled == 0) {
    //     // safe to just change brk number, no need to update tables or anything
    //     return 0;
    // }s

    // --- Calculate how many frames you need using diff
    // --- Hunt down available frames from the frame data structure
    // --- Update all process pagetables, either by going through each one or
    // by keeping a global kernel pagetable that is shared by all process, includes
    // stuff from region 0 not including kernel stack.
    return 0;
}
