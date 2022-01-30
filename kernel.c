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

// Keep track of process numbers
int current_pid;

// ProcessControlBlock
pcb_t;

// Currently running process
pcb_t current_process;

// Queue of ready, blocked, zombie processes
ready_procs_t;
blocked_procs_t;
zombie_procs_t;
