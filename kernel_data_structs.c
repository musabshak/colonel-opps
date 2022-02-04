
#include "hardware.h"
#include "queue.h"  // generic queue DS imported from engs50 code
#include "yalnix.h"
#include "ylib.h"

/**
 * ========================
 * === GLOBAL PROCESS QUEUES ====
 * ========================
 */
// queue_t *READY_PROCESSES = qopen();
// queue_t *BLOCKED_PROCESSES = qopen();
// queue_t *ZOMBIE_PROCESSES = qopen();

/*
 * ===============
 * === PROCESS ===
 * ===============
 *
 */

typedef struct ProcessControlBlock {
    unsigned int pid;
    // --- userland
    UserContext uctxt;
    void *user_brk;
    void *user_data;
    void *user_text;
    // --- kernelland (don't need to keep track of heap/data/text because same for all processes)
    KernelContext kctxt;
    // --- metadata
    pcb_t *parent;
    queue_t *children_procs;
    pagetable_t *ptable;
} pcb_t;

pcb_t *pcb_init(UserContext *init_uctxt) {
    pcb_t *idle_pcb = malloc(sizeof(pcb_t));

    idle_pcb->uctxt = init_uctxt;

    // Set the pc in uctxt to point to idle function in kernel text
    idle_pcb->uctxt->pc = ? ? ? ;
    idle_pcb->pid = PID++;

    // Create page table
    pagetable_t *pagetable = pagetable_init();
    // One valid pte
    pte_t *valid_pte = pagetable->table[pagetable->size - 1];
    valid_pte->valid = 0x1;
    valid_pte->prot = 0x111;
    valid_pte->pfn =    // within 
}

/**
 *
 *
 */

typedef struct KernelShared {
    void *brk;         // heap end
    void *data_end;    // heap start
    void *data_start;  // text end
} kershared_t;

kershared_t *kershared_init(void *data_start,
                            void *data_end, void *orig_brk) {
    kershared_t *kershared = malloc(1 * sizeof(kershared_t));

    kershared->brk = orig_brk;
    kershared->data_end = data_end;
    kershared->data_start = data_start;

    return kershared;
}

// Input: pointer to parent pcb
// Output: pointer to a newly malloced child pcb
// Child's pcb has new PID. Other pointers point to copies of what the parent pointers
// pointed to.
// pcb_t *pcb_copy(pcb_t *pcb_tocopy) {

//     // Malloc a new pcb: child_pcb *
//     // Malloc a new pagetable
//     // Copy what parent_pcb's pointers are pointing to, into newly assigned frames
//     pagetable_deepcopy(pcb_tocopy->ptable);
// }

/*
 *  =================
 *  === PAGETABLE ===
 *  =================
 */

const int NUM_PT_ENTRIES;

typedef struct PageTable {
    pte_t table[VMEM_REGION_SIZE / PAGESIZE];
    int size;
} pagetable_t;

// potentially only have one valid page for user's
// stack, taking hint from KernelStart()'s needs
pagetable_t *pagetable_init() {
    unsigned int size = VMEM_REGION_SIZE / PAGESIZE;

    pagetable_t *new_ptable_p = malloc(sizeof *new_ptable_p);

    return new_ptable_p
}

pagetable_t *pagetable_deepcopy();
pagetable_t *pagetable_newcopy(pagetable_t *callers_pt);  // copy pointers to another table's frames

pagetable_t *pagetable_deepcopy(pagetable_t *pagetable_tocopy) {
    // new_pagetable;
    //
    // for i in range(pcb_tocpy->pagetable->size) {
    //     frame = pcb_tocopy->pagetable[i];
    //     if frame not valid { continue; }

    //     new_frame = allocate_new_frame();
    //     for j in old_frame.bytes() {
    //         new_frame[j] = old_frame[j];
    //     }

    //     new_pagetable[i] = new_frame;
    // }
}

/*
 *  =============
 *  === FRAME ===
 *  =============
 *
 *  Copy-On-Write:
 *      - Each frame keeps track of how many page tables it appears in (ref_counter).
 *      When something like fork() is called, we use COW on the child process's
 *      memory and page table, meaning we point to the same physical frames (as
 *      opposed to copying the parent's data to a new frame).
 *      - Crucially, when we fork() we increment each frame in the page table's
 *      rec_counter. Whenever we try to write to a frame, the kernel first checks if
 *      the number of references to it is 1. If so, it is not being shared and it is
 *      safe to write.
 *      - If the references are >1, then the frame is shared and it is not safe to
 *      write. The kernel copies the current frame to a new frame, replaces the old
 *      frame in the (calling process's) page table with the new frame, and decrements
 *      the reference counter.
 *
 */

// typedef struct Frame {
//     int ref_count;
//     int id;
//     int base;
//     int limit;
// } frame_t;

// frame_t frame_new(int ref_count, int id, int base, int limit) {
//     return (frame_t { ref_count; id; base; limit; })
// }

/**
 * ===================
 * === FRAME TABLE ===
 * ===================
 *
 *  This structure is how the kernel interacts with physical memory, e.g.
 *  knows which frames are free, knows which frames to assign to page
 *  tables, etc.
 *
 *  Easy implementation: bit vector of size PMEM_SIZE?
 *  Efficient implementation (no overhead): linked list of free frames?
 *
 */

typedef struct FrameTable {
    unsigned int *frames;
    int size;
} frametable_t;

/*
 *  Initialize the frametable. This function is called during start-up,
 *  when the kernel is passed the information about the memory size by the
 *  hardware.
 */
frametable_t *frametable_init(unsigned int hardware_mem_size) {
    unsigned int num_frames = hardware_mem_size / PAGESIZE;

    unsigned int *frames = malloc(num_frames * (sizeof(unsigned int)));
    frametable_t *frametable = malloc(1 * sizeof(frametable_t));

    for (int i = 0; i < num_frames; i++) {
        frames[i] = 0;
    }

    frametable->frames = frames;
    frametable->size = num_frames;

    return frametable;
}

/**
 * Find free frame in the bit vector representing physical memory. Return index of
 * the free frame.
 */
int find_free_frame() {
}

/** ====================
 * === KERNEL STACK ===
 * ====================
 *
 *
 *  - this will be unique to each process
 *  - size is fixed in this implementation
 *  - do we need size? does keeping it give extra safety and/or efficiency?
 *
 *  --- Methods:
 *  ker_stack_t *ker_stack_new();   // allocate enough space, return pointer
 *                                  // relative to virtual memory of calling process
 */
// typedef struct KernelStack {
//     size;
//     base;
//     limit;
//     frame_ptr;
//     stack_ptr;
// } ker_stack_t;

/** ===================
 * === KERNEL HEAP ===
 * ===================

 *
 *  --- Methods:
 *
 */
// typedef struct KernelHeap {
//     brk;
//     size;
//     base;
//     limit;
// } ker_heap_t;
