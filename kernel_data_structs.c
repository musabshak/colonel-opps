/*
 * Major kernel data structures:
 *      - process
 *          - user stack, heap
 *          - kernel stack, heap, data, text
 *      - page (logical memory), frame (physical memory), frame and page tables
 *          - page table entry (pte) sketched in include/hardware.h
 *      - user context
 *          - include/hardware.h
 *      - kernel context
 *          - include/hardware.h
 *      - syscall table
 *      - array of active processes
 *      - queue of waiting processes
 *      - array of exit statuses, to be checked for waiting process
 *          - exit status {int exit_status, process *parent}
 *      - pipe
 *      - lock
 *      - cvar (condition variable)
 *      - file descriptor
 *          - file descriptor table (per process) ->
 *          - file table (system wide, indexes opened files with mode) -> 
 *          - inode table (system wide)
 *      - file?
 * 
 *      - interrupt vector, vector table
 */

/* 
 * ===============
 * === PROCESS === 
 * ===============
 * 
 */

typedef struct Process {
    // --- userland 
    user_stack;
    user_heap;
    user_data;
    user_text;
    // --- kernelland
    kernel stack;
    kernel_heap;
    kernel_data;
    kernel_text;
    // --- metadata
    process_t *parent;
    int pid;
} process_t;


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

typedef struct Frame {
    int ref_count;
    int id;
    int base;
    int limit;
} frame_t;

frame_t frame_new(int ref_count, int id, int base, int limit) {
    return (frame_t { ref_count; id; base; limit; })
}

/**
 * ===================
 * === FRAME TABLE ===
 * ===================
 * 
 *  This structure is how the kernel interacts with physical memory, e.g. 
 *  knows which frames are free, knows which frames to assign to page 
 *  tables, etc. 
 * 
 */

typedef struct FrameTable {
    frame_t *frames;
    int size;
} frametable_t;

/*
 *  Initialize the frametable. This function is called during start-up, 
 *  when the kernel is passed the information about the memory size by the 
 *  hardware.
 */
frametable_t frametable_init(int hardware_mem_size, int frame_size, int pmem_base) {
    int num_frames = hardware_mem_size / frame_size;

    frame_t *frames = malloc(num_frames*(sizeof(frame_t)));
    frametable_t frametable = malloc(1*sizeof(frametable_t));

    for (int i=0; i<num_frames; i++) {
        frames[i] = frame_new(0, i, pmem_base + i*frame_size, (i+1)*frame_size);
    }

    return frametable_t { frames; num_frames };
}

/* 
 * ========================
 * === ACTIVE PROCESSES ===
 * ========================
 *  typedef struct ActiveProcesses {
 *      process_t *procs;
 *      int size;
 *  } active_procs_t;
 * 
 * =========================
 * === WAITING PROCESSES ===
 * =========================
 *  typedef struct WaitingProcesses {
 *      
 *  } waiting_procs_t;
 * 
 * ====================
 * === KERNEL STACK ===
 * ====================
 *  typedef struct KernelStack {
 *      size;
 *      base;
 *      limit;
 *      frame_ptr;
 *      stack_ptr;
 *  } ker_stack_t;
 * 
 *  - this will be unique to each process
 *  - size is fixed in this implementation
 *  - do we need size? does keeping it give extra safety and/or efficiency?
 * 
 *  --- Methods:
 *  ker_stack_t *ker_stack_new();   // allocate enough space, return pointer
 *                                  // relative to virtual memory of calling process
 *
 * ===================
 * === KERNEL HEAP ===
 * ===================
 *  typedef struct KernelHeap {
 *      brk;
 *      size;
 *      base;
 *      limit;
 *  } ker_heap_t;
 * 
 *  --- Methods:
 *  
 */