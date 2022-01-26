/*
 * Major kernel data structures:
 *      - process
 *          - user stack, heap
 *          - kernel stack, heap, data, text
 *      - array of active processes
 *      - queue of waiting processes
 *      - array of exit statuses, to be checked for waiting process
 *          - exit status {int exit_status, process *parent}
 *      - pipe
 *      - lock
 *      - cvar (condition variable)
 * 
 *      - interrupt vector, vector table
 * 
 * ===============
 * === PROCESS === 
 * ===============
 *  typdef struct Process {
 *      // --- userland 
 *      user_stack;
 *      user_heap;
 *      user_data;
 *      user_text;
 *      // --- kernelland
 *      kernel stack;
 *      kernel_heap;
 *      kernel_data;
 *      kernel_text;
 *      // --- metadata
 *      process_t *parent;
 *      int pid;
 *      bool initialized; // to see if we own proc mem or its just copied from fork()
 *  } process_t;
 * 
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