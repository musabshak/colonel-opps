/*
 * Major kernel data structures:
 *      - process
 *          - user stack, heap
 *          - kernel stack, heap, data, text
 *      - array of active processes
 *      - queue of waiting processes
 *      - pipe
 *      - lock
 *      - cvar (condition variable)
 * 
 * ===============
 * === PROCESS === 
 * ===============
 *  typdef struct Process {
 *      process_t *parent;
 *  } process_t;
 * 
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