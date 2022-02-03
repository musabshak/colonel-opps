#ifndef __KERNEL_DATA_STRUCTS
#define __KERNEL_DATA_STRUCTS

//  ===== GLOBAL DATA =====
// queue_t *READY_PROCESSES;
// queue_t *BLOCKED_PROCESSES;
// queue_t *ZOMBIE_PROCESSES;

//  ===== PROCESS CONTROL BLOCK =====
typedef struct ProcessControlBlock pcb_t;
typedef struct KernelShared {
    void *brk;
} kershared_t;

kershared_t *kershared_init(void *data_start,
                            void *data_end, void *orig_brk);

pcb_t *pcb_copy(pcb_t *pcb_tocopy);

//  ===== PAGE TABLE =====
const int NUM_PT_ENTRIES;

typedef struct PageTable pagetable_t;

pagetable_t *pagetable_new();
pagetable_t *pagetable_deepcopy();
pagetable_t *pagetable_newcopy(pagetable_t *callers_pt);
pagetable_t *pagetable_deepcopy(pagetable_t *pagetable_tocopy);

//  ===== FRAME, FRAME TABLE =====
typedef struct Frame frame_t;
typedef struct FrameTable frametable_t;

frame_t frame_new(int ref_count, int id, int base, int limit);
frametable_t *frametable_init(unsigned int hardware_mem_size);
int find_free_frame();

//  ===== KERNEL STUFF =====
typedef struct KernelStack ker_stack_t;
typedef struct KernelHeap ker_heap_t;

#endif  // __KERNEL_DATA_STRUCTS