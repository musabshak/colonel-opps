#include "kernel_data_structs.h"

#include "queue.h"
#include "ykernel.h"

// typedef struct ProcessControlBlock {
//     unsigned int pid;
//     // --- userland
//     UserContext uctxt;
//     void *user_brk;
//     void *user_data;
//     void *user_text;
//     // --- kernelland
//     KernelContext kctxt;
//     unsigned int kstack_frame_idxs[KERNEL_STACK_MAXSIZE / PAGESIZE];
//     // --- metadata
//     pcb_t *parent;
//     queue_t *children_procs;
//     pte_t *r1_ptable;
// } pcb_t;

pcb_t *something;

extern g_len_pagetable;
extern g_num_kernel_stack_pages;
extern g_reg0_ptable;

KernelContext *KCSwitch(KernelContext *kc_in, void *curr_pcb_p, void *new_pcb_p) {
    pcb_t *new_pcb = ((pcb_t *)new_pcb_p);
    pcb_t *curr_pcb = ((pcb_t *)curr_pcb);

    // Save current kernel context in current process's pcb (saving current state of
    // current process in it's pcb so we can return to it later).
    curr_pcb->kctxt = *kc_in;

    // Update mapping of kernel stack in R0 ptable to reflect new kernel's stack frames
    for (int i = 0; i < g_num_kernel_stack_pages; i++) {
        g_reg0_ptable[g_len_pagetable - 1 - i].pfn = new_pcb->kstack_frame_idxs[i];
    }

    // At the end of switching, return kernel context (previously) saved in new_pcb'
    return &(new_pcb->kctxt);
}
