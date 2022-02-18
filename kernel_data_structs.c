#include "kernel_data_structs.h"

#include "queue.h"
#include "ykernel.h"

extern int *g_frametable;

extern pcb_t *g_running_pcb;
extern unsigned int g_len_pagetable;
extern unsigned int g_len_frametable;
extern unsigned int g_num_kernel_stack_pages;
extern pte_t *g_reg0_ptable;

KernelContext *KCSwitch(KernelContext *kc_in, void *curr_pcb_p, void *new_pcb_p) {
    TracePrintf(1, "Entering KCSwitch\n");
    pcb_t *curr_pcb = ((pcb_t *)curr_pcb_p);
    pcb_t *new_pcb = ((pcb_t *)new_pcb_p);

    // Save current kernel context in current process's pcb (saving current state of
    // current process in it's pcb so we can return to it later).
    // curr_pcb->kctxt = *kc_in;
    memcpy(&(curr_pcb->kctxt), kc_in, sizeof(KernelContext));

    // TEMPORARY
    // new_pcb->kstack_frame_idxs[0] = 127;
    // new_pcb->kstack_frame_idxs[1] = 126;

    // Update mapping of kernel stack in R0 ptable to reflect new kernel's stack frames
    for (int i = 0; i < g_num_kernel_stack_pages; i++) {
        g_reg0_ptable[g_len_pagetable - 1 - i].pfn = new_pcb->kstack_frame_idxs[i];
    }

    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_KSTACK);

    // Tell MMU to look at new process' R1 page table
    WriteRegister(REG_PTBR1, (unsigned int)(new_pcb->r1_ptable));
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_1);

    TracePrintf(1, "Leaving KCSwitch\n");

    g_running_pcb = new_pcb;
    TracePrintf(1, "g_running_pcb's pid: %d\n", g_running_pcb->pid);

    // WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_ALL);

    // At the end of switching, return pointer to kernel context (previously) saved in new_pcb
    // return &(new_pcb->kctxt);
    return &(new_pcb->kctxt);
}

/**
 * Returns index of first free frame in given frame table. Returns -1 if no free frames
 * available.
 *
 * Note that this function does *not* mark the frame as "used" in the frametable.
 */
int find_free_frame(unsigned int *frametable) {
    for (int idx = 0; idx < g_len_frametable; idx++) {
        if (frametable[idx] == 0) {
            return idx;
        }
    }
    return -1;
}

void print_r0_page_table(pte_t *ptable, int size, int *frametable) {

    TracePrintf(1, "Printing R0 page table\n\n");

    TracePrintf(1, "%3s  %2s    %s|%s|%s\t  F used?\n", "Idx", "P#", "Valid", "Prot", "PFN#");
    for (int i = size - 1; i >= 0; i--) {
        TracePrintf(1, "%3d  %2x -->%5x|%4d|%4x\t  %d\n", i, i, ptable[i].valid, ptable[i].prot,
                    ptable[i].pfn, frametable[i]);
    }
    TracePrintf(1, "\n");
}

void print_r1_page_table(pte_t *ptable, int size) {

    TracePrintf(1, "Printing R1 page table\n\n");

    TracePrintf(1, "%3s  %2s    %s|%s|%s\n", "Idx", "P#", "Valid", "Prot", "PFN#");
    for (int i = size - 1; i >= 0; i--) {
        TracePrintf(1, "%3d  %2x -->%5x|%4d|%4x\n", i, i + size, ptable[i].valid, ptable[i].prot,
                    ptable[i].pfn);
    }
    TracePrintf(1, "\n");
}

int raise_brk_user(void *new_brk, void *current_brk, pte_t *ptable) {
    TracePrintf(1, "Calling h_raise_brk w/ arg: %x (page %d)\n", new_brk, (unsigned int)new_brk >> PAGESHIFT);

    unsigned int current_page = ((unsigned int)current_brk >> PAGESHIFT) - MAX_PT_LEN;
    unsigned int new_page = ((unsigned int)new_brk >> PAGESHIFT) - MAX_PT_LEN;

    unsigned int num_pages_to_raise = new_page - current_page;
    unsigned int new_brk_int = (unsigned int)new_brk;

    // Check if `new_brk` is not 0th byte of page. Then, since we are rounding the
    // brk up to the next page we want to allocate the page the new_brk is
    // on.
    if (new_brk_int != (new_brk_int & PAGEMASK)) {
        num_pages_to_raise += 1;
    }

    // Allocate new pages in R0 ptable (find free frames for each page etc.)
    for (int i = 0; i < num_pages_to_raise; i++) {
        int free_frame_idx = find_free_frame(g_frametable);
        g_frametable[free_frame_idx] = 1;  // mark frame as used

        // no free frames were found
        if (free_frame_idx < 0) {
            return ERROR;
        }

        // (current_page + i + 1) => assumes current_page has already been allocated
        unsigned int next_page = current_page + i;
        ptable[next_page].valid = 1;
        ptable[next_page].prot = PROT_READ | PROT_WRITE;
        ptable[next_page].pfn = free_frame_idx;
    }

    return 0;
}

int lower_brk_user(void *new_brk, void *current_brk, pte_t *ptable) {
    TracePrintf(1, "Calling h_lower_brk\n");

    unsigned int current_page = ((unsigned int)current_brk >> PAGESHIFT) - MAX_PT_LEN;
    unsigned int new_page = ((unsigned int)new_brk >> PAGESHIFT) - MAX_PT_LEN;

    unsigned int num_pages_to_lower = current_page - new_page;
    unsigned int new_brk_int = (unsigned int)new_brk;

    if (new_brk_int != (new_brk_int & PAGEMASK)) {
        num_pages_to_lower -= 1;
    }

    // "Frees" pages from R0 pagetable (marks those frames as unused, etc.)
    for (int i = 0; i < num_pages_to_lower; i++) {
        unsigned int prev_page = current_page - i - 1;
        unsigned int idx_to_free = g_reg0_ptable[prev_page].pfn;
        g_frametable[idx_to_free] = 0;  // mark frame as un-used

        ptable[prev_page].valid = 0;
        ptable[prev_page].prot = PROT_NONE;
        ptable[prev_page].pfn = 0;  // should never be touched
    }

    return 0;
}

/**
 * Helper function called by SetKernelBrk(void *addr) in the case that addr > g_kernel_brk,
 * also analagously by `Brk()`.
 *
 * Modifies (if need be)
 *      - `ptable` (allocates new pages)
 *      - `*curr_brk`
 */
// int h_raise_brk(void *new_brk, void **curr_brk, pte_t *ptable) {
//     TracePrintf(1, "Calling h_raise_brk\n");

//     unsigned int current_page = (unsigned int)curr_brk >> PAGESHIFT;
//     unsigned int new_page = (unsigned int)new_brk >> PAGESHIFT;

//     unsigned int num_pages_to_raise = new_page - current_page;
//     unsigned int new_brk_int = (unsigned int)new_brk;

//     // Check if `new_brk` is not 0th byte of page. Then, since we are rounding the
//     // brk up to the next page we want to allocate the page the new_brk is
//     // on.
//     if (new_brk_int != (new_brk_int & PAGEMASK)) {
//         num_pages_to_raise += 1;
//     }

//     // Allocate new pages in ptable (find free frames for each page etc.)
//     for (int i = 0; i < num_pages_to_raise; i++) {
//         int free_frame_idx = find_free_frame(g_frametable);
//         g_frametable[free_frame_idx] = 1;  // mark frame as used

//         // no free frames were found
//         if (free_frame_idx < 0) {
//             return ERROR;
//         }

//         // !!! (current_page + i + 1) => assumes current_page has already been allocated
//         unsigned int next_page = current_page + i;
//         ptable[next_page].valid = 1;
//         ptable[next_page].prot = PROT_READ | PROT_WRITE;
//         ptable[next_page].pfn = free_frame_idx;
//     }

//     *curr_brk = (void *)(UP_TO_PAGE(new_brk_int));

//     return 0;
// }

// /**
//  * Helper function called by SetKernelBrk(void *addr) in the case that addr < g_kernel_brk.
//  *
//  * Modifies (if need be)
//  *      - `ptable` (allocates new pages)
//  *      - `*curr_brk`
//  */
// int h_lower_brk(void *new_brk, void **curr_brk, pte_t *ptable) {
//     // TracePrintf(1, "Calling h_lower_brk\n");

//     unsigned int current_page = (unsigned int)curr_brk >> PAGESHIFT;
//     unsigned int new_page = (unsigned int)new_brk >> PAGESHIFT;

//     unsigned int num_pages_to_lower = current_page - new_page;
//     unsigned int new_brk_int = (unsigned int)new_brk;

//     if (new_brk_int != (new_brk_int & PAGEMASK)) {
//         num_pages_to_lower -= 1;
//     }

//     // !!! "Frees" pages from pagetable (marks those frames as unused, etc.)
//     for (int i = 0; i < num_pages_to_lower; i++) {
//         unsigned int prev_page = current_page - i - 1;
//         unsigned int idx_to_free = g_reg0_ptable[prev_page].pfn;
//         g_frametable[idx_to_free] = 0;  // mark frame as un-used

//         ptable[prev_page].valid = 0;
//         ptable[prev_page].prot = PROT_NONE;
//         ptable[prev_page].pfn = 0;  // should never be touched
//     }

//     *curr_brk = (void *)(UP_TO_PAGE(new_brk_int));

//     return 0;
// }
