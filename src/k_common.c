/**
 * Authors: Varun Malladi and Musab Shakeel
 * Date: 2/5/2022
 *
 * This file contains different shared kernel code.
 *
 */

#include "k_common.h"

#include <stdbool.h>

#include "printing.h"
#include "queue.h"
#include "ykernel.h"

void kExit(int status);

/**
 * Used by KCCopy.
 */
int copy_page_contents(unsigned int source_page, unsigned int target_page) {

    memcpy((void *)(target_page << PAGESHIFT), (void *)(source_page << PAGESHIFT), PAGESIZE);

    return SUCCESS;
}

void print_pcb(void *elementp) {
    pcb_t *my_pcb = (pcb_t *)elementp;
    TracePrintf(2, "pid: %d \n", my_pcb->pid);
}

KernelContext *KCCopy(KernelContext *kc_in, void *new_pcb_p, void *not_used) {
    TracePrintf(2, "Entering KCCopy\n");

    pcb_t *new_pcb = ((pcb_t *)new_pcb_p);

    // Copy the current kernel context into the new process
    memcpy(&(new_pcb->kctxt), kc_in, sizeof(KernelContext));

    unsigned int page_below_kstack = g_len_pagetable - g_num_kernel_stack_pages - 1;
    unsigned int page_below_kstack_addr = page_below_kstack << PAGESHIFT;

    // Map page below kernel stack to allocated free frame for new kernel stack. This is a hack for
    // copying pages into unmapped frames (unmapped frames for new kernel stack).
    g_reg0_ptable[page_below_kstack].valid = 1;
    g_reg0_ptable[page_below_kstack].prot = PROT_READ | PROT_WRITE;

    // Copy contents of current kernel stack (g_r0_ptable) into frames allocated for the new process's
    // kernel stack
    for (int i = 0; i < g_num_kernel_stack_pages; i++) {

        g_reg0_ptable[page_below_kstack].pfn = new_pcb->kstack_frame_idxs[i];

        // !!!!!!!! Flush temporarily used page
        WriteRegister(REG_TLB_FLUSH, page_below_kstack_addr);

        // Copy page contents
        unsigned int source_page = g_len_pagetable - 1 - i;
        unsigned int target_page = page_below_kstack;

        char *c_source = (char *)(source_page << PAGESHIFT);
        char *c_target = (char *)(target_page << PAGESHIFT);

        int rc = copy_page_contents(source_page, target_page);

        TracePrintf(2, "kstack_frame_idxs[%d] = %d\n", i, new_pcb->kstack_frame_idxs[i]);
        TracePrintf(2, "source page: %d target page: %d\n", source_page, target_page);

        if (rc != 0) {
            TracePrintf(1, "Error occurred in copy_page_contents in KCCopy()\n");
            return NULL;
        }

        for (int j = 0; j < PAGESIZE; j++) {
            if (c_target[j] != c_source[j]) {
                TracePrintf(1, "ERRRROR IN COPYING!\n");
            }
        }
    }

    // Make redzone page invalid again
    g_reg0_ptable[page_below_kstack].valid = 0;
    g_reg0_ptable[page_below_kstack].prot = PROT_NONE;

    WriteRegister(REG_TLB_FLUSH, page_below_kstack_addr);

    TracePrintf(2, "Exiting KCCopy\n");
    return kc_in;
}

KernelContext *KCSwitch(KernelContext *kc_in, void *curr_pcb_p, void *new_pcb_p) {

    TracePrintf(2, "Entering KCSwitch\n");
    pcb_t *curr_pcb = ((pcb_t *)curr_pcb_p);
    pcb_t *new_pcb = ((pcb_t *)new_pcb_p);

    /**
     * Save current kernel context in current process's pcb (saving current state of
     * current process in it's pcb so we can return to it later).
     *
     * Could also probably use:
     *      curr_pcb->kctxt = *kc_in;
     */
    if (curr_pcb_p != NULL) {
        memcpy(&(curr_pcb->kctxt), kc_in, sizeof(KernelContext));
    }

    // Update mapping of kernel stack in R0 ptable to reflect new kernel's stack frames
    for (int i = 0; i < g_num_kernel_stack_pages; i++) {
        g_reg0_ptable[g_len_pagetable - 1 - i].pfn = new_pcb->kstack_frame_idxs[i];
    }

    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_KSTACK);

    // Tell MMU to look at new process' R1 page table
    WriteRegister(REG_PTBR1, (unsigned int)(new_pcb->r1_ptable));
    WriteRegister(REG_TLB_FLUSH, TLB_FLUSH_1);

    g_running_pcb = new_pcb;

    TracePrintf(2, "g_running_pcb's pid: %d\n", g_running_pcb->pid);
    TracePrintf(2, "Leaving KCSwitch\n");

    // At the end of switching, return pointer to kernel context (previously) saved in new_pcb
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

/**
 * Find `num_frames` number of free frames, allocate an array of integers to store them
 * in. That array will be terminated with `-1`. Returns `NULL` on failure.
 */
int *find_n_free_frames(unsigned int *frametable, int num_frames) {
    // TODO: safety checks

    // Leave extra spot for `NULL` ending
    int *frame_arr = malloc(num_frames * sizeof(int) + 1);
    if (frame_arr == NULL) {
        TP_ERROR("`malloc()` failed.\n");
        return NULL;
    }

    int frames_found = 0;
    bool ran_out_of_mem = false;

    for (int i = 0; i < num_frames; i++) {
        int frame_idx = find_free_frame(frametable);

        if (frame_idx < 0) {
            TracePrintf(1, "Ran out of physical memory.\n");
            ran_out_of_mem = true;
            frame_arr[frames_found] = -1;
            break;
        }

        frame_arr[frames_found] = frame_idx;
        frames_found++;
        frametable[frame_idx] = 1;
    }

    if (ran_out_of_mem) {
        // failure
        retire_frames(frametable, frame_arr);
        free(frame_arr);
        return NULL;
    } else {
        // insert terminating indicator
        frame_arr[num_frames] = -1;

        return frame_arr;
    }
}

/**
 * Takes an array of frame table indices, terminated with -1, and marks those frames
 * as available.
 */
void retire_frames(int *frametable, int *frame_idxs) {
    for (int i = 0;; i++) {
        if (frame_idxs[i] == -1) {
            break;
        }

        frametable[frame_idxs[i]] = 0;
    }
}

void print_r0_page_table(pte_t *ptable, int size, int *frametable) {

    TracePrintf(2, "Printing R0 page table\n\n");

    TracePrintf(2, "%3s  %2s    %s|%s|%s\t  F used?\n", "Idx", "P#", "Valid", "Prot", "PFN#");
    for (int i = size - 1; i >= 0; i--) {
        TracePrintf(1, "%3d  %2d -->%5d|%4d|%4d\t  %d\n", i, i, ptable[i].valid, ptable[i].prot,
                    ptable[i].pfn, frametable[i]);
    }
    TracePrintf(2, "\n");
}

void print_r1_page_table(pte_t *ptable, int size) {

    TracePrintf(2, "Printing R1 page table\n\n");

    TracePrintf(2, "%3s  %2s    %s|%s|%s\n", "Idx", "P#", "Valid", "Prot", "PFN#");
    for (int i = size - 1; i >= 0; i--) {
        TracePrintf(2, "%3d  %2d -->%5d|%4d|%4d\n", i, i + size, ptable[i].valid, ptable[i].prot,
                    ptable[i].pfn);
    }
    TracePrintf(2, "\n");
}

/**
 * Returns a new pipe id. Returns ERROR if the maximum number of pipes per kernel
 * session has been exhausted.
 *
 * Currently implemented naively (via a global counter). Overflow of pipe_ids
 * protected by g_max_pipes.
 *
 * Pipe ids are necessarily a multiple of PIPE_ID_K (3) because pipe ids are incremented
 * by 3 each time. This is so we're able to distinguish between pipes, locks, and cvars.
 *
 * So the number of max allowed pipes is actually g_max_pipes/PIPE_ID_K.
 *
 * Similar notes apply for assign_lock_id() and assign_cvar_id().
 */
int assign_pipe_id() {
    if (g_pipe_id == g_max_pipes) {
        TracePrintf(1,
                    "The maximum number of allowed pipes has already been created. Please delete some pipes "
                    "in order to create more!\n");
        return ERROR;
    }

    g_pipe_id += PIPE_ID_K;
    return g_pipe_id - PIPE_ID_K;
}

/**
 * Retires a given pipe id.
 *
 * Currently implemented naively.
 */
int retire_pipe_id(int pipe_id) { return 0; }

/**
 * Returns a new lock id. Returns ERROR if the maximum number of locks per kernel
 * session has been exhausted.
 *
 * Currently implemented naively (via a global counter). Overflow of pipe_ids
 * protected by g_max_locks.
 */
int assign_lock_id() {
    if (g_lock_id == g_max_locks) {
        TracePrintf(1,
                    "The maximum number of allowed locks has already been created. Please delete some locks "
                    "in order to create more!\n");
        return ERROR;
    }

    g_lock_id += LOCK_ID_K;
    return g_lock_id - LOCK_ID_K;
}

/**
 * Retires a given lock id.
 *
 * Currently implemented naively.
 */
int retire_lock_id(int lock_id) { return 0; }

/**
 * Returns a new cvar id. Returns ERROR if the maximum number of cvars per kernel
 * session has been exhausted.
 *
 * Currently implemented naively (via a global counter). Overflow of pipe_ids
 * protected by g_max_cvars.
 */
int assign_cvar_id() {
    if (g_cvar_id == g_max_cvars) {
        TracePrintf(1,
                    "The maximum number of allowed cvars has already been created. Please delete some cvars "
                    "in order to create more!\n");
        return ERROR;
    }

    g_cvar_id += CVAR_ID_K;
    return g_cvar_id - CVAR_ID_K;
}

/**
 * Retires a given cvar id.
 *
 * Currently implemented naively.
 */
int retire_cvar_id(int cvar_id) { return 0; }

/**
 * Used by happly()
 */

void print_pipe(void *elementp) {
    pipe_t *pipe = elementp;
    TracePrintf(2, "Pipe id: %d\n", pipe->pipe_id);
}

/**
 * Used by hsearch()
 */

bool search_pipe(void *elementp, const void *searchkeyp) {
    pipe_t *pipe = (pipe_t *)elementp;
    const char *search_key_str = searchkeyp;

    char pipe_key[MAX_KEYLEN];
    sprintf(pipe_key, "pipe%d\0", pipe->pipe_id);

    TracePrintf(2, "Comparing strings: %s =? %s\n", pipe_key, search_key_str);
    if (strcmp(pipe_key, search_key_str) == 0) {
        TracePrintf(2, "Strings are the same!\n");
        return true;
    } else {
        return false;
    }
}
