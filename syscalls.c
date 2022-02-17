#include "kernel_data_structs.h"
#include "ykernel.h"

extern pcb_t *g_running_pcb;

int kGetPid() {
    // Confirm that there is a process that is currently running
    if (g_running_pcb == NULL) {
        return ERROR;
    }

    return g_running_pcb->pid;
}

int kBrk(void *addr) {
    //  --- Calculate the extra memory the user is asking for
    pcb_t *calling_proc = running_process_p;
    int amount_mem_requested = addr - calling_proc->user_heap->limit;

    //  --- Get enough frames
    int num_frames_needed = amount_mem_requested / frame_size + 1;

    int new_frames[num_frames_needed];
    int frames_acquired = 0;
    for (int i = 0; j < frametable->size; i++) {
        if (frametable->frames[i].ref_count != 0) {
            continue;
        }

        new_frames[frames_acquired] = frametable->frames[i].id;
    }

    //  --- Update caller's pagetable
    pagetable_t *callers_pagetable = calling_proc->pagetable;
    // calculate which pages correspond to the requested heap area, update those
    // page table entries to point to the frames in new_frames[], change bit to
    // valid

    // Change user heap limit to addr
    calling_proc->user_heap->limit = addr;
}

/**  =============
 *  === DELAY ===
 *  =============
 *
 *  From manual (p. 33):
 *      The calling process is blocked until at least clock ticks clock interrupts
 *      have occurred after the call. Upon completion of the delay, the value 0 is
 *      returned.
 *      If clock ticks is 0, return is immediate. If clock ticks is less than 0,
 *      time travel is not carried out, and ERROR is returned instead.
 */
int kDelay(int clock_ticks) {
    if (clock_ticks < 0) {
        return ERROR;
    }
    if (clock_ticks == 0) {
        return 0;
    }
}
