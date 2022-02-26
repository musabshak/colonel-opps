#include "kernel_data_structs.h"
#include "ykernel.h"

/**
 * old_process_destination_queue == NULL means the old (currently running) process should not be put
 * into any queues. This is the case for
 *      - kWait() because we don't actually need to maintain a blocked queue associated with Wait(); we're
 *        storing the wait flag as an attribute in the pcb (which is sufficient)
 *      - kExit() because well, there is no old process left to put into any queues
 */
int schedule(queue_t *old_process_destination_queue) {

    TracePrintf(2, "Entering scheduler\n");

    int rc;

    // Get a new process from ready queue (if none ready, new_pcb becomes g_idle_pcb)
    pcb_t *new_pcb = (pcb_t *)qget(g_ready_procs_queue);
    if (new_pcb == NULL) {
        new_pcb = g_idle_pcb;
    }

    /**
     * Put the previously running process (old process) into the queue specified in the function call.
     *
     * Don't put in any queue if:
     *      - caller of schedule specified so (old_process_destination_queue == NULL)
     *      - g_running_pcb == NULL (kExit called schedule)
     *      - current process is idle process
     * If g_running_pcb is g_idle_pcb, don't put in either of the two queues; context switch directly.
     */

    if (!(old_process_destination_queue == NULL || g_running_pcb == NULL ||
          g_running_pcb->pid == g_idle_pcb->pid)) {
        rc = qput(old_process_destination_queue, (void *)g_running_pcb);
        if (rc != 0) {
            TracePrintf(1, "Failed to return previously running process to specified queue.\n");
            return ERROR;
        }
    }

    // Invoke KCSwitch()
    rc = KernelContextSwitch(KCSwitch, g_running_pcb, new_pcb);
    if (rc != 0) {
        TracePrintf(1, "Failed to switch kernel context.\n");
        return ERROR;
    }

    TracePrintf(2, "Exiting scheduler\n");
    return 0;
}