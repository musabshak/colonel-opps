#include "kernel_data_structs.h"
#include "ykernel.h"

extern queue_t *g_delay_blocked_procs_queue;
extern queue_t *g_ready_procs_queue;
extern pcb_t *g_idle_pcb;
extern pcb_t *g_running_pcb;

int pcb_delay_finished(void *elementp, const void *key) {

    pcb_t *pcb = (pcb_t *)elementp;

    // increment clock_ticks for the specified pcb
    pcb->elapsed_clock_ticks += 1;

    TracePrintf(1, "pid: %d, elapsed: %d, delay_ticks: %d\n", pcb->pid, pcb->elapsed_clock_ticks,
                pcb->delay_clock_ticks);

    if (pcb->elapsed_clock_ticks < pcb->delay_clock_ticks) {
        return 0;  // false
    }

    /**
     * This process has paid its dues; time to move it to ready queue and to indicate to q_remove_all
     * to remove it from g_delay_blocked_procs_queue.
     */

    TracePrintf(1, "DUES HAVE BEEN PAID\n");

    // move to ready queue
    qput(g_ready_procs_queue, (void *)pcb);

    // tell qremove_all to remove this pcb from g_delay_blocked_procs_queue
    return 1;
}

/**
 *  kDelay - 0
 *  clocktrap - 1
 */
int schedule(enum CallerFunc caller_id) {

    TracePrintf(1, "Entering scheduler\n");

    int rc;
    // int is_caller_kDelay = !is_caller_clocktrap;
    int is_idle_current_process = g_running_pcb->pid == g_idle_pcb->pid;

    /**
     * If trap_clock called schedule() (meaning that a clock trap has happened), iterate through the
     * blocked processes associated with the kDelay syscall and increment each process'
     * pcb->elapsed_clock_ticks. If pcb->elapsed_clock_ticks >= pcb->delay_clock_ticks, remove process
     * from blocked queue and add to the ready queue.
     *
     * This is done using the qremove_all method. qremove_all takes a search function and a key. The search
     * function is applied to every queue node. If the search function returns true, then that node is removed
     * from the queue.
     *
     * The "search" function supplied to the following qremove_all call is not strictly/purely a "search"
     * function. The function pcb_delay_finished for each PCB first increments the elapsed_clock_ticks
     * attribute. Then, the function checks if the elapsed_clock_ticks are >= the delay_clock_ticks. If they
     * are, then the function adds the PCB to the g_ready_procs_queue, while also returning 1, indicating to
     * the qremove_all caller to delete the node from the g_delay_blocked_procs_queue.
     */

    if (caller_id == F_clockTrap) {
        TracePrintf(1, "calling qremove_all\n");
        qremove_all(g_delay_blocked_procs_queue, pcb_delay_finished, NULL);
    }

    TracePrintf(1, "ready queue: \n");
    qapply(g_ready_procs_queue, print_pcb);
    TracePrintf(1, "\n");

    TracePrintf(1, "blocked queue: \n");
    qapply(g_delay_blocked_procs_queue, print_pcb);
    TracePrintf(1, "\n");

    // Get a new process from ready queue (if none ready, new_pcb becomes g_idle_pcb)
    pcb_t *new_pcb = (pcb_t *)qget(g_ready_procs_queue);
    if (new_pcb == NULL) {
        new_pcb = g_idle_pcb;
    }

    /**
     * Decide where to put g_running_pcb: into g_ready_procs_queue or g_delay_blocked_queue.
     *
     * This decision is based on who called the scheduler -- the kDelay syscall or the TrapClock
     * handler.
     *
     * If g_running_pcb is g_idle_pcb, don't put in either of the two queues; context switch directly.
     */

    // Caller is kDelay.
    // Put currently running process in the blocked queue.
    if (caller_id == F_kDelay && !is_idle_current_process) {
        // Put current process in blocked processes queue
        qput(g_delay_blocked_procs_queue, (void *)g_running_pcb);
    }

    // Caller is TrapClock handler.
    // Return currently running process into ready queue.
    if (caller_id == F_clockTrap && !is_idle_current_process) {
        rc = qput(g_ready_procs_queue, (void *)g_running_pcb);
        if (rc != 0) {
            TracePrintf(2, "Failed to return running process to ready queue.\n");
            return ERROR;
        }
    }

    // Caller is kWait.
    // Do not put process in blocked queue
    if (caller_id == F_kWait && !is_idle_current_process) {
        // rc = KernelContextSwitch(KCSwitch, g_running_pcb, new_pcb);
    }

    // Caller is kExit
    if (caller_id == F_kExit) {
        rc = KernelContextSwitch(KCSwitch, NULL, new_pcb);
        return 0;
    }

    // Invoke KCSwitch()
    rc = KernelContextSwitch(KCSwitch, g_running_pcb, new_pcb);
    if (rc != 0) {
        TracePrintf(1, "Failed to switch kernel context.\n");
        return ERROR;
    }

    TracePrintf(1, "Exiting scheduler\n");
    return 0;
}