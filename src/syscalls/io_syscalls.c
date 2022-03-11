/**
 * io_syscalls.c
 *
 * Authors: Varun Malladi
 * Date: Late February 2022
 *
 * Contains the TtyRead and TtyWrite syscalls, as well as helper functions, structures,
 * etc.
 */

#include <stdbool.h>
#include <ykernel.h>

#include "address_validation.h"
#include "k_common.h"
#include "trap_handlers.h"

extern term_buf_t *g_term_bufs[NUM_TERMINALS];

/**
 * This is how we handle "locked" access to terminals (only one process can use a terminal
 * at a time). This method only works because we are the kernel.
 *
 * Each entry in the array represents the terminal with id corresponding to its index.
 * `0` indicates that no process is using the terminal. A nonzero value should represent
 * that the process with that PID is using the terminal, e.g. if `term_status[0] == 2` then
 * this means PID 2 is using terminal 0.
 */
int term_read_status[NUM_TERMINALS] = {0, 0, 0, 0};
int term_write_status[NUM_TERMINALS] = {0, 0, 0, 0};

// This was created to handle the case where a process tried to write to a different terminal
// while `TtyTransmit` was in progress (initiated by another process, for another terminal)
bool tty_transmit_in_progress = false;

enum TermAccessKind { Read, Write };

/**
 * Return the value at index `idx` of the read/write status arrays above.
 */
int term_queue_get(int idx, enum TermAccessKind queue_kind) {
    if (queue_kind == Read) {
        return term_read_status[idx];
    } else if (queue_kind == Write) {
        return term_write_status[idx];
    }
}

/**
 * Set the value at index `idx` of the read/write status arrays above.
 */
void term_queue_set(int idx, enum TermAccessKind queue_kind, int val) {
    if (queue_kind == Read) {
        term_read_status[idx] = val;
    } else if (queue_kind == Write) {
        term_write_status[idx] = val;
    }
}

/**
 * Check if terminal is being used by another process. If so, sleep.
 */
void gain_access_to_term(int tty_id, enum TermAccessKind access_kind) {
    // Sleep if the terminal is marked with a different PID than the one of this process,
    // and if it is not not being used
    bool can_gain_access;
    if (access_kind == Read) {
        can_gain_access = term_queue_get(tty_id, access_kind) == g_running_pcb->pid ||
                          term_queue_get(tty_id, access_kind) == 0;
    } else if (access_kind == Write) {
        can_gain_access = (term_queue_get(tty_id, access_kind) == g_running_pcb->pid ||
                           term_queue_get(tty_id, access_kind) == 0) &&
                          tty_transmit_in_progress == false;
    }

    // We use a while loop in case of when we wake up, another process took control of the
    // terminal before this process could
    while (can_gain_access == false) {
        g_running_pcb->blocked_term = tty_id;

        if (access_kind == Read) {
            TracePrintf(2, "PID %d tried to read from terminal %d, but it was in use. Sleeping...\n",
                        g_running_pcb->pid, tty_id);
            schedule(g_term_blocked_read_queue);
        } else if (access_kind == Write) {
            TracePrintf(2, "PID %d tried to write to terminal %d, but it was in use. Sleeping...\n",
                        g_running_pcb->pid, tty_id);
            schedule(g_term_blocked_write_queue);
        }

        // Woke up after sleep-- check if we can gain access now
        if (access_kind == Read) {
            can_gain_access = term_queue_get(tty_id, access_kind) == g_running_pcb->pid ||
                              term_queue_get(tty_id, access_kind) == 0;
        } else if (access_kind == Write) {
            can_gain_access = (term_queue_get(tty_id, access_kind) == g_running_pcb->pid ||
                               term_queue_get(tty_id, access_kind) == 0) &&
                              tty_transmit_in_progress == false;
        }
    }

    // Woke up with access to terminal-- free to continue. Update status arrays and bits
    // as necessary
    if (access_kind == Read) {
        TracePrintf(2, "PID %d has read access to terminal %d.\n", g_running_pcb->pid, tty_id);
        term_read_status[tty_id] = g_running_pcb->pid;
    } else if (access_kind == Write) {
        TracePrintf(2, "PID %d has write access to terminal %d.\n", g_running_pcb->pid, tty_id);
        term_write_status[tty_id] = g_running_pcb->pid;
        tty_transmit_in_progress = true;
    }
}

/**
 * Mark terminal as available and wake up next process waiting on it.
 */
int release_access_to_term(int tty_id, enum TermAccessKind access_kind) {
    // Mark terminal in appropriate queue as unused
    if (access_kind == Read) {
        TracePrintf(2, "PID %d releasing read access to terminal %d.\n", g_running_pcb->pid, tty_id);
        term_read_status[tty_id] = 0;
    } else if (access_kind == Write) {
        TracePrintf(2, "PID %d releasing write access to terminal %d.\n", g_running_pcb->pid, tty_id);
        term_write_status[tty_id] = 0;
        tty_transmit_in_progress = false;
    }

    // Wake up any processes waiting for this kind of access on this terminal
    int *key = malloc(sizeof(int));
    if (key == NULL) {
        TP_ERROR("`malloc()` failed.\n");
        return ERROR;
    }
    *key = tty_id;

    if (access_kind == Read) {
        pcb_t *pcb = qremove(g_term_blocked_read_queue, is_waiting_for_term_id, (void *)key);
        if (pcb != NULL) {
            TracePrintf(2, "PID %d woke up from terminal read blocked queue.\n", pcb->pid);
            qput(g_ready_procs_queue, (void *)pcb);
        }
    } else if (access_kind == Write) {
        pcb_t *pcb = qget(g_term_blocked_write_queue);
        if (pcb != NULL) {
            TracePrintf(2, "PID %d woke up from terminal write blocked queue.\n", pcb->pid);
            qput(g_ready_procs_queue, (void *)pcb);
        }
    }

    free(key);
    return SUCCESS;
}

/**
 * Reading more than `TERMINAL_MAX_LINE` is undefined. So we exit with error if
 * that is attempted.
 */
int kTtyRead(int tty_id, void *buf, int len) {
    TracePrintf(2, "Entering `TtyRead()`...\n");

    /**
     * Validate user inputs
     */

    if (!(tty_id >= 0 && tty_id < NUM_TERMINALS)) {
        TP_ERROR("tried to read from an invalid terminal.\n");
        return ERROR;
    }

    if (!(is_valid_array(g_running_pcb->r1_ptable, buf, len, PROT_READ | PROT_WRITE))) {
        TP_ERROR("the `buf` that was passed was not valid.\n");
        return ERROR;
    }

    if (len > TERMINAL_MAX_LINE) {
        TP_ERROR("attempted to read more than `TERMINAL_MAX_LINE` from terminal.\n");
        return ERROR;
    }

    // Check if terminal is being used by another process. If so, sleep.
    gain_access_to_term(tty_id, Read);

    /**
     * If there isn't an input line from the terminal ready to go, block this process
     * until there is. We detect this by seeing if the corresponding kernel buf for this
     * terminal is `NULL`.
     */

    term_buf_t *k_buf = g_term_bufs[tty_id];

    if (k_buf->ptr == NULL) {
        g_running_pcb->blocked_term = tty_id;
        schedule(g_term_blocked_read_queue);
    }

    /**
     * There is now an input line ready to be read. So copy that over.
     */

    int bytes_remaining_in_kbuf = k_buf->end_pos_offset - k_buf->curr_pos_offset;

    // Copy over to user buf, clear kernel buf, and return
    if (bytes_remaining_in_kbuf <= len && bytes_remaining_in_kbuf > 0) {
        memcpy(buf, k_buf->ptr + k_buf->curr_pos_offset, len);
        free(k_buf->ptr);  // TODO: abstract this "clearing" into a function
        k_buf->ptr = NULL;
        k_buf->curr_pos_offset, k_buf->end_pos_offset = 0;
        return len;
    }

    // Copy over `len` bytes from the kernel buf, update kernel buf accordingly
    // to make it available for future reading. Return.
    else if (bytes_remaining_in_kbuf > len) {
        memcpy(buf, k_buf->ptr + k_buf->curr_pos_offset, len);
        k_buf->curr_pos_offset += len;
        return len;
    }

    /**
     * Wake up any processes waiting on this terminal.
     */

    if (release_access_to_term(tty_id, Read) == ERROR) {
        return ERROR;
    }

    return len;
}

/**
 * Calls to `TtyWrite` for more than `TERMINAL MAX LINE` bytes are supported.
 */
int kTtyWrite(int tty_id, void *buf, int len) {
    TracePrintf(2, "Entering `kTtyWrite()`...\n");

    /**
     * Validate user input
     */

    if (!(tty_id >= 0 && tty_id < NUM_TERMINALS)) {
        TP_ERROR("tried to read from an invalid terminal.\n");
        return ERROR;
    }

    if (!(is_valid_array(g_running_pcb->r1_ptable, buf, len, PROT_READ | PROT_WRITE))) {
        TP_ERROR("the `buf` that was passed was not valid.\n");
        return ERROR;
    }

    /**
     * Check if terminal is being used by another process. If so, sleep.
     */

    gain_access_to_term(tty_id, Write);

    /**
     * Copy user buf to kernel buf
     */

    void *kbuf = malloc(len);
    if (kbuf == NULL) {
        TP_ERROR("`malloc()` failed.\n");
        return ERROR;
    }

    memcpy(kbuf, buf, len);

    /**
     * Write from kernel buffer to terminal
     */

    void *current_byte = kbuf;
    int bytes_remaining = len;

    while (bytes_remaining > 0) {
        if (bytes_remaining < TERMINAL_MAX_LINE) {
            TtyTransmit(tty_id, current_byte, bytes_remaining);
            // Block until this operation completes
            g_running_pcb->blocked_term = tty_id;
            schedule(g_term_blocked_transmit_queue);
            break;
        }

        TtyTransmit(tty_id, current_byte, TERMINAL_MAX_LINE);
        // Block until this operation completes
        g_running_pcb->blocked_term = tty_id;
        schedule(g_term_blocked_transmit_queue);

        current_byte += TERMINAL_MAX_LINE;
        bytes_remaining -= TERMINAL_MAX_LINE;
    }

    free(kbuf);

    /**
     * Wake up next process waiting on this terminal
     */

    release_access_to_term(tty_id, Write);

    TracePrintf(2, "Exiting `kTtyWrite()`...\n");
    return len;
}
