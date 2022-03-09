#include "address_validation.h"
#include "k_common.h"

/**
 * Used as "search" fxn in qremove_all (in kPipeWrite).
 *
 * Does two things
 *      - Puts process on ready queue
 *      - returns true
 * Otherwise
 *      - returns false
 */
bool put_proc_on_ready_queue(void *elementp, const void *key) {

    pcb_t *proc = (pcb_t *)elementp;

    qput(g_ready_procs_queue, proc);
    return true;
}

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

/**
 * Pipe buffer enqueue.
 *
 * Returns ERROR if anythign goes wrong, and success if everything goes right.
 *
 * Idea: https://www.geeksforgeeks.org/circular-queue-set-1-introduction-array-implementation/
 */

int circular_enqueue(pipe_t *pipe, char byte_to_write) {

    // Just to be safe, check this
    if (pipe->curr_num_bytes == PIPE_BUFFER_LEN) {
        TP_ERROR("Trying to enqueue into a full pipe!\n");
        return ERROR;
    }

    if (pipe->front == -1) {  // insert first element
        pipe->front = 0;
        pipe->back = 0;
    } else if (pipe->back == PIPE_BUFFER_LEN - 1) {
        pipe->back = 0;
    } else {
        pipe->back += 1;
    }

    pipe->buffer[pipe->back] = byte_to_write;
    pipe->curr_num_bytes += 1;

    return SUCCESS;
}

/**
 * Pipe buffer dequeue.
 *
 * Writes byte into address pointed to by char_addr.
 *
 * Returns ERROR if anything goes wrong, and SUCCESS if everything goes right.
 *
 * Idea: https://www.geeksforgeeks.org/circular-queue-set-1-introduction-array-implementation/
 */

int circular_dequeue(pipe_t *pipe, char *char_addr) {

    // Check that the pipe buffer is not empty, just to be safe
    if (pipe->curr_num_bytes == 0) {
        TP_ERROR("Trying to dequeue from an empty pipe!\n");
        return ERROR;
    }

    *char_addr = pipe->buffer[pipe->front];  // dequeued char
    pipe->buffer[pipe->front] = '\0';        // mark dequeued char as NULL
    pipe->curr_num_bytes--;

    // Update front
    if (pipe->front == pipe->back) {  // means queue is now empty
        pipe->front = -1;
        pipe->back = -1;
    } else if (pipe->front == PIPE_BUFFER_LEN - 1) {  // circle back to the start of queue
        pipe->front = 0;
    } else {
        pipe->front += 1;
    }

    return SUCCESS;
}

/**
 * Buffer implementation:
 *      - Easy way: use currently existing Queue code (linked list implementation).
 *      - Slicker way: implement a circular array implementation of FIFO queue for pipe buffers.
 *
 * We do it the slicker way. That is, The pipe is really a Queue ADT implemented as a circular array.
 *
 * Passing an invalid pointer to kPipeInit() does not result in the user program exiting; the syscall
 * just returns with an ERROR.
 *
 *
 */
int kPipeInit(int *pipe_idp) {
    TracePrintf(2, "Entering `kPipeInit()`\n");

    /**
     * Verify that user-given pointer is valid (user has permissions to write
     * to what the pointer is pointing to)
     */
    if (!is_r1_addr(pipe_idp) || !is_writeable_addr(g_running_pcb->r1_ptable, (void *)pipe_idp)) {
        TracePrintf(1, "`kPipeInit()` passed an invalid pointer -- syscall now returning ERROR\n");
        return ERROR;
    }

    /**
     * Allocate a pipe on kernel heap and initialize it.
     */
    pipe_t *new_pipe = malloc(sizeof(*new_pipe));
    if (new_pipe == NULL) {
        TracePrintf(1, "malloc failed in `kPipeInit`()\n");
        return ERROR;
    }

    // Initialize pipe
    new_pipe->pipe_id = assign_pipe_id();

    // Check that max pipe limit has not been reached
    if (new_pipe->pipe_id == ERROR) {
        free(new_pipe);
        return ERROR;
    }

    new_pipe->curr_num_bytes = 0;
    new_pipe->front = -1;
    new_pipe->back = -1;
    new_pipe->blocked_procs_queue = qopen();

    /**
     * Put newly created pipe in global pipes hashtable
     */
    char pipe_key[MAX_KEYLEN];  // 12 should be more than enough to cover a billion pipes (even though
                                // g_max_pipes will probably be less)

    sprintf(pipe_key, "pipe%d\0", new_pipe->pipe_id);

    TracePrintf(2, "pipe key: %s; pipe key length: %d\n", pipe_key, strlen(pipe_key));

    int rc = hput(g_pipes_htable, (void *)new_pipe, pipe_key, strlen(pipe_key));
    if (rc != 0) {
        TracePrintf(1, "error occurred while putting pipe into hashtable\n");
        free(new_pipe);
        return ERROR;
    }

    TracePrintf(2, "printing pipes hash table\n");
    happly(g_pipes_htable, print_pipe);

    *pipe_idp = new_pipe->pipe_id;

    return SUCCESS;
}

/**
 * Returns the number of bytes read.
 *
 * If syscall fails, some pipe contents may have been partly written into the buffer.
 */
int kPipeRead(int pipe_id, void *buffer, int len) {

    /**
     * Check that the args are legit (pipe_id, buffer, len).
     *
     * Buffer (living in R1 land) needs to have write permissions (it is going to be written into).
     */
    if (!is_valid_array(g_running_pcb->r1_ptable, buffer, len, PROT_WRITE)) {
        TP_ERROR("buffer not valid\n");
        return ERROR;
    }

    char *buffer_str = (char *)buffer;

    /**
     * Get pipe from hashtable
     */
    char pipe_key[MAX_KEYLEN];
    sprintf(pipe_key, "pipe%d\0", pipe_id);

    pipe_t *pipe = (pipe_t *)hsearch(g_pipes_htable, search_pipe, pipe_key, strlen(pipe_key));
    if (pipe == NULL) {
        TP_ERROR("Failed retrieving pipe %d from pipes hashtable\n", pipe_id);
        return ERROR;
    }

    int curr_num_bytes = pipe->curr_num_bytes;

    /**
     * If pipe is empty, block the caller
     */
    while (curr_num_bytes == 0) {
        TracePrintf(2, "pipe is empty, blocking caller\n");
        schedule(pipe->blocked_procs_queue);
        curr_num_bytes = pipe->curr_num_bytes;  // need to update after process wakes back up
    }

    curr_num_bytes = pipe->curr_num_bytes;  // for if process wakes up again

    /**
     * If pipe->curr_num_bytes <= len, give all to the caller and return.
     * If pipe->curr_num_bytes > len, give the first len to caller and return.
     *
     */
    int num_bytes_to_read;  // = min(curr_num_bytes, len)
    if (curr_num_bytes <= len) {
        num_bytes_to_read = curr_num_bytes;
    } else {
        num_bytes_to_read = len;
    }

    int rc;

    /**
     * Call circular_dequeue() num_bytes_to_read times
     */
    for (int i = 0; i < num_bytes_to_read; i++) {
        rc = circular_dequeue(pipe, &buffer_str[i]);

        if (rc != 0) {
            TP_ERROR("Dequeue failed\n");
            return ERROR;
        }
    }

    return num_bytes_to_read;
}

/**
 * If a writer tries to write and the buffer is full, the syscall returns ERROR.
 *
 * All blocked processes waiting for bytes on the pipe are woken up by kPipeWrite.
 */
int kPipeWrite(int pipe_id, void *buffer, int len) {

    /**
     * Check that the args are legit (pipe_id, buffer, len).
     *
     * Buffer (living in R1 land) needs to have read permissions (it's going to be read from).
     */
    if (!is_valid_array(g_running_pcb->r1_ptable, buffer, len, PROT_READ | PROT_WRITE)) {
        TP_ERROR("buffer not valid\n");
        return ERROR;
    }

    char *buffer_str = (char *)buffer;

    /**
     * Get pipe from hashtable
     */
    char pipe_key[MAX_KEYLEN];
    sprintf(pipe_key, "pipe%d\0", pipe_id);

    pipe_t *pipe = (pipe_t *)hsearch(g_pipes_htable, search_pipe, pipe_key, strlen(pipe_key));
    if (pipe == NULL) {
        TP_ERROR("Failed retrieving pipe %d from pipes hashtable\n", pipe_id);
        return ERROR;
    }

    int num_free_bytes = PIPE_BUFFER_LEN - pipe->curr_num_bytes;

    /**
     * If pipe is full, fail the syscall
     */
    if (num_free_bytes == 0) {
        TP_ERROR("Trying to write to a full pipe\n");
        return ERROR;
    }

    /**
     * Otherwise, write as many as possible
     */

    int num_bytes_to_write;  // = min(num_free_bytes, len)
    if (num_free_bytes <= len) {
        num_bytes_to_write = num_free_bytes;
    } else {
        num_bytes_to_write = len;
    }

    int rc;

    /**
     * Write into pipe's buffer from input buffer.
     * Call circular_enqueue(byte) num_bytes_to_write times.
     */
    for (int i = 0; i < num_bytes_to_write; i++) {
        rc = circular_enqueue(pipe, buffer_str[i]);

        if (rc != 0) {
            TP_ERROR("Enqueue failed\n");
            return ERROR;
        }
    }

    /**
     * Wake up all processes that were waiting for bytes on this pipe.
     *
     * (done similarly as in clockTrap where blocked queue needed to be iterated, and processes
     * needed to be removed during iteration if they had paid their dues in waiting).
     */

    qremove_all(pipe->blocked_procs_queue, put_proc_on_ready_queue, NULL);
    return num_bytes_to_write;
}
