#include "address_validation.h"
#include "kernel_data_structs.h"

/**
 * Used by hsearch()
 */

bool search_lock(void *elementp, const void *searchkeyp) {
    lock_t *lock = (lock_t *)elementp;
    const char *search_key_str = searchkeyp;

    char lock_key[MAX_KEYLEN];
    sprintf(lock_key, "lock%d\0", lock->lock_id);

    TracePrintf(2, "Comparing strings: %s =? %s\n", lock_key, search_key_str);
    if (strcmp(lock_key, search_key_str) == 0) {
        TracePrintf(2, "Strings are the same!\n");
        return true;
    } else {
        return false;
    }
}

/**
 * Used by hsearch()
 */

bool search_cvar(void *elementp, const void *searchkeyp) {
    cvar_t *cvar = (cvar_t *)elementp;
    const char *search_key_str = searchkeyp;

    char cvar_key[MAX_KEYLEN];
    sprintf(cvar_key, "cvar%d\0", cvar->cvar_id);

    TracePrintf(2, "Comparing strings: %s =? %s\n", cvar_key, search_key_str);
    if (strcmp(cvar_key, search_key_str) == 0) {
        TracePrintf(2, "Strings are the same!\n");
        return true;
    } else {
        return false;
    }
}

/**
 * Used by happly()
 */

void print_lock(void *elementp) {
    lock_t *lock = elementp;
    TracePrintf(2, "Lock id: %d\n", lock->lock_id);
}

/**
 * Used by happly()
 */

void print_cvar(void *elementp) {
    cvar_t *cvar = elementp;
    TracePrintf(2, "Cvar id: %d\n", cvar->cvar_id);
}

/*
 *
 *  From manual (p. 34):
 *      Create a new lock; save its identifier at *lock idp. In case
 *      of any error, the value ERROR is returned.
 *
 *  Pseudocode
 *  - Malloc a new lock struct onto the kernel heap
 *      - Need to malloc, as opposed to just storing lock as local variable in kernel stack because
 *       need lock to persist in virtual memory even as processes are switched; kernel stack is unique
 *       per process
 *  - Add newly created lock to global lock_list_qp (linked list)
 *      - qadd(lock_list_qp, lock)
 *  - Initilize lock struct
 *      - Allocate a unique lock_id for the lock
 *          - lock_id determined by global lock_id counter (kernel.c)
 *      - set lock.locked = 0
 *      - set lock.owner = -1
 *  - Set *lock_idp = lock.lock_id
 *  - Return 0 if everything went successfully, ERROR otherwise
 */

int kLockInit(int *lock_idp) {
    TracePrintf(2, "Entering `kLockInit`\n");
    /**
     * Verify that user-given pointer is valid (user has permissions to write
     * to what the pointer is pointing to)
     */
    if (!is_r1_addr(lock_idp) || !is_writeable_addr(g_running_pcb->r1_ptable, (void *)lock_idp)) {
        TracePrintf(1, "`kLockInit()` passed an invalid pointer -- syscall now returning ERROR\n");
        return ERROR;
    }

    /**
     * Allocate a lock on kernel heap and initialize it.
     */
    lock_t *new_lock = malloc(sizeof(*new_lock));
    if (new_lock == NULL) {
        TracePrintf(1, "malloc failed in `kLockInit`()\n");
        return ERROR;
    }

    /**
     * Initialize lock.
     */
    new_lock->lock_id = assign_lock_id();

    // Check that max lock limit has not been reached
    if (new_lock->lock_id == ERROR) {
        free(new_lock);
        return ERROR;
    }

    new_lock->locked = false;
    new_lock->corrupted = false;
    new_lock->owner_proc = NULL;
    new_lock->blocked_procs_queue = qopen();

    /**
     * Put newly created lock in global locks hashtable
     */
    char lock_key[MAX_KEYLEN];  // 12 should be more than enough to cover a billion locks (even though
                                // g_max_locks will probably be less)

    sprintf(lock_key, "lock%d\0", new_lock->lock_id);

    TracePrintf(2, "lock key: %s; lock key length: %d\n", lock_key, strlen(lock_key));

    int rc = hput(g_locks_htable, (void *)new_lock, lock_key, strlen(lock_key));
    if (rc != 0) {
        TracePrintf(1, "error occurred while putting lock into hashtable\n");
        free(new_lock);
        return ERROR;
    }

    TracePrintf(2, "printing locks hash table\n");
    happly(g_locks_htable, print_lock);

    *lock_idp = new_lock->lock_id;

    return SUCCESS;
}

/*
 *  From manual (p. 34):
 *      Acquire the lock identified by lock id. In case of any error,
 *      the value ERROR is returned.
 *
 *  Pseudocode
 *  - Traverse lock_list_qp to find the lock referenced by lock_id
 *  - if lock.locked == 0
 *      - lock.locked = 1
 *      - lock.owner = running_process.pid;
 *      - return 0
 *  - elif lock.locked == 1
 *      - if lock.owner == running_procces.pid
 *          - return ERROR (you already have the lock!)
 *      - else
 *          - add running_process to blocked_processes queue
 *              - qadd(lock.blocked_processes, running_process)
 *          - return 0
 *
 */

int kAcquire(int lock_id) {
    /**
     * TODO: validate arg
     */

    /**
     * Get lock from hashtable
     */
    char lock_key[MAX_KEYLEN];
    sprintf(lock_key, "lock%d\0", lock_id);

    lock_t *lock = (lock_t *)hsearch(g_locks_htable, search_lock, lock_key, strlen(lock_key));
    if (lock == NULL) {
        TP_ERROR("Failed retrieving lock %d from locks hashtable\n", lock_id);
        return ERROR;
    }

    /**
     * If lock isn't locked, lock it, set the owner process, and return.
     */
    if (!lock->locked) {
        lock->locked = true;
        lock->owner_proc = g_running_pcb;
        return 0;
    }

    /**
     * If lock is already locked, check that the acquiring process is not the lock
     * owner. If it is, return ERROR. If not, add the process to the blocked queue
     * associated with the lock, and call the scheduler.
     */
    if (lock->owner_proc == g_running_pcb) {
        TP_ERROR("Process %d already owns lock %d!\n", g_running_pcb->pid, lock->lock_id);
        return ERROR;
    }

    qput(lock->blocked_procs_queue, g_running_pcb);
    schedule(NULL);

    return 0;
}

/*
 *  From manual (p. 35):
 *      Release the lock identified by lock id. The caller must currently
 *      hold this lock. In case of any error, the value ERROR is returned.
 *
 *  Pseudocode
 *  - Traverse lock_list_qp to find the lock referenced by lock_id
 *  - if lock.locked == 0 (cannot release an unacquired lock)
 *      - return ERROR
 *  - if lock.owner != running_process.pid
 *      - return ERROR
 *  - else
 *      - if qsize(lock.blocked_processes) != 0
 *          - proc = qget(lock.blocked_processes)
 *          - MOVE proc to READY_PROCESSES
 *          - lock.owner = proc.id
 *          - lock.locked = 1 (lock stays locked)
 *      - else
 *          - lock.owner = -1
 *          - lock.locked = 0
 */

int kRelease(int lock_id) {
    /**
     * TODO: validate arg
     */

    /**
     * Get lock from hashtable
     */
    char lock_key[MAX_KEYLEN];
    sprintf(lock_key, "lock%d\0", lock_id);

    lock_t *lock = (lock_t *)hsearch(g_locks_htable, search_lock, lock_key, strlen(lock_key));
    if (lock == NULL) {
        TP_ERROR("Failed retrieving lock %d from locks hashtable\n", lock_id);
        return ERROR;
    }

    /**
     * Check that we're not trying to release an unacquired lock.
     */

    if (!lock->locked) {
        TP_ERROR("Cannot release an un-locked lock!\n");
        return ERROR;
    }

    /**
     * If there is a process waiting to get this lock (blocked process queue
     * associated with the lock is not empty), move that process out of the blocked
     * queue into the ready queue, and transfer lock ownership here directly.
     *
     * If not, unnlock the lock and set attributes accordingly.
     */

    if (qlen(lock->blocked_procs_queue) > 0) {
        pcb_t *proc = qget(lock->blocked_procs_queue);
        qput(g_ready_procs_queue, proc);
        lock->owner_proc = proc;
        lock->locked = true;  // stays locked
        return 0;
    }

    lock->locked = false;
    lock->owner_proc = NULL;

    return 0;
}

/*
 *  ================
 *  === CVARINIT ===
 *  ================
 *
 *  From manual (p. 35):
 *      Create a new condition variable; save its identifier at *cvar_idp.
 *      In case of any error, the value ERROR is returned.
 *
 *
 *  Pseudocode
 *  - Malloc a new cvar struct onto the kernel heap
 *  - Add newly created cvar to global cvar_list_qp (linked list)
 *  - Initilize cvar struct
 *      - Allocate a unique cvar_id for the lock
 *          - cvar_id determined by global cvar_id counter (kernel.c)
 *  - Set *cvar_idp = cvar.cvar_id
 *  - Return 0 if everything went successfully, ERROR otherwise
 *
 */
int kCvarInit(int *cvar_idp) {
    TracePrintf(2, "Entering `kCvarInit`\n");
    /**
     * Verify that user-given pointer is valid (user has permissions to write
     * to what the pointer is pointing to).
     */
    if (!is_r1_addr(cvar_idp) || !is_writeable_addr(g_running_pcb->r1_ptable, (void *)cvar_idp)) {
        TracePrintf(1, "`kCvarInit()` passed an invalid pointer -- syscall now returning ERROR\n");
        return ERROR;
    }

    /**
     * Allocate a cvar on kernel heap and initialize it.
     */
    cvar_t *new_cvar = malloc(sizeof(*new_cvar));
    if (new_cvar == NULL) {
        TracePrintf(1, "malloc failed in `kCvarInit`()\n");
        return ERROR;
    }

    /**
     * Initialize cvar.
     */
    new_cvar->cvar_id = assign_cvar_id();

    // Check that max cvar limit has not been reached
    if (new_cvar->cvar_id == ERROR) {
        free(new_cvar);
        return ERROR;
    }

    new_cvar->blocked_procs_queue = qopen();

    /**
     * Put newly created cvar in global cvars hashtable
     */
    char cvar_key[MAX_KEYLEN];  // 12 should be more than enough to cover a billion cvars (even though
                                // g_max_cvars will probably be less)

    sprintf(cvar_key, "cvar%d\0", new_cvar->cvar_id);

    TracePrintf(2, "cvar key: %s; cvar key length: %d\n", cvar_key, strlen(cvar_key));

    int rc = hput(g_cvars_htable, (void *)new_cvar, cvar_key, strlen(cvar_key));
    if (rc != 0) {
        TracePrintf(1, "error occurred while putting cvar into hashtable\n");
        free(new_cvar);
        return ERROR;
    }

    TracePrintf(2, "printing cvars hash table\n");
    happly(g_cvars_htable, print_cvar);

    *cvar_idp = new_cvar->cvar_id;

    return SUCCESS;
}

/*
 *  ================
 *  === CVARWAIT ===
 *  ================
 *
 *  From manual (p. 35):
 *      The kernel-level process releases the lock identified by lock id and
 *      waits on the condition variable indentified by cvar id. When the
 *      kernel-level process wakes up (e.g., because the condition variable was
 *      signaled), it re-acquires the lock. (Use Mesa-style semantics.)
 *      When the lock is finally acquired, the call returns to userland. In case
 *      of any error, the value ERROR is returned.
 *
 *  Pseudocode
 *  - Traverse cvar_list_qp to find cvar associated with cvar_id
 *  - Set the following
 *      - cvar.lock_id = lock_id (don't need this either)
 *      - cvar.pid = running_process.pid (don't need this - have the blocked queue)
 *  - Call kRelease(lock_id)
 *  - Add running_process to cvar.blocked_processes queue
 *  - ** at this time, cvar_wait method is blocked because the calling process was just
 *      put into the blocked queue **
 *  - ** signal wakes up process **
 *  - Call kAcquire(lock_id)
 *  - return 0
 */
int kCvarWait(int cvar_id, int lock_id) {
    /**
     * TODO: validate arguments
     */

    /**
     * Get cvar from hashtable
     */
    char cvar_key[MAX_KEYLEN];
    sprintf(cvar_key, "cvar%d\0", cvar_id);

    cvar_t *cvar = (cvar_t *)hsearch(g_cvars_htable, search_cvar, cvar_key, strlen(cvar_key));
    if (cvar == NULL) {
        TP_ERROR("Failed retrieving cvar %d from cvars hashtable\n", cvar_id);
        return ERROR;
    }

    /**
     * Get lock from hashtable
     */
    char lock_key[MAX_KEYLEN];
    sprintf(lock_key, "lock%d\0", lock_id);

    lock_t *lock = (lock_t *)hsearch(g_locks_htable, search_lock, lock_key, strlen(lock_key));
    if (lock == NULL) {
        TP_ERROR("Failed retrieving lock %d from locks hashtable\n", lock_id);
        return ERROR;
    }

    /**
     * Release the lock
     */
    int rc;
    rc = kRelease(lock_id);
    if (rc != 0) {
        TP_ERROR("Failed releasing the lock in kCvarWait\n");
    }

    /**
     * Make the current process go to sleep, "waiting" for things to change.
     */
    schedule(cvar->blocked_procs_queue);

    // Now the process is sleeping. Will be "woken up" by a signal() or broadcast() call.

    /**
     * Acquire the lock after the process wakes up.
     */
    rc = kAcquire(lock_id);
    if (rc != 0) {
        TP_ERROR("Failed acquiring the lock in kCvarWait\n");
    }

    return 0;
}

/*
 *  ==================
 *  === CVARSIGNAL ===
 *  ==================
 *
 *  From manual (p. 35):
 *      Signal the condition variable identified by cvar id. (Use Mesa-style
 *      semantics.) In case of any error, the value ERROR is returned.
 *
 *  Pseudocode
 *  - Traverse cvar_list_qp to find cvar associated with cvar_id
 *  - Find and remove one blocked process associated with the cvar
 *      - proc = qget(cvar.blocked_process)
 *  - Add proc to the ready_processes queue
 *  - return 0
 */
int kCvarSignal(int cvar_id) {
    /**
     * TODO: validate arguments
     */

    /**
     * Get cvar from hashtable
     */
    char cvar_key[MAX_KEYLEN];
    sprintf(cvar_key, "cvar%d\0", cvar_id);

    cvar_t *cvar = (cvar_t *)hsearch(g_cvars_htable, search_cvar, cvar_key, strlen(cvar_key));
    if (cvar == NULL) {
        TP_ERROR("Failed retrieving cvar %d from cvars hashtable\n", cvar_id);
        return ERROR;
    }

    /**
     * Find one blocked process associated with cvar and move it to the ready queue.
     */
    pcb_t *proc = (pcb_t *)qget(cvar->blocked_procs_queue);
    if (proc == NULL) {
        TP_ERROR("Trying to signal a cvar that has no blocked processes associated with it!\n");
        return ERROR;
    }

    qput(g_ready_procs_queue, proc);

    return 0;
}

/*
 *  =====================
 *  === CVARBROADCAST ===
 *  =====================
 *
 *  From manual (p. 35):
 *      Broadcast the condition variable identified by cvar id. (Use Mesa-style
 *      semantics.) In case of any error, the value ERROR is returned.
 *
 *  Pseudocode
 *  - Traverse cvar_list_qp to find cvar associated with cvar_id
 *  - Go through cvar.blocked_processes and pop all PCBs from this list
 *  - Add each popped list to the ready_processes queue
 *  - return 0
 *
 */
int kCvarBroadcast(int cvar_id) {
    /**
     * TODO: validate arguments
     */

    /**
     * Get cvar from hashtable
     */
    char cvar_key[MAX_KEYLEN];
    sprintf(cvar_key, "cvar%d\0", cvar_id);

    cvar_t *cvar = (cvar_t *)hsearch(g_cvars_htable, search_cvar, cvar_key, strlen(cvar_key));
    if (cvar == NULL) {
        TP_ERROR("Failed retrieving cvar %d from cvars hashtable\n", cvar_id);
        return ERROR;
    }

    /**
     * Remove ALL blocked process associated with cvar and move them ALL to the ready queue.
     */
    pcb_t *proc = (pcb_t *)qget(cvar->blocked_procs_queue);
    if (proc == NULL) {
        TP_ERROR("Trying to broadcast a cvar that has no blocked processes associated with it!\n");
        return ERROR;
    }

    while (proc != NULL) {
        qput(g_ready_procs_queue, proc);
        proc = (pcb_t *)qget(cvar->blocked_procs_queue);
    }

    return 0;
}

/*
 *  ===============
 *  === RECLAIM ===
 *  ===============
 *
 *  From manual (p. 35):
 *      Destroy the lock, condition variable, or pipe indentified by id,
 *      and release any associated resources.
 *      In case of any error, the value ERROR is returned.
 *      If you feel additional specification is necessary to handle unusual
 *      scenarios, then create and document it.
 *
 *  Thoughts
 *  - Not sure how to determine whether its a lock/cvar/pipe being reclaimed, based on id alone
 *  since we're maintaing separate counters for
 *      - Suggestions: increment lock_id in multiples of 3, cvar_id in multiples of 5, pipe_id in multiples of
 * 7
 *
 *  Pseudocode
 *  - Determine whether to look in the lock_list_qp or cvar_list_qp or pipe_list_qp
 *      - if id % 3 == 0: look in lock_qp
 *      - elif id % 5 == 0: look in cvar_list_qp
 *      - elif id % 7 == 0: look in pipe_list_qp
 *  - If lock
 *      - Go through lock.blocked_processes, remove each process from queue, and kill process?
 *
 */
int kReclaim(int id) {}
