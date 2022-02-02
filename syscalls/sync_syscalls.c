#include <queue.h>  // generic queue DS imported from engs50 code

/*
LinkedList to hold all the locks (naive data structure).
In future, replace with hashtable, indexed by lock_id because
    - Will have to traverse entire list to retrieve a particular lock
*/
queue_t *lock_list_qp = qopen();

// Queue of cvars
queue_t *cvar_list_qp = qopen();

/** ===================
 * === Lock Struct ===
 * ===================
 *
 */

typedef struct Lock {
    unsigned int lock_id;
    unsigned int locked;     // takes value 1 or 0 (T or F)
    unsigned int owner;      // takes pid of process that owns lock
    unsigned int corrupted;  // indicates whether lock is corrupted (if process holding lock
                             // exited w/o releasing)

    queue_t *blocked_processes;  // Queue of blocked processes associated with this lock
} lock_t;

/** ===================
 * === Cvar Struct ===
 * ===================
 *
 */
typedef struct Cvar {
    unsigned int cvar_id;
    unsigned int lock_id;
    unsigned int pid;

    queue_t *blocked_processes;
} cvar_t;

/*
 *  ================
 *  === LOCKINIT ===
 *  ================
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
}

/*
 *  ===============
 *  === ACQUIRE ===
 *  ===============
 *
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
}

/*
 *  ===============
 *  === RELEASE ===
 *  ===============
 *
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
 *      - cvar.lock_id = lock_id
 *      - cvar.pid = running_process.pid
 *  - Call kRelease(lock_id)
 *  - Add running_process to cvar.blocked_processes queue
 *  - ** at this time, cvar_wait method is blocked because the calling process was just
 *      put into the blocked queue **
 *  - ** signal wakes up process **
 *  - Call kAcquire(lock_id)
 *  - return 0
 *
 *
 *
 */
int kCvarWait(int cvar_id, int lock_id) {
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
 *      - Suggestions: increment lock_id in multiples of 3, cvar_id in multiples of 5, pipe_id in multiples of 7
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
int kReclaim(int id) {
}
