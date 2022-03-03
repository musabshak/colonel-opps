/**
 * Authors: Musab Shakeel
 * Date: 3/2/2022
 */

#include <yuser.h>
#define g_max_locks 50

/**
 * (1)
 *
 * Test creating a lock.
 */
void test_lock_init() {
    TracePrintf(1, "Initializing a new lock\n");
    int rc, lock_id;

    rc = LockInit(&lock_id);
    if (rc != 0) {
        TracePrintf(1, "Error in `LockInit` syscall\n");
    } else {
        TracePrintf(1, "Lock %d initialized successfully!\n", lock_id);
    }

    while (1) {
        TracePrintf(1, "LOCK TEST RUNNING\n");
        Pause();
    }
}

/**
 * (2)
 *
 * Tests creating > maximum number of locks allowed by the OS.
 */
void test_lock_init2() {
    TracePrintf(1, "Initializing a multitude of new locks\n");
    int lock_ids[g_max_locks + 5];
    int rc;

    for (int i = 0; i < g_max_locks + 5; i++) {
        rc = LockInit(&lock_ids[i]);
        if (rc != 0) {
            TracePrintf(1, "Error in `LockInit` syscall\n");
        } else {
            TracePrintf(1, "Lock %d initialized successfully!\n", lock_ids[i]);
        }
    }

    while (1) {
        TracePrintf(1, "LOCK TEST RUNNING\n");
        Pause();
    }
}

/**
 * (3)
 *
 * Tests passing invalid pointers to kLockInit.
 */
void test_lock_init3() {

    void *sneaky_kernel_addr = (void *)0x02ab60;
    void *null_ptr = NULL;

    int rc;

    TracePrintf(1, "Initializing locks with invalid pointers\n");
    rc = LockInit((int *)sneaky_kernel_addr);
    if (rc != 0) {
        TracePrintf(1, "Error in `LockInit` syscall\n");
    } else {
        TracePrintf(1, "Lock initialized successfully! (should never be printed)\n");
    }

    rc = LockInit((int *)null_ptr);
    if (rc != 0) {
        TracePrintf(1, "Error in `LockInit` syscall\n");
    } else {
        TracePrintf(1, "Lock initialized successfully! (should never be printed)\n");
    }

    while (1) {
        TracePrintf(1, "LOCK TEST RUNNING\n");
        Pause();
    }
}

/**
 * (4)
 *
 * Test basic acquire/release functionality with two processes.
 */
void test_locks1() {
    int rc, pid, lock_id;

    /**
     * Create a lock
     */
    TracePrintf(1, "Initializing lock ... \n");
    rc = LockInit(&lock_id);

    /**
     * Fork a child and make sure it acquires lock by delaying parent for a bit.
     */

    pid = Fork();
    if (pid == 0) {
        TracePrintf(1, "Process %d acquiring lock %d\n", GetPid(), lock_id);
        rc = Acquire(lock_id);
        TracePrintf(1, "Process %d successfully acquired lock %d\n", GetPid(), lock_id);

        TracePrintf(1, "Process %d will now count to ten!\n", GetPid());
        for (int i = 1; i <= 10; i++) {
            TracePrintf(1, "Process %d: %d\n", GetPid(), i);
            Pause();
        }
        TracePrintf(1, "Process %d releasing lock %d\n", GetPid(), lock_id);
        rc = Release(lock_id);

        Exit(0);
    }

    Delay(1);  // make sure child gets the lock

    TracePrintf(1, "Process %d acquiring lock %d\n", GetPid(), lock_id);
    rc = Acquire(lock_id);
    TracePrintf(1, "Process %d successfully acquired lock %d\n", GetPid(), lock_id);

    TracePrintf(1, "Process %d will now count to ten!\n", GetPid());
    for (int i = 1; i <= 10; i++) {
        TracePrintf(1, "Process %d: %d\n", GetPid(), i);
        Pause();
    }

    TracePrintf(1, "Process %d releasing lock %d\n", GetPid(), lock_id);
    rc = Release(lock_id);

    Exit(0);
}

/**
 * (5)
 *
 * Test kAcquire and kRelease with many processes.
 *
 * Fork many processes. Each process counts to five before giving up the lock.
 *
 */

void test_locks2() {
    int lock_id;

    /**
     * Create a lock
     */
    TracePrintf(1, "Initializing lock ... \n");
    LockInit(&lock_id);

    /**
     * Fork many processes;
     */
    for (int i = 0; i < 5; i++) {
        Fork();
    }

    Acquire(lock_id);

    for (int i = 1; i <= 5; i++) {
        TracePrintf(1, "Process %d counting: %d\n", GetPid(), i);
        Pause();
    }

    Release(lock_id);

    int status;

    for (int i = 0; i < 5; i++) {
        Wait(&status);
    }
}

/**
 * (6)
 *
 * Test initialziing a cvar
 */

void test_cvar_init() {
    TracePrintf(1, "Initializing a new cvar\n");
    int rc, cvar_id;

    rc = CvarInit(&cvar_id);
    if (rc != 0) {
        TracePrintf(1, "Error in `CvarInit` syscall\n");
    } else {
        TracePrintf(1, "Cvar %d initialized successfully!\n", cvar_id);
    }

    while (1) {
        TracePrintf(1, "CVAR TEST RUNNING\n");
        Pause();
    }
}

/**
 * (7)
 *
 * Test CvarWait/CvarSignal.
 */

void test_cvar1() {
    int lock_id, cvar_id;

    LockInit(&lock_id);
    CvarInit(&cvar_id);

    int pid = Fork();
    if (pid == 0) {
        Acquire(lock_id);
        Delay(5);
        CvarSignal(cvar_id);
        Release(lock_id);
        Exit(0);
    }

    Acquire(lock_id);
    CvarWait(cvar_id, lock_id);
    for (int i = 0; i < 6; i++) {
        TracePrintf(1, "Process %d counting: %d\n", GetPid(), i);
        Pause();
    }
    Release(lock_id);
}

int main(int argc, char **argv) {

    if (argc < 2) {
        TracePrintf(1, "Need to specify an option argument\n");
        Exit(-1);
    }

    int test_case = atoi(argv[1]);

    switch (test_case) {
        case 1:
            test_lock_init();
            break;
        case 2:
            test_lock_init2();
            break;
        case 3:
            test_lock_init3();
            break;
        case 4:
            test_locks1();
            break;
        case 5:
            test_locks2();
            break;
        case 6:
            test_cvar_init();
            break;
        case 7:
            test_cvar1();
            break;
        default:
            while (1) {
                TracePrintf(1, "%s RUNNING!\n", argv[0]);
                Pause();
            }
    }
}
