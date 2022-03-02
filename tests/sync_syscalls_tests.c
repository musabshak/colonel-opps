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
        default:

            while (1) {
                TracePrintf(1, "%s RUNNING!\n", argv[0]);
                Pause();
            }
    }
}
