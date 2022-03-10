/**
 * mem_leak_tests.c
 *
 * Authors: Varun Malladi
 *
 * We interpret "memory leaks" here to be the case where processes exit or otherwise
 * seem to release their frames, but this change is not reflected in the frametable,
 * leading the kernel to think those frames are in use when they are not.
 */

#include <stdbool.h>
#include <yuser.h>

/**
 * Test 1: Try to grow user heap when physical memory is full
 *
 * Fork until we run out of physical memory. Them one of the processes will try to grow
 * its heap. We expect this process to exit. We should then be able to fork again, because
 * there is now space for another process.
 */
void test1() {
    bool physical_mem_full = false;

    int pid = Fork();
    if (pid == 0) {
        while (1) {
            TracePrintf(1, "PID %d (non-forking proc) RUNNING!\n", GetPid());

            if (physical_mem_full == true) {
                TracePrintf(1, "Physical memory full... PID %d trying to grow its stack a lot...\n",
                            GetPid());

                void* ptr = malloc(1000 * 10);

                if (ptr == NULL) {
                    TracePrintf(1, "`malloc()` failed!\n");
                }
            }

            Pause();
        }
    } else {
        int rc;
        while (1) {
            TracePrintf(1, "PID %d RUNNING!\n", GetPid());

            rc = Fork();

            if (rc == ERROR) {
                TracePrintf(1, "Fork failed! (PID %d)\n", GetPid());
                TracePrintf(1, "PID %d trying to grow heap...\n", GetPid());
                void* ptr = malloc(1000 * 200);

                if (ptr == NULL) {
                    TracePrintf(1, "`malloc()` failed!\n");
                } else {
                    TracePrintf(1, "`malloc()` succeeded!\n");
                }
            } else if (rc != 0) {
                TracePrintf(1, "Fork succeeded (caller was PID %d)!\n", GetPid());
            }

            Pause();
        }
    }
}

/**
 * Test 2: Fork as much as you can, exit all children, try it again
 *
 * We should expect the number of processes before and after exiting to be the same.
 */
void test2() {
    int pid = Fork();
    if (pid == 0) {
        while (1) {
            TracePrintf(1, "PID %d RUNNING!\n", GetPid());
            int pid2 = Fork();
            if (pid2 != 0) {
                Delay(20);
                Exit(0);
            } else if (pid2 == ERROR) {
                Exit(0);
            }
        }
    } else {
        Delay(30);
    }

    pid = Fork();
    if (pid == 0) {
        while (1) {
            TracePrintf(1, "PID %d RUNNING!\n", GetPid());
            int pid2 = Fork();
            if (pid2 != 0) {
                Delay(20);
                Exit(0);
            } else if (pid2 == ERROR) {
                Exit(0);
            }
        }
    } else {
        Delay(30);
    }
}

int main(int argc, char** argv) {
    int test_num = atoi(argv[1]);

    switch (test_num) {
        case 1:
            test1();
            break;
        case 2:
            test2();
            break;
        default:
            while (1) {
                TracePrintf(1, "What are you doing here?\n");
                Pause();
            }
    }
}
