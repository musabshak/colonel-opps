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
            TracePrintf(1, "PID %d RUNNING!\n", GetPid());

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
                TracePrintf(1, "Fork failed!\n");
                physical_mem_full = true;
            } else if (rc == 0) {
                TracePrintf(1, "Fork succeeded!\n");
            }

            Pause();
        }
    }
}

int main(int argc, char** argv) {
    int test_num = atoi(argv[1]);

    switch (test_num) {
        case 1:
            test1();
            break;
        default:
            while (1) {
                TracePrintf(1, "What are you doing here?\n");
                Pause();
            }
    }
}
