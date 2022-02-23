/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/22/2022
 *
 * Some userland test code for yalnix checkpoint 4 syscalls (kWait, kExit).
 */

#include <yuser.h>

int main(int argc, char* argv[]) {

    TracePrintf(1, "RUNNING CP4_WAIT_TEST\n");

    TracePrintf(1, "About to fork:\n");
    int pid = Fork();

    if (pid == 0) {
        for (int i = 0; i < 10; i++) {
            TracePrintf(1, "This is the child (i=%d)\n", i);
            Pause();
        }
    }

    TracePrintf(1, "Parent before waiting\n");
    int status;
    int child_pid = Wait(&status);

    TracePrintf(1, "Parent after waiting. Returned: child_pid: %d status: %d\n", child_pid, status);
}
