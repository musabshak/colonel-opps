/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/26/2022
 */

#include <yuser.h>

/**
 * (1)
 */
void test_implicitly_grow_ustack() {
    TracePrintf(2, "Implicitly growing user stack by a reasonable amount...\n");

    int on_stack_1[10000];
    for (int i = 0; i < 10000; i++) {
        on_stack_1[i] = 0;
    }

    TracePrintf(2, "User stack implicitly grew!\n");

    while (1) {
        TracePrintf(2, "CP4_TEST RUNNING!\n");
        Pause();
    }
}

/**
 * (2)
 */
void test_implicitly_grow_ustack_toomuch() {
    int pid = Fork();
    if (pid == 0) {
        // For some reason, including that code here results in unexpected behavior.
        // For instance, the program does not even fork! Even when delegating this code
        // to another file, the Traceprints there do not work. However, we can still
        // detect that exit code by waiting.

        char *args[] = {"tests/grow_ustack_toomuch", NULL};
        Exec("tests/grow_ustack_toomuch", args);
    } else {
        TracePrintf(2, "CP4_TEST RUNNING!\n");
        TracePrintf(2, "CP4_TEST waiting on child...\n");

        int status;
        int pid = Wait(&status);
        TracePrintf(2, "CP4_TEST finished waiting, received exit status %d from PID %d.\n", status, pid);

        while (1) {
            TracePrintf(2, "CP4_TEST RUNNING!\n");
            Pause();
        }
    }
}

int main(int argc, char **argv) {

    int test_case = atoi(argv[1]);

    switch (test_case) {
        case 1:
            test_implicitly_grow_ustack();
            break;
        case 2:
            test_implicitly_grow_ustack_toomuch();
            break;

        default:
            while (1) {
                TracePrintf(2, "%s RUNNING!\n", argv[0]);
                Pause();
            }
    }
}
