/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/25/2022
 *
 * Some userland test code for yalnix syscalls.
 */

#include <yuser.h>

/**
 * (10)
 */
void test_implicitly_grow_ustack() {
    TracePrintf(1, "Implicitly growing user stack by a reasonable amount...\n");

    int on_stack_1[90000];
    for (int i = 0; i < 90000; i++) {
        on_stack_1[i] = 3;
        TracePrintf(1, "on_stack_1[%d] == %d\n", i, on_stack_1[i]);
    }

    for (int i = 0; i < 90000; i++) {
        TracePrintf(1, "on_stack_1[%d] == %d\n", i, on_stack_1[i]);
    }

    TracePrintf(1, "User stack implicitly grew!\n");

    while (1) {
        TracePrintf(1, "CP5_TEST RUNNING!\n");
        Pause();
    }
}

/**
 * (11)
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

/**
 * (18)
 */
void test_terminal() {
    int pid = Fork();
    if (pid == 0) {
        char *args[] = {"tests/terminal_tests", NULL};
        Exec("tests/terminal_tests", args);
    } else {
        while (1) {
            TracePrintf(1, "CP5_TESTS RUNNING!\n");
            Pause();
        }
    }
}

int main(int argc, char **argv) {

    int test_case = atoi(argv[1]);

    switch (test_case) {

        case 10:
            test_implicitly_grow_ustack();
            break;
        case 11:
            test_implicitly_grow_ustack_toomuch();
            break;

        case 18:
            test_terminal();
            break;
        default:
            while (1) {
                TracePrintf(2, "CP5 TEST RUNNING!\n");
                Pause();
            }
    }
}
