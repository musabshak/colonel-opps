/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/16/2022
 *
 * Some userland test code for yalnix checkpoint 3 syscalls (getPid, Brk, Delay).
 */

#include <yuser.h>

/**
 * Forks, parent loops, child forks again, and the child and the child's child both loop.
 * This tests basic functionality.
 */
void test_fork() {
    int pid2;
    TracePrintf(1, "About to fork:\n");
    int pid = Fork();
    if (pid == 0) {
        while (1) {
            TracePrintf(1, "This is the child (before forking again).\n");

            pid2 = Fork();

            if (pid2 == 0) {
                while (1) {
                    TracePrintf(1, "This is the child's child.\n");
                    Pause();
                }

            } else {
                while (1) {
                    TracePrintf(1, "This is the child.\n");
                    Pause();
                }
            }
            Pause();
        }
    } else {
        while (1) {
            TracePrintf(1, "This is the parent... `Fork()` returned %d.\n", pid);
            Pause();
        }
    }
}

/**
 * Try calling `Exec()` with some arguments.
 */
void test_exec_with_args() {
    TracePrintf(1, "About to `Exec()` with arguments...\n");

    char *args_vec[] = {"hello", "world", NULL};
    Exec("tests/exec_test", args_vec);
}

void test_exec_without_args() {
    int pid = Fork();
    if (pid == 0) {
        for (int i = 0; i < 5; i++) {
            TracePrintf(2, "CP4_CHILD RUNNING!\n");
            Pause();
        }

        TracePrintf(2, "About to `Exec()` without arguments...\n");

        char *args_vec[] = {NULL};
        int rc = Exec("tests/exec_test", args_vec);

        TracePrintf(2, "Exec failed!\n");
        Exit(rc);
    } else {
        TracePrintf(2, "CP4_TEST RUNNING!\n");
        TracePrintf(2, "Waiting on child...\n");

        int status;
        int pid = Wait(&status);
        TracePrintf(2, "Finished waiting, received exit status %d from PID %d.\n", status, pid);

        while (1) {
            TracePrintf(2, "CP4_TEST RUNNING!\n");
            Pause();
        }
    }
}

/**
 * Tries to load a program normally.
 *
 */
void test_exec() {
    TracePrintf(1, "About to exec:\n");
    char *args_vec[] = {"hello", "world", NULL};

    Exec("tests/init", args_vec);

    while (1) {
        TracePrintf(1, "CP4_TEST RUNNING! (should never be printed b/c exec)\n");
    }
}

void test_exit() {
    int pid = Fork();
    if (pid == 0) {
        for (int i = 0; i < 3; i++) {
            TracePrintf(1, "CP4_TEST's child RUNNING!\n");
            Pause();
        }
        TracePrintf(1, "CP4_TEST child about to exit...\n");
        Exit(0);
    } else {
        while (1) {
            TracePrintf(1, "CP4_TEST RUNNING!\n");
            Pause();
        }
    }
}

void test_wait() {
    int pid = Fork();
    if (pid == 0) {
        for (int i = 0; i < 5; i++) {
            TracePrintf(1, "CP4 TEST CHILD RUNNING!\n");
            Pause();
        }
        TracePrintf(1, "CP4 TEST child about to exit...\n");
        Exit(0);
    } else {
        TracePrintf(1, "CP4 TEST waiting on child.\n");
        int exit_status;
        int exit_pid = Wait(&exit_status);

        TracePrintf(1, "CP4 TEST received exit status %d from PID %d.\n", exit_status, exit_pid);

        while (1) {
            TracePrintf(1, "CP4 TEST RUNNING!\n");
            Pause();
        }
    }
}

void test_exec_with_kernel_addr() {
    // TracePrintf(1, "About to exec with a kernel address:\n");

    // char *sneaky_kernel_addr = (char *)(0x02ab60);
    // char **args_vec = {sneaky_kernel_addr, NULL};

    // Exec("tests/init", args_vec);

    // while (1) {
    //     TracePrintf(1, "CP4_TEST RUNNING! (should never be printed b/c exec)\n");
    //     Pause();
    // }
}

void test_exec_with_bad_prog() {
    int pid = Fork();
    if (pid == 0) {
        TracePrintf(1, "CP4_TEST_CHILD about to exec a nonsense file...\n");
        Pause();
        char *args_vec[] = {"hello", "world", NULL};
        Exec("tests/cp4_tests.c", args_vec);
    } else {
        TracePrintf(1, "CP4_TEST waiting on child to exit...\n");
        for (int i = 0; i < 5; i++) {
            Pause();
        }

        int status;
        int pid = Wait(&status);
        TracePrintf(1, "CP4_TEST received exit status %d from PID %d.\n", status, pid);
    }

    while (1) {
        TracePrintf(1, "CP4_TEST RUNNING!\n");
        Pause();
    }
}

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
    TracePrintf(1, "CP4_TEST RUNNING!\n");

    int test_case = atoi(argv[1]);
    switch (test_case) {
        case 1:
            test_fork();
            break;
        case 2:
            test_exec();
            break;
        case 3:
            test_exec_with_kernel_addr();
            break;
        case 4:
            test_exit();
            break;
        case 5:
            test_wait();
            break;
        case 6:
            test_exec_with_bad_prog();
            break;
        case 7:
            test_exec_with_args();
            break;
        case 8:
            test_exec_without_args();
            break;
        case 10:
            test_implicitly_grow_ustack();
            break;
        case 11:
            test_implicitly_grow_ustack_toomuch();
            break;
        default:
            while (1) {
                TracePrintf(1, "CP4_TEST RUNNING!\n");
                Pause();
            }
    }
}
