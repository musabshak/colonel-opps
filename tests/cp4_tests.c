/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/16/2022
 *
 * Some userland test code for yalnix checkpoint 3 syscalls (getPid, Brk, Delay).
 */

#include <yuser.h>

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

void test_exec() {
    TracePrintf(1, "About to exec:\n");
    char *args_vec[] = {"hello", "world", NULL};

    Exec("tests/init", args_vec);

    while (1) {
        TracePrintf(1, "CP4_TEST RUNNING! (should never be printed b/c exec)\n");
    }
}

void test_exec_with_kernel_addr() {
    TracePrintf(1, "About to exec with a kernel address:\n");

    char *sneaky_kernel_addr = (char *)(0x02ab60);
    char **args_vec = {sneaky_kernel_addr, NULL};

    Exec("tests/init", args_vec);

    while (1) {
        TracePrintf(1, "CP4_TEST RUNNING! (should never be printed b/c exec)\n");
        Pause();
    }
}

int main(int argc, char **argv) {
    TracePrintf(1, "CP4_TEST RUNNING!\n");

    int test_case = atoi(argv[1]);
    switch (test_case) {
        case 1:
            test_fork();
        case 2:
            test_exec();
        case 3:
            test_exec_with_kernel_addr();
        default:
            while (1) {
                TracePrintf(1, "CP4_TEST RUNNING!\n");
                Pause();
            }
    }
}