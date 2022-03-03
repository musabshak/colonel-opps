/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/25/2022
 *
 * Some userland test code for yalnix syscalls.
 */

#include <yuser.h>

/**
 * Round-robin scheduler test (12).
 *
 * This tests the round robin scheduler. This test assumes that the Fork() syscall and the
 * GetPid() syscall are working correctly.
 *
 * A total of 8 processes are created.
 *
 * Expected behavior in the TRACE:
 *  - Process 2, 3, 4, ..., 8 should run a total of num_times times
 *  - Process 0, 2, 3, ..., 8 should switch after each clock trap (the order may not be sequential becuase
 *    time of creation of processes may be different).
 *  - After the other processes terminate, the init process (pid = 0) will continue to run, switching with
 * idle on each clock trap.
 *
 */
void test_scheduler() {

    for (int i = 0; i < 3; i++) {
        Fork();
    }

    int pid = GetPid();
    int num_times = 3;

    // init process should continue to run
    if (pid == 0) {
        while (1) {
            TracePrintf(1, "PROCESS %d RUNNING\n", pid);
            Pause();
        }
    }

    int j = 0;
    // other processes should run a total of num_times times
    while (j < num_times) {
        pid = GetPid();
        TracePrintf(1, "PROCESS %d RUNNING\n", pid);
        Pause();
        j += 1;
    }
}

/**
 * This tests basic fork functionality.
 *
 * Forks, parent loops, child forks again, and the child and the child's child both loop. A total
 * of 3 processes are created (parent, child, child's child).
 *
 */
void test_fork() {
    int pid, pid2;
    TracePrintf(1, "About to fork:\n");
    pid = Fork();
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
            TracePrintf(1, "This is the parent... `Fork()` returned child's pid: %d.\n", pid);
            Pause();
        }
    }
}

/**
 * (2)
 *
 * Tries to load a program normally.
 *
 */
void test_exec() {
    TracePrintf(1, "About to exec init process (that prints INIT RUNNING):\n");
    char *args_vec[] = {"hello", "world", NULL};

    Exec("tests/init", args_vec);

    while (1) {
        TracePrintf(1, "CP4 TEST RUNNING! (should never be printed b/c exec)\n");
    }
}

/**
 * (7)
 * Try calling `Exec()` with some arguments.
 */
void test_exec_with_args() {
    TracePrintf(1, "About to `Exec()` with arguments...\n");

    char *args_vec[] = {"hello", "world", NULL};
    Exec("tests/exec_test", args_vec);
}

/**
 * (8)
 */
void test_exec_without_args() {
    int pid = Fork();
    if (pid == 0) {
        for (int i = 0; i < 5; i++) {
            TracePrintf(1, "CP4_CHILD RUNNING!\n");
            Pause();
        }

        TracePrintf(1, "About to `Exec()` without arguments...\n");

        char **args_vec = NULL;
        int rc = Exec("tests/exec_test", args_vec);

        TracePrintf(1, "Exec failed!\n");
        Exit(rc);
    } else {
        TracePrintf(1, "CP4_TEST RUNNING!\n");
        TracePrintf(1, "Waiting on child...\n");

        int status;
        int pid = Wait(&status);
        TracePrintf(1, "Finished waiting, received exit status %d from PID %d.\n", status, pid);

        while (1) {
            TracePrintf(1, "CP4_TEST RUNNING!\n");
            Pause();
        }
    }
}

/**
 * (3)
 */
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

/**
 * (6)
 */
void test_exec_with_bad_prog() {
    int pid = Fork();
    if (pid == 0) {
        TracePrintf(1, "CP4_TEST_CHILD about to exec a nonsense file...\n");
        Pause();
        char *args_vec[] = {"hello", "world", NULL};
        Exec("tests/cp4_tests.c", args_vec);
    } else {
        TracePrintf(1, "CP4_TEST looping, waiting (not syscall) on child to exit...\n");
        for (int i = 0; i < 5; i++) {
            TracePrintf(1, "CP4_TEST RUNNING\n");
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

/**
 * kExit() test (4).
 *
 * Forks a child process and runs it for 3 loops, after which the child exits.
 */
void test_exit() {
    int pid = Fork();
    if (pid == 0) {
        for (int i = 0; i < 3; i++) {
            TracePrintf(1, "CHILD RUNNING!\n");
            Pause();
        }
        TracePrintf(1, "child about to exit ...\n");
        Exit(0);
    } else {
        while (1) {
            TracePrintf(1, "PARENT RUNNING!\n");
            Pause();
        }
    }
}

/**
 *  kExit() test (16).
 *
 *  Tests the case where the init process exits (the CPU should halted).
 */
void test_exit_2() { Exit(-1); }

/**
 * kWait() test (5).
 *
 * This tests basic kWait() functionality.
 *      - Tests the case where the parent is put into the g_wait_blocked_procs queue (parent is blocked
 *         waiting for a child to finish).
 *      - Since the parent code calls Wait immediately, the child will not be in the zombie queue so this
 *         test does not cover the zombie functionality.
 *
 * Assumes Exit() has been tested and is working correctly.
 *
 * A child is forked, which runs for 5 clock traps and then exits successfully.
 * Meanwhile, the parent waits for the child to exit, after which it starts running in a
 * while loop.
 *
 * Also partly checks the following Exit() functionality:
 *  - A process exits with the given exit code (because in this test, Wait() collects
 *    the exit code of the exiting child process)
 */
void test_wait() {
    int pid = Fork();
    int predetermined_exit_status = 454;
    if (pid == 0) {
        for (int i = 0; i < 5; i++) {
            TracePrintf(1, "CHILD RUNNING! (pid: %d)\n", GetPid());
            Pause();
        }
        TracePrintf(1, "child about to exit ...\n");
        Exit(predetermined_exit_status);
    } else {
        TracePrintf(1, "parent waiting on child ....\n");
        int exit_status;
        int exit_pid = Wait(&exit_status);

        TracePrintf(1, "parent received exit status %d from PID %d (should have received %d)\n", exit_status,
                    exit_pid, predetermined_exit_status);

        while (1) {
            TracePrintf(1, "PARENT RUNNING!\n");
            Pause();
        }
    }
}

/**
 * kWait() test (13)
 *
 * This tests the case where Wait() is called with an invalid pointer.
 * Should expect to see a Traceprint saying that kWait will not write into the provided pointer.
 *
 *
 */
void test_wait_2() {

    void *invalid_ptr = NULL;

    int pid = Fork();
    int predetermined_exit_status = 454;

    if (pid == 0) {
        for (int i = 0; i < 5; i++) {
            TracePrintf(1, "CHILD RUNNING! (pid: %d)\n", GetPid());
            Pause();
        }
        TracePrintf(1, "child about to exit ...\n");
        Exit(predetermined_exit_status);
    }

    else {
        TracePrintf(1, "parent waiting on child ....\n");
        int exit_pid = Wait(invalid_ptr);

        TracePrintf(1, "parent received exit status - from PID %d\n", exit_pid);

        while (1) {
            TracePrintf(1, "PARENT RUNNING!\n");
            Pause();
        }
    }
}

/**
 * kWait() test (14).
 *
 * Tests the case where kWait() is called but the process does not have any child processes (running or
 * zombies).
 *
 * Expected behavior
 *      - Wait returns immediately with ERROR (-1)
 */

void test_wait_3() {

    int j = 0;
    while (j < 5) {
        TracePrintf(1, "PARENT RUNNING (will call Wait in a bit)\n");
        Pause();
        j += 1;
    }

    int exit_status, pid;

    TracePrintf(1, "parent waiting on child ....\n");
    pid = Wait(&exit_status);
    TracePrintf(1,
                "Wait returned PID: %d (should be -1 for ERROR since parent did not have any children when "
                "Wait was called)\n ",
                pid);

    while (1) {
        TracePrintf(1, "PARENT RUNNING!\n");
        Pause();
    }
}

/**
 * kWait() test (15).
 *
 * Tests the case where kWait() is called after sleeping for a little bit such that the children have had
 * time to get on the Zombie queue.
 *
 * Does this with two children on the zombie queue (both of parent's calls to Wait should return
 * immediately).
 */

void test_wait_4() {

    int exit_status, pid, j;
    int predetermined_exit_status1 = -10;
    int predetermined_exit_status2 = 42;

    pid = Fork();

    if (pid == 0) {  // child 1
        TracePrintf(1, "child (pid: %d) exiting with status code %d. Should go into zombie queue.\n",
                    GetPid(), predetermined_exit_status1);
        Exit(predetermined_exit_status1);
    }

    pid = Fork();

    if (pid == 0) {
        TracePrintf(1, "child (pid: %d) exiting with status code %d. Should go into zombie queue.\n",
                    GetPid(), predetermined_exit_status2);
        Exit(predetermined_exit_status2);
    }

    j = 0;
    while (j < 4) {
        TracePrintf(1, "PARENT RUNNING (will call Wait in a bit)\n");
        Pause();
        j += 1;
    }

    TracePrintf(1, "parent waiting on child ....\n");
    pid = Wait(&exit_status);
    TracePrintf(1,
                "parent received exit status %d from PID: %d (should return immediately; exit status should "
                "be %d)\n ",
                exit_status, pid, predetermined_exit_status1);

    j = 0;
    while (j < 4) {
        TracePrintf(1, "PARENT RUNNING (will call Wait in a bit)\n");
        Pause();
        j += 1;
    }

    TracePrintf(1, "parent waiting on child ....\n");
    pid = Wait(&exit_status);
    TracePrintf(1,
                "parent received exit status %d from PID: %d (should return immediately; exit status should "
                "be %d)\n ",
                exit_status, pid, predetermined_exit_status2);

    while (1) {
        TracePrintf(1, "PARENT RUNNING!\n");
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
        case 12:
            test_scheduler();
            break;
        case 13:
            test_wait_2();
            break;
        case 14:
            test_wait_3();
            break;
        case 15:
            test_wait_4();
            break;
        case 16:
            test_exit_2();
        case 18:
            test_terminal();
            break;
        default:
            while (1) {
                TracePrintf(2, "CP4 TEST RUNNING!\n");
                Pause();
            }
    }
}
