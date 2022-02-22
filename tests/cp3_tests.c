/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/16/2022
 *
 * Some userland test code for yalnix checkpoint 3 syscalls (getPid, Brk, Delay).
 */

#include <yuser.h>

int main(int argc, char** argv) {

    int clock_ticks = 4;
    TracePrintf(1, "TEST PROG RUNNING!\n");
    TracePrintf(1, "Getting process pid\n");
    int pid = GetPid();
    TracePrintf(1, "My pid is: %d\n", pid);

    TracePrintf(1, "TEST PROG RUNNING!\n");
    TracePrintf(1, "Calling malloc!\n");
    void* myp = malloc(100000);
    TracePrintf(1, "Calling malloc with too many bytes:\n");
    void* too_many = malloc(2147483646);  // 1 less than max possible value of int

    TracePrintf(1, "TEST PROG RUNNING!\n");
    TracePrintf(1, "Delaying for %d clock ticks!\n", clock_ticks);
    Delay(clock_ticks);
    TracePrintf(1, "TEST PROG FINISHED RUNNING\n");

    while (1) {
        TracePrintf(1, "TEST PROG RUNNING!\n");
        Pause();
        break;
    }

    TracePrintf(1, "About to exec:\n");
    char **args_vec = (char *[]){"hello", "world"};
    args_vec[1] = NULL;
    Exec("tests/init", args_vec);

    while (1) {
        TracePrintf(1, "INIT RUNNING!\n");
        Pause();
    }
}
