/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/16/2022
 *
 * Some userland test code for yalnix checkpoint 3 syscalls (getPid, Brk, Delay).
 */

#include <yuser.h>

int main(void) {

    int clock_ticks = 2;
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
    }
}
