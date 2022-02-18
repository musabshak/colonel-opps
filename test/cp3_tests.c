
#include <yuser.h>

int main(void) {
    // Test Brk

    // Test GetPid
    // TracePrintf(1, "My PID is %d.\n", GetPid());

    //     // Test Delay
    // TracePrintf(1, "Delaying 0...\n");
    // Delay(0);
    // TracePrintf(1, "Delaying 5...\n");
    // Delay(5);

    // while (1) {
    //     TracePrintf(1, "TEST 1 RUNNING!\n");
    //     TracePrintf(1, "My PID is %d.\n", GetPid());
    //     Pause();
    // }

    // Testing Brk

    TracePrintf(1, "TEST 1 RUNNING!\n");

    TracePrintf(1, "Getting process pid\n");
    int pid = GetPid();
    TracePrintf(1, "My pid is: %d\n", pid);

    TracePrintf(1, "Calling malloc!\n");
    void* myp = malloc(100000);

    TracePrintf(1, "Delaying for 10 clock ticks!\n");
    Delay(10);

    TracePrintf(1, "TEST 1 DONE!\n");
}
