
#include <yuser.h>

int main() {
    // Test Brk

    // Test Delay
    TracePrintf(1, "Delaying 0...\n");
    Delay(0);
    TracePrintf(1, "Delaying 5...\n");
    Delay(5);

    // Test GetPid
    TracePrintf(1, "My PID is %d.\n", GetPid());
}
