
#include <yuser.h>

int main() {
    TracePrintf(1, "TERMINAL_TESTS RUNNING!\n");

    TtyPrintf(0, "Hello world!\n");

    while (1) {
        TracePrintf(1, "TERMINAL_TESTS RUNNING!\n");
        Pause();
    }
}
