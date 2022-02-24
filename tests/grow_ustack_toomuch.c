
#include <yuser.h>

int main() {
    for (int i = 0; i < 5; i++) {
        TracePrintf(2, "GROW_USTACK RUNNING!\n");
        Pause();
    }

    TracePrintf(2, "GROW_USTACK implictly growing user stack by too much...\n");

    int on_stack_2[1000000];
    for (int i = 0; i < 1000000; i++) {
        on_stack_2[i] = 0;
    }

    while (1) {
        TracePrintf(2, "GROW_USTACK  RUNNING!\n");
        Pause();
    }
}
