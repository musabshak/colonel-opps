#include "yuser.h"

// char big[100000];

int main(int argc, char *argv[]) {

    TracePrintf(1, "Printing arguments given to init\n");

    for (int i = 0; i < argc; i++) {
        TracePrintf(1, "argument%d: %s\n", i, argv[i]);
    }

    while (1) {
        TracePrintf(1, "INIT RUNNING!\n");
        Pause();
    }

    return 0;
}