
#include <yuser.h>

int main(int argc, char **argv) {
    if (argc == 0) {
        TracePrintf(1, "exec_test received 0 arguments.\n");
    } else {
        for (int i = 0; i < argc; i++) {
            TracePrintf(1, "exec_test received argument `%s`\n", argv[i]);
        }
    }

    while (1) {
        TracePrintf(1, "EXEC_TEST RUNNING!\n");
        Pause();
    }
}
