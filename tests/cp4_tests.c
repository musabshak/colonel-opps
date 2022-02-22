/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/16/2022
 *
 * Some userland test code for yalnix checkpoint 3 syscalls (getPid, Brk, Delay).
 */

#include <yuser.h>

int main(int argc, char **argv) {

    TracePrintf(1, "About to exec:\n");
    char *args_vec[] = {"my_arg1", "my_arg2", NULL};

    Exec("tests/init", args_vec);

    while (1) {
        TracePrintf(1, "CP4_TESTS RUNNING! (should never be printed b/c exec\n");
        Pause();
    }
}
