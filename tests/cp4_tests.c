/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/16/2022
 *
 * Some userland test code for yalnix checkpoint 3 syscalls (getPid, Brk, Delay).
 */

#include <yuser.h>

int main(int argc, char **argv)
{
    // TracePrintf(1, "About to fork:\n");
    // int pid = Fork();
    // if (pid == 0)
    // {
    //     while (1)
    //     {
    //         TracePrintf(1, "This is the child.\n");
    //         Pause();
    //     }
    // }
    // else
    // {
    //     while (1)
    //     {
    //         TracePrintf(1, "This is the parent... `Fork()` returned %d.\n", pid);
    //         Pause();
    //     }
    // }

    TracePrintf(1, "About to exec:\n");
    char **args_vec = (char *[]){"hello", "world"};
    args_vec[1] = NULL;
    Exec("tests/init", args_vec);

    while (1)
    {
        TracePrintf(1, "INIT RUNNING!\n");
    }
}

// int main(int argc, char **argv) {

//     TracePrintf(1, "About to exec:\n");
//     char *args_vec[] = {"my_arg1", "my_arg2", NULL};

//     Exec("tests/init", args_vec);

//     while (1) {
//         TracePrintf(1, "CP4_TESTS RUNNING! (should never be printed b/c exec\n");
//         Pause();
//     }
// }
