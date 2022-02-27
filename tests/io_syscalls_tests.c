/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/26/2022
 */

#include <yuser.h>

int main(int argc, char **argv) {

    if (argc < 2) {
        TracePrintf(1, "Need to specify an option argument\n");
        Exit(-1);
    }

    int test_case = atoi(argv[1]);

    switch (test_case) {
        case 1:
            break;
        case 2:
            break;
        default:

            while (1) {
                TracePrintf(2, "%s RUNNING!\n", argv[0]);
                Pause();
            }
    }
}
