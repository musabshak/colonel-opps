/**
 * Authors: Musab Shakeel
 * Date: 3/2/2022
 */

#include <yuser.h>
#define g_max_locks 50

/**
 * (1)
 *
 * Test
 *  - Calling reclaim on a pipe/lock/cvar
 *  - Calling reclaim on a pipe/lock/cvar that has been reclaimed already
 *  - Calling reclaim on an invalid id
 */
void test_reclaim1() {
    int pipe_id, lock_id, cvar_id, rc;
    PipeInit(&pipe_id);
    LockInit(&lock_id);
    CvarInit(&cvar_id);

    TracePrintf(1, "Calling Reclaim() on a pipe\n");
    rc = Reclaim(pipe_id);
    TracePrintf(1, "rc: %d\n", rc);

    TracePrintf(1, "Calling Reclaim() on an already reclaimed pipe\n");
    rc = Reclaim(pipe_id);
    TracePrintf(1, "rc: %d\n\n", rc);

    TracePrintf(1, "Calling Reclaim() on a lock\n");
    rc = Reclaim(lock_id);
    TracePrintf(1, "rc: %d\n", rc);

    TracePrintf(1, "Calling Reclaim() on an already reclaimed lock\n");
    rc = Reclaim(lock_id);
    TracePrintf(1, "rc: %d\n\n", rc);

    TracePrintf(1, "Calling Reclaim() on a cvar\n");
    rc = Reclaim(cvar_id);
    TracePrintf(1, "rc: %d\n", rc);

    TracePrintf(1, "Calling Reclaim() on an already reclaimed cvar\n");
    rc = Reclaim(cvar_id);
    TracePrintf(1, "rc: %d\n\n", rc);

    TracePrintf(1, "Calling Reclaim() on an invalid id\n");
    rc = Reclaim(2);
    TracePrintf(1, "rc: %d\n\n", rc);
}

/**
 * (2)
 *
 * Test
 *  - Calling reclaim on a pipe/lock/cvar that have associated blocked processes
 *  - calling reclaim on a locked lock
 */
void test_reclaim2() {}

int main(int argc, char **argv) {

    if (argc < 2) {
        TracePrintf(1, "Need to specify an option argument\n");
        Exit(-1);
    }

    int test_case = atoi(argv[1]);

    switch (test_case) {
        case 1:
            test_reclaim1();
            break;
        case 2:
            test_reclaim2();
            break;
        default:
            while (1) {
                TracePrintf(1, "%s RUNNING!\n", argv[0]);
                Pause();
            }
    }
}
