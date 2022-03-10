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
    TracePrintf(1, "rc: %d\n\n", rc);

    TracePrintf(1, "Calling Reclaim() on an already reclaimed pipe\n");
    rc = Reclaim(pipe_id);
    TracePrintf(1, "rc: %d\n\n", rc);

    TracePrintf(1, "Calling Reclaim() on a lock\n");
    rc = Reclaim(lock_id);
    TracePrintf(1, "rc: %d\n\n", rc);

    TracePrintf(1, "Calling Reclaim() on an already reclaimed lock\n");
    rc = Reclaim(lock_id);
    TracePrintf(1, "rc: %d\n\n", rc);

    TracePrintf(1, "Calling Reclaim() on a cvar\n");
    rc = Reclaim(cvar_id);
    TracePrintf(1, "rc: %d\n\n", rc);

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
 *  - Calling reclaim on a locked lock
 *  - Calling reclaim on a pipe/lock/cvar that have associated blocked processes
 *
 */
void test_reclaim2() {
    int pipe_id, lock_id, cvar_id, rc;
    int buf_len = 50;
    char read_buf[buf_len];

    PipeInit(&pipe_id);
    LockInit(&lock_id);
    CvarInit(&cvar_id);

    TracePrintf(1, "Acquiring lock\n");
    rc = Acquire(lock_id);
    TracePrintf(1, "rc: %d\n\n", rc);

    TracePrintf(1, "Reclaiming a locked lock\n");
    rc = Reclaim(lock_id);
    TracePrintf(1, "rc: %d\n\n", rc);

    int pid = Fork();
    if (pid == 0) {
        PipeRead(pipe_id, (void *)read_buf, buf_len);
        Exit(0);
    }

    /**
     * Test reclaiming pipe w/ blocked processes.
     */
    Delay(3);  // make sure child process reads
    TracePrintf(1, "Reclaiming a pipe with associated blocked procs\n");
    rc = Reclaim(pipe_id);
    TracePrintf(1, "rc: %d\n\n", rc);

    /**
     * Test reclaiming lock w/ blocked procceses.
     */
    pid = Fork();
    if (pid == 0) {
        int i = 0;
        while (i < 2) {
            Fork();
            i += 1;
        }
        Acquire(lock_id);
        Exit(0);
    }
    Delay(3);

    Release(lock_id);

    TracePrintf(1, "Reclaiming a lock with associated blocked procs\n");
    rc = Reclaim(lock_id);
    TracePrintf(1, "rc: %d\n\n", rc);

    /**
     * Test reclaiming cvar w/ blocked processes.
     */
    pid = Fork();
    if (pid == 0) {
        CvarWait(cvar_id, lock_id);
    }

    Delay(2);

    TracePrintf(1, "Reclaiming a cvar with associated blocked procs\n");
    rc = Reclaim(cvar_id);
    TracePrintf(1, "rc: %d\n\n", rc);
}

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
