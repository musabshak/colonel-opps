/**
 * Authors: Musab Shakeel and Varun Malladi
 * Date: 2/26/2022
 */

#include <yuser.h>

#define g_max_pipes 50

/**
 * (1)
 *
 * Test creating a pipe.
 */
void test_pipe_init() {
    TracePrintf(1, "Initializing a new pipe\n");
    int rc, pipe_id;

    rc = PipeInit(&pipe_id);
    if (rc != 0) {
        TracePrintf(1, "Error in `PipeInit` syscall\n");
    } else {
        TracePrintf(1, "Pipe %d initialized successfully!\n", pipe_id);
    }

    while (1) {
        TracePrintf(1, "PIPE TEST RUNNING\n");
        Pause();
    }
}

/**
 * (2)
 *
 * Tests creating > maximum number of pipes allowed by the OS.
 */
void test_pipe_init2() {
    TracePrintf(1, "Initializing a multitude of new pipes\n");
    int pipe_ids[g_max_pipes + 5];
    int rc;

    for (int i = 0; i < g_max_pipes + 5; i++) {
        rc = PipeInit(&pipe_ids[i]);
        if (rc != 0) {
            TracePrintf(1, "Error in `PipeInit` syscall\n");
        } else {
            TracePrintf(1, "Pipe %d initialized successfully!\n", pipe_ids[i]);
        }
    }

    while (1) {
        TracePrintf(1, "PIPE TEST RUNNING\n");
        Pause();
    }
}

/**
 * (3)
 *
 * Test passing invalid pointers to kPipeInit.
 */
void test_pipe_init3() {
    TracePrintf(1, "Initializing pipes with invalid pointers\n");

    void *sneaky_kernel_addr = (void *)0x02ab60;
    void *null_ptr = NULL;

    int rc;

    rc = PipeInit((int *)sneaky_kernel_addr);
    if (rc != 0) {
        TracePrintf(1, "Error in `PipeInit` syscall\n");
    } else {
        TracePrintf(1, "Pipe initialized successfully! (should never be printed)\n");
    }

    rc = PipeInit((int *)null_ptr);
    if (rc != 0) {
        TracePrintf(1, "Error in `PipeInit` syscall\n");
    } else {
        TracePrintf(1, "Pipe initialized successfully! (should never be printed)\n");
    }

    while (1) {
        TracePrintf(1, "PIPE TEST RUNNING\n");
        Pause();
    }
}

/**
 * (4)
 *
 * Tests basic pipe read/write functionality.
 */
void test_pipe_read_write() {

    TracePrintf(1, "Initializing a new pipe\n");
    int rc, pipe_id, num_bytes_written, num_bytes_read;

    char *write_buf = "abcde";
    int len = 5;
    char read_buf[len];

    rc = PipeInit(&pipe_id);
    if (rc != 0) {
        TracePrintf(1, "Error in `PipeInit` syscall\n");
    } else {
        TracePrintf(1, "Pipe %d initialized successfully!\n", pipe_id);
    }

    TracePrintf(1, "Writing some bytes to a new pipe\n");

    num_bytes_written = PipeWrite(pipe_id, (void *)write_buf, len);
    if (num_bytes_written == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just wrote %d bytes into pipe %d\n", num_bytes_written, pipe_id);
    }

    TracePrintf(1, "Reading some bytes from the same pipe\n");

    num_bytes_read = PipeRead(pipe_id, (void *)read_buf, len);
    if (num_bytes_read == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just read %d bytes from pipe %d\n", num_bytes_read, pipe_id);
    }

    while (1) {
        TracePrintf(1, "PIPE TEST RUNNING\n");
        Pause();
    }
}

int main(int argc, char **argv) {

    if (argc < 2) {
        TracePrintf(1, "Need to specify an option argument\n");
        Exit(-1);
    }

    int test_case = atoi(argv[1]);

    switch (test_case) {
        case 1:
            test_pipe_init();
            break;
        case 2:
            test_pipe_init2();
            break;
        case 3:
            test_pipe_init3();
            break;
        case 4:
            test_pipe_read_write();
            break;
        default:

            while (1) {
                TracePrintf(1, "%s RUNNING!\n", argv[0]);
                Pause();
            }
    }
}
