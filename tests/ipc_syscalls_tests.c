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
 * Tests passing invalid pointers to kPipeInit.
 */
void test_pipe_init3() {

    void *sneaky_kernel_addr = (void *)0x02ab60;
    void *null_ptr = NULL;

    int rc;

    TracePrintf(1, "Initializing pipes with invalid pointers\n");
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

    int rc, pipe_id, num_bytes_written, num_bytes_read;

    char *write_buf = "abcde";
    int len = 5;
    char read_buf[len + 1];
    read_buf[len] = '\0';

    TracePrintf(1, "Initializing a new pipe\n");

    rc = PipeInit(&pipe_id);
    if (rc != 0) {
        TracePrintf(1, "Error in `PipeInit` syscall\n");
    } else {
        TracePrintf(1, "Pipe %d initialized successfully!\n", pipe_id);
    }

    TracePrintf(1, "Writing some bytes to a new pipe. Bytes: %s\n", write_buf);

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
        TracePrintf(1, "Just read %d bytes from pipe %d. Bytes: %s\n", num_bytes_read, pipe_id, read_buf);
    }

    while (1) {
        TracePrintf(1, "PIPE TEST RUNNING\n");
        Pause();
    }
}

/**
 * (5)
 *
 * Tests basic pipe read/write functionality with two different processes.
 */
void test_pipe_read_write2() {

    int rc, pipe_id, num_bytes_written, num_bytes_read, fork_rc;

    char *write_buf = "abcdefghijklmnopqrstuvwxyz";
    int len = 26;
    char read_buf[len + 1];

    TracePrintf(1, "Initializing a new pipe\n");
    rc = PipeInit(&pipe_id);
    if (rc != 0) {
        TracePrintf(1, "Error in `PipeInit` syscall\n");
    } else {
        TracePrintf(1, "Pipe %d initialized successfully!\n", pipe_id);
    }

    TracePrintf(1, "Process %d writing some bytes to pipe %d. Bytes: %s\n", GetPid(), pipe_id, write_buf);

    num_bytes_written = PipeWrite(pipe_id, (void *)write_buf, len);
    if (num_bytes_written == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just wrote %d bytes into pipe %d\n", num_bytes_written, pipe_id);
    }

    fork_rc = Fork();

    if (fork_rc == 0) {
        TracePrintf(1, "Process %d reading some bytes from pipe %d\n", GetPid(), pipe_id);

        num_bytes_read = PipeRead(pipe_id, (void *)read_buf, len);
        if (num_bytes_read == -1) {
            TracePrintf(1, "PipeWrite syscall failed\n");
        } else {
            TracePrintf(1, "Just read %d bytes from pipe %d: %s\n", num_bytes_read, pipe_id, read_buf);
        }
        Exit(0);
    }

    while (1) {
        TracePrintf(1, "PIPE TEST RUNNING\n");
        Pause();
    }
}

/**
 * (6)
 *
 * Test writing to a pipe that is full.
 *
 * Also test pipe reuse (writing into a pipe that has been emptied from prior use). This
 * aims to tickle the circular queue implementation (but much more thorough edge case
 * testing is needed for circular queue operations).
 */
void test_pipe_read_write3() {

    int rc, pipe_id, num_bytes_written, num_bytes_read;
    int PIPE_BUFFER_LEN = 256;

    char write_buf[PIPE_BUFFER_LEN + 1];
    char read_buf[PIPE_BUFFER_LEN + 1];
    write_buf[PIPE_BUFFER_LEN] = '\0';
    read_buf[PIPE_BUFFER_LEN] = '\0';

    char *write_buf2 = "musab shakeel";
    char len2 = 13;
    char read_buf2[len2 + 1];

    char *tmp = write_buf;

    // Fill up write_buf completely
    for (int i = 0; i < PIPE_BUFFER_LEN; i++) {
        tmp += sprintf(tmp, "X");
    }

    TracePrintf(1, "write_buf: %s\n", write_buf);

    TracePrintf(1, "Initializing a new pipe\n");
    rc = PipeInit(&pipe_id);
    if (rc != 0) {
        TracePrintf(1, "Error in `PipeInit` syscall\n");
    } else {
        TracePrintf(1, "Pipe %d initialized successfully!\n", pipe_id);
    }

    TracePrintf(1, "Writing some bytes to a new pipe. Bytes: %s\n", write_buf);

    num_bytes_written = PipeWrite(pipe_id, (void *)write_buf, PIPE_BUFFER_LEN);
    if (num_bytes_written == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just wrote %d bytes into pipe %d\n", num_bytes_written, pipe_id);
    }

    TracePrintf(1, "Writing into full pipe\n");
    num_bytes_written = PipeWrite(pipe_id, (void *)"abc", 3);
    if (num_bytes_written == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just wrote %d bytes into pipe %d\n", num_bytes_written, pipe_id);
    }

    TracePrintf(1, "Reading some bytes from the same pipe\n");
    num_bytes_read = PipeRead(pipe_id, (void *)read_buf, PIPE_BUFFER_LEN);
    if (num_bytes_read == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just read %d bytes from pipe %d. Bytes: %s\n", num_bytes_read, pipe_id, read_buf);
    }

    TracePrintf(1, "Writing into newly emptied pipe. Bytes: %s\n", write_buf2);
    num_bytes_written = PipeWrite(pipe_id, (void *)write_buf2, len2);
    if (num_bytes_written == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just wrote %d bytes into pipe %d\n", num_bytes_written, pipe_id);
    }

    TracePrintf(1, "Reading some bytes from the same pipe\n");
    num_bytes_read = PipeRead(pipe_id, (void *)read_buf2, len2);
    if (num_bytes_read == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just read %d bytes from pipe %d. Bytes: %s\n", num_bytes_read, pipe_id, read_buf2);
    }

    while (1) {
        TracePrintf(1, "PIPE TEST RUNNING\n");
        Pause();
    }
}

/**
 * (7)
 *
 * Test that a processes waiting for bytes on an empty pipe get woken up after someone writes to that pipe.
 */
void test_pipe_read_write4() {
    int rc, pipe_id, num_bytes_written, num_bytes_read;

    char *write_buf = "abcdefghijklmno";
    int len = 15;
    char read_buf[len + 1];
    read_buf[len] = '\0';

    /**
     * Initialize pipe
     */
    TracePrintf(1, "Initializing a new pipe\n");
    rc = PipeInit(&pipe_id);
    if (rc != 0) {
        TracePrintf(1, "Error in `PipeInit` syscall\n");
    } else {
        TracePrintf(1, "Pipe %d initialized successfully!\n", pipe_id);
    }

    /**
     * Fork a child to try and read from empty pipe
     */
    int pid = Fork();
    if (pid == 0) {
        TracePrintf(1, "Process %d trying to read some bytes from an empty pipe\n", GetPid());
        num_bytes_read = PipeRead(pipe_id, (void *)read_buf, len);
        if (num_bytes_read == -1) {
            TracePrintf(1, "PipeWrite syscall failed\n");
        } else {
            TracePrintf(1, "Just read %d bytes from pipe %d. Bytes: %s\n", num_bytes_read, pipe_id, read_buf);
        }

        Exit(0);
    }

    // Delay parent for a bit so it is clear that the child process that is waiting for bytes on the pipe,
    // remains asleep
    Delay(10);

    TracePrintf(1, "Writing some bytes to a new pipe. Bytes: %s\n", write_buf);
    num_bytes_written = PipeWrite(pipe_id, (void *)write_buf, len);
    if (num_bytes_written == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just wrote %d bytes into pipe %d\n", num_bytes_written, pipe_id);
    }

    while (1) {
        TracePrintf(1, "PIPE TEST RUNNING\n");
        Pause();
    }
}

/**
 * (8)
 *
 * Test that multiple processes waiting for bytes on an empty pipe get woken up after someone writes to that
 * pipe.
 */
void test_pipe_read_write5() {
    int rc, pipe_id, num_bytes_written, num_bytes_read;

    char *write_buf = "abcdefghijklmnopqrstuvwxyz";
    int len = 26;
    char read_buf[len + 1];
    memset(read_buf, 0, len + 1);
    int num_bytes_to_read = 10;
    int orig_pid = GetPid();

    /**
     * Initialize pipe
     */
    TracePrintf(1, "Initializing a new pipe\n");
    rc = PipeInit(&pipe_id);
    if (rc != 0) {
        TracePrintf(1, "Error in `PipeInit` syscall\n");
    } else {
        TracePrintf(1, "Pipe %d initialized successfully!\n", pipe_id);
    }

    /**
     * Fork multiple children to try and read from empty pipe
     */
    for (int i = 0; i < 4; i++) {
        Fork();
    }

    if (GetPid() != orig_pid) {

        TracePrintf(1, "Process %d trying to read some bytes from an empty pipe\n", GetPid());
        num_bytes_read = PipeRead(pipe_id, (void *)read_buf, num_bytes_to_read);
        if (num_bytes_read == -1) {
            TracePrintf(1, "PipeWrite syscall failed\n");
        } else {
            TracePrintf(1, "Process %d just read %d bytes from pipe %d. Bytes: %s\n", GetPid(),
                        num_bytes_read, pipe_id, read_buf);
        }

        Exit(0);
    }

    // Delay parent for a bit so it is clear that the child process that is waiting for bytes on the pipe,
    // remains asleep
    Delay(3);

    TracePrintf(1, "Writing some bytes to a new pipe. Bytes: %s\n", write_buf);
    num_bytes_written = PipeWrite(pipe_id, (void *)write_buf, len);
    if (num_bytes_written == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just wrote %d bytes into pipe %d\n", num_bytes_written, pipe_id);
    }

    // Delay a little more before writing more bytes to pipe
    Delay(3);

    TracePrintf(1, "Writing some bytes to a new pipe. Bytes: %s\n", write_buf);
    num_bytes_written = PipeWrite(pipe_id, (void *)write_buf, len);
    if (num_bytes_written == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just wrote %d bytes into pipe %d\n", num_bytes_written, pipe_id);
    }

    while (1) {
        TracePrintf(1, "PIPE TEST RUNNING\n");
        Pause();
    }
}

/**
 * (9)
 *
 * Test that circular array wrap-around happens properly.
 */
void test_pipe_read_write6() {

    int rc, pipe_id, num_bytes_written, num_bytes_read;
    int PIPE_BUFFER_LEN = 256;

    char write_buf[PIPE_BUFFER_LEN + 1];
    char read_buf[PIPE_BUFFER_LEN + 1];
    write_buf[PIPE_BUFFER_LEN] = '\0';
    read_buf[PIPE_BUFFER_LEN] = '\0';

    char *write_buf2 = "so many edge cases to test gah";
    char len2 = strlen(write_buf2);
    char read_buf2[len2 + 10];

    char *tmp = write_buf;

    // Fill up write_buf completely
    for (int i = 0; i < PIPE_BUFFER_LEN - 3; i++) {
        tmp += sprintf(tmp, "X");
    }

    TracePrintf(1, "write_buf: %s\n", write_buf);

    TracePrintf(1, "Initializing a new pipe\n");
    rc = PipeInit(&pipe_id);
    if (rc != 0) {
        TracePrintf(1, "Error in `PipeInit` syscall\n");
    } else {
        TracePrintf(1, "Pipe %d initialized successfully!\n", pipe_id);
    }

    TracePrintf(1, "Writing some bytes to a new pipe. Bytes: %s\n", write_buf);
    num_bytes_written = PipeWrite(pipe_id, (void *)write_buf, PIPE_BUFFER_LEN - 3);
    if (num_bytes_written == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just wrote %d bytes into pipe %d\n", num_bytes_written, pipe_id);
    }

    TracePrintf(1, "Reading some bytes from the same pipe\n");
    num_bytes_read = PipeRead(pipe_id, (void *)read_buf, PIPE_BUFFER_LEN - 6);
    if (num_bytes_read == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just read %d bytes from pipe %d. Bytes: %s\n", num_bytes_read, pipe_id, read_buf);
    }

    TracePrintf(1, "Writing into pipe again. Bytes: %s\n", write_buf2);
    num_bytes_written = PipeWrite(pipe_id, (void *)write_buf2, len2);
    if (num_bytes_written == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just wrote %d bytes into pipe %d\n", num_bytes_written, pipe_id);
    }

    TracePrintf(1, "Reading some bytes from the same pipe\n");
    num_bytes_read = PipeRead(pipe_id, (void *)read_buf2, len2 + 3);
    if (num_bytes_read == -1) {
        TracePrintf(1, "PipeWrite syscall failed\n");
    } else {
        TracePrintf(1, "Just read %d bytes from pipe %d. Bytes: %s\n", num_bytes_read, pipe_id, read_buf2);
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
        case 5:
            test_pipe_read_write2();
            break;
        case 6:
            test_pipe_read_write3();
            break;
        case 7:
            test_pipe_read_write4();
            break;
        case 8:
            test_pipe_read_write5();
            break;
        case 9:
            test_pipe_read_write6();
            break;
        default:

            while (1) {
                TracePrintf(1, "%s RUNNING!\n", argv[0]);
                Pause();
            }
    }
}
