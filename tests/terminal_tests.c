
#include <yuser.h>

/**
 * Prints "hello world" to each of the valid terminals
 */
void print_hello_world() {
    TracePrintf(1, "TEST START: hello world\n");
    Pause();

    for (int i = 0; i < 4; i++) {
        TtyPrintf(i, "Hello, World!");
    }

    TracePrintf(1, "TEST END: hello world\n");
}

/**
 * Try printing more than `TERMINAL_MAX_LINE` (1024) bytes.
 */
void print_more_than_tmaxline() {
    TracePrintf(1, "TEST START: printing more than terminal max line\n");
    Pause();

    int max_term_len = 1024;
    int chars_in_maxterm = max_term_len / sizeof(char);
    int str_len = max_term_len * 3 / sizeof(char) + 1;
    char *long_str = malloc(sizeof(char) * str_len);
    if (long_str == NULL) {
        TracePrintf(1, "TEST FAILED: printing more than terminal max line\n");
        return;
    }

    // The first 1024 bytes will be 'a', the next 1024 bytes will be 'b', then 'c'
    for (int i = 0; i < str_len; i++) {
        if (i == str_len - 1) {
            long_str[i] = '\0';
        } else if (i / chars_in_maxterm == 0) {
            long_str[i] = 'a';
        } else if (i / chars_in_maxterm == 1) {
            long_str[i] = 'b';
        } else if (i / chars_in_maxterm == 2) {
            long_str[i] = 'c';
        }
    }

    TtyPrintf(0, "%s", long_str);

    TracePrintf(1, "TEST END: printing more than terminal max line\n");
}

/**
 * Read a reasonable amount from the terminal (0) and print it to terminal (1)
 */
void read_reasonable() {
    TracePrintf(1, "TEST START: read reasonable amount from terminal\n");
    Pause();

    int len_to_read = 500;
    void *buf = malloc(len_to_read);
    int bytes_read = TtyRead(0, buf, len_to_read);

    int str_len = bytes_read / sizeof(char);
    char *str = (char *)buf;
    str[str_len] = '\0';

    TtyPrintf(1, "%s", str);

    TracePrintf(1, "TEST END: read reasonable amount from terminal\n");
}

void multiple_procs_write_to_same_terminal() {
    int pid0 = Fork();
    if (pid0 == 0) {
        int pid1 = Fork();
        if (pid1 == 0) {
            print_more_than_tmaxline();
            Exit(0);
        }

        print_more_than_tmaxline();
        Exit(0);
    }

    print_more_than_tmaxline();

    while (1) {
        TracePrintf(1, "TERMINAL_TESTS RUNNING!\n");
        Pause();
    }
}

int main() {
    TracePrintf(1, "TERMINAL_TESTS RUNNING!\n");

    // print_hello_world();
    // print_more_than_tmaxline();
    // read_reasonable();
    multiple_procs_write_to_same_terminal();

    while (1) {
        TracePrintf(1, "TERMINAL_TESTS RUNNING!\n");
        Pause();
    }
}
