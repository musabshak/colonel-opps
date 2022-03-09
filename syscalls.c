#include <stdbool.h>

#include "k_common.h"
#include "load_program.h"
#include "printing.h"
#include "trap_handlers.h"
#include "ykernel.h"

// putting this in [k_common.h] caused issues

void kExit(int status);

/**
 * (From manual)
 *
 * Read the next line of input from terminal `tty_id`, copying it into the buffer
 * referenced by `buf`. The maximum length of the line to be returned is given by `len`.
 *
 * Note: The line returned in the buffer is not null-terminated.
 *
 * Return behavior:
 *  - If there are sufficient unread bytes already waiting, the call will return right away,
 *  with those.
 *  - Otherwise, the calling process is blocked until a line of input is available to be
 *  returned.
 *      - If the length of the next available input line is longer than `len` bytes, only the
 *      first `len` bytes of the line are copied to the calling process, and the remaining
 *      bytes of the line are saved by the kernel for the next `TtyRead()` (by this or another
 *      process).
 *      - If the length of the next available input line is shorter than len bytes, only as
 *      many bytes are copied to the calling process as are available in the input line; On
 *      success, the number of bytes actually copied into the calling process’s buffer is
 *      returned; in case of any error, the value ERROR is returned.
 */
