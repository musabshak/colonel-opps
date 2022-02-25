
#ifndef __PRINTING_H
#define __PRINTING_H

#include <yuser.h>

/**
 * Traceprints an error message. By our convention, this occurs at kernel trace
 * level 1.
 *
 * The purpose of this macro is to make the error message format consistent.
 */
#define TP_ERROR(format, args...)                                \
    do {                                                         \
        TracePrintf(1, "ERROR (%s): " format, __func__, ##args); \
    } while (0)

#endif  // __PRINTING_H
