#ifndef __MEM_MANAGEMENT_H
#define __MEM_MANAGEMENT_H

#include "queue.h"

typedef queue_t m_builder_t;

/**
 * The kind of thing you want to `malloc`. Each kind has a suffix of either "Temp" or
 * "Perm". This indicates how these should be handled in the case of a graceful
 * closure of the malloc builder, e.g. with `m_builder_conclude()`. In that case,
 * we successfully did everything and want to clean up all the temporary things
 * we malloced, and these are indicated with the "Temp" suffix. "Perm" means permanent,
 * so that these are not freed on a graceful exit.
 */
enum MemKind {
    // Just a regular pointer, e.g. `void *`.
    RawTemp,
    RawPerm,
    // A queue, e.g. `queue_t`
    QueueTemp,
    QueuePerm,
    // An integer array populated by `find_n_free_frames()`. Unwinding here also entails
    // freeing the pages that have been marked as occupied by that function.
    FrameArr,
};

struct MPtr {
    void *ptr;
    enum MemKind kind;
};

/**
 * Allocate and return a pointer to a new struct.
 */
m_builder_t *m_builder_init();
/**
 * Allocate `size` amount of memory and, if it is not `NULL`, put in on the `m_builder_t`
 * queue. Returns the pointer to the allocated memory (may be `NULL`). `kind` is the
 * type of item being allocated, e.g. a queue.
 */
void *m_builder_malloc(m_builder_t *malloc_builder, enum MemKind kind, int size);
/**
 * Free every pointer in the queue AND the queue itself. The motivating use case is calling
 * this after a `malloc()` call has failed, and right before returning with error.
 */
void m_builder_unwind(m_builder_t *malloc_builder);
/**
 * Free non-permanent pointers, and the malloc builder itself
 */
void m_builder_conclude(m_builder_t *malloc_builder);

#endif  // __MEM_MANAGEMENT_H