/**
 * mem_management.c
 *
 * Functions helpful for memory management.
 */

#include <yuser.h>

#include "queue.h"

/**
 * A "malloc builder" is a struct that makes it easier to deal with successive
 * `malloc` calls. It keeps track of pointers that have been `malloc`ed, and
 * if something goes wrong we can "unwind" this struct, which `free`s all the
 * `malloc`s.
 *
 * This is implemented as a wrapper around a `queue_t`.
 */
typedef queue_t m_builder_t;

/**
 * Allocate and return a pointer to a new struct.
 */
m_builder_t *m_builder_init() { return qopen(); }

/**
 * A wrapper around `free()` which we can iterate over the queue to free all the
 * elements.
 */
void free_helper(void *item) { free(item); }

/**
 * Put a new item onto the queue. For instance, a pointer just `malloc`ed.
 */
int m_builder_put(m_builder_t *malloc_builder, void *item) { return qput(malloc_builder, item); }

/**
 * Allocate `size` amount of memory and, if it is not `NULL`, put in on the `m_builder_t`
 * queue. Returns the pointer to the allocated memory (may be `NULL`).
 */
void *m_builder_malloc(m_builder_t *malloc_builder, int size) {
    void *ptr = malloc(size);

    if (ptr != NULL) {
        m_builder_put(malloc_builder, ptr);
    }

    return ptr;
}

/**
 * Free every pointer in the queue AND the queue itself. The motivating use case is calling
 * this after a `malloc()` call has failed, and right before returning with error.
 */
void m_builder_unwind(m_builder_t *malloc_builder) {
    qapply(malloc_builder, free_helper);
    qclose(malloc_builder);
}
