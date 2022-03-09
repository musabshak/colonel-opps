/**
 * mem_management.c
 *
 * Functions helpful for memory management.
 */

#include "mbuilder.h"

#include <stdlib.h>

#include "k_common.h"
#include "queue.h"

extern unsigned int *g_frametable;

/**
 * A "malloc builder" is a struct that makes it easier to deal with successive
 * `malloc` calls. It keeps track of pointers that have been `malloc`ed, and
 * if something goes wrong we can "unwind" this struct, which `free`s all the
 * `malloc`s.
 *
 * This is implemented as a wrapper around a `queue_t`.
 */
typedef queue_t m_builder_t;

typedef struct WidePtr {
    void *ptr;
    enum MemKind kind;
} wideptr_t;

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
 * A wrapper aound `qclose()` which we can iterate over the queue to free all the
 * elements
 */
void qclose_helper(void *item) { qclose((queue_t *)item); }

/**
 * Put a new item onto the queue. For instance, a pointer just `malloc`ed.
 */
int m_builder_put(m_builder_t *malloc_builder, wideptr_t *item) { return qput(malloc_builder, (void *)item); }

/**
 * Allocate `size` amount of memory and, if it is not `NULL`, put in on the `m_builder_t`
 * queue. Returns the pointer to the allocated memory (may be `NULL`). `kind` is the
 * type of item being allocated, e.g. a queue.
 */
void *m_builder_malloc(m_builder_t *malloc_builder, enum MemKind kind, int size) {
    void *ptr;
    switch (kind) {
        case RawTemp:
        case RawPerm:
            ptr = malloc(size);
            break;
        case QueueTemp:
        case QueuePerm:
            ptr = (void *)qopen();
            break;
        case FrameArr:
            ptr = (void *)find_n_free_frames(g_frametable, size);
            break;
    }
    if (ptr == NULL) {
        return NULL;
    }

    wideptr_t *wideptr = malloc(sizeof(wideptr_t));
    if (wideptr == NULL) {
        switch (kind) {
            case RawTemp:
            case RawPerm:
                free(ptr);
                break;
            case QueueTemp:
            case QueuePerm:
                qclose((queue_t *)ptr);
                break;
        }

        return NULL;
    }

    wideptr->ptr = ptr;
    wideptr->kind = kind;

    m_builder_put(malloc_builder, wideptr);

    return ptr;
}

/**
 * Free every pointer in the queue AND the queue itself. The motivating use case is calling
 * this after a `malloc()` call has failed, and right before returning with error.
 *
 * The freeing is done in accordance to the `kind` of the element.
 */
void m_builder_unwind(m_builder_t *malloc_builder) {
    wideptr_t *item;
    while ((item = (wideptr_t *)qget(malloc_builder)) != NULL) {
        switch (item->kind) {
            case RawTemp:
            case RawPerm:
                free(item->ptr);
                break;
            case QueueTemp:
            case QueuePerm:
                qclose((queue_t *)item->ptr);
                break;
            case FrameArr:
                // mark all frames as available again
                retire_frames(g_frametable, (int *)item->ptr);
                free(item->ptr);
                break;
        }

        free(item);
    }

    qclose(malloc_builder);
}

/**
 * Free non-permanent pointers, and the malloc builder itself
 */
void m_builder_conclude(m_builder_t *malloc_builder) {
    wideptr_t *item;
    while ((item = (wideptr_t *)qget(malloc_builder)) != NULL) {
        switch (item->kind) {
            case RawTemp:
            case FrameArr:
                free(item->ptr);
                break;
            case QueueTemp:
                qclose(item->ptr);
                break;
            case RawPerm:
            case QueuePerm:
                break;
        }

        free(item);
    }

    qclose(malloc_builder);
}
