#ifndef __MEM_MANAGEMENT_H
#define __MEM_MANAGEMENT_H

#include "queue.h"

typedef queue_t m_builder_t;

/**
 * Allocate and return a pointer to a new struct.
 */
m_builder_t *m_builder_init();
/**
 * Put a new item onto the queue. For instance, a pointer just `malloc`ed.
 */
int m_builder_put(m_builder_t *malloc_builder, void *item);
/**
 * Allocate `size` amount of memory and, if it is not `NULL`, put in on the `m_builder_t`
 * queue. Returns the pointer to the allocated memory (may be `NULL`).
 */
void *m_builder_malloc(m_builder_t *malloc_builder, int size);
/**
 * Allocate `size` amount of memory and, if it is not `NULL`, put in on the `m_builder_t`
 * queue. Returns the pointer to the allocated memory (may be `NULL`).
 */
void *m_builder_malloc(m_builder_t *malloc_builder, int size);
/**
 * Free every pointer in the queue AND the queue itself. The motivating use case is calling
 * this after a `malloc()` call has failed, and right before returning with error.
 */
void m_builder_unwind(m_builder_t *malloc_builder);

#endif  // __MEM_MANAGEMENT_H