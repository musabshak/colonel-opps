
#include <stdio.h>
#include <stdlib.h>

#include "mem_management.h"

int main() {
    m_builder_t *malloc_builder = m_builder_init();

    m_builder_malloc(malloc_builder, Temp, 4);
    m_builder_malloc(malloc_builder, Queue, 4);
    void *ptr = m_builder_malloc(malloc_builder, Perm, 4);

    m_builder_unwind(malloc_builder);
    free(ptr);

    return 0;
}
