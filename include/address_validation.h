#ifndef __ADDRESS_VALIDATION_H
#define __ADDRESS_VALIDATION_H

#include <stdbool.h>

#include "k_common.h"

bool is_above_ubrk(pcb_t *proc, void *addr);
bool is_above_ubrk_redzone(pcb_t *proc, void *addr);
bool is_below_userstack_allocation(pte_t *r1_ptable, void *addr);
unsigned int get_last_allocated_ustack_page(pte_t *r1_ptable);
unsigned int get_page_of_addr(void *addr);

bool is_r1_addr(void *addr);
bool is_writeable_addr(pte_t *r1_ptable, void *addr);
bool is_readable_str(pte_t *r1_ptable, char *str);
bool is_valid_array(pte_t *r1_ptable, void *array, int array_len, int prot);

#endif