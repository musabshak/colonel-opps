
#include "address_validation.h"

#include <stdbool.h>
#include <yuser.h>

#include "address_validation.h"
#include "kernel_data_structs.h"

extern unsigned int g_len_pagetable;

/**
 * Check if the provided address is above the userland break for the specified
 * process.
 */
bool is_above_ubrk(pcb_t *proc, void *addr) { return (addr > proc->user_brk); }

/**
 * Check if the address is above the redzone of the process's r1 pagetable. This
 * means that there is at least one unallocated page between the page of the last
 * used user heap address and the page of `addr`.
 */
bool is_above_ubrk_redzone(pcb_t *proc, void *addr) {
    unsigned int page_of_addr = get_page_of_addr(addr);
    unsigned int page_of_brk = get_page_of_addr(proc->user_brk);

    return (page_of_addr > page_of_brk);
}

/**
 * Is this address below the currently allocated memory for the user stack?
 * (We are viewing the user stack as growing from the top of the PCB down.)
 * In particular, is the page of the address strictly less than the last allocated
 * stack page?
 *
 * We do not validate that this is a region 1 address!
 */
bool is_below_userstack_allocation(pte_t *r1_ptable, void *addr) {
    unsigned int last_allocated_ustack_page = get_last_allocated_ustack_page(r1_ptable);
    unsigned int page_of_addr = ((unsigned int)(addr) >> PAGESHIFT) - g_len_pagetable;

    return (page_of_addr < last_allocated_ustack_page);
}

/**
 * Returns the (relative) page number of the last allocated page for the user
 * stack (which grows downwards from the top of the page table).
 */
unsigned int get_last_allocated_ustack_page(pte_t *r1_ptable) {
    // initial value, should never be returned
    unsigned int last_allocated_userstack_page = g_len_pagetable;

    for (int i = 0; i < g_len_pagetable; i++) {
        int page_num = g_len_pagetable - 1 - i;
        if (r1_ptable[page_num].valid == 1) {
            last_allocated_userstack_page = page_num;
        } else {
            break;
        }
    }

    return last_allocated_userstack_page;
}

unsigned int get_page_of_addr(void *addr) { return ((unsigned int)(addr) >> PAGESHIFT); }
