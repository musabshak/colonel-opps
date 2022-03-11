/**
 * address_validation.c
 *
 * Authors: Varun Malladi
 *
 * Functions related to validating addresses passed to the kernel by the user. For example,
 * strings and arrays.
 */

#include "address_validation.h"

#include <stdbool.h>
#include <yuser.h>

#include "address_validation.h"
#include "k_common.h"

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

/**
 * Returns the page the passed address is on (not relative)
 */
unsigned int get_page_of_addr(void *addr) { return ((unsigned int)(addr) >> PAGESHIFT); }

/**
 * Checks if the address lies in region 1. True if yes.
 */
bool is_r1_addr(void *addr) {
    unsigned int addr_page = ((unsigned int)(addr) >> PAGESHIFT);
    if (addr_page < g_len_pagetable || addr_page >= 2 * MAX_PT_LEN) {
        // the address points to r0 (kernel) memory, or past r1 memory
        return false;
    }

    return true;
}

/**
 * Check that the address pointed to by a pointer passed from userland, is write-able.
 */
bool is_writeable_addr(pte_t *r1_ptable, void *addr) {

    // Check that pointer is a valid R1 pointer
    if (!is_r1_addr(addr)) {
        TracePrintf(1, "Pointer is not pointing to an R1 addr\n");
        return false;
    }

    // Check for write permissions in the pagetable
    unsigned int addr_page = ((unsigned int)addr) >> PAGESHIFT;

    // It is safe to do this because we know the address in in region 1
    addr_page = addr_page % g_len_pagetable;

    if (r1_ptable[addr_page].prot & PROT_WRITE == PROT_WRITE) {
        return true;
    }

    return false;
}

/**
 * Similar to `is_valid_array()`, but for strings, and for read-only access.
 */
bool is_readable_str(pte_t *r1_ptable, char *str) {
    // We iterate in this way so that we even validate the terminating character
    for (char *pointer_to_char = str;; pointer_to_char++) {
        // Tells us when to break out of the loop
        int should_break = 0;
        if (*pointer_to_char == '\0') {
            should_break = 1;
        }

        // Check if address is in region 1
        if (is_r1_addr((void *)pointer_to_char) == false) {
            return false;
        }

        // Check if user has read permissions to this page
        unsigned int addr_page = ((unsigned int)(str) >> PAGESHIFT);
        addr_page = addr_page % g_len_pagetable;

        if (r1_ptable[addr_page].prot & PROT_READ != PROT_READ) {
            return false;
        }

        // Break out of loop if necessary
        if (should_break == 1) {
            break;
        }
    }

    return true;
}

/**
 * Given an array (a pointer to the first element of an array), with length `array_len`,
 * check if each address in the array is accessible by the user under protection `prot`.
 *
 * For instance, if the user is trying to (just) write to this array, we might call this
 * with `prot = PROT_WRITE`. Note that this just checks if the permissions include `prot`,
 * not that the permissions are exactly `prot`. In this example, acessing a page with
 * protection `PROT_READ | PROT_WRITE` would still be valid, as it includes `PROT_WRITE`.
 *
 * Note that buffers are just character arrays.
 */
bool is_valid_array(pte_t *r1_ptable, void *array, int array_len, int prot) {
    for (int i = 0; i < array_len; i++) {
        void *addr = array + i;
        if (is_r1_addr(addr) == false) {
            // address is not in region 1
            return false;
        }

        unsigned int addr_page = ((unsigned int)(addr) >> PAGESHIFT);
        // It is safe to do this because we know the address in in region 1
        addr_page = addr_page % g_len_pagetable;

        // See if the pagetable has the same protections the user is asking the kernel to
        // to utilize. We do this by checking if adding the protections in `prot` to the
        // existing one in the pagetable will result in the same protection that the pagetable
        // originally had. If it is the same, then that page must have already included
        // `prot` (potentially it may have included more permissions).
        if (r1_ptable[addr_page].prot & prot != prot) {
            return false;
        }
    }

    return true;
}
