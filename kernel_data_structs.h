
#ifndef __KERNEL_DATA_STRUCTS_H
#define __KERNEL_DATA_STRUCTS_H

// #pragma once

#include "queue.h"
#include "ykernel.h"

typedef struct ProcessControlBlock pcb_t;
typedef struct ProcessControlBlock {
    unsigned int pid;
    // --- userland
    UserContext uctxt;
    void *user_brk;
    void *user_data;
    void *user_text;
    // --- kernelland
    KernelContext kctxt;
    unsigned int kstack_frame_idxs[KERNEL_STACK_MAXSIZE / PAGESIZE];
    // --- metadata
    pcb_t *parent;
    queue_t *children_procs;
    pte_t *r1_ptable;
} pcb_t;

KernelContext *KCSwitch(KernelContext *kc_in, void *curr_pcb_p, void *new_pcb_p);
int find_free_frame(unsigned int *frametable);

void print_r0_page_table(pte_t *ptable, int size, int *frametable);
void print_r1_page_table(pte_t *ptable, int size);

#endif  // __KERNEL_DATA_STRUCTS_H
