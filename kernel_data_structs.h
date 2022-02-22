
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
    unsigned int user_text_pg0;
    unsigned int user_data_pg0;
    void *user_data_end;
    void *user_stack_base;

    // --- kernelland
    KernelContext kctxt;
    unsigned int kstack_frame_idxs[KERNEL_STACK_MAXSIZE / PAGESIZE];

    // ---- metadata
    pcb_t *parent;
    pte_t *r1_ptable;

    // --- for kWait/kExit
    queue_t *zombie_procs;
    queue_t *children_procs;
    int is_wait_blocked;
    int exit_status;

    // --- for kDelay
    int elapsed_clock_ticks;
    int delay_clock_ticks;
} pcb_t;

KernelContext *KCCopy(KernelContext *kc_in, void *new_pcb_p, void *not_used);
KernelContext *KCSwitch(KernelContext *kc_in, void *curr_pcb_p, void *new_pcb_p);
int find_free_frame(unsigned int *frametable);

void print_r0_page_table(pte_t *ptable, int size, int *frametable);
void print_r1_page_table(pte_t *ptable, int size);

int raise_brk_user(void *new_brk, void *current_brk, pte_t *ptable);
int lower_brk_user(void *new_brk, void *current_brk, pte_t *ptable);

void print_pcb(void *elementp);

// int h_raise_brk(void *new_brk, void **curr_brk, pte_t *ptable);
// int h_lower_brk(void *new_brk, void **curr_brk, pte_t *ptable);

#endif  // __KERNEL_DATA_STRUCTS_H
