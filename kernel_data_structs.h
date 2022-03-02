
#ifndef __KERNEL_DATA_STRUCTS_H
#define __KERNEL_DATA_STRUCTS_H

// #pragma once

#include "queue.h"
#include "ykernel.h"

typedef struct ProcessControlBlock pcb_t;
typedef struct TermBuf term_buf_t;

// S========= EXTERN DECLARATIONS ========== //
extern pcb_t *g_running_pcb;
extern pcb_t *g_idle_pcb;
extern pte_t *g_reg0_ptable;

extern queue_t *g_ready_procs_queue;
extern queue_t *g_delay_blocked_procs_queue;
extern queue_t *g_term_blocked_transmit_queue;
extern queue_t *g_term_blocked_read_queue;
extern queue_t *g_term_blocked_write_queue;
extern unsigned int *g_frametable;

extern unsigned int g_len_pagetable;
extern unsigned int g_len_frametable;
extern unsigned int g_num_kernel_stack_pages;

// extern term_buf_t g_term_bufs[NUM_TERMINALS];

// E========= EXTERN DECLARATIONS ========== //

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
    int exit_status;  // process's own exit_status
    int last_dying_child_exit_code;
    int last_dying_child_pid;

    // --- for kDelay
    int elapsed_clock_ticks;
    int delay_clock_ticks;

    // --- for IO
    void *term_bufs[NUM_TERMINALS];
    int blocked_term;  // TODO: do we want a seperate field for waiting for term write/read?
} pcb_t;

typedef struct ZombiePCB {
    int pid;
    int exit_status;
} zombie_pcb_t;

typedef struct TermBuf {
    void *ptr;
    // `ptr + curr_pos_offset` points to the first byte in the buffer that
    // has NOT been read/copied
    int curr_pos_offset;
    // `ptr + end_pos_offset - 1` points to the last readable byte in the buffer
    int end_pos_offset;
} term_buf_t;

KernelContext *KCCopy(KernelContext *kc_in, void *new_pcb_p, void *not_used);
KernelContext *KCSwitch(KernelContext *kc_in, void *curr_pcb_p, void *new_pcb_p);
int find_free_frame(unsigned int *frametable);
int *find_n_free_frames(unsigned int *frametable, int num_frames);
void retire_frames(int *frametable, int *frame_idxs);

void print_r0_page_table(pte_t *ptable, int size, int *frametable);
void print_r1_page_table(pte_t *ptable, int size);

int raise_brk_user(void *new_brk, void *current_brk, pte_t *ptable);
int lower_brk_user(void *new_brk, void *current_brk, pte_t *ptable);

void print_pcb(void *elementp);

int destroy_pcb(pcb_t *pcb, int exit_status);

int schedule(queue_t *old_process_destination_queue);

// int h_raise_brk(void *new_brk, void **curr_brk, pte_t *ptable);
// int h_lower_brk(void *new_brk, void **curr_brk, pte_t *ptable);

#endif  // __KERNEL_DATA_STRUCTS_H
