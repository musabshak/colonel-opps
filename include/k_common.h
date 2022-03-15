/**
 * k_common.h
 *
 * Authors: Varun Malladi and Musab Shakeel
 * Date: 2/2022
 *
 * Header file for k_common.c. This file additionally externs global variables declared in kernel.c. These
 * globals are used in several different kernel source files (i.e. several different source files #include
 * "k_common.h").
 */

#pragma once

#include "hash.h"
#include "printing.h"
#include "queue.h"
#include "ykernel.h"

#define MAX_KEYLEN 12  // for pipe/lock/cvar key ("pipe132") for hashtable

#define PIPE_ID_K 3  // increment pipe/lock/cvar ids by prime numbers (to be able to distinguish b/w them)
#define LOCK_ID_K 5
#define CVAR_ID_K 7

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
extern hashtable_t *g_pipes_htable;
extern int g_max_pipes;
extern int g_pipe_id;

extern hashtable_t *g_locks_htable;
extern int g_max_locks;
extern int g_lock_id;

extern hashtable_t *g_cvars_htable;
extern int g_max_cvars;
extern int g_cvar_id;

// E========= EXTERN DECLARATIONS ========== //

typedef struct ProcessControlBlock {
    unsigned int pid;

    // --- userland
    UserContext uctxt;
    void *user_brk;
    unsigned int user_text_pg0;  // populated in LoadProgram
    unsigned int user_data_pg0;  // populated in LoadProgram
    void *user_data_end;         // populated in LoadProgram
    void *user_stack_base;       // populated in LoadProgram; updated by memoryTrapHandler()

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

typedef struct Pipe {
    int pipe_id;
    char buffer[PIPE_BUFFER_LEN];  // circular
    int curr_num_bytes;            // number of current bytes in the pipe
    int front;                     // index of front element of pipe
    int back;                      // index of back elemetn of pipe
    queue_t *blocked_procs_queue;  // blocked processes associated with a particular pipe
} pipe_t;

typedef struct Lock {
    unsigned int lock_id;
    bool locked;
    bool corrupted;  // indicates whether lock is corrupted (if process holding lock
                     // exited w/o releasing)
    pcb_t *owner_proc;

    queue_t *blocked_procs_queue;  // Queue of blocked processes associated with this lock
} lock_t;

typedef struct Cvar {
    unsigned int cvar_id;
    queue_t *blocked_procs_queue;
} cvar_t;

KernelContext *KCCopy(KernelContext *kc_in, void *new_pcb_p, void *not_used);
KernelContext *KCSwitch(KernelContext *kc_in, void *curr_pcb_p, void *new_pcb_p);

int find_free_frame(unsigned int *frametable);
int *find_n_free_frames(unsigned int *frametable, int num_frames);
void retire_frames(int *frametable, int *frame_idxs);

void print_r0_page_table(pte_t *ptable, int size, int *frametable);
void print_r1_page_table(pte_t *ptable, int size);

void print_pcb(void *elementp);
int destroy_pcb(pcb_t *pcb, int exit_status);

int schedule(queue_t *old_process_destination_queue);

int assign_pipe_id();
int retire_pipe_id(int pipe_id);

int assign_lock_id();
int retire_lock_id(int lock_id);

int assign_cvar_id();
int retire_cvar_id(int cvar_id);

void print_pipe(void *elementp);
bool search_pipe(void *elementp, const void *searchkeyp);