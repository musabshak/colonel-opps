#ifndef __SYSCALLS_H
#define __SYSCALLS_H

//  ===== BASIC PROCESS CORDINATION =====
pcb_t *running_process_p;

int kFork();
int kExec(char *filename, char **argvec);
void kExit(int status);
int kWait(int *status_ptr);
int kGetPid();
int kBrk(void *addr);
int kDelay(int clock_ticks);

//  ===== Input / Output =====
int kTtyRead(int tty_id, void *buf, int len);
int kTtyWrite(int tty_id, void *buf, int len);

//  ===== Interprocess Communication =====
int kPipeInit(int *pipe_idp);
int kPipeRead(int pipe_id, void *buf, int len);
int kPipeWrite(int pipe_id, void *buf, int len);

//  ===== Synchronization =====
typedef struct Lock lock_t;
typedef struct Cvar cvar_t;

queue_t *lock_list_qp;
queue_t *cvar_list_qp;

int kLockInit(int *lock_idp);
int kAcquire(int lock_id);
int kRelease(int lock_id);
int kCvarInit(int *cvar_idp);
int kCvarWait(int cvar_id, int lock_id);
int kCvarSignal(int cvar_id);
int kCvarBroadcast(int cvar_id);
int kReclaim(int id);


#endif // __SYSCALLS_H