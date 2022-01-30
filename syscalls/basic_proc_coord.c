// Assume global coming from kernel:
pcb_t *running_process_p;

/*
 *  ============
 *  === FORK ===
 *  ============
 *
 * From manual (p. 31):
 *      Fork is how new processes are created in Yalnix. The memory
 *      image of the new process (the child) is a copy of that of the
 *      process calling Fork (the parent). When the Fork call completes,
 *      both the parent process and the child process return (separately)
 *      from the syscall as if they had been the one to call Fork, since
 *      the child is a copy of the parent. The only distinction is the fact
 *      that the return value in the calling (parent) process is the process
 *      ID of the new (child) process, while the value returned in the child
 *      is 0. If, for any reason, the new process cannot be created, this
 *      syscall instead returns the value ERROR to the calling process.
 */

int kFork() {
    //  --- Go to kernelland

    // Identify calling process's pcb
    pcb_t *parent_pcb;

    // Make a new pcb for child process.
    // Copy the parent process pointers to make a new process
    pcb_t *child_pcb = pcb_copy(parent_pcb);

    // Assign a new PID to child_pcb -> pid
    // Put 0 in register of child_pcb -> uctxt

    // Push new process into ready processes array
    ready_procs.push(child_pcb);

    // return from fork() with 0.
    return 0;
}

/*
 * ============
 * === EXEC ===
 * ============
 *
 * From manual (p. 31-32):
 *      ???
 */
int kExec(char *filename, char **argvec) {
    // Initialize memory of calling function if it hasn't been
    // Load text at filename to proc mem,
    // Let argc = # entries in argvec before NULL
    // Call main(argc, argvec)
}

/**
 * ============
 * === EXIT ===
 * ============
 *
 * From manual (p. 33):
 *      Exit is the normal means of terminating a process. The current process is
 *      terminated, the integer status value is saved for possible later collection
 *      by the parent process on a call to Wait. All resources used by the calling
 *      process will be freed, except for the saved status information. This call
 *      can never return.
 *      When a process exits or is aborted, if it has children, they should continue
 *      to run normally, but they will no longer have a parent. When the orphans
 *      later exit, you need not save or report their exit status since there is no
 *      longer anybody to care.
 *      If the initial process exits, you should halt the system.
 */

void kExit(int status) {
    // Go to kernelland
    // If parent == NULL (the exiting process is an orphan)
    // Then return
    // Else, add to exit status array
}

/**
 * ============
 * === WAIT ===
 * ============
 *
 * From manual (p. 33):
 *      Collect the process ID and exit status returned by a child process of the
 *      calling program.
 *      If the caller has an exited child whose information has not yet been collected
 *      via Wait, then this call will return immediately with that information.
 *      If the calling process has no remaining child processes (exited or running),
 *      then this call returns immediately, with ERROR.
 *      Otherwise, the calling process blocks until its next child calls exits or is
 *      aborted; then, the call returns with the exit information of that child.
 *      On success, the process ID of the child process is returned. If status ptr is
 *      not null, the exit status of the child is copied to that address.
 */
int kWait(int *status_ptr) {
    // Go to kernelland
    // If no children, return with ERROR
    // Else, kernel blocks this process by adding it to waiting queue
    // This means: when process is running, check the exit status array
    // to see if the child has returned. If not, go back t
}

/**  ==============
 *  === GETPID ===
 *  ==============
 */
int kGetPid() {
    // Confirm that there is a process that is currently running
    if (running_process_p == NULL) {
        return ERROR;
    }

    return running_process_p->pid;
}

/* *  ===========
 *  === BRK ===
 *  ===========
 *
 * Increments the user's heap.
 */
int kBrk(void *addr) {
    //  --- Calculate the extra memory the user is asking for
    pcb_t *calling_proc = running_process_p;
    int amount_mem_requested = addr - calling_proc->user_heap->limit;

    //  --- Get enough frames
    int num_frames_needed = amount_mem_requested / frame_size + 1;

    int new_frames[num_frames_needed];
    int frames_acquired = 0;
    for (int i=0; j<frametable->size; i++) {
        if (frametable->frames[i].ref_count != 0) { continue; }

        new_frames[frames_acquired] = frametable->frames[i].id;
    }

    //  --- Update caller's pagetable
    pagetable_t *callers_pagetable = calling_proc->pagetable;
    // calculate which pages correspond to the requested heap area, update those 
    // page table entries to point to the frames in new_frames[], change bit to 
    // valid


    // Change user heap limit to addr
    calling_proc->user_heap->limit = addr;
}

/**  =============
 *  === DELAY ===
 *  =============
 *
 *  From manual (p. 33):
 *      The calling process is blocked until at least clock ticks clock interrupts
 *      have occurred after the call. Upon completion of the delay, the value 0 is
 *      returned.
 *      If clock ticks is 0, return is immediate. If clock ticks is less than 0,
 *      time travel is not carried out, and ERROR is returned instead.
 */
int kDelay(int clock_ticks) {
}