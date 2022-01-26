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
 * 
 *  int fork() {
 *      //  --- Go to kernelland
 *      
 *      // Identify calling process's 
 *      // Copy the process pointers to make a new process
 *      // Push new process into active processes array, next operation is to 
 *         return from fork() with 0.
 *      // (Parent process) return from fork() with pid of child.
 *  }
 * 
 * ============
 * === EXEC ===
 * ============
 * 
 * From manual (p. 31-32):
 *      ???
 * 
 *  int exec(char *filename, char **argvec) {
 *      // Initialize memory of calling function if it hasn't been
 *      // Load text at filename to proc mem, 
 *      // Let argc = # entries in argvec before NULL
 *      // Call main(argc, argvec) 
 *  }
 * 
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
 * 
 *  void exit(int status) {
 *      // Go to kernelland
 *      // If parent == NULL (the exiting process is an orphan)
 *      // Then return
 *      // Else, add to exit status array
 *  }
 * 
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
 * 
 *  int wait(int *status_ptr) {
 *      // Go to kernelland
 *      // If no children, return with ERROR
 *      // Else, kernel blocks this process by adding it to waiting queue
 *      // This means: when process is running, check the exit status array
 *      // to see if the child has returned. If not, go back t
 *      
 *  }
 *  
 *  ==============
 *  === GETPID ===
 *  ==============
 * 
 *  int getpid() {
 *      // go to kernel land
 *      // return thisproc.pid
 *  }
 * 
 *  ===========
 *  === BRK ===
 *  ===========
 * 
 * Increments the user's heap.
 * 
 *  int Brk(void *addr) {
 *      // Calculate the extra memory the user is asking for
 *      // Get enough frames
 *      // Change user heap limit to addr
 *  }
 * 
 *  =============
 *  === DELAY ===
 *  =============
 * 
 *  From manual (p. 33):
 *      The calling process is blocked until at least clock ticks clock interrupts 
 *      have occurred after the call. Upon completion of the delay, the value 0 is 
 *      returned.
 *      If clock ticks is 0, return is immediate. If clock ticks is less than 0, 
 *      time travel is not carried out, and ERROR is returned instead.
 * 
 *  int Delay(int clock_ticks) {
 * 
 *  }
 * 
 */