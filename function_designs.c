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
 *      // (Parent process) return from fork() with 0.
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
 * 
 * 
 */