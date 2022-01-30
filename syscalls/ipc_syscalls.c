/*
 *  ================
 *  === PIPEINIT ===
 *  ================
 * 
 *  From manual (p. 34):
 *      Create a new pipe; save its identifier at *pipe idp. (See the 
 *      header files for the length of the pipe’s internal buffer.) In 
 *      case of any error, the value ERROR is returned.
 * 
 *  - It seems that, for the syscall, we don't need to have two file 
 *    descriptors, as is the case for the user call in Linux pipe().
 *  - Presumably, this is a read and write fd.
 */

int kPipeInit(int *pipe_idp) {
    // Create a new file of size (pipe internal buffer) in VFS
    // *pipe_idp = fd_of_newfile
}

/*
 *  ================
 *  === PIPEREAD ===
 *  ================
 * 
 *  From manual (p. 34): 
 *      Read len consecutive bytes from the named pipe into the buffer 
 *      starting at address buf, following the standard semantics:
 *          - If the pipe is empty, then block the caller.
 *          - If the pipe has plen ≤ len unread bytes, give all of them 
 *            to the caller and return.
 *          - If the pipe has plen > len unread bytes, give the first len 
 *            bytes to caller and return. Retain the unread plen − len bytes 
 *            in the pipe.
 * 
 */

int kPipeRead(int pipe_id, void *buf, int len) {
    // Using the fd pipe_id
    // Read byte by byte, consuming upon reading
}

/*
 *  =================
 *  === PIPEWRITE ===
 *  =================
 * 
 *  From manual (p. 34):
 *      Write the len bytes starting at buf to the named pipe. (As the 
 *      pipe is a FIFO buffer, these bytes should be appended to the sequence 
 *      of unread bytes currently in the pipe.) Return as soon as you get the 
 *      bytes into the buffer. In case of any error, the value ERROR is 
 *      returned. Otherwise, return the number of bytes written.
 * 
 */

int kPipeWrite(int pipe_id, void *buf, int len) {
    
}