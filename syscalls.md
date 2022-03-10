# syscalls

We document here the approach and design choices in our syscalls.

## Basic process coordination

### Fork
Our implementation fully copies the process that called it (rather than copy-on-write).
We essentially go page-by-page through the caller's region 1 pagetable and copy each 
valid page into a newly allocated page in the (soon to be) child's region 1 pagetable.
We do not copy the contents of the caller's kernel stack, but rather give the child free
frames for it (that are empty). The child's PCB is a copy of the parent's with a few 
modifications, such as the region 1 page table, kernel stack frames, and PID.

### Exec
Besides valid pointers, we require that the user pass at least one argument into this 
function. For example, convention would dictate this just be the name of the program. 
The bulk of this syscall is validating its arguments, then calling `LoadProgram()` if 
everything is OK.

### Exit
This frees the associated memory of the process (with `destroy_pcb()`), then calls the 
scheduler. Now, the child will first check if its parent is waiting on it. If it is, 
then it will put the parent back on the ready queue before destroying itself and 
calling the scheduler (see the Wait section).

### Wait
Each PCB has (space for) a queue of zombie processes. A call to this syscall will first
see if there are any processes already on this queue. 
- If there are, it will get remove from this queue and give the relevant exit data to 
the caller. No scheduling is necessary since we do not need to block.
- If there are no zombie processes there currently:
    - If there are not even any children, then we would just be waiting indefinetely, so
    return with an error.
    - If there are children, mark this PCB as waiting, then schedule in such a way that 
    the scheduler does not put this process back on the ready queue. We do not put it 
    on any other queue, just take it off the ready queue. The idea is that we don't ever
    need to walk through all waiting-on-child processes. This process will wake up where 
    it left off when one of its children exits (see the Exit section), and at that point 
    we try to populate the provided status pointer with the child's exit status and then 
    returns the PID of the child it took the exit status from.

### GetPID
Our PCB struct contains a field for that process's PID. We assume that the 
currently running process is the one that is calling this function, so we just 
retrived the PID field from there.

### Brk
The break is defined to be the first invalid byte in the (user) process's virtual memory.
A consequence of this is that the break will always point to the 0th byte of a page.

Our function first determines if it was invoked to raise or lower the break. It handles these
two cases as follows:
- *Raising break*
    - Given the address passed to the function, we can calculating the number of pages 
    we need to allocate by subtracting the page of that address from the last page 
    currently in use by the process.
    - But we don't actually store the "last page currently in use" in the PCB. We do 
    store the (user) break, so what we do is subtract the page of the address from the 
    page of the current user break. 
        - If the address passed was the 0th byte of its page, then this is the correct 
        number of pages to raise by. (Since we don't need to allocate the page the new
        break will actually be on)
        - If not, then, since the new break will actually be the 0th byte of the next 
        page after the one the address passed is on, we increment the number of pages
        we need to raise by by one.
- *Lowering break*
    - Very similar to lowering the break. However, if the address passed is not the 0th 
    byte of its page, then the new break will be the 0th byte of the page after the one 
    the address is on (so we don't need to free the page the address is on). Therefore 
    we decrement the number of pages to decrease by one.
    
### Delay
We have fields in the PCB that keep track of how many clock traps we need to delay for, 
and how many we have already been delaying for. We set the former to the provided argument,
and the latter to 0. Then we call the scheduler, telling it to put the caller on a delay
queue. (On clock traps, this queue is traversed it puts the process back on the ready 
queue if it has delayed for long enough.) Once we wake up, we know that we have finished 
delaying so we return.
