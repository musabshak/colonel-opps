# colonel-opps
Authors: Musab Shakeel and Varun Malladi  
Course: CS 58 

## Notes (for the course staff))
Verbose documentation detailing design choices for many of the syscalls is available in `docs/syscalls.md`.
Here, we provide an overview of some implementation details that the course staff may find relevant (for understanding behavior of some syscalls and/or for grading purposes).

### Random notes on implementation/design choices
- We use a generic queue as the storage data structure for our process queues (ready processes, blocked processes associated with kDelay/pipes/cvars/locks etc). The generic queue is implemented using a singly linked list.
    - For `g_delay_blocked_procs_queue` (blocked processes associated with kDelay() syscall), where we need to iterate through the queue to increment the `elapsed_ticks` for each process, and then potentially remove a `pcb_t*` from the queue, we use the `qremove_all()` generic queue method. `qremove_all()` takes in a "search" function that is applied to each element of the queue. We write the "search" function cleverly. The point being that we update the `elapsed_ticks` of each process in the queue, and remove processes that have finished their delay period, all in one `O(n)` pass.
- We create a separate `ZombiePCB` struct, containing only the `pid` and `exit_status` for a given process, to put in the `zombie_procs_queue` associated with a process. This means that for zombie processes (for all intents and purposes dead but need their `exit_status` to be collected by the parent), we're not storing unnecessary information.
- The internal pipe buffer does not use a generic queue. The pipe buffer is actually a queue ADT implemented using a circular array implementation (so we avoided the overhead of queue pointers by using a circular array)- Pipes/locks/cvars, are stored in hashtables to ensure an `O(1)` lookup in the syscalls associated with these objects (`PipeRead`, `PipeWrite`, `Acquire`, `Release`, etc)
- We implemented sophisticated, atomic handling of `Fork()` call failure. 
    - All malloced memory is carefully freed before `Fork()` exits with ERROR
    - TODO VARUN
    - Refer to documentation for `malloc builder` provided in `docs/mbuilder.md`
- We were careful to ensure graceful handling of cases where processes run out of physical memory. Refer to the next subsection `Dealing with running out of physical memory`
- There is no blocked process queue associated with the `kWait()` syscall (no need for a queue, we just mark the PCB with the attribute: `is_wait_blocked`)
- Our `kReclaim()` implementation is not very sophisticated
    - If the blocked process queues associated with the pipe/lock/cvar are not empty, the reclaim call fails
    - If a lock that is currently locked is being reclaimed, the call fails.
- Other minor notes
    - Kernel supports a maximum of 50 pipes, 50 locks, 50cvars (at any given point in time). This may be changed by modifying the constants in `kernel.c`.
    - You may call `yalnix` with a maximum of 30 arguments (arbitrary).


### Dealing with running out of physical memory
We (to our knowledge) gracefully handle scenarios where we run out of physical memory.  

Places where we may run out of physical memory (basically anywhere find_free_frame() is called in a loop)  
- `setKernelBrk` (while raising kernel heap) 
    - We `Halt()` the CPU.
- `kBrk` (while raising user heap) 
    - No memory leaks (no frames that will permanently remain marked as "used")
    - The user process is exited with ERROR.
- `MemoryTrap` (while raising user stack) 
    - No memory leaks (no frames that will permanently remain marked as "used")
    - The user process is exited with ERROR.
- `kFork` (while allocating frames for the new process - R1 ptable, kernel stack)
    - No memory leaks (no frames that will permanently remain marked as "used")
    - User's `Fork()` call returns with failure
- `kExec` 
    - Should not run out of memory since we just cleared memory from an earlier process but ...
    - Process that exec-ed exits with ERROR.





### Things we could improve
- Can improve how we track our free frames
    - Currently use a bitvector
    - Ideally, we would track free frames using a linked list (as suggested in the manual)
    - Even with the current bitvector implementation, we could have been slightly more sophisticated. We could have stored a `num_frames_currently_available` attribute with the bitvector. This would have made checking if enough physical memory is available for a process (before we created the process) easy. Currently our use of `find_n_free_frames()` solves the issue of atomic failure but it's more verbose than it needs to be.
- Our `assign_pipe_id()` and `retire_pipe_id()` (and equivalent functions for locks, cvars) are naive
    - We maintain global ID counters for pipes/locks/cvars. We use prime numbers for pipe/lock/cvar ids to be
    able to distinguish between the three, given an ID
    - There is no mechanism in place to reclaim a previously assigned id for future use
    - To prevent issues caused by a really large number of pipes/locks/cvars being created, we restrict
    the maximum number of of pipes/locks/cvars to a finite, small number (currently 50)
- Can make `kReclaim()` more sophisticated
- For pipe syscalls, can make buffer grow if pipe is full when `kPipeWrite()` tries to write
    



### Potential vulnerabilities
- There is no check in place for length of arguments provided to kernel. So, if the kernel is run with 
a really long string, the kernel may crash before even booting.


### Feedback request
This is the biggest C project (in terms of codebase size) that either of us have worked on; we would love feedback on code structure. Constructive feedback on code style is also welcome. If it isn't already a part
of the usual feedback provided by the course staff, we'd love to know if the staff catches any memory leaks. We'd also love to know if Sean is able to force our kernel to crash (and if so, what was the point of failure
in our code). Thanks!