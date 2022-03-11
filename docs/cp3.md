# Checkpoint 3 Submission

Code: https://git.dartmouth.edu/f00436k/colonel-opps/-/blob/checkpoint-3/kernel.c
[commit: 408eefc44d590394349b66f6a6884c0111ca30df in checkpoint-3 branch]


## Questions and comments
We made the checkpoint (everything is working as expected).

A summary of bugs/challenges we faced is included in the log.md file in 
the root directory. Some outstanding questions we had were:
- Why are initial malloc calls not trigerring SetKernelBrk?
    - Why is malloc allocating in the user data section?
- What is a clock tick (what we are measuring `Delay()` with)? 
    - Is it each time `TrapClock()` is called, or is it directly defined as 
    a certain CPU speed measurement?

## Instructions to run
Build with `make all`, and run as `yalnix -W` for normal functionality and 
`init.c` as the initial process, or as `yalnix -W tests/cp3_tests`, which makes 
the test file the initial process for the purposes of observing userland tests.

## Tests
A brief description of tests (all contained within cp3_tests.c)

### GetPid
This works as expected. Calling getPID() on the user process returns a pid of 0 (can be seen
in the trace file after you generate it, if you search for "pid"). This makes sense because the userland
process is the first process that's created in our kernel in KernelStart().

### Malloc
When we try to call `malloc` with `100000` bytes, the user `brk` starts out 
at page 137 and after `Brk` is called by the kernel the new user `brk` is on page 149, as expected.

When we try to `malloc` too many bytes (into or beyond user stack), the malloc call returns NULL.

### Delay
`Delay(n)` for `n <= 0` returns immediately, as expected.

The meaningful case is for `Delay(n) with n > 0`. We tested the Delay syscall by calling 
`Delay(2)` in our userland test program. As expected, the userland calling process is blocked until 
2 clock interrupts have elapsed. In the mean time, the idle process is run. After 2 clock interrupts have
elapsed, the calling process is put back on the ready queue and dispatched at the next clock trap. Subsequently,
the regular cadence of idle > user_process > idle > user_process resumes, alternating every clock trap.