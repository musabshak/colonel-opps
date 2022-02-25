# Checkpoint 4 Submission

Code: https://git.dartmouth.edu/f00436k/colonel-opps/-/tree/checkpoint-4
[commit: 86a308c7f5a8691dc801552171507950ed360127 in checkpoint-4 branch]

## Questions and comments
We made the checkpoint (everything is working as expected):
- Fork(), Exec(), Wait() work (verified with testing)
- Wait() works (verified with testing)
- We also wrote Exit() and it works (verified with testing)
- Round robin scheduler works (tested, works)
- Wrote memoryTrapHandler (half-tested/slightly buggy at the moment)

Some outstanding questions: 
- Why was it that when I tried to allocate too much on the user stack in the init program, 
even after forking, the entire thing broke? 
- When we tried to test the handling of when the user tries to grow the stack too much, we (in the init program) forked, and in the child 
instantiated an array of size 1000000. The result was that the fork call never happened, and the traceprint 
directly before allocating the array wasn’t printed.

To reproduce the error, replace lines 427-433 in `tests/cp4_tests.c` with the following:
```
TracePrintf(1, "Trying to grow user stack too much...\n");

int arr[1000000];
for (int i=0; i<1000000; i++) {
    arr[i] = 0;
}
```
Then build and run program with `./yalnix tests/cp4_tests 11`. Looking at the `TRACE` file, 
you should see that "CP4_TEST RUNNING!" prints but then there is a segfault, and the 
(as expected) the caller PCB gets destroyed. But we see the message that PID 0 was trying 
to be retired, while we expect the child (PID 2) to be killed. And when we search the 
document for "fork", nothing shows up (where we would expect a trace print).

## Instructions to run
Build with `make clean; make all`, and run as `yalnix -W` for normal functionality and 
`init.c` as the initial process, or as `yalnix -W tests/cp4_tests <option_int>`, which makes 
the test program the initial process for the purposes of observing userland tests. Run command with ideal  
traceprinting levels: `yalnix -W -lh 0 -lk 1 tests/cp4_tests <option_int>`
