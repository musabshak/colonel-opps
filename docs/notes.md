## Miscel FAQ
- What is a "trap"?
    - A trap is a _synchronous_ interrupt triggered by an exception in a user process, or by a library call (wrapper around syscall) in a user process
    - A trap changes the mode of the OS to a kernel routine (hardware bit "priv" turned on so hardware/CPU is receptive to kernel-level changes)
    - In kernel mode, a "trap handler" is associated with each trap, defined by the interrupt vector table
    - A trap may be viewed as a CPU interrupt handler
- Differences between a trap and an interrupt
    - Trap
        - Signal emitted by a user program (current process running on a processor))
        - Executes a specific functionality in OS
    - Interrupt 
        - Signal emitted by hardware device (caused by devices and may not be related to currently running process)
        - Forces CPU to trigger a speciffec interrupt handler routine
- Syscalls
    - Subtle terminology difference
    - Syscalls (system calls) are explicit requests from user code for kernel to do something
    - Implemented similar to interrupts (as a special type of interrupt)
    - CPU provides some conventions for implementing syscalls ("stuff syscall number in one register, other parameters in other registers, use this special trap instruction")
    - Have handlers (defined by interrupt vector)
- Exceptions/traps/interrupts
    - Same basic pattern: suspend current userland execution, switch to kernel mode, start running at some specific address in kernel mode
    - in x86, a program invokes a system call by generating an interrupt using the INT instruction
- Basic plan
    - Interrupt (INT instruction) stops normal processor loop (which looks like: read an instruction, advance PC, execute instruction, repeat) and starts executed a new sequence called an interrupt handler
    - Before starting the interrupt handler, registers are saved so the OS can restore them when returning from the interrupt




## Kernel data structures

Major kernel data structures:
- process
    - user stack, heap
    - kernel stack, heap, data, text
- page (logical memory), frame (physical memory), frame and page tables
    - page table entry (pte) sketched in include/hardware.h
    - user context
        - include/hardware.h
    - kernel context
        - include/hardware.h
    - syscall table
    - queue of ready processes
    - queue of waiting processes
    - array of exit statuses, to be checked for waiting process
        - exit status {int exit_status, process *parent}
    - pipe
    - lock
    - cvar (condition variable)
    - file descriptor
        - file descriptor table (per process) ->
        - file table (system wide, indexes opened files with mode) ->
        - inode table (system wide)
    - file?
    - interrupt vector, vector table

### Process Control Block (PCB)
References
- L5 (s65-)

Attributes/fields/data
- pid
- uspace 
    - Pointers to uspace memory: stack, heap, data, text)
- uctxt
    - Pointers to uspace libraries etc
    - Program counter, stack pointer, register A
- kstack
    - Pointer to kernel stack
    - Pointers to kernel code/context
- kctxt
    - Pointers to kernel code/context

Notes
- PCB lives in Kernel heap

### Lock/mutex
### Interrupt Vector Table
- A table of function pointers (pointers to syscall handlers)
- Needs to exist a function/handler for each of the following. 
    - Prototype: ``` void trap_handler(UserContext *) {} ```
```
#define	TRAP_KERNEL		0
#define	TRAP_CLOCK		1
#define	TRAP_ILLEGAL		2
#define	TRAP_MEMORY		3
#define	TRAP_MATH		4
#define	TRAP_TTY_RECEIVE	5
#define	TRAP_TTY_TRANSMIT	6
#define	TRAP_DISK		7
```

### UserContext
- Defined in hardware.h







## Traps


## Kernel syscalls [userland library version prototypes defined in yuser.h]
Note that these will be invoked by the TRAP_KERNEL trap handler

### GetPid()


### Fork()
    - Create new page table
    - Replicate valid bits
    - Set valid pages pointer to new frames
    - Copy frame contents
### Exec()
    - Go through page table and free all the frames for all the valid pages
    - If arguments given, save arguments somwehere (otherwise will lose them as you wipe address space) (arguments live in execed process' data)
- Exit()
    - Free all the frames
- Wait()

- Brk()
- PipeInit()
- PipeRead()
- PipeWrite()
- LockInit()
- Acquire()
- Release()
- CvarInit
- CvarWait
- CvarSignal
- CvarBroadcast



## Other functions