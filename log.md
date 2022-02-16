## Bugs
### Checkpoint 3
- u_long type not found (used in load_info.h, included in load_program.c)
    - Include hardware.h in load_program.c
- load_program page numbers were already relative
    - Needed to take out the "... - MAX_PT_LEN" 
    - While flushing specific region 1 pages, need to add MAX_PT_LEN to addresses
- Needed to flush kernel stack contents INSIDE KCSwitch call (it didn't work to flush r0 kstack entries right after the KCSwitch call)
- Forgot to flush R0 tlb entry for red zone page temporarily used while copying old kernel stack frame contents into new kernel stack frames
- Needed to flush TLB for redzone page used to copy contents of kernel stack frames into new stack frames
    - SO FRUSTRATING


### Checkpoint 2
- Segfault as soon as virtual memory turned on
    - We were getting a segfault right as we enabled virtual memory with WriteRegister(ENABLE_VM, 1)
    - Solution: Need to use `malloc()` even before enabling VM
- Setting stack pointer (`sp` register) to empty R1 user stack caused a read from invalid virtual address 0x200000
    - Solution: Hardware expects a 4-byte gap from top of stack (stack granularity is 4 byte word in Intel x86). Set
    sp to 0x1ffffc and not 0x1fffff
- Use of `unsigned int` for a variable that would be expected to take on negative values
    - Caused a lot of bad things 
- Marking frame used/unused in frametable
    - We sometimes forgot to mark frame in frametable as used/unused when allocating/deallocating pages in pagetables
- Mysteriously increasing home directory size (Babylon)
    - .vscode-server taking up a lot of space (2.8G)
    - It seems okay to delete this folder




## Challenges
### Checkpoint 3


### Checkpoint 2
- Figuring out how Thayer Babylons dump core
    - Solution
        - Need to set `ulimit -c unlimited`
        - Core dumped in /var/lib/apport/coredump
        - Only 5 recent coredumps kept by Babylons
        - Defined an environment variable CDUMP that stores path to most recently generated core dump
- Backtracing stack and examining core using `gdb`
    - Will backtrace to address `0x0`, which cannot be read
    - Receives error signals
    - Solution: this is somewhat expected; certain files implementing the Yalnix
    simulation are not provided to us, so `gdb` gets confused




## Todos
### Todo other
- Bring SetKernelBrk tests into main code
    - Write some thoughtful, SetKernelBrk-specific macros?
- CLARIFY C header/extern/linking concepts
- Write test_KCCopy function

### Todo cp3
- Write userland init program source (init.c)
- Parse KernelStart arguments
    - If none specified, load ./init into R1 ptable
    - If specified, load the specified program ./my_program_executable and feed it the entire cmd_args array
- Prepare kernel for loading init program into colonel-opps
    - Create new PCB (init_pcb) X
        - New PID (helper_new_pid()) X
        - New R1 ptable (all invalid) X
        - Allocate frames for init's kernel stack frames X
            - But no new pages exist in R0 ptable for init's kernel stack
        - User Context (from uctxt arg to KernelStart) X
    - Write KCCopy() X
        - Copies the current KernelContext into init_pcb
        - Copies contents of current kernel stack into new kernel stack frames in init_pcb 
            - Since the allocated frames for init's kernel stack haven't been mapped onto, to do this, temporarily map the destination frame into some page (perhaps the page right below the kernel stack (red zone page))
- Load init program into colonel-opps
    - Need to open the init executable and set it up in init_pcb->r1_ptable
    - Edit provided LoadProgram function
        - Loads executable into the *current* r1_ptable
            - By the time of function invocation, make sure to have already written into the registers addresses of init's r1_ptable!
- Context-switching (changing processes)
    - Edit TrapClock(UserContext *user_context)
        - At the start of TrapClock, copy current user_context into PCB of old running process (running_process_pcb) (old_process_pcb)
        - Get new process from g_ready_processes: new_process_pcb
        - At the end of TrapClock, make sure hardware is using r1_ptable of the new_process_pcb (new_process_pcb->r1_ptable)
        - Copy the user_context of the new process (new_process_pcb->user_context) into the uctxt address passed to TrapClock 
        - Invoke KCSwitch() 
            - Changes kernel stack contents from old_process to new_process
            - Copy current KernelContext into old_process_pcb
            - Change R0 kernel stack mappings to those for the new_process_pcb
            - Return a pointer to the KernelContext in the new_process_pcb
- Implement 3 syscalls
    - Brk
    - GetPid
    - Delay



### Todo cp2
Overview  
- Kernel should boot and run idle in user mode
    - "Running idle": a while loop

Booting Tasks  
- Set up interrupt vector
- Write KernelStart()
- Set up a way to track free frames
- Set up initial Region 0 page table using help of following (virtual) addresses given to kernel by build process
    - void *_kernel_data_start
        - Lowest address in the kernel data region
    - void *_kernel_data_end
        - Lowest address not in use by the kernel's instructions and global data, at boot time
    - void *_kernel_orig_brk
        - The address the kernel library believes is its brk (re: kernel heap) at boot time
- Set up a Region 1 page table for idle
    - With one valid page, for idle's user stack
- Write SetKernelBrk(void *addr)
    - Change kernel brk to addr (lowest location not used in kernel)
    - Maintain a flag to indicate if virtual memory has been enabled
    - Before enabling VM, SetKernelBrk only needs to track if and by how much the kernel brk is being raised beyond _kernel_orig_brk
    - After VM is enabled, SetKernelBrk acts like the standard Brk, but for userland
- Enable virtual memory
    -If kernel brk has been raised since you build your Region 0 page table, you need to adjust the page table approporiately before turning the VM on

Trap Tasks  
- TRAP_CLOCK
    - Traceprints when there is a clock trap
- TRAP_KERNEL
    - Traceprints (in hex) the code of the syscall
- TRAP_GENERIC
    - Runs for all other entries in interrupt vector

Idle Tasks  
- Kernel is already running as its own first process
    - Formalize that by creating an idlePCB that keeps track of this identity
        - Region 1 page table
        - Kernel stack frames
        - UserContext (from the uctxt argument to KernelStart)
        - pid (from helper_new_pid())









