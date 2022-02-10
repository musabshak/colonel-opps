### Bugs

## Checkpoint 2
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




### Challenges
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