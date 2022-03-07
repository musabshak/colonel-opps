# malloc builder

The purpose of this module is to abstract away the `free`s and associated cleanup we 
have to do in a function that `malloc`s a lot of things. There are two main cases that 
we consider and handle:
- returning from the function with error
- returning from the function with success

In both cases, returning will likely require the `free`ing of many pointers that have
been allocating over the course of the function.

This module also abstracts the details of allocation in some cases. For example, in 
trying to manually allocate an array of free frames, one would have to `malloc` the 
array then search for those free frames, mark them as valid in the frametable, and 
put them in the array. The detail only increases if we are to properly handle errors,
such as if there are no more free frames half-way through this allocation process. 

## Key Structures

The enum `MemKind` represents the type of object that is being allocated. 
```
enum MemKind {
    RawTemp,
    RawPerm,

    QueueTemp,
    QueuePerm,

    FrameArr,
};
```

- `Raw` refers to a general pointer. The caller will be returned a `void *`. This is useful 
for allocating memory that does not require special handling in allocation or freeing other 
than essentially calling `malloc` and `free`. 
- `Queue` refers to the generic queue data structure used in this program, e.g. the one 
described in `queue.h`.
- `FrameArr` refers to an array containing the identification information of free frames that 
have been found. That is, in allocating something of this kind, a certain amount of free frames
are found and their identification is stored in an array returned to the user.

These variants might have a `Temp` or `Perm` suffix. `Temp` means that this was a temporary 
pointer, hence should be `free`d no matter if we return with success or error. `Perm` means 
permanent, and these objects should only be `free`d if we return with error, not if we 
return with success. Even if a kind doesn't have a suffix, e.g. `FrameArr`, the `free`ing 
behavior may vary depending on if we exit with success or failure.

## Key functions

- `mbuilder_init()`
    - Creates a new malloc builder, which is where data about the various allocation calls and
    their associated kinds will be stored.
    - In the current implementation, the malloc builder is implemented as a queue. 
- `m_builder_malloc()`
    - Allocate a new object of the specified kind, returning a pointer to it.
- `m_builder_unwind()`
    - Call this function on the malloc builder right before returning with an error. As 
    described above, it will essentially free everything that was allocated during the 
    function
- `m_builder_conclude()`
    - Call this function on the malloc builder right before returning with success. As 
    described above, the temporary allocations will be free'd, but the permanent ones 
    will persist.

## Specific kind behavior

- `Raw`
    - *Allocation*: just a normal `malloc()` call
    - *Freeing*: just a normal `free()` call
        - *Temp*: free
        - *Perm*: don't free
- `Queue`
    - *Allocation*: a call to `qopen()`
    - *Freeing*: a call to `qclose()`
        - *Temp*: free
        - *Perm*: don't free
- `FrameArr`
    - *Allocation*: a call to `find_n_free_frames()`
    - *Freeing*
        - *Temp*: a call to `retire_frames()` and frees the array holding the frames
        - *Perm*: frees the array holding the frames

