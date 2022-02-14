
#ifndef __LOAD_PROGRAM_H
#define __LOAD_PROGRAM_H

#include <fcntl.h>
#include <load_info.h>
#include <unistd.h>
#include <ykernel.h>

#include "kernel_data_structs.h"

int LoadProgram(char *name, char *args[], pcb_t *proc);

#endif  // __LOAD_PROGRAM_H