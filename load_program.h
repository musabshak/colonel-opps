
#ifndef __LOAD_PROGRAM_H
#define __LOAD_PROGRAM_H

#include <fcntl.h>
#include <load_info.h>
#include <unistd.h>
#include <ykernel.h>

#include "k_common.h"

int LoadProgram(char *name, char *args[], pcb_t *proc);

#endif  // __LOAD_PROGRAM_H