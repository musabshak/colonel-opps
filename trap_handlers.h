
#ifndef __TRAP_HANDLERS_H
#define __TRAP_HANDLERS_H

#include "ykernel.h"

int TrapKernelHandler(UserContext *user_context);
int TrapClock(UserContext *user_context);
int TrapIllegal(UserContext *user_context);
int TrapMemory(UserContext *user_context);
int TrapMath(UserContext *user_context);
int TrapTTYReceive(UserContext *user_context);
int TrapTTYTransmit(UserContext *user_context);
int TrapDisk(UserContext *user_context);
int GenericHandler(UserContext *user_context);

#endif  // __TRAP_HANDLERS_H
