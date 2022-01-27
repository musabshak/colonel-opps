/*
 *  ================
 *  === LOCKINIT ===
 *  ================
 * 
 *  From manual (p. 34):
 *      Create a new lock; save its identifier at *lock idp. In case 
 *      of any error, the value ERROR is returned.
 * 
 */

int kLockInit(int *lock_idp) {

}

/*
 *  ===============
 *  === ACQUIRE ===
 *  ===============
 * 
 *  From manual (p. 34):
 *      Acquire the lock identified by lock id. In case of any error, 
 *      the value ERROR is returned.
 * 
 */

int kAcquire(int lock_id) {

}

/*
 *  ===============
 *  === RELEASE ===
 *  ===============
 * 
 *  From manual (p. 35):
 *      Release the lock identified by lock id. The caller must currently 
 *      hold this lock. In case of any error, the value ERROR is returned.
 * 
 */

int kRelease(int lock_id) {

}

/*
 *  ================
 *  === CVARINIT ===
 *  ================
 * 
 *  From manual (p. 35):
 *      Create a new condition variable; save its identifier at *cvar_idp. 
 *      In case of any error, the value ERROR is returned.
 * 
 */
int kCvarInit(int *cvar_idp) {

}

/*
 *  ==================
 *  === CVARSIGNAL ===
 *  ==================
 * 
 *  From manual (p. 35):
 *      Signal the condition variable identified by cvar id. (Use Mesa-style 
 *      semantics.) In case of any error, the value ERROR is returned.
 * 
 */
int kCvarSignal(int cvar_id) {

}

/*
 *  =====================
 *  === CVARBROADCAST ===
 *  =====================
 * 
 *  From manual (p. 35):
 *      Broadcast the condition variable identified by cvar id. (Use Mesa-style 
 *      semantics.) In case of any error, the value ERROR is returned.
 * 
 */
int kCvarBroadcast(int cvar_id) {

}

/*
 *  ================
 *  === CVARWAIT ===
 *  ================
 * 
 *  From manual (p. 35):
 *      The kernel-level process releases the lock identified by lock id and 
 *      waits on the condition variable indentified by cvar id. When the 
 *      kernel-level process wakes up (e.g., because the condition variable was 
 *      signaled), it re-acquires the lock. (Use Mesa-style semantics.)
 *      When the lock is finally acquired, the call returns to userland. In case 
 *      of any error, the value ERROR is returned.
 * 
 */
int kCvarWait(int cvar_id, int lock_id) {

}

/*
 *  ===============
 *  === RECLAIM ===
 *  ===============
 * 
 *  From manual (p. 35):
 *      Destroy the lock, condition variable, or pipe indentified by id, 
 *      and release any associated resources.
 *      In case of any error, the value ERROR is returned.
 *      If you feel additional specification is necessary to handle unusual 
 *      scenarios, then create and document it.
 * 
 */
int kReclaim(int id) {

}
