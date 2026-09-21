/*
 *	bpP.h -- selects the vendored copy of ION's private Bundle Protocol
 *	header that matches the installed ION-DTN (see README in this
 *	directory).
 *
 *	ION 4.2.0 changed the layout of BpVdb (delDeltas[] became the
 *	8-byte ion_ipc_atomic_t) and VEndpoint (appCookie), so one copy
 *	cannot serve both releases: a daemon compiled with the wrong one
 *	reads the wrong words of shared memory.  ion.h of 4.2.0 defines
 *	ION_IPC_ATOMIC_OPAQUE_DEFINED alongside the new type; 4.1.4's does
 *	not, and that is what tells the two apart.
 */
#ifndef BPP_H
#include "ion.h"
#ifdef ION_IPC_ATOMIC_OPAQUE_DEFINED
#include "bpP-4.2.0.h"
#else
#include "bpP-4.1.4.h"
#endif
#endif
