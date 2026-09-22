/*
 *	bpP.h -- selects the vendored copy of ION's private Bundle Protocol
 *	header that matches the installed ION-DTN (see README in this
 *	directory).
 *
 *	The layouts of the structures the contributions read and allocate
 *	(BpVdb, VPlan, VInduct, ClProtocol, ...) changed at 4.0.2, 4.1.0,
 *	4.1.4 and 4.2.0, so one copy cannot serve every release: a daemon
 *	compiled with the wrong one reads the wrong words of shared memory.
 *	Each release group is told apart by a macro that its installed
 *	headers are the first to define:
 *
 *	  ION_IPC_ATOMIC_OPAQUE_DEFINED  ion.h  4.2.0 (with ion_ipc_atomic_t)
 *	  FQN_MAX_LENGTH                 ion.h  4.1.4 (with getOwnFqnn)
 *	  BP_VERSION                     bp.h   4.1.0
 *	  BP_BIBE_REQUESTED              bp.h   4.0.2
 *
 *	and anything older is 4.0.0 or 4.0.1, which share the layouts.
 */
#ifndef BPP_H
#include "ion.h"
#include "bp.h"
#if defined(ION_IPC_ATOMIC_OPAQUE_DEFINED)
#include "bpP-4.2.0.h"
#elif defined(FQN_MAX_LENGTH)
#include "bpP-4.1.4.h"
#elif defined(BP_VERSION)
#include "bpP-4.1.3s.h"		/*	4.1.0 through 4.1.3s.	*/
#elif defined(BP_BIBE_REQUESTED)
#include "bpP-4.0.2.h"
#else
#include "bpP-4.0.1.h"		/*	4.0.0 and 4.0.1.	*/
#endif
#endif
