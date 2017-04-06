/*
 * Copyright (c) 2003-2009 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef _I386_CPU_CAPABILITIES_H
#define _I386_CPU_CAPABILITIES_H

#ifndef	__ASSEMBLER__
#include <stdint.h>
#endif
 
/*
 * This API only supported for Apple internal use.
 */

/* Bit definitions for _cpu_capabilities: */

#define	kHasMMX				0x00000001
#define	kHasSSE				0x00000002
#define	kHasSSE2			0x00000004
#define	kHasSSE3			0x00000008
#define	kCache32			0x00000010	/* cache line size is 32 bytes */
#define	kCache64			0x00000020
#define	kCache128			0x00000040
#define	kFastThreadLocalStorage		0x00000080	/* TLS ptr is kept in a user-mode-readable register */
#define kHasSupplementalSSE3		0x00000100
#define	k64Bit				0x00000200	/* processor supports EM64T (not what mode you're running in) */
#define	kHasSSE4_1			0x00000400
#define	kHasSSE4_2			0x00000800
#define	kHasAES				0x00001000
#define	kInOrderPipeline		0x00002000
#define	kSlow				0x00004000	/* tsc < nanosecond */
#define	kUP				0x00008000	/* set if (kNumCPUs == 1) */
#define	kNumCPUs			0x00FF0000	/* number of CPUs (see _NumCPUs() below) */
#define	kNumCPUsShift			16
#define	kHasAVX1_0			0x01000000
#define	kHasRDRAND			0x02000000
#define	kHasF16C			0x04000000
#define	kHasENFSTRG			0x08000000
#define	kHasFMA				0x10000000
#define	kHasAVX2_0			0x20000000
#define	kHasBMI1			0x40000000
#define	kHasBMI2			0x80000000
/* Extending into 64-bits from here: */ 
#define	kHasRTM			0x0000000100000000ULL
#define	kHasHLE			0x0000000200000000ULL
#define	kHasRDSEED		0x0000000800000000ULL
#define	kHasADX			0x0000000400000000ULL
#define	kHasMPX			0x0000001000000000ULL
#define	kHasSGX			0x0000002000000000ULL


#ifndef	__ASSEMBLER__
#include <sys/cdefs.h>

__BEGIN_DECLS
extern uint64_t  _get_cpu_capabilities( void );
__END_DECLS

inline static
int _NumCPUs( void )
{
	return (int) (_get_cpu_capabilities() & kNumCPUs) >> kNumCPUsShift;
}

#endif /* __ASSEMBLER__ */

#endif /* _I386_CPU_CAPABILITIES_H */
