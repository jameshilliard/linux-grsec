/*
 * Supervisor Mode Access Prevention support
 *
 * Copyright (C) 2012 Intel Corporation
 * Author: H. Peter Anvin <hpa@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#ifndef _ASM_X86_SMAP_H
#define _ASM_X86_SMAP_H

#include <linux/stringify.h>
#include <asm/nops.h>
#include <asm/cpufeatures.h>

/* "Raw" instruction opcodes */
#define __ASM_CLAC	.byte 0x0f,0x01,0xca
#define __ASM_STAC	.byte 0x0f,0x01,0xcb

#ifdef __ASSEMBLY__

#include <asm/nospec-branch.h>

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
#define ASM_PAX_OPEN_USERLAND "call __pax_open_userland"
#define ASM_PAX_CLOSE_USERLAND "call __pax_close_userland"
#else
#define ASM_PAX_OPEN_USERLAND ""
#define ASM_PAX_CLOSE_USERLAND ""
#endif

#ifdef CONFIG_X86_SMAP

#define ASM_CLAC \
	ALTERNATIVE "", __stringify(__ASM_CLAC), X86_FEATURE_SMAP

#define ASM_PAX_CLAC __stringify(__ASM_CLAC)

#define ASM_STAC \
	ALTERNATIVE "", __stringify(__ASM_STAC), X86_FEATURE_SMAP

#define ASM_PAX_STAC __stringify(__ASM_STAC)

#else /* CONFIG_X86_SMAP */

#define ASM_CLAC
#define ASM_STAC

#define ASM_PAX_CLAC ""
#define ASM_PAX_STAC ""

#endif /* CONFIG_X86_SMAP */

#define ASM_USER_ACCESS_BEGIN	ALTERNATIVE_2 \
	"", \
	ASM_PAX_OPEN_USERLAND, \
	X86_FEATURE_UDEREF, \
	ASM_PAX_STAC, \
	X86_FEATURE_SMAP

#define ASM_USER_ACCESS_END	ALTERNATIVE_2 \
	"", \
	ASM_PAX_CLOSE_USERLAND, \
	X86_FEATURE_UDEREF, \
	ASM_PAX_CLAC, \
	X86_FEATURE_SMAP

#else /* __ASSEMBLY__ */

#include <asm/alternative.h>

#define __HAVE_ARCH_PAX_OPEN_USERLAND
#define __HAVE_ARCH_PAX_CLOSE_USERLAND

#if defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF)
extern void __pax_open_userland(void);
extern void __pax_close_userland(void);
#define PAX_OPEN_USERLAND "call %P[open]"
#define PAX_OPEN_USERLAND_CONSTRAINTS :: [open] "i" (__pax_open_userland) : "memory", "rax"
#define PAX_CLOSE_USERLAND "call %P[close]"
#define PAX_CLOSE_USERLAND_CONSTRAINTS :: [close] "i" (__pax_close_userland) : "memory", "rax"
#else
#define PAX_OPEN_USERLAND ""
#define PAX_OPEN_USERLAND_CONSTRAINTS
#define PAX_CLOSE_USERLAND ""
#define PAX_CLOSE_USERLAND_CONSTRAINTS
#endif

#ifdef CONFIG_X86_SMAP

#define CLAC __stringify(__ASM_CLAC)
#define STAC __stringify(__ASM_STAC)

/* These macros can be used in asm() statements */
#define ASM_CLAC \
	ALTERNATIVE("", __stringify(__ASM_CLAC), X86_FEATURE_SMAP)
#define ASM_STAC \
	ALTERNATIVE("", __stringify(__ASM_STAC), X86_FEATURE_SMAP)

#else /* CONFIG_X86_SMAP */

#define CLAC ""
#define STAC ""

#define ASM_CLAC
#define ASM_STAC

#endif /* CONFIG_X86_SMAP */

#define __uaccess_begin() asm volatile(ALTERNATIVE_2( \
	"", \
	PAX_OPEN_USERLAND, \
	X86_FEATURE_UDEREF, \
	STAC, \
	X86_FEATURE_SMAP) \
	PAX_OPEN_USERLAND_CONSTRAINTS);

#define __uaccess_end() asm volatile(ALTERNATIVE_2( \
	"", \
	PAX_CLOSE_USERLAND, \
	X86_FEATURE_UDEREF, \
	CLAC, \
	X86_FEATURE_SMAP) \
	PAX_CLOSE_USERLAND_CONSTRAINTS);

#define __uaccess_begin_nospec()	\
({					\
	__uaccess_begin();		\
	barrier_nospec();		\
})

#define stac()	__uaccess_begin()
#define clac()	__uaccess_end()

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_SMAP_H */
