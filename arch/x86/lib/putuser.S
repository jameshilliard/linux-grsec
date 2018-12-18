/*
 * __put_user functions.
 *
 * (C) Copyright 2005 Linus Torvalds
 * (C) Copyright 2005 Andi Kleen
 * (C) Copyright 2008 Glauber Costa
 *
 * These functions have a non-standard call interface
 * to make them more efficient, especially as they
 * return an error value in addition to the "real"
 * return value.
 */
#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/errno.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <asm/segment.h>
#include <asm/pgtable.h>
#include <asm/frame.h>
#include <asm/nospec-branch.h>

/*
 * __put_user_X
 *
 * Inputs:	%eax[:%edx] contains the data
 *		%ecx contains the address
 *
 * Outputs:	%eax is error code (0 or -EFAULT)
 *
 * These functions should not modify any other registers,
 * as they get called from within inline assembly.
 */

#define ENTER	FRAME_BEGIN
#define EXIT	FRAME_END ; pax_force_retaddr ; ret

#if defined(CONFIG_X86_32) && defined(CONFIG_PAX_MEMORY_UDEREF)
#define __copyuser_seg gs;
#else
#define __copyuser_seg
#endif

.text
ENTRY(__put_user_1)
	ENTER

#if !defined(CONFIG_X86_32) || !defined(CONFIG_PAX_MEMORY_UDEREF)
	GET_THREAD_INFO(%_ASM_BX)
	cmp TI_addr_limit(%_ASM_BX),%_ASM_CX
	jae range_not_ok
#endif

	ASM_USER_ACCESS_BEGIN
1:	__copyuser_seg movb %al,(%_ASM_CX)
	xor %eax,%eax
	ASM_USER_ACCESS_END
	EXIT
ENDPROC(__put_user_1)

ENTRY(__put_user_2)
	ENTER

#if !defined(CONFIG_X86_32) || !defined(CONFIG_PAX_MEMORY_UDEREF)
	GET_THREAD_INFO(%_ASM_BX)
	mov TI_addr_limit(%_ASM_BX),%_ASM_BX
	sub $1,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae range_not_ok
#endif

	ASM_USER_ACCESS_BEGIN
2:	__copyuser_seg movw %ax,(%_ASM_CX)
	xor %eax,%eax
	ASM_USER_ACCESS_END
	EXIT
ENDPROC(__put_user_2)

ENTRY(__put_user_4)
	ENTER

#if !defined(CONFIG_X86_32) || !defined(CONFIG_PAX_MEMORY_UDEREF)
	GET_THREAD_INFO(%_ASM_BX)
	mov TI_addr_limit(%_ASM_BX),%_ASM_BX
	sub $3,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae range_not_ok
#endif

	ASM_USER_ACCESS_BEGIN
3:	__copyuser_seg movl %eax,(%_ASM_CX)
	xor %eax,%eax
	ASM_USER_ACCESS_END
	EXIT
ENDPROC(__put_user_4)

ENTRY(__put_user_8)
	ENTER

#if !defined(CONFIG_X86_32) || !defined(CONFIG_PAX_MEMORY_UDEREF)
	GET_THREAD_INFO(%_ASM_BX)
	mov TI_addr_limit(%_ASM_BX),%_ASM_BX
	sub $7,%_ASM_BX
	cmp %_ASM_BX,%_ASM_CX
	jae range_not_ok
#endif

	ASM_USER_ACCESS_BEGIN
4:	__copyuser_seg mov %_ASM_AX,(%_ASM_CX)
#ifdef CONFIG_X86_32
5:	__copyuser_seg movl %edx,4(%_ASM_CX)
#endif
	xor %eax,%eax
	ASM_USER_ACCESS_END
	EXIT
ENDPROC(__put_user_8)

bad_put_user:
	ASM_USER_ACCESS_END
range_not_ok:
	movl $-EFAULT,%eax
	EXIT
END(bad_put_user)

	_ASM_EXTABLE(1b,bad_put_user)
	_ASM_EXTABLE(2b,bad_put_user)
	_ASM_EXTABLE(3b,bad_put_user)
	_ASM_EXTABLE(4b,bad_put_user)
#ifdef CONFIG_X86_32
	_ASM_EXTABLE(5b,bad_put_user)
#endif
