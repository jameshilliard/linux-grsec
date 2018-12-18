/* SPDX-License-Identifier: GPL-2.0 */

#include <asm/asm.h>
#include <asm/processor-flags.h>
#include <asm-generic/export.h>
#include <linux/linkage.h>

/*
 * unsigned long native_save_fl(void)
 */
RAP_ENTRY(native_save_fl)
	pushf
	_ASM_TEST $X86_EFLAGS_AC, (%_ASM_SP)
	jnz .Lcheck_save_fl
.Lsave_fl:
	pop %_ASM_AX
	ret
.Lcheck_save_fl:
	mov %cr4, %_ASM_AX
	test $X86_CR4_SMAP, %_ASM_AX
	jz .Lsave_fl
	ud2
ENDPROC(native_save_fl)
EXPORT_SYMBOL(native_save_fl)

/*
 * void native_restore_fl(unsigned long flags)
 * %eax/%rdi: flags
 */
RAP_ENTRY(native_restore_fl)
	push %_ASM_ARG1
	push %_ASM_ARG1
	_ASM_TEST $X86_EFLAGS_AC, (%_ASM_SP)
	jnz .Lcheck_restore_fl
.Lrestore_fl:
	popf
	pop %_ASM_ARG1
	ret
.Lcheck_restore_fl:
	mov %cr4, %_ASM_ARG1
	test $X86_CR4_SMAP, %_ASM_ARG1
	jz .Lrestore_fl
	ud2
ENDPROC(native_restore_fl)
EXPORT_SYMBOL(native_restore_fl)
