/*

 x86 function call convention, 64-bit:
 -------------------------------------
  arguments           |  callee-saved      | extra caller-saved | return
 [callee-clobbered]   |                    | [callee-clobbered] |
 ---------------------------------------------------------------------------
 rdi rsi rdx rcx r8-9 | rbx rbp [*] r12-15 | r10-11             | rax, rdx [**]

 ( rsp is obviously invariant across normal function calls. (gcc can 'merge'
   functions when it sees tail-call optimization possibilities) rflags is
   clobbered. Leftover arguments are passed over the stack frame.)

 [*]  In the frame-pointers case rbp is fixed to the stack frame.

 [**] for struct return values wider than 64 bits the return convention is a
      bit more complex: up to 128 bits width we return small structures
      straight in rax, rdx. For structures larger than that (3 words or
      larger) the caller puts a pointer to an on-stack return struct
      [allocated in the caller's stack frame] into the first argument - i.e.
      into rdi. All other arguments shift up by one in this case.
      Fortunately this case is rare in the kernel.

For 32-bit we have the following conventions - kernel is built with
-mregparm=3 and -freg-struct-return:

 x86 function calling convention, 32-bit:
 ----------------------------------------
  arguments         | callee-saved        | extra caller-saved | return
 [callee-clobbered] |                     | [callee-clobbered] |
 -------------------------------------------------------------------------
 eax edx ecx        | ebx edi esi ebp [*] | <none>             | eax, edx [**]

 ( here too esp is obviously invariant across normal function calls. eflags
   is clobbered. Leftover arguments are passed over the stack frame. )

 [*]  In the frame-pointers case ebp is fixed to the stack frame.

 [**] We build with -freg-struct-return, which on 32-bit means similar
      semantics as on 64-bit: edx can be used for a second return value
      (i.e. covering integer and structure sizes up to 64 bits) - after that
      it gets more complex and more expensive: 3-word or larger struct returns
      get done in the caller's frame and the pointer to the return struct goes
      into regparm0, i.e. eax - the other arguments shift up and the
      function's register parameters degenerate to regparm=2 in essence.

*/

#include <asm/cpufeatures.h>
#include <asm/asm-offsets.h>
#include <asm/processor-flags.h>
#include <asm/irqflags.h>
#include <asm/nospec-branch.h>
#include <linux/stringify.h>

#ifdef CONFIG_X86_64

/*
 * 64-bit system call stack frame layout defines and helpers,
 * for assembly code:
 */

/* The layout forms the "struct pt_regs" on the stack: */
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
#define R15		0*8
#define R14		1*8
#define R13		2*8
#define R12		3*8
#define RBP		4*8
#define RBX		5*8
/* These regs are callee-clobbered. Always saved on kernel entry. */
#define R11		6*8
#define R10		7*8
#define R9		8*8
#define R8		9*8
#define RAX		10*8
#define RCX		11*8
#define RDX		12*8
#define RSI		13*8
#define RDI		14*8
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
#define ORIG_RAX	15*8
/* Return frame for iretq */
#define RIP		16*8
#define CS		17*8
#define EFLAGS		18*8
#define RSP		19*8
#define SS		20*8

#define SIZEOF_PTREGS	21*8

	.macro ALLOC_PT_GPREGS_ON_STACK addskip=0
	addq	$-(15*8+\addskip), %rsp
	.endm

	.macro SAVE_C_REGS_HELPER offset=0 rax=1 rcx=1 r8910=1 r11=1
#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movq %r12, R12+\offset(%rsp)
#endif
	.if \r11
	movq %r11, R11+\offset(%rsp)
	.endif
	.if \r8910
	movq %r10, R10+\offset(%rsp)
	movq %r9,  R9+\offset(%rsp)
	movq %r8,  R8+\offset(%rsp)
	.endif
	.if \rax
	movq %rax, RAX+\offset(%rsp)
	.endif
	.if \rcx
	movq %rcx, RCX+\offset(%rsp)
	.endif
	movq %rdx, RDX+\offset(%rsp)
	movq %rsi, RSI+\offset(%rsp)
	movq %rdi, RDI+\offset(%rsp)
	.endm
	.macro SAVE_C_REGS offset=0
	SAVE_C_REGS_HELPER \offset, 1, 1, 1, 1
	.endm
	.macro SAVE_C_REGS_EXCEPT_RAX_RCX offset=0
	SAVE_C_REGS_HELPER \offset, 0, 0, 1, 1
	.endm
	.macro SAVE_C_REGS_EXCEPT_R891011
	SAVE_C_REGS_HELPER 0, 1, 1, 0, 0
	.endm
	.macro SAVE_C_REGS_EXCEPT_RCX_R891011
	SAVE_C_REGS_HELPER 0, 1, 0, 0, 0
	.endm
	.macro SAVE_C_REGS_EXCEPT_RAX_RCX_R11
	SAVE_C_REGS_HELPER 0, 0, 0, 1, 0
	.endm

	.macro SAVE_EXTRA_REGS offset=0
	movq %r15, R15+\offset(%rsp)
	movq %r14, R14+\offset(%rsp)
	movq %r13, R13+\offset(%rsp)
#ifndef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movq %r12, R12+\offset(%rsp)
#endif
	movq %rbp, RBP+\offset(%rsp)
	movq %rbx, RBX+\offset(%rsp)
	.endm

	.macro RESTORE_EXTRA_REGS offset=0
	movq R15+\offset(%rsp), %r15
	movq R14+\offset(%rsp), %r14
	movq R13+\offset(%rsp), %r13
#ifndef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	movq R12+\offset(%rsp), %r12
#endif
	movq RBP+\offset(%rsp), %rbp
	movq RBX+\offset(%rsp), %rbx
	.endm

	.macro ZERO_EXTRA_REGS
	xorl	%r15d, %r15d
	xorl	%r14d, %r14d
	xorl	%r13d, %r13d
#ifndef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	xorl	%r12d, %r12d
#endif
	xorl	%ebp, %ebp
	xorl	%ebx, %ebx
	.endm

	.macro RESTORE_C_REGS_HELPER rstor_rax=1, rstor_rcx=1, rstor_r11=1, rstor_r8910=1, rstor_rdx=1, rstor_r12=1
#ifdef CONFIG_PAX_KERNEXEC_PLUGIN_METHOD_OR
	.if \rstor_r12
	movq R12(%rsp), %r12
	.endif
#endif
	.if \rstor_r11
	movq R11(%rsp), %r11
	.endif
	.if \rstor_r8910
	movq R10(%rsp), %r10
	movq R9(%rsp), %r9
	movq R8(%rsp), %r8
	.endif
	.if \rstor_rax
	movq RAX(%rsp), %rax
	.endif
	.if \rstor_rcx
	movq RCX(%rsp), %rcx
	.endif
	.if \rstor_rdx
	movq RDX(%rsp), %rdx
	.endif
	movq RSI(%rsp), %rsi
	movq RDI(%rsp), %rdi
	.endm

	.macro RESTORE_C_REGS
	RESTORE_C_REGS_HELPER 1,1,1,1,1,1
	.endm

	.macro RESTORE_C_REGS_EXCEPT_RAX
	RESTORE_C_REGS_HELPER 0,1,1,1,1,0
	.endm

	.macro RESTORE_C_REGS_EXCEPT_RCX
	RESTORE_C_REGS_HELPER 1,0,1,1,1,0
	.endm

	.macro RESTORE_C_REGS_EXCEPT_R11
	RESTORE_C_REGS_HELPER 1,1,0,1,1,1
	.endm

	.macro RESTORE_C_REGS_EXCEPT_RCX_R11
	RESTORE_C_REGS_HELPER 1,0,0,1,1,1
	.endm

	.macro REMOVE_PT_GPREGS_FROM_STACK addskip=0
	subq $-(15*8+\addskip), %rsp
	.endm

	.macro icebp
	.byte 0xf1
	.endm

#define CPU_ENTRY_AREA \
	_entry_trampoline - CPU_ENTRY_AREA_entry_trampoline(%rip)

/* The top word of the SYSENTER stack is hot and is usable as scratch space. */
#define RSP_SCRATCH	CPU_ENTRY_AREA_entry_stack + \
			SIZEOF_entry_stack - 8 + CPU_ENTRY_AREA

	.macro pax_enter_kernel_user scratch_reg:req
#ifdef CONFIG_PAX_MEMORY_UDEREF
	ALTERNATIVE "jmp .Lenter_kernel_user_\@", "", X86_FEATURE_UDEREF

#ifdef CONFIG_PARAVIRT
//	ALTERNATIVE "pushq %rdi", PV_SAVE_REGS(CLBR_NONE), X86_FEATURE_XENPV
//	PV_SAVE_REGS(CLBR_NONE)
#endif

	.ifnc \scratch_reg,%rdi
	mov	%rdi, \scratch_reg
	.endif
	GET_CR3_INTO_RDI
//	ALTERNATIVE "", "dec %dil", X86_FEATURE_PCID
//	cmp	$1, %dil
//	jnz	.Lbug_enter_kernel_user_\@
	and	$-4*PAGE_SIZE_asm, %rdi
	ALTERNATIVE "", "bts $63, %rdi", X86_FEATURE_PCID
	SET_RDI_INTO_CR3
	.ifnc \scratch_reg,%rdi
	mov	\scratch_reg, %rdi
	.endif

#ifdef CONFIG_PARAVIRT
//	PV_RESTORE_REGS(CLBR_NONE)
#endif

	jmp .Lenter_kernel_user_\@

.Lbug_enter_kernel_user_\@:
	ud2
.Lenter_kernel_user_\@:
#endif
	.endm

	.macro pax_exit_kernel_user scratch_reg:req
#ifdef CONFIG_PAX_MEMORY_UDEREF
	ALTERNATIVE "jmp .Lexit_kernel_user_\@", "", X86_FEATURE_UDEREF

#ifdef CONFIG_PARAVIRT
//	PV_SAVE_REGS(CLBR_NONE)
#endif

	.ifnc \scratch_reg,%rdi
	mov	%rdi, \scratch_reg
	.endif

	GET_CR3_INTO_RDI
	cmp	$0, %dil
	jnz	.Lbug_exit_kernel_user_\@

	or	$2*PAGE_SIZE_asm, %rdi
	ALTERNATIVE "", "inc %dil ; bts $63, %rdi", X86_FEATURE_PCID
	SET_RDI_INTO_CR3

	.ifnc \scratch_reg,%rdi
	mov	\scratch_reg, %rdi
	.endif

#ifdef CONFIG_PARAVIRT
//	PV_RESTORE_REGS(CLBR_NONE)
#endif

	jmp .Lexit_kernel_user_\@

.Lbug_exit_kernel_user_\@:
	mov	$0, %dil
	SET_RDI_INTO_CR3
	ud2
.Lexit_kernel_user_\@:
#endif
	.endm

	.macro pax_enter_kernel_nmi

#ifdef CONFIG_PARAVIRT
	push	%rdi
//	PV_SAVE_REGS(CLBR_NONE)
#endif

#ifdef CONFIG_PAX_KERNEXEC
	GET_CR0_INTO_RDI
	bts	$X86_CR0_WP_BIT, %rdi
	jc	.Lenter_kernel_nmi_skip_cr0_\@
	SET_RDI_INTO_CR0
	or	$2, %ebx
.Lenter_kernel_nmi_skip_cr0_\@:
#endif

#ifdef CONFIG_PAX_MEMORY_UDEREF
	ALTERNATIVE "jmp .Lenter_kernel_nmi_skip_cr3_\@", "", X86_FEATURE_UDEREF
	GET_CR3_INTO_RDI
	btr	$13, %rdi
	jnc	.Lenter_kernel_nmi_skip_cr3_\@

	btr	$12, %rdi
	jc	.Lenter_kernel_nmi_skip_user_\@

	/* TODO BUG_ON(PCID && dil == 0) */
	or	$4, %ebx
	ALTERNATIVE "", "mov $0, %dil ; bts $63, %rdi", X86_FEATURE_PCID
	SET_RDI_INTO_CR3
	mov	$__UDEREF_KERNEL_DS, %edi
	mov	%edi, %ss
	jmp	.Lenter_kernel_nmi_skip_cr3_\@

.Lenter_kernel_nmi_skip_user_\@:
	or	$8, %ebx
	ALTERNATIVE "", "mov $0, %dil ; bts $63, %rdi", X86_FEATURE_PCID
	SET_RDI_INTO_CR3
	mov	$__UACCESS_KERNEL_DS, %edi
	mov	%edi, %ss
.Lenter_kernel_nmi_skip_cr3_\@:
#endif

#ifdef CONFIG_PARAVIRT
	popq	%rdi
//	PV_RESTORE_REGS(CLBR_NONE)
#endif

	.endm

	.macro pax_exit_kernel_nmi

#ifdef CONFIG_PARAVIRT
	pushq	%rdi
//	PV_SAVE_REGS(CLBR_NONE)
#endif

#ifdef CONFIG_PAX_KERNEXEC
	btr	$1, %ebx
	jnc	.Lexit_kernel_nmi_skip_cr0_\@
	GET_CR0_INTO_RDI
	btr	$X86_CR0_WP_BIT, %rdi
	SET_RDI_INTO_CR0
.Lexit_kernel_nmi_skip_cr0_\@:
#endif

#ifdef CONFIG_PAX_MEMORY_UDEREF
	ALTERNATIVE "jmp .Lexit_kernel_nmi_skip_cr3_\@", "", X86_FEATURE_UDEREF
	btr	$2,%ebx
	jnc	.Lexit_kernel_nmi_skip_user\@

	GET_CR3_INTO_RDI
	add	$2*PAGE_SIZE_asm, %rdi
	ALTERNATIVE "", "inc %dil ; bts $63, %rdi", X86_FEATURE_PCID
	SET_RDI_INTO_CR3
	mov	$__KERNEL_DS, %edi
	mov	%edi, %ss
	jmp	.Lexit_kernel_nmi_skip_cr3_\@

.Lexit_kernel_nmi_skip_user\@:
	btr	$3,%ebx
	jnc	.Lexit_kernel_nmi_skip_cr3_\@

	GET_CR3_INTO_RDI
	add	$3*PAGE_SIZE_asm, %rdi
	ALTERNATIVE "", "inc %dil ; bts $63, %rdi", X86_FEATURE_PCID
	SET_RDI_INTO_CR3
	mov	$__KERNEL_DS, %edi
	mov	%edi, %ss

.Lexit_kernel_nmi_skip_cr3_\@:
#endif

#ifdef CONFIG_PARAVIRT
	popq	%rdi
//	PV_RESTORE_REGS(CLBR_NONE)
#endif

	.endm

#endif /* CONFIG_X86_64 */

	.macro pax_randomize_kstack
#ifdef CONFIG_PAX_RANDKSTACK
	pax_direct_call pax_randomize_kstack
#endif
	.endm

	.macro pax_erase_kstack
#ifdef CONFIG_PAX_MEMORY_STACKLEAK
	pax_direct_call pax_erase_kstack
#endif
	.endm

	.macro pax_enter_kernel
#if defined(CONFIG_PAX_KERNEXEC) || (defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF))
	pax_direct_call pax_enter_kernel
#endif
	.endm

	.macro pax_exit_kernel
#if defined(CONFIG_PAX_KERNEXEC) || (defined(CONFIG_X86_64) && defined(CONFIG_PAX_MEMORY_UDEREF))
	pax_direct_call pax_exit_kernel
#endif
	.endm
