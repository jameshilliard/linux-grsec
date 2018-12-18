#ifndef _ASM_X86_RMWcc
#define _ASM_X86_RMWcc

#ifdef CC_HAVE_ASM_GOTO

#define __GEN_RMWcc(fullop, var, size, cc, ...)				\
do {									\
	asm_volatile_goto (fullop					\
			"\n\t"__PAX_REFCOUNT(size)			\
			";j" cc " %l[cc_label]"				\
			: : [counter] "m" (var), ## __VA_ARGS__ 	\
			: "memory", "cc", "cx" : cc_label);		\
	return 0;							\
cc_label:								\
	return 1;							\
} while (0)

#define __GEN_RMWcc_unchecked(fullop, var, cc, ...)			\
do {									\
	asm_volatile_goto (fullop "; j" cc " %l[cc_label]"		\
			: : "m" (var), ## __VA_ARGS__ 			\
			: "memory" : cc_label);				\
	return 0;							\
cc_label:								\
	return 1;							\
} while (0)

#define GEN_UNARY_RMWcc(op, var, size, arg0, cc) 			\
	__GEN_RMWcc(op " " arg0, var, size, cc)

#define GEN_UNARY_RMWcc_unchecked(op, var, arg0, cc) 			\
	__GEN_RMWcc_unchecked(op " " arg0, var, cc)

#define GEN_BINARY_RMWcc(op, var, size, vcon, val, arg0, cc)		\
	__GEN_RMWcc(op " %1, " arg0, var, size, cc, vcon (val))

#define GEN_BINARY_RMWcc_unchecked(op, var, vcon, val, arg0, cc)	\
	__GEN_RMWcc_unchecked(op " %1, " arg0, var, cc, vcon (val))

#else /* !CC_HAVE_ASM_GOTO */

#define __GEN_RMWcc(fullop, var, size, cc, ...)				\
do {									\
	char c;								\
	asm volatile (fullop 						\
			"\n\t"__PAX_REFCOUNT(size)			\
			"; set" cc " %1"				\
			: [counter] "+m" (var), "=qm" (c)		\
			: __VA_ARGS__ : "memory", "cc", "cx");		\
	return c != 0;							\
} while (0)

#define __GEN_RMWcc_unchecked(fullop, var, cc, ...)			\
do {									\
	char c;								\
	asm volatile (fullop "; set" cc " %1"				\
			: "+m" (var), "=qm" (c)				\
			: __VA_ARGS__ : "memory");			\
	return c != 0;							\
} while (0)

#define GEN_UNARY_RMWcc(op, var, size, arg0, cc)			\
	__GEN_RMWcc(op " " arg0, var, size, cc)

#define GEN_UNARY_RMWcc_unchecked(op, var, arg0, cc)			\
	__GEN_RMWcc_unchecked(op " " arg0, var, cc)

#define GEN_BINARY_RMWcc(op, var, size, vcon, val, arg0, cc)		\
	__GEN_RMWcc(op " %2, " arg0, var, size, cc, vcon (val))

#define GEN_BINARY_RMWcc_unchecked(op, var, vcon, val, arg0, cc)	\
	__GEN_RMWcc_unchecked(op " %2, " arg0, var, cc, vcon (val))

#endif /* CC_HAVE_ASM_GOTO */

#endif /* _ASM_X86_RMWcc */
