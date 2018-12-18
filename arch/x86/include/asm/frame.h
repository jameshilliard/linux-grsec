#ifdef __ASSEMBLY__

#include <asm/asm.h>

/* The annotation hides the frame from the unwinder and makes it look
   like a ordinary ebp save/restore. This avoids some special cases for
   frame pointer later */
#ifdef CONFIG_FRAME_POINTER
	.macro FRAME_BEGIN
	__ASM_SIZE(push,)	%__ASM_REG(bp)
	__ASM_SIZE(mov)		%__ASM_REG(sp), %__ASM_REG(bp)
	.endm
	.macro FRAME_END
	__ASM_SIZE(pop,)	%__ASM_REG(bp)
	.endm
#else
	.macro FRAME_BEGIN
	.endm
	.macro FRAME_END
	.endm
#endif

#endif  /*  __ASSEMBLY__  */
