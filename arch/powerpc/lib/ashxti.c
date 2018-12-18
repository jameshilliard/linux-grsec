#include <linux/export.h>
#include <asm/byteorder.h>

typedef int word_type __attribute__ ((mode (__word__)));

typedef int DWtype __attribute__((mode(TI)));

struct DWstruct {
	long high, low;
};

typedef union {
	struct DWstruct s;
	DWtype ll;
} DWunion;

DWtype notrace __ashlti3(DWtype u, word_type b)
{
	DWunion uu, w;
	word_type bm;

	if (b == 0)
		return u;

	uu.ll = u;
	bm = BITS_PER_LONG - b;

	if (bm <= 0) {
		w.s.low = 0;
		w.s.high = (unsigned long) uu.s.low << -bm;
	} else {
		const unsigned long carries = (unsigned long) uu.s.low >> bm;

		w.s.low = (unsigned long) uu.s.low << b;
		w.s.high = ((unsigned long) uu.s.high << b) | carries;
	}

	return w.ll;
}
EXPORT_SYMBOL(__ashlti3);

DWtype notrace __ashrti3(DWtype u, word_type b)
{
	DWunion uu, w;
	word_type bm;

	if (b == 0)
		return u;

	uu.ll = u;
	bm = BITS_PER_LONG - b;

	if (bm <= 0) {
		/* w.s.high = 1..1 or 0..0 */
		w.s.high =
		    uu.s.high >> (BITS_PER_LONG - 1);
		w.s.low = uu.s.high >> -bm;
	} else {
		const unsigned long carries = (unsigned long) uu.s.high << bm;

		w.s.high = uu.s.high >> b;
		w.s.low = ((unsigned long) uu.s.low >> b) | carries;
	}

	return w.ll;
}
EXPORT_SYMBOL(__ashrti3);
