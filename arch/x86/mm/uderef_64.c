#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>

#ifdef CONFIG_PAX_MEMORY_UDEREF
/* PaX: due to the special call convention these functions must
 * - remain leaf functions under all configurations,
 * - never be called directly, only dereferenced from the wrappers.
 */
void __used __pax_open_userland(void)
{
	unsigned int cpu;

	if (unlikely(!segment_eq(get_fs(), USER_DS)))
		return;

	cpu = raw_get_cpu();
	BUG_ON((read_cr3() & ~PAGE_MASK) != PCID_KERNEL);
	if (static_cpu_has(X86_FEATURE_PCID))
		write_cr3(__pa_nodebug(get_cpu_pgd(cpu, uaccess)) | PCID_USER | PCID_NOFLUSH);
	else
		write_cr3(__pa_nodebug(get_cpu_pgd(cpu, uaccess)) | PCID_KERNEL);
	raw_put_cpu_no_resched();
}
EXPORT_SYMBOL(__pax_open_userland);

void __used __pax_close_userland(void)
{
	unsigned int cpu;

	if (unlikely(!segment_eq(get_fs(), USER_DS)))
		return;

	cpu = raw_get_cpu();
	if (static_cpu_has(X86_FEATURE_PCID)) {
		BUG_ON((read_cr3() & ~PAGE_MASK) != PCID_USER);
		write_cr3(__pa_nodebug(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL | PCID_NOFLUSH);
	} else {
		BUG_ON((read_cr3() & ~PAGE_MASK) != PCID_KERNEL);
		write_cr3(__pa_nodebug(get_cpu_pgd(cpu, kernel)) | PCID_KERNEL);
	}
	raw_put_cpu_no_resched();
}
EXPORT_SYMBOL(__pax_close_userland);
#endif
