#ifndef __LINUX_KCONFIG_H
#define __LINUX_KCONFIG_H

#include <generated/autoconf.h>

#ifndef __ASSEMBLY__
extern struct missing_include_for_attribute __do_const;
extern struct missing_include_for_attribute __intentional_overflow;
extern struct missing_include_for_attribute __latent_entropy;
extern struct missing_include_for_attribute __mutable_const;
extern struct missing_include_for_attribute __nocapture;
extern struct missing_include_for_attribute __no_const;
extern struct missing_include_for_attribute __no_randomize_layout;
extern struct missing_include_for_attribute __randomize_layout;
extern struct missing_include_for_attribute __rap_hash;
extern struct missing_include_for_attribute __size_overflow;
extern struct missing_include_for_attribute __skip_size_overflow;
extern struct missing_include_for_attribute __turn_off_size_overflow;
extern struct missing_include_for_attribute __unverified_nocapture;

extern struct missing_include_for_attribute __aligned;
extern struct missing_include_for_attribute __alloc_size;
extern struct missing_include_for_attribute __assume_aligned;
extern struct missing_include_for_attribute __attribute_const__;
extern struct missing_include_for_attribute __bos;
extern struct missing_include_for_attribute __bos0;
extern struct missing_include_for_attribute __bos1;
extern struct missing_include_for_attribute ____cacheline_aligned;
extern struct missing_include_for_attribute ____cacheline_aligned_in_smp;
extern struct missing_include_for_attribute ____cacheline_internodealigned_in_smp;
extern struct missing_include_for_attribute __malloc;
extern struct missing_include_for_attribute __must_check;
extern struct missing_include_for_attribute __naked;
extern struct missing_include_for_attribute __noclone;
extern struct missing_include_for_attribute __noreturn;
extern struct missing_include_for_attribute __no_sanitize_address;
extern struct missing_include_for_attribute __nostackprotector;
extern struct missing_include_for_attribute __packed;
extern struct missing_include_for_attribute __printf;
extern struct missing_include_for_attribute __pure;
extern struct missing_include_for_attribute __scanf;
extern struct missing_include_for_attribute __used;
extern struct missing_include_for_attribute __visible;
extern struct missing_include_for_attribute __weak;
#endif

/*
 * Helper macros to use CONFIG_ options in C/CPP expressions. Note that
 * these only work with boolean and tristate options.
 */

/*
 * Getting something that works in C and CPP for an arg that may or may
 * not be defined is tricky.  Here, if we have "#define CONFIG_BOOGER 1"
 * we match on the placeholder define, insert the "0," for arg1 and generate
 * the triplet (0, 1, 0).  Then the last step cherry picks the 2nd arg (a one).
 * When CONFIG_BOOGER is not defined, we generate a (... 1, 0) pair, and when
 * the last step cherry picks the 2nd arg, we get a zero.
 */
#define __ARG_PLACEHOLDER_1 0,
#define config_enabled(cfg)		___is_defined(cfg)
#define __is_defined(x)			___is_defined(x)
#define ___is_defined(val)		____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk)	__take_second_arg(arg1_or_junk 1, 0)
#define __take_second_arg(__ignored, val, ...) val

/*
 * IS_BUILTIN(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y', 0
 * otherwise. For boolean options, this is equivalent to
 * IS_ENABLED(CONFIG_FOO).
 */
#define IS_BUILTIN(option) config_enabled(option)

/*
 * IS_MODULE(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'm', 0
 * otherwise.
 */
#define IS_MODULE(option) config_enabled(option##_MODULE)

/*
 * IS_REACHABLE(CONFIG_FOO) evaluates to 1 if the currently compiled
 * code can call a function defined in code compiled based on CONFIG_FOO.
 * This is similar to IS_ENABLED(), but returns false when invoked from
 * built-in code when CONFIG_FOO is set to 'm'.
 */
#define IS_REACHABLE(option) (config_enabled(option) || \
		 (config_enabled(option##_MODULE) && __is_defined(MODULE)))

/*
 * IS_ENABLED(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y' or 'm',
 * 0 otherwise.
 */
#define IS_ENABLED(option) \
	(IS_BUILTIN(option) || IS_MODULE(option))

#endif /* __LINUX_KCONFIG_H */
