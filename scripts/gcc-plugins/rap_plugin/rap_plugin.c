/*
 * Copyright 2012-2017 by PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Homepage: http://pax.grsecurity.net/
 *
 * Usage:
 * $ # for 4.5/4.6/C based 4.7
 * $ gcc -I`gcc -print-file-name=plugin`/include -I`gcc -print-file-name=plugin`/include/c-family -fPIC -shared -O2 -o rap_plugin.so rap_plugin.c
 * $ # for C++ based 4.7/4.8+
 * $ g++ -I`g++ -print-file-name=plugin`/include -I`g++ -print-file-name=plugin`/include/c-family -fPIC -shared -O2 -o rap_plugin.so rap_plugin.c
 * $ gcc -fplugin=./rap_plugin.so -fplugin-arg-rap_plugin-check=call test.c -O2
 *
 * This plugin implements the Reuse Attack Protector (RAP) Control Flow Integrity (CFI) scheme
 * along with a poor man's emulation of non-executable kernel memory on amd64 (KERNEXEC) and
 * a defense mechanism against Spectre v2 (CVE-2017-5715, branch target injection). Since all
 * of these defenses instrument around the same code, there's an ordering requirement and thus
 * the need to implement them together. That said, they can all be invidiually enabled during
 * compilation.
 *
 * The instrumented code under various configurations looks like this:
 *
 * Indirect calls (forward edge), including tail calls (implemented as indirect jumps)
 *
 *                           all inlined                thunked retpoline                  no retpoline
 *    ---------------------------------------------------------------------------------------------------------
 *    load fptr              mov (fptr), %rax           mov (fptr), %rax                   mov (fptr), %rax
 *    ---------------------------------------------------------------------------------------------------------
 *    kernexec               bts $63, %rax              bts $63, %rax                      bts $63, %rax
 *    ---------------------------------------------------------------------------------------------------------
 *    rap fptr check         cmpq $hash, -8(%rax)       cmpq $hash, -8(%rax)               cmpq $hash, -8(%rax)
 *                           jnz .bad                   jnz .bad                           jnz .bad
 *    ---------------------------------------------------------------------------------------------------------
 *    retpoline              jmp 1f
 *                        2: call 3f
 *                        4: pause
 *                           lfence
 *                           jmp 4b
 *                        3: mov %rax, (%rsp)
 *                           ret
 *    ---------------------------------------------------------------------------------------------------------
 *                                                      jmp 1f                             jmp 1f
 *    rap return check       movabs -$hash, %rax        movabs -$hash, %rax                movabs -$hash, %rax
 *                           .fill padding              .fill padding                      .fill padding
 *    ---------------------------------------------------------------------------------------------------------
 *    retpoline           1: call 2b                 1: call __x86_indirect_thunk_rax
 *    ---------------------------------------------------------------------------------------------------------
 *    original call                                                                     1: call *%rax
 *
 */

#include "rap.h"

__visible int plugin_is_GPL_compatible;

static struct plugin_info rap_plugin_info = {
	.version	= "201802112315",
	.help		= "typecheck=ret,call,nospec\tenable the corresponding type hash checking based features\n"
			  "retabort=ud2\t\t\toverride __builtin_trap with specified asm for both kinds of return address checking\n"
			  "callabort=ud2\t\t\toverride __builtin_trap with specified asm for indirect call checking\n"
			  "hash=abs,abs-finish,abs-ops,abs-attr,const,volatile\n"
			  "report=func,fptr,abs\n"
			  "include=<file>\t\t\tinclude <file> into all translation units to provide various RAP macros instead of the builtin ones\n"
			  "kernexec_method=[bts|or]\tKERNEXEC instrumentation method\n"
};

rap_hash_flags_t imprecise_rap_hash_flags = {
	.qual_const	= 1,
	.qual_volatile	= 1,
};

tree rap_hash_type_node;

static bool report_func_hash, report_abs_hash;
const char *rap_ret_abort;
const char *rap_call_abort;
const char *rap_include;

bool enable_type_ret = false;
bool enable_type_call = false;
bool enable_type_nospec = false;
bool enable_abs_attr = false;

// create the equivalent of
// asm volatile("" : : : "memory");
// or
// asm("" : "+rm"(var));
// or
// asm("" : : "rm"(var));
gimple barrier(tree var, bool full)
{
	gimple stmt;
	gasm *asm_stmt;
#if BUILDING_GCC_VERSION <= 4007
	VEC(tree, gc) *inputs = NULL;
	VEC(tree, gc) *outputs = NULL;
	VEC(tree, gc) *clobbers = NULL;
#else
	vec<tree, va_gc> *inputs = NULL;
	vec<tree, va_gc> *outputs = NULL;
	vec<tree, va_gc> *clobbers = NULL;
#endif

	if (!var && full) {
		tree clobber;

		clobber = build_tree_list(NULL_TREE, build_const_char_string(7, "memory"));
#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(tree, gc, clobbers, clobber);
#else
		vec_safe_push(clobbers, clobber);
#endif
	} else if (full) {
		tree input, output;

		input = build_tree_list(NULL_TREE, build_const_char_string(2, "0"));
		input = chainon(NULL_TREE, build_tree_list(input, var));
#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(tree, gc, inputs, input);
#else
		vec_safe_push(inputs, input);
#endif

		output = build_tree_list(NULL_TREE, build_const_char_string(4, "=rm"));
		gcc_assert(SSA_NAME_VAR(var));
		var = make_ssa_name(SSA_NAME_VAR(var), NULL);
		output = chainon(NULL_TREE, build_tree_list(output, var));
#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(tree, gc, outputs, output);
#else
		vec_safe_push(outputs, output);
#endif
	} else {
		tree input;

		input = build_tree_list(NULL_TREE, build_const_char_string(3, "rm"));
		input = chainon(NULL_TREE, build_tree_list(input, var));
#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(tree, gc, inputs, input);
#else
		vec_safe_push(inputs, input);
#endif
	}

	stmt = gimple_build_asm_vec("", inputs, outputs, clobbers, NULL);
	asm_stmt = as_a_gasm(stmt);
	if (!var && full)
		gimple_asm_set_volatile(asm_stmt, true);
	else if (full)
		SSA_NAME_DEF_STMT(var) = stmt;
	return stmt;
}

gimple ibarrier(tree var)
{
	gimple stmt;
	gasm *asm_stmt;
#if BUILDING_GCC_VERSION <= 4007
	VEC(tree, gc) *inputs = NULL;
	VEC(tree, gc) *outputs = NULL;
	VEC(tree, gc) *clobbers = NULL;
#else
	vec<tree, va_gc> *inputs = NULL;
	vec<tree, va_gc> *outputs = NULL;
	vec<tree, va_gc> *clobbers = NULL;
#endif

	tree input, output;

	input = build_tree_list(NULL_TREE, build_const_char_string(2, "0"));
	input = chainon(NULL_TREE, build_tree_list(input, var));
#if BUILDING_GCC_VERSION <= 4007
	VEC_safe_push(tree, gc, inputs, input);
#else
	vec_safe_push(inputs, input);
#endif

	output = build_tree_list(NULL_TREE, build_const_char_string(4, "=rm"));
	if (SSA_NAME_VAR(var))
		var = make_ssa_name(SSA_NAME_VAR(var), NULL);
	else
#if BUILDING_GCC_VERSION >= 4008
		var = make_temp_ssa_name(TREE_TYPE(var), NULL, "rap_ibarrier");
#else
		gcc_unreachable();
#endif
	output = chainon(NULL_TREE, build_tree_list(output, var));
#if BUILDING_GCC_VERSION <= 4007
	VEC_safe_push(tree, gc, outputs, output);
#else
	vec_safe_push(outputs, output);
#endif

	stmt = gimple_build_asm_vec("lfence", inputs, outputs, clobbers, NULL);
	asm_stmt = as_a_gasm(stmt);
	gimple_asm_set_volatile(asm_stmt, true);
	SSA_NAME_DEF_STMT(var) = stmt;

	return stmt;
}

static const struct gcc_debug_hooks *old_debug_hooks;
static struct gcc_debug_hooks rap_debug_hooks;

static bool __rap_cgraph_indirectly_callable(cgraph_node_ptr node, void *data __unused)
{
#if BUILDING_GCC_VERSION >= 4008
	if (NODE_SYMBOL(node)->externally_visible)
#else
	if (node->local.externally_visible)
#endif
		return true;

	if (NODE_SYMBOL(node)->address_taken)
		return true;

	if (DECL_STATIC_CONSTRUCTOR(NODE_DECL(node)) || DECL_STATIC_DESTRUCTOR(NODE_DECL(node)))
		return true;

	return false;
}

static bool rap_cgraph_indirectly_callable(cgraph_node_ptr node)
{
	return cgraph_for_node_and_aliases(node, __rap_cgraph_indirectly_callable, NULL, true);
}

static void rap_hash_align(const_tree decl)
{
	unsigned HOST_WIDE_INT rap_hash_offset;
	unsigned HOST_WIDE_INT skip;

	skip = 1ULL << align_functions_log;
	if (DECL_USER_ALIGN(decl))
		return;

//	if (!optimize_function_for_speed_p(cfun))
//		return;

	if (UNITS_PER_WORD == 8)
		rap_hash_offset = 2 * sizeof(rap_hash_t);
	else if (UNITS_PER_WORD == 4)
		rap_hash_offset =  sizeof(rap_hash_t);
	else
		gcc_unreachable();

#ifdef TARGET_386
	if (skip <= rap_hash_offset)
		skip = UNITS_PER_WORD == 8 ? 2 : 1;
	else
		skip -= rap_hash_offset;
	{
		char padding[skip];

		// this byte sequence helps disassemblers not trip up on the following rap hash
		memset(padding, 0xcc, sizeof padding - 1);
		padding[sizeof padding - 1] = 0xb8;
		if (UNITS_PER_WORD == 8 && sizeof padding > 1)
			padding[sizeof padding - 2] = 0x48;
		ASM_OUTPUT_ASCII(asm_out_file, padding, sizeof padding);
	}
#else
	if (skip > rap_hash_offset)
		ASM_OUTPUT_SKIP(asm_out_file, skip - rap_hash_offset);
#endif
}

static void rap_begin_function(tree decl)
{
	cgraph_node_ptr node;
	rap_hash_t imprecise_rap_hash;

	gcc_assert(debug_hooks == &rap_debug_hooks);

	// chain to previous callback
	if (old_debug_hooks && old_debug_hooks->begin_function)
		old_debug_hooks->begin_function(decl);

	// align the rap hash if necessary
	rap_hash_align(decl);

	// don't compute hash for functions called only directly
	node = cgraph_get_node(decl);
	gcc_assert(node);
	if (!rap_cgraph_indirectly_callable(node)) {
		imprecise_rap_hash.hash = 0;
	} else {
		imprecise_rap_hash = rap_hash_function_node_imprecise(node);
	}

	if (report_func_hash)
		inform(DECL_SOURCE_LOCATION(decl), "func rap_hash: %x %s", imprecise_rap_hash.hash, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(decl)));

	if (UNITS_PER_WORD == 8)
		fprintf(asm_out_file, "\t.quad %#llx\t%s __rap_hash_call_%s\n", (long long)imprecise_rap_hash.hash, ASM_COMMENT_START, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(decl)));
	else
		fprintf(asm_out_file, "\t.long %#x\t%s __rap_hash_call_%s\n", imprecise_rap_hash.hash, ASM_COMMENT_START, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(decl)));
}

static void rap_emit_hash_symbol(const char *type, const char *asmname, rap_hash_t hash)
{
	char *name = NULL;

	gcc_assert(asprintf(&name, "__rap_hash_%s_%s", type, asmname) != -1);

	fprintf(asm_out_file, "\t.pushsection .text\n");

	fprintf(asm_out_file, GLOBAL_ASM_OP " %s\n", name);
	if (UNITS_PER_WORD == 8)
		fprintf(asm_out_file, "\t.offset %#018llx\n", (long long)hash.hash);
	else if (UNITS_PER_WORD == 4)
		fprintf(asm_out_file, "\t.offset %#010x\n", hash.hash);
	else
		gcc_unreachable();

	ASM_OUTPUT_TYPE_DIRECTIVE(asm_out_file, name, "object");
	ASM_OUTPUT_LABEL(asm_out_file, name);
	free(name);

	fprintf(asm_out_file, "\t.popsection\n");
}

static void rap_emit_hash_symbols(const char *asmname, rap_hash_t hash)
{

	rap_emit_hash_symbol("call", asmname, hash);
	hash.hash = -hash.hash;
	rap_emit_hash_symbol("ret", asmname, hash);
}

/*
   emit an absolute symbol for each function that may be referenced through the plt
     - all externs
     - non-static functions
       - use visibility instead?

   .globl __rap_hash_call_func
   .offset 0xhash_for_func
   .type __rap_hash_call_func, @object
   __rap_hash_call_func:
   .previous
*/
static void rap_finish_unit(void *gcc_data __unused, void *user_data __unused)
{
	cgraph_node_ptr node;
	rap_hash_t hash;

	gcc_assert(debug_hooks == &rap_debug_hooks);

	hash.hash = 0;
	FOR_EACH_FUNCTION(node) {
		tree fndecl;
		const char *asmname;

		if (node->thunk.thunk_p || node->alias)
			continue;
		if (cgraph_function_body_availability(node) >= AVAIL_INTERPOSABLE) {
			if (!rap_cgraph_indirectly_callable(node))
				continue;
		}

#if BUILDING_GCC_VERSION >= 4007
		gcc_assert(cgraph_function_or_thunk_node(node, NULL) == node);
#endif

		fndecl = NODE_DECL(node);
		gcc_assert(fndecl);
		if (DECL_IS_BUILTIN(fndecl) && DECL_BUILT_IN_CLASS(fndecl) == BUILT_IN_NORMAL)
			continue;

		if (!TREE_PUBLIC(fndecl))
			continue;

		if (DECL_ARTIFICIAL(fndecl))
			continue;

		if (DECL_ABSTRACT_ORIGIN(fndecl) && DECL_ABSTRACT_ORIGIN(fndecl) != fndecl)
			continue;

		gcc_assert(DECL_ASSEMBLER_NAME(fndecl));
		asmname = IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(fndecl));
		if (strchr(asmname, '.'))
			continue;

		if (asmname[0] == '*')
			asmname++;

		gcc_assert(asmname[0]);

		hash = rap_hash_function_node_imprecise(node);
		if (report_abs_hash)
			inform(DECL_SOURCE_LOCATION(fndecl), "abs rap_hash: %x %s", hash.hash, IDENTIFIER_POINTER(DECL_ASSEMBLER_NAME(fndecl)));
		rap_emit_hash_symbols(asmname, hash);
	}
}

// emit the rap hash as an absolute symbol for all functions seen in the frontend
// this is necessary as later unreferenced nodes will be removed yet we'd like to emit as many hashes as possible
static void rap_emit_hash_symbols_finish_decl(void *event_data, void *data __unused)
{
	tree fndecl = (tree)event_data;
	rap_hash_t hash;
	const char *asmname;

	if (fndecl == error_mark_node)
		return;

	if (TREE_CODE(fndecl) != FUNCTION_DECL)
		return;

	if (!TREE_PUBLIC(fndecl))
		return;

	if (DECL_ARTIFICIAL(fndecl))
		return;

	if (DECL_ABSTRACT_ORIGIN(fndecl) && DECL_ABSTRACT_ORIGIN(fndecl) != fndecl)
		return;

	asmname = DECL_NAME_POINTER(fndecl);
	gcc_assert(asmname[0]);

	if (strchr(asmname, '.'))
		return;

	hash = rap_hash_function_decl(fndecl, imprecise_rap_hash_flags);
	rap_emit_hash_symbols(asmname, hash);
	if (report_abs_hash)
		inform(DECL_SOURCE_LOCATION(fndecl), "abs rap_hash: %x %s", hash.hash, asmname);
}

static void rap_emit_hash_symbols_type(const_tree type, const char *prefix)
{
	const_tree field;

	if (TYPE_FIELDS(type) == NULL_TREE)
		return;

	// TODO skip constified types for now
	if (TYPE_READONLY(type))
		return;

	// create the prefix if it hasn't been done yet
	if (!*prefix) {
		const_tree name = type_name(type);

		// skip an anonymous struct embedded inside another one
		// we'll see it when we walk the parent later
		if (!name)
			return;

		prefix = IDENTIFIER_POINTER(name);
		gcc_assert(*prefix);
	}

	for (field = TYPE_FIELDS(type); field; field = TREE_CHAIN(field)) {
		const_tree fieldtype, fieldname;
		char *hashname = NULL, *newprefix = NULL;
		rap_hash_t hash;

		fieldtype = TREE_TYPE(field);
		switch (TREE_CODE(fieldtype)) {
		default:
			continue;

		case RECORD_TYPE:
		case UNION_TYPE:
			fieldname = DECL_NAME(field);
			if (!fieldname)
				continue;
			gcc_assert(asprintf(&newprefix, "%s.%s", prefix, IDENTIFIER_POINTER(fieldname)) != -1);
			rap_emit_hash_symbols_type(fieldtype, newprefix);
			free(newprefix);
			continue;

		case POINTER_TYPE:
			fieldtype = TREE_TYPE(fieldtype);
			if (TREE_CODE(fieldtype) != FUNCTION_TYPE)
				continue;

			hash = rap_hash_function_type(fieldtype, imprecise_rap_hash_flags);
			fieldname = DECL_NAME(field);
			gcc_assert(fieldname);
			gcc_assert(asprintf(&hashname, "%s.%s", prefix, IDENTIFIER_POINTER(fieldname)) != -1);
			if (report_abs_hash)
				inform(DECL_SOURCE_LOCATION(field), "abs rap_hash: %x %s", hash.hash, hashname);
			rap_emit_hash_symbols(hashname, hash);
			free(hashname);
			continue;
		}
	}
}

static void rap_emit_hash_symbols_finish_type(void *event_data, void *data __unused)
{
	const_tree type = (const_tree)event_data;

	if (type == NULL_TREE || type == error_mark_node)
		return;

	if (!lookup_attribute("rap_hash", TYPE_ATTRIBUTES(type)))
		return;

	switch (TREE_CODE(type)) {
	default:
		debug_tree(type);
		gcc_unreachable();

#if BUILDING_GCC_VERSION >= 5000
	case ENUMERAL_TYPE:
#endif
	case UNION_TYPE:
		break;

	case RECORD_TYPE:
		rap_emit_hash_symbols_type(type, "");
		break;
	}
}

static void rap_assembly_start(void)
{
	gcc_assert(debug_hooks == &rap_debug_hooks);

	// chain to previous callback
	if (old_debug_hooks && old_debug_hooks->assembly_start)
		old_debug_hooks->assembly_start();

#ifdef TARGET_386
	if (rap_include)
		fprintf(asm_out_file, "\t.include \"%s\"\n", rap_include);

	if (enable_type_call || enable_type_ret) {
		fprintf(asm_out_file, "%s",
			"\t.macro rap_abort kind:req reg:req\n"
			"\t\t.ifc \\reg,%eax\n"
			"\t\t\t.byte 0x0f,0xb9,0x00|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%ecx\n"
			"\t\t\t.byte 0x0f,0xb9,0x08|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%edx\n"
			"\t\t\t.byte 0x0f,0xb9,0x10|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%ebx\n"
			"\t\t\t.byte 0x0f,0xb9,0x18|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%esp\n"
			"\t\t\t.byte 0x0f,0xb9,0x20|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%ebp\n"
			"\t\t\t.byte 0x0f,0xb9,0x28|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%esi\n"
			"\t\t\t.byte 0x0f,0xb9,0x30|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%edi\n"
			"\t\t\t.byte 0x0f,0xb9,0x38|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%r8d\n"
			"\t\t\t.byte 0x0f,0xb9,0x02|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%r9d\n"
			"\t\t\t.byte 0x0f,0xb9,0x0a|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%r10d\n"
			"\t\t\t.byte 0x0f,0xb9,0x12|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%r11d\n"
			"\t\t\t.byte 0x0f,0xb9,0x1a|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%r12d\n"
			"\t\t\t.byte 0x0f,0xb9,0x22|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%r13d\n"
			"\t\t\t.byte 0x0f,0xb9,0x2a|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%r14d\n"
			"\t\t\t.byte 0x0f,0xb9,0x32|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.ifc \\reg,%r15d\n"
			"\t\t\t.byte 0x0f,0xb9,0x3a|\\kind\n"
			"\t\t\t.exitm\n"
			"\t\t.endif\n"

			"\t\t.error \"unknown register \\reg\"\n"
			"\t.endm\n"
		);
	}

	if (enable_type_call) {
		fprintf(asm_out_file,
			"\t.macro rap_indirect_call target:req hash:req\n"
			"\t\tjmp .Lrap_call_target_\\@\n"
			"\t\t%s\n"
			"\t\t%s __rap_hash_ret_\\hash\n"
			"\t\t.skip 8-(.Lrap_call_target_end_\\@-.Lrap_call_target_\\@),0xcc\n"
			"\t.Lrap_call_target_\\@:\n"
			"\t\tcall \\target\n"
			"\t.Lrap_call_target_end_\\@:\n"
			"\t.endm\n",
			(UNITS_PER_WORD == 8 ? ".byte 0x48, 0xb8" : ".byte 0xb8"),
			(UNITS_PER_WORD == 8 ? ".quad" : ".long")
		);

		fprintf(asm_out_file,
			"\t.macro rap_direct_call target:req hash=\"\"\n"
			"\t\t.ifb \\hash\n"
			"\t\t\trap_indirect_call \\target, \\target\n"
			"\t\t.else\n"
			"\t\t\trap_indirect_call \\target, \\hash\n"
			"\t\t.endif\n"
			"\t.endm\n"
		);

		fprintf(asm_out_file,
			"\t.macro rap_paravirt_call target:req hash:req\n"
			"\t\trap_indirect_call *\\target, \\hash\n"
			"\t.endm\n"
		);

		fprintf(asm_out_file,
			"\t.macro rap_call_abort reg:req\n"
			"\t\trap_abort 1,\\reg\n"
			"\t.endm\n"
		);
	}

	if (enable_type_ret) {
		if (!rap_include)
			fprintf(asm_out_file,
				"\t.macro rap_ret func:req\n"
				"\t\tret\n"
				"\t.endm\n"
			);

		fprintf(asm_out_file,
			"\t.macro rap_ret_abort reg:req\n"
			"\t\trap_abort 0,\\reg\n"
			"\t.endm\n"
		);
	}
#else
#error unsupported target
#endif
}

static void (*old_override_options_after_change)(void);
#if BUILDING_GCC_VERSION >= 4006
static void (*old_override_asm_out_print_operand)(FILE *file, rtx x, int code);
#endif
#if BUILDING_GCC_VERSION >= 6000
# ifndef ix86_indirect_branch_register
static rtx_insn *(*old_override_gen_tablejump)(rtx, rtx);
# endif
#endif

static void rap_override_options_after_change(void)
{
	if (old_override_options_after_change)
		old_override_options_after_change();

#if BUILDING_GCC_VERSION >= 5000
	flag_ipa_icf_functions = 0;
#endif

#if BUILDING_GCC_VERSION >= 7000
	flag_code_hoisting = 0;
#endif

#if BUILDING_GCC_VERSION >= 8000
	flag_cf_protection = CF_NONE;
	flag_reorder_blocks_and_partition = 0;
#endif

	if (enable_type_ret) {
		flag_crossjumping = 0;
		flag_optimize_sibling_calls = 0;
	}

	if (enable_type_nospec) {
#ifdef ix86_indirect_branch
		ix86_indirect_branch = indirect_branch_keep;
		ix86_indirect_branch_register = 1;
#endif

#if BUILDING_GCC_VERSION < 6000
		flag_jump_tables = 0;
#endif
	}
}

#if BUILDING_GCC_VERSION >= 4006
static void rap_override_asm_out_print_operand(FILE *file, rtx x, int code)
{
	if (ASSEMBLER_DIALECT == ASM_ATT && code == 'V') {
		if (!REG_P(x)) {
			print_rtl_single(stderr, x);
			gcc_unreachable();
		}
		ASSEMBLER_DIALECT = ASM_INTEL;
		print_reg(x, code, file);
		ASSEMBLER_DIALECT = ASM_ATT;
	} else
		old_override_asm_out_print_operand(file, x, code);
}
#endif

#if BUILDING_GCC_VERSION >= 6000
#ifndef ix86_indirect_branch_register
static rtx_insn *rap_override_gen_tablejump(rtx operand0, rtx operand1)
{
	rtx_insn *retpoline;
	rtx reg, body, clobbers;
	rtvec argvec, constraintvec, labelvec;

	gcc_assert(REG_P(operand0));
	reg = operand0;

	argvec = rtvec_alloc(1);
	constraintvec = rtvec_alloc(1);
	labelvec = rtvec_alloc(0);

	start_sequence();

	body = gen_rtx_ASM_OPERANDS(GET_MODE(reg), ggc_strdup(""), empty_string, 0, argvec, constraintvec, labelvec, UNKNOWN_LOCATION);
	MEM_VOLATILE_P(body) = 1;
	ASM_OPERANDS_INPUT(body, 0) = reg;
	ASM_OPERANDS_INPUT_CONSTRAINT_EXP(body, 0) = gen_rtx_ASM_INPUT_loc(GET_MODE(reg), ggc_strdup("0"), UNKNOWN_LOCATION);
	ASM_OPERANDS_OUTPUT_CONSTRAINT(body) = ggc_strdup("=r");
	emit_insn(gen_rtx_set(reg, body));

	emit_jump_insn(gen_rtx_PARALLEL(VOIDmode, gen_rtvec(2, gen_rtx_set(pc_rtx, operand0), gen_rtx_USE(VOIDmode, gen_rtx_LABEL_REF(VOIDmode, operand1)))));
	retpoline = get_insns();
	end_sequence();

	return retpoline;
}
#endif
#endif

static void rap_start_unit_common(void *gcc_data __unused, void *user_data __unused)
{
	rap_hash_type_node = long_integer_type_node;

	if (debug_hooks)
		rap_debug_hooks = *debug_hooks;

	if (enable_type_call || enable_type_ret || rap_include)
		rap_debug_hooks.assembly_start = rap_assembly_start;
	if (enable_type_call || enable_type_ret)
		rap_debug_hooks.begin_function = rap_begin_function;

	old_debug_hooks = debug_hooks;
	debug_hooks = &rap_debug_hooks;

	old_override_options_after_change = targetm.override_options_after_change;
	targetm.override_options_after_change = rap_override_options_after_change;

	if (enable_type_nospec) {
#if BUILDING_GCC_VERSION >= 4006
		if (targetm.asm_out.print_operand) {
			old_override_asm_out_print_operand = targetm.asm_out.print_operand;
			targetm.asm_out.print_operand = rap_override_asm_out_print_operand;
		}
#endif

#if BUILDING_GCC_VERSION >= 6000
# ifndef ix86_indirect_branch_register
		if (targetm.gen_tablejump) {
			old_override_gen_tablejump = targetm.gen_tablejump;
			targetm.gen_tablejump = rap_override_gen_tablejump;
		}
# endif
#endif
	}
}

static bool rap_unignore_gate(void)
{
	if (!DECL_IGNORED_P(current_function_decl))
		return false;

//	inform(DECL_SOURCE_LOCATION(current_function_decl), "DECL_IGNORED fixed");

	DECL_IGNORED_P(current_function_decl) = 0;
	return false;
}

#define PASS_NAME rap_unignore
#define NO_EXECUTE
#define TODO_FLAGS_FINISH TODO_dump_func
#include "gcc-generate-rtl-pass.h"

static bool rap_version_check(struct plugin_gcc_version *gcc_version, struct plugin_gcc_version *plugin_version)
{
	if (!gcc_version || !plugin_version)
		return false;

#if BUILDING_GCC_VERSION >= 5000
	if (strncmp(gcc_version->basever, plugin_version->basever, 4))
#else
	if (strcmp(gcc_version->basever, plugin_version->basever))
#endif
		return false;
	if (strcmp(gcc_version->datestamp, plugin_version->datestamp))
		return false;
	if (strcmp(gcc_version->devphase, plugin_version->devphase))
		return false;
	if (strcmp(gcc_version->revision, plugin_version->revision))
		return false;
//	if (strcmp(gcc_version->configuration_arguments, plugin_version->configuration_arguments))
//		return false;
	return true;
}

static tree handle_rap_hash_attribute(tree *node, tree name, tree args __unused, int flags, bool *no_add_attrs)
{
	*no_add_attrs = true;

	switch (TREE_CODE(*node)) {
	default:
		error("%qE attribute applies to structure types and function declarations only (%qD)", name, *node);
		return NULL_TREE;

	case FUNCTION_DECL:
		if (enable_abs_attr)
			rap_emit_hash_symbols_finish_decl(*node, NULL);
		return NULL_TREE;

	case RECORD_TYPE:
		break;
	}

	*no_add_attrs = false;
	return NULL_TREE;
}

static tree handle_indirect_branch_attribute(tree *node, tree name, tree args __unused, int flags, bool *no_add_attrs)
{
	tree value;
	const char *ibranch_type;

	*no_add_attrs = true;

	gcc_assert(DECL_P(*node));

	switch (TREE_CODE(*node)) {
	default:
		error("%qE attribute applies to functions only (%qD)", name, *node);
		return NULL_TREE;

	case FUNCTION_DECL:
		break;
	}

	value = TREE_VALUE(args);
	if (TREE_CODE(value) != STRING_CST) {
		error_at(DECL_SOURCE_LOCATION(*node), "%qE attribute requires a string constant argument, not %qE", name, value);
		return NULL_TREE;
	}

	ibranch_type = TREE_STRING_POINTER(value);
#if 0
	// TODO we don't support gcc generated retpoline thunks for now
	if (strcmp(ibranch_type, "keep") && strcmp(ibranch_type, "thunk") && strcmp(ibranch_type, "thunk-inline") && strcmp(ibranch_type, "thunk-extern")) {
		error_at(DECL_SOURCE_LOCATION(*node), "argument to %qE attribute is %qE, must be one of keep|thunk|thunk-inline|thunk-extern", name, value);
#else
	if (strcmp(ibranch_type, "keep") && strcmp(ibranch_type, "thunk-extern")) {
		error_at(DECL_SOURCE_LOCATION(*node), "argument to %qE attribute is %qE, must be keep or thunk-extern", name, value);
#endif
		return NULL_TREE;
	}

	*no_add_attrs = false;
	return NULL_TREE;
}

static struct attribute_spec rap_hash_attr = ATTRIBUTE_SPEC_INIT("rap_hash", 0, 0, false, false, false, handle_rap_hash_attribute, true, NULL);
static struct attribute_spec indirect_branch_attr = ATTRIBUTE_SPEC_INIT("indirect_branch", 1, 1, true, false, false, handle_indirect_branch_attribute, false, NULL);

static void register_attributes(void *event_data __unused, void *data __unused)
{
	if (enable_type_call || enable_type_ret)
		register_attribute(&rap_hash_attr);

#ifdef TARGET_386
	if (enable_type_nospec && !lookup_attribute_spec(get_identifier("indirect_branch")))
		register_attribute(&indirect_branch_attr);
#endif
}

EXPORTED_CONST struct ggc_root_tab gt_ggc_r_gt_rap[] = {
	{
		.base = &rap_hash_type_node,
		.nelt = 1,
		.stride = sizeof(rap_hash_type_node),
		.cb = &gt_ggc_mx_tree_node,
		.pchw = &gt_pch_nx_tree_node
	},
	LAST_GGC_ROOT_TAB
};

__visible int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	int i;
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	bool enable_abs = false;
	bool enable_abs_finish = false;
	bool enable_abs_ops = false;

	PASS_INFO(rap_ret,				"optimized",		1, PASS_POS_INSERT_AFTER);
	PASS_INFO(rap_fptr,				"rap_ret",		1, PASS_POS_INSERT_AFTER);
#ifdef TARGET_386
# ifndef ix86_indirect_branch
	PASS_INFO(rap_indirect_branch_register,		"vregs",		1, PASS_POS_INSERT_BEFORE);
# endif
#endif
	PASS_INFO(rap_mark_retloc,			"mach",			1, PASS_POS_INSERT_AFTER);
	PASS_INFO(rap_retpoline,			"shorten",		1, PASS_POS_INSERT_BEFORE);
	PASS_INFO(rap_unignore,				"final",		1, PASS_POS_INSERT_BEFORE);

	PASS_INFO(kernexec_reload,			"early_optimizations",	1, PASS_POS_INSERT_BEFORE);
	// unfortunately PRE can screw up fptr types from unions...
	// see cpuhp_step_startup/cpuhp_step_teardown and kernel/cpu.c:cpuhp_invoke_callback
	PASS_INFO(kernexec_fptr,			"optimized",		1, PASS_POS_INSERT_BEFORE);
	PASS_INFO(kernexec_retaddr,			"pro_and_epilogue",	1, PASS_POS_INSERT_AFTER);

	if (!rap_version_check(version, &gcc_version)) {
		error_gcc_version(version);
		return 1;
	}

#if BUILDING_GCC_VERSION >= 5000
	if (flag_ipa_icf_functions) {
//		warning_at(UNKNOWN_LOCATION, 0, G_("-fipa-icf is incompatible with %s, disabling..."), plugin_name);
//		inform(UNKNOWN_LOCATION, G_("-fipa-icf is incompatible with %s, disabling..."), plugin_name);
		flag_ipa_icf_functions = 0;
	}
#endif

#if BUILDING_GCC_VERSION >= 7000
	if (flag_code_hoisting) {
//		warning_at(UNKNOWN_LOCATION, 0, G_("-fcode-hoisting is incompatible with %s, disabling..."), plugin_name);
//		inform(UNKNOWN_LOCATION, G_("-fcode-hoisting is incompatible with %s, disabling..."), plugin_name);
		flag_code_hoisting = 0;
	}
#endif

#if BUILDING_GCC_VERSION >= 8000
	if (flag_cf_protection != CF_NONE) {
//		warning_at(UNKNOWN_LOCATION, 0, G_("-fcf-protection is incompatible with %s, disabling..."), plugin_name);
//		inform(UNKNOWN_LOCATION, G_("-fcf-protection is incompatible with %s, disabling..."), plugin_name);
		flag_cf_protection = CF_NONE;
	}

	// FIXME: somehow basic block reordering can leave a stray cfi_restore_state directive around
	// see block/partitions/ldm.c on i386
	if (flag_reorder_blocks_and_partition) {
//		warning_at(UNKNOWN_LOCATION, 0, G_("-flag-reorder-blocks-and-partition is incompatible with %s, disabling..."), plugin_name);
//		inform(UNKNOWN_LOCATION, G_("-freorder-blocks-and-partition is incompatible with %s, disabling..."), plugin_name);
		flag_reorder_blocks_and_partition = 0;
	}
#endif

	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i].key, "disable"))
			continue;

		if (!strcmp(argv[i].key, "typecheck")) {
			char *values, *value, *saveptr;

			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			values = xstrdup(argv[i].value);
			value = strtok_r(values, ",", &saveptr);
			while (value) {
				if (!strcmp(value, "ret"))
					enable_type_ret = true;
				else if (!strcmp(value, "call"))
					enable_type_call = true;
				else if (!strcmp(value, "nospec"))
					enable_type_nospec = true;
				else
					error(G_("unknown value supplied for option '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, value);
				value = strtok_r(NULL, ",", &saveptr);
			}
			free(values);
			continue;
		}

		if (!strcmp(argv[i].key, "retabort")) {
			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			rap_ret_abort = xstrdup(argv[i].value);
			continue;
		}

		if (!strcmp(argv[i].key, "callabort")) {
			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			rap_call_abort = xstrdup(argv[i].value);
			continue;
		}

		if (!strcmp(argv[i].key, "hash")) {
			char *values, *value, *saveptr;

			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			values = xstrdup(argv[i].value);
			value = strtok_r(values, ",", &saveptr);
			while (value) {
				if (!strcmp(value, "abs"))
					enable_abs = enable_abs_finish = true;
				else if (!strcmp(value, "abs-finish"))
					enable_abs_finish = true;
				else if (!strcmp(value, "abs-ops"))
					enable_abs_ops = true;
				else if (!strcmp(value, "abs-attr"))
					enable_abs_attr = true;
//				else if (!strcmp(value, "const"))
//					imprecise_rap_hash_flags.qual_const = 1;
//				else if (!strcmp(value, "volatile"))
//					imprecise_rap_hash_flags.qual_volatile = 1;
				else
					error(G_("unknown value supplied for option '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, value);
				value = strtok_r(NULL, ",", &saveptr);
			}
			free(values);
			continue;
		}

		if (!strcmp(argv[i].key, "report")) {
			char *values, *value, *saveptr;

			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			values = xstrdup(argv[i].value);
			value = strtok_r(values, ",", &saveptr);
			while (value) {
				if (!strcmp(value, "func"))
					report_func_hash = true;
				else if (!strcmp(value, "fptr"))
					report_fptr_hash = true;
				else if (!strcmp(value, "abs"))
					report_abs_hash = true;
				else
					error(G_("unknown value supplied for option '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, value);
				value = strtok_r(NULL, ",", &saveptr);
			}
			free(values);
			continue;
		}

		if (!strcmp(argv[i].key, "include")) {
			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			rap_include = xstrdup(argv[i].value);
			continue;
		}

		if (!strcmp(argv[i].key, "kernexec_method")) {
#ifdef TARGET_386
			if (TARGET_64BIT == 0)
				continue;

			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}

			if (!strcmp(argv[i].value, "bts") || !strcmp(argv[i].value, "\"bts\"")) {
				kernexec_instrument_fptr = kernexec_instrument_fptr_bts;
				kernexec_instrument_retaddr = kernexec_instrument_retaddr_bts;
			} else if (!strcmp(argv[i].value, "or") || !strcmp(argv[i].value, "\"or\"")) {
				kernexec_instrument_fptr = kernexec_instrument_fptr_or;
				kernexec_instrument_retaddr = kernexec_instrument_retaddr_or;
				fix_register("r12", 1, 1);
			} else
#endif
				error(G_("invalid option argument '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, argv[i].value);
			continue;
		}

		error(G_("unknown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &rap_plugin_info);
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	if (enable_type_ret) {
		flag_crossjumping = 0;
		flag_optimize_sibling_calls = 0;
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &rap_ret_pass_info);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &rap_mark_retloc_pass_info);
	}

	if (enable_type_nospec) {
#ifdef TARGET_386
# ifdef ix86_indirect_branch
#  ifndef ix86_indirect_branch_register
#   error unsupported GCC version as it lacks the full retpoline implementation
#  endif
		if (enable_type_call && ix86_indirect_branch != indirect_branch_thunk_extern)
			error(G_("only the -mindirect-branch=thunk-extern retpoline variant is supported"));
		// NB: if we ever stop replacing the original indirect jmp/call insns
		// then this will need to be enabled to prevent double instrumentation
		// ix86_indirect_branch = indirect_branch_keep;

		if (!ix86_indirect_branch_register)
			error(G_("-mindirect-branch-register must be enabled for retpoline support"));
# else
#  if BUILDING_GCC_VERSION < 6000
		flag_jump_tables = 0;
#  endif
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &rap_indirect_branch_register_pass_info);
# endif

		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &rap_retpoline_pass_info);
#else
#error unsupported target
#endif
	}

	if (enable_type_call || enable_type_ret) {
		if (enable_abs)
#if BUILDING_GCC_VERSION >= 4007
			register_callback(plugin_name, PLUGIN_FINISH_DECL, rap_emit_hash_symbols_finish_decl, NULL);
#else
			register_callback(plugin_name, PLUGIN_PRE_GENERICIZE, rap_emit_hash_symbols_finish_decl, NULL);
#endif
		if (enable_abs_ops)
			register_callback(plugin_name, PLUGIN_FINISH_TYPE, rap_emit_hash_symbols_finish_type, NULL);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &rap_unignore_pass_info);
		register_callback(plugin_name, PLUGIN_REGISTER_GGC_ROOTS, NULL, (void *)&gt_ggc_r_gt_rap);
		if (enable_abs_finish)
			register_callback(plugin_name, PLUGIN_FINISH_UNIT, rap_finish_unit, NULL);
		register_callback(plugin_name, PLUGIN_ALL_IPA_PASSES_START, rap_calculate_func_hashes, NULL);

		if (!enable_type_ret) {
			rap_fptr_pass_info.reference_pass_name = rap_ret_pass_info.reference_pass_name;
			rap_fptr_pass_info.pos_op = rap_ret_pass_info.pos_op;
		}
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &rap_fptr_pass_info);
	}

	if (enable_type_call || enable_type_ret || enable_type_nospec || rap_include)
		register_callback(plugin_name, PLUGIN_START_UNIT, rap_start_unit_common, NULL);

	if (kernexec_instrument_fptr == kernexec_instrument_fptr_or)
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &kernexec_reload_pass_info);
	if (kernexec_instrument_fptr)
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &kernexec_fptr_pass_info);
	if (kernexec_instrument_retaddr)
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &kernexec_retaddr_pass_info);

	return 0;
}
