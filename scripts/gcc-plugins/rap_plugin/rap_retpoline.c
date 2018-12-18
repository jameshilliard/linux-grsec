/*
 * Copyright 2018 by PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Homepage: http://pax.grsecurity.net/
 */

#include "rap.h"

enum retpoline_kind {
	retpoline_jump,
	retpoline_call,
	retpoline_tailcall
};

static rtx_insn *rap_gen_retpoline(enum retpoline_kind kind, rtx reg, rtx_insn *insn)
{
#ifdef TARGET_386
	rtx body, parallel;
	rtx_insn *retpoline;
	rtvec argvec, constraintvec, labelvec;
	char name[64];
	int regno, nclobbers;
	unsigned int i, loc;
	hard_reg_set_iterator hrsi;

	start_sequence();
	loc = INSN_LOCATION(insn);
	argvec = rtvec_alloc(0);
	constraintvec = rtvec_alloc(0);
	labelvec = rtvec_alloc(0);

	gcc_assert(HARD_REGISTER_P(reg));
	gcc_assert(REGNO(reg) != REGNO(stack_pointer_rtx));
	regno = REGNO(reg);

	if (rap_include) {
		if (kind == retpoline_call)
			sprintf(name, "__CALL_NOSPEC %s%s", LEGACY_INT_REGNO_P(regno) ? TARGET_64BIT ? "r" : "e" : "", reg_names[regno]);
		else
			sprintf(name, "JMP_NOSPEC %s%s", LEGACY_INT_REGNO_P(regno) ? TARGET_64BIT ? "r" : "e" : "", reg_names[regno]);
	} else
		sprintf(name, "%s __x86_indirect_thunk_%s%s", kind == retpoline_call ? "call" : "jmp", LEGACY_INT_REGNO_P(regno) ? TARGET_64BIT ? "r" : "e" : "", reg_names[regno]);

	if (UNITS_PER_WORD == 8)
		body = gen_rtx_ASM_OPERANDS(VOIDmode, ggc_strdup(name), empty_string, 0, argvec, constraintvec, labelvec, loc);
	else
		body = gen_rtx_ASM_OPERANDS(VOIDmode, ggc_strdup(name), empty_string, 0, argvec, constraintvec, labelvec, loc);
	MEM_VOLATILE_P(body) = 1;

	if (kind == retpoline_jump) {
		parallel = gen_rtx_PARALLEL(VOIDmode, rtvec_alloc(2));
		XVECEXP(parallel, 0, 0) = body;
		if (TARGET_64BIT)
			XVECEXP(parallel, 0, 1) = gen_rtx_CLOBBER(VOIDmode, gen_rtx_REG(DImode, regno));
		else
			XVECEXP(parallel, 0, 1) = gen_rtx_CLOBBER(VOIDmode, gen_rtx_REG(SImode, regno));
		emit_insn(parallel);
		retpoline = get_insns();
		end_sequence();

		mark_jump_label(PATTERN(insn), retpoline, 0);
		if (find_reg_note(insn, REG_DEAD, reg))
			add_reg_note(retpoline, REG_DEAD, reg);
		SET_INSN_LOCATION(retpoline, loc);
		return retpoline;
	}

	nclobbers = 1; // 1 for body itself
	EXECUTE_IF_SET_IN_HARD_REG_SET(regs_invalidated_by_call, 0, i, hrsi) {
		switch (i) {
		case FIRST_INT_REG ... LAST_INT_REG:
		case FIRST_REX_INT_REG ... LAST_REX_INT_REG:
			nclobbers++;
		}
	}
	parallel = gen_rtx_PARALLEL(VOIDmode, rtvec_alloc(nclobbers));
	XVECEXP(parallel, 0, 0) = body;
	nclobbers = 1;
	EXECUTE_IF_SET_IN_HARD_REG_SET(regs_invalidated_by_call, 0, i, hrsi) {
		switch (i) {
		case FIRST_INT_REG ... LAST_INT_REG:
		case FIRST_REX_INT_REG ... LAST_REX_INT_REG:
			if (TARGET_64BIT)
				XVECEXP(parallel, 0, nclobbers++) = gen_rtx_CLOBBER(VOIDmode, gen_rtx_REG(DImode, i));
			else
				XVECEXP(parallel, 0, nclobbers++) = gen_rtx_CLOBBER(VOIDmode, gen_rtx_REG(SImode, i));
		}
	}

	emit_insn(parallel);
	retpoline = get_insns();
	end_sequence();
	SET_INSN_LOCATION(retpoline, loc);
	return retpoline;
#else
#error unsupported target
#endif
}

static void remove_call_arg_locations(rtx_insn *insn)
{
#if BUILDING_GCC_VERSION >= 4007 && BUILDING_GCC_VERSION < 8000
	rtx_insn *next;

	for (next = NEXT_INSN(insn); next; next = NEXT_INSN(next)) {
		rtx_insn *tmp;

		if (GET_CODE(next) == BARRIER)
			continue;
		if (GET_CODE(next) != NOTE)
			break;
		if (NOTE_KIND(next) != NOTE_INSN_CALL_ARG_LOCATION)
			continue;

		tmp = PREV_INSN(next);
		delete_insn(next);
		next = tmp;
	}
#endif
}

static bool is_reusable_reg(rtx_insn *insn, rtx reg)
{
	if (reg == NULL_RTX || GET_CODE(reg) != REG)
		return false;

	if (find_reg_note(insn, REG_DEAD, reg))
		return true;

	if (TEST_HARD_REG_BIT(regs_invalidated_by_call, REGNO(reg)))
		return true;

	return false;
}

static rtx_insn *rap_handle_indirect_jump(rtx_insn *insn, bool tailcall)
{
	rtx body, reg;
	rtx_insn *retpoline;
	int ret;

	body = PATTERN(insn);
	if (GET_CODE(body) == PARALLEL)
		body = XVECEXP(body, 0, 0);

	if (JUMP_P(insn)) {
		if (GET_CODE(body) != SET)
			return insn;

		if (SET_DEST(body) != pc_rtx) {
			print_rtl_single(stderr, insn);
			gcc_unreachable();
		}
		switch (GET_CODE(SET_SRC(body))) {
		default:
			break;

		case IF_THEN_ELSE:
		case LABEL_REF:
			return insn;
		}
	}

	if (GET_CODE(body) == SET)
		body = SET_SRC(body);
	if (GET_CODE(body) == CALL) {
		gcc_assert(tailcall);
		body = XEXP(body, 0);
		gcc_assert(MEM_P(body));
	} else
		gcc_assert(!tailcall);

	if (REG_P(body)) {
		gcc_assert(!tailcall);
		reg = body;
	} else if (MEM_P(body) && !tailcall) {
		struct ix86_address out;

		ret = ix86_decompose_address(XEXP(body, 0), &out);
		gcc_assert(ret == 1);

		if (!out.index && !out.base) {
			gcc_assert(out.disp);
			return insn;
		}

		// try to find a reusable register to load the jump target into
		if (is_reusable_reg(insn, out.index))
			reg = out.index;
		else if (is_reusable_reg(insn, out.base))
			reg = out.base;
		else
			reg = NULL_RTX;

		if (reg == NULL_RTX) {
			print_rtl_single(stderr, insn);
			print_rtl_single(stderr, out.index);
			print_rtl_single(stderr, out.base);
			print_rtl_single(stderr, out.disp);
			gcc_unreachable();
		}
	} else if (MEM_P(body) && tailcall) {
		body = XEXP(body, 0);
		switch (GET_CODE(body)) {
		case MEM:
		default:
			print_rtl_single(stderr, insn);
			print_rtl_single(stderr, body);
			gcc_unreachable();

		case SYMBOL_REF:
			return insn;

		case REG:
			reg = body;
			break;
		}
	} else
		return insn;

	if (!REG_P(body)) {
		rtx_insn *load;

		start_sequence();
		emit_move_insn(reg, body);
		load = get_insns();
		SET_INSN_LOCATION(load, INSN_LOCATION(insn));
		end_sequence();
		emit_insn_before(load, insn);
	}

	retpoline = rap_gen_retpoline(tailcall ? retpoline_tailcall : retpoline_jump, reg, insn);
	emit_insn_before(retpoline, insn);

	if (tailcall)
#if BUILDING_GCC_VERSION >= 4007
		remove_call_arg_locations(insn);
#else
		// gcc 4.5/4.6 expect to find an actual tailcall rtx in the epilogue, preserve it
		return insn;
#endif

	delete_insn(insn);
	return retpoline;
}

static rtx_insn *rap_handle_indirect_call(rtx_insn *insn)
{
	rtx body, reg;
	rtx_insn *retpoline;

	body = PATTERN(insn);
	if (GET_CODE(body) == SET)
		body = SET_SRC(body);
	gcc_assert(GET_CODE(body) == CALL);

	body = XEXP(body, 0);
	gcc_assert(MEM_P(body));

	body = XEXP(body, 0);
	switch (GET_CODE(body)) {
	case MEM: {
		// for some reason the register allocator in gcc 4.8 fails to emulate
		// -mindirect-branch-register and still spills the register to the stack
		// but marks it as dead at least so let's try to recover it if we can
		// rtl match: (insn (set (mem/f/c:SI) (reg:SI 5 di)) (expr_list:REG_DEAD (reg:SI 5 di)))
		rtx_insn *prev;
		rtx prev_body;

		prev = PREV_INSN(insn);
		gcc_assert(prev);
		prev_body = PATTERN(prev);

		if (GET_CODE(prev_body) == SET && rtx_equal_p(body, SET_DEST(prev_body))) {
			reg = SET_SRC(prev_body);
			if (GET_CODE(reg) == REG && find_reg_note(prev, REG_DEAD, reg))
				break;
		}
		print_rtl_single(stderr, prev);
	}
		// FALLTHROUGH

	default:
		print_rtl_single(stderr, insn);
		print_rtl_single(stderr, body);
		gcc_unreachable();

	case SYMBOL_REF:
		return insn;

	case REG:
		reg = body;
		break;
	}

	retpoline = rap_gen_retpoline(retpoline_call, reg, insn);
	emit_insn_before(retpoline, insn);
	remove_call_arg_locations(insn);
	delete_insn(insn);
	if (REG_P(body))
		rap_mark_retloc(retpoline);
	else
		rap_mark_retloc(NEXT_INSN(retpoline));
	return retpoline;
}

static unsigned int rap_retpoline_execute(void)
{
	rtx_insn *insn;

	for (insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		if (INSN_DELETED_P(insn))
			continue;

		// rtl match (jump_insn:TI 66 63 67 10 (parallel [ (set (pc) (mem/u/c:DI (plus:DI (mult:DI (reg:DI 0 ax [132]) (const_int 8 [0x8])) (label_ref:DI 68)) [0  S8 A8])) ]) -> 68)
		if (JUMP_P(insn) && !returnjump_p(insn)) {
			insn = rap_handle_indirect_jump(insn, false);
			continue;
		}

		// rtl match (call_insn (set (reg) (call (mem))))
		if (CALL_P(insn)) {
			if (SIBLING_CALL_P(insn))
				insn = rap_handle_indirect_jump(insn, true);
			else
				insn = rap_handle_indirect_call(insn);
		}
	}

	return 0;
}

/*
 * by forcing the fptr through an inline asm the compiler will be forced to load it into a register
 * which allows it to redirect the indirect call or jump to the appropriate retpoline
 * this is basically a poor man's emulation of -mindirect-branch-register found in retpoline capable compilers
 */
static unsigned int rap_indirect_branch_register_execute(void)
{
	rtx_insn *insn;

	for (insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		rtx body, mem, reg, regload;
		rtvec argvec, constraintvec, labelvec;

		if (INSN_DELETED_P(insn))
			continue;

		if (JUMP_P(insn)) {
			// rtl match (jump_insn (set (pc) (mem)))
			body = PATTERN(insn);
			if (GET_CODE(body) == PARALLEL)
				body = XVECEXP(body, 0, 0);
			if (GET_CODE(body) == ASM_OPERANDS)
				continue;
			if (GET_CODE(body) != SET) {
				print_rtl_single(stderr, insn);
				gcc_unreachable();
			}
			body = SET_SRC(body);
			if (GET_CODE(body) != MEM)
				continue;
		} else if (CALL_P(insn)) {
			// rtl match (call_insn (set (reg) (call (mem))))
			body = PATTERN(insn);
			if (GET_CODE(body) == SET)
				body = SET_SRC(body);
			gcc_assert(GET_CODE(body) == CALL);
			body = XEXP(body, 0);
			gcc_assert(GET_CODE(body) == MEM);
		} else
			continue;

		mem = XEXP(body, 0);
		switch (GET_CODE(mem)) {
		default:
			print_rtl_single(stderr, insn);
			print_rtl_single(stderr, mem);
			gcc_unreachable();

		case SYMBOL_REF:
			continue;

		case PLUS: {
			rtx_insn *temp;

			start_sequence();
			mem = copy_to_reg(mem);
			gcc_assert(GET_CODE(mem) == REG);
			temp = get_insns();
			end_sequence();
			emit_insn_before(temp, insn);
			break;
		}

//		case MEM:
		case REG:
			break;
		}

		argvec = rtvec_alloc(1);
		constraintvec = rtvec_alloc(1);
		labelvec = rtvec_alloc(0);

		regload = gen_rtx_ASM_OPERANDS(Pmode, ggc_strdup(""), empty_string, 0, argvec, constraintvec, labelvec, INSN_LOCATION(insn));
		MEM_VOLATILE_P(regload) = 1;
		ASM_OPERANDS_INPUT(regload, 0) = mem;
		ASM_OPERANDS_INPUT_CONSTRAINT_EXP(regload, 0) = gen_rtx_ASM_INPUT_loc(Pmode, ggc_strdup("0"), INSN_LOCATION(insn));
		ASM_OPERANDS_OUTPUT_CONSTRAINT(regload) = ggc_strdup("=r");
		reg = gen_reg_rtx(Pmode);
		emit_insn_before(gen_rtx_set(reg, regload), insn);
		XEXP(body, 0) = reg;
		df_insn_rescan(insn);
	}

	return 0;
}

bool rap_retpoline_gate(void)
{
	tree ib;

	ib = lookup_attribute("indirect_branch", DECL_ATTRIBUTES(current_function_decl));
	return !ib || strcmp(TREE_STRING_POINTER(TREE_VALUE(TREE_VALUE(ib))), "keep");
}

#define PASS_NAME rap_retpoline
#define TODO_FLAGS_FINISH TODO_dump_func | TODO_verify_rtl_sharing | TODO_df_verify
#include "gcc-generate-rtl-pass.h"

static bool rap_indirect_branch_register_gate(void)
{
	return rap_retpoline_gate();
}

#define PASS_NAME rap_indirect_branch_register
#define TODO_FLAGS_FINISH TODO_dump_func | TODO_verify_rtl_sharing | TODO_df_verify
#include "gcc-generate-rtl-pass.h"
