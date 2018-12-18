/*
 * Copyright 2018 by the PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Note: the choice of the license means that the compilation process is
 *       NOT 'eligible' as defined by gcc's library exception to the GPL v3,
 *       but for the kernel it doesn't matter since it doesn't link against
 *       any of the gcc libraries
 *
 * gcc plugin to defend against the Spectre vulnerabilities by instrumentation
 *
 * TODO:
 * - spectre v1
 *   - static analysis
 *
 * - spectre v2
 *   - arch support
 *   - benchmarking
 *
 * - spectre v4
 *   - static analysis
 *
 * BUGS:
 * - see the TODOs
 */

#include "gcc-common.h"

__visible int plugin_is_GPL_compatible;

static GTY(()) tree array_index_mask_nospec_decl;
static bool array_index_mask_nospec_used_orig;
static bool array_index_mask_nospec_preserved_orig;

static GTY(()) tree barrier_nospec_decl;
static bool barrier_nospec_used_orig;
static bool barrier_nospec_preserved_orig;

static bool verbose;

static struct plugin_info respectre_plugin_info = {
	.version	= "201810120025",
	.help		= "verbose\tlog Spectre instrumented statements\n"
};

enum placement { before, after };
enum adjustment { keep, inc };
enum defense { mask, mask_adjust, fence };

#if BUILDING_GCC_VERSION >= 5000
typedef struct hash_set<gimple> gimple_set;

static inline bool pointer_set_insert(gimple_set *visited, gimple stmt)
{
	return visited->add(stmt);
}

static inline bool pointer_set_contains(gimple_set *visited, gimple stmt)
{
	return visited->contains(stmt);
}

static inline gimple_set* pointer_set_create(void)
{
	return new hash_set<gimple>;
}

static inline void pointer_set_destroy(gimple_set *visited)
{
	delete visited;
}
#else
typedef struct pointer_set_t gimple_set;
#endif

static tree create_new_var(tree type, const char *name)
{
	tree var;

	var = create_tmp_var(type, name);
	add_referenced_var(var);
	mark_sym_for_renaming(var);
	return var;
}

static bool simple_assign_p(gimple stmt)
{
	if (!is_gimple_assign(stmt))
		return false;

	if (gimple_assign_cast_p(stmt))
		return true;

	if (gimple_assign_rhs_code(stmt) == SSA_NAME)
		return true;

	return false;
}

/*
 * compute the bound used for masking
 *
 * this is not a trivial exercise in case the bound check isn't against the index itself but some derived value
 * we have to undo the computation on the bound and use the original index instead of the derived value
 *
 * another bound adjustment is necessary to compensate for equality tests where the bound is off-by-one for masking purposes
 *
 * to top it all off, sometimes the above two adjustments cancel each other out so we don't need to do anything in the end
 */
static tree respectre_compute_bound(gimple_stmt_iterator *gsi, location_t mask_loc, tree block, tree bound, enum adjustment adjust, gimple assign_stmt)
{
	tree rhs2;
	enum tree_code op;

	if (!assign_stmt && adjust == keep)
		return bound;

	// adjust bound if it's against a derived index value, see respectre_choose_defense
	if (assign_stmt) {
		tree bound_type, rhs2_type;

		rhs2 = gimple_assign_rhs2(assign_stmt);

		gcc_assert(TREE_CODE(rhs2) == INTEGER_CST);

		bound_type = TREE_TYPE(bound);
		rhs2_type = TREE_TYPE(rhs2);
		if (TYPE_MAIN_VARIANT(bound_type) != TYPE_MAIN_VARIANT(rhs2_type)) {
			gcc_assert(TYPE_UNSIGNED(bound_type) == TYPE_UNSIGNED(rhs2_type));
			gcc_assert(TYPE_SIZE(bound_type) == TYPE_SIZE(rhs2_type));
		}

		switch (gimple_assign_rhs_code(assign_stmt)) {
		default:
			debug_gimple_stmt(assign_stmt);
			debug_tree(rhs2);
			debug_tree(bound);
			gcc_unreachable();

		case MINUS_EXPR:
			op = PLUS_EXPR;
			break;

		case MULT_EXPR:
			op = CEIL_DIV_EXPR;
			break;

		case PLUS_EXPR:
			op = MINUS_EXPR;
			break;
		}
	}

	if (TREE_CODE(bound) == INTEGER_CST) {
		// adjust bound if it's against a derived index value
		if (assign_stmt) {
			bound = fold_binary_to_constant(op, TREE_TYPE(bound), bound, rhs2);
			gcc_assert(bound);
		}

		// adjust bound if it's off-by-one
		if (adjust == inc) {
			bound = fold_binary_to_constant(PLUS_EXPR, TREE_TYPE(bound), bound, integer_one_node);
			gcc_assert(bound);
		}

		return bound;
	} else {
		gimple stmt;
		tree respectre_bound = NULL_TREE;
		bool adjusted = false;

		// adjust bound if it's against a derived index value
		if (assign_stmt) {
			if (adjust == inc) {
				switch (op) {
				default:
					break;

				case MINUS_EXPR:
				case PLUS_EXPR:
					rhs2 = fold_binary_to_constant(op, TREE_TYPE(rhs2), rhs2, integer_one_node);
					gcc_assert(rhs2);

					// no need to do anything for 0
					if (tree_int_cst_equal(rhs2, integer_zero_node))
						return bound;

					adjusted = true;
					break;
				}


			}

			respectre_bound = create_new_var(TREE_TYPE(bound), "respectre_bound");
			respectre_bound = make_ssa_name(respectre_bound, NULL);
			stmt = gimple_build_assign_with_ops(op, respectre_bound, bound, rhs2);
			gimple_set_location(stmt, mask_loc);
			gimple_set_block(stmt, block);
			gsi_insert_before(gsi, stmt, GSI_SAME_STMT);
			update_stmt(stmt);
		}

		// adjust bound if it's off-by-one
		if (adjust == inc && !adjusted) {
			if (respectre_bound) {
				bound = respectre_bound;
				respectre_bound = copy_ssa_name(respectre_bound, NULL);
			} else {
				respectre_bound = create_new_var(TREE_TYPE(bound), "respectre_bound2");
				respectre_bound = make_ssa_name(respectre_bound, NULL);
			}
			stmt = gimple_build_assign_with_ops(PLUS_EXPR, respectre_bound, bound, build_int_cstu(TREE_TYPE(bound), 1));
			gimple_set_location(stmt, mask_loc);
			gimple_set_block(stmt, block);
			gsi_insert_before(gsi, stmt, GSI_SAME_STMT);
			update_stmt(stmt);
		}

		gcc_assert(respectre_bound);
		return respectre_bound;
	}
}

/*
 * compute then apply a mask against index
 * gcc will compute the PHIs as necessary
 */
static tree __respectre_mask_array_index(tree array_index_mask, location_t array_loc, basic_block in_bound_bb, tree array_index, tree index, tree bound, enum adjustment adjust, gimple assign_stmt)
{
	gimple stmt;
	gimple reference;
	gimple_stmt_iterator gsi;
	gcall *gcallee;
	cgraph_node_ptr node;
	int frequency;
	tree respectre_bound, respectre_index, mask, block;
	location_t mask_loc;

	gcc_assert(TREE_CODE(index) == SSA_NAME);
	gcc_assert(TREE_CODE(array_index) == SSA_NAME);

	gsi = gsi_after_labels(in_bound_bb);
	reference = gsi_end_p(gsi) ? NULL : gsi_stmt(gsi);
	if (!reference) {
		gimple_stmt_iterator gsi2;

		gsi2 = gsi_after_labels(single_succ(in_bound_bb));
		reference = gsi_end_p(gsi2) ? NULL : gsi_stmt(gsi2);
	}
	gcc_assert(reference);
	mask_loc = reference ? gimple_location(reference) : UNKNOWN_LOCATION;
	block = gimple_block(reference);
	if (!block)
		block = DECL_INITIAL(current_function_decl);
	gcc_assert(block);

	respectre_bound = respectre_compute_bound(&gsi, mask_loc, block, bound, adjust, assign_stmt);
	if (assign_stmt)
		index = array_index;

	// create the mask variable
	mask = create_new_var(TREE_TYPE(TREE_TYPE(array_index_mask)), "respectre_mask");
	mask = make_ssa_name(mask, NULL);

	// create the index variable
	if (TREE_CODE(index) == INTEGER_CST) {
		debug_bb(in_bound_bb);
		debug_tree(index);
		gcc_unreachable();
	}

	// convert index to the type expected by array_index_mask
	if (!useless_type_conversion_p(TREE_TYPE(mask), TREE_TYPE(index))) {
		gcc_assert(fold_convertible_p(TREE_TYPE(mask), index));
		respectre_index = create_new_var(TREE_VALUE(TYPE_ARG_TYPES(TREE_TYPE(array_index_mask))), "respectre_index");
		respectre_index = make_ssa_name(respectre_index, NULL);
		stmt = gimple_build_assign(respectre_index, fold_convert_loc(mask_loc, TREE_TYPE(respectre_index), index));
		gimple_set_location(stmt, mask_loc);
		gimple_set_block(stmt, block);
		gsi_insert_before(&gsi, stmt, GSI_SAME_STMT);
		update_stmt(stmt);
	} else
		respectre_index = index;

	// insert call to array_index_mask
	stmt = gimple_build_call(array_index_mask, 2, respectre_index, respectre_bound);
	gimple_set_location(stmt, mask_loc);
	gimple_set_block(stmt, block);
	gcallee = as_a_gcall(stmt);
	gimple_call_set_lhs(gcallee, mask);
	gsi_insert_before(&gsi, stmt, GSI_SAME_STMT);
	update_stmt(stmt);

	// convert mask to the type of index
	if (!useless_type_conversion_p(TREE_TYPE(mask), TREE_TYPE(index))) {
		gcc_assert(fold_convertible_p(TREE_TYPE(mask), index));
		mask = create_new_var(TREE_TYPE(index), "respectre_mask2");
		mask = make_ssa_name(mask, NULL);
		stmt = gimple_build_assign(mask, fold_convert_loc(mask_loc, TREE_TYPE(index), gimple_call_lhs(gcallee)));
		gimple_set_location(stmt, mask_loc);
		gimple_set_block(stmt, block);
		gsi_insert_before(&gsi, stmt, GSI_SAME_STMT);
		update_stmt(stmt);
	}

	// insert index mask operation
	stmt = gimple_build_assign_with_ops(BIT_AND_EXPR, copy_ssa_name(index, NULL), index, mask);
	gimple_set_location(stmt, mask_loc);
	gimple_set_block(stmt, block);
	gsi_insert_before(&gsi, stmt, GSI_SAME_STMT);
	update_stmt(stmt);

	// convert index to the type of array_index
	if (!useless_type_conversion_p(TREE_TYPE(array_index), TREE_TYPE(gimple_assign_lhs(stmt)))) {
		gcc_assert(fold_convertible_p(TREE_TYPE(array_index), gimple_assign_lhs(stmt)));
		stmt = gimple_build_assign(copy_ssa_name(array_index, NULL), fold_convert_loc(mask_loc, TREE_TYPE(array_index), gimple_assign_lhs(stmt)));
		gimple_set_location(stmt, mask_loc);
		gimple_set_block(stmt, block);
		gsi_insert_before(&gsi, stmt, GSI_SAME_STMT);
		update_stmt(stmt);
	}

	// update the cgraph
	node = cgraph_get_node(array_index_mask);
	gcc_assert(node);
	frequency = compute_call_stmt_bb_frequency(current_function_decl, in_bound_bb);
	cgraph_create_edge(cgraph_get_node(current_function_decl), node, gcallee, in_bound_bb->count, frequency, in_bound_bb->loop_depth);

	if (verbose) {
		inform(array_loc, "Spectre v1 array index bound %qE", bound);
		inform(mask_loc, "Spectre v1 array index mask");
	}

	switch (TREE_CODE(bound)) {
	case SSA_NAME:
		if (verbose) {
			fprintf(stderr, "Spectre v1 bound def stmt ");
			print_gimple_stmt(stderr, SSA_NAME_DEF_STMT(bound), 0, TDF_LINENO);
		}
		break;

	case INTEGER_CST:
		break;

	default:
		if (verbose) {
			fprintf(stderr, "UNKNOWN BOUND TYPE ");
			debug_tree(bound);
		}
		break;
	}

	return gimple_assign_lhs(stmt);
}

static bool reachable_from_p(const_basic_block bb1, const_basic_block bb2)
{
	return dominated_by_p(CDI_DOMINATORS, bb1, bb2);
}

static void update_phi_stmt(edge e, basic_block old_bb, gimple *old_stmt, const_tree index)
{
	gimple_stmt_iterator gsi;

	if (!dominated_by_p(CDI_DOMINATORS, old_bb, e->dest))
		return;

	for (gsi = gsi_start_phis(old_bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
		gphi *new_stmt;

		new_stmt = as_a_gphi(gsi_stmt(gsi));

		if (index == PHI_ARG_DEF_FROM_EDGE(new_stmt, single_succ_edge(e->dest))) {
			if (*old_stmt != new_stmt)
				*old_stmt = new_stmt;
			return;
		}
	}
}

// split_edge can reallocate a PHI stmt so we need to update our own reference to it
// also fix up the post-dominator info while at it
static basic_block respectre_split_edge(edge e, gimple *array_stmt, gimple *assign_stmt, const_tree index)
{
	basic_block bb, old_array_bb, old_assign_bb;

	old_array_bb = gimple_bb(*array_stmt);
	old_assign_bb = gimple_bb(*assign_stmt);
	bb = split_edge(e);
	gcc_assert(single_succ_p(e->dest));

	// split_edge doesn't adjust CDI_POST_DOMINATORS but we need this information
	set_immediate_dominator(CDI_POST_DOMINATORS, bb, single_succ(bb));

	if (get_immediate_dominator(CDI_POST_DOMINATORS, single_pred(bb)) == single_succ(bb)) {
		edge_iterator ei;
		edge f;

		FOR_EACH_EDGE(f, ei, single_pred(bb)->succs) {
			if (f == single_pred_edge(bb))
				continue;

			if (!dominated_by_p(CDI_POST_DOMINATORS, f->dest, single_pred(bb)))
				break;
		}

		if (!f)
			set_immediate_dominator(CDI_POST_DOMINATORS, single_pred(bb), bb);
	}

	if (gimple_code(*array_stmt) == GIMPLE_PHI)
		update_phi_stmt(e, old_array_bb, array_stmt, index);

	if (gimple_code(*assign_stmt) == GIMPLE_PHI)
		update_phi_stmt(e, old_assign_bb, assign_stmt, index);

	return bb;
}

/*
 * when computing the proper mask for the array index would be too cumbersome
 * the strategy is to simply fence the array access itself
 */
static void __respectre_fence_array_index(tree barrier_nospec, gimple assign_stmt)
{
	gimple stmt;
	gimple reference;
	gimple_stmt_iterator gsi;
	gcall *gcallee;
	cgraph_node_ptr node;
	int frequency;
	tree block;
	basic_block bb;
	location_t fence_loc;

	switch (gimple_code(assign_stmt)) {
	default:
		debug_gimple_stmt(assign_stmt);
		gcc_unreachable();

	case GIMPLE_ASSIGN:
		gsi = gsi_for_stmt(assign_stmt);
		reference = assign_stmt;
		break;

	case GIMPLE_PHI:
		gsi = gsi_after_labels(gimple_bb(assign_stmt));
		reference = gsi_end_p(gsi) ? NULL : gsi_stmt(gsi);
		break;
	}

	gcc_assert(reference);
	fence_loc = reference ? gimple_location(reference) : UNKNOWN_LOCATION;
	block = gimple_block(reference);
	if (!block)
		block = DECL_INITIAL(current_function_decl);
	gcc_assert(block);
	bb = gimple_bb(assign_stmt);
	gcc_assert(bb);

	// insert call to barrier_nospec
	stmt = gimple_build_call(barrier_nospec, 0);
	gimple_set_location(stmt, fence_loc);
	gimple_set_block(stmt, block);
	gcallee = as_a_gcall(stmt);
	gsi_insert_before(&gsi, stmt, GSI_SAME_STMT);
	update_stmt(stmt);

	// update the cgraph
	node = cgraph_get_node(barrier_nospec);
	gcc_assert(node);
	frequency = compute_call_stmt_bb_frequency(current_function_decl, bb);
	cgraph_create_edge(cgraph_get_node(current_function_decl), node, gcallee, bb->count, frequency, bb->loop_depth);

	if (verbose)
		inform(fence_loc, "Spectre v1 array index fence");
}

static bool respectre_fence_array_index(tree barrier_nospec, unsigned int ncond, gcond *conds[], gimple *array_stmt, gimple *assign_stmt, tree index)
{
	const_basic_block array_bb = gimple_bb(*array_stmt);
	unsigned int i;
	bool bounded = false;

	if (barrier_nospec == NULL_TREE) {
		error_at(gimple_location(*array_stmt), "barrier_nospec is not defined");
		return false;
	}

	// instrument in-bound blocks of bound checks
	for (i = 0; i < ncond; i++) {
		tree lhs, rhs;
		basic_block cond_bb, then_bb, else_bb, join_bb, in_bound_bb;
		edge in_bound_edge;
		bool then_dom, else_dom, join_dom;
		gcond *use_stmt = conds[i];

		lhs = gimple_cond_lhs(use_stmt);
		rhs = gimple_cond_rhs(use_stmt);

		cond_bb = gimple_bb(use_stmt);
		gcc_assert(EDGE_COUNT(cond_bb->succs) == 2);

		then_bb = EDGE_SUCC(cond_bb, 0)->dest;
		else_bb = EDGE_SUCC(cond_bb, 1)->dest;
		join_bb = nearest_common_dominator(CDI_POST_DOMINATORS, then_bb, else_bb);

		then_dom = reachable_from_p(array_bb, then_bb);
		else_dom = reachable_from_p(array_bb, else_bb);
		join_dom = dominated_by_p(CDI_POST_DOMINATORS, array_bb, join_bb);

		gcc_assert(join_dom);

		switch (gimple_cond_code(use_stmt)) {
		default:
			debug_gimple_stmt(use_stmt);
			gcc_unreachable();

		case LE_EXPR:
		case LT_EXPR:
			if (then_dom && index == lhs)
				in_bound_edge = EDGE_SUCC(cond_bb, 0);
			else if (else_dom && index == rhs)
				in_bound_edge = EDGE_SUCC(cond_bb, 1);
			else
				break;

			in_bound_bb = in_bound_edge->dest;

			// filter out false positive bound checks in preceding loops
			if (bb_loop_depth(cond_bb) && !flow_bb_inside_loop_p(loop_outermost(cond_bb->loop_father), in_bound_bb))
				break;

			bounded = true;
			break;

		case GE_EXPR:
		case GT_EXPR:
			if (then_dom && index == rhs)
				in_bound_edge = EDGE_SUCC(cond_bb, 0);
			else if (else_dom && index == lhs)
				in_bound_edge = EDGE_SUCC(cond_bb, 1);
			else
				break;

			in_bound_bb = in_bound_edge->dest;

			// filter out false positive bound checks in preceding loops
			if (bb_loop_depth(cond_bb) && !flow_bb_inside_loop_p(loop_outermost(cond_bb->loop_father), in_bound_bb))
				break;

			bounded = true;
			break;
		}
	}

	if (bounded)
		__respectre_fence_array_index(barrier_nospec, *assign_stmt);

	return bounded;
}

static void __respectre_propagate_respectre_index(gimple array_stmt, tree *index, tree respectre_index)
{
	imm_use_iterator imm_iter;
	gimple stmt;
	bool found = false;

	// first fake a PHI stmt if respectre_index doesn't dominate the array_stmt
	FOR_EACH_IMM_USE_STMT(stmt, imm_iter, *index) {
		gimple def_stmt;

		if (stmt != array_stmt)
			continue;

		if (gimple_code(stmt) != GIMPLE_ASSIGN)
			continue;

		def_stmt = SSA_NAME_DEF_STMT(respectre_index);
		if (dominated_by_p(CDI_DOMINATORS, gimple_bb(stmt), gimple_bb(def_stmt)))
			continue;

		found = true;
		BREAK_FROM_IMM_USE_STMT(imm_iter);
	}

	if (found) {
		gphi *phi;
		edge e;
		edge_iterator ei;

		phi = as_a_gphi(create_phi_node(copy_ssa_name(*index, NULL), gimple_bb(array_stmt)));
#if BUILDING_GCC_VERSION <= 4007
		// unfortunately gimple_phi_set_result in earlier gcc versions doesn't do this...
		SSA_NAME_DEF_STMT(gimple_phi_result(phi)) = phi;
#endif
		FOR_EACH_EDGE(e, ei, gimple_bb(array_stmt)->preds) {
			if (reachable_from_p(e->src, gimple_bb(SSA_NAME_DEF_STMT(respectre_index))))
				add_phi_arg(phi, respectre_index, e, gimple_location(SSA_NAME_DEF_STMT(respectre_index)));
			else
				add_phi_arg(phi, *index, e, gimple_location(SSA_NAME_DEF_STMT(*index)));
		}
		respectre_index = gimple_phi_result(phi);
		update_stmt(phi);
	}

	found = false;
	FOR_EACH_IMM_USE_STMT(stmt, imm_iter, *index) {
		use_operand_p use;
		gimple def_stmt;

		// TODO: replace all uses?
		if (stmt != array_stmt)
			continue;

		def_stmt = SSA_NAME_DEF_STMT(respectre_index);
		switch (gimple_code(stmt)) {
		default:
			debug_gimple_stmt(stmt);
			gcc_unreachable();

		case GIMPLE_ASSIGN:
			gcc_assert(dominated_by_p(CDI_DOMINATORS, gimple_bb(stmt), gimple_bb(def_stmt)));

			FOR_EACH_IMM_USE_ON_STMT(use, imm_iter) {
				SET_USE(use, respectre_index);
			}
			update_stmt(stmt);
			break;

		case GIMPLE_PHI: {
			gphi *phi_stmt;
			unsigned int i;

			phi_stmt = as_a_gphi(stmt);
			for (i = 0; i < gimple_phi_num_args(phi_stmt); i++) {
				if (dominated_by_p(CDI_DOMINATORS, gimple_phi_arg_edge(phi_stmt, i)->src, gimple_bb(def_stmt)))
					break;
				gcc_assert(!dominated_by_p(CDI_POST_DOMINATORS, gimple_bb(def_stmt), gimple_phi_arg_edge(phi_stmt, i)->src));
			}

			if (i == gimple_phi_num_args(phi_stmt))
				continue;

			FOR_EACH_IMM_USE_ON_STMT(use, imm_iter) {
				if (i != (unsigned int)PHI_ARG_INDEX_FROM_USE(use))
					continue;

				SET_USE(use, respectre_index);
				break;
			}

			update_stmt(stmt);
			break;
		}
		}

		found = true;
		BREAK_FROM_IMM_USE_STMT(imm_iter);
	}

	*index = respectre_index;
	// TODO: special case handling of simple casts, should be more generic
	gcc_assert(found);
	return;
}

/*
 * strategy for masking the array index on the speculatively executed in-bound paths:
 *
 * - create a masked index variable
 *   - initialize it with the index itself (effectively masked with all 1s)
 *     - not all paths may do a bound check
 *       - warn about that?
 *   - for PARM_DECLs insert it in the first BB, split it if necessary
 * - replace the array use of the index with the masked index
 *   - this ensures that we'll get the same PHIs as the index, if any
 * - for each use in a condition:
 *   - determine if it's a bound check and find the in-bound path if it is
 *   - compute a new masked index version in the in-bound path
 *     - extract the mask from the condition
 *       - evaluate INTEGER_CST bounds at compile time
 * - compute PHI if necessary
 */
static bool respectre_mask_array_index(tree array_index_mask, unsigned int ncond, gcond *conds[], gimple *array_stmt, tree *array_index, gimple *assign_stmt, tree index, enum defense defense)
{
	const_basic_block array_bb = gimple_bb(*array_stmt);
	tree respectre_index = NULL_TREE;
	enum adjustment adjustment;
	unsigned int i;
	bool bounded = false;

	gcc_assert(TREE_CODE(index) == SSA_NAME);

	if (array_index_mask == NULL_TREE) {
		error_at(gimple_location(*array_stmt), "array_index_mask_nospec is not defined");
		return false;
	}

	// instrument in-bound blocks of bound checks
	for (i = 0; i < ncond; i++) {
		tree lhs, rhs, bound;
		basic_block cond_bb, then_bb, else_bb, join_bb, in_bound_bb;
		edge in_bound_edge;
		bool then_dom, else_dom, join_dom;
		gcond *use_stmt = conds[i];

		lhs = gimple_cond_lhs(use_stmt);
		rhs = gimple_cond_rhs(use_stmt);

		cond_bb = gimple_bb(use_stmt);
		gcc_assert(EDGE_COUNT(cond_bb->succs) == 2);

		then_bb = EDGE_SUCC(cond_bb, 0)->dest;
		else_bb = EDGE_SUCC(cond_bb, 1)->dest;
		join_bb = nearest_common_dominator(CDI_POST_DOMINATORS, then_bb, else_bb);

		then_dom = reachable_from_p(array_bb, then_bb);
		else_dom = reachable_from_p(array_bb, else_bb);
		join_dom = dominated_by_p(CDI_POST_DOMINATORS, array_bb, join_bb);

		gcc_assert(join_dom);

		switch (gimple_cond_code(use_stmt)) {
		default:
			debug_gimple_stmt(use_stmt);
			gcc_unreachable();

		/*
		 * decision table to detect a bound check and compute the bound
		 *
		 * cond/[i] | then  else
		 * ---------------------
		 *  i <= b  | b+1   -
		 *  i <  b  | b     -
		 *  b <= i  | -     b
		 *  b <  i  | -     b+1
		 */
		case LE_EXPR:
		case LT_EXPR:
			if (then_dom && index == lhs) {
				adjustment = gimple_cond_code(use_stmt) == LE_EXPR ? inc : keep;
				bound = rhs;
				in_bound_edge = EDGE_SUCC(cond_bb, 0);
			} else if (else_dom && index == rhs) {
				adjustment = gimple_cond_code(use_stmt) == LT_EXPR ? inc : keep;
				bound = lhs;
				in_bound_edge = EDGE_SUCC(cond_bb, 1);
			} else
				break;

			in_bound_bb = in_bound_edge->dest;

			// filter out false positive bound checks in preceding loops
			if (bb_loop_depth(cond_bb) && !flow_bb_inside_loop_p(loop_outermost(cond_bb->loop_father), in_bound_bb))
				break;

			// don't instrument if we have a PHI stmt and the in-bound block has a definition for it already
			if (gimple_code(*assign_stmt) == GIMPLE_PHI) {
				gphi *phi_stmt;
				unsigned int i;

				phi_stmt = as_a_gphi(*assign_stmt);
				for (i = 0; i < gimple_phi_num_args(phi_stmt); i++) {
					gimple def_stmt;
					tree var;

					if (gimple_phi_arg_edge(phi_stmt, i)->src != in_bound_bb)
						continue;

					var = gimple_phi_arg_def(phi_stmt, i);
					if (TREE_CODE(var) != SSA_NAME)
						continue;

					def_stmt = SSA_NAME_DEF_STMT(var);
					if (!gimple_bb(def_stmt))
						continue;

					if (gimple_bb(def_stmt) == in_bound_bb)
						break;
				}
				if (i < gimple_phi_num_args(phi_stmt))
					break;
			}

			if (!single_pred_p(in_bound_edge->dest))
				in_bound_bb = respectre_split_edge(in_bound_edge, array_stmt, assign_stmt, index);

			if (defense == mask_adjust)
				respectre_index = __respectre_mask_array_index(array_index_mask, gimple_location(*array_stmt), in_bound_bb, *array_index, index, bound, adjustment, *assign_stmt);
			else
				respectre_index = __respectre_mask_array_index(array_index_mask, gimple_location(*array_stmt), in_bound_bb, *array_index, index, bound, adjustment, NULL);
			bounded = true;
			break;

		/*
		 * decision table to detect a bound check and compute the bound
		 *
		 * cond/[i] | then  else
		 * ---------------------
		 *  i >= b  | -     b
		 *  i >  b  | -     b+1
		 *  b >= i  | b+1   -
		 *  b >  i  | b     -
		 */
		case GE_EXPR:
		case GT_EXPR:
			if (then_dom && index == rhs) {
				adjustment = gimple_cond_code(use_stmt) == GE_EXPR ? inc : keep;
				bound = lhs;
				in_bound_edge = EDGE_SUCC(cond_bb, 0);
			} else if (else_dom && index == lhs) {
				adjustment = gimple_cond_code(use_stmt) == GT_EXPR ? inc : keep;
				bound = rhs;
				in_bound_edge = EDGE_SUCC(cond_bb, 1);
			} else
				break;

			in_bound_bb = in_bound_edge->dest;

			// filter out false positive bound checks in preceding loops
			if (bb_loop_depth(cond_bb) && !flow_bb_inside_loop_p(loop_outermost(cond_bb->loop_father), in_bound_bb))
				break;

			// don't instrument if we have a PHI stmt and the in-bound block has a definition for it already
			if (gimple_code(*assign_stmt) == GIMPLE_PHI) {
				gphi *phi_stmt;
				unsigned int i;

				phi_stmt = as_a_gphi(*assign_stmt);
				for (i = 0; i < gimple_phi_num_args(phi_stmt); i++) {
					gimple def_stmt;
					tree var;

					if (gimple_phi_arg_edge(phi_stmt, i)->src != in_bound_bb)
						continue;

					var = gimple_phi_arg_def(phi_stmt, i);
					if (TREE_CODE(var) != SSA_NAME)
						continue;

					def_stmt = SSA_NAME_DEF_STMT(var);
					if (!gimple_bb(def_stmt))
						continue;

					if (gimple_bb(def_stmt) == in_bound_bb)
						break;
				}
				if (i < gimple_phi_num_args(phi_stmt))
					break;
			}

			if (!single_pred_p(in_bound_edge->dest))
				in_bound_bb = respectre_split_edge(in_bound_edge, array_stmt, assign_stmt, index);

			if (defense == mask_adjust)
				respectre_index = __respectre_mask_array_index(array_index_mask, gimple_location(*array_stmt), in_bound_bb, *array_index, index, bound, adjustment, *assign_stmt);
			else
				respectre_index = __respectre_mask_array_index(array_index_mask, gimple_location(*array_stmt), in_bound_bb, *array_index, index, bound, adjustment, NULL);
			bounded = true;
			break;
		}
	}

	if (bounded)
		__respectre_propagate_respectre_index(*array_stmt, array_index, respectre_index);

	return bounded;
}

static bool respectre_is_index_loop_variable(loop_p loop, tree index)
{
	loop_p ploop;
	unsigned int i;
	gimple_stmt_iterator gsi;
	gimple def_stmt;

	switch (TREE_CODE(index)) {
	default:
		debug_tree(index);
		gcc_unreachable();

	// TODO: handle these?
	case ADDR_EXPR:
	case ARRAY_REF:
	case COMPONENT_REF:
	case INTEGER_CST:
	case INDIRECT_REF:
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case VAR_DECL:
		return false;

	case SSA_NAME:
		if (!SSA_NAME_VAR(index))
			return false;
		break;

	case PARM_DECL:
		break;
	}

	if (!loop)
		return false;
	if (loop->header == ENTRY_BLOCK_PTR_FOR_FN(cfun) && loop->latch == EXIT_BLOCK_PTR_FOR_FN(cfun))
		return false;

	for (gsi = gsi_start_phis(loop->header); !gsi_end_p(gsi); gsi_next(&gsi)) {
		gphi *phi;
		tree phires;

		phi = as_a_gphi(gsi_stmt(gsi));
		phires = PHI_RESULT(phi);

		if (SSA_NAME_OCCURS_IN_ABNORMAL_PHI(phires))
			continue;

#if BUILDING_GCC_VERSION >= 4008
		if (virtual_operand_p(phires))
			continue;
#endif

		switch (TREE_CODE(index)) {
		default:
			gcc_unreachable();

		case PARM_DECL:
			if (SSA_NAME_VAR(phires) == index)
				return true;
			continue;

		case SSA_NAME:
			if (!SSA_NAME_VAR(phires))
				continue;

			if (SSA_NAME_VAR(phires) == SSA_NAME_VAR(index))
				return true;
		}
	}

#if BUILDING_GCC_VERSION <= 4007
	FOR_EACH_VEC_ELT(loop_p, loop->superloops, i, ploop) {
#else
	FOR_EACH_VEC_SAFE_ELT(loop->superloops, i, ploop) {
#endif
		if (respectre_is_index_loop_variable(ploop, index))
			return true;
	}

	if (TREE_CODE(index) != SSA_NAME)
		return false;

	// walk the use-def chain a bit for more witnesses
	// TODO: simple heuristics for now:
	// - track only rhs1 of an influencing assignment
	// - a single argument call with a loop variable returns a loop variable
	def_stmt = SSA_NAME_DEF_STMT(index);
	switch (gimple_code(def_stmt)) {
	default:
		debug_gimple_stmt(def_stmt);
		gcc_unreachable();

	case GIMPLE_ASSIGN:
		return respectre_is_index_loop_variable(loop, gimple_assign_rhs1(def_stmt));

	case GIMPLE_CALL:
		if (gimple_call_num_args(def_stmt) < 1)
			return false;
		return respectre_is_index_loop_variable(loop, gimple_call_arg(def_stmt, 0));

	case GIMPLE_ASM:
	case GIMPLE_NOP:
	case GIMPLE_PHI:
		return false;
	}
}

static bool respectre_is_interesting_assign(gimple use_stmt, tree index)
{
	gassign *assign_stmt;

	if (!(gimple_bb(use_stmt)->flags & BB_REACHABLE))
		return false;
	if (gimple_code(use_stmt) != GIMPLE_ASSIGN)
		return false;

	assign_stmt = as_a_gassign(use_stmt);
	if (index == gimple_assign_lhs(assign_stmt))
		return false;
	if (TREE_CODE(gimple_assign_lhs(assign_stmt)) != SSA_NAME)
		return false;

	switch (gimple_assign_rhs_code(assign_stmt)) {
	default:
		fprintf(stderr, "code %s ", get_tree_code_name(gimple_assign_rhs_code(assign_stmt)));
		debug_gimple_stmt(assign_stmt);
		debug_tree(index);
		gcc_unreachable();

	case ADDR_EXPR:
	case ARRAY_REF:
	case BIT_FIELD_REF:
	case COMPONENT_REF:
	case EQ_EXPR:
	case GE_EXPR:
	case GT_EXPR:
	case INDIRECT_REF:
	case LE_EXPR:
	case LT_EXPR:
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case NE_EXPR:
	case POINTER_PLUS_EXPR:
#if BUILDING_GCC_VERSION >= 8000
	case POINTER_DIFF_EXPR: // TODO: should it be treated as MINUS_EXPR instead?
#endif
	case TARGET_MEM_REF:
	case TRUTH_NOT_EXPR:
		return false;

	case EXACT_DIV_EXPR:
	case LROTATE_EXPR:
	case LSHIFT_EXPR:
	case RROTATE_EXPR:
	case RSHIFT_EXPR:
	case TRUNC_DIV_EXPR:
	case TRUNC_MOD_EXPR:
		if (index == gimple_assign_rhs2(assign_stmt))
			return false;
		// FALLTHROUGH

	case ABS_EXPR:
	case BIT_AND_EXPR:
	case BIT_IOR_EXPR:
	case BIT_NOT_EXPR:
	case BIT_XOR_EXPR:
	case CONVERT_EXPR:
	case MAX_EXPR:
	case MIN_EXPR:
	case MINUS_EXPR:
	case MULT_EXPR:
	case NEGATE_EXPR:
	case NOP_EXPR:
	case PARM_DECL:
	case PLUS_EXPR:
	case SSA_NAME:
	case VAR_DECL:
		break;
	}

	return true;
}

static int earlier_bb_p(const void *a, const void *b, void *c)
{
	const gcond *a_stmt = *(const gcond **)a;
	const gcond *b_stmt = *(const gcond **)b;
	const_basic_block a_bb = gimple_bb(a_stmt);
	const_basic_block b_bb = gimple_bb(b_stmt);
	const_basic_block index_bb = (const_basic_block)c;

	gcc_assert(dominated_by_p(CDI_DOMINATORS, index_bb, a_bb));
	gcc_assert(dominated_by_p(CDI_DOMINATORS, index_bb, b_bb));

	if (dominated_by_p(CDI_DOMINATORS, a_bb, b_bb))
		return -1;
	if (dominated_by_p(CDI_DOMINATORS, b_bb, a_bb))
		return 1;

	gcc_unreachable();
}

// look for index uses that indicate a potential bound check
// TODO: check for both upper and lower bound checks?
static bool index_bound_check_p(const_gimple array_stmt, const_gimple assign_stmt, const_gimple use_stmt)
{
	const_basic_block array_bb, assign_bb;
	basic_block cond_bb, then_bb, else_bb, join_bb;
	const gcond *cond_stmt;

	if (!use_stmt)
		return false;
	if (gimple_code(use_stmt) != GIMPLE_COND)
		return false;

	cond_stmt = as_a_const_gcond(use_stmt);
	switch (gimple_cond_code(cond_stmt)) {
	default:
		return false;

	case LE_EXPR:
	case LT_EXPR:
	case GE_EXPR:
	case GT_EXPR:
		break;
	}

	cond_bb = gimple_bb(cond_stmt);
	if (!(cond_bb->flags & BB_REACHABLE))
		return false;

	gcc_assert(EDGE_COUNT(cond_bb->succs) == 2);

	assign_bb = gimple_bb(assign_stmt);
	if (!dominated_by_p(CDI_DOMINATORS, assign_bb, cond_bb))
		return false;

	array_bb = gimple_bb(array_stmt);
	then_bb = EDGE_SUCC(cond_bb, 0)->dest;
	else_bb = EDGE_SUCC(cond_bb, 1)->dest;
	join_bb = nearest_common_dominator(CDI_POST_DOMINATORS, then_bb, else_bb);

	if (!dominated_by_p(CDI_POST_DOMINATORS, array_bb, join_bb))
		return false;
	if (dominated_by_p(CDI_DOMINATORS, array_bb, then_bb) == dominated_by_p(CDI_DOMINATORS, array_bb, else_bb))
		return false;

	switch (gimple_code(array_stmt)) {
	default:
		gcc_unreachable();

	case GIMPLE_ASSIGN:
		return array_bb != join_bb;

	case GIMPLE_PHI:
		return true;
	}
}

static bool __respectre_is_index_bounded(gimple *array_stmt, tree *array_index, gimple *assign_stmt, tree index, enum defense defense)
{
	basic_block assign_bb;
	imm_use_iterator imm_iter;
	gimple use_stmt;
	bool bounded = false;
	unsigned int i, ncond;
	gcond **conds;

	assign_bb = gimple_bb(*assign_stmt);
	gcc_assert(assign_bb);
	if (respectre_is_index_loop_variable(assign_bb->loop_father, index))
		return false;

	ncond = 0;
	FOR_EACH_IMM_USE_STMT(use_stmt, imm_iter, index) {
		if (!index_bound_check_p(*array_stmt, *assign_stmt, use_stmt))
			continue;

		ncond++;
	}

	if (!ncond)
		return false;

	conds = XCNEWVEC(gcond *, ncond);

	i = 0;
	FOR_EACH_IMM_USE_STMT(use_stmt, imm_iter, index) {
		if (!index_bound_check_p(*array_stmt, *assign_stmt, use_stmt))
			continue;

		conds[i++] = as_a_gcond(use_stmt);
	}

	// prefer the bound check closest to the array use
	qsort_r(conds, ncond, sizeof(gcond *), earlier_bb_p, assign_bb);

	if (defense == fence)
		// for now bound checked uses in subsequent assignments are treated with a fence instead of masking
		bounded = respectre_fence_array_index(barrier_nospec_decl, ncond, conds, array_stmt, assign_stmt, index);
	else
		bounded = respectre_mask_array_index(array_index_mask_nospec_decl, ncond, conds, array_stmt, array_index, assign_stmt, index, defense);

	free(conds);

	return bounded;
}

/*
 * we can use index masking if the bound check is done against a value derived in a simple enough way:
 * - the index is cast to a different type for the bound check
 * - the index is adjusted by a simple numerical op for the bound check
 */
static enum defense respectre_choose_defense(tree index, gassign *assign_stmt)
{
	tree rhs1, rhs2, next_index;

	next_index = gimple_assign_lhs(assign_stmt);

	if (TREE_CODE(next_index) != SSA_NAME)
		return fence;

	if (simple_assign_p(assign_stmt))
		return gimple_assign_rhs1(assign_stmt) == index ? mask : fence;

	switch (gimple_assign_rhs_code(assign_stmt)) {
	default:
		if (gimple_num_ops(assign_stmt) < 3)
			return fence;

		rhs1 = gimple_assign_rhs1(assign_stmt);
		rhs2 = gimple_assign_rhs2(assign_stmt);

		if (rhs1 != index)
			return fence;
		if (TREE_CODE(rhs2) != INTEGER_CST)
			return fence;

		return fence;

	case MINUS_EXPR:
	case MULT_EXPR:
	case PLUS_EXPR:
		rhs1 = gimple_assign_rhs1(assign_stmt);
		rhs2 = gimple_assign_rhs2(assign_stmt);

		if (rhs1 != index)
			return fence;
		if (TREE_CODE(rhs2) != INTEGER_CST)
			return fence;
		return mask_adjust;
	}
}

static bool respectre_is_index_bounded(gimple *array_stmt, gimple *assign_stmt, tree index)
{
	basic_block assign_bb;
	imm_use_iterator imm_iter;
	gimple use_stmt;
	bool bounded = false;
	unsigned int i, nassign;
	gassign **assigns;

	// 1. handle uses in conditions
	if (__respectre_is_index_bounded(array_stmt, &index, assign_stmt, index, mask))
		return true;

	// 2. follow and handle index uses in subsequent assignments
	// this is needed to get past casts and simple computations on the index
	// before a bound check is done on the result
	// TODO: follow the def-use chains a bit inside the index BB only?
	nassign = 0;
	FOR_EACH_IMM_USE_STMT(use_stmt, imm_iter, index) {
		if (!reachable_from_p(gimple_bb(*assign_stmt), gimple_bb(use_stmt)))
			continue;
		if (respectre_is_interesting_assign(use_stmt, index))
			nassign++;
	}

	if (!nassign)
		return false;

	assigns = XCNEWVEC(gassign *, nassign);

	i = 0;
	FOR_EACH_IMM_USE_STMT(use_stmt, imm_iter, index) {
		if (!reachable_from_p(gimple_bb(*assign_stmt), gimple_bb(use_stmt)))
			continue;
		if (respectre_is_interesting_assign(use_stmt, index))
			assigns[i++] = as_a_gassign(use_stmt);
	}

	// prefer the bound check closest to the array use
	assign_bb = gimple_bb(*assign_stmt);
	gcc_assert(assign_bb);
	qsort_r(assigns, nassign, sizeof(gassign *), earlier_bb_p, assign_bb);

	for (i = 0; i < nassign; i++) {
		use_stmt = assigns[i];
		tree next_index = gimple_assign_lhs(use_stmt);
		enum defense defense;

		defense = respectre_choose_defense(index, assigns[i]);
		if (__respectre_is_index_bounded(assign_stmt, &index, &use_stmt, next_index, defense))
			return true;
	}

	free(assigns);

	return bounded;
}

/*
 * determine whether the array index variable is
 *   - bound checked
 *   - not a loop counter
 * TODO: check if it is also tainted (its value range is untrusted)
 *   - syscall argument
 *   - I/O data (network, USB, disk, etc)
 *
 * gimple match:
 * if (x_4(D) < array1_size.0_3)
 *   goto <bb 3>;
 * else
 *   goto <bb 4>;
 * <bb 3>:
 * _5 = array1[x_4(D)];
*/
static void respectre_handle_index(gimple_set *visited, gimple *assign_stmt, tree index)
{
	switch (TREE_CODE(index)) {
	default:
		debug_gimple_stmt(*assign_stmt);
		debug_tree(index);
		gcc_unreachable();

	case ADDR_EXPR:
	case INTEGER_CST:
		return;

	case PARM_DECL:
		// TODO: check arg passed by callers in IPA
		return;

	case ARRAY_REF:
	case BIT_FIELD_REF:
	case COMPONENT_REF:
	case INDIRECT_REF:
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case TARGET_MEM_REF:
	case VAR_DECL:
		// TODO: verify dynamic and global variables
		return;

	case REALPART_EXPR:
	case IMAGPART_EXPR:
		index = TREE_OPERAND(index, 0);
		gcc_assert(TREE_CODE(index) == SSA_NAME);
		// TODO: how to handle modular arithmetic on the array index?
		// FALLTHROUGH

	case SSA_NAME: {
		gimple def_stmt;

		def_stmt = SSA_NAME_DEF_STMT(index);
		gcc_assert(def_stmt);

		if (pointer_set_insert(visited, def_stmt))
			return;

		if (SSA_NAME_VAR(index) &&
		    DECL_NAME(SSA_NAME_VAR(index)) &&
		    !strncmp(DECL_NAME_POINTER(SSA_NAME_VAR(index)), "respectre_index", sizeof("respectre_index") - 1))
			return;

		switch (gimple_code(def_stmt)) {
		default:
			debug_gimple_stmt(def_stmt);
			gcc_unreachable();

		case GIMPLE_ASM:
			// TODO: would catch asm array_index_mask_nospec?
			return;

		case GIMPLE_CALL:
			if (respectre_is_index_bounded(assign_stmt, assign_stmt, index))
				return;

			// TODO: check function return value in IPA
			return;

		case GIMPLE_PHI: {
			gphi *phi_stmt;
			unsigned int i;

			phi_stmt = as_a_gphi(def_stmt);

			// verify that none of the incoming PHI versions indicate a loop variable
			for (i = 0; i < gimple_phi_num_args(phi_stmt); i++) {
				tree index2 = gimple_phi_arg_def(phi_stmt, i);

				if (TREE_CODE(index2) != SSA_NAME)
					continue;

				gimple def_stmt2 = SSA_NAME_DEF_STMT(index2);

				// ignore definitions without a BB, typically for PARM_DECLs
				// and (potentially) uninitialized variables
				if (gimple_code(def_stmt2) == GIMPLE_NOP) {
					enum tree_code code;

					gcc_assert(SSA_NAME_VAR(index2));
					code = TREE_CODE(SSA_NAME_VAR(index2));
					gcc_assert(code == PARM_DECL || code == VAR_DECL);
					continue;
				}
				if (respectre_is_index_loop_variable(gimple_bb(def_stmt2)->loop_father, index2))
					return;
			}

			if (respectre_is_index_bounded(assign_stmt, assign_stmt, index))
				return;

			for (i = 0; i < gimple_phi_num_args(phi_stmt); i++) {
				tree index2 = gimple_phi_arg_def(phi_stmt, i);
				respectre_handle_index(visited, &def_stmt, index2);
				phi_stmt = as_a_gphi(def_stmt);
			}

			return;
		}

		case GIMPLE_NOP:
			if (TREE_CODE(index) != SSA_NAME)
				return;
			if (!SSA_NAME_VAR(index))
				return;
			if (TREE_CODE(SSA_NAME_VAR(index)) != PARM_DECL)
				return;

			if (respectre_is_index_bounded(assign_stmt, assign_stmt, index))
				return;

			// TODO: check arg passed by callers in IPA
			return;

		case GIMPLE_ASSIGN:
			if (respectre_is_index_bounded(assign_stmt, assign_stmt, index))
				return;

			gassign *next_assign_stmt = as_a_gassign(def_stmt);

			switch (gimple_num_ops(def_stmt)) {
			default:
				debug_gimple_stmt(def_stmt);
				gcc_unreachable();

#if BUILDING_GCC_VERSION >= 4006
			case 4:
				gcc_assert(gimple_assign_rhs_code(def_stmt) == COND_EXPR);

				respectre_handle_index(visited, &def_stmt, gimple_assign_rhs2(next_assign_stmt));
				respectre_handle_index(visited, &def_stmt, gimple_assign_rhs3(next_assign_stmt));
				return;
#endif

			case 3:
				switch (gimple_assign_rhs_code(def_stmt)) {
				default:
					fprintf(stderr, "%s ", get_tree_code_name(gimple_assign_rhs_code(def_stmt)));
					debug_gimple_stmt(def_stmt);
					gcc_unreachable();
					break;

				// TODO
				case BIT_AND_EXPR:
				case BIT_IOR_EXPR:
				case BIT_NOT_EXPR:
				case BIT_XOR_EXPR:
					break;

				// TODO
				case EQ_EXPR:
				case NE_EXPR:
					break;

#if BUILDING_GCC_VERSION >= 8000
				case POINTER_DIFF_EXPR: // TODO: should it be treated as MINUS_EXPR instead?
					break;
#endif

				// ignore rhs2 for asymmetric ops
				case EXACT_DIV_EXPR:
				case LROTATE_EXPR:
				case LSHIFT_EXPR:
				case MINUS_EXPR:
				case RROTATE_EXPR:
				case RSHIFT_EXPR:
				case TRUNC_DIV_EXPR:
				case TRUNC_MOD_EXPR:
					respectre_handle_index(visited, &def_stmt, gimple_assign_rhs1(next_assign_stmt));
					break;

				case ABS_EXPR:
				case GE_EXPR:
				case GT_EXPR:
				case LE_EXPR:
				case LT_EXPR:
				case MAX_EXPR:
				case MIN_EXPR:
				case MULT_EXPR:
				case NEGATE_EXPR:
				case NOP_EXPR:
				case PLUS_EXPR:
				case POINTER_PLUS_EXPR:
					respectre_handle_index(visited, &def_stmt, gimple_assign_rhs1(next_assign_stmt));
					respectre_handle_index(visited, &def_stmt, gimple_assign_rhs2(next_assign_stmt));
				}
				return;

			case 2:
				respectre_handle_index(visited, &def_stmt, gimple_assign_rhs1(next_assign_stmt));
				return;
			}
		}
	}
	}
}

static void respectre_handle_array(gimple assign_stmt, tree index, tree array_min, tree array_max)
{
	gimple_set *visited;

	switch (TREE_CODE(index)) {
	default:
		print_gimple_stmt(stderr, assign_stmt, 0, TDF_LINENO);
		fprintf(stderr, "INDEX ");debug_tree(index);
		gcc_unreachable();

	case INTEGER_CST:
		return;

	case SSA_NAME:
		if (SSA_NAME_VAR(index) &&
		    DECL_NAME(SSA_NAME_VAR(index)) &&
		    !strncmp(DECL_NAME_POINTER(SSA_NAME_VAR(index)), "respectre_index", sizeof("respectre_index") - 1))
			return;

#if BUILDING_GCC_VERSION >= 4009
		wide_int index_min, index_max;
		enum value_range_type vrtype;

		vrtype = get_range_info(index, &index_min, &index_max);

		if (vrtype == VR_RANGE) {
			bool in_bounds = true;

			// determine if array_min <= index_min and index_max <= array_max
			if (array_min && TREE_CODE(array_min) == INTEGER_CST) {
				gcc_assert(tree_fits_uhwi_p(array_min));
				if (tree_to_uhwi(array_min) > index_min.to_uhwi())
					in_bounds = false;
			} else
				in_bounds = false;

			if (array_max && TREE_CODE(array_max) == INTEGER_CST) {
				gcc_assert(tree_fits_uhwi_p(array_max));
				if (tree_to_uhwi(array_max) + 1 < index_max.to_uhwi())
					in_bounds = false;
			} else
				in_bounds = false;

			if (in_bounds)
				return;
		}
#endif
		break;
	}

	if (respectre_is_index_loop_variable(gimple_bb(assign_stmt)->loop_father, index))
		return;

	visited = pointer_set_create();
	respectre_handle_index(visited, &assign_stmt, index);
	pointer_set_destroy(visited);
}

static tree respectre_walk_tree(tree *tp, int *walk_subtrees, void *data)
{
	tree rhs1 = *tp;
	tree index, array_min, array_max;
	gassign *assign_stmt = (gassign *)data;

	*walk_subtrees = 0;

	switch (TREE_CODE(rhs1)) {
	default:
		break;
		debug_gimple_stmt(assign_stmt);
		gcc_unreachable();

	case INDIRECT_REF: {
		tree ptr, off;
		gimple def_stmt;

		ptr = TREE_OPERAND(rhs1, 0);

		if (TREE_CODE(ptr) != SSA_NAME)
			return NULL_TREE;

		def_stmt = SSA_NAME_DEF_STMT(ptr);
		switch (gimple_code(def_stmt)) {
		default:
			// TODO: handle others?
			return NULL_TREE;

		case GIMPLE_ASSIGN:
			if (gimple_assign_rhs_code(def_stmt) != POINTER_PLUS_EXPR)
				return NULL_TREE;
			gcc_assert(gimple_num_ops(def_stmt) == 3);
			break;
		}

		ptr = gimple_assign_rhs1(def_stmt);
		off = gimple_assign_rhs2(def_stmt);

		respectre_handle_array(def_stmt, off, NULL_TREE, NULL_TREE);
		break;
	}

#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF: {
		tree ptr, off;
		gimple def_stmt;

		ptr = TREE_OPERAND(rhs1, 0);
		off = TREE_OPERAND(rhs1, 1);

		if (TREE_CODE(ptr) != SSA_NAME)
			return NULL_TREE;
		if (TREE_CODE(off) != INTEGER_CST) {
			debug_tree(current_function_decl);
			debug_gimple_stmt(assign_stmt);
			debug_tree(rhs1);
			gcc_unreachable();
		}

		def_stmt = SSA_NAME_DEF_STMT(ptr);
		switch (gimple_code(def_stmt)) {
		default:
			// TODO: handle others?
			return NULL_TREE;

		case GIMPLE_ASSIGN:
			if (gimple_assign_rhs_code(def_stmt) != POINTER_PLUS_EXPR)
				return NULL_TREE;
			gcc_assert(gimple_num_ops(def_stmt) == 3);
			break;
		}

		ptr = gimple_assign_rhs1(def_stmt);
		off = gimple_assign_rhs2(def_stmt);

		respectre_handle_array(def_stmt, off, NULL_TREE, NULL_TREE);
		break;
	}
#endif

	// optimizations can turn an ARRAY_REF into a TARGET_MEM_REF
	case TARGET_MEM_REF: {
		tree base, domain;

		base = TMR_BASE(rhs1);
		switch (TREE_CODE(base)) {
		default:
			return NULL_TREE; // TODO

		case ADDR_EXPR:
			break;
		}

		base = TREE_OPERAND(base, 0);
print_gimple_stmt(stderr, assign_stmt, 0, TDF_LINENO);
debug_tree(base);
gcc_unreachable();

		switch (TREE_CODE(base)) {
		default:
			return NULL_TREE; // TODO

		case STRING_CST:
		case VAR_DECL:
			break;
		}

		switch (TREE_CODE(TREE_TYPE(base))) {
		default:
			return NULL_TREE; // TODO

		case ARRAY_TYPE:
			break;
		}

		domain = TYPE_DOMAIN(TREE_TYPE(base));
		if (domain) {
			array_min = TYPE_MIN_VALUE(domain);
			array_max = TYPE_MAX_VALUE(domain);
		} else {
			array_min = NULL_TREE;
			array_max = NULL_TREE;
		}

		index = TMR_INDEX(rhs1);
#if BUILDING_GCC_VERSION >= 4006
		if (!index)
			index = TMR_INDEX2(rhs1);
#endif
		gcc_assert(index);

		respectre_handle_array(assign_stmt, index, array_min, array_max);
		break;
	}

	case COMPONENT_REF:
		rhs1 = TREE_OPERAND(rhs1, 0);
		if (TREE_CODE(rhs1) == ARRAY_REF)
			*walk_subtrees = 1;
		return NULL_TREE;

	case ADDR_EXPR:
		*walk_subtrees = 1;
		return NULL_TREE;

	case ARRAY_REF:
		*walk_subtrees = 1;

		index = TREE_OPERAND(rhs1, 1);
		array_min = array_ref_low_bound(rhs1);
		array_max = array_ref_up_bound(rhs1);

		respectre_handle_array(assign_stmt, index, array_min, array_max);
		break;
	}

	return NULL_TREE;
}

/*
 * Spectre v1 defense:
 * - find array (and pointer+offset) reads where the index is bound checked
 *   - check whether an index use
 *     - is a bound check
 *     - dominates (precedes) the array read
 *   - if none is then walk the use-def chain recursively and check the same
 * - instrument the bound checked index calculation
 *   - lfence
 *   - index masking
 */
static unsigned int respectre_execute(void)
{
	basic_block bb;

	loop_optimizer_init(LOOPS_NORMAL | LOOPS_HAVE_RECORDED_EXITS);
	gcc_assert(current_loops);

	calculate_dominance_info(CDI_DOMINATORS);
	calculate_dominance_info(CDI_POST_DOMINATORS);

	gcc_assert(dom_info_available_p(CDI_DOMINATORS));
	gcc_assert(dom_info_available_p(CDI_POST_DOMINATORS));

	scev_initialize();

	find_unreachable_blocks();

	// 1. loop through BBs and GIMPLE statements
	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			tree rhs1;
			gimple stmt;

			stmt = gsi_stmt(gsi);
			if (!is_gimple_assign(stmt))
				continue;

			// 2. handle Spectre v1 (Bounds Check Bypass)
			rhs1 = gimple_assign_rhs1(as_a_gassign(stmt));
			walk_tree_without_duplicates(&rhs1, respectre_walk_tree, stmt);
		}
	}

	scev_finalize();
	free_dominance_info(CDI_POST_DOMINATORS);
	free_dominance_info(CDI_DOMINATORS);
	loop_optimizer_finalize();

	return 0;
}

static bool respectre_gate(void)
{
	tree section;

	section = lookup_attribute("section", DECL_ATTRIBUTES(current_function_decl));
	if (!section || !TREE_VALUE(section))
		return true;

	section = TREE_VALUE(TREE_VALUE(section));

	gcc_assert(strncmp(TREE_STRING_POINTER(section), ".vsyscall_", 10));

	if (!strncmp(TREE_STRING_POINTER(section), ".init.text", 10))
		return false;
	if (!strncmp(TREE_STRING_POINTER(section), ".devinit.text", 13))
		return false;
	if (!strncmp(TREE_STRING_POINTER(section), ".cpuinit.text", 13))
		return false;
	if (!strncmp(TREE_STRING_POINTER(section), ".meminit.text", 13))
		return false;
	if (!strncmp(TREE_STRING_POINTER(section), ".head.text", 10))
		return false;

	return true;
}

#define PASS_NAME respectre
#define TODO_FLAGS_FINISH TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_remove_unused_locals | TODO_update_ssa | TODO_cleanup_cfg | TODO_ggc_collect | TODO_rebuild_cgraph_edges | TODO_verify_flow
#include "gcc-generate-gimple-pass.h"

/*
 * the TU must provide array_index_mask_nospec. look it up by name early enough and mark it as used
 * otherwise gcc would delete it if the TU itself doesn't use it and before the instrumentation needs it
 */
static void find_nospec_decls(void *event_data __unused, void *data __unused)
{
	tree fndecl = (tree)event_data;
	const char *asmname;

	if (fndecl == error_mark_node)
		return;

	if (TREE_CODE(fndecl) != FUNCTION_DECL)
		return;

	if (DECL_ARTIFICIAL(fndecl))
		return;

	if (DECL_ABSTRACT_ORIGIN(fndecl) && DECL_ABSTRACT_ORIGIN(fndecl) != fndecl)
		return;

	asmname = DECL_NAME_POINTER(fndecl);
	gcc_assert(asmname[0]);

	if (DECL_NAME_LENGTH(fndecl) == sizeof("array_index_mask_nospec") - 1 &&
	    !strcmp(DECL_NAME_POINTER(fndecl), "array_index_mask_nospec")) {
		gcc_assert(!array_index_mask_nospec_decl);
		array_index_mask_nospec_decl = fndecl;
		array_index_mask_nospec_used_orig = TREE_USED(fndecl);
		TREE_USED(fndecl) = 1;
		array_index_mask_nospec_preserved_orig = DECL_PRESERVE_P(fndecl);
		DECL_PRESERVE_P(fndecl) = 1;
		return;
	}

	if (DECL_NAME_LENGTH(fndecl) == sizeof("barrier_nospec") - 1 &&
	    !strcmp(DECL_NAME_POINTER(fndecl), "barrier_nospec")) {
		gcc_assert(!barrier_nospec_decl);
		barrier_nospec_decl = fndecl;
		barrier_nospec_used_orig = TREE_USED(fndecl);
		TREE_USED(fndecl) = 1;
		barrier_nospec_preserved_orig = DECL_PRESERVE_P(fndecl);
		DECL_PRESERVE_P(fndecl) = 1;
		return;
	}
}

/*
 * undo the forced used mark on array_index_mask_nospec
 * the instrumentation no longer needs it as we're past inlining here
 */
static void unmark_nospec_decls(void *event_data __unused, void *data __unused)
{
	cgraph_node_ptr node;

	if (array_index_mask_nospec_decl) {
		TREE_USED(array_index_mask_nospec_decl) = array_index_mask_nospec_used_orig;
		DECL_PRESERVE_P(array_index_mask_nospec_decl) = array_index_mask_nospec_preserved_orig;
		node = cgraph_get_node(array_index_mask_nospec_decl);
		gcc_assert(node);
#if BUILDING_GCC_VERSION <= 4007
		gcc_assert(NODE_SYMBOL(node)->needed);
		NODE_SYMBOL(node)->needed = array_index_mask_nospec_preserved_orig;
#else
		gcc_assert(NODE_SYMBOL(node)->force_output);
		NODE_SYMBOL(node)->force_output = array_index_mask_nospec_preserved_orig;
#endif
	}

	if (barrier_nospec_decl) {
		TREE_USED(barrier_nospec_decl) = barrier_nospec_used_orig;
		DECL_PRESERVE_P(barrier_nospec_decl) = barrier_nospec_preserved_orig;
		node = cgraph_get_node(barrier_nospec_decl);
		gcc_assert(node);
#if BUILDING_GCC_VERSION <= 4007
		gcc_assert(NODE_SYMBOL(node)->needed);
		NODE_SYMBOL(node)->needed = barrier_nospec_preserved_orig;
#else
		gcc_assert(NODE_SYMBOL(node)->force_output);
		NODE_SYMBOL(node)->force_output = barrier_nospec_preserved_orig;
#endif
	}
}

__visible int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	int i;

	static const struct ggc_root_tab gt_ggc_r_gt_respectre[] = {
		{
			.base = &array_index_mask_nospec_decl,
			.nelt = 1,
			.stride = sizeof(array_index_mask_nospec_decl),
			.cb = &gt_ggc_mx_tree_node,
			.pchw = &gt_pch_nx_tree_node
		},
		{
			.base = &barrier_nospec_decl,
			.nelt = 1,
			.stride = sizeof(barrier_nospec_decl),
			.cb = &gt_ggc_mx_tree_node,
			.pchw = &gt_pch_nx_tree_node
		},
		LAST_GGC_ROOT_TAB
	};

	PASS_INFO(respectre, "ssa", 1, PASS_POS_INSERT_AFTER);

	if (!plugin_default_version_check(version, &gcc_version)) {
		error_gcc_version(version);
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &respectre_plugin_info);

	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i].key, "verbose")) {
			verbose = true;
			continue;
		}

		error(G_("unknown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_PRE_GENERICIZE, find_nospec_decls, NULL);
	register_callback(plugin_name, PLUGIN_ALL_IPA_PASSES_END, unmark_nospec_decls, NULL);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &respectre_pass_info);
	register_callback(plugin_name, PLUGIN_REGISTER_GGC_ROOTS, NULL, (void *)&gt_ggc_r_gt_respectre);

	return 0;
}
