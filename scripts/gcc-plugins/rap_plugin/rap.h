#ifndef RAP_H_INCLUDED
#define RAP_H_INCLUDED

#include "gcc-common.h"

typedef struct {
	int hash; // will be sign extended to long in reality
} rap_hash_t;

typedef struct {
	unsigned int qual_const:1;
	unsigned int qual_volatile:1;
} rap_hash_flags_t;
extern rap_hash_flags_t imprecise_rap_hash_flags;

extern bool report_fptr_hash;

extern GTY(()) tree rap_hash_type_node;
extern const char *rap_ret_abort;
extern const char *rap_call_abort;
extern const char *rap_include;
extern bool enable_type_ret, enable_type_call, enable_type_nospec;

extern void (*kernexec_instrument_fptr)(gimple_stmt_iterator *);
extern void (*kernexec_instrument_retaddr)(rtx);
void kernexec_instrument_fptr_bts(gimple_stmt_iterator *gsi);
void kernexec_instrument_fptr_or(gimple_stmt_iterator *gsi);
void kernexec_instrument_retaddr_bts(rtx insn);
void kernexec_instrument_retaddr_or(rtx insn);

void rap_mark_retloc(rtx_insn *insn);
bool rap_retpoline_gate(void);

void siphash24fold(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k);
void rap_calculate_func_hashes(void *event_data, void *data);
rap_hash_t rap_hash_function_type(const_tree fntype, rap_hash_flags_t flags);
rap_hash_t rap_hash_function_decl(const_tree fndecl, rap_hash_flags_t flags);
rap_hash_t rap_hash_function_node_imprecise(cgraph_node_ptr node);
tree get_rap_hash(gimple_seq *stmts, location_t loc, tree fptr, HOST_WIDE_INT rap_hash_offset);
const_tree type_name(const_tree type);
tree create_new_var(tree type, const char *name);

gimple barrier(tree var, bool full);
gimple ibarrier(tree var);
bool rap_cmodel_check(void);

#if BUILDING_GCC_VERSION >= 4009
opt_pass *make_rap_ret_pass(void);
opt_pass *make_rap_fptr_pass(void);
opt_pass *make_rap_mark_retloc_pass(void);
opt_pass *make_rap_retpoline_pass(void);
opt_pass *make_rap_indirect_branch_register_pass(void);
opt_pass *make_kernexec_reload_pass(void);
opt_pass *make_kernexec_fptr_pass(void);
opt_pass *make_kernexec_retaddr_pass(void);
#else
struct opt_pass *make_rap_ret_pass(void);
struct opt_pass *make_rap_fptr_pass(void);
struct opt_pass *make_rap_mark_retloc_pass(void);
struct opt_pass *make_rap_retpoline_pass(void);
struct opt_pass *make_rap_indirect_branch_register_pass(void);
struct opt_pass *make_kernexec_reload_pass(void);
struct opt_pass *make_kernexec_fptr_pass(void);
struct opt_pass *make_kernexec_retaddr_pass(void);
#endif

#endif
