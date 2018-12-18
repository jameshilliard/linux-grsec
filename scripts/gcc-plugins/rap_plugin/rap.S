#include <asm/nospec-branch.h>

#define SET(x) .set #x, x

SET(X86_FEATURE_RETPOLINE)
SET(X86_FEATURE_RETPOLINE_AMD)
