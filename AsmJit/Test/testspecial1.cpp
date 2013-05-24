// [AsmJit]
// Complete JIT Assembler for C++ Language.
//
// [License]
// Zlib - See COPYING file in this package.

// Test special instruction generation.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AsmJit/AsmJit.h>

// This is type of function we will generate
typedef void (*MyFn)(int32_t*, int32_t*, int32_t, int32_t);

int main(int argc, char* argv[])
{
  using namespace AsmJit;

  // ==========================================================================
  // Create compiler.
  Compiler c;

  // Log compiler output.
  FileLogger logger(stderr);
  c.setLogger(&logger);

  {
    c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder4<Void, int32_t*, int32_t*, int32_t, int32_t>());
    c.getFunction()->setHint(FUNCTION_HINT_NAKED, true);

    GPVar dst0_hi(c.argGP(0));
    GPVar dst0_lo(c.argGP(1));

    GPVar v0_hi(c.newGP(VARIABLE_TYPE_GPD));
    GPVar v0_lo(c.argGP(2));

    GPVar src0(c.argGP(3));
    c.imul(v0_hi, v0_lo, src0);

    c.mov(dword_ptr(dst0_hi), v0_hi);
    c.mov(dword_ptr(dst0_lo), v0_lo);
    c.endFunction();
  }
  // ==========================================================================

  // ==========================================================================
  // Make the function.
  MyFn fn = function_cast<MyFn>(c.make());

  {
    int32_t out_hi;
    int32_t out_lo;

    int32_t v0 = 4;
    int32_t v1 = 4;

    int32_t expected_hi = 0;
    int32_t expected_lo = v0 * v1;

    fn(&out_hi, &out_lo, v0, v1);

    printf("out_hi=%d (expected %d)\n", out_hi, expected_hi);
    printf("out_lo=%d (expected %d)\n", out_lo, expected_lo);

    printf("Status: %s\n", (out_hi == expected_hi && out_lo == expected_lo)
      ? "Success" 
      : "Failure");
  }

  // Free the generated function if it's not needed anymore.
  MemoryManager::getGlobal()->free((void*)fn);
  // ==========================================================================

  return 0;
}
