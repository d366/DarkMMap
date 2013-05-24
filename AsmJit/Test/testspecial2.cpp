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
typedef void (*MyFn)(int32_t*, int32_t, int32_t, int32_t);

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
    c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder4<Void, int32_t*, int32_t, int32_t, int32_t>());

    GPVar dst0(c.argGP(0));
    GPVar v0(c.argGP(1));

    c.shl(v0, c.argGP(2));
    c.ror(v0, c.argGP(3));
    
    c.mov(dword_ptr(dst0), v0);
    c.endFunction();
  }
  // ==========================================================================

  // ==========================================================================
  // Make the function.
  MyFn fn = function_cast<MyFn>(c.make());

  {
    int32_t out;
    int32_t v0 = 0x000000FF;
    int32_t expected = 0x0000FF00;

    fn(&out, v0, 16, 8);

    printf("out=%d (expected %d)\n", out, expected);
    printf("Status: %s\n", (out == expected) ? "Success" : "Failure");
  }

  // Free the generated function if it's not needed anymore.
  MemoryManager::getGlobal()->free((void*)fn);
  // ==========================================================================

  return 0;
}
