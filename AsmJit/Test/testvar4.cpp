// [AsmJit]
// Complete JIT Assembler for C++ Language.
//
// [License]
// Zlib - See COPYING file in this package.

// Test variable scope detection in loop.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AsmJit/AsmJit.h>

// This is type of function we will generate
typedef void (*MyFn)(uint32_t*);

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
    c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder1<Void, uint32_t*>());

    GPVar var[32];
    int i;

    for (i = 0; i < ASMJIT_ARRAY_SIZE(var); i++)
    {
      var[i] = c.newGP(VARIABLE_TYPE_GPD);
      c.xor_(var[i], var[i]);
    }

    GPVar v0(c.newGP(VARIABLE_TYPE_GPD));
    Label L(c.newLabel());

    c.mov(v0, imm(32));
    c.bind(L);

    for (i = 0; i < ASMJIT_ARRAY_SIZE(var); i++)
    {
      c.add(var[i], imm(i));
    }

    c.dec(v0);
    c.jnz(L);

    GPVar a0(c.argGP(0));
    for (i = 0; i < ASMJIT_ARRAY_SIZE(var); i++)
    {
      c.mov(dword_ptr(a0, i * 4), var[i]);
    }
    c.endFunction();
  }
  // ==========================================================================

  // ==========================================================================
  // Make the function.
  MyFn fn = function_cast<MyFn>(c.make());

  {
    uint32_t out[32];
    int i;
    bool success = true;

    fn(out);

    for (i = 0; i < ASMJIT_ARRAY_SIZE(out); i++)
    {
      printf("out[%d]=%u (expected %d)\n", i, out[i], i * 32);
      if (out[i] != i * 32) success = false;
    }

    printf("Status: %s\n", (success) ? "Success" : "Failure");
  }

  // Free the generated function if it's not needed anymore.
  MemoryManager::getGlobal()->free((void*)fn);
  // ==========================================================================

  return 0;
}
