// [AsmJit]
// Complete JIT Assembler for C++ Language.
//
// [License]
// Zlib - See COPYING file in this package.

// This file is used as a function call test (calling functions inside
// the generated code).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AsmJit/AsmJit.h>

// Type of generated function.
typedef int (*MyFn)(void);

// Function that is called inside the generated one. Because this test is 
// mainly about register arguments, we need to use the fastcall calling 
// convention under 32-bit mode.
static int oneFunc(void) { return 1; }

int main(int argc, char* argv[])
{
  using namespace AsmJit;

  // ==========================================================================
  // Create compiler.
  Compiler c;

  // Log compiler output.
  FileLogger logger(stderr);
  c.setLogger(&logger);

  c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder1<int,int>());
  c.getFunction()->setHint(FUNCTION_HINT_NAKED, true);
  Label L0(c.newLabel());
  Label L1(c.newLabel());
  GPVar x(c.newGP());
  GPVar y(c.newGP());
  c.mov(x, 0);
  c.jnz(L0);
  c.mov(y, c.argGP(0));
  c.jmp(L1);
  c.bind(L0);
  ECall *ctx = c.call((void*)oneFunc);
  ctx->setPrototype(CALL_CONV_DEFAULT, FunctionBuilder1<int,int>());
  ctx->setArgument(0, c.argGP(0));
  ctx->setReturn(y);
  c.bind(L1);
  c.add(x, y);
  c.endFunction();

  // TODO: Remove
#if 0
  c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder0<int>());
  c.getFunction()->setHint(FUNCTION_HINT_NAKED, true);
  GPVar x(c.newGP());
  GPVar y(c.newGP());
  ECall *ctx = c.call((void*)oneFunc);
  ctx->setPrototype(CALL_CONV_DEFAULT, FunctionBuilder0<int>());
  ctx->setReturn(y);
  c.mov(x, 0);
  c.add(x, y);
  c.ret(x);
  c.endFunction();
#endif
  // ==========================================================================

  // ==========================================================================
  // Make the function.
  MyFn fn = function_cast<MyFn>(c.make());

  //uint result = fn();
  //bool success = result == 1;

  //printf("Result %u (expected 1)\n", result);
  //printf("Status: %s\n", success ? "Success" : "Failure");

  // Free the generated function if it's not needed anymore.
  MemoryManager::getGlobal()->free((void*)fn);
  // ==========================================================================

  return 0;
}
