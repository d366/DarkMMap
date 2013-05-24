// [AsmJit]
// Complete JIT Assembler for C++ Language.
//
// [License]
// Zlib - See COPYING file in this package.

// Recursive function call test.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AsmJit/AsmJit.h>

// Type of generated function.
typedef int (*MyFn)(int);

int main(int argc, char* argv[])
{
  using namespace AsmJit;

  // ==========================================================================
  // Create compiler.
  Compiler c;

  // Log compiler output.
  FileLogger logger(stderr);
  c.setLogger(&logger);

  ECall* ctx;
  Label skip(c.newLabel());

  EFunction* func = c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder1<int, int>());
  func->setHint(FUNCTION_HINT_NAKED, true);

  GPVar var(c.argGP(0));
  c.cmp(var, imm(1));
  c.jle(skip);

  GPVar tmp(c.newGP(VARIABLE_TYPE_INT32));
  c.mov(tmp, var);
  c.dec(tmp);

  ctx = c.call(func->getEntryLabel());
  ctx->setPrototype(CALL_CONV_DEFAULT, FunctionBuilder1<int, int>());
  ctx->setArgument(0, tmp);
  ctx->setReturn(tmp);
  c.mul(c.newGP(VARIABLE_TYPE_INT32), var, tmp);

  c.bind(skip);
  c.ret(var);
  c.endFunction();
  // ==========================================================================

  // ==========================================================================
  // Make the function.
  MyFn fn = function_cast<MyFn>(c.make());

  printf("Factorial 5 == %d\n", fn(5));

  // Free the generated function if it's not needed anymore.
  MemoryManager::getGlobal()->free((void*)fn);
  // ==========================================================================

  return 0;
}
