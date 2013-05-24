// [AsmJit]
// Complete JIT Assembler for C++ Language.
//
// [License]
// Zlib - See COPYING file in this package.

// This file is used as a dummy test. It's changed during development.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AsmJit/AsmJit.h>

// This is type of function we will generate
typedef void (*MyFn)(void);

static void dummyFunc(void)
{

}

int main(int argc, char* argv[])
{
  using namespace AsmJit;

  // ==========================================================================
  // Log compiler output.
  FileLogger logger(stderr);
  logger.setLogBinary(true);

  // Create compiler.
  Compiler c;
  c.setLogger(&logger);

  c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder0<Void>());
  c.getFunction()->setHint(FUNCTION_HINT_NAKED, true);

  ECall* ctx = c.call((void*)dummyFunc);
  ctx->setPrototype(CALL_CONV_DEFAULT, FunctionBuilder0<Void>());

  c.endFunction();
  // ==========================================================================

  // ==========================================================================
  // Make the function.
  MyFn fn = function_cast<MyFn>(c.make());

  // Call it.
  // printf("Result %llu\n", (unsigned long long)fn());

  // Free the generated function if it's not needed anymore.
  MemoryManager::getGlobal()->free((void*)fn);
  // ==========================================================================

  return 0;
}
