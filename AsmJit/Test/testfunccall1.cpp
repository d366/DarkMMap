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
typedef int (*MyFn)(int, int, int);

// Function that is called inside the generated one.
static int calledFn(int a, int b, int c) { return (a + b) * c; }

int main(int argc, char* argv[])
{
  using namespace AsmJit;

  // ==========================================================================
  // Create compiler.
  Compiler c;

  // Log compiler output.
  FileLogger logger(stderr);
  c.setLogger(&logger);

  c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder3<int, int, int, int>());

  GPVar v0(c.argGP(0));
  GPVar v1(c.argGP(1));
  GPVar v2(c.argGP(2));

  // Just do something;)
  c.shl(v0, imm(1));
  c.shl(v1, imm(1));
  c.shl(v2, imm(1));

  // Call function.
  GPVar address(c.newGP());
  c.mov(address, imm((sysint_t)(void*)calledFn));

  ECall* ctx = c.call(address);
  ctx->setPrototype(CALL_CONV_DEFAULT, FunctionBuilder3<Void, int, int, int>());
  ctx->setArgument(0, v2);
  ctx->setArgument(1, v1);
  ctx->setArgument(2, v0);

  //ctx->setReturn(v0);
  //c.ret(v0);

  c.endFunction();
  // ==========================================================================

  // ==========================================================================
  // Make the function.
  MyFn fn = function_cast<MyFn>(c.make());

  uint result = fn(3, 2, 1);
  bool success = result == 36;

  printf("Result %u (expected 36)\n", result);
  printf("Status: %s\n", success ? "Success" : "Failure");

  // Free the generated function if it's not needed anymore.
  MemoryManager::getGlobal()->free((void*)fn);
  // ==========================================================================

  return 0;
}
