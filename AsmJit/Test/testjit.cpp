// [AsmJit]
// Complete JIT Assembler for C++ Language.
//
// [License]
// Zlib - See COPYING file in this package.

// This file is only included as an example and simple test if jit
// compiler works.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AsmJit/AsmJit.h>

// This is type of function we will generate
typedef int (*MyFn)();

int main(int argc, char* argv[])
{
  using namespace AsmJit;

  // ==========================================================================
  // Create assembler.
  Assembler a;

  // Log assembler output.
  FileLogger logger(stderr);
  a.setLogger(&logger);

  // Prolog.
  a.push(nbp);
  a.mov(nbp, nsp);

  // Mov 1024 to EAX/RAX, EAX/RAX is also return value.
  a.mov(nax, 1024);

  // Epilog.
  a.mov(nsp, nbp);
  a.pop(nbp);
  a.ret();
  // ==========================================================================

  // NOTE:
  // This function can be also completely rewritten to this form:
  //   a.mov(nax, 1024);
  //   a.ret();
  // If you are interested in removing prolog and epilog, please
  // study calling conventions and check register preservations.

  // ==========================================================================
  // Make the function.
  MyFn fn = function_cast<MyFn>(a.make());

  // Call it.
  int result = fn();
  printf("Result from jit function: %d\n", result);
  printf("Status: %s\n", result == 1024 ? "Success" : "Failure");

  // Free the generated function if it's not needed anymore.
  MemoryManager::getGlobal()->free((void*)fn);
  // ==========================================================================

  return 0;
}
