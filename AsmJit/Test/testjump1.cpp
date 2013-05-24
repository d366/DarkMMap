// [AsmJit]
// Complete JIT Assembler for C++ Language.
//
// [License]
// Zlib - See COPYING file in this package.

// This file is used to test crossed jumps.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AsmJit/AsmJit.h>

using namespace AsmJit;
typedef void (*VoidFn)();

int main(int, char**)
{
  Compiler c;

  FileLogger logger(stderr);
  c.setLogger(&logger);

  c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder0<Void>());

  Label L_A = c.newLabel();
  Label L_B = c.newLabel();
  Label L_C = c.newLabel();

  c.jmp(L_B);

  c.bind(L_A);
  c.jmp(L_C);

  c.bind(L_B);
  c.jmp(L_A);

  c.bind(L_C);

  c.ret();
  c.endFunction();

  VoidFn fn = function_cast<VoidFn>(c.make());

  // Ensure that everything is ok.
  if (!fn)
  {
    printf("Error making jit function (%u).\n", c.getError());
    return 1;
  }

  // Free the JIT function if it's not needed anymore.
  MemoryManager::getGlobal()->free((void*)fn);

  return 0;
}
