// [AsmJit]
// Complete JIT Assembler for C++ Language.
//
// [License]
// Zlib - See COPYING file in this package.

// This file is used as rep-test.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AsmJit/AsmJit.h>

// This is type of function we will generate
typedef void (*MemCopy)(void* a, void* b, sysuint_t size);

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
    c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder3<Void, void*, void*, sysuint_t>());
    c.getFunction()->setHint(FUNCTION_HINT_NAKED, true);

    GPVar dst(c.argGP(0));
    GPVar src(c.argGP(1));
    GPVar cnt(c.argGP(2));

    c.rep_movsb(dst, src, cnt);
    c.endFunction();
  }
  // ==========================================================================

  // ==========================================================================
  {
    MemCopy copy = function_cast<MemCopy>(c.make());

    char src[20] = "Hello AsmJit";
    char dst[20];
    
    copy(dst, src, strlen(src) + 1);
    printf("src=%s\n", src);
    printf("dst=%s\n", dst);
    printf("Status: %s\n", strcmp(src, dst) == 0 ? "Success" : "Failure");

    MemoryManager::getGlobal()->free((void*)copy);
  }
  // ==========================================================================

  return 0;
}
