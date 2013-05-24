// [AsmJit]
// Complete JIT Assembler for C++ Language.
//
// [License]
// Zlib - See COPYING file in this package.

// This file is used to test trampoline generation (absolute addressing
// in 64-bit mode).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AsmJit/AsmJit.h>

#if defined(ASMJIT_X86)

int main(int argc, char* argv[])
{
  printf("Trampoline test can be only used in x64 mode.\n");
  printf("Status: %s\n", "Success");

  return 0;
}

#else

// This is type of function we will generate
typedef void (*MyFn)(void);

static int i = 0;

// Function that is called from JIT code.
static void calledfn(void)
{
  i++;
}

int main(int argc, char* argv[])
{
  using namespace AsmJit;

  // ==========================================================================
  // Create assembler.
  Assembler a;

  // Log compiler output.
  FileLogger logger(stderr);
  a.setLogger(&logger);

  a.call(imm((sysint_t)calledfn)); // First trampoline - call.
  a.jmp(imm((sysint_t)calledfn));  // Second trampoline - jump, will return.
  MyFn fn0 = function_cast<MyFn>(a.make());

  a.clear(); // Purge assembler, we will reuse it.
  a.jmp(imm((sysint_t)fn0));
  MyFn fn1 = function_cast<MyFn>(a.make());

  // ==========================================================================

  // ==========================================================================
  fn0();
  fn1();

  printf("Status: %s\n", (i == 4) ? "Success" : "Failure");

  // If functions are not needed again they should be freed.
  MemoryManager::getGlobal()->free((void*)fn0);
  MemoryManager::getGlobal()->free((void*)fn1);
  // ==========================================================================

  return 0;
}

#endif
