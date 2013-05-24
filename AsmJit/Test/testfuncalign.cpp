// [AsmJit]
// Complete JIT Assembler for C++ Language.
//
// [License]
// Zlib - See COPYING file in this package.

// Test function variables alignment (for sse2 code, 16-byte xmm variables).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AsmJit/AsmJit.h>

using namespace AsmJit;

// Generated functions prototypes.
typedef sysint_t (*MyFn0)();
typedef sysint_t (*MyFn1)(sysint_t);
typedef sysint_t (*MyFn2)(sysint_t, sysint_t);
typedef sysint_t (*MyFn3)(sysint_t, sysint_t, sysint_t);

static void* compileFunction(int args, int vars, bool naked, bool pushPopSequence)
{
  Compiler c;

  // Not enabled by default...
  // FileLogger logger(stderr);
  // c.setLogger(&logger);

  switch (args)
  {
    case 0:
      c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder0<sysint_t>());
      break;
    case 1:
      c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder1<sysint_t, sysint_t>());
      break;
    case 2:
      c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder2<sysint_t, sysint_t, sysint_t>());
      break;
    case 3:
      c.newFunction(CALL_CONV_DEFAULT, FunctionBuilder3<sysint_t, sysint_t, sysint_t, sysint_t>());
      break;
  }
  c.getFunction()->setHint(FUNCTION_HINT_NAKED, naked);
  c.getFunction()->setHint(FUNCTION_HINT_PUSH_POP_SEQUENCE, pushPopSequence);

  GPVar gvar(c.newGP());
  XMMVar xvar(c.newXMM(VARIABLE_TYPE_XMM));

  // Alloc, use and spill preserved registers.
  if (vars)
  {
    int var = 0;
    uint32_t index = 0;
    uint32_t mask = 1;
    uint32_t preserved = c.getFunction()->getPrototype().getPreservedGP();

    do {
      if ((preserved & mask) != 0 && (index != REG_INDEX_ESP && index != REG_INDEX_EBP))
      {
        GPVar somevar(c.newGP(VARIABLE_TYPE_GPD));
        c.alloc(somevar, index);
        c.mov(somevar, imm(0));
        c.spill(somevar);
        var++;
      }

      index++;
      mask <<= 1;
    } while (var < vars && index < REG_NUM_GP);
  }

  c.alloc(gvar, nax);
  c.lea(gvar, xvar.m());
  c.and_(gvar, imm(15));
  c.ret(gvar);
  c.endFunction();

  return c.make();
}

static bool testFunction(int args, int vars, bool naked, bool pushPopSequence)
{
  void* fn = compileFunction(args, vars, naked, pushPopSequence);
  sysint_t result = 0;

  printf("Function (args=%d, vars=%d, naked=%d, pushPop=%d):", args, vars, naked, pushPopSequence);

  switch (args)
  {
    case 0:
      result = AsmJit::function_cast<MyFn0>(fn)();
      break;
    case 1:
      result = AsmJit::function_cast<MyFn1>(fn)(1);
      break;
    case 2:
      result = AsmJit::function_cast<MyFn2>(fn)(1, 2);
      break;
    case 3:
      result = AsmJit::function_cast<MyFn3>(fn)(1, 2, 3);
      break;
  }

  printf(" result=%d (expected 0)\n", (int)result);

  MemoryManager::getGlobal()->free(fn);
  return result == 0;
}

#define TEST_FN(naked, pushPop) \
{ \
  for (int _args = 0; _args < 4; _args++) \
  { \
    for (int _vars = 0; _vars < 4; _vars++) \
    { \
      testFunction(_args, _vars, naked, pushPop); \
    } \
  } \
}

int main(int argc, char* argv[])
{
  TEST_FN(false, false)
  TEST_FN(false, true )

  if (CompilerUtil::isStack16ByteAligned())
  {
    // If stack is 16-byte aligned by the operating system.
    TEST_FN(true , false)
    TEST_FN(true , true )
  }

  return 0;
}
