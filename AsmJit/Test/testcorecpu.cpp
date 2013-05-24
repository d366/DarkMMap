// [AsmJit]
// Complete JIT Assembler for C++ Language.
//
// [License]
// Zlib - See COPYING file in this package.

// this file is used to test cpu detection.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AsmJit/AsmJit.h>

using namespace AsmJit;

struct BitDescription
{
  uint32_t mask;
  const char* description;
};

static const BitDescription cFeatures[] = 
{
  { CPU_FEATURE_RDTSC                       , "RDTSC" },
  { CPU_FEATURE_RDTSCP                      , "RDTSCP" },
  { CPU_FEATURE_CMOV                        , "CMOV" },
  { CPU_FEATURE_CMPXCHG8B                   , "CMPXCHG8B" },
  { CPU_FEATURE_CMPXCHG16B                  , "CMPXCHG16B" },
  { CPU_FEATURE_CLFLUSH                     , "CLFLUSH" },
  { CPU_FEATURE_PREFETCH                    , "PREFETCH" },
  { CPU_FEATURE_LAHF_SAHF                   , "LAHF/SAHF" },
  { CPU_FEATURE_FXSR                        , "FXSAVE/FXRSTOR" },
  { CPU_FEATURE_FFXSR                       , "FXSAVE/FXRSTOR Optimizations" },
  { CPU_FEATURE_MMX                         , "MMX" },
  { CPU_FEATURE_MMX_EXT                     , "MMX Extensions" },
  { CPU_FEATURE_3DNOW                       , "3dNow!" },
  { CPU_FEATURE_3DNOW_EXT                   , "3dNow! Extensions" },
  { CPU_FEATURE_SSE                         , "SSE" },
  { CPU_FEATURE_SSE2                        , "SSE2" },
  { CPU_FEATURE_SSE3                        , "SSE3" },
  { CPU_FEATURE_SSSE3                       , "Suplemental SSE3 (SSSE3)" },
  { CPU_FEATURE_SSE4_A                      , "SSE4A" },
  { CPU_FEATURE_SSE4_1                      , "SSE4.1" },
  { CPU_FEATURE_SSE4_2                      , "SSE4.2" },
  { CPU_FEATURE_AVX                         , "AVX" },
  { CPU_FEATURE_MSSE                        , "Misaligned SSE" },
  { CPU_FEATURE_MONITOR_MWAIT               , "MONITOR/MWAIT" },
  { CPU_FEATURE_MOVBE                       , "MOVBE" },
  { CPU_FEATURE_POPCNT                      , "POPCNT" },
  { CPU_FEATURE_LZCNT                       , "LZCNT" },
  { CPU_FEATURE_PCLMULDQ                    , "PCLMULDQ" },
  { CPU_FEATURE_MULTI_THREADING             , "Multi-Threading" },
  { CPU_FEATURE_EXECUTE_DISABLE_BIT         , "Execute Disable Bit" },
  { CPU_FEATURE_64_BIT                      , "64 Bit Processor" },
  { 0, NULL }
};

static void printBits(const char* msg, uint32_t mask, const BitDescription* d)
{
  for (; d->mask; d++)
  {
    if (mask & d->mask) printf("%s%s\n", msg, d->description);
  }
}

int main(int argc, char* argv[])
{
  CpuInfo *i = getCpuInfo();

  printf("CPUID Detection\n");
  printf("===============\n");

  printf("\nBasic info\n");
  printf("  Vendor string         : %s\n", i->vendor);
  printf("  Brand string          : %s\n", i->brand);
  printf("  Family                : %u\n", i->family);
  printf("  Model                 : %u\n", i->model);
  printf("  Stepping              : %u\n", i->stepping);
  printf("  Number of Processors  : %u\n", i->numberOfProcessors);
  printf("  Features              : 0x%0.8X\n", i->features);
  printf("  Bugs                  : 0x%0.8X\n", i->bugs);

  printf("\nExtended Info (X86/X64):\n");
  printf("  Processor Type        : %u\n", i->x86ExtendedInfo.processorType);
  printf("  Brand Index           : %u\n", i->x86ExtendedInfo.brandIndex);
  printf("  CL Flush Cache Line   : %u\n", i->x86ExtendedInfo.flushCacheLineSize);
  printf("  Max logical Processors: %u\n", i->x86ExtendedInfo.maxLogicalProcessors);
  printf("  APIC Physical ID      : %u\n", i->x86ExtendedInfo.apicPhysicalId);

  printf("\nCpu Features:\n");
  printBits("  ", i->features, cFeatures);

  return 0;
}
