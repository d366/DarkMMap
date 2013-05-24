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

int main(int argc, char* argv[])
{
  printf("AsmJit size test\n");
  printf("================\n");
  printf("\n");

  printf("Variable sizes:\n");
  printf("  uint8_t                   : %u\n", (uint32_t)sizeof(uint8_t));
  printf("  uint16_t                  : %u\n", (uint32_t)sizeof(uint16_t));
  printf("  uint32_t                  : %u\n", (uint32_t)sizeof(uint32_t));
  printf("  uint64_t                  : %u\n", (uint32_t)sizeof(uint64_t));
  printf("  sysuint_t                 : %u\n", (uint32_t)sizeof(sysuint_t));
  printf("  void*                     : %u\n", (uint32_t)sizeof(void*));
  printf("\n");

  printf("Structure sizes:\n");
  printf("  AsmJit::Operand           : %u\n", (uint32_t)sizeof(Operand));
  printf("  AsmJit::Operand::BaseData : %u\n", (uint32_t)sizeof(Operand::BaseData));
  printf("  AsmJit::Operand::ImmData  : %u\n", (uint32_t)sizeof(Operand::ImmData));
  printf("  AsmJit::Operand::LblData  : %u\n", (uint32_t)sizeof(Operand::LblData));
  printf("  AsmJit::Operand::MemData  : %u\n", (uint32_t)sizeof(Operand::MemData));
  printf("  AsmJit::Operand::RegData  : %u\n", (uint32_t)sizeof(Operand::RegData));
  printf("  AsmJit::Operand::VarData  : %u\n", (uint32_t)sizeof(Operand::VarData));
  printf("  AsmJit::Operand::BinData  : %u\n", (uint32_t)sizeof(Operand::BinData));
  printf("\n");

  printf("  AsmJit::Assembler         : %u\n", (uint32_t)sizeof(Assembler));
  printf("  AsmJit::Compiler          : %u\n", (uint32_t)sizeof(Compiler));
  printf("  AsmJit::FunctionDefinition: %u\n", (uint32_t)sizeof(FunctionDefinition));
  printf("\n");

  printf("  AsmJit::Emittable         : %u\n", (uint32_t)sizeof(Emittable));
  printf("  AsmJit::EAlign            : %u\n", (uint32_t)sizeof(EAlign));
  printf("  AsmJit::ECall             : %u\n", (uint32_t)sizeof(ECall));
  printf("  AsmJit::EComment          : %u\n", (uint32_t)sizeof(EComment));
  printf("  AsmJit::EData             : %u\n", (uint32_t)sizeof(EData));
  printf("  AsmJit::EEpilog           : %u\n", (uint32_t)sizeof(EEpilog));
  printf("  AsmJit::EFunction         : %u\n", (uint32_t)sizeof(EFunction));
  printf("  AsmJit::EFunctionEnd      : %u\n", (uint32_t)sizeof(EFunctionEnd));
  printf("  AsmJit::EInstruction      : %u\n", (uint32_t)sizeof(EInstruction));
  printf("  AsmJit::EJmp              : %u\n", (uint32_t)sizeof(EJmp));
  printf("  AsmJit::EProlog           : %u\n", (uint32_t)sizeof(EProlog));
  printf("  AsmJit::ERet              : %u\n", (uint32_t)sizeof(ERet));
  printf("\n");

  printf("  AsmJit::VarData           : %u\n", (uint32_t)sizeof(VarData));
  printf("  AsmJit::VarAllocRecord    : %u\n", (uint32_t)sizeof(VarAllocRecord));
  printf("  AsmJit::StateData         : %u\n", (uint32_t)sizeof(StateData));
  printf("\n");

  return 0;
}
