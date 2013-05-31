#pragma once

#include "stdafx.h"

#pragma warning( disable : 4100 4244 4245 4127 )

#include "AsmJit/AsmJit/Assembler.h"
#include "AsmJit/AsmJit/MemoryManager.h"

#pragma warning( default : 4100 4244 4245 4127 )

namespace ds_mmap
{
    #define WordSize sizeof(size_t)

    // General purpose asm variable
    struct GenVar
    {
        enum etype
        {
            reg,
            imm,
            mem,
            mem_ptr
        };

        AsmJit::GPReg reg_val;
        AsmJit::Mem   mem_val;
        size_t        imm_val;
        etype         type;

        GenVar(size_t _imm)
            : type(imm)
            , imm_val(_imm)
        {
        }

        GenVar(const AsmJit::GPReg& _reg)
            : type(reg)
            , reg_val(_reg)
            , imm_val((size_t)-1)
        {
        }

        GenVar(const AsmJit::Mem& _mem)
            : type(mem)
            , mem_val(_mem)
            , imm_val((size_t)-1)
        {
        }

        explicit GenVar(AsmJit::Mem* _mem)
            : type(mem_ptr)
            , mem_val(*_mem)
            , imm_val((size_t)-1)
        {
        }

        inline etype  getType() const { return type; }
        inline size_t getImm()  const { return imm_val; }

        inline const AsmJit::GPReg& getReg() const { return reg_val; }
        inline const AsmJit::Mem&   getMem() const { return mem_val; }
    };

    // 
    // Some helper functions for assembly code generation
    //
    class CAsmHelperBase
    {
    public:
        CAsmHelperBase(AsmJit::Assembler& _a);
        ~CAsmHelperBase(void);

        // Function prologue code
        virtual void GenPrologue() = 0;

        // Function epilogue code
        virtual void GenEpilogue( int retSize = WordSize ) = 0;

        // Function call code (__stdcall convention)
        virtual void GenCall(void* pFN, std::initializer_list<GenVar> args) = 0;

        // Function call code (__cdecl convention)
        virtual void GenCallCdecl(void* pFN, std::initializer_list<GenVar> args) = 0;

        // Function call code (__thiscall convention)
        virtual void GenCallThiscall(void* pFN, std::initializer_list<GenVar> args) = 0;

        // Return from remote thread
        virtual void ExitThreadWithStatus() = 0;

        // Return from remote thread
        virtual void SaveRetValAndSignalEvent() = 0;

    protected:
        AsmJit::Assembler& a;
        CAsmHelperBase& operator=(const CAsmHelperBase& other);
    };

    #ifdef _M_AMD64
    #define AsmJitHelper CAsmHelper64
    #else
    #define AsmJitHelper CAsmHelper32
    #endif
}