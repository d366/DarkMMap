#pragma once

#include "AsmHelperBase.h"

#define LODWORD(l)    ((DWORD)(((ULONGLONG)(l)) & 0xffffffff))
#define HIDWORD(l)    ((DWORD)((((ULONGLONG)(l)) >> 32) & 0xffffffff))

namespace ds_mmap
{
    class CAsmHelper32 : public CAsmHelperBase
    {
    public:
        CAsmHelper32(AsmJit::Assembler& _a);
        ~CAsmHelper32(void);

        // Generate function prologue code
        virtual void GenPrologue();

        // Generate function epilogue code
        virtual void GenEpilogue( int retSize = WordSize );

        // Function call code (__stdcall convention)
        virtual void GenCall(void* pFN, std::initializer_list<GenVar> args, eCalligConvention cc = CC_stdcall);

        // Return from remote thread
        virtual void ExitThreadWithStatus();

        // Return from remote thread
        virtual void SaveRetValAndSignalEvent();

    private:
        CAsmHelper32& operator = (const CAsmHelper32& other);

        // Prepare argument to be passed into function
        void PushArg(const GenVar& arg, eArgType regidx = AT_stack);

        template<typename _Type>
        void PushArgp(_Type arg, eArgType index)
        {
            static const AsmJit::GPReg regs[] = { AsmJit::ecx, AsmJit::edx };

            // for __fastcall and __thiscall
            if( index < AT_stack )
                a.mov(regs[index], arg);
            else
                a.push(arg);
        }

    };
}

