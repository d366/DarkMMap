#pragma once

#include "AsmHelperBase.h"

namespace ds_mmap
{
    class CAsmHelper64 : public CAsmHelperBase
    {
    public:
        CAsmHelper64(AsmJit::Assembler& _a);
        ~CAsmHelper64(void);

        // Function prologue code
        virtual void GenPrologue();

        // Function epilogue code (with return)
        virtual void GenEpilogue( int retSize = 0);

        // Function call code
        virtual void GenCall( void* pFN, std::initializer_list<GenVar> args, eCalligConvention cc = CC_stdcall );

        // Return from remote thread
        virtual void ExitThreadWithStatus();

        // Save rax value and raise completion event
        virtual void SaveRetValAndSignalEvent();

    private:

        // Pass argument appropriately
        template<typename _Type>
        void PushArgp(_Type arg, size_t index, bool fpu = false)
        {
            static const AsmJit::GPReg regs[]   = { AsmJit::rcx, AsmJit::rdx, AsmJit::r8, AsmJit::r9 };
            static const AsmJit::XMMReg xregs[] = { AsmJit::xmm0, AsmJit::xmm1, AsmJit::xmm2, AsmJit::xmm3 };

            if( index < 4 )
            {
                if(fpu)
                {
                    a.mov(AsmJit::rax, arg);
                    a.movq(xregs[index], AsmJit::rax);
                }
                else
                    a.mov(regs[index], arg);
            }
            else
            {
                a.mov(AsmJit::r15, arg);
                a.mov(AsmJit::qword_ptr(AsmJit::rsp, index * WordSize), AsmJit::r15);
            }
        }

        // Prepare argument to be passed into function
        void PushArg(GenVar arg, size_t index);
    };
}
