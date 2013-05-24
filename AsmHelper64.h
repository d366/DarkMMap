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
        virtual void GenCall( void* pFN, std::initializer_list<GenVar> args);

        // Function call code (__cdecl convention)
        virtual void GenCallCdecl(void* pFN, std::initializer_list<GenVar> args);

        // Function call code (__thiscall convention)
        virtual void GenCallThiscall(void* pFN, std::initializer_list<GenVar> args);

        // Return from remote thread
        virtual void ExitThreadWithStatus();

        // 
        virtual void SaveRetValAndSignalEvent();

    private:

        template<typename _Type>
        void PushArgp(_Type arg, size_t index)
        {
            if( index == 0)
                a.mov(AsmJit::rcx, arg);
            else if( index == 1)
                a.mov(AsmJit::rdx, arg);
            else if( index == 2)
                a.mov(AsmJit::r8, arg);
            else if( index == 3)
                a.mov(AsmJit::r9, arg);
            else
            {
                a.mov(AsmJit::r15, arg);
                a.mov(AsmJit::qword_ptr(AsmJit::rsp, index*WordSize), AsmJit::r15);
            }
        }

        void PushArg(GenVar arg, size_t index);
    };
}
