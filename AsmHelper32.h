#pragma once

#include "AsmHelperBase.h"

namespace ds_mmap
{
    class CAsmHelper32 : public CAsmHelperBase
    {
    public:
        CAsmHelper32(AsmJit::Assembler& _a);
        ~CAsmHelper32(void);

        // 
        virtual void GenPrologue();

        // 
        virtual void GenEpilogue( int retSize = WordSize );

        // Function call code (__stdcall convention)
        virtual void GenCall(void* pFN, std::initializer_list<GenVar> args);

        // Function call code (__cdecl convention)
        virtual void GenCallCdecl(void* pFN, std::initializer_list<GenVar> args);

        // Function call code (__thiscall convention)
        virtual void GenCallThiscall(void* pFN, std::initializer_list<GenVar> args);

        // Return from remote thread
        virtual void ExitThreadWithStatus();

        // Return from remote thread
        virtual void SaveRetValAndSignalEvent();

    private:
        CAsmHelper32& operator = (const CAsmHelper32& other);

        template<typename _Type>
        void PushArg(_Type arg, bool bThiscall = false)
        {
            if(arg.getType() == GenVar::imm)
            {
                if(bThiscall)
                    a.mov(AsmJit::ecx, arg.getImm());
                else
                    a.push(arg.getImm());
            }
            else if(arg.getType() == GenVar::mem_ptr)
            {
                a.lea(AsmJit::eax, arg.getMem());
                if(bThiscall)
                    a.mov(AsmJit::ecx, AsmJit::eax);
                else
                    a.push(AsmJit::eax);
            }
            else if(arg.getType() == GenVar::mem)
            {
                if(bThiscall)
                    a.mov(AsmJit::ecx, arg.getMem());
                else
                    a.push(arg.getMem());
            }
            else
            {
                if(bThiscall)
                    a.mov(AsmJit::ecx, arg.getReg());
                else
                    a.push(arg.getReg());
            }
        }
    };
}

