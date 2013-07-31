#include "AsmHelper32.h"

namespace ds_mmap
{
    CAsmHelper32::CAsmHelper32( AsmJit::Assembler& _a )
        : CAsmHelperBase(_a)
    {
    }

    CAsmHelper32::~CAsmHelper32(void)
    {
    }

    void CAsmHelper32::GenPrologue()
    {
        a.push  (AsmJit::ebp);
        a.mov   (AsmJit::ebp, AsmJit::esp);
    }

    void CAsmHelper32::GenEpilogue( int retSize /*= WordSize */ )
    {
        a.mov   (AsmJit::esp, AsmJit::ebp);
        a.pop   (AsmJit::ebp);
        a.ret   (retSize);
    }

    void CAsmHelper32::GenCall( void* pFN, std::initializer_list<GenVar> args, eCalligConvention cc /*= CC_stdcall*/ )
    {
        int firsidx = 0;

        // first argument to be pushed on stack
        if(cc == CC_thiscall)
            firsidx = 1;
        else if(cc == CC_fastcall)
            firsidx = 2;

        // Push args on stack
        for(int i = (int)args.size() - 1; i >= firsidx; i--)
        {
            const GenVar& arg = *(args.begin() + i);
            PushArg(arg);
        }

        // Pass arguments in registers
        if((cc == CC_thiscall || cc == CC_fastcall) && args.size() > 0)
        {
            PushArg (*args.begin(), AT_ecx);

            if(args.size() > 1 && cc == CC_fastcall)
                PushArg (*(args.begin() + 1), AT_edx);
        } 

        a.mov (AsmJit::eax, (size_t)pFN);
        a.call(AsmJit::eax);

        if(cc == CC_cdecl)
             a.add(AsmJit::esp, args.size() * WordSize);
    }

    void CAsmHelper32::ExitThreadWithStatus()
    {
        a.mov   (AsmJit::edx, AsmJit::eax);

        // mov eax, fs:[0x18]
        a._emitWord(0xA164);
        a._emitDWord(0x18); 

        a.mov   (AsmJit::dword_ptr(AsmJit::eax, 0x14), AsmJit::edx);
        a.push  (AsmJit::edx);
        a.mov   (AsmJit::eax, (DWORD)&ExitThread);
        a.call  (AsmJit::eax);
    }

    void CAsmHelper32::SaveRetValAndSignalEvent()
    {
        a.mov   (AsmJit::edx, AsmJit::Mem(AsmJit::ebp, 8));
        a.mov   (AsmJit::dword_ptr(AsmJit::edx), AsmJit::eax);

        // SetEvent(hEvent)
        a.mov   (AsmJit::eax, AsmJit::dword_ptr(AsmJit::edx, 4));
        a.push  (AsmJit::eax);
        a.mov   (AsmJit::eax, (DWORD)&SetEvent);
        a.call  (AsmJit::eax);
    }

    void CAsmHelper32::PushArg( const GenVar& arg, eArgType regidx /*= AT_stack*/ )
    {
        if(arg.getType() == GenVar::imm)
        {
            PushArgp(arg.getImm(), regidx);             
        }
        else if(arg.getType() == GenVar::imm_double)
        {
            PushArgp(arg.getImm_double(), regidx);  
        }
        else if(arg.getType() == GenVar::imm_float)
        {
            PushArgp(arg.getImm_float(), regidx);  
        }
        else if(arg.getType() == GenVar::mem_ptr)
        {
            a.lea(AsmJit::eax, arg.getMem());
            PushArgp(AsmJit::eax, regidx); 
        }
        else if(arg.getType() == GenVar::mem)
        {
            PushArgp(arg.getMem(), regidx); 
        }
        else
        {
            PushArgp(arg.getReg(), regidx); 
        }
    }

}