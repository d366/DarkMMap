#include "AsmHelper64.h"

namespace ds_mmap
{
    CAsmHelper64::CAsmHelper64(AsmJit::Assembler& _a)
        : CAsmHelperBase(_a)
    {
    }

    CAsmHelper64::~CAsmHelper64(void)
    {
    }

    void CAsmHelper64::GenPrologue()
    {
        a.mov (AsmJit::qword_ptr(AsmJit::rsp, 1*WordSize), AsmJit::rcx);
        a.mov (AsmJit::qword_ptr(AsmJit::rsp, 2*WordSize), AsmJit::rdx);
        a.mov (AsmJit::qword_ptr(AsmJit::rsp, 3*WordSize), AsmJit::r8);
        a.mov (AsmJit::qword_ptr(AsmJit::rsp, 4*WordSize), AsmJit::r9);
    }

    void CAsmHelper64::GenEpilogue( int retSize /*= 0*/ )
    {
        UNREFERENCED_PARAMETER(retSize);
        a.ret ();
    }

    void CAsmHelper64::GenCall( void* pFN, std::initializer_list<GenVar> args, eCalligConvention /*cc = CC_stdcall*/ )
    {
        //
        // reserve stack size (0x28 - minimal size for 4 registers and return address)
        // after call, stack must be aligned on 16 bytes boundary
        //
        size_t rsp_dif = (args.size() > 4) ? 0x28 + (args.size() - 4) * WordSize: 0x28;

        // align on (16 bytes - sizeof(return address))
        if((rsp_dif + WordSize) % 16 )
            rsp_dif = ((rsp_dif >> 3) + 1) << 3 ;

        a.sub(AsmJit::rsp, rsp_dif);

        // Set args
        for(size_t i = 0; i < args.size(); i++)
        {
            const GenVar& arg = *(args.begin() + i);
            PushArg(arg, i);
        }

        a.mov   (AsmJit::r13, (size_t)pFN);
        a.call  (AsmJit::r13);
        a.add   (AsmJit::rsp, rsp_dif);
    }

    void CAsmHelper64::ExitThreadWithStatus()
    {
        a.mov   (AsmJit::rcx, AsmJit::rax);
        a.mov   (AsmJit::r13, (DWORD64)&ExitThread);
        a.call  (AsmJit::r13);
    }

    void CAsmHelper64::SaveRetValAndSignalEvent()
    {
        a.mov   (AsmJit::rdx, AsmJit::qword_ptr(AsmJit::rsp, WordSize));
        a.mov   (AsmJit::qword_ptr(AsmJit::rdx), AsmJit::rax);

        // SetEvent(hEvent)
        a.mov   (AsmJit::rcx, AsmJit::qword_ptr(AsmJit::rdx, WordSize));
        a.mov   (AsmJit::r13, (DWORD64)&SetEvent);
        a.call  (AsmJit::r13);
    }

    void CAsmHelper64::PushArg( GenVar arg, size_t index )
    {
        if(arg.getType() == GenVar::imm)
        {
            PushArgp(arg.getImm(), index);
        }
        else if(arg.getType() == GenVar::imm_double)
        {
            PushArgp(arg.getImm_double(), index, true);  
        }
        else if(arg.getType() == GenVar::imm_float)
        {
            PushArgp(arg.getImm_float(), index, true);  
        }
        else if(arg.getType() == GenVar::mem_ptr)
        {
            a.lea(AsmJit::rax, arg.getMem());
            PushArgp(AsmJit::rax, index);
        }
        else if(arg.getType() == GenVar::mem)
        {
            PushArgp(arg.getMem(), index);
        }
        else
        {
            PushArgp(arg.getReg(), index);
        }
    }
}
