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

    void CAsmHelper32::GenCall( void* pFN, std::initializer_list<GenVar> args )
    {
        // Set args
        for(int i = (int)args.size() - 1; i >= 0; i--)
        {
            const GenVar& arg = *(args.begin() + i);
            PushArg(arg);
        }

        a.mov   (AsmJit::eax, (size_t)pFN);
        a.call  (AsmJit::eax);
    }

    void CAsmHelper32::GenCallCdecl( void* pFN, std::initializer_list<GenVar> args )
    {
        // Set args
        GenCall(pFN, args);
        a.add(AsmJit::esp, args.size() * WordSize);
    }

    void CAsmHelper32::GenCallThiscall( void* pFN, std::initializer_list<GenVar> args )
    {
        // Set args
        for(int i = (int)args.size() - 2; i > 0; i--)
        {
            const GenVar& arg = *(args.begin() + i);
            PushArg(arg);
        }

        // First arg in ecx
        PushArg (*args.begin());
        a.mov   (AsmJit::eax, (size_t)pFN);
        a.call  (AsmJit::eax);
    }

    void CAsmHelper32::ExitThreadWithStatus()
    {
        a.push  (AsmJit::eax);
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
}