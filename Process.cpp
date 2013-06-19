#include "Process.h"

namespace ds_mmap
{
    namespace ds_process
    {
        // taken from CRT include <Ehdata.h>
        #define EH_MAGIC_NUMBER1        0x19930520    
        #define EH_PURE_MAGIC_NUMBER1   0x01994000
        #define EH_EXCEPTION_NUMBER     ('msc' | 0xE0000000)

        void*  CProcess::pImageBase = nullptr;
        size_t CProcess::imageSize  = 0;

        CProcess::CProcess()
            : Modules(Core)
            , m_pVEHCode(nullptr)
            , m_hVEH(nullptr)
        {
            GrantPriviledge(SE_LOAD_DRIVER_NAME);

        #ifdef _M_AMD64
            //AddVectoredExceptionHandler(0, &CProcess::VectoredHandler64);
        #else
            //AddVectoredExceptionHandler(0, &CProcess::VectoredHandler32);
        #endif
        }

        CProcess::~CProcess(void)
        {
        }


        /*
            Set working Game process

            IN:
                pid - process ID
                bLoadDll - dll injection flag
                hProcess - handle to game process, if it was previously created by CProcess::Create

            OUT:
                void

            RETURN:
                void
        */
        void CProcess::Attach( DWORD pid, HANDLE hProcess /*= NULL*/ )
        {
            // Detach from existing process, if any
            if(Core.m_hProcess)
            {
                CloseHandle(Core.m_hProcess);
                Core.m_hProcess = NULL;
            }

            DWORD dwAccess  = PROCESS_QUERY_INFORMATION | 
                              PROCESS_VM_READ           | 
                              PROCESS_VM_WRITE          | 
                              PROCESS_VM_OPERATION      | 
                              PROCESS_CREATE_THREAD     |
                              PROCESS_TERMINATE;

            Core.m_pid        = pid;
            Core.m_hProcess   = (hProcess != NULL) ? hProcess : OpenProcess(dwAccess, FALSE, pid);

            Modules.NtLoader().Init();
        }

        /*
            Return current process PID
        */
        DWORD CProcess::Pid()
        {
            return Core.m_pid;
        }

        /*
            Checks if process is still valid. (crash detection)

            RETURN:
                Validity flag
        */
        bool CProcess::IsValid()
        {
            DWORD dwExitCode;

            if(!GetExitCodeProcess(Core.m_hProcess, &dwExitCode))
                return false;

            return (dwExitCode == STILL_ACTIVE);
        }

        /*
            Return address of main module

            IN:
                void

            OUT:
                void

            RETURN:
                Address of main module
        */
        DWORD CProcess::ModuleBase()
        {
            return Core.m_dwImageBase;
        }

        /*
            Disable DEP for target process

            RETURN:
                Error code
        */
        DWORD CProcess::DisabeDEP()
        {
            // Try to use driver to disable DEP
            HANDLE hFile = CreateFile(_T("\\\\.\\DarkDep"), GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);

            if(hFile != INVALID_HANDLE_VALUE)
            {
                ULONGLONG pid = Core.m_pid;
                DWORD junk    = 0;
                BOOL result   = DeviceIoControl(hFile, (DWORD)IOCTL_DARKDEP_DISABLE_DEP, &pid, sizeof(pid), NULL, 0, &junk, NULL);

                CloseHandle(hFile);

                return result ? ERROR_SUCCESS : GetLastError();
            }

            return GetLastError();
        }

        /*
            Inject VEH wrapper into process
            Used to enable execution of SEH handlers out of image

            RETURN:
                Error code
        */
        DWORD CProcess::CreateVEH( size_t pTargetBase /*= 0*/, size_t imageSize /*= 0*/ )
        {
            AsmJit::Assembler a;
            AsmJitHelper ah(a);
            size_t result = 0;
    
            //
            // Copy CProcess::VectoredHandler into target process
            //
            if(Core.Allocate(0x1000, m_pVEHCode) != ERROR_SUCCESS)
                return GetLastError();

        #ifdef _M_AMD64 
            // Resolve compiler incremental table address, if any
            AsmJit::Assembler ea;
            AsmJit::Label lExit = ea.newLabel();

            //
            // Assembly code for VectoredHandler64
            // 0x10 - EXCEPTION_RECORD.ExceptionAddress
            // 0x20 - EXCEPTION_RECORD.ExceptionInformation[0]
            // 0x30 - EXCEPTION_RECORD.ExceptionInformation[2]
            // 0x38 - EXCEPTION_RECORD.ExceptionInformation[3]
            //
            ea.mov(AsmJit::rax, qword_ptr(AsmJit::rcx));
            //ea.cmp(AsmJit::qword_ptr(AsmJit::rax), EH_EXCEPTION_NUMBER);
            //ea.jne(lExit);
            ea.mov(AsmJit::rdx, pTargetBase);
            ea.mov(AsmJit::r8, AsmJit::qword_ptr(AsmJit::rax, 0x30));
            ea.cmp(AsmJit::r8, AsmJit::rdx); 
            ea.jl(lExit);
            ea.add(AsmJit::rdx, imageSize);
            ea.cmp(AsmJit::r8, AsmJit::rdx); 
            ea.jg(lExit);
            ea.cmp(AsmJit::qword_ptr(AsmJit::rax, 0x20), EH_PURE_MAGIC_NUMBER1); 
            ea.jne(lExit);
            ea.cmp(AsmJit::qword_ptr(AsmJit::rax, 0x38), 0);
            ea.jne(lExit);
            ea.mov(AsmJit::qword_ptr(AsmJit::rax, 0x20), EH_MAGIC_NUMBER1);
            ea.mov(AsmJit::rcx, qword_ptr(AsmJit::rcx));
            ea.mov(AsmJit::rdx, pTargetBase);
            ea.mov(AsmJit::qword_ptr(AsmJit::rax, 0x38), AsmJit::rdx);
            ea.bind(lExit);
            ea.xor_(AsmJit::eax, AsmJit::eax);
            ea.ret();         

            if(Core.Write(m_pVEHCode, ea.getCodeSize(), ea.make()) != ERROR_SUCCESS)
            {
                Core.Free(m_pVEHCode);
                m_pVEHCode = nullptr;
                return GetLastError();
            }
        #else
            UNREFERENCED_PARAMETER(pTargetBase);
            UNREFERENCED_PARAMETER(imageSize);

            // Resolve compiler incremental table address if any
            void *pFunc = ResolveJmp(&CProcess::VectoredHandler32);   

            if(Core.Write(m_pVEHCode, SizeOfProc(pFunc), pFunc) != ERROR_SUCCESS)
            {
                Core.Free(m_pVEHCode);
                m_pVEHCode = nullptr;
                return GetLastError();
            }
        #endif

            ah.GenPrologue();

            //
            // AddVectoredExceptionHandler(0, pHandler);
            //
            ah.GenCall(&AddVectoredExceptionHandler, {0, (size_t)m_pVEHCode});

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
            m_hVEH = (void*)result;

            return (result == 0 ? GetLastError() : ERROR_SUCCESS);
        }

        /*
            Remove VEH wrapper from process

            RETURN:
                Error code
        */
        DWORD CProcess::RemoveVEH()
        {
            AsmJit::Assembler a;
            AsmJitHelper ah(a);
            size_t result = 0;

            ah.GenPrologue();

            // RemoveVectoredExceptionHandler(pHandler);
            ah.GenCall(&RemoveVectoredExceptionHandler, {(size_t)m_hVEH});

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
            //Core.Free(m_pVEHCode);

            return GetLastError();
        }

        /*
            Unlink memory region from process VAD list
        */
        DWORD CProcess::UnlinkVad( void* pBase, size_t size )
        {
            HANDLE hFile = CreateFile(_T("\\\\.\\VadPurge"), GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);

            // Load missing driver
            if(hFile == INVALID_HANDLE_VALUE)
            {
                DWORD err = LoadDriver(DRV_FILE);

                if(err != ERROR_SUCCESS && err != STATUS_IMAGE_ALREADY_LOADED)
                    return err;

                hFile = CreateFile(_T("\\\\.\\VadPurge"), GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);
            }

            if(hFile != INVALID_HANDLE_VALUE)
            {
                PURGE_DATA data = { Core.m_pid, 1, { (ULONGLONG)pBase, size} };
                DWORD junk      = 0;

                BOOL result = DeviceIoControl(hFile, (DWORD)IOCTL_VADPURGE_PURGE, &data, sizeof(data), NULL, 0, &junk, NULL);

                CloseHandle(hFile);

                return result ? ERROR_SUCCESS : GetLastError();
            }

            return GetLastError();
        }

        /*
            Load driver by name. Driver must reside in current working directory

            IN:
                name - driver filename

            RETURN:
                Error code

        */
        DWORD CProcess::LoadDriver( const std::wstring& name )
        {
            HKEY key1, key2;
            DWORD dwType = 1;
            UNICODE_STRING Ustr;
            LSTATUS status = 0;
            WCHAR wszLocalPath[MAX_PATH] = {0};
            WCHAR wszFilePath[MAX_PATH]  = {0};

            GetFullPathName(name.c_str(), ARRAYSIZE(wszFilePath), wszFilePath, NULL);

            wsprintf(wszLocalPath, L"\\??\\%s", wszFilePath);

            status = RegOpenKey(HKEY_LOCAL_MACHINE, L"system\\CurrentControlSet\\Services", &key1);

            if(status)
                return status;

            status = RegCreateKeyW(key1, DRV_NAME, &key2);

            if(status)
            {
                RegCloseKey(key1);
                return status;
            }

            status = RegSetValueEx(key2, L"ImagePath", 0, REG_SZ, (BYTE*)wszLocalPath, (DWORD)(sizeof(WCHAR) * (wcslen(wszLocalPath) + 1)));

            if(status)
            {
                RegCloseKey(key2);
                RegCloseKey(key1);
                return status;
            }

            status = RegSetValueEx(key2, L"Type", 0, REG_DWORD, (BYTE*)&dwType, sizeof(DWORD));

            if(status)
            {
                RegCloseKey(key2);
                RegCloseKey(key1);
                return status;
            }

            RegCloseKey(key2);
            RegCloseKey(key1);

            RtlInitUnicodeString((PUNICODE_STRING)&Ustr, DRV_REG_PATH);

            // Remove previously loaded instance
            NtUnloadDriver(&Ustr);

            return NtLoadDriver(&Ustr);
        }

        /*
            Grant current process arbitrary privilege

            IN:
                name - privilege name

            RETURN:
                Error code
        */
        DWORD CProcess::GrantPriviledge( const std::wstring& name )
        {
            TOKEN_PRIVILEGES Priv, PrivOld;
            DWORD cbPriv = sizeof(PrivOld);
            HANDLE hToken;

            if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,FALSE, &hToken))
            {
                if (GetLastError()!=ERROR_NO_TOKEN)
                    return GetLastError();

                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
                    return GetLastError();
            }

            Priv.PrivilegeCount = 1;
            Priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            LookupPrivilegeValue(NULL, name.c_str(), &Priv.Privileges[0].Luid);

            if (!AdjustTokenPrivileges(hToken, FALSE, &Priv, sizeof(Priv),&PrivOld, &cbPriv))
            {
                CloseHandle(hToken);
                return GetLastError();
            }

            if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
            {
                CloseHandle(hToken);
                return GetLastError();
            }

            return ERROR_SUCCESS;
        }


        /*
            VEH to inject into process
        */
        #ifdef _M_AMD64

        //
        // This thing is fragile as fuck.
        // Assumptions were made after some testing and may not be 100% accurate
        // Support for C++ exceptions generated by non VC++ compiler weren't tested at all so I suppose they don't work
        //
        LONG CALLBACK CProcess::VectoredHandler64( _In_ PEXCEPTION_POINTERS ExceptionInfo )
        {
            // Check if it's a VC++ exception
            // for SEH RtlAddFunctionTable is enough
            if(ExceptionInfo->ExceptionRecord->ExceptionCode == EH_EXCEPTION_NUMBER)
            {
                // Check exception site image boundaries
                if(ExceptionInfo->ExceptionRecord->ExceptionInformation[2] >= (ULONG_PTR)pImageBase
                    && ExceptionInfo->ExceptionRecord->ExceptionInformation[2] <= ((ULONG_PTR)pImageBase + imageSize))
                {
                    // Assume that's our exception because ImageBase = 0 and not suitable magic number
                    if(ExceptionInfo->ExceptionRecord->ExceptionInformation[0] == EH_PURE_MAGIC_NUMBER1 
                        && ExceptionInfo->ExceptionRecord->ExceptionInformation[3] == 0)
                    {
                        // magic number (seems it , this one is for vc110)
                        ExceptionInfo->ExceptionRecord->ExceptionInformation[0] = (ULONG_PTR)EH_MAGIC_NUMBER1;

                        // fix exception image base
                        ExceptionInfo->ExceptionRecord->ExceptionInformation[3] = (ULONG_PTR)pImageBase;
                    }
                }
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }

        #else

        // warning C4733: Inline asm assigning to 'FS:0' : handler not registered as safe handler
        #pragma warning(disable : 4733)

        typedef _EXCEPTION_DISPOSITION(__cdecl *_pexcept_handler)
            (
                _EXCEPTION_RECORD *ExceptionRecord,
                void * EstablisherFrame,
                _CONTEXT *ContextRecord,
                void * DispatcherContext
            );

        LONG __declspec(naked) CALLBACK CProcess::VectoredHandler32( _In_ PEXCEPTION_POINTERS ExceptionInfo )
        {
            EXCEPTION_REGISTRATION_RECORD  *pFs;
            EXCEPTION_DISPOSITION           res;

            __asm
            {
                push ebp
                mov ebp, esp
                sub esp, __LOCAL_SIZE
            }

            pFs = (EXCEPTION_REGISTRATION_RECORD*)__readfsdword(0);
            res = ExceptionContinueSearch;

            // Prevent CRT from calling handlers in chain with EH_UNWINDING
            for(; res == ExceptionContinueSearch && pFs && pFs != (EXCEPTION_REGISTRATION_RECORD*)0xffffffff; pFs = pFs->Next, __writefsdword(0, (DWORD)pFs))
            {
                ExceptionInfo->ExceptionRecord->ExceptionFlags &= ~EXCEPTION_UNWIND;

                if(pFs->Handler)
                {
                    // Last frame contains special handler with __stdcall convention
                    if(pFs->Next != (EXCEPTION_REGISTRATION_RECORD*)0xffffffff)
                        res = ((_pexcept_handler)pFs->Handler)(ExceptionInfo->ExceptionRecord, pFs, ExceptionInfo->ContextRecord, NULL);
                    else
                        res = pFs->Handler(ExceptionInfo->ExceptionRecord, pFs, ExceptionInfo->ContextRecord, NULL);

                    // Unwind stack properly
                    if(res == ExceptionContinueSearch)
                    {
                        ExceptionInfo->ExceptionRecord->ExceptionFlags |= EXCEPTION_UNWIND;

                        if(pFs->Next != (EXCEPTION_REGISTRATION_RECORD*)0xffffffff)
                            res = ((_pexcept_handler)pFs->Handler)(ExceptionInfo->ExceptionRecord, pFs, ExceptionInfo->ContextRecord, NULL);
                        else
                            res = pFs->Handler(ExceptionInfo->ExceptionRecord, pFs, ExceptionInfo->ContextRecord, NULL);
                    }
                }
            }

            // We are screwed if got here
            //return EXCEPTION_CONTINUE_SEARCH;
            __asm
            {
                mov esp, ebp
                pop ebp

                mov eax, EXCEPTION_CONTINUE_SEARCH
                ret 4
            }
        }
#pragma warning(default : 4733)
        #endif//_M_AMD64
    }
}
