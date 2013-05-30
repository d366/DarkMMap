#include "MemCore.h"

namespace ds_mmap
{
    namespace ds_process
    {
        CMemCore::CMemCore(void)
            : m_hProcess(NULL)
            , m_hMainThd(NULL)
            , m_dwImageBase(0)
            , m_pid(0)
            , m_hWorkThd(NULL)
            , m_hWaitEvent(NULL)
            , m_pWorkerCode(nullptr)
            , m_pW8DllBase(nullptr)
        {
        }

        CMemCore::~CMemCore(void)
        {
            if(m_hProcess)
                CloseHandle(m_hProcess);

            if(m_hMainThd)
                CloseHandle(m_hMainThd);
        }

        /*
            Allocate memory in process

            IN:
                size - amount to allocate in bytes
                pAddr - desired address of allocated memory

            OUT:
                pAddr - address of allocated memory

            RETURN:
                Error code
        */
        DWORD CMemCore::Allocate( size_t size, PVOID &pAddr )
        {
            SetLastError(ERROR_SUCCESS);

            pAddr = VirtualAllocEx(m_hProcess, pAddr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if(!pAddr)
            {
                pAddr = VirtualAllocEx(m_hProcess, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if(pAddr)
                    SetLastError(ERROR_IMAGE_NOT_AT_BASE);
            }

            return GetLastError();
        }

        /*
            Free allocated memory in process

            IN:
                pAddr - address to release

            OUT:
                void

            RETURN:
                Error code
        */
        DWORD CMemCore::Free( PVOID pAddr )
        {
            SetLastError(ERROR_SUCCESS);
            VirtualFreeEx(m_hProcess, pAddr, 0, MEM_RELEASE);

            return GetLastError();
        }

        /*
            Change memory protection

            IN:
                pAddr - address to change protection of
                size - size of data
                flProtect - new protection flags

            OUT:
                void

            RETURN:
                Error code
        */
        DWORD CMemCore::Protect( PVOID pAddr, size_t size, DWORD flProtect, DWORD *pOld /*= NULL*/ )
        {
            DWORD dwOld = 0;

            SetLastError(ERROR_SUCCESS);

            VirtualProtectEx(m_hProcess, pAddr, size, flProtect, &dwOld);

            if(pOld)
                *pOld = dwOld;

            return GetLastError();
        }

        /*
            Read process memory

            IN:
                dwAddress - read starting address
                dwSize - bytes to read
                pResult - pointer to receiving buffer

            OUT:
                pResult - read data

            RETURN:
                Error code
        */
        DWORD CMemCore::Read( void* dwAddress, size_t dwSize, PVOID pResult )
        {
            SIZE_T dwRead = 0;

            if(dwAddress == 0)
                return ERROR_INVALID_ADDRESS;

            if(!ReadProcessMemory(m_hProcess, (LPCVOID)dwAddress, pResult, dwSize, &dwRead) || dwRead != dwSize)
                return GetLastError();

            return ERROR_SUCCESS;
        }

        /*
            Write process memory

            IN:
                dwAddress - read starting address
                dwSize - bytes to read
                pResult - pointer to data to be written

            OUT:
                void

            RETURN:
                Error code
        */
        DWORD CMemCore::Write( void* pAddress, size_t dwSize, const void* pData )
        {
            SIZE_T dwWritten = 0;

            if(pAddress == NULL)
            {
                SetLastError(ERROR_INVALID_ADDRESS);
                return ERROR_INVALID_ADDRESS;
            }

            if(!WriteProcessMemory(m_hProcess, pAddress, pData, dwSize, &dwWritten) || dwWritten != dwSize)
                return GetLastError();

            return ERROR_SUCCESS;
        }

        /*
            Perform function call in remote process

            IN:
                pCodeCave - code to execute
                size - size of code
                pArg - argument to pass into function

            OUT:
                callResult - result of execution

            RETURN:
                Error code
        */
        DWORD CMemCore::RemoteCall( PVOID pCode, size_t size, size_t& callResult, PVOID pArg /*= NULL*/ )
        {
            DWORD dwResult  = ERROR_SUCCESS;
            void *pCodecave = NULL;

            //Create codecave
            Allocate(size, pCodecave);

            //Write code into process
            if(Write(pCodecave, size, pCode) != ERROR_SUCCESS)
            {
                if(pCodecave)
                    Free(pCodecave);

                return GetLastError();
            }
    
            dwResult = RemoteCallDirect(pCodecave, pArg, callResult);

            if(pCodecave)
                Free(pCodecave);

            return dwResult;
        }


        /*
            Perform direct function call in remote process by its address

            IN:
                pProc - function address
                pArg - thread argument

            OUT:
                callResult - execution result

            RETURN:
                Error code
        */
        DWORD CMemCore::RemoteCallDirect( PVOID pProc, PVOID pArg, size_t& callResult, bool waitForReturn /*= true */ )
        {
            DWORD dwResult    = ERROR_SUCCESS;
            HANDLE hThread    = NULL;

            //Create execution thread
            callResult  = 0xFFFFFFF0;
            hThread     = CreateRemoteThread(m_hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pProc, pArg, 0, NULL);

            if (hThread && waitForReturn)
            {
                WaitForSingleObject(hThread, INFINITE);
                GetExitCodeThread(hThread, (LPDWORD)&callResult);
            }

            return dwResult;
        }

        /*
            Create event to synchronize APC procedures

            RETURN:
                Error code
        */
        bool CMemCore::CreateAPCEvent()
        {
            AsmJit::Assembler a;
            AsmJitHelper ah(a);

            size_t dwResult     = ERROR_SUCCESS;
            void *pCodecave     = NULL;
            LPWSTR pEventName   = L"_MMapEvent_0x54";       // TODO: randomize name
            size_t len          = (wcslen(pEventName) + 1) * sizeof(wchar_t);

            Allocate(a.getCodeSize() + len, pCodecave);

            ah.GenPrologue();
            ah.GenCall(&CreateEventW, {NULL, TRUE, FALSE, (size_t)pCodecave});

            // Save event handle
        #ifdef _M_AMD64
            a.mov(AsmJit::ndx, AsmJit::qword_ptr(AsmJit::nsp, WordSize));
        #else
            a.mov(AsmJit::ndx, dword_ptr(AsmJit::nbp, 2*WordSize));
        #endif   

            a.mov(sysint_ptr(AsmJit::ndx, WordSize), AsmJit::nax);

            ah.ExitThreadWithStatus();
            ah.GenEpilogue();

            if(Write((uint8_t*)pCodecave + len, a.getCodeSize(), a.make()) != ERROR_SUCCESS ||
                Write((uint8_t*)pCodecave, len, pEventName) != ERROR_SUCCESS)
            {
                if(pCodecave)
                    Free(pCodecave);

                return false;
            }

            RemoteCallDirect((uint8_t*)pCodecave + len, m_pWorkerCode, dwResult);

            m_hWaitEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, pEventName);

            if(pCodecave)
                Free(pCodecave);

            return true;
        }

        /*
            Create thread in remote process to execute code later

            RETURN:
                Error code

            Thread code layout:
            -------------------------------------------------------------------------
            | Return value |  Event handle  |  Free Space   | Thread execution code |
            ------------------------------------------------------------------------
            |   4/8 bytes  |    4/8 bytes   |   8/16 bytes  |                       |
            -------------------------------------------------------------------------
        */
        DWORD CMemCore::CreateWorkerThread()
        {
            AsmJit::Assembler a;
            AsmJitHelper ah(a);
            AsmJit::Label l_loop = a.newLabel();
            DWORD dwResult = ERROR_SUCCESS;
            int space = 4*WordSize;

            //
            // Create execution thread
            //
            if(!m_hWorkThd)
            {
                //
                // Create codecave
                //
                if(m_pWorkerCode == nullptr)
                    Allocate(a.getCodeSize() + space, m_pWorkerCode);

                ah.GenPrologue();

                a.bind(l_loop);
                ah.GenCall(&SleepEx, {10, TRUE});
                a.jmp(l_loop);

                ah.ExitThreadWithStatus();
                ah.GenEpilogue();

                // Write code into process
                if(Write((uint8_t*)m_pWorkerCode + space, a.getCodeSize(), a.make()) != ERROR_SUCCESS)
                {
                    if(m_pWorkerCode)
                    {
                        Free(m_pWorkerCode);
                        m_pWorkerCode = nullptr;
                    }

                    return GetLastError();
                }

                m_hWorkThd = CreateRemoteThread(m_hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((uint8_t*)m_pWorkerCode + space), m_pWorkerCode, 0, NULL);

                if (!m_hWorkThd || !CreateAPCEvent())
                    dwResult = GetLastError();
            }

            return dwResult;
        }

        DWORD CMemCore::TerminateWorkerThread()
        {
            /*if(m_hWaitEvent)
            {
                CloseHandle(m_hWaitEvent);
                m_hWaitEvent = NULL;
            }*/

            if(m_hWorkThd)
            {
                BOOL res   = TerminateThread(m_hWorkThd, 0);
                m_hWorkThd = NULL;

                /*if(m_pWorkerCode)
                {
                    Free(m_pWorkerCode);
                    m_pWorkerCode = nullptr;
                }*/

                return res == TRUE;
            }
            else
                return ERROR_SUCCESS;
        }

        /*
            Execute code in context of existing thread

            IN:
                pCode - code to execute
                size - code size

            OUT:
                callResult - last function result

            RETURN:
                Error code
        */
        DWORD CMemCore::ExecInWorkerThread( PVOID pCode, size_t size, size_t& callResult )
        {
            DWORD dwResult  = ERROR_SUCCESS;
            void *pCodecave = NULL;

            if(Allocate(size, pCodecave) != ERROR_SUCCESS)
                return GetLastError();

            if(Write(pCodecave, size, pCode) != ERROR_SUCCESS)
            {
                if(pCodecave)
                    Free(pCodecave);

                return GetLastError();
            }

            // Create thread if needed
            if(!m_hWorkThd)
                CreateWorkerThread();

            if(m_hWaitEvent)
                ResetEvent(m_hWaitEvent);

            // Execute code in thread context
            QueueUserAPC((PAPCFUNC)pCodecave, m_hWorkThd, (ULONG_PTR)m_pWorkerCode);

            dwResult   = WaitForSingleObject(m_hWaitEvent, INFINITE);
            callResult = Read<size_t>((size_t)m_pWorkerCode);

            if(pCodecave)
                Free(pCodecave);

            return dwResult;
        }

        /*void* CMemCore::GetLdrpModuleBaseAddressIndex()
        {
            if(m_pW8DllBase == nullptr)
            {
                uint8_t *pCodeBase = nullptr;
                size_t codeSize    = 0;

                HMODULE mod = GetModuleHandle(L"ntdll.dll");
                if(!mod)
                    return nullptr;

                IMAGE_DOS_HEADER *pDos = (IMAGE_DOS_HEADER*)mod;
                IMAGE_NT_HEADERS *pNtHdr = (IMAGE_NT_HEADERS*)((size_t)mod + pDos->e_lfanew);
                IMAGE_SECTION_HEADER *pSection = (IMAGE_SECTION_HEADER*)((size_t)pNtHdr + sizeof(IMAGE_NT_HEADERS));

                // Search for code section
                for(size_t i = 0; i < pNtHdr->OptionalHeader.NumberOfRvaAndSizes; i++)
                {
                    if(_stricmp((char*)pSection->Name, ".text") == 0)
                    {
                        pCodeBase = (uint8_t*)mod + pSection->VirtualAddress;
                        codeSize  = pSection->Misc.VirtualSize;
                        break;
                    }
                }

                if(pCodeBase)
                {
                    const char *pBytes = "\x8B\xFF\x55\x8B\xEC\x53\x56\x57\x8B\xF0\x33\xFF\x33\xDB\x85\xF6";
                    std::vector<size_t> found;

                    FindBytes((const uint8_t*)pBytes, strlen(pBytes), found, (size_t)pCodeBase, codeSize);

                    if(!found.empty())
                    {
                        m_pW8DllBase = *(void**)(found.front() + 0x28);
                        return m_pW8DllBase;
                    }
                }

                return nullptr;
            }
            else
                return m_pW8DllBase;
        }

        int CMemCore::FindBytes( const uint8_t *val, size_t valSize, std::vector<size_t> &out, size_t startAddress, size_t regionSize )
        {
            // Search memory region
            for(size_t ptr = startAddress; ptr < startAddress + regionSize; ptr ++)
            {
                if( memcmp( (void*)ptr, val, valSize ) == 0 )
                    out.push_back(ptr);
            }

            return 0;
        }*/

    }
}