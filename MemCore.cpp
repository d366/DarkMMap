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
            , m_pCodecave(nullptr)
            , m_codeSize(0)
        {
        }

        CMemCore::~CMemCore(void)
        {
            TerminateWorkerThread();

            if(m_hProcess)
                CloseHandle(m_hProcess);

            if(m_hMainThd)
                CloseHandle(m_hMainThd);

            if(m_pCodecave)
                Free(m_pCodecave);

            FreeAll();
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
                {
                    m_Allocations.emplace_back(pAddr);
                    SetLastError(ERROR_IMAGE_NOT_AT_BASE);
                }
            }
            else
                m_Allocations.emplace_back(pAddr);            

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

            //
            // Erase record from allocation table
            //
            auto iter = std::find(m_Allocations.begin(), m_Allocations.end(), pAddr);

            if(iter != m_Allocations.end())
                m_Allocations.erase(iter);

            return GetLastError();
        }

        /*
            Free all allocated memory regions
        */
        void CMemCore::FreeAll()
        {
            for(auto& pAddr : m_Allocations)
                VirtualFreeEx(m_hProcess, pAddr, 0, MEM_RELEASE);

            m_Allocations.clear();
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
            // Allocate new codecave
            if(!m_pCodecave)
            {
                if(Allocate(size, m_pCodecave) != ERROR_SUCCESS)
                    return GetLastError();

                m_codeSize = size;
            }
            // Reallocate for new size
            else if(size > m_codeSize)
            {
                Free(m_pCodecave);
                m_pCodecave = nullptr;

                if(Allocate(size, m_pCodecave) != ERROR_SUCCESS)
                    return GetLastError();

                m_codeSize = size;
            }

            //Write code into process
            if(Write(m_pCodecave, size, pCode) != ERROR_SUCCESS)
                return GetLastError();
    
            return RemoteCallDirect(m_pCodecave, pArg, callResult);
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
        bool CMemCore::CreateAPCEvent( DWORD threadID )
        {
            AsmJit::Assembler a;
            AsmJitHelper ah(a);

            size_t dwResult        = ERROR_SUCCESS;
            void *pCodecave        = NULL;
            wchar_t pEventName[64] = {0};
            size_t len;

            // Generate event name
            swprintf_s(pEventName, ARRAYSIZE(pEventName), L"_MMapEvent_0x%x", threadID);
            len = (wcslen(pEventName) + 1) * sizeof(wchar_t);

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

            if(dwResult == NULL || m_hWaitEvent == NULL)
            {
                SetLastError(ERROR_OBJECT_NOT_FOUND);
                return false;
            }

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
                DWORD thdID = 0;

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

                m_hWorkThd = CreateRemoteThread(m_hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((uint8_t*)m_pWorkerCode + space), m_pWorkerCode, 0, &thdID);

                // Create synchronization event
                if (!m_hWorkThd || !CreateAPCEvent(thdID))
                    dwResult = GetLastError();
            }

            return dwResult;
        }

        /*
        */
        DWORD CMemCore::TerminateWorkerThread()
        {
            if(m_hWaitEvent)
            {
                CloseHandle(m_hWaitEvent);
                m_hWaitEvent = NULL;
            }

            if(m_hWorkThd)
            {
                BOOL res   = TerminateThread(m_hWorkThd, 0);
                m_hWorkThd = NULL;

                if(m_pWorkerCode)
                {
                    Free(m_pWorkerCode);
                    m_pWorkerCode = nullptr;
                }

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
            DWORD dwResult = ERROR_SUCCESS;

            // Allocate new codecave
            if(!m_pCodecave)
            {
                if(Allocate((size > 0x1000) ? size : 0x1000, m_pCodecave) != ERROR_SUCCESS)
                    return GetLastError();

                m_codeSize = size;
            }
            // Reallocate for new size
            else if(size > m_codeSize)
            {
                Free(m_pCodecave);
                m_pCodecave = nullptr;

                if(Allocate(size, m_pCodecave) != ERROR_SUCCESS)
                    return GetLastError();

                m_codeSize = size;
            }

            if(Write(m_pCodecave, size, pCode) != ERROR_SUCCESS)
                return GetLastError();

            // Create thread if needed
            if(!m_hWorkThd)
                CreateWorkerThread();

            if(m_hWaitEvent)
                ResetEvent(m_hWaitEvent);

            // Execute code in thread context
            QueueUserAPC((PAPCFUNC)m_pCodecave, m_hWorkThd, (ULONG_PTR)m_pWorkerCode);

            dwResult   = WaitForSingleObject(m_hWaitEvent, INFINITE);
            callResult = Read<size_t>((size_t)m_pWorkerCode);

            // Ensure APC function fully returns
            Sleep(1);

            return dwResult;
        }

        /*
            Find data by pattern

            IN:
                sig - byte signature to find
                pattern - pattern mask
                scanStart - scan start
                scanSize - size of data to scan

            OUT:
                out - found addresses

            RETURN:
                Number of found items

        */
        size_t CMemCore::FindPattern( const std::string& sig, const std::string& pattern, void* scanStart, size_t scanSize, std::vector<size_t>& out )
        {
            bool fullMatch = false;
            uint8_t *pBuffer = (uint8_t*)VirtualAlloc(NULL, scanSize, MEM_COMMIT, PAGE_READWRITE);

            out.clear();

            // Size mismatch
            if(pattern.length() > sig.length())
                return 0;

            // No arbitrary bytes in mask
            if(pattern.find('?') == pattern.npos)
                fullMatch = true;

            if(pBuffer && Read(scanStart, scanSize, pBuffer) == ERROR_SUCCESS)
            {
                size_t length = pattern.length();

                //
                // Scan buffer
                //
                for(size_t x = 0; x < scanSize - length; x++ )
                {
                    bool bMatch = true;

                    if(fullMatch)
                        bMatch = (memcmp(sig.data(), pBuffer + x, length) == 0);
                    else
                        for(size_t i = 0; i < length; i++)
                        {
                            if(pattern[i] == 'x' && ((char*)(pBuffer + x))[i] != sig[i])
                            {
                                bMatch = false;
                                break;
                            }
                        }

                    if(bMatch)
                        out.emplace_back((size_t)scanStart + x);
                }                
            }

            if(pBuffer)
                VirtualFree(pBuffer, 0, MEM_DECOMMIT);

            return out.size();
        }

        /*
            Retrieve process PEB address

            RETURN:
                PEB address
        */
        PPEB CMemCore::GetPebBase()
        {
            PROCESS_BASIC_INFORMATION pbi = {0};
            ULONG bytes = 0;

            NtQueryInformationProcess(m_hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &bytes);

            return pbi.PebBaseAddress;
        }
        
    }
}