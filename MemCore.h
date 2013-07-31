#ifndef _MEM_CORE_H_
#define _MEM_CORE_H_

#include "stdafx.h"
#include "LDasm.h"
#include "AsmHelperBase.h"
#ifdef _M_AMD64
#include "AsmHelper64.h"
#else
#include "AsmHelper32.h"
#endif
#include "NtStructures.h"
#include <vector>
#include <memory>

namespace ds_mmap
{
    namespace ds_process
    {
        class CMemCore
        {
            friend class CMemModules;
            friend class CProcess;
            friend class CNtLdr;
    
        public:
            CMemCore(void);
            ~CMemCore(void);
    
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
            DWORD Allocate(size_t size, PVOID &pAddr);
    
            /*
                Free allocated memory in process
    
                IN:
                    pAddr - address to release
    
                RETURN:
                    Error code
            */
            DWORD Free(PVOID pAddr);

            /*
                Free all allocated memory regions
            */
            void FreeAll();
    
            /*
                Change memory protection
    
                IN:
                    pAddr - address to change protection of
                    size - size of data
                    flProtect - new protection flags
    
                OUT:
                    pOld - old protection (optional)
    
                RETURN:
                    Error code
            */
            DWORD Protect( PVOID pAddr, size_t size, DWORD flProtect, DWORD *pOld = NULL);
    
    
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
            DWORD Read(void* dwAddress, size_t dwSize, PVOID pResult);
    
            /*
                Read process memory (templated)
    
                IN:
                    dwAddress - read starting address
    
                OUT:
                    void
    
                RETURN:
                    Read data
            */
            template<class T>
            T Read(size_t dwAddress)
            {
                return Read<T>((void*)dwAddress);
            };
    
            template<class T>
            T Read(void* dwAddress)
            {
                T res = {0};
    
                Read(dwAddress, sizeof(T), &res);
    
                return res;
            };
    
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
            DWORD Write(void* pAddress, size_t dwSize, const void* pData);
    
            /*
                Write process memory (templated)
    
                IN:
                    dwAddress - read starting address
                    data - data to be written
    
                OUT:
                    void
    
                RETURN:
                    Error code
            */
            template<class T>
            DWORD Write(size_t dwAddress, T data)
            {
                return Write<T>((void*)dwAddress, data);
            }
    
            template<class T>
            DWORD Write(void* dwAddress, T data)
            {
                if(Write(dwAddress, sizeof(T), &data) != ERROR_SUCCESS)
                    return GetLastError();
    
                return ERROR_SUCCESS;
            }
        
            /*
                Perform function call in remote process
    
                IN:
                    pCode - code to execute
                    size - size of code
                    pArg - argument to pass into function
    
                OUT:
                    callResult - call return value
    
                RETURN:
                    Error code
            */
            DWORD RemoteCall( PVOID pCode, size_t size, size_t& callResult, PVOID pArg = NULL );
    
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
            DWORD RemoteCallDirect( PVOID pProc, PVOID pArg, size_t& callResult, bool waitForReturn = true );
    
            /*
                Create environment for future RPC

                IN:
                     noThread - create only codecave and sync event, without thread
    
                RETURN:
                    Error code
            */
            DWORD CreateRPCEnvironment(bool noThread = false);
    
            /*
                Terminate existing worker thread
    
                RETURN:
                    Error code
            */
            DWORD TerminateWorkerThread();
    
            /*
                Execute code in context of existing worker thread
    
                IN:
                    pCode - code to execute
                    size - code size
    
                OUT:
                    callResult - last function result
    
                RETURN:
                    Error code
            */
            DWORD ExecInWorkerThread( PVOID pCode, size_t size, size_t& callResult );

            /*
                Execute code in context of arbitrary existing thread
    
                IN:
                    pCode - code to execute
                    size - code size
                    thread - handle of thread to execute code in
    
                OUT:
                    callResult - last function result
    
                RETURN:
                    Error code
            */
            DWORD ExecInAnyThread( PVOID pCode, size_t size, size_t& callResult, HANDLE hThread = NULL );

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
            size_t FindPattern(const std::string& sig, const std::string& pattern, void* scanStart, size_t scanSize, std::vector<size_t>& out);

            /*
                Retrieve process PEB address

                RETURN:
                    PEB address
            */
            PPEB GetPebBase();

            /*
                Retrieve thread TEB address

                RETURN:
                    TEB address
            */
            PTEB GetTebBase(HANDLE hThread = NULL);

        private:

            /*
                Create thread for RPC

                RETURN:
                    Thread ID
            */
            DWORD CreateWorkerThread();

            /*
                Create event to synchronize APC procedures
    
                RETURN:
                    Error code
            */
            bool CreateAPCEvent(DWORD threadID);

            /*
                Copy executable code to codecave for future execution

                IN:
                    pCode - code to copy
                    size - code size

                RETURN:
                    Error code
            */
            DWORD PrepareCodecave( PVOID pCode, size_t size  );

        private:
            HANDLE  m_hProcess;         // Process handle
            HANDLE  m_hMainThd;         // Process main thread handle
            HANDLE  m_hWorkThd;         // Worker thread handle
            HANDLE  m_hWaitEvent;       // APC sync event handle
            DWORD   m_pid;              // Process PID
            void*   m_pWorkerCode;      // Worker thread address space
            void*   m_pCodecave;        // Codecave for code execution
            size_t  m_codeSize;         // Current codecave size

            std::vector<void*> m_Allocations;   // List of all memory allocations
        };
    }
}

#endif//_MEM_CORE_H_