#ifndef _MEM_CORE_H_
#define _MEM_CORE_H_

#include "stdafx.h"
#include "LDasm.h"
#include "AsmHelperBase.h"
#include "AsmHelper32.h"
#include "AsmHelper64.h"

namespace ds_mmap
{
    namespace ds_process
    {
        class CMemCore
        {
            friend class CMemModules;
            friend class CProcess;
    
        public:
            CMemCore(void);
            ~CMemCore(void);
    
            /*
                Allocate memory in process
    
                IN:
                    size - amount to allocate in bytes
    
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
    
                OUT:
                    void
    
                RETURN:
                    Error code
            */
            DWORD Free(PVOID pAddr);
    
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
                T res;
    
                if(Read(dwAddress, sizeof(T), &res) != ERROR_SUCCESS)
                    return (T)-1;
    
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
            DWORD Write(void* pAddress, size_t dwSize, void* pData);
    
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
            DWORD RemoteCall( PVOID pCode, size_t size, size_t& callResult, PVOID pArg = NULL);
    
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
                Create thread in remote process to execute code later
    
                RETURN:
                    Error code
            */
            DWORD CreateWorkerThread();
    
            /*
                Terminate existing worker thread
    
                RETURN:
                    Error code
            */
            DWORD TerminateWorkerThread();
    
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
            DWORD ExecInWorkerThread( PVOID pCode, size_t size, size_t& callResult );
    
        
        private:
            /*
                Create event to synchronize APC procedures
    
                RETURN:
                    Error code
            */
            bool CreateAPCEvent();
    
        private:
            HANDLE  m_hProcess;         // Process handle
            HANDLE  m_hMainThd;         // Process main thread handle
            HANDLE  m_hWorkThd;        // Worker thread handle
            HANDLE  m_hWaitEvent;      // APC sync event handle
            DWORD   m_dwImageBase;      // Address of main module
            DWORD   m_pid;              // Process PID
            void*   m_pWorkerCode;     // Worker thread address space
        };
    }
}

#endif//_MEM_CORE_H_