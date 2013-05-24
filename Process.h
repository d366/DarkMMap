#ifndef _PROCESS_H_
#define _PROCESS_H_

#include "stdafx.h"
#include "MemCore.h"
#include "MemModules.h"

namespace ds_mmap
{
    namespace ds_process
    {
        #define FILE_DEVICE_DARKDEP             0x00008006
        #define IOCTL_DARKDEP_DISABLE_DEP       CTL_CODE(FILE_DEVICE_DARKDEP, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
        #define IOCTL_DARKDEP_SET_PROTECTION    CTL_CODE(FILE_DEVICE_DARKDEP, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

        //#pragma pack( push, 8 )
        typedef struct _SET_PROC_PROTECTION
        {
            ULONG    pid;
            BOOLEAN enableState;
        }SET_PROC_PROTECTION, *PSET_PROC_PROTECTION;
        //#pragma pack( pop )

        //Provides operations with game process memory 
        class CProcess
        {
        public:
            CProcess();
            ~CProcess(void);

            /*
                Set working Game process

                IN:
                    hProcess - handle to game process
                    dwModuleBase - address of main module

                OUT:
                    void

                RETURN:
                    void
            */
            void Attach(DWORD pid, HANDLE hProcess = NULL);

            /*
                Return current process PID
            */
            DWORD Pid();

            /*
                Checks if process is still valid. (crash detection)

                RETURN:
                    Validity flag
            */
            bool IsValid();
    
            /*
                Return address of main module

                RETURN:
                    Address of main module
            */
            DWORD ModuleBase();

            /*
                Disable DEP for target process

                RETURN:
                    Error code
            */
            DWORD DisabeDEP();

            /*
                Inject VEH wrapper into process
                Used to enable execution of SEH handlers out of image

                RETURN:
                    Error code
            */
            DWORD CreateVEH(size_t pTargetBase = 0, size_t imageSize = 0);

            /*
                Remove VEH wrapper from process

                RETURN:
                    Error code
            */
            DWORD RemoveVEH();

        public:
            //
            // VEH to inject
            //
        #ifdef _M_AMD64
            static LONG CALLBACK VectoredHandler64( _In_ PEXCEPTION_POINTERS ExceptionInfo );
        #else
            static LONG CALLBACK VectoredHandler32( _In_ PEXCEPTION_POINTERS ExceptionInfo );
        #endif

        public:
            CMemCore    Core;       // Process core memory routines
            CMemModules Modules;    // Module routines

            static void* pImageBase;
            static size_t imageSize;

        private:
            void *m_pVEHCode;       // VEH function codecave
            void *m_hVEH;           // VEH handle
        };
    }
}
#endif//_PROCESS_H_