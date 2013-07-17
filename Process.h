#ifndef _PROCESS_H_
#define _PROCESS_H_

#include "stdafx.h"
#include "MemCore.h"
#include "MemModules.h"
#include "VADPurge/VADPurgeDef.h"

#include <winioctl.h>

namespace ds_mmap
{
    namespace ds_process
    {
        #define FILE_DEVICE_DARKDEP             0x00008006
        #define IOCTL_DARKDEP_DISABLE_DEP       CTL_CODE(FILE_DEVICE_DARKDEP, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
        #define IOCTL_DARKDEP_SET_PROTECTION    CTL_CODE(FILE_DEVICE_DARKDEP, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

        #define DRV_NAME                        L"VADPurge"
        #define DRV_FILE                        L"VADPurge.sys"
        #define DRV_REG_PATH                    L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services\\VADPurge"
        #define STATUS_IMAGE_ALREADY_LOADED     ((NTSTATUS)0xC000010EL)

        extern "C" NTSYSAPI NTSTATUS NTAPI NtLoadDriver     (__in PUNICODE_STRING DriverServiceName);
        extern "C" NTSYSAPI NTSTATUS NTAPI NtUnloadDriver   (__in PUNICODE_STRING DriverServiceName);

        // Provides operations with process memory 
        class CProcess
        {
        public:
            CProcess();
            ~CProcess(void);

            /*
                Set working process

                IN:
                    hProcess - handle to process
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

            /*
                Unlink memory region from process VAD list

                IN:
                    pBase - region base address
                    size - region size

                RETURN:
                    Error code
            */
            DWORD UnlinkVad(void* pBase, size_t size);

            //
            // VEH to inject
            //
        #ifdef _M_AMD64
            static LONG CALLBACK VectoredHandler64( _In_ PEXCEPTION_POINTERS ExceptionInfo );
        #else
            static LONG CALLBACK VectoredHandler32( _In_ PEXCEPTION_POINTERS ExceptionInfo );
        #endif

        private:
            /*
                Load driver by name. Driver must reside in current working directory

                IN:
                    name - driver filename

                RETURN:
                    Error code

            */
            DWORD LoadDriver(const std::wstring& name);

            /*
                Grant current process arbitrary privilege

                IN:
                    name - privilege name

                RETURN:
                    Error code
            */
            DWORD GrantPriviledge( const std::wstring& name );

            /*
                Get Handle of oldest existing thread in process
            */
            DWORD GetMainThreadID();

        public:
            CMemCore    Core;       // Process core memory routines
            CMemModules Modules;    // Module routines

            // For debug purposes only
            static void* pImageBase;
            static size_t imageSize;

        private:
            void *m_pVEHCode;       // VEH function codecave
            void *m_hVEH;           // VEH handle
        };
    }
}
#endif//_PROCESS_H_