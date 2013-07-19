#pragma once

#include "stdafx.h"
#include "FileProjection.h"
#include "PEManger.h"
#include "Process.h"
#include "ImageNET.h"

#include <map>

namespace ds_mmap
{
    // DllMain routine
    typedef BOOL (APIENTRY *pDllMain)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

    enum eLoadFlags
    {
        NoFlags         = 0x00,     // No flags
        ManualImports   = 0x01,     // Manually map import libraries
        CreateLdrRef    = 0x02,     // Create module references for native loader
        UnlinkVAD       = 0x04,     // Unlink image VAD from process VAD tree
        RebaseProcess   = 0x20,     // If target image is an .exe file, process base address will be replaced with mapped module value

        NoExceptions    = 0x1000,   // Do not create custom exception handler
        NoDelayLoad     = 0x2000,   // Do not resolve delay import
        NoSxS           = 0x4000,   // Do not apply SxS activation context
    };

    struct ImageContext
    {
        CFileProjection      Image;           // Image file mapping
        ds_pe::CPEManger     ImagePE;         // PE parser
        eLoadFlags           flags;           // Image loader flags
        void                *pTargetBase;     // Target image base address
        size_t               pExpTableAddr;   // Exception table address (amd64 only)
        std::vector<void*>   tlsCallbacks;    // TLS callback routines
        std::tr2::sys::wpath FilePath;        // path to image being mapped
        std::wstring         FileName;        // File name string
        pDllMain             EntryPoint;      // Target image entry point

        ImageContext()
            : flags(NoFlags)
            , pTargetBase(nullptr)
            , pExpTableAddr(0)
            , FilePath(L"")
            , EntryPoint(nullptr)
        {
        }

        ~ImageContext()
        {
        }
    };

    typedef std::vector<std::unique_ptr<ImageContext>> vecImageCtx;

    //
    // Image mapper
    //
    class CDarkMMap
    {
        
    public:
        CDarkMMap(DWORD pid);
        ~CDarkMMap(void);

        /*
            Manually map PE image into target process

            IN:
                path - path to image
                flags - loader flags

            RETURN:
                Loaded module base address
        */
        HMODULE MapDll( const std::wstring& path, eLoadFlags flags = NoFlags );
        HMODULE MapDll( const std::string&  path, eLoadFlags flags = NoFlags );

        /*
            Map pure managed dll
        */
        HMODULE MapPureManaged();

        /*
            Unmap associated PE image from target process
        */
        bool UnmapAllModules();

        /*
            Get address of function in another process

            IN:
                hMod - module base
                func - function name or ordinal

            OUT:
                void

            RETURN:
                Function address
                0 - if not found shdocvw.dll 0x8d
        */
        FARPROC GetProcAddressEx(HMODULE mod, const char* procName);
        
    private:
        /*
            Copy image header and sections into target process
        */
        bool CopyImage();

        /*
            Set proper section protection
        */
        bool ProtectImageMemory();

        /*
            Fix relocations if image wasn't loaded at base address
        */
        bool RelocateImage();

        /*
            Fill import table
        */
        bool ResolveImport();

        /*
            Fill delay import table
        */
        bool ResolveDelayImport();

        /*
            Resolve static TLS storage
        */
        bool InitStaticTLS();

        /*
            Execute TLS callbacks

            IN:
                dwReason - DLL_PROCESS_ATTACH
                           DLL_THREAD_ATTACH 
                           DLL_PROCESS_DETACH
                           DLL_THREAD_DETTACH
        */
        bool RunTLSInitializers(DWORD dwReason);

        /*
            Call image entry point

            IN:
                dwReason - DLL_PROCESS_ATTACH
                           DLL_THREAD_ATTACH 
                           DLL_PROCESS_DETACH
                           DLL_THREAD_DETTACH
        */
        bool CallEntryPoint(DWORD dwReason);

        /*
            Set custom exception handler to bypass SafeSEH under DEP 
        */
        bool EnableExceptions();

        /*
            Remove custom exception handler
        */
        bool DisableExceptions();

        /*
            Create SxS activation context from image manifest

            IN:
                id - manifest resource id
        */
        bool CreateActx(int id = 2);

        /*
            Free existing activation context, if any
        */
        bool FreeActx();

        /*
            Calculate and set security cookie
        */
        bool InitializeCookie();

        /*
            Transform section characteristics into memory protection flags

            IN:
                characteristics - section characteristics

            RETURN:
                Memory protection value
        */
        DWORD GetSectionProt(DWORD characteristics);

    private:
        vecImageCtx             m_Images;           // Mapped images
        ImageContext           *m_pTopImage;        // Image context information 
        ds_process::CProcess    m_TargetProcess;    // Target process manager
        int                     m_tlsIndex;         // Current static TLS index
        void                   *m_pAContext;        // SxS activation context memory address
    };
}

