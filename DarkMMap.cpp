#include "DarkMMap.h"

namespace ds_mmap
{
    CDarkMMap::CDarkMMap(DWORD pid)
        : m_pTopImage(nullptr)
        , m_tlsIndex(0)
        , m_pAContext(nullptr)
    {
        m_TargetProcess.Attach(pid);
    }

    CDarkMMap::~CDarkMMap(void)
    {
        UnmapAllModules();
    }

    /*
        Get address of function in another process

        IN:
            hMod - module base
            func - function name or ordinal

        OUT:
            void

        RETURN:
            Function address
            0 - if not found
    */
    FARPROC CDarkMMap::GetProcAddressEx( HMODULE mod, const char* procName )
    {
        return m_TargetProcess.Modules.GetProcAddressEx(mod, procName);
    }

     /*
        Perform an arbitrary function call in remote process.
        x86 version does not support floating point arguments

        IN:
            pFn - function address
            args - function arguments
            cc - function calling convention (is ignored for x64)
            hContextThread - execution thread
                             if NULL - function will be executed in new thread
                             if INVALID_HANDLE_VALUE - function will be executed in default worker thread

        OUT:
            result - function return value

        RETURN:
            true if successful call
    */
    bool CDarkMMap::CallFunction( void* pFn, std::initializer_list<GenVar> args, size_t& result, eCalligConvention cc /*= CC_cdecl*/, HANDLE hContextThread /*= INVALID_HANDLE_VALUE*/ )
    {
        AsmJit::Assembler a;
        AsmJitHelper ah(a);

        // Invalid calling convention
        if(cc < CC_cdecl || cc > CC_fastcall)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }

        ah.GenPrologue();
        ah.GenCall(pFn, args, cc);

        if(hContextThread == INVALID_HANDLE_VALUE || hContextThread != NULL)
        {
            // Ensure RPC environment exists
            if(m_TargetProcess.Core.CreateRPCEnvironment(true) != ERROR_SUCCESS)
                return false;

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            // Run in appropriate thread
            if(hContextThread == INVALID_HANDLE_VALUE)
                m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
            else
                m_TargetProcess.Core.ExecInAnyThread(a.make(), a.getCodeSize(), result, hContextThread);
        }
        else
        {
            size_t tmp = 0;

            ah.ExitThreadWithStatus();
            ah.GenEpilogue();

            m_TargetProcess.Core.RemoteCall(a.make(), a.getCodeSize(), result, &tmp);
        }

        return true;
    }


    /*
        Manually map PE image into target process

        IN:
            path - path to image
            flags - loader flags

        RETURN:
            Loaded module base address
    */
    HMODULE CDarkMMap::MapDll( const std::string& path, eLoadFlags flags /*= NoFlags*/)
    {
        wchar_t tmp[1024] = {0};

        MultiByteToWideChar(CP_ACP, 0, path.c_str(), (int)path.length(), tmp, ARRAYSIZE(tmp));

        return MapDll(tmp, flags);
    }

    /*
        Manually map PE image into target process

        IN:
            path - path to image
            flags - loader flags

        RETURN:
            Loaded module base address
    */
    HMODULE CDarkMMap::MapDll( const std::wstring& path, eLoadFlags flags /*= NoFlags*/ )
    {
        std::tr2::sys::wpath tmpPath(path);
        ImageContext *pOldImage = m_pTopImage;

        m_pTopImage           = new ImageContext();
        m_pTopImage->FilePath = path;
        m_pTopImage->FileName = m_pTopImage->FilePath.filename();
        m_pTopImage->flags    = flags;

        // Load and parse image
        if(!m_pTopImage->Image.Project(path) || !m_pTopImage->ImagePE.Parse(m_pTopImage->Image, m_pTopImage->Image.isPlainData()))
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }
        
        // Open target process and create thread for code execution
        if(m_TargetProcess.Core.CreateRPCEnvironment() != ERROR_SUCCESS)
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }

        // Already loaded
        if(HMODULE hMod = m_TargetProcess.Modules.GetModuleAddress(m_pTopImage->FileName.c_str()))
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return hMod;
        }

        // Use ASLR aware image base
        m_pTopImage->pTargetBase = (void*)m_pTopImage->ImagePE.ImageBase();

        // Try to map image at it's original base
        DWORD dwResult = m_TargetProcess.Core.Allocate(m_pTopImage->ImagePE.ImageSize(), m_pTopImage->pTargetBase);
        if(dwResult != ERROR_SUCCESS && dwResult != ERROR_IMAGE_NOT_AT_BASE)
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }

        // For debug testing only
        if(!(flags & NoExceptions))
        {
            ds_process::CProcess::pImageBase = m_pTopImage->pTargetBase;
            ds_process::CProcess::imageSize  = m_pTopImage->ImagePE.ImageSize();
        }

        // Set current activation context
        if(!(flags & NoSxS))
            m_TargetProcess.Modules.PushLocalActx(m_pTopImage->Image.actx());

        // Create Activation context for SxS
        // .exe files usually contain manifest under id of 1
        // .dll files have manifest under id of 2
        if(!(flags & NoSxS))
        {
            if(!CreateActx(2))
                CreateActx(1);
        }

        // Core image mapping operations
        if(!CopyImage() || !RelocateImage())
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }

        /*if(m_pTopImage->ImagePE.IsPureManaged())
            return MapPureManaged();*/
        
       m_TargetProcess.Modules.AddManualModule(m_pTopImage->FileName, (HMODULE)m_pTopImage->pTargetBase);

        // Create reference for native loader functions
        if(flags & CreateLdrRef)
            m_TargetProcess.Modules.NtLoader().CreateNTReference(
                (HMODULE)m_pTopImage->pTargetBase, m_pTopImage->ImagePE.ImageSize(), m_pTopImage->FileName, m_pTopImage->FilePath);

        // Import tables
        if(!ResolveImport() || (!(flags & NoDelayLoad) && !ResolveDelayImport()))
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }

        // Apply proper memory protection for sections
        ProtectImageMemory();

        // Make exception handling possible (C and C++)
        if(/*m_TargetProcess.DisabeDEP() != ERROR_SUCCESS &&*/
            !(flags & NoExceptions) && !EnableExceptions())
        {
            delete m_pTopImage;
            m_pTopImage = pOldImage;
            return 0;
        }

        // Unlink image from VAD list
        if(m_pTopImage->flags & UnlinkVAD)
            m_TargetProcess.UnlinkVad(m_pTopImage->pTargetBase, m_pTopImage->ImagePE.ImageSize());

        // TLS stuff
        if(!(flags & NoTLS))
        {
            m_pTopImage->ImagePE.GetTLSCallbacks(m_pTopImage->pTargetBase, m_pTopImage->tlsCallbacks);

            if(!InitStaticTLS() || !RunTLSInitializers(DLL_PROCESS_ATTACH))
            {
                delete m_pTopImage;
                m_pTopImage = pOldImage;
                return 0;
            }
        }

        // Stupid security cookie
        InitializeCookie();
        
        // Topmost image, change process base module address if needed
        if(flags & RebaseProcess && m_pTopImage->ImagePE.IsExe() && pOldImage == nullptr)
            m_TargetProcess.Core.Write((size_t)m_TargetProcess.Core.GetPebBase() + 2 * WordSize, (size_t)m_pTopImage->pTargetBase);

        // Entry point
        if((m_pTopImage->EntryPoint = (pDllMain)m_pTopImage->ImagePE.EntryPoint(m_pTopImage->pTargetBase)) != nullptr)      
            CallEntryPoint(DLL_PROCESS_ATTACH);       

        // Free local image
        m_pTopImage->Image.Release();

        if(!(flags & NoSxS))
            m_TargetProcess.Modules.PopLocalActx();

        // Save mapped image context
        m_Images.emplace_back(m_pTopImage);
        m_pTopImage = pOldImage;

        // Last module was mapped
        /*if(m_pTopImage == nullptr)
            m_TargetProcess.Core.TerminateWorkerThread();*/

        return (HMODULE)m_Images.back()->pTargetBase;
    }

    /*
        Map pure IL image
        Not supported yet
    */
    HMODULE CDarkMMap::MapPureManaged()
    {
        CImageNET netImg;

        if(!netImg.Init(m_pTopImage->FilePath))
        {
            SetLastError(0x1337);
            return 0;
        }

        netImg.Parse();

        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return 0;
        //return (HMODULE)m_pTopImage->pTargetBase;
    }

    /*
        Unmap associated PE image and it's dependencies from target process
    */
    bool CDarkMMap::UnmapAllModules()
    {
        for (auto iter = m_Images.rbegin(); iter != m_Images.rend(); iter++)
        {
            m_pTopImage = iter->get();

            if(!(m_pTopImage->flags & NoTLS))
                RunTLSInitializers(DLL_PROCESS_DETACH);

            CallEntryPoint(DLL_PROCESS_DETACH);

            // Free activation context memory
            FreeActx();

            // Remove VEH
            if(!(m_pTopImage->flags & NoExceptions))
                DisableExceptions();

            // Free memory
            m_TargetProcess.Core.Free(m_pTopImage->pTargetBase);

            // Remove reference from local modules list
            m_TargetProcess.Modules.RemoveManualModule(m_pTopImage->FilePath.filename());
        }        

        // Terminate worker thread
        m_TargetProcess.Core.TerminateWorkerThread();

        m_Images.clear();
        m_pTopImage = nullptr;

        return true;
    }

    /*
        Copy image header and sections into target process
    */
    bool CDarkMMap::CopyImage()
    {
        // offset to first section equals to header size
        size_t dwHeaderSize = m_pTopImage->ImagePE.HeadersSize();

        // Copy header
        if(m_TargetProcess.Core.Write(m_pTopImage->pTargetBase, dwHeaderSize, m_pTopImage->Image.base()) != ERROR_SUCCESS)
            return false;

        // Set header protection
        if(m_TargetProcess.Core.Protect(m_pTopImage->pTargetBase, dwHeaderSize, PAGE_READONLY) != ERROR_SUCCESS)
            return false;

        auto sections = m_pTopImage->ImagePE.Sections();

        // Copy sections
        for( auto& section : sections)
        {
            // Skip discardable sections
            if(!(section.Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)))
                continue;

            uint8_t* pSource = (uint8_t*)m_pTopImage->ImagePE.ResolveRvaToVA(section.VirtualAddress);

            if(m_TargetProcess.Core.Write((uint8_t*)m_pTopImage->pTargetBase + section.VirtualAddress, section.Misc.VirtualSize, pSource) != ERROR_SUCCESS)
                return false;
        }

        return true;
    }

    /*
        Set proper section protection
    */
    bool CDarkMMap::ProtectImageMemory()
    {
        // Copy sections
        for(auto& section : m_pTopImage->ImagePE.Sections())
        {
            if(m_TargetProcess.Core.Protect((uint8_t*)m_pTopImage->pTargetBase + section.VirtualAddress, section.Misc.VirtualSize, GetSectionProt(section.Characteristics)) != ERROR_SUCCESS)
                return false;
        }

        return true;
    }

    /*
        Fix relocations if image wasn't loaded at base address
    */
    bool CDarkMMap::RelocateImage()
    {
        size_t Delta = 0;
        ds_pe::IMAGE_BASE_RELOCATION2* fixrec = (ds_pe::IMAGE_BASE_RELOCATION2*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_BASERELOC);

        // Reloc delta
        Delta = (size_t)m_pTopImage->pTargetBase - (size_t)m_pTopImage->ImagePE.ImageBase();

        // No need to relocate
        if(Delta == 0)
        {
            SetLastError(ERROR_SUCCESS);
            return true;
        }

        // No relocations
        if (fixrec == nullptr) 
        {
            SetLastError(err::mapping::CantRelocate);
            return false;
        }

        // table not empty
        while (fixrec->BlockSize)                        
        {
            DWORD count = (fixrec->BlockSize - 8) >> 1;             // records count

            for (DWORD i = 0; i < count; ++i)
            {
                WORD fixtype    = (fixrec->Item[i].Type);           // fixup type
                WORD fixoffset  = (fixrec->Item[i].Offset) % 4096;  // offset in 4K block

                // no fixup required
                if (fixtype == IMAGE_REL_BASED_ABSOLUTE) 
                    continue;

                // add delta 
                if (fixtype == IMAGE_REL_BASED_HIGHLOW || fixtype == IMAGE_REL_BASED_DIR64) 
                {
                    size_t targetAddr = (size_t)m_pTopImage->pTargetBase + fixoffset + fixrec->PageRVA;
                    size_t sourceAddr = *(size_t*)((size_t)m_pTopImage->Image.base() + fixoffset + fixrec->PageRVA) + Delta;

                    if(m_TargetProcess.Core.Write(targetAddr, sourceAddr) != ERROR_SUCCESS)
                        return false;
                }
                else
                {
                    // TODO: support for all remaining relocations
                    SetLastError(err::mapping::AbnormalRelocation);
                    return false;
                }
            }

            // next reloc entry
            fixrec = (ds_pe::IMAGE_BASE_RELOCATION2*)((size_t)fixrec + fixrec->BlockSize);
        } 

        return true;
    }

    /*
        Fill import table
    */
    bool CDarkMMap::ResolveImport()
    {
        IMAGE_IMPORT_DESCRIPTOR *pImportTbl = (IMAGE_IMPORT_DESCRIPTOR*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_IMPORT);
        void* base                          = m_pTopImage->Image.base();

        if(!pImportTbl)
            return true;
        
        // Imports
        for (; pImportTbl->Name; ++pImportTbl)
        {
            IMAGE_THUNK_DATA* pRVA  = nullptr;
            DWORD IAT_Index         = 0;
            char *pDllName          = MAKE_PTR(char*, pImportTbl->Name, base);
            std::string strDll      = pDllName;
            std::wstring strBaseDll = L"";
            HMODULE hMod            = m_TargetProcess.Modules.GetModuleAddress(pDllName, false, m_pTopImage->FileName.c_str());

            strBaseDll.assign(strDll.begin(), strDll.end());
            m_TargetProcess.Modules.ResolvePath(strBaseDll, ds_process::Default, m_pTopImage->FileName);

            // Load dependency if needed
            if(!hMod)
            {      
                m_TargetProcess.Modules.ResolvePath(strDll, ds_process::EnsureFullPath);

                // For win32 one exception handler is enough
                // For amd64 each image must have it's own handler to resolve C++ exceptions properly
            #ifdef _M_AMD64
                eLoadFlags newFlags = (eLoadFlags)(m_pTopImage->flags | NoDelayLoad | NoSxS);
            #else
                eLoadFlags newFlags = (eLoadFlags)(m_pTopImage->flags | NoDelayLoad | NoSxS | PartialExcept);
            #endif

                // Loading method
                if(m_pTopImage->flags & ManualImports)
                    hMod = MapDll(strDll, newFlags);
                else
                    hMod = m_TargetProcess.Modules.SimpleInject(strDll.c_str(), m_pAContext);

                if(!hMod)
                {
                    printf("Missing import %s\n", strDll.c_str());

                    if(GetLastError() == ERROR_SUCCESS)
                        SetLastError(err::mapping::CantResolveImport);

                    return false;
                }            
            }

            if (pImportTbl->OriginalFirstThunk)
                pRVA = MAKE_PTR(IMAGE_THUNK_DATA*, pImportTbl->OriginalFirstThunk, base);
            else
                pRVA = MAKE_PTR(IMAGE_THUNK_DATA*, pImportTbl->FirstThunk, base);

            while (pRVA->u1.AddressOfData)
            {
                IMAGE_IMPORT_BY_NAME* pAddressTable = MAKE_PTR(IMAGE_IMPORT_BY_NAME*, pRVA->u1.AddressOfData, base);
                void* pFuncPtr                      = 0;
                size_t dwIATAddress                 = 0;                

                // import by name
                // WordSize * 8 - 1 = 0x80000000 (x86) or 0x8000000000000000 (x64)
                if ((size_t)pRVA->u1.AddressOfData < (1LL << (WordSize * 8 - 1) ) && pAddressTable->Name[0])
                {
                    pFuncPtr = m_TargetProcess.Modules.GetProcAddressEx(hMod, pAddressTable->Name, strBaseDll.c_str());
                }
                // import by ordinal
                else 
                {
                    pFuncPtr = m_TargetProcess.Modules.GetProcAddressEx(hMod, (char*)((USHORT)pRVA->u1.AddressOfData & 0xFFFF), strBaseDll.c_str());
                }

                if(pFuncPtr == nullptr)
                {
                    SetLastError(err::mapping::NoImportFunction);
                    return false;
                }

                // Save address to IAT
                if (pImportTbl->FirstThunk)
                {
                    dwIATAddress = pImportTbl->FirstThunk + (size_t)m_pTopImage->pTargetBase + IAT_Index;
                }
                // Save address to OrigianlFirstThunk
                else
                {
                    dwIATAddress = pRVA->u1.AddressOfData - (size_t)base + (size_t)m_pTopImage->pTargetBase;
                }

                // Write address to IAT
                m_TargetProcess.Core.Write(dwIATAddress, pFuncPtr);

                // Go to next entry
                pRVA++;
                IAT_Index += WordSize;
            }
        }

        return true;
    }

    /*
        Fill delay import table
    */
    bool CDarkMMap::ResolveDelayImport()
    {
        IMAGE_DELAYLOAD_DESCRIPTOR *pDelayLoad = (IMAGE_DELAYLOAD_DESCRIPTOR*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
        void* base                             = m_pTopImage->Image.base();

        // No delay import
        if(!pDelayLoad)
            return true;

        for (; pDelayLoad->DllNameRVA; ++pDelayLoad)
        {
            IMAGE_THUNK_DATA* pRVA  = nullptr;
            DWORD IAT_Index         = 0;
            char *pDllName          = MAKE_PTR(char*, pDelayLoad->DllNameRVA, base);
            std::string strDll      = pDllName;
            std::wstring strBaseDll = L"";
            HMODULE hMod            = m_TargetProcess.Modules.GetModuleAddress(pDllName, false, m_pTopImage->FileName.c_str());

            strBaseDll.assign(strDll.begin(), strDll.end());
            m_TargetProcess.Modules.ResolvePath(strBaseDll, ds_process::Default, m_pTopImage->FileName);

            // Load dependency if needed
            if(!hMod)
            {
                m_TargetProcess.Modules.ResolvePath(strDll, ds_process::EnsureFullPath);

                // For win32 one exception handler is enough
                // For amd64 each image must have it's own handler to properly C++ exceptions properly
            #ifdef _M_AMD64
                eLoadFlags newFlags = (eLoadFlags)(m_pTopImage->flags | NoDelayLoad | NoSxS);
            #else
                eLoadFlags newFlags = (eLoadFlags)(m_pTopImage->flags | NoDelayLoad | NoSxS | PartialExcept);
            #endif

                // Loading method
                if(m_pTopImage->flags & ManualImports)
                    hMod = MapDll(strDll, newFlags);
                else
                    hMod = m_TargetProcess.Modules.SimpleInject(strDll.c_str(), m_pAContext);

                if(!hMod)
                    continue;      
            }
            
            pRVA = MAKE_PTR(IMAGE_THUNK_DATA*, pDelayLoad->ImportNameTableRVA, base);

            while (pRVA->u1.AddressOfData)
            {
                IMAGE_IMPORT_BY_NAME* pAddressTable = MAKE_PTR(IMAGE_IMPORT_BY_NAME*, pRVA->u1.AddressOfData, base);
                void* pFuncPtr                      = 0;
                size_t dwIATAddress                 = 0; 

                // import by name
                // WordSize * 8 - 1 = 0x80000000 (x86) or 0x8000000000000000 (x64)
                if ((size_t)pAddressTable < (1LL << (WordSize * 8 - 1) ) && pAddressTable->Name[0])
                {
                    pFuncPtr = m_TargetProcess.Modules.GetProcAddressEx(hMod, pAddressTable->Name, strBaseDll.c_str());
                }
                // import by ordinal
                else 
                {
                    pFuncPtr = m_TargetProcess.Modules.GetProcAddressEx(hMod, (char*)((USHORT)pAddressTable & 0xFFFF), strBaseDll.c_str());
                }

                if(pFuncPtr == nullptr)
                {
                    SetLastError(err::mapping::NoImportFunction);
                    return false;
                }

                dwIATAddress = pDelayLoad->ImportAddressTableRVA + (size_t)m_pTopImage->pTargetBase + IAT_Index;

                // Write address to IAT
                m_TargetProcess.Core.Write(dwIATAddress, pFuncPtr);

                // Go to next entry
                pRVA++;
                IAT_Index += WordSize;
            }
        }


        return true;
    }

    /*
        Set custom exception handler to bypass SafeSEH under DEP 
    */
    bool CDarkMMap::EnableExceptions()
    {
    #ifdef _M_AMD64
        size_t size = m_pTopImage->ImagePE.DirectorySize(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
        IMAGE_RUNTIME_FUNCTION_ENTRY *pExpTable = (IMAGE_RUNTIME_FUNCTION_ENTRY*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_EXCEPTION);

        if(pExpTable)
        {
            AsmJit::Assembler a;
            AsmJitHelper ah(a);
            size_t result = 0;

            m_pTopImage->pExpTableAddr = REBASE(pExpTable, m_pTopImage->Image.base(), m_pTopImage->pTargetBase);

            ah.GenPrologue();

            ah.GenCall(&RtlAddFunctionTable, { m_pTopImage->pExpTableAddr, size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (size_t)m_pTopImage->pTargetBase });

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            if(m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result) != ERROR_SUCCESS)
                return false;

            if(m_pTopImage->flags & CreateLdrRef)
                return true;
            else
                return (m_TargetProcess.CreateVEH((size_t)m_pTopImage->pTargetBase, m_pTopImage->ImagePE.ImageSize()) == ERROR_SUCCESS);
        }
        else
            return false;
    #else
        m_TargetProcess.Modules.NtLoader().InsertInvertedFunctionTable(m_pTopImage->pTargetBase, m_pTopImage->ImagePE.ImageSize());

        if(m_pTopImage->flags & PartialExcept)
            return true;
        else
            return (m_TargetProcess.CreateVEH((size_t)m_pTopImage->pTargetBase, m_pTopImage->ImagePE.ImageSize()) == ERROR_SUCCESS);
    #endif
    }

    /*
        Remove custom exception handler
    */
    bool CDarkMMap::DisableExceptions()
    {
    #ifdef _M_AMD64
        if(m_pTopImage->pExpTableAddr)
        {
            AsmJit::Assembler a;
            AsmJitHelper ah(a);
            size_t result = 0;

            ah.GenPrologue();

            // RtlDeleteFunctionTable(pExpTable);
            ah.GenCall(&RtlDeleteFunctionTable, { m_pTopImage->pExpTableAddr });

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();
           
            if(m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result) != ERROR_SUCCESS)
                return false;

            if(m_pTopImage->flags & CreateLdrRef)
                return true;
            else
                return (m_TargetProcess.RemoveVEH() == ERROR_SUCCESS);
        }
        else
            return false;
    #else
        if(m_pTopImage->flags & (PartialExcept | NoExceptions))
            return true;
        else
            return (m_TargetProcess.RemoveVEH() == ERROR_SUCCESS);

    #endif
    }

    /*
        Resolve static TLS storage
    */
    bool CDarkMMap::InitStaticTLS()
    {
        IMAGE_TLS_DIRECTORY *pTls = (IMAGE_TLS_DIRECTORY*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_TLS);

        if(pTls && pTls->AddressOfIndex)
        {
            // Use native TLS initialization
            m_TargetProcess.Modules.NtLoader().AddStaticTLSEntry(m_pTopImage->pTargetBase);

            /*AsmJit::Assembler a;
            AsmJitHelper ah(a);
            size_t result = 0;

            ah.GenPrologue();

            // HeapAlloc(GetProcessHeap, HEAP_ZERO_MEMORY, 4);
            ah.GenCall(&GetProcessHeap, { });
            a.mov(AsmJit::nsi, AsmJit::nax);

            ah.GenCall(&HeapAlloc, { AsmJit::nsi, 0xC0000 | HEAP_ZERO_MEMORY, 6 * WordSize });
            a.mov(AsmJit::ndi, AsmJit::nax);

            ah.GenCall(&HeapAlloc, { AsmJit::nsi, 0xC0000 | HEAP_ZERO_MEMORY, pTls->EndAddressOfRawData - pTls->StartAddressOfRawData + pTls->SizeOfZeroFill + 8 });
            a.mov(AsmJit::nbx, AsmJit::nax);

        #ifdef _M_IX86       
            // mov eax, fs:[0x18]
            a._emitWord(0xA164);
            a._emitDWord(0x18);          
        #else
            // mov rax, gs:[0x30]
            a._emitByte(0x65);          
            a._emitDWord(0x25048B48);
            a._emitDWord(0x30);
        #endif
            void *pCopyFunc = GetProcAddress(GetModuleHandle(_T("ntdll.dll")), "memcpy");

            // TEB.ThreadLocalStoragePointer
            a.add(AsmJit::nax, 0xB*WordSize);
            a.mov(AsmJit::sysint_ptr(AsmJit::nax), AsmJit::ndi);
            ah.GenCall(pCopyFunc, { AsmJit::nbx, 
                                    REBASE(pTls->StartAddressOfRawData,  m_pTopImage->ImagePE.ImageBase(), m_pTopImage->pTargetBase), 
                                    pTls->EndAddressOfRawData - pTls->StartAddressOfRawData });

            a.mov(AsmJit::sysint_ptr(AsmJit::ndi, WordSize*m_tlsIndex), AsmJit::nbx);

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result);

            // Write static tls index into target image
            m_TargetProcess.Core.Write<int>(REBASE(pTls->AddressOfIndex, m_pTopImage->ImagePE.ImageBase(), m_pTopImage->pTargetBase), m_tlsIndex);

            // Increase used static tls index
            m_tlsIndex++;*/
        }

        return true;
    }

    /*
        Execute TLS callbacks

        IN:
            dwReason - DLL_PROCESS_ATTACH
                       DLL_THREAD_ATTACH 
                       DLL_PROCESS_DETACH
                       DLL_THREAD_DETTACH
    */
    bool CDarkMMap::RunTLSInitializers( DWORD dwReason )
    {
        AsmJit::Assembler a;
        AsmJitHelper ah(a);
        size_t result = 0;

        // No callbacks to execute
        if(m_pTopImage->tlsCallbacks.empty())
            return true;

        ah.GenPrologue();

        // ActivateActCtx
        if(m_pAContext)
        {
            a.mov(AsmJit::nax, (size_t)m_pAContext);
            a.mov(AsmJit::nax, AsmJit::dword_ptr(AsmJit::nax));
            ah.GenCall(&ActivateActCtx, {AsmJit::nax, (size_t)m_pAContext + sizeof(HANDLE)});
        }

        for (auto& pCallback : m_pTopImage->tlsCallbacks)
            // PTLS_CALLBACK_FUNCTION(pTopImage->pTargetBase, dwReason, Reserved);
            ah.GenCall(pCallback, {(size_t)m_pTopImage->pTargetBase, dwReason, NULL});

        // DeactivateActCtx
        if(m_pAContext)
        {
            a.mov(AsmJit::nax, (size_t)m_pAContext + sizeof(HANDLE));
            a.mov(AsmJit::nax, AsmJit::dword_ptr(AsmJit::nax));
            ah.GenCall(&DeactivateActCtx, {0, AsmJit::nax});
        }

        ah.SaveRetValAndSignalEvent();
        ah.GenEpilogue();

        m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
                
        return true;
    }

    /*
        Calculate and set security cookie
    */
    bool CDarkMMap::InitializeCookie()
    {
        IMAGE_LOAD_CONFIG_DIRECTORY *pLC = (IMAGE_LOAD_CONFIG_DIRECTORY*)m_pTopImage->ImagePE.DirectoryAddress(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);

        if(pLC && pLC->SecurityCookie)
        {
            FILETIME systime = {0};
            LARGE_INTEGER PerformanceCount = {0};
            int cookie = 0;

            //
            // Cookie generation taken from bcryptprimitives.dll
            //
            GetSystemTimeAsFileTime(&systime);
            QueryPerformanceCounter(&PerformanceCount);

            cookie  = systime.dwHighDateTime ^ systime.dwLowDateTime ^ GetCurrentThreadId();
            cookie ^= GetCurrentProcessId();
            cookie ^= PerformanceCount.LowPart;
            cookie ^= PerformanceCount.HighPart;
            cookie ^= (unsigned int)&cookie;

            if ( cookie == 0xBB40E64E )
                cookie = 0xBB40E64F;
            else if ( !(cookie & 0xFFFF0000) )       
                cookie |= (cookie | 0x4711) << 16;

            m_TargetProcess.Core.Write<int>(REBASE(pLC->SecurityCookie, m_pTopImage->ImagePE.ImageBase(), m_pTopImage->pTargetBase), cookie); 
        }

        return true;
    }

    /*
        Call image entry point

        IN:
            dwReason - DLL_PROCESS_ATTACH
                        DLL_THREAD_ATTACH 
                        DLL_PROCESS_DETACH
                        DLL_THREAD_DETTACH
    */
    bool CDarkMMap::CallEntryPoint( DWORD dwReason )
    {
        AsmJit::Assembler a;
        AsmJitHelper ah(a);
        size_t result = 0;

        ah.GenPrologue();

        // ActivateActCtx
        if(m_pAContext)
        {
            a.mov(AsmJit::nax, (size_t)m_pAContext);
            a.mov(AsmJit::nax, AsmJit::dword_ptr(AsmJit::nax));
            ah.GenCall(&ActivateActCtx, { AsmJit::nax, (size_t)m_pAContext + sizeof(HANDLE) });
        }

        // DllMain(pTopImage->pTargetBase, DLL_PROCESS_ATTACH, NULL)
        ah.GenCall(m_pTopImage->EntryPoint, { (size_t)m_pTopImage->pTargetBase, dwReason, NULL });

        // DeactivateActCtx
        if(m_pAContext)
        {
            a.mov(AsmJit::nax, (size_t)m_pAContext + sizeof(HANDLE));
            a.mov(AsmJit::nax, AsmJit::dword_ptr(AsmJit::nax));
            ah.GenCall(&DeactivateActCtx, { 0, AsmJit::nax });
        }

        ah.SaveRetValAndSignalEvent();
        ah.GenEpilogue();

        m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result);

        return true;
    }


    /*
        Create activation context

        IN:
            id - manifest resource id

        RETURN:
            Execution status

        Target memory layout:
        -----------------------------
        | hCtx | ACTCTX | file_path |
        -----------------------------
    */
    bool CDarkMMap::CreateActx( int id /*= 2*/ )
    {
        AsmJit::Assembler a;
        AsmJitHelper ah(a);

        size_t   result = 0;
        ACTCTX   act    = {0};

        m_TargetProcess.Core.Allocate(512, m_pAContext);

        act.cbSize          = sizeof(act);
        act.dwFlags         = ACTCTX_FLAG_RESOURCE_NAME_VALID;
        act.lpSource        = (LPCWSTR)((SIZE_T)m_pAContext + sizeof(HANDLE) + sizeof(act));
        act.lpResourceName  = MAKEINTRESOURCE(id);

        ah.GenPrologue();

        // CreateActCtx(&act)
        ah.GenCall(&CreateActCtx, {(size_t)m_pAContext + sizeof(HANDLE)});

        // pTopImage->pAContext = CreateActCtx(&act)
        a.mov(AsmJit::ndx, (size_t)m_pAContext);
        a.mov(AsmJit::sysint_ptr(AsmJit::ndx), AsmJit::nax);

        ah.SaveRetValAndSignalEvent();
        ah.GenEpilogue();

        m_TargetProcess.Core.Write((BYTE*)m_pAContext + sizeof(HANDLE), sizeof(act), &act);
        m_TargetProcess.Core.Write((BYTE*)m_pAContext + sizeof(HANDLE) + sizeof(act), 
            (m_pTopImage->FilePath.string().length() + 1)*sizeof(TCHAR) , (void*)m_pTopImage->FilePath.string().c_str());

        if(m_TargetProcess.Core.ExecInWorkerThread(a.make(), a.getCodeSize(), result) != ERROR_SUCCESS || (HANDLE)result == INVALID_HANDLE_VALUE)
        {
            if(m_TargetProcess.Core.Free(m_pAContext) == ERROR_SUCCESS)
                m_pAContext = nullptr;

            SetLastError(err::mapping::CantCreateActx);
            return false;
        }

        return true;
    }

    /*
        Free existing activation context, if any
    */
    bool CDarkMMap::FreeActx()
    {
        if(m_pAContext)
        {
            m_TargetProcess.Core.Free(m_pAContext);
            m_pAContext = nullptr;
        }

        return true;
    }

    /*
        Transform section characteristics into memory protection flags

        IN:
            characteristics - section characteristics

        RETURN:
            Memory protection value
    */
    DWORD CDarkMMap::GetSectionProt( DWORD characteristics )
    {
        DWORD dwResult = PAGE_NOACCESS;

        if(characteristics & IMAGE_SCN_MEM_EXECUTE) 
        {
            if(characteristics & IMAGE_SCN_MEM_WRITE)
                dwResult = PAGE_EXECUTE_READWRITE;
            else if(characteristics & IMAGE_SCN_MEM_READ)
                dwResult = PAGE_EXECUTE_READ;
            else
                dwResult = PAGE_EXECUTE;
        } 
        else
        {
            if(characteristics & IMAGE_SCN_MEM_WRITE)
                dwResult = PAGE_READWRITE;
            else if(characteristics & IMAGE_SCN_MEM_READ)
                dwResult = PAGE_READONLY;
            else
                dwResult = PAGE_NOACCESS;
        }

        return dwResult;
    }
}
