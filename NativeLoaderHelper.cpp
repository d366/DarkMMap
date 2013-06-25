#include "NativeLoaderHelper.h"

namespace ds_mmap
{
    namespace ds_process
    {
        CNtLdr::CNtLdr(CMemCore& memory)
            : m_memory(memory)
            , m_LdrpHashTable(0)
            , m_LdrpModuleIndexBase(0)
            , m_LdrpModuleBase(0)
            , m_LdrHeapBase(0)
            , m_RtlInsertInvertedFunctionTable(nullptr)
            , m_LdrpInvertedFunctionTable(nullptr)
        {
            memset(&m_verinfo, 0x0, sizeof(m_verinfo));
        }

        CNtLdr::~CNtLdr(void)
        {
        }

        bool CNtLdr::Init()
        {
            m_verinfo.dwOSVersionInfoSize = sizeof(m_verinfo);

            GetVersionEx(&m_verinfo);

            //
            // Dynamic data initialization
            //
            FindLdrpHashTable();
            FindLdrpModuleIndexBase();
            FindLdrpModuleBase();
            FindPatterns();
            FindLdrHeap();

            return true;
        }

        bool CNtLdr::CreateNTReference( HMODULE hMod, size_t ImageSize, const std::wstring& DllBaseName, const std::wstring& DllBasePath )
        {
            // Win 8 and higher
            if(m_verinfo.dwMajorVersion >= 6 && m_verinfo.dwMinorVersion >= 2)
            {
                ULONG hash = 0;
                _LDR_DATA_TABLE_ENTRY_W8 *pEntry = InitW8Node((void*)hMod, ImageSize, DllBaseName, DllBasePath, hash);

                // Insert into LdrpHashTable
                InsertHashNode((PLIST_ENTRY)((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, HashLinks)), hash);

                //
                // Win8 module tree
                //
                _LDR_DATA_TABLE_ENTRY_W8 *pLdrNode = CONTAINING_RECORD(m_LdrpModuleIndexBase, _LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode);
                _LDR_DATA_TABLE_ENTRY_W8 LdrNode   = m_memory.Read<_LDR_DATA_TABLE_ENTRY_W8>(pLdrNode);

                // Walk tree
                for(;;)
                {
                    if(hMod < LdrNode.DllBase)
                    {
                        if(LdrNode.BaseAddressIndexNode.Left)
                        {
                            pLdrNode = CONTAINING_RECORD(LdrNode.BaseAddressIndexNode.Left, _LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode);
                            m_memory.Read(pLdrNode, sizeof(LdrNode), &LdrNode);
                        }
                        else
                        {
                            InsertTreeNode(pLdrNode, pEntry, true);
                            return true;
                        }
                    }
                    else if(hMod > LdrNode.DllBase)
                    {
                        if(LdrNode.BaseAddressIndexNode.Right)
                        {
                            pLdrNode = CONTAINING_RECORD(LdrNode.BaseAddressIndexNode.Right, _LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode);
                            m_memory.Read(pLdrNode, sizeof(LdrNode), &LdrNode);
                        }
                        else
                        {
                            InsertTreeNode(pLdrNode, pEntry, false);
                            return true;
                        }
                    }
                    // Already in tree (increase ref counter)
                    else if(hMod == LdrNode.DllBase)
                    {
                        //
                        // pLdrNode->DdagNode->ReferenceCount++;
                        //
                        _LDR_DDAG_NODE Ddag = m_memory.Read<_LDR_DDAG_NODE>(LdrNode.DdagNode);

                        Ddag.ReferenceCount++;

                        m_memory.Write<_LDR_DDAG_NODE>(LdrNode.DdagNode, Ddag);

                        return true;
                    }
                    else
                        return false;
                }
            }
            // Windows 7 and earlier
            else
            {
                ULONG hash = 0;
                _LDR_DATA_TABLE_ENTRY_W7 *pEntry = InitW7Node((void*)hMod, ImageSize, DllBaseName, DllBasePath, hash);

                // Insert into LdrpHashTable
                InsertHashNode((PLIST_ENTRY)((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W7, HashLinks)), hash);

                // Insert into LDR list
                InsertMemModuleNode((PLIST_ENTRY)((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W7, InMemoryOrderLinks)), 
                                    (PLIST_ENTRY)((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W7, InLoadOrderLinks)));
			}

            return false;
        }

        /*
        */
        bool CNtLdr::InsertInvertedFunctionTable( void* ModuleBase, size_t ImageSize )
        { 
            AsmJit::Assembler a;
            AsmJitHelper ah(a);
            size_t result = 0;

            // Invalid addresses. Probably pattern scan has failed
            if(m_RtlInsertInvertedFunctionTable == nullptr || m_LdrpInvertedFunctionTable == 0)
                return false;

            ah.GenPrologue();

            ah.GenCall(m_RtlInsertInvertedFunctionTable, { (size_t)ModuleBase, ImageSize });

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            m_memory.ExecInWorkerThread(a.make(), a.getCodeSize(), result);

            RTL_INVERTED_FUNCTION_TABLE table = {0};

            m_memory.Read(m_LdrpInvertedFunctionTable, sizeof(RTL_INVERTED_FUNCTION_TABLE), &table);

            for(DWORD i = 0; i < table.Count; i++)
            {
                if(table.Entries[i].ImageBase == ModuleBase)
                {
                    // If Image has SAFESEH, RtlInsertInvertedFunctionTable is enough
                    if(table.Entries[i].ExceptionDirectorySize != 0)
                        return true;

                    //
                    // Create fake Exception directory
                    // Directory will be filled later, during exception handling
                    //
                    PIMAGE_RUNTIME_FUNCTION_ENTRY pImgEntry = nullptr;

                    // Allocate memory for 256 possible handlers
                    m_memory.Allocate(sizeof(DWORD)*0x100, (PVOID&)pImgEntry);

                    // m_LdrpInvertedFunctionTable->Entries[i].ExceptionDirectory
                    size_t field_ofst = (size_t)&table.Entries[i].ExceptionDirectory - (size_t)&table;

                    return (m_memory.Write((size_t)m_LdrpInvertedFunctionTable + field_ofst, RtlEncodeSystemPointer(pImgEntry)) == ERROR_SUCCESS);
                }
            }

            return false;
        }

        /*
        */
        _LDR_DATA_TABLE_ENTRY_W8* CNtLdr::InitW8Node( void* ModuleBase, size_t ImageSize, const std::wstring& dllname, const std::wstring& dllpath, ULONG& outHash )
        {
            void *StringBuf         = nullptr;
            UNICODE_STRING strLocal = {0};
            size_t result           = 0;

            _LDR_DATA_TABLE_ENTRY_W8 *pEntry = nullptr; 
            _LDR_DDAG_NODE *pDdagNode = nullptr;

            AsmJit::Assembler a;
            AsmJitHelper ah(a);

            // Allocate space for Unicode string
            m_memory.Allocate(0x1000, StringBuf);

            //
            // HeapAlloc(LdrHeap, HEAP_ZERO_MEMORY, sizeof(_LDR_DATA_TABLE_ENTRY_W8));
            //
            ah.GenPrologue();
            ah.GenCall(&HeapAlloc, { m_LdrHeapBase, HEAP_ZERO_MEMORY, sizeof(_LDR_DATA_TABLE_ENTRY_W8) });

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            m_memory.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
            pEntry = (_LDR_DATA_TABLE_ENTRY_W8*)result;

            if(pEntry)
            {
                a.clear();

                //
                // HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(_LDR_DDAG_NODE));
                //
                ah.GenPrologue();

                ah.GenCall(&HeapAlloc, { m_LdrHeapBase, HEAP_ZERO_MEMORY, sizeof(_LDR_DDAG_NODE) });

                ah.SaveRetValAndSignalEvent();
                ah.GenEpilogue();

                m_memory.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
                pDdagNode = (_LDR_DDAG_NODE*)result;

                if(pDdagNode)
                {
                    // pEntry->DllBase = ModuleBase;
                    m_memory.Write<void*>((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, DllBase), ModuleBase);

                    // pEntry->SizeOfImage = ImageSize;
                    m_memory.Write<ULONG>((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, SizeOfImage), (ULONG)ImageSize);

                    // Dll name and name hash
                    RtlInitUnicodeString(&strLocal, dllname.c_str());
                    RtlHashUnicodeString(&strLocal, TRUE, 0, &outHash);

                    // Write into buffer
                    strLocal.Buffer = (PWSTR)StringBuf;
                    m_memory.Write((uint8_t*)StringBuf, dllname.length() * sizeof(wchar_t) + 2, (void*)dllname.c_str());

                    // pEntry->BaseDllName = strLocal;
                    m_memory.Write<UNICODE_STRING>((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, BaseDllName), strLocal);

                    // Dll full path
                    RtlInitUnicodeString(&strLocal, dllpath.c_str());
                    strLocal.Buffer = (PWSTR)((uint8_t*)StringBuf + 0x800);
                    m_memory.Write((uint8_t*)StringBuf + 0x800, dllpath.length() * sizeof(wchar_t) + 2, (void*)dllpath.c_str());
              
                    // pEntry->FullDllName = strLocal;
                    m_memory.Write<UNICODE_STRING>((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, FullDllName), strLocal);

                    // pEntry->BaseNameHashValue = hash;
                    m_memory.Write<ULONG>((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, BaseNameHashValue), outHash);

                    //
                    // Ddag node
                    //

                    // pEntry->DdagNode = pDdagNode;
                    m_memory.Write<_LDR_DDAG_NODE*>((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, DdagNode), pDdagNode);

                    // pDdagNode->State = LdrModulesReadyToRun;
                    m_memory.Write<enum _LDR_DDAG_STATE>((uint8_t*)pDdagNode + FIELD_OFFSET(_LDR_DDAG_NODE, State), LdrModulesReadyToRun);

                    // pDdagNode->ReferenceCount = 1;
                    m_memory.Write<ULONG>((uint8_t*)pDdagNode + FIELD_OFFSET(_LDR_DDAG_NODE, ReferenceCount), 1);

                    // pDdagNode->LoadCount = -1;
                    m_memory.Write<LONG>((uint8_t*)pDdagNode + FIELD_OFFSET(_LDR_DDAG_NODE, LoadCount), -1);

                    return pEntry;
                }

                return nullptr;
            }

            return nullptr;
        }

        /*
        */
        _LDR_DATA_TABLE_ENTRY_W7* CNtLdr::InitW7Node( void* ModuleBase, size_t ImageSize, const std::wstring& dllname, const std::wstring& dllpath, ULONG& outHash )
        {
            void *StringBuf         = nullptr;
            UNICODE_STRING strLocal = {0};
            size_t result           = 0;

            _LDR_DATA_TABLE_ENTRY_W7 *pEntry = nullptr; 

            AsmJit::Assembler a;
            AsmJitHelper ah(a);

            // Allocate space for Unicode string
            m_memory.Allocate(MAX_PATH, StringBuf);

            //
            // HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(_LDR_DATA_TABLE_ENTRY_W8));
            //
            ah.GenPrologue();

            ah.GenCall(&HeapAlloc, {m_LdrHeapBase, HEAP_ZERO_MEMORY, sizeof(_LDR_DATA_TABLE_ENTRY_W7)});

            ah.SaveRetValAndSignalEvent();
            ah.GenEpilogue();

            m_memory.ExecInWorkerThread(a.make(), a.getCodeSize(), result);
            pEntry = (_LDR_DATA_TABLE_ENTRY_W7*)result;

            if(pEntry)
            {
                // pEntry->DllBase = ModuleBase;
                m_memory.Write<void*>((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W7, DllBase), ModuleBase);

                // pEntry->SizeOfImage = ImageSize;
                m_memory.Write<ULONG>((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W7, SizeOfImage), (ULONG)ImageSize);

                // pEntry->LoadCount = -1;
                m_memory.Write<short>((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W7, LoadCount), -1);

                // Dll name
                RtlInitUnicodeString(&strLocal, dllname.c_str());

                // Name hash
                outHash = 0;
                for(auto& chr : dllname)
                    outHash += 0x1003F * (unsigned short)RtlUpcaseUnicodeChar(chr);

                // Write into buffer
                strLocal.Buffer = (PWSTR)StringBuf;
                m_memory.Write((uint8_t*)StringBuf, dllname.length() * sizeof(wchar_t) + 2, (void*)dllname.c_str());

                // pEntry->BaseDllName = strLocal;
                m_memory.Write<UNICODE_STRING>((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W7, BaseDllName), strLocal);

                // Dll full path
                RtlInitUnicodeString(&strLocal, dllpath.c_str());
                strLocal.Buffer = (PWSTR)((uint8_t*)StringBuf + 0x800);
                m_memory.Write((uint8_t*)StringBuf + 0x800, dllpath.length() * sizeof(wchar_t) + 2, (void*)dllpath.c_str());

                // pEntry->FullDllName = strLocal;
                m_memory.Write<UNICODE_STRING>((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W7, FullDllName), strLocal);

                return pEntry;
            }

            return nullptr;
        }

        /*
        */
        void CNtLdr::InsertTreeNode( void* pParentNode, void* pNode, bool bLeft /*= false*/ )
        {
            // Parent node
            // pNode->BaseAddressIndexNode.ParentValue = (ULONG)&pParentNode->BaseAddressIndexNode;
            m_memory.Write<void*>((uint8_t*)pNode + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode.ParentValue), 
                                  (uint8_t*)pParentNode + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode));

            if(bLeft)
                // pParentNode->BaseAddressIndexNode.Left  = (_RTL_BALANCED_NODE*)(&pNode->BaseAddressIndexNode);
                m_memory.Write<void*>((uint8_t*)pParentNode + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode.Left), 
                                      (uint8_t*)pNode + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode));
                    
            else
                // pParentNode->BaseAddressIndexNode.Right = (_RTL_BALANCED_NODE*)(&pNode->BaseAddressIndexNode);
                m_memory.Write<void*>((uint8_t*)pParentNode + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode.Right), 
                                      (uint8_t*)pNode + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode));
        }

        /*
        */
		void CNtLdr::InsertMemModuleNode( PLIST_ENTRY pNodeMemoryOrderLink, PLIST_ENTRY pNodeLoadOrderLink )
		{
            PPEB pPeb = m_memory.GetPebBase();

            if(pPeb)
            {
                PPEB_LDR_DATA pLdr = m_memory.Read<PPEB_LDR_DATA>((uint8_t*)pPeb + FIELD_OFFSET(PEB, Ldr));
                
                // Insert into pLdr->InMemoryOrderModuleList
                if(pLdr)
                    InsertTailList((PLIST_ENTRY)((uint8_t*)pLdr + FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList)), pNodeMemoryOrderLink);

                // Module list
                PLIST_ENTRY pModuleList = m_memory.Read<PLIST_ENTRY>(m_LdrpModuleBase);

                if(pModuleList)
                    InsertTailList(pModuleList, pNodeLoadOrderLink);
            }
        }

        /*
        */
        void CNtLdr::InsertHashNode( PLIST_ENTRY pNodeLink, ULONG hash )
        {
            if(pNodeLink)
            {
                // LrpHashTable record
                PLIST_ENTRY pHashList = m_memory.Read<PLIST_ENTRY>(m_LdrpHashTable + sizeof(LIST_ENTRY)*(hash & 0x1F));

                InsertTailList(pHashList, pNodeLink);
            }
        }

        /*
        */
        VOID CNtLdr::InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
        {
            PLIST_ENTRY PrevEntry;

            //PrevEntry = ListHead->Blink;
            PrevEntry = m_memory.Read<PLIST_ENTRY>((uint8_t*)ListHead + FIELD_OFFSET(LIST_ENTRY, Blink));

            //Entry->Flink = ListHead;
            //Entry->Blink = PrevEntry;
            m_memory.Write<PLIST_ENTRY>((uint8_t*)Entry + FIELD_OFFSET(LIST_ENTRY, Flink), ListHead);
            m_memory.Write<PLIST_ENTRY>((uint8_t*)Entry + FIELD_OFFSET(LIST_ENTRY, Blink), PrevEntry);

            //PrevEntry->Flink = Entry;
            //ListHead->Blink  = Entry;
            m_memory.Write<PLIST_ENTRY>((uint8_t*)PrevEntry + FIELD_OFFSET(LIST_ENTRY, Flink), Entry);
            m_memory.Write<PLIST_ENTRY>((uint8_t*)ListHead + FIELD_OFFSET(LIST_ENTRY, Blink), Entry);
        }

        /*
            Find LdrpHashTable[] table with list heads
        */
        bool CNtLdr::FindLdrpHashTable()
        {
            _PEB_LDR_DATA_W8 *Ldr = (_PEB_LDR_DATA_W8*)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
            ULONG NtdllHashIndex  = 0;

            // Win 8 and higher
            if(m_verinfo.dwMajorVersion >= 6 && m_verinfo.dwMinorVersion >= 2)
            {
                // get ntdll entry
                _LDR_DATA_TABLE_ENTRY_W8 *Ntdll = CONTAINING_RECORD (Ldr->InInitializationOrderModuleList.Flink, _LDR_DATA_TABLE_ENTRY_W8, InInitializationOrderLinks);

                RtlHashUnicodeString(&Ntdll->BaseDllName, TRUE, 0, &NtdllHashIndex);
                NtdllHashIndex &= 0x1F;

                // get ntdll.dll module bounds
                ULONG_PTR NtdllBase = (ULONG_PTR) Ntdll->DllBase;
                ULONG_PTR NtdllEndAddress = NtdllBase + Ntdll->SizeOfImage - 1;

                // scan hash list to the head (head is located within ntdll)
                bool bHeadFound = false;
                PLIST_ENTRY pNtdllHashHead = NULL;

                for (PLIST_ENTRY e = Ntdll->HashLinks.Flink; e != &Ntdll->HashLinks; e = e->Flink)
                {
                    if ((ULONG_PTR)e >= NtdllBase && (ULONG_PTR)e < NtdllEndAddress)
                    {
                        bHeadFound = true;
                        pNtdllHashHead = e;
                        break;
                    }
                }

                if (bHeadFound)
                {
                    m_LdrpHashTable = (size_t)(pNtdllHashHead - NtdllHashIndex);
                }

                return bHeadFound;
            }
            else
            {
                // get ntdll entry
                _LDR_DATA_TABLE_ENTRY_W7 *Ntdll = CONTAINING_RECORD (Ldr->InInitializationOrderModuleList.Flink, _LDR_DATA_TABLE_ENTRY_W7, InInitializationOrderLinks);
                std::wstring name = Ntdll->BaseDllName.Buffer;
                
                for(auto& ch : name)
                    NtdllHashIndex += 0x1003F * (unsigned short)RtlUpcaseUnicodeChar(ch);

                NtdllHashIndex &= 0x1F;

                // get ntdll.dll module bounds
                ULONG_PTR NtdllBase = (ULONG_PTR) Ntdll->DllBase;
                ULONG_PTR NtdllEndAddress = NtdllBase + Ntdll->SizeOfImage - 1;

                // scan hash list to the head (head is located within ntdll)
                bool bHeadFound = false;
                PLIST_ENTRY pNtdllHashHead = NULL;

                for (PLIST_ENTRY e = Ntdll->HashLinks.Flink; e != &Ntdll->HashLinks; e = e->Flink)
                {
                    if ((ULONG_PTR)e >= NtdllBase && (ULONG_PTR)e < NtdllEndAddress)
                    {
                        bHeadFound = true;
                        pNtdllHashHead = e;
                        break;
                    }
                }

                if (bHeadFound)
                {
                    m_LdrpHashTable = (size_t)(pNtdllHashHead - NtdllHashIndex);
                }

                return bHeadFound;
            }  
        }

        /*
        */
        bool CNtLdr::FindLdrpModuleIndexBase()
        {
            PPEB pPeb = m_memory.GetPebBase();

            if(pPeb)
            {
                size_t lastNode = 0;

                _PEB_LDR_DATA_W8 Ldr            = m_memory.Read<_PEB_LDR_DATA_W8>(m_memory.Read<size_t>((size_t)pPeb + FIELD_OFFSET(PEB, Ldr)));
                _LDR_DATA_TABLE_ENTRY_W8 *Ntdll = CONTAINING_RECORD (Ldr.InInitializationOrderModuleList.Flink, _LDR_DATA_TABLE_ENTRY_W8, InInitializationOrderLinks);
                _RTL_BALANCED_NODE pNode        = m_memory.Read<_RTL_BALANCED_NODE>((size_t)Ntdll + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode));

                for(; pNode.ParentValue; )
                {
                    lastNode = pNode.ParentValue & (size_t)-8;
                    pNode = m_memory.Read<_RTL_BALANCED_NODE>(lastNode);
                }

                m_LdrpModuleIndexBase = lastNode;

                return true;
            }

            return false;
        }

        /*
        */
        bool CNtLdr::FindLdrpModuleBase()
        {
            PPEB pPEB = m_memory.GetPebBase();
            PEB  peb  = m_memory.Read<PEB>(pPEB);

            m_LdrpModuleBase = (size_t)peb.Ldr + FIELD_OFFSET(_PEB_LDR_DATA_W8, InLoadOrderModuleList);

            return true;
        }

        /*
            Find data patterns
        */
        bool CNtLdr::FindPatterns()
        {
            std::vector<size_t> foundData;
            ds_pe::CPEManger ntdll;
            void* pStart    = nullptr;
            size_t scanSize = 0;

            ntdll.Parse(GetModuleHandle(_T("ntdll.dll")), false);

            // Find ntdll code section
            for(auto& section : ntdll.Sections())
            {
                if(_stricmp((const char*)section.Name, ".text") == 0)
                {
                    pStart   = (void*)((size_t)GetModuleHandle(_T("ntdll.dll")) + section.VirtualAddress);
                    scanSize = section.Misc.VirtualSize;

                    break;
                }
            }

            // Win 8 and later
            if(m_verinfo.dwMajorVersion >= 6 && m_verinfo.dwMinorVersion >= 2)
            {
            #ifdef _M_AMD64
            #else
                // RtlInsertInvertedFunctionTable
                // 8B FF 55 8B EC 51 51 53 57 8B 7D 08 8D
                m_memory.FindPattern("\x8b\xff\x55\x8b\xec\x51\x51\x53\x57\x8b\x7d\x08\x8d", "xxxxxxxxxxxxx", pStart, scanSize, foundData);

                if(!foundData.empty())
                {
                    m_RtlInsertInvertedFunctionTable = (int(__stdcall*)(void*, size_t))foundData.front();
                    m_LdrpInvertedFunctionTable      = (PRTL_INVERTED_FUNCTION_TABLE)(*(size_t*)((size_t)m_RtlInsertInvertedFunctionTable + 0x26));
                }
            #endif

            }
            // Win 7 and earlier
            else
            {
            #ifdef _M_AMD64
            #else
                // RtlInsertInvertedFunctionTable
                // 8B FF 55 8B EC 56 68
                m_memory.FindPattern("\x8b\xff\x55\x8b\xec\x56\x68", "xxxxxxx", pStart, scanSize, foundData);

                if(!foundData.empty())
                    m_RtlInsertInvertedFunctionTable = (int(__stdcall*)(void*, size_t))foundData.front();

                // RtlLookupFunctionTable + 0x11
                // 89 5D E0 38
                m_memory.FindPattern("\x89\x5D\xE0\x38", "xxxx", pStart, scanSize, foundData);
                
                if(!foundData.empty())
                    m_LdrpInvertedFunctionTable = (PRTL_INVERTED_FUNCTION_TABLE)(*(size_t*)(foundData.front() + 0x1B));

            #endif
            }

            return true;
        }

        /*
            Find Loader heap base
        */
        bool CNtLdr::FindLdrHeap()
        {
            PPEB pPeb = m_memory.GetPebBase();
            MEMORY_BASIC_INFORMATION mbi = {0};

            if(pPeb)
            {
                PEB_LDR_DATA          Ldr        = m_memory.Read<PEB_LDR_DATA>(m_memory.Read<size_t>((size_t)pPeb + FIELD_OFFSET(PEB, Ldr)));
                PLDR_DATA_TABLE_ENTRY NtdllEntry = CONTAINING_RECORD(Ldr.InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                if (VirtualQueryEx(m_memory.m_hProcess, NtdllEntry, &mbi, sizeof(mbi)))
                {
                    m_LdrHeapBase = (size_t)mbi.AllocationBase;
                    return true;
                }
            }

            return false;
        }

    }
}
