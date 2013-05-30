#include "NativeLoaderHelper.h"

namespace ds_mmap
{
    namespace ds_process
    {
        CNtLdr::CNtLdr(CMemCore& memory)
            : m_memory(memory)
        {
        }

        CNtLdr::~CNtLdr(void)
        {
        }

        bool CNtLdr::CreateNTReference( HMODULE hMod, size_t ImageSize, const std::wstring& DllBaseName, const std::wstring& DllBasePath )
        {
            OSVERSIONINFO verinfo = {sizeof(OSVERSIONINFO), 0};

            GetVersionEx(&verinfo);

            // Win 8 and higher
            if(verinfo.dwMajorVersion >= 6 && verinfo.dwMinorVersion >= 2)
            {
                ULONG hash = 0;
                _LDR_DATA_TABLE_ENTRY_W8 *pEntry = InitW8Node((void*)hMod, ImageSize, DllBaseName, DllBasePath, hash);

                // Insert into LdrpHashTable
                InsertHashNode((PLIST_ENTRY)((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W8, HashLinks)), hash, NT_LDRP_HASH_TABLE_W8);

                //
                // Win8 module tree
                //
                void* pIndex = (void*)((size_t)GetModuleHandle(L"ntdll.dll") + NT_LDRP_MODULE_TREE_ROOT);

                if(pIndex)
                {
                    void* pAddr = m_memory.Read<void*>(pIndex);

                    // Tree root node
                    _LDR_DATA_TABLE_ENTRY_W8 *pLdrNode = CONTAINING_RECORD(pAddr, _LDR_DATA_TABLE_ENTRY_W8, BaseAddressIndexNode);
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
            }
            // Windows 7 and less
            else
            {
                ULONG hash = 0;
                _LDR_DATA_TABLE_ENTRY_W7 *pEntry = InitW7Node((void*)hMod, ImageSize, DllBaseName, DllBasePath, hash);

                // 
                // Insert into LdrpHashTable
                //
                InsertHashNode((PLIST_ENTRY)((uint8_t*)pEntry + FIELD_OFFSET(_LDR_DATA_TABLE_ENTRY_W7, HashLinks)), hash, NT_LDRP_HASH_TABLE_W7);
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
            // HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(_LDR_DATA_TABLE_ENTRY_W8));
            //
            ah.GenPrologue();

            ah.GenCall(&GetProcessHeap, {});
            ah.GenCall(&HeapAlloc, {AsmJit::nax, HEAP_ZERO_MEMORY, sizeof(_LDR_DATA_TABLE_ENTRY_W8)});

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

                ah.GenCall(&GetProcessHeap, {});
                ah.GenCall(&HeapAlloc, {AsmJit::nax, HEAP_ZERO_MEMORY, sizeof(_LDR_DDAG_NODE)});

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

            ah.GenCall(&GetProcessHeap, {});
            ah.GenCall(&HeapAlloc, {AsmJit::nax, HEAP_ZERO_MEMORY, sizeof(_LDR_DATA_TABLE_ENTRY_W7)});

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

                // Dll name and name hash
                RtlInitUnicodeString(&strLocal, dllname.c_str());
                RtlHashUnicodeString(&strLocal, TRUE, 0, &outHash);

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
        void CNtLdr::InsertMemModuleNode(void* /*pNode*/)
        {
            //
            // STUB
            //
        }

        

        /*
        */
        void CNtLdr::InsertHashNode( PLIST_ENTRY pNodeLink, ULONG hash, size_t VarOffset )
        {
            if(pNodeLink)
            {
                size_t hashAddress = (size_t)GetModuleHandle(L"ntdll.dll") + VarOffset;

                // LrpHashTable record
                PLIST_ENTRY pHashList = m_memory.Read<PLIST_ENTRY>(hashAddress + sizeof(LIST_ENTRY)*(hash & 0x1F));

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

    }
}
