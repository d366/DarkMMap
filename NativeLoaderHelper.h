#pragma once

#include "stdafx.h"
#include "MemCore.h"
#include "PEManger.h"

#define FIELD_OFFSET2(type, field)  ((LONG)(LONG_PTR)&(((type)0)->field))
#define GET_FIELD_PTR(entry, field) (void*)((uint8_t*)entry + FIELD_OFFSET2(decltype(entry), field))

extern "C"
NTSYSAPI 
NTSTATUS 
NTAPI 
RtlDosApplyFileIsolationRedirection_Ustr(IN ULONG Flags,
                                         IN PUNICODE_STRING OriginalName,
                                         IN PUNICODE_STRING Extension,
                                         IN OUT PUNICODE_STRING StaticString,
                                         IN OUT PUNICODE_STRING DynamicString,
                                         IN OUT PUNICODE_STRING *NewName,
                                         IN PULONG  NewFlags,
                                         IN PSIZE_T FileNameSize,
                                         IN PSIZE_T RequiredLength);    

extern "C"
NTSYSAPI 
NTSTATUS 
NTAPI 
RtlHashUnicodeString(_In_   PCUNICODE_STRING String,
                     _In_   BOOLEAN CaseInSensitive,
                     _In_   ULONG HashAlgorithm,
                     _Out_  PULONG HashValue );

extern "C"
NTSYSAPI 
WCHAR 
NTAPI 
RtlUpcaseUnicodeChar( WCHAR chr );

extern "C" 
NTSYSAPI 
PVOID 
NTAPI 
RtlEncodeSystemPointer( IN PVOID Pointer );

extern "C" 
NTSYSAPI 
PVOID 
NTAPI 
RtlRbInsertNodeEx( IN PVOID Root, IN PVOID Parent, IN BOOL InsertRight, IN _RTL_BALANCED_NODE* Link );

namespace ds_mmap
{
    namespace ds_process
    {
        class CNtLdr
        {
        public:
            CNtLdr(CMemCore& memory);
            ~CNtLdr(void);

            /*
                Initialize some loader stuff
            */
            bool Init();

            /*
                Add module to some loader structures 
                (LdrpHashTable, LdrpModuleIndex (win8 only), InMemoryOrderModuleList (win7 only))

                IN:
                    hMod - module base address
                    ImageSize - size of image
                    DllBaseName - image name
                    DllBasePath - image path
                
                RETURN:
                    true on success
            */
            bool CreateNTReference(HMODULE hMod, size_t ImageSize, const std::wstring& DllBaseName, const std::wstring& DllBasePath);

            /*
                Create thread static TLS array

                IN:
                    pModule - module base address

                RETURN:
                    true on success
            */
            bool AddStaticTLSEntry(void* pModule);

            /*
                Create module record in LdrpInvertedFunctionTable
                Used to create fake SAFESEH entries

                IN:
                    ModuleBase - module base address
                    ImageSize - image size

                RETURN:
                    true on success
            */
            bool InsertInvertedFunctionTable( void* ModuleBase, size_t ImageSize );

            /*
                Get address of LdrpInvertedFunctionTable variable
            */
            void* LdrpInvertedFunctionTable() const { return m_LdrpInvertedFunctionTable; }

        private:

            /*
                Find LdrpHashTable[] table with list heads
            */
            bool FindLdrpHashTable();

            /*
                Find LdrpModuleIndex variable for win8
            */
            bool FindLdrpModuleIndexBase();

            /*
                Get PEB->Ldr->InLoadOrderModuleList address
            */
            bool FindLdrpModuleBase();

            /*
                Search for RtlInsertInvertedFunctionTable, LdrpInvertedFunctionTable, LdrpHandleTlsData
            */
            bool PatternSearch();

            /*
                Find Loader heap base
            */
            bool FindLdrHeap();

            /*
                Initialize OS-specific module entry

                IN:
                    ModuleBase - module base address
                    ImageSize - image size
                    dllname - Image name
                    dllpath - image path

                OUT:
                    outHash - image name hash

                RETURN:
                    Pointer to created entry
            */
            _LDR_DATA_TABLE_ENTRY_W8* InitW8Node( void* ModuleBase, size_t ImageSize, const std::wstring& dllname, const std::wstring& dllpath, ULONG& outHash );
            _LDR_DATA_TABLE_ENTRY_W7* InitW7Node( void* ModuleBase, size_t ImageSize, const std::wstring& dllname, const std::wstring& dllpath, ULONG& outHash );

            /*
                Insert entry into win8 module tree

                IN:
                    pParentNode - parent node
                    pNode - node to insert
                    bLeft - insert as left child (if false - insert as right child)
            */
            void InsertTreeNode( _LDR_DATA_TABLE_ENTRY_W8* pParentNode, _LDR_DATA_TABLE_ENTRY_W8* pNode, bool bLeft = false );

            /*
                Insert entry into LdrpHashTable[]

                IN:
                    pNodeLink - link of entry to be inserted
                    hash - entry hash
            */
            void InsertHashNode( PLIST_ENTRY pNodeLink, ULONG hash );

            /*
                Insert entry into InLoadOrderModuleList and InMemoryOrderModuleList

                IN:
                  pNodeMemoryOrderLink - InMemoryOrderModuleList link of entry to be inserted
                  pNodeLoadOrderLink   - InLoadOrderModuleList link of entry to be inserted
            */
			void InsertMemModuleNode( PLIST_ENTRY pNodeMemoryOrderLink, PLIST_ENTRY pNodeLoadOrderLink );

            /*
                Insert entry into standard double linked list

                IN:
                    ListHead - List head pointer
                    Entry - entry list link to be inserted
            */
            VOID InsertTailList( PLIST_ENTRY ListHead, PLIST_ENTRY Entry );

            /*
                Get module native node ptr or create new

                IN:
                    ptr - node pointer (if nullptr - new dummy node is allocated)
                    pModule - module base address

                RETURN:
                    Node address
            */
            template<typename T> 
            T* SetNode(T* ptr, void* pModule);

            /*
                Determine if current OS is Win8 and higher
            */
            inline bool IsWin8orHigher() const { return (m_verinfo.dwMajorVersion >= 6 && m_verinfo.dwMinorVersion >= 2); }

            /*
            */
            CNtLdr& operator =( const CNtLdr& other );
        private:
            CMemCore&       m_memory;                           // Process memory routines
            OSVERSIONINFO   m_verinfo;                          // OS version info
            size_t          m_LdrpHashTable;                    // LdrpHashTable address
            size_t          m_LdrpModuleIndexBase;              // LdrpModuleIndex address
            size_t          m_LdrpModuleBase;                   // PEB->Ldr->InLoadOrderModuleList address
            size_t          m_LdrHeapBase;                      // Loader heap base address
            void           *m_LdrpHandleTlsData;                // LdrpHandleTlsData address
            void           *m_LdrpInvertedFunctionTable;        // LdrpInvertedFunctionTable address
            void           *m_RtlInsertInvertedFunctionTable;   // RtlInsertInvertedFunctionTable address

            std::map<HMODULE, void*> m_nodeMap;                 // Map of allocated native structures
        };
    }
}

