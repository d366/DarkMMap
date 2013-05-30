#pragma once

#include "stdafx.h"
#include "MemCore.h"

namespace ds_mmap
{
    namespace ds_process
    {
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
                                                 IN PULONG 	NewFlags,
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

        class CNtLdr
        {
        public:
            CNtLdr(CMemCore& memory);
            ~CNtLdr(void);

            /*
            */
            bool CreateNTReference(HMODULE hMod, size_t ImageSize, const std::wstring& DllBaseName, const std::wstring& DllBasePath);

        private:
            /*
            */
            _LDR_DATA_TABLE_ENTRY_W8* InitW8Node( void* ModuleBase, size_t ImageSize, const std::wstring& dllname, const std::wstring& dllpath, ULONG& outHash );
            _LDR_DATA_TABLE_ENTRY_W7* InitW7Node( void* ModuleBase, size_t ImageSize, const std::wstring& dllname, const std::wstring& dllpath, ULONG& outHash );

            /*
            */
            void InsertTreeNode(void* pParentNode, void* pNode, bool bLeft = false);

            /*
            */
            void InsertHashNode(PLIST_ENTRY pNodeLink, ULONG hash, size_t VarOffset);

            /*
            */
            void InsertMemModuleNode(void* pNode);

            /*
            */
            VOID InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry);

            /*
            */
            CNtLdr& operator=(const CNtLdr& other);

        private:
            CMemCore& m_memory;
        };
    }
}

