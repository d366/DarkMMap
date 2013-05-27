#ifndef _MEM_MODULES_H_
#define _MEM_MODULES_H_

#include "stdafx.h"
#include "MemCore.h"

#include <string>
#include <map>
#include <algorithm>
#include <vector>
#include <stack>
#include <filesystem>
#include <Shlwapi.h>

#pragma comment(lib, "ntdll.lib")

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
        //
        // Api schema structures
        //
        struct ApiSchemaMapHeader
        {
            DWORD Version;
            DWORD NumModules;
        };

        struct ApiSchemaModuleEntry
        {
            DWORD OffsetToName;
            WORD NameSize;
            DWORD OffsetOfHosts;
        };

        struct ApiSchemaModuleHostsHeader
        {
            DWORD NumHosts;
        };

        struct ApiSchemaModuleHost
        {
            DWORD OffsetOfImportingName;
            WORD ImportingNameSize;
            DWORD OffsetOfHostName;
            WORD HostNameSize;
        };

        // Resolve path flags
        enum eResolveFlag
        {
            Default         = 0,
            ApiSchemaOnly   = 1,
            EnsureFullPath  = 2,
        };

        class CMemModules
        {
            typedef std::map<std::wstring, std::vector<std::wstring>> mapApiSchema;

        public:
            CMemModules(CMemCore& mem);
            ~CMemModules(void);

            /*
                Inject Dll into process

                RETURN:
                    Error code
            */
            HMODULE SimpleInject( const std::string& dllName, void *pActx = nullptr );

            /*
                Unload Dll from process

                RETURN:
                    Error code
            */
            DWORD SimpleUnload( const std::string& dllName );

            /*
                Resolve dll path

                IN:
                    path - dll path

                OUT:
                    path - resolved path

                RETURN:
                    Error code
            */
            DWORD ResolvePath(std::string& path,  eResolveFlag flags);
            DWORD ResolvePath(std::wstring& path, eResolveFlag flags);

            /*
                Get specific module address

                IN:
                    proc - process ID
                    modname - module name

                OUT:
                    void

                RETURN:
                    Module address
                    0 - if not found
            */
            HMODULE GetModuleAddress( const char* modname, bool skipManualModules = false );
            HMODULE GetModuleAddress( const wchar_t* modname, bool skipManualModules = false );

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
            FARPROC GetProcAddressEx( HMODULE hMod, const char* name );   

            /*
                Add manually mapped module to list

                IN:
                    name - module name
                    base - module base address
            */
            void AddManualModule(const std::wstring& name, HMODULE base);

            /*
                Remove manually mapped module from list

                IN:
                    name - module name
            */
            void RemoveManualModule(const std::wstring& name);

            /*
                Set active activation context
            */
            void PushLocalActx(HANDLE hActx = INVALID_HANDLE_VALUE);

            /*
                Restore previous active activation context
            */
            void PopLocalActx( );

        private:
            CMemModules& operator = (const CMemModules&) {}

            /*
                Initialize Api schema from current process table
            */
            bool InitApiSchema();

            /*
                Try SxS redirection
            */
            DWORD ProbeSxSRedirect(std::wstring& path);

            /*
                Get directory containing main process module

                RETURN:
                    Directory path
            */
            std::wstring GetProcessDirectory();

            
        private:
            CMemCore&           m_memory;           // Process memory routines
            static mapApiSchema m_ApiSchemaMap;     // Api schema map

            // List of manually mapped modules
            std::map<std::wstring, HMODULE> ms_modules;

            // Activation context stack
            std::stack<HANDLE> m_ActxStack;
        };
    }
}
#endif// _MEM_MODULES_H_