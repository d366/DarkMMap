#ifndef _MEM_MODULES_H_
#define _MEM_MODULES_H_

#include "stdafx.h"
#include "MemCore.h"
#include "NativeLoaderHelper.h"

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
            */
            bool CreateNTReference(HMODULE hMod, size_t ImageSize, const std::wstring& DllBaseName, const std::wstring& DllBasePath );

            /*
                Set active activation context
            */
            void PushLocalActx(HANDLE hActx = INVALID_HANDLE_VALUE);

            /*
                Restore previous active activation context
            */
            void PopLocalActx( );

            /*
            */
            CNtLdr& NtLoader() { return m_native; }

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

            CNtLdr m_native;
        };
    }
}
#endif// _MEM_MODULES_H_