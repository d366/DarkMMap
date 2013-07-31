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
                    baseName - name of base import dll (API Schema resolve only)

                OUT:
                    path - resolved path

                RETURN:
                    Error code
            */
            DWORD ResolvePath(std::string& path,  eResolveFlag flags, const std::wstring& baseName = L"");
            DWORD ResolvePath(std::wstring& path, eResolveFlag flags, const std::wstring& baseName = L"");

            /*
                Get specific module address

                IN:
                    modname - module name
                    skipManualModules - don't search for manually mapped modules
                    baseModule - name of base import dll (API Schema resolve only)

                OUT:
                    void

                RETURN:
                    Module address
                    0 - if not found
            */
            HMODULE GetModuleAddress( const char* modname,    bool skipManualModules = false, const wchar_t* baseModule = L"" );
            HMODULE GetModuleAddress( const wchar_t* modname, bool skipManualModules = false, const wchar_t* baseModule = L"" );

            /*
                Get address of function in another process

                IN:
                    hMod - module base
                    func - function name or ordinal
                    baseModule - name of base import dll (API Schema resolve only)

                OUT:
                    void

                RETURN:
                    Function address
                    0 - if not found
            */
            FARPROC GetProcAddressEx( HMODULE hMod, const char* name, const wchar_t* baseModule = L"" );   

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

            /*
            */
            CNtLdr& NtLoader() { return m_native; }

        private:
            CMemModules& operator = (const CMemModules&) { }

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

            // Native loader routines
            CNtLdr m_native;
        };
    }
}
#endif// _MEM_MODULES_H_