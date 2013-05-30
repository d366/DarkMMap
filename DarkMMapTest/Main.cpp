#include "stdafx.h"
#include "../DarkMMap.h"
#include <iostream>
#include <metahost.h>
#include <atlbase.h>

#pragma comment(lib, "mscoree.lib")

#define TARGET_RUNTIME L'4'

ICLRMetaHost    *pClrHost       = nullptr;
ICLRRuntimeInfo *pRuntimeinfo   = nullptr;
ICLRRuntimeHost *pRuntimeHost   = nullptr;

DWORD InitRuntime( )
{
    DWORD         dwRet     = 0;
    HRESULT       hr        = S_OK;
    WCHAR         ver[255]  = {0};
    IEnumUnknown *pRuntimes = nullptr;

    // MetaHost instance 
    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pClrHost);
    if(!SUCCEEDED(hr))
        return 1;

    // Get available runtimes
    hr = pClrHost->EnumerateInstalledRuntimes(&pRuntimes);
    if(!SUCCEEDED(hr))
        return 1;

    // Search for target runtime needed for managed dll to run
    while(pRuntimes->Next(1, (IUnknown**)&pRuntimeinfo, &dwRet) == S_OK && dwRet > 0)
    {
        dwRet = ARRAYSIZE(ver);

        hr = pRuntimeinfo->GetVersionString(ver, &dwRet);

        // ver - string "vA.B[.X]"
        if(ver[1] == TARGET_RUNTIME)
            break;

        pRuntimeinfo->Release();
        pRuntimeinfo = nullptr;
    }

    // Found runtime
    if(pRuntimeinfo != nullptr)
    {
        BOOL started = FALSE;

        // Get CLR hosting interface
        hr = pRuntimeinfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&pRuntimeHost);
        if(!SUCCEEDED(hr))
            return 1;

        // Check if runtime is already running
        hr = pRuntimeinfo->IsStarted(&started, &dwRet);
        if(!SUCCEEDED(hr))
            return 1;

        // Start .NET runtime if needed
        if(started == FALSE)
        {
            hr = pRuntimeHost->Start();
            if(!SUCCEEDED(hr))
                return 1;
        }
    }

    if(pRuntimes)
        pRuntimes->Release();

    return 0;
}

int _tmain(int /*argc*/, _TCHAR* /*argv[]*/)
{
    HMODULE mod = NULL;
    ds_mmap::CDarkMMap mapper(GetCurrentProcessId());
    ds_mmap::CDarkMMap mapper90(GetCurrentProcessId());
    ds_mmap::CDarkMMap mapperRemote(3360);

#ifdef _M_AMD64
    wchar_t* path = L"C:\\Users\\Ton\\Documents\\Visual Studio 2012\\Projects\\DarkMMap\\DummyDll64.dll";
    wchar_t* path90 = L"C:\\Users\\Ton\\Documents\\Visual Studio 2012\\Projects\\DarkMMap\\DummyDll6490.dll";
    //wchar_t* path = L"C:\\windows\\system32\\dxcpl.exe";
#else
    wchar_t* path = L"C:\\Users\\Ton\\Documents\\Visual Studio 2012\\Projects\\DarkMMap\\DummyDll.dll";
    wchar_t *path90 = L"..\\DummyDll90.dll";
    //wchar_t* path = L"C:\\Users\\Ton\\Documents\\Visual Studio 2012\\Projects\\ImgSearch\\Release\\ImgSearch.exe";
    //wchar_t* path = L"D:\\Games\\World of Warcraft\\Wow.exe";
    //wchar_t* path = L"C:\\windows\\system32\\cmd.exe";
#endif

    //AddVectoredExceptionHandler(0, &ds_mmap::ds_process::CProcess::VectoredHandler32);

    //InitRuntime();

    //mod = LoadLibraryW(path);

    /*void (__stdcall *pInit)(LPVOID) = (void (__stdcall*)(LPVOID))mapper90.GetProcAddressEx(mod, "_InitRuntime@4");
    void (*pDispose)(void) = (void (*)(void))GetProcAddress(mod, "Dispose");

    if(pInit)
        pInit(&si);

    if(pDispose)
        pDispose();*/

    //FreeLibrary(mod);

    if((mod = mapper.MapDll(path, (ds_mmap::eLoadFlags)(ds_mmap::CreateLdrRef | ds_mmap::ManualImports | ds_mmap::NoDelayLoad))) != 0
        /*&& mapper.MapDll(path90, ds_mmap::ManualImports) != 0*/)
    {
        //mod = GetModuleHandle(L"DummyDll.dll");
        //mod = GetModuleHandle(L"ClrDummy.dll");
        //int (*proc)(char*) = (int (*)(char*))GetProcAddress(mod, "fnDummyDll");
        //void (*proc)(void) = (void (*)(void))GetProcAddress(mod, "Init");

        //if(proc)
            //proc("Test");

        //if(proc)
            //proc();

        mapper.UnmapAllModules();
    }
    else
    {
        std::cout << "Mapping failed with error " << GetLastError() << ": " << err::GetErrorDescription(GetLastError()) << std::endl;
    }

    return 0;
}
