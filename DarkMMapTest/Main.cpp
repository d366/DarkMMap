#include "stdafx.h"
#include "../DarkMMap.h"
#include <iostream>

int _tmain(int /*argc*/, _TCHAR* /*argv[]*/)
{
    ds_mmap::CDarkMMap mapper(GetCurrentProcessId());
    ds_mmap::CDarkMMap mapper90(GetCurrentProcessId());

#ifdef _M_AMD64
    wchar_t* path = L"..\\DummyDll64.dll";
    wchar_t* path90 = ..\\DummyDll6490.dll";
    //wchar_t* path = L"C:\\windows\\system32\\cmd.exe";
#else
    wchar_t *path = L"..\\DummyDll.dll";
    wchar_t *path90 = L"..\\DummyDll90.dll";
    //wchar_t* path = L"C:\\windows\\system32\\cmd.exe";
#endif

    if(mapper.MapDll(path, ds_mmap::ManualImports) != 0 
        && mapper.MapDll(path90, ds_mmap::ManualImports) != 0)
    {
        mapper.UnmapDll();
    }
    else
    {
        std::cout << "Mapping failed with error " << GetLastError() << ": " << err::GetErrorDescription(GetLastError()) << std::endl;
    }

    return 0;
}
