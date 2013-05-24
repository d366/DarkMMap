#include "Errors.h"

#include <windows.h>

namespace err
{
    std::string err::GetErrorDescription( int code )
    {
        //
        // Custom error
        //
        for(int i = 0; i < ARRAYSIZE(ErrorDescription); i++)
            if(ErrorDescription[i].code == code)
                return ErrorDescription[i].description;

        //
        // Win32 Error
        //
        LPSTR lpMsgBuf = nullptr;

        if(FormatMessageA
            (
                FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                code,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&lpMsgBuf,
                0, NULL 
            ) != 0)
        {
            std::string ret(lpMsgBuf);

            LocalFree(lpMsgBuf);
            return ret;
        }

        return "";
    }
}