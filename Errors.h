#ifndef _ERRORS_H_
#define _ERRORS_H_

#include <string>

//
// Custom error codes
//
namespace err
{
    const unsigned long base = 100000; 

    namespace general
    {
        enum eCode
        {
            Success             = 0,
            UnknownError        = base + 1,

            end                 = base + 100, 
        };
    };

    namespace pe
    {
        enum eCode
        {
            NoFile              = general::end + 1,
            NoSignature         = general::end + 2,

            end                 = general::end + 100,
        };
    }

    namespace mapping
    {
        enum eCode
        {
            AlreayLoaded        = pe::end + 1,
            CantMap             = pe::end + 2,
            AbnormalRelocation  = pe::end + 3,
            CantCreateActx      = pe::end + 4,
            CantResolveImport   = pe::end + 5,
            NoImportFunction    = pe::end + 6,
            ResolutionSkipped   = pe::end + 7,
            CantRelocate        = pe::end + 8,

            end                 = pe::end + 100,
        };
    }
    
    struct ErrDesc
    {
        int code;
        char *description; 
    };

    const ErrDesc ErrorDescription[] = 
    {
        { general::Success,             "Success" },
        { general::UnknownError,        "Unknown error" },

        { pe::NoFile,                   "No file to map" },
        { pe::NoSignature,              "Invalid or absent PE signature" },

        { mapping::AlreayLoaded,        "Image is already present in process" },
        { mapping::ResolutionSkipped,   "Image name resolution was skipped" },
        { mapping::CantMap,             "Can't map image" },
        { mapping::AbnormalRelocation,  "Abnormal relocation encountered during image fix-up" },
        { mapping::CantCreateActx,      "Can't create Activation context" },
        { mapping::CantResolveImport,   "Failed to resolve one or more import libraries" },
        { mapping::NoImportFunction,    "Import function was not found in module" },
        { mapping::CantRelocate,        "Image can't be relocated. Relocation information is missing" }
    };

    std::string GetErrorDescription(int code);
};

#endif// _ERRORS_H_