#pragma once

#include "stdafx.h"
#include <cor.h>
#include <CorError.h>

#include <map>

// .NET metadata parser
class CImageNET
{
    typedef std::map<std::pair<std::wstring, std::wstring>, size_t> mapMethodRVA;

public:
    CImageNET(void);
    ~CImageNET(void);

    /*
        Initialize COM parser
    */
    bool Init( const std::wstring& path );

    /*
        Parse .NET metadata
    */
    bool Parse();

private:
    std::wstring             m_path;
    IMetaDataImport         *m_pMetaImport;
    IMetaDataDispenserEx    *m_pMetaDisp;
    IMetaDataAssemblyImport *m_pAssemblyImport;
    mapMethodRVA             m_methods;
};

