#include "ImageNET.h"


CImageNET::CImageNET(void)
    : m_pMetaDisp(nullptr)
    , m_pMetaImport(nullptr)
    , m_pAssemblyImport(nullptr)
{
}


CImageNET::~CImageNET(void)
{
    //
    // release interfaces
    //
    if (m_pMetaDisp)
    {
        m_pMetaDisp->Release();
        m_pMetaDisp = nullptr;
    }
    if (m_pMetaImport)
    {
        m_pMetaImport->Release();
        m_pMetaImport = nullptr;
    }
    if (m_pAssemblyImport)
    {
        m_pAssemblyImport->Release();
        m_pAssemblyImport = nullptr;
    }

    CoUninitialize();
}

bool CImageNET::Init( const std::wstring& path )
{
    HRESULT hr;
    VARIANT value;

    m_path = path;

    hr = CoInitialize(0);

    hr = CoCreateInstance(CLSID_CorMetaDataDispenser, NULL, CLSCTX_INPROC_SERVER, IID_IMetaDataDispenserEx, (void**)&m_pMetaDisp);
    if(FAILED(hr))
    {
        m_pMetaDisp = nullptr;
        return false;
    }

    //
    // query needed interfaces
    //
    hr = m_pMetaDisp->OpenScope(m_path.c_str(), 0, IID_IMetaDataImport, (IUnknown**)&m_pMetaImport);
    if (hr == CLDB_E_BADUPDATEMODE)
    {
        V_VT(&value)  = VT_UI4;
        V_UI4(&value) = MDUpdateIncremental;

        if (FAILED(hr = m_pMetaDisp->SetOption(MetaDataSetUpdate, &value)))
            return false;

        hr = m_pMetaDisp->OpenScope(m_path.c_str(), 0, IID_IMetaDataImport, (IUnknown**)&m_pMetaImport);
    }

    if (FAILED(hr))
        return false;

    hr = m_pMetaImport->QueryInterface(IID_IMetaDataAssemblyImport, (void**) &m_pAssemblyImport);
    if (FAILED(hr))
        return false;

    return true;
}

bool CImageNET::Parse()
{
    DWORD       dwcTypeDefs, dwTypeDefFlags, dwcTokens, dwSigBlobSize;
    HCORENUM    hceTypeDefs     = 0;
    mdTypeRef   rTypeDefs[10]   = {0};
    WCHAR       wcName[1024]    = {0};
    mdToken     tExtends        = 0;
    HCORENUM    hceMethods      = 0;
    mdToken     rTokens[10]     = {0};
    //
    // enumeration loop
    //
    while (SUCCEEDED(m_pMetaImport->EnumTypeDefs(&hceTypeDefs, rTypeDefs, ARRAYSIZE(rTypeDefs), &dwcTypeDefs))
        && dwcTypeDefs > 0)
    {
        for (UINT i = 0; i < dwcTypeDefs; i++)
        {
            HRESULT hr = m_pMetaImport->GetTypeDefProps(rTypeDefs[i], wcName, ARRAYSIZE(wcName), NULL, &dwTypeDefFlags, &tExtends);
            if ( FAILED(hr) )
                continue;

            while (SUCCEEDED(m_pMetaImport->EnumMethods(&hceMethods, rTypeDefs[i], rTokens, ARRAYSIZE(rTokens), &dwcTokens))
                && dwcTokens > 0)
            {
                DWORD            dwCodeRVA, dwAttr;
                WCHAR            wmName[1024]   = {0};
                PCCOR_SIGNATURE  pbySigBlob     = nullptr;

                for (UINT j = 0; j < dwcTokens; j++)
                {
                    // get method information
                    HRESULT hr = m_pMetaImport->GetMemberProps(
                        rTokens[j],
                        NULL,
                        wmName, ARRAYSIZE(wmName), NULL,
                        &dwAttr,
                        &pbySigBlob, &dwSigBlobSize,
                        &dwCodeRVA,
                        NULL,
                        NULL,
                        NULL, NULL);
                    if ( FAILED(hr) )
                        continue;

                    m_methods.emplace(std::make_pair(wcName, wmName), dwCodeRVA);
                }
            }
        }
    }

    return true;
}

