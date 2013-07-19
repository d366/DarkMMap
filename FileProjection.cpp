#include "FileProjection.h"

namespace ds_mmap
{
    CFileProjection::CFileProjection(void)
        : m_hMapping(NULL)
        , m_hFile(INVALID_HANDLE_VALUE)
        , m_pData(nullptr)
        , m_isPlainData(false)
        , m_hctx(INVALID_HANDLE_VALUE)
    {
    }

    CFileProjection::CFileProjection( const std::wstring& path ) 
        : CFileProjection()
    {
        Project(path);
    }


    CFileProjection::~CFileProjection(void)
    {
        Release();
    }

    /*
        Open file as memory-mapped PE image

        IN:
            path - file path

        RETURN:
            Address of file mapping
    */
    void* CFileProjection::Project( const std::wstring& path )
    {
        Release();

        ACTCTX act          = {0};
        act.cbSize          = sizeof(act);
        act.dwFlags         = ACTCTX_FLAG_RESOURCE_NAME_VALID;
        act.lpSource        = path.c_str();
        act.lpResourceName  = MAKEINTRESOURCE(2);

        m_hctx = CreateActCtx(&act);

        if(m_hctx == INVALID_HANDLE_VALUE)
        {
            act.lpResourceName  = MAKEINTRESOURCE(1);
            m_hctx = CreateActCtx(&act);
        }

        m_hFile = CreateFile(path.c_str(), FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);

        if(m_hFile != INVALID_HANDLE_VALUE)
        {
            // Try mapping as image
            m_hMapping = CreateFileMapping(m_hFile, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);

            if(m_hMapping && m_hMapping != INVALID_HANDLE_VALUE)
            {
                m_pData = MapViewOfFile(m_hMapping, FILE_MAP_READ, 0, 0, 0);
            }
            // Map as simple datafile
            else
            {
                m_isPlainData = true;
                m_hMapping    = CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0, 0, NULL);

                if(m_hMapping && m_hMapping != INVALID_HANDLE_VALUE)
                    m_pData = MapViewOfFile(m_hMapping, FILE_MAP_READ, 0, 0, 0);
            }
        }

        return m_pData;
    }

    /*
        Release mapping, if any
    */
    void CFileProjection::Release()
    {
        if(m_hctx != INVALID_HANDLE_VALUE)
        {
            ReleaseActCtx(m_hctx);
            m_hctx = INVALID_HANDLE_VALUE;
        }

        if(m_pData)
        {
            UnmapViewOfFile(m_pData);
            m_pData = nullptr;
        }

        if(m_hMapping && m_hMapping != INVALID_HANDLE_VALUE)
        {
            CloseHandle(m_hMapping);
            m_hMapping = NULL;
        }

        if(m_hFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(m_hFile);
            m_hFile = INVALID_HANDLE_VALUE;
        }
    }

    /*
        Get mapping base

        RETURN:
            Address of file mapping
    */
    void* CFileProjection::base() const
    {
        return m_pData;
    }

    /*
        Get activation context
    */
    HANDLE CFileProjection::actx() const
    {
        return m_hctx;
    }

    /*
        Get mapping base

        RETURN:
            Address of file mapping
    */
    CFileProjection::operator void*() const
    {
        return m_pData;
    }

    /*
        Is plain datafile
    */
    bool CFileProjection::isPlainData() const
    {
        return m_isPlainData;
    }

};