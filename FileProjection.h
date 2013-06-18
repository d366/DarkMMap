#pragma once

#include <Windows.h>
#include <string>
#include <tchar.h>

namespace ds_mmap
{
    // 
    // Load file as PE image
    //
    class CFileProjection
    {
    public:
        CFileProjection(void);
        CFileProjection(const std::wstring& path);
        ~CFileProjection(void);

        /*
            Open file as memory-mapped PE image

            IN:
                path - file path

            RETURN:
                Address of file mapping
        */
        void* Project(const std::wstring& path);

        /*
            Release file mapping
        */
        void Release();

        /*
            Get mapping base

            RETURN:
                Address of file mapping
        */
        void* base() const;

        /*
            Get activation context
        */
        HANDLE actx() const;

        /* 
            is plain data file
        */
        bool isPlainData() const;

        /*
            Get mapping base

            RETURN:
                Address of file mapping
        */
        operator void*() const;

    private:
        HANDLE  m_hFile;        // Target file HANDLE
        HANDLE  m_hMapping;     // Memory mapping object
        void*   m_pData;        // Mapping base
        bool    m_isPlainData;  // File mapped as plain data file
        HANDLE  m_hctx;         // Activation context
    };
};
