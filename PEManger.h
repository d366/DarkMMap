#pragma once

#include "stdafx.h"

#include <DbgHelp.h>
#include <stdint.h>
#include <algorithm>
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <unordered_map>
#include <set>

#pragma comment(lib, "dbghelp.lib")
namespace ds_mmap
{
    namespace ds_pe
    {
        #define MAX_SECTIONS 10

        struct IMAGE_BASE_RELOCATION2
        {
            ULONG PageRVA;
            ULONG BlockSize;

            struct
            {
                WORD Offset : 12; 
                WORD Type   : 4; 
            }Item[1];
        };

        //
        // Primitive PE parsing class
        //
        class CPEManger
        {
            typedef std::map<std::string, std::vector<std::string>> mapImports;

        public:
            CPEManger(void);
            ~CPEManger(void);

            /*
                Parse PE image from memory
                Image must be loaded with proper sections memory alignment

                IN:
                    pFileBase - image base address

                RETURN:
                    Status

            */
            bool Parse(const void* pFileBase, bool isPlainData);

            /*
                Remap virtual address to file address
            */
            size_t ResolveRvaToVA(size_t Rva) const;

            /*
                Size of image in memory
            */
            size_t ImageSize() const;

            /*
                Size of headers
            */
            size_t HeadersSize() const;

            /*
                Image base. ASLR is taken into account
            */
            size_t ImageBase() const;

            /*
                Get image sections
            */
            const std::vector<IMAGE_SECTION_HEADER>& Sections() const;

            /*
                Get target entry point address

                IN:
                    base - target image base 

                RETURN:
                    Calculated entry point
            */
            const void* EntryPoint( const void* base ) const;

            /*
                Retrieve TLS callbacks
                Callbacks are rebased for target image

                IN:
                    targetBase - target image base

                OUT:
                    result - array of callbacks

                RETURN:
                    Number of callbacks in image
            */
            int GetTLSCallbacks(const void* targetBase, std::vector<void*>& result) const;

            /*
                Retrieve arbitrary directory address

                IN:
                    index - directory index

                RETURN:
                    Directory address in memory
                    0 - if directory is not present
            */
            size_t DirectoryAddress(int index) const;

            /*
                Retrieve arbitrary directory size

                IN:
                    index - directory index

                RETURN:
                    Directory size
                    0 - if directory is not present
            */
            size_t DirectorySize( int index ) const;

            /*
                Pure IL image
            */
            bool IsPureManaged() const;

            /*
                Image is exe file and not a dynamic-link library
            */
            bool IsExe() const;

        private:
            bool                                m_isPlainData;  // File mapped as plain data file
            const void                         *m_pFileBase;    // File mapping base address
            const IMAGE_NT_HEADERS             *m_pImageHdr;    // PE header info
            std::vector<IMAGE_SECTION_HEADER>   m_sections;     // Section info
        };
    }
}


