#include "PEManger.h"

namespace ds_mmap
{
    namespace ds_pe
    {
        CPEManger::CPEManger(void)
            : m_pFileBase(nullptr)
            , m_pImageHdr(nullptr)
            , m_isPlainData(false)
        {
        }

        CPEManger::~CPEManger(void)
        {
        }

        /*
            Parse PE image from memory
            Image must be loaded with proper sections memory alignment

            IN:
                pFileBase - image base address

            RETURN:
                Status
        */
        bool CPEManger::Parse( const void* pFileBase, bool isPlainData )
        {
            const IMAGE_DOS_HEADER        *pDosHdr    = nullptr;
            const IMAGE_SECTION_HEADER    *pSection   = nullptr;

            if(!pFileBase)
            {
                SetLastError(err::pe::NoFile);
                return false;
            }

            m_isPlainData = isPlainData;

            // Get DOS header
            m_pFileBase = pFileBase;
            pDosHdr   = (const IMAGE_DOS_HEADER*)(m_pFileBase);

            // File not a valid PE file
            if(pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
            {
                SetLastError(err::pe::NoSignature);
                return false;
            }

            // Get image header
            m_pImageHdr = (const IMAGE_NT_HEADERS*)((uint8_t*)pDosHdr + pDosHdr->e_lfanew);

            // File not a valid PE file
            if(m_pImageHdr->Signature != IMAGE_NT_SIGNATURE)
            {
                SetLastError(err::pe::NoSignature);
                return false;
            }

            pSection = (const IMAGE_SECTION_HEADER*)((uint8_t*)m_pImageHdr + sizeof(IMAGE_NT_HEADERS));

            // Sections
            for(int i = 0; i < m_pImageHdr->FileHeader.NumberOfSections; ++i, pSection++)
                m_sections.push_back(*pSection);

            return true;
        }

        /*
            Retrieve arbitrary directory address

            IN:
                index - directory index

            RETURN:
                Directory address in memory
        */
        size_t CPEManger::DirectoryAddress( int index ) const
        {
            if(m_pImageHdr->OptionalHeader.DataDirectory[index].VirtualAddress == 0)
                return 0;
            else
                return ResolveRvaToVA(m_pImageHdr->OptionalHeader.DataDirectory[index].VirtualAddress);
        }

        size_t CPEManger::ResolveRvaToVA( size_t Rva ) const
        {
            if(m_isPlainData)
                return (size_t)ImageRvaToVa((PIMAGE_NT_HEADERS)m_pImageHdr, (PVOID)m_pFileBase, (ULONG)Rva, NULL);
            else
                return (size_t)m_pFileBase + Rva;
        }

        /*
            Retrieve arbitrary directory size

            IN:
                index - directory index

            RETURN:
                Directory size
                0 - if directory is not present
        */
        size_t CPEManger::DirectorySize( int index ) const
        {
            if(m_pImageHdr->OptionalHeader.DataDirectory[index].VirtualAddress == 0)
                return 0;
            else
                return (size_t)m_pImageHdr->OptionalHeader.DataDirectory[index].Size;
        }

        /*
            Get image sections
        */
        const std::vector<IMAGE_SECTION_HEADER>& CPEManger::Sections() const
        {
            return m_sections;
        }

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
        int CPEManger::GetTLSCallbacks( const void* targetBase, std::vector<void*>& result ) const
        {
            IMAGE_TLS_DIRECTORY *pTls = (IMAGE_TLS_DIRECTORY*)DirectoryAddress(IMAGE_DIRECTORY_ENTRY_TLS);
            size_t* pCallback = nullptr;

            if(!pTls)
                return 0;

            if(m_pImageHdr->OptionalHeader.ImageBase != (size_t)m_pFileBase)
                pCallback = (size_t*)REBASE(pTls->AddressOfCallBacks, m_pImageHdr->OptionalHeader.ImageBase, m_pFileBase);
            else
                pCallback = (size_t*)pTls->AddressOfCallBacks;

            for(; *pCallback; pCallback++)
                result.push_back((void*)REBASE(*pCallback, m_pImageHdr->OptionalHeader.ImageBase, targetBase));

            return (int)result.size();
        }

        /*
            Size of image in memory
        */
        size_t CPEManger::ImageSize() const
        {
            return m_pImageHdr->OptionalHeader.SizeOfImage;
        }

        /*
            Size of image in memory
        */
        size_t CPEManger::HeadersSize() const
        {
            return m_pImageHdr->OptionalHeader.SizeOfHeaders;
        }

        /*
            Image base. ASLR is taken into account
        */
        size_t CPEManger::ImageBase() const
        {
            return m_pImageHdr->OptionalHeader.ImageBase;
        }

        /*
            Get target entry point address

            IN:
                base - target image base 

            RETURN:
                Calculated entry point
        */
        const void* CPEManger::EntryPoint( const void* base ) const
        {
            return (const void*)((size_t)base + m_pImageHdr->OptionalHeader.AddressOfEntryPoint);
        }

        /*
            Pure IL image
        */
        bool CPEManger::IsPureManaged() const
        {
            IMAGE_COR20_HEADER *pCorHdr = (IMAGE_COR20_HEADER*)DirectoryAddress(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);

            if(pCorHdr)
            {
                if(pCorHdr->Flags & COMIMAGE_FLAGS_ILONLY)
                    return true;
            }

            return false;
        }

        /*
            Image is exe file and not a dynamic-link library
        */
        bool CPEManger::IsExe() const
        {
            return !(m_pImageHdr->FileHeader.Characteristics & IMAGE_FILE_DLL);
        }
    }
}