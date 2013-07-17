#pragma once
#include <windows.h>
#include <winternl.h>

#pragma warning(disable : 4201)

enum _LDR_DDAG_STATE
{
    LdrModulesMerged=-5,
    LdrModulesInitError=-4,
    LdrModulesSnapError=-3,
    LdrModulesUnloaded=-2,
    LdrModulesUnloading=-1,
    LdrModulesPlaceHolder=0,
    LdrModulesMapping=1,
    LdrModulesMapped=2,
    LdrModulesWaitingForDependencies=3,
    LdrModulesSnapping=4,
    LdrModulesSnapped=5,
    LdrModulesCondensed=6,
    LdrModulesReadyToInit=7,
    LdrModulesInitializing=8,
    LdrModulesReadyToRun=9
};

enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency=0,
    LoadReasonStaticForwarderDependency=1,
    LoadReasonDynamicForwarderDependency=2,
    LoadReasonDelayloadDependency=3,
    LoadReasonDynamicLoad=4,
    LoadReasonAsImageLoad=5,
    LoadReasonAsDataLoad=6,
    LoadReasonUnknown=-1
};

struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE * Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE * Left;
            struct _RTL_BALANCED_NODE * Right;
        };
    };
    union
    {
        union
        {
            struct
            {
                unsigned char Red: 1;
            };
            struct
            {
                unsigned char Balance: 2;
            };
        };

        size_t ParentValue;
    };
};

struct _LDR_DDAG_NODE
{
    _LIST_ENTRY Modules;
    struct _LDR_SERVICE_TAG_RECORD * ServiceTagList;
    unsigned long LoadCount;
    unsigned long ReferenceCount;
    unsigned long DependencyCount;
    _SINGLE_LIST_ENTRY RemovalLink;
    void* IncomingDependencies;
    _LDR_DDAG_STATE State;
    struct _SINGLE_LIST_ENTRY CondenseLink;
    unsigned long PreorderNumber;
    unsigned long LowestLink;
};

struct _PEB_LDR_DATA_W8
{
    unsigned long Length;
    unsigned char Initialized;
    void * SsHandle;
    _LIST_ENTRY InLoadOrderModuleList;
    _LIST_ENTRY InMemoryOrderModuleList;
    _LIST_ENTRY InInitializationOrderModuleList;
    void * EntryInProgress;
    unsigned char ShutdownInProgress;
    void * ShutdownThreadId;
};

struct _LDR_DATA_TABLE_ENTRY_W8
{
    _LIST_ENTRY InLoadOrderLinks;
    _LIST_ENTRY InMemoryOrderLinks;
    union
    {
        _LIST_ENTRY InInitializationOrderLinks;
        _LIST_ENTRY InProgressLinks;
    };
    void * DllBase;
    void * EntryPoint;
    unsigned long SizeOfImage;
    _UNICODE_STRING FullDllName;
    _UNICODE_STRING BaseDllName;
    unsigned long Flags;
    unsigned short ObsoleteLoadCount;
    unsigned short TlsIndex;
    struct _LIST_ENTRY HashLinks;
    unsigned long TimeDateStamp;
    struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
    void * PatchInformation;
    _LDR_DDAG_NODE * DdagNode;
    _LIST_ENTRY NodeModuleLink;
    struct _LDRP_DLL_SNAP_CONTEXT * SnapContext;
    void * ParentDllBase;
    void * SwitchBackContext;
    _RTL_BALANCED_NODE BaseAddressIndexNode;
    _RTL_BALANCED_NODE MappingInfoIndexNode;
    unsigned long OriginalBase;
    union _LARGE_INTEGER LoadTime;
    unsigned long BaseNameHashValue;
    _LDR_DLL_LOAD_REASON LoadReason;
};

struct _LDR_DATA_TABLE_ENTRY_W7
{
    _LIST_ENTRY InLoadOrderLinks;
    _LIST_ENTRY InMemoryOrderLinks;
    _LIST_ENTRY InInitializationOrderLinks;
    void * DllBase;
    void * EntryPoint;
    unsigned long SizeOfImage;
    _UNICODE_STRING FullDllName;
    _UNICODE_STRING BaseDllName;
    unsigned long Flags;
    unsigned short LoadCount;
    unsigned short TlsIndex;
    union
    {
        _LIST_ENTRY HashLinks;
        struct
        {
            void * SectionPointer;
            unsigned long CheckSum;
        };
    };
    union
    {
        unsigned long TimeDateStamp;
        void * LoadedImports;
    };
    struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
    void * PatchInformation;
    _LIST_ENTRY ForwarderLinks;
    _LIST_ENTRY ServiceTagLinks;
    _LIST_ENTRY StaticLinks;
    void * ContextInformation;
    unsigned long OriginalBase;
    _LARGE_INTEGER LoadTime;
};


#pragma warning(default : 4201)

typedef struct _RTL_INVERTED_FUNCTION_TABLE_ENTRY
{
    PIMAGE_RUNTIME_FUNCTION_ENTRY ExceptionDirectory;
    PVOID                         ImageBase;
    ULONG                         ImageSize;
    ULONG                         ExceptionDirectorySize;

} RTL_INVERTED_FUNCTION_TABLE_ENTRY, * PRTL_INVERTED_FUNCTION_TABLE_ENTRY;

typedef struct _RTL_INVERTED_FUNCTION_TABLE7
{
    ULONG Count;
    ULONG MaxCount;
    ULONG Pad[0x1];
    RTL_INVERTED_FUNCTION_TABLE_ENTRY Entries[0x200];

} RTL_INVERTED_FUNCTION_TABLE7, * PRTL_INVERTED_FUNCTION_TABLE7;

typedef struct _RTL_INVERTED_FUNCTION_TABLE8
{
    ULONG Count;
    ULONG MaxCount;
    ULONG Pad[0x2];
    RTL_INVERTED_FUNCTION_TABLE_ENTRY Entries[0x200];

} RTL_INVERTED_FUNCTION_TABLE8, * PRTL_INVERTED_FUNCTION_TABLE8;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS    ExitStatus;
    PTEB        TebBaseAddress;
    struct
    {
        PVOID p1;
        PVOID p2;
    }ClientId;
    KAFFINITY   AffinityMask;
    LONG        Priority;
    LONG        BasePriority;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

//
// Api schema structures
//
struct ApiSchemaMapHeader
{
    DWORD Version;
    DWORD NumModules;
};

struct ApiSchemaModuleEntry
{
    DWORD OffsetToName;
    WORD NameSize;
    DWORD OffsetOfHosts;
};

struct ApiSchemaModuleHostsHeader
{
    DWORD NumHosts;
};

struct ApiSchemaModuleHost
{
    DWORD OffsetOfImportingName;
    WORD ImportingNameSize;
    DWORD OffsetOfHostName;
    WORD HostNameSize;
};