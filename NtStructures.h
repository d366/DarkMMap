#pragma once
#include <windows.h>
#include <winternl.h>

#ifdef _M_AMD64
#define NT_LDRP_HASH_TABLE_W7       0x104800
#define NT_LDRP_HASH_TABLE_W8       0x13E7B0
#define NT_LDRP_MODULE_TREE_ROOT    0x13EAA0
#else
#define NT_LDRP_HASH_TABLE_W7       0x104800
#define NT_LDRP_HASH_TABLE_W8       0xEE6C0
#define NT_LDRP_MODULE_TREE_ROOT    0xEFA98
#endif

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