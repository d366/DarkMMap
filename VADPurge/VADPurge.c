#include "VADPurge.h"

// OS Dependant offsets
OFST_DEF ofst_current;

// Function prototypes
NTSTATUS DriverEntry    ( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING registryPath );
NTSTATUS VPDispatch     ( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
VOID     VPUnload       ( IN PDRIVER_OBJECT DriverObject );
NTSTATUS VPPurgeRecord  ( IN PPURGE_DATA pData);
NTSTATUS VPInitOffsets  ( );
VOID     VPTrace        ( IN PCHAR pFormat, ... );

#pragma alloc_text(PAGE, DriverEntry)
#pragma alloc_text(PAGE, VPUnload)
#pragma alloc_text(PAGE, VPDispatch)
#pragma alloc_text(PAGE, VPPurgeRecord)
#pragma alloc_text(PAGE, VPInitOffsets)
#pragma alloc_text(PAGE, VPTrace)

/*
*/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS       status                   = STATUS_SUCCESS;
    PDEVICE_OBJECT deviceObject             = NULL;
    WCHAR          deviceNameBuffer[]       = DEVICE_NAME;
    WCHAR          deviceLinkBuffer[]       = DOS_DEVICE_NAME;
    UNICODE_STRING deviceNameUnicodeString;
    UNICODE_STRING deviceLinkUnicodeString;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DPRINT("DriverEntry\n");

    RtlZeroMemory(&ofst_current, sizeof(ofst_current));

    RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
     
    status = IoCreateDevice(DriverObject, 0, &deviceNameUnicodeString, FILE_DEVICE_VADPURGE, 0, TRUE, &deviceObject);

    if ( !NT_SUCCESS(status) )
    {
        DPRINT ("IoCreateDevice failed: %x\n", status);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]          =
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           =
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = VPDispatch;
    DriverObject->DriverUnload                          = VPUnload;

    RtlInitUnicodeString(&deviceLinkUnicodeString, deviceLinkBuffer);

    status = IoCreateSymbolicLink(&deviceLinkUnicodeString, &deviceNameUnicodeString);

    if ( !NT_SUCCESS(status) )
    {
        DPRINT ("IoCreateSymbolicLink failed\n");
        IoDeleteDevice (deviceObject);
    }

    // Get OS Dependant offsets
    if( !NT_SUCCESS(VPInitOffsets()) )
    {
        DPRINT ("Unsupported OS version. Aborting\n");
        IoDeleteSymbolicLink(&deviceLinkUnicodeString);
        IoDeleteDevice (deviceObject);
    }

    return status;
}

/*
*/
NTSTATUS VPDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION  irpStack;
    PVOID               ioBuffer;
    ULONG               inputBufferLength;
    ULONG               outputBufferLength;
    ULONG               ioControlCode;
    NTSTATUS            ntStatus;

    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    irpStack           = IoGetCurrentIrpStackLocation(Irp);
                
    ioBuffer           = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength  = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (irpStack->MajorFunction)
    {
    case IRP_MJ_DEVICE_CONTROL:
        {
            ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

            switch (ioControlCode)
            {
            case IOCTL_VADPURGE_PURGE:
                {
                    if ( inputBufferLength >= sizeof(PURGE_DATA) && ioBuffer )
                    {
                        Irp->IoStatus.Status = VPPurgeRecord((PPURGE_DATA)ioBuffer);
                    }
                    else
                    {
                        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                        DPRINT ("Error. Invalid parameter passed\n");
                    }
                }
                break;

            default:
                DPRINT ("Unknown IRP_MJ_DEVICE_CONTROL %d\n", ioControlCode);
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                break;
            }
        }
        break;
    }

    ntStatus = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return ntStatus;
}

/*
*/
VOID VPUnload(IN PDRIVER_OBJECT DriverObject)
{
    WCHAR           deviceLinkBuffer[]  = DOS_DEVICE_NAME;
    UNICODE_STRING  deviceLinkUnicodeString;

    RtlInitUnicodeString(&deviceLinkUnicodeString, deviceLinkBuffer);
    IoDeleteSymbolicLink(&deviceLinkUnicodeString);
    IoDeleteDevice(DriverObject->DeviceObject);

    DPRINT ("Driver has been unloaded\n");

    return;
}

/*
*/
NTSTATUS VPPurgeRecord( IN PPURGE_DATA pData )
{
    NTSTATUS    status    = STATUS_SUCCESS;
    PEPROCESS   EProcess  = NULL;
    ULONGLONG   vpnStart  = pData->entries[0].startAddr >> 12;

    __try
    {
        DPRINT ("ProcID = %d\n", pData->procID);
        status = PsLookupProcessByProcessId((HANDLE)pData->procID, &EProcess);

        if (NT_ERROR(status) || EProcess == NULL)
        {
            DPRINT ("PsLookupProcessByProcessId Failed (%d)\n", status);
        }
        else
        {
            DPRINT ("EPROCESS = 0x%Ix\n", EProcess);

            if(ofst_current.ofsVadRoot != 0)
            {
                PMM_AVL_TABLE pTable    = (PMM_AVL_TABLE)((PUCHAR)EProcess + ofst_current.ofsVadRoot);
                PMMADDRESS_NODE pNode   = (PMMADDRESS_NODE)pTable->BalancedRoot.RightChild;

                DPRINT ("_MM_AVL_TABLE = 0x%Ix\n", pTable);
                DPRINT ("VadRootNode = 0x%Ix\n",   pNode);
                DPRINT ("VPN to find = 0x%Ix\n",   vpnStart);

                //
                // Search VAD
                //
                if(MiFindNodeOrParent(pTable, (ULONG_PTR)vpnStart, &pNode) == TableFoundNode)
                {
                    PMMVAD_SHORT pVad  = (PMMVAD_SHORT)pNode;
                    //PPOOL_HEADER pPool = (PPOOL_HEADER)((PUCHAR)pNode - sizeof(POOL_HEADER));

                    //DPRINT ("Found VAD node: tag = 0x%x, type = %d, prot = %d, isPrivate = %d. Unlinking...", 
                        //pPool->PoolTag, pVad->u.VadFlags.VadType, pVad->u.VadFlags.Protection, pVad->u.VadFlags.PrivateMemory);
                    DPRINT ("Found VAD node: \n");
                    DPRINT ("   vad tag    = 0x%Ix\n", pPool->PoolTag);
                    DPRINT ("   start      = 0x%Ix\n", pVad->StartingVpn);
                    DPRINT ("   end        = 0x%Ix\n", pVad->EndingVpn);
                    DPRINT ("   commit     = 0x%Ix\n", pVad->u1.VadFlags1.MemCommit);
                    DPRINT ("   type       = 0x%Ix\n", pVad->u.VadFlags.VadType);
                    DPRINT ("   protection = 0x%Ix\n", pVad->u.VadFlags.Protection);
                    DPRINT ("   isPrivate  = 0x%Ix\n", pVad->u.VadFlags.PrivateMemory);

                    DPRINT ("Unlinking...");

                    //pVad->u.VadFlags.Protection  = 0;
                    //pVad->u1.VadFlags1.MemCommit = 0;

                    // Unlink node from AVL tree
                    MiRemoveNode(pNode, pTable);          

                    //
                    // If the hint points at the removed VAD, change the hint.
                    //
                    if (pTable->NodeHint == pVad) 
                    {
                        pTable->NodeHint = pTable->BalancedRoot.RightChild;

                        if(pTable->NumberGenericTableElements == 0)
                            pTable->NodeHint = NULL;
                    }

                    // Free node memory
                    //ExFreePoolWithTag(pNode, pPool->PoolTag);

                    DPRINT ("Successfull");
                }
                else
                {
                    DPRINT ("VAD entry not found\n");
                    status = STATUS_NOT_FOUND;
                }               
            }
            else
            {
                DPRINT ("Invalid VadRoot offset\n");
                status = STATUS_INVALID_ADDRESS;
            }

            ObDereferenceObject((PVOID)EProcess);

            EProcess = NULL;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT ("Exception in VPPurgeEntry\n");

        if(EProcess != NULL)
            ObDereferenceObject((PVOID)EProcess);

        status = STATUS_UNHANDLED_EXCEPTION;
    }

    return status;
}

/*
*/
NTSTATUS VPInitOffsets()
{
    RTL_OSVERSIONINFOEXW verInfo;
    NTSTATUS status = STATUS_SUCCESS;

    __try
    {
        verInfo.dwOSVersionInfoSize = sizeof(verInfo);

        status = RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);

        if(status == STATUS_SUCCESS)
        {
            DPRINT("OS version %d.%d.%d.%d\n", verInfo.dwMajorVersion, verInfo.dwMinorVersion, verInfo.dwBuildNumber, verInfo.wServicePackMajor);

            //
            // Windows 7
            //
            if(verInfo.dwMajorVersion == 6 && verInfo.dwMinorVersion == 1)
            {
                // No SP
                if(verInfo.wServicePackMajor == 0)
                {
                #ifdef _M_AMD64
                    ofst_current.ofsVadRoot = 0x448;
                #else
                    ofst_current.ofsVadRoot = 0x278;
                #endif// _M_AMD64
                }
                // SP1
                else if(verInfo.wServicePackMajor == 1)
                {
                #ifdef _M_AMD64
                    ofst_current.ofsVadRoot = 0x448;
                #else
                    ofst_current.ofsVadRoot = 0x278;
                #endif// _M_AMD64
                }
                else
                    return STATUS_NOT_SUPPORTED;
            }

            //
            // Windows 8
            //
            else if(verInfo.dwMajorVersion == 6 && verInfo.dwMinorVersion == 2)
            {
                // No SP
                if(verInfo.wServicePackMajor == 0)
                {
                #ifdef _M_AMD64
                    ofst_current.ofsVadRoot = 0x590;
                #else
                    ofst_current.ofsVadRoot = 0x384;
                #endif// _M_AMD64
                }
                // SP1 (Stub)
                else if(verInfo.wServicePackMajor == 1)
                {
                }
                else
                    return STATUS_NOT_SUPPORTED;
            }
            else
                return STATUS_NOT_SUPPORTED;
        }

    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }

    DPRINT("ofsVadRoot = 0x%X\n", ofst_current.ofsVadRoot);

    return status;
}

/*
*/
VOID VPTrace( IN PCHAR pFormat, ... )
{
	CHAR Buffer[2048];
    CHAR *pPrefix = "VadPurge.sys: ";
	va_list Next;
	NTSTATUS Status = STATUS_SUCCESS;

    va_start(Next, pFormat);

    RtlZeroMemory(&Buffer, sizeof(Buffer));

    RtlStringCbCopyA(Buffer, sizeof(Buffer), pPrefix);
    Status = RtlStringCbVPrintfA(Buffer + strlen(pPrefix), sizeof(Buffer) - strlen(pPrefix), pFormat, Next);

    if (NT_SUCCESS(Status) == TRUE )
        DbgPrint(Buffer);

    va_end(Next);
}