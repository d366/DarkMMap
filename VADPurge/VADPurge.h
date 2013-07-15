#ifndef _VAD_PURGE_H_
#define _VAD_PURGE_H_

#include <Ntifs.h>
#include <Ntstrsafe.h>

#include "VADPurgeDef.h"
#include "PrivateRoutines.h"

#define DEVICE_NAME     L"\\Device\\VadPurge"
#define DOS_DEVICE_NAME L"\\DosDevices\\VADPURGE"


typedef struct _OFST_DEF
{
    ULONG ofsVadRoot;

}OFST_DEF, *POFST_DEF;


#endif// _VAD_PURGE_H_