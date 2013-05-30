#pragma once

#define WIN32_LEAN_AND_MEAN

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>

#include <initializer_list>

#include "Errors.h"

#define MAKE_PTR(T, pRVA, base)          (T)((size_t)pRVA + (size_t)base)
#define REBASE(pRVA, baseOld, baseNew)      ((size_t)pRVA - (size_t)baseOld + (size_t)baseNew)

