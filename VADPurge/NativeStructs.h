#pragma once

#define VAD_TAG         ' daV'
#define VAD_SHORT_TAG   'SdaV'
#define VAD_LONG_TAG    'ldaV'

#ifdef _WIN8_
#include "NativeStructs8.h"
#elif _WIN7_
#include "NativeStructs7.h"
#else
#error Unsupported OS build version
#endif