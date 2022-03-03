#pragma once
#include "data.h"
#include "WhiteRegditList.h"
#include "WhiteFileList.h"
#include "CurrencyFunc.h"
#include <ntddk.h>

//É¾³ý×¢²á±íÖµ¼ü
NTSTATUS NTAPI Fake_ZwDeleteKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);