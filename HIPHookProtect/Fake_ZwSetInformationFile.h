#pragma once
#include "data.h"
#include "WhiteFileList.h"
#include "CurrencyFunc.h"
#include <ntddk.h>

NTSTATUS NTAPI Fake_ZwSetInformationFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg);