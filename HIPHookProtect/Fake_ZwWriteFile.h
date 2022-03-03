#pragma once
#include "data.h"
#include "DoFake.h"
#include "WhiteFileList.h"
#include <ntddk.h>

NTSTATUS NTAPI Fake_ZwWriteFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg);