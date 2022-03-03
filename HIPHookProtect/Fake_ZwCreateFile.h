#pragma once
#include "data.h"
#include "DoFake.h"
#include "WhiteFileList.h"
#include <ntddk.h>

NTSTATUS NTAPI Fake_ZwCreateFile(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);