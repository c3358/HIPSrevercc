#pragma once
#include "data.h"
#include "DoFake.h"
#include "WhiteProcessList.h"
#include <ntddk.h>
NTSTATUS NTAPI Fake_CreateProcessNotifyRoutine(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg);