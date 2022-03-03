#pragma once
#include "data.h"
#include <ntddk.h>

ULONG NTAPI HookPort_ForRunFuncTable(IN ULONG CallIndex, IN PHANDLE ArgArray, IN NTSTATUS InResult, IN PULONG* RetFuncArray, IN PULONG* RetFuncArgArray, IN ULONG  RetCount);


//获取原始的SSDT
ULONG NTAPI HookPort_GetOriginalServiceRoutine(IN ULONG ServiceIndex);

NTSTATUS NTAPI HookProtect_DoFake(ULONG CallIndex, PHANDLE ArgArray, PULONG* RetFuncArray, PULONG* RetFuncArgArray, PULONG RetNumber, PULONG Result);