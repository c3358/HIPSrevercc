#pragma once
#include "data.h"
#include "WhiteRegditList.h"
#include "WhiteFileList.h"
#include "CurrencyFunc.h"
#include <ntddk.h>
//��ע����ֵ
NTSTATUS NTAPI Fake_ZwOpenKeyEx(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);