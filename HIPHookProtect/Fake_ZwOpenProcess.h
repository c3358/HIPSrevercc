#pragma once
#include "data.h"
#include "WhiteRegditList.h"
#include "WhiteFileList.h"
#include "CurrencyFunc.h"
#include <ntddk.h>

//��¼��־��
NTSTATUS RecordLogOurselfProtect(PCUNICODE_STRING stProcessPathName, BOOL bFlag, BOOL bOperate);

//�򿪽���
NTSTATUS NTAPI Fake_ZwOpenProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);