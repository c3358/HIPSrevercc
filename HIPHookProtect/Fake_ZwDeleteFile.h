#pragma once
#include "data.h"
#include "DoFake.h"
#include "WhiteFileList.h"
#include <ntddk.h>

//ɾ���ļ�
NTSTATUS NTAPI Fake_ZwDeleteFile(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);