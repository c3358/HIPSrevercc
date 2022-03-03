#pragma once
#include "data.h"
#include "DoFake.h"
#include "WhiteFileList.h"
#include <ntddk.h>

//É¾³ýÎÄ¼þ
NTSTATUS NTAPI Fake_ZwDeleteFile(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);