#pragma once
#include "data.h"
#include "DoFake.h"
#include <ntddk.h>


NTSTATUS NTAPI Filter_CreateProcessNotifyRoutine(IN HANDLE  ParentId, IN HANDLE  ProcessId, IN BOOLEAN  Create);

