#pragma once
#include "data.h"
#include "DoFake.h"
#include <ntddk.h>

NTSTATUS NTAPI Filter_ZwDeleteKey(IN HANDLE KeyHandle);