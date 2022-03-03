#pragma once
#include "data.h"
#include "DoFake.h"
#include <ntddk.h>


NTSTATUS NTAPI Filter_ZwOpenKeyEx(
	OUT PHANDLE            KeyHandle,
	IN  ACCESS_MASK        DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes,
	IN  ULONG              OpenOptions 
);