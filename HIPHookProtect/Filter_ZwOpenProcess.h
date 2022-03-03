#pragma once
#include "data.h"
#include "DoFake.h"
#include <ntddk.h>


NTSTATUS NTAPI Filter_ZwOpenProcess(
	OUT          PHANDLE            ProcessHandle,
	IN           ACCESS_MASK        DesiredAccess,
	IN           POBJECT_ATTRIBUTES ObjectAttributes,
	IN			 PCLIENT_ID         ClientId OPTIONAL
);