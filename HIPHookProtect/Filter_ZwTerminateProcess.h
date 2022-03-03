#pragma once
#include "data.h"
#include "DoFake.h"
#include <ntddk.h>


NTSTATUS NTAPI Filter_ZwTerminateProcess(
	IN HANDLE   ProcessHandle OPTIONAL,
	IN           NTSTATUS ExitStatus
);