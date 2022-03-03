#pragma once
#include "data.h"
#include "DoFake.h"
#include <ntddk.h>

NTSTATUS NTAPI Filter_ZwWriteFile(
	IN           HANDLE           FileHandle,
	IN HANDLE           Event OPTIONAL,
	IN PIO_APC_ROUTINE  ApcRoutine OPTIONAL,
	IN PVOID            ApcContext OPTIONAL,
	OUT          PIO_STATUS_BLOCK IoStatusBlock,
	OUT          PVOID            Buffer,
	IN           ULONG            Length,
	IN PLARGE_INTEGER   ByteOffset OPTIONAL,
	IN PULONG           Key OPTIONAL);