#pragma once
#include "data.h"
#include "DoFake.h"
#include <ntddk.h>


NTSTATUS NTAPI Filter_ZwSetInformationFile(
	IN  HANDLE                 FileHandle,
	OUT PIO_STATUS_BLOCK       IoStatusBlock,
	IN  PVOID                  FileInformation,
	IN  ULONG                  Length,
	IN  FILE_INFORMATION_CLASS FileInformationClass
);