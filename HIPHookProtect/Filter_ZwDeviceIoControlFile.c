#include "Filter_ZwDeviceIoControlFile.h"

NTSTATUS
NTAPI
Filter_ZwDeviceIoControlFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
) {
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &FileHandle;//参数数组，指向栈中属于本函数的所有参数

	NTSTATUS(NTAPI * ZwDeviceIoControlFilePtr)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
	//原始函数执行前检查
	Result = HookProtect_DoFake(ZwDeviceIoControlFile_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwDeviceIoControlFilePtr = g_FilterFun_table->OldFunc[ZwDeviceIoControlFile_FilterIndex];

		//调用原始函数
		Result = ZwDeviceIoControlFilePtr(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
		if (NT_SUCCESS(Result))
		{
			//原始函数执行后检查
			Result = HookPort_ForRunFuncTable(ZwDeviceIoControlFile_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;







}