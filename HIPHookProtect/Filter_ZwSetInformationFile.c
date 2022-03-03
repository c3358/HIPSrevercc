#include "Filter_ZwSetInformationFile.h"

NTSTATUS NTAPI Filter_ZwSetInformationFile(
	IN  HANDLE                 FileHandle,
	OUT PIO_STATUS_BLOCK       IoStatusBlock,
	IN  PVOID                  FileInformation,
	IN  ULONG                  Length,
	IN  FILE_INFORMATION_CLASS FileInformationClass
) {
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &FileHandle;//参数数组，指向栈中属于本函数的所有参数

	NTSTATUS(NTAPI * ZwSetInformationFilePtr)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
	//原始函数执行前检查
	Result = HookProtect_DoFake(ZwSetInformationFile_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwSetInformationFilePtr = g_FilterFun_table->OldFunc[ZwSetInformationFile_FilterIndex];

		//调用原始函数
		Result = ZwSetInformationFilePtr(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
		if (NT_SUCCESS(Result))
		{
			//原始函数执行后检查
			Result = HookPort_ForRunFuncTable(ZwSetInformationFile_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;






}