#include "Filter_ZwOpenFile.h"




NTSTATUS NTAPI Filter_ZwOpenFile(OUT PHANDLE  FileHandle, IN ACCESS_MASK  DesiredAccess, IN POBJECT_ATTRIBUTES  ObjectAttributes, OUT PIO_STATUS_BLOCK  IoStatusBlock, IN ULONG  ShareAccess, IN ULONG  OpenOptions)
{
	NTSTATUS Result, OutResult;
	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &FileHandle;//参数数组，指向栈中属于本函数的所有参数
	NTSTATUS(NTAPI * ZwOpenFilePtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
	Result = HookProtect_DoFake(ZwOpenFile_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		
		//获取原始函数地址
		ZwOpenFilePtr = g_FilterFun_table->OldFunc[ZwOpenFile_FilterIndex];
		
		//调用原始函数
		Result = ZwOpenFilePtr(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
		if (NT_SUCCESS(Result))
		{
			//调用返回值检查函数
			Result = HookPort_ForRunFuncTable(ZwOpenFile_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;
}