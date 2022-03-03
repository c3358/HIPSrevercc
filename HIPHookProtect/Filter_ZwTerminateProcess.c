#include "Filter_ZwTerminateProcess.h"

NTSTATUS NTAPI Filter_ZwTerminateProcess(
	IN HANDLE   ProcessHandle OPTIONAL,
	IN           NTSTATUS ExitStatus
){

	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &ProcessHandle;//参数数组，指向栈中属于本函数的所有参数

	NTSTATUS(NTAPI * ZwTerminateProcessPtr)(HANDLE, NTSTATUS);
	//原始函数执行前检查
	Result = HookProtect_DoFake(ZwTerminateProcess_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwTerminateProcessPtr = g_FilterFun_table->OldFunc[ZwTerminateProcess_FilterIndex];

		//调用原始函数
		Result = ZwTerminateProcessPtr(ProcessHandle, ExitStatus);
		if (NT_SUCCESS(Result))
		{
			//原始函数执行后检查
			Result = HookPort_ForRunFuncTable(ZwTerminateProcess_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;



}