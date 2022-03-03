#include "Filter_ZwOpenProcess.h"

NTSTATUS NTAPI Filter_ZwOpenProcess(
	OUT          PHANDLE            ProcessHandle,
	IN           ACCESS_MASK        DesiredAccess,
	IN           POBJECT_ATTRIBUTES ObjectAttributes,
	IN			 PCLIENT_ID         ClientId OPTIONAL
){

	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &ProcessHandle;//参数数组，指向栈中属于本函数的所有参数

	NTSTATUS(NTAPI * ZwOpenProcessPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
	//原始函数执行前检查
	Result = HookProtect_DoFake(ZwOpenProcess_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwOpenProcessPtr = g_FilterFun_table->OldFunc[ZwOpenProcess_FilterIndex];

		//调用原始函数
		Result = ZwOpenProcessPtr(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		if (NT_SUCCESS(Result))
		{
			//原始函数执行后检查
			Result = HookPort_ForRunFuncTable(ZwOpenProcess_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;



}