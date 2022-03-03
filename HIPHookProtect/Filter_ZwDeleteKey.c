#include "Filter_ZwDeleteKey.h"


NTSTATUS NTAPI Filter_ZwDeleteKey(IN HANDLE KeyHandle)
{
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &KeyHandle;//参数数组，指向栈中属于本函数的所有参数

	NTSTATUS(NTAPI * ZwDeleteKeyPtr)(HANDLE);
	//原始函数执行前检查
	Result = HookProtect_DoFake(ZwDeleteKey_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwDeleteKeyPtr = g_FilterFun_table->OldFunc[ZwDeleteKey_FilterIndex];

		//调用原始函数
		Result = ZwDeleteKeyPtr(KeyHandle);
		if (NT_SUCCESS(Result))
		{
			//原始函数执行后检查
			Result = HookPort_ForRunFuncTable(ZwDeleteKey_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;

}
