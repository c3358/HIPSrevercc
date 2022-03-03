#include "Filter_ZwOpenKey.h"

NTSTATUS NTAPI Filter_ZwOpenKey(
	OUT PHANDLE            KeyHandle,
	IN  ACCESS_MASK        DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes 

) {

	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &KeyHandle;//参数数组，指向栈中属于本函数的所有参数

	NTSTATUS(NTAPI * ZwOpenKeyPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
	//原始函数执行前检查
	Result = HookProtect_DoFake(ZwOpenKey_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwOpenKeyPtr = g_FilterFun_table->OldFunc[ZwOpenKey_FilterIndex];

		//调用原始函数
		Result = ZwOpenKeyPtr(KeyHandle, DesiredAccess, ObjectAttributes);
		if (NT_SUCCESS(Result))
		{
			//原始函数执行后检查
			Result = HookPort_ForRunFuncTable(ZwOpenKey_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;







}