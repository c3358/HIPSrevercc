#include "Filter_ZwOpenKeyEx.h"

NTSTATUS NTAPI Filter_ZwOpenKeyEx(
	OUT PHANDLE            KeyHandle,
	IN  ACCESS_MASK        DesiredAccess,
	IN  POBJECT_ATTRIBUTES ObjectAttributes,
	IN  ULONG              OpenOptions
) {

	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &KeyHandle;//参数数组，指向栈中属于本函数的所有参数

	NTSTATUS(NTAPI * ZwOpenKeyExPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
	//原始函数执行前检查
	Result = HookProtect_DoFake(ZwOpenKeyEx_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//获取原始函数地址
		ZwOpenKeyExPtr = g_FilterFun_table->OldFunc[ZwOpenKeyEx_FilterIndex];

		//调用原始函数
		Result = ZwOpenKeyExPtr(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
		if (NT_SUCCESS(Result))
		{
			//原始函数执行后检查
			Result = HookPort_ForRunFuncTable(ZwOpenKeyEx_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;




}