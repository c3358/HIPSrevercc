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
	PVOID    pArgArray = &KeyHandle;//�������飬ָ��ջ�����ڱ����������в���

	NTSTATUS(NTAPI * ZwOpenKeyPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
	//ԭʼ����ִ��ǰ���
	Result = HookProtect_DoFake(ZwOpenKey_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//��ȡԭʼ������ַ
		ZwOpenKeyPtr = g_FilterFun_table->OldFunc[ZwOpenKey_FilterIndex];

		//����ԭʼ����
		Result = ZwOpenKeyPtr(KeyHandle, DesiredAccess, ObjectAttributes);
		if (NT_SUCCESS(Result))
		{
			//ԭʼ����ִ�к���
			Result = HookPort_ForRunFuncTable(ZwOpenKey_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;







}