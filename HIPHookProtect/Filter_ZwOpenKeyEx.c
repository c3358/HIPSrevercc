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
	PVOID    pArgArray = &KeyHandle;//�������飬ָ��ջ�����ڱ����������в���

	NTSTATUS(NTAPI * ZwOpenKeyExPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG);
	//ԭʼ����ִ��ǰ���
	Result = HookProtect_DoFake(ZwOpenKeyEx_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//��ȡԭʼ������ַ
		ZwOpenKeyExPtr = g_FilterFun_table->OldFunc[ZwOpenKeyEx_FilterIndex];

		//����ԭʼ����
		Result = ZwOpenKeyExPtr(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
		if (NT_SUCCESS(Result))
		{
			//ԭʼ����ִ�к���
			Result = HookPort_ForRunFuncTable(ZwOpenKeyEx_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;




}