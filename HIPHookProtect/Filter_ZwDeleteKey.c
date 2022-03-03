#include "Filter_ZwDeleteKey.h"


NTSTATUS NTAPI Filter_ZwDeleteKey(IN HANDLE KeyHandle)
{
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &KeyHandle;//�������飬ָ��ջ�����ڱ����������в���

	NTSTATUS(NTAPI * ZwDeleteKeyPtr)(HANDLE);
	//ԭʼ����ִ��ǰ���
	Result = HookProtect_DoFake(ZwDeleteKey_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//��ȡԭʼ������ַ
		ZwDeleteKeyPtr = g_FilterFun_table->OldFunc[ZwDeleteKey_FilterIndex];

		//����ԭʼ����
		Result = ZwDeleteKeyPtr(KeyHandle);
		if (NT_SUCCESS(Result))
		{
			//ԭʼ����ִ�к���
			Result = HookPort_ForRunFuncTable(ZwDeleteKey_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;

}
