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
	PVOID    pArgArray = &ProcessHandle;//�������飬ָ��ջ�����ڱ����������в���

	NTSTATUS(NTAPI * ZwOpenProcessPtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
	//ԭʼ����ִ��ǰ���
	Result = HookProtect_DoFake(ZwOpenProcess_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//��ȡԭʼ������ַ
		ZwOpenProcessPtr = g_FilterFun_table->OldFunc[ZwOpenProcess_FilterIndex];

		//����ԭʼ����
		Result = ZwOpenProcessPtr(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		if (NT_SUCCESS(Result))
		{
			//ԭʼ����ִ�к���
			Result = HookPort_ForRunFuncTable(ZwOpenProcess_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;



}