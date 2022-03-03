#include "Filter_ZwTerminateProcess.h"

NTSTATUS NTAPI Filter_ZwTerminateProcess(
	IN HANDLE   ProcessHandle OPTIONAL,
	IN           NTSTATUS ExitStatus
){

	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &ProcessHandle;//�������飬ָ��ջ�����ڱ����������в���

	NTSTATUS(NTAPI * ZwTerminateProcessPtr)(HANDLE, NTSTATUS);
	//ԭʼ����ִ��ǰ���
	Result = HookProtect_DoFake(ZwTerminateProcess_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//��ȡԭʼ������ַ
		ZwTerminateProcessPtr = g_FilterFun_table->OldFunc[ZwTerminateProcess_FilterIndex];

		//����ԭʼ����
		Result = ZwTerminateProcessPtr(ProcessHandle, ExitStatus);
		if (NT_SUCCESS(Result))
		{
			//ԭʼ����ִ�к���
			Result = HookPort_ForRunFuncTable(ZwTerminateProcess_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;



}