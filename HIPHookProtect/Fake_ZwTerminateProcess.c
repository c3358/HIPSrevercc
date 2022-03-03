#include "Fake_ZwTerminateProcess.h"

//��������
NTSTATUS NTAPI Fake_ZwTerminateProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	ULONG          ReturnLength = NULL;
	PEPROCESS      pPeprocess = NULL;
	HANDLE		   hProcessID = 0;
	BOOLEAN        ObfDereferenceObjectFlag = FALSE;		//�����ObfDereferenceObject  ������Ҫ
	UNICODE_STRING stProcessPathName;
	RtlInitUnicodeString(&stProcessPathName, L"HIPTermintor.exe");

	//0����ȡZwTerminateProcessԭʼ����
	HANDLE   In_ProcessHandle = *(ULONG*)((ULONG)ArgArray);
	NTSTATUS In_ExitStatus = *(ULONG*)((ULONG)ArgArray + 4);
	//��һ��R3����ZwTerminateProcess�����������̵ķ�����ʩ
	//1��������Ӧ�ò����
	if (!ExGetPreviousMode())
	{
		return result;
	}


	// ��ȡEprocess�ṹ
	//ע��ObReferenceObjectByHandle��ȡ��Eprocess�ṹ��Ҫ������
	Status = ObReferenceObjectByHandle(In_ProcessHandle, NULL, PsProcessType, ExGetPreviousMode(), &pPeprocess, 0);
	if (!NT_SUCCESS(Status))
	{
		//��ȡʧ��ֱ���˳�
		result = STATUS_SUCCESS;
		return result;
	}
	else
	{
		//��ʾObReferenceObjectByHandle�������óɹ���������Ҫ�ͷ�
		ObfDereferenceObjectFlag = TRUE;
		hProcessID = PsGetProcessId(pPeprocess);

	}

	//�ж��Ƿ�������������������̵�PID
	if (hProcessID == g_OurselfProcessID)
	{
		//�ж��Ƿ�Ϊ���������̣��Լ������Լ�
		if (PsGetCurrentProcessId() != g_OurselfProcessID)
		{
			result = STATUS_ACCESS_DENIED;
			RecordLogOurselfProtect(&stProcessPathName, FALSE, Operate_ExitProcess);
		}

	}

	//6��ObfDereferenceObjectFlagΪ�����Ҫ�ͷţ�����ObReferenceObjectByHandle or IoGetCurrentProcess��ʽ��ȡ��Eprocess�ṹ
	if (ObfDereferenceObjectFlag)
	{
		ObfDereferenceObject(pPeprocess);
	}

	return result;
}