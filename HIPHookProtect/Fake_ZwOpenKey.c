#include "Fake_ZwOpenKey.h"
NTSTATUS NTAPI After_ZwOpenKey_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS  Status, result;
	PEPROCESS pPeprocess = NULL;
	HANDLE   Object = NULL;
	POBJECT_NAME_INFORMATION pFileNameInfo = NULL;
	ULONG NumberOfBytes = 0x1024;
	ULONG ReturnLength = NULL;
	ULONG Tag = 0x206B6444u;
	BOOLEAN ErrorFlag = TRUE;				//�ɹ�1��ʧ��0
	result = STATUS_SUCCESS;
	//0����ȡZwOpenKeyԭʼ����
	PHANDLE   In_KeyHandle = *(ULONG*)((ULONG)ArgArray);
	//1���ж��ϴε���ԭʼ��������ֵ
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//����ַ�Ϸ���
	if (myProbeRead(In_KeyHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(After_ZwOpenKey_Func��In_KeyHandle) error \r\n"));
		return result;
	}
	Status = ObReferenceObjectByHandle(*(ULONG*)In_KeyHandle, 0, 0, UserMode, &Object, 0);
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	pFileNameInfo = (POBJECT_NAME_INFORMATION)Safe_AllocBuff(NonPagedPool, NumberOfBytes, Tag);
	if (!pFileNameInfo)
	{
		ObfDereferenceObject(Object);
		return result;
	}
	//2��ͨ��ע���_OBJECTָ���ѯע���·��
	Status = ObQueryNameString(Object, pFileNameInfo, NumberOfBytes, &ReturnLength);
	ObfDereferenceObject(Object);
	if (!NT_SUCCESS(Status) || !pFileNameInfo->Name.Buffer || !pFileNameInfo->Name.Length)
	{
		ExFreePool(pFileNameInfo);
		return result;
	}
	//3���ж��Ƿ�Ϊ����·��
	if (Safe_QueryProtectRegditList_RegditName(&pFileNameInfo->Name))
	{
		//�ж��ǲ��ǰ׽���
		if (Safe_QueryWhitePID(PsGetCurrentProcessId()))
			RecordLogRegdit(&pFileNameInfo->Name, TRUE, Operate_OpenKey);
		else
		{
			RecordLogRegdit(&pFileNameInfo->Name, FALSE, Operate_OpenKey);
			ErrorFlag = FALSE;
			result = STATUS_ACCESS_DENIED;
		}
	}
	else
	{
		//�Ϸ�����
		ErrorFlag = TRUE;
		result = STATUS_SUCCESS;
	}


	//ʧ�ܷ���Ҫ��վ��
	if (!ErrorFlag)
	{
		Safe_ZwNtClose(*(ULONG*)In_KeyHandle, 1);
		*(ULONG*)In_KeyHandle = 0;
	}
	//�ͷ�nre�ռ�
	ExFreePool(pFileNameInfo);
	pFileNameInfo = NULL;
	return result;
}

//��ע����ֵ
NTSTATUS NTAPI Fake_ZwOpenKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	result = STATUS_SUCCESS;
	//0����ȡZwOpenKey��ԭʼ����
	ACCESS_MASK    DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	//1��������Ӧ�ò����
	if (ExGetPreviousMode())
	{
		//2����дȨ��ִ�м��
		if (KEY_READ == DesiredAccess || KEY_WRITE == DesiredAccess)
		{
			//3���������ú���
			*(ULONG*)ret_func = After_ZwOpenKey_Func;
		}
	}
	return result;
}