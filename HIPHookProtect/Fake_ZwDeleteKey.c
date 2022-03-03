#include "Fake_ZwDeleteKey.h"


//删除注册表值键
NTSTATUS NTAPI Fake_ZwDeleteKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	HANDLE   Object = NULL;
	POBJECT_NAME_INFORMATION pFileNameInfo = NULL;
	ULONG NumberOfBytes = 0x1024;
	ULONG ReturnLength = NULL;
	ULONG Tag = 0x206d6444u;
	BOOLEAN ErrorFlag = TRUE;				//成功1，失败0
	result = STATUS_SUCCESS;
	//获得ZwDelete参数
	HANDLE    In_KeyHandle = *(ULONG*)((ULONG)ArgArray);

	//1、必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return STATUS_SUCCESS;
	}

	//检查地址合法性
	if (myProbeRead(In_KeyHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(After_ZwOpenKey_Func：In_KeyHandle) error \r\n"));
		return result;
	}
	Status = ObReferenceObjectByHandle(In_KeyHandle, 0, 0, UserMode, &Object, 0);
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
	//2、驱动层通过注册表_OBJECT指针查询注册表路径ObQueryNameString
	Status = ObQueryNameString(Object, pFileNameInfo, NumberOfBytes, &ReturnLength);
	//解引用
	ObfDereferenceObject(Object);
	if (!NT_SUCCESS(Status) || !pFileNameInfo->Name.Buffer || !pFileNameInfo->Name.Length)
	{
		ExFreePool(pFileNameInfo);
		return result;
	}
	//3、判断是否为保护路径
	if (Safe_QueryProtectRegditList_RegditName(&pFileNameInfo->Name))
	{
		//判断是不是白进程
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
		//合法返回
		ErrorFlag = TRUE;
		result = STATUS_SUCCESS;
	}


	//失败返回要清空句柄
	if (!ErrorFlag)
	{
		Safe_ZwNtClose(*(ULONG*)In_KeyHandle, 1);
		*(ULONG*)In_KeyHandle = 0;
	}
	//释放nre空间
	ExFreePool(pFileNameInfo);
	pFileNameInfo = NULL;
	return result;
}