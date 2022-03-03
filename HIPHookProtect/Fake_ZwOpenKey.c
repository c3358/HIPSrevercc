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
	BOOLEAN ErrorFlag = TRUE;				//成功1，失败0
	result = STATUS_SUCCESS;
	//0、获取ZwOpenKey原始参数
	PHANDLE   In_KeyHandle = *(ULONG*)((ULONG)ArgArray);
	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//检查地址合法性
	if (myProbeRead(In_KeyHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(After_ZwOpenKey_Func：In_KeyHandle) error \r\n"));
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
	//2、通过注册表_OBJECT指针查询注册表路径
	Status = ObQueryNameString(Object, pFileNameInfo, NumberOfBytes, &ReturnLength);
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

//打开注册表键值
NTSTATUS NTAPI Fake_ZwOpenKey(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	result = STATUS_SUCCESS;
	//0、获取ZwOpenKey的原始参数
	ACCESS_MASK    DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{
		//2、读写权限执行检查
		if (KEY_READ == DesiredAccess || KEY_WRITE == DesiredAccess)
		{
			//3、启动调用后检查
			*(ULONG*)ret_func = After_ZwOpenKey_Func;
		}
	}
	return result;
}