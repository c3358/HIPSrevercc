#include "Fake_ZwTerminateProcess.h"

//结束进程
NTSTATUS NTAPI Fake_ZwTerminateProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       result = STATUS_SUCCESS;
	NTSTATUS       Status = STATUS_SUCCESS;
	ULONG          ReturnLength = NULL;
	PEPROCESS      pPeprocess = NULL;
	HANDLE		   hProcessID = 0;
	BOOLEAN        ObfDereferenceObjectFlag = FALSE;		//真调用ObfDereferenceObject  假则不需要
	UNICODE_STRING stProcessPathName;
	RtlInitUnicodeString(&stProcessPathName, L"HIPTermintor.exe");

	//0、获取ZwTerminateProcess原始函数
	HANDLE   In_ProcessHandle = *(ULONG*)((ULONG)ArgArray);
	NTSTATUS In_ExitStatus = *(ULONG*)((ULONG)ArgArray + 4);
	//第一种R3调用ZwTerminateProcess结束保护进程的防御措施
	//1、必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return result;
	}


	// 获取Eprocess结构
	//注意ObReferenceObjectByHandle获取的Eprocess结构需要解引用
	Status = ObReferenceObjectByHandle(In_ProcessHandle, NULL, PsProcessType, ExGetPreviousMode(), &pPeprocess, 0);
	if (!NT_SUCCESS(Status))
	{
		//获取失败直接退出
		result = STATUS_SUCCESS;
		return result;
	}
	else
	{
		//表示ObReferenceObjectByHandle函数调用成功，后续需要释放
		ObfDereferenceObjectFlag = TRUE;
		hProcessID = PsGetProcessId(pPeprocess);

	}

	//判断是否结束的是自身被保护进程的PID
	if (hProcessID == g_OurselfProcessID)
	{
		//判断是否为自身保护进程，自己结束自己
		if (PsGetCurrentProcessId() != g_OurselfProcessID)
		{
			result = STATUS_ACCESS_DENIED;
			RecordLogOurselfProtect(&stProcessPathName, FALSE, Operate_ExitProcess);
		}

	}

	//6、ObfDereferenceObjectFlag为真才需要释放，区别ObReferenceObjectByHandle or IoGetCurrentProcess方式获取的Eprocess结构
	if (ObfDereferenceObjectFlag)
	{
		ObfDereferenceObject(pPeprocess);
	}

	return result;
}