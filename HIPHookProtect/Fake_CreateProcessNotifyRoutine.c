#include "Fake_CreateProcessNotifyRoutine.h"

extern _INTERCEPT_PROCESS g_InterceptProcessData;




//��ý�������·��
BOOLEAN GetProcPath(IN HANDLE PID, OUT PANSI_STRING pImageName)
{
	NTSTATUS status;
	HANDLE hProcess = NULL;
	CLIENT_ID clientid;
	OBJECT_ATTRIBUTES ObjectAttributes;
	ULONG returnedLength;
	ULONG bufferLength;
	PVOID buffer;
	PUNICODE_STRING imageName;




	InitializeObjectAttributes(&ObjectAttributes, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
	clientid.UniqueProcess = PID;
	clientid.UniqueThread = 0;
	//ͨ��PID��ý��̾��
	ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientid);

	//��ô�С
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		NULL, // buffer
		0, // buffer size
		&returnedLength);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return FALSE;
	}

	bufferLength = returnedLength - sizeof(UNICODE_STRING);

	buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, 'ipgD');

	if (buffer == NULL)
	{
		return FALSE;
	}


	//����ļ�������
	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, buffer, returnedLength, &returnedLength);
	imageName = (PUNICODE_STRING)buffer;


	RtlUnicodeStringToAnsiString(pImageName, imageName, FALSE);
	ExFreePool(buffer);
}


NTSTATUS NTAPI Fake_CreateProcessNotifyRoutine(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{
	PEPROCESS	Process;
	NTSTATUS	status;
	HANDLE      ProcessHandle;
	CLIENT_ID   ClientId;
	ULONG       SafeModIndex = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	//PROCESS_SESSION_INFORMATION SessionInfo;
	UCHAR ImageFileNameBuff[0x256] = { 0 };
	ProcessHandle = NULL;
	IN HANDLE In_ParentId = *(ULONG*)((ULONG)ArgArray);
	IN HANDLE In_ProcessId = *(ULONG*)((ULONG)ArgArray + 4);
	IN BOOLEAN In_Create = *(ULONG*)((ULONG)ArgArray + 8);





	UCHAR szBuffer[0x200] = { 0 };
	ANSI_STRING stProcFullPath = { 0 };
	stProcFullPath.Buffer = szBuffer;
	stProcFullPath.MaximumLength = 0x200;
	//��CreateΪTrueʱ���������´����Ľ��̣�ProcessId���ָ�����ĳ�ʼ���̱߳������󱻵��á�
	if (In_Create)
	{
		//DbgBreakPoint();
		status = PsLookupProcessByProcessId(In_ProcessId, &Process);
		GetProcPath(In_ProcessId, &stProcFullPath);

		if (NT_SUCCESS(status))
		{

			RtlZeroMemory(&g_InterceptProcessData, sizeof(_INTERCEPT_PROCESS));
			g_InterceptProcessData.bCreate = In_Create;
			g_InterceptProcessData.hParentId = In_ParentId;
			g_InterceptProcessData.hProcessId = In_ProcessId;
			strncpy(g_InterceptProcessData.ProcFullPath, stProcFullPath.Buffer, stProcFullPath.Length);

			//֪ͨӦ�ò�
			KeSetEvent(g_pProcessInterceptEvent, IO_NO_INCREMENT, FALSE);
		}
		return STATUS_SUCCESS;
	}
	else
	{
		//���̽������н���Ӱ�������ɾ��(��Ӧ��Ӧ�ò�Ĳ���ûд)
		Safe_DeleteWhiteList_PID(In_ProcessId);
		return STATUS_SUCCESS;
	}
}