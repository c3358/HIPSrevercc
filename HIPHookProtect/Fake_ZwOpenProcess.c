#include "Fake_ZwOpenProcess.h"
//��¼��־��
NTSTATUS RecordLogOurselfProtect(PCUNICODE_STRING stProcessPathName, BOOL bFlag, BOOL bOperate)
{
	PWSTR szwTime;
	PUNICODE_STRING szwProcessFileName;
	UNICODE_STRING stTime;

	UCHAR szBuffer1[0x100] = { 0 };
	UCHAR szBuffer2[0x100] = { 0 };
	ANSI_STRING stTimeA;
	stTimeA.Buffer = szBuffer1;
	stTimeA.Length = 0;
	stTimeA.MaximumLength = 0x100;
	ANSI_STRING stProcessFileNameA;
	stProcessFileNameA.Buffer = szBuffer2;
	stProcessFileNameA.Length = 0;
	stProcessFileNameA.MaximumLength = 0x100;

	UCHAR szBuffer3[0x100] = { 0 };
	ANSI_STRING stRegditNameA;
	stRegditNameA.Buffer = szBuffer3;
	stRegditNameA.Length = 0;
	stRegditNameA.MaximumLength = 0x100;

	UCHAR szBuffer[0x300] = { 0 };
	static UCHAR szBufferTo[0x300] = { 0 };




	//��ȡʱ��
	szwTime = GetTimeFunction();
	RtlInitUnicodeString(&stTime, szwTime);
	RtlUnicodeStringToAnsiString(&stTimeA, &stTime, FALSE);


	//��ȡ����·��
	szwProcessFileName = GetCurrentProcessFileName();


	RtlUnicodeStringToAnsiString(&stProcessFileNameA, szwProcessFileName, FALSE);
	RtlUnicodeStringToAnsiString(&stRegditNameA, stProcessPathName, FALSE);

	strncpy(szBuffer, stTimeA.Buffer, 19);
	strcat(szBuffer + 19, "    ");
	strncat(szBuffer + 23, stProcessFileNameA.Buffer, stProcessFileNameA.Length);
	RtlZeroMemory(szBuffer + 23 + stProcessFileNameA.Length, 260 - stProcessFileNameA.Length);

	strcat(szBuffer + 283, "    ");
	if (bOperate == Operate_OpenProcess)
	{
		strcat(szBuffer + 287, "[���ұ���]���򿪽���");
	}
	else if (bOperate == Operate_ExitProcess)
	{
		strcat(szBuffer + 287, "[���ұ���]����������");
	}

	strcat(szBuffer + 307, "    ");
	strncat(szBuffer + 311, stRegditNameA.Buffer, stRegditNameA.Length);
	RtlZeroMemory(szBuffer + 311 + stRegditNameA.Length, 260 - stRegditNameA.Length);
	strcat(szBuffer + 571, "    ");
	if (bFlag == TRUE)
	{
		strcat(szBuffer + 575, "����\r\n");
	}
	else
	{
		strcat(szBuffer + 575, "�ܾ�\r\n");
	}


	if (strcmp(szBuffer, szBufferTo))
	{
		HANDLE hfile;
		OBJECT_ATTRIBUTES objectAttributes;
		IO_STATUS_BLOCK iostatus;

		UNICODE_STRING logFileUnicodeString;

		//��ʼ��UNICODE_STRING�ַ���
		RtlInitUnicodeString(&logFileUnicodeString,
			L"\\??\\C:\\1.log");

		//��ʼ��objectAttributes
		InitializeObjectAttributes(&objectAttributes,
			&logFileUnicodeString,
			OBJ_CASE_INSENSITIVE,//�Դ�Сд����
			NULL,
			NULL);

		//���ļ�
		NTSTATUS ntStatus = ZwCreateFile(&hfile,
			FILE_APPEND_DATA,		//׷��д
			&objectAttributes,
			&iostatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN_IF,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (!NT_SUCCESS(ntStatus))
		{
			return ntStatus;
		}
		//д�ļ�
		ntStatus = ZwWriteFile(hfile,
			NULL,
			NULL,
			NULL,
			&iostatus,
			szBuffer,
			581,
			NULL,
			NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			ZwClose(hfile);
			return ntStatus;
		}
		ZwClose(hfile);

		RtlZeroMemory(szBufferTo, 0x300);
		strcpy(szBufferTo, szBuffer);
	}

	KeSetEvent(g_pFileShowEvent, IO_NO_INCREMENT, FALSE);
	return STATUS_SUCCESS;
}


//�򿪽���
NTSTATUS NTAPI Fake_ZwOpenProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       Status = STATUS_SUCCESS;
	NTSTATUS       result = STATUS_SUCCESS;
	UNICODE_STRING stProcessPathName;
	RtlInitUnicodeString(&stProcessPathName, L"HIPTermintor.exe");


	//0����ȡZwOpenProcess����
	PCLIENT_ID  In_ClientId = *(ULONG*)((ULONG)ArgArray + 0xC);
	//1��������Ӧ�ò����
	if (!ExGetPreviousMode())
	{
		return result;
	}

	//����򿪵������������Ľ���
	if (g_OurselfProcessID == In_ClientId->UniqueProcess)
	{
		//�ж��ǲ��Ǳ�������
		if (Safe_QueryWhitePID(PsGetCurrentProcessId()))
		{

			RecordLogOurselfProtect(&stProcessPathName, TRUE, Operate_OpenProcess);
		}
		else
		{
			RecordLogOurselfProtect(&stProcessPathName, FALSE, Operate_OpenProcess);
			result = STATUS_ACCESS_DENIED;
		}
	}


	return result;
}