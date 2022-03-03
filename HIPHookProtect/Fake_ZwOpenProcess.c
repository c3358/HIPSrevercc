#include "Fake_ZwOpenProcess.h"
//记录日志：
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




	//获取时间
	szwTime = GetTimeFunction();
	RtlInitUnicodeString(&stTime, szwTime);
	RtlUnicodeStringToAnsiString(&stTimeA, &stTime, FALSE);


	//获取进程路径
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
		strcat(szBuffer + 287, "[自我保护]：打开进程");
	}
	else if (bOperate == Operate_ExitProcess)
	{
		strcat(szBuffer + 287, "[自我保护]：结束进程");
	}

	strcat(szBuffer + 307, "    ");
	strncat(szBuffer + 311, stRegditNameA.Buffer, stRegditNameA.Length);
	RtlZeroMemory(szBuffer + 311 + stRegditNameA.Length, 260 - stRegditNameA.Length);
	strcat(szBuffer + 571, "    ");
	if (bFlag == TRUE)
	{
		strcat(szBuffer + 575, "允许\r\n");
	}
	else
	{
		strcat(szBuffer + 575, "拒绝\r\n");
	}


	if (strcmp(szBuffer, szBufferTo))
	{
		HANDLE hfile;
		OBJECT_ATTRIBUTES objectAttributes;
		IO_STATUS_BLOCK iostatus;

		UNICODE_STRING logFileUnicodeString;

		//初始化UNICODE_STRING字符串
		RtlInitUnicodeString(&logFileUnicodeString,
			L"\\??\\C:\\1.log");

		//初始化objectAttributes
		InitializeObjectAttributes(&objectAttributes,
			&logFileUnicodeString,
			OBJ_CASE_INSENSITIVE,//对大小写敏感
			NULL,
			NULL);

		//打开文件
		NTSTATUS ntStatus = ZwCreateFile(&hfile,
			FILE_APPEND_DATA,		//追加写
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
		//写文件
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


//打开进程
NTSTATUS NTAPI Fake_ZwOpenProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS       Status = STATUS_SUCCESS;
	NTSTATUS       result = STATUS_SUCCESS;
	UNICODE_STRING stProcessPathName;
	RtlInitUnicodeString(&stProcessPathName, L"HIPTermintor.exe");


	//0、获取ZwOpenProcess参数
	PCLIENT_ID  In_ClientId = *(ULONG*)((ULONG)ArgArray + 0xC);
	//1、必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return result;
	}

	//如果打开的是自身被保护的进程
	if (g_OurselfProcessID == In_ClientId->UniqueProcess)
	{
		//判断是不是保护进程
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