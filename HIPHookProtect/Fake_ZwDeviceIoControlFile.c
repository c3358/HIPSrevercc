#include "Fake_ZwDeviceIoControlFile.h"


//记录日志：网络操作
NTSTATUS RecordLogInternet(PCUNICODE_STRING stData, BOOL bFlag, BOOL bOperate)
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
	RtlUnicodeStringToAnsiString(&stRegditNameA, stData, FALSE);

	strncpy(szBuffer, stTimeA.Buffer, 19);
	strcat(szBuffer + 19, "    ");
	strncat(szBuffer + 23, stProcessFileNameA.Buffer, stProcessFileNameA.Length);
	RtlZeroMemory(szBuffer + 23 + stProcessFileNameA.Length, 260 - stProcessFileNameA.Length);

	strcat(szBuffer + 283, "    ");
	if (bOperate == Operate_SendData)
	{
		strcat(szBuffer + 287, "[网络保护]：发送数据");
	}
	else if (bOperate == Operate_RecvData)
	{
		strcat(szBuffer + 287, "[网络保护]：接收数据");
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


//IO操作
NTSTATUS NTAPI After_ZwDeviceIoControlFile_Func(IN ULONG FilterIndex, IN PVOID ArgArray, IN NTSTATUS InResult, IN PULONG RetFuncArgArray)
{
	NTSTATUS  Status, result;
	result = STATUS_SUCCESS;



	//0、获取ZwDeviceIoControlFile的原始参数
	ULONG IoControlCode = *(ULONG*)((ULONG)ArgArray + 0x14);
	PVOID InputBuffer = *(ULONG*)((ULONG)ArgArray + 0x18);
	ULONG InputBufferLength = *(ULONG*)((ULONG)ArgArray + 0x1c);


	PAFD_INFO AfdInfo = (PAFD_INFO)InputBuffer;;
	PVOID Buffer = AfdInfo->BufferArray->buf;
	ULONG Len = AfdInfo->BufferArray->len;
	if (Len >= 50)
	{
		*((BYTE*)Buffer + 50) = 0;
		Len = 50;
	}
	BYTE szBuffer[0x100] = { 0 };
	for (int i = 0; i < Len; i++)
	{
		sprintf(szBuffer + i, "%x", *((BYTE*)Buffer + i));
	}

	BYTE stBufferBuffer[0x200] = { 0 };
	ANSI_STRING stABuffer;
	UNICODE_STRING stBuffer;
	stBuffer.Buffer = stBufferBuffer;
	stBuffer.Length = 0;
	stBuffer.MaximumLength = 0x200;
	RtlInitAnsiString(&stABuffer, szBuffer);
	RtlAnsiStringToUnicodeString(&stBuffer, &stABuffer, FALSE);

	//1、判断上次调用原始函数返回值
	if (!NT_SUCCESS(InResult))
	{
		return InResult;
	}
	//检查地址合法性
	if (myProbeRead(IoControlCode, sizeof(HANDLE), sizeof(CHAR)))
	{
		return result;
	}

	if (IoControlCode == IO_AFD_SEND)
	{
		//判断是不是白进程
		if (Safe_QueryWhitePID(PsGetCurrentProcessId()))
			RecordLogInternet(&stBuffer, TRUE, Operate_SendData);
		else
		{
			RecordLogInternet(&stBuffer, FALSE, Operate_SendData);
			result = STATUS_ACCESS_DENIED;
		}
	}
	else if (IoControlCode == IO_AFD_RECV)
	{
		//判断是不是白进程
		if (Safe_QueryWhitePID(PsGetCurrentProcessId()))
			RecordLogInternet(&stBuffer, TRUE, Operate_RecvData);
		else
		{
			RecordLogInternet(&stBuffer, FALSE, Operate_RecvData);
			result = STATUS_ACCESS_DENIED;
		}
	}
	return result;
}

//IO操作
NTSTATUS NTAPI Fake_ZwDeviceIoControlFile(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	result = STATUS_SUCCESS;

	//0、获取ZwDeviceIoControlFile的原始参数
	ULONG IoControlCode = *(ULONG*)((ULONG)ArgArray + 0x14);

	//1、必须是应用层调用
	if (ExGetPreviousMode())
	{

		if (IoControlCode == IO_AFD_SEND || IoControlCode == IO_AFD_RECV)
		{
			//DbgBreakPoint();
			//3、启动调用后检查
			*(ULONG*)ret_func = After_ZwDeviceIoControlFile_Func;
		}

	}

	return result;
}

