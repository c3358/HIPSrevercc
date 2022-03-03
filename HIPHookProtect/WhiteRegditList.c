#include "WhiteRegditList.h"




//向注册表保护列表中插入新的保护项
ULONG NTAPI Safe_InsertProtectRegditList(IN PUNICODE_STRING stRegditPath)
{
	KIRQL NewIrql = NULL;
	ULONG Index = NULL;						//数组下标索引
	ULONG result = FALSE;					//返回值
	//加锁
	NewIrql = KfAcquireSpinLock(&g_All_ProtectRegdit->SpinLock);

	//1、新增插入  白名单个数+1，成功返回TRUE，失败FALSE
	//2、已存在    无视，默认返回FALSE（失败）

	while (!g_All_ProtectRegdit->ProtectRegditNumber || RtlCompareUnicodeString(stRegditPath, &g_All_ProtectRegdit->RegditPath[Index], TRUE))
	{
		//假设是新的白名单信息就插入
		if (++Index >= g_All_ProtectRegdit->ProtectRegditNumber)
		{
			//判断是否超过最大值
			if (Index <= PROTECTREGDITMAXIMUM)
			{
				//插到最后面


				g_All_ProtectRegdit->RegditPath[g_All_ProtectRegdit->ProtectRegditNumber].Buffer = (PWCHAR)ExAllocatePool(NonPagedPool, stRegditPath->Length);
				g_All_ProtectRegdit->RegditPath[g_All_ProtectRegdit->ProtectRegditNumber].Length = 0;
				g_All_ProtectRegdit->RegditPath[g_All_ProtectRegdit->ProtectRegditNumber].MaximumLength = stRegditPath->Length;
				RtlCopyUnicodeString(&g_All_ProtectRegdit->RegditPath[g_All_ProtectRegdit->ProtectRegditNumber], stRegditPath);

				//数量自增1
				g_All_ProtectRegdit->ProtectRegditNumber++;
				//成功返回
				result = TRUE;
				break;
			}
			else
			{
				//失败返回
				result = FALSE;
				break;
			}
		}
	}
	//}
	//解锁
	KfReleaseSpinLock(&g_All_ProtectRegdit->SpinLock, NewIrql);
	return result;
}



//根据名称查询是否在注册表保护列表中
ULONG NTAPI Safe_QueryProtectRegditList_RegditName(IN PUNICODE_STRING ObjectName)
{

	KIRQL NewIrql;
	ULONG result;
	result = 0;
	//加锁
	NewIrql = KfAcquireSpinLock(&g_All_ProtectRegdit->SpinLock);
	//判断名单个数
	if (g_All_ProtectRegdit->ProtectRegditNumber)
	{
		for (ULONG Index = 0; Index < g_All_ProtectRegdit->ProtectRegditNumber; Index++)
		{
			//找到返回该数组在列表中下标
			if (!RtlCompareUnicodeString(ObjectName, &g_All_ProtectRegdit->RegditPath[Index], TRUE))
			{
				result = 1;
				break;
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_All_ProtectRegdit->SpinLock, NewIrql);
	return result;

}





//记录日志：注册表操作
NTSTATUS RecordLogRegdit(PCUNICODE_STRING stRegditName, BOOL bFlag, BOOL bOperate)
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
	RtlUnicodeStringToAnsiString(&stRegditNameA, stRegditName, FALSE);

	strncpy(szBuffer, stTimeA.Buffer, 19);
	strcat(szBuffer + 19, "    ");
	strncat(szBuffer + 23, stProcessFileNameA.Buffer, stProcessFileNameA.Length);
	RtlZeroMemory(szBuffer + 23 + stProcessFileNameA.Length, 260 - stProcessFileNameA.Length);

	strcat(szBuffer + 283, "    ");
	if (bOperate == Operate_OpenKey)
	{
		strcat(szBuffer + 287, "[注册保护]：打开注册");
	}
	else if (bOperate == Operate_DeleteKey)
	{
		strcat(szBuffer + 287, "[注册保护]：删除注册");
	}
	else if (bOperate == Operate_CreateKey)
	{
		strcat(szBuffer + 287, "[注册保护]：创建注册");
	}
	else if (bOperate == Operate_RenameKey)
	{
		strcat(szBuffer + 287, "[注册保护]：更名注册");
	}
	else if (bOperate == Operate_SetValueKey)
	{
		strcat(szBuffer + 287, "[注册保护]：设置键值");
	}
	else if (bOperate == Operate_DeleteValue)
	{
		strcat(szBuffer, "[文件保护]：删除键值");
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