/*
说明：
SystemProcessDataList跟NoSystemProcessDataList很相似这里说下区别：
1、
SystemProcessDataList保存特定系统进程文件信息一共24个
相关结构：
SystemInformationList保存PID信息
SYSTEM_INFORMATIONFILE_XOR保存文件信息

2、
NoSystemProcessDataList保存除了特定系统进程的所有文件信息，最大0x800组
相关结构：
//保存文件文件信息校验信息
//文件信息校验的SYSTEM_INFORMATIONFILE_XOR
typedef struct _ALL_INFORMATIONFILE_CRC
{
ULONG FileNumber;									// +0   保存大小的东西
SYSTEM_INFORMATIONFILE_XOR FileBuff[0x2000];		// +4   填充，后续知道再加
KSPIN_LOCK	SpinLock;								// 末尾 自旋锁
}ALL_INFORMATIONFILE_CRC, *P_ALL_INFORMATIONFILE_CRC;

P_ALL_INFORMATIONFILE_CRC g_All_InformationFile_CRC;
*/
#include "WhiteFileList.h"




//************************************     
// 函数名称: Safe_GetInformationFile     
// 返 回 值: NTSTATUS NTAPI     
// 参    数: IN HANDLE Handle                                      [In]目录句柄
// 参    数: OUT PSYSTEM_INFORMATIONFILE_XOR System_Information    [Out]输出文件信息
// 参    数: IN KPROCESSOR_MODE AccessMode                         [In]用户层or内核层
//************************************  
NTSTATUS NTAPI Safe_GetInformationFile(IN HANDLE Handle, OUT PSYSTEM_INFORMATIONFILE System_Information, IN KPROCESSOR_MODE AccessMode)
{
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK StatusBlock = { 0 };
	PFILE_OBJECT    FileObject = NULL;
	ULONG			DeviceType = 0;
	ULONG           FastfatFlag = 0;
	FILE_FS_VOLUME_INFORMATION FsInformation = { 0 };
	FILE_INTERNAL_INFORMATION  FileInformation = { 0 };
	FILE_BASIC_INFORMATION	   FileBaInformation = { 0 };
	struct _DRIVER_OBJECT* DriverObject;
	//1、判断句柄的合法性4的倍数
	if (((ULONG)Handle & 3) == 3 || !Handle)// 判断句柄合法性
	{
		return Status;
	}
	//2、得到文件对象指针
	Status = ObReferenceObjectByHandle(Handle, FILE_ANY_ACCESS, *IoFileObjectType, AccessMode, (PVOID*)&FileObject, NULL);
	//2、1判断操作是否成功
	if (!NT_SUCCESS(Status) && !FileObject)
	{
		return Status;
	}
	//2、2 判断设备对象
	if (!FileObject->DeviceObject)
	{
		//关闭设备句柄
		ObfDereferenceObject(FileObject);
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	//3、过滤掉特定文件设备类型
	DeviceType = FileObject->DeviceObject->DeviceType;
	if (DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM &&   //磁盘文件系统设备
		DeviceType != FILE_DEVICE_DISK &&   //磁盘设备
		DeviceType != FILE_DEVICE_FILE_SYSTEM &&   //文件系统设备
		DeviceType != FILE_DEVICE_UNKNOWN &&   //未知类型
		DeviceType != FILE_DEVICE_CD_ROM &&   //CD光驱设备
		DeviceType != FILE_DEVICE_CD_ROM_FILE_SYSTEM &&   //CD光驱文件系统设备
		DeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM      //网络文件系统设备
		)
	{
		if (DeviceType != FILE_DEVICE_NETWORK_REDIRECTOR)  //网卡设备
		{
			//关闭设备句柄
			ObfDereferenceObject(FileObject);
			Status = STATUS_UNSUCCESSFUL;
			return Status;
		}
	}
	if (DeviceType == FILE_DEVICE_MULTI_UNC_PROVIDER)	   //多UNC设备
	{
		if (!FileObject->FileName.Buffer || !FileObject->FileName.Length)
		{
			//关闭设备句柄
			ObfDereferenceObject(FileObject);
			Status = STATUS_UNSUCCESSFUL;
			return Status;
		}
	}
	//判断DriverName
	DriverObject = FileObject->DeviceObject->DriverObject;
	if (DriverObject)
	{
		if (_wcsnicmp(DriverObject->DriverName.Buffer, L"\\Driver\\Fastfat", 0xF) == 0)
		{
			FastfatFlag = 1;
		}
	}
	//关闭设备句柄
	ObfDereferenceObject(FileObject);
	//4、根据KernelMode or UserMode判断使用哪个函数
	//查询卷的信息
	//AccessMode == 1执行Safe_UserModexxx,否则ZwQueryVolumeInformationFile
	Status = AccessMode ? Safe_UserMode_ZwQueryVolumeInformationFile(Handle, &StatusBlock, (PVOID)&FsInformation, sizeof(FILE_FS_VOLUME_INFORMATION), FileFsVolumeInformation, 1) : ZwQueryVolumeInformationFile(Handle, &StatusBlock, (PVOID)&FsInformation, sizeof(FILE_FS_VOLUME_INFORMATION), FileFsVolumeInformation);
	if (NT_SUCCESS(Status))
	{
		//AccessMode == 1执行Safe_UserModexxx,否则ZwQueryInformationFile
		//获取该文件唯一ID
		Status = AccessMode ? Safe_UserMode_ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileInformation, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, 1) : ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileInformation, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, 1);
		if (NT_SUCCESS(Status))
		{
			if ((FileInformation.IndexNumber.HighPart) || (FileInformation.IndexNumber.HighPart == FastfatFlag))
			{
				System_Information->u.IndexNumber_HighPart = FileInformation.IndexNumber.HighPart;	//保存该进程唯一标识ID
				System_Information->IndexNumber_LowPart = FileInformation.IndexNumber.LowPart;	    //保存该进程唯一标识ID
				System_Information->VolumeSerialNumber = FsInformation.VolumeSerialNumber;			//保存序列号体积
			}
			else
			{
				//AccessMode == 1执行Safe_UserModexxx,否则ZwQueryInformationFile
				Status = AccessMode ? Safe_UserMode_ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileBaInformation, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, 1) : ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileBaInformation, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, 1);
				if (NT_SUCCESS(Status))
				{
					System_Information->u.XorResult = FileBaInformation.CreationTime.LowPart ^ FileBaInformation.ChangeTime.HighPart;		//看不懂蜜汁操作
					System_Information->IndexNumber_LowPart = FileInformation.IndexNumber.LowPart;	//保存该进程唯一标识ID
					System_Information->VolumeSerialNumber = FsInformation.VolumeSerialNumber;		//保存序列号体积
					return STATUS_SUCCESS;
				}
			}
		}
	}
	return Status;

}



//************************************     
// 函数名称: Safe_InsertInformationFileList     
// 函数说明：插入该列表中文件信息  
// 返 回 值: ULONG NTAPI    
// 参    数: IN ULONG IndexNumber_LowPart     [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
// 参    数: IN ULONG IndexNumber_HighPart    [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
// 参    数: IN ULONG VolumeSerialNumber      [IN]序列号体积      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
//************************************ 
ULONG NTAPI Safe_InsertInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber, IN PUNICODE_STRING stFilePath)
{
	KIRQL NewIrql = NULL;
	ULONG Index = NULL;						//数组下标索引
	ULONG result = FALSE;					//返回值
	//加锁
	NewIrql = KfAcquireSpinLock(&g_InformationFile->SpinLock);
	//判断名单个数
	if (g_InformationFile->FileListNumber < 0x2000)
	{
		//1、新增插入  白名单个数+1，成功返回TRUE（个数 < 0x1FFE），失败FALSE（个数 > 0x1FFE）
		//2、已存在    无视，默认返回FALSE（失败）
		while (IndexNumber_LowPart != g_InformationFile->FileBuff[Index].IndexNumber_LowPart
			&& IndexNumber_HighPart != g_InformationFile->FileBuff[Index].u.IndexNumber_HighPart
			&& VolumeSerialNumber != g_InformationFile->FileBuff[Index].VolumeSerialNumber
			)
		{
			//假设是新的白名单信息就插入
			if (++Index >= g_InformationFile->FileListNumber)
			{
				//判断是否超过最大值
				if (Index <= CRCLISTNUMBER)
				{
					//插到最后面
					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].IndexNumber_LowPart = IndexNumber_LowPart;
					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].u.IndexNumber_HighPart = IndexNumber_HighPart;
					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].VolumeSerialNumber = VolumeSerialNumber;


					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].stFilePath.Buffer = (PWCHAR)ExAllocatePool(NonPagedPool, stFilePath->Length);
					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].stFilePath.Length = 0;
					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].stFilePath.MaximumLength = stFilePath->Length;
					RtlCopyUnicodeString(&g_InformationFile->FileBuff[g_InformationFile->FileListNumber].stFilePath, stFilePath);

					//数量自增1
					g_InformationFile->FileListNumber++;
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
	}
	//解锁
	KfReleaseSpinLock(&g_InformationFile->SpinLock, NewIrql);
	return result;
}

//************************************     
// 函数名称: Safe_DeleteInformationFileList     
// 函数说明：删除该列表中文件信息 
// 返 回 值: ULONG NTAPI    
// 参    数: IN ULONG IndexNumber_LowPart     [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
// 参    数: IN ULONG IndexNumber_HighPart    [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
// 参    数: IN ULONG VolumeSerialNumber      [IN]序列号体积      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
//************************************  
ULONG NTAPI Safe_DeleteInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber)
{
	KIRQL NewIrql = NULL;
	ULONG result = TRUE;					//返回值
	//加锁
	NewIrql = KfAcquireSpinLock(&g_InformationFile->SpinLock);
	//判断名单个数
	if (g_InformationFile->FileListNumber)
	{
		for (ULONG Index = 0; Index < g_InformationFile->FileListNumber; Index++)
		{
			//找到返回该数组在列表中下标
			if (
				IndexNumber_LowPart == g_InformationFile->FileBuff[Index].IndexNumber_LowPart
				&& IndexNumber_HighPart == g_InformationFile->FileBuff[Index].u.IndexNumber_HighPart
				&& VolumeSerialNumber == g_InformationFile->FileBuff[Index].VolumeSerialNumber
				)
			{
				//清空退出进程的信息(后一个往前挪)
				for (ULONG i = Index; i <= g_InformationFile->FileListNumber;i++)
				{
					g_InformationFile->FileBuff[i].IndexNumber_LowPart = g_InformationFile->FileBuff[i + 1].IndexNumber_LowPart;
					g_InformationFile->FileBuff[i].u.IndexNumber_HighPart = g_InformationFile->FileBuff[i + 1].u.IndexNumber_HighPart;
					g_InformationFile->FileBuff[i].VolumeSerialNumber = g_InformationFile->FileBuff[i + 1].VolumeSerialNumber;
				}
				//数量-1
				g_InformationFile->FileListNumber--;
				break;
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_InformationFile->SpinLock, NewIrql);
	return result;
}

//************************************     
// 函数名称: Safe_QueryInformationFileList     
// 函数说明：查找该文件信息是否在列表中，找到返回1，失败返回0  
// 返 回 值: ULONG NTAPI    找到返回1，找不到返回0  
// 参    数: IN ULONG IndexNumber_LowPart     [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
// 参    数: IN ULONG IndexNumber_HighPart    [IN]该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
// 参    数: IN ULONG VolumeSerialNumber      [IN]序列号体积      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
//************************************  
ULONG NTAPI Safe_QueryInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber)
{
	KIRQL NewIrql;
	ULONG result;
	ULONG GotoFalg;							//不想同goto设置的Falg
	result = 0;
	//加锁
	NewIrql = KfAcquireSpinLock(&g_InformationFile->SpinLock);
	//判断名单个数
	if (g_InformationFile->FileListNumber)
	{
		for (ULONG Index = 0; Index < g_InformationFile->FileListNumber; Index++)
		{
			//找到返回该数组在列表中下标
			if (
				IndexNumber_LowPart == g_InformationFile->FileBuff[Index].IndexNumber_LowPart
				&& IndexNumber_HighPart == g_InformationFile->FileBuff[Index].u.IndexNumber_HighPart
				&& VolumeSerialNumber == g_InformationFile->FileBuff[Index].VolumeSerialNumber
				)
			{
				result = 1;
				break;
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_InformationFile->SpinLock, NewIrql);
	return result;
}







//************************************     
// 函数名称: Safe_QueryInformationFileList_Name     
// 函数说明：根据文件对象名称查找是否在列表中  
// 返 回 值: ULONG NTAPI    找到返回1，找不到返回0  
// 参    数: IN PUNICODE_STRING ObjectName  文件对象名称
//************************************  
ULONG NTAPI Safe_QueryInformationFileList_Name(IN PUNICODE_STRING ObjectName)
{
	HANDLE FileHandle = NULL;
	ULONG Result = NULL;
	HANDLE Pid = NULL;
	NTSTATUS Status = NULL;
	SYSTEM_INFORMATIONFILE System_InformationFile_XOR = { 0 };			//文件信息
	// 1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	ULONG             ulAttributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	InitializeObjectAttributes(
		&ObjectAttributes,								 // 返回初始化完毕的结构体
		ObjectName,										 // 文件对象名称
		ulAttributes,									 // 对象属性
		NULL, NULL);									 // 一般为NULL
	Pid = PsGetCurrentProcessId();
	//非白名单进程继续
	if (!Safe_QueryWhitePID(Pid))
	{
		Status = Safe_IoCreateFile(&ObjectAttributes, &FileHandle);
		if (Status == STATUS_GUARD_PAGE_VIOLATION)
		{
			Result = 1;
			return Result;
		}
		if (NT_SUCCESS(Status))
		{
			//获取文件信息
			Status = Safe_GetInformationFile(FileHandle, (ULONG)&System_InformationFile_XOR, KernelMode);
			if (NT_SUCCESS(Status))
			{
				//查询XOR在不在列表中
				if (Safe_QueryInformationFileList(
					System_InformationFile_XOR.IndexNumber_LowPart,
					System_InformationFile_XOR.u.IndexNumber_HighPart,
					System_InformationFile_XOR.VolumeSerialNumber))
				{
					Result = 1;
				}
			}
			ZwClose(FileHandle);
		}
	}
	return Result;
}

ULONG NTAPI Safe_QueryInformationFileList_FileName(IN PUNICODE_STRING ObjectName)
{

	KIRQL NewIrql;
	ULONG result;
	result = 0;
	//加锁
	NewIrql = KfAcquireSpinLock(&g_InformationFile->SpinLock);
	//判断名单个数
	if (g_InformationFile->FileListNumber)
	{
		for (ULONG Index = 0; Index < g_InformationFile->FileListNumber; Index++)
		{
			//找到返回该数组在列表中下标
			if (!RtlCompareUnicodeString(ObjectName, &g_InformationFile->FileBuff[Index].stFilePath, TRUE))
			{
				result = 1;
				break;
			}
		}
	}
	//解锁
	KfReleaseSpinLock(&g_InformationFile->SpinLock, NewIrql);
	return result;

}





//向文件白名单中添加文件
NTSTATUS Safe_AddFileWhiteList(PCUNICODE_STRING stFileName)
{

	NTSTATUS Status;
	HANDLE hFile1 = NULL;
	OBJECT_ATTRIBUTES stAttributes = { 0 };
	IO_STATUS_BLOCK stBlock = { 0 };
	SYSTEM_INFORMATIONFILE System_InformationFile_XOR = { 0 };							//文件信息


	InitializeObjectAttributes(
		&stAttributes,
		stFileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	Status = ZwOpenFile(&hFile1, GENERIC_ALL, &stAttributes, &stBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
	if (NT_SUCCESS(Status))
	{

		Safe_GetInformationFile(hFile1, (ULONG)&System_InformationFile_XOR, KernelMode);	//获取文件信息
		if (Safe_InsertInformationFileList(													//向被保护文件列表中添加文件
			System_InformationFile_XOR.IndexNumber_LowPart,
			System_InformationFile_XOR.u.IndexNumber_HighPart,
			System_InformationFile_XOR.VolumeSerialNumber,
			stFileName))
		{
			ZwClose(hFile1);
			return STATUS_SUCCESS;
		}

		ZwClose(hFile1);
	}

	return STATUS_INVALID_PARAMETER;
}


//记录日志：文件操作
NTSTATUS RecordLogFile(PCUNICODE_STRING stFileName, BOOL bFlag, BOOL bOperate)
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
	ANSI_STRING stFileNameA;
	stFileNameA.Buffer = szBuffer3;
	stFileNameA.Length = 0;
	stFileNameA.MaximumLength = 0x100;

	UCHAR szBuffer[0x300] = { 0 };
	static UCHAR szBufferTo[0x300] = { 0 };




	//获取时间
	szwTime = GetTimeFunction();
	RtlInitUnicodeString(&stTime, szwTime);
	RtlUnicodeStringToAnsiString(&stTimeA, &stTime, FALSE);


	//获取进程路径
	szwProcessFileName = GetCurrentProcessFileName();


	RtlUnicodeStringToAnsiString(&stProcessFileNameA, szwProcessFileName, FALSE);
	RtlUnicodeStringToAnsiString(&stFileNameA, stFileName, FALSE);

	strncpy(szBuffer, stTimeA.Buffer, 19);
	strcat(szBuffer + 19, "    ");
	strncat(szBuffer + 23, stProcessFileNameA.Buffer, stProcessFileNameA.Length);
	RtlZeroMemory(szBuffer + 23 + stProcessFileNameA.Length, 260 - stProcessFileNameA.Length);

	strcat(szBuffer + 283, "    ");
	if (bOperate == Operate_DeleteFile)
	{
		strcat(szBuffer + 287, "[文件保护]：删除文件");
	}
	else if (bOperate == Operate_WriteFile)
	{
		strcat(szBuffer + 287, "[文件保护]：写入文件");
	}
	else if (bOperate == Operate_ReadFile)
	{
		strcat(szBuffer + 287, "[文件保护]：读取文件");
	}
	else if (bOperate == Operate_CreateFile)
	{
		strcat(szBuffer + 287, "[文件保护]：打开文件");
	}
	else if (bOperate == Operate_OpenFile)
	{
		strcat(szBuffer + 287, "[文件保护]：打开文件");
	}
	else if (bOperate == Operate_SetInformationFile)
	{
		strcat(szBuffer, "[文件保护]：删除文件");
	}
	strcat(szBuffer + 307, "    ");
	strncat(szBuffer + 311, stFileNameA.Buffer, stFileNameA.Length);
	RtlZeroMemory(szBuffer + 311 + stFileNameA.Length, 260 - stFileNameA.Length);
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