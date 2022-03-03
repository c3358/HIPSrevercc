/*
˵����
SystemProcessDataList��NoSystemProcessDataList����������˵������
1��
SystemProcessDataList�����ض�ϵͳ�����ļ���Ϣһ��24��
��ؽṹ��
SystemInformationList����PID��Ϣ
SYSTEM_INFORMATIONFILE_XOR�����ļ���Ϣ

2��
NoSystemProcessDataList��������ض�ϵͳ���̵������ļ���Ϣ�����0x800��
��ؽṹ��
//�����ļ��ļ���ϢУ����Ϣ
//�ļ���ϢУ���SYSTEM_INFORMATIONFILE_XOR
typedef struct _ALL_INFORMATIONFILE_CRC
{
ULONG FileNumber;									// +0   �����С�Ķ���
SYSTEM_INFORMATIONFILE_XOR FileBuff[0x2000];		// +4   ��䣬����֪���ټ�
KSPIN_LOCK	SpinLock;								// ĩβ ������
}ALL_INFORMATIONFILE_CRC, *P_ALL_INFORMATIONFILE_CRC;

P_ALL_INFORMATIONFILE_CRC g_All_InformationFile_CRC;
*/
#include "WhiteFileList.h"




//************************************     
// ��������: Safe_GetInformationFile     
// �� �� ֵ: NTSTATUS NTAPI     
// ��    ��: IN HANDLE Handle                                      [In]Ŀ¼���
// ��    ��: OUT PSYSTEM_INFORMATIONFILE_XOR System_Information    [Out]����ļ���Ϣ
// ��    ��: IN KPROCESSOR_MODE AccessMode                         [In]�û���or�ں˲�
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
	//1���жϾ���ĺϷ���4�ı���
	if (((ULONG)Handle & 3) == 3 || !Handle)// �жϾ���Ϸ���
	{
		return Status;
	}
	//2���õ��ļ�����ָ��
	Status = ObReferenceObjectByHandle(Handle, FILE_ANY_ACCESS, *IoFileObjectType, AccessMode, (PVOID*)&FileObject, NULL);
	//2��1�жϲ����Ƿ�ɹ�
	if (!NT_SUCCESS(Status) && !FileObject)
	{
		return Status;
	}
	//2��2 �ж��豸����
	if (!FileObject->DeviceObject)
	{
		//�ر��豸���
		ObfDereferenceObject(FileObject);
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	//3�����˵��ض��ļ��豸����
	DeviceType = FileObject->DeviceObject->DeviceType;
	if (DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM &&   //�����ļ�ϵͳ�豸
		DeviceType != FILE_DEVICE_DISK &&   //�����豸
		DeviceType != FILE_DEVICE_FILE_SYSTEM &&   //�ļ�ϵͳ�豸
		DeviceType != FILE_DEVICE_UNKNOWN &&   //δ֪����
		DeviceType != FILE_DEVICE_CD_ROM &&   //CD�����豸
		DeviceType != FILE_DEVICE_CD_ROM_FILE_SYSTEM &&   //CD�����ļ�ϵͳ�豸
		DeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM      //�����ļ�ϵͳ�豸
		)
	{
		if (DeviceType != FILE_DEVICE_NETWORK_REDIRECTOR)  //�����豸
		{
			//�ر��豸���
			ObfDereferenceObject(FileObject);
			Status = STATUS_UNSUCCESSFUL;
			return Status;
		}
	}
	if (DeviceType == FILE_DEVICE_MULTI_UNC_PROVIDER)	   //��UNC�豸
	{
		if (!FileObject->FileName.Buffer || !FileObject->FileName.Length)
		{
			//�ر��豸���
			ObfDereferenceObject(FileObject);
			Status = STATUS_UNSUCCESSFUL;
			return Status;
		}
	}
	//�ж�DriverName
	DriverObject = FileObject->DeviceObject->DriverObject;
	if (DriverObject)
	{
		if (_wcsnicmp(DriverObject->DriverName.Buffer, L"\\Driver\\Fastfat", 0xF) == 0)
		{
			FastfatFlag = 1;
		}
	}
	//�ر��豸���
	ObfDereferenceObject(FileObject);
	//4������KernelMode or UserMode�ж�ʹ���ĸ�����
	//��ѯ�����Ϣ
	//AccessMode == 1ִ��Safe_UserModexxx,����ZwQueryVolumeInformationFile
	Status = AccessMode ? Safe_UserMode_ZwQueryVolumeInformationFile(Handle, &StatusBlock, (PVOID)&FsInformation, sizeof(FILE_FS_VOLUME_INFORMATION), FileFsVolumeInformation, 1) : ZwQueryVolumeInformationFile(Handle, &StatusBlock, (PVOID)&FsInformation, sizeof(FILE_FS_VOLUME_INFORMATION), FileFsVolumeInformation);
	if (NT_SUCCESS(Status))
	{
		//AccessMode == 1ִ��Safe_UserModexxx,����ZwQueryInformationFile
		//��ȡ���ļ�ΨһID
		Status = AccessMode ? Safe_UserMode_ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileInformation, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, 1) : ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileInformation, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, 1);
		if (NT_SUCCESS(Status))
		{
			if ((FileInformation.IndexNumber.HighPart) || (FileInformation.IndexNumber.HighPart == FastfatFlag))
			{
				System_Information->u.IndexNumber_HighPart = FileInformation.IndexNumber.HighPart;	//����ý���Ψһ��ʶID
				System_Information->IndexNumber_LowPart = FileInformation.IndexNumber.LowPart;	    //����ý���Ψһ��ʶID
				System_Information->VolumeSerialNumber = FsInformation.VolumeSerialNumber;			//�������к����
			}
			else
			{
				//AccessMode == 1ִ��Safe_UserModexxx,����ZwQueryInformationFile
				Status = AccessMode ? Safe_UserMode_ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileBaInformation, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, 1) : ZwQueryInformationFile(Handle, &StatusBlock, (PVOID)&FileBaInformation, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, 1);
				if (NT_SUCCESS(Status))
				{
					System_Information->u.XorResult = FileBaInformation.CreationTime.LowPart ^ FileBaInformation.ChangeTime.HighPart;		//��������֭����
					System_Information->IndexNumber_LowPart = FileInformation.IndexNumber.LowPart;	//����ý���Ψһ��ʶID
					System_Information->VolumeSerialNumber = FsInformation.VolumeSerialNumber;		//�������к����
					return STATUS_SUCCESS;
				}
			}
		}
	}
	return Status;

}



//************************************     
// ��������: Safe_InsertInformationFileList     
// ����˵����������б����ļ���Ϣ  
// �� �� ֵ: ULONG NTAPI    
// ��    ��: IN ULONG IndexNumber_LowPart     [IN]���ļ�ΨһID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
// ��    ��: IN ULONG IndexNumber_HighPart    [IN]���ļ�ΨһID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
// ��    ��: IN ULONG VolumeSerialNumber      [IN]���к����      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
//************************************ 
ULONG NTAPI Safe_InsertInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber, IN PUNICODE_STRING stFilePath)
{
	KIRQL NewIrql = NULL;
	ULONG Index = NULL;						//�����±�����
	ULONG result = FALSE;					//����ֵ
	//����
	NewIrql = KfAcquireSpinLock(&g_InformationFile->SpinLock);
	//�ж���������
	if (g_InformationFile->FileListNumber < 0x2000)
	{
		//1����������  ����������+1���ɹ�����TRUE������ < 0x1FFE����ʧ��FALSE������ > 0x1FFE��
		//2���Ѵ���    ���ӣ�Ĭ�Ϸ���FALSE��ʧ�ܣ�
		while (IndexNumber_LowPart != g_InformationFile->FileBuff[Index].IndexNumber_LowPart
			&& IndexNumber_HighPart != g_InformationFile->FileBuff[Index].u.IndexNumber_HighPart
			&& VolumeSerialNumber != g_InformationFile->FileBuff[Index].VolumeSerialNumber
			)
		{
			//�������µİ�������Ϣ�Ͳ���
			if (++Index >= g_InformationFile->FileListNumber)
			{
				//�ж��Ƿ񳬹����ֵ
				if (Index <= CRCLISTNUMBER)
				{
					//�嵽�����
					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].IndexNumber_LowPart = IndexNumber_LowPart;
					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].u.IndexNumber_HighPart = IndexNumber_HighPart;
					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].VolumeSerialNumber = VolumeSerialNumber;


					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].stFilePath.Buffer = (PWCHAR)ExAllocatePool(NonPagedPool, stFilePath->Length);
					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].stFilePath.Length = 0;
					g_InformationFile->FileBuff[g_InformationFile->FileListNumber].stFilePath.MaximumLength = stFilePath->Length;
					RtlCopyUnicodeString(&g_InformationFile->FileBuff[g_InformationFile->FileListNumber].stFilePath, stFilePath);

					//��������1
					g_InformationFile->FileListNumber++;
					//�ɹ�����
					result = TRUE;
					break;
				}
				else
				{
					//ʧ�ܷ���
					result = FALSE;
					break;
				}
			}
		}
	}
	//����
	KfReleaseSpinLock(&g_InformationFile->SpinLock, NewIrql);
	return result;
}

//************************************     
// ��������: Safe_DeleteInformationFileList     
// ����˵����ɾ�����б����ļ���Ϣ 
// �� �� ֵ: ULONG NTAPI    
// ��    ��: IN ULONG IndexNumber_LowPart     [IN]���ļ�ΨһID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
// ��    ��: IN ULONG IndexNumber_HighPart    [IN]���ļ�ΨһID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
// ��    ��: IN ULONG VolumeSerialNumber      [IN]���к����      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
//************************************  
ULONG NTAPI Safe_DeleteInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber)
{
	KIRQL NewIrql = NULL;
	ULONG result = TRUE;					//����ֵ
	//����
	NewIrql = KfAcquireSpinLock(&g_InformationFile->SpinLock);
	//�ж���������
	if (g_InformationFile->FileListNumber)
	{
		for (ULONG Index = 0; Index < g_InformationFile->FileListNumber; Index++)
		{
			//�ҵ����ظ��������б����±�
			if (
				IndexNumber_LowPart == g_InformationFile->FileBuff[Index].IndexNumber_LowPart
				&& IndexNumber_HighPart == g_InformationFile->FileBuff[Index].u.IndexNumber_HighPart
				&& VolumeSerialNumber == g_InformationFile->FileBuff[Index].VolumeSerialNumber
				)
			{
				//����˳����̵���Ϣ(��һ����ǰŲ)
				for (ULONG i = Index; i <= g_InformationFile->FileListNumber;i++)
				{
					g_InformationFile->FileBuff[i].IndexNumber_LowPart = g_InformationFile->FileBuff[i + 1].IndexNumber_LowPart;
					g_InformationFile->FileBuff[i].u.IndexNumber_HighPart = g_InformationFile->FileBuff[i + 1].u.IndexNumber_HighPart;
					g_InformationFile->FileBuff[i].VolumeSerialNumber = g_InformationFile->FileBuff[i + 1].VolumeSerialNumber;
				}
				//����-1
				g_InformationFile->FileListNumber--;
				break;
			}
		}
	}
	//����
	KfReleaseSpinLock(&g_InformationFile->SpinLock, NewIrql);
	return result;
}

//************************************     
// ��������: Safe_QueryInformationFileList     
// ����˵�������Ҹ��ļ���Ϣ�Ƿ����б��У��ҵ�����1��ʧ�ܷ���0  
// �� �� ֵ: ULONG NTAPI    �ҵ�����1���Ҳ�������0  
// ��    ��: IN ULONG IndexNumber_LowPart     [IN]���ļ�ΨһID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
// ��    ��: IN ULONG IndexNumber_HighPart    [IN]���ļ�ΨһID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
// ��    ��: IN ULONG VolumeSerialNumber      [IN]���к����      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
//************************************  
ULONG NTAPI Safe_QueryInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber)
{
	KIRQL NewIrql;
	ULONG result;
	ULONG GotoFalg;							//����ͬgoto���õ�Falg
	result = 0;
	//����
	NewIrql = KfAcquireSpinLock(&g_InformationFile->SpinLock);
	//�ж���������
	if (g_InformationFile->FileListNumber)
	{
		for (ULONG Index = 0; Index < g_InformationFile->FileListNumber; Index++)
		{
			//�ҵ����ظ��������б����±�
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
	//����
	KfReleaseSpinLock(&g_InformationFile->SpinLock, NewIrql);
	return result;
}







//************************************     
// ��������: Safe_QueryInformationFileList_Name     
// ����˵���������ļ��������Ʋ����Ƿ����б���  
// �� �� ֵ: ULONG NTAPI    �ҵ�����1���Ҳ�������0  
// ��    ��: IN PUNICODE_STRING ObjectName  �ļ���������
//************************************  
ULONG NTAPI Safe_QueryInformationFileList_Name(IN PUNICODE_STRING ObjectName)
{
	HANDLE FileHandle = NULL;
	ULONG Result = NULL;
	HANDLE Pid = NULL;
	NTSTATUS Status = NULL;
	SYSTEM_INFORMATIONFILE System_InformationFile_XOR = { 0 };			//�ļ���Ϣ
	// 1. ��ʼ��OBJECT_ATTRIBUTES������
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	ULONG             ulAttributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	InitializeObjectAttributes(
		&ObjectAttributes,								 // ���س�ʼ����ϵĽṹ��
		ObjectName,										 // �ļ���������
		ulAttributes,									 // ��������
		NULL, NULL);									 // һ��ΪNULL
	Pid = PsGetCurrentProcessId();
	//�ǰ��������̼���
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
			//��ȡ�ļ���Ϣ
			Status = Safe_GetInformationFile(FileHandle, (ULONG)&System_InformationFile_XOR, KernelMode);
			if (NT_SUCCESS(Status))
			{
				//��ѯXOR�ڲ����б���
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
	//����
	NewIrql = KfAcquireSpinLock(&g_InformationFile->SpinLock);
	//�ж���������
	if (g_InformationFile->FileListNumber)
	{
		for (ULONG Index = 0; Index < g_InformationFile->FileListNumber; Index++)
		{
			//�ҵ����ظ��������б����±�
			if (!RtlCompareUnicodeString(ObjectName, &g_InformationFile->FileBuff[Index].stFilePath, TRUE))
			{
				result = 1;
				break;
			}
		}
	}
	//����
	KfReleaseSpinLock(&g_InformationFile->SpinLock, NewIrql);
	return result;

}





//���ļ�������������ļ�
NTSTATUS Safe_AddFileWhiteList(PCUNICODE_STRING stFileName)
{

	NTSTATUS Status;
	HANDLE hFile1 = NULL;
	OBJECT_ATTRIBUTES stAttributes = { 0 };
	IO_STATUS_BLOCK stBlock = { 0 };
	SYSTEM_INFORMATIONFILE System_InformationFile_XOR = { 0 };							//�ļ���Ϣ


	InitializeObjectAttributes(
		&stAttributes,
		stFileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	Status = ZwOpenFile(&hFile1, GENERIC_ALL, &stAttributes, &stBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
	if (NT_SUCCESS(Status))
	{

		Safe_GetInformationFile(hFile1, (ULONG)&System_InformationFile_XOR, KernelMode);	//��ȡ�ļ���Ϣ
		if (Safe_InsertInformationFileList(													//�򱻱����ļ��б�������ļ�
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


//��¼��־���ļ�����
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




	//��ȡʱ��
	szwTime = GetTimeFunction();
	RtlInitUnicodeString(&stTime, szwTime);
	RtlUnicodeStringToAnsiString(&stTimeA, &stTime, FALSE);


	//��ȡ����·��
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
		strcat(szBuffer + 287, "[�ļ�����]��ɾ���ļ�");
	}
	else if (bOperate == Operate_WriteFile)
	{
		strcat(szBuffer + 287, "[�ļ�����]��д���ļ�");
	}
	else if (bOperate == Operate_ReadFile)
	{
		strcat(szBuffer + 287, "[�ļ�����]����ȡ�ļ�");
	}
	else if (bOperate == Operate_CreateFile)
	{
		strcat(szBuffer + 287, "[�ļ�����]�����ļ�");
	}
	else if (bOperate == Operate_OpenFile)
	{
		strcat(szBuffer + 287, "[�ļ�����]�����ļ�");
	}
	else if (bOperate == Operate_SetInformationFile)
	{
		strcat(szBuffer, "[�ļ�����]��ɾ���ļ�");
	}
	strcat(szBuffer + 307, "    ");
	strncat(szBuffer + 311, stFileNameA.Buffer, stFileNameA.Length);
	RtlZeroMemory(szBuffer + 311 + stFileNameA.Length, 260 - stFileNameA.Length);
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