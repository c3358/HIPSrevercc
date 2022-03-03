#include "Fake_ZwCreateFile.h"

NTSTATUS NTAPI Fake_ZwCreateFile(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	PVOID		Object = NULL;
	BOOL		bFlag = FALSE;											//�ж��ļ��Ƿ����
	BOOL		OpenOrCreat = FALSE;									//�ж��Ǵ��ļ����Ǵ����ļ���Ĭ�ϴ򿪣�
	HANDLE      FileHandle = NULL;
	HANDLE      TempRootDirectory = NULL;
	BOOLEAN     RootDirectoryFlag = NULL;								//�ͷű�ʶ��
	SYSTEM_INFORMATIONFILE System_InformationFile_XOR = { 0 };		//�ļ���Ϣ
	OBJECT_ATTRIBUTES TempObjectAttributes = { 0 };						//��ʱ����
	result = STATUS_SUCCESS;


	//0����ȡZwCreateFileԭʼ����
	IN HANDLE             In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	IN ACCESS_MASK        In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	IN POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	IN PIO_STATUS_BLOCK	  In_IoStatusBlock = *(ULONG*)((ULONG)ArgArray + 0xC);
	IN PLARGE_INTEGER	  In_AllocationSize = *(ULONG*)((ULONG)ArgArray + 0x10);
	IN ULONG			  In_FileAttributes = *(ULONG*)((ULONG)ArgArray + 0x14);
	IN ULONG			  In_ShareAccess = *(ULONG*)((ULONG)ArgArray + 0x18);
	IN ULONG			  In_CreateDisposition = *(ULONG*)((ULONG)ArgArray + 0x1C);
	//1��������Ӧ�ò����
	if (!ExGetPreviousMode())
	{
		return result;
	}





	InitializeObjectAttributes(
		&TempObjectAttributes,
		In_ObjectAttributes->ObjectName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		TempRootDirectory,
		NULL
	);
	Status = Safe_IoCreateFile(&TempObjectAttributes, &FileHandle);
	//RootDirectoryFlagΪ���ʾʹ��ObOpenObjectByPointer��ȡ�ģ������Ҫ�ͷŵ�
	if (RootDirectoryFlag)
	{
		ZwClose(TempRootDirectory);
	}
	if (Status != STATUS_GUARD_PAGE_VIOLATION)
	{
		if (NT_SUCCESS(Status))
		{
			//��ȡ�ļ���Ϣ
			Status = Safe_GetInformationFile(FileHandle, (ULONG)&System_InformationFile_XOR, KernelMode);
			//��֤�ļ���Ϣ
			if (NT_SUCCESS(Status))
			{
				//��ѯXOR�ڲ����б���
				if (Safe_QueryInformationFileList(
					System_InformationFile_XOR.IndexNumber_LowPart,
					System_InformationFile_XOR.u.IndexNumber_HighPart,
					System_InformationFile_XOR.VolumeSerialNumber))
				{
					//�ǰ���������
					if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
					{
						RecordLogFile(In_ObjectAttributes->ObjectName, FALSE, Operate_CreateFile);
						ZwClose(FileHandle);
						result = STATUS_ACCESS_DENIED;
						return result;
					}
					RecordLogFile(In_ObjectAttributes->ObjectName, TRUE, Operate_CreateFile);
				}

			}
			ZwClose(FileHandle);
		}


		result = STATUS_SUCCESS;
		return result;
	}
	result = STATUS_GUARD_PAGE_VIOLATION;
	return result;
}