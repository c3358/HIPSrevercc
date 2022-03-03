#include "Fake_ZwDeleteFile.h"


//ɾ���ļ�
NTSTATUS NTAPI Fake_ZwDeleteFile(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	PVOID		Object = NULL;
	HANDLE      FileHandle = NULL;
	HANDLE      TempRootDirectory = NULL;
	HANDLE		Handle_v4 = NULL;
	BOOLEAN     RootDirectoryFlag = FALSE;								//�ͷű�ʶ��
	SYSTEM_INFORMATIONFILE System_InformationFile_XOR = { 0 };		//�ļ���Ϣ
	OBJECT_ATTRIBUTES TempObjectAttributes = { 0 };						//��ʱ����
	result = STATUS_SUCCESS;
	//0����ȡZwDelteFileԭʼ����
	IN POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray);
	//1��������Ӧ�ò����
	if (!ExGetPreviousMode())
	{
		return result;
	}
	if (myProbeRead(In_ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(Fake_ZwDeleteFile��In_ObjectAttributes) error \r\n"));
		return 0;
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
	result = STATUS_GUARD_PAGE_VIOLATION;
	if (Status != STATUS_GUARD_PAGE_VIOLATION)
	{
		if (NT_SUCCESS(Status))
		{
			//��ȡ�ļ���Ϣ
			Status = Safe_GetInformationFile(FileHandle, (ULONG)&System_InformationFile_XOR, KernelMode);
			ZwClose(FileHandle);
			//��֤�ļ���Ϣ
			if (NT_SUCCESS(Status))
			{

				//��ѯXOR�ڲ����б���
				if (Safe_QueryInformationFileList(
					System_InformationFile_XOR.IndexNumber_LowPart,
					System_InformationFile_XOR.u.IndexNumber_HighPart,
					System_InformationFile_XOR.VolumeSerialNumber))
				{
					//�ǰ�����ֱ�Ӵ��󷵻�
					if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
					{
						RecordLogFile(In_ObjectAttributes->ObjectName, FALSE, Operate_DeleteFile);
						return STATUS_ACCESS_DENIED;
					}
					RecordLogFile(In_ObjectAttributes->ObjectName, TRUE, Operate_DeleteFile);
				}

			}
		}
		result = STATUS_SUCCESS;
		return result;
	}
	return result;
}
