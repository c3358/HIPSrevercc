#include "Fake_ZwOpenFile.h"

NTSTATUS NTAPI Fake_ZwOpenFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{

	NTSTATUS    Status = STATUS_SUCCESS;
	NTSTATUS	result = STATUS_SUCCESS;
	PVOID		Object = NULL;
	HANDLE      FileHandle = NULL;
	HANDLE      TempRootDirectory = NULL;
	HANDLE		Handle_v4 = NULL;
	BOOLEAN     RootDirectoryFlag = FALSE;								//�ͷű�ʶ��
	SYSTEM_INFORMATIONFILE System_InformationFile_XOR = { 0 };		//�ļ���Ϣ
	OBJECT_ATTRIBUTES TempObjectAttributes = { 0 };						//��ʱ����
	//0����ȡZwOpenFileԭʼ����
	HANDLE             In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	ACCESS_MASK        In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	PIO_STATUS_BLOCK   In_IoStatusBlock = *(ULONG*)((ULONG)ArgArray + 0xC);
	ULONG              In_ShareAccess = *(ULONG*)((ULONG)ArgArray + 0x10);
	ULONG              In_OpenOptions = *(ULONG*)((ULONG)ArgArray + 0x14);
	//1��������Ӧ�ò����
	if (!ExGetPreviousMode())
	{
		return result;
	}
	//2����ȡ������
	Handle_v4 = PsGetCurrentProcessId();


	//���FileHandle�ļ�������������ַ�Ϸ���
	if (myProbeRead(In_FileHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(Fake_ZwOpenFile��In_FileHandle) error \r\n"));
		return result;
	}







	//ͨ���������ƣ��õ������ں˾��
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
			//ͨ���ں˾��/��ȡ�ļ���Ϣ
			Status = Safe_GetInformationFile(FileHandle, (ULONG)&System_InformationFile_XOR, KernelMode);
			//��֤�ļ���Ϣ
			if (NT_SUCCESS(Status))
			{
				//��ѯXOR�ڲ��ڱ����б���
				if (Safe_QueryInformationFileList(
					System_InformationFile_XOR.IndexNumber_LowPart,
					System_InformationFile_XOR.u.IndexNumber_HighPart,
					System_InformationFile_XOR.VolumeSerialNumber))
				{



					//�ǰ���������
					if (!Safe_QueryWhitePID(Handle_v4) )
					{
						RecordLogFile(In_ObjectAttributes->ObjectName, FALSE, Operate_OpenFile);
						ZwClose(FileHandle);
						result = STATUS_ACCESS_DENIED;								//�ܾ�����				
						return result;
					}
					RecordLogFile(In_ObjectAttributes->ObjectName, TRUE, Operate_OpenFile);
				}



			}
			ZwClose(FileHandle);
		}
		result = STATUS_SUCCESS;
		return result;
	}
	result = STATUS_GUARD_PAGE_VIOLATION;


	return result;
	return result;
}