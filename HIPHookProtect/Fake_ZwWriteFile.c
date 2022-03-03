#include "Fake_ZwWriteFile.h"

NTSTATUS NTAPI Fake_ZwWriteFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{
	NTSTATUS       Status, result;
	PFILE_OBJECT   FileObject = NULL;
	result = STATUS_SUCCESS;
	//��ZwWriteFile���������
	IN HANDLE  In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	IN PVOID   In_ApcContext = *(ULONG*)((ULONG)ArgArray + 0xC);
	//1��������Ӧ�ò����
	if (!ExGetPreviousMode())
	{
		return result;
	}
	

	//1���õ��ļ�����ָ��
	Status = ObReferenceObjectByHandle(In_FileHandle, FILE_ANY_ACCESS, *IoFileObjectType, UserMode, (PVOID*)&FileObject, NULL);
	//1��1�жϲ����Ƿ�ɹ�
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	//2 �ж��豸�������������ļ��豸���͵�
	if ((!FileObject->DeviceObject) || (!FileObject->DeviceObject->DriverObject) || (FileObject->DeviceObject->DeviceType != FILE_DEVICE_DISK))
	{
		//�ر��豸���
		ObfDereferenceObject(FileObject);
		return result;
	}


	UCHAR szBuffer[0x200] = { '\\', 0, '?', 0, '?', 0, '\\', 0 };
	UNICODE_STRING stFileName = { 0 };
	stFileName.Buffer = szBuffer;
	stFileName.Length = 8;
	stFileName.MaximumLength = 0x200;



	//����ļ�DOS�����̷���
	UNICODE_STRING stFileDosName = { 0 };
	Status = RtlVolumeDeviceToDosName(FileObject->DeviceObject, &stFileDosName);

	if (NT_SUCCESS(Status))
	{
		if (FileObject->FileName.Length && FileObject->FileName.Buffer)
		{
			RtlAppendUnicodeStringToString(&stFileName, &stFileDosName);
			RtlAppendUnicodeStringToString(&stFileName, &FileObject->FileName);
			if (Safe_QueryInformationFileList_FileName(&stFileName))
			{
				ObfDereferenceObject(FileObject);
				//�ǰ�����ֱ�Ӵ��󷵻�
				if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
				{
					RecordLogFile(&stFileName, FALSE, Operate_WriteFile);
					return STATUS_ACCESS_DENIED;
				}
				RecordLogFile(&stFileName, TRUE, Operate_WriteFile);
			}

		}

	}

	ObfDereferenceObject(FileObject);
	return result;
}

//��ȡIoGetDiskDeviceObject������ַ�������øú���
NTSTATUS NTAPI Safe_IoGetDiskDeviceObjectPrt(PDEVICE_OBJECT FileSystemDeviceObject, PDEVICE_OBJECT* DiskDeviceObject)
{
	NTSTATUS       Status;
	UNICODE_STRING IoGetDiskDeviceObjectString;
	NTSTATUS(*IoGetDiskDeviceObjectPtr)(PDEVICE_OBJECT FileSystemDeviceObject, PDEVICE_OBJECT * DiskDeviceObject);
	//1���ж��ǲ��ǵ�һ�ν�ȥ���������MmGetSystemRoutineAddress��ʽ��ȡIoGetDiskDeviceObject������ַ����������
	IoGetDiskDeviceObjectPtr = (ULONG)MmGetSystemRoutineAddress(&IoGetDiskDeviceObjectString);;

	//��ȡʧ��ֱ�ӷ���
	if (!IoGetDiskDeviceObjectPtr)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	
	//2������IoGetDiskDeviceObject����
	Status = IoGetDiskDeviceObjectPtr(FileSystemDeviceObject, DiskDeviceObject);
	return Status;
}
