#include "Fake_ZwSetInformationFile.h"

NTSTATUS NTAPI Fake_ZwSetInformationFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{
	NTSTATUS       Status, result;
	PFILE_OBJECT   FileObject = NULL;
	result = STATUS_SUCCESS;
	//��ZwWriteFile���������
	IN HANDLE  In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	IN PVOID	FileInformation = *(ULONG*)((ULONG)ArgArray + 8);
	IN FILE_INFORMATION_CLASS FileInformationClass = *(ULONG*)((ULONG)ArgArray + 0x10);
	//������Ӧ�ò����
	if (!ExGetPreviousMode())
	{
		return result;
	}

	//�ж��Ƿ�Ϊɾ���ļ�
	if (FileInformationClass == FileDispositionInformation || FileInformationClass == FileDispositionInformationEx)
	{
		if (((FILE_DISPOSITION_INFORMATION*)FileInformation)->DeleteFile == FALSE)
		{
			return result;
		}
	}
	else
	{
		return result;
	}


	//�õ��ļ�����ָ��
	Status = ObReferenceObjectByHandle(In_FileHandle, FILE_ANY_ACCESS, *IoFileObjectType, UserMode, (PVOID*)&FileObject, NULL);
	//�жϲ����Ƿ�ɹ�
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	//�ж��豸�������������ļ��豸���͵�
	if ((!FileObject->DeviceObject) || !FileObject->DeviceObject->DriverObject || (FileObject->DeviceObject->DeviceType != FILE_DEVICE_DISK))
	{
		//�ر��豸���
		ObfDereferenceObject(FileObject);
		return result;
	}

	UCHAR szBuffer[0x1000] = { '\\', 0, '?', 0, '?', 0, '\\', 0 };
	UNICODE_STRING stFileName = { 0 };
	stFileName.Buffer = szBuffer;
	stFileName.Length = 8;
	stFileName.MaximumLength = 0x1000;

	//����ļ�DOS�����̷���
	UNICODE_STRING stFileDosName = { 0 };
	Status = RtlVolumeDeviceToDosName(FileObject->DeviceObject, &stFileDosName);

	if (NT_SUCCESS(Status))
	{
		if (FileObject->FileName.Length)
		{
			RtlAppendUnicodeStringToString(&stFileName, &stFileDosName);
			RtlAppendUnicodeStringToString(&stFileName, &FileObject->FileName);
			if (Safe_QueryInformationFileList_FileName(&stFileName))
			{
				//�ǰ���������
				if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
				{
					RecordLogFile(&stFileName, FALSE, Operate_DeleteFile);
					ObfDereferenceObject(FileObject);
					result = STATUS_ACCESS_DENIED;
					return result;
				}
				RecordLogFile(&stFileName, TRUE, Operate_DeleteFile);
			}

		}
	}
	ObfDereferenceObject(FileObject);
	return result;
}
