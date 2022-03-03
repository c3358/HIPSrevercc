#include "Fake_ZwSetInformationFile.h"

NTSTATUS NTAPI Fake_ZwSetInformationFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{
	NTSTATUS       Status, result;
	PFILE_OBJECT   FileObject = NULL;
	result = STATUS_SUCCESS;
	//将ZwWriteFile参数提出来
	IN HANDLE  In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	IN PVOID	FileInformation = *(ULONG*)((ULONG)ArgArray + 8);
	IN FILE_INFORMATION_CLASS FileInformationClass = *(ULONG*)((ULONG)ArgArray + 0x10);
	//必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return result;
	}

	//判断是否为删除文件
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


	//得到文件对象指针
	Status = ObReferenceObjectByHandle(In_FileHandle, FILE_ANY_ACCESS, *IoFileObjectType, UserMode, (PVOID*)&FileObject, NULL);
	//判断操作是否成功
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	//判断设备对象、驱动对象，文件设备类型等
	if ((!FileObject->DeviceObject) || !FileObject->DeviceObject->DriverObject || (FileObject->DeviceObject->DeviceType != FILE_DEVICE_DISK))
	{
		//关闭设备句柄
		ObfDereferenceObject(FileObject);
		return result;
	}

	UCHAR szBuffer[0x1000] = { '\\', 0, '?', 0, '?', 0, '\\', 0 };
	UNICODE_STRING stFileName = { 0 };
	stFileName.Buffer = szBuffer;
	stFileName.Length = 8;
	stFileName.MaximumLength = 0x1000;

	//获得文件DOS名（盘符）
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
				//非白名单进程
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
