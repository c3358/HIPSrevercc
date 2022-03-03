#include "Fake_ZwReadFile.h"

NTSTATUS NTAPI Fake_ZwReadFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{
	NTSTATUS       Status, result;
	PFILE_OBJECT   FileObject = NULL;
	result = STATUS_SUCCESS;
	//将ZwWriteFile参数提出来
	IN HANDLE  In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	IN PVOID   In_ApcContext = *(ULONG*)((ULONG)ArgArray + 0xC);
	OUT PVOID  Buffer = *(ULONG*)((ULONG)ArgArray + 0x14);
	//1、必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return result;
	}


	//1、得到文件对象指针
	Status = ObReferenceObjectByHandle(In_FileHandle, FILE_ANY_ACCESS, *IoFileObjectType, UserMode, (PVOID*)&FileObject, NULL);
	//1、1判断操作是否成功
	if (!NT_SUCCESS(Status))
	{
		return result;
	}
	//2 判断设备对象、驱动对象、文件设备类型等
	if ((!FileObject->DeviceObject) || (!FileObject->DeviceObject->DriverObject) || (FileObject->DeviceObject->DeviceType != FILE_DEVICE_DISK))
	{
		//关闭设备句柄
		ObfDereferenceObject(FileObject);
		return result;
	}


	UCHAR szBuffer[0x200] = { '\\', 0, '?', 0, '?', 0, '\\', 0 };
	UNICODE_STRING stFileName = { 0 };
	stFileName.Buffer = szBuffer;
	stFileName.Length = 8;
	stFileName.MaximumLength = 0x200;

	//获得文件DOS名（盘符）
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
				//非白名单直接错误返回
				if (!Safe_QueryWhitePID(PsGetCurrentProcessId()))
				{
					RecordLogFile(&stFileName, FALSE, Operate_ReadFile);
					return STATUS_ACCESS_DENIED;
				}
				RecordLogFile(&stFileName, TRUE, Operate_ReadFile);
			}


		}
	}

	ObfDereferenceObject(FileObject);
	return result;
}

