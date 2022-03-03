#include "Fake_ZwWriteFile.h"

NTSTATUS NTAPI Fake_ZwWriteFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{
	NTSTATUS       Status, result;
	PFILE_OBJECT   FileObject = NULL;
	result = STATUS_SUCCESS;
	//将ZwWriteFile参数提出来
	IN HANDLE  In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	IN PVOID   In_ApcContext = *(ULONG*)((ULONG)ArgArray + 0xC);
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

//获取IoGetDiskDeviceObject函数地址，并调用该函数
NTSTATUS NTAPI Safe_IoGetDiskDeviceObjectPrt(PDEVICE_OBJECT FileSystemDeviceObject, PDEVICE_OBJECT* DiskDeviceObject)
{
	NTSTATUS       Status;
	UNICODE_STRING IoGetDiskDeviceObjectString;
	NTSTATUS(*IoGetDiskDeviceObjectPtr)(PDEVICE_OBJECT FileSystemDeviceObject, PDEVICE_OBJECT * DiskDeviceObject);
	//1、判断是不是第一次进去，如果是用MmGetSystemRoutineAddress方式获取IoGetDiskDeviceObject函数地址并保存起来
	IoGetDiskDeviceObjectPtr = (ULONG)MmGetSystemRoutineAddress(&IoGetDiskDeviceObjectString);;

	//获取失败直接返回
	if (!IoGetDiskDeviceObjectPtr)
	{
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	
	//2、调用IoGetDiskDeviceObject函数
	Status = IoGetDiskDeviceObjectPtr(FileSystemDeviceObject, DiskDeviceObject);
	return Status;
}
