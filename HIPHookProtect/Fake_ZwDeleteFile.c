#include "Fake_ZwDeleteFile.h"


//删除文件
NTSTATUS NTAPI Fake_ZwDeleteFile(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	PVOID		Object = NULL;
	HANDLE      FileHandle = NULL;
	HANDLE      TempRootDirectory = NULL;
	HANDLE		Handle_v4 = NULL;
	BOOLEAN     RootDirectoryFlag = FALSE;								//释放标识符
	SYSTEM_INFORMATIONFILE System_InformationFile_XOR = { 0 };		//文件信息
	OBJECT_ATTRIBUTES TempObjectAttributes = { 0 };						//临时变量
	result = STATUS_SUCCESS;
	//0、获取ZwDelteFile原始参数
	IN POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray);
	//1、必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return result;
	}
	if (myProbeRead(In_ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(Fake_ZwDeleteFile：In_ObjectAttributes) error \r\n"));
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
	//RootDirectoryFlag为真表示使用ObOpenObjectByPointer获取的，这个需要释放的
	if (RootDirectoryFlag)
	{
		ZwClose(TempRootDirectory);
	}
	result = STATUS_GUARD_PAGE_VIOLATION;
	if (Status != STATUS_GUARD_PAGE_VIOLATION)
	{
		if (NT_SUCCESS(Status))
		{
			//获取文件信息
			Status = Safe_GetInformationFile(FileHandle, (ULONG)&System_InformationFile_XOR, KernelMode);
			ZwClose(FileHandle);
			//验证文件信息
			if (NT_SUCCESS(Status))
			{

				//查询XOR在不在列表中
				if (Safe_QueryInformationFileList(
					System_InformationFile_XOR.IndexNumber_LowPart,
					System_InformationFile_XOR.u.IndexNumber_HighPart,
					System_InformationFile_XOR.VolumeSerialNumber))
				{
					//非白名单直接错误返回
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
