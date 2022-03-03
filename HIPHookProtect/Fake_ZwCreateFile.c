#include "Fake_ZwCreateFile.h"

NTSTATUS NTAPI Fake_ZwCreateFile(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg)
{
	NTSTATUS    Status, result;
	PVOID		Object = NULL;
	BOOL		bFlag = FALSE;											//判断文件是否存在
	BOOL		OpenOrCreat = FALSE;									//判断是打开文件还是创建文件（默认打开）
	HANDLE      FileHandle = NULL;
	HANDLE      TempRootDirectory = NULL;
	BOOLEAN     RootDirectoryFlag = NULL;								//释放标识符
	SYSTEM_INFORMATIONFILE System_InformationFile_XOR = { 0 };		//文件信息
	OBJECT_ATTRIBUTES TempObjectAttributes = { 0 };						//临时变量
	result = STATUS_SUCCESS;


	//0、获取ZwCreateFile原始参数
	IN HANDLE             In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	IN ACCESS_MASK        In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	IN POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	IN PIO_STATUS_BLOCK	  In_IoStatusBlock = *(ULONG*)((ULONG)ArgArray + 0xC);
	IN PLARGE_INTEGER	  In_AllocationSize = *(ULONG*)((ULONG)ArgArray + 0x10);
	IN ULONG			  In_FileAttributes = *(ULONG*)((ULONG)ArgArray + 0x14);
	IN ULONG			  In_ShareAccess = *(ULONG*)((ULONG)ArgArray + 0x18);
	IN ULONG			  In_CreateDisposition = *(ULONG*)((ULONG)ArgArray + 0x1C);
	//1、必须是应用层调用
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
	//RootDirectoryFlag为真表示使用ObOpenObjectByPointer获取的，这个需要释放的
	if (RootDirectoryFlag)
	{
		ZwClose(TempRootDirectory);
	}
	if (Status != STATUS_GUARD_PAGE_VIOLATION)
	{
		if (NT_SUCCESS(Status))
		{
			//获取文件信息
			Status = Safe_GetInformationFile(FileHandle, (ULONG)&System_InformationFile_XOR, KernelMode);
			//验证文件信息
			if (NT_SUCCESS(Status))
			{
				//查询XOR在不在列表中
				if (Safe_QueryInformationFileList(
					System_InformationFile_XOR.IndexNumber_LowPart,
					System_InformationFile_XOR.u.IndexNumber_HighPart,
					System_InformationFile_XOR.VolumeSerialNumber))
				{
					//非白名单进程
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