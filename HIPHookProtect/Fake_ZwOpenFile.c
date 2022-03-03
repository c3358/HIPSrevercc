#include "Fake_ZwOpenFile.h"

NTSTATUS NTAPI Fake_ZwOpenFile(ULONG CallIndex, PVOID ArgArray, PULONG ret_func, PULONG ret_arg)
{

	NTSTATUS    Status = STATUS_SUCCESS;
	NTSTATUS	result = STATUS_SUCCESS;
	PVOID		Object = NULL;
	HANDLE      FileHandle = NULL;
	HANDLE      TempRootDirectory = NULL;
	HANDLE		Handle_v4 = NULL;
	BOOLEAN     RootDirectoryFlag = FALSE;								//释放标识符
	SYSTEM_INFORMATIONFILE System_InformationFile_XOR = { 0 };		//文件信息
	OBJECT_ATTRIBUTES TempObjectAttributes = { 0 };						//临时变量
	//0、获取ZwOpenFile原始参数
	HANDLE             In_FileHandle = *(ULONG*)((ULONG)ArgArray);
	ACCESS_MASK        In_DesiredAccess = *(ULONG*)((ULONG)ArgArray + 4);
	POBJECT_ATTRIBUTES In_ObjectAttributes = *(ULONG*)((ULONG)ArgArray + 8);
	PIO_STATUS_BLOCK   In_IoStatusBlock = *(ULONG*)((ULONG)ArgArray + 0xC);
	ULONG              In_ShareAccess = *(ULONG*)((ULONG)ArgArray + 0x10);
	ULONG              In_OpenOptions = *(ULONG*)((ULONG)ArgArray + 0x14);
	//1、必须是应用层调用
	if (!ExGetPreviousMode())
	{
		return result;
	}
	//2、获取自身句柄
	Handle_v4 = PsGetCurrentProcessId();


	//检查FileHandle文件句柄输出参数地址合法性
	if (myProbeRead(In_FileHandle, sizeof(HANDLE), sizeof(CHAR)))
	{
		KdPrint(("ProbeRead(Fake_ZwOpenFile：In_FileHandle) error \r\n"));
		return result;
	}







	//通过对象名称，得到对象内核句柄
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
			//通过内核句柄/获取文件信息
			Status = Safe_GetInformationFile(FileHandle, (ULONG)&System_InformationFile_XOR, KernelMode);
			//验证文件信息
			if (NT_SUCCESS(Status))
			{
				//查询XOR在不在保护列表中
				if (Safe_QueryInformationFileList(
					System_InformationFile_XOR.IndexNumber_LowPart,
					System_InformationFile_XOR.u.IndexNumber_HighPart,
					System_InformationFile_XOR.VolumeSerialNumber))
				{



					//非白名单进程
					if (!Safe_QueryWhitePID(Handle_v4) )
					{
						RecordLogFile(In_ObjectAttributes->ObjectName, FALSE, Operate_OpenFile);
						ZwClose(FileHandle);
						result = STATUS_ACCESS_DENIED;								//拒绝访问				
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