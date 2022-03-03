#include "CurrencyFunc.h"

//************************************     
// 函数名称: PageProtectOn     
// 函数说明：恢复内存保护    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值: VOID     
//************************************  
VOID PageProtectOn()
{
	__asm {//恢复内存保护  
		mov  eax, cr0
		or eax, 10000h
		mov  cr0, eax
		sti
	}
}

//************************************     
// 函数名称: PageProtectOff     
// 函数说明：关闭保护    
// IDA地址 ：
// 作    者：Mr.M    
// 参考网址：
// 作成日期：2019/12/31     
// 返 回 值: VOID     
//************************************  
VOID PageProtectOff()
{
	__asm {//去掉内存保护
		cli
		mov  eax, cr0
		and eax, not 10000h
		mov  cr0, eax
	}
}

LONG ExSystemExceptionFilter()
{
	return ExGetPreviousMode() != KernelMode ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

NTSTATUS NTAPI myProbeRead(PVOID Address, SIZE_T Size, ULONG Alignment)
{
	NTSTATUS result = STATUS_SUCCESS;
	if (ExGetPreviousMode() != KernelMode && KeGetCurrentIrql() <= APC_LEVEL)
	{
		try
		{
			if (Size == 0)
			{
				result = STATUS_UNSUCCESSFUL;
				return result;
			}
			ProbeForRead(Address, Size, Alignment);
		}
		except(ExSystemExceptionFilter())
		{
			result = GetExceptionCode();
			return result;
		}
	}
	else
	{
		result = STATUS_UNSUCCESSFUL;
	}
	return result;
}

NTSTATUS NTAPI myProbeWrite(PVOID Address, SIZE_T Size, ULONG Alignment)
{
	NTSTATUS result = STATUS_SUCCESS;
	if (ExGetPreviousMode() != KernelMode && KeGetCurrentIrql() <= APC_LEVEL)
	{
		try
		{
			if (Size == 0)
			{
				result = STATUS_UNSUCCESSFUL;
				return result;
			}
			ProbeForWrite(Address, Size, Alignment);
		}
		except(ExSystemExceptionFilter())
		{
			result = GetExceptionCode();
			return result;
		}
	}
	else
	{
		result = STATUS_UNSUCCESSFUL;
	}
	return result;
}


PVOID Safe_AllocBuff(POOL_TYPE PoolType, ULONG Size, ULONG Tag)
{
	PVOID pBuff;
	pBuff = ExAllocatePoolWithTag(PoolType, Size, Tag);
	if (!pBuff)
		return FALSE;
	RtlZeroMemory(pBuff, Size);
	return pBuff;
}

//释放空间
PVOID Safe_ExFreePool(IN PVOID pBuff)
{
	if (MmIsAddressValid(pBuff))
	{
		ExFreePool(pBuff);
		pBuff = NULL;
	}
}
ULONG NTAPI Safe_pPsGetProcessId(PVOID VirtualAddress)
{
	if (VirtualAddress < MmUserProbeAddress || !MmIsAddressValid(VirtualAddress))
		return 0;
	
	return g_NtFuncAddress->pPsGetProcessId(VirtualAddress);
}

NTSTATUS NTAPI Safe_IoCreateFile(_In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PHANDLE FileHandle)
{
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	NTSTATUS Status;
	Status = STATUS_UNSUCCESSFUL;
	Status = IoCreateFile(FileHandle,
		GENERIC_READ | SYNCHRONIZE,
		ObjectAttributes,
		&IoStatusBlock,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
		CreateFileTypeNone,
		0,
		IO_NO_PARAMETER_CHECKING
	);
	return Status;
}


NTSTATUS NTAPI Safe_UserMode_ZwQueryVolumeInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FsInformation, _In_ ULONG Length, _In_ FS_INFORMATION_CLASS FsInformationClass, IN BOOLEAN HighVersion_Flag)
{
	NTSTATUS     Status;
	PFILE_OBJECT FileObject = NULL;
	//Safe_Initialize_Data
	//执行完毕后并且版本>=Win7置1
	if (HighVersion_Flag)
	{
		//1、得到文件对象指针
		Status = ObReferenceObjectByHandle(FileHandle, FILE_ANY_ACCESS, *IoFileObjectType, UserMode, (PVOID*)&FileObject, NULL);
		//1、1判断操作是否成功
		if (NT_SUCCESS(Status))
		{
			Status = IoQueryVolumeInformation(FileObject, FsInformationClass, Length, FsInformation, &IoStatusBlock);
			ObfDereferenceObject(FileObject);
		}
	}
	else
	{
		Status = ZwQueryVolumeInformationFile(FileHandle, &IoStatusBlock, FsInformation, Length, FsInformationClass);
	}
	return Status;
}

//************************************     
// 函数名称: HookPort_LockMemory     
// 函数说明：通过编程方式使用 MDL 绕过 KiServiceTable 的只读属性，需要借助 Windows 执行体组件中的 I/O 管理器以及
//			 内存管理器导出的一些函数，大致流程如下：
//           IoAllocateMdl() 分配一个 MDL 来描述 KiServiceTable->MmProbeAndLockPages() 把该 MDL 描述的 KiServiceTable 所
//           属物理页锁定在内存中，并赋予对这张页面的读写访问权限（实际是将描述该页面的 PTE 内容中的 “R” 标志位修改成 “W”）
//           ->MmGetSystemAddressForMdlSafe() 将 KiServiceTable 映射到另一片内核虚拟地址区域（一般而言，位于 rootkit 被加载
//           到的内核地址范围内）。   
// 返 回 值: PVOID     
// 参    数: PVOID VirtualAddress     
// 参    数: ULONG Length     
// 参    数: PVOID *Mdl_a3  
// 参    数: ULONG Version_Win10_Flag
//************************************  
PVOID HookProtect_LockMemory(PVOID VirtualAddress, ULONG Length, PVOID* Mdl_a3, ULONG Version_Win10_Flag)
{
	PMDL Mdl_v3; // eax@1
	PMDL Mdl_v4; // eax@2
	PVOID result; // eax@3

	Mdl_v3 = IoAllocateMdl(VirtualAddress, Length, 0, FALSE, NULL);
	*Mdl_a3 = Mdl_v3;
	if (Mdl_v3)
	{
		MmProbeAndLockPages(Mdl_v3, KernelMode, (Version_Win10_Flag != 0 ? 0 : 2));
		Mdl_v4 = Mdl_v3;
		if (Mdl_v3->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL))		//仅当 _MDL 的 MdlFlags 字段内设置了 MDL_MAPPED_TO_SYSTEM_VA 或  MDL_SOURCE_IS_NONPAGED_POOL 比特位，MappedSystemVa 字段才有效。
			result = Mdl_v4->MappedSystemVa;
		else
			result = MmMapLockedPagesSpecifyCache(Mdl_v4, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	}
	else
	{
		result = 0;
	}
	return result;
}


//释放MDL
VOID  HookProtect_RemoveLockMemory(PMDL pmdl)
{
	MmUnlockPages(pmdl);
	IoFreeMdl(pmdl);
}



//************************************     
// 函数名称: HookPort_GetAndReplaceSymbol     
// 函数说明：此函数分析PE文件获取其导出符号的地址 
//			 如指定了ReplaceValue，则用ReplaceValue替换查找到的符号的值  
// 返 回 值: PVOID NTAPI     
// 参    数: PVOID ImageBase     
// 参    数: PANSI_STRING SymbolName     
// 参    数: PVOID ReplaceValue     
// 参    数: PVOID * SymbolAddr     
//************************************  
PVOID NTAPI Safe_GetAndReplaceSymbol(PVOID ImageBase, PANSI_STRING SymbolName, PVOID ReplaceValue, PVOID* SymbolAddr)
{

	PCHAR	AddressOfNames, pSymbolName;
	PVOID symbol_address, result;
	ULONG Size, func_index;
	DWORD NameOrdinals, NumberOfNames, Low, Mid, High;
	long	ret;

	PIMAGE_EXPORT_DIRECTORY pIED;


	pIED = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &Size);
	if (!pIED)
		return NULL;

	AddressOfNames = (CHAR*)ImageBase + pIED->AddressOfNames;
	NameOrdinals = (DWORD)((CHAR*)ImageBase + pIED->AddressOfNameOrdinals);
	NumberOfNames = pIED->NumberOfNames;

	Low = 0;
	High = NumberOfNames - 1;
	if ((long)High < 0)
		return NULL;

	while (TRUE)
	{
		Mid = (Low + High) >> 1;
		pSymbolName = (PCHAR)ImageBase + *(PULONG)&AddressOfNames[4 * Mid];
		ret = strcmp(SymbolName->Buffer, pSymbolName);
		if (!ret)
			break;

		if (ret > 0)
		{
			Low = Mid + 1;
		}
		else
		{
			High = Mid - 1;
		}
		if (High < Low)
			break;
	}

	result = NULL;

	if (High >= Low && (func_index = *(WORD*)(NameOrdinals + 2 * Mid), func_index < pIED->NumberOfFunctions))
	{

		symbol_address = (PVOID)((PCHAR)ImageBase + 4 * func_index + pIED->AddressOfFunctions);

		result = (CHAR*)ImageBase + *(PULONG)symbol_address;

		*SymbolAddr = symbol_address;

		if (ReplaceValue)
		{
			//关闭保护
			PageProtectOff();

			InterlockedExchange(symbol_address, (PCHAR)ReplaceValue - (PCHAR)ImageBase);

			//开启保护
			PageProtectOn();
		}

		return result;
	}

	return result;

}


//当AccessMode == 1，UserMode模式
NTSTATUS NTAPI Safe_UserMode_ZwQueryInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass, IN BOOLEAN HighVersion_Flag)
{
	NTSTATUS     Status;
	PFILE_OBJECT FileObject = NULL;
	PFILE_POSITION_INFORMATION pFilePositionInformation = NULL;
	//Safe_Initialize_Data
	//执行完毕后并且版本>=Win7置1
	if (HighVersion_Flag)
	{
		//1、得到文件对象指针
		Status = ObReferenceObjectByHandle(FileHandle, FILE_ANY_ACCESS, *IoFileObjectType, UserMode, (PVOID*)&FileObject, NULL);
		//1、1判断操作是否成功
		if (NT_SUCCESS(Status))
		{
			//文件位置信息
			if (FilePositionInformation == FileInformationClass)
			{
				if (Length >= 8)
				{
					pFilePositionInformation = FileInformation;
					pFilePositionInformation->CurrentByteOffset = FileObject->CurrentByteOffset;
					Status = 0;
				}
				else
				{
					Status = STATUS_INFO_LENGTH_MISMATCH;
				}
			}
			else
			{
				Status = IoQueryFileInformation(FileObject, FileInformationClass, Length, FileInformation, &IoStatusBlock);
			}
			ObfDereferenceObject(FileObject);
		}
	}
	else
	{
		Status = ZwQueryInformationFile(FileHandle, &IoStatusBlock, FileInformation, Length, FileInformationClass);
	}
	return Status;
}

PVOID Safe_GetSymbolAddress(PANSI_STRING SymbolName, PVOID NtImageBase)
{

	PVOID pModuleBase;
	ULONG ModuleSize;

	PVOID SymbolAddr, result = NULL;
	result = Safe_GetAndReplaceSymbol(NtImageBase, SymbolName, NULL, &SymbolAddr);

	return result;
}

//************************************     
// 函数名称: Safe_GetModuleBaseAddress     
// 函数说明：根据函数名获取指定内核基址     
// 返 回 值: BOOLEAN NTAPI     
// 参    数: PUNICODE_STRING ModuleName ModuleName    模块名 
// 参    数: PVOID * pModuleBase					  模块基址
// 参    数: ULONG * ModuleSize						  模块大小
// 参    数: USHORT * LoadOrderIndex    
//************************************  
BOOLEAN NTAPI Safe_GetModuleBaseAddress(IN PUNICODE_STRING ModuleName, OUT PVOID* pModuleBase, OUT ULONG* ModuleSize, OUT USHORT* LoadOrderIndex)
{

	NTSTATUS status; // eax@5

	ULONG    uCount; // eax@8  
	PSYSTEM_MODULE_INFORMATION    pSysModule;
	STRING DestinationString;
	UNICODE_STRING CmpString2;
	ULONG ReturnLength; // [sp+Ch] [bp-14h]@5  
	PCHAR  pModuleInfo = NULL; // [sp+10h] [bp-10h]@8
	size_t	BufLen = 4096; // [sp+14h] [bp-Ch]@12
	BOOLEAN Result = FALSE;
	PCHAR            pName = NULL;
	ULONG            ui;

	do {

		if (pModuleInfo)
			ExFreePool(pModuleInfo);

		pModuleInfo = ExAllocatePoolWithTag(NonPagedPool, BufLen, 0x12331231);

		if (!pModuleInfo)
		{
			Result = FALSE;
			return Result;

		}

		status = ZwQuerySystemInformation(SystemModuleInformation, pModuleInfo, BufLen, &ReturnLength);
		if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH)
		{
			ExFreePool(pModuleInfo);
			Result = FALSE;
			return Result;
		}

		BufLen += 4096;

	} while (!NT_SUCCESS(status));


	uCount = (ULONG) * (ULONG*)pModuleInfo;
	pSysModule = (PSYSTEM_MODULE_INFORMATION)(pModuleInfo + sizeof(ULONG));

	if (!ModuleName)
	{

		*pModuleBase = pSysModule->Base;
		*ModuleSize = pSysModule->Size;
		ExFreePool(pModuleInfo);
		Result = TRUE;
		return Result;
	}

	for (ui = 0; ui < uCount; ui++)
	{

		pName = strrchr(pSysModule->ImageName, '\\');
		if (pName) {
			++pName;
		}
		else {
			pName = pSysModule->ImageName;
		}
		RtlInitAnsiString(&DestinationString, pName);
		status = RtlAnsiStringToUnicodeString(&CmpString2, &DestinationString, TRUE);
		if (!NT_SUCCESS(status))
		{
			Result = FALSE;
			break;
		}
		//相等退出
		if (RtlEqualUnicodeString(ModuleName, &CmpString2, TRUE))
		{
			Result = TRUE;
			break;
		}
		RtlFreeUnicodeString(&CmpString2);
		pSysModule++;

	}
	if (ui >= uCount)
	{
		ExFreePool(pModuleInfo);
		Result = FALSE;
		return Result;
	}
	if (pModuleBase)
	{
		*pModuleBase = pSysModule->Base;
	}
	if (ModuleSize)
	{
		*ModuleSize = pSysModule->Size;
	}
	if (LoadOrderIndex)
	{
		*LoadOrderIndex = pSysModule->LoadOrderIndex;
	}
	RtlFreeUnicodeString(&CmpString2);
	ExFreePool(pModuleInfo);
	return Result;
}


//获得时间
PWCHAR GetTimeFunction() {
	LARGE_INTEGER snow, now;
	TIME_FIELDS now_fields;
	static WCHAR time_str[32] = { 0 };
	WCHAR buff = 0x0;
	UNICODE_STRING unsting = { 0 };
	int count = 0;
	//获得标准时间
	KeQuerySystemTime(&snow);
	//转换为当地时间
	ExSystemTimeToLocalTime(&snow, &now);
	RtlTimeToTimeFields(&now, &now_fields);
	//打到字符串中
	RtlStringCchPrintfW(time_str, 32, L"%4d-%2d-%2d %2d:%2d:%2d"
		, now_fields.Year, now_fields.Month, now_fields.Day,
		now_fields.Hour, now_fields.Minute, now_fields.Second);
	return time_str;
}

//获得进程路径
PUNICODE_STRING GetCurrentProcessFileName()
{

	DWORD dwAddress = (DWORD)PsGetCurrentProcess();
	if (dwAddress == 0 || dwAddress == 0xFFFFFFFF)
		return NULL;
	dwAddress += 0x1a8;
	if ((dwAddress = *(DWORD*)dwAddress) == 0) return 0;
	dwAddress += 0x10;
	if ((dwAddress = *(DWORD*)dwAddress) == 0) return 0;
	dwAddress += 0x38;
	if (*(DWORD*)dwAddress == 0) return 0;

	return dwAddress;
}


//释放句柄
NTSTATUS NTAPI Safe_ZwNtClose(IN HANDLE Handle, IN BOOLEAN HighVersion_Flag)
{
	NTSTATUS Status;
	Status = STATUS_UNSUCCESSFUL;
	//Win7置1
	if (HighVersion_Flag)
	{
		Status = NtClose(Handle);
	}
	else
	{
		Status = ZwClose(Handle);
	}
	return Status;
}