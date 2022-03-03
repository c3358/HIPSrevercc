#include "CurrencyFunc.h"

//************************************     
// ��������: PageProtectOn     
// ����˵�����ָ��ڴ汣��    
// IDA��ַ ��
// ��    �ߣ�Mr.M    
// �ο���ַ��
// �������ڣ�2019/12/31     
// �� �� ֵ: VOID     
//************************************  
VOID PageProtectOn()
{
	__asm {//�ָ��ڴ汣��  
		mov  eax, cr0
		or eax, 10000h
		mov  cr0, eax
		sti
	}
}

//************************************     
// ��������: PageProtectOff     
// ����˵�����رձ���    
// IDA��ַ ��
// ��    �ߣ�Mr.M    
// �ο���ַ��
// �������ڣ�2019/12/31     
// �� �� ֵ: VOID     
//************************************  
VOID PageProtectOff()
{
	__asm {//ȥ���ڴ汣��
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

//�ͷſռ�
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
	//ִ����Ϻ��Ұ汾>=Win7��1
	if (HighVersion_Flag)
	{
		//1���õ��ļ�����ָ��
		Status = ObReferenceObjectByHandle(FileHandle, FILE_ANY_ACCESS, *IoFileObjectType, UserMode, (PVOID*)&FileObject, NULL);
		//1��1�жϲ����Ƿ�ɹ�
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
// ��������: HookPort_LockMemory     
// ����˵����ͨ����̷�ʽʹ�� MDL �ƹ� KiServiceTable ��ֻ�����ԣ���Ҫ���� Windows ִ��������е� I/O �������Լ�
//			 �ڴ������������һЩ�����������������£�
//           IoAllocateMdl() ����һ�� MDL ������ KiServiceTable->MmProbeAndLockPages() �Ѹ� MDL ������ KiServiceTable ��
//           ������ҳ�������ڴ��У������������ҳ��Ķ�д����Ȩ�ޣ�ʵ���ǽ�������ҳ��� PTE �����е� ��R�� ��־λ�޸ĳ� ��W����
//           ->MmGetSystemAddressForMdlSafe() �� KiServiceTable ӳ�䵽��һƬ�ں������ַ����һ����ԣ�λ�� rootkit ������
//           �����ں˵�ַ��Χ�ڣ���   
// �� �� ֵ: PVOID     
// ��    ��: PVOID VirtualAddress     
// ��    ��: ULONG Length     
// ��    ��: PVOID *Mdl_a3  
// ��    ��: ULONG Version_Win10_Flag
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
		if (Mdl_v3->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL))		//���� _MDL �� MdlFlags �ֶ��������� MDL_MAPPED_TO_SYSTEM_VA ��  MDL_SOURCE_IS_NONPAGED_POOL ����λ��MappedSystemVa �ֶβ���Ч��
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


//�ͷ�MDL
VOID  HookProtect_RemoveLockMemory(PMDL pmdl)
{
	MmUnlockPages(pmdl);
	IoFreeMdl(pmdl);
}



//************************************     
// ��������: HookPort_GetAndReplaceSymbol     
// ����˵�����˺�������PE�ļ���ȡ�䵼�����ŵĵ�ַ 
//			 ��ָ����ReplaceValue������ReplaceValue�滻���ҵ��ķ��ŵ�ֵ  
// �� �� ֵ: PVOID NTAPI     
// ��    ��: PVOID ImageBase     
// ��    ��: PANSI_STRING SymbolName     
// ��    ��: PVOID ReplaceValue     
// ��    ��: PVOID * SymbolAddr     
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
			//�رձ���
			PageProtectOff();

			InterlockedExchange(symbol_address, (PCHAR)ReplaceValue - (PCHAR)ImageBase);

			//��������
			PageProtectOn();
		}

		return result;
	}

	return result;

}


//��AccessMode == 1��UserModeģʽ
NTSTATUS NTAPI Safe_UserMode_ZwQueryInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass, IN BOOLEAN HighVersion_Flag)
{
	NTSTATUS     Status;
	PFILE_OBJECT FileObject = NULL;
	PFILE_POSITION_INFORMATION pFilePositionInformation = NULL;
	//Safe_Initialize_Data
	//ִ����Ϻ��Ұ汾>=Win7��1
	if (HighVersion_Flag)
	{
		//1���õ��ļ�����ָ��
		Status = ObReferenceObjectByHandle(FileHandle, FILE_ANY_ACCESS, *IoFileObjectType, UserMode, (PVOID*)&FileObject, NULL);
		//1��1�жϲ����Ƿ�ɹ�
		if (NT_SUCCESS(Status))
		{
			//�ļ�λ����Ϣ
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
// ��������: Safe_GetModuleBaseAddress     
// ����˵�������ݺ�������ȡָ���ں˻�ַ     
// �� �� ֵ: BOOLEAN NTAPI     
// ��    ��: PUNICODE_STRING ModuleName ModuleName    ģ���� 
// ��    ��: PVOID * pModuleBase					  ģ���ַ
// ��    ��: ULONG * ModuleSize						  ģ���С
// ��    ��: USHORT * LoadOrderIndex    
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
		//����˳�
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


//���ʱ��
PWCHAR GetTimeFunction() {
	LARGE_INTEGER snow, now;
	TIME_FIELDS now_fields;
	static WCHAR time_str[32] = { 0 };
	WCHAR buff = 0x0;
	UNICODE_STRING unsting = { 0 };
	int count = 0;
	//��ñ�׼ʱ��
	KeQuerySystemTime(&snow);
	//ת��Ϊ����ʱ��
	ExSystemTimeToLocalTime(&snow, &now);
	RtlTimeToTimeFields(&now, &now_fields);
	//���ַ�����
	RtlStringCchPrintfW(time_str, 32, L"%4d-%2d-%2d %2d:%2d:%2d"
		, now_fields.Year, now_fields.Month, now_fields.Day,
		now_fields.Hour, now_fields.Minute, now_fields.Second);
	return time_str;
}

//��ý���·��
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


//�ͷž��
NTSTATUS NTAPI Safe_ZwNtClose(IN HANDLE Handle, IN BOOLEAN HighVersion_Flag)
{
	NTSTATUS Status;
	Status = STATUS_UNSUCCESSFUL;
	//Win7��1
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