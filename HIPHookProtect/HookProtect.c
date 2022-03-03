#include "HookProtect.h"


//************************************     
// 函数名称: HookPort_GetNativeFunAddress     
// 函数说明：获取指定函数基址        
// 返 回 值: BOOLEAN      
//************************************ 
BOOLEAN  HookProtect_GetNativeFunAddress(PVOID* NtImageBase)
{
	ULONG result = TRUE; // eax@2
	STRING DestinationString; // [sp+4h] [bp-8h]@1

	RtlInitAnsiString(&DestinationString, "ZwOpenFile");
	g_FilterFun_table->OldFunc[ZwOpenFile_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	RtlInitAnsiString(&DestinationString, "ZwCreateFile");
	g_FilterFun_table->OldFunc[ZwCreateFile_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	RtlInitAnsiString(&DestinationString, "ZwDeleteFile");
	g_FilterFun_table->OldFunc[ZwDeleteFile_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	RtlInitAnsiString(&DestinationString, "ZwReadFile");
	g_FilterFun_table->OldFunc[ZwReadFile_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	RtlInitAnsiString(&DestinationString, "ZwWriteFile");
	g_FilterFun_table->OldFunc[ZwWriteFile_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	RtlInitAnsiString(&DestinationString, "ZwSetInformationFile");
	g_FilterFun_table->OldFunc[ZwSetInformationFile_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	RtlInitAnsiString(&DestinationString, "ZwOpenKey");
	g_FilterFun_table->OldFunc[ZwOpenKey_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	RtlInitAnsiString(&DestinationString, "ZwDeleteKey");
	g_FilterFun_table->OldFunc[ZwDeleteKey_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	RtlInitAnsiString(&DestinationString, "ZwOpenKeyEx");
	g_FilterFun_table->OldFunc[ZwOpenKeyEx_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	RtlInitAnsiString(&DestinationString, "ZwDeviceIoControlFile");
	g_FilterFun_table->OldFunc[ZwDeviceIoControlFile_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	RtlInitAnsiString(&DestinationString, "ZwOpenProcess");
	g_FilterFun_table->OldFunc[ZwOpenProcess_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	RtlInitAnsiString(&DestinationString, "ZwTerminateProcess");
	g_FilterFun_table->OldFunc[ZwTerminateProcess_FilterIndex] = (ULONG)Safe_GetSymbolAddress((ULONG)&DestinationString, NtImageBase);
	


	return result;
}
//获得原服务例程的服务索引
BOOLEAN  NTAPI HookProtect_GetAllNativeFunIndex(PVOID* NtImageBase)
{
	g_FilterFun_table->SSDTIndex[ZwOpenFile_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwOpenFile_FilterIndex] + 1);
	g_FilterFun_table->SSDTIndex[ZwCreateFile_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwCreateFile_FilterIndex] + 1);
	g_FilterFun_table->SSDTIndex[ZwDeleteFile_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwDeleteFile_FilterIndex] + 1);
	g_FilterFun_table->SSDTIndex[ZwReadFile_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwReadFile_FilterIndex] + 1);
	g_FilterFun_table->SSDTIndex[ZwWriteFile_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwWriteFile_FilterIndex] + 1);
	g_FilterFun_table->SSDTIndex[ZwSetInformationFile_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwSetInformationFile_FilterIndex] + 1);
	g_FilterFun_table->SSDTIndex[ZwOpenKey_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwOpenKey_FilterIndex] + 1);
	g_FilterFun_table->SSDTIndex[ZwDeleteKey_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwDeleteKey_FilterIndex] + 1);
	g_FilterFun_table->SSDTIndex[ZwOpenKeyEx_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwOpenKeyEx_FilterIndex] + 1);
	g_FilterFun_table->SSDTIndex[ZwDeviceIoControlFile_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwDeviceIoControlFile_FilterIndex] + 1);
	g_FilterFun_table->SSDTIndex[ZwOpenProcess_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwOpenProcess_FilterIndex] + 1);
	g_FilterFun_table->SSDTIndex[ZwTerminateProcess_FilterIndex] = *(DWORD*)((PCHAR)g_FilterFun_table->OldFunc[ZwTerminateProcess_FilterIndex] + 1);
	return TRUE;
}


//得到SSDT
NTSTATUS NTAPI HookProtect_GetSSDT()
{
	NTSTATUS		Status;
	Status = STATUS_UNSUCCESSFUL;
	//1、获取原始NT内核基地址
	if (!Safe_GetModuleBaseAddress(0, &g_NtData->NtImageBase, &g_NtData->NtImageSize, 0))
	{
		KdPrint(("获取NT内核基址失败\t\n"));
		return Status;
	}
	//3、获取SSDT基址
	Status = Safe_GetSSDTTableAddress(
		&g_SSDTTable_data->SSDT_KeServiceTableBase,			//[Out]SSDT_KeServiceTableBase
		&g_SSDTTable_data->SSDT_KeNumberOfServices,			//[Out]SSDT_KeNumberOfServices
		&g_SSDTTable_data->SSDT_KeParamTableBase,			//[Out]SSDT_KeParamTableBase
		g_NtData->NtImageBase								//[In]Nt内核的基地址
	);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	KdPrint(("SSDT_KeServiceTableBase：%X\t\n", g_SSDTTable_data->SSDT_KeServiceTableBase));
	KdPrint(("获取SSDT表成功\t\n"));
	return Status;
}


//设置Filter函数
NTSTATUS NTAPI HookProtect_SetFilterFunc()
{

	g_FilterFun_table->FilterFunc[ZwCreateFile_FilterIndex] = Filter_ZwCreateFile;
	g_FilterFun_table->FilterFunc[ZwDeleteFile_FilterIndex] = Filter_ZwDeleteFile;
	g_FilterFun_table->FilterFunc[ZwDeleteKey_FilterIndex] = Filter_ZwDeleteKey;
	g_FilterFun_table->FilterFunc[ZwDeviceIoControlFile_FilterIndex] = Filter_ZwDeviceIoControlFile;
	g_FilterFun_table->FilterFunc[ZwOpenFile_FilterIndex] = Filter_ZwOpenFile;
	g_FilterFun_table->FilterFunc[ZwOpenKey_FilterIndex] = Filter_ZwOpenKey;
	g_FilterFun_table->FilterFunc[ZwOpenKeyEx_FilterIndex] = Filter_ZwOpenKeyEx;
	g_FilterFun_table->FilterFunc[ZwOpenProcess_FilterIndex] = Filter_ZwOpenProcess;
	g_FilterFun_table->FilterFunc[ZwReadFile_FilterIndex] = Filter_ZwReadFile;
	g_FilterFun_table->FilterFunc[ZwSetInformationFile_FilterIndex] = Filter_ZwSetInformationFile;
	g_FilterFun_table->FilterFunc[ZwTerminateProcess_FilterIndex] = Filter_ZwTerminateProcess;
	g_FilterFun_table->FilterFunc[ZwWriteFile_FilterIndex] = Filter_ZwWriteFile;

	g_FilterFun_table->FilterFunc[CreateProcessNotifyRoutineIndex] = Filter_CreateProcessNotifyRoutine;

}


//设置Fake函数
NTSTATUS NTAPI HookProtect_SetFakeFunc()
{

	g_FilterFun_table->FakeFunc[ZwCreateFile_FilterIndex] = Fake_ZwCreateFile;
	g_FilterFun_table->FakeFunc[ZwDeleteFile_FilterIndex] = Fake_ZwDeleteFile;
	g_FilterFun_table->FakeFunc[ZwDeleteKey_FilterIndex] = Fake_ZwDeleteKey;
	g_FilterFun_table->FakeFunc[ZwDeviceIoControlFile_FilterIndex] = Fake_ZwDeviceIoControlFile;
	g_FilterFun_table->FakeFunc[ZwOpenFile_FilterIndex] = Fake_ZwOpenFile;
	g_FilterFun_table->FakeFunc[ZwOpenKey_FilterIndex] = Fake_ZwOpenKey;
	g_FilterFun_table->FakeFunc[ZwOpenKeyEx_FilterIndex] = Fake_ZwOpenKeyEx;
	g_FilterFun_table->FakeFunc[ZwOpenProcess_FilterIndex] = Fake_ZwOpenProcess;
	g_FilterFun_table->FakeFunc[ZwReadFile_FilterIndex] = Fake_ZwReadFile;
	g_FilterFun_table->FakeFunc[ZwSetInformationFile_FilterIndex] = Fake_ZwSetInformationFile;
	g_FilterFun_table->FakeFunc[ZwTerminateProcess_FilterIndex] = Fake_ZwTerminateProcess;
	g_FilterFun_table->FakeFunc[ZwWriteFile_FilterIndex] = Fake_ZwWriteFile;

	g_FilterFun_table->FakeFunc[CreateProcessNotifyRoutineIndex] = Fake_CreateProcessNotifyRoutine;




}

//设置SSDT HOOK
NTSTATUS NTAPI HookProtect_SetSSDThook(ULONG FilterIndex)
{

	//安装SSDThook
	volatile LONG* Mdlv2_MappedSystemVa = 0;
	PMDL MemoryDescriptorList = 0; 
	MemoryDescriptorList = 0;
	PVOID NtFunc = (DWORD)((PCHAR)g_SSDTTable_data->SSDT_KeServiceTableBase + 4 * g_FilterFun_table->SSDTIndex[FilterIndex]);
	Mdlv2_MappedSystemVa = HookProtect_LockMemory(
		NtFunc,
		sizeof(ULONG),
		&MemoryDescriptorList,
		0
	);
	if (Mdlv2_MappedSystemVa)
	{
		g_FilterFun_table->OldFunc[FilterIndex] = InterlockedExchange(Mdlv2_MappedSystemVa, g_FilterFun_table->FilterFunc[FilterIndex]);
	}
	if (MemoryDescriptorList)
	{
		HookProtect_RemoveLockMemory(MemoryDescriptorList);
	}
}










BOOLEAN NTAPI HookProtect_InitData()
{
	UNICODE_STRING  DestinationString;
	UNICODE_STRING  Win32kSysString;
	PVOID 			pModuleBase = NULL;
	ULONG 			ModuleSize = NULL;
	ULONG           Tag = 0x206B6444;
	
	//各种new空间
	//这个结构专门保存文件文件信息的
	g_InformationFile = Safe_AllocBuff(NonPagedPool, sizeof(INFORMATIONFILE), Tag);
	if (!g_InformationFile)
	{
		return FALSE;
	}
	//这个结构专门保存注册表信息的
	g_All_ProtectRegdit = Safe_AllocBuff(NonPagedPool, sizeof(INFORMATIONFILE), Tag);
	if (!g_All_ProtectRegdit)
	{
		ExFreePool(g_InformationFile);
		return FALSE;
	}
	//过滤函数表
	g_FilterFun_table = Safe_AllocBuff(NonPagedPool, sizeof(FILTERFUN_TABLE), Tag);
	if (!g_FilterFun_table)
	{
		ExFreePool(g_InformationFile);
		ExFreePool(g_All_ProtectRegdit);
		return FALSE;
	}
	//SSDT表信息
	g_SSDTTable_data = Safe_AllocBuff(NonPagedPool, sizeof(SSDTTable_Data), Tag);
	if (!g_SSDTTable_data)
	{
		ExFreePool(g_InformationFile);
		ExFreePool(g_All_ProtectRegdit);
		ExFreePool(g_FilterFun_table);
		return FALSE;
	}

	g_NtData = Safe_AllocBuff(NonPagedPool, sizeof(NtData), Tag);
	if (!g_NtData)
	{
		ExFreePool(g_InformationFile);
		ExFreePool(g_All_ProtectRegdit);
		ExFreePool(g_FilterFun_table);
		ExFreePool(g_SSDTTable_data);
		return FALSE;
	}
	//一些系统函数
	g_NtFuncAddress = Safe_AllocBuff(NonPagedPool, sizeof(NtFuncAddress), Tag);
	if (!g_NtFuncAddress)
	{
		ExFreePool(g_InformationFile);
		ExFreePool(g_All_ProtectRegdit);
		ExFreePool(g_FilterFun_table);
		ExFreePool(g_SSDTTable_data);
		ExFreePool(g_NtData);
		return FALSE;
	}



	//初始化自旋锁
	KeInitializeSpinLock(&g_White_List.SpinLock);
	KeInitializeSpinLock(&g_InformationFile->SpinLock);
	KeInitializeSpinLock(&g_All_ProtectRegdit->SpinLock);



	RtlInitUnicodeString(&DestinationString, L"ObGetObjectType");
	g_NtFuncAddress->pObGetObjectType = MmGetSystemRoutineAddress(&DestinationString);
	RtlInitUnicodeString(&DestinationString, L"ObDuplicateObject");
	g_NtFuncAddress->pObDuplicateObject = (ULONG)MmGetSystemRoutineAddress(&DestinationString);
	RtlInitUnicodeString(&DestinationString, L"PsGetThreadProcessId");
	g_NtFuncAddress->pPsGetThreadProcessId = (ULONG)MmGetSystemRoutineAddress(&DestinationString);
	RtlInitUnicodeString(&DestinationString, L"PsGetProcessId");
	g_NtFuncAddress->pPsGetProcessId = (ULONG)MmGetSystemRoutineAddress(&DestinationString);
	RtlInitUnicodeString(&DestinationString, L"PsGetProcessImageFileName");
	g_NtFuncAddress->pPsGetProcessImageFileName = (ULONG)MmGetSystemRoutineAddress(&DestinationString);
	return TRUE;
}


VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING	SymbolicLinkName;		
	UNICODE_STRING	SymbolicLinkName1;		
	UNREFERENCED_PARAMETER(DriverObject);
	RtlInitUnicodeString(&SymbolicLinkName, HookProtect_LinkName);
	RtlInitUnicodeString(&SymbolicLinkName1, HookProtect_DeviceName);
	//删除符号链接
	if (Global_HookProtectDeviceObject != NULL)
	{
		IoDeleteDevice(Global_HookProtectDeviceObject);
		IoDeleteSymbolicLink(&SymbolicLinkName1);
	}
	//释放new空间
	if (g_InformationFile)
	{
		ExFreePool(g_InformationFile);
	}
	if (g_All_ProtectRegdit)
	{
		ExFreePool(g_All_ProtectRegdit);
	}
	if (g_FilterFun_table)
	{
		ExFreePool(g_FilterFun_table);
	}
	if (g_SSDTTable_data)
	{
		ExFreePool(g_SSDTTable_data);
	}
	if (g_NtData)
	{
		ExFreePool(g_NtData);
	}
	if (g_NtFuncAddress)
	{
		ExFreePool(g_NtFuncAddress);
	}



	KdPrint(("卸载成功\t\n"));
	return;
}


//************************************     
// 函数名称: DriverEntry     
// 函数说明：驱动程序入口         
// 返 回 值: NTSTATUS     
// 参    数: IN PDRIVER_OBJECT DriverObj     
// 参    数: IN PUNICODE_STRING RegPath     
//************************************  
NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT  DriverObject,		//代表本驱动的驱动对象
	IN PUNICODE_STRING RegPath				//驱动的路径，在注册表中
)
{
	NTSTATUS		 Status;
	UNICODE_STRING   DestinationString;
	UNICODE_STRING   SymbolicLinkName;		

	RtlInitUnicodeString(&DestinationString, HookProtect_DeviceName);
	RtlInitUnicodeString(&SymbolicLinkName, HookProtect_LinkName);

	
	//创建设备
	Status = IoCreateDevice(				
		DriverObject,						//[_In_]驱动对象
		NULL,								//[_In_]扩展大小是0
		&DestinationString,					//[_In_opt_]设备名称
		FILE_DEVICE_UNKNOWN,				//[_In_]设备类型，填写未知类型
		FILE_DEVICE_SECURE_OPEN,			//[_In_]驱动特征
		FALSE,								//[_In_]Exclusive
		&Global_HookProtectDeviceObject	//[_Out_]得到设备对象
	);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	//创建符号链接
	Status = IoCreateSymbolicLink(
		&SymbolicLinkName,		//[_In_]符号链接名称
		&DestinationString		//[_In_]设备名称
	);
	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(Global_HookProtectDeviceObject);
		Global_HookProtectDeviceObject = NULL;
		return Status;
	}





	//3、 不感兴趣的通用处理
	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = Safe_CommonProc;
	}
	//3、1 设置驱动通信例程
	DriverObject->MajorFunction[IRP_MJ_CREATE] = Safe_CreateCloseCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Safe_CreateCloseCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = Safe_CreateCloseCleanup;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Safe_DeviceControl;
	DriverObject->MajorFunction[IRP_MJ_READ] = Safe_Read;
	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = Safe_Shutdown;				

	//设置同步事件对象（与应用层同步）
	UNICODE_STRING ustrFileEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\FileOn");
	g_pFileShowEvent = (PKEVENT)ExAllocatePool(NonPagedPool, sizeof(KEVENT));
	g_pFileShowEvent = IoCreateSynchronizationEvent(&ustrFileEventName, &g_hFileShowEvent);


	UNICODE_STRING ustrInterceptEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\ProcessIntercept");
	g_pProcessInterceptEvent = (PKEVENT)ExAllocatePool(NonPagedPool, sizeof(KEVENT));
	g_pProcessInterceptEvent = IoCreateSynchronizationEvent(&ustrInterceptEventName, &g_hProcessInterceptEvent);



	//初始化数据
	HookProtect_InitData();
	//获取SSDT
	HookProtect_GetSSDT();

	//DbgBreakPoint();
	//获取函数基址
	HookProtect_GetNativeFunAddress(g_NtData->NtImageBase);
	                                                                
	//获取函数服务索引
	HookProtect_GetAllNativeFunIndex(g_NtData->NtImageBase);

	


	//设置过滤函数
	HookProtect_SetFakeFunc();
	//设置代理过滤函数                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          
	HookProtect_SetFilterFunc();

	//DbgBreakPoint();
	//创建进程回调
	PsSetCreateProcessNotifyRoutine(Filter_CreateProcessNotifyRoutine, FALSE);


	//安装SSDThook
	for (int i = ZwOpenFile_FilterIndex; i <= ZwTerminateProcess_FilterIndex; i++)
		HookProtect_SetSSDThook(i);




	DriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}


