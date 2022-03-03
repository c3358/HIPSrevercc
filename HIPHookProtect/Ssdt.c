#include "Ssdt.h"


//************************************     
// 函数名称: SafePort_GetSSDTTableAddress     
// 函数说明：获取SSDT基址    
// 返 回 值: NTSTATUS NTAPI     
// 参    数: OUT PVOID * SSDT_KeServiceTableBase     //[Out]SSDT_KeServiceTableBase
// 参    数: OUT ULONG * SSDT_KeNumberOfServices     //[Out]SSDT_KeNumberOfServices
// 参    数: OUT PVOID * SSDT_KeParamTableBase       //[Out]SSDT_KeParamTableBase
// 参    数: IN PVOID * NtImageBase					 //[In]Nt内核的基地址
//************************************  
NTSTATUS NTAPI Safe_GetSSDTTableAddress(OUT PVOID* SSDT_KeServiceTableBase, OUT ULONG* SSDT_KeNumberOfServices, OUT PVOID* SSDT_KeParamTableBase, IN PVOID* NtImageBase)
{
	NTSTATUS                     Status = STATUS_UNSUCCESSFUL;
	ANSI_STRING					 KeServiceDescriptorTableString;
	PCHAR						 SymbolAddr = NULL;
	PServiceDescriptorTableEntry KeServiceDescriptorTable = NULL;
	//3、获取SSDT基址
	RtlInitAnsiString(&KeServiceDescriptorTableString, "KeServiceDescriptorTable");
	SymbolAddr = Safe_GetSymbolAddress(&KeServiceDescriptorTableString, NtImageBase);
	if (SymbolAddr)
	{
		KeServiceDescriptorTable = (PServiceDescriptorTableEntry)SymbolAddr;
		*SSDT_KeServiceTableBase = KeServiceDescriptorTable->ServiceTableBase;
		*SSDT_KeNumberOfServices = KeServiceDescriptorTable->NumberOfServices;
		*SSDT_KeParamTableBase = KeServiceDescriptorTable->ParamTableBase;
		if (!KeServiceDescriptorTable && MmIsAddressValid(KeServiceDescriptorTable))
		{
			
			return STATUS_UNSUCCESSFUL;
		}
		if (!*SSDT_KeNumberOfServices)
		{
			
			return STATUS_UNSUCCESSFUL;
		}
		if (!*SSDT_KeServiceTableBase || !*SSDT_KeParamTableBase)
		{
		
			return STATUS_UNSUCCESSFUL;
		}
		Status = STATUS_SUCCESS;
	}
	else
	{
		//查找SSDT表失败
		Status = STATUS_UNSUCCESSFUL;
	}
	return Status;
}