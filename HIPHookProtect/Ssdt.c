#include "Ssdt.h"


//************************************     
// ��������: SafePort_GetSSDTTableAddress     
// ����˵������ȡSSDT��ַ    
// �� �� ֵ: NTSTATUS NTAPI     
// ��    ��: OUT PVOID * SSDT_KeServiceTableBase     //[Out]SSDT_KeServiceTableBase
// ��    ��: OUT ULONG * SSDT_KeNumberOfServices     //[Out]SSDT_KeNumberOfServices
// ��    ��: OUT PVOID * SSDT_KeParamTableBase       //[Out]SSDT_KeParamTableBase
// ��    ��: IN PVOID * NtImageBase					 //[In]Nt�ں˵Ļ���ַ
//************************************  
NTSTATUS NTAPI Safe_GetSSDTTableAddress(OUT PVOID* SSDT_KeServiceTableBase, OUT ULONG* SSDT_KeNumberOfServices, OUT PVOID* SSDT_KeParamTableBase, IN PVOID* NtImageBase)
{
	NTSTATUS                     Status = STATUS_UNSUCCESSFUL;
	ANSI_STRING					 KeServiceDescriptorTableString;
	PCHAR						 SymbolAddr = NULL;
	PServiceDescriptorTableEntry KeServiceDescriptorTable = NULL;
	//3����ȡSSDT��ַ
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
		//����SSDT��ʧ��
		Status = STATUS_UNSUCCESSFUL;
	}
	return Status;
}