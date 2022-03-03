#pragma once
#include "data.h"
#include "CurrencyFunc.h"
#include <ntddk.h>


//KeServiceDescriptorTable�ı�ṹ
typedef struct ServiceDescriptorEntry {
	ULONG* ServiceTableBase;				 // ������ַ
	ULONG* ServiceCounterTableBase;			 // �������ַ
	ULONG NumberOfServices;					 // ������ĸ���
	UCHAR* ParamTableBase;					 // �������Ĳ��������������ʼ��ַ�������ÿһ����Առ1�ֽڣ���¼��ֵ�Ƕ�Ӧ�����Ĳ�������*4
} ServiceDescriptorTableEntry, * PServiceDescriptorTableEntry;

//��ȡSSDT��ַ
NTSTATUS NTAPI Safe_GetSSDTTableAddress(OUT PVOID* SSDT_KeServiceTableBase, OUT ULONG* SSDT_KeNumberOfServices, OUT PVOID* SSDT_KeParamTableBase, IN PVOID* NtImageBase);

