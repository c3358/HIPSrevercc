#pragma once
#include "Data.h"
#include <ntddk.h>

#include "CurrencyFunc.h"


//�ܱ���ע���·���������
#define PROTECTREGDITMAXIMUM		0xFE


//�������Ʋ�ѯ�Ƿ���ע������б���
ULONG NTAPI Safe_QueryProtectRegditList_RegditName(IN PUNICODE_STRING ObjectName);

//��ע������б��в����µı�����
ULONG NTAPI Safe_InsertProtectRegditList(IN PUNICODE_STRING stRegditPath);

NTSTATUS NTAPI Safe_GetInformationFile(IN HANDLE Handle, OUT PSYSTEM_INFORMATIONFILE System_Information, IN KPROCESSOR_MODE AccessMode);


//��¼��־��ע������
NTSTATUS RecordLogRegdit(PCUNICODE_STRING stRegditName, BOOL bFlag, BOOL bOperate);