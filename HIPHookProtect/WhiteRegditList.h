#pragma once
#include "Data.h"
#include <ntddk.h>

#include "CurrencyFunc.h"


//受保护注册表路径最大容量
#define PROTECTREGDITMAXIMUM		0xFE


//根据名称查询是否在注册表保护列表中
ULONG NTAPI Safe_QueryProtectRegditList_RegditName(IN PUNICODE_STRING ObjectName);

//向注册表保护列表中插入新的保护项
ULONG NTAPI Safe_InsertProtectRegditList(IN PUNICODE_STRING stRegditPath);

NTSTATUS NTAPI Safe_GetInformationFile(IN HANDLE Handle, OUT PSYSTEM_INFORMATIONFILE System_Information, IN KPROCESSOR_MODE AccessMode);


//记录日志：注册表操作
NTSTATUS RecordLogRegdit(PCUNICODE_STRING stRegditName, BOOL bFlag, BOOL bOperate);