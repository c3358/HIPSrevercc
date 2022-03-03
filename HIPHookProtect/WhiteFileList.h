#pragma once
#include "Data.h"
#include <ntddk.h>
#include "WhiteFileList.h"
#include "WhiteProcessList.h"
#include "WhiteRegditList.h"


#define CRCLISTNUMBER 0X1FFE		//最大容量




/*****************************增加*****************************/
//插入该列表中文件信息
//返回值：成功1 
//        失败0
ULONG NTAPI Safe_InsertInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber, IN PUNICODE_STRING stFilePath);
/*****************************增加*****************************/




/*****************************删除*****************************/
//删除该列表中文件信息
ULONG NTAPI Safe_DeleteInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber);
/*****************************删除*****************************/





/*****************************查询*****************************/
//查找该文件信息是否在列表中，找到返回1，失败返回0
//返回值：成功1 
//        失败0
ULONG NTAPI Safe_QueryInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber);

//根据路径查询是否在列表中
//返回值：成功1 
//        失败0
ULONG NTAPI Safe_QueryInformationFileList_Name(IN PUNICODE_STRING ObjectName);




ULONG NTAPI Safe_QueryInformationFileList_FileName(IN PUNICODE_STRING ObjectName);
/*****************************查询*****************************/





//向文件白名单中添加文件
NTSTATUS Safe_AddFileWhiteList(PCUNICODE_STRING stFileName);


//记录日志：文件操作
NTSTATUS RecordLogFile(PCUNICODE_STRING stFileName, BOOL bFlag, BOOL bOperate);