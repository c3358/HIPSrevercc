#pragma once
#include "Data.h"
#include <ntddk.h>
#include "WhiteFileList.h"
#include "WhiteProcessList.h"
#include "WhiteRegditList.h"


#define CRCLISTNUMBER 0X1FFE		//�������




/*****************************����*****************************/
//������б����ļ���Ϣ
//����ֵ���ɹ�1 
//        ʧ��0
ULONG NTAPI Safe_InsertInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber, IN PUNICODE_STRING stFilePath);
/*****************************����*****************************/




/*****************************ɾ��*****************************/
//ɾ�����б����ļ���Ϣ
ULONG NTAPI Safe_DeleteInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber);
/*****************************ɾ��*****************************/





/*****************************��ѯ*****************************/
//���Ҹ��ļ���Ϣ�Ƿ����б��У��ҵ�����1��ʧ�ܷ���0
//����ֵ���ɹ�1 
//        ʧ��0
ULONG NTAPI Safe_QueryInformationFileList(IN ULONG IndexNumber_LowPart, IN ULONG IndexNumber_HighPart, IN ULONG VolumeSerialNumber);

//����·����ѯ�Ƿ����б���
//����ֵ���ɹ�1 
//        ʧ��0
ULONG NTAPI Safe_QueryInformationFileList_Name(IN PUNICODE_STRING ObjectName);




ULONG NTAPI Safe_QueryInformationFileList_FileName(IN PUNICODE_STRING ObjectName);
/*****************************��ѯ*****************************/





//���ļ�������������ļ�
NTSTATUS Safe_AddFileWhiteList(PCUNICODE_STRING stFileName);


//��¼��־���ļ�����
NTSTATUS RecordLogFile(PCUNICODE_STRING stFileName, BOOL bFlag, BOOL bOperate);