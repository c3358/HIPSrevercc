#pragma once
#pragma once
#include "Data.h"
#include <ntddk.h>
#include "WhiteFileList.h"
#include "WhiteProcessList.h"
#include "WhiteRegditList.h"


//���������̸���
#define WHITELISTNUMBER					0xFE
#define WHITELISTNUMBERMAXIMUM			0x100



//�������ṹ��
typedef struct _WHITEPROCESSLIST
{
	ULONG Number;										//���������̸���				    
	ULONG PID[WHITELISTNUMBERMAXIMUM];					//��������PID						
	KSPIN_LOCK SpinLock;								//������
}WHITEPROCESSLIST, * PWHITEPROCESSLIST;										//�������������PID
WHITEPROCESSLIST g_White_List;


/*****************************ɾ��*****************************/
//�ж��ǲ��ǰ���������
//1������ǣ���������������Ϣ��������Ĩ��
//2��������ǣ�ֱ���˳�
BOOLEAN Safe_DeleteWhiteList_PID(_In_ HANDLE ProcessId);
/*****************************ɾ��*****************************/





/*****************************���*****************************/

// ��Ӱ�����������Ϣ
BOOLEAN  Safe_InsertWhiteList_PID(_In_ HANDLE ProcessId);
/*****************************���*****************************/





/*****************************��ѯ*****************************/
//�ж��ǲ��ǰ�����_EPROCESS
//����ֵ����1������0
BOOLEAN Safe_QueryWhiteEProcess(_In_ PEPROCESS Process);

//�ж��ǲ��ǰ�������PID
//����ֵ����1������0
BOOLEAN Safe_QueryWhitePID(_In_ HANDLE ProcessId);


//����ProcessHandleת����Eprocess��Ȼ�����Safe_QueryWhitePID_PsGetProcessId
//�ж��ǲ��ǰ�������PID
//����ֵ����1������0
BOOLEAN Safe_QueryWintePID_ProcessHandle(IN HANDLE ProcessHandle);


//Eprocess_UniqueProcessId
//�ж��ǲ��ǰ�������PID
//����ֵ����1������0
BOOLEAN Safe_QueryWhitePID_PsGetProcessId(IN PEPROCESS pPeprocess);

