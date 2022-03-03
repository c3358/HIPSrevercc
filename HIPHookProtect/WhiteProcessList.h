#pragma once
#pragma once
#include "Data.h"
#include <ntddk.h>
#include "WhiteFileList.h"
#include "WhiteProcessList.h"
#include "WhiteRegditList.h"


//白名单进程个数
#define WHITELISTNUMBER					0xFE
#define WHITELISTNUMBERMAXIMUM			0x100



//白名单结构体
typedef struct _WHITEPROCESSLIST
{
	ULONG Number;										//白名单进程个数				    
	ULONG PID[WHITELISTNUMBERMAXIMUM];					//白名单的PID						
	KSPIN_LOCK SpinLock;								//自旋锁
}WHITEPROCESSLIST, * PWHITEPROCESSLIST;										//保存白名单进程PID
WHITEPROCESSLIST g_White_List;


/*****************************删除*****************************/
//判断是不是白名单进程
//1：如果是：将白名单进程信息从数组中抹除
//2、如果不是：直接退出
BOOLEAN Safe_DeleteWhiteList_PID(_In_ HANDLE ProcessId);
/*****************************删除*****************************/





/*****************************添加*****************************/

// 添加白名单进程信息
BOOLEAN  Safe_InsertWhiteList_PID(_In_ HANDLE ProcessId);
/*****************************添加*****************************/





/*****************************查询*****************************/
//判断是不是白名单_EPROCESS
//返回值：是1，不是0
BOOLEAN Safe_QueryWhiteEProcess(_In_ PEPROCESS Process);

//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWhitePID(_In_ HANDLE ProcessId);


//根据ProcessHandle转换成Eprocess，然后调用Safe_QueryWhitePID_PsGetProcessId
//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWintePID_ProcessHandle(IN HANDLE ProcessHandle);


//Eprocess_UniqueProcessId
//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWhitePID_PsGetProcessId(IN PEPROCESS pPeprocess);

