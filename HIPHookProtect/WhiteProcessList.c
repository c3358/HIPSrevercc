#include "WhiteProcessList.h"

//判断是不是白名单进程
//1：如果是：将白名单进程信息从数组中抹除
//2、如果不是：直接退出
BOOLEAN Safe_DeleteWhiteList_PID(_In_ HANDLE ProcessId)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//下标索引
	NewIrql = KfAcquireSpinLock(&g_White_List.SpinLock);
	//判断白名单个数
	if (g_White_List.Number)
	{
		for (ULONG Index = 0; Index < g_White_List.Number; Index++)
		{
			//判断句柄合法性（句柄是4的倍数）
			//0x00,0x04,0x08,0x10,0x14等等的二进制既然低2位永远为0，那么微软就利用了这两位做一个标志位，用来指示当前句柄值所代表的内核对象到那个表项数组中找到。
			if ((((ULONG)ProcessId | 3) ^ 3) == ((g_White_List.PID[Index] | 3) ^ 3))
			{
				//清空退出进程的信息(后一个往前挪)
				for (ULONG i = Index; i <= g_White_List.Number; i++)
				{
					g_White_List.PID[i] = g_White_List.PID[i + 1];			//进程PID

				}
				//保护进程个数-1
				--g_White_List.Number;
				break;
			}
		}
	}
	KfReleaseSpinLock(&g_White_List.SpinLock, NewIrql);
	return TRUE;
}








// 添加白名单进程信息
// 成功返回1，失败返回0
BOOLEAN  Safe_InsertWhiteList_PID(_In_ HANDLE ProcessId)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//下标索引
	UCHAR ImageFileNameBuff[0x256] = { 0 };
	NTSTATUS	status, result;
	ULONG GotoFalg;							//不想同goto设置的Falg
	GotoFalg = 1;
	NewIrql = KfAcquireSpinLock(&g_White_List.SpinLock);
	//判断白名单个数
	if (g_White_List.Number < 0xFF)
	{
		//1、新增插入  白名单个数+1，成功返回TRUE（个数<=0xFE），失败FALSE（个数>0xFE）
		while ((((ULONG)ProcessId | 3) ^ 3) != ((g_White_List.PID[Index] | 3) ^ 3))
		{
			//假设是新的白名单信息就插入
			if (++Index >= g_White_List.Number)
			{
				//取消条件2
				GotoFalg = 0;
				//白名单进程个数<=0xFE
				if (g_White_List.Number <= WHITELISTNUMBER)
				{
					g_White_List.PID[g_White_List.Number] = ProcessId;

					//白名单个数自增1
					g_White_List.Number++;
					//成功返回
					result = TRUE;
					break;
				}
				else
				{
					//失败返回
					result = FALSE;
					break;
				}
			}
		}
		//2、已存在
		if (GotoFalg)
		{
			result = TRUE;
		}
	}
	KfReleaseSpinLock(&g_White_List.SpinLock, NewIrql);
	return result;
}


//判断是不是白名单_EPROCESS
//返回值：是1，不是0
BOOLEAN Safe_QueryWhiteEProcess(_In_ PEPROCESS Process)
{
	ULONG result;
	PEPROCESS	ProcObject;
	NTSTATUS	status;
	result = FALSE;
	//判断白名单个数
	if (g_White_List.Number)
	{
		for (ULONG Index = 0; Index < g_White_List.Number; Index++)
		{
			status = PsLookupProcessByProcessId(g_White_List.PID[Index], &ProcObject);
			if (NT_SUCCESS(status))
			{
				ObfDereferenceObject(ProcObject);
				//判断Process是否跟白名单的相同
				if (Process == ProcObject)
				{
					result = TRUE;
					break;
				}

			}
		}
	}
	else
	{
		result = FALSE;
	}
	return result;
}


//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWhitePID(_In_ HANDLE ProcessId)
{
	ULONG result;
	PEPROCESS	ProcObject;
	result = FALSE;
	//判断白名单个数
	if (g_White_List.Number)
	{
		for (ULONG Index = 0; Index < g_White_List.Number; Index++)
		{
			//判断是不是白名单进程
			if ((((ULONG)ProcessId | 3) ^ 3) == ((g_White_List.PID[Index] | 3) ^ 3))
			{
				//如果是返回TRUE
				result = TRUE;
				break;
			}
		}
	}
	else
	{
		result = FALSE;
	}
	return result;
}


//Eprocess_UniqueProcessId
//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWhitePID_PsGetProcessId(IN PEPROCESS pPeprocess)
{
	BOOLEAN        Result = FALSE;
	HANDLE         ProcessId = NULL;
	ProcessId = Safe_pPsGetProcessId(pPeprocess);
	if (ProcessId)
	{
		Result = Safe_QueryWhitePID(ProcessId);
	}
	return Result;
}

//根据ProcessHandle转换成Eprocess，然后调用Safe_QueryWhitePID_PsGetProcessId
//判断是不是白名单的PID
//返回值：是1，不是0
BOOLEAN Safe_QueryWintePID_ProcessHandle(IN HANDLE ProcessHandle)
{
	NTSTATUS       Status;
	BOOLEAN        Result = FALSE;
	Status = STATUS_SUCCESS;
	PEPROCESS pPeprocess = NULL;
	if (ProcessHandle && (Status = ObReferenceObjectByHandle(ProcessHandle, NULL, PsProcessType, UserMode, &pPeprocess, NULL), NT_SUCCESS(Status)))
	{
		Result = Safe_QueryWhitePID_PsGetProcessId(pPeprocess);
		ObfDereferenceObject((PVOID)pPeprocess);
	}
	else
	{
		Result = FALSE;
	}
	return Result;
}



