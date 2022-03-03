#include "WhiteProcessList.h"

//�ж��ǲ��ǰ���������
//1������ǣ���������������Ϣ��������Ĩ��
//2��������ǣ�ֱ���˳�
BOOLEAN Safe_DeleteWhiteList_PID(_In_ HANDLE ProcessId)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//�±�����
	NewIrql = KfAcquireSpinLock(&g_White_List.SpinLock);
	//�жϰ���������
	if (g_White_List.Number)
	{
		for (ULONG Index = 0; Index < g_White_List.Number; Index++)
		{
			//�жϾ���Ϸ��ԣ������4�ı�����
			//0x00,0x04,0x08,0x10,0x14�ȵȵĶ����Ƽ�Ȼ��2λ��ԶΪ0����ô΢�������������λ��һ����־λ������ָʾ��ǰ���ֵ��������ں˶����Ǹ������������ҵ���
			if ((((ULONG)ProcessId | 3) ^ 3) == ((g_White_List.PID[Index] | 3) ^ 3))
			{
				//����˳����̵���Ϣ(��һ����ǰŲ)
				for (ULONG i = Index; i <= g_White_List.Number; i++)
				{
					g_White_List.PID[i] = g_White_List.PID[i + 1];			//����PID

				}
				//�������̸���-1
				--g_White_List.Number;
				break;
			}
		}
	}
	KfReleaseSpinLock(&g_White_List.SpinLock, NewIrql);
	return TRUE;
}








// ��Ӱ�����������Ϣ
// �ɹ�����1��ʧ�ܷ���0
BOOLEAN  Safe_InsertWhiteList_PID(_In_ HANDLE ProcessId)
{
	KIRQL NewIrql;
	ULONG Index = 0;						//�±�����
	UCHAR ImageFileNameBuff[0x256] = { 0 };
	NTSTATUS	status, result;
	ULONG GotoFalg;							//����ͬgoto���õ�Falg
	GotoFalg = 1;
	NewIrql = KfAcquireSpinLock(&g_White_List.SpinLock);
	//�жϰ���������
	if (g_White_List.Number < 0xFF)
	{
		//1����������  ����������+1���ɹ�����TRUE������<=0xFE����ʧ��FALSE������>0xFE��
		while ((((ULONG)ProcessId | 3) ^ 3) != ((g_White_List.PID[Index] | 3) ^ 3))
		{
			//�������µİ�������Ϣ�Ͳ���
			if (++Index >= g_White_List.Number)
			{
				//ȡ������2
				GotoFalg = 0;
				//���������̸���<=0xFE
				if (g_White_List.Number <= WHITELISTNUMBER)
				{
					g_White_List.PID[g_White_List.Number] = ProcessId;

					//��������������1
					g_White_List.Number++;
					//�ɹ�����
					result = TRUE;
					break;
				}
				else
				{
					//ʧ�ܷ���
					result = FALSE;
					break;
				}
			}
		}
		//2���Ѵ���
		if (GotoFalg)
		{
			result = TRUE;
		}
	}
	KfReleaseSpinLock(&g_White_List.SpinLock, NewIrql);
	return result;
}


//�ж��ǲ��ǰ�����_EPROCESS
//����ֵ����1������0
BOOLEAN Safe_QueryWhiteEProcess(_In_ PEPROCESS Process)
{
	ULONG result;
	PEPROCESS	ProcObject;
	NTSTATUS	status;
	result = FALSE;
	//�жϰ���������
	if (g_White_List.Number)
	{
		for (ULONG Index = 0; Index < g_White_List.Number; Index++)
		{
			status = PsLookupProcessByProcessId(g_White_List.PID[Index], &ProcObject);
			if (NT_SUCCESS(status))
			{
				ObfDereferenceObject(ProcObject);
				//�ж�Process�Ƿ������������ͬ
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


//�ж��ǲ��ǰ�������PID
//����ֵ����1������0
BOOLEAN Safe_QueryWhitePID(_In_ HANDLE ProcessId)
{
	ULONG result;
	PEPROCESS	ProcObject;
	result = FALSE;
	//�жϰ���������
	if (g_White_List.Number)
	{
		for (ULONG Index = 0; Index < g_White_List.Number; Index++)
		{
			//�ж��ǲ��ǰ���������
			if ((((ULONG)ProcessId | 3) ^ 3) == ((g_White_List.PID[Index] | 3) ^ 3))
			{
				//����Ƿ���TRUE
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
//�ж��ǲ��ǰ�������PID
//����ֵ����1������0
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

//����ProcessHandleת����Eprocess��Ȼ�����Safe_QueryWhitePID_PsGetProcessId
//�ж��ǲ��ǰ�������PID
//����ֵ����1������0
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



