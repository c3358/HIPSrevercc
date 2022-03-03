#include "DoFake.h"


// ����:
//	CallIndex			[INT]ϵͳ������ú�
//	ArgArray			[INT]ԭ�����Ĳ������飬���а�����ջ�б���ĸ÷��������еĲ���		
//	InResult			[INT]����ԭʼ�����ķ���ֵ
//	RetFuncArray		[INT]�������غ���ָ�������,���Ϊ16������ָ��
//	RetFuncArgArray		[INT]�뷵�صĺ���ָ���Ӧ��һ������,�ڵ���RetFuncArray�е�һ������ʱ��Ҫ�����ڱ������ж�Ӧ�Ĳ���
//	RetCount			[INT]�ظ������˼��Σ�һ�㶼��1�Σ�
// ����ֵ:
//	ʹ�� NT_SUCCESS ����в���
//
ULONG NTAPI HookPort_ForRunFuncTable(IN ULONG CallIndex, IN PHANDLE ArgArray, IN NTSTATUS InResult, IN PULONG* RetFuncArray, IN PULONG* RetFuncArgArray, IN ULONG  RetCount)
{
	NTSTATUS Status;
	NTSTATUS(NTAPI * pPostProcessPtr)(ULONG,		// ��    ��: IN ULONG FilterIndex        [In]Filter_ZwOpenFileIndex���
		PHANDLE,								// ��    ��: IN PVOID ArgArray           [In]ZwOpenFile�������׵�ַ
		NTSTATUS,								// ��    ��: IN NTSTATUS Result          [In]����ԭʼZwOpenFile����ֵ
		ULONG									// ��    ��: IN PULONG RetFuncArgArray   [In]]�뷵�صĺ���ָ���Ӧ��һ������,�ڵ���RetFuncArray�е�һ������ʱ��Ҫ�����ڱ������ж�Ӧ�Ĳ���
		);
	Status = InResult;
	if (RetCount)
	{
		pPostProcessPtr = RetFuncArray[0];
		if (pPostProcessPtr && MmIsAddressValid(pPostProcessPtr))
		{
			Status = pPostProcessPtr(CallIndex, ArgArray, InResult, RetFuncArgArray[0]);
		}
	}


	return Status;
}

//��ȡԭʼ��SSDT����
ULONG NTAPI HookPort_GetOriginalServiceRoutine(IN ULONG ServiceIndex)
{
	ULONG Index;
	ULONG ServiceTableBase = 0;
	ULONG Result = 0;
	Index = ServiceIndex;

	//SSDT
	ServiceTableBase = g_SSDTTable_data->SSDT_KeServiceTableBase;
	Result = *(ULONG*)(ServiceTableBase + 4 * Index);
	return Result;
}


NTSTATUS NTAPI HookProtect_DoFake(ULONG CallIndex, PHANDLE ArgArray, PULONG* RetFuncArray, PULONG* RetFuncArgArray, PULONG RetNumber, PULONG Result)
{

	ULONG		Index = 0;
	PULONG		ret_func;
	PULONG		ret_arg;
	NTSTATUS	status;
	PFILTERFUN_TABLE	ptemp_rule;

	NTSTATUS(NTAPI * FilterFunc)(ULONG, PHANDLE, PULONG, PULONG);


	ptemp_rule = g_FilterFun_table;
	//ULONG Number = RetFuncArray - RetFuncArgArray;
	//ִ���Լ�������鹹API������ֱ���ɹ�(һ����0x10�λ���)

	// ���Ҷ�Ӧ�Ĺ��˺�����������
	if (ptemp_rule->FakeFunc[CallIndex])
	{

		ret_func = ret_arg = NULL;

		FilterFunc = (NTSTATUS(NTAPI*)(ULONG, PHANDLE, PULONG, PULONG))ptemp_rule->FakeFunc[CallIndex];

		status = FilterFunc(CallIndex, ArgArray, (PULONG)&ret_func, (PULONG)&ret_arg);

		if (ret_func && RetFuncArray)
		{
			*RetNumber = 1;
			*RetFuncArray++ = ret_func;
			*RetFuncArgArray++ = ret_arg;
		}
		//�жϴ˴ι����Ƿ�������
		if (!status)
		{
			//û���ⷵ��1

			return 1;
		}
	}



	//�˴ι��������⣬����0
	*Result = status;
	return STATUS_SUCCESS;

}