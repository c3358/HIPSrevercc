#include "DoFake.h"


// 参数:
//	CallIndex			[INT]系统服务调用号
//	ArgArray			[INT]原函数的参数数组，其中包含了栈中保存的该服务函数所有的参数		
//	InResult			[INT]调用原始函数的返回值
//	RetFuncArray		[INT]函数返回函数指针的数组,最多为16个函数指针
//	RetFuncArgArray		[INT]与返回的函数指针对应的一个参数,在调用RetFuncArray中的一个函数时需要传递在本参数中对应的参数
//	RetCount			[INT]重复调用了几次，一般都是1次，
// 返回值:
//	使用 NT_SUCCESS 宏进行测试
//
ULONG NTAPI HookPort_ForRunFuncTable(IN ULONG CallIndex, IN PHANDLE ArgArray, IN NTSTATUS InResult, IN PULONG* RetFuncArray, IN PULONG* RetFuncArgArray, IN ULONG  RetCount)
{
	NTSTATUS Status;
	NTSTATUS(NTAPI * pPostProcessPtr)(ULONG,		// 参    数: IN ULONG FilterIndex        [In]Filter_ZwOpenFileIndex序号
		PHANDLE,								// 参    数: IN PVOID ArgArray           [In]ZwOpenFile参数的首地址
		NTSTATUS,								// 参    数: IN NTSTATUS Result          [In]调用原始ZwOpenFile返回值
		ULONG									// 参    数: IN PULONG RetFuncArgArray   [In]]与返回的函数指针对应的一个参数,在调用RetFuncArray中的一个函数时需要传递在本参数中对应的参数
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

//获取原始的SSDT服务
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
	//执行自己构造的虚构API函数，直到成功(一共有0x10次机会)

	// 查找对应的过滤函数，并调用
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
		//判断此次过滤是否有问题
		if (!status)
		{
			//没问题返回1

			return 1;
		}
	}



	//此次过滤有问题，返回0
	*Result = status;
	return STATUS_SUCCESS;

}