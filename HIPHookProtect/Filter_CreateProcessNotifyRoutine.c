#include "Filter_CreateProcessNotifyRoutine.h"

NTSTATUS NTAPI Filter_CreateProcessNotifyRoutine(IN HANDLE  ParentId, IN HANDLE  ProcessId, IN BOOLEAN  Create)
{
	NTSTATUS result;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };

	ULONG		RetCount;
	PVOID		pArgArray = &ParentId;//�������飬ָ��ջ�����ڱ����������в���
	
	result = HookProtect_DoFake(CreateProcessNotifyRoutineIndex, pArgArray, 0, 0, 0, 0);

	
	
	return result;
}