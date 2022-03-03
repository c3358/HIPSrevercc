#include "Filter_ZwWriteFile.h"

NTSTATUS NTAPI Filter_ZwWriteFile(
	IN           HANDLE           FileHandle,
	IN HANDLE           Event OPTIONAL,
	IN PIO_APC_ROUTINE  ApcRoutine OPTIONAL,
	IN PVOID            ApcContext OPTIONAL,
	OUT          PIO_STATUS_BLOCK IoStatusBlock,
	OUT          PVOID            Buffer,
	IN           ULONG            Length,
	IN PLARGE_INTEGER   ByteOffset OPTIONAL,
	IN PULONG           Key OPTIONAL)
{
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &FileHandle;//�������飬ָ��ջ�����ڱ����������в���

	NTSTATUS(NTAPI * ZwWriteFilePtr)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
	//ԭʼ����ִ��ǰ���
	Result = HookProtect_DoFake(ZwWriteFile_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//��ȡԭʼ������ַ
		ZwWriteFilePtr = g_FilterFun_table->OldFunc[ZwWriteFile_FilterIndex];

		//����ԭʼ����
		Result = ZwWriteFilePtr(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
		if (NT_SUCCESS(Result))
		{
			//ԭʼ����ִ�к���
			Result = HookPort_ForRunFuncTable(ZwWriteFile_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;

}