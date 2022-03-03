#include "Filter_ZwCreateFile.h"


NTSTATUS NTAPI Filter_ZwCreateFile(OUT PHANDLE  FileHandle, IN ACCESS_MASK  DesiredAccess, IN POBJECT_ATTRIBUTES  ObjectAttributes, OUT PIO_STATUS_BLOCK  IoStatusBlock, IN PLARGE_INTEGER  AllocationSize  OPTIONAL, IN ULONG  FileAttributes, IN ULONG  ShareAccess, IN ULONG  CreateDisposition, IN ULONG  CreateOptions, IN PVOID  EaBuffer  OPTIONAL, IN ULONG  EaLength)
{
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &FileHandle;//�������飬ָ��ջ�����ڱ����������в���
	
	NTSTATUS(NTAPI * ZwCreateFilePtr)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
	//ԭʼ����ִ��ǰ���
	Result = HookProtect_DoFake(ZwCreateFile_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//��ȡԭʼ������ַ
		ZwCreateFilePtr = g_FilterFun_table->OldFunc[ZwCreateFile_FilterIndex];

		//����ԭʼ����
		Result = ZwCreateFilePtr(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
		if (NT_SUCCESS(Result))
		{
			//ԭʼ����ִ�к���
			Result = HookPort_ForRunFuncTable(ZwCreateFile_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;

}