#include "Filter_ZwSetInformationFile.h"

NTSTATUS NTAPI Filter_ZwSetInformationFile(
	IN  HANDLE                 FileHandle,
	OUT PIO_STATUS_BLOCK       IoStatusBlock,
	IN  PVOID                  FileInformation,
	IN  ULONG                  Length,
	IN  FILE_INFORMATION_CLASS FileInformationClass
) {
	NTSTATUS Result, OutResult;

	PULONG   FuncTable[16] = { 0 };
	PULONG   ArgTable[16] = { 0 };
	ULONG    RetNumber = NULL;
	PVOID    pArgArray = &FileHandle;//�������飬ָ��ջ�����ڱ����������в���

	NTSTATUS(NTAPI * ZwSetInformationFilePtr)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
	//ԭʼ����ִ��ǰ���
	Result = HookProtect_DoFake(ZwSetInformationFile_FilterIndex, pArgArray, FuncTable, ArgTable, &RetNumber, &OutResult);
	if (Result)
	{
		//��ȡԭʼ������ַ
		ZwSetInformationFilePtr = g_FilterFun_table->OldFunc[ZwSetInformationFile_FilterIndex];

		//����ԭʼ����
		Result = ZwSetInformationFilePtr(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
		if (NT_SUCCESS(Result))
		{
			//ԭʼ����ִ�к���
			Result = HookPort_ForRunFuncTable(ZwSetInformationFile_FilterIndex, pArgArray, Result, FuncTable, ArgTable, RetNumber);
		}
	}
	else
	{
		Result = OutResult;
	}
	return Result;






}