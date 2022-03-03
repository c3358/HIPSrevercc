#include "WhiteRegditList.h"




//��ע������б��в����µı�����
ULONG NTAPI Safe_InsertProtectRegditList(IN PUNICODE_STRING stRegditPath)
{
	KIRQL NewIrql = NULL;
	ULONG Index = NULL;						//�����±�����
	ULONG result = FALSE;					//����ֵ
	//����
	NewIrql = KfAcquireSpinLock(&g_All_ProtectRegdit->SpinLock);

	//1����������  ����������+1���ɹ�����TRUE��ʧ��FALSE
	//2���Ѵ���    ���ӣ�Ĭ�Ϸ���FALSE��ʧ�ܣ�

	while (!g_All_ProtectRegdit->ProtectRegditNumber || RtlCompareUnicodeString(stRegditPath, &g_All_ProtectRegdit->RegditPath[Index], TRUE))
	{
		//�������µİ�������Ϣ�Ͳ���
		if (++Index >= g_All_ProtectRegdit->ProtectRegditNumber)
		{
			//�ж��Ƿ񳬹����ֵ
			if (Index <= PROTECTREGDITMAXIMUM)
			{
				//�嵽�����


				g_All_ProtectRegdit->RegditPath[g_All_ProtectRegdit->ProtectRegditNumber].Buffer = (PWCHAR)ExAllocatePool(NonPagedPool, stRegditPath->Length);
				g_All_ProtectRegdit->RegditPath[g_All_ProtectRegdit->ProtectRegditNumber].Length = 0;
				g_All_ProtectRegdit->RegditPath[g_All_ProtectRegdit->ProtectRegditNumber].MaximumLength = stRegditPath->Length;
				RtlCopyUnicodeString(&g_All_ProtectRegdit->RegditPath[g_All_ProtectRegdit->ProtectRegditNumber], stRegditPath);

				//��������1
				g_All_ProtectRegdit->ProtectRegditNumber++;
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
	//}
	//����
	KfReleaseSpinLock(&g_All_ProtectRegdit->SpinLock, NewIrql);
	return result;
}



//�������Ʋ�ѯ�Ƿ���ע������б���
ULONG NTAPI Safe_QueryProtectRegditList_RegditName(IN PUNICODE_STRING ObjectName)
{

	KIRQL NewIrql;
	ULONG result;
	result = 0;
	//����
	NewIrql = KfAcquireSpinLock(&g_All_ProtectRegdit->SpinLock);
	//�ж���������
	if (g_All_ProtectRegdit->ProtectRegditNumber)
	{
		for (ULONG Index = 0; Index < g_All_ProtectRegdit->ProtectRegditNumber; Index++)
		{
			//�ҵ����ظ��������б����±�
			if (!RtlCompareUnicodeString(ObjectName, &g_All_ProtectRegdit->RegditPath[Index], TRUE))
			{
				result = 1;
				break;
			}
		}
	}
	//����
	KfReleaseSpinLock(&g_All_ProtectRegdit->SpinLock, NewIrql);
	return result;

}





//��¼��־��ע������
NTSTATUS RecordLogRegdit(PCUNICODE_STRING stRegditName, BOOL bFlag, BOOL bOperate)
{
	PWSTR szwTime;
	PUNICODE_STRING szwProcessFileName;
	UNICODE_STRING stTime;

	UCHAR szBuffer1[0x100] = { 0 };
	UCHAR szBuffer2[0x100] = { 0 };
	ANSI_STRING stTimeA;
	stTimeA.Buffer = szBuffer1;
	stTimeA.Length = 0;
	stTimeA.MaximumLength = 0x100;
	ANSI_STRING stProcessFileNameA;
	stProcessFileNameA.Buffer = szBuffer2;
	stProcessFileNameA.Length = 0;
	stProcessFileNameA.MaximumLength = 0x100;

	UCHAR szBuffer3[0x100] = { 0 };
	ANSI_STRING stRegditNameA;
	stRegditNameA.Buffer = szBuffer3;
	stRegditNameA.Length = 0;
	stRegditNameA.MaximumLength = 0x100;

	UCHAR szBuffer[0x300] = { 0 };
	static UCHAR szBufferTo[0x300] = { 0 };




	//��ȡʱ��
	szwTime = GetTimeFunction();
	RtlInitUnicodeString(&stTime, szwTime);
	RtlUnicodeStringToAnsiString(&stTimeA, &stTime, FALSE);


	//��ȡ����·��
	szwProcessFileName = GetCurrentProcessFileName();


	RtlUnicodeStringToAnsiString(&stProcessFileNameA, szwProcessFileName, FALSE);
	RtlUnicodeStringToAnsiString(&stRegditNameA, stRegditName, FALSE);

	strncpy(szBuffer, stTimeA.Buffer, 19);
	strcat(szBuffer + 19, "    ");
	strncat(szBuffer + 23, stProcessFileNameA.Buffer, stProcessFileNameA.Length);
	RtlZeroMemory(szBuffer + 23 + stProcessFileNameA.Length, 260 - stProcessFileNameA.Length);

	strcat(szBuffer + 283, "    ");
	if (bOperate == Operate_OpenKey)
	{
		strcat(szBuffer + 287, "[ע�ᱣ��]����ע��");
	}
	else if (bOperate == Operate_DeleteKey)
	{
		strcat(szBuffer + 287, "[ע�ᱣ��]��ɾ��ע��");
	}
	else if (bOperate == Operate_CreateKey)
	{
		strcat(szBuffer + 287, "[ע�ᱣ��]������ע��");
	}
	else if (bOperate == Operate_RenameKey)
	{
		strcat(szBuffer + 287, "[ע�ᱣ��]������ע��");
	}
	else if (bOperate == Operate_SetValueKey)
	{
		strcat(szBuffer + 287, "[ע�ᱣ��]�����ü�ֵ");
	}
	else if (bOperate == Operate_DeleteValue)
	{
		strcat(szBuffer, "[�ļ�����]��ɾ����ֵ");
	}
	strcat(szBuffer + 307, "    ");
	strncat(szBuffer + 311, stRegditNameA.Buffer, stRegditNameA.Length);
	RtlZeroMemory(szBuffer + 311 + stRegditNameA.Length, 260 - stRegditNameA.Length);
	strcat(szBuffer + 571, "    ");
	if (bFlag == TRUE)
	{
		strcat(szBuffer + 575, "����\r\n");
	}
	else
	{
		strcat(szBuffer + 575, "�ܾ�\r\n");
	}


	if (strcmp(szBuffer, szBufferTo))
	{
		HANDLE hfile;
		OBJECT_ATTRIBUTES objectAttributes;
		IO_STATUS_BLOCK iostatus;

		UNICODE_STRING logFileUnicodeString;

		//��ʼ��UNICODE_STRING�ַ���
		RtlInitUnicodeString(&logFileUnicodeString,
			L"\\??\\C:\\1.log");

		//��ʼ��objectAttributes
		InitializeObjectAttributes(&objectAttributes,
			&logFileUnicodeString,
			OBJ_CASE_INSENSITIVE,//�Դ�Сд����
			NULL,
			NULL);

		//���ļ�
		NTSTATUS ntStatus = ZwCreateFile(&hfile,
			FILE_APPEND_DATA,		//׷��д
			&objectAttributes,
			&iostatus,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN_IF,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (!NT_SUCCESS(ntStatus))
		{
			return ntStatus;
		}
		//д�ļ�
		ntStatus = ZwWriteFile(hfile,
			NULL,
			NULL,
			NULL,
			&iostatus,
			szBuffer,
			581,
			NULL,
			NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			ZwClose(hfile);
			return ntStatus;
		}
		ZwClose(hfile);

		RtlZeroMemory(szBufferTo, 0x300);
		strcpy(szBufferTo, szBuffer);
	}

	KeSetEvent(g_pFileShowEvent, IO_NO_INCREMENT, FALSE);
	return STATUS_SUCCESS;
}