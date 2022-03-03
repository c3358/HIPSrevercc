#include "stdafx.h"
#include <exdisp.h>
#include <comdef.h>
#include "ControlEx.h"

HANDLE g_hEventObjectRule;
HANDLE g_hEventObjectFile;
HANDLE g_hEventObjectProcessIntercept;

typedef struct _INTERCEPT_PROCESS
{
	HANDLE             hParentId;             // �ڻص������б��������Ϣ
	HANDLE             hProcessId;
	UCHAR              ProcFullPath[0x200];          //����·��
	BOOLEAN            bCreate;				  //�Ǵ������̻��ǽ�������
}_INTERCEPT_PROCESS, * PINTERCEPT_PROCESS;
_INTERCEPT_PROCESS g_InterceptProcessData = { 0 };

typedef  DWORD(WINAPI* SUSPENDPROCESS)(HANDLE);
typedef  DWORD(WINAPI* RESUMEPROCESS)(HANDLE);

//�ļ�,ע������������־
DWORD WINAPI _ProtectLogThread(LPVOID lpParam)
{
	DWORD dwReadOfNum = 0;
	OVERLAPPED stOverlapped = { 0 };
	OVERLAPPED stOverlappedTo = { 0 };
	BYTE szBuffer[0x300] = { 0 };
	CPaintManagerUI* m_pm = (CPaintManagerUI*)lpParam;
	CListUI* pFileList = static_cast<CListUI*>(m_pm->FindControl(_T("FileListDemo")));
	CListUI* pRegeditList = static_cast<CListUI*>(m_pm->FindControl(_T("RegditListDemo")));
	CListUI* pInterList = static_cast<CListUI*>(m_pm->FindControl(_T("InterListDemo")));
	CListUI* pOurSelfProtectList = static_cast<CListUI*>(m_pm->FindControl(_T("OurSelfProtectListDemo")));
	
	DWORD dwFileListNum = 0;					//�ļ��б��Ӧ������
	DWORD dwRegeditListNum = 0;					//ע����б��Ӧ������
	DWORD dwInterListNum = 0;					//�����б��Ӧ������
	DWORD dwOurSelfProtectListNum = 0;			//���ұ����б��Ӧ������
	BYTE szTime[0x20] = { 0 };			//ʱ��
	BYTE szDesFileName[260] = { 0 };	//Դ�ļ�·��
	BYTE szSouFileName[260] = { 0 };	//Ŀ���ļ�·��
	BYTE szOperate[0x20] = { 0 };		//����
	BYTE szResult[0x20] = { 0 };		//���

	WaitForSingleObject(g_hEventObjectFile, INFINITE);

	HANDLE hFile = CreateFile(TEXT("C:\\1.log"), FILE_GENERIC_READ,             //  ���ļ�������ļ������
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,					//  ����ʽ�򿪣����������ط���Ҫ��д���ļ�
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		return 0;
	}

	for (int i = 0;;i++)
	{
		stOverlapped = stOverlappedTo;
		if (ReadFile(hFile, szBuffer, 581, &dwReadOfNum, &stOverlapped))
		{
			CListTextElementUI* pListElement = new CListTextElementUI;
			
			
			//��������
			strncpy((char*)szTime, (char*)szBuffer, 19);
			strcpy((char*)szDesFileName, (char*)szBuffer + 23);
			strncpy((char*)szOperate, (char*)szBuffer + 287, 20);
			strcpy((char*)szSouFileName, (char*)szBuffer + 311);
			strncpy((char*)szResult, (char*)szBuffer + 575, 4);

			if (!strncmp((char*)szOperate, "[�ļ�����]", 10))
			{
				pListElement->SetTag(dwFileListNum);
				pFileList->Add(pListElement);
				dwFileListNum++;

			}
			else if (!strncmp((char*)szOperate, "[ע�ᱣ��]", 10))
			{
				pListElement->SetTag(dwRegeditListNum);
				pRegeditList->Add(pListElement);
				dwRegeditListNum++;
			}
			else if (!strncmp((char*)szOperate, "[���籣��]", 10))
			{
				pListElement->SetTag(dwInterListNum);
				pInterList->Add(pListElement);
				dwInterListNum++;
			}
			else if (!strncmp((char*)szOperate, "[���ұ���]", 10))
			{

				pListElement->SetTag(dwOurSelfProtectListNum);
				pOurSelfProtectList->Add(pListElement);
				dwOurSelfProtectListNum++;
			}
			pListElement->SetText(0, (char*)szTime);
			pListElement->SetText(1, (char*)szDesFileName);
			pListElement->SetText(2, (char*)szOperate);
			pListElement->SetText(3, (char*)szSouFileName);
			pListElement->SetText(4, (char*)szResult);

			ZeroMemory(szBuffer, 0x300);
			stOverlappedTo.Offset = 581 * (i + 1);
			stOverlapped = stOverlappedTo;
		}
		else
		{
			i--;
			WaitForSingleObject(g_hEventObjectFile, INFINITE);
		}

	}
	return 0;

}


//������ʾ
DWORD WINAPI _RuleThread(LPVOID lpParam)
{
	DWORD dwReadOfNum = 0;
	OVERLAPPED stOverlapped = { 0 };
	OVERLAPPED stOverlappedTo = { 0 };
	BYTE szBuffer[0x300] = { 0 };
	CPaintManagerUI* m_pm = (CPaintManagerUI*)lpParam;
	CListUI* pList = static_cast<CListUI*>(m_pm->FindControl(_T("RuleListDemo")));


	BYTE szRule[0x20] = { 0 };		//����
	BYTE szFileName[260] = { 0 };	//Ŀ��

	WaitForSingleObject(g_hEventObjectRule, INFINITE);

	//�п��ܴ򿪵�ʱ���ļ���û�д���
	HANDLE hFile = CreateFile(TEXT("C:\\Users\\Administrator\\Desktop\\rule.txt"), FILE_GENERIC_READ,             //  ���ļ�������ļ������
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,													  //  ����ʽ�򿪣����������ط���Ҫ��д���ļ�
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		return 0;
	}

	for (int i = 0;;i++)
	{
		stOverlapped = stOverlappedTo;
		if (ReadFile(hFile, szBuffer, 276, &dwReadOfNum, &stOverlapped))
		{
			CListTextElementUI* pListElement = new CListTextElementUI;
			pListElement->SetTag(i);
			pList->Add(pListElement);


			//��������
			strncpy((char*)szRule, (char*)szBuffer, 10);
			strcpy((char*)szFileName, (char*)szBuffer + 14);

			pListElement->SetText(0, (char*)szRule);
			pListElement->SetText(1, (char*)szFileName);


			ZeroMemory(szBuffer, 0x300);
			stOverlappedTo.Offset += 276;
			stOverlapped = stOverlappedTo;
		}
		else
		{
			i--;
			WaitForSingleObject(g_hEventObjectRule, INFINITE);
		}

	}
	return 0;

}


//����������Ϣ��ʾ
DWORD WINAPI _ProcessInterceptThread(LPVOID lpParam)
{

	DWORD flag = 0;				//�жϽ����Ƿ���ֹ����
	DWORD dwRetLeng = 0;
	BYTE bInBuffer[0x10] = { 0 };
	BYTE szShowProcessIntercept[0x200] = { 0 };
	HANDLE hDevice;
	HANDLE hHandle;
	SUSPENDPROCESS ZwSupendProcess = (SUSPENDPROCESS)GetProcAddress(LoadLibrary(TEXT("ntdll.dll")), (LPCSTR)TEXT("ZwSuspendProcess"));;
	RESUMEPROCESS ZwResumeProcess = (RESUMEPROCESS)GetProcAddress(LoadLibrary(TEXT("ntdll.dll")), (LPCSTR)TEXT("ZwResumeProcess"));;
	CPaintManagerUI* m_pm = (CPaintManagerUI*)lpParam;
	CListUI* pList = static_cast<CListUI*>(m_pm->FindControl(_T("ProcessListDemo")));

	for (int i = 1;;i++)
	{
		WaitForSingleObject(g_hEventObjectProcessIntercept, INFINITE);

		if (i == 1)
		{
			//��ȡ�������
			hDevice = CreateFile(TEXT("\\\\.\\HIPHookProtect"), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
			if (hDevice == INVALID_HANDLE_VALUE)
			{
				return 0;
			}
		}

		//������ͨ�Ż�ȡ����������Ϣ
		if (!DeviceIoControl(
			hDevice,
			IOCTL_GETINTERCEPTDATA,
			bInBuffer, 1,
			&g_InterceptProcessData, sizeof(_INTERCEPT_PROCESS),
			&dwRetLeng, NULL))
		{
			CloseHandle(hDevice);
			return 0;
		}
		//�������
		hHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)g_InterceptProcessData.hProcessId);
		ZwSupendProcess(hHandle);
		strcpy((char*)szShowProcessIntercept, (LPSTR)g_InterceptProcessData.ProcFullPath);
		strcat((char*)szShowProcessIntercept, TEXT("������ͼ�����Ƿ�����"));
		//�ж��Ƿ���������
		if (IDNO == ::MessageBox(NULL, (LPSTR)szShowProcessIntercept, TEXT("HIPTerminator"), MB_ICONWARNING | MB_YESNO))
		{
			flag = 0;
			TerminateProcess(hHandle, 0);
		}
		else
		{
			flag = 1;
			ZwResumeProcess(hHandle);
		}
		CloseHandle(hHandle);
		ZeroMemory(szShowProcessIntercept, 0x200);


		//��ʾ�����̱����б�
		CListTextElementUI* pListElement = new CListTextElementUI;
		pListElement->SetTag(i);
		pList->Add(pListElement);

		pListElement->SetText(0, TEXT("��������"));
		pListElement->SetText(1, (char*)g_InterceptProcessData.ProcFullPath);
		if (flag)
		{
			pListElement->SetText(2, TEXT("����"));
		}
		else
		{
			pListElement->SetText(2, TEXT("��ֹ"));
		}


	}
	CloseHandle(hDevice);
	return 0;
}