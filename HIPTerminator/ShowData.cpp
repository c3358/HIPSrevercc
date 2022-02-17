#include "stdafx.h"
#include <exdisp.h>
#include <comdef.h>
#include "ControlEx.h"

HANDLE g_hEventObjectRule;
HANDLE g_hEventObjectFile;
HANDLE g_hEventObjectProcessIntercept;

typedef struct _INTERCEPT_PROCESS
{
	HANDLE             hParentId;             // 在回调函数中保存进程信息
	HANDLE             hProcessId;
	UCHAR              ProcFullPath[0x200];          //进程路径
	BOOLEAN            bCreate;				  //是创建进程还是结束进程
}_INTERCEPT_PROCESS, * PINTERCEPT_PROCESS;
_INTERCEPT_PROCESS g_InterceptProcessData = { 0 };

typedef  DWORD(WINAPI* SUSPENDPROCESS)(HANDLE);
typedef  DWORD(WINAPI* RESUMEPROCESS)(HANDLE);

//文件防护日志
DWORD WINAPI _FileLogThread(LPVOID lpParam)
{
	DWORD dwReadOfNum = 0;
	OVERLAPPED stOverlapped = { 0 };
	OVERLAPPED stOverlappedTo = { 0 };
	BYTE szBuffer[0x300] = { 0 };
	CPaintManagerUI* m_pm = (CPaintManagerUI*)lpParam;
	CListUI* pList = static_cast<CListUI*>(m_pm->FindControl(_T("FileListDemo")));

	BYTE szTime[0x20] = { 0 };			//时间
	BYTE szDesFileName[260] = { 0 };	//源文件路径
	BYTE szSouFileName[260] = { 0 };	//目的文件路径
	BYTE szOperate[0x20] = { 0 };		//操作
	BYTE szResult[0x20] = { 0 };		//结果

	WaitForSingleObject(g_hEventObjectFile, INFINITE);

	HANDLE hFile = CreateFile(TEXT("C:\\1.log"), FILE_GENERIC_READ,             //  打开文件，获得文件读句柄
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,					//  共享方式打开，避免其他地方需要读写此文件
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
			pListElement->SetTag(i);
			pList->Add(pListElement);


			//解析数据
			strncpy((char*)szTime, (char*)szBuffer, 19);
			strcpy((char*)szDesFileName, (char*)szBuffer + 23);
			strncpy((char*)szOperate, (char*)szBuffer + 287, 20);
			strcpy((char*)szSouFileName, (char*)szBuffer + 311);
			strncpy((char*)szResult, (char*)szBuffer + 575, 4);

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


//规则显示
DWORD WINAPI _RuleThread(LPVOID lpParam)
{
	DWORD dwReadOfNum = 0;
	OVERLAPPED stOverlapped = { 0 };
	OVERLAPPED stOverlappedTo = { 0 };
	BYTE szBuffer[0x300] = { 0 };
	CPaintManagerUI* m_pm = (CPaintManagerUI*)lpParam;
	CListUI* pList = static_cast<CListUI*>(m_pm->FindControl(_T("RuleListDemo")));


	BYTE szRule[0x20] = { 0 };		//规则
	BYTE szFileName[260] = { 0 };	//目标

	WaitForSingleObject(g_hEventObjectRule, INFINITE);

	//有可能打开的时候，文件还没有创建
	HANDLE hFile = CreateFile(TEXT("C:\\Users\\Administrator\\Desktop\\rule.txt"), FILE_GENERIC_READ,             //  打开文件，获得文件读句柄
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,													  //  共享方式打开，避免其他地方需要读写此文件
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


			//解析数据
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


//进程拦截信息显示
DWORD WINAPI _ProcessInterceptThread(LPVOID lpParam)
{

	DWORD flag = 0;				//判断进程是否被阻止运行
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
			//获取驱动句柄
			hDevice = CreateFile(TEXT("\\\\.\\360SelfProtection"), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
			if (hDevice == INVALID_HANDLE_VALUE)
			{
				return 0;
			}
		}

		//与驱动通信获取进程拦截信息
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
		//挂起进程
		hHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)g_InterceptProcessData.hProcessId);
		ZwSupendProcess(hHandle);
		strcpy((char*)szShowProcessIntercept, (LPSTR)g_InterceptProcessData.ProcFullPath);
		strcat((char*)szShowProcessIntercept, TEXT("进程试图运行是否允许？"));
		//判断是否允许运行
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


		//显示到进程保护列表
		CListTextElementUI* pListElement = new CListTextElementUI;
		pListElement->SetTag(i);
		pList->Add(pListElement);

		pListElement->SetText(0, TEXT("创建进程"));
		pListElement->SetText(1, (char*)g_InterceptProcessData.ProcFullPath);
		if (flag)
		{
			pListElement->SetText(2, TEXT("允许"));
		}
		else
		{
			pListElement->SetText(2, TEXT("阻止"));
		}


	}
	CloseHandle(hDevice);
	return 0;
}