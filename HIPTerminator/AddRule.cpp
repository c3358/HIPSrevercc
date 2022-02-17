#include "stdafx.h"
#include <exdisp.h>
#include <comdef.h>
#include "ControlEx.h"
#include "AddRule.h"

extern HANDLE g_hEventObjectRule;
extern HANDLE g_hEventObjectFile;



void AddRuleWnd::Init() {
	m_pCloseBtn = static_cast<CButtonUI*>(m_pmAddRule.FindControl(_T("closebtn")));
}

//����ӡ���ť��������
void AddRuleWnd::OnAddRuleButton()
{
	DWORD dwPid;
	DWORD dwWriteOfNum = 0;
	BYTE bOutBuffer[0x10] = { 0 };
	DWORD dwRetLeng = 0;
	BYTE szBufferWrite[0x200] = { 0 };
	DWORD dwReadOfNum = 0;
	OVERLAPPED stOverlappedRead = { 0 };
	BYTE szBufferRead[0x200] = { 0 };


	CEditUI* pEditRuleName = static_cast<CEditUI*>(m_pmAddRule.FindControl(_T("RuleName")));
	pEditRuleName->SetEnabled(false);
	CDuiString szRuleName = pEditRuleName->GetText();


	CEditUI* pEditTargetName = static_cast<CEditUI*>(m_pmAddRule.FindControl(_T("TargetName")));
	pEditTargetName->SetEnabled(false);
	CDuiString szTargetName = pEditTargetName->GetText();


	//������ĺϷ���
	if (strncmp(szRuleName, "1", 1) && strncmp(szRuleName, "2", 1) && strncmp(szRuleName, "3", 1))
	{
		::MessageBox(GetHWND(), TEXT("�����������"), NULL, MB_OK);
		return;
	}



	HANDLE hFile = CreateFile(TEXT("C:\\Users\\Administrator\\Desktop\\rule.txt"), GENERIC_ALL,					//���ļ�������ļ������
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,													//����ʽ�򿪣����������ط���Ҫ��д���ļ�
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		::MessageBox(GetHWND(), TEXT("�����ļ���ʧ��"), NULL, MB_OK);
		return;
	}


	if (!strncmp(szRuleName, "1", 1))
	{
		strcat((char*)szBufferWrite, TEXT("�ļ�����  "));
	}
	else if (!strncmp(szRuleName, "2", 1))
	{
		strcat((char*)szBufferWrite, TEXT("���̰�����"));

	}
	else if (!strncmp(szRuleName, "3", 1))
	{
		strcat((char*)szBufferWrite, TEXT("ע�����"));
	}
	strcat((char*)szBufferWrite + 10, "    ");
	strcat((char*)szBufferWrite + 14, szTargetName);
	ZeroMemory((char*)szBufferWrite + 14 + szTargetName.GetLength(), 260 - szTargetName.GetLength());
	strcat((char*)szBufferWrite + 274, "\r\n");



	//��ȡ�������
	HANDLE hDevice = CreateFile(TEXT("\\\\.\\360SelfProtection"), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return;
	}
	//֪ͨ���������жϹ����Ƿ���ӳɹ�
	if (!strncmp(szRuleName, "1", 1))						//����ļ�������
	{

		if (!DeviceIoControl(
			hDevice,
			IOCTL_SETFILEWHITE,
			(LPVOID)szTargetName.GetData(),
			szTargetName.GetLength(),
			bOutBuffer, 0x4,
			&dwRetLeng, NULL)
			|| *(DWORD*)bOutBuffer == 0)
		{
			CloseHandle(hDevice);
			return;
		}
	}
	else if (!strncmp(szRuleName, "2", 1))					//��ӽ��̰�����
	{
		dwPid = atoi(szTargetName.GetData());
		if (!DeviceIoControl(
			hDevice,
			IOCTL_SETPROCESSWHITE,
			&dwPid,
			0x4,
			bOutBuffer, 0x4,
			&dwRetLeng, NULL)
			|| *(DWORD*)bOutBuffer == 0)
		{
			CloseHandle(hDevice);
			return;
		}
	}
	CloseHandle(hDevice);



	//׷��д�뵽�����ļ���
	SetFilePointer(hFile, NULL, NULL, FILE_END);
	if (!WriteFile(hFile, szBufferWrite, 276, &dwWriteOfNum, NULL))
	{
		::MessageBox(GetHWND(), TEXT("�����ļ�д��ʧ��"), NULL, MB_OK);
		return;
	}
	CloseHandle(hFile);


	//֪ͨ��ʾ�����̶߳��ļ�
	SetEvent(g_hEventObjectRule);
	return;

}


//��ɾ������ť��������
void AddRuleWnd::OnDeleteRuleButton() {
}


void AddRuleWnd::Notify(TNotifyUI& msg)
{
	if (msg.sType == _T("windowinit")) OnPrepare();
	else if (msg.sType == _T("click")) {
		if (msg.pSender == m_pCloseBtn) {
			//�رմ���
			DestroyWindow(GetHWND());
			return;
		}

		if (_tcsicmp(msg.pSender->GetName(), _T("Add")) == 0) {
			OnAddRuleButton();
			return;
		}
		if (_tcsicmp(msg.pSender->GetName(), _T("Delete")) == 0) {
			OnDeleteRuleButton();
			return;
		}

	}

}



LRESULT AddRuleWnd::OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	//���ô��ڷ��
	LONG styleValue = ::GetWindowLong(*this, GWL_STYLE);
	styleValue &= ~WS_CAPTION;
	::SetWindowLong(*this, GWL_STYLE, styleValue | WS_CLIPSIBLINGS | WS_CLIPCHILDREN);

	//���ھ������Ⱦ�����
	m_pmAddRule.Init(m_hWnd);
	CDialogBuilder builder;
	CDialogBuilderCallbackEx cb;
	//����XML����̬�����������أ�����skin.xml��UI����Ĵ������Լ����Ե�����
	CControlUI* pRoot = builder.Create(_T("AddRule.xml"), (UINT)0, &cb, &m_pmAddRule);
	ASSERT(pRoot && "Failed to parse XML");

	//���ӿؼ���CControlUI�����ݵ���Ⱦ���HASH��
	m_pmAddRule.AttachDialog(pRoot);
	//������Ⱦ���֪ͨ����
	m_pmAddRule.AddNotifier(this);

	Init();

	return 0;
}



LRESULT AddRuleWnd::OnNcActivate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	if (::IsIconic(*this)) bHandled = FALSE;
	return (wParam == 0) ? TRUE : FALSE;
}

LRESULT AddRuleWnd::OnNcCalcSize(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	return 0;
}

LRESULT AddRuleWnd::OnNcPaint(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	return 0;
}



LRESULT AddRuleWnd::OnNcHitTest(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	POINT pt; pt.x = GET_X_LPARAM(lParam); pt.y = GET_Y_LPARAM(lParam);
	::ScreenToClient(*this, &pt);

	RECT rcClient;
	::GetClientRect(*this, &rcClient);

	RECT rcCaption = m_pmAddRule.GetCaptionRect();
	if (pt.x >= rcClient.left + rcCaption.left && pt.x < rcClient.right - rcCaption.right \
		&& pt.y >= rcCaption.top && pt.y < rcCaption.bottom) {
		CControlUI* pControl = static_cast<CControlUI*>(m_pmAddRule.FindControl(pt));
		if (pControl && _tcscmp(pControl->GetClass(), DUI_CTR_BUTTON) != 0)
			return HTCAPTION;
	}

	return HTCLIENT;
}



LRESULT AddRuleWnd::OnSize(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	SIZE szRoundCorner = m_pmAddRule.GetRoundCorner();
	if (!::IsIconic(*this) && (szRoundCorner.cx != 0 || szRoundCorner.cy != 0)) {
		CDuiRect rcWnd;
		::GetWindowRect(*this, &rcWnd);
		rcWnd.Offset(-rcWnd.left, -rcWnd.top);
		rcWnd.right++; rcWnd.bottom++;
		HRGN hRgn = ::CreateRoundRectRgn(rcWnd.left, rcWnd.top, rcWnd.right, rcWnd.bottom, szRoundCorner.cx, szRoundCorner.cy);
		::SetWindowRgn(*this, hRgn, TRUE);
		::DeleteObject(hRgn);
	}

	bHandled = FALSE;
	return 0;
}


//�൱��MFC�е�AfxWindowProc
LRESULT AddRuleWnd::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	LRESULT lRes = 0;
	BOOL bHandled = TRUE;
	switch (uMsg) {
	case WM_CREATE:        lRes = OnCreate(uMsg, wParam, lParam, bHandled); break;
	case WM_NCACTIVATE:    lRes = OnNcActivate(uMsg, wParam, lParam, bHandled); break;
	case WM_NCCALCSIZE:    lRes = OnNcCalcSize(uMsg, wParam, lParam, bHandled); break;
	case WM_NCPAINT:       lRes = OnNcPaint(uMsg, wParam, lParam, bHandled); break;
	case WM_NCHITTEST:     lRes = OnNcHitTest(uMsg, wParam, lParam, bHandled); break;
	case WM_SIZE:          lRes = OnSize(uMsg, wParam, lParam, bHandled); break;
	default:
		bHandled = FALSE;
	}
	if (bHandled) return lRes;
	//DUILIB�⣨��Ⱦ�ࣩ����Ϣ������
	if (m_pmAddRule.MessageHandler(uMsg, wParam, lParam, lRes)) return lRes;
	//Ĭ�ϴ���
	return CWindowWnd::HandleMessage(uMsg, wParam, lParam);
}