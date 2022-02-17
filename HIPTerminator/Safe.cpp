#include "stdafx.h"
#include <exdisp.h>
#include <comdef.h>
#include "ControlEx.h"
#include"AddRule.h"

extern HANDLE g_hEventObjectRule;
extern HANDLE g_hEventObjectFile;
extern HANDLE g_hEventObjectProcessIntercept;

class SafeFrameWnd : public CWindowWnd, public INotifyUI
{
public:
	SafeFrameWnd() { };
	LPCTSTR GetWindowClassName() const { return _T("UIMainFrame"); };
	UINT GetClassStyle() const { return CS_DBLCLKS; };
	void OnFinalMessage(HWND /*hWnd*/) { delete this; };

	//��ʾ������־
	int ShowLog();

	//����������Ӵ���
	int PopAddRuleWindow(HWND hParent);


	void Init() {
		m_pCloseBtn = static_cast<CButtonUI*>(m_pm.FindControl(_T("closebtn")));
		m_pRestoreBtn = static_cast<CButtonUI*>(m_pm.FindControl(_T("restorebtn")));
		m_pMinBtn = static_cast<CButtonUI*>(m_pm.FindControl(_T("minbtn")));

		g_hEventObjectRule = CreateEvent(NULL, FALSE, FALSE, TEXT("RuleOn"));									//����ͬ���������ʾ
		g_hEventObjectFile = CreateEvent(NULL, FALSE, FALSE, TEXT("Global\\FileOn"));							//����ͬ���ļ���������ʾ
		g_hEventObjectProcessIntercept = CreateEvent(NULL, FALSE, FALSE, TEXT("Global\\ProcessIntercept"));		//����ͬ����ȡ����������Ϣ

		//���������ļ�
		HANDLE hFile = CreateFile(TEXT("C:\\Users\\Administrator\\Desktop\\rule.txt"), GENERIC_ALL,             //���ļ�������ļ������
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,												//����ʽ�򿪣����������ط���Ҫ��д���ļ�
			NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			::MessageBox(GetHWND(), TEXT("�����ļ���ʧ��"), NULL, MB_OK);
			return;

		}
		CloseHandle(hFile);

		hFile = CreateFile(TEXT("C:\\1.log"), GENERIC_ALL,							//���ļ�������ļ������
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,					//����ʽ�򿪣����������ط���Ҫ��д���ļ�
			NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			::MessageBox(GetHWND(), TEXT("��־�ļ���ʧ��"), NULL, MB_OK);
			return;

		}
		CloseHandle(hFile);
	}

	void OnPrepare() {
	}



	//�ؼ��¼�֪ͨ����
	void Notify(TNotifyUI& msg)
	{
		if (msg.sType == _T("windowinit")) OnPrepare();
		else if (msg.sType == _T("click")) {
			if (msg.pSender == m_pCloseBtn) {
				PostQuitMessage(0);
				return;
			}
			else if (msg.pSender == m_pMinBtn) {
				SendMessage(WM_SYSCOMMAND, SC_MINIMIZE, 0); return;
			}
			else if (msg.pSender == m_pRestoreBtn) {
				SendMessage(WM_SYSCOMMAND, SC_RESTORE, 0); return;
			}
			else if (_tcsicmp(msg.pSender->GetName(), _T("Add_Rule")) == 0) {
				//������ӹ����Ӵ���
				PopAddRuleWindow(GetHWND());
				return;
			}
		}
		else if (msg.sType == _T("selectchanged"))
		{
			CDuiString name = msg.pSender->GetName();
			CTabLayoutUI* pControl = static_cast<CTabLayoutUI*>(m_pm.FindControl(_T("switch")));
			if (name == _T("FileProtect"))
				pControl->SelectItem(0);
			else if (name == _T("RegisterProtect"))
				pControl->SelectItem(1);
			else if (name == _T("ProcessProtect"))
				pControl->SelectItem(2);
			else if (name == _T("InterProtect"))
				pControl->SelectItem(3);
			else if (name == _T("OurselfProtect"))
				pControl->SelectItem(4);
			else if (name == _T("HookProtect"))
				pControl->SelectItem(5);
			else if (name == _T("Rule"))
				pControl->SelectItem(6);
		}
	}

	LRESULT OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		//���ô��ڷ��
		LONG styleValue = ::GetWindowLong(*this, GWL_STYLE);
		styleValue &= ~WS_CAPTION;
		::SetWindowLong(*this, GWL_STYLE, styleValue | WS_CLIPSIBLINGS | WS_CLIPCHILDREN);

		//���ھ������Ⱦ�����
		m_pm.Init(m_hWnd);
		CDialogBuilder builder;
		CDialogBuilderCallbackEx cb;
		//����XML����̬�����������أ�����skin.xml��UI����Ĵ������Լ����Ե�����
		CControlUI* pRoot = builder.Create(_T("skin.xml"), (UINT)0, &cb, &m_pm);
		ASSERT(pRoot && "Failed to parse XML");

		//���ӿؼ���CControlUI�����ݵ���Ⱦ���HASH��
		m_pm.AttachDialog(pRoot);
		//������Ⱦ���֪ͨ����
		m_pm.AddNotifier(this);

		Init();

		//��ʾ��־
		ShowLog();
		return 0;
	}

	LRESULT OnClose(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		bHandled = FALSE;
		return 0;
	}

	LRESULT OnDestroy(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		::PostQuitMessage(0L);

		bHandled = FALSE;
		return 0;
	}

	LRESULT OnNcActivate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		if (::IsIconic(*this)) bHandled = FALSE;
		return (wParam == 0) ? TRUE : FALSE;
	}

	LRESULT OnNcCalcSize(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		return 0;
	}

	LRESULT OnNcPaint(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		return 0;
	}

	LRESULT OnNcHitTest(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		POINT pt; pt.x = GET_X_LPARAM(lParam); pt.y = GET_Y_LPARAM(lParam);
		::ScreenToClient(*this, &pt);

		RECT rcClient;
		::GetClientRect(*this, &rcClient);
		RECT rcCaption = m_pm.GetCaptionRect();
		if (pt.x >= rcClient.left + rcCaption.left && pt.x < rcClient.right - rcCaption.right \
			&& pt.y >= rcCaption.top && pt.y < rcCaption.bottom) {
			CControlUI* pControl = static_cast<CControlUI*>(m_pm.FindControl(pt));
			if (pControl && _tcscmp(pControl->GetClass(), DUI_CTR_BUTTON) != 0 &&
				_tcscmp(pControl->GetClass(), DUI_CTR_OPTION) != 0 &&
				_tcscmp(pControl->GetClass(), DUI_CTR_TEXT) != 0)
				return HTCAPTION;
		}

		return HTCLIENT;
	}

	LRESULT OnSize(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		SIZE szRoundCorner = m_pm.GetRoundCorner();
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

	LRESULT OnGetMinMaxInfo(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		MONITORINFO oMonitor = {};
		oMonitor.cbSize = sizeof(oMonitor);
		::GetMonitorInfo(::MonitorFromWindow(*this, MONITOR_DEFAULTTOPRIMARY), &oMonitor);
		CDuiRect rcWork = oMonitor.rcWork;
		rcWork.Offset(-oMonitor.rcMonitor.left, -oMonitor.rcMonitor.top);

		LPMINMAXINFO lpMMI = (LPMINMAXINFO)lParam;
		lpMMI->ptMaxPosition.x = rcWork.left;
		lpMMI->ptMaxPosition.y = rcWork.top;
		lpMMI->ptMaxSize.x = rcWork.right;
		lpMMI->ptMaxSize.y = rcWork.bottom;

		bHandled = FALSE;
		return 0;
	}

	LRESULT OnSysCommand(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
	{
		// ��ʱ�����յ�WM_NCDESTROY���յ�wParamΪSC_CLOSE��WM_SYSCOMMAND
		if (wParam == SC_CLOSE) {
			::PostQuitMessage(0L);
			bHandled = TRUE;
			return 0;
		}
		BOOL bZoomed = ::IsZoomed(*this);
		LRESULT lRes = CWindowWnd::HandleMessage(uMsg, wParam, lParam);
		if (::IsZoomed(*this) != bZoomed) {
			if (!bZoomed) {
				CControlUI* pControl = static_cast<CControlUI*>(m_pm.FindControl(_T("maxbtn")));
				if (pControl) pControl->SetVisible(false);
				pControl = static_cast<CControlUI*>(m_pm.FindControl(_T("restorebtn")));
				if (pControl) pControl->SetVisible(true);
			}
			else {
				CControlUI* pControl = static_cast<CControlUI*>(m_pm.FindControl(_T("maxbtn")));
				if (pControl) pControl->SetVisible(true);
				pControl = static_cast<CControlUI*>(m_pm.FindControl(_T("restorebtn")));
				if (pControl) pControl->SetVisible(false);
			}
		}
		return lRes;
	}

	//�൱��MFC�е�AfxWindowProc
	LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		LRESULT lRes = 0;
		BOOL bHandled = TRUE;
		switch (uMsg) {
		case WM_CREATE:        lRes = OnCreate(uMsg, wParam, lParam, bHandled); break;
		case WM_CLOSE:         lRes = OnClose(uMsg, wParam, lParam, bHandled); break;
		case WM_DESTROY:       lRes = OnDestroy(uMsg, wParam, lParam, bHandled); break;
		case WM_NCACTIVATE:    lRes = OnNcActivate(uMsg, wParam, lParam, bHandled); break;
		case WM_NCCALCSIZE:    lRes = OnNcCalcSize(uMsg, wParam, lParam, bHandled); break;
		case WM_NCPAINT:       lRes = OnNcPaint(uMsg, wParam, lParam, bHandled); break;
		case WM_NCHITTEST:     lRes = OnNcHitTest(uMsg, wParam, lParam, bHandled); break;
		case WM_SIZE:          lRes = OnSize(uMsg, wParam, lParam, bHandled); break;
		case WM_GETMINMAXINFO: lRes = OnGetMinMaxInfo(uMsg, wParam, lParam, bHandled); break;
		case WM_SYSCOMMAND:    lRes = OnSysCommand(uMsg, wParam, lParam, bHandled); break;
		default:
			bHandled = FALSE;
		}
		if (bHandled) return lRes;
		//DUILIB�⣨��Ⱦ�ࣩ����Ϣ������
		if (m_pm.MessageHandler(uMsg, wParam, lParam, lRes)) return lRes;
		//Ĭ�ϴ���
		return CWindowWnd::HandleMessage(uMsg, wParam, lParam);
	}

public:
	CPaintManagerUI m_pm;				//��Ⱦ��

private:
	CButtonUI* m_pCloseBtn;
	CButtonUI* m_pRestoreBtn;
	CButtonUI* m_pMinBtn;
	//...
};



//��ʾ��־
int SafeFrameWnd::ShowLog()
{
	DWORD dwThreadId = NULL;
	HANDLE dwThreadHandle = NULL;
	dwThreadHandle = CreateThread(NULL, NULL, _FileLogThread, &m_pm, NULL, &dwThreadId);
	if (!dwThreadHandle)
	{
		return FALSE;
	}


	dwThreadHandle = NULL;
	dwThreadHandle = CreateThread(NULL, NULL, _RuleThread, &m_pm, NULL, &dwThreadId);
	if (!dwThreadHandle)
	{
		return FALSE;
	}

	dwThreadHandle = NULL;
	dwThreadHandle = CreateThread(NULL, NULL, _ProcessInterceptThread, &m_pm, NULL, &dwThreadId);
	if (!dwThreadHandle)
	{
		return FALSE;
	}

	return TRUE;
}


//������ӹ��򴰿�
int SafeFrameWnd::PopAddRuleWindow(HWND hParent)
{
	//ģ̬�Ӵ��ڣ���ӹ���
	AddRuleWnd* pAddRuleWnd = new AddRuleWnd();
	pAddRuleWnd->Create(hParent, TEXT("��ӹ���"), UI_WNDSTYLE_DIALOG, 0L, 0, 0, 0, 0);
	pAddRuleWnd->CenterWindow();
	pAddRuleWnd->ShowModal();
	delete pAddRuleWnd;
	return TRUE;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPSTR /*lpCmdLine*/, int nCmdShow)
{
	//�������õ���Ⱦ��ĳ�Ա�Ķ��Ǿ�̬��Ա
	//����ʵ�����������Ⱦ����أ���Ⱦ�����������ͼ�ģ�
	CPaintManagerUI::SetInstance(hInstance);
	//������Դ����·��
	CPaintManagerUI::SetResourcePath(CPaintManagerUI::GetInstancePath() + _T("SafeRes"));
	//������Դ��
	CPaintManagerUI::SetResourceZip(_T("SafeRes.zip"));

	//��ʼ��COM��
	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;

	//����������
	SafeFrameWnd* pFrame = new SafeFrameWnd();
	if (pFrame == NULL) return 0;

	//����������
	pFrame->Create(NULL, _T("��������ϵͳ1.0"), UI_WNDSTYLE_FRAME, 0L, 0, 0, 800, 572);

	//���ھ�����ʾ
	pFrame->CenterWindow();
	::ShowWindow(*pFrame, SW_SHOW);

	//������Ϣѭ��
	CPaintManagerUI::MessageLoop();

	//�˳������ͷ�COM��
	::CoUninitialize();
	return 0;
}

