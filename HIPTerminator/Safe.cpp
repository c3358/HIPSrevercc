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

	//显示防护日志
	int ShowLog();

	//弹出规则添加窗口
	int PopAddRuleWindow(HWND hParent);


	void Init() {
		m_pCloseBtn = static_cast<CButtonUI*>(m_pm.FindControl(_T("closebtn")));
		m_pRestoreBtn = static_cast<CButtonUI*>(m_pm.FindControl(_T("restorebtn")));
		m_pMinBtn = static_cast<CButtonUI*>(m_pm.FindControl(_T("minbtn")));

		g_hEventObjectRule = CreateEvent(NULL, FALSE, FALSE, TEXT("RuleOn"));									//用来同步规则的显示
		g_hEventObjectFile = CreateEvent(NULL, FALSE, FALSE, TEXT("Global\\FileOn"));							//用来同步文件保护的显示
		g_hEventObjectProcessIntercept = CreateEvent(NULL, FALSE, FALSE, TEXT("Global\\ProcessIntercept"));		//用来同步获取进程拦截信息

		//创建规则文件
		HANDLE hFile = CreateFile(TEXT("C:\\Users\\Administrator\\Desktop\\rule.txt"), GENERIC_ALL,             //打开文件，获得文件读句柄
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,												//共享方式打开，避免其他地方需要读写此文件
			NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			::MessageBox(GetHWND(), TEXT("规则文件打开失败"), NULL, MB_OK);
			return;

		}
		CloseHandle(hFile);

		hFile = CreateFile(TEXT("C:\\1.log"), GENERIC_ALL,							//打开文件，获得文件读句柄
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,					//共享方式打开，避免其他地方需要读写此文件
			NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			::MessageBox(GetHWND(), TEXT("日志文件打开失败"), NULL, MB_OK);
			return;

		}
		CloseHandle(hFile);
	}

	void OnPrepare() {
	}



	//控件事件通知例程
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
				//弹出添加规则子窗口
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
		//设置窗口风格
		LONG styleValue = ::GetWindowLong(*this, GWL_STYLE);
		styleValue &= ~WS_CAPTION;
		::SetWindowLong(*this, GWL_STYLE, styleValue | WS_CLIPSIBLINGS | WS_CLIPCHILDREN);

		//窗口句柄与渲染类关联
		m_pm.Init(m_hWnd);
		CDialogBuilder builder;
		CDialogBuilderCallbackEx cb;
		//加载XML并动态创建界面无素，解析skin.xml和UI对象的创建，以及属性的设置
		CControlUI* pRoot = builder.Create(_T("skin.xml"), (UINT)0, &cb, &m_pm);
		ASSERT(pRoot && "Failed to parse XML");

		//附加控件（CControlUI）数据到渲染类的HASH表
		m_pm.AttachDialog(pRoot);
		//增加渲染类的通知处理
		m_pm.AddNotifier(this);

		Init();

		//显示日志
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
		// 有时会在收到WM_NCDESTROY后收到wParam为SC_CLOSE的WM_SYSCOMMAND
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

	//相当于MFC中的AfxWindowProc
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
		//DUILIB库（渲染类）的消息处理函数
		if (m_pm.MessageHandler(uMsg, wParam, lParam, lRes)) return lRes;
		//默认处理
		return CWindowWnd::HandleMessage(uMsg, wParam, lParam);
	}

public:
	CPaintManagerUI m_pm;				//渲染类

private:
	CButtonUI* m_pCloseBtn;
	CButtonUI* m_pRestoreBtn;
	CButtonUI* m_pMinBtn;
	//...
};



//显示日志
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


//弹出添加规则窗口
int SafeFrameWnd::PopAddRuleWindow(HWND hParent)
{
	//模态子窗口（添加规则）
	AddRuleWnd* pAddRuleWnd = new AddRuleWnd();
	pAddRuleWnd->Create(hParent, TEXT("添加规则"), UI_WNDSTYLE_DIALOG, 0L, 0, 0, 0, 0);
	pAddRuleWnd->CenterWindow();
	pAddRuleWnd->ShowModal();
	delete pAddRuleWnd;
	return TRUE;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPSTR /*lpCmdLine*/, int nCmdShow)
{
	//下面设置的渲染类的成员的都是静态成员
	//设置实例句柄（与渲染类相关，渲染类就是用来绘图的）
	CPaintManagerUI::SetInstance(hInstance);
	//设置资源所在路径
	CPaintManagerUI::SetResourcePath(CPaintManagerUI::GetInstancePath() + _T("SafeRes"));
	//设置资源包
	CPaintManagerUI::SetResourceZip(_T("SafeRes.zip"));

	//初始化COM库
	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;

	//创建窗口类
	SafeFrameWnd* pFrame = new SafeFrameWnd();
	if (pFrame == NULL) return 0;

	//创建主窗口
	pFrame->Create(NULL, _T("主动防御系统1.0"), UI_WNDSTYLE_FRAME, 0L, 0, 0, 800, 572);

	//窗口居中显示
	pFrame->CenterWindow();
	::ShowWindow(*pFrame, SW_SHOW);

	//处理消息循环
	CPaintManagerUI::MessageLoop();

	//退出程序并释放COM库
	::CoUninitialize();
	return 0;
}

