#pragma once
#include "stdafx.h"

class FileShowUI : public CContainerUI 
{
public:
	FileShowUI()
	{
		
		CDialogBuilder builder;
		CContainerUI* pFileShow = static_cast<CContainerUI*>(builder.Create(_T("FileShow.xml"), (UINT)0));
		if(pFileShow) {
			this->Add(pFileShow);
		}
		else {
			this->RemoveAll();
			return;
		}
	}
};

class RegditShowUI : public CContainerUI
{
public:
	RegditShowUI()
	{
		CDialogBuilder builder;
		CContainerUI* pRegditShow = static_cast<CContainerUI*>(builder.Create(_T("RegditShow.xml"), (UINT)0));
		if (pRegditShow) {
			this->Add(pRegditShow);
		}
		else {
			this->RemoveAll();
			return;
		}
	}
};

class ProcessShowUI : public CContainerUI
{
public:
	ProcessShowUI()
	{
		CDialogBuilder builder;
		CContainerUI* pProcessShow = static_cast<CContainerUI*>(builder.Create(_T("ProcessShow.xml"), (UINT)0));
		if (pProcessShow) {
			this->Add(pProcessShow);
		}
		else {
			this->RemoveAll();
			return;
		}
	}
};


class InterShowUI : public CContainerUI
{
public:
	InterShowUI()
	{
		CDialogBuilder builder;
		CContainerUI* pInterShow = static_cast<CContainerUI*>(builder.Create(_T("InterShow.xml"), (UINT)0));
		if (pInterShow) {
			this->Add(pInterShow);
		}
		else {
			this->RemoveAll();
			return;
		}
	}
};



class OurSelfProtectUI : public CContainerUI
{
public:
	OurSelfProtectUI()
	{
		CDialogBuilder builder;
		CContainerUI* pOurSelfProtect = static_cast<CContainerUI*>(builder.Create(_T("OurSelfProtect.xml"), (UINT)0));
		if (pOurSelfProtect) {
			this->Add(pOurSelfProtect);
		}
		else {
			this->RemoveAll();
			return;
		}
	}
};



class HookShowUI : public CContainerUI
{
public:
	HookShowUI()
	{
		CDialogBuilder builder;
		CContainerUI* pHookShow = static_cast<CContainerUI*>(builder.Create(_T("HookShow.xml"), (UINT)0));
		if (pHookShow) {
			this->Add(pHookShow);
		}
		else {
			this->RemoveAll();
			return;
		}
	}
};











class RuleShowUI : public CContainerUI
{
public:
	RuleShowUI()
	{
		CDialogBuilder builder;
		CContainerUI* pRuleShow = static_cast<CContainerUI*>(builder.Create(_T("RuleShow.xml"), (UINT)0));
		if (pRuleShow) {
			this->Add(pRuleShow);
		}
		else {
			this->RemoveAll();
			return;
		}
	}
};


class CDialogBuilderCallbackEx : public IDialogBuilderCallback
{
public:
	CControlUI* CreateControl(LPCTSTR pstrClass) 
	{
		if( _tcscmp(pstrClass, _T("FileShow")) == 0 ) return new FileShowUI;
		if (_tcscmp(pstrClass, _T("RegditShow")) == 0) return new RegditShowUI;
		if (_tcscmp(pstrClass, _T("ProcessShow")) == 0) return new ProcessShowUI;
		if (_tcscmp(pstrClass, _T("InterShow")) == 0) return new InterShowUI;
		if (_tcscmp(pstrClass, _T("OurSelfProtect")) == 0) return new OurSelfProtectUI;
		if (_tcscmp(pstrClass, _T("HookShow")) == 0) return new HookShowUI;
		if (_tcscmp(pstrClass, _T("RuleShow")) == 0) return new RuleShowUI;
		return NULL;
	}
};




