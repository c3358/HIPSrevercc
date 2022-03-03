
#if !defined(AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_)
#define AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_

#pragma once

#define WIN32_LEAN_AND_MEAN	
#define _CRT_SECURE_NO_DEPRECATE


#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#define FILE_DEVICE_UNKNOWN             0x00000022
#define METHOD_BUFFERED                 0
#define FILE_ANY_ACCESS                 0



#define IOCTL_BASE        0x800
#define MY_CTL_CODE(i)                                              \
	CTL_CODE                                                        \
	(                                                               \
	FILE_DEVICE_UNKNOWN,  /* �����Ƶ��������� */                    \
	IOCTL_BASE + i,       /* 0x800~0xFFF�ǿ��ɳ���Ա�Զ���Ĳ��� */ \
	METHOD_BUFFERED,      /* ����ģʽ��ʹ�û�������ʽ���� */        \
	FILE_ANY_ACCESS       /* ����Ȩ�ޣ�ȫ�� */                      \
	)
#define IOCTL_OCTRL      MY_CTL_CODE(0)
#define IOCTL_SETFILEWHITE      MY_CTL_CODE(1)						//�����ļ���������
#define IOCTL_GETINTERCEPTDATA  MY_CTL_CODE(2)						//��ȡ����������Ϣ
#define IOCTL_SETPROCESSWHITE   MY_CTL_CODE(3)						//���ý��̰�����
#define IOCTL_SETPROTECTREGDIT  MY_CTL_CODE(4)						//����ע���������
#define IOCTL_SETOURSELFPID		MY_CTL_CODE(5)						//����������������PID

#include <windows.h>
#include <objbase.h>
#include <zmouse.h>

#include "F:\duilib-master\DuiLib\UIlib.h"
#include "ShowData.h"
using namespace DuiLib;


//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_)