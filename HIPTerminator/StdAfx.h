
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
	FILE_DEVICE_UNKNOWN,  /* 欲控制的驱动类型 */                    \
	IOCTL_BASE + i,       /* 0x800~0xFFF是可由程序员自定义的部分 */ \
	METHOD_BUFFERED,      /* 操作模式：使用缓冲区方式操作 */        \
	FILE_ANY_ACCESS       /* 访问权限：全部 */                      \
	)
#define IOCTL_OCTRL      MY_CTL_CODE(0)
#define IOCTL_SETFILEWHITE      MY_CTL_CODE(1)						//设置文件保护名单
#define IOCTL_GETINTERCEPTDATA  MY_CTL_CODE(2)						//获取进程拦截信息
#define IOCTL_SETPROCESSWHITE   MY_CTL_CODE(3)						//设置进程白名单
#define IOCTL_SETPROTECTREGDIT  MY_CTL_CODE(4)						//设置注册表保护名单
#define IOCTL_SETOURSELFPID		MY_CTL_CODE(5)						//设置自身被保护进程PID

#include <windows.h>
#include <objbase.h>
#include <zmouse.h>

#include "F:\duilib-master\DuiLib\UIlib.h"
#include "ShowData.h"
using namespace DuiLib;


//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_)