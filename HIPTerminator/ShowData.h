#pragma once
#include<Windows.h>



//文件保护日志显示
DWORD WINAPI _ProtectLogThread(LPVOID lpParam);
//规则显示
DWORD WINAPI _RuleThread(LPVOID lpParam);
//进程拦截信息显示
DWORD WINAPI _ProcessInterceptThread(LPVOID lpParam);