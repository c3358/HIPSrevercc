#pragma once
#include<Windows.h>



//�ļ�������־��ʾ
DWORD WINAPI _ProtectLogThread(LPVOID lpParam);
//������ʾ
DWORD WINAPI _RuleThread(LPVOID lpParam);
//����������Ϣ��ʾ
DWORD WINAPI _ProcessInterceptThread(LPVOID lpParam);