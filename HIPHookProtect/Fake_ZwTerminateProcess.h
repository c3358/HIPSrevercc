#pragma once
#include "Fake_ZwOpenProcess.h"

//��������
NTSTATUS NTAPI Fake_ZwTerminateProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);