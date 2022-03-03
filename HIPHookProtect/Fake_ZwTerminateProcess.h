#pragma once
#include "Fake_ZwOpenProcess.h"

//½áÊø½ø³Ì
NTSTATUS NTAPI Fake_ZwTerminateProcess(IN ULONG CallIndex, IN PVOID ArgArray, IN PULONG ret_func, IN PULONG ret_arg);