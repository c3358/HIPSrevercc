#pragma once
#include "data.h"
#include <ntddk.h>
#include <ntimage.h>
#include "defstruct.h"
#include <ntstrsafe.h>


typedef struct tagSYSTEM_MODULE_INFORMATION {
	ULONG Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;



//
// System Information Classes.
//
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,              // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,                //ϵͳ������Ϣ
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,				//ϵͳģ��
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadImage,					   //26 ��������
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemLoadAndCallImage,					//38 ��������
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass   // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

extern
NTSTATUS
ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength);

NTSTATUS
NTAPI
ZwQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

extern
PVOID NTAPI
RtlImageDirectoryEntryToData(
	IN PVOID          BaseAddress,
	IN BOOLEAN        ImageLoaded,
	IN ULONG		   Directory,
	OUT PULONG        Size);

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG ProcessID;                //���̵ı�ʶID 
	UCHAR ObjectTypeNumber;         //�������� 
	UCHAR Flags;					//0x01 = PROTECT_FROM_CLOSE,0x02 = INHERIT 
	USHORT Handle;					//����������ֵ 
	PVOID  Object;					//��������ָ���ں˶����ַ 
	ACCESS_MASK GrantedAccess;      //�������ʱ��׼��Ķ���ķ���Ȩ 
}SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

BOOLEAN NTAPI Safe_GetModuleBaseAddress(IN PUNICODE_STRING ModuleName, OUT PVOID* pModuleBase, OUT ULONG* ModuleSize, OUT USHORT* LoadOrderIndex);

PVOID NTAPI Safe_GetAndReplaceSymbol(PVOID ImageBase, PANSI_STRING SymbolName, PVOID ReplaceValue, PVOID* SymbolAddr);

PVOID HookProtect_LockMemory(PVOID VirtualAddress, ULONG Length, PVOID* Mdl_a3, ULONG Version_Win10_Flag);

VOID  HookProtect_RemoveLockMemory(PMDL pmdl);


PVOID Safe_GetSymbolAddress(PANSI_STRING SymbolName, PVOID NtImageBase);

PVOID Safe_AllocBuff(POOL_TYPE PoolType, ULONG Size, ULONG Tag);

//�ͷſռ�
PVOID Safe_ExFreePool(IN PVOID pBuff);

NTSTATUS NTAPI Safe_IoCreateFile(_In_ POBJECT_ATTRIBUTES ObjectAttributes, _Out_ PHANDLE FileHandle);

NTSTATUS NTAPI Safe_UserMode_ZwQueryVolumeInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FsInformation, _In_ ULONG Length, _In_ FS_INFORMATION_CLASS FsInformationClass, IN BOOLEAN HighVersion_Flag);
ULONG NTAPI Safe_pPsGetProcessId(PVOID VirtualAddress);


//���ʱ��
PWCHAR GetTimeFunction();

//��ý���·��
PUNICODE_STRING GetCurrentProcessFileName();


NTSTATUS NTAPI myProbeRead(PVOID Address, SIZE_T Size, ULONG Alignment);
NTSTATUS NTAPI myProbeWrite(PVOID Address, SIZE_T Size, ULONG Alignment);
NTSTATUS NTAPI Safe_ZwNtClose(IN HANDLE Handle, IN BOOLEAN HighVersion_Flag);

NTSTATUS NTAPI Safe_UserMode_ZwQueryInformationFile(_In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock, _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length, _In_ FILE_INFORMATION_CLASS FileInformationClass, IN BOOLEAN HighVersion_Flag);