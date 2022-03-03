#pragma once
#include <ntifs.h>
#include "defstruct.h"

//文件操作
#define Operate_DeleteFile	0x0
#define Operate_ReadFile	0x1
#define Operate_WriteFile	0x2
#define Operate_CreateFile	0x3
#define Operate_OpenFile	0x4
#define Operate_SetInformationFile	0x5


//注册表操作
#define Operate_OpenKey		0x0
#define Operate_DeleteKey	0x1
#define Operate_CreateKey	0x2
#define Operate_RenameKey	0x3
#define Operate_SetValueKey 0x4
#define Operate_DeleteValue 0x5


//网络操作
#define Operate_SendData	0x0
#define Operate_RecvData	0x1

//自我保护
#define Operate_OpenProcess 0x0
#define Operate_ExitProcess 0x1


//R3与R0交互命令
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

#define IO_AFD_BIND 0x12003 
#define IO_AFD_CONNECT 0x12007 
#define IO_AFD_RECV 0x12017 
#define IO_AFD_SEND 0x1201f


typedef struct AFD_WSABUF {
	unsigned int  len;
	PCHAR  buf;
}AFD_WSABUF, * PAFD_WSABUF;

typedef struct AFD_INFO {
	PAFD_WSABUF  BufferArray;
	ULONG  BufferCount;
	ULONG  AfdFlags;
	ULONG  TdiFlags;
} AFD_INFO, * PAFD_INFO;


HANDLE g_hFileShowEvent;							//用来与应用层同步文件保护的显示（事件对象）
PKEVENT g_pFileShowEvent;
HANDLE g_hProcessInterceptEvent;					//用来与应用层同步进程拦截信息获取（事件对象）
PKEVENT g_pProcessInterceptEvent;
HANDLE g_OurselfProcessID;							//我们自身被保护进程PID





typedef struct _INTERCEPT_PROCESS
{
	HANDLE             hParentId;             // 在回调函数中保存进程信息
	HANDLE             hProcessId;
	UCHAR              ProcFullPath[0x200];   //进程路径
	BOOLEAN            bCreate;				  //是创建进程还是结束进程
}_INTERCEPT_PROCESS, * PINTERCEPT_PROCESS;




typedef struct _SYSTEM_INFORMATIONFILE
{
	ULONG IndexNumber_LowPart;				//该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
	union {								//判断条件        if ((FileInformation.IndexNumber.HighPart) || (FileInformation.IndexNumber.HighPart == FastfatFlag))
		ULONG IndexNumber_HighPart;			//该文件唯一ID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
		ULONG XorResult;					//秘制操作（异或  FileBasicInformation FILE_BASIC_INFORMATION FileBaInformation.CreationTime.LowPart ^ FileBaInformation.ChangeTime.HighPart;
	} u;
	ULONG VolumeSerialNumber;				//序列号体积      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
	UNICODE_STRING stFilePath;
}SYSTEM_INFORMATIONFILE, * PSYSTEM_INFORMATIONFILE;


//保存文件文件信息校验信息
//文件信息校验的SYSTEM_INFORMATIONFILE_XOR
typedef struct _INFORMATIONFILE
{
	ULONG FileListNumber;							// +0   保存个数的东西
	SYSTEM_INFORMATIONFILE FileBuff[0x2000];		// +4   填充，后续知道再加
	KSPIN_LOCK	SpinLock;								// 末尾 自旋锁 
}INFORMATIONFILE, * PINFORMATIONFILE;
PINFORMATIONFILE g_InformationFile;



//保存受保护注册表信息
typedef struct _ALL_PROTECTREGDIT
{
	ULONG ProtectRegditNumber;							// 受保护注册表的个数
	UNICODE_STRING RegditPath[0x100];					// 注册表路径
	KSPIN_LOCK	SpinLock;								// 自旋锁 
}ALL_PROTECTREGDIT, * P_ALL_PROTECTREGDIT;
P_ALL_PROTECTREGDIT g_All_ProtectRegdit;











#define FAKEMAXNUM 0x100

typedef struct _FILTERFUN_TABLE {
	ULONG 	Size; 									//本结构的大小,为0x51C	 
	ULONG 	IsFilterFunFilledReady;             	//标志,表明过滤函数表是否准备好 
	PULONG 	FakeFunc[FAKEMAXNUM];    				//偏移为0x2C,过滤函数数组,共有过滤函数0x9E个  (函数)
	PULONG	FilterFunc[FAKEMAXNUM];					//代理过滤函数数组
	PULONG	OldFunc[FAKEMAXNUM];					//原始ssdt函数地址
	ULONG	SSDTIndex[FAKEMAXNUM];					//原始ssdt函数的服务索引
}FILTERFUN_TABLE, * PFILTERFUN_TABLE;

PFILTERFUN_TABLE  g_FilterFun_table;


//SSDT表信息
typedef struct _SSDTTable_Data {
	PVOID SSDT_KeServiceTableBase;
	ULONG SSDT_KeNumberOfServices;
	PVOID SSDT_KeParamTableBase;
}SSDTTable_Data, * PSSDTTable_Data;

PSSDTTable_Data g_SSDTTable_data;

//nt内核基地址和大小
typedef struct _NtData
{
	PVOID NtImageBase;
	ULONG NtImageSize;
}NtData, * PNtData;

PNtData g_NtData;

typedef struct _NtFuncAddress
{
	POBJECT_TYPE(*pObGetObjectType)(IN PVOID pObject);
	NTSTATUS(*pObDuplicateObject)(IN PEPROCESS SourceProcess, IN HANDLE SourceHandle, IN PEPROCESS TargetProcess OPTIONAL, OUT PHANDLE TargetHandle OPTIONAL, IN ACCESS_MASK DesiredAccess, IN ULONG HandleAttributes, IN ULONG Options, IN KPROCESSOR_MODE PreviousMode);						//NTSTATUS ObDuplicateObject(xxx);
	HANDLE(*pPsGetThreadProcessId)(IN PETHREAD Thread);			//HANDLE   PsGetThreadProcessId(PETHREAD Thread);
	HANDLE(*pPsGetProcessId)(IN PEPROCESS Process);				//HANDLE   PsGetProcessId(PEPROCESS Process);
	UCHAR* (*pPsGetProcessImageFileName)(IN PEPROCESS Process);	//UCHAR   *PsGetProcessImageFileName(PEPROCESS Process);
	PPEB(*pPsGetProcessPeb)(IN PEPROCESS Process);

}NtFuncAddress, * PNtFuncAddress;

PNtFuncAddress g_NtFuncAddress;


//各个函数在代理过滤函数表中的索引
#define ZwOpenFile_FilterIndex						0x0
#define ZwCreateFile_FilterIndex					0x1
#define ZwDeleteFile_FilterIndex					0x2
#define	ZwReadFile_FilterIndex						0x3
#define	ZwWriteFile_FilterIndex						0x4
#define ZwSetInformationFile_FilterIndex			0x5
#define ZwOpenKey_FilterIndex						0x6
#define	ZwDeleteKey_FilterIndex						0x7
#define ZwOpenKeyEx_FilterIndex						0x8
#define ZwDeviceIoControlFile_FilterIndex			0x9
#define ZwOpenProcess_FilterIndex					0xA
#define ZwTerminateProcess_FilterIndex				0xB

#define CreateProcessNotifyRoutineIndex				0xC


NTSTATUS
NTAPI
ZwQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);