#pragma once
#include <ntifs.h>
#include "defstruct.h"

//�ļ�����
#define Operate_DeleteFile	0x0
#define Operate_ReadFile	0x1
#define Operate_WriteFile	0x2
#define Operate_CreateFile	0x3
#define Operate_OpenFile	0x4
#define Operate_SetInformationFile	0x5


//ע������
#define Operate_OpenKey		0x0
#define Operate_DeleteKey	0x1
#define Operate_CreateKey	0x2
#define Operate_RenameKey	0x3
#define Operate_SetValueKey 0x4
#define Operate_DeleteValue 0x5


//�������
#define Operate_SendData	0x0
#define Operate_RecvData	0x1

//���ұ���
#define Operate_OpenProcess 0x0
#define Operate_ExitProcess 0x1


//R3��R0��������
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


HANDLE g_hFileShowEvent;							//������Ӧ�ò�ͬ���ļ���������ʾ���¼�����
PKEVENT g_pFileShowEvent;
HANDLE g_hProcessInterceptEvent;					//������Ӧ�ò�ͬ������������Ϣ��ȡ���¼�����
PKEVENT g_pProcessInterceptEvent;
HANDLE g_OurselfProcessID;							//����������������PID





typedef struct _INTERCEPT_PROCESS
{
	HANDLE             hParentId;             // �ڻص������б��������Ϣ
	HANDLE             hProcessId;
	UCHAR              ProcFullPath[0x200];   //����·��
	BOOLEAN            bCreate;				  //�Ǵ������̻��ǽ�������
}_INTERCEPT_PROCESS, * PINTERCEPT_PROCESS;




typedef struct _SYSTEM_INFORMATIONFILE
{
	ULONG IndexNumber_LowPart;				//���ļ�ΨһID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.LowPart
	union {								//�ж�����        if ((FileInformation.IndexNumber.HighPart) || (FileInformation.IndexNumber.HighPart == FastfatFlag))
		ULONG IndexNumber_HighPart;			//���ļ�ΨһID    FileInternalInformation FILE_INTERNAL_INFORMATION->IndexNumber.HighPart
		ULONG XorResult;					//���Ʋ��������  FileBasicInformation FILE_BASIC_INFORMATION FileBaInformation.CreationTime.LowPart ^ FileBaInformation.ChangeTime.HighPart;
	} u;
	ULONG VolumeSerialNumber;				//���к����      FileFsVolumeInformation _FILE_FS_VOLUME_INFORMATION->VolumeSerialNumber;
	UNICODE_STRING stFilePath;
}SYSTEM_INFORMATIONFILE, * PSYSTEM_INFORMATIONFILE;


//�����ļ��ļ���ϢУ����Ϣ
//�ļ���ϢУ���SYSTEM_INFORMATIONFILE_XOR
typedef struct _INFORMATIONFILE
{
	ULONG FileListNumber;							// +0   ��������Ķ���
	SYSTEM_INFORMATIONFILE FileBuff[0x2000];		// +4   ��䣬����֪���ټ�
	KSPIN_LOCK	SpinLock;								// ĩβ ������ 
}INFORMATIONFILE, * PINFORMATIONFILE;
PINFORMATIONFILE g_InformationFile;



//�����ܱ���ע�����Ϣ
typedef struct _ALL_PROTECTREGDIT
{
	ULONG ProtectRegditNumber;							// �ܱ���ע���ĸ���
	UNICODE_STRING RegditPath[0x100];					// ע���·��
	KSPIN_LOCK	SpinLock;								// ������ 
}ALL_PROTECTREGDIT, * P_ALL_PROTECTREGDIT;
P_ALL_PROTECTREGDIT g_All_ProtectRegdit;











#define FAKEMAXNUM 0x100

typedef struct _FILTERFUN_TABLE {
	ULONG 	Size; 									//���ṹ�Ĵ�С,Ϊ0x51C	 
	ULONG 	IsFilterFunFilledReady;             	//��־,�������˺������Ƿ�׼���� 
	PULONG 	FakeFunc[FAKEMAXNUM];    				//ƫ��Ϊ0x2C,���˺�������,���й��˺���0x9E��  (����)
	PULONG	FilterFunc[FAKEMAXNUM];					//������˺�������
	PULONG	OldFunc[FAKEMAXNUM];					//ԭʼssdt������ַ
	ULONG	SSDTIndex[FAKEMAXNUM];					//ԭʼssdt�����ķ�������
}FILTERFUN_TABLE, * PFILTERFUN_TABLE;

PFILTERFUN_TABLE  g_FilterFun_table;


//SSDT����Ϣ
typedef struct _SSDTTable_Data {
	PVOID SSDT_KeServiceTableBase;
	ULONG SSDT_KeNumberOfServices;
	PVOID SSDT_KeParamTableBase;
}SSDTTable_Data, * PSSDTTable_Data;

PSSDTTable_Data g_SSDTTable_data;

//nt�ں˻���ַ�ʹ�С
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


//���������ڴ�����˺������е�����
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