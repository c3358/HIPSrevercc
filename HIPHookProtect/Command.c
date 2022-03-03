#include "Command.h"

_INTERCEPT_PROCESS g_InterceptProcessData = { 0 };



//������Ȥ��ͨ�ô���
NTSTATUS Safe_CommonProc(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	//ֱ����ɣ����سɹ�
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}




NTSTATUS Safe_Shutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	IrpStack;
	UNREFERENCED_PARAMETER(DeviceObject);
	//��
	Irp->IoStatus.Status = Status;							//��ʾIRP���״̬
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS Safe_CreateCloseCleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Safe_Read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	IrpStack;
	UNREFERENCED_PARAMETER(DeviceObject);
	//��
	Irp->IoStatus.Status = Status;							//��ʾIRP���״̬
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}




NTSTATUS Safe_DeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	IrpStack;
	UNREFERENCED_PARAMETER(DeviceObject);
	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	/*
	//1����������,�����Ǳ�������
	if (Safe_QueryWhitePID(PsGetCurrentProcessId()))
	{
		//��
	}
	*/

	if (IrpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		BYTE bUNICODEbuffer[0x200] = { 0 };
		UNICODE_STRING stUNICODEBuffer;
		UNICODE_STRING stANSIBuffer;
		PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG inlen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
		ULONG outlen = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
		stUNICODEBuffer.Buffer = bUNICODEbuffer;
		stUNICODEBuffer.MaximumLength = 0x200;
		stUNICODEBuffer.Length = 0;



		switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_SETFILEWHITE:												//����ļ�������

			*((BYTE*)buffer + inlen) = 0;
			RtlInitAnsiString(&stANSIBuffer, buffer);
			RtlAnsiStringToUnicodeString(&stUNICODEBuffer, &stANSIBuffer, FALSE);
			Status = Safe_AddFileWhiteList(&stUNICODEBuffer);
			if (NT_SUCCESS(Status))
				*(DWORD*)buffer = 1;
			else
				*(DWORD*)buffer = 0;
			Irp->IoStatus.Information = 4;
			break;
		case IOCTL_GETINTERCEPTDATA:											//��ȡ����������Ϣ

			memcpy(buffer, &g_InterceptProcessData, sizeof(_INTERCEPT_PROCESS));
			Irp->IoStatus.Information = sizeof(_INTERCEPT_PROCESS);
			break;
		case IOCTL_SETPROCESSWHITE:												//���ý��̰�����
			if (Safe_InsertWhiteList_PID(*(HANDLE*)buffer))
				*(DWORD*)buffer = 1;
			else
				*(DWORD*)buffer = 0;
			Irp->IoStatus.Information = 4;
			break;
		case IOCTL_SETPROTECTREGDIT:											//���ñ�����ע�������
			*((BYTE*)buffer + inlen) = 0;
			RtlInitAnsiString(&stANSIBuffer, buffer);
			RtlAnsiStringToUnicodeString(&stUNICODEBuffer, &stANSIBuffer, FALSE);
			if (Safe_InsertProtectRegditList(&stUNICODEBuffer))
				*(DWORD*)buffer = 1;
			else
				*(DWORD*)buffer = 0;
			Irp->IoStatus.Information = 4;
			break;
		case IOCTL_SETOURSELFPID:												//����������������PID
			g_OurselfProcessID = *((DWORD*)buffer);
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
	}





	Irp->IoStatus.Status = Status;							//��ʾIRP���״̬
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}