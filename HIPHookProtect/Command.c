#include "Command.h"

_INTERCEPT_PROCESS g_InterceptProcessData = { 0 };



//不感兴趣的通用处理
NTSTATUS Safe_CommonProc(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	//直接完成，返回成功
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}




NTSTATUS Safe_Shutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	IrpStack;
	UNREFERENCED_PARAMETER(DeviceObject);
	//略
	Irp->IoStatus.Status = Status;							//表示IRP完成状态
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
	//略
	Irp->IoStatus.Status = Status;							//表示IRP完成状态
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
	//1、检查调用者,必须是保护进程
	if (Safe_QueryWhitePID(PsGetCurrentProcessId()))
	{
		//略
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
		case IOCTL_SETFILEWHITE:												//添加文件白名单

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
		case IOCTL_GETINTERCEPTDATA:											//获取进程拦截信息

			memcpy(buffer, &g_InterceptProcessData, sizeof(_INTERCEPT_PROCESS));
			Irp->IoStatus.Information = sizeof(_INTERCEPT_PROCESS);
			break;
		case IOCTL_SETPROCESSWHITE:												//设置进程白名单
			if (Safe_InsertWhiteList_PID(*(HANDLE*)buffer))
				*(DWORD*)buffer = 1;
			else
				*(DWORD*)buffer = 0;
			Irp->IoStatus.Information = 4;
			break;
		case IOCTL_SETPROTECTREGDIT:											//设置被保护注册表名单
			*((BYTE*)buffer + inlen) = 0;
			RtlInitAnsiString(&stANSIBuffer, buffer);
			RtlAnsiStringToUnicodeString(&stUNICODEBuffer, &stANSIBuffer, FALSE);
			if (Safe_InsertProtectRegditList(&stUNICODEBuffer))
				*(DWORD*)buffer = 1;
			else
				*(DWORD*)buffer = 0;
			Irp->IoStatus.Information = 4;
			break;
		case IOCTL_SETOURSELFPID:												//设置自身被保护进程PID
			g_OurselfProcessID = *((DWORD*)buffer);
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
	}





	Irp->IoStatus.Status = Status;							//表示IRP完成状态
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}