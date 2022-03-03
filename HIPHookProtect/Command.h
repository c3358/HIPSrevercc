#pragma once
#include "data.h"
#include "WhiteFileList.h"
#include "WhiteProcessList.h"
#include "WhiteRegditList.h"


//������Ȥ��ͨ�ô���
NTSTATUS Safe_CommonProc(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

//����
NTSTATUS Safe_Shutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

//��
NTSTATUS Safe_Read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);


//������������CLEANUP
NTSTATUS Safe_CreateCloseCleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp);


NTSTATUS Safe_DeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
