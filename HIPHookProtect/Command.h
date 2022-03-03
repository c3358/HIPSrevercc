#pragma once
#include "data.h"
#include "WhiteFileList.h"
#include "WhiteProcessList.h"
#include "WhiteRegditList.h"


//不感兴趣的通用处理
NTSTATUS Safe_CommonProc(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

//重启
NTSTATUS Safe_Shutdown(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

//读
NTSTATUS Safe_Read(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);


//创建、结束、CLEANUP
NTSTATUS Safe_CreateCloseCleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp);


NTSTATUS Safe_DeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
