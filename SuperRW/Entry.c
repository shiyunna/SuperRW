#include "Comm.h"
#include "new_WriteMemory.h"
#include "ReadandWrite.h"
#include "bypasscallback.h"

BOOLEAN pre = FALSE;
VOID DriverUnload(PDRIVER_OBJECT pDriver)
{

	PDEVICE_OBJECT	pNextObj;
	DbgPrint("Enter DriverUnload\n");
	if (pre) {

		ObUnRegisterCallbacks(obHandle);
	}//如果注册回调函数成功则删除回调

	if (pDriver->DeviceObject)
	{
		IoDeleteDevice(pDriver->DeviceObject);

		UNICODE_STRING SymbolName = RTL_CONSTANT_STRING(SYMBOLNAME);

		NTSTATUS status = IoDeleteSymbolicLink(&SymbolName);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("链表删除失败！\n");

		}
	}

	DbgPrint("驱动卸载成功！\n");

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg_Path)
{

	DbgPrint("驱动加载成功 ！\n");
	//ULONG_PTR ulpBase32 = GetModuleBaseAddr(13760, "kernel32.dll");
	//DbgPrint("x86 kernel32 Module Base = %llx\r\n", ulpBase32);
	pDriver->DriverUnload = DriverUnload;

	NTSTATUS status = STATUS_SUCCESS;

	BypassCheckSign(pDriver); // 

	status = ProtectProcess();   //干掉
	if (NT_SUCCESS(status))
	{
		DbgPrint(("注册回调函数成功"));
		pre = TRUE;
	}
	else {
		DbgPrint(("注册回调函数失败"));
	}

	PDEVICE_OBJECT pDevice = NULL;
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(DEVICENAME);
	UNICODE_STRING SymbolName = RTL_CONSTANT_STRING(SYMBOLNAME);

	status = IoCreateDevice(pDriver, NULL, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevice);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("设备创建失败！\n");
		pDriver->DriverUnload(pDriver);
		return status;
	}
	status = IoCreateSymbolicLink(&SymbolName, &DeviceName);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("创建链表失败！\n");
		IoDeleteDevice(pDevice);
	}
	pDriver->MajorFunction[IRP_MJ_CREATE] = CreateDriver;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = CloseDriver;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIrpCtl;

	return status;

}
