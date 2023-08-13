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
	}//���ע��ص������ɹ���ɾ���ص�

	if (pDriver->DeviceObject)
	{
		IoDeleteDevice(pDriver->DeviceObject);

		UNICODE_STRING SymbolName = RTL_CONSTANT_STRING(SYMBOLNAME);

		NTSTATUS status = IoDeleteSymbolicLink(&SymbolName);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("����ɾ��ʧ�ܣ�\n");

		}
	}

	DbgPrint("����ж�سɹ���\n");

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg_Path)
{

	DbgPrint("�������سɹ� ��\n");
	//ULONG_PTR ulpBase32 = GetModuleBaseAddr(13760, "kernel32.dll");
	//DbgPrint("x86 kernel32 Module Base = %llx\r\n", ulpBase32);
	pDriver->DriverUnload = DriverUnload;

	NTSTATUS status = STATUS_SUCCESS;

	BypassCheckSign(pDriver); // 

	status = ProtectProcess();   //�ɵ�
	if (NT_SUCCESS(status))
	{
		DbgPrint(("ע��ص������ɹ�"));
		pre = TRUE;
	}
	else {
		DbgPrint(("ע��ص�����ʧ��"));
	}

	PDEVICE_OBJECT pDevice = NULL;
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(DEVICENAME);
	UNICODE_STRING SymbolName = RTL_CONSTANT_STRING(SYMBOLNAME);

	status = IoCreateDevice(pDriver, NULL, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevice);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("�豸����ʧ�ܣ�\n");
		pDriver->DriverUnload(pDriver);
		return status;
	}
	status = IoCreateSymbolicLink(&SymbolName, &DeviceName);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("��������ʧ�ܣ�\n");
		IoDeleteDevice(pDevice);
	}
	pDriver->MajorFunction[IRP_MJ_CREATE] = CreateDriver;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = CloseDriver;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIrpCtl;

	return status;

}
