#include "NewStruct.h"
#define DEVICENAME L"\\Device\\SuperRW"
#define SYMBOLNAME L"\\??\\SuperRW"
//�Զ����IO�����롣�Լ�����ʱȡ0x800��0xFFF | 0x0��0x7FF��΢�����ġ�
#define READCODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)//Readmemory
#define WRITECODE CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)//WriteMemory
#define WRITECODE2 CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_OUT_DIRECT,FILE_ANY_ACCESS) //WriteProtectVirtualMemory
#define GetProcessBaseModule CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)  //Getmodule

#define QueryProcessMemory CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)  //QueryMemory


//�Զ��庯������
NTSTATUS DriverIrpCtl(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS CreateDriver(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS CloseDriver(PDEVICE_OBJECT pDevice, PIRP pIrp);
//800-804:
// Read and write ->new_WriteMemory �� ReadandWrite �� 
//.....
ULONG_PTR GetModuleBaseAddr(HANDLE hProcessId, char* szModuleName);

//900-903:
NTSTATUS QueryMemory(HANDLE pid, ULONG64 BaseAddress, PMyMEMORY_BASIC_INFORMATION pInformation);

//�ṹ�岿��
typedef struct _ReadInfo
{
	ULONG64 ProcessID;
	ULONG64 pSource;
	ULONG64 pTarget;
	ULONG64 Size;
}ReadInfo, * PReadInfo;//���ڴ�ṹ

typedef struct _WriteInfo
{
	ULONG64 ProcessID;
	ULONG64 pSource;
	ULONG64 pTarget;
	ULONG64 Size;
}WriteInfo, * PWriteInfo; //д�ڴ�ṹ

typedef struct _ReadWriteInfo {
	ULONG64 ulPid;
	ULONG64 ulBaseAddress;
	ULONG64 ulBuffer;
	ULONG64 ulSize;

}ReadWriteInfo, * PReadWriteInfo;

typedef struct	_GetModuleInfo {
	ULONG64 ulPid;
	ULONG64 ulModuleName;
}GetModuleInfo, * PGetModuleInfo;

typedef struct _QueryMemoryInfo
{
	ULONG64 pid;
	ULONG64 BaseAddress;
	MyMEMORY_BASIC_INFORMATION memoryInfo;
}QueryMemoryInfo, * PQueryMemoryInfo;


//��ȡ�ṹ��
