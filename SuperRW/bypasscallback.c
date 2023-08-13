#include "Comm.h"
#include "new_WriteMemory.h"
#include "ReadandWrite.h"
#include "bypasscallback.h"

BOOLEAN BypassCheckSign(PDRIVER_OBJECT pDriverObject)
{
#ifdef _WIN64
	//64位的结构
	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY listEntry;
		ULONG64 __Undefined1;
		ULONG64 __Undefined2;
		ULONG64 __Undefined3;
		ULONG64 NonPagedDebugInfo;
		ULONG64 DllBase;
		ULONG64 EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING path;
		UNICODE_STRING name;
		ULONG   Flags;
		USHORT  LoadCount;
		USHORT  __Undefined5;
		ULONG64 __Undefined6;
		ULONG   CheckSum;
		ULONG   __padding1;
		ULONG   TimeDateStamp;
		ULONG   __padding2;
	} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#else
	//32位的结构
	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY listEntry;
		ULONG unknown1;
		ULONG unknown2;
		ULONG unknown3;
		ULONG unknown4;
		ULONG unknown5;
		ULONG unknown6;
		ULONG unknown7;
		UNICODE_STRING path;
		UNICODE_STRING name;
		ULONG   Flags;
	} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#endif

	PKLDR_DATA_TABLE_ENTRY pLdrData = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	pLdrData->Flags |= 0x20;

	return TRUE;
}



NTSTATUS ProtectProcess()
{

	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");

	memset(&opReg, 0, sizeof(opReg)); //初始化结构体变量

	opReg.ObjectType = PsProcessType;

	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;



	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)(&MyCallback);  //注册回调函数指针

	obReg.OperationRegistration = &opReg; //注意这一条语句

	PVOID addr = (PVOID)((ULONG64)*PsThreadType + 0x40 + 0x20);
	*(PULONG)addr = 0x1fffff;


	addr = (PVOID)((ULONG64)*PsProcessType + 0x40 + 0x20);
	*(PULONG)addr = 0x1fffff;  //注意  ： 修改PsProcessType/PsThreadType下_OBJECT_TYPE_INITIALIZER下RetainAccess为0x1fffff 无视抹权限 ObpPreInterceptHandleCreate
	// 方式2 .注册两个obregistercallbacks 层分别在xx的上方和下方 等xx抹了之后 抹回去
	//方式3 ： Pte hook Obp
	//方式4：遍历CallbacksList替换或修改Pre Post函数
	return ObRegisterCallbacks(&obReg, &obHandle); //注册回调函数
}

OB_PREOP_CALLBACK_STATUS MyCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{

	if (pOperationInformation->KernelHandle == TRUE)
	{
		//如果是KernelHandle则直接返回不做操作
		return(OB_PREOP_SUCCESS);
	}

	if (pOperationInformation->ObjectType != *PsProcessType)
	{
		return(OB_PREOP_SUCCESS);
	}
	char szProcName[16] = { 0 };
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);



	UNREFERENCED_PARAMETER(RegistrationContext);

	strcpy(szProcName, GetProcessNameByProcessID(pid));

	if (!_stricmp(szProcName, "newunknown.exe"))

	{

		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{


			DbgPrint("nowname：%s\n", szProcName);
			//拒绝PROCESS_TERMINATE处理
			if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				if (pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess == PROCESS_TERMINATE)
				{
					//拒绝PROCESS_TERMINATE处理
					if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
					{
						//Terminate the process, such as by calling the user-mode TerminateProcess routine..
						pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
					}

				}

			}
			return OB_PREOP_SUCCESS;
		}

	}
}

char* GetProcessNameByProcessID(HANDLE pid)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS EProcess = NULL;
	char* NAME = NULL;
	status = PsLookupProcessByProcessId(pid, &EProcess);

	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	ObDereferenceObject(EProcess);
	return (char*)PsGetProcessImageFileName(EProcess);

}


