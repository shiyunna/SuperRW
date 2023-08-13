#pragma once
#include<ntifs.h>
#ifdef __cplusplus
extern "C"
{
#endif
	UCHAR* PsGetProcessImageFileName(PEPROCESS EProcess);
#ifdef __cplusplus
}
#endif
#define PROCESS_TERMINATE                  (0x0001) 

PVOID obHandle;  //»Øµ÷¾ä±ú

BOOLEAN BypassCheckSign(PDRIVER_OBJECT pDriverObject);

NTSTATUS ProtectProcess();

char* GetProcessNameByProcessID(HANDLE pid);

OB_PREOP_CALLBACK_STATUS MyCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);