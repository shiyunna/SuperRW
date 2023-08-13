#include "Comm.h"
#include "new_WriteMemory.h"
#include "ReadandWrite.h"
#include "func.h"


//��ȡMmcopyVirtualMeory�ṹ
NTSTATUS MmCopyVirtualMemory(IN PEPROCESS FromProcess, IN CONST VOID* FromAddress, IN PEPROCESS ToProcess, OUT PVOID ToAddress, IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode, OUT PSIZE_T NumberOfBytesCopied);

NTSTATUS NTAPI NtProtectVirtualMemory(

	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection) {

	typedef NTSTATUS(NTAPI* ZwProtectVirtualMemoryProc)(
		IN HANDLE               ProcessHandle,
		IN OUT PVOID* BaseAddress,
		IN OUT PULONG           NumberOfBytesToProtect,
		IN ULONG                NewAccessProtection,
		OUT PULONG              OldAccessProtection);

	static ZwProtectVirtualMemoryProc MyZwProtectVirtualMemory = NULL;
	if (!MyZwProtectVirtualMemory)
	{
		UNICODE_STRING usFunctionName = { 0 };
		RtlInitUnicodeString(&usFunctionName, L"ZwIsProcessInJob");
		PUCHAR puFunctionAddr = (PUCHAR)MmGetSystemRoutineAddress(&usFunctionName);
		if (puFunctionAddr)
		{
			puFunctionAddr += 20;
			for (size_t i = 0; i < 50; i++)
			{	//����������
				if (puFunctionAddr[i] == 0x48 && puFunctionAddr[i + 1] == 0x8b && puFunctionAddr[i + 2] == 0xc4) {
					MyZwProtectVirtualMemory = (ZwProtectVirtualMemoryProc)(puFunctionAddr + i);
					break;
				}
			}
		}
	}
	if (MyZwProtectVirtualMemory)
	{
		return MyZwProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	}

}



NTSTATUS WriteProcessIDMemory(HANDLE hProcessID, PVOID pBaseAddress, PVOID pBuffer, SIZE_T szBufferSize)
{
	if ((ULONG64)pBaseAddress >= MmHighestUserAddress || (ULONG64)pBaseAddress + szBufferSize >= MmHighestUserAddress || (ULONG64)pBaseAddress + szBufferSize < (ULONG64)pBaseAddress)
	{
		return STATUS_ACCESS_VIOLATION;
	}
	if (pBuffer == NULL)
	{
		return STATUS_INVALID_PARAMETER_3;
	}
	PEPROCESS pEprocess;
	KAPC_STATE kApc = { 0 };
	NTSTATUS ntStatus = PsLookupProcessByProcessId(hProcessID, &pEprocess);
	if (!NT_SUCCESS(ntStatus)) {
		return ntStatus;
	}

	if (PsGetProcessExitStatus(pEprocess) != STATUS_PENDING)
	{
		ObDereferenceObject(pEprocess);
		return STATUS_INVALID_PARAMETER_1;
	}

	SIZE_T retNum = 0;
	//ֱ����дһ��
	ntStatus = MmCopyVirtualMemory(IoGetCurrentProcess(), pBuffer, pEprocess, pBaseAddress, szBufferSize, UserMode, &retNum);
	if (NT_SUCCESS(ntStatus))
	{
		ObDereferenceObject(pEprocess);
		return ntStatus;

	}
	//û��д�ɹ�
	PEPROCESS pCurrentEprocess = IoGetCurrentProcess();
	KeStackAttachProcess(pEprocess, &kApc);
	PVOID pvAddr = pBaseAddress;
	SIZE_T szSize = szBufferSize;
	ULONG ulAttr = 0;
	ntStatus = NtProtectVirtualMemory(NtCurrentProcess(), &pvAddr, &szSize, PAGE_EXECUTE_READWRITE, &ulAttr);
	if (NT_SUCCESS(ntStatus))
	{
		SIZE_T retNum = 0;
		ntStatus = MmCopyVirtualMemory(IoGetCurrentProcess(), pBuffer, pEprocess, pBaseAddress, szBufferSize, UserMode, &retNum);
		NtProtectVirtualMemory(NtCurrentProcess(), &pvAddr, &szSize, ulAttr, &ulAttr);
	}

	KeUnstackDetachProcess(&kApc);
	ObDereferenceObject(pEprocess);
	if (!NT_SUCCESS(ntStatus))
	{
		//���ж�
		_disable();
		//��ȡCR0
		ULONG64 ulRegCr0 = __readcr0();
		__writecr0(ulRegCr0 & (~0x10000));//�ر���
		ntStatus = MmCopyVirtualMemory(IoGetCurrentProcess(), pBuffer, pEprocess, pBaseAddress, szBufferSize, UserMode, &retNum);
		__writecr0(ulRegCr0);
		_enable();
	}
	return ntStatus;
}