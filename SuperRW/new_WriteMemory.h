#pragma once
#include<ntifs.h>
#include<intrin.h>


NTSTATUS NTAPI NtProtectVirtualMemory(

	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection);

NTSTATUS WriteProcessIDMemory(HANDLE hProcessID, PVOID pBaseAddress, PVOID pBuffer, SIZE_T szBufferSize);
