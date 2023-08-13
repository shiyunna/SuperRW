#include <ntifs.h>
#include <ntimage.h>

//定义结构

typedef struct _DataStruct
{
	ULONG	ProcessPid;
	PVOID	TargetAddress;
	ULONG	Length;
	PVOID	Buffer;
} DataStruct, * PDataStruct;


#pragma pack(4)
typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;


typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;


typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
#pragma pack()


#pragma pack(8)
typedef struct _PEB64
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG64 Mutant;
	ULONG64 ImageBaseAddress;
	ULONG64 Ldr;
	ULONG64 ProcessParameters;
	ULONG64 SubSystemData;
	ULONG64 ProcessHeap;
	ULONG64 FastPebLock;
	ULONG64 AtlThunkSListPtr;
	ULONG64 IFEOKey;
	ULONG64 CrossProcessFlags;
	ULONG64 UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG64 ApiSetMap;
} PEB64, * PPEB64;


typedef struct _PEB_LDR_DATA64
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;


typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY64 HashLinks;
	ULONG64 SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	ULONG64 LoadedImports;
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;
#pragma pack()

typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG    WaitTime;
	PVOID    StartAddress;
	CLIENT_ID   ClientID;
	KPRIORITY   Priority;
	KPRIORITY   BasePriority;
	ULONG    ContextSwitchCount;
	ULONG    ThreadState;
	KWAIT_REASON  WaitReason;
	ULONG    Reserved; //Add
}SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES
{
	ULONG    NextEntryDelta;
	ULONG    ThreadCount;
	ULONG    Reserved[6];
	LARGE_INTEGER  CreateTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  KernelTime;
	UNICODE_STRING  ProcessName;
	KPRIORITY   BasePriority;
	HANDLE   ProcessId;  //Modify
	HANDLE   InheritedFromProcessId;//Modify
	ULONG    HandleCount;
	ULONG    SessionId;
	ULONG_PTR  PageDirectoryBase;
	VM_COUNTERS VmCounters;
	SIZE_T    PrivatePageCount;//Add
	IO_COUNTERS  IoCounters; //windows 2000 only
	struct _SYSTEM_THREADS Threads[1];
}SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID       ServiceTableBase;
	PVOID       ServiceCounterTableBase;
	ULONGLONG   NumberOfServices;
	PVOID       ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;


typedef NTSTATUS(NTAPI* fn_NtCreateThreadEx)
(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	PVOID ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID StartAddress,
	PVOID Parameter,
	ULONG Flags,
	SIZE_T StackZeroBits,
	SIZE_T SizeOfStackCommit,
	SIZE_T SizeOfStackReserve,
	PVOID ByteBuffer);
fn_NtCreateThreadEx NtCreateThreadEx;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,        //  0
	SystemProcessorInformation,        //  1
	SystemPerformanceInformation,        //  2
	SystemTimeOfDayInformation,        //  3
	SystemPathInformation,        //  4
	SystemProcessInformation,               //5
	SystemCallCountInformation,        //  6
	SystemDeviceInformation,        //  7
	SystemProcessorPerformanceInformation,        //  8
	SystemFlagsInformation,        //  9
	SystemCallTimeInformation,        //  10
	SystemModuleInformation,        //  11
	SystemLocksInformation,        //  12
	SystemStackTraceInformation,        //  13
	SystemPagedPoolInformation,        //  14
	SystemNonPagedPoolInformation,        //  15
	SystemHandleInformation,        //  16
	SystemObjectInformation,        //  17
	SystemPageFileInformation,        //  18
	SystemVdmInstemulInformation,        //  19
	SystemVdmBopInformation,        //  20
	SystemFileCacheInformation,        //  21
	SystemPoolTagInformation,        //  22
	SystemInterruptInformation,        //  23
	SystemDpcBehaviorInformation,        //  24
	SystemFullMemoryInformation,        //  25
	SystemLoadGdiDriverInformation,        //  26
	SystemUnloadGdiDriverInformation,        //  27
	SystemTimeAdjustmentInformation,        //  28
	SystemSummaryMemoryInformation,        //  29
	SystemMirrorMemoryInformation,        //  30
	SystemPerformanceTraceInformation,        //  31
	SystemObsolete0,        //  32
	SystemExceptionInformation,        //  33
	SystemCrashDumpStateInformation,        //  34
	SystemKernelDebuggerInformation,        //  35
	SystemContextSwitchInformation,        //  36
	SystemRegistryQuotaInformation,        //  37
	SystemExtendServiceTableInformation,        //  38
	SystemPrioritySeperation,        //  39
	SystemVerifierAddDriverInformation,        //  40
	SystemVerifierRemoveDriverInformation,        //  41
	SystemProcessorIdleInformation,        //  42
	SystemLegacyDriverInformation,        //  43
	SystemCurrentTimeZoneInformation,        //  44
	SystemLookasideInformation,        //  45
	SystemTimeSlipNotification,        //  46
	SystemSessionCreate,        //  47
	SystemSessionDetach,        //  48
	SystemSessionInformation,        //  49
	SystemRangeStartInformation,        //  50
	SystemVerifierInformation,        //  51
	SystemVerifierThunkExtend,        //  52
	SystemSessionProcessInformation,        //  53
	SystemLoadGdiDriverInSystemSpace,        //  54
	SystemNumaProcessorMap,        //  55
	SystemPrefetcherInformation,        //  56
	SystemExtendedProcessInformation,        //  57
	SystemRecommendedSharedDataAlignment,        //  58
	SystemComPlusPackage,        //  59
	SystemNumaAvailableMemory,        //  60
	SystemProcessorPowerInformation,        //  61
	SystemEmulationBasicInformation,        //  62
	SystemEmulationProcessorInformation,        //  63
	SystemExtendedHandleInformation,        //  64
	SystemLostDelayedWriteInformation,        //  65
	SystemBigPoolInformation,        //  66
	SystemSessionPoolTagInformation,        //  67
	SystemSessionMappedViewInformation,        //  68
	SystemHotpatchInformation,        //  69
	SystemObjectSecurityMode,        //  70
	SystemWatchdogTimerHandler,        //  71
	SystemWatchdogTimerInformation,        //  72
	SystemLogicalProcessorInformation,        //  73
	SystemWow64SharedInformation,        //  74
	SystemRegisterFirmwareTableInformationHandler,        //  75
	SystemFirmwareTableInformation,        //  76
	SystemModuleInformationEx,        //  77
	SystemVerifierTriageInformation,        //  78
	SystemSuperfetchInformation,        //  79
	SystemMemoryListInformation,        //  80
	SystemFileCacheInformationEx,        //  81
	MaxSystemInfoClass                      //82

} SYSTEM_INFORMATION_CLASS;

typedef struct
{
	PVOID section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	char ImageName[MAXIMUM_FILENAME_LENGTH];

}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct
{
	ULONG ModuleCount;
	SYSTEM_MODULE Module[1];
}SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

#pragma pack(0)

typedef struct _PEB_LDR_DATA
{

	ULONG Length;
	UCHAR Initialized;
	VOID* SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	VOID* EntryInProgress;
	UCHAR ShutdownInProgress;
	VOID* ShutdownThreadId;
}PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB
{
	ULONG64 x;
	VOID* Mutant;
	VOID* ImageBaseAddress;
	PEB_LDR_DATA* Ldr;

}PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	VOID* DllBase;
	VOID* EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			VOID* SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		VOID* LoadedImports;
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	VOID* PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
	VOID* ContextInformation;
	ULONGLONG OriginalBase;
	LARGE_INTEGER LoadTime;
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;