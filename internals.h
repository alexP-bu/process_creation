#include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NtCurrentProcess()((HANDLE)(LONG_PTR)-1)	

//https://chromium.googlesource.com/external/github.com/DynamoRIO/drmemory/+/refs/heads/master/wininc/ntifs.h
#define FSCTL_PIPE_PEEK CTL_CODE(FILE_DEVICE_NAMED_PIPE, 3, METHOD_BUFFERED, FILE_READ_DATA)

//https://processhacker.sourceforge.io/doc/ntbasic_8h.html
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_CREATE 0x00000002
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_PIPE_BYTE_STREAM_TYPE 0x00000000
#define FILE_PIPE_BYTE_STREAM_MODE 0x00000000
#define FILE_PIPE_QUEUE_OPERATION 0x00000000
#define FILE_NON_DIRECTORY_FILE 0x00000040

/*
  * STRUCTS 
*/

//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntobapi_x/object_information_class.htm
typedef enum OBJECT_INFORMATION_CLASS {
  ObjectBasicInformation,
  ObjectNameInformation,
  ObjectTypeInformation,
  ObjectTypesInformation,
  ObjectHandleFlagInformation,
  ObjectSessionInformation,
  ObjectSessionObjectInformation,
  MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

//https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
typedef struct UNICODE_STRING{
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

//http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FPEB_LDR_DATA.html
typedef struct _PEB_LDR_DATA {
  ULONG Length;
  BOOLEAN Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

//http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FTEB.html
typedef struct PEB_FREE_BLOCK {
  struct PEB_FREE_BLOCK *Next;
  ULONG Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

//http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FTEB.html
typedef void (*PPEBLOCKROUTINE)(
  PVOID PebLock
);

typedef struct RTL_DRIVE_LETTER_CURDIR{
  USHORT Flags;
  USHORT Length;
  ULONG TimeStamp;
  UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR,*PRTL_DRIVE_LETTER_CURDIR;

//http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/
typedef struct RTL_USER_PROCESS_PARAMETERS{
  ULONG MaximumLength;
  ULONG Length;
  ULONG Flags;
  ULONG DebugFlags;
  PVOID ConsoleHandle;
  ULONG ConsoleFlags;
  HANDLE StdInputHandle;
  HANDLE StdOutputHandle;
  HANDLE StdErrorHandle;
  UNICODE_STRING CurrentDirectoryPath;
  HANDLE CurrentDirectoryHandle;
  UNICODE_STRING DllPath;
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
  PVOID Environment;
  ULONG StartingPositionLeft;
  ULONG StartingPositionTop;
  ULONG Width;
  ULONG Height;
  ULONG CharWidth;
  ULONG CharHeight;
  ULONG ConsoleTextAttributes;
  ULONG WindowFlags;
  ULONG ShowWindowFlags;
  UNICODE_STRING WindowTitle;
  UNICODE_STRING DesktopName;
  UNICODE_STRING ShellInfo;
  UNICODE_STRING RuntimeData;
  RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS,*PRTL_USER_PROCESS_PARAMETERS;

//http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FTEB.html
typedef struct PEB {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  BOOLEAN Spare;
  HANDLE Mutant;
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA LoaderData;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID SubSystemData;
  PVOID ProcessHeap;
  PVOID FastPebLock;
  PPEBLOCKROUTINE FastPebLockRoutine;
  PPEBLOCKROUTINE FastPebUnlockRoutine;
  ULONG EnvironmentUpdateCount;
  PVOID *KernelCallbackTable;
  PVOID EventLogSection;
  PVOID EventLog;
  PPEB_FREE_BLOCK FreeList;
  ULONG TlsExpansionCounter;
  PVOID TlsBitmap;
  ULONG TlsBitmapBits[0x2];
  PVOID ReadOnlySharedMemoryBase;
  PVOID ReadOnlySharedMemoryHeap;
  PVOID *ReadOnlyStaticServerData;
  PVOID AnsiCodePageData;
  PVOID OemCodePageData;
  PVOID UnicodeCaseTableData;
  ULONG NumberOfProcessors;
  ULONG NtGlobalFlag;
  BYTE Spare2[0x4];
  LARGE_INTEGER CriticalSectionTimeout;
  ULONG HeapSegmentReserve;
  ULONG HeapSegmentCommit;
  ULONG HeapDeCommitTotalFreeThreshold;
  ULONG HeapDeCommitFreeBlockThreshold;
  ULONG NumberOfHeaps;
  ULONG MaximumNumberOfHeaps;
  PVOID **ProcessHeaps;
  PVOID GdiSharedHandleTable;
  PVOID ProcessStarterHelper;
  PVOID GdiDCAttributeList;
  PVOID LoaderLock;
  ULONG OSMajorVersion;
  ULONG OSMinorVersion;
  ULONG OSBuildNumber;
  ULONG OSPlatformId;
  ULONG ImageSubSystem;
  ULONG ImageSubSystemMajorVersion;
  ULONG ImageSubSystemMinorVersion;
  ULONG GdiHandleBuffer[0x22];
  ULONG PostProcessInitRoutine;
  ULONG TlsExpansionBitmap;
  BYTE  TlsExpansionBitmapBits[0x80];
  ULONG SessionId;
} PEB, *PPEB;

//https://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
typedef struct CLIENT_ID{
  PVOID UniqueProcess;
  PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

//http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FTEB.html
typedef struct _TEB {
  NT_TIB Tib;
  PVOID EnvironmentPointer;
  CLIENT_ID Cid;
  PVOID ActiveRpcInfo;
  PVOID ThreadLocalStoragePointer;
  PPEB  Peb;
  ULONG LastErrorValue;
  ULONG CountOfOwnedCriticalSections;
  PVOID CsrClientThread;
  PVOID Win32ThreadInfo;
  ULONG Win32ClientInfo[0x1F];
  PVOID WOW32Reserved;
  ULONG CurrentLocale;
  ULONG FpSoftwareStatusRegister;
  PVOID SystemReserved1[0x36];
  PVOID Spare1;
  ULONG ExceptionCode;
  ULONG SpareBytes1[0x28];
  PVOID SystemReserved2[0xA];
  ULONG GdiRgn;
  ULONG GdiPen;
  ULONG GdiBrush;
  CLIENT_ID RealClientId;
  PVOID GdiCachedProcessHandle;
  ULONG GdiClientPID;
  ULONG GdiClientTID;
  PVOID GdiThreadLocaleInfo;
  PVOID UserReserved[5];
  PVOID GlDispatchTable[0x118];
  ULONG GlReserved1[0x1A];
  PVOID GlReserved2;
  PVOID GlSectionInfo;
  PVOID GlSection;
  PVOID GlTable;
  PVOID GlCurrentRC;
  PVOID GlContext;
  NTSTATUS LastStatusValue;
  UNICODE_STRING StaticUnicodeString;
  WCHAR StaticUnicodeBuffer[0x105];
  PVOID DeallocationStack;
  PVOID TlsSlots[0x40];
  LIST_ENTRY TlsLinks;
  PVOID Vdm;
  PVOID ReservedForNtRpc;
  PVOID DbgSsReserved[0x2];
  ULONG HardErrorDisabled;
  PVOID Instrumentation[0x10];
  PVOID WinSockData;
  ULONG GdiBatchCount;
  ULONG Spare2;
  ULONG Spare3;
  ULONG Spare4;
  PVOID ReservedForOle;
  ULONG WaitingOnLoaderLock;
  PVOID StackCommit;
  PVOID StackCommitMax;
  PVOID StackReserved;
} TEB, *PTEB;

//https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
typedef struct OBJECT_ATTRIBUTES{
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block
typedef struct IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

//https://doxygen.reactos.org/d6/d09/struct__FILE__PIPE__PEEK__BUFFER.html
typedef struct FILE_PIPE_PEEK_BUFFER{
  ULONG NamedPipeState;
  ULONG ReadDataAvailable;
  ULONG NumberOfMessages;
  ULONG MessageLEngth;
  CHAR Data[1];
} FILE_PIPE_PEEK_BUFFER, *PFILE_PIPE_PEEK_BUFFER;

//https://doxygen.reactos.org/d3/d21/struct__OBJECT__HANDLE__ATTRIBUTE__INFORMATION.html
typedef struct OBJECT_HANDLE_ATTRIBUTE_INFORMATION {
  BOOLEAN Inherit;
  BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_ATTRIBUTE_INFORMATION;

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_public_object_basic_information
typedef struct OBJECT_BASIC_INFORMATION {
  ULONG Attributes;
  ACCESS_MASK GrantedAccess;
  ULONG HandleCount;
  ULONG PointerCount;
  ULONG Reserved[10];
}OBJECT_BASIC_INFORMATION;


/*
  * FUNCTIONS
*/

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory
typedef NTSTATUS (NTAPI* ntAllocateVirtualMemory)(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  ULONG_PTR ZeroBits,
  PSIZE_T RegionSize,
  ULONG AllocationType,
  ULONG Protect
);

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntfreevirtualmemory
typedef NTSTATUS (NTAPI* ntFreeVirtualMemory)(
  HANDLE ProcessHandle,
  PVOID *BaseAddress,
  PSIZE_T RegionSize,
  ULONG FreeType
);

//https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
typedef NTSTATUS (NTAPI* ntQueryObject)(
  HANDLE Handle,
  OBJECT_INFORMATION_CLASS ObjectInformationClass,
  PVOID ObjectInformation,
  ULONG ObjectInformationLength,
  PULONG ReturnLength
);

//http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FNtSetInformationObject.html
typedef NTSTATUS (NTAPI* ntSetInformationObject)(
  HANDLE ObjectHandle,
  OBJECT_INFORMATION_CLASS ObjectInformationClass,
  PVOID ObjectInformation,
  ULONG Length
);

typedef BOOL (WINAPI* createProcessInternalW)(
  HANDLE hUserToken,
  LPCWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,
  LPSTARTUPINFOW lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation,
  PHANDLE hNewToken
);

typedef BOOL (WINAPI* createProcessInternalA)(
  HANDLE hToken,
  LPCSTR lpApplicationName,
  LPSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandles,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,
  LPSTARTUPINFOA lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation,
  PHANDLE hNewToken
);

//http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FLdrUnloadDll.html
typedef NTSTATUS (NTAPI* ldrUnloadDll)(
  HANDLE ModuleHandle
);

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitunicodestring
typedef void (NTAPI* rtlInitUnicodeString)(
  PUNICODE_STRING DestinationString,
  PCWSTR SourceString
);

//https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntopenfile
typedef NTSTATUS(NTAPI* ntOpenFile)(
  PHANDLE FileHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK IoStatusBlock,
  ULONG ShareAccess,
  ULONG OpenOptions
);

//http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FFile%2FNtCreateNamedPipeFile.html
typedef NTSTATUS (NTAPI* ntCreateNamedPipeFile)(
  PHANDLE NamedPipeFileHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK IoStatusBlock,
  ULONG ShareAccess,
  ULONG CreateDisposition,
  ULONG CreateOptions,
  BOOLEAN WriteModeMessage,
  BOOLEAN ReadModeMessage,
  BOOLEAN NonBlocking,
  ULONG MaxInstances,
  ULONG InBufferSize,
  ULONG OutBufferSize,
  PLARGE_INTEGER DefaultTimeOut
);

//https://processhacker.sourceforge.io/doc/ntioapi_8h_source.html
typedef VOID (NTAPI *PIO_APC_ROUTINE)(
  PVOID ApcContext,
  PIO_STATUS_BLOCK IoStatusBlock,
  ULONG Reserved
);

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntfscontrolfile
typedef NTSTATUS (NTAPI* ntFsControlFile)(
  HANDLE FileHandle,
  HANDLE Event,
  PIO_APC_ROUTINE ApcRoutine,
  PVOID ApcContext,
  PIO_STATUS_BLOCK IoStatusBlock,
  ULONG FsControlCode,
  PVOID InputBuffer,
  ULONG InputBufferLength,
  PVOID OutputBuffer,
  ULONG OutputBufferLength
); 

//https://learn.microsoft.com/en-us/windows/win32/devnotes/ntreadfile
//https://stackoverflow.com/questions/10822771/how-to-use-icmpsendecho2-with-pio-apc-routine
typedef NTSTATUS (NTAPI* ntReadFile)(
  HANDLE FileHandle,
  HANDLE Event,
  PIO_APC_ROUTINE ApcRoutine,
  PVOID ApcContext,
  PIO_STATUS_BLOCK IoStatusBlock,
  PVOID Buffer,
  ULONG Length,
  PLARGE_INTEGER ByteOffset,
  PULONG Key
);

//https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntclose
typedef NTSTATUS (NTAPI* ntClose)(
  HANDLE Handle
);

//https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntwaitforsingleobject
typedef NTSTATUS (NTAPI* ntWaitForSingleObject)(
  HANDLE Handle,
  BOOLEAN Alertable,
  PLARGE_INTEGER Timeout
);

/*
  * NtCreateUserProcess setup
*/

typedef enum _PS_IFEO_KEY_STATE{
	PsReadIFEOAllValues,
	PsSkipIFEODebugger,
	PsSkipAllIFEO,
	PsMaxIFEOKeyStates
} PS_IFEO_KEY_STATE, * PPS_IFEO_KEY_STATE;

typedef enum _PS_ATTRIBUTE_NUM{
	PsAttributeParentProcess, // in HANDLE
	PsAttributeDebugObject, // in HANDLE
	PsAttributeToken, // in HANDLE
	PsAttributeClientId, // out PCLIENT_ID
	PsAttributeTebAddress, // out PTEB *
	PsAttributeImageName, // in PWSTR
	PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
	PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
	PsAttributePriorityClass, // in UCHAR
	PsAttributeErrorMode, // in ULONG
	PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
	PsAttributeHandleList, // in HANDLE[]
	PsAttributeGroupAffinity, // in PGROUP_AFFINITY
	PsAttributePreferredNode, // in PUSHORT
	PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
	PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
	PsAttributeMitigationOptions, // in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
	PsAttributeProtectionLevel, // in PS_PROTECTION // since WINBLUE
	PsAttributeSecureProcess, // in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
	PsAttributeJobList, // in HANDLE[]
	PsAttributeChildProcessPolicy, // 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
	PsAttributeAllApplicationPackagesPolicy, // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
	PsAttributeWin32kFilter, // in PWIN32K_SYSCALL_FILTER
	PsAttributeSafeOpenPromptOriginClaim, // in
	PsAttributeBnoIsolation, // in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
	PsAttributeDesktopAppPolicy, // in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
	PsAttributeChpe, // in BOOLEAN // since REDSTONE3
	PsAttributeMitigationAuditOptions, // in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
	PsAttributeMachineType, // in WORD // since 21H2
	PsAttributeComponentFilter,
	PsAttributeEnableOptionalXStateFeatures, // since WIN11
	PsAttributeMax
} PS_ATTRIBUTE_NUM;

#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000
#define PS_ATTRIBUTE_INPUT 0x00020000
#define PS_ATTRIBUTE_ADDITIVE 0x00040000

#define PsAttributeValue(Number, Thread, Input, Additive) \
  (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
  ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
  ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
  ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE) // 0x60000
#define PS_ATTRIBUTE_DEBUG_OBJECT \
    PsAttributeValue(PsAttributeDebugObject, FALSE, TRUE, TRUE) // 0x60001
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE) // 0x60002
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE) // 0x10003
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE) // 0x10004
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE) // 0x20005
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE) // 0x6
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE) // 0x20007
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE) // 0x20008
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE) // 0x20009
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE) // 0x2000A
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE) // 0x2000B
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE) // 0x2000C
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE) // 0x2000D
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE) // 0x2000E
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE) // 0x60010
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, FALSE) // 0x20011
#define PS_ATTRIBUTE_SECURE_PROCESS \
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE) // 0x20012
#define PS_ATTRIBUTE_JOB_LIST \
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE) // 0x20013
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY \
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE) // 0x20014
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE) // 0x20015
#define PS_ATTRIBUTE_WIN32K_FILTER \
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE) // 0x20016
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM \
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE) // 0x20017
#define PS_ATTRIBUTE_BNO_ISOLATION \
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE) // 0x20018
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY \
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE) // 0x20019
#define PS_ATTRIBUTE_CHPE \
    PsAttributeValue(PsAttributeChpe, FALSE, TRUE, TRUE) // 0x6001A
#define PS_ATTRIBUTE_MITIGATION_AUDIT_OPTIONS \
    PsAttributeValue(PsAttributeMitigationAuditOptions, FALSE, TRUE, FALSE) // 0x2001B
#define PS_ATTRIBUTE_MACHINE_TYPE \
    PsAttributeValue(PsAttributeMachineType, FALSE, TRUE, TRUE) // 0x6001C
#define PS_ATTRIBUTE_COMPONENT_FILTER \
    PsAttributeValue(PsAttributeComponentFilter, FALSE, TRUE, FALSE) // 0x2001D
#define PS_ATTRIBUTE_ENABLE_OPTIONAL_XSTATE_FEATURES \
    PsAttributeValue(PsAttributeEnableOptionalXStateFeatures, TRUE, TRUE, FALSE) // 0x3001E

#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON (0x00000001ull << 44)
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS 0x00008000 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 0x01
#define HANDLE_CREATE_NEW_CONSOLE   ((HANDLE)-2)

typedef enum _PS_CREATE_STATE{
  PsCreateInitialState,
  PsCreateFailOnFileOpen,
  PsCreateFailOnSectionCreate,
  PsCreateFailExeFormat,
  PsCreateFailMachineMismatch,
  PsCreateFailExeName, // Debugger specified
  PsCreateSuccess,
  PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_STD_HANDLE_INFO{
	union{
		ULONG Flags;
		struct{
			ULONG StdHandleState : 2; // PS_STD_HANDLE_STATE
			ULONG PseudoHandleMask : 3; // PS_STD_*
		} s;
	};
	ULONG StdHandleSubsystemType;
} PS_STD_HANDLE_INFO, * PPS_STD_HANDLE_INFO;

typedef struct SECTION_IMAGE_INFORMATION{
	PVOID TransferAddress; // Entry point
	ULONG ZeroBits;
	SIZE_T MaximumStackSize;
	SIZE_T CommittedStackSize;
	ULONG SubSystemType;
	union{
		struct{
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		} s1;
		ULONG SubSystemVersion;
	} u1;
	union{
		struct{
			USHORT MajorOperatingSystemVersion;
			USHORT MinorOperatingSystemVersion;
		} s2;
		ULONG OperatingSystemVersion;
	} u2;
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	union{
		UCHAR ImageFlags;
		struct{
			UCHAR ComPlusNativeReady : 1;
			UCHAR ComPlusILOnly : 1;
			UCHAR ImageDynamicallyRelocated : 1;
			UCHAR ImageMappedFlat : 1;
			UCHAR BaseBelow4gb : 1;
			UCHAR ComPlusPrefer32bit : 1;
			UCHAR Reserved : 2;
		} s3;
	} u3;
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

//https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html
typedef struct _PS_CREATE_INFO{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union{
		// PsCreateInitialState
		struct{
			union{
				ULONG InitFlags;
				struct{
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				} s1;
			} u1;
			ACCESS_MASK AdditionalFileAccess;
		} InitState;
		// PsCreateFailOnSectionCreate
		struct{
			HANDLE FileHandle;
		} FailSection;
		// PsCreateFailExeFormat
		struct{
			USHORT DllCharacteristics;
		} ExeFormat;
		// PsCreateFailExeName
		struct{
			HANDLE IFEOKey;
    } ExeName;
		// PsCreateSuccess
	  struct{
			union{
			  ULONG OutputFlags;
				struct{
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1; // From Image File Execution Options
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				} s2;
			} u2;
			HANDLE FileHandle;
			HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1]; // Depends on how many attribute entries should be supplied to NtCreateUserProcess
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef NTSTATUS (NTAPI* ntCreateUserProcess)(
  PHANDLE ProcessHandle,
  PHANDLE ThreadHandle,
  ACCESS_MASK ProcessDesiredAccess,
  ACCESS_MASK ThreadDesiredAccess,
  POBJECT_ATTRIBUTES ProcessObjectAttributes,
  POBJECT_ATTRIBUTES ThreadObjectAttributes,
  ULONG ProcessFlags,
  ULONG ThreadFlags,
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
  PPS_CREATE_INFO CreateInfo,
  PPS_ATTRIBUTE_LIST AttributeList
);

typedef NTSTATUS (NTAPI* rtlCreateProcessParametersEx)(
  PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
  PUNICODE_STRING ImagePathName,
  PUNICODE_STRING DllPath,
  PUNICODE_STRING CurrentDirectory,
  PUNICODE_STRING CommandLine,
  PVOID Environment,
  PUNICODE_STRING WindowTitle,
  PUNICODE_STRING DesktopInfo,
  PUNICODE_STRING ShellInfo,
  PUNICODE_STRING RuntimeData,
  ULONG Flags
);

typedef PVOID (NTAPI* rtlAllocateHeap)(
  PVOID HeapHandle,
	ULONG Flags,
	SIZE_T Size
);
