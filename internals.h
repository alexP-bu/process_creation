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

//https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters
typedef struct RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

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
  HANDLE ModuleHandle;
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