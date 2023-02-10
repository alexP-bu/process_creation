#include <windows.h>
//https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NtCurrentProcess()((HANDLE)(LONG_PTR)-1)

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block
typedef struct IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  };
  ULONG_PTR Information;
}IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

//https://processhacker.sourceforge.io/doc/ntioapi_8h_source.html
typedef VOID (NTAPI *PIO_APC_ROUTINE)(
  PVOID ApcContext,
  PIO_STATUS_BLOCK IoStatusBlock,
  ULONG Reserved
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

//https://gitee.com/M2-Team/M2-SDK/blob/master/M2.Windows.h
typedef struct PS_ATTRIBUTE{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

//https://gitee.com/M2-Team/M2-SDK/blob/master/M2.Windows.h
typedef struct PS_ATTRIBUTE_LIST{
  SIZE_T TotalLength;
  PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

//https://www.vergiliusproject.com/kernels/x64/Windows%208%20%7C%202012/RTM/PS_CREATE_STATE
typedef enum PS_CREATE_STATE{
  PsCreateInitialState,
  PsCreateFailOnFileOpen,
  PsCreateFailOnSectionCreate,
  PsCreateFailExeFormat,
  PsCreateFailMachineMismatch,
  PsCreateFailExeName,
  PsCreateSuccess,
  PsCreateMaximumStates 
} PS_CREATE_STATE;

//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi/ps_create_info/index.htm
//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntpsapi/ps_create_info/initflags.htm
//this one is weird man
typedef struct PS_CREATE_INFO{
  ULONG_PTR Size;
  PS_CREATE_STATE State;
  union {
    struct{
      union {
        ULONG InitFlags;
        struct{
          UCHAR WriteOutputOnExit : 1;
          UCHAR DetectManifest : 1;
          UCHAR IFEOSkipDebugger : 1;
          UCHAR IFEODoNotPropagateKeyState : 1;
          UCHAR SpareBits1 : 4; //used later version
          UCHAR IFEOKeyState : 2;
          UCHAR SpareBits2 : 8; //used later version
          USHORT ProhibitedImageCharacteristics : 16;
        };
        ACCESS_MASK AdditionalFileAccess;
      };
    } InitState;
    struct{
      HANDLE FileHandle;
    } FailSection;
    struct {
      USHORT DllCharacteristics;
    } ExeFormat;
    struct {
      HANDLE IFEOKey;
    } ExeName;
    struct {
      union {
        UCHAR ProtectedProcess : 1;
        UCHAR AddressSpaceOverride : 1;
        UCHAR DevOverrideEnabled : 1;
        UCHAR ManifestDetected : 1;
        UCHAR ProtectedProcessLight : 1;
        UCHAR SpareBits1 : 3; //used later version
        UCHAR SpareBits2 : 8;
        USHORT SpareBits3 : 16;
      };
      HANDLE FileHandle;
      HANDLE SectionHandle;
      ULONGLONG UserProcessParameters;
      ULONG UserProcessParametersNative;
      ULONG UserProcessParamtersWow64;
      ULONG CurrentParameterFlags;
      ULONGLONG PebAddressNative;
      ULONG PebAddressWow64;
      ULONGLONG ManifestAddress;
      ULONG ManifestSize;
    } SuccessState;
  };
} PS_CREATE_INFO, *PPS_CREATE_INFO;

//https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
typedef struct UNICODE_STRING{
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

//https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters
typedef struct RTL_USER_PROCESS_PARAMETERS {
  BYTE Reserved1[16];
  PVOID Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

//https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
typedef struct OBJECT_ATTRIBUTES{
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

//https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html
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

//https://doxygen.reactos.org/d3/d21/struct__OBJECT__HANDLE__ATTRIBUTE__INFORMATION.html
typedef struct OBJECT_HANDLE_ATTRIBUTE_INFORMATION {
  BOOLEAN Inherit;
  BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_ATTRIBUTE_INFORMATION;

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

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_public_object_basic_information
typedef struct OBJECT_BASIC_INFORMATION {
  ULONG Attributes;
  ACCESS_MASK GrantedAccess;
  ULONG HandleCount;
  ULONG PointerCount;
  ULONG Reserved[10];
}OBJECT_BASIC_INFORMATION;

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