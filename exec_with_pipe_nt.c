#include "internals.h"
#include <stdio.h>
#define BUFSIZE 4096

int main(int argc, char** argv){
  //get our current process
  HANDLE hCurProcess = NULL;
  hCurProcess = NtCurrentProcess();

  //get ntdll / kernel32 and functions we need from it
  HMODULE hNtdll = NULL;
  HMODULE hKernel32 = NULL;
  hNtdll = GetModuleHandleA("Ntdll.dll");
  hKernel32 = GetModuleHandleA("Kernel32.dll");

  //get addresses from ntdll
  FARPROC fpNtAllocateVirtualMemory = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
  FARPROC fpNtFreeVirtualMemory = GetProcAddress(hNtdll, "NtFreeVirtualMemory");
  FARPROC fpNtQueryObject = GetProcAddress(hNtdll, "NtQueryObject");
  FARPROC fpNtSetInformationObject = GetProcAddress(hNtdll, "NtSetInformationObject");
  FARPROC fpNtWaitForSingleObject = GetProcAddress(hNtdll, "NtWaitForSingleObject");
  FARPROC fpNtClose = GetProcAddress(hNtdll, "NtClose");
  FARPROC fpNtReadFile = GetProcAddress(hNtdll, "NtReadFile");
  FARPROC fpNtFsControlFile = GetProcAddress(hNtdll, "NtFsControlFile");
  FARPROC fpNtCreateNamedPipeFile = GetProcAddress(hNtdll, "NtCreateNamedPipeFile");
  FARPROC fpRtlInitUnicodeString = GetProcAddress(hNtdll, "RtlInitUnicodeString");
  FARPROC fpNtOpenFile = GetProcAddress(hNtdll, "NtOpenFile");
  FARPROC fpLdrUnloadDll = GetProcAddress(hNtdll, "LdrUnloadDll");
  FARPROC fpNtCreateUserProcess = GetProcAddress(hNtdll, "NtCreateUserProcess");
  FARPROC fpRtlCreateProcessParametersEx = GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
  FARPROC fpRtlAllocateHeap = GetProcAddress(hNtdll, "RtlAllocateHeap");

  //cast functions to get our Nt function pointers
  ntAllocateVirtualMemory NtAllocateVirtualMemory = (ntAllocateVirtualMemory)fpNtAllocateVirtualMemory;
  ntFreeVirtualMemory NtFreeVirtualMemory = (ntFreeVirtualMemory)fpNtFreeVirtualMemory;
  ntQueryObject NtQueryObject = (ntQueryObject)fpNtQueryObject;
  ntSetInformationObject NtSetInformationObject = (ntSetInformationObject)fpNtSetInformationObject;
  ntWaitForSingleObject NtWaitForSingleObject = (ntWaitForSingleObject)fpNtWaitForSingleObject;
  ntClose NtClose = (ntClose)fpNtClose;
  ntReadFile NtReadFile = (ntReadFile)fpNtReadFile; 
  ntFsControlFile NtFsControlFile = (ntFsControlFile)fpNtFsControlFile;
  ntCreateNamedPipeFile NtCreateNamedPipeFile = (ntCreateNamedPipeFile)fpNtCreateNamedPipeFile;
  rtlInitUnicodeString RtlInitUnicodeString = (rtlInitUnicodeString)fpRtlInitUnicodeString;
  ntOpenFile NtOpenFile = (ntOpenFile)fpNtOpenFile;
  ldrUnloadDll LdrUnloadDll = (ldrUnloadDll)fpLdrUnloadDll;
  ntCreateUserProcess NtCreateUserProcess = (ntCreateUserProcess)fpNtCreateUserProcess;
  rtlCreateProcessParametersEx RtlCreateProcessParametersEx = (rtlCreateProcessParametersEx)fpRtlCreateProcessParametersEx;
  rtlAllocateHeap RtlAllocateHeap = (rtlAllocateHeap)fpRtlAllocateHeap;

  //kernel32.dll functions for createprocess
  FARPROC fpCreateProcessInternalA = GetProcAddress(hKernel32, "CreateProcessInternalA");
  FARPROC fpCreateProcessInternalW = GetProcAddress(hKernel32, "CreateProcessInternalW");
  createProcessInternalA CreateProcessInternalA = (createProcessInternalA)fpCreateProcessInternalA;
  createProcessInternalW CreateProcessInternalW = (createProcessInternalW)fpCreateProcessInternalW;

  //get length of command line args
  SIZE_T dwArgsLen = 0;
  for(SIZE_T i = 1; i < argc; i++){
    dwArgsLen += 1; //spaces
    dwArgsLen += strlen(argv[i]);
  }

  //remove our use of malloc by using HeapCreate, HeapAlloc, HeapFree, HeapDestroy
  //finally let's bypass HeapAlloc with a direct call to NtAllocateVirtualMemory
  NTSTATUS ntStatus;
  SIZE_T stCommandLine = (sizeof(BYTE) * (strlen("cmd /c "))) + (sizeof(BYTE) * (dwArgsLen + 1));
  PVOID lpCommandLine = 0;
  NtAllocateVirtualMemory(
    hCurProcess,
    &lpCommandLine,
    0,
    &stCommandLine,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
  );

  //format: cmd /c program arg0 arg1 
  sprintf(lpCommandLine, "cmd /c ");
  for(DWORD i = 1; i < argc; i++){
    sprintf((PBYTE)lpCommandLine + strlen(lpCommandLine), "%s ", argv[i]);
  }
  sprintf((PBYTE)lpCommandLine + strlen(lpCommandLine), "%c", '\0');
  //sprintf((PBYTE)lpCommandLine + strlen(lpCommandLine), " > outfile.txt%c", '\0'); //WE GOT IT TO REDIRECT TO AN OUTPUT FILE now to named pipe..
  //sprintf((PBYTE)lpCommandLine + strlen(lpCommandLine), " > outfile.txt\"%c", '\0');
  //printf("got command line: %s\nlen: %d\n", lpCommandLine, strlen(lpCommandLine)); //DEBUG

  //create pipe!
  //reversed CreatePipe -> NtCreateNamedPipeFile, NtOpenFile again
  //setup help found at https://doxygen.reactos.org/df/d77/npipe_8c_source.html
  HANDLE hReadPipe;
  HANDLE hWritePipe;
  UNICODE_STRING pipeName;
  LARGE_INTEGER defaultTimeout;
  ULONG attributes;
  defaultTimeout.QuadPart = -1200000000;
  //setup pipe name
  WCHAR pipeNameBuffer[128];
  LONG pipeId;
  LONG ProcessPipeId;
  pipeId = InterlockedIncrement(&ProcessPipeId);
  struct _TEB* teb = NtCurrentTeb();
  swprintf(pipeNameBuffer, sizeof(pipeNameBuffer), L"\\Device\\NamedPipe\\Win32Pipes.%p.%08x", teb->Cid.UniqueProcess, pipeId);
  RtlInitUnicodeString(&pipeName, pipeNameBuffer);
  //setup pipe object attributes
  attributes = OBJ_CASE_INSENSITIVE;
  OBJECT_ATTRIBUTES objectAttributes;
  objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
  objectAttributes.RootDirectory = NULL;
  objectAttributes.Attributes = attributes;
  objectAttributes.ObjectName = &pipeName;
  objectAttributes.SecurityDescriptor = NULL;
  objectAttributes.SecurityQualityOfService = NULL;
  IO_STATUS_BLOCK statusBlock;
  NtCreateNamedPipeFile(
    &hReadPipe,
    GENERIC_READ | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
    &objectAttributes,
    &statusBlock,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    FILE_CREATE,
    FILE_SYNCHRONOUS_IO_NONALERT,
    FILE_PIPE_BYTE_STREAM_TYPE,
    FILE_PIPE_BYTE_STREAM_MODE,
    FILE_PIPE_QUEUE_OPERATION,
    1,
    BUFSIZE,
    BUFSIZE,
    &defaultTimeout
  );
  NtOpenFile(
    &hWritePipe, 
    FILE_GENERIC_WRITE, 
    &objectAttributes, 
    &statusBlock, 
    FILE_SHARE_READ, 
    FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
  );

  //make sure only write end is inherited
  //we can use ntqueryobject + ntsetinformationobject (reversed sethandleinformation)
  OBJECT_HANDLE_ATTRIBUTE_INFORMATION ohai;
  OBJECT_INFORMATION_CLASS oic;
  ULONG ulBytesWritten = 0;
  NtQueryObject(
    hWritePipe, 
    ObjectHandleFlagInformation, 
    &ohai, 
    sizeof(OBJECT_HANDLE_ATTRIBUTE_INFORMATION), 
    &ulBytesWritten
  );
  ohai.Inherit = TRUE;
  NtSetInformationObject(
    hWritePipe, 
    ObjectHandleFlagInformation, 
    &ohai, 
    sizeof(ohai)
  );

  //CreateProcessA reversed:
  //CreateProcessA -> CreateProcessInternalA -> CreateProcessInternalW -> ZwCreateUserProcess -> NtCreateUserProcess
  PROCESS_INFORMATION pi;
  RtlZeroMemory(&pi, sizeof(pi));
  //setup for A functions:
  /*
  STARTUPINFOA si;
  RtlZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.hStdOutput = hWritePipe;
  si.hStdError = hWritePipe;
  si.dwFlags = STARTF_USESTDHANDLES;
  */
  //first step: CreateProccessA call:
  /*
  if(!CreateProcessA(NULL, lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)){
    printf("[!] Error creating process: %d\n", GetLastError());
    return -1;
  }
  */
  //second step: CreateProccessInternalA call:
  /*
  if(!CreateProcessInternalA(NULL, NULL, lpCommandLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi, NULL)){
    printf("[!] Error creating process: %d\n", GetLastError);
    return -1;
  }
  */
  //third step: CreateProcessInternalW call (unicode function):
  UNICODE_STRING usCommandLine;
  PVOID wCommandLine = NULL;
  SIZE_T wCommandLineLen = strlen(lpCommandLine) + 1;
  NtAllocateVirtualMemory(
    hCurProcess, 
    &wCommandLine, 
    0, 
    &wCommandLineLen, 
    MEM_COMMIT | MEM_RESERVE, 
    PAGE_READWRITE
  );
  mbstowcs(wCommandLine, lpCommandLine, wCommandLineLen);
  RtlInitUnicodeString(&usCommandLine, wCommandLine);
  /*
  STARTUPINFOW sw;
  RtlZeroMemory(&sw, sizeof(sw));
  sw.cb = sizeof(sw);
  sw.hStdOutput = hWritePipe;
  sw.hStdError = hWritePipe;
  sw.dwFlags = STARTF_USESTDHANDLES;
  if(!CreateProcessInternalW(
    NULL, 
    NULL, 
    usCommandLine.Buffer, 
    NULL, 
    NULL, 
    TRUE, 
    0, 
    NULL, 
    NULL, 
    &sw, 
    &pi, 
    NULL
  )){
    printf("[!] Error creating process: %d\n", GetLastError());
    return -1;
  };
  */
  //TODO fourth step: NtCreateUserProcess call, it takes the same params as ZwCreateUserProcess
  //currently reversing CreateProcessInternalW: 
  //IsProcessInJob, BaseFormatObjectAttributes, BaseFormatObjectAttributes, RtlFreeAnsiString, BasepFreeAppCompatData,
  //BasepReleaseSxsCreateProcessUtilityStruct, RtlAllocateHeap, RtlGetExePath, SearchPathW (it finds cmd.exe path),
  //GetFileAtributesW (on L"C:\\Windows\\System32\\cmd.exe"), RtlDosPathNAmeToNtPathName_U (on L"C:\\Windows\\System32\\cmd.exe"),
  //RtlInitUnicodeStringEx(on L"C:\\Windows\\System32\\cmd.exe"), RtlDetermineDosPathNameType_u, GetEmbdeddedImageMitigationPolicy,
  //RtlWow64GetProcessMachines, 
  //then a function is called with A bunch of RtlInitUnicodeStringEx and RtlCreateProcessParametersWithTemplate
  //another function is called which then calls LdrQueryImageFileExecutionOptionsEx 
  //then finally ZwCreateUserProcess -> NtCreateUserProcess is called
  //then: RtlDestroyProcessParameters, BasepCheckWebBladeHashes, BasepIsProcessAllowed, BasepCheckWinSaferRestrictions, BasepQueryAppCompat,
  //BasepConstructSxsCreateProcessMessage, CsrCaptureMessageMultiUnicodeStringsInPlace, CsrClientCallServer, BaseCheckElevation, 
  //BasepGetAppCompatData, ZwAllocateVirtualMemory, ZwWriteVirtualMemory, ZwWriteVirtualMemory, BaseElevationPostProcessing,
  //ZwResumeThread, RtlFreeAnsiString, BasepReleaseSxsCreateProcessUtilityStruct, RtlFreeHeap, NtCLose, NtClose, BasepFreeAppCompatData,
  //RtlFreeAnsiString, CsrFreeCaptureBuffer
  
  //IsProcessInJob SKIP
  HANDLE hProcess = NULL;
  HANDLE hThread = NULL;
  //setup image path name
  UNICODE_STRING usImagePathName;
  RtlInitUnicodeString(&usImagePathName, (PWSTR)L"\\??\\C:\\Windows\\System32\\cmd.exe");
  //setup the RTL_USER_PROCESS_PARAMETERS struct
  PRTL_USER_PROCESS_PARAMETERS processParams = NULL;
  ntStatus = RtlCreateProcessParametersEx(
    &processParams,
    &usImagePathName,
    NULL,
    NULL,
    &usCommandLine,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    RTL_USER_PROCESS_PARAMETERS_NORMALIZED
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error creating process params: %x\n", ntStatus);
    return -1;
  }
  processParams->StdOutputHandle = hWritePipe;
  processParams->StdErrorHandle = hWritePipe;
  //setup the PS_CREATE_INFO struct
  PS_CREATE_INFO createInfo = { 0 };
  createInfo.Size = sizeof(createInfo);
  createInfo.State = PsCreateInitialState;
  //setup the PS_ATTRIBUTES_LIST struct
  PPS_ATTRIBUTE_LIST attributesList = RtlAllocateHeap(
    NtCurrentTeb()->Peb->ProcessHeap, 
    HEAP_ZERO_MEMORY, 
    sizeof(PS_ATTRIBUTE_LIST)
  );
  attributesList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
  
  //image name
	attributesList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	attributesList->Attributes[0].Size = usImagePathName.Length;
	attributesList->Attributes[0].ValuePtr = usImagePathName.Buffer;
  
  //call ntcreateuserprocess
  ntStatus = NtCreateUserProcess(
    &hProcess,
    &hThread,
    MAXIMUM_ALLOWED,
    MAXIMUM_ALLOWED,
    NULL,
    NULL,
    PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
    0,
    processParams,
    &createInfo,
    attributesList
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] failed to create user process: %x\n", ntStatus);
    return -1;
  }

  //read from pipe
  PVOID pvBuffer = NULL;
  SIZE_T stBufferSize = (SIZE_T)(sizeof(BYTE) * BUFSIZE);
  NtAllocateVirtualMemory(
    hCurProcess, 
    &pvBuffer, 
    0, 
    &stBufferSize, 
    MEM_COMMIT | MEM_RESERVE, 
    PAGE_READWRITE
  );

  //reversed WaitForSingleObject:
  //WaitForSingleObject -> WaitForSingleObjectEx -> ZwWaitForSingleObject -> NtWaitForSingleObject
  LARGE_INTEGER liTimeout;
  liTimeout.QuadPart = 50;
  ULONG totBytes = 0;
  while(NtWaitForSingleObject(hProcess, TRUE, &liTimeout)){
    //reversed PeekNamedPipe:
    //PeekNamedPipe -> RtlAllocateHeap, ZwCreateEvent, ZwFsControlFile, RtlFreeHeap, NtClose
    //We want ZwFsControlFile -> NtFsControlFile with FSCTL_PIPE_PEEK
    //https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b6e51f60-a6df-4c2d-9b28-40092e816641
    IO_STATUS_BLOCK isbPeek;
    FILE_PIPE_PEEK_BUFFER peekBuffer;
    ntStatus = NtFsControlFile(
      hReadPipe, 
      NULL, 
      NULL, 
      NULL, 
      &isbPeek, 
      FSCTL_PIPE_PEEK, 
      NULL, 
      0, 
      &peekBuffer, 
      sizeof(peekBuffer)
    );
    if(ntStatus == STATUS_PENDING){
      ntStatus = NtWaitForSingleObject(hReadPipe, FALSE, NULL);
      if(NT_SUCCESS(ntStatus)){
        ntStatus = isbPeek.Status;
      }
    }
    if(NT_SUCCESS(ntStatus)){
      totBytes = peekBuffer.ReadDataAvailable;
    }else{
      printf("[!] Error peeking pipe: %x\n", ntStatus);
      return -1;
    }
    //read the actual data
    while(totBytes > 0){
      ULONG numBytes = 0;
      ULONG bytesRead = 0;
      if(totBytes > (BUFSIZE - 1)){
        numBytes = BUFSIZE;
      }else{
        numBytes = totBytes;
      }
      //reversed: Readfile -> NtReadFile
      IO_STATUS_BLOCK isbRead; 
      ntStatus = NtReadFile(
        hReadPipe, 
        NULL, 
        NULL, 
        NULL, 
        &isbRead, 
        pvBuffer, 
        numBytes, 
        NULL, 
        NULL
      );
      if(ntStatus == STATUS_PENDING){
        ntStatus = NtWaitForSingleObject(hReadPipe, FALSE, NULL);
        if(NT_SUCCESS(ntStatus)){
          ntStatus = isbRead.Status;
        }
      }
      if(NT_SUCCESS(ntStatus)){
        bytesRead = isbRead.Information;
      }else{
        printf("[!] Error reading pipe: %x\n", ntStatus);
        return -1;
      }
      ((PBYTE)pvBuffer)[bytesRead] = '\0';
      printf("%s", pvBuffer); //THIS IS THE OUTPUT RIGHT HERE WE CAN RETURN IT 
      totBytes -= bytesRead;
    }
  }

  //cleanup
  NtClose(pi.hThread);
  NtClose(pi.hProcess);
  NtClose(hWritePipe);
  NtClose(hReadPipe);
  NtFreeVirtualMemory(hCurProcess, &lpCommandLine, &stCommandLine, MEM_RELEASE);
  NtFreeVirtualMemory(hCurProcess, &pvBuffer, &stBufferSize, MEM_RELEASE);
  //NtFreeVirtualMemory(hCurProcess, &wCommandLine, &wCommandLineLen, MEM_RELEASE);
  LdrUnloadDll(hNtdll);
  LdrUnloadDll(hKernel32);
  return 0;
}
