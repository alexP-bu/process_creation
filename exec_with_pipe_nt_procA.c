#include "internals.h"
#include <stdio.h>
#define BUFSIZE 4096

int main(int argc, char** argv){
  
  //lets get ntdll / kernel32 and functions we need from it
  HANDLE hProcess = NULL;
  hProcess = NtCurrentProcess();
  if(!hProcess){
    printf("[!] Error getting current process: %d\n", GetLastError());
    return -1;
  }
  HMODULE hNtdll = NULL;
  hNtdll = GetModuleHandleA("Ntdll.dll");
  if(!hNtdll){
    printf("[!] Error loading Ntdll.dll: %d\n", GetLastError());
    return -1;
  }
  HMODULE hKernel32 = NULL;
  hKernel32 = GetModuleHandleA("Kernel32.dll");
  if(!hKernel32){
    printf("[!] Error loading kernel32.dll %d\n", GetLastError());
    return -1;
  }

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
  FARPROC fpRtlInitAnsiStringEx = GetProcAddress(hNtdll, "RtlInitAnsiStringEx");
  FARPROC fpRtlAnsiStringToUnicodeString = GetProcAddress(hNtdll, "RtlAnsiStringToUnicodeString");
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
  rtlInitAnsiStringEx RtlInitAnsiStringEx = (rtlInitAnsiStringEx)fpRtlInitAnsiStringEx;
  rtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString = (rtlAnsiStringToUnicodeString)fpRtlAnsiStringToUnicodeString;

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

  //let's remove our use of malloc by using HeapCreate, HeapAlloc, HeapFree, HeapDestroy
  //finally let's bypass HeapAlloc with a direct call to NtAllocateVirtualMemory
  NTSTATUS ntStatus;
  SIZE_T stCommandLine = (sizeof(BYTE) * (strlen("cmd /c "))) + (sizeof(BYTE) * (dwArgsLen + 1));
  PVOID lpCommandLine = 0;
  ntStatus = NtAllocateVirtualMemory(
    hProcess,
    (PVOID)&lpCommandLine,
    0,
    &stCommandLine,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error allocating virtual memory for command line: %x\n", ntStatus);
    return -1;
  }

  //format: cmd /c program arg0 arg1 
  sprintf(lpCommandLine, "cmd /c ");
  for(DWORD i = 1; i < argc; i++){
    sprintf((PBYTE)lpCommandLine + strlen(lpCommandLine), "%s ", argv[i]);
  }
  sprintf((PBYTE)lpCommandLine + strlen(lpCommandLine), "%c", '\0');
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
  swprintf(
    pipeNameBuffer, 
    sizeof(pipeNameBuffer), 
    L"\\Device\\NamedPipe\\Win32Pipes.%p.%08x", 
    teb->Cid.UniqueProcess, pipeId
  );
  RtlInitUnicodeString(
    &pipeName, 
    pipeNameBuffer
  );
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
  ntStatus = NtCreateNamedPipeFile(
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
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error creating named pipe file: %x\n", ntStatus);
    return -1;
  } 
  ntStatus = NtOpenFile(
    &hWritePipe,
    FILE_GENERIC_WRITE,
    &objectAttributes,
    &statusBlock,
    FILE_SHARE_READ,
    FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error opening write pipe of file: %x\n", ntStatus);
    return -1;
  }

  //make sure only write end is inherited
  //we can use ntqueryobject + ntsetinformationobject (reversed sethandleinformation)
  OBJECT_HANDLE_ATTRIBUTE_INFORMATION ohai;
  OBJECT_INFORMATION_CLASS oic;
  ULONG ulBytesWritten = 0;
  ntStatus = NtQueryObject(
    hWritePipe,
    ObjectHandleFlagInformation,
    &ohai,
    sizeof(OBJECT_HANDLE_ATTRIBUTE_INFORMATION),
    &ulBytesWritten
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error querying nt object: %x\n", ntStatus);
    return -1;
  }
  ohai.Inherit = TRUE;
  ntStatus = NtSetInformationObject(
    hWritePipe,
    ObjectHandleFlagInformation,
    &ohai,
    sizeof(ohai)
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error setting nt object information: %x\n", ntStatus);
    return -1;
  }

  //CreateProcessA reversed:
  //CreateProcessA -> CreateProcessInternalA -> CreateProcessInternalW -> ZwCreateUserProcess -> NtCreateUserProcess
  //TODO working on a way to do this with NtCreateUserProcess
  //setup:
  STARTUPINFOA si;
  si.cb = sizeof(si);
  RtlZeroMemory(&si, sizeof(si));
  si.hStdOutput = hWritePipe;
  si.hStdError = hWritePipe;
  si.dwFlags = STARTF_USESTDHANDLES;
  PROCESS_INFORMATION pi;
  RtlZeroMemory(&pi, sizeof(pi));
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
  STARTUPINFOW sw;
  RtlMoveMemory(&sw, &si, sizeof(STARTUPINFOA));
  //for the commandline, RtlInitAnsiStringEx is called, then RtlAnsiStringToUnicodeString
  ANSI_STRING asCmdLine;
  ntStatus = RtlInitAnsiStringEx(&asCmdLine, lpCommandLine);
  if(!NT_SUCCESS(ntStatus)){
    printf("Error initializing ansi string: %x\n", ntStatus);
    return -1;
  }
  ntStatus = RtlAnsiStringToUnicodeString(
    &usCommandLine,
    &asCmdLine,
    TRUE
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error initializing ansi string to unicode string: %x\n", ntStatus);
    return -1;
  }
  if(!CreateProcessInternalW(
    NULL,
    NULL,
    &usCommandLine,
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

  //read from pipe
  PVOID pvBuffer = NULL;
  SIZE_T stBufferSize = (SIZE_T)(sizeof(BYTE) * BUFSIZE);
  ntStatus = NtAllocateVirtualMemory(
    hProcess,
    &pvBuffer,
    0,
    &stBufferSize,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error allocating virtual memory for output buffer: %x", ntStatus);
    return -1;
  }

  //reversed WaitForSingleObject:
  //WaitForSingleObject -> WaitForSingleObjectEx -> ZwWaitForSingleObject -> NtWaitForSingleObject
  LARGE_INTEGER liTimeout;
  liTimeout.QuadPart = 50;
  ULONG totBytes = 0;
  while(NtWaitForSingleObject(pi.hProcess, TRUE, &liTimeout)){
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
      printf("%s", pvBuffer); //THIS IS THE OUTPUT RIGHT HERE
      totBytes -= bytesRead;
    }
  }

  //cleanup
  if(!NT_SUCCESS(NtClose(pi.hThread))){
    printf("[!] Error closing thread handle..\n");
    return -1;
  }
  if(!NT_SUCCESS(NtClose(pi.hProcess))){
    printf("[!] Error closing process handle..\n");
    return -1;
  }
  if(!NT_SUCCESS(NtClose(hWritePipe))){
    printf("[!] Error closing handle to write end of named pipe...\n");
    return -1;
  }
  if(!NT_SUCCESS(NtClose(hReadPipe))){
    printf("[!] Error closing handle to read end of named pipe...\n");
    return -1;
  }
  ntStatus = NtFreeVirtualMemory(
    hProcess,
    &lpCommandLine,
    &stCommandLine,
    MEM_RELEASE
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error freeing commandline memory: %x\n", ntStatus);
    return -1;
  }
  ntStatus = NtFreeVirtualMemory(
    hProcess,
    &pvBuffer,
    &stBufferSize,
    MEM_RELEASE
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error freeing output buffer memory: %x\n", ntStatus);
    return -1;
  }
  ntStatus = LdrUnloadDll(hNtdll);
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error freeing library: %x\n", ntStatus);
    return -1;
  }
  return 0;
}
