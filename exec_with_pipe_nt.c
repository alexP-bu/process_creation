#include "internals.h"
#include <stdio.h>
#define BUFSIZE 4096

int main(int argc, char** argv){
  
  //lets get ntdll and functions we need from it
  HANDLE hProcess = NULL;
  hProcess = NtCurrentProcess();
  if(!hProcess){
    printf("[!] Error getting current process: %d\n", GetLastError());
    return -1;
  }
  HMODULE hNtdll = NULL;
  hNtdll = LoadLibraryA("ntdll");
  if(!hNtdll){
    printf("[!] Error loading ntdll: %d\n", GetLastError());
    return -1;
  }

  //get addresses from ntdll
  FARPROC fpNtAllocateVirtualMemory = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
  FARPROC fpNtFreeVirtualMemory = GetProcAddress(hNtdll, "NtFreeVirtualMemory");
  FARPROC fpNtQueryObject = GetProcAddress(hNtdll, "NtQueryObject");
  FARPROC fpNtSetInformationObject = GetProcAddress(hNtdll, "NtSetInformationObject");
  FARPROC fpNtCreateUserProcess = GetProcAddress(hNtdll, "NtCreateUserProcess");
  FARPROC fpNtWaitForSingleObject = GetProcAddress(hNtdll, "NtWaitForSingleObject");
  FARPROC fpNtClose = GetProcAddress(hNtdll, "NtClose");
  //cast functions to get our Nt function pointers
  ntAllocateVirtualMemory NtAllocateVirtualMemory = (ntAllocateVirtualMemory)fpNtAllocateVirtualMemory;
  ntFreeVirtualMemory NtFreeVirtualMemory = (ntFreeVirtualMemory)fpNtFreeVirtualMemory;
  ntQueryObject NtQueryObject = (ntQueryObject)fpNtQueryObject;
  ntSetInformationObject NtSetInformationObject = (ntSetInformationObject)fpNtSetInformationObject;
  ntCreateUserProcess NtCreateUserProcess = (ntCreateUserProcess)fpNtCreateUserProcess;
  ntWaitForSingleObject NtWaitForSingleObject = (ntWaitForSingleObject)fpNtWaitForSingleObject;
  ntClose NtClose = (ntClose)fpNtClose;

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

  //create pipe
  HANDLE hReadPipe;
  HANDLE hWritePipe;
  SECURITY_ATTRIBUTES sa;
  RtlZeroMemory(&sa, sizeof(sa));

  //createpipe calls NtOpenFile and NtCreateNamedPipeFile then NtOpenFile again, 
  //TODO need to keep reversing this
  if(!CreatePipe(
    &hReadPipe,
    &hWritePipe,
    &sa,
    BUFSIZE
  )){
    printf("[!] Error creating pipe: %d\n", GetLastError());
    return -1;
  }

  //make sure only write end is inherited
  //we can use ntqueryobject + ntsetinformationobject (reverse engineered sethandleinformation)
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

  //CreateProcessA reverse engineering:
  //CreateProcessA -> CreateProcessInternalA -> CreateProcessInternalW -> ZwCreateUserProcess -> NtCreateUserProcess
  //So, let's user NtCreateUserProcess to make it happen
  //https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html
  //TODO need to actually make it work lol
  STARTUPINFO si;
  RtlZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  si.hStdOutput = hWritePipe;
  si.hStdError = hWritePipe;
  si.dwFlags = STARTF_USESTDHANDLES;
  PROCESS_INFORMATION pi;
  RtlZeroMemory(&pi, sizeof(pi));
  if(!CreateProcessA(
    NULL,
    lpCommandLine,
    NULL,
    NULL,
    TRUE,
    0,
    NULL,
    NULL,
    &si,
    &pi
  )){
    printf("[!] Error creating process: %d\n", GetLastError());
    return -1;
  }

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
  DWORD totBytes = 0;
  while(NtWaitForSingleObject(pi.hProcess, TRUE, &liTimeout)){
    if(!PeekNamedPipe(hReadPipe, NULL, 0, NULL, &totBytes, NULL)){
      printf("[!] Error peeking named pipe: %d\n", GetLastError());
      return -1;
    }
    while(totBytes > 0){
      DWORD numBytes = 0;
      DWORD bytesRead = 0;
      if(totBytes > (BUFSIZE - 1)){
        numBytes = BUFSIZE;
      }else{
        numBytes = totBytes;
      } 
      if(!ReadFile(hReadPipe, pvBuffer, numBytes, &bytesRead, NULL)){
        printf("[!] Error reading data from pipe: %d\n", GetLastError());
        return -1;
      }
      ((PBYTE)pvBuffer)[bytesRead] = '\0';
      printf("%s", pvBuffer);
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
    printf("[!] Error freeing commandline memory, %x\n", ntStatus);
    return -1;
  }
  ntStatus = NtFreeVirtualMemory(
    hProcess,
    &pvBuffer,
    &stBufferSize,
    MEM_RELEASE
  );
  if(!NT_SUCCESS(ntStatus)){
    printf("[!] Error freeing output buffer memory, %x\n", ntStatus);
    return -1;
  }
  return 0;
}