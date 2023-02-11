//file to create a process using NtCreateUserProcess()
#include "internals.h"
#include <stdio.h>

int main(int argc, char **argv){
  //load ntdll.dll
  HMODULE hNtdll = LoadLibraryA("ntdll.dll");
  
  //get function addresses
  FARPROC pNtCreateUserProcess = GetProcAddress(hNtdll, "NtCreateUserProcess");
  FARPROC pRtlInitUnicodeString = GetProcAddress(hNtdll, "RtlInitUnicodeString");
  FARPROC pRtlCreateProcessParametersEx = GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
  FARPROC pRtlAllocateHeap = GetProcAddress(hNtdll, "RtlAllocateHeap");
  FARPROC pRtlFreeHeap = GetProcAddress(hNtdll, "RtlFreeHeap");

  //cast function addresses to function pointers
  ntCreateUserProcess NtCreateUserProcess = (ntCreateUserProcess)pNtCreateUserProcess;
  rtlInitUnicodeString RtlInitUnicodeString = (rtlInitUnicodeString)pRtlInitUnicodeString;
  rtlCreateProcessParametersEx RtlCreateProcessParametersEx = (rtlCreateProcessParametersEx)pRtlCreateProcessParametersEx;
  rtlAllocateHeap RtlAllocateHeap = (rtlAllocateHeap)pRtlAllocateHeap;
  rtlFreeHeap RtlFreeHeap = (rtlFreeHeap)pRtlFreeHeap;

	// Path to the image file from which the process will be created
	UNICODE_STRING NtImagePath;
	RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Windows\\System32\\calc.exe");

	// Create the process parameters
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

	// Initialize the PS_CREATE_INFO structure
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;

	// Initialize the PS_ATTRIBUTE_LIST structure
	PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
	AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[0].Size = NtImagePath.Length;
	AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

	// Create the process
	HANDLE hProcess, hThread = NULL;
  NTSTATUS status =
	NtCreateUserProcess(
    &hProcess, 
    &hThread, 
    PROCESS_ALL_ACCESS, 
    THREAD_ALL_ACCESS, 
    NULL, 
    NULL, 
    0, 
    0, 
    ProcessParameters, 
    &CreateInfo, 
    AttributeList);
  if (!NT_SUCCESS(status)) {
    printf("NtCreateUserProcess failed with status 0x%08x\n", status);
  }
  
  RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, AttributeList);
	RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, ProcessParameters);
  printf("TEST\n");
  return 0;
}
