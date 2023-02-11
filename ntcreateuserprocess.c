//file to create a process using NtCreateUserProcess()
//it like kinda works bro but man its wonky
//https://github.com/BlackOfWorld/NtCreateUserProcess/tree/ee9e963b9542722c2fec4c1c874c0ac84c8c9bdf
#include "internals.h"
#include <stdio.h>

int main(int argc, char **argv){
	//try to redirect output to file
	SECURITY_ATTRIBUTES sa;
  sa.nLength = sizeof(sa);
  sa.bInheritHandle = TRUE;
  sa.lpSecurityDescriptor = NULL;
	HANDLE hFile = CreateFileA("outfile.txt", GENERIC_WRITE, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

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
	UNICODE_STRING NtImagePath, Params, ImagePath;
	RtlInitUnicodeString(&ImagePath, (PWSTR)L"C:\\Windows\\System32\\cmd.exe");
	RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Windows\\System32\\cmd.exe");
	//RtlInitUnicodeString(&Params, (PWSTR)L"\"C:\\WINDOWS\\SYSTEM32\\cmd.exe\" start /min /c \"ping 127.0.0.1 > outfile.txt\"");
	//RtlInitUnicodeString(&Params, (PWSTR)L"/c start /min cmd /c \"ping 127.0.0.1 > outfile.txt\""); //THIS ONE WORKS GOOD SOMEWHAT
	RtlInitUnicodeString(&Params, (PWSTR)L"/c ping 127.0.0.1");
	// Create the process parameters
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	RtlCreateProcessParametersEx(&ProcessParameters, &ImagePath, NULL, NULL, &Params, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
	ProcessParameters->StandardOutput = hFile; //WILL IT WORK?
	// Initialize the PS_CREATE_INFO structure
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;
	//Skip Image File Execution Options debugger
	CreateInfo.InitState.u1.InitFlags = PsSkipIFEODebugger;
	OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES)};
	PPS_STD_HANDLE_INFO stdHandleInfo = (PPS_STD_HANDLE_INFO)RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(PS_STD_HANDLE_INFO));
	PCLIENT_ID clientId = (PCLIENT_ID)RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
	PSECTION_IMAGE_INFORMATION SecImgInfo = (PSECTION_IMAGE_INFORMATION)RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(SECTION_IMAGE_INFORMATION));
	PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
	// Create necessary attributes
	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
	AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_CLIENT_ID;
	AttributeList->Attributes[0].Size = sizeof(CLIENT_ID);
	AttributeList->Attributes[0].ValuePtr = clientId;
	AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_IMAGE_INFO;
	AttributeList->Attributes[1].Size = sizeof(SECTION_IMAGE_INFORMATION);
	AttributeList->Attributes[1].ValuePtr = SecImgInfo;
	AttributeList->Attributes[2].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[2].Size = NtImagePath.Length;
	AttributeList->Attributes[2].ValuePtr = NtImagePath.Buffer;
	AttributeList->Attributes[3].Attribute = PS_ATTRIBUTE_STD_HANDLE_INFO;
	AttributeList->Attributes[3].Size = sizeof(PS_STD_HANDLE_INFO);
	AttributeList->Attributes[3].ValuePtr = stdHandleInfo;
	DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
	// Add process mitigation attribute
	AttributeList->Attributes[4].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
	AttributeList->Attributes[4].Size = sizeof(DWORD64);
	AttributeList->Attributes[4].ValuePtr = &policy;
	// Spoof Parent Process Id as explorer.exe
	DWORD trayPID;
	HWND trayWnd = FindWindowW(L"Shell_TrayWnd", NULL);
	GetWindowThreadProcessId(trayWnd, &trayPID);
	HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, trayPID);
	if (hParent){
		AttributeList->Attributes[5].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
		AttributeList->Attributes[5].Size = sizeof(HANDLE);
		AttributeList->Attributes[5].ValuePtr = hParent;
	}else{
		AttributeList->TotalLength -= sizeof(PS_ATTRIBUTE);
	}
	// Create the process
	HANDLE hProcess = NULL, hThread = NULL;
  NTSTATUS status;
	status = NtCreateUserProcess(
		&hProcess, 
		&hThread, 
		PROCESS_ALL_ACCESS, 
		THREAD_ALL_ACCESS, 
		&objAttr, 
		&objAttr, 
		PROCESS_CREATE_FLAGS_INHERIT_HANDLES, 
		0, 
		ProcessParameters, 
		&CreateInfo, 
		AttributeList);
  if (!NT_SUCCESS(status)){
    printf("NtCreateUserProcess failed with status: %x\n", status);
  }else{
		WaitForSingleObject(hProcess, INFINITE);
	}
	// Clean up
	if(hParent) CloseHandle(hParent);
	RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, AttributeList);
	RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, stdHandleInfo);
	RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, clientId);
	RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap, 0, SecImgInfo);
  return 0;
}
