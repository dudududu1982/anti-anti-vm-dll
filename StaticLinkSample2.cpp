#include <Windows.h>
#include "MinHook.h"
#include <stdio.h> 
#include <io.h> 

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

// Helper function for MH_CreateHookApi().
template <typename T>
inline MH_STATUS MH_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHookApi(pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

typedef int (WINAPI *MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);
typedef HANDLE (WINAPI *CREATEFILEW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE); 

// Pointer for calling original MessageBoxW.
MESSAGEBOXW fpMessageBoxW = NULL;
CREATEFILEW fpCreateFileW= NULL; 

 //Detour function which overrides MessageBoxW.
int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    return fpMessageBoxW(hWnd, L"Hooked!", lpCaption, uType);
}
//NTSTATUS DetourNtOpenFile (PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,ULONG ShareAccess,ULONG OpenOptions);

// Detour function which overrides CreateFileW. 
HANDLE WINAPI DetourCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess,DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{ 
   if(lpFileName != NULL){ 
      wprintf(L"File: %s %x %x\n",lpFileName, dwDesiredAccess, dwShareMode); 
      if(wcscmp(lpFileName,L"C:\\Windows\\System32\\drivers\\etc\\hosts") == 0 && //Deny access to this one specific file 
      dwDesiredAccess == 0xC0000000){ 
         return INVALID_HANDLE_VALUE; 
      } 
   } 
    return fpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile); 

} 

BOOL APIENTRY DllMain( HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
	if (DLL_PROCESS_ATTACH == ul_reason_for_call) {
		// Initialize MinHook.
		if (MH_Initialize() != MH_OK)
		{
			return FALSE;
		}

		// Create a hook for MessageBoxW, in disabled state.
		if (MH_CreateHookApiEx(L"user32", "MessageBoxW", &DetourMessageBoxW, &fpMessageBoxW) != MH_OK)
		{
			return FALSE;
		}

		// Enable the hook for MessageBoxW.
		if (MH_EnableHook(&MessageBoxW) != MH_OK)
		{
			return FALSE;
		}

		fpMessageBoxW(NULL, L"HOOK DONE1", L"HOOK DONE1", 0);

		// Create a hook for MessageBoxW, in disabled state.
		//if (MH_CreateHookApiEx(L"ntdll", "NtOpenFile", &DetourNtOpenFile, &fpMessageBoxW) != MH_OK)
		//{
		//	return FALSE;
		//}

		// Enable the hook for MessageBoxW.
		//if (MH_EnableHook(&MessageBoxW) != MH_OK)
		//{
		//	return FALSE;
		//}
		 // Create a hook for MessageBoxW, in disabled state. 
		if (MH_CreateHookApiEx(L"Kernel32", "CreateFileW", &DetourCreateFileW, &fpCreateFileW) != MH_OK) 
		{ 
			return 1; 
		} 

		// Enable the hook for MessageBoxW. 
		if (MH_EnableHook(&CreateFileW) != MH_OK) 
		{ 
			return 1; 
		} 

		fpMessageBoxW(NULL, L"HOOK DONE2", L"HOOK DONE2", 0);
	}

    return TRUE;
}
