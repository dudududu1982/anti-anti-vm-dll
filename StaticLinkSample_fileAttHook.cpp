#include <Windows.h>
#include "MinHook.h"
#include <stdio.h> 
#include <io.h> 
#include <stdlib.h>

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif


char * dumpFileToBuffer(char const* const fileName)
{
	FILE* file = fopen(fileName, "r"); /* should check the result */
	long length;
	char * buffer = 0;
	if (file)
	{
		fseek (file, 0, SEEK_END);
		length = ftell (file);
		fseek (file, 0, SEEK_SET);
		buffer = (char*)malloc (length);
		if (buffer)
		{
			fread (buffer, 1, length, file);
		}
		fclose (file);
		return buffer;
	}
	else
	{
		return NULL;
	}
}

// Helper function for MH_CreateHookApi().
template <typename T>
inline MH_STATUS MH_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
	return MH_CreateHookApi(pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}
typedef DWORD(WINAPI *GETFILEATTRIBUTESA)(LPCTSTR);
typedef int (WINAPI *MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);
typedef HANDLE (WINAPI *CREATEFILEW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE); 

// Pointer for calling original MessageBoxW.
MESSAGEBOXW fpMessageBoxW = NULL;
CREATEFILEW fpCreateFileW= NULL; 
GETFILEATTRIBUTESA fpGetFileAttributesA = NULL;

//Detour function which overrides MessageBoxW.
int WINAPI DetourMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	return fpMessageBoxW(hWnd, L"Hooked!", lpCaption, uType);
}
//NTSTATUS DetourNtOpenFile (PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,ULONG ShareAccess,ULONG OpenOptions);

// Detour function which overrides CreateFileW. 
HANDLE WINAPI DetourCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess,DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{ 
	char const* const fileName = "C:\\temp\\files_blackList.txt";
	char * fileBuffer = 0;
	wchar_t * pch;
	fileBuffer = dumpFileToBuffer(fileName);
	if (fileBuffer)
	{
		if(lpFileName != NULL){ 
			wprintf(L"File: %s %x %x\n",lpFileName, dwDesiredAccess, dwShareMode); 
			pch = (wchar_t *)strtok(fileBuffer, "\n");
			while (pch) {
				if(wcscmp(lpFileName,pch) == 0 && //Deny access to this one specific file 
					dwDesiredAccess == 0xC0000000){ 
						return INVALID_HANDLE_VALUE; 
				}
				pch = (wchar_t *)strtok(NULL, "\n");
			} 
			return fpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile); 
		}
	} 
}
DWORD WINAPI DetourGetFileAttributesA(LPCTSTR lpFileName) 
{ 
	char const* const fileName = "C:\\temp\\files_blackList.txt";
	char * fileBuffer = 0;
	char * pch;
	fileBuffer = dumpFileToBuffer(fileName);
	if (fileBuffer)
	{
		if(lpFileName != NULL){ 
			pch = strtok(fileBuffer, "\n");
			while (pch) {
				if(strcmp((char*)lpFileName,pch) == 0)//Deny access to this one specific file )
				{ 
					return INVALID_FILE_ATTRIBUTES; 
				}
				pch = strtok(NULL, "\n");
			} 
			return fpGetFileAttributesA(lpFileName); 
		}

	}
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
			//if (MH_CreateHookApiEx(L"user32", "MessageBoxW", &DetourMessageBoxW, &fpMessageBoxW) != MH_OK)
			//{
			//	return FALSE;
			//}

			//Enable the hook for MessageBoxW.
			//if (MH_EnableHook(&MessageBoxW) != MH_OK)
			//{
			///	return FALSE;
			//}

			//fpMessageBoxW(NULL, L"HOOK DONE1", L"HOOK DONE1", 0);

			if (MH_CreateHookApiEx(L"Kernel32", "GetFileAttributesA", &DetourGetFileAttributesA, &fpGetFileAttributesA) != MH_OK)
			{
				return FALSE;
			}

			// Enable the hook for MessageBoxW.
			if (MH_EnableHook(&GetFileAttributesA) != MH_OK)
			{
				return FALSE;
			}
			//fpMessageBoxW(NULL, L"HOOK DONE3", L"HOOK DONE3", 0);
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
			//if (MH_CreateHookApiEx(L"Kernel32", "CreateFileW", &DetourCreateFileW, &fpCreateFileW) != MH_OK) 
			//{ 
			//	return 1; 
			//} 

			// Enable the hook for MessageBoxW. 
			//if (MH_EnableHook(&CreateFileW) != MH_OK) 
			//{ 
			//	return 1; 
			//} 
			//
			//fpMessageBoxW(NULL, L"HOOK DONE2", L"HOOK DONE2", 0);
		}

		return TRUE;
	}
