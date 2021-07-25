#pragma warning(disable:4996 4244 4018 4800)
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <tchar.h>
#include <wininet.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <tlhelp32.h>
#include "urlmon.h"
#include <conio.h>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"wininet.lib")
//-------------------------------------------------------------------------------------------------
#define ProcessName "PointBlank.exe" 
//-------------------------------------------------------------------------------------------------
#define FileToInject "Loader.dll" 
//-------------------------------------------------------------------------------------------------
bool InjectDLL(DWORD ProcessID);
//-------------------------------------------------------------------------------------------------
typedef HINSTANCE(*fpLoadLibrary)(char*);
//-------------------------------------------------------------------------------------------------

#include <windows.h>
#include <tlhelp32.h>
#include <iostream> // For STL i/o
#include <ctime>    // For std::chrono
#include <thread>   // For std::this_thread
using namespace std;
#pragma warning(disable: 4244 4101 4390 4715 4474 4996)
DWORD FindProcessId(const char *name)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnapshot, &ProcEntry))
	{
		{
			if (stricmp(ProcEntry.szExeFile, name) == 0)
				return ProcEntry.th32ProcessID;
			while (Process32Next(hSnapshot, &ProcEntry))
				if (stricmp(ProcEntry.szExeFile, name) == 0)
				{
					return ProcEntry.th32ProcessID;
				}
		}
	}
}
//-------------------------------------------------------------------------------------------------
void Detour(void* dwAddress, void* dwJmp, int Size)
{
	DWORD dwOldProtect, dwRelAddr;
	DWORD dwJumpTo = (DWORD)dwJmp;
	BYTE* pAddress = (BYTE*)dwAddress;
	VirtualProtect((LPVOID)pAddress, sizeof(dwAddress), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	dwRelAddr = (DWORD)(dwJumpTo - (DWORD)pAddress) - 5;
	*(BYTE*)pAddress = 0xE9;
	*(DWORD*)(pAddress + 0x1) = dwRelAddr;
	for (DWORD x = 0x5; x < Size; x++)*(BYTE*)(pAddress + x) = 0x90;
	VirtualProtect((LPVOID)pAddress, sizeof(dwAddress), dwOldProtect, &dwOldProtect);
}
//-------------------------------------------------------------------------------------------------
DWORD bytes;
BYTE examplebytes[5] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC };
//-------------------------------------------------------------------------------------------------
DWORD GetSizeofCode(const char* szModuleName)
{
	HMODULE hModule = GetModuleHandleA(szModuleName);
	if (!hModule) return NULL;
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(hModule);
	if (!pDosHeader) return NULL;
	PIMAGE_NT_HEADERS pNTHeader = PIMAGE_NT_HEADERS((LONG)hModule + pDosHeader->e_lfanew);
	if (!pNTHeader) return NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeader->OptionalHeader;
	if (!pOptionalHeader) return NULL;
	return pOptionalHeader->SizeOfCode;
}
//-------------------------------------------------------------------------------------------------
DWORD ShowScan;
//-------------------------------------------------------------------------------------------------
#include <windows.h>
#include <stdio.h>
#include <fstream>
#include <winbase.h>
#include <fstream>
#include <winbase.h>
#include <winternl.h>
#include <time.h>
//------------------------------------------------------------------------------
#pragma warning(disable: 4996)
using namespace std;
//------------------------------------------------------------------------------
ofstream infile;
//------------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
//------------------------------------------------------------------------------
char *GetDirectoryFile(char *filename);
void __cdecl add_log(const char * fmt, ...);
void thethread();
char dlldir[320];
//------------------------------------------------------------------------------
DWORD FindPattern(DWORD dwStart, DWORD dwLen, BYTE* pszPatt, char pszMask[])
{
	unsigned int i = NULL;
	int iLen = strlen(pszMask) - 1;
	for (DWORD dwRet = dwStart; dwRet < dwStart + dwLen; dwRet++){
		if (*(BYTE*)dwRet == pszPatt[i] || pszMask[i] == '?'){
			if (pszMask[i + 1] == '\0') return(dwRet - iLen); i++;
		}
		else i = NULL;
	}
	return NULL;
}
#include <windows.h>
#include <shellapi.h>
//-------------------------------------------------------------------------------------------------
void inject()
{
	
	AllocConsole();
	
	system("CLS");
	
	system("color 07");

	_cprintf("Start Game PointBlank!");
	
	DWORD processId = NULL;
	//======================================================================//
	PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
	HANDLE hProcSnap;
	//======================================================================//
	while (!processId)
	{
		
		hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		//======================================================================//
		if (Process32First(hProcSnap, &pe32))
		{
			do
			{
				if (!strcmp(pe32.szExeFile, ProcessName))
				{
					processId = pe32.th32ProcessID;
					//-------------------------------------------------------------------------------------------------
					DWORD dwLoadLibrary = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
					DWORD ProcessId = FindProcessId("PointBlank.exe");
					HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId);
					Beep(440, 300);
					WriteProcessMemory(hProcess, (void*)dwLoadLibrary, examplebytes, 5, &bytes);
					//-------------------------------------------------------------------------------------------------
					ShellExecute(NULL, "open", "PB_Functoin.exe", NULL, NULL, SW_SHOWDEFAULT);
					ShowWindow(GetConsoleWindow(), SW_HIDE);
					
					break;
				}
			} while (Process32Next(hProcSnap, &pe32));
		}
	
	
	}
	//-------------------------------------------------------------------------------------------------
	while (!InjectDLL(processId))
	{
		
		_cprintf("DLL failed to inject\n");
		
	}
	
	_cprintf("successfuly!");
	
	CloseHandle(hProcSnap);
	
	Sleep(500);
	
	return;
}
//-------------------------------------------------------------------------------------------------
bool InjectDLL(DWORD ProcessID)
{
	//======================================================================//
	HANDLE hProc;
	//======================================================================//
	LPVOID paramAddr;
	//======================================================================//
	HINSTANCE hDll = LoadLibrary("KERNEL32");
	//======================================================================//
	fpLoadLibrary LoadLibraryAddr = (fpLoadLibrary)GetProcAddress(hDll, "LoadLibraryA");
	//======================================================================//
	hProc = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessID);
	//======================================================================//
	char dllPath[250] = "C:\\Windows\\System32\\";
	//======================================================================//
	strcat(dllPath, FileToInject);
	//======================================================================//
	paramAddr = VirtualAllocEx(hProc, 0, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	bool memoryWritten = WriteProcessMemory(hProc, paramAddr, dllPath, strlen(dllPath) + 1, NULL);
	//======================================================================//
	CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryAddr, paramAddr, 0, 0);
	//======================================================================//
	CloseHandle(hProc);
	//======================================================================//
	return memoryWritten;
}

