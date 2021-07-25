#define WIN32_LEAN_AND_MEAN

#include "resource.h"
#include <windows.h>
#include "Header.h"
//-------------------------------------------------------------------------------------------------
bool exists_test(const std::string& name){
	if (FILE *file = fopen(name.c_str(), "r")) {
		fclose(file);
		return true;
	}
	else {
		return false;
	}
}
//-------------------------------------------------------------------------------------------------
BOOL CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);
//-------------------------------------------------------------------------------------------------
void CheckDll(){
	if (exists_test("Loader.dll")){
	
	}
	else{
		MessageBox(0, "ไฟล์ Loader.dll สูญหาย โปรดาวโหลดแล้วทำการแตกไฟล์ใหม่ครับ", "Error", MB_OK | MB_ICONSTOP);
		ExitProcess(1);
	}

}
void CheckEXE(){
	if (exists_test("PB_Functoin.exe")){

	}
	else{
		MessageBox(0, "ไฟล์ PB_Functoin.exe สูญหาย โปรดาวโหลดแล้วทำการแตกไฟล์ใหม่ครับ", "Error", MB_OK | MB_ICONSTOP);
		ExitProcess(1);
	}

}
//-------------------------------------------------------------------------------------------------
int _DeleteFile64()
{

	if (remove("C:\\Windows\\System32\\drivers\\etc\\hosts") != 0)
		perror("Error deleting file");
	else
		puts("File successfully deleted");
	return 0;
}
//-------------------------------------------------------------------------------------------------
#include <windows.h>
#include <shellapi.h>
//-------------------------------------------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPervInstance, LPSTR lpCMDline, int nCmdShow)
{

	__asm call _DeleteFile64
	CheckDll();
	CheckEXE();
	//======================================================================//
	WNDCLASSEX wc;
	ZeroMemory(&wc, sizeof(WNDCLASSEX));
	//======================================================================//
	HWND dialog;
	//======================================================================//
	dialog = CreateDialog(hInstance, MAKEINTRESOURCE(Windows), NULL, DialogProc);
	if (!dialog)
	{

		return 1;
	}
	ShowWindow(dialog, nCmdShow);
	//======================================================================//
	UpdateWindow(dialog);
	//======================================================================//
	MSG msg;
	//======================================================================//
	while (GetMessage(&msg, 0, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	//======================================================================//
	return (int)msg.wParam;
}

//-------------------------------------------------------------------------------------------------
BOOL CALLBACK DialogProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{

	switch (message)
	{
	case WM_INITDIALOG:
	
		
		MessageBox(NULL, "** คลิกขวา Run as administrator ทุกครั้ง ** ถ้าไม่คลิดขวารันแอสมินอาจโปรไม่ติดได้ครับ!!!", "", MB_OK | MB_ICONWARNING);
		
		Beep(440, 300);
		DeleteFileA("C:\\Windows\\System32\\Loader.dll");
		DeleteFileA("C:\\Windows\\SysWOW64\\Loader.dll");
		Sleep(100);
		//-------------------------------------------------------------------------------------------------
		Beep(440, 300);
		CopyFileA("Loader.dll", "C:\\Windows\\System32\\Loader.dll", TRUE);
		CopyFileA("Loader.dll", "C:\\Windows\\SysWOW64\\Loader.dll", TRUE);
		Beep(440, 300);
		ShowWindow(hwnd, SW_HIDE);

		inject();
		//-------------------------------------------------------------------------------------------------
		ExitProcess(1);
		//-------------------------------------------------------------------------------------------------
		break;
		//-------------------------------------------------------------------------------------------------
	case WM_CLOSE:
		DestroyWindow(hwnd);
		return TRUE;
		break;
		
	case WM_DESTROY:
		PostQuitMessage(0);
		return TRUE;
	
	}

	
	return FALSE;
}
//-------------------------------------------------------------------------------------------------