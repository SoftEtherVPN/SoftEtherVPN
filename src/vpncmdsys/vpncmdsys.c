// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpncmdsys.c
// vpncmd bootstrup

#include <GlobalConst.h>

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <locale.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "vpncmdsys.h"

static UINT ret_code = 0;

// Get whether the system is a Windows NT
bool IsWindowsNt()
{
	OSVERSIONINFO info;

	ZeroMemory(&info, sizeof(info));
	info.dwOSVersionInfoSize = sizeof(info);

	if (GetVersionEx(&info) == false)
	{
		return false;
	}

	if (info.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		return true;
	}

	return false;
}

// Execute a child process
bool ExecProcess(char *exe_name, wchar_t *args_w)
{
	bool ret;
	wchar_t exe_name_w[MAX_SIZE];
	char args[MAX_SIZE];
	STARTUPINFO info;
	STARTUPINFOW info_w;
	PROCESS_INFORMATION proc;
	// Validate arguments
	if (exe_name == NULL || args_w == NULL)
	{
		return false;
	}

	ZeroMemory(exe_name_w, sizeof(exe_name_w));
	ZeroMemory(args, sizeof(args));
	mbstowcs(exe_name_w, exe_name, strlen(exe_name));
	wcstombs(args, args_w, sizeof(args));

	ZeroMemory(&info, sizeof(info));
	info.cb = sizeof(info);

	ZeroMemory(&info_w, sizeof(info_w));
	info_w.cb = sizeof(info_w);

	ZeroMemory(&proc, sizeof(proc));

	if (IsWindowsNt() == false)
	{
		ret = CreateProcess(exe_name, args, NULL, NULL, false, NORMAL_PRIORITY_CLASS,
			NULL, NULL, &info, &proc);
	}
	else
	{
		ret = CreateProcessW(exe_name_w, args_w, NULL, NULL, false, NORMAL_PRIORITY_CLASS,
			NULL, NULL, &info_w, &proc);
	}

	if (ret)
	{
		WaitForSingleObject(proc.hProcess, INFINITE);

		GetExitCodeProcess(proc.hProcess, &ret_code);
	}

	return ret;
}

// Entry point
int main(int argc, char *argv[])
{
	HKEY hKey;
	bool ok = false;
	char error[MAX_SIZE];
	wchar_t *current_args;
	bool flag = false;
	bool break_now = false;

	error[0] = 0;

	setlocale(LC_ALL, "");

	current_args = GetCommandLineW();

	// Remove the program name portion from the command line string
	while (true)
	{
		switch (*current_args)
		{
		case L'\"':
			if (flag == false)
			{
				flag = true;
			}
			else
			{
				flag = false;
			}
			break;

		case L' ':
		case L'\t':
		case 0:
			if (flag == false)
			{
				break_now = true;
			}
			break;
		}
		if (break_now)
		{
			break;
		}
		current_args++;
	}

	while (true)
	{
		if (*current_args == L' ' || *current_args == L'\t')
		{
			current_args++;
		}
		else
		{
			break;
		}
	}

	strcpy(error, "VPN Command Line Tools is not Installed.\nPlease reinstall programs.");

	// Get the path of the vpncmd.exe from the registry
	if (RegOpenKey(HKEY_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, &hKey) == 0)
	{
		DWORD type = REG_SZ;
		DWORD size = 4096;
		char buf[4096];

		if (RegQueryValueEx(hKey, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH, NULL, &type, (LPBYTE)buf, &size) == 0)
		{
			wchar_t args[MAX_SIZE];

			swprintf(args, sizeof(args), L"\"%S\" %s", buf, current_args);
			if (ExecProcess(buf, args) == false)
			{
				//sprintf(error, "Failed to execute \"%S\".", buf);
			}
			else
			{
				ok = true;
			}
		}

		RegCloseKey(hKey);
	}

	if (ok == false)
	{
		printf("%s\n", error);
	}

	return ret_code;
}

