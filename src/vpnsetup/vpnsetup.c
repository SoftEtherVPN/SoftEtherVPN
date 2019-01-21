// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


#include <GlobalConst.h>

// vpnsetup.c
// VPN Setup Wizard

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
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

// WinMain function
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	UINT ret;

	InitProcessCallOnce();

	VgUseStaticLink();

	ret = SWExec();

	ExitProcess(ret);

	return (int)ret;
}


