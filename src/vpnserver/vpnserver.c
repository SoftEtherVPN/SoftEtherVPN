// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpnserver.c
// VPN Server service program

#include <GlobalConst.h>

#define	VPN_EXE

#ifdef	WIN32
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include "../PenCore/resource.h"
#endif	// WIN32
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

// Process starting function
void StartProcess()
{
	// Start the server
	InitCedar();
	StInit();
	StStartServer(false);
}

// Process termination function
void StopProcess()
{
	// Stop the server
	StStopServer();
	StFree();
	FreeCedar();
}

// WinMain function
int main(int argc, char *argv[])
{
	InitProcessCallOnce();

	VgUseStaticLink();

#ifdef	OS_WIN32

	return MsService(GC_SVC_NAME_VPNSERVER, StartProcess, StopProcess, ICO_CASCADE, argv[0]);
#else	// OS_WIN32
	return UnixService(argc, argv, "vpnserver", StartProcess, StopProcess);
#endif	// OS_WIN32
}

