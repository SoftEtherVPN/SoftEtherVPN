// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpnbridge.c
// VPN Bridge Service Program

#define	VPN_EXE

#include "Cedar/Server.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Unix.h"
#include "Mayaqua/Win32.h"

// Process start function
void StartProcess()
{
	// Start the server
	InitCedar();
	StInit();
	StStartServer(true);
}

// Process stop function
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

#ifdef	OS_WIN32
	return MsService(GC_SVC_NAME_VPNBRIDGE, StartProcess, StopProcess, ICO_BRIDGE, argv[0]);
#else	// OS_WIN32
	return UnixService(argc, argv, "vpnbridge", StartProcess, StopProcess);
#endif	// OS_WIN32
}


