// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpnserver.c
// VPN Server service program

#define	VPN_EXE

#include "Cedar/Server.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Unix.h"
#include "Mayaqua/Win32.h"

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

#ifdef	OS_WIN32
	return MsService(GC_SVC_NAME_VPNSERVER, StartProcess, StopProcess, ICO_CASCADE, argv[0]);
#else	// OS_WIN32
	return UnixService(argc, argv, "vpnserver", StartProcess, StopProcess);
#endif	// OS_WIN32
}

