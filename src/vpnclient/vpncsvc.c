// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpncsvc.c
// VPN Client Service Program

#include <GlobalConst.h>

#define	VPN_EXE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

// Process start function
void StartProcess()
{
	// Start the client
	InitCedar();
	CtStartClient();
}

// Process termination function
void StopProcess()
{
  	// Stop the client
	CtStopClient();
	FreeCedar();
}

// WinMain function
int main(int argc, char *argv[])
{
	InitProcessCallOnce();

#ifdef	OS_WIN32

	return MsService(GC_SVC_NAME_VPNCLIENT, StartProcess, StopProcess, ICO_MACHINE, argv[0]);
#else	// OS_WIN32
	return UnixService(argc, argv, "vpnclient", StartProcess, StopProcess);
#endif	// OS_WIN32
}


