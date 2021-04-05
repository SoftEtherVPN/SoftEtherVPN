// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpncmgr.c
// VPN Client connection manager program

#include "Cedar/Cedar.h"
#include "Cedar/SM.h"

// WinMain function
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	InitProcessCallOnce();

#if defined(_DEBUG) || defined(DEBUG)	// In VC++ compilers, the macro is "_DEBUG", not "DEBUG".
	// If set memcheck = true, the program will be vitally slow since it will log all malloc() / realloc() / free() calls to find the cause of memory leak.
	// For normal debug we set memcheck = false.
	// Please set memcheck = true if you want to test the cause of memory leaks.
	InitMayaqua(false, true, 0, NULL);
#else
	InitMayaqua(false, false, 0, NULL);
#endif
	InitCedar();
	SMExec();
	FreeCedar();
	FreeMayaqua();
	return 0;
}


