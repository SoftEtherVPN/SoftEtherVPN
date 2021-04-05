// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module

#include "Cedar/SW.h"

#include "Mayaqua/Mayaqua.h"

// WinMain function
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	UINT ret;

	InitProcessCallOnce();

	ret = SWExec();

	ExitProcess(ret);

	return (int)ret;
}
