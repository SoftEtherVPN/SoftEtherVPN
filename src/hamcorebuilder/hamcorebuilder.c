// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// hamcorebuilder.c
// hamcore.se2 Build Utility

#include <GlobalConst.h>

#ifdef	WIN32
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#endif	// WIN32
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>


// main function
int main(int argc, char *argv[])
{
	MayaquaMinimalMode();

#if defined(_DEBUG) || defined(DEBUG)	// In VC++ compilers, the macro is "_DEBUG", not "DEBUG".
	// If set memcheck = true, the program will be vitally slow since it will log all malloc() / realloc() / free() calls to find the cause of memory leak.
	// For normal debug we set memcheck = false.
	// Please set memcheck = true if you want to test the cause of memory leaks.
	InitMayaqua(false, true, argc, argv);
#else
	InitMayaqua(false, false, argc, argv);
#endif
	InitCedar();

	Print("hamcore.se2 Build Utility\n");
	Print("Copyright (c) SoftEther VPN Project. All Rights Reserved.\n\n");

	if (argc < 3)
	{
		Print("Usage: hamcorebuilder <src_dir> <dest_hamcore_filename>\n\n");
	}
	else
	{
		char *src_dir = argv[1];
		char *dst_filename = argv[2];

		Print("Src Dir: '%s'\n", src_dir);
		Print("Dest Filename: '%s'\n", dst_filename);

		Print("\nProcessing...\n");

#ifdef	WIN32
		BuildHamcore(dst_filename, src_dir, false);
#else
		BuildHamcore(dst_filename, src_dir, true);
#endif

		Print("\nDone.\n");
	}

	FreeCedar();
	FreeMayaqua();

	return 0;
}

