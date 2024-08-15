// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpncmd.c
// VPN Command Line Management Utility

#include "Cedar/Cedar.h"
#ifdef OS_WIN32
#include "Cedar/CMInner.h"
#endif
#include "Cedar/Command.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

// main function
int main(int argc, char *argv[])
{
	wchar_t *s;
	UINT ret = 0;

	InitProcessCallOnce();

#ifdef	OS_WIN32
	SetConsoleTitleA(CEDAR_PRODUCT_STR " VPN Command Line Utility");
#else
	// For *nix, disable output buffering to allow for interactive use
	setbuf(stdout,NULL);
#endif	// OS_WIN32

#if defined(_DEBUG) || defined(DEBUG)	// In VC++ compilers, the macro is "_DEBUG", not "DEBUG".
	// If set memcheck = true, the program will be vitally slow since it will log all malloc() / realloc() / free() calls to find the cause of memory leak.
	// For normal debug we set memcheck = false.
	// Please set memcheck = true if you want to test the cause of memory leaks.
	InitMayaqua(false, true, argc, argv);
#else
	InitMayaqua(false, false, argc, argv);
#endif
	InitCedar();

#ifdef OS_WIN32
	CmExecUiHelperMain();
#endif

	s = GetCommandLineUniStr();

	if (s == NULL)
	{
		s = CopyUniStr(L"");
	}

	if (UniStrCmpi(s, L"exit") != 0)
	{
		UINT size = UniStrSize(s) + 64;
		wchar_t *tmp;

		tmp = Malloc(size);
		UniFormat(tmp, size, L"vpncmd %s", s);
		ret = CommandMain(tmp);

		Free(tmp);
	}

#ifdef	OS_WIN32
	{
		UINT i;
		LIST *o = MsGetProcessList();
		bool b = false;

		for (i = 0;i < LIST_NUM(o);i++)
		{
			MS_PROCESS *p = LIST_DATA(o, i);

			if (EndWith(p->ExeFilename, "\\cmd.exe") || EndWith(p->ExeFilename, "\\command.com"))
			{
				b = true;
				break;
			}
		}

		MsFreeProcessList(o);

		if (b == false)
		{
			if (ret != ERR_NO_ERROR)
			{
				SleepThread(1000);
			}
		}
	}
#endif	// OS_WIN32

	Free(s);

	FreeCedar();
	FreeMayaqua();
	return ret;
}


