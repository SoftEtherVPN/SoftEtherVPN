// SoftEther VPN Source Code - Developer Edition Master Branch
// VPN Driver Installer


#include <GlobalConst.h>

#ifdef	WIN32
#define	HAM_WIN32
#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <DbgHelp.h>
#include <Iphlpapi.h>
#include <wtsapi32.h>
#include "../pencore/resource.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "vpndrvinst.h"

void disablevlan(UINT num, char **arg)
{
	bool ok;
	if (num < 1)
	{
		return;
	}

	ok = MsDisableVLan(arg[0]);

	if (ok == false)
	{
		_exit(1);
	}
	else
	{
		_exit(0);
	}
}

void enablevlan(UINT num, char **arg)
{
	bool ok;
	if (num < 1)
	{
		return;
	}

	ok = MsEnableVLan(arg[0]);

	if (ok == false)
	{
		_exit(1);
	}
	else
	{
		_exit(0);
	}
}

void instvlan(UINT num, char **arg)
{
	KAKUSHI *k = NULL;
	MS_DRIVER_VER ver;
	bool ok;
	if (num < 1)
	{
		return;
	}

	InitWinUi(L"VPN", _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	if (MsIsNt())
	{
		k = InitKakushi();
	}

	CiInitDriverVerStruct(&ver);

	ok = MsInstallVLan(VLAN_ADAPTER_NAME_TAG, VLAN_CONNECTION_NAME, arg[0], &ver);

	FreeKakushi(k);

	FreeWinUi();

	if (ok == false)
	{
		_exit(1);
	}
	else
	{
		_exit(0);
	}
}

void upgradevlan(UINT num, char **arg)
{
	bool ok;
	KAKUSHI *k = NULL;
	MS_DRIVER_VER ver;
	if (num < 1)
	{
		return;
	}

	InitWinUi(L"VPN", _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	if (MsIsNt())
	{
		k = InitKakushi();
	}

	CiInitDriverVerStruct(&ver);

	ok = MsUpgradeVLan(VLAN_ADAPTER_NAME_TAG, VLAN_CONNECTION_NAME, arg[0], &ver);

	FreeKakushi(k);

	FreeWinUi();

	if (ok == false)
	{
		_exit(1);
	}
	else
	{
		_exit(0);
	}
}

void uninstvlan(UINT num, char **arg)
{
	bool ok;
	if (num < 1)
	{
		return;
	}

	ok = MsUninstallVLan(arg[0]);

	if (ok == false)
	{
		_exit(1);
	}
	else
	{
		_exit(0);
	}
}

TEST_LIST test_list[] =
{
	{"instvlan", instvlan},
	{"uninstvlan", uninstvlan},
	{"upgradevlan", upgradevlan},
	{"enablevlan", enablevlan},
	{"disablevlan", disablevlan},
};

// Main function
void MainFunction(char *cmd)
{
	char tmp[MAX_SIZE];
	bool first = true;
	bool exit_now = false;

	while (true)
	{
		if (first && StrLen(cmd) != 0 && g_memcheck == false)
		{
			first = false;
			StrCpy(tmp, sizeof(tmp), cmd);
			exit_now = true;
			Print("%s\n", cmd);
		}
		else
		{
			_exit(0);
		}
		Trim(tmp);
		if (StrLen(tmp) != 0)
		{
			UINT i, num;
			bool b = false;
			TOKEN_LIST *token = ParseCmdLine(tmp);
			char *cmd = token->Token[0];

			num = sizeof(test_list) / sizeof(TEST_LIST);
			for (i = 0;i < num;i++)
			{
				if (!StrCmpi(test_list[i].command_str, cmd))
				{
					char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
					UINT j;
					for (j = 0;j < token->NumTokens - 1;j++)
					{
						arg[j] = CopyStr(token->Token[j + 1]);
					}
					test_list[i].proc(token->NumTokens - 1, arg);
					for (j = 0;j < token->NumTokens - 1;j++)
					{
						Free(arg[j]);
					}
					Free(arg);
					b = true;
					_exit(1);
					break;
				}
			}
			FreeToken(token);

			if (exit_now)
			{
				break;
			}
		}
	}
}

// winmain function
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
	EnableProbe(false);
	InitCedar();
	SetHamMode();
	MainFunction(cmdline);
	FreeCedar();
	FreeMayaqua();

	return 0;
}

