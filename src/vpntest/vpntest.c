// vpntest.c
// VPN Server / VPN Client / VPN Bridge test program

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
#include "vpntest.h"

void client_test(UINT num, char **arg)
{
	Print("VPN Client Test. Press Enter key to stop the VPN Client .\n");
	CtStartClient();
	GetLine(NULL, 0);
	CtStopClient();
}

void server_test(UINT num, char **arg)
{
	Print("VPN Server Test. Press Enter key to stop the VPN Server .\n");

	StInit();

	StStartServer(false);

	GetLine(NULL, 0);

	StStopServer();

	StFree();
}

void bridge_test(UINT num, char **arg)
{
	Print("VPN Bridge Test. Press Enter key to stop the VPN Bridge .\n");

	StInit();

	StStartServer(true);

	GetLine(NULL, 0);

	StStopServer();

	StFree();
}

#ifdef OS_WIN32
void server_manager_test(UINT num, char **arg)
{
	SMExec();
}

void client_manager_test(UINT num, char **arg)
{
	CMExec();
}

void setup_test(UINT num, char **arg)
{
	char name[MAX_SIZE];
	Print("SetupAPI test. Please enter the name of the NIC I should retrieve the status of.\n");
	GetLine(name, sizeof(name));
	Print("Status: %s\n", MsIsVLanEnabledWithoutLock(name) ? "enabled" : "disabled");
}
#endif

void memory_leak_test(UINT num, char **arg)
{
	char *a = Malloc(1);

	Print("Hello, I am the great dictator of this kingdom!\n");
	Print("Just now I called Malloc(1) and never free! Ha ha ha !!\n");
}

// The list of test functions
// Test function definition list
typedef void (TEST_PROC)(UINT num, char **arg);

typedef struct TEST_LIST
{
	char *command_str;
	TEST_PROC *proc;
	char *help;
} TEST_LIST;

TEST_LIST test_list[] =
{
	{"c", client_test, "VPN Client in Test Mode, enter key to graceful stop."},
	{"s", server_test, "VPN Server in Test Mode, enter key to graceful stop."},
	{"b", bridge_test, "VPN Bridge in Test Mode, enter key to graceful stop."},
#ifdef OS_WIN32
	{"sm", server_manager_test, "VPN Server Manager UI in Test Mode."},
	{"cm", client_manager_test, "VPN Client Manager UI in Test Mode."},
	{"setupapi", setup_test, "SetupAPI test: tries to retrieve the specified NIC's status."},
#endif
	{"memory_leak", memory_leak_test, "Memory leak test: Try to leak one byte by malloc()."},
};

// Test function
int TestMain(char *cmd)
{
	char tmp[MAX_SIZE];
	bool first = true;
	bool exit_now = false;
	int status = 0;

	Print("SoftEther VPN Project\n");
	Print("vpntest: VPN Server / VPN Client / VPN Bridge test program\n");
	Print("Usage: vpntest [/memcheck] [command]\n\n");
	Print("Enter '?' or 'help' to show the command list.\n");
	Print("Enter 'q' or 'exit' to exit the process.\n\n");
	Print("   - In Jurassic Park: \"It's a UNIX system! I know this!\"\n\n");

#ifdef	OS_WIN32
	MsSetEnableMinidump(true);
#endif	// OS_WIN32

	while (true)
	{
		Print("TEST>");
		if (first && StrLen(cmd) != 0 && g_memcheck == false)
		{
			first = false;
			StrCpy(tmp, sizeof(tmp), cmd);
			exit_now = true;
			Print("%s\n", cmd);
		}
		else
		{
			GetLine(tmp, sizeof(tmp));
		}
		Trim(tmp);
		if (StrLen(tmp) != 0)
		{
			UINT i, num;
			bool b = false;
			TOKEN_LIST *token = ParseCmdLine(tmp);
			char *cmd = token->Token[0];
			if (!StrCmpi(cmd, "exit") || !StrCmpi(cmd, "quit") || !StrCmpi(cmd, "q"))
			{
				FreeToken(token);
				break;
			}
			else if (StrCmpi(cmd, "?") == 0 || StrCmpi(cmd, "help") == 0)
			{
				UINT max_len = 0;
				Print("Available commands:\n\n");
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (i = 0;i < num;i++)
				{
					TEST_LIST *t = &test_list[i];
					max_len = MAX(max_len, StrLen(t->command_str));
				}
				for (i = 0;i < num;i++)
				{
					TEST_LIST *t = &test_list[i];
					UINT len = StrLen(t->command_str);
					char *pad = NULL;
					if (len < max_len)
					{
						UINT padlen = max_len - len;
						pad = MakeCharArray(' ', padlen);
					}
					Print(" '%s'%s : %s\n", t->command_str, pad == NULL ? "" : pad, t->help);
					if (pad != NULL)
					{
						Free(pad);
					}
				}
				Print("\n");
			}
			else if (StartWith(tmp, "vpncmd"))
			{
				wchar_t *s = CopyStrToUni(tmp);
				CommandMain(s);
				Free(s);
			}
			else
			{
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
						Print("\n");
						break;
					}
				}
				if (b == false)
				{
					status = 2;
					Print("Invalid Command: %s\n\n", cmd);
				}
			}
			FreeToken(token);

			if (exit_now)
			{
				break;
			}
		}
	}
	Print("Exiting...\n\n");
	return status;
}

// Main function
int main(int argc, char *argv[])
{
	bool memchk = false;
	UINT i;
	char cmd[MAX_SIZE];
	char *s;
	int status = 0;

	InitProcessCallOnce();

	cmd[0] = 0;
	if (argc >= 2)
	{
		for (i = 1;i < (UINT)argc;i++)
		{
			s = argv[i];
			if (s[0] == '/')
			{
				if (!StrCmpi(s, "/memcheck"))
				{
					memchk = true;
				}
			}
			else
			{
				StrCpy(cmd, sizeof(cmd), &s[0]);
			}
		}
	}

	InitMayaqua(memchk, true, argc, argv);
	EnableProbe(true);
	InitCedar();
	SetHamMode();
	status = TestMain(cmdline);
	FreeCedar();
	FreeMayaqua();

	return status;
}

