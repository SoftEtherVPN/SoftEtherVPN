// SoftEther VPN Source Code
// Hamster Test Code
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


// Ham.c
// Hamster Test Program

#include <GlobalConst.h>

#define	HAM_C

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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
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
	InitMayaqua(false, false, 0, NULL);
	EnableProbe(false);
	InitCedar();
	SetHamMode();
	MainFunction(cmdline);
	FreeCedar();
	FreeMayaqua();

	return 0;
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
