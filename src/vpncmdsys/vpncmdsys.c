// SoftEther VPN Source Code
// Cedar Communication Module
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


// vpncmdsys.c
// vpncmd bootstrup

#include <GlobalConst.h>

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <locale.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "vpncmdsys.h"

static UINT ret_code = 0;

// Get whether the system is a Windows NT
bool IsWindowsNt()
{
	OSVERSIONINFO info;

	ZeroMemory(&info, sizeof(info));
	info.dwOSVersionInfoSize = sizeof(info);

	if (GetVersionEx(&info) == false)
	{
		return false;
	}

	if (info.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		return true;
	}

	return false;
}

// Execute a child process
bool ExecProcess(char *exe_name, wchar_t *args_w)
{
	bool ret;
	wchar_t exe_name_w[MAX_SIZE];
	char args[MAX_SIZE];
	STARTUPINFO info;
	STARTUPINFOW info_w;
	PROCESS_INFORMATION proc;
	// Validate arguments
	if (exe_name == NULL || args_w == NULL)
	{
		return false;
	}

	ZeroMemory(exe_name_w, sizeof(exe_name_w));
	ZeroMemory(args, sizeof(args));
	mbstowcs(exe_name_w, exe_name, strlen(exe_name));
	wcstombs(args, args_w, sizeof(args));

	ZeroMemory(&info, sizeof(info));
	info.cb = sizeof(info);

	ZeroMemory(&info_w, sizeof(info_w));
	info_w.cb = sizeof(info_w);

	ZeroMemory(&proc, sizeof(proc));

	if (IsWindowsNt() == false)
	{
		ret = CreateProcess(exe_name, args, NULL, NULL, false, NORMAL_PRIORITY_CLASS,
			NULL, NULL, &info, &proc);
	}
	else
	{
		ret = CreateProcessW(exe_name_w, args_w, NULL, NULL, false, NORMAL_PRIORITY_CLASS,
			NULL, NULL, &info_w, &proc);
	}

	if (ret)
	{
		WaitForSingleObject(proc.hProcess, INFINITE);

		GetExitCodeProcess(proc.hProcess, &ret_code);
	}

	return ret;
}

// Entry point
int main(int argc, char *argv[])
{
	HKEY hKey;
	bool ok = false;
	char error[MAX_SIZE];
	wchar_t *current_args;
	bool flag = false;
	bool break_now = false;

	error[0] = 0;

	setlocale(LC_ALL, "");

	current_args = GetCommandLineW();

	// Remove the program name portion from the command line string
	while (true)
	{
		switch (*current_args)
		{
		case L'\"':
			if (flag == false)
			{
				flag = true;
			}
			else
			{
				flag = false;
			}
			break;

		case L' ':
		case L'\t':
		case 0:
			if (flag == false)
			{
				break_now = true;
			}
			break;
		}
		if (break_now)
		{
			break;
		}
		current_args++;
	}

	while (true)
	{
		if (*current_args == L' ' || *current_args == L'\t')
		{
			current_args++;
		}
		else
		{
			break;
		}
	}

	strcpy(error, "VPN Command Line Tools is not Installed.\nPlease reinstall programs.");

	// Get the path of the vpncmd.exe from the registry
	if (RegOpenKey(HKEY_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, &hKey) == 0)
	{
		DWORD type = REG_SZ;
		DWORD size = 4096;
		char buf[4096];

		if (RegQueryValueEx(hKey, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH, NULL, &type, (LPBYTE)buf, &size) == 0)
		{
			wchar_t args[MAX_SIZE];

			swprintf(args, sizeof(args), L"\"%S\" %s", buf, current_args);
			if (ExecProcess(buf, args) == false)
			{
				//sprintf(error, "Failed to execute \"%S\".", buf);
			}
			else
			{
				ok = true;
			}
		}

		RegCloseKey(hKey);
	}

	if (ok == false)
	{
		printf("%s\n", error);
	}

	return ret_code;
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
