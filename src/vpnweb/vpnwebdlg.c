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


// vpnwebdlg.c
// VPN Client Web Installer

#include <GlobalConst.h>

#define VPNWEBDLG_C
#define _CRT_SECURE_NO_DEPRECATE

#include <winsock2.h>
#include <windows.h>
#include <Wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <locale.h>
#include <Msi.h>
#include <Msiquery.h>
#include "vpnwebdlg.h"
#include "vpnwebdlg_inner.h"
#include "resource.h"

#pragma comment(lib, "wininet.lib")

static VPNWEBDLG_INIT data;
static bool inited = false;
static VW_TASK task;
static bool clicked_flag = false;

// Check the signature of the EXE file, and displays a warning if dangerous
bool VwCheckExeSign(HWND hWnd, char *exe)
{
	wchar_t tmp[2048];
	bool danger = true;
	wchar_t *warningMessage = msgWarning;
	wchar_t *warningMessageTitle = msgWarningTitle;
	// Validate arguments
	if (hWnd == NULL || exe == NULL)
	{
		return false;
	}

	if (VwCheckFileDigitalSignature(hWnd, exe, &danger))
	{
		if (danger == false)
		{
			// Safe
			return true;
		}
		else
		{
			// Show the message because there is potentially dangerous
			swprintf(tmp, sizeof(tmp) / 2, warningMessage,
				VwUrlToFileName(exe), VwUrlToFileName(exe), VwUrlToFileName(exe));

			if (MessageBoxW(hWnd, tmp, warningMessageTitle,
				MB_OKCANCEL | MB_DEFBUTTON2 | MB_ICONEXCLAMATION) == IDOK)
			{
				return true;
			}

			return false;
		}
	}
	else
	{
		// Danger
		return false;
	}
}

// Check the digital signature of the file
bool VwCheckFileDigitalSignature(HWND hWnd, char *name, bool *danger)
{
	HRESULT ret = S_OK;
	wchar_t tmp[MAX_PATH];
	LONG (WINAPI *_WinVerifyTrust)(HWND, GUID *, LPVOID) = NULL;
	HINSTANCE hDll;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (danger != NULL)
	{
		*danger = false;
	}

	swprintf(tmp, sizeof(tmp), L"%S", name);

	hDll = LoadLibrary("Wintrust.dll");
	if (hDll == NULL)
	{
		return false;
	}

	_WinVerifyTrust =
		(LONG (__stdcall *)(HWND,GUID *,LPVOID))
		GetProcAddress(hDll, "WinVerifyTrust");
	if (_WinVerifyTrust == NULL)
	{
		FreeLibrary(hDll);
		return false;
	}
	else
	{
		GUID action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		WINTRUST_FILE_INFO file;
		WINTRUST_DATA data;

		Zero(&file, sizeof(file));
		file.cbStruct = sizeof(file);
		file.pcwszFilePath = tmp;

		Zero(&data, sizeof(data));
		data.cbStruct = sizeof(data);
		data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
		data.dwUIChoice = (hWnd != NULL ? WTD_UI_NOGOOD : WTD_UI_NONE);
		data.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN;
		data.dwUnionChoice = WTD_CHOICE_FILE;
		data.pFile = &file;

		ret = _WinVerifyTrust(hWnd, &action_id, &data);

		if (ret == ERROR_SUCCESS && danger != NULL)
		{
			if (hWnd != NULL)
			{
				if (VwCheckFileDigitalSignature(NULL, name, NULL) == false)
				{
					// It's a dangerous file, but the user selected the [OK]
					*danger = true;
				}
			}
		}
	}

	FreeLibrary(hDll);

	if (ret != ERROR_SUCCESS)
	{
		return false;
	}

	return true;
}

// Task execution thread
DWORD CALLBACK VwTaskThread(void *param)
{
	HWND hWnd = data.hWnd;
	VW_FILE *f;

	// Download the Inf file
	f = VwOpenFile(data.InstallerInfUrl);

	if (f == NULL)
	{
		wchar_t tmp[MAX_SIZE];
		swprintf(tmp, sizeof(tmp) / 2, msgInfDownloadFailed, VwUrlToFileName(data.InstallerInfUrl));
		VwPrint(hWnd, tmp);
		return 0;
	}
	else
	{
		UINT size = 0;
		UINT bufsize = 0;
		UINT readsize = 1024;
		UINT build = 0;
		char *buf;

		// Read all the contents of the file
		buf = ZeroMalloc(size);

		while (true)
		{
			UINT ret;

			bufsize = size + readsize;
			buf = ReAlloc(buf, bufsize);
			ret = VwReadFile(f, buf + size, readsize);

			if (ret == INFINITE || size >= 65536 || task.Halt)
			{
				wchar_t tmp[MAX_SIZE];
				// Download Failed
				Free(buf);
				VwCloseFile(f);
				swprintf(tmp, sizeof(tmp) / 2, msgInfDownloadFailed, VwUrlToFileName(data.InstallerInfUrl));
				VwPrint(hWnd, tmp);
				return 0;
			}
			else if (ret == 0)
			{
				// Download Complete
				break;
			}
			else
			{
				size += ret;
			}
		}

		VwCloseFile(f);

		bufsize = size + 1;
		buf = ReAlloc(buf, bufsize);
		buf[size] = 0;

		build = VwGetBuildFromVpnInstallInf(buf);
		if (build == 0)
		{
			wchar_t tmp[MAX_SIZE];
			// Build number incorrect
			Free(buf);
			swprintf(tmp, sizeof(tmp) / 2, msgBadInfFile, VwUrlToFileName(data.InstallerInfUrl));
			VwPrint(hWnd, tmp);
			return 0;
		}
		else
		{
			char tmpdir[MAX_SIZE];
			char wintmp[MAX_SIZE];
			char temp_vpninstaller_exe[MAX_SIZE];
			char temp_vpninstaller_exe_tmp[MAX_SIZE];
			char temp_vpninstaller_inf[MAX_SIZE];
			HANDLE h;

			GetTempPath(sizeof(wintmp), wintmp);

			if (lstrlen(wintmp) >= 1)
			{
				if (wintmp[lstrlen(wintmp) - 1] == '\\')
				{
					wintmp[lstrlen(wintmp) - 1] = 0;
				}
			}

			// Generate a temporary directory name
			_snprintf(tmpdir, sizeof(tmpdir), "%s\\vpninstall_%u", wintmp, build);

			// Generate a temporary file name
			_snprintf(temp_vpninstaller_exe, sizeof(temp_vpninstaller_exe),
				"%s\\%s", tmpdir, VPNINSTALL_EXE_FILENAME);
			_snprintf(temp_vpninstaller_exe_tmp, sizeof(temp_vpninstaller_exe_tmp),
				"%s\\%s", tmpdir, VPNINSTALL_EXE_FILENAME_TMP);
			_snprintf(temp_vpninstaller_inf, sizeof(temp_vpninstaller_inf),
				"%s\\%s", tmpdir, VPNINSTALL_INF_FILENAME);

			// Create a directory
			MakeDir(tmpdir);

			// Save the inf file
			h = FileCreate(temp_vpninstaller_inf);
			if (h == NULL)
			{
				wchar_t tmp[MAX_SIZE];
				// File creation failure
				Free(buf);
				swprintf(tmp, sizeof(tmp) / 2, msgWriteFailed, VPNINSTALL_INF_FILENAME);
				VwPrint(hWnd, tmp);
				return 0;
			}

			FileWrite(h, buf, lstrlen(buf));
			FileClose(h);

			Free(buf);

			// Download the vpninstall.exe
			h = FileOpen(temp_vpninstaller_exe, false);
			if (h == NULL)
			{
				UCHAR *buffer;
				UINT buffer_size = 65536;
				UINT total_size, current_size;

				// Perform the download so download unfinished
				VwPrint(hWnd, msgDownloading);
				Show(hWnd, P_PROGRESS);
				SetPos(hWnd, P_PROGRESS, 0);

				f = VwOpenFile(data.InstallerExeUrl);
				if (f == NULL)
				{
					// Download Failed
					wchar_t tmp[MAX_SIZE];

					swprintf(tmp, sizeof(tmp) / 2, msgInfDownloadFailed, VwUrlToFileName(data.InstallerExeUrl));
					VwPrint(hWnd, tmp);
					return 0;
				}

				total_size = VwGetFileSize(f);
				if (total_size == 0)
				{
					total_size = 2 * 1024 * 1024;
				}
				current_size = 0;

				h = FileCreate(temp_vpninstaller_exe_tmp);
				if (h == NULL)
				{
					wchar_t tmp[MAX_SIZE];
					// File creation failure
					swprintf(tmp, sizeof(tmp) / 2, msgWriteFailed, VPNINSTALL_EXE_FILENAME);
					VwPrint(hWnd, tmp);
					VwCloseFile(f);
					return 0;
				}

				buffer = ZeroMalloc(buffer_size);

				while (true)
				{
					UINT ret;

					ret = VwReadFile(f, buffer, buffer_size);

					if (ret == INFINITE || task.Halt || current_size >= (8 * 1024 * 1024))
					{
						// Download Failed
						wchar_t tmp[MAX_SIZE];

DOWNLOAD_FAILED:
						swprintf(tmp, sizeof(tmp) / 2, msgInfDownloadFailed, VwUrlToFileName(data.InstallerExeUrl));
						VwPrint(hWnd, tmp);
						Free(buffer);
						FileClose(h);
						VwCloseFile(f);
						return 0;
					}
					else if (ret == 0)
					{
						// Download Complete
						break;
					}
					else
					{
						UINT pos = 0;
						current_size += ret;

						pos = (UINT)((float)current_size * 100.0f / (float)total_size);
						SetPos(hWnd, P_PROGRESS, pos);

						if (FileWrite(h, buffer, ret) == false)
						{
							goto DOWNLOAD_FAILED;
						}
					}
				}

				Free(buffer);
				FileClose(h);
				VwCloseFile(f);

				Hide(hWnd, P_PROGRESS);

				// Rename the file
				if (MoveFile(temp_vpninstaller_exe_tmp, temp_vpninstaller_exe) == false)
				{
					// Download Failed
					wchar_t tmp[MAX_SIZE];
					swprintf(tmp, sizeof(tmp) / 2, msgInfDownloadFailed, VwUrlToFileName(data.InstallerExeUrl));
					VwPrint(hWnd, tmp);
					return 0;
				}
			}
			else
			{
				// Download has already been completed
				FileClose(h);
			}
			
			VwPrint(hWnd, msgProcessCreating);

			if (VwCheckExeSign(hWnd, temp_vpninstaller_exe))
			{
				// Starting the vpninstall.exe
				STARTUPINFO info;
				PROCESS_INFORMATION ret;
				char cmdline[MAX_SIZE];

				Zero(&info, sizeof(info));
				Zero(&ret, sizeof(ret));
				info.cb = sizeof(info);
				info.dwFlags = STARTF_USESHOWWINDOW;
				info.wShowWindow = SW_SHOWDEFAULT;

				if (data.VpnServerManagerMode == FALSE)
				{
					if (lstrlen(data.SettingUrl) == 0)
					{
						_snprintf(cmdline, sizeof(cmdline) - 1,
							"\"%s\" /web", temp_vpninstaller_exe);
					}
					else
					{
						_snprintf(cmdline, sizeof(cmdline) - 1,
							"\"%s\" /web \"%s\"", temp_vpninstaller_exe, data.SettingUrl);
					}
				}
				else
				{
					char args[MAX_SIZE];

					_snprintf(args, sizeof(args) - 1,
						"\"\"%s\"\" /HUB:\"\"%s\"\" /PASSWORD:\"\"%s\"\" /HWND:%I64u",
						data.VpnServerHostname,
						data.VpnServerHubName,
						data.VpnServerPassword,
						(UINT64)/*data.hControlWnd*/0ULL);

					_snprintf(cmdline, sizeof(cmdline) - 1,
						"\"%s\" /web \"%s\"", temp_vpninstaller_exe, args);
				}

				if (CreateProcess(NULL, cmdline, NULL, NULL, FALSE,
					NORMAL_PRIORITY_CLASS, NULL, NULL, &info, &ret) == false)
				{
					// Process startup failure
					wchar_t tmp[MAX_SIZE];
					swprintf(tmp, sizeof(tmp) / 2, msgProcessFailed, VPNINSTALL_EXE_FILENAME);
					VwPrint(hWnd, tmp);
					return 0;
				}

				if (data.VpnServerManagerMode == FALSE)
				{
					VwPrint(hWnd, msgProcessCreated);
				}
				else
				{
					VwPrint(hWnd, msgProcessCreatedForVpnServer);
				}
			}
			else
			{
				VwPrint(hWnd, msgUserCancal);
			}
		}
	}

	return 0;
}

// Get the build number from file vpninstall.inf
UINT VwGetBuildFromVpnInstallInf(char *buf)
{
	UINT i, len;
	char tmp[MAX_SIZE];
	UINT wp;
	char seps[] = " \t";

	len = lstrlen(buf);

	wp = 0;
	for (i = 0;i < len;i++)
	{
		char c = buf[i];

		if (c == 13 || c == 10)
		{
			tmp[wp] = 0;
			wp = 0;

			if (lstrlen(tmp) >= 1)
			{
				char *token = strtok(tmp, seps);
				if (token != NULL && lstrcmpi(token, VPNINSTALL_INF_BUILDTAG) == 0)
				{
					token = strtok(NULL, seps);
					if (token != NULL)
					{
						return (UINT)strtod(token, NULL);
					}
				}
			}
		}
		else
		{
			if ((wp + 2) < sizeof(tmp))
			{
				tmp[wp++] = c;
			}
		}
	}

	return 0;
}

// Convert the URL to the file name
char *VwUrlToFileName(char *url)
{
	UINT i, len;
	char *ret = url;
	bool b = true;
	len = lstrlen(url);

	for (i = 0;i < len;i++)
	{
		char c = url[i];

		if (c == '?' || c == '#')
		{
			b = false;
		}

		if (b)
		{
			if (c == '/' || c == '\\')
			{
				if (lstrlen(url + i + 1) > 1)
				{
					ret = url + i + 1;
				}
			}
		}
	}

	return ret;
}

// Initialization
void VwOnInit(HWND hWnd)
{
	inited = false;
	if (IsSupportedOs() == false)
	{
		// The OS is unsupported
		Hide(hWnd, P_PROGRESS);
		SetDlgItemTextA(hWnd, S_INFO, msgNotSupported);
		return;
	}

	if(data.VpnServerManagerMode == FALSE)
	{
		SetText(hWnd, S_INFO2, msgStartTextForVpnClient);
		SetText(hWnd, B_START, msgButtonForVpnClient);
	}
	else
	{
		SetText(hWnd, S_INFO2, msgStartTextForVpnServer);
		SetText(hWnd, B_START, msgButtonForVpnServer);
	}

	if (lstrlen(data.InstallerExeUrl) == 0 || lstrlen(data.InstallerInfUrl) == 0)
	{
		// Parameter is not specified
		Hide(hWnd, P_PROGRESS);
		SetDlgItemTextA(hWnd, S_INFO, msgNoParam);
		return;
	}

	if (data.VpnServerManagerMode == FALSE)
	{
		Show(hWnd, S_ICON_VPN);
		Hide(hWnd, S_ICON_SERVER);
	}
	else
	{
		Show(hWnd, S_ICON_SERVER);
		Hide(hWnd, S_ICON_VPN);


	}

	Hide(hWnd, P_PROGRESS);
	Hide(hWnd, S_INFO);
	Show(hWnd, S_INFO2);
	Show(hWnd, B_START);
	clicked_flag = false;

	Zero(&task, sizeof(task));
}

// Release
void VwOnFree(HWND hWnd)
{
	if (inited == false)
	{
		return;
	}

	task.Halt = true;

	if (task.Thread != NULL)
	{
		while (true)
		{
			if (WaitForSingleObject(task.Thread, 30) != WAIT_TIMEOUT)
			{
				break;
			}
			DoEvents(hWnd);
		}
		CloseHandle(task.Thread);
		task.Thread = NULL;
	}
}

// Show the string
void VwPrint(HWND hWnd, wchar_t *str)
{
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	SetText(hWnd, S_INFO, str);
}

// Dialog procedure
INT_PTR CALLBACK VpnWebDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		VwOnInit(hWnd);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_START:
			if (clicked_flag == false)
			{
				clicked_flag = true;
				SetTimer(hWnd, 1, 1, NULL);
			}
			break;
		}
		break;

	case WM_DESTROY:
		VwOnFree(hWnd);
		break;

	case WM_CLOSE:
		return 1;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			inited = true;
			Hide(hWnd, B_START);
			Hide(hWnd, S_INFO2);
			Show(hWnd, S_INFO);
			VwPrint(hWnd, msgInfDownloag);
			task.Thread = VwNewThread(VwTaskThread, NULL);
			break;

		case 2:
			KillTimer(hWnd, 2);
			SendMessage(hWnd, WM_COMMAND, B_START, 0);
			break;
		}
		break;

	case WM_CTLCOLORBTN:
	case WM_CTLCOLORDLG:
	case WM_CTLCOLOREDIT:
	case WM_CTLCOLORLISTBOX:
	case WM_CTLCOLORMSGBOX:
	case WM_CTLCOLORSCROLLBAR:
	case WM_CTLCOLORSTATIC:
		return (UINT)GetStockObject(WHITE_BRUSH);
	}

	return 0;
}

// Set the string to window
void SetText(HWND hWnd, UINT id, wchar_t *str)
{
	wchar_t tmp[512];
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	Zero(tmp, sizeof(tmp));
	GetWindowTextW(DlgItem(hWnd, id), tmp, sizeof(tmp) - 1);

	if (lstrcmpW(tmp, str) == 0)
	{
		return;
	}

	SetWindowTextW(DlgItem(hWnd, id), str);
}

// Check whether the OS is supported
bool IsSupportedOs()
{
	OSVERSIONINFO ver;

	Zero(&ver, sizeof(ver));

	ver.dwOSVersionInfoSize = sizeof(ver);
	if (GetVersionExA(&ver) == false)
	{
		return false;
	}

	if (ver.dwMajorVersion <= 4)
	{
		return false;
	}

	if (ver.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS || ver.dwPlatformId == VER_PLATFORM_WIN32s)
	{
		return false;
	}

	return true;
}

// Show a message box
UINT MsgBox(HWND hWnd, UINT flag, wchar_t *msg)
{
	// Validate arguments
	if (msg == NULL)
	{
		msg = L"MessageBox";
	}

	return MessageBoxW(hWnd, msg, msgAppTitle, flag);
}

// Create a directory
bool MakeDir(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	return CreateDirectory(name, NULL);
}

// Create a file
HANDLE FileCreate(char *name)
{
	HANDLE h;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	h = CreateFile(name, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (h == NULL || h == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	return h;
}

// Open the file
HANDLE FileOpen(char *name, bool write_mode)
{
	HANDLE h;
	DWORD lock_mode;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	if (write_mode)
	{
		lock_mode = FILE_SHARE_READ;
	}
	else
	{
		lock_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
	}

	h = CreateFile(name,
		(write_mode ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ),
		lock_mode,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	return h;
}

// Close the file
void FileClose(HANDLE h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	FlushFileBuffers(h);

	CloseHandle(h);
}

// Read from the file
bool FileRead(HANDLE h, void *buf, UINT size)
{
	UINT read_size;
	// Validate arguments
	if (h == NULL || buf == NULL || size == 0)
	{
		return false;
	}

	if (ReadFile(h, buf, size, &read_size, NULL) == false)
	{
		return false;
	}

	if (read_size != size)
	{
		return false;
	}

	return true;
}

// Write to the file
bool FileWrite(HANDLE h, void *buf, UINT size)
{
	DWORD write_size;
	// Validate arguments
	if (h == NULL || buf == NULL || size == 0)
	{
		return false;
	}

	if (WriteFile(h, buf, size, &write_size, NULL) == false)
	{
		return false;
	}

	if (write_size != size)
	{
		return false;
	}

	return true;
}

// Get the file size
UINT64 FileSize(HANDLE h)
{
	UINT64 ret;
	DWORD tmp;
	// Validate arguments
	if (h == NULL)
	{
		return 0;
	}

	tmp = 0;
	ret = GetFileSize(h, &tmp);
	if (ret == (DWORD)-1)
	{
		return 0;
	}

	if (tmp != 0)
	{
		ret += (UINT64)tmp * 4294967296ULL;
	}

	return ret;
}

// Open the Internet file
VW_FILE *VwOpenFile(char *path)
{
	VW_FILE *f;
	HINTERNET hHttpFile;
	HINTERNET hInternet = InternetOpenA(
		"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)",
		INTERNET_OPEN_TYPE_PRECONFIG,
		NULL, NULL, 0);
	UINT size;
	UINT sizesize;
	char tmp[8];
	// Validate arguments
	if (path == NULL)
	{
		return NULL;
	}

	if (hInternet == NULL)
	{
		return NULL;
	}

	hHttpFile = InternetOpenUrlA(hInternet, path, NULL, 0,
		INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD, 0);

	if (hHttpFile == NULL)
	{
		InternetCloseHandle(hInternet);
		return NULL;
	}

	size = 0;
	sizesize = sizeof(size);

	ZeroMemory(tmp, sizeof(tmp));

	if (strlen(path) >= 6)
	{
		CopyMemory(tmp, path, 6);
	}

	if (lstrcmpi(tmp, "ftp://") == 0)
	{
		// ftp
		DWORD high = 0;

		size = FtpGetFileSize(hHttpFile, &high);
	}
	else
	{
		UINT errorcode = 0;
		UINT errorcode_size = sizeof(errorcode);

		// http
		if (HttpQueryInfo(hHttpFile, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
			&size, &sizesize, NULL) == false)
		{
			size = 0;
		}

		if (HttpQueryInfo(hHttpFile, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
			&errorcode, &errorcode_size, NULL) == false ||
			(errorcode / 100) != 2)
		{
			// HTTP getting error
			InternetCloseHandle(hInternet);
			InternetCloseHandle(hHttpFile);
			return NULL;
		}
	}

	f = ZeroMalloc(sizeof(VW_FILE));
	f->hInternet = hInternet;
	f->hHttpFile = hHttpFile;
	f->FileSize = size;

	return f;
}

// Get the Internet file size
UINT VwGetFileSize(VW_FILE *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return 0;
	}

	return f->FileSize;
}

// Read from the Internet file
UINT VwReadFile(VW_FILE *f, void *buf, UINT size)
{
	UINT readsize = 0;
	// Validate arguments
	if (f == NULL || buf == NULL)
	{
		return INFINITE;
	}

	if (InternetReadFile(f->hHttpFile, buf, size, &readsize) == false)
	{
		return INFINITE;
	}

	return readsize;
}

// Close the Internet file
void VwCloseFile(VW_FILE *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	InternetCloseHandle(f->hHttpFile);
	InternetCloseHandle(f->hInternet);

	Free(f);
}

// Memory reallocation
void *ReAlloc(void *p, UINT size)
{
	void *ret;
	if (size == 0)
	{
		size = 1;
	}

	ret = realloc(p, size);
	if (ret == NULL)
	{
		_exit(0);
	}

	return ret;
}

// Memory allocation
void *ZeroMalloc(UINT size)
{
	void *p;
	if (size == 0)
	{
		size = 1;
	}

	p = malloc(size);
	if (p == NULL)
	{
		_exit(0);
	}

	Zero(p, size);

	return p;
}

// Memory clear
void Zero(void *p, UINT size)
{
	if (p != NULL)
	{
		ZeroMemory(p, size);
	}
}

// Memory release
void Free(void *p)
{
	if (p != NULL)
	{
		free(p);
	}
}

// Thread creation
HANDLE VwNewThread(LPTHREAD_START_ROUTINE start, void *param)
{
	HANDLE h;
	DWORD id;
	// Validate arguments
	if (start == NULL)
	{
		return NULL;
	}

	h = (HANDLE)_beginthreadex(NULL, 0, start, param, 0, &id);

	return h;
}

// Thread release
void VwFreeThread(HANDLE h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	CloseHandle(h);
}

// Dialog procedure that does not do anything
INT_PTR CALLBACK VpnWebDummyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	return 0;
}

// Initialization of the dialog
HWND InitVpnWebDlg(VPNWEBDLG_INIT *init)
{
	HWND hWnd;
	// Validate arguments
	if (init == NULL)
	{
		return NULL;
	}

	_configthreadlocale(_DISABLE_PER_THREAD_LOCALE);
	setlocale(LC_ALL, "");

	ZeroMemory(&data, sizeof(data));
	CopyMemory(&data, init, sizeof(data));

	LoadTables(data.LanguageId);

	hWnd = CreateDialog(hDllInstance, MAKEINTRESOURCE(IDD_VPNWEBDLG),
		data.hControlWnd, VpnWebDlgProc);

	data.hWnd = hWnd;

	ShowWindow(hWnd, SW_SHOW);

	return hWnd;
}

// Exit the dialog
void FreeVpnWebDlg()
{
	DestroyWindow(data.hWnd);
}

// Get the size of the dialog
void GetVpnWebDlgSize(SIZE *size)
{
	HWND hWnd;
	RECT rect;
	// Validate arguments
	if (size == NULL)
	{
		return;
	}

	hWnd = CreateDialog(hDllInstance, MAKEINTRESOURCE(IDD_VPNWEBDLG),
		GetDesktopWindow(), VpnWebDummyDlgProc);

	ZeroMemory(&rect, sizeof(rect));
	GetWindowRect(hWnd, &rect);

	DestroyWindow(hWnd);

	size->cx = rect.right - rect.left;
	size->cy = rect.bottom - rect.top;
}


// Get the item in the dialog
HWND DlgItem(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	if (id == 0)
	{
		return hWnd;
	}
	else
	{
		return GetDlgItem(hWnd, id);
	}
}

// Hide the window
void Hide(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (IsShow(hWnd, id))
	{
		ShowWindow(DlgItem(hWnd, id), SW_HIDE);
	}
}

// Display the window
void Show(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (IsHide(hWnd, id))
	{
		ShowWindow(DlgItem(hWnd, id), SW_SHOW);
	}
}

// Changing the visibility setting
void SetShow(HWND hWnd, UINT id, bool b)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (b)
	{
		Show(hWnd, id);
	}
	else
	{
		Hide(hWnd, id);
	}
}

// Get whether the window is shown
bool IsShow(HWND hWnd, UINT id)
{
	return IsHide(hWnd, id) ? false : true;
}

// Get whether the window is hidden
bool IsHide(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return true;
	}

	if (GetStyle(hWnd, id) & WS_VISIBLE)
	{
		return false;
	}
	else
	{
		return true;
	}
}

// Remove the window style
void RemoveExStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	old = GetExStyle(hWnd, id);
	if ((old & style) == 0)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_EXSTYLE, old & ~style);
	Refresh(DlgItem(hWnd, id));
}

// Set the window style
void SetExStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	old = GetExStyle(hWnd, id);
	if (old & style)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_EXSTYLE, old | style);
	Refresh(DlgItem(hWnd, id));
}

// Get the window style
UINT GetExStyle(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	return GetWindowLong(DlgItem(hWnd, id), GWL_EXSTYLE);
}

// Remove the window style
void RemoveStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	old = GetStyle(hWnd, id);
	if ((old & style) == 0)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_STYLE, old & ~style);
	Refresh(DlgItem(hWnd, id));
}

// Set the window style
void SetStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	old = GetStyle(hWnd, id);
	if (old & style)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_STYLE, old | style);
	Refresh(DlgItem(hWnd, id));
}

// Get the window style
UINT GetStyle(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	return GetWindowLong(DlgItem(hWnd, id), GWL_STYLE);
}

// Update the window
void Refresh(HWND hWnd)
{
	HWND parent;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	DoEvents(hWnd);
	UpdateWindow(hWnd);
	DoEvents(hWnd);

	parent = GetParent(hWnd);
	if (parent != NULL)
	{
		Refresh(parent);
	}
}

// Handle the event
void DoEvents(HWND hWnd)
{
	MSG msg;

	if (PeekMessage(&msg, hWnd, 0, 0, PM_REMOVE))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	UpdateWindow(hWnd);

	if (hWnd)
	{
		DoEvents(NULL);
	}
}

// Disable the window
void Disable(HWND hWnd, UINT id)
{
	SetEnable(hWnd, id, false);
}

// Enable the window
void Enable(HWND hWnd, UINT id)
{
	SetEnable(hWnd, id, true);
}

// Set the enabled state of the window
void SetEnable(HWND hWnd, UINT id, bool b)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (b == false)
	{
		if (IsEnable(hWnd, id))
		{
			EnableWindow(DlgItem(hWnd, id), false);
			Refresh(DlgItem(hWnd, id));
		}
	}
	else
	{
		if (IsDisable(hWnd, id))
		{
			EnableWindow(DlgItem(hWnd, id), true);
			Refresh(DlgItem(hWnd, id));
		}
	}
}

// Examine whether the Window is disabled
bool IsDisable(HWND hWnd, UINT id)
{
	return IsEnable(hWnd, id) ? false : true;
}

// Examine whether the window is enabled
bool IsEnable(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return false;
	}

	return IsWindowEnabled(DlgItem(hWnd, id));
}

// Set the position of the progress bar
void SetPos(HWND hWnd, UINT id, UINT pos)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, PBM_SETPOS, pos, 0);
}

// Set the range of the progress bar
void SetRange(HWND hWnd, UINT id, UINT start, UINT end)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, PBM_SETRANGE32, start, end);
}

// Transmit a message to the control
UINT SendMsg(HWND hWnd, UINT id, UINT msg, WPARAM wParam, LPARAM lParam)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	return (UINT)SendMessageA(DlgItem(hWnd, id), msg, wParam, lParam);
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
