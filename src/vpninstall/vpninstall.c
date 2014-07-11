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


// vpninstall.c
// VPN Client Web Installer Bootstrap

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
#include <Msiquery.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "vpninstall.h"
#include "resource.h"

#pragma comment(lib, "wininet.lib")

static bool is_debug = true;
static LIST *string_table = NULL;
static VI_SETTING setting;
static bool sleep_before_exit = false;
static int skip = 0;

// Convert the URL to the file name
char *ViUrlToFileName(char *url)
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

// Check the signature of the EXE file, and displays a warning if dangerous
bool ViCheckExeSign(HWND hWnd, wchar_t *exew)
{
	wchar_t tmp[2048];
	bool danger = true;
	wchar_t *warningMessage = _U(IDS_SIGN_WARNING+skip);
	wchar_t *warningMessageTitle = _U(IDS_SIGN_WARNING_TITLE+skip);
	// Validate arguments
	if (hWnd == NULL || exew == NULL)
	{
		return false;
	}

	if (MsCheckFileDigitalSignatureW(hWnd, exew, &danger))
	{
		if (danger == false)
		{
			// Safe
			return true;
		}
		else
		{
			wchar_t filename[MAX_PATH];

			GetFileNameFromFilePathW(filename, sizeof(filename), exew);

			// Show the message because there is potentially dangerous
			swprintf(tmp, sizeof(tmp) / 2, warningMessage,
				filename, filename, filename);

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

// Start the installation process
void ViInstallProcessStart(HWND hWnd, VI_INSTALL_DLG *d)
{
	wchar_t *exew;
	bool ok;
	char instdir[MAX_PATH];
	char hamcore[MAX_PATH];
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	ViGenerateVpnSMgrTempDirName(instdir, sizeof(instdir), ViGetSuitableArchForCpu()->Build);
	ConbinePath(hamcore, sizeof(hamcore), instdir, "hamcore.se2");

	exew = setting.DownloadedInstallerPathW;
	d->NoClose = true;

	Hide(hWnd, IDCANCEL);
	SetPos(hWnd, P_PROGRESS, 100);
	Hide(hWnd, P_PROGRESS);
	Hide(hWnd, S_SIZEINFO);
	SetText(hWnd, S_STATUS, _U(IDS_INSTALLSTART+skip));

	ok = true;

	if (setting.DownloadNotRequired == false)
	{
		if (setting.WebMode && ViCheckExeSign(hWnd, exew) == false)
		{
			// The digital signature is not reliable
			ok = false;
		}
		else
		{
			// Installation
			HANDLE hProcess;
			SHELLEXECUTEINFOW info;

			// Run
			Zero(&info, sizeof(info));
			info.cbSize = sizeof(info);
			info.lpVerb = L"open";
			info.lpFile = exew;
			info.fMask = SEE_MASK_NOCLOSEPROCESS;
			info.lpParameters = L"/HIDESTARTCOMMAND:1 /DISABLEAUTOIMPORT:1 /ISWEBINSTALLER:1";
			info.nShow = SW_SHOWNORMAL;
			if (ShellExecuteExW(&info) == false)
			{
				MsgBox(hWnd, MB_ICONSTOP, _U(IDS_INSTALLSTART_ERROR+skip));
				ok = false;
			}
			else
			{
				hProcess = info.hProcess;

				// Wait for the install process to complete
				while (true)
				{
					if (WaitForSingleObject(hProcess, 50) != WAIT_TIMEOUT)
					{
						break;
					}

					DoEvents(hWnd);
				}
				CloseHandle(hProcess);
			}
		}
	}

	if (ok && d->WindowsShutdowning == false)
	{
		VI_SETTING_ARCH *a = ViGetSuitableArchForCpu();
		wchar_t arg[MAX_PATH];
		wchar_t exe[MAX_PATH];
		char *arg1 = "/easy";
		// Hide the screen
		Hide(hWnd, 0);

		if (setting.NormalMode)
		{
			arg1 = "/normal";
		}

		// (Just in case) start the VPN Client service
		if (MsIsServiceRunning("vpnclient") == false)
		{
			MsStartService("vpnclient");
		}

		// Wait for that the service becomes available
		SwWaitForVpnClientPortReady(0);

		if (UniIsEmptyStr(setting.DownloadedSettingPathW) == false)
		{
			// Start a connection by importing the configuration file into the VPN Client
			UniFormat(arg, sizeof(arg), L"%S \"%s\"", arg1, setting.DownloadedSettingPathW);
		}
		else
		{
			// Just start the Connection Manager
			UniFormat(arg, sizeof(arg), L"%S", arg1);
		}

		// Get the installation state
		ViLoadCurrentInstalledStatusForArch(a);

		if (a->CurrentInstalled)
		{
			HANDLE h;
			wchar_t filename[MAX_PATH];

			StrToUni(filename, sizeof(filename), a->VpnCMgrExeFileName);

			ConbinePathW(exe, sizeof(exe), a->CurrentInstalledPathW, filename);

			// Start the Connection Manager
			h = MsRunAsUserExW(exe, arg, false);
			if (h != NULL)
			{
				if (UniIsEmptyStr(setting.DownloadedSettingPathW) == false)
				{
					sleep_before_exit = true;
				}

				CloseHandle(h);
			}
		}
	}

	d->NoClose = false;
	Close(hWnd);
}

// End User License Agreement dialog
UINT ViEulaDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	wchar_t *text = (wchar_t *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetText(hWnd, 0, _U(IDS_DLG_TITLE+skip));
		SetText(hWnd, S_EULA_NOTICE1, _U(IDS_EULA_NOTICE1+skip));
		SetText(hWnd, S_BOLD, _U(IDS_EULA_NOTICE2+skip));
		SetText(hWnd, S_EULA_NOTICE3, _U(IDS_EULA_NOTICE3+skip));
		SetText(hWnd, IDOK, _U(IDS_EULA_AGREE+skip));
		SetText(hWnd, IDCANCEL, _U(IDS_EULA_DISAGREE+skip));

		DlgFont(hWnd, S_BOLD, 0, true);
		SetText(hWnd, E_EULA, text);
		Focus(hWnd, E_EULA);
		SendMsg(hWnd, E_EULA, EM_SETSEL, 0, 0);
		Center(hWnd);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			EndDialog(hWnd, 1);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// Display the End User License Agreement
bool ViEulaDlg(HWND hWnd, wchar_t *text)
{
	// Validate arguments
	if (text == NULL)
	{
		return false;
	}

	if (Dialog(hWnd, D_EULA, ViEulaDlgProc, text) == 0)
	{
		return false;
	}

	return true;
}

// Extract the license agreement from the EXE file
wchar_t *ViExtractEula(char *exe)
{
	BUF *b;
	UINT tmp_size;
	char *tmp;
	wchar_t *ret;
	// Validate arguments
	if (exe == NULL)
	{
		return false;
	}

	b = ViExtractResource(exe, RT_RCDATA, "LICENSE");
	if (b == NULL)
	{
		return NULL;
	}

	tmp_size = b->Size + 1;
	tmp = ZeroMalloc(tmp_size);

	Copy(tmp, b->Buf, b->Size);
	FreeBuf(b);

	ret = CopyStrToUni(tmp);
	Free(tmp);

	return ret;
}

// Extract the Cabinet file from the EXE file
bool ViExtractCabinetFile(char *exe, char *cab)
{
	BUF *b;
	// Validate arguments
	if (exe == NULL || cab == NULL)
	{
		return false;
	}

	b = ViExtractResource(exe, RT_RCDATA, "CABINET");
	if (b == NULL)
	{
		return false;
	}

	if (DumpBuf(b, cab) == false)
	{
		FreeBuf(b);

		return false;
	}

	FreeBuf(b);

	return true;
}

// Extract the resource from the EXE file
BUF *ViExtractResource(char *exe, char *type, char *name)
{
	HINSTANCE h;
	HRSRC hr;
	HGLOBAL hg;
	UINT size;
	void *data;
	BUF *buf;
	// Validate arguments
	if (exe == NULL || type == NULL || name == NULL)
	{
		return NULL;
	}

	h = LoadLibraryExA(exe, NULL, LOAD_LIBRARY_AS_DATAFILE);
	if (h == NULL)
	{
		return NULL;
	}

	hr = FindResourceA(h, name, type);
	if (hr == NULL)
	{
		FreeLibrary(h);
		return NULL;
	}

	hg = LoadResource(h, hr);
	if (hg == NULL)
	{
		FreeLibrary(h);
		return NULL;
	}

	size = SizeofResource(h, hr);
	data = (void *)LockResource(hg);

	buf = NewBuf();
	WriteBuf(buf, data, size);

	FreeResource(hg);
	FreeLibrary(h);

	SeekBuf(buf, 0, 0);

	return buf;
}

// Open the file
VI_FILE *ViOpenFile(char *path)
{
	VI_FILE *f;
	// Validate arguments
	if (path == NULL)
	{
		return NULL;
	}

	if (ViIsInternetFile(path))
	{
		HINTERNET hHttpFile;
		HINTERNET hInternet = InternetOpenA(DEFAULT_USER_AGENT,
			INTERNET_OPEN_TYPE_PRECONFIG,
			NULL, NULL, 0);
		UINT size;
		UINT sizesize;

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

		if (StartWith(path, "ftp://"))
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

		f = ZeroMalloc(sizeof(VI_FILE));
		f->InternetFile = true;
		f->hInternet = hInternet;
		f->hHttpFile = hHttpFile;
		f->FileSize = size;

		return f;
	}
	else
	{
		IO *io;
		char fullpath[MAX_PATH];
		char exedir[MAX_PATH];

		GetExeDir(exedir, sizeof(exedir));

		ConbinePath(fullpath, sizeof(fullpath), exedir, path);

		io = FileOpen(fullpath, false);
		if (io == NULL)
		{
			return NULL;
		}

		f = ZeroMalloc(sizeof(VI_FILE));
		f->InternetFile = false;
		f->FileSize = FileSize(io);
		f->io = io;

		return f;
	}
}

// Get the file size
UINT ViGetFileSize(VI_FILE *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return 0;
	}

	return f->FileSize;
}

// Read from the file
UINT ViReadFile(VI_FILE *f, void *buf, UINT size)
{
	// Validate arguments
	if (f == NULL || buf == NULL)
	{
		return INFINITE;
	}

	if (f->InternetFile == false)
	{
		UINT readsize = MIN(size, f->FileSize - f->IoReadFileSize);
		bool ret;

		if (readsize == 0)
		{
			return 0;
		}

		ret = FileRead(f->io, buf, readsize);

		if (ret == false)
		{
			return INFINITE;
		}

		f->IoReadFileSize += readsize;

		return readsize;
	}
	else
	{
		UINT readsize = 0;

		if (InternetReadFile(f->hHttpFile, buf, size, &readsize) == false)
		{
			return INFINITE;
		}

		return readsize;
	}
}

// Close the file
void ViCloseFile(VI_FILE *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	if (f->InternetFile == false)
	{
		FileClose(f->io);
	}
	else
	{
		InternetCloseHandle(f->hHttpFile);
		InternetCloseHandle(f->hInternet);
	}

	Free(f);
}

// Determine whether the specified file name is the file on the Internet
bool ViIsInternetFile(char *path)
{
	// Validate arguments
	if (path == NULL)
	{
		return false;
	}

	if (StartWith(path, "http://") || StartWith(path, "https://") || StartWith(path, "ftp://"))
	{
		return true;
	}

	return false;
}

// Installer dialog initialization
void ViInstallDlgOnInit(HWND hWnd, VI_INSTALL_DLG *d)
{
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	d->hWnd = hWnd;

	SetIcon(hWnd, 0, IDI_MAIN);

	SetText(hWnd, 0, _U(IDS_DLG_TITLE+skip));
	SetText(hWnd, S_TITLE, _U(IDS_DLG_TITLE+skip));

	SetText(hWnd, S_STATUS, _U(IDS_INSTALL_DLG__STATUS_INIT+skip));
	SetText(hWnd, IDCANCEL, _U(IDS_INSTALL_CANCEL+skip));

	DlgFont(hWnd, S_TITLE+skip, 12, true);
	SetRange(hWnd, P_PROGRESS, 0, 100);
	SetPos(hWnd, P_PROGRESS, 0);

	SetTimer(hWnd, 1, 22, NULL);
}

// Start the download thread
void ViDownloadThreadStart(VI_INSTALL_DLG *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	d->DownloadStarted = true;
	d->DownloadThread = NewThread(ViDownloadThread, d);
}


// Stop the download thread
void ViDownloadThreadStop(VI_INSTALL_DLG *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	if (d->DownloadStarted == false)
	{
		return;
	}

	d->DownloadStarted = false;
	d->Halt = true;

	while (true)
	{
		if (WaitThread(d->DownloadThread, 50))
		{
			break;
		}

		DoEvents(NULL);
	}

	ReleaseThread(d->DownloadThread);
}

// Download thread
void ViDownloadThread(THREAD *thread, void *param)
{
	VI_INSTALL_DLG *d;
	VI_SETTING_ARCH *a;
	HWND hWnd;
	UINT num_files = 2;
	VI_DOWNLOAD_FILE files[2];
	VI_DOWNLOAD_FILE *f;
	UINT i;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	d = (VI_INSTALL_DLG *)param;
	hWnd = d->hWnd;

	Zero(files, sizeof(files));

	a = ViGetSuitableArchForCpu();

	// File body
	f = &files[0];
	StrCpy(f->SrcPath, sizeof(f->SrcPath), a->Path);

	// Configuration file
	if (IsEmptyStr(setting.SettingPath) == false)
	{
		f = &files[1];
		StrCpy(f->SrcPath, sizeof(f->SrcPath), setting.SettingPath);
	}
	else
	{
		// No configuration file
		num_files = 1;
	}

	for (i = 0;i < num_files;i++)
	{
		bool b = true;

		if (i == 0 && setting.DownloadNotRequired)
		{
			b = false;
		}

		if (b)
		{
			wchar_t tmp[MAX_SIZE];
			IO *dest = NULL;
			VI_FILE *down;
			UINT ret;
			UINT totalsize;
			UINT currentsize;
			wchar_t filename_w[MAX_PATH];

			f = &files[i];
			GetFileNameFromFilePath(f->FileName, sizeof(f->FileName), f->SrcPath);
			MakeSafeFileName(f->FileName, sizeof(f->FileName), f->FileName);

			StrToUni(filename_w, sizeof(filename_w), f->FileName);
			ConbinePathW(f->DestPathW, sizeof(f->DestPathW), MsGetMyTempDirW(), filename_w);

			ViInstallDlgSetPos(hWnd, 0);
			UniFormat(tmp, sizeof(tmp), _U(IDS_DOWNLOADSTART+skip), f->FileName);
			ViInstallDlgSetText(d, hWnd, S_STATUS, tmp);

			down = ViOpenFile(f->SrcPath);
			if (down == NULL)
			{
				MsgBoxEx(hWnd, MB_ICONSTOP, _U(IDS_DOWNLOAD_ERROR+skip), f->FileName);

				ViInstallDlgCancel(hWnd);
				return;
			}

			dest = FileCreateW(f->DestPathW);
			if (dest == NULL)
			{
				MsgBoxEx(hWnd, MB_ICONSTOP, _U(IDS_TEMP_ERROR+skip), f->DestPathW);

				ViCloseFile(down);
				ViInstallDlgCancel(hWnd);
				return;
			}

			totalsize = ViGetFileSize(down);
			currentsize = 0;

			UniFormat(tmp, sizeof(tmp), _U(IDS_DOWNLOADING3+skip), f->FileName);
			ViInstallDlgSetText(d, hWnd, S_STATUS, tmp);

			while (true)
			{
				UINT pos = 0;

				if (d->Halt)
				{
					// User cancel
					FileClose(dest);
					ViCloseFile(down);
					return;
				}

				UniFormat(tmp, sizeof(tmp), _U(IDS_DOWNLOADING3+skip), f->FileName);

				ViInstallDlgSetText(d, hWnd, IDS_DOWNLOADING3+skip, tmp);
				ret = ViReadFile(down, d->Buf, d->BufSize);

				if (ret == INFINITE)
				{
					// Communication error
					MsgBoxEx(hWnd, MB_ICONSTOP, _U(IDS_DOWNLOAD_ERROR+skip), f->FileName);

					FileClose(dest);
					ViCloseFile(down);
					ViInstallDlgCancel(hWnd);

					return;
				}

				// Draw progress
				currentsize += ret;

				if (totalsize != 0)
				{
					UniFormat(tmp, sizeof(tmp), _U(IDS_DOWNLOADING+skip),
						((float)totalsize) / 1024.0f / 1024.0f,
						((float)currentsize) / 1024.0f / 1024.0f);

					pos = (UINT)(((float)currentsize) * 100.0f / ((float)totalsize));
				}
				else
				{
					UniFormat(tmp, sizeof(tmp), _U(IDS_DOWNLOADING2+skip),
						((float)currentsize) / 1024.0f / 1024.0f);
					pos = (UINT)(((float)currentsize) * 100.0f / (1024.0f * 1024.0f * 10.0f));
				}

				ViInstallDlgSetText(d, hWnd, S_SIZEINFO, tmp);
				ViInstallDlgSetPos(hWnd, pos);

				if (ret == 0)
				{
					// Download Complete
					break;
				}
				else
				{
					FileWrite(dest, d->Buf, ret);
				}
			}

			ViCloseFile(down);
			FileClose(dest);
		}
	}

	UniStrCpy(setting.DownloadedInstallerPathW, sizeof(setting.DownloadedInstallerPathW),
		files[0].DestPathW);

	if (num_files >= 2)
	{
		UniStrCpy(setting.DownloadedSettingPathW, sizeof(setting.DownloadedSettingPathW),
			files[1].DestPathW);
	}

	PostMessageA(hWnd, WM_VI_DOWNLOAD_FINISHED, 0, 0);
}

// Operation of the progress bar
void ViInstallDlgSetPos(HWND hWnd, UINT pos)
{
	PostMessage(hWnd, WM_VI_SETPOS, 0, pos);
}

// Set the text
void ViInstallDlgSetText(VI_INSTALL_DLG *d, HWND hWnd, UINT id, wchar_t *text)
{
	DWORD value = 0;
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	if (d->Halt)
	{
		return;
	}

	SendMessageTimeout(hWnd, WM_VI_SETTEXT, id, (LPARAM)text, SMTO_BLOCK, 200, &value);
}

// Cancel
void ViInstallDlgCancel(HWND hWnd)
{
	PostMessageA(hWnd, WM_VI_CANCEL, 0, 0);
}

// Installer operation start
void ViInstallDlgOnStart(HWND hWnd, VI_INSTALL_DLG *d)
{
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	// Start the download thread
	ViDownloadThreadStart(d);
}

// Cancel the installation
void ViInstallDlgOnClose(HWND hWnd, VI_INSTALL_DLG *d)
{
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	if (d->DialogCanceling)
	{
		return;
	}
	if (d->NoClose)
	{
		return;
	}

	d->DialogCanceling = true;

	// Disable the cancel button
	Disable(hWnd, IDCANCEL);

	// Stop the download thread if it runs
	ViDownloadThreadStop(d);

	// Exit the dialog
	EndDialog(hWnd, 0);
}

// Installer procedure
UINT ViInstallDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	VI_INSTALL_DLG *d = (VI_INSTALL_DLG *)param;
	UINT pos;
	wchar_t *text;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		ViInstallDlgOnInit(hWnd, param);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			ViInstallDlgOnStart(hWnd, d);
			break;
		}
		break;

	case WM_VI_SETPOS:
		// Setting the progress bar
		pos = (UINT)lParam;
		SetPos(hWnd, P_PROGRESS, MAKESURE(pos, 0, 100));
		break;

	case WM_VI_SETTEXT:
		// Set the string
		text = (wchar_t *)lParam;
		SetText(hWnd, (UINT)wParam, text);
		break;

	case WM_VI_CANCEL:
		// There was a cancellation from the thread side
		ViInstallDlgOnClose(hWnd, d);
		break;

	case WM_VI_DOWNLOAD_FINISHED:
		// Download Complete
		ViInstallProcessStart(hWnd, d);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			ViInstallDlgOnClose(hWnd, d);
			break;
		}
		break;

	case WM_QUERYENDSESSION:
		d->WindowsShutdowning = true;
		break;

	case WM_CLOSE:
		break;
	}

	return 0;
}

// Show the dialog
void ViInstallDlg()
{
	VI_INSTALL_DLG d;

	Zero(&d, sizeof(d));

	d.BufSize = 65535;
	d.Buf = Malloc(d.BufSize);

	Dialog(NULL, D_INSTALL, ViInstallDlgProc, &d);

	Free(d.Buf);
}

// Read the inf file from the buffer
bool ViLoadInfFromBuf(VI_SETTING *set, BUF *buf)
{
	bool ret;
	if (set == NULL || buf == NULL)
	{
		return false;
	}

	Zero(set, sizeof(VI_SETTING));

	SeekBuf(buf, 0, 0);
	while (true)
	{
		char *tmp = CfgReadNextLine(buf);
		TOKEN_LIST *tokens;

		if (tmp == NULL)
		{
			break;
		}

		tokens = ParseToken(tmp, " \t");

		if (tokens != NULL)
		{
			if (tokens->NumTokens >= 2)
			{
				if (StartWith(tokens->Token[0], "#") == false
					|| StartWith(tokens->Token[0], "//") == false)
				{
					char *name, *value;
					name = tokens->Token[0];
					value = tokens->Token[1];

					if (StrCmpi(name, "VpnInstallBuild") == 0)
					{
						set->VpnInstallBuild = ToInt(value);
					}
					else if (StrCmpi(name, "NormalMode") == 0)
					{
						set->NormalMode = ToBool(value);
					}
					else if (StrCmpi(name, "VpnSettingPath") == 0)
					{
						StrCpy(set->SettingPath, sizeof(set->SettingPath), value);
					}
					else if (StrCmpi(name, "VpnClientBuild") == 0)
					{
						set->x86.Build = ToInt(value);
					}
					else if (StrCmpi(name, "VpnClientPath") == 0)
					{
						StrCpy(set->x86.Path, sizeof(set->x86.Path), value);
					}
				}
			}
			FreeToken(tokens);
		}

		Free(tmp);
	}

	ret = false;

	StrCpy(set->x86.VpnCMgrExeFileName, sizeof(set->x86.VpnCMgrExeFileName), (MsIsX64() ? "vpncmgr_x64.exe" : "vpncmgr.exe"));

	if (set->VpnInstallBuild != 0)
	{
		if (set->x86.Build != 0 && IsEmptyStr(set->x86.Path) == false)
		{
			set->x86.Supported = true;
			ret = true;
		}
	}

	return ret;
}

// Read the inf file
bool ViLoadInf(VI_SETTING *set, char *filename)
{
	BUF *b;
	bool ret = false;
	// Validate arguments
	if (set == NULL || filename == NULL)
	{
		return false;
	}

	b = ReadDump(filename);
	if (b == NULL)
	{
		return false;
	}

	ret = ViLoadInfFromBuf(set, b);

	FreeBuf(b);

	return ret;
}

// Get the product information from the Msi
bool ViMsiGetProductInfo(char *product_code, char *name, char *buf, UINT size)
{
	UINT ret;
	char tmp[MAX_SIZE];
	DWORD sz;
	// Validate arguments
	if (product_code == NULL || name == NULL || buf == NULL)
	{
		return false;
	}

	sz = sizeof(tmp);

	ret = MsiGetProductInfoA(product_code, name, tmp, &sz);
	if (ret != ERROR_SUCCESS)
	{
		return false;
	}

	StrCpy(buf, size, tmp);

	return true;
}

// Extract the build number from the version string
UINT ViVersionStrToBuild(char *str)
{
	TOKEN_LIST *t;
	UINT ret;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	t = ParseToken(str, ".");
	if (t == NULL)
	{
		return 0;
	}

	ret = 0;

	if (t->NumTokens == 3)
	{
		ret = ToInt(t->Token[2]);
	}

	FreeToken(t);

	return ret;
}

// Get the current installation state for the given architecture
void ViLoadCurrentInstalledStatusForArch(VI_SETTING_ARCH *a)
{
	char tmp[MAX_SIZE];
	UINT build;
	wchar_t *dir;
	// Validate arguments
	if (a == NULL)
	{
		return;
	}
	if (a->Supported == false)
	{
		// Unsupported
		return;
	}

	// Read from the registry
	Format(tmp, sizeof(tmp), "%s\\%s", SW_REG_KEY, "vpnclient");

	build = MsRegReadIntEx2(REG_LOCAL_MACHINE, tmp, "InstalledBuild", false, true);

	dir = MsRegReadStrEx2W(REG_LOCAL_MACHINE, tmp, "InstalledDir", false, true);

	if (build == 0 || UniIsEmptyStr(dir))
	{
		// Not installed
		a->CurrentInstalled = false;
	}
	else
	{
		// Installed
		a->CurrentInstalled = true;
		a->CurrentInstalledBuild = build;

		UniStrCpy(a->CurrentInstalledPathW, sizeof(a->CurrentInstalledPathW), dir);
	}

	Free(dir);
}

// Get the best architecture for the current CPU
VI_SETTING_ARCH *ViGetSuitableArchForCpu()
{
	return &setting.x86;
}

// Get the current installation state
void ViLoadCurrentInstalledStates()
{
	ViLoadCurrentInstalledStatusForArch(&setting.x86);
}

// Main process
void ViMain()
{
	char tmp[MAX_PATH];
	UINT ostype = GetOsInfo()->OsType;
	VI_SETTING_ARCH *suitable;
	TOKEN_LIST *t;
	UINT i;

	if (OS_IS_WINDOWS_NT(ostype) == false ||
		GET_KETA(ostype, 100) <= 1)
	{
		// The OS is too old
		MsgBox(NULL, MB_ICONEXCLAMATION, _U(IDS_BAD_OS+skip));
		return;
	}

	Zero(&setting, sizeof(setting));

	// Read the inf file
	Format(tmp, sizeof(tmp), "%s\\%s", MsGetExeDirName(), VI_INF_FILENAME);
	if (ViLoadInf(&setting, tmp) == false)
	{
		// Failure
		MsgBoxEx(NULL, MB_ICONSTOP, _U(IDS_INF_LOAD_FAILED+skip), VI_INF_FILENAME);
		return;
	}

	ViSetSkip();

	// Parse the command line options
	t = GetCommandLineToken();

	for (i = 0;i < t->NumTokens;i++)
	{
		char *s = t->Token[i];

		if (IsEmptyStr(s) == false)
		{
			if (StartWith(s, "/") || StartWith(s, "-"))
			{
				if (StrCmpi(&s[1], "web") == 0)
				{
					setting.WebMode = true;
				}
			}
			else
			{
				StrCpy(setting.SettingPath, sizeof(setting.SettingPath), s);
			}
		}
	}

	FreeToken(t);

	suitable = ViGetSuitableArchForCpu();

	// Security check
	if (setting.WebMode)
	{
		bool ok = true;

		if (ViIsInternetFile(suitable->Path) == false)
		{
			ok = false;
		}

		if (IsEmptyStr(setting.SettingPath) == false)
		{
			if (ViIsInternetFile(setting.SettingPath) == false)
			{
				ok = false;
			}
		}

		if (ok == false)
		{
			// Security breach
			MsgBox(NULL, MB_ICONEXCLAMATION, _U(IDS_SECURITY_ERROR+skip));
			return;
		}
	}

	// Get the current installation state
	ViLoadCurrentInstalledStates();

	if (suitable->Supported == false)
	{
		// This CPU isn't supported
		MsgBox(NULL, MB_ICONEXCLAMATION, _U(IDS_CPU_NOT_SUPPORTED+skip));
		return;
	}

	if (suitable->CurrentInstalled && suitable->Build <= suitable->CurrentInstalledBuild)
	{
		// Do not download client software since it has already been installed
		setting.DownloadNotRequired = true;
	}

	// Show the dialog
	ViInstallDlg();
}

// Generate the temporary directory name for vpnsmgr
void ViGenerateVpnSMgrTempDirName(char *name, UINT size, UINT build)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	Format(name, size, "%s\\px_" GC_SW_SOFTETHER_PREFIX "vpnsmgr_%u", MsGetTempDir(), build);
}

// Compare the string resources
int ViCompareString(void *p1, void *p2)
{
	VI_STRING *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	s1 = *(VI_STRING **)p1;
	s2 = *(VI_STRING **)p2;

	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	if (s1->Id > s2->Id)
	{
		return 1;
	}
	else if (s1->Id < s2->Id)
	{
		return -1;
	}
	return 0;
}

// Reading a string resource
wchar_t *ViLoadString(HINSTANCE hInst, UINT id)
{
	wchar_t *ret = NULL;

	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType))
	{
		char *a = ViLoadStringA(hInst, id);
		if (a != NULL)
		{
			ret = CopyStrToUni(a);
			Free(a);
		}
	}
	else
	{
		UINT tmp_size = 60000;
		wchar_t *tmp = Malloc(tmp_size);

		if (LoadStringW(hInst, id, tmp, tmp_size) != 0)
		{
			ret = CopyUniStr(tmp);
		}

		Free(tmp);
	}

	return ret;
}
char *ViLoadStringA(HINSTANCE hInst, UINT id)
{
	UINT tmp_size = 60000;
	char *tmp = Malloc(tmp_size);
	char *ret = NULL;

	if (LoadStringA(hInst, id, tmp, tmp_size) != 0)
	{
		ret = CopyStr(tmp);
	}

	Free(tmp);

	return ret;
}

// Acquisition of string
wchar_t *ViGetString(UINT id)
{
	VI_STRING t, *s;
	wchar_t *ret = NULL;

	Zero(&t, sizeof(t));
	t.Id = id;

	LockList(string_table);
	{
		s = Search(string_table, &t);

		if (s != NULL)
		{
			ret = s->String;
		}
	}
	UnlockList(string_table);

	return ret;
}
char *ViGetStringA(UINT id)
{
	VI_STRING t, *s;
	char *ret = NULL;

	Zero(&t, sizeof(t));
	t.Id = id;

	LockList(string_table);
	{
		s = Search(string_table, &t);

		if (s != NULL)
		{
			ret = s->StringA;
		}
	}
	UnlockList(string_table);

	return ret;
}

// Calculate the difference between the the current language configuration and the base of the string table
void ViSetSkip()
{
	skip = 0;

	if (MsIsCurrentUserLocaleIdJapanese() == false)
	{
		skip = MESSAGE_OFFSET_EN - MESSAGE_OFFSET_JP;
	}
}

// Read the string table
void ViLoadStringTables()
{
	UINT i, n;
	HINSTANCE hInst = GetModuleHandle(NULL);

	string_table = NewList(ViCompareString);

	n = 0;
	for (i = 1;;i++)
	{
		wchar_t *str = ViLoadString(hInst, i);
		if (str != NULL)
		{
			VI_STRING *s;
			n = 0;

			s = ZeroMalloc(sizeof(VI_STRING));
			s->Id = i;
			s->String = str;
			s->StringA = CopyUniToStr(str);

			Insert(string_table, s);
		}
		else
		{
			n++;
			if (n >= 1500)
			{
				break;
			}
		}
	}
}

// Release the string table
void ViFreeStringTables()
{
	UINT i;
	if (string_table == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(string_table);i++)
	{
		VI_STRING *s = LIST_DATA(string_table, i);

		Free(s->String);
		Free(s->StringA);
		Free(s);
	}

	ReleaseList(string_table);
	string_table = NULL;
}

// WinMain function
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	INSTANCE *instance;
	is_debug = false;
	MayaquaMinimalMode();
	InitMayaqua(false, is_debug, 0, NULL);
	InitCedar();
	ViSetSkip();
	ViLoadStringTables();
	InitWinUi(_U(IDS_TITLE+skip), _A(IDS_FONT+skip), ToInt(_A(IDS_FONT_SIZE+skip)));
	instance = NewSingleInstance(VI_INSTANCE_NAME);
	if (instance == NULL)
	{
		MsgBox(NULL, MB_ICONINFORMATION, _U(IDS_INSTANCE_EXISTS+skip));
	}
	else
	{
		ViMain();
		FreeSingleInstance(instance);
		if (sleep_before_exit)
		{
			SleepThread(60 * 1000);
		}
	}
	FreeWinUi();
	ViFreeStringTables();
	FreeCedar();
	FreeMayaqua();
	return 0;
}



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
