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


// vpninstall.h
// Header of vpninstall.c

#ifndef	VPNINSTALL_H
#define	VPNINSTALL_H

// Constants
#define	VI_INF_FILENAME				"vpninstall.inf"
#define VI_INSTANCE_NAME			"VpnAutoInstaller"
#define	WM_VI_SETPOS				(WM_APP + 41)
#define WM_VI_SETTEXT				(WM_APP + 42)
#define WM_VI_CANCEL				(WM_APP + 43)
#define WM_VI_DOWNLOAD_FINISHED		(WM_APP + 44)
#define MESSAGE_OFFSET_JP  IDS_TITLE
#define MESSAGE_OFFSET_EN  IDS_TITLE_EN

// Macro
#define _U(id)		(ViGetString(id))
#define	_A(id)		(ViGetStringA(id))


// Type declaration
typedef struct VI_STRING
{
	UINT Id;
	wchar_t *String;
	char *StringA;
} VI_STRING;

typedef struct VI_SETTING_ARCH
{
	bool Supported;
	UINT Build;
	char Path[MAX_SIZE];
	char VpnCMgrExeFileName[MAX_PATH];
	bool CurrentInstalled;
	wchar_t CurrentInstalledPathW[MAX_PATH];
	UINT CurrentInstalledBuild;
} VI_SETTING_ARCH;

typedef struct VI_SETTING
{
	UINT VpnInstallBuild;
	VI_SETTING_ARCH x86;
	char SettingPath[MAX_SIZE];
	wchar_t DownloadedSettingPathW[MAX_PATH];
	wchar_t DownloadedInstallerPathW[MAX_PATH];
	bool DownloadNotRequired;
	bool WebMode;
	bool NormalMode;
} VI_SETTING;

typedef struct VI_INSTALL_DLG
{
	HWND hWnd;
	bool DownloadStarted;
	THREAD *DownloadThread;
	bool DialogCanceling;
	UINT BufSize;
	void *Buf;
	bool Halt;
	bool NoClose;
	bool WindowsShutdowning;
} VI_INSTALL_DLG;

typedef struct VI_FILE
{
	bool InternetFile;
	UINT FileSize;
	HINTERNET hInternet;
	HINTERNET hHttpFile;
	UINT IoReadFileSize;
	IO *io;
} VI_FILE;

typedef struct VI_DOWNLOAD_FILE
{
	char SrcPath[MAX_SIZE];
	char FileName[MAX_PATH];
	wchar_t DestPathW[MAX_SIZE];
} VI_DOWNLOAD_FILE;

// Function prototype
int main(int argc, char *argv[]);
void ViLoadStringTables();
void ViFreeStringTables();
wchar_t *ViLoadString(HINSTANCE hInst, UINT id);
char *ViLoadStringA(HINSTANCE hInst, UINT id);
int ViCompareString(void *p1, void *p2);
wchar_t *ViGetString(UINT id);
char *ViGetStringA(UINT id);
void ViMain();
bool ViLoadInf(VI_SETTING *set, char *filename);
bool ViLoadInfFromBuf(VI_SETTING *set, BUF *buf);
void ViLoadCurrentInstalledStates();
void ViLoadCurrentInstalledStatusForArch(VI_SETTING_ARCH *a);
bool ViMsiGetProductInfo(char *product_code, char *name, char *buf, UINT size);
UINT ViVersionStrToBuild(char *str);
VI_SETTING_ARCH *ViGetSuitableArchForCpu();
void ViInstallDlg();
UINT ViInstallDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void ViInstallDlgOnInit(HWND hWnd, VI_INSTALL_DLG *d);
void ViInstallDlgOnStart(HWND hWnd, VI_INSTALL_DLG *d);
void ViInstallDlgOnClose(HWND hWnd, VI_INSTALL_DLG *d);
VI_FILE *ViOpenFile(char *path);
UINT ViGetFileSize(VI_FILE *f);
UINT ViReadFile(VI_FILE *f, void *buf, UINT size);
void ViCloseFile(VI_FILE *f);
bool ViIsInternetFile(char *path);
void ViDownloadThreadStart(VI_INSTALL_DLG *d);
void ViDownloadThreadStop(VI_INSTALL_DLG *d);
void ViDownloadThread(THREAD *thread, void *param);
void ViInstallDlgSetPos(HWND hWnd, UINT pos);
void ViInstallDlgSetText(VI_INSTALL_DLG *d, HWND hWnd, UINT id,wchar_t *text);
void ViInstallDlgCancel(HWND hWnd);
void ViInstallProcessStart(HWND hWnd, VI_INSTALL_DLG *d);
bool ViExtractCabinetFile(char *exe, char *cab);
wchar_t *ViExtractEula(char *exe);
BUF *ViExtractResource(char *exe, char *type, char *name);
bool ViEulaDlg(HWND hWnd, wchar_t *text);
UINT ViEulaDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool ViCheckExeSign(HWND hWnd, wchar_t *exew);
char *ViUrlToFileName(char *url);
void ViGenerateVpnSMgrTempDirName(char *name, UINT size, UINT build);
void ViSetSkip();

#endif	// VPNINSTALL_H


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
