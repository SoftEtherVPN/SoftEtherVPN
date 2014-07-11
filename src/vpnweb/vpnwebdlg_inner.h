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


// vpnwebdlg.h
// Header of vpnwebdlg.c (Inner)


#define	VPNINSTALL_EXE_FILENAME		"vpninstall.exe"
#define	VPNINSTALL_EXE_FILENAME_TMP	"vpninstall.exe.tmp"
#define VPNINSTALL_INF_FILENAME		"vpninstall.inf"
#define VPNINSTALL_INF_BUILDTAG		"VpnInstallBuild"

#include "resource.h"
extern HINSTANCE hDllInstance;
#define MESSAGE_OFFSET_JP  IDS_MESSAGE_APPTITLE
#define MESSAGE_OFFSET_EN  IDS_MESSAGE_APPTITLE_EN
#define MESSAGE_OFFSET_RES1 12000
#define MESSAGE_OFFSET_RES2 13000

static wchar_t *msgAppTitle = NULL;
static char *msgNotSupported = NULL;
static wchar_t *msgInfDownloag = NULL;
static wchar_t *msgInfDownloadFailed = NULL;
static wchar_t *msgBadInfFile = NULL;
static wchar_t *msgWriteFailed = NULL;
static wchar_t *msgDownloading = NULL;
static wchar_t *msgProcessFailed = NULL;
static wchar_t *msgProcessCreating =NULL;
static wchar_t *msgProcessCreated = NULL;
static wchar_t *msgWarning = NULL;
static wchar_t *msgWarningTitle = NULL;
static wchar_t *msgUserCancal = NULL;
static wchar_t *msgStartTextForVpnServer = NULL;
static wchar_t *msgButtonForVpnServer = NULL;
static wchar_t *msgProcessCreatedForVpnServer = NULL;
static wchar_t *msgStartTextForVpnClient = NULL;
static wchar_t *msgButtonForVpnClient = NULL;
static char *msgNoParam = NULL;

static void **_messages;

typedef enum MessageType {
	_e_msgAppTitle,_e_msgNotSupported,_e_msgInfDownloag,_e_msgInfDownloadFailed,
	_e_msgBadInfFile,_e_msgWriteFailed,_e_msgDownloading,_e_msgProcessFailed,
	_e_msgProcessCreating,_e_msgProcessCreated,_e_msgWarning,_e_msgWarningTitle,
	_e_msgUserCancal,_e_msgStartTextForVpnServer,_e_msgButtonForVpnServer,_e_msgProcessCreatedForVpnServer,
	_e_msgNoParam, _e_msgStartTextForVpnClient, _e_msgButtonForVpnClient, _e_msgEnd} MessageType_t;

	int currentPage=MESSAGE_OFFSET_EN;

int GetLocalizedMessageOffset(){
	return currentPage;
}
wchar_t *LoadMessageW(enum MessageType e){
	wchar_t *pTmp=(wchar_t*)calloc(sizeof(wchar_t),1024);
	LoadStringW(hDllInstance,GetLocalizedMessageOffset()+e,pTmp,1024);
	return pTmp;
}
char *LoadMessageA(enum MessageType e){
	char *pTmp=(char*)calloc(sizeof(char),1024);
	LoadStringA(hDllInstance,GetLocalizedMessageOffset()+e,pTmp,1024);
	return pTmp;
}
void FreeMessage(void *p){
	free(p);
}
int LoadTables(char *pTag){
	if( stricmp(pTag,"JP")==0 || stricmp(pTag,"JA")==0){
		currentPage=MESSAGE_OFFSET_JP;
		
	}else if( stricmp(pTag,"EN")==0)
	{
		currentPage=MESSAGE_OFFSET_EN;
	}
//		currentPage=MESSAGE_OFFSET_EN;

	msgAppTitle=LoadMessageW(_e_msgAppTitle);
	msgNotSupported=LoadMessageA(_e_msgNotSupported);
	msgInfDownloag=LoadMessageW(_e_msgInfDownloag);
	msgInfDownloadFailed=LoadMessageW(_e_msgInfDownloadFailed);
	msgBadInfFile=LoadMessageW(_e_msgBadInfFile);
	msgWriteFailed=LoadMessageW(_e_msgWriteFailed);
	msgDownloading=LoadMessageW(_e_msgDownloading);
	msgProcessFailed=LoadMessageW(_e_msgProcessFailed);
	msgProcessCreating=LoadMessageW(_e_msgProcessCreating);
	msgProcessCreated=LoadMessageW(_e_msgProcessCreated);
	msgWarning=LoadMessageW(_e_msgWarning);
	msgWarningTitle=LoadMessageW(_e_msgWarningTitle);
	msgUserCancal=LoadMessageW(_e_msgUserCancal);
	msgStartTextForVpnServer=LoadMessageW(_e_msgStartTextForVpnServer);
	msgButtonForVpnServer=LoadMessageW(_e_msgButtonForVpnServer);
	msgProcessCreatedForVpnServer=LoadMessageW(_e_msgProcessCreatedForVpnServer);
	msgNoParam=LoadMessageA(_e_msgNoParam);
	msgStartTextForVpnClient=LoadMessageW(_e_msgStartTextForVpnClient);
	msgButtonForVpnClient=LoadMessageW(_e_msgButtonForVpnClient);
	return 0;

}

#define false		0
#define true		1
#define	bool		UINT
#define MAX_SIZE	512

typedef struct VW_FILE
{
	UINT FileSize;
	HINTERNET hInternet;
	HINTERNET hHttpFile;
} VW_FILE;

typedef struct VW_TASK
{
	HANDLE Thread;
	bool Halt;
} VW_TASK;


INT_PTR CALLBACK VpnWebDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK VpnWebDummyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

void VwOnInit(HWND hWnd);
void VwOnFree(HWND hWnd);
HANDLE VwNewThread(LPTHREAD_START_ROUTINE start, void *param);
void VwFreeThread(HANDLE h);
void VwCloseFile(VW_FILE *f);
UINT VwReadFile(VW_FILE *f, void *buf, UINT size);
UINT VwGetFileSize(VW_FILE *f);
VW_FILE *VwOpenFile(char *path);
void VwPrint(HWND hWnd, wchar_t *str);
DWORD CALLBACK VwTaskThread(void *param);
char *VwUrlToFileName(char *url);
UINT VwGetBuildFromVpnInstallInf(char *buf);
bool VwCheckFileDigitalSignature(HWND hWnd, char *name, bool *danger);
bool VwCheckExeSign(HWND hWnd, char *exe);

void *ZeroMalloc(UINT size);
void Free(void *p);
void *ReAlloc(void *p, UINT size);
void Zero(void *p, UINT size);
HANDLE FileCreate(char *name);
HANDLE FileOpen(char *name, bool write_mode);
void FileClose(HANDLE h);
bool FileRead(HANDLE h, void *buf, UINT size);
bool FileWrite(HANDLE h, void *buf, UINT size);
UINT64 FileSize(HANDLE h);
bool MakeDir(char *name);
UINT MsgBox(HWND hWnd, UINT flag, wchar_t *msg);
void Hide(HWND hWnd, UINT id);
void Show(HWND hWnd, UINT id);
void SetShow(HWND hWnd, UINT id, bool b);
bool IsShow(HWND hWnd, UINT id);
bool IsHide(HWND hWnd, UINT id);
void RemoveExStyle(HWND hWnd, UINT id, UINT style);
void SetExStyle(HWND hWnd, UINT id, UINT style);
UINT GetExStyle(HWND hWnd, UINT id);
void RemoveStyle(HWND hWnd, UINT id, UINT style);
void SetStyle(HWND hWnd, UINT id, UINT style);
UINT GetStyle(HWND hWnd, UINT id);
void Refresh(HWND hWnd);
void DoEvents(HWND hWnd);
void Disable(HWND hWnd, UINT id);
void Enable(HWND hWnd, UINT id);
void SetEnable(HWND hWnd, UINT id, bool b);
bool IsDisable(HWND hWnd, UINT id);
bool IsEnable(HWND hWnd, UINT id);
HWND DlgItem(HWND hWnd, UINT id);
bool IsSupportedOs();
void SetText(HWND hWnd, UINT id, wchar_t *str);
UINT SendMsg(HWND hWnd, UINT id, UINT msg, WPARAM wParam, LPARAM lParam);
void SetRange(HWND hWnd, UINT id, UINT start, UINT end);
void SetPos(HWND hWnd, UINT id, UINT pos);



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
