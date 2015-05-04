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


// SWInner.h
// Header of SW.c (for internal use)

#ifndef	SW_INNER_H
#define	SW_INNER_H

// Component string
#define	SW_NAME_VPNSERVER			"vpnserver"
#define	SW_LONG_VPNSERVER			_UU("SW_LONG_VPNSERVER")

#define	SW_NAME_VPNCLIENT			"vpnclient"
#define	SW_LONG_VPNCLIENT			_UU("SW_LONG_VPNCLIENT")

#define	SW_NAME_VPNBRIDGE			"vpnbridge"
#define	SW_LONG_VPNBRIDGE			_UU("SW_LONG_VPNBRIDGE")

#define	SW_NAME_VPNSMGR				"vpnsmgr"
#define	SW_LONG_VPNSMGR				_UU("SW_LONG_VPNSMGR")

#define	SW_NAME_VPNCMGR				"vpncmgr"
#define	SW_LONG_VPNCMGR				_UU("SW_LONG_VPNCMGR")

#define	SW_VPN_CLIENT_UIHELPER_REGVALUE	GC_SW_UIHELPER_REGVALUE

#define	SW_VPN_CLIENT_EXT_REGKEY	"SOFTWARE\\Classes\\.vpn"
#define	SW_VPN_CLIENT_EXT_REGVALUE	"vpnfile"
#define	SW_VPN_CLIENT_EXT_REGKEY_SUB1	"SOFTWARE\\Classes\\.vpn\\vpnfile"
#define	SW_VPN_CLIENT_EXT_REGKEY_SUB2	"SOFTWARE\\Classes\\.vpn\\vpnfile\\ShellNew"

#define	SW_VPN_CLIENT_VPNFILE_REGKEY	"SOFTWARE\\Classes\\vpnfile"
#define	SW_VPN_CLIENT_VPNFILE_REGVALUE	"VPN Client Connection Setting File"
#define	SW_VPN_CLIENT_VPNFILE_ICON_REGKEY	"SOFTWARE\\Classes\\vpnfile\\DefaultIcon"
#define	SW_VPN_CLIENT_VPNFILE_SHELLOPEN_CMD_REGKEY	"SOFTWARE\\Classes\\vpnfile\\shell\\open\\command"
#define	SW_VPN_CLIENT_VPNFILE_SHELLOPEN_CMD_REGKEY_SUB1	"SOFTWARE\\Classes\\vpnfile\\shell\\open"
#define	SW_VPN_CLIENT_VPNFILE_SHELLOPEN_CMD_REGKEY_SUB2	"SOFTWARE\\Classes\\vpnfile\\shell"

#define	SW_REG_KEY_EULA					"Software\\" GC_REG_COMPANY_NAME "\\Setup Wizard Settings\\Eula"


// Component ID
#define	SW_CMP_VPN_SERVER			1	// VPN Server
#define	SW_CMP_VPN_CLIENT			2	// VPN Client
#define	SW_CMP_VPN_BRIDGE			3	// VPN Bridge
#define	SW_CMP_VPN_SMGR				4	// VPN Server Manager (Tools Only)
#define	SW_CMP_VPN_CMGR				5	// VPN Client Manager (Tools Only)

// Exit code
#define	SW_EXIT_CODE_USER_CANCEL			1000000001		// Cancel by the user
#define	SW_EXIT_CODE_INTERNAL_ERROR			1000000002		// Internal error

// Special messages to be used in the setup wizard
#define	WM_SW_BASE						(WM_APP + 251)
#define	WM_SW_INTERACT_UI				(WM_SW_BASE + 0)	// UI processing
#define	WM_SW_EXIT						(WM_SW_BASE + 1)	// Close

// Automatic connection setting file
#define	SW_AUTO_CONNECT_ACCOUNT_FILE_NAME	"auto_connect.vpn"
#define	SW_AUTO_CONNECT_ACCOUNT_FILE_NAME_W	L"auto_connect.vpn"

// Installer cache file to be stored in the VPN Client installation folder
#define	SW_SFX_CACHE_FILENAME				L"installer.cache"

// Flag file
#define	SW_FLAG_EASY_MODE					"easy_mode.flag"
#define	SW_FLAG_EASY_MODE_2					"@easy_mode.flag"

// Multiple-starts prevention name
#define	SW_SINGLE_INSTANCE_NAME				"SoftEther_VPN_Setup_Wizard"

// Time to wait for the VPN Client service startup
#define	SW_VPNCLIENT_SERVICE_WAIT_READY_TIMEOUT		(30 * 1000)

// UI interaction
typedef struct SW_UI
{
	UINT Type;							// Type
	wchar_t *Message;					// Message string
	UINT Param;							// Parameters
	UINT RetCode;						// Return value
} SW_UI;

// Type of UI interaction
#define	SW_UI_TYPE_PRINT				0	// Display the message
#define	SW_UI_TYPE_MSGBOX				1	// Show a message box
#define	SW_UI_TYPE_FINISH				2	// Completion
#define	SW_UI_TYPE_ERROR				3	// Error

// Resource type of the file stored in the setup.exe
#define	SW_SFX_RESOURCE_TYPE			"DATAFILE"

// Code of old MSI
typedef struct SW_OLD_MSI
{
	char *ProductCode;						// Product code
	char *ComponentCode;					// Component code
} SW_OLD_MSI;

// Component
typedef struct SW_COMPONENT
{
	UINT Id;							// ID
	bool Detected;						// Whether it has been detected as an installation source
	LIST *NeedFiles;					// Necessary files
	char *Name;							// Internal name
	char *SvcName;						// Service name
	wchar_t *Title;						// Display name
	wchar_t *Description;				// Detail
	wchar_t *DefaultDirName;			// Installation directory name of the default
	wchar_t *LongName;					// Long name
	UINT Icon;							// Icon
	UINT IconExeIndex;					// The index number of the icon within the Setup.exe
	bool SystemModeOnly;				// Only system mode
	bool InstallService;				// Installation of service
	wchar_t *SvcFileName;				// Service file name
	wchar_t *StartExeName;				// Start EXE file name
	wchar_t *StartDescription;			// Description of the running software
	SW_OLD_MSI *OldMsiList;				// Old MSI Product List
	UINT NumOldMsi;						// The number of old MSI Product List
	bool CopyVGDat;						// Copy of the VPN Gate DAT file
} SW_COMPONENT;

// File copy task
typedef struct SW_TASK_COPY
{
	wchar_t SrcFileName[MAX_SIZE];		// Original file name
	wchar_t DstFileName[MAX_SIZE];		// Destination file name
	wchar_t SrcDir[MAX_SIZE];			// Source directory
	wchar_t DstDir[MAX_SIZE];			// Destination directory
	bool Overwrite;						// Override flag
	bool SetupFile;						// Setup file flag
} SW_TASK_COPY;

// Link creation task
typedef struct SW_TASK_LINK
{
	wchar_t TargetDir[MAX_SIZE];		// Target directory
	wchar_t TargetExe[MAX_SIZE];		// Target EXE file name
	wchar_t TargetArg[MAX_SIZE];		// Arguments to pass to the target
	wchar_t IconExe[MAX_SIZE];			// Icon EXE file name
	UINT IconIndex;						// Icon Index number
	wchar_t DestDir[MAX_SIZE];			// Directory name to be created
	wchar_t DestName[MAX_SIZE];			// File name to be created
	wchar_t DestDescription[MAX_SIZE];	// Description string
	bool NoDeleteDir;					// Do not delete the directory on uninstall
} SW_TASK_LINK;

// Setup Tasks
typedef struct SW_TASK
{
	LIST *CopyTasks;					// File copy task
	LIST *SetSecurityPaths;				// List of paths to set the security
	LIST *LinkTasks;					// Link creation task
} SW_TASK;

// Setup log
typedef struct SW_LOG
{
	UINT Type;							// Type of log
	wchar_t Path[MAX_PATH];				// Path
} SW_LOG;

// Type of setup log
#define	SW_LOG_TYPE_FILE				1	// File
#define	SW_LOG_TYPE_DIR					2	// Directory
#define	SW_LOG_TYPE_REGISTRY			3	// Registry
#define	SW_LOG_TYPE_LNK					4	// Shortcut file
#define	SW_LOG_TYPE_LNK_DIR				5	// Shortcut directory
#define	SW_LOG_TYPE_SVC					6	// Service

// Setup log files
typedef struct SW_LOGFILE
{
	LIST *LogList;							// List of log
	bool IsSystemMode;						// Whether the system mode
	UINT Build;								// Build Number
	SW_COMPONENT *Component;				// Component
} SW_LOGFILE;

// SFX file
typedef struct SW_SFX_FILE
{
	char InnerFileName[MAX_PATH];				// Internal file name
	wchar_t DiskFileName[MAX_PATH];				// File name of the disk
} SW_SFX_FILE;

// SW instance
typedef struct SW
{
	LIST *ComponentList;				// List of components
	wchar_t InstallSrc[MAX_SIZE];		// Source directory
	bool IsSystemMode;					// Whether the system mode
	bool UninstallMode;					// Uninstall mode
	UINT ExitCode;						// Exit code
	void *ReExecProcessHandle;			// Child process handle of a result of the re-run itself
	bool IsReExecForUac;				// Whether the process was re-run for UAC handling
	SW_COMPONENT *CurrentComponent;		// Component that is currently selected
	bool EulaAgreed;					// Whether the user accepted the license agreement
	bool DoubleClickBlocker;			// Double-click blocker
	bool LanguageMode;					// Language setting mode
	UINT LangId;						// Language ID in the language setting mode
	bool SetLangAndReboot;				// Prompt to restart after making the language setting
	bool LangNow;						// Start the language setting process right now
	bool EasyMode;						// Simple installer creation mode
	bool WebMode;						// Web installer creation mode
	bool OnlyAutoSettingMode;			// Apply only mode of connection settings of VPN Client

	INSTANCE *Single;					// Multiple-starts check
	wchar_t DefaultInstallDir_System[MAX_PATH];		// Default system installation directory
	wchar_t DefaultInstallDir_User[MAX_PATH];		// Default user installation directory
	bool IsAvailableSystemMode;			// Whether the system mode is selectable
	bool IsAvailableUserMode;			// Whether the user mode is selectable
	bool ShowWarningForUserMode;		// Whether to display a warning for the user-mode
	wchar_t InstallDir[MAX_PATH];		// Destination directory
	THREAD *PerformThread;				// Set up processing thread
	bool Run;							// Whether to start the tool after Setup finishes
	SW_LOGFILE *LogFile;				// Log file
	bool MsiRebootRequired;				// Need to be re-started as a result of MSI
	bool LangNotChanged;				// Language has not changed
	wchar_t FinishMsg[MAX_SIZE * 2];	// Completion message
	wchar_t Easy_SettingFile[MAX_PATH];	// Connection settings file name of the Simple installer creation kit:
	wchar_t Easy_OutFile[MAX_PATH];		// Destination file name of the simple installer creation kit
	bool Easy_EraseSensitive;			// Simple installer creation kit: Delete the confidential information
	bool Easy_EasyMode;					// Simple installer creation kit: simple mode
	wchar_t Web_SettingFile[MAX_PATH];	// Connection setting file name for the Web installer creation Kit
	wchar_t Web_OutFile[MAX_PATH];		// Destination file name of the Web installer creation Kit
	bool Web_EraseSensitive;			// Web installer creation Kit: removing confidential information
	bool Web_EasyMode;					// Web installer creation kit: simple mode
	wchar_t vpncmgr_path[MAX_PATH];		// Path of vpncmgr.exe
	wchar_t auto_setting_path[MAX_PATH];	// Path of automatic connection setting
	bool HideStartCommand;				// Not to show the option to start the program on installation complete screen
	char SfxMode[MAX_SIZE];				// SFX generation mode
	wchar_t SfxOut[MAX_PATH];			// SFX destination
	wchar_t CallerSfxPath[MAX_PATH];	// Calling SFX path
	bool IsEasyInstaller;				// Whether the calling SFX was built by the simple installer creation kit
	bool IsWebInstaller;				// Whether Web installer
	bool DisableAutoImport;				// Not to use the automatic import process
	bool SuInstMode;					// SuInst mode
	UINT CurrentEulaHash;				// Hash of the license agreement
} SW;


// Function prototype
SW *NewSw();
UINT FreeSw(SW *sw);

void SwDefineComponents(SW *sw);
SW_COMPONENT *SwNewComponent(char *name, char *svc_name, UINT id, UINT icon, UINT icon_index, wchar_t *svc_filename,
							 wchar_t *long_name, bool system_mode_only, UINT num_files, char *files[],
							 wchar_t *start_exe_name, wchar_t *start_description,
							 SW_OLD_MSI *old_msis, UINT num_old_msis);
void SwFreeComponent(SW_COMPONENT *c);
void SwDetectComponents(SW *sw);
bool SwIsComponentDetected(SW *sw, SW_COMPONENT *c);
void SwParseCommandLine(SW *sw);
SW_COMPONENT *SwFindComponent(SW *sw, char *name);

void SwInitDefaultInstallDir(SW *sw);
void SwUiMain(SW *sw);
bool SwCheckNewDirName(wchar_t *name);
wchar_t *SwGetOldMsiInstalledDir(SW_COMPONENT *c);
bool SwUninstallOldMsiInstalled(HWND hWnd, WIZARD_PAGE *wp, SW_COMPONENT *c, bool *reboot_required);

bool SwReExecMyself(SW *sw, wchar_t *additional_params, bool as_admin);

SW_TASK *SwNewTask();
void SwFreeTask(SW_TASK *t);
SW_TASK_COPY *SwNewCopyTask(wchar_t *srcfilename, wchar_t *dstfilename, wchar_t *srcdir, wchar_t *dstdir, bool overwrite, bool setup_file);
void SwFreeCopyTask(SW_TASK_COPY *ct);
void SwDefineTasks(SW *sw, SW_TASK *t, SW_COMPONENT *c);
SW_TASK_LINK *SwNewLinkTask(wchar_t *target_dir, wchar_t *target_exe, wchar_t *target_arg,
							wchar_t *icon_exe, UINT icon_index,
							wchar_t *dest_dir, wchar_t *dest_name, wchar_t *dest_desc,
							bool no_delete_dir);
void SwFreeLinkTask(SW_TASK_LINK *lt);

void SwAddLog(SW *sw, SW_LOGFILE *logfile, UINT type, wchar_t *path);
void SwAddLogA(SW *sw, SW_LOGFILE *logfile, UINT type, char *path);
bool SwSaveLogFile(SW *sw, wchar_t *dst_name, SW_LOGFILE *logfile);
SW_LOGFILE *SwLoadLogFile(SW *sw, wchar_t *filename);
SW_LOGFILE *SwNewLogFile();
void SwFreeLogFile(SW_LOGFILE *logfile);

void SwInstallShortcuts(SW *sw, WIZARD_PAGE *wp, SW_COMPONENT *c, SW_TASK *t);
void SwDeleteShortcuts(SW_LOGFILE *logfile);

bool SwCheckOs(SW *sw, SW_COMPONENT *c);

bool SwEnterSingle(SW *sw);
void SwLeaveSingle(SW *sw);

UINT SwWelcomeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwModeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwNotAdminDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwComponents(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwComponentsInit(HWND hWnd, SW *sw);
void SwComponentsUpdate(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page);
UINT SwEula(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwEulaUpdate(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page);
UINT SwDir(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwDirUpdate(HWND hWnd, SW *sw, WIZARD_PAGE *wizard_page);
UINT SwReady(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwPerform(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwPerformInit(HWND hWnd, SW *sw, WIZARD_PAGE *wp);
void SwPerformThread(THREAD *thread, void *param);
void SwPerformPrint(WIZARD_PAGE *wp, wchar_t *str);
UINT SwPerformMsgBox(WIZARD_PAGE *wp, UINT flags, wchar_t *msg);
UINT SwInteractUi(WIZARD_PAGE *wp, SW_UI *ui);
void SwInteractUiCalled(HWND hWnd, SW *sw, WIZARD_PAGE *wp, SW_UI *ui);
bool SwInstallMain(SW *sw, WIZARD_PAGE *wp, SW_COMPONENT *c);
UINT SwError(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwFinish(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwUninst1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
bool SwUninstallMain(SW *sw, WIZARD_PAGE *wp, SW_COMPONENT *c);
UINT SwLang1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwLang1Init(HWND hWnd, SW *sw);
UINT SwGetLangIcon(char *name);
void SwLang1Update(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page);
UINT SwEasy1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwEasy2(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwEasy2Update(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page);
bool SwEasyMain(SW *sw, WIZARD_PAGE *wp);
UINT SwWeb1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
UINT SwWeb2(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param);
void SwWeb2Update(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page);
bool SwWebMain(SW *sw, WIZARD_PAGE *wp);


void SwGenerateDefaultSfxFileName(wchar_t *name, UINT size);
void SwGenerateDefaultZipFileName(wchar_t *name, UINT size);

bool CALLBACK SwEnumResourceNamesProc(HMODULE hModule, const char *type, char *name, LONG_PTR lParam);

UINT SwSfxModeMain();
bool CALLBACK SfxModeMainDialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
bool SwSfxExtractProcess(HWND hWnd, bool *hide_error_msg);
bool SwSfxExtractFile(HWND hWnd, void *data, UINT size, wchar_t *dst, bool compressed);
SW_SFX_FILE *SwNewSfxFile(char *inner_file_name, wchar_t *disk_file_name);
bool SwSfxCopyVgFiles(HWND hWnd, wchar_t *src, wchar_t *dst);

#endif	// SW_INNER_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
