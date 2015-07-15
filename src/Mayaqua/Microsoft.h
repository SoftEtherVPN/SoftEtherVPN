// SoftEther VPN Source Code
// Mayaqua Kernel
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


// Microsoft.h
// Header of Microsoft.c

#ifdef	OS_WIN32

// Make available the types for Windows even if windows.h is not included
#ifndef	_WINDEF_

typedef void *HWND;

#endif	// _WINDEF_

#ifndef	MICROSOFT_H
#define	MICROSOFT_H


// Constant for Event log
#define	MS_EVENTLOG_TYPE_INFORMATION		0
#define	MS_EVENTLOG_TYPE_WARNING			1
#define	MS_EVENTLOG_TYPE_ERROR				2

#define	MS_RC_EVENTLOG_TYPE_INFORMATION		0x40000001L
#define	MS_RC_EVENTLOG_TYPE_WARNING			0x80000002L
#define	MS_RC_EVENTLOG_TYPE_ERROR			0xC0000003L


// TCP/IP registry value
#define	TCP_MAX_NUM_CONNECTIONS				16777214

#define	DEFAULT_TCP_MAX_WINDOW_SIZE_RECV	5955584
#define	DEFAULT_TCP_MAX_WINDOW_SIZE_SEND	131072
#define	DEFAULT_TCP_MAX_NUM_CONNECTIONS		16777214

// Constant
#define	SVC_ARG_INSTALL				"/install"
#define	SVC_ARG_UNINSTALL			"/uninstall"
#define	SVC_ARG_START				"/start"
#define	SVC_ARG_STOP				"/stop"
#define	SVC_ARG_TEST				"/test"
#define	SVC_ARG_USERMODE			"/usermode"
#define	SVC_ARG_USERMODE_SHOWTRAY	"/usermode_showtray"
#define	SVC_ARG_USERMODE_HIDETRAY	"/usermode_hidetray"
#define	SVC_ARG_SERVICE				"/service"
#define	SVC_ARG_SETUP_INSTALL		"/setup_install"
#define	SVC_ARG_SETUP_UNINSTALL		"/setup_uninstall"
#define	SVC_ARG_WIN9X_SERVICE		"/win9x_service"
#define	SVC_ARG_WIN9X_INSTALL		"/win9x_install"
#define	SVC_ARG_WIN9X_UNINSTALL		"/win9x_uninstall"
#define	SVC_ARG_TCP					"/tcp"
#define	SVC_ARG_TCP_UAC				"/tcp_uac"
#define	SVC_ARG_TCP_UAC_W			L"/tcp_uac"
#define	SVC_ARG_TCP_SETUP			"/tcpsetup"
#define	SVC_ARG_TRAFFIC				"/traffic"
#define	SVC_ARG_UIHELP				"/uihelp"
#define	SVC_ARG_UIHELP_W			L"/uihelp"
#define SVC_ARG_SILENT				"/silent"

// Time to suicide, if the service freezed
#define	SVC_SELFKILL_TIMEOUT		(5 * 60 * 1000)

// The name of the device driver of the virtual LAN card for Win32 (first part)
#define	VLAN_ADAPTER_NAME			"VPN Client Adapter"
#define	VLAN_ADAPTER_NAME_OLD		"SoftEther VPN Client 2.0 Adapter"

// The name of the device driver of the virtual LAN card for Win32 (full name)
#define	VLAN_ADAPTER_NAME_TAG		"VPN Client Adapter - %s"
#define	VLAN_ADAPTER_NAME_TAG_OLD	"SoftEther VPN Client 2.0 Adapter - %s"

// Display name of Virtual LAN card in the [Network Connections] in Win32 (full name)
#define	VLAN_CONNECTION_NAME		"%s - VPN Client"
#define	VLAN_CONNECTION_NAME_OLD	"%s - SoftEther VPN Client 2.0"


// Suspend handler windows class name
#define	MS_SUSPEND_HANDLER_WNDCLASSNAME	"MS_SUSPEND_HANDLER"

// Command line format in the service mode
#define	SVC_RUN_COMMANDLINE			L"\"%s\" /service"

// Mode value
#define	SVC_MODE_NONE				0
#define	SVC_MODE_INSTALL			1
#define	SVC_MODE_UNINSTALL			2
#define	SVC_MODE_START				3
#define	SVC_MODE_STOP				4
#define	SVC_MODE_TEST				5
#define	SVC_MODE_USERMODE			6
#define	SVC_MODE_SERVICE			7
#define	SVC_MODE_SETUP_INSTALL		8
#define	SVC_MODE_SETUP_UNINSTALL	9
#define	SVC_MODE_WIN9X_SERVICE		10
#define	SVC_MODE_WIN9X_INSTALL		11
#define	SVC_MODE_WIN9X_UNINSTALL	12
#define	SVC_MODE_TCP				13
#define	SVC_MODE_TCPSETUP			14
#define	SVC_MODE_TRAFFIC			15
#define	SVC_MODE_UIHELP				16
#define	SVC_MODE_TCP_UAC			17


#define	WIN9X_SVC_REGKEY_1			"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
#define	WIN9X_SVC_REGKEY_2			"Software\\Microsoft\\Windows\\CurrentVersion\\Run"

#define	VISTA_MMCSS_KEYNAME			"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks"
#define	VISTA_MMCSS_FILENAME		"mmcss_backup.dat"

#define	SVC_NAME					"SVC_%s_NAME"
#define	SVC_TITLE					"SVC_%s_TITLE"
#define	SVC_DESCRIPT				"SVC_%s_DESCRIPT"

#define	SVC_USERMODE_SETTING_KEY	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\UserMode Settings"
#define	SVC_HIDETRAY_REG_VALUE		"HideTray_%S"

#define	SVC_CALLING_SM_PROCESS_ID_KEY	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\Service Control\\%s"
#define SVC_CALLING_SM_PROCESS_ID_VALUE	"ProcessId"

#define	SOFTETHER_FW_SCRIPT_HASH	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\FW ScriptHash"

#define	MMCSS_PROFILE_KEYNAME		"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile"

// Other constants
#define	MS_REG_TCP_SETTING_KEY		"Software\\" GC_REG_COMPANY_NAME "\\Network Settings"



// Constants about driver
#define	DRIVER_INSTALL_SYS_NAME_TAG_NEW	"Neo_%04u.sys"
#define	DRIVER_INSTALL_SYS_NAME_TAG_MAXID	128				// Maximum number of install


// Vista driver installer related
#define	VISTA_DRIVER_INSTALLER_SRC	L"|driver_installer.exe"
#define	VISTA_DRIVER_INSTALLER_SRC_X64	L"|driver_installer_x64.exe"
#define	VISTA_DRIVER_INSTALLER_SRC_IA64	L"|driver_installer_ia64.exe"
#define	VISTA_DRIVER_INSTALLER_DST	L"%s\\driver_installer.exe"

#define	DRIVER_DEVICE_ID_TAG		"NeoAdapter_%s"


#if		(defined(MICROSOFT_C) || defined(NETWORK_C)) && (defined(OS_WIN32))

typedef enum __TCP_TABLE_CLASS {
	_TCP_TABLE_BASIC_LISTENER,
	_TCP_TABLE_BASIC_CONNECTIONS,
	_TCP_TABLE_BASIC_ALL,
	_TCP_TABLE_OWNER_PID_LISTENER,
	_TCP_TABLE_OWNER_PID_CONNECTIONS,
	_TCP_TABLE_OWNER_PID_ALL,
	_TCP_TABLE_OWNER_MODULE_LISTENER,
	_TCP_TABLE_OWNER_MODULE_CONNECTIONS,
	_TCP_TABLE_OWNER_MODULE_ALL
} _TCP_TABLE_CLASS, *_PTCP_TABLE_CLASS;

// A pointer to the network related Win32 API function
typedef struct NETWORK_WIN32_FUNCTIONS
{
	HINSTANCE hIpHlpApi32;
	HINSTANCE hIcmp;
	DWORD (WINAPI *DeleteIpForwardEntry)(PMIB_IPFORWARDROW);
	DWORD (WINAPI *CreateIpForwardEntry)(PMIB_IPFORWARDROW);
	DWORD (WINAPI *GetIpForwardTable)(PMIB_IPFORWARDTABLE, PULONG, BOOL);
	DWORD (WINAPI *GetNetworkParams)(PFIXED_INFO, PULONG);
	ULONG (WINAPI *GetAdaptersAddresses)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
	DWORD (WINAPI *GetIfTable)(PMIB_IFTABLE, PULONG, BOOL);
	DWORD (WINAPI *GetIfTable2)(void **);
	void (WINAPI *FreeMibTable)(PVOID);
	DWORD (WINAPI *IpRenewAddress)(PIP_ADAPTER_INDEX_MAP);
	DWORD (WINAPI *IpReleaseAddress)(PIP_ADAPTER_INDEX_MAP);
	DWORD (WINAPI *GetInterfaceInfo)(PIP_INTERFACE_INFO, PULONG);
	DWORD (WINAPI *GetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
	DWORD (WINAPI *GetExtendedTcpTable)(PVOID, PDWORD, BOOL, ULONG, _TCP_TABLE_CLASS, ULONG);
	DWORD (WINAPI *AllocateAndGetTcpExTableFromStack)(PVOID *, BOOL, HANDLE, DWORD, DWORD);
	DWORD (WINAPI *GetTcpTable)(PMIB_TCPTABLE, PDWORD, BOOL);
	DWORD (WINAPI *NotifyRouteChange)(PHANDLE, LPOVERLAPPED);
	BOOL (WINAPI *CancelIPChangeNotify)(LPOVERLAPPED);
	DWORD (WINAPI *NhpAllocateAndGetInterfaceInfoFromStack)(IP_INTERFACE_NAME_INFO **,
		PDWORD, BOOL, HANDLE, DWORD);
	HANDLE (WINAPI *IcmpCreateFile)();
	BOOL (WINAPI *IcmpCloseHandle)(HANDLE);
	DWORD (WINAPI *IcmpSendEcho)(HANDLE, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION,
		LPVOID, DWORD, DWORD);
} NETWORK_WIN32_FUNCTIONS;
#endif


#ifdef	MICROSOFT_C
// WCM related code on Windows 8
typedef enum _MS_WCM_PROPERTY
{
	ms_wcm_global_property_domain_policy,
	ms_wcm_global_property_minimize_policy,
	ms_wcm_global_property_roaming_policy,  
	ms_wcm_global_property_powermanagement_policy,
	ms_wcm_intf_property_connection_cost,   //used to set/get cost level and flags for the connection
	ms_wcm_intf_property_dataplan_status,   //used by MNO to indicate plan data associated with new cost
	ms_wcm_intf_property_hotspot_profile,   //used to store hotspot profile (WISPr credentials)
} MS_WCM_PROPERTY, *MS_PWCM_PROPERTY;

typedef struct _MS_WCM_POLICY_VALUE {
	BOOL fValue;
	BOOL fIsGroupPolicy;
} MS_WCM_POLICY_VALUE, *MS_PWCM_POLICY_VALUE;

#define MS_WCM_MAX_PROFILE_NAME            256

typedef enum _MS_WCM_MEDIA_TYPE
{
	ms_wcm_media_unknown,
	ms_wcm_media_ethernet,
	ms_wcm_media_wlan,
	ms_wcm_media_mbn,
	ms_wcm_media_invalid,
	ms_wcm_media_max
} MS_WCM_MEDIA_TYPE, *MS_PWCM_MEDIA_TYPE;

typedef struct _MS_WCM_PROFILE_INFO {
	WCHAR strProfileName[MS_WCM_MAX_PROFILE_NAME];
	GUID AdapterGUID;
	MS_WCM_MEDIA_TYPE Media;
} MS_WCM_PROFILE_INFO, *MS_PWCM_PROFILE_INFO;

typedef struct _MS_WCM_PROFILE_INFO_LIST {
	DWORD            dwNumberOfItems;

	MS_WCM_PROFILE_INFO ProfileInfo[1];

} MS_WCM_PROFILE_INFO_LIST, *MS_PWCM_PROFILE_INFO_LIST;


// Internal structure
typedef struct MS
{
	HINSTANCE hInst;
	HINSTANCE hKernel32;
	bool IsNt;
	bool IsAdmin;
	struct NT_API *nt;
	HANDLE hCurrentProcess;
	UINT CurrentProcessId;
	bool MiniDumpEnabled;
	char *ExeFileName;
	char *ExeFileDir;
	char *WindowsDir;
	char *System32Dir;
	char *TempDir;
	char *WinTempDir;
	char *WindowsDrive;
	char *ProgramFilesDir;
	char *ProgramFilesDirX86;
	char *ProgramFilesDirX64;
	char *CommonStartMenuDir;
	char *CommonProgramsDir;
	char *CommonStartupDir;
	char *CommonAppDataDir;
	char *CommonDesktopDir;
	char *PersonalStartMenuDir;
	char *PersonalProgramsDir;
	char *PersonalStartupDir;
	char *PersonalAppDataDir;
	char *PersonalDesktopDir;
	char *MyDocumentsDir;
	char *LocalAppDataDir;
	char *MyTempDir;
	char *UserName;
	char *UserNameEx;
	wchar_t *ExeFileNameW;
	wchar_t *ExeFileDirW;
	wchar_t *WindowsDirW;
	wchar_t *System32DirW;
	wchar_t *TempDirW;
	wchar_t *WinTempDirW;
	wchar_t *WindowsDriveW;
	wchar_t *ProgramFilesDirW;
	wchar_t *ProgramFilesDirX86W;
	wchar_t *ProgramFilesDirX64W;
	wchar_t *CommonStartMenuDirW;
	wchar_t *CommonProgramsDirW;
	wchar_t *CommonStartupDirW;
	wchar_t *CommonAppDataDirW;
	wchar_t *CommonDesktopDirW;
	wchar_t *PersonalStartMenuDirW;
	wchar_t *PersonalProgramsDirW;
	wchar_t *PersonalStartupDirW;
	wchar_t *PersonalAppDataDirW;
	wchar_t *PersonalDesktopDirW;
	wchar_t *MyDocumentsDirW;
	wchar_t *LocalAppDataDirW;
	wchar_t *MyTempDirW;
	wchar_t *UserNameW;
	wchar_t *UserNameExW;
	wchar_t *MinidumpBaseFileNameW;
	IO *LockFile;
} MS;

// For Windows NT API
typedef struct NT_API
{
	HINSTANCE hAdvapi32;
	HINSTANCE hShell32;
	HINSTANCE hNewDev;
	HINSTANCE hSetupApi;
	HINSTANCE hWtsApi32;
	HINSTANCE hPsApi;
	HINSTANCE hKernel32;
	HINSTANCE hSecur32;
	HINSTANCE hUser32;
	HINSTANCE hDbgHelp;
	HINSTANCE hWcmapi;
	HINSTANCE hDwmapi;
	BOOL (WINAPI *OpenProcessToken)(HANDLE, DWORD, PHANDLE);
	BOOL (WINAPI *LookupPrivilegeValue)(char *, char *, PLUID);
	BOOL (WINAPI *AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
	BOOL (WINAPI *InitiateSystemShutdown)(LPTSTR, LPTSTR, DWORD, BOOL, BOOL);
	BOOL (WINAPI *LogonUserW)(wchar_t *, wchar_t *, wchar_t *, DWORD, DWORD, HANDLE *);
	BOOL (WINAPI *LogonUserA)(char *, char *, char *, DWORD, DWORD, HANDLE *);
	BOOL (WINAPI *UpdateDriverForPlugAndPlayDevicesW)(HWND hWnd, wchar_t *hardware_id, wchar_t *inf_path, UINT flag, BOOL *need_reboot);
	UINT (WINAPI *CM_Get_DevNode_Status_Ex)(UINT *, UINT *, DWORD, UINT, HANDLE);
	UINT (WINAPI *CM_Get_Device_ID_ExA)(DWORD, char *, UINT, UINT, HANDLE);
	UINT (WINAPI *WTSQuerySessionInformation)(HANDLE, DWORD, WTS_INFO_CLASS, wchar_t *, DWORD *);
	void (WINAPI *WTSFreeMemory)(void *);
	BOOL (WINAPI *WTSDisconnectSession)(HANDLE, DWORD, BOOL);
	BOOL (WINAPI *WTSEnumerateSessions)(HANDLE, DWORD, DWORD, PWTS_SESSION_INFO *, DWORD *);
	SC_HANDLE (WINAPI *OpenSCManager)(LPCTSTR, LPCTSTR, DWORD);
	SC_HANDLE (WINAPI *CreateServiceA)(SC_HANDLE, LPCTSTR, LPCTSTR, DWORD, DWORD, DWORD, DWORD, LPCTSTR, LPCTSTR, LPDWORD, LPCTSTR, LPCTSTR, LPCTSTR);
	SC_HANDLE (WINAPI *CreateServiceW)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
	BOOL (WINAPI *ChangeServiceConfig2)(SC_HANDLE, DWORD, LPVOID);
	BOOL (WINAPI *CloseServiceHandle)(SC_HANDLE);
	SC_HANDLE (WINAPI *OpenService)(SC_HANDLE, LPCTSTR, DWORD);
	BOOL (WINAPI *QueryServiceStatus)(SC_HANDLE, LPSERVICE_STATUS);
	BOOL (WINAPI *StartService)(SC_HANDLE, DWORD, LPCTSTR);
	BOOL (WINAPI *ControlService)(SC_HANDLE, DWORD, LPSERVICE_STATUS);
	BOOL (WINAPI *SetServiceStatus)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS);
	SERVICE_STATUS_HANDLE (WINAPI *RegisterServiceCtrlHandler)(LPCTSTR, LPHANDLER_FUNCTION);
	BOOL (WINAPI *StartServiceCtrlDispatcher)(CONST LPSERVICE_TABLE_ENTRY);
	BOOL (WINAPI *DeleteService)(SC_HANDLE);
	BOOL (WINAPI *EnumProcesses)(DWORD *, DWORD, DWORD *);
	BOOL (WINAPI *EnumProcessModules)(HANDLE, HMODULE *, DWORD, DWORD *);
	DWORD (WINAPI *GetModuleFileNameExA)(HANDLE, HMODULE, LPSTR, DWORD);
	DWORD (WINAPI *GetModuleFileNameExW)(HANDLE, HMODULE, LPWSTR, DWORD);
	DWORD (WINAPI *GetProcessImageFileNameA)(HANDLE, LPSTR, DWORD);
	DWORD (WINAPI *GetProcessImageFileNameW)(HANDLE, LPWSTR, DWORD);
	BOOL (WINAPI *QueryFullProcessImageNameA)(HANDLE, DWORD, LPSTR, PDWORD);
	BOOL (WINAPI *QueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
	LONG (WINAPI *RegDeleteKeyExA)(HKEY, LPCTSTR, REGSAM, DWORD);
	BOOL (WINAPI *IsWow64Process)(HANDLE, BOOL *);
	void (WINAPI *GetNativeSystemInfo)(SYSTEM_INFO *);
	BOOL (WINAPI *DuplicateTokenEx)(HANDLE, DWORD, SECURITY_ATTRIBUTES *, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, HANDLE *);
	BOOL (WINAPI *ConvertStringSidToSidA)(LPCSTR, PSID *);
	BOOL (WINAPI *SetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, void *, DWORD);
	BOOL (WINAPI *GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, void *, DWORD, PDWORD);
	BOOL (WINAPI *CreateProcessAsUserA)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, void *, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
	BOOL (WINAPI *CreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, void *, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
	BOOL (WINAPI *LookupAccountSidA)(LPCSTR,PSID,LPSTR,LPDWORD,LPSTR,LPDWORD,PSID_NAME_USE);
	BOOL (WINAPI *LookupAccountNameA)(LPCSTR,LPCSTR,PSID,LPDWORD,LPSTR,LPDWORD,PSID_NAME_USE);
	BOOL (WINAPI *GetUserNameExA)(EXTENDED_NAME_FORMAT, LPSTR, PULONG);
	BOOL (WINAPI *GetUserNameExW)(EXTENDED_NAME_FORMAT, LPWSTR, PULONG);
	BOOL (WINAPI *SwitchDesktop)(HDESK);
	HDESK (WINAPI *OpenDesktopA)(LPTSTR, DWORD, BOOL, ACCESS_MASK);
	BOOL (WINAPI *CloseDesktop)(HDESK);
	BOOL (WINAPI *SetProcessShutdownParameters)(DWORD, DWORD);
	HANDLE (WINAPI *RegisterEventSourceW)(LPCWSTR, LPCWSTR);
	BOOL (WINAPI *ReportEventW)(HANDLE, WORD, WORD, DWORD, PSID, WORD, DWORD, LPCWSTR *, LPVOID);
	BOOL (WINAPI *DeregisterEventSource)(HANDLE);
	BOOL (WINAPI *Wow64DisableWow64FsRedirection)(void **);
	BOOLEAN (WINAPI *Wow64EnableWow64FsRedirection)(BOOLEAN);
	BOOL (WINAPI *Wow64RevertWow64FsRedirection)(void *);
	BOOL (WINAPI *GetFileInformationByHandle)(HANDLE, LPBY_HANDLE_FILE_INFORMATION);
	HANDLE (WINAPI *GetProcessHeap)();
	BOOL (WINAPI *MiniDumpWriteDump)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
		PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION,
		PMINIDUMP_CALLBACK_INFORMATION);
	BOOL (WINAPI *AllocateLocallyUniqueId)(PLUID);
	NTSTATUS (NTAPI *LsaConnectUntrusted)(PHANDLE);
	NTSTATUS (NTAPI *LsaLookupAuthenticationPackage)(HANDLE, PLSA_STRING, PULONG);
	NTSTATUS (NTAPI *LsaLogonUser)(HANDLE, PLSA_STRING, SECURITY_LOGON_TYPE, ULONG,
		PVOID, ULONG, PTOKEN_GROUPS, PTOKEN_SOURCE, PVOID, PULONG, PLUID, PHANDLE,
		PQUOTA_LIMITS, PNTSTATUS);
	NTSTATUS (NTAPI *LsaDeregisterLogonProcess)(HANDLE);
	NTSTATUS (NTAPI *LsaFreeReturnBuffer)(PVOID);
	DWORD (WINAPI *WcmQueryProperty)(const GUID *, LPCWSTR, MS_WCM_PROPERTY, PVOID, PDWORD, PBYTE *);
	DWORD (WINAPI *WcmSetProperty)(const GUID *, LPCWSTR, MS_WCM_PROPERTY, PVOID, DWORD, const BYTE *);
	void (WINAPI *WcmFreeMemory)(PVOID);
	DWORD (WINAPI *WcmGetProfileList)(PVOID, MS_WCM_PROFILE_INFO_LIST **ppProfileList);
	DWORD (WINAPI *SetNamedSecurityInfoW)(LPWSTR, UINT, SECURITY_INFORMATION, PSID, PSID, PACL, PACL);
	BOOL (WINAPI *AddAccessAllowedAceEx)(PACL, DWORD, DWORD, DWORD, PSID);
	HRESULT (WINAPI *DwmIsCompositionEnabled)(BOOL *);
	BOOL (WINAPI *GetComputerNameExW)(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD);
} NT_API;

typedef struct MS_EVENTLOG
{
	HANDLE hEventLog;
} MS_EVENTLOG;

extern NETWORK_WIN32_FUNCTIONS *w32net;

typedef struct MS_USERMODE_SVC_PULSE_THREAD_PARAM
{
	void *hWnd;
	void *GlobalPulse;
	volatile bool Halt;
} MS_USERMODE_SVC_PULSE_THREAD_PARAM;

#endif	// MICROSOFT_C

// Structure to suppress the warning message
typedef struct NO_WARNING
{
	DWORD ThreadId;
	THREAD *NoWarningThread;
	EVENT *HaltEvent;
	volatile bool Halt;
	wchar_t *SoundFileName;
	UINT64 StartTimer;
	UINT64 StartTick;
} NO_WARNING;

// ID of the root key
#define	REG_CLASSES_ROOT		0	// HKEY_CLASSES_ROOT
#define	REG_LOCAL_MACHINE		1	// HKEY_LOCAL_MACHINE
#define	REG_CURRENT_USER		2	// HKEY_CURRENT_USER
#define	REG_USERS				3	// HKEY_USERS

// Service Functions
typedef void (SERVICE_FUNCTION)();

// Process list item
typedef struct MS_PROCESS
{
	char ExeFilename[MAX_PATH];		// EXE file name
	wchar_t ExeFilenameW[MAX_PATH];	// EXE file name (Unicode)
	UINT ProcessId;					// Process ID
} MS_PROCESS;

#define	MAX_MS_ADAPTER_IP_ADDRESS	64

// Network adapter
typedef struct MS_ADAPTER
{
	char Title[MAX_PATH];			// Display name
	wchar_t TitleW[MAX_PATH];		// Display Name (Unicode)
	UINT Index;						// Index
	UINT Type;						// Type
	UINT Status;					// Status
	UINT Mtu;						// MTU
	UINT Speed;						// Speed
	UINT AddressSize;				// Address size
	UCHAR Address[8];				// Address
	UINT64 RecvBytes;				// Number of received bytes
	UINT64 RecvPacketsBroadcast;	// Number of broadcast packets received
	UINT64 RecvPacketsUnicast;		// Number of unicast packets received
	UINT64 SendBytes;				// Number of bytes sent
	UINT64 SendPacketsBroadcast;	// Number of sent broadcast packets
	UINT64 SendPacketsUnicast;		// Number of sent unicast packets
	bool Info;						// Whether there is detailed information
	char Guid[MAX_SIZE];			// GUID
	UINT NumIpAddress;				// The number of IP addresses
	IP IpAddresses[MAX_MS_ADAPTER_IP_ADDRESS];	// IP address
	IP SubnetMasks[MAX_MS_ADAPTER_IP_ADDRESS];	// Subnet mask
	UINT NumGateway;				// The number of the gateway
	IP Gateways[MAX_MS_ADAPTER_IP_ADDRESS];	// Gateway
	bool UseDhcp;					// Using DHCP flag
	IP DhcpServer;					// DHCP Server
	UINT64 DhcpLeaseStart;			// DHCP lease start date and time
	UINT64 DhcpLeaseExpires;		// DHCP lease expiration date and time
	bool UseWins;					// WINS use flag
	IP PrimaryWinsServer;			// Primary WINS server
	IP SecondaryWinsServer;			// Secondary WINS server
	bool IsWireless;				// Whether wireless
	bool IsNotEthernetLan;			// Whether It isn't a Ethernet LAN
} MS_ADAPTER;

// Network adapter list
typedef struct MS_ADAPTER_LIST
{
	UINT Num;						// Count
	MS_ADAPTER **Adapters;			// Content
} MS_ADAPTER_LIST;

// TCP setting
typedef struct MS_TCP
{
	UINT RecvWindowSize;			// Receive window size
	UINT SendWindowSize;			// Send window size
} MS_TCP;

// Sleep prevention
typedef struct MS_NOSLEEP
{
	THREAD *Thread;					// Thread
	EVENT *HaltEvent;				// Halting event
	volatile bool Halt;				// Halting flag
	bool NoScreenSaver;				// Prevent Screensaver

	// Following is for Windows Vista
	wchar_t ScreenSaveActive[MAX_PATH];
	wchar_t SCRNSAVE_EXE[MAX_PATH];
} MS_NOSLEEP;

// Child window enumeration
typedef struct ENUM_CHILD_WINDOW_PARAM
{
	LIST *o;
	bool no_recursion;
	bool include_ipcontrol;
} ENUM_CHILD_WINDOW_PARAM;

// Driver version information
typedef struct MS_DRIVER_VER
{
	UINT Year, Month, Day;
	UINT Major, Minor, Build;
} MS_DRIVER_VER;

// Suspend handler
typedef struct MS_SUSPEND_HANDLER
{
	HWND hWnd;
	THREAD *Thread;
	volatile bool AboutToClose;
} MS_SUSPEND_HANDLER;


// Function prototype
void MsInit();
void MsFree();
char *MsCutExeNameFromCommandLine(char *str);
wchar_t *MsCutExeNameFromUniCommandLine(wchar_t *str);

DWORD MsRegAccessMaskFor64Bit(bool force32bit);
DWORD MsRegAccessMaskFor64BitEx(bool force32bit, bool force64bit);

bool MsRegIsKey(UINT root, char *name);
bool MsRegIsKeyEx(UINT root, char *name, bool force32bit);
bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit, bool force64bit);

bool MsRegIsValue(UINT root, char *keyname, char *valuename);
bool MsRegIsValueEx(UINT root, char *keyname, char *valuename, bool force32bit);
bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsRegGetValueTypeAndSize(UINT root, char *keyname, char *valuename, UINT *type, UINT *size);
bool MsRegGetValueTypeAndSizeEx(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit);
bool MsRegGetValueTypeAndSizeEx2(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit, bool force64bit);
bool MsRegGetValueTypeAndSizeW(UINT root, char *keyname, char *valuename, UINT *type, UINT *size);
bool MsRegGetValueTypeAndSizeExW(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit);
bool MsRegGetValueTypeAndSizeEx2W(UINT root, char *keyname, char *valuename, UINT *type, UINT *size, bool force32bit, bool force64bit);

bool MsRegReadValue(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size);
bool MsRegReadValueEx(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit);
bool MsRegReadValueEx2(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit, bool force64bit);
bool MsRegReadValueW(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size);
bool MsRegReadValueExW(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit);
bool MsRegReadValueEx2W(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit, bool force64bit);

char *MsRegReadStr(UINT root, char *keyname, char *valuename);
char *MsRegReadStrEx(UINT root, char *keyname, char *valuename, bool force32bit);
char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);
wchar_t *MsRegReadStrW(UINT root, char *keyname, char *valuename);
wchar_t *MsRegReadStrExW(UINT root, char *keyname, char *valuename, bool force32bit);
wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

UINT MsRegReadInt(UINT root, char *keyname, char *valuename);
UINT MsRegReadIntEx(UINT root, char *keyname, char *valuename, bool force32bit);
UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);
LIST *MsRegReadStrList(UINT root, char *keyname, char *valuename);
LIST *MsRegReadStrListEx(UINT root, char *keyname, char *valuename, bool force32bit);
LIST *MsRegReadStrListEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

BUF *MsRegReadBin(UINT root, char *keyname, char *valuename);
BUF *MsRegReadBinEx(UINT root, char *keyname, char *valuename, bool force32bit);
BUF *MsRegReadBinEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsRegNewKey(UINT root, char *keyname);
bool MsRegNewKeyEx(UINT root, char *keyname, bool force32bit);
bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);

bool MsRegWriteValue(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size);
bool MsRegWriteValueEx(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit);
bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit);
bool MsRegWriteValueW(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size);
bool MsRegWriteValueExW(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit);
bool MsRegWriteValueEx2W(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit);

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str);
bool MsRegWriteStrEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit);
bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit);
bool MsRegWriteStrExpand(UINT root, char *keyname, char *valuename, char *str);
bool MsRegWriteStrExpandEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit);
bool MsRegWriteStrExpandEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit);
bool MsRegWriteStrW(UINT root, char *keyname, char *valuename, wchar_t *str);
bool MsRegWriteStrExW(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit);
bool MsRegWriteStrEx2W(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit, bool force64bit);
bool MsRegWriteStrExpandW(UINT root, char *keyname, char *valuename, wchar_t *str);
bool MsRegWriteStrExpandExW(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit);
bool MsRegWriteStrExpandEx2W(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit, bool force64bit);

bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value);
bool MsRegWriteIntEx(UINT root, char *keyname, char *valuename, UINT value, bool force32bit);
bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit, bool force64bit);
bool MsRegWriteBin(UINT root, char *keyname, char *valuename, void *data, UINT size);
bool MsRegWriteBinEx(UINT root, char *keyname, char *valuename, void *data, UINT size, bool force32bit);
bool MsRegWriteBinEx2(UINT root, char *keyname, char *valuename, void *data, UINT size, bool force32bit, bool force64bit);

TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname);
TOKEN_LIST *MsRegEnumKeyEx(UINT root, char *keyname, bool force32bit);
TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);
TOKEN_LIST *MsRegEnumValue(UINT root, char *keyname);
TOKEN_LIST *MsRegEnumValueEx(UINT root, char *keyname, bool force32bit);
TOKEN_LIST *MsRegEnumValueEx2(UINT root, char *keyname, bool force32bit, bool force64bit);

bool MsRegDeleteKey(UINT root, char *keyname);
bool MsRegDeleteKeyEx(UINT root, char *keyname, bool force32bit);
bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit);
bool MsRegDeleteValue(UINT root, char *keyname, char *valuename);
bool MsRegDeleteValueEx(UINT root, char *keyname, char *valuename, bool force32bit);
bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit);

bool MsIsNt();
bool MsIsAdmin();
bool MsEnablePrivilege(char *name, bool enable);
void *MsGetCurrentProcess();
UINT MsGetCurrentProcessId();
char *MsGetExeFileName();
char *MsGetExeDirName();
wchar_t *MsGetExeDirNameW();

bool MsShutdown(bool reboot, bool force);
bool MsShutdownEx(bool reboot, bool force, UINT time_limit, char *message);
bool MsCheckLogon(wchar_t *username, char *password);
bool MsIsPasswordEmpty(wchar_t *username);
TOKEN_LIST *MsEnumNetworkAdapters(char *start_with_name, char *start_with_name_2);
TOKEN_LIST *MsEnumNetworkAdaptersNeo();
bool MsGetNeoDeiverFilename(char *name, UINT size, char *instance_name);
bool MsMakeNewNeoDriverFilename(char *name, UINT size);
void MsGenerateNeoDriverFilenameFromInt(char *name, UINT size, UINT n);
TOKEN_LIST *MsEnumNeoDriverFilenames();
char *MsGetNetworkAdapterGuid(char *tag_name, char *instance_name);
wchar_t *MsGetNetworkConnectionName(char *guid);
char *MsGetNetworkConfigRegKeyNameFromGuid(char *guid);
char *MsGetNetworkConfigRegKeyNameFromInstanceName(char *tag_name, char *instance_name);
void MsSetNetworkConfig(char *tag_name, char *instance_name, char *friendly_name, bool show_icon);
void MsInitNetworkConfig(char *tag_name, char *instance_name, char *connection_tag_name);
void MsNormalizeInterfaceDefaultGatewaySettings(char *tag_name, char *instance_name);

char *MsGetSpecialDir(int id);
wchar_t *MsGetSpecialDirW(int id);
void MsGetSpecialDirs();
bool MsCheckIsAdmin();
void MsInitTempDir();
void MsFreeTempDir();
void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir);
void MsDeleteTempDir();
void MsDeleteAllFile(char *dir);
void MsDeleteAllFileW(wchar_t *dir);
char *MsCreateTempFileName(char *name);
char *MsCreateTempFileNameByExt(char *ext);
IO *MsCreateTempFile(char *name);
IO *MsCreateTempFileByExt(char *ext);

bool MsInstallVLan(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver);
bool MsInstallVLanWithoutLock(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver);
bool MsInstallVLanInternal(wchar_t *infpath, wchar_t *hwid_w, char *hwid);
bool MsUpgradeVLan(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver);
bool MsUpgradeVLanWithoutLock(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver);
bool MsEnableVLan(char *instance_name);
bool MsEnableVLanWithoutLock(char *instance_name);
bool MsDisableVLan(char *instance_name);
bool MsDisableVLanWithoutLock(char *instance_name);
bool MsUninstallVLan(char *instance_name);
bool MsUninstallVLanWithoutLock(char *instance_name);
bool MsIsVLanEnabled(char *instance_name);
bool MsIsVLanEnabledWithoutLock(char *instance_name);
bool MsIsValidVLanInstanceNameForInfCatalog(char *instance_name);
void MsGetInfCatalogDir(char *dst, UINT size);
void MsRestartVLan(char *instance_name);
void MsRestartVLanWithoutLock(char *instance_name);
bool MsIsVLanExists(char *tag_name, char *instance_name);
void MsDeleteTroubleVLAN(char *tag_name, char *instance_name);
bool MsStartDriverInstall(char *instance_name, UCHAR *mac_address, char *neo_sys, UCHAR *ret_mac_address, MS_DRIVER_VER *ver);
void MsFinishDriverInstall(char *instance_name, char *neo_sys);
void MsGetDriverPath(char *instance_name, wchar_t *src_inf, wchar_t *src_sys, wchar_t *dest_inf, wchar_t *dest_sys, wchar_t *src_cat, wchar_t *dest_cat, char *neo_sys);
void MsGetDriverPathA(char *instance_name, char *src_inf, char *src_sys, char *dest_inf, char *dest_sys, char *src_cat, char *dst_cat, char *neo_sys);
void MsGenMacAddress(UCHAR *mac);
char *MsGetMacAddress(char *tag_name, char *instance_name);
char *MsGetNetCfgRegKeyName(char *tag_name, char *instance_name);
void MsSetMacAddress(char *tag_name, char *instance_name, char *mac_address);
char *MsGetDriverVersion(char *tag_name, char *instance_name);
char *MsGetDriverFileName(char *tag_name, char *instance_name);
void MsTest();
void MsInitGlobalNetworkConfig();
void MsDisableNetworkOffloadingEtc();
void MsSetThreadPriorityHigh();
void MsSetThreadPriorityLow();
void MsSetThreadPriorityIdle();
void MsSetThreadPriorityRealtime();
void MsRestoreThreadPriority();
char *MsGetLocalAppDataDir();
char *MsGetCommonAppDataDir();
char *MsGetWindowsDir();
char *MsGetSystem32Dir();
char *MsGetTempDir();
char *MsGetWindowsDrive();
char *MsGetProgramFilesDir();
char *MsGetProgramFilesDirX86();
char *MsGetProgramFilesDirX64();
char *MsGetCommonStartMenuDir();
char *MsGetCommonProgramsDir();
char *MsGetCommonStartupDir();
char *MsGetCommonAppDataDir();
char *MsGetCommonDesktopDir();
char *MsGetPersonalStartMenuDir();
char *MsGetPersonalProgramsDir();
char *MsGetPersonalStartupDir();
char *MsGetPersonalAppDataDir();
char *MsGetPersonalDesktopDir();
char *MsGetMyDocumentsDir();
char *MsGetMyTempDir();
char *MsGetUserName();
char *MsGetUserNameEx();
char *MsGetWinTempDir();
wchar_t *MsGetWindowsDirW();
wchar_t *MsGetExeFileNameW();
wchar_t *MsGetExeFileDirW();
wchar_t *MsGetWindowDirW();
wchar_t *MsGetSystem32DirW();
wchar_t *MsGetTempDirW();
wchar_t *MsGetWindowsDriveW();
wchar_t *MsGetProgramFilesDirW();
wchar_t *MsGetProgramFilesDirX86W();
wchar_t *MsGetProgramFilesDirX64W();
wchar_t *MsGetCommonStartMenuDirW();
wchar_t *MsGetCommonProgramsDirW();
wchar_t *MsGetCommonStartupDirW();
wchar_t *MsGetCommonAppDataDirW();
wchar_t *MsGetCommonDesktopDirW();
wchar_t *MsGetPersonalStartMenuDirW();
wchar_t *MsGetPersonalProgramsDirW();
wchar_t *MsGetPersonalStartupDirW();
wchar_t *MsGetPersonalAppDataDirW();
wchar_t *MsGetPersonalDesktopDirW();
wchar_t *MsGetMyDocumentsDirW();
wchar_t *MsGetLocalAppDataDirW();
wchar_t *MsGetMyTempDirW();
wchar_t *MsGetUserNameW();
wchar_t *MsGetUserNameExW();
wchar_t *MsGetWinTempDirW();
struct SAFE_TABLE *MsGetSafeTable();
UINT MsGetProcessId();
void MsTerminateProcess();
bool MsIsServiceInstalled(char *name);
bool MsInstallService(char *name, char *title, wchar_t *description, char *path);
bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path, UINT *error_code);
bool MsInstallServiceW(char *name, wchar_t *title, wchar_t *description, wchar_t *path);
bool MsInstallDeviceDriverW(char *name, wchar_t *title, wchar_t *path, UINT *error_code);
bool MsUpdateServiceConfig(char *name);
bool MsSetServiceDescription(char *name, wchar_t *description);
bool MsUninstallService(char *name);
bool MsStartService(char *name);
bool MsStartServiceEx(char *name, UINT *error_code);
bool MsStopService(char *name);
bool MsIsServiceRunning(char *name);
bool MsIsTerminalServiceInstalled();
bool MsIsUserSwitchingInstalled();
bool MsIsTerminalServiceMultiUserInstalled();
UINT MsGetCurrentTerminalSessionId();
bool MsIsTerminalSessionActive(UINT session_id);
bool MsIsCurrentTerminalSessionActive();
bool MsIsCurrentDesktopAvailableForVnc();
wchar_t *MsGetSessionUserName(UINT session_id);
UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon, char *cmd_line);
void MsTestModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void MsTestMode(char *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void MsServiceMode(SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void MsUserModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon);
void MsUserMode(char *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon);
bool MsIsUserMode();
void MsTestOnly();
void MsStopUserModeFromService();
char *MsGetPenCoreDllFileName();
void MsPlaySound(char *name);
void MsSetThreadSingleCpu();
void MsWin9xTest();
bool MsCheckVLanDeviceIdFromRootEnum(char *name);
bool MsInstallVLan9x(char *instance_name, MS_DRIVER_VER *ver);
void MsUpdateCompatibleIDs(char *instance_name);
LIST *MsGetProcessList();
LIST *MsGetProcessList9x();
LIST *MsGetProcessListNt();
void MsFreeProcessList(LIST *o);
void MsPrintProcessList(LIST *o);
int MsCompareProcessList(void *p1, void *p2);
MS_PROCESS *MsSearchProcessById(LIST *o, UINT id);
void MsGetCurrentProcessExeName(char *name, UINT size);
void MsGetCurrentProcessExeNameW(wchar_t *name, UINT size);
bool MsKillProcess(UINT id);
UINT MsKillProcessByExeName(wchar_t *name);
void MsKillOtherInstance();
void MsKillOtherInstanceEx(char *exclude_svcname);
bool MsGetShortPathNameA(char *long_path, char *short_path, UINT short_path_size);
bool MsGetShortPathNameW(wchar_t *long_path, wchar_t *short_path, UINT short_path_size);
void MsWriteCallingServiceManagerProcessId(char *svcname, UINT pid);
UINT MsReadCallingServiceManagerProcessId(char *svcname, bool current_user);
bool MsStopIPsecService();
char *MsGetIPsecServiceName();
bool MsStartIPsecService();

void MsGenerateUserModeSvcGlobalPulseName(char *name, UINT size, char *svc_name);
void *MsCreateUserModeSvcGlocalPulse(char *svc_name);
void MsStopUserModeSvc(char *svc_name);
void MsUserModeGlobalPulseRecvThread(THREAD *thread, void *param);

MS_ADAPTER_LIST *MsCreateAdapterListInner();
MS_ADAPTER_LIST *MsCreateAdapterListInnerEx(bool no_info);
MS_ADAPTER_LIST *MsCreateAdapterListInnerExVista(bool no_info);
void MsFreeAdapter(MS_ADAPTER *a);
void MsFreeAdapterList(MS_ADAPTER_LIST *o);
wchar_t *MsGetAdapterTypeStr(UINT type);
wchar_t *MsGetAdapterStatusStr(UINT status);
MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a);
MS_ADAPTER_LIST *MsCloneAdapterList(MS_ADAPTER_LIST *o);
void MsInitAdapterListModule();
void MsFreeAdapterListModule();
MS_ADAPTER_LIST *MsCreateAdapterList();
MS_ADAPTER_LIST *MsCreateAdapterListEx(bool no_info);
void MsGetAdapterTcpIpInformation(MS_ADAPTER *a);
MS_ADAPTER *MsGetAdapter(char *title);
MS_ADAPTER *MsGetAdapterByGuid(char *guid);
MS_ADAPTER *MsGetAdapterByGuidFromList(MS_ADAPTER_LIST *o, char *guid);
UINT ConvertMidStatusVistaToXp(UINT st);

void *MsLoadLibrary(char *name);
void *MsLoadLibraryW(wchar_t *name);
void *MsLoadLibraryAsDataFile(char *name);
void *MsLoadLibraryAsDataFileW(wchar_t *name);
void *MsLoadLibraryRawW(wchar_t *name);
void MsFreeLibrary(void *h);
void *MsGetProcAddress(void *h, char *name);

void MsPrintTick();
bool MsDisableIme();

void MsGetTcpConfig(MS_TCP *tcp);
void MsSetTcpConfig(MS_TCP *tcp);
void MsSaveTcpConfigReg(MS_TCP *tcp);
bool MsLoadTcpConfigReg(MS_TCP *tcp);
bool MsIsTcpConfigSupported();
void MsApplyTcpConfig();
bool MsIsShouldShowTcpConfigApp();
void MsDeleteTcpConfigReg();

UINT MsGetConsoleWidth();
UINT MsSetConsoleWidth(UINT size);
NO_WARNING *MsInitNoWarning();
NO_WARNING *MsInitNoWarningEx(UINT start_timer);
void MsFreeNoWarning(NO_WARNING *nw);
void MsNoWarningThreadProc(THREAD *thread, void *param);
char *MsNoWarningSoundInit();
void MsNoWarningSoundFree(char *s);
bool MsCloseWarningWindow(NO_WARNING *nw, UINT thread_id);
LIST *MsEnumChildWindows(LIST *o, HWND hWnd);
void MsAddWindowToList(LIST *o, HWND hWnd);
UINT MsGetThreadLocale();
LIST *NewWindowList();
int CmpWindowList(void *p1, void *p2);
void AddWindow(LIST *o, HWND hWnd);
void FreeWindowList(LIST *o);
LIST *EnumAllChildWindow(HWND hWnd);
LIST *EnumAllChildWindowEx(HWND hWnd, bool no_recursion, bool include_ipcontrol, bool no_self);
LIST *EnumAllWindow();
LIST *EnumAllWindowEx(bool no_recursion, bool include_ipcontrol);
LIST *EnumAllTopWindow();

bool MsExecDriverInstaller(char *arg);
bool MsIsVista();
bool MsIsWin2000();
bool MsIsWin2000OrGreater();
bool MsIsWinXPOrGreater();
void MsRegistWindowsFirewallEx(char *title, char *exe);
void MsRegistWindowsFirewallEx2(char *title, char *exe, char *dir);
bool MsIs64BitWindows();
bool MsIsX64();
bool MsIsIA64();
void *MsDisableWow64FileSystemRedirection();
void MsRestoreWow64FileSystemRedirection(void *p);
void MsSetWow64FileSystemRedirectionEnable(bool enable);
bool MsIsWindows10();
bool MsIsWindows81();
bool MsIsWindows8();
bool MsIsWindows7();
bool MsIsInfCatalogRequired();

bool MsCheckFileDigitalSignature(HWND hWnd, char *name, bool *danger);
bool MsCheckFileDigitalSignatureW(HWND hWnd, wchar_t *name, bool *danger);


bool MsGetProcessExeName(char *path, UINT size, UINT id);
bool MsGetProcessExeNameW(wchar_t *path, UINT size, UINT id);
bool MsGetWindowOwnerProcessExeName(char *path, UINT size, HWND hWnd);
bool MsGetWindowOwnerProcessExeNameW(wchar_t *path, UINT size, HWND hWnd);

void *MsRunAsUserEx(char *filename, char *arg, bool hide);
void *MsRunAsUserExW(wchar_t *filename, wchar_t *arg, bool hide);
void *MsRunAsUserExInner(char *filename, char *arg, bool hide);
void *MsRunAsUserExInnerW(wchar_t *filename, wchar_t *arg, bool hide);

UINT MsGetCursorPosHash();
bool MsIsProcessExists(char *exename);
bool MsIsProcessExistsW(wchar_t *exename);
bool MsGetProcessNameFromId(wchar_t *exename, UINT exename_size, UINT pid);
bool MsIsProcessIdExists(UINT pid);

void MsGetComputerName(char *name, UINT size);
void MsGetComputerNameFull(wchar_t *name, UINT size);
void MsGetComputerNameFullEx(wchar_t *name, UINT size, bool with_cache);
void MsNoSleepThread(THREAD *thread, void *param);
void MsNoSleepThreadVista(THREAD *thread, void *param);
UINT64 MsGetScreenSaverTimeout();
void *MsNoSleepStart(bool no_screensaver);
void MsNoSleepEnd(void *p);
bool MsIsRemoteDesktopAvailable();
bool MsIsRemoteDesktopCanEnableByRegistory();
bool MsIsRemoteDesktopEnabled();
bool MsEnableRemoteDesktop();

void MsSetFileToHidden(char *name);
void MsSetFileToHiddenW(wchar_t *name);
bool MsGetFileVersion(char *name, UINT *v1, UINT *v2, UINT *v3, UINT *v4);
bool MsGetFileVersionW(wchar_t *name, UINT *v1, UINT *v2, UINT *v3, UINT *v4);

bool MsExtractCabinetFileFromExe(char *exe, char *cab);
bool MsExtractCabinetFileFromExeW(wchar_t *exe, wchar_t *cab);
BUF *MsExtractResourceFromExe(char *exe, char *type, char *name);
BUF *MsExtractResourceFromExeW(wchar_t *exe, char *type, char *name);
bool MsExtractCab(char *cab_name, char *dest_dir_name);
bool MsExtractCabW(wchar_t *cab_name, wchar_t *dest_dir_name);
bool MsGetCabarcExeFilename(char *name, UINT size);
bool MsGetCabarcExeFilenameW(wchar_t *name, UINT size);
bool MsExtractCabFromMsi(char *msi, char *cab);
bool MsExtractCabFromMsiW(wchar_t *msi, wchar_t *cab);
bool MsIsDirectory(char *name);
bool MsIsDirectoryW(wchar_t *name);
bool MsUniIsDirectory(wchar_t *name);
bool MsUniFileDelete(wchar_t *name);
bool MsUniDirectoryDelete(wchar_t *name);
bool MsUniMakeDir(wchar_t *name);
void MsUniMakeDirEx(wchar_t *name);
void MsMakeDirEx(char *name);
bool MsMakeDir(char *name);
bool MsDirectoryDelete(char *name);
bool MsFileDelete(char *name);
bool MsExecute(char *exe, char *arg);
bool MsExecute2(char *exe, char *arg, bool runas);
bool MsExecuteW(wchar_t *exe, wchar_t *arg);
bool MsExecute2W(wchar_t *exe, wchar_t *arg, bool runas);
bool MsExecuteEx(char *exe, char *arg, void **process_handle);
bool MsExecuteEx2(char *exe, char *arg, void **process_handle, bool runas);
bool MsExecuteExW(wchar_t *exe, wchar_t *arg, void **process_handle);
bool MsExecuteEx2W(wchar_t *exe, wchar_t *arg, void **process_handle, bool runas);
void MsCloseHandle(void *handle);
UINT MsWaitProcessExit(void *process_handle);
bool MsIsFileLocked(char *name);
bool MsIsFileLockedW(wchar_t *name);
bool MsIsLocalDrive(char *name);
bool MsIsLocalDriveW(wchar_t *name);
void MsUpdateSystem();
bool MsGetPhysicalMacAddressFromNetbios(void *address);
bool MsGetPhysicalMacAddressFromApi(void *address);
bool MsGetPhysicalMacAddress(void *address);
bool MsIsUseWelcomeLogin();
UINT64 MsGetHiResCounter();
double MsGetHiResTimeSpan(UINT64 diff);
UINT64 MsGetHiResTimeSpanUSec(UINT64 diff);
BUF *MsRegSubkeysToBuf(UINT root, char *keyname, bool force32bit, bool force64bit);
void MsBufToRegSubkeys(UINT root, char *keyname, BUF *b, bool overwrite, bool force32bit, bool force64bit);
void MsRegDeleteSubkeys(UINT root, char *keyname, bool force32bit, bool force64bit);
void MsRestartMMCSS();
bool MsIsMMCSSNetworkThrottlingEnabled();
void MsSetMMCSSNetworkThrottlingEnable(bool enable);
void MsSetShutdownParameters(UINT level, UINT flag);
void MsChangeIconOnTrayEx2(void *icon, wchar_t *tooltip, wchar_t *info_title, wchar_t *info, UINT info_flags);
bool MsIsTrayInited();
UINT MsGetClipboardOwnerProcessId();
void MsDeleteClipboard();
void *MsInitEventLog(wchar_t *src_name);
void MsFreeEventLog(void *p);
bool MsWriteEventLog(void *p, UINT type, wchar_t *str);
bool MsIsWinXPOrWinVista();
bool MsGetFileInformation(void *h, void *info);
void MsSetErrorModeToSilent();
void MsSetEnableMinidump(bool enabled);
void MsWriteMinidump(wchar_t *filename, void *ex);


void *MsInitGlobalLock(char *name, bool ts_local);
void MsGlobalLock(void *p);
void MsGlobalUnlock(void *p);
void MsFreeGlobalLock(void *p);

void *MsOpenOrCreateGlobalPulse(char *name);
bool MsWaitForGlobalPulse(void *p, UINT timeout);
void MsCloseGlobalPulse(void *p);
void MsSendGlobalPulse(void *p);

bool MsPerformMsChapV2AuthByLsa(char *username, UCHAR *challenge8, UCHAR *client_response_24, UCHAR *ret_pw_hash_hash);

void MsDisableWcmNetworkMinimize();
bool MsSetFileSecureAcl(wchar_t *path);

bool MsGetMsiInstalledDir(char *component_code, wchar_t *dir, UINT dir_size);
bool MsMsiUninstall(char *product_code, HWND hWnd, bool *reboot_required);

UINT MsGetUserLocaleId();
UINT MsGetSystemLocaleId();
bool MsIsCurrentUserLocaleIdJapanese();

TOKEN_LIST *MsEnumResources(void *hModule, char *type);
void *MsGetCurrentModuleHandle();

bool MsIsAeroEnabled();
bool MsIsAeroColor();

bool MsIsInVmMain();
bool MsIsInVm();

void MsTest();

bool MsSaveSystemInfo(wchar_t *dst_filename);
bool MsCollectVpnInfo(BUF *bat, char *tmpdir, char *svc_name, wchar_t *config_name, wchar_t *logdir_name);

MS_SUSPEND_HANDLER *MsNewSuspendHandler();
void MsFreeSuspendHandler(MS_SUSPEND_HANDLER *h);

void MsBeginVLanCard();
void MsEndVLanCard();
bool MsIsVLanCardShouldStop();
void MsProcEnterSuspend();
void MsProcLeaveSuspend();
UINT64 MsGetSuspendModeBeginTick();

// Inner functions
#ifdef	MICROSOFT_C

LONG CALLBACK MsExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo);
HKEY MsGetRootKeyFromInt(UINT root);
NT_API *MsLoadNtApiFunctions();
void MsFreeNtApiFunctions(NT_API *nt);
void MsDestroyDevInfo(HDEVINFO info);
HDEVINFO MsGetDevInfoFromDeviceId(SP_DEVINFO_DATA *dev_info_data, char *device_id);
bool MsStartDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
bool MsStopDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
bool MsDeleteDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
bool MsIsDeviceRunning(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data);
void CALLBACK MsServiceDispatcher(DWORD argc, LPTSTR *argv);
void CALLBACK MsServiceHandler(DWORD opcode);
bool MsServiceStopProc();
void MsServiceStoperMainThread(THREAD *t, void *p);
void MsServiceStarterMainThread(THREAD *t, void *p);
LRESULT CALLBACK MsUserModeWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
bool MsShowIconOnTray(HWND hWnd, HICON icon, wchar_t *tooltip, UINT msg);
void MsRestoreIconOnTray();
void MsChangeIconOnTray(HICON icon, wchar_t *tooltip);
bool MsChangeIconOnTrayEx(HICON icon, wchar_t *tooltip, wchar_t *info_title, wchar_t *info, UINT info_flags, bool add);
void MsHideIconOnTray();
void MsUserModeTrayMenu(HWND hWnd);
bool MsAppendMenu(HMENU hMenu, UINT flags, UINT_PTR id, wchar_t *str);
bool MsInsertMenu(HMENU hMenu, UINT pos, UINT flags, UINT_PTR id_new_item, wchar_t *lp_new_item);
bool CALLBACK MsEnumChildWindowProc(HWND hWnd, LPARAM lParam);
BOOL CALLBACK EnumTopWindowProc(HWND hWnd, LPARAM lParam);
bool CALLBACK MsEnumThreadWindowProc(HWND hWnd, LPARAM lParam);
HANDLE MsCreateUserToken();
SID *MsGetSidFromAccountName(char *name);
void MsFreeSid(SID *sid);
bool CALLBACK MsEnumResourcesInternalProc(HMODULE hModule, const char *type, char *name, LONG_PTR lParam);
void CALLBACK MsScmDispatcher(DWORD argc, LPTSTR *argv);
LRESULT CALLBACK MsSuspendHandlerWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
void MsSuspendHandlerThreadProc(THREAD *thread, void *param);



#endif	// MICROSOFT_C

#endif	// MICROSOFT_H

#endif	// OS_WIN32


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
