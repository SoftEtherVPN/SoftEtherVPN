// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Microsoft.c
// For Microsoft Windows code
// (not compiled on non-Windows environments)

#include <GlobalConst.h>

#ifdef	WIN32

#define	MICROSOFT_C

typedef enum    _PNP_VETO_TYPE {
    PNP_VetoTypeUnknown,            // Name is unspecified
    PNP_VetoLegacyDevice,           // Name is an Instance Path
    PNP_VetoPendingClose,           // Name is an Instance Path
    PNP_VetoWindowsApp,             // Name is a Module
    PNP_VetoWindowsService,         // Name is a Service
    PNP_VetoOutstandingOpen,        // Name is an Instance Path
    PNP_VetoDevice,                 // Name is an Instance Path
    PNP_VetoDriver,                 // Name is a Driver Service Name
    PNP_VetoIllegalDeviceRequest,   // Name is an Instance Path
    PNP_VetoInsufficientPower,      // Name is unspecified
    PNP_VetoNonDisableable,         // Name is an Instance Path
    PNP_VetoLegacyDriver,           // Name is a Service
    PNP_VetoInsufficientRights      // Name is unspecified
}   PNP_VETO_TYPE, *PPNP_VETO_TYPE;

#define	_WIN32_IE			0x0600
#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#define   SECURITY_WIN32
#include <winsock2.h>
#include <windows.h>
#include <Wintrust.h>
#include <Softpub.h>
#include <Iphlpapi.h>
#include <ws2ipdef.h>
#include <netioapi.h>
#include <tlhelp32.h>
#include <wincon.h>
#include <Nb30.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <setupapi.h>
#include <regstr.h>
#include <process.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <Ntsecapi.h>
#include <security.h>
#include <Msi.h>
#include <Msiquery.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <cfgmgr32.h>
#include <sddl.h>
#include <Aclapi.h>

static MS *ms = NULL;

// Function prototype
UINT MsgBox(HWND hWnd, UINT flag, wchar_t *msg);
UINT MsgBoxEx(HWND hWnd, UINT flag, wchar_t *msg, ...);
void ShowTcpIpConfigUtil(HWND hWnd, bool util_mode);
void CmTraffic(HWND hWnd);
void CnStart();
void InitCedar();
void FreeCedar();
void InitWinUi(wchar_t *software_name, char *font, UINT fontsize);
void FreeWinUi();

// Global variable
UINT64 ms_uint64_1 = 0;

// Adapter list related
static LOCK *lock_adapter_list = NULL;
static MS_ADAPTER_LIST *last_adapter_list = NULL;

// Service related
static SERVICE_STATUS_HANDLE ssh = NULL;
static SERVICE_STATUS status = { 0 };
static HANDLE service_stop_event = NULL;
static BOOL (WINAPI *_StartServiceCtrlDispatcher)(CONST LPSERVICE_TABLE_ENTRY) = NULL;
static SERVICE_STATUS_HANDLE (WINAPI *_RegisterServiceCtrlHandler)(LPCTSTR, LPHANDLER_FUNCTION) = NULL;
static BOOL (WINAPI *_SetServiceStatus)(SERVICE_STATUS_HANDLE, LPSERVICE_STATUS) = NULL;
static char g_service_name[MAX_SIZE];
static SERVICE_FUNCTION *g_start, *g_stop;
static bool exiting = false;
static bool wnd_end;
static bool is_usermode = false;
static bool wts_is_locked_flag = false;
static HICON tray_icon;
static NOTIFYICONDATA nid;
static NOTIFYICONDATAW nid_nt;
static bool service_for_9x_mode = false;
static THREAD *service_stopper_thread = NULL;
static bool tray_inited = false;
static HWND hWndUsermode = NULL;
static HANDLE hLsa = NULL;
static ULONG lsa_package_id = 0;
static TOKEN_SOURCE lsa_token_source;
static LOCK *vlan_lock = NULL;
static COUNTER *suspend_handler_singleton = NULL;
static COUNTER *vlan_card_counter = NULL;
static volatile BOOL vlan_card_should_stop_flag = false;
static volatile BOOL vlan_is_in_suspend_mode = false;
static volatile UINT64 vlan_suspend_mode_begin_tick = 0;

// msi.dll
static HINSTANCE hMsi = NULL;
static UINT (WINAPI *_MsiGetProductInfoW)(LPCWSTR, LPCWSTR, LPWSTR, LPDWORD) = NULL;
static UINT (WINAPI *_MsiConfigureProductW)(LPCWSTR, int, INSTALLSTATE) = NULL;
static INSTALLUILEVEL (WINAPI *_MsiSetInternalUI)(INSTALLUILEVEL, HWND *) = NULL;
static INSTALLSTATE (WINAPI *_MsiLocateComponentW)(LPCWSTR, LPWSTR, LPDWORD) = NULL;

#define SE_GROUP_INTEGRITY                 (0x00000020L)

typedef enum _TOKEN_INFORMATION_CLASS_VISTA
{
	VistaTokenUser = 1,
	VistaTokenGroups,
	VistaTokenPrivileges,
	VistaTokenOwner,
	VistaTokenPrimaryGroup,
	VistaTokenDefaultDacl,
	VistaTokenSource,
	VistaTokenType,
	VistaTokenImpersonationLevel,
	VistaTokenStatistics,
	VistaTokenRestrictedSids,
	VistaTokenSessionId,
	VistaTokenGroupsAndPrivileges,
	VistaTokenSessionReference,
	VistaTokenSandBoxInert,
	VistaTokenAuditPolicy,
	VistaTokenOrigin,
	VistaTokenElevationType,
	VistaTokenLinkedToken,
	VistaTokenElevation,
	VistaTokenHasRestrictions,
	VistaTokenAccessInformation,
	VistaTokenVirtualizationAllowed,
	VistaTokenVirtualizationEnabled,
	VistaTokenIntegrityLevel,
	VistaTokenUIAccess,
	VistaTokenMandatoryPolicy,
	VistaTokenLogonSid,
	VistaMaxTokenInfoClass
} TOKEN_INFORMATION_CLASS_VISTA, *PTOKEN_INFORMATION_CLASS_VISTA;

typedef struct MS_MSCHAPV2_PARAMS
{
	wchar_t Username[MAX_SIZE];
	wchar_t Workstation[MAX_SIZE];
	wchar_t Domain[MAX_SIZE];
	UCHAR ClientResponse24[24];
	UCHAR ResponseBuffer[MAX_SIZE];
} MS_MSCHAPV2_PARAMS;

// The function which should be called once as soon as possible after the process is started
void MsInitProcessCallOnce()
{
	// Mitigate the DLL injection attack
	char system_dir[MAX_PATH];
	char kernel32_path[MAX_PATH];
	UINT len;
	HINSTANCE hKernel32;

	// Get the full path of kernel32.dll
	memset(system_dir, 0, sizeof(system_dir));
	GetSystemDirectory(system_dir, sizeof(system_dir));
	len = lstrlenA(system_dir);
	if (system_dir[len] == '\\')
	{
		system_dir[len] = 0;
	}
	wsprintfA(kernel32_path, "%s\\kernel32.dll", system_dir);

	// Load kernel32.dll
	hKernel32 = LoadLibraryA(kernel32_path);
	if (hKernel32 != NULL)
	{
		BOOL (WINAPI *_SetDllDirectoryA)(LPCTSTR);

		_SetDllDirectoryA = (BOOL (WINAPI *)(LPCTSTR))
			GetProcAddress(hKernel32, "SetDllDirectoryA");

		if (_SetDllDirectoryA != NULL)
		{
			_SetDllDirectoryA("");
		}

		FreeLibrary(hKernel32);
	}
}

// Collect the information of the VPN software
bool MsCollectVpnInfo(BUF *bat, char *tmpdir, char *svc_name, wchar_t *config_name, wchar_t *logdir_name)
{
	wchar_t *inst_dir;
	char subkey[MAX_PATH];
	bool ret = false;
	wchar_t tmpdir_w[MAX_PATH];
	// Validate arguments
	if (bat == NULL || tmpdir == NULL || svc_name == NULL || config_name == NULL || logdir_name == NULL)
	{
		return false;
	}

	StrToUni(tmpdir_w, sizeof(tmpdir_w), tmpdir);

	Format(subkey, sizeof(subkey), "SOFTWARE\\" GC_REG_COMPANY_NAME "\\Setup Wizard Settings\\%s", svc_name);
	inst_dir = MsRegReadStrEx2W(REG_LOCAL_MACHINE, subkey, "InstalledDir", false, true);
	if (UniIsEmptyStr(inst_dir) == false)
	{
		wchar_t config_src[MAX_PATH];
		wchar_t config_dst[MAX_PATH];
		wchar_t log_dir[MAX_PATH];
		DIRLIST *dir;
		UINT64 max_dt_file = 0;

		// config file
		CombinePathW(config_src, sizeof(config_src), inst_dir, config_name);
		UniFormat(config_dst, sizeof(config_dst), L"%s\\%S_%s", tmpdir_w, svc_name, config_name);
		ret = FileCopyExW(config_src, config_dst, false);

		// Log file
		CombinePathW(log_dir, sizeof(log_dir), inst_dir, logdir_name);

		dir = EnumDirW(log_dir);

		if (dir != NULL)
		{
			UINT i;
			DIRENT *latest_log = NULL;

			for (i = 0;i < dir->NumFiles;i++)
			{
				DIRENT *e = dir->File[i];

				// Get the most recent file
				if (max_dt_file <= e->UpdateDate)
				{
					max_dt_file = e->UpdateDate;

					latest_log = e;
				}
			}

			if (latest_log != NULL)
			{
				wchar_t fullpath[MAX_SIZE];
				IO *f;

				// Open the log file
				CombinePathW(fullpath, sizeof(fullpath), log_dir, latest_log->FileNameW);
				f = FileOpenExW(fullpath, false, false);

				if (f != NULL)
				{
					UINT size = FileSize(f);

					if (size >= 1)
					{
						UINT copy_size = 1024 * 1024;
						UINT seek_size = 0;
						UCHAR *buf;

						if (copy_size < size)
						{
							seek_size = size - copy_size;
						}
						else
						{
							copy_size = size;
						}

						FileSeek(f, 0, seek_size);

						buf = Malloc(copy_size + 3);
						buf[0] = 0xEF;
						buf[1] = 0xBB;
						buf[2] = 0xBF;
						if (FileRead(f, buf + 3, copy_size))
						{
							char log_dst_filename[MAX_PATH];

							Format(log_dst_filename, sizeof(log_dst_filename), "%s\\lastlog_%s_%s",
								tmpdir, svc_name, latest_log->FileName);

							SaveFile(log_dst_filename, buf, copy_size + 3);
						}

						Free(buf);
					}

					FileClose(f);
				}
			}

			FreeDir(dir);
		}
	}
	Free(inst_dir);

	return ret;
}

// Save the system information
bool MsSaveSystemInfo(wchar_t *dst_filename)
{
	char tmpdir[MAX_PATH];
	UCHAR rand_data[SHA1_SIZE];
	char rand_str[MAX_SIZE];
	char filename_bat[MAX_PATH];
	BUF *bat;
	char tmp[MAX_PATH];
	char cmd[MAX_PATH];
	char cmd_arg[MAX_PATH];
	bool ret = false;
	DIRLIST *dir;
	UINT i;
	// Validate arguments
	if (dst_filename == NULL)
	{
		return false;
	}
	if (MsIsAdmin() == false || MsIsWin2000OrGreater() == false)
	{
		return false;
	}

	Rand(rand_data, sizeof(rand_data));
	BinToStr(rand_str, sizeof(rand_str), rand_data, 4);

	// Create a temporary directory
	Format(tmpdir, sizeof(tmpdir), "%s\\Temp\\se_support_%s", MsGetWindowsDir(), rand_str);
	MakeDirEx(tmpdir);

	// Create a batch file
	CombinePath(filename_bat, sizeof(filename_bat), tmpdir, "make_system_info.cmd");
	bat = NewBuf();

	Format(tmp, sizeof(tmp), "systeminfo > %s\\SystemInfo.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "ipconfig > %s\\ipconfig.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "netsh dump > %s\\netsh.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "route print > %s\\route.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "netstat -nab > %s\\netstat_nab.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "netstat -nao > %s\\netstat_nao.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "netstat -na > %s\\netstat_na.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "netstat -fab > %s\\netstat_fab.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "netstat -fao > %s\\netstat_fao.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "netstat -fa > %s\\netstat_fa.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "netstat -ab > %s\\netstat_ab.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "netstat -ao > %s\\netstat_ao.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "netstat -a > %s\\netstat_a.txt", tmpdir);
	WriteBufLine(bat, tmp);

	Format(tmp, sizeof(tmp), "\"%s\\Common Files\\Microsoft Shared\\MSInfo\\msinfo32.exe\" /report %s\\SystemInfo.txt", MsGetProgramFilesDir(), tmpdir);
	WriteBufLine(bat, tmp);

	// Collect the information of the VPN software
	MsCollectVpnInfo(bat, tmpdir, "vpnclient", L"vpn_client.config", L"client_log");
	MsCollectVpnInfo(bat, tmpdir, "vpnserver", L"vpn_server.config", L"server_log");
	MsCollectVpnInfo(bat, tmpdir, "vpnbridge", L"vpn_bridge.config", L"server_log");

	MsCollectVpnInfo(bat, tmpdir, "sevpnclient", L"vpn_client.config", L"client_log");
	MsCollectVpnInfo(bat, tmpdir, "sevpnserver", L"vpn_server.config", L"server_log");
	MsCollectVpnInfo(bat, tmpdir, "sevpnbridge", L"vpn_bridge.config", L"server_log");

	WriteBufLine(bat, "");

	DumpBuf(bat, filename_bat);

	FreeBuf(bat);

	// Run the batch file
	CombinePath(cmd, sizeof(cmd), MsGetSystem32Dir(), "cmd.exe");
	Format(cmd_arg, sizeof(cmd_arg), "/C %s", filename_bat);
	if (Win32Run(cmd, cmd_arg, false, true))
	{
		dir = EnumDir(tmpdir);
		if (dir != NULL)
		{
			ZIP_PACKER *zip;
			zip = NewZipPacker();

			for (i = 0;i < dir->NumFiles;i++)
			{
				char *name = dir->File[i]->FileName;
				char full[MAX_PATH];

				CombinePath(full, sizeof(full), tmpdir, name);

				ZipAddRealFile(zip, name, SystemTime64(), 0, full);
			}
			FreeDir(dir);

			ret = ZipWriteW(zip, dst_filename);
			FreeZipPacker(zip);
		}
	}

	// Delete the temporary directory
	dir = EnumDir(tmpdir);
	if (dir != NULL)
	{
		for (i = 0;i < dir->NumFiles;i++)
		{
			char *name = dir->File[i]->FileName;
			char full[MAX_PATH];

			CombinePath(full, sizeof(full), tmpdir, name);

			if (EndWith(full, ".txt") || EndWith(full, ".cmd") || EndWith(full, ".config") || EndWith(full, ".log"))
			{
				FileDelete(full);
			}
		}
		FreeDir(dir);
	}
	DeleteDir(tmpdir);

	return ret;
}

// Determine whether this is running in a VM
bool MsIsInVmMain()
{
	char *bat_data = "On Error Resume Next\r\n\r\nDim str\r\n\r\nSet wmi_svc = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2\")\r\n\r\nSet items = wmi_svc.ExecQuery(\"Select * from Win32_BaseBoard\")\r\n\r\nFor Each item in items\r\n	str = str & item.Manufacturer\r\nNext\r\n\r\nSet items = Nothing\r\n\r\nSet items = wmi_svc.ExecQuery(\"Select * from Win32_ComputerSystem\")\r\n\r\nFor Each item in items\r\n	str = str & item.Manufacturer\r\nNext\r\n\r\nSet items = Nothing\r\n\r\nSet wmi_svc = Nothing\r\n\r\nstr = LCase(str)\r\n\r\nDim ret\r\n\r\nret = 0\r\n\r\nif InStr(str, \"microsoft corporation\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"vmware\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"virtualbox\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"virtualpc\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"xen\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"hvm\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"domu\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"kvm\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"oracle vm\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"qemu\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"parallels\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"xvm\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"virtual\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nif InStr(str, \"bochs\") > 0 then\r\n	ret = 1\r\nend if\r\n\r\nwscript.quit ret\r\n\r\n";
	wchar_t bat_filename[MAX_SIZE];
	wchar_t cscript_exe[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	void *process;
	bool ret = false;

	if (MsIsNt() == false)
	{
		return false;
	}

	if (MsIsWin2000OrGreater() == false)
	{
		return false;
	}

	CombinePathW(bat_filename, sizeof(bat_filename), MsGetMyTempDirW(), L"detectvm.vbs");

	if (DumpDataW(bat_data, StrLen(bat_data), bat_filename) == false)
	{
		return false;
	}

	CombinePathW(cscript_exe, sizeof(cscript_exe), MsGetSystem32DirW(), L"cscript.exe");

	UniFormat(tmp, sizeof(tmp), L"\"%s\"", bat_filename);

	process = Win32RunEx3W(cscript_exe, tmp, true, NULL, true);

	if (process == NULL)
	{
		return false;
	}

	if (Win32WaitProcess(process, 30000))
	{
		DWORD exit_code = 0;

		if (GetExitCodeProcess(process, &exit_code))
		{
			if (exit_code == 1)
			{
				ret = true;
			}
		}
	}

	Win32CloseProcess(process);

	return ret;
}
bool MsIsInVm()
{
	static bool flag_detected = false;
	static bool flag_is_vm = false;

	if (flag_detected == false)
	{
		flag_is_vm = MsIsInVmMain();

		flag_detected = true;
	}

	return flag_is_vm;
}

// Get the current module handle
void *MsGetCurrentModuleHandle()
{
	return ms->hInst;
}

// Resource enumeration procedure
bool CALLBACK MsEnumResourcesInternalProc(HMODULE hModule, const char *type, char *name, LONG_PTR lParam)
{
	LIST *o = (LIST *)lParam;
	// Validate arguments
	if (type == NULL || name == NULL || o == NULL)
	{
		return true;
	}

	Add(o, CopyStr(name));

	return true;
}

// Enumeration of resources
TOKEN_LIST *MsEnumResources(void *hModule, char *type)
{
	LIST *o;
	TOKEN_LIST *ret;
	// Validate arguments
	if (hModule == NULL)
	{
		hModule = MsGetCurrentModuleHandle();
	}
	if (type == NULL)
	{
		return NullToken();
	}

	o = NewListFast(NULL);

	if (EnumResourceNamesA(hModule, type, MsEnumResourcesInternalProc, (LONG_PTR)o) == false)
	{
		ReleaseList(o);
		return NullToken();
	}

	ret = ListToTokenList(o);

	FreeStrList(o);

	return ret;
}

// Get whether the locale ID of the current user is Japanese
bool MsIsCurrentUserLocaleIdJapanese()
{
	UINT lcid = MsGetUserLocaleId();

	if (lcid == 1041)
	{
		return true;
	}

	return false;
}

// Get the locale ID of the user
UINT MsGetUserLocaleId()
{
	static UINT lcid_cache = 0;

	if (lcid_cache == 0)
	{
		lcid_cache = (UINT)GetUserDefaultLCID();
	}

	return lcid_cache;
}

// Set a secure ACL to the specified file or directory
bool MsSetFileSecureAcl(wchar_t *path)
{
	SID *sid_system;
	SID *sid_admin;
	bool ret = false;
	// Validate arguments
	if (path == NULL)
	{
		return false;
	}
	if (ms->nt == NULL)
	{
		return false;
	}
	if (ms->nt->SetNamedSecurityInfoW == NULL || ms->nt->AddAccessAllowedAceEx == NULL)
	{
		return false;
	}

	sid_system = MsGetSidFromAccountName("SYSTEM");
	sid_admin = MsGetSidFromAccountName("Administrators");

	if (sid_system != NULL && sid_admin != NULL)
	{
		UINT acl_size = 4096;
		ACL *acl;

		acl = ZeroMalloc(acl_size);

		if (InitializeAcl(acl, acl_size, 2))
		{
			if (ms->nt->AddAccessAllowedAceEx(acl, 2, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE, GENERIC_ALL, sid_system) &&
				ms->nt->AddAccessAllowedAceEx(acl, 2, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE, GENERIC_ALL, sid_admin))
			{
				if (ms->nt->SetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL) == ERROR_SUCCESS)
				{
					ret = true;
				}
			}
		}

		Free(acl);
	}

	MsFreeSid(sid_system);
	MsFreeSid(sid_admin);

	return ret;
}

// Disable the minimization function of the number of network connections by WCM
void MsDisableWcmNetworkMinimize()
{
	MS_WCM_POLICY_VALUE v;
	bool b;
	if (ms->nt == NULL)
	{
		return;
	}
	if (ms->nt->WcmQueryProperty == NULL || ms->nt->WcmSetProperty == NULL || ms->nt->WcmFreeMemory == NULL || ms->nt->WcmGetProfileList == NULL)
	{
		return;
	}

	if (MsIsWindows8() == false)
	{
		return;
	}

	Zero(&v, sizeof(v));
	v.fIsGroupPolicy = true;
	v.fValue = false;
	b = false;
	ms->nt->WcmSetProperty(NULL, NULL, ms_wcm_global_property_minimize_policy, NULL, sizeof(v), (const BYTE *)&v);
	ms->nt->WcmSetProperty(NULL, NULL, ms_wcm_global_property_minimize_policy, NULL, sizeof(b), (const BYTE *)&b);

	Zero(&v, sizeof(v));
	v.fIsGroupPolicy = true;
	v.fValue = false;
	b = false;
	ms->nt->WcmSetProperty(NULL, NULL, ms_wcm_global_property_domain_policy, NULL, sizeof(v), (const BYTE *)&v);
	ms->nt->WcmSetProperty(NULL, NULL, ms_wcm_global_property_domain_policy, NULL, sizeof(b), (const BYTE *)&b);

	Zero(&v, sizeof(v));
	v.fIsGroupPolicy = false;
	v.fValue = false;
	ms->nt->WcmSetProperty(NULL, NULL, ms_wcm_global_property_minimize_policy, NULL, sizeof(v), (const BYTE *)&v);
	ms->nt->WcmSetProperty(NULL, NULL, ms_wcm_global_property_minimize_policy, NULL, sizeof(b), (const BYTE *)&b);

	Zero(&v, sizeof(v));
	v.fIsGroupPolicy = false;
	v.fValue = false;
	ms->nt->WcmSetProperty(NULL, NULL, ms_wcm_global_property_domain_policy, NULL, sizeof(v), (const BYTE *)&v);
	ms->nt->WcmSetProperty(NULL, NULL, ms_wcm_global_property_domain_policy, NULL, sizeof(b), (const BYTE *)&b);
}

// Request the MS-CHAPv2 authentication to the LSA
bool MsPerformMsChapV2AuthByLsa(char *username, UCHAR *challenge8, UCHAR *client_response_24, UCHAR *ret_pw_hash_hash)
{
	bool ret = false;
	char user[MAX_SIZE];
	char domain[MAX_SIZE];
	wchar_t workstation[MAX_SIZE + 1];
	LSA_STRING origin;
	MSV1_0_LM20_LOGON *m;
	MS_MSCHAPV2_PARAMS *p;
	UINT m_size;
	DWORD sz;
	void *profile_buffer = NULL;
	LUID logon_id;
	UINT profile_buffer_size = 0;
	UINT i;
	HANDLE hLogon = NULL;
	QUOTA_LIMITS q;
	char *origin_str = "SE-VPN";
	NTSTATUS sub_status = 0;
	// Validate arguments
	if (username == NULL || challenge8 == NULL || client_response_24 == NULL || ret_pw_hash_hash == NULL)
	{
		return false;
	}
	if (hLsa == NULL)
	{
		return false;
	}

	ParseNtUsername(username, user, sizeof(user), domain, sizeof(domain), false);

	// Get the machine name
	Zero(workstation, sizeof(workstation));
	sz = MAX_SIZE;
	GetComputerNameW(workstation, &sz);

	// Build a MSV1_0_INTERACTIVE_LOGON
	m_size = sizeof(MSV1_0_LM20_LOGON) + sizeof(MS_MSCHAPV2_PARAMS);
	m = ZeroMalloc(m_size);
	p = (MS_MSCHAPV2_PARAMS *)(((UCHAR *)m) + sizeof(MSV1_0_LM20_LOGON));

	StrToUni(p->Username, sizeof(p->Username), user);
	StrToUni(p->Domain, sizeof(p->Domain), domain);
	UniStrCpy(p->Workstation, sizeof(p->Workstation), workstation);
	Copy(p->ClientResponse24, client_response_24, 24);

	m->MessageType = MsV1_0Lm20Logon;

	// User name
	m->UserName.Length = m->UserName.MaximumLength = (USHORT)(UniStrLen(p->Username) * sizeof(wchar_t));
	m->UserName.Buffer = p->Username;

	// Workstation name
	m->Workstation.Length = m->Workstation.MaximumLength = (USHORT)(UniStrLen(p->Workstation) * sizeof(wchar_t));
	m->Workstation.Buffer = p->Workstation;

	// Domain name
	if (IsEmptyUniStr(p->Domain) == false)
	{
		m->LogonDomainName.Length = m->LogonDomainName.MaximumLength = (USHORT)(UniStrLen(p->Domain) * sizeof(wchar_t));
		m->LogonDomainName.Buffer = p->Domain;
	}

	// Challenge
	Copy(m->ChallengeToClient, challenge8, 8);

	// Response
	m->CaseInsensitiveChallengeResponse.Length = m->CaseInsensitiveChallengeResponse.MaximumLength = 24;
	m->CaseInsensitiveChallengeResponse.Buffer = p->ClientResponse24;

	m->CaseSensitiveChallengeResponse.Length = m->CaseSensitiveChallengeResponse.MaximumLength = sizeof(p->ResponseBuffer);
	m->CaseSensitiveChallengeResponse.Buffer = p->ResponseBuffer;

	m->ParameterControl = MSV1_0_ALLOW_MSVCHAPV2;

	Zero(&origin, sizeof(origin));
	origin.Length = origin.MaximumLength = StrLen(origin_str);
	origin.Buffer = origin_str;

	Zero(&logon_id, sizeof(logon_id));
	Zero(&q, sizeof(q));

	i = ms->nt->LsaLogonUser(hLsa, &origin, Network, lsa_package_id, m, m_size, NULL, &lsa_token_source,
		&profile_buffer, &profile_buffer_size, &logon_id, &hLogon, &q, &sub_status);

	if (i == 0)
	{
		if (profile_buffer != NULL)
		{
			MSV1_0_LM20_LOGON_PROFILE *response = (MSV1_0_LM20_LOGON_PROFILE *)profile_buffer;

			Copy(ret_pw_hash_hash, response->UserSessionKey, 16);

			ret = true;

			ms->nt->LsaFreeReturnBuffer(profile_buffer);
		}
		CloseHandle(hLogon);
	}

	Free(m);

	return ret;
}

// Send a pulse
void MsSendGlobalPulse(void *p)
{
	HANDLE h;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	h = (HANDLE)p;

	PulseEvent(h);
}

// Release a pulse
void MsCloseGlobalPulse(void *p)
{
	HANDLE h;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	h = (HANDLE)p;

	CloseHandle(h);
}

// Wait for arriving the pulse
bool MsWaitForGlobalPulse(void *p, UINT timeout)
{
	HANDLE h;
	UINT ret;
	// Validate arguments
	if (p == NULL)
	{
		return false;
	}
	if (timeout == TIMEOUT_INFINITE)
	{
		timeout = INFINITE;
	}

	h = (HANDLE)p;

	ret = WaitForSingleObject(h, timeout);

	if (ret == WAIT_OBJECT_0)
	{
		return true;
	}

	return false;
}

// Open or create a pulse
void *MsOpenOrCreateGlobalPulse(char *name)
{
	UCHAR hash[20];
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	HANDLE h;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	StrCpy(tmp, sizeof(tmp), name);
	Trim(tmp);
	StrUpper(tmp);

	Sha1(hash, name, StrLen(name));

	BinToStr(tmp, sizeof(tmp), hash, sizeof(hash));

	Format(tmp2, sizeof(tmp2), "GlobalPulse_%s", tmp);

	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType))
	{
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2 ||
			GetOsInfo()->OsType == OSTYPE_WINDOWS_NT_4_TERMINAL_SERVER)
		{
			Format(tmp2, sizeof(tmp2), "Global\\GlobalPulse_%s", tmp);
		}
	}

	h = CreateEvent(NULL, true, false, tmp2);

	return (void *)h;
}

// Stop the IPsec service
bool MsStopIPsecService()
{
	if (MsIsServiceRunning(MsGetIPsecServiceName()))
	{
		Debug("Stopping Windows Service: %s\n", MsGetIPsecServiceName());
		if (MsStopService(MsGetIPsecServiceName()))
		{
			return true;
		}
	}

	return false;
}

// Start the IPsec service
bool MsStartIPsecService()
{
	if (MsIsServiceRunning(MsGetIPsecServiceName()) == false)
	{
		Debug("Starting Windows Service: %s\n", MsGetIPsecServiceName());
		return MsStartService(MsGetIPsecServiceName());
	}

	return false;
}

// Get the IPsec service name
char *MsGetIPsecServiceName()
{
	char *svc_name = "PolicyAgent";

	if (MsIsVista())
	{
		svc_name = "ikeext";
	}

	return svc_name;
}

// Initialize the global lock
void *MsInitGlobalLock(char *name, bool ts_local)
{
	char tmp[MAX_SIZE];
	HANDLE h;
	// Validate arguments
	if (name == NULL)
	{
		name = "default_global_lock";
	}

	if (ts_local)
	{
		HashInstanceNameLocal(tmp, sizeof(tmp), name);
	}
	else
	{
		HashInstanceName(tmp, sizeof(tmp), name);
	}

	h = CreateMutexA(NULL, false, tmp);
	if (h == NULL || h == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	return (void *)h;
}

// Get a global lock
void MsGlobalLock(void *p)
{
	HANDLE h = (HANDLE)p;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	WaitForSingleObject(p, INFINITE);
}

// Unlock the global lock
void MsGlobalUnlock(void *p)
{
	HANDLE h = (HANDLE)p;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	ReleaseMutex(h);
}

// Release the global lock
void MsFreeGlobalLock(void *p)
{
	HANDLE h = (HANDLE)p;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	CloseHandle(h);
}


// Set the mode not to show the errors
void MsSetErrorModeToSilent()
{
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
}

// Get the file information
bool MsGetFileInformation(void *h, void *info)
{
	// Validate arguments
	if (h == INVALID_HANDLE_VALUE || info == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		return false;
	}

	if (ms->nt->GetFileInformationByHandle == NULL)
	{
		return false;
	}

	return ms->nt->GetFileInformationByHandle(h, info);
}

// Set the shutdown parameters of the process
void MsSetShutdownParameters(UINT level, UINT flag)
{
	if (MsIsNt() == false)
	{
		return;
	}

	if (ms->nt == false || ms->nt->SetProcessShutdownParameters == NULL)
	{
		return;
	}

	ms->nt->SetProcessShutdownParameters(level, flag);
}

// Get whether the version of the OS is Windows XP or Windows Vista or later
bool MsIsWinXPOrWinVista()
{
	OS_INFO *info = GetOsInfo();
	if (info == NULL)
	{
		return false;
	}

	if (OS_IS_WINDOWS_NT(info->OsType) == false)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) >= 3)
	{
		return true;
	}

	return false;
}

// Restart of MMCSS
void MsRestartMMCSS()
{
	MsStopService("CTAudSvcService");
	MsStopService("audiosrv");
	MsStopService("MMCSS");
	MsStartService("MMCSS");
	MsStartService("audiosrv");
	MsStartService("CTAudSvcService");
}

// Enable / disable network throttling by MMCSS
void MsSetMMCSSNetworkThrottlingEnable(bool enable)
{
	UINT value;
	if (MsIsVista() == false)
	{
		return;
	}

	if (enable)
	{
		value = 0x0000000a;
	}
	else
	{
		value = 0xffffffff;
	}

	MsRegWriteIntEx2(REG_LOCAL_MACHINE, MMCSS_PROFILE_KEYNAME, "NetworkThrottlingIndex",
		value,
		false, true);

	MsRestartMMCSS();
}

// Examine whether the Network throttling by MMCSS is enabled
bool MsIsMMCSSNetworkThrottlingEnabled()
{
	UINT value;
	if (MsIsVista() == false)
	{
		return false;
	}

	if (MsRegIsKeyEx2(REG_LOCAL_MACHINE, MMCSS_PROFILE_KEYNAME, false, true) == false)
	{
		return false;
	}

	value = MsRegReadIntEx2(REG_LOCAL_MACHINE, MMCSS_PROFILE_KEYNAME,
		"NetworkThrottlingIndex", false, true);

	if (value == 0)
	{
		return false;
	}

	if (value == 0x0000000a)
	{
		return true;
	}

	return false;
}

typedef struct _ASTAT_
{
	ADAPTER_STATUS adapt;
	NAME_BUFFER    NameBuff[30];
} ASTAT, *PASTAT;

// Get the precise time from the value of the high-resolution counter
double MsGetHiResTimeSpan(UINT64 diff)
{
	LARGE_INTEGER t;
	UINT64 freq;

	if (QueryPerformanceFrequency(&t) == false)
	{
		freq = 1000ULL;
	}
	else
	{
		Copy(&freq, &t, sizeof(UINT64));
	}

	return (double)diff / (double)freq;
}
UINT64 MsGetHiResTimeSpanUSec(UINT64 diff)
{
	LARGE_INTEGER t;
	UINT64 freq;

	if (QueryPerformanceFrequency(&t) == false)
	{
		freq = 1000ULL;
	}
	else
	{
		Copy(&freq, &t, sizeof(UINT64));
	}

	return (UINT64)(diff) * 1000ULL * 1000ULL / (UINT64)freq;
}

// Get a high-resolution counter
UINT64 MsGetHiResCounter()
{
	LARGE_INTEGER t;
	UINT64 ret;

	if (QueryPerformanceCounter(&t) == false)
	{
		return Tick64();
	}

	Copy(&ret, &t, sizeof(UINT64));

	return ret;
}

// System-wide updating notification
void MsUpdateSystem()
{
	static DWORD dw = 0;

	SendMessageTimeoutA(HWND_BROADCAST, WM_WININICHANGE, 0, 0, SMTO_NORMAL, 1, (PDWORD_PTR)&dw);
	SleepThread(25);
	SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)"Environment", SMTO_NORMAL, 1, (PDWORD_PTR)&dw);
	SleepThread(25);
	SHChangeNotify(SHCNE_GLOBALEVENTS, SHCNF_IDLIST | SHCNF_FLUSHNOWAIT | SHCNF_NOTIFYRECURSIVE, NULL, NULL);
	SleepThread(25);
	SHChangeNotify(SHCNE_GLOBALEVENTS, SHCNF_IDLIST, NULL, NULL);
	SleepThread(25);
	SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST | SHCNF_FLUSHNOWAIT | SHCNF_NOTIFYRECURSIVE, NULL, NULL);
	SleepThread(25);
	SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
	SleepThread(25);
	SHChangeNotify(SHCNE_ALLEVENTS, SHCNF_IDLIST | SHCNF_FLUSHNOWAIT | SHCNF_NOTIFYRECURSIVE, NULL, NULL);
	SleepThread(25);
	SHChangeNotify(SHCNE_ALLEVENTS, SHCNF_IDLIST, NULL, NULL);
	SleepThread(25);
}

// Wait for the process termination
UINT MsWaitProcessExit(void *process_handle)
{
	HANDLE h = (HANDLE)process_handle;
	UINT ret = 1;

	if (h == NULL)
	{
		return 1;
	}

	while (true)
	{
		WaitForSingleObject(h, INFINITE);

		ret = 1;
		if (GetExitCodeProcess(h, &ret) == false)
		{
			break;
		}

		if (ret != STILL_ACTIVE)
		{
			break;
		}
	}

	CloseHandle(h);

	return ret;
}

// Execution of the file (to get process handle)
bool MsExecuteEx(char *exe, char *arg, void **process_handle)
{
	return MsExecuteEx2(exe, arg, process_handle, false);
}
bool MsExecuteEx2(char *exe, char *arg, void **process_handle, bool runas)
{
	SHELLEXECUTEINFO info;
	HANDLE h;
	// Validate arguments
	if (exe == NULL || process_handle == NULL)
	{
		return false;
	}

	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.lpVerb = (runas ? "runas" : "open");
	info.lpFile = exe;
	info.fMask = SEE_MASK_NOCLOSEPROCESS;
	info.lpParameters = arg;
	info.nShow = SW_SHOWNORMAL;
	if (ShellExecuteEx(&info) == false)
	{
		return false;
	}

	h = info.hProcess;

	*process_handle = (void *)h;

	return true;
}
bool MsExecuteEx2W(wchar_t *exe, wchar_t *arg, void **process_handle, bool runas)
{
	SHELLEXECUTEINFOW info;
	HANDLE h;
	// Validate arguments
	if (exe == NULL || process_handle == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char exe_a[MAX_SIZE];
		char arg_a[MAX_SIZE];

		UniToStr(exe_a, sizeof(exe_a), exe);
		UniToStr(arg_a, sizeof(arg_a), arg);

		return MsExecuteEx(exe_a, arg_a, process_handle);
	}

	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.lpVerb = (runas ? L"runas" : L"open");
	info.lpFile = exe;
	info.fMask = SEE_MASK_NOCLOSEPROCESS;
	info.lpParameters = arg;
	info.nShow = SW_SHOWNORMAL;
	if (ShellExecuteExW(&info) == false)
	{
		return false;
	}

	h = info.hProcess;

	*process_handle = (void *)h;

	return true;
}

// Close the handle
void MsCloseHandle(void *handle)
{
	if (handle != NULL)
	{
		CloseHandle(handle);
	}
}

// Execution of the file
bool MsExecute(char *exe, char *arg)
{
	return MsExecute2(exe, arg, false);
}
bool MsExecute2(char *exe, char *arg, bool runas)
{
	DWORD d;
	// Validate arguments
	if (exe == NULL)
	{
		return false;
	}

	d = (DWORD)ShellExecuteA(NULL, (runas ? "runas" : "open"), exe, arg, MsGetExeDirName(), SW_SHOWNORMAL);

	if (d > 32)
	{
		return true;
	}

	return false;
}
bool MsExecuteW(wchar_t *exe, wchar_t *arg)
{
	return MsExecute2W(exe, arg, false);
}
bool MsExecute2W(wchar_t *exe, wchar_t *arg, bool runas)
{
	DWORD d;
	// Validate arguments
	if (exe == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char exe_a[MAX_SIZE];
		char arg_a[MAX_SIZE];

		UniToStr(exe_a, sizeof(exe_a), exe);
		UniToStr(arg_a, sizeof(arg_a), arg);

		return MsExecute(exe_a, arg_a);
	}

	d = (DWORD)ShellExecuteW(NULL, (runas ? L"runas" : L"open"), exe, arg, MsGetExeDirNameW(), SW_SHOWNORMAL);

	if (d > 32)
	{
		return true;
	}

	return false;
}

// Recursive directory creation
void MsUniMakeDirEx(wchar_t *name)
{
	UINT wp;
	wchar_t *tmp;
	UINT i, len;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	tmp = ZeroMalloc(UniStrSize(name) * 2);
	wp = 0;
	len = UniStrLen(name);
	for (i = 0;i < len;i++)
	{
		wchar_t c = name[i];

		if (c == '\\')
		{
			if (UniStrCmpi(tmp, L"\\\\") != 0 && UniStrCmpi(tmp, L"\\") != 0)
			{
				MsUniMakeDir(tmp);
			}
		}

		tmp[wp++] = c;
	}

	Free(tmp);

	MsUniMakeDir(name);
}

// Create a directory
bool MsUniMakeDir(wchar_t *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(name);
		bool ret = MsMakeDir(s);
		Free(s);
		return ret;
	}

	return CreateDirectoryW(name, NULL);
}
bool MsMakeDir(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	return CreateDirectoryA(name, NULL);
}

static wchar_t ms_computer_name_full_cache[MAX_SIZE] = {0};

// Get the full name of the computer
void MsGetComputerNameFullEx(wchar_t *name, UINT size, bool with_cache)
{
	UINT size2 = size;
	// Validate arguments
	UniStrCpy(name, size, L"");
	if (name == NULL || size == 0)
	{
		return;
	}

	if (with_cache)
	{
		if (UniIsEmptyStr(ms_computer_name_full_cache) == false)
		{
			UniStrCpy(name, size, ms_computer_name_full_cache);
			return;
		}
	}

	if (MsIsNt() == false || ms->nt->GetComputerNameExW == NULL ||
		ms->nt->GetComputerNameExW(ComputerNameDnsFullyQualified, name, &size2) == false)
	{
		char tmp[MAX_SIZE];

		MsGetComputerName(tmp, sizeof(tmp));

		StrToUni(name, size, tmp);
	}

	if (with_cache)
	{
		UniStrCpy(ms_computer_name_full_cache, sizeof(ms_computer_name_full_cache), name);
	}
}

// Get the computer name
void MsGetComputerName(char *name, UINT size)
{
	DWORD sz;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	sz = size;
	GetComputerName(name, &sz);
}

// Get the hash value of the position of the mouse cursor
UINT MsGetCursorPosHash()
{
	POINT p;

	Zero(&p, sizeof(p));

	if (GetCursorPos(&p) == false)
	{
		return 0;
	}

	return MAKELONG((USHORT)p.x, (USHORT)p.y);
}

// Start the process as a standard user privileges
void *MsRunAsUserExW(wchar_t *filename, wchar_t *arg, bool hide)
{
	void *ret = MsRunAsUserExInnerW(filename, arg, hide);

	if (ret == NULL)
	{
		Debug("MsRunAsUserExInner Failed.\n");
		ret = Win32RunExW(filename, arg, hide);
	}

	return ret;
}
void *MsRunAsUserExInnerW(wchar_t *filename, wchar_t *arg, bool hide)
{
	STARTUPINFOW info;
	PROCESS_INFORMATION ret;
	wchar_t cmdline[MAX_SIZE];
	wchar_t name[MAX_PATH];
	HANDLE hToken;
	// Validate arguments
	if (filename == NULL)
	{
		return NULL;
	}

	if (MsIsVista() == false)
	{
		// Can not be used in non-Windows Vista
		return NULL;
	}

	UniStrCpy(name, sizeof(name), filename);
	UniTrim(name);

	if (UniSearchStr(name, L"\"", 0) == INFINITE)
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"%s %s", name, arg);
		}
	}
	else
	{
		if (arg == NULL)
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\"", name);
		}
		else
		{
			UniFormat(cmdline, sizeof(cmdline), L"\"%s\" %s", name, arg);
		}
	}

	Zero(&info, sizeof(info));
	Zero(&ret, sizeof(ret));
	info.cb = sizeof(info);
	info.dwFlags = STARTF_USESHOWWINDOW;
	info.wShowWindow = (hide == false ? SW_SHOWDEFAULT : SW_HIDE);

	UniTrim(cmdline);

	hToken = MsCreateUserToken();

	if (hToken == NULL)
	{
		return NULL;
	}

	if (ms->nt->CreateProcessAsUserW(hToken, NULL, cmdline, NULL, NULL, FALSE,
		(hide == false ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW | CREATE_NEW_CONSOLE) | NORMAL_PRIORITY_CLASS,
		NULL, NULL, &info, &ret) == FALSE)
	{
		return NULL;
	}

	CloseHandle(hToken);

	CloseHandle(ret.hThread);
	return ret.hProcess;
}

// Get the SID from the account name
SID *MsGetSidFromAccountName(char *name)
{
	SID *sid;
	UINT sid_size = 4096;
	char *domain_name;
	UINT domain_name_size = 4096;
	SID_NAME_USE use = SidTypeUser;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	if (MsIsNt() == false)
	{
		return NULL;
	}

	sid = ZeroMalloc(sid_size);
	domain_name = ZeroMalloc(domain_name_size);

	if (ms->nt->LookupAccountNameA(NULL, name, sid, &sid_size, domain_name, &domain_name_size, &use) == false)
	{
		Free(sid);
		Free(domain_name);
		return NULL;
	}

	Free(domain_name);

	return sid;
}

// Release the SID
void MsFreeSid(SID *sid)
{
	// Validate arguments
	if (sid == NULL)
	{
		return;
	}

	Free(sid);
}

// Create a token of standard user
HANDLE MsCreateUserToken()
{
	char *medium_sid = "S-1-16-8192";
	char *administrators_sid = "S-1-5-32-544";
	SID *sid = NULL;
	TOKEN_MANDATORY_LABEL til;
	HANDLE hCurrentToken, hNewToken;
	if (MsIsNt() == false)
	{
		return NULL;
	}
	if (ms->nt->ConvertStringSidToSidA == NULL ||
		ms->nt->OpenProcessToken == NULL ||
		ms->nt->DuplicateTokenEx == NULL ||
		ms->nt->GetTokenInformation == NULL ||
		ms->nt->SetTokenInformation == NULL)
	{
		return NULL;
	}

	Zero(&til, sizeof(til));

	if (ms->nt->ConvertStringSidToSidA(medium_sid, &sid) == false)
	{
		return NULL;
	}

	til.Label.Attributes = SE_GROUP_INTEGRITY;
	til.Label.Sid = sid;

	if (ms->nt->OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hCurrentToken) == false)
	{
		LocalFree(sid);
		return NULL;
	}

	if (ms->nt->DuplicateTokenEx(hCurrentToken, MAXIMUM_ALLOWED, NULL,
		SecurityImpersonation, TokenPrimary, &hNewToken) == false)
	{
		CloseHandle(hCurrentToken);
		LocalFree(sid);
		return NULL;
	}

	if (ms->nt->SetTokenInformation(hNewToken, VistaTokenIntegrityLevel, &til,
		sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(sid)) == false)
	{
		CloseHandle(hNewToken);
		CloseHandle(hCurrentToken);
		LocalFree(sid);
		return NULL;
	}

	CloseHandle(hCurrentToken);
	LocalFree(sid);

	return hNewToken;
}

// Check whether SHA-2 kernel mode signature is supported
bool MsIsSha2KernelModeSignatureSupported()
{
	HINSTANCE hDll;
	bool ret = false;

	if (MsIsWindows8())
	{
		return true;
	}

	hDll = LoadLibrary("Wintrust.dll");
	if (hDll == NULL)
	{
		return false;
	}

	if (GetProcAddress(hDll, "CryptCATAdminAcquireContext2") != NULL)
	{
		ret = true;
	}

	FreeLibrary(hDll);

	return ret;
}

// Check whether KB3033929 is required
bool MsIsKB3033929RequiredAndMissing()
{
	OS_INFO *info = GetOsInfo();

	if (info == NULL)
	{
		return false;
	}

	if (OS_IS_WINDOWS_NT(info->OsType))
	{
		if (GET_KETA(info->OsType, 100) == 6)
		{
			if (MsIsX64())
			{
				if (MsIsSha2KernelModeSignatureSupported() == false)
				{
					return true;
				}
			}
		}
	}

	return false;
}

// Check the digital signature of the file
bool MsCheckFileDigitalSignatureW(HWND hWnd, wchar_t *name, bool *danger)
{
	HRESULT ret = S_OK;
	wchar_t *tmp;
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

	tmp = name;

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
				if (MsCheckFileDigitalSignatureW(NULL, name, NULL) == false)
				{
					// It's a dangerous file, but the user had to select the [OK]
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

// Disable the WoW64 redirection
void *MsDisableWow64FileSystemRedirection()
{
	void *p = NULL;
	if (MsIs64BitWindows() == false)
	{
		return NULL;
	}

	if (ms->nt->Wow64DisableWow64FsRedirection == NULL ||
		ms->nt->Wow64RevertWow64FsRedirection == NULL)
	{
		return NULL;
	}

	if (ms->nt->Wow64DisableWow64FsRedirection(&p) == false)
	{
		return NULL;
	}

	if (p == NULL)
	{
		p = (void *)0x12345678;
	}

	return p;
}

// Restore the WoW64 redirection
void MsRestoreWow64FileSystemRedirection(void *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}
	if (p == (void *)0x12345678)
	{
		p = NULL;
	}
	if (MsIs64BitWindows() == false)
	{
		return;
	}

	if (ms->nt->Wow64DisableWow64FsRedirection == NULL ||
		ms->nt->Wow64RevertWow64FsRedirection == NULL)
	{
		return;
	}

	ms->nt->Wow64RevertWow64FsRedirection(p);
}

// Get whether the x64 version of Windows is currently running
bool MsIsX64()
{
	SYSTEM_INFO info;

	if (MsIs64BitWindows() == false)
	{
		return false;
	}
	if (ms->nt->GetNativeSystemInfo == NULL)
	{
		return false;
	}

	Zero(&info, sizeof(info));
	ms->nt->GetNativeSystemInfo(&info);

	if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
	{
		return true;
	}

	return false;
}

// Get whether the IA64 version of Windows is currently running
bool MsIsIA64()
{
	if (MsIs64BitWindows() == false)
	{
		return false;
	}

	if (MsIsX64())
	{
		return false;
	}

	return true;
}

// Acquisition whether it's a 64bit Windows
bool MsIs64BitWindows()
{
	if (Is64())
	{
		return true;
	}
	else
	{
		if (MsIsNt() == false)
		{
			return false;
		}
		else
		{
			if (ms == NULL || ms->nt == NULL)
			{
				return false;
			}

			if (ms->nt->IsWow64Process == NULL)
			{
				return false;
			}
			else
			{
				bool b = false;
				if (ms->nt->IsWow64Process(GetCurrentProcess(), &b) == false)
				{
					return false;
				}
				return b;
			}
		}
	}
}

// Windows Firewall registration
void MsRegistWindowsFirewallEx2(char *title, char *exe, char *dir)
{
	char tmp[MAX_PATH];
	// Validate arguments
	if (title == NULL || exe == NULL)
	{
		return;
	}
	if (dir == NULL || IsEmptyStr(dir))
	{
		dir = MsGetExeDirName();
	}

	ConbinePath(tmp, sizeof(tmp), dir, exe);

	if (IsFileExists(tmp) == false)
	{
		return;
	}

	MsRegistWindowsFirewallEx(title, tmp);
}
void MsRegistWindowsFirewallEx(char *title, char *exe)
{
	char *data =
		"Option Explicit\r\nConst NET_FW_PROFILE_DOMAIN = 0\r\nConst NET_FW_PROFILE_STANDARD = 1\r\n"
		"Const NET_FW_SCOPE_ALL = 0\r\nConst NET_FW_IP_VERSION_ANY = 2\r\nDim fwMgr\r\n"
		"Set fwMgr = CreateObject(\"HNetCfg.FwMgr\")\r\nDim profile\r\n"
		"Set profile = fwMgr.LocalPolicy.CurrentProfile\r\nDim app\r\n"
		"Set app = CreateObject(\"HNetCfg.FwAuthorizedApplication\")\r\n"
		"app.ProcessImageFileName = \"$PATH$\"\r\napp.Name = \"$TITLE$\"\r\n"
		"app.Scope = NET_FW_SCOPE_ALL\r\napp.IpVersion = NET_FW_IP_VERSION_ANY\r\n"
		"app.Enabled = TRUE\r\nOn Error Resume Next\r\nprofile.AuthorizedApplications."
		"Add app\r\n";
	char *tmp;
	UINT tmp_size;
	char filename[MAX_PATH];
	char cscript[MAX_PATH];
	char arg[MAX_PATH];
	UINT ostype;
	IO *o;
	char hash[MAX_PATH];
	UCHAR hashbin[SHA1_SIZE];
	UCHAR file_hash_bin[SHA1_SIZE];
	char file_hash_str[MAX_SIZE];
	// Validate arguments
	if (title == NULL || exe == NULL)
	{
		return;
	}

	// OS check (This Is not performed except Windows XP, Windows Server 2003, Windows Vista or later)
	ostype = GetOsInfo()->OsType;
	if (OS_IS_WINDOWS_NT(ostype) == false)
	{
		return;
	}
	if (MsIsAdmin() == false)
	{
		return;
	}

	if (MsIsVista())
	{
		data = "Option Explicit\r\n\r\nConst PROFILES_ALL = 7\r\nConst NET_FW_ACTION_ALLOWNET_FW_ACTION_ALLOW = 1\r\n"
			"\r\nDim policy2\r\nDim rules\r\nDim new_rule\r\n\r\nOn Error Resume Next\r\n\r\n"
			"Set policy2 = CreateObject(\"HNetCfg.FwPolicy2\")\r\nSet rules = policy2.Rules\r\n"
			"Set new_rule = CreateObject(\"HNetCfg.FWRule\")\r\nnew_rule.Name = \"$TITLE$\"\r\n"
			"new_rule.Description = \"$TITLE$\"\r\nnew_rule.ApplicationName = \"$PATH$\"\r\n"
			"new_rule.Enabled = TRUE\r\nnew_rule.Profiles = PROFILES_ALL\r\nnew_rule.Action = "
			"NET_FW_ACTION_ALLOWNET_FW_ACTION_ALLOW\r\nrules.Add new_rule\r\n\r\n";
	}

	tmp_size = StrLen(data) * 4;
	tmp = ZeroMalloc(tmp_size);

	Sha1(hashbin, exe, StrLen(exe));
	BinToStr(hash, sizeof(hash), hashbin, 6);

	ReplaceStrEx(tmp, tmp_size, data, "$TITLE$", title, false);
	ReplaceStrEx(tmp, tmp_size, tmp, "$PATH$", exe, false);

	Sha1(file_hash_bin, tmp, StrLen(tmp));
	BinToStr(file_hash_str, sizeof(file_hash_str), file_hash_bin, sizeof(file_hash_bin));

	if (MsIsVista() == false || MsRegReadIntEx2(REG_LOCAL_MACHINE, SOFTETHER_FW_SCRIPT_HASH, file_hash_str, false, true) == 0)
	{
		Format(filename, sizeof(filename), "%s\\winfire_%s.vbs", MsGetMyTempDir(), hash);
		o = FileCreate(filename);
		FileWrite(o, tmp, StrLen(tmp));
		FileClose(o);

		Format(cscript, sizeof(cscript), "%s\\cscript.exe", MsGetSystem32Dir());
		Format(arg, sizeof(arg), "\"%s\"", filename);

		if (Run(cscript, arg, true, false))
		{
			MsRegWriteIntEx2(REG_LOCAL_MACHINE, SOFTETHER_FW_SCRIPT_HASH, file_hash_str, 1, false, true);
		}

		Debug("cscript %s\n", arg);
	}

	Free(tmp);
}

// Run driver installer for Vista
bool MsExecDriverInstaller(char *arg)
{
	wchar_t tmp[MAX_PATH];
	wchar_t hamcore_dst[MAX_PATH];
	wchar_t hamcore_src[MAX_PATH];
	wchar_t lang_config_src[MAX_PATH];
	wchar_t lang_config_dst[MAX_PATH];
	HANDLE h;
	UINT retcode;
	SHELLEXECUTEINFOW info;
	wchar_t *arg_w;
	// Validate arguments
	if (arg == NULL)
	{
		return false;
	}

	UniFormat(hamcore_dst, sizeof(hamcore_dst), L"%s\\hamcore.se2", MsGetMyTempDirW());
	UniFormat(hamcore_src, sizeof(hamcore_src), L"%s\\hamcore.se2", MsGetExeDirNameW());

	// Extract the File
	UniFormat(tmp, sizeof(tmp), VISTA_DRIVER_INSTALLER_DST, MsGetMyTempDirW());

	if (FileCopyW(VISTA_DRIVER_INSTALLER_SRC, tmp) == false)
	{
		return false;
	}

	if (FileCopyW(hamcore_src, hamcore_dst) == false)
	{
		return false;
	}

	ConbinePathW(lang_config_src, sizeof(lang_config_src), MsGetExeDirNameW(), L"lang.config");
	ConbinePathW(lang_config_dst, sizeof(lang_config_dst), MsGetMyTempDirW(), L"lang.config");
	FileCopyW(lang_config_src, lang_config_dst);

	arg_w = CopyStrToUni(arg);

	// Run
	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.lpVerb = L"open";
	info.lpFile = tmp;
	info.fMask = SEE_MASK_NOCLOSEPROCESS;
	info.lpParameters = arg_w;
	info.nShow = SW_SHOWNORMAL;
	if (ShellExecuteExW(&info) == false)
	{
		Free(arg_w);
		return false;
	}

	Free(arg_w);

	h = info.hProcess;
	retcode = 1;

	while (true)
	{
		// Wait for completion
		WaitForSingleObject(h, INFINITE);

		// Get the exit code
		retcode = 1;
		if (GetExitCodeProcess(h, &retcode) == false)
		{
			break;
		}

		if (retcode != STILL_ACTIVE)
		{
			break;
		}
	}

	CloseHandle(h);

	if (retcode & 1)
	{
		return false;
	}

	return true;
}

// Get the locale of the current thread
UINT MsGetThreadLocale()
{
	return (UINT)GetThreadLocale();
}

// Set the width of the current console
UINT MsSetConsoleWidth(UINT size)
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;
	COORD c;
	UINT old_x, old_y;
	// Validate arguments
	if (size == 0)
	{
		return 0;
	}
	if (h == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	Zero(&info, sizeof(info));
	if (GetConsoleScreenBufferInfo(h, &info) == false)
	{
		return 0;
	}

	old_x = info.dwSize.X;
	old_y = info.dwSize.Y;

	c.X = size;
	c.Y = old_y;

	SetConsoleScreenBufferSize(h, c);

	return old_x;
}

// Get the width of the current console
UINT MsGetConsoleWidth()
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info;

	if (h == INVALID_HANDLE_VALUE)
	{
		return 80;
	}

	Zero(&info, sizeof(info));
	if (GetConsoleScreenBufferInfo(h, &info) == false)
	{
		return 80;
	}

	return info.dwSize.X;
}

// Disable the MS-IME
bool MsDisableIme()
{
	HINSTANCE h;
	bool ret = false;
	char dll_name[MAX_PATH];
	BOOL (WINAPI *_ImmDisableIME)(DWORD);

	Format(dll_name, sizeof(dll_name), "%s\\imm32.dll", MsGetSystem32Dir());
	h = MsLoadLibrary(dll_name);
	if (h == NULL)
	{
		return false;
	}

	_ImmDisableIME = (BOOL (__stdcall *)(DWORD))GetProcAddress(h, "ImmDisableIME");

	if (_ImmDisableIME != NULL)
	{
		ret = _ImmDisableIME(-1);
	}

	FreeLibrary(h);

	return ret;
}

// Display the current time
void MsPrintTick()
{
	UINT tick = timeGetTime();
	static UINT tick_init = 0;
	if (tick_init == 0)
	{
		tick_init = tick;
		tick = 0;
	}
	else
	{
		tick -= tick_init;
	}

	printf("[%u]\n", tick);
}

// LoadLibrary compatible for hamcore (Read as a data file)
void *MsLoadLibraryAsDataFileW(wchar_t *name)
{
	BUF *b;
	wchar_t tmp_dll_name[MAX_SIZE];
	char hash_str[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	Sha0(hash, name, UniStrLen(name));

	BinToStr(hash_str, sizeof(hash_str), hash, 4);

	UniFormat(tmp_dll_name, sizeof(tmp_dll_name), L"%s\\%S.dll", MsGetMyTempDirW(), hash_str);

	if (IsFileExistsW(tmp_dll_name) == false)
	{
		b = ReadDumpW(name);
		if (b == NULL)
		{
			return NULL;
		}

		DumpBufW(b, tmp_dll_name);
		FreeBuf(b);
	}

	return LoadLibraryExW(tmp_dll_name, NULL, LOAD_LIBRARY_AS_DATAFILE);
}
void *MsLoadLibraryAsDataFile(char *name)
{
	wchar_t name_w[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	StrToUni(name_w, sizeof(name_w), name);

	return MsLoadLibraryAsDataFileW(name_w);
}

// LoadLibrary (compatible for Hamcore)
void *MsLoadLibraryW(wchar_t *name)
{
	BUF *b;
	wchar_t tmp_dll_name[MAX_SIZE];
	char hash_str[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	Sha0(hash, name, UniStrSize(name));

	BinToStr(hash_str, sizeof(hash_str), hash, 4);

	UniFormat(tmp_dll_name, sizeof(tmp_dll_name), L"%s\\%S.dll", MsGetMyTempDirW(), hash_str);

	if (IsFileExistsW(tmp_dll_name) == false)
	{
		b = ReadDumpW(name);
		if (b == NULL)
		{
			return NULL;
		}

		DumpBufW(b, tmp_dll_name);
		FreeBuf(b);
	}

	if (IsNt())
	{
		return LoadLibraryW(tmp_dll_name);
	}
	else
	{
		char tmp_dll_name_a[MAX_SIZE];
		HINSTANCE ret;

		UniToStr(tmp_dll_name_a, sizeof(tmp_dll_name_a), tmp_dll_name);

		ret = LoadLibraryA(tmp_dll_name_a);

		return ret;
	}
}
void *MsLoadLibrary(char *name)
{
	wchar_t name_w[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	StrToUni(name_w, sizeof(name_w), name);

	return MsLoadLibraryW(name_w);
}

// Search for the adapter by GUID
MS_ADAPTER *MsGetAdapterByGuid(char *guid)
{
	MS_ADAPTER_LIST *o;
	MS_ADAPTER *ret = NULL;
	// Validate arguments
	if (guid == NULL)
	{
		return NULL;
	}

	o = MsCreateAdapterList();
	if (o == NULL)
	{
		return NULL;
	}

	ret = MsGetAdapterByGuidFromList(o, guid);

	MsFreeAdapterList(o);

	return ret;
}
MS_ADAPTER *MsGetAdapterByGuidFromList(MS_ADAPTER_LIST *o, char *guid)
{
	MS_ADAPTER *ret = NULL;
	UINT i;
	// Validate arguments
	if (o == NULL || guid == NULL)
	{
		return NULL;
	}

	for (i = 0;i < o->Num;i++)
	{
		if (StrCmpi(o->Adapters[i]->Guid, guid) == 0)
		{
			ret = MsCloneAdapter(o->Adapters[i]);
			break;
		}
	}

	return ret;
}

// Get a single adapter
MS_ADAPTER *MsGetAdapter(char *title)
{
	MS_ADAPTER_LIST *o;
	MS_ADAPTER *ret = NULL;
	UINT i;
	// Validate arguments
	if (title == NULL)
	{
		return NULL;
	}

	o = MsCreateAdapterList();
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0;i < o->Num;i++)
	{
		if (StrCmpi(o->Adapters[i]->Title, title) == 0)
		{
			ret = MsCloneAdapter(o->Adapters[i]);
			break;
		}
	}

	MsFreeAdapterList(o);

	return ret;
}

// 32-bit overflow checking
#define	CHECK_32BIT_OVERFLOW(old_value, new_value)				\
{																\
	if ((old_value) > (new_value))								\
	{															\
		(new_value) += ((UINT64)4294967296ULL);					\
	}															\
}

// Get the TCP/IP information of the specified adapter
void MsGetAdapterTcpIpInformation(MS_ADAPTER *a)
{
	IP_ADAPTER_INFO *info, *info_top;
	UINT info_size;
	UINT ret;
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (w32net->GetAdaptersInfo == NULL)
	{
		return;
	}

	info_top = ZeroMalloc(sizeof(IP_ADAPTER_INFO));
	info_size = sizeof(IP_ADAPTER_INFO);

	ret = w32net->GetAdaptersInfo(info_top, &info_size);
	if (ret == ERROR_INSUFFICIENT_BUFFER || ret == ERROR_BUFFER_OVERFLOW)
	{
		Free(info_top);
		info_size *= 2;
		info_top = ZeroMalloc(info_size);

		if (w32net->GetAdaptersInfo(info_top, &info_size) != NO_ERROR)
		{
			Free(info_top);
			return;
		}
	}
	else if (ret != NO_ERROR)
	{
		Free(info_top);
		return;
	}

	// Search for their own entry
	info = info_top;

	while (info != NULL)
	{
		if (info->Index == a->Index)
		{
			IP_ADDR_STRING *s;

			// IP address
			a->NumIpAddress = 0;
			s = &info->IpAddressList;
			while (s != NULL)
			{
				if (a->NumIpAddress < MAX_MS_ADAPTER_IP_ADDRESS)
				{
					StrToIP(&a->IpAddresses[a->NumIpAddress], s->IpAddress.String);
					StrToIP(&a->SubnetMasks[a->NumIpAddress], s->IpMask.String);
					a->NumIpAddress++;
				}
				s = s->Next;
			}

			// Gateway
			a->NumGateway = 0;
			s = &info->GatewayList;
			while (s != NULL)
			{
				if (a->NumGateway < MAX_MS_ADAPTER_IP_ADDRESS)
				{
					StrToIP(&a->Gateways[a->NumGateway], s->IpAddress.String);
					a->NumGateway++;
				}
				s = s->Next;
			}

			// DHCP Server
			a->UseDhcp = (info->DhcpEnabled == 0 ? false : true);
			if (a->UseDhcp)
			{
				SYSTEMTIME st;

				StrToIP(&a->DhcpServer, info->DhcpServer.IpAddress.String);
				TimeToSystem(&st, info->LeaseObtained);
				a->DhcpLeaseStart = SystemToUINT64(&st);

				TimeToSystem(&st, info->LeaseExpires);
				a->DhcpLeaseExpires = SystemToUINT64(&st);
			}

			// WINS server
			a->UseWins = info->HaveWins;
			if (a->UseWins)
			{
				StrToIP(&a->PrimaryWinsServer, info->PrimaryWinsServer.IpAddress.String);
				StrToIP(&a->SecondaryWinsServer, info->SecondaryWinsServer.IpAddress.String);
			}

			StrCpy(a->Guid, sizeof(a->Guid), info->AdapterName);

			a->Info = true;

			break;
		}

		info = info->Next;
	}

	Free(info_top);
}

// Generation of adapter list
MS_ADAPTER_LIST *MsCreateAdapterList()
{
	return MsCreateAdapterListEx(false);
}
MS_ADAPTER_LIST *MsCreateAdapterListEx(bool no_info)
{
	MS_ADAPTER_LIST *ret;

	if (no_info)
	{
		ret = MsCreateAdapterListInnerEx(true);

		return ret;
	}

	Lock(lock_adapter_list);
	{
		MS_ADAPTER_LIST *old = last_adapter_list;
		UINT i;

		// Fetch a new adapter list
		ret = MsCreateAdapterListInner();

		if (ret == NULL)
		{
			Unlock(lock_adapter_list);
			return NULL;
		}

		// Check whether the previously acquired item exists for each entry
		// in the list of adapters have been taken
		for (i = 0;i < ret->Num;i++)
		{
			UINT j;
			for (j = 0;j < old->Num;j++)
			{
				MS_ADAPTER *o = old->Adapters[j];
				MS_ADAPTER *n = ret->Adapters[i];

				if (StrCmpi(o->Title, n->Title) == 0)
				{
					// If the value of older item is small, increment it
					CHECK_32BIT_OVERFLOW(o->RecvBytes, n->RecvBytes);
					CHECK_32BIT_OVERFLOW(o->RecvPacketsBroadcast, n->RecvPacketsBroadcast);
					CHECK_32BIT_OVERFLOW(o->RecvPacketsUnicast, n->RecvPacketsUnicast);
					CHECK_32BIT_OVERFLOW(o->SendBytes, n->SendBytes);
					CHECK_32BIT_OVERFLOW(o->SendPacketsBroadcast, n->SendPacketsBroadcast);
					CHECK_32BIT_OVERFLOW(o->SendPacketsUnicast, n->SendPacketsUnicast);
					break;
				}
			}
		}

		// Release the old adapter list
		MsFreeAdapterList(old);

		// Save a clone of the adapter list that newly acquired
		last_adapter_list = MsCloneAdapterList(ret);
	}
	Unlock(lock_adapter_list);

	return ret;
}

// Initialization of the adapter module list
void MsInitAdapterListModule()
{
	lock_adapter_list = NewLock(NULL);

	last_adapter_list = MsCreateAdapterListInner();
}

// Release of the adapter module list
void MsFreeAdapterListModule()
{
	if (last_adapter_list != NULL)
	{
		MsFreeAdapterList(last_adapter_list);
		last_adapter_list = NULL;
	}

	DeleteLock(lock_adapter_list);
	lock_adapter_list = NULL;
}

// Clone the adapter list
MS_ADAPTER_LIST *MsCloneAdapterList(MS_ADAPTER_LIST *o)
{
	MS_ADAPTER_LIST *ret;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = o->Num;
	ret->Adapters = ZeroMalloc(sizeof(MS_ADAPTER *) * ret->Num);

	for (i = 0;i < ret->Num;i++)
	{
		ret->Adapters[i] = ZeroMalloc(sizeof(MS_ADAPTER));
		Copy(ret->Adapters[i], o->Adapters[i], sizeof(MS_ADAPTER));
	}

	return ret;
}

// Clone the adapter
MS_ADAPTER *MsCloneAdapter(MS_ADAPTER *a)
{
	MS_ADAPTER *ret;
	// Validate arguments
	if (a == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER));
	Copy(ret, a, sizeof(MS_ADAPTER));

	return ret;
}

// Creating an adapters list
MS_ADAPTER_LIST *MsCreateAdapterListInner()
{
	return MsCreateAdapterListInnerEx(false);
}
MS_ADAPTER_LIST *MsCreateAdapterListInnerEx(bool no_info)
{
	LIST *o;
	UINT i;
	UINT retcode;
	MIB_IFTABLE *table;
	UINT table_size = sizeof(MIB_IFTABLE);
	MS_ADAPTER_LIST *ret;

	if (w32net->GetIfTable2 != NULL && w32net->FreeMibTable != NULL)
	{
		return MsCreateAdapterListInnerExVista(no_info);
	}

	if (w32net->GetIfTable == NULL)
	{
		return ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	}

	table = ZeroMalloc(table_size);

	retcode = w32net->GetIfTable(table, &table_size, TRUE);
	if (retcode == ERROR_INSUFFICIENT_BUFFER || retcode == ERROR_BUFFER_OVERFLOW)
	{
		Free(table);
		table_size *= 2;
		table = ZeroMalloc(table_size);
		if (w32net->GetIfTable(table, &table_size, TRUE) != NO_ERROR)
		{
			Free(table);
			return ZeroMalloc(sizeof(MS_ADAPTER_LIST));
		}
	}
	else if (retcode != NO_ERROR)
	{
		Free(table);
		return ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	}

	o = NewListFast(NULL);

	for (i = 0;i < table->dwNumEntries;i++)
	{
		MIB_IFROW *r = &table->table[i];
		char title[MAX_PATH];
		UINT num = 0;
		MS_ADAPTER *a;
		UINT j;

		//if (r->dwOperStatus == MIB_IF_OPER_STATUS_CONNECTED || r->dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL)
		{
			//if (r->dwType & IF_TYPE_ETHERNET_CSMACD)
			{
				for (j = 1;;j++)
				{
					UINT k;
					bool exists;
					if (j == 1)
					{
						StrCpy(title, sizeof(title), (char *)r->bDescr);
					}
					else
					{
						Format(title, sizeof(title), "%s (%u)", (char *)r->bDescr, j);
					}

					exists = false;

					for (k = 0;k < LIST_NUM(o);k++)
					{
						MS_ADAPTER *a = LIST_DATA(o, k);

						if (StrCmpi(a->Title, title) == 0)
						{
							exists = true;
							break;
						}
					}

					if (exists == false)
					{
						break;
					}
				}

				a = ZeroMalloc(sizeof(MS_ADAPTER));

				// Create an adapter information
				StrCpy(a->Title, sizeof(a->Title), title);
				StrToUni(a->TitleW, sizeof(a->TitleW), title);
				a->Index = r->dwIndex;
				a->Type = r->dwType;
				a->Status = r->dwOperStatus;
				a->Mtu = r->dwMtu;
				a->Speed = r->dwSpeed;
				a->AddressSize = MIN(sizeof(a->Address), r->dwPhysAddrLen);
				Copy(a->Address, r->bPhysAddr, a->AddressSize);
				a->RecvBytes = r->dwInOctets;
				a->RecvPacketsBroadcast = r->dwInNUcastPkts;
				a->RecvPacketsUnicast = r->dwInUcastPkts;
				a->SendBytes = r->dwOutOctets;
				a->SendPacketsBroadcast = r->dwOutNUcastPkts;
				a->SendPacketsUnicast = r->dwOutUcastPkts;

				if (a->Type != IF_TYPE_ETHERNET_CSMACD)
				{
					a->IsNotEthernetLan = true;
				}

				// TCP/IP information acquisition
				if (no_info == false)
				{
					MsGetAdapterTcpIpInformation(a);
				}

				Add(o, a);
			}
		}
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = LIST_NUM(o);
	ret->Adapters = ToArray(o);

	ReleaseList(o);
	Free(table);

	return ret;
}

// Creating an adapters list (Windows Vista version)
MS_ADAPTER_LIST *MsCreateAdapterListInnerExVista(bool no_info)
{
	LIST *o;
	UINT i;
	UINT retcode;
	MIB_IF_TABLE2 *table;
	UINT table_size = sizeof(MIB_IFTABLE);
	MS_ADAPTER_LIST *ret;

	if (w32net->GetIfTable2 == NULL || w32net->FreeMibTable == NULL)
	{
		return ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	}

	retcode = w32net->GetIfTable2(&table);
	if (retcode != NO_ERROR || table == NULL)
	{
		return ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	}

	o = NewListFast(NULL);

	for (i = 0;i < table->NumEntries;i++)
	{
		MIB_IF_ROW2 *r = &table->Table[i];
		wchar_t title[MAX_PATH];
		UINT num = 0;
		MS_ADAPTER *a;
		UINT j;

		//if (r->dwOperStatus == MIB_IF_OPER_STATUS_CONNECTED || r->dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL)
		{
			//if (r->dwType & IF_TYPE_ETHERNET_CSMACD)
			{
				for (j = 1;;j++)
				{
					UINT k;
					bool exists;
					if (j == 1)
					{
						UniStrCpy(title, sizeof(title), r->Description);
					}
					else
					{
						UniFormat(title, sizeof(title), L"%s (%u)", r->Description, j);
					}

					exists = false;

					for (k = 0;k < LIST_NUM(o);k++)
					{
						MS_ADAPTER *a = LIST_DATA(o, k);

						if (UniStrCmpi(a->TitleW, title) == 0)
						{
							exists = true;
							break;
						}
					}

					if (exists == false)
					{
						break;
					}
				}

				a = ZeroMalloc(sizeof(MS_ADAPTER));

				// Create an adapter information
				UniStrCpy(a->TitleW, sizeof(a->TitleW), title);
				UniToStr(a->Title, sizeof(a->Title), title);
				a->Index = r->InterfaceIndex;
				a->Type = r->Type;
				a->Status = ConvertMidStatusVistaToXp(r->OperStatus);
				a->Mtu = r->Mtu;
				a->Speed = MAX((UINT)r->TransmitLinkSpeed, (UINT)r->ReceiveLinkSpeed);
				a->AddressSize = MIN(sizeof(a->Address), r->PhysicalAddressLength);
				Copy(a->Address, r->PhysicalAddress, a->AddressSize);
				a->RecvBytes = r->InOctets;
				a->RecvPacketsBroadcast = r->InNUcastPkts;
				a->RecvPacketsUnicast = r->InUcastPkts;
				a->SendBytes = r->OutOctets;
				a->SendPacketsBroadcast = r->OutNUcastPkts;
				a->SendPacketsUnicast = r->OutUcastPkts;

				if (r->MediaType == NdisMediumWirelessWan || r->PhysicalMediumType == NdisPhysicalMediumWirelessLan ||
					r->PhysicalMediumType == NdisPhysicalMediumWirelessWan || r->PhysicalMediumType == NdisPhysicalMediumWiMax ||
					r->Type == IF_TYPE_IEEE80211)
				{
					a->IsWireless = true;
				}

				if (a->IsWireless ||
					r->Type != IF_TYPE_ETHERNET_CSMACD ||
					r->MediaType != NdisMedium802_3 || 
					(r->PhysicalMediumType != 0 && r->PhysicalMediumType != NdisPhysicalMedium802_3))
				{
					a->IsNotEthernetLan = true;
				}

				// TCP/IP information acquisition
				if (no_info == false)
				{
					MsGetAdapterTcpIpInformation(a);
				}

				Add(o, a);
			}
		}
	}

	ret = ZeroMalloc(sizeof(MS_ADAPTER_LIST));
	ret->Num = LIST_NUM(o);
	ret->Adapters = ToArray(o);

	ReleaseList(o);
	w32net->FreeMibTable(table);

	return ret;
}

// Convert the MIB Operational Status from Vista format to XP format
UINT ConvertMidStatusVistaToXp(UINT st)
{
	switch (st)
	{
	case IfOperStatusUp:
		return MIB_IF_OPER_STATUS_CONNECTED;

	case IfOperStatusDown:
		return MIB_IF_OPER_STATUS_DISCONNECTED;
	}

	return MIB_IF_OPER_STATUS_NON_OPERATIONAL;
}

// Release the adapter list
void MsFreeAdapterList(MS_ADAPTER_LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < o->Num;i++)
	{
		MsFreeAdapter(o->Adapters[i]);
	}
	Free(o->Adapters);

	Free(o);
}

// Release the adapter information
void MsFreeAdapter(MS_ADAPTER *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	Free(a);
}

// Get the status string of the adapter
wchar_t *MsGetAdapterStatusStr(UINT status)
{
	wchar_t *ret;

	switch (status)
	{
	case MIB_IF_OPER_STATUS_NON_OPERATIONAL:
		ret = _UU("MS_NON_OPERATIONAL");
		break;

	case MIB_IF_OPER_STATUS_UNREACHABLE:
		ret = _UU("MS_UNREACHABLE");
		break;

	case MIB_IF_OPER_STATUS_DISCONNECTED:
		ret = _UU("MS_DISCONNECTED");
		break;

	case MIB_IF_OPER_STATUS_CONNECTING:
		ret = _UU("MS_CONNECTING");
		break;

	case MIB_IF_OPER_STATUS_CONNECTED:
		ret = _UU("MS_CONNECTED");
		break;

	default:
		ret = _UU("MS_OPERATIONAL");
		break;
	}

	return ret;
}

// Get the type string of the adapter
wchar_t *MsGetAdapterTypeStr(UINT type)
{
	wchar_t *ret;

	switch (type)
	{
	case IF_TYPE_PROP_VIRTUAL:
		ret = _UU("MS_VIRTUAL");
		break;

	case MIB_IF_TYPE_ETHERNET:
		ret = _UU("MS_ETHERNET");
		break;

	case IF_TYPE_IEEE80211:
		ret = _UU("MS_WLAN");
		break;

	case MIB_IF_TYPE_TOKENRING:
		ret = _UU("MS_TOKENRING");
		break;

	case MIB_IF_TYPE_FDDI:
		ret = _UU("MS_FDDI");
		break;

	case MIB_IF_TYPE_PPP:
		ret = _UU("MS_PPP");
		break;

	case MIB_IF_TYPE_LOOPBACK:
		ret = _UU("MS_LOOPBACK");
		break;

	case MIB_IF_TYPE_SLIP:
		ret = _UU("MS_SLIP");
		break;

	default:
		ret = _UU("MS_OTHER");
		break;
	}

	return ret;
}

// Kill the process of specified EXE file name
UINT MsKillProcessByExeName(wchar_t *name)
{
	LIST *o;
	UINT me, i;
	UINT num = 0;
	// Validate arguments
	if (name == NULL)
	{
		return 0;
	}

	o = MsGetProcessList();
	me = MsGetProcessId();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);
		if (p->ProcessId != me)
		{
			if (UniStrCmpi(p->ExeFilenameW, name) == 0)
			{
				if (MsKillProcess(p->ProcessId))
				{
					num++;
				}
			}
		}
	}

	MsFreeProcessList(o);

	return num;
}

// Terminate all instances except the EXE itself
void MsKillOtherInstance()
{
	MsKillOtherInstanceEx(NULL);
}
void MsKillOtherInstanceEx(char *exclude_svcname)
{
	UINT me, i;
	wchar_t me_path[MAX_PATH];
	wchar_t me_path_short[MAX_PATH];
	LIST *o = MsGetProcessList();
	UINT e_procid = 0;
	UINT e_procid2 = 0;

	if (exclude_svcname != NULL)
	{
		e_procid = MsReadCallingServiceManagerProcessId(exclude_svcname, false);
		e_procid2 = MsReadCallingServiceManagerProcessId(exclude_svcname, true);
	}

	me = MsGetProcessId();

	MsGetCurrentProcessExeNameW(me_path, sizeof(me_path));
	MsGetShortPathNameW(me_path, me_path_short, sizeof(me_path_short));

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);
		if (p->ProcessId != me)
		{
			if ((e_procid == 0 || (e_procid != p->ProcessId)) && (e_procid2 == 0 || (e_procid2 != p->ProcessId)))
			{
				wchar_t tmp[MAX_PATH];
				MsGetShortPathNameW(p->ExeFilenameW, tmp, sizeof(tmp));
				if (UniStrCmpi(me_path_short, tmp) == 0)
				{
					MsKillProcess(p->ProcessId);
				}
			}
		}
	}

	MsFreeProcessList(o);
}

// Get the short file name
bool MsGetShortPathNameA(char *long_path, char *short_path, UINT short_path_size)
{
	// Validate arguments
	if (long_path == NULL || short_path == NULL)
	{
		return false;
	}

	if (GetShortPathNameA(long_path, short_path, short_path_size) == 0)
	{
		StrCpy(short_path, short_path_size, long_path);
		return false;
	}

	return true;
}
bool MsGetShortPathNameW(wchar_t *long_path, wchar_t *short_path, UINT short_path_size)
{
	// Validate arguments
	if (long_path == NULL || short_path == NULL)
	{
		return false;
	}

	if (IsNt() == false)
	{
		char short_path_a[MAX_SIZE];
		char long_path_a[MAX_SIZE];
		bool ret;

		UniToStr(long_path_a, sizeof(long_path_a), long_path);

		ret = MsGetShortPathNameA(long_path_a, short_path_a, sizeof(short_path_a));

		StrToUni(short_path, short_path_size, short_path_a);

		return ret;
	}

	if (GetShortPathNameW(long_path, short_path, short_path_size) == 0)
	{
		UniStrCpy(short_path, short_path_size, long_path);
		return false;
	}

	return true;
}

// Kill the specified process
bool MsKillProcess(UINT id)
{
	HANDLE h;
	// Validate arguments
	if (id == 0)
	{
		return false;
	}

	h = OpenProcess(PROCESS_TERMINATE, FALSE, id);
	if (h == NULL)
	{
		return false;
	}

	if (TerminateProcess(h, 0) == FALSE)
	{
		CloseHandle(h);
		return false;
	}

	CloseHandle(h);

	return true;
}

// Get the current EXE file name
void MsGetCurrentProcessExeNameW(wchar_t *name, UINT size)
{
	UINT id;
	LIST *o;
	MS_PROCESS *p;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	id = MsGetCurrentProcessId();
	o = MsGetProcessList();
	p = MsSearchProcessById(o, id);
	if (p != NULL)
	{
		p = MsSearchProcessById(o, id);
		UniStrCpy(name, size, p->ExeFilenameW);
	}
	else
	{
		UniStrCpy(name, size, MsGetExeFileNameW());
	}
	MsFreeProcessList(o);
}

// Search the process by the process ID
MS_PROCESS *MsSearchProcessById(LIST *o, UINT id)
{
	MS_PROCESS *p, t;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	t.ProcessId = id;

	p = Search(o, &t);

	return p;
}

// Compare the Process List items
int MsCompareProcessList(void *p1, void *p2)
{
	MS_PROCESS *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(MS_PROCESS **)p1;
	e2 = *(MS_PROCESS **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}

	if (e1->ProcessId > e2->ProcessId)
	{
		return 1;
	}
	else if (e1->ProcessId < e2->ProcessId)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// Release of the process list
void MsFreeProcessList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);
		Free(p);
	}

	ReleaseList(o);
}

// Get the Process List (for WinNT)
LIST *MsGetProcessListNt()
{
	LIST *o;
	UINT max = 16384;
	DWORD *processes;
	UINT needed, num;
	UINT i;

	o = NewListFast(MsCompareProcessList);

	if (ms->nt->EnumProcesses == NULL)
	{
		return o;
	}

	processes = ZeroMalloc(sizeof(DWORD) * max);

	if (ms->nt->EnumProcesses(processes, sizeof(DWORD) * max, &needed) == FALSE)
	{
		Free(processes);
		return NULL;
	}

	num = needed / sizeof(DWORD);

	for (i = 0;i < num;i++)
	{
		UINT id = processes[i];
		HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			false, id);

		if (h != NULL)
		{
			HINSTANCE hInst = NULL;
			DWORD needed;
			char exe[MAX_SIZE];
			wchar_t exe_w[MAX_SIZE];
			bool ok = false;
			DWORD sz1, sz2;

			sz1 = sizeof(exe) - 1;
			sz2 = sizeof(exe_w) / sizeof(wchar_t) - 1;

			if (ms->nt->EnumProcessModules(h, &hInst, sizeof(hInst), &needed) == false)
			{
				hInst = NULL;
			}

			if (ms->nt->GetModuleFileNameExA(h, hInst, exe, sizeof(exe) - 1) &&
				ms->nt->GetModuleFileNameExW(h, hInst, exe_w, sizeof(exe_w) / sizeof(wchar_t) - 1))
			{
				ok = true;
			}
			else if (ms->nt->QueryFullProcessImageNameA != NULL &&
				ms->nt->QueryFullProcessImageNameW != NULL &&
				ms->nt->QueryFullProcessImageNameA(h, 0, exe, &sz1) &&
				ms->nt->QueryFullProcessImageNameW(h, 0, exe_w, &sz2))
			{
				ok = true;
			}

			if (ok)
			{
				MS_PROCESS *p = ZeroMalloc(sizeof(MS_PROCESS));

				StrCpy(p->ExeFilename, sizeof(p->ExeFilename), exe);
				UniStrCpy(p->ExeFilenameW, sizeof(p->ExeFilenameW), exe_w);
				p->ProcessId = id;

				Add(o, p);
			}

			CloseHandle(h);
		}
	}

	Sort(o);

	Free(processes);

	return o;
}

// Get the Process List (for Win9x)
LIST *MsGetProcessList9x()
{
	HANDLE h;
	LIST *o;
	HANDLE (WINAPI *CreateToolhelp32Snapshot)(DWORD, DWORD);
	BOOL (WINAPI *Process32First)(HANDLE, LPPROCESSENTRY32);
	BOOL (WINAPI *Process32Next)(HANDLE, LPPROCESSENTRY32);

	CreateToolhelp32Snapshot =
		(HANDLE (__stdcall *)(DWORD,DWORD))
		GetProcAddress(ms->hKernel32, "CreateToolhelp32Snapshot");
	Process32First =
		(BOOL (__stdcall *)(HANDLE,LPPROCESSENTRY32))
		GetProcAddress(ms->hKernel32, "Process32First");
	Process32Next =
		(BOOL (__stdcall *)(HANDLE,LPPROCESSENTRY32))
		GetProcAddress(ms->hKernel32, "Process32Next");

	o = NewListFast(MsCompareProcessList);

	if (CreateToolhelp32Snapshot != NULL && Process32First != NULL && Process32Next != NULL)
	{
		h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (h != INVALID_HANDLE_VALUE)
		{
			PROCESSENTRY32 e;
			Zero(&e, sizeof(e));
			e.dwSize = sizeof(e);

			if (Process32First(h, &e))
			{
				while (true)
				{
					MS_PROCESS *p = ZeroMalloc(sizeof(MS_PROCESS));
					StrCpy(p->ExeFilename, sizeof(p->ExeFilename), e.szExeFile);
					StrToUni(p->ExeFilenameW, sizeof(p->ExeFilenameW), p->ExeFilename);
					p->ProcessId = e.th32ProcessID;
					Add(o, p);
					if (Process32Next(h, &e) == false)
					{
						break;
					}
				}
			}
			CloseHandle(h);
		}
	}

	Sort(o);

	return o;
}

// Get the Process List
LIST *MsGetProcessList()
{
	if (MsIsNt() == false)
	{
		// Windows 9x
		return MsGetProcessList9x();
	}
	else
	{
		// Windows NT, 2000, XP
		return MsGetProcessListNt();
	}
}

// Force to run the current thread on a single CPU
void MsSetThreadSingleCpu()
{
	SetThreadAffinityMask(GetCurrentThread(), 1);
}

// Playback of sound
void MsPlaySound(char *name)
{
	char tmp[MAX_SIZE];
	char wav[MAX_SIZE];
	char *temp;
	BUF *b;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	Format(tmp, sizeof(tmp), "|%s", name);

	b = ReadDump(tmp);
	if (b == NULL)
	{
		return;
	}

	temp = MsGetMyTempDir();
	Format(wav, sizeof(tmp), "%s\\%s", temp, name);
	DumpBuf(b, wav);

	PlaySound(wav, NULL, SND_ASYNC | SND_FILENAME | SND_NODEFAULT);

	FreeBuf(b);
}

// Show an icon in the task tray
bool MsShowIconOnTray(HWND hWnd, HICON icon, wchar_t *tooltip, UINT msg)
{
	bool ret = true;
	// Validate arguments
	if (hWnd == NULL || icon == NULL)
	{
		return true;
	}

	if (MsIsNt() == false)
	{
		Zero(&nid, sizeof(nid));
		nid.cbSize = sizeof(nid);
		nid.hWnd = hWnd;
		nid.uID = 1;
		nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO;
		nid.uCallbackMessage = msg;
		nid.hIcon = icon;
		UniToStr(nid.szTip, sizeof(nid.szTip), tooltip);
		ret = Shell_NotifyIcon(NIM_ADD, &nid);
	}
	else
	{
		Zero(&nid_nt, sizeof(nid_nt));
		nid_nt.cbSize = sizeof(nid_nt);
		nid_nt.hWnd = hWnd;
		nid_nt.uID = 1;
		nid_nt.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_INFO;
		nid_nt.uCallbackMessage = msg;
		nid_nt.hIcon = icon;
		UniStrCpy(nid_nt.szTip, sizeof(nid_nt.szTip), tooltip);

		ret = Shell_NotifyIconW(NIM_ADD, &nid_nt);
	}

	tray_inited = true;

	return ret;
}

// Restore the icon in the task tray
void MsRestoreIconOnTray()
{
	if (tray_inited == false)
	{
		return;
	}

	if (MsIsNt() == false)
	{
		Shell_NotifyIcon(NIM_ADD, &nid);
	}
	else
	{
		Shell_NotifyIconW(NIM_ADD, &nid_nt);
	}
}

// Change the icon in the task tray
void MsChangeIconOnTray(HICON icon, wchar_t *tooltip)
{
	MsChangeIconOnTrayEx(icon, tooltip, NULL, NULL, NIIF_NONE, false);
}
bool MsChangeIconOnTrayEx(HICON icon, wchar_t *tooltip, wchar_t *info_title, wchar_t *info, UINT info_flags, bool add)
{
	bool changed = false;
	bool ret = true;

	if (tray_inited == false)
	{
		return ret;
	}

	if (icon != NULL)
	{
		if (MsIsNt() == false)
		{
			if (nid.hIcon != icon)
			{
				changed = true;
				nid.hIcon = icon;
			}
		}
		else
		{
			if (nid_nt.hIcon != icon)
			{
				changed = true;
				nid_nt.hIcon = icon;
			}
		}
	}

	if (tooltip != NULL)
	{
		if (MsIsNt() == false)
		{
			char tmp[MAX_SIZE];

			UniToStr(tmp, sizeof(tmp), tooltip);

			if (StrCmp(nid.szTip, tmp) != 0)
			{
				StrCpy(nid.szTip, sizeof(nid.szTip), tmp);
				changed = true;
			}
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			UniStrCpy(tmp, sizeof(tmp), tooltip);

			if (UniStrCmp(nid_nt.szTip, tmp) != 0)
			{
				UniStrCpy(nid_nt.szTip, sizeof(nid_nt.szTip), tmp);
				changed = true;
			}
		}
	}

	if (info_title != NULL && info != NULL)
	{
		if (MsIsNt() == false)
		{
			char tmp1[MAX_SIZE];
			char tmp2[MAX_PATH];

			UniToStr(tmp1, sizeof(tmp1), info_title);
			UniToStr(tmp2, sizeof(tmp2), info);

			if (StrCmp(nid.szInfo, tmp1) != 0 ||
				StrCmp(nid.szInfoTitle, tmp2) != 0)
			{
				StrCpy(nid.szInfo, sizeof(nid.szInfo), tmp1);
				StrCpy(nid.szInfoTitle, sizeof(nid.szInfoTitle), tmp2);
				nid.dwInfoFlags = info_flags;

				changed = true;
			}
		}
		else
		{
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_PATH];

			UniStrCpy(tmp1, sizeof(tmp1), info_title);
			UniStrCpy(tmp2, sizeof(tmp2), info);

			if (UniStrCmp(nid_nt.szInfo, tmp1) != 0 ||
				UniStrCmp(nid_nt.szInfoTitle, tmp2) != 0)
			{
				UniStrCpy(nid_nt.szInfo, sizeof(nid_nt.szInfo), tmp1);
				UniStrCpy(nid_nt.szInfoTitle, sizeof(nid_nt.szInfoTitle), tmp2);
				nid_nt.dwInfoFlags = info_flags;

				changed = true;
			}
		}
	}

	if (changed || add)
	{
		UINT op = (add ? NIM_ADD : NIM_MODIFY);
		if (MsIsNt() == false)
		{
			ret = Shell_NotifyIcon(op, &nid);
		}
		else
		{
			ret = Shell_NotifyIconW(op, &nid_nt);
		}
	}

	return ret;
}

// Remove the icon in the task tray
void MsHideIconOnTray()
{
	if (MsIsNt() == false)
	{
		Shell_NotifyIcon(NIM_DELETE, &nid);
	}
	else
	{
		Shell_NotifyIconW(NIM_DELETE, &nid_nt);
	}

	tray_inited = false;
}

// Insert a menu item
bool MsInsertMenu(HMENU hMenu, UINT pos, UINT flags, UINT_PTR id_new_item, wchar_t *lp_new_item)
{
	bool ret;

	if (MsIsNt())
	{
		ret = InsertMenuW(hMenu, pos, flags, id_new_item, lp_new_item);
	}
	else
	{
		char *s = CopyUniToStr(lp_new_item);
		ret = InsertMenuA(hMenu, pos, flags, id_new_item, s);
		Free(s);
	}

	return ret;
}

// Adding a menu item
bool MsAppendMenu(HMENU hMenu, UINT flags, UINT_PTR id, wchar_t *str)
{
	bool ret;

	if (MsIsNt())
	{
		ret = AppendMenuW(hMenu, flags, id, str);
	}
	else
	{
		char *s = CopyUniToStr(str);
		ret = AppendMenuA(hMenu, flags, id, s);
		Free(s);
	}

	return ret;
}

// Display the menu
void MsUserModeTrayMenu(HWND hWnd)
{
	HMENU h;
	POINT p;
	wchar_t tmp[MAX_SIZE];
	wchar_t caption[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Create a menu
	h = CreatePopupMenu();
	MsAppendMenu(h, MF_ENABLED | MF_STRING, 10001, _UU("SVC_USERMODE_MENU_1"));
	MsAppendMenu(h, MF_SEPARATOR, 10002, NULL);

	if (MsIsNt())
	{
		GetWindowTextW(hWnd, caption, sizeof(caption));
	}
	else
	{
		char tmp[MAX_SIZE];
		GetWindowTextA(hWnd, tmp, sizeof(tmp));
		StrToUni(caption, sizeof(caption), tmp);
	}

	UniFormat(tmp, sizeof(tmp), _UU("SVC_USERMODE_MENU_2"), caption);
	MsAppendMenu(h, MF_ENABLED | MF_STRING, 10003, tmp);

	// Display the menu
	GetCursorPos(&p);

	SetForegroundWindow(hWnd);
	TrackPopupMenu(h, TPM_LEFTALIGN, p.x, p.y, 0, hWnd, NULL);
	PostMessage(hWnd, WM_NULL, 0, 0);

	DestroyMenu(h);
}

// Window procedure for the user mode
LRESULT CALLBACK MsUserModeWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	wchar_t tmp[MAX_SIZE];
	char title[MAX_SIZE];
	wchar_t title_w[MAX_SIZE];
	char value_name[MAX_SIZE];
	static UINT taskbar_msg = 0;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	if (msg == taskbar_msg && taskbar_msg != 0)
	{
		// The taskbar was regenerated
		if (MsRegReadInt(REG_CURRENT_USER, SVC_USERMODE_SETTING_KEY, value_name) == 0 &&
			service_for_9x_mode == false)
		{
			MsRestoreIconOnTray();
		}
	}

	switch (msg)
	{
	case WM_ENDSESSION:
		// Resume
		if (wParam == false)
		{
			break;
		}
	case WM_CREATE:
		// Start
		exiting = false;
		g_start();
		GetWindowText(hWnd, title, sizeof(title));
		StrToUni(title_w, sizeof(title_w), title);
		UniFormat(tmp, sizeof(tmp), _UU("SVC_TRAY_TOOLTIP"), title);

		if (taskbar_msg == 0)
		{
			taskbar_msg = RegisterWindowMessage("TaskbarCreated");
		}

		Format(value_name, sizeof(value_name), SVC_HIDETRAY_REG_VALUE, title_w);
		if (MsRegReadInt(REG_CURRENT_USER, SVC_USERMODE_SETTING_KEY, value_name) == 0 &&
			service_for_9x_mode == false)
		{
			MsShowIconOnTray(hWnd, tray_icon, tmp, WM_APP + 33);
		}

		break;
	case WM_APP + 33:
		if (wParam == 1)
		{
			// The operation to the icon in the task tray
			switch (lParam)
			{
			case WM_RBUTTONDOWN:
				// Right click
				MsUserModeTrayMenu(hWnd);
				break;
			case WM_LBUTTONDBLCLK:
				// Left double-click
				break;
			}
		}
		break;
	case WM_LBUTTONDOWN:
		MsUserModeTrayMenu(hWnd);
		break;
	case WM_QUERYENDSESSION:
		if (exiting == false)
		{
			exiting = true;
			MsHideIconOnTray();
			g_stop();
			DestroyWindow(hWnd);
		}
		return TRUE;
	case WM_CLOSE:
		// Stop
		if (exiting == false)
		{
			exiting = true;
			g_stop();
			MsHideIconOnTray();
			DestroyWindow(hWnd);
		}
		break;
	case WM_DESTROY:
		wnd_end = true;
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case 10001:
			GetWindowText(hWnd, title, sizeof(title));
			StrToUni(title_w, sizeof(title_w), title);
			// Display a confirmation message
			if (MsgBoxEx(hWnd, MB_ICONINFORMATION | MB_OKCANCEL | MB_DEFBUTTON2 |
				MB_SYSTEMMODAL, _UU("SVC_HIDE_TRAY_MSG"), title, title) == IDOK)
			{
				char tmp[MAX_SIZE];
				Format(tmp, sizeof(tmp), SVC_HIDETRAY_REG_VALUE, title_w);
				// Write to the registry
				MsRegWriteInt(REG_CURRENT_USER, SVC_USERMODE_SETTING_KEY, tmp, 1);
				// Hide the icon
				MsHideIconOnTray();
			}
			break;
		case 10003:
			SendMessage(hWnd, WM_CLOSE, 0, 0);
			break;
		}
		break;
	}
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

// Get whether this instance is in user mode
bool MsIsUserMode()
{
	return is_usermode;
}

// Only run the test (for debugging)
void MsTestOnly()
{
	g_start();
	GetLine(NULL, 0);
	g_stop();

	_exit(0);
}

// Stop the user-mode service
void MsStopUserModeSvc(char *svc_name)
{
	void *p;
	// Validate arguments
	if (svc_name == NULL)
	{
		return;
	}

	p = MsCreateUserModeSvcGlocalPulse(svc_name);
	if (p == NULL)
	{
		return;
	}

	MsSendGlobalPulse(p);

	MsCloseGlobalPulse(p);
}

// Creating a global pulse for user-mode service
void *MsCreateUserModeSvcGlocalPulse(char *svc_name)
{
	char name[MAX_SIZE];
	// Validate arguments
	if (svc_name == NULL)
	{
		return NULL;
	}

	MsGenerateUserModeSvcGlobalPulseName(name, sizeof(name), svc_name);

	return MsOpenOrCreateGlobalPulse(name);
}

// Get the global pulse name for the user-mode service
void MsGenerateUserModeSvcGlobalPulseName(char *name, UINT size, char *svc_name)
{
	wchar_t tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (name == NULL || svc_name == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), L"usersvc_%S_@_%s", svc_name, MsGetUserNameW());

	UniTrim(tmp);
	UniStrUpper(tmp);

	Sha1(hash, tmp, UniStrLen(tmp) * sizeof(wchar_t));

	BinToStr(name, size, hash, sizeof(hash));
}

// Declare the beginning of use of a VLAN card
void MsBeginVLanCard()
{
	Inc(vlan_card_counter);
}

// Declare the ending of use of a VLAN card
void MsEndVLanCard()
{
	Dec(vlan_card_counter);
}

// Return the flag whether the VLAN cards must be stopped
bool MsIsVLanCardShouldStop()
{
	return vlan_card_should_stop_flag;
}

// Suspend procs
void MsProcEnterSuspend()
{
	UINT64 giveup_tick = Tick64() + 2000;
	UINT num = Count(vlan_card_counter);

	vlan_is_in_suspend_mode = true;

	vlan_card_should_stop_flag = true;

	vlan_suspend_mode_begin_tick = Tick64();

	while (true)
	{
		UINT64 now = Tick64();

		if (now >= giveup_tick)
		{
			break;
		}

		if (Count(vlan_card_counter) == 0)
		{
			break;
		}

		SleepThread(100);
	}

	if (num >= 1)
	{
		SleepThread(3000);
	}
}
void MsProcLeaveSuspend()
{
	vlan_card_should_stop_flag = false;
	vlan_is_in_suspend_mode = false;
	vlan_suspend_mode_begin_tick = Tick64();
}
UINT64 MsGetSuspendModeBeginTick()
{
	if (vlan_is_in_suspend_mode)
	{
		return Tick64();
	}

	return vlan_suspend_mode_begin_tick;
}

// Suspend handler window proc
LRESULT CALLBACK MsSuspendHandlerWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	MS_SUSPEND_HANDLER *h;
	CREATESTRUCT *cs;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	h = (MS_SUSPEND_HANDLER *)GetWindowLongPtrA(hWnd, GWLP_USERDATA);
	if (h == NULL && msg != WM_CREATE)
	{
		goto LABEL_END;
	}

	switch (msg)
	{
	case WM_CREATE:
		cs = (CREATESTRUCT *)lParam;
		h = (MS_SUSPEND_HANDLER *)cs->lpCreateParams;
		SetWindowLongPtrA(hWnd, GWLP_USERDATA, (LONG_PTR)h);
		break;

	case WM_POWERBROADCAST:
		if (MsIsVista())
		{
			switch (wParam)
			{
			case PBT_APMSUSPEND:
				MsProcEnterSuspend();
				return 1;

			case PBT_APMRESUMEAUTOMATIC:
			case PBT_APMRESUMESUSPEND:
				MsProcLeaveSuspend();
				return 1;
			}
		}
		break;

	case WM_CLOSE:
		/*if (h->AboutToClose == false)
		{
			return 0;
		}*/
		break;

	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}

LABEL_END:
	return DefWindowProc(hWnd, msg, wParam, lParam);
}

// Suspend handler thread
void MsSuspendHandlerThreadProc(THREAD *thread, void *param)
{
	char wndclass_name[MAX_PATH];
	WNDCLASS wc;
	HWND hWnd;
	MSG msg;
	MS_SUSPEND_HANDLER *h = (MS_SUSPEND_HANDLER *)param;
	// Validate arguments
	if (h == NULL || thread == NULL)
	{
		return;
	}

	Format(wndclass_name, sizeof(wndclass_name), "WNDCLASS_%X", Rand32());

	Zero(&wc, sizeof(wc));
	wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hIcon = NULL;
	wc.hInstance = ms->hInst;
	wc.lpfnWndProc = MsSuspendHandlerWindowProc;
	wc.lpszClassName = wndclass_name;
	if (RegisterClassA(&wc) == 0)
	{
		NoticeThreadInit(thread);
		return;
	}

	hWnd = CreateWindowA(wndclass_name, wndclass_name, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, NULL, ms->hInst, h);

	h->hWnd = hWnd;

	NoticeThreadInit(thread);

	if (hWnd == NULL)
	{
		UnregisterClassA(wndclass_name, ms->hInst);
		return;
	}

	//ShowWindow(hWnd, SW_SHOWNORMAL);

	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	vlan_card_should_stop_flag = false;
	vlan_is_in_suspend_mode = false;
	vlan_suspend_mode_begin_tick = 0;

	DestroyWindow(hWnd);

	UnregisterClassA(wndclass_name, ms->hInst);
}

// New suspend handler
MS_SUSPEND_HANDLER *MsNewSuspendHandler()
{
	THREAD *t;
	MS_SUSPEND_HANDLER *h;

	if (Inc(suspend_handler_singleton) >= 2)
	{
		Dec(suspend_handler_singleton);
		return NULL;
	}

	vlan_card_should_stop_flag = false;
	vlan_is_in_suspend_mode = false;
	vlan_suspend_mode_begin_tick = 0;

	h = ZeroMalloc(sizeof(MS_SUSPEND_HANDLER));

	t = NewThread(MsSuspendHandlerThreadProc, h);

	WaitThreadInit(t);

	h->Thread = t;

	return h;
}

void MsFreeSuspendHandler(MS_SUSPEND_HANDLER *h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	if (h->hWnd != NULL)
	{
		h->AboutToClose = true;
		PostMessageA(h->hWnd, WM_CLOSE, 0, 0);
	}

	WaitThread(h->Thread, INFINITE);
	ReleaseThread(h->Thread);

	Free(h);

	Dec(suspend_handler_singleton);

	vlan_card_should_stop_flag = false;
}

// Start in user mode
void MsUserModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon)
{
	WNDCLASS wc;
	HINSTANCE hDll;
	HWND hWnd;
	MSG msg;
	INSTANCE *inst;
	char title_a[MAX_PATH];
	MS_USERMODE_SVC_PULSE_THREAD_PARAM p;
	THREAD *recv_thread = NULL;
	// Validate arguments
	if (title == NULL || start == NULL || stop == NULL)
	{
		return;
	}

	UniToStr(title_a, sizeof(title_a), title);

	is_usermode = true;
	g_start = start;
	g_stop = stop;

	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		if (service_for_9x_mode == false)
		{
			// Do not display an error if Win9x service mode
			MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_USERMODE_MUTEX"), ms->ExeFileNameW);
		}
		return;
	}

	if (Is64())
	{
		hDll = MsLoadLibraryAsDataFile(PENCORE_DLL_NAME);
	}
	else
	{
		hDll = MsLoadLibrary(PENCORE_DLL_NAME);
	}

	// Read icon
	tray_icon = LoadImage(hDll, MAKEINTRESOURCE(icon), IMAGE_ICON, 16, 16,
		(MsIsNt() ? LR_SHARED : 0) | LR_VGACOLOR);

	// Creating the main window
	Zero(&wc, sizeof(wc));
	wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wc.hCursor = LoadCursor(NULL,IDC_ARROW);
	wc.hIcon = LoadIcon(hDll, MAKEINTRESOURCE(icon));
	wc.hInstance = ms->hInst;
	wc.lpfnWndProc = MsUserModeWindowProc;
	wc.lpszClassName = title_a;
	if (RegisterClass(&wc) == 0)
	{
		return;
	}

	hWnd = CreateWindow(title_a, title_a, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL, NULL, ms->hInst, NULL);

	if (hWnd == NULL)
	{
		return;
	}

	Zero(&p, sizeof(p));
	p.hWnd = hWnd;
	p.GlobalPulse = MsCreateUserModeSvcGlocalPulse(g_service_name);

	if (p.GlobalPulse != NULL)
	{
		// Start the global pulse monitoring thread for termination
		p.Halt = false;

		recv_thread = NewThread(MsUserModeGlobalPulseRecvThread, &p);
	}

	hWndUsermode = hWnd;

	wnd_end = false;
	// Window loop
	while (wnd_end == false)
	{
		GetMessage(&msg, NULL, 0, 0);
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	FreeSingleInstance(inst);

	p.hWnd = NULL;

	hWndUsermode = NULL;

	if (p.GlobalPulse != NULL)
	{
		// Terminate the monitoring thread of termination global pulse
		p.Halt = true;
		MsSendGlobalPulse(p.GlobalPulse);

		WaitThread(recv_thread, INFINITE);
		ReleaseThread(recv_thread);

		MsCloseGlobalPulse(p.GlobalPulse);
	}

	// Might abort
	_exit(0);
}

// The thread that wait for global pulse to stop the user mode service
void MsUserModeGlobalPulseRecvThread(THREAD *thread, void *param)
{
	MS_USERMODE_SVC_PULSE_THREAD_PARAM *p = (MS_USERMODE_SVC_PULSE_THREAD_PARAM *)param;
	// Validate arguments
	if (thread == NULL || p == NULL)
	{
		return;
	}

	while (p->Halt == false)
	{
		if (MsWaitForGlobalPulse(p->GlobalPulse, INFINITE))
		{
			break;
		}
	}

	if (p->hWnd != NULL)
	{
		PostMessageA(p->hWnd, WM_CLOSE, 0, 0);
	}
}

// Service stopping procedure main thread
void MsServiceStoperMainThread(THREAD *t, void *p)
{
	// Stopping procedure
	g_stop();
}

// Service stop procedure
bool MsServiceStopProc()
{
	THREAD *thread;
	bool ret = true;
	UINT64 selfkill_timeout = Tick64() + SVC_SELFKILL_TIMEOUT;

	thread = NewThread(MsServiceStoperMainThread, NULL);

	while (WaitThread(thread, 250) == false)
	{
		if (Tick64() >= selfkill_timeout)
		{
			// Suicide when it freezes
			ret = false;
			break;
		}
		// During stopping procedure to complete, call the SetServiceStatus periodically
		status.dwWin32ExitCode = 0;
		status.dwWaitHint = 100000;
		status.dwCheckPoint++;
		status.dwCurrentState = SERVICE_STOP_PENDING;
		_SetServiceStatus(ssh, &status);
	}

	// Report that the stopping is complete
	status.dwWin32ExitCode = 0;
	status.dwWaitHint = 0;
	status.dwCheckPoint = 0;
	status.dwCurrentState = SERVICE_STOPPED;
	_SetServiceStatus(ssh, &status);

	if (ret == false)
	{
		// Force termination here if this has committed suicide
		_exit(-1);
	}
	else
	{
		ReleaseThread(thread);
	}

	return ret;
}

// Service handler
void CALLBACK MsServiceHandler(DWORD opcode)
{
	switch (opcode)
	{
	case SERVICE_CONTROL_SHUTDOWN:
	case SERVICE_CONTROL_STOP:
		// Stopping request
		status.dwWin32ExitCode = 0;
		status.dwWaitHint = 100000;
		status.dwCheckPoint = 0;
		status.dwCurrentState = SERVICE_STOP_PENDING;

		// Set the stopping event
		if (service_stop_event != NULL)
		{
			SetEvent(service_stop_event);
		}
		break;
	}

	_SetServiceStatus(ssh, &status);
}

// Dispatch function of the service
void CALLBACK MsServiceDispatcher(DWORD argc, LPTSTR *argv)
{
	// Creating a stopping event
	service_stop_event = CreateEventA(NULL, true, false, NULL);

	// Preparing for the service
	Zero(&status, sizeof(status));
	status.dwServiceType = SERVICE_WIN32;
	status.dwCurrentState = SERVICE_START_PENDING;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	ssh = _RegisterServiceCtrlHandler(g_service_name, MsServiceHandler);

	if (ssh == NULL)
	{
		MessageBox(NULL, "RegisterServiceCtrlHandler() Failed.", "MsServiceDispatcher()", MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	status.dwWaitHint = 300000;
	status.dwCheckPoint = 0;
	status.dwCheckPoint++;
	status.dwCurrentState = SERVICE_START_PENDING;
	_SetServiceStatus(ssh, &status);

	// Report the start completion
	status.dwWaitHint = 0;
	status.dwCheckPoint = 0;
	status.dwCurrentState = SERVICE_RUNNING;
	_SetServiceStatus(ssh, &status);

	//// Initialization
	// Start of the Mayaqua
#if defined(_DEBUG) || defined(DEBUG)	// In VC++ compilers, the macro is "_DEBUG", not "DEBUG".
	// If set memcheck = true, the program will be vitally slow since it will log all malloc() / realloc() / free() calls to find the cause of memory leak.
	// For normal debug we set memcheck = false.
	// Please set memcheck = true if you want to test the cause of memory leaks.
	InitMayaqua(false, true, 0, NULL);
#else
	InitMayaqua(false, false, 0, NULL);
#endif

	// Stop the MS-IME
	MsDisableIme();

	// Service operation start
	g_start();
	MsUpdateServiceConfig(g_service_name);

	// Wait for the stopping event to be signaled state
	WaitForSingleObject(service_stop_event, INFINITE);

	// Service operation stop
	MsServiceStopProc();
}

// Start as a test mode
void MsTestMode(char *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	wchar_t *title_w = CopyStrToUni(title);

	MsTestModeW(title_w, start, stop);
	Free(title_w);
}
void MsTestModeW(wchar_t *title, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	INSTANCE *inst;
	// Validate arguments
	if (title == NULL || start == NULL || stop == NULL)
	{
		return;
	}

	is_usermode = true;

	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		// Already started
		MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_TEST_MUTEX"), ms->ExeFileNameW);
		return;
	}

	// Start
	start();

	// Display the message
	MsgBoxEx(NULL, MB_ICONINFORMATION | MB_SYSTEMMODAL, _UU("SVC_TEST_MSG"), title);

	// Stop
	stop();

	FreeSingleInstance(inst);
}

// Write the process ID of the process which is calling the service manager
void MsWriteCallingServiceManagerProcessId(char *svcname, UINT pid)
{
	char tmp[MAX_PATH];

	Format(tmp, sizeof(tmp), SVC_CALLING_SM_PROCESS_ID_KEY, svcname);

	if (pid != 0)
	{
		MsRegWriteInt(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
		MsRegWriteInt(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE, pid);
	}
	else
	{
		MsRegDeleteValue(REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKey(REG_LOCAL_MACHINE, tmp);

		MsRegDeleteValue(REG_CURRENT_USER, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
		MsRegDeleteKey(REG_CURRENT_USER, tmp);
	}
}

// Get the process ID of the process which is calling the service manager
UINT MsReadCallingServiceManagerProcessId(char *svcname, bool current_user)
{
	char tmp[MAX_PATH];
	// Validate arguments
	if (svcname == NULL)
	{
		return 0;
	}

	Format(tmp, sizeof(tmp), SVC_CALLING_SM_PROCESS_ID_KEY, svcname);

	return MsRegReadInt(current_user ? REG_CURRENT_USER : REG_LOCAL_MACHINE, tmp, SVC_CALLING_SM_PROCESS_ID_VALUE);
}

// Service main function
UINT MsService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop, UINT icon, char *cmd_line)
{
	UINT mode;
	UINT ret = 0;
	char *arg;
	wchar_t *arg_w;
	TOKEN_LIST *t = NULL;
	UNI_TOKEN_LIST *ut = NULL;
	char *service_name;
	wchar_t *service_title;
	wchar_t *service_description;
	wchar_t *service_title_uni;
	char tmp[MAX_SIZE];
	bool restoreReg = false;
	bool silent = false;
	bool is_win32_service_mode = false;
	// Validate arguments
	if (name == NULL || start == NULL || stop == NULL)
	{
		return ret;
	}

	g_start = start;
	g_stop = stop;
	StrCpy(g_service_name, sizeof(g_service_name), name);
	StrLower(g_service_name);

	// Determine whether it's in Win32 service mode
	if (cmd_line != NULL && lstrcmpiA(cmd_line, SVC_ARG_SERVICE) == 0)
	{
		HINSTANCE h_advapi32 = LoadLibraryA("advapi32.dll");

		if (h_advapi32 != NULL)
		{
			// Check whether there is the SCM in the service mode
			_StartServiceCtrlDispatcher =
				(BOOL (__stdcall *)(const LPSERVICE_TABLE_ENTRY))
				GetProcAddress(h_advapi32, "StartServiceCtrlDispatcherW");

			_RegisterServiceCtrlHandler =
				(SERVICE_STATUS_HANDLE (__stdcall *)(LPCTSTR,LPHANDLER_FUNCTION))
				GetProcAddress(h_advapi32, "RegisterServiceCtrlHandlerW");

			_SetServiceStatus =
				(BOOL (__stdcall *)(SERVICE_STATUS_HANDLE,LPSERVICE_STATUS))
				GetProcAddress(h_advapi32, "SetServiceStatus");

			if (_StartServiceCtrlDispatcher != NULL &&
				_RegisterServiceCtrlHandler != NULL && 
				_SetServiceStatus != NULL)
			{
				is_win32_service_mode = true;
			}
		}
	}

	// Run the service using the SCM in the case of Win32 service mode
	if (is_win32_service_mode)
	{
		SERVICE_TABLE_ENTRY dispatch_table[] =
		{
			{"", MsServiceDispatcher},
			{NULL, NULL},
		};

		MsSetErrorModeToSilent();

		if (_StartServiceCtrlDispatcher(dispatch_table) == false)
		{
			MessageBox(NULL, "StartServiceCtrlDispatcher() Failed.", "MsServiceMode()", MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION | MB_OK | MB_ICONEXCLAMATION);
		}
		else
		{
			MsUpdateServiceConfig(g_service_name);
		}

		// Abort here in the case of using the SCM
		_exit(0);
		return 0;
	}

	// Start of the Mayaqua
#if defined(_DEBUG) || defined(DEBUG)	// In VC++ compilers, the macro is "_DEBUG", not "DEBUG".
	// If set memcheck = true, the program will be vitally slow since it will log all malloc() / realloc() / free() calls to find the cause of memory leak.
	// For normal debug we set memcheck = false.
	// Please set memcheck = true if you want to test the cause of memory leaks.
	InitMayaqua(false, true, 0, NULL);
#else
	InitMayaqua(false, false, 0, NULL);
#endif

	// Stop the MS-IME
	MsDisableIme();

	// Get the information about the service from the string table
	Format(tmp, sizeof(tmp), SVC_NAME, name);
	service_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	service_title = _UU(tmp);
	service_title_uni = _UU(tmp);
	Format(tmp, sizeof(tmp), SVC_DESCRIPT, name);
	service_description = _UU(tmp);

	if (StrLen(service_name) == 0 || UniStrLen(service_title) == 0)
	{
		// The service information isn't found
		MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_NOT_FOUND"), name);
	}
	else
	{
		wchar_t path[MAX_SIZE];
		// Check the argument
		mode = SVC_MODE_NONE;

		t = GetCommandLineToken();
		arg = NULL;

		ut = GetCommandLineUniToken();
		arg_w = NULL;

		if (t->NumTokens >= 1)
		{
			arg = t->Token[0];
		}
		if(t->NumTokens >= 2)
		{
			if(StrCmpi(t->Token[1], SVC_ARG_SILENT) == 0)
			{
				silent = true;
			}
		}

		if (ut->NumTokens >= 1)
		{
			arg_w = ut->Token[0];
		}

		if (arg != NULL)
		{
			if (StrCmpi(arg, SVC_ARG_INSTALL) == 0)
			{
				mode = SVC_MODE_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_UNINSTALL) == 0)
			{
				mode = SVC_MODE_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_START) == 0)
			{
				mode = SVC_MODE_START;
			}
			if (StrCmpi(arg, SVC_ARG_STOP) == 0)
			{
				mode = SVC_MODE_STOP;
			}
			if (StrCmpi(arg, SVC_ARG_TEST) == 0)
			{
				mode = SVC_MODE_TEST;
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE) == 0)
			{
				mode = SVC_MODE_USERMODE;
			}
			if (StrCmpi(arg, SVC_ARG_SETUP_INSTALL) == 0)
			{
				mode = SVC_MODE_SETUP_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_SETUP_UNINSTALL) == 0)
			{
				mode = SVC_MODE_SETUP_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_WIN9X_SERVICE) == 0)
			{
				mode = SVC_MODE_WIN9X_SERVICE;
			}
			if (StrCmpi(arg, SVC_ARG_WIN9X_INSTALL) == 0)
			{
				mode = SVC_MODE_WIN9X_INSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_WIN9X_UNINSTALL) == 0)
			{
				mode = SVC_MODE_WIN9X_UNINSTALL;
			}
			if (StrCmpi(arg, SVC_ARG_TCP) == 0)
			{
				mode = SVC_MODE_TCP;
			}
			if (StrCmpi(arg, SVC_ARG_TCP_UAC) == 0)
			{
				mode = SVC_MODE_TCP_UAC;
			}
			if (StrCmpi(arg, SVC_ARG_TCP_SETUP) == 0)
			{
				mode = SVC_MODE_TCPSETUP;
			}
			if (StrCmpi(arg, SVC_ARG_TRAFFIC) == 0)
			{
				mode = SVC_MODE_TRAFFIC;
			}
			if (StrCmpi(arg, SVC_ARG_UIHELP) == 0)
			{
				mode = SVC_MODE_UIHELP;
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE_SHOWTRAY) == 0)
			{
				char tmp[MAX_SIZE];
				mode = SVC_MODE_USERMODE;
				Format(tmp, sizeof(tmp), SVC_HIDETRAY_REG_VALUE, service_title);
				MsRegDeleteValue(REG_CURRENT_USER, SVC_USERMODE_SETTING_KEY, tmp);
			}
			if (StrCmpi(arg, SVC_ARG_USERMODE_HIDETRAY) == 0)
			{
				char tmp[MAX_SIZE];
				mode = SVC_MODE_USERMODE;
				Format(tmp, sizeof(tmp), SVC_HIDETRAY_REG_VALUE, service_title);
				MsRegWriteInt(REG_CURRENT_USER, SVC_USERMODE_SETTING_KEY, tmp, 1);
			}
			if (StrCmpi(arg, SVC_ARG_SERVICE) == 0)
			{
				mode = SVC_MODE_SERVICE;
			}

			if (mode != SVC_MODE_NONE)
			{
				// Network Config
				MsInitGlobalNetworkConfig();
			}
		}

		// Get the command-line name when running as a service
		UniFormat(path, sizeof(path), SVC_RUN_COMMANDLINE, ms->ExeFileNameW);

		if ((mode == SVC_MODE_INSTALL || mode == SVC_MODE_UNINSTALL || mode == SVC_MODE_START ||
			mode == SVC_MODE_STOP || mode == SVC_MODE_SERVICE) &&
			(ms->IsNt == false))
		{
			// Tried to use the command for the NT in non-WindowsNT system
			MsgBox(NULL, MB_ICONSTOP, _UU("SVC_NT_ONLY"));
		}
		else if ((mode == SVC_MODE_INSTALL || mode == SVC_MODE_UNINSTALL || mode == SVC_MODE_START ||
			mode == SVC_MODE_STOP || mode == SVC_MODE_SERVICE) &&
			(ms->IsAdmin == false))
		{
			// Do not have Administrators privilege
			MsgBox(NULL, MB_ICONEXCLAMATION, _UU("SVC_NOT_ADMIN"));
		}
		else
		{
			// Performs processing depend on mode
			switch (mode)
			{
			case SVC_MODE_NONE:
				// Exit by showing a guidance message
				if (arg_w != NULL && UniEndWith(arg_w, L".vpn"))
				{
					if (MsgBox(NULL, MB_ICONQUESTION | MB_YESNO, _UU("CM_VPN_FILE_CLICKED")) == IDYES)
					{
						wchar_t vpncmgr[MAX_PATH];
						wchar_t filename[MAX_PATH];

						UniFormat(filename, sizeof(filename), L"\"%s\"", arg_w);
						UniFormat(vpncmgr, sizeof(vpncmgr), L"%s\\vpncmgr.exe", MsGetExeDirNameW());

						RunW(vpncmgr, filename, false, false);
					}
				}
				else
				{
					MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_HELP"),
						service_title, service_name, service_title, service_title, service_name, service_title, service_name, service_title, service_name, service_title, service_name, service_title, service_title);
				}
				break;

			case SVC_MODE_SETUP_INSTALL:
				// Setup.exe installation mode
				// Uninstall the old version
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if (MsIsServiceRunning(service_name))
					{
						MsStopService(service_name);
					}
					MsUninstallService(service_name);
				}
				if (MsInstallServiceW(service_name, service_title, service_description, path) == false)
				{
					ret = 1;
				}
				MsStartService(service_name);
				MsWriteCallingServiceManagerProcessId(service_name, 0);
				break;

			case SVC_MODE_SETUP_UNINSTALL:
				// Setup.exe uninstall mode
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					if (MsIsServiceRunning(service_name))
					{
						MsStopService(service_name);
					}
					if (MsUninstallService(service_name) == false)
					{
						ret = 1;
					}
				}
				break;

			case SVC_MODE_INSTALL:
				// Install the service
				// Check whether it is already installed
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name))
				{
					// Already installed
					// Show a message asking if you want to uninstall
					if(silent == true)
					{
						// Always cancel the operation
						break;
					}
					if (MsgBoxEx(NULL, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("SVC_ALREADY_INSTALLED"),
						service_title, service_name) == IDNO)
					{
						// Cancel the operation
						break;
					}
					else
					{
						// Whether the existing service is working?
						if (MsIsServiceRunning(service_name))
						{
							// Try to stop
							if (MsStopService(service_name) == false)
							{
								// Failed to stop
								if(silent == false)
								{
									MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_STOP_FAILED"),
										service_title, service_name);
								}
								break;
							}
						}
						// Uninstall
						if (MsUninstallService(service_name) == false)
						{
							// Failed to uninstall
							if(silent == false)
							{
								MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_UNINSTALL_FAILED"),
									service_title, service_name);
							}
							break;
						}
					}
				}

				// Do the installation
				if (MsInstallServiceW(service_name, service_title, service_description, path) == false)
				{
					// Failed to install
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_INSTALL_FAILED"),
							service_title, service_name);
					}
					break;
				}

				// Start the service
				if (MsStartService(service_name) == false)
				{
					// Failed to start
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_INSTALL_FAILED_2"),
							service_title, service_name, path);
					}
					break;
				}

				// All successful
				if(silent == false)
				{
					MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_INSTALL_OK"),
						service_title, service_name, path);
				}
				break;

			case SVC_MODE_UNINSTALL:
				// Uninstall the service
				// Check whether it is already installed
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_NOT_INSTALLED"),
							service_title, service_name, path);
					}
					break;
				}

				// If the service is currently running, stop it
				if (MsIsServiceRunning(service_name))
				{
					// Stop the service
					if (MsStopService(service_name) == false)
					{
						// Failed to stop
						if(silent == false)
						{
							MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_STOP_FAILED"),
								service_title, service_name);
						}
						break;
					}
				}

				// Uninstall the service
				if (MsUninstallService(service_name) == false)
				{
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONSTOP, _UU("SVC_UNINSTALL_FAILED"),
							service_title, service_name);
					}
					break;
				}

				// All successful
				if(silent == false)
				{
					MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_UNINSTALL_OK"),
						service_title, service_name);
				}
				break;

			case SVC_MODE_START:
				// Start the service
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					// Service is not installed
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_NOT_INSTALLED"),
							service_title, service_name);
					}
					break;
				}

				// Confirm whether the service is running
				if (MsIsServiceRunning(service_name))
				{
					// Service is running
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVR_ALREADY_START"),
							service_title, service_name);
					}
					break;
				}

				// Start the service
				if (MsStartService(service_name) == false)
				{
					// Failed to start
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_START_FAILED"),
							service_title, service_name);
					}
					break;
				}

				// All successful
				if(silent == false)
				{
					MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_START_OK"),
						service_title, service_name);
				}
				break;

			case SVC_MODE_STOP:
				// Stop the service
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsServiceInstalled(service_name) == false)
				{
					// Service is not installed
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_NOT_INSTALLED"),
							service_title, service_name);
					}
					break;
				}

				// Confirm whether the service is running
				if (MsIsServiceRunning(service_name) == false)
				{
					// The service is stopped
					if(silent == false)
					{
					MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_ALREADY_STOP"),
						service_title, service_name);
					}
					break;
				}
				// Stop the service
				if (MsStopService(service_name) == false)
				{
					// Failed to stop
					if(silent == false)
					{
						MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("SVC_STOP_FAILED"),
							service_title, service_name);
					}
					break;
				}

				// All successful
				if(silent == false)
				{
					MsgBoxEx(NULL, MB_ICONINFORMATION, _UU("SVC_STOP_OK"),
						service_title, service_name);
				}
				break;

			case SVC_MODE_TEST:
				// Test mode
				MsTestModeW(service_title, start, stop);
				break;

			case SVC_MODE_WIN9X_SERVICE:
				// Win9x service mode (hide icon in the task tray unconditionally)
				if (MsIsNt())
				{
					// Don't do this on Windows 2000 or later
					break;
				}
				service_for_9x_mode = true;
				// Not a oblivion to break
			case SVC_MODE_USERMODE:
				// User mode
				MsUserModeW(service_title, start, stop, icon);
				break;

			case SVC_MODE_WIN9X_INSTALL:
				// Win9x installation mode
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsNt() == false)
				{
					// Adding a registry key
					char cmdline[MAX_PATH];
					Format(cmdline, sizeof(cmdline), "\"%s\" %s",
						MsGetExeFileName(), SVC_ARG_WIN9X_SERVICE);
					MsRegWriteStr(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_1,
						name, cmdline);
					MsRegWriteStr(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_2,
						name, cmdline);

					// Start
					//Run(MsGetExeFileName(), SVC_ARG_WIN9X_SERVICE, false, false);
				}
				break;

			case SVC_MODE_WIN9X_UNINSTALL:
				// Win9x uninstall mode
				MsWriteCallingServiceManagerProcessId(service_name, MsGetCurrentProcessId());
				restoreReg = true;

				if (MsIsNt() == false)
				{
					// Delete the registry key
					MsRegDeleteValue(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_1,
						name);
					MsRegDeleteValue(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_2,
						name);

					// Terminate all the processes of PacketiX VPN Client other than itself
					MsKillOtherInstance();
				}
				break;

			case SVC_MODE_SERVICE:
				// Run as a service
				// Obsoleted (2012.12.31) (Do this in the above code)
				//MsServiceMode(start, stop);
				break;

			case SVC_MODE_TCP:
			case SVC_MODE_TCP_UAC:
				// TCP Utility
				InitCedar();
				InitWinUi(service_title_uni, NULL, 0);

				if (MsIsVista() && MsIsAdmin() == false && mode != SVC_MODE_TCP_UAC)
				{
					void *handle = NULL;
					if (MsExecuteEx2W(ms->ExeFileNameW, SVC_ARG_TCP_UAC_W, &handle, true) == false)
					{
						ShowTcpIpConfigUtil(NULL, true);
					}
					else
					{
						MsWaitProcessExit(handle);
					}
				}
				else
				{
					ShowTcpIpConfigUtil(NULL, true);
				}

				FreeWinUi();
				FreeCedar();
				break;

			case SVC_MODE_TCPSETUP:
				// TCP optimization mode (This is called by the installer)
				InitCedar();
				InitWinUi(service_title_uni, NULL, 0);

				if (MsIsVista() && MsIsAdmin() == false)
				{
					void *handle = NULL;
					if (MsExecuteEx2W(ms->ExeFileNameW, arg_w, &handle, true) == false)
					{
						ShowTcpIpConfigUtil(NULL, false);
					}
					else
					{
						MsWaitProcessExit(handle);
					}
				}
				else
				{
					ShowTcpIpConfigUtil(NULL, false);
				}

				FreeWinUi();
				FreeCedar();
				break;

			case SVC_MODE_TRAFFIC:
				// Communication throughput measurement tool
				InitCedar();
				InitWinUi(service_title_uni, NULL, 0);
				CmTraffic(NULL);
				FreeWinUi();
				FreeCedar();
				break;

			case SVC_MODE_UIHELP:
				// Starting the UI Helper
				CnStart();
				break;
			}

		}
		FreeToken(t);
		UniFreeToken(ut);

		if (restoreReg)
		{
			MsWriteCallingServiceManagerProcessId(service_name, 0);
		}
	}

	FreeMayaqua();

	return 0;
}

// Get the user name of the specified session
wchar_t *MsGetSessionUserName(UINT session_id)
{
	if (MsIsTerminalServiceInstalled() || MsIsUserSwitchingInstalled())
	{
		wchar_t *ret;
		wchar_t *name;
		UINT size = 0;
		if (ms->nt->WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, session_id,
			WTSUserName, (wchar_t *)&name, &size) == false)
		{
			return NULL;
		}

		if (name == NULL || UniStrLen(name) == 0)
		{
			ret = NULL;
		}
		else
		{
			ret = UniCopyStr(name);
		}

		ms->nt->WTSFreeMemory(name);

		return ret;
	}
	return NULL;
}

// Get whether the current terminal session is active
bool MsIsCurrentTerminalSessionActive()
{
	return MsIsTerminalSessionActive(MsGetCurrentTerminalSessionId());
}

// Get whether the specified terminal session is active
bool MsIsTerminalSessionActive(UINT session_id)
{
	if (MsIsTerminalServiceInstalled() || MsIsUserSwitchingInstalled())
	{
		UINT *status = NULL;
		UINT size = sizeof(status);
		bool active = true;

		if (ms->nt->WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, session_id,
			WTSConnectState, (wchar_t *)&status, &size) == false)
		{
			return true;
		}

		switch (*status)
		{
		case WTSDisconnected:
		case WTSShadow:
		case WTSIdle:
		case WTSDown:
		case WTSReset:
			active = false;
			break;
		}

		ms->nt->WTSFreeMemory(status);

		return active;
	}

	return true;
}

// Get the current terminal session ID
UINT MsGetCurrentTerminalSessionId()
{
	if (MsIsTerminalServiceInstalled() || MsIsUserSwitchingInstalled())
	{
		UINT ret;
		UINT *session_id = NULL;
		UINT size = sizeof(session_id);
		if (ms->nt->WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
			WTSSessionId, (wchar_t *)&session_id, &size) == false)
		{
			return 0;
		}

		ret = *session_id;

		ms->nt->WTSFreeMemory(session_id);

		return ret;
	}

	return 0;
}

// Examine whether the user switching is installed
bool MsIsUserSwitchingInstalled()
{
	OS_INFO *info = GetOsInfo();
	OSVERSIONINFOEX i;

	if (OS_IS_WINDOWS_NT(info->OsType) == false)
	{
		return false;
	}

	if (ms->nt->WTSDisconnectSession == NULL ||
		ms->nt->WTSFreeMemory == NULL ||
		ms->nt->WTSQuerySessionInformation == NULL)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) < 2)
	{
		return false;
	}

	Zero(&i, sizeof(i));
	i.dwOSVersionInfoSize = sizeof(i);
	if (GetVersionEx((OSVERSIONINFO *)&i) == false)
	{
		return false;
	}

	if (i.wSuiteMask & VER_SUITE_SINGLEUSERTS)
	{
		return true;
	}

	return false;
}

// Examine whether Windows 2000 or later
bool MsIsWin2000OrGreater()
{
	OS_INFO *info = GetOsInfo();

	if (OS_IS_WINDOWS_NT(info->OsType) == false)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) >= 2)
	{
		return true;
	}

	return false;
}

// Examine whether Windows XP or later
bool MsIsWinXPOrGreater()
{
	OS_INFO *info = GetOsInfo();

	if (OS_IS_WINDOWS_NT(info->OsType) == false)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) >= 3)
	{
		return true;
	}

	return false;
}

// Examine whether the Terminal Services is installed
bool MsIsTerminalServiceInstalled()
{
	OS_INFO *info = GetOsInfo();
	OSVERSIONINFOEX i;

	if (OS_IS_WINDOWS_NT(info->OsType) == false)
	{
		return false;
	}

	if (ms->nt->WTSDisconnectSession == NULL ||
		ms->nt->WTSFreeMemory == NULL ||
		ms->nt->WTSQuerySessionInformation == NULL)
	{
		return false;
	}

	if (GET_KETA(info->OsType, 100) < 2)
	{
		return false;
	}

	Zero(&i, sizeof(i));
	i.dwOSVersionInfoSize = sizeof(i);
	if (GetVersionEx((OSVERSIONINFO *)&i) == false)
	{
		return false;
	}

	if (i.wSuiteMask & VER_SUITE_TERMINAL || i.wSuiteMask & VER_SUITE_SINGLEUSERTS)
	{
		return true;
	}

	return false;
}

// Stop the service
bool MsStopService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = ms->nt->OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		ret = ms->nt->ControlService(service, SERVICE_CONTROL_STOP, &st);

		ms->nt->CloseServiceHandle(service);
	}

	if (ret)
	{
		UINT64 end = Tick64() + 10000ULL;
		while (Tick64() < end)
		{
			if (MsIsServiceRunning(name) == false)
			{
				break;
			}

			SleepThread(250);
		}
	}

	ms->nt->CloseServiceHandle(sc);
	return ret;
}

// Start the service
bool MsStartService(char *name)
{
	return MsStartServiceEx(name, NULL);
}
bool MsStartServiceEx(char *name, UINT *error_code)
{
	SC_HANDLE sc, service;
	bool ret = false;
	static UINT dummy = 0;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}
	if (error_code == NULL)
	{
		error_code = &dummy;
	}

	*error_code = 0;

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		*error_code = GetLastError();
		return false;
	}

	service = ms->nt->OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		ret = ms->nt->StartService(service, 0, NULL);

		ms->nt->CloseServiceHandle(service);
	}
	else
	{
		*error_code = GetLastError();
	}

	if (ret)
	{
		UINT64 end = Tick64() + 10000ULL;
		while (Tick64() < end)
		{
			if (MsIsServiceRunning(name))
			{
				break;
			}

			SleepThread(250);
		}
	}

	ms->nt->CloseServiceHandle(sc);
	return ret;
}

// Get whether the service is running
bool MsIsServiceRunning(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	// Validate arguments
	if (name == NULL || IsEmptyStr(name))
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}

	sc = ms->nt->OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
	{
		return false;
	}

	service = ms->nt->OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
	{
		SERVICE_STATUS st;
		Zero(&st, sizeof(st));
		if (ms->nt->QueryServiceStatus(service, &st))
		{
			switch (st.dwCurrentState)
			{
			case SERVICE_CONTINUE_PENDING:
			case SERVICE_PAUSE_PENDING:
			case SERVICE_PAUSED:
			case SERVICE_RUNNING:
			case SERVICE_START_PENDING:
			case SERVICE_STOP_PENDING:
				ret = true;
				break;
			}
		}

		ms->nt->CloseServiceHandle(service);
	}

	ms->nt->CloseServiceHandle(sc);
	return ret;
}

// Uninstall the service
bool MsUninstallService(char *name)
{
	SC_HANDLE sc, service;
	bool ret = false;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}

	MsStopService(name);

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = ms->nt->OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		if (ms->nt->DeleteService(service))
		{
			ret = true;
		}
		ms->nt->CloseServiceHandle(service);
	}

	ms->nt->CloseServiceHandle(sc);

	if (ret)
	{
		SleepThread(2000);
	}

	return ret;
}

// Update the title and description of the service
bool MsSetServiceDescription(char *name, wchar_t *description)
{
	SC_HANDLE sc, service;
	// Validate arguments
	if (name == NULL || description == NULL)
	{
		return false;
	}

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = ms->nt->OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_DESCRIPTIONW d;

			if (UniIsEmptyStr(description) == false)
			{
				Zero(&d, sizeof(d));
				d.lpDescription = description;
				ms->nt->ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);
			}
		}

		ms->nt->CloseServiceHandle(service);
	}

	ms->nt->CloseServiceHandle(sc);

	return true;
}

// Update the service setting
bool MsUpdateServiceConfig(char *name)
{
	SC_HANDLE sc, service;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	// Whether just after Windows startup (deadlock prevention)
	if (timeGetTime() <= (60 * 30 * 1000))
	{
		if (MsRegReadInt(REG_LOCAL_MACHINE, "Software\\" GC_REG_COMPANY_NAME "\\Update Service Config", name) != 0)
		{
			return false;
		}
	}

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		return false;
	}

	service = ms->nt->OpenService(sc, name, SERVICE_ALL_ACCESS);
	if (service != NULL)
	{
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_FAILURE_ACTIONS action;
			SC_ACTION *e;
			Zero(&action, sizeof(action));
			e = ZeroMalloc(sizeof(SC_ACTION) * 3);
			e[0].Delay = 10000; e[0].Type = SC_ACTION_RESTART;
			e[1].Delay = 10000; e[1].Type = SC_ACTION_RESTART;
			e[2].Delay = 10000; e[2].Type = SC_ACTION_RESTART;
			action.cActions = 3;
			action.lpsaActions = e;
			action.dwResetPeriod = 1 * 60 * 60 * 24;
			ms->nt->ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &action);

			MsRegWriteInt(REG_LOCAL_MACHINE, "Software\\" GC_REG_COMPANY_NAME "\\Update Service Config", name, 1);
		}

		
		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_DESCRIPTIONW d;
			wchar_t *description;
			char dname[MAX_SIZE];

			Format(dname, sizeof(dname), "SVC_%s_DESCRIPT", name);

			description = _UU(dname);

			if (UniIsEmptyStr(description) == false)
			{
				Zero(&d, sizeof(d));
				d.lpDescription = description;
				ms->nt->ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);
			}
		}

		ms->nt->CloseServiceHandle(service);
	}

	ms->nt->CloseServiceHandle(sc);

	return true;
}

// Install the device driver
bool MsInstallDeviceDriverW(char *name, wchar_t *title, wchar_t *path, UINT *error_code)
{
	SC_HANDLE sc, service;
	bool ret = false;
	wchar_t name_w[MAX_SIZE];
	static UINT temp_int = 0;
	// Validate arguments
	if (name == NULL || title == NULL || path == NULL)
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}
	if (error_code == NULL)
	{
		error_code = &temp_int;
	}

	*error_code = 0;

	StrToUni(name_w, sizeof(name_w), name);

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		*error_code = GetLastError();
		return false;
	}

	service = ms->nt->CreateServiceW(sc, name_w, title, SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);

	if (service != NULL)
	{
		ret = true;

		ms->nt->CloseServiceHandle(service);
	}
	else
	{
		*error_code = GetLastError();
	}

	ms->nt->CloseServiceHandle(sc);

	if (ret)
	{
		SleepThread(2000);
	}

	return ret;
}

// Install the service
bool MsInstallServiceW(char *name, wchar_t *title, wchar_t *description, wchar_t *path)
{
	return MsInstallServiceExW(name, title, description, path, NULL);
}
bool MsInstallServiceExW(char *name, wchar_t *title, wchar_t *description, wchar_t *path, UINT *error_code)
{
	SC_HANDLE sc, service;
	bool ret = false;
	wchar_t name_w[MAX_SIZE];
	static UINT temp_int = 0;
	// Validate arguments
	if (name == NULL || title == NULL || path == NULL)
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}
	if (error_code == NULL)
	{
		error_code = &temp_int;
	}

	*error_code = 0;

	StrToUni(name_w, sizeof(name_w), name);

	sc = ms->nt->OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (sc == NULL)
	{
		*error_code = GetLastError();
		return false;
	}

	service = ms->nt->CreateServiceW(sc, name_w, title, SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS | (MsIsVista() ? 0 : SERVICE_INTERACTIVE_PROCESS), SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL);

	if (service != NULL)
	{
		ret = true;

		if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			SERVICE_DESCRIPTIONW d;
			SERVICE_FAILURE_ACTIONS action;
			SC_ACTION *e;
			Zero(&d, sizeof(d));
			d.lpDescription = description;
			ms->nt->ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &d);
			Zero(&action, sizeof(action));
			e = ZeroMalloc(sizeof(SC_ACTION) * 3);
			e[0].Delay = 10000; e[0].Type = SC_ACTION_RESTART;
			e[1].Delay = 10000; e[1].Type = SC_ACTION_RESTART;
			e[2].Delay = 10000; e[2].Type = SC_ACTION_RESTART;
			action.cActions = 3;
			action.lpsaActions = e;
			action.dwResetPeriod = 1 * 60 * 60 * 24;
			ms->nt->ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &action);

			Free(e);
		}

		ms->nt->CloseServiceHandle(service);
	}
	else
	{
		*error_code = GetLastError();
	}

	ms->nt->CloseServiceHandle(sc);

	if (ret)
	{
		SleepThread(2000);
	}

	return ret;
}

// Check whether the specified service is installed
bool MsIsServiceInstalled(char *name)
{
	SC_HANDLE sc;
	SC_HANDLE service;
	bool ret = false;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}
	if (ms->IsNt == false)
	{
		return false;
	}

	sc = ms->nt->OpenSCManager(NULL, NULL, GENERIC_READ);
	if (sc == NULL)
	{
		return false;
	}

	service = ms->nt->OpenService(sc, name, GENERIC_READ);
	if (service != NULL)
	{
		ret = true;
	}

	ms->nt->CloseServiceHandle(service);
	ms->nt->CloseServiceHandle(sc);

	return ret;
}

// Kill the process
void MsTerminateProcess()
{
	TerminateProcess(GetCurrentProcess(), 0);
	_exit(0);
}

// Get the Process ID
UINT MsGetProcessId()
{
	return GetCurrentProcessId();
}

// Lower the priority of the thread to lowest
void MsSetThreadPriorityIdle()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
}

// Raise the priority of a thread
void MsSetThreadPriorityHigh()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
}

// Raise the priority of the thread to highest
void MsSetThreadPriorityRealtime()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
}

// Restore the priority of the thread
void MsRestoreThreadPriority()
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
}

// Check whether should show the TCP setting application
bool MsIsShouldShowTcpConfigApp()
{
	MS_TCP tcp1, tcp2;
	if (MsIsTcpConfigSupported() == false)
	{
		return false;
	}

	MsGetTcpConfig(&tcp1);
	if (MsLoadTcpConfigReg(&tcp2) == false)
	{
		return true;
	}

	if (Cmp(&tcp1, &tcp2, sizeof(MS_TCP) != 0))
	{
		return true;
	}

	return false;
}

// Apply the temporary settings data of registry to the TCP parameter of the Windows
void MsApplyTcpConfig()
{
	if (MsIsTcpConfigSupported())
	{
		MS_TCP tcp;

		if (MsLoadTcpConfigReg(&tcp))
		{
			MsSetTcpConfig(&tcp);
		}
	}
}

// Check whether the dynamic configuration of TCP is supported in current state
bool MsIsTcpConfigSupported()
{
	if (MsIsNt() && MsIsAdmin())
	{
		UINT type = GetOsInfo()->OsType;

		if (GET_KETA(type, 100) >= 2)
		{
			return true;
		}
	}

	return false;
}

// Read the TCP settings from the registry setting
bool MsLoadTcpConfigReg(MS_TCP *tcp)
{
	// Validate arguments
	if (tcp == NULL)
	{
		return false;
	}

	if (MsIsNt())
	{
		Zero(tcp, sizeof(MS_TCP));

		if (MsRegIsValueEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "RecvWindowSize", true) == false ||
			MsRegIsValueEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "SendWindowSize", true) == false)
		{
			return false;
		}

		tcp->RecvWindowSize = MsRegReadIntEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "RecvWindowSize", true);
		tcp->SendWindowSize = MsRegReadIntEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "SendWindowSize", true);

		return true;
	}
	else
	{
		return false;
	}
}

// Remove the TCP settings from the registry
void MsDeleteTcpConfigReg()
{
	if (MsIsNt() && MsIsAdmin())
	{
		MsRegDeleteKeyEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, true);
	}
}

// Write the TCP settings to the registry setting
void MsSaveTcpConfigReg(MS_TCP *tcp)
{
	// Validate arguments
	if (tcp == NULL)
	{
		return;
	}

	if (MsIsNt() && MsIsAdmin())
	{
		MsRegWriteIntEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "RecvWindowSize", tcp->RecvWindowSize, true);
		MsRegWriteIntEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "SendWindowSize", tcp->SendWindowSize, true);
	}
}

// Get the current TCP settings
void MsGetTcpConfig(MS_TCP *tcp)
{
	// Validate arguments
	if (tcp == NULL)
	{
		return;
	}

	Zero(tcp, sizeof(MS_TCP));

	if (MsIsNt())
	{
		UINT v;
		// Initialize the network setting
		MsInitGlobalNetworkConfig();

		// Read the value of TcpWindowSize or GlobalMaxTcpWindowSize if there is
		v = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "TcpWindowSize");
		tcp->RecvWindowSize = MAX(tcp->RecvWindowSize, v);

		v = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "GlobalMaxTcpWindowSize");
		tcp->RecvWindowSize = MAX(tcp->RecvWindowSize, v);

		v = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters", "DefaultReceiveWindow");
		tcp->RecvWindowSize = MAX(tcp->RecvWindowSize, v);

		// Read the value of DefaultSendWindow if there is
		tcp->SendWindowSize = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters", "DefaultSendWindow");
	}
}

// Write the TCP settings
void MsSetTcpConfig(MS_TCP *tcp)
{
	// Validate arguments
	if (tcp == NULL)
	{
		return;
	}

	if (MsIsNt() && MsIsAdmin())
	{
		bool window_scaling = false;
		UINT tcp1323opts;

		if (tcp->RecvWindowSize >= 65536 || tcp->SendWindowSize >= 65536)
		{
			window_scaling = true;
		}

		// Set the Tcp1323Opts
		tcp1323opts = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Tcp1323Opts");
		if (window_scaling)
		{
			if (tcp1323opts == 0)
			{
				tcp1323opts = 1;
			}
			if (tcp1323opts == 2)
			{
				tcp1323opts = 3;
			}
		}
		else
		{
			if (tcp1323opts == 1)
			{
				tcp1323opts = 0;
			}
			if (tcp1323opts == 3)
			{
				tcp1323opts = 2;
			}
		}
		MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Tcp1323Opts", tcp1323opts);

		// Set the Receive Window
		if (tcp->RecvWindowSize == 0)
		{
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultReceiveWindow");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"TcpWindowSize");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"GlobalMaxTcpWindowSize");
		}
		else
		{
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultReceiveWindow", tcp->RecvWindowSize);
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"TcpWindowSize", tcp->RecvWindowSize);
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"GlobalMaxTcpWindowSize", tcp->RecvWindowSize);
		}

		// Setting the Send Window
		if (tcp->SendWindowSize == 0)
		{
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultSendWindow");
		}
		else
		{
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultSendWindow", tcp->SendWindowSize);
		}
	}
}

// Initialize the global network settings
void MsInitGlobalNetworkConfig()
{
	if (MsIsNt())
	{
		UINT current_window_size;
		current_window_size = MsRegReadInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "TcpWindowSize");

		if (current_window_size == 65535 || current_window_size == 5980160 ||
			current_window_size == 16777216 || current_window_size == 16777214)
		{
			// Remove the strange value which is written by older version of PacketiX VPN
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultReceiveWindow");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters",
				"DefaultSendWindow");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"Tcp1323Opts");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"TcpWindowSize");
			MsRegDeleteValue(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"GlobalMaxTcpWindowSize");

			// Set vpn_no_change = true
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "vpn_no_change", 1);
			MsRegWriteInt(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters", "vpn_no_change", 1);
		}
	}
	else
	{
		if (MsRegReadInt(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\VxD\\MSTCP",
			"packetix_no_optimize") == 0)
		{
			// Disable the DeadGWDetect
			MsRegWriteStr(REG_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\VxD\\MSTCP",
				"DeadGWDetect", "0");
		}
	}

	MsApplyTcpConfig();
}

// Process disabling other off-loading of network and others
void MsDisableNetworkOffloadingEtc()
{
	wchar_t netsh[MAX_SIZE];
	UINT exec_timeout = 10000;
	if (MsIsNt() == false)
	{
		return;
	}

	// Get the path of netsh.exe
	CombinePathW(netsh, sizeof(netsh), MsGetSystem32DirW(), L"netsh.exe");

	// Registry settings
	MsRegWriteIntEx2(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "DisableTaskOffload", 1, false, true);
	MsRegWriteIntEx2(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "TcpNumConnections", TCP_MAX_NUM_CONNECTIONS, false, true);

	if (MsIsVista() == false)
	{
		// Windows Server 2003 or earlier
		MsRegWriteIntEx2(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "EnableRSS", 1, false, true);
		MsRegWriteIntEx2(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "EnableTCPChimney", 1, false, true);
		MsRegWriteIntEx2(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "EnableTCPA", 1, false, true);

		Win32RunAndWaitProcess(netsh, L"netsh int ip set chimney disabled", true, true, exec_timeout);
		SleepThread(250);
	}
	else
	{
		// Windows Vista or later
		Win32RunAndWaitProcess(netsh, L"int ipv4 set global taskoffload=disabled", true, true, exec_timeout);
		SleepThread(250);
		Win32RunAndWaitProcess(netsh, L"int ipv6 set global taskoffload=disabled", true, true, exec_timeout);
		SleepThread(250);
		Win32RunAndWaitProcess(netsh, L"int tcp set global chimney=disabled", true, true, exec_timeout);
		SleepThread(250);
	}
}

// Upgrade the virtual LAN card
bool MsUpgradeVLan(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver)
{
	bool ret;

	Lock(vlan_lock);
	{
		ret = MsUpgradeVLanWithoutLock(tag_name, connection_tag_name, instance_name, ver);
	}
	Unlock(vlan_lock);

	return ret;
}
bool MsUpgradeVLanWithoutLock(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver)
{
	char hwid[MAX_PATH];
	wchar_t hwid_w[MAX_PATH];
	bool ret = false;
	UCHAR old_mac_address[6];
	char *s;
	// Validate arguments
	if (instance_name == NULL || tag_name == NULL || connection_tag_name == NULL || ver == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		// Can not be upgraded in Windows 9x
		return false;
	}

	if (MsIsInfCatalogRequired())
	{
		if (MsIsValidVLanInstanceNameForInfCatalog(instance_name) == false)
		{
			return false;
		}

		StrUpper(instance_name);
	}

	Zero(hwid, sizeof(hwid));
	Format(hwid, sizeof(hwid), DRIVER_DEVICE_ID_TAG, instance_name);
	StrToUni(hwid_w, sizeof(hwid_w), hwid);

	// Examine whether the virtual LAN card with the specified name has already registered
	if (MsIsVLanExists(tag_name, instance_name) == false)
	{
		// Not registered
		return false;
	}

	// Get the previous MAC address
	s = MsGetMacAddress(tag_name, instance_name);
	if (s == NULL)
	{
		Zero(old_mac_address, 6);
	}
	else
	{
		BUF *b;
		b = StrToBin(s);
		Free(s);

		if (b->Size == 6)
		{
			Copy(old_mac_address, b->Buf, b->Size);
		}
		else
		{
			Zero(old_mac_address, 6);
		}

		FreeBuf(b);
	}

	ret = MsUninstallVLanWithoutLock(instance_name);

	ret = MsInstallVLanWithoutLock(tag_name, connection_tag_name, instance_name, ver);

	return ret;
}

// Test for Windows 9x
void MsWin9xTest()
{
}

// Update the CompatibleIDs of virtual LAN card
void MsUpdateCompatibleIDs(char *instance_name)
{
	TOKEN_LIST *t;
	char id[MAX_SIZE];
	char device_title[MAX_SIZE];
	char device_title_old[MAX_SIZE];
	// Validate arguments
	if (instance_name == NULL)
	{
		return;
	}

	Format(id, sizeof(id), DRIVER_DEVICE_ID_TAG, instance_name);
	Format(device_title, sizeof(device_title), VLAN_ADAPTER_NAME_TAG, instance_name);
	Format(device_title_old, sizeof(device_title_old), VLAN_ADAPTER_NAME_TAG_OLD, instance_name);

	t = MsRegEnumKey(REG_LOCAL_MACHINE, "Enum\\Root\\Net");
	if (t != NULL)
	{
		UINT i;
		for (i = 0;i < t->NumTokens;i++)
		{
			char keyname[MAX_PATH];
			char *str;
			char *title;

			Format(keyname, sizeof(keyname), "Enum\\Root\\Net\\%s", t->Token[i]);

			title = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "DeviceDesc");

			if (title != NULL)
			{
				if (StrCmpi(title, device_title) == 0 || StrCmpi(title, device_title_old) == 0)
				{
					Format(keyname, sizeof(keyname), "Enum\\Root\\Net\\%s",t->Token[i]);
					str = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "CompatibleIDs");
					if (str != NULL)
					{
						Free(str);
					}
					else
					{
						MsRegWriteStr(REG_LOCAL_MACHINE, keyname, "CompatibleIDs", id);
					}
				}
				Free(title);
			}
		}

		FreeToken(t);
	}

	MsRegWriteStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup", "SourcePath",
		ms->System32Dir);
}

// Installing the virtual LAN card (for Win9x)
bool MsInstallVLan9x(char *instance_name, MS_DRIVER_VER *ver)
{
	char sysdir[MAX_PATH];
	char infdir[MAX_PATH];
	char otherdir[MAX_PATH];
	char syspath[MAX_PATH];
	char syspath2[MAX_PATH];
	char infpath[MAX_PATH];
	char vpn16[MAX_PATH];
	char infpath_src[MAX_PATH];
	char syspath_src[MAX_PATH];
	char neo_sys[MAX_PATH];
	// Validate arguments
	if (instance_name == NULL || ver == NULL)
	{
		return false;
	}

	StrCpy(sysdir, sizeof(sysdir), MsGetSystem32Dir());
	Format(infdir, sizeof(infdir), "%s\\inf", MsGetWindowsDir());
	Format(otherdir, sizeof(otherdir), "%s\\other", infdir);
	Format(syspath, sizeof(syspath), "%s\\Neo_%s.sys", sysdir, instance_name);
	Format(syspath2, sizeof(syspath2), "%s\\Neo_%s.sys", infdir, instance_name);
	Format(infpath, sizeof(infpath), "%s\\Neo_%s.inf", infdir, instance_name);
	Format(vpn16, sizeof(vpn16), "%s\\vpn16.exe", MsGetMyTempDir());

	MakeDir(otherdir);

	Format(neo_sys, sizeof(neo_sys), "Neo_%s.sys", instance_name);

	// Copy of vpn16.exe
	FileCopy("|vpn16.exe", vpn16);

	// Starting the installation
	if (MsStartDriverInstall(instance_name, NULL, neo_sys, NULL, ver) == false)
	{
		return false;
	}
	MsGetDriverPathA(instance_name, NULL, NULL, infpath_src, syspath_src, NULL, NULL, neo_sys);

	// Copy of the inf file
	FileCopy(infpath_src, infpath);

	// Copy of the sys file
	FileCopy(syspath_src, syspath);

	// Install the device driver
	if (Run(vpn16, instance_name, false, true) == false)
	{
		return false;
	}

	// Update the CompatibleIDs
	MsUpdateCompatibleIDs(instance_name);

	return true;
}

// Child window enumeration procedure
bool CALLBACK MsEnumChildWindowProc(HWND hWnd, LPARAM lParam)
{
	LIST *o = (LIST *)lParam;

	if (o != NULL)
	{
		MsEnumChildWindows(o, hWnd);
	}

	return true;
}

// Enumerate specified window and all the its child windows
LIST *MsEnumChildWindows(LIST *o, HWND hWnd)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	if (o == NULL)
	{
		o = NewListFast(NULL);
	}

	MsAddWindowToList(o, hWnd);

	EnumChildWindows(hWnd, MsEnumChildWindowProc, (LPARAM)o);

	return o;
}

// Add a window to the list
void MsAddWindowToList(LIST *o, HWND hWnd)
{
	// Validate arguments
	if (o == NULL || hWnd == NULL)
	{
		return;
	}

	if (IsInList(o, hWnd) == false)
	{
		Add(o, hWnd);
	}
}

// Enumeration of the window that the thread owns
bool CALLBACK MsEnumThreadWindowProc(HWND hWnd, LPARAM lParam)
{
	LIST *o = (LIST *)lParam;

	if (o == NULL)
	{
		return false;
	}

	MsEnumChildWindows(o, hWnd);

	return true;
}

// Window enumeration procedure
BOOL CALLBACK EnumTopWindowProc(HWND hWnd, LPARAM lParam)
{
	LIST *o = (LIST *)lParam;
	HWND hParent;
	char c1[MAX_SIZE], c2[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || o == NULL)
	{
		return TRUE;
	}

	Zero(c1, sizeof(c1));
	Zero(c2, sizeof(c2));

	hParent = GetParent(hWnd);

	GetClassName(hWnd, c1, sizeof(c1));

	if (hParent != NULL)
	{
		GetClassName(hParent, c2, sizeof(c2));
	}

	if (StrCmpi(c1, "SysIPAddress32") != 0 && (IsEmptyStr(c2) || StrCmpi(c2, "SysIPAddress32") != 0))
	{
		AddWindow(o, hWnd);
	}

	return TRUE;
}

// Child window enumeration procedure
BOOL CALLBACK EnumChildWindowProc(HWND hWnd, LPARAM lParam)
{
	ENUM_CHILD_WINDOW_PARAM *p = (ENUM_CHILD_WINDOW_PARAM *)lParam;
	LIST *o;
	HWND hParent;
	char c1[MAX_SIZE], c2[MAX_SIZE];
	bool ok = false;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return TRUE;
	}

	o = p->o;

	Zero(c1, sizeof(c1));
	Zero(c2, sizeof(c2));

	hParent = GetParent(hWnd);

	GetClassName(hWnd, c1, sizeof(c1));

	if (hParent != NULL)
	{
		GetClassName(hParent, c2, sizeof(c2));
	}

	if (p->include_ipcontrol || (StrCmpi(c1, "SysIPAddress32") != 0 && (IsEmptyStr(c2) || StrCmpi(c2, "SysIPAddress32") != 0)))
	{
		ok = true;
	}

	if (MsIsWine())
	{
		if (StrCmpi(c1, "SysIPAddress32") == 0 || StrCmpi(c2, "SysIPAddress32") == 0)
		{
			ok = true;
		}
	}

	if (ok)
	{
		AddWindow(o, hWnd);

		if (p->no_recursion == false)
		{
			EnumChildWindows(hWnd, EnumChildWindowProc, (LPARAM)p);
		}
	}

	return TRUE;
}
LIST *EnumAllTopWindow()
{
	LIST *o = NewWindowList();

	EnumWindows(EnumTopWindowProc, (LPARAM)o);

	return o;
}

// Enumerate the child windows of all that is in the specified window
LIST *EnumAllChildWindow(HWND hWnd)
{
	return EnumAllChildWindowEx(hWnd, false, false, false);
}
LIST *EnumAllChildWindowEx(HWND hWnd, bool no_recursion, bool include_ipcontrol, bool no_self)
{
	ENUM_CHILD_WINDOW_PARAM p;
	LIST *o = NewWindowList();

	Zero(&p, sizeof(p));
	p.include_ipcontrol = include_ipcontrol;
	p.no_recursion = no_recursion;
	p.o = o;

	if (no_self == false)
	{
		AddWindow(o, hWnd);
	}

	EnumChildWindows(hWnd, EnumChildWindowProc, (LPARAM)&p);

	return o;
}

// Release of the window list
void FreeWindowList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HWND *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

// Add a window to the window list
void AddWindow(LIST *o, HWND hWnd)
{
	HWND t, *e;
	// Validate arguments
	if (o == NULL || hWnd == NULL)
	{
		return;
	}

	t = hWnd;

	if (Search(o, &t) != NULL)
	{
		return;
	}

	e = ZeroMalloc(sizeof(HWND));
	*e = hWnd;

	Insert(o, e);
}

// Comparison of the window list items
int CmpWindowList(void *p1, void *p2)
{
	HWND *h1, *h2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	h1 = *(HWND **)p1;
	h2 = *(HWND **)p2;
	if (h1 == NULL || h2 == NULL)
	{
		return 0;
	}

	return Cmp(h1, h2, sizeof(HWND));
}

// Creating a new window list
LIST *NewWindowList()
{
	return NewListFast(CmpWindowList);
}

// Determine whether it's Windows Vista or later
bool MsIsVista()
{
	OS_INFO *info = GetOsInfo();

	if (info == NULL)
	{
		return false;
	}

	if (OS_IS_WINDOWS_NT(info->OsType))
	{
		if (GET_KETA(info->OsType, 100) >= 5)
		{
			return true;
		}
	}

	return false;
}

// Determine whether it's Windows 7 or later
bool MsIsWindows7()
{
	OS_INFO *info = GetOsInfo();

	if (info == NULL)
	{
		return false;
	}

	if (OS_IS_WINDOWS_NT(info->OsType))
	{
		if (GET_KETA(info->OsType, 100) >= 6)
		{
			return true;
		}
	}

	return false;
}

// Determine whether it's Windows 10 or later
bool MsIsWindows10()
{
	OS_INFO *info = GetOsInfo();

	if (info == NULL)
	{
		return false;
	}

	if (OS_IS_WINDOWS_NT(info->OsType))
	{
		if (GET_KETA(info->OsType, 100) == 7)
		{
			if (GET_KETA(info->OsType, 1) >= 2)
			{
				return true;
			}
		}

		if (GET_KETA(info->OsType, 100) >= 8)
		{
			return true;
		}
	}

	return false;
}

// Determine whether it's Windows 8.1 or later
bool MsIsWindows81()
{
	OS_INFO *info = GetOsInfo();

	if (info == NULL)
	{
		return false;
	}

	if (OS_IS_WINDOWS_NT(info->OsType))
	{
		if (GET_KETA(info->OsType, 100) == 7)
		{
			if (GET_KETA(info->OsType, 1) >= 1)
			{
				return true;
			}
		}

		if (GET_KETA(info->OsType, 100) >= 8)
		{
			return true;
		}
	}

	return false;
}

// Determine whether it's Windows 8 or later
bool MsIsWindows8()
{
	OS_INFO *info = GetOsInfo();

	if (info == NULL)
	{
		return false;
	}

	if (OS_IS_WINDOWS_NT(info->OsType))
	{
		if (GET_KETA(info->OsType, 100) >= 7)
		{
			return true;
		}
	}

	return false;
}

// Whether INF catalog signature is required
bool MsIsInfCatalogRequired()
{
	return MsIsWindows8();
}

// Get the process path of the owner of the window
bool MsGetWindowOwnerProcessExeName(char *path, UINT size, HWND hWnd)
{
	DWORD procId = 0;
	// Validate arguments
	if (path == NULL || hWnd == NULL)
	{
		return false;
	}

	GetWindowThreadProcessId(hWnd, &procId);
	if (procId == 0)
	{
		return false;
	}

	if (MsGetProcessExeName(path, size, procId) == false)
	{
		return false;
	}

	return true;
}

// Get the process path from process ID
bool MsGetProcessExeName(char *path, UINT size, UINT id)
{
	LIST *o;
	MS_PROCESS *proc;
	bool ret = false;
	// Validate arguments
	if (path == NULL)
	{
		return false;
	}

	o = MsGetProcessList();
	proc = MsSearchProcessById(o, id);

	if (proc != NULL)
	{
		ret = true;
		StrCpy(path, size, proc->ExeFilename);
	}

	MsFreeProcessList(o);

	return ret;
}

// Close the alert dialog
bool MsCloseWarningWindow(NO_WARNING *nw, UINT thread_id)
{
	UINT i;
	LIST *o;
	bool ret = false;
	bool press = false;

	if (MsIsVista() == false || nw->StartTimer == 0)
	{
		press = true;
	}

	if (nw->StartTick != 0 && nw->StartTick <= Tick64())
	{
		press = true;
	}

	if (MsIsVista() == false)
	{
		o = NewListFast(NULL);
		EnumThreadWindows(thread_id, MsEnumThreadWindowProc, (LPARAM)o);
	}
	else
	{
		o = EnumAllTopWindow();
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HWND hWnd;

		if (nw->Halt)
		{
			break;
		}
		
		if (MsIsVista() == false)
		{
			hWnd = LIST_DATA(o, i);
		}
		else
		{
			hWnd = *((HWND *)LIST_DATA(o, i));
		}

		if (hWnd != NULL)
		{
			OS_INFO *info = GetOsInfo();

			if (MsIsNt())
			{
				// Get whether this window is a warning screen of driver
				if (MsIsVista() == false)
				{
					// Other than Windows Vista
					HWND hStatic, hOk, hCancel, hDetail;

					hStatic = GetDlgItem(hWnd, 0x14C1);
					hOk = GetDlgItem(hWnd, 0x14B7);
					hCancel = GetDlgItem(hWnd, 0x14BA);
					hDetail = GetDlgItem(hWnd, 0x14B9);

					if ((hStatic != NULL || hDetail != NULL) && hOk != NULL && hCancel != NULL)
					{
						char tmp[MAX_SIZE];
						bool b = false;

						if (GetClassName(hStatic, tmp, sizeof(tmp)) != 0)
						{
							if (StrCmpi(tmp, "static") == 0)
							{
								b = true;
							}
						}

						if (GetClassName(hDetail, tmp, sizeof(tmp)) != 0)
						{
							if (StrCmpi(tmp, "button") == 0)
							{
								b = true;
							}
						}

						if (b)
						{
							if (GetClassName(hOk, tmp, sizeof(tmp)) != 0)
							{
								if (StrCmpi(tmp, "button") == 0)
								{
									if (GetClassName(hCancel, tmp, sizeof(tmp)) != 0)
									{
										if (StrCmpi(tmp, "button") == 0)
										{
											// Press the OK button since it was found
											PostMessage(hWnd, WM_COMMAND, 0x14B7, 0);

											ret = true;
										}
									}
								}
							}
						}
					}
				}
				else
				{
					// Windows Vista
					char exe[MAX_PATH];

					if (MsGetWindowOwnerProcessExeName(exe, sizeof(exe), hWnd))
					{
						if (EndWith(exe, "rundll32.exe"))
						{
							LIST *o;
							HWND h;
							UINT i;

							o = EnumAllChildWindow(hWnd);

							if (o != NULL)
							{
								for (i = 0;i < LIST_NUM(o);i++)
								{
									char tmp[MAX_SIZE];

									h = *((HWND *)LIST_DATA(o, i));

									Zero(tmp, sizeof(tmp));
									GetClassNameA(h, tmp, sizeof(tmp));

									if (StrCmpi(tmp, "DirectUIHWND") == 0)
									{
										LIST *o = EnumAllChildWindow(h);

										if (o != NULL)
										{
											UINT j;
											UINT numDirectUIHWND = 0;
											UINT numButton = 0;
											HWND hButton1 = NULL;
											HWND hButton2 = NULL;

											for (j = 0;j < LIST_NUM(o);j++)
											{
												HWND hh;
												char tmp[MAX_SIZE];

												hh = *((HWND *)LIST_DATA(o, j));

												Zero(tmp, sizeof(tmp));
												GetClassNameA(hh, tmp, sizeof(tmp));

												if (StrCmpi(tmp, "DirectUIHWND") == 0)
												{
													numDirectUIHWND++;
												}

												if (StrCmpi(tmp, "button") == 0)
												{
													numButton++;
													if (hButton1 == NULL)
													{
														hButton1 = hh;
													}
													else
													{
														hButton2 = hh;
													}
												}
											}

											if ((numDirectUIHWND == 1 || numDirectUIHWND == 2) && numButton == 2)
											{
												if (hButton1 != NULL && hButton2 != NULL)
												{
													HWND hButton;
													HWND hParent;
													RECT r1, r2;

													GetWindowRect(hButton1, &r1);
													GetWindowRect(hButton2, &r2);

													hButton = hButton1;

													if (numDirectUIHWND == 1)
													{
														// Warning that there is no signature
														if (r1.top < r2.top)
														{
															hButton = hButton2;
														}
													}
													else
													{
														// Notification that there is signature
														if (r1.left >= r2.left)
														{
															hButton = hButton2;
														}
													}

													hParent = GetParent(hButton);

													// Press the OK button since it was found
													if (press)
													{
														PostMessage(hParent, WM_COMMAND, 1, 0);
													}

													ret = true;
												}
											}

											FreeWindowList(o);
										}
									}
								}

								FreeWindowList(o);
							}
						}
					}
				}
			}
		}
	}

	if (MsIsVista() == false)
	{
		ReleaseList(o);
	}
	else
	{
		FreeWindowList(o);
	}

	if (press == false)
	{
		if (ret)
		{
			ret = false;

			if (nw->StartTick == 0)
			{
				nw->StartTick = Tick64() + nw->StartTimer;
			}
		}
	}

	return ret;
}

// Thread to suppress a warning message
void MsNoWarningThreadProc(THREAD *thread, void *param)
{
	NO_WARNING *nw;
	UINT interval;
	UINT i;
	bool found0 = false;
	// Validate arguments
	if (thread == NULL)
	{
		return;
	}

	nw = (NO_WARNING *)param;

	nw->NoWarningThread = thread;
	AddRef(thread->ref);

	NoticeThreadInit(thread);

	interval = 50;

	if (MsIsVista())
	{
		interval = 1000;
	}

	i = 0;

	while (nw->Halt == false)
	{
		bool found = false;

		// Close the alert dialog
		found = MsCloseWarningWindow(nw, nw->ThreadId);
		if (i == 0)
		{
			found0 = found;
		}
		else
		{
			if (found0 == false && found)
			{
				break;
			}
		}
		i++;

		// Loop until the command incomes from parent thread
		Wait(nw->HaltEvent, interval);
	}
}

// Initialize the procedure to turn off the warning sound
char *MsNoWarningSoundInit()
{
	char *ret = MsRegReadStr(REG_CURRENT_USER, "AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current", "");

	if (IsEmptyStr(ret))
	{
		Free(ret);
		ret = NULL;
	}
	else
	{
		MsRegWriteStr(REG_CURRENT_USER,
			"AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current",
			"", "");
	}

	return ret;
}

// Release of procedure to turn off the warning sound
void MsNoWarningSoundFree(char *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	MsRegWriteStrExpand(REG_CURRENT_USER,
		"AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current",
		"", s);

	Free(s);
}

// The start of the procedure to suppress the warning
NO_WARNING *MsInitNoWarning()
{
	return MsInitNoWarningEx(0);
}
NO_WARNING *MsInitNoWarningEx(UINT start_timer)
{
	THREAD *thread;
	NO_WARNING *nw = ZeroMalloc(sizeof(NO_WARNING));

	nw->StartTimer = (UINT64)start_timer;

	// Get the current sound file name
	if (MsIsVista() == false)
	{
		wchar_t *tmp;

		// Turn off the unnecessary warning tone in Windows XP or earlier
		tmp = MsRegReadStrW(REG_CURRENT_USER, "AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current", "");
		if (UniIsEmptyStr(tmp) == false)
		{
			nw->SoundFileName = CopyUniStr(tmp);

			MsRegWriteStrW(REG_CURRENT_USER,
				"AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current",
				"", L"");
		}

		Free(tmp);
	}

	nw->ThreadId = GetCurrentThreadId();
	nw->HaltEvent = NewEvent();

	thread = NewThread(MsNoWarningThreadProc, nw);
	WaitThreadInit(thread);

	ReleaseThread(thread);

	return nw;
}

// End of the procedure to suppress the warning
void MsFreeNoWarning(NO_WARNING *nw)
{
	// Validate arguments
	if (nw == NULL)
	{
		return;
	}

	nw->Halt = true;
	Set(nw->HaltEvent);

	WaitThread(nw->NoWarningThread, INFINITE);
	ReleaseThread(nw->NoWarningThread);

	ReleaseEvent(nw->HaltEvent);

	if (MsIsVista() == false)
	{
		if (nw->SoundFileName != NULL)
		{
			MsRegWriteStrExpandW(REG_CURRENT_USER,
				"AppEvents\\Schemes\\Apps\\.Default\\SystemAsterisk\\.Current",
				"", nw->SoundFileName);

			Free(nw->SoundFileName);
		}
	}

	Free(nw);
}

// Obtain the name of the directory that the inf catalog file is stored
void MsGetInfCatalogDir(char *dst, UINT size)
{
	// Validate arguments
	if (dst == NULL)
	{
		return;
	}

	Format(dst, size, "|DriverPackages\\%s\\%s", (MsIsWindows10() ? "Neo6_Win10" : "Neo6_Win8"), (MsIsX64() ? "x64" : "x86"));
}

// Examine whether the virtual LAN card name can be used as a instance name of the VLAN
bool MsIsValidVLanInstanceNameForInfCatalog(char *instance_name)
{
	char src_dir[MAX_SIZE];
	char tmp[MAX_SIZE];
	bool ret;
	// Validate arguments
	if (instance_name == NULL)
	{
		return false;
	}

	MsGetInfCatalogDir(src_dir, sizeof(src_dir));

	Format(tmp, sizeof(tmp), "%s\\Neo6_%s_%s.inf", src_dir, (MsIsX64() ? "x64" : "x86"), instance_name);

	ret = IsFile(tmp);

	return ret;
}

// Delete the device information that is about the device which failed during the installation of the same name before installing the virtual LAN card
void MsDeleteTroubleVLAN(char *tag_name, char *instance_name)
{
	HDEVINFO dev_info;
	SP_DEVINFO_LIST_DETAIL_DATA detail_data;
	SP_DEVINFO_DATA data;
	UINT i;
	char target_name[MAX_SIZE];
	LIST *o;
	// Validate arguments
	if (tag_name == NULL || instance_name == NULL)
	{
		return;
	}

	Format(target_name, sizeof(target_name), DRIVER_DEVICE_ID_TAG, instance_name);

	// Create a device information list
	dev_info = SetupDiGetClassDevsEx(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT, NULL, NULL, NULL);
	if (dev_info == NULL)
	{
		return;
	}

	Zero(&detail_data, sizeof(detail_data));
	detail_data.cbSize = sizeof(detail_data);
	if (SetupDiGetDeviceInfoListDetail(dev_info, &detail_data) == false)
	{
		MsDestroyDevInfo(dev_info);
		return;
	}

	Zero(&data, sizeof(data));
	data.cbSize = sizeof(data);

	// Enumeration start
	o = NewListFast(NULL);

	for (i = 0;SetupDiEnumDeviceInfo(dev_info, i, &data);i++)
	{
		char *buffer;
		UINT buffer_size = 8092;
		DWORD data_type;

		buffer = ZeroMalloc(buffer_size);

		if (SetupDiGetDeviceRegistryProperty(dev_info, &data, SPDRP_HARDWAREID, &data_type, (PBYTE)buffer, buffer_size, NULL))
		{
			if (StrCmpi(buffer, target_name) == 0)
			{
				// Found
				SP_DEVINFO_DATA *data2 = Clone(&data, sizeof(SP_DEVINFO_DATA));

				Add(o, data2);
			}
		}

		Free(buffer);
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SP_DEVINFO_DATA *data = LIST_DATA(o, i);
		bool ret;

		ret = SetupDiRemoveDevice(dev_info, data);

		Debug("Deleting Troubled NIC %u: %u\n", i, ret);

		Free(data);
	}

	ReleaseList(o);

	MsDestroyDevInfo(dev_info);
}

// Install a virtual LAN card
bool MsInstallVLan(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver)
{
	bool ret;

	Lock(vlan_lock);
	{
		ret = MsInstallVLanWithoutLock(tag_name, connection_tag_name, instance_name, ver);
	}
	Unlock(vlan_lock);

	return ret;
}
bool MsInstallVLanWithoutLock(char *tag_name, char *connection_tag_name, char *instance_name, MS_DRIVER_VER *ver)
{
	wchar_t infpath[MAX_PATH];
	char hwid[MAX_PATH];
	wchar_t hwid_w[MAX_PATH];
	bool ret = false;
	char neo_sys[MAX_PATH];
	UCHAR new_mac_address[6];
	UINT i;
	// Validate arguments
	if (instance_name == NULL || tag_name == NULL || connection_tag_name == NULL || ver == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		// For Windows 9x
		return MsInstallVLan9x(instance_name, ver);
	}

	if (MsIsInfCatalogRequired())
	{
		if (MsIsValidVLanInstanceNameForInfCatalog(instance_name) == false)
		{
			Debug("MsIsValidVLanInstanceNameForInfCatalog() returns false.\n");
			return false;
		}

		StrUpper(instance_name);
	}

	Zero(hwid, sizeof(hwid));
	Format(hwid, sizeof(hwid), DRIVER_DEVICE_ID_TAG, instance_name);
	StrToUni(hwid_w, sizeof(hwid_w), hwid);

	// Examine whether the virtual LAN card with the specified name has already registered
	if (MsIsVLanExists(tag_name, instance_name))
	{
		// Already be registered
		Debug("MsIsVLanExists() returns true.\n");
		return false;
	}

	// Determining destination .sys file name of the installation
	if (MsIsInfCatalogRequired() == false)
	{
		if (MsMakeNewNeoDriverFilename(neo_sys, sizeof(neo_sys)) == false)
		{
			return false;
		}
	}
	else
	{
		if (MsIsWindows10() == false)
		{
			Format(neo_sys, sizeof(neo_sys), "Neo_%s.sys", instance_name);
		}
		else
		{
			Format(neo_sys, sizeof(neo_sys), "Neo6_%s_%s.sys", (MsIsX64() ? "x64" : "x86"), instance_name);
		}
	}

	// Starting the Installation
	if (MsStartDriverInstall(instance_name, NULL, neo_sys, new_mac_address, ver) == false)
	{
		return false;
	}
	MsGetDriverPath(instance_name, NULL, NULL, infpath, NULL, NULL, NULL, neo_sys);

	// Delete the device information that is left on fail of installation
	if (MsIsNt())
	{
		MsDeleteTroubleVLAN(tag_name, instance_name);
	}

	// Call the Win32 API
	ret = MsInstallVLanInternal(infpath, hwid_w, hwid);

	// Installation complete
	MsFinishDriverInstall(instance_name, neo_sys);

	for (i = 0;i < 5;i++)
	{
		MsInitNetworkConfig(tag_name, instance_name, connection_tag_name);
		if (MsIsInfCatalogRequired())
		{
			// Write the MAC address
			char mac_address_str[MAX_SIZE];
			BinToStr(mac_address_str, sizeof(mac_address_str), new_mac_address, sizeof(new_mac_address));
			MsSetMacAddress(VLAN_ADAPTER_NAME_TAG, instance_name, mac_address_str);
		}

		SleepThread(MsIsVista() ? 1000 : 300);
	}

	if (ret)
	{
		MsDisableVLan(instance_name);
		SleepThread(MsIsVista() ? 1000 : 300);
		MsEnableVLan(instance_name);
	}

	return ret;
}

// Test function
void MsTest()
{
}

// Install a virtual LAN card (by calling Win32 API)
bool MsInstallVLanInternal(wchar_t *infpath, wchar_t *hwid_w, char *hwid)
{
	bool need_reboot;
	bool ret = false;
	wchar_t inf_class_name[MAX_PATH];
	GUID inf_class_guid;
	HDEVINFO device_info;
	SP_DEVINFO_DATA device_info_data;
	// Validate arguments
	if (infpath == NULL || hwid_w == NULL || hwid == NULL)
	{
		return false;
	}

	Debug("MsInstallVLanInternal('%S', '%S', '%s');\n",
		infpath, hwid_w, hwid);

	Zero(&inf_class_guid, sizeof(inf_class_guid));
	Zero(&device_info, sizeof(device_info));
	Zero(&device_info_data, sizeof(device_info_data));
	Zero(inf_class_name, sizeof(inf_class_name));

	// Get the class GUID of the inf file
	if (SetupDiGetINFClassW(infpath, &inf_class_guid, inf_class_name, sizeof(inf_class_name), NULL))
	{
		// Get the device information set
		device_info = SetupDiCreateDeviceInfoList(&inf_class_guid, NULL);
		if (device_info != INVALID_HANDLE_VALUE)
		{
			// Windows 2000 or later
			Zero(&device_info_data, sizeof(device_info_data));
			device_info_data.cbSize = sizeof(device_info_data);
			if (SetupDiCreateDeviceInfoW(device_info, inf_class_name, &inf_class_guid,
				NULL, NULL, DICD_GENERATE_ID, &device_info_data))
			{
				char hwid_copy[MAX_SIZE];
				Zero(hwid_copy, sizeof(hwid_copy));
				StrCpy(hwid_copy, sizeof(hwid_copy), hwid);

				// Set the registry information
				if (SetupDiSetDeviceRegistryProperty(device_info, &device_info_data,
					SPDRP_HARDWAREID, (BYTE *)hwid_copy, sizeof(hwid_copy)))
				{
					NO_WARNING *nw = NULL;

					//if (MsIsVista() == false)
					{
						nw = MsInitNoWarning();
					}

					// Start the class installer
					if (SetupDiCallClassInstaller(DIF_REGISTERDEVICE, device_info,
						&device_info_data))
					{
						// Do the installation
						if (ms->nt->UpdateDriverForPlugAndPlayDevicesW(
							NULL, hwid_w, infpath, 1, &need_reboot))
						{
							ret = true;
						}
						else
						{
							// Installation Failed
							Debug("UpdateDriverForPlugAndPlayDevicesW Error: %X\n", GetLastError());
							if (SetupDiCallClassInstaller(DIF_REMOVE, device_info,
								&device_info_data) == false)
							{
								Debug("SetupDiCallClassInstaller for Delete Failed. Err=%X\n", GetLastError());
							}

							if (SetupDiRemoveDevice(device_info, &device_info_data) == false)
							{
								Debug("SetupDiRemoveDevice for Delete Failed. Err=%X\n", GetLastError());
							}
						}
					}
					else
					{
						Debug("SetupDiCallClassInstaller for Create Error: %X\n", GetLastError());
					}

					MsFreeNoWarning(nw);
				}
				else
				{
					Debug("SetupDiSetDeviceRegistryProperty Error: %X\n", GetLastError());
				}
			}
			else
			{
				Debug("SetupDiCreateDeviceInfoW Error: %X\n", GetLastError());
			}
			// Remove the device information set
			SetupDiDestroyDeviceInfoList(device_info);
		}
		else
		{
			Debug("SetupDiCreateDeviceInfoList Error: %X\n", GetLastError());
		}
	}
	else
	{
		Debug("SetupDiGetINFClassW Error: %X\n", GetLastError());
	}

	return ret;
}

// Get the device information from the device ID
HDEVINFO MsGetDevInfoFromDeviceId(SP_DEVINFO_DATA *dev_info_data, char *device_id)
{
	HDEVINFO dev_info;
	SP_DEVINFO_LIST_DETAIL_DATA detail_data;
	SP_DEVINFO_DATA data;
	UINT i;
	bool found;
	char target_name[MAX_SIZE];
	// Validate arguments
	if (dev_info_data == NULL || device_id == NULL)
	{
		return NULL;
	}

	StrCpy(target_name, sizeof(target_name), device_id);

	// Create a device information list
	dev_info = SetupDiGetClassDevsEx(NULL, NULL, NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT, NULL, NULL, NULL);
	if (dev_info == NULL)
	{
		return NULL;
	}

	Zero(&detail_data, sizeof(detail_data));
	detail_data.cbSize = sizeof(detail_data);
	if (SetupDiGetDeviceInfoListDetail(dev_info, &detail_data) == false)
	{
		MsDestroyDevInfo(dev_info);
		return NULL;
	}

	Zero(&data, sizeof(data));
	data.cbSize = sizeof(data);

	// Enumeration start
	found = false;
	for (i = 0;SetupDiEnumDeviceInfo(dev_info, i, &data);i++)
	{
		char *buffer;
		UINT buffer_size = 8092;
		DWORD data_type;

		buffer = ZeroMalloc(buffer_size);

		if (SetupDiGetDeviceRegistryProperty(dev_info, &data, SPDRP_HARDWAREID, &data_type, (PBYTE)buffer, buffer_size, NULL))
		{
			if (StrCmpi(buffer, target_name) == 0)
			{
				// Found
				found = true;
			}
		}

		Free(buffer);

		if (found)
		{
			break;
		}
	}

	if (found == false)
	{
		MsDestroyDevInfo(dev_info);
		return NULL;
	}
	else
	{
		Copy(dev_info_data, &data, sizeof(data));
		return dev_info;
	}
}

// Examine whether the specified device is operating
bool MsIsDeviceRunning(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data)
{
	SP_DEVINFO_LIST_DETAIL_DATA detail;
	UINT status = 0, problem = 0;
	// Validate arguments
	if (info == NULL || dev_info_data == NULL)
	{
		return false;
	}

	Zero(&detail, sizeof(detail));
	detail.cbSize = sizeof(detail);

	if (SetupDiGetDeviceInfoListDetail(info, &detail) == false ||
		ms->nt->CM_Get_DevNode_Status_Ex(&status, &problem, dev_info_data->DevInst,
		0, detail.RemoteMachineHandle) != CR_SUCCESS)
	{
		return false;
	}

	if (status & 8)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Start the specified device
bool MsStartDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data)
{
	SP_PROPCHANGE_PARAMS p;
	// Validate arguments
	if (info == NULL || dev_info_data == NULL)
	{
		return false;
	}

	Zero(&p, sizeof(p));
	p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	p.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	p.StateChange = DICS_ENABLE;
	p.Scope = DICS_FLAG_GLOBAL;
	if (SetupDiSetClassInstallParams(info, dev_info_data, &p.ClassInstallHeader, sizeof(p)))
	{
		SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, info, dev_info_data);
	}

	Zero(&p, sizeof(p));
	p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	p.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	p.StateChange = DICS_ENABLE;
	p.Scope = DICS_FLAG_CONFIGSPECIFIC;

	if (SetupDiSetClassInstallParams(info, dev_info_data, &p.ClassInstallHeader, sizeof(p)) == false ||
		SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, info, dev_info_data) == false)
	{
		return false;
	}

	return true;
}

// Stop the specified device
bool MsStopDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data)
{
	SP_PROPCHANGE_PARAMS p;
	// Validate arguments
	if (info == NULL || dev_info_data == NULL)
	{
		return false;
	}

	Zero(&p, sizeof(p));
	p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	p.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	p.StateChange = DICS_DISABLE;
	p.Scope = DICS_FLAG_CONFIGSPECIFIC;

	if (SetupDiSetClassInstallParams(info, dev_info_data, &p.ClassInstallHeader, sizeof(p)) == false ||
		SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, info, dev_info_data) == false)
	{
		return false;
	}

	return true;
}

// Remove the specified device
bool MsDeleteDevice(HDEVINFO info, SP_DEVINFO_DATA *dev_info_data)
{
	SP_REMOVEDEVICE_PARAMS p;
	SP_DEVINFO_LIST_DETAIL_DATA detail;
	char device_id[MAX_PATH];
	CONFIGRET ret;
	// Validate arguments
	if (info == NULL || dev_info_data == NULL)
	{
		return false;
	}

	Zero(&detail, sizeof(detail));
	detail.cbSize = sizeof(detail);

	if (SetupDiGetDeviceInfoListDetail(info, &detail) == false)
	{
		Debug("SetupDiGetDeviceInfoListDetail Failed. Err=0x%X\n", GetLastError());
		return false;
	}

	ret = ms->nt->CM_Get_Device_ID_Ex(dev_info_data->DevInst, device_id, sizeof(device_id),
		0, detail.RemoteMachineHandle);
	if (ret != CR_SUCCESS)
	{
		Debug("CM_Get_Device_ID_Ex Failed. Err=0x%X\n", ret);
		return false;
	}

	Zero(&p, sizeof(p));
	p.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	p.ClassInstallHeader.InstallFunction = DIF_REMOVE;
	p.Scope = DI_REMOVEDEVICE_GLOBAL;

	if (SetupDiSetClassInstallParams(info, dev_info_data, &p.ClassInstallHeader, sizeof(p)) == false)
	{
		Debug("SetupDiSetClassInstallParams Failed. Err=0x%X\n", GetLastError());
		return false;
	}

	if (SetupDiCallClassInstaller(DIF_REMOVE, info, dev_info_data) == false)
	{
		Debug("SetupDiCallClassInstaller Failed. Err=0x%X\n", GetLastError());
		return false;
	}

	return true;
}

// Enable the virtual LAN card
bool MsEnableVLan(char *instance_name)
{
	bool ret;

	Lock(vlan_lock);
	{
		ret = MsEnableVLanWithoutLock(instance_name);
	}
	Unlock(vlan_lock);

	return ret;
}
bool MsEnableVLanWithoutLock(char *instance_name)
{
	char tmp[MAX_PATH];
	HDEVINFO h;
	bool ret;
	SP_DEVINFO_DATA data;
	// Validate arguments
	if (instance_name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		return false;
	}

	Format(tmp, sizeof(tmp), DRIVER_DEVICE_ID_TAG, instance_name);

	h = MsGetDevInfoFromDeviceId(&data, tmp);
	if (h == NULL)
	{
		return false;
	}

	ret = MsStartDevice(h, &data);

	MsDestroyDevInfo(h);

	return ret;
}

// Disable the virtual LAN card
bool MsDisableVLan(char *instance_name)
{
	bool ret;

	Lock(vlan_lock);
	{
		ret = MsDisableVLanWithoutLock(instance_name);
	}
	Unlock(vlan_lock);

	return ret;
}
bool MsDisableVLanWithoutLock(char *instance_name)
{
	char tmp[MAX_PATH];
	HDEVINFO h;
	bool ret;
	SP_DEVINFO_DATA data;
	// Validate arguments
	if (instance_name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		return false;
	}

	Format(tmp, sizeof(tmp), DRIVER_DEVICE_ID_TAG, instance_name);

	h = MsGetDevInfoFromDeviceId(&data, tmp);
	if (h == NULL)
	{
		return false;
	}

	ret = MsStopDevice(h, &data);

	MsDestroyDevInfo(h);

	return ret;
}

// Restart the virtual LAN card
void MsRestartVLan(char *instance_name)
{
	Lock(vlan_lock);
	{
		MsRestartVLanWithoutLock(instance_name);
	}
	Unlock(vlan_lock);
}
void MsRestartVLanWithoutLock(char *instance_name)
{
	// Validate arguments
	if (instance_name == NULL)
	{
		return;
	}

	if (MsIsNt() == false)
	{
		return;
	}

	if (MsIsVLanEnabled(instance_name) == false)
	{
		return;
	}

	MsDisableVLan(instance_name);
	MsEnableVLan(instance_name);
}

// Get whether the virtual LAN card is working
bool MsIsVLanEnabled(char *instance_name)
{
	bool ret;

	Lock(vlan_lock);
	{
		ret = MsIsVLanEnabledWithoutLock(instance_name);
	}
	Unlock(vlan_lock);

	return ret;
}
bool MsIsVLanEnabledWithoutLock(char *instance_name)
{
	char tmp[MAX_PATH];
	HDEVINFO h;
	bool ret;
	SP_DEVINFO_DATA data;
	// Validate arguments
	if (instance_name == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		return true;
	}

	Format(tmp, sizeof(tmp), DRIVER_DEVICE_ID_TAG, instance_name);

	h = MsGetDevInfoFromDeviceId(&data, tmp);
	if (h == NULL)
	{
		return false;
	}

	ret = MsIsDeviceRunning(h, &data);

	MsDestroyDevInfo(h);

	return ret;
}

// Uninstall the virtual LAN card
bool MsUninstallVLan(char *instance_name)
{
	bool ret;

	Lock(vlan_lock);
	{
		ret = MsUninstallVLanWithoutLock(instance_name);
	}
	Unlock(vlan_lock);

	return ret;
}
bool MsUninstallVLanWithoutLock(char *instance_name)
{
	char tmp[MAX_PATH];
	HDEVINFO h;
	bool ret;
	SP_DEVINFO_DATA data;
	// Validate arguments
	if (instance_name == NULL)
	{
		return false;
	}

	Format(tmp, sizeof(tmp), DRIVER_DEVICE_ID_TAG, instance_name);

	h = MsGetDevInfoFromDeviceId(&data, tmp);
	if (h == NULL)
	{
		return false;
	}

	ret = MsDeleteDevice(h, &data);

	MsDestroyDevInfo(h);

	return ret;
}

// Dispose the device information
void MsDestroyDevInfo(HDEVINFO info)
{
	// Validate arguments
	if (info == NULL)
	{
		return;
	}

	SetupDiDestroyDeviceInfoList(info);
}

// Start the driver installation
bool MsStartDriverInstall(char *instance_name, UCHAR *mac_address, char *neo_sys, UCHAR *ret_mac_address, MS_DRIVER_VER *ver)
{
	wchar_t src_inf[MAX_PATH];
	wchar_t src_sys[MAX_PATH];
	wchar_t dest_inf[MAX_PATH];
	wchar_t dest_sys[MAX_PATH];
	wchar_t src_cat[MAX_PATH];
	wchar_t dst_cat[MAX_PATH];
	UCHAR mac_address_bin[6];
	char mac_address_str[32];
	UINT size;
	char *tmp;
	BUF *b;
	IO *io;
	char str_year[16];
	char str_month[16];
	char str_day[16];
	char str_major[16];
	char str_minor[16];
	char str_build[16];
	// Validate arguments
	if (instance_name == NULL || neo_sys == NULL || ver == NULL)
	{
		return false;
	}

	Format(str_year, sizeof(str_year), "%04d", ver->Year);
	Format(str_month, sizeof(str_month), "%02d", ver->Month);
	Format(str_day, sizeof(str_day), "%02d", ver->Day);

	ToStr(str_major, ver->Major);
	ToStr(str_minor, ver->Minor);
	ToStr(str_build, ver->Build);

	MsGetDriverPath(instance_name, src_inf, src_sys, dest_inf, dest_sys, src_cat, dst_cat, neo_sys);
	Debug("MsStartDriverInstall\n");
	Debug("  instance_name: %s\n", instance_name);
	Debug("  src_inf: %S\n", src_inf);
	Debug("  src_sys: %S\n", src_sys);
	Debug("  dest_inf: %S\n", dest_inf);
	Debug("  dest_sys: %S\n", dest_sys);
	Debug("  src_cat: %S\n", src_cat);
	Debug("  dst_cat: %S\n", dst_cat);
	Debug("  neo_sys: %s\n", neo_sys);

	// Processing INF file
	io = FileOpenW(src_inf, false);
	if (io == NULL)
	{
		return false;
	}

	size = FileSize(io);
	tmp = ZeroMalloc(size * 2);
	if (FileRead(io, tmp, size) == false)
	{
		FileClose(io);
		Free(tmp);
		return false;
	}

	FileClose(io);

	if (mac_address == NULL)
	{
		MsGenMacAddress(mac_address_bin);
	}
	else
	{
		Copy(mac_address_bin, mac_address, 6);
	}

	BinToStr(mac_address_str, sizeof(mac_address_str), mac_address_bin, sizeof(mac_address_bin));

	//ReplaceStrEx(tmp, size * 2, tmp, "$TAG_DRIVER_VER$", DRIVER_VER_STR, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$TAG_INSTANCE_NAME$", instance_name, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$TAG_MAC_ADDRESS$", mac_address_str, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$TAG_SYS_NAME$", neo_sys, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$YEAR$", str_year, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$MONTH$", str_month, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$DAY$", str_day, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$VER_MAJOR$", str_major, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$VER_MINOR$", str_minor, false);
	ReplaceStrEx(tmp, size * 2, tmp, "$VER_BUILD$", str_build, false);

	if (MsIsVista())
	{
		//ReplaceStrEx(tmp, size * 2, tmp, "\"100\"", "\"2000\"", false);
	}

	io = FileCreateW(dest_inf);
	if (io == NULL)
	{
		Free(tmp);
		return false;
	}

	FileWrite(io, tmp, StrLen(tmp));
	FileClose(io);

	Free(tmp);

	// Processing the SYS file
	b = ReadDumpW(src_sys);
	if (b == NULL)
	{
		return false;
	}

	if (DumpBufW(b, dest_sys) == false)
	{
		FreeBuf(b);
		return false;
	}

	FreeBuf(b);

	// Copy of the catalog file
	if (IsEmptyUniStr(src_cat) == false && IsEmptyUniStr(dst_cat) == false)
	{
		if (FileCopyW(src_cat, dst_cat) == false)
		{
			return false;
		}
	}

	if (ret_mac_address != NULL)
	{
		Copy(ret_mac_address, mac_address_bin, 6);
	}

	return true;
}

// Generation of the MAC address
void MsGenMacAddress(UCHAR *mac)
{
	UCHAR hash_src[40];
	UCHAR hash[20];
	UINT64 now;
	// Validate arguments
	if (mac == NULL)
	{
		return;
	}

	Rand(hash_src, 40);
	now = SystemTime64();
	Copy(hash_src, &now, sizeof(now));

	Sha0(hash, hash_src, sizeof(hash_src));

	mac[0] = 0x5E;
	mac[1] = hash[0];
	mac[2] = hash[1];
	mac[3] = hash[2];
	mac[4] = hash[3];
	mac[5] = hash[4];
}

// Finish the driver installation
void MsFinishDriverInstall(char *instance_name, char *neo_sys)
{
	wchar_t src_inf[MAX_PATH];
	wchar_t src_sys[MAX_PATH];
	wchar_t dest_inf[MAX_PATH];
	wchar_t dest_sys[MAX_PATH];
	wchar_t src_cat[MAX_SIZE];
	wchar_t dst_cat[MAX_SIZE];
	// Validate arguments
	if (instance_name == NULL)
	{
		return;
	}

	MsGetDriverPath(instance_name, src_inf, src_sys, dest_inf, dest_sys, src_cat, dst_cat, neo_sys);

	// Delete the files
	FileDeleteW(dest_inf);
	FileDeleteW(dest_sys);

	if (IsEmptyUniStr(dst_cat) == false)
	{
		FileDeleteW(dst_cat);
	}
}

// Get the path to the driver file
void MsGetDriverPath(char *instance_name, wchar_t *src_inf, wchar_t *src_sys, wchar_t *dest_inf, wchar_t *dest_sys, wchar_t *src_cat, wchar_t *dest_cat, char *neo_sys)
{
	wchar_t *src_filename;
	wchar_t *src_sys_filename;
	// Validate arguments
	if (instance_name == NULL)
	{
		return;
	}

	// WinNT x86
	src_filename = L"|DriverPackages\\Neo\\x86\\Neo_x86.inf";
	src_sys_filename = L"|DriverPackages\\Neo\\x86\\Neo_x86.sys";

	if (MsIsNt() == false)
	{
		// Win9x
		src_filename = L"|DriverPackages\\Neo9x\\x86\\Neo9x_x86.inf";
		src_sys_filename = L"|DriverPackages\\Neo9x\\x86\\Neo9x_x86.sys";
	}
	else if (MsIsX64())
	{
		// WinNT x64
		src_filename = L"|DriverPackages\\Neo\\x64\\Neo_x64.inf";
		src_sys_filename = L"|DriverPackages\\Neo\\x64\\Neo_x64.sys";
	}

	if (MsIsWindows7())
	{
		// Use the NDIS 6.2 driver for Windows 7 or later
		if (MsIsX64())
		{
			src_filename = L"|DriverPackages\\Neo6\\x64\\Neo6_x64.inf";
			src_sys_filename = L"|DriverPackages\\Neo6\\x64\\Neo6_x64.sys";
		}
		else
		{
			src_filename = L"|DriverPackages\\Neo6\\x86\\Neo6_x86.inf";
			src_sys_filename = L"|DriverPackages\\Neo6\\x86\\Neo6_x86.sys";
		}
	}

	if (MsIsInfCatalogRequired())
	{
		// Windows 8 or later
		if (MsIsX64())
		{
			src_filename = L"|DriverPackages\\Neo6_Win8\\x64\\Neo6_x64.inf";
			src_sys_filename = L"|DriverPackages\\Neo6_Win8\\x64\\Neo6_x64.sys";
		}
		else
		{
			src_filename = L"|DriverPackages\\Neo6_Win8\\x86\\Neo6_x86.inf";
			src_sys_filename = L"|DriverPackages\\Neo6_Win8\\x86\\Neo6_x86.sys";
		}
	}

	if (src_inf != NULL)
	{
		if (MsIsInfCatalogRequired() == false)
		{
			// Windows 7 or before
			UniStrCpy(src_inf, MAX_PATH, src_filename);
		}
		else
		{
			// Windows 8.1 or later
			char tmp[MAX_SIZE];

			MsGetInfCatalogDir(tmp, sizeof(tmp));

			UniFormat(src_inf, MAX_PATH, L"%S\\Neo6_%S_%S.inf", tmp, (MsIsX64() ? "x64" : "x86"), instance_name);
		}
	}

	if (src_sys != NULL)
	{
		UniStrCpy(src_sys, MAX_PATH, src_sys_filename);

		if (MsIsWindows10())
		{
			UniFormat(src_sys, MAX_PATH, L"|DriverPackages\\Neo6_Win10\\%S\\Neo6_%S_%S.sys",
				(MsIsX64() ? "x64" : "x86"), (MsIsX64() ? "x64" : "x86"), instance_name);
		}
	}

	if (dest_inf != NULL)
	{
		char inf_name[MAX_PATH];

		if (MsIsInfCatalogRequired() == false)
		{
			Format(inf_name, sizeof(inf_name), "Neo_%s.inf", instance_name);
		}
		else
		{
			Format(inf_name, sizeof(inf_name), "Neo6_%s_%s.inf", (MsIsX64() ? "x64" : "x86"), instance_name);
		}
		UniFormat(dest_inf, MAX_PATH, L"%s\\%S", ms->MyTempDirW, inf_name);
	}

	if (dest_sys != NULL)
	{
		char sys_name[MAX_PATH];
		StrCpy(sys_name, sizeof(sys_name), neo_sys);
		UniFormat(dest_sys, MAX_PATH, L"%s\\%S", ms->MyTempDirW, sys_name);
	}

	if (src_cat != NULL)
	{
		if (MsIsInfCatalogRequired())
		{
			char tmp[MAX_SIZE];

			MsGetInfCatalogDir(tmp, sizeof(tmp));

			if (MsIsWindows8() == false)
			{
				// Windows Vista and Windows 7 uses SHA-1 catalog files
				// (Unused? Never reach here!)
				UniFormat(src_cat, MAX_PATH, L"%S\\inf.cat", tmp);
			}
			else
			{
				// Windows 8 or above uses SHA-256 catalog files
				UniFormat(src_cat, MAX_PATH, L"%S\\inf2.cat", tmp);
			}

			if (MsIsWindows10())
			{
				// Windows 10
				UniFormat(src_cat, MAX_PATH, L"%S\\Neo6_%S_%S.cat", tmp, (MsIsX64() ? "x64" : "x86"), instance_name);
			}
		}
		else
		{
			UniStrCpy(src_cat, MAX_PATH, L"");
		}
	}

	if (dest_cat != NULL)
	{
		if (MsIsInfCatalogRequired())
		{
			if (MsIsWindows10() == false)
			{
				UniFormat(dest_cat, MAX_PATH, L"%s\\inf_%S.cat", ms->MyTempDirW, instance_name);
			}
			else
			{
				UniFormat(dest_cat, MAX_PATH, L"%s\\Neo6_%S_%S.cat", ms->MyTempDirW, (MsIsX64() ? "x64" : "x86"), instance_name);
			}
		}
		else
		{
			UniStrCpy(dest_cat, MAX_PATH, L"");
		}
	}
}
void MsGetDriverPathA(char *instance_name, char *src_inf, char *src_sys, char *dest_inf, char *dest_sys, char *src_cat, char *dst_cat, char *neo_sys)
{
	wchar_t src_inf_w[MAX_PATH];
	wchar_t src_sys_w[MAX_PATH];
	wchar_t dest_inf_w[MAX_PATH];
	wchar_t dest_sys_w[MAX_PATH];
	wchar_t src_cat_w[MAX_PATH];
	wchar_t dst_cat_w[MAX_PATH];

	// Validate arguments
	if (instance_name == NULL)
	{
		return;
	}

	MsGetDriverPath(instance_name, src_inf_w, src_sys_w, dest_inf_w, dest_sys_w, src_cat_w, dst_cat_w, neo_sys);

	UniToStr(src_inf, MAX_PATH, src_inf_w);
	UniToStr(src_sys, MAX_PATH, src_sys_w);
	UniToStr(dest_inf, MAX_PATH, dest_inf_w);
	UniToStr(dest_sys, MAX_PATH, dest_sys_w);
	UniToStr(src_cat, MAX_PATH, src_cat_w);
	UniToStr(dst_cat, MAX_PATH, dst_cat_w);
}

// Examine whether the virtual LAN card with the specified name has already registered
bool MsIsVLanExists(char *tag_name, char *instance_name)
{
	char *guid;
	// Validate arguments
	if (instance_name == NULL || tag_name == NULL)
	{
		return false;
	}

	guid = MsGetNetworkAdapterGuid(tag_name, instance_name);
	if (guid == NULL)
	{
		return false;
	}

	Free(guid);
	return true;
}

// Delete VPN temporary directories that remain in the system but not used
void MsDeleteTempDir()
{
	HANDLE h;
	wchar_t dir_mask[MAX_PATH];
	WIN32_FIND_DATAA data_a;
	WIN32_FIND_DATAW data_w;

	Zero(&data_a, sizeof(data_a));
	Zero(&data_w, sizeof(data_w));

	UniFormat(dir_mask, sizeof(dir_mask), L"%s\\*", ms->TempDirW);

	if (IsNt())
	{
		h = FindFirstFileW(dir_mask, &data_w);
	}
	else
	{
		char *tmp_a = CopyUniToStr(dir_mask);

		h = FindFirstFileA(tmp_a, &data_a);

		Free(tmp_a);
	}

	if (h != INVALID_HANDLE_VALUE)
	{
		bool b = true;

		do
		{
			if (IsNt() == false)
			{
				Zero(&data_w, sizeof(data_w));
				StrToUni(data_w.cFileName, sizeof(data_w.cFileName), data_a.cFileName);
				data_w.dwFileAttributes = data_a.dwFileAttributes;
				data_w.ftCreationTime = data_a.ftCreationTime;
				data_w.ftLastWriteTime = data_a.ftLastWriteTime;
				data_w.nFileSizeHigh = data_a.nFileSizeHigh;
				data_w.nFileSizeLow = data_a.nFileSizeLow;
			}

			if (UniStrCmpi(data_w.cFileName, L".") != 0 &&
				UniStrCmpi(data_w.cFileName, L"..") != 0)
			{
				if (data_w.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (UniStartWith(data_w.cFileName, L"VPN_") && UniStrLen(data_w.cFileName) == 8)
					{
						wchar_t lock_file_name[MAX_PATH];
						wchar_t dir_name[MAX_PATH];
						bool delete_now = false;
						IO *io;

						UniFormat(dir_name, sizeof(dir_name), L"%s\\%s",
							ms->TempDirW, data_w.cFileName);
						MsGenLockFile(lock_file_name, sizeof(lock_file_name), dir_name);

						io = FileOpenExW(lock_file_name, false, false);
						if (io != NULL)
						{
							// Mark to delete if the lock file is not locked
							FileClose(io);
							io = FileOpenW(lock_file_name, true);
							if (io != NULL)
							{
								delete_now = true;
								FileClose(io);
							}
						}
						else
						{
							DIRLIST *d;

							// Mark to delete if all files in this folder are not locked
							delete_now = true;

							d = EnumDirW(dir_name);
							if (d != NULL)
							{
								UINT i;

								for (i = 0;i < d->NumFiles;i++)
								{
									wchar_t full_path[MAX_PATH];

									UniFormat(full_path, sizeof(full_path), L"%s\\%s", dir_name, d->File[i]->FileNameW);

									io = FileOpenW(full_path, true);
									if (io != NULL)
									{
										delete_now = true;
										FileClose(io);
									}
								}
								FreeDir(d);
							}
						}
						if (delete_now)
						{
							MsDeleteAllFileW(dir_name);

							Win32DeleteDirW(dir_name);
						}
					}
				}
			}


			Zero(&data_w, sizeof(data_w));
			Zero(&data_a, sizeof(data_a));

			if (IsNt())
			{
				b = FindNextFileW(h, &data_w);
			}
			else
			{
				b = FindNextFileA(h, &data_a);
			}
		}
		while (b);

		FindClose(h);
	}
}

// Delete all the files in the specified directory
void MsDeleteAllFile(char *dir)
{
	HANDLE h;
	char file_mask[MAX_PATH];
	WIN32_FIND_DATA data;
	// Validate arguments
	if (dir == NULL || IsEmptyStr(dir))
	{
		return;
	}

	Format(file_mask, sizeof(file_mask), "%s\\*.*", dir);

	h = FindFirstFile(file_mask, &data);
	if (h != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (StrCmpi(data.cFileName, ".") != 0 &&
				StrCmpi(data.cFileName, "..") != 0)
			{
				char fullpath[MAX_PATH];
				Format(fullpath, sizeof(fullpath), "%s\\%s", dir, data.cFileName);
				if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == false)
				{
					DeleteFile(fullpath);
				}
				else
				{
					MsDeleteAllFile(fullpath);
					RemoveDirectory(fullpath);
				}
			}
		}
		while (FindNextFile(h, &data));

		FindClose(h);
	}
}
void MsDeleteAllFileW(wchar_t *dir)
{
	HANDLE h;
	wchar_t file_mask[MAX_PATH];
	WIN32_FIND_DATAW data;
	// Validate arguments
	if (dir == NULL || UniIsEmptyStr(dir))
	{
		return;
	}

	if (IsNt() == false)
	{
		char *dir_a = CopyUniToStr(dir);

		MsDeleteAllFile(dir_a);

		Free(dir_a);

		return;
	}

	UniFormat(file_mask, sizeof(file_mask), L"%s\\*.*", dir);

	h = FindFirstFileW(file_mask, &data);
	if (h != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (UniStrCmpi(data.cFileName, L".") != 0 &&
				UniStrCmpi(data.cFileName, L"..") != 0)
			{
				wchar_t fullpath[MAX_PATH];

				UniFormat(fullpath, sizeof(fullpath), L"%s\\%s", dir, data.cFileName);

				if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == false)
				{
					DeleteFileW(fullpath);
				}
				else
				{
					MsDeleteAllFileW(fullpath);
					RemoveDirectoryW(fullpath);
				}
			}
		}
		while (FindNextFileW(h, &data));

		FindClose(h);
	}
}

// Initialize the temporary directory
void MsInitTempDir()
{
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[16];
	UCHAR random[2];
	wchar_t lockfilename[MAX_PATH];
	UINT num = 0;

	// Delete the unused temporary directory
	MsDeleteTempDir();

	// Determine the name of the temporary directory
	while (true)
	{
		random[0] = rand() % 256;
		random[1] = rand() % 256;
		BinToStrW(tmp2, sizeof(tmp2), random, sizeof(random));

		UniFormat(tmp, sizeof(tmp), L"%s\\VPN_%s", ms->TempDirW, tmp2);

		// Create Directory
		if (MakeDirW(tmp))
		{
			break;
		}

		if ((num++) >= 100)
		{
			// Failed many times
			char msg[MAX_SIZE];
			Format(msg, sizeof(msg),
				"Couldn't create Temporary Directory: %s\r\n\r\n"
				"Please contact your system administrator.",
				tmp);
			exit(0);
		}
	}

	ms->MyTempDirW = CopyUniStr(tmp);
	ms->MyTempDir = CopyUniToStr(tmp);

	// Create a lock file
	MsGenLockFile(lockfilename, sizeof(lockfilename), ms->MyTempDirW);
	ms->LockFile = FileCreateW(lockfilename);
}

// Release the temporary directory
void MsFreeTempDir()
{
	wchar_t lock_file_name[MAX_SIZE];

	// Delete the lock file
	MsGenLockFile(lock_file_name, sizeof(lock_file_name), ms->MyTempDirW);
	FileClose(ms->LockFile);

	// Memory release
	Free(ms->MyTempDir);
	Free(ms->MyTempDirW);
	ms->MyTempDir = NULL;
	ms->MyTempDirW = NULL;

	// Delete directory
	MsDeleteTempDir();
}

// Generation of the name of the lock file
void MsGenLockFile(wchar_t *name, UINT size, wchar_t *temp_dir)
{
	// Validate arguments
	if (name == NULL || temp_dir == NULL)
	{
		return;
	}

	UniFormat(name, size, L"%s\\VPN_Lock.dat", temp_dir);
}

// Normalization of the configuration of the interface metric of the default gateway in the network configuration
void MsNormalizeInterfaceDefaultGatewaySettings(char *tag_name, char *instance_name)
{
	char tmp[MAX_SIZE];
	char netsh[MAX_PATH];
	char *config_str;
	char tmp2[MAX_SIZE];
	UINT if_index;
	UINT if_metric;
	// Validate arguments
	if (tag_name == NULL || instance_name == NULL)
	{
		return;
	}

	Debug("MsNormalizeInterfaceDefaultGatewaySettings()\n");

	if (MsIsVista() == false)
	{
		Debug("MsIsVista() == false\n");
		return;
	}

	Format(tmp2, sizeof(tmp2), tag_name, instance_name);
	if_index = Win32GetVLanInterfaceID(tmp2);
	Debug("if_index=%u\n", if_index);

	if (if_index == 0)
	{
		return;
	}

	CombinePath(netsh, sizeof(netsh), MsGetSystem32Dir(), "netsh.exe");

	// Set the interface metric value
	config_str = MsGetNetworkAdapterGuid(tag_name, instance_name);
	if (config_str != NULL)
	{
		LIST *o;
		LIST *o2;

		Debug("MsNormalizeInterfaceDefaultGatewaySettings()\n");
		Debug("if_index(%s) = %u\n", instance_name, if_index);

		Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
			config_str);

		o = MsRegReadStrList(REG_LOCAL_MACHINE, tmp, "DefaultGateway");
		o2 = MsRegReadStrList(REG_LOCAL_MACHINE, tmp, "DefaultGatewayMetric");

		if_metric = MsRegReadInt(REG_LOCAL_MACHINE, tmp, "InterfaceMetric");
		Debug("if_metric = %u\n", if_metric);

		if (if_metric != 0)
		{
			if (o != NULL)
			{
				UINT i;

				for (i = 0;i < LIST_NUM(o);i++)
				{
					char *s = LIST_DATA(o, i);
					char tmp[MAX_SIZE];

					char *cm = NULL;
					UINT current_metric;

					if (o2 != NULL)
					{
						if (LIST_NUM(o2) > i)
						{
							current_metric = ToInt(LIST_DATA(o2, i));
						}
					}

					Debug("gateway[%u] = %s\n", i, s);
					Debug("current_metric[%u] = %u\n", i, current_metric);

					if (current_metric == 0)
					{
						if (IsEmptyStr(s) == false)
						{
							Format(tmp, sizeof(tmp), "int ipv4 delete route prefix=0.0.0.0/0 interface=%u nexthop=%s",
								if_index, s);
							Debug("netsh %s\n", tmp);
							Run(netsh, tmp, true, true);

							Format(tmp, sizeof(tmp), "int ipv4 add route prefix=0.0.0.0/0 interface=%u nexthop=%s metric=%u",
								if_index, s, if_metric);
							Debug("netsh %s\n", tmp);
							Run(netsh, tmp, true, true);
						}
					}
				}
			}
		}

		FreeStrList(o);
		FreeStrList(o2);

		Free(config_str);
	}
}

// Initialization of the network configuration
void MsInitNetworkConfig(char *tag_name, char *instance_name, char *connection_tag_name)
{
	char tmp[MAX_SIZE];
	char *config_str;
	// Validate arguments
	if (tag_name == NULL || instance_name == NULL || connection_tag_name == NULL)
	{
		return;
	}

	if (MsIsNt() == false)
	{
		return;
	}

	// Settings such as string
	Format(tmp, sizeof(tmp), connection_tag_name, instance_name);
	MsSetNetworkConfig(tag_name, instance_name, tmp, true);

	// Set the interface metric value
	config_str = MsGetNetworkAdapterGuid(tag_name, instance_name);
	if (config_str != NULL)
	{
		Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
			config_str);

		MsRegWriteInt(REG_LOCAL_MACHINE, tmp, "InterfaceMetric", 1);
		MsRegWriteInt(REG_LOCAL_MACHINE, tmp, "EnableDeadGWDetect", 0);

		if (MsRegReadInt(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
			"packetix_no_optimize") == 0)
		{
			MsRegWriteInt(REG_LOCAL_MACHINE,
				"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
				"EnableDeadGWDetect",
				0);
		}

		Free(config_str);
	}
}

// Configure the network settings
void MsSetNetworkConfig(char *tag_name, char *instance_name, char *friendly_name, bool show_icon)
{
	char *key;
	char *old_name;
	// Validate arguments
	if (tag_name == NULL || instance_name == NULL || friendly_name == NULL)
	{
		return;
	}

	key = MsGetNetworkConfigRegKeyNameFromInstanceName(tag_name, instance_name);
	if (key == NULL)
	{
		return;
	}

	old_name = MsRegReadStr(REG_LOCAL_MACHINE, key, "Name");
	if (old_name != NULL)
	{
		if (MsIsVista())
		{
			char arg[MAX_PATH];
			char netsh[MAX_PATH];

			Format(netsh, sizeof(netsh), "%s\\netsh.exe", MsGetSystem32Dir());

			if (StrCmp(old_name, friendly_name) != 0)
			{
				Format(arg, sizeof(arg), "interface set interface name=\"%s\" newname=\"%s\"",
					old_name, friendly_name);

				Run(netsh, arg, true, true);
			}

			Format(arg, sizeof(arg), "netsh interface ipv4 set interface interface=\"%s\" metric=1",
				friendly_name);

			Run(netsh, arg, true, true);
		}
	}

	if (StrCmp(old_name, friendly_name) != 0)
	{
		MsRegWriteStr(REG_LOCAL_MACHINE, key, "Name", friendly_name);
	}

	MsRegWriteInt(REG_LOCAL_MACHINE, key, "ShowIcon", show_icon ? 1 : 0);

	Free(key);

	Free(old_name);
}

// Get the network configuration key name by the instance name
char *MsGetNetworkConfigRegKeyNameFromInstanceName(char *tag_name, char *instance_name)
{
	char *guid, *ret;
	// Validate arguments
	if (tag_name == NULL || instance_name == NULL)
	{
		return NULL;
	}

	guid = MsGetNetworkAdapterGuid(tag_name, instance_name);
	if (guid == NULL)
	{
		return NULL;
	}

	ret = MsGetNetworkConfigRegKeyNameFromGuid(guid);

	Free(guid);

	return ret;
}

// Get the network configuration key name by the GUID
char *MsGetNetworkConfigRegKeyNameFromGuid(char *guid)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (guid == NULL)
	{
		return NULL;
	}

	Format(tmp, sizeof(tmp),
		"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection",
		guid);

	return CopyStr(tmp);
}

// Configuring the MAC address
void MsSetMacAddress(char *tag_name, char *instance_name, char *mac_address)
{
	TOKEN_LIST *key_list;
	UINT i;
	char dest_name[MAX_SIZE];
	char mac_str[MAX_SIZE];
	// Validate arguments
	if (tag_name == NULL || instance_name == NULL)
	{
		return;
	}

	// Normalization of the MAC address
	if (NormalizeMacAddress(mac_str, sizeof(mac_str), mac_address) == false)
	{
		return;
	}

	// Generate the desired name
	Format(dest_name, sizeof(dest_name), tag_name, instance_name);

	// Enumerate the key
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return;
	}

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// Read the DriverDesc
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			if (StrCmpi(dest_name, driver_desc) == 0)
			{
				// Writing of the MAC address
				MsRegWriteStr(REG_LOCAL_MACHINE, full_key_name, "NetworkAddress", mac_str);
				Free(driver_desc);

				// Restarting the driver
				MsRestartVLan(instance_name);
				break;
			}
			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	return;
}

// Get the file name of the device driver
char *MsGetDriverFileName(char *tag_name, char *instance_name)
{
	TOKEN_LIST *key_list;
	UINT i;
	char *ret = NULL;
	char dest_name[MAX_SIZE];
	// Validate arguments
	if (tag_name == NULL || instance_name == NULL)
	{
		return NULL;
	}

	// Generate the desired name
	Format(dest_name, sizeof(dest_name), tag_name, instance_name);

	// Enumerate the key
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return NULL;
	}

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// Read the DriverDesc
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			if (StrCmpi(dest_name, driver_desc) == 0)
			{
				// Read the file name
				ret = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DeviceVxDs");
				Free(driver_desc);
				break;
			}
			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	return ret;
}

// Get the version of the device driver
char *MsGetDriverVersion(char *tag_name, char *instance_name)
{
	TOKEN_LIST *key_list;
	TOKEN_LIST *t;
	UINT i;
	char *ret = NULL;
	char dest_name[MAX_SIZE];
	// Validate arguments
	if (tag_name == NULL || instance_name == NULL)
	{
		return NULL;
	}

	// Generate the desired name
	Format(dest_name, sizeof(dest_name), tag_name, instance_name);

	// Enumerate the key
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return NULL;
	}

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// Read the DriverDesc
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			if (StrCmpi(dest_name, driver_desc) == 0)
			{
				// Read the version information
				ret = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverVersion");
				if (ret == NULL)
				{
					ret = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "NeoVersion");
				}
				Free(driver_desc);
				break;
			}
			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	if (ret == NULL)
	{
		return NULL;
	}

	t = ParseToken(ret, ", ");
	if (t->NumTokens == 2)
	{
		Free(ret);
		ret = CopyStr(t->Token[1]);
	}
	FreeToken(t);

	return ret;
}

// Get the MAC address
char *MsGetMacAddress(char *tag_name, char *instance_name)
{
	TOKEN_LIST *key_list;
	UINT i;
	char *ret = NULL;
	char dest_name[MAX_SIZE];
	// Validate arguments
	if (tag_name == NULL || instance_name == NULL)
	{
		return NULL;
	}

	// Generate the desired name
	Format(dest_name, sizeof(dest_name), tag_name, instance_name);

	// Enumerate the key
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}

	if (key_list == NULL)
	{
		return NULL;
	}

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// Read the DriverDesc
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			if (StrCmpi(dest_name, driver_desc) == 0)
			{
				// Read the MAC address
				ret = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "NetworkAddress");

				if (IsEmptyStr(ret) == false)
				{
					// Insert hyphens between the MAC address elements
					BUF *b = StrToBin(ret);
					if (b != NULL && b->Size == 6)
					{
						char tmp[MAX_SIZE];
						MacToStr(tmp, sizeof(tmp), b->Buf);

						Free(ret);
						ret = CopyStr(tmp);
					}
					FreeBuf(b);
				}

				Free(driver_desc);
				break;
			}
			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	return ret;
}

// Check whether the device name of the virtual LAN card exists really
bool MsCheckVLanDeviceIdFromRootEnum(char *name)
{
	TOKEN_LIST *t;
	char *root;
	char *keyname;
	UINT i;
	bool ret;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (MsIsNt())
	{
		root = "SYSTEM\\CurrentControlSet\\Enum\\Root\\NET";
		keyname = "HardwareID";
	}
	else
	{
		root = "Enum\\Root\\Net";
		keyname = "CompatibleIDs";
	}

	t = MsRegEnumKey(REG_LOCAL_MACHINE, root);
	if (t == NULL)
	{
		return false;
	}

	ret = false;

	for (i = 0;i < t->NumTokens;i++)
	{
		char *subname = t->Token[i];
		char fullname[MAX_SIZE];
		char *value;

		Format(fullname, sizeof(fullname), "%s\\%s", root, subname);

		value = MsRegReadStr(REG_LOCAL_MACHINE, fullname, keyname);
		if (value != NULL)
		{
			if (StrCmpi(value, name) == 0)
			{
				ret = true;
			}
			Free(value);
		}

		if (ret)
		{
			break;
		}
	}

	FreeToken(t);

	return ret;
}

// Get the GUID of the network adapter
char *MsGetNetworkAdapterGuid(char *tag_name, char *instance_name)
{
	TOKEN_LIST *key_list;
	UINT i;
	char *ret = NULL;
	char dest_name[MAX_SIZE];
	// Validate arguments
	if (tag_name == NULL || instance_name == NULL)
	{
		return NULL;
	}

	// Generate the desired name
	Format(dest_name, sizeof(dest_name), tag_name, instance_name);

	// Enumerate the key
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return NULL;
	}

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;
		char *device_id;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		device_id = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "MatchingDeviceId");

		if (device_id != NULL)
		{
			if (MsCheckVLanDeviceIdFromRootEnum(device_id))
			{
				// Read the DriverDesc
				driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
				if (driver_desc != NULL)
				{
					if (StrCmpi(dest_name, driver_desc) == 0)
					{
						// Read the NetCfgInstanceId
						if (MsIsNt())
						{
							ret = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "NetCfgInstanceId");
						}
						else
						{
							ret = CopyStr("");
						}
						Free(driver_desc);
						Free(device_id);
						break;
					}
					Free(driver_desc);
				}
			}
			Free(device_id);
		}
	}

	FreeToken(key_list);

	return ret;
}
// Get the network connection name
wchar_t *MsGetNetworkConnectionName(char *guid)
{
	wchar_t *ncname = NULL;
	// Validate arguments
	if (guid == NULL)
	{
		return NULL;
	}

	// Get the network connection name
	if (IsNt() != false && GetOsInfo()->OsType >= OSTYPE_WINDOWS_2000_PROFESSIONAL)
	{
		char tmp[MAX_SIZE];
		Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection", guid);
		ncname = MsRegReadStrW(REG_LOCAL_MACHINE, tmp, "Name");
	}

	return ncname;
}

// Generate driver file name for the new Neo
bool MsMakeNewNeoDriverFilename(char *name, UINT size)
{
	TOKEN_LIST *t = MsEnumNeoDriverFilenames();
	UINT i;
	bool ret = false;

	i = 0;
	while (true)
	{
		char tmp[MAX_PATH];
		UINT n;

		i++;
		if (i >= 10000)
		{
			break;
		}

		n = Rand32() % DRIVER_INSTALL_SYS_NAME_TAG_MAXID;

		MsGenerateNeoDriverFilenameFromInt(tmp, sizeof(tmp), n);

		if (IsInToken(t, tmp) == false)
		{
			StrCpy(name, size, tmp);
			ret = true;
			break;
		}
	}

	FreeToken(t);

	return ret;
}

// Generate the driver file name of Neo from a integer
void MsGenerateNeoDriverFilenameFromInt(char *name, UINT size, UINT n)
{
	Format(name, size, DRIVER_INSTALL_SYS_NAME_TAG_NEW, n);
}

// Enumeration of the driver file names of installed Neo
TOKEN_LIST *MsEnumNeoDriverFilenames()
{
	TOKEN_LIST *neos = MsEnumNetworkAdaptersNeo();
	LIST *o = NewListFast(NULL);
	TOKEN_LIST *ret;
	UINT i;

	for (i = 0;i < neos->NumTokens;i++)
	{
		char filename[MAX_PATH];
		if (MsGetNeoDriverFilename(filename, sizeof(filename), neos->Token[i]))
		{
			Add(o, CopyStr(filename));
		}
	}

	FreeToken(neos);

	ret = ListToTokenList(o);
	FreeStrList(o);

	return ret;
}

// Get the driver file name of Neo
bool MsGetNeoDriverFilename(char *name, UINT size, char *instance_name)
{
	char tmp[MAX_SIZE];
	char *ret;
	// Validate arguments
	if (name == NULL || instance_name == NULL)
	{
		return false;
	}

	Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Services\\Neo_%s", instance_name);

	ret = MsRegReadStr(REG_LOCAL_MACHINE, tmp, "ImagePath");
	if (ret == NULL)
	{
		return false;
	}

	GetFileNameFromFilePath(name, size, ret);
	Free(ret);

	return true;
}

// Enumeration of the network adapter (only Neo)
TOKEN_LIST *MsEnumNetworkAdaptersNeo()
{
	TOKEN_LIST *key_list;
	TOKEN_LIST *ret;
	LIST *o;
	UINT i;

	// Enumerate the key
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return NULL;
	}

	o = NewListFast(CompareStr);

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;
		char *device_id;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// Read the DriverDesc
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			// Check whether it starts with the specific name
			device_id = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "MatchingDeviceId");

			if (device_id != NULL)
			{
				if (MsCheckVLanDeviceIdFromRootEnum(device_id))
				{
					char *tag = "neoadapter_";
					if (StartWith(device_id, tag))
					{
						char tmp[MAX_SIZE];
						StrCpy(tmp, sizeof(tmp), &device_id[StrLen(tag)]);

						Add(o, CopyStr(tmp));
					}
				}
				Free(device_id);
			}

			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = LIST_NUM(o);
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	return ret;
}

// Enumeration of the network adapter
TOKEN_LIST *MsEnumNetworkAdapters(char *start_with_name, char *start_with_name_2)
{
	TOKEN_LIST *key_list;
	TOKEN_LIST *ret;
	LIST *o;
	UINT i;

	// Enumerate the key
	if (MsIsNt())
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");
	}
	else
	{
		key_list = MsRegEnumKey(REG_LOCAL_MACHINE,
			"System\\CurrentControlSet\\Services\\Class\\Net");
	}
	if (key_list == NULL)
	{
		return NULL;
	}

	o = NewListFast(CompareStr);

	for (i = 0;i < key_list->NumTokens;i++)
	{
		char *key_name = key_list->Token[i];
		char full_key_name[MAX_SIZE];
		char *driver_desc;
		char *device_id;

		if (MsIsNt())
		{
			Format(full_key_name, sizeof(full_key_name),
				"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}\\%s",
				key_name);
		}
		else
		{
			Format(full_key_name, sizeof(full_key_name),
				"System\\CurrentControlSet\\Services\\Class\\Net\\%s",
				key_name);
		}

		// Read the DriverDesc
		driver_desc = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "DriverDesc");
		if (driver_desc != NULL)
		{
			// Check whether it starts with the specific name
			if ((IsEmptyStr(start_with_name) && IsEmptyStr(start_with_name_2)) ||
				(StartWith(driver_desc, start_with_name) || StartWith(driver_desc, start_with_name_2)))
			{
				device_id = MsRegReadStr(REG_LOCAL_MACHINE, full_key_name, "MatchingDeviceId");

				if (device_id != NULL)
				{
					if (MsCheckVLanDeviceIdFromRootEnum(device_id))
					{
						char instance_name[MAX_SIZE];
						// Extract only the instance name from the name
						if (StartWith(driver_desc, start_with_name))
						{
							if (StrLen(driver_desc) > (StrLen(start_with_name) + 3))
							{
								StrCpy(instance_name, sizeof(instance_name),
									driver_desc + StrLen(start_with_name) + 3);
								Add(o, CopyStr(instance_name));
							}
						}
						else
						{
							if (StrLen(driver_desc) > (StrLen(start_with_name_2) + 3))
							{
								StrCpy(instance_name, sizeof(instance_name),
									driver_desc + StrLen(start_with_name_2) + 3);
								Add(o, CopyStr(instance_name));
							}
						}
					}
					Free(device_id);
				}
			}

			Free(driver_desc);
		}
	}

	FreeToken(key_list);

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = LIST_NUM(o);
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	return ret;
}

// Attempt to logon to the domain
bool MsCheckLogon(wchar_t *username, char *password)
{
	wchar_t password_unicode[MAX_SIZE];
	HANDLE h;
	// Validate arguments
	if (username == NULL || password == NULL)
	{
		return false;
	}

	if (MsIsNt() == false)
	{
		return false;
	}

	StrToUni(password_unicode, sizeof(password_unicode), password);

	if (GET_KETA(GetOsInfo()->OsType, 100) >= 2)
	{
		if (ms->nt->LogonUserW(username, NULL, password_unicode, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
		{
			// Logon failure
			return false;
		}
	}
	else
	{
		char username_ansi[MAX_SIZE];
		UniToStr(username_ansi, sizeof(username_ansi), username);

		if (ms->nt->LogonUserA(username_ansi, NULL, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &h) == false)
		{
			// Logon failure
			return false;
		}
	}

	CloseHandle(h);

	return true;
}

// Execute the shutdown
bool MsShutdown(bool reboot, bool force)
{
	UINT flag = 0;
	// Get the privilege
	if (MsEnablePrivilege(SE_SHUTDOWN_NAME, true) == false)
	{
		return false;
	}

	flag |= (reboot ? EWX_REBOOT : EWX_SHUTDOWN);
	flag |= (force ? EWX_FORCE : 0);

	// Execute the shutdown
	if (ExitWindowsEx(flag, 0) == false)
	{
		MsEnablePrivilege(SE_SHUTDOWN_NAME, false);
		return false;
	}

	// Release of privilege
	MsEnablePrivilege(SE_SHUTDOWN_NAME, false);

	return true;
}

// Enable or disable the privilege
bool MsEnablePrivilege(char *name, bool enable)
{
	HANDLE hToken;
	NT_API *nt = ms->nt;
	LUID luid;
	TOKEN_PRIVILEGES *tp;
	bool ret;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}
	if (MsIsNt() == false)
	{
		return true;
	}

	// Open the process token
	if (nt->OpenProcessToken(ms->hCurrentProcess, TOKEN_ADJUST_PRIVILEGES, &hToken) == false)
	{
		return false;
	}

	// Get a local unique identifier
	if (nt->LookupPrivilegeValue(NULL, name, &luid) == FALSE)
	{
		CloseHandle(hToken);
		return false;
	}

	// Create a structure to enable / disable the privilege
	tp = ZeroMalloc(sizeof(TOKEN_PRIVILEGES));
	tp->PrivilegeCount = 1;
	tp->Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	Copy(&tp->Privileges[0].Luid, &luid, sizeof(LUID));

	// Manipulate the privilege
	ret = nt->AdjustTokenPrivileges(hToken, false, tp, sizeof(TOKEN_PRIVILEGES), 0, 0);

	Free(tp);
	CloseHandle(hToken);

	return ret;
}

// Get whether the current OS is a NT system
bool MsIsNt()
{
	if (ms == NULL)
	{
		OSVERSIONINFO os;
		Zero(&os, sizeof(os));
		os.dwOSVersionInfoSize = sizeof(os);
		GetVersionEx(&os);
		if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	return ms->IsNt;
}

// Get whether the current system is WINE
bool MsIsWine()
{
	bool ret = false;

	if (ms == NULL)
	{
		HINSTANCE h = LoadLibrary("kernel32.dll");

		if (h != NULL)
		{
			if (GetProcAddress(h, "wine_get_unix_file_name") != NULL)
			{
				ret = true;
			}

			FreeLibrary(h);
		}
	}
	else
	{
		ret = ms->IsWine;
	}

	return ret;
}

// Get whether the current user is an Admin
bool MsIsAdmin()
{
	return ms->IsAdmin;
}

// Load the NT system function
NT_API *MsLoadNtApiFunctions()
{
	NT_API *nt = ZeroMalloc(sizeof(NT_API));
	OSVERSIONINFO info;

	Zero(&info, sizeof(info));
	info.dwOSVersionInfoSize = sizeof(info);
	GetVersionEx(&info);

	nt->hKernel32 = LoadLibrary("kernel32.dll");
	if (nt->hKernel32 == NULL)
	{
		Free(nt);
		return NULL;
	}

	nt->hAdvapi32 = LoadLibrary("advapi32.dll");
	if (nt->hAdvapi32 == NULL)
	{
		Free(nt);
		return NULL;
	}

	nt->hShell32 = LoadLibrary("shell32.dll");
	if (nt->hShell32 == NULL)
	{
		FreeLibrary(nt->hAdvapi32);
		Free(nt);
		return NULL;
	}

	nt->hPsApi = LoadLibrary("psapi.dll");

	if (info.dwMajorVersion >= 5)
	{
		nt->hNewDev = LoadLibrary("newdev.dll");
		if (nt->hNewDev == NULL)
		{
			FreeLibrary(nt->hShell32);
			FreeLibrary(nt->hAdvapi32);
			Free(nt);
			return NULL;
		}

		nt->hSetupApi = LoadLibrary("setupapi.dll");
	}

	nt->hSecur32 = LoadLibrary("secur32.dll");

	nt->hUser32 = LoadLibrary("user32.dll");

	nt->hDbgHelp = LoadLibrary("dbghelp.dll");

	nt->hWcmapi = LoadLibrary("wcmapi.dll");

	nt->hDwmapi = LoadLibrary("dwmapi.dll");

	// Read the function
	nt->GetComputerNameExW =
		(BOOL (__stdcall *)(COMPUTER_NAME_FORMAT,LPWSTR,LPDWORD))
		GetProcAddress(nt->hKernel32, "GetComputerNameExW");

	nt->IsWow64Process =
		(BOOL (__stdcall *)(HANDLE,BOOL *))
		GetProcAddress(nt->hKernel32, "IsWow64Process");

	nt->GetFileInformationByHandle =
		(BOOL (__stdcall *)(HANDLE,LPBY_HANDLE_FILE_INFORMATION))
		GetProcAddress(nt->hKernel32, "GetFileInformationByHandle");

	nt->GetProcessHeap =
		(HANDLE (__stdcall *)())
		GetProcAddress(nt->hKernel32, "GetProcessHeap");

	nt->SetProcessShutdownParameters =
		(BOOL (__stdcall *)(DWORD,DWORD))
		GetProcAddress(nt->hKernel32, "SetProcessShutdownParameters");

	nt->GetNativeSystemInfo =
		(void (__stdcall *)(SYSTEM_INFO *))
		GetProcAddress(nt->hKernel32, "GetNativeSystemInfo");

	nt->AdjustTokenPrivileges =
		(BOOL (__stdcall *)(HANDLE,BOOL,PTOKEN_PRIVILEGES,DWORD,PTOKEN_PRIVILEGES,PDWORD))
		GetProcAddress(nt->hAdvapi32, "AdjustTokenPrivileges");

	nt->LookupPrivilegeValue =
		(BOOL (__stdcall *)(char *,char *,PLUID))
		GetProcAddress(nt->hAdvapi32, "LookupPrivilegeValueA");

	nt->OpenProcessToken =
		(BOOL (__stdcall *)(HANDLE,DWORD,PHANDLE))
		GetProcAddress(nt->hAdvapi32, "OpenProcessToken");

	nt->InitiateSystemShutdown =
		(BOOL (__stdcall *)(LPTSTR,LPTSTR,DWORD,BOOL,BOOL))
		GetProcAddress(nt->hAdvapi32, "InitiateSystemShutdownA");

	nt->LogonUserW =
		(BOOL (__stdcall *)(wchar_t *,wchar_t *,wchar_t *,DWORD,DWORD,HANDLE *))
		GetProcAddress(nt->hAdvapi32, "LogonUserW");

	nt->LogonUserA =
		(BOOL (__stdcall *)(char *,char *,char *,DWORD,DWORD,HANDLE * ))
		GetProcAddress(nt->hAdvapi32, "LogonUserA");

	nt->DuplicateTokenEx =
		(BOOL (__stdcall *)(HANDLE,DWORD,SECURITY_ATTRIBUTES *,SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,HANDLE *))
		GetProcAddress(nt->hAdvapi32, "DuplicateTokenEx");

	nt->ConvertStringSidToSidA =
		(BOOL (__stdcall *)(LPCSTR,PSID *))
		GetProcAddress(nt->hAdvapi32, "ConvertStringSidToSidA");

	nt->GetTokenInformation =
		(BOOL (__stdcall *)(HANDLE,TOKEN_INFORMATION_CLASS,void *,DWORD,PDWORD))
		GetProcAddress(nt->hAdvapi32, "GetTokenInformation");

	nt->SetTokenInformation =
		(BOOL (__stdcall *)(HANDLE,TOKEN_INFORMATION_CLASS,void *,DWORD))
		GetProcAddress(nt->hAdvapi32, "SetTokenInformation");

	nt->CreateProcessAsUserA =
		(BOOL (__stdcall *)(HANDLE,LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,void *,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION))
		GetProcAddress(nt->hAdvapi32, "CreateProcessAsUserA");

	nt->CreateProcessAsUserW =
		(BOOL (__stdcall *)(HANDLE,LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,void *,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION))
		GetProcAddress(nt->hAdvapi32, "CreateProcessAsUserW");

	nt->LookupAccountSidA =
		(BOOL (__stdcall *)(LPCSTR,PSID,LPSTR,LPDWORD,LPSTR,LPDWORD,PSID_NAME_USE))
		GetProcAddress(nt->hAdvapi32, "LookupAccountSidA");

	nt->LookupAccountNameA =
		(BOOL (__stdcall *)(LPCSTR,LPCSTR,PSID,LPDWORD,LPSTR,LPDWORD,PSID_NAME_USE))
		GetProcAddress(nt->hAdvapi32, "LookupAccountNameA");

	nt->SetNamedSecurityInfoW =
		(DWORD (__stdcall *)(LPWSTR,UINT,SECURITY_INFORMATION,PSID,PSID,PACL,PACL))
		GetProcAddress(nt->hAdvapi32, "SetNamedSecurityInfoW");

	nt->AddAccessAllowedAceEx =
		(BOOL (__stdcall *)(PACL,DWORD,DWORD,DWORD,PSID))
		GetProcAddress(nt->hAdvapi32, "AddAccessAllowedAceEx");

	nt->QueryFullProcessImageNameA =
		(BOOL (__stdcall *)(HANDLE,DWORD,LPSTR,PDWORD))
		GetProcAddress(nt->hKernel32, "QueryFullProcessImageNameA");

	nt->QueryFullProcessImageNameW =
		(BOOL (__stdcall *)(HANDLE,DWORD,LPWSTR,PDWORD))
		GetProcAddress(nt->hKernel32, "QueryFullProcessImageNameW");

	nt->RegLoadKeyW =
		(LSTATUS (__stdcall *)(HKEY,LPCWSTR,LPCWSTR))
		GetProcAddress(nt->hAdvapi32, "RegLoadKeyW");

	nt->RegUnLoadKeyW =
		(LSTATUS (__stdcall *)(HKEY,LPCWSTR))
		GetProcAddress(nt->hAdvapi32, "RegUnLoadKeyW");

	if (info.dwMajorVersion >= 5)
	{
		nt->UpdateDriverForPlugAndPlayDevicesW =
			(BOOL (__stdcall *)(HWND,wchar_t *,wchar_t *,UINT,BOOL *))
			GetProcAddress(nt->hNewDev, "UpdateDriverForPlugAndPlayDevicesW");

		nt->CM_Get_Device_ID_ExA =
			(UINT (__stdcall *)(DWORD,char *,UINT,UINT,HANDLE))
			GetProcAddress(nt->hSetupApi, "CM_Get_Device_ID_ExA");

		nt->CM_Get_DevNode_Status_Ex =
			(UINT (__stdcall *)(UINT *,UINT *,DWORD,UINT,HANDLE))
			GetProcAddress(nt->hSetupApi, "CM_Get_DevNode_Status_Ex");
	}

	nt->hWtsApi32 = LoadLibrary("wtsapi32.dll");
	if (nt->hWtsApi32 != NULL)
	{
		// Terminal Services related API
		nt->WTSQuerySessionInformation =
			(UINT (__stdcall *)(HANDLE,DWORD,WTS_INFO_CLASS,wchar_t *,DWORD *))
			GetProcAddress(nt->hWtsApi32, "WTSQuerySessionInformationW");
		nt->WTSFreeMemory =
			(void (__stdcall *)(void *))
			GetProcAddress(nt->hWtsApi32, "WTSFreeMemory");
		nt->WTSDisconnectSession =
			(BOOL (__stdcall *)(HANDLE,DWORD,BOOL))
			GetProcAddress(nt->hWtsApi32, "WTSDisconnectSession");
		nt->WTSEnumerateSessionsA =
			(BOOL (__stdcall *)(HANDLE,DWORD,DWORD,PWTS_SESSION_INFOA *,DWORD *))
			GetProcAddress(nt->hWtsApi32, "WTSEnumerateSessionsA");
		nt->WTSRegisterSessionNotification =
			(BOOL (__stdcall *)(HWND,DWORD))
			GetProcAddress(nt->hWtsApi32, "WTSRegisterSessionNotification");
		nt->WTSUnRegisterSessionNotification =
			(BOOL (__stdcall *)(HWND))
			GetProcAddress(nt->hWtsApi32, "WTSUnRegisterSessionNotification");
	}

	// Service related API
	nt->OpenSCManager =
		(SC_HANDLE (__stdcall *)(LPCTSTR,LPCTSTR,DWORD))
		GetProcAddress(nt->hAdvapi32, "OpenSCManagerA");
	nt->CreateServiceA =
		(SC_HANDLE (__stdcall *)(SC_HANDLE,LPCTSTR,LPCTSTR,DWORD,DWORD,DWORD,DWORD,LPCTSTR,LPCTSTR,LPDWORD,LPCTSTR,LPCTSTR,LPCTSTR))
		GetProcAddress(nt->hAdvapi32, "CreateServiceA");
	nt->CreateServiceW =
		(SC_HANDLE (__stdcall *)(SC_HANDLE,LPCWSTR,LPCWSTR,DWORD,DWORD,DWORD,DWORD,LPCWSTR,LPCWSTR,LPDWORD,LPCWSTR,LPCWSTR,LPCWSTR))
		GetProcAddress(nt->hAdvapi32, "CreateServiceW");
	nt->ChangeServiceConfig2 =
		(BOOL (__stdcall *)(SC_HANDLE,DWORD,LPVOID))
		GetProcAddress(nt->hAdvapi32, "ChangeServiceConfig2W");
	nt->CloseServiceHandle =
		(BOOL (__stdcall *)(SC_HANDLE))
		GetProcAddress(nt->hAdvapi32, "CloseServiceHandle");
	nt->OpenService =
		(SC_HANDLE (__stdcall *)(SC_HANDLE,LPCTSTR,DWORD))
		GetProcAddress(nt->hAdvapi32, "OpenServiceA");
	nt->QueryServiceStatus =
		(BOOL (__stdcall *)(SC_HANDLE,LPSERVICE_STATUS))
		GetProcAddress(nt->hAdvapi32, "QueryServiceStatus");
	nt->StartService =
		(BOOL (__stdcall *)(SC_HANDLE,DWORD,LPCTSTR))
		GetProcAddress(nt->hAdvapi32, "StartServiceA");
	nt->ControlService =
		(BOOL (__stdcall *)(SC_HANDLE,DWORD,LPSERVICE_STATUS))
		GetProcAddress(nt->hAdvapi32, "ControlService");
	nt->SetServiceStatus =
		(BOOL (__stdcall *)(SERVICE_STATUS_HANDLE,LPSERVICE_STATUS))
		GetProcAddress(nt->hAdvapi32, "SetServiceStatus");
	nt->RegisterServiceCtrlHandler =
		(SERVICE_STATUS_HANDLE (__stdcall *)(LPCTSTR,LPHANDLER_FUNCTION))
		GetProcAddress(nt->hAdvapi32, "RegisterServiceCtrlHandlerW");
	nt->StartServiceCtrlDispatcher =
		(BOOL (__stdcall *)(const LPSERVICE_TABLE_ENTRY))
		GetProcAddress(nt->hAdvapi32, "StartServiceCtrlDispatcherW");
	nt->DeleteService =
		(BOOL (__stdcall *)(SC_HANDLE))
		GetProcAddress(nt->hAdvapi32, "DeleteService");
	nt->RegisterEventSourceW =
		(HANDLE (__stdcall *)(LPCWSTR,LPCWSTR))
		GetProcAddress(nt->hAdvapi32, "RegisterEventSourceW");
	nt->ReportEventW =
		(BOOL (__stdcall *)(HANDLE,WORD,WORD,DWORD,PSID,WORD,DWORD,LPCWSTR *,LPVOID))
		GetProcAddress(nt->hAdvapi32, "ReportEventW");
	nt->DeregisterEventSource =
		(BOOL (__stdcall *)(HANDLE))
		GetProcAddress(nt->hAdvapi32, "DeregisterEventSource");
	nt->Wow64DisableWow64FsRedirection =
		(BOOL (__stdcall *)(void **))
		GetProcAddress(nt->hKernel32, "Wow64DisableWow64FsRedirection");
	nt->Wow64EnableWow64FsRedirection =
		(BOOLEAN (__stdcall *)(BOOLEAN))
		GetProcAddress(nt->hKernel32, "Wow64EnableWow64FsRedirection");
	nt->Wow64RevertWow64FsRedirection =
		(BOOL (__stdcall *)(void *))
		GetProcAddress(nt->hKernel32, "Wow64RevertWow64FsRedirection");

	if (nt->hPsApi != NULL)
	{
		// Process related API
		nt->EnumProcesses =
			(BOOL (__stdcall *)(DWORD *,DWORD,DWORD *))
			GetProcAddress(nt->hPsApi, "EnumProcesses");

		nt->EnumProcessModules =
			(BOOL (__stdcall *)(HANDLE,HMODULE * ,DWORD,DWORD *))
			GetProcAddress(nt->hPsApi, "EnumProcessModules");

		nt->GetModuleFileNameExA =
			(DWORD (__stdcall *)(HANDLE,HMODULE,LPSTR,DWORD))
			GetProcAddress(nt->hPsApi, "GetModuleFileNameExA");

		nt->GetModuleFileNameExW =
			(DWORD (__stdcall *)(HANDLE,HMODULE,LPWSTR,DWORD))
			GetProcAddress(nt->hPsApi, "GetModuleFileNameExW");

		nt->GetProcessImageFileNameA =
			(DWORD (__stdcall *)(HANDLE,LPSTR,DWORD))
			GetProcAddress(nt->hPsApi, "GetProcessImageFileNameA");

		nt->GetProcessImageFileNameW =
			(DWORD (__stdcall *)(HANDLE,LPWSTR,DWORD))
			GetProcAddress(nt->hPsApi, "GetProcessImageFileNameW");
	}

	// Registry related API
	nt->RegDeleteKeyExA =
		(LONG (__stdcall *)(HKEY,LPCTSTR,REGSAM,DWORD))
		GetProcAddress(nt->hAdvapi32, "RegDeleteKeyExA");

	// Security related API
	if (nt->hSecur32 != NULL)
	{
		nt->GetUserNameExA =
			(BOOL (__stdcall *)(EXTENDED_NAME_FORMAT,LPSTR,PULONG))
			GetProcAddress(nt->hSecur32, "GetUserNameExA");

		nt->GetUserNameExW =
			(BOOL (__stdcall *)(EXTENDED_NAME_FORMAT,LPWSTR,PULONG))
			GetProcAddress(nt->hSecur32, "GetUserNameExW");

		nt->LsaConnectUntrusted =
			(NTSTATUS (__stdcall *)(PHANDLE))
			GetProcAddress(nt->hSecur32, "LsaConnectUntrusted");

		nt->LsaLookupAuthenticationPackage =
			(NTSTATUS (__stdcall *)(HANDLE,PLSA_STRING,PULONG))
			GetProcAddress(nt->hSecur32, "LsaLookupAuthenticationPackage");

		nt->LsaLogonUser =
			(NTSTATUS (__stdcall *)(HANDLE,PLSA_STRING,SECURITY_LOGON_TYPE,ULONG,PVOID,ULONG,PTOKEN_GROUPS,PTOKEN_SOURCE,PVOID,PULONG,PLUID,PHANDLE,PQUOTA_LIMITS,PNTSTATUS))
			GetProcAddress(nt->hSecur32, "LsaLogonUser");

		nt->LsaDeregisterLogonProcess =
			(NTSTATUS (__stdcall *)(HANDLE))
			GetProcAddress(nt->hSecur32, "LsaDeregisterLogonProcess");

		nt->LsaFreeReturnBuffer =
			(NTSTATUS (__stdcall *)(PVOID))
			GetProcAddress(nt->hSecur32, "LsaFreeReturnBuffer");
	}

	// WCM related API of Windows 8
	if (nt->hWcmapi != NULL)
	{
		nt->WcmQueryProperty =
			(DWORD (__stdcall *)(const GUID *,LPCWSTR,MS_WCM_PROPERTY,PVOID,PDWORD,PBYTE *))
			GetProcAddress(nt->hWcmapi, "WcmQueryProperty");

		nt->WcmSetProperty =
			(DWORD (__stdcall *)(const GUID *,LPCWSTR,MS_WCM_PROPERTY,PVOID,DWORD,const BYTE *))
			GetProcAddress(nt->hWcmapi, "WcmSetProperty");

		nt->WcmFreeMemory =
			(void (__stdcall *)(PVOID))
			GetProcAddress(nt->hWcmapi, "WcmFreeMemory");

		nt->WcmGetProfileList =
			(DWORD (__stdcall *)(PVOID,MS_WCM_PROFILE_INFO_LIST **))
			GetProcAddress(nt->hWcmapi, "WcmGetProfileList");
	}

	nt->AllocateLocallyUniqueId =
		(BOOL (__stdcall *)(PLUID))
		GetProcAddress(nt->hAdvapi32, "AllocateLocallyUniqueId");

	// Desktop related API
	if (nt->hUser32 != NULL)
	{
		nt->SwitchDesktop =
			(BOOL (__stdcall *)(HDESK))
			GetProcAddress(nt->hUser32, "SwitchDesktop");
		nt->OpenDesktopA =
			(HDESK (__stdcall *)(LPTSTR,DWORD,BOOL,ACCESS_MASK))
			GetProcAddress(nt->hUser32, "OpenDesktopA");
		nt->CloseDesktop =
			(BOOL (__stdcall *)(HDESK))
			GetProcAddress(nt->hUser32, "CloseDesktop");
	}

	// DWM API
	if (nt->hDwmapi)
	{
		nt->DwmIsCompositionEnabled =
			(HRESULT (__stdcall *)(BOOL *))
			GetProcAddress(nt->hDwmapi, "DwmIsCompositionEnabled");
	}

	// Debug related API
	if (nt->hDbgHelp != NULL)
	{
		nt->MiniDumpWriteDump =
			(BOOL (__stdcall *)(HANDLE,DWORD,HANDLE,MINIDUMP_TYPE,PMINIDUMP_EXCEPTION_INFORMATION,PMINIDUMP_USER_STREAM_INFORMATION,PMINIDUMP_CALLBACK_INFORMATION))
			GetProcAddress(nt->hDbgHelp, "MiniDumpWriteDump");
	}

	return nt;
}

// Release of NT system function
void MsFreeNtApiFunctions(NT_API *nt)
{
	// Validate arguments
	if (nt == NULL)
	{
		return;
	}

	if (nt->hSecur32 != NULL)
	{
		FreeLibrary(nt->hSecur32);
	}

	if (nt->hNewDev != NULL)
	{
		FreeLibrary(nt->hSetupApi);
		FreeLibrary(nt->hNewDev);
	}

	FreeLibrary(nt->hAdvapi32);

	FreeLibrary(nt->hShell32);

	if (nt->hWtsApi32 != NULL)
	{
		FreeLibrary(nt->hWtsApi32);
	}

	if (nt->hPsApi != NULL)
	{
		FreeLibrary(nt->hPsApi);
	}

	if (nt->hUser32 != NULL)
	{
		FreeLibrary(nt->hUser32);
	}

	if (nt->hDbgHelp != NULL)
	{
		FreeLibrary(nt->hDbgHelp);
	}

	if (nt->hWcmapi != NULL)
	{
		FreeLibrary(nt->hWcmapi);
	}

	if (nt->hDwmapi != NULL)
	{
		FreeLibrary(nt->hDwmapi);
	}

	FreeLibrary(nt->hKernel32);

	Free(nt);
}

// Get whether the screen color is like to Aero of Windows Vista or later
bool MsIsAeroColor()
{
	UINT r;
	if (MsIsNt() == false)
	{
		return false;
	}

	if (MsIsVista() == false)
	{
		return false;
	}

	r = GetSysColor(COLOR_MENU);
	if (r == 0xFFFFFF || r == 0xF0F0F0 || r >= 0xF00000)
	{
		return true;
	}

	if (MsIsAeroEnabled())
	{
		return true;
	}

	return false;
}

// Get whether Aero is enabled
bool MsIsAeroEnabled()
{
	bool ret;
	if (MsIsNt() == false)
	{
		return false;
	}

	if (ms->nt->DwmIsCompositionEnabled == NULL)
	{
		return false;
	}

	ret = false;

	if (ms->nt->DwmIsCompositionEnabled(&ret) != S_OK)
	{
		return false;
	}

	return ret;
}

// Generate an access mask to force accessing to the 32 bit registry key for 64 bit application
DWORD MsRegAccessMaskFor64BitEx(bool force32bit, bool force64bit)
{
	if (MsIs64BitWindows() == false)
	{
		return 0;
	}
	if (force32bit)
	{
		return KEY_WOW64_32KEY;
	}
	if (force64bit)
	{
		return KEY_WOW64_64KEY;
	}

	return 0;
}

// Load the hive
bool MsRegLoadHive(UINT root, wchar_t *keyname, wchar_t *filename)
{
	LONG ret;
	if (keyname == NULL || filename == NULL)
	{
		WHERE;
		return false;
	}

	if (ms->nt == NULL || ms->nt->RegLoadKeyW == NULL || ms->nt->RegUnLoadKeyW == NULL)
	{
		WHERE;
		return false;
	}

	ret = ms->nt->RegLoadKeyW(MsGetRootKeyFromInt(root), keyname, filename);

	if (ret != ERROR_SUCCESS)
	{
		Debug("RegLoadKeyW: %S %S %u\n", keyname, filename, GetLastError());
		return false;
	}
	WHERE;

	return true;
}

// Unload the hive
bool MsRegUnloadHive(UINT root, wchar_t *keyname)
{
	LONG ret;
	if (keyname == NULL)
	{
		return false;
	}

	if (ms->nt == NULL || ms->nt->RegLoadKeyW == NULL || ms->nt->RegUnLoadKeyW == NULL)
	{
		return false;
	}

	ret = ms->nt->RegUnLoadKeyW(MsGetRootKeyFromInt(root), keyname);

	if (ret != ERROR_SUCCESS)
	{
		Debug("RegUnLoadKeyW: %u\n", GetLastError());
		return false;
	}

	return true;
}

// Delete the value
bool MsRegDeleteValue(UINT root, char *keyname, char *valuename)
{
	return MsRegDeleteValueEx(root, keyname, valuename, false);
}
bool MsRegDeleteValueEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegDeleteValueEx2(root, keyname, valuename, force32bit, false);
}
bool MsRegDeleteValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	bool ret;
	// Validate arguments
	if (keyname == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	if (RegDeleteValue(h, valuename) != ERROR_SUCCESS)
	{
		ret = false;
	}
	else
	{
		ret = true;
	}

	RegCloseKey(h);

	return ret;
}

// Delete the key
bool MsRegDeleteKey(UINT root, char *keyname)
{
	return MsRegDeleteKeyEx(root, keyname, false);
}
bool MsRegDeleteKeyEx(UINT root, char *keyname, bool force32bit)
{
	return MsRegDeleteKeyEx2(root, keyname, force32bit, false);
}
bool MsRegDeleteKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	// Validate arguments
	if (keyname == NULL)
	{
		return false;
	}

	if (MsIsNt() && ms->nt->RegDeleteKeyExA != NULL)
	{
		if (ms->nt->RegDeleteKeyExA(MsGetRootKeyFromInt(root), keyname, MsRegAccessMaskFor64BitEx(force32bit, force64bit), 0) != ERROR_SUCCESS)
		{
			return false;
		}
	}
	else
	{
		if (RegDeleteKey(MsGetRootKeyFromInt(root), keyname) != ERROR_SUCCESS)
		{
			return false;
		}
	}

	return true;
}

// Enumeration of values
TOKEN_LIST *MsRegEnumValue(UINT root, char *keyname)
{
	return MsRegEnumValueEx(root, keyname, false);
}
TOKEN_LIST *MsRegEnumValueEx(UINT root, char *keyname, bool force32bit)
{
	return MsRegEnumValueEx2(root, keyname, force32bit, false);
}
TOKEN_LIST *MsRegEnumValueEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT i;
	TOKEN_LIST *t;
	LIST *o;

	if (keyname == NULL)
	{
		h = MsGetRootKeyFromInt(root);
	}
	else
	{
		if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
		{
			return NULL;
		}
	}

	o = NewListFast(CompareStr);

	for (i = 0;;i++)
	{
		char tmp[MAX_SIZE];
		UINT ret;
		UINT size = sizeof(tmp);

		Zero(tmp, sizeof(tmp));
		ret = RegEnumValue(h, i, tmp, &size, NULL, NULL, NULL, NULL);
		if (ret == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if (ret != ERROR_SUCCESS)
		{
			break;
		}

		Add(o, CopyStr(tmp));
	}

	Sort(o);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	if (keyname != NULL)
	{
		RegCloseKey(h);
	}

	return t;
}

// Enumeration of the keys
TOKEN_LIST *MsRegEnumKey(UINT root, char *keyname)
{
	return MsRegEnumKeyEx(root, keyname, false);
}
TOKEN_LIST *MsRegEnumKeyEx(UINT root, char *keyname, bool force32bit)
{
	return MsRegEnumKeyEx2(root, keyname, force32bit, false);
}
TOKEN_LIST *MsRegEnumKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT i;
	TOKEN_LIST *t;
	LIST *o;

	if (keyname == NULL)
	{
		h = MsGetRootKeyFromInt(root);
	}
	else
	{
		if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
		{
			return NULL;
		}
	}

	o = NewListFast(CompareStr);

	for (i = 0;;i++)
	{
		char tmp[MAX_SIZE];
		UINT ret;
		UINT size = sizeof(tmp);
		FILETIME ft;

		Zero(tmp, sizeof(tmp));
		ret = RegEnumKeyEx(h, i, tmp, &size, NULL, NULL, NULL, &ft);
		if (ret == ERROR_NO_MORE_ITEMS)
		{
			break;
		}
		else if (ret != ERROR_SUCCESS)
		{
			break;
		}

		Add(o, CopyStr(tmp));
	}

	Sort(o);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	if (keyname != NULL)
	{
		RegCloseKey(h);
	}

	return t;
}

// Set the binary data
bool MsRegWriteBin(UINT root, char *keyname, char *valuename, void *data, UINT size)
{
	return MsRegWriteBinEx(root, keyname, valuename, data, size, false);
}
bool MsRegWriteBinEx(UINT root, char *keyname, char *valuename, void *data, UINT size, bool force32bit)
{
	return MsRegWriteBinEx2(root, keyname, valuename, data, size, force32bit, false);
}
bool MsRegWriteBinEx2(UINT root, char *keyname, char *valuename, void *data, UINT size, bool force32bit, bool force64bit)
{
	// Validate arguments
	if (keyname == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_BINARY, data, size, force32bit, force64bit);
}

// Set the integer value
bool MsRegWriteInt(UINT root, char *keyname, char *valuename, UINT value)
{
	return MsRegWriteIntEx(root, keyname, valuename, value, false);
}
bool MsRegWriteIntEx(UINT root, char *keyname, char *valuename, UINT value, bool force32bit)
{
	return MsRegWriteIntEx2(root, keyname, valuename, value, force32bit, false);
}
bool MsRegWriteIntEx2(UINT root, char *keyname, char *valuename, UINT value, bool force32bit, bool force64bit)
{
	// Validate arguments
	if (keyname == NULL)
	{
		return false;
	}

	// Endian correction
	if (IsBigEndian())
	{
		value = Swap32(value);
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_DWORD_LITTLE_ENDIAN, &value, sizeof(UINT), force32bit, force64bit);
}

// Set the string
bool MsRegWriteStrExpand(UINT root, char *keyname, char *valuename, char *str)
{
	return MsRegWriteStrExpandEx(root, keyname, valuename, str, false);
}
bool MsRegWriteStrExpandEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit)
{
	return MsRegWriteStrExpandEx2(root, keyname, valuename, str, force32bit, false);
}
bool MsRegWriteStrExpandEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit)
{
	// Validate arguments
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_EXPAND_SZ, str, StrSize(str), force32bit, force64bit);
}
bool MsRegWriteStrExpandW(UINT root, char *keyname, char *valuename, wchar_t *str)
{
	return MsRegWriteStrExpandExW(root, keyname, valuename, str, false);
}
bool MsRegWriteStrExpandExW(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit)
{
	return MsRegWriteStrExpandEx2W(root, keyname, valuename, str, force32bit, false);
}
bool MsRegWriteStrExpandEx2W(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit, bool force64bit)
{
	// Validate arguments
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2W(root, keyname, valuename, REG_EXPAND_SZ, str, UniStrSize(str), force32bit, force64bit);
}

bool MsRegWriteStr(UINT root, char *keyname, char *valuename, char *str)
{
	return MsRegWriteStrEx(root, keyname, valuename, str, false);
}
bool MsRegWriteStrEx(UINT root, char *keyname, char *valuename, char *str, bool force32bit)
{
	return MsRegWriteStrEx2(root, keyname, valuename, str, force32bit, false);
}
bool MsRegWriteStrEx2(UINT root, char *keyname, char *valuename, char *str, bool force32bit, bool force64bit)
{
	// Validate arguments
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2(root, keyname, valuename, REG_SZ, str, StrSize(str), force32bit, force64bit);
}
bool MsRegWriteStrW(UINT root, char *keyname, char *valuename, wchar_t *str)
{
	return MsRegWriteStrExW(root, keyname, valuename, str, false);
}
bool MsRegWriteStrExW(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit)
{
	return MsRegWriteStrEx2W(root, keyname, valuename, str, force32bit, false);
}
bool MsRegWriteStrEx2W(UINT root, char *keyname, char *valuename, wchar_t *str, bool force32bit, bool force64bit)
{
	// Validate arguments
	if (keyname == NULL || str == NULL)
	{
		return false;
	}

	return MsRegWriteValueEx2W(root, keyname, valuename, REG_SZ, str, UniStrSize(str), force32bit, force64bit);
}

// Set the value
bool MsRegWriteValueEx2(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit)
{
	HKEY h;
	// Validate arguments
	if (keyname == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	// Create a key
	MsRegNewKeyEx2(root, keyname, force32bit, force64bit);

	// Open the key
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// Write the value
	if (RegSetValueEx(h, valuename, 0, type, data, size) != ERROR_SUCCESS)
	{
		RegCloseKey(h);
		return false;
	}

	// Close the key
	RegCloseKey(h);

	return true;
}
bool MsRegWriteValueEx2W(UINT root, char *keyname, char *valuename, UINT type, void *data, UINT size, bool force32bit, bool force64bit)
{
	HKEY h;
	wchar_t *valuename_w;
	// Validate arguments
	if (keyname == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	if (IsNt() == false)
	{
		UINT size_a;
		void *data_a;
		bool ret;

		if (type == REG_SZ || type == REG_MULTI_SZ || type == REG_EXPAND_SZ)
		{
			data_a = CopyUniToStr(data);
			size_a = StrSize(data_a);
		}
		else
		{
			data_a = Clone(data, size);
			size_a = size;
		}

		ret = MsRegWriteValueEx2(root, keyname, valuename, type, data_a, size_a, force32bit, force64bit);

		Free(data_a);

		return ret;
	}

	// Create a key
	MsRegNewKeyEx2(root, keyname, force32bit, force64bit);

	// Open the key
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	valuename_w = CopyStrToUni(valuename);

	// Write the value
	if (RegSetValueExW(h, valuename_w, 0, type, data, size) != ERROR_SUCCESS)
	{
		RegCloseKey(h);
		Free(valuename_w);
		return false;
	}

	// Close the key
	RegCloseKey(h);
	Free(valuename_w);

	return true;
}

// Get the binary data
BUF *MsRegReadBin(UINT root, char *keyname, char *valuename)
{
	return MsRegReadBinEx(root, keyname, valuename, false);
}
BUF *MsRegReadBinEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadBinEx2(root, keyname, valuename, force32bit, false);
}
BUF *MsRegReadBinEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	UINT type, size;
	BUF *b;
	// Validate arguments
	if (keyname == NULL || valuename == NULL)
	{
		return 0;
	}

	// Read the value
	if (MsRegReadValueEx2(root, keyname, valuename, &ret, &type, &size, force32bit, force64bit) == false)
	{
		return 0;
	}

	b = NewBuf();

	WriteBuf(b, ret, size);
	SeekBuf(b, 0, 0);

	Free(ret);

	return b;
}

// Get an integer value
UINT MsRegReadInt(UINT root, char *keyname, char *valuename)
{
	return MsRegReadIntEx(root, keyname, valuename, false);
}
UINT MsRegReadIntEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadIntEx2(root, keyname, valuename, force32bit, false);
}
UINT MsRegReadIntEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	UINT type, size;
	UINT value;
	// Validate arguments
	if (keyname == NULL || valuename == NULL)
	{
		return 0;
	}

	// Read the value
	if (MsRegReadValueEx2(root, keyname, valuename, &ret, &type, &size, force32bit, force64bit) == false)
	{
		return 0;
	}

	// Check the type
	if (type != REG_DWORD_LITTLE_ENDIAN && type != REG_DWORD_BIG_ENDIAN)
	{
		// It is not a DWORD
		Free(ret);
		return 0;
	}

	// Check the size
	if (size != sizeof(UINT))
	{
		Free(ret);
		return 0;
	}

	Copy(&value, ret, sizeof(UINT));

	Free(ret);

	// Endian conversion
	if (IsLittleEndian())
	{
#ifdef	REG_DWORD_BIG_ENDIAN
		if (type == REG_DWORD_BIG_ENDIAN)
		{
			value = Swap32(value);
		}
#endif	// REG_DWORD_BIG_ENDIAN
	}
	else
	{
#ifdef	REG_DWORD_LITTLE_ENDIAN_FLAG
		if (type == REG_DWORD_LITTLE_ENDIAN_FLAG)
		{
			value = Swap32(value);
		}
#endif	// REG_DWORD_LITTLE_ENDIAN_FLAG
	}

	return value;
}

// Get a string list
LIST *MsRegReadStrList(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrListEx(root, keyname, valuename, false);
}
LIST *MsRegReadStrListEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadStrListEx2(root, keyname, valuename, force32bit, false);
}
LIST *MsRegReadStrListEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	LIST *o;
	char *ret;
	UINT type, size;
	// Validate arguments
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	// Read the value
	if (MsRegReadValueEx2(root, keyname, valuename, &ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	// Check the type
	if (type != REG_MULTI_SZ)
	{
		// It is not a string list
		Free(ret);
		return NULL;
	}

	if (size < 2)
	{
		// Invalid size
		Free(ret);
		return NULL;
	}

	if (ret[size - 1] != 0)
	{
		// Invalid data
		Free(ret);
		return NULL;
	}

	// Creating a list
	o = StrToStrList(ret, size);

	Free(ret);

	return o;
}

// Get a string
char *MsRegReadStr(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrEx(root, keyname, valuename, false);
}
char *MsRegReadStrEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadStrEx2(root, keyname, valuename, force32bit, false);
}
char *MsRegReadStrEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	char *ret;
	UINT type, size;
	// Validate arguments
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	// Read the value
	if (MsRegReadValueEx2(root, keyname, valuename, &ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	// Check the type
	if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ)
	{
		// It is not a string
		Free(ret);

		if (type == REG_MULTI_SZ)
		{
			// It is a string list
			LIST *o = MsRegReadStrList(root, keyname, valuename);
			if (o != NULL)
			{
				if (LIST_NUM(o) >= 1)
				{
					ret = CopyStr(LIST_DATA(o, 0));
					FreeStrList(o);
					return ret;
				}
			}
		}
		return NULL;
	}

	if (size == 0)
	{
		// Invalid size
		Free(ret);

		return CopyStr("");
	}

	if (ret[size - 1] != 0)
	{
		// Invalid data
		Free(ret);
		return NULL;
	}

	return ret;
}
wchar_t *MsRegReadStrW(UINT root, char *keyname, char *valuename)
{
	return MsRegReadStrExW(root, keyname, valuename, false);
}
wchar_t *MsRegReadStrExW(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegReadStrEx2W(root, keyname, valuename, force32bit, false);
}
wchar_t *MsRegReadStrEx2W(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	wchar_t *ret;
	UINT type, size;
	// Validate arguments
	if (keyname == NULL || valuename == NULL)
	{
		return NULL;
	}

	// Read the value
	if (MsRegReadValueEx2W(root, keyname, valuename, &ret, &type, &size, force32bit, force64bit) == false)
	{
		return NULL;
	}

	// Check the type
	if (type != REG_SZ && type != REG_EXPAND_SZ)
	{
		// It is not a string
		Free(ret);

		return NULL;
	}

	if (ret[size / sizeof(wchar_t) - 1] != 0)
	{
		// Invalid data
		Free(ret);
		return NULL;
	}

	return ret;
}

// Read the value
bool MsRegReadValueEx2(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	// Validate arguments
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	// Open the key
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// Open up the value
	*data = ZeroMalloc(*size);
	ret = RegQueryValueEx(h, valuename, 0, type, *data, size);

	if (ret == ERROR_SUCCESS)
	{
		// Reading is complete
		RegCloseKey(h);
		return true;
	}

	if (ret != ERROR_MORE_DATA)
	{
		// Strange error occurs
		Free(*data);
		*data = NULL;
		RegCloseKey(h);
		return false;
	}

	// Get the data by re-allocating memory
	*data = ReAlloc(*data, *size);
	ret = RegQueryValueEx(h, valuename, 0, type, *data, size);
	if (ret != ERROR_SUCCESS)
	{
		// An error has occured
		Free(*data);
		*data = NULL;
		RegCloseKey(h);
	}

	RegCloseKey(h);

	return true;
}
bool MsRegReadValueEx2W(UINT root, char *keyname, char *valuename, void **data, UINT *type, UINT *size, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT ret;
	wchar_t *valuename_w;
	// Validate arguments
	if (keyname == NULL || data == NULL || type == NULL || size == NULL)
	{
		return false;
	}
	*type = 0;
	*size = 0;

	if (IsNt() == false)
	{
		bool ret;
		void *data_a = NULL;
		UINT type_a = 0, size_a = 0;

		ret = MsRegReadValueEx2(root, keyname, valuename, &data_a, &type_a, &size_a, force32bit, force64bit);

		if (ret != false)
		{
			if (type_a == REG_SZ || type_a == REG_MULTI_SZ || type_a == REG_EXPAND_SZ)
			{
				*data = CopyStrToUni(data_a);
				Free(data_a);

				size_a = UniStrSize(*data);
			}
			else
			{
				*data = data_a;
			}

			*type = type_a;
			*size = size_a;
		}

		return ret;
	}

	// Open the key
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	valuename_w = CopyStrToUni(valuename);

	// Open up the value
	*data = ZeroMalloc(*size);
	ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);

	if (ret == ERROR_SUCCESS)
	{
		// Reading is complete
		RegCloseKey(h);
		Free(valuename_w);
		return true;
	}

	if (ret != ERROR_MORE_DATA)
	{
		// Strange error occurs
		Free(*data);
		*data = NULL;
		Free(valuename_w);
		RegCloseKey(h);
		return false;
	}

	// Get the data by re-allocating memory
	*data = ReAlloc(*data, *size);
	ret = RegQueryValueExW(h, valuename_w, 0, type, *data, size);
	if (ret != ERROR_SUCCESS)
	{
		// An error has occured
		Free(*data);
		*data = NULL;
		Free(valuename_w);
		RegCloseKey(h);
	}

	Free(valuename_w);

	RegCloseKey(h);

	return true;
}

// Confirm that the specified value exists on the registry
bool MsRegIsValue(UINT root, char *keyname, char *valuename)
{
	return MsRegIsValueEx(root, keyname, valuename, false);
}
bool MsRegIsValueEx(UINT root, char *keyname, char *valuename, bool force32bit)
{
	return MsRegIsValueEx2(root, keyname, valuename, force32bit, false);
}
bool MsRegIsValueEx2(UINT root, char *keyname, char *valuename, bool force32bit, bool force64bit)
{
	HKEY h;
	UINT type, size;
	UINT ret;
	// Validate arguments
	if (keyname == NULL)
	{
		return false;
	}

	// Open the key
	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), keyname, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	// Open up the value
	size = 0;
	ret = RegQueryValueEx(h, valuename, 0, &type, NULL, &size);

	if (ret == ERROR_SUCCESS || ret == ERROR_MORE_DATA)
	{
		RegCloseKey(h);
		return true;
	}

	RegCloseKey(h);

	return false;
}

// Create a key in the registry
bool MsRegNewKeyEx2(UINT root, char *keyname, bool force32bit, bool force64bit)
{
	HKEY h;
	// Validate arguments
	if (keyname == NULL)
	{
		return false;
	}

	// Confirm whether there is the key  
	if (MsRegIsKeyEx2(root, keyname, force32bit, force64bit))
	{
		// Already exists
		return true;
	}

	// Create a key
	if (RegCreateKeyEx(MsGetRootKeyFromInt(root), keyname, 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS | MsRegAccessMaskFor64BitEx(force32bit, force64bit), NULL, &h, NULL) != ERROR_SUCCESS)
	{
		// Failed
		return false;
	}

	RegCloseKey(h);

	return true;
}

// Confirm the specified key exists on the registry
bool MsRegIsKey(UINT root, char *name)
{
	return MsRegIsKeyEx(root, name, false);
}
bool MsRegIsKeyEx(UINT root, char *name, bool force32bit)
{
	return MsRegIsKeyEx2(root, name, force32bit, false);
}
bool MsRegIsKeyEx2(UINT root, char *name, bool force32bit, bool force64bit)
{
	HKEY h;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (RegOpenKeyEx(MsGetRootKeyFromInt(root), name, 0, KEY_READ | MsRegAccessMaskFor64BitEx(force32bit, force64bit), &h) != ERROR_SUCCESS)
	{
		return false;
	}

	RegCloseKey(h);

	return true;
}

// Getting root key handle
HKEY MsGetRootKeyFromInt(UINT root)
{
	switch (root)
	{
	case REG_CLASSES_ROOT:
		return HKEY_CLASSES_ROOT;

	case REG_LOCAL_MACHINE:
		return HKEY_LOCAL_MACHINE;

	case REG_CURRENT_USER:
		return HKEY_CURRENT_USER;

	case REG_USERS:
		return HKEY_USERS;
	}

	return NULL;
}

// Cut the executable file name from the command line string (Unicode version)
wchar_t *MsCutExeNameFromUniCommandLine(wchar_t *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	if (str[0] != L'\"')
	{
		UINT i = UniSearchStrEx(str, L" ", 0, true);
		if (i == INFINITE)
		{
			return str + UniStrLen(str);
		}
		else
		{
			return str + i + 1;
		}
	}
	else
	{
		str++;
		while (true)
		{
			if ((*str) == 0)
			{
				return str + UniStrLen(str);
			}
			if ((*str) == L'\"')
			{
				break;
			}
			str++;
		}

		while (true)
		{
			if ((*str) == 0)
			{
				return str + UniStrLen(str);
			}
			if ((*str) == L' ')
			{
				return str + 1;
			}
			str++;
		}
	}
}

// Cut the executable file name from the command line string
char *MsCutExeNameFromCommandLine(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	if (str[0] != '\"')
	{
		UINT i = SearchStrEx(str, " ", 0, true);
		if (i == INFINITE)
		{
			return str + StrLen(str);
		}
		else
		{
			return str + i + 1;
		}
	}
	else
	{
		str++;
		while (true)
		{
			if ((*str) == 0)
			{
				return str + StrLen(str);
			}
			if ((*str) == '\"')
			{
				break;
			}
			str++;
		}

		while (true)
		{
			if ((*str) == 0)
			{
				return str + StrLen(str);
			}
			if ((*str) == ' ')
			{
				return str + 1;
			}
			str++;
		}
	}
}

// Get the Process handle
void *MsGetCurrentProcess()
{
	return ms->hCurrentProcess;
}

// Get the Process ID
UINT MsGetCurrentProcessId()
{
	return ms->CurrentProcessId;
}

// Get the EXE file name
char *MsGetExeFileName()
{
	return ms == NULL ? "Unknown" : ms->ExeFileName;
}

// Get the name of the directory where the EXE file is in
char *MsGetExeDirName()
{
	return ms->ExeFileDir;
}
wchar_t *MsGetExeDirNameW()
{
	return ms->ExeFileDirW;
}

// Get the special directory name
char *MsGetSpecialDir(int id)
{
	LPITEMIDLIST t = NULL;
	char tmp[MAX_PATH];

	if (SHGetSpecialFolderLocation(NULL, id, &t) != S_OK)
	{
		return CopyStr(ms->ExeFileDir);
	}

	if (SHGetPathFromIDList(t, tmp) == false)
	{
		return CopyStr(ms->ExeFileDir);
	}

	Win32NukuEn(tmp, sizeof(tmp), tmp);

	return CopyStr(tmp);
}
wchar_t *MsGetSpecialDirW(int id)
{
	LPITEMIDLIST t = NULL;
	wchar_t tmp[MAX_PATH];

	if (IsNt() == false)
	{
		char *tmp = MsGetSpecialDir(id);
		wchar_t *ret = CopyStrToUni(tmp);

		Free(tmp);

		return ret;
	}

	if (SHGetSpecialFolderLocation(NULL, id, &t) != S_OK)
	{
		return UniCopyStr(ms->ExeFileDirW);
	}

	if (SHGetPathFromIDListW(t, tmp) == false)
	{
		return UniCopyStr(ms->ExeFileDirW);
	}

	Win32NukuEnW(tmp, sizeof(tmp), tmp);

	return UniCopyStr(tmp);
}

// Get all the special directory
void MsGetSpecialDirs()
{
	char tmp[MAX_PATH];

	// System32
	GetSystemDirectory(tmp, sizeof(tmp));
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->System32Dir = CopyStr(tmp);
	ms->System32DirW = CopyStrToUni(tmp);

	// The Windows directory is parent of the System32 directory
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->WindowsDir = CopyStr(tmp);
	ms->WindowsDirW = CopyStrToUni(tmp);

	// Temp directory under the Windows directory
	Format(tmp, sizeof(tmp), "%s\\Temp", ms->WindowsDir);
	ms->WinTempDir = CopyStr(tmp);
	ms->WinTempDirW = CopyStrToUni(tmp);
	MsUniMakeDirEx(ms->WinTempDirW);

	// System drive
	tmp[2] = 0;
	ms->WindowsDrive = CopyStr(tmp);
	ms->WindowsDriveW = CopyStrToUni(tmp);

	// Temp
	GetTempPath(MAX_PATH, tmp);
	Win32NukuEn(tmp, sizeof(tmp), tmp);
	ms->TempDir = CopyStr(tmp);

	// Get the Temp (Unicode)
	if (IsNt())
	{
		wchar_t tmp_w[MAX_PATH];

		GetTempPathW(MAX_PATH, tmp_w);
		Win32NukuEnW(tmp_w, sizeof(tmp_w), tmp_w);

		ms->TempDirW = CopyUniStr(tmp_w);
	}
	else
	{
		ms->TempDirW = CopyStrToUni(tmp);
	}
	MakeDirExW(ms->TempDirW);
	MakeDirEx(ms->TempDir);

	// Program Files
	ms->ProgramFilesDir = MsGetSpecialDir(CSIDL_PROGRAM_FILES);
	if (StrCmpi(ms->ProgramFilesDir, ms->ExeFileDir) == 0)
	{
		char tmp[MAX_PATH];
		Format(tmp, sizeof(tmp), "%s\\Program Files", ms->WindowsDrive);

		Free(ms->ProgramFilesDir);
		ms->ProgramFilesDir = CopyStr(tmp);
	}

	ms->ProgramFilesDirW = MsGetSpecialDirW(CSIDL_PROGRAM_FILES);
	if (UniStrCmpi(ms->ProgramFilesDirW, ms->ExeFileDirW) == 0)
	{
		wchar_t tmp[MAX_PATH];
		UniFormat(tmp, sizeof(tmp), L"%s\\Program Files", ms->WindowsDriveW);

		Free(ms->ProgramFilesDirW);
		ms->ProgramFilesDirW = UniCopyStr(tmp);
	}

	// Program Files (x86)
	ms->ProgramFilesDirX86 = MsGetSpecialDir(CSIDL_PROGRAM_FILESX86);
	if (StrCmpi(ms->ProgramFilesDirX86, ms->ExeFileDir) == 0)
	{
		if (MsIs64BitWindows())
		{
			char tmp[MAX_PATH];
			Format(tmp, sizeof(tmp), "%s\\Program Files (x86)", ms->WindowsDrive);

			Free(ms->ProgramFilesDirX86);
			ms->ProgramFilesDirX86 = CopyStr(tmp);
		}
		else
		{
			Free(ms->ProgramFilesDirX86);
			ms->ProgramFilesDirX86 = CopyStr(ms->ProgramFilesDir);
		}
	}

	ms->ProgramFilesDirX86W = MsGetSpecialDirW(CSIDL_PROGRAM_FILESX86);
	if (UniStrCmpi(ms->ProgramFilesDirX86W, ms->ExeFileDirW) == 0)
	{
		if (MsIs64BitWindows())
		{
			wchar_t tmp[MAX_PATH];
			UniFormat(tmp, sizeof(tmp), L"%s\\Program Files (x86)", ms->WindowsDriveW);

			Free(ms->ProgramFilesDirX86W);
			ms->ProgramFilesDirX86W = UniCopyStr(tmp);
		}
		else
		{
			Free(ms->ProgramFilesDirX86W);
			ms->ProgramFilesDirX86W = UniCopyStr(ms->ProgramFilesDirW);
		}
	}

	// Program Files (x64)
	if (MsIs64BitWindows())
	{
		if (Is64())
		{
			ms->ProgramFilesDirX64 = CopyStr(ms->ProgramFilesDir);
			ms->ProgramFilesDirX64W = CopyUniStr(ms->ProgramFilesDirW);
		}
		else
		{
			char tmpa[MAX_SIZE];
			wchar_t tmpw[MAX_SIZE];

			ReplaceStrEx(tmpa, sizeof(tmpa), ms->ProgramFilesDir, "\\Program Files (x86)", "\\Program Files", false);
			UniReplaceStrEx(tmpw, sizeof(tmpw), ms->ProgramFilesDirW, L"\\Program Files (x86)", L"\\Program Files", false);

			ms->ProgramFilesDirX64 = CopyStr(tmpa);
			ms->ProgramFilesDirX64W = CopyUniStr(tmpw);
		}
	}
	else
	{
		ms->ProgramFilesDirX64 = CopyStr(ms->ProgramFilesDir);
		ms->ProgramFilesDirX64W = CopyUniStr(ms->ProgramFilesDirW);
	}

	if (MsIsNt())
	{
		// Common start menu
		ms->CommonStartMenuDir = MsGetSpecialDir(CSIDL_COMMON_STARTMENU);
		ms->CommonStartMenuDirW = MsGetSpecialDirW(CSIDL_COMMON_STARTMENU);

		// Common program
		ms->CommonProgramsDir = MsGetSpecialDir(CSIDL_COMMON_PROGRAMS);
		ms->CommonProgramsDirW = MsGetSpecialDirW(CSIDL_COMMON_PROGRAMS);

		// Common startup
		ms->CommonStartupDir = MsGetSpecialDir(CSIDL_COMMON_STARTUP);
		ms->CommonStartupDirW = MsGetSpecialDirW(CSIDL_COMMON_STARTUP);

		// Common application data
		ms->CommonAppDataDir = MsGetSpecialDir(CSIDL_COMMON_APPDATA);
		ms->CommonAppDataDirW = MsGetSpecialDirW(CSIDL_COMMON_APPDATA);

		// Common desktop
		ms->CommonDesktopDir = MsGetSpecialDir(CSIDL_COMMON_DESKTOPDIRECTORY);
		ms->CommonDesktopDirW = MsGetSpecialDirW(CSIDL_COMMON_DESKTOPDIRECTORY);

		// Local Settings
		ms->LocalAppDataDir = MsGetSpecialDir(CSIDL_LOCAL_APPDATA);
		ms->LocalAppDataDirW = MsGetSpecialDirW(CSIDL_LOCAL_APPDATA);
	}
	else
	{
		// Start menu of the individual
		ms->PersonalStartMenuDir = MsGetSpecialDir(CSIDL_STARTMENU);
		ms->CommonStartMenuDir = CopyStr(ms->PersonalStartMenuDir);
		ms->PersonalStartMenuDirW = MsGetSpecialDirW(CSIDL_STARTMENU);
		ms->CommonStartMenuDirW = CopyUniStr(ms->PersonalStartMenuDirW);

		// Program of the individual
		ms->PersonalProgramsDir = MsGetSpecialDir(CSIDL_PROGRAMS);
		ms->CommonProgramsDir = CopyStr(ms->PersonalProgramsDir);
		ms->PersonalProgramsDirW = MsGetSpecialDirW(CSIDL_PROGRAMS);
		ms->CommonProgramsDirW = CopyUniStr(ms->PersonalProgramsDirW);

		// Start-up of the individual
		ms->PersonalStartupDir = MsGetSpecialDir(CSIDL_STARTUP);
		ms->CommonStartupDir = CopyStr(ms->PersonalStartupDir);
		ms->PersonalStartupDirW = MsGetSpecialDirW(CSIDL_STARTUP);
		ms->CommonStartupDirW = CopyUniStr(ms->PersonalStartupDirW);

		// Application data of the individual
		ms->PersonalAppDataDir = MsGetSpecialDir(CSIDL_APPDATA);
		ms->CommonAppDataDir = CopyStr(ms->PersonalAppDataDir);
		ms->PersonalAppDataDirW = MsGetSpecialDirW(CSIDL_APPDATA);
		ms->CommonAppDataDirW = CopyUniStr(ms->PersonalAppDataDirW);

		// Desktops of the individual
		ms->PersonalDesktopDir = MsGetSpecialDir(CSIDL_DESKTOP);
		ms->CommonDesktopDir = CopyStr(ms->PersonalDesktopDir);
		ms->PersonalDesktopDirW = MsGetSpecialDirW(CSIDL_DESKTOP);
		ms->CommonDesktopDirW = CopyUniStr(ms->PersonalDesktopDirW);

		// Local Settings
		ms->LocalAppDataDir = CopyStr(ms->PersonalAppDataDir);
		ms->LocalAppDataDirW = CopyUniStr(ms->PersonalAppDataDirW);
	}
}

// Check whether the current user is a Administrators
bool MsCheckIsAdmin()
{
	UCHAR test_bit[32];
	UCHAR tmp[32];
	UCHAR exe_hash[SHA1_SIZE];
	char *name_tag = "Vpn_Check_Admin_Key_%u";
	DWORD type;
	DWORD size;
	char name[MAX_SIZE];

	Sha1(exe_hash, MsGetExeFileNameW(), UniStrLen(MsGetExeFileNameW()));

	Format(name, sizeof(name), name_tag, *((UINT *)exe_hash));

	Rand(test_bit, sizeof(test_bit));

	if (RegSetValueEx(HKEY_LOCAL_MACHINE, name, 0, REG_BINARY, test_bit, sizeof(test_bit)) != ERROR_SUCCESS)
	{
		return false;
	}

	size = sizeof(tmp);
	if (RegQueryValueEx(HKEY_LOCAL_MACHINE, name, 0, &type, tmp, &size) != ERROR_SUCCESS)
	{
		RegDeleteValue(HKEY_LOCAL_MACHINE, name);
		return false;
	}

	RegDeleteValue(HKEY_LOCAL_MACHINE, name);

	if (Cmp(test_bit, tmp, 32) != 0)
	{
		return false;
	}

	return true;
}

// Library initialization
void MsInit()
{
	char *str_ansi;
	wchar_t *str_unicode;
	OSVERSIONINFO os;
	char tmp[MAX_SIZE];
	UINT size;
	if (ms != NULL)
	{
		// Already initialized
		return;
	}

	suspend_handler_singleton = NewCounter();
	vlan_card_counter = NewCounter();
	vlan_card_should_stop_flag = false;

	ms = ZeroMalloc(sizeof(MS));

	// Getting instance handle
	ms->hInst = GetModuleHandle(NULL);

	// Get the KERNEL32.DLL
	ms->hKernel32 = LoadLibrary("kernel32.dll");

	// Get a command line string from the OS
	str_ansi = CopyStr(GetCommandLineA());
	Trim(str_ansi);
	str_unicode = UniCopyStr(GetCommandLineW());
	UniTrim(str_unicode);

	SetCommandLineStr(MsCutExeNameFromCommandLine(str_ansi));
	SetCommandLineUniStr(MsCutExeNameFromUniCommandLine(str_unicode));

	Free(str_unicode);
	Free(str_ansi);

	// Get the version of the OS
	Zero(&os, sizeof(os));
	os.dwOSVersionInfoSize = sizeof(os);
	GetVersionEx(&os);

	if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
	{
		// NT series
		ms->IsNt = true;

		ms->nt = MsLoadNtApiFunctions();

		if (ms->nt == NULL)
		{
			ms->IsNt = false;
			ms->IsAdmin = true;
		}
		else
		{
			// Whether I am an Administrators
			ms->IsAdmin = MsCheckIsAdmin();
		}
	}
	else
	{
		// In 9x system: Impersonate a Administrators always
		ms->IsAdmin = true;
	}

	if (GetProcAddress(ms->hKernel32, "wine_get_unix_file_name") != NULL)
	{
		ms->IsWine = true;
	}

	// Get information about the current process
	ms->hCurrentProcess = GetCurrentProcess();
	ms->CurrentProcessId = GetCurrentProcessId();

	// Get the EXE file name
	GetModuleFileName(NULL, tmp, sizeof(tmp));
	ms->ExeFileName = CopyStr(tmp);
	Win32GetDirFromPath(tmp, sizeof(tmp), tmp);
	ms->ExeFileDir = CopyStr(tmp);

	// Get the EXE file name (Unicode)
	if (IsNt())
	{
		wchar_t tmp_w[MAX_PATH];

		GetModuleFileNameW(NULL, tmp_w, sizeof(tmp_w));
		ms->ExeFileNameW = CopyUniStr(tmp_w);

		Win32GetDirFromPathW(tmp_w, sizeof(tmp_w), tmp_w);
		ms->ExeFileDirW = CopyUniStr(tmp_w);
	}
	else
	{
		ms->ExeFileNameW = CopyStrToUni(ms->ExeFileName);
		ms->ExeFileDirW = CopyStrToUni(ms->ExeFileDir);
	}

	// Get the special directories
	MsGetSpecialDirs();

	// Initialize the temporary directory
	MsInitTempDir();

	// Get the user name
	size = sizeof(tmp);
	GetUserName(tmp, &size);
	ms->UserName = CopyStr(tmp);

	// Get the user name (Unicode)
	if (IsNt())
	{
		wchar_t tmp_w[MAX_PATH];

		size = sizeof(tmp_w);

		GetUserNameW(tmp_w, &size);
		ms->UserNameW = CopyUniStr(tmp_w);
	}
	else
	{
		ms->UserNameW = CopyStrToUni(ms->UserName);
	}

	// Get the full user name
	if (ms->nt != NULL && ms->nt->GetUserNameExA != NULL)
	{
		wchar_t tmp_w[MAX_PATH];

		size = sizeof(tmp);
		if (ms->nt->GetUserNameExA(NameSamCompatible, tmp, &size))
		{
			ms->UserNameEx = CopyStr(tmp);
		}

		size = sizeof(tmp_w);
		if (ms->nt->GetUserNameExW(NameSamCompatible, tmp_w, &size))
		{
			ms->UserNameExW = CopyUniStr(tmp_w);
		}
	}

	if (ms->UserNameEx == NULL)
	{
		ms->UserNameEx = CopyStr(ms->UserName);
	}
	if (ms->UserNameExW == NULL)
	{
		ms->UserNameExW = CopyUniStr(ms->UserNameW);
	}

	// Initialization of the adapter list
	MsInitAdapterListModule();

	// Initialization of minidump base file name
	if (true)
	{
		wchar_t tmp[MAX_PATH];
		if (MsIsAdmin())
		{
			CombinePathW(tmp, sizeof(tmp), ms->ExeFileDirW, L"vpn_debug\\dump");
		}
		else
		{
			CombinePathW(tmp, sizeof(tmp), ms->TempDirW, L"vpn_debug\\dump");
		}
		ms->MinidumpBaseFileNameW = CopyUniStr(tmp);
	}

	MsSetEnableMinidump(true);

	if (MsIsNt())
	{
		if (ms->nt->MiniDumpWriteDump != NULL)
		{
			SetUnhandledExceptionFilter(MsExceptionHandler);
		}
	}

	// Open a LSA handle
	hLsa = NULL;
	lsa_package_id = 0;
	if (MsIsNt())
	{
		MsEnablePrivilege(SE_TCB_NAME, true);

		if (ms->nt->AllocateLocallyUniqueId != NULL &&
			ms->nt->LsaConnectUntrusted != NULL &&
			ms->nt->LsaLookupAuthenticationPackage != NULL &&
			ms->nt->LsaLogonUser != NULL &&
			ms->nt->LsaDeregisterLogonProcess != NULL &&
			ms->nt->LsaFreeReturnBuffer != NULL)
		{
			HANDLE h = NULL;
			NTSTATUS ret = ms->nt->LsaConnectUntrusted(&h);

			if (ret == 0)
			{
				LSA_STRING pkg_name;
				ULONG ul = 0;

				Zero(&pkg_name, sizeof(pkg_name));
				pkg_name.Buffer = MSV1_0_PACKAGE_NAME;
				pkg_name.Length = pkg_name.MaximumLength = StrLen(MSV1_0_PACKAGE_NAME);

				ret = ms->nt->LsaLookupAuthenticationPackage(h, &pkg_name, &ul);

				if (ret == 0)
				{
					Zero(&lsa_token_source, sizeof(lsa_token_source));

					ms->nt->AllocateLocallyUniqueId(&lsa_token_source.SourceIdentifier);
					Copy(lsa_token_source.SourceName, "SE-VPN  ", 8);

					lsa_package_id = ul;
					hLsa = h;
				}
				else
				{
					ms->nt->LsaDeregisterLogonProcess(h);
				}
			}
		}
	}

	// Read the msi.dll
	if (hMsi == NULL)
	{
		hMsi = LoadLibrary("msi.dll");

		if (hMsi != NULL)
		{
			_MsiConfigureProductW =
				(UINT (__stdcall *)(LPCWSTR,int,INSTALLSTATE)) GetProcAddress(hMsi, "MsiConfigureProductW");
			_MsiGetProductInfoW =
				(UINT (__stdcall *)(LPCWSTR,LPCWSTR,LPWSTR,LPDWORD)) GetProcAddress(hMsi, "MsiGetProductInfoW");
			_MsiSetInternalUI =
				(INSTALLUILEVEL (__stdcall *)(INSTALLUILEVEL,HWND *)) GetProcAddress(hMsi, "MsiSetInternalUI");
			_MsiLocateComponentW =
				(INSTALLSTATE (__stdcall *)(LPCWSTR,LPWSTR,LPDWORD)) GetProcAddress(hMsi, "MsiLocateComponentW");
		}
	}

	// Lock created
	vlan_lock = NewLock();
}

// Uninstall the MSI product
bool MsMsiUninstall(char *product_code, HWND hWnd, bool *reboot_required)
{
	wchar_t *product_code_w;
	bool ret = false;
	INSTALLUILEVEL old_level;
	HWND old_hwnd;
	UINT r;
	// Validate arguments
	if (product_code == NULL)
	{
		return false;
	}
	if (_MsiSetInternalUI == NULL || _MsiConfigureProductW == NULL)
	{
		return false;
	}

	if (reboot_required != NULL)
	{
		*reboot_required = false;
	}

	product_code_w = CopyStrToUni(product_code);

	old_hwnd = hWnd;
	old_level = _MsiSetInternalUI(INSTALLUILEVEL_PROGRESSONLY, &old_hwnd);

	r = _MsiConfigureProductW(product_code_w, INSTALLLEVEL_DEFAULT, INSTALLSTATE_ABSENT);

	if (r == ERROR_SUCCESS || r == ERROR_SUCCESS_REBOOT_INITIATED || r == ERROR_SUCCESS_REBOOT_REQUIRED)
	{
		ret = true;

		if (r == ERROR_SUCCESS_REBOOT_INITIATED || r == ERROR_SUCCESS_REBOOT_REQUIRED)
		{
			if (reboot_required != NULL)
			{
				*reboot_required = true;
			}
		}
	}

	if (old_level != INSTALLUILEVEL_NOCHANGE)
	{
		_MsiSetInternalUI(old_level, &old_hwnd);
	}

	Free(product_code_w);

	return ret;
}

// Get the installation directory of the MSI component
bool MsGetMsiInstalledDir(char *component_code, wchar_t *dir, UINT dir_size)
{
	wchar_t *component_code_w;
	bool ret = false;
	wchar_t tmp[MAX_SIZE];
	UINT sz = sizeof(tmp) / sizeof(wchar_t);
	// Validate arguments
	if (component_code == NULL || dir == NULL)
	{
		return false;
	}
	if (_MsiGetProductInfoW == NULL)
	{
		return false;
	}

	component_code_w = CopyStrToUni(component_code);

	Zero(tmp, sizeof(tmp));

	if (_MsiLocateComponentW(component_code_w, tmp, &sz) == INSTALLSTATE_LOCAL)
	{
		if (UniIsEmptyStr(tmp) == false)
		{
			GetDirNameFromFilePathW(dir, dir_size, tmp);
			ret = true;
		}
	}

	Free(component_code_w);

	return ret;
}

// Determine whether minidump is enabled
bool MsIsMinidumpEnabled()
{
	return ms->MiniDumpEnabled;
}

// Determine whether to create a minidump
void MsSetEnableMinidump(bool enabled)
{
	ms->MiniDumpEnabled = enabled;
}

// Output the minidump
void MsWriteMinidump(wchar_t *filename, void *ex)
{
	wchar_t tmp[MAX_PATH];
	wchar_t dir[MAX_PATH];
	HANDLE h;
	MINIDUMP_EXCEPTION_INFORMATION info;
	struct _EXCEPTION_POINTERS *exp = (struct _EXCEPTION_POINTERS *)ex;

	if (filename != NULL)
	{
		UniStrCpy(tmp, sizeof(tmp), filename);
	}
	else
	{
		SYSTEMTIME tm;

		Zero(&tm, sizeof(tm));
		GetLocalTime(&tm);

		UniFormat(tmp, sizeof(tmp), L"%s_%04u%02u%02u_%02u%02u%02u.dmp",
			ms->MinidumpBaseFileNameW,
			tm.wYear, tm.wMonth, tm.wDay, tm.wHour, tm.wMinute, tm.wSecond);
	}

	GetDirNameFromFilePathW(dir, sizeof(dir), tmp);

	CreateDirectoryW(dir, NULL);

	Zero(&info, sizeof(info));

	if (exp != NULL)
	{
		info.ThreadId = GetCurrentThreadId();
		info.ExceptionPointers = exp;
		info.ClientPointers = true;
	}

	h = CreateFileW(tmp, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (h != INVALID_HANDLE_VALUE)
	{
		ms->nt->MiniDumpWriteDump(ms->hCurrentProcess, ms->CurrentProcessId,
			h,
			MiniDumpNormal | MiniDumpWithFullMemory | MiniDumpWithDataSegs |
			MiniDumpWithHandleData
			,
			info.ThreadId == 0 ? NULL : &info, NULL, NULL);

		FlushFileBuffers(h);
		CloseHandle(h);
	}
}

// Exception handler
LONG CALLBACK MsExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	if (ms->MiniDumpEnabled)
	{
		MsWriteMinidump(NULL, ExceptionInfo);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

// Release of the library
void MsFree()
{
	if (ms == NULL)
	{
		// Uninitialized
		return;
	}

	// Release the LSA
	if (hLsa != NULL)
	{
		ms->nt->LsaDeregisterLogonProcess(hLsa);

		hLsa = NULL;
	}

	// Release of the adapter list
	MsFreeAdapterListModule();

	// Release of the temporary directory
	MsFreeTempDir();

	if (ms->IsNt)
	{
		// Release of NT series API
		MsFreeNtApiFunctions(ms->nt);
	}

	// Memory release
	// ANSI
	Free(ms->WindowsDir);
	Free(ms->System32Dir);
	Free(ms->TempDir);
	Free(ms->WinTempDir);
	Free(ms->WindowsDrive);
	Free(ms->ProgramFilesDir);
	Free(ms->CommonStartMenuDir);
	Free(ms->CommonProgramsDir);
	Free(ms->CommonStartupDir);
	Free(ms->CommonAppDataDir);
	Free(ms->CommonDesktopDir);
	Free(ms->PersonalStartMenuDir);
	Free(ms->PersonalProgramsDir);
	Free(ms->PersonalStartupDir);
	Free(ms->PersonalAppDataDir);
	Free(ms->PersonalDesktopDir);
	Free(ms->MyDocumentsDir);
	Free(ms->ExeFileDir);
	Free(ms->ExeFileName);
	Free(ms->UserName);
	Free(ms->UserNameEx);
	Free(ms->LocalAppDataDir);
	Free(ms->ProgramFilesDirX86);
	Free(ms->ProgramFilesDirX64);
	// Unicode
	Free(ms->WindowsDirW);
	Free(ms->System32DirW);
	Free(ms->TempDirW);
	Free(ms->WinTempDirW);
	Free(ms->WindowsDriveW);
	Free(ms->ProgramFilesDirW);
	Free(ms->CommonStartMenuDirW);
	Free(ms->CommonProgramsDirW);
	Free(ms->CommonStartupDirW);
	Free(ms->CommonAppDataDirW);
	Free(ms->CommonDesktopDirW);
	Free(ms->PersonalStartMenuDirW);
	Free(ms->PersonalProgramsDirW);
	Free(ms->PersonalStartupDirW);
	Free(ms->PersonalAppDataDirW);
	Free(ms->PersonalDesktopDirW);
	Free(ms->MyDocumentsDirW);
	Free(ms->ExeFileDirW);
	Free(ms->ExeFileNameW);
	Free(ms->UserNameW);
	Free(ms->UserNameExW);
	Free(ms->LocalAppDataDirW);
	Free(ms->MinidumpBaseFileNameW);
	Free(ms->ProgramFilesDirX86W);
	Free(ms->ProgramFilesDirX64W);

	Free(ms);
	ms = NULL;

	// Delete the lock
	DeleteLock(vlan_lock);
	vlan_lock = NULL;

	DeleteCounter(suspend_handler_singleton);
	suspend_handler_singleton = NULL;

	DeleteCounter(vlan_card_counter);
	vlan_card_counter = NULL;
	vlan_card_should_stop_flag = false;
}

// Directory acquisition related
char *MsGetWindowsDir()
{
	return ms->WindowsDir;
}
wchar_t *MsGetWindowsDirW()
{
	return ms->WindowsDirW;
}
char *MsGetSystem32Dir()
{
	return ms->System32Dir;
}
char *MsGetTempDir()
{
	return ms->TempDir;
}
char *MsGetProgramFilesDir()
{
	return ms->ProgramFilesDir;
}
char *MsGetCommonStartupDir()
{
	return ms->CommonStartupDir;
}
char *MsGetMyTempDir()
{
	return ms->MyTempDir;
}

wchar_t *MsGetExeFileNameW()
{
	return ms == NULL ? L"Unknown" : ms->ExeFileNameW;
}
wchar_t *MsGetExeFileDirW()
{
	return ms->ExeFileDirW;
}
wchar_t *MsGetSystem32DirW()
{
	return ms->System32DirW;
}
wchar_t *MsGetTempDirW()
{
	return ms->TempDirW;
}
wchar_t *MsGetCommonStartMenuDirW()
{
	return ms->CommonStartMenuDirW;
}
wchar_t *MsGetCommonProgramsDirW()
{
	return ms->CommonProgramsDirW;
}
wchar_t *MsGetProgramFilesDirX64W()
{
	return ms->ProgramFilesDirX64W;
}
wchar_t *MsGetCommonStartupDirW()
{
	return ms->CommonStartupDirW;
}
wchar_t *MsGetCommonDesktopDirW()
{
	return ms->CommonDesktopDirW;
}
wchar_t *MsGetPersonalStartMenuDirW()
{
	if (ms->PersonalStartMenuDirW == NULL)
	{
		ms->PersonalStartMenuDirW = MsGetSpecialDirW(CSIDL_STARTMENU);
	}

	return ms->PersonalStartMenuDirW;
}
wchar_t *MsGetPersonalProgramsDirW()
{
	if (ms->PersonalProgramsDirW == NULL)
	{
		ms->PersonalProgramsDirW = MsGetSpecialDirW(CSIDL_PROGRAMS);
	}

	return ms->PersonalProgramsDirW;
}
wchar_t *MsGetPersonalStartupDirW()
{
	if (ms->PersonalStartupDirW == NULL)
	{
		ms->PersonalStartupDirW = MsGetSpecialDirW(CSIDL_STARTUP);
	}

	return ms->PersonalStartupDirW;
}
wchar_t *MsGetPersonalAppDataDirW()
{
	if (ms->PersonalAppDataDirW == NULL)
	{
		ms->PersonalAppDataDirW = MsGetSpecialDirW(CSIDL_APPDATA);
	}

	return ms->PersonalAppDataDirW;
}
wchar_t *MsGetPersonalDesktopDirW()
{
	if (ms->PersonalDesktopDirW == NULL)
	{
		ms->PersonalDesktopDirW = MsGetSpecialDirW(CSIDL_DESKTOP);
	}

	return ms->PersonalDesktopDirW;
}
wchar_t *MsGetMyTempDirW()
{
	return ms->MyTempDirW;
}
wchar_t *MsGetUserNameW()
{
	return ms->UserNameW;
}

#endif	// WIN32

