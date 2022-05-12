// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// CMInner.h
// Internal header for the CM.c

#include "Client.h"
#include "CM.h"
#include "Command.h"
#include "WinUi.h"

#include "Mayaqua/Table.h"

#include <stdlib.h>

#define STARTUP_MUTEX_NAME	GC_SW_SOFTETHER_PREFIX "vpncmgr_startup_mutex"

#define	NAME_OF_VPN_CLIENT_MANAGER	"vpncmgr"

typedef struct LVB LVB;

void CmVoice(char *name);

typedef struct CM_UAC_HELPER
{
	THREAD *Thread;
	volatile bool Halt;
	EVENT *HaltEvent;
} CM_UAC_HELPER;

typedef struct CM_VOICE
{
	UINT voice_id;
	char *perfix;
} CM_VOICE;

static CM_VOICE cm_voice[] =
{
	{VOICE_SSK,		"ssk"		},
	{VOICE_AHO,		"aho"		},
};

typedef struct CM_ENUM_HUB
{
	HWND hWnd;
	THREAD *Thread;
	SESSION *Session;
	CLIENT_OPTION *ClientOption;
	TOKEN_LIST *Hub;
} CM_ENUM_HUB;

#define CM_SETTING_INIT_NONE		0
#define CM_SETTING_INIT_EASY		1	// Transition to the simple mode
#define CM_SETTING_INIT_NORMAL		2	// Transition to the normal mode
#define CM_SETTING_INIT_SELECT		3	// Show a selection screen
#define	CM_SETTING_INIT_CONNECT		4	// Import process by the simple installer

typedef struct CM
{
	HWND hMainWnd;
	HWND hStatusBar;
	REMOTE_CLIENT *Client;
	char *server_name;
	char *password;
	wchar_t *import_file_name;
	bool HideStatusBar;
	bool HideTrayIcon;
	bool ShowGrid;
	bool VistaStyle;
	bool ShowPort;
	wchar_t StatudBar1[MAX_SIZE];
	wchar_t StatudBar2[MAX_SIZE];
	wchar_t StatudBar3[MAX_SIZE];
	HICON Icon2, Icon3;
	bool IconView;
	THREAD *NotifyClientThread;
	NOTIFY_CLIENT *NotifyClient;
	volatile bool Halt;
	bool OnCloseDispatched;
	LIST *StatusWindowList;
	CEDAR *Cedar;
	LIST *EnumHubList;
	UINT WindowCount;
	bool DisableVoice;
	UINT VoiceId;
	UINT OldConnectedNum;
	bool UpdateConnectedNumFlag;
	UCHAR ShortcutKey[SHA1_SIZE];
	bool TrayInited;
	bool TraySucceed;
	bool TrayAnimation;
	bool TraySpeedAnimation;
	UINT TrayAnimationCounter;
	bool StartupMode;
	THREAD *TryExecUiHelperThread;
	volatile bool TryExecUiHelperHalt;
	HANDLE TryExecUiHelperProcessHandle;
	EVENT *TryExecUiHelperHaltEvent;
	bool WindowsShutdowning;
	bool CmSettingSupported;
	bool CmEasyModeSupported;
	bool CmSettingInitialFlag;
	CM_SETTING CmSetting;
	HWND hEasyWnd;
	bool StartupFinished;
	bool ConnectStartedFlag;
	bool PositiveDisconnectFlag;
	wchar_t EasyLastSelectedAccountName[MAX_ACCOUNT_NAME_LEN + 1];
	WINDOWPLACEMENT FakeWindowPlacement;
	bool CheckedAndShowedAdminPackMessage;
	INSTANCE *StartupMutex;
	bool BadProcessChecked;
	bool PopupMenuOpen;
	WINUI_UPDATE *Update;
} CM;

typedef struct CM_STATUS
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];		// Account name
	HWND hWndPolicy;					// Policy dialog
} CM_STATUS;

typedef struct CM_POLICY
{
	HWND hWnd;
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];		// Account name
	POLICY *Policy;						// Policy dialog
	CM_STATUS *CmStatus;				// CM_STATUS
	bool Extension;						// Extension
} CM_POLICY;

typedef struct CM_ACCOUNT
{
	bool EditMode;						// Edit mode (false: New mode)
	bool LinkMode;						// Link mode
	bool NatMode;						// NAT mode
	CLIENT_OPTION *ClientOption;		// Client option
	CLIENT_AUTH *ClientAuth;			// Authentication data
	bool Startup;						// Startup account
	bool CheckServerCert;				// Check the server certificate
	bool RetryOnServerCert;				// Retry on invalid server certificate
	bool AddDefaultCA;					// Use default trust store
	X *ServerCert;						// Server certificate
	char old_server_name[MAX_HOST_NAME_LEN + 1];	// Old server name
	bool Inited;						// Initialization flag
	POLICY Policy;						// Policy (only link mode)
	struct SM_HUB *Hub;					// HUB
	RPC *Rpc;							// RPC
	bool OnlineFlag;					// Online flag
	bool Flag1;							// Flag 1
	bool HideClientCertAuth;			// Hide the client authentication
	bool HideSecureAuth;				// Hide the smart card authentication
	bool HideTrustCert;					// Hide the trusted certificate authority button
	UCHAR ShortcutKey[SHA1_SIZE];		// Shortcut key
	bool LockMode;						// Setting lock mode
	bool Link_ConnectNow;				// Start the connection immediately
	UINT PolicyVer;						// Policy version
} CM_ACCOUNT;

typedef struct CM_CHANGE_PASSWORD
{
	CLIENT_OPTION *ClientOption;		// Client Option
	char Username[MAX_USERNAME_LEN + 1];	// User name
	char HubName[MAX_HUBNAME_LEN + 1];		// HUB name
} CM_CHANGE_PASSWORD;

typedef struct CM_TRAFFIC
{
	bool ServerMode;		// Server mode
	bool Double;			// 2x mode
	bool Raw;				// Raw data mode
	UINT Port;				// Port number
	char Host[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT NumTcp;			// Number of TCP connections
	UINT Type;				// Type
	UINT Span;				// Period
} CM_TRAFFIC;

typedef struct CM_TRAFFIC_DLG
{
	HWND hWnd;				// Window handle
	CM_TRAFFIC *Setting;	// Setting
	TTS *Tts;				// Measurement server
	TTC *Ttc;				// Measurement client
	THREAD *HaltThread;		// Thread for stopping
	THREAD *ClientEndWaitThread;	// Thread to wait for the client to finish
	bool Started;			// Started flag
	bool Stopping;			// Stopping
	UINT RetCode;			// Return value
	TT_RESULT Result;		// Result
	EVENT *ResultShowEvent;	// Display result event
	bool CloseDialogAfter;	// Flag of whether or not to close the dialog
} CM_TRAFFIC_DLG;

typedef struct CM_PROXY_HTTP_HEADER_DLG
{
	CLIENT_OPTION *ClientOption;
	HWND EditBox;
	UINT CurrentItem;
	UINT CurrentSubItem;
} CM_PROXY_HTTP_HEADER_DLG;

// Internet connection settings
typedef struct CM_INTERNET_SETTING
{
	UINT ProxyType;								// Type of proxy server
	char ProxyHostName[MAX_HOST_NAME_LEN + 1];	// Proxy server host name
	UINT ProxyPort;								// Proxy server port number
	char ProxyUsername[MAX_USERNAME_LEN + 1];	// Proxy server user name
	char ProxyPassword[MAX_USERNAME_LEN + 1];	// Proxy server password
} CM_INTERNET_SETTING;

static CM *cm = NULL;

void CmFreeTrayExternal(void *hWnd);

// Normal RPC call macro
__forceinline static bool CALL(HWND hWnd, UINT code)
{
	UINT ret = code;
	if (ret != ERR_NO_ERROR)
	{
		if (ret == ERR_DISCONNECTED)
		{
			if (cm != NULL)
			{
				Close(cm->hMainWnd);
			}
			else
			{
				MsgBox(hWnd, MB_ICONSTOP, _UU("SM_DISCONNECTED"));
			}

			if (cm != NULL)
			{
				CmFreeTrayExternal((void *)cm->hMainWnd);
			}
			exit(0);
		}
		else
		{
			UINT flag = MB_ICONEXCLAMATION;
			if (ret == ERR_VLAN_IS_USED)
			{
				CmVoice("using_vlan");
			}
			if (hWnd != NULL && cm != NULL && cm->hEasyWnd != NULL)
			{
				hWnd = cm->hEasyWnd;
			}
			if (hWnd != NULL && cm != NULL && hWnd == cm->hEasyWnd)
			{
				flag |= MB_SETFOREGROUND | MB_TOPMOST;
			}
			MsgBox(hWnd, flag, _E(ret));
		}
	}

	if (ret == ERR_NO_ERROR)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Extended RPC call macro (get an error value)
__forceinline static UINT CALLEX(HWND hWnd, UINT code)
{
	UINT ret = code;
	if (ret != ERR_NO_ERROR)
	{
		if (ret == ERR_DISCONNECTED)
		{
			if (cm != NULL)
			{
				Close(cm->hMainWnd);
			}
			else
			{
				MsgBox(hWnd, MB_ICONSTOP, _UU("SM_DISCONNECTED"));
			}
			if (cm != NULL)
			{
				CmFreeTrayExternal((void *)cm->hMainWnd);
			}
			exit(0);
		}
	}

	return ret;
}

typedef struct CM_LOADX
{
	X *x;
} CM_LOADX;

typedef struct CM_SETTING_DLG
{
	bool CheckPassword;
	UCHAR HashedPassword[SHA1_SIZE];
} CM_SETTING_DLG;

typedef struct CM_EASY_DLG
{
	bool EndDialogCalled;
} CM_EASY_DLG;



// Task tray related
#define	WM_CM_TRAY_MESSAGE			(WM_APP + 44)
#define WM_CM_SETTING_CHANGED_MESSAGE	(WM_APP + 45)
#define WM_CM_EASY_REFRESH			(WM_APP + 46)
#define WM_CM_SHOW					(WM_APP + 47)
#define	CMD_EASY_DBLCLICK			40697
#define	CMD_VGC_CONNECT				40698
#define	CM_TRAY_ANIMATION_INTERVAL	3000
#define	CM_TRAY_MAX_ITEMS			4096
#define	CM_TRAY_MENU_ID_START		12000
#define	CM_TRAY_MENU_CONNECT_ID_START	(CM_TRAY_MENU_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_MENU_STATUS_ID_START	(CM_TRAY_MENU_CONNECT_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_MENU_DISCONNECT_ID_START	(CM_TRAY_MENU_STATUS_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_MENU_RECENT_ID_START	(CM_TRAY_MENU_DISCONNECT_ID_START + CM_TRAY_MAX_ITEMS)
#define	CM_TRAY_IS_CONNECT_ID(id)	(((id) >= CM_TRAY_MENU_CONNECT_ID_START) && (id) < CM_TRAY_MENU_STATUS_ID_START)
#define	CM_TRAY_IS_STATUS_ID(id)	(((id) >= CM_TRAY_MENU_STATUS_ID_START) && (id) < CM_TRAY_MENU_DISCONNECT_ID_START)
#define	CM_TRAY_IS_DISCONNECT_ID(id)	(((id) >= CM_TRAY_MENU_DISCONNECT_ID_START) && (id) < (CM_TRAY_MENU_DISCONNECT_ID_START + CM_TRAY_MAX_ITEMS))
#define	CM_TRAY_IS_RECENT_ID(id)	(((id) >= CM_TRAY_MENU_RECENT_ID_START) && (id) < (CM_TRAY_MENU_RECENT_ID_START + CM_TRAY_MAX_ITEMS))


// Function prototype
void InitCM(bool set_app_id);
void FreeCM();
void MainCM();
bool LoginCM();
void LogoutCM();
UINT CmLoginDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void MainCMWindow();
void CmSendImportMessage(HWND hWnd, wchar_t *filename, UINT msg);
UINT CmMainWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmMainWindowOnSize(HWND hWnd);
void CmMainWindowOnInit(HWND hWnd);
void CmMainWindowOnQuit(HWND hWnd);
void CmSaveMainWindowPos(HWND hWnd);
void CmMainWindowOnCommand(HWND hWnd, WPARAM wParam, LPARAM lParam);
void CmMainWindowOnCommandEx(HWND hWnd, WPARAM wParam, LPARAM lParam, bool easy);
bool CmIsEnabled(HWND hWnd, UINT id);
bool CmIsChecked(UINT id);
bool CmIsBold(UINT id);
void CmMainWindowOnPopupMenu(HWND hWnd, HMENU hMenu, UINT pos);
void CmSaveMainWindowPos(HWND hWnd);
void CmRedrawStatusBar(HWND hWnd);
void CmRefresh(HWND hWnd);
void CmRefreshEx(HWND hWnd, bool style_changed);
void CmSetForegroundProcessToCnService();
void CmInitAccountList(HWND hWnd);
void CmInitAccountListEx(HWND hWnd, bool easy);
void CmInitVLanList(HWND hWnd);
void CmRefreshAccountList(HWND hWnd);
void CmRefreshAccountListEx(HWND hWnd, bool easy);
void CmRefreshAccountListEx2(HWND hWnd, bool easy, bool style_changed);
void CmRefreshVLanList(HWND hWnd);
void CmRefreshVLanListEx(HWND hWnd, bool style_changed);
void CmSaveAccountListPos(HWND hWnd);
void CmSaveVLanListPos(HWND hWnd);
wchar_t *CmGetProtocolName(UINT n);
void CmVLanNameToPrintName(char *str, UINT size, char *name);
bool CmPrintNameToVLanName(char *name, UINT size, char *str);
void CmMainWindowOnNotify(HWND hWnd, NMHDR *n);
void CmOnKey(HWND hWnd, bool ctrl, bool alt, UINT key);
void CmAccountListRightClick(HWND hWnd);
void CmVLanListRightClick(HWND hWnd);
void CmConnect(HWND hWnd, wchar_t *account_name);
void CmDisconnect(HWND hWnd, wchar_t *account_name);
void CmInitNotifyClientThread();
void CmFreeNotifyClientThread();
void CmNotifyClientThread(THREAD *thread, void *param);
void CmDeleteAccount(HWND hWnd, wchar_t *account_name);
void CmStatus(HWND hWnd, wchar_t *account_name);
void CmStatusDlg(HWND hWnd, wchar_t *account_name);
UINT CmStatusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmStatusDlgPrint(HWND hWnd, CM_STATUS *cmst);
void CmPrintStatusToListView(LVB *b, RPC_CLIENT_GET_CONNECTION_STATUS *s);
void CmPrintStatusToListViewEx(LVB *b, RPC_CLIENT_GET_CONNECTION_STATUS *s, bool server_mode);
void CmStatusDlgPrintCert(HWND hWnd, CM_STATUS *st, bool server);
void CmPolicyDlg(HWND hWnd, CM_STATUS *st);
UINT CmPolicyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmPolicyDlgPrint(HWND hWnd, CM_POLICY *p);
void CmPolicyDlgPrintEx(HWND hWnd, CM_POLICY *p, bool cascade_mode);
void CmPolicyDlgPrintEx2(HWND hWnd, CM_POLICY *p, bool cascade_mode, UINT ver);
void CmNewAccount(HWND hWnd);
void CmEditAccount(HWND hWnd, wchar_t *account_name);
void CmGenerateNewAccountName(HWND hWnd, wchar_t *name, UINT size);
void CmGenerateCopyName(HWND hWnd, wchar_t *name, UINT size, wchar_t *old_name);
void CmGenerateImportName(HWND hWnd, wchar_t *name, UINT size, wchar_t *old_name);
CM_ACCOUNT *CmCreateNewAccountObject(HWND hWnd);
CM_ACCOUNT *CmGetExistAccountObject(HWND hWnd, wchar_t *account_name);
void CmEnumHubStart(HWND hWnd, CLIENT_OPTION *o);
void CmInitEnumHub();
void CmFreeEnumHub();
void CmFreeAccountObject(HWND hWnd, CM_ACCOUNT *a);
bool CmEditAccountDlg(HWND hWnd, CM_ACCOUNT *a);
UINT CmEditAccountDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmEditAccountDlgUpdate(HWND hWnd, CM_ACCOUNT *a);
void CmEditAccountDlgInit(HWND hWnd, CM_ACCOUNT *a);
void CmEditAccountDlgOnOk(HWND hWnd, CM_ACCOUNT *a);
void CmEditAccountDlgStartEnumHub(HWND hWnd, CM_ACCOUNT *a);
bool CmLoadXAndK(HWND hWnd, X **x, K **k);
bool CmLoadXListAndK(HWND hWnd, X **x, K **k, LIST **cc);
bool CmLoadKEx(HWND hWnd, K **k, char *filename, UINT size);
bool CmLoadKExW(HWND hWnd, K **k, wchar_t *filename, UINT size);
bool CmLoadXFromFileOrSecureCard(HWND hWnd, X **x);
void CmLoadXFromFileOrSecureCardDlgInit(HWND hWnd, CM_LOADX *p);
void CmLoadXFromFileOrSecureCardDlgUpdate(HWND hWnd, CM_LOADX *p);
UINT CmLoadXFromFileOrSecureCardDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool CmLoadX(HWND hWnd, X **x);
bool CmLoadXEx(HWND hWnd, X **x, char *filename, UINT size);
bool CmLoadXExW(HWND hWnd, X **x, wchar_t *filename, UINT size);
X *CmGetIssuer(X *x);
bool CmProxyDlg(HWND hWnd, CLIENT_OPTION *a);
void CmProxyDlgUpdate(HWND hWnd, CLIENT_OPTION *a);
UINT CmProxyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool CmDetailDlg(HWND hWnd, CM_ACCOUNT *a);
UINT CmDetailDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
char *CmNewVLanDlg(HWND hWnd);
UINT CmNewVLanDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmCopyAccount(HWND hWnd, wchar_t *account_name);
void CmExportAccount(HWND hWnd, wchar_t *account_name);
void CmSortcut(HWND hWnd, wchar_t *account_name);
void CmImportAccount(HWND hWnd);
void CmImportAccountMain(HWND hWnd, wchar_t *filename);
void CmImportAccountMainEx(HWND hWnd, wchar_t *filename, bool overwrite);
void CmTrustDlg(HWND hWnd);
UINT CmTrustDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrustDlgUpdate(HWND hWnd);
void CmTrustDlgRefresh(HWND hWnd);
void CmTrustImport(HWND hWnd);
void CmTrustExport(HWND hWnd);
void CmTrustView(HWND hWnd);
void CmPassword(HWND hWnd);
UINT CmPasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmPasswordRefresh(HWND hWnd);
void CmRefreshStatusBar(HWND hWnd);
UINT CmGetNumConnected(HWND hWnd);
void CmDisconnectAll(HWND hWnd);
wchar_t *CmGenerateMainWindowTitle();
void CmConfigDlg(HWND hWnd);
UINT CmConfigDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmConfigDlgInit(HWND hWnd);
void CmConfigDlgRefresh(HWND hWnd);
void CmConfigDlgOnOk(HWND hWnd);
bool CmWarningDesktop(HWND hWnd, wchar_t *account_name);
UINT CmDesktopDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmDesktopDlgInit(HWND hWnd, wchar_t *account_name);
bool CmStopInstallVLan(HWND hWnd);
void CmChangePassword(HWND hWnd, CLIENT_OPTION *o, char *hubname, char *username);
UINT CmChangePasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmChangePasswordUpdate(HWND hWnd, CM_CHANGE_PASSWORD *p);
void SmShowPublicVpnServerHtml(HWND hWnd);
void CmConnectShortcut(UCHAR *key);
UINT CmSelectSecure(HWND hWnd, UINT current_id);
void CmClientSecureManager(HWND hWnd);
UINT CmClientSelectSecure(HWND hWnd);
UINT CmSelectSecureDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSelectSecureDlgInit(HWND hWnd, UINT default_id);
void CmSelectSecureDlgUpdate(HWND hWnd);
void CmSecureManager(HWND hWnd, UINT id);
void CmSecureManagerEx(HWND hWnd, UINT id, bool no_new_cert);
UINT CmSecureManagerDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSecureManagerDlgInit(HWND hWnd, UINT id);
void CmSecureManagerDlgUpdate(HWND hWnd, UINT id);
void CmSecureManagerDlgRefresh(HWND hWnd, UINT id);
void CmSecureManagerDlgPrintList(HWND hWnd, LIST *o);
void CmSecureManagerDlgPrintListEx(HWND hWnd, UINT id, LIST *o, UINT type);
wchar_t *CmSecureObjTypeToStr(UINT type);
UINT CmSecureType(HWND hWnd);
UINT CmSecureTypeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSecureManagerDlgImport(HWND hWnd, UINT id);
void CmSecureManagerDlgDelete(HWND hWnd, UINT id);
void CmSecureManagerDlgExport(HWND hWnd, UINT id);
void CmSecureManagerDlgNewCert(HWND hWnd, UINT id);
void CmSecurePin(HWND hWnd, UINT id);
UINT CmSecurePinDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSecurePinDlgUpdate(HWND hWnd);
void CmInitTray(HWND hWnd);
void CmPollingTray(HWND hWnd);
void CmFreeTray(HWND hWnd);
void CmChangeTrayString(HWND hWnd, wchar_t *str);
UINT CmGetTrayIconId(bool animation, UINT animation_counter);
void CmShowOrHideWindow(HWND hWnd);
void CmShowTrayMenu(HWND hWnd);
HMENU CmCreateTraySubMenu(HWND hWnd, bool flag, UINT start_id);
HMENU CmCreateRecentSubMenu(HWND hWnd, UINT start_id);
bool CmCheckPkcsEula(HWND hWnd, UINT id);
UINT CmPkcsEulaDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmDeleteOldStartupTrayFile();
UINT CmTrafficDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrafficDlgInit(HWND hWnd);
bool CmTrafficDlgUpdate(HWND hWnd);
void CmTrafficDlgOnOk(HWND hWnd);
bool CmTrafficLoadFromReg(CM_TRAFFIC *t);
void CmTrafficGetDefaultSetting(CM_TRAFFIC *t);
void CmTrafficSaveToReg(CM_TRAFFIC *t);
void CmTrafficDlgToStruct(HWND hWnd, CM_TRAFFIC *t);
void CmExecTraffic(HWND hWnd, CM_TRAFFIC *t);
UINT CmTrafficRunDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrafficRunDlgInit(HWND hWnd, CM_TRAFFIC_DLG *d);
void CmTrafficRunDlgStart(HWND hWnd, CM_TRAFFIC_DLG *d);
void CmTrafficRunDlgPrintProc(void *param, wchar_t *str);
void CmTrafficRunDlgAddStr(HWND hWnd, wchar_t *str);
void CmTrafficRunDlgHalt(HWND hWnd, CM_TRAFFIC_DLG *d);
void CmTrafficRunDlgHaltThread(THREAD *t, void *param);
void CmTrafficRunDlgClientWaitThread(THREAD *t, void *param);
void CmTrafficResult(HWND hWnd, TT_RESULT *r);
UINT CmTrafficResultDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmTrafficResultDlgInit(HWND hWnd, TT_RESULT *res);
void CmTryToExecUiHelper();
void CmInitTryToExecUiHelper();
void CmFreeTryToExecUiHelper();
void CmTryToExecUiHelperThread(THREAD *thread, void *param);
bool CmSetting(HWND hWnd);
UINT CmSettingDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmSettingDlgInit(HWND hWnd, CM_SETTING_DLG *d);
void CmSettingDlgUpdate(HWND hWnd, CM_SETTING_DLG *d);
void CmSettingDlgOnOk(HWND hWnd, CM_SETTING_DLG *d);
void CmApplyCmSetting();
void CmMainWindowOnTrayClicked(HWND hWnd, WPARAM wParam, LPARAM lParam);
void CmShowEasy();
void CmCloseEasy();
void CmMainWindowOnShowEasy(HWND hWnd);
UINT CmEasyDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CmEasyDlgInit(HWND hWnd, CM_EASY_DLG *d);
void CmEasyDlgUpdate(HWND hWnd, CM_EASY_DLG *d);
void CmEasyDlgRefresh(HWND hWnd, CM_EASY_DLG *d);
void CmRefreshEasy();
void CmEasyDlgOnNotify(HWND hWnd, CM_EASY_DLG *d, NMHDR *n);
void CmEasyDlgOnKey(HWND hWnd, CM_EASY_DLG *d, bool ctrl, bool alt, UINT key);
void CmEasyDlgOnCommand(HWND hWnd, CM_EASY_DLG *d, WPARAM wParam, LPARAM lParam);

bool CmStartStartupMutex();
void CmEndStartupMutex();
void CmSetUacWindowActive();
void CmUacHelperThread(THREAD *thread, void *param);
void CmProxyDlgUseForIE(HWND hWnd, CLIENT_OPTION *o);
void CmGetSystemInternetSetting(CM_INTERNET_SETTING *setting);
void CmProxyDlgSet(HWND hWnd, CLIENT_OPTION *o, CM_INTERNET_SETTING *setting);
bool CmGetProxyServerNameAndPortFromIeProxyRegStr(char *name, UINT name_size, UINT *port, char *str, char *server_type);
void *CmUpdateJumpList(UINT start_id);

void CmProxyHttpHeaderDlgUpdate(HWND hWnd);
void CmProxyHttpHeaderDlgRefresh(HWND hWnd, CM_PROXY_HTTP_HEADER_DLG *d);
void CmProxyHttpHeaderDlgInit(HWND hWnd, CM_PROXY_HTTP_HEADER_DLG *d);
UINT CmProxyHttpHeaderDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool CmProxyHttpHeaderDlg(HWND hWnd, CLIENT_OPTION *a);
