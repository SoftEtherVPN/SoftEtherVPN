// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// SMInner.h
// The internal header of SM.c

#ifndef SMINNER_H
#define SMINNER_H

#include "Admin.h"
#include "Connection.h"
#include "DDNS.h"
#include "Proto_EtherIP.h"
#include "WinUi.h"

#include "Mayaqua/TcpIp.h"

// Constants
#define	SM_REG_KEY			"Software\\SoftEther VPN Developer Edition\\SoftEther VPN\\Server Manager"
#define	SM_CERT_REG_KEY		"Software\\SoftEther VPN Developer Edition\\SoftEther VPN\\Server Manager\\Cert Tool"
#define	SM_SETTING_REG_KEY	"Software\\SoftEther VPN Developer Edition\\SoftEther VPN\\Server Manager\\Settings"
#define	SM_LASTHUB_REG_KEY	"Software\\SoftEther VPN Developer Edition\\SoftEther VPN\\Server Manager\\Last HUB Name"
#define	SM_HIDE_CERT_UPDATE_MSG_KEY	"Software\\SoftEther VPN Developer Edition\\SoftEther VPN\\Server Manager\\Hide Cert Update Msg"

#define	NAME_OF_VPN_SERVER_MANAGER	"vpnsmgr"
#define	NAME_OF_VPN_SERVER_TARGET	"vpnserver@%s"
#define	NAME_OF_VPN_BRIDGE_TARGET	"vpnbridge@%s"

// Constants (Old value)
#define	SM_SETTING_REG_KEY_OLD	"Software\\SoftEther Corporation\\PacketiX VPN\\Server Manager\\Settings"

// Connection setting
typedef struct SETTING
{
	wchar_t Title[MAX_SIZE];	// Setting Name
	bool ServerAdminMode;		// Server management mode
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB name
	UCHAR HashedPassword[SHA1_SIZE];	// Password
	CLIENT_OPTION ClientOption;	// Client Option
	UCHAR Reserved[10240 - sizeof(bool) * 8 - SHA1_SIZE];	// Reserved area
} SETTING;

// Structure declaration
typedef struct SM
{
	CEDAR *Cedar;				// Cedar
	LIST *SettingList;			// Setting List
	SETTING *TempSetting;		// Temporaly setting
	HWND hParentWnd;			// Parent window handle
	WINUI_UPDATE *Update;		// Updater
} SM;

// Edit connection settings
typedef struct SM_EDIT_SETTING
{
	bool EditMode;				// Edit mode
	SETTING *OldSetting;		// Pointer to the previous settings
	SETTING *Setting;			// Pointer to the configuration
	bool Inited;				// Initialized flag
} SM_EDIT_SETTING;

// Server management dialog
typedef struct SM_SERVER
{
	RPC *Rpc;					// RPC
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	wchar_t Title[MAX_SIZE];	// Title
	bool ServerAdminMode;		// Server management mode
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB name
	UINT ServerType;			// Type of server
	bool Bridge;				// VPN Bridge product
	UINT PolicyVer;				// Policy version
	RPC_SERVER_STATUS ServerStatus;	// Server status
	RPC_SERVER_INFO ServerInfo;		// Server Information
	CAPSLIST *CapsList;			// Caps list
	SETTING *CurrentSetting;	// The current connection settings
	wchar_t *AdminMsg;			// Message for Administrators
	bool IPsecMessageDisplayed;	// Whether to have already displayed a message about IPsec
	bool VgsMessageDisplayed;	// Whether to have already displayed a message about VGS
	WINUI_UPDATE *Update;		// Update notification
	bool IsInClient;			// Within VPN Client mode
} SM_SERVER;

typedef void (SM_STATUS_INIT_PROC)(HWND hWnd, SM_SERVER *p, void *param);
typedef bool (SM_STATUS_REFRESH_PROC)(HWND hWnd, SM_SERVER *p, void *param);

// Information display dialog
typedef struct SM_STATUS
{
	SM_SERVER *p;				// Pointer to the P
	void *Param;				// Parameter
	UINT Icon;					// Icon
	wchar_t *Caption;			// Title
	bool show_refresh_button;	// Show Updates button
	bool NoImage;				// No image
	SM_STATUS_INIT_PROC *InitProc;
	SM_STATUS_REFRESH_PROC *RefreshProc;
} SM_STATUS;

// Virtual HUB edit dialog
typedef struct SM_EDIT_HUB
{
	SM_SERVER *p;				// P
	bool EditMode;				// Edit mode
	char HubName[MAX_HUBNAME_LEN + 1];	// HUB name
} SM_EDIT_HUB;

// SSL related
typedef struct SM_SSL
{
	SM_SERVER *p;				// P
	X *Cert;					// Certificate
	K *Key;						// Secret key
	bool SetCertAndKey;			// Set the key
} SM_SSL;

// Save the certificate
typedef struct SM_SAVE_KEY_PAIR
{
	X *Cert;					// Certificate
	K *Key;						// Secret key
	char *Pass;					// Passphrase
} SM_SAVE_KEY_PAIR;

// Connection information
typedef struct SM_CONNECTION_INFO
{
	SM_SERVER *p;				// P
	char *ConnectionName;		// Connection name
} SM_CONNECTION_INFO;

// Management of HUB
typedef struct SM_HUB
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	char *HubName;				// HUB name
	char CurrentPushRouteStr[MAX_DHCP_CLASSLESS_ROUTE_TABLE_STR_SIZE];	// Current editing push routing table string
} SM_HUB;

// Show the User list
typedef struct SM_USER
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	char *GroupName;			// Filter by group name
	bool SelectMode;			// Selection mode
	char *SelectedName;			// User name of the selected
	bool AllowGroup;			// Allow selection of group
	bool CreateNow;				// Create a user immediately
} SM_USER;

// Edit the User
typedef struct SM_EDIT_USER
{
	bool Inited;				// Initialized flag
	bool EditMode;				// Edit mode
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	RPC_SET_USER SetUser;		// Configure the User
} SM_EDIT_USER;

// User information
typedef struct SM_USER_INFO
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	char *Username;				// Username
} SM_USER_INFO;

// Policy
typedef struct SM_POLICY
{
	bool Inited;				// Initialize
	POLICY *Policy;				// Policy
	wchar_t *Caption;			// Title
	bool CascadeMode;			// Cascade mode
	UINT Ver;					// Version
} SM_POLICY;

// Show the Group list
typedef struct SM_GROUP
{
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	bool SelectMode;			// Selection mode
	char *SelectedGroupName;	// Group name of the selected
} SM_GROUP;

// Edit the Group
typedef struct SM_EDIT_GROUP
{
	bool Inited;				// Initialization flag
	bool EditMode;				// Edit mode
	SM_SERVER *p;				// P
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	RPC_SET_GROUP SetGroup;		// Group Settings
} SM_EDIT_GROUP;

// Access list
typedef struct SM_ACCESS_LIST
{
	RPC *Rpc;					// RPC
	SM_HUB *Hub;				// HUB
	LIST *AccessList;			// Access list
} SM_ACCESS_LIST;

// Edit the access list
typedef struct SM_EDIT_ACCESS
{
	SM_HUB *Hub;				// HUB
	bool Inited;				// Initialization flag
	bool EditMode;				// Edit mode
	SM_ACCESS_LIST *AccessList;	// Access list
	ACCESS *Access;				// Access list item
} SM_EDIT_ACCESS;

// Display status of the access list
typedef struct SM_LINK
{
	SM_HUB *Hub;				// HUB
	wchar_t *AccountName;		// Account name
} SM_LINK;

// Session status
typedef struct SM_SESSION_STATUS
{
	SM_HUB *Hub;				// HUB
	char *SessionName;			// Session name
} SM_SESSION_STATUS;

// Address table
typedef struct SM_TABLE
{
	SM_HUB *Hub;				// HUB
	RPC *Rpc;					// RPC
	char *SessionName;			// Session name
} SM_TABLE;

// Certificate tool
typedef struct SM_CERT
{
	X *x;						// Generated certificate
	K *k;						// Generated secret key
	X *root_x;					// Root certificate
	K *root_k;					// Private key of the root certificate
	bool do_not_save;			// Do not save to the file
	char *default_cn;			// Default CN
	bool root_only;				// Only the root certificate
} SM_CERT;

// Config edit
typedef struct SM_CONFIG
{
	SM_SERVER *s;				// SM_SERVER
	RPC_CONFIG Config;			// Config body
} SM_CONFIG;

// Hub_admin_option edit
typedef struct SM_EDIT_AO
{
	SM_EDIT_HUB *e;
	bool CanChange;
	RPC_ADMIN_OPTION CurrentOptions;
	RPC_ADMIN_OPTION DefaultOptions;
	bool NewMode;
	char Name[MAX_ADMIN_OPTION_NAME_LEN + 1];
	UINT Value;
	bool ExtOption;
} SM_EDIT_AO;

// Editing the switch
typedef struct SM_L3SW
{
	SM_SERVER *s;
	char *SwitchName;
	bool Enable;
} SM_L3SW;

// Specify the certificate and private key in the smart card
typedef struct SM_SECURE_KEYPAIR
{
	UINT Id;
	bool UseCert;
	bool UseKey;
	char CertName[MAX_SIZE];
	char KeyName[MAX_SIZE];
	bool Flag;
	UINT BitmapId;
} SM_SECURE_KEYPAIR;

// CRL edit
typedef struct SM_EDIT_CRL
{
	SM_HUB *s;
	bool NewCrl;
	UINT Key;
} SM_EDIT_CRL;

// AC list edit
typedef struct SM_EDIT_AC_LIST
{
	SM_EDIT_HUB *s;
	LIST *AcList;
} SM_EDIT_AC_LIST;

// AC edit
typedef struct SM_EDIT_AC
{
	SM_EDIT_AC_LIST *e;
	UINT id;
} SM_EDIT_AC;

// Download the log File
typedef struct SM_READ_LOG_FILE
{
	HWND hWnd;
	SM_SERVER *s;
	char *server_name;
	char *filepath;
	UINT totalsize;
	bool cancel_flag;
	BUF *Buffer;
} SM_READ_LOG_FILE;

// Setup dialog
typedef struct SM_SETUP
{
	SM_SERVER *s;
	RPC *Rpc;
	bool IsBridge;
	bool UseRemote;			// Remote Access VPN
	bool UseSite;			// LAN-to-LAN VPN
	bool UseSiteEdge;		// VPN Server / Bridge to be installed in each site
	char HubName[MAX_HUBNAME_LEN + 1];	// Virtual HUB name
	bool Flag1;
	bool Flag2;
} SM_SETUP;

// EtherIP ID edit dialog
typedef struct SM_ETHERIP_ID
{
	SM_SERVER *s;
	bool EditMode;
	char EditId[MAX_SIZE];
	bool InitCompleted;
	ETHERIP_ID Data;
} SM_ETHERIP_ID;

// DDNS dialog
typedef struct SM_DDNS
{
	SM_SERVER *s;
	DDNS_CLIENT_STATUS Status;
	bool Flag;
	bool HostnameSetFlag;
	bool Changed;
	bool Silent;
	bool NoChangeCert;
	bool DoNotPoll;
} SM_DDNS;

// VPN Azure dialog
typedef struct SM_AZURE
{
	SM_SERVER *s;
	bool OnSetup;
} SM_AZURE;



// Function prototype
void InitSM();
void InitSMEx(bool from_cm);
void SmParseCommandLine();
void MainSM();
void FreeSM();
void FreeSMEx(bool from_cm);
void SmMainDlg();
UINT SmMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmMainDlgInit(HWND hWnd);
void SmMainDlgUpdate(HWND hWnd);
void SmInitSettingList();
void SmFreeSettingList();
void SmWriteSettingList();
void SmLoadSettingList();
void SmInitDefaultSettingList();
int SmCompareSetting(void *p1, void *p2);
SETTING *SmGetSetting(wchar_t *title);
bool SmAddSetting(SETTING *s);
void SmDeleteSetting(wchar_t *title);
bool SmCheckNewName(SETTING *s, wchar_t *new_title);
void SmRefreshSetting(HWND hWnd);
void SmRefreshSettingEx(HWND hWnd, wchar_t *select_name);
bool SmAddSettingDlg(HWND hWnd, wchar_t *new_name, UINT new_name_size);
bool SmEditSettingDlg(HWND hWnd);
UINT SmEditSettingDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditSettingDlgInit(HWND hWnd, SM_EDIT_SETTING *p);
void SmEditSettingDlgUpdate(HWND hWnd, SM_EDIT_SETTING *p);
void SmEditSettingDlgOnOk(HWND hWnd, SM_EDIT_SETTING *p);
void SmConnect(HWND hWnd, SETTING *s);
void SmConnectEx(HWND hWnd, SETTING *s, bool is_in_client);
char *SmPassword(HWND hWnd, char *server_name);
UINT SmServerDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmServerDlgInit(HWND hWnd, SM_SERVER *p);
void SmServerDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmServerDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmStatusDlg(HWND hWnd, SM_SERVER *p, void *param, bool no_image, bool show_refresh_button, wchar_t *caption, UINT icon,
				 SM_STATUS_INIT_PROC *init, SM_STATUS_REFRESH_PROC *refresh);
UINT SmStatusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool SmRefreshHubStatus(HWND hWnd, SM_SERVER *p, void *param);
void SmInsertTrafficInfo(LVB *b, TRAFFIC *t);
bool SmCreateHubDlg(HWND hWnd, SM_SERVER *p);
bool SmEditHubDlg(HWND hWnd, SM_SERVER *p, char *hubname);
UINT SmEditHubProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditHubInit(HWND hWnd, SM_EDIT_HUB *s);
void SmEditHubUpdate(HWND hWnd, SM_EDIT_HUB *s);
void SmEditHubOnOk(HWND hWnd, SM_EDIT_HUB *s);
bool SmCreateListenerDlg(HWND hWnd, SM_SERVER *p);
UINT SmCreateListenerDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSslDlg(HWND hWnd, SM_SERVER *p);
UINT SmSslDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSslDlgInit(HWND hWnd, SM_SSL *s);
void SmSslDlgOnOk(HWND hWnd, SM_SSL *s);
void SmSslDlgUpdate(HWND hWnd, SM_SSL *s);
void SmGetCertInfoStr(wchar_t *str, UINT size, X *x);
bool SmRegenerateServerCert(HWND hWnd, SM_SERVER *server, char *default_cn, X **x, K **k, bool root_only);
bool SmSaveKeyPairDlg(HWND hWnd, X *x, K *k);
UINT SmSaveKeyPairDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSaveKeyPairDlgInit(HWND hWnd, SM_SAVE_KEY_PAIR *s);
void SmSaveKeyPairDlgUpdate(HWND hWnd, SM_SAVE_KEY_PAIR *s);
void SmSaveKeyPairDlgOnOk(HWND hWnd, SM_SAVE_KEY_PAIR *s);
bool SmRefreshServerStatus(HWND hWnd, SM_SERVER *p, void *param);
bool SmRefreshServerInfo(HWND hWnd, SM_SERVER *p, void *param);
void SmPrintNodeInfo(LVB *b, NODE_INFO *info);
wchar_t *SmGetConnectionTypeStr(UINT type);
void SmConnectionDlg(HWND hWnd, SM_SERVER *p);
UINT SmConnectionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmConnectionDlgInit(HWND hWnd, SM_SERVER *p);
void SmConnectionDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmConnectionDlgUpdate(HWND hWnd, SM_SERVER *p);
bool SmRefreshConnectionStatus(HWND hWnd, SM_SERVER *p, void *param);
bool SmFarmDlg(HWND hWnd, SM_SERVER *p);
UINT SmFarmDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmFarmDlgInit(HWND hWnd, SM_SERVER *p);
void SmFarmDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmFarmDlgOnOk(HWND hWnd, SM_SERVER *p);
UINT SmFarmMemberDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmFarmMemberDlgInit(HWND hWnd, SM_SERVER *p);
void SmFarmMemberDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmFarmMemberDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmFarmMemberDlgOnOk(HWND hWnd, SM_SERVER *p);
void SmFarmMemberCert(HWND hWnd, SM_SERVER *p, UINT id);
bool SmRefreshFarmMemberInfo(HWND hWnd, SM_SERVER *p, void *param);
bool SmRefreshFarmConnectionInfo(HWND hWnd, SM_SERVER *p, void *param);
UINT SmChangeServerPasswordDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubDlg(HWND hWnd, SM_HUB *s);
UINT SmHubDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubDlgInit(HWND hWnd, SM_HUB *s);
void SmHubDlgUpdate(HWND hWnd, SM_HUB *s);
void SmHubDlgRefresh(HWND hWnd, SM_HUB *s);
void SmUserListDlg(HWND hWnd, SM_HUB *s);
UINT SmUserListProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmUserListInit(HWND hWnd, SM_USER *s);
void SmUserListRefresh(HWND hWnd, SM_USER *s);
void SmUserListUpdate(HWND hWnd, SM_USER *s);
wchar_t *SmGetAuthTypeStr(UINT id);
bool SmCreateUserDlg(HWND hWnd, SM_HUB *s);
UINT SmEditUserDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditUserDlgInit(HWND hWnd, SM_EDIT_USER *s);
void SmEditUserDlgUpdate(HWND hWnd, SM_EDIT_USER *s);
void SmEditUserDlgOk(HWND hWnd, SM_EDIT_USER *s);
bool SmPolicyDlg(HWND hWnd, POLICY *p, wchar_t *caption);
bool SmPolicyDlgEx(HWND hWnd, POLICY *p, wchar_t *caption, bool cascade_mode);
bool SmPolicyDlgEx2(HWND hWnd, POLICY *p, wchar_t *caption, bool cascade_mode, UINT ver);
UINT SmPolicyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmPolicyDlgInit(HWND hWnd, SM_POLICY *s);
void SmPolicyDlgUpdate(HWND hWnd, SM_POLICY *s);
void SmPolicyDlgOk(HWND hWnd, SM_POLICY *s);
bool SmEditUserDlg(HWND hWnd, SM_HUB *s, char *username);
bool SmRefreshUserInfo(HWND hWnd, SM_SERVER *s, void *param);
void SmGroupListDlg(HWND hWnd, SM_HUB *s);
char *SmSelectGroupDlg(HWND hWnd, SM_HUB *s, char *default_name);
UINT SmGroupListDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmGroupListDlgInit(HWND hWnd, SM_GROUP *s);
void SmGroupListDlgUpdate(HWND hWnd, SM_GROUP *s);
void SmGroupListDlgRefresh(HWND hWnd, SM_GROUP *s);
bool SmCreateGroupDlg(HWND hWnd, SM_GROUP *s);
bool SmEditGroupDlg(HWND hWnd, SM_GROUP *s, char *name);
UINT SmEditGroupDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditGroupDlgInit(HWND hWnd, SM_EDIT_GROUP *g);
void SmEditGroupDlgUpdate(HWND hWnd, SM_EDIT_GROUP *g);
void SmEditGroupDlgOnOk(HWND hWnd, SM_EDIT_GROUP *g);
void SmUserListDlgEx(HWND hWnd, SM_HUB *s, char *groupname, bool create);
void SmAccessListDlg(HWND hWnd, SM_HUB *s);
UINT SmAccessListProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmAccessListInit(HWND hWnd, SM_ACCESS_LIST *s);
void SmAccessListUpdate(HWND hWnd, SM_ACCESS_LIST *s);
void SmAccessListRefresh(HWND hWnd, SM_ACCESS_LIST *s);
bool SmAddAccess(HWND hWnd, SM_ACCESS_LIST *s, bool ipv6);
bool SmCloneAccess(HWND hWnd, SM_ACCESS_LIST *s, ACCESS *t);
bool SmEditAccess(HWND hWnd, SM_ACCESS_LIST *s, ACCESS *a);
UINT SmEditAccessDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditAccessInit(HWND hWnd, SM_EDIT_ACCESS *s);
void SmEditAccessUpdate(HWND hWnd, SM_EDIT_ACCESS *s);
void SmEditAccessOnOk(HWND hWnd, SM_EDIT_ACCESS *s);
void SmRedirect(HWND hWnd, SM_EDIT_ACCESS *s);
UINT SmRedirectDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmRedirectDlgInit(HWND hWnd, SM_EDIT_ACCESS *s);
void SmRedirectDlgUpdate(HWND hWnd, SM_EDIT_ACCESS *s);
UINT SmSimulationDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSimulationUpdate(HWND hWnd, SM_EDIT_ACCESS *s);
void SmSimulationInit(HWND hWnd, SM_EDIT_ACCESS *s);
void SmSimulationOnOk(HWND hWnd, SM_EDIT_ACCESS *s);
char *SmSelectUserDlg(HWND hWnd, SM_HUB *s, char *default_name);
char *SmSelectUserDlgEx(HWND hWnd, SM_HUB *s, char *default_name, bool allow_group);
void SmRadiusDlg(HWND hWnd, SM_HUB *s);
UINT SmRadiusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmRadiusDlgInit(HWND hWnd, SM_HUB *s);
void SmRadiusDlgUpdate(HWND hWnd, SM_HUB *s);
void SmRadiusDlgOnOk(HWND hWnd, SM_HUB *s);
void SmLinkDlg(HWND hWnd, SM_HUB *s);
void SmLinkDlgEx(HWND hWnd, SM_HUB *s, bool createNow);
UINT SmLinkDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLinkDlgInit(HWND hWnd, SM_HUB *s);
void SmLinkDlgUpdate(HWND hWnd, SM_HUB *s);
void SmLinkDlgRefresh(HWND hWnd, SM_HUB *s);
bool SmLinkCreate(HWND hWnd, SM_HUB *s);
bool SmLinkCreateEx(HWND hWnd, SM_HUB *s, bool connectNow);
bool SmLinkEdit(HWND hWnd, SM_HUB *s, wchar_t *name);
bool SmRefreshLinkStatus(HWND hWnd, SM_SERVER *s, void *param);
UINT SmLogDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLogDlgInit(HWND hWnd, SM_HUB *s);
void SmLogDlgUpdate(HWND hWnd, SM_HUB *s);
void SmLogDlgOnOk(HWND hWnd, SM_HUB *s);
void SmCaDlg(HWND hWnd, SM_HUB *s);
UINT SmCaDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmCaDlgInit(HWND hWnd, SM_HUB *s);
void SmCaDlgRefresh(HWND hWnd, SM_HUB *s);
void SmCaDlgUpdate(HWND hWnd, SM_HUB *s);
void SmCaDlgOnOk(HWND hWnd, SM_HUB *s);
bool SmCaDlgAdd(HWND hWnd, SM_HUB *s);
void SmSessionDlg(HWND hWnd, SM_HUB *s);
UINT SmSessionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSessionDlgInit(HWND hWnd, SM_HUB *s);
void SmSessionDlgUpdate(HWND hWnd, SM_HUB *s);
void SmSessionDlgRefresh(HWND hWnd, SM_HUB *s);
bool SmRefreshSessionStatus(HWND hWnd, SM_SERVER *s, void *param);
void SmMacTableDlg(HWND hWnd, SM_HUB *s, char *session_name);
UINT SmMacTableDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmMacTableDlgInit(HWND hWnd, SM_TABLE *s);
void SmMacTableDlgUpdate(HWND hWnd, SM_TABLE *s);
void SmMacTableDlgRefresh(HWND hWnd, SM_TABLE *s);
void SmIpTableDlg(HWND hWnd, SM_HUB *s, char *session_name);
UINT SmIpTableDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmIpTableDlgInit(HWND hWnd, SM_TABLE *s);
void SmIpTableDlgUpdate(HWND hWnd, SM_TABLE *s);
void SmIpTableDlgRefresh(HWND hWnd, SM_TABLE *s);
bool SmCreateCert(HWND hWnd, X **x, K **k, bool do_not_save, char *default_cn, bool root_only);
UINT SmCreateCertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmCreateCertDlgInit(HWND hWnd, SM_CERT *s);
void SmCreateCertDlgUpdate(HWND hWnd, SM_CERT *s);
void SmCreateCertDlgOnOk(HWND hWnd, SM_CERT *s);
UINT SmSNATDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSNATDlgUpdate(HWND hWnd, SM_HUB *s);
void SmBridgeDlg(HWND hWnd, SM_SERVER *s);
void SmInstallWinPcap(HWND hWnd, SM_SERVER *s);
UINT SmBridgeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT SmBridgeDlgInit(HWND hWnd, SM_SERVER *s);
void SmBridgeDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmBridgeDlgRefresh(HWND hWnd, SM_SERVER *s);
void SmBridgeDlgOnOk(HWND hWnd, SM_SERVER *s);
void SmAddServerCaps(LVB *b, CAPSLIST *t);
void SmConfig(HWND hWnd, SM_SERVER *s);
UINT SmConfigDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmConfigDlgInit(HWND hWnd, SM_CONFIG *c);
void SmHubAdminOption(HWND hWnd, SM_EDIT_HUB *e);
void SmHubExtOption(HWND hWnd, SM_EDIT_HUB *e);
UINT SmHubAdminOptionDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubAdminOptionDlgUpdate(HWND hWnd, SM_EDIT_AO *a);
void SmHubAdminOptionDlgInit(HWND hWnd, SM_EDIT_AO *a);
void SmHubAdminOptionDlgOk(HWND hWnd, SM_EDIT_AO *a);
UINT SmHubAdminOptionValueDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubAdminOptionValueDlgUpdate(HWND hWnd, SM_EDIT_AO *a);
void SmL3(HWND hWnd, SM_SERVER *s);
UINT SmL3Dlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3DlgInit(HWND hWnd, SM_SERVER *s);
void SmL3DlgUpdate(HWND hWnd, SM_SERVER *s);
void SmL3DlgRefresh(HWND hWnd, SM_SERVER *s);
UINT SmL3AddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3AddDlgUpdate(HWND hWnd, SM_SERVER *s);
UINT SmL3SwDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3SwDlgInit(HWND hWnd, SM_L3SW *w);
void SmL3SwDlgUpdate(HWND hWnd, SM_L3SW *w);
void SmL3SwDlgRefresh(HWND hWnd, SM_L3SW *w);
UINT SmL3SwIfDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3SwIfDlgInit(HWND hWnd, SM_L3SW *w);
void SmL3SwIfDlgUpdate(HWND hWnd, SM_L3SW *w);
UINT SmL3SwTableDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmL3SwTableDlgInit(HWND hWnd, SM_L3SW *w);
void SmL3SwTableDlgUpdate(HWND hWnd, SM_L3SW *w);
bool SmL3IsSwActive(SM_SERVER *s, char *name);
UINT SmGetCurrentSecureId(HWND hWnd);
UINT SmGetCurrentSecureIdFromReg();
UINT SmSelectSecureId(HWND hWnd);
void SmWriteSelectSecureIdReg(UINT id);
bool SmSelectKeyPair(HWND hWnd, char *cert_name, UINT cert_name_size, char *key_name, UINT key_name_size);
bool SmSelectKeyPairEx(HWND hWnd, char *cert_name, UINT cert_name_size, char *key_name, UINT key_name_size, UINT bitmap_id);
UINT SmSelectKeyPairDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSelectKeyPairDlgInit(HWND hWnd, SM_SECURE_KEYPAIR *k);
void SmSelectKeyPairDlgUpdate(HWND hWnd, SM_SECURE_KEYPAIR *k);
void SmSelectKeyPairDlgRefresh(HWND hWnd, SM_SECURE_KEYPAIR *k);
void SmSecureManager(HWND hWnd);
UINT SmCrlDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmCrlDlgInit(HWND hWnd, SM_HUB *s);
void SmCrlDlgUpdate(HWND hWnd, SM_HUB *s);
void SmCrlDlgRefresh(HWND hWnd, SM_HUB *s);
UINT SmEditCrlDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEditCrlDlgInit(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgUpdate(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgOnOk(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgOnLoad(HWND hWnd, SM_EDIT_CRL *c);
void SmEditCrlDlgSetName(HWND hWnd, NAME *name);
void SmEditCrlDlgSetSerial(HWND hWnd, X_SERIAL *serial);
void SmEditCrlDlgSetHash(HWND hWnd, UCHAR *hash_md5, UCHAR *hash_sha1);
void SmHubAc(HWND hWnd, SM_EDIT_HUB *s);
UINT SmHubAcDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubAcDlgInit(HWND hWnd, SM_EDIT_AC_LIST *p);
void SmHubAcDlgUpdate(HWND hWnd, SM_EDIT_AC_LIST *p);
void SmHubAcDlgRefresh(HWND hWnd, SM_EDIT_AC_LIST *p);
UINT SmHubEditAcDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubEditAcDlgInit(HWND hWnd, SM_EDIT_AC *p);
void SmHubEditAcDlgUpdate(HWND hWnd, SM_EDIT_AC *p);
void SmHubEditAcDlgOnOk(HWND hWnd, SM_EDIT_AC *p);
UINT SmLogFileDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLogFileDlgInit(HWND hWnd, SM_SERVER *p);
void SmLogFileDlgRefresh(HWND hWnd, SM_SERVER *p);
void SmLogFileDlgUpdate(HWND hWnd, SM_SERVER *p);
void SmLogFileStartDownload(HWND hWnd, SM_SERVER *s, char *server_name, char *filepath, UINT totalsize);
UINT SmReadLogFile(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool SmReadLogFileProc(DOWNLOAD_PROGRESS *g);
UINT SmSaveLogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLicense(HWND hWnd, SM_SERVER *s);
UINT SmLicenseDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLicenseDlgInit(HWND hWnd, SM_SERVER *s);
void SmLicenseDlgRefresh(HWND hWnd, SM_SERVER *s);
void SmLicenseDlgUpdate(HWND hWnd, SM_SERVER *s);
bool SmLicenseAdd(HWND hWnd, SM_SERVER *s);
UINT SmLicenseAddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmLicenseAddDlgInit(HWND hWnd, SM_SERVER *s);
void SmLicenseAddDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmLicenseAddDlgShiftTextItem(HWND hWnd, UINT id1, UINT id2, UINT *next_focus);
void SmLicenseAddDlgGetText(HWND hWnd, char *str, UINT size);
void SmLicenseAddDlgOnOk(HWND hWnd, SM_SERVER *s);
bool SmSetup(HWND hWnd, SM_SERVER *s);
UINT SmSetupDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSetupDlgInit(HWND hWnd, SM_SETUP *s);
void SmSetupDlgUpdate(HWND hWnd, SM_SETUP *s);
void SmSetupDlgOnOk(HWND hWnd, SM_SETUP *s);
UINT SmSetupHubDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSetupHubDlgUpdate(HWND hWnd, SM_SETUP *s);
bool SmSetupInit(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllHub(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllLocalBridge(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllLayer3(HWND hWnd, SM_SETUP *s);
bool SmSetupDeleteAllObjectInBridgeHub(HWND hWnd, SM_SETUP *s);
void SmSetupStep(HWND hWnd, SM_SETUP *s);
UINT SmSetupStepDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSetupStepDlgInit(HWND hWnd, SM_SETUP *s);
void SmSetupOnClose(HWND hWnd, SM_SETUP *s);
bool SmSetupIsNew(SM_SERVER *s);
void SmVLan(HWND hWnd, SM_SERVER *s);
UINT SmVLanDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmVLanDlgInit(HWND hWnd, SM_SERVER *s);
void SmVLanDlgRefresh(HWND hWnd, SM_SERVER *s);
void SmVLanDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmHubMsg(HWND hWnd, SM_EDIT_HUB *s);
UINT SmHubMsgDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmHubMsgDlgInit(HWND hWnd, SM_EDIT_HUB *s);
void SmHubMsgDlgUpdate(HWND hWnd, SM_EDIT_HUB *s);
void SmHubMsgDlgOnOk(HWND hWnd, SM_EDIT_HUB *s);
void SmIPsec(HWND hWnd, SM_SERVER *s);
UINT SmIPsecDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmIPsecDlgInit(HWND hWnd, SM_SERVER *s);
void SmIPsecDlgOnOk(HWND hWnd, SM_SERVER *s);
void SmIPsecDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmIPsecDlgGetSetting(HWND hWnd, IPSEC_SERVICES *sl);
void SmEtherIp(HWND hWnd, SM_SERVER *s);
UINT SmEtherIpDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEtherIpDlgInit(HWND hWnd, SM_SERVER *s);
void SmEtherIpDlgRefresh(HWND hWnd, SM_SERVER *s);
void SmEtherIpDlgUpdate(HWND hWnd, SM_SERVER *s);
bool SmEtherIpId(HWND hWnd, SM_ETHERIP_ID *t);
UINT SmEtherIpIdDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmEtherIpIdDlgInit(HWND hWnd, SM_ETHERIP_ID *t);
void SmEtherIpIdDlgOnOk(HWND hWnd, SM_ETHERIP_ID *t);
void SmEtherIpIdDlgUpdate(HWND hWnd, SM_ETHERIP_ID *t);
void SmEtherIpIdDlgGetSetting(HWND hWnd, SM_ETHERIP_ID *t);
bool SmDDns(HWND hWnd, SM_SERVER *s, bool silent, bool no_change_cert);
UINT SmDDnsDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmDDnsDlgInit(HWND hWnd, SM_DDNS *d);
void SmDDnsRefresh(HWND hWnd, SM_DDNS *d);
void SmDDnsDlgOnOk(HWND hWnd, SM_DDNS *d);
void SmDDnsDlgUpdate(HWND hWnd, SM_DDNS *d);
void SmOpenVpn(HWND hWnd, SM_SERVER *s);
UINT SmOpenVpnDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmOpenVpnDlgInit(HWND hWnd, SM_SERVER *s);
void SmOpenVpnDlgOnOk(HWND hWnd, SM_SERVER *s, bool no_close);
void SmOpenVpnDlgUpdate(HWND hWnd, SM_SERVER *s);
void SmOpenVpn(HWND hWnd, SM_SERVER *s);
void SmSpecialListener(HWND hWnd, SM_SERVER *s);
UINT SmSpecialListenerDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmSpecialListenerDlgInit(HWND hWnd, SM_SERVER *s);
void SmSpecialListenerDlgOnOk(HWND hWnd, SM_SERVER *s);
void SmShowIPSecMessageIfNecessary(HWND hWnd, SM_SERVER *p);
void SmShowCertRegenerateMessageIfNecessary(HWND hWnd, SM_SERVER *p);
UINT SmVmBridgeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmAzure(HWND hWnd, SM_SERVER *s, bool on_setup);
UINT SmAzureDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmAzureDlgOnInit(HWND hWnd, SM_AZURE *a);
void SmAzureDlgRefresh(HWND hWnd, SM_AZURE *a);
void SmAzureSetStatus(HWND hWnd, SM_AZURE *a);
bool SmProxy(HWND hWnd, INTERNET_SETTING *t);
UINT SmProxyDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void SmProxyDlgInit(HWND hWnd, INTERNET_SETTING *t);
void SmProxyDlgUpdate(HWND hWnd, INTERNET_SETTING *t);

#endif
