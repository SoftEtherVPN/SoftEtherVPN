// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Client.h
// Header of Client.c

#ifndef	CLIENT_H
#define	CLIENT_H

#define	CLIENT_CONFIG_PORT					GC_CLIENT_CONFIG_PORT		// Client port number
#define	CLIENT_NOTIFY_PORT					GC_CLIENT_NOTIFY_PORT		// Client notification port number
#define CLIENT_WAIT_CN_READY_TIMEOUT		(10 * 1000)	// Standby time to start the client notification service


// Check whether the client can run on the specified OS_TYPE
#define	IS_CLIENT_SUPPORTED_OS(t)			\
	((OS_IS_WINDOWS_NT(t) && GET_KETA(t, 100) >= 2) || (OS_IS_WINDOWS_9X(t)))


// Constants
#define	CLIENT_CONFIG_FILE_NAME				"$vpn_client.config"
#define	CLIENT_DEFAULT_KEEPALIVE_HOST		"keepalive.softether.org"
#define	CLIENT_DEFAULT_KEEPALIVE_PORT		80
#define	CLIENT_DEFAULT_KEEPALIVE_INTERVAL	KEEP_INTERVAL_DEFAULT

#define	CLIENT_RPC_MODE_NOTIFY				0
#define	CLIENT_RPC_MODE_MANAGEMENT			1
#define	CLIENT_RPC_MODE_SHORTCUT			2
#define	CLIENT_RPC_MODE_SHORTCUT_DISCONNECT	3

#define	CLIENT_MACOS_TAP_NAME				"tap0"

#define	CLIENT_SAVER_INTERVAL				(30 * 1000)

#define	CLIENT_NOTIFY_SERVICE_INSTANCENAME	GC_SW_SOFTETHER_PREFIX "vpnclient_uihelper"

#define	CLIENT_WIN32_EXE_FILENAME			"vpnclient.exe"

#define CLIENT_CUSTOM_INI_FILENAME			"$custom.ini"

#define	CLIENT_GLOBAL_PULSE_NAME			"clientglobalpulse"

#define	CLIENT_WIN32_REGKEYNAME				"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Client"
#define	CLIENT_WIN32_REGVALUE_PORT			"RpcPort"
#define	CLIENT_WIN32_REGVALUE_PID			"RpcPid"


// List of virtual LAN cards in UNIX
struct UNIX_VLAN
{
	bool Enabled;							// Enable flag
	char Name[MAX_SIZE];					// Name
	UCHAR MacAddress[6];					// MAC address
	UCHAR Padding[2];
};

// Account
struct ACCOUNT
{
	// Static data
	CLIENT_OPTION *ClientOption;			// Client Option
	CLIENT_AUTH *ClientAuth;				// Client authentication data
	bool CheckServerCert;					// Check the server certificate
	bool RetryOnServerCert;					// Retry on invalid server certificate
	X *ServerCert;							// Server certificate
	bool StartupAccount;					// Start-up account
	UCHAR ShortcutKey[SHA1_SIZE];			// Key
	UINT64 CreateDateTime;					// Creation date and time
	UINT64 UpdateDateTime;					// Updating date
	UINT64 LastConnectDateTime;				// Last connection date and time

	// Dynamic data
	LOCK *lock;								// Lock
	SESSION *ClientSession;					// Client session
	CLIENT_STATUS_PRINTER *StatusPrinter;	// Status indicator

	SOCK *StatusWindow;						// Status window
};

// Client Settings
struct CLIENT_CONFIG
{
	bool AllowRemoteConfig;					// Allow the remote configuration
	bool UseKeepConnect;					// Keep connected to the Internet
	char KeepConnectHost[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT KeepConnectPort;					// Port number
	UINT KeepConnectProtocol;				// Protocol
	UINT KeepConnectInterval;				// Interval
	bool NoChangeWcmNetworkSettingOnWindows8;	// Don't change the WCM network settings on Windows 8
};

// Version acquisition
struct RPC_CLIENT_VERSION
{
	char ClientProductName[128];		// Client product name
	char ClientVersionString[128];		// Client version string
	char ClientBuildInfoString[128];	// Build client information string
	UINT ClientVerInt;					// Client version integer value
	UINT ClientBuildInt;				// Client build number integer value
	UINT ProcessId;						// Process ID
	UINT OsType;						// OS type
	bool IsVLanNameRegulated;			// Whether a virtual LAN card name must be "VLAN" + number
	bool IsVgcSupported;				// Whether the VPN Gate Client is supported
	bool ShowVgcLink;					// Display a VPN Gate Client link
	char ClientId[128];					// Client OD
};

// Password Setting
struct RPC_CLIENT_PASSWORD
{
	char Password[MAX_PASSWORD_LEN + 1];	// Password
	bool PasswordRemoteOnly;				// The password is required only remote access
};

// Get the password setting
struct RPC_CLIENT_PASSWORD_SETTING
{
	bool IsPasswordPresented;				// Password exists
	bool PasswordRemoteOnly;				// The password is required only remote access
};

// Certificate enumeration item
struct RPC_CLIENT_ENUM_CA_ITEM
{
	UINT Key;								// Certificate key
	wchar_t SubjectName[MAX_SIZE];			// Issued to
	wchar_t IssuerName[MAX_SIZE];			// Issuer
	UINT64 Expires;							// Expiration date
};

// Certificate enumeration
struct RPC_CLIENT_ENUM_CA
{
	UINT NumItem;							// Number of items
	RPC_CLIENT_ENUM_CA_ITEM **Items;		// Item
};

// Certificate item
struct RPC_CERT
{
	X *x;									// Certificate
};

// Delete the certificate
struct RPC_CLIENT_DELETE_CA
{
	UINT Key;								// Certificate key
};

// Get the certificate
struct RPC_GET_CA
{
	UINT Key;								// Certificate key
	X *x;									// Certificate
};

// Get the issuer
struct RPC_GET_ISSUER
{
	X *x;									// Certificate
	X *issuer_x;							// Issuer
};

// Secure device enumeration item
struct RPC_CLIENT_ENUM_SECURE_ITEM
{
	UINT DeviceId;							// Device ID
	UINT Type;								// Type
	char DeviceName[MAX_SIZE];				// Device name
	char Manufacturer[MAX_SIZE];			// Manufacturer
};

// Enumeration of secure devices
struct RPC_CLIENT_ENUM_SECURE
{
	UINT NumItem;							// Number of items
	RPC_CLIENT_ENUM_SECURE_ITEM **Items;	// Item
};

// Specify a secure device
struct RPC_USE_SECURE
{
	UINT DeviceId;							// Device ID
};

// Enumerate objects in the secure device
struct RPC_ENUM_OBJECT_IN_SECURE
{
	UINT hWnd;								// Window handle
	UINT NumItem;							// Number of items
	char **ItemName;						// Item name
	bool *ItemType;							// Type (true = secret key, false = public key)
};

// Create a virtual LAN
struct RPC_CLIENT_CREATE_VLAN
{
	char DeviceName[MAX_SIZE];				// Device name
};

// Get a Virtual LAN information
struct RPC_CLIENT_GET_VLAN
{
	char DeviceName[MAX_SIZE];				// Device name
	bool Enabled;							// Flag of whether it works or not
	char MacAddress[MAX_SIZE];				// MAC address
	char Version[MAX_SIZE];					// Version
	char FileName[MAX_SIZE];				// Driver file name
	char Guid[MAX_SIZE];					// GUID
};

// Set the virtual LAN information
struct RPC_CLIENT_SET_VLAN
{
	char DeviceName[MAX_SIZE];				// Device name
	char MacAddress[MAX_SIZE];				// MAC address
};

// Virtual LAN enumeration item
struct RPC_CLIENT_ENUM_VLAN_ITEM
{
	char DeviceName[MAX_SIZE];				// Device name
	bool Enabled;							// Operation flag
	char MacAddress[MAX_SIZE];				// MAC address
	char Version[MAX_SIZE];					// Version
};

// Enumerate the virtual LANs
struct RPC_CLIENT_ENUM_VLAN
{
	UINT NumItem;							// Item count
	RPC_CLIENT_ENUM_VLAN_ITEM **Items;		// Item
};

// Create an account
struct RPC_CLIENT_CREATE_ACCOUNT
{
	CLIENT_OPTION *ClientOption;			// Client Option
	CLIENT_AUTH *ClientAuth;				// Client authentication data
	bool StartupAccount;					// Startup account
	bool CheckServerCert;					// Checking of the server certificate
	bool RetryOnServerCert;					// Retry on invalid server certificate
	X *ServerCert;							// Server certificate
	UCHAR ShortcutKey[SHA1_SIZE];			// Shortcut Key
};

// Enumeration item of account
struct RPC_CLIENT_ENUM_ACCOUNT_ITEM
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	char UserName[MAX_USERNAME_LEN + 1];	//  User name
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	char DeviceName[MAX_DEVICE_NAME_LEN + 1];	// Device name
	UINT ProxyType;							// Type of proxy connection
	char ProxyName[MAX_HOST_NAME_LEN + 1];	// Host name
	bool Active;							// Operation flag
	bool Connected;							// Connection completion flag
	bool StartupAccount;					// Startup account
	UINT Port;								// Port number (Ver 3.0 or later)
	char HubName[MAX_HUBNAME_LEN + 1];		// Virtual HUB name (Ver 3.0 or later)
	UINT64 CreateDateTime;					// Creation date and time (Ver 3.0 or later)
	UINT64 UpdateDateTime;					// Modified date (Ver 3.0 or later)
	UINT64 LastConnectDateTime;				// Last connection date and time (Ver 3.0 or later)
	UINT tmp1;								// Temporary data
};

// Enumeration of accounts
struct RPC_CLIENT_ENUM_ACCOUNT
{
	UINT NumItem;							// Item count
	RPC_CLIENT_ENUM_ACCOUNT_ITEM **Items;	// Items
};

// Delete the Account
struct RPC_CLIENT_DELETE_ACCOUNT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
};

// Change the account name
struct RPC_RENAME_ACCOUNT
{
	wchar_t OldName[MAX_ACCOUNT_NAME_LEN + 1];		// Old name
	wchar_t NewName[MAX_ACCOUNT_NAME_LEN + 1];		// New Name
};

// Get the account
struct RPC_CLIENT_GET_ACCOUNT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	CLIENT_OPTION *ClientOption;			// Client Option
	CLIENT_AUTH *ClientAuth;				// Client authentication data
	bool StartupAccount;					// Startup account
	bool CheckServerCert;					// Check the server certificate
	bool RetryOnServerCert;					// Retry on invalid server certificate
	X *ServerCert;							// Server certificate
	UCHAR ShortcutKey[SHA1_SIZE];			// Shortcut Key
	UINT64 CreateDateTime;					// Creation date and time (Ver 3.0 or later)
	UINT64 UpdateDateTime;					// Modified date (Ver 3.0 or later)
	UINT64 LastConnectDateTime;				// Last connection date and time (Ver 3.0 or later)
};

// Connection
struct RPC_CLIENT_CONNECT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
};

// Get the Connection status
struct RPC_CLIENT_GET_CONNECTION_STATUS
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	bool Active;							// Operation flag
	bool Connected;							// Connected flag
	UINT SessionStatus;						// Session status
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT ServerPort;						// Port number of the server
	char ServerProductName[MAX_SIZE];		// Server product name
	UINT ServerProductVer;					// Server product version
	UINT ServerProductBuild;				// Server product build number
	X *ServerX;								// Server certificate
	X *ClientX;								// Client certificate
	UINT64 StartTime;						// Connection start time
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	UINT64 FirstConnectionEstablisiedTime;	// Connection completion time of the first connection
	UINT64 CurrentConnectionEstablishTime;	// Connection completion time of this connection
	UINT NumConnectionsEstablished;			// Number of connections have been established so far
	bool HalfConnection;					// Half-connection
	bool QoS;								// VoIP / QoS
	UINT MaxTcpConnections;					// Maximum number of the TCP connections
	UINT NumTcpConnections;					// Number of current TCP connections
	UINT NumTcpConnectionsUpload;			// Number of inbound connections
	UINT NumTcpConnectionsDownload;			// Number of outbound connections
	bool UseEncrypt;						// Use of encryption
	char CipherName[32];					// Cipher algorithm name
	char ProtocolName[64];					// Protocol name
	bool UseCompress;						// Use of compression
	bool IsRUDPSession;						// R-UDP session
	char UnderlayProtocol[64];				// Physical communication protocol
	char ProtocolDetails[256];				// Protocol details
	bool IsUdpAccelerationEnabled;			// The UDP acceleration is enabled
	bool IsUsingUdpAcceleration;			// Using the UDP acceleration function
	char SessionName[MAX_SESSION_NAME_LEN + 1];	// Session name
	char ConnectionName[MAX_CONNECTION_NAME_LEN + 1];	// Connection name
	UCHAR SessionKey[SHA1_SIZE];			// Session key
	POLICY Policy;							// Policy
	UINT64 TotalSendSize;					// Total transmitted data size
	UINT64 TotalRecvSize;					// Total received data size
	UINT64 TotalSendSizeReal;				// Total transmitted data size (no compression)
	UINT64 TotalRecvSizeReal;				// Total received data size (no compression)
	TRAFFIC Traffic;						// Traffic data
	bool IsBridgeMode;						// Bridge Mode
	bool IsMonitorMode;						// Monitor mode
	UINT VLanId;							// VLAN ID
};


// RPC connection
struct CLIENT_RPC_CONNECTION
{
	struct CLIENT *Client;					// Client
	bool RpcMode;							// True: RPC mode, false: notification mode
	THREAD *Thread;							// Processing thread
	SOCK *Sock;								// Socket
};

// Client object
struct CLIENT
{
	LOCK *lock;								// Lock
	LOCK *lockForConnect;					// Lock to be used in the CtConnect
	REF *ref;								// Reference counter
	CEDAR *Cedar;							// Cedar
	volatile bool Halt;						// Halting flag
	UINT Err;								// Error code
	CFG_RW *CfgRw;							// Configuration file R/W
	LIST *AccountList;						// Account list
	UCHAR EncryptedPassword[SHA1_SIZE];		// Password
	bool PasswordRemoteOnly;				// Password is required only remote access
	UINT UseSecureDeviceId;					// Secure device ID to be used
	CLIENT_CONFIG Config;					// Client Settings
	LIST *RpcConnectionList;				// RPC connection list
	SOCK *RpcListener;						// RPC listener
	THREAD *RpcThread;						// RPC thread
	LOCK *HelperLock;						// Auxiliary lock
	THREAD *SaverThread;					// Saver thread
	EVENT *SaverHalter;						// The event to stop the Saver thread
	LIST *NotifyCancelList;					// Notification event list
	KEEP *Keep;								// Keep Connection
	LIST *UnixVLanList;						// List of virtual LAN cards in UNIX
	LOG *Logger;							// Logger
	bool DontSavePassword;					// Flag for not to save the password
	ERASER *Eraser;							// Eraser
	SOCKLIST *SockList;						// Socket list
	CM_SETTING *CmSetting;					// CM configuration
	void *GlobalPulse;						// Global pulse
	THREAD *PulseRecvThread;				// Pulse reception thread
	volatile bool HaltPulseThread;			// Stop flag for the pulse reception thread
	bool NoSaveLog;							// Do not save the log
	bool NoSaveConfig;						// Do not save the settings
	INTERNET_SETTING CommonProxySetting;	// Common proxy settings
	void *MsSuspendHandler;					// MS suspend handler

};

// Notification to the remote client
struct RPC_CLIENT_NOTIFY
{
	UINT NotifyCode;						// Code
};

// Type of notification
#define	CLIENT_NOTIFY_ACCOUNT_CHANGED	1	// Account change notification
#define	CLIENT_NOTIFY_VLAN_CHANGED		2	// Virtual LAN card change notification

// Remote client
struct REMOTE_CLIENT
{
	RPC *Rpc;
	UINT OsType;
	bool Unix;
	bool Win9x;
	UINT ProcessId;
	UINT ClientBuildInt;
	bool IsVgcSupported;
	bool ShowVgcLink;
	char ClientId[128];
};

// Notification client
struct NOTIFY_CLIENT
{
	SOCK *Sock;
};

// CM configuration
struct CM_SETTING
{
	bool EasyMode;							// Simple mode
	bool LockMode;							// Setting lock mode
	UCHAR HashedPassword[SHA1_SIZE];		// Password
};




// Function prototype
REMOTE_CLIENT *CcConnectRpc(char *server_name, char *password, bool *bad_pass, bool *no_remote, UINT wait_retry);
REMOTE_CLIENT *CcConnectRpcEx(char *server_name, char *password, bool *bad_pass, bool *no_remote, UCHAR *key, UINT *key_error_code, bool shortcut_disconnect, UINT wait_retry);
UINT CcShortcut(UCHAR *key);
UINT CcShortcutDisconnect(UCHAR *key);
void CcDisconnectRpc(REMOTE_CLIENT *rc);
NOTIFY_CLIENT *CcConnectNotify(REMOTE_CLIENT *rc);
void CcDisconnectNotify(NOTIFY_CLIENT *n);
void CcStopNotify(NOTIFY_CLIENT *n);
bool CcWaitNotify(NOTIFY_CLIENT *n);
UINT CcGetClientVersion(REMOTE_CLIENT *r, RPC_CLIENT_VERSION *a);
UINT CcSetCmSetting(REMOTE_CLIENT *r, CM_SETTING *a);
UINT CcGetCmSetting(REMOTE_CLIENT *r, CM_SETTING *a);
UINT CcSetPassword(REMOTE_CLIENT *r, RPC_CLIENT_PASSWORD *pass);
UINT CcGetPasswordSetting(REMOTE_CLIENT *r, RPC_CLIENT_PASSWORD_SETTING *a);
UINT CcEnumCa(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_CA *e);
UINT CcAddCa(REMOTE_CLIENT *r, RPC_CERT *cert);
UINT CcDeleteCa(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_CA *p);
UINT CcGetCa(REMOTE_CLIENT *r, RPC_GET_CA *get);
UINT CcEnumSecure(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_SECURE *e);
UINT CcUseSecure(REMOTE_CLIENT *r, RPC_USE_SECURE *sec);
UINT CcGetUseSecure(REMOTE_CLIENT *r, RPC_USE_SECURE *sec);
UINT CcCreateVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *create);
UINT CcUpgradeVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *create);
UINT CcGetVLan(REMOTE_CLIENT *r, RPC_CLIENT_GET_VLAN *get);
UINT CcSetVLan(REMOTE_CLIENT *r, RPC_CLIENT_SET_VLAN *set);
UINT CcEnumVLan(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_VLAN *e);
UINT CcDeleteVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *d);
UINT CcEnableVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *vlan);
UINT CcDisableVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *vlan);
UINT CcCreateAccount(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_ACCOUNT *a);
UINT CcEnumAccount(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_ACCOUNT *e);
UINT CcDeleteAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a);
UINT CcSetAccount(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_ACCOUNT *a);
UINT CcGetAccount(REMOTE_CLIENT *r, RPC_CLIENT_GET_ACCOUNT *a);
UINT CcRenameAccount(REMOTE_CLIENT *r, RPC_RENAME_ACCOUNT *rename);
UINT CcSetClientConfig(REMOTE_CLIENT *r, CLIENT_CONFIG *o);
UINT CcGetClientConfig(REMOTE_CLIENT *r, CLIENT_CONFIG *o);
UINT CcConnect(REMOTE_CLIENT *r, RPC_CLIENT_CONNECT *connect);
UINT CcDisconnect(REMOTE_CLIENT *r, RPC_CLIENT_CONNECT *connect);
UINT CcGetAccountStatus(REMOTE_CLIENT *r, RPC_CLIENT_GET_CONNECTION_STATUS *st);
UINT CcSetStartupAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a);
UINT CcRemoveStartupAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a);
UINT CcGetIssuer(REMOTE_CLIENT *r, RPC_GET_ISSUER *a);


void CcSetServiceToForegroundProcess(REMOTE_CLIENT *r);
char *CiGetFirstVLan(CLIENT *c);
void CiNormalizeAccountVLan(CLIENT *c);

void CnStart();
void CnListenerProc(THREAD *thread, void *param);

void CnReleaseSocket(SOCK *s, PACK *p);

void CnStatusPrinter(SOCK *s, PACK *p);
void Win32CnStatusPrinter(SOCK *s, PACK *p);

void CnConnectErrorDlg(SOCK *s, PACK *p);
void Win32CnConnectErrorDlg(SOCK *s, PACK *p);
void Win32CnConnectErrorDlgThreadProc(THREAD *thread, void *param);

void CnPasswordDlg(SOCK *s, PACK *p);
void Win32CnPasswordDlg(SOCK *s, PACK *p);
void Win32CnPasswordDlgThreadProc(THREAD *thread, void *param);

void CnMsgDlg(SOCK *s, PACK *p);
void Win32CnMsgDlg(SOCK *s, PACK *p);
void Win32CnMsgDlgThreadProc(THREAD *thread, void *param);

void CnNicInfo(SOCK *s, PACK *p);
void Win32CnNicInfo(SOCK *s, PACK *p);
void Win32CnNicInfoThreadProc(THREAD *thread, void *param);

void CnCheckCert(SOCK *s, PACK *p);
void Win32CnCheckCert(SOCK *s, PACK *p);
void Win32CnCheckCertThreadProc(THREAD *thread, void *param);

void CnExecDriverInstaller(SOCK *s, PACK *p);
void Win32CnExecDriverInstaller(SOCK *s, PACK *p);

bool CnCheckAlreadyExists(bool lock);
bool CnIsCnServiceReady();
void CnWaitForCnServiceReady();

void CnSecureSign(SOCK *s, PACK *p);

SOCK *CncConnect();
SOCK *CncConnectEx(UINT timeout);
void CncReleaseSocket();
void CncExit();
bool CncExecDriverInstaller(char *arg);
SOCK *CncStatusPrinterWindowStart(SESSION *s);
void CncStatusPrinterWindowPrint(SOCK *s, wchar_t *str);
void CncStatusPrinterWindowStop(SOCK *s);
void CncStatusPrinterWindowThreadProc(THREAD *thread, void *param);
bool CncConnectErrorDlg(SESSION *session, UI_CONNECTERROR_DLG *dlg);
void CncConnectErrorDlgHaltThread(THREAD *thread, void *param);
bool CncPasswordDlg(SESSION *session, UI_PASSWORD_DLG *dlg);
void CncCheckCert(SESSION *session, UI_CHECKCERT *dlg);
void CncCheckCertHaltThread(THREAD *thread, void *param);
bool CncSecureSignDlg(SECURE_SIGN *sign);
SOCK *CncMsgDlg(UI_MSG_DLG *dlg);
void CndMsgDlgFree(SOCK *s);
SOCK *CncNicInfo(UI_NICINFO *info);
void CncNicInfoFree(SOCK *s);

void CtStartClient();
void CtStopClient();
void CtReleaseClient(CLIENT *c);
bool CtGetClientVersion(CLIENT *c, RPC_CLIENT_VERSION *ver);
bool CtGetCmSetting(CLIENT *c, CM_SETTING *s);
bool CtSetCmSetting(CLIENT *c, CM_SETTING *s);
bool CtSetPassword(CLIENT *c, RPC_CLIENT_PASSWORD *pass);
bool CtGetPasswordSetting(CLIENT *c, RPC_CLIENT_PASSWORD_SETTING *a);
bool CtEnumCa(CLIENT *c, RPC_CLIENT_ENUM_CA *e);
bool CtAddCa(CLIENT *c, RPC_CERT *cert);
bool CtDeleteCa(CLIENT *c, RPC_CLIENT_DELETE_CA *p);
bool CtGetCa(CLIENT *c, RPC_GET_CA *get);
bool CtEnumSecure(CLIENT *c, RPC_CLIENT_ENUM_SECURE *e);
bool CtUseSecure(CLIENT *c, RPC_USE_SECURE *sec);
bool CtGetUseSecure(CLIENT *c, RPC_USE_SECURE *sec);
bool CtEnumObjectInSecure(CLIENT *c, RPC_ENUM_OBJECT_IN_SECURE *e);
bool CtCreateVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *create);
bool CtUpgradeVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *create);
bool CtGetVLan(CLIENT *c, RPC_CLIENT_GET_VLAN *get);
bool CtSetVLan(CLIENT *c, RPC_CLIENT_SET_VLAN *set);
bool CtEnumVLan(CLIENT *c, RPC_CLIENT_ENUM_VLAN *e);
bool CtDeleteVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *d);
bool CtEnableVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *vlan);
bool CtDisableVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *vlan);
bool CtCreateAccount(CLIENT *c, RPC_CLIENT_CREATE_ACCOUNT *a, bool inner);
bool CtEnumAccount(CLIENT *c, RPC_CLIENT_ENUM_ACCOUNT *e);
bool CtDeleteAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a, bool inner);
bool CtSetAccount(CLIENT *c, RPC_CLIENT_CREATE_ACCOUNT *a, bool inner);
bool CtGetAccount(CLIENT *c, RPC_CLIENT_GET_ACCOUNT *a);
bool CtRenameAccount(CLIENT *c, RPC_RENAME_ACCOUNT *rename, bool inner);
bool CtSetClientConfig(CLIENT *c, CLIENT_CONFIG *o);
bool CtGetClientConfig(CLIENT *c, CLIENT_CONFIG *o);
bool CtConnect(CLIENT *c, RPC_CLIENT_CONNECT *connect);
bool CtDisconnect(CLIENT *c, RPC_CLIENT_CONNECT *connect, bool inner);
bool CtGetAccountStatus(CLIENT *c, RPC_CLIENT_GET_CONNECTION_STATUS *st);
bool CtSetStartupAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a, bool inner);
bool CtRemoveStartupAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a);
bool CtGetIssuer(CLIENT *c, RPC_GET_ISSUER *a);
bool CtGetCommonProxySetting(CLIENT *c, INTERNET_SETTING *a);
bool CtSetCommonProxySetting(CLIENT *c, INTERNET_SETTING *a);


// Internal function prototype
void CiSendGlobalPulse(CLIENT *c);
void CiPulseRecvThread(THREAD *thread, void *param);
void CiServerThread(THREAD *t, void *param);
void CiInitSaver(CLIENT *c);
void CiFreeSaver(CLIENT *c);
void CiGetSessionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st, SESSION *s);
PACK *CiRpcDispatch(RPC *rpc, char *name, PACK *p);
void CiRpcAccepted(CLIENT *c, SOCK *s);
void CiNotifyMain(CLIENT *c, SOCK *s);
void CiRpcAcceptThread(THREAD *thread, void *param);
void CiRpcServerThread(THREAD *thread, void *param);
void CiStartRpcServer(CLIENT *c);
void CiStopRpcServer(CLIENT *c);
CLIENT_OPTION *CiLoadClientOption(FOLDER *f);
CLIENT_AUTH *CiLoadClientAuth(FOLDER *f);
ACCOUNT *CiLoadClientAccount(FOLDER *f);
void CiLoadClientConfig(CLIENT_CONFIG *c, FOLDER *f);
void CiLoadAccountDatabase(CLIENT *c, FOLDER *f);
void CiLoadCAList(CLIENT *c, FOLDER *f);
void CiLoadCACert(CLIENT *c, FOLDER *f);
void CiLoadVLanList(CLIENT *c, FOLDER *f);
void CiLoadVLan(CLIENT *c, FOLDER *f);
bool CiReadSettingFromCfg(CLIENT *c, FOLDER *root);
void CiWriteAccountDatabase(CLIENT *c, FOLDER *f);
void CiWriteAccountData(FOLDER *f, ACCOUNT *a);
void CiWriteClientOption(FOLDER *f, CLIENT_OPTION *o);
void CiWriteClientAuth(FOLDER *f, CLIENT_AUTH *a);
void CiWriteClientConfig(FOLDER *cc, CLIENT_CONFIG *config);
void CiWriteSettingToCfg(CLIENT *c, FOLDER *root);
void CiWriteCAList(CLIENT *c, FOLDER *f);
void CiWriteCACert(CLIENT *c, FOLDER *f, X *x);
void CiWriteVLanList(CLIENT *c, FOLDER *f);
void CiWriteVLan(CLIENT *c, FOLDER *f, UNIX_VLAN *v);
void CiFreeClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st);
bool CiCheckCertProc(SESSION *s, CONNECTION *c, X *server_x, bool *expired);
bool CiSecureSignProc(SESSION *s, CONNECTION *c, SECURE_SIGN *sign);
bool Win32CiSecureSign(SECURE_SIGN *sign);
void CiFreeClientAuth(CLIENT_AUTH *auth);
void CiFreeClientCreateAccount(RPC_CLIENT_CREATE_ACCOUNT *a);
void CiFreeClientGetAccount(RPC_CLIENT_GET_ACCOUNT *a);
void CiFreeClientEnumVLan(RPC_CLIENT_ENUM_VLAN *e);
void CiFreeClientEnumSecure(RPC_CLIENT_ENUM_SECURE *e);
void CiFreeClientEnumCa(RPC_CLIENT_ENUM_CA *e);
void CiFreeEnumObjectInSecure(RPC_ENUM_OBJECT_IN_SECURE *a);
void CiFreeGetCa(RPC_GET_CA *a);
void CiFreeGetIssuer(RPC_GET_ISSUER *a);
void CiFreeClientEnumAccount(RPC_CLIENT_ENUM_ACCOUNT *a);
void CiSetError(CLIENT *c, UINT err);
void CiCheckOs();
CLIENT *CiNewClient();
void CiCleanupClient(CLIENT *c);
bool CiLoadConfigurationFile(CLIENT *c);
void CiSaveConfigurationFile(CLIENT *c);
void CiInitConfiguration(CLIENT *c);
void CiSetVLanToDefault(CLIENT *c);
bool CiIsVLan(CLIENT *c, char *name);
void CiFreeConfiguration(CLIENT *c);
int CiCompareAccount(void *p1, void *p2);
void CiFreeAccount(ACCOUNT *a);
void CiNotify(CLIENT *c);
void CiNotifyInternal(CLIENT *c);
void CiClientStatusPrinter(SESSION *s, wchar_t *status);
void CiInitKeep(CLIENT *c);
void CiFreeKeep(CLIENT *c);
int CiCompareUnixVLan(void *p1, void *p2);
BUF *CiAccountToCfg(RPC_CLIENT_CREATE_ACCOUNT *t);
RPC_CLIENT_CREATE_ACCOUNT *CiCfgToAccount(BUF *b);
void CiChangeAllVLanMacAddressIfCleared(CLIENT *c);
void CiChangeAllVLanMacAddress(CLIENT *c);
void CiChangeAllVLanMacAddressIfMachineChanged(CLIENT *c);
bool CiReadLastMachineHash(void *data);
bool CiWriteLastMachineHash(void *data);
void CiGetCurrentMachineHash(void *data);
void CiGetCurrentMachineHashOld(void *data);
void CiGetCurrentMachineHashNew(void *data);
LIST *CiLoadIni();
void CiFreeIni(LIST *o);
void CiLoadIniSettings(CLIENT *c);
bool CiLoadConfigFilePathFromIni(char *path, UINT size);
int CiCompareClientAccountEnumItemByLastConnectDateTime(void *p1, void *p2);
bool CiIsValidVLanRegulatedName(char *name);
void CiGenerateVLanRegulatedName(char *name, UINT size, UINT i);
bool CiGetNextRecommendedVLanName(REMOTE_CLIENT *r, char *name, UINT size);
void CiDisableWcmNetworkMinimize(CLIENT *c);
bool CiTryToParseAccount(BUF *b);
bool CiTryToParseAccountFile(wchar_t *name);
bool CiEraseSensitiveInAccount(BUF *b);
bool CiHasAccountSensitiveInformation(BUF *b);
void CiApplyInnerVPNServerConfig(CLIENT *c);
void CiIncrementNumActiveSessions();
void CiDecrementNumActiveSessions();

BUF *EncryptPassword(char *password);
BUF *EncryptPassword2(char *password);
char *DecryptPassword(BUF *b);
char *DecryptPassword2(BUF *b);

void InRpcGetIssuer(RPC_GET_ISSUER *c, PACK *p);
void OutRpcGetIssuer(PACK *p, RPC_GET_ISSUER *c);
void InRpcClientVersion(RPC_CLIENT_VERSION *ver, PACK *p);
void OutRpcClientVersion(PACK *p, RPC_CLIENT_VERSION *ver);
void InRpcClientPassword(RPC_CLIENT_PASSWORD *pw, PACK *p);
void OutRpcClientPassword(PACK *p, RPC_CLIENT_PASSWORD *pw);
void InRpcClientEnumCa(RPC_CLIENT_ENUM_CA *e, PACK *p);
void OutRpcClientEnumCa(PACK *p, RPC_CLIENT_ENUM_CA *e);
void InRpcCert(RPC_CERT *c, PACK *p);
void OutRpcCert(PACK *p, RPC_CERT *c);
void InRpcClientDeleteCa(RPC_CLIENT_DELETE_CA *c, PACK *p);
void OutRpcClientDeleteCa(PACK *p, RPC_CLIENT_DELETE_CA *c);
void InRpcGetCa(RPC_GET_CA *c, PACK *p);
void OutRpcGetCa(PACK *p, RPC_GET_CA *c);
void InRpcClientEnumSecure(RPC_CLIENT_ENUM_SECURE *e, PACK *p);
void OutRpcClientEnumSecure(PACK *p, RPC_CLIENT_ENUM_SECURE *e);
void InRpcUseSecure(RPC_USE_SECURE *u, PACK *p);
void OutRpcUseSecure(PACK *p, RPC_USE_SECURE *u);
void OutRpcEnumObjectInSecure(PACK *p, RPC_ENUM_OBJECT_IN_SECURE *e);
void InRpcCreateVLan(RPC_CLIENT_CREATE_VLAN *v, PACK *p);
void OutRpcCreateVLan(PACK *p, RPC_CLIENT_CREATE_VLAN *v);
void InRpcClientGetVLan(RPC_CLIENT_GET_VLAN *v, PACK *p);
void OutRpcClientGetVLan(PACK *p, RPC_CLIENT_GET_VLAN *v);
void InRpcClientSetVLan(RPC_CLIENT_SET_VLAN *v, PACK *p);
void OutRpcClientSetVLan(PACK *p, RPC_CLIENT_SET_VLAN *v);
void InRpcClientEnumVLan(RPC_CLIENT_ENUM_VLAN *v, PACK *p);
void OutRpcClientEnumVLan(PACK *p, RPC_CLIENT_ENUM_VLAN *v);
void InRpcClientOption(CLIENT_OPTION *c, PACK *p);
void OutRpcClientOption(PACK *p, CLIENT_OPTION *c);
void InRpcClientAuth(CLIENT_AUTH *c, PACK *p);
void OutRpcClientAuth(PACK *p, CLIENT_AUTH *c);
void InRpcClientCreateAccount(RPC_CLIENT_CREATE_ACCOUNT *c, PACK *p);
void OutRpcClientCreateAccount(PACK *p, RPC_CLIENT_CREATE_ACCOUNT *c);
void InRpcClientEnumAccount(RPC_CLIENT_ENUM_ACCOUNT *e, PACK *p);
void OutRpcClientEnumAccount(PACK *p, RPC_CLIENT_ENUM_ACCOUNT *e);
void InRpcClientDeleteAccount(RPC_CLIENT_DELETE_ACCOUNT *a, PACK *p);
void OutRpcClientDeleteAccount(PACK *p, RPC_CLIENT_DELETE_ACCOUNT *a);
void InRpcRenameAccount(RPC_RENAME_ACCOUNT *a, PACK *p);
void OutRpcRenameAccount(PACK *p, RPC_RENAME_ACCOUNT *a);
void InRpcClientGetAccount(RPC_CLIENT_GET_ACCOUNT *c, PACK *p);
void OutRpcClientGetAccount(PACK *p, RPC_CLIENT_GET_ACCOUNT *c);
void InRpcClientConnect(RPC_CLIENT_CONNECT *c, PACK *p);
void OutRpcClientConnect(PACK *p, RPC_CLIENT_CONNECT *c);
void InRpcPolicy(POLICY *o, PACK *p);
void OutRpcPolicy(PACK *p, POLICY *o);
void InRpcClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *s, PACK *p);
void OutRpcClientGetConnectionStatus(PACK *p, RPC_CLIENT_GET_CONNECTION_STATUS *c);
void InRpcClientConfig(CLIENT_CONFIG *c, PACK *p);
void OutRpcClientConfig(PACK *p, CLIENT_CONFIG *c);
void InRpcClientPasswordSetting(RPC_CLIENT_PASSWORD_SETTING *a, PACK *p);
void OutRpcClientPasswordSetting(PACK *p, RPC_CLIENT_PASSWORD_SETTING *a);
void InRpcTraffic(TRAFFIC *t, PACK *p);
void OutRpcTraffic(PACK *p, TRAFFIC *t);
void InRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i);
void OutRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i, UINT num);
void OutRpcCmSetting(PACK *p, CM_SETTING *c);
void InRpcCmSetting(CM_SETTING *c, PACK *p);


#ifdef	OS_WIN32
void CiInitDriverVerStruct(MS_DRIVER_VER *ver);
#endif	// OS_EIN32

#endif	// CLIENT_H


