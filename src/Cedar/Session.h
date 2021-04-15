// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Session.h
// Header of Session.c

#ifndef	SESSION_H
#define	SESSION_H

#include "Cedar.h"

// Interval to increment the number of logins after the connection
#define	NUM_LOGIN_INCREMENT_INTERVAL		(30 * 1000)

// Packet adapter function
typedef bool (PA_INIT)(SESSION *s);
typedef CANCEL *(PA_GETCANCEL)(SESSION *s);
typedef UINT (PA_GETNEXTPACKET)(SESSION *s, void **data);
typedef bool (PA_PUTPACKET)(SESSION *s, void *data, UINT size);
typedef void (PA_FREE)(SESSION *s);

// Client related function
typedef void (CLIENT_STATUS_PRINTER)(SESSION *s, wchar_t *status);

// Node information
struct NODE_INFO
{
	char ClientProductName[64];		// Client product name
	UINT ClientProductVer;			// Client version
	UINT ClientProductBuild;		// Client build number
	char ServerProductName[64];		// Server product name
	UINT ServerProductVer;			// Server version
	UINT ServerProductBuild;		// Server build number
	char ClientOsName[64];			// Client OS name
	char ClientOsVer[128];			// Client OS version
	char ClientOsProductId[64];		// Client OS Product ID
	char ClientHostname[64];		// Client host name
	UINT ClientIpAddress;			// Client IP address
	UINT ClientPort;				// Client port number
	char ServerHostname[64];		// Server host name
	UINT ServerIpAddress;			// Server IP address
	UINT ServerPort;				// Server port number
	char ProxyHostname[64];			// Proxy host name
	UINT ProxyIpAddress;			// Proxy Server IP Address
	UINT ProxyPort;					// Proxy port number
	char HubName[64];				// HUB name
	UCHAR UniqueId[16];				// Unique ID
	// The following is for IPv6 support
	UCHAR ClientIpAddress6[16];		// Client IPv6 address
	UCHAR ServerIpAddress6[16];		// Server IP address
	UCHAR ProxyIpAddress6[16];		// Proxy Server IP Address
	char Padding[304 - (16 * 3)];	// Padding
};

// Packet adapter
struct PACKET_ADAPTER
{
	PA_INIT *Init;
	PA_GETCANCEL *GetCancel;
	PA_GETNEXTPACKET *GetNextPacket;
	PA_PUTPACKET *PutPacket;
	PA_FREE *Free;
	void *Param;
	UINT Id;
};

// Packet Adapter IDs
#define	PACKET_ADAPTER_ID_VLAN_WIN32		1


// Session structure
struct SESSION
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	CEDAR *Cedar;					// Cedar
	bool LocalHostSession;			// Local host session
	bool ServerMode;				// Server mode session
	bool NormalClient;				// Connecting session from a regular client (not such as localbridge)
	bool LinkModeClient;			// Link mode client
	bool LinkModeServer;			// Link mode server
	bool SecureNATMode;				// SecureNAT session
	bool BridgeMode;				// Bridge session
	bool BridgeIsEthLoopbackBlock;	// Loopback is disabled on the Ethernet level
	bool VirtualHost;				// Virtual host mode
	bool L3SwitchMode;				// Layer-3 switch mode
	bool InProcMode;				// In-process mode
	THREAD *Thread;					// Management thread
	CONNECTION *Connection;			// Connection
	char ClientIP[64];				// Client IP
	CLIENT_OPTION *ClientOption;	// Client connection options
	CLIENT_AUTH *ClientAuth;		// Client authentication data
	volatile bool Halt;				// Halting flag
	volatile bool CancelConnect;	// Cancel the connection
	EVENT *HaltEvent;				// Halting event
	UINT Err;						// Error value
	HUB *Hub;						// HUB
	CANCEL *Cancel1;				// Cancel object 1
	CANCEL *Cancel2;				// Cancel object 2
	PACKET_ADAPTER *PacketAdapter;	// Packet adapter
	UCHAR UdpSendKey[16];			// UDP encryption key for transmission
	UCHAR UdpRecvKey[16];			// UDP encryption key for reception
	UINT ClientStatus;				// Client Status
	bool RetryFlag;					// Retry flag (client)
	bool ForceStopFlag;				// Forced stop flag (client)
	UINT CurrentRetryCount;			// Current retry counter (client)
	UINT RetryInterval;				// Retry interval (client)
	bool ConnectSucceed;			// Connection success flag (client)
	bool SessionTimeOuted;			// Session times out
	UINT Timeout;					// Time-out period
	UINT64 NextConnectionTime;		// Time to put next additional connection
	IP ServerIP;					// IP address of the server
	bool ClientModeAndUseVLan;		// Use a virtual LAN card in client mode
	LOCK *TrafficLock;				// Traffic data lock
	LINK *Link;						// A reference to the link object
	SNAT *SecureNAT;				// A reference to the SecureNAT object
	BRIDGE *Bridge;					// A reference to the Bridge object
	NODE_INFO NodeInfo;				// Node information
	UINT64 LastIncrementTraffic;	// Last time that updated the traffic data of the user
	bool AdministratorMode;			// Administrator mode
	LIST *CancelList;				// Cancellation list
	L3IF *L3If;						// Layer-3 interface
	IP DefaultDns;					// IP address of the default DNS server
	bool IPv6Session;				// IPv6 session (Physical communication is IPv6)
	UINT VLanId;					// VLAN ID
	UINT UniqueId;					// Unique ID
	UCHAR IpcMacAddress[6];			// MAC address for IPC
	UCHAR Padding[2];

	IP ServerIP_CacheForNextConnect;	// Server IP, cached for next connect

	UINT64 CreatedTime;				// Creation date and time
	UINT64 LastCommTime;			// Last communication date and time
	UINT64 LastCommTimeForDormant;	// Last communication date and time (for dormant)
	TRAFFIC *Traffic;				// Traffic data
	TRAFFIC *OldTraffic;			// Old traffic data
	UINT64 TotalSendSize;			// Total transmitted data size
	UINT64 TotalRecvSize;			// Total received data size
	UINT64 TotalSendSizeReal;		// Total transmitted data size (no compression)
	UINT64 TotalRecvSizeReal;		// Total received data size (no compression)
	char *Name;						// Session name
	char *Username;					// User name
	char UserNameReal[MAX_USERNAME_LEN + 1];	// User name (real)
	char GroupName[MAX_USERNAME_LEN + 1];	// Group name
	POLICY *Policy;					// Policy
	UCHAR SessionKey[SHA1_SIZE];	// Session key
	UINT SessionKey32;				// 32bit session key
	char SessionKeyStr[64];			// Session key string
	UINT MaxConnection;				// Maximum number of concurrent TCP connections
	bool UseEncrypt;				// Use encrypted communication
	bool UseCompress;				// Use data compression
	bool HalfConnection;			// Half connection mode
	bool QoS;						// VoIP / QoS
	bool NoSendSignature;			// Do not send a signature
	bool IsOpenVPNL3Session;		// Whether OpenVPN L3 session
	bool IsOpenVPNL2Session;		// Whether OpenVPN L2 session
	UINT NumDisconnected;			// Number of socket disconnection
	bool NoReconnectToSession;		// Disable to reconnect to the session
	char UnderlayProtocol[64];		// Physical communication protocol
	char ProtocolDetails[256];		// Protocol details
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	UINT64 FirstConnectionEstablisiedTime;	// Connection completion time of the first connection
	UINT64 CurrentConnectionEstablishTime;	// Completion time of this connection
	UINT NumConnectionsEstablished;	// Number of connections established so far
	UINT AdjustMss;					// MSS adjustment value
	bool IsVPNClientAndVLAN_Win32;	// Is the VPN Client session with a VLAN card (Win32)

	bool IsRUDPSession;				// Whether R-UDP session
	UINT RUdpMss;					// The value of the MSS should be applied while the R-UDP is used
	bool EnableBulkOnRUDP;			// Allow the bulk transfer in the R-UDP session
	UINT BulkOnRUDPVersion;			// RUDP Bulk version
	bool EnableHMacOnBulkOfRUDP;	// Use the HMAC to sign the bulk transfer of R-UDP session
	bool EnableUdpRecovery;			// Enable the R-UDP recovery

	bool UseUdpAcceleration;		// Use of UDP acceleration mode
	UINT UdpAccelerationVersion;	// UDP acceleration version
	bool UseHMacOnUdpAcceleration;	// Use the HMAC in the UDP acceleration mode
	UDP_ACCEL *UdpAccel;			// UDP acceleration
	bool IsUsingUdpAcceleration;	// Flag of whether the UDP acceleration is used
	UINT UdpAccelMss;				// MSS value to be applied while the UDP acceleration is used
	bool UdpAccelFastDisconnectDetect;	// Fast disconnection detection is enabled

	bool IsAzureSession;			// Whether the session via VPN Azure
	IP AzureRealServerGlobalIp;		// Real global IP of the server-side in the case of session via VPN Azure

	ACCOUNT *Account;				// Client account
	UINT VLanDeviceErrorCount;		// Number of times that the error occurred in the virtual LAN card
	bool Win32HideConnectWindow;	// Hide the status window
	bool Win32HideNicInfoWindow;	// Hide the NIC information window
	bool UserCanceled;				// Canceled by the user
	UINT64 LastTryAddConnectTime;	// Last time that attempted to add a connection

	bool IsMonitorMode;				// Whether the monitor mode
	bool IsBridgeMode;				// Whether the bridge mode
	bool UseClientLicense;			// Number of assigned client licenses
	bool UseBridgeLicense;			// Number of assigned bridge licenses

	COUNTER *LoggingRecordCount;	// Counter for the number of logging records

	bool FreeInfoShowed;			// Whether a warning about Free Edition has already displayed

	bool Client_NoSavePassword;		// Prohibit the password saving
	wchar_t *Client_Message;		// Message that has been sent from the server

	LIST *DelayedPacketList;		// Delayed packet list
	UINT Flag1;

	USER *NumLoginIncrementUserObject;	// User objects to increment the number of logins
	HUB *NumLoginIncrementHubObject;	// Virtual HUB object to increment the number of logins
	UINT64 NumLoginIncrementTick;		// Time to perform increment a number of log

	bool FirstTimeHttpRedirect;		// Redirect HTTP only for the first time
	char FirstTimeHttpRedirectUrl[128];	// URL for redirection only the first time
	UINT FirstTimeHttpAccessCheckIp;	// IP address for access checking

	UCHAR BulkSendKey[RUDP_BULK_KEY_SIZE_MAX];	// RUDP Bulk Send Key
	UINT BulkSendKeySize;						// RUDP Bulk Send Key size
	UCHAR BulkRecvKey[RUDP_BULK_KEY_SIZE_MAX];	// RUDP Bulk Recv Key
	UINT BulkRecvKeySize;						// RUDP Bulk Recv Key size

	// To examine the maximum number of allowed logging target packets per minute
	UINT64 MaxLoggedPacketsPerMinuteStartTick;	// Inspection start time
	UINT CurrentNumPackets;				// Current number of packets

	// Measures for D-Link bug
	UINT64 LastDLinkSTPPacketSendTick;	// Last D-Link STP packet transmission time
	UCHAR LastDLinkSTPPacketDataHash[MD5_SIZE];	// Last D-Link STP packet hash

	SHARED_BUFFER *IpcSessionSharedBuffer;	// A shared buffer between IPC and Session
	IPC_SESSION_SHARED_BUFFER_DATA *IpcSessionShared;	// Shared data between IPC and Session
};

// Password dialog
struct UI_PASSWORD_DLG
{
	UINT Type;						// Type of password
	char Username[MAX_USERNAME_LEN + 1];	// User name
	char Password[MAX_PASSWORD_LEN + 1];	// Password
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT RetryIntervalSec;			// Time to retry
	EVENT *CancelEvent;				// Event to cancel the dialog display
	bool ProxyServer;				// The authentication by the proxy server
	UINT64 StartTick;				// Start time
	bool AdminMode;					// Administrative mode
	bool ShowNoSavePassword;		// Whether to display a check box that does not save the password
	bool NoSavePassword;			// Mode that not to save the password
	SOCK *Sock;						// Socket
};

// Message dialog
struct UI_MSG_DLG
{
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	char HubName[MAX_HUBNAME_LEN + 1];	// Virtual HUB name
	wchar_t *Msg;					// Body
	SOCK *Sock;						// Socket
	bool Halt;						// Flag to close
};

// NIC information
struct UI_NICINFO
{
	wchar_t AccountName[MAX_SIZE];	// Connection setting name
	char NicName[MAX_SIZE];			// Virtual NIC name

	SOCK *Sock;						// Socket
	bool Halt;						// Flag to close
	ROUTE_CHANGE *RouteChange;		// Routing table change notification
	UINT CurrentIcon;				// Current icon
	UINT64 CloseAfterTime;			// Close automatically
};

// Connection Error dialog
struct UI_CONNECTERROR_DLG
{
	EVENT *CancelEvent;				// Event to cancel the dialog display
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT Err;						// Error code
	UINT CurrentRetryCount;			// Current retry count
	UINT RetryLimit;				// Limit of the number of retries
	UINT64 StartTick;				// Start time
	UINT RetryIntervalSec;			// Time to retry
	bool HideWindow;				// Hide the window
	SOCK *Sock;						// Socket
};

// Server certificate checking dialog
struct UI_CHECKCERT
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Account name
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	X *x;							// Server certificate
	X *parent_x;					// Parent certificate
	X *old_x;						// Certificate of previous
	bool DiffWarning;				// Display a warning of certificate forgery
	bool Ok;						// Connection permission flag
	bool SaveServerCert;			// Save the server certificate
	SESSION *Session;				// Session
	volatile bool Halt;				// Halting flag
	SOCK *Sock;						// Socket
};


// Function prototype
SESSION *NewClientSessionEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa, struct ACCOUNT *account);
SESSION *NewClientSession(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, PACKET_ADAPTER *pa);
SESSION *NewRpcSession(CEDAR *cedar, CLIENT_OPTION *option);
SESSION *NewRpcSessionEx(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str);
SESSION *NewRpcSessionEx2(CEDAR *cedar, CLIENT_OPTION *option, UINT *err, char *client_str, void *hWnd);
SESSION *NewServerSession(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy);
SESSION *NewServerSessionEx(CEDAR *cedar, CONNECTION *c, HUB *h, char *username, POLICY *policy, bool inproc_mode, UCHAR *ipc_mac_address);
void ClientThread(THREAD *t, void *param);
void ReleaseSession(SESSION *s);
void CleanupSession(SESSION *s);
void StopSession(SESSION *s);
void StopSessionEx(SESSION *s, bool no_wait);
bool SessionConnect(SESSION *s);
bool ClientConnect(CONNECTION *c);
PACKET_ADAPTER *NewPacketAdapter(PA_INIT *init, PA_GETCANCEL *getcancel, PA_GETNEXTPACKET *getnext,
								 PA_PUTPACKET *put, PA_FREE *free);
void FreePacketAdapter(PACKET_ADAPTER *pa);
void SessionMain(SESSION *s);
void NewSessionKey(CEDAR *cedar, UCHAR *session_key, UINT *session_key_32);
SESSION *GetSessionFromKey(CEDAR *cedar, UCHAR *session_key);
bool IsIpcMacAddress(UCHAR *mac);
void ClientAdditionalConnectChance(SESSION *s);
void SessionAdditionalConnect(SESSION *s);
void ClientAdditionalThread(THREAD *t, void *param);
void PrintSessionTotalDataSize(SESSION *s);
void AddTrafficForSession(SESSION *s, TRAFFIC *t);
void IncrementUserTraffic(HUB *hub, char *username, SESSION *s);
void Notify(SESSION *s, UINT code);
void PrintStatus(SESSION *s, wchar_t *str);
LIST *NewCancelList();
void ReleaseCancelList(LIST *o);
void AddCancelList(LIST *o, CANCEL *c);
void CancelList(LIST *o);
bool IsPriorityHighestPacketForQoS(void *data, UINT size);
UINT GetNextDelayedPacketTickDiff(SESSION *s);

UINT PrepareDHCPRequestForStaticIPv4(SESSION *s, BLOCK *b);
void ClearDHCPLeaseRecordForIPv4(SESSION *s, UINT static_ip);

#endif	// SESSION_H



