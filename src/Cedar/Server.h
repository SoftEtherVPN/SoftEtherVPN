// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Server.h
// Header of Server.c

#ifndef	SERVER_H
#define	SERVER_H

// Default ports
#define	SERVER_DEF_PORTS_1				443
#define	SERVER_DEF_PORTS_2				992
#define	SERVER_DEF_PORTS_3				1194
#define	SERVER_DEF_PORTS_4				GC_DEFAULT_PORT

#define	SERVER_DEF_PORTS_INCLIENT_1		995
#define	SERVER_DEF_PORTS_INCLIENT_2		465
#define	SERVER_DEF_PORTS_INCLIENT_3		9008	// for admin (in client)
#define	SERVER_DEF_PORTS_INCLIENT_4		1195

#define	SERVER_DEF_PORTS_INCLIENT_DYN_MIN	1201
#define	SERVER_DEF_PORTS_INCLIENT_DYN_MAX	1999

extern char *SERVER_CONFIG_FILE_NAME;
// This is set to an invalid OpenSSL cipher specification by default.
// The server will default to a list of sane and secure modern ciphers.
#define	SERVER_DEFAULT_CIPHER_NAME		"~DEFAULT~"
#define	SERVER_DEFAULT_CERT_DAYS		(365 * 10)
#define	SERVER_DEFAULT_HUB_NAME			"DEFAULT"
#define	SERVER_DEFAULT_BRIDGE_NAME		"BRIDGE"
#define	SERVER_CONTROL_TCP_TIMEOUT		(60 * 1000)
#define	SERVER_FARM_CONTROL_INTERVAL	(10 * 1000)

#define	SERVER_FILE_SAVE_INTERVAL_DEFAULT	(5 * 60 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_MIN		(5 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_MAX		(3600 * 1000)
#define	SERVER_FILE_SAVE_INTERVAL_USERMODE	(1 * 60 * 1000)

#define	SERVER_LICENSE_VIOLATION_SPAN	(SERVER_FARM_CONTROL_INTERVAL * 2)


#define SERVER_DEADLOCK_CHECK_SPAN		(2 * 60 * 1000)
#define SERVER_DEADLOCK_CHECK_TIMEOUT	(10 * 60 * 1000)


#define	RETRY_CONNECT_TO_CONTROLLER_INTERVAL	(1 * 1000)

#define	MAX_PUBLIC_PORT_NUM				128

#define	MEMBER_SELECTOR_TXT_FILENAME	"$member_selector.config"
#define	MEMBER_SELECTOR_CONNECT_TIMEOUT	2000
#define	MEMBER_SELECTOR_DATA_TIMEOUT	5000

#define FIRM_SERV_RECV_PACK_MAX_SIZE	(100 * 1024 * 1024)

// Virtual HUB list hosted by each farm member
struct HUB_LIST
{
	struct FARM_MEMBER *FarmMember;		// Farm member
	bool DynamicHub;					// Dynamic HUB
	char Name[MAX_HUBNAME_LEN + 1];		// HUB Name
	UINT NumSessions;					// Number of sessions
	UINT NumSessionsClient;				// Number of client sessions
	UINT NumSessionsBridge;				// Number of bridge sessions
	UINT NumMacTables;					// Number of MAC table entries
	UINT NumIpTables;					// Number of IP table entries
};

// Task
struct FARM_TASK
{
	EVENT *CompleteEvent;				// Completion notice
	PACK *Request;						// Request
	PACK *Response;						// Response
	FARM_MEMBER *FarmMember;			// Destination farm member
	char TaskName[MAX_PATH];			// Task name
	char HostName[MAX_PATH];			// Host name
};

// Farm member
struct FARM_MEMBER
{
	CEDAR *Cedar;						// Cedar
	UINT64 ConnectedTime;				// Connection date and time
	UINT Me;							// Myself
	UINT Ip;							// IP address
	UINT NumPort;						// Number of port numbers
	UINT *Ports;						// Port number
	char hostname[MAX_HOST_NAME_LEN + 1];	// Host name
	X *ServerCert;						// Server certificate
	LIST *HubList;						// Virtual HUB list
	QUEUE *TaskQueue;					// Task queue
	EVENT *TaskPostEvent;				// Task queuing event
	UINT Point;							// Point
	volatile bool Halting;				// Stopped
	UINT NumSessions;					// Number of sessions
	UINT MaxSessions;					// Maximum number of sessions
	UINT NumTcpConnections;				// Number of TCP connections
	TRAFFIC Traffic;					// Traffic information
	UINT AssignedClientLicense;			// Number of assigned client licenses
	UINT AssignedBridgeLicense;			// Number of assigned bridge licenses
	UINT Weight;						// Performance ratio
	UCHAR RandomKey[SHA1_SIZE];			// Random number key (license check)
	UINT64 SystemId;					// System ID (license check)
};

// Connection to the farm controller
struct FARM_CONTROLLER
{
	LOCK *lock;							// Lock
	struct SERVER *Server;				// Server
	THREAD *Thread;						// Thread
	SOCK *Sock;							// Socket
	SESSION *Session;					// Session
	volatile bool Halt;					// Halting flag
	EVENT *HaltEvent;					// Halting event
	UINT LastError;						// Last error
	bool Online;						// Online flag
	UINT64 StartedTime;					// Connection start time
	UINT64 CurrentConnectedTime;		// Connection time of this time
	UINT64 FirstConnectedTime;			// First connection time
	UINT NumConnected;					// Number of connection count
	UINT NumTry;						// Number of trials
	UINT NumFailed;						// Connection failure count
	bool IsConnected;					// Whether it's connected
};

// Server listener
struct SERVER_LISTENER
{
	UINT Port;							// Port number
	bool Enabled;						// Active flag
	LISTENER *Listener;					// Listener object
	bool DisableDos;					// Disable the DoS detection
};

// Syslog configuration
struct SYSLOG_SETTING
{
	UINT SaveType;							// Save type
	char Hostname[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT Port;								// Port number
};

// Setting of SSTP and OpenVPN
struct OPENVPN_SSTP_CONFIG
{
	bool EnableOpenVPN;						// OpenVPN is enabled
	bool EnableSSTP;						// SSTP is enabled
};

// Server object
struct SERVER
{
	UINT ServerType;					// Type of server
	UINT UpdatedServerType;				// Type of updated server
	LIST *ServerListenerList;			// Server listener list
	LIST *PortsUDP;						// The ports used by Proto's UDP listener
	UCHAR HashedPassword[SHA1_SIZE];	// Password
	char ControllerName[MAX_HOST_NAME_LEN + 1];		// Controller name
	UINT ControllerPort;				// Controller port
	UINT Weight;						// Performance ratio
	bool ControllerOnly;				// Only controller function
	UCHAR MemberPassword[SHA1_SIZE];	// Password for farm members
	UINT PublicIp;						// Public IP 
	UINT NumPublicPort;					// Number of public ports
	UINT *PublicPorts;					// Public port array
	UINT64 StartTime;					// Start-up time
	UINT AutoSaveConfigSpan;			// Auto save interval
	UINT AutoSaveConfigSpanSaved;		// Auto save interval (stored value)
	bool DontBackupConfig;				// Do not save a backup of the configuration automatically
	bool BackupConfigOnlyWhenModified;	// Save a backup of the configuration only if there is a modification
	UINT ConfigRevision;				// Configuration file revision
	bool DisableDosProtection;			// Disable the DoS attack protection
	UCHAR MyRandomKey[SHA1_SIZE];		// Their own random key
	bool FarmControllerInited;			// Initialization of farm controller has been completed
	bool DisableDeadLockCheck;			// Disable the deadlock check
	bool UseWebUI;						// Use the WebUI
	bool SaveDebugLog;					// Save the debug log
	bool NoSendSignature;				// Let the client not to send a signature
	bool UseWebTimePage;				// Use WebTimePage
	bool NoLinuxArpFilter;				// Not to set arp_filter in Linux
	bool NoHighPriorityProcess;			// Not to raise the priority of the process
	bool NoDebugDump;					// Not to output the debug dump
	bool DisableNatTraversal;			// Disable the NAT-traversal feature
	bool EnableVpnOverIcmp;				// VPN over ICMP is enabled
	bool EnableVpnOverDns;				// VPN over DNS is enabled
	bool NoMoreSave;					// Do not save any more
	bool EnableConditionalAccept;		// Apply the Conditional Accept the Listener
	bool EnableLegacySSL;				// Enable Legacy SSL
	bool DisableIPsecAggressiveMode;	// Disable IPsec's aggressive mode

	volatile bool Halt;					// Halting flag
	LOCK *lock;							// Lock
	REF *ref;							// Reference counter
	CEDAR *Cedar;						// Cedar
	CFG_RW *CfgRw;						// Configuration file R/W
	LOCK *SaveCfgLock;					// Settings saving lock
	EVENT *SaveHaltEvent;				// Saving thread halting event
	THREAD *SaveThread;					// Settings saving thread
	FARM_CONTROLLER *FarmController;	// Farm controller
	LOCK *TasksFromFarmControllerLock;	// Lock while processing tasks from farm controller
	LIST *FarmMemberList;				// Farm members list
	FARM_MEMBER *Me;					// Register myself as a farm member
	THREAD *FarmControlThread;			// Farm control thread
	EVENT *FarmControlThreadHaltEvent;	// Farm control thread halting event
	LIST *HubCreateHistoryList;			// Virtual HUB creation history list

	KEEP *Keep;							// Maintaining connections
	LOG *Logger;						// Server logger
	ERASER *Eraser;						// Eraser

	bool Led;							// Use the LED display board
	bool LedSpecial;					// LED Special

	UINT CurrentTotalNumSessionsOnFarm;	// Total number of sessions in this server farm
	UINT CurrentAssignedClientLicense;	// Current number of assigned client licenses
	UINT CurrentAssignedBridgeLicense;	// Current number of assigned bridge license


	LOCK *SyslogLock;					// The lock of the syslog configuration
	SYSLOG_SETTING SyslogSetting;		// Syslog configuration
	SLOG *Syslog;						// Syslog object

	LOCK *CapsCacheLock;				// Lock for Caps cache
	CAPSLIST *CapsListCache;			// Caps cache
	UINT LicenseHash;					// Hash value of the license list

	bool SnapshotInited;
	EVENT *SnapshotHaltEvent;			// Snapshot halting event
	volatile bool HaltSnapshot;			// Snapshot halting flag
	THREAD *SnapshotThread;				// Snapshot thread
	LOG *SnapshotLogger;				// Snapshot logger
	UINT64 LastSnapshotTime;			// Time that the last snapshot created

	THREAD *DeadLockCheckThread;		// Deadlock check thread
	volatile bool HaltDeadLockThread;	// Halting flag
	EVENT *DeadLockWaitEvent;			// Waiting Event

	PROTO *Proto;						// Protocols handler
	IPSEC_SERVER *IPsecServer;			// IPsec server function
	DDNS_CLIENT *DDnsClient;			// DDNS client feature
	LOCK *OpenVpnSstpConfigLock;		// Lock OpenVPN and SSTP configuration

	AZURE_CLIENT *AzureClient;			// VPN Azure client
	bool EnableVpnAzure;				// Flag whether VPN Azure client is enabled

	bool DisableGetHostNameWhenAcceptTcp;	// Disable GetHostName when accepting TCP
	bool DisableCoreDumpOnUnix;			// Disable core dump on UNIX

	TINY_LOG *DebugLog;					// Debug log

	DYNAMIC_LISTENER *DynListenerIcmp;	// VPN over ICMP listener
	DYNAMIC_LISTENER *DynListenerDns;	// VPN over DNS listener

	bool IPsecMessageDisplayed;			// Flag for whether the message about IPsec is displayed

	bool IsInVm;						// Whether I'm within the VM



	volatile UINT NatTGlobalUdpPort;	// NAT-T global UDP port

	IP ListenIP;						// Listen IP
	bool StrictSyslogDatetimeFormat;	// Make syslog datetime format strict RFC3164
	bool DisableJsonRpcWebApi;					// Disable JSON-RPC Web API
};


// Enumerate sessions *
struct RPC_ENUM_SESSION
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	UINT NumSession;								// Number of sessions
	struct RPC_ENUM_SESSION_ITEM *Sessions;			// Session list
};

// Session status *
struct RPC_SESSION_STATUS
{
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB Name
	char Name[MAX_SESSION_NAME_LEN + 1];			// Session name
	char Username[MAX_USERNAME_LEN + 1];			// User name
	char RealUsername[MAX_USERNAME_LEN + 1];		// Real user name
	char GroupName[MAX_USERNAME_LEN + 1];			// Group name
	bool LinkMode;									// Link mode
	RPC_CLIENT_GET_CONNECTION_STATUS Status;		// Status
	UINT ClientIp;									// Client IP address
	UCHAR ClientIp6[16];							// Client IPv6 address
	IP ClientIpAddress;								// Client IP address (IPv4/IPv6)
	char ClientHostName[MAX_HOST_NAME_LEN + 1];		// Client host name
	NODE_INFO NodeInfo;								// Node information
};


// Type of server
#define	SERVER_TYPE_STANDALONE			0		// Stand-alone server
#define	SERVER_TYPE_FARM_CONTROLLER		1		// Farm controller server
#define	SERVER_TYPE_FARM_MEMBER			2		// Farm member server


// Caps related
struct CAPS
{
	char *Name;							// Name
	UINT Value;							// Value
};
struct CAPSLIST
{
	LIST *CapsList;						// Caps list
};

// Log file
struct LOG_FILE
{
	char Path[MAX_PATH];				// Path name
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT FileSize;						// File size
	UINT64 UpdatedTime;					// Updating date
};


// Global server flags
#define	NUM_GLOBAL_SERVER_FLAGS			128
#define	GSF_DISABLE_PUSH_ROUTE			1
#define	GSF_DISABLE_RADIUS_AUTH			2
#define	GSF_DISABLE_CERT_AUTH			3
#define	GSF_DISABLE_DEEP_LOGGING		4
#define	GSF_DISABLE_AC					5
#define	GSF_DISABLE_SYSLOG				6
#define	GSF_SHOW_OSS_MSG				7
#define	GSF_LOCALBRIDGE_NO_DISABLE_OFFLOAD	8
#define	GSF_DISABLE_SESSION_RECONNECT	9

// Global parameters
#define	NUM_GLOBAL_PARAMS					128
#define	GP_MAX_SEND_SOCKET_QUEUE_SIZE		1
#define	GP_MIN_SEND_SOCKET_QUEUE_SIZE		2
#define	GP_MAX_SEND_SOCKET_QUEUE_NUM		3
#define	GP_SELECT_TIME						4
#define	GP_SELECT_TIME_FOR_NAT				5
#define	GP_MAX_STORED_QUEUE_NUM				6
#define	GP_MAX_BUFFERING_PACKET_SIZE		7
#define	GP_HUB_ARP_SEND_INTERVAL			8
#define	GP_MAC_TABLE_EXPIRE_TIME			9
#define	GP_IP_TABLE_EXPIRE_TIME				10
#define	GP_IP_TABLE_EXPIRE_TIME_DHCP		11
#define	GP_STORM_CHECK_SPAN					12
#define	GP_STORM_DISCARD_VALUE_START		13
#define	GP_STORM_DISCARD_VALUE_END			14
#define	GP_MAX_MAC_TABLES					15
#define	GP_MAX_IP_TABLES					16
#define	GP_MAX_HUB_LINKS					17
#define	GP_MEM_FIFO_REALLOC_MEM_SIZE		18
#define	GP_QUEUE_BUDGET						19
#define	GP_FIFO_BUDGET						20

extern UINT vpn_global_parameters[NUM_GLOBAL_PARAMS];

#define	VPN_GP(id, default_value)	((UINT)(vpn_global_parameters[(id)] != 0 ? vpn_global_parameters[(id)] : (default_value)))



// Virtual HUB creation history
struct SERVER_HUB_CREATE_HISTORY
{
	char HubName[MAX_HUBNAME_LEN + 1];
	UINT64 CreatedTime;
};

// Function prototype declaration
SERVER *SiNewServer(bool bridge);
SERVER *SiNewServerEx(bool bridge, bool in_client_inner_server, bool relay_server);
void SiReleaseServer(SERVER *s);
void SiCleanupServer(SERVER *s);
void StStartServer(bool bridge);
void StStopServer();
void SiInitConfiguration(SERVER *s);
void SiFreeConfiguration(SERVER *s);
UINT SiWriteConfigurationFile(SERVER *s);
void SiLoadInitialConfiguration(SERVER *s);
bool SiLoadConfigurationFile(SERVER *s);
bool SiLoadConfigurationFileMain(SERVER *s, FOLDER *root);
void SiInitDefaultServerCert(SERVER *s);
void SiInitCipherName(SERVER *s);
void SiGenerateDefaultCert(X **server_x, K **server_k);
void SiGenerateDefaultCertEx(X **server_x, K **server_k, char *common_name);
void SiInitListenerList(SERVER *s);
void SiLockListenerList(SERVER *s);
void SiUnlockListenerList(SERVER *s);
bool SiAddListener(SERVER *s, UINT port, bool enabled);
bool SiAddListenerEx(SERVER *s, UINT port, bool enabled, bool disable_dos);
bool SiEnableListener(SERVER *s, UINT port);
bool SiDisableListener(SERVER *s, UINT port);
bool SiDeleteListener(SERVER *s, UINT port);
SERVER_LISTENER *SiGetListener(SERVER *s, UINT port);
int CompareServerListener(void *p1, void *p2);
void SiStopAllListener(SERVER *s);
void SiInitDefaultHubList(SERVER *s);
void SiSetDefaultHubOption(HUB_OPTION *o);
FOLDER *SiWriteConfigurationToCfg(SERVER *s);
bool SiLoadConfigurationCfg(SERVER *s, FOLDER *root);
void SiWriteLocalBridges(FOLDER *f, SERVER *s);
void SiLoadLocalBridges(SERVER *s, FOLDER *f);
void SiWriteLocalBridgeCfg(FOLDER *f, LOCALBRIDGE *br);
void SiLoadLocalBridgeCfg(SERVER *s, FOLDER *f);
void SiWriteListeners(FOLDER *f, SERVER *s);
void SiLoadListeners(SERVER *s, FOLDER *f);
void SiWriteListenerCfg(FOLDER *f, SERVER_LISTENER *r);
void SiLoadListenerCfg(SERVER *s, FOLDER *f);
void SiWriteServerCfg(FOLDER *f, SERVER *s);
void SiLoadServerCfg(SERVER *s, FOLDER *f);
void SiWriteGlobalParamsCfg(FOLDER *f);
void SiLoadGlobalParamsCfg(FOLDER *f);
void SiLoadGlobalParamItem(UINT id, UINT value);
void SiLoadProtoCfg(PROTO *p, FOLDER *f);
void SiWriteProtoCfg(FOLDER *f, PROTO *p);
void SiWriteTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiWriteTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e);
void SiLoadTraffic(FOLDER *parent, char *name, TRAFFIC *t);
void SiSaverThread(THREAD *thread, void *param);
void SiLoadLicenseManager(SERVER *s, FOLDER *f);
void SiWriteLicenseManager(FOLDER *f, SERVER *s);
void SiLoadL3Switchs(SERVER *s, FOLDER *f);
void SiLoadL3SwitchCfg(L3SW *sw, FOLDER *f);
void SiWriteL3Switchs(FOLDER *f, SERVER *s);
void SiWriteL3SwitchCfg(FOLDER *f, L3SW *sw);
void SiLoadIPsec(SERVER *s, FOLDER *f);
void SiWriteIPsec(FOLDER *f, SERVER *s);
void SiWriteHubs(FOLDER *f, SERVER *s);
void SiLoadHubs(SERVER *s, FOLDER *f);
void SiWriteHubCfg(FOLDER *f, HUB *h);
void SiLoadHubCfg(SERVER *s, FOLDER *f, char *name);
void SiLoadHubLogCfg(HUB_LOG *g, FOLDER *f);
void SiWriteHubOptionCfg(FOLDER *f, HUB_OPTION *o);
void SiWriteHubLogCfg(FOLDER *f, HUB_LOG *g);
void SiWriteHubLogCfgEx(FOLDER *f, HUB_LOG *g, bool el_mode);
void SiLoadHubOptionCfg(FOLDER *f, HUB_OPTION *o);
void SiWriteHubLinks(FOLDER *f, HUB *h);
void SiLoadHubLinks(HUB *h, FOLDER *f);
void SiWriteHubAdminOptions(FOLDER *f, HUB *h);
void SiLoadHubAdminOptions(HUB *h, FOLDER *f);
void SiWriteHubLinkCfg(FOLDER *f, LINK *k);
void SiLoadHubLinkCfg(FOLDER *f, HUB *h);
void SiWriteHubAccessLists(FOLDER *f, HUB *h);
void SiLoadHubAccessLists(HUB *h, FOLDER *f);
void SiWriteHubAccessCfg(FOLDER *f, ACCESS *a);
void SiLoadHubAccessCfg(HUB *h, FOLDER *f);
void SiWriteHubDb(FOLDER *f, HUBDB *db, bool no_save_ac_list);
void SiLoadHubDb(HUB *h, FOLDER *f);
void SiWriteUserList(FOLDER *f, LIST *o);
void SiLoadUserList(HUB *h, FOLDER *f);
void SiWriteUserCfg(FOLDER *f, USER *u);
void SiLoadUserCfg(HUB *h, FOLDER *f);
void SiWriteGroupList(FOLDER *f, LIST *o);
void SiLoadGroupList(HUB *h, FOLDER *f);
void SiWriteGroupCfg(FOLDER *f, USERGROUP *g);
void SiLoadGroupCfg(HUB *h, FOLDER *f);
void SiWriteCertList(FOLDER *f, LIST *o);
void SiLoadCertList(LIST *o, FOLDER *f);
void SiWriteCrlList(FOLDER *f, LIST *o);
void SiLoadCrlList(LIST *o, FOLDER *f);
void SiWriteAcList(FOLDER *f, LIST *o);
void SiLoadAcList(LIST *o, FOLDER *f);
void SiWritePolicyCfg(FOLDER *f, POLICY *p, bool cascade_mode);
void SiLoadPolicyCfg(POLICY *p, FOLDER *f);
void SiLoadSecureNAT(HUB *h, FOLDER *f);
void SiWriteSecureNAT(HUB *h, FOLDER *f);
void SiRebootServerEx(bool bridge, bool reset_setting);
void SiRebootServer(bool bridge);
void SiRebootServerThread(THREAD *thread, void *param);
void StInit();
void StFree();
void SiSetServerType(SERVER *s, UINT type,
					 UINT ip, UINT num_port, UINT *ports,
					 char *controller_name, UINT controller_port, UCHAR *password, UINT weight, bool controller_only);
FARM_CONTROLLER *SiStartConnectToController(SERVER *s);
void SiStopConnectToController(FARM_CONTROLLER *f);
void SiFarmServ(SERVER *server, SOCK *sock, X *cert, UINT ip, UINT num_port, UINT *ports, char *hostname, UINT point, UINT weight, UINT max_sessions);
int CompareHubList(void *p1, void *p2);
void SiFarmServMain(SERVER *server, SOCK *sock, FARM_MEMBER *f);
FARM_TASK *SiFarmServPostTask(FARM_MEMBER *f, PACK *request);
PACK *SiFarmServWaitTask(FARM_TASK *t);
PACK *SiExecTask(FARM_MEMBER *f, PACK *p);
PACK *SiCallTask(FARM_MEMBER *f, PACK *p, char *taskname);
void SiAcceptTasksFromController(FARM_CONTROLLER *f, SOCK *sock);
void SiAcceptTasksFromControllerMain(FARM_CONTROLLER *f, SOCK *sock);
PACK *SiCalledTask(FARM_CONTROLLER *f, PACK *p, char *taskname);
void SiHubOnlineProc(HUB *h);
void SiHubOfflineProc(HUB *h);
FARM_MEMBER *SiGetNextFarmMember(SERVER *s, CONNECTION *c, HUB *h);
bool SiGetMemberSelectorUrl(char *url, UINT url_size);
void SiCallCreateHub(SERVER *s, FARM_MEMBER *f, HUB *h);
void SiCallUpdateHub(SERVER *s, FARM_MEMBER *f, HUB *h);
void SiCallDeleteHub(SERVER *s, FARM_MEMBER *f, HUB *h);
void SiCallEnumSession(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_SESSION *t);
void SiCallEnumNat(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_NAT *t);
void SiCallEnumDhcp(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_DHCP *t);
void SiCallGetNatStatus(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_NAT_STATUS *t);
void SiCallEnumMacTable(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_MAC_TABLE *t);
void SiCallEnumIpTable(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_IP_TABLE *t);
void SiCallDeleteSession(SERVER *s, FARM_MEMBER *f, char *hubname, char *session_name);
void SiCallCreateTicket(SERVER *s, FARM_MEMBER *f, char *hubname, char *username, char *realusername, POLICY *policy, UCHAR *ticket, UINT counter, char *groupname);
void SiCallDeleteMacTable(SERVER *s, FARM_MEMBER *f, char *hubname, UINT key);
void SiCallDeleteIpTable(SERVER *s, FARM_MEMBER *f, char *hubname, UINT key);
void SiCalledCreateHub(SERVER *s, PACK *p);
void SiCalledUpdateHub(SERVER *s, PACK *p);
void SiCalledDeleteHub(SERVER *s, PACK *p);
void SiCalledDeleteSession(SERVER *s, PACK *p);
void SiCalledDeleteMacTable(SERVER *s, PACK *p);
void SiCalledDeleteIpTable(SERVER *s, PACK *p);
PACK *SiCalledCreateTicket(SERVER *s, PACK *p);
PACK *SiCalledEnumSession(SERVER *s, PACK *p);
PACK *SiCalledEnumNat(SERVER *s, PACK *p);
PACK *SiCalledEnumDhcp(SERVER *s, PACK *p);
PACK *SiCalledGetNatStatus(SERVER *s, PACK *p);
PACK *SiCalledEnumMacTable(SERVER *s, PACK *p);
PACK *SiCalledEnumIpTable(SERVER *s, PACK *p);
void SiCalledEnumHub(SERVER *s, PACK *p, PACK *req);
void SiPackAddCreateHub(PACK *p, HUB *h);
FARM_MEMBER *SiGetHubHostingMember(SERVER *s, HUB *h, bool admin_mode, CONNECTION *c);
void SiCallEnumHub(SERVER *s, FARM_MEMBER *f);
void SiStartFarmControl(SERVER *s);
void SiStopFarmControl(SERVER *s);
void SiFarmControlThread(THREAD *thread, void *param);
void SiAccessListToPack(PACK *p, LIST *o);
void SiAccessToPack(PACK *p, ACCESS *a, UINT i, UINT total);
ACCESS *SiPackToAccess(PACK *p, UINT i);
UINT SiNumAccessFromPack(PACK *p);
void SiHubUpdateProc(HUB *h);
bool SiCheckTicket(HUB *h, UCHAR *ticket, char *username, UINT username_size, char *usernamereal, UINT usernamereal_size, POLICY *policy, char *sessionname, UINT sessionname_size, char *groupname, UINT groupname_size);
UINT SiGetPoint(SERVER *s);
UINT SiCalcPoint(SERVER *s, UINT num, UINT weight);
bool SiCallGetSessionStatus(SERVER *s, FARM_MEMBER *f, RPC_SESSION_STATUS *t);
PACK *SiCalledGetSessionStatus(SERVER *s, PACK *p);
bool SiCallEnumLogFileList(SERVER *s, FARM_MEMBER *f, RPC_ENUM_LOG_FILE *t, char *hubname);
PACK *SiCalledEnumLogFileList(SERVER *s, PACK *p);
bool SiCallReadLogFile(SERVER *s, FARM_MEMBER *f, RPC_READ_LOG_FILE *t);
PACK *SiCalledReadLogFile(SERVER *s, PACK *p);
int CmpLogFile(void *p1, void *p2);
LIST *EnumLogFile(char *hubname);
void EnumLogFileDir(LIST *o, char *dirname);
void FreeEnumLogFile(LIST *o);
bool CheckLogFileNameFromEnumList(LIST *o, char *name, char *server_name);
void IncrementServerConfigRevision(SERVER *s);
void GetServerProductName(SERVER *s, char *name, UINT size);
void GetServerProductNameInternal(SERVER *s, char *name, UINT size);


void SiSetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiGetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting);
void SiWriteSysLog(SERVER *s, char *typestr, char *hubname, wchar_t *message);
UINT SiGetSysLogSaveStatus(SERVER *s);
void SiInitDeadLockCheck(SERVER *s);
void SiFreeDeadLockCheck(SERVER *s);
void SiDeadLockCheckThread(THREAD *t, void *param);
void SiCheckDeadLockMain(SERVER *s, UINT timeout);
void SiDebugLog(SERVER *s, char *msg);
UINT SiDebug(SERVER *s, RPC_TEST *ret, UINT i, char *str);
UINT SiDebugProcHelloWorld(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcExit(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcDump(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcRestorePriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcSetHighPriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetExeFileName(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcCrash(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetIPsecMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcSetIPsecMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetVgsMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcSetVgsMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetCurrentTcpSendQueueLength(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);
UINT SiDebugProcGetCurrentGetIPThreadCount(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);

typedef UINT (SI_DEBUG_PROC)(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size);

CAPS *NewCaps(char *name, UINT value);
void FreeCaps(CAPS *c);
CAPSLIST *NewCapsList();
int CompareCaps(void *p1, void *p2);
void AddCaps(CAPSLIST *caps, CAPS *c);
CAPS *GetCaps(CAPSLIST *caps, char *name);
void FreeCapsList(CAPSLIST *caps);
bool GetCapsBool(CAPSLIST *caps, char *name);
UINT GetCapsInt(CAPSLIST *caps, char *name);
void AddCapsBool(CAPSLIST *caps, char *name, bool b);
void AddCapsInt(CAPSLIST *caps, char *name, UINT i);
void InRpcCapsList(CAPSLIST *t, PACK *p);
void OutRpcCapsList(PACK *p, CAPSLIST *t);
void FreeRpcCapsList(CAPSLIST *t);
void InitCapsList(CAPSLIST *t);
void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p);
void OutRpcSysLogSetting(PACK *p, SYSLOG_SETTING *t);

void GetServerCaps(SERVER *s, CAPSLIST *t);
void FlushServerCaps(SERVER *s);
bool GetServerCapsBool(SERVER *s, char *name);
UINT GetServerCapsInt(SERVER *s, char *name);
void GetServerCapsMain(SERVER *s, CAPSLIST *t);
void InitServerCapsCache(SERVER *s);
void FreeServerCapsCache(SERVER *s);
void DestroyServerCapsCache(SERVER *s);

void SetGlobalServerFlag(UINT index, UINT value);
UINT GetGlobalServerFlag(UINT index);
void UpdateGlobalServerFlags(SERVER *s, CAPSLIST *t);


bool IsAdminPackSupportedServerProduct(char *name);

void SiInitHubCreateHistory(SERVER *s);
void SiFreeHubCreateHistory(SERVER *s);
void SiDeleteOldHubCreateHistory(SERVER *s);
void SiAddHubCreateHistory(SERVER *s, char *name);
void SiDelHubCreateHistory(SERVER *s, char *name);
bool SiIsHubRegistedOnCreateHistory(SERVER *s, char *name);

bool SiTooManyUserObjectsInServer(SERVER *s, bool oneMore);

bool SiCanOpenVpnOverDnsPort();
bool SiCanOpenVpnOverIcmpPort();
void SiApplySpecialListenerStatus(SERVER *s);

bool SiIsAzureEnabled(SERVER *s);
bool SiIsAzureSupported(SERVER *s);
void SiApplyAzureConfig(SERVER *s, DDNS_CLIENT_STATUS *ddns_status);
void SiSetAzureEnable(SERVER *s, bool enabled);

void SiUpdateCurrentRegion(CEDAR *c, char *region, bool force_update);
void SiGetCurrentRegion(CEDAR *c, char *region, UINT region_size);
bool SiIsEnterpriseFunctionsRestrictedOnOpenSource(CEDAR *c);

#endif	// SERVER_H



