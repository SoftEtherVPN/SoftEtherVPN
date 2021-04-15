// SoftEther VPN Source Code
// Cedar Communication Module


// Hub.h
// Header of Hub.c

#ifndef	HUB_H
#define	HUB_H

#include "Account.h"
#include "Logging.h"

// Prefix in the access list for investigating whether the user name which is contained in a particular file 
#define	ACCESS_LIST_INCLUDED_PREFIX		"include:"		// Included
#define	ACCESS_LIST_EXCLUDED_PREFIX		"exclude:"		// Not included

// The default value for the cache expiration of the user name reference file of the access list (in seconds)
#define	ACCESS_LIST_INCLUDE_FILE_CACHE_LIFETIME		30

// The maximum length of the include file in the access list
#define	ACCESS_LIST_INCLUDE_FILE_MAX_SIZE			(1024 * 1024)

// <INFO> tags of the URL in the access list
#define	ACCESS_LIST_URL_INFO_TAG					"<INFO>"

// Old MAC address entry flush interval
#define	OLD_MAC_ADDRESS_ENTRY_FLUSH_INTERVAL		1000

// Default flooding queue length
#define	DEFAULT_FLOODING_QUEUE_LENGTH				(32 * 1024 * 1024)

// SoftEther link control packet
struct SE_LINK
{
	UCHAR DestMacAddress[6];			// Destination MAC address
	UCHAR SrcMacAddress[6];				// Source MAC address
	UCHAR SignatureS;					// 'S'
	UCHAR SignatureE;					// 'E'
	UCHAR Padding[2];					// Padding
	UINT Type;							// Type
	UCHAR HubSignature[16];				// HUB signature
	UINT TransactionId;					// Transaction ID
	UINT Data;							// Data
	UCHAR Dummy[20];					// Dummy
	UCHAR Checksum[SHA1_SIZE];			// Checksum
};


// Test packet reception record
struct TEST_HISTORY
{
	SESSION *s1;
	SESSION *s2;
};

// State machine for link test
struct SE_TEST
{
	LOCK *lock;							// Lock
	UINT64 LastTestPacketSentTime;		// Time that sent the test packet at the last
	UINT NextTestPacketSendInterval;	// Next test packet transmission interval
	bool CurrentTesting;				// Test by sending a test packet currently
	UINT TransactionId;					// Transaction ID
	LIST *TestHistory;					// Reception history
};

// Macro
#define	NO_ACCOUNT_DB(h)		((h)->FarmMember)

// Database in the case of a stand-alone or a farm master HUB
struct HUBDB
{
	LIST *UserList;						// User List
	LIST *GroupList;					// Group List
	LIST *RootCertList;					// Certificate list to trust
	LIST *CrlList;						// CRL list
	LIST *AcList;						// AC List
};

// Traffic limiter
struct TRAFFIC_LIMITER
{
	UINT64 LastTime;					// Time of last measured
	UINT64 Value;						// The current value
};

// Record the number of broadcast of each endpoint
struct STORM
{
	UCHAR MacAddress[6];				// MAC address
	UCHAR Padding[2];					// Padding
	IP SrcIp;							// Source IP address
	IP DestIp;							// Destination IP address
	UINT64 CheckStartTick;				// Time that checking is started
	UINT CurrentBroadcastNum;			// The current number of broadcasts
	UINT DiscardValue;					// Ratio to discard the broadcast packet
	bool StrictMode;					// Strict mode
};

// Packet adapter information structure for HUB
struct HUB_PA
{
	CANCEL *Cancel;						// Cancel object
	QUEUE *PacketQueue;					// Packet queue
	bool MonitorPort;					// Monitor port
	UINT64 Now;							// Current time
	TRAFFIC_LIMITER UploadLimiter;		// Upload bandwidth limit
	TRAFFIC_LIMITER DownloadLimiter;	// Download bandwidth limitation
	SESSION *Session;					// Session
	LIST *StormList;					// Broadcast storm recording list
	UINT64 UsernameHash;				// User name hash
	UINT64 UsernameHashSimple;			// User name hash (simple)
	UINT64 GroupnameHash;				// Group name hash
};

// HUB options
struct HUB_OPTION
{
	// Standard options
	UINT DefaultGateway;				// Used in IPC when DHCP cannot be used (e.g. WireGuard sessions)
	UINT DefaultSubnet;					// Used in IPC when DHCP cannot be used (e.g. WireGuard sessions)
	UINT MaxSession;					// Maximum number of simultaneous connections
	bool NoEnum;						// Excluded from the enumeration
	// Advanced options
	bool NoArpPolling;					// No ARP polling
	bool NoIPv6AddrPolling;				// No IPv6 address polling
	bool NoIpTable;						// Do not generate an IP address table
	bool NoMacAddressLog;				// Not to write the registration log of the MAC address
	bool ManageOnlyPrivateIP;			// Manage only private IP
	bool ManageOnlyLocalUnicastIPv6;	// Manage only local unicast IPv6 addresses
	bool DisableIPParsing;				// Disable the IP interpretation
	bool YieldAfterStorePacket;			// Yield after the packet is stored
	bool NoSpinLockForPacketDelay;		// Do not use the spin lock
	UINT BroadcastStormDetectionThreshold;	// Broadcast number limit threshold
	bool FilterPPPoE;					// Filtering the PPPoE (0x8863, 0x8864)
	bool FilterOSPF;					// Filtering the OSPF (ip_proto = 89)
	bool FilterIPv4;					// Filter IPv4 packets
	bool FilterIPv6;					// Filter IPv6 packets
	bool FilterNonIP;					// Filter all non-IP packets
	bool FilterBPDU;					// Filter the BPDU packets
	UINT ClientMinimumRequiredBuild;	// If the build number of the client is lower than a certain value, deny it
	bool NoIPv6DefaultRouterInRAWhenIPv6;	// Delete the default router specification from the IPv6 router advertisement (only in the case of IPv6 physical connection)
	bool NoIPv4PacketLog;				// Do not save the packet log for the IPv4 packet
	bool NoIPv6PacketLog;				// Do not save the packet log of IPv6 packets
	bool NoLookBPDUBridgeId;			// Don't look the BPDU bridge ID for switching
	bool NoManageVlanId;				// Don't manage the VLAN ID
	UINT VlanTypeId;					// Type ID of VLAN packets (usually 0x8100)
	bool FixForDLinkBPDU;				// Apply the fix for the BPDU of the strange behavior of the D-Link
	UINT RequiredClientId;				// Client ID
	UINT AdjustTcpMssValue;				// TCP MSS adjustment value
	bool DisableAdjustTcpMss;			// Completely disable the TCP MSS adjustment function
	bool NoDhcpPacketLogOutsideHub;		// Suppress DHCP unrelated log
	bool DisableHttpParsing;			// Prohibit the HTTP interpretation
	bool DisableUdpAcceleration;		// Prohibit the UDP acceleration function
	bool DisableUdpFilterForLocalBridgeNic;	// Not to perform filtering DHCP packets associated with local bridge NIC
	bool ApplyIPv4AccessListOnArpPacket;	// Apply an IPv4 access list to the ARP packet
	bool RemoveDefGwOnDhcpForLocalhost;	// Remove the designation of the DHCP server from the DHCP response packet addressed to localhost
	UINT SecureNAT_MaxTcpSessionsPerIp;		// Maximum number of TCP sessions per IP address
	UINT SecureNAT_MaxTcpSynSentPerIp;		// Maximum number of TCP sessions of SYN_SENT state per IP address
	UINT SecureNAT_MaxUdpSessionsPerIp;		// Maximum number of UDP sessions per IP address
	UINT SecureNAT_MaxDnsSessionsPerIp;		// Maximum number of DNS sessions per IP address
	UINT SecureNAT_MaxIcmpSessionsPerIp;	// Maximum number of ICMP sessions per IP address
	UINT AccessListIncludeFileCacheLifetime;	// Expiration of the access list external file (in seconds)
	bool DisableKernelModeSecureNAT;			// Disable the kernel mode NAT
	bool DisableIpRawModeSecureNAT;			// Disable the IP Raw Mode NAT
	bool DisableUserModeSecureNAT;			// Disable the user mode NAT
	bool DisableCheckMacOnLocalBridge;	// Disable the MAC address verification in local bridge
	bool DisableCorrectIpOffloadChecksum;	// Disable the correction of checksum that is IP-Offloaded
	bool BroadcastLimiterStrictMode;	// Strictly broadcast packets limiting mode
	UINT MaxLoggedPacketsPerMinute;		// Maximum number of logging target packets per minute
	bool DoNotSaveHeavySecurityLogs;	// Do not take heavy security log
	bool DropBroadcastsInPrivacyFilterMode;	// Drop broadcasting packets if the both source and destination session is PrivacyFilter mode
	bool DropArpInPrivacyFilterMode;	// Drop ARP packets if the both source and destination session is PrivacyFilter mode
	bool SuppressClientUpdateNotification;	// Suppress the update notification function on the VPN Client
	UINT FloodingSendQueueBufferQuota;	// The global quota of send queues of flooding packets
	bool AssignVLanIdByRadiusAttribute;	// Assign the VLAN ID for the VPN session, by the attribute value of RADIUS
	bool DenyAllRadiusLoginWithNoVlanAssign;	// Deny all RADIUS login with no VLAN ID assigned
	bool SecureNAT_RandomizeAssignIp;	// Randomize the assignment IP address for new DHCP client
	UINT DetectDormantSessionInterval;	// Interval (seconds) threshold to detect a dormant VPN session
	bool NoPhysicalIPOnPacketLog;		// Disable saving physical IP address on the packet log
	bool UseHubNameAsDhcpUserClassOption;	// Add HubName to DHCP request as User-Class option
	bool UseHubNameAsRadiusNasId;		// Add HubName to Radius request as NAS-Identifier attrioption
};

// MAC table entry
struct MAC_TABLE_ENTRY
{
	UCHAR MacAddress[6];				// MAC address
	UCHAR Padding[2];
	UINT VlanId;						// VLAN ID
	SESSION *Session;					// Session
	HUB_PA *HubPa;						// HUB packet adapter
	UINT64 CreatedTime;					// Creation date and time
	UINT64 UpdatedTime;					// Updating date
};

// IP table entry
struct IP_TABLE_ENTRY
{
	IP Ip;								// IP address
	SESSION *Session;					// Session
	bool DhcpAllocated;					// Assigned by DHCP
	UINT64 CreatedTime;					// Creation date and time
	UINT64 UpdatedTime;					// Updating date
	UCHAR MacAddress[6];				// MAC address
};

// Loop List
struct LOOP_LIST
{
	UINT NumSessions;
	SESSION **Session;
};

// Access list
struct ACCESS
{
	// IPv4
	UINT Id;							// ID
	wchar_t Note[MAX_ACCESSLIST_NOTE_LEN + 1];	// Note

	// --- Please add items to the bottom of here for enhancements ---
	bool Active;						// Enable flag
	UINT Priority;						// Priority
	bool Discard;						// Discard flag
	UINT SrcIpAddress;					// Source IP address
	UINT SrcSubnetMask;					// Source subnet mask
	UINT DestIpAddress;					// Destination IP address
	UINT DestSubnetMask;				// Destination subnet mask
	UINT Protocol;						// Protocol
	UINT SrcPortStart;					// Source port number starting point
	UINT SrcPortEnd;					// Source port number end point
	UINT DestPortStart;					// Destination port number starting point
	UINT DestPortEnd;					// Destination port number end point
	UINT64 SrcUsernameHash;				// Source user name hash
	bool IsSrcUsernameIncludeOrExclude;	// The source user name is formed as the "include:" or "exclude:"
	char SrcUsername[MAX_USERNAME_LEN + 1];
	bool IsDestUsernameIncludeOrExclude;	// The destination user name is formed as "include:" or "exclude:"
	UINT64 DestUsernameHash;			// Destination user name hash
	char DestUsername[MAX_USERNAME_LEN + 1];
	bool CheckSrcMac;					// Presence of a source MAC address setting
	UCHAR SrcMacAddress[6];				// Source MAC address
	UCHAR SrcMacMask[6];				// Source MAC address mask
	bool CheckDstMac;					// Whether the setting of the destination MAC address exists
	UCHAR DstMacAddress[6];				// Destination MAC address
	UCHAR DstMacMask[6];				// Destination MAC address mask
	bool CheckTcpState;					// The state of the TCP connection
	bool Established;					// Established(TCP)
	UINT Delay;							// Delay
	UINT Jitter;						// Jitter
	UINT Loss;							// Packet loss
	char RedirectUrl[MAX_REDIRECT_URL_LEN + 1];	// URL to redirect to

	// IPv6
	bool IsIPv6;						// Whether it's an IPv6
	IPV6_ADDR SrcIpAddress6;			// The source IP address (IPv6)
	IPV6_ADDR SrcSubnetMask6;			// Source subnet mask (IPv6)
	IPV6_ADDR DestIpAddress6;			// Destination IP address (IPv6)
	IPV6_ADDR DestSubnetMask6;			// Destination subnet mask (IPv6)

	// --- Please add items to the above of here for enhancements ---

	// For management
	UINT UniqueId;						// Unique ID
};

// Ticket
struct TICKET
{
	UINT64 CreatedTick;						// Creation date and time
	UCHAR Ticket[SHA1_SIZE];				// Ticket
	char Username[MAX_USERNAME_LEN + 1];	// User name
	char UsernameReal[MAX_USERNAME_LEN + 1];	// Real user name
	char GroupName[MAX_USERNAME_LEN + 1];	// Group name
	char SessionName[MAX_SESSION_NAME_LEN + 1];	// Session name
	POLICY Policy;							// Policy
};

// Traffic difference
struct TRAFFIC_DIFF
{
	UINT Type;							// Type
	TRAFFIC Traffic;					// Traffic
	char *HubName;						// HUB name
	char *Name;							// Name
};

// Administration options
struct ADMIN_OPTION
{
	char Name[MAX_ADMIN_OPTION_NAME_LEN + 1];	// Name
	UINT Value;									// Data
	wchar_t Descrption[MAX_SIZE];				// Descrption
};

// Certificate Revocation List entry
struct CRL
{
	X_SERIAL *Serial;					// Serial number
	NAME *Name;							// Name information
	UCHAR DigestMD5[MD5_SIZE];			// MD5 hash
	UCHAR DigestSHA1[SHA1_SIZE];		// SHA-1 hash
};

// Access control
struct AC
{
	UINT Id;							// ID
	UINT Priority;						// Priority
	bool Deny;							// Deny access
	bool Masked;						// Is masked
	IP IpAddress;						// IP address
	IP SubnetMask;						// Subnet mask
};

// User List
struct USERLIST
{
	char Filename[MAX_PATH];			// File name
	LIST *UserHashList;					// Hash list of user names
};

// HUB structure
struct HUB
{
	LOCK *lock;							// Lock
	LOCK *lock_online;					// Lock for Online
	REF *ref;							// Reference counter
	CEDAR *Cedar;						// Cedar
	UINT Type;							// Type
	HUBDB *HubDb;						// Database
	char *Name;							// The name of the HUB
	LOCK *RadiusOptionLock;				// Lock for Radius option
	char *RadiusServerName;				// Radius server name
	UINT RadiusServerPort;				// Radius server port number
	UINT RadiusRetryInterval;			// Radius retry interval
	BUF *RadiusSecret;					// Radius shared key
	char RadiusSuffixFilter[MAX_SIZE];	// Radius suffix filter
	char RadiusRealm[MAX_SIZE];			// Radius realm (optional)
	bool RadiusConvertAllMsChapv2AuthRequestToEap;	// Convert all MS-CHAPv2 auth request to EAP
	bool RadiusUsePeapInsteadOfEap;			// Use PEAP instead of EAP
	volatile bool Halt;					// Halting flag
	bool Offline;						// Offline
	bool BeingOffline;					// Be Doing Offline
	LIST *SessionList;					// Session list
	COUNTER *SessionCounter;			// Session number generation counter
	TRAFFIC *Traffic;					// Traffic information
	TRAFFIC *OldTraffic;				// Old traffic information
	LOCK *TrafficLock;					// Traffic lock
	COUNTER *NumSessions;				// The current number of sessions
	COUNTER *NumSessionsClient;			// The current number of sessions (client)
	COUNTER *NumSessionsBridge;			// The current number of sessions (bridge)
	HUB_OPTION *Option;					// HUB options
	HASH_LIST *MacHashTable;			// MAC address hash table
	LIST *IpTable;						// IP address table
	LIST *MonitorList;					// Monitor port session list
	LIST *LinkList;						// Linked list
	UCHAR HubSignature[16];				// HUB signature
	UCHAR HubMacAddr[6];				// MAC address of the HUB
	IP HubIp;							// IP address of the HUB (IPv4)
	IPV6_ADDR HubIpV6;					// IP address of the HUB (IPv6)
	UINT HubIP6Id;						// IPv6 packet ID of the HUB
	UCHAR Padding[2];					// Padding
	LOCK *LoopListLock;					// Lock for the loop list
	UINT NumLoopList;					// Number of loop lists
	LOOP_LIST **LoopLists;				// Loop List
	LIST *AccessList;					// Access list
	HUB_LOG LogSetting;					// Log Settings
	LOG *PacketLogger;					// Packet logger
	LOG *SecurityLogger;				// Security logger
	UCHAR HashedPassword[SHA1_SIZE];	// Password
	UCHAR SecurePassword[SHA1_SIZE];	// Secure password
	LIST *TicketList;					// Ticket list
	bool FarmMember;					// Farm member
	UINT64 LastIncrementTraffic;		// Traffic reporting time
	UINT64 LastSendArpTick;				// ARP transmission time of the last
	SNAT *SecureNAT;					// SecureNAT
	bool EnableSecureNAT;				// SecureNAT enable / disable flag
	VH_OPTION *SecureNATOption;			// SecureNAT Option
	THREAD *WatchDogThread;				// Watchdog thread
	EVENT *WatchDogEvent;				// Watchdog event
	bool WatchDogStarted;				// Whether the watchdog thread is used
	volatile bool HaltWatchDog;			// Stop the watchdog thread
	LIST *AdminOptionList;				// Administration options list
	UINT64 CreatedTime;					// Creation date and time
	UINT64 LastCommTime;				// Last communication date and time
	UINT64 LastLoginTime;				// Last login date and time
	UINT NumLogin;						// Number of logins
	bool HubIsOnlineButHalting;			// Virtual HUB is really online, but it is in offline state to stop
	UINT FarmMember_MaxSessionClient;	// Maximum client connection sessions for cluster members
	UINT FarmMember_MaxSessionBridge;	// Maximum bridge connection sessions for cluster members
	bool FarmMember_MaxSessionClientBridgeApply;	// Apply the FarmMember_MaxSession*
	UINT CurrentVersion;				// The current version
	UINT LastVersion;					// Version of when the update notification is issued at the last
	wchar_t *Msg;						// Message to be displayed when the client is connected
	LIST *UserList;						// Cache of the user list file
	bool IsVgsHub;						// Whether it's a VGS Virtual HUB
	bool IsVgsSuperRelayHub;			// Whether it's a VGS Super Relay Virtual HUB
	UINT64 LastFlushTick;				// Last tick to flush the MAC address table
	bool StopAllLinkFlag;				// Stop all link flag
	bool ForceDisableComm;				// Disable the communication function
};


// Global variable
extern ADMIN_OPTION admin_options[];
extern UINT num_admin_options;


// Function prototype
HUBDB *NewHubDb();
void DeleteHubDb(HUBDB *d);
HUB *NewHub(CEDAR *cedar, char *HubName, HUB_OPTION *option);
void SetHubMsg(HUB *h, wchar_t *msg);
wchar_t *GetHubMsg(HUB *h);
void GenHubMacAddress(UCHAR *mac, char *name);
void GenHubIpAddress(IP *ip, char *name);
bool IsHubIpAddress(IP *ip);
bool IsHubIpAddress32(UINT ip32);
bool IsHubIpAddress64(IPV6_ADDR *addr);
bool IsHubMacAddress(UCHAR *mac);
void ReleaseHub(HUB *h);
void CleanupHub(HUB *h);
int CompareHub(void *p1, void *p2);
void LockHubList(CEDAR *cedar);
void UnlockHubList(CEDAR *cedar);
HUB *GetHub(CEDAR *cedar, char *name);
bool IsHub(CEDAR *cedar, char *name);
void StopHub(HUB *h);
void AddSession(HUB *h, SESSION *s);
void DelSession(HUB *h, SESSION *s);
SESSION *SearchSessionByUniqueId(HUB *h, UINT id);
UINT GetNewUniqueId(HUB *h);
void StopAllSession(HUB *h);
bool HubPaInit(SESSION *s);
void HubPaFree(SESSION *s);
CANCEL *HubPaGetCancel(SESSION *s);
UINT HubPaGetNextPacket(SESSION *s, void **data);
bool HubPaPutPacket(SESSION *s, void *data, UINT size);
PACKET_ADAPTER *GetHubPacketAdapter();
int CompareMacTable(void *p1, void *p2);
UINT GetHashOfMacTable(void *p);
void StorePacket(HUB *hub, SESSION *s, PKT *packet);
bool StorePacketFilter(SESSION *s, PKT *packet);
void StorePacketToHubPa(HUB_PA *dest, SESSION *src, void *data, UINT size, PKT *packet, bool is_flooding, bool no_check_acl);
void SetHubOnline(HUB *h);
void SetHubOffline(HUB *h);
SESSION *GetSessionByName(HUB *hub, char *name);
int CompareIpTable(void *p1, void *p2);
bool StorePacketFilterByPolicy(SESSION *s, PKT *p);
bool DeleteIPv6DefaultRouterInRA(PKT *p);
bool StorePacketFilterByTrafficLimiter(SESSION *s, PKT *p);
void IntoTrafficLimiter(TRAFFIC_LIMITER *tr, PKT *p);
bool IsMostHighestPriorityPacket(SESSION *s, PKT *p);
bool IsPriorityPacketForQoS(PKT *p);
int CompareStormList(void *p1, void *p2);
STORM *SearchStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict);
STORM *AddStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict);
bool CheckBroadcastStorm(HUB *hub, SESSION *s, PKT *p);
void AddRootCert(HUB *hub, X *x);
int CmpAccessList(void *p1, void *p2);
void InitAccessList(HUB *hub);
void FreeAccessList(HUB *hub);
void AddAccessList(HUB *hub, ACCESS *a);
void AddAccessListEx(HUB *hub, ACCESS *a, bool no_sort, bool no_reassign_id);
bool IsTcpPacketNcsiHttpAccess(PKT *p);
UINT64 UsernameToInt64(char *name);
void MakeSimpleUsernameRemoveNtDomain(char *dst, UINT dst_size, char *src);
bool ApplyAccessListToStoredPacket(HUB *hub, SESSION *s, PKT *p);
void ForceRedirectToUrl(HUB *hub, SESSION *src_session, PKT *p, char *redirect_url);
BUF *BuildRedirectToUrlPayload(HUB *hub, SESSION *s, char *redirect_url);
bool ApplyAccessListToForwardPacket(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *p);
bool IsPacketMaskedByAccessList(SESSION *s, PKT *p, ACCESS *a, UINT64 dest_username, UINT64 dest_groupname, SESSION *dest_session);
void GetAccessListStr(char *str, UINT size, ACCESS *a);
void DeleteOldIpTableEntry(LIST *o);
void SetRadiusServer(HUB *hub, char *name, UINT port, char *secret);
void SetRadiusServerEx(HUB *hub, char *name, UINT port, char *secret, UINT interval);
bool GetRadiusServer(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size);
bool GetRadiusServerEx(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size, UINT *interval);
bool GetRadiusServerEx2(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size, UINT *interval, char *suffix_filter, UINT suffix_filter_size);
int CompareCert(void *p1, void *p2);
void GetHubLogSetting(HUB *h, HUB_LOG *setting);
void SetHubLogSetting(HUB *h, HUB_LOG *setting);
void SetHubLogSettingEx(HUB *h, HUB_LOG *setting, bool no_change_switch_type);
void DeleteExpiredIpTableEntry(LIST *o);
void DeleteExpiredMacTableEntry(HASH_LIST *h);
void AddTrafficDiff(HUB *h, char *name, UINT type, TRAFFIC *traffic);
void IncrementHubTraffic(HUB *h);
void EnableSecureNAT(HUB *h, bool enable);
void EnableSecureNATEx(HUB *h, bool enable, bool no_change);
void StartHubWatchDog(HUB *h);
void StopHubWatchDog(HUB *h);
void HubWatchDogThread(THREAD *t, void *param);
int CompareAdminOption(void *p1, void *p2);
UINT GetHubAdminOptionEx(HUB *h, char *name, UINT default_value);
UINT GetHubAdminOption(HUB *h, char *name);
void DeleteAllHubAdminOption(HUB *h, bool lock);
void AddHubAdminOptionsDefaults(HUB *h, bool lock);
bool IsCertMatchCrl(X *x, CRL *crl);
bool IsCertMatchCrlList(X *x, LIST *o);
wchar_t *GenerateCrlStr(CRL *crl);
bool IsValidCertInHub(HUB *h, X *x);
void FreeCrl(CRL *crl);
CRL *CopyCrl(CRL *crl);
int CmpAc(void *p1, void *p2);
LIST *NewAcList();
void AddAc(LIST *o, AC *ac);
bool DelAc(LIST *o, UINT id);
AC *GetAc(LIST *o, UINT id);
void SetAc(LIST *o, UINT id, AC *ac);
void DelAllAc(LIST *o);
void SetAcList(LIST *o, LIST *src);
void NormalizeAcList(LIST *o);
bool IsIpMaskedByAc(IP *ip, AC *ac);
bool IsIpDeniedByAcList(IP *ip, LIST *o);
char *GenerateAcStr(AC *ac);
void FreeAcList(LIST *o);
LIST *CloneAcList(LIST *o);
bool IsIPManagementTargetForHUB(IP *ip, HUB *hub);
wchar_t *GetHubAdminOptionHelpString(char *name);
void HubOptionStructToData(RPC_ADMIN_OPTION *ao, HUB_OPTION *o, char *hub_name);
ADMIN_OPTION *NewAdminOption(char *name, UINT value);
void DataToHubOptionStruct(HUB_OPTION *o, RPC_ADMIN_OPTION *ao);
UINT GetHubAdminOptionData(RPC_ADMIN_OPTION *ao, char *name);
bool IsURLMsg(wchar_t *str, char *url, UINT url_size);
LIST *NewUserList();
void DeleteAllUserListCache(LIST *o);
void FreeUserList(LIST *o);
void FreeUserListEntry(USERLIST *u);
int CompareUserList(void *p1, void *p2);
USERLIST *LoadUserList(LIST *o, char *filename);
USERLIST *FindUserList(LIST *o, char *filename);
bool IsUserMatchInUserList(LIST *o, char *filename, UINT64 user_hash);
bool IsUserMatchInUserListWithCacheExpires(LIST *o, char *filename, UINT64 user_hash, UINT64 lifetime);
bool IsUserMatchInUserListWithCacheExpiresAcl(LIST *o, char *name_in_acl, UINT64 user_hash, UINT64 lifetime);
bool CheckMaxLoggedPacketsPerMinute(SESSION *s, UINT max_packets, UINT64 now);
EAP_CLIENT *HubNewEapClient(CEDAR *cedar, char *hubname, char *client_ip_str, char *username, char *vpn_protocol_state_str);

#endif	// HUB_H


