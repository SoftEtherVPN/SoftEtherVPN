// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// IPC.h
// Header of IPC.c

#ifndef	IPC_H
#define	IPC_H

// Constants
#define	IPC_ARP_LIFETIME				(3 * 60 * 1000)
#define	IPC_ARP_GIVEUPTIME				(1 * 1000)
#define	IPC_DHCP_TIMEOUT				(5 * 1000)
#define	IPC_DHCP_MIN_LEASE				5
#define	IPC_DHCP_DEFAULT_LEASE			3600

#define	IPC_MAX_PACKET_QUEUE_LEN		10000

#define	IPC_DHCP_VENDOR_ID				"MSFT 5.0"

#define	IPC_PASSWORD_MSCHAPV2_TAG		"xH7DiNlurDhcYV4a:"

#define IPC_LAYER_2						2
#define IPC_LAYER_3						3

// ARP table entry
struct IPC_ARP
{
	IP Ip;								// IP address
	bool Resolved;						// Whether the MAC address have been resolved
	UCHAR MacAddress[6];				// MAC address
	UINT64 GiveupTime;					// Time to give up (in the case of unresolved)
	UINT64 ExpireTime;					// Expiration date (If resolved)
	QUEUE *PacketQueue;					// Transmission packet queue
};

// DHCP release queue
struct IPC_DHCP_RELEASE_QUEUE
{
	DHCP_OPTION_LIST Req;
	UINT TranId;
	UCHAR MacAddress[6];
};

// IPC_SESSION_SHARED_BUFFER_DATA
struct IPC_SESSION_SHARED_BUFFER_DATA
{
	char ProtocolDetails[256];
	bool EnableUdpAccel;
	bool UsingUdpAccel;
};

// IPC_PARAM
struct IPC_PARAM
{
	char ClientName[MAX_SIZE];
	char Postfix[MAX_SIZE];
	char HubName[MAX_HUBNAME_LEN + 1];
	char UserName[MAX_USERNAME_LEN + 1];
	char Password[MAX_PASSWORD_LEN + 1];
	IP ClientIp;
	UINT ClientPort;
	IP ServerIp;
	UINT ServerPort;
	char ClientHostname[MAX_SIZE];
	char CryptName[MAX_SIZE];
	bool BridgeMode;
	UINT Mss;
	bool IsL3Mode;
	X *ClientCertificate;
	UINT Layer;
};

// IPC_ASYNC object
struct IPC_ASYNC
{
	CEDAR *Cedar;						// Cedar
	IPC_PARAM Param;					// Parameters for creating IPC
	THREAD *Thread;						// Thread
	SOCK_EVENT *SockEvent;				// Socket events that is set when the connection is completed
	bool Done;							// Processing completion flag
	IPC *Ipc;							// IPC object (if it fails to connect, the value is NULL)
	TUBE *TubeForDisconnect;			// Tube for disconnection notification
	UINT ErrorCode;						// Error code in the case of failing to connect
	DHCP_OPTION_LIST L3ClientAddressOption;	// Client IP address option (Only in the case of L3 mode)
	UINT64 L3DhcpRenewInterval;			// DHCP update interval
	UINT64 L3NextDhcpRenewTick;			// DHCP renewal time of the next
	bool DhcpAllocFailed;				// Failed to get IP address from the DHCP server
};

// IPC object
struct IPC
{
	CEDAR *Cedar;
	char HubName[MAX_HUBNAME_LEN + 1];
	char UserName[MAX_USERNAME_LEN + 1];
	char Password[MAX_PASSWORD_LEN + 1];
	char ClientHostname[MAX_SIZE];
	UCHAR random[SHA1_SIZE];
	char SessionName[MAX_SESSION_NAME_LEN + 1];
	char ConnectionName[MAX_CONNECTION_NAME_LEN + 1];
	POLICY *Policy;
	SOCK *Sock;
	INTERRUPT_MANAGER *Interrupt;		// Interrupt manager
	IP ClientIPAddress;					// IP address of the client
	IP SubnetMask;						// Subnet mask of the client
	IP DefaultGateway;					// Default gateway address
	IP BroadcastAddress;				// Broadcast address
	UCHAR MacAddress[6];				// MAC address
	UCHAR Padding[2];
	LIST *ArpTable;						// ARP table
	QUEUE *IPv4ReceivedQueue;			// IPv4 reception queue
	TUBE_FLUSH_LIST *FlushList;			// Tube Flush List
	UCHAR MsChapV2_ServerResponse[20];	// Server response
	DHCP_CLASSLESS_ROUTE_TABLE ClasslessRoute;	// Classless routing table
	SHARED_BUFFER *IpcSessionSharedBuffer;	// A shared buffer between IPC and Session
	IPC_SESSION_SHARED_BUFFER_DATA *IpcSessionShared;	// Shared data between IPC and Session
	UINT Layer;
};

// MS-CHAPv2 authentication information
struct IPC_MSCHAP_V2_AUTHINFO
{
	char MsChapV2_PPPUsername[MAX_SIZE];	// MS-CHAPv2 Username
	UCHAR MsChapV2_ServerChallenge[16];	// MS-CHAPv2 Server Challenge
	UCHAR MsChapV2_ClientChallenge[16];	// MS-CHAPv2 Client Challenge
	UCHAR MsChapV2_ClientResponse[24];	// MS-CHAPv2 Client Response
	EAP_CLIENT *MsChapV2_EapClient;		// EAP client
};

IPC *NewIPC(CEDAR *cedar, char *client_name, char *postfix, char *hubname, char *username, char *password,
			UINT *error_code, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port,
			char *client_hostname, char *crypt_name,
			bool bridge_mode, UINT mss, EAP_CLIENT *eap_client, X *client_certificate,
			UINT layer);
IPC *NewIPCByParam(CEDAR *cedar, IPC_PARAM *param, UINT *error_code);
IPC *NewIPCBySock(CEDAR *cedar, SOCK *s, void *mac_address);
void FreeIPC(IPC *ipc);
bool IsIPCConnected(IPC *ipc);
void IPCSetSockEventWhenRecvL2Packet(IPC *ipc, SOCK_EVENT *e);
void IPCSendL2(IPC *ipc, void *data, UINT size);
void IPCSendIPv4(IPC *ipc, void *data, UINT size);
BLOCK *IPCRecvL2(IPC *ipc);
BLOCK *IPCRecvIPv4(IPC *ipc);
void IPCProcessInterrupts(IPC *ipc);
void IPCProcessL3Events(IPC *ipc);
void IPCProcessL3EventsEx(IPC *ipc, UINT64 now);
bool IPCSetIPv4Parameters(IPC *ipc, IP *ip, IP *subnet, IP *gw, DHCP_CLASSLESS_ROUTE_TABLE *rt);
IPC_ARP *IPCNewARP(IP *ip, UCHAR *mac_address);
void IPCFreeARP(IPC_ARP *a);
int IPCCmpArpTable(void *p1, void *p2);
void IPCSendIPv4Unicast(IPC *ipc, void *data, UINT size, IP *next_ip);
IPC_ARP *IPCSearchArpTable(IPC *ipc, IP *ip);
void IPCSendIPv4WithDestMacAddr(IPC *ipc, void *data, UINT size, UCHAR *dest_mac_addr);
void IPCFlushArpTable(IPC *ipc);
void IPCFlushArpTableEx(IPC *ipc, UINT64 now);
void IPCProcessArp(IPC *ipc, BLOCK *b);
void IPCAssociateOnArpTable(IPC *ipc, IP *ip, UCHAR *mac_address);
bool IsValidUnicastMacAddress(UCHAR *mac);
bool IsValidUnicastIPAddress4(IP *ip);
bool IsValidUnicastIPAddressUINT4(UINT ip);
DHCPV4_DATA *IPCSendDhcpRequest(IPC *ipc, IP *dest_ip, UINT tran_id, DHCP_OPTION_LIST *opt, UINT expecting_code, UINT timeout, TUBE *discon_poll_tube);
BUF *IPCBuildDhcpRequest(IPC *ipc, IP *dest_ip, UINT tran_id, DHCP_OPTION_LIST *opt);
BUF *IPCBuildDhcpRequestOptions(IPC *ipc, DHCP_OPTION_LIST *opt);
bool IPCDhcpAllocateIP(IPC *ipc, DHCP_OPTION_LIST *opt, TUBE *discon_poll_tube);
bool IPCDhcpRequestInformIP(IPC *ipc, DHCP_OPTION_LIST *opt, TUBE *discon_poll_tube, IP *client_ip);
void IPCDhcpRenewIP(IPC *ipc, IP *dhcp_server);
void IPCDhcpFreeIP(IPC *ipc, IP *dhcp_server);
IPC_ASYNC *NewIPCAsync(CEDAR *cedar, IPC_PARAM *param, SOCK_EVENT *sock_event);
void IPCAsyncThreadProc(THREAD *thread, void *param);
void FreeIPCAsync(IPC_ASYNC *a);

bool ParseAndExtractMsChapV2InfoFromPassword(IPC_MSCHAP_V2_AUTHINFO *d, char *password);

#endif	// IPC_H
