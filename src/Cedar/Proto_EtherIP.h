// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_EtherIP.h
// Header of Proto_EtherIP.c

#ifndef	PROTO_ETHERIP_H
#define	PROTO_ETHERIP_H

//// Macro


//// Constants
#define	ETHERIP_VPN_CONNECT_RETRY_INTERVAL		(15 * 1000)	// VPN connection retry interval
#define	ETHERIP_CLIENT_NAME						"EtherIP Client"
#define	ETHERIP_POSTFIX							"ETHERIP"
#define	ETHERIP_L2TPV3_CLIENT_NAME				"L2TPv3 Client"
#define	ETHERIP_L2TPV3_CLIENT_NAME_EX			"L2TPv3 Client - %s"
#define	ETHERIP_L2TPV3_POSTFIX					"L2TPV3"

//// Type

// EtherIP server
struct ETHERIP_SERVER
{
	REF *Ref;
	CEDAR *Cedar;
	IPSEC_SERVER *IPsec;
	LOCK *Lock;
	UINT Id;
	IKE_SERVER *Ike;
	UINT64 Now;									// Current time
	INTERRUPT_MANAGER *Interrupts;				// Interrupt manager
	SOCK_EVENT *SockEvent;						// SockEvent
	char CryptName[MAX_SIZE];					// Cipher algorithm name
	LIST *SendPacketList;						// Transmission packet list
	UINT64 LastConnectFailedTick;				// Time that it fails to connect at the last
	IPC *Ipc;									// IPC
	THREAD *IpcConnectThread;					// IPC connection thread
	IPSEC_SERVICES CurrentIPSecServiceSetting;	// Copy of the current IPsec service settings
	IP ClientIP, ServerIP;
	UINT ClientPort, ServerPort;
	bool IsTunnelMode;							// Whether the IPsec is in the tunnel mode
	UINT CryptBlockSize;						// Encryption block size of IPsec
	char ClientId[MAX_SIZE];					// Client ID has been presented by the IPsec connection
	UINT LastEtherIPSettingVerNo;				// Version number of EtherIP settings last checked
	ETHERIP_ID CurrentEtherIPIdSetting;			// Current EtherIP ID settings
	bool L2TPv3;								// L2TPv3 mode
	char VendorName[MAX_SIZE];					// Vendor name
};


//// Function prototype
ETHERIP_SERVER *NewEtherIPServer(CEDAR *cedar, IPSEC_SERVER *ipsec, IKE_SERVER *ike,
								 IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, char *crypt_name,
								 bool is_tunnel_mode, UINT crypt_block_size,
								 char *client_id, UINT id);
void ReleaseEtherIPServer(ETHERIP_SERVER *s);
void CleanupEtherIPServer(ETHERIP_SERVER *s);
void SetEtherIPServerSockEvent(ETHERIP_SERVER *s, SOCK_EVENT *e);
void EtherIPProcInterrupts(ETHERIP_SERVER *s);
void EtherIPProcRecvPackets(ETHERIP_SERVER *s, BLOCK *b);
void EtherIPIpcConnectThread(THREAD *t, void *p);
UINT CalcEtherIPTcpMss(ETHERIP_SERVER *s);


#endif	// PROTO_ETHERIP_H
