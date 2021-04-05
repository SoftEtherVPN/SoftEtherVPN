// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_L2TP.h
// Header of Proto_L2TP.c

#ifndef	PROTO_L2TP_H
#define	PROTO_L2TP_H

#include "CedarType.h"

#include "Mayaqua/Network.h"

// Check the sequence number
#define	L2TP_SEQ_LT(a, b)			(((USHORT)(((USHORT)(a)) - ((USHORT)(b)))) & 0x8000)
#define	L2TP_SEQ_EQ(a, b)			((USHORT)(a) == (USHORT)(b))

//// Constants

// Client string
#define L2TP_IPC_CLIENT_NAME_TAG		"L2TP VPN Client - %s"
#define L2TP_IPC_CLIENT_NAME_NO_TAG		"L2TP VPN Client"
#define	L2TP_IPC_POSTFIX				"L2TP"

// L2TP vendor name
#define	L2TP_VENDOR_NAME				"L2TP"

// L2TP packet retransmission interval
#define	L2TP_PACKET_RESEND_INTERVAL		500

// Timeout for L2TP tunnel disconnecting completion
#define	L2TP_TUNNEL_DISCONNECT_TIMEOUT	3000

// Timeout for L2TP session disconnection completion
#define	L2TP_SESSION_DISCONNECT_TIMEOUT	3000

// Time-out interval of L2TP tunnel
#define	L2TP_TUNNEL_TIMEOUT				(60 * 1000)

// Transmission interval of L2TP Hello
#define	L2TP_HELLO_INTERVAL				(8801)

// Threshold number of registered items in the transmission queue for suppressing the L2TP Hello transmission
#define	L2TP_HELLO_SUPRESS_MAX_THRETHORD_NUM_SEND_QUEUE		32

// Quota
#define	L2TP_QUOTA_MAX_NUM_TUNNELS_PER_IP		1000			// Number of L2TP sessions per IP address
#define	L2TP_QUOTA_MAX_NUM_TUNNELS				30000			// Limit of the number of sessions
#define	L2TP_QUOTA_MAX_NUM_SESSIONS_PER_TUNNEL	1024		// Max sessions in a tunnel

// L2TP window size
#define	L2TP_WINDOW_SIZE				16

// L2TP packet header bit mask
#define	L2TP_HEADER_BIT_TYPE			0x80	// Type
#define	L2TP_HEADER_BIT_LENGTH			0x40	// Length
#define	L2TP_HEADER_BIT_SEQUENCE		0x08	// Sequence
#define	L2TP_HEADER_BIT_OFFSET			0x02	// Offset
#define	L2TP_HEADER_BIT_PRIORITY		0x01	// Priority
#define	L2TP_HEADER_BIT_VER				0x0F	// Version

// L2TP AVP header bit mask
#define	L2TP_AVP_BIT_MANDATORY			0x80	// Mandatory
#define	L2TP_AVP_BIT_HIDDEN				0x40	// Hidden
#define	L2TP_AVP_LENGTH					0x3FF	// Length

// AVP value
#define	L2TP_AVP_TYPE_MESSAGE_TYPE		0		// Message Type
#define	L2TP_AVP_TYPE_RESULT_CODE		1		// Result Code
#define	L2TP_AVP_TYPE_PROTOCOL_VERSION	2		// Protocol Version
#define	L2TP_AVP_TYPE_FRAME_CAP			3		// Framing Capabilities
#define	L2TP_AVP_TYPE_BEARER_CAP		4		// Bearer Capabilities
#define	L2TP_AVP_TYPE_TIE_BREAKER		5		// Tie Breaker
#define	L2TP_AVP_TYPE_HOST_NAME			7		// Host Name
#define	L2TP_AVP_TYPE_VENDOR_NAME		8		// Vendor Name
#define	L2TP_AVP_TYPE_ASSIGNED_TUNNEL	9		// Assigned Tunnel
#define	L2TP_AVP_TYPE_RECV_WINDOW_SIZE	10		// Receive Window Size
#define	L2TP_AVP_TYPE_ASSIGNED_SESSION	14		// Assigned Session ID
#define	L2TP_AVP_TYPE_CALL_SERIAL		15		// Call Serial Number
#define	L2TP_AVP_TYPE_PPP_DISCONNECT_CAUSE	46	// PPP Disconnect Cause Code
#define	L2TP_AVP_TYPE_V3_ROUTER_ID		60		// Router ID
#define	L2TP_AVP_TYPE_V3_TUNNEL_ID		61		// Assigned Control Connection ID
#define	L2TP_AVP_TYPE_V3_PW_CAP_LIST	62		// Pseudowire Capabilities List
#define	L2TP_AVP_TYPE_V3_SESSION_ID_LOCAL	63	// Local Session ID
#define	L2TP_AVP_TYPE_V3_SESSION_ID_REMOTE	64	// Remote Session ID
#define	L2TP_AVP_TYPE_V3_PW_TYPE		68		// Pseudowire Type
#define	L2TP_AVP_TYPE_V3_CIRCUIT_STATUS	71

// Message Type value
#define	L2TP_MESSAGE_TYPE_SCCRQ			1		// Start-Control-Connection-Request
#define	L2TP_MESSAGE_TYPE_SCCRP			2		// Start-Control-Connection-Reply
#define	L2TP_MESSAGE_TYPE_SCCCN			3		// Start-Control-Connection-Connected
#define	L2TP_MESSAGE_TYPE_STOPCCN		4		// Stop-Control-Connection-Notification
#define	L2TP_MESSAGE_TYPE_HELLO			6		// Hello
#define	L2TP_MESSAGE_TYPE_ICRQ			10		// Incoming-Call-Request
#define	L2TP_MESSAGE_TYPE_ICRP			11		// Incoming-Call-Reply
#define	L2TP_MESSAGE_TYPE_ICCN			12		// Incoming-Call-Connected
#define	L2TP_MESSAGE_TYPE_CDN			14		// Call-Disconnect-Notify

// Type of L2TPv3 virtual network
#define	L2TPV3_PW_TYPE_ETHERNET			5		// Ethernet
#define	L2TPV3_PW_TYPE_ETHERNET_VLAN	4		// Ethernet VLAN

// L2TPv3 vendor unique value
#define	L2TP_AVP_VENDOR_ID_CISCO		9		// Cisco Systems
#define	L2TPV3_CISCO_AVP_TUNNEL_ID		1		// Assigned Connection ID
#define	L2TPV3_CISCO_AVP_PW_CAP_LIST	2		// Pseudowire Capabilities List
#define	L2TPV3_CISCO_AVP_SESSION_ID_LOCAL	3	// Local Session ID
#define	L2TPV3_CISCO_AVP_SESSION_ID_REMOTE	4	// Remote Session ID
#define	L2TPV3_CISCO_AVP_PW_TYPE			7	// Pseudowire Type
#define	L2TPV3_CISCO_AVP_DRAFT_AVP_VERSION	10	// Draft AVP Version



//// Types

// L2TP queue
struct L2TP_QUEUE
{
	BUF *Buf;									// Data
	USHORT Ns;									// Sequence number
	UINT64 NextSendTick;						// Scheduled time to be sent next
	L2TP_PACKET *L2TPPacket;					// L2TP packet data
};

// L2TP AVP value
struct L2TP_AVP
{
	bool Mandatory;								// Force bit
	UINT Length;								// Overall length
	USHORT VendorID;							// Vendor ID
	USHORT Type;								// Type
	UINT DataSize;								// Data size
	void *Data;									// Data body
};

// L2TP packet
struct L2TP_PACKET
{
	bool IsControl;								// Whether it's a control message
	bool HasLength;								// Whether there is length bit
	bool HasSequence;							// Whether there is sequence bit
	bool HasOffset;								// Whether there is offset bit
	bool IsPriority;							// Whether priority packet
	bool IsZLB;									// Zero Length Bit
	bool IsYamahaV3;							// L2TPv3 on YAMAHA
	UINT Ver;									// Version
	UINT Length;								// Length
	UINT TunnelId;								// Tunnel ID
	UINT SessionId;								// Session ID
	USHORT Ns, Nr;								// Sequence number
	UINT OffsetSize;							// Offset size
	UINT DataSize;								// Data size
	void *Data;									// Data body
	LIST *AvpList;								// AVP list
	UINT MessageType;							// Message type
};

// L2TP session
struct L2TP_SESSION
{
	L2TP_TUNNEL *Tunnel;						// Parent L2TP tunnel
	bool IsV3;									// L2TPv3
	bool IsCiscoV3;								// L2TPv3 for Cisco
	UINT SessionId1;							// Session ID (server -> client direction)
	UINT SessionId2;							// Session ID (client -> server direction)
	bool Established;							// Established
	bool WantToDisconnect;						// Whether to want to disconnect
	bool Disconnecting;							// Whether disconnected
	UINT64 DisconnectTimeout;					// Disconnection completion time-out
	bool HasThread;								// Whether have a thread
	THREAD *Thread;								// Thread
	PPP_SESSION* PPPSession;						// Underlying PPP session
	TUBE *TubeSend;								// Tube of PPP to L2TP direction
	TUBE *TubeRecv;								// Tube of L2TP to PPP direction
	UINT PseudowireType;						// Type of L2TPv3 virtual line
	ETHERIP_SERVER *EtherIP;					// EtherIP server
};

// L2TP tunnel
struct L2TP_TUNNEL
{
	bool IsV3;									// L2TPv3
	bool IsCiscoV3;								// L2TPv3 for Cisco
	bool IsYamahaV3;							// L2TPv3 for YAMAHA
	IP ClientIp;								// Client IP address
	UINT ClientPort;							// Client port number
	IP ServerIp;								// Server IP address
	UINT ServerPort;							// Server port number
	UINT TunnelId1;								// Tunnel ID (server -> client direction)
	UINT TunnelId2;								// Tunnel ID (client -> server direction)
	char HostName[MAX_SIZE];					// Destination host name
	char VendorName[MAX_SIZE];					// Destination vendor name
	LIST *SessionList;							// L2TP session list
	LIST *SendQueue;							// Transmission queue
	LIST *RecvQueue;							// Reception queue
	USHORT NextNs;								// Value of Ns of the packet to be sent next
	USHORT LastNr;								// Value of NR received in the last
	bool Established;							// Whether the tunnel is established
	bool StateChanged;							// Whether the state have changed
	bool WantToDisconnect;						// Whether to want to disconnect
	bool Disconnecting;							// Whether disconnected
	UINT64 DisconnectTimeout;					// Disconnection completion time-out
	UINT64 LastRecvTick;						// Time which the data has been received at last
	bool Timedout;								// Whether the time-out
	UINT64 LastHelloSent;						// Time which the data has been sent at last
};

// L2TP server
struct L2TP_SERVER
{
	CEDAR *Cedar;
	UINT64 Now;									// Current time
	LIST *SendPacketList;						// Transmission packet
	LIST *TunnelList;							// Tunnel list
	INTERRUPT_MANAGER *Interrupts;				// Interrupt manager
	SOCK_EVENT *SockEvent;						// SockEvent
	bool Halt;									// Start the shutdown
	bool Halting;								// During shutdown
	bool HaltCompleted;							// Shutdown is complete
	EVENT *HaltCompletedEvent;					// Stopping completion event
	LIST *ThreadList;							// Thread list
	char CryptName[MAX_SIZE];					// Cipher algorithm name
	IKE_SERVER *IkeServer;						// IKE server (Only if associated)
	IKE_CLIENT *IkeClient;						// IKE client (Only if associated)
	bool IsIPsecIPv6;							// Whether it's IPv6
	UINT CryptBlockSize;						// Cipher block size of the upper layer
	TUBE_FLUSH_LIST *FlushList;					// Tube Flush List
};


//// Function prototype
L2TP_SERVER *NewL2TPServer(CEDAR *cedar);
L2TP_SERVER *NewL2TPServerEx(CEDAR *cedar, IKE_SERVER *ike, bool is_ipv6, UINT crypt_block_size);
UINT GetNumL2TPTunnelsByClientIP(L2TP_SERVER *l2tp, IP *client_ip);
void SetL2TPServerSockEvent(L2TP_SERVER *l2tp, SOCK_EVENT *e);
void FreeL2TPServer(L2TP_SERVER *l2tp);
void StopL2TPServer(L2TP_SERVER *l2tp, bool no_wait);
void ProcL2TPPacketRecv(L2TP_SERVER *l2tp, UDPPACKET *p);
L2TP_PACKET *ParseL2TPPacket(UDPPACKET *p);
BUF *BuildL2TPPacketData(L2TP_PACKET *pp, L2TP_TUNNEL *t);
L2TP_AVP *GetAVPValue(L2TP_PACKET *p, UINT type);
L2TP_AVP *GetAVPValueEx(L2TP_PACKET *p, UINT type, UINT vendor_id);
L2TP_TUNNEL *NewL2TPTunnel(L2TP_SERVER *l2tp, L2TP_PACKET *p, UDPPACKET *udp);
UINT GenerateNewTunnelId(L2TP_SERVER *l2tp, IP *client_ip);
UINT GenerateNewTunnelIdEx(L2TP_SERVER *l2tp, IP *client_ip, bool is_32bit);
void FreeL2TPTunnel(L2TP_TUNNEL *t);
L2TP_TUNNEL *GetTunnelFromId(L2TP_SERVER *l2tp, IP *client_ip, UINT tunnel_id, bool is_v3);
L2TP_TUNNEL *GetTunnelFromIdOfAssignedByClient(L2TP_SERVER *l2tp, IP *client_ip, UINT tunnel_id);
L2TP_TUNNEL *GetTunnelFromIdOfAssignedByClientEx(L2TP_SERVER *l2tp, IP *client_ip, UINT tunnel_id, bool is_v3);
void SendL2TPControlPacket(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, UINT session_id, L2TP_PACKET *p);
void SendL2TPControlPacketMain(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_QUEUE *q);
void SendL2TPDataPacket(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s, void *data, UINT size);
void FreeL2TPQueue(L2TP_QUEUE *q);
void L2TPAddInterrupt(L2TP_SERVER *l2tp, UINT64 next_tick);
void L2TPSendUDP(L2TP_SERVER *l2tp, UDPPACKET *p);
void L2TPProcessInterrupts(L2TP_SERVER *l2tp);
L2TP_PACKET *NewL2TPControlPacket(UINT message_type, bool is_v3);
L2TP_AVP *NewAVP(USHORT type, bool mandatory, USHORT vendor_id, void *data, UINT data_size);
int CmpL2TPQueueForRecv(void *p1, void *p2);
void L2TPProcessRecvControlPacket(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_PACKET *p);
L2TP_SESSION *GetSessionFromId(L2TP_TUNNEL *t, UINT session_id);
L2TP_SESSION *GetSessionFromIdAssignedByClient(L2TP_TUNNEL *t, UINT session_id);
L2TP_SESSION *NewL2TPSession(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, UINT session_id_by_client);
UINT GenerateNewSessionId(L2TP_TUNNEL *t);
UINT GenerateNewSessionIdEx(L2TP_TUNNEL *t, bool is_32bit);
void FreeL2TPSession(L2TP_SESSION *s);
void DisconnectL2TPSession(L2TP_TUNNEL *t, L2TP_SESSION *s);
void DisconnectL2TPTunnel(L2TP_TUNNEL *t);
void StartL2TPThread(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s);
void StopL2TPThread(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s);
UINT CalcL2TPMss(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s);
UINT GenerateNewSessionIdForL2TPv3(L2TP_SERVER *l2tp);
L2TP_SESSION *SearchL2TPSessionById(L2TP_SERVER *l2tp, bool is_v3, UINT id);
void L2TPSessionManageEtherIPServer(L2TP_SERVER *l2tp, L2TP_SESSION *s);

#endif	// PROTO_L2TP_H
