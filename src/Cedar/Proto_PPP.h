// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_PPP.h
// Header of Proto_PPP.c

#ifndef	PROTO_PPP_H
#define	PROTO_PPP_H

#include "CedarType.h"

#include "Mayaqua/TcpIp.h"

//// Macro
#define	PPP_LCP_CODE_IS_NEGATIVE(c)			((c) == PPP_LCP_CODE_NAK || (c) == PPP_LCP_CODE_REJECT || (c) == PPP_LCP_CODE_CODE_REJECT || (c) == PPP_LCP_CODE_PROTOCOL_REJECT)
#define	PPP_LCP_CODE_IS_REQUEST(c)			((c) == PPP_LCP_CODE_REQ)
#define	PPP_LCP_CODE_IS_RESPONSE(c)			((c) == PPP_LCP_CODE_ACK || (c) == PPP_LCP_CODE_NAK || (c) == PPP_LCP_CODE_REJECT || (c) == PPP_LCP_CODE_PROTOCOL_REJECT)
#define	PPP_LCP_CODE_IS_WITH_OPTION_LIST(c)	((c) == PPP_LCP_CODE_REQ || (c) == PPP_LCP_CODE_ACK || (c) == PPP_LCP_CODE_NAK || (c) == PPP_LCP_CODE_REJECT)

#define	PPP_PAP_CODE_IS_REQUEST(c)			((c) == PPP_PAP_CODE_REQ)
#define	PPP_PAP_CODE_IS_RESPONSE(c)			((c) == PPP_PAP_CODE_ACK || (c) == PPP_PAP_CODE_NAK)

#define	PPP_CHAP_CODE_IS_REQUEST(c)			((c) == PPP_CHAP_CODE_CHALLENGE || (c) == PPP_CHAP_CODE_SUCCESS || (c) == PPP_CHAP_CODE_FAILURE)
#define	PPP_CHAP_CODE_IS_RESPONSE(c)		((c) == PPP_CHAP_CODE_RESPONSE)

#define	PPP_EAP_CODE_IS_REQUEST(c)			((c) == PPP_EAP_CODE_REQUEST)
#define	PPP_EAP_CODE_IS_RESPONSE(c)			((c) == PPP_EAP_CODE_RESPONSE || (c) == PPP_EAP_CODE_SUCCESS || (c) == PPP_EAP_CODE_FAILURE)

#define	PPP_CODE_IS_RESPONSE(protocol, c)	((((protocol) == PPP_PROTOCOL_LCP || (protocol) == PPP_PROTOCOL_IPCP || (protocol) == PPP_PROTOCOL_IPV6CP) && PPP_LCP_CODE_IS_RESPONSE(c)) || (((protocol) == PPP_PROTOCOL_PAP) && PPP_PAP_CODE_IS_RESPONSE(c)) || (((protocol) == PPP_PROTOCOL_CHAP) && PPP_CHAP_CODE_IS_RESPONSE(c)) || (((protocol) == PPP_PROTOCOL_EAP) && PPP_EAP_CODE_IS_RESPONSE(c)))
#define	PPP_CODE_IS_REQUEST(protocol, c)	((((protocol) == PPP_PROTOCOL_LCP || (protocol) == PPP_PROTOCOL_IPCP || (protocol) == PPP_PROTOCOL_IPV6CP) && PPP_LCP_CODE_IS_REQUEST(c)) || (((protocol) == PPP_PROTOCOL_PAP) && PPP_PAP_CODE_IS_REQUEST(c)) || (((protocol) == PPP_PROTOCOL_CHAP) && PPP_CHAP_CODE_IS_REQUEST(c)) || (((protocol) == PPP_PROTOCOL_EAP) && PPP_EAP_CODE_IS_REQUEST(c)))
#define	PPP_CODE_IS_WITH_OPTION_LIST(protocol, c) ((((protocol) == PPP_PROTOCOL_LCP || (protocol) == PPP_PROTOCOL_IPCP || (protocol) == PPP_PROTOCOL_IPV6CP) && PPP_LCP_CODE_IS_WITH_OPTION_LIST(c)) || false)

#define	PPP_IS_SUPPORTED_PROTOCOL(p)		((p) == PPP_PROTOCOL_LCP || (p) == PPP_PROTOCOL_PAP || (p) == PPP_PROTOCOL_CHAP || (p) == PPP_PROTOCOL_IPCP || (p) == PPP_PROTOCOL_IPV6CP || (p) == PPP_PROTOCOL_IP || (p) == PPP_PROTOCOL_IPV6 || (p) == PPP_PROTOCOL_EAP )

#define PPP_STATUS_IS_UNAVAILABLE(c)		((c) == PPP_STATUS_FAIL || (c) == PPP_STATUS_AUTH_FAIL || (c) == PPP_STATUS_CLOSING || (c) == PPP_STATUS_CLOSING_WAIT || (c) == PPP_STATUS_CLOSED)

//// Constants

// Time-out value
#define	PPP_PACKET_RECV_TIMEOUT			(15 * 1000)	// Timeout until the next packet is received (3/4 of default policy)
#define	PPP_PACKET_RESEND_INTERVAL		(3 * 1000)	// Retransmission interval of the last packet
#define	PPP_TERMINATE_TIMEOUT			2000		// Timeout value to complete disconnection after requesting to disconnect in the PPP
#define	PPP_ECHO_SEND_INTERVAL			4792		// Transmission interval of PPP Echo Request
#define	PPP_DATA_TIMEOUT				(20 * 1000)	// Communication time-out (from default policy)

// MRU
#define	PPP_MRU_DEFAULT					1500		// Default value
#define	PPP_MRU_MIN						100			// Minimum value
#define	PPP_MRU_MAX						1500		// Maximum value

// PPP protocol (for control)
#define	PPP_PROTOCOL_LCP				0xc021
#define	PPP_PROTOCOL_PAP				0xc023
#define	PPP_PROTOCOL_IPCP				0x8021
#define	PPP_PROTOCOL_CHAP				0xc223
#define	PPP_PROTOCOL_EAP				0xc227
#define	PPP_PROTOCOL_IPV6CP				0x8057

// PPP protocol (for transfer)
#define	PPP_PROTOCOL_IP					0x0021
#define	PPP_PROTOCOL_IPV6				0x0057

// LCP code
#define	PPP_LCP_CODE_REQ				1
#define	PPP_LCP_CODE_ACK				2
#define	PPP_LCP_CODE_NAK				3
#define	PPP_LCP_CODE_REJECT				4
#define	PPP_LCP_CODE_TERMINATE_REQ		5
#define	PPP_LCP_CODE_TERMINATE_ACK		6
#define	PPP_LCP_CODE_CODE_REJECT		7
#define	PPP_LCP_CODE_PROTOCOL_REJECT	8
#define	PPP_LCP_CODE_ECHO_REQUEST		9
#define	PPP_LCP_CODE_ECHO_RESPONSE		10
#define	PPP_LCP_CODE_DROP				11
#define	PPP_LCP_CODE_IDENTIFICATION		12

// PAP Code
#define	PPP_PAP_CODE_REQ				1
#define	PPP_PAP_CODE_ACK				2
#define	PPP_PAP_CODE_NAK				3

// CHAP code
#define	PPP_CHAP_CODE_CHALLENGE			1
#define	PPP_CHAP_CODE_RESPONSE			2
#define	PPP_CHAP_CODE_SUCCESS			3
#define	PPP_CHAP_CODE_FAILURE			4

// LCP Option Type
#define	PPP_LCP_OPTION_MRU				1
#define	PPP_LCP_OPTION_AUTH				3

// IPCP option type
#define	PPP_IPCP_OPTION_IP				3
#define	PPP_IPCP_OPTION_DNS1			129
#define	PPP_IPCP_OPTION_DNS2			131
#define	PPP_IPCP_OPTION_WINS1			130
#define	PPP_IPCP_OPTION_WINS2			132

// IPV6CP option type
#define	PPP_IPV6CP_OPTION_EUI			1

// EAP codes
#define	PPP_EAP_CODE_REQUEST			1
#define	PPP_EAP_CODE_RESPONSE			2
#define	PPP_EAP_CODE_SUCCESS			3
#define	PPP_EAP_CODE_FAILURE			4

// EAP types
#define	PPP_EAP_TYPE_IDENTITY			1
#define	PPP_EAP_TYPE_NOTIFICATION		2
#define	PPP_EAP_TYPE_NAK				3
#define	PPP_EAP_TYPE_TLS				13

// EAP-TLS Flags
#define	PPP_EAP_TLS_FLAG_NONE			0
#define	PPP_EAP_TLS_FLAG_TLS_LENGTH		1 << 7
#define	PPP_EAP_TLS_FLAG_FRAGMENTED		1 << 6
#define	PPP_EAP_TLS_FLAG_SSLSTARTED		1 << 5

// Authentication protocol
#define	PPP_LCP_AUTH_PAP				PPP_PROTOCOL_PAP
#define	PPP_LCP_AUTH_CHAP				PPP_PROTOCOL_CHAP
#define	PPP_LCP_AUTH_EAP				PPP_PROTOCOL_EAP

// Algorithm of CHAP
#define	PPP_CHAP_ALG_MS_CHAP_V2			0x81

// Link status
#define	PPP_STATUS_CONNECTED			0x1
#define	PPP_STATUS_BEFORE_AUTH			0x10
#define	PPP_STATUS_AUTHENTICATING		0x11
#define	PPP_STATUS_AUTH_SUCCESS			0x19
#define	PPP_STATUS_NETWORK_LAYER		0x20
#define	PPP_STATUS_CLOSING				0x100
#define	PPP_STATUS_CLOSING_WAIT			0x101
#define	PPP_STATUS_CLOSED				0x110
#define	PPP_STATUS_FAIL					0x1000
#define	PPP_STATUS_AUTH_FAIL			0x1010

#define	PPP_UNSPECIFIED					0xFFFF

//// Type

// IP options used in the PPP
struct PPP_IPOPTION
{
	IP IpAddress;						// IP address
	IP DnsServer1, DnsServer2;			// DNS server address
	IP WinsServer1, WinsServer2;		// WINS server address
};

// PPP packet
struct PPP_PACKET
{
	USHORT Protocol;					// Protocol
	bool IsControl;						// Whether or not the control packet
	PPP_LCP *Lcp;						// LCP packet data
	UINT DataSize;						// Data size
	void *Data;							// Data body
};

// PPP LCP packet
struct PPP_LCP
{
	UCHAR Code;							// Code
	UCHAR Id;							// ID
	UCHAR MagicNumber[4];				// Magic number
	LIST *OptionList;					// PPP options list
	void *Data;							// Data
	UINT DataSize;						// Data size
};

// PPP Options
struct PPP_OPTION
{
	UCHAR Type;							// Type of option
	UINT DataSize;						// Data size
	UCHAR Data[254];					// Data
	bool IsSupported;					// Flag of whether it is supported
	bool IsAccepted;					// Flag for whether accepted
	UCHAR AltData[254];					// Alternate data when it isn't accepted
	UINT AltDataSize;					// Alternate data size
};

#ifdef	OS_WIN32
#pragma pack(push, 1)
#else	// OS_WIN32
#pragma pack(1)
#endif


// PPP EAP packet
// EAP is a subset of LCP, sharing Code and Id. The Data field is then mapped to this structure
// We got 8 bytes of size before this structure
struct PPP_EAP
{
	UCHAR Type;
	union {
		UCHAR Data[0];
		struct PPP_EAP_TLS
		{
			UCHAR Flags;
			union {
				UCHAR TlsDataWithoutLength[0];
				struct
				{
					UINT TlsLength;
					UCHAR Data[0];
				} TlsDataWithLength;
			};
		} Tls;
	};
} GCC_PACKED;

#ifdef	OS_WIN32
#pragma pack(pop)
#else	// OS_WIN32
#pragma pack()
#endif

struct PPP_EAP_TLS_CONTEXT
{
	SSL_PIPE *SslPipe;
	DH_CTX *Dh;
	struct SslClientCertInfo ClientCert;
	UCHAR *CachedBufferRecv;
	UCHAR *CachedBufferRecvPntr;
	UCHAR *CachedBufferSend;
	UCHAR *CachedBufferSendPntr;
};

// PPP request resend
struct PPP_REQUEST_RESEND
{
	PPP_PACKET *Packet;
	UCHAR Id;
	UINT64 ResendTime;
	UINT64 TimeoutTime;
};

// PPP next packet struct
struct PPP_DELAYED_PACKET
{
	PPP_PACKET *Packet;
	UINT DelayTicks;
};

// PPP session
struct PPP_SESSION
{
	CEDAR *Cedar;						// Cedar
	IP ClientIP;						// Client IP address
	UINT ClientPort;					// Client port
	IP ServerIP;						// Server IP address
	UINT ServerPort;					// Server port
	TUBE *TubeSend;						// Sending tube
	TUBE *TubeRecv;						// Receiving tube
	UCHAR NextId;						// ID to be used next
	UINT Mru1;							// MRU (server -> client)
	UINT Mru2;							// MRU (client -> server)
	LIST *RecvPacketList;				// Received packet list
	bool IsTerminateReceived;			// Whether a Terminate has been received
	UINT DisconnectCauseCode;			// L2TP disconnect cause code
	UINT DisconnectCauseDirection;		// L2TP disconnect cause direction code
	IPC *Ipc;							// IPC
	bool ClientLCPOptionDetermined;		// LCP option from the client has been determined
	char Postfix[MAX_SIZE];				// Postfix of the session name
	char ClientHostname[MAX_SIZE];		// Client host name
	char ClientSoftwareName[MAX_SIZE];	// Client software name
	UINT64 NextEchoSendTime;			// Time to send Echo Request next
	UINT64 LastRecvTime;				// Time which the data has been received last
	DHCP_OPTION_LIST ClientAddressOption;	// Client address option
	bool DhcpIpAllocTried;				// Whether the request for an IP address is already attempted by DHCP
	bool DhcpIpInformTried;				// Whether the acquirement for an IP information is already attempted by DHCP
	bool DhcpAllocated;					// IP address is assigned by DHCP
	bool UseStaticIPAddress;			// Use a static IP address that is specified by the client
	UINT64 DhcpRenewInterval;			// DHCP update interval
	UINT64 DhcpNextRenewTime;			// DHCP renewal time of the next
	char CryptName[MAX_SIZE];			// Cipher algorithm name
	UINT AdjustMss;						// MSS value
	TUBE_FLUSH_LIST *FlushList;			// Tube Flush List
	bool EnableMSCHAPv2;				// Enable the MS-CHAP v2
	USHORT AuthProtocol;				// Authentication protocol
	bool AuthOk;						// Flag for whether the authentication was successful
	UCHAR MsChapV2_ServerChallenge[16];	// MS-CHAPv2 Server Challenge
	UCHAR MsChapV2_ClientChallenge[16];	// MS-CHAPv2 Client Challenge
	UCHAR MsChapV2_ClientResponse[24];	// MS-CHAPv2 Client Response
	UCHAR MsChapV2_ServerResponse[20];	// MS-CHAPv2 Server Response
	UINT MsChapV2_ErrorCode;			// Authentication failure error code of MS-CHAPv2
	UINT MsChapV2_PacketId;				// MS-CHAPv2 Packet ID

	bool MsChapV2_UseDoubleMsChapV2;	// Use the double-MSCHAPv2 technique
	EAP_CLIENT *EapClient;				// EAP client

	UCHAR ServerInterfaceId[8];			// Server IPv6CP Interface Identifier
	UCHAR ClientInterfaceId[8];			// Client IPv6CP Interface Identifier

	UINT PPPStatus;

	// EAP contexts
	UINT Eap_Protocol;					// Current EAP Protocol used
	UINT Eap_PacketId;					// EAP Packet ID;
	UCHAR Eap_Identity[MAX_SIZE];		// Received from client identity
	PPP_EAP_TLS_CONTEXT Eap_TlsCtx;		// Context information for EAP TLS. May be possibly reused for EAP TTLS?

	LIST *SentReqPacketList;			// Sent requests list

	PPP_PACKET *CurrentPacket;
	LIST *DelayedPackets;

	UINT64 PacketRecvTimeout;
	UINT64 DataTimeout;
	UINT64 UserConnectionTimeout;
	UINT64 UserConnectionTick;

	THREAD *SessionThread;				// Thread of the PPP session
};



// Function prototype

// Main dataloop
void PPPThread(THREAD *thread, void *param);

// Entry point
PPP_SESSION *NewPPPSession(CEDAR *cedar, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, TUBE *send_tube, TUBE *recv_tube, char *postfix, char *client_software_name, char *client_hostname, char *crypt_name, UINT adjust_mss);

// PPP processing functions
bool PPPRejectUnsupportedPacket(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPRejectUnsupportedPacketEx(PPP_SESSION *p, PPP_PACKET *pp, bool force);
bool PPPProcessRetransmissions(PPP_SESSION *p);
bool PPPSendEchoRequest(PPP_SESSION *p);
// Response packets
bool PPPProcessResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req);
bool PPPProcessLCPResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req);
bool PPPProcessCHAPResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req);
bool PPPProcessIPCPResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req);
bool PPPProcessEAPResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req);
bool PPPProcessIPv6CPResponsePacket(PPP_SESSION *p, PPP_PACKET *pp, PPP_PACKET *req);
// Request packets
bool PPPProcessRequestPacket(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPProcessLCPRequestPacket(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPProcessPAPRequestPacket(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPProcessIPCPRequestPacket(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPProcessEAPRequestPacket(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPProcessIPv6CPRequestPacket(PPP_SESSION *p, PPP_PACKET *pp);

// LCP option based packets utility
bool PPPRejectLCPOptions(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPRejectLCPOptionsEx(PPP_SESSION *p, PPP_PACKET *pp, bool simulate);
bool PPPNackLCPOptions(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPNackLCPOptionsEx(PPP_SESSION *p, PPP_PACKET *pp, bool simulate);
bool PPPAckLCPOptions(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPAckLCPOptionsEx(PPP_SESSION *p, PPP_PACKET *pp, bool simulate);

// PPP networking functions
// Send packets
bool PPPSendAndRetransmitRequest(PPP_SESSION *p, USHORT protocol, PPP_LCP *c);
bool PPPSendPacketAndFree(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPSendPacketEx(PPP_SESSION *p, PPP_PACKET *pp, bool no_flush);
// Receive packets
PPP_PACKET *PPPRecvPacket(PPP_SESSION *p, bool async);
// Helpers for delaying packets
PPP_PACKET *PPPGetNextPacket(PPP_SESSION *p);
void PPPAddNextPacket(PPP_SESSION *p, PPP_PACKET *pp, UINT delay);
int PPPDelayedPacketsComparator(void *a, void *b);
char PPPRelatedPacketComparator(PPP_PACKET *a, PPP_PACKET *b);

// PPP utility functions
// Packet structures creation utilities
PPP_LCP *NewPPPLCP(UCHAR code, UCHAR id);
PPP_OPTION *NewPPPOption(UCHAR type, void *data, UINT size);
// Packet parse utilities
PPP_PACKET *ParsePPPPacket(void *data, UINT size);
PPP_LCP *PPPParseLCP(USHORT protocol, void *data, UINT size);
bool PPPParseMSCHAP2ResponsePacket(PPP_SESSION *p, PPP_PACKET *req);
// Packet building utilities
BUF *BuildPPPPacketData(PPP_PACKET *pp);
BUF *BuildLCPData(PPP_LCP *c);
PPP_LCP *BuildMSCHAP2ChallengePacket(PPP_SESSION *p);
// IPCP packet utilities
bool PPPGetIPOptionFromLCP(PPP_IPOPTION *o, PPP_LCP *c);
bool PPPSetIPOptionToLCP(PPP_IPOPTION *o, PPP_LCP *c, bool only_modify);
bool PPPGetIPAddressValueFromLCP(PPP_LCP *c, UINT type, IP *ip);
bool PPPSetIPAddressValueToLCP(PPP_LCP *c, UINT type, IP *ip, bool only_modify);
// EAP packet utilities
bool PPPProcessEAPTlsResponse(PPP_SESSION *p, PPP_EAP *eap_packet, UINT eapTlsSize);
PPP_LCP *BuildEAPPacketEx(UCHAR code, UCHAR id, UCHAR type, UINT datasize);
PPP_LCP *BuildEAPTlsPacketEx(UCHAR code, UCHAR id, UCHAR type, UINT datasize, UCHAR flags);
PPP_LCP *BuildEAPTlsRequest(UCHAR id, UINT datasize, UCHAR flags);
// Other packet utilities
PPP_OPTION *PPPGetOptionValue(PPP_LCP *c, UCHAR type);
bool IsHubExistsWithLock(CEDAR *cedar, char *hubname);
void PPPSetStatus(PPP_SESSION *p, UINT status);

// Memory freeing functions
void FreePPPSession(PPP_SESSION *p);
void FreePPPLCP(PPP_LCP *c);
void FreePPPOptionList(LIST *o);
void FreePPPPacket(PPP_PACKET *pp);
void FreePPPPacketEx(PPP_PACKET *pp, bool no_free_struct);
void PPPFreeEapClient(PPP_SESSION *p);

// Utility functions used not only in PPP stack
bool PPPParseUsername(CEDAR *cedar, char *src, ETHERIP_ID *dst);
void GenerateNtPasswordHash(UCHAR *dst, char *password);
void GenerateNtPasswordHashHash(UCHAR *dst_hash, UCHAR *src_hash);
void MsChapV2Server_GenerateChallenge(UCHAR *dst);
void MsChapV2_GenerateChallenge8(UCHAR *dst, UCHAR *client_challenge, UCHAR *server_challenge, char *username);
void MsChapV2Client_GenerateResponse(UCHAR *dst, UCHAR *challenge8, UCHAR *nt_password_hash);
void MsChapV2Server_GenerateResponse(UCHAR *dst, UCHAR *nt_password_hash_hash, UCHAR *client_response, UCHAR *challenge8);
bool MsChapV2VerityPassword(IPC_MSCHAP_V2_AUTHINFO *d, char *password);
char *MsChapV2DoBruteForce(IPC_MSCHAP_V2_AUTHINFO *d, LIST *password_list);

#endif	// PROTO_PPP_H
