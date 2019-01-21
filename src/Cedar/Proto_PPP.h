// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_PPP.h
// Header of Proto_PPP.c

#ifndef	PROTO_PPP_H
#define	PROTO_PPP_H


//// Macro
#define	PPP_LCP_CODE_IS_NEGATIVE(c)			((c) == PPP_LCP_CODE_NAK || (c) == PPP_LCP_CODE_REJECT || (c) == PPP_LCP_CODE_CODE_REJECT || (c) == PPP_LCP_CODE_PROTOCOL_REJECT)
#define	PPP_LCP_CODE_IS_REQUEST(c)			((c) == PPP_LCP_CODE_REQ)
#define	PPP_LCP_CODE_IS_RESPONSE(c)			((c) == PPP_LCP_CODE_ACK || (c) == PPP_LCP_CODE_NAK || (c) == PPP_LCP_CODE_REJECT || (c) == PPP_LCP_CODE_PROTOCOL_REJECT)
#define	PPP_LCP_CODE_IS_WITH_OPTION_LIST(c)	((c) == PPP_LCP_CODE_REQ || (c) == PPP_LCP_CODE_ACK || (c) == PPP_LCP_CODE_NAK)

#define	PPP_PAP_CODE_IS_REQUEST(c)			((c) == PPP_PAP_CODE_REQ)
#define	PPP_PAP_CODE_IS_RESPONSE(c)			((c) == PPP_PAP_CODE_ACK || (c) == PPP_PAP_CODE_NAK)

#define	PPP_CODE_IS_RESPONSE(protocol, c)	((((protocol) == PPP_PROTOCOL_LCP || (protocol) == PPP_PROTOCOL_IPCP) && PPP_LCP_CODE_IS_RESPONSE(c)) || (((protocol) == PPP_PROTOCOL_PAP) && PPP_PAP_CODE_IS_RESPONSE(c)))
#define	PPP_CODE_IS_REQUEST(protocol, c)	((((protocol) == PPP_PROTOCOL_LCP || (protocol) == PPP_PROTOCOL_IPCP) && PPP_LCP_CODE_IS_REQUEST(c)) || (((protocol) == PPP_PROTOCOL_PAP) && PPP_PAP_CODE_IS_REQUEST(c)) || ((protocol) == PPP_PROTOCOL_CHAP))
#define	PPP_CODE_IS_WITH_OPTION_LIST(protocol, c) ((((protocol) == PPP_PROTOCOL_LCP || (protocol) == PPP_PROTOCOL_IPCP) && PPP_LCP_CODE_IS_WITH_OPTION_LIST(c)) || false)

#define	PPP_IS_SUPPORTED_PROTOCOL(p)		((p) == PPP_PROTOCOL_LCP || (p) == PPP_PROTOCOL_PAP || (p) == PPP_PROTOCOL_CHAP || (p) == PPP_PROTOCOL_IPCP || (p) == PPP_PROTOCOL_IP)


//// Constants

// Time-out value
#define	PPP_PACKET_RECV_TIMEOUT			10000		// Timeout until the next packet is received
#define	PPP_PACKET_RESEND_INTERVAL		1000		// Retransmission interval of the last packet
#define	PPP_TERMINATE_TIMEOUT			2000		// Timeout value to complete disconnection after requesting to disconnect in the PPP
#define	PPP_ECHO_SEND_INTERVAL			4792		// Transmission interval of PPP Echo Request
#define	PPP_DATA_TIMEOUT				(20 * 1000)	// Communication time-out

// MRU
#define	PPP_MRU_DEFAULT					1500		// Default value
#define	PPP_MRU_MIN						100			// Minimum value
#define	PPP_MRU_MAX						1500		// Maximum value

// PPP protocol (for control)
#define	PPP_PROTOCOL_LCP				0xc021
#define	PPP_PROTOCOL_PAP				0xc023
#define	PPP_PROTOCOL_IPCP				0x8021
#define	PPP_PROTOCOL_CHAP				0xc223

// PPP protocol (for transfer)
#define	PPP_PROTOCOL_IP					0x0021

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

// Authentication protocol
#define	PPP_LCP_AUTH_PAP				PPP_PROTOCOL_PAP
#define	PPP_LCP_AUTH_CHAP				PPP_PROTOCOL_CHAP

// Algorithm of CHAP
#define	PPP_CHAP_ALG_MS_CHAP_V2			0x81


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
	PPP_PACKET *LastStoredPacket;		// Packet that is stored at the last
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

	bool MsChapV2_UseDoubleMsChapV2;	// Use the double-MSCHAPv2 technieue
	EAP_CLIENT *EapClient;				// EAP client
};

// Function prototype
THREAD *NewPPPSession(CEDAR *cedar, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, TUBE *send_tube, TUBE *recv_tube, char *postfix, char *client_software_name, char *client_hostname, char *crypt_name, UINT adjust_mss);
void PPPThread(THREAD *thread, void *param);
void FreePPPSession(PPP_SESSION *p);
void FreePPPOptionList(LIST *o);
void FreePPPLCP(PPP_LCP *c);
PPP_LCP *NewPPPLCP(UCHAR code, UCHAR id);
PPP_LCP *ParseLCP(USHORT protocol, void *data, UINT size);
BUF *BuildLCPData(PPP_LCP *c);
PPP_OPTION *GetOptionValue(PPP_LCP *c, UCHAR type);
PPP_PACKET *ParsePPPPacket(void *data, UINT size);
void FreePPPPacket(PPP_PACKET *pp);
void FreePPPPacketEx(PPP_PACKET *pp, bool no_free_struct);
BUF *BuildPPPPacketData(PPP_PACKET *pp);
PPP_OPTION *NewPPPOption(UCHAR type, void *data, UINT size);
bool PPPSendPacket(PPP_SESSION *p, PPP_PACKET *pp);
bool PPPSendPacketEx(PPP_SESSION *p, PPP_PACKET *pp, bool no_flush);
PPP_PACKET *PPPRecvPacket(PPP_SESSION *p, bool async);
PPP_PACKET *PPPRecvPacketWithLowLayerProcessing(PPP_SESSION *p, bool async);
PPP_PACKET *PPPRecvPacketForCommunication(PPP_SESSION *p);
void PPPStoreLastPacket(PPP_SESSION *p, PPP_PACKET *pp);
void PPPCleanTerminate(PPP_SESSION *p);
bool PPPGetIPOptionFromLCP(PPP_IPOPTION *o, PPP_LCP *c);
bool PPPSetIPOptionToLCP(PPP_IPOPTION *o, PPP_LCP *c, bool only_modify);
bool PPPGetIPAddressValueFromLCP(PPP_LCP *c, UINT type, IP *ip);
bool PPPSetIPAddressValueToLCP(PPP_LCP *c, UINT type, IP *ip, bool only_modify);

bool PPPSendRequest(PPP_SESSION *p, USHORT protocol, PPP_LCP *c);
USHORT PPPContinueCurrentProtocolRequestListening(PPP_SESSION *p, USHORT protocol);
bool PPPContinueUntilFinishAllLCPOptionRequestsDetermined(PPP_SESSION *p);
PPP_PACKET *PPPRecvResponsePacket(PPP_SESSION *p, PPP_PACKET *req, USHORT expected_protocol, USHORT *received_protocol, bool finish_when_all_lcp_acked,
								  bool return_mschapv2_response_with_no_processing);
PPP_PACKET *PPPProcessRequestPacket(PPP_SESSION *p, PPP_PACKET *req);
void PPPSendEchoRequest(PPP_SESSION *p);
bool PPPParseUsername(CEDAR *cedar, char *src, ETHERIP_ID *dst);
bool IsHubExistsWithLock(CEDAR *cedar, char *hubname);

void GenerateNtPasswordHash(UCHAR *dst, char *password);
void GenerateNtPasswordHashHash(UCHAR *dst_hash, UCHAR *src_hash);
void MsChapV2Server_GenerateChallenge(UCHAR *dst);
void MsChapV2_GenerateChallenge8(UCHAR *dst, UCHAR *client_challenge, UCHAR *server_challenge, char *username);
void MsChapV2Client_GenerateResponse(UCHAR *dst, UCHAR *challenge8, UCHAR *nt_password_hash);
void MsChapV2Server_GenerateResponse(UCHAR *dst, UCHAR *nt_password_hash_hash, UCHAR *client_response, UCHAR *challenge8);
bool MsChapV2VerityPassword(IPC_MSCHAP_V2_AUTHINFO *d, char *password);
char *MsChapV2DoBruteForce(IPC_MSCHAP_V2_AUTHINFO *d, LIST *password_list);
void PPPFreeEapClient(PPP_SESSION *p);

#endif	// PROTO_PPP_H
