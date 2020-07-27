// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_OpenVPN.h
// Header of Proto_OpenVPN.c

#ifndef	PROTO_OPENVPN_H
#define	PROTO_OPENVPN_H


//// Constants
#define	OPENVPN_UDP_PORT						1194	// OpenVPN default UDP port number
#define	OPENVPN_UDP_PORT_INCLUDE				1195	// OpenVPN default UDP port number (Operating within the client)

#define	OPENVPN_MAX_NUMACK						4		// The maximum number of ACKs
#define	OPENVPN_NUM_CHANNELS					8		// Maximum number of channels during a session
#define	OPENVPN_CONTROL_PACKET_RESEND_INTERVAL	500		// Control packet retransmission interval
#define	OPENVPN_CONTROL_PACKET_MAX_DATASIZE		1200	// Maximum data size that can be stored in one control packet

#define	OPENVPN_MAX_SSL_RECV_BUF_SIZE			(256 * 1024)	// SSL receive buffer maximum length

#define	OPENVPN_MAX_KEY_SIZE					64		// Maximum key size
#define	OPENVPN_TAG_SIZE						16		// Tag size (for packet authentication in AEAD mode)

#define	OPENVPN_TMP_BUFFER_SIZE					(65536 + 256)	// Temporary buffer size

#define	OPENVPN_PING_SEND_INTERVAL				3000	// Transmission interval of Ping
#define	OPENVPN_RECV_TIMEOUT					10000	// Communication time-out
#define	OPENVPN_NEW_SESSION_DEADLINE_TIMEOUT	30000	// Grace time to complete new VPN session connection since it was created

#define	OPENVPN_MAX_PACKET_ID_FOR_TRIGGER_REKEY	0xFF000000	// Packet ID that is a trigger to start the re-key
#define	OPENVPN_TCP_MAX_PACKET_SIZE				2000	// The maximum packet size allowed in TCP mode


// The default algorithm
#define	OPENVPN_DEFAULT_CIPHER					"AES-128-CBC"
#define	OPENVPN_DEFAULT_MD						"SHA1"

// Encryption related
#define	OPENVPN_PREMASTER_LABEL					"OpenVPN master secret"
#define	OPENVPN_EXPANSION_LABEL					"OpenVPN key expansion"

// IPC related
#define	OPENVPN_IPC_CLIENT_NAME					"OpenVPN Client"
#define	OPENVPN_IPC_POSTFIX_L2					"OPENVPN_L2"
#define	OPENVPN_IPC_POSTFIX_L3					"OPENVPN_L3"

// MTU
#define	OPENVPN_MTU_LINK						1514	// Ethernet MTU
#define	OPENVPN_MTU_TUN							1500	// Tun MTU

// Protocol
#define	OPENVPN_PROTOCOL_UDP					0		// UDP
#define	OPENVPN_PROTOCOL_TCP					1		// TCP

// Op-code
#define	OPENVPN_P_CONTROL_SOFT_RESET_V1			3		// Soft reset request
#define	OPENVPN_P_CONTROL_V1					4		// SSL negotiation packet
#define	OPENVPN_P_ACK_V1						5		// Acknowledgment
#define	OPENVPN_P_DATA_V1						6		// Data packet
#define	OPENVPN_P_CONTROL_HARD_RESET_CLIENT_V2	7		// Connection request from client
#define	OPENVPN_P_CONTROL_HARD_RESET_SERVER_V2	8		// Connection response from server

// State of OpenVPN channel
#define	OPENVPN_CHANNEL_STATUS_INIT					0	// Initialization phase
#define	OPENVPN_CHANNEL_STATUS_TLS_WAIT_CLIENT_KEY	1	// Waiting for the key information from the client
#define	OPENVPN_CHANNEL_STATUS_TLS_WAIT_CLIENT_PUSH_REQUEST	2	// Waiting for PUSH_REQUEST from the client
#define	OPENVPN_CHANNEL_STATUS_TLS_VPN_CONNECTING	3	// VPN connecting process is running
#define	OPENVPN_CHANNEL_STATUS_ESTABLISHED			4	// VPN connection established
#define	OPENVPN_CHANNEL_STATUS_DISCONNECTED			5	// Disconnected

// Quota
#define	OPENVPN_QUOTA_MAX_NUM_SESSIONS_PER_IP	1000			// Number of OpenVPN sessions per IP address
#define	OPENVPN_QUOTA_MAX_NUM_SESSIONS			30000			// Limit of the number of sessions

// Mode
#define	OPENVPN_MODE_UNKNOWN					0		// Unknown
#define	OPENVPN_MODE_L2							1		// TAP (Ethernet)
#define	OPENVPN_MODE_L3							2		// TUN (IP)

// Scramble mode
#define	OPENVPN_SCRAMBLE_MODE_DISABLED			0		// No scramble
#define	OPENVPN_SCRAMBLE_MODE_XORMASK			1		// XOR the bytes with the specified string
#define	OPENVPN_SCRAMBLE_MODE_XORPTRPOS			2		// XOR each byte with its position in the buffer
#define	OPENVPN_SCRAMBLE_MODE_REVERSE			3		// Reverses bytes order, keeping the first byte unchanged
#define	OPENVPN_SCRAMBLE_MODE_OBFUSCATE			4		// Performs the above steps using the specified string for xormask

//// Type

// Data of OpenVPN Key Method 2
struct OPENVPN_KEY_METHOD_2
{
	UCHAR PreMasterSecret[48];							// Pre Master Secret (client only)
	UCHAR Random1[32];									// Random 1
	UCHAR Random2[32];									// Random 2
	char OptionString[512];								// Option string
	char Username[512];									// User name
	char Password[512];									// Password
	char PeerInfo[1536];								// PeerInfo
};

// OpenVPN sending control packet
struct OPENVPN_CONTROL_PACKET
{
	UCHAR OpCode;										// Op-code
	UINT PacketId;										// Packet ID
	UINT DataSize;										// Data size
	UCHAR *Data;										// Data body
	UINT64 NextSendTime;								// Scheduled next transmission time
	bool NoResend;										// Disable re-sending
	UINT NumSent;										// How many times we have sent this packet
};

// OpenVPN packet
struct OPENVPN_PACKET
{
	UCHAR OpCode;										// Op-code
	UCHAR KeyId;										// Key ID
	UINT64 MySessionId;									// Channel ID of the sender
	UCHAR NumAck;										// Number of ACK
	UINT AckPacketId[OPENVPN_MAX_NUMACK];				// ACK packet ID list
	UINT64 YourSessionId;								// Destination Channel ID (If there are one or more ACK)
	UINT PacketId;										// Packet ID
	UINT DataSize;										// Data size
	UCHAR *Data;										// Data body
};

// OpenVPN channel
struct OPENVPN_CHANNEL
{
	OPENVPN_SERVER *Server;
	OPENVPN_SESSION *Session;
	UINT Status;										// State
	LIST *AckReplyList;									// Response ACK list
	UINT MaxRecvPacketId;								// The maximum value of the arrived packet ID
	UINT NextSendPacketId;								// The value of a packet ID to be transmitted next
	LIST *SendControlPacketList;						// Sending control packet list
	SSL_PIPE *SslPipe;									// SSL pipe
	OPENVPN_KEY_METHOD_2 ClientKey;						// Key sent from the client
	OPENVPN_KEY_METHOD_2 ServerKey;						// Key sent from the server
	char Proto[64];										// Protocol
	CIPHER *CipherEncrypt;								// Encryption algorithm
	CIPHER *CipherDecrypt;								// Decryption algorithm
	MD *MdSend;											// Transmission MD algorithm
	MD *MdRecv;											// Reception MD algorithm
	UCHAR IvSend[64];									// Transmission IV
	UCHAR IvRecv[64];									// Reception IV
	UCHAR MasterSecret[48];								// Master Secret
	UCHAR ExpansionKey[256];							// Expansion Key
	UINT LastDataPacketId;								// Previous Data Packet ID
	UINT64 EstablishedTick;								// Established time
	UCHAR KeyId;										// KEY ID
	bool IsRekeyChannel;								// Whether it is a channel for key update
	bool IsInitiatorServer;								// Whether the channel was started from the server side
	bool RekeyInitiated;								// Whether re-keying has already started
	UINT64 NextRekey;
	struct SslClientCertInfo ClientCert;                // Client certificate and verification data
};

// OpenVPN session
struct OPENVPN_SESSION
{
	UINT Id;											// ID
	OPENVPN_SERVER *Server;
	UINT64 ServerSessionId;								// The session ID of the server-side
	UINT64 ClientSessionId;								// Session ID of the client side
	UINT Protocol;										// Protocol
	IP ClientIp;										// Client IP address
	UINT ClientPort;									// Client port number
	IP ServerIp;										// Server IP address
	UINT ServerPort;									// Server port number
	OPENVPN_CHANNEL *Channels[OPENVPN_NUM_CHANNELS];	// Channels (up to 8)
	UINT LastCreatedChannelIndex;						// Channel number that is created in the last
	UINT Mode;											// Mode (L3 or L2)
	UINT ObfuscationMode;								// Packet obfuscation/scrambling mode
	UINT LinkMtu;										// link-mtu
	UINT TunMtu;										// tun-mtu
	IPC_ASYNC *IpcAsync;								// Asynchronous IPC connection
	IPC *Ipc;											// Connected IPC connection
	char PushReplyStr[MAX_SIZE];						// PUSH_REPLY string
	UINT64 NextPingSendTick;							// Next time to send a Ping
	bool Established;									// VPN communication established flag
	UINT64 CreatedTick;									// Creation date and time
	UINT64 LastCommTick;								// Last communication date and time
};

// OpenVPN server
struct OPENVPN_SERVER
{
	CEDAR *Cedar;
	INTERRUPT_MANAGER *Interrupt;						// Interrupt manager
	LIST *RecvPacketList;								// Received packets list
	LIST *SendPacketList;								// Transmission packet list
	LIST *SessionList;									// Session list
	UINT64 Now;											// Current time
	UINT64 Giveup;										// Session establishment deadline
	SOCK_EVENT *SockEvent;								// Socket event
	UCHAR TmpBuf[OPENVPN_TMP_BUFFER_SIZE];				// Temporary buffer
	UINT DisconnectCount;								// The number of session lost that have occurred so far
	bool SupressSendPacket;								// Packet transmission suppression flag
	UINT NextSessionId;									// Next session ID
	DH_CTX *Dh;											// DH key
	UINT SessionEstablishedCount;						// Number of session establishment
	// Options
	char *DefaultClientOption;							// Default option string to push to client
	bool Obfuscation;									// Obfuscation enabled/disabled
	char *ObfuscationMask;								// String (mask) for XOR obfuscation
	bool PushDummyIPv4AddressOnL2Mode;					// Push a dummy IPv4 address in L2 mode
};

//// Function prototype
const PROTO_IMPL *OvsGetProtoImpl();
const char *OvsName();
const PROTO_OPTION *OvsOptions();
bool OvsInit(void **param, const LIST *options, CEDAR *cedar, INTERRUPT_MANAGER *im, SOCK_EVENT *se, const char *cipher, const char *hostname);
void OvsFree(void *param);
bool OvsIsPacketForMe(const PROTO_MODE mode, const UCHAR *data, const UINT size);
bool OvsProcessData(void *param, TCP_RAW_DATA *in, FIFO *out);
bool OvsProcessDatagrams(void *param, LIST *in, LIST *out);
bool OvsIsOk(void *param);
UINT OvsEstablishedSessions(void *param);

OPENVPN_SERVER *NewOpenVpnServer(const LIST *options, CEDAR *cedar, INTERRUPT_MANAGER *interrupt, SOCK_EVENT *sock_event);
void FreeOpenVpnServer(OPENVPN_SERVER *s);
void OvsRecvPacket(OPENVPN_SERVER *s, LIST *recv_packet_list, UINT protocol);
void OvsProceccRecvPacket(OPENVPN_SERVER *s, UDPPACKET *p, UINT protocol);
int OvsCompareSessionList(void *p1, void *p2);
OPENVPN_SESSION *OvsSearchSession(OPENVPN_SERVER *s, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, UINT protocol);
OPENVPN_SESSION *OvsNewSession(OPENVPN_SERVER *s, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, UINT protocol);
OPENVPN_SESSION *OvsFindOrCreateSession(OPENVPN_SERVER *s, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, UINT protocol);
void OvsFreeSession(OPENVPN_SESSION *se);
UINT OvsGetNumSessionByClientIp(OPENVPN_SERVER *s, IP *ip);

OPENVPN_PACKET *OvsParsePacket(UCHAR *data, UINT size);
void OvsFreePacket(OPENVPN_PACKET *p);
BUF *OvsBuildPacket(OPENVPN_PACKET *p);
OPENVPN_PACKET *OvsNewControlPacket(UCHAR opcode, UCHAR key_id, UINT64 my_channel_id, UINT num_ack,
									UINT *ack_packet_ids, UINT64 your_channel_id, UINT packet_id,
									UINT data_size, UCHAR *data);
void OvsSendDataPacket(OPENVPN_CHANNEL *c, UCHAR key_id, UINT data_packet_id, void *data, UINT data_size);


OPENVPN_CHANNEL *OvsNewChannel(OPENVPN_SESSION *se, UCHAR key_id);
void OvsFreeChannel(OPENVPN_CHANNEL *c);
UINT64 OvsNewServerSessionId(OPENVPN_SERVER *s);
UINT OvsGetAckReplyList(OPENVPN_CHANNEL *c, UINT *ret);

void OvsSendPacketNow(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_PACKET *p);
void OvsSendPacketRawNow(OPENVPN_SERVER *s, OPENVPN_SESSION *se, void *data, UINT size);

void OvsProcessRecvControlPacket(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c, OPENVPN_PACKET *p);
void OvsSendControlPacket(OPENVPN_CHANNEL *c, UCHAR opcode, UCHAR *data, UINT data_size);
void OvsSendControlPacketEx(OPENVPN_CHANNEL *c, UCHAR opcode, UCHAR *data, UINT data_size, bool no_resend);
void OvsSendControlPacketWithAutoSplit(OPENVPN_CHANNEL *c, UCHAR opcode, UCHAR *data, UINT data_size);
void OvsFreeControlPacket(OPENVPN_CONTROL_PACKET *p);
void OvsDeleteFromSendingControlPacketList(OPENVPN_CHANNEL *c, UINT num_acks, UINT *acks);
UINT OvsParseKeyMethod2(OPENVPN_KEY_METHOD_2 *ret, UCHAR *data, UINT size, bool client_mode);
bool OvsReadStringFromBuf(BUF *b, char *str, UINT str_size);
void OvsSetupSessionParameters(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c, OPENVPN_KEY_METHOD_2 *data);
BUF *OvsBuildKeyMethod2(OPENVPN_KEY_METHOD_2 *d);
void OvsWriteStringToBuf(BUF *b, char *str, UINT max_size);

UINT OvsPeekStringFromFifo(FIFO *f, char *str, UINT str_size);
void OvsBeginIPCAsyncConnectionIfEmpty(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c);
UINT OvsCalcTcpMss(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c);

CIPHER *OvsGetCipher(char *name);
MD *OvsGetMd(char *name);

#endif	// PROTO_OPENVPN_H
