// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

// Connection.h
// Header of Connection.c

#ifndef	CONNECTION_H
#define	CONNECTION_H

#include "Cedar.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Proxy.h"

// Magic number indicating that the packet is compressed
#define	CONNECTION_BULK_COMPRESS_SIGNATURE	0xDEADBEEFCAFEFACEULL

#define	KEEP_ALIVE_STRING				"Internet Connection Keep Alive Packet"

#define	UPDATE_LAST_COMM_TIME(v, n)		{if ((v) <= (n)) { v = (n); } }

// KEEP CONNECT structure
struct KEEP
{
	LOCK *lock;										// Lock
	bool Server;									// Server mode
	volatile bool Halt;								// Stop flag
	bool Enable;									// Enable flag
	char ServerName[MAX_HOST_NAME_LEN + 1];			// Server name
	UINT ServerPort;								// Server port number
	bool UdpMode;									// UDP mode
	UINT Interval;									// Packet transmission interval
	THREAD *Thread;									// Connection thread
	EVENT *HaltEvent;								// Stop event
	CANCEL *Cancel;									// Cancel
};

// SECURE_SIGN Structure
struct SECURE_SIGN
{
	char SecurePublicCertName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// Secure device certificate name
	char SecurePrivateKeyName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// Secure device secret key name
	X *ClientCert;					// Client certificate
	UCHAR Random[SHA1_SIZE];		// Random value for signature
	UCHAR Signature[4096 / 8];		// Signed data
	UINT UseSecureDeviceId;
	UINT BitmapId;					// Bitmap ID
};

// Function type declaration
typedef bool (CHECK_CERT_PROC)(SESSION *s, CONNECTION *c, X *server_x, bool *expired);
typedef bool (SECURE_SIGN_PROC)(SESSION *s, CONNECTION *c, SECURE_SIGN *sign);

// RC4 key pair
struct RC4_KEY_PAIR
{
	UCHAR ServerToClientKey[16];
	UCHAR ClientToServerKey[16];
};

// Client Options
struct CLIENT_OPTION
{
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];			// Connection setting name
	char Hostname[MAX_HOST_NAME_LEN + 1];					// Host name
	UINT Port;												// Port number
	UINT PortUDP;											// UDP port number (0: Use only TCP)
	UINT ProxyType;											// Type of proxy
	char ProxyName[MAX_HOST_NAME_LEN + 1];					// Proxy server name
	UINT ProxyPort;											// Port number of the proxy server
	char ProxyUsername[PROXY_MAX_USERNAME_LEN + 1];			// Maximum user name length
	char ProxyPassword[PROXY_MAX_PASSWORD_LEN + 1];			// Maximum password length
	char CustomHttpHeader[HTTP_CUSTOM_HEADER_MAX_SIZE + 1];	// Custom HTTP proxy header
	UINT NumRetry;											// Automatic retries
	UINT RetryInterval;										// Retry interval
	char HubName[MAX_HUBNAME_LEN + 1];						// HUB name
	UINT MaxConnection;										// Maximum number of concurrent TCP connections
	bool UseEncrypt;										// Use encrypted communication
	bool UseCompress;										// Use data compression
	bool HalfConnection;									// Use half connection in TCP
	bool NoRoutingTracking;									// Disable the routing tracking
	char DeviceName[MAX_DEVICE_NAME_LEN + 1];				// VLAN device name
	UINT AdditionalConnectionInterval;						// Connection attempt interval when additional connection establish
	UINT ConnectionDisconnectSpan;							// Disconnection interval
	bool HideStatusWindow;									// Hide the status window
	bool HideNicInfoWindow;									// Hide the NIC status window
	bool RequireMonitorMode;								// Monitor port mode
	bool RequireBridgeRoutingMode;							// Bridge or routing mode
	bool DisableQoS;										// Disable the VoIP / QoS function
	bool FromAdminPack;										// For Administration Pack
	bool NoUdpAcceleration;									// Do not use UDP acceleration mode
	UCHAR HostUniqueKey[SHA1_SIZE];							// Host unique key
};

// Client authentication data
struct CLIENT_AUTH
{
	UINT AuthType;									// Authentication type
	char Username[MAX_USERNAME_LEN + 1];			// User name
	UCHAR HashedPassword[SHA1_SIZE];				// Hashed passwords
	char PlainPassword[MAX_PASSWORD_LEN + 1];		// Password
	X *ClientX;										// Client certificate
	K *ClientK;										// Client private key
	char SecurePublicCertName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// Secure device certificate name
	char SecurePrivateKeyName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// Secure device secret key name
	char OpensslEnginePrivateKeyName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// Secure device secret key name
	char OpensslEngineName[MAX_SECURE_DEVICE_FILE_LEN + 1];	// Secure device secret key name
	CHECK_CERT_PROC *CheckCertProc;					// Server certificate confirmation procedure
	SECURE_SIGN_PROC *SecureSignProc;				// Security signing procedure
};

// TCP socket data structure
struct TCPSOCK
{
	SOCK *Sock;						// Socket
	FIFO *RecvFifo;					// Reception buffer
	FIFO *SendFifo;					// Transmission buffer
	UINT Mode;						// Read mode
	UINT WantSize;					// Requested data size
	UINT NextBlockNum;				// Total number of blocks that can be read next
	UINT NextBlockSize;				// Block size that is planned to read next
	UINT CurrentPacketNum;			// Current packet number
	UINT64 LastCommTime;			// Last communicated time
	UINT64 LastRecvTime;			// Time the last data received
	UINT LateCount;					// The number of delay occurences
	UINT Direction;					// Direction
	UINT64 NextKeepAliveTime;		// Next time to send a KeepAlive packet
	RC4_KEY_PAIR Rc4KeyPair;		// RC4 key pair
	CRYPT *SendKey;					// Transmission key
	CRYPT *RecvKey;					// Reception key
	UINT64 DisconnectTick;			// Time to disconnect this connection
	UINT64 EstablishedTick;			// Establishment time
};

// TCP communication data structure
struct TCP
{
	LIST *TcpSockList;				// TCP socket list
};

// UDP communication data structure
struct UDP
{
	SOCK *s;						// UDP socket (for transmission)
	IP ip;							// Destination IP address
	UINT port;						// Destination port number
	UINT64 NextKeepAliveTime;		// Next time to send a KeepAlive packet
	UINT64 Seq;						// Packet sequence number
	UINT64 RecvSeq;
	QUEUE *BufferQueue;				// Queue of buffer to be sent
};

// Data block
struct BLOCK
{
	bool Compressed;				// Compression flag
	UINT Size;						// Block size
	UINT SizeofData;				// Data size
	UCHAR *Buf;						// Buffer
	bool PriorityQoS;				// Priority packet for VoIP / QoS function
	UINT Ttl;						// TTL value (Used only in ICMP NAT of Virtual.c)
	UINT Param1;					// Parameter 1
	bool IsFlooding;				// Is flooding packet
	UCHAR RawFlagRetUdpAccel;		// Raw flag returned by UDP accel
};

// Connection structure
struct CONNECTION
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	CEDAR *Cedar;					// Cedar
	struct SESSION *Session;		// Session
	UINT Protocol;					// Protocol
	SOCK *FirstSock;				// Socket for negotiation
	SOCK *TubeSock;					// Socket for in-process communication
	TCP *Tcp;						// TCP communication data structure
	UDP *Udp;						// UDP communication data structure
	bool ServerMode;				// Server mode
	UINT Status;					// Status
	char *Name;						// Connection name
	THREAD *Thread;					// Thread
	volatile bool Halt;				// Stop flag
	UCHAR Random[SHA1_SIZE];		// Random number for Authentication
	UINT ServerVer;					// Server version
	UINT ServerBuild;				// Server build number
	UINT ClientVer;					// Client version
	UINT ClientBuild;				// Client build number
	char ServerStr[MAX_SERVER_STR_LEN + 1];	// Server string
	char ClientStr[MAX_CLIENT_STR_LEN + 1];	// Client string
	UINT Err;						// Error value
	bool ClientConnectError_NoSavePassword;	// Don't save the password for the specified user name
	QUEUE *ReceivedBlocks;			// Block queue that is received
	QUEUE *SendBlocks;				// Block queue planned to be sent
	QUEUE *SendBlocks2;				// Send queue (high priority)
	COUNTER *CurrentNumConnection;	// Counter of the number of current connections
	LIST *ConnectingThreads;		// List of connected threads
	LIST *ConnectingSocks;			// List of the connected sockets
	bool flag1;						// Flag 1
	UCHAR *RecvBuf;					// Receive buffer
	char ServerName[MAX_HOST_NAME_LEN + 1];	// Server name
	UINT ServerPort;				// Port number
	bool RestoreServerNameAndPort;	// Flag to restore the  server name and port number to original
	bool UseTicket;					// Ticket using flag
	UCHAR Ticket[SHA1_SIZE];		// Ticket
	UINT CurrentSendQueueSize;		// Total size of the transmission queue
	X *ServerX;						// Server certificate
	X *ClientX;						// Client certificate
	char *CipherName;				// Encryption algorithm name
	UINT64 ConnectedTick;			// Time it is connected
	IP ClientIp;					// Client IP address
	char ClientHostname[MAX_HOST_NAME_LEN + 1];	// Client host name
	UINT Type;						// Type
	void *hWndForUI;				// Parent window
	bool IsInProc;					// In-process
	char InProcPrefix[64];			// Prefix
	UINT InProcLayer;				// InProc layer
	UINT AdditionalConnectionFailedCounter;		// Additional connection failure counter
	UINT64 LastCounterResetTick;	// Time the counter was reset finally
	bool WasSstp;					// Processed the SSTP
	bool WasDatProxy;				// DAT proxy processed
	UCHAR CToken_Hash[SHA1_SIZE];	// CTOKEN_HASH
	UINT LastTcpQueueSize;			// The last queue size of TCP sockets
	UINT LastPacketQueueSize;		// The last queue size of packets
	UINT LastRecvFifoTotalSize;		// The last RecvFifo total size
	UINT LastRecvBlocksNum;			// The last ReceivedBlocks num
	bool IsJsonRpc;					// Is JSON-RPC
	bool JsonRpcAuthed;				// JSON-RPC Authed
	LISTENER *Listener;				// Listener ref
};



// Function prototypes

CONNECTION *NewClientConnection(SESSION *s);
CONNECTION *NewClientConnectionEx(SESSION *s, char *client_str, UINT client_ver, UINT client_build);
CONNECTION *NewServerConnection(CEDAR *cedar, SOCK *s, THREAD *t);
void ReleaseConnection(CONNECTION *c);
void CleanupConnection(CONNECTION *c);
int CompareConnection(void *p1, void *p2);
void StopConnection(CONNECTION *c, bool no_wait);
void ConnectionAccept(CONNECTION *c);
void StartTunnelingMode(CONNECTION *c);
void EndTunnelingMode(CONNECTION *c);
void DisconnectTcpSockets(CONNECTION *c);
void ConnectionReceive(CONNECTION *c, CANCEL *c1, CANCEL *c2);
void ConnectionSend(CONNECTION *c, UINT64 now);
TCPSOCK *NewTcpSock(SOCK *s);
void FreeTcpSock(TCPSOCK *ts);
BLOCK *NewBlock(void *data, UINT size, int compress);
void FreeBlock(BLOCK *b);
void StopAllAdditionalConnectThread(CONNECTION *c);
UINT GenNextKeepAliveSpan(CONNECTION *c);
void SendKeepAlive(CONNECTION *c, TCPSOCK *ts);
void DisconnectUDPSockets(CONNECTION *c);
void PutUDPPacketData(CONNECTION *c, void *data, UINT size);
void SendDataWithUDP(SOCK *s, CONNECTION *c);
void InsertReceivedBlockToQueue(CONNECTION *c, BLOCK *block, bool no_lock);
UINT TcpSockRecv(SESSION *s, TCPSOCK *ts, void *data, UINT size);
UINT TcpSockSend(SESSION *s, TCPSOCK *ts, void *data, UINT size);
void WriteSendFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size);
void WriteRecvFifo(SESSION *s, TCPSOCK *ts, void *data, UINT size);
CLIENT_AUTH *CopyClientAuth(CLIENT_AUTH *a);
BUF *NewKeepPacket(bool server_mode);
void KeepThread(THREAD *thread, void *param);
KEEP *StartKeep();
void StopKeep(KEEP *k);
void InRpcSecureSign(SECURE_SIGN *t, PACK *p);
void OutRpcSecureSign(PACK *p, SECURE_SIGN *t);
void FreeRpcSecureSign(SECURE_SIGN *t);
void NormalizeEthMtu(BRIDGE *b, CONNECTION *c, UINT packet_size);
UINT GetMachineRand();



#endif	// CONNECTION_H
