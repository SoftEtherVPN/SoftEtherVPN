// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// UdpAccel.h
// Header of UdpAccel.c

#ifndef	UDPACCEL_H
#define	UDPACCEL_H

// Constants
#define	UDP_ACCELERATION_COMMON_KEY_SIZE_V1	20			// V1: Common key size
#define	UDP_ACCELERATION_PACKET_KEY_SIZE_V1	20			// V1: Key size for the packet
#define	UDP_ACCELERATION_PACKET_IV_SIZE_V1	20			// V1: IV size for the packet

#define	UDP_ACCELERATION_COMMON_KEY_SIZE_V2	128			// V2: Common key size
#define	UDP_ACCELERATION_PACKET_IV_SIZE_V2	12			// V2: IV size for the packet
#define	UDP_ACCELERATION_PACKET_MAC_SIZE_V2	16			// V2: MAC size for the packet

#define	UDP_ACCELERATION_TMP_BUF_SIZE		2048		// Temporary buffer size
#define	UDP_ACCELERATION_WINDOW_SIZE_MSEC	(30 * 1000)	// Receive window size (in milliseconds)

#define	UDP_ACCELERATION_SUPPORTED_MAX_PAYLOAD_SIZE	1600	// Maximum supported payload size
#define	UDP_ACCELERATION_MAX_PADDING_SIZE	32			// Maximum padding size

#define	UDP_ACCELERATION_REQUIRE_CONTINUOUS	(10 * 1000)	// Not to use if stable communication is not continued at least for this time

// Time constant for Build 8534 or earlier
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN	(1 * 1000)	// Keep Alive Interval (minimum)
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX	(3 * 1000)	// Keep Alive Interval (maximum)
#define	UDP_ACCELERATION_KEEPALIVE_TIMEOUT		(9 * 1000)	// Time to disconnect time by non-communication

// Time constant for Build 8535 or later
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST	(500)	// Keep Alive Interval (minimum)
#define	UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX_FAST	(1000)	// Keep Alive Interval (maximum)
#define	UDP_ACCELERATION_KEEPALIVE_TIMEOUT_FAST			(2100)	// Time to disconnect time by non-communication

// Range of port numbers
#define	UDP_SERVER_PORT_LOWER				40000		// Minimum port
#define	UDP_SERVER_PORT_HIGHER				44999		// Maximum port

// NAT-T port signature to be embedded in the Keep Alive of the session
#define	UDP_NAT_T_PORT_SIGNATURE_IN_KEEP_ALIVE			"NATT_MY_PORT"

// UDP Acceleration Mode
struct UDP_ACCEL
{
	CEDAR *Cedar;										// Cedar
	bool NoNatT;										// Not to communicate with the NAT-T server (To communicate with the query server instead)
	bool ClientMode;									// Whether client mode
	bool IsInCedarPortList;								// Whether included in the port list of the Cedar
	UINT64 Now;											// Current time
	CIPHER *CipherEncrypt;								// Encryption context
	CIPHER *CipherDecrypt;								// Decryption context
	UCHAR MyKey[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];	// Send-direction common key
	UCHAR YourKey[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];	// Receive-direction common key
	SOCK *UdpSock;										// UDP socket
	UINT MyPort;										// My port number
	UINT YourPort;										// Port number of the other party
	IP MyIp;											// My IP address
	IP YourIp;											// IP address of the other party
	IP YourIp2;											// IP address of the other party (second)
	bool IsIPv6;										// Whether it's an IPv6
	UCHAR TmpBuf[UDP_ACCELERATION_TMP_BUF_SIZE];		// Temporary buffer
	UINT64 LastRecvYourTick;							// Opponent's tick value of the last reception
	UINT64 LastRecvMyTick;								// My tick value of the last reception
	QUEUE *RecvBlockQueue;								// Reception block queue
	bool UseHMac;										// Flag to use the HMAC
	bool PlainTextMode;									// No encryption
	UINT64 LastSetSrcIpAndPortTick;						// Opponent's tick ??value at the time of storing the IP address and port number of the opponent at the end
	UINT64 LastRecvTick;								// Tick when data has received at the end
	UINT64 NextSendKeepAlive;							// Next time to send a KeepAlive packet
	UCHAR NextIv[UDP_ACCELERATION_PACKET_IV_SIZE_V1];	// IV to be used next
	UINT MyCookie;										// My cookie
	UINT YourCookie;									// Cookie of the other party
	bool Inited;										// Initialized flag
	UINT Mss;											// Optimal MSS
	UINT MaxUdpPacketSize;								// Get the maximum transmittable UDP size
	LOCK *NatT_Lock;									// Lock the IP address field of NAT-T server
	IP NatT_IP;											// IP address of the NAT-T server
	THREAD *NatT_GetIpThread;							// IP address acquisition thread of NAT-T server
	bool NatT_Halt;										// Halting flag of IP address acquisition thread of NAT-T server
	EVENT *NatT_HaltEvent;								// Halting event of IP address acquisition thread of NAT-T server
	UINT64 NextPerformNatTTick;							// Time to communicate with NAT-T server next time
	UINT CommToNatT_NumFail;							// Number of failures to communicate with NAT-T server
	UINT MyPortByNatTServer;							// Self port number which is received from the NAT-T server
	bool MyPortByNatTServerChanged;						// The self port number which is received from the NAT-T server changes
	UINT YourPortByNatTServer;							// Port number of the opponent that was found via the NAT-T server
	bool YourPortByNatTServerChanged;					// Port number of the opponent that was found via the NAT-T server has been changed
	bool FatalError;									// A fatal error occurred
	bool NatT_IP_Changed;								// IP address of the NAT-T server has changed
	UINT64 NatT_TranId;									// Transaction ID to be exchanged with the NAT-T server
	bool IsReachedOnce;									// It is true if it succeeds in mutual transmission and reception of packets at least once
	UINT64 CreatedTick;									// Object creation time
	bool FastDetect;									// Fast disconnection detection mode
	UINT64 FirstStableReceiveTick;						// Start time of current stable continued receivable period
	bool UseSuperRelayQuery;							// Use the super relay query
	bool UseUdpIpQuery;									// Use the self IP address query by UDP
	IP UdpIpQueryHost;									// Host for the self IP address query by UDP
	UINT UdpIpQueryPort;								// Port number for self IP address for query by UDP
	UCHAR UdpIpQueryPacketData[16];						// Query packet data (final transmission)
	UINT UdpIpQueryPacketSize;							// Query packet data size (final transmission)
	UCHAR UdpHostUniqueKey[SHA1_SIZE];					// Unique key for UDP self endpoint query
	UINT Version;										// Version
	UCHAR MyKey_V2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];	// Send-direction common key (version 2)
	UCHAR NextIv_V2[UDP_ACCELERATION_PACKET_IV_SIZE_V2];	// IV to be used next (version 2)
	bool ReadRawFlagMode;								// Read raw flag mode
};

// Function prototype
UDP_ACCEL *NewUdpAccel(CEDAR *cedar, IP *ip, bool client_mode, bool random_port, bool no_nat_t);
void FreeUdpAccel(UDP_ACCEL *a);
bool UdpAccelInitClient(UDP_ACCEL *a, UCHAR *server_key, IP *server_ip, UINT server_port, UINT server_cookie, UINT client_cookie, IP *server_ip_2);
bool UdpAccelInitServer(UDP_ACCEL *a, UCHAR *client_key, IP *client_ip, UINT client_port, IP *client_ip_2);
void UdpAccelPoll(UDP_ACCEL *a);
void UdpAccelSetTick(UDP_ACCEL *a, UINT64 tick64);
BLOCK *UdpAccelProcessRecvPacket(UDP_ACCEL *a, UCHAR *buf, UINT size, IP *src_ip, UINT src_port);
void UdpAccelCalcKeyV1(UCHAR *key, UCHAR *common_key, UCHAR *iv);
bool UdpAccelIsSendReady(UDP_ACCEL *a, bool check_keepalive);
void UdpAccelSend(UDP_ACCEL *a, UCHAR *data, UINT data_size, UCHAR flag, UINT max_size, bool high_priority);
void UdpAccelSendBlock(UDP_ACCEL *a, BLOCK *b);
UINT UdpAccelCalcMss(UDP_ACCEL *a);
void NatT_GetIpThread(THREAD *thread, void *param);

#endif	// UDPACCEL_H


