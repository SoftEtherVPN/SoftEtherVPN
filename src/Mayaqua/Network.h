// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori, Ph.D.
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


// Network.h
// Header of Network.c

#ifndef	NETWORK_H
#define	NETWORK_H

// Dynamic Value
struct DYN_VALUE
{
	char Name[256];								// Name
	UINT64 Value;								// Value
};

#define	DYN64(id, default_value)	( (UINT64)GetDynValueOrDefaultSafe ( #id , (UINT64)( default_value )))
#define	DYN32(id, default_value)	(UINT)DYN64(id, (UINT)default_value)

#define	MAX_HOST_NAME_LEN			255		// Maximum length of the host name

#define	TIMEOUT_GETIP				2300

#define	TIMEOUT_INFINITE			(0x7fffffff)
#define	TIMEOUT_TCP_PORT_CHECK		(10 * 1000)
#define	TIMEOUT_SSL_CONNECT			(15 * 1000)

#define	TIMEOUT_HOSTNAME			(500)
#define	TIMEOUT_NETBIOS_HOSTNAME	(100)
#define	EXPIRES_HOSTNAME			(10 * 60 * 1000)

#define	SOCKET_BUFFER_SIZE			0x10000000

#define	IPV6_DUMMY_FOR_IPV4			0xFEFFFFDF

#define	UDPLISTENER_CHECK_INTERVAL	1000ULL
#define	UDPLISTENER_WAIT_INTERVAL	1234

#define	UDP_MAX_MSG_SIZE_DEFAULT	65507

#define	MAX_NUM_IGNORE_ERRORS		1024

#ifndef	USE_STRATEGY_LOW_MEMORY
#define	DEFAULT_GETIP_THREAD_MAX_NUM		512
#else	// USE_STRATEGY_LOW_MEMORY
#define	DEFAULT_GETIP_THREAD_MAX_NUM		64
#endif	// USE_STRATEGY_LOW_MEMORY

#define	DEFAULT_CIPHER_LIST			"ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDHE+AES256:DHE+AES256:RSA+AES"

// SSL logging function
//#define	ENABLE_SSL_LOGGING
#define	SSL_LOGGING_DIRNAME			"@ssl_log"

// Private IP list file
#define	PRIVATE_IP_TXT_FILENAME		"@private_ip.txt"

// Start range of the random UDP port
#define	RAND_UDP_PORT_START			5000
#define	RAND_UDP_PORT_END			65530
#define	RAND_UDP_PORT_DEFAULT_NUM_RETRY	64

// Special Port
#define	MAKE_SPECIAL_PORT(p)		(UINT)((UINT)0x10000 | (UINT)(p))
#define	IS_SPECIAL_PORT(p)			(MAKEBOOL((p) & (UINT)0x10000))
#define	GET_SPECIAL_PORT(p)			(UINT)((UINT)(p) & (UINT)0xffff)

// Random R-UDP port ID
#define	RAND_PORT_ID_SERVER_LISTEN	1

// UDP buffer size
#define	UDP_MAX_BUFFER_SIZE			11911168

// Expiration of the cache acquired from the IP address list of the host
#define	HOST_IP_ADDRESS_LIST_CACHE	(5 * 1000)

// IP address
struct IP
{
	UCHAR addr[4];					// IPv4 address, (meaning that 223.255.255.254 = IPv6)
	UCHAR ipv6_addr[16];			// IPv6 address
	UINT ipv6_scope_id;				// IPv6 scope ID
};

// Size when comparing the IP structures only in the address part
#define	SIZE_OF_IP_FOR_ADDR			(sizeof(UCHAR) * 20)

// Compare the IP address part
#define	CmpIpAddr(ip1, ip2)			(Cmp((ip1), (ip2), SIZE_OF_IP_FOR_ADDR))

// IPv6 address (different format)
struct IPV6_ADDR
{
	UCHAR Value[16];				// Value
} GCC_PACKED;

// IPv6 Address Types
#define IPV6_ADDR_UNICAST						1	// Unicast
#define IPV6_ADDR_LOCAL_UNICAST					2	// Local unicast
#define IPV6_ADDR_GLOBAL_UNICAST				4	// Global Unicast
#define IPV6_ADDR_MULTICAST						8	// Multicast
#define IPV6_ADDR_ALL_NODE_MULTICAST			16	// All-nodes multicast
#define IPV6_ADDR_ALL_ROUTER_MULTICAST			32	// All routers multicast
#define IPV6_ADDR_SOLICIATION_MULTICAST			64	// Solicited-node multicast
#define	IPV6_ADDR_ZERO							128	// All zeros
#define	IPV6_ADDR_LOOPBACK						256	// Loop-back


// DNS cache list
struct DNSCACHE
{
	char *HostName;
	IP IpAddress;
};

// Client list
struct IP_CLIENT
{
	IP IpAddress;					// IP address
	UINT NumConnections;			// The number of connections
};

// Socket event
struct SOCK_EVENT
{
	REF *ref;						// Reference counter
#ifdef	OS_WIN32
	void *hEvent;					// Pointer to a Win32 event handle
#else	// OS_WIN32
	LIST *SockList;					// Socket list
	int pipe_read, pipe_write;		// Pipe
	UINT current_pipe_data;			// Amount of data in the current pipe
#endif	// OS_WIN32
};

// Type of socket
#define	SOCK_TCP				1
#define	SOCK_UDP				2
#define	SOCK_INPROC				3
#define	SOCK_RUDP_LISTEN		5
#define	SOCK_REVERSE_LISTEN		6

// SSL Accept Settings
struct SSL_ACCEPT_SETTINGS
{
	bool Tls_Disable1_0;
	bool Tls_Disable1_1;
	bool Tls_Disable1_2;
};

// Socket
struct SOCK
{
	REF *ref;					// Reference counter
	LOCK *lock;					// Lock
	LOCK *ssl_lock;				// Lock related to the SSL
	LOCK *disconnect_lock;		// Disconnection lock
	SOCKET socket;				// Socket number
	SSL *ssl;					// SSL object
	struct ssl_ctx_st *ssl_ctx;	// SSL_CTX
	char SniHostname[256];		// SNI host name
	UINT Type;					// Type of socket
	bool Connected;				// Connecting flag
	bool ServerMode;			// Server mode
	bool AsyncMode;				// Asynchronous mode
	bool SecureMode;			// SSL communication mode
	bool ListenMode;			// In listening
	BUF *SendBuf;				// Transmission buffer
	bool IpClientAdded;			// Whether it has been added to the list IP_CLIENT
	bool LocalOnly;				// Only local
	bool EnableConditionalAccept;	// Conditional Accept is Enabled
	IP RemoteIP;				// IP address of the remote host
	IP LocalIP;					// IP address of the local host
	char *RemoteHostname;		// Remote host name
	UINT RemotePort;			// Port number of the remote side
	UINT LocalPort;				// Port number of the local side
	UINT64 SendSize;			// Total size of the sent data
	UINT64 RecvSize;			// Total size of received data
	UINT64 SendNum;				// Number of sent data blocks
	UINT64 RecvNum;				// Number of received data blocks
	X *RemoteX;					// Certificate of the remote host
	X *LocalX;					// Certificate of the local host
	char *CipherName;			// Cipher algorithm name
	char *WaitToUseCipher;		// Set the algorithm name to want to use
	bool IgnoreRecvErr;			// Whether the RecvFrom error is ignorable
	bool IgnoreSendErr;			// Whether the SendTo error is ignorable
	UINT TimeOut;				// Time-out value
	SOCK_EVENT *SockEvent;		// Associated socket-event
	bool CancelAccept;			// Cancel flag of the Accept
	bool AcceptCanceled;		// Flag which shows canceling of the Accept
	bool WriteBlocked;			// Previous write is blocked
	bool NoNeedToRead;			// Is not required to read
	bool Disconnecting;			// Disconnecting
	bool UdpBroadcast;			// UDP broadcast mode
	void *Param;				// Any parameters
	bool IPv6;					// IPv6
	bool IsRawSocket;			// Whether it is a raw socket
	const char *SslVersion;		// SSL version
	UINT RawSocketIPProtocol;	// IP protocol number if it's a raw socket
	TUBE *SendTube;				// Tube for transmission
	TUBE *RecvTube;				// Tube for reception
	QUEUE *InProcAcceptQueue;	// Accept queue of the in-process socket
	EVENT *InProcAcceptEvent;	// Accept event of the in-process socket
	FIFO *InProcRecvFifo;		// Receive FIFO of the in-process socket
	UINT UdpMaxMsgSize;			// Maximum transmitting and receiving size at a time on UDP
	int CurrentTos;				// Current ToS value
	bool IsTtlSupported;		// Whether the TTL value is supported
	UINT CurrentTtl;			// Current TTL value
	RUDP_STACK *R_UDP_Stack;	// R-UDP stack
	char UnderlayProtocol[64];	// Underlying protocol
	QUEUE *ReverseAcceptQueue;	// Accept queue for the reverse socket
	EVENT *ReverseAcceptEvent;	// Accept event for the reverse socket
	bool IsReverseAcceptedSocket;	// Whether it is a reverse socket
	IP Reverse_MyServerGlobalIp;	// Self global IP address when using the reverse socket
	UINT Reverse_MyServerPort;		// Self port number when using the reverse socket
	UCHAR Ssl_Init_Async_SendAlert[2];	// Initial state of SSL send_alert
	SSL_ACCEPT_SETTINGS SslAcceptSettings;	// SSL Accept Settings
	bool RawIP_HeaderIncludeFlag;

#ifdef	ENABLE_SSL_LOGGING
	// SSL Logging (for debug)
	bool IsSslLoggingEnabled;	// Flag
	IO *SslLogging_Recv;		// for Recv
	IO *SslLogging_Send;		// for Send
	LOCK *SslLogging_Lock;		// Locking
#endif	// ENABLE_SSL_LOGGING

	void *hAcceptEvent;			// Event for Accept

	// R-UDP socket related
	bool IsRUDPSocket;			// Whether this is R-UDP socket
	TUBE *BulkSendTube;			// Tube for Bulk send
	TUBE *BulkRecvTube;			// Tube for Bulk receive
	SHARED_BUFFER *BulkSendKey;	// Bulk send key
	SHARED_BUFFER *BulkRecvKey;	// Bulk receive key
	UINT RUDP_OptimizedMss;		// Optimal MSS value

#ifdef	OS_UNIX
	pthread_t CallingThread;	// Thread that is calling the system call
#endif	// OS_UNIX

#ifdef	OS_WIN32
	void *hEvent;				// Event for asynchronous mode
#endif	// OS_WIN32
};

// Underlying protocol description string of socket
#define	SOCK_UNDERLAY_NATIVE_V6		"Standard TCP/IP (IPv6)"
#define	SOCK_UNDERLAY_NATIVE_V4		"Standard TCP/IP (IPv4)"
#define	SOCK_UNDERLAY_NAT_T			"VPN over UDP with NAT-T (IPv4)"
#define	SOCK_UNDERLAY_DNS			"VPN over DNS (IPv4)"
#define	SOCK_UNDERLAY_ICMP			"VPN over ICMP (IPv4)"
#define	SOCK_UNDERLAY_INPROC		"In-Process Pipe"
#define	SOCK_UNDERLAY_INPROC_EX		"Legacy VPN - %s"
#define	SOCK_UNDERLAY_AZURE			"TCP/IP via VPN Azure (IPv4)"

// Constant of the return value
#define	SOCK_LATER	(0xffffffff)	// In blocking

// Socket Set
#define	MAX_SOCKSET_NUM		60		// Number of sockets that can be stored in a socket set
struct SOCKSET
{
	UINT NumSocket;					// The number of sockets
	SOCK *Sock[MAX_SOCKSET_NUM];	// Array of pointers to the socket
};

// Cancel object
struct CANCEL
{
	REF *ref;						// Reference counter
	bool SpecialFlag;				// Special flag (associated to the event which is generated by Win32 driver)
#ifdef	OS_WIN32
	void *hEvent;					// Pointer to a Win32 event handle
#else	// OS_WIN32
	int pipe_read, pipe_write;		// Pipe
	int pipe_special_read2, pipe_special_read3;
#endif	// OS_WIN32
};

// Routing table entry
struct ROUTE_ENTRY
{
	IP DestIP;
	IP DestMask;
	IP GatewayIP;
	bool LocalRouting;
	bool PPPConnection;
	UINT Metric;
	UINT OldIfMetric;
	UINT InterfaceID;
	UINT64 InnerScore;
};

// Routing table
struct ROUTE_TABLE
{
	UINT NumEntry;
	UINT HashedValue;
	ROUTE_ENTRY **Entry;
};

// ICMP response result
struct ICMP_RESULT
{
	bool Ok;										// Whether a correct response returned
	bool Timeout;									// Whether a time-out is occurred
	UCHAR Type;										// Message type
	UCHAR Code;										// Message code
	UCHAR Ttl;										// TTL
	UCHAR *Data;									// Data body
	UINT DataSize;									// Data size
	UINT Rtt;										// Round Trip Time
	IP IpAddress;									// IP address
};


// Host name cache list
typedef struct HOSTCACHE
{
	UINT64 Expires;							// Expiration
	IP IpAddress;							// IP address
	char HostName[256];						// Host name
} HOSTCACHE;

// NETBIOS name requests
typedef struct NBTREQUEST
{
	USHORT TransactionId;
	USHORT Flags;
	USHORT NumQuestions;
	USHORT AnswerRRs;
	USHORT AuthorityRRs;
	USHORT AdditionalRRs;
	UCHAR Query[38];
} NBTREQUEST;

// NETBIOS name response
typedef struct NBTRESPONSE
{
	USHORT TransactionId;
	USHORT Flags;
	USHORT NumQuestions;
	USHORT AnswerRRs;
	USHORT AuthorityRRs;
	USHORT AdditionalRRs;
	UCHAR Response[61];
} NBTRESPONSE;

// Socket list
typedef struct SOCKLIST
{
	LIST *SockList;
} SOCKLIST;


// Parameters for timeout thread for Solaris
typedef struct SOCKET_TIMEOUT_PARAM{
	SOCK *sock;
	CANCEL *cancel;
	THREAD *thread;
	bool unblocked;
} SOCKET_TIMEOUT_PARAM;

// Parameters for GetIP thread
struct GETIP_THREAD_PARAM
{
	REF *Ref;
	char HostName[MAX_PATH];
	bool IPv6;
	UINT Timeout;
	IP Ip;
	bool Ok;
};

// Parameters for the IP address release thread
struct WIN32_RELEASEADDRESS_THREAD_PARAM
{
	REF *Ref;
	char Guid[MAX_SIZE];
	UINT Timeout;
	bool Ok;
	bool Renew;
};

// TCP table entry
typedef struct TCPTABLE
{
	UINT Status;
	IP LocalIP;
	UINT LocalPort;
	IP RemoteIP;
	UINT RemotePort;
	UINT ProcessId;
} TCPTABLE;

// State of TCP
#define	TCP_STATE_CLOSED				1
#define	TCP_STATE_LISTEN				2
#define	TCP_STATE_SYN_SENT				3
#define	TCP_STATE_SYN_RCVD				4
#define	TCP_STATE_ESTAB					5
#define	TCP_STATE_FIN_WAIT1				6
#define	TCP_STATE_FIN_WAIT2				7
#define	TCP_STATE_CLOSE_WAIT			8
#define	TCP_STATE_CLOSING				9
#define	TCP_STATE_LAST_ACK				10
#define	TCP_STATE_TIME_WAIT				11
#define	TCP_STATE_DELETE_TCB			12

// Routing table changing notification
struct ROUTE_CHANGE
{
	ROUTE_CHANGE_DATA *Data;
};

// Tube flush list
struct TUBE_FLUSH_LIST
{
	LIST *List;							// List
};

// Tube
struct TUBE
{
	REF *Ref;							// Reference counter
	LOCK *Lock;							// Lock
	QUEUE *Queue;						// Packet queue
	EVENT *Event;						// Event
	SOCK_EVENT *SockEvent;				// SockEvent
	UINT SizeOfHeader;					// Header size
	TUBEPAIR_DATA *TubePairData;		// Tube pair data
	UINT IndexInTubePair;				// Number in the tube pair
	bool IsInFlushList;					// Whether it is registered in the Tube Flush List
	void *Param1, *Param2, *Param3;
	UINT IntParam1, IntParam2, IntParam3;
};

// Data that is to send and to receive in the tube
struct TUBEDATA
{
	void *Data;							// Body of data
	UINT DataSize;						// The size of the data
	void *Header;						// The body of the header
	UINT HeaderSize;					// Size of the header
};

// Tube pair data
struct TUBEPAIR_DATA
{
	bool IsDisconnected;				// Disconnection flag
	REF *Ref;							// Reference counter
	LOCK *Lock;							// Lock
	EVENT *Event1, *Event2;				// Event
	SOCK_EVENT *SockEvent1, *SockEvent2;	// SockEvent
};

// UDP listener socket entry
struct UDPLISTENER_SOCK
{
	IP IpAddress;						// IP address
	UINT Port;							// Port number
	SOCK *Sock;							// Socket
	bool HasError;						// Whether an error occurs
	bool Mark;							// Mark
	bool ErrorDebugDisplayed;			// Whether the error has been displayed
	UINT64 NextMyIpAndPortPollTick;		// Time to check the self IP address and port number next
	IP PublicIpAddress;					// Global IP address
	UINT PublicPort;					// Global port number
};

// UDP packet
struct UDPPACKET
{
	IP SrcIP;							// Source IP address
	IP DstIP;							// Destination IP address
	UINT SrcPort;						// Source port
	UINT DestPort;						// Destination port
	UINT Size;							// Data size
	void *Data;							// Data body
	UINT Type;							// Type
};

// UDP listener packet receipt notification procedure
typedef void (UDPLISTENER_RECV_PROC)(UDPLISTENER *u, LIST *packet_list);

// UDP listener
struct UDPLISTENER
{
	bool Halt;							// Halting flag
	SOCK_EVENT *Event;					// Event
	THREAD *Thread;						// Thread
	LIST *PortList;						// Port list
	LIST *SockList;						// Socket list
	UINT64 LastCheckTick;				// Time which the socket list was checked last
	UDPLISTENER_RECV_PROC *RecvProc;	// Receive procedure
	LIST *SendPacketList;				// Transmission packet list
	void *Param;						// Parameters
	INTERRUPT_MANAGER *Interrupts;		// Interrupt manager
	bool HostIPAddressListChanged;		// IP address list of the host has changed
	bool IsEspRawPortOpened;			// Whether the raw port opens
	bool PollMyIpAndPort;				// Examine whether the global IP and the port number of its own
	QUERYIPTHREAD *GetNatTIpThread;		// NAT-T IP address acquisition thread
	IP ListenIP;						// Listen IP
};

#define	QUERYIPTHREAD_INTERVAL_LAST_OK	(3 * 60 * 60 * 1000)
#define	QUERYIPTHREAD_INTERVAL_LAST_NG	(30 * 1000)

// IP address acquisition thread
struct QUERYIPTHREAD
{
	THREAD *Thread;						// Thread
	EVENT *HaltEvent;					// Halting event
	bool Halt;							// Halting flag
	LOCK *Lock;							// Lock
	IP Ip;								// Get the IP address
	char Hostname[MAX_SIZE];			// Host name
	UINT IntervalLastOk;				// Interval if last was OK
	UINT IntervalLastNg;				// Interval if last was NG
};

// Interrupt management
struct INTERRUPT_MANAGER
{
	LIST *TickList;						// Time list
};

// SSL BIO
struct SSL_BIO
{
	BIO *bio;							// BIO
	FIFO *SendFifo;						// Transmission FIFO
	FIFO *RecvFifo;						// Reception FIFO
	bool IsDisconnected;				// Disconnected
	bool NoFree;						// Not to release the BIO
};

// SSL pipe
struct SSL_PIPE
{
	bool ServerMode;					// Whether it's in the server mode
	bool IsDisconnected;				// Disconnected
	SSL *ssl;							// SSL object
	struct ssl_ctx_st *ssl_ctx;			// SSL_CTX
	SSL_BIO *SslInOut;					// I/O BIO for the data in the SSL tunnel
	SSL_BIO *RawIn, *RawOut;			// Input and output BIO of the data flowing through the physical network
};

// IP address block list
struct IPBLOCK
{
	IP Ip;							// IP address
	IP Mask;						// Subnet mask
};


// R-UDP related constants
#define	RUDP_RESEND_TIMER				200			// Retransmission timer (initial value)
#define	RUDP_RESEND_TIMER_MAX			4792		// Retransmission timer (maximum value)
#define	RUDP_KEEPALIVE_INTERVAL_MIN		2500		// Transmission interval of Keep Alive (minimum)
#define	RUDP_KEEPALIVE_INTERVAL_MAX		4792		// Transmission interval of Keep Alive (maximum)
#define	RUDP_TIMEOUT					12000		// Time-out of R-UDP communication
#define	RUDP_DIRECT_CONNECT_TIMEOUT		5000		// R-UDP direct connection time-out
#define	RUDP_MAX_SEGMENT_SIZE			512			// Maximum segment size
// Maximum R-UDP packet size
#define	RUDP_MAX_PACKET_SIZE			(RUDP_MAX_SEGMENT_SIZE + sizeof(UINT64) * RUDP_MAX_NUM_ACK + SHA1_SIZE * 2 + sizeof(UINT64) * 4 + sizeof(UINT) + 255)
#define	RUDP_MAX_NUM_ACK				64			// Maximum number of ACKs
#define	RUDP_LOOP_WAIT_INTERVAL_S		1234		// Waiting time in the thread main loop (in server side)
#define	RUDP_LOOP_WAIT_INTERVAL_C		100			// Waiting time in the thread main loop (in client side)
#define	RUDP_MAX_FIFO_SIZE				(1600 * 1600)	// The maximum FIFO buffer size

// Interval for sending ICMP Echo from the client side when R-UDP used in ICMP mode
#define	RUDP_CLIENT_ECHO_REQUEST_SEND_INTERVAL_MIN	1000
#define	RUDP_CLIENT_ECHO_REQUEST_SEND_INTERVAL_MAX	3000

// R-UDP error code
#define	RUDP_ERROR_OK					0			// Success
#define	RUDP_ERROR_UNKNOWN				1			// Unknown Error
#define	RUDP_ERROR_TIMEOUT				2			// Time-out
#define	RUDP_ERROR_NAT_T_GETIP_FAILED	3			// IP address acquisition failure of NAT-T server
#define	RUDP_ERROR_NAT_T_NO_RESPONSE	4			// There is no response from the NAT-T server
#define	RUDP_ERROR_NAT_T_TWO_OR_MORE	5			// There are two or more hosts on the same destination IP address
#define	RUDP_ERROR_NAT_T_NOT_FOUND		6			// Host does not exist at the specified IP address
#define	RUDP_ERROR_USER_CANCELED		7			// Cancel by the user

// R-UDP segment
struct RUDP_SEGMENT
{
	UINT64 SeqNo;									// Sequence number
	UINT Size;										// Size
	UCHAR Data[RUDP_MAX_SEGMENT_SIZE];				// Data
	UINT64 NextSendTick;							// Next transmission time
	UINT NumSent;									// Number of times sent
};

// Status of R-UDP session
#define	RUDP_SESSION_STATUS_CONNECT_SENT	0		// Connection request sent
#define	RUDP_SESSION_STATUS_ESTABLISHED		1		// Connection established

// Quota
#define	RUDP_QUOTA_MAX_NUM_SESSIONS_PER_IP	DYN32(RUDP_QUOTA_MAX_NUM_SESSIONS_PER_IP, 1000)	// The number of R-UDP sessions per an IP address
#define	RUDP_QUOTA_MAX_NUM_SESSIONS			DYN32(RUDP_QUOTA_MAX_NUM_SESSIONS, 30000)	// Limit of the Number of sessions

// Range of the sequence numbers of bulk packet
#define	RUDP_BULK_SEQ_NO_RANGE				16384ULL
#define	RUDP_BULK_MAX_RECV_PKTS_IN_QUEUE	8192

// R-UDP session
struct RUDP_SESSION
{
	UINT Status;						// Status
	bool ServerMode;					// Whether it's in the server mode
	bool DisconnectFlag;				// Disconnection flag
	bool DisconnectedByYou;				// Disconnected from opponent
	bool UseHMac;
	IP MyIp;							// IP address of itself
	UINT MyPort;						// Port number of itself
	IP YourIp;							// Opponent IP address
	UINT YourPort;						// Opponent port number
	LIST *SendSegmentList;				// Transmission segment list
	LIST *RecvSegmentList;				// Received segments list
	LIST *ReplyAckList;					// List of ACKs in response
	SOCK *TcpSock;						// Corresponding TCP socket
	UINT64 LastSentTick;				// Time which the data has been sent last
	UINT64 LastRecvTick;				// Time which the data has been received last
	UCHAR Key_Init[SHA1_SIZE];			// Initial key
	UCHAR Key_Send[SHA1_SIZE];			// Key that is used to send
	UCHAR Key_Recv[SHA1_SIZE];			// Key that is used to receive
	UCHAR Magic_KeepAliveRequest[SHA1_SIZE];	// The magic number for the KeepAlive request
	UCHAR Magic_KeepAliveResponse[SHA1_SIZE];	// The magic number for KeepAlive response
	UINT64 Magic_Disconnect;			// Disconnection Signal
	UINT64 NextSendSeqNo;				// Transmission sequence number to be used next
	UINT64 LastRecvCompleteSeqNo;		// Sequence number of receiving complete
										// (This indicates all segments which have sequence number up to this number are received completely)
	UCHAR NextIv[SHA1_SIZE];			// IV value to be used next
	UINT NextKeepAliveInterval;			// Interval value of KeepAlive to be used next
	FIFO *RecvFifo;						// Reception FIFO
	FIFO *SendFifo;						// Transmission FIFO
	UINT64 YourTick;					// The largest value among received Tick from the opponent
	UINT64 LatestRecvMyTick;			// Value of the last tick among the received tick values
	UINT64 LatestRecvMyTick2;			// Variable for confirming whether LatestRecvMyTick2 changes
	UINT CurrentRtt;					// Current RTT value

	UINT Icmp_Type;						// Number of Type to be used in the ICMP
	USHORT Dns_TranId;					// Value of transaction ID used in DNS
	UINT64 Client_Icmp_NextSendEchoRequest;	// Time to send the next Echo Request in the ICMP
	SHARED_BUFFER *BulkSendKey;			// Bulk send key
	SHARED_BUFFER *BulkRecvKey;			// Bulk receive key
	UCHAR BulkNextIv[SHA1_SIZE];		// Next IV to the bulk send
	UINT64 BulkNextSeqNo;				// Next SEQ NO to the bulk send
	bool FlushBulkSendTube;				// Flag to be Flush the bulk send Tube
	UINT64 BulkRecvSeqNoMax;			// Highest sequence number received
};

// NAT Traversal Server Information
#define	UDP_NAT_T_SERVER_TAG				"x%c.x%c.dev.servers.nat-traversal.softether-network.net."
#define	UDP_NAT_T_SERVER_TAG_ALT			"x%c.x%c.dev.servers.nat-traversal.uxcom.jp."
#define	UDP_NAT_T_PORT						5004

// Related to processing to get the IP address of the NAT-T server
#define	UDP_NAT_T_GET_IP_INTERVAL			DYN32(UDP_NAT_T_GET_IP_INTERVAL, (5 * 1000))		// IP address acquisition interval of NAT-T server (before success)
#define	UDP_NAT_T_GET_IP_INTERVAL_MAX		DYN32(UDP_NAT_T_GET_IP_INTERVAL, (150 * 1000))		// IP address acquisition interval of NAT-T server (before success)
#define	UDP_NAT_T_GET_IP_INTERVAL_AFTER		DYN32(UDP_NAT_T_GET_IP_INTERVAL_AFTER, (5 * 60 * 1000))	// IP address acquisition interval of NAT-T server (after success)

// Related to process to get the private IP address of itself with making a TCP connection to the NAT-T server
#define	UDP_NAT_T_GET_PRIVATE_IP_TCP_SERVER		"www.msftncsi.com."

#define	UDP_NAT_T_PORT_FOR_TCP_1			80
#define	UDP_NAT_T_PORT_FOR_TCP_2			443

#define	UDP_NAT_TRAVERSAL_VERSION			1

#define	UDP_NAT_T_GET_PRIVATE_IP_INTERVAL	DYN32(UDP_NAT_T_GET_PRIVATE_IP_INTERVAL, (15 * 60 * 1000))			// Polling interval (before success)
#define	UDP_NAT_T_GET_PRIVATE_IP_INTERVAL_AFTER_MIN	DYN32(UDP_NAT_T_GET_PRIVATE_IP_INTERVAL_AFTER_MIN, (30 * 60 * 1000))	// Polling interval (after success)
#define	UDP_NAT_T_GET_PRIVATE_IP_INTERVAL_AFTER_MAX	DYN32(UDP_NAT_T_GET_PRIVATE_IP_INTERVAL_AFTER_MAX, (60 * 60 * 1000))	// Polling interval (after success)
#define	UDP_NAT_T_GET_PRIVATE_IP_CONNECT_TIMEOUT	DYN32(UDP_NAT_T_GET_PRIVATE_IP_CONNECT_TIMEOUT, (5 * 1000))			// TCP connection time-out

// About token acquisition from the NAT-T server
#define	UDP_NAT_T_GET_TOKEN_INTERVAL_1		DYN32(UDP_NAT_T_GET_TOKEN_INTERVAL_1, (5 * 1000))		// Token acquisition interval from the NAT-T server (If not acquired)
#define	UDP_NAT_T_GET_TOKEN_INTERVAL_FAIL_MAX	DYN32(UDP_NAT_T_GET_TOKEN_INTERVAL_FAIL_MAX, 20)
#define	UDP_NAT_T_GET_TOKEN_INTERVAL_2_MIN	DYN32(UDP_NAT_T_GET_TOKEN_INTERVAL_2_MIN, (20 * 60 * 1000))	// Token acquisition interval minimum value from the NAT-T server (If token have been obtained)
#define	UDP_NAT_T_GET_TOKEN_INTERVAL_2_MAX	DYN32(UDP_NAT_T_GET_TOKEN_INTERVAL_2_MAX, (30 * 60 * 1000))	// Token acquisition interval maximum value from the NAT-T server (If token have been obtained)

// The Register interval for NAT-T server
#define	UDP_NAT_T_REGISTER_INTERVAL_INITIAL	DYN32(UDP_NAT_T_REGISTER_INTERVAL_INITIAL, (5 * 1000))		// Transmission interval when the Register is not completed
#define	UDP_NAT_T_REGISTER_INTERVAL_FAIL_MAX	DYN32(UDP_NAT_T_REGISTER_INTERVAL_FAIL_MAX, 20)
#define	UDP_NAT_T_REGISTER_INTERVAL_MIN		DYN32(UDP_NAT_T_REGISTER_INTERVAL_MIN, (220 * 1000))		// Minimum value of the Register interval
#define	UDP_NAT_T_REGISTER_INTERVAL_MAX		DYN32(UDP_NAT_T_REGISTER_INTERVAL_MAX, (240 * 1000))		// Maximum value of the Register interval

// Interval for checking whether the port number or the IP address is changed
#define	UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MIN	DYN32(UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MIN, (24 * 1000))
#define	UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MAX	DYN32(UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MAX, (28 * 1000))

// The Connect Request interval for NAT-T server
#define	UDP_NAT_T_CONNECT_INTERVAL			DYN32(UDP_NAT_T_CONNECT_INTERVAL, 200)

// Polling interval for its own IP information acquisition to the NAT-T server in regular communication between the client and the server
#define	UDP_NAT_T_INTERVAL_MIN				DYN32(UDP_NAT_T_INTERVAL_MIN, (5 * 60 * 1000))
#define	UDP_NAT_T_INTERVAL_MAX				DYN32(UDP_NAT_T_INTERVAL_MAX, (10 * 60 * 1000))
#define	UDP_NAT_T_INTERVAL_INITIAL			DYN32(UDP_NAT_T_INTERVAL_INITIAL, (3 * 1000))
#define	UDP_NAT_T_INTERVAL_FAIL_MAX			DYN32(UDP_NAT_T_INTERVAL_FAIL_MAX, 60)

// R-UDP stack callback function definition
typedef void (RUDP_STACK_INTERRUPTS_PROC)(RUDP_STACK *r);
typedef bool (RUDP_STACK_RPC_RECV_PROC)(RUDP_STACK *r, UDPPACKET *p);

// ICMP protocol number
#define	IP_PROTO_ICMPV4		0x01	// ICMPv4 protocol
#define	IP_PROTO_ICMPV6		0x3a	// ICMPv6 protocol

// R-UDP protocol
#define	RUDP_PROTOCOL_UDP				0	// UDP
#define	RUDP_PROTOCOL_ICMP				1	// ICMP
#define	RUDP_PROTOCOL_DNS				2	// DNS

// Maximum time of continuously changing of the NAT-T hostname
#define	RUDP_NATT_MAX_CONT_CHANGE_HOSTNAME	30
#define	RUDP_NATT_CONT_CHANGE_HOSTNAME_RESET_INTERVAL	(5 * 60 * 1000)

// Minimum time to wait for a trial to connect by ICMP and DNS in case failing to connect by TCP
#define	SOCK_CONNECT_WAIT_FOR_ICMP_AND_DNS_AT_LEAST		5000

#define	RUDP_MAX_VALIDATED_SOURCE_IP_ADDRESSES		512
#define	RUDP_VALIDATED_SOURCE_IP_ADDRESS_EXPIRES	(RUDP_TIMEOUT * 2)

// Validated Source IP Addresses for R-UDP
struct RUDP_SOURCE_IP
{
	UINT64 ExpiresTick;					// Expires
	IP ClientIP;						// Client IP address
};

// R-UDP stack
struct RUDP_STACK
{
	bool ServerMode;					// Whether it's in the server mode
	char SvcName[MAX_SIZE];				// Service name
	UCHAR SvcNameHash[SHA1_SIZE];		// Hash of the service name
	bool Halt;							// Halting flag
	void *Param;						// Parameters that can be used by developers
	UINT64 Now;							// Current time
	EVENT *HaltEvent;					// Halting event
	INTERRUPT_MANAGER *Interrupt;		// Interrupt manager
	LIST *SessionList;					// Session List
	SOCK *UdpSock;						// UDP socket
	UINT Port;							// Port number
	UINT Protocol;						// Protocol
	SOCK_EVENT *SockEvent;				// Socket event
	THREAD *Thread;						// Thread
	LOCK *Lock;							// Lock
	RUDP_STACK_INTERRUPTS_PROC *ProcInterrupts;	// Interrupt notification callback
	RUDP_STACK_RPC_RECV_PROC *ProcRpcRecv;	// RPC reception notification callback
	THREAD *IpQueryThread;				// NAT-T server IP inquiry thread
	UCHAR TmpBuf[65536];				// Temporary buffer
	LIST *SendPacketList;				// Transmission UDP packet list
	EVENT *NewSockConnectEvent;			// Event to inform that a new socket is connected
	QUEUE *NewSockQueue;				// Queue of new socket
	UINT64 TotalPhysicalReceived;		// Physical amount of data received
	UINT64 TotalLogicalReceived;		// Logical amount of data received
	UINT64 TotalPhysicalSent;			// Physical amount of data transmitted
	UINT64 TotalLogicalSent;			// Logical amount of data transmitted
	char CurrentRegisterHostname[MAX_SIZE];	// The host name of the the current destination of registration
	UINT NumChangedHostname;			// How number of changing NAT-T hostname has occured continuously
	UINT64 NumChangedHostnameValueResetTick;

	// NAT-T server related
	bool NoNatTRegister;				// Flag not to register with the NAT-T server
	UINT64 NatT_TranId;					// Transaction ID is used to communicate with the NAT-T server
	UINT64 NatT_SessionKey;				// Current Session Key
	IP NatT_IP;							// IP address of the NAT-T server
	IP NatT_IP_Safe;					// IP address of the NAT-T server (thread-safe)
	IP My_Private_IP;					// Private IP address of itself
	IP My_Private_IP_Safe;				// Private IP address of itself (thread-safe)
	UINT64 NatT_GetTokenNextTick;		// Time to get the next token
	UINT NatT_GetTokenFailNum;			// Token acquisition failure times
	char NatT_Token[MAX_SIZE];			// Token needed to communicate with NAT-T Server
	bool NatT_Token_Ok;					// Flag of whether it have a valid token
	UINT64 NatT_RegisterNextTick;		// Time to register next
	UINT NatT_RegisterFailNum;			// The number of Register failures
	bool NatT_Register_Ok;				// Is a successful registration
	char NatT_Registered_IPAndPort[128];		// IP address and port number at the time of registration success
	UINT64 NatT_NextNatStatusCheckTick;	// Time to check the NAT state next
	UINT LastDDnsFqdnHash;				// DNS FQDN hash value when last checked
	volatile UINT *NatTGlobalUdpPort;	// NAT-T global UDP port
	UCHAR RandPortId;					// Random UDP port ID
	bool NatT_EnableSourceIpValidation;	// Enable the source IP address validation mechanism
	LIST *NatT_SourceIpList;			// Authenticated source IP address list

	// For Client
	bool TargetIpAndPortInited;			// The target IP address and the port number are initialized
	IP TargetIp;						// Target IP address
	UINT TargetPort;					// Target port number
	EVENT *TargetConnectedEvent;		// Event to be set when the connection to the target is successful
	SOCK *TargetConnectedSock;			// Connected socket
	bool ClientInitiated;				// Flag to indicate that the connection is initiated
	bool DoNotSetTargetConnectedSock;	// Flag indicating that it should not set the TargetConnectedSock
	USHORT Client_IcmpId, Client_IcmpSeqNo;	// Sequence number and ICMP ID that is randomly generated on the client side
};

// Data for the thread for concurrent connection attempts for the R-UDP and TCP
struct CONNECT_TCP_RUDP_PARAM
{
	IP Ip;
	UINT Port;
	UINT Timeout;
	char Hostname[MAX_SIZE];
	bool *CancelFlag;
	UINT NatT_ErrorCode;
	char SvcName[MAX_SIZE];
	char HintStr[MAX_SIZE];
	char TargetHostname[MAX_SIZE];
	SOCK *Result_Nat_T_Sock;
	SOCK *Result_Tcp_Sock;
	bool Finished;
	bool Ok;
	UINT64 FinishedTick;
	EVENT *FinishEvent;
	UINT RUdpProtocol;
	UINT Delay;
	bool Tcp_TryStartSsl;
	LOCK *CancelLock;
	SOCK *CancelDisconnectSock;
	bool Tcp_InNegotiation;
};

#define	SSL_DEFAULT_CONNECT_TIMEOUT		(15 * 1000)		// SSL default timeout

// Header for TCP Pair 
struct TCP_PAIR_HEADER
{
	bool EnableHMac;
};

// The constants for file query by using UDP
#define	UDP_FILE_QUERY_RETRY_INTERVAL	100			// Retry interval
#define	UDP_FILE_QUERY_DST_PORT			5004		// Destination UDP port number
#define	UDP_FILE_QUERY_MAGIC_NUMBER		"{5E465695-7923-4CCD-9B51-44444BE1E758}"	// Magic number
#define	UDP_FILE_QUERY_BFLETS_TXT_FILENAME	"|BFletsUdpList.txt"	// Text file name of the IPv6 node list

// The constant for DNS proxy for the B FLETs
#define	BFLETS_DNS_PROXY_PORT			443
#define	BFLETS_DNS_PROXY_PATH			"/ddns/queryhost.aspx"
#define	BFLETS_DNS_PROXY_CERT_HASH		"EFAC5FA0CDD14E0F864EED58A73C35D7E33B62F3"
#define	BFLETS_DNS_PROXY_TIMEOUT_FOR_GET_F	500		// Timeout when searching for the server by UDP
#define	BFLETS_DNS_PROXY_TIMEOUT_FOR_QUERY	3000	// Timeout for the response from the proxy DNS server

// FLET'S Hikar-Next (East) DNS proxy host name
#define	FLETS_NGN_EAST_DNS_PROXY_HOSTNAME		"senet.aoi.flets-east.jp"
#define	FLETS_NGN_WEST_DNS_PROXY_HOSTNAME		"senet.p-ns.flets-west.jp"
#define	FLETS_NGN_DNS_QUERY_TIMEOUT				1000		// FLET'S Hikar-Next host name query timeout

// Detection result of the type of FLET'S line
#define	FLETS_DETECT_TYPE_EAST_BFLETS_PRIVATE		1	// NTT East B-FLETs
#define	FLETS_DETECT_TYPE_EAST_NGN_PRIVATE			2	// Wrapping in network of NTT East NGN
#define	FLETS_DETECT_TYPE_WEST_NGN_PRIVATE			4	// Wrapping in network of NTT West NGN

// NIC adapter entry
struct NIC_ENTRY
{
	char IfName[MAX_SIZE];
	UCHAR MacAddress[6];
};


// HTTP value
struct HTTP_VALUE
{
	char *Name;						// Name
	char *Data;						// Data
};

// HTTP header
struct HTTP_HEADER
{
	char *Method;					// Method
	char *Target;					// Target
	char *Version;					// Version
	LIST *ValueList;				// Value list
};

// HTTPS server / client related string constant
#define	DEFAULT_USER_AGENT	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0"
#define	DEFAULT_ACCEPT		"image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/msword, application/vnd.ms-powerpoint, application/vnd.ms-excel, */*"
#define	DEFAULT_ENCODING	"gzip, deflate"
#define	HTTP_CONTENT_TYPE	"text/html; charset=iso-8859-1"
#define	HTTP_CONTENT_TYPE2	"application/octet-stream"
#define	HTTP_CONTENT_TYPE3	"image/jpeg"
#define	HTTP_CONTENT_TYPE4	"text/html"
#define	HTTP_CONTENT_TYPE5	"message/rfc822"
#define	HTTP_KEEP_ALIVE		"timeout=15; max=19"
#define	HTTP_VPN_TARGET		"/vpnsvc/vpn.cgi"
#define	HTTP_VPN_TARGET2	"/vpnsvc/connect.cgi"
#define HTTP_VPN_TARGET_POSTDATA	"VPNCONNECT"
#define	HTTP_SAITAMA		"/saitama.jpg"
#define	HTTP_PICTURES		"/picture"
// Maximum size of the custom HTTP header
#define	HTTP_CUSTOM_HEADER_MAX_SIZE	1024
// Maximum size of a single line in the HTTP header
#define	HTTP_HEADER_LINE_MAX_SIZE	4096
// Maximum number of lines in the HTTP header
#define	HTTP_HEADER_MAX_LINES		128
// Maximum size of the random number to be included in the PACK
#define	HTTP_PACK_RAND_SIZE_MAX		1000
// Maximum PACK size in the HTTP
#define	HTTP_PACK_MAX_SIZE			65536





int GetCurrentTimezone();

bool GetSniNameFromSslPacket(UCHAR *packet_buf, UINT packet_size, char *sni, UINT sni_size);

void SetDhParam(DH_CTX *dh);

bool IsUseDnsProxy();
bool IsUseAlternativeHostname();

#ifdef	OS_WIN32
int GetCurrentTimezoneWin32();
#endif	// OS_WIN32

HTTP_VALUE *GetHttpValue(HTTP_HEADER *header, char *name);
void AddHttpValue(HTTP_HEADER *header, HTTP_VALUE *value);
bool AddHttpValueStr(HTTP_HEADER* header, char *string);
HTTP_HEADER *NewHttpHeader(char *method, char *target, char *version);
HTTP_HEADER *NewHttpHeaderEx(char *method, char *target, char *version, bool no_sort);
int CompareHttpValue(void *p1, void *p2);
void FreeHttpValue(HTTP_VALUE *value);
void FreeHttpHeader(HTTP_HEADER *header);

bool SendPack(SOCK *s, PACK *p);
PACK *RecvPack(SOCK *s);
PACK *RecvPackWithHash(SOCK *s);
bool SendPackWithHash(SOCK *s, PACK *p);

UINT GetErrorFromPack(PACK *p);
PACK *PackError(UINT error);

void CreateDummyValue(PACK *p);

HTTP_VALUE *NewHttpValue(char *name, char *data);
char *RecvLine(SOCK *s, UINT max_size);
HTTP_HEADER *RecvHttpHeader(SOCK *s);
bool SendHttpHeader(SOCK *s, HTTP_HEADER *header);
char *HttpHeaderToStr(HTTP_HEADER *header);
bool PostHttp(SOCK *s, HTTP_HEADER *header, void *post_data, UINT post_size);
UINT GetContentLength(HTTP_HEADER *header);
void GetHttpDateStr(char *str, UINT size, UINT64 t);
bool HttpSendForbidden(SOCK *s, char *target, char *server_id);
bool HttpSendNotFound(SOCK *s, char *target);
bool HttpSendNotImplemented(SOCK *s, char *method, char *target, char *version);
bool HttpServerSend(SOCK *s, PACK *p);
bool HttpClientSend(SOCK *s, PACK *p);
PACK *HttpServerRecv(SOCK *s);
PACK *HttpClientRecv(SOCK *s);

bool GetIPViaDnsProxyForJapanFlets(IP *ip_ret, char *hostname, bool ipv6, UINT timeout, bool *cancel, char *dns_proxy_hostname);
bool GetDnsProxyIPAddressForJapanBFlets(IP *ip_ret, UINT timeout, bool *cancel);
BUF *QueryFileByUdpForJapanBFlets(UINT timeout, bool *cancel);
BUF *QueryFileByIPv6Udp(LIST *ip_list, UINT timeout, bool *cancel);
UINT DetectFletsType();

void ListenTcpForPopupFirewallDialog();

bool DetectIsServerSoftEtherVPN(SOCK *s);
void ConnectThreadForTcp(THREAD *thread, void *param);
void ConnectThreadForRUDP(THREAD *thread, void *param);
void ConnectThreadForOverDnsOrIcmp(THREAD *thread, void *param);
SOCK *NewRUDPClientNatT(char *svc_name, IP *ip, UINT *error_code, UINT timeout, bool *cancel, char *hint_str, char *target_hostname);
RUDP_STACK *NewRUDPServer(char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, bool no_natt_register, bool over_dns_mode, volatile UINT *natt_global_udp_port, UCHAR rand_port_id, IP *listen_ip);
SOCK *NewRUDPClientDirect(char *svc_name, IP *ip, UINT port, UINT *error_code, UINT timeout, bool *cancel, SOCK *sock, SOCK_EVENT *sock_event, UINT local_port, bool over_dns_mode);
RUDP_STACK *NewRUDP(bool server_mode, char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, SOCK *sock, SOCK_EVENT *sock_event, bool server_no_natt_register, bool over_dns_mode, IP *client_target_ip, volatile UINT *natt_global_udp_port, UCHAR rand_port_id, IP *listen_ip);
void FreeRUDP(RUDP_STACK *r);
void RUDPMainThread(THREAD *thread, void *param);
void RUDPRecvProc(RUDP_STACK *r, UDPPACKET *p);
void RUDPInterruptProc(RUDP_STACK *r);
void RUDPIpQueryThread(THREAD *thread, void *param);
void RUDPSendPacket(RUDP_STACK *r, IP *dest_ip, UINT dest_port, void *data, UINT size, UINT icmp_type);
void GetCurrentMachineIpProcessHash(void *hash);
void GetCurrentMachineIpProcessHashInternal(void *hash);
int RUDPCompareSessionList(void *p1, void *p2);
RUDP_SESSION *RUDPNewSession(bool server_mode, IP *my_ip, UINT my_port, IP *your_ip, UINT your_port, UCHAR *init_key);
void RUDPFreeSession(RUDP_SESSION *se);
int RUDPCompareSegmentList(void *p1, void *p2);
RUDP_SESSION *RUDPSearchSession(RUDP_STACK *r, IP *my_ip, UINT my_port, IP *your_ip, UINT your_port);
void RUDPSendSegmentNow(RUDP_STACK *r, RUDP_SESSION *se, UINT64 seq_no, void *data, UINT size);
void RUDPSendSegment(RUDP_STACK *r, RUDP_SESSION *se, void *data, UINT size);
bool RUDPProcessRecvPacket(RUDP_STACK *r, RUDP_SESSION *se, void *recv_data, UINT recv_size);
bool RUDPCheckSignOfRecvPacket(RUDP_STACK *r, RUDP_SESSION *se, void *recv_data, UINT recv_size);
void RUDPProcessAck(RUDP_STACK *r, RUDP_SESSION *se, UINT64 seq);
void RUDPProcessAck2(RUDP_STACK *r, RUDP_SESSION *se, UINT64 max_seq);
void RUDPProcessRecvPayload(RUDP_STACK *r, RUDP_SESSION *se, UINT64 seq, void *payload_data, UINT payload_size);
void RUDPInitSock(RUDP_STACK *r, RUDP_SESSION *se);
void RUDPDisconnectSession(RUDP_STACK *r, RUDP_SESSION *se, bool disconnected_by_you);
UINT64 RUDPGetCurrentSendingMinSeqNo(RUDP_SESSION *se);
UINT64 RUDPGetCurrentSendingMaxSeqNo(RUDP_SESSION *se);
SOCK *ListenRUDP(char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, bool no_natt_register, bool over_dns_mode);
SOCK *ListenRUDPEx(char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, bool no_natt_register, bool over_dns_mode,
				   volatile UINT *natt_global_udp_port, UCHAR rand_port_id, IP *listen_ip);
SOCK *AcceptRUDP(SOCK *s);
void *InitWaitUntilHostIPAddressChanged();
void FreeWaitUntilHostIPAddressChanged(void *p);
void WaitUntilHostIPAddressChanged(void *p, EVENT *event, UINT timeout, UINT ip_check_interval);
UINT GetHostIPAddressHash32();
bool GetMyPrivateIP(IP *ip, bool from_vg);
char *GetRandHostNameForGetMyPrivateIP();
UINT GenRandInterval(UINT min, UINT max);
void RUDPProcess_NatT_Recv(RUDP_STACK *r, UDPPACKET *udp);
void RUDPDo_NatT_Interrupt(RUDP_STACK *r);
void RUDPGetRegisterHostNameByIP(char *dst, UINT size, IP *ip);
bool RUDPParseIPAndPortStr(void *data, UINT data_size, IP *ip, UINT *port);
void ParseNtUsername(char *src_username, char *dst_username, UINT dst_username_size, char *dst_domain, UINT dst_domain_size, bool do_not_parse_atmark);
void RUDPBulkSend(RUDP_STACK *r, RUDP_SESSION *se, void *data, UINT data_size);
bool RUDPProcessBulkRecvPacket(RUDP_STACK *r, RUDP_SESSION *se, void *recv_data, UINT recv_size);
UINT RUDPCalcBestMssForBulk(RUDP_STACK *r, RUDP_SESSION *se);
bool IsIPLocalHostOrMySelf(IP *ip);
bool RUDPIsIpInValidateList(RUDP_STACK *r, IP *ip);
void RUDPAddIpToValidateList(RUDP_STACK *r, IP *ip);

bool GetBestLocalIpForTarget(IP *local_ip, IP *target_ip);
SOCK *NewUDP4ForSpecificIp(IP *target_ip, UINT port);

#ifdef	OS_WIN32

// Function prototype for Win32
void Win32InitSocketLibrary();
void Win32FreeSocketLibrary();
void Win32Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2);
void Win32InitAsyncSocket(SOCK *sock);
void Win32JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event);
void Win32FreeAsyncSocket(SOCK *sock);
void Win32IpForwardRowToRouteEntry(ROUTE_ENTRY *entry, void *ip_forward_row);
void Win32RouteEntryToIpForwardRow(void *ip_forward_row, ROUTE_ENTRY *entry);
int Win32CompareRouteEntryByMetric(void *p1, void *p2);
ROUTE_TABLE *Win32GetRouteTable();
bool Win32AddRouteEntry(ROUTE_ENTRY *e, bool *already_exists);
void Win32DeleteRouteEntry(ROUTE_ENTRY *e);
void Win32UINTToIP(IP *ip, UINT i);
UINT Win32IPToUINT(IP *ip);
UINT Win32GetVLanInterfaceID(char *instance_name);
char **Win32EnumVLan(char *tag_name);
void Win32Cancel(CANCEL *c);
void Win32CleanupCancel(CANCEL *c);
CANCEL *Win32NewCancel();
SOCK_EVENT *Win32NewSockEvent();
void Win32SetSockEvent(SOCK_EVENT *event);
void Win32CleanupSockEvent(SOCK_EVENT *event);
bool Win32WaitSockEvent(SOCK_EVENT *event, UINT timeout);
bool Win32GetDefaultDns(IP *ip, char *domain, UINT size);
bool Win32GetDnsSuffix(char *domain, UINT size);
void Win32RenewDhcp9x(UINT if_id);
void Win32ReleaseDhcp9x(UINT if_id, bool wait);
void Win32FlushDnsCache();
int CompareIpAdapterIndexMap(void *p1, void *p2);
ROUTE_CHANGE *Win32NewRouteChange();
void Win32FreeRouteChange(ROUTE_CHANGE *r);
bool Win32IsRouteChanged(ROUTE_CHANGE *r);
bool Win32GetAdapterFromGuid(void *a, char *guid);
SOCKET Win32Accept(SOCK *sock, SOCKET s, struct sockaddr *addr, int *addrlen, bool ipv6);

bool Win32ReleaseAddress(void *a);
bool Win32ReleaseAddressByGuid(char *guid);
bool Win32ReleaseAddressByGuidEx(char *guid, UINT timeout);
void Win32ReleaseAddressByGuidExThread(THREAD *t, void *param);
void ReleaseWin32ReleaseAddressByGuidThreadParam(WIN32_RELEASEADDRESS_THREAD_PARAM *p);
bool Win32ReleaseOrRenewAddressByGuidEx(char *guid, UINT timeout, bool renew);
bool Win32RenewAddress(void *a);
bool Win32RenewAddressByGuid(char *guid);
bool Win32RenewAddressByGuidEx(char *guid, UINT timeout);


#else	// OS_WIN32

// Function prototype for UNIX
void UnixInitSocketLibrary();
void UnixFreeSocketLibrary();
void UnixSelect(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2);
void UnixInitAsyncSocket(SOCK *sock);
void UnixJoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event);
void UnixFreeAsyncSocket(SOCK *sock);
ROUTE_TABLE *UnixGetRouteTable();
bool UnixAddRouteEntry(ROUTE_ENTRY *e, bool *already_exists);
void UnixDeleteRouteEntry(ROUTE_ENTRY *e);
UINT UnixGetVLanInterfaceID(char *instance_name);
char **UnixEnumVLan(char *tag_name);
void UnixCancel(CANCEL *c);
void UnixCleanupCancel(CANCEL *c);
CANCEL *UnixNewCancel();
SOCK_EVENT *UnixNewSockEvent();
void UnixSetSockEvent(SOCK_EVENT *event);
void UnixCleanupSockEvent(SOCK_EVENT *event);
bool UnixWaitSockEvent(SOCK_EVENT *event, UINT timeout);
bool UnixGetDefaultDns(IP *ip);
void UnixNewPipe(int *pipe_read, int *pipe_write);
void UnixWritePipe(int pipe_write);
void UnixDeletePipe(int p1, int p2);
void UnixSelectInner(UINT num_read, UINT *reads, UINT num_write, UINT *writes, UINT timeout);
void UnixSetSocketNonBlockingMode(int fd, bool nonblock);

#endif	// OS_WIN32

// Function prototype
void InitNetwork();
void FreeNetwork();
void InitDnsCache();
void FreeDnsCache();
void LockDnsCache();
void UnlockDnsCache();
int CompareDnsCache(void *p1, void *p2);
void GenDnsCacheKeyName(char *dst, UINT size, char *src, bool ipv6);
void NewDnsCacheEx(char *hostname, IP *ip, bool ipv6);
DNSCACHE *FindDnsCacheEx(char *hostname, bool ipv6);
bool QueryDnsCacheEx(IP *ip, char *hostname, bool ipv6);
void NewDnsCache(char *hostname, IP *ip);
DNSCACHE *FindDnsCache(char *hostname);
bool QueryDnsCache(IP *ip, char *hostname);
void InAddrToIP(IP *ip, struct in_addr *addr);
void InAddrToIP6(IP *ip, struct in6_addr *addr);
void IPToInAddr(struct in_addr *addr, IP *ip);
void IPToInAddr6(struct in6_addr *addr, IP *ip);
bool StrToIP(IP *ip, char *str);
UINT StrToIP32(char *str);
UINT UniStrToIP32(wchar_t *str);
void IPToStr(char *str, UINT size, IP *ip);
void IPToStr4(char *str, UINT size, IP *ip);
void IPToStr32(char *str, UINT size, UINT ip);
void IPToStr4or6(char *str, UINT size, UINT ip_4_uint, UCHAR *ip_6_bytes);
void IPToUniStr(wchar_t *str, UINT size, IP *ip);
void IPToUniStr32(wchar_t *str, UINT size, UINT ip);
bool GetIPEx(IP *ip, char *hostname, bool ipv6);
bool GetIP46Ex(IP *ip4, IP *ip6, char *hostname, UINT timeout, bool *cancel);
bool GetIP(IP *ip, char *hostname);
bool GetIP4(IP *ip, char *hostname);
bool GetIP6(IP *ip, char *hostname);
bool GetIP4Ex(IP *ip, char *hostname, UINT timeout, bool *cancel);
bool GetIP6Ex(IP *ip, char *hostname, UINT timeout, bool *cancel);
bool GetIP4Ex6Ex(IP *ip, char *hostname, UINT timeout, bool ipv6, bool *cancel);
bool GetIP4Ex6Ex2(IP *ip, char *hostname, UINT timeout, bool ipv6, bool *cancel, bool only_direct_dns);
void GetIP4Ex6ExThread(THREAD *t, void *param);
void ReleaseGetIPThreadParam(GETIP_THREAD_PARAM *p);
void CleanupGetIPThreadParam(GETIP_THREAD_PARAM *p);
bool GetIP4Inner(IP *ip, char *hostname);
bool GetIP6Inner(IP *ip, char *hostname);
bool GetHostNameInner(char *hostname, UINT size, IP *ip);
bool GetHostNameInner6(char *hostname, UINT size, IP *ip);
bool GetHostName(char *hostname, UINT size, IP *ip);
void GetHostNameThread(THREAD *t, void *p);
void GetMachineName(char *name, UINT size);
void GetMachineNameEx(char *name, UINT size, bool no_load_hosts);
bool GetMachineNameFromHosts(char *name, UINT size);
void GetMachineHostName(char *name, UINT size);
void UINTToIP(IP *ip, UINT value);
UINT IPToUINT(IP *ip);
SOCK *NewSock();
void ReleaseSock(SOCK *s);
void CleanupSock(SOCK *s);
SOCK *Connect(char *hostname, UINT port);
SOCK *ConnectEx(char *hostname, UINT port, UINT timeout);
SOCK *ConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag);
SOCK *ConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, char *nat_t_svc_name, UINT *nat_t_error_code, bool try_start_ssl, bool no_get_hostname);
SOCK *ConnectEx4(char *hostname, UINT port, UINT timeout, bool *cancel_flag, char *nat_t_svc_name, UINT *nat_t_error_code, bool try_start_ssl, bool no_get_hostname, IP *ret_ip);
SOCKET ConnectTimeoutIPv4(IP *ip, UINT port, UINT timeout, bool *cancel_flag);
bool SetSocketBufferSize(SOCKET s, bool send, UINT size);
UINT SetSocketBufferSizeWithBestEffort(SOCKET s, bool send, UINT size);
void InitUdpSocketBufferSize(SOCKET s);
void QuerySocketInformation(SOCK *sock);
bool SetTtl(SOCK *sock, UINT ttl);
void Disconnect(SOCK *sock);
SOCK *Listen(UINT port);
SOCK *ListenEx(UINT port, bool local_only);
SOCK *ListenEx2(UINT port, bool local_only, bool enable_ca, IP *listen_ip);
SOCK *ListenEx6(UINT port, bool local_only);
SOCK *ListenEx62(UINT port, bool local_only, bool enable_ca);
SOCK *Accept(SOCK *sock);
SOCK *Accept6(SOCK *sock);
UINT Send(SOCK *sock, void *data, UINT size, bool secure);
UINT Recv(SOCK *sock, void *data, UINT size, bool secure);
UINT Peek(SOCK *sock, void *data, UINT size);
void SetNoNeedToRead(SOCK *sock);
UINT SecureSend(SOCK *sock, void *data, UINT size);
UINT SecureRecv(SOCK *sock, void *data, UINT size);
bool StartSSL(SOCK *sock, X *x, K *priv);
bool StartSSLEx(SOCK *sock, X *x, K *priv, UINT ssl_timeout, char *sni_hostname);
bool AddChainSslCert(struct ssl_ctx_st *ctx, X *x);
void AddChainSslCertOnDirectory(struct ssl_ctx_st *ctx);
bool SendAll(SOCK *sock, void *data, UINT size, bool secure);
void SendAdd(SOCK *sock, void *data, UINT size);
bool SendNow(SOCK *sock, int secure);
bool RecvAll(SOCK *sock, void *data, UINT size, bool secure);
bool RecvAllEx(SOCK *sock, void **data_new_ptr, UINT size, bool secure);
void InitSockSet(SOCKSET *set);
void AddSockSet(SOCKSET *set, SOCK *sock);
CANCEL *NewCancel();
CANCEL *NewCancelSpecial(void *hEvent);
void ReleaseCancel(CANCEL *c);
void CleanupCancel(CANCEL *c);
void Cancel(CANCEL *c);
void Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2);
void SetWantToUseCipher(SOCK *sock, char *name);
SOCK *NewUDP(UINT port);
SOCK *NewUDPEx(UINT port, bool ipv6);
SOCK *NewUDPEx2(UINT port, bool ipv6, IP *ip);
SOCK *NewUDPEx3(UINT port, IP *ip);
SOCK *NewUDP4(UINT port, IP *ip);
SOCK *NewUDP6(UINT port, IP *ip);
SOCK *NewUDPEx2Rand(bool ipv6, IP *ip, void *rand_seed, UINT rand_seed_size, UINT num_retry);
SOCK *NewUDPEx2RandMachineAndExePath(bool ipv6, IP *ip, UINT num_retry, UCHAR rand_port_id);
void ClearSockDfBit(SOCK *s);
void SetRawSockHeaderIncludeOption(SOCK *s, bool enable);
UINT SendTo(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size);
UINT SendToEx(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast);
UINT SendTo6Ex(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast);
UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size);
UINT RecvFrom6(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size);
void SetTimeout(SOCK *sock, UINT timeout);
UINT GetTimeout(SOCK *sock);
bool CheckTCPPort(char *hostname, UINT port);
bool CheckTCPPortEx(char *hostname, UINT port, UINT timeout);
ROUTE_TABLE *GetRouteTable();
void FreeRouteTable(ROUTE_TABLE *t);
bool AddRouteEntryEx(ROUTE_ENTRY *e, bool *already_exists);
bool AddRouteEntry(ROUTE_ENTRY *e);
void DeleteRouteEntry(ROUTE_ENTRY *e);
char **EnumVLan(char *tag_name);
void FreeEnumVLan(char **s);
UINT GetVLanInterfaceID(char *tag_name);
ROUTE_ENTRY *GetBestRouteEntry(IP *ip);
ROUTE_ENTRY *GetBestRouteEntryEx(IP *ip, UINT exclude_if_id);
ROUTE_ENTRY *GetBestRouteEntryFromRouteTableEx(ROUTE_TABLE *table, IP *ip, UINT exclude_if_id);
void FreeRouteEntry(ROUTE_ENTRY *e);
void JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event);
SOCK_EVENT *NewSockEvent();
void SetSockEvent(SOCK_EVENT *event);
void CleanupSockEvent(SOCK_EVENT *event);
bool WaitSockEvent(SOCK_EVENT *event, UINT timeout);
void ReleaseSockEvent(SOCK_EVENT *event);
void SetIP(IP *ip, UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4);
UINT SetIP32(UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4);
bool GetDefaultDns(IP *ip);
bool GetDomainName(char *name, UINT size);
bool UnixGetDomainName(char *name, UINT size);
void AcceptInit(SOCK *s);
void AcceptInitEx(SOCK *s, bool no_lookup_hostname);
void DisableGetHostNameWhenAcceptInit();
TOKEN_LIST *GetCipherList();
COUNTER *GetNumTcpConnectionsCounter();
void InitWaitThread();
void FreeWaitThread();
void AddWaitThread(THREAD *t);
void DelWaitThread(THREAD *t);
void InitHostCache();
void FreeHostCache();
int CompareHostCache(void *p1, void *p2);
void AddHostCache(IP *ip, char *hostname);
bool GetHostCache(char *hostname, UINT size, IP *ip);
bool IsSubnetMask(IP *ip);
bool IsSubnetMask4(IP *ip);
bool IsSubnetMask32(UINT ip);
bool IsNetworkAddress4(IP *ip, IP *mask);
bool IsNetworkAddress32(UINT ip, UINT mask);
bool IsHostIPAddress4(IP *ip);
bool IsHostIPAddress32(UINT ip);
bool IsZeroIp(IP *ip);
bool IsZeroIP(IP *ip);
bool IsZeroIP6Addr(IPV6_ADDR *addr);
UINT IntToSubnetMask32(UINT i);
void IntToSubnetMask4(IP *ip, UINT i);
bool GetNetBiosName(char *name, UINT size, IP *ip);
bool NormalizeMacAddress(char *dst, UINT size, char *src);
SOCKLIST *NewSockList();
void StopSockList(SOCKLIST *sl);
void FreeSockList(SOCKLIST *sl);
bool IsIPv6Supported();
void SetSockTos(SOCK *s, int tos);
void SetSockHighPriority(SOCK *s, bool flag);
void InitIpClientList();
void FreeIpClientList();
int CompareIpClientList(void *p1, void *p2);
void AddIpClient(IP *ip);
void DelIpClient(IP *ip);
IP_CLIENT *SearchIpClient(IP *ip);
UINT GetNumIpClient(IP *ip);
void SetLinuxArpFilter();
int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag);
void EnableNetworkNameCache();
void DisableNetworkNameCache();
bool IsNetworkNameCacheEnabled();
ROUTE_CHANGE *NewRouteChange();
void FreeRouteChange(ROUTE_CHANGE *r);
bool IsRouteChanged(ROUTE_CHANGE *r);
void RouteToStr(char *str, UINT str_size, ROUTE_ENTRY *e);
void DebugPrintRoute(ROUTE_ENTRY *e);
void DebugPrintRouteTable(ROUTE_TABLE *r);
bool IsIPv6LocalNetworkAddress(IP *ip);

#ifdef	ENABLE_SSL_LOGGING
void SockEnableSslLogging(SOCK *s);
void SockWriteSslLog(SOCK *s, void *send_data, UINT send_size, void *recv_data, UINT recv_size);
void SockCloseSslLogging(SOCK *s);
#endif	// ENABLE_SSL_LOGGING

void SocketTimeoutThread(THREAD *t, void *param);
SOCKET_TIMEOUT_PARAM *NewSocketTimeout(SOCK *sock);
void FreeSocketTimeout(SOCKET_TIMEOUT_PARAM *ttp);

bool IsIP6(IP *ip);
bool IsIP4(IP *ip);
void IPv6AddrToIP(IP *ip, IPV6_ADDR *addr);
bool IPToIPv6Addr(IPV6_ADDR *addr, IP *ip);
void SetIP6(IP *ip, UCHAR *value);
void GetLocalHostIP6(IP *ip);
void GetLocalHostIP4(IP *ip);
bool IsLocalHostIP6(IP *ip);
bool IsLocalHostIP4(IP *ip);
bool IsLocalHostIP(IP *ip);
void ZeroIP6(IP *ip);
void ZeroIP4(IP *ip);
bool CheckIPItemStr6(char *str);
void IPItemStrToChars6(UCHAR *chars, char *str);
bool StrToIP6(IP *ip, char *str);
bool StrToIP6Addr(IPV6_ADDR *ip, char *str);
void IPToStr6(char *str, UINT size, IP *ip);
void IP6AddrToStr(char *str, UINT size, IPV6_ADDR *addr);
void IPToStr6Array(char *str, UINT size, UCHAR *bytes);
void IPToStr6Inner(char *str, IP *ip);
void IntToSubnetMask6(IP *ip, UINT i);
void IPAnd6(IP *dst, IP *a, IP *b);
void GetAllRouterMulticastAddress6(IP *ip);
void GetAllNodeMulticaseAddress6(IP *ip);
void GetLoopbackAddress6(IP *ip);
UINT GetIPAddrType6(IP *ip);
UINT GetIPv6AddrType(IPV6_ADDR *addr);
void GetPrefixAddress6(IP *dst, IP *ip, IP *subnet);
bool IsInSameNetwork6(IP *a1, IP *a2, IP *subnet);
bool IsInSameNetwork6ByStr(char *ip1, char *ip2, char *subnet);
void GenerateEui64Address6(UCHAR *dst, UCHAR *mac);
void GenerateEui64LocalAddress(IP *a, UCHAR *mac);
bool IsSubnetMask6(IP *a);
UINT SubnetMaskToInt(IP *a);
UINT SubnetMaskToInt6(IP *a);
UINT SubnetMaskToInt4(IP *a);
bool IsStrIPv6Address(char *str);
void IPAnd4(IP *dst, IP *a, IP *b);
bool IsInSameNetwork4(IP *a1, IP *a2, IP *subnet);
bool IsInSameNetwork4Standard(IP *a1, IP *a2);

bool ParseIpAndSubnetMask4(char *src, UINT *ip, UINT *mask);
bool ParseIpAndSubnetMask46(char *src, IP *ip, IP *mask);
bool ParseIpAndMask4(char *src, UINT *ip, UINT *mask);
bool ParseIpAndMask6(char *src, IP *ip, IP *mask);
bool ParseIpAndMask46(char *src, IP *ip, IP *mask);
bool IsIpStr4(char *str);
bool IsIpStr6(char *str);
bool IsIpMask6(char *str);
bool StrToMask6(IP *mask, char *str);
bool StrToMask6Addr(IPV6_ADDR *mask, char *str);
void MaskToStr(char *str, UINT size, IP *mask);
void Mask6AddrToStrEx(char *str, UINT size, IPV6_ADDR *mask, bool always_full_address);
void Mask6AddrToStr(char *str, UINT size, IPV6_ADDR *mask);
void MaskToStr32(char *str, UINT size, UINT mask);
void MaskToStr32Ex(char *str, UINT size, UINT mask, bool always_full_address);
void MaskToStrEx(char *str, UINT size, IP *mask, bool always_full_address);

TUBEDATA *NewTubeData(void *data, UINT size, void *header, UINT header_size);
void FreeTubeData(TUBEDATA *d);
TUBE *NewTube(UINT size_of_header);
void ReleaseTube(TUBE *t);
void CleanupTube(TUBE *t);
bool TubeSend(TUBE *t, void *data, UINT size, void *header);
bool TubeSendEx(TUBE *t, void *data, UINT size, void *header, bool no_flush);
bool TubeSendEx2(TUBE *t, void *data, UINT size, void *header, bool no_flush, UINT max_num_in_queue);
void TubeFlush(TUBE *t);
void TubeFlushEx(TUBE *t, bool force);
TUBEDATA *TubeRecvAsync(TUBE *t);
TUBEDATA *TubeRecvSync(TUBE *t, UINT timeout);
TUBEPAIR_DATA *NewTubePairData();
void ReleaseTubePairData(TUBEPAIR_DATA *d);
void CleanupTubePairData(TUBEPAIR_DATA *d);
void NewTubePair(TUBE **t1, TUBE **t2, UINT size_of_header);
void TubeDisconnect(TUBE *t);
bool IsTubeConnected(TUBE *t);
void SetTubeSockEvent(TUBE *t, SOCK_EVENT *e);
SOCK_EVENT *GetTubeSockEvent(TUBE *t);

TUBE_FLUSH_LIST *NewTubeFlushList();
void FreeTubeFlushList(TUBE_FLUSH_LIST *f);
void AddTubeToFlushList(TUBE_FLUSH_LIST *f, TUBE *t);
void FlushTubeFlushList(TUBE_FLUSH_LIST *f);

LIST *GetHostIPAddressListInternal();
LIST *GetHostIPAddressList();
LIST *CloneIPAddressList(LIST *o);
bool IsMyIPAddress(IP *ip);
void FreeHostIPAddressList(LIST *o);
void AddHostIPAddressToList(LIST *o, IP *ip);
int CmpIpAddressList(void *p1, void *p2);
UINT64 GetHostIPAddressListHash();

UDPLISTENER *NewUdpListener(UDPLISTENER_RECV_PROC *recv_proc, void *param, IP *listen_ip);
void UdpListenerThread(THREAD *thread, void *param);
void FreeUdpListener(UDPLISTENER *u);
void AddPortToUdpListener(UDPLISTENER *u, UINT port);
void DeletePortFromUdpListener(UDPLISTENER *u, UINT port);
void DeleteAllPortFromUdpListener(UDPLISTENER *u);
void UdpListenerSendPackets(UDPLISTENER *u, LIST *packet_list);
UDPPACKET *NewUdpPacket(IP *src_ip, UINT src_port, IP *dst_ip, UINT dst_port, void *data, UINT size);
void FreeUdpPacket(UDPPACKET *p);
UDPLISTENER_SOCK *DetermineUdpSocketForSending(UDPLISTENER *u, UDPPACKET *p);
bool IsUdpPortOpened(UDPLISTENER *u, IP *server_ip, UINT port);

INTERRUPT_MANAGER *NewInterruptManager();
void FreeInterruptManager(INTERRUPT_MANAGER *m);
void AddInterrupt(INTERRUPT_MANAGER *m, UINT64 tick);
UINT GetNextIntervalForInterrupt(INTERRUPT_MANAGER *m);

void NewSocketPair(SOCK **client, SOCK **server, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port);
SOCK *NewInProcSocket(TUBE *tube_send, TUBE *tube_recv);
SOCK *ListenInProc();
SOCK *AcceptInProc(SOCK *s);
SOCK *ConnectInProc(SOCK *listen_sock, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port);
UINT SendInProc(SOCK *sock, void *data, UINT size);
UINT RecvInProc(SOCK *sock, void *data, UINT size);
void WaitForTubes(TUBE **tubes, UINT num, UINT timeout);

SOCK *ListenReverse();
SOCK *AcceptReverse(SOCK *s);
void InjectNewReverseSocketToAccept(SOCK *listen_sock, SOCK *s, IP *client_ip, UINT client_port);

bool NewTcpPair(SOCK **s1, SOCK **s2);
SOCK *ListenAnyPortEx2(bool local_only, bool disable_ca);

bool IsIcmpApiSupported();
ICMP_RESULT *IcmpApiEchoSend(IP *dest_ip, UCHAR ttl, UCHAR *data, UINT size, UINT timeout);
void IcmpApiFreeResult(ICMP_RESULT *ret);

#ifdef	OS_WIN32
void Win32WaitForTubes(TUBE **tubes, UINT num, UINT timeout);
#else	// OS_WIN32
void UnixWaitForTubes(TUBE **tubes, UINT num, UINT timeout);
#endif	// OS_WIN32

#define PREVERIFY_ERR_MESSAGE_SIZE 100
// Info on client certificate collected during TLS handshake
struct SslClientCertInfo {
	int PreverifyErr;
	char PreverifyErrMessage[PREVERIFY_ERR_MESSAGE_SIZE];
	X *X;
};

SSL_PIPE *NewSslPipe(bool server_mode, X *x, K *k, DH_CTX *dh);
SSL_PIPE *NewSslPipeEx(bool server_mode, X *x, K *k, DH_CTX *dh, bool verify_peer, struct SslClientCertInfo *clientcert);
void FreeSslPipe(SSL_PIPE *s);
bool SyncSslPipe(SSL_PIPE *s);

SSL_BIO *NewSslBioMem();
SSL_BIO *NewSslBioSsl();
void FreeSslBio(SSL_BIO *b);
bool SslBioSync(SSL_BIO *b, bool sync_send, bool sync_recv);

void SetCurrentGlobalIP(IP *ip, bool ipv6);
bool GetCurrentGlobalIP(IP *ip, bool ipv6);
void GetCurrentGlobalIPGuess(IP *ip, bool ipv6);
bool IsIPAddressInSameLocalNetwork(IP *a);

bool IsIPPrivate(IP *ip);
bool IsIPMyHost(IP *ip);
void LoadPrivateIPFile();
bool IsOnPrivateIPFile(UINT ip);
void FreePrivateIPFile();

LIST *GetNicList();
void FreeNicList(LIST *o);
bool IsMacAddressLocalInner(LIST *o, void *addr);
bool IsMacAddressLocalFast(void *addr);
void RefreshLocalMacAddressList();

struct ssl_ctx_st *NewSSLCtx(bool server_mode);
void FreeSSLCtx(struct ssl_ctx_st *ctx);

void SetCurrentDDnsFqdn(char *name);
void GetCurrentDDnsFqdn(char *name, UINT size);
UINT GetCurrentDDnsFqdnHash();

void DisableRDUPServerGlobally();

void QueryIpThreadMain(THREAD *thread, void *param);
QUERYIPTHREAD *NewQueryIpThread(char *hostname, UINT interval_last_ok, UINT interval_last_ng);
bool GetQueryIpThreadResult(QUERYIPTHREAD *t, IP *ip);
void FreeQueryIpThread(QUERYIPTHREAD *t);

void SetGetIpThreadMaxNum(UINT num);
UINT GetGetIpThreadMaxNum();
UINT GetCurrentGetIpThreadNum();

#ifdef	OS_WIN32
LIST *Win32GetNicList();
#endif	// OS_WIN32


void InitDynList();
void FreeDynList();
void AddDynList(BUF *b);
void ExtractAndApplyDynList(PACK *p);
void SetDynListValue(char *name, UINT64 value);
UINT64 GetDynValue(char *name);
UINT64 GetDynValueOrDefault(char *name, UINT64 default_value, UINT64 min_value, UINT64 max_value);
UINT64 GetDynValueOrDefaultSafe(char *name, UINT64 default_value);


#endif	// NETWORK_H

