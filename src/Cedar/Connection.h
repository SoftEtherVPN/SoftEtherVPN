// SoftEther VPN Source Code
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
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


// Connection.h
// Header of Connection.c

#ifndef	CONNECTION_H
#define	CONNECTION_H

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
	UCHAR Signature[128];			// Signed data
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
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];	// Connection setting name
	char Hostname[MAX_HOST_NAME_LEN + 1];			// Host name
	UINT Port;										// Port number
	UINT PortUDP;									// UDP port number (0: Use only TCP)
	UINT ProxyType;									// Type of proxy
	char ProxyName[MAX_HOST_NAME_LEN + 1];			// Proxy server name
	UINT ProxyPort;									// Port number of the proxy server
	char ProxyUsername[MAX_PROXY_USERNAME_LEN + 1];	// Maximum user name length
	char ProxyPassword[MAX_PROXY_PASSWORD_LEN + 1];	// Maximum password length
	UINT NumRetry;									// Automatic retries
	UINT RetryInterval;								// Retry interval
	char HubName[MAX_HUBNAME_LEN + 1];				// HUB name
	UINT MaxConnection;								// Maximum number of concurrent TCP connections
	bool UseEncrypt;								// Use encrypted communication
	bool UseCompress;								// Use data compression
	bool HalfConnection;							// Use half connection in TCP
	bool NoRoutingTracking;							// Disable the routing tracking
	char DeviceName[MAX_DEVICE_NAME_LEN + 1];		// VLAN device name
	UINT AdditionalConnectionInterval;				// Connection attempt interval when additional connection establish
	UINT ConnectionDisconnectSpan;					// Disconnection interval
	bool HideStatusWindow;							// Hide the status window
	bool HideNicInfoWindow;							// Hide the NIC status window
	bool RequireMonitorMode;						// Monitor port mode
	bool RequireBridgeRoutingMode;					// Bridge or routing mode
	bool DisableQoS;								// Disable the VoIP / QoS function
	bool FromAdminPack;								// For Administration Pack
	bool NoTls1;									// Do not use TLS 1.0
	bool NoUdpAcceleration;							// Do not use UDP acceleration mode
	UCHAR HostUniqueKey[SHA1_SIZE];					// Host unique key
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
	BOOL Compressed;				// Compression flag
	UINT Size;						// Block size
	UINT SizeofData;				// Data size
	UCHAR *Buf;						// Buffer
	bool PriorityQoS;				// Priority packet for VoIP / QoS function
	UINT Ttl;						// TTL value (Used only in ICMP NAT of Virtual.c)
	UINT Param1;					// Parameter 1
	bool IsFlooding;				// Is flooding packet
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
	bool DontUseTls1;				// Do not use TLS 1.0
	void *hWndForUI;				// Parent window
	bool IsInProc;					// In-process
	char InProcPrefix[64];			// Prefix
	UINT AdditionalConnectionFailedCounter;		// Additional connection failure counter
	UINT64 LastCounterResetTick;	// Time the counter was reset finally
	bool WasSstp;					// Processed the SSTP
	bool WasDatProxy;				// DAT proxy processed
	UCHAR CToken_Hash[SHA1_SIZE];	// CTOKEN_HASH
	UINT LastTcpQueueSize;			// The last queue size of TCP sockets
	UINT LastPacketQueueSize;		// The last queue size of packets
	UINT LastRecvFifoTotalSize;		// The last RecvFifo total size
	UINT LastRecvBlocksNum;			// The last ReceivedBlocks num
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
void InsertReveicedBlockToQueue(CONNECTION *c, BLOCK *block, bool no_lock);
void InitTcpSockRc4Key(TCPSOCK *ts, bool server_mode);
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

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
