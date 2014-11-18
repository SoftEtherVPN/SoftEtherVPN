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


// Interop_OpenVPN.h
// Header of Interop_OpenVPN.c

#ifndef	INTEROP_OPENVPN_H
#define	INTEROP_OPENVPN_H


//// Constants
#define	OPENVPN_UDP_PORT						1194	// OpenVPN default UDP port number
#define	OPENVPN_UDP_PORT_INCLUDE				1195	// OpenVPN default UDP port number (Operating within the client)

#define	OPENVPN_MAX_NUMACK						4		// The maximum number of ACKs
#define	OPENVPN_NUM_CHANNELS					8		// Maximum number of channels during a session
#define	OPENVPN_CONTROL_PACKET_RESEND_INTERVAL	500		// Control packet retransmission interval
#define	OPENVPN_CONTROL_PACKET_MAX_DATASIZE		1200	// Maximum data size that can be stored in one control packet

#define	OPENVPN_MAX_SSL_RECV_BUF_SIZE			(256 * 1024)	// SSL receive buffer maximum length

#define	OPENVPN_MAX_KEY_SIZE					64		// Maximum key size

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

// List of supported encryption algorithms
#define	OPENVPN_CIPHER_LIST						"[NULL-CIPHER] NULL AES-128-CBC AES-192-CBC AES-256-CBC BF-CBC CAST-CBC CAST5-CBC DES-CBC DES-EDE-CBC DES-EDE3-CBC DESX-CBC RC2-40-CBC RC2-64-CBC RC2-CBC"

// List of the supported hash algorithm
#define	OPENVPN_MD_LIST							"SHA SHA1 MD5 MD4 RMD160"

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
	UCHAR MasterSecret[48];								// Master Secret
	UCHAR ExpansionKey[256];							// Expansion Key
	UCHAR NextIv[64];									// Next IV
	UINT LastDataPacketId;								// Previous Data Packet ID
	UINT64 EstablishedTick;								// Established time
	UCHAR KeyId;										// KEY ID
	bool IsRekeyChannel;								// Whether it is a channel for key update
	bool IsInitiatorServer;								// Whether the channel was started from the server side
	bool RekeyInitiated;								// Whether re-keying has already started
	UINT64 NextRekey;
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
	LIST *SendPacketList;								// Transmission packet list
	LIST *SessionList;									// Session list
	UINT64 Now;											// Current time
	SOCK_EVENT *SockEvent;								// Socket event
	UCHAR TmpBuf[OPENVPN_TMP_BUFFER_SIZE];				// Temporary buffer
	UINT DisconnectCount;								// The number of session lost that have occurred so far
	bool SupressSendPacket;								// Packet transmission suppression flag
	UINT NextSessionId;									// Next session ID
	DH_CTX *Dh;											// DH key
	UINT SessionEstablishedCount;						// Number of session establishment
};

// OpenVPN server (UDP mode)
struct OPENVPN_SERVER_UDP
{
	CEDAR *Cedar;
	UDPLISTENER *UdpListener;							// UDP listener
	OPENVPN_SERVER *OpenVpnServer;						// OpenVPN server
	UINT64 VgsNextGetPublicPortsTick;
};

// OpenVPN Default Client Option String
#define	OVPN_DEF_CLIENT_OPTION_STRING	"dev-type tun,link-mtu 1500,tun-mtu 1500,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client"


//// Function prototype
OPENVPN_SERVER_UDP *NewOpenVpnServerUdp(CEDAR *cedar);
void FreeOpenVpnServerUdp(OPENVPN_SERVER_UDP *u);
void OpenVpnServerUdpListenerProc(UDPLISTENER *u, LIST *packet_list);
void OvsApplyUdpPortList(OPENVPN_SERVER_UDP *u, char *port_list);

OPENVPN_SERVER *NewOpenVpnServer(CEDAR *cedar, INTERRUPT_MANAGER *interrupt, SOCK_EVENT *sock_event);
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
void OvsSendControlPacketWithAutoSplit(OPENVPN_CHANNEL *c, UCHAR opcode, UCHAR *data, UINT data_size);
void OvsFreeControlPacket(OPENVPN_CONTROL_PACKET *p);
void OvsDeleteFromSendingControlPacketList(OPENVPN_CHANNEL *c, UINT num_acks, UINT *acks);
UINT OvsParseKeyMethod2(OPENVPN_KEY_METHOD_2 *ret, UCHAR *data, UINT size, bool client_mode);
bool OvsReadStringFromBuf(BUF *b, char *str, UINT str_size);
void OvsSetupSessionParameters(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c, OPENVPN_KEY_METHOD_2 *data);
BUF *OvsBuildKeyMethod2(OPENVPN_KEY_METHOD_2 *d);
void OvsWriteStringToBuf(BUF *b, char *str, UINT max_size);

LIST *OvsParseOptions(char *str);
void OvsFreeOptions(LIST *o);
LIST *OvsNewOptions();
void OvsAddOption(LIST *o, char *key, char *value);
bool OvsHasOption(LIST *o, char *key);
UINT OvsPeekStringFromFifo(FIFO *f, char *str, UINT str_size);
void OvsBeginIPCAsyncConnectionIfEmpty(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c);
bool OvsIsCompatibleL3IP(UINT ip);
UINT OvsGetCompatibleL3IPNext(UINT ip);
UINT OvsCalcTcpMss(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c);

CIPHER *OvsGetCipher(char *name);
MD *OvsGetMd(char *name);
bool OvsCheckTcpRecvBufIfOpenVPNProtocol(UCHAR *buf, UINT size);

bool OvsPerformTcpServer(CEDAR *cedar, SOCK *sock);

void OvsSetReplyForVgsPollEnable(bool b);

void OvsSetNoOpenVpnTcp(bool b);
bool OvsGetNoOpenVpnTcp();

void OvsSetNoOpenVpnUdp(bool b);



#endif	// INTEROP_OPENVPN_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
