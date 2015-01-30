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


// IPsec_L2TP.h
// Header of IPsec_L2TP.c

#ifndef	IPSEC_L2TP_H
#define	IPSEC_L2TP_H

//// Macro

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
BUF *BuildL2TPPacketData(L2TP_PACKET *pp);
L2TP_AVP *GetAVPValue(L2TP_PACKET *p, UINT type);
L2TP_AVP *GetAVPValueEx(L2TP_PACKET *p, UINT type, UINT vendor_id);
L2TP_TUNNEL *NewL2TPTunnel(L2TP_SERVER *l2tp, L2TP_PACKET *p, UDPPACKET *udp);
UINT GenerateNewTunnelId(L2TP_SERVER *l2tp, IP *client_ip);
UINT GenerateNewTunnelIdEx(L2TP_SERVER *l2tp, IP *client_ip, bool is_32bit);
void FreeL2TPTunnel(L2TP_TUNNEL *t);
L2TP_TUNNEL *GetTunnelFromId(L2TP_SERVER *l2tp, IP *client_ip, UINT tunnel_id, bool is_v3);
L2TP_TUNNEL *GetTunnelFromIdOfAssignedByClient(L2TP_SERVER *l2tp, IP *client_ip, UINT tunnel_id);
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

#endif	// IPSEC_L2TP_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
