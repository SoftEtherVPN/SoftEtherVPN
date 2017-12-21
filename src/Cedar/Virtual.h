// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
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


// Virtual.h
// Header of Virtual.c

#ifndef	VIRTUAL_H
#define	VIRTUAL_H


#define	NN_RAW_IP_PORT_START			61001
#define	NN_RAW_IP_PORT_END				65535

#define	VIRTUAL_TCP_SEND_TIMEOUT		(21 * 1000)

#define	NN_NEXT_WAIT_TIME_FOR_DEVICE_ENUM	(30 * 1000)
#define	NN_NEXT_WAIT_TIME_MAX_FAIL_COUNT	30

#define	NN_HOSTNAME_FORMAT				"securenat-%s"
#define	NN_HOSTNAME_STARTWITH			"securenat-"
#define	NN_HOSTNAME_STARTWITH2			"securenat_"
#define	NN_CHECK_CONNECTIVITY_TIMEOUT	(5 * 1000)
#define	NN_CHECK_CONNECTIVITY_INTERVAL	(1 * 1000)

#define	NN_POLL_CONNECTIVITY_TIMEOUT	(4 * 60 * 1000 + 10)
#define	NN_POLL_CONNECTIVITY_INTERVAL	(1 * 60 * 1000)

#define	NN_MAX_QUEUE_LENGTH				10000
#define	NN_NO_NATIVE_NAT_FILENAME		L"@no_native_nat_niclist.txt"

#define	NN_TIMEOUT_FOR_UNESTBALISHED_TCP	(10 * 1000)		// Time-out period of a TCP connection incomplete session

// Destination host name of the connectivity test for the Internet
// (Access the www.yahoo.com. Access the www.baidu.com from China. I am sorry.)
#define	NN_CHECK_HOSTNAME				(IsEmptyStr(secure_nat_target_hostname) ? (IsUseAlternativeHostname() ? "www.baidu.com" : "www.yahoo.com") : secure_nat_target_hostname)


// Native NAT entry
struct NATIVE_NAT_ENTRY
{
	UINT Id;						// ID
	UINT Status;					// Status
	UINT Protocol;					// Protocol
	UINT SrcIp;						// Source IP address
	UINT SrcPort;					// Source port number
	UINT DestIp;					// Destination IP address
	UINT DestPort;					// Destination port number
	UINT PublicIp;					// Public IP address
	UINT PublicPort;				// Public port number
	UINT64 CreatedTime;				// Connection time
	UINT64 LastCommTime;			// Last communication time
	UINT64 TotalSent;				// Total number of bytes sent
	UINT64 TotalRecv;				// Total number of bytes received
	UINT LastSeq;					// Last sequence number
	UINT LastAck;					// Last acknowledgment number
	UINT HashCodeForSend;			// Cached hash code (transmit direction)
	UINT HashCodeForRecv;			// Cached hash code (receive direction)
};

// Native NAT
struct NATIVE_NAT
{
	struct VH *v;					// Virtual machine
	bool Active;					// Whether currently available
	THREAD *Thread;					// Main thread
	bool Halt;						// Halting flag
	TUBE *HaltTube;					// Tube to be disconnected in order to stop
	TUBE *HaltTube2;				// Tube 2 to be disconnected in order to stop
	TUBE *HaltTube3;				// Tube 3 to be disconnected in order to stop
	LOCK *Lock;						// Lock
	EVENT *HaltEvent;				// Halting event
	UINT LastInterfaceIndex;		// Index number of the interface that is used for attempting last
	UINT LastInterfaceDeviceHash;	// Hash value of the device list at the time of the last attempted
	UINT NextWaitTimeForRetry;		// Time for waiting next time for the device list enumeration
	UINT FailedCount;				// The number of failed searching for the interface
	UINT LastHostAddressHash;		// Hash of the last host IP address
	DHCP_OPTION_LIST CurrentDhcpOptions;	// Current DHCP options
	QUEUE *SendQueue;				// Transmission queue
	QUEUE *RecvQueue;				// Reception queue
	CANCEL *Cancel;					// Cancel object (Hit if there is a received packet)
	LOCK *CancelLock;				// Lock of the cancel object
	HASH_LIST *NatTableForSend;		// Native NAT table (for transmission)
	HASH_LIST *NatTableForRecv;		// Native NAT table (for reception)
	UINT PublicIP;					// Public IP
	USHORT NextId;					// Next IP packet ID
	bool SendStateChanged;			// Transmission state changed
	LIST *IpCombine;				// IP combining list
	UINT CurrentIpQuota;			// Current IP combining quota
	UCHAR CurrentMacAddress[6];		// Current MAC address
	bool IsRawIpMode;				// Is RAW_IP mode
};

// ARP entry
struct ARP_ENTRY
{
	UINT IpAddress;					// IP address
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	UINT64 Created;					// Creation date and time
	UINT64 Expire;					// Expiration date
};

// ARP waiting list
struct ARP_WAIT
{
	UINT IpAddress;					// IP address trying to solve
	UINT NextTimeoutTimeValue;		// Next time before timing out
	UINT64 TimeoutTime;				// Current Time-out of transmission
	UINT64 GiveupTime;				// Time to give up the transmission
};

// IP waiting list
struct IP_WAIT
{
	UINT DestIP;					// Destination IP address
	UINT SrcIP;						// Source IP address
	UINT64 Expire;					// Storage life
	void *Data;						// Data
	UINT Size;						// Size
};

// IP partial list
struct IP_PART
{
	UINT Offset;					// Offset
	UINT Size;						// Size
};

// IP restore list
struct IP_COMBINE
{
	UINT DestIP;					// Destination IP address
	UINT SrcIP;						// Source IP address
	USHORT Id;						// IP packet ID
	UCHAR Ttl;						// TTL
	UINT64 Expire;					// Storage life
	void *Data;						// Packet data
	UINT DataReserved;				// Area reserved for data
	UINT Size;						// Packet size (Total)
	LIST *IpParts;					// IP partial list
	UCHAR Protocol;					// Protocol number
	bool MacBroadcast;				// Broadcast packets at the MAC level
	UCHAR *HeadIpHeaderData;		// Data of the IP header of the top
	UINT HeadIpHeaderDataSize;		// Data size of the IP header of the top
	bool SrcIsLocalMacAddr;			// Source MAC address is on the same machine
	UINT MaxL3Size;					// Largest L3 size
};

#define	IP_COMBINE_INITIAL_BUF_SIZE		(MAX_IP_DATA_SIZE)		// Initial buffer size

// NAT session table
struct NAT_ENTRY
{
	// TCP | UDP common items
	struct VH *v;					// Virtual machine
	UINT Id;						// ID
	LOCK *lock;						// Lock
	UINT Protocol;					// Protocol
	UINT SrcIp;						// Source IP address
	UINT SrcPort;					// Source port number
	UINT DestIp;					// Destination IP address
	UINT DestPort;					// Destination port number
	UINT PublicIp;					// Public IP address
	UINT PublicPort;				// Public port number
	UINT64 CreatedTime;				// Connection time
	UINT64 LastCommTime;			// Last communication time
	SOCK *Sock;						// Socket
	bool DisconnectNow;				// Flag to stop immediately
	UINT tag1;
	bool ProxyDns;					// DNS proxy
	UINT DestIpProxy;				// Proxy DNS address

	// ICMP NAT item (only for the calling ICMP API mode)
	THREAD *IcmpThread;				// ICMP query thread
	BLOCK *IcmpQueryBlock;			// Block that contains the ICMP query
	BLOCK *IcmpResponseBlock;		// Block that contains ICMP result
	bool IcmpTaskFinished;			// Flag indicating that the processing of ICMP has been completed
	UCHAR *IcmpOriginalCopy;		// Copy of the original ICMP packet
	UINT IcmpOriginalCopySize;		// The size of the copy of original ICMP packet

	// DNS NAT item
	THREAD *DnsThread;				// DNS query thread
	bool DnsGetIpFromHost;			// Reverse resolution flag
	char *DnsTargetHostName;		// Target host name
	IP DnsResponseIp;				// Response IP address
	char *DnsResponseHostName;		// Response host name
	UINT DnsTransactionId;			// DNS transaction ID
	bool DnsFinished;				// DNS query completion flag
	bool DnsOk;						// DNS success flag
	bool DnsPollingFlag;			// DNS polling completion flag

	// UDP item
	QUEUE *UdpSendQueue;			// UDP send queue
	QUEUE *UdpRecvQueue;			// UDP receive queue
	bool UdpSocketCreated;			// Whether an UDP socket was created

	// TCP items
	FIFO *SendFifo;					// Transmission FIFO
	FIFO *RecvFifo;					// Receive FIFO
	UINT TcpStatus;					// TCP state
	bool NatTcpCancelFlag;			// TCP connection cancel flag
	THREAD *NatTcpConnectThread;	// TCP socket connection thread
	bool TcpMakeConnectionFailed;	// Failed to connect with connection thread
	bool TcpMakeConnectionSucceed;	// Successfully connected by the connection thread
	UINT TcpSendMaxSegmentSize;		// Maximum transmission segment size
	UINT TcpRecvMaxSegmentSize;		// Maximum reception segment size
	UINT64 LastSynAckSentTime;		// Time which the SYN+ACK was sent last
	UINT SynAckSentCount;			// SYN + ACK transmission times
	UINT TcpSendWindowSize;			// Transmission window size
	UINT TcpSendCWnd;				// Transmission congestion window size (/mss)
	UINT TcpRecvWindowSize;			// Receive window size
	UINT TcpSendTimeoutSpan;		// Transmission time-out period
	UINT64 TcpLastSentTime;			// Time for the last transmitted over TCP
	UINT64 LastSentKeepAliveTime;	// Time which the keep-alive ACK was sent last
	FIFO *TcpRecvWindow;			// TCP receive window
	LIST *TcpRecvList;				// TCP reception list
	bool SendAckNext;				// Send an ACK at the time of the next transmission
	UINT LastSentWindowSize;		// My window size that sent the last
	UINT64 TcpLastRecvAckTime;		// Time that the other party has received the last data in TCP

	UINT64 SendSeqInit;				// Initial send sequence number
	UINT64 SendSeq;					// Send sequence number
	UINT64 RecvSeqInit;				// Initial receive sequence number
	UINT64 RecvSeq;					// Receive sequence number
	UINT FinSentSeq;				// Sequence number with the last FIN

	bool CurrentSendingMission;		// Burst transmission ongoing
	UINT SendMissionSize;			// Transmission size of this time
	bool RetransmissionUsedFlag;	// Retransmission using record flag

	UINT CurrentRTT;				// Current RTT value
	UINT64 CalcRTTStartTime;		// RTT measurement start time
	UINT64 CalcRTTStartValue;		// RTT measurement start value

	bool TcpFinished;				// Data communication end flag of TCP
	bool TcpDisconnected;			// TCP Disconnect flag
	bool TcpForceReset;				// TCP connection force reset flag
	UINT64 FinSentTime;				// Time which the FIN was sent last
	UINT FinSentCount;				// Number of FIN transmissions

	UINT64 test_TotalSent;
};


// TCP options
struct TCP_OPTION
{
	UINT MaxSegmentSize;			// Maximum segment size
	UINT WindowScaling;				// Window scaling
};

// Virtual host structure
struct VH
{
	REF *ref;						// Reference counter
	LOCK *lock;						// Lock
	SESSION *Session;				// Session
	CANCEL *Cancel;					// Cancel object
	QUEUE *SendQueue;				// Transmission queue
	bool Active;					// Active flag
	volatile bool HaltNat;			// NAT halting flag
	LIST *ArpTable;					// ARP table
	LIST *ArpWaitTable;				// ARP waiting table
	LIST *IpWaitTable;				// IP waiting table
	LIST *IpCombine;				// IP combining table
	UINT64 Now;						// Current time
	UINT64 NextArpTablePolling;		// Next time to poll the ARP table
	UINT Mtu;						// MTU value
	UINT IpMss;						// Maximum IP data size
	UINT TcpMss;					// TCP maximum data size
	UINT UdpMss;					// UDP maximum data size
	bool flag1;						// Flag 1
	bool flag2;						// Flag 2
	USHORT NextId;					// ID of the IP packet
	UINT CurrentIpQuota;			// IP packet memory quota
	LIST *NatTable;					// NAT table
	SOCK_EVENT *SockEvent;			// Socket event
	THREAD *NatThread;				// NAT thread
	void *TmpBuf;					// Buffer that can be used temporarily
	bool NatDoCancelFlag;			// Flag of whether to hit the cancel
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	UINT HostIP;					// Host IP
	UINT HostMask;					// Host subnet mask
	UINT NatTcpTimeout;				// NAT TCP timeout in seconds
	UINT NatUdpTimeout;				// NAT UDP timeout in seconds
	bool UseNat;					// NAT use flag
	bool UseDhcp;					// DHCP using flag
	UINT DhcpIpStart;				// Distribution start address
	UINT DhcpIpEnd;					// Distribution end address
	UINT DhcpMask;					// Subnet mask
	UINT DhcpExpire;				// Address distribution expiration date
	UINT DhcpGateway;				// Gateway address
	UINT DhcpDns;					// DNS server address 1
	UINT DhcpDns2;					// DNS server address 2
	char DhcpDomain[MAX_HOST_NAME_LEN + 1];	// Assigned domain name
	LIST *DhcpLeaseList;			// DHCP lease list
	UINT64 LastDhcpPolling;			// Time which the DHCP list polled last
	bool SaveLog;					// Save a log
	DHCP_CLASSLESS_ROUTE_TABLE PushRoute;	// Pushing routing table
	COUNTER *Counter;				// Session counter
	UINT DhcpId;					// DHCP ID
	UINT64 LastSendBeacon;			// Time which the beacon has been sent last
	LOG *Logger;					// Logger
	NAT *nat;						// A reference to the NAT object
	bool IcmpRawSocketOk;			// ICMP RAW SOCKET is available
	bool IcmpApiOk;					// ICMP API is available
	HUB_OPTION *HubOption;			// Pointer to the Virtual HUB options

	NATIVE_NAT *NativeNat;			// Native NAT
};

// Virtual host option
struct VH_OPTION
{
	char HubName[MAX_HUBNAME_LEN + 1];	// Target Virtual HUB name
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	IP Ip;							// IP address
	IP Mask;						// Subnet mask
	bool UseNat;					// Use flag of NAT function
	UINT Mtu;						// MTU value
	UINT NatTcpTimeout;				// NAT TCP timeout in seconds
	UINT NatUdpTimeout;				// NAT UDP timeout in seconds
	bool UseDhcp;					// Using flag of DHCP function
	IP DhcpLeaseIPStart;			// Start of IP address range for DHCP distribution
	IP DhcpLeaseIPEnd;				// End of IP address range for DHCP distribution
	IP DhcpSubnetMask;				// DHCP subnet mask
	UINT DhcpExpireTimeSpan;		// DHCP expiration date
	IP DhcpGatewayAddress;			// Assigned gateway address
	IP DhcpDnsServerAddress;		// Assigned DNS server address 1
	IP DhcpDnsServerAddress2;		// Assigned DNS server address 2
	char DhcpDomainName[MAX_HOST_NAME_LEN + 1];	// Assigned domain name
	bool SaveLog;					// Save a log
	bool ApplyDhcpPushRoutes;		// Apply flag for DhcpPushRoutes
	char DhcpPushRoutes[MAX_DHCP_CLASSLESS_ROUTE_TABLE_STR_SIZE];	// DHCP pushing routes
};

// DHCP lease entry
struct DHCP_LEASE
{
	UINT Id;						// ID
	UINT64 LeasedTime;				// Leased time
	UINT64 ExpireTime;				// Expiration date
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];				// Padding
	UINT IpAddress;					// IP address
	UINT Mask;						// Subnet mask
	char *Hostname;					// Host name
};

// DNS query
typedef struct NAT_DNS_QUERY
{
	REF *ref;						// Reference counter
	char Hostname[256];				// Host name
	bool Ok;						// Result success flag
	IP Ip;							// Result IP address
} NAT_DNS_QUERY;

// Parsed DNS query
struct DNS_PARSED_PACKET
{
	UINT TransactionId;
	char Hostname[128];
};


// Virtual LAN card of the virtual host
PACKET_ADAPTER *VirtualGetPacketAdapter();
bool VirtualPaInit(SESSION *s);
CANCEL *VirtualPaGetCancel(SESSION *s);
UINT VirtualPaGetNextPacket(SESSION *s, void **data);
bool VirtualPaPutPacket(SESSION *s, void *data, UINT size);
void VirtualPaFree(SESSION *s);

bool VirtualInit(VH *v);
UINT VirtualGetNextPacket(VH *v, void **data);
bool VirtualPutPacket(VH *v, void *data, UINT size);
void Virtual_Free(VH *v);

VH *NewVirtualHost(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, VH_OPTION *vh_option);
VH *NewVirtualHostEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, VH_OPTION *vh_option, NAT *nat);
void LockVirtual(VH *v);
void UnlockVirtual(VH *v);
void ReleaseVirtual(VH *v);
void CleanupVirtual(VH *v);
void StopVirtualHost(VH *v);
void SetVirtualHostOption(VH *v, VH_OPTION *vo);
void GenMacAddress(UCHAR *mac);
void GetVirtualHostOption(VH *v, VH_OPTION *o);

void VirtualLayer2(VH *v, PKT *packet);
bool VirtualLayer2Filter(VH *v, PKT *packet);
void VirtualArpReceived(VH *v, PKT *packet);
void VirtualArpResponseRequest(VH *v, PKT *packet);
void VirtualArpResponseReceived(VH *v, PKT *packet);
void VirtualArpSendResponse(VH *v, UCHAR *dest_mac, UINT dest_ip, UINT src_ip);
void VirtualArpSendRequest(VH *v, UINT dest_ip);
void VirtualIpSend(VH *v, UCHAR *dest_mac, void *data, UINT size);
void VirtualLayer2Send(VH *v, UCHAR *dest_mac, UCHAR *src_mac, USHORT protocol, void *data, UINT size);
void VirtualPolling(VH *v);
void InitArpTable(VH *v);
void FreeArpTable(VH *v);
int CompareArpTable(void *p1, void *p2);
ARP_ENTRY *SearchArpTable(VH *v, UINT ip);
void RefreshArpTable(VH *v);
void PollingArpTable(VH *v);
void InsertArpTable(VH *v, UCHAR *mac, UINT ip);
bool IsMacBroadcast(UCHAR *mac);
bool IsMacInvalid(UCHAR *mac);
void InitArpWaitTable(VH *v);
void FreeArpWaitTable(VH *v);
int CompareArpWaitTable(void *p1, void *p2);
ARP_WAIT *SearchArpWaitTable(VH *v, UINT ip);
void DeleteArpWaitTable(VH *v, UINT ip);
void SendArp(VH *v, UINT ip);
void InsertArpWaitTable(VH *v, ARP_WAIT *w);
void PollingArpWaitTable(VH *v);
void ArpIpWasKnown(VH *v, UINT ip, UCHAR *mac);
void InitIpWaitTable(VH *v);
void FreeIpWaitTable(VH *v);
void InsertIpWaitTable(VH *v, UINT dest_ip, UINT src_ip, void *data, UINT size);
void SendFragmentedIp(VH *v, UINT dest_ip, UINT src_ip, USHORT id, USHORT total_size, USHORT offset, UCHAR protocol, void *data, UINT size, UCHAR *dest_mac, UCHAR ttl);
void SendIp(VH *v, UINT dest_ip, UINT src_ip, UCHAR protocol, void *data, UINT size);
void SendIpEx(VH *v, UINT dest_ip, UINT src_ip, UCHAR protocol, void *data, UINT size, UCHAR ttl);
void PollingIpWaitTable(VH *v);
void DeleteOldIpWaitTable(VH *v);
void SendWaitingIp(VH *v, UCHAR *mac, UINT dest_ip);
void VirtualIpReceived(VH *v, PKT *packet);
void InitIpCombineList(VH *v);
void FreeIpCombineList(VH *v);
int CompareIpCombine(void *p1, void *p2);
void CombineIp(VH *v, IP_COMBINE *c, UINT offset, void *data, UINT size, bool last_packet, UCHAR *head_ip_header_data, UINT head_ip_header_size);
void IpReceived(VH *v, UINT src_ip, UINT dest_ip, UINT protocol, void *data, UINT size, bool mac_broadcast, UCHAR ttl, UCHAR *ip_header, UINT ip_header_size, bool is_local_mac, UINT max_l3_size);
void FreeIpCombine(VH *v, IP_COMBINE *c);
void PollingIpCombine(VH *v);
IP_COMBINE *InsertIpCombine(VH *v, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol, bool mac_broadcast, UCHAR ttl, bool src_is_localmac);
IP_COMBINE *SearchIpCombine(VH *v, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol);
void VirtualIcmpReceived(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size, UCHAR ttl, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size);
void VirtualIcmpEchoRequestReceived(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size, UCHAR ttl, void *icmp_data, UINT icmp_size, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size);
void VirtualIcmpEchoRequestReceivedRaw(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size, UCHAR ttl, void *icmp_data, UINT icmp_size, UCHAR *ip_header, UINT ip_header_size);
void VirtualIcmpEchoSendResponse(VH *v, UINT src_ip, UINT dst_ip, USHORT id, USHORT seq_no, void *data, UINT size);
void VirtualIcmpSend(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size);
void VirtualUdpReceived(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size, bool mac_broadcast, bool is_localmac, UINT max_l3_size);
void SendUdp(VH *v, UINT dest_ip, UINT dest_port, UINT src_ip, UINT src_port, void *data, UINT size);
UINT GetNetworkAddress(UINT addr, UINT mask);
UINT GetBroadcastAddress(UINT addr, UINT mask);
void GetBroadcastAddress4(IP *dst, IP *addr, IP *mask);
bool IsInNetwork(UINT uni_addr, UINT network_addr, UINT mask);
void UdpRecvForMe(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
void UdpRecvLlmnr(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
void UdpRecvForBroadcast(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
void UdpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, bool dns_proxy);
void UdpRecvForNetBiosBroadcast(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, bool dns_proxy, bool unicast);
bool IsNetbiosRegistrationPacket(UCHAR *buf, UINT size);
bool ProcessNetBiosNameQueryPacketForMyself(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
void EncodeNetBiosName(UCHAR *dst, char *src);
char *CharToNetBiosStr(char c);
void InitNat(VH *v);
void FreeNat(VH *v);
int CompareNat(void *p1, void *p2);
NAT_ENTRY *SearchNat(VH *v, NAT_ENTRY *target);
void SetNat(NAT_ENTRY *n, UINT protocol, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT public_ip, UINT public_port);
void DeleteNatTcp(VH *v, NAT_ENTRY *n);
void DeleteNatUdp(VH *v, NAT_ENTRY *n);
void DeleteNatIcmp(VH *v, NAT_ENTRY *n);
NAT_ENTRY *CreateNatUdp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT dns_proxy_ip);
NAT_ENTRY *CreateNatIcmp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UCHAR *original_copy, UINT original_copy_size);
void NatThread(THREAD *t, void *param);
void NatThreadMain(VH *v);
bool NatTransactUdp(VH *v, NAT_ENTRY *n);
bool NatTransactIcmp(VH *v, NAT_ENTRY *n);
void NatIcmpThreadProc(THREAD *thread, void *param);
void PoolingNat(VH *v);
void PoolingNatUdp(VH *v, NAT_ENTRY *n);
void PollingNatIcmp(VH *v, NAT_ENTRY *n);
void VirtualTcpReceived(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size, UINT max_l3_size);
void TcpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, TCP_HEADER *tcp, void *data, UINT size, UINT max_l3_size);
NAT_ENTRY *CreateNatTcp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port);
bool NatTransactTcp(VH *v, NAT_ENTRY *n);
void CreateNatTcpConnectThread(VH *v, NAT_ENTRY *n);
void NatTcpConnectThread(THREAD *t, void *p);
void PollingNatTcp(VH *v, NAT_ENTRY *n);
void ParseTcpOption(TCP_OPTION *o, void *data, UINT size);
void SendTcp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT seq, UINT ack, UINT flag, UINT window_size, UINT mss, void *data, UINT size);
void DnsProxy(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
bool ParseDnsPacket(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size);
bool ParseDnsPacketEx(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, DNS_PARSED_PACKET *parsed_result);
void SetDnsProxyVgsHostname(char *hostname);
bool NatTransactDns(VH *v, NAT_ENTRY *n);
void NatDnsThread(THREAD *t, void *param);
bool NatGetIP(IP *ip, char *hostname);
void NatGetIPThread(THREAD *t, void *param);
NAT_ENTRY *CreateNatDns(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port,
				  UINT transaction_id, bool dns_get_ip_from_host, char *dns_target_host_name);
void PollingNatDns(VH *v, NAT_ENTRY *n);
void SendNatDnsResponse(VH *v, NAT_ENTRY *n);
void BuildDnsQueryPacket(BUF *b, char *hostname, bool ptr);
void BuildDnsResponsePacketA(BUF *b, IP *ip);
void BuildDnsResponsePacketPtr(BUF *b, char *hostname);
bool ArpaToIP(IP *ip, char *str);
BUF *BuildDnsHostName(char *hostname);
bool CanCreateNewNatEntry(VH *v);
void VirtualDhcpServer(VH *v, PKT *p);
void InitDhcpServer(VH *v);
void FreeDhcpServer(VH *v);
void PollingDhcpServer(VH *v);
int CompareDhcpLeaseList(void *p1, void *p2);
DHCP_LEASE *NewDhcpLease(UINT expire, UCHAR *mac_address, UINT ip, UINT mask, char *hostname);
void FreeDhcpLease(DHCP_LEASE *d);
DHCP_LEASE *SearchDhcpLeaseByMac(VH *v, UCHAR *mac);
DHCP_LEASE *SearchDhcpLeaseByIp(VH *v, UINT ip);
UINT ServeDhcpDiscover(VH *v, UCHAR *mac, UINT request_ip);
UINT GetFreeDhcpIpAddress(VH *v);
UINT GetFreeDhcpIpAddressByRandom(VH *v, UCHAR *mac);
UINT ServeDhcpRequest(VH *v, UCHAR *mac, UINT request_ip);
void VirtualDhcpSend(VH *v, UINT tran_id, UINT dest_ip, UINT dest_port,
					 UINT new_ip, UCHAR *client_mac, BUF *b, UINT hw_type, UINT hw_addr_size);
void VLog(VH *v, char *str);
void SendBeacon(VH *v);
void PollingBeacon(VH *v);
HUB_OPTION *NatGetHubOption(VH *v);
UINT GetNumNatEntriesPerIp(VH *v, UINT ip, UINT protocol, bool tcp_syn_sent);
void NatSetHubOption(VH *v, HUB_OPTION *o);
NAT_ENTRY *GetOldestNatEntryOfIp(VH *v, UINT ip, UINT protocol);
void DisconnectNatEntryNow(VH *v, NAT_ENTRY *e);

NATIVE_NAT *NewNativeNat(VH *v);
void FreeNativeNat(NATIVE_NAT *t);
void NativeNatThread(THREAD *thread, void *param);
NATIVE_STACK *NnGetNextInterface(NATIVE_NAT *t);

bool NnTestConnectivity(NATIVE_STACK *a, TUBE *halt_tube);
void NnMainLoop(NATIVE_NAT *t, NATIVE_STACK *a);

BUF *NnBuildDnsQueryPacket(char *hostname, USHORT tran_id);
BUF *NnBuildUdpPacket(BUF *payload, UINT src_ip, USHORT src_port, UINT dst_ip, USHORT dst_port);
BUF *NnBuildTcpPacket(BUF *payload, UINT src_ip, USHORT src_port, UINT dst_ip, USHORT dst_port, UINT seq, UINT ack, UINT flag, UINT window_size, UINT mss);
BUF *NnBuildIpPacket(BUF *payload, UINT src_ip, UINT dst_ip, UCHAR protocol, UCHAR ttl);
UINT NnGenSrcPort(bool raw_ip_mode);
bool NnParseDnsResponsePacket(UCHAR *data, UINT size, IP *ret_ip);
BUF *NnReadDnsRecord(BUF *buf, bool answer, USHORT *ret_type, USHORT *ret_class);
bool NnReadDnsLabel(BUF *buf);
void NnClearQueue(NATIVE_NAT *t);

int CmpNativeNatTableForSend(void *p1, void *p2);
int CmpNativeNatTableForRecv(void *p1, void *p2);
UINT GetHashNativeNatTableForSend(void *p);
UINT GetHashNativeNatTableForRecv(void *p);
void NnSetNat(NATIVE_NAT_ENTRY *e, UINT protocol, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT pub_ip, UINT pub_port);

bool NnIsActive(VH *v);
bool NnIsActiveEx(VH *v, bool *is_ipraw_mode);
void NnUdpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, UINT max_l3_size);
void NnTcpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, TCP_HEADER *old_tcp, void *data, UINT size, UINT max_l3_size);
void NnIcmpEchoRecvForInternet(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, void *icmp_data, UINT icmp_size, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size);
UINT NnMapNewPublicPort(NATIVE_NAT *t, UINT protocol, UINT dest_ip, UINT dest_port, UINT public_ip);
void NnIpSendForInternet(NATIVE_NAT *t, UCHAR ip_protocol, UCHAR ttl, UINT src_ip, UINT dest_ip, void *data, UINT size, UINT max_l3_size);
void NnIpSendFragmentedForInternet(NATIVE_NAT *t, UCHAR ip_protocol, UINT src_ip, UINT dest_ip, USHORT id, USHORT total_size,
								   USHORT offset, void *data, UINT size, UCHAR ttl);
void NnPoll(NATIVE_NAT *t);
void NnLayer2(NATIVE_NAT *t, PKT *packet);
void NnFragmentedIpReceived(NATIVE_NAT *t, PKT *packet);
void NnIpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, UINT protocol, void *data, UINT size,
				  UCHAR ttl, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size);
void NnUdpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, UINT max_l3_size);
void NnTcpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, UINT max_l3_size);
void NnIcmpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, UINT max_l3_size);

void NnCombineIp(NATIVE_NAT *t, IP_COMBINE *c, UINT offset, void *data, UINT size, bool last_packet, UCHAR *head_ip_header_data, UINT head_ip_header_size);
void NnFreeIpCombine(NATIVE_NAT *t, IP_COMBINE *c);
IP_COMBINE *NnSearchIpCombine(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol);
IP_COMBINE *NnInsertIpCombine(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol, bool mac_broadcast, UCHAR ttl, bool src_is_localmac);
void NnInitIpCombineList(NATIVE_NAT *t);
void NnFreeIpCombineList(NATIVE_NAT *t);
void NnPollingIpCombine(NATIVE_NAT *t);
void NnDeleteOldSessions(NATIVE_NAT *t);
void NnDeleteSession(NATIVE_NAT *t, NATIVE_NAT_ENTRY *e);

NATIVE_NAT_ENTRY *NnGetOldestNatEntryOfIp(NATIVE_NAT *t, UINT ip, UINT protocol);
void NnDeleteOldestNatSession(NATIVE_NAT *t, UINT ip, UINT protocol);
UINT NnGetNumNatEntriesPerIp(NATIVE_NAT *t, UINT src_ip, UINT protocol);
void NnDeleteOldestNatSessionIfNecessary(NATIVE_NAT *t, UINT ip, UINT protocol);

void NnSetSecureNatTargetHostname(char *name);


#endif	// VIRTUAL_H


