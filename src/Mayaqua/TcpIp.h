// SoftEther VPN Source Code
// Mayaqua Kernel
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


// TcpIp.h
// Header of TcpIp.c

#ifndef	TCPIP_H
#define	TCPIP_H

#ifdef	OS_WIN32
#pragma pack(push, 1)
#endif	// OS_WIN32

// MTU when using of the PPPoE
#define	MTU_FOR_PPPOE		(1500 - 46)

// MAC header
struct MAC_HEADER
{
	UCHAR	DestAddress[6];			// Source MAC address
	UCHAR	SrcAddress[6];			// Destination MAC address
	USHORT	Protocol;				// Protocol
} GCC_PACKED;

// MAC protocol
#define	MAC_PROTO_ARPV4		0x0806	// ARPv4 packet
#define	MAC_PROTO_IPV4		0x0800	// IPv4 packets
#define	MAC_PROTO_IPV6		0x86dd	// IPv6 packets
#define	MAC_PROTO_TAGVLAN	0x8100	// Tagged VLAN packets

// LLC header
struct LLC_HEADER
{
	UCHAR	Dsap;
	UCHAR	Ssap;
	UCHAR	Ctl;
} GCC_PACKED;

// The value of the SSAP and the DSAP of the LLC header
#define	LLC_DSAP_BPDU		0x42
#define	LLC_SSAP_BPDU		0x42

// BPDU header
struct BPDU_HEADER
{
	USHORT	ProtocolId;				// Protocol ID (STP == 0x0000)
	UCHAR	Version;				// Version
	UCHAR	Type;					// Type
	UCHAR	Flags;					// Flag
	USHORT	RootPriority;			// Priority of the root bridge
	UCHAR	RootMacAddress[6];		// MAC address of the root bridge
	UINT	RootPathCost;			// Path cost to the root bridge
	USHORT	BridgePriority;			// Priority of the outgoing bridge
	UCHAR	BridgeMacAddress[6];	// MAC address of the outgoing bridge
	USHORT	BridgePortId;			// Port ID of the outgoing bridge
	USHORT	MessageAge;				// Expiration date
	USHORT	MaxAge;					// Maximum expiration date
	USHORT	HelloTime;				// Hello Time
	USHORT	ForwardDelay;			// Forward Delay
} GCC_PACKED;

// ARPv4 header
struct ARPV4_HEADER
{
	USHORT	HardwareType;			// Hardware type
	USHORT	ProtocolType;			// Protocol type
	UCHAR	HardwareSize;			// Hardware size
	UCHAR	ProtocolSize;			// Protocol size
	USHORT	Operation;				// Operation
	UCHAR	SrcAddress[6];			// Source MAC address
	UINT	SrcIP;					// Source IP address
	UCHAR	TargetAddress[6];		// Target MAC address
	UINT	TargetIP;				// Target IP address
} GCC_PACKED;

// ARP hardware type
#define	ARP_HARDWARE_TYPE_ETHERNET		0x0001

// ARP operation type
#define	ARP_OPERATION_REQUEST			1
#define	ARP_OPERATION_RESPONSE			2

// Tagged VLAN header
struct TAGVLAN_HEADER
{
	UCHAR Data[2];					// Data
} GCC_PACKED;

// IPv4 header
struct IPV4_HEADER
{
	UCHAR	VersionAndHeaderLength;		// Version and header size
	UCHAR	TypeOfService;				// Service Type
	USHORT	TotalLength;				// Total size
	USHORT	Identification;				// Identifier
	UCHAR	FlagsAndFlagmentOffset[2];	// Flag and Fragment offset
	UCHAR	TimeToLive;					// TTL
	UCHAR	Protocol;					// Protocol
	USHORT	Checksum;					// Checksum
	UINT	SrcIP;						// Source IP address
	UINT	DstIP;						// Destination IP address
} GCC_PACKED;

// Macro for IPv4 header operation
#define	IPV4_GET_VERSION(h)			(((h)->VersionAndHeaderLength >> 4 & 0x0f))
#define	IPV4_SET_VERSION(h, v)		((h)->VersionAndHeaderLength |= (((v) & 0x0f) << 4))
#define	IPV4_GET_HEADER_LEN(h)		((h)->VersionAndHeaderLength & 0x0f)
#define	IPV4_SET_HEADER_LEN(h, v)	((h)->VersionAndHeaderLength |= ((v) & 0x0f))

// Macro for IPv4 fragment related operation
#define	IPV4_GET_FLAGS(h)			(((h)->FlagsAndFlagmentOffset[0] >> 5) & 0x07)
#define	IPV4_SET_FLAGS(h, v)		((h)->FlagsAndFlagmentOffset[0] |= (((v) & 0x07) << 5))
#define	IPV4_GET_OFFSET(h)			(((h)->FlagsAndFlagmentOffset[0] & 0x1f) * 256 + ((h)->FlagsAndFlagmentOffset[1]))
#define	IPV4_SET_OFFSET(h, v)		{(h)->FlagsAndFlagmentOffset[0] |= (UCHAR)((v) / 256); (h)->FlagsAndFlagmentOffset[1] = (UCHAR)((v) % 256);}

// IPv4 / IPv6 common protocol
#define	IP_PROTO_TCP		0x06	// TCP protocol
#define	IP_PROTO_UDP		0x11	// UDP protocol
#define	IP_PROTO_ESP		50		// ESP protocol
#define	IP_PROTO_ETHERIP	97		// EtherIP protocol
#define	IP_PROTO_L2TPV3		115		// L2TPv3 protocol


// UDP header
struct UDP_HEADER
{
	USHORT	SrcPort;				// Source port number
	USHORT	DstPort;				// Destination port number
	USHORT	PacketLength;			// Data length
	USHORT	Checksum;				// Checksum
} GCC_PACKED;

// UDPv4 pseudo header
struct UDPV4_PSEUDO_HEADER
{
	UINT	SrcIP;					// Source IP address
	UINT	DstIP;					// Destination IP address
	UCHAR	Reserved;				// Unused
	UCHAR	Protocol;				// Protocol number
	USHORT	PacketLength1;			// UDP data length 1
	USHORT	SrcPort;				// Source port number
	USHORT	DstPort;				// Destination port number
	USHORT	PacketLength2;			// UDP data length 2
	USHORT	Checksum;				// Checksum
} GCC_PACKED;

// IPv4 pseudo header
struct IPV4_PSEUDO_HEADER
{
	UINT	SrcIP;					// Source IP address
	UINT	DstIP;					// Destination IP address
	UCHAR	Reserved;				// Unused
	UCHAR	Protocol;				// Protocol number
	USHORT	PacketLength;			// Packet size
} GCC_PACKED;

// TCP header
struct TCP_HEADER
{
	USHORT	SrcPort;					// Source port number
	USHORT	DstPort;					// Destination port number
	UINT	SeqNumber;				// Sequence number
	UINT	AckNumber;				// Acknowledgment number
	UCHAR	HeaderSizeAndReserved;	// Header size and Reserved area
	UCHAR	Flag;					// Flag
	USHORT	WindowSize;				// Window size
	USHORT	Checksum;				// Checksum
	USHORT	UrgentPointer;			// Urgent Pointer
} GCC_PACKED;

// TCP macro
#define	TCP_GET_HEADER_SIZE(h)	(((h)->HeaderSizeAndReserved >> 4) & 0x0f)
#define	TCP_SET_HEADER_SIZE(h, v)	((h)->HeaderSizeAndReserved = (((v) & 0x0f) << 4))

// TCP flags
#define	TCP_FIN						1
#define	TCP_SYN						2
#define	TCP_RST						4
#define	TCP_PSH						8
#define	TCP_ACK						16
#define	TCP_URG						32

// ICMP header
struct ICMP_HEADER
{
	UCHAR	Type;					// Type
	UCHAR	Code;					// Code
	USHORT	Checksum;				// Checksum
} GCC_PACKED;

// ICMP Echo
struct ICMP_ECHO
{
	USHORT	Identifier;						// ID
	USHORT	SeqNo;							// Sequence number
} GCC_PACKED;

// ICMP message type
#define	ICMP_TYPE_ECHO_REQUEST						8
#define	ICMP_TYPE_ECHO_RESPONSE						0
#define	ICMP_TYPE_DESTINATION_UNREACHABLE			3
#define	ICMP_TYPE_TIME_EXCEEDED						11
#define	ICMP_TYPE_INFORMATION_REQUEST				15
#define	ICMP_TYPE_INFORMATION_REPLY					16

// ICMP message code
// In case of ICMP_TYPE_DESTINATION_UNREACHABLE
#define	ICMP_CODE_NET_UNREACHABLE					0
#define	ICMP_CODE_HOST_UNREACHABLE					1
#define	ICMP_CODE_PROTOCOL_UNREACHABLE				2
#define	ICMP_CODE_PORT_UNREACHABLE					3
#define	ICMP_CODE_FRAGMENTATION_NEEDED_DF_SET		4
#define	ICMP_CODE_SOURCE_ROUTE_FAILED				5

// In case of TIME_EXCEEDED
#define	ICMP_CODE_TTL_EXCEEDED_IN_TRANSIT			0
#define	ICMP_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDED	1

// DHCPv4 Header
struct DHCPV4_HEADER
{
	UCHAR	OpCode;				// Op-code
	UCHAR	HardwareType;		// Hardware type
	UCHAR	HardwareAddressSize;	// Hardware address size
	UCHAR	Hops;				// Number of hops
	UINT	TransactionId;		// Transaction ID
	USHORT	Seconds;				// Seconds
	USHORT	Flags;				// Flag
	UINT	ClientIP;			// Client IP address
	UINT	YourIP;				// Assigned IP address
	UINT	ServerIP;			// Server IP address
	UINT	RelayIP;				// Relay IP address
	UCHAR	ClientMacAddress[6];	// Client MAC address
	UCHAR	Padding[10];			// Padding for non-Ethernet
} GCC_PACKED;

// DNSv4 header
struct DNSV4_HEADER
{
	USHORT	TransactionId;			// Transaction ID
	UCHAR	Flag1;					// Flag 1
	UCHAR	Flag2;					// Flag 2
	USHORT	NumQuery;				// Number of queries
	USHORT	AnswerRRs;				// Answer RR number
	USHORT	AuthorityRRs;			// Authority RR number
	USHORT	AdditionalRRs;			// Additional RR number
} GCC_PACKED;

#define	DHCP_MAGIC_COOKIE	0x63825363	// Magic Cookie (fixed)

// NetBIOS Datagram header
struct NBTDG_HEADER
{
	UCHAR MessageType;
	UCHAR MoreFlagments;
	USHORT DatagramId;
	UINT SrcIP;
	USHORT SrcPort;
	USHORT DatagramLen;
	USHORT PacketOffset;
} GCC_PACKED;

// IPv6 packet header information
struct IPV6_HEADER_PACKET_INFO
{
	IPV6_HEADER *IPv6Header;					// IPv6 header
	IPV6_OPTION_HEADER *HopHeader;				// Hop-by-hop option header
	UINT HopHeaderSize;							// Hop-by-hop option header size
	IPV6_OPTION_HEADER *EndPointHeader;			// End point option header
	UINT EndPointHeaderSize;					// End point option header size
	IPV6_OPTION_HEADER *RoutingHeader;			// Routing header
	UINT RoutingHeaderSize;						// Routing header size
	IPV6_FRAGMENT_HEADER *FragmentHeader;		// Fragment header
	void *Payload;								// Payload
	UINT PayloadSize;							// Payload size
	UCHAR Protocol;								// Payload protocol
	bool IsFragment;							// Whether it's a fragmented packet
	UINT TotalHeaderSize;						// Total header size
};

// IPv6 header
struct IPV6_HEADER
{
	UCHAR VersionAndTrafficClass1;		// Version Number (4 bit) and Traffic Class 1 (4 bit)
	UCHAR TrafficClass2AndFlowLabel1;	// Traffic Class 2 (4 bit) and Flow Label 1 (4 bit)
	UCHAR FlowLabel2;					// Flow Label 2 (8 bit)
	UCHAR FlowLabel3;					// Flow Label 3 (8 bit)
	USHORT PayloadLength;				// Length of the payload (including extension header)
	UCHAR NextHeader;					// Next header
	UCHAR HopLimit;						// Hop limit
	IPV6_ADDR SrcAddress;				// Source address
	IPV6_ADDR DestAddress;				// Destination address
} GCC_PACKED;


// Macro for IPv6 header operation
#define IPV6_GET_VERSION(h)			(((h)->VersionAndTrafficClass1 >> 4) & 0x0f)
#define IPV6_SET_VERSION(h, v)		((h)->VersionAndTrafficClass1 = ((h)->VersionAndTrafficClass1 & 0x0f) | ((v) << 4) & 0xf0)
#define IPV6_GET_TRAFFIC_CLASS(h)	((((h)->VersionAndTrafficClass1 << 4) & 0xf0) | ((h)->TrafficClass2AndFlowLabel1 >> 4) & 0x0f)
#define	IPV6_SET_TRAFFIC_CLASS(h, v)	((h)->VersionAndTrafficClass1 = ((h)->VersionAndTrafficClass1 & 0xf0) | (((v) >> 4) & 0x0f),\
	(h)->TrafficClass2AndFlowLabel1 = (h)->TrafficClass2AndFlowLabel1 & 0x0f | ((v) << 4) & 0xf0)
#define	IPV6_GET_FLOW_LABEL(h)		((((h)->TrafficClass2AndFlowLabel1 << 16) & 0xf0000) | (((h)->FlowLabel2 << 8) & 0xff00) |\
	(((h)->FlowLabel3) & 0xff))
#define IPV6_SET_FLOW_LABEL(h, v)	((h)->TrafficClass2AndFlowLabel1 = ((h)->TrafficClass2AndFlowLabel1 & 0xf0 | ((v) >> 16) & 0x0f),\
	(h)->FlowLabel2 = ((v) >> 8) & 0xff,\
	(h)->FlowLabel3 = (v) & 0xff)


// Maximum hops of IPv6 (not routing)
#define IPV6_HOP_MAX					255

// Standard hops of IPv6
#define IPV6_HOP_DEFAULT				127

// IPv6 header number
#define IPV6_HEADER_HOP					0	// Hop-by-hop option header
#define IPV6_HEADER_ENDPOINT			60	// End point option header
#define IPV6_HEADER_ROUTING				43	// Routing header
#define IPV6_HEADER_FRAGMENT			44	// Fragment header
#define IPV6_HEADER_NONE				59	// No Next Header

// IPv6 option header
// (Used on hop option header, end point option header, routing header)
struct IPV6_OPTION_HEADER
{
	UCHAR NextHeader;					// Next header
	UCHAR Size;							// Header size (/8)
} GCC_PACKED;

// IPv6 fragment header
// (fragment impossible part is until just before the routing header
// or hop-by-hop option header or first extended header or payload)
struct IPV6_FRAGMENT_HEADER
{
	UCHAR NextHeader;					// Next header
	UCHAR Reserved;						// Reserved
	UCHAR FlagmentOffset1;				// Fragment offset 1 (/8, 8 bit)
	UCHAR FlagmentOffset2AndFlags;		// Fragment offset 2 (/8, 5 bit) + Reserved (2 bit) + More flag (1 bit)
	UINT Identification;				// ID
} GCC_PACKED;

// Macro for IPv6 fragment header operation
#define IPV6_GET_FRAGMENT_OFFSET(h)		(((((h)->FlagmentOffset1) << 5) & 0x1fe0) | (((h)->FlagmentOffset2AndFlags >> 3) & 0x1f))
#define IPV6_SET_FRAGMENT_OFFSET(h, v)	((h)->FlagmentOffset1 = (v / 32) & 0xff,	\
	((h)->FlagmentOffset2AndFlags = ((v % 256) << 3) & 0xf8) | ((h)->FlagmentOffset2AndFlags & 0x07))
#define IPV6_GET_FLAGS(h)				((h)->FlagmentOffset2AndFlags & 0x0f)
#define IPV6_SET_FLAGS(h, v)				((h)->FlagmentOffset2AndFlags = (((h)->FlagmentOffset2AndFlags & 0xf8) | (v & 0x07)))

// Flag
#define IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS		0x01	// There are more fragments

// Virtual IPv6 header
struct IPV6_PSEUDO_HEADER
{
	IPV6_ADDR SrcAddress;				// Source address
	IPV6_ADDR DestAddress;				// Destination address
	UINT UpperLayerPacketSize;			// Upper layer packet size
	UCHAR Padding[3];					// Padding
	UCHAR NextHeader;					// Next Header (TCP / UDP)
} GCC_PACKED;

// ICMPv6 Router Solicitation header
struct ICMPV6_ROUTER_SOLICIATION_HEADER
{
	UINT Reserved;							// Reserved
	// + Option (source link-layer address [optional])
} GCC_PACKED;

// ICMPv6 Router Advertisement header
struct ICMPV6_ROUTER_ADVERTISEMENT_HEADER
{
	UCHAR CurHopLimit;						// Hop limit of the default
	UCHAR Flags;							// Flag (0)
	USHORT Lifetime;						// Lifetime
	UINT ReachableTime;						// 0
	UINT RetransTimer;						// 0
	// + Option (prefix information [required], MTU [optional])
} GCC_PACKED;

// ICMPv6 Neighbor Solicitation header
struct ICMPV6_NEIGHBOR_SOLICIATION_HEADER
{
	UINT Reserved;							// Reserved
	IPV6_ADDR TargetAddress;				// Target address
	// + Option (source link-layer address [required])
} GCC_PACKED;

// ICMPv6 Neighbor Advertisement header
struct ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER
{
	UCHAR Flags;							// Flag
	UCHAR Reserved[3];						// Reserved
	IPV6_ADDR TargetAddress;				// Target address
	// + Option (target link-layer address)
} GCC_PACKED;

#define ICMPV6_NEIGHBOR_ADVERTISEMENT_FLAG_ROUTER		0x80	// Router
#define ICMPV6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED	0x40	// Solicited flag
#define ICMPV6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERWRITE	0x20	// Overwrite flag

// ICMPv6 option list
struct ICMPV6_OPTION_LIST
{
	ICMPV6_OPTION_LINK_LAYER *SourceLinkLayer;		// Source link-layer address
	ICMPV6_OPTION_LINK_LAYER *TargetLinkLayer;		// Target link-layer address
	ICMPV6_OPTION_PREFIX *Prefix;					// Prefix Information
	ICMPV6_OPTION_MTU *Mtu;							// MTU
} GCC_PACKED;

// ICMPv6 option
struct ICMPV6_OPTION
{
	UCHAR Type;								// Type
	UCHAR Length;							// Length (/8, include type and length)
} GCC_PACKED;

#define	ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER	1		// Source link-layer address
#define ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER	2		// Target link-layer address
#define ICMPV6_OPTION_TYPE_PREFIX				3		// Prefix Information
#define ICMPV6_OPTION_TYPE_MTU					5		// MTU

// ICMPv6 link layer options
struct ICMPV6_OPTION_LINK_LAYER
{
	ICMPV6_OPTION IcmpOptionHeader;			// Option header
	UCHAR Address[6];						// MAC address
} GCC_PACKED;

// ICMPv6 prefix information option
struct ICMPV6_OPTION_PREFIX
{
	ICMPV6_OPTION IcmpOptionHeader;			// Option header
	UCHAR SubnetLength;						// Subnet length
	UCHAR Flags;							// Flag
	UINT ValidLifetime;						// Formal lifetime
	UINT PreferredLifetime;					// Preferred lifetime
	UINT Reserved;							// Reserved
	IPV6_ADDR Prefix;						// Prefix address
} GCC_PACKED;

#define ICMPV6_OPTION_PREFIX_FLAG_ONLINK		0x80	// On link
#define ICMPV6_OPTION_PREFIX_FLAG_AUTO			0x40	// Automatic

// ICMPv6 MTU option
struct ICMPV6_OPTION_MTU
{
	ICMPV6_OPTION IcmpOptionHeader;			// Option header
	USHORT Reserved;						// Reserved
	UINT Mtu;								// MTU value
} GCC_PACKED;


// IPv6 header information
struct IPV6_HEADER_INFO
{
	bool IsRawIpPacket;
	USHORT Size;
	UINT Id;
	UCHAR Protocol;
	UCHAR HopLimit;
	IPV6_ADDR SrcIpAddress;
	IPV6_ADDR DestIpAddress;
	bool UnicastForMe;
	bool UnicastForRouting;
	bool UnicastForRoutingWithProxyNdp;
	bool IsBroadcast;
	UINT TypeL4;
};

// ICMPv6 header information
struct ICMPV6_HEADER_INFO
{
	UCHAR Type;
	UCHAR Code;
	USHORT DataSize;
	void *Data;
	ICMP_ECHO EchoHeader;
	void *EchoData;
	UINT EchoDataSize;

	union
	{
		// Meaning is determined by the value of the Type
		ICMPV6_ROUTER_SOLICIATION_HEADER *RouterSoliciationHeader;
		ICMPV6_ROUTER_ADVERTISEMENT_HEADER *RouterAdvertisementHeader;
		ICMPV6_NEIGHBOR_SOLICIATION_HEADER *NeighborSoliciationHeader;
		ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER *NeighborAdvertisementHeader;
		void *HeaderPointer;
	} Headers;

	ICMPV6_OPTION_LIST OptionList;
};

// The Type value of ICMPv6
#define ICMPV6_TYPE_ECHO_REQUEST				128		// ICMPv6 Echo request
#define ICMPV6_TYPE_ECHO_RESPONSE				129		// ICMPv6 Echo response
#define ICMPV6_TYPE_ROUTER_SOLICIATION			133		// Router Solicitation
#define ICMPV6_TYPE_ROUTER_ADVERTISEMENT		134		// Router Advertisement
#define ICMPV6_TYPE_NEIGHBOR_SOLICIATION		135		// Neighbor Solicitation
#define ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT		136		// Neighbor Advertisement

// Minimum DHCP packet size
#define	DHCP_MIN_SIZE				300

// Constants about DHCP
#define	DHCP_ID_MESSAGE_TYPE		0x35
#define	DHCP_ID_REQUEST_IP_ADDRESS	0x32
#define	DHCP_ID_HOST_NAME			0x0c
#define	DHCP_ID_SERVER_ADDRESS		0x36
#define	DHCP_ID_LEASE_TIME			0x33
#define	DHCP_ID_DOMAIN_NAME			0x0f
#define	DHCP_ID_SUBNET_MASK			0x01
#define	DHCP_ID_GATEWAY_ADDR		0x03
#define	DHCP_ID_DNS_ADDR			0x06
#define	DHCP_ID_WINS_ADDR			0x2C
#define	DHCP_ID_CLIENT_ID			0x3d
#define	DHCP_ID_VENDOR_ID			0x3c
#define	DHCP_ID_REQ_PARAM_LIST		0x37
#define	DHCP_ID_CLASSLESS_ROUTE		0x79
#define	DHCP_ID_MS_CLASSLESS_ROUTE	0xF9
#define	DHCP_ID_PRIVATE				0xFA


// DHCP client action
#define	DHCP_DISCOVER		1
#define	DHCP_REQUEST		3
#define	DHCP_RELEASE		7
#define	DHCP_INFORM			8

// DHCP server action
#define	DHCP_OFFER			2
#define	DHCP_DECLINE		4
#define	DHCP_ACK			5
#define	DHCP_NACK			6

// HTTPLOG data structure
struct HTTPLOG
{
	char Method[32];						// Method
	char Hostname[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT Port;								// Port number
	char Path[MAX_SIZE];					// Path
	char Protocol[64];						// Protocol
	char UserAgent[MAX_SIZE];				// User Agent value
	char Referer[MAX_SIZE];					// Referer
};

// Packet
struct PKT
{
	UCHAR			*PacketData;	// Packet data body
	UINT			PacketSize;		// Packet size
	MAC_HEADER		*MacHeader;		// MAC header
	UCHAR			*MacAddressSrc;	// Source MAC address
	UCHAR			*MacAddressDest;	// Destination MAC address
	bool			BroadcastPacket;		// Broadcast packet
	bool			InvalidSourcePacket;	// Packet with an invalid source address
	bool			AccessChecked;	// Packets that pass was confirmed by the access list
	UINT			VlanTypeID;		// TypeID of the tagged VLAN (usually 0x8100)
	UINT			VlanId;			// VLAN ID
	UINT			Delay;			// Delay
	UINT			Jitter;			// Jitter
	UINT			Loss;			// Packet loss
	UINT64			DelayedForwardTick;	// Sending time in case of delayed
	struct SESSION	*DelayedSrcSession;	// Source session
	UINT			TypeL3;			// Layer-3 packet classification
	IPV6_HEADER_PACKET_INFO IPv6HeaderPacketInfo;	// IPv6 packet header information (only for TypeL3 == L3_IPV6)
	ICMPV6_HEADER_INFO ICMPv6HeaderPacketInfo;		// ICMPv6 header information (Only for TypeL4 == L4_ICMPV6)
	UINT			DhcpOpCode;		// DHCP opcode
	union
	{
		IPV4_HEADER		*IPv4Header;	// IPv4 header
		ARPV4_HEADER	*ARPv4Header;	// ARPv4 header
		IPV6_HEADER		*IPv6Header;	// IPv6 header
		TAGVLAN_HEADER	*TagVlanHeader;	// Tag header
		BPDU_HEADER		*BpduHeader;	// BPDU header
		void			*PointerL3;
	} L3;
	UINT			TypeL4;				// Layer-4 packet classification
	UINT			IPv4PayloadSize;	// IPv4 payload size
	void			*IPv4PayloadData;	// IPv4 payload data
	union
	{
		UDP_HEADER	*UDPHeader;			// UDP header
		TCP_HEADER	*TCPHeader;			// TCP header
		ICMP_HEADER	*ICMPHeader;		// ICMP header
		void		*PointerL4;
	} L4;
	UINT			TypeL7;			// Layer-7 packet classification
	union
	{
		DHCPV4_HEADER	*DHCPv4Header;	// DHCPv4 header
		IKE_HEADER		*IkeHeader;		// IKE header
		void			*PointerL7;
	} L7;
	UCHAR				*Payload;		// Pointer to the payload of TCP or UDP
	UINT				PayloadSize;	// Payload size
	struct HTTPLOG		*HttpLog;		// HTTP log
} GCC_PACKED;

// Layer-3 packet classification
#define	L3_UNKNOWN			0		// Unknown
#define	L3_ARPV4			1		// ARPv4 packet
#define	L3_IPV4				2		// IPv4 packet
#define	L3_TAGVLAN			3		// Tagged VLAN packet
#define	L3_BPDU				4		// BPDU packet
#define L3_IPV6				5		// IPv6 packet

// Layer-4 packet classification
#define	L4_UNKNOWN			0		// Unknown
#define	L4_UDP				1		// UDPv4 packet
#define	L4_TCP				2		// TCPv4 packet
#define	L4_ICMPV4			3		// ICMPv4 packet
#define	L4_ICMPV6			4		// ICMPv6 packet
#define	L4_FRAGMENT			5		// Fragment packet

// Layer-7 packet classification
#define	L7_UNKNOWN			0		// Unknown
#define	L7_DHCPV4			1		// DHCPv4 packet
#define	L7_IKECONN			2		// IKE connection request packet
#define	L7_OPENVPNCONN		3		// OpenVPN connection request packet


// IKE header
struct IKE_HEADER
{
	UINT64 InitiatorCookie;						// Initiator cookie
	UINT64 ResponderCookie;						// Responder cookie
	UCHAR NextPayload;							// Next payload
	UCHAR Version;								// Version
	UCHAR ExchangeType;							// Exchange type
	UCHAR Flag;									// Flag
	UINT MessageId;								// Message ID
	UINT MessageSize;							// Message size
} GCC_PACKED;

// IKE exchange type
#define	IKE_EXCHANGE_TYPE_MAIN				2	// Main mode
#define IKE_EXCHANGE_TYPE_AGGRESSIVE		4	// Aggressive mode
#define IKE_EXCHANGE_TYPE_INFORMATION		5	// Information exchange
#define IKE_EXCHANGE_TYPE_QUICK				32	// Quick mode

// DHCPv4 data
struct DHCPV4_DATA
{
	UCHAR *Data;
	UINT Size;
	IP SrcIP;
	UINT SrcPort;
	IP DestIP;
	UINT DestPort;
	UINT OpCode;

	UCHAR *OptionData;
	UINT OptionSize;

	DHCPV4_HEADER *Header;
	LIST *OptionList;

	struct DHCP_OPTION_LIST *ParsedOptionList;
};
// DHCP Option
struct DHCP_OPTION
{
	UINT Id;						// ID
	UINT Size;						// Size
	void *Data;						// Data
};

// DHCP classless static route entry
struct DHCP_CLASSLESS_ROUTE
{
	bool Exists;					// Existing flag
	IP Network;						// Network address
	IP SubnetMask;					// Subnet mask
	IP Gateway;						// Gateway
	UINT SubnetMaskLen;				// Subnet mask length
};

#define	MAX_DHCP_CLASSLESS_ROUTE_ENTRIES	64
#define	MAX_DHCP_CLASSLESS_ROUTE_TABLE_STR_SIZE	3200

// DHCP classless static route table
struct DHCP_CLASSLESS_ROUTE_TABLE
{
	UINT NumExistingRoutes;			// Number of existing routing table entries
	DHCP_CLASSLESS_ROUTE Entries[MAX_DHCP_CLASSLESS_ROUTE_ENTRIES];	// Entries
};

// DHCP option list
struct DHCP_OPTION_LIST
{
	// Common Item
	UINT Opcode;					// DHCP opcode

	// Client request
	UINT RequestedIp;				// Requested IP address
	char Hostname[MAX_HOST_NAME_LEN + 1]; // Host name

	// Server response
	UINT ClientAddress;				// Client address
	UINT ServerAddress;				// DHCP server address
	UINT LeaseTime;					// Lease time
	char DomainName[MAX_HOST_NAME_LEN + 1];	// Domain name
	UINT SubnetMask;				// Subnet mask
	UINT Gateway;					// Gateway address
	UINT DnsServer;					// DNS server address 1
	UINT DnsServer2;				// DNS server address 2
	UINT WinsServer;				// WINS server address 1
	UINT WinsServer2;				// WINS server address 2
	DHCP_CLASSLESS_ROUTE_TABLE ClasslessRoute;	// Classless static routing table
};

// Modification option in the DHCP packet
struct DHCP_MODIFY_OPTION
{
	bool RemoveDefaultGatewayOnReply;			// Remove the default gateway from the DHCP Reply
};

// Special IP address
#define	SPECIAL_IPV4_ADDR_LLMNR_DEST		0xE00000FC	// 224.0.0.252

// Special port
#define	SPECIAL_UDP_PORT_LLMNR				5355	// LLMNR
#define	SPECIAL_UDP_PORT_NBTNS				137		// NetBIOS Name Service
#define	SPECIAL_UDP_PORT_NBTDGM				138		// NetBIOS Datagram
#define	SPECIAL_UDP_PORT_WSD				3702	// WS-Discovery
#define	SPECIAL_UDP_PORT_SSDP				1900	// SSDP


PKT *ParsePacketIPv4WithDummyMacHeader(UCHAR *buf, UINT size);
PKT *ParsePacket(UCHAR *buf, UINT size);
PKT *ParsePacketEx(UCHAR *buf, UINT size, bool no_l3);
PKT *ParsePacketEx2(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id);
PKT *ParsePacketEx3(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address);
PKT *ParsePacketEx4(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address, bool no_http, bool correct_checksum);
void FreePacket(PKT *p);
void FreePacketWithData(PKT *p);
void FreePacketIPv4(PKT *p);
void FreePacketTagVlan(PKT *p);
void FreePacketARPv4(PKT *p);
void FreePacketUDPv4(PKT *p);
void FreePacketTCPv4(PKT *p);
void FreePacketICMPv4(PKT *p);
void FreePacketDHCPv4(PKT *p);
bool ParsePacketL2(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketL2Ex(PKT *p, UCHAR *buf, UINT size, bool no_l3);
bool ParsePacketARPv4(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketIPv4(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketBPDU(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketTAGVLAN(PKT *p, UCHAR *buf, UINT size);
bool ParseICMPv4(PKT *p, UCHAR *buf, UINT size);
bool ParseICMPv6(PKT *p, UCHAR *buf, UINT size);
bool ParseTCP(PKT *p, UCHAR *buf, UINT size);
bool ParseUDP(PKT *p, UCHAR *buf, UINT size);
void ParseDHCPv4(PKT *p, UCHAR *buf, UINT size);
PKT *ClonePacket(PKT *p, bool copy_data);
void FreeClonePacket(PKT *p);

void CorrectChecksum(PKT *p);

bool ParsePacketIPv6(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketIPv6Header(IPV6_HEADER_PACKET_INFO *info, UCHAR *buf, UINT size);
bool ParseIPv6ExtHeader(IPV6_HEADER_PACKET_INFO *info, UCHAR next_header, UCHAR *buf, UINT size);
bool ParseICMPv6Options(ICMPV6_OPTION_LIST *o, UCHAR *buf, UINT size);
void CloneICMPv6Options(ICMPV6_OPTION_LIST *dst, ICMPV6_OPTION_LIST *src);
void FreeCloneICMPv6Options(ICMPV6_OPTION_LIST *o);
USHORT CalcChecksumForIPv4(UINT src_ip, UINT dst_ip, UCHAR protocol, void *data, UINT size, UINT real_size);
USHORT CalcChecksumForIPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR protocol, void *data, UINT size, UINT real_size);
BUF *BuildICMPv6Options(ICMPV6_OPTION_LIST *o);
void BuildICMPv6OptionValue(BUF *b, UCHAR type, void *header_pointer, UINT total_size);
BUF *BuildIPv6(IPV6_ADDR *dest_ip, IPV6_ADDR *src_ip, UINT id, UCHAR protocol, UCHAR hop_limit, void *data,
			   UINT size);
BUF *BuildIPv6PacketHeader(IPV6_HEADER_PACKET_INFO *info, UINT *bytes_before_payload);
UCHAR IPv6GetNextHeaderFromQueue(QUEUE *q);
void BuildAndAddIPv6PacketOptionHeader(BUF *b, IPV6_OPTION_HEADER *opt, UCHAR next_header, UINT size);
BUF *BuildICMPv6NeighborSoliciation(IPV6_ADDR *src_ip, IPV6_ADDR *target_ip, UCHAR *my_mac_address, UINT id);
BUF *BuildICMPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR hop_limit, UCHAR type, UCHAR code, void *data, UINT size, UINT id);

bool VLanRemoveTag(void **packet_data, UINT *packet_size, UINT vlan_id, UINT vlan_tpid);
void VLanInsertTag(void **packet_data, UINT *packet_size, UINT vlan_id, UINT vlan_tpid);

DHCPV4_DATA *ParseDHCPv4Data(PKT *pkt);
void FreeDHCPv4Data(DHCPV4_DATA *d);

bool AdjustTcpMssL3(UCHAR *src, UINT src_size, UINT mss);
bool AdjustTcpMssL2(UCHAR *src, UINT src_size, UINT mss, USHORT tag_vlan_tpid);
UINT GetIpHeaderSize(UCHAR *src, UINT src_size);

bool IsDhcpPacketForSpecificMac(UCHAR *data, UINT size, UCHAR *mac_address);

ICMP_RESULT *IcmpEchoSendBySocket(IP *dest_ip, UCHAR ttl, UCHAR *data, UINT size, UINT timeout);
ICMP_RESULT *IcmpEchoSend(IP *dest_ip, UCHAR ttl, UCHAR *data, UINT size, UINT timeout);
ICMP_RESULT *IcmpParseResult(IP *dest_ip, USHORT src_id, USHORT src_seqno, UCHAR *recv_buffer, UINT recv_buffer_size);
void IcmpFreeResult(ICMP_RESULT *r);

USHORT IpChecksum(void *buf, UINT size);
bool IpCheckChecksum(IPV4_HEADER *ip);

LIST *BuildDhcpOption(DHCP_OPTION_LIST *opt);
DHCP_OPTION *NewDhcpOption(UINT id, void *data, UINT size);
DHCP_OPTION_LIST *ParseDhcpOptionList(void *data, UINT size);
DHCP_OPTION *GetDhcpOption(LIST *o, UINT id);
void FreeDhcpOptions(LIST *o);
LIST *ParseDhcpOptions(void *data, UINT size);
BUF *BuildDhcpOptionsBuf(LIST *o);
HTTPLOG *ParseHttpAccessLog(PKT *pkt);

BUF *DhcpModify(DHCP_MODIFY_OPTION *m, void *data, UINT size);
BUF *DhcpModifyIPv4(DHCP_MODIFY_OPTION *m, void *data, UINT size);

DHCP_CLASSLESS_ROUTE *GetBestClasslessRoute(DHCP_CLASSLESS_ROUTE_TABLE *t, IP *ip);
void DhcpParseClasslessRouteData(DHCP_CLASSLESS_ROUTE_TABLE *t, void *data, UINT size);
BUF *DhcpBuildClasslessRouteData(DHCP_CLASSLESS_ROUTE_TABLE *t);
bool ParseClasslessRouteStr(DHCP_CLASSLESS_ROUTE *r, char *str);
bool ParseClasslessRouteTableStr(DHCP_CLASSLESS_ROUTE_TABLE *d, char *str);
bool CheckClasslessRouteTableStr(char *str);
void BuildClasslessRouteStr(char *str, UINT str_size, DHCP_CLASSLESS_ROUTE *r);
void BuildClasslessRouteTableStr(char *str, UINT str_size, DHCP_CLASSLESS_ROUTE_TABLE *t);
bool NormalizeClasslessRouteTableStr(char *dst, UINT dst_size, char *src);



#ifdef	OS_WIN32
#pragma pack(pop)
#endif	// OS_WIN32

#endif	// TCPIP_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
