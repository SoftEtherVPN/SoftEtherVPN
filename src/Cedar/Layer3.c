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


// Layer3.c
// Layer-3 switch module

#include "CedarPch.h"

static UCHAR broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// Process the IP queue
void L3PollingIpQueue(L3IF *f)
{
	L3PACKET *p;
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	// Process the packet came from another session
	while (p = GetNext(f->IpPacketQueue))
	{
		PKT *pkt = p->Packet;

		// Send as an IP packet
		L3SendIp(f, p);
	}
}

// Process IP packets
void L3RecvIp(L3IF *f, PKT *p, bool self)
{
	IPV4_HEADER *ip;
	UINT header_size;
	UINT next_hop = 0;
	L3IF *dst;
	L3PACKET *packet;
	UINT new_ttl = 0;
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return;
	}

	ip = p->L3.IPv4Header;
	header_size = IPV4_GET_HEADER_LEN(p->L3.IPv4Header) * 4;

	// Calculate the checksum
	if (IpCheckChecksum(ip) == false)
	{
		// The checksum does not match
		goto FREE_PACKET;
	}

	// Register in the ARP table
	L3KnownArp(f, ip->SrcIP, p->MacAddressSrc);

	if (p->BroadcastPacket)
	{
		// Not to route in the case of broadcast packet
		goto FREE_PACKET;
	}

	// Calculate the TTL
	if (ip->TimeToLive >= 1)
	{
		new_ttl = ip->TimeToLive - 1;
	}
	else
	{
		new_ttl = 0;
	}

	if (new_ttl == 0)
	{
		if (ip->DstIP != f->IpAddress)
		{
			UINT src_packet_size = p->PacketSize - sizeof(MAC_HEADER);
			UINT icmp_packet_total_size = sizeof(MAC_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER) + 4 + header_size + 8;
			UCHAR *buf;
			IPV4_HEADER *ipv4;
			ICMP_HEADER *icmpv4;
			UCHAR *data;
			PKT *pkt;
			UINT data_size = MIN(p->PacketSize - header_size, header_size + 8);

			// Generate an ICMP message that means that the TTL has expired
			buf = ZeroMalloc(icmp_packet_total_size);
			ipv4 = (IPV4_HEADER *)(buf + sizeof(MAC_HEADER));
			icmpv4 = (ICMP_HEADER *)(buf + sizeof(MAC_HEADER) + sizeof(IPV4_HEADER));
			data = buf + sizeof(MAC_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER) + 4;

			IPV4_SET_VERSION(ipv4, 4);
			IPV4_SET_HEADER_LEN(ipv4, sizeof(IPV4_HEADER) / 4);
			ipv4->TotalLength = Endian16((USHORT)(icmp_packet_total_size - sizeof(MAC_HEADER)));
			ipv4->TimeToLive = 0xff;
			ipv4->Protocol = IP_PROTO_ICMPV4;
			ipv4->SrcIP = f->IpAddress;
			ipv4->DstIP = ip->SrcIP;
			ipv4->Checksum = IpChecksum(ipv4, sizeof(IPV4_HEADER));

			icmpv4->Type = 11;
			Copy(data, ip, data_size);
			icmpv4->Checksum = IpChecksum(icmpv4, sizeof(ICMP_HEADER) + data_size + 4);

			buf[12] = 0x08;
			buf[13] = 0x00;

			pkt = ParsePacket(buf, icmp_packet_total_size);
			if (pkt == NULL)
			{
				Free(buf);
			}
			else
			{
				L3RecvIp(f, pkt, true);
			}

			// Discard the packet body whose the TTL has expired
			goto FREE_PACKET;
		}
	}

	// Rewrite the TTL
	p->L3.IPv4Header->TimeToLive = (UCHAR)new_ttl;

	// Get the interface corresponding to the destination IP address
	dst = L3GetNextIf(f->Switch, ip->DstIP, &next_hop);

	if (dst == NULL && self == false)
	{
		UINT src_packet_size = p->PacketSize - sizeof(MAC_HEADER);
		UINT icmp_packet_total_size = sizeof(MAC_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER) + 4 + header_size + 8;
		UCHAR *buf;
		IPV4_HEADER *ipv4;
		ICMP_HEADER *icmpv4;
		UCHAR *data;
		PKT *pkt;
			UINT data_size = MIN(p->PacketSize - header_size, header_size + 8);

		// Respond with ICMP that indicates that no route can be found
		buf = ZeroMalloc(icmp_packet_total_size);
		ipv4 = (IPV4_HEADER *)(buf + sizeof(MAC_HEADER));
		icmpv4 = (ICMP_HEADER *)(buf + sizeof(MAC_HEADER) + sizeof(IPV4_HEADER));
		data = buf + sizeof(MAC_HEADER) + sizeof(IPV4_HEADER) + sizeof(ICMP_HEADER) + 4;

		IPV4_SET_VERSION(ipv4, 4);
		IPV4_SET_HEADER_LEN(ipv4, sizeof(IPV4_HEADER) / 4);
		ipv4->TotalLength = Endian16((USHORT)(icmp_packet_total_size - sizeof(MAC_HEADER)));
		ipv4->TimeToLive = 0xff;
		ipv4->Protocol = IP_PROTO_ICMPV4;
		ipv4->SrcIP = f->IpAddress;
		ipv4->DstIP = ip->SrcIP;
		ipv4->Checksum = IpChecksum(ipv4, sizeof(IPV4_HEADER));

		icmpv4->Type = 3;
		Copy(data, ip, data_size);
		icmpv4->Checksum = IpChecksum(icmpv4, sizeof(ICMP_HEADER) + data_size + 4);

		buf[12] = 0x08;
		buf[13] = 0x00;

		pkt = ParsePacket(buf, icmp_packet_total_size);
		if (pkt == NULL)
		{
			Free(buf);
		}
		else
		{
			L3RecvIp(f, pkt, true);
		}

		// Discard the packet body whose route can not be found
		goto FREE_PACKET;
	}

	if (dst != NULL && ip->DstIP == dst->IpAddress)
	{
		bool free_packet = true;
		// IP packet addressed to myself has arrived
		if (p->TypeL4 == L4_ICMPV4)
		{
			ICMP_HEADER *icmp = p->L4.ICMPHeader;
			if (icmp->Type == ICMP_TYPE_ECHO_REQUEST)
			{
				// Reply by rewriting the source and destination of the IP packet
				UINT src_ip, dst_ip;
				src_ip = p->L3.IPv4Header->DstIP;
				dst_ip = p->L3.IPv4Header->SrcIP;

				p->L3.IPv4Header->DstIP = dst_ip;
				p->L3.IPv4Header->SrcIP = src_ip;

				ip->TimeToLive = 0xff;

				// Recalculates the checksum
				ip->FlagsAndFlagmentOffset[0] = ip->FlagsAndFlagmentOffset[1] = 0;
				icmp->Checksum = 0;
				icmp->Type = ICMP_TYPE_ECHO_RESPONSE;
				icmp->Checksum = IpChecksum(icmp, p->PacketSize - sizeof(MAC_HEADER) - header_size);

				dst = L3GetNextIf(f->Switch, ip->DstIP, &next_hop);

				free_packet = false;
			}
		}

		if (free_packet)
		{
			goto FREE_PACKET;
		}
	}

	if (dst == NULL)
	{
		// The destination does not exist
		goto FREE_PACKET;
	}

	// Recalculate the IP checksum
	ip->Checksum = 0;
	ip->Checksum = IpChecksum(ip, header_size);

	// Treat as a Layer-3 packet
	packet = ZeroMalloc(sizeof(L3PACKET));
	packet->Expire = Tick64() + IP_WAIT_FOR_ARP_TIMEOUT;
	packet->NextHopIp = next_hop;
	packet->Packet = p;

	// Store to the destination session
	L3StoreIpPacketToIf(f, dst, packet);

	return;

FREE_PACKET:
	// Release the packet
	Free(p->PacketData);
	FreePacket(p);
	return;
}

// Process the Layer 2 packet
void L3RecvL2(L3IF *f, PKT *p)
{
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return;
	}

	// Ignore any packets except a unicast packet which is destinated other
	// or a packet which I sent
	if (Cmp(p->MacAddressSrc, f->MacAddress, 6) == 0 ||
		(p->BroadcastPacket == false && Cmp(p->MacAddressDest, f->MacAddress, 6) != 0))
	{
		// Release the packet
		Free(p->PacketData);
		FreePacket(p);
		return;
	}

	if (p->TypeL3 == L3_ARPV4)
	{
		// Received an ARP packet
		L3RecvArp(f, p);

		// Release the packet
		Free(p->PacketData);
		FreePacket(p);
	}
	else if (p->TypeL3 == L3_IPV4)
	{
		// Received an IP packet
		L3RecvIp(f, p, false);
	}
	else
	{
		// Release the packet
		Free(p->PacketData);
		FreePacket(p);
	}
}

// Store the IP packet to a different interface
void L3StoreIpPacketToIf(L3IF *src_if, L3IF *dst_if, L3PACKET *p)
{
	// Validate arguments
	if (src_if == NULL || p == NULL || dst_if == NULL)
	{
		return;
	}

	// Add to the queue of store-destination session
	InsertQueue(dst_if->IpPacketQueue, p);

	// Hit the Cancel object of the store-destination session
	AddCancelList(src_if->CancelList, dst_if->Session->Cancel1);
}

// Write the packet (Process because the packet was received)
void L3PutPacket(L3IF *f, void *data, UINT size)
{
	PKT *p;
	L3SW *s;
	if (f == NULL)
	{
		return;
	}

	s = f->Switch;

	if (data != NULL)
	{
		// Handle the next packet
		if (f->CancelList == NULL)
		{
			f->CancelList = NewCancelList();
		}

		// Packet analysis
		p = ParsePacket(data, size);

		if (p == NULL)
		{
			// Packet analysis failure
			Free(data);
		}
		else
		{
			// Packet analysis success
			Lock(s->lock);
			{
				L3RecvL2(f, p);
			}
			Unlock(s->lock);
		}
	}
	else
	{
		// Cancel for the cancellation list after all packet processing has been finished
		if (f->CancelList != NULL)
		{
			CancelList(f->CancelList);
			ReleaseCancelList(f->CancelList);
			f->CancelList = NULL;
		}
	}
}

// Send the waiting IP packets whose destination MAC address has been resolved
void L3SendWaitingIp(L3IF *f, UCHAR *mac, UINT ip, L3ARPENTRY *a)
{
	UINT i;
	LIST *o = NULL;
	// Validate arguments
	if (f == NULL || mac == NULL || a == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(f->IpWaitList);i++)
	{
		L3PACKET *p = LIST_DATA(f->IpWaitList, i);

		if (p->NextHopIp == ip)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Add(o, p);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			L3PACKET *p = LIST_DATA(o, i);

			// Transmission
			L3SendIpNow(f, a, p);

			Delete(f->IpWaitList, p);
			Free(p->Packet->PacketData);
			FreePacket(p->Packet);
			Free(p);
		}

		ReleaseList(o);
	}
}

// Register in the ARP table
void L3InsertArpTable(L3IF *f, UINT ip, UCHAR *mac)
{
	L3ARPENTRY *a, t;
	// Validate arguments
	if (f == NULL || ip == 0 || ip == 0xffffffff || mac == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.IpAddress = ip;

	a = Search(f->ArpTable, &t);

	if (a == NULL)
	{
		// Since this is not registered, register this
		a = ZeroMalloc(sizeof(L3ARPENTRY));
		a->IpAddress = ip;
		Copy(a->MacAddress, mac, 6);
		Insert(f->ArpTable, a);
	}

	// Extend the expiration date
	a->Expire = Tick64() + ARP_ENTRY_EXPIRES;

	// Send waiting IP packets
	L3SendWaitingIp(f, mac, ip, a);
}

// Function to be called when the ARP resolved
void L3KnownArp(L3IF *f, UINT ip, UCHAR *mac)
{
	L3ARPWAIT t, *w;
	// Validate arguments
	if (f == NULL || ip == 0 || ip == 0xffffffff || mac == NULL)
	{
		return;
	}

	// Delete an ARP query entry to this IP address
	Zero(&t, sizeof(t));
	t.IpAddress = ip;
	w = Search(f->IpWaitList, &t);
	if (w != NULL)
	{
		Delete(f->IpWaitList, w);
		Free(w);
	}

	// Register in the ARP table
	L3InsertArpTable(f, ip, mac);
}

// Issue an ARP query
void L3SendArp(L3IF *f, UINT ip)
{
	L3ARPWAIT t, *w;
	// Validate arguments
	if (f == NULL || ip == 0 || ip == 0xffffffff)
	{
		return;
	}

	// Examine whether it has not already registered
	Zero(&t, sizeof(t));
	t.IpAddress = ip;
	w = Search(f->ArpWaitTable, &t);

	if (w != NULL)
	{
		// Do not do anything because it is already registered in the waiting list
		return;
	}
	else
	{
		// Register in the waiting list newly
		w = ZeroMalloc(sizeof(L3ARPWAIT));
		w->Expire = Tick64() + ARP_REQUEST_GIVEUP;
		w->IpAddress = ip;
		Insert(f->ArpWaitTable, w);
	}
}

// Received an ARP request
void L3RecvArpRequest(L3IF *f, PKT *p)
{
	ARPV4_HEADER *a;
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return;
	}

	a = p->L3.ARPv4Header;

	L3KnownArp(f, a->SrcIP, a->SrcAddress);

	if (a->TargetIP == f->IpAddress)
	{
		// Respond only if the ARP packet addressed to myself
		L3SendArpResponseNow(f, a->SrcAddress, a->SrcIP, f->IpAddress);
	}
}

// Received an ARP response
void L3RecvArpResponse(L3IF *f, PKT *p)
{
	ARPV4_HEADER *a;
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return;
	}

	a = p->L3.ARPv4Header;

	L3KnownArp(f, a->SrcIP, a->SrcAddress);
}

// Received an ARP packet
void L3RecvArp(L3IF *f, PKT *p)
{
	ARPV4_HEADER *a;
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return;
	}

	a = p->L3.ARPv4Header;

	if (Endian16(a->HardwareType) != ARP_HARDWARE_TYPE_ETHERNET ||
		Endian16(a->ProtocolType) != MAC_PROTO_IPV4 ||
		a->HardwareSize != 6 || a->ProtocolSize != 4)
	{
		return;
	}
	if (Cmp(a->SrcAddress, p->MacAddressSrc, 6) != 0)
	{
		return;
	}

	switch (Endian16(a->Operation))
	{
	case ARP_OPERATION_REQUEST:
		// ARP request arrives
		L3RecvArpRequest(f, p);
		break;

	case ARP_OPERATION_RESPONSE:
		// ARP response arrives
		L3RecvArpResponse(f, p);
		break;
	}
}

// Send an IP packet
void L3SendIp(L3IF *f, L3PACKET *p)
{
	L3ARPENTRY *a = NULL;
	bool broadcast = false;
	IPV4_HEADER *ip;
	bool for_me = false;
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return;
	}
	if (p->Packet->TypeL3 != L3_IPV4)
	{
		return;
	}

	ip = p->Packet->L3.IPv4Header;

	// Determining whether it's a broadcast
	if (p->NextHopIp == 0xffffffff ||
		((p->NextHopIp & f->SubnetMask) == (f->IpAddress & f->SubnetMask)) &&
		((p->NextHopIp & (~f->SubnetMask)) == (~f->SubnetMask)))
	{
		broadcast = true;
	}

	if (broadcast == false && ip->DstIP == f->IpAddress)
	{
		// me?
	}
	else if (broadcast == false)
	{
		// Examine whether the ARP entry contains this in the case of unicast
		a = L3SearchArpTable(f, p->NextHopIp);

		if (a == NULL)
		{
			// Since It is not in the ARP table,
			// insert it into the IP waiting list without sending immediately
			p->Expire = Tick64() + IP_WAIT_FOR_ARP_TIMEOUT;

			Insert(f->IpWaitList, p);

			// Issue an ARP query
			L3SendArp(f, p->NextHopIp);
			return;
		}
	}

	if (for_me == false)
	{
		// Send the IP packet
		L3SendIpNow(f, a, p);
	}

	// Release the packet
	Free(p->Packet->PacketData);
	FreePacket(p->Packet);
	Free(p);
}

// Send the IP packet immediately
void L3SendIpNow(L3IF *f, L3ARPENTRY *a, L3PACKET *p)
{
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return;
	}

	L3SendL2Now(f, a != NULL ? a->MacAddress : broadcast, f->MacAddress, Endian16(p->Packet->MacHeader->Protocol),
		p->Packet->L3.PointerL3, p->Packet->PacketSize - sizeof(MAC_HEADER));
}

// Search in the ARP table
L3ARPENTRY *L3SearchArpTable(L3IF *f, UINT ip)
{
	L3ARPENTRY *e, t;
	// Validate arguments
	if (f == NULL || ip == 0 || ip == 0xffffffff)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	t.IpAddress = ip;

	e = Search(f->ArpTable, &t);

	return e;
}

// Send an ARP request packet
void L3SendArpRequestNow(L3IF *f, UINT dest_ip)
{
	ARPV4_HEADER arp;
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	// Build an ARP header
	arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
	arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
	arp.HardwareSize = 6;
	arp.ProtocolSize = 4;
	arp.Operation = Endian16(ARP_OPERATION_REQUEST);
	Copy(arp.SrcAddress, f->MacAddress, 6);
	arp.SrcIP = f->IpAddress;
	Zero(&arp.TargetAddress, 6);
	arp.TargetIP = dest_ip;

	// Transmission
	L3SendL2Now(f, broadcast, f->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(arp));
}

// Send an ARP response packet
void L3SendArpResponseNow(L3IF *f, UCHAR *dest_mac, UINT dest_ip, UINT src_ip)
{
	ARPV4_HEADER arp;
	// Validate arguments
	if (f == NULL || dest_mac == NULL)
	{
		return;
	}

	// Build a header
	arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
	arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
	arp.HardwareSize = 6;
	arp.ProtocolSize = 4;
	arp.Operation = Endian16(ARP_OPERATION_RESPONSE);
	Copy(arp.SrcAddress, f->MacAddress, 6);
	Copy(arp.TargetAddress, dest_mac, 6);
	arp.SrcIP = src_ip;
	arp.TargetIP = dest_ip;

	// Transmission
	L3SendL2Now(f, dest_mac, f->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(arp));
}

// Generate a MAC address of the interface
void L3GenerateMacAddress(L3IF *f)
{
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	b = NewBuf();
	WriteBuf(b, f->Switch->Name, StrLen(f->Switch->Name));
	WriteBuf(b, f->HubName, StrLen(f->HubName));
	WriteBuf(b, &f->IpAddress, sizeof(f->IpAddress));

	GenMacAddress(f->MacAddress);
	Hash(hash, b->Buf, b->Size, true);
	Copy(f->MacAddress + 2, hash, 4);
	f->MacAddress[1] = 0xA3;
	FreeBuf(b);
}

// Send an L2 packet immediately
void L3SendL2Now(L3IF *f, UCHAR *dest_mac, UCHAR *src_mac, USHORT protocol, void *data, UINT size)
{
	UCHAR *buf;
	MAC_HEADER *mac_header;
	PKT *p;
	// Validate arguments
	if (f == NULL || dest_mac == NULL || src_mac == NULL || data == NULL)
	{
		return;
	}

	// Buffer creation
	buf = Malloc(MAC_HEADER_SIZE + size);

	// MAC header
	mac_header = (MAC_HEADER *)&buf[0];
	Copy(mac_header->DestAddress, dest_mac, 6);
	Copy(mac_header->SrcAddress, src_mac, 6);
	mac_header->Protocol = Endian16(protocol);

	// Copy data
	Copy(&buf[sizeof(MAC_HEADER)], data, size);

	// Size
	size += sizeof(MAC_HEADER);

	// Packet generation
	p = ZeroMalloc(sizeof(PKT));
	p->PacketData = buf;
	p->PacketSize = size;

	// Add to the queue
	InsertQueue(f->SendQueue, p);
}

// Polling for the ARP resolution waiting list
void L3PollingArpWaitTable(L3IF *f)
{
	UINT i;
	LIST *o = NULL;
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(f->ArpWaitTable);i++)
	{
		L3ARPWAIT *w = LIST_DATA(f->ArpWaitTable, i);

		if (w->Expire <= Tick64())
		{
			// The ARP request entry is expired
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Insert(o, w);
		}
		else if ((w->LastSentTime + ARP_REQUEST_TIMEOUT) <= Tick64())
		{
			// Send a next ARP request packet
			w->LastSentTime = Tick64();

			L3SendArpRequestNow(f, w->IpAddress);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			L3ARPWAIT *w = LIST_DATA(o, i);

			Delete(f->ArpWaitTable, w);
			Free(w);
		}

		ReleaseList(o);
	}
}

// Clear old ARP table entries
void L3DeleteOldArpTable(L3IF *f)
{
	UINT i;
	LIST *o = NULL;
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	if ((f->LastDeleteOldArpTable + ARP_ENTRY_POLLING_TIME) > Tick64())
	{
		return;
	}
	f->LastDeleteOldArpTable = Tick64();

	for (i = 0;i < LIST_NUM(f->ArpTable);i++)
	{
		L3ARPENTRY *a = LIST_DATA(f->ArpTable, i);

		if (a->Expire <= Tick64())
		{
			// Expired
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Insert(o, a);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			L3ARPENTRY *a = LIST_DATA(o, i);

			Delete(f->ArpTable, a);
			Free(a);
		}

		ReleaseList(o);
	}
}

// Clear the IP waiting list
void L3DeleteOldIpWaitList(L3IF *f)
{
	UINT i;
	LIST *o = NULL;
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(f->IpWaitList);i++)
	{
		L3PACKET *p = LIST_DATA(f->IpWaitList, i);

		if (p->Expire <= Tick64())
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Insert(o, p);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			L3PACKET *p = LIST_DATA(o, i);

			Delete(f->IpWaitList, p);

			Free(p->Packet->PacketData);
			FreePacket(p->Packet);
			Free(p);
		}

		ReleaseList(o);
	}
}

// Beacon transmission
void L3PollingBeacon(L3IF *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	if (f->LastBeaconSent == 0 ||
		(f->LastBeaconSent + BEACON_SEND_INTERVAL) <= Tick64())
	{
		UINT dest_ip;
		UCHAR *udp_buf;
		UINT udp_buf_size;
		ARPV4_HEADER arp;
		IPV4_HEADER *ip;
		UDP_HEADER *udp;
		static char beacon_str[] =
			"PacketiX VPN Virtual Layer-3 Switch Beacon";

		// Send an UDP
		dest_ip = (f->IpAddress & f->SubnetMask) | (~f->SubnetMask);
		udp_buf_size = sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + sizeof(beacon_str);
		udp_buf = ZeroMalloc(udp_buf_size);

		ip = (IPV4_HEADER *)udp_buf;
		udp = (UDP_HEADER *)(udp_buf + sizeof(IPV4_HEADER));
		udp->DstPort = Endian16(7);
		udp->SrcPort = Endian16(7);
		udp->PacketLength = Endian16(sizeof(UDP_HEADER) + sizeof(beacon_str));

		Copy(udp_buf + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER), beacon_str, sizeof(beacon_str));

		udp->Checksum = CalcChecksumForIPv4(f->IpAddress, dest_ip, 0x11, udp, sizeof(UDP_HEADER) + sizeof(beacon_str), 0);

		ip->DstIP = dest_ip;
		IPV4_SET_VERSION(ip, 4);
		IPV4_SET_HEADER_LEN(ip, (IP_HEADER_SIZE / 4));
		ip->TypeOfService = DEFAULT_IP_TOS;
		ip->TotalLength = Endian16((USHORT)(udp_buf_size));
		ip->TimeToLive = DEFAULT_IP_TTL;
		ip->Protocol = IP_PROTO_UDP;
		ip->SrcIP = f->IpAddress;
		ip->Checksum = IpChecksum(ip, IP_HEADER_SIZE);

		L3SendL2Now(f, broadcast, f->MacAddress, MAC_PROTO_IPV4, udp_buf, udp_buf_size);

		Free(udp_buf);

		// Build the ARP header
		arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
		arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
		arp.HardwareSize = 6;
		arp.ProtocolSize = 4;
		arp.Operation = Endian16(ARP_OPERATION_RESPONSE);
		Copy(arp.SrcAddress, f->MacAddress, 6);
		arp.SrcIP = f->IpAddress;
		arp.TargetAddress[0] =
			arp.TargetAddress[1] =
			arp.TargetAddress[2] =
			arp.TargetAddress[3] =
			arp.TargetAddress[4] =
			arp.TargetAddress[5] = 0xff;
		arp.TargetIP = dest_ip;

		// Transmission
		L3SendL2Now(f, broadcast, f->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(arp));

		f->LastBeaconSent = Tick64();
	}
}

// Polling process
void L3Polling(L3IF *f)
{
	L3SW *s;
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	s = f->Switch;

	// Lock the entire switch in the middle of the polling process
	Lock(s->lock);
	{
		// Beacon transmission
		L3PollingBeacon(f);

		// Process the IP queue
		L3PollingIpQueue(f);

		// Clear old ARP table entries
		L3DeleteOldArpTable(f);

		// Polling ARP resolution waiting list
		L3PollingArpWaitTable(f);

		// Clear the IP waiting list
		L3DeleteOldIpWaitList(f);
	}
	Unlock(s->lock);
}

// Get the next packet
UINT L3GetNextPacket(L3IF *f, void **data)
{
	UINT ret = 0;
	// Validate arguments
	if (f == NULL || data == NULL)
	{
		return 0;
	}

START:
	// Examine the send queue
	LockQueue(f->SendQueue);
	{
		PKT *p = GetNext(f->SendQueue);

		if (p != NULL)
		{
			// There is a packet
			ret = p->PacketSize;
			*data = p->PacketData;
			// Packet structure may be discarded
			Free(p);
		}
	}
	UnlockQueue(f->SendQueue);

	if (ret == 0)
	{
		// Polling process
		L3Polling(f);

        // Examine whether a new packet is queued for results of the polling process
		if (f->SendQueue->num_item != 0)
		{
			// Get the packet immediately if it's in the queue
			goto START;
		}
	}

	return ret;
}

// Determine the packet destined for the specified IP address should be sent to which interface
L3IF *L3GetNextIf(L3SW *s, UINT ip, UINT *next_hop)
{
	UINT i;
	L3IF *f;
	UINT next_hop_ip = 0;
	// Validate arguments
	if (s == NULL || ip == 0 || ip == 0xffffffff)
	{
		return NULL;
	}

	f = NULL;

	// Examine whether the specified IP address is contained
	// in the networks which each interfaces belong to
	for (i = 0;i < LIST_NUM(s->IfList);i++)
	{
		L3IF *ff = LIST_DATA(s->IfList, i);

		if ((ff->IpAddress & ff->SubnetMask) == (ip & ff->SubnetMask))
		{
			f = ff;
			next_hop_ip = ip;
			break;
		}
	}

	if (f == NULL)
	{
		// Find the routing table if it's not found
		L3TABLE *t = L3GetBestRoute(s, ip);

		if (t == NULL)
		{
			// Still not found
			return NULL;
		}
		else
		{
			// Find the interface with the IP address of the router of
			// NextHop of the found route
			for (i = 0;i < LIST_NUM(s->IfList);i++)
			{
				L3IF *ff = LIST_DATA(s->IfList, i);

				if ((ff->IpAddress & ff->SubnetMask) == (t->GatewayAddress & ff->SubnetMask))
				{
					f = ff;
					next_hop_ip = t->GatewayAddress;
					break;
				}
			}
		}
	}

	if (f == NULL)
	{
		// Destination interface was unknown after all
		return NULL;
	}

	if (next_hop != NULL)
	{
		*next_hop = next_hop_ip;
	}

	return f;
}

// Get the best routing table entry for the specified IP address
L3TABLE *L3GetBestRoute(L3SW *s, UINT ip)
{
	UINT i;
	UINT max_mask = 0;
	UINT min_metric = INFINITE;
	L3TABLE *ret = NULL;
	// Validate arguments
	if (s == NULL || ip == 0)
	{
		return NULL;
	}

	// 1st condition: Choose the one which have the largest subnet mask
	// 2nd condition: Choose the one which have the smallest metric
	for (i = 0;i < LIST_NUM(s->TableList);i++)
	{
		L3TABLE *t = LIST_DATA(s->TableList, i);

		if ((t->NetworkAddress & t->SubnetMask) == (ip & t->SubnetMask))
		{
			if (t->SubnetMask >= max_mask)
			{
				max_mask = t->SubnetMask;
				if (min_metric >= t->Metric)
				{
					min_metric = t->Metric;
					ret = t;
				}
			}
		}
	}

	return ret;
}

// Initialize the Layer-3 interface
void L3InitInterface(L3IF *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	// MAC address generation
	L3GenerateMacAddress(f);

	// List generation
	f->ArpTable = NewList(CmpL3ArpEntry);
	f->ArpWaitTable = NewList(CmpL3ArpWaitTable);
	f->IpPacketQueue = NewQueue();
	f->IpWaitList = NewList(NULL);
	f->SendQueue = NewQueue();
}

// Release the Layer-3 interface
void L3FreeInterface(L3IF *f)
{
	UINT i;
	L3PACKET *p;
	PKT *pkt;
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(f->ArpTable);i++)
	{
		L3ARPENTRY *a = LIST_DATA(f->ArpTable, i);
		Free(a);
	}
	ReleaseList(f->ArpTable);
	f->ArpTable = NULL;

	for (i = 0;i < LIST_NUM(f->ArpWaitTable);i++)
	{
		L3ARPWAIT *w = LIST_DATA(f->ArpWaitTable, i);
		Free(w);
	}
	ReleaseList(f->ArpWaitTable);
	f->ArpWaitTable = NULL;

	while (p = GetNext(f->IpPacketQueue))
	{
		Free(p->Packet->PacketData);
		FreePacket(p->Packet);
		Free(p);
	}
	ReleaseQueue(f->IpPacketQueue);
	f->IpPacketQueue = NULL;

	for (i = 0;i < LIST_NUM(f->IpWaitList);i++)
	{
		L3PACKET *p = LIST_DATA(f->IpWaitList, i);
		Free(p->Packet->PacketData);
		FreePacket(p->Packet);
		Free(p);
	}
	ReleaseList(f->IpWaitList);
	f->IpWaitList = NULL;

	while (pkt = GetNext(f->SendQueue))
	{
		Free(pkt->PacketData);
		FreePacket(pkt);
	}
	ReleaseQueue(f->SendQueue);
	f->SendQueue = NULL;
}

// Layer-3 interface thread
void L3IfThread(THREAD *t, void *param)
{
	L3IF *f;
	CONNECTION *c;
	SESSION *s;
	POLICY *policy;
	char tmp[MAX_SIZE];
	char name[MAX_SIZE];
	char username[MAX_SIZE];
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	f = (L3IF *)param;

	StrCpy(username, sizeof(username), L3_USERNAME);
	if (f->Switch != NULL)
	{
		StrCat(username, sizeof(username), f->Switch->Name);
	}

	// Create a connection
	c = NewServerConnection(f->Switch->Cedar, NULL, t);
	c->Protocol = CONNECTION_HUB_LAYER3;

	// Create a Session
	policy = ClonePolicy(GetDefaultPolicy());
	// Not to limit the number of broadcast by policy
	policy->NoBroadcastLimiter = true;
	s = NewServerSession(f->Switch->Cedar, c, f->Hub, username, policy);
	c->Session = s;

	ReleaseConnection(c);

	// Determine the name of the session
	GetMachineHostName(tmp, sizeof(tmp));
	if (f->Switch->Cedar->Server->ServerType == SERVER_TYPE_STANDALONE)
	{
		Format(name, sizeof(name), "SID-L3-%s-%u", f->Switch->Name, Inc(f->Hub->SessionCounter));
	}
	else
	{
		Format(name, sizeof(name), "SID-L3-%s-%s-%u", tmp, f->Switch->Name, Inc(f->Hub->SessionCounter));
	}
	ConvertSafeFileName(name, sizeof(name), name);
	StrUpper(name);

	Free(s->Name);
	s->Name = CopyStr(name);

	s->L3SwitchMode = true;
	s->L3If = f;

	if (s->Username != NULL)
	{
		Free(s->Username);
	}
	s->Username = CopyStr(username);

	StrCpy(s->UserNameReal, sizeof(s->UserNameReal), username);

	f->Session = s;
	AddRef(s->ref);

	// Notify the initialization completion
	NoticeThreadInit(t);

	// Session main process
	SessionMain(s);

	// Release the session
	ReleaseSession(s);
}

// Initialize all Layer-3 interfaces
void L3InitAllInterfaces(L3SW *s)
{
	UINT i;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->IfList);i++)
	{
		L3IF *f = LIST_DATA(s->IfList, i);
		THREAD *t;

		L3InitInterface(f);

		f->Hub = GetHub(s->Cedar, f->HubName);
		t = NewThread(L3IfThread, f);
		WaitThreadInit(t);
		ReleaseThread(t);
	}
}

// Release all Layer-3 interfaces
void L3FreeAllInterfaces(L3SW *s)
{
	UINT i;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->IfList);i++)
	{
		L3IF *f = LIST_DATA(s->IfList, i);

		ReleaseHub(f->Hub);
		f->Hub = NULL;
		ReleaseSession(f->Session);
		f->Session = NULL;

		L3FreeInterface(f);
	}
}

// Layer-3 test
void L3Test(SERVER *s)
{
	L3SW *ss = L3AddSw(s->Cedar, "TEST");
	L3AddIf(ss, "DEFAULT", 0x0101a8c0, 0x00ffffff);
	L3AddIf(ss, "DEFAULT2", 0x0102a8c0, 0x00ffffff);
	L3SwStart(ss);
	ReleaseL3Sw(ss);
}

// Layer-3 switch thread
void L3SwThread(THREAD *t, void *param)
{
	L3SW *s;
	bool shutdown_now = false;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	s = (L3SW *)param;

	s->Active = true;

	NoticeThreadInit(t);

	// Operation start
	SLog(s->Cedar, "L3_SWITCH_START", s->Name);

	while (s->Halt == false)
	{
		if (s->Online == false)
		{
			// Because the L3 switch is off-line now,
			// attempt to make it on-line periodically
			LockList(s->Cedar->HubList);
			{
				Lock(s->lock);
				{
					UINT i;
					UINT n = 0;
					bool all_exists = true;
					if (LIST_NUM(s->IfList) == 0)
					{
						// Don't operate if there is no interface
						all_exists = false;
					}
					for (i = 0;i < LIST_NUM(s->IfList);i++)
					{
						L3IF *f = LIST_DATA(s->IfList, i);
						HUB *h = GetHub(s->Cedar, f->HubName);

						if (h != NULL)
						{
							if (h->Offline || h->Type == HUB_TYPE_FARM_DYNAMIC)
							{
								all_exists = false;
							}
							else
							{
								n++;
							}
							ReleaseHub(h);
						}
						else
						{
							all_exists = false;
						}
					}

					if (all_exists && n >= 1)
					{
						// Start the operation because all Virtual HUBs for
						// interfaces are enabled
						SLog(s->Cedar, "L3_SWITCH_ONLINE", s->Name);
						L3InitAllInterfaces(s);
						s->Online = true;
					}
				}
				Unlock(s->lock);
			}
			UnlockList(s->Cedar->HubList);
		}
		else
		{
			// Examine periodically whether all sessions terminated
			UINT i;
			bool any_halted = false;
			LIST *o = NULL;

SHUTDOWN:

			Lock(s->lock);
			{
				for (i = 0;i < LIST_NUM(s->IfList);i++)
				{
					L3IF *f = LIST_DATA(s->IfList, i);
					if (f->Session->Halt || f->Hub->Offline != false)
					{
						any_halted = true;
						break;
					}
				}

				if (shutdown_now)
				{
					any_halted = true;
				}

				if (any_halted)
				{
					SLog(s->Cedar, "L3_SWITCH_OFFLINE", s->Name);
					o = NewListFast(NULL);
					// If there is any terminated session, terminate all sessions
					for (i = 0;i < LIST_NUM(s->IfList);i++)
					{
						L3IF *f = LIST_DATA(s->IfList, i);
						Insert(o, f->Session);
					}

					// Restore to the offline
					s->Online = false;
				}
			}
			Unlock(s->lock);

			if (o != NULL)
			{
				UINT i;
				for (i = 0;i < LIST_NUM(o);i++)
				{
					SESSION *s = LIST_DATA(o, i);
					StopSession(s);
				}
				L3FreeAllInterfaces(s);
				ReleaseList(o);
				o = NULL;
			}
		}

		SleepThread(50);
	}

	if (s->Online != false)
	{
		shutdown_now = true;
		goto SHUTDOWN;
	}

	// Stop the operation
	SLog(s->Cedar, "L3_SWITCH_STOP", s->Name);
}

// Start a Layer-3 switch
void L3SwStart(L3SW *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Lock(s->lock);
	{
		if (s->Active == false)
		{
			// Start if there is registered interface
			if (LIST_NUM(s->IfList) >= 1)
			{
				s->Halt = false;

				// Create a thread
				s->Thread = NewThread(L3SwThread, s);
				WaitThreadInit(s->Thread);
			}
		}
	}
	Unlock(s->lock);
}

// Stop the Layer-3 switch
void L3SwStop(L3SW *s)
{
	THREAD *t = NULL;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Lock(s->lock);
	{
		if (s->Active == false)
		{
			Unlock(s->lock);
			return;
		}

		s->Halt = true;

		t = s->Thread;

		s->Active = false;
	}
	Unlock(s->lock);

	WaitThread(t, INFINITE);
	ReleaseThread(t);
}

// Add a Layer-3 switch
L3SW *L3AddSw(CEDAR *c, char *name)
{
	L3SW *s = NULL;
	// Validate arguments
	if (c == NULL || name == NULL)
	{
		return NULL;
	}

	LockList(c->L3SwList);
	{
		s = L3GetSw(c, name);

		if (s == NULL)
		{
			s = NewL3Sw(c, name);

			Insert(c->L3SwList, s);

			AddRef(s->ref);
		}
		else
		{
			ReleaseL3Sw(s);
			s = NULL;
		}
	}
	UnlockList(c->L3SwList);

	return s;
}

// Delete the Layer-3 switch
bool L3DelSw(CEDAR *c, char *name)
{
	L3SW *s;
	bool ret = false;
	// Validate arguments
	if (c == NULL || name == NULL)
	{
		return false;
	}

	LockList(c->L3SwList);
	{
		s = L3GetSw(c, name);

		if (s != NULL)
		{
			// Stop and delete
			L3SwStop(s);
			Delete(c->L3SwList, s);
			ReleaseL3Sw(s);
			ReleaseL3Sw(s);

			ret = true;
		}
	}
	UnlockList(c->L3SwList);

	return ret;
}


// Delete the routing table
bool L3DelTable(L3SW *s, L3TABLE *tbl)
{
	bool ret = false;
	// Validate arguments
	if (s == NULL || tbl == NULL)
	{
		return false;
	}

	Lock(s->lock);
	{
		if (s->Active == false)
		{
			L3TABLE *t = Search(s->TableList, tbl);

			if (t != NULL)
			{
				Delete(s->TableList, t);
				Free(t);

				ret = true;
			}
		}
	}
	Unlock(s->lock);

	return ret;
}

// Add to the routing table
bool L3AddTable(L3SW *s, L3TABLE *tbl)
{
	bool ret = false;
	// Validate arguments
	if (s == NULL || tbl == NULL)
	{
		return false;
	}

	if (tbl->Metric == 0 || tbl->GatewayAddress == 0 || tbl->GatewayAddress == 0xffffffff)
	{
		return false;
	}

	Lock(s->lock);
	{
		if (LIST_NUM(s->TableList) >= GetServerCapsInt(s->Cedar->Server, "i_max_l3_table"))
		{
			// Too many
		}
		else
		{
			// Create
			if (s->Active == false)
			{
				if (Search(s->TableList, tbl) == NULL)
				{
					L3TABLE *t = ZeroMalloc(sizeof(L3TABLE));

					Copy(t, tbl, sizeof(L3TABLE));

					Insert(s->TableList, t);

					ret = true;
				}
			}
		}
	}
	Unlock(s->lock);

	return ret;
}

// Get the L3 switch
L3SW *L3GetSw(CEDAR *c, char *name)
{
	L3SW t, *s;
	// Validate arguments
	if (c == NULL || name == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.Name, sizeof(t.Name), name);

	LockList(c->L3SwList);
	{
		s = Search(c->L3SwList, &t);
	}
	UnlockList(c->L3SwList);

	if (s != NULL)
	{
		AddRef(s->ref);
	}

	return s;
}

// Get the interface that is connected to the specified Virtual HUB from the L3 switch
L3IF *L3SearchIf(L3SW *s, char *hubname)
{
	L3IF t, *f;
	// Validate arguments
	if (s == NULL || hubname == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), hubname);

	f = Search(s->IfList, &t);

	return f;
}

// Delete the interface
bool L3DelIf(L3SW *s, char *hubname)
{
	L3IF *f;
	bool ret = false;
	// Validate arguments
	if (s == NULL || hubname == NULL)
	{
		return false;
	}

	Lock(s->lock);
	{
		if (s->Active == false)
		{
			f = L3SearchIf(s, hubname);

			if (f != NULL)
			{
				// Remove
				Delete(s->IfList, f);
				Free(f);

				ret = true;
			}
		}
	}
	Unlock(s->lock);

	return ret;
}

// Add an interface
bool L3AddIf(L3SW *s, char *hubname, UINT ip, UINT subnet)
{
	L3IF *f;
	bool ret = false;
	// Validate arguments
	if (s == NULL || hubname == NULL || IsSafeStr(hubname) == false ||
		ip == 0 || ip == 0xffffffff)
	{
		return false;
	}

	Lock(s->lock);
	{
		if (LIST_NUM(s->TableList) >= GetServerCapsInt(s->Cedar->Server, "i_max_l3_if"))
		{
			// Too many
		}
		else
		{
			if (s->Active == false)
			{
				// Examine whether the interface is already in the same Virtual HUB
				if (L3SearchIf(s, hubname) == NULL)
				{
					// Add
					f = ZeroMalloc(sizeof(L3IF));

					f->Switch = s;
					StrCpy(f->HubName, sizeof(f->HubName), hubname);
					f->IpAddress = ip;
					f->SubnetMask = subnet;

					Insert(s->IfList, f);

					ret = true;
				}
			}
		}
	}
	Unlock(s->lock);

	return ret;
}

// Clean-up the L3 switch
void CleanupL3Sw(L3SW *s)
{
	UINT i;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->IfList);i++)
	{
		L3IF *f = LIST_DATA(s->IfList, i);
		Free(f);
	}
	ReleaseList(s->IfList);

	for (i = 0;i < LIST_NUM(s->TableList);i++)
	{
		L3TABLE *t = LIST_DATA(s->TableList, i);
		Free(t);
	}
	ReleaseList(s->TableList);

	DeleteLock(s->lock);
	Free(s);
}

// Release the L3 switch
void ReleaseL3Sw(L3SW *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		CleanupL3Sw(s);
	}
}

// Create a new L3 switch
L3SW *NewL3Sw(CEDAR *c, char *name)
{
	L3SW *o;
	// Validate arguments
	if (c == NULL || name == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(L3SW));

	StrCpy(o->Name, sizeof(o->Name), name);

	o->lock = NewLock();
	o->ref = NewRef();
	o->Cedar = c;
	o->Active = false;

	o->IfList = NewList(CmpL3If);
	o->TableList = NewList(CmpL3Table);

	return o;
}

// Stop all L3 switches in the Cedar
void L3FreeAllSw(CEDAR *c)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	LockList(c->L3SwList);
	{
		for (i = 0;i < LIST_NUM(c->L3SwList);i++)
		{
			L3SW *s = LIST_DATA(c->L3SwList, i);
			Insert(o, CopyStr(s->Name));
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			char *name = LIST_DATA(o, i);

			L3DelSw(c, name);

			Free(name);
		}

		ReleaseList(o);
	}
	UnlockList(c->L3SwList);
}

// Stop the L3 switch function of the Cedar
void FreeCedarLayer3(CEDAR *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	ReleaseList(c->L3SwList);
	c->L3SwList = NULL;
}

// Start the L3 switch function of the Cedar
void InitCedarLayer3(CEDAR *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	c->L3SwList = NewList(CmpL3Sw);
}

// Interface comparison function
int CmpL3If(void *p1, void *p2)
{
	L3IF *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(L3IF **)p1;
	f2 = *(L3IF **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}

	return StrCmpi(f1->HubName, f2->HubName);
}

// Routing table entry comparison function
int CmpL3Table(void *p1, void *p2)
{
	L3TABLE *t1, *t2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	t1 = *(L3TABLE **)p1;
	t2 = *(L3TABLE **)p2;
	if (t1 == NULL || t2 == NULL)
	{
		return 0;
	}

	if (t1->NetworkAddress > t2->NetworkAddress)
	{
		return 1;
	}
	else if (t1->NetworkAddress < t2->NetworkAddress)
	{
		return -1;
	}
	else if (t1->SubnetMask > t2->SubnetMask)
	{
		return 1;
	}
	else if (t1->SubnetMask < t2->SubnetMask)
	{
		return -1;
	}
	else if (t1->GatewayAddress > t2->GatewayAddress)
	{
		return 1;
	}
	else if (t1->GatewayAddress < t2->GatewayAddress)
	{
		return -1;
	}
	else if (t1->Metric > t2->Metric)
	{
		return 1;
	}
	else if (t1->Metric < t2->Metric)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// L3SW comparison function
int CmpL3Sw(void *p1, void *p2)
{
	L3SW *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(L3SW **)p1;
	s2 = *(L3SW **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	return StrCmpi(s1->Name, s2->Name);
}

// ARP waiting entry comparison function
int CmpL3ArpWaitTable(void *p1, void *p2)
{
	L3ARPWAIT *w1, *w2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	w1 = *(L3ARPWAIT **)p1;
	w2 = *(L3ARPWAIT **)p2;
	if (w1 == NULL || w2 == NULL)
	{
		return 0;
	}
	if (w1->IpAddress > w2->IpAddress)
	{
		return 1;
	}
	else if (w1->IpAddress < w2->IpAddress)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// ARP entries comparison function
int CmpL3ArpEntry(void *p1, void *p2)
{
	L3ARPENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(L3ARPENTRY **)p1;
	e2 = *(L3ARPENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	if (e1->IpAddress > e2->IpAddress)
	{
		return 1;
	}
	else if (e1->IpAddress < e2->IpAddress)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
