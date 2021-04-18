// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Virtual.c
// User-mode virtual host program

#include "Virtual.h"

#include "BridgeUnix.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Hub.h"
#include "IPC.h"
#include "NativeStack.h"
#include "Server.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

static UCHAR broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static char v_vgs_hostname[256] = {0};

static char secure_nat_target_hostname[MAX_SIZE] = {0};

// Specify the destination host name to be used for connectivity testing in SecureNAT
void NnSetSecureNatTargetHostname(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	StrCpy(secure_nat_target_hostname, sizeof(secure_nat_target_hostname), name);
}

// Delete the oldest NAT session if necessary
void NnDeleteOldestNatSessionIfNecessary(NATIVE_NAT *t, UINT ip, UINT protocol)
{
	UINT current_num;
	UINT max_sessions = 0;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->v->HubOption != NULL)
	{
		HUB_OPTION *o = t->v->HubOption;

		switch (protocol)
		{
		case NAT_TCP:
			max_sessions = o->SecureNAT_MaxTcpSessionsPerIp;
			break;

		case NAT_UDP:
			max_sessions = o->SecureNAT_MaxUdpSessionsPerIp;
			break;

		case NAT_ICMP:
			max_sessions = o->SecureNAT_MaxIcmpSessionsPerIp;
			break;
		}
	}

	if (max_sessions == 0)
	{
		return;
	}

	current_num = NnGetNumNatEntriesPerIp(t, ip, protocol);

	if (current_num >= max_sessions)
	{
		NnDeleteOldestNatSession(t, ip, protocol);
	}
}

// Delete the oldest NAT session
void NnDeleteOldestNatSession(NATIVE_NAT *t, UINT ip, UINT protocol)
{
	NATIVE_NAT_ENTRY *e;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	e = NnGetOldestNatEntryOfIp(t, ip, protocol);

	if (e != NULL)
	{
		NnDeleteSession(t, e);
	}
}

// Get the oldest NAT session
NATIVE_NAT_ENTRY *NnGetOldestNatEntryOfIp(NATIVE_NAT *t, UINT ip, UINT protocol)
{
	UINT i;
	NATIVE_NAT_ENTRY *oldest = NULL;
	UINT64 oldest_tick = 0xFFFFFFFFFFFFFFFFULL;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(t->NatTableForRecv->AllList); i++)
	{
		NATIVE_NAT_ENTRY *e = LIST_DATA(t->NatTableForRecv->AllList, i);

		if (e->SrcIp == ip)
		{
			if (e->Protocol == protocol)
			{
				if (e->LastCommTime <= oldest_tick)
				{
					oldest_tick = e->LastCommTime;
					oldest = e;
				}
			}
		}
	}

	return oldest;
}

// Get the number of NAT sessions per IP address
UINT NnGetNumNatEntriesPerIp(NATIVE_NAT *t, UINT src_ip, UINT protocol)
{
	UINT ret = 0;
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return 0;
	}

	for (i = 0; i < LIST_NUM(t->NatTableForRecv->AllList); i++)
	{
		NATIVE_NAT_ENTRY *e = LIST_DATA(t->NatTableForRecv->AllList, i);

		if (e->SrcIp == src_ip)
		{
			if (e->Protocol == protocol)
			{
				ret++;
			}
		}
	}

	return ret;
}

// Delete the old NAT sessions
void NnDeleteOldSessions(NATIVE_NAT *t)
{
	UINT i;
	LIST *o;
	UINT64 now;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	o = NULL;
	now = t->v->Now;

	for (i = 0; i < LIST_NUM(t->NatTableForSend->AllList); i++)
	{
		NATIVE_NAT_ENTRY *e = LIST_DATA(t->NatTableForSend->AllList, i);
		UINT64 timeout;

		if (e->Status == NAT_TCP_CONNECTED || e->Status == NAT_TCP_ESTABLISHED)
		{
			timeout = e->LastCommTime + (UINT64)(e->Protocol == NAT_TCP ? t->v->NatTcpTimeout : t->v->NatUdpTimeout);
		}
		else
		{
			timeout = e->LastCommTime + (UINT64)NN_TIMEOUT_FOR_UNESTBALISHED_TCP;
		}

		if (timeout < now)
		{
			// Time-out occurs
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Add(o, e);
		}
	}

	if (o != NULL)
	{
		for (i = 0; i < LIST_NUM(o); i++)
		{
			NATIVE_NAT_ENTRY *e = LIST_DATA(o, i);

			NnDeleteSession(t, e);
		}

		ReleaseList(o);
	}
}

// Delete the NAT entry
void NnDeleteSession(NATIVE_NAT *t, NATIVE_NAT_ENTRY *e)
{
	// Validate arguments
	if (t == NULL || e == NULL)
	{
		return;
	}

	switch (e->Protocol)
	{
	case NAT_TCP:
		// Send a RST to the client side
		SendTcp(t->v, e->DestIp, e->DestPort, e->SrcIp, e->SrcPort,
		        e->LastAck, e->LastSeq + (e->Status == NAT_TCP_CONNECTING ? 1 : 0), TCP_RST | TCP_ACK, 0, 0, NULL, 0);

		NLog(t->v, "LH_NAT_TCP_DELETED", e->Id);
		break;

	case NAT_UDP:
		NLog(t->v, "LH_NAT_UDP_DELETED", e->Id);
		break;

	case NAT_ICMP:
		Debug("NAT ICMP %u Deleted.\n", e->Id);
		break;
	}

	DeleteHash(t->NatTableForSend, e);
	DeleteHash(t->NatTableForRecv, e);

	Free(e);
}

// Poll the IP combining object
void NnPollingIpCombine(NATIVE_NAT *t)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	// Discard the old combining object
	o = NULL;
	for (i = 0; i < LIST_NUM(t->IpCombine); i++)
	{
		IP_COMBINE *c = LIST_DATA(t->IpCombine, i);

		if (c->Expire < t->v->Now)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Add(o, c);
		}
	}

	if (o != NULL)
	{
		for (i = 0; i < LIST_NUM(o); i++)
		{
			IP_COMBINE *c = LIST_DATA(o, i);

			// Remove from the list
			Delete(t->IpCombine, c);

			// Release the memory
			NnFreeIpCombine(t, c);
		}
		ReleaseList(o);
	}
}

// Combine the IP packet received to the IP combining object
void NnCombineIp(NATIVE_NAT *t, IP_COMBINE *c, UINT offset, void *data, UINT size, bool last_packet, UCHAR *head_ip_header_data, UINT head_ip_header_size)
{
	UINT i;
	IP_PART *p;
	UINT need_size;
	UINT data_size_delta;
	// Validate arguments
	if (c == NULL || data == NULL)
	{
		return;
	}

	// Check the size and offset
	if ((offset + size) > 65535)
	{
		// Do not process a packet larger than 64Kbytes
		return;
	}

	if (last_packet == false && c->Size != 0)
	{
		if ((offset + size) > c->Size)
		{
			// Do not process a packet larger than the packet size
			return;
		}
	}

	if (head_ip_header_data != NULL && head_ip_header_size >= sizeof(IPV4_HEADER))
	{
		if (c->HeadIpHeaderData == NULL)
		{
			c->HeadIpHeaderData = Clone(head_ip_header_data, head_ip_header_size);
			c->HeadIpHeaderDataSize = head_ip_header_size;
		}
	}

	need_size = offset + size;
	data_size_delta = c->DataReserved;
	// Ensure sufficient if the buffer is insufficient
	while (c->DataReserved < need_size)
	{
		c->DataReserved = c->DataReserved * 4;
		c->Data = ReAlloc(c->Data, c->DataReserved);
	}
	data_size_delta = c->DataReserved - data_size_delta;
	t->CurrentIpQuota += data_size_delta;

	// Overwrite the data into the buffer
	Copy(((UCHAR *)c->Data) + offset, data, size);

	if (last_packet)
	{
		// If No More Fragment packet arrives, the size of this datagram is finalized
		c->Size = offset + size;
	}

	// Check the overlap between the region which is represented by the offset and size of the
	// existing received list and the region which is represented by the offset and size
	for (i = 0; i < LIST_NUM(c->IpParts); i++)
	{
		UINT moving_size;
		IP_PART *p = LIST_DATA(c->IpParts, i);

		// Check the overlapping between the existing area and head area
		if ((p->Offset <= offset) && ((p->Offset + p->Size) > offset))
		{
			// Compress behind the offset of this packet since a duplication is
			// found in the first part with the existing packet and this packet

			if ((offset + size) <= (p->Offset + p->Size))
			{
				// This packet is buried in the existing packet
				size = 0;
			}
			else
			{
				// Retral region is not overlapped
				moving_size = p->Offset + p->Size - offset;
				offset += moving_size;
				size -= moving_size;
			}
		}
		if ((p->Offset < (offset + size)) && ((p->Offset + p->Size) >= (offset + size)))
		{
			// Compress the size of this packet forward because a duplication is
			// found between the posterior portion the existing packet and this packet

			moving_size = p->Offset + p->Size - offset - size;
			size -= moving_size;
		}

		if ((p->Offset >= offset) && ((p->Offset + p->Size) <= (offset + size)))
		{
			// This packet was overwritten to completely hunched over a existing packet
			p->Size = 0;
		}
	}

	if (size != 0)
	{
		// Register this packet
		p = ZeroMalloc(sizeof(IP_PART));

		p->Offset = offset;
		p->Size = size;

		Add(c->IpParts, p);
	}

	if (c->Size != 0)
	{
		// Get the total size of the data portion list already received
		UINT total_size = 0;
		UINT i;

		for (i = 0; i < LIST_NUM(c->IpParts); i++)
		{
			IP_PART *p = LIST_DATA(c->IpParts, i);

			total_size += p->Size;
		}

		if (total_size == c->Size)
		{
			// Received whole of the IP packet
			//Debug("Combine: %u\n", total_size);
			NnIpReceived(t, c->SrcIP, c->DestIP, c->Protocol, c->Data, c->Size, c->Ttl,
			             c->HeadIpHeaderData, c->HeadIpHeaderDataSize, c->MaxL3Size);

			// Release the combining object
			NnFreeIpCombine(t, c);

			// Remove from the combining object list
			Delete(t->IpCombine, c);
		}
	}
}

// Release the IP combining object
void NnFreeIpCombine(NATIVE_NAT *t, IP_COMBINE *c)
{
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Release the data
	t->CurrentIpQuota -= c->DataReserved;
	Free(c->Data);

	// Release the partial list
	for (i = 0; i < LIST_NUM(c->IpParts); i++)
	{
		IP_PART *p = LIST_DATA(c->IpParts, i);

		Free(p);
	}

	Free(c->HeadIpHeaderData);

	ReleaseList(c->IpParts);
	Free(c);
}

// Search the IP combining list
IP_COMBINE *NnSearchIpCombine(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol)
{
	IP_COMBINE *c, tt;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	tt.DestIP = dest_ip;
	tt.SrcIP = src_ip;
	tt.Id = id;
	tt.Protocol = protocol;

	c = Search(t->IpCombine, &tt);

	return c;
}

// Insert by creating a new object to the IP combining list
IP_COMBINE *NnInsertIpCombine(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol, bool mac_broadcast, UCHAR ttl, bool src_is_localmac)
{
	IP_COMBINE *c;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	// Examine the quota
	if ((t->CurrentIpQuota + IP_COMBINE_INITIAL_BUF_SIZE) > IP_COMBINE_WAIT_QUEUE_SIZE_QUOTA)
	{
		// IP packet can not be stored any more
		return NULL;
	}

	c = ZeroMalloc(sizeof(IP_COMBINE));
	c->SrcIsLocalMacAddr = src_is_localmac;
	c->DestIP = dest_ip;
	c->SrcIP = src_ip;
	c->Id = id;
	c->Expire = t->v->Now + (UINT64)IP_COMBINE_TIMEOUT;
	c->Size = 0;
	c->IpParts = NewList(NULL);
	c->Protocol = protocol;
	c->MacBroadcast = mac_broadcast;
	c->Ttl = ttl;

	// Secure the memory
	c->DataReserved = IP_COMBINE_INITIAL_BUF_SIZE;
	c->Data = Malloc(c->DataReserved);
	t->CurrentIpQuota += c->DataReserved;

	Insert(t->IpCombine, c);

	return c;
}

// Initialize the IP combining list
void NnInitIpCombineList(NATIVE_NAT *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	t->IpCombine = NewList(CompareIpCombine);
}

// Release the IP combining list
void NnFreeIpCombineList(NATIVE_NAT *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(t->IpCombine); i++)
	{
		IP_COMBINE *c = LIST_DATA(t->IpCombine, i);

		NnFreeIpCombine(t, c);
	}

	ReleaseList(t->IpCombine);
}

// A TCP packet is received
void NnTcpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, UINT max_l3_size)
{
	TCP_HEADER *tcp;
	UCHAR *payload;
	UINT payload_size;
	UINT tcp_header_size;
	// Validate arguments
	if (t == NULL || data == NULL)
	{
		return;
	}

	// TCP header
	if (size < sizeof(TCP_HEADER))
	{
		return;
	}

	tcp = (TCP_HEADER *)data;

	// Get the TCP header size
	tcp_header_size = TCP_GET_HEADER_SIZE(tcp) * 4;
	if (size < tcp_header_size || tcp_header_size < sizeof(TCP_HEADER))
	{
		return;
	}

	// Payload
	payload = ((UCHAR *)data) + tcp_header_size;
	payload_size = size - tcp_header_size;

	// Search the port from the NAT table
	if (true)
	{
		NATIVE_NAT_ENTRY tt;
		NATIVE_NAT_ENTRY *e;

		NnSetNat(&tt, NAT_TCP, 0, 0, src_ip, Endian16(tcp->SrcPort), dest_ip, Endian16(tcp->DstPort));

		e = SearchHash(t->NatTableForRecv, &tt);

		if (e != NULL)
		{
			// Last communication time
			e->LastCommTime = t->v->Now;
			e->TotalRecv += (UINT64)size;

			// Rewrite the TCP header
			tcp->Checksum = 0;
			tcp->DstPort = Endian16(e->SrcPort);

			if (tcp->Flag & TCP_FIN || tcp->Flag & TCP_RST)
			{
				// Disconnect
				e->Status = NAT_TCP_WAIT_DISCONNECT;
			}

			if (tcp->Flag & TCP_SYN && tcp->Flag & TCP_ACK)
			{
				// Connection complete
				if (e->Status != NAT_TCP_WAIT_DISCONNECT)
				{
					e->Status = NAT_TCP_ESTABLISHED;
				}
			}

			e->LastSeq = Endian32(tcp->AckNumber);
			e->LastAck = Endian32(tcp->SeqNumber);

			// Checksum recalculation
			tcp->Checksum = CalcChecksumForIPv4(src_ip, e->SrcIp, IP_PROTO_TCP, tcp, size, 0);

			// IP transmission
			SendIp(t->v, e->SrcIp, src_ip, IP_PROTO_TCP, tcp, size);
		}
	}
}

// An ICMP packet has been received
void NnIcmpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, UINT max_l3_size)
{
	ICMP_HEADER *icmp;
	// Validate arguments
	if (t == NULL || data == NULL)
	{
		return;
	}
	if (ttl == 0)
	{
		ttl = 1;
	}

	// ICMP header
	if (size < sizeof(ICMP_HEADER))
	{
		return;
	}

	icmp = (ICMP_HEADER *)data;

	if (icmp->Type == ICMP_TYPE_ECHO_RESPONSE)
	{
		UCHAR *payload;
		UINT payload_size;
		ICMP_ECHO *echo;
		NATIVE_NAT_ENTRY tt, *e;

		// Echo Response
		echo = (ICMP_ECHO *)(((UCHAR *)data) + sizeof(ICMP_HEADER));

		if (size < (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO)))
		{
			return;
		}

		payload = ((UCHAR *)data) + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO);
		payload_size = size - (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));

		// Search the NAT
		NnSetNat(&tt, NAT_ICMP, 0, 0, 0, 0, dest_ip, Endian16(echo->Identifier));

		e = SearchHash(t->NatTableForRecv, &tt);

		if (e != NULL)
		{
			// Rewrite the header
			icmp->Checksum = 0;
			echo->Identifier = Endian16(e->SrcPort);
			icmp->Checksum = IpChecksum(icmp, size);

			e->LastCommTime = t->v->Now;
			e->TotalRecv += (UINT64)size;

			// Transmission
			SendIpEx(t->v, e->SrcIp, src_ip, IP_PROTO_ICMPV4, icmp, size, MAX(ttl - 1, 1));
		}
	}
	else if (icmp->Type == ICMP_TYPE_ECHO_REQUEST)
	{
		UCHAR *payload;
		UINT payload_size;
		ICMP_ECHO *echo;

		// Echo Response
		echo = (ICMP_ECHO *)(((UCHAR *)data) + sizeof(ICMP_HEADER));

		if (size < (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO)))
		{
			return;
		}

		payload = ((UCHAR *)data) + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO);
		payload_size = size - (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));

		if (dest_ip == t->PublicIP)
		{
			// Respond as soon as the Echo Request is received at the public side interface
			ICMP_HEADER *ret_icmp;
			ICMP_ECHO *ret_echo;
			UINT ret_size = sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + payload_size;

			ret_icmp = ZeroMalloc(ret_size);
			ret_echo = (ICMP_ECHO *)(((UCHAR *)ret_icmp) + sizeof(ICMP_HEADER));

			ret_icmp->Type = ICMP_TYPE_ECHO_RESPONSE;
			ret_icmp->Code = icmp->Code;

			ret_echo->Identifier = echo->Identifier;
			ret_echo->SeqNo = echo->SeqNo;

			Copy((UCHAR *)ret_icmp + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO),
			     payload, payload_size);

			ret_icmp->Checksum = IpChecksum(ret_icmp, ret_size);

			NnIpSendForInternet(t, IP_PROTO_ICMPV4, 0, dest_ip, src_ip, ret_icmp, ret_size, max_l3_size);

			Free(ret_icmp);
		}
	}
	else
	{
		if (icmp->Type == ICMP_TYPE_DESTINATION_UNREACHABLE || icmp->Type == ICMP_TYPE_TIME_EXCEEDED)
		{
			// Rewrite the Src IP of the IPv4 header of the ICMP response packet
			if (size >= (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + sizeof(IPV4_HEADER)))
			{
				IPV4_HEADER *orig_ipv4 = (IPV4_HEADER *)(((UCHAR *)data) + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));
				UINT orig_ipv4_size = size - (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));

				UINT orig_ipv4_header_size = GetIpHeaderSize((UCHAR *)orig_ipv4, orig_ipv4_size);

				if (orig_ipv4_header_size >= sizeof(IPV4_HEADER) && orig_ipv4_size >= orig_ipv4_header_size)
				{
					if (orig_ipv4->Protocol == IP_PROTO_ICMPV4)
					{
						// Search the inner ICMP header
						UINT inner_icmp_size = orig_ipv4_size - orig_ipv4_header_size;

						if (inner_icmp_size >= (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO)))
						{
							ICMP_HEADER *inner_icmp = (ICMP_HEADER *)(((UCHAR *)data) +
							                          sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + orig_ipv4_header_size);

							if (inner_icmp->Type == ICMP_TYPE_ECHO_REQUEST)
							{
								ICMP_ECHO *inner_echo = (ICMP_ECHO *)(((UCHAR *)inner_icmp) + sizeof(ICMP_HEADER));
								NATIVE_NAT_ENTRY tt, *e;

								// Search for the existing NAT table entry
								NnSetNat(&tt, NAT_ICMP, 0, 0, 0, 0, orig_ipv4->SrcIP, Endian16(inner_echo->Identifier));

								e = SearchHash(t->NatTableForRecv, &tt);

								if (e != NULL)
								{
									e->LastCommTime = t->v->Now;

									// Rewrite the inner IP packet and the ICMP header according to the NAT table
									inner_echo->Identifier = Endian16(e->SrcPort);
									inner_icmp->Checksum = 0;

									orig_ipv4->SrcIP = e->SrcIp;

									orig_ipv4->Checksum = 0;
									orig_ipv4->Checksum = IpChecksum(orig_ipv4, orig_ipv4_header_size);

									// Rewrite the outer ICMP header
									if (true)
									{
										UCHAR *payload;
										UINT payload_size;
										ICMP_ECHO *echo;

										// Echo Response
										echo = (ICMP_ECHO *)(((UCHAR *)data) + sizeof(ICMP_HEADER));

										if (size < (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO)))
										{
											return;
										}

										payload = ((UCHAR *)data) + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO);
										payload_size = size - (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));

										// Rewrite the header
										icmp->Checksum = 0;
										echo->Identifier = Endian16(e->SrcPort);
										icmp->Checksum = IpChecksum(icmp, size);

										// Transmission
										SendIpEx(t->v, e->SrcIp, src_ip, IP_PROTO_ICMPV4, icmp, size, MAX(ttl - 1, 1));
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

// An UDP packet has been received
void NnUdpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, UINT max_l3_size)
{
	UDP_HEADER *udp;
	UCHAR *payload;
	UINT payload_size;
	// Validate arguments
	if (t == NULL || data == NULL)
	{
		return;
	}

	// UDP header
	if (size <= sizeof(UDP_HEADER))
	{
		return;
	}

	udp = (UDP_HEADER *)data;

	// Payload
	payload = ((UCHAR *)data) + sizeof(UDP_HEADER);
	payload_size = size - sizeof(UDP_HEADER);

	// Inspect the payload size
	if (payload_size < (Endian16(udp->PacketLength) - sizeof(UDP_HEADER)))
	{
		return;
	}

	// Truncate the payload
	payload_size = Endian16(udp->PacketLength) - sizeof(UDP_HEADER);

	// Search the port number from the NAT table
	if (true)
	{
		NATIVE_NAT_ENTRY tt;
		NATIVE_NAT_ENTRY *e;

		NnSetNat(&tt, NAT_UDP, 0, 0, 0, 0, dest_ip, Endian16(udp->DstPort));

		e = SearchHash(t->NatTableForRecv, &tt);

		if (e != NULL)
		{
			// Last communication time
			e->LastCommTime = t->v->Now;
			e->TotalRecv += (UINT64)payload_size;

			// Deliver to the client by rewriting the port number
			SendUdp(t->v, e->SrcIp, e->SrcPort, src_ip, Endian16(udp->SrcPort),
			        payload, payload_size);
		}
	}
}

// A combined IP packet is received
void NnIpReceived(NATIVE_NAT *t, UINT src_ip, UINT dest_ip, UINT protocol, void *data, UINT size,
                  UCHAR ttl, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size)
{
	// Validate arguments
	if (t == NULL || data == NULL)
	{
		return;
	}

	if (dest_ip != t->PublicIP)
	{
		// Destination IP is not a unicast
		return;
	}

	switch (protocol)
	{
	case IP_PROTO_UDP:
		// UDP
		NnUdpReceived(t, src_ip, dest_ip, data, size, ttl, max_l3_size);
		break;

	case IP_PROTO_TCP:
		// TCP
		NnTcpReceived(t, src_ip, dest_ip, data, size, ttl, max_l3_size);
		break;

	case IP_PROTO_ICMPV4:
		// ICMP
		NnIcmpReceived(t, src_ip, dest_ip, data, size, ttl, max_l3_size);
		break;
	}
}

// Received an IP packet
void NnFragmentedIpReceived(NATIVE_NAT *t, PKT *packet)
{
	IPV4_HEADER *ip;
	void *data;
	UINT data_size_recved;
	UINT size;
	UINT ipv4_header_size;
	bool last_packet = false;
	UINT l3_size = 0;
	UCHAR *head_ip_header_data = NULL;
	UINT head_ip_header_size = 0;
	// Validate arguments
	if (t == NULL || packet == NULL)
	{
		return;
	}

	ip = packet->L3.IPv4Header;

	// Get the size of the IPv4 header
	ipv4_header_size = IPV4_GET_HEADER_LEN(packet->L3.IPv4Header) * 4;
	head_ip_header_size = ipv4_header_size;

	// Get the pointer to the data
	data = ((UCHAR *)packet->L3.PointerL3) + ipv4_header_size;

	// Get the data size
	size = l3_size = Endian16(ip->TotalLength);
	if (size <= ipv4_header_size)
	{
		// There is no data
		return;
	}
	size -= ipv4_header_size;

	// Get the size of data actually received
	data_size_recved = packet->PacketSize - (ipv4_header_size + MAC_HEADER_SIZE);
	if (data_size_recved < size)
	{
		// Data insufficient (It may be missing on the way)
		return;
	}

	if (IPV4_GET_OFFSET(ip) == 0 && (IPV4_GET_FLAGS(ip) & 0x01) == 0)
	{
		// Because this packet has not been fragmented, it can be passed to the upper layer immediately
		head_ip_header_data = (UCHAR *)packet->L3.IPv4Header;
		NnIpReceived(t, ip->SrcIP, ip->DstIP, ip->Protocol, data, size, ip->TimeToLive,
		             head_ip_header_data, head_ip_header_size, l3_size);
	}
	else
	{
		// This packet is necessary to combine because it is fragmented
		UINT offset = IPV4_GET_OFFSET(ip) * 8;
		IP_COMBINE *c = NnSearchIpCombine(t, ip->SrcIP, ip->DstIP, Endian16(ip->Identification), ip->Protocol);

		if (offset == 0)
		{
			head_ip_header_data = (UCHAR *)packet->L3.IPv4Header;
		}

		last_packet = ((IPV4_GET_FLAGS(ip) & 0x01) == 0 ? true : false);

		if (c != NULL)
		{
			// It is the second or subsequent packet
			c->MaxL3Size = MAX(c->MaxL3Size, l3_size);
			NnCombineIp(t, c, offset, data, size, last_packet, head_ip_header_data, head_ip_header_size);
		}
		else
		{
			// Create a combining object because it is the first packet
			c = NnInsertIpCombine(
			        t, ip->SrcIP, ip->DstIP, Endian16(ip->Identification), ip->Protocol, packet->BroadcastPacket,
			        ip->TimeToLive, false);
			if (c != NULL)
			{
				c->MaxL3Size = MAX(c->MaxL3Size, l3_size);
				NnCombineIp(t, c, offset, data, size, last_packet, head_ip_header_data, head_ip_header_size);
			}
		}
	}
}

// Layer 2 packet processing
void NnLayer2(NATIVE_NAT *t, PKT *packet)
{
	// Validate arguments
	if (t == NULL || packet == NULL)
	{
		return;
	}

	if (packet->TypeL3 == L3_IPV4)
	{
		// IPv4
		NnFragmentedIpReceived(t, packet);
	}
}

// Extract the received packets of native NAT, and deliver it to the VPN client
void NnPoll(NATIVE_NAT *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	LockQueue(t->RecvQueue);
	{
		while (true)
		{
			PKT *pkt = GetNext(t->RecvQueue);

			if (pkt == NULL)
			{
				break;
			}

			NnLayer2(t, pkt);

			FreePacketWithData(pkt);
		}
	}
	UnlockQueue(t->RecvQueue);

	if (t->SendStateChanged)
	{
		TUBE *halt_tube = NULL;

		Lock(t->Lock);
		{
			if (t->HaltTube != NULL)
			{
				halt_tube = t->HaltTube;

				AddRef(halt_tube->Ref);
			}
		}
		Unlock(t->Lock);

		if (halt_tube != NULL)
		{
			TubeFlushEx(halt_tube, true);

			t->SendStateChanged = false;

			ReleaseTube(halt_tube);
		}
	}

	NnPollingIpCombine(t);

	NnDeleteOldSessions(t);
}

// Send a fragmented IP packet to the Internet
void NnIpSendFragmentedForInternet(NATIVE_NAT *t, UCHAR ip_protocol, UINT src_ip, UINT dest_ip, USHORT id, USHORT total_size,
                                   USHORT offset, void *data, UINT size, UCHAR ttl)
{
	UCHAR *buf;
	IPV4_HEADER *ip;
	BLOCK *b;
	// Validate arguments
	if (t == NULL || data == NULL)
	{
		return;
	}

	// Memory allocation
	buf = Malloc(size + IP_HEADER_SIZE);
	ip = (IPV4_HEADER *)&buf[0];

	// IP header construction
	ip->VersionAndHeaderLength = 0;
	IPV4_SET_VERSION(ip, 4);
	IPV4_SET_HEADER_LEN(ip, (IP_HEADER_SIZE / 4));
	ip->TypeOfService = DEFAULT_IP_TOS;
	ip->TotalLength = Endian16((USHORT)(size + IP_HEADER_SIZE));
	ip->Identification = Endian16(id);
	ip->FlagsAndFragmentOffset[0] = ip->FlagsAndFragmentOffset[1] = 0;
	IPV4_SET_OFFSET(ip, (offset / 8));
	if ((offset + size) >= total_size)
	{
		IPV4_SET_FLAGS(ip, 0x00);
	}
	else
	{
		IPV4_SET_FLAGS(ip, 0x01);
	}
	ip->TimeToLive = (ttl == 0 ? DEFAULT_IP_TTL : ttl);
	ip->Protocol = ip_protocol;
	ip->Checksum = 0;
	ip->SrcIP = src_ip;
	ip->DstIP = dest_ip;

	// Checksum calculation
	ip->Checksum = IpChecksum(ip, IP_HEADER_SIZE);

	// Data copy
	Copy(buf + IP_HEADER_SIZE, data, size);

	// Transmission
	b = NewBlock(buf, size + IP_HEADER_SIZE, 0);

	LockQueue(t->SendQueue);
	{
		if (t->SendQueue->num_item <= NN_MAX_QUEUE_LENGTH)
		{
			InsertQueue(t->SendQueue, b);

			t->SendStateChanged = true;
		}
		else
		{
			FreeBlock(b);
		}
	}
	UnlockQueue(t->SendQueue);
}

// Send an IP packet to the Internet
void NnIpSendForInternet(NATIVE_NAT *t, UCHAR ip_protocol, UCHAR ttl, UINT src_ip, UINT dest_ip, void *data, UINT size, UINT max_l3_size)
{
	UINT mss = 0;
	UCHAR *buf;
	USHORT offset;
	USHORT id;
	USHORT total_size;
	UINT size_of_this_packet;
	// Validate arguments
	if (t == NULL || data == NULL)
	{
		return;
	}

	// Maximum segment size
	if (max_l3_size > IP_HEADER_SIZE)
	{
		mss = max_l3_size - IP_HEADER_SIZE;
	}

	if (mss == 0)
	{
		mss = t->v->IpMss;
	}

	mss = MAX(mss, 1000);

	// Buffer
	buf = (UCHAR *)data;

	// ID
	id = (t->NextId++);

	// Total size
	total_size = (USHORT)size;

	// Start to fragment
	offset = 0;

	while (true)
	{
		bool last_packet = false;
		// Get the size of this packet
		size_of_this_packet = MIN((USHORT)mss, (total_size - offset));
		if ((offset + (USHORT)size_of_this_packet) == total_size)
		{
			last_packet = true;
		}

		// Transmit the fragmented packet
		NnIpSendFragmentedForInternet(t, ip_protocol, src_ip, dest_ip, id, total_size, offset,
		                              buf + offset, size_of_this_packet, ttl);
		if (last_packet)
		{
			break;
		}

		offset += (USHORT)size_of_this_packet;
	}
}

// Communication of ICMP towards the Internet
void NnIcmpEchoRecvForInternet(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size, UCHAR ttl, void *icmp_data, UINT icmp_size, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size)
{
	NATIVE_NAT_ENTRY tt;
	NATIVE_NAT_ENTRY *e;
	NATIVE_NAT *t;
	USHORT src_port;
	ICMP_HEADER *old_icmp_header;
	ICMP_ECHO *old_icmp_echo;
	ICMP_HEADER *icmp;
	ICMP_ECHO *echo;
	UCHAR *payload_data;
	UINT payload_size;
	// Validate arguments
	if (NnIsActive(v) == false || icmp_data == NULL)
	{
		return;
	}

	t = v->NativeNat;

	old_icmp_header = (ICMP_HEADER *)icmp_data;
	old_icmp_echo = (ICMP_ECHO *)(((UCHAR *)icmp_data) + sizeof(ICMP_HEADER));

	if (size < (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO)))
	{
		return;
	}

	payload_data = ((UCHAR *)icmp_data) + (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));
	payload_size = icmp_size - (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));

	if (dest_ip == v->HostIP)
	{
		// Respond because it is addressed to me
		VirtualIcmpEchoSendResponse(v, dest_ip, src_ip, Endian16(old_icmp_echo->Identifier),
		                            Endian16(old_icmp_echo->SeqNo), payload_data, payload_size);

		return;
	}

	if (ttl <= 1)
	{
		// Reply the Time Exceeded immediately for the packet whose TTL is 1
		UINT reply_size = sizeof(ICMP_HEADER) + 4 + ip_header_size + 8;
		UCHAR *reply_data = ZeroMalloc(reply_size);
		ICMP_HEADER *icmp = (ICMP_HEADER *)reply_data;
		icmp->Type = ICMP_TYPE_TIME_EXCEEDED;
		icmp->Code = ICMP_CODE_TTL_EXCEEDED_IN_TRANSIT;
		Copy(reply_data + sizeof(ICMP_HEADER) + 4, ip_header, ip_header_size);
		Copy(reply_data + sizeof(ICMP_HEADER) + 4 + ip_header_size, icmp_data, MIN(icmp_size, 8));

		icmp->Checksum = IpChecksum(icmp, reply_size);

		SendIp(v, src_ip, v->HostIP, IP_PROTO_ICMPV4, reply_data, reply_size);

		Free(reply_data);

		return;
	}

	src_port = Endian16(old_icmp_echo->Identifier);

	// Search whether there is an existing session
	NnSetNat(&tt, NAT_ICMP, src_ip, src_port, 0, 0, 0, 0);

	e = SearchHash(t->NatTableForSend, &tt);

	if (e == NULL)
	{
		// Create a new session because there is no existing one
		UINT public_port;

		if (CanCreateNewNatEntry(v) == false)
		{
			// Can not make any more
			return;
		}

		NnDeleteOldestNatSessionIfNecessary(t, src_ip, NAT_ICMP);

		// Get a free port
		public_port = NnMapNewPublicPort(t, NAT_ICMP, 0, 0, t->PublicIP);
		if (public_port == 0)
		{
			// There are no free ports
			return;
		}

		e = ZeroMalloc(sizeof(NATIVE_NAT_ENTRY));

		e->Status = NAT_TCP_ESTABLISHED;

		e->HashCodeForSend = INFINITE;
		e->HashCodeForRecv = INFINITE;
		e->Id = Inc(v->Counter);
		e->Protocol = NAT_ICMP;
		e->SrcIp = src_ip;
		e->SrcPort = src_port;
		e->DestIp = 0;
		e->DestPort = 0;
		e->PublicIp = t->PublicIP;
		e->PublicPort = public_port;

		e->CreatedTime = v->Now;
		e->LastCommTime = v->Now;

		// Add to the list
		AddHash(t->NatTableForSend, e);
		AddHash(t->NatTableForRecv, e);

		// Log
		if (true)
		{
			IP ip1, ip2;
			char s1[MAX_SIZE], s2[MAX_SIZE];
			UINTToIP(&ip1, src_ip);
			UINTToIP(&ip2, dest_ip);
			IPToStr(s1, 0, &ip1);
			IPToStr(s2, 0, &ip2);

			Debug("ICMP Session %u:  %s:0x%x -> %s:0x%x\n", e->Id, s1, src_port, s2, public_port);
		}
	}

	// Rebuild the ICMP header
	icmp = ZeroMalloc(sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + payload_size);
	icmp->Code = old_icmp_header->Code;
	icmp->Type = old_icmp_header->Type;
	icmp->Checksum = 0;

	echo = (ICMP_ECHO *)(((UCHAR *)icmp) + sizeof(ICMP_HEADER));
	echo->SeqNo = old_icmp_echo->SeqNo;
	echo->Identifier = Endian16(e->PublicPort);

	Copy(((UCHAR *)icmp) + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO), payload_data, payload_size);

	icmp->Checksum = IpChecksum(icmp, sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + payload_size);

	e->TotalSent += (UINT64)payload_size;
	e->LastCommTime = v->Now;

	// Send to the Internet
	NnIpSendForInternet(t, IP_PROTO_ICMPV4, ttl - 1, e->PublicIp, dest_ip, icmp, sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + payload_size, max_l3_size);

	Free(icmp);
}

// Communication of UDP towards the Internet
void NnUdpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, UINT max_l3_size)
{
	NATIVE_NAT_ENTRY tt;
	NATIVE_NAT_ENTRY *e;
	NATIVE_NAT *t;
	UDP_HEADER *udp;
	// Validate arguments
	if (NnIsActive(v) == false || data == NULL)
	{
		return;
	}

	t = v->NativeNat;

	// Search whether there is an existing session
	NnSetNat(&tt, NAT_UDP, src_ip, src_port, 0, 0, 0, 0);

	e = SearchHash(t->NatTableForSend, &tt);

	if (e == NULL)
	{
		// Create a new session because there is no existing one
		UINT public_port;

		if (CanCreateNewNatEntry(v) == false)
		{
			// Can not make any more
			return;
		}

		NnDeleteOldestNatSessionIfNecessary(t, src_ip, NAT_UDP);

		// Get a free port
		public_port = NnMapNewPublicPort(t, NAT_UDP, 0, 0, t->PublicIP);
		if (public_port == 0)
		{
			// There are no free ports
			return;
		}

		e = ZeroMalloc(sizeof(NATIVE_NAT_ENTRY));

		e->Status = NAT_TCP_ESTABLISHED;

		e->HashCodeForSend = INFINITE;
		e->HashCodeForRecv = INFINITE;
		e->Id = Inc(v->Counter);
		e->Protocol = NAT_UDP;
		e->SrcIp = src_ip;
		e->SrcPort = src_port;
		e->DestIp = 0;
		e->DestPort = 0;
		e->PublicIp = t->PublicIP;
		e->PublicPort = public_port;

		e->CreatedTime = v->Now;
		e->LastCommTime = v->Now;

		// Add to the list
		AddHash(t->NatTableForSend, e);
		AddHash(t->NatTableForRecv, e);

		// Log
		if (true)
		{
			IP ip1, ip2;
			char s1[MAX_SIZE], s2[MAX_SIZE];
			UINTToIP(&ip1, src_ip);
			UINTToIP(&ip2, dest_ip);
			IPToStr(s1, 0, &ip1);
			IPToStr(s2, 0, &ip2);

			NLog(v, "LH_NAT_UDP_CREATED", e->Id, s1, src_port, s2, dest_port);
		}
	}

	// Rebuild the UDP header
	udp = ZeroMalloc(sizeof(UDP_HEADER) + size);

	udp->SrcPort = Endian16(e->PublicPort);
	udp->DstPort = Endian16(dest_port);
	udp->PacketLength = Endian16((USHORT)sizeof(UDP_HEADER) + size);

	Copy(((UCHAR *)udp) + sizeof(UDP_HEADER), data, size);

	udp->Checksum = CalcChecksumForIPv4(e->PublicIp, dest_ip, IP_PROTO_UDP, udp, sizeof(UDP_HEADER) + size, 0);

	e->TotalSent += (UINT64)size;
	e->LastCommTime = v->Now;

	// Send to the Internet
	NnIpSendForInternet(t, IP_PROTO_UDP, 127, e->PublicIp, dest_ip, udp, sizeof(UDP_HEADER) + size, max_l3_size);

	Free(udp);
}

// Communication of TCP towards the Internet
void NnTcpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, TCP_HEADER *old_tcp, void *data, UINT size, UINT max_l3_size)
{
	NATIVE_NAT_ENTRY tt;
	NATIVE_NAT_ENTRY *e;
	NATIVE_NAT *t;
	UINT tcp_header_size;
	TCP_HEADER *tcp;
	// Validate arguments
	if (NnIsActive(v) == false || old_tcp == NULL || data == NULL)
	{
		return;
	}

	t = v->NativeNat;

	// Search whether there is an existing session
	NnSetNat(&tt, NAT_TCP, src_ip, src_port, dest_ip, dest_port, 0, 0);

	e = SearchHash(t->NatTableForSend, &tt);

	if (e == NULL)
	{
		// Create a new session because there is no existing one
		UINT public_port;

		if (((old_tcp->Flag & TCP_SYN) && ((old_tcp->Flag & TCP_ACK) == 0)) == false)
		{
			// If there is no existing session, pass through only for SYN packet
			return;
		}

		if (CanCreateNewNatEntry(v) == false)
		{
			// Can not make any more
			return;
		}

		NnDeleteOldestNatSessionIfNecessary(t, src_ip, NAT_TCP);

		// Get a free port
		public_port = NnMapNewPublicPort(t, NAT_TCP, dest_ip, dest_port, t->PublicIP);
		if (public_port == 0)
		{
			// There are no free ports
			return;
		}

		e = ZeroMalloc(sizeof(NATIVE_NAT_ENTRY));

		e->HashCodeForSend = INFINITE;
		e->HashCodeForRecv = INFINITE;
		e->Id = Inc(v->Counter);
		e->Status = NAT_TCP_CONNECTING;
		e->Protocol = NAT_TCP;
		e->SrcIp = src_ip;
		e->SrcPort = src_port;
		e->DestIp = dest_ip;
		e->DestPort = dest_port;
		e->PublicIp = t->PublicIP;
		e->PublicPort = public_port;

		e->CreatedTime = v->Now;
		e->LastCommTime = v->Now;

		// Add to the list
		AddHash(t->NatTableForSend, e);
		AddHash(t->NatTableForRecv, e);

		// Log
		if (true)
		{
			IP ip1, ip2;
			char s1[MAX_SIZE], s2[MAX_SIZE];
			UINTToIP(&ip1, src_ip);
			UINTToIP(&ip2, dest_ip);
			IPToStr(s1, 0, &ip1);
			IPToStr(s2, 0, &ip2);

			NLog(v, "LH_NAT_TCP_CREATED", e->Id, s1, src_port, s2, dest_port);
		}
	}

	// Update the last communication time
	e->LastCommTime = v->Now;

	e->TotalSent += (UINT64)size;

	tcp_header_size = TCP_GET_HEADER_SIZE(old_tcp) * 4;

	// Create a new TCP packet
	tcp = ZeroMalloc(tcp_header_size + size);

	// Copy the old TCP header
	Copy(tcp, old_tcp, tcp_header_size);

	if (tcp->Flag & TCP_RST || tcp->Flag & TCP_FIN)
	{
		// Disconnect
		e->Status = NAT_TCP_WAIT_DISCONNECT;
	}

	// Rewrite the TCP header
	tcp->Checksum = 0;
	tcp->SrcPort = Endian16(e->PublicPort);

	e->LastSeq = Endian32(tcp->SeqNumber);
	e->LastAck = Endian32(tcp->AckNumber);

	// Payload
	Copy(((UCHAR *)tcp) + tcp_header_size, data, size);

	// Checksum calculation
	tcp->Checksum = CalcChecksumForIPv4(e->PublicIp, dest_ip, IP_PROTO_TCP, tcp, tcp_header_size + size, 0);

	// Send to the Internet
	NnIpSendForInternet(t, IP_PROTO_TCP, 127, e->PublicIp, dest_ip, tcp, tcp_header_size + size, max_l3_size);

	Free(tcp);
}

// Assign a new public-side port
UINT NnMapNewPublicPort(NATIVE_NAT *t, UINT protocol, UINT dest_ip, UINT dest_port, UINT public_ip)
{
	UINT i;
	UINT base_port;
	UINT port_start = 1025;
	UINT port_end = 65500;
	// Validate arguments
	if (t == NULL)
	{
		return 0;
	}

	if (t->IsRawIpMode)
	{
		port_start = NN_RAW_IP_PORT_START;
		port_end = NN_RAW_IP_PORT_END;
	}

	base_port = Rand32() % (port_end - port_start) + port_start;

	for (i = 0; i < (port_end - port_start); i++)
	{
		UINT port;
		NATIVE_NAT_ENTRY tt;
		NATIVE_NAT *e;

		port = base_port + i;
		if (port > port_end)
		{
			port = port - port_end + port_start;
		}

		// Is this port vacant?
		NnSetNat(&tt, protocol, 0, 0, dest_ip, dest_port, public_ip, port);

		e = SearchHash(t->NatTableForRecv, &tt);

		if (e == NULL)
		{
			// Free port is found
			return port;
		}
	}

	return 0;
}

// Examine whether the native NAT is available
bool NnIsActive(VH *v)
{
	return NnIsActiveEx(v, NULL);
}
bool NnIsActiveEx(VH *v, bool *is_ipraw_mode)
{
	// Validate arguments
	if (v == NULL)
	{
		return false;
	}

	if (v->NativeNat == NULL)
	{
		return false;
	}

	if (v->NativeNat->PublicIP == 0)
	{
		return false;
	}

	if (v->NativeNat->Active)
	{
		if (is_ipraw_mode != NULL)
		{
			*is_ipraw_mode = v->NativeNat->IsRawIpMode;
		}
	}

	return v->NativeNat->Active;
}

// Native NAT main loop
void NnMainLoop(NATIVE_NAT *t, NATIVE_STACK *a)
{
	IPC *ipc;
	TUBE *tubes[3];
	UINT num_tubes = 0;
	UINT64 next_poll_tick = 0;
	INTERRUPT_MANAGER *interrupt;
	USHORT dns_src_port = 0;
	USHORT dns_tran_id = 0;
	USHORT tcp_src_port = 0;
	UINT tcp_seq = 0;
	IP yahoo_ip;
	bool wait_for_dns = false;
	UINT64 tcp_last_recv_tick = 0;
	UINT dhcp_renew_interval;
	UINT64 next_dhcp_renew_tick = 0;
	// Validate arguments
	if (t == NULL || a == NULL)
	{
		return;
	}

	dhcp_renew_interval = a->CurrentDhcpOptionList.LeaseTime;

	if (dhcp_renew_interval == 0)
	{
		dhcp_renew_interval = IPC_DHCP_DEFAULT_LEASE;
	}

	dhcp_renew_interval = MAX(dhcp_renew_interval, IPC_DHCP_MIN_LEASE) / 2;

	interrupt = NewInterruptManager();

	ipc = a->Ipc;

	tubes[num_tubes++] = ipc->Sock->RecvTube;
	//tubes[num_tubes++] = ipc->Sock->SendTube;	// bug 2015.10.01 remove
	tubes[num_tubes++] = t->HaltTube;

	Zero(&yahoo_ip, sizeof(yahoo_ip));

	next_poll_tick = Tick64() + (UINT64)NN_POLL_CONNECTIVITY_INTERVAL;
	AddInterrupt(interrupt, next_poll_tick);

	tcp_last_recv_tick = Tick64();
	next_dhcp_renew_tick = Tick64() + (UINT64)dhcp_renew_interval * 1000;
	AddInterrupt(interrupt, next_dhcp_renew_tick);

	while (t->Halt == false && t->v->UseNat)
	{
		UINT64 now = Tick64();
		bool call_cancel = false;
		bool state_changed = false;
		UINT wait_interval;

		if (t->v->HubOption != NULL)
		{
			if (t->IsRawIpMode == false && t->v->HubOption->DisableKernelModeSecureNAT)
			{
				break;
			}
			if (t->IsRawIpMode && t->v->HubOption->DisableIpRawModeSecureNAT)
			{
				break;
			}
		}

		IPCFlushArpTable(ipc);
		call_cancel = false;

LABEL_RESTART:
		state_changed = false;

		if (next_poll_tick == 0 || next_poll_tick <= now)
		{
			BUF *dns_query;

			dns_src_port = NnGenSrcPort(a->IsIpRawMode);
			dns_tran_id = Rand16();

			// Start a connectivity check periodically
			dns_query = NnBuildIpPacket(NnBuildUdpPacket(NnBuildDnsQueryPacket(NN_CHECK_HOSTNAME, dns_tran_id),
			                            IPToUINT(&ipc->ClientIPAddress), dns_src_port, IPToUINT(&a->DnsServerIP), 53),
			                            IPToUINT(&ipc->ClientIPAddress), IPToUINT(&a->DnsServerIP), IP_PROTO_UDP, 0);

			IPCSendIPv4(ipc, dns_query->Buf, dns_query->Size);

			wait_for_dns = true;

			FreeBuf(dns_query);

			next_poll_tick = now + (UINT64)NN_POLL_CONNECTIVITY_INTERVAL;
			AddInterrupt(interrupt, next_poll_tick);
		}

		if (next_dhcp_renew_tick == 0 || next_dhcp_renew_tick <= now)
		{
			IP ip;

			UINTToIP(&ip, a->CurrentDhcpOptionList.ServerAddress);

			IPCDhcpRenewIP(ipc, &ip);

			next_dhcp_renew_tick = now + (UINT64)dhcp_renew_interval * 1000;
			AddInterrupt(interrupt, next_dhcp_renew_tick);
		}

		// Send an IP packet to IPC
		LockQueue(t->SendQueue);
		{
			while (true)
			{
				BLOCK *b = GetNext(t->SendQueue);

				if (b == NULL)
				{
					break;
				}

				IPCSendIPv4(ipc, b->Buf, b->Size);

				state_changed = true;

				FreeBlock(b);
			}
		}
		UnlockQueue(t->SendQueue);

		// Happy processing
		IPCProcessL3EventsIPv4Only(ipc);

		LockQueue(t->RecvQueue);
		{
			while (true)
			{
				// Receive an IP packet from IPC
				BLOCK *b = IPCRecvIPv4(ipc);
				PKT *pkt;

				if (b == NULL)
				{
					// Can not receive any more
					break;
				}

				// Parse the packet
				pkt = ParsePacketIPv4WithDummyMacHeader(b->Buf, b->Size);

				FreeBlock(b);

				if (pkt != NULL)
				{
					bool no_store = false;

					// Read the contents of the packet first, to determine whether it is a response for the connectivity test packet
					if (wait_for_dns)
					{
						if (pkt->TypeL3 == L3_IPV4 && pkt->TypeL4 == L4_UDP &&
						        pkt->L3.IPv4Header->SrcIP == IPToUINT(&a->DnsServerIP) &&
						        pkt->L3.IPv4Header->DstIP == IPToUINT(&ipc->ClientIPAddress) &&
						        pkt->L4.UDPHeader->SrcPort == Endian16(53) && pkt->L4.UDPHeader->DstPort == Endian16(dns_src_port))
						{
							DNSV4_HEADER *dns_header = (DNSV4_HEADER *)pkt->Payload;
							if (pkt->PayloadSize >= sizeof(DNSV4_HEADER))
							{
								if (dns_header->TransactionId == Endian16(dns_tran_id))
								{
									IP ret_ip;

									if (NnParseDnsResponsePacket(pkt->Payload, pkt->PayloadSize, &ret_ip))
									{
										BUF *tcp_query;

										Copy(&yahoo_ip, &ret_ip, sizeof(IP));

										//SetIP(&yahoo_ip, 192, 168, 2, 32);

										// DNS response has been received
										no_store = true;

										tcp_src_port = NnGenSrcPort(a->IsIpRawMode);

										// Generate a TCP connection attempt packet
										tcp_seq = Rand32();
										tcp_query = NnBuildIpPacket(NnBuildTcpPacket(NewBuf(), IPToUINT(&ipc->ClientIPAddress), tcp_src_port,
										                            IPToUINT(&yahoo_ip), 80, tcp_seq, 0, TCP_SYN, 8192, 1414),
										                            IPToUINT(&ipc->ClientIPAddress), IPToUINT(&yahoo_ip), IP_PROTO_TCP, 0);

										IPCSendIPv4(ipc, tcp_query->Buf, tcp_query->Size);

										FreeBuf(tcp_query);

										wait_for_dns = false;
									}
								}
							}
						}
					}

					if (pkt->TypeL3 == L3_IPV4 && pkt->TypeL4 == L4_TCP &&
					        pkt->L3.IPv4Header->SrcIP == IPToUINT(&yahoo_ip) &&
					        pkt->L3.IPv4Header->DstIP == IPToUINT(&ipc->ClientIPAddress) &&
					        pkt->L4.TCPHeader->SrcPort == Endian16(80) && pkt->L4.TCPHeader->DstPort == Endian16(tcp_src_port))
					{
						TCP_HEADER *tcp_header = (TCP_HEADER *)pkt->L4.TCPHeader;
						if ((tcp_header->Flag & TCP_SYN) && (tcp_header->Flag & TCP_ACK))
						{
							// There was a TCP response
							BUF *tcp_query;
							UINT recv_seq = Endian32(tcp_header->SeqNumber) + 1;

							no_store = true;

							// Send a RST
							tcp_query = NnBuildIpPacket(NnBuildTcpPacket(NewBuf(), IPToUINT(&ipc->ClientIPAddress), tcp_src_port,
							                            IPToUINT(&yahoo_ip), 80, tcp_seq + 1, recv_seq, TCP_RST | TCP_ACK, 8192, 0),
							                            IPToUINT(&ipc->ClientIPAddress), IPToUINT(&yahoo_ip), IP_PROTO_TCP, 0);

							IPCSendIPv4(ipc, tcp_query->Buf, tcp_query->Size);

							FreeBuf(tcp_query);

							tcp_last_recv_tick = now;
						}
					}

					if (t->RecvQueue->num_item > NN_MAX_QUEUE_LENGTH)
					{
						no_store = true;
					}

					if (no_store == false)
					{
						// Put in the queue
						InsertQueue(t->RecvQueue, pkt);
						call_cancel = true;
						state_changed = true;
					}
					else
					{
						// Release the packet
						FreePacketWithData(pkt);
					}
				}
			}
		}
		UnlockQueue(t->RecvQueue);

		if (state_changed)
		{
			goto LABEL_RESTART;
		}

		if (call_cancel)
		{
			CANCEL *c = NULL;

			Lock(t->CancelLock);
			{
				c = t->Cancel;

				AddRef(c->ref);
			}
			Unlock(t->CancelLock);

			Cancel(c);

			ReleaseCancel(c);
		}

		if (IsTubeConnected(ipc->Sock->RecvTube) == false || IsTubeConnected(ipc->Sock->SendTube) == false)
		{
			// Disconnected
			break;
		}

		if ((tcp_last_recv_tick + (UINT64)NN_POLL_CONNECTIVITY_TIMEOUT) < now)
		{
			// Connectivity test has timed out because a certain period of time has elapsed
			Debug("NN_POLL_CONNECTIVITY_TIMEOUT\n");
			break;
		}

		wait_interval = GetNextIntervalForInterrupt(interrupt);
		wait_interval = MIN(wait_interval, 1234);

		if (wait_interval != 0)
		{
			WaitForTubes(tubes, num_tubes, wait_interval);
		}
	}

	FreeInterruptManager(interrupt);
}

// Build an IP packet
BUF *NnBuildIpPacket(BUF *payload, UINT src_ip, UINT dst_ip, UCHAR protocol, UCHAR ttl)
{
	BUF *ret = NewBuf();
	IPV4_HEADER h;

	if (ttl == 0)
	{
		ttl = 127;
	}

	// IP header
	Zero(&h, sizeof(h));
	IPV4_SET_VERSION(&h, 4);
	IPV4_SET_HEADER_LEN(&h, sizeof(IPV4_HEADER) / 4);
	h.TotalLength = Endian16((USHORT)sizeof(IPV4_HEADER) + payload->Size);
	h.Identification = Rand16();
	h.TimeToLive = ttl;
	h.Protocol = protocol;
	h.SrcIP = src_ip;
	h.DstIP = dst_ip;

	h.Checksum = IpChecksum(&h, sizeof(h));

	WriteBuf(ret, &h, sizeof(h));
	WriteBufBuf(ret, payload);

	SeekBufToBegin(ret);

	FreeBuf(payload);

	return ret;
}

// Build an UDP packet
BUF *NnBuildUdpPacket(BUF *payload, UINT src_ip, USHORT src_port, UINT dst_ip, USHORT dst_port)
{
	BUF *ret = NewBuf();
	BUF *phbuf = NewBuf();
	UDPV4_PSEUDO_HEADER ph;
	UDP_HEADER h;

	// UDP pseudo header
	Zero(&ph, sizeof(ph));

	ph.SrcIP = src_ip;
	ph.DstIP = dst_ip;
	ph.SrcPort = Endian16(src_port);
	ph.DstPort = Endian16(dst_port);
	ph.Protocol = IP_PROTO_UDP;
	ph.PacketLength1 = ph.PacketLength2 = Endian16(payload->Size + (USHORT)sizeof(UDP_HEADER));

	WriteBuf(phbuf, &ph, sizeof(ph));
	WriteBufBuf(phbuf, payload);

	// UDP header
	Zero(&h, sizeof(h));
	h.SrcPort = Endian16(src_port);
	h.DstPort = Endian16(dst_port);
	h.PacketLength = Endian16(payload->Size + (USHORT)sizeof(UDP_HEADER));
	h.Checksum = IpChecksum(phbuf->Buf, phbuf->Size);

	WriteBuf(ret, &h, sizeof(h));
	WriteBuf(ret, payload->Buf, payload->Size);

	SeekBufToBegin(ret);

	FreeBuf(payload);
	FreeBuf(phbuf);

	return ret;
}

// Build a TCP packet
BUF *NnBuildTcpPacket(BUF *payload, UINT src_ip, USHORT src_port, UINT dst_ip, USHORT dst_port, UINT seq, UINT ack, UINT flag, UINT window_size, UINT mss)
{
	BUF *ret;
	IPV4_PSEUDO_HEADER *vh;
	TCP_HEADER *tcp;
	static UCHAR tcp_mss_option[] = {0x02, 0x04, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00};
	UINT header_size = TCP_HEADER_SIZE;
	UINT total_size;

	// Memory allocation
	vh = Malloc(sizeof(IPV4_PSEUDO_HEADER) + TCP_HEADER_SIZE + payload->Size + 32);
	tcp = (TCP_HEADER *)(((UCHAR *)vh) + sizeof(IPV4_PSEUDO_HEADER));

	if (mss != 0)
	{
		USHORT *mss_size;
		mss_size = (USHORT *)(&tcp_mss_option[2]);
		*mss_size = Endian16((USHORT)mss);
		header_size += sizeof(tcp_mss_option);
	}

	total_size = header_size + payload->Size;

	// Pseudo header generation
	vh->SrcIP = src_ip;
	vh->DstIP = dst_ip;
	vh->Reserved = 0;
	vh->Protocol = IP_PROTO_TCP;
	vh->PacketLength = Endian16((USHORT)total_size);

	// TCP header generation
	tcp->SrcPort = Endian16((USHORT)src_port);
	tcp->DstPort = Endian16((USHORT)dst_port);
	tcp->SeqNumber = Endian32(seq);
	tcp->AckNumber = Endian32(ack);
	tcp->HeaderSizeAndReserved = 0;
	TCP_SET_HEADER_SIZE(tcp, (UCHAR)(header_size / 4));
	tcp->Flag = (UCHAR)flag;
	tcp->WindowSize = Endian16((USHORT)window_size);
	tcp->Checksum = 0;
	tcp->UrgentPointer = 0;

	// Copy the option values
	if (mss != 0)
	{
		Copy(((UCHAR *)tcp) + TCP_HEADER_SIZE, tcp_mss_option, sizeof(tcp_mss_option));
	}

	// Data copy
	Copy(((UCHAR *)tcp) + header_size, payload->Buf, payload->Size);

	// Checksum calculation
	tcp->Checksum = IpChecksum(vh, total_size + 12);

	ret = NewBufFromMemory(tcp, total_size);

	Free(vh);

	FreeBuf(payload);

	return ret;
}

// Build a DNS query packet
BUF *NnBuildDnsQueryPacket(char *hostname, USHORT tran_id)
{
	BUF *buf = NewBuf();
	DNSV4_HEADER header;

	Zero(&header, sizeof(header));

	header.TransactionId = Endian16(tran_id);
	header.Flag1 = 0x01;
	header.Flag2 = 0x00;
	header.NumQuery = Endian16(1);

	WriteBuf(buf, &header, sizeof(header));

	BuildDnsQueryPacket(buf, hostname, false);

	SeekBufToBegin(buf);

	return buf;
}

// Read a DNS record
BUF *NnReadDnsRecord(BUF *buf, bool answer, USHORT *ret_type, USHORT *ret_class)
{
	USHORT type;
	USHORT clas;
	UINT ttl;
	BUF *ret = NULL;
	// Validate arguments
	if (buf == NULL)
	{
		return NULL;
	}

	// Read the DNS label
	if (NnReadDnsLabel(buf) == false)
	{
		return false;
	}

	// Type and Class
	if (ReadBuf(buf, &type, sizeof(USHORT)) != sizeof(USHORT))
	{
		return false;
	}

	if (ret_type != NULL)
	{
		*ret_type = Endian16(type);
	}

	if (ReadBuf(buf, &clas, sizeof(USHORT)) != sizeof(USHORT))
	{
		return false;
	}

	if (ret_class != NULL)
	{
		*ret_class = Endian16(clas);
	}

	if (answer)
	{
		USHORT data_len;
		UCHAR *data;

		// TTL
		if (ReadBuf(buf, &ttl, sizeof(UINT)) != sizeof(UINT))
		{
			return false;
		}

		// data_len
		if (ReadBuf(buf, &data_len, sizeof(USHORT)) != sizeof(USHORT))
		{
			return false;
		}

		data_len = Endian16(data_len);

		// data
		data = Malloc(data_len);
		if (ReadBuf(buf, data, data_len) != data_len)
		{
			Free(data);
			return false;
		}

		ret = NewBufFromMemory(data, data_len);

		Free(data);
	}
	else
	{
		ret = NewBuf();
	}

	return ret;
}

// Read the DNS label
bool NnReadDnsLabel(BUF *buf)
{
	UCHAR c;
	UCHAR tmp[256];
	// Validate arguments
	if (buf == NULL)
	{
		return false;
	}

LABEL_START:

	if (ReadBuf(buf, &c, 1) != 1)
	{
		return false;
	}

	if (c == 0)
	{
		return true;
	}

	if (c & 0xC0)
	{
		// Compression label
		if (ReadBuf(buf, &c, 1) != 1)
		{
			return false;
		}
		else
		{
			return true;
		}
	}
	else
	{
		// Usual label
		if (ReadBuf(buf, tmp, c) != c)
		{
			return false;
		}
		else
		{
			goto LABEL_START;
		}
	}

}

// Parse the DNS response packet
bool NnParseDnsResponsePacket(UCHAR *data, UINT size, IP *ret_ip)
{
	BUF *buf = NewBufFromMemory(data, size);
	bool ret = false;
	DNSV4_HEADER h;

	if (ReadBuf(buf, &h, sizeof(h)) == sizeof(h))
	{
		UINT num_questions = Endian16(h.NumQuery);
		UINT num_answers = Endian16(h.AnswerRRs);
		UINT i;

		for (i = 0; i < num_questions; i++)
		{
			BUF *r = NnReadDnsRecord(buf, false, NULL, NULL);

			if (r != NULL)
			{
				FreeBuf(r);
			}
			else
			{
				goto LABEL_CLEANUP;
			}
		}

		for (i = 0; i < num_answers; i++)
		{
			USHORT tp, cl;
			BUF *r = NnReadDnsRecord(buf, true, &tp, &cl);

			if (r != NULL)
			{
				if (tp == 0x0001 && cl == 0x0001 && r->Size == IPV4_SIZE)
				{
					ret = true;

					if (ret_ip != NULL)
					{
						ZeroIP4(ret_ip);
						Copy(IPV4(ret_ip->address), r->Buf, IPV4_SIZE);
					}
				}

				FreeBuf(r);
			}
			else
			{
				goto LABEL_CLEANUP;
			}
		}
	}

LABEL_CLEANUP:
	FreeBuf(buf);

	return ret;
}

// Test the connectivity of the stack to the Internet
bool NnTestConnectivity(NATIVE_STACK *a, TUBE *halt_tube)
{
	BUF *dns_query;
	BUF *dns_query2;
	bool ok = false;
	USHORT dns_tran_id = Rand16();
	UINT64 next_send_tick = 0;
	UINT64 giveup_time;
	IPC *ipc;
	INTERRUPT_MANAGER *interrupt;
	TUBE *tubes[3];
	UINT num_tubes = 0;
	IP yahoo_ip;
	IP my_priv_ip;
	UINT num_send_dns = 0;
	IP using_dns;
	UINT src_port = 0;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}

	src_port = NnGenSrcPort(a->IsIpRawMode);

	Copy(&using_dns, &a->DnsServerIP, sizeof(IP));

	// Get my physical IP
	if (a->IsIpRawMode)
	{
		if (GetMyPrivateIP(&my_priv_ip, false) == false)
		{
			Debug("NnTestConnectivity: GetMyPrivateIP failed.\n");
			return false;
		}
		else
		{
			Debug("NnTestConnectivity: GetMyPrivateIP ok: %r\n", &my_priv_ip);

			if (a->Eth != NULL)
			{
				Copy(&a->Eth->MyPhysicalIPForce, &my_priv_ip, sizeof(IP));
			}
		}
	}

	ipc = a->Ipc;
	interrupt = NewInterruptManager();

	tubes[num_tubes++] = ipc->Sock->RecvTube;
	tubes[num_tubes++] = ipc->Sock->SendTube;

	if (halt_tube != NULL)
	{
		tubes[num_tubes++] = halt_tube;
	}

	Zero(&yahoo_ip, sizeof(yahoo_ip));

	// Try to get an IP address of www.yahoo.com
	dns_query = NnBuildIpPacket(NnBuildUdpPacket(NnBuildDnsQueryPacket(NN_CHECK_HOSTNAME, dns_tran_id),
	                            IPToUINT(&ipc->ClientIPAddress), src_port, IPToUINT(&a->DnsServerIP), 53),
	                            IPToUINT(&ipc->ClientIPAddress), IPToUINT(&a->DnsServerIP), IP_PROTO_UDP, 0);

	dns_query2 = NnBuildIpPacket(NnBuildUdpPacket(NnBuildDnsQueryPacket(NN_CHECK_HOSTNAME, dns_tran_id),
	                             IPToUINT(&ipc->ClientIPAddress), src_port, IPToUINT(&a->DnsServerIP), 53),
	                             IPToUINT(&ipc->ClientIPAddress), IPToUINT(&a->DnsServerIP2), IP_PROTO_UDP, 0);

	giveup_time = Tick64() + NN_CHECK_CONNECTIVITY_TIMEOUT;
	AddInterrupt(interrupt, giveup_time);
	while (true)
	{
		UINT64 now = Tick64();

		IPCFlushArpTable(a->Ipc);

		if (now >= giveup_time)
		{
			break;
		}

		// Send a packet periodically
		if (next_send_tick == 0 || next_send_tick <= now)
		{
			next_send_tick = now + (UINT64)NN_CHECK_CONNECTIVITY_INTERVAL;

			AddInterrupt(interrupt, next_send_tick);

			if ((num_send_dns % 2) == 0)
			{
				IPCSendIPv4(ipc, dns_query->Buf, dns_query->Size);
			}
			else
			{
				IPCSendIPv4(ipc, dns_query2->Buf, dns_query2->Size);
			}

			num_send_dns++;
		}

		// Happy processing
		IPCProcessL3EventsIPv4Only(ipc);

		while (true)
		{
			// Receive a packet
			BLOCK *b = IPCRecvIPv4(ipc);
			PKT *pkt;

			if (b == NULL)
			{
				break;
			}

			// Parse the packet
			pkt = ParsePacketIPv4WithDummyMacHeader(b->Buf, b->Size);

			if (pkt != NULL)
			{
				if (pkt->TypeL3 == L3_IPV4 && pkt->TypeL4 == L4_UDP &&
				        (pkt->L3.IPv4Header->SrcIP == IPToUINT(&a->DnsServerIP) ||
				         pkt->L3.IPv4Header->SrcIP == IPToUINT(&a->DnsServerIP2)) &&
				        pkt->L3.IPv4Header->DstIP == IPToUINT(&ipc->ClientIPAddress) &&
				        pkt->L4.UDPHeader->SrcPort == Endian16(53) && pkt->L4.UDPHeader->DstPort == Endian16(src_port))
				{
					DNSV4_HEADER *dns_header = (DNSV4_HEADER *)pkt->Payload;
					if (pkt->PayloadSize >= sizeof(DNSV4_HEADER))
					{
						if (dns_header->TransactionId == Endian16(dns_tran_id))
						{
							IP ret_ip;

							if (NnParseDnsResponsePacket(pkt->Payload, pkt->PayloadSize, &ret_ip))
							{
								UINTToIP(&using_dns, pkt->L3.IPv4Header->SrcIP);
								Debug("NativeStack: Using DNS: %r\n", &using_dns);

								Copy(&yahoo_ip, &ret_ip, sizeof(IP));
							}
						}
					}
				}
			}

			FreePacketWithData(pkt);
			FreeBlock(b);
		}

		if ((halt_tube != NULL && IsTubeConnected(halt_tube) == false) ||
		        IsTubeConnected(ipc->Sock->SendTube) == false || IsTubeConnected(ipc->Sock->RecvTube) == false)
		{
			// Disconnected
			break;
		}

		if (IsZeroIP(&yahoo_ip) == false)
		{
			// There is a response
			break;
		}

		// Keep the CPU waiting
		WaitForTubes(tubes, num_tubes, GetNextIntervalForInterrupt(interrupt));
	}

	FreeBuf(dns_query);
	FreeBuf(dns_query2);

	if (IsZeroIP(&yahoo_ip) == false)
	{
		BUF *tcp_query;
		UINT seq = Rand32();
		bool tcp_get_response = false;
		UINT recv_seq = 0;

		// Since the IP address of www.yahoo.com has gotten, try to connect by TCP
		giveup_time = Tick64() + NN_CHECK_CONNECTIVITY_TIMEOUT;
		AddInterrupt(interrupt, giveup_time);

		// Generate a TCP packet
		tcp_query = NnBuildIpPacket(NnBuildTcpPacket(NewBuf(), IPToUINT(&ipc->ClientIPAddress), src_port,
		                            IPToUINT(&yahoo_ip), 80, seq, 0, TCP_SYN, 8192, 1414),
		                            IPToUINT(&ipc->ClientIPAddress), IPToUINT(&yahoo_ip), IP_PROTO_TCP, 0);

		Debug("Test TCP to %r\n", &yahoo_ip);

		next_send_tick = 0;

		while (true)
		{
			UINT64 now = Tick64();

			IPCFlushArpTable(a->Ipc);

			if (now >= giveup_time)
			{
				break;
			}

			// Send the packet periodically
			if (next_send_tick == 0 || next_send_tick <= now)
			{
				next_send_tick = now + (UINT64)NN_CHECK_CONNECTIVITY_INTERVAL;

				AddInterrupt(interrupt, next_send_tick);

				IPCSendIPv4(ipc, tcp_query->Buf, tcp_query->Size);
			}

			// Happy procedure
			IPCProcessL3EventsIPv4Only(ipc);

			while (true)
			{
				// Receive a packet
				BLOCK *b = IPCRecvIPv4(ipc);
				PKT *pkt;

				if (b == NULL)
				{
					break;
				}

				// Parse the packet
				pkt = ParsePacketIPv4WithDummyMacHeader(b->Buf, b->Size);

				if (pkt != NULL)
				{
					if (pkt->TypeL3 == L3_IPV4 && pkt->TypeL4 == L4_TCP &&
					        pkt->L3.IPv4Header->SrcIP == IPToUINT(&yahoo_ip) &&
					        pkt->L3.IPv4Header->DstIP == IPToUINT(&ipc->ClientIPAddress) &&
					        pkt->L4.TCPHeader->SrcPort == Endian16(80) && pkt->L4.TCPHeader->DstPort == Endian16(src_port))
					{
						TCP_HEADER *tcp_header = (TCP_HEADER *)pkt->L4.TCPHeader;
						if ((tcp_header->Flag & TCP_SYN) && (tcp_header->Flag & TCP_ACK))
						{
							// There was a TCP response
							tcp_get_response = true;
							recv_seq = Endian32(tcp_header->SeqNumber);
						}
					}
				}

				FreePacketWithData(pkt);
				FreeBlock(b);
			}

			if ((halt_tube != NULL && IsTubeConnected(halt_tube) == false) ||
			        IsTubeConnected(ipc->Sock->SendTube) == false || IsTubeConnected(ipc->Sock->RecvTube) == false)
			{
				// Disconnected
				break;
			}

			if (tcp_get_response)
			{
				WHERE;
				break;
			}

			// Keep the CPU waiting
			WaitForTubes(tubes, num_tubes, GetNextIntervalForInterrupt(interrupt));
		}

		FreeBuf(tcp_query);

		// Send a RST
		if (recv_seq != 0)
		{
			recv_seq++;
		}

		tcp_query = NnBuildIpPacket(NnBuildTcpPacket(NewBuf(), IPToUINT(&ipc->ClientIPAddress), src_port,
		                            IPToUINT(&yahoo_ip), 80, seq + 1, recv_seq, TCP_RST | TCP_ACK, 8192, 0),
		                            IPToUINT(&ipc->ClientIPAddress), IPToUINT(&yahoo_ip), IP_PROTO_TCP, 0);

		IPCSendIPv4(ipc, tcp_query->Buf, tcp_query->Size);

		FreeBuf(tcp_query);

		SleepThread(100);

		if (tcp_get_response)
		{
			ok = true;
		}
	}

	FreeInterruptManager(interrupt);

	if (ok)
	{
		if (IsZeroIP(&using_dns) == false)
		{
			Copy(&a->DnsServerIP, &using_dns, sizeof(IP));
		}

		if (a->IsIpRawMode)
		{
			if (NsStartIpTablesTracking(a) == false)
			{
				Debug("NsStartIpTablesTracking failed.\n");
				ok = false;
			}
		}
	}

	return ok;
}

// Generate source port number by a random number
UINT NnGenSrcPort(bool raw_ip_mode)
{
	if (raw_ip_mode == false)
	{
		return 1025 + Rand32() % (65500 - 1025);
	}
	else
	{
		return NN_RAW_IP_PORT_START + Rand32() % (NN_RAW_IP_PORT_END - NN_RAW_IP_PORT_START);
	}
}

// Get a next good interface for the native NAT
NATIVE_STACK *NnGetNextInterface(NATIVE_NAT *t)
{
	NATIVE_STACK *ret = NULL;
	UINT current_hash;
	TOKEN_LIST *device_list;
	UINT i;
	char tmp[MAX_SIZE];
	char *dev_name;
	UINT current_ip_hash;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	t->NextWaitTimeForRetry = NN_NEXT_WAIT_TIME_FOR_DEVICE_ENUM * MIN((t->FailedCount + 1), NN_NEXT_WAIT_TIME_MAX_FAIL_COUNT);

	// Get the device list
	device_list = GetEthListEx(NULL,
	                           !(t->v->HubOption != NULL && t->v->HubOption->DisableKernelModeSecureNAT),
	                           !(t->v->HubOption != NULL && t->v->HubOption->DisableIpRawModeSecureNAT));

	if (device_list == NULL || device_list->NumTokens == 0)
	{
		// Device list acquisition failure (Or no device acquired as a result)
		FreeToken(device_list);
		t->FailedCount++;
		return NULL;
	}

	current_hash = GetEthDeviceHash();
	current_ip_hash = GetHostIPAddressHash32();

	if (t->LastInterfaceDeviceHash != current_hash || t->LastHostAddressHash != current_ip_hash)
	{
		// Device list is altered from the previous search
		t->LastInterfaceIndex = INFINITE;
		t->FailedCount = 0;
	}

	t->LastInterfaceDeviceHash = current_hash;
	t->LastHostAddressHash = current_ip_hash;

	if (t->LastInterfaceIndex == INFINITE)
	{
		i = 0;
	}
	else
	{
		i = t->LastInterfaceIndex + 1;
		if (i >= device_list->NumTokens)
		{
			i = 0;
		}
	}

	if ((i + 1) == device_list->NumTokens)
	{
		// Searched to the end
		t->LastInterfaceIndex = INFINITE;

		// Increase the number of search failures by one
		t->FailedCount++;
	}
	else
	{
		// It is not the end yet
		t->LastInterfaceIndex = i;
		t->NextWaitTimeForRetry = 0;
	}

	dev_name = device_list->Token[i];

	if (IsInLinesFile(NN_NO_NATIVE_NAT_FILENAME, dev_name, true) == false)
	{
		// Try to open the device
		BinToStr(tmp, sizeof(tmp), t->v->MacAddress, 6);
		ret = NewNativeStack(NULL, dev_name, tmp);

		if (ret != NULL)
		{
			// Test whether an IP address can be obtained from a DHCP server
			DHCP_OPTION_LIST opt;

			Copy(t->CurrentMacAddress, ret->Ipc->MacAddress, 6);

			Zero(&opt, sizeof(opt));

			BinToStr(tmp, sizeof(tmp), ret->MacAddress, 6);
			Format(ret->Ipc->ClientHostname, sizeof(ret->Ipc->ClientHostname), NN_HOSTNAME_FORMAT, tmp);
			StrLower(ret->Ipc->ClientHostname);

			Debug("IPCDhcpAllocateIP for %s\n", ret->DeviceName);
			if (IPCDhcpAllocateIP(ret->Ipc, &opt, t->HaltTube2))
			{
				char client_ip[64];
				char dhcp_ip[64];
				char client_mask[64];
				char gateway_ip[64];

				IP ip;
				IP subnet;
				IP gw;

				IPToStr32(client_ip, sizeof(client_ip), opt.ClientAddress);
				IPToStr32(client_mask, sizeof(client_mask), opt.SubnetMask);
				IPToStr32(dhcp_ip, sizeof(dhcp_ip), opt.ServerAddress);
				IPToStr32(gateway_ip, sizeof(gateway_ip), opt.Gateway);

				Debug("DHCP: client_ip=%s, client_mask=%s, dhcp_ip=%s, gateway_ip=%s\n",
				      client_ip, client_mask, dhcp_ip, gateway_ip);

				Copy(&ret->CurrentDhcpOptionList, &opt, sizeof(DHCP_OPTION_LIST));

				// IP parameter settings
				UINTToIP(&ip, opt.ClientAddress);
				UINTToIP(&subnet, opt.SubnetMask);
				UINTToIP(&gw, opt.Gateway);

				IPCSetIPv4Parameters(ret->Ipc, &ip, &subnet, &gw, &opt.ClasslessRoute);

				// Determine the DNS server to use
				UINTToIP(&ret->DnsServerIP, opt.DnsServer);
				UINTToIP(&ret->DnsServerIP2, opt.DnsServer2);
				if (IsZeroIP(&ret->DnsServerIP))
				{
					// Use 8.8.8.8 instead If the DNS is not assigned from the DHCP server
					SetIP(&ret->DnsServerIP, 8, 8, 8, 8);
				}
				if (IsZeroIP(&ret->DnsServerIP2))
				{
					// Use 8.8.4.4 instead If the DNS is not assigned from the DHCP server
					SetIP(&ret->DnsServerIP2, 8, 8, 4, 4);
				}

				// Connectivity test
				// (always fail if the default gateway is not set)
				if (opt.Gateway != 0 &&
				        NnTestConnectivity(ret, t->HaltTube2))
				{
					// Reset the number of search failures
					t->FailedCount = 0;
					Debug("Connectivity OK.\n");
				}
				else
				{
					Debug("Connectivity Failed.\n");
					FreeNativeStack(ret);
					ret = NULL;
				}
			}
			else
			{
				Debug("DHCP Failed.\n");
				FreeNativeStack(ret);
				ret = NULL;

				Zero(t->CurrentMacAddress, sizeof(t->CurrentMacAddress));
			}
		}
	}

	FreeToken(device_list);

	return ret;
}

// Native NAT thread
void NativeNatThread(THREAD *thread, void *param)
{
	NATIVE_NAT *t = (NATIVE_NAT *)param;
	void *wait_handle = InitWaitUntilHostIPAddressChanged();
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (t->Halt == false)
	{
		NATIVE_STACK *a;

		while (t->v->UseNat == false || t->v->HubOption == NULL || (t->v->HubOption->DisableKernelModeSecureNAT && t->v->HubOption->DisableIpRawModeSecureNAT))
		{
			if (t->Halt)
			{
				break;
			}

			// If the NAT is disabled, wait until it becomes enabled
			Wait(t->HaltEvent, 1234);
		}

		if (t->Halt)
		{
			break;
		}

		// Get a next good native NAT stack
		Debug("NnGetNextInterface Start.\n");

		NnClearQueue(t);

		a = NnGetNextInterface(t);

		if (a != NULL)
		{
			char macstr[64];
			// Acquisition success
			Debug("NnGetNextInterface Ok: %s\n", a->DeviceName);

			t->IsRawIpMode = a->IsIpRawMode;

			Lock(t->Lock);
			{
				if (a->Sock1 != NULL)
				{
					t->HaltTube = a->Sock2->RecvTube;

					if (t->HaltTube != NULL)
					{
						AddRef(t->HaltTube->Ref);
					}
				}
			}
			Unlock(t->Lock);

			NnClearQueue(t);

			t->PublicIP = IPToUINT(&a->Ipc->ClientIPAddress);
			t->Active = true;


			Debug("NnMainLoop Start.\n");
			MacToStr(macstr, sizeof(macstr), a->Ipc->MacAddress);
			NLog(t->v, "LH_KERNEL_MODE_START", a->DeviceName,
			     &a->Ipc->ClientIPAddress, &a->Ipc->SubnetMask, &a->Ipc->DefaultGateway, &a->Ipc->BroadcastAddress,
			     macstr, &a->CurrentDhcpOptionList.ServerAddress, &a->DnsServerIP);
			NnMainLoop(t, a);
			Debug("NnMainLoop End.\n");

			t->IsRawIpMode = false;

			t->Active = false;
			t->PublicIP = 0;


			NnClearQueue(t);

			// Close the stack
			Lock(t->Lock);
			{
				if (t->HaltTube != NULL)
				{
					ReleaseTube(t->HaltTube);
					t->HaltTube = NULL;
				}
			}
			Unlock(t->Lock);
			FreeNativeStack(a);

			Zero(t->CurrentMacAddress, 6);
		}
		else
		{
			Debug("NnGetNextInterface Failed.\n");
		}

		// Wait for a certain period of time
		if (t->NextWaitTimeForRetry != 0)
		{
			WaitUntilHostIPAddressChanged(wait_handle, t->HaltEvent, t->NextWaitTimeForRetry, 1000);
		}
	}

	FreeWaitUntilHostIPAddressChanged(wait_handle);
}

// Erase the contents of the queue for transmission and reception
void NnClearQueue(NATIVE_NAT *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	LockQueue(t->SendQueue);
	{
		while (true)
		{
			BLOCK *b = GetNext(t->SendQueue);

			if (b == NULL)
			{
				break;
			}

			FreeBlock(b);
		}
	}
	UnlockQueue(t->SendQueue);

	LockQueue(t->RecvQueue);
	{
		while (true)
		{
			PKT *p = GetNext(t->RecvQueue);

			if (p == NULL)
			{
				break;
			}

			FreePacketWithData(p);
		}
	}
	UnlockQueue(t->RecvQueue);
}

// Structure setting function to search for native NAT
void NnSetNat(NATIVE_NAT_ENTRY *e, UINT protocol, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT pub_ip, UINT pub_port)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	Zero(e, sizeof(NATIVE_NAT_ENTRY));

	e->Protocol = protocol;
	e->SrcIp = src_ip;
	e->SrcPort = src_port;
	e->DestIp = dest_ip;
	e->DestPort = dest_port;
	e->PublicIp = pub_ip;
	e->PublicPort = pub_port;
	e->HashCodeForSend = e->HashCodeForRecv = INFINITE;
}

// Get the hash code of the native NAT table (receiving direction)
UINT GetHashNativeNatTableForRecv(void *p)
{
	UINT r;
	NATIVE_NAT_ENTRY *e = (NATIVE_NAT_ENTRY *)p;
	if (e == NULL)
	{
		return 0;
	}

	if (e->HashCodeForRecv != INFINITE)
	{
		return e->HashCodeForRecv;
	}

	r = 0;

	r += e->Protocol;
	r += e->PublicIp;
	r += e->PublicPort;

	if (e->Protocol == NAT_TCP)
	{
		r += e->DestIp;
		r += e->DestPort;
	}

	e->HashCodeForRecv = r;

	return r;
}

// Comparison function of native NAT table (receiving direction)
int CmpNativeNatTableForRecv(void *p1, void *p2)
{
	int r;
	NATIVE_NAT_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(NATIVE_NAT_ENTRY **)p1;
	e2 = *(NATIVE_NAT_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}

	r = COMPARE_RET(e1->Protocol, e2->Protocol);
	if (r != 0)
	{
		return r;
	}

	r = COMPARE_RET(e1->PublicIp, e2->PublicIp);
	if (r != 0)
	{
		return r;
	}

	r = COMPARE_RET(e1->PublicPort, e2->PublicPort);
	if (r != 0)
	{
		return r;
	}

	if (e1->Protocol == NAT_TCP)
	{
		r = COMPARE_RET(e1->DestIp, e2->DestIp);
		if (r != 0)
		{
			return r;
		}

		r = COMPARE_RET(e1->DestPort, e2->DestPort);
		if (r != 0)
		{
			return r;
		}
	}

	return 0;
}

// Get the hash code of the native NAT table (transmit direction)
UINT GetHashNativeNatTableForSend(void *p)
{
	UINT r;
	NATIVE_NAT_ENTRY *e = (NATIVE_NAT_ENTRY *)p;
	if (e == NULL)
	{
		return 0;
	}

	if (e->HashCodeForSend != INFINITE)
	{
		return e->HashCodeForSend;
	}

	r = 0;

	r += e->Protocol;
	r += e->SrcIp;
	r += e->SrcPort;

	if (e->Protocol == NAT_TCP)
	{
		r += e->DestIp;
		r += e->DestPort;
	}

	e->HashCodeForSend = r;

	return r;
}

// Comparison function of native NAT table (transmit direction)
int CmpNativeNatTableForSend(void *p1, void *p2)
{
	int r;
	NATIVE_NAT_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(NATIVE_NAT_ENTRY **)p1;
	e2 = *(NATIVE_NAT_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}

	r = COMPARE_RET(e1->Protocol, e2->Protocol);
	if (r != 0)
	{
		return r;
	}

	r = COMPARE_RET(e1->SrcIp, e2->SrcIp);
	if (r != 0)
	{
		return r;
	}

	r = COMPARE_RET(e1->SrcPort, e2->SrcPort);
	if (r != 0)
	{
		return r;
	}

	if (e1->Protocol == NAT_TCP)
	{
		r = COMPARE_RET(e1->DestIp, e2->DestIp);
		if (r != 0)
		{
			return r;
		}

		r = COMPARE_RET(e1->DestPort, e2->DestPort);
		if (r != 0)
		{
			return r;
		}
	}

	return 0;
}

// Start the native NAT
NATIVE_NAT *NewNativeNat(VH *v)
{
	NATIVE_NAT *t;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(NATIVE_NAT));

	t->v = v;

	t->Cancel = v->Cancel;
	AddRef(t->Cancel->ref);

	// Data structure initialization
	t->LastInterfaceIndex = INFINITE;
	t->SendQueue = NewQueue();
	t->RecvQueue = NewQueue();
	NnInitIpCombineList(t);

	t->Lock = NewLock();

	t->CancelLock = NewLock();

	t->HaltEvent = NewEvent();

	NewTubePair(&t->HaltTube2, &t->HaltTube3, 0);

	// Create a NAT table
	t->NatTableForSend = NewHashList(GetHashNativeNatTableForSend, CmpNativeNatTableForSend, 11, true);
	t->NatTableForRecv = NewHashList(GetHashNativeNatTableForRecv, CmpNativeNatTableForRecv, 11, true);

	t->Thread = NewThread(NativeNatThread, t);

	return t;
}

// Stop the native NAT
void FreeNativeNat(NATIVE_NAT *t)
{
	TUBE *tube;
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	t->Halt = true;

	Lock(t->Lock);
	{
		tube = t->HaltTube;

		if (tube != NULL)
		{
			AddRef(tube->Ref);
		}
	}
	Unlock(t->Lock);

	if (tube != NULL)
	{
		TubeFlushEx(tube, true);

		SleepThread(100);

		TubeDisconnect(tube);

		ReleaseTube(tube);
	}

	TubeDisconnect(t->HaltTube2);
	TubeDisconnect(t->HaltTube3);

	Set(t->HaltEvent);

	WaitThread(t->Thread, INFINITE);

	ReleaseThread(t->Thread);

	DeleteLock(t->Lock);

	DeleteLock(t->CancelLock);

	ReleaseEvent(t->HaltEvent);

	ReleaseTube(t->HaltTube2);
	ReleaseTube(t->HaltTube3);

	NnClearQueue(t);

	ReleaseQueue(t->RecvQueue);
	ReleaseQueue(t->SendQueue);

	ReleaseCancel(t->Cancel);

	// Release the NAT table
	for (i = 0; i < LIST_NUM(t->NatTableForSend->AllList); i++)
	{
		NATIVE_NAT_ENTRY *e = LIST_DATA(t->NatTableForSend->AllList, i);

		Free(e);
	}

	ReleaseHashList(t->NatTableForSend);
	ReleaseHashList(t->NatTableForRecv);

	NnFreeIpCombineList(t);

	Free(t);
}

// Take the log of Virtual Host
void VLog(VH *v, char *str)
{
	// Not take!!
	return;
}

// Disconnect the NAT entry immediately
void DisconnectNatEntryNow(VH *v, NAT_ENTRY *e)
{
	// Validate arguments
	if (v == NULL || e == NULL)
	{
		return;
	}

	if (e->DisconnectNow == false)
	{
		e->DisconnectNow = true;

		SetSockEvent(v->SockEvent);
	}
}

// Get the NAT entry with specified source IP address and the oldest last communication time
NAT_ENTRY *GetOldestNatEntryOfIp(VH *v, UINT ip, UINT protocol)
{
	UINT i;
	NAT_ENTRY *oldest = NULL;
	UINT64 oldest_tick = 0xFFFFFFFFFFFFFFFFULL;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(v->NatTable); i++)
	{
		NAT_ENTRY *e = LIST_DATA(v->NatTable, i);

		if (e->DisconnectNow == false)
		{
			if (e->SrcIp == ip)
			{
				if (e->Protocol == protocol)
				{
					if (protocol != NAT_TCP || e->TcpStatus != NAT_TCP_CONNECTING)
					{
						if (e->LastCommTime <= oldest_tick)
						{
							oldest_tick = e->LastCommTime;
							oldest = e;
						}
					}
				}
			}
		}
	}

	return oldest;
}

// Get the number of current NAT entries per IP address
UINT GetNumNatEntriesPerIp(VH *v, UINT ip, UINT protocol, bool tcp_syn_sent)
{
	UINT ret = 0;
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return 0;
	}

	for (i = 0; i < LIST_NUM(v->NatTable); i++)
	{
		NAT_ENTRY *e = LIST_DATA(v->NatTable, i);

		if (e->DisconnectNow == false)
		{
			if (e->SrcIp == ip)
			{
				if (e->Protocol == protocol)
				{
					bool ok = false;

					if (protocol == NAT_TCP)
					{
						if (tcp_syn_sent)
						{
							if (e->TcpStatus == NAT_TCP_CONNECTING)
							{
								ok = true;
							}
						}
						else
						{
							if (e->TcpStatus != NAT_TCP_CONNECTING)
							{
								ok = true;
							}
						}
					}
					else
					{
						ok = true;
					}

					if (ok)
					{
						ret++;
					}
				}
			}
		}
	}

	return ret;
}

// Check whether the NAT is available
bool CanCreateNewNatEntry(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return false;
	}

	if (v->UseNat == false)
	{
		// NAT stopped
		return false;
	}

	if (NnIsActive(v) && v->NativeNat != NULL && v->NativeNat->NatTableForRecv != NULL)
	{
		if (v->NativeNat->NatTableForRecv->AllList->num_item > NAT_MAX_SESSIONS_KERNEL)
		{
			// Number of sessions exceeded (kernel mode)
			return false;
		}
	}
	else
	{
		if (v->NatTable->num_item > NAT_MAX_SESSIONS)
		{
			// Number of sessions exceeded (user mode)
			return false;
		}
	}

	return true;
}

// Set a pointer to the Virtual HUB options
void NatSetHubOption(VH *v, HUB_OPTION *o)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	v->HubOption = o;
}

// Get a pointer to the Virtual HUB options
HUB_OPTION *NatGetHubOption(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	return v->HubOption;
}

// The main function of NAT processing thread
void NatThreadMain(VH *v)
{
	bool halt_flag;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	v->TmpBuf = Malloc(NAT_TMPBUF_SIZE);

	while (true)
	{
		// Wait until the next event is set
		WaitSockEvent(v->SockEvent, SELECT_TIME);

		halt_flag = false;

		LockVirtual(v);
		{
			// Process on all NAT sessions
			UINT i, num;

			v->Now = Tick64();
			v->NatDoCancelFlag = false;

LIST_ELEMENT_DELETED:
			num = LIST_NUM(v->NatTable);
			for (i = 0; i < num; i++)
			{
				NAT_ENTRY *n = LIST_DATA(v->NatTable, i);

				switch (n->Protocol)
				{
				case NAT_TCP:		// TCP
					if (NatTransactTcp(v, n) == false)
					{
						goto LIST_ELEMENT_DELETED;
					}
					break;

				case NAT_UDP:		// UDP
					if (NatTransactUdp(v, n) == false)
					{
						goto LIST_ELEMENT_DELETED;
					}
					break;

				case NAT_ICMP:		// ICMP
					if (NatTransactIcmp(v, n) == false)
					{
						goto LIST_ELEMENT_DELETED;
					}
					break;

				case NAT_DNS:		// DNS
					if (NatTransactDns(v, n) == false)
					{
						goto LIST_ELEMENT_DELETED;
					}
					break;
				}
			}

			if (v->NatDoCancelFlag)
			{
				// Hit the cancel of the parent thread
				Cancel(v->Cancel);
			}

			// Halting flag check
			if (v->HaltNat)
			{
				halt_flag = true;
			}
		}
		UnlockVirtual(v);

		if (halt_flag)
		{
			// Terminate the thread by disconnecting all entries forcibly
			LockVirtual(v);
			{
				UINT num = LIST_NUM(v->NatTable);
				NAT_ENTRY **nn = ToArray(v->NatTable);
				UINT i;

				for (i = 0; i < num; i++)
				{
					NAT_ENTRY *n = nn[i];
					n->DisconnectNow = true;

					switch (n->Protocol)
					{
					case NAT_TCP:		// TCP
						NatTransactTcp(v, n);
						break;

					case NAT_UDP:		// UDP
						NatTransactUdp(v, n);
						break;

					case NAT_ICMP:		// ICMP
						NatTransactIcmp(v, n);
						break;

					case NAT_DNS:		// DNS
						NatTransactDns(v, n);
						break;
					}
				}

				Free(nn);
			}
			UnlockVirtual(v);
			break;
		}
	}

	Free(v->TmpBuf);
}

// DNS: Thread to get the IP address
void NatGetIPThread(THREAD *t, void *param)
{
	NAT_DNS_QUERY *q;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	q = (NAT_DNS_QUERY *)param;
	AddWaitThread(t);

	q->Ok = GetIP(&q->Ip, q->Hostname);

	DelWaitThread(t);

	if (Release(q->ref) == 0)
	{
		Free(q);
	}
}

// DNS: Get an IP address from host name
bool NatGetIP(IP *ip, char *hostname)
{
	TOKEN_LIST *t;
	bool ret = false;
	// Validate arguments
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	t = ParseToken(hostname, ".");
	if (t == NULL)
	{
		return false;
	}
	if (t->NumTokens == 0)
	{
		FreeToken(t);
		return false;
	}

	if (t->NumTokens == 1)
	{
		ret = GetIP(ip, hostname);
	}
	else
	{
		char *hostname2 = t->Token[0];
		NAT_DNS_QUERY *q1, *q2;
		THREAD *t1, *t2;

		q1 = ZeroMalloc(sizeof(NAT_DNS_QUERY));
		q2 = ZeroMalloc(sizeof(NAT_DNS_QUERY));
		q1->ref = NewRef();
		q2->ref = NewRef();
		AddRef(q1->ref);
		AddRef(q2->ref);
		StrCpy(q1->Hostname, sizeof(q1->Hostname), hostname);
		StrCpy(q2->Hostname, sizeof(q2->Hostname), hostname2);

		t1 = NewThread(NatGetIPThread, q1);
		t2 = NewThread(NatGetIPThread, q2);

		WaitThread(t1, NAT_DNS_QUERY_TIMEOUT);

		if (q1->Ok)
		{
			ret = true;
			Copy(ip, &q1->Ip, sizeof(IP));
		}
		else
		{
			WaitThread(t2, NAT_DNS_QUERY_TIMEOUT);
			if (q1->Ok)
			{
				ret = true;
				Copy(ip, &q1->Ip, sizeof(IP));
			}
			else if (q2->Ok)
			{
				ret = true;
				Copy(ip, &q2->Ip, sizeof(IP));
			}
		}

		ReleaseThread(t1);
		ReleaseThread(t2);

		if (Release(q1->ref) == 0)
		{
			Free(q1);
		}
		if (Release(q2->ref) == 0)
		{
			Free(q2);
		}
	}

	FreeToken(t);

	return ret;
}

// DNS query function
void NatDnsThread(THREAD *t, void *param)
{
	NAT_ENTRY *n;
	IP ip;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}
	n = (NAT_ENTRY *)param;

	// Notify the initialization completion
	NoticeThreadInit(t);

	// Run processing
	if (EndWith(n->DnsTargetHostName, ".in-addr.arpa") == false)
	{
		// Forward resolution
		if (NatGetIP(&ip, n->DnsTargetHostName))
		{
			// Forward resolution success
			Copy(&n->DnsResponseIp, &ip, sizeof(IP));
			n->DnsOk = true;
		}
	}
	else
	{
		// Reverse resolution
		IP ip;
		n->DnsGetIpFromHost = true;		// Set the reverse resolution flag
		// Convert a *.in-addr.arpa string to an IP address
		if (ArpaToIP(&ip, n->DnsTargetHostName))
		{
			// Reverse resolution process
			char tmp[256];
			if (GetHostName(tmp, sizeof(tmp), &ip))
			{
				// Reverse resolution success
				n->DnsResponseHostName = CopyStr(tmp);
				n->DnsOk = true;
			}
		}
	}

	// Notify the results
	n->DnsFinished = true;

	SetSockEvent(n->v->SockEvent);
}

// Convert a reverse resolution address to an IP address
bool ArpaToIP(IP *ip, char *str)
{
	TOKEN_LIST *token;
	bool ret = false;
	// Validate arguments
	if (ip == NULL || str == NULL)
	{
		return false;
	}

	// Token conversion
	token = ParseToken(str, ".");
	if (token->NumTokens == 6)
	{
		// Convert the token [0, 1, 2, 3] to IP
		UINT i;
		ZeroIP4(ip);
		for (i = 0; i < IPV4_SIZE; ++i)
		{
			IPV4(ip->address)[i] = (UCHAR)ToInt(token->Token[3 - i]);
		}
		ret = true;
	}

	FreeToken(token);

	if (IPToUINT(ip) == 0)
	{
		ret = false;
	}

	return ret;
}

// Handle a DNS entry
bool NatTransactDns(VH *v, NAT_ENTRY *n)
{
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return true;
	}

	if (n->DisconnectNow)
	{
		goto DISCONNECT;
	}

	if (n->DnsThread == NULL && n->DnsFinished == false)
	{
		// Create a thread
		THREAD *t = NewThread(NatDnsThread, (void *)n);
		WaitThreadInit(t);
		n->DnsThread = t;
	}
	else
	{
		// Wait for the result
		if (n->DnsFinished)
		{
			// Results have been received
			WaitThread(n->DnsThread, INFINITE);
			ReleaseThread(n->DnsThread);
			n->DnsThread = NULL;
			// Notify to the main thread
			v->NatDoCancelFlag = true;
		}
	}

	return true;

DISCONNECT:

	// Releasing process
	if (n->DnsThread != NULL)
	{
		WaitThread(n->DnsThread, INFINITE);
		ReleaseThread(n->DnsThread);
		n->DnsThread = NULL;
	}

	if (n->DnsTargetHostName != NULL)
	{
		Free(n->DnsTargetHostName);
		n->DnsTargetHostName = NULL;
	}

	if (n->DnsResponseHostName != NULL)
	{
		Free(n->DnsResponseHostName);
		n->DnsResponseHostName = NULL;
	}

	DeleteLock(n->lock);
	Delete(v->NatTable, n);
	Free(n);

	return false;
}

// ICMP thread procedure
void NatIcmpThreadProc(THREAD *thread, void *param)
{
	NAT_ENTRY *n;
	ICMP_RESULT *ret = NULL;
	USHORT src_id = 0, src_seqno = 0;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	n = (NAT_ENTRY *)param;

	if (n->IcmpQueryBlock)
	{
		UCHAR *data = n->IcmpQueryBlock->Buf;
		UINT size = n->IcmpQueryBlock->Size;

		if (size >= (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO)))
		{
			ICMP_HEADER *icmp = (ICMP_HEADER *)data;
			ICMP_ECHO *echo = (ICMP_ECHO *)(data + sizeof(ICMP_HEADER));

			if (icmp->Type == ICMP_TYPE_ECHO_REQUEST && icmp->Code == 0)
			{
				UCHAR *icmp_payload = data + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO);
				UINT icmp_payload_size = size - sizeof(ICMP_HEADER) - sizeof(ICMP_ECHO);
				IP dest_ip;

				src_id = Endian16(echo->Identifier);
				src_seqno = Endian16(echo->SeqNo);

				UINTToIP(&dest_ip, n->DestIp);

				// Send a query by using the ICMP API
				ret = IcmpApiEchoSend(&dest_ip, n->IcmpQueryBlock->Ttl,
				                      icmp_payload, icmp_payload_size, NAT_ICMP_TIMEOUT_WITH_API);
			}
		}
	}

	if (ret != NULL && ret->Timeout == false)
	{
		// Convert to an IPv4 + ICMP packet since the result of ICMP API was obtained
		IPV4_HEADER ipv4;
		ICMP_HEADER icmp;
		ICMP_ECHO echo;
		BUF *buf = NewBuf();

		// IPv4 header
		Zero(&ipv4, sizeof(ipv4));
		IPV4_SET_VERSION(&ipv4, 4);
		IPV4_SET_HEADER_LEN(&ipv4, sizeof(IPV4_HEADER) / 4);
		ipv4.TimeToLive = ret->Ttl;
		ipv4.Protocol = IP_PROTO_ICMPV4;
		ipv4.SrcIP = IPToUINT(&ret->IpAddress);
		ipv4.DstIP = 0x01010101;


		// ICMP header
		Zero(&icmp, sizeof(icmp));
		Zero(&echo, sizeof(echo));

		if (ret->Ok)
		{
			// Normal response
			echo.Identifier = Endian16(src_id);
			echo.SeqNo = Endian16(src_seqno);

			ipv4.TotalLength = Endian16((USHORT)(sizeof(ipv4) + sizeof(icmp) + sizeof(echo) + ret->DataSize));

			WriteBuf(buf, &ipv4, sizeof(ipv4));
			WriteBuf(buf, &icmp, sizeof(icmp));
			WriteBuf(buf, &echo, sizeof(echo));
			WriteBuf(buf, ret->Data, ret->DataSize);
		}
		else
		{
			// Error reply
			icmp.Type = ret->Type;
			icmp.Code = ret->Code;
			echo.Identifier = Endian16(src_id);
			echo.SeqNo = Endian16(src_seqno);

			ipv4.TotalLength = Endian16((USHORT)(sizeof(ipv4) + sizeof(icmp) + sizeof(echo) + n->IcmpOriginalCopySize));

			WriteBuf(buf, &ipv4, sizeof(ipv4));
			WriteBuf(buf, &icmp, sizeof(icmp));
			WriteBuf(buf, &echo, sizeof(echo));

			// Copy of the original packet to be included in the response packet
			WriteBuf(buf, n->IcmpOriginalCopy, n->IcmpOriginalCopySize);
		}

		n->IcmpResponseBlock = NewBlock(Clone(buf->Buf, buf->Size), buf->Size, 0);
		n->IcmpResponseBlock->Ttl = ret->Ttl;

		FreeBuf(buf);
	}
	IcmpApiFreeResult(ret);

	// Inform the completion of the processing
	n->IcmpTaskFinished = true;
	SetSockEvent(n->v->SockEvent);
}

// Process ICMP entry
bool NatTransactIcmp(VH *v, NAT_ENTRY *n)
{
	void *buf;
	UINT recv_size;
	BLOCK *block;
	IP dest_ip;
	UINT num_ignore_errors = 0;
	UINT dest_port = 0;
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return true;
	}

	dest_port = n->DestPort;

	if (n->DisconnectNow)
	{
		goto DISCONNECT;
	}

	if (v->IcmpRawSocketOk)
	{
		// Environment that the Raw sockets are available
		if (n->UdpSocketCreated == false)
		{
			// Create a UDP socket
			n->Sock = NewUDP(MAKE_SPECIAL_PORT(IP_PROTO_ICMPV4));
			if (n->Sock == NULL)
			{
				// Socket creation failure
				goto DISCONNECT;
			}
			else
			{
				n->PublicIp = IPToUINT(&n->Sock->LocalIP);
				n->PublicPort = n->Sock->LocalPort;

				JoinSockToSockEvent(n->Sock, v->SockEvent);
				n->UdpSocketCreated = true;
			}
		}
	}
	else
	{
		// Create a thread for using ICMP API if Raw sockets are not available
		if (n->IcmpThread == NULL)
		{
			if (n->UdpSendQueue->num_item >= 1)
			{
				// Since UdpSendQueue contains only 1 query, get a first query
				// and create a thread and pass the query to the thread
				BLOCK *block = GetNext(n->UdpSendQueue);

				n->IcmpQueryBlock = block;

				n->IcmpThread = NewThread(NatIcmpThreadProc, n);
			}
		}

		if (n->IcmpTaskFinished)
		{
			if (n->IcmpResponseBlock != NULL)
			{
				// Because there was a response from the thread that calls ICMP API, pass this result to the stack
				block = n->IcmpResponseBlock;
				n->IcmpResponseBlock = NULL;
				InsertQueue(n->UdpRecvQueue, block);
				v->NatDoCancelFlag = true;
				n->LastCommTime = v->Now;
			}
			else
			{
				// Disconnect immediately when it fails
				goto DISCONNECT;
			}
		}

		// Examine whether this session timed-out
		if ((n->LastCommTime + (UINT64)NAT_ICMP_TIMEOUT_WITH_API) < v->Now || n->LastCommTime > v->Now)
		{
			// Time-out
			goto DISCONNECT;
		}

		return true;
	}

	// Following are processed only for if the raw sockets are available
	buf = v->TmpBuf;
	UINTToIP(&dest_ip, n->DestIp);

	// Try to receive data from the UDP socket
	while (true)
	{
		IP src_ip;
		UINT src_port;
		recv_size = RecvFrom(n->Sock, &src_ip, &src_port, buf, 65536);

		if (recv_size == SOCK_LATER)
		{
			// Packet has not arrived
			break;
		}
		else if (recv_size == 0)
		{
			Debug("ICMP ERROR\n");
			// Error?
			if (n->Sock->IgnoreRecvErr == false)
			{
				// A fatal error occurred
				goto DISCONNECT;
			}
			else
			{
				if ((num_ignore_errors++) >= MAX_NUM_IGNORE_ERRORS)
				{
					goto DISCONNECT;
				}
			}
		}
		else
		{
			// Analyze the arriving packet
			ICMP_RESULT *ret = IcmpParseResult(&dest_ip, n->SrcPort, 0, buf, recv_size);

			if (ret != NULL)
			{
				if ((ret->Ok && CmpIpAddr(&ret->IpAddress, &dest_ip) == 0) ||
				        (ret->DataSize >= sizeof(IPV4_HEADER) && ((IPV4_HEADER *)ret->Data)->DstIP == n->DestIp))
				{
					// Insert to the queue
					void *data = Malloc(recv_size);
					Copy(data, buf, recv_size);
					block = NewBlock(data, recv_size, 0);
					InsertQueue(n->UdpRecvQueue, block);
					v->NatDoCancelFlag = true;
					n->LastCommTime = v->Now;
				}

				IcmpFreeResult(ret);
			}
		}
	}

	// Try to send data to the UDP socket
	while (block = GetNext(n->UdpSendQueue))
	{
		// Assemble the Echo header and ICMP header
		UINT send_size;

		SetTtl(n->Sock, block->Ttl);
		send_size = SendTo(n->Sock, &dest_ip, dest_port, block->Buf, block->Size);

		FreeBlock(block);
		if (send_size == 0)
		{
			Debug("ICMP ERROR\n");
			// Determine whether a fatal error
			if (n->Sock->IgnoreSendErr == false)
			{
				// A fatal error occurred
				goto DISCONNECT;
			}
		}
		else
		{
			n->LastCommTime = v->Now;
		}
	}

	// Examine whether this session timed-out
	if ((n->LastCommTime + (UINT64)NAT_ICMP_TIMEOUT) < v->Now || n->LastCommTime > v->Now)
	{
		// Time-out
		goto DISCONNECT;
	}

	return true;

DISCONNECT:
	// Disconnect this session
	if (n->UdpSocketCreated)
	{
		// Close the socket
		Disconnect(n->Sock);
		ReleaseSock(n->Sock);
		n->Sock = NULL;
	}

	// Terminate if the thread has been created
	if (n->IcmpThread != NULL)
	{
		WaitThread(n->IcmpThread, INFINITE);
		ReleaseThread(n->IcmpThread);
		n->IcmpThread = NULL;
	}

	// Delete the entry
	DeleteNatIcmp(v, n);

	return false;
}

// Process the UDP entry
bool NatTransactUdp(VH *v, NAT_ENTRY *n)
{
	void *buf;
	UINT recv_size;
	BLOCK *block;
	IP dest_ip;
	UINT num_ignore_errors;
	UINT dest_port = 0;
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return true;
	}

	dest_port = n->DestPort;

	if (n->DisconnectNow)
	{
		goto DISCONNECT;
	}

	if (n->UdpSocketCreated == false)
	{
		// Create a UDP socket
		n->Sock = NewUDP(0);
		if (n->Sock == NULL)
		{
			// Socket creation failure
			goto DISCONNECT;
		}
		else
		{
			n->PublicIp = IPToUINT(&n->Sock->LocalIP);
			n->PublicPort = n->Sock->LocalPort;

			JoinSockToSockEvent(n->Sock, v->SockEvent);
			n->UdpSocketCreated = true;
		}
	}

	buf = v->TmpBuf;
	if (n->ProxyDns == false)
	{
		UINTToIP(&dest_ip, n->DestIp);
	}
	else
	{
		UINTToIP(&dest_ip, n->DestIpProxy);
	}

	num_ignore_errors = 0;

	// Try to receive data from the UDP socket
	while (true)
	{
		IP src_ip;
		UINT src_port;
		recv_size = RecvFrom(n->Sock, &src_ip, &src_port, buf, 65536);

		if (recv_size == SOCK_LATER)
		{
			// Packet has not arrived
			break;
		}
		else if (recv_size == 0)
		{
			// Error?
			if (n->Sock->IgnoreRecvErr == false)
			{
				// A fatal error occurred
				goto DISCONNECT;
			}
			else
			{
				if ((num_ignore_errors++) > MAX_NUM_IGNORE_ERRORS)
				{
					goto DISCONNECT;
				}
			}
		}
		else
		{
			// Packet arrives. Check the source IP
			if (IPToUINT(&src_ip) == n->DestIp || n->DestIp == 0xFFFFFFFF || (IPToUINT(&src_ip) == n->DestIpProxy && n->ProxyDns) && src_port == n->DestPort)
			{
				// Insert to the queue
				void *data = Malloc(recv_size);
				Copy(data, buf, recv_size);
				block = NewBlock(data, recv_size, 0);

				if (block != NULL)
				{
					if (src_port == SPECIAL_UDP_PORT_WSD || src_port == SPECIAL_UDP_PORT_SSDP)
					{
						// Make believe there is a response from the host really in the case of WSD packet
						block->Param1 = IPToUINT(&src_ip);
					}
				}

				InsertQueue(n->UdpRecvQueue, block);
				v->NatDoCancelFlag = true;
				n->LastCommTime = v->Now;
			}
		}
	}

	// Try to send data to the UDP socket
	while (block = GetNext(n->UdpSendQueue))
	{
		UINT send_size;
		bool is_nbtdgm = false;
		LIST *local_ip_list = NULL;

		if (dest_port == SPECIAL_UDP_PORT_NBTDGM)
		{
			// Determine whether NetBIOS Datagram packet
			NBTDG_HEADER *nh = (NBTDG_HEADER *)block->Buf;

			if (nh != NULL && block->Size >= sizeof(NBTDG_HEADER))
			{
				if (nh->SrcIP == n->SrcIp && Endian16(nh->SrcPort) == n->SrcPort)
				{
					local_ip_list = GetHostIPAddressList();

					if (local_ip_list != NULL)
					{
						is_nbtdgm = true;
					}
				}
			}
		}

		if (is_nbtdgm == false)
		{
			// Normal UDP packet
			send_size = SendTo(n->Sock, &dest_ip, dest_port, block->Buf, block->Size);
		}
		else
		{
			// IP address and port number is embedded in the NetBIOS Datagram Packet.
			// Transfer by rewriting it properly
			UINT i;

			for (i = 0; i < LIST_NUM(local_ip_list); i++)
			{
				IP *my_ip = LIST_DATA(local_ip_list, i);

				if (IsIP4(my_ip) && IsZeroIp(my_ip) == false && IsLocalHostIP(my_ip) == false)
				{
					NBTDG_HEADER *nh = (NBTDG_HEADER *)block->Buf;

					nh->SrcIP = IPToUINT(my_ip);
					nh->SrcPort = Endian16(n->PublicPort);

					send_size = SendTo(n->Sock, &dest_ip, dest_port, block->Buf, block->Size);
				}
			}
		}

		if (local_ip_list != NULL)
		{
			FreeHostIPAddressList(local_ip_list);
		}

		FreeBlock(block);
		if (send_size == 0)
		{
			// Determining whether a fatal error
			if (n->Sock->IgnoreSendErr == false)
			{
				// A fatal error occurred
				goto DISCONNECT;
			}
		}
		else
		{
			n->LastCommTime = v->Now;
		}
	}

	// Examine whether this session timed-out
	if ((n->LastCommTime + (UINT64)v->NatUdpTimeout) < v->Now || n->LastCommTime > v->Now)
	{
		// Time-out
		goto DISCONNECT;
	}

	return true;

DISCONNECT:
	// Disconnect this session
	if (n->UdpSocketCreated)
	{
		// Close the socket
		Disconnect(n->Sock);
		ReleaseSock(n->Sock);
		n->Sock = NULL;
	}

	// Delete the entry
	DeleteNatUdp(v, n);

	return false;
}

// Thread to make a connection to the TCP host
void NatTcpConnectThread(THREAD *t, void *p)
{
	NAT_ENTRY *n = (NAT_ENTRY *)p;
	IP ip;
	char hostname[MAX_SIZE];
	UINT port_number;
	SOCK *sock;
	SOCK_EVENT *e;
	// Validate arguments
	if (n == NULL || t == NULL)
	{
		return;
	}

	UINTToIP(&ip, n->DestIp);
	IPToStr(hostname, sizeof(hostname), &ip);
	port_number = n->DestPort;
	e = n->v->SockEvent;
	AddRef(e->ref);

	// Notify the initialization completion
	NoticeThreadInit(t);

	// Attempt to connect to the TCP host
	Debug("NatTcpConnect Connecting to %s:%u\n", hostname, port_number);
	sock = ConnectEx3(hostname, port_number, 0, &n->NatTcpCancelFlag, NULL, NULL, false, true);
	if (sock == NULL)
	{
		// Connection failure
		n->TcpMakeConnectionFailed = true;
	}
	else
	{
		// Successful connection
		n->TcpMakeConnectionSucceed = true;
	}
	n->Sock = sock;
	JoinSockToSockEvent(sock, e);
	SetSockEvent(e);

	ReleaseSockEvent(e);
}

// Create a thread for trying to connect to the TCP host
void CreateNatTcpConnectThread(VH *v, NAT_ENTRY *n)
{
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return;
	}

	// Create a thread
	n->NatTcpConnectThread = NewThread(NatTcpConnectThread, (void *)n);

	// Wait for a thread initialization completion
	WaitThreadInit(n->NatTcpConnectThread);
}

// Handle the TCP entry
bool NatTransactTcp(VH *v, NAT_ENTRY *n)
{
	char str[MAX_SIZE];
	bool timeouted = false;
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return false;
	}

	if (n->DisconnectNow)
	{
		goto DISCONNECT;
	}

	// Process by state of the TCP
	switch (n->TcpStatus)
	{
	case NAT_TCP_CONNECTING:		// Waiting for connection
		if (n->NatTcpConnectThread == NULL)
		{
			// Start a connection by creating a connection thread
			CreateNatTcpConnectThread(v, n);
		}
		else
		{
			// Wait for the result of the connection thread that has already started
			if (n->TcpMakeConnectionFailed || n->TcpMakeConnectionSucceed)
			{
				// Use the results because operation thread has already finished
				WaitThread(n->NatTcpConnectThread, INFINITE);
				ReleaseThread(n->NatTcpConnectThread);
				n->NatTcpConnectThread = NULL;

				if (n->TcpMakeConnectionSucceed)
				{
					// Connection is successful, and a Sock was created
					n->TcpStatus = NAT_TCP_CONNECTED;
					IPToStr32(str, sizeof(str), n->DestIp);
					NLog(v, "LH_NAT_TCP_SUCCEED", n->Id, n->Sock->RemoteHostname, str, n->DestPort);
				}
				else
				{
					// Failed to connect
					n->TcpStatus = NAT_TCP_SEND_RESET;
					IPToStr32(str, sizeof(str), n->DestIp);
					NLog(v, "LH_NAT_TCP_FAILED", n->Id, str, n->DestPort);
				}
				v->NatDoCancelFlag = true;
			}
		}
		break;

	case NAT_TCP_CONNECTED:			// TCP socket connection completed. Negotiating with the client host
		break;

	case NAT_TCP_SEND_RESET:		// TCP communication disconnection: Send a RST to the client host
		break;

	case NAT_TCP_ESTABLISHED:		// TCP connection established
	{
		UINT old_send_fifo_size = 0;

		// Transmit to the socket if there is data in the receive buffer
		while (n->RecvFifo->size > 0)
		{
			UINT sent_size = Send(n->Sock, ((UCHAR *)n->RecvFifo->p) + n->RecvFifo->pos,
			                      n->RecvFifo->size, false);
			if (sent_size == 0)
			{
				// Communication has been disconnected
				n->TcpFinished = true;
				v->NatDoCancelFlag = true;
				break;
			}
			else if (sent_size == SOCK_LATER)
			{
				// Blocking
				break;
			}
			else
			{
				// Successful transmission
				ReadFifo(n->RecvFifo, NULL, sent_size);
				n->SendAckNext = true;

				if (false)
				{
					IP ip;

					n->test_TotalSent += sent_size;

					UINTToIP(&ip, n->DestIp);
					Debug("TCP %u: %r:%u %u\n", n->Id, &ip, n->DestPort, (UINT)n->test_TotalSent);
				}
			}
		}

		old_send_fifo_size = FifoSize(n->SendFifo);

		// Write to the transmission buffer by obtaining data from the socket
		while (true)
		{
			void *buf = (void *)v->TmpBuf;
			UINT want_to_recv_size = 0;
			UINT recv_size;
			// Calculate the size of wanting to receive
			if (n->SendFifo->size < NAT_SEND_BUF_SIZE)
			{
				// Still can receive
				want_to_recv_size = MIN(NAT_SEND_BUF_SIZE - n->SendFifo->size, NAT_TMPBUF_SIZE);
			}
			if (want_to_recv_size == 0)
			{
				SetNoNeedToRead(n->Sock);
				break;
			}
			recv_size = Recv(n->Sock, buf, want_to_recv_size, false);
			if (recv_size == 0)
			{
				// Communication has been disconnected
				n->TcpFinished = true;
				v->NatDoCancelFlag = true;
				if (n->TcpDisconnected == false)
				{
					Disconnect(n->Sock);
					n->TcpDisconnected = true;
				}
				break;
			}
			else if (recv_size == SOCK_LATER)
			{
				// Blocking
				break;
			}
			else
			{
				// Successful reception
				WriteFifo(n->SendFifo, buf, recv_size);
				v->NatDoCancelFlag = true;
			}
		}

		if (old_send_fifo_size == 0 && FifoSize(n->SendFifo) != 0)
		{
			// Reset the time data for timeout when the data is newly queued
			// in the empty transmission buffer in the transmission process
			n->TcpLastRecvAckTime = v->Now;
		}

		// Raise a transmission time-out if a certain period of time elapsed
		// after receiving the last ACK, and the transmission buffer is not
		// empty, and the reception window size of other party is not 0
		if ((n->TcpLastRecvAckTime + (UINT64)VIRTUAL_TCP_SEND_TIMEOUT) < v->Now)
		{
			if (FifoSize(n->SendFifo) != 0 && n->TcpSendWindowSize != 0)
			{
				timeouted = true;
			}
		}
	}
	break;

	}

	// Timeout Detection
	if ((n->LastCommTime + (UINT64)v->NatTcpTimeout) < v->Now || n->LastCommTime > v->Now)
	{
		timeouted = true;
	}

	if (timeouted)
	{
		// Time-out occurs, the session close
		n->TcpStatus = NAT_TCP_SEND_RESET;
		v->NatDoCancelFlag = true;
	}

	return true;

DISCONNECT:		// Disconnect and session disposal
	DeleteNatTcp(v, n);

	return false;
}

// Delete the entry of TCP NAT
void DeleteNatTcp(VH *v, NAT_ENTRY *n)
{
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return;
	}

	NLog(v, "LH_NAT_TCP_DELETED", n->Id);

	// Shutdown of connection thread
	if (n->NatTcpConnectThread != NULL)
	{
		n->NatTcpCancelFlag = true;

		WaitThread(n->NatTcpConnectThread, INFINITE);
		ReleaseThread(n->NatTcpConnectThread);
		n->NatTcpConnectThread = NULL;
	}
	if (n->Sock != NULL)
	{
		// Disconnect the socket
		Disconnect(n->Sock);
		ReleaseSock(n->Sock);
		n->Sock = NULL;
	}

	// Release the window memory
	if (n->TcpRecvWindow != NULL)
	{
		ReleaseFifo(n->TcpRecvWindow);
		n->TcpRecvWindow = NULL;
	}

	// Release the window reception list
	if (n->TcpRecvList != NULL)
	{
		UINT i;
		for (i = 0; i < LIST_NUM(n->TcpRecvList); i++)
		{
			IP_PART *p = LIST_DATA(n->TcpRecvList, i);
			Free(p);
		}
		ReleaseList(n->TcpRecvList);
		n->TcpRecvList = NULL;
	}

	// FIFO release
	ReleaseFifo(n->SendFifo);
	ReleaseFifo(n->RecvFifo);

	// Delete from the NAT entry
	Delete(v->NatTable, n);

	DeleteLock(n->lock);

	// Release the memory
	Free(n);

	Debug("NAT_ENTRY: DeleteNatTcp\n");
}

// NAT processing thread
void NatThread(THREAD *t, void *param)
{
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	// Notify the initialization completion
	NoticeThreadInit(t);

	NatThreadMain((VH *)param);
}

// Send a beacon packet
void SendBeacon(VH *v)
{
	UINT dest_ip;
	ARPV4_HEADER arp;
	static char beacon_str[] =
	    "SecureNAT Virtual TCP/IP Stack Beacon";
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Send an UDP
	dest_ip = (v->HostIP & v->HostMask) | (~v->HostMask);
	SendUdp(v, dest_ip, 7, v->HostIP, 7, beacon_str, sizeof(beacon_str));

	// Build the ARP header
	arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
	arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
	arp.HardwareSize = 6;
	arp.ProtocolSize = 4;
	arp.Operation = Endian16(ARP_OPERATION_RESPONSE);
	Copy(arp.SrcAddress, v->MacAddress, 6);
	arp.SrcIP = v->HostIP;
	arp.TargetAddress[0] =
	    arp.TargetAddress[1] =
	        arp.TargetAddress[2] =
	            arp.TargetAddress[3] =
	                arp.TargetAddress[4] =
	                    arp.TargetAddress[5] = 0xff;
	arp.TargetIP = dest_ip;

	// Transmission
	VirtualLayer2Send(v, broadcast, v->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(arp));
}

// Send a TCP packet
void SendTcp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT seq, UINT ack, UINT flag, UINT window_size, UINT mss, void *data, UINT size)
{
	static UCHAR tcp_mss_option[] = {0x02, 0x04, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00};
	IPV4_PSEUDO_HEADER *vh;
	TCP_HEADER *tcp;
	UINT header_size = TCP_HEADER_SIZE;
	UINT total_size;
	// Validate arguments
	if (v == NULL || (size != 0 && data == NULL))
	{
		return;
	}

	// Memory allocation
	vh = Malloc(sizeof(IPV4_PSEUDO_HEADER) + TCP_HEADER_SIZE + size + 32);
	tcp = (TCP_HEADER *)(((UCHAR *)vh) + sizeof(IPV4_PSEUDO_HEADER));

	if (mss != 0)
	{
		USHORT *mss_size;
		mss_size = (USHORT *)(&tcp_mss_option[2]);
		*mss_size = Endian16((USHORT)mss);
		header_size += sizeof(tcp_mss_option);
	}

	total_size = header_size + size;
	if (total_size > 65536)
	{
		// Packet is too long
		Free(vh);
		return;
	}

	// Pseudo header generation
	vh->SrcIP = src_ip;
	vh->DstIP = dest_ip;
	vh->Reserved = 0;
	vh->Protocol = IP_PROTO_TCP;
	vh->PacketLength = Endian16((USHORT)total_size);

	// TCP header generation
	tcp->SrcPort = Endian16((USHORT)src_port);
	tcp->DstPort = Endian16((USHORT)dest_port);
	tcp->SeqNumber = Endian32(seq);
	tcp->AckNumber = Endian32(ack);
	tcp->HeaderSizeAndReserved = 0;
	TCP_SET_HEADER_SIZE(tcp, (UCHAR)(header_size / 4));
	tcp->Flag = (UCHAR)flag;
	tcp->WindowSize = Endian16((USHORT)window_size);
	tcp->Checksum = 0;
	tcp->UrgentPointer = 0;

	// Copy the option values
	if (mss != 0)
	{
		Copy(((UCHAR *)tcp) + TCP_HEADER_SIZE, tcp_mss_option, sizeof(tcp_mss_option));
	}

	// Data copy
	Copy(((UCHAR *)tcp) + header_size, data, size);

	// Checksum calculation
	tcp->Checksum = IpChecksum(vh, total_size + 12);

	// Submit as an IP packet
	SendIp(v, dest_ip, src_ip, IP_PROTO_TCP, tcp, total_size);

	// Release the memory
	Free(vh);
}

// Polling process of TCP
void PollingNatTcp(VH *v, NAT_ENTRY *n)
{
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return;
	}

	switch (n->TcpStatus)
	{
	case NAT_TCP_CONNECTING:		// Socket connecting: nothing to do
		break;

	case NAT_TCP_CONNECTED:			// The socket connected: process SYN + ACK, ACK
		if ((n->LastSynAckSentTime > v->Now) || n->LastSynAckSentTime == 0 || ((n->LastSynAckSentTime + (UINT64)(NAT_TCP_SYNACK_SEND_TIMEOUT * (UINT64)(n->SynAckSentCount + 1)) <= v->Now)))
		{
			n->LastSynAckSentTime = v->Now;
			// Send a SYN + ACK
			SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
			        (UINT)(n->SendSeqInit + n->SendSeq),
			        (UINT)(n->RecvSeqInit + n->RecvSeq),
			        TCP_SYN | TCP_ACK, n->TcpRecvWindowSize,
			        v->TcpMss, NULL, 0);
			n->SynAckSentCount++;
		}
		break;

	case NAT_TCP_SEND_RESET:		// Reset the connection
		// Send a RST
		if (n->TcpFinished == false || n->TcpForceReset)
		{
			SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
			        (UINT)(n->SendSeq + n->SendSeqInit),
			        (UINT)(n->SendSeq + n->SendSeqInit),
			        TCP_RST, 0,
			        0, NULL, 0);
			// Disconnect
			n->TcpStatus = NAT_TCP_WAIT_DISCONNECT;
			n->DisconnectNow = true;
		}
		else
		{
			// Send FINs for NAT_FIN_SEND_MAX_COUNT times
			if (n->FinSentTime == 0 || (n->FinSentTime > v->Now) || (n->FinSentTime + NAT_FIN_SEND_INTERVAL * (n->FinSentCount + 1)) < v->Now)
			{
				SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
				        (UINT)(n->SendSeq + n->SendSeqInit),
				        (UINT)(n->RecvSeq + n->RecvSeqInit),
				        TCP_ACK | TCP_FIN, 0,
				        0, NULL, 0);
				n->FinSentTime = v->Now;
				n->FinSentSeq = (UINT)(n->SendSeq + n->SendSeqInit);
				n->FinSentCount++;
				if (n->FinSentCount >= NAT_FIN_SEND_MAX_COUNT)
				{
					n->TcpFinished = false;
				}
			}
		}
		break;

	case NAT_TCP_ESTABLISHED:		// Connection established
	{
		UINT send_data_size;
		UINT current_pointer;
		UINT notice_window_size_value = 0;
		UINT buf_free_bytes = 0;
		// Determine the value of the window size to be notified
		if (FifoSize(n->RecvFifo) < NAT_RECV_BUF_SIZE)
		{
			buf_free_bytes = NAT_RECV_BUF_SIZE - FifoSize(n->RecvFifo);
		}
		notice_window_size_value = MIN(n->TcpRecvWindowSize, buf_free_bytes);
		if (n->LastSentKeepAliveTime == 0 ||
		        (n->LastSentKeepAliveTime + (UINT64)NAT_ACK_KEEPALIVE_SPAN) < v->Now ||
		        (n->LastSentKeepAliveTime > v->Now))
		{
			if (n->LastSentKeepAliveTime != 0)
			{
				// Send an ACK packet for Keep-Alive
				SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
				        (UINT)(n->SendSeqInit + n->SendSeq),
				        (UINT)(n->RecvSeqInit + n->RecvSeq) - 1,
				        TCP_ACK,
				        notice_window_size_value,
				        0,
				        NULL,
				        0);
			}
			n->LastSentKeepAliveTime = v->Now;
		}
		if (n->TcpLastSentTime == 0 ||
		        (n->TcpLastSentTime > v->Now) ||
		        ((n->TcpLastSentTime + (UINT64)n->TcpSendTimeoutSpan) < v->Now) ||
		        n->SendAckNext)
		{
			// If there is data to send, send the data
			// Calculate the segment size to be transmitted
			send_data_size = n->TcpSendWindowSize;
			if (send_data_size > (n->TcpSendCWnd * n->TcpSendMaxSegmentSize))
			{
				// Apply the cwnd value
				send_data_size = n->TcpSendCWnd * n->TcpSendMaxSegmentSize;
			}
			if (send_data_size > n->SendFifo->size)
			{
				// Can not be sent over the data that is currently held
				send_data_size = n->SendFifo->size;
			}
			if (send_data_size >= 1)
			{
				// Transmit the fragmented segments
				current_pointer = 0;
				while (send_data_size > 0)
				{
					UINT send_segment_size = MIN(n->TcpSendMaxSegmentSize, send_data_size);
					void *send_segment = (void *)(((UCHAR *)n->SendFifo->p) + n->SendFifo->pos + current_pointer);
					SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
					        (UINT)(n->SendSeqInit + n->SendSeq + (UINT64)current_pointer),
					        (UINT)(n->RecvSeqInit + n->RecvSeq),
					        TCP_ACK | TCP_PSH,
					        notice_window_size_value,
					        0,
					        send_segment,
					        send_segment_size);
					current_pointer += send_segment_size;
					send_data_size -= send_segment_size;
				}
				// Record the transmission time
				n->TcpLastSentTime = v->Now;
				// Record the stream size to be transmitted this time
				n->SendMissionSize = current_pointer;
				n->CurrentSendingMission = true;
				// RTT measurement
				if (n->CalcRTTStartTime == 0)
				{
					n->CalcRTTStartTime = v->Now;
					n->CalcRTTStartValue = n->SendSeq + current_pointer - 1;
				}
				if (n->RetransmissionUsedFlag == false)
				{
					n->RetransmissionUsedFlag = true;
				}
				else
				{
					// Congestion is detected
					if (n->TcpSendCWnd > 2)
					{
						n->TcpSendCWnd--;
					}
				}
			}
			else if (n->SendAckNext)
			{
				// Send only an ACK
				SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
				        (UINT)(n->SendSeqInit + n->SendSeq),
				        (UINT)(n->RecvSeqInit + n->RecvSeq),
				        TCP_ACK,
				        notice_window_size_value,
				        0,
				        NULL,
				        0);
			}
			n->SendAckNext = false;
		}
		if (n->TcpFinished)
		{
			// Disconnect if all data transmission has completed
			if (n->SendFifo->size == 0 && n->RecvFifo->size == 0)
			{
				n->TcpStatus = NAT_TCP_SEND_RESET;
			}
		}
	}
	break;
	}
}

// Reception of TCP packets addressed to the Internet
void TcpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, TCP_HEADER *tcp, void *data, UINT size, UINT max_l3_size)
{
	NAT_ENTRY *n, t;
	UINT seq, ack;
	UINT64 seq64 = 0, ack64 = 0;
	// Validate arguments
	if (v == NULL || tcp == NULL || data == NULL)
	{
		return;
	}

	if (NnIsActive(v))
	{
		NnTcpRecvForInternet(v, src_ip, src_port, dest_ip, dest_port, tcp, data, size, max_l3_size);
		return;
	}

	seq = Endian32(tcp->SeqNumber);
	ack = Endian32(tcp->AckNumber);

	if (v->HubOption != NULL && v->HubOption->DisableUserModeSecureNAT)
	{
		// Disable User-mode NAT
		SendTcp(v, dest_ip, dest_port, src_ip, src_port,
		        0, seq + 1, TCP_RST | TCP_ACK, 0, 0, NULL, 0);
		return;
	}

	// Search for a session for this packet from the NAT table
	SetNat(&t, NAT_TCP, src_ip, src_port, dest_ip, dest_port, 0, 0);
	n = SearchNat(v, &t);

	if (n == NULL)
	{
		// There is no existing session
		// Allow through only SYN packet
		if ((tcp->Flag & TCP_SYN) && ((tcp->Flag & TCP_ACK) == false))
		{
			TCP_OPTION o;
			// Create a new session
			n = CreateNatTcp(v, src_ip, src_port, dest_ip, dest_port);
			if (n == NULL)
			{
				// Return the RST if it was not possible to create
				SendTcp(v, dest_ip, dest_port, src_ip, src_port,
				        0, seq + 1, TCP_RST | TCP_ACK, 0, 0, NULL, 0);
				return;
			}

			// Get the options
			ParseTcpOption(&o, ((UCHAR *)tcp) + TCP_HEADER_SIZE, TCP_GET_HEADER_SIZE(tcp) * 4 - TCP_HEADER_SIZE);
			if (o.MaxSegmentSize == 0)
			{
				o.MaxSegmentSize = v->TcpMss;
			}

			Debug("TCP SYN: MSS=%u, WS=%u\n", o.MaxSegmentSize, o.WindowScaling);

			// Initial sequence number
			n->RecvSeqInit = (UINT64)Endian32(tcp->SeqNumber);
			n->RecvSeq = 1;

			n->TcpSendMaxSegmentSize = o.MaxSegmentSize;
			n->TcpRecvWindowSize = NAT_TCP_RECV_WINDOW_SIZE;
			n->TcpSendWindowSize = (UINT)Endian16(tcp->WindowSize);
			if (o.WindowScaling != 0)
			{
				if (o.WindowScaling > 14)
				{
					o.WindowScaling = 14;
				}
				n->TcpSendWindowSize = (n->TcpSendWindowSize << o.WindowScaling);
			}
		}
	}

	if (n == NULL)
	{
		// Return a RST since a packet which is not registered in the NAT entry arrived
		SendTcp(v, dest_ip, dest_port, src_ip, src_port,
		        ack, ack, TCP_RST, 0, 0, NULL, 0);
		return;
	}

	n->TcpLastRecvAckTime = v->Now;

	switch (n->TcpStatus)
	{
	case NAT_TCP_SEND_RESET:		// Disconnect the connection by sending a RST
		if ((tcp->Flag & TCP_ACK) && ((tcp->Flag & TCP_SYN) == false))
		{
			if (n->FinSentCount >= 1)
			{
				if (ack == (n->FinSentSeq + 1))
				{
					n->TcpForceReset = true;
				}
			}
		}
		break;

	case NAT_TCP_CONNECTED:			// Socket connection completion: SYN + ACK, ACK processing
		if ((tcp->Flag & TCP_ACK) && ((tcp->Flag & TCP_SYN) == false))
		{
			if (seq == (UINT)(n->RecvSeqInit + n->RecvSeq) &&
			        ack == (UINT)(n->SendSeqInit + n->SendSeq + 1))
			{
				// Handshake complete since the ACK packet came back
				n->SendSeq++;		// SYN packet consumes the seq by 1
				Debug("TCP Connection Established.\n");
				n->TcpStatus = NAT_TCP_ESTABLISHED;
				// Initialize the congestion window size
				n->TcpSendCWnd = 1;
				n->LastCommTime = v->Now;
			}
			else
			{
				goto TCP_RESET;
			}
		}
		else if (tcp->Flag & TCP_RST)
		{
TCP_RESET:
			// Receive a RST
			Debug("TCP Connection Reseted.\n");
			n->TcpStatus = NAT_TCP_SEND_RESET;
		}
		break;

	case NAT_TCP_ESTABLISHED:		// Connection established
		if (tcp->Flag & TCP_FIN)
		{
			// Complete the connection
			n->TcpFinished = true;
		}
		if (tcp->Flag & TCP_RST)
		{
			// Receive a RST
			goto TCP_RESET;
		}
		else if (tcp->Flag & TCP_ACK)
		{
			TCP_OPTION opt;
			n->LastCommTime = v->Now;
			// Get the options, such as window size
			n->TcpSendWindowSize = Endian16(tcp->WindowSize);
			ParseTcpOption(&opt, ((UCHAR *)tcp) + TCP_HEADER_SIZE, TCP_GET_HEADER_SIZE(tcp) * 4 - TCP_HEADER_SIZE);
			if (opt.WindowScaling != 0)
			{
				if (opt.WindowScaling > 14)
				{
					opt.WindowScaling = 14;
				}
				n->TcpSendWindowSize = (n->TcpSendWindowSize << opt.WindowScaling);
			}
			// First, process the received ACK
			// Store the end position of the stream that has received the acknowledgment to ack64
			ack64 = n->SendSeq + (UINT64)ack - (n->SendSeqInit + n->SendSeq) % X32;
			if ((n->SendSeqInit + n->SendSeq) % X32 > ack)
			{
				if (((n->SendSeqInit + n->SendSeq) % X32 - ack) >= 0x80000000)
				{
					ack64 = n->SendSeq + (UINT64)ack + X32 - (n->SendSeqInit + n->SendSeq) % X32;
				}
			}
			if (ack64 > n->SendSeq)
			{
				// Reception of 1 byte or more seems to have been completed by the client
				UINT slide_offset = (UINT)(ack64 - n->SendSeq);	// Sliding size of the window
				if (slide_offset == 0 || slide_offset > n->TcpSendWindowSize || slide_offset > n->SendFifo->size)
				{
					// Ignore because the offset value of acknowledgment is
					// larger than the size that should have been sent so far
				}
				else
				{
					// RTT measurement
					if (n->CalcRTTStartTime != 0)
					{
						if (n->CalcRTTStartValue < ack64)
						{
							UINT time_span;
							if (v->Now > n->CalcRTTStartTime)
							{
								time_span = (UINT)(v->Now - n->CalcRTTStartTime);
							}
							else
							{
								time_span = 100;
							}
							n->CalcRTTStartTime = 0;

							// Smoothing
							n->CurrentRTT =
							    (UINT)
							    (
							        ((UINT64)n->CurrentRTT * (UINT64)9 +
							         (UINT64)time_span * (UINT64)1) / (UINT64)10
							    );
							n->TcpSendTimeoutSpan = n->CurrentRTT * 2;
						}
					}
					// Reduce the transmission size
					n->SendMissionSize -= slide_offset;
					if (n->SendMissionSize == 0)
					{
						// Try to increase the transmission segment size because
						// all segments to be sent this time have been sent
						if (n->TcpSendCWnd < 65536)
						{
							n->TcpSendCWnd++;
						}
						n->CurrentSendingMission = false;
						n->TcpLastSentTime = 0;
						n->RetransmissionUsedFlag = false;
					}
					// Slide the buffer
					n->SendSeq += slide_offset;
					ReadFifo(n->SendFifo, NULL, slide_offset);
					// Send further by the size of confirmed transmission completion by the ACK this time
					if (n->SendMissionSize != 0 && false)
					{
						UINT notice_window_size_value = 0;
						UINT send_data_size;
						UINT buf_free_bytes;
						UINT send_offset = n->SendMissionSize;
						// Determine the value of the window size to be notified
						if (FifoSize(n->RecvFifo) < NAT_RECV_BUF_SIZE)
						{
							buf_free_bytes = NAT_RECV_BUF_SIZE - FifoSize(n->RecvFifo);
						}
						notice_window_size_value = MIN(n->TcpRecvWindowSize, buf_free_bytes);
						// Calculate the segment size to be transmitted
						send_data_size = n->TcpSendWindowSize;
						if (send_data_size > (n->TcpSendCWnd * n->TcpSendMaxSegmentSize))
						{
							// Apply the cwnd value
							send_data_size = n->TcpSendCWnd * n->TcpSendMaxSegmentSize;
						}
						if (n->SendFifo->size > send_offset)
						{
							send_data_size = MIN(send_data_size, n->SendFifo->size - send_offset);
							send_data_size = MIN(send_data_size, slide_offset);
						}
						else
						{
							send_data_size = 0;
						}
						if (send_data_size >= 1)
						{
							// Transmit the fragmented segments
							UINT current_pointer = 0;
							while (send_data_size > 0)
							{
								UINT send_segment_size = MIN(n->TcpSendMaxSegmentSize, send_data_size);
								void *send_segment = (void *)((
								                                  (UCHAR *)n->SendFifo->p) + n->SendFifo->pos +
								                              current_pointer + send_offset);

								SendTcp(v, n->DestIp, n->DestPort, n->SrcIp, n->SrcPort,
								        (UINT)(n->SendSeqInit + n->SendSeq + (UINT64)current_pointer
								               + (UINT)send_offset),
								        (UINT)(n->RecvSeqInit + n->RecvSeq),
								        TCP_ACK | TCP_PSH,
								        notice_window_size_value,
								        0,
								        send_segment,
								        send_segment_size);
								current_pointer += send_segment_size;
								send_data_size -= send_segment_size;
							}
							n->SendMissionSize += current_pointer;
							n->CurrentSendingMission = true;
							n->TcpLastSentTime = v->Now;
							// RTT measurement
							if (n->CalcRTTStartTime == 0)
							{
								n->CalcRTTStartTime = v->Now;
								n->CalcRTTStartValue = n->SendSeq + current_pointer - 1;
							}
						}
					}
					// Event occurs
					SetSockEvent(v->SockEvent);
				}
			}
			// Next, receive the data
			seq64 = n->RecvSeq + (UINT64)seq - (n->RecvSeqInit + n->RecvSeq) % X32;
			if ((n->RecvSeqInit + n->RecvSeq) % X32 > seq)
			{
				if (((n->RecvSeqInit + n->RecvSeq) % X32 - seq) >= 0x80000000)
				{
					seq64 = n->RecvSeq + (UINT64)seq + X32 - (n->RecvSeqInit + n->RecvSeq) % X32;
				}
			}
			// Position of the starting point of the data from the client is in the seq64 at this time
			if (seq64 >= n->RecvSeq && (seq64 + size) <= (n->RecvSeq + n->TcpRecvWindowSize))
			{
				if (size >= 1)
				{
					// One or more bytes of data has been received within the receive window
					UINT offset = (UINT)(seq64 - n->RecvSeq);
					UINT i;
					IP_PART *me;
					if (n->TcpRecvWindow == NULL)
					{
						n->TcpRecvWindow = NewFifo();
					}
					if (n->TcpRecvList == NULL)
					{
						n->TcpRecvList = NewListFast(NULL);
					}
					// Add to the list by overwriting arriving packets to the buffer
					if (FifoSize(n->TcpRecvWindow) < (offset + size))
					{
						// Buffer size expansion
						WriteFifo(n->TcpRecvWindow, NULL, offset + size - FifoSize(n->TcpRecvWindow));
					}
					Copy(((UCHAR *)n->TcpRecvWindow->p) + n->TcpRecvWindow->pos +
					     offset, data, size);
					me = ZeroMalloc(sizeof(IP_PART));
					me->Offset = offset;
					me->Size = size;
					for (i = 0; i < LIST_NUM(n->TcpRecvList); i++)
					{
						IP_PART *p = LIST_DATA(n->TcpRecvList, i);
						// If there are overlapped region, remove these
						if (p->Size != 0)
						{
							if (me->Offset <= p->Offset && (me->Offset + me->Size) >= (p->Offset + p->Size))
							{
								// This packet completely overwrite the existing packet
								p->Size = 0;
							}
							else if (me->Offset >= p->Offset && (me->Offset + me->Size) <= (p->Offset + p->Size))
							{
								// Existing packet completely override this packet
								me->Size = 0;
							}
							else if (me->Offset > p->Offset && me->Offset < (p->Offset + p->Size) &&
							         (me->Offset + me->Size) > (p->Offset + p->Size))
							{
								// Partially overlapped
								p->Size -= p->Offset + p->Size - me->Offset;
							}
							else if (me->Offset < p->Offset && (me->Offset + size) > p->Offset && (me->Offset + size) < (p->Offset + p->Size))
							{
								// Partially overlapped
								me->Size -= me->Offset + me->Size - p->Offset;
							}
						}
					}
					if (me->Size == 0)
					{
						Free(me);
					}
					else
					{
						Add(n->TcpRecvList, me);
					}
KILL_NULL_FIRST:
					// Remove all blank items from reception list
					for (i = 0; i < LIST_NUM(n->TcpRecvList); i++)
					{
						IP_PART *p = LIST_DATA(n->TcpRecvList, i);
						if (p->Size == 0)
						{
							Delete(n->TcpRecvList, p);
							Free(p);
							goto KILL_NULL_FIRST;
						}
					}
SCAN_FIRST:
					// Extract if there is something starting at offset 0 in the received list
					for (i = 0; i < LIST_NUM(n->TcpRecvList); i++)
					{
						IP_PART *p = LIST_DATA(n->TcpRecvList, i);
						UINT sz;
						if (p->Offset == 0)
						{
							// Since a data block starts with 0 is found,
							// slide it left by that amount and write the buffer
							// for extracting data to the FIFO
							sz = p->Size;
							WriteFifo(n->RecvFifo, ((UCHAR *)n->TcpRecvWindow->p) + n->TcpRecvWindow->pos, sz);
							// Release from the list
							Delete(n->TcpRecvList, p);
							Free(p);
							ReadFifo(n->TcpRecvWindow, NULL, sz);
							// Slide all the items to the left
							for (i = 0; i < LIST_NUM(n->TcpRecvList); i++)
							{
								p = LIST_DATA(n->TcpRecvList, i);
								p->Offset -= sz;
							}
							// Update the parameters of the TCB
							n->RecvSeq += (UINT64)sz;
							SetSockEvent(v->SockEvent);
							n->SendAckNext = true;
							// Re-scan from the beginning
							goto SCAN_FIRST;
						}
					}
				}
			}
		}
		break;
	}

	SetSockEvent(v->SockEvent);
}

// Parse the TCP options
void ParseTcpOption(TCP_OPTION *o, void *data, UINT size)
{
	UCHAR *buf = (UCHAR *)data;
	UINT i = 0;
	UINT value_size = 0;
	UINT value_id = 0;
	UCHAR value[128];
	// Validate arguments
	if (o == NULL || data == NULL)
	{
		return;
	}

	Zero(o, sizeof(TCP_OPTION));

	while(i < size)
	{
		if (buf[i] == 0)
		{
			return;
		}
		else if (buf[i] == 1)
		{
			i++;
			continue;
		}
		else
		{
			value_id = buf[i];
			i++;
			if (i >= size)
			{
				return;
			}
			value_size = buf[i];
			if (value_size <= 1 || value_size > sizeof(value))
			{
				return;
			}
			i++;
			if (i >= size)
			{
				return;
			}
			value_size -= 2;

			Copy(value, &buf[i], value_size);
			i += value_size;
			if (i > size)
			{
				return;
			}

			switch (value_id)
			{
			case 2:	// MSS
				if (value_size == 2)
				{
					USHORT *mss = (USHORT *)value;
					o->MaxSegmentSize = Endian16(*mss);
				}
				break;

			case 3: // WSS
				if (value_size == 1)
				{
					UCHAR *wss = (UCHAR *)value;
					o->WindowScaling = *wss;
				}
				break;

			}
		}
	}
}

// Create a new NAT TCP session
NAT_ENTRY *CreateNatTcp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port)
{
	NAT_ENTRY *n;
	HUB_OPTION *o;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	if (CanCreateNewNatEntry(v) == false)
	{
		return NULL;
	}

	o = NatGetHubOption(v);

	// Fail immediately if the connection with SYN_SENT are too many
	if (o != NULL && o->SecureNAT_MaxTcpSynSentPerIp != 0)
	{
		if (GetNumNatEntriesPerIp(v, src_ip, NAT_TCP, true) >= o->SecureNAT_MaxTcpSynSentPerIp)
		{
			return NULL;
		}
	}

	// If the connections other than SYN_SENT are too many, delete old ones
	if (o != NULL && o->SecureNAT_MaxTcpSessionsPerIp != 0)
	{
		if (GetNumNatEntriesPerIp(v, src_ip, NAT_TCP, false) >= o->SecureNAT_MaxTcpSessionsPerIp)
		{
			NAT_ENTRY *oldest = GetOldestNatEntryOfIp(v, src_ip, NAT_TCP);

			if (oldest != NULL)
			{
				DisconnectNatEntryNow(v, oldest);
			}
		}
	}

	// Create a NAT entry
	n = ZeroMalloc(sizeof(NAT_ENTRY));
	n->Id = Inc(v->Counter);
	n->v = v;
	n->lock = NewLock();
	n->Protocol = NAT_TCP;
	n->SrcIp = src_ip;
	n->SrcPort = src_port;
	n->DestIp = dest_ip;
	n->DestPort = dest_port;
	n->CreatedTime = n->LastCommTime = v->Now;
	n->TcpLastRecvAckTime = v->Now;
	n->Sock = NULL;
	n->DisconnectNow = false;
	n->TcpSendMaxSegmentSize = n->TcpRecvMaxSegmentSize = v->TcpMss;

	n->SendFifo = NewFifo();
	n->RecvFifo = NewFifo();

	n->TcpStatus = NAT_TCP_CONNECTING;

	n->SendSeqInit = Rand32();
	n->CurrentRTT = NAT_INITIAL_RTT_VALUE;
	n->TcpSendTimeoutSpan = n->CurrentRTT * 2;

	// Add to the NAT table
	Add(v->NatTable, n);


#if	1
	{
		IP ip1, ip2;
		char s1[MAX_SIZE], s2[MAX_SIZE];
		UINTToIP(&ip1, src_ip);
		UINTToIP(&ip2, dest_ip);
		IPToStr(s1, 0, &ip1);
		IPToStr(s2, 0, &ip2);
		Debug("NAT_ENTRY: CreateNatTcp %s %u -> %s %u\n", s1, src_port, s2, dest_port);

		NLog(v, "LH_NAT_TCP_CREATED", n->Id, s1, src_port, s2, dest_port);
	}
#endif

	return n;
}

// Received TCP packets from the virtual network
void VirtualTcpReceived(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size, UINT max_l3_size)
{
	TCP_HEADER *tcp;
	UINT src_port, dest_port;
	UINT header_size, buf_size;
	void *buf;
	IP ip1, ip2;
	// Validate arguments
	if (v == NULL || data == NULL)
	{
		return;
	}

	// Get the header
	if (size < TCP_HEADER_SIZE)
	{
		// Size is too small
		return;
	}
	tcp = (TCP_HEADER *)data;
	src_port = Endian16(tcp->SrcPort);
	dest_port = Endian16(tcp->DstPort);
	if (src_port == 0 || dest_port == 0)
	{
		// Port number is invalid
		return;
	}
	if (src_ip == dest_ip || src_ip == 0 || src_ip == 0xffffffff || dest_ip == 0 || dest_ip == 0xffffffff)
	{
		// IP address is invalid
		return;
	}
	UINTToIP(&ip1, src_ip);
	UINTToIP(&ip2, dest_ip);
	if (IsLocalHostIP4(&ip1) || IsLocalHostIP4(&ip2))
	{
		// Loopback IP address can not be specified
		return;
	}
	if (IsInNetwork(dest_ip, v->HostIP, v->HostMask))
	{
		// Ignore the packets toward the network of the virtual LAN side
		return;
	}
	// Get the header size
	header_size = TCP_GET_HEADER_SIZE(tcp) * 4;
	if (size < header_size)
	{
		// Header size is invalid
		return;
	}
	// Get the address and size of the buffer
	buf_size = size - header_size;
	buf = (void *)(((UCHAR *)data) + header_size);

	TcpRecvForInternet(v, src_ip, src_port, dest_ip, dest_port, tcp, buf, buf_size, max_l3_size);
}

// NAT ICMP polling
void PollingNatIcmp(VH *v, NAT_ENTRY *n)
{
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return;
	}

	// Process if there are any packets in the receive queue
	if (n->UdpRecvQueue->num_item != 0)
	{
		BLOCK *block;

		// Send all ICMP packets to the virtual network
		while (block = GetNext(n->UdpRecvQueue))
		{
			// Rewrite the destination IP address of the returned packet to the IP address of the client
			UCHAR *data;
			UINT size;

			data = (UCHAR *)block->Buf;
			size = block->Size;

			if (size >= sizeof(IPV4_HEADER))
			{
				IPV4_HEADER *ipv4 = (IPV4_HEADER *)data;
				UINT ipv4_header_size = GetIpHeaderSize((UCHAR *)ipv4, size);

				if (ipv4_header_size >= sizeof(IPV4_HEADER) && (Endian16(ipv4->TotalLength) >= ipv4_header_size))
				{
					UCHAR *ipv4_payload = data + ipv4_header_size;
					UINT ipv4_payload_size = Endian16(ipv4->TotalLength) - ipv4_header_size;

					if (ipv4_payload_size >= sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO))
					{
						ICMP_HEADER *icmp = (ICMP_HEADER *)(data + ipv4_header_size);
						UINT icmp_size = ipv4_payload_size;

						if (icmp->Type == ICMP_TYPE_DESTINATION_UNREACHABLE || icmp->Type == ICMP_TYPE_TIME_EXCEEDED)
						{
							// Rewrite the Src IP of the IPv4 header of the ICMP response packet
							if (icmp_size >= (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + sizeof(IPV4_HEADER)))
							{
								IPV4_HEADER *orig_ipv4 = (IPV4_HEADER *)(data + ipv4_header_size + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));
								UINT orig_ipv4_size = icmp_size - (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));

								UINT orig_ipv4_header_size = GetIpHeaderSize((UCHAR *)orig_ipv4, orig_ipv4_size);

								if (orig_ipv4_header_size >= sizeof(IPV4_HEADER))
								{
									orig_ipv4->SrcIP = n->SrcIp;
									orig_ipv4->Checksum = 0;
									orig_ipv4->Checksum = IpChecksum(orig_ipv4, orig_ipv4_header_size);
								}
							}
						}

						// Recalculate the checksum of ICMP
						icmp->Checksum = IpChecksum(icmp, icmp_size);

						SendIpEx(v, n->SrcIp, ipv4->SrcIP, ipv4->Protocol, ipv4_payload, ipv4_payload_size,
						         MAX(ipv4->TimeToLive - 1, 1));
					}
				}
			}

			FreeBlock(block);
		}

		if (v->IcmpRawSocketOk == false)
		{
			// Release the NAT entry as soon as the results is received in the case of using ICMP API
			n->DisconnectNow = true;
		}
	}
}

// NAT UDP polling
void PoolingNatUdp(VH *v, NAT_ENTRY *n)
{
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return;
	}

	// Process if there are any packets in the receive queue
	if (n->UdpRecvQueue->num_item != 0)
	{
		BLOCK *block;

		// Send all UDP packets to the virtual network
		while (block = GetNext(n->UdpRecvQueue))
		{
			UINT src_ip = n->DestIp;

			if (src_ip == 0xFFFFFFFF)
			{
				src_ip = v->HostIP;
			}

			if (block->Param1 != 0)
			{
				src_ip = block->Param1;
			}

			SendUdp(v, n->SrcIp, n->SrcPort, src_ip, n->DestPort,
			        block->Buf, block->Size);

			FreeBlock(block);
		}
	}
}

// NAT polling
void PoolingNat(VH *v)
{
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	if (NnIsActive(v))
	{
		// Poll whether the packet comes from native NAT
		NnPoll(v->NativeNat);
	}

	// Process by scanning the all NAT entries
	for (i = 0; i < LIST_NUM(v->NatTable); i++)
	{
		NAT_ENTRY *n = LIST_DATA(v->NatTable, i);

		switch (n->Protocol)
		{
		case NAT_TCP:
			PollingNatTcp(v, n);
			break;

		case NAT_UDP:
			PoolingNatUdp(v, n);
			break;

		case NAT_ICMP:
			PollingNatIcmp(v, n);
			break;

		case NAT_DNS:
			PollingNatDns(v, n);
			break;
		}
	}
}

// Comparison function of the NAT table entry
int CompareNat(void *p1, void *p2)
{
	NAT_ENTRY *n1, *n2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	n1 = *(NAT_ENTRY **)p1;
	n2 = *(NAT_ENTRY **)p2;
	if (n1 == n2)
	{
		return 0;
	}

	if (n1->SrcIp > n2->SrcIp) return 1;
	else if (n1->SrcIp < n2->SrcIp) return -1;
	else if (n1->DestIp > n2->DestIp) return 1;
	else if (n1->DestIp < n2->DestIp) return -1;
	else if (n1->SrcPort > n2->SrcPort) return 1;
	else if (n1->SrcPort < n2->SrcPort) return -1;
	else if (n1->DestPort > n2->DestPort) return 1;
	else if (n1->DestPort < n2->DestPort) return -1;
	else if (n1->Protocol > n2->Protocol) return 1;
	else if (n1->Protocol < n2->Protocol) return -1;
	else return 0;
}

// Configure the NAT structure
void SetNat(NAT_ENTRY *n, UINT protocol, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT public_ip, UINT public_port)
{
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	n->Protocol = protocol;
	n->SrcIp = src_ip;
	n->SrcPort = src_port;
	n->DestIp = dest_ip;
	n->DestPort = dest_port;
	n->PublicIp = public_ip;
	n->PublicPort = public_port;
}

// Initialize the NAT
void InitNat(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Create a NAT table
	v->NatTable = NewList(CompareNat);

	// Create a socket event
	v->SockEvent = NewSockEvent();

	// Create the NAT thread
	v->HaltNat = false;
	v->NatThread = NewThread(NatThread, (void *)v);
	WaitThreadInit(v->NatThread);

	if (IsEthSupported())
	{
		// Start a native NAT if access to the layer 2 Ethernet is supported
		v->NativeNat = NewNativeNat(v);
	}
}

// Release the NAT
void FreeNat(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Stop the native NAT
	if (v->NativeNat != NULL)
	{
		FreeNativeNat(v->NativeNat);
		v->NativeNat = NULL;
	}

	// Stop the NAT thread
	v->HaltNat = true;
	SetSockEvent(v->SockEvent);
	WaitThread(v->NatThread, INFINITE);
	ReleaseThread(v->NatThread);
	v->NatThread = NULL;
	ReleaseSockEvent(v->SockEvent);
	v->SockEvent = NULL;

	// Release the NAT table
	ReleaseList(v->NatTable);
}

// Search the NAT table
NAT_ENTRY *SearchNat(VH *v, NAT_ENTRY *target)
{
	NAT_ENTRY *n;
	// Validate arguments
	if (v == NULL || target == NULL)
	{
		return NULL;
	}

	// Binary search
	n = (NAT_ENTRY *)Search(v->NatTable, target);

	return n;
}

// Delete the UDP NAT entry
void DeleteNatUdp(VH *v, NAT_ENTRY *n)
{
	BLOCK *block;
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return;
	}

	NLog(v, "LH_NAT_UDP_DELETED", n->Id);

	// Release all queues
	while (block = GetNext(n->UdpRecvQueue))
	{
		FreeBlock(block);
	}
	ReleaseQueue(n->UdpRecvQueue);
	while (block = GetNext(n->UdpSendQueue))
	{
		FreeBlock(block);
	}
	ReleaseQueue(n->UdpSendQueue);

	// Release the socket
	if (n->Sock != NULL)
	{
		Disconnect(n->Sock);
		ReleaseSock(n->Sock);
		n->Sock = NULL;
	}

	DeleteLock(n->lock);

	// Remove from the table
	Delete(v->NatTable, n);

	// Release the memory
	Free(n);

	Debug("NAT: DeleteNatUdp\n");

}

// Delete the ICMP NAT entry
void DeleteNatIcmp(VH *v, NAT_ENTRY *n)
{
	BLOCK *block;
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return;
	}

	//NLog(v, "LH_NAT_ICMP_DELETED", n->Id);

	// Release all queues
	while (block = GetNext(n->UdpRecvQueue))
	{
		FreeBlock(block);
	}
	ReleaseQueue(n->UdpRecvQueue);
	while (block = GetNext(n->UdpSendQueue))
	{
		FreeBlock(block);
	}
	ReleaseQueue(n->UdpSendQueue);

	if (n->IcmpQueryBlock != NULL)
	{
		FreeBlock(n->IcmpQueryBlock);
	}

	if (n->IcmpResponseBlock != NULL)
	{
		FreeBlock(n->IcmpResponseBlock);
	}

	if (n->IcmpOriginalCopy != NULL)
	{
		Free(n->IcmpOriginalCopy);
	}

	// Release the socket
	if (n->Sock != NULL)
	{
		Disconnect(n->Sock);
		ReleaseSock(n->Sock);
		n->Sock = NULL;
	}

	DeleteLock(n->lock);

	// Remove from the table
	Delete(v->NatTable, n);

	// Release the memory
	Free(n);

	Debug("NAT: DeleteNatIcmp\n");

}

// Create a NAT ICMP entry
NAT_ENTRY *CreateNatIcmp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UCHAR *original_copy, UINT original_copy_size)
{
	NAT_ENTRY *n;
	HUB_OPTION *o;
	// Validate arguments
	if (v == NULL || original_copy == NULL || original_copy_size == 0)
	{
		return NULL;
	}

	if (CanCreateNewNatEntry(v) == false)
	{
		return NULL;
	}

	o = NatGetHubOption(v);
	if (o != NULL && o->SecureNAT_MaxIcmpSessionsPerIp != 0)
	{
		if (GetNumNatEntriesPerIp(v, src_ip, NAT_ICMP, false) >= o->SecureNAT_MaxIcmpSessionsPerIp)
		{
			NAT_ENTRY *oldest = GetOldestNatEntryOfIp(v, src_ip, NAT_ICMP);

			if (oldest != NULL)
			{
				DisconnectNatEntryNow(v, oldest);
			}
		}
	}

	n = ZeroMalloc(sizeof(NAT_ENTRY));
	n->Id = Inc(v->Counter);
	n->v = v;
	n->lock = NewLock();
	n->Protocol = NAT_ICMP;
	n->SrcIp = src_ip;
	n->SrcPort = src_port;
	n->DestIp = dest_ip;
	n->DestPort = dest_port;

	n->CreatedTime = n->LastCommTime = v->Now;

	n->UdpSendQueue = NewQueue();
	n->UdpRecvQueue = NewQueue();

	n->UdpSocketCreated = false;

	n->IcmpOriginalCopy = Clone(original_copy, original_copy_size);
	n->IcmpOriginalCopySize = original_copy_size;

	SetSockEvent(v->SockEvent);

#if	1
	{
		IP ip1, ip2;
		char s1[MAX_SIZE], s2[MAX_SIZE];
		UINTToIP(&ip1, src_ip);
		UINTToIP(&ip2, dest_ip);
		IPToStr(s1, 0, &ip1);
		IPToStr(s2, 0, &ip2);
		Debug("NAT_ENTRY: CreateNatIcmp %s %u -> %s %u\n", s1, src_port, s2, dest_port);

		//NLog(v, "LH_NAT_ICMP_CREATED", n->Id, s1, s2, src_port);
	}
#endif

	Add(v->NatTable, n);

	return n;
}

// Create a NAT UDP entry
NAT_ENTRY *CreateNatUdp(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, UINT dns_proxy_ip)
{
	NAT_ENTRY *n;
	HUB_OPTION *o;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	if (CanCreateNewNatEntry(v) == false)
	{
		return NULL;
	}

	o = NatGetHubOption(v);
	if (o != NULL && o->SecureNAT_MaxTcpSessionsPerIp != 0)
	{
		if (GetNumNatEntriesPerIp(v, src_ip, NAT_UDP, false) >= o->SecureNAT_MaxUdpSessionsPerIp)
		{
			NAT_ENTRY *oldest = GetOldestNatEntryOfIp(v, src_ip, NAT_UDP);

			if (oldest != NULL)
			{
				DisconnectNatEntryNow(v, oldest);
			}
		}
	}

	n = ZeroMalloc(sizeof(NAT_ENTRY));
	n->Id = Inc(v->Counter);
	n->v = v;
	n->lock = NewLock();
	n->Protocol = NAT_UDP;
	n->SrcIp = src_ip;
	n->SrcPort = src_port;
	n->DestIp = dest_ip;
	n->DestPort = dest_port;

	if (dns_proxy_ip != 0)
	{
		n->ProxyDns = true;
		n->DestIpProxy = dns_proxy_ip;
	}

	n->CreatedTime = n->LastCommTime = v->Now;

	n->UdpSendQueue = NewQueue();
	n->UdpRecvQueue = NewQueue();

	n->UdpSocketCreated = false;

	SetSockEvent(v->SockEvent);

#if	1
	{
		IP ip1, ip2;
		char s1[MAX_SIZE], s2[MAX_SIZE];
		UINTToIP(&ip1, src_ip);
		UINTToIP(&ip2, dest_ip);
		IPToStr(s1, 0, &ip1);
		IPToStr(s2, 0, &ip2);
		Debug("NAT_ENTRY: CreateNatUdp %s %u -> %s %u\n", s1, src_port, s2, dest_port);

		NLog(v, "LH_NAT_UDP_CREATED", n->Id, s1, src_port, s2, dest_port);
	}
#endif

	Add(v->NatTable, n);

	return n;
}

// Ignore for NetBIOS name registration packet
bool IsNetbiosRegistrationPacket(UCHAR *buf, UINT size)
{
	// Validate arguments
	if (buf == NULL || size == 0)
	{
		return false;
	}

	if (size >= 4)
	{
		USHORT us = *((USHORT *)(buf + 2));

		us = Endian16(us);

		if (((us & 0x7800) >> 11) == 5)
		{
			return true;
		}
	}

	return false;
}

// Generate the encoded NetBIOS name
void EncodeNetBiosName(UCHAR *dst, char *src)
{
	char tmp[17];
	UINT i;
	UINT copy_len;
	UINT wp;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	for (i = 0; i < 16; i++)
	{
		tmp[i] = ' ';
	}
	tmp[16] = 0;

	copy_len = StrLen(src);
	if (copy_len > 16)
	{
		copy_len = 16;
	}

	Copy(tmp, src, copy_len);

	wp = 0;

	tmp[15] = 0;

	for (i = 0; i < 16; i++)
	{
		char c = tmp[i];
		char *s = CharToNetBiosStr(c);

		dst[wp++] = s[0];
		dst[wp++] = s[1];
	}
}

// Convert the string to NetBIOS characters
char *CharToNetBiosStr(char c)
{
	c = ToUpper(c);

	switch (c)
	{
	case '\0':
		return "AA";
	case 'A':
		return "EB";
	case 'B':
		return "EC";
	case 'C':
		return "ED";
	case 'D':
		return "EE";
	case 'E':
		return "EF";
	case 'F':
		return "EG";
	case 'G':
		return "EH";
	case 'H':
		return "EI";
	case 'I':
		return "EJ";
	case 'J':
		return "EK";
	case 'K':
		return "EL";
	case 'L':
		return "EM";
	case 'M':
		return "EN";
	case 'N':
		return "EO";
	case 'O':
		return "EP";
	case 'P':
		return "FA";
	case 'Q':
		return "FB";
	case 'R':
		return "FC";
	case 'S':
		return "FD";
	case 'T':
		return "FE";
	case 'U':
		return "FF";
	case 'V':
		return "FG";
	case 'W':
		return "FH";
	case 'X':
		return "FI";
	case 'Y':
		return "FJ";
	case 'Z':
		return "FK";
	case '0':
		return "DA";
	case '1':
		return "DB";
	case '2':
		return "DC";
	case '3':
		return "DD";
	case '4':
		return "DE";
	case '5':
		return "DF";
	case '6':
		return "DG";
	case '7':
		return "DH";
	case '8':
		return "DI";
	case '9':
		return "DJ";
	case ' ':
		return "CA";
	case '!':
		return "CB";
	case '\"':
		return "CC";
	case '#':
		return "CD";
	case '$':
		return "CE";
	case '%':
		return "CF";
	case '&':
		return "CG";
	case '\'':
		return "CH";
	case '(':
		return "CI";
	case ')':
		return "CJ";
	case '*':
		return "CK";
	case '+':
		return "CL";
	case ',':
		return "CM";
	case '-':
		return "CN";
	case '.':
		return "CO";
	case '=':
		return "DN";
	case ':':
		return "DK";
	case ';':
		return "DL";
	case '@':
		return "EA";
	case '^':
		return "FO";
	case '_':
		return "FP";
	case '{':
		return "HL";
	case '}':
		return "HN";
	case '~':
		return "HO";
	}

	return "CA";
}

// Process if a NetBIOS name resolution packet for the my host name
bool ProcessNetBiosNameQueryPacketForMyself(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size)
{
	BUF *rb;
	USHORT tran_id;
	USHORT flags;
	USHORT num_query;
	USHORT zero1, zero2, zero3;
	UCHAR name_size;
	UCHAR encoded_name[32];
	UCHAR node_type;
	USHORT type, classid;
	UCHAR my_pc_encoded_name[32];
	bool ret = false;
	// Validate arguments
	if (v == NULL || data == NULL)
	{
		return false;
	}

	rb = NewBufFromMemory(data, size);

	ReadBuf(rb, &tran_id, sizeof(USHORT));

	ReadBuf(rb, &flags, sizeof(USHORT));
	flags = Endian16(flags);

	ReadBuf(rb, &num_query, sizeof(USHORT));
	num_query = Endian16(num_query);

	ReadBuf(rb, &zero1, sizeof(USHORT));
	ReadBuf(rb, &zero2, sizeof(USHORT));
	ReadBuf(rb, &zero3, sizeof(USHORT));

	ReadBuf(rb, &name_size, 1);

	ReadBuf(rb, encoded_name, 32);

	ReadBuf(rb, &node_type, 1);

	ReadBuf(rb, &type, sizeof(USHORT));
	type = Endian16(type);

	if (ReadBuf(rb, &classid, sizeof(USHORT)) == sizeof(USHORT))
	{
		classid = Endian16(classid);

		if (((flags >> 11) & 0x0F) == 0 &&
		        num_query == 1 && name_size == 0x20 &&
		        zero1 == 0 && zero2 == 0 && zero3 == 0 && node_type == 0 && type == 0x0020 && classid == 0x0001)
		{
			char my_pcname[MAX_SIZE];

			// Get the encoded name of this PC
			Zero(my_pcname, sizeof(my_pcname));
			GetMachineHostName(my_pcname, sizeof(my_pcname));

			EncodeNetBiosName(my_pc_encoded_name, my_pcname);

			if (Cmp(my_pc_encoded_name, encoded_name, 30) == 0)
			{
				// Assemble the response packet since the name resolution packet which targets this PC name received
				BUF *sb = NewBuf();
				USHORT us;
				UINT ui;
				LIST *ip_list;
				BUF *ip_list_buf;
				bool found = false;

				WriteBuf(sb, &tran_id, sizeof(USHORT));

				flags = Endian16(0x8500);
				WriteBuf(sb, &flags, sizeof(USHORT));

				num_query = 0;
				WriteBuf(sb, &num_query, sizeof(USHORT));

				us = Endian16(1);
				WriteBuf(sb, &us, sizeof(USHORT));

				us = 0;
				WriteBuf(sb, &us, sizeof(USHORT));
				WriteBuf(sb, &us, sizeof(USHORT));

				name_size = 0x20;
				WriteBuf(sb, &name_size, 1);

				WriteBuf(sb, encoded_name, 32);

				node_type = 0;
				WriteBuf(sb, &node_type, 1);

				type = Endian16(type);
				classid = Endian16(classid);

				WriteBuf(sb, &type, sizeof(USHORT));
				WriteBuf(sb, &classid, sizeof(USHORT));

				ui = Endian32((UINT)(Tick64() / 1000ULL));
				WriteBuf(sb, &ui, sizeof(UINT));

				ip_list_buf = NewBuf();

				ip_list = GetHostIPAddressList();
				if (ip_list != NULL)
				{
					UINT i;

					// Return only private IP if there is a private IP
					for (i = 0; i < LIST_NUM(ip_list); i++)
					{
						IP *ip = LIST_DATA(ip_list, i);

						if (IsIP4(ip) && IsLocalHostIP4(ip) == false && IsZeroIp(ip) == false)
						{
							if (IsIPPrivate(ip))
							{
								USHORT flags = Endian16(0x4000);
								UINT ip_uint = IPToUINT(ip);

								WriteBuf(ip_list_buf, &flags, sizeof(USHORT));
								WriteBuf(ip_list_buf, &ip_uint, sizeof(UINT));

								found = true;
							}
						}
					}

					if (found == false)
					{
						// Return all IP if no private IP are found
						for (i = 0; i < LIST_NUM(ip_list); i++)
						{
							IP *ip = LIST_DATA(ip_list, i);

							if (IsIP4(ip) && IsLocalHostIP4(ip) == false && IsZeroIp(ip) == false)
							{
								USHORT flags = Endian16(0x4000);
								UINT ip_uint = IPToUINT(ip);

								WriteBuf(ip_list_buf, &flags, sizeof(USHORT));
								WriteBuf(ip_list_buf, &ip_uint, sizeof(UINT));

								found = true;
							}
						}
					}

					FreeHostIPAddressList(ip_list);
				}

				us = Endian16(ip_list_buf->Size);
				WriteBuf(sb, &us, sizeof(USHORT));

				WriteBufBuf(sb, ip_list_buf);

				SendUdp(v, src_ip, src_port, v->HostIP, dest_port, sb->Buf, sb->Size);

				FreeBuf(ip_list_buf);

				FreeBuf(sb);

				WHERE;
			}
		}
	}

	FreeBuf(rb);

	return ret;
}

// Process the NetBIOS broadcast packet
void UdpRecvForNetBiosBroadcast(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, bool dns_proxy, bool unicast)
{
	// Validate arguments
	if (data == NULL || v == NULL)
	{
		return;
	}

	// Ignore for NetBIOS name registration packet
	if (IsNetbiosRegistrationPacket(data, size) == false)
	{
		if (unicast == false)
		{
			dest_ip = 0xFFFFFFFF;
		}

		if (ProcessNetBiosNameQueryPacketForMyself(v, src_ip, src_port, dest_ip, dest_port, data, size) == false)
		{
			UdpRecvForInternet(v, src_ip, src_port, dest_ip, dest_port, data, size, false);
		}
	}
}

// Process the UDP packet to the Internet
void UdpRecvForInternet(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, bool dns_proxy)
{
	NAT_ENTRY *n, t;
	BLOCK *block;
	void *buf;
	UINT dns_ip = 0;
	// Validate arguments
	if (data == NULL || v == NULL)
	{
		return;
	}

	if (dns_proxy)
	{
		// Get the DNS server of the proxy to connect to
		IP ip;
		char tmp[MAX_SIZE];
		if (GetDefaultDns(&ip) == false)
		{
			// Failure
			Debug("Failed to GetDefaultDns()\n");
			return;
		}
		dns_ip = IPToUINT(&ip);
		IPToStr(tmp, sizeof(tmp), &ip);
		Debug("Redirect to DNS Server %s\n", tmp);
	}

	// Examine whether the NAT entry for this packet has already been created
	SetNat(&t, NAT_UDP, src_ip, src_port, dest_ip, dest_port, 0, 0);
	n = SearchNat(v, &t);

	if (n == NULL)
	{
		// Create a NAT entry because it is the first packet
		n = CreateNatUdp(v, src_ip, src_port, dest_ip, dest_port, dns_proxy ? dns_ip : 0);
		if (n == NULL)
		{
			// Entry creation failed
			return;
		}

		if (dns_proxy)
		{
			n->ProxyDns = true;
			n->DestIpProxy = dns_ip;
		}
	}

	// Set the event by inserting the packet into the queue
	buf = Malloc(size);
	Copy(buf, data, size);
	block = NewBlock(buf, size, 0);
	InsertQueue(n->UdpSendQueue, block);

	SetSockEvent(v->SockEvent);
}

// Attempt to interpret the DNS packet
bool ParseDnsPacket(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size)
{
	return ParseDnsPacketEx(v, src_ip, src_port, dest_ip, dest_port, data, size, NULL);
}
bool ParseDnsPacketEx(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size, DNS_PARSED_PACKET *parsed_result)
{
	DNSV4_HEADER *dns;
	NAT_ENTRY *nat;
	UINT transaction_id;
	void *query_data;
	UINT query_data_size;
	char hostname[256];
	// Validate arguments
	if (v == NULL || data == NULL || size == 0)
	{
		return false;
	}

	// Check the header size
	if (size < sizeof(DNSV4_HEADER))
	{
		// Undersize
		return false;
	}

	// DNS header acquisition
	dns = (DNSV4_HEADER *)data;
	transaction_id = Endian16(dns->TransactionId);
	if ((dns->Flag1 & 78) != 0 || (dns->Flag1 & 0x80) != 0)
	{
		// Illegal opcode
		return false;
	}
	if (Endian16(dns->NumQuery) != 1)
	{
		// Number of queries is invalid
		return false;
	}

	query_data = ((UCHAR *)dns) + sizeof(DNSV4_HEADER);
	query_data_size = size - sizeof(DNSV4_HEADER);

	// Interpret the query
	if (ParseDnsQuery(hostname, sizeof(hostname), query_data, query_data_size) == false)
	{
		// Interpretation fails
		return false;
	}

	if (parsed_result != NULL)
	{
		// Only analyse without processing
		Zero(parsed_result, sizeof(DNS_PARSED_PACKET));
		StrCpy(parsed_result->Hostname, sizeof(parsed_result->Hostname), hostname);
		parsed_result->TransactionId = transaction_id;

		return true;
	}

	// Create a DNS entry
	nat = CreateNatDns(v, src_ip, src_port, dest_ip, dest_port, transaction_id,
	                   false, hostname);

	if (nat == false)
	{
		return false;
	}

	return true;
}

// Send the NAT DNS response packet
void SendNatDnsResponse(VH *v, NAT_ENTRY *n)
{
	BUF *b;
	UINT dns_header_size;
	DNSV4_HEADER *dns;
	UINT src_ip;
	// Validate arguments
	if (n == NULL || v == NULL)
	{
		return;
	}

	// Generate the data
	b = NewBuf();

	// Add a Query
	if (n->DnsGetIpFromHost == false)
	{
		BuildDnsQueryPacket(b, n->DnsTargetHostName, false);
	}
	else
	{
		BuildDnsQueryPacket(b, n->DnsTargetHostName, true);
	}

	// Add a Response
	if (n->DnsOk)
	{
		if (n->DnsGetIpFromHost == false)
		{
			BuildDnsResponsePacketA(b, &n->DnsResponseIp);
		}
		else
		{
			BuildDnsResponsePacketPtr(b, n->DnsResponseHostName);
		}
	}

	// Generate a DNS header
	dns_header_size = sizeof(DNSV4_HEADER) + b->Size;

	dns = ZeroMalloc(dns_header_size);
	dns->TransactionId = Endian16((USHORT)n->DnsTransactionId);

	// Generate a response flag
	if (n->DnsOk)
	{
		dns->Flag1 = 0x85;
		dns->Flag2 = 0x80;
	}
	else
	{
		dns->Flag1 = 0x85;
		dns->Flag2 = 0x83;
	}

	dns->NumQuery = Endian16(1);
	dns->AnswerRRs = Endian16(n->DnsOk != false ? 1 : 0);
	dns->AuthorityRRs = 0;
	dns->AdditionalRRs = 0;

	// Settings, such as the source IP address
	src_ip = n->DestIp;
	if (src_ip == Endian32(SPECIAL_IPV4_ADDR_LLMNR_DEST) && n->DestPort == SPECIAL_UDP_PORT_LLMNR)
	{
		// Make a unicast response in the case of LLMNR packet
		src_ip = v->HostIP;

		dns->Flag1 = 0x84;
		dns->Flag2 = 0x00;
	}

	// Copy data
	Copy(((UCHAR *)dns) + sizeof(DNSV4_HEADER), b->Buf, b->Size);

	// Send this packet
	SendUdp(v, n->SrcIp, n->SrcPort, src_ip, n->DestPort, dns, dns_header_size);

	// Release the memory
	Free(dns);
	FreeBuf(b);
}

// Generate a DNS response packet (host name)
void BuildDnsResponsePacketPtr(BUF *b, char *hostname)
{
	USHORT magic;
	USHORT type, clas;
	UINT ttl;
	USHORT len;
	BUF *c;
	// Validate arguments
	if (b == NULL || hostname == NULL)
	{
		return;
	}

	magic = Endian16(0xc00c);
	type = Endian16(0x000c);
	clas = Endian16(0x0001);
	ttl = Endian32(NAT_DNS_RESPONSE_TTL);

	c = BuildDnsHostName(hostname);
	if (c == NULL)
	{
		return;
	}
	len = Endian16((USHORT)c->Size);

	WriteBuf(b, &magic, 2);
	WriteBuf(b, &type, 2);
	WriteBuf(b, &clas, 2);
	WriteBuf(b, &ttl, 4);
	WriteBuf(b, &len, 2);
	WriteBuf(b, c->Buf, c->Size);
	FreeBuf(c);
}

// Generate a DNS response packet (host IP address)
void BuildDnsResponsePacketA(BUF *b, IP *ip)
{
	UINT ip_addr;
	USHORT magic;
	USHORT type, clas;
	UINT ttl;
	USHORT len;
	// Validate arguments
	if (b == NULL || ip == NULL)
	{
		return;
	}

	ip_addr = IPToUINT(ip);
	magic = Endian16(0xc00c);
	type = Endian16(0x0001);
	clas = Endian16(0x0001);
	ttl = Endian32(NAT_DNS_RESPONSE_TTL);
	len = Endian16((USHORT)sizeof(ttl));

	WriteBuf(b, &magic, sizeof(magic));
	WriteBuf(b, &type, sizeof(type));
	WriteBuf(b, &clas, sizeof(clas));
	WriteBuf(b, &ttl, sizeof(ttl));
	WriteBuf(b, &len, sizeof(len));
	WriteBuf(b, &ip_addr, sizeof(ip_addr));
}

// Generate a DNS query data packet
void BuildDnsQueryPacket(BUF *b, char *hostname, bool ptr)
{
	USHORT val;
	BUF *c;
	// Validate arguments
	if (b == NULL || hostname == NULL)
	{
		return;
	}

	// Convert the host name to a buffer
	c = BuildDnsHostName(hostname);
	if (c == NULL)
	{
		return;
	}

	WriteBuf(b, c->Buf, c->Size);
	FreeBuf(c);

	// Type and class
	if (ptr == false)
	{
		val = Endian16(0x0001);
	}
	else
	{
		val = Endian16(0x000c);
	}
	WriteBuf(b, &val, 2);

	val = Endian16(0x0001);
	WriteBuf(b, &val, 2);
}

// Generate a DNS host name buffer
BUF *BuildDnsHostName(char *hostname)
{
	UINT i;
	UCHAR size;
	TOKEN_LIST *token;
	BUF *b;
	// Validate arguments
	if (hostname == NULL)
	{
		return NULL;
	}

	// Split the host name into tokens
	token = ParseToken(hostname, ".");
	if (token == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	// Add a host string
	for (i = 0; i < token->NumTokens; i++)
	{
		size = (UCHAR)StrLen(token->Token[i]);
		WriteBuf(b, &size, 1);
		WriteBuf(b, token->Token[i], size);
	}

	// NULL character
	size = 0;
	WriteBuf(b, &size, 1);

	SeekBuf(b, 0, 0);

	FreeToken(token);

	return b;
}

// Process the NAT DNS entry
void PollingNatDns(VH *v, NAT_ENTRY *n)
{
	// Validate arguments
	if (v == NULL || n == NULL)
	{
		return;
	}

	if (n->DnsFinished)
	{
		if (n->DnsPollingFlag == false)
		{
			n->DnsPollingFlag = true;
			// Process has been completed
			SendNatDnsResponse(v, n);

			// Terminating
			n->DisconnectNow = true;
		}
	}
}

// Create a NAT DNS entry
NAT_ENTRY *CreateNatDns(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port,
                        UINT transaction_id, bool dns_get_ip_from_host, char *dns_target_host_name)
{
	NAT_ENTRY *n;
	HUB_OPTION *o;
	// Validate arguments
	if (v == NULL || dns_target_host_name == NULL)
	{
		return NULL;
	}

	if (CanCreateNewNatEntry(v) == false)
	{
		return NULL;
	}

	o = NatGetHubOption(v);
	if (o != NULL && o->SecureNAT_MaxDnsSessionsPerIp != 0)
	{
		if (GetNumNatEntriesPerIp(v, src_ip, NAT_DNS, false) >= o->SecureNAT_MaxDnsSessionsPerIp)
		{
			NAT_ENTRY *oldest = GetOldestNatEntryOfIp(v, src_ip, NAT_DNS);

			if (oldest != NULL)
			{
				DisconnectNatEntryNow(v, oldest);
			}
		}
	}

	n = ZeroMalloc(sizeof(NAT_ENTRY));
	n->Id = Inc(v->Counter);
	n->v = v;
	n->lock = NewLock();
	n->Protocol = NAT_DNS;
	n->SrcIp = src_ip;
	n->SrcPort = src_port;
	n->DestIp = dest_ip;
	n->DestPort = dest_port;
	n->DnsTransactionId = transaction_id;
	n->CreatedTime = n->LastCommTime = v->Now;
	n->DisconnectNow = false;

	n->DnsGetIpFromHost = false;
	n->DnsTargetHostName = CopyStr(dns_target_host_name);

	Add(v->NatTable, n);

#if	1
	{
		IP ip1, ip2;
		char s1[MAX_SIZE], s2[MAX_SIZE];
		UINTToIP(&ip1, src_ip);
		UINTToIP(&ip2, dest_ip);
		IPToStr(s1, 0, &ip1);
		IPToStr(s2, 0, &ip2);
		Debug("NAT_ENTRY: CreateNatDns %s %u -> %s %u\n", s1, src_port, s2, dest_port);
	}
#endif


	return n;
}

// Set the VGS host name
void SetDnsProxyVgsHostname(char *hostname)
{
	// Validate arguments
	if (hostname == NULL)
	{
		return;
	}

	StrCpy(v_vgs_hostname, sizeof(v_vgs_hostname), hostname);
}

// Operate as a DNS proxy
void DnsProxy(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size)
{
	// Validate arguments
	if (v == NULL || data == NULL || size == 0)
	{
		return;
	}

	if (dest_port == SPECIAL_UDP_PORT_LLMNR)
	{
		// Process by analyzing the DNS query in the case of LLMNR
		ParseDnsPacket(v, src_ip, src_port, dest_ip, dest_port, data, size);
	}
	else
	{
		// Forward the packet as it is in the case of a normal DNS packet
		if (IsEmptyStr(v_vgs_hostname) == false)
		{
			// Response by proxy in the case of trying to get the IP of the VGS
			DNS_PARSED_PACKET p;

			Zero(&p, sizeof(p));
			if (ParseDnsPacketEx(v, src_ip, src_port, dest_ip, dest_port, data, size, &p))
			{
				if (StrCmpi(p.Hostname, "254.254.211.10.in-addr.arpa") == 0)
				{
					NAT_ENTRY n;

					Zero(&n, sizeof(n));
					n.DnsTargetHostName = p.Hostname;
					n.DnsGetIpFromHost = true;
					n.DnsResponseHostName = v_vgs_hostname;
					n.DnsTransactionId = p.TransactionId;
					n.DnsOk = true;
					n.DestIp = dest_ip;
					n.SrcIp = src_ip;
					n.DestPort = dest_port;
					n.SrcPort = src_port;

					SendNatDnsResponse(v, &n);
					return;
				}
			}
		}

		UdpRecvForInternet(v, src_ip, src_port, dest_ip, dest_port, data, size, true);
	}
}

// Process the LLMNR query
void UdpRecvLlmnr(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size)
{
	// Validate arguments
	if (data == NULL || v == NULL)
	{
		return;
	}

	if (dest_port == SPECIAL_UDP_PORT_LLMNR)
	{
		// DNS proxy start
		DnsProxy(v, src_ip, src_port, dest_ip, dest_port, data, size);
	}
}

// Process the UDP packet to the virtual host
void UdpRecvForMe(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size)
{
	// Validate arguments
	if (data == NULL || v == NULL)
	{
		return;
	}

	if (dest_port == NAT_DNS_PROXY_PORT)
	{
		// DNS proxy start
		DnsProxy(v, src_ip, src_port, dest_ip, dest_port, data, size);
	}
}

// Process the UDP broadcast packet
void UdpRecvForBroadcast(VH *v, UINT src_ip, UINT src_port, UINT dest_ip, UINT dest_port, void *data, UINT size)
{
	// Validate arguments
	if (data == NULL || v == NULL)
	{
		return;
	}
}

// An UDP packet has been received
void VirtualUdpReceived(VH *v, UINT src_ip, UINT dest_ip, void *data, UINT size, bool mac_broadcast, bool is_localmac, UINT max_l3_size)
{
	UDP_HEADER *udp;
	UINT packet_length;
	void *buf;
	UINT buf_size;
	UINT src_port, dest_port;
	// Validate arguments
	if (v == NULL || data == NULL)
	{
		return;
	}

	// Check the header
	udp = (UDP_HEADER *)data;
	if (size < UDP_HEADER_SIZE)
	{
		return;
	}
	packet_length = Endian16(udp->PacketLength);
	if (packet_length != size)
	{
		return;
	}
	buf = ((UCHAR *)data) + UDP_HEADER_SIZE;
	buf_size = size - UDP_HEADER_SIZE;
	src_port = Endian16(udp->SrcPort);
	dest_port = Endian16(udp->DstPort);
	// Check the port number
	if (dest_port == 0)
	{
		// Port number is invalid
		return;
	}

	// Determine whether it's broadcast packet or packet addressed to myself
	if (dest_ip == v->HostIP)
	{
		// IP packet addressed to myself has arrived
		UdpRecvForMe(v, src_ip, src_port, dest_ip, dest_port, buf, buf_size);
	}
	else if ((mac_broadcast || dest_ip == Endian32(0xE00000FC)) && dest_port == SPECIAL_UDP_PORT_LLMNR)
	{
		if (is_localmac == false)
		{
			// Packet addressed to 224.0.0.252 (LLMNR) arrives
			UdpRecvLlmnr(v, src_ip, src_port, dest_ip, dest_port, buf, buf_size);
		}
	}
	else if (mac_broadcast && (dest_port == SPECIAL_UDP_PORT_WSD || dest_port == SPECIAL_UDP_PORT_SSDP))
	{
		if (is_localmac == false)
		{
			// WS-Discovery packet arrives
			UdpRecvForInternet(v, src_ip, src_port, 0xFFFFFFFF, dest_port, buf, buf_size, false);
		}
	}
	else if (mac_broadcast && (dest_port == SPECIAL_UDP_PORT_NBTDGM || dest_port == SPECIAL_UDP_PORT_NBTNS))
	{
		if (is_localmac == false)
		{
			// NetBIOS Broadcast packet arrived
			UdpRecvForNetBiosBroadcast(v, src_ip, src_port, dest_ip, dest_port, buf, buf_size, false, false);
		}
	}
	else if (mac_broadcast || dest_ip == 0xffffffff || dest_ip == GetBroadcastAddress(v->HostIP, v->HostMask))
	{
		if (is_localmac == false)
		{
			// Broadcast packet arrived
			UdpRecvForBroadcast(v, src_ip, src_port, dest_ip, dest_port, buf, buf_size);
		}
	}
	else if (IsInNetwork(dest_ip, v->HostIP, v->HostMask) == false)
	{
		// Packets to other than local address (that is on the Internet) has been received
		if (NnIsActive(v) == false)
		{
			if (v->HubOption != NULL && v->HubOption->DisableUserModeSecureNAT)
			{
				// User-mode NAT is disabled
				return;
			}

			// User-mode NAT
			UdpRecvForInternet(v, src_ip, src_port, dest_ip, dest_port, buf, buf_size, false);
		}
		else
		{
			// Kernel-mode NAT
			NnUdpRecvForInternet(v, src_ip, src_port, dest_ip, dest_port, buf, buf_size, max_l3_size);
		}
	}
	else
	{
		// Local address has arrived. Ignore it
	}
}

// Determine the network address of the subnet to which the specified IP address belongs
UINT GetNetworkAddress(UINT addr, UINT mask)
{
	return (addr & mask);
}

// Determine the broadcast address of the subnet to which the specified IP address belongs
UINT GetBroadcastAddress(UINT addr, UINT mask)
{
	return ((addr & mask) | (~mask));
}
void GetBroadcastAddress4(IP *dst, IP *addr, IP *mask)
{
	// Validate arguments
	if (dst == NULL || IsIP4(addr) == false || IsIP4(mask) == false)
	{
		Zero(dst, sizeof(IP));
		return;
	}

	UINTToIP(dst, GetBroadcastAddress(IPToUINT(addr), IPToUINT(mask)));
}

// Determine whether the specified IP address belongs to the sub-network that is
// represented by a another specified network address and a subnet mask
bool IsInNetwork(UINT uni_addr, UINT network_addr, UINT mask)
{
	if (GetNetworkAddress(uni_addr, mask) == GetNetworkAddress(network_addr, mask))
	{
		return true;
	}
	return false;
}

// Send an UDP packet
void SendUdp(VH *v, UINT dest_ip, UINT dest_port, UINT src_ip, UINT src_port, void *data, UINT size)
{
	UDPV4_PSEUDO_HEADER *vh;
	UDP_HEADER *udp;
	UINT udp_packet_length = UDP_HEADER_SIZE + size;
	USHORT checksum;
	// Validate arguments
	if (v == NULL || data == NULL)
	{
		return;
	}
	if (udp_packet_length > 65536)
	{
		return;
	}

	// Generate a virtual header
	vh = Malloc(sizeof(UDPV4_PSEUDO_HEADER) + size);
	udp = (UDP_HEADER *)(((UCHAR *)vh) + 12);

	vh->SrcIP = src_ip;
	vh->DstIP = dest_ip;
	vh->Reserved = 0;
	vh->Protocol = IP_PROTO_UDP;
	vh->PacketLength1 = Endian16((USHORT)udp_packet_length);
	udp->SrcPort = Endian16((USHORT)src_port);
	udp->DstPort = Endian16((USHORT)dest_port);
	udp->PacketLength = Endian16((USHORT)udp_packet_length);
	udp->Checksum = 0;

	// Copy data
	Copy(((UCHAR *)udp) + UDP_HEADER_SIZE, data, size);

	// Calculate the checksum
	checksum = IpChecksum(vh, udp_packet_length + 12);
	if (checksum == 0x0000)
	{
		checksum = 0xffff;
	}
	udp->Checksum = checksum;

	// Send a packet
	SendIp(v, dest_ip, src_ip, IP_PROTO_UDP, udp, udp_packet_length);

	// Release the memory
	Free(vh);
}

// Poll the IP combining object
void PollingIpCombine(VH *v)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Discard the old combining object
	o = NULL;
	for (i = 0; i < LIST_NUM(v->IpCombine); i++)
	{
		IP_COMBINE *c = LIST_DATA(v->IpCombine, i);

		if (c->Expire < v->Now)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Add(o, c);
		}
	}

	if (o != NULL)
	{
		for (i = 0; i < LIST_NUM(o); i++)
		{
			IP_COMBINE *c = LIST_DATA(o, i);

			// Remove from the list
			Delete(v->IpCombine, c);

			// Release the memory
			FreeIpCombine(v, c);
		}
		ReleaseList(o);
	}
}

// Send an ICMP packet
void VirtualIcmpSend(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size)
{
	ICMP_HEADER *icmp;
	void *data_buf;
	// Validate arguments
	if (v == NULL || data == NULL)
	{
		return;
	}

	// Build the header
	icmp = ZeroMalloc(sizeof(ICMP_HEADER) + size);
	// Data copy
	data_buf = ((UCHAR *)icmp) + sizeof(ICMP_HEADER);
	Copy(data_buf, data, size);
	// Other
	icmp->Checksum = 0;
	icmp->Code = 0;
	icmp->Type = ICMP_TYPE_ECHO_RESPONSE;
	// Checksum
	icmp->Checksum = IpChecksum(icmp, sizeof(ICMP_HEADER) + size);

	// IP packet transmission
	SendIp(v, dst_ip, src_ip, IP_PROTO_ICMPV4, icmp, sizeof(ICMP_HEADER) + size);

	// Release the memory
	Free(icmp);
}

// Send the ICMP Echo Response packet
void VirtualIcmpEchoSendResponse(VH *v, UINT src_ip, UINT dst_ip, USHORT id, USHORT seq_no, void *data, UINT size)
{
	ICMP_ECHO *e;
	// Validate arguments
	if (v == NULL || data == NULL)
	{
		return;
	}

	// Build the header
	e = ZeroMalloc(sizeof(ICMP_ECHO) + size);
	e->Identifier = Endian16(id);
	e->SeqNo = Endian16(seq_no);

	// Data copy
	Copy(((UCHAR *)e) + sizeof(ICMP_ECHO), data, size);

	// Send an ICMP
	VirtualIcmpSend(v, src_ip, dst_ip, e, sizeof(ICMP_ECHO) + size);

	// Release the memory
	Free(e);
}

// Treat the ICMP Echo Request packet with a Raw Socket
void VirtualIcmpEchoRequestReceivedRaw(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size, UCHAR ttl, void *icmp_data, UINT icmp_size, UCHAR *ip_header, UINT ip_header_size)
{
	ICMP_ECHO *echo;
	UINT data_size;
	void *data_buf;
	USHORT id, seq_no;
	void *buf;
	BLOCK *block;
	// Validate arguments
	if (v == NULL || data == NULL || icmp_data == NULL || ip_header == NULL)
	{
		return;
	}
	if (ttl == 0)
	{
		ttl = 1;
	}

	echo = (ICMP_ECHO *)data;

	// Echo size check
	if (size < sizeof(ICMP_ECHO))
	{
		// Insufficient data
		return;
	}

	id = Endian16(echo->Identifier);
	seq_no = Endian16(echo->SeqNo);

	// Data size
	data_size = size - sizeof(ICMP_ECHO);

	// Data body
	data_buf = ((UCHAR *)data) + sizeof(ICMP_ECHO);

	if (dst_ip == v->HostIP)
	{
		// Respond because it is addressed to me
		VirtualIcmpEchoSendResponse(v, v->HostIP, src_ip, id, seq_no, data_buf, data_size);
	}
	else if (IsInNetwork(dst_ip, v->HostIP, v->HostMask) == false)
	{
		NAT_ENTRY *n = NULL, t;
		// Process by creating a NAT entry because it is addressed to the Internet

		if (ttl <= 1)
		{
			// Reply the Time Exceeded immediately for the packet whose TTL is 1
			UINT reply_size = sizeof(ICMP_HEADER) + 4 + ip_header_size + 8;
			UCHAR *reply_data = ZeroMalloc(reply_size);
			ICMP_HEADER *icmp = (ICMP_HEADER *)reply_data;
			icmp->Type = ICMP_TYPE_TIME_EXCEEDED;
			icmp->Code = ICMP_CODE_TTL_EXCEEDED_IN_TRANSIT;
			Copy(reply_data + sizeof(ICMP_HEADER) + 4, ip_header, ip_header_size);
			Copy(reply_data + sizeof(ICMP_HEADER) + 4 + ip_header_size, icmp_data, MIN(icmp_size, 8));

			icmp->Checksum = IpChecksum(icmp, reply_size);

			SendIp(v, src_ip, v->HostIP, IP_PROTO_ICMPV4, reply_data, reply_size);

			Free(reply_data);
		}
		else
		{
			SetNat(&t, NAT_ICMP, src_ip, id, dst_ip, id, 0, 0);

			if (v->IcmpRawSocketOk)
			{
				// Examine whether a NAT entry for this packet has already been created
				n = SearchNat(v, &t);
			}

			if (n == NULL)
			{
				// Create a NAT entry because it is the first packet
				n = CreateNatIcmp(v, src_ip, id, dst_ip, id, (UCHAR *)ip_header, ip_header_size + 8);

				if (n == NULL)
				{
					// Entry creation failed
					return;
				}
			}

			// Set the event by inserting the packet into the queue
			buf = Malloc(icmp_size);
			Copy(buf, icmp_data, icmp_size);
			block = NewBlock(buf, icmp_size, 0);
			block->Ttl = MAKESURE(ttl - 1, 1, 255);
			InsertQueue(n->UdpSendQueue, block);

			SetSockEvent(v->SockEvent);
		}
	}
}

// Receive an ICMP Echo Request packet
void VirtualIcmpEchoRequestReceived(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size, UCHAR ttl, void *icmp_data, UINT icmp_size, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size)
{
	ICMP_ECHO *echo;
	UINT data_size;
	void *data_buf;
	USHORT id, seq_no;
	// Validate arguments
	if (v == NULL || data == NULL || icmp_data == NULL)
	{
		return;
	}

	//Debug("ICMP: %u\n", size);

	if (NnIsActive(v))
	{
		// Process by the Native NAT
		NnIcmpEchoRecvForInternet(v, src_ip, dst_ip, data, size, ttl, icmp_data, icmp_size,
		                          ip_header, ip_header_size, max_l3_size);
		return;
	}

	if (v->HubOption != NULL && v->HubOption->DisableUserModeSecureNAT)
	{
		// User-mode NAT is disabled
		return;
	}

	if (v->IcmpRawSocketOk || v->IcmpApiOk)
	{
		// Process in the Raw Socket
		VirtualIcmpEchoRequestReceivedRaw(v, src_ip, dst_ip, data, size, ttl, icmp_data, icmp_size,
		                                  ip_header, ip_header_size);
		return;
	}

	// Returns the fake ICMP forcibly if any of Native NAT or Raw Socket can not be used

	echo = (ICMP_ECHO *)data;

	// Echo size check
	if (size < sizeof(ICMP_ECHO))
	{
		// Insufficient data
		return;
	}

	id = Endian16(echo->Identifier);
	seq_no = Endian16(echo->SeqNo);

	// Data size
	data_size = size - sizeof(ICMP_ECHO);

	// Data body
	data_buf = ((UCHAR *)data) + sizeof(ICMP_ECHO);

	// Return the ICMP Echo Response
	VirtualIcmpEchoSendResponse(v, dst_ip, src_ip, id, seq_no, data_buf, data_size);
}

// An ICMP packet has been received
void VirtualIcmpReceived(VH *v, UINT src_ip, UINT dst_ip, void *data, UINT size, UCHAR ttl, UCHAR *ip_header, UINT ip_header_size, UINT max_l3_size)
{
	ICMP_HEADER *icmp;
	UINT msg_size;
	USHORT checksum_calc, checksum_original;
	// Validate arguments
	if (v == NULL || data == NULL)
	{
		return;
	}

	// Size check
	if (size < sizeof(ICMP_HEADER))
	{
		return;
	}

	// ICMP header
	icmp = (ICMP_HEADER *)data;

	// Get the ICMP message size
	msg_size = size - sizeof(ICMP_HEADER);

	// Check the checksum of the ICMP header
	checksum_original = icmp->Checksum;
	icmp->Checksum = 0;
	checksum_calc = IpChecksum(data, size);
	icmp->Checksum = checksum_original;

	if (checksum_calc != checksum_original)
	{
		// Checksum is invalid
		Debug("ICMP CheckSum Failed.\n");
		return;
	}

	// Identified by the opcode
	switch (icmp->Type)
	{
	case ICMP_TYPE_ECHO_REQUEST:	// ICMP Echo request
		VirtualIcmpEchoRequestReceived(v, src_ip, dst_ip, ((UCHAR *)data) + sizeof(ICMP_HEADER), msg_size, ttl,
		                               icmp, size, ip_header, ip_header_size, max_l3_size);
		break;

	case ICMP_TYPE_ECHO_RESPONSE:	// ICMP Echo response
		// Do Nothing
		break;
	}
}

// Received an IP packet
void IpReceived(VH *v, UINT src_ip, UINT dest_ip, UINT protocol, void *data, UINT size, bool mac_broadcast, UCHAR ttl, UCHAR *ip_header, UINT ip_header_size, bool is_local_mac, UINT max_l3_size)
{
	// Validate arguments
	if (v == NULL || data == NULL)
	{
		return;
	}

	// Deliver the data to the supported high-level protocol
	switch (protocol)
	{
	case IP_PROTO_ICMPV4:	// ICMPv4
		if (mac_broadcast == false)
		{
			VirtualIcmpReceived(v, src_ip, dest_ip, data, size, ttl, ip_header, ip_header_size, max_l3_size);
		}
		break;

	case IP_PROTO_TCP:		// TCP
		if (mac_broadcast == false)
		{
			VirtualTcpReceived(v, src_ip, dest_ip, data, size, max_l3_size);
		}
		break;

	case IP_PROTO_UDP:		// UDP
		VirtualUdpReceived(v, src_ip, dest_ip, data, size, mac_broadcast, is_local_mac, max_l3_size);
		break;
	}
}

// Combine the IP packet received to the IP combining object
void CombineIp(VH *v, IP_COMBINE *c, UINT offset, void *data, UINT size, bool last_packet, UCHAR *head_ip_header_data, UINT head_ip_header_size)
{
	UINT i;
	IP_PART *p;
	UINT need_size;
	UINT data_size_delta;
	// Validate arguments
	if (c == NULL || data == NULL)
	{
		return;
	}

	// Check the size and offset
	if ((offset + size) > 65535)
	{
		// Do not process packet larger than 64Kbytes
		return;
	}

	if (last_packet == false && c->Size != 0)
	{
		if ((offset + size) > c->Size)
		{
			// Do not process the packet larger than the packet size
			return;
		}
	}

	if (head_ip_header_data != NULL && head_ip_header_size >= sizeof(IPV4_HEADER))
	{
		if (c->HeadIpHeaderData == NULL)
		{
			c->HeadIpHeaderData = Clone(head_ip_header_data, head_ip_header_size);
			c->HeadIpHeaderDataSize = head_ip_header_size;
		}
	}

	need_size = offset + size;
	data_size_delta = c->DataReserved;
	// Ensure sufficient if the buffer is insufficient
	while (c->DataReserved < need_size)
	{
		c->DataReserved = c->DataReserved * 4;
		c->Data = ReAlloc(c->Data, c->DataReserved);
	}
	data_size_delta = c->DataReserved - data_size_delta;
	v->CurrentIpQuota += data_size_delta;

	// Overwrite the data into the buffer
	Copy(((UCHAR *)c->Data) + offset, data, size);

	if (last_packet)
	{
		// If No More Fragment packet arrives, the size of this datagram is finalized
		c->Size = offset + size;
	}

	// Check the overlap between the region which is represented by the offset and size of the
	// existing received list and the region which is represented by the offset and size
	for (i = 0; i < LIST_NUM(c->IpParts); i++)
	{
		UINT moving_size;
		IP_PART *p = LIST_DATA(c->IpParts, i);

		// Check the overlapping between the existing area and head area
		if ((p->Offset <= offset) && ((p->Offset + p->Size) > offset))
		{
			// Compress behind the offset of this packet since a duplication is
			// found in the first part with the existing packet and this packet

			if ((offset + size) <= (p->Offset + p->Size))
			{
				// This packet is buried in the existing packet
				size = 0;
			}
			else
			{
				// Retral region is not overlapped
				moving_size = p->Offset + p->Size - offset;
				offset += moving_size;
				size -= moving_size;
			}
		}
		if ((p->Offset < (offset + size)) && ((p->Offset + p->Size) >= (offset + size)))
		{
			// Compress the size of this packet forward because a duplication is
			// found between the posterior portion the existing packet and this packet

			moving_size = p->Offset + p->Size - offset - size;
			size -= moving_size;
		}

		if ((p->Offset >= offset) && ((p->Offset + p->Size) <= (offset + size)))
		{
			// This packet was overwritten to completely cover an existing packet
			p->Size = 0;
		}
	}

	if (size != 0)
	{
		// Register this packet
		p = ZeroMalloc(sizeof(IP_PART));

		p->Offset = offset;
		p->Size = size;

		Add(c->IpParts, p);
	}

	if (c->Size != 0)
	{
		// Get the total size of the data portion list already received
		UINT total_size = 0;
		UINT i;

		for (i = 0; i < LIST_NUM(c->IpParts); i++)
		{
			IP_PART *p = LIST_DATA(c->IpParts, i);

			total_size += p->Size;
		}

		if (total_size == c->Size)
		{
			// Received all of the IP packet
			IpReceived(v, c->SrcIP, c->DestIP, c->Protocol, c->Data, c->Size, c->MacBroadcast, c->Ttl,
			           c->HeadIpHeaderData, c->HeadIpHeaderDataSize, c->SrcIsLocalMacAddr, c->MaxL3Size);

			// Release the combining object
			FreeIpCombine(v, c);

			// Remove from the combining object list
			Delete(v->IpCombine, c);
		}
	}
}

// Release the IP combining object
void FreeIpCombine(VH *v, IP_COMBINE *c)
{
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Release the data
	v->CurrentIpQuota -= c->DataReserved;
	Free(c->Data);

	// Release the partial list
	for (i = 0; i < LIST_NUM(c->IpParts); i++)
	{
		IP_PART *p = LIST_DATA(c->IpParts, i);

		Free(p);
	}

	Free(c->HeadIpHeaderData);

	ReleaseList(c->IpParts);
	Free(c);
}

// Search the IP combining list
IP_COMBINE *SearchIpCombine(VH *v, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol)
{
	IP_COMBINE *c, t;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	t.DestIP = dest_ip;
	t.SrcIP = src_ip;
	t.Id = id;
	t.Protocol = protocol;

	c = Search(v->IpCombine, &t);

	return c;
}

// Insert by creating a new object to the IP combining list
IP_COMBINE *InsertIpCombine(VH *v, UINT src_ip, UINT dest_ip, USHORT id, UCHAR protocol, bool mac_broadcast, UCHAR ttl, bool src_is_localmac)
{
	IP_COMBINE *c;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	// Examine the quota
	if ((v->CurrentIpQuota + IP_COMBINE_INITIAL_BUF_SIZE) > IP_COMBINE_WAIT_QUEUE_SIZE_QUOTA)
	{
		// IP packet can not be stored any more
		return NULL;
	}

	c = ZeroMalloc(sizeof(IP_COMBINE));
	c->SrcIsLocalMacAddr = src_is_localmac;
	c->DestIP = dest_ip;
	c->SrcIP = src_ip;
	c->Id = id;
	c->Expire = v->Now + (UINT64)IP_COMBINE_TIMEOUT;
	c->Size = 0;
	c->IpParts = NewList(NULL);
	c->Protocol = protocol;
	c->MacBroadcast = mac_broadcast;
	c->Ttl = ttl;

	// Secure the memory
	c->DataReserved = IP_COMBINE_INITIAL_BUF_SIZE;
	c->Data = Malloc(c->DataReserved);
	v->CurrentIpQuota += c->DataReserved;

	Insert(v->IpCombine, c);

	return c;
}

// Initialize the IP combining list
void InitIpCombineList(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	v->IpCombine = NewList(CompareIpCombine);
}

// Release the IP combining list
void FreeIpCombineList(VH *v)
{
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(v->IpCombine); i++)
	{
		IP_COMBINE *c = LIST_DATA(v->IpCombine, i);

		FreeIpCombine(v, c);
	}

	ReleaseList(v->IpCombine);
}

// Comparison of IP combining list entry
int CompareIpCombine(void *p1, void *p2)
{
	IP_COMBINE *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(IP_COMBINE **)p1;
	c2 = *(IP_COMBINE **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}
	if (c1->Id > c2->Id)
	{
		return 1;
	}
	else if (c1->Id < c2->Id)
	{
		return -1;
	}
	else if (c1->DestIP > c2->DestIP)
	{
		return 1;
	}
	else if (c1->DestIP < c2->DestIP)
	{
		return -1;
	}
	else if (c1->SrcIP > c2->SrcIP)
	{
		return 1;
	}
	else if (c1->SrcIP < c2->SrcIP)
	{
		return -1;
	}
	else if (c1->Protocol > c2->Protocol)
	{
		return 1;
	}
	else if (c1->Protocol < c2->Protocol)
	{
		return -1;
	}
	return 0;
}

// Received an IP packet
void VirtualIpReceived(VH *v, PKT *packet)
{
	IPV4_HEADER *ip;
	void *data;
	UINT data_size_recved;
	UINT size;
	UINT ipv4_header_size;
	bool last_packet;
	UCHAR *head_ip_header_data = NULL;
	UINT head_ip_header_size = 0;
	bool is_local_mac = false;
	UINT ip_l3_size;
	// Validate arguments
	if (v == NULL || packet == NULL)
	{
		return;
	}

	ip = packet->L3.IPv4Header;

	if (packet->BroadcastPacket)
	{
		is_local_mac = IsMacAddressLocalFast(packet->MacAddressSrc);
	}

	// Get the size of the IPv4 header
	ipv4_header_size = IPV4_GET_HEADER_LEN(packet->L3.IPv4Header) * 4;
	head_ip_header_size = ipv4_header_size;

	// Calculate the checksum of the IPv4 header
	if (IpCheckChecksum(ip) == false)
	{
		return;
	}

	// Get a pointer to the data
	data = ((UCHAR *)packet->L3.PointerL3) + ipv4_header_size;

	// Register to the ARP table
	ArpIpWasKnown(v, packet->L3.IPv4Header->SrcIP, packet->MacAddressSrc);

	// Get the data size
	size = ip_l3_size = Endian16(ip->TotalLength);
	if (size <= ipv4_header_size)
	{
		// There is no data
		return;
	}
	size -= ipv4_header_size;

	// Get the size of data actually received
	data_size_recved = packet->PacketSize - (ipv4_header_size + MAC_HEADER_SIZE);
	if (data_size_recved < size)
	{
		// Data insufficient (It may be missing on the way)
		return;
	}

	if (IPV4_GET_OFFSET(ip) == 0 && (IPV4_GET_FLAGS(ip) & 0x01) == 0)
	{
		// Because this packet has not been fragmented, it can be delivered to the upper layer immediately
		head_ip_header_data = (UCHAR *)packet->L3.IPv4Header;
		IpReceived(v, ip->SrcIP, ip->DstIP, ip->Protocol, data, size, packet->BroadcastPacket, ip->TimeToLive,
		           head_ip_header_data, head_ip_header_size, is_local_mac, ip_l3_size);
	}
	else
	{
		// This packet is necessary to combine because it is fragmented
		UINT offset = IPV4_GET_OFFSET(ip) * 8;
		IP_COMBINE *c = SearchIpCombine(v, ip->SrcIP, ip->DstIP, Endian16(ip->Identification), ip->Protocol);

		if (offset == 0)
		{
			head_ip_header_data = (UCHAR *)packet->L3.IPv4Header;
		}

		last_packet = ((IPV4_GET_FLAGS(ip) & 0x01) == 0 ? true : false);

		if (c != NULL)
		{
			// It is the second or subsequent packet
			c->MaxL3Size = MAX(c->MaxL3Size, ip_l3_size);
			CombineIp(v, c, offset, data, size, last_packet, head_ip_header_data, head_ip_header_size);
		}
		else
		{
			// Create a combining object because it is the first packet
			c = InsertIpCombine(
			        v, ip->SrcIP, ip->DstIP, Endian16(ip->Identification), ip->Protocol, packet->BroadcastPacket,
			        ip->TimeToLive, is_local_mac);
			if (c != NULL)
			{
				c->MaxL3Size = ip_l3_size;

				CombineIp(v, c, offset, data, size, last_packet, head_ip_header_data, head_ip_header_size);
			}
		}
	}
}

// Send the waiting IP packets from the specified IP address
void SendWaitingIp(VH *v, UCHAR *mac, UINT dest_ip)
{
	UINT i;
	LIST *o = NULL;
	// Validate arguments
	if (v == NULL || mac == NULL)
	{
		return;
	}

	// Get a target list
	for (i = 0; i < LIST_NUM(v->IpWaitTable); i++)
	{
		IP_WAIT *w = LIST_DATA(v->IpWaitTable, i);

		if (w->DestIP == dest_ip)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Add(o, w);
		}
	}

	// Send the target packets at once
	if (o != NULL)
	{
		for (i = 0; i < LIST_NUM(o); i++)
		{
			IP_WAIT *w = LIST_DATA(o, i);

			// Transmission processing
			VirtualIpSend(v, mac, w->Data, w->Size);

			// Remove from the list
			Delete(v->IpWaitTable, w);

			// Release the memory
			Free(w->Data);
			Free(w);
		}

		ReleaseList(o);
	}
}

// Remove the old IP waiting table entries
void DeleteOldIpWaitTable(VH *v)
{
	UINT i;
	LIST *o = NULL;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Get the deleting list
	for (i = 0; i < LIST_NUM(v->IpWaitTable); i++)
	{
		IP_WAIT *w = LIST_DATA(v->IpWaitTable, i);

		if (w->Expire < v->Now)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Add(o, w);
		}
	}

	// Delete all at once
	if (o != NULL)
	{
		for (i = 0; i < LIST_NUM(o); i++)
		{
			IP_WAIT *w = LIST_DATA(o, i);

			// Remove from the list
			Delete(v->IpWaitTable, w);

			// Release the memory
			Free(w->Data);
			Free(w);
		}
		ReleaseList(o);
	}
}

// Poll the IP waiting table
void PollingIpWaitTable(VH *v)
{
	// Delete the old table entries
	DeleteOldIpWaitTable(v);
}

// Insert the IP packet to the IP waiting table
void InsertIpWaitTable(VH *v, UINT dest_ip, UINT src_ip, void *data, UINT size)
{
	IP_WAIT *w;
	// Validate arguments
	if (v == NULL || data == NULL || size == 0)
	{
		return;
	}

	w = ZeroMalloc(sizeof(IP_WAIT));
	w->Data = data;
	w->Size = size;
	w->SrcIP = src_ip;
	w->DestIP = dest_ip;
	w->Expire = v->Now + (UINT64)IP_WAIT_FOR_ARP_TIMEOUT;

	Add(v->IpWaitTable, w);
}

// Initialize the IP waiting table
void InitIpWaitTable(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	v->IpWaitTable = NewList(NULL);
}

// Release the IP waiting table
void FreeIpWaitTable(VH *v)
{
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(v->IpWaitTable); i++)
	{
		IP_WAIT *w = LIST_DATA(v->IpWaitTable, i);

		Free(w->Data);
		Free(w);
	}

	ReleaseList(v->IpWaitTable);
}

// MAC address for the IP address is found because something such as an ARP Response arrives
void ArpIpWasKnown(VH *v, UINT ip, UCHAR *mac)
{
	// Validate arguments
	if (v == NULL || mac == NULL)
	{
		return;
	}

	// If there is a query for this IP address in the ARP queue, delete it
	DeleteArpWaitTable(v, ip);

	// Update or register in the ARP table
	InsertArpTable(v, mac, ip);

	// Send the IP packets waiting in the IP waiting list
	SendWaitingIp(v, mac, ip);
}

// Re-issue ARPs by checking the ARP waiting list
void PollingArpWaitTable(VH *v)
{
	UINT i;
	LIST *o;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Initialize the deletion list
	o = NULL;

	// Scan whole ARP waiting list
	for (i = 0; i < LIST_NUM(v->ArpWaitTable); i++)
	{
		ARP_WAIT *w = LIST_DATA(v->ArpWaitTable, i);

		if (w->GiveupTime < v->Now || (w->GiveupTime - 100 * 1000) > v->Now)
		{
			// Give up the sending of ARP
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}
			Add(o, w);
		}
		else
		{
			if (w->TimeoutTime < v->Now)
			{
				// Send an ARP again
				VirtualArpSendRequest(v, w->IpAddress);

				// Set the next timeout time
				w->TimeoutTime = v->Now + (UINT64)w->NextTimeoutTimeValue;
				// Increase the ARP transmission interval of the second and subsequent
				w->NextTimeoutTimeValue = w->NextTimeoutTimeValue + ARP_REQUEST_TIMEOUT;
			}
		}
	}

	// Remove if there is a ARP waiting record to be deleted
	if (o != NULL)
	{
		for (i = 0; i < LIST_NUM(o); i++)
		{
			ARP_WAIT *w = LIST_DATA(o, i);

			DeleteArpWaitTable(v, w->IpAddress);
		}
		ReleaseList(o);
	}
}

// Issue an ARP
void SendArp(VH *v, UINT ip)
{
	ARP_WAIT *w;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Examine whether the destination IP address has been registered in the ARP waiting list first
	w = SearchArpWaitTable(v, ip);
	if (w != NULL)
	{
		// Do not do anything because it is already registered
		return;
	}

	// Send an ARP packet first
	VirtualArpSendRequest(v, ip);

	// Register in the ARP waiting list
	w = ZeroMalloc(sizeof(ARP_WAIT));
	w->GiveupTime = v->Now + (UINT64)ARP_REQUEST_GIVEUP;
	w->TimeoutTime = v->Now + (UINT64)ARP_REQUEST_TIMEOUT;
	w->NextTimeoutTimeValue = ARP_REQUEST_TIMEOUT;
	w->IpAddress = ip;

	InsertArpWaitTable(v, w);
}

// Delete the ARP waiting table
void DeleteArpWaitTable(VH *v, UINT ip)
{
	ARP_WAIT *w;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	w = SearchArpWaitTable(v, ip);
	if (w == NULL)
	{
		return;
	}
	Delete(v->ArpWaitTable, w);

	Free(w);
}

// Search the ARP waiting table
ARP_WAIT *SearchArpWaitTable(VH *v, UINT ip)
{
	ARP_WAIT *w, t;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	t.IpAddress = ip;
	w = Search(v->ArpWaitTable, &t);

	return w;
}

// Register in the ARP waiting table
void InsertArpWaitTable(VH *v, ARP_WAIT *w)
{
	// Validate arguments
	if (v == NULL || w == NULL)
	{
		return;
	}

	Add(v->ArpWaitTable, w);
}

// Initialize the ARP waiting table
void InitArpWaitTable(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	v->ArpWaitTable = NewList(CompareArpWaitTable);
}

// Release the ARP waiting table
void FreeArpWaitTable(VH *v)
{
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(v->ArpWaitTable); i++)
	{
		ARP_WAIT *w = LIST_DATA(v->ArpWaitTable, i);

		Free(w);
	}

	ReleaseList(v->ArpWaitTable);
}

// Insert an entry in the ARP table
void InsertArpTable(VH *v, UCHAR *mac, UINT ip)
{
	ARP_ENTRY *e, t;
	// Validate arguments
	if (v == NULL || mac == NULL || ip == 0 || ip == 0xffffffff || IsMacBroadcast(mac) || IsMacInvalid(mac))
	{
		return;
	}

	// Check whether the same IP address is not already registered
	t.IpAddress = ip;
	e = Search(v->ArpTable, &t);
	if (e != NULL)
	{
		// Override this simply because it was registered
		if (Cmp(e->MacAddress, mac, 6) != 0)
		{
			e->Created = v->Now;
			Copy(e->MacAddress, mac, 6);
		}
		e->Expire = v->Now + (UINT64)ARP_ENTRY_EXPIRES;
	}
	else
	{
		// Create a new entry
		e = ZeroMalloc(sizeof(ARP_ENTRY));

		e->Created = v->Now;
		e->Expire = v->Now + (UINT64)ARP_ENTRY_EXPIRES;
		Copy(e->MacAddress, mac, 6);
		e->IpAddress = ip;

		Add(v->ArpTable, e);
	}
}

// Poll the ARP table
void PollingArpTable(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	if (v->Now > v->NextArpTablePolling)
	{
		v->NextArpTablePolling = v->Now + (UINT64)ARP_ENTRY_POLLING_TIME;
		RefreshArpTable(v);
	}
}

// Remove the old ARP entries
void RefreshArpTable(VH *v)
{
	UINT i;
	LIST *o;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	o = NewListFast(NULL);
	for (i = 0; i < LIST_NUM(v->ArpTable); i++)
	{
		ARP_ENTRY *e = LIST_DATA(v->ArpTable, i);

		// Check for expired
		if (e->Expire < v->Now)
		{
			// Expired
			Add(o, e);
		}
	}

	// Remove expired entries at once
	for (i = 0; i < LIST_NUM(o); i++)
	{
		ARP_ENTRY *e = LIST_DATA(o, i);

		Delete(v->ArpTable, e);
		Free(e);
	}

	ReleaseList(o);
}

// Search the ARP table
ARP_ENTRY *SearchArpTable(VH *v, UINT ip)
{
	ARP_ENTRY *e, t;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	t.IpAddress = ip;
	e = Search(v->ArpTable, &t);

	return e;
}

// Initialize the ARP table
void InitArpTable(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	v->ArpTable = NewList(CompareArpTable);
}

// Release the ARP table
void FreeArpTable(VH *v)
{
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Delete all entries
	for (i = 0; i < LIST_NUM(v->ArpTable); i++)
	{
		ARP_ENTRY *e = LIST_DATA(v->ArpTable, i);
		Free(e);
	}
	ReleaseList(v->ArpTable);
}

// Comparison of the ARP waiting table entry
int CompareArpWaitTable(void *p1, void *p2)
{
	ARP_WAIT *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(ARP_WAIT **)p1;
	e2 = *(ARP_WAIT **)p2;
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
	return 0;
}

// Comparison of the ARP table entry
int CompareArpTable(void *p1, void *p2)
{
	ARP_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(ARP_ENTRY **)p1;
	e2 = *(ARP_ENTRY **)p2;
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
	return 0;
}

// Initialize the virtual host
bool VirtualInit(VH *v)
{
	// Initialize the log
	v->Logger = NULL;

	LockVirtual(v);
	{
		// Initialize
		v->Cancel = NewCancel();
		v->SendQueue = NewQueue();
	}
	UnlockVirtual(v);

	// Counter reset
	v->Counter->c = 0;
	v->DhcpId = 0;

	// Initialize the ARP table
	InitArpTable(v);

	// Initialize the ARP waiting table
	InitArpWaitTable(v);

	// Initialize the IP waiting table
	InitIpWaitTable(v);

	// Initialize the IP combining list
	InitIpCombineList(v);

	// Initialize the NAT
	InitNat(v);

	// Initialize the DHCP server
	InitDhcpServer(v);

	// Other initialization
	v->flag1 = false;
	v->NextArpTablePolling = Tick64() + (UINT64)ARP_ENTRY_POLLING_TIME;
	v->CurrentIpQuota = 0;
	v->Active = true;

	return true;
}
bool VirtualPaInit(SESSION *s)
{
	VH *v;
	// Validate arguments
	if (s == NULL || (v = (VH *)s->PacketAdapter->Param) == NULL)
	{
		return false;
	}

	return VirtualInit(v);
}

// Get the cancel object of the virtual host
CANCEL *VirtualPaGetCancel(SESSION *s)
{
	VH *v;
	// Validate arguments
	if (s == NULL || (v = (VH *)s->PacketAdapter->Param) == NULL)
	{
		return NULL;
	}

	AddRef(v->Cancel->ref);
	return v->Cancel;
}

// Get the next packet from the virtual host
UINT VirtualGetNextPacket(VH *v, void **data)
{
	UINT ret = 0;

START:
	// Examine the transmission queue
	LockQueue(v->SendQueue);
	{
		BLOCK *block = GetNext(v->SendQueue);

		if (block != NULL)
		{
			// There is a packet
			ret = block->Size;
			*data = block->Buf;
			// Discard the structure
			Free(block);
		}
	}
	UnlockQueue(v->SendQueue);

	if (ret == 0)
	{
		LockVirtual(v);
		{
			v->Now = Tick64();
			// Polling process
			VirtualPolling(v);
		}
		UnlockVirtual(v);
		if (v->SendQueue->num_item != 0)
		{
			goto START;
		}
	}

	return ret;
}
UINT VirtualPaGetNextPacket(SESSION *s, void **data)
{
	VH *v;
	// Validate arguments
	if (s == NULL || (v = (VH *)s->PacketAdapter->Param) == NULL)
	{
		return INFINITE;
	}

	return VirtualGetNextPacket(v, data);
}

// Polling process (Always called once in a SessionMain loop)
void VirtualPolling(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// DHCP polling
	PollingDhcpServer(v);

	// NAT polling
	PoolingNat(v);

	// Clear the old ARP table entries
	PollingArpTable(v);

	// Poll the ARP waiting list
	PollingArpWaitTable(v);

	// Poll the IP waiting list
	PollingIpWaitTable(v);

	// Poll the IP combining list
	PollingIpCombine(v);

	// Beacon transmission procedure
	PollingBeacon(v);
}

// Beacon transmission procedure
void PollingBeacon(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	if (v->LastSendBeacon == 0 ||
	        ((v->LastSendBeacon + BEACON_SEND_INTERVAL) <= Tick64()))
	{
		v->LastSendBeacon = Tick64();

		SendBeacon(v);
	}
}

// Send a Layer-2 packet
void VirtualLayer2Send(VH *v, UCHAR *dest_mac, UCHAR *src_mac, USHORT protocol, void *data, UINT size)
{
	MAC_HEADER *mac_header;
	UCHAR *buf;
	BLOCK *block;
	// Validate arguments
	if (v == NULL || dest_mac == NULL || src_mac == NULL || data == NULL || size > (MAX_PACKET_SIZE - sizeof(MAC_HEADER)))
	{
		return;
	}

	// Create buffer
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

	// Generate the packet
	block = NewBlock(buf, size, 0);

	// Insert into the queue
	LockQueue(v->SendQueue);
	{
		InsertQueue(v->SendQueue, block);
	}
	UnlockQueue(v->SendQueue);

	// Cancel
	Cancel(v->Cancel);
}

// Send an IP packet (with automatic fragmentation)
void SendIp(VH *v, UINT dest_ip, UINT src_ip, UCHAR protocol, void *data, UINT size)
{
	SendIpEx(v, dest_ip, src_ip, protocol, data, size, 0);
}
void SendIpEx(VH *v, UINT dest_ip, UINT src_ip, UCHAR protocol, void *data, UINT size, UCHAR ttl)
{
	UINT mss;
	UCHAR *buf;
	USHORT offset;
	USHORT id;
	USHORT total_size;
	UINT size_of_this_packet;
	// Validate arguments
	if (v == NULL || data == NULL || size == 0 || size > MAX_IP_DATA_SIZE_TOTAL)
	{
		return;
	}

	// Maximum segment size
	mss = v->IpMss;

	// Buffer
	buf = (UCHAR *)data;

	// ID
	id = (v->NextId++);

	// Total size
	total_size = (USHORT)size;

	// Start to split
	offset = 0;

	while (true)
	{
		bool last_packet = false;
		// Gets the size of this packet
		size_of_this_packet = MIN((USHORT)mss, (total_size - offset));
		if ((offset + (USHORT)size_of_this_packet) == total_size)
		{
			last_packet = true;
		}

		// Transmit the fragmented packet
		SendFragmentedIp(v, dest_ip, src_ip, id,
		                 total_size, offset, protocol, buf + offset, size_of_this_packet, NULL, ttl);
		if (last_packet)
		{
			break;
		}

		offset += (USHORT)size_of_this_packet;
	}
}

// Reserve to send the fragmented IP packet
void SendFragmentedIp(VH *v, UINT dest_ip, UINT src_ip, USHORT id, USHORT total_size, USHORT offset, UCHAR protocol, void *data, UINT size, UCHAR *dest_mac, UCHAR ttl)
{
	UCHAR *buf;
	IPV4_HEADER *ip;
	ARP_ENTRY *arp;
	// Validate arguments
	if (v == NULL || data == NULL || size == 0)
	{
		return;
	}

	// Memory allocation
	buf = Malloc(size + IP_HEADER_SIZE);
	ip = (IPV4_HEADER *)&buf[0];

	// IP header construction
	ip->VersionAndHeaderLength = 0;
	IPV4_SET_VERSION(ip, 4);
	IPV4_SET_HEADER_LEN(ip, (IP_HEADER_SIZE / 4));
	ip->TypeOfService = DEFAULT_IP_TOS;
	ip->TotalLength = Endian16((USHORT)(size + IP_HEADER_SIZE));
	ip->Identification = Endian16(id);
	ip->FlagsAndFragmentOffset[0] = ip->FlagsAndFragmentOffset[1] = 0;
	IPV4_SET_OFFSET(ip, (offset / 8));
	if ((offset + size) >= total_size)
	{
		IPV4_SET_FLAGS(ip, 0x00);
	}
	else
	{
		IPV4_SET_FLAGS(ip, 0x01);
	}
	ip->TimeToLive = (ttl == 0 ? DEFAULT_IP_TTL : ttl);
	ip->Protocol = protocol;
	ip->Checksum = 0;
	ip->SrcIP = src_ip;
	ip->DstIP = dest_ip;

	// Checksum calculation
	ip->Checksum = IpChecksum(ip, IP_HEADER_SIZE);

	// Data copy
	Copy(buf + IP_HEADER_SIZE, data, size);

	if (dest_mac == NULL)
	{
		if (ip->DstIP == 0xffffffff ||
		        (IsInNetwork(ip->DstIP, v->HostIP, v->HostMask) && (ip->DstIP & (~v->HostMask)) == (~v->HostMask)))
		{
			// Broadcast address
			dest_mac = broadcast;
		}
		else
		{
			// Send an ARP query if the destination MAC address is unknown
			arp = SearchArpTable(v, dest_ip);
			if (arp != NULL)
			{
				dest_mac = arp->MacAddress;
			}
		}
	}
	if (dest_mac != NULL)
	{
		// Send the packet immediately
		VirtualIpSend(v, dest_mac, buf, size + IP_HEADER_SIZE);

		// Packet data may be released
		Free(buf);
	}
	else
	{
		// Because this packet still can not be transferred, add it to the IP waiting table
		InsertIpWaitTable(v, dest_ip, src_ip, buf, size + IP_HEADER_SIZE);

		// Issue an ARP
		SendArp(v, dest_ip);
	}
}

// Send an IP packet (fragmented)
void VirtualIpSend(VH *v, UCHAR *dest_mac, void *data, UINT size)
{
	// Validate arguments
	if (v == NULL || dest_mac == NULL || data == NULL || size == 0)
	{
		return;
	}

	// Transmission
	VirtualLayer2Send(v, dest_mac, v->MacAddress, MAC_PROTO_IPV4, data, size);
}

// Send an ARP request packet
void VirtualArpSendRequest(VH *v, UINT dest_ip)
{
	ARPV4_HEADER arp;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Build the ARP header
	arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
	arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
	arp.HardwareSize = 6;
	arp.ProtocolSize = 4;
	arp.Operation = Endian16(ARP_OPERATION_REQUEST);
	Copy(arp.SrcAddress, v->MacAddress, 6);
	arp.SrcIP = v->HostIP;
	Zero(&arp.TargetAddress, 6);
	arp.TargetIP = dest_ip;

	// Transmission
	VirtualLayer2Send(v, broadcast, v->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(arp));
}

// Send an ARP response packet
void VirtualArpSendResponse(VH *v, UCHAR *dest_mac, UINT dest_ip, UINT src_ip)
{
	ARPV4_HEADER arp;
	// Validate arguments
	if (v == NULL || dest_mac == NULL)
	{
		return;
	}

	// Build the ARP header
	arp.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
	arp.ProtocolType = Endian16(MAC_PROTO_IPV4);
	arp.HardwareSize = 6;
	arp.ProtocolSize = 4;
	arp.Operation = Endian16(ARP_OPERATION_RESPONSE);
	Copy(arp.SrcAddress, v->MacAddress, 6);
	Copy(arp.TargetAddress, dest_mac, 6);
	arp.SrcIP = src_ip;
	arp.TargetIP = dest_ip;

	// Transmission
	VirtualLayer2Send(v, dest_mac, v->MacAddress, MAC_PROTO_ARPV4, &arp, sizeof(ARPV4_HEADER));
}

// An ARP request packet was received
void VirtualArpResponseRequest(VH *v, PKT *packet)
{
	ARPV4_HEADER *arp;
	// Validate arguments
	if (v == NULL || packet == NULL)
	{
		return;
	}

	arp = packet->L3.ARPv4Header;

	// Memory the information of the host IP address and the MAC address of the other party
	ArpIpWasKnown(v, arp->SrcIP, arp->SrcAddress);

	// Search whether it matches with the IP address of this host
	if (v->HostIP == arp->TargetIP)
	{
		// Respond since the match
		VirtualArpSendResponse(v, arp->SrcAddress, arp->SrcIP, v->HostIP);
		return;
	}
	// Do nothing if it doesn't match
}

// An ARP response packet is received
void VirtualArpResponseReceived(VH *v, PKT *packet)
{
	ARPV4_HEADER *arp;
	// Validate arguments
	if (v == NULL || packet == NULL)
	{
		return;
	}

	arp = packet->L3.ARPv4Header;

	// Regard this information as known information
	ArpIpWasKnown(v, arp->SrcIP, arp->SrcAddress);
}

// Received an ARP packet
void VirtualArpReceived(VH *v, PKT *packet)
{
	ARPV4_HEADER *arp;
	// Validate arguments
	if (v == NULL || packet == NULL)
	{
		return;
	}

	arp = packet->L3.ARPv4Header;

	if (Endian16(arp->HardwareType) != ARP_HARDWARE_TYPE_ETHERNET)
	{
		// Ignore if hardware type is other than Ethernet
		return;
	}
	if (Endian16(arp->ProtocolType) != MAC_PROTO_IPV4)
	{
		// Ignore if the protocol type is a non-IPv4
		return;
	}
	if (arp->HardwareSize != 6 || arp->ProtocolSize != 4)
	{
		// Ignore because the size of protocol address or hardware address is invalid
		return;
	}
	// Check the source MAC address
	if (Cmp(arp->SrcAddress, packet->MacAddressSrc, 6) != 0)
	{
		// MAC address in the MAC header and the MAC address of the ARP packet are different
		return;
	}

	switch (Endian16(arp->Operation))
	{
	case ARP_OPERATION_REQUEST:		// ARP request
		VirtualArpResponseRequest(v, packet);
		break;

	case ARP_OPERATION_RESPONSE:	// ARP response
		VirtualArpResponseReceived(v, packet);
		break;
	}
}

// Release the DHCP server
void FreeDhcpServer(VH *v)
{
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Empty the leases lists
	for (i = 0; i < LIST_NUM(v->DhcpLeaseList); ++i)
	{
		DHCP_LEASE *d = LIST_DATA(v->DhcpLeaseList, i);
		FreeDhcpLease(d);
	}

	ReleaseList(v->DhcpLeaseList);
	v->DhcpLeaseList = NULL;

	for (i = 0; i < LIST_NUM(v->DhcpPendingLeaseList); ++i)
	{
		DHCP_LEASE *d = LIST_DATA(v->DhcpPendingLeaseList, i);
		FreeDhcpLease(d);
	}

	ReleaseList(v->DhcpPendingLeaseList);
	v->DhcpPendingLeaseList = NULL;
}

// Initialize the DHCP server
void InitDhcpServer(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Create a list
	v->DhcpLeaseList = NewList(CompareDhcpLeaseList);
	v->DhcpPendingLeaseList = NewList(CompareDhcpLeaseList);
}

// Search for a pending DHCP lease item by the IP address
DHCP_LEASE *SearchDhcpPendingLeaseByIp(VH *v, UINT ip)
{
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(v->DhcpPendingLeaseList); ++i)
	{
		DHCP_LEASE *d = LIST_DATA(v->DhcpPendingLeaseList, i);
		if (d->IpAddress == ip)
		{
			return d;
		}
	}

	return NULL;
}

// Search for a DHCP lease item by the IP address
DHCP_LEASE *SearchDhcpLeaseByIp(VH *v, UINT ip)
{
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(v->DhcpLeaseList); ++i)
	{
		DHCP_LEASE *d = LIST_DATA(v->DhcpLeaseList, i);
		if (d->IpAddress == ip)
		{
			return d;
		}
	}

	return NULL;
}

// Search for a pending DHCP lease item by the MAC address
DHCP_LEASE *SearchDhcpPendingLeaseByMac(VH *v, UCHAR *mac)
{
	DHCP_LEASE *d, t;
	// Validate arguments
	if (v == NULL || mac == NULL)
	{
		return NULL;
	}

	Copy(&t.MacAddress, mac, 6);
	d = Search(v->DhcpPendingLeaseList, &t);

	return d;
}

// Search for a DHCP lease item by the MAC address
DHCP_LEASE *SearchDhcpLeaseByMac(VH *v, UCHAR *mac)
{
	DHCP_LEASE *d, t;
	// Validate arguments
	if (v == NULL || mac == NULL)
	{
		return NULL;
	}

	Copy(&t.MacAddress, mac, 6);
	d = Search(v->DhcpLeaseList, &t);

	return d;
}

// Release the DHCP lease item
void FreeDhcpLease(DHCP_LEASE *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	Free(d->Hostname);
	Free(d);
}

// Create a DHCP lease item
DHCP_LEASE *NewDhcpLease(UINT expire, UCHAR *mac_address, UINT ip, UINT mask, char *hostname)
{
	DHCP_LEASE *d;
	// Validate arguments
	if (mac_address == NULL || hostname == NULL)
	{
		return NULL;
	}

	d = ZeroMalloc(sizeof(DHCP_LEASE));
	d->LeasedTime = (UINT64)Tick64();
	if (expire == INFINITE)
	{
		d->ExpireTime = INFINITE;
	}
	else
	{
		d->ExpireTime = d->LeasedTime + (UINT64)expire;
	}
	d->IpAddress = ip;
	d->Mask = mask;
	d->Hostname = CopyStr(hostname);
	Copy(d->MacAddress, mac_address, 6);


	return d;
}

// Comparison of the items in the DHCP list
int CompareDhcpLeaseList(void *p1, void *p2)
{
	DHCP_LEASE *d1, *d2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	d1 = *(DHCP_LEASE **)p1;
	d2 = *(DHCP_LEASE **)p2;
	if (d1 == NULL || d2 == NULL)
	{
		return 0;
	}

	return Cmp(d1->MacAddress, d2->MacAddress, 6);
}

// Poll the DHCP server
void PollingDhcpServer(VH *v)
{
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	if (v->LastDhcpPolling != 0)
	{
		if ((v->LastDhcpPolling + (UINT64)DHCP_POLLING_INTERVAL) > v->Now &&
		        v->LastDhcpPolling < v->Now)
		{
			return;
		}
	}
	v->LastDhcpPolling = v->Now;

LIST_CLEANUP:
	for (i = 0; i < LIST_NUM(v->DhcpLeaseList); ++i)
	{
		DHCP_LEASE *d = LIST_DATA(v->DhcpLeaseList, i);

		if (d->ExpireTime < v->Now)
		{
			FreeDhcpLease(d);
			Delete(v->DhcpLeaseList, d);
			goto LIST_CLEANUP;
		}
	}

PENDING_LIST_CLEANUP:
	// Remove expired entries
	for (i = 0; i < LIST_NUM(v->DhcpPendingLeaseList); ++i)
	{
		DHCP_LEASE *d = LIST_DATA(v->DhcpPendingLeaseList, i);

		if (d->ExpireTime < v->Now)
		{
			FreeDhcpLease(d);
			Delete(v->DhcpPendingLeaseList, d);
			goto PENDING_LIST_CLEANUP;
		}
	}
}

// Correspond to the DHCP REQUEST
UINT ServeDhcpRequest(VH *v, UCHAR *mac, UINT request_ip)
{
	return ServeDhcpRequestEx(v, mac, request_ip, false);
}

UINT ServeDhcpRequestEx(VH *v, UCHAR *mac, UINT request_ip, bool is_static_ip)
{
	UINT ret;
	// Validate arguments
	if (v == NULL || mac == NULL)
	{
		return 0;
	}

	ret = ServeDhcpDiscoverEx(v, mac, request_ip, is_static_ip);
	if (ret != request_ip)
	{
		if (request_ip != 0)
		{
			// Raise an error if the requested IP address cannot to be assigned
			return 0;
		}
	}

	return ret;
}

// Correspond to the DHCP DISCOVER
UINT ServeDhcpDiscover(VH *v, UCHAR *mac, UINT request_ip)
{
	UINT ret = 0;
	// Validate arguments
	if (v == NULL || mac == NULL)
	{
		return 0;
	}

	if (request_ip != 0)
	{
		// IP address is specified
		DHCP_LEASE *d = SearchDhcpLeaseByIp(v, request_ip);
		if (d == NULL)
		{
			d = SearchDhcpPendingLeaseByIp(v, request_ip);
		}

		if (d != NULL)
		{
			// If an entry for the same IP address already exists,
			// check whether it is a request from the same MAC address
			if (Cmp(mac, d->MacAddress, 6) == 0)
			{
				// Examine whether the specified IP address is within the range of assignment
				if (Endian32(v->DhcpIpStart) <= Endian32(request_ip) &&
				        Endian32(request_ip) <= Endian32(v->DhcpIpEnd))
				{
					// Accept if within the range
					ret = request_ip;
				}
			}
		}
		else
		{
			// Examine whether the specified IP address is within the range of assignment
			if (Endian32(v->DhcpIpStart) <= Endian32(request_ip) &&
			        Endian32(request_ip) <= Endian32(v->DhcpIpEnd))
			{
				// Accept if within the range
				ret = request_ip;
			}
			else
			{
				// Propose an IP in the range since it's a Discover although It is out of range
			}
		}
	}

	if (ret == 0)
	{
		// If there is any entry with the same MAC address
		// that are already registered, use it with priority
		DHCP_LEASE *d = SearchDhcpLeaseByMac(v, mac);
		if (d == NULL)
		{
			d = SearchDhcpPendingLeaseByMac(v, mac);
		}

		if (d != NULL)
		{
			// Examine whether the found IP address is in the allocation region
			if (Endian32(v->DhcpIpStart) <= Endian32(d->IpAddress) &&
			        Endian32(d->IpAddress) <= Endian32(v->DhcpIpEnd))
			{
				// Use the IP address if it's found within the range
				ret = d->IpAddress;
			}
		}
	}

	if (ret == 0)
	{
		// Take an appropriate IP addresses that can be assigned newly
		HUB_OPTION *opt = NatGetHubOption(v);

		if (opt != NULL && opt->SecureNAT_RandomizeAssignIp)
		{
			ret = GetFreeDhcpIpAddressByRandom(v, mac);
		}
		else
		{
			ret = GetFreeDhcpIpAddress(v);
		}
	}

	return ret;
}

UINT ServeDhcpDiscoverEx(VH *v, UCHAR *mac, UINT request_ip, bool is_static_ip)
{
	if (is_static_ip == false)
	{
		return ServeDhcpDiscover(v, mac, request_ip );
	}

	if (v == NULL || mac == NULL || request_ip == 0)
	{
		return 0;
	}

	DHCP_LEASE *d = SearchDhcpLeaseByIp(v, request_ip);
	if (d != NULL)
	{
		// The requested IP address is used already
		return 0;
	}

	// For static IP, the requested IP address must NOT be within the range of the DHCP pool
	if (Endian32(request_ip) < Endian32(v->DhcpIpStart) || Endian32(request_ip) > Endian32(v->DhcpIpEnd))
	{
		return request_ip;
	}

	return 0;
}

// Take an appropriate IP addresses that can be assigned newly
UINT GetFreeDhcpIpAddress(VH *v)
{
	UINT ip_start, ip_end;
	UINT i;
	// Validate arguments
	if (v == NULL)
	{
		return 0;
	}

	ip_start = Endian32(v->DhcpIpStart);
	ip_end = Endian32(v->DhcpIpEnd);

	for (i = ip_start; i <= ip_end; i++)
	{
		UINT ip = Endian32(i);
		if (SearchDhcpLeaseByIp(v, ip) == NULL && SearchDhcpPendingLeaseByIp(v, ip) == NULL)
		{
			// A free IP address is found
			return ip;
		}
	}

	// There is no free address
	return 0;
}

// Take an appropriate IP addresses that can be assigned newly (random)
UINT GetFreeDhcpIpAddressByRandom(VH *v, UCHAR *mac)
{
	UINT ip_start, ip_end;
	UINT i;
	UINT num_retry;
	// Validate arguments
	if (v == NULL || mac == NULL)
	{
		return 0;
	}

	ip_start = Endian32(v->DhcpIpStart);
	ip_end = Endian32(v->DhcpIpEnd);

	if (ip_start > ip_end)
	{
		return 0;
	}

	num_retry = (ip_end - ip_start + 1) * 2;
	num_retry = MIN(num_retry, 65536 * 2);

	for (i = 0; i < num_retry; i++)
	{
		UCHAR rand_seed[sizeof(UINT) + 6];
		UCHAR hash[16];
		UINT rand_int;
		UINT new_ip;

		WRITE_UINT(&rand_seed[0], i);
		Copy(rand_seed + sizeof(UINT), mac, 6);

		Md5(hash, rand_seed, sizeof(rand_seed));

		rand_int = READ_UINT(hash);

		new_ip = Endian32(ip_start + (rand_int % (ip_end - ip_start + 1)));

		if (SearchDhcpLeaseByIp(v, new_ip) == NULL && SearchDhcpPendingLeaseByIp(v, new_ip) == NULL)
		{
			// A free IP address is found
			return new_ip;
		}
	}

	// There is no free address
	return 0;
}

// Virtual DHCP Server
void VirtualDhcpServer(VH *v, PKT *p)
{
	DHCPV4_HEADER *dhcp;
	UCHAR *data;
	UINT size;
	UINT dhcp_header_size;
	UINT dhcp_data_offset;
	UINT tran_id;
	UINT magic_cookie = Endian32(DHCP_MAGIC_COOKIE);
	bool ok;
	DHCP_OPTION_LIST *opt;
	// Validate arguments
	if (v == NULL || p == NULL)
	{
		return;
	}

	if (v->NativeNat != NULL)
	{
		if (Cmp(p->MacAddressSrc, v->NativeNat->CurrentMacAddress, 6) == 0)
		{
			// DHCP server is kept from responding for the native NAT interface
			// ** Not be needed to return yet **
			//return;
		}
	}

	dhcp = p->L7.DHCPv4Header;

	tran_id = Endian32(dhcp->TransactionId);

	// Get the DHCP data and size
	dhcp_header_size = sizeof(DHCPV4_HEADER);
	dhcp_data_offset = (UINT)(((UCHAR *)p->L7.DHCPv4Header) - ((UCHAR *)p->MacHeader) + dhcp_header_size);
	data = ((UCHAR *)dhcp) + dhcp_header_size;
	size = p->PacketSize - dhcp_data_offset;
	if (dhcp_header_size < 5)
	{
		// Data size is invalid
		return;
	}

	// Search for Magic Cookie
	ok = false;
	while (size >= 5)
	{
		if (Cmp(data, &magic_cookie, sizeof(magic_cookie)) == 0)
		{
			// Found
			data += 4;
			size -= 4;
			ok = true;
			break;
		}
		data++;
		size--;
	}

	if (ok == false)
	{
		// The packet is invalid
		return;
	}

	// Parse DHCP options list
	opt = ParseDhcpOptionList(data, size);
	if (opt == NULL)
	{
		// The packet is invalid
		return;
	}

	if (StartWith(opt->Hostname, NN_HOSTNAME_STARTWITH) || StartWith(opt->Hostname, NN_HOSTNAME_STARTWITH2))
	{
		Free(opt);
		return;
	}

	if (dhcp->OpCode == 1 && (opt->Opcode == DHCP_DISCOVER || opt->Opcode == DHCP_REQUEST || opt->Opcode == DHCP_INFORM))
	{
		// Operate as the server
		UINT ip = 0, ip_static = dhcp->ServerIP;
		dhcp->ServerIP = 0;

		if (opt->RequestedIp == 0)
		{
			opt->RequestedIp = (ip_static ? ip_static : p->L3.IPv4Header->SrcIP);
		}
		if (opt->Opcode == DHCP_DISCOVER)
		{
			// Return an IP address that can be used
			ip = ServeDhcpDiscoverEx(v, p->MacAddressSrc, opt->RequestedIp, ip_static);
		}
		else if (opt->Opcode == DHCP_REQUEST)
		{
			// Determine the IP address
			if (ip_static && opt->RequestedIp != ip_static)
			{
				// Don't allow opt->RequestedIp other than the IP written in user's note
				ip = 0;
			}
			else
			{
				ip = ServeDhcpRequestEx(v, p->MacAddressSrc, opt->RequestedIp, ip_static);
			}
		}

		if (ip != 0 || opt->Opcode == DHCP_INFORM)
		{
			// Respond if there is providable IP address

			if (opt->Opcode == DHCP_REQUEST)
			{
				DHCP_LEASE *d;
				char client_mac[MAX_SIZE];
				char client_ip[MAX_SIZE];

				// Remove old records with the same IP address
				d = SearchDhcpLeaseByIp(v, ip);
				if (d != NULL)
				{
					FreeDhcpLease(d);
					Delete(v->DhcpLeaseList, d);
				}

				d = SearchDhcpPendingLeaseByIp(v, ip);
				if (d != NULL)
				{
					FreeDhcpLease(d);
					Delete(v->DhcpPendingLeaseList, d);
				}

				// Create a new entry
				d = NewDhcpLease(v->DhcpExpire, p->MacAddressSrc, ip, v->DhcpMask, opt->Hostname);
				d->Id = ++v->DhcpId;
				Add(v->DhcpLeaseList, d);

				MacToStr(client_mac, sizeof(client_mac), d->MacAddress);
				IPToStr32(client_ip, sizeof(client_ip), d->IpAddress);

				NLog(v, "LH_NAT_DHCP_CREATED", d->Id, client_mac, client_ip, d->Hostname, v->DhcpExpire / 1000);
			}

			// Respond
			if (true)
			{
				DHCP_OPTION_LIST ret;
				LIST *o;
				Zero(&ret, sizeof(ret));

				ret.Opcode = (opt->Opcode == DHCP_DISCOVER ? DHCP_OFFER : DHCP_ACK);
				ret.ServerAddress = v->HostIP;
				if (v->DhcpExpire == INFINITE)
				{
					ret.LeaseTime = INFINITE;
				}
				else
				{
					ret.LeaseTime = Endian32(v->DhcpExpire / 1000);
				}

				if (opt->Opcode == DHCP_INFORM)
				{
					ret.LeaseTime = 0;
				}

				StrCpy(ret.DomainName, sizeof(ret.DomainName), v->DhcpDomain);
				ret.SubnetMask = v->DhcpMask;
				ret.DnsServer = v->DhcpDns;
				ret.DnsServer2 = v->DhcpDns2;
				ret.Gateway = v->DhcpGateway;

				if (GetGlobalServerFlag(GSF_DISABLE_PUSH_ROUTE) == 0)
				{
					Copy(&ret.ClasslessRoute, &v->PushRoute, sizeof(DHCP_CLASSLESS_ROUTE_TABLE));

					if (IsIpcMacAddress(p->MacAddressSrc))
					{
						if (ret.Gateway == 0)
						{
							// If the default gateway is not specified, add the static routing table
							// entry for the local IP subnet
							// (for PPP clients)
							IP dhcp_ip;
							IP dhcp_mask;
							IP dhcp_network;

							UINTToIP(&dhcp_ip, ip);

							if (ip == 0)
							{
								UINTToIP(&dhcp_ip, p->L3.IPv4Header->SrcIP);
							}

							UINTToIP(&dhcp_mask, v->DhcpMask);

							IPAnd4(&dhcp_network, &dhcp_ip, &dhcp_mask);

							if (GetBestClasslessRoute(&ret.ClasslessRoute, &dhcp_ip) == NULL)
							{
								if (ret.ClasslessRoute.NumExistingRoutes < MAX_DHCP_CLASSLESS_ROUTE_ENTRIES)
								{
									DHCP_CLASSLESS_ROUTE *cr = &ret.ClasslessRoute.Entries[ret.ClasslessRoute.NumExistingRoutes];

									cr->Exists = true;

									UINTToIP(&cr->Gateway, v->HostIP);

									if (v->UseNat == false && ret.ClasslessRoute.NumExistingRoutes >= 1)
									{
										Copy(&cr->Gateway, &ret.ClasslessRoute.Entries[0].Gateway, sizeof(IP));
									}

									Copy(&cr->Network, &dhcp_network, sizeof(IP));
									Copy(&cr->SubnetMask, &dhcp_mask, sizeof(IP));
									cr->SubnetMaskLen = SubnetMaskToInt(&dhcp_mask);

									ret.ClasslessRoute.NumExistingRoutes++;
								}
							}
						}
					}
				}

				if (opt->Opcode != DHCP_INFORM)
				{
					char client_mac[MAX_SIZE];
					char client_ip[64];
					IP ips;

					BinToStr(client_mac, sizeof(client_mac), p->MacAddressSrc, 6);
					UINTToIP(&ips, ip);
					IPToStr(client_ip, sizeof(client_ip), &ips);

					if (ret.Opcode == DHCP_OFFER)
					{
						// DHCP_OFFER
						DHCP_LEASE *d = NewDhcpLease(5000, p->MacAddressSrc, ip, v->DhcpMask, opt->Hostname);
						d->Id = LIST_NUM(v->DhcpPendingLeaseList);
						Add(v->DhcpPendingLeaseList, d);

						Debug("VirtualDhcpServer(): %s has been marked as pending for %s\n", client_ip, client_mac);
					}
					else
					{
						// DHCP_ACK
						Debug("VirtualDhcpServer(): %s has been assigned to %s\n", client_ip, client_mac);
					}
				}

				// Build a DHCP option
				o = BuildDhcpOption(&ret);
				if (o != NULL)
				{
					BUF *b = BuildDhcpOptionsBuf(o);
					if (b != NULL)
					{
						UINT dest_ip = p->L3.IPv4Header->SrcIP;
						if (dest_ip == 0)
						{
							dest_ip = 0xffffffff;
						}
						// Transmission
						VirtualDhcpSend(v, tran_id, dest_ip, Endian16(p->L4.UDPHeader->SrcPort),
						                ip, dhcp->ClientMacAddress, b, dhcp->HardwareType, dhcp->HardwareAddressSize);

						// Release the memory
						FreeBuf(b);
					}
					FreeDhcpOptions(o);
				}
			}
		}
		else
		{
			// There is no IP address that can be provided
			DHCP_OPTION_LIST ret;
			LIST *o;
			Zero(&ret, sizeof(ret));

			ret.Opcode = DHCP_NACK;
			ret.ServerAddress = v->HostIP;
			StrCpy(ret.DomainName, sizeof(ret.DomainName), v->DhcpDomain);
			ret.SubnetMask = v->DhcpMask;

			// Build the DHCP option
			o = BuildDhcpOption(&ret);
			if (o != NULL)
			{
				BUF *b = BuildDhcpOptionsBuf(o);
				if (b != NULL)
				{
					UINT dest_ip = p->L3.IPv4Header->SrcIP;
					if (dest_ip == 0)
					{
						dest_ip = 0xffffffff;
					}
					// Transmission
					VirtualDhcpSend(v, tran_id, dest_ip, Endian16(p->L4.UDPHeader->SrcPort),
					                ip, dhcp->ClientMacAddress, b, dhcp->HardwareType, dhcp->HardwareAddressSize);

					// Release the memory
					FreeBuf(b);
				}
				FreeDhcpOptions(o);
			}
		}
	}

	// Release the memory
	Free(opt);
}

// Submit the DHCP response packet
void VirtualDhcpSend(VH *v, UINT tran_id, UINT dest_ip, UINT dest_port,
                     UINT new_ip, UCHAR *client_mac, BUF *b, UINT hw_type, UINT hw_addr_size)
{
	UINT blank_size = 128 + 64;
	UINT dhcp_packet_size;
	UINT magic = Endian32(DHCP_MAGIC_COOKIE);
	DHCPV4_HEADER *dhcp;
	void *magic_cookie_addr;
	void *buffer_addr;
	// Validate arguments
	if (v == NULL || b == NULL)
	{
		return;
	}

	// Calculate the DHCP packet size
	dhcp_packet_size = blank_size + sizeof(DHCPV4_HEADER) + sizeof(magic) + b->Size;

	if (dhcp_packet_size < DHCP_MIN_SIZE)
	{
		// Padding
		dhcp_packet_size = DHCP_MIN_SIZE;
	}

	// Create a header
	dhcp = ZeroMalloc(dhcp_packet_size);

	dhcp->OpCode = 2;
	dhcp->HardwareType = hw_type;
	dhcp->HardwareAddressSize = hw_addr_size;
	dhcp->Hops = 0;
	dhcp->TransactionId = Endian32(tran_id);
	dhcp->Seconds = 0;
	dhcp->Flags = 0;
	dhcp->YourIP = new_ip;
	dhcp->ServerIP = v->HostIP;
	Copy(dhcp->ClientMacAddress, client_mac, 6);

	// Calculate the address
	magic_cookie_addr = (((UCHAR *)dhcp) + sizeof(DHCPV4_HEADER) + blank_size);
	buffer_addr = ((UCHAR *)magic_cookie_addr) + sizeof(magic);

	// Magic Cookie
	Copy(magic_cookie_addr, &magic, sizeof(magic));

	// Buffer
	Copy(buffer_addr, b->Buf, b->Size);

	// Transmission
	SendUdp(v, dest_ip, dest_port, v->HostIP, NAT_DHCP_SERVER_PORT, dhcp, dhcp_packet_size);

	Free(dhcp);
}

// Virtual host: Process the Layer2
void VirtualLayer2(VH *v, PKT *packet)
{
	bool ok;
	// Validate arguments
	if (packet == NULL || v == NULL)
	{
		return;
	}

	// Packet filter
	if (VirtualLayer2Filter(v, packet) == false)
	{
		// Packet was ignored
		return;
	}

	ok = false;
	if (packet->TypeL3 == L3_IPV4 && packet->TypeL4 == L4_UDP && packet->TypeL7 == L7_DHCPV4)
	{
		if (v->UseDhcp)
		{
			// A special treatment on the DHCP packet
			if (packet->BroadcastPacket || Cmp(packet->MacAddressDest, v->MacAddress, 6) == 0)
			{
				// Virtual DHCP server processing
				VirtualDhcpServer(v, packet);
				ok = true;
			}
		}
	}

	if (ok == false)
	{
		// The process for each supported protocol
		switch (packet->TypeL3)
		{
		case L3_ARPV4:	// ARPv4
			VirtualArpReceived(v, packet);
			break;

		case L3_IPV4:	// IPv4
			VirtualIpReceived(v, packet);
			break;
		}
	}
}

// Packet filter (Blocking packets to other than me)
bool VirtualLayer2Filter(VH *v, PKT *packet)
{
	// Validate arguments
	if (v == NULL || packet == NULL)
	{
		return false;
	}

	// Pass through if broadcast packet
	if (packet->BroadcastPacket)
	{
		return true;
	}

	// Ignore if the sender of the packet is myself
	if (Cmp(packet->MacAddressSrc, v->MacAddress, 6) == 0)
	{
		return false;
	}
	// Pass through in the case of a packet addressed to me
	if (Cmp(packet->MacAddressDest, v->MacAddress, 6) == 0)
	{
		return true;
	}

	// Discard if the other packets
	return false;
}

// The virtual host is made to receive a packet
bool VirtualPutPacket(VH *v, void *data, UINT size)
{
	if (data == NULL)
	{
		// Flush
		v->flag1 = false;

		if (v->NativeNat != NULL)
		{
			if (v->NativeNat->SendStateChanged)
			{
				TUBE *halt_tube = NULL;

				Lock(v->NativeNat->Lock);
				{
					if (v->NativeNat->HaltTube != NULL)
					{
						halt_tube = v->NativeNat->HaltTube;

						AddRef(halt_tube->Ref);
					}
				}
				Unlock(v->NativeNat->Lock);

				if (halt_tube != NULL)
				{
					TubeFlushEx(halt_tube, true);

					v->NativeNat->SendStateChanged = false;

					ReleaseTube(halt_tube);
				}
			}
		}
	}
	else
	{
		// Interpret the received packet
		PKT *packet = ParsePacket(data, size);

		if (v->flag1 == false)
		{
			v->flag1 = true;
			v->Now = Tick64();
		}

		// Lock the entire virtual machine in here
		LockVirtual(v);
		{
			if (packet != NULL)
			{
				// Process the Layer-2
				VirtualLayer2(v, packet);

				// Release the packet structure
				FreePacket(packet);
			}
		}
		UnlockVirtual(v);

		Free(data);
	}

	return true;
}
bool VirtualPaPutPacket(SESSION *s, void *data, UINT size)
{
	VH *v;
	// Validate arguments
	if (s == NULL || (v = (VH *)s->PacketAdapter->Param) == NULL)
	{
		return false;
	}

	return VirtualPutPacket(v, data, size);
}

// Get the options for the virtual host
void GetVirtualHostOption(VH *v, VH_OPTION *o)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	LockVirtual(v);
	{
		Zero(o, sizeof(VH_OPTION));

		// MAC address
		Copy(o->MacAddress, v->MacAddress, 6);

		// Host information
		UINTToIP(&o->Ip, v->HostIP);
		UINTToIP(&o->Mask, v->HostMask);

		o->Mtu = v->Mtu;

		// NAT timeout information
		o->NatTcpTimeout = v->NatTcpTimeout / 1000;
		o->NatUdpTimeout = v->NatUdpTimeout / 1000;

		// NAT using flag
		o->UseNat = v->UseNat;

		// DHCP using flag
		o->UseDhcp = v->UseDhcp;

		// IP address range for DHCP distribution
		UINTToIP(&o->DhcpLeaseIPStart, v->DhcpIpStart);
		UINTToIP(&o->DhcpLeaseIPEnd, v->DhcpIpEnd);

		// Subnet mask
		UINTToIP(&o->DhcpSubnetMask, v->DhcpMask);

		// Expiration date
		if (v->DhcpExpire != INFINITE)
		{
			o->DhcpExpireTimeSpan = v->DhcpExpire / 1000;
		}
		else
		{
			o->DhcpExpireTimeSpan = INFINITE;
		}

		// Gateway address
		UINTToIP(&o->DhcpGatewayAddress, v->DhcpGateway);

		// DNS server address
		UINTToIP(&o->DhcpDnsServerAddress, v->DhcpDns);
		UINTToIP(&o->DhcpDnsServerAddress2, v->DhcpDns2);

		// Domain name
		StrCpy(o->DhcpDomainName, sizeof(o->DhcpDomainName), v->DhcpDomain);

		// Save a log
		o->SaveLog = v->SaveLog;

		// Pushing route option
		BuildClasslessRouteTableStr(o->DhcpPushRoutes, sizeof(o->DhcpPushRoutes), &v->PushRoute);
		o->ApplyDhcpPushRoutes = true;
	}
	UnlockVirtual(v);
}

// Set the option to the virtual host
void SetVirtualHostOption(VH *v, VH_OPTION *vo)
{
	UINT i;
	// Validate arguments
	if (v == NULL || vo == NULL)
	{
		return;
	}

	LockVirtual(v);
	{
		// Set the MAC address
		for (i = 0; i < 6; i++)
		{
			if (vo->MacAddress[i] != 0)
			{
				Copy(v->MacAddress, vo->MacAddress, 6);
				break;
			}
		}

		// Set the host information list
		v->HostIP = IPToUINT(&vo->Ip);
		v->HostMask = IPToUINT(&vo->Mask);

		// Set the MTU, MMS
		v->Mtu = MIN(vo->Mtu, MAX_L3_DATA_SIZE);
		if (v->Mtu == 0)
		{
			v->Mtu = MAX_L3_DATA_SIZE;
		}
		v->Mtu = MAX(v->Mtu, TCP_HEADER_SIZE + IP_HEADER_SIZE + MAC_HEADER_SIZE + 8);
		v->IpMss = ((v->Mtu - IP_HEADER_SIZE) / 8) * 8;
		v->TcpMss = ((v->IpMss - TCP_HEADER_SIZE) / 8) * 8;
		v->UdpMss = ((v->IpMss - UDP_HEADER_SIZE) / 8) * 8;

		if (vo->NatTcpTimeout != 0)
		{
			v->NatTcpTimeout = MIN(vo->NatTcpTimeout, 4000000) * 1000;
		}
		if (vo->NatUdpTimeout != 0)
		{
			v->NatUdpTimeout = MIN(vo->NatUdpTimeout, 4000000) * 1000;
		}
		v->NatTcpTimeout = MAKESURE(v->NatTcpTimeout, NAT_TCP_MIN_TIMEOUT, NAT_TCP_MAX_TIMEOUT);
		v->NatUdpTimeout = MAKESURE(v->NatUdpTimeout, NAT_UDP_MIN_TIMEOUT, NAT_UDP_MAX_TIMEOUT);
		Debug("Timeout: %d , %d\n", v->NatTcpTimeout, v->NatUdpTimeout);

		// NAT using flag
		v->UseNat = vo->UseNat;

		// DHCP using flag
		v->UseDhcp = vo->UseDhcp;

		// Expiration date
		if (vo->DhcpExpireTimeSpan == 0 || vo->DhcpExpireTimeSpan == INFINITE)
		{
			v->DhcpExpire = INFINITE;
		}
		else
		{
			v->DhcpExpire = MAKESURE(DHCP_MIN_EXPIRE_TIMESPAN,
			                         MIN(vo->DhcpExpireTimeSpan * 1000, 2000000000),
			                         INFINITE);
		}

		// Address range to be distributed
		v->DhcpIpStart = IPToUINT(&vo->DhcpLeaseIPStart);
		v->DhcpIpEnd = IPToUINT(&vo->DhcpLeaseIPEnd);
		if (Endian32(v->DhcpIpEnd) < Endian32(v->DhcpIpStart))
		{
			v->DhcpIpEnd = v->DhcpIpStart;
		}

		// Subnet mask
		v->DhcpMask = IPToUINT(&vo->DhcpSubnetMask);

		// Gateway address
		v->DhcpGateway = IPToUINT(&vo->DhcpGatewayAddress);

		// DNS server address
		v->DhcpDns = IPToUINT(&vo->DhcpDnsServerAddress);
		v->DhcpDns2 = IPToUINT(&vo->DhcpDnsServerAddress2);

		// Domain name
		StrCpy(v->DhcpDomain, sizeof(v->DhcpDomain), vo->DhcpDomainName);

		// Save a log
		v->SaveLog = vo->SaveLog;

		// DHCP routing table pushing setting
		if (vo->ApplyDhcpPushRoutes)
		{
			DHCP_CLASSLESS_ROUTE_TABLE rt;

			Zero(&rt, sizeof(rt));

			if (ParseClasslessRouteTableStr(&rt, vo->DhcpPushRoutes))
			{
				Copy(&v->PushRoute, &rt, sizeof(DHCP_CLASSLESS_ROUTE_TABLE));
			}
		}
	}
	UnlockVirtual(v);
}

// Release the virtual host
void Virtual_Free(VH *v)
{
	// Release the DHCP server
	FreeDhcpServer(v);

	// NAT release
	FreeNat(v);

	LockVirtual(v);
	{
		// Release the IP combining list
		FreeIpCombineList(v);

		// Release the IP waiting table
		FreeIpWaitTable(v);

		// Release the ARP waiting table
		FreeArpWaitTable(v);

		// Release the ARP table
		FreeArpTable(v);

		// Release the transmission queue
		LockQueue(v->SendQueue);
		{
			BLOCK *block;

			// Release all queues
			while (block = GetNext(v->SendQueue))
			{
				FreeBlock(block);
			}
		}
		UnlockQueue(v->SendQueue);
		ReleaseQueue(v->SendQueue);
		v->SendQueue = NULL;

		// Release the cancel object
		ReleaseCancel(v->Cancel);

		v->Active = false;
	}
	UnlockVirtual(v);

	// Release the logger
	FreeLog(v->Logger);
}
void VirtualPaFree(SESSION *s)
{
	VH *v;
	// Validate arguments
	if (s == NULL || (v = (VH *)s->PacketAdapter->Param) == NULL)
	{
		return;
	}

	Virtual_Free(v);
}

// Release the virtual host
void ReleaseVirtual(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	if (Release(v->ref) == 0)
	{
		CleanupVirtual(v);
	}
}

// Lock the virtual host
void LockVirtual(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	Lock(v->lock);
}

// Unlock the virtual host
void UnlockVirtual(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	Unlock(v->lock);
}

// Cleanup the virtual host
void CleanupVirtual(VH *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	if (v->Session != NULL)
	{
		ReleaseSession(v->Session);
	}

	DeleteCounter(v->Counter);
	DeleteLock(v->lock);

	Free(v);
}

// Stop the virtual host
void StopVirtualHost(VH *v)
{
	SESSION *s;
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Get the session corresponding to the virtual host
	LockVirtual(v);
	{
		s = v->Session;
		if (s != NULL)
		{
			AddRef(s->ref);
		}
	}
	UnlockVirtual(v);

	if (s == NULL)
	{
		// This session is already stopped
		return;
	}

	// Stop Session
	StopSession(s);

	ReleaseSession(s);
}

// Create a new virtual host
VH *NewVirtualHost(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, VH_OPTION *vh_option)
{
	return NewVirtualHostEx(cedar, option, auth, vh_option, NULL);
}
VH *NewVirtualHostEx(CEDAR *cedar, CLIENT_OPTION *option, CLIENT_AUTH *auth, VH_OPTION *vh_option, NAT *nat)
{
	VH *v;
	SOCK *s;
	// Validate arguments
	if (vh_option == NULL)
	{
		return NULL;
	}

	// Create a VH
	v = ZeroMalloc(sizeof(VH));
	v->ref = NewRef();
	v->lock = NewLock();
	v->Counter = NewCounter();

	v->nat = nat;

	// Examine whether ICMP Raw Socket can be created
	s = NewUDP4(MAKE_SPECIAL_PORT(IP_PROTO_ICMPV4), NULL);
	if (s != NULL)
	{
		if (s->IsTtlSupported)
		{
			v->IcmpRawSocketOk = true;
		}

		ReleaseSock(s);
	}

	if (v->IcmpRawSocketOk == false)
	{
		v->IcmpApiOk = true;
	}

	// Set the options
	SetVirtualHostOption(v, vh_option);

	return v;
}

// Generate a random MAC address
void GenMacAddress(UCHAR *mac)
{
	UCHAR rand_data[32];
	UINT64 now;
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (mac == NULL)
	{
		return;
	}

	// Get the current time
	now = SystemTime64();

	// Generate a random number
	Rand(rand_data, sizeof(rand_data));

	// Add to the buffer
	b = NewBuf();
	WriteBuf(b, &now, sizeof(now));
	WriteBuf(b, rand_data, sizeof(rand_data));

	// Hash
	Sha0(hash, b->Buf, b->Size);

	// Generate a MAC address
	mac[0] = 0x5E;
	mac[1] = hash[0];
	mac[2] = hash[1];
	mac[3] = hash[2];
	mac[4] = hash[3];
	mac[5] = hash[4];

	FreeBuf(b);
}

// Get a packet of virtual host adapter
PACKET_ADAPTER *VirtualGetPacketAdapter()
{
	return NewPacketAdapter(VirtualPaInit, VirtualPaGetCancel,
	                        VirtualPaGetNextPacket, VirtualPaPutPacket, VirtualPaFree);
}


