// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// TcpIp.c
// Utility module for TCP/IP packet processing

#include "TcpIp.h"

#include "Cfg.h"
#include "Memory.h"
#include "Str.h"

// Release the memory for the ICMP response
void IcmpFreeResult(ICMP_RESULT *r)
{
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	IcmpApiFreeResult(r);
}

// Parse the ICMP reply packet received from the socket
ICMP_RESULT *IcmpParseResult(IP *dest_ip, USHORT src_id, USHORT src_seqno, UCHAR *recv_buffer, UINT recv_buffer_size)
{
	ICMP_RESULT *ret = NULL;
	UINT i;
	// Validate arguments
	if (dest_ip == NULL || IsIP4(dest_ip) == false || recv_buffer == NULL || recv_buffer_size == 0)
	{
		return NULL;
	}

	i = recv_buffer_size;

	if (true)
	{
		UINT ip_header_size = GetIpHeaderSize(recv_buffer, i);
		if (ip_header_size >= sizeof(IPV4_HEADER) && (ip_header_size <= i))
		{
			IPV4_HEADER *ipv4 = (IPV4_HEADER *)recv_buffer;
			if ((IPV4_GET_VERSION(ipv4) == 4) && (ipv4->Protocol == IP_PROTO_ICMPV4))
			{
				UINT ip_total_len = (UINT)Endian16(ipv4->TotalLength);

				if ((ip_total_len >= sizeof(IPV4_HEADER)) && (ip_total_len <= i) && (ip_total_len >= ip_header_size))
				{
					UINT icmp_packet_size = ip_total_len - ip_header_size;
					ICMP_HEADER *icmp = (ICMP_HEADER *)(recv_buffer + ip_header_size);

					if (icmp_packet_size >= sizeof(ICMP_HEADER))
					{
						USHORT chksum = icmp->Checksum;
						USHORT chksum2;
						icmp->Checksum = 0;

						chksum2 = IpChecksum(icmp, icmp_packet_size);

						if (chksum2 == chksum)
						{
							if (icmp->Type == ICMP_TYPE_ECHO_RESPONSE)
							{
								ICMP_ECHO *echo = (ICMP_ECHO *)(recv_buffer + ip_header_size + sizeof(ICMP_HEADER));
								if (icmp_packet_size >= (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO)))
								{
									if (Endian16(echo->Identifier) == src_id && (src_seqno == 0 || Endian16(echo->SeqNo) == src_seqno))
									{
										IP ip;

										UINTToIP(&ip, ipv4->SrcIP);

										// Received the correct Echo response
										ret = ZeroMalloc(sizeof(ICMP_RESULT));

										ret->Ok = true;
										ret->Ttl = ipv4->TimeToLive;
										ret->DataSize = icmp_packet_size - (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));
										ret->Data = Clone(recv_buffer + ip_header_size + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO),
										                  ret->DataSize);
										Copy(&ret->IpAddress, &ip, sizeof(IP));
									}
								}
							}
							else if (icmp->Type == ICMP_TYPE_ECHO_REQUEST)
							{
								// Ignore because an Echo request should not arrive
							}
							else
							{
								// If an error is returned, compare to the copy of
								// the ICMP packet last sent
								IPV4_HEADER *orig_ipv4 = (IPV4_HEADER *)(recv_buffer + ip_header_size + 4 + sizeof(ICMP_HEADER));
								if (icmp_packet_size >= (sizeof(ICMP_HEADER) + 4 + sizeof(IPV4_HEADER)))
								{
									UINT orig_ipv4_header_size = GetIpHeaderSize((UCHAR *)orig_ipv4, icmp_packet_size - 4 - sizeof(ICMP_HEADER));
									if (orig_ipv4_header_size >= sizeof(IPV4_HEADER))
									{
										if ((IPV4_GET_VERSION(orig_ipv4) == 4) && (orig_ipv4->Protocol == IP_PROTO_ICMPV4))
										{
											if (icmp_packet_size >= (sizeof(ICMP_HEADER) + 4 + orig_ipv4_header_size + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO)))
											{
												ICMP_HEADER *orig_icmp = (ICMP_HEADER *)(recv_buffer + ip_header_size + sizeof(ICMP_HEADER) + 4 + orig_ipv4_header_size);
												ICMP_ECHO *orig_echo = (ICMP_ECHO *)(recv_buffer + ip_header_size + sizeof(ICMP_HEADER) + 4 + orig_ipv4_header_size + sizeof(ICMP_HEADER));

												if (orig_icmp->Type == ICMP_TYPE_ECHO_REQUEST && orig_echo->Identifier == Endian16(src_id) && (src_seqno == 0 || orig_echo->SeqNo == Endian16(src_seqno)))
												{
													IP ip;

													UINTToIP(&ip, ipv4->SrcIP);

													ret = ZeroMalloc(sizeof(ICMP_RESULT));

													ret->Type = icmp->Type;
													ret->Code = icmp->Code;
													ret->Ttl = ipv4->TimeToLive;
													ret->DataSize = icmp_packet_size - (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));
													ret->Data = Clone(recv_buffer + ip_header_size + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO),
													                  ret->DataSize);
													Copy(&ret->IpAddress, &ip, sizeof(IP));
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
		}
	}

	return ret;
}

// Get whether the packet is a DHCP packet associated with the specified MAC address
bool IsDhcpPacketForSpecificMac(UCHAR *data, UINT size, UCHAR *mac_address)
{
	USHORT *us;
	IPV4_HEADER *ip;
	UDP_HEADER *udp;
	UINT ip_header_size;
	bool is_send = false, is_recv = false;
	// Validate arguments
	if (data == NULL || mac_address == NULL || IsZero(mac_address, 6))
	{
		return false;
	}

	// Whether the src or the dest matches
	if (size < 14)
	{
		return false;
	}

	// Destination MAC address
	if (Cmp(data, mac_address, 6) == 0)
	{
		is_recv = true;
	}
	size -= 6;
	data += 6;

	// Source MAC address
	if (Cmp(data, mac_address, 6) == 0)
	{
		is_send = true;
	}
	size -= 6;
	data += 6;

	if (is_send == false && is_recv == false)
	{
		return false;
	}
	if (is_send && is_recv)
	{
		return false;
	}

	// TPID
	us = (USHORT *)data;
	size -= 2;
	data += 2;

	if (READ_USHORT(us) != MAC_PROTO_IPV4)
	{
		// Other than IPv4
		return false;
	}

	// IP header
	ip_header_size = GetIpHeaderSize(data, size);
	if (ip_header_size == 0)
	{
		// IPv4 header analysis failure
		return false;
	}

	ip = (IPV4_HEADER *)data;
	data += ip_header_size;
	size -= ip_header_size;

	if (ip->Protocol != IP_PROTO_UDP)
	{
		// Not an UDP packet
		return false;
	}

	// UDP header
	if (size < sizeof(UDP_HEADER))
	{
		return false;
	}
	udp = (UDP_HEADER *)data;
	data += sizeof(UDP_HEADER);
	size -= sizeof(UDP_HEADER);

	if (is_send)
	{
		// Detect whether it's a DHCP Request packet
		if (Endian16(udp->DstPort) == 67)
		{
			Debug("IsDhcpPacketForSpecificMac: DHCP Request Packet is Detected.\n");
			return true;
		}
	}
	else if (is_recv)
	{
		// Detect whether it's a DHCP Response packet
		if (Endian16(udp->SrcPort) == 67)
		{
			Debug("IsDhcpPacketForSpecificMac: DHCP Response Packet is Detected.\n");
			return true;
		}
	}

	return false;
}

// Adjust the MSS of the TCP in the IP packet (L2)
bool AdjustTcpMssL2(UCHAR *src, UINT src_size, UINT mss, USHORT tag_vlan_tpid)
{
	MAC_HEADER *mac;
	USHORT proto;
	// Validate arguments
	if (src == NULL || src_size == 0 || mss == 0)
	{
		return false;
	}
	if (tag_vlan_tpid == 0)
	{
		tag_vlan_tpid = MAC_PROTO_TAGVLAN;
	}

	if (src_size < sizeof(MAC_HEADER))
	{
		return false;
	}

	mac = (MAC_HEADER *)src;

	src += sizeof(MAC_HEADER);
	src_size -= sizeof(MAC_HEADER);

	proto = Endian16(mac->Protocol);

	if (proto == MAC_PROTO_IPV4 || proto == MAC_PROTO_IPV6)
	{
		// Ordinary IPv4 / IPv6 packet
		return AdjustTcpMssL3(src, src_size, mss);
	}
	else if (proto == tag_vlan_tpid)
	{
		// IPv4 / IPv6 packets in the VLAN tag
		if (src_size < 4)
		{
			return false;
		}

		src += 2;
		src_size -= 2;

		proto = READ_USHORT(src);

		if (proto == MAC_PROTO_IPV4 || proto == MAC_PROTO_IPV6)
		{
			if (mss >= 5)
			{
				mss -= 4;

				src += 2;
				src_size -= 2;

				return AdjustTcpMssL3(src, src_size, mss);
			}
		}
	}

	return false;
}

// Get an IP header size
UINT GetIpHeaderSize(UCHAR *src, UINT src_size)
{
	UCHAR ip_ver;
	TCP_HEADER *tcp = NULL;
	IPV4_HEADER *ip = NULL;
	IPV6_HEADER *ip6 = NULL;
	// Validate arguments
	if (src == NULL || src_size == 0)
	{
		return 0;
	}

	// Get the IP version number
	ip_ver = (src[0] >> 4) & 0x0f;

	if (ip_ver == 4)
	{
		// IPv4
		UINT ip_header_size;
		if (src_size < sizeof(IPV4_HEADER))
		{
			// No IPv4 header
			return 0;
		}

		ip = (IPV4_HEADER *)src;

		ip_header_size = IPV4_GET_HEADER_LEN(ip) * 4;
		if (ip_header_size < sizeof(IPV4_HEADER))
		{
			// Header size is invalid
			return 0;
		}

		if (src_size < ip_header_size)
		{
			// No IPv4 header
			return 0;
		}

		return ip_header_size;
	}
	else if (ip_ver == 6)
	{
		// IPv6
		IPV6_HEADER_PACKET_INFO v6;

		if (ParsePacketIPv6Header(&v6, src, src_size) == false)
		{
			// IPv6 analysis failure
			return 0;
		}

		ip6 = v6.IPv6Header;
		if (ip6 == NULL)
		{
			return 0;
		}

		if (src_size < v6.TotalHeaderSize)
		{
			// No header data
			return 0;
		}

		return v6.TotalHeaderSize;
	}
	else
	{
		// Invalid
		return 0;
	}
}

// Adjust the MSS of TCP in the IP packet (L3)
bool AdjustTcpMssL3(UCHAR *src, UINT src_size, UINT mss)
{
	UCHAR ip_ver;
	TCP_HEADER *tcp = NULL;
	UINT tcp_size = 0;
	UINT tcp_header_size;
	UCHAR *options;
	UINT options_size;
	IPV4_HEADER *ip = NULL;
	IPV6_HEADER *ip6 = NULL;
	// Validate arguments
	if (src == NULL || src_size == 0 || mss == 0)
	{
		return false;
	}

	// Get the IP version number
	ip_ver = (src[0] >> 4) & 0x0f;

	if (ip_ver == 4)
	{
		UINT ip_header_size;
		UINT ip_total_length;
		// IPv4
		if (src_size < sizeof(IPV4_HEADER))
		{
			// No IPv4 header
			return false;
		}

		ip = (IPV4_HEADER *)src;

		if (ip->Protocol != IP_PROTO_TCP)
		{
			// Non-TCP
			return false;
		}

		if (IPV4_GET_OFFSET(ip) != 0)
		{
			// It is the second or later packet of fragmented packet
			return false;
		}

		if (IPV4_GET_FLAGS(ip) & 0x01)
		{
			// Fragmented packet
			return false;
		}

		ip_header_size = IPV4_GET_HEADER_LEN(ip) * 4;
		if (ip_header_size < sizeof(IPV4_HEADER))
		{
			// Header size is invalid
			return false;
		}

		if (src_size < ip_header_size)
		{
			// No IPv4 header
			return false;
		}

		ip_total_length = READ_USHORT(&ip->TotalLength);

		if (ip_total_length < ip_header_size)
		{
			// Invalid total length
			return false;
		}

		if (src_size < ip_total_length)
		{
			// No total length
			return false;
		}

		src += ip_header_size;
		src_size = ip_total_length - ip_header_size;

		if (src_size < sizeof(TCP_HEADER))
		{
			// No TCP header
			return false;
		}

		tcp = (TCP_HEADER *)src;
		tcp_size = src_size;
	}
	else if (ip_ver == 6)
	{
		// IPv6
		IPV6_HEADER_PACKET_INFO v6;

		if (ParsePacketIPv6Header(&v6, src, src_size) == false)
		{
			// IPv6 analysis failure
			return false;
		}

		ip6 = v6.IPv6Header;
		if (ip6 == NULL)
		{
			return false;
		}

		if (v6.Protocol != IP_PROTO_TCP)
		{
			// Non-TCP
			return false;
		}

		if (v6.IsFragment)
		{
			// It is the second or later packet of fragmented packet
			return false;
		}

		if (v6.FragmentHeader != NULL)
		{
			if (IPV6_GET_FLAGS(v6.FragmentHeader) & IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS)
			{
				// Fragmented packet
				return false;
			}
		}

		tcp = (TCP_HEADER *)v6.Payload;
		tcp_size = v6.PayloadSize;
	}
	else
	{
		// This isn't either IPv4, IPv6
		return false;
	}

	// Processing of the TCP header
	if (tcp == NULL || tcp_size < sizeof(TCP_HEADER))
	{
		return false;
	}

	tcp_header_size = TCP_GET_HEADER_SIZE(tcp) * 4;
	if (tcp_header_size < sizeof(TCP_HEADER))
	{
		// TCP header size is invalid
		return false;
	}

	if (tcp_size < tcp_header_size)
	{
		// Packet length shortage
		return false;
	}

	if (((tcp->Flag & TCP_SYN) == false) ||
	        ((tcp->Flag & TCP_RST) ||
	         (tcp->Flag & TCP_PSH) ||
	         (tcp->Flag & TCP_URG)))
	{
		// Not a SYN packet
		return false;
	}

	// Get the option field
	options = ((UCHAR *)tcp) + sizeof(TCP_HEADER);
	options_size = tcp_header_size - sizeof(TCP_HEADER);

	if (ip6 != NULL)
	{
		// Reduce MSS by 20 since an IP header for IPv6 is 20 bytes larger than IPv4
		if (mss >= 20)
		{
			mss -= 20;
		}
	}

	// MSS should be at least 64
	mss = MAX(mss, 64);

	if (options_size >= 4 && options[0] == 0x02 && options[1] == 0x04)
	{
		// MSS option of TCP is added
		USHORT current_mss = READ_USHORT(((UCHAR *)options) + 2);

		if (current_mss <= mss)
		{
			// if the value of the MSS is smaller than the specified size
			// from the beginning, it doesn't need to be rewritten
			return false;
		}
		else
		{
			WRITE_USHORT(((UCHAR *)options) + 2, mss);

			// Clear the checksum
			tcp->Checksum = 0;

			if (ip != NULL)
			{
				// Calculate the TCPv4 checksum
				tcp->Checksum = CalcChecksumForIPv4(ip->SrcIP, ip->DstIP, IP_PROTO_TCP, tcp, tcp_size, 0);
			}
			else
			{
				// Calculate the TCPv6 checksum
				tcp->Checksum = CalcChecksumForIPv6(&ip6->SrcAddress, &ip6->DestAddress,
				                                    IP_PROTO_TCP, tcp, tcp_size, 0);
			}

			return true;
		}
	}
	else
	{
		// MSS option of TCP is not added
		return false;
	}
}


// Parse the DHCPv4 packet
DHCPV4_DATA *ParseDHCPv4Data(PKT *pkt)
{
	DHCPV4_DATA *d;
	UCHAR *data;
	UINT size;
	UINT magic_cookie = Endian32(DHCP_MAGIC_COOKIE);
	bool ok = false;
	DHCP_OPTION *o;
	// Validate arguments
	if (pkt == NULL)
	{
		return NULL;
	}
	if (pkt->TypeL3 != L3_IPV4 || pkt->TypeL4 != L4_UDP || pkt->TypeL7 != L7_DHCPV4)
	{
		return NULL;
	}

	d = ZeroMalloc(sizeof(DHCPV4_DATA));
	d->Size = (UINT)(pkt->PacketSize - (((UCHAR *)pkt->L7.PointerL7) - ((UCHAR *)pkt->PacketData)));
	d->Data = Clone(pkt->L7.PointerL7, d->Size);

	if (d->Size < sizeof(DHCPV4_HEADER))
	{
		goto LABEL_ERROR;
	}

	// Header
	d->Header = (DHCPV4_HEADER *)d->Data;

	data = d->Data;
	size = d->Size;

	// Search for the Magic Cookie
	ok = false;
	while (size >= 5)
	{
		if (Cmp(data, &magic_cookie, 4) == 0)
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
		// Magic Cookie not found
		goto LABEL_ERROR;
	}

	// Parse the DHCP Options
	d->OptionData = data;
	d->OptionSize = size;

	d->OptionList = ParseDhcpOptions(data, size);
	if (d->OptionList == NULL)
	{
		// Parsing failure
		goto LABEL_ERROR;
	}

	UINTToIP(&d->SrcIP, pkt->L3.IPv4Header->SrcIP);
	UINTToIP(&d->DestIP, pkt->L3.IPv4Header->DstIP);

	d->SrcPort = Endian16(pkt->L4.UDPHeader->SrcPort);
	d->DestPort = Endian16(pkt->L4.UDPHeader->DstPort);

	o = GetDhcpOption(d->OptionList, DHCP_ID_MESSAGE_TYPE);
	if (o == NULL || o->Size != 1)
	{
		goto LABEL_ERROR;
	}

	d->OpCode = *((UCHAR *)o->Data);

	d->ParsedOptionList = ParseDhcpOptionList(d->OptionData, d->OptionSize);

	if (d->ParsedOptionList == NULL)
	{
		goto LABEL_ERROR;
	}

	if (d->ParsedOptionList->ServerAddress == 0)
	{
		d->ParsedOptionList->ServerAddress = d->Header->ServerIP;
	}

	d->ParsedOptionList->ClientAddress = d->Header->YourIP;

	return d;

LABEL_ERROR:
	FreeDHCPv4Data(d);
	return NULL;
}

// Release the DHCPv4 packet
void FreeDHCPv4Data(DHCPV4_DATA *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	FreeDhcpOptions(d->OptionList);
	Free(d->Data);

	Free(d->ParsedOptionList);

	Free(d);
}

// Embed a VLAN tag to the packet
void VLanInsertTag(void **packet_data, UINT *packet_size, UINT vlan_id, UINT vlan_tpid)
{
	UINT dest_size;
	UCHAR *dest_data;
	UINT src_size;
	UCHAR *src_data;
	USHORT vlan_ushort = Endian16(((USHORT)vlan_id) & 0xFFF);
	USHORT vlan_tpid_ushort;
	// Validate arguments
	if (packet_data == NULL || *packet_data == NULL || packet_size == NULL ||
	        *packet_size < 14 || vlan_id == 0)
	{
		return;
	}
	if (vlan_tpid == 0)
	{
		vlan_tpid = MAC_PROTO_TAGVLAN;
	}

	vlan_tpid_ushort = Endian16((USHORT)vlan_tpid);

	src_size = *packet_size;
	src_data = (UCHAR *)(*packet_data);

	dest_size = src_size + 4;
	dest_data = Malloc(dest_size);

	Copy(&dest_data[12], &vlan_tpid_ushort, sizeof(USHORT));
	Copy(&dest_data[14], &vlan_ushort, sizeof(USHORT));

	Copy(&dest_data[0], &src_data[0], 12);
	Copy(&dest_data[16], &src_data[12], src_size - 12);

	*packet_size = dest_size;
	*packet_data = dest_data;

	Free(src_data);
}

// Remove the VLAN tag from the packet
bool VLanRemoveTag(void **packet_data, UINT *packet_size, UINT vlan_id, UINT vlan_tpid)
{
	UCHAR *src_data;
	UINT src_size;
	USHORT vlan_tpid_ushort;
	UCHAR *vlan_tpid_uchar;
	// Validate arguments
	if (packet_data == NULL || *packet_data == NULL || packet_size == NULL ||
	        *packet_size < 14)
	{
		return false;
	}

	if (vlan_tpid == 0)
	{
		vlan_tpid = MAC_PROTO_TAGVLAN;
	}

	vlan_tpid_ushort = Endian16((USHORT)vlan_tpid);
	vlan_tpid_uchar = (UCHAR *)(&vlan_tpid_ushort);

	src_data = (UCHAR *)(*packet_data);
	src_size = *packet_size;

	if (src_data[12] == vlan_tpid_uchar[0] && src_data[13] == vlan_tpid_uchar[1])
	{
		if (src_size >= 18)
		{
			USHORT vlan_ushort;

			vlan_ushort = READ_USHORT(&src_data[14]);
			vlan_ushort = vlan_ushort & 0xFFF;

			if (vlan_id == 0 || (vlan_ushort == vlan_id))
			{
				UINT dest_size = src_size - 4;
				UINT i;

				for (i = 12; i < dest_size; i++)
				{
					src_data[i] = src_data[i + 4];
				}

				*packet_size = dest_size;

				return true;
			}
		}
	}

	return false;
}

// Sending of an ICMPv6 packet
BUF *BuildICMPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR hop_limit, UCHAR type, UCHAR code, void *data, UINT size, UINT id)
{
	ICMP_HEADER *icmp;
	void *data_buf;
	BUF *ret;
	// Validate arguments
	if (src_ip == NULL || dest_ip == NULL || data == NULL)
	{
		return NULL;
	}

	// Assemble the header
	icmp = ZeroMalloc(sizeof(ICMP_HEADER) + size);
	data_buf = ((UCHAR *)icmp) + sizeof(ICMP_HEADER);
	Copy(data_buf, data, size);

	icmp->Type = type;
	icmp->Code = code;
	icmp->Checksum = CalcChecksumForIPv6(src_ip, dest_ip, IP_PROTO_ICMPV6, icmp,
	                                     sizeof(ICMP_HEADER) + size, 0);

	ret = BuildIPv6(dest_ip, src_ip, id, IP_PROTO_ICMPV6, hop_limit, icmp,
	                sizeof(ICMP_HEADER) + size);

	Free(icmp);

	return ret;
}

// Build an ICMPv6 Neighbor Solicitation packet
BUF *BuildICMPv6NeighborSoliciation(IPV6_ADDR *src_ip, IPV6_ADDR *target_ip, UCHAR *my_mac_address, UINT id, bool use_multicast)
{
	ICMPV6_OPTION_LIST opt;
	ICMPV6_OPTION_LINK_LAYER link;
	ICMPV6_NEIGHBOR_SOLICIATION_HEADER header;
	BUF *b;
	BUF *b2;
	BUF *ret;
	// Validate arguments
	if (src_ip == NULL || target_ip == NULL || my_mac_address == NULL)
	{
		return NULL;
	}

	Zero(&link, sizeof(link));
	Copy(link.Address, my_mac_address, 6);

	Zero(&opt, sizeof(opt));
	opt.SourceLinkLayer = &link;

	b = BuildICMPv6Options(&opt);

	Zero(&header, sizeof(header));
	Copy(&header.TargetAddress, target_ip, sizeof(IPV6_ADDR));

	b2 = NewBuf();

	WriteBuf(b2, &header, sizeof(header));
	WriteBufBuf(b2, b);

	if (use_multicast)
	{
		IPV6_ADDR solicitAddress;
		Zero(&solicitAddress, sizeof(IPV6_ADDR));
		solicitAddress.Value[0] = 0xFF;
		solicitAddress.Value[1] = 0x02;
		solicitAddress.Value[11] = 0x01;
		solicitAddress.Value[12] = 0xFF;
		Copy(&solicitAddress.Value[13], &target_ip->Value[13], 3);

		ret = BuildICMPv6(src_ip, &solicitAddress, 255,
	                          ICMPV6_TYPE_NEIGHBOR_SOLICIATION, 0, b2->Buf, b2->Size, id);
	}
	else
	{
		ret = BuildICMPv6(src_ip, target_ip, 255,
	                          ICMPV6_TYPE_NEIGHBOR_SOLICIATION, 0, b2->Buf, b2->Size, id);
	}

	FreeBuf(b);
	FreeBuf(b2);

	return ret;
}

BUF *BuildICMPv6RouterSoliciation(IPV6_ADDR *src_ip, IPV6_ADDR *target_ip, UCHAR *my_mac_address, UINT id)
{
	ICMPV6_OPTION_LIST opt;
	ICMPV6_OPTION_LINK_LAYER link;
	ICMPV6_ROUTER_SOLICIATION_HEADER header;
	BUF *b;
	BUF *b2;
	BUF *ret;

	if (src_ip == NULL || target_ip == NULL || my_mac_address == NULL)
	{
		return NULL;
	}

	Zero(&link, sizeof(link));
	Copy(link.Address, my_mac_address, 6);

	Zero(&opt, sizeof(opt));
	opt.SourceLinkLayer = &link;

	b = BuildICMPv6Options(&opt);

	Zero(&header, sizeof(header));

	b2 = NewBuf();

	WriteBuf(b2, &header, sizeof(header));
	WriteBufBuf(b2, b);

	ret = BuildICMPv6(src_ip, target_ip, 255,
	                  ICMPV6_TYPE_ROUTER_SOLICIATION, 0, b2->Buf, b2->Size, id);

	FreeBuf(b);
	FreeBuf(b2);

	return ret;
}

// Get the next header number from the queue
UCHAR IPv6GetNextHeaderFromQueue(QUEUE *q)
{
	UINT *p;
	UCHAR v = 0;
	// Validate arguments
	if (q == NULL)
	{
		return IPV6_HEADER_NONE;
	}

	p = (UINT *)GetNext(q);
	if (p != NULL)
	{
		v = (UCHAR)(*p);
		Free(p);
	}

	return v;
}

// Add an IPv6 extension header option (variable length)
void BuildAndAddIPv6PacketOptionHeader(BUF *b, IPV6_OPTION_HEADER *opt, UCHAR next_header, UINT size)
{
	IPV6_OPTION_HEADER *h;
	UINT total_size;
	// Validate arguments
	if (b == NULL || opt == NULL)
	{
		return;
	}

	total_size = size;
	if ((total_size % 8) != 0)
	{
		total_size = ((total_size / 8) + 1) * 8;
	}

	h = ZeroMalloc(total_size);
	Copy(h, opt, size);
	h->Size = (total_size / 8) - 1;
	h->NextHeader = next_header;

	WriteBuf(b, h, total_size);

	Free(h);
}

// Build an IPv6 packet
BUF *BuildIPv6(IPV6_ADDR *dest_ip, IPV6_ADDR *src_ip, UINT id, UCHAR protocol, UCHAR hop_limit, void *data,
               UINT size)
{
	IPV6_HEADER_PACKET_INFO info;
	IPV6_HEADER ip_header;
	BUF *buf;
	UINT size_for_headers;
	// Validate arguments
	if (dest_ip == NULL || src_ip == NULL || data == NULL)
	{
		return NULL;
	}
	if (hop_limit == 0)
	{
		hop_limit = 255;
	}

	// IPv6 header
	Zero(&ip_header, sizeof(ip_header));
	IPV6_SET_VERSION(&ip_header, 6);
	ip_header.HopLimit = hop_limit;
	Copy(&ip_header.SrcAddress, src_ip, sizeof(IPV6_ADDR));
	Copy(&ip_header.DestAddress, dest_ip, sizeof(IPV6_ADDR));

	// Arrangement of the packet header information
	Zero(&info, sizeof(info));
	info.IPv6Header = &ip_header;
	info.Protocol = protocol;
	info.Payload = data;
	info.PayloadSize = size;

	buf = BuildIPv6PacketHeader(&info, &size_for_headers);
	if (buf == NULL)
	{
		return NULL;
	}

	return buf;
}

// Build the IPv6 packet header section
BUF *BuildIPv6PacketHeader(IPV6_HEADER_PACKET_INFO *info, UINT *bytes_before_payload)
{
	BUF *b;
	QUEUE *q;
	UINT bbp = 0;
	// Validate arguments
	if (info == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	q = NewQueueFast();

	// Create the list of options headers
	if (info->HopHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_HOP);
	}
	if (info->EndPointHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_ENDPOINT);
	}
	if (info->RoutingHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_ROUTING);
	}
	if (info->FragmentHeader != NULL)
	{
		InsertQueueInt(q, IPV6_HEADER_FRAGMENT);
	}
	InsertQueueInt(q, info->Protocol);

	// IPv6 header
	info->IPv6Header->NextHeader = IPv6GetNextHeaderFromQueue(q);
	WriteBuf(b, info->IPv6Header, sizeof(IPV6_HEADER));

	// Hop-by-hop option header
	if (info->HopHeader != NULL)
	{
		BuildAndAddIPv6PacketOptionHeader(b, info->HopHeader,
		                                  IPv6GetNextHeaderFromQueue(q), info->HopHeaderSize);
	}

	// End point option header
	if (info->EndPointHeader != NULL)
	{
		BuildAndAddIPv6PacketOptionHeader(b, info->EndPointHeader,
		                                  IPv6GetNextHeaderFromQueue(q), info->EndPointHeaderSize);
	}

	// Routing header
	if (info->RoutingHeader != NULL)
	{
		BuildAndAddIPv6PacketOptionHeader(b, info->RoutingHeader,
		                                  IPv6GetNextHeaderFromQueue(q), info->RoutingHeaderSize);
	}

	// Fragment header
	if (info->FragmentHeader != NULL)
	{
		info->FragmentHeader->NextHeader = IPv6GetNextHeaderFromQueue(q);
		WriteBuf(b, info->FragmentHeader, sizeof(IPV6_FRAGMENT_HEADER));
	}

	bbp = b->Size;
	if (info->FragmentHeader == NULL)
	{
		bbp += sizeof(IPV6_FRAGMENT_HEADER);
	}

	// Payload
	if (info->Protocol != IPV6_HEADER_NONE)
	{
		WriteBuf(b, info->Payload, info->PayloadSize);
	}

	ReleaseQueue(q);

	SeekBuf(b, 0, 0);

	// Payload length
	((IPV6_HEADER *)b->Buf)->PayloadLength = Endian16(b->Size - (USHORT)sizeof(IPV6_HEADER));

	if (bytes_before_payload != NULL)
	{
		// Calculate the length just before the payload
		// (by assuming fragment header is always included)
		*bytes_before_payload = bbp;
	}

	return b;
}

// Build the option values of an ICMPv6 packet
void BuildICMPv6OptionValue(BUF *b, UCHAR type, void *header_pointer, UINT total_size)
{
	UINT packet_size;
	UCHAR *packet;
	ICMPV6_OPTION *opt;
	// Validate arguments
	if (b == NULL || header_pointer == NULL)
	{
		return;
	}

	packet_size = ((total_size + 7) / 8) * 8;
	packet = ZeroMalloc(packet_size);

	Copy(packet, header_pointer, total_size);
	opt = (ICMPV6_OPTION *)packet;
	opt->Length = (UCHAR)(packet_size / 8);
	opt->Type = type;

	WriteBuf(b, packet, packet_size);

	Free(packet);
}

// Build the options of the ICMPv6 packet
BUF *BuildICMPv6Options(ICMPV6_OPTION_LIST *o)
{
	BUF *b;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	if (o->SourceLinkLayer != NULL)
	{
		BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER, o->SourceLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	}
	if (o->TargetLinkLayer != NULL)
	{
		BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER, o->TargetLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	}
	for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
	{
		if (o->Prefix[i] != NULL)
		{
			BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_PREFIX, o->Prefix[i], sizeof(ICMPV6_OPTION_PREFIX));
		}
		else
		{
			break;
		}
	}
	if (o->Mtu != NULL)
	{
		BuildICMPv6OptionValue(b, ICMPV6_OPTION_TYPE_MTU, o->Mtu, sizeof(ICMPV6_OPTION_MTU));
	}

	SeekBuf(b, 0, 0);

	return b;
}

// Checksum calculation (IPv4)
USHORT CalcChecksumForIPv4(UINT src_ip, UINT dst_ip, UCHAR protocol, void *data, UINT size, UINT real_size)
{
	UCHAR *tmp;
	UINT tmp_size;
	IPV4_PSEUDO_HEADER *ph;
	USHORT ret;
	bool use_free = false;
	UCHAR tmp_buffer[1600];
	// Validate arguments
	if (data == NULL && size != 0)
	{
		return 0;
	}

	if (real_size == 0)
	{
		real_size = size;
	}

	if (real_size == INFINITE)
	{
		real_size = 0;
	}

	tmp_size = size + sizeof(IPV4_PSEUDO_HEADER);

	if (tmp_size > sizeof(tmp_buffer))
	{
		tmp = Malloc(tmp_size);

		use_free = true;
	}
	else
	{
		tmp = tmp_buffer;
	}

	ph = (IPV4_PSEUDO_HEADER *)tmp;
	ph->SrcIP = src_ip;
	ph->DstIP = dst_ip;
	ph->PacketLength = Endian16(real_size);
	ph->Protocol = protocol;
	ph->Reserved = 0;

	if (size >= 1)
	{
		Copy(((UCHAR *)tmp) + sizeof(IPV4_PSEUDO_HEADER), data, size);
	}

	ret = IpChecksum(tmp, tmp_size);

	if (use_free)
	{
		Free(tmp);
	}

	return ret;
}

// Checksum calculation (IPv6)
USHORT CalcChecksumForIPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR protocol, void *data, UINT size, UINT real_size)
{
	UCHAR *tmp;
	UINT tmp_size;
	IPV6_PSEUDO_HEADER *ph;
	USHORT ret;
	bool use_free = false;
	UCHAR tmp_buffer[256];
	// Validate arguments
	if (data == NULL && size != 0)
	{
		return 0;
	}

	if (real_size == 0)
	{
		real_size = size;
	}

	if (real_size == INFINITE)
	{
		real_size = 0;
	}

	tmp_size = size + sizeof(IPV6_PSEUDO_HEADER);

	if (tmp_size > sizeof(tmp_buffer))
	{
		tmp = Malloc(tmp_size);

		use_free = true;
	}
	else
	{
		tmp = tmp_buffer;
	}

	ph = (IPV6_PSEUDO_HEADER *)tmp;
	Zero(ph, sizeof(IPV6_PSEUDO_HEADER));
	Copy(&ph->SrcAddress, src_ip, sizeof(IPV6_ADDR));
	Copy(&ph->DestAddress, dest_ip, sizeof(IPV6_ADDR));
	ph->UpperLayerPacketSize = Endian32(real_size);
	ph->NextHeader = protocol;

	Copy(((UCHAR *)tmp) + sizeof(IPV6_PSEUDO_HEADER), data, size);

	ret = IpChecksum(tmp, tmp_size);

	if (use_free)
	{
		Free(tmp);
	}

	return ret;
}

// Release the cloned packet
void FreeClonePacket(PKT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	Free(p->IPv6HeaderPacketInfo.IPv6Header);
	Free(p->IPv6HeaderPacketInfo.HopHeader);
	Free(p->IPv6HeaderPacketInfo.EndPointHeader);
	Free(p->IPv6HeaderPacketInfo.RoutingHeader);
	Free(p->IPv6HeaderPacketInfo.FragmentHeader);
	Free(p->IPv6HeaderPacketInfo.Payload);
	Free(p->ICMPv6HeaderPacketInfo.Data);
	Free(p->ICMPv6HeaderPacketInfo.EchoData);
	Free(p->ICMPv6HeaderPacketInfo.Headers.HeaderPointer);
	FreeCloneICMPv6Options(&p->ICMPv6HeaderPacketInfo.OptionList);
	Free(p->L3.PointerL3);
	Free(p->L4.PointerL4);
	Free(p->L7.PointerL7);
	Free(p->PacketData);
	Free(p->MacHeader);
	Free(p->HttpLog);
	Free(p);
}

// Copy the packet header
PKT *ClonePacket(PKT *p, bool copy_data)
{
	PKT *ret;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	ret = ZeroMallocFast(sizeof(PKT));
	ret->PacketSize = p->PacketSize;

	// Copy of the MAC header
	ret->MacHeader = MallocFast(sizeof(MAC_HEADER));
	Copy(ret->MacHeader, p->MacHeader, sizeof(MAC_HEADER));

	// Copy of the MAC flag
	ret->BroadcastPacket = p->BroadcastPacket;
	ret->InvalidSourcePacket = p->InvalidSourcePacket;

	// Copy of the IPv6 related structure
	Copy(&ret->IPv6HeaderPacketInfo, &p->IPv6HeaderPacketInfo, sizeof(IPV6_HEADER_PACKET_INFO));
	Copy(&ret->ICMPv6HeaderPacketInfo, &p->ICMPv6HeaderPacketInfo, sizeof(ICMPV6_HEADER_INFO));

	// Layer 3
	ret->TypeL3 = p->TypeL3;
	switch (ret->TypeL3)
	{
	case L3_ARPV4:
		// ARP packet
		ret->L3.ARPv4Header = MallocFast(sizeof(ARPV4_HEADER));
		Copy(ret->L3.ARPv4Header, p->L3.ARPv4Header, sizeof(ARPV4_HEADER));
		break;

	case L3_IPV4:
		// IPv4 packet
		ret->L3.IPv4Header = MallocFast(sizeof(IPV4_HEADER));
		Copy(ret->L3.IPv4Header, p->L3.IPv4Header, sizeof(IPV4_HEADER));
		break;

	case L3_IPV6:
		// IPv6 packet
		ret->L3.IPv6Header = MallocFast(sizeof(IPV6_HEADER));
		Copy(ret->L3.IPv6Header, p->L3.IPv6Header, sizeof(IPV6_HEADER));

		ret->IPv6HeaderPacketInfo.IPv6Header = Clone(p->IPv6HeaderPacketInfo.IPv6Header,
		                                       sizeof(IPV6_HEADER));

		ret->IPv6HeaderPacketInfo.HopHeader = Clone(p->IPv6HeaderPacketInfo.HopHeader,
		                                      sizeof(IPV6_OPTION_HEADER));

		ret->IPv6HeaderPacketInfo.EndPointHeader = Clone(p->IPv6HeaderPacketInfo.EndPointHeader,
		        sizeof(IPV6_OPTION_HEADER));

		ret->IPv6HeaderPacketInfo.RoutingHeader = Clone(p->IPv6HeaderPacketInfo.RoutingHeader,
		        sizeof(IPV6_OPTION_HEADER));

		ret->IPv6HeaderPacketInfo.FragmentHeader = Clone(p->IPv6HeaderPacketInfo.FragmentHeader,
		        sizeof(IPV6_FRAGMENT_HEADER));

		ret->IPv6HeaderPacketInfo.Payload = Clone(p->IPv6HeaderPacketInfo.Payload,
		                                    p->IPv6HeaderPacketInfo.PayloadSize);
		break;
	}

	// Layer 4
	ret->TypeL4 = p->TypeL4;
	switch (ret->TypeL4)
	{
	case L4_ICMPV4:
		// ICMPv4 packet
		ret->L4.ICMPHeader = MallocFast(sizeof(ICMP_HEADER));
		Copy(ret->L4.ICMPHeader, p->L4.ICMPHeader, sizeof(ICMP_HEADER));
		break;

	case L4_ICMPV6:
		// ICMPv6 packet
		ret->L4.ICMPHeader = MallocFast(sizeof(ICMP_HEADER));
		Copy(ret->L4.ICMPHeader, p->L4.ICMPHeader, sizeof(ICMP_HEADER));

		ret->ICMPv6HeaderPacketInfo.Data = Clone(p->ICMPv6HeaderPacketInfo.Data,
		                                   p->ICMPv6HeaderPacketInfo.DataSize);

		ret->ICMPv6HeaderPacketInfo.EchoData = Clone(p->ICMPv6HeaderPacketInfo.EchoData,
		                                       p->ICMPv6HeaderPacketInfo.EchoDataSize);

		switch (ret->ICMPv6HeaderPacketInfo.Type)
		{
		case ICMPV6_TYPE_ECHO_REQUEST:
		case ICMPV6_TYPE_ECHO_RESPONSE:
			break;

		case ICMPV6_TYPE_ROUTER_SOLICIATION:
			ret->ICMPv6HeaderPacketInfo.Headers.RouterSoliciationHeader =
			    Clone(p->ICMPv6HeaderPacketInfo.Headers.RouterSoliciationHeader,
			          sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER));
			break;

		case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
			ret->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader =
			    Clone(p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader,
			          sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER));
			break;

		case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:
			ret->ICMPv6HeaderPacketInfo.Headers.NeighborSoliciationHeader =
			    Clone(p->ICMPv6HeaderPacketInfo.Headers.NeighborSoliciationHeader,
			          sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER));
			break;

		case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
			ret->ICMPv6HeaderPacketInfo.Headers.NeighborAdvertisementHeader =
			    Clone(p->ICMPv6HeaderPacketInfo.Headers.NeighborAdvertisementHeader,
			          sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER));
			break;
		}

		CloneICMPv6Options(&ret->ICMPv6HeaderPacketInfo.OptionList,
		                   &p->ICMPv6HeaderPacketInfo.OptionList);
		break;

	case L4_TCP:
		// TCP packet
		ret->L4.TCPHeader = MallocFast(sizeof(TCP_HEADER));
		Copy(ret->L4.TCPHeader, p->L4.TCPHeader, sizeof(TCP_HEADER));
		break;

	case L4_UDP:
		// UDP packet
		ret->L4.UDPHeader = MallocFast(sizeof(UDP_HEADER));
		Copy(ret->L4.UDPHeader, p->L4.UDPHeader, sizeof(UDP_HEADER));
		break;
	}

	// Layer 7
	ret->TypeL7 = p->TypeL7;
	switch (ret->TypeL7)
	{
	case L7_DHCPV4:
		// DHCP packet
		ret->L7.DHCPv4Header = MallocFast(sizeof(DHCPV4_HEADER));
		Copy(ret->L7.DHCPv4Header, p->L7.DHCPv4Header, sizeof(DHCPV4_HEADER));
		break;

	case L7_IKECONN:
		// IKE packet
		ret->L7.IkeHeader = MallocFast(sizeof(IKE_HEADER));
		Copy(ret->L7.IkeHeader, p->L7.IkeHeader, sizeof(IKE_HEADER));
		break;

	case L7_DNS:
		StrCpy(ret->DnsQueryHost, sizeof(ret->DnsQueryHost), p->DnsQueryHost);
		break;
	}

	// Address data
	ret->MacAddressSrc = ret->MacHeader->SrcAddress;
	ret->MacAddressDest = ret->MacHeader->DestAddress;

	if (copy_data)
	{
		// Copy also the packet body
		ret->PacketData = MallocFast(p->PacketSize);
		Copy(ret->PacketData, p->PacketData, p->PacketSize);
	}

	if (p->HttpLog != NULL)
	{
		ret->HttpLog = Clone(p->HttpLog, sizeof(HTTPLOG));
	}

	return ret;
}

// Parse the packet but without data layer except for ICMP
PKT *ParsePacketUpToICMPv6(UCHAR *buf, UINT size)
{
	return ParsePacketEx5(buf, size, false, 0, true, true, false, true);
}

// Parse the contents of the packet
PKT *ParsePacket(UCHAR *buf, UINT size)
{
	return ParsePacketEx(buf, size, false);
}
PKT *ParsePacketEx(UCHAR *buf, UINT size, bool no_l3)
{
	return ParsePacketEx2(buf, size, no_l3, 0);
}
PKT *ParsePacketEx2(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id)
{
	return ParsePacketEx3(buf, size, no_l3, vlan_type_id, true);
}
PKT *ParsePacketEx3(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address)
{
	return ParsePacketEx4(buf, size, no_l3, vlan_type_id, bridge_id_as_mac_address, false, false);
}
PKT *ParsePacketEx4(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address, bool no_http, bool correct_checksum)
{
	return ParsePacketEx5(buf, size, no_l3, vlan_type_id, bridge_id_as_mac_address, no_http, correct_checksum, false);
}
PKT *ParsePacketEx5(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address, bool no_http, bool correct_checksum, bool no_l3_l4_except_icmpv6)
{
	PKT *p;
	USHORT vlan_type_id_16;
	// Validate arguments
	if (buf == NULL || size == 0)
	{
		return NULL;
	}

	if (vlan_type_id == 0)
	{
		vlan_type_id = MAC_PROTO_TAGVLAN;
	}

	vlan_type_id_16 = Endian16((USHORT)vlan_type_id);

	p = ZeroMallocFast(sizeof(PKT));

	p->VlanTypeID = vlan_type_id;

	// If there is garbage after the payload in IPv4 and IPv6 packets, eliminate it
	if (size >= 24)
	{
		if (buf[12] == 0x08 && buf[13] == 0x00)
		{
			USHORT ip_total_size2 = READ_USHORT(&buf[16]);
			UINT mac_packet_size;

			if (ip_total_size2 >= 1)
			{
				mac_packet_size = (UINT)ip_total_size2 + 14;

				if (size > mac_packet_size)
				{
					size = mac_packet_size;
				}
			}
		}
		else if (buf[12] == 0x86 && buf[13] == 0xdd)
		{
			USHORT ip_payload_size_2 = READ_USHORT(&buf[18]);
			UINT mac_packet_size;

			if (ip_payload_size_2 >= 1)
			{
				mac_packet_size = (UINT)ip_payload_size_2 + 14 + 40;

				if (size > mac_packet_size)
				{
					size = mac_packet_size;
				}
			}
		}
		else if (buf[12] == ((UCHAR *)&vlan_type_id_16)[0] && buf[13] == ((UCHAR *)&vlan_type_id_16)[1])
		{
			if (buf[16] == 0x08 && buf[17] == 0x00)
			{
				USHORT ip_total_size2 = READ_USHORT(&buf[20]);
				UINT mac_packet_size;

				if (ip_total_size2 >= 1)
				{
					mac_packet_size = (UINT)ip_total_size2 + 14 + 4;

					if (size > mac_packet_size)
					{
						size = mac_packet_size;
					}
				}
			}
			else if (buf[16] == 0x86 && buf[17] == 0xdd)
			{
				USHORT ip_payload_size_2 = READ_USHORT(&buf[22]);
				UINT mac_packet_size;

				if (ip_payload_size_2 >= 1)
				{
					mac_packet_size = (UINT)ip_payload_size_2 + 14 + 40 + 4;

					if (size > mac_packet_size)
					{
						size = mac_packet_size;
					}
				}
			}
		}
	}

	// Do parse
	if (ParsePacketL2Ex(p, buf, size, no_l3, no_l3_l4_except_icmpv6) == false)
	{
		// Parsing failure
		FreePacket(p);
		return NULL;
	}

	p->PacketData = buf;
	p->PacketSize = size;

	p->MacAddressSrc = p->MacHeader->SrcAddress;
	p->MacAddressDest = p->MacHeader->DestAddress;

	if (bridge_id_as_mac_address)
	{
		if (p->TypeL3 == L3_BPDU)
		{
			if (p->L3.BpduHeader != NULL)
			{
				p->MacAddressSrc = p->L3.BpduHeader->BridgeMacAddress;
			}
		}
	}

	if (no_http == false)
	{
		USHORT port_raw = Endian16(80);
		USHORT port_raw2 = Endian16(8080);
		USHORT port_raw3 = Endian16(443);
		USHORT port_raw4 = Endian16(3128);

		// Analyze if the packet is a part of HTTP
		if ((p->TypeL3 == L3_IPV4 || p->TypeL3 == L3_IPV6) && p->TypeL4 == L4_TCP)
		{
			TCP_HEADER *tcp = p->L4.TCPHeader;
			if (tcp != NULL && (tcp->DstPort == port_raw || tcp->DstPort == port_raw2 || tcp->DstPort == port_raw4) &&
			        (!((tcp->Flag & TCP_SYN) || (tcp->Flag & TCP_RST) || (tcp->Flag & TCP_FIN))))
			{
				if (p->PayloadSize >= 1)
				{
					p->HttpLog = ParseHttpAccessLog(p);
				}
			}
			if (tcp != NULL && tcp->DstPort == port_raw3 &&
			        (!((tcp->Flag & TCP_SYN) || (tcp->Flag & TCP_RST) || (tcp->Flag & TCP_FIN))))
			{
				if (p->PayloadSize >= 1)
				{
					p->HttpLog = ParseHttpsAccessLog(p);
				}
			}
		}
	}

	if (p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4)
	{
		// Get the DHCP opcode
		DHCPV4_DATA *d = ParseDHCPv4Data(p);

		if (d != NULL)
		{
			p->DhcpOpCode = d->OpCode;

			FreeDHCPv4Data(d);
		}
	}

	if (correct_checksum)
	{
		// Correct the checksum of the UDP, IP and TCP
		CorrectChecksum(p);
	}

	// Parsing success
	return p;
}

// Correct the checksum (store the correct value in the header by recalculating the checksum which is by off-load processing)
void CorrectChecksum(PKT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->TypeL3 == L3_IPV4)
	{
		IPV4_HEADER *v4 = p->L3.IPv4Header;

		if (v4 != NULL)
		{
			if (v4->Checksum == 0x0000)
			{
				v4->Checksum = IpChecksum(v4, IPV4_GET_HEADER_LEN(v4) * 4);
			}

			if (p->TypeL4 == L4_TCP)
			{
				// Recalculate the TCP checksum
				if (IPV4_GET_OFFSET(v4) == 0 && (IPV4_GET_FLAGS(v4) & 0x01) == 0)
				{
					// TCP checksuming doesn't target fragmented IP packets
					TCP_HEADER *tcp = p->L4.TCPHeader;

					if (tcp != NULL)
					{
						USHORT tcp_offloading_checksum1 = CalcChecksumForIPv4(v4->SrcIP, v4->DstIP, IP_PROTO_TCP, NULL, 0, p->IPv4PayloadSize);
						USHORT tcp_offloading_checksum2 = ~tcp_offloading_checksum1;

						if (tcp->Checksum == 0 || tcp->Checksum == tcp_offloading_checksum1 || tcp->Checksum == tcp_offloading_checksum2)
						{
							tcp->Checksum = 0;
							tcp->Checksum = CalcChecksumForIPv4(v4->SrcIP, v4->DstIP, IP_PROTO_TCP, tcp, p->IPv4PayloadSize, 0);
						}
					}
				}
			}

			if (p->TypeL4 == L4_UDP)
			{
				// Recalculation of the UDP checksum
				if (IPV4_GET_OFFSET(v4) == 0 || (IPV4_GET_FLAGS(v4) & 0x01) == 0)
				{
					// If it is not divided, or it is divided but it is the first fragment of the UDP packet
					UDP_HEADER *udp = p->L4.UDPHeader;

					if (udp != NULL && udp->Checksum != 0)
					{
						USHORT udp_len = Endian16(udp->PacketLength);
						USHORT udp_offloading_checksum1 = CalcChecksumForIPv4(v4->SrcIP, v4->DstIP, IP_PROTO_UDP, NULL, 0, udp_len);
						USHORT udp_offloading_checksum2 = ~udp_offloading_checksum1;

						if (udp->Checksum == udp_offloading_checksum1 || udp->Checksum == udp_offloading_checksum2)
						{
							udp->Checksum = 0;

							if ((IPV4_GET_FLAGS(v4) & 0x01) == 0 && (p->IPv4PayloadSize >= udp_len))
							{
								// Calculate the checksum correctly based on the data in case of a non-fragmented packet
								udp->Checksum = CalcChecksumForIPv4(v4->SrcIP, v4->DstIP, IP_PROTO_UDP, udp, udp_len, 0);
							}
							else
							{
								// In case of the first fragment of the packet, set the checksum to 0
								// because there isn't entire data of the packet
								udp->Checksum = 0;
							}
						}
					}
				}
			}
		}
	}
	else if (p->TypeL3 == L3_IPV6)
	{
		IPV6_HEADER *v6 = p->L3.IPv6Header;
		IPV6_HEADER_PACKET_INFO *v6info = &p->IPv6HeaderPacketInfo;

		if (v6 != NULL)
		{
			if (p->TypeL4 == L4_TCP)
			{
				// Recalculate the TCP checksum
				if (v6info->IsFragment == false)
				{
					if (v6info->FragmentHeader == NULL || ((IPV6_GET_FLAGS(v6info->FragmentHeader) & IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS) == 0))
					{
						// TCP checksuming doesn't target fragmented packets
						TCP_HEADER *tcp = p->L4.TCPHeader;

						if (tcp != NULL)
						{
							USHORT tcp_offloading_checksum1 = CalcChecksumForIPv6(&v6->SrcAddress, &v6->DestAddress, IP_PROTO_TCP, NULL, 0, v6info->PayloadSize);
							USHORT tcp_offloading_checksum2 = ~tcp_offloading_checksum1;

							if (tcp->Checksum == 0 || tcp->Checksum == tcp_offloading_checksum1 || tcp->Checksum == tcp_offloading_checksum2)
							{
								tcp->Checksum = 0;
								tcp->Checksum = CalcChecksumForIPv6(&v6->SrcAddress, &v6->DestAddress, IP_PROTO_TCP, tcp, v6info->PayloadSize, 0);
							}
						}
					}
				}
			}
			else if (p->TypeL4 == L4_UDP)
			{
				// Recalculation of the UDP checksum
				if (v6info->IsFragment == false)
				{
					UDP_HEADER *udp = p->L4.UDPHeader;

					if (udp != NULL && udp->Checksum != 0)
					{
						USHORT udp_len = Endian16(udp->PacketLength);
						USHORT udp_offloading_checksum1 = CalcChecksumForIPv6(&v6->SrcAddress, &v6->DestAddress, IP_PROTO_UDP, NULL, 0, udp_len);
						USHORT udp_offloading_checksum2 = ~udp_offloading_checksum1;

						if (udp->Checksum == udp_offloading_checksum1 || udp->Checksum == udp_offloading_checksum2)
						{
							udp->Checksum = 0;

							if ((v6info->FragmentHeader == NULL || ((IPV6_GET_FLAGS(v6info->FragmentHeader) & IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS) == 0)) && (v6info->PayloadSize >= udp_len))
							{
								// If the packet is not fragmented, recalculate the checksum
								udp->Checksum = CalcChecksumForIPv6(&v6->SrcAddress, &v6->DestAddress, IP_PROTO_UDP, udp, udp_len, 0);
							}
							else
							{
								// Don't do (can't do) anything in the case of fragmented packet
							}
						}
					}
				}
			}
		}
	}
}


// Parse the HTTPS access log
HTTPLOG *ParseHttpsAccessLog(PKT *pkt)
{
	HTTPLOG h;
	char sni[MAX_PATH];
	// Validate arguments
	if (pkt == NULL)
	{
		return NULL;
	}

	if (GetSniNameFromSslPacket(pkt->Payload, pkt->PayloadSize, sni, sizeof(sni)) == false)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));

	StrCpy(h.Method, sizeof(h.Method), "SSL_Connect");
	StrCpy(h.Hostname, sizeof(h.Hostname), sni);
	h.Port = Endian16(pkt->L4.TCPHeader->DstPort);
	StrCpy(h.Path, sizeof(h.Path), "/");
	h.IsSsl = true;

	return Clone(&h, sizeof(h));
}

// Parse the HTTP access log
HTTPLOG *ParseHttpAccessLog(PKT *pkt)
{
	HTTPLOG h;
	UCHAR *buf;
	UINT size;
	BUF *b;
	char *line1;
	bool ok = false;
	// Validate arguments
	if (pkt == NULL)
	{
		return NULL;
	}

	buf = pkt->Payload;
	size = pkt->PayloadSize;

	if (size <= 5)
	{
		return NULL;
	}

	// Check whether it starts with the HTTP-specific string
	if (CmpCaseIgnore(buf, "GET ", 4) != 0 &&
	        CmpCaseIgnore(buf, "HEAD ", 5) != 0 &&
	        CmpCaseIgnore(buf, "POST ", 5) != 0)
	{
		return NULL;
	}

	Zero(&h, sizeof(h));

	h.Port = Endian16(pkt->L4.TCPHeader->DstPort);

	b = NewBuf();
	WriteBuf(b, buf, size);
	SeekBuf(b, 0, 0);

	line1 = CfgReadNextLine(b);

	if (line1 != NULL)
	{
		TOKEN_LIST *tokens = ParseToken(line1, " \t");
		if (tokens != NULL)
		{
			if (tokens->NumTokens == 3)
			{
				StrCpy(h.Method, sizeof(h.Hostname), tokens->Token[0]);
				Trim(h.Method);

				StrCpy(h.Path, sizeof(h.Path), tokens->Token[1]);
				Trim(h.Path);

				StrCpy(h.Protocol, sizeof(h.Protocol), tokens->Token[2]);
				Trim(h.Protocol);

				StrUpper(h.Method);

				while (true)
				{
					char *line = CfgReadNextLine(b);
					UINT i;

					if (line == NULL)
					{
						break;
					}

					i = SearchStr(line, ":", 0);
					if (i != INFINITE && i < (MAX_SIZE / 2))
					{
						char name[MAX_SIZE];
						char value[MAX_SIZE];

						StrCpy(name, sizeof(name), line);
						name[i] = 0;
						Trim(name);

						StrCpy(value, sizeof(value), line + i + 1);
						Trim(value);

						if (StrCmpi(name, "host") == 0)
						{
							StrCpy(h.Hostname, sizeof(h.Hostname), value);
						}
						else if (StrCmpi(name, "referer") == 0)
						{
							StrCpy(h.Referer, sizeof(h.Referer), value);
						}
						else if (StrCmpi(name, "user-agent") == 0)
						{
							StrCpy(h.UserAgent, sizeof(h.UserAgent), value);
						}
					}

					Free(line);
				}

				if (IsEmptyStr(h.Hostname) == false)
				{
					ok = true;
				}
			}
			FreeToken(tokens);
		}
	}

	Free(line1);
	FreeBuf(b);

	if (ok)
	{
		return Clone(&h, sizeof(h));
	}
	else
	{
		return NULL;
	}
}


// Layer-2 parsing
bool ParsePacketL2Ex(PKT *p, UCHAR *buf, UINT size, bool no_l3, bool no_l3_l4_except_icmpv6)
{
	UINT i;
	bool b1, b2;
	USHORT type_id_16;
	// Validate arguments
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// Check the size
	if (size < sizeof(MAC_HEADER))
	{
		return false;
	}

	// MAC header
	p->MacHeader = (MAC_HEADER *)buf;

	buf += sizeof(MAC_HEADER);
	size -= sizeof(MAC_HEADER);

	// Analysis of the MAC header
	p->BroadcastPacket = true;
	b1 = true;
	b2 = true;
	for (i = 0; i < 6; i++)
	{
		if (p->MacHeader->DestAddress[i] != 0xff)
		{
			p->BroadcastPacket = false;
		}
		if (p->MacHeader->SrcAddress[i] != 0xff)
		{
			b1 = false;
		}
		if (p->MacHeader->SrcAddress[i] != 0x00)
		{
			b2 = false;
		}
	}
	if (b1 || b2 || (Cmp(p->MacHeader->SrcAddress, p->MacHeader->DestAddress, 6) == 0))
	{
		p->InvalidSourcePacket = true;
	}
	else
	{
		p->InvalidSourcePacket = false;
	}

	if (p->MacHeader->DestAddress[0] & 0x01)
	{
		p->BroadcastPacket = true;
	}

	// Parse L3 packet
	type_id_16 = Endian16(p->MacHeader->Protocol);

	if (type_id_16 > 1500)
	{
		// Ordinary Ethernet frame
		switch (type_id_16)
		{
		case MAC_PROTO_ARPV4:	// ARPv4
			if (no_l3 || no_l3_l4_except_icmpv6)
			{
				return true;
			}

			return ParsePacketARPv4(p, buf, size);

		case MAC_PROTO_IPV4:	// IPv4
			if (no_l3 || no_l3_l4_except_icmpv6)
			{
				return true;
			}

			return ParsePacketIPv4(p, buf, size);

		case MAC_PROTO_IPV6:	// IPv6
			if (no_l3)
			{
				return true;
			}

			return ParsePacketIPv6(p, buf, size, no_l3_l4_except_icmpv6);

		default:				// Unknown
			if (type_id_16 == p->VlanTypeID)
			{
				// VLAN
				return ParsePacketTAGVLAN(p, buf, size);
			}
			else
			{
				return true;
			}
		}
	}
	else
	{
		// Old IEEE 802.3 frame (payload length of the packet is written in the header)
		// (It has been used in the BPDU, etc.)
		UINT length = (UINT)type_id_16;
		LLC_HEADER *llc;

		// Check whether the length is remaining
		if (size < length || size < sizeof(LLC_HEADER))
		{
			return true;
		}

		// Read an LLC header
		llc = (LLC_HEADER *)buf;
		buf += sizeof(LLC_HEADER);
		size -= sizeof(LLC_HEADER);

		// Determine the protocol by the value of DSAP and SSAP
		if (llc->Dsap == LLC_DSAP_BPDU && llc->Ssap == LLC_SSAP_BPDU)
		{
			// This is a BPDU (Spanning Tree)
			return ParsePacketBPDU(p, buf, size);
		}
		else
		{
			// Unknown protocol
			return true;
		}
	}
}

// TAG VLAN parsing
bool ParsePacketTAGVLAN(PKT *p, UCHAR *buf, UINT size)
{
	USHORT vlan_ushort;
	// Validate arguments
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// Check the size
	if (size < sizeof(TAGVLAN_HEADER))
	{
		return false;
	}

	// TAG VLAN header
	p->L3.TagVlanHeader = (TAGVLAN_HEADER *)buf;
	p->TypeL3 = L3_TAGVLAN;

	buf += sizeof(TAGVLAN_HEADER);
	size -= sizeof(TAGVLAN_HEADER);

	vlan_ushort = READ_USHORT(p->L3.TagVlanHeader->Data);
	vlan_ushort = vlan_ushort & 0xFFF;

	p->VlanId = vlan_ushort;

	return true;
}

// BPDU Parsing
bool ParsePacketBPDU(PKT *p, UCHAR *buf, UINT size)
{
	// Validate arguments
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// Check the size
	if (size < sizeof(BPDU_HEADER))
	{
		return true;
	}

	// BPDU header
	p->L3.BpduHeader = (BPDU_HEADER *)buf;
	p->TypeL3 = L3_BPDU;

	buf += sizeof(BPDU_HEADER);
	size -= sizeof(BPDU_HEADER);

	return true;
}

// ARPv4 Parsing
bool ParsePacketARPv4(PKT *p, UCHAR *buf, UINT size)
{
	// Validate arguments
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// Check the size
	if (size < sizeof(ARPV4_HEADER))
	{
		return false;
	}

	// ARPv4 header
	p->L3.ARPv4Header = (ARPV4_HEADER *)buf;
	p->TypeL3 = L3_ARPV4;

	buf += sizeof(ARPV4_HEADER);
	size -= sizeof(ARPV4_HEADER);

	return true;
}

// Analysis of the IPv6 extension header
bool ParseIPv6ExtHeader(IPV6_HEADER_PACKET_INFO *info, UCHAR next_header, UCHAR *buf, UINT size)
{
	bool ret = false;
	IPV6_OPTION_HEADER *option_header;
	UINT option_header_size;
	UCHAR next_header_2 = IPV6_HEADER_NONE;
	// Validate arguments
	if (info == NULL || buf == NULL)
	{
		return false;
	}

	info->IsFragment = false;

	while (true)
	{
		if (size > 8)
		{
			next_header_2 = *((UCHAR *)buf);
		}

		switch (next_header)
		{
		case IPV6_HEADER_HOP:
		case IPV6_HEADER_ENDPOINT:
		case IPV6_HEADER_ROUTING:
			// Variable-length header
			if (size < 8)
			{
				return false;
			}

			option_header = (IPV6_OPTION_HEADER *)buf;
			option_header_size = (option_header->Size + 1) * 8;
			if (size < option_header_size)
			{
				return false;
			}

			switch (next_header)
			{
			case IPV6_HEADER_HOP:
				info->HopHeader = (IPV6_OPTION_HEADER *)buf;
				info->HopHeaderSize = option_header_size;
				break;

			case IPV6_HEADER_ENDPOINT:
				info->EndPointHeader = (IPV6_OPTION_HEADER *)buf;
				info->EndPointHeaderSize = option_header_size;
				break;

			case IPV6_HEADER_ROUTING:
				info->RoutingHeader = (IPV6_OPTION_HEADER *)buf;
				info->RoutingHeaderSize = option_header_size;
				break;
			}

			buf += option_header_size;
			size -= option_header_size;
			break;

		case IPV6_HEADER_FRAGMENT:
			// Fragment header (fixed length)
			if (size < sizeof(IPV6_FRAGMENT_HEADER))
			{
				return false;
			}

			info->FragmentHeader = (IPV6_FRAGMENT_HEADER *)buf;

			if (IPV6_GET_FRAGMENT_OFFSET(info->FragmentHeader) != 0)
			{
				info->IsFragment = true;
			}

			buf += sizeof(IPV6_FRAGMENT_HEADER);
			size -= sizeof(IPV6_FRAGMENT_HEADER);
			break;

		default:
			// Considered that the payload follows
			if (next_header != IPV6_HEADER_NONE)
			{
				info->Payload = buf;
				info->PayloadSize = size;
			}
			else
			{
				info->Payload = NULL;
				info->PayloadSize = 0;
			}
			info->Protocol = next_header;
			return true;
		}

		next_header = next_header_2;
	}
}

// Analysis of the IPv6 header
bool ParsePacketIPv6Header(IPV6_HEADER_PACKET_INFO *info, UCHAR *buf, UINT size)
{
	// Validate arguments
	if (info == NULL || buf == NULL)
	{
		Zero(info, sizeof(IPV6_HEADER_PACKET_INFO));
		return false;
	}

	Zero(info, sizeof(IPV6_HEADER_PACKET_INFO));

	// IPv6 header
	if (size < sizeof(IPV6_HEADER))
	{
		// Invalid size
		return false;
	}

	info->IPv6Header = (IPV6_HEADER *)buf;
	buf += sizeof(IPV6_HEADER);
	size -= sizeof(IPV6_HEADER);

	if (IPV6_GET_VERSION(info->IPv6Header) != 6)
	{
		// Invalid version
		return false;
	}

	// Analysis of the extension header
	if (ParseIPv6ExtHeader(info, info->IPv6Header->NextHeader, buf, size) == false)
	{
		return false;
	}

	// Record the header size
	if (info->Payload != NULL)
	{
		info->TotalHeaderSize = (UINT)((UINT64)(info->Payload) - (UINT64)(info->IPv6Header));
	}

	return true;
}

// Analyse the options of ICMPv6 packet
bool ParseICMPv6Options(ICMPV6_OPTION_LIST *o, UCHAR *buf, UINT size)
{
	// Validate arguments
	if (o == NULL || buf == NULL)
	{
		return false;
	}

	Zero(o, sizeof(ICMPV6_OPTION_LIST));

	// Read the header part
	while (true)
	{
		ICMPV6_OPTION *option_header;
		UINT header_total_size;
		UCHAR *header_pointer;
		if (size < sizeof(ICMPV6_OPTION))
		{
			// Size shortage
			return true;
		}

		option_header = (ICMPV6_OPTION *)buf;
		// Calculate the entire header size
		header_total_size = option_header->Length * 8;
		if (header_total_size == 0)
		{
			// The size is zero
			return true;
		}
		if (size < header_total_size)
		{
			// Size shortage
			return true;
		}

		header_pointer = buf;
		buf += header_total_size;
		size -= header_total_size;

		switch (option_header->Type)
		{
		case ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER:
		case ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER:
			// Source or target link-layer option
			if (header_total_size >= sizeof(ICMPV6_OPTION_LINK_LAYER))
			{
				if (option_header->Type == ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER)
				{
					o->SourceLinkLayer = (ICMPV6_OPTION_LINK_LAYER *)header_pointer;
				}
				else
				{
					o->TargetLinkLayer = (ICMPV6_OPTION_LINK_LAYER *)header_pointer;
				}
			}
			else
			{
				// ICMPv6 packet corruption?
				return false;
			}
			break;

		case ICMPV6_OPTION_TYPE_PREFIX:
			// Prefix Information
			if (header_total_size >= sizeof(ICMPV6_OPTION_PREFIX))
			{
				UINT i;
				for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
				{
					if (o->Prefix[i] == NULL)
					{
						o->Prefix[i] = (ICMPV6_OPTION_PREFIX *)header_pointer;
						break;
					}
				}
			}
			else
			{
				// ICMPv6 packet corruption?
			}
			break;

		case ICMPV6_OPTION_TYPE_MTU:
			// MTU
			if (header_total_size >= sizeof(ICMPV6_OPTION_MTU))
			{
				o->Mtu = (ICMPV6_OPTION_MTU *)header_pointer;
			}
			else
			{
				// ICMPv6 packet corruption?
			}
			break;
		}
	}
}

// ICMPv6 parsing
bool ParseICMPv6(PKT *p, UCHAR *buf, UINT size)
{
	ICMPV6_HEADER_INFO icmp_info;
	ICMP_HEADER *icmp;
	ICMP_ECHO *echo;
	UINT msg_size;
	// Validate arguments
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	Zero(&icmp_info, sizeof(icmp_info));

	if (size < sizeof(ICMP_HEADER))
	{
		return false;
	}

	icmp = (ICMP_HEADER *)buf;
	p->L4.ICMPHeader = icmp;

	msg_size = size - sizeof(ICMP_HEADER);

	icmp_info.Type = icmp->Type;
	icmp_info.Code = icmp->Code;
	icmp_info.Data = ((UCHAR *)buf) + sizeof(ICMP_HEADER);
	icmp_info.DataSize = msg_size;

	switch (icmp_info.Type)
	{
	case ICMPV6_TYPE_ECHO_REQUEST:
	case ICMPV6_TYPE_ECHO_RESPONSE:
		// ICMP Echo Request / Response
		if (icmp_info.DataSize < sizeof(ICMP_ECHO))
		{
			return false;
		}

		echo = (ICMP_ECHO *)icmp_info.Data;

		icmp_info.EchoHeader.Identifier = Endian16(echo->Identifier);
		icmp_info.EchoHeader.SeqNo = Endian16(echo->SeqNo);
		icmp_info.EchoData = (UCHAR *)echo + sizeof(ICMP_ECHO);
		icmp_info.EchoDataSize = icmp_info.DataSize - sizeof(ICMP_ECHO);

		break;

	case ICMPV6_TYPE_ROUTER_SOLICIATION:
		// Router Solicitation
		if (icmp_info.DataSize < sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER))
		{
			return false;
		}

		icmp_info.Headers.RouterSoliciationHeader =
		    (ICMPV6_ROUTER_SOLICIATION_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER),
		                       icmp_info.DataSize - sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER)) == false)
		{
			return false;
		}

		break;

	case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
		// Router Advertisement
		if (icmp_info.DataSize < sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER))
		{
			return false;
		}

		icmp_info.Headers.RouterAdvertisementHeader =
		    (ICMPV6_ROUTER_ADVERTISEMENT_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER),
		                       icmp_info.DataSize - sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER)) == false)
		{
			return false;
		}

		break;

	case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:
		// Neighbor Solicitation
		if (icmp_info.DataSize < sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER))
		{
			return false;
		}

		icmp_info.Headers.NeighborSoliciationHeader =
		    (ICMPV6_NEIGHBOR_SOLICIATION_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER),
		                       icmp_info.DataSize - sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER)) == false)
		{
			return false;
		}

		break;

	case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
		// Neighbor Advertisement
		if (icmp_info.DataSize < sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER))
		{
			return false;
		}

		icmp_info.Headers.NeighborAdvertisementHeader =
		    (ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER *)(((UCHAR *)icmp_info.Data));

		if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER),
		                       icmp_info.DataSize - sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER)) == false)
		{
			return false;
		}

		break;
	}

	p->TypeL4 = L4_ICMPV6;
	Copy(&p->ICMPv6HeaderPacketInfo, &icmp_info, sizeof(ICMPV6_HEADER_INFO));

	return true;
}

// Release of the ICMPv6 options
void FreeCloneICMPv6Options(ICMPV6_OPTION_LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	Free(o->SourceLinkLayer);
	Free(o->TargetLinkLayer);

	for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
	{
		Free(o->Prefix[i]);
		o->Prefix[i] = NULL;
	}
	Free(o->Mtu);
}

// Clone of the ICMPv6 options
void CloneICMPv6Options(ICMPV6_OPTION_LIST *dst, ICMPV6_OPTION_LIST *src)
{
	UINT i;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	Zero(dst, sizeof(ICMPV6_OPTION_LIST));

	dst->SourceLinkLayer = Clone(src->SourceLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	dst->TargetLinkLayer = Clone(src->TargetLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
	{
		if (src->Prefix[i] != NULL)
		{
			dst->Prefix[i] = Clone(src->Prefix[i], sizeof(ICMPV6_OPTION_PREFIX));
		}
		else
		{
			break;
		}
	}
	dst->Mtu = Clone(src->Mtu, sizeof(ICMPV6_OPTION_MTU));
}

// IPv6 parsing
bool ParsePacketIPv6(PKT *p, UCHAR *buf, UINT size, bool no_l3_l4_except_icmpv6)
{
	// Validate arguments
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (ParsePacketIPv6Header(&p->IPv6HeaderPacketInfo, buf, size) == false)
	{
		return false;
	}

	p->TypeL3 = L3_IPV6;
	p->L3.IPv6Header = p->IPv6HeaderPacketInfo.IPv6Header;

	if (p->IPv6HeaderPacketInfo.Payload == NULL)
	{
		// No payload
		return true;
	}

	buf = p->IPv6HeaderPacketInfo.Payload;
	size = p->IPv6HeaderPacketInfo.PayloadSize;

	if (p->IPv6HeaderPacketInfo.IsFragment)
	{
		// This is a fragmented packet. Quit interpreting
		p->TypeL4 = L4_FRAGMENT;
		return true;
	}

	// Parse a L4 packet
	switch (p->IPv6HeaderPacketInfo.Protocol)
	{
	case IP_PROTO_ICMPV6:	// ICMPv6
		if (ParseICMPv6(p, buf, size) == false)
		{
			// Returns true also if it fails to parse ICMPv6
			return true;
		}
		else
		{
			return true;
		}

	case IP_PROTO_TCP:		// TCP
		if (no_l3_l4_except_icmpv6)
		{
			return true;
		}
		return ParseTCP(p, buf, size);

	case IP_PROTO_UDP:		// UDP
		if (no_l3_l4_except_icmpv6)
		{
			return true;
		}
		return ParseUDP(p, buf, size);

	default:				// Unknown
		return true;
	}

	return true;
}

// Parse the IPv4 by adding a dummy MAC header
PKT *ParsePacketIPv4WithDummyMacHeader(UCHAR *buf, UINT size)
{
	UCHAR *tmp;
	UINT tmp_size;
	PKT *ret;
	// Validate arguments
	if (buf == NULL)
	{
		return NULL;
	}

	tmp_size = size + 14;
	tmp = Malloc(tmp_size);
	Zero(tmp, 12);
	WRITE_USHORT(tmp + 12, MAC_PROTO_IPV4);
	Copy(tmp + 14, buf, size);

	ret = ParsePacket(tmp, tmp_size);

	if (ret == NULL)
	{
		Free(tmp);
	}

	return ret;
}

// IPv4 parsing
bool ParsePacketIPv4(PKT *p, UCHAR *buf, UINT size)
{
	UINT header_size;
	// Validate arguments
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// Check the size
	if (size < sizeof(IPV4_HEADER))
	{
		return false;
	}

	// IPv4 header
	p->L3.IPv4Header = (IPV4_HEADER *)buf;
	p->TypeL3 = L3_IPV4;

	// Check the header
	header_size = IPV4_GET_HEADER_LEN(p->L3.IPv4Header) * 4;
	if (header_size < sizeof(IPV4_HEADER) || size < header_size)
	{
		// Header size is invalid
		p->L3.IPv4Header = NULL;
		p->TypeL3= L3_UNKNOWN;
		return true;
	}

	buf += header_size;
	size -= header_size;

	p->IPv4PayloadSize = MIN(size, Endian16(p->L3.IPv4Header->TotalLength) - header_size);
	if (Endian16(p->L3.IPv4Header->TotalLength) < header_size)
	{
		p->IPv4PayloadSize = 0;
	}

	p->IPv4PayloadData = buf;

	if (IPV4_GET_OFFSET(p->L3.IPv4Header) != 0)
	{
		// Quit analysing since this is fragmented
		p->TypeL4 = L4_FRAGMENT;

		return true;
	}

	// Parse a L4 packet
	switch (p->L3.IPv4Header->Protocol)
	{
	case IP_PROTO_ICMPV4:	// ICMPv4
		return ParseICMPv4(p, buf, size);

	case IP_PROTO_UDP:		// UDP
		return ParseUDP(p, buf, size);

	case IP_PROTO_TCP:		// TCP
		return ParseTCP(p, buf, size);

	default:				// Unknown
		return true;
	}
}

// ICMPv4 parsing
bool ParseICMPv4(PKT *p, UCHAR *buf, UINT size)
{
	// Validate arguments
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// Check the size
	if (size < sizeof(ICMP_HEADER))
	{
		// Size is invalid
		return false;
	}

	// ICMPv4 header
	p->L4.ICMPHeader = (ICMP_HEADER *)buf;
	p->TypeL4 = L4_ICMPV4;

	buf += sizeof(ICMP_HEADER);
	size -= sizeof(ICMP_HEADER);

	return true;
}

// TCP parsing
bool ParseTCP(PKT *p, UCHAR *buf, UINT size)
{
	UINT header_size;
	// Validate arguments
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// Check the size
	if (size < sizeof(TCP_HEADER))
	{
		// Size is invalid
		return false;
	}

	// TCP header
	p->L4.TCPHeader = (TCP_HEADER *)buf;
	p->TypeL4 = L4_TCP;

	// Check the header size
	header_size = TCP_GET_HEADER_SIZE(p->L4.TCPHeader) * 4;
	if (header_size < sizeof(TCP_HEADER) || size < header_size)
	{
		// Header size is invalid
		p->L4.TCPHeader = NULL;
		p->TypeL4 = L4_UNKNOWN;
		return true;
	}

	buf += header_size;
	size -= header_size;

	p->Payload = buf;
	p->PayloadSize = size;

	return true;
}

// Get the next byte
UCHAR GetNextByte(BUF *b)
{
	UCHAR c = 0;
	// Validate arguments
	if (b == NULL)
	{
		return 0;
	}

	if (ReadBuf(b, &c, 1) != 1)
	{
		return 0;
	}

	return c;
}

// Interpret the DNS query
bool ParseDnsQuery(char *name, UINT name_size, void *data, UINT data_size)
{
	BUF *b;
	char tmp[257];
	bool ok = true;
	USHORT val;
	// Validate arguments
	if (name == NULL || data == NULL || data_size == 0)
	{
		return false;
	}
	StrCpy(name, name_size, "");

	b = NewBuf();
	WriteBuf(b, data, data_size);
	SeekBuf(b, 0, 0);

	while (true)
	{
		UINT next_len = (UINT)GetNextByte(b);
		if (next_len > 0)
		{
			// Read only the specified length
			Zero(tmp, sizeof(tmp));
			if (ReadBuf(b, tmp, next_len) != next_len)
			{
				ok = false;
				break;
			}
			// Append
			if (StrLen(name) != 0)
			{
				StrCat(name, name_size, ".");
			}
			StrCat(name, name_size, tmp);
		}
		else
		{
			// Read all
			break;
		}
	}

	if (ReadBuf(b, &val, sizeof(val)) != sizeof(val))
	{
		ok = false;
	}
	else
	{
		if (Endian16(val) != 0x01 && Endian16(val) != 0x0c)
		{
			ok = false;
		}
	}

	if (ReadBuf(b, &val, sizeof(val)) != sizeof(val))
	{
		ok = false;
	}
	else
	{
		if (Endian16(val) != 0x01)
		{
			ok = false;
		}
	}

	FreeBuf(b);

	if (ok == false || StrLen(name) == 0)
	{
		return false;
	}
	else
	{
		return true;
	}
}

// DNS parsing
void ParseDNS(PKT *p, UCHAR *buf, UINT size)
{
	UCHAR *query_data;
	UINT query_data_size;
	DNSV4_HEADER *dns;
	char hostname[MAX_SIZE];
	if (p == NULL|| buf == NULL)
	{
		return;
	}

	if (size < sizeof(DNSV4_HEADER))
	{
		return;
	}

	dns = (DNSV4_HEADER *)buf;

	if ((dns->Flag1 & 78) != 0 || (dns->Flag1 & 0x80) != 0)
	{
		// Illegal opcode
		return;
	}
	if (Endian16(dns->NumQuery) != 1)
	{
		// Number of queries is invalid
		return;
	}

	query_data = ((UCHAR *)dns) + sizeof(DNSV4_HEADER);
	query_data_size = size - sizeof(DNSV4_HEADER);

	// Interpret the query
	if (ParseDnsQuery(hostname, sizeof(hostname), query_data, query_data_size) == false)
	{
		// Interpretation fails
		return;
	}

	StrCpy(p->DnsQueryHost, sizeof(p->DnsQueryHost), hostname);
	p->TypeL7 = L7_DNS;
}

// UDP parsing
bool ParseUDP(PKT *p, UCHAR *buf, UINT size)
{
	USHORT src_port, dst_port;
	// Validate arguments
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	// Check the size
	if (size < sizeof(UDP_HEADER))
	{
		// Size is invalid
		return false;
	}

	// UDP header
	p->L4.UDPHeader = (UDP_HEADER *)buf;
	p->TypeL4 = L4_UDP;

	buf += sizeof(UDP_HEADER);
	size -= sizeof(UDP_HEADER);

	p->Payload = buf;
	p->PayloadSize = size;

	// Check the port number
	src_port = Endian16(p->L4.UDPHeader->SrcPort);
	dst_port = Endian16(p->L4.UDPHeader->DstPort);

	if ((src_port == 67 && dst_port == 68) ||
	        (src_port == 68 && dst_port == 67))
	{
		if (p->TypeL3 == L3_IPV4)
		{
			// A DHCP packet is found
			ParseDHCPv4(p, buf, size);

			return true;
		}
	}

	if (dst_port == 53)
	{
		ParseDNS(p, buf, size);
		return true;
	}


	if (src_port == 500 || dst_port == 500 || src_port == 4500 || dst_port == 4500)
	{
		if (p->PayloadSize >= sizeof(IKE_HEADER))
		{
			IKE_HEADER *ike_header = (IKE_HEADER *)p->Payload;

			if (ike_header->InitiatorCookie != 0 && ike_header->ResponderCookie == 0 &&
			        (ike_header->ExchangeType == IKE_EXCHANGE_TYPE_MAIN ||
			         ike_header->ExchangeType == IKE_EXCHANGE_TYPE_AGGRESSIVE))
			{
				// the IKE connection request packet is found
				p->TypeL7 = L7_IKECONN;
				p->L7.IkeHeader = ike_header;
				return true;
			}
		}
	}

	// Determine whether it's an OpenVPN UDP packet
	if (size == 14)
	{
		if (buf[0] == 0x38)
		{
			if (IsZero(buf + 9, 5))
			{
				if (IsZero(buf + 1, 8) == false)
				{
					// An OpenVPN connection request packet is found
					p->TypeL7 = L7_OPENVPNCONN;
					return true;
				}
			}
		}
	}

	return true;
}

// DHCPv4 parsing
void ParseDHCPv4(PKT *p, UCHAR *buf, UINT size)
{
	// Validate arguments
	if (p == NULL || buf == NULL)
	{
		return;
	}

	// Check the size
	if (size < sizeof(DHCPV4_HEADER))
	{
		// Size is invalid
		return;
	}

	// DHCPv4 header
	p->L7.DHCPv4Header = (DHCPV4_HEADER *)buf;
	p->TypeL7 = L7_DHCPV4;
}

// Release the memory of the packet
void FreePacket(PKT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->MacHeader != NULL)
	{
		switch (p->TypeL3)
		{
		case L3_IPV4:
			FreePacketIPv4(p);
			break;

		case L3_ARPV4:
			FreePacketARPv4(p);
			break;

		case L3_TAGVLAN:
			FreePacketTagVlan(p);
			break;
		}
	}

	if (p->HttpLog != NULL)
	{
		Free(p->HttpLog);
	}

	Free(p);
}

// Release the memory of the packet with data
void FreePacketWithData(PKT *p)
{
	void *data;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	data = p->PacketData;

	FreePacket(p);

	Free(data);
}

// Release the memory for the IPv4 packet
void FreePacketIPv4(PKT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	switch (p->TypeL4)
	{
	case L4_ICMPV4:
		FreePacketICMPv4(p);
		break;

	case L4_TCP:
		FreePacketTCPv4(p);
		break;

	case L4_UDP:
		FreePacketUDPv4(p);
		break;
	}

	p->L3.IPv4Header = NULL;
	p->TypeL3 = L3_UNKNOWN;
}

// Release the memory for the tagged VLAN packet
void FreePacketTagVlan(PKT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	p->L3.TagVlanHeader = NULL;
	p->TypeL3 = L3_UNKNOWN;
}

// Release the memory for the ARPv4 packet
void FreePacketARPv4(PKT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	p->L3.ARPv4Header = NULL;
	p->TypeL3 = L3_UNKNOWN;
}

// Release the memory of the UDPv4 packet
void FreePacketUDPv4(PKT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	switch (p->TypeL7)
	{
	case L7_DHCPV4:
		FreePacketDHCPv4(p);
		break;
	}

	p->L4.UDPHeader = NULL;
	p->TypeL4 = L4_UNKNOWN;
}

// Release the memory for the TCPv4 packet
void FreePacketTCPv4(PKT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	p->L4.TCPHeader = NULL;
	p->TypeL4 = L4_UNKNOWN;
}

// Release the memory for the ICMPv4 packet
void FreePacketICMPv4(PKT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	p->L4.ICMPHeader = NULL;
	p->TypeL4 = L4_UNKNOWN;
}

// Release the memory for the DHCPv4 packet
void FreePacketDHCPv4(PKT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	p->L7.DHCPv4Header = NULL;
	p->TypeL7 = L7_UNKNOWN;
}


// Confirm the checksum of the IP header
bool IpCheckChecksum(IPV4_HEADER *ip)
{
	UINT header_size;
	USHORT checksum_original, checksum_calc;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	header_size = IPV4_GET_HEADER_LEN(ip) * 4;
	checksum_original = ip->Checksum;
	ip->Checksum = 0;
	checksum_calc = IpChecksum(ip, header_size);
	ip->Checksum = checksum_original;

	if (checksum_original == checksum_calc)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Calculate the checksum
USHORT IpChecksum(void *buf, UINT size)
{
	int sum = 0;
	USHORT *addr = (USHORT *)buf;
	int len = (int)size;
	USHORT *w = addr;
	int nleft = len;
	USHORT answer = 0;

	while (nleft > 1)
	{
		USHORT ww = 0;
		Copy(&ww, w++, sizeof(USHORT));
		sum += ww;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(UCHAR *)(&answer) = *(UCHAR *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	answer = ~sum;

	return answer;
}

// Convert a DHCP option list into a buffer
BUF *BuildDhcpOptionsBuf(LIST *o)
{
	BUF *b;
	UINT i;
	UCHAR id;
	UCHAR sz;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	for (i = 0; i < LIST_NUM(o); i++)
	{
		DHCP_OPTION *d = LIST_DATA(o, i);
		UINT current_size = d->Size;
		UINT current_pos = 0;

		id = (UCHAR)d->Id;
		if (d->Size <= 255)
		{
			sz = (UCHAR)d->Size;
		}
		else
		{
			sz = 0xFF;
		}
		WriteBuf(b, &id, 1);
		WriteBuf(b, &sz, 1);
		WriteBuf(b, d->Data, sz);

		current_size -= sz;
		current_pos += sz;

		while (current_size != 0)
		{
			id = DHCP_ID_PRIVATE;
			if (current_size <= 255)
			{
				sz = (UCHAR)current_size;
			}
			else
			{
				sz = 0xFF;
			}
			WriteBuf(b, &id, 1);
			WriteBuf(b, &sz, 1);
			WriteBuf(b, ((UCHAR *)d->Data) + current_pos, sz);

			current_size -= sz;
			current_pos += sz;
		}

	}

	id = 0xff;
	WriteBuf(b, &id, 1);

	return b;
}

// Convert a DHCP option list to the DHCP option
LIST *BuildDhcpOption(DHCP_OPTION_LIST *opt)
{
	LIST *o;
	UCHAR opcode;
	BUF *dns_buf;
	// Validate arguments
	if (opt == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);

	// Op-code
	opcode = (UCHAR)opt->Opcode;
	Add(o, NewDhcpOption(DHCP_ID_MESSAGE_TYPE, &opcode, sizeof(opcode)));
	Add(o, NewDhcpOption(DHCP_ID_SERVER_ADDRESS, &opt->ServerAddress, sizeof(opt->ServerAddress)));

	if (opt->LeaseTime != 0)
	{
		Add(o, NewDhcpOption(DHCP_ID_LEASE_TIME, &opt->LeaseTime, sizeof(opt->LeaseTime)));
	}

	if (StrLen(opt->DomainName) != 0 && opt->DnsServer != 0)
	{
		Add(o, NewDhcpOption(DHCP_ID_DOMAIN_NAME, opt->DomainName, StrLen(opt->DomainName)));
	}
	if (opt->SubnetMask != 0)
	{
		Add(o, NewDhcpOption(DHCP_ID_SUBNET_MASK, &opt->SubnetMask, sizeof(opt->SubnetMask)));
	}
	if (opt->Gateway != 0)
	{
		Add(o, NewDhcpOption(DHCP_ID_GATEWAY_ADDR, &opt->Gateway, sizeof(opt->Gateway)));
	}

	dns_buf = NewBuf();

	if (opt->DnsServer != 0)
	{
		WriteBuf(dns_buf, &opt->DnsServer, sizeof(opt->DnsServer));
	}
	if (opt->DnsServer2 != 0)
	{
		WriteBuf(dns_buf, &opt->DnsServer2, sizeof(opt->DnsServer2));
	}

	if (dns_buf->Size >= 1)
	{
		Add(o, NewDhcpOption(DHCP_ID_DNS_ADDR, dns_buf->Buf, dns_buf->Size));
	}

	FreeBuf(dns_buf);

	if (opt->ClasslessRoute.NumExistingRoutes >= 1)
	{
		BUF *b = DhcpBuildClasslessRouteData(&opt->ClasslessRoute);

		if (b != NULL)
		{
			Add(o, NewDhcpOption(DHCP_ID_CLASSLESS_ROUTE, b->Buf, b->Size));
			Add(o, NewDhcpOption(DHCP_ID_MS_CLASSLESS_ROUTE, b->Buf, b->Size));

			FreeBuf(b);
		}
	}

	return o;
}

// Create a new DHCP option item
DHCP_OPTION *NewDhcpOption(UINT id, void *data, UINT size)
{
	DHCP_OPTION *ret;
	if (size != 0 && data == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(DHCP_OPTION));
	ret->Data = ZeroMalloc(size);
	Copy(ret->Data, data, size);
	ret->Size = size;
	ret->Id = id;

	return ret;
}

// Parse a DHCP options list
DHCP_OPTION_LIST *ParseDhcpOptionList(void *data, UINT size)
{
	DHCP_OPTION_LIST *ret;
	LIST *o;
	DHCP_OPTION *a;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	// Parse the list
	o = ParseDhcpOptions(data, size);
	if (o == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(DHCP_OPTION_LIST));

	// Get the opcode
	a = GetDhcpOption(o, DHCP_ID_MESSAGE_TYPE);
	if (a != NULL)
	{
		if (a->Size == 1)
		{
			ret->Opcode = *((UCHAR *)a->Data);
		}
	}

	switch (ret->Opcode)
	{
	case DHCP_DISCOVER:
	case DHCP_REQUEST:
		// Parse this more finely because this is client requests
		// Requested IP address
		a = GetDhcpOption(o, DHCP_ID_REQUEST_IP_ADDRESS);
		if (a != NULL && a->Size == 4)
		{
			Copy(&ret->RequestedIp, a->Data, 4);
		}
		// Host name
		a = GetDhcpOption(o, DHCP_ID_HOST_NAME);
		if (a != NULL)
		{
			if (a->Size > 1)
			{
				Copy(ret->Hostname, a->Data, MIN(a->Size, sizeof(ret->Hostname) - 1));
			}
		}
		break;

	case DHCP_OFFER:
	case DHCP_ACK:
		// Subnet mask
		a = GetDhcpOption(o, DHCP_ID_SUBNET_MASK);
		if (a != NULL && a->Size >= 4)
		{
			Copy(&ret->SubnetMask, a->Data, 4);
		}

		// Lease time
		a = GetDhcpOption(o, DHCP_ID_LEASE_TIME);
		if (a != NULL && a->Size == 4)
		{
			ret->LeaseTime = READ_UINT(a->Data);
		}

		// Server IP address
		a = GetDhcpOption(o, DHCP_ID_SERVER_ADDRESS);
		if (a != NULL && a->Size >= 4)
		{
			Copy(&ret->ServerAddress, a->Data, 4);
		}

		// Domain name
		a = GetDhcpOption(o, DHCP_ID_DOMAIN_NAME);
		if (a != NULL && a->Size >= 1)
		{
			Zero(ret->DomainName, sizeof(ret->DomainName));
			Copy(ret->DomainName, a->Data, MIN(a->Size, sizeof(ret->DomainName) - 1));
		}

		// Gateway
		a = GetDhcpOption(o, DHCP_ID_GATEWAY_ADDR);
		if (a != NULL && a->Size >= 4)
		{
			Copy(&ret->Gateway, a->Data, 4);
		}

		// DNS server
		a = GetDhcpOption(o, DHCP_ID_DNS_ADDR);
		if (a != NULL && a->Size >= 4)
		{
			Copy(&ret->DnsServer, a->Data, 4);

			if (a->Size >= 8)
			{
				Copy(&ret->DnsServer2, ((UCHAR *)a->Data) + 4, 4);
			}
		}

		// WINS server
		a = GetDhcpOption(o, DHCP_ID_WINS_ADDR);
		if (a != NULL && a->Size >= 4)
		{
			Copy(&ret->WinsServer, a->Data, 4);

			if (a->Size >= 8)
			{
				Copy(&ret->WinsServer2, ((UCHAR *)a->Data) + 4, 4);
			}
		}

		// Classless static routing table entries
		// RFC 3442
		a = GetDhcpOption(o, DHCP_ID_CLASSLESS_ROUTE);
		if (a != NULL)
		{
			DhcpParseClasslessRouteData(&ret->ClasslessRoute, a->Data, a->Size);
		}
		// Microsoft Extension
		a = GetDhcpOption(o, DHCP_ID_MS_CLASSLESS_ROUTE);
		if (a != NULL)
		{
			DhcpParseClasslessRouteData(&ret->ClasslessRoute, a->Data, a->Size);
		}

		break;
	}

	// Release the list
	FreeDhcpOptions(o);

	return ret;
}

// Normalize the classless routing table string
bool NormalizeClasslessRouteTableStr(char *dst, UINT dst_size, char *src)
{
	DHCP_CLASSLESS_ROUTE_TABLE t;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (ParseClasslessRouteTableStr(&t, src))
	{
		BuildClasslessRouteTableStr(dst, dst_size, &t);

		return true;
	}

	return false;
}

// Build the string from the classless routing table
void BuildClasslessRouteTableStr(char *str, UINT str_size, DHCP_CLASSLESS_ROUTE_TABLE *t)
{
	UINT i;
	UINT num = 0;
	ClearStr(str, str_size);
	// Validate arguments
	if (str == NULL || t == NULL)
	{
		return;
	}

	for (i = 0; i < MAX_DHCP_CLASSLESS_ROUTE_ENTRIES; i++)
	{
		DHCP_CLASSLESS_ROUTE *r = &t->Entries[i];

		if (r->Exists)
		{
			char tmp[128];

			Zero(tmp, sizeof(tmp));
			BuildClasslessRouteStr(tmp, sizeof(tmp), r);

			if (IsEmptyStr(tmp) == false)
			{
				if (num >= 1)
				{
					StrCat(str, str_size, ", ");
				}

				StrCat(str, str_size, tmp);

				num++;
			}
		}
	}
}

// Build the string from the classless routing table entry
void BuildClasslessRouteStr(char *str, UINT str_size, DHCP_CLASSLESS_ROUTE *r)
{
	ClearStr(str, str_size);
	// Validate arguments
	if (str == NULL || r == NULL || r->Exists == false)
	{
		return;
	}

	Format(str, str_size, "%r/%r/%r", &r->Network, &r->SubnetMask, &r->Gateway);
}

// Check the classless routing table string
bool CheckClasslessRouteTableStr(char *str)
{
	DHCP_CLASSLESS_ROUTE_TABLE d;

	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	return ParseClasslessRouteTableStr(&d, str);
}

// Parse the classless routing table string
bool ParseClasslessRouteTableStr(DHCP_CLASSLESS_ROUTE_TABLE *d, char *str)
{
	bool ret = true;
	TOKEN_LIST *t;
	// Validate arguments
	if (d == NULL || str == NULL)
	{
		return false;
	}

	Zero(d, sizeof(DHCP_CLASSLESS_ROUTE_TABLE));

	t = ParseTokenWithoutNullStr(str, NULL);

	if (t != NULL)
	{
		UINT i;

		for (i = 0; i < t->NumTokens; i++)
		{
			DHCP_CLASSLESS_ROUTE r;

			Zero(&r, sizeof(r));
			if (ParseClasslessRouteStr(&r, t->Token[i]))
			{
				if (d->NumExistingRoutes < MAX_DHCP_CLASSLESS_ROUTE_ENTRIES)
				{
					Copy(&d->Entries[d->NumExistingRoutes], &r, sizeof(DHCP_CLASSLESS_ROUTE));
					d->NumExistingRoutes++;
				}
				else
				{
					// Overflow
					ret = false;
					break;
				}
			}
			else
			{
				// Parse error
				ret = false;
				break;
			}
		}
	}

	FreeToken(t);

	return ret;
}

// Parse the classless routing table entry string
bool ParseClasslessRouteStr(DHCP_CLASSLESS_ROUTE *r, char *str)
{
	TOKEN_LIST *t;
	bool ret = false;
	char tmp[MAX_PATH];
	// Validate arguments
	if (r == NULL || str == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	t = ParseTokenWithoutNullStr(str, "/");
	if (t == NULL)
	{
		return false;
	}

	if (t->NumTokens == 3)
	{
		char ip_and_mask[MAX_PATH];
		char gateway[MAX_PATH];

		Zero(r, sizeof(DHCP_CLASSLESS_ROUTE));

		Format(ip_and_mask, sizeof(ip_and_mask), "%s/%s", t->Token[0], t->Token[1]);
		StrCpy(gateway, sizeof(gateway), t->Token[2]);

		if (ParseIpAndSubnetMask46(ip_and_mask, &r->Network, &r->SubnetMask))
		{
			r->SubnetMaskLen = SubnetMaskToInt4(&r->SubnetMask);

			if (StrToIP(&r->Gateway, gateway))
			{
				if (IsIP4(&r->Gateway) && IsIP4(&r->Network) && IsIP4(&r->SubnetMask))
				{
					r->Exists = true;

					IPAnd4(&r->Network, &r->Network, &r->SubnetMask);

					ret = true;
				}
			}
		}
	}

	FreeToken(t);

	return ret;
}

// Build the classless static routing table data for a DHCP message
BUF *DhcpBuildClasslessRouteData(DHCP_CLASSLESS_ROUTE_TABLE *t)
{
	BUF *b;
	UINT i;
	// Validate arguments
	if (t == NULL || t->NumExistingRoutes == 0)
	{
		return NULL;
	}

	b = NewBuf();

	for (i = 0; i < MAX_DHCP_CLASSLESS_ROUTE_ENTRIES; i++)
	{
		DHCP_CLASSLESS_ROUTE *r = &t->Entries[i];

		if (r->Exists && r->SubnetMaskLen <= 32)
		{
			UCHAR c;
			UINT data_len;
			UINT ip32;
			UCHAR tmp[4];

			// Width of subnet mask
			c = (UCHAR)r->SubnetMaskLen;
			WriteBuf(b, &c, 1);

			// Number of significant octets
			data_len = (r->SubnetMaskLen + 7) / 8;
			Zero(tmp, sizeof(tmp));
			Copy(tmp, &r->Network, data_len);
			WriteBuf(b, tmp, data_len);

			// Gateway
			ip32 = IPToUINT(&r->Gateway);
			WriteBuf(b, &ip32, sizeof(UINT));
		}
	}

	SeekBufToBegin(b);

	return b;
}

// Parse a classless static routing table entries from the DHCP message
void DhcpParseClasslessRouteData(DHCP_CLASSLESS_ROUTE_TABLE *t, void *data, UINT size)
{
	BUF *b;
	// Validate arguments
	if (t == NULL || data == NULL || size == 0)
	{
		return;
	}

	b = MemToBuf(data, size);

	while (b->Current < b->Size)
	{
		UCHAR c;
		UINT subnet_mask_len;
		UINT data_len;
		BYTE tmp[IPV4_SIZE];
		IP ip;
		IP mask;
		IP gateway;
		DHCP_CLASSLESS_ROUTE r;
		UINT ip32;
		bool exists = false;
		UINT i;

		// Subnet mask length
		c = ReadBufChar(b);
		subnet_mask_len = c;
		if (subnet_mask_len > 32)
		{
			// Invalid data
			break;
		}

		data_len = (subnet_mask_len + 7) / 8;

		Zero(tmp, sizeof(tmp));
		if (ReadBuf(b, tmp, data_len) != data_len)
		{
			// Invalid data
			break;
		}

		// IP address body
		ZeroIP4(&ip);
		Copy(IPV4(ip.address), tmp, sizeof(tmp));

		Zero(&mask, sizeof(mask));
		IntToSubnetMask4(&mask, subnet_mask_len);

		// Gateway address
		Zero(&gateway, sizeof(gateway));
		if (ReadBuf(b, &ip32, sizeof(UINT)) != sizeof(UINT))
		{
			// Invalid data
			break;
		}
		UINTToIP(&gateway, ip32);

		Zero(&r, sizeof(r));
		r.Exists = true;
		Copy(&r.Gateway, &gateway, sizeof(IP));
		Copy(&r.Network, &ip, sizeof(IP));
		Copy(&r.SubnetMask, &mask, sizeof(IP));
		r.SubnetMaskLen = subnet_mask_len;

		for (i = 0; i < MAX_DHCP_CLASSLESS_ROUTE_ENTRIES; i++)
		{
			if (Cmp(&t->Entries[i], &r, sizeof(DHCP_CLASSLESS_ROUTE)) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			if (t->NumExistingRoutes >= MAX_DHCP_CLASSLESS_ROUTE_ENTRIES)
			{
				// Overflow
				break;
			}

			Copy(&t->Entries[t->NumExistingRoutes], &r, sizeof(DHCP_CLASSLESS_ROUTE));
			t->NumExistingRoutes++;
		}
	}

	FreeBuf(b);
}

// Finding a DHCP option
DHCP_OPTION *GetDhcpOption(LIST *o, UINT id)
{
	UINT i;
	DHCP_OPTION *ret = NULL;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		DHCP_OPTION *opt = LIST_DATA(o, i);
		if (opt->Id == id)
		{
			ret = opt;
		}
	}

	return ret;
}

// Get the best classless routing table entry from the routing table
DHCP_CLASSLESS_ROUTE *GetBestClasslessRoute(DHCP_CLASSLESS_ROUTE_TABLE *t, IP *ip)
{
	DHCP_CLASSLESS_ROUTE *ret = NULL;
	UINT i;
	UINT max_mask = 0;
	// Validate arguments
	if (t == NULL || ip == NULL)
	{
		return NULL;
	}
	if (t->NumExistingRoutes == 0)
	{
		return NULL;
	}

	for (i = 0; i < MAX_DHCP_CLASSLESS_ROUTE_ENTRIES; i++)
	{
		DHCP_CLASSLESS_ROUTE *e = &t->Entries[i];

		if (e->Exists)
		{
			if (IsInSameNetwork4(ip, &e->Network, &e->SubnetMask))
			{
				if (max_mask <= e->SubnetMaskLen)
				{
					max_mask = e->SubnetMaskLen;
					ret = e;
				}
			}
		}
	}

	return ret;
}

// Release the DHCP option
void FreeDhcpOptions(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		DHCP_OPTION *opt = LIST_DATA(o, i);
		Free(opt->Data);
		Free(opt);
	}

	ReleaseList(o);
}

// Parse the DHCP Options
LIST *ParseDhcpOptions(void *data, UINT size)
{
	BUF *b;
	LIST *o;
	DHCP_OPTION *last_opt;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, data, size);
	SeekBuf(b, 0, 0);

	o = NewListFast(NULL);

	last_opt = NULL;

	while (true)
	{
		UCHAR c = 0;
		UCHAR sz = 0;
		DHCP_OPTION *opt;
		if (ReadBuf(b, &c, 1) != 1)
		{
			break;
		}
		if (c == 0xff)
		{
			break;
		}
		if (ReadBuf(b, &sz, 1) != 1)
		{
			break;
		}

		if (c == DHCP_ID_PRIVATE && last_opt != NULL)
		{
			UINT new_size = last_opt->Size + (UINT)sz;
			UCHAR *new_buf = ZeroMalloc(new_size);
			Copy(new_buf, last_opt->Data, last_opt->Size);
			ReadBuf(b, new_buf + last_opt->Size, sz);
			Free(last_opt->Data);
			last_opt->Data = new_buf;
			last_opt->Size = new_size;
		}
		else
		{
			opt = ZeroMalloc(sizeof(DHCP_OPTION));
			opt->Id = (UINT)c;
			opt->Size = (UINT)sz;
			opt->Data = ZeroMalloc((UINT)sz);
			ReadBuf(b, opt->Data, sz);
			Add(o, opt);

			last_opt = opt;
		}
	}

	FreeBuf(b);

	return o;
}

// Rewrite the DHCP message data in the requested IPv4 packet appropriately
BUF *DhcpModifyIPv4(DHCP_MODIFY_OPTION *m, void *data, UINT size)
{
	PKT *p;
	BUF *ret = NULL;
	// Validate arguments
	if (m == NULL || data == NULL || size == 0)
	{
		return NULL;
	}

	p = ParsePacketEx4(data, size, false, 0, false, false, false);

	if (p != NULL && p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4)
	{
		BUF *new_buf = DhcpModify(m, p->Payload, p->PayloadSize);

		if (new_buf != NULL)
		{
			ret = NewBuf();

			WriteBuf(ret, p->PacketData, p->PacketSize - p->PayloadSize);
			WriteBuf(ret, new_buf->Buf, new_buf->Size);

			FreeBuf(new_buf);
		}
	}

	FreePacket(p);

	if (ret != NULL)
	{
		PKT *p = ParsePacketEx4(ret->Buf, ret->Size, false, 0, false, false, false);

		if (p != NULL)
		{
			// Recalculation of the UDP checksum
			if (p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP)
			{
				UDP_HEADER *udp = p->L4.UDPHeader;

				udp->Checksum = 0;
				udp->Checksum = CalcChecksumForIPv4(p->L3.IPv4Header->SrcIP,
				                                    p->L3.IPv4Header->DstIP,
				                                    IP_PROTO_UDP,
				                                    udp,
				                                    p->PacketSize - (UINT)(((UCHAR *)udp) - ((UCHAR *)p->PacketData)), 0);
			}

			FreePacket(p);
		}
	}

	return ret;
}

// Rewrite the DHCP packet appropriately
BUF *DhcpModify(DHCP_MODIFY_OPTION *m, void *data, UINT size)
{
	DHCPV4_HEADER *dhcp_header;
	UCHAR *data_ptr;
	bool ret_ok = false;
	BUF *ret = NULL;
	BUF *opt_buf = NULL;
	UINT magic_cookie = Endian32(DHCP_MAGIC_COOKIE);
	bool ok = false;
	DHCP_OPTION_LIST *opt = NULL;
	LIST *opt_list = NULL;
	LIST *opt_list2 = NULL;
	UINT src_size = size;
	UINT i;
	// Validate arguments
	if (m == NULL || data == NULL || size == 0)
	{
		return NULL;
	}

	data_ptr = (UCHAR *)data;

	if (size < sizeof(DHCPV4_HEADER))
	{
		goto LABEL_CLEANUP;
	}

	dhcp_header = (DHCPV4_HEADER *)data_ptr;
	data_ptr += sizeof(DHCPV4_HEADER);

	// Search for a Magic Cookie
	while (size >= 5)
	{
		if (Cmp(data_ptr, &magic_cookie, sizeof(UINT)) == 0)
		{
			// Found
			data_ptr += sizeof(UINT);
			size -= sizeof(UINT);
			ok = true;
			break;
		}

		data_ptr++;
		size--;
	}

	if (ok == false)
	{
		// The packet is invalid
		goto LABEL_CLEANUP;
	}

	ret = NewBuf();
	WriteBuf(ret, data, (UINT)(data_ptr - ((UCHAR *)data)));

	// Parse the DHCP options list
	opt = ParseDhcpOptionList(data_ptr, size);
	if (opt == NULL)
	{
		// The packet is invalid
		goto LABEL_CLEANUP;
	}

	opt_list = ParseDhcpOptions(data_ptr, size);
	if (opt_list == NULL)
	{
		// The packet is invalid
		goto LABEL_CLEANUP;
	}

	// Rebuilding the options list
	opt_list2 = NewListFast(NULL);

	for (i = 0; i < LIST_NUM(opt_list); i++)
	{
		DHCP_OPTION *o = LIST_DATA(opt_list, i);
		DHCP_OPTION *o2 = NULL;
		bool ok = true;

		if (m->RemoveDefaultGatewayOnReply)
		{
			if (opt->Opcode == DHCP_OFFER || opt->Opcode == DHCP_ACK)
			{
				// Remove the default gateway from the DHCP Reply
				if (o->Id == DHCP_ID_GATEWAY_ADDR)
				{
					ok = false;
				}
				if (o->Id == DHCP_ID_DNS_ADDR || o->Id == DHCP_ID_WINS_ADDR || o->Id == DHCP_ID_DOMAIN_NAME)
				{
					ok = false;
				}
			}
		}

		if (ok)
		{
			o2 = NewDhcpOption(o->Id, o->Data, o->Size);
			if (o2 != NULL)
			{
				Add(opt_list2, o2);
			}

		}

	}

	opt_buf = BuildDhcpOptionsBuf(opt_list2);

	WriteBuf(ret, opt_buf->Buf, opt_buf->Size);

	if (src_size != ret->Size || Cmp(data, ret->Buf, ret->Size) != 0)
	{
		// Rewrite if anything changes. Do not rewrite if there is no change
		ret_ok = true;

		if (ret->Size < DHCP_MIN_SIZE)
		{
			// Padding
			UCHAR *pad_buf;
			UINT pad_size = DHCP_MIN_SIZE - ret->Size;

			pad_buf = ZeroMalloc(pad_size);

			WriteBuf(ret, pad_buf, pad_size);

			Free(pad_buf);
		}
	}

LABEL_CLEANUP:
	// Memory release
	if (opt_buf != NULL)
	{
		FreeBuf(opt_buf);
	}

	if (opt != NULL)
	{
		Free(opt);
	}

	if (opt_list != NULL)
	{
		FreeDhcpOptions(opt_list);
	}

	if (opt_list2 != NULL)
	{
		FreeDhcpOptions(opt_list2);
	}

	// Return a value
	if (ret_ok)
	{
		return ret;
	}
	else
	{
		FreeBuf(ret);
		return NULL;
	}
}
