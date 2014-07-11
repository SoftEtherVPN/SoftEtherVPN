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


// IPsec_IKE.c
// IKE (ISAKMP) and ESP protocol stack

#include "CedarPch.h"


// Processing of IKE received packet
void ProcIKEPacketRecv(IKE_SERVER *ike, UDPPACKET *p)
{
	// Validate arguments
	if (ike == NULL || p == NULL)
	{
		return;
	}

	if (p->Type == IKE_UDP_TYPE_ISAKMP)
	{
		// ISAKMP (IKE) packet
		IKE_PACKET *header;

		header = ParseIKEPacketHeader(p);
		if (header == NULL)
		{
			return;
		}

		//Debug("InitiatorCookie: %I64u, ResponderCookie: %I64u\n", header->InitiatorCookie, header->ResponderCookie);

		switch (header->ExchangeType)
		{
		case IKE_EXCHANGE_TYPE_MAIN:	// Main mode
			ProcIkeMainModePacketRecv(ike, p, header);
			break;

		case IKE_EXCHANGE_TYPE_AGGRESSIVE:	// Aggressive mode
			ProcIkeAggressiveModePacketRecv(ike, p, header);
			break;

		case IKE_EXCHANGE_TYPE_QUICK:	// Quick mode
			ProcIkeQuickModePacketRecv(ike, p, header);
			break;

		case IKE_EXCHANGE_TYPE_INFORMATION:	// Information exchange
			ProcIkeInformationalExchangePacketRecv(ike, p, header);
			break;
		}

		IkeFree(header);
	}
	else if (p->Type == IKE_UDP_TYPE_ESP)
	{
		// ESP packet
		ProcIPsecEspPacketRecv(ike, p);
	}
}

// Send a packet via IPsec
void IPsecSendPacketByIPsecSa(IKE_SERVER *ike, IPSECSA *sa, UCHAR *data, UINT data_size, UCHAR protocol_id)
{
	bool is_tunnel_mode;
	IKE_CLIENT *c;
	// Validate arguments
	if (ike == NULL || sa == NULL || data == NULL || data_size == 0)
	{
		return;
	}

	is_tunnel_mode = IsIPsecSaTunnelMode(sa);

	c = sa->IkeClient;

	if (c == NULL)
	{
		return;
	}

	if (is_tunnel_mode)
	{
		// Add an IPv4 / IPv6 header in the case of tunnel mode
		if (IsZeroIP(&c->TunnelModeClientIP) == false || IsZeroIP(&c->TunnelModeServerIP) == false)
		{
			BUF *b;
			UCHAR esp_proto_id;

			b = NewBuf();

			if (IsIP4(&c->TunnelModeClientIP))
			{
				// IPv4 header
				IPV4_HEADER h;

				h.VersionAndHeaderLength = 0;
				h.TypeOfService = 0;
				IPV4_SET_VERSION(&h, 4);
				IPV4_SET_HEADER_LEN(&h, sizeof(IPV4_HEADER) / 4);
				h.TotalLength = Endian16((USHORT)(data_size + sizeof(IPV4_HEADER)));
				h.Identification = Endian16(c->TunnelSendIpId++);
				h.FlagsAndFlagmentOffset[0] = h.FlagsAndFlagmentOffset[1] = 0;
				h.TimeToLive = DEFAULT_IP_TTL;
				h.Protocol = protocol_id;
				h.SrcIP = IPToUINT(&c->TunnelModeServerIP);
				h.DstIP = IPToUINT(&c->TunnelModeClientIP);
				h.Checksum = 0;
				h.Checksum = IpChecksum(&h, sizeof(IPV4_HEADER));

				WriteBuf(b, &h, sizeof(IPV4_HEADER));

				esp_proto_id = IKE_PROTOCOL_ID_IPV4;
			}
			else
			{
				// IPv6 header
				IPV6_HEADER h;

				Zero(&h, sizeof(h));
				h.VersionAndTrafficClass1 = 0;
				IPV6_SET_VERSION(&h, 6);
				h.TrafficClass2AndFlowLabel1 = 0;
				h.FlowLabel2 = h.FlowLabel3 = 0;
				h.PayloadLength = Endian16(data_size);
				h.NextHeader = protocol_id;
				h.HopLimit = 64;
				Copy(h.SrcAddress.Value, c->TunnelModeServerIP.ipv6_addr, 16);
				Copy(h.DestAddress.Value, c->TunnelModeClientIP.ipv6_addr, 16);

				WriteBuf(b, &h, sizeof(IPV6_HEADER));

				esp_proto_id = IKE_PROTOCOL_ID_IPV6;
			}

			WriteBuf(b, data, data_size);

			IPsecSendPacketByIPsecSaInner(ike, sa, b->Buf, b->Size, esp_proto_id);

			FreeBuf(b);
		}
	}
	else
	{
		// Send as it is in the case of transport mode
		IPsecSendPacketByIPsecSaInner(ike, sa, data, data_size, protocol_id);
	}
}
void IPsecSendPacketByIPsecSaInner(IKE_SERVER *ike, IPSECSA *sa, UCHAR *data, UINT data_size, UCHAR protocol_id)
{
	UINT esp_size;
	UINT encrypted_payload_size;
	UCHAR *esp;
	UINT i;
	UINT size_of_padding;
	IKE_CRYPTO_PARAM cp;
	BUF *enc;
	IKE_CLIENT *c;
	// Validate arguments
	if (ike == NULL || sa == NULL || data == NULL || data_size == 0)
	{
		return;
	}

	c = sa->IkeClient;
	if (c == NULL)
	{
		return;
	}

	// Calculate the payload size after encryption
	encrypted_payload_size = data_size + 2;
	if ((encrypted_payload_size % sa->TransformSetting.Crypto->BlockSize) != 0)
	{
		encrypted_payload_size = ((encrypted_payload_size / sa->TransformSetting.Crypto->BlockSize) + 1) * sa->TransformSetting.Crypto->BlockSize;
	}
	size_of_padding = encrypted_payload_size - data_size - 2;

	// Calculate the size of the ESP packet
	esp_size = sizeof(UINT) * 2 + sa->TransformSetting.Crypto->BlockSize + encrypted_payload_size + IKE_ESP_HASH_SIZE;

	// Build the ESP packet
	esp = Malloc(esp_size + IKE_MAX_HASH_SIZE);

	// SPI
	WRITE_UINT(esp, sa->Spi);

	// Sequence number
	sa->CurrentSeqNo++;
	WRITE_UINT(esp + sizeof(UINT), sa->CurrentSeqNo);

	// IV
	Copy(esp + sizeof(UINT) * 2, sa->EspIv, sa->TransformSetting.Crypto->BlockSize);

	// Payload data
	Copy(esp + sizeof(UINT) * 2 + sa->TransformSetting.Crypto->BlockSize, data, data_size);

	// Padding
	for (i = 0;i < size_of_padding;i++)
	{
		esp[sizeof(UINT) * 2 + sa->TransformSetting.Crypto->BlockSize + data_size + i] = (UCHAR)(i + 1);
	}

	// Padding length
	esp[sizeof(UINT) * 2 + sa->TransformSetting.Crypto->BlockSize + data_size + size_of_padding] = (UCHAR)size_of_padding;

	// Next header number
	esp[sizeof(UINT) * 2 + sa->TransformSetting.Crypto->BlockSize + data_size + size_of_padding + 1] = protocol_id;

	// Encryption
	Copy(cp.Iv, sa->EspIv, sa->TransformSetting.Crypto->BlockSize);
	cp.Key = sa->CryptoKey;

	enc = IkeEncrypt(esp + sizeof(UINT) * 2 + sa->TransformSetting.Crypto->BlockSize, encrypted_payload_size, &cp);
	if (enc != NULL)
	{
		bool start_qm = false;
		UINT server_port = c->ServerPort;
		UINT client_port = c->ClientPort;

		// Overwrite the encrypted result
		Copy(esp + sizeof(UINT) * 2 + sa->TransformSetting.Crypto->BlockSize, enc->Buf, encrypted_payload_size);

		FreeBuf(enc);

		// Calculate the HMAC
		IkeHMac(sa->TransformSetting.Hash,
			esp + sizeof(UINT) * 2 + sa->TransformSetting.Crypto->BlockSize + encrypted_payload_size,
			sa->HashKey,
			sa->TransformSetting.Hash->HashSize,
			esp,
			sizeof(UINT) * 2 + sa->TransformSetting.Crypto->BlockSize + encrypted_payload_size);

		//*(UCHAR *)(esp + sizeof(UINT) * 2 + sa->TransformSetting.Crypto->BlockSize + encrypted_payload_size) = 0xff;

		if (sa->TransformSetting.CapsuleMode == IKE_P2_CAPSULE_TRANSPORT ||
			sa->TransformSetting.CapsuleMode == IKE_P2_CAPSULE_TUNNEL)
		{
			server_port = client_port = IPSEC_PORT_IPSEC_ESP_RAW;
		}

		// Add the completed packet to the transmission list
		IkeSendUdpPacket(ike, IKE_UDP_TYPE_ESP, &c->ServerIP, server_port, &c->ClientIP, client_port,
			esp, esp_size);

		// Feedback the IV
		Copy(sa->EspIv, cp.NextIv, sa->TransformSetting.Crypto->BlockSize);

		sa->TotalSize += esp_size;

		if (sa->CurrentSeqNo >= 0xf0000000)
		{
			start_qm = true;
		}

		if (sa->TransformSetting.LifeKilobytes != 0)
		{
			UINT64 hard_size = (UINT64)sa->TransformSetting.LifeKilobytes * (UINT64)1000;
			UINT64 soft_size = hard_size * (UINT64)2 / (UINT64)3;

			if (sa->TotalSize >= soft_size)
			{
				start_qm = true;
			}
		}

		if (start_qm)
		{
			if (sa->StartQM_FlagSet == false)
			{
				sa->StartQM_FlagSet = true;
				c->StartQuickModeAsSoon = true;
			}
		}
	}
	else
	{
		// Encryption failure
		Free(esp);
	}
}
void IPsecSendPacketByIkeClient(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size, UCHAR protocol_id)
{
	// Validate arguments
	if (ike == NULL || c == NULL || data == NULL || data_size == 0)
	{
		return;
	}

	if (c->CurrentIpSecSaSend == NULL)
	{
		return;
	}

	IPsecSendPacketByIPsecSa(ike, c->CurrentIpSecSaSend, data, data_size, protocol_id);
}

// Send an UDP packet via IPsec
void IPsecSendUdpPacket(IKE_SERVER *ike, IKE_CLIENT *c, UINT src_port, UINT dst_port, UCHAR *data, UINT data_size)
{
	UCHAR *udp;
	UINT udp_size;
	UDP_HEADER *u;
	UCHAR tmp1600[1600];
	bool no_free = false;
	// Validate arguments
	if (ike == NULL || c == NULL || data == NULL || data_size == 0)
	{
		return;
	}

	// Build an UDP packet
	udp_size = sizeof(UDP_HEADER) + data_size;

	if (udp_size > sizeof(tmp1600))
	{
		udp = Malloc(udp_size);
	}
	else
	{
		udp = tmp1600;
		no_free = true;
	}

	// UDP header
	u = (UDP_HEADER *)udp;
	u->SrcPort = Endian16(src_port);
	u->DstPort = Endian16(dst_port);
	u->PacketLength = Endian16(udp_size);
	u->Checksum = 0;

	//Debug("IPsec UDP Send: %u -> %u %u\n", src_port, dst_port, data_size);
#ifdef	RAW_DEBUG
	IPsecIkeSendUdpForDebug(IPSEC_PORT_L2TP, 1, data, data_size);
#endif	// RAW_DEBUG

	// Payload
	Copy(udp + sizeof(UDP_HEADER), data, data_size);

	if (IsIP6(&c->ClientIP))
	{
		if (IsIPsecSaTunnelMode(c->CurrentIpSecSaSend) == false)
		{
			u->Checksum = CalcChecksumForIPv6((IPV6_ADDR *)c->TransportModeServerIP.ipv6_addr,
				(IPV6_ADDR *)c->TransportModeClientIP.ipv6_addr,
				IP_PROTO_UDP,
				u,
				udp_size, 0);
		}
		else
		{
			u->Checksum = CalcChecksumForIPv6((IPV6_ADDR *)c->TunnelModeServerIP.ipv6_addr,
				(IPV6_ADDR *)c->TunnelModeClientIP.ipv6_addr,
				IP_PROTO_UDP,
				u,
				udp_size, 0);
		}
	}

	IPsecSendPacketByIkeClient(ike, c, udp, udp_size, IP_PROTO_UDP);

	if (no_free == false)
	{
		Free(udp);
	}
}

// Get whether the specified IPsec SA is in tunnel mode
bool IsIPsecSaTunnelMode(IPSECSA *sa)
{
	// Validate arguments
	if (sa == NULL)
	{
		return false;
	}

	if (sa->TransformSetting.CapsuleMode == IKE_P2_CAPSULE_TUNNEL ||
		sa->TransformSetting.CapsuleMode == IKE_P2_CAPSULE_NAT_TUNNEL_1 ||
		sa->TransformSetting.CapsuleMode == IKE_P2_CAPSULE_NAT_TUNNEL_2)
	{
		return true;
	}

	return false;
}

// Reception process of ESP packet
void ProcIPsecEspPacketRecv(IKE_SERVER *ike, UDPPACKET *p)
{
	UCHAR *src;
	UINT src_size;
	UINT spi;
	UINT seq;
	IPSECSA *ipsec_sa;
	IKE_CLIENT *c;
	UINT block_size;
	UINT hash_size;
	bool update_status = false;
	UCHAR *iv;
	UCHAR *hash;
	UCHAR *encrypted_payload_data;
	UINT size_of_payload_data;
	IKE_CRYPTO_PARAM cp;
	BUF *dec;
	UCHAR calced_hash[IKE_MAX_HASH_SIZE];
	bool is_tunnel_mode = false;
	// Validate arguments
	if (ike == NULL || p == NULL)
	{
		return;
	}

	src = (UCHAR *)p->Data;
	src_size = p->Size;

	if (p->DestPort == IPSEC_PORT_IPSEC_ESP_RAW)
	{
		if (IsIP4(&p->DstIP))
		{
			// Skip the IP header when received in Raw mode (only in the case of IPv4)
			UINT ip_header_size = GetIpHeaderSize(src, src_size);

			src += ip_header_size;
			src_size -= ip_header_size;
		}
	}

	// Get the SPI
	if (src_size < sizeof(UINT))
	{
		return;
	}

	spi = READ_UINT(src + 0);
	if (spi == 0)
	{
		return;
	}

	// Get the sequence number
	if (src_size < (sizeof(UINT) * 2))
	{
		return;
	}
	seq = READ_UINT(src + sizeof(UINT));

	// Search and retrieve the IPsec SA from SPI
	ipsec_sa = SearchClientToServerIPsecSaBySpi(ike, spi);
	if (ipsec_sa == NULL)
	{
		// Invalid SPI
		UINT64 init_cookie = Rand64();
		UINT64 resp_cookie = 0;
		IKE_CLIENT *c = NULL;
		IKE_CLIENT t;


		Copy(&t.ClientIP, &p->SrcIP, sizeof(IP));
		t.ClientPort = p->SrcPort;
		Copy(&t.ServerIP, &p->DstIP, sizeof(IP));
		t.ServerPort = p->DestPort;
		t.CurrentIkeSa = NULL;

		if (p->DestPort == IPSEC_PORT_IPSEC_ESP_RAW)
		{
			t.ClientPort = t.ServerPort = IPSEC_PORT_IPSEC_ISAKMP;
		}

		c = Search(ike->ClientList, &t);

		if (c != NULL && c->CurrentIkeSa != NULL)
		{
			init_cookie = c->CurrentIkeSa->InitiatorCookie;
			resp_cookie = c->CurrentIkeSa->ResponderCookie;
		}

		SendInformationalExchangePacketEx(ike, (c == NULL ? &t : c), IkeNewNoticeErrorInvalidSpiPayload(spi), false,
			init_cookie, resp_cookie);

		SendDeleteIPsecSaPacket(ike, (c == NULL ? &t : c), spi);
		return;
	}

	is_tunnel_mode = IsIPsecSaTunnelMode(ipsec_sa);

	c = ipsec_sa->IkeClient;
	if (c == NULL)
	{
		return;
	}

	block_size = ipsec_sa->TransformSetting.Crypto->BlockSize;
	hash_size = IKE_ESP_HASH_SIZE;

	// Get the IV
	if (src_size < (sizeof(UINT) * 2 + block_size + hash_size + block_size))
	{
		return;
	}
	iv = src + sizeof(UINT) * 2;

	// Get the hash
	hash = src + src_size - hash_size;

	// Inspect the HMAC
	IkeHMac(ipsec_sa->TransformSetting.Hash, calced_hash, ipsec_sa->HashKey,
		ipsec_sa->TransformSetting.Hash->HashSize, src, src_size - hash_size);

	if (Cmp(calced_hash, hash, hash_size) != 0)
	{
		//Debug("IPsec SA 0x%X: Invalid HMAC Value.\n", ipsec_sa->Spi);
		return;
	}

	// Get the payload data
	encrypted_payload_data = src + sizeof(UINT) * 2 + block_size;
	size_of_payload_data = src_size - hash_size - block_size - sizeof(UINT) * 2;
	if (size_of_payload_data == 0 || (size_of_payload_data % block_size) != 0)
	{
		// Payload data don't exist or is not a multiple of block size
		return;
	}

	// Decrypt the payload data
	cp.Key = ipsec_sa->CryptoKey;
	Copy(&cp.Iv, iv, block_size);

	dec = IkeDecrypt(encrypted_payload_data, size_of_payload_data, &cp);
	if (dec != NULL)
	{
		UCHAR *dec_data = dec->Buf;
		UINT dec_size = dec->Size;
		UCHAR size_of_padding = dec_data[dec_size - 2];
		UCHAR next_header = dec_data[dec_size - 1];
		if ((dec_size - 2) >= size_of_padding)
		{
			UINT orig_size = dec_size - 2 - size_of_padding;

			ipsec_sa->TotalSize += dec_size;

			if (is_tunnel_mode)
			{
				// Tunnel Mode
				if (next_header == IKE_PROTOCOL_ID_IPV4 || next_header == IKE_PROTOCOL_ID_IPV6)
				{
					// Check the contents by parsing the IPv4 / IPv6 header in the case of tunnel mode
					BUF *b = NewBuf();
					static UCHAR src_mac_dummy[6] = {0, 0, 0, 0, 0, 0, };
					static UCHAR dst_mac_dummy[6] = {0, 0, 0, 0, 0, 0, };
					USHORT tpid = Endian16(next_header == IKE_PROTOCOL_ID_IPV4 ? MAC_PROTO_IPV4 : MAC_PROTO_IPV6);
					PKT *pkt;

					WriteBuf(b, src_mac_dummy, sizeof(src_mac_dummy));
					WriteBuf(b, dst_mac_dummy, sizeof(dst_mac_dummy));
					WriteBuf(b, &tpid, sizeof(tpid));

					WriteBuf(b, dec_data, dec_size);

					// Parse
					pkt = ParsePacket(b->Buf, b->Size);

#ifdef	RAW_DEBUG
					IPsecIkeSendUdpForDebug(IPSEC_PORT_L2TP, 1, b->Buf, b->Size);
#endif	// RAW_DEBUG

					if (pkt == NULL)
					{
						// Parsing failure
						dec_data = NULL;
						dec_size = 0;
					}
					else
					{
						// Parsing success
						switch (pkt->TypeL3)
						{
						case L3_IPV4:
							// Save the internal IP address information
							UINTToIP(&c->TunnelModeServerIP, pkt->L3.IPv4Header->DstIP);
							UINTToIP(&c->TunnelModeClientIP, pkt->L3.IPv4Header->SrcIP);

							if (IPV4_GET_OFFSET(pkt->L3.IPv4Header) == 0)
							{
								if ((IPV4_GET_FLAGS(pkt->L3.IPv4Header) & 0x01) == 0)
								{
									if (pkt->L3.IPv4Header->Protocol == IPSEC_IP_PROTO_ETHERIP)
									{
										// EtherIP
										if (ike->IPsec->Services.EtherIP_IPsec)
										{
											// An EtherIP packet has been received
											ProcIPsecEtherIPPacketRecv(ike, c, pkt->IPv4PayloadData, pkt->IPv4PayloadSize, true);
										}
									}
									else if (pkt->L3.IPv4Header->Protocol == IPSEC_IP_PROTO_L2TPV3)
									{
										// L2TPv3
										if (ike->IPsec->Services.EtherIP_IPsec)
										{
											// A L2TPv3 packet has been received
											ProcL2TPv3PacketRecv(ike, c, pkt->IPv4PayloadData, pkt->IPv4PayloadSize, true);
										}
									}
								}
							}
							break;

						case L3_IPV6:
							// Save the internal IP address information
							SetIP6(&c->TunnelModeServerIP, pkt->IPv6HeaderPacketInfo.IPv6Header->DestAddress.Value);
							SetIP6(&c->TunnelModeClientIP, pkt->IPv6HeaderPacketInfo.IPv6Header->SrcAddress.Value);

							if (pkt->IPv6HeaderPacketInfo.IsFragment == false)
							{
								if (pkt->IPv6HeaderPacketInfo.FragmentHeader == NULL || (IPV6_GET_FLAGS(pkt->IPv6HeaderPacketInfo.FragmentHeader) & IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS) == 0)
								{
									if (pkt->IPv6HeaderPacketInfo.Protocol == IPSEC_IP_PROTO_ETHERIP)
									{
										// EtherIP
										if (ike->IPsec->Services.EtherIP_IPsec)
										{
											// An EtherIP packet has been received
											ProcIPsecEtherIPPacketRecv(ike, c, pkt->IPv6HeaderPacketInfo.Payload, pkt->IPv6HeaderPacketInfo.PayloadSize, true);
										}
									}
									else if (pkt->IPv6HeaderPacketInfo.Protocol == IPSEC_IP_PROTO_L2TPV3)
									{
										// L2TPv3
										if (ike->IPsec->Services.EtherIP_IPsec)
										{
											// A L2TPv3 packet has been received
											ProcL2TPv3PacketRecv(ike, c, pkt->IPv6HeaderPacketInfo.Payload, pkt->IPv6HeaderPacketInfo.PayloadSize, true);
										}
									}
								}
							}
							break;
						}

						FreePacket(pkt);
					}

					FreeBuf(b);
				}
			}
			else
			{
				// Transport mode
				if (next_header == IP_PROTO_UDP)
				{
					if (ike->IPsec->Services.L2TP_IPsec)
					{
						// An UDP packet has been received
						ProcIPsecUdpPacketRecv(ike, c, dec_data, dec_size);
					}
				}
				else if (next_header == IPSEC_IP_PROTO_ETHERIP)
				{
					if (ike->IPsec->Services.EtherIP_IPsec)
					{
						// An EtherIP packet has been received
						ProcIPsecEtherIPPacketRecv(ike, c, dec_data, dec_size, false);
					}
				}
				else if (next_header == IPSEC_IP_PROTO_L2TPV3)
				{
					if (ike->IPsec->Services.EtherIP_IPsec)
					{
						// A L2TPv3 packet has been received
						ProcL2TPv3PacketRecv(ike, c, dec_data, dec_size, false);
					}
				}
			}

			update_status = true;
		}

		FreeBuf(dec);
	}

	if (update_status)
	{
		bool start_qm = false;
		// Update the status of the client
		c->CurrentIpSecSaRecv = ipsec_sa;
		if (ipsec_sa->PairIPsecSa != NULL)
		{
			c->CurrentIpSecSaSend = ipsec_sa->PairIPsecSa;
		}
		c->LastCommTick = ike->Now;
		ipsec_sa->LastCommTick = ike->Now;
		if (ipsec_sa->PairIPsecSa != NULL)
		{
			ipsec_sa->PairIPsecSa->LastCommTick = ike->Now;
		}

		SetIkeClientEndpoint(ike, c, &p->SrcIP, p->SrcPort, &p->DstIP, p->DestPort);

		if (seq >= 0xf0000000)
		{
			// Execute a QuickMode forcibly since sequence number is going to exhaust
			start_qm = true;
		}

		if (ipsec_sa->TransformSetting.LifeKilobytes != 0)
		{
			UINT64 hard_size = (UINT64)ipsec_sa->TransformSetting.LifeKilobytes * (UINT64)1000;
			UINT64 soft_size = hard_size * (UINT64)2 / (UINT64)3;

			if (ipsec_sa->TotalSize >= soft_size)
			{
				// Execute a QuickMode forcibly because the capacity limit is going to exceed
				start_qm = true;
			}
		}

		if (start_qm)
		{
			if (ipsec_sa->StartQM_FlagSet == false)
			{
				c->StartQuickModeAsSoon = true;
				ipsec_sa->StartQM_FlagSet = true;
			}
		}
	}
}

// Received the L2TPv3 packet via the IPsec tunnel
void ProcL2TPv3PacketRecv(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size, bool is_tunnel_mode)
{
	UDPPACKET p;
	// Validate arguments
	if (ike == NULL || c == NULL || data == NULL || data_size == 0)
	{
		return;
	}

	c->IsL2TPOnIPsecTunnelMode = is_tunnel_mode;

	IPsecIkeClientManageL2TPServer(ike, c);

	// Pass the received packet to the L2TP server
	p.Type = 0;
	p.Data = data;
	p.DestPort = IPSEC_PORT_L2TPV3_VIRTUAL;
	p.Size = data_size;

	if (is_tunnel_mode)
	{
		Copy(&p.DstIP, &c->TunnelModeServerIP, sizeof(IP));
		Copy(&p.SrcIP, &c->TunnelModeClientIP, sizeof(IP));
	}
	else
	{
		Copy(&p.DstIP, &c->L2TPServerIP, sizeof(IP));
		Copy(&p.SrcIP, &c->L2TPClientIP, sizeof(IP));
	}
	p.SrcPort = IPSEC_PORT_L2TPV3_VIRTUAL;

#ifdef	RAW_DEBUG
	IPsecIkeSendUdpForDebug(IPSEC_PORT_L2TP, 1, ((UCHAR *)p.Data) + 4, p.Size - 4);
#endif	// RAW_DEBUG

	ProcL2TPPacketRecv(c->L2TP, &p);
}

// An EtherIP packet has been received via an IPsec tunnel
void ProcIPsecEtherIPPacketRecv(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size, bool is_tunnel_mode)
{
	BLOCK *b;
	// Validate arguments
	if (ike == NULL || c == NULL || data == NULL || data_size == 0)
	{
		return;
	}

	c->IsEtherIPOnIPsecTunnelMode = is_tunnel_mode;

	IPsecIkeClientManageEtherIPServer(ike, c);

	b = NewBlock(data, data_size, 0);

	EtherIPProcRecvPackets(c->EtherIP, b);

	Free(b);
}

// An UDP packet has been received via the IPsec tunnel
void ProcIPsecUdpPacketRecv(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size)
{
	UDP_HEADER *u;
	UINT payload_size;
	UINT src_port, dst_port;
	UINT packet_length;
	// Validate arguments
	if (ike == NULL || c == NULL || data == NULL || data_size == 0)
	{
		return;
	}

	if (data_size <= sizeof(UDP_HEADER))
	{
		// There is no UDP header or the data is 0 bytes
		return;
	}

	// UDP header
	u = (UDP_HEADER *)data;

	packet_length = Endian16(u->PacketLength);

	if (packet_length <= sizeof(UDP_HEADER))
	{
		return;
	}

	payload_size = packet_length - sizeof(UDP_HEADER);

	if (payload_size == 0)
	{
		// No data
		return;
	}

	if (data_size < (sizeof(UDP_HEADER) + payload_size))
	{
		// Data is not followed
		return;
	}

	src_port = Endian16(u->SrcPort);
	dst_port = Endian16(u->DstPort);

	if (dst_port == IPSEC_PORT_L2TP)
	{
		UDPPACKET p;
		// A L2TP packet has been received
		IPsecIkeClientManageL2TPServer(ike, c);

		// Update Port number
		c->L2TPClientPort = src_port;

		// Pass the received packet to the L2TP server
		p.Type = 0;
		p.Data = data + sizeof(UDP_HEADER);
		p.DestPort = IPSEC_PORT_L2TP;
		Copy(&p.DstIP, &c->L2TPServerIP, sizeof(IP));
		p.Size = payload_size;
		Copy(&p.SrcIP, &c->L2TPClientIP, sizeof(IP));
		p.SrcPort = IPSEC_PORT_L2TP;

		ProcL2TPPacketRecv(c->L2TP, &p);

		//Debug("IPsec UDP Recv: %u <= %u %u\n", dst_port, src_port, p.Size);

#ifdef	RAW_DEBUG
		IPsecIkeSendUdpForDebug(IPSEC_PORT_L2TP, 1, p.Data, p.Size);
#endif	// RAW_DEBUG
	}
}

// Send a raw packet for debugging
void IPsecIkeSendUdpForDebug(UINT dst_port, UINT dst_ip, void *data, UINT size)
{
	SOCK *s = NewUDP(0);
	IP d;

	SetIP(&d, dst_ip, dst_ip, dst_ip, dst_ip);

	SendTo(s, &d, dst_port, data, size);

	ReleaseSock(s);
}

// L2TP packet transmission (via IPsec SA tunnel)
void IPsecIkeClientSendL2TPPackets(IKE_SERVER *ike, IKE_CLIENT *c, L2TP_SERVER *l2tp)
{
	UINT i;
	// Validate arguments
	if (ike == NULL || c == NULL || l2tp == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(l2tp->SendPacketList);i++)
	{
		UDPPACKET *u = LIST_DATA(l2tp->SendPacketList, i);

		if (u->SrcPort != IPSEC_PORT_L2TPV3_VIRTUAL)
		{
			// L2TP UDP packet transmission
			IPsecSendUdpPacket(ike, c, IPSEC_PORT_L2TP, c->L2TPClientPort,
				u->Data, u->Size);
		}
		else
		{
			// L2TPv3 special IP packet transmission
			IPsecSendPacketByIkeClient(ike, c, u->Data, u->Size, IPSEC_IP_PROTO_L2TPV3);

#ifdef	RAW_DEBUG
			IPsecIkeSendUdpForDebug(IPSEC_PORT_L2TP, 1, ((UCHAR *)u->Data) + 4, u->Size - 4);
#endif	// RAW_DEBUG
		}

		FreeUdpPacket(u);
	}

	DeleteAll(l2tp->SendPacketList);
}

// Manage the L2TP server that is associated with the IKE_CLIENT
void IPsecIkeClientManageL2TPServer(IKE_SERVER *ike, IKE_CLIENT *c)
{
	L2TP_SERVER *l2tp;
	// Validate arguments
	if (ike == NULL || c == NULL)
	{
		return;
	}

	if (c->L2TP == NULL)
	{
		UINT crypt_block_size = IKE_MAX_BLOCK_SIZE;

		if (c->CurrentIpSecSaRecv != NULL)
		{
			crypt_block_size = c->CurrentIpSecSaRecv->TransformSetting.Crypto->BlockSize;
		}

		c->L2TP = NewL2TPServerEx(ike->Cedar, ike, IsIP6(&c->ClientIP), crypt_block_size);
		c->L2TP->IkeClient = c;

		Copy(&c->L2TPServerIP, &c->ServerIP, sizeof(IP));
		Copy(&c->L2TPClientIP, &c->ClientIP, sizeof(IP));

		if (c->CurrentIpSecSaRecv != NULL)
		{
			Format(c->L2TP->CryptName, sizeof(c->L2TP->CryptName),
				"IPsec - %s (%u bits)",
				c->CurrentIpSecSaRecv->TransformSetting.Crypto->Name,
				c->CurrentIpSecSaRecv->TransformSetting.CryptoKeySize * 8);
		}

		Debug("IKE_CLIENT 0x%X: L2TP Server Started.\n", c);

		IPsecLog(ike, c, NULL, NULL, "LI_L2TP_SERVER_STARTED");
	}

	l2tp = c->L2TP;

	if (l2tp->Interrupts == NULL)
	{
		l2tp->Interrupts = ike->Interrupts;
	}

	if (l2tp->SockEvent == NULL)
	{
		SetL2TPServerSockEvent(l2tp, ike->SockEvent);
	}

	l2tp->Now = ike->Now;
}

// Manage the EtherIP server that is associated with the IKE_CLIENT
void IPsecIkeClientManageEtherIPServer(IKE_SERVER *ike, IKE_CLIENT *c)
{
	ETHERIP_SERVER *s;
	// Validate arguments
	if (ike == NULL || c == NULL)
	{
		return;
	}

	if (c->EtherIP == NULL)
	{
		char crypt_name[MAX_SIZE];
		UINT crypt_block_size = IKE_MAX_BLOCK_SIZE;

		Zero(crypt_name, sizeof(crypt_name));

		if (c->CurrentIpSecSaRecv != NULL)
		{
			Format(crypt_name, sizeof(crypt_name),
				"IPsec - %s (%u bits)",
				c->CurrentIpSecSaRecv->TransformSetting.Crypto->Name,
				c->CurrentIpSecSaRecv->TransformSetting.CryptoKeySize * 8);

			crypt_block_size = c->CurrentIpSecSaRecv->TransformSetting.Crypto->BlockSize;
		}

		c->EtherIP = NewEtherIPServer(ike->Cedar, ike->IPsec, ike,
			&c->ClientIP, c->ClientPort,
			&c->ServerIP, c->ServerPort, crypt_name,
			c->IsEtherIPOnIPsecTunnelMode, crypt_block_size, c->ClientId,
			++ike->CurrentEtherId);

		Debug("IKE_CLIENT 0x%X: EtherIP Server Started.\n", c);

		IPsecLog(ike, c, NULL, NULL, NULL, "LI_ETHERIP_SERVER_STARTED", ike->CurrentEtherId);
	}
	else
	{
		StrCpy(c->EtherIP->ClientId, sizeof(c->EtherIP->ClientId), c->ClientId);
	}

	s = c->EtherIP;

	if (s->Interrupts == NULL)
	{
		s->Interrupts = ike->Interrupts;
	}

	if (s->SockEvent == NULL)
	{
		SetEtherIPServerSockEvent(s, ike->SockEvent);
	}

	s->Now = ike->Now;
}

// EtherIP packet transmission (via IPsec SA tunnel)
void IPsecIkeClientSendEtherIPPackets(IKE_SERVER *ike, IKE_CLIENT *c, ETHERIP_SERVER *s)
{
	UINT i;
	// Validate arguments
	if (ike == NULL || c == NULL || s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->SendPacketList);i++)
	{
		BLOCK *b = LIST_DATA(s->SendPacketList, i);

		// Packet transmission
		IPsecSendPacketByIkeClient(ike, c, b->Buf, b->Size, IPSEC_IP_PROTO_ETHERIP);

		FreeBlock(b);
	}

	DeleteAll(s->SendPacketList);
}

// Handle the deletion payload
void ProcDeletePayload(IKE_SERVER *ike, IKE_CLIENT *c, IKE_PACKET_DELETE_PAYLOAD *d)
{
	// Validate arguments
	if (ike == NULL || c == NULL || d == NULL)
	{
		return;
	}

	if (d->ProtocolId == IKE_PROTOCOL_ID_IPSEC_ESP)
	{
		UINT i;
		// Remove the IPsec SA
		for (i = 0;i < LIST_NUM(d->SpiList);i++)
		{
			BUF *b = LIST_DATA(d->SpiList, i);

			if (b->Size == 4)
			{
				UINT spi = READ_UINT(b->Buf);
				MarkIPsecSaAsDeleted(ike, SearchIPsecSaBySpi(ike, c, spi));
			}
		}
	}
	else if (d->ProtocolId == IKE_PROTOCOL_ID_IKE)
	{
		UINT i;
		// Remove the IKE SA
		for (i = 0;i < LIST_NUM(d->SpiList);i++)
		{
			BUF *b = LIST_DATA(d->SpiList, i);

			if (b->Size == 16)
			{
				UINT64 v1 = READ_UINT64(((UCHAR *)b->Buf) + 0);
				UINT64 v2 = READ_UINT64(((UCHAR *)b->Buf) + 8);

				IKE_SA *sa = FindIkeSaByResponderCookie(ike, v2);

				if (sa != NULL && sa->IkeClient == c)
				{
					MarkIkeSaAsDeleted(ike, sa);
				}
			}
		}
	}
}

// Mark the IKE_CLIENT for deletion
void MarkIkeClientAsDeleted(IKE_SERVER *ike, IKE_CLIENT *c)
{
	char client_ip_str[MAX_SIZE];
	char server_ip_str[MAX_SIZE];
	// Validate arguments
	if (ike == NULL || c == NULL)
	{
		return;
	}

	if (c->Deleting)
	{
		return;
	}

	ike->StateHasChanged = true;

	c->Deleting = true;

	IPToStr(client_ip_str, sizeof(client_ip_str), &c->ClientIP);
	IPToStr(server_ip_str, sizeof(server_ip_str), &c->ServerIP);

	Debug("Deleting IKE_CLIENT: %p: %s:%u -> %s:%u\n", c, client_ip_str, c->ClientPort, server_ip_str, c->ServerPort);

	IPsecLog(ike, c, NULL, NULL, "LI_DELETE_IKE_CLIENT");
}

// Mark the IKE SA for deletion
void MarkIkeSaAsDeleted(IKE_SERVER *ike, IKE_SA *sa)
{
	// Validate arguments
	if (ike == NULL || sa == NULL)
	{
		return;
	}

	if (sa->Deleting)
	{
		return;
	}

	ike->StateHasChanged = true;

	sa->Deleting = true;

	Debug("IKE SA %I64u - %I64u has been marked as being deleted.\n", sa->InitiatorCookie, sa->ResponderCookie);

	SendDeleteIkeSaPacket(ike, sa->IkeClient, sa->InitiatorCookie, sa->ResponderCookie);

	IPsecLog(ike, NULL, sa, NULL, "LI_DELETE_IKE_SA");
}

// Mark the IPsec SA for deletion
void MarkIPsecSaAsDeleted(IKE_SERVER *ike, IPSECSA *sa)
{
	// Validate arguments
	if (ike == NULL || sa == NULL)
	{
		return;
	}

	if (sa->Deleting)
	{
		return;
	}

	ike->StateHasChanged = true;

	sa->Deleting = true;

	Debug("IPsec SA 0x%X has been marked as being deleted.\n", sa->Spi);

	SendDeleteIPsecSaPacket(ike, sa->IkeClient, sa->Spi);

	IPsecLog(ike, NULL, NULL, sa, "LI_DELETE_IPSEC_SA");
}

// IPsec SA Deletion packet transmission process
void SendDeleteIPsecSaPacket(IKE_SERVER *ike, IKE_CLIENT *c, UINT spi)
{
	IKE_PACKET_PAYLOAD *payload;
	BUF *buf;
	// Validate arguments
	if (ike == NULL || c == NULL || spi == 0)
	{
		return;
	}

	buf = NewBuf();
	WriteBufInt(buf, spi);

	payload = IkeNewDeletePayload(IKE_PROTOCOL_ID_IPSEC_ESP, NewListSingle(buf));

	SendInformationalExchangePacket(ike, c, payload);
}

// IKE SA deletion packet transmission process
void SendDeleteIkeSaPacket(IKE_SERVER *ike, IKE_CLIENT *c, UINT64 init_cookie, UINT64 resp_cookie)
{
	IKE_PACKET_PAYLOAD *payload;
	BUF *buf;
	// Validate arguments
	if (ike == NULL || c == NULL)
	{
		return;
	}

	buf = NewBuf();
	WriteBufInt64(buf, init_cookie);
	WriteBufInt64(buf, resp_cookie);

	payload = IkeNewDeletePayload(IKE_PROTOCOL_ID_IKE, NewListSingle(buf));

	SendInformationalExchangePacket(ike, c, payload);
}

// Information exchange packet transmission process
void SendInformationalExchangePacket(IKE_SERVER *ike, IKE_CLIENT *c, IKE_PACKET_PAYLOAD *payload)
{
	SendInformationalExchangePacketEx(ike, c, payload, false, 0, 0);
}
void SendInformationalExchangePacketEx(IKE_SERVER *ike, IKE_CLIENT *c, IKE_PACKET_PAYLOAD *payload, bool force_plain, UINT64 init_cookie, UINT64 resp_cookie)
{
	IKE_SA *sa;
	IKE_PACKET *ps;
	LIST *payload_list;
	UCHAR dummy_hash_data[IKE_MAX_HASH_SIZE];
	IKE_PACKET_PAYLOAD *hash_payload;
	BUF *ps_buf;
	UINT after_hash_offset, after_hash_size;
	BUF *ps_buf_after_hash;
	BUF *tmp_buf;
	UCHAR hash[IKE_MAX_HASH_SIZE];
	IKE_CRYPTO_PARAM cp;
	bool plain = false;
	// Validate arguments
	if (ike == NULL || c == NULL || payload == NULL)
	{
		IkeFreePayload(payload);
		return;
	}

	sa = c->CurrentIkeSa;
	if (sa == NULL)
	{
		plain = true;
	}

	if (force_plain)
	{
		plain = true;
	}

	if (plain && (init_cookie == 0 && resp_cookie == 0))
	{
		init_cookie = Rand64();
		resp_cookie = 0;
	}

	payload_list = NewListFast(NULL);

	Zero(dummy_hash_data, sizeof(dummy_hash_data));

	// Hash payload
	if (plain == false)
	{
		hash_payload = IkeNewDataPayload(IKE_PAYLOAD_HASH, dummy_hash_data, sa->HashSize);
		Add(payload_list, hash_payload);
	}

	// Body
	Add(payload_list, payload);

	// Packet creation
	ps = IkeNew((plain ? init_cookie : sa->InitiatorCookie), (plain ? resp_cookie : sa->ResponderCookie),
		IKE_EXCHANGE_TYPE_INFORMATION, false, false, false,
		GenerateNewMessageId(ike), payload_list);

	if (plain == false)
	{
		// Build a temporary packet
		ps_buf = IkeBuild(ps, NULL);

		// Get the payload after the hash part
		after_hash_offset = sizeof(IKE_HEADER) + hash_payload->BitArray->Size + sizeof(IKE_COMMON_HEADER);
		after_hash_size = ((ps_buf->Size > after_hash_offset) ? (ps_buf->Size - after_hash_offset) : 0);

		ps_buf_after_hash = MemToBuf(((UCHAR *)ps_buf->Buf) + after_hash_offset, after_hash_size);
		FreeBuf(ps_buf);

		// Calculate the hash
		tmp_buf = NewBuf();
		WriteBufInt(tmp_buf, ps->MessageId);
		WriteBufBuf(tmp_buf, ps_buf_after_hash);
		IkeHMac(sa->TransformSetting.Hash, hash, sa->SKEYID_a, sa->HashSize, tmp_buf->Buf, tmp_buf->Size);
		FreeBuf(tmp_buf);

		// Overwrite the hash
		Copy(hash_payload->Payload.Hash.Data->Buf, hash, sa->HashSize);

		ps->FlagEncrypted = true;
		FreeBuf(ps_buf_after_hash);
	}

	// Packet reply
	Zero(&cp, sizeof(cp));

	if (plain == false)
	{
		cp.Key = sa->CryptoKey;
		IkeCalcPhase2InitialIv(cp.Iv, sa, ps->MessageId);
	}

	ps_buf = IkeBuild(ps, &cp);

	IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP, &c->ServerIP, c->ServerPort,
		&c->ClientIP, c->ClientPort,
		ps_buf->Buf, ps_buf->Size);

#ifdef	RAW_DEBUG
	IkeDebugUdpSendRawPacket(ps);
#endif	// RAW_DEBUG

	Free(ps_buf);

	IkeFree(ps);
}

// Information exchange packet reception process
void ProcIkeInformationalExchangePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header)
{
	IKE_CLIENT *c;
	IKE_SA *ike_sa;
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL || header->InitiatorCookie == 0 || header->ResponderCookie == 0
		|| header->MessageId == 0 || header->FlagEncrypted == false)
	{
		return;
	}

	c = SearchOrCreateNewIkeClientForIkePacket(ike, &p->SrcIP, p->SrcPort, &p->DstIP, p->DestPort, header);

	if (c == NULL)
	{
		return;
	}

	ike_sa = FindIkeSaByResponderCookieAndClient(ike, header->ResponderCookie, c);

	if (ike_sa != NULL && ike_sa->Established)
	{
		IKE_PACKET *pr;
		IKE_CRYPTO_PARAM cp;

		// Packet decoding
		Zero(&cp, sizeof(cp));
		cp.Key = ike_sa->CryptoKey;
		IkeCalcPhase2InitialIv(cp.Iv, ike_sa, header->MessageId);

		pr = IkeParse(p->Data, p->Size, &cp);
#ifdef	RAW_DEBUG
		IkeDebugUdpSendRawPacket(pr);
#endif	// RAW_DEBUG
		if (pr != NULL)
		{
			// Get the hash payload
			IKE_PACKET_PAYLOAD *hash_payload;

			hash_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_HASH, 0);
			if (hash_payload != NULL)
			{
				// Get the payload after the hash
				UINT header_and_hash_size = sizeof(IKE_COMMON_HEADER) + hash_payload->BitArray->Size;
				void *after_hash_data = ((UCHAR *)pr->DecryptedPayload->Buf) + header_and_hash_size;
				if (pr->DecryptedPayload->Size > header_and_hash_size)
				{
					UINT after_hash_size = pr->DecryptedPayload->Size - header_and_hash_size;
					UCHAR hash1[IKE_MAX_HASH_SIZE];
					BUF *hash1_buf;

					hash1_buf = NewBuf();
					WriteBufInt(hash1_buf, header->MessageId);
					WriteBuf(hash1_buf, after_hash_data, after_hash_size);

					IkeHMac(ike_sa->TransformSetting.Hash, hash1, ike_sa->SKEYID_a, ike_sa->HashSize,
						hash1_buf->Buf, hash1_buf->Size);

					// Compare the hash value
					if (IkeCompareHash(hash_payload, hash1, ike_sa->HashSize))
					{
						UINT i, num;
						// Handle the deletion payload
						num = IkeGetPayloadNum(pr->PayloadList, IKE_PAYLOAD_DELETE);
						for (i = 0;i < num;i++)
						{
							IKE_PACKET_PAYLOAD *payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_DELETE, i);
							IKE_PACKET_DELETE_PAYLOAD *del = &payload->Payload.Delete;

							ProcDeletePayload(ike, c, del);
						}
						num = IkeGetPayloadNum(pr->PayloadList, IKE_PAYLOAD_NOTICE);
						// Handle the notification payload
						for (i = 0;i < num;i++)
						{
							IKE_PACKET_PAYLOAD *payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NOTICE, i);
							IKE_PACKET_NOTICE_PAYLOAD *n = &payload->Payload.Notice;

							if (n->MessageType == IKE_NOTICE_DPD_REQUEST || n->MessageType == IKE_NOTICE_DPD_RESPONSE)
							{
								if (n->MessageData != NULL && n->MessageData->Size == sizeof(UINT))
								{
									UINT seq_no = READ_UINT(n->MessageData->Buf);

									if (n->Spi->Size == (sizeof(UINT64) * 2))
									{
										UINT64 init_cookie = READ_UINT64(((UCHAR *)n->Spi->Buf));
										UINT64 resp_cookie = READ_UINT64(((UCHAR *)n->Spi->Buf) + sizeof(UINT64));

										if (init_cookie != 0 && resp_cookie != 0)
										{
											IKE_SA *found_ike_sa = SearchIkeSaByCookie(ike, init_cookie, resp_cookie);

											if (found_ike_sa != NULL && found_ike_sa->IkeClient == c)
											{
												if (n->MessageType == IKE_NOTICE_DPD_REQUEST)
												{
													// Return the DPD Response (ACK) for the DPD Request
													SendInformationalExchangePacket(ike, c,
														IkeNewNoticeDpdPayload(true, init_cookie, resp_cookie,
														seq_no));
												}

												// Update the status of the IKE SA
												found_ike_sa->LastCommTick = ike->Now;
												ike_sa->LastCommTick = ike->Now;
												found_ike_sa->IkeClient->LastCommTick = ike->Now;
												ike_sa->IkeClient->LastCommTick = ike->Now;
												ike_sa->IkeClient->CurrentIkeSa = ike_sa;
											}
										}
									}
								}
							}
						}
					}

					FreeBuf(hash1_buf);
				}
			}

			IkeFree(pr);
		}
	}
}

// Create a new message ID
UINT GenerateNewMessageId(IKE_SERVER *ike)
{
	UINT ret;
	// Validate arguments
	if (ike == NULL)
	{
		return 0;
	}

	while (true)
	{
		ret = Rand32();

		if (ret != 0 && ret != 0xffffffff)
		{
			UINT i;
			bool ok = true;

			for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
			{
				IPSECSA *sa = LIST_DATA(ike->IPsecSaList, i);

				if (sa->MessageId == ret)
				{
					ok = false;
					break;
				}
			}

			if (ok)
			{
				return ret;
			}
		}
	}
}

// Start the quick mode
void StartQuickMode(IKE_SERVER *ike, IKE_CLIENT *c)
{
	IPSEC_SA_TRANSFORM_SETTING setting;
	IKE_SA *ike_sa;
	UINT message_id;
	UCHAR iv[IKE_MAX_BLOCK_SIZE];
	// Validate arguments
	if (ike == NULL || c == NULL)
	{
		return;
	}

	if (IsZero(&c->CachedTransformSetting, sizeof(IPSEC_SA_TRANSFORM_SETTING)))
	{
		// Cached transform setting does not exist
		Debug("Error: c->CachedTransformSetting is not existing.\n");
		return;
	}

	ike_sa = c->CurrentIkeSa;
	if (ike_sa == NULL)
	{
		return;
	}

	IPsecLog(ike, NULL, ike_sa, NULL, "LI_START_QM_FROM_SERVER");

	Copy(&setting, &c->CachedTransformSetting, sizeof(IPSEC_SA_TRANSFORM_SETTING));

	message_id = GenerateNewMessageId(ike);

	IkeCalcPhase2InitialIv(iv, ike_sa, message_id);

#ifdef	FORCE_LIFETIME_QM
	setting.LifeSeconds = FORCE_LIFETIME_QM;
#endif	// FORCE_LIFETIME_QM

	if (true)
	{
		IKE_PACKET *ps;
		LIST *payload_list;
		IKE_PACKET_PAYLOAD *send_hash_payload;
		IKE_PACKET_PAYLOAD *send_sa_payload;
		IKE_PACKET_PAYLOAD *send_proposal_payload;
		IKE_PACKET_PAYLOAD *send_transform_payload;
		IKE_PACKET_PAYLOAD *send_rand_payload;
		IKE_PACKET_PAYLOAD *send_key_payload = NULL;
		IKE_PACKET_PAYLOAD *send_id_1 = NULL, *send_id_2 = NULL;
		UINT shared_key_size = 0;
		UCHAR *shared_key = NULL;
		BUF *initiator_rand;
		IPSECSA *ipsec_sa_s_c, *ipsec_sa_c_s;
		BUF *ps_buf;
		UINT after_hash_offset, after_hash_size;
		BUF *ps_buf_after_hash;
		BUF *tmp_buf;
		UINT spi;
		UINT spi_be;
		UCHAR hash1[IKE_MAX_HASH_SIZE];
		UCHAR zero = 0;
		DH_CTX *dh = NULL;
		UCHAR dummy_hash_data[IKE_MAX_HASH_SIZE];

		initiator_rand = RandBuf(IKE_SA_RAND_SIZE);

		if (setting.Dh != NULL)
		{
			// Generate DH
			dh = IkeDhNewCtx(setting.Dh);

			if (dh != NULL)
			{
				send_key_payload = IkeNewDataPayload(IKE_PAYLOAD_KEY_EXCHANGE,
					dh->MyPublicKey->Buf, dh->MyPublicKey->Size);
			}
		}

		Zero(dummy_hash_data, sizeof(dummy_hash_data));

		// Dummy hash value
		payload_list = NewListFast(NULL);
		send_hash_payload = IkeNewDataPayload(IKE_PAYLOAD_HASH, dummy_hash_data, ike_sa->HashSize);
		Add(payload_list, send_hash_payload);

		// Determine the SPI
		spi = GenerateNewIPsecSaSpi(ike, 0);
		spi_be = Endian32(spi);

		// SA
		send_transform_payload = TransformSettingToTransformPayloadForIPsec(ike, &setting);
		send_proposal_payload = IkeNewProposalPayload(1, IKE_PROTOCOL_ID_IPSEC_ESP, &spi_be, sizeof(spi_be),
			NewListSingle(send_transform_payload));
		send_sa_payload = IkeNewSaPayload(NewListSingle(send_proposal_payload));
		Add(payload_list, send_sa_payload);

		// Random number
		send_rand_payload = IkeNewDataPayload(IKE_PAYLOAD_RAND, initiator_rand->Buf, initiator_rand->Size);
		Add(payload_list, send_rand_payload);

		// Key exchange
		if (send_key_payload != NULL)
		{
			Add(payload_list, send_key_payload);
		}

		if (c->SendID1andID2)
		{
			// Add the ID payload
			if (setting.CapsuleMode == IKE_P2_CAPSULE_NAT_TUNNEL_1 || setting.CapsuleMode == IKE_P2_CAPSULE_NAT_TUNNEL_2)
			{
				UCHAR zero[32];

				Zero(zero, sizeof(zero));

				// Tunnel Mode
				send_id_1 = IkeNewIdPayload((IsIP4(&c->ServerIP) ? IKE_ID_IPV4_ADDR_SUBNET : IKE_ID_IPV6_ADDR_SUBNET),
					0, 0,
					zero, (IsIP4(&c->ServerIP) ? 8 : 32));

				send_id_2 = IkeNewIdPayload(c->SendID1_Type,
					c->SendID1_Protocol, c->SendID1_Port,
					c->SendID1_Buf->Buf, c->SendID1_Buf->Size);
			}
			else
			{
				// Transport mode
				// Specify in the reverse order in which the client has been specified
				send_id_2 = IkeNewIdPayload(c->SendID1_Type,
					c->SendID1_Protocol, c->SendID1_Port,
					c->SendID1_Buf->Buf, c->SendID1_Buf->Size);

				send_id_1 = IkeNewIdPayload(c->SendID2_Type,
					c->SendID2_Protocol, c->SendID2_Port,
					c->SendID2_Buf->Buf, c->SendID2_Buf->Size);
			}

			Add(payload_list, send_id_1);
			Add(payload_list, send_id_2);
		}

		if (true)
		{
			// NAT-OA payload
			if (c->SendNatOaDraft1)
			{
				Add(payload_list, IkeNewNatOaPayload(IKE_PAYLOAD_NAT_OA_DRAFT, &c->ServerIP));
			}

			if (c->SendNatOaDraft2)
			{
				Add(payload_list, IkeNewNatOaPayload(IKE_PAYLOAD_NAT_OA_DRAFT_2, &c->ServerIP));
			}

			if (c->SendNatOaRfc)
			{
				Add(payload_list, IkeNewNatOaPayload(IKE_PAYLOAD_NAT_OA, &c->ClientIP));
				Add(payload_list, IkeNewNatOaPayload(IKE_PAYLOAD_NAT_OA, &c->ServerIP));
			}
		}

		// Build a packet
		ps = IkeNew(ike_sa->InitiatorCookie, ike_sa->ResponderCookie, IKE_EXCHANGE_TYPE_QUICK,
			false, false, false, message_id, payload_list);

		// Build a temporary packet
		ps_buf = IkeBuild(ps, NULL);

		// Get the payload after the hash part
		after_hash_offset = sizeof(IKE_HEADER) + send_hash_payload->BitArray->Size + sizeof(IKE_COMMON_HEADER);
		after_hash_size = ((ps_buf->Size > after_hash_offset) ? (ps_buf->Size - after_hash_offset) : 0);

		ps_buf_after_hash = MemToBuf(((UCHAR *)ps_buf->Buf) + after_hash_offset, after_hash_size);
		FreeBuf(ps_buf);

		// Calculate the hash #1
		tmp_buf = NewBuf();
		WriteBufInt(tmp_buf, message_id);
		WriteBufBuf(tmp_buf, ps_buf_after_hash);
		IkeHMac(ike_sa->TransformSetting.Hash, hash1, ike_sa->SKEYID_a, ike_sa->HashSize, tmp_buf->Buf, tmp_buf->Size);
		FreeBuf(tmp_buf);

		// Overwrite hash #1
		Copy(send_hash_payload->Payload.Hash.Data->Buf, hash1, ike_sa->HashSize);

		// Create an IPsec SA
		ipsec_sa_c_s = NewIPsecSa(ike, c, ike_sa, true, message_id, false, iv, spi,
			initiator_rand->Buf, initiator_rand->Size, NULL, 0,
			&setting, shared_key, shared_key_size);

		ipsec_sa_s_c = NewIPsecSa(ike, c, ike_sa, true, message_id, true, iv, 0,
			initiator_rand->Buf, initiator_rand->Size, NULL, 0,
			&setting, shared_key, shared_key_size);

		ipsec_sa_c_s->PairIPsecSa = ipsec_sa_s_c;
		ipsec_sa_s_c->PairIPsecSa = ipsec_sa_c_s;

		ipsec_sa_s_c->Dh = dh;

		Insert(ike->IPsecSaList, ipsec_sa_c_s);
		Insert(ike->IPsecSaList, ipsec_sa_s_c);

		// Packet transmission
		ps->FlagEncrypted = true;
		IPsecSaSendPacket(ike, ipsec_sa_s_c, ps);
		ipsec_sa_s_c->NumResends = 3;
#ifdef	RAW_DEBUG
		IkeDebugUdpSendRawPacket(ps);
#endif	// RAW_DEBUG

		IkeFree(ps);
		Free(shared_key);
		FreeBuf(ps_buf_after_hash);
		FreeBuf(initiator_rand);
	}
}

// Process the quick mode received packet
void ProcIkeQuickModePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header)
{
	IKE_CLIENT *c;
	IKE_SA *ike_sa;
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL || header->InitiatorCookie == 0 || header->ResponderCookie == 0
		|| header->MessageId == 0 || header->FlagEncrypted == false)
	{
		return;
	}

	c = SearchOrCreateNewIkeClientForIkePacket(ike, &p->SrcIP, p->SrcPort, &p->DstIP, p->DestPort, header);

	if (c == NULL)
	{
		return;
	}

	ike_sa = FindIkeSaByResponderCookieAndClient(ike, header->ResponderCookie, c);

	if (ike_sa == NULL)
	{
		// IKE SA does not exist
		SendInformationalExchangePacketEx(ike, c, IkeNewNoticeErrorInvalidCookiePayload(header->InitiatorCookie,
			header->ResponderCookie), true, header->InitiatorCookie, header->ResponderCookie);
	}

	if (ike_sa != NULL && ike_sa->Established)
	{
		// Update the status of the IKE SA
		ike_sa->LastCommTick = ike->Now;
		ike_sa->IkeClient->LastCommTick = ike->Now;
		ike_sa->IkeClient->CurrentIkeSa = ike_sa;

		// Search whether the Message ID is already in the database
		if (SearchIPsecSaByMessageId(ike, c, header->MessageId) == NULL)
		{
			IKE_PACKET *pr;
			IKE_CRYPTO_PARAM cp;

			// Message ID does not exist. Start a new Quick Mode session
			Zero(&cp, sizeof(cp));
			cp.Key = ike_sa->CryptoKey;
			IkeCalcPhase2InitialIv(cp.Iv, ike_sa, header->MessageId);

			pr = IkeParse(p->Data, p->Size, &cp);
#ifdef	RAW_DEBUG
			IkeDebugUdpSendRawPacket(pr);
#endif	// RAW_DEBUG
			if (pr != NULL)
			{
				// Get the hash payload
				IKE_PACKET_PAYLOAD *hash_payload;

				hash_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_HASH, 0);
				if (hash_payload != NULL)
				{
					// Get the payload after the hash
					UINT header_and_hash_size = sizeof(IKE_COMMON_HEADER) + hash_payload->BitArray->Size;
					void *after_hash_data = ((UCHAR *)pr->DecryptedPayload->Buf) + header_and_hash_size;
					if (pr->DecryptedPayload->Size > header_and_hash_size)
					{
						UINT after_hash_size = pr->DecryptedPayload->Size - header_and_hash_size;
						UCHAR hash1[IKE_MAX_HASH_SIZE];
						BUF *hash1_buf;

						hash1_buf = NewBuf();
						WriteBufInt(hash1_buf, header->MessageId);
						WriteBuf(hash1_buf, after_hash_data, after_hash_size);

						IkeHMac(ike_sa->TransformSetting.Hash, hash1, ike_sa->SKEYID_a, ike_sa->HashSize,
							hash1_buf->Buf, hash1_buf->Size);

						// Compare the hash value
						if (IkeCompareHash(hash_payload, hash1, ike_sa->HashSize))
						{
							IKE_PACKET_PAYLOAD *sa_payload, *rand_payload, *key_payload, *id_payload_1, *id_payload_2;

							// Get the payload of other
							sa_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_SA, 0);
							rand_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_RAND, 0);
							key_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_KEY_EXCHANGE, 0);
							id_payload_1 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_ID, 0);
							id_payload_2 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_ID, 1);

							if (sa_payload != NULL && rand_payload != NULL)
							{
								IPSEC_SA_TRANSFORM_SETTING setting;

								Zero(&setting, sizeof(setting));

								// Interpret the SA payload
								if (GetBestTransformSettingForIPsecSa(ike, pr, &setting, &p->DstIP) && (GetNumberOfIPsecSaOfIkeClient(ike, c) <= IKE_QUOTA_MAX_SA_PER_CLIENT))
								{
									// Appropriate transform setting is selected
									Debug("P2 Transform: %s %s %s(%u) %u %u\n",
										(setting.Dh == NULL ? NULL : setting.Dh->Name), setting.Hash->Name, setting.Crypto->Name, setting.CryptoKeySize,
										setting.LifeKilobytes, setting.LifeSeconds);

#ifdef	FORCE_LIFETIME_QM
									setting.LifeSeconds = FORCE_LIFETIME_QM;
#endif	// FORCE_LIFETIME_QM

									// Cache the transform attribute value
									Copy(&c->CachedTransformSetting, &setting, sizeof(IPSEC_SA_TRANSFORM_SETTING));

									// Check the key exchange payload if the PFS is specified
									if (setting.Dh == NULL || (setting.Dh != NULL && key_payload != NULL &&
										key_payload->Payload.KeyExchange.Data->Size <= setting.Dh->KeySize))
									{
										// Create a payload for response
										IKE_PACKET *ps;
										LIST *payload_list;
										IKE_PACKET_PAYLOAD *send_hash_payload;
										IKE_PACKET_PAYLOAD *send_sa_payload;
										IKE_PACKET_PAYLOAD *send_proposal_payload;
										IKE_PACKET_PAYLOAD *send_transform_payload;
										IKE_PACKET_PAYLOAD *send_rand_payload;
										IKE_PACKET_PAYLOAD *send_key_payload = NULL;
										IKE_PACKET_PAYLOAD *send_id_1 = NULL, *send_id_2 = NULL;
										UCHAR dummy_hash_data[IKE_MAX_HASH_SIZE];
										DH_CTX *dh = NULL;
										UINT shared_key_size = 0;
										UCHAR *shared_key = NULL;
										BUF *initiator_rand, *responder_rand;
										IPSECSA *ipsec_sa_s_c, *ipsec_sa_c_s;
										BUF *ps_buf;
										UINT after_hash_offset, after_hash_size;
										BUF *ps_buf_after_hash;
										BUF *tmp_buf;
										UINT spi;
										UINT spi_be;
										UCHAR hash2[IKE_MAX_HASH_SIZE];
										UCHAR hash3[IKE_MAX_HASH_SIZE];
										UCHAR zero = 0;

										IPsecLog(ike, NULL, ike_sa, NULL, "LI_START_QM_FROM_CLIENT");

										initiator_rand = CloneBuf(rand_payload->Payload.Rand.Data);
										responder_rand = RandBuf(IKE_SA_RAND_SIZE);

										if (setting.Dh != NULL)
										{
											// Calculate DH
											dh = IkeDhNewCtx(setting.Dh);
											shared_key_size = (dh == NULL ? 0 : dh->Size);
											shared_key = ZeroMalloc(shared_key_size);

											if (DhCompute(dh, shared_key, key_payload->Payload.KeyExchange.Data->Buf, key_payload->Payload.KeyExchange.Data->Size))
											{
												// DH calculation success
												Debug("P2 DH Ok.\n");

												send_key_payload = IkeNewDataPayload(IKE_PAYLOAD_KEY_EXCHANGE,
													dh->MyPublicKey->Buf, dh->MyPublicKey->Size);

												IkeDhFreeCtx(dh);
											}
											else
											{
												// DH calculation failure
												Debug("P2 DhCompute failed.\n");

												shared_key = NULL;
												Free(shared_key);
												shared_key_size = 0;

												IPsecLog(ike, NULL, ike_sa, NULL, "LI_QM_DH_ERROR");
											}
										}

										Zero(dummy_hash_data, sizeof(dummy_hash_data));

										// Dummy hash value
										payload_list = NewListFast(NULL);
										send_hash_payload = IkeNewDataPayload(IKE_PAYLOAD_HASH, dummy_hash_data, ike_sa->HashSize);
										Add(payload_list, send_hash_payload);

										// Determine the SPI
										spi = GenerateNewIPsecSaSpi(ike, setting.SpiServerToClient);
										spi_be = Endian32(spi);

										// SA
										send_transform_payload = TransformSettingToTransformPayloadForIPsec(ike, &setting);
										send_proposal_payload = IkeNewProposalPayload(1, IKE_PROTOCOL_ID_IPSEC_ESP, &spi_be, sizeof(spi_be),
											NewListSingle(send_transform_payload));
										send_sa_payload = IkeNewSaPayload(NewListSingle(send_proposal_payload));
										Add(payload_list, send_sa_payload);

										// Random number
										send_rand_payload = IkeNewDataPayload(IKE_PAYLOAD_RAND, responder_rand->Buf, responder_rand->Size);
										Add(payload_list, send_rand_payload);

										// Key exchange
										if (send_key_payload != NULL)
										{
											Add(payload_list, send_key_payload);
										}

										// ID
										if (id_payload_1 != NULL && id_payload_2 != NULL)
										{
											send_id_1 = IkeNewIdPayload(id_payload_1->Payload.Id.Type,
												id_payload_1->Payload.Id.ProtocolId, id_payload_1->Payload.Id.Port,
												id_payload_1->Payload.Id.IdData->Buf, id_payload_1->Payload.Id.IdData->Size);

											send_id_2 = IkeNewIdPayload(id_payload_2->Payload.Id.Type,
												id_payload_2->Payload.Id.ProtocolId, id_payload_2->Payload.Id.Port,
												id_payload_2->Payload.Id.IdData->Buf, id_payload_2->Payload.Id.IdData->Size);

											Add(payload_list, send_id_1);
											Add(payload_list, send_id_2);

											if (c->SendID1_Buf != NULL)
											{
												FreeBuf(c->SendID1_Buf);
											}

											if (c->SendID2_Buf != NULL)
											{
												FreeBuf(c->SendID2_Buf);
											}

											c->SendID1_Type = id_payload_1->Payload.Id.Type;
											c->SendID1_Protocol = id_payload_1->Payload.Id.ProtocolId;
											c->SendID1_Port = id_payload_1->Payload.Id.Port;
											c->SendID1_Buf = CloneBuf(id_payload_1->Payload.Id.IdData);

											c->SendID2_Type = id_payload_2->Payload.Id.Type;
											c->SendID2_Protocol = id_payload_2->Payload.Id.ProtocolId;
											c->SendID2_Port = id_payload_2->Payload.Id.Port;
											c->SendID2_Buf = CloneBuf(id_payload_2->Payload.Id.IdData);

											c->SendID1andID2 = true;
										}
										else
										{
											c->SendID1andID2 = false;
										}

										if (true)
										{
											// Reply if NAT-OA payload is presented by the client
											IKE_PACKET_PAYLOAD *nat_oa_draft1 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_OA_DRAFT, 0);
											IKE_PACKET_PAYLOAD *nat_oa_draft2 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_OA_DRAFT_2, 0);
											IKE_PACKET_PAYLOAD *nat_oa_rfc_0 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_OA, 0);
											IKE_PACKET_PAYLOAD *nat_oa_rfc_1 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_OA, 1);

											c->SendNatOaDraft1 = c->SendNatOaDraft2 = c->SendNatOaRfc = false;

											c->ShouldCalcChecksumForUDP = false;

											if (nat_oa_draft1 != NULL)
											{
												Add(payload_list, IkeNewNatOaPayload(IKE_PAYLOAD_NAT_OA_DRAFT, &c->ServerIP));
												c->SendNatOaDraft1 = true;

												if (IsIP4(&nat_oa_draft1->Payload.NatOa.IpAddress) == IsIP4(&c->ServerIP))
												{
													Copy(&c->TransportModeClientIP, &nat_oa_draft1->Payload.NatOa.IpAddress, sizeof(IP));
													Copy(&c->TransportModeServerIP, &c->ServerIP, sizeof(IP));

													c->ShouldCalcChecksumForUDP = true;
												}
											}

											if (nat_oa_draft2 != NULL)
											{
												Add(payload_list, IkeNewNatOaPayload(IKE_PAYLOAD_NAT_OA_DRAFT_2, &c->ServerIP));
												c->SendNatOaDraft2 = true;

												if (IsIP4(&nat_oa_draft2->Payload.NatOa.IpAddress) == IsIP4(&c->ServerIP))
												{
													Copy(&c->TransportModeClientIP, &nat_oa_draft2->Payload.NatOa.IpAddress, sizeof(IP));
													Copy(&c->TransportModeServerIP, &c->ServerIP, sizeof(IP));

													c->ShouldCalcChecksumForUDP = true;
												}
											}

											if (nat_oa_rfc_0 != NULL && nat_oa_rfc_1 != NULL)
											{
												Add(payload_list, IkeNewNatOaPayload(IKE_PAYLOAD_NAT_OA, &c->ClientIP));
												Add(payload_list, IkeNewNatOaPayload(IKE_PAYLOAD_NAT_OA, &c->ServerIP));
												c->SendNatOaRfc = true;

												if (IsIP4(&nat_oa_rfc_0->Payload.NatOa.IpAddress) == IsIP4(&c->ServerIP))
												{
													Copy(&c->TransportModeClientIP, &nat_oa_rfc_0->Payload.NatOa.IpAddress, sizeof(IP));
													Copy(&c->TransportModeServerIP, &c->ServerIP, sizeof(IP));

													c->ShouldCalcChecksumForUDP = true;
												}
											}
										}

										// Build a packet
										ps = IkeNew(ike_sa->InitiatorCookie, ike_sa->ResponderCookie, IKE_EXCHANGE_TYPE_QUICK,
											false, false, false, header->MessageId, payload_list);

										// Build a temporary packet
										ps_buf = IkeBuild(ps, NULL);

										// Get the payload after the hash part
										after_hash_offset = sizeof(IKE_HEADER) + send_hash_payload->BitArray->Size + sizeof(IKE_COMMON_HEADER);
										after_hash_size = ((ps_buf->Size > after_hash_offset) ? (ps_buf->Size - after_hash_offset) : 0);

										ps_buf_after_hash = MemToBuf(((UCHAR *)ps_buf->Buf) + after_hash_offset, after_hash_size);
										FreeBuf(ps_buf);

										// Calculate the hash #2
										tmp_buf = NewBuf();
										WriteBufInt(tmp_buf, header->MessageId);
										WriteBufBuf(tmp_buf, initiator_rand);
										WriteBufBuf(tmp_buf, ps_buf_after_hash);
										IkeHMac(ike_sa->TransformSetting.Hash, hash2, ike_sa->SKEYID_a, ike_sa->HashSize, tmp_buf->Buf, tmp_buf->Size);
										FreeBuf(tmp_buf);

										// Calculate the hash #3
										tmp_buf = NewBuf();
										WriteBuf(tmp_buf, &zero, 1);
										WriteBufInt(tmp_buf, header->MessageId);
										WriteBufBuf(tmp_buf, initiator_rand);
										WriteBufBuf(tmp_buf, responder_rand);
										IkeHMac(ike_sa->TransformSetting.Hash, hash3, ike_sa->SKEYID_a, ike_sa->HashSize, tmp_buf->Buf, tmp_buf->Size);
										FreeBuf(tmp_buf);

										// Create an IPsec SA
										ipsec_sa_c_s = NewIPsecSa(ike, c, ike_sa, false, header->MessageId, false, cp.NextIv, spi,
											initiator_rand->Buf, initiator_rand->Size, responder_rand->Buf, responder_rand->Size,
											&setting, shared_key, shared_key_size);
										ipsec_sa_s_c = NewIPsecSa(ike, c, ike_sa, false, header->MessageId, true, cp.NextIv, setting.SpiServerToClient,
											initiator_rand->Buf, initiator_rand->Size, responder_rand->Buf, responder_rand->Size,
											&setting, shared_key, shared_key_size);

										ipsec_sa_c_s->PairIPsecSa = ipsec_sa_s_c;
										ipsec_sa_s_c->PairIPsecSa = ipsec_sa_c_s;

										Insert(ike->IPsecSaList, ipsec_sa_c_s);
										Insert(ike->IPsecSaList, ipsec_sa_s_c);

										Copy(ipsec_sa_c_s->Hash3, hash3, ike_sa->HashSize);

										// Overwrite hash #2
										Copy(send_hash_payload->Payload.Hash.Data->Buf, hash2, ike_sa->HashSize);

										// Packet reply
										ps->FlagEncrypted = true;
										IPsecSaSendPacket(ike, ipsec_sa_s_c, ps);
										IkeSaSendPacket(ike, ike_sa, NULL);

#ifdef	RAW_DEBUG
										IkeDebugUdpSendRawPacket(ps);
#endif	// RAW_DEBUG

										IkeFree(ps);
										Free(shared_key);
										FreeBuf(ps_buf_after_hash);
										FreeBuf(initiator_rand);
										FreeBuf(responder_rand);
									}
								}
								else
								{
									// No appropriate transform setting
									Debug("No Appropriate Transform was Found.\n");

									IPsecLog(ike, NULL, ike_sa, NULL, "LI_IPSEC_NO_TRANSFORM");

									SendInformationalExchangePacket(ike, c, IkeNewNoticeErrorNoProposalChosenPayload(true, header->InitiatorCookie, header->ResponderCookie));
								}
							}
						}
						else
						{
							Debug("QM-1: Hash 1 is invalid.\n");
						}

						FreeBuf(hash1_buf);
					}
				}

				IkeFree(pr);
			}
		}
		else
		{
			// Get the IPsec SA
			IPSECSA *ipsec_sa_cs = SearchIPsecSaByMessageId(ike, c, header->MessageId);
			if (ipsec_sa_cs != NULL)
			{
				IPSECSA *ipsec_sa_sc = ipsec_sa_cs->PairIPsecSa;
				if (ipsec_sa_sc != NULL)
				{
					if (ipsec_sa_sc->Established == false && ipsec_sa_cs->Established == false)
					{
						IKE_PACKET *pr = IPsecSaRecvPacket(ike, ipsec_sa_cs, p->Data, p->Size);

#ifdef	RAW_DEBUG
						IkeDebugUdpSendRawPacket(pr);
#endif	// RAW_DEBUG

						if (pr != NULL)
						{
							if (ipsec_sa_cs->Initiated == false)
							{
								// Initiator is client-side
								// Check hash3 payload
								IKE_PACKET_PAYLOAD *hash_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_HASH, 0);

								if (hash_payload != NULL)
								{
									BUF *hash_buf = hash_payload->Payload.Hash.Data;
									if (hash_buf != NULL)
									{
										if (hash_buf->Size == ipsec_sa_cs->IkeSa->HashSize)
										{
											if (Cmp(hash_buf->Buf, ipsec_sa_cs->Hash3, hash_buf->Size) == 0)
											{
												ipsec_sa_cs->Established = ipsec_sa_sc->Established = true;
												ipsec_sa_cs->EstablishedTick = ipsec_sa_sc->EstablishedTick = ike->Now;
												ipsec_sa_cs->LastCommTick = ipsec_sa_sc->LastCommTick = ike->Now;

												c->CurrentIpSecSaRecv = ipsec_sa_cs;
												c->CurrentIpSecSaSend = ipsec_sa_sc;

												Debug("IPsec SA 0x%X & 0x%X Established.\n",
													ipsec_sa_cs->Spi,
													ipsec_sa_sc->Spi);

												IPsecLog(ike, NULL, NULL, ipsec_sa_sc, "LI_IPSEC_SA_ESTABLISHED");

												IPsecSaSendPacket(ike, ipsec_sa_sc, NULL);
											}
											else
											{
												Debug("QM-3: Hash 3 is invalid.\n");
											}
										}
									}
								}
							}
							else
							{
								// Initiator is server-side
								// Get hash payload
								IKE_PACKET_PAYLOAD *hash_payload;

								hash_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_HASH, 0);
								if (hash_payload != NULL && ipsec_sa_sc->InitiatorRand != NULL)
								{
									// Get the payload after the hash
									UINT header_and_hash_size = sizeof(IKE_COMMON_HEADER) + hash_payload->BitArray->Size;
									void *after_hash_data = ((UCHAR *)pr->DecryptedPayload->Buf) + header_and_hash_size;
									if (pr->DecryptedPayload->Size > header_and_hash_size)
									{
										UINT after_hash_size = pr->DecryptedPayload->Size - header_and_hash_size;
										UCHAR hash2[IKE_MAX_HASH_SIZE];
										BUF *hash2_buf;

										hash2_buf = NewBuf();
										WriteBufInt(hash2_buf, header->MessageId);
										WriteBufBuf(hash2_buf, ipsec_sa_sc->InitiatorRand);
										WriteBuf(hash2_buf, after_hash_data, after_hash_size);

										IkeHMac(ipsec_sa_sc->SKEYID_Hash, hash2, ipsec_sa_sc->SKEYID_a, ipsec_sa_sc->SKEYID_Hash->HashSize,
											hash2_buf->Buf, hash2_buf->Size);

										FreeBuf(hash2_buf);

										// Compare the hash value
										if (IkeCompareHash(hash_payload, hash2, ike_sa->HashSize))
										{
											IKE_PACKET_PAYLOAD *sa_payload, *rand_payload, *key_payload, *id_payload_1, *id_payload_2;

											// Get the payload of other
											sa_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_SA, 0);
											rand_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_RAND, 0);
											key_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_KEY_EXCHANGE, 0);
											id_payload_1 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_ID, 0);
											id_payload_2 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_ID, 1);

											if (sa_payload != NULL && rand_payload != NULL)
											{
												IPSEC_SA_TRANSFORM_SETTING setting;

												// Interpret the SA payload
												if (GetBestTransformSettingForIPsecSa(ike, pr, &setting, &p->DstIP))
												{
													// Appropriate transform setting is selected
													Debug("P2 Transform: %s %s %s(%u) %u %u\n",
														(setting.Dh == NULL ? NULL : setting.Dh->Name), setting.Hash->Name, setting.Crypto->Name, setting.CryptoKeySize,
														setting.LifeKilobytes, setting.LifeSeconds);

#ifdef	FORCE_LIFETIME_QM
													setting.LifeSeconds = FORCE_LIFETIME_QM;
#endif	// FORCE_LIFETIME_QM

													// Check the key exchange payload if the PFS is specified
													if (setting.Dh == NULL || (setting.Dh != NULL && key_payload != NULL && ipsec_sa_sc->Dh != NULL &&
														key_payload->Payload.KeyExchange.Data->Size <= setting.Dh->KeySize))
													{
														IKE_PACKET *ps;
														LIST *payload_list;
														IKE_PACKET_PAYLOAD *send_hash_payload;
														IKE_PACKET_PAYLOAD *send_key_payload = NULL;
														IKE_PACKET_PAYLOAD *send_id_1 = NULL, *send_id_2 = NULL;
														DH_CTX *dh = NULL;
														UINT shared_key_size = 0;
														UCHAR *shared_key = NULL;
														BUF *initiator_rand, *responder_rand;
														BUF *tmp_buf;
														UCHAR hash3[IKE_MAX_HASH_SIZE];
														char tmp[MAX_SIZE];
														UCHAR zero = 0;

														initiator_rand = ipsec_sa_sc->InitiatorRand;
														responder_rand = CloneBuf(rand_payload->Payload.Rand.Data);

														if (setting.Dh != NULL)
														{
															// Calculate DH
															DH_CTX *dh = ipsec_sa_sc->Dh;

															shared_key_size = (dh == NULL ? 0 : dh->Size);
															shared_key = ZeroMalloc(shared_key_size);

															if (DhCompute(dh, shared_key, key_payload->Payload.KeyExchange.Data->Buf, key_payload->Payload.KeyExchange.Data->Size))
															{
																// DH calculation success
																Debug("P2 DH Ok.\n");
															}
															else
															{
																// DH calculation failure
																Debug("P2 DhCompute failed.\n");

																shared_key = NULL;
																Free(shared_key);
																shared_key_size = 0;

																IPsecLog(ike, NULL, ike_sa, NULL, "LI_QM_DH_ERROR");
															}
														}

														// Update the information of IPsec SA
														if (shared_key != NULL)
														{
															ipsec_sa_sc->SharedKey = NewBuf(shared_key, shared_key_size);
															ipsec_sa_cs->SharedKey = NewBuf(shared_key, shared_key_size);
														}

														ipsec_sa_sc->Spi = setting.SpiServerToClient;
														IPsecLog(ike, NULL, NULL, ipsec_sa_sc, "LI_IPSEC_SA_SPI_SET", ipsec_sa_sc->Spi);
														ike->IPsecSaList->sorted = false;

														ipsec_sa_sc->ResponderRand = CloneBuf(responder_rand);
														ipsec_sa_cs->ResponderRand = CloneBuf(responder_rand);

														Copy(&ipsec_sa_sc->TransformSetting, &setting, sizeof(IPSEC_SA_TRANSFORM_SETTING));
														Copy(&ipsec_sa_cs->TransformSetting, &setting, sizeof(IPSEC_SA_TRANSFORM_SETTING));

														ipsec_sa_sc->Established = true;
														ipsec_sa_cs->Established = true;

														IPsecLog(ike, NULL, NULL, ipsec_sa_sc, "LI_IPSEC_SA_ESTABLISHED");

														ipsec_sa_sc->LastCommTick = ike->Now;
														ipsec_sa_cs->LastCommTick = ike->Now;

														c->CurrentIpSecSaRecv = ipsec_sa_cs;
														c->CurrentIpSecSaSend = ipsec_sa_sc;

														// Calculate the KEYMAT
														IPsecCalcKeymat(ike, ipsec_sa_sc->SKEYID_Hash, ipsec_sa_sc->KeyMat, sizeof(ipsec_sa_sc->KeyMat),
															ipsec_sa_sc->SKEYID_d, ipsec_sa_sc->SKEYID_Hash->HashSize, IKE_PROTOCOL_ID_IPSEC_ESP,
															ipsec_sa_sc->Spi, initiator_rand->Buf, initiator_rand->Size,
															responder_rand->Buf, responder_rand->Size,
															shared_key, shared_key_size);

														IPsecCalcKeymat(ike, ipsec_sa_cs->SKEYID_Hash, ipsec_sa_cs->KeyMat, sizeof(ipsec_sa_cs->KeyMat),
															ipsec_sa_cs->SKEYID_d, ipsec_sa_cs->SKEYID_Hash->HashSize, IKE_PROTOCOL_ID_IPSEC_ESP,
															ipsec_sa_cs->Spi, initiator_rand->Buf, initiator_rand->Size,
															responder_rand->Buf, responder_rand->Size,
															shared_key, shared_key_size);

														IkeFreeKey(ipsec_sa_sc->CryptoKey);
														IkeFreeKey(ipsec_sa_cs->CryptoKey);

														ipsec_sa_sc->CryptoKey = IkeNewKey(setting.Crypto, ipsec_sa_sc->KeyMat, setting.CryptoKeySize);
														ipsec_sa_cs->CryptoKey = IkeNewKey(setting.Crypto, ipsec_sa_cs->KeyMat, setting.CryptoKeySize);

														Copy(ipsec_sa_sc->HashKey, ipsec_sa_sc->KeyMat + setting.CryptoKeySize, setting.Hash->HashSize);
														Copy(ipsec_sa_cs->HashKey, ipsec_sa_cs->KeyMat + setting.CryptoKeySize, setting.Hash->HashSize);

														BinToStrEx(tmp, sizeof(tmp), ipsec_sa_sc->KeyMat, ipsec_sa_sc->TransformSetting.CryptoKeySize);
														Debug("  KEYMAT (SC): %s\n", tmp);

														BinToStrEx(tmp, sizeof(tmp), ipsec_sa_cs->KeyMat, ipsec_sa_cs->TransformSetting.CryptoKeySize);
														Debug("  KEYMAT (CS): %s\n", tmp);

														Debug("IPsec SA 0x%X & 0x%X Established (Server is Initiator).\n",
															ipsec_sa_cs->Spi,
															ipsec_sa_sc->Spi);

														// Calculate the hash #3
														tmp_buf = NewBuf();
														WriteBuf(tmp_buf, &zero, 1);
														WriteBufInt(tmp_buf, header->MessageId);
														WriteBufBuf(tmp_buf, initiator_rand);
														WriteBufBuf(tmp_buf, responder_rand);
														IkeHMac(ipsec_sa_cs->SKEYID_Hash, hash3, ipsec_sa_cs->SKEYID_a, ipsec_sa_cs->SKEYID_Hash->HashSize, tmp_buf->Buf, tmp_buf->Size);
														FreeBuf(tmp_buf);

														// Return the hash #3
														send_hash_payload = IkeNewDataPayload(IKE_PAYLOAD_HASH, hash3, ipsec_sa_cs->SKEYID_Hash->HashSize);

														payload_list = NewListSingle(send_hash_payload);
														ps = IkeNew(ike_sa->InitiatorCookie, ike_sa->ResponderCookie,
															IKE_EXCHANGE_TYPE_QUICK, true, false, false, header->MessageId, payload_list);

														IPsecSaSendPacket(ike, ipsec_sa_sc, ps);
#ifdef	RAW_DEBUG
														IkeDebugUdpSendRawPacket(ps);
#endif	// RAW_DEBUG
														ipsec_sa_sc->NumResends = 3;

														if (false)
														{
															UINT i;

															for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
															{
																IPSECSA *sa = LIST_DATA(ike->IPsecSaList, i);

																if (sa != ipsec_sa_sc && sa != ipsec_sa_cs)
																{
																	MarkIPsecSaAsDeleted(ike, sa);
																}
															}
														}

														IkeFree(ps);

														// Release the memory
														FreeBuf(responder_rand);
													}
												}
												else
												{
													// No appropriate transform setting
													Debug("No Appropriate Transform was Found.\n");

													IPsecLog(ike, NULL, ike_sa, NULL, "LI_IPSEC_NO_TRANSFORM");

													SendInformationalExchangePacket(ike, c, IkeNewNoticeErrorNoProposalChosenPayload(true, header->InitiatorCookie, header->ResponderCookie));
												}
											}
										}
									}
								}
							}
							IkeFree(pr);
						}
					}
				}
			}
		}
	}
}

// Calculate the KEYMAT
void IPsecCalcKeymat(IKE_SERVER *ike, IKE_HASH *h, void *dst, UINT dst_size, void *skeyid_d_data, UINT skeyid_d_size, UCHAR protocol, UINT spi, void *rand_init_data, UINT rand_init_size,
					 void *rand_resp_data, UINT rand_resp_size, void *df_key_data, UINT df_key_size)
{
	BUF *k;
	BUF *ret;
	// Validate arguments
	if (ike == NULL || dst == NULL || h == NULL || rand_init_data == NULL || rand_resp_data == NULL||
		(df_key_size != 0 && df_key_data == NULL))
	{
		return;
	}

	ret = NewBuf();

	k = NULL;

	while (true)
	{
		BUF *tmp = NewBuf();
		UCHAR hash[IKE_MAX_HASH_SIZE];

		if (k != NULL)
		{
			WriteBufBuf(tmp, k);
		}

		if (df_key_data != NULL)
		{
			WriteBuf(tmp, df_key_data, df_key_size);
		}

		WriteBuf(tmp, &protocol, 1);

		WriteBufInt(tmp, spi);

		WriteBuf(tmp, rand_init_data, rand_init_size);
		WriteBuf(tmp, rand_resp_data, rand_resp_size);

		if (k != NULL)
		{
			FreeBuf(k);
		}

		IkeHMac(h, hash, skeyid_d_data, skeyid_d_size, tmp->Buf, tmp->Size);

		FreeBuf(tmp);

		k = MemToBuf(hash, h->HashSize);

		WriteBufBuf(ret, k);

		if (ret->Size >= dst_size)
		{
			break;
		}
	}

	Copy(dst, ret->Buf, dst_size);

	FreeBuf(ret);
	FreeBuf(k);
}

// Search for IPsec SA from Message ID
IPSECSA *SearchIPsecSaByMessageId(IKE_SERVER *ike, IKE_CLIENT *c, UINT message_id)
{
	UINT i;
	// Validate arguments
	if (ike == NULL || c == NULL || message_id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
	{
		IPSECSA *sa = LIST_DATA(ike->IPsecSaList, i);

		if (sa->IkeClient == c)
		{
			if (sa->MessageId == message_id)
			{
				if (sa->ServerToClient == false)
				{
					if (sa->Established == false)
					{
						return sa;
					}
				}
			}
		}
	}

	return NULL;
}

// Search for IPsec SA from SPI value
IPSECSA *SearchClientToServerIPsecSaBySpi(IKE_SERVER *ike, UINT spi)
{
	IPSECSA t;
	// Validate arguments
	if (ike == NULL || spi == 0)
	{
		return NULL;
	}

	t.ServerToClient = false;
	t.Spi = spi;

	return Search(ike->IPsecSaList, &t);
}
IPSECSA *SearchIPsecSaBySpi(IKE_SERVER *ike, IKE_CLIENT *c, UINT spi)
{
	UINT i;
	// Validate arguments
	if (ike == NULL || c == NULL || spi == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
	{
		IPSECSA *sa = LIST_DATA(ike->IPsecSaList, i);

		if (sa->Spi == spi)
		{
			if (sa->IkeClient == c)
			{
				return sa;
			}
		}
	}

	return NULL;
}

// Search an IKE SA from the value of the Cookie
IKE_SA *SearchIkeSaByCookie(IKE_SERVER *ike, UINT64 init_cookie, UINT64 resp_cookie)
{
	UINT i;
	// Validate arguments
	if (ike == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
	{
		IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);

		if (sa->InitiatorCookie == init_cookie && sa->ResponderCookie == resp_cookie)
		{
			return sa;
		}
	}

	return NULL;
}

// Generate the SPI value of new IPsec SA
UINT GenerateNewIPsecSaSpi(IKE_SERVER *ike, UINT counterpart_spi)
{
	UINT ret;
	// Validate arguments
	if (ike == NULL)
	{
		return 0;
	}

	while (true)
	{
		ret = Rand32();

		if (ret != counterpart_spi)
		{
			if (ret >= 4096 && ret != INFINITE)
			{
				if (SearchClientToServerIPsecSaBySpi(ike, ret) == NULL)
				{
					return ret;
				}
			}
		}
	}
}

// Calculate the initial IV for Phase 2
void IkeCalcPhase2InitialIv(void *iv, IKE_SA *sa, UINT message_id)
{
	BUF *b;
	UCHAR hash[IKE_MAX_HASH_SIZE];
	// Validate arguments
	if (iv == NULL || sa == NULL)
	{
		return;
	}

	message_id = Endian32(message_id);

	b = NewBuf();
	WriteBuf(b, sa->Iv, sa->BlockSize);
	WriteBuf(b, &message_id, sizeof(UINT));

	IkeHash(sa->TransformSetting.Hash, hash, b->Buf, b->Size);

	Copy(iv, hash, sa->TransformSetting.Crypto->BlockSize);

	FreeBuf(b);
}

// Create a new IPsec SA
IPSECSA *NewIPsecSa(IKE_SERVER *ike, IKE_CLIENT *c, IKE_SA *ike_sa, bool initiate, UINT message_id, bool server_to_client, void *iv, UINT spi, void *init_rand_data, UINT init_rand_size, void *res_rand_data, UINT res_rand_size, IPSEC_SA_TRANSFORM_SETTING *setting, void *shared_key_data, UINT shared_key_size)
{
	IPSECSA *sa;
	char tmp[MAX_SIZE];
	UINT total_key_size;
	// Validate arguments
	if (ike == NULL || c == NULL || ike_sa == NULL || message_id == 0 || iv == NULL || setting == NULL ||
		(shared_key_data == NULL && shared_key_size != 0))
	{
		return NULL;
	}

	sa = ZeroMalloc(sizeof(IPSECSA));

	if (server_to_client == false)
	{
		ike->CurrentIPsecSaId++;
	}
	sa->Id = ike->CurrentIPsecSaId;

	sa->IkeClient = c;
	sa->IkeSa = ike_sa;

	sa->MessageId = message_id;
	sa->FirstCommTick = ike->Now;
	sa->LastCommTick = ike->Now;
	sa->Initiated = initiate;

	sa->ServerToClient = server_to_client;

	sa->Spi = spi;

	sa->SKEYID_Hash = ike_sa->TransformSetting.Hash;
	Copy(sa->SKEYID_a, ike_sa->SKEYID_a, sa->SKEYID_Hash->HashSize);
	Copy(sa->SKEYID_d, ike_sa->SKEYID_d, sa->SKEYID_Hash->HashSize);

	sa->InitiatorRand = MemToBuf(init_rand_data, init_rand_size);

	if (initiate == false)
	{
		sa->ResponderRand = MemToBuf(res_rand_data, res_rand_size);
	}

	Copy(sa->Iv, iv, ike_sa->BlockSize);

	Copy(&sa->TransformSetting, setting, sizeof(IPSEC_SA_TRANSFORM_SETTING));

	if (shared_key_data != NULL)
	{
		sa->SharedKey = MemToBuf(shared_key_data, shared_key_size);
	}

	total_key_size = sa->TransformSetting.CryptoKeySize + sa->TransformSetting.Hash->HashSize;

	if (initiate == false)
	{
		IPsecCalcKeymat(ike, ike_sa->TransformSetting.Hash, sa->KeyMat, total_key_size,
			ike_sa->SKEYID_d, ike_sa->HashSize, IKE_PROTOCOL_ID_IPSEC_ESP, spi, sa->InitiatorRand->Buf,
			sa->InitiatorRand->Size, sa->ResponderRand->Buf, sa->ResponderRand->Size,
			shared_key_data, shared_key_size);

		sa->CryptoKey = IkeNewKey(sa->TransformSetting.Crypto, sa->KeyMat, sa->TransformSetting.CryptoKeySize);

		Copy(sa->HashKey, sa->KeyMat + sa->TransformSetting.CryptoKeySize, sa->TransformSetting.Hash->HashSize);
	}

	Debug("New IPsec SA (StoC = %u): 0x%X 0x%X (%s %s %s(%u) %u %u)\n",
		sa->ServerToClient,
		sa->MessageId,
		sa->Spi,
		(setting->Dh == NULL ? NULL : setting->Dh->Name), setting->Hash->Name, setting->Crypto->Name, setting->CryptoKeySize,
		setting->LifeKilobytes, setting->LifeSeconds);

	IPsecLog(ike, c, NULL, sa, "LI_NEW_IPSEC_SA",
		(sa->ServerToClient ? _UU("LI_TAG_SERVER_TO_CLIENT") : _UU("LI_TAG_CLIENT_TO_SERVER")),
		sa->Spi,
		(setting->Dh == NULL ? NULL : setting->Dh->Name), setting->Hash->Name, setting->Crypto->Name, setting->CryptoKeySize * 8,
		setting->LifeKilobytes, setting->LifeSeconds);

	Rand(sa->EspIv, sizeof(sa->EspIv));

	if (initiate == false)
	{
		BinToStrEx(tmp, sizeof(tmp), sa->KeyMat, sa->TransformSetting.CryptoKeySize);
		Debug("  KEYMAT: %s\n", tmp);
	}

	// Set the expiration time
	if (setting->LifeSeconds != 0)
	{
		UINT64 span = (UINT64)(setting->LifeSeconds * 1000) + (UINT64)IKE_SOFT_EXPIRES_MARGIN;
		sa->ExpiresHardTick = ike->Now + span;
		sa->ExpiresSoftTick = ike->Now + span;
		//sa->ExpiresSoftTick = ike->Now + (UINT64)5000;

		AddInterrupt(ike->Interrupts, sa->ExpiresSoftTick);
	}

	return sa;
}

// Treat aggressive mode packet reception
void ProcIkeAggressiveModePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header)
{
	IKE_CLIENT *c;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL || header->InitiatorCookie == 0)
	{
		return;
	}

	c = SearchOrCreateNewIkeClientForIkePacket(ike, &p->SrcIP, p->SrcPort, &p->DstIP, p->DestPort, header);

	if (c == NULL)
	{
		return;
	}

	if (header->ResponderCookie == 0)
	{
		// Start process of the state 1
		IKE_CAPS caps;
		IKE_SA *sa;
		IKE_PACKET *pr = IkeParse(p->Data, p->Size, NULL);

		if (pr != NULL)
		{
			// Determine the CAPS
			IkeCheckCaps(&caps, pr);
			if (caps.MS_L2TPIPSecVPNClient || caps.MS_NT5_ISAKMP_OAKLEY || caps.MS_Vid_InitialContact)
			{
				c->IsMicrosoft = true;
			}

			if ((caps.NatTraversalDraftIetf || caps.NatTraversalRfc3947) || (IsUdpPortOpened(ike->IPsec->UdpListener, &p->DstIP, IPSEC_PORT_IPSEC_ESP_RAW)))
			{
				sa = FindIkeSaByEndPointAndInitiatorCookie(ike, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort, header->InitiatorCookie, IKE_SA_AGRESSIVE_MODE);

				if (sa == NULL)
				{
					// Check whether there is acceptable SA parameters by analyzing proposed parameters
					IKE_SA_TRANSFORM_SETTING setting;

					if (GetBestTransformSettingForIkeSa(ike, pr, &setting) && (GetNumberOfIkeSaOfIkeClient(ike, c) <= IKE_QUOTA_MAX_SA_PER_CLIENT))
					{
						IKE_PACKET_PAYLOAD *tp;
						IKE_PACKET_PAYLOAD *pp;
						IKE_PACKET_PAYLOAD *sap;
						IKE_PACKET_PAYLOAD *client_sa_payload;
						IKE_PACKET_PAYLOAD *your_key_payload;
						IKE_PACKET_PAYLOAD *your_rand_payload;
						IKE_PACKET_PAYLOAD *your_id_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_ID, 0);

						// Appropriate transform setting is selected
						Debug("P1 Transform: %s %s %s(%u) %u %u\n",
							setting.Dh->Name, setting.Hash->Name, setting.Crypto->Name, setting.CryptoKeySize,
							setting.LifeKilobytes, setting.LifeSeconds);

						// Receive a key exchange packet
						your_key_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_KEY_EXCHANGE, 0);
						your_rand_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_RAND, 0);
						if (your_key_payload != NULL && your_rand_payload != NULL && your_id_payload != NULL)
						{
							// Check the key payload
							BUF *your_key_buf = your_key_payload->Payload.KeyExchange.Data;
							BUF *your_rand_buf = your_rand_payload->Payload.Rand.Data;

							// DH generation
							DH_CTX *dh = IkeDhNewCtx(setting.Dh);
							UINT shared_key_size = (dh == NULL ? 0 : dh->Size);
							UCHAR *shared_key = ZeroMalloc(shared_key_size);

							// DH calculation
							if (DhCompute(dh, shared_key, your_key_buf->Buf, your_key_buf->Size))
							{
								IKE_PACKET *ps;
								LIST *payload_list;
								IKE_PACKET_PAYLOAD *my_key_payload;
								IKE_PACKET_PAYLOAD *my_rand_payload;
								BUF *nat_buf1, *nat_buf2;
								BUF *iv_buf;
								UCHAR iv_hashed_data[IKE_MAX_HASH_SIZE];
								UCHAR initiator_hash[IKE_MAX_HASH_SIZE];
								BUF *b;
								IKE_PACKET_PAYLOAD *my_id_payload, *my_hash_payload;
								UCHAR responder_hash[IKE_MAX_HASH_SIZE];
								BUF *idir_b;
								IKE_PACKET_PAYLOAD *your_nat_d_1 = NULL;
								IKE_PACKET_PAYLOAD *your_nat_d_2 = NULL;

								// Create an IKE SA
								sa = NewIkeSa(ike, c, header->InitiatorCookie, IKE_SA_AGRESSIVE_MODE, &setting);
								Copy(&sa->Caps, &caps, sizeof(IKE_CAPS));
								sa->State= IKE_SA_AM_STATE_1_SA;
								Insert(ike->IkeSaList, sa);

								sa->HashSize = sa->TransformSetting.Hash->HashSize;
								sa->KeySize = sa->TransformSetting.CryptoKeySize;
								sa->BlockSize = sa->TransformSetting.Crypto->BlockSize;

								// Get the Caps additionally
								if (sa->Caps.NatTraversalRfc3947)
								{
									sa->Caps.UsingNatTraversalRfc3947 = true;

									your_nat_d_1 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_D, 0);
									your_nat_d_2 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_D, 1);
								}
								else if (sa->Caps.NatTraversalDraftIetf)
								{
									sa->Caps.UsingNatTraversalDraftIetf = true;

									your_nat_d_1 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_D_DRAFT, 0);
									your_nat_d_2 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_D_DRAFT, 1);
								}

								// Calculation success
								sa->DhSharedKey = MemToBuf(shared_key, shared_key_size);
								sa->InitiatorRand = RandBuf(IKE_SA_RAND_SIZE);
								sa->ResponderRand = CloneBuf(your_rand_buf);

								// Save a bit array of SA payload presented by the client
								client_sa_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_SA, 0);
								sa->SAi_b = CloneBuf(client_sa_payload->BitArray);

								// Save the ID payload presented by the client
								sa->YourIDPayloadForAM = CloneBuf(your_id_payload->BitArray);

								//// Assemble the SA payload
								// Construct transform payload
								tp = TransformSettingToTransformPayloadForIke(ike, &setting);

								// Build a proposal payload
								pp = IkeNewProposalPayload(1, IKE_PROTOCOL_ID_IKE, NULL, 0, NewListSingle(tp));

								// Build the SA payload
								sap = IkeNewSaPayload(NewListSingle(pp));

								payload_list = NewListSingle(sap);

								// Send a key exchange packet
								my_key_payload = IkeNewDataPayload(IKE_PAYLOAD_KEY_EXCHANGE, dh->MyPublicKey->Buf, dh->MyPublicKey->Size);
								my_rand_payload = IkeNewDataPayload(IKE_PAYLOAD_RAND, sa->InitiatorRand->Buf, sa->InitiatorRand->Size);

								Add(payload_list, my_key_payload);
								Add(payload_list, my_rand_payload);

								// NAT-D Packet
								// Address of the opponent. Randomize in order to be forced to use NAT
								nat_buf1 = IkeCalcNatDetectHash(ike, sa->TransformSetting.Hash, Rand64(), Rand64(), &c->ClientIP, Rand16());

								// My address
								if (c->IsMicrosoft == false || (your_nat_d_1 == NULL || your_nat_d_2 == NULL || your_nat_d_1->BitArray == NULL))
								{
									// Calculate exactly
									nat_buf2 = IkeCalcNatDetectHash(ike, sa->TransformSetting.Hash,
										sa->InitiatorCookie, sa->ResponderCookie, &c->ServerIP, c->ServerPort);
								}
								else
								{
									// Parrot the NAT_D payload indicating myself I got from
									// the other if it has connected from a Microsoft VPN Client
									nat_buf2 = CloneBuf(your_nat_d_1->BitArray);
								}

								// Save DH information
								sa->GXi = CloneBuf(your_key_buf);
								sa->GXr = CloneBuf(dh->MyPublicKey);

								// Calculate the key set
								IkeCalcSaKeySet(ike, sa, NULL);

								// Calculate the initiator side hash value
								b = NewBuf();
								WriteBufBuf(b, sa->GXi);
								WriteBufBuf(b, sa->GXr);
								WriteBufInt64(b, sa->InitiatorCookie);
								WriteBufInt64(b, sa->ResponderCookie);
								WriteBufBuf(b, sa->SAi_b);
								WriteBufBuf(b, sa->YourIDPayloadForAM);

								IkeHMac(sa->TransformSetting.Hash, initiator_hash, sa->SKEYID, sa->HashSize,
									b->Buf, b->Size);

								FreeBuf(b);

								Copy(sa->InitiatorHashForAM, initiator_hash, sa->HashSize);

								// Prepare the response ID payload
								// Generate the ID payload
								if (IsIP6(&sa->IkeClient->ServerIP))
								{
									// IPv6 address
									my_id_payload = IkeNewIdPayload(IKE_ID_IPV6_ADDR, 0, 0, sa->IkeClient->ServerIP.ipv6_addr, 16);
								}
								else
								{
									// IPv4 address
									my_id_payload = IkeNewIdPayload(IKE_ID_IPV4_ADDR, 0, 0, sa->IkeClient->ServerIP.addr, 4);
								}

								// Build the ID payload tentatively
								idir_b = IkeBuildIdPayload(&my_id_payload->Payload.Id);

								b = NewBuf();
								WriteBufBuf(b, sa->GXr);
								WriteBufBuf(b, sa->GXi);
								WriteBufInt64(b, sa->ResponderCookie);
								WriteBufInt64(b, sa->InitiatorCookie);
								WriteBufBuf(b, sa->SAi_b);
								WriteBufBuf(b, idir_b);

								IkeHMac(sa->TransformSetting.Hash, responder_hash, sa->SKEYID, sa->HashSize,
									b->Buf, b->Size);

								FreeBuf(b);
								FreeBuf(idir_b);

								my_hash_payload = IkeNewDataPayload(IKE_PAYLOAD_HASH, responder_hash, sa->HashSize);

								Add(payload_list, my_id_payload);
								Add(payload_list, my_hash_payload);

								ps = IkeNew(sa->InitiatorCookie, sa->ResponderCookie, IKE_EXCHANGE_TYPE_AGGRESSIVE,
									false, false, false, 0, payload_list);

								// Add the vendor ID
								IkeAddVendorIdPayloads(ps);

								// NAT-D related
								if (sa->Caps.UsingNatTraversalRfc3947)
								{
									// RFC-compliant
									Add(payload_list, IkeNewDataPayload(IKE_PAYLOAD_NAT_D, nat_buf1->Buf, nat_buf1->Size));
									Add(payload_list, IkeNewDataPayload(IKE_PAYLOAD_NAT_D, nat_buf2->Buf, nat_buf2->Size));
								}

								if (sa->Caps.UsingNatTraversalDraftIetf)
								{
									// Draft compliant
									Add(payload_list, IkeNewDataPayload(IKE_PAYLOAD_NAT_D_DRAFT, nat_buf1->Buf, nat_buf1->Size));
									Add(payload_list, IkeNewDataPayload(IKE_PAYLOAD_NAT_D_DRAFT, nat_buf2->Buf, nat_buf2->Size));
								}

								FreeBuf(nat_buf1);
								FreeBuf(nat_buf2);

								StrCpy(c->ClientId, sizeof(c->ClientId), your_id_payload->Payload.Id.StrData);
								Debug("Client ID = %s\n", c->ClientId);

								IPsecLog(ike, c, NULL, NULL, NULL, "LI_SET_CLIENT_ID", c->ClientId);

								// Initial IV setting
								iv_buf = NewBuf();
								WriteBuf(iv_buf, your_key_buf->Buf, your_key_buf->Size);
								WriteBuf(iv_buf, dh->MyPublicKey->Buf, dh->MyPublicKey->Size);
								IkeHash(sa->TransformSetting.Hash, iv_hashed_data, iv_buf->Buf, iv_buf->Size);

								BinToStrEx(tmp, sizeof(tmp), iv_hashed_data, sa->BlockSize);
								Debug("Initial IV: %s\n", tmp);

								IkeSaUpdateIv(sa, iv_hashed_data, sa->HashSize);

								FreeBuf(iv_buf);

								// Transmission
								IkeSaSendPacket(ike, sa, ps);

								IkeFree(ps);
							}
							else
							{
								// DH calculation failure
								Debug("DhCompute failed.\n");
							}

							Free(shared_key);
							DhFree(dh);
						}
					}
					else
					{
						// No appropriate transform setting
						Debug("No Appropriate Transform was Found.\n");

						IPsecLog(ike, c, NULL, NULL, "LI_IKE_NO_TRANSFORM");

						SendInformationalExchangePacket(ike, c, IkeNewNoticeErrorNoProposalChosenPayload(false, header->InitiatorCookie, header->ResponderCookie));
					}
				}
			}
			else
			{
				// Client does not support NAT Traversal
				Debug("Client doesn't support NAT-T.\n");

				IPsecLog(ike, c, NULL, NULL, "LI_IKE_NO_NAT_T");
			}

			IkeFree(pr);
		}
	}
	else
	{
		// Process of state 2
		IKE_SA *sa;

		sa = FindIkeSaByResponderCookieAndClient(ike, header->ResponderCookie, c);

		if (sa == NULL)
		{
			SendInformationalExchangePacketEx(ike, c, IkeNewNoticeErrorInvalidCookiePayload(header->InitiatorCookie,
				header->ResponderCookie), true, header->InitiatorCookie, header->ResponderCookie);
		}

		if (sa != NULL && sa->Mode == IKE_SA_AGRESSIVE_MODE)
		{
			IKE_PACKET *pr = NULL;

			sa->LastCommTick = ike->Now;

			switch (sa->State)
			{
			case IKE_SA_AM_STATE_1_SA:
				pr = IkeSaRecvPacket(ike, sa, p->Data, p->Size);
				if (pr != NULL)
				{
					IKE_PACKET_PAYLOAD *your_hash_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_HASH, 0);

					if (your_hash_payload != NULL)
					{
						// Compare the hash
						if (IkeCompareHash(your_hash_payload, sa->InitiatorHashForAM, sa->HashSize))
						{
							// Transit to the established state
							Debug("IKE SA 0x%X Established.\n", sa);
							sa->State = IKE_SA_AM_STATE_2_ESTABLISHED;
							sa->EstablishedTick = ike->Now;
							sa->Established = true;
							c->CurrentIkeSa = sa;
							c->NextDpdSendTick = ike->Now + (UINT64)IKE_INTERVAL_DPD_KEEPALIVE;
							StrCpy(c->Secret, sizeof(c->Secret), sa->Secret);

							IPsecLog(ike, NULL, sa, NULL, "LI_IKE_SA_ESTABLISHED");

							IkeSaSendPacket(ike, sa, NULL);
						}
						else
						{
							Debug("IKE SA 0x%X Invalid Hash.\n", sa);
						}
					}
				}
				break;
			}

			if (pr != NULL)
			{
				IkeFree(pr);
			}
		}
	}
}

// Process of the main mode packet reception
void ProcIkeMainModePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header)
{
	IKE_CLIENT *c;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (ike == NULL || p == NULL || header == NULL || header->InitiatorCookie == 0)
	{
		return;
	}

	c = SearchOrCreateNewIkeClientForIkePacket(ike, &p->SrcIP, p->SrcPort, &p->DstIP, p->DestPort, header);

	if (c == NULL)
	{
		return;
	}

	if (header->ResponderCookie == 0)
	{
		// Start process of the state 1
		IKE_CAPS caps;
		IKE_SA *sa;
		IKE_PACKET *pr = IkeParse(p->Data, p->Size, NULL);

		if (pr != NULL)
		{
			// Determine the CAPS
			IkeCheckCaps(&caps, pr);
			if (caps.MS_L2TPIPSecVPNClient || caps.MS_NT5_ISAKMP_OAKLEY || caps.MS_Vid_InitialContact)
			{
				c->IsMicrosoft = true;
			}

			if ((caps.NatTraversalDraftIetf || caps.NatTraversalRfc3947) || (IsUdpPortOpened(ike->IPsec->UdpListener, &p->DstIP, IPSEC_PORT_IPSEC_ESP_RAW)))
			{
				sa = FindIkeSaByEndPointAndInitiatorCookie(ike, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort, header->InitiatorCookie, IKE_SA_MAIN_MODE);

				if (sa == NULL)
				{
					// Check whether there is acceptable SA parameters by analyzing proposed parameters
					IKE_SA_TRANSFORM_SETTING setting;

					if (GetBestTransformSettingForIkeSa(ike, pr, &setting) && (GetNumberOfIkeSaOfIkeClient(ike, c) <= IKE_QUOTA_MAX_SA_PER_CLIENT))
					{
						IKE_PACKET *ps;
						IKE_PACKET_PAYLOAD *tp;
						IKE_PACKET_PAYLOAD *pp;
						IKE_PACKET_PAYLOAD *sap;
						LIST *payload_list;
						IKE_PACKET_PAYLOAD *client_sa_payload;

						// Appropriate transform setting is selected
						Debug("P1 Transform: %s %s %s(%u) %u %u\n",
							setting.Dh->Name, setting.Hash->Name, setting.Crypto->Name, setting.CryptoKeySize,
							setting.LifeKilobytes, setting.LifeSeconds);

#ifdef	FORCE_LIFETIME_MM
						setting.LifeSeconds = FORCE_LIFETIME_MM;
#endif	// FORCE_LIFETIME_MM

						// Create an IKE SA
						sa = NewIkeSa(ike, c, header->InitiatorCookie, IKE_SA_MAIN_MODE, &setting);

						Copy(&sa->Caps, &caps, sizeof(IKE_CAPS));

						Insert(ike->IkeSaList, sa);

						// Answer the SA parameter selection results
						sa->State = IKE_SA_MM_STATE_1_SA;

						// Save a bit array of SA payload presented by the client
						client_sa_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_SA, 0);
						sa->SAi_b = CloneBuf(client_sa_payload->BitArray);

						//// Assemble the SA payload
						// Construct a transform payload
						tp = TransformSettingToTransformPayloadForIke(ike, &setting);

						// Build a proposal payload
						pp = IkeNewProposalPayload(1, IKE_PROTOCOL_ID_IKE, NULL, 0, NewListSingle(tp));

						// Build a SA payload
						sap = IkeNewSaPayload(NewListSingle(pp));

						payload_list = NewListSingle(sap);

						ps = IkeNew(sa->InitiatorCookie, sa->ResponderCookie, IKE_EXCHANGE_TYPE_MAIN,
							false, false, false, 0, payload_list);

						// Add the vendor ID payload
						IkeAddVendorIdPayloads(ps);

						IkeSaSendPacket(ike, sa, ps);

						sa->HashSize = sa->TransformSetting.Hash->HashSize;
						sa->KeySize = sa->TransformSetting.CryptoKeySize;
						sa->BlockSize = sa->TransformSetting.Crypto->BlockSize;

						IkeFree(ps);
					}
					else
					{
						// No appropriate transform setting
						Debug("No Appropriate Transform was Found.\n");

						IPsecLog(ike, c, NULL, NULL, "LI_IKE_NO_TRANSFORM");

						SendInformationalExchangePacket(ike, c, IkeNewNoticeErrorNoProposalChosenPayload(false, header->InitiatorCookie, header->ResponderCookie));
					}
				}
				else
				{
					// Ignore for IKE SA which already exists (Because it's likely to be a re-transmission)
				}
			}
			else
			{
				// It does not support NAT Traversal
				Debug("Client doesn't support NAT-T.\n");

				IPsecLog(ike, c, NULL, NULL, "LI_IKE_NO_NAT_T");
			}
			IkeFree(pr);
		}
	}
	else
	{
		// Process of state 2 or later
		IKE_SA *sa;

		sa = FindIkeSaByResponderCookieAndClient(ike, header->ResponderCookie, c);

		if (sa == NULL)
		{
			SendInformationalExchangePacketEx(ike, c, IkeNewNoticeErrorInvalidCookiePayload(header->InitiatorCookie,
				header->ResponderCookie), true, header->InitiatorCookie, header->ResponderCookie);
		}

		if (sa != NULL && sa->Mode == IKE_SA_MAIN_MODE)
		{
			IKE_PACKET *pr = NULL;

			sa->LastCommTick = ike->Now;

			switch (sa->State)
			{
			case IKE_SA_MM_STATE_1_SA:
				pr = IkeSaRecvPacket(ike, sa, p->Data, p->Size);
				if (pr != NULL)
				{
					// Receive a key exchange packet
					IKE_PACKET_PAYLOAD *your_key_payload;
					IKE_PACKET_PAYLOAD *your_rand_payload;
					IKE_PACKET_PAYLOAD *your_nat_d_1 = NULL;
					IKE_PACKET_PAYLOAD *your_nat_d_2 = NULL;

					your_key_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_KEY_EXCHANGE, 0);
					your_rand_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_RAND, 0);

					if (IkeGetPayloadNum(pr->PayloadList, IKE_PAYLOAD_NAT_D) != 0)
					{
						sa->Caps.UsingNatTraversalRfc3947 = true;

						your_nat_d_1 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_D, 0);
						your_nat_d_2 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_D, 1);
					}

					if (IkeGetPayloadNum(pr->PayloadList, IKE_PAYLOAD_NAT_D_DRAFT) != 0)
					{
						sa->Caps.UsingNatTraversalDraftIetf = true;

						your_nat_d_1 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_D_DRAFT, 0);
						your_nat_d_2 = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_NAT_D_DRAFT, 1);
					}

					if (your_key_payload != NULL && your_rand_payload != NULL)
					{
						// Check the key payload
						BUF *your_key_buf = your_key_payload->Payload.KeyExchange.Data;
						BUF *your_rand_buf = your_rand_payload->Payload.Rand.Data;

						// DH generation
						DH_CTX *dh = IkeDhNewCtx(sa->TransformSetting.Dh);
						UINT shared_key_size = (dh == NULL ? 0 : dh->Size);
						UCHAR *shared_key = ZeroMalloc(shared_key_size);

						// DH calculation
						if (DhCompute(dh, shared_key, your_key_buf->Buf, your_key_buf->Size))
						{
							IKE_PACKET *ps;
							LIST *payload_list;
							IKE_PACKET_PAYLOAD *my_key_payload;
							IKE_PACKET_PAYLOAD *my_rand_payload;
							BUF *nat_buf1, *nat_buf2;
							BUF *iv_buf;
							UCHAR iv_hashed_data[IKE_MAX_HASH_SIZE];

							// Calculation success
							sa->DhSharedKey = MemToBuf(shared_key, shared_key_size);
							sa->InitiatorRand = RandBuf(IKE_SA_RAND_SIZE);
							sa->ResponderRand = CloneBuf(your_rand_buf);

							// Send a key exchange packet
							my_key_payload = IkeNewDataPayload(IKE_PAYLOAD_KEY_EXCHANGE, dh->MyPublicKey->Buf, dh->MyPublicKey->Size);
							my_rand_payload = IkeNewDataPayload(IKE_PAYLOAD_RAND, sa->InitiatorRand->Buf, sa->InitiatorRand->Size);

							payload_list = NewListSingle(my_key_payload);
							Add(payload_list, my_rand_payload);

							// NAT-D packet
							// Address of the opponent. Randomize in order to be forced to use NAT
							nat_buf1 = IkeCalcNatDetectHash(ike, sa->TransformSetting.Hash, Rand64(), Rand64(), &c->ClientIP, Rand16());
							//nat_buf1 = IkeCalcNatDetectHash(ike, sa->TransformSetting.Hash, sa->InitiatorCookie, sa->ResponderCookie, &c->ClientIP, c->ClientPort);
							// My address

							if (c->IsMicrosoft == false || (your_nat_d_1 == NULL || your_nat_d_2 == NULL || your_nat_d_1->BitArray == NULL))
							{
								// Calculate exactly
								nat_buf2 = IkeCalcNatDetectHash(ike, sa->TransformSetting.Hash,
									sa->InitiatorCookie, sa->ResponderCookie, &c->ServerIP, c->ServerPort);
							}
							else
							{
								// Parrot the NAT_D payload indicating myself I got from
								// the other if it has connected from a Microsoft VPN Client
								nat_buf2 = CloneBuf(your_nat_d_1->BitArray);
							}

							if (sa->Caps.UsingNatTraversalRfc3947)
							{
								// RFC-compliant
								Add(payload_list, IkeNewDataPayload(IKE_PAYLOAD_NAT_D, nat_buf1->Buf, nat_buf1->Size));
								Add(payload_list, IkeNewDataPayload(IKE_PAYLOAD_NAT_D, nat_buf2->Buf, nat_buf2->Size));
							}

							if (sa->Caps.UsingNatTraversalDraftIetf)
							{
								// Draft compliant
								Add(payload_list, IkeNewDataPayload(IKE_PAYLOAD_NAT_D_DRAFT, nat_buf1->Buf, nat_buf1->Size));
								Add(payload_list, IkeNewDataPayload(IKE_PAYLOAD_NAT_D_DRAFT, nat_buf2->Buf, nat_buf2->Size));
							}

							FreeBuf(nat_buf1);
							FreeBuf(nat_buf2);

							ps = IkeNew(sa->InitiatorCookie, sa->ResponderCookie, IKE_EXCHANGE_TYPE_MAIN,
								false, false, false, 0, payload_list);

							// Initial IV setting
							iv_buf = NewBuf();
							WriteBuf(iv_buf, your_key_buf->Buf, your_key_buf->Size);
							WriteBuf(iv_buf, dh->MyPublicKey->Buf, dh->MyPublicKey->Size);
							IkeHash(sa->TransformSetting.Hash, iv_hashed_data, iv_buf->Buf, iv_buf->Size);

							BinToStrEx(tmp, sizeof(tmp), iv_hashed_data, sa->BlockSize);
							Debug("Initial IV: %s\n", tmp);

							IkeSaUpdateIv(sa, iv_hashed_data, sa->HashSize);

							FreeBuf(iv_buf);

							// Save the DH information
							sa->GXi = CloneBuf(your_key_buf);
							sa->GXr = CloneBuf(dh->MyPublicKey);

							// Transmission
							IkeSaSendPacket(ike, sa, ps);

							IkeFree(ps);

							// Calculate the key set
							IkeCalcSaKeySet(ike, sa, NULL);

							sa->State = IKE_SA_MM_STATE_2_KEY;
						}
						else
						{
							// DH calculation failure
							Debug("DhCompute failed.\n");
						}

						Free(shared_key);
						DhFree(dh);
					}
				}
				break;

			case IKE_SA_MM_STATE_2_KEY:
				pr = IkeSaRecvPacket(ike, sa, p->Data, p->Size);
				if (pr != NULL && pr->FlagEncrypted)
				{
					// Receive an ID exchange packet
					IKE_PACKET_PAYLOAD *your_id_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_ID, 0);
					IKE_PACKET_PAYLOAD *your_hash_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_HASH, 0);

					if (your_id_payload && your_hash_payload)
					{
						UCHAR initiator_hash[IKE_MAX_HASH_SIZE];
						BUF *b;

						// Calculate the initiator side hash value
						b = NewBuf();
						WriteBufBuf(b, sa->GXi);
						WriteBufBuf(b, sa->GXr);
						WriteBufInt64(b, sa->InitiatorCookie);
						WriteBufInt64(b, sa->ResponderCookie);
						WriteBufBuf(b, sa->SAi_b);
						WriteBufBuf(b, your_id_payload->BitArray);

						StrCpy(c->ClientId, sizeof(c->ClientId), your_id_payload->Payload.Id.StrData);
						Debug("Client ID = %s\n", c->ClientId);
						IPsecLog(ike, c, NULL, NULL, NULL, "LI_SET_CLIENT_ID", c->ClientId);

						IkeHMac(sa->TransformSetting.Hash, initiator_hash, sa->SKEYID, sa->HashSize,
							b->Buf, b->Size);

						FreeBuf(b);

						// Hash comparison
						if (IkeCompareHash(your_hash_payload, initiator_hash, sa->HashSize))
						{
							// Generate a response packet
							IKE_PACKET *ps;
							LIST *payload_list = NewListFast(NULL);
							IKE_PACKET_PAYLOAD *my_id_payload, *my_hash_payload;
							UCHAR responder_hash[IKE_MAX_HASH_SIZE];
							BUF *idir_b;

							// Generate an ID payload
							if (IsIP6(&sa->IkeClient->ServerIP))
							{
								// IPv6 address
								my_id_payload = IkeNewIdPayload(IKE_ID_IPV6_ADDR, 0, 0, sa->IkeClient->ServerIP.ipv6_addr, 16);
							}
							else
							{
								// IPv4 address
								my_id_payload = IkeNewIdPayload(IKE_ID_IPV4_ADDR, 0, 0, sa->IkeClient->ServerIP.addr, 4);
							}

							// Build the ID payload tentatively
							idir_b = IkeBuildIdPayload(&my_id_payload->Payload.Id);

							// Generate the hash payload
							b = NewBuf();
							WriteBufBuf(b, sa->GXr);
							WriteBufBuf(b, sa->GXi);
							WriteBufInt64(b, sa->ResponderCookie);
							WriteBufInt64(b, sa->InitiatorCookie);
							WriteBufBuf(b, sa->SAi_b);
							WriteBufBuf(b, idir_b);

							IkeHMac(sa->TransformSetting.Hash, responder_hash, sa->SKEYID, sa->HashSize,
								b->Buf, b->Size);

							FreeBuf(b);
							FreeBuf(idir_b);

							my_hash_payload = IkeNewDataPayload(IKE_PAYLOAD_HASH, responder_hash, sa->HashSize);

							Add(payload_list, my_id_payload);
							Add(payload_list, my_hash_payload);

							ps = IkeNew(sa->InitiatorCookie, sa->ResponderCookie, IKE_EXCHANGE_TYPE_MAIN, true, false,
								false, 0, payload_list);

							// Transmission
							IkeSaSendPacket(ike, sa, ps);
							sa->NumResends = 3;

							IkeFree(ps);

							StrCpy(c->ClientId, sizeof(c->ClientId), your_id_payload->Payload.Id.StrData);

							// Transit to the established state
							Debug("IKE SA 0x%X Established. Client ID=%s\n", sa, c->ClientId);
							sa->State = IKE_SA_MM_STATE_3_ESTABLISHED;
							sa->EstablishedTick = ike->Now;
							c->CurrentIkeSa = sa;
							c->NextDpdSendTick = ike->Now + (UINT64)IKE_INTERVAL_DPD_KEEPALIVE;
							StrCpy(c->Secret, sizeof(c->Secret), sa->Secret);
							sa->Established = true;

							IPsecLog(ike, NULL, sa, NULL, "LI_IKE_SA_ESTABLISHED");
						}
						else
						{
							Debug("IKE SA 0x%X Invalid Hash.\n", sa);
						}
					}
				}
				break;
			}

			if (pr != NULL)
			{
				IkeFree(pr);
			}
		}
	}
}

// Update the IV of IPsec SA
void IPsecSaUpdateIv(IPSECSA *sa, void *iv, UINT iv_size)
{
	// Validate arguments
	if (sa == NULL || iv == NULL)
	{
		return;
	}

	Copy(sa->Iv, iv, MIN(sa->IkeSa->BlockSize, iv_size));

	if (iv_size < sa->IkeSa->BlockSize)
	{
		Zero(sa->Iv + sa->IkeSa->BlockSize, sa->IkeSa->BlockSize - iv_size);
	}

	sa->IsIvExisting = true;
}

// Update the IV of the IKE SA
void IkeSaUpdateIv(IKE_SA *sa, void *iv, UINT iv_size)
{
	// Validate arguments
	if (sa == NULL || iv == NULL)
	{
		return;
	}

	Copy(sa->Iv, iv, MIN(sa->BlockSize, iv_size));

	if (iv_size < sa->BlockSize)
	{
		Zero(sa->Iv + sa->BlockSize, sa->BlockSize - iv_size);
	}

	sa->IsIvExisting = true;
}

// Calculate the key set of the IKE SA
void IkeCalcSaKeySet(IKE_SERVER *ike, IKE_SA *sa, char *secret)
{
	BUF *secret_buf;
	BUF *rand_buf;
	BUF *d_buf, *a_buf, *e_buf;
	UCHAR u;
	IKE_HASH *h;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (ike == NULL || sa == NULL)
	{
		return;
	}

	h = sa->TransformSetting.Hash;

	// Calculation of SKEYID
	StrCpy(sa->Secret, sizeof(sa->Secret), secret == NULL ? ike->Secret : secret);
	secret_buf = IkeStrToPassword(sa->Secret);
	rand_buf = CloneBuf(sa->ResponderRand);
	SeekBufToEnd(rand_buf);
	BinToStrEx(tmp, sizeof(tmp), rand_buf->Buf, rand_buf->Size);
	Debug("ResponderRand: %s\n", tmp);
	BinToStrEx(tmp, sizeof(tmp), sa->InitiatorRand->Buf, sa->InitiatorRand->Size);
	Debug("InitiatorRand: %s\n", tmp);

	WriteBufBuf(rand_buf, sa->InitiatorRand);

	IkeHMacBuf(h, sa->SKEYID, secret_buf, rand_buf);

	BinToStrEx(tmp, sizeof(tmp), sa->SKEYID, sa->HashSize);
	Debug("SKEYID: %s\n", tmp);

	// SKEYID_d
	d_buf = CloneBuf(sa->DhSharedKey);
	SeekBufToEnd(d_buf);
	WriteBufInt64(d_buf, sa->InitiatorCookie);
	WriteBufInt64(d_buf, sa->ResponderCookie);
	u = 0;
	WriteBuf(d_buf, &u, 1);
	IkeHMac(h, sa->SKEYID_d, sa->SKEYID, sa->HashSize, d_buf->Buf, d_buf->Size);

	BinToStrEx(tmp, sizeof(tmp), sa->SKEYID_d, sa->HashSize);
	Debug("SKEYID_d: %s\n", tmp);

	// SKEYID_a
	a_buf = MemToBuf(sa->SKEYID_d, sa->HashSize);
	SeekBufToEnd(a_buf);
	WriteBufBuf(a_buf, sa->DhSharedKey);
	WriteBufInt64(a_buf, sa->InitiatorCookie);
	WriteBufInt64(a_buf, sa->ResponderCookie);
	u = 1;
	WriteBuf(a_buf, &u, 1);
	IkeHMac(h, sa->SKEYID_a, sa->SKEYID, sa->HashSize, a_buf->Buf, a_buf->Size);

	BinToStrEx(tmp, sizeof(tmp), sa->SKEYID_a, sa->HashSize);
	Debug("SKEYID_a: %s\n", tmp);

	// SKEYID_e
	e_buf = MemToBuf(sa->SKEYID_a, sa->HashSize);
	SeekBufToEnd(e_buf);
	WriteBufBuf(e_buf, sa->DhSharedKey);
	WriteBufInt64(e_buf, sa->InitiatorCookie);
	WriteBufInt64(e_buf, sa->ResponderCookie);
	u = 2;
	WriteBuf(e_buf, &u, 1);
	IkeHMac(h, sa->SKEYID_e, sa->SKEYID, sa->HashSize, e_buf->Buf, e_buf->Size);

	BinToStrEx(tmp, sizeof(tmp), sa->SKEYID_e, sa->HashSize);
	Debug("SKEYID_e: %s\n", tmp);

	if (sa->CryptoKey != NULL)
	{
		IkeFreeKey(sa->CryptoKey);
	}

	sa->CryptoKey = IkeNewCryptoKeyFromK(ike, sa->SKEYID_e, sa->HashSize, sa->TransformSetting.Hash,
		sa->TransformSetting.Crypto, sa->TransformSetting.CryptoKeySize);

	// Release the memory
	FreeBuf(secret_buf);
	FreeBuf(rand_buf);
	FreeBuf(d_buf);
	FreeBuf(a_buf);
	FreeBuf(e_buf);
}

// Extend the key size
BUF *IkeExpandKeySize(IKE_HASH *h, void *k, UINT k_size, UINT target_size)
{
	BUF *b1, *b2;
	UCHAR tmp[IKE_MAX_HASH_SIZE];
	UINT tmp_size;
	// Validate arguments
	if (h == NULL || k == NULL || k_size == 0)
	{
		return NULL;
	}

	if (k_size >= target_size)
	{
		return MemToBuf(k, target_size);
	}

	tmp[0] = 0;
	tmp_size = 1;
	b1 = NewBuf();

	do
	{
		IkeHMac(h, tmp, k, k_size, tmp, tmp_size);
		WriteBuf(b1, tmp, h->HashSize);

		tmp_size = h->HashSize;
	}
	while (b1->Size < target_size);

	b2 = MemToBuf(b1->Buf, target_size);

	FreeBuf(b1);

	return b2;
}

// Generate a key from K
IKE_CRYPTO_KEY *IkeNewCryptoKeyFromK(IKE_SERVER *ike, void *k, UINT k_size, IKE_HASH *h, IKE_CRYPTO *c, UINT crypto_key_size)
{
	BUF *key_buf;
	IKE_CRYPTO_KEY *ret;
	// Validate arguments
	if (ike == NULL || k == NULL || k_size == 0 || h == NULL || c == NULL || crypto_key_size == 0)
	{
		return NULL;
	}

	key_buf = IkeExpandKeySize(h, k, k_size, crypto_key_size);
	if (key_buf == NULL)
	{
		return NULL;
	}

	ret = IkeNewKey(c, key_buf->Buf, key_buf->Size);

	FreeBuf(key_buf);

	return ret;
}

// Generate a hash for NAT detection
BUF *IkeCalcNatDetectHash(IKE_SERVER *ike, IKE_HASH *hash, UINT64 initiator_cookie, UINT64 responder_cookie, IP *ip, UINT port)
{
	BUF *b;
	USHORT us;
	USHORT hash_data[IKE_MAX_HASH_SIZE];
	// Validate arguments
	if (ike == NULL || ip == NULL || hash == NULL)
	{
		return NewBuf();
	}

	b = NewBuf();

	WriteBufInt64(b, initiator_cookie);
	WriteBufInt64(b, responder_cookie);

	if (IsIP6(ip))
	{
		WriteBuf(b, ip->ipv6_addr, sizeof(ip->ipv6_addr));
	}
	else
	{
		WriteBuf(b, ip->addr, sizeof(ip->addr));
	}

	us = Endian16((USHORT)port);

	WriteBuf(b, &us, sizeof(USHORT));

	IkeHash(hash, hash_data, b->Buf, b->Size);

	FreeBuf(b);

	return MemToBuf(hash_data, hash->HashSize);
}

// Check the capacity of the opposite IPsec client
void IkeCheckCaps(IKE_CAPS *caps, IKE_PACKET *p)
{
	// Validate arguments
	if (caps == NULL || p == NULL)
	{
		Zero(caps, sizeof(IKE_CAPS));
		return;
	}

	Zero(caps, sizeof(IKE_CAPS));

	caps->NatTraversalRfc3947 = IkeIsVendorIdExists(p, IKE_VENDOR_ID_RFC3947_NAT_T);

	caps->NatTraversalDraftIetf = IkeIsVendorIdExists(p, IKE_VENDOR_ID_IPSEC_NAT_T_IKE_03) ||
		IkeIsVendorIdExists(p, IKE_VENDOR_ID_IPSEC_NAT_T_IKE_02) ||
		IkeIsVendorIdExists(p, IKE_VENDOR_ID_IPSEC_NAT_T_IKE_02_2) ||
		IkeIsVendorIdExists(p, IKE_VENDOR_ID_IPSEC_NAT_T_IKE_00);

	caps->DpdRfc3706 = IkeIsVendorIdExists(p, IKE_VENDOR_ID_RFC3706_DPD);

	caps->MS_L2TPIPSecVPNClient = IkeIsVendorIdExists(p, IKE_VENDOR_ID_MICROSOFT_L2TP);
	caps->MS_NT5_ISAKMP_OAKLEY = IkeIsVendorIdExists(p, IKE_VENDOR_ID_MS_NT5_ISAKMPOAKLEY);
	caps->MS_Vid_InitialContact = IkeIsVendorIdExists(p, IKE_VENDOR_ID_MS_VID_INITIALCONTACT);
}

// Check whether the specified vendor ID is contained in the packet
bool IkeIsVendorIdExists(IKE_PACKET *p, char *str)
{
	BUF *buf;
	UINT i, num;
	bool ok = false;
	// Validate arguments
	if (p == NULL || str == NULL)
	{
		return false;
	}

	buf = IkeStrToVendorId(str);
	if (buf == NULL)
	{
		return false;
	}

	num = IkeGetPayloadNum(p->PayloadList, IKE_PAYLOAD_VENDOR_ID);
	for (i = 0;i < num;i++)
	{
		IKE_PACKET_PAYLOAD *payload = IkeGetPayload(p->PayloadList, IKE_PAYLOAD_VENDOR_ID, i);

		if (CompareBuf(payload->Payload.VendorId.Data, buf))
		{
			ok = true;
		}
		else
		{
			if (payload->Payload.VendorId.Data != NULL)
			{
				if (payload->Payload.VendorId.Data->Size >= buf->Size)
				{
					if (Cmp(payload->Payload.VendorId.Data->Buf, buf->Buf, buf->Size) == 0)
					{
						ok = true;
					}
				}
			}
		}
	}

	FreeBuf(buf);

	return ok;
}

// Add the vendor ID payload list
void IkeAddVendorIdPayloads(IKE_PACKET *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	IkeAddVendorId(p, IKE_VENDOR_ID_RFC3947_NAT_T);
	IkeAddVendorId(p, IKE_VENDOR_ID_IPSEC_NAT_T_IKE_03);
	IkeAddVendorId(p, IKE_VENDOR_ID_IPSEC_NAT_T_IKE_02);
	IkeAddVendorId(p, IKE_VENDOR_ID_IPSEC_NAT_T_IKE_02_2);
	IkeAddVendorId(p, IKE_VENDOR_ID_IPSEC_NAT_T_IKE_00);
	IkeAddVendorId(p, IKE_VENDOR_ID_RFC3706_DPD);
}

// Add the vendor ID payload
void IkeAddVendorId(IKE_PACKET *p, char *str)
{
	BUF *buf;
	IKE_PACKET_PAYLOAD *payload;
	// Validate arguments
	if (p == NULL || str == NULL)
	{
		return;
	}

	buf = IkeStrToVendorId(str);
	if (buf == NULL)
	{
		return;
	}

	payload = IkeNewDataPayload(IKE_PAYLOAD_VENDOR_ID, buf->Buf, buf->Size);

	Add(p->PayloadList, payload);

	FreeBuf(buf);
}

// Convert string to the vendor ID
BUF *IkeStrToVendorId(char *str)
{
	// Validate arguments
	if (IsEmptyStr(str))
	{
		return NULL;
	}

	if (StartWith(str, "0x"))
	{
		BUF *buf = StrToBin(str + 2);

		if (buf == NULL || buf->Size == 0)
		{
			FreeBuf(buf);
			return NULL;
		}

		return buf;
	}
	else
	{
		BUF *buf;
		UCHAR hash[MD5_SIZE];

		Hash(hash, str, StrLen(str), false);

		buf = MemToBuf(hash, sizeof(hash));

		return buf;
	}
}

// Receive a packet using the IKE SA
IKE_PACKET *IkeSaRecvPacket(IKE_SERVER *ike, IKE_SA *sa, void *data, UINT size)
{
	IKE_PACKET *ret;
	// Validate arguments
	if (ike == NULL || sa == NULL || (size != 0 && data == NULL))
	{
		return NULL;
	}

	if (sa->IsIvExisting == false || sa->CryptoKey == NULL)
	{
		ret = IkeParse(data, size, NULL);
	}
	else
	{
		IKE_CRYPTO_PARAM cp;

		Copy(&cp.Iv, sa->Iv, sa->BlockSize);
		cp.Key = sa->CryptoKey;

		ret = IkeParse(data, size, &cp);

		if (ret->FlagEncrypted)
		{
			IkeSaUpdateIv(sa, cp.NextIv, sa->BlockSize);
		}
	}

	return ret;
}

// Receive a packet using IPsec SA (Quick Mode received)
IKE_PACKET *IPsecSaRecvPacket(IKE_SERVER *ike, IPSECSA *sa, void *data, UINT size)
{
	IKE_PACKET *ret;
	// Validate arguments
	if (ike == NULL || sa == NULL || (size != 0 && data == NULL))
	{
		return NULL;
	}

	if (sa->IsIvExisting == false || sa->IkeSa->CryptoKey == NULL)
	{
		ret = IkeParse(data, size, NULL);
	}
	else
	{
		IKE_CRYPTO_PARAM cp;

		Copy(&cp.Iv, sa->Iv, sa->IkeSa->BlockSize);
		cp.Key = sa->IkeSa->CryptoKey;

		ret = IkeParse(data, size, &cp);

		if (ret->FlagEncrypted)
		{
			IPsecSaUpdateIv(sa, cp.NextIv, sa->IkeSa->BlockSize);
			IPsecSaUpdateIv(sa->PairIPsecSa, cp.NextIv, sa->IkeSa->BlockSize);
		}
	}

	return ret;
}

// Send a packet using IPsec SA (Quick Mode transmission)
void IPsecSaSendPacket(IKE_SERVER *ike, IPSECSA *sa, IKE_PACKET *p)
{
	BUF *buf;
	// Validate arguments
	if (ike == NULL || sa == NULL)
	{
		return;
	}

	if (p == NULL)
	{
		FreeBuf(sa->SendBuffer);
		sa->SendBuffer = NULL;
		sa->NextSendTick = 0;
		return;
	}

	// Build a packet
	if (p->FlagEncrypted == false)
	{
		buf = IkeBuild(p, NULL);
	}
	else
	{
		IKE_CRYPTO_PARAM cp;

		Copy(cp.Iv, sa->Iv, sa->IkeSa->BlockSize);
		cp.Key = sa->IkeSa->CryptoKey;

		buf = IkeBuild(p, &cp);

		IPsecSaUpdateIv(sa, cp.NextIv, sa->IkeSa->BlockSize);
		IPsecSaUpdateIv(sa->PairIPsecSa, cp.NextIv, sa->IkeSa->BlockSize);
	}

	if (buf == NULL)
	{
		return;
	}

	// Register the last packet to re-transmit
	if (sa->SendBuffer != NULL)
	{
		FreeBuf(sa->SendBuffer);
	}

	sa->SendBuffer = CloneBuf(buf);
	sa->NextSendTick = ike->Now + (UINT64)(IKE_SA_RESEND_INTERVAL);
	AddInterrupt(ike->Interrupts, sa->NextSendTick);

	IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP, &sa->IkeClient->ServerIP, sa->IkeClient->ServerPort,
		&sa->IkeClient->ClientIP, sa->IkeClient->ClientPort,
		buf->Buf, buf->Size);

	Free(buf);
}

// Send a packet using the IKE SA
void IkeSaSendPacket(IKE_SERVER *ike, IKE_SA *sa, IKE_PACKET *p)
{
	BUF *buf;
	// Validate arguments
	if (ike == NULL || sa == NULL)
	{
		return;
	}

	if (p == NULL)
	{
		FreeBuf(sa->SendBuffer);
		sa->SendBuffer = NULL;
		sa->NextSendTick = 0;
		return;
	}

	// Build a packet
	if (p->FlagEncrypted == false)
	{
		buf = IkeBuild(p, NULL);
	}
	else
	{
		IKE_CRYPTO_PARAM cp;

		Copy(cp.Iv, sa->Iv, sa->BlockSize);
		cp.Key = sa->CryptoKey;

		buf = IkeBuild(p, &cp);

		IkeSaUpdateIv(sa, cp.NextIv, sa->BlockSize);
	}

	if (buf == NULL)
	{
		return;
	}

	if (p->ExchangeType != IKE_EXCHANGE_TYPE_INFORMATION)
	{
		// Register the last packet to re-transmit
		if (sa->SendBuffer != NULL)
		{
			FreeBuf(sa->SendBuffer);
		}

		sa->SendBuffer = CloneBuf(buf);
		sa->NextSendTick = ike->Now + (UINT64)(IKE_SA_RESEND_INTERVAL);
		AddInterrupt(ike->Interrupts, sa->NextSendTick);
	}

	IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP, &sa->IkeClient->ServerIP, sa->IkeClient->ServerPort,
		&sa->IkeClient->ClientIP, sa->IkeClient->ClientPort,
		buf->Buf, buf->Size);

	Free(buf);
}

// Send an UDP packet
void IkeSendUdpPacket(IKE_SERVER *ike, UINT type, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, void *data, UINT size)
{
	UDPPACKET *p;
	// Validate arguments
	if (ike == NULL || server_ip == NULL || client_ip == NULL || server_port == 0 || client_port == 0 || data == NULL || size == 0)
	{
		return;
	}

	p = NewUdpPacket(server_ip, server_port, client_ip, client_port, data, size);

	p->Type = type;

	Add(ike->SendPacketList, p);
}

// Create an IKE SA
IKE_SA *NewIkeSa(IKE_SERVER *ike, IKE_CLIENT *c, UINT64 init_cookie, UINT mode, IKE_SA_TRANSFORM_SETTING *setting)
{
	IKE_SA *sa;
	// Validate arguments
	if (ike == NULL || c == NULL || init_cookie == 0 || setting == NULL)
	{
		return NULL;
	}

	sa = ZeroMalloc(sizeof(IKE_SA));

	sa->Id = ++ike->CurrentIkeSaId;

	sa->IkeClient = c;
	sa->InitiatorCookie = init_cookie;
	sa->ResponderCookie = GenerateNewResponserCookie(ike);
	sa->Mode = mode;
	sa->FirstCommTick = sa->LastCommTick = ike->Now;
	Copy(&sa->TransformSetting, setting, sizeof(IKE_SA_TRANSFORM_SETTING));

	Debug("New IKE SA (Mode = %u): %I64u <--> %I64u (%s %s %s(%u) %u %u)\n",
		mode,
		sa->InitiatorCookie,
		sa->ResponderCookie,
		setting->Dh->Name, setting->Hash->Name, setting->Crypto->Name, setting->CryptoKeySize,
		setting->LifeKilobytes, setting->LifeSeconds);

	IPsecLog(ike, NULL, sa, NULL, "LI_NEW_IKE_SA",
		(mode == IKE_SA_MAIN_MODE ? _UU("LI_TAG_MAINMODE") : _UU("LI_TAG_AGGRESSIVE")),
		sa->InitiatorCookie, sa->ResponderCookie,
		setting->Dh->Name, setting->Hash->Name, setting->Crypto->Name, setting->CryptoKeySize * 8,
		setting->LifeKilobytes, setting->LifeSeconds);

	return sa;
}

// Search an IKE SA from the Responder Cookie
IKE_SA *FindIkeSaByResponderCookie(IKE_SERVER *ike, UINT64 responder_cookie)
{
	IKE_SA t;
	// Validate arguments
	if (ike == NULL || responder_cookie == 0)
	{
		return NULL;
	}

	t.ResponderCookie = responder_cookie;

	return Search(ike->IkeSaList, &t);
}

// Search an IKE SA from the Responder Cookie and the IKE_CLIENT
IKE_SA *FindIkeSaByResponderCookieAndClient(IKE_SERVER *ike, UINT64 responder_cookie, IKE_CLIENT *c)
{
	IKE_SA *sa;
	// Validate arguments
	if (ike == NULL || responder_cookie == 0 || c == NULL)
	{
		return NULL;
	}

	sa = FindIkeSaByResponderCookie(ike, responder_cookie);
	if (sa == NULL)
	{
		return NULL;
	}

	if (sa->IkeClient != c)
	{
		return NULL;
	}

	return sa;
}

// Search an IKE SA from the endpoint and the Initiator Cookie
IKE_SA *FindIkeSaByEndPointAndInitiatorCookie(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, UINT64 init_cookie, UINT mode)
{
	UINT i;
	// Validate arguments
	if (ike == NULL || client_ip == NULL || server_ip == NULL || client_port == 0 || server_port == 0 || init_cookie == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
	{
		IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);
		IKE_CLIENT *c;

		c = sa->IkeClient;

		if (CmpIpAddr(&c->ClientIP, client_ip) == 0 &&
			CmpIpAddr(&c->ServerIP, server_ip) == 0 &&
			c->ClientPort == client_port &&
			c->ServerPort == server_port &&
			sa->InitiatorCookie == init_cookie &&
			sa->Mode == mode)
		{
			return sa;
		}
	}

	return NULL;
}

// Get the number of IPsec SA that is associated with the IKE_CLIENT
UINT GetNumberOfIPsecSaOfIkeClient(IKE_SERVER *ike, IKE_CLIENT *c)
{
	UINT num = 0, i;
	// Validate arguments
	if (ike == NULL || c == NULL)
	{
		return 0;
	}

	for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
	{
		IPSECSA *sa = LIST_DATA(ike->IPsecSaList, i);

		if (sa->IkeClient == c)
		{
			num++;
		}
	}

	return num;
}

// Get the number of IKE SA that is associated with the IKE_CLIENT
UINT GetNumberOfIkeSaOfIkeClient(IKE_SERVER *ike, IKE_CLIENT *c)
{
	UINT num = 0, i;
	// Validate arguments
	if (ike == NULL || c == NULL)
	{
		return 0;
	}

	for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
	{
		IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);

		if (sa->IkeClient == c)
		{
			num++;
		}
	}

	return num;
}

// Get the number of clients that are connected from the specified IP address
UINT GetNumberOfIkeClientsFromIP(IKE_SERVER *ike, IP *client_ip)
{
	UINT i, num;
	// Validate arguments
	if (ike == NULL || client_ip == NULL)
	{
		return 0;
	}

	num = 0;

	for (i = 0;i < LIST_NUM(ike->ClientList);i++)
	{
		IKE_CLIENT *c = LIST_DATA(ike->ClientList, i);

		if (CmpIpAddr(&c->ClientIP, client_ip) == 0)
		{
			num++;
		}
	}

	return num;
}

// Find the appropriate IKE client. Create if it is absent
IKE_CLIENT *SearchOrCreateNewIkeClientForIkePacket(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, IKE_PACKET *pr)
{
	IKE_CLIENT *c;
	// Validate arguments
	if (ike == NULL || pr == NULL || client_ip == NULL || server_ip == NULL || client_port == 0 || server_port == 0 || pr == NULL)
	{
		return NULL;
	}

	c = SearchIkeClientForIkePacket(ike, client_ip, client_port, server_ip, server_port, pr);
	if (c == NULL)
	{
		if (GetNumberOfIkeClientsFromIP(ike, client_ip) > IKE_QUOTA_MAX_NUM_CLIENTS_PER_IP ||
			LIST_NUM(ike->ClientList) > IKE_QUOTA_MAX_NUM_CLIENTS)
		{
			return NULL;
		}


		c = NewIkeClient(ike, client_ip, client_port, server_ip, server_port);

		Insert(ike->ClientList, c);
	}

	return SetIkeClientEndpoint(ike, c, client_ip, client_port, server_ip, server_port);
}

// Create an IKE client
IKE_CLIENT *NewIkeClient(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port)
{
	IKE_CLIENT *c;
	char client_ip_str[MAX_SIZE];
	char server_ip_str[MAX_SIZE];
	// Validate arguments
	if (ike == NULL || client_ip == NULL || server_ip == NULL || client_port == 0 || server_port == 0)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(IKE_CLIENT));

	c->Id = ++ike->CurrentIkeClientId;

	Copy(&c->ClientIP, client_ip, sizeof(IP));
	c->ClientPort = client_port;

	Copy(&c->ServerIP, server_ip, sizeof(IP));
	Copy(&c->TransportModeServerIP, server_ip, sizeof(IP));
	Copy(&c->TransportModeClientIP, client_ip, sizeof(IP));
	c->ServerPort = server_port;

	c->LastCommTick = ike->Now;
	c->FirstCommTick = ike->Now;

	IPToStr(client_ip_str, sizeof(client_ip_str), client_ip);
	IPToStr(server_ip_str, sizeof(server_ip_str), server_ip);

	Debug("New IKE_CLIENT: %p: %s:%u -> %s:%u\n", c, client_ip_str, client_port, server_ip_str, server_port);

	IPsecLog(ike, c, NULL, NULL, "LI_NEW_IKE_CLIENT");

	return c;
}

// Search for the best associated IKE client when an IKE packet has been received
IKE_CLIENT *SearchIkeClientForIkePacket(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, IKE_PACKET *pr)
{
	IKE_CLIENT t;
	IKE_CLIENT *c = NULL;
	// Validate arguments
	if (ike == NULL || pr == NULL || client_ip == NULL || server_ip == NULL || client_port == 0 || server_port == 0)
	{
		return NULL;
	}

	if (true)
	{
		UINT i;

		if (pr->InitiatorCookie != 0 && pr->ResponderCookie != 0)
		{
			for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
			{
				IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);

				// Extract what Cookie matches exactly
				if (sa->InitiatorCookie == pr->InitiatorCookie && sa->ResponderCookie == pr->ResponderCookie)
				{
					IKE_CLIENT *cc = sa->IkeClient;

					if (CmpIpAddr(&cc->ServerIP, server_ip) == 0 &&
						CmpIpAddr(&cc->ClientIP, client_ip) == 0)
					{
						c = cc;
						break;
					}
				}
			}
		}
	}

	if (c == NULL)
	{
		// Search by a pair of IP address and port number
		Copy(&t.ClientIP, client_ip, sizeof(IP));
		t.ClientPort = client_port;
		Copy(&t.ServerIP, server_ip, sizeof(IP));
		t.ServerPort = server_port;

		c = Search(ike->ClientList, &t);

		if (c != NULL)// && server_port == IPSEC_PORT_IPSEC_ISAKMP)
		{
			// Search that the IKE_SA that points to this IKE_CLIENT exists and match the Cookie
			bool ok = false;
			UINT i;

			if (server_port == IPSEC_PORT_IPSEC_ESP_UDP)
			{
				// Regard as OK if the port number exactly match in the case of connecting to a server-side 4500
				ok = true;
			}
			else
			{
				if (c->CurrentIkeSa != NULL &&
					c->CurrentIkeSa->InitiatorCookie == pr->InitiatorCookie &&
					c->CurrentIkeSa->ResponderCookie == pr->ResponderCookie)
				{
					ok = true;
				}
				else 
				{
					for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
					{
						IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);

						if (sa->IkeClient == c)
						{
							if (sa->InitiatorCookie == pr->InitiatorCookie &&
								sa->ResponderCookie == pr->ResponderCookie)
							{
								ok = true;
								break;
							}
						}
					}
				}
			}

			if (ok == false)
			{
				// Not found
				c = NULL;
			}
		}
	}

	return c;
}

// Comparison of IPsec SA
int CmpIPsecSa(void *p1, void *p2)
{
	IPSECSA *sa1, *sa2;
	int r;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	sa1 = *(IPSECSA **)p1;
	sa2 = *(IPSECSA **)p2;
	if (sa1 == NULL || sa2 == NULL)
	{
		return 0;
	}

	r = COMPARE_RET(sa1->ServerToClient, sa2->ServerToClient);
	if (r != 0)
	{
		return r;
	}

	r = COMPARE_RET(sa1->Spi, sa2->Spi);

	return r;
}

// Comparison of IKE_SA
int CmpIkeSa(void *p1, void *p2)
{
	IKE_SA *sa1, *sa2;
	int r;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	sa1 = *(IKE_SA **)p1;
	sa2 = *(IKE_SA **)p2;
	if (sa1 == NULL || sa2 == NULL)
	{
		return 0;
	}

	r = COMPARE_RET(sa1->ResponderCookie, sa2->ResponderCookie);

	return r;
}

// Comparison of IKE_CLIENT
int CmpIkeClient(void *p1, void *p2)
{
	IKE_CLIENT *c1, *c2;
	int r;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(IKE_CLIENT **)p1;
	c2 = *(IKE_CLIENT **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	r = CmpIpAddr(&c1->ClientIP, &c2->ClientIP);
	if (r != 0)
	{
		return r;
	}

	r = CmpIpAddr(&c1->ServerIP, &c2->ServerIP);
	if (r != 0)
	{
		return r;
	}

	r = COMPARE_RET(c1->ClientPort, c2->ClientPort);
	if (r != 0)
	{
		return r;
	}

	r = COMPARE_RET(c1->ServerPort, c2->ServerPort);
	if (r != 0)
	{
		return r;
	}

	return 0;
}

// Update the endpoint information of IKE_CLIENT
IKE_CLIENT *SetIkeClientEndpoint(IKE_SERVER *ike, IKE_CLIENT *c, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port)
{
	char client_ip_str[MAX_SIZE];
	char server_ip_str[MAX_SIZE];
	IKE_CLIENT *ret = c;
	IKE_CLIENT *cc;
	IKE_CLIENT t;
	// Validate arguments
	if (ike == NULL || c == NULL || client_ip == NULL || client_port == 0 || server_ip == NULL || server_port == 0)
	{
		return NULL;
	}

	if (CmpIpAddr(&c->ClientIP, client_ip) == 0 &&
		CmpIpAddr(&c->ServerIP, server_ip) == 0 &&
		c->ClientPort == client_port &&
		c->ServerPort == server_port)
	{
		// No change
		return ret;
	}

	if (IS_SPECIAL_PORT(client_port) || IS_SPECIAL_PORT(server_port))
	{
		// Don't change in the case of Raw socket
		return ret;
	}

	// Search for an existing IKE_CLIENT which exactly matches to combination of the new IP address and the port number
	Copy(&t.ClientIP, client_ip, sizeof(IP));
	t.ClientPort = client_port;
	Copy(&t.ServerIP, server_ip, sizeof(IP));
	t.ServerPort = server_port;

	cc = Search(ike->ClientList, &t);
	if (cc != NULL && c != cc && cc->Deleting == false && c->L2TP == NULL)
	{
		UINT i;
		// Merge into this existing IKE_CLIENT since it found
		for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
		{
			IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);

			if (sa->IkeClient == c)
			{
				sa->IkeClient = cc;
			}
		}
		for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
		{
			IPSECSA *sa = LIST_DATA(ike->IPsecSaList, i);

			if (sa->IkeClient == c)
			{
				sa->IkeClient = cc;
			}
		}

		if (cc->LastCommTick < c->LastCommTick)
		{
			StrCpy(cc->ClientId, sizeof(cc->ClientId), c->ClientId);
		}

		cc->FirstCommTick = MIN(cc->FirstCommTick, c->FirstCommTick);
		cc->LastCommTick = MAX(cc->LastCommTick, c->LastCommTick);

		ret = cc;

		IPToStr(client_ip_str, sizeof(client_ip_str), client_ip);
		IPToStr(server_ip_str, sizeof(server_ip_str), server_ip);

		Debug("Merge IKE_CLIENT: %p->%p: %s:%u -> %s:%u\n", c, cc, client_ip_str, client_port, server_ip_str, server_port);

		IPsecLog(ike, c, NULL, NULL, "LI_CLIENT_MERGE", c->Id, cc->Id, cc->Id);

		// Remove old IKE_CLIENT from the list and free
		Delete(ike->ClientList, c);
		FreeIkeClient(ike, c);
	}
	else
	{
		// Rewrite the end point information of this IKE_CLIENT because not found
		Copy(&c->ClientIP, client_ip, sizeof(IP));
		Copy(&c->ServerIP, server_ip, sizeof(IP));
		c->ClientPort = client_port;
		c->ServerPort = server_port;

		IPToStr(client_ip_str, sizeof(client_ip_str), client_ip);
		IPToStr(server_ip_str, sizeof(server_ip_str), server_ip);

		Debug("Update IKE_CLIENT: %p: %s:%u -> %s:%u\n", c, client_ip_str, client_port, server_ip_str, server_port);

		IPsecLog(ike, c, NULL, NULL, "LI_CLIENT_UPDATE");

		ike->ClientList->sorted = false;
	}

	return ret;
}

// Select the optimal transform setting for IPsec SA
bool GetBestTransformSettingForIPsecSa(IKE_SERVER *ike, IKE_PACKET *pr, IPSEC_SA_TRANSFORM_SETTING *setting, IP *server_ip)
{
	IKE_PACKET_PAYLOAD *sa_payload;
	IKE_PACKET_SA_PAYLOAD *sa;
	UINT i, num;
	bool ocmii_flag = false;
	// Validate arguments
	if (ike == NULL || pr == NULL || setting == NULL || server_ip == NULL)
	{
		return false;
	}

	Zero(setting, sizeof(IPSEC_SA_TRANSFORM_SETTING));

	// Get the SA payload
	sa_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_SA, 0);
	if (sa_payload == NULL)
	{
		return false;
	}

	sa = &sa_payload->Payload.Sa;

	// Scan all proposal payloads
	num = IkeGetPayloadNum(sa->PayloadList, IKE_PAYLOAD_PROPOSAL);
	for (i = 0;i < num;i++)
	{
		IKE_PACKET_PAYLOAD *proposal_payload = IkeGetPayload(sa->PayloadList, IKE_PAYLOAD_PROPOSAL, i);

		if (proposal_payload != NULL)
		{
			IKE_PACKET_PROPOSAL_PAYLOAD *proposal = &proposal_payload->Payload.Proposal;

			// Examine the contents of the proposal payload
			if (proposal->ProtocolId == IKE_PROTOCOL_ID_IPSEC_ESP && proposal->Spi->Size == 4)
			{
				// Scan all transform payloads
				UINT j, num2;

				num2 = IkeGetPayloadNum(proposal->PayloadList, IKE_PAYLOAD_TRANSFORM);
				for (j = 0;j < num2;j++)
				{
					IKE_PACKET_PAYLOAD *transform_payload = IkeGetPayload(proposal->PayloadList, IKE_PAYLOAD_TRANSFORM, j);
					if (transform_payload != NULL)
					{
						IKE_PACKET_TRANSFORM_PAYLOAD *transform = &transform_payload->Payload.Transform;
						IPSEC_SA_TRANSFORM_SETTING set;

						if (TransformPayloadToTransformSettingForIPsecSa(ike, transform, &set, server_ip))
						{
							Copy(setting, &set, sizeof(IPSEC_SA_TRANSFORM_SETTING));

							setting->SpiServerToClient = READ_UINT(proposal->Spi->Buf);

							return true;
						}
						else
						{
							if (set.OnlyCapsuleModeIsInvalid)
							{
								if (ocmii_flag == false)
								{
									Copy(setting, &set, sizeof(IPSEC_SA_TRANSFORM_SETTING));
									ocmii_flag = true;
								}
							}
						}
					}
				}
			}
		}
	}

	return false;
}

// Select the optimal transform settings for the IKE SA
bool GetBestTransformSettingForIkeSa(IKE_SERVER *ike, IKE_PACKET *pr, IKE_SA_TRANSFORM_SETTING *setting)
{
	IKE_PACKET_PAYLOAD *sa_payload;
	IKE_PACKET_SA_PAYLOAD *sa;
	UINT i, num;
	// Validate arguments
	if (ike == NULL || pr == NULL || setting == NULL)
	{
		return false;
	}

	// Get the SA payload
	sa_payload = IkeGetPayload(pr->PayloadList, IKE_PAYLOAD_SA, 0);
	if (sa_payload == NULL)
	{
		return false;
	}

	sa = &sa_payload->Payload.Sa;

	// Scan all proposal payloads
	num = IkeGetPayloadNum(sa->PayloadList, IKE_PAYLOAD_PROPOSAL);
	for (i = 0;i < num;i++)
	{
		IKE_PACKET_PAYLOAD *proposal_payload = IkeGetPayload(sa->PayloadList, IKE_PAYLOAD_PROPOSAL, i);

		if (proposal_payload != NULL)
		{
			IKE_PACKET_PROPOSAL_PAYLOAD *proposal = &proposal_payload->Payload.Proposal;

			// Examine the contents of the proposal payload
			if (proposal->ProtocolId == IKE_PROTOCOL_ID_IKE)
			{
				// Scan all transform payloads
				UINT j, num2;

				num2 = IkeGetPayloadNum(proposal->PayloadList, IKE_PAYLOAD_TRANSFORM);
				for (j = 0;j < num2;j++)
				{
					IKE_PACKET_PAYLOAD *transform_payload = IkeGetPayload(proposal->PayloadList, IKE_PAYLOAD_TRANSFORM, j);
					if (transform_payload != NULL)
					{
						IKE_PACKET_TRANSFORM_PAYLOAD *transform = &transform_payload->Payload.Transform;

						if (transform->TransformId == IKE_TRANSFORM_ID_P1_KEY_IKE)
						{
							IKE_SA_TRANSFORM_SETTING set;

							if (TransformPayloadToTransformSettingForIkeSa(ike, transform, &set))
							{
								Copy(setting, &set, sizeof(IKE_SA_TRANSFORM_SETTING));
								return true;
							}
						}
					}
				}
			}
		}
	}

	return false;
}

// Convert a structure to the transform payload (for IPsec SA)
IKE_PACKET_PAYLOAD *TransformSettingToTransformPayloadForIPsec(IKE_SERVER *ike, IPSEC_SA_TRANSFORM_SETTING *setting)
{
	LIST *value_list;
	// Validate arguments
	if (ike == NULL || setting == NULL)
	{
		return NULL;
	}

	value_list = NewListFast(NULL);

	Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P2_HMAC, setting->HashId));

	if (setting->Dh != NULL)
	{
		Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P2_DH_GROUP, setting->DhId));
	}

	if (setting->LifeSeconds != INFINITE)
	{
		Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P2_LIFE_TYPE, IKE_P2_LIFE_TYPE_SECONDS));
		Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P2_LIFE_VALUE, setting->LifeSeconds));
	}

	if (setting->LifeKilobytes != INFINITE)
	{
		Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P2_LIFE_TYPE, IKE_P2_LIFE_TYPE_KILOBYTES));
		Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P2_LIFE_VALUE, setting->LifeKilobytes));
	}

	if (setting->Crypto->VariableKeySize)
	{
		Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P2_KEY_SIZE, setting->CryptoKeySize * 8));
	}

	Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P2_CAPSULE, setting->CapsuleMode));

	return IkeNewTransformPayload(1, setting->CryptoId, value_list);
}

// Convert a structure to the transform payload (for IKE SA)
IKE_PACKET_PAYLOAD *TransformSettingToTransformPayloadForIke(IKE_SERVER *ike, IKE_SA_TRANSFORM_SETTING *setting)
{
	LIST *value_list;
	// Validate arguments
	if (ike == NULL || setting == NULL)
	{
		return NULL;
	}

	value_list = NewListFast(NULL);

	Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P1_CRYPTO, setting->CryptoId));
	Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P1_HASH, setting->HashId));
	Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P1_AUTH_METHOD, IKE_P1_AUTH_METHOD_PRESHAREDKEY));
	Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P1_DH_GROUP, setting->DhId));

	if (setting->LifeSeconds != INFINITE)
	{
		Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P1_LIFE_TYPE, IKE_P1_LIFE_TYPE_SECONDS));
		Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P1_LIFE_VALUE, setting->LifeSeconds));
	}

	if (setting->LifeKilobytes != INFINITE)
	{
		Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P1_LIFE_TYPE, IKE_P1_LIFE_TYPE_KILOBYTES));
		Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P1_LIFE_VALUE, setting->LifeKilobytes));
	}

	if (setting->Crypto->VariableKeySize)
	{
		Add(value_list, IkeNewTransformValue(IKE_TRANSFORM_VALUE_P1_KET_SIZE, setting->CryptoKeySize * 8));
	}

	return IkeNewTransformPayload(1, IKE_TRANSFORM_ID_P1_KEY_IKE, value_list);
}

// Convert a transform payload to a structure (for IPsec SA)
bool TransformPayloadToTransformSettingForIPsecSa(IKE_SERVER *ike, IKE_PACKET_TRANSFORM_PAYLOAD *transform, IPSEC_SA_TRANSFORM_SETTING *setting, IP *server_ip)
{
	UINT i;
	UINT capsule_mode;
	bool is_esp_supported;
	// Validate arguments
	if (ike == NULL || transform == NULL || setting == NULL || server_ip == NULL)
	{
		return false;
	}

	is_esp_supported = IsUdpPortOpened(ike->IPsec->UdpListener, server_ip, IPSEC_PORT_IPSEC_ESP_RAW);

	Zero(setting, sizeof(IPSEC_SA_TRANSFORM_SETTING));

	setting->CryptoId = transform->TransformId;
	setting->HashId = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P2_HMAC, 0);

	setting->DhId = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P2_DH_GROUP, 0);

	setting->LifeKilobytes = INFINITE;
	setting->LifeSeconds = INFINITE;

	for (i = 0;i < IkeGetTransformValueNum(transform, IKE_TRANSFORM_VALUE_P2_LIFE_TYPE);i++)
	{
		UINT life_type = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P2_LIFE_TYPE, i);

		switch (life_type)
		{
		case IKE_P2_LIFE_TYPE_SECONDS:		// Number of seconds
			setting->LifeSeconds = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P2_LIFE_VALUE, i);
			break;

		case IKE_P2_LIFE_TYPE_KILOBYTES:	// Kilobytes
			setting->LifeKilobytes = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P2_LIFE_VALUE, i);
			break;

		default:
			// Unsupported expiration type
			return false;
		}
	}

	setting->Crypto = GetIkeCrypto(ike->Engine, true, setting->CryptoId);
	setting->Hash = GetIkeHash(ike->Engine, true, setting->HashId);
	setting->Dh = GetIkeDh(ike->Engine, true, setting->DhId);

	if (setting->Crypto == NULL || setting->Hash == NULL)
	{
		// Unsupported algorithm
		return false;
	}

	if (setting->Crypto->VariableKeySize)
	{
		// Get the actual key size in the case of variable key size
		setting->CryptoKeySize = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P2_KEY_SIZE, 0);

		// bits -> bytes
		setting->CryptoKeySize = setting->CryptoKeySize / 8;

		if (setting->CryptoKeySize == 0 || IkeCheckKeySize(setting->Crypto, setting->CryptoKeySize) == false)
		{
			// The key size is not specified or inappropriate
			return false;
		}
	}
	else
	{
		// Get a fixed key length for fixed key size
		setting->CryptoKeySize = setting->Crypto->KeySizes[0];
	}

	capsule_mode = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P2_CAPSULE, 0);
	if (capsule_mode != IKE_P2_CAPSULE_NAT_TUNNEL_1 && capsule_mode != IKE_P2_CAPSULE_NAT_TUNNEL_2 &&
		capsule_mode != IKE_P2_CAPSULE_NAT_TRANSPORT_1 && capsule_mode != IKE_P2_CAPSULE_NAT_TRANSPORT_2)
	{
		// No support for UDP encapsulation mode except for the NAT-Traversal
		if (capsule_mode == IKE_P2_CAPSULE_TRANSPORT || capsule_mode == IKE_P2_CAPSULE_TUNNEL)
		{
			if (is_esp_supported == false)
			{
				setting->OnlyCapsuleModeIsInvalid = true;
				return false;
			}
			else
			{
				// It is an environment that can send and receive ESP packets
			}
		}
		else
		{
			return false;
		}
	}

	setting->CapsuleMode = capsule_mode;

	return true;
}

// Convert a transform payload to a structure (for IKE SA)
bool TransformPayloadToTransformSettingForIkeSa(IKE_SERVER *ike, IKE_PACKET_TRANSFORM_PAYLOAD *transform, IKE_SA_TRANSFORM_SETTING *setting)
{
	UINT i;
	// Validate arguments
	if (ike == NULL || transform == NULL || setting == NULL)
	{
		return false;
	}

	Zero(setting, sizeof(IKE_SA_TRANSFORM_SETTING));

	setting->CryptoId = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P1_CRYPTO, 0);
	setting->HashId = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P1_HASH, 0);

	if (IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P1_AUTH_METHOD, 0) != IKE_P1_AUTH_METHOD_PRESHAREDKEY)
	{
		// Only PSK authentication method is supported
		return false;
	}

	setting->DhId = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P1_DH_GROUP, 0);

	setting->LifeKilobytes = INFINITE;
	setting->LifeSeconds = INFINITE;

	for (i = 0;i < IkeGetTransformValueNum(transform, IKE_TRANSFORM_VALUE_P1_LIFE_TYPE);i++)
	{
		UINT life_type = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P1_LIFE_TYPE, i);

		switch (life_type)
		{
		case IKE_P1_LIFE_TYPE_SECONDS:		// Number of seconds
			setting->LifeSeconds = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P1_LIFE_VALUE, i);
			break;

		case IKE_P1_LIFE_TYPE_KILOBYTES:	// Kilobytes
			setting->LifeKilobytes = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P1_LIFE_VALUE, i);
			break;

		default:
			// Unsupported expiration type
			return false;
		}
	}

	setting->Crypto = GetIkeCrypto(ike->Engine, false, setting->CryptoId);
	setting->Hash = GetIkeHash(ike->Engine, false, setting->HashId);
	setting->Dh = GetIkeDh(ike->Engine, false, setting->DhId);

	if (setting->Crypto == NULL || setting->Hash == NULL || setting->Dh == NULL)
	{
		// Unsupported algorithm
		return false;
	}

	if (setting->Crypto->VariableKeySize)
	{
		// Get the actual key size in the case of variable key size
		setting->CryptoKeySize = IkeGetTransformValue(transform, IKE_TRANSFORM_VALUE_P1_KET_SIZE, 0);

		// bits -> bytes
		setting->CryptoKeySize = setting->CryptoKeySize / 8;

		if (setting->CryptoKeySize == 0 || IkeCheckKeySize(setting->Crypto, setting->CryptoKeySize) == false)
		{
			// The key size is not specified or inappropriate
			return false;
		}
	}
	else
	{
		// Get a fixed key length for fixed key size
		setting->CryptoKeySize = setting->Crypto->KeySizes[0];
	}

	return true;
}

// Creating a new Responder Cookie
UINT64 GenerateNewResponserCookie(IKE_SERVER *ike)
{
	UINT64 c;
	// Validate arguments
	if (ike == NULL)
	{
		return 0;
	}

	while (true)
	{
		bool b = false;
		UINT i;

		c = Rand64();

		for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
		{
			IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);

			if (sa->ResponderCookie == c)
			{
				b = true;
				break;
			}
		}

		if (b == false)
		{
			return c;
		}
	}
}

// Parse the IKE packet header
IKE_PACKET *ParseIKEPacketHeader(UDPPACKET *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	return IkeParseHeader(p->Data, p->Size, NULL);
}

// Search for another IPsec SA belonging to the IKE_CLIENT which have same conditions to the specified IPsec SA
IPSECSA *GetOtherLatestIPsecSa(IKE_SERVER *ike, IPSECSA *sa)
{
	UINT i;
	UINT64 min_value = 0;
	IPSECSA *max_sa = NULL;
	// Validate arguments
	if (ike == NULL || sa == NULL)
	{
		return NULL;
	}

	if (sa->IkeClient == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
	{
		IPSECSA *sa2 = LIST_DATA(ike->IPsecSaList, i);

		if (sa2 != sa)
		{
			if (sa2->IkeClient == sa->IkeClient)
			{
				if (sa2->ServerToClient == sa->ServerToClient)
				{
					if (sa2->Deleting == false)
					{
						if (sa2->Established)
						{
							UINT64 last_comm_tick = sa2->LastCommTick;

							if (sa2->ServerToClient)
							{
								if (sa2->PairIPsecSa != NULL)
								{
									last_comm_tick = sa2->PairIPsecSa->LastCommTick;
								}
							}

							if (min_value < last_comm_tick)
							{
								min_value = last_comm_tick;

								max_sa = sa2;
							}
						}
					}
				}
			}
		}
	}

	return max_sa;
}

// Search for another IKE_SA belonging to the IKE_CLIENT which have same conditions to the specified IKE_SA
IKE_SA *GetOtherLatestIkeSa(IKE_SERVER *ike, IKE_SA *sa)
{
	UINT i;
	UINT64 min_value = 0;
	IKE_SA *max_sa = NULL;
	// Validate arguments
	if (ike == NULL || sa == NULL)
	{
		return NULL;
	}

	if (sa->IkeClient == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
	{
		IKE_SA *sa2 = LIST_DATA(ike->IkeSaList, i);

		if (sa2 != sa)
		{
			if (sa2->IkeClient == sa->IkeClient)
			{
				if (sa2->Deleting == false)
				{
					if (sa2->Established)
					{
						if (min_value < sa2->LastCommTick)
						{
							min_value = sa2->LastCommTick;

							max_sa = sa2;
						}
					}
				}
			}
		}
	}

	return max_sa;
}

// Purge the IPsec SA
void PurgeIPsecSa(IKE_SERVER *ike, IPSECSA *sa)
{
	UINT i;
	IPSECSA *other_sa;
	// Validate arguments
	if (ike == NULL || sa == NULL)
	{
		return;
	}

	other_sa = GetOtherLatestIPsecSa(ike, sa);

	// Rewrite the pairing partner by looking for IPsec SA that are paired
	for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
	{
		IPSECSA *sa2 = LIST_DATA(ike->IPsecSaList, i);

		if (sa2->PairIPsecSa == sa)
		{
			sa2->PairIPsecSa = other_sa;
		}
	}

	// Rewrite the IKE_CLIENT using this IPsec SA to use alternate
	for (i = 0;i < LIST_NUM(ike->ClientList);i++)
	{
		IKE_CLIENT *c = LIST_DATA(ike->ClientList, i);

		if (c->CurrentIpSecSaRecv == sa)
		{
			c->CurrentIpSecSaRecv = other_sa;
		}

		if (c->CurrentIpSecSaSend == sa)
		{
			c->CurrentIpSecSaSend = other_sa;
		}
	}

	Delete(ike->IPsecSaList, sa);
	FreeIPsecSa(sa);
}

// Remove the IKE SA
void PurgeIkeSa(IKE_SERVER *ike, IKE_SA *sa)
{
	IKE_SA *other_sa;
	UINT i;
	// Validate arguments
	if (ike == NULL || sa == NULL)
	{
		return;
	}

	Debug("Purging IKE SA %I64u-%I64u\n", sa->InitiatorCookie, sa->ResponderCookie);

	// Rewrite to alternative IKE_SA of all IPsec SA that are using this IKE_SA
	other_sa = GetOtherLatestIkeSa(ike, sa);

	for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
	{
		IPSECSA *ipsec_sa = LIST_DATA(ike->IPsecSaList, i);

		if (ipsec_sa->IkeSa == sa)
		{
			if (other_sa == NULL)
			{
				// Remove this IPsec SA because there is no alternative IKE_SA
				Debug("  Deleting IPsec SA 0x%X of this IKE SA (no alternatives)\n", ipsec_sa->Spi);
				MarkIPsecSaAsDeleted(ike, ipsec_sa);
				ipsec_sa->IkeSa = NULL;
			}
			else
			{
				// Replace to the alternative IKE_SA
				Debug("  Replacing IKE SA of IPsec SA 0x%X from %I64u-%I64u to %I64u-%I64u\n", ipsec_sa->Spi,
					sa->InitiatorCookie, sa->ResponderCookie,
					other_sa->InitiatorCookie, other_sa->ResponderCookie);
				ipsec_sa->IkeSa = other_sa;
			}
		}
	}

	// Substitute the IKE_SA of all IKE_CLIENT that are using this IKE_SA with alternative
	for (i = 0;i < LIST_NUM(ike->ClientList);i++)
	{
		IKE_CLIENT *c = LIST_DATA(ike->ClientList, i);

		if (c->CurrentIkeSa == sa)
		{
			c->CurrentIkeSa = other_sa;
		}
	}

	Delete(ike->IkeSaList, sa);
	FreeIkeSa(sa);
}

// Purge the IKE_CLIENT
void PurgeIkeClient(IKE_SERVER *ike, IKE_CLIENT *c)
{
	UINT i;
	// Validate arguments
	if (ike == NULL || c == NULL)
	{
		return;
	}

	// Delete all of IPsec SA and IKE SA that belong to this IKE Client
	for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
	{
		IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);

		if (sa->IkeClient == c)
		{
			MarkIkeSaAsDeleted(ike, sa);
		}
	}
	for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
	{
		IPSECSA *sa = LIST_DATA(ike->IPsecSaList, i);

		if (sa->IkeClient == c)
		{
			MarkIPsecSaAsDeleted(ike, sa);
		}
	}

	Delete(ike->ClientList, c);
	FreeIkeClient(ike, c);
}

// Remove the SA that has been marked to delete
void PurgeDeletingSAsAndClients(IKE_SERVER *ike)
{
	UINT i;
	LIST *o = NULL;
	// Validate arguments
	if (ike == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
	{
		IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);
		if (sa->Deleting)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Add(o, sa);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_SA *sa = LIST_DATA(o, i);

		PurgeIkeSa(ike, sa);
	}

	ReleaseList(o);

	o = NULL;

	for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
	{
		IPSECSA *sa = LIST_DATA(ike->IPsecSaList, i);
		if (sa->Deleting)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Add(o, sa);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IPSECSA *sa = LIST_DATA(o, i);

		PurgeIPsecSa(ike, sa);
	}

	ReleaseList(o);

	o = NULL;

	for (i = 0;i < LIST_NUM(ike->ClientList);i++)
	{
		IKE_CLIENT *c = LIST_DATA(ike->ClientList, i);
		if (c->Deleting)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Add(o, c);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IKE_CLIENT *c = LIST_DATA(o, i);

		PurgeIkeClient(ike, c);
	}

	ReleaseList(o);
}

// IKE interrupt process
void ProcessIKEInterrupts(IKE_SERVER *ike)
{
	UINT i;
	// Validate arguments
	if (ike == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(ike->ClientList);i++)
	{
		IKE_CLIENT *c = LIST_DATA(ike->ClientList, i);

		c->CurrentExpiresSoftTick_CtoS = 0;
		c->CurrentExpiresSoftTick_StoC = 0;
		c->CurrentNumEstablishedIPsecSA_CtoS = 0;
		c->CurrentNumEstablishedIPsecSA_StoC = 0;
		c->CurrentNumHealtyIPsecSA_CtoS = 0;
		c->CurrentNumHealtyIPsecSA_StoC = 0;
	}

	// Packet retransmission by scanning all IKE SA
	for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
	{
		IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);

		if (sa->SendBuffer != NULL)
		{
			if (ike->Now >= sa->NextSendTick)
			{
				IKE_CLIENT *c = sa->IkeClient;

				IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP, &c->ServerIP, c->ServerPort, &c->ClientIP, c->ClientPort,
					Clone(sa->SendBuffer->Buf, sa->SendBuffer->Size), sa->SendBuffer->Size);

				sa->NextSendTick += (UINT64)(IKE_SA_RESEND_INTERVAL);

				AddInterrupt(ike->Interrupts, sa->NextSendTick);

				if (sa->NumResends != 0)
				{
					sa->NumResends--;
					if (sa->NumResends == 0)
					{
						sa->NextSendTick = 0;
						FreeBuf(sa->SendBuffer);
						sa->SendBuffer = NULL;
					}
				}
			}
		}

		// Remove those of non-communication
		if (sa->IkeClient == NULL || (sa->IkeClient->CurrentIkeSa != sa))
		{
			// When the IKE_CLIENT don't point this
			if (sa->Established == false)
			{
				// Make time-out in a short time when it is not established
				if ((sa->LastCommTick + (UINT64)IKE_TIMEOUT_FOR_IKE_CLIENT_FOR_NOT_ESTABLISHED) <= ike->Now)
				{
					WHERE;
					MarkIkeSaAsDeleted(ike, sa);
				}
			}
			else
			{
				// Timeout in a long time in the case of established
				if ((sa->LastCommTick + (UINT64)IKE_TIMEOUT_FOR_IKE_CLIENT) <= ike->Now)
				{
					WHERE;
					MarkIkeSaAsDeleted(ike, sa);
				}
			}
		}
	}

	// Packet retransmission by scanning all IPsec SA
	for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
	{
		IPSECSA *sa = LIST_DATA(ike->IPsecSaList, i);
		IKE_CLIENT *c = sa->IkeClient;

		if (sa->SendBuffer != NULL)
		{
			if (ike->Now >= sa->NextSendTick)
			{
				IKE_CLIENT *c = sa->IkeClient;

				IkeSendUdpPacket(ike, IKE_UDP_TYPE_ISAKMP, &c->ServerIP, c->ServerPort, &c->ClientIP, c->ClientPort,
					Clone(sa->SendBuffer->Buf, sa->SendBuffer->Size), sa->SendBuffer->Size);

				sa->NextSendTick += (UINT64)(IKE_SA_RESEND_INTERVAL);

				AddInterrupt(ike->Interrupts, sa->NextSendTick);

				if (sa->NumResends != 0)
				{
					sa->NumResends--;

					if (sa->NumResends == 0)
					{
						sa->NextSendTick = 0;
						FreeBuf(sa->SendBuffer);
						sa->SendBuffer = NULL;
					}
				}
			}
		}

		if (sa->Established && sa->Deleting == false && c != NULL)
		{
			// Get the flexible expiration date of SA for each IKE_CLIENT
			if (sa->ServerToClient)
			{
				c->CurrentExpiresSoftTick_StoC = MAX(c->CurrentExpiresSoftTick_StoC, sa->ExpiresSoftTick);
				c->CurrentNumEstablishedIPsecSA_StoC++;

				if (sa->ExpiresSoftTick == 0 || sa->ExpiresSoftTick > ike->Now)
				{
					c->CurrentNumHealtyIPsecSA_StoC++;
				}
			}
			else
			{
				c->CurrentExpiresSoftTick_CtoS = MAX(c->CurrentExpiresSoftTick_CtoS, sa->ExpiresSoftTick);
				c->CurrentNumEstablishedIPsecSA_CtoS++;

				if (sa->ExpiresSoftTick == 0 || sa->ExpiresSoftTick > ike->Now)
				{
					c->CurrentNumHealtyIPsecSA_CtoS++;
				}
			}
		}

		// Remove those of non-communication
		if (sa->IkeClient == NULL || (sa->IkeClient->CurrentIpSecSaRecv != sa && sa->IkeClient->CurrentIpSecSaSend != sa))
		{
			// When the IKE_CLIENT don't point this
			UINT64 last_comm_tick = sa->LastCommTick;

			if (sa->ServerToClient && sa->PairIPsecSa != NULL)
			{
				last_comm_tick = sa->PairIPsecSa->LastCommTick;
			}

			if (sa->Established == false)
			{
				// Make time-out in a short time when it is not established
				if ((last_comm_tick + (UINT64)IKE_TIMEOUT_FOR_IKE_CLIENT_FOR_NOT_ESTABLISHED) <= ike->Now)
				{
					WHERE;
					MarkIPsecSaAsDeleted(ike, sa);
				}
			}
			else
			{
				// Timeout in a long time in the case of established
				if ((last_comm_tick + (UINT64)IKE_TIMEOUT_FOR_IKE_CLIENT) <= ike->Now)
				{
					WHERE;
					MarkIPsecSaAsDeleted(ike, sa);
				}
			}
		}
	}

	// IKE_CLIENT scanning process
	for (i = 0;i < LIST_NUM(ike->ClientList);i++)
	{
		IKE_CLIENT *c = LIST_DATA(ike->ClientList, i);
		UINT64 tick;
		UCHAR data[1];
		bool need_qm = false;
		bool need_qm_hard = false;
		UINT64 qm_soft_tick = 0;

		// Determine whether it is necessary to start a new Quick Mode
		if (c->CurrentExpiresSoftTick_StoC != 0 && ike->Now >= c->CurrentExpiresSoftTick_StoC)
		{
			need_qm = true;
			qm_soft_tick = MAX(qm_soft_tick, c->CurrentExpiresSoftTick_StoC);
		}

		if (c->CurrentExpiresSoftTick_CtoS != 0 && ike->Now >= c->CurrentExpiresSoftTick_CtoS)
		{
			need_qm = true;
			qm_soft_tick = MAX(qm_soft_tick, c->CurrentExpiresSoftTick_StoC);
		}

		if (c->CurrentNumHealtyIPsecSA_CtoS == 0 || c->CurrentNumHealtyIPsecSA_StoC == 0)
		{
			need_qm = true;
			need_qm_hard = true;
		}

		if (c->StartQuickModeAsSoon)
		{
			need_qm = true;
			need_qm_hard = true;
		}

		if (c->Deleting || c->CurrentIkeSa == NULL || c->CurrentIkeSa->Deleting)
		{
			need_qm = false;
			need_qm_hard = true;
		}

		if (need_qm)
		{
			if (c->StartQuickModeAsSoon || ((c->LastQuickModeStartTick + (UINT64)IKE_QUICKMODE_START_INTERVAL) <= ike->Now))
			{
				// Start the Quick Mode
				Debug("IKE_CLIENT 0x%X: Begin QuickMode\n", c);
				c->StartQuickModeAsSoon = false;
				c->LastQuickModeStartTick = ike->Now;

				AddInterrupt(ike->Interrupts, c->LastQuickModeStartTick + (UINT64)IKE_QUICKMODE_START_INTERVAL);

				StartQuickMode(ike, c);
			}
		}

		if (need_qm_hard)
		{
			if (c->NeedQmBeginTick == 0)
			{
				c->NeedQmBeginTick = ike->Now;
			}
		}
		else
		{
			c->NeedQmBeginTick = 0;
		}

		if (((c->LastCommTick + (UINT64)IKE_TIMEOUT_FOR_IKE_CLIENT) <= ike->Now) ||
			((c->CurrentIkeSa == NULL && c->CurrentIpSecSaRecv == NULL && c->CurrentIpSecSaSend == NULL) && (c->LastCommTick + (UINT64)IKE_TIMEOUT_FOR_IKE_CLIENT_FOR_NOT_ESTABLISHED) <= ike->Now) ||
			(c->NeedQmBeginTick != 0 && ((c->NeedQmBeginTick + (UINT64)IKE_QUICKMODE_FAILED_TIMEOUT) <= ike->Now)))
		{
			// Remove IKE_CLIENT not communicating for a certain period of time
			WHERE;
			MarkIkeClientAsDeleted(ike, c);
		}

		// L2TP processing
		if (c->L2TP != NULL)
		{
			IPsecIkeClientManageL2TPServer(ike, c);

			// Interrupt processing occurs
			L2TPProcessInterrupts(c->L2TP);

			// Packet transmission
			IPsecIkeClientSendL2TPPackets(ike, c, c->L2TP);
		}

		// EtherIP processing
		if (c->EtherIP != NULL)
		{
			IPsecIkeClientManageEtherIPServer(ike, c);

			// Interrupt processing occurs
			EtherIPProcInterrupts(c->EtherIP);

			// Packet transmission
			IPsecIkeClientSendEtherIPPackets(ike, c, c->EtherIP);
		}

		// KeepAlive transmission
		tick = MAX(c->LastCommTick + (UINT64)IKE_INTERVAL_UDP_KEEPALIVE, c->NextKeepAliveSendTick);

		if (tick <= ike->Now && c->ServerPort == IPSEC_PORT_IPSEC_ESP_UDP)
		{
			c->NextKeepAliveSendTick = ike->Now + (UINT64)IKE_INTERVAL_UDP_KEEPALIVE;

			AddInterrupt(ike->Interrupts, c->NextKeepAliveSendTick);

			Zero(data, sizeof(data));
			data[0] = 0xff;

			IkeSendUdpPacket(ike, IKE_UDP_KEEPALIVE, &c->ServerIP, c->ServerPort, &c->ClientIP, c->ClientPort, Clone(data, sizeof(data)), sizeof(data));
		}

		// DPD transmission
		if (c->NextDpdSendTick == 0 || c->NextDpdSendTick <= ike->Now)
		{
			if (c->CurrentIkeSa != NULL && c->CurrentIkeSa->Established)
			{
				if (c->CurrentIkeSa->Caps.DpdRfc3706)
				{
					c->NextDpdSendTick = ike->Now + (UINT64)IKE_INTERVAL_DPD_KEEPALIVE;

					AddInterrupt(ike->Interrupts, c->NextDpdSendTick);

					SendInformationalExchangePacket(ike, c,
						IkeNewNoticeDpdPayload(false, c->CurrentIkeSa->InitiatorCookie, c->CurrentIkeSa->ResponderCookie,
						c->DpdSeqNo++));
				}
			}
		}
	}

	do
	{
		ike->StateHasChanged = false;

		// Deletion process
		PurgeDeletingSAsAndClients(ike);
	}
	while (ike->StateHasChanged);

	// Maintenance of the thread list
	MainteThreadList(ike->ThreadList);
	/*Debug("ike->ThreadList: %u\n", LIST_NUM(ike->ThreadList));
	{
		UINT i;
		for (i = 0;i < LIST_NUM(ike->ThreadList);i++)
		{
			THREAD *t = LIST_DATA(ike->ThreadList, i);

			Debug("  Thread %u: 0x%p ID: %u Stop: %u Ref: %u\n", i, t, t->ThreadId, t->Stopped, t->ref->c->c);
		}
	}*/
}

// Stop the IKE server
void StopIKEServer(IKE_SERVER *ike)
{
	// Validate arguments
	if (ike == NULL)
	{
		return;
	}
}

// Set the socket events in IKE server
void SetIKEServerSockEvent(IKE_SERVER *ike, SOCK_EVENT *e)
{
	// Validate arguments
	if (ike == NULL)
	{
		return;
	}

	if (e != NULL)
	{
		AddRef(e->ref);
	}

	if (ike->SockEvent != NULL)
	{
		ReleaseSockEvent(ike->SockEvent);
	}

	ike->SockEvent = e;
}

// Release the IKE client
void FreeIkeClient(IKE_SERVER *ike, IKE_CLIENT *c)
{
	// Validate arguments
	if (c == NULL || ike == NULL)
	{
		return;
	}

	if (c->L2TP != NULL)
	{
		StopL2TPServer(c->L2TP, true);
		FreeL2TPServer(c->L2TP);
	}

	if (c->EtherIP != NULL)
	{
		ReleaseEtherIPServer(c->EtherIP);
	}

	FreeBuf(c->SendID1_Buf);
	FreeBuf(c->SendID2_Buf);

	Free(c);
}

// Release the IPsec SA
void FreeIPsecSa(IPSECSA *sa)
{
	// Validate arguments
	if (sa == NULL)
	{
		return;
	}

	IkeFreeKey(sa->CryptoKey);

	FreeBuf(sa->SendBuffer);

	FreeBuf(sa->InitiatorRand);
	FreeBuf(sa->ResponderRand);

	FreeBuf(sa->SharedKey);

	IkeDhFreeCtx(sa->Dh);

	Free(sa);
}

// Release the IKE SA
void FreeIkeSa(IKE_SA *sa)
{
	// Validate arguments
	if (sa == NULL)
	{
		return;
	}

	FreeBuf(sa->SendBuffer);

	FreeBuf(sa->InitiatorRand);
	FreeBuf(sa->ResponderRand);
	FreeBuf(sa->DhSharedKey);
	FreeBuf(sa->YourIDPayloadForAM);

	FreeBuf(sa->GXi);
	FreeBuf(sa->GXr);

	FreeBuf(sa->SAi_b);

	IkeFreeKey(sa->CryptoKey);

	Free(sa);
}

// Release the IKE server
void FreeIKEServer(IKE_SERVER *ike)
{
	UINT i;
	// Validate arguments
	if (ike == NULL)
	{
		return;
	}

	IPsecLog(ike, NULL, NULL, NULL, "LI_STOPPING");

	for (i = 0;i < LIST_NUM(ike->SendPacketList);i++)
	{
		UDPPACKET *udp = LIST_DATA(ike->SendPacketList, i);

		FreeUdpPacket(udp);
	}

	ReleaseList(ike->SendPacketList);

	Debug("Num of IPsec SAs: %u\n", LIST_NUM(ike->IPsecSaList));
	IPsecLog(ike, NULL, NULL, NULL, "LI_NUM_IPSEC_SA", LIST_NUM(ike->IPsecSaList));

	for (i = 0;i < LIST_NUM(ike->IPsecSaList);i++)
	{
		IPSECSA *sa = LIST_DATA(ike->IPsecSaList, i);

		FreeIPsecSa(sa);
	}

	ReleaseList(ike->IPsecSaList);

	Debug("Num of IKE SAs: %u\n", LIST_NUM(ike->IkeSaList));
	IPsecLog(ike, NULL, NULL, NULL, "LI_NUM_IKE_SA", LIST_NUM(ike->IkeSaList));

	for (i = 0;i < LIST_NUM(ike->IkeSaList);i++)
	{
		IKE_SA *sa = LIST_DATA(ike->IkeSaList, i);

		FreeIkeSa(sa);
	}

	ReleaseList(ike->IkeSaList);

	Debug("Num of IKE_CLIENTs: %u\n", LIST_NUM(ike->ClientList));
	IPsecLog(ike, NULL, NULL, NULL, "LI_NUM_IKE_CLIENTS", LIST_NUM(ike->ClientList));

	for (i = 0;i < LIST_NUM(ike->ClientList);i++)
	{
		IKE_CLIENT *c = LIST_DATA(ike->ClientList, i);

		FreeIkeClient(ike, c);
	}

	ReleaseList(ike->ClientList);

	ReleaseSockEvent(ike->SockEvent);

	IPsecLog(ike, NULL, NULL, NULL, "LI_STOP");

	ReleaseCedar(ike->Cedar);

	FreeIkeEngine(ike->Engine);

	Debug("FreeThreadList()...\n");
	FreeThreadList(ike->ThreadList);
	Debug("FreeThreadList() Done.\n");

	Free(ike);
}

// Create a new IKE server
IKE_SERVER *NewIKEServer(CEDAR *cedar, IPSEC_SERVER *ipsec)
{
	IKE_SERVER *ike;
	// Validate arguments
	if (cedar == NULL)
	{
		return NULL;
	}

	ike = ZeroMalloc(sizeof(IKE_SERVER));

	ike->Cedar = cedar;
	AddRef(cedar->ref);

	ike->IPsec = ipsec;

	ike->Now = Tick64();

	ike->SendPacketList = NewList(NULL);

	ike->IkeSaList = NewList(CmpIkeSa);

	ike->IPsecSaList = NewList(CmpIPsecSa);

	ike->ClientList = NewList(CmpIkeClient);

	ike->Engine = NewIkeEngine();

	ike->ThreadList = NewThreadList();

	IPsecLog(ike, NULL, NULL, NULL, "LI_START");

	return ike;
}




// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
