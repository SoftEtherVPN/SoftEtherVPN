// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Communication Module

// ProxyProtocol.c
// Implementation of the PROXY protocol (versions 1 and 2) receiver
// Specification: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

#include "ProxyProtocol.h"

#include "Memory.h"
#include "Object.h"
#include "Str.h"
#include "Tick64.h"

// The PROXY protocol version 2 binary signature
static const UCHAR pp_v2_signature[PP_V2_SIGNATURE_LENGTH] =
{
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51,
	0x55, 0x49, 0x54, 0x0A
};

// Peek data from a socket until the requested amount is available, or time out
// Returns the number of bytes currently available (>= 1), or 0 on error / timeout
static UINT PPPeekUntil(SOCK *s, UCHAR *buf, UINT need)
{
	UINT got = 0;
	UINT64 start;
	// Validate arguments
	if (s == NULL || buf == NULL || need == 0)
	{
		return 0;
	}

	start = Tick64();

	while (true)
	{
		UINT ret = Peek(s, buf, need);

		if (ret >= 1)
		{
			got = ret;

			if (ret >= need)
			{
				return ret;
			}
		}
		else
		{
			// The peer disconnected or a reception error occurred
			return 0;
		}

		// Time-out check
		if ((Tick64() - start) >= (UINT64)PP_HEADER_TIMEOUT)
		{
			return got;
		}

		SleepThread(5);
	}
}

// Consume exactly size bytes from the socket
static bool PPConsume(SOCK *s, UINT size, UCHAR *tmp)
{
	return RecvAll(s, tmp, size, false);
}

// Parse a PROXY protocol version 1 header line (without the trailing CRLF)
UINT PPParseV1Header(char *line, UINT line_len, PP_HEADER *header)
{
	TOKEN_LIST *tokens;
	// Validate arguments
	if (line == NULL || header == NULL)
	{
		return PP_RET_ERROR;
	}

	Zero(header, sizeof(PP_HEADER));

	// Replace the CRLF with a NUL to ease the parsing
	if (line_len >= 2 && line[line_len - 2] == '\r' && line[line_len - 1] == '\n')
	{
		line_len -= 2;
	}

	if (line_len == 0 || line_len > PP_V1_MAX_LENGTH)
	{
		return PP_RET_ERROR;
	}

	line[line_len] = 0;

	tokens = ParseToken(line, " \t");

	if (tokens->NumTokens >= 2 && StrCmpi(tokens->Token[0], "PROXY") == 0)
	{
		if (StrCmpi(tokens->Token[1], "TCP4") == 0 && tokens->NumTokens >= 6)
		{
			IP src, dst;
			UINT sport, dport;

			if (StrToIP(&src, tokens->Token[2]) == false || StrToIP(&dst, tokens->Token[3]) == false ||
				IsIP4(&src) == false || IsIP4(&dst) == false)
			{
				FreeToken(tokens);
				return PP_RET_ERROR;
			}

			sport = ToInt(tokens->Token[4]);
			dport = ToInt(tokens->Token[5]);

			if (sport > 65535 || dport > 65535)
			{
				FreeToken(tokens);
				return PP_RET_ERROR;
			}

			CopyIP(&header->SrcIp, &src);
			CopyIP(&header->DstIp, &dst);
			header->SrcPort = sport;
			header->DstPort = dport;
			header->IsV2 = false;
			header->Local = false;

			FreeToken(tokens);
			return PP_RET_PARSED;
		}
		else if (StrCmpi(tokens->Token[1], "TCP6") == 0 && tokens->NumTokens >= 6)
		{
			IP src, dst;
			UINT sport, dport;

			if (StrToIP(&src, tokens->Token[2]) == false || StrToIP(&dst, tokens->Token[3]) == false)
			{
				FreeToken(tokens);
				return PP_RET_ERROR;
			}

			sport = ToInt(tokens->Token[4]);
			dport = ToInt(tokens->Token[5]);

			if (sport > 65535 || dport > 65535)
			{
				FreeToken(tokens);
				return PP_RET_ERROR;
			}

			CopyIP(&header->SrcIp, &src);
			CopyIP(&header->DstIp, &dst);
			header->SrcPort = sport;
			header->DstPort = dport;
			header->IsV2 = false;
			header->Local = false;

			FreeToken(tokens);
			return PP_RET_PARSED;
		}
		else if (StrCmpi(tokens->Token[1], "UNKNOWN") == 0)
		{
			// Keep the socket address as-is
			header->IsV2 = false;
			header->Local = true;

			FreeToken(tokens);
			return PP_RET_PARSED;
		}
	}

	FreeToken(tokens);
	return PP_RET_ERROR;
}

// Parse a PROXY protocol version 2 header
// prefix: the first PP_V2_PREFIX_LENGTH bytes of the header
// block: the address block + TLVs (exactly block_len bytes)
UINT PPParseV2Header(const UCHAR *prefix, const UCHAR *block, UINT block_len, PP_HEADER *header)
{
	UCHAR ver_cmd, fam_proto;
	UINT len;
	// Validate arguments
	if (prefix == NULL || header == NULL || block == NULL)
	{
		return PP_RET_ERROR;
	}

	Zero(header, sizeof(PP_HEADER));

	// Check the signature
	if (Cmp((void *)prefix, (void *)pp_v2_signature, PP_V2_SIGNATURE_LENGTH) != 0)
	{
		return PP_RET_ERROR;
	}

	ver_cmd = prefix[12];
	fam_proto = prefix[13];
	len = READ_USHORT(prefix + 14);

	if (len != block_len)
	{
		return PP_RET_ERROR;
	}

	if ((ver_cmd >> 4) != 2)
	{
		return PP_RET_ERROR;
	}

	header->IsV2 = true;
	header->Local = ((ver_cmd & 0x0F) == 0x00);

	if (header->Local)
	{
		// LOCAL command: keep the socket address
		return PP_RET_PARSED;
	}

	switch (fam_proto >> 4)
	{
	case 0x01:	// AF_INET
	{
		UINT src_ip, dst_ip;

		if (len < 12)
		{
			return PP_RET_ERROR;
		}

		src_ip = READ_UINT(block);
		dst_ip = READ_UINT(block + 4);

		UINTToIP(&header->SrcIp, src_ip);
		UINTToIP(&header->DstIp, dst_ip);

		header->SrcPort = READ_USHORT(block + 8);
		header->DstPort = READ_USHORT(block + 10);

		return PP_RET_PARSED;
	}
	case 0x02:	// AF_INET6
	{
		if (len < 36)
		{
			return PP_RET_ERROR;
		}

		Copy(header->SrcIp.address, (void *)block, 16);
		Copy(header->DstIp.address, (void *)(block + 16), 16);
		header->SrcIp.ipv6_scope_id = 0;
		header->DstIp.ipv6_scope_id = 0;

		header->SrcPort = READ_USHORT(block + 32);
		header->DstPort = READ_USHORT(block + 34);

		return PP_RET_PARSED;
	}
	default:	// AF_UNSPEC: keep the socket address
		return PP_RET_PARSED;
	}
}

// Apply the parsed header information to the socket
bool PPApplyHeaderToSocket(SOCK *s, PP_HEADER *header)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (s == NULL || header == NULL)
	{
		return false;
	}

	if (header->Local)
	{
		// LOCAL / UNKNOWN: keep the current socket address
		return true;
	}

	if (IsZeroIp(&header->SrcIp))
	{
		return false;
	}

	CopyIP(&s->RemoteIP, &header->SrcIp);
	s->RemotePort = header->SrcPort;

	// Use the IP address string as the host name
	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);

	if (s->RemoteHostname != NULL)
	{
		Free(s->RemoteHostname);
	}

	s->RemoteHostname = CopyStr(tmp);

	return true;
}

// Attempt to detect and consume a PROXY protocol header on the socket.
// Returns PP_RET_NONE, PP_RET_PARSED or PP_RET_ERROR.
// The caller must disconnect the socket if PP_RET_ERROR is returned.
UINT PPProcessSocket(SOCK *s, bool *header_found, PP_HEADER *header_out)
{
	UCHAR sniff[PP_SNIFF_SIZE];
	UINT n;
	UINT old_timeout;
	UINT ret = PP_RET_NONE;
	// Validate arguments
	if (s == NULL || s->Type != SOCK_TCP)
	{
		if (header_found != NULL)
		{
			*header_found = false;
		}
		return PP_RET_NONE;
	}

	if (header_found != NULL)
	{
		*header_found = false;
	}

	// Set a short time-out for reading the header
	old_timeout = s->TimeOut;
	SetTimeout(s, PP_HEADER_TIMEOUT);

	n = Peek(s, sniff, sizeof(sniff));

	if (n == 0)
	{
		// No data at all: assume a plain connection attempt or a dead peer.
		// Fall back to the original time-out and let the subsequent protocol
		// handling deal with it.
		SetTimeout(s, old_timeout);
		return PP_RET_NONE;
	}

	if (sniff[0] == 'P')
	{
		// Possibly a PROXY protocol version 1 header
		if (n < 6)
		{
			n = PPPeekUntil(s, sniff, 6);

			if (n < 6)
			{
				SetTimeout(s, old_timeout);
				return PP_RET_NONE;
			}
		}

		if (Cmp(sniff, "PROXY ", 6) != 0)
		{
			// Not a PROXY protocol header
			SetTimeout(s, old_timeout);
			return PP_RET_NONE;
		}

		{
			UCHAR line[PP_V1_MAX_LENGTH + 2 + 1];
			UINT i, total = 0;

			// Read the complete line including the CRLF
			while (true)
			{
				n = Peek(s, line, sizeof(line) - 1);

				if (n == 0)
				{
					SetTimeout(s, old_timeout);
					return PP_RET_ERROR;
				}

				for (i = 0; i + 1 < n; i++)
				{
					if (line[i] == '\r' && line[i + 1] == '\n')
					{
						total = i + 2;
						break;
					}
				}

				if (total != 0)
				{
					break;
				}

				if (n >= (sizeof(line) - 1))
				{
					// The header is too long
					SetTimeout(s, old_timeout);
					return PP_RET_ERROR;
				}

				SleepThread(5);
			}

			if (PPConsume(s, total, line) == false)
			{
				SetTimeout(s, old_timeout);
				return PP_RET_ERROR;
			}

			line[total] = 0;

			ret = PPParseV1Header((char *)line, total, header_out);

			if (ret == PP_RET_PARSED && header_found != NULL)
			{
				*header_found = true;
			}
		}
	}
	else if (sniff[0] == 0x0D)
	{
		// Possibly a PROXY protocol version 2 header
		if (n < PP_V2_SIGNATURE_LENGTH)
		{
			n = PPPeekUntil(s, sniff, PP_V2_SIGNATURE_LENGTH);

			if (n < PP_V2_SIGNATURE_LENGTH)
			{
				// Not enough data: not a PROXY protocol header
				SetTimeout(s, old_timeout);
				return PP_RET_NONE;
			}
		}

		if (Cmp(sniff, pp_v2_signature, PP_V2_SIGNATURE_LENGTH) != 0)
		{
			// Not a PROXY protocol header
			SetTimeout(s, old_timeout);
			return PP_RET_NONE;
		}

		{
			UCHAR prefix[PP_V2_PREFIX_LENGTH];
			UCHAR *block = NULL;
			UINT block_len;

			if (PPConsume(s, PP_V2_PREFIX_LENGTH, prefix) == false)
			{
				SetTimeout(s, old_timeout);
				return PP_RET_ERROR;
			}

			// Read the address block and the TLVs, and discard them together
			block_len = READ_USHORT(prefix + 14);

			if (block_len > 0)
			{
				block = Malloc(block_len);

				if (PPConsume(s, block_len, block) == false)
				{
					Free(block);
					SetTimeout(s, old_timeout);
					return PP_RET_ERROR;
				}
			}
			else
			{
				block = Malloc(1);
			}

			ret = PPParseV2Header(prefix, block, block_len, header_out);

			Free(block);

			if (ret == PP_RET_PARSED && header_found != NULL)
			{
				*header_found = true;
			}
		}
	}

	// Restore the original time-out
	SetTimeout(s, old_timeout);

	return ret;
}

// Comparison function for the network list
static int PPCompareNetwork(void *p1, void *p2)
{
	PP_NETWORK *n1, *n2;
	int ret;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	n1 = *(PP_NETWORK **)p1;
	n2 = *(PP_NETWORK **)p2;
	if (n1 == NULL || n2 == NULL)
	{
		return 0;
	}

	ret = CmpIpAddr(&n1->Network, &n2->Network);
	if (ret != 0)
	{
		return ret;
	}

	return CmpIpAddr(&n1->SubnetMask, &n2->SubnetMask);
}

// Create a new empty trusted network list
LIST *PPNewNetworkList()
{
	return NewList(PPCompareNetwork);
}

// Free a trusted network list
void PPFreeNetworkList(LIST *networks)
{
	UINT i;
	// Validate arguments
	if (networks == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(networks); i++)
	{
		PP_NETWORK *n = LIST_DATA(networks, i);
		Free(n);
	}

	ReleaseList(networks);
}

// Convert a prefix length (0..32 for IPv4, 0..128 for IPv6) to a mask
static bool PPPrefixToMask(IP *mask, IP *network, UINT prefix)
{
	UINT i;
	// Validate arguments
	if (mask == NULL || network == NULL)
	{
		return false;
	}

	Zero(mask, sizeof(IP));

	if (IsIP4(network))
	{
		if (prefix > 32)
		{
			return false;
		}

		if (prefix == 0)
		{
			// 0.0.0.0
			UINTToIP(mask, 0);
			return true;
		}
		for (i = 0; i < 4; i++)
		{
			UCHAR v = 0;
			if (prefix >= 8)
			{
				v = 0xFF;
				prefix -= 8;
			}
			else
			{
				v = (UCHAR)(0xFF << (8 - prefix));
				prefix = 0;
			}
			mask->address[12 + i] = v;
		}
	}
	else
	{
		if (prefix > 128)
		{
			return false;
		}

		for (i = 0; i < 16; i++)
		{
			UCHAR v = 0;
			if (prefix >= 8)
			{
				v = 0xFF;
				prefix -= 8;
			}
			else
			{
				v = (UCHAR)(0xFF << (8 - prefix));
				prefix = 0;
			}
			mask->address[i] = v;
		}
	}

	return true;
}

// Add a network to the trusted network list
bool PPAddNetwork(LIST *networks, IP *network, IP *mask)
{
	PP_NETWORK *n;
	// Validate arguments
	if (networks == NULL || network == NULL || mask == NULL)
	{
		return false;
	}

	n = ZeroMalloc(sizeof(PP_NETWORK));

	CopyIP(&n->Network, network);
	CopyIP(&n->SubnetMask, mask);

	// Normalize the network address
	{
		UINT i;
		for (i = 0; i < 16; i++)
		{
			n->Network.address[i] &= n->SubnetMask.address[i];
		}
	}

	if (IsZeroIp(&n->SubnetMask))
	{
		// A zero-length mask is invalid
		Free(n);
		return false;
	}

	Add(networks, n);

	return true;
}

// Add a network to the trusted network list by a string like "192.168.0.0/24" or "192.168.0.0/255.255.255.0"
bool PPAddNetworkStr(LIST *networks, char *str)
{
	TOKEN_LIST *tokens;
	IP network, mask;
	// Validate arguments
	if (networks == NULL || str == NULL)
	{
		return false;
	}

	tokens = ParseToken(str, "/");

	if (tokens->NumTokens == 1)
	{
		// A single IP address: treat it as /32 or /128
		if (StrToIP(&network, tokens->Token[0]) == false)
		{
			FreeToken(tokens);
			return false;
		}

		if (IsIP4(&network))
		{
			UINTToIP(&mask, 0xFFFFFFFF);
		}
		else
		{
			UINT i;
			Zero(&mask, sizeof(mask));
			for (i = 0; i < 16; i++)
			{
				mask.address[i] = 0xFF;
			}
		}
	}
	else if (tokens->NumTokens == 2)
	{
		UINT prefix;

		if (StrToIP(&network, tokens->Token[0]) == false)
		{
			FreeToken(tokens);
			return false;
		}

		// The second token may be either a prefix length or a dotted mask
		prefix = ToInt(tokens->Token[1]);

		if (prefix != 0)
		{
			if (PPPrefixToMask(&mask, &network, prefix) == false)
			{
				FreeToken(tokens);
				return false;
			}
		}
		else
		{
			if (StrToIP(&mask, tokens->Token[1]) == false)
			{
				FreeToken(tokens);
				return false;
			}
		}
	}
	else
	{
		FreeToken(tokens);
		return false;
	}

	FreeToken(tokens);

	return PPAddNetwork(networks, &network, &mask);
}

// Parse a comma-separated list of networks and add them all to the list.
// Returns the number of successfully parsed entries.
UINT PPParseNetworkListStr(LIST *networks, char *str)
{
	TOKEN_LIST *tokens;
	UINT i, ret = 0;
	// Validate arguments
	if (networks == NULL || str == NULL)
	{
		return 0;
	}

	tokens = ParseToken(str, ",; ");

	for (i = 0; i < tokens->NumTokens; i++)
	{
		if (IsEmptyStr(tokens->Token[i]) == false)
		{
			if (PPAddNetworkStr(networks, tokens->Token[i]))
			{
				ret++;
			}
		}
	}

	FreeToken(tokens);

	return ret;
}

// Build a comma-separated string of the network list
void PPBuildNetworkListStr(char *str, UINT size, LIST *networks)
{
	UINT i;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	Zero(str, size);

	if (networks == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(networks); i++)
	{
		PP_NETWORK *n = LIST_DATA(networks, i);
		char ip_str[MAX_SIZE];
		char mask_str[MAX_SIZE];
		char entry[MAX_SIZE * 2];

		IPToStr(ip_str, sizeof(ip_str), &n->Network);
		IPToStr(mask_str, sizeof(mask_str), &n->SubnetMask);

		if (i == 0)
		{
			Format(entry, sizeof(entry), "%s/%s", ip_str, mask_str);
		}
		else
		{
			Format(entry, sizeof(entry), ", %s/%s", ip_str, mask_str);
		}

		StrCat(str, size, entry);
	}
}

// Check whether the specified IP address is within any of the networks
bool PPCheckNetworkListContains(LIST *networks, IP *ip)
{
	UINT i;
	// Validate arguments
	if (networks == NULL || ip == NULL || LIST_NUM(networks) == 0)
	{
		return false;
	}

	for (i = 0; i < LIST_NUM(networks); i++)
	{
		PP_NETWORK *n = LIST_DATA(networks, i);
		UINT j;
		bool match = true;

		for (j = 0; j < 16; j++)
		{
			if ((ip->address[j] & n->SubnetMask.address[j]) != n->Network.address[j])
			{
				match = false;
				break;
			}
		}

		if (match)
		{
			return true;
		}
	}

	return false;
}

// Check whether the trusted network list is empty
bool PPIsNetworkListEmpty(LIST *networks)
{
	if (networks == NULL)
	{
		return true;
	}

	return LIST_NUM(networks) == 0;
}
