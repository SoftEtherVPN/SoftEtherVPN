// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Communication Module

// ProxyProtocol.h
// Header of ProxyProtocol.c
// Implementation of the PROXY protocol (versions 1 and 2) receiver
// Specification: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

#ifndef	PROXY_PROTOCOL_H
#define	PROXY_PROTOCOL_H

#include "MayaType.h"
#include "Network.h"

// Maximum length of a PROXY protocol version 1 header (including CRLF)
#define	PP_V1_MAX_LENGTH					107
// Length of a PROXY protocol version 2 header prefix (12-byte signature + 4-byte fields)
#define	PP_V2_PREFIX_LENGTH				16
// Length of the PROXY protocol version 2 binary signature
#define	PP_V2_SIGNATURE_LENGTH			12
// Maximum length of the PROXY protocol version 2 address block + TLVs
#define	PP_V2_ADDR_BLOCK_MAX				65535
// Time-out for receiving the PROXY protocol header (in milliseconds)
#define	PP_HEADER_TIMEOUT					(8 * 1000)
// Number of bytes to peek for protocol sniffing
#define	PP_SNIFF_SIZE						8

// Result of attempting to parse the PROXY protocol header
#define	PP_RET_NONE						0	// The client is not speaking the PROXY protocol. No bytes consumed.
#define	PP_RET_PARSED						1	// The header was parsed successfully and consumed.
#define	PP_RET_ERROR						2	// A malformed PROXY protocol header was detected. The socket must be disconnected.

// Parsed PROXY protocol header information
typedef struct PP_HEADER
{
	bool IsV2;							// Whether the header is version 2
	bool Local;							// Whether the command is LOCAL (v2 only): keep the socket address
	IP SrcIp;							// Source (real client) IP address
	IP DstIp;							// Destination IP address
	UINT SrcPort;						// Source (real client) port number
	UINT DstPort;						// Destination port number
} PP_HEADER;

// Trusted network entry (for restricting PROXY protocol acceptance)
typedef struct PP_NETWORK
{
	IP Network;							// Network address
	IP SubnetMask;						// Subnet mask
} PP_NETWORK;

// Function prototype
UINT PPProcessSocket(SOCK *s, bool *header_found, PP_HEADER *header_out);
UINT PPParseV1Header(char *line, UINT line_len, PP_HEADER *header);
UINT PPParseV2Header(const UCHAR *prefix, const UCHAR *block, UINT block_len, PP_HEADER *header);
bool PPApplyHeaderToSocket(SOCK *s, PP_HEADER *header);

// Trusted networks management
LIST *PPNewNetworkList();
void PPFreeNetworkList(LIST *networks);
bool PPAddNetworkStr(LIST *networks, char *str);
bool PPAddNetwork(LIST *networks, IP *network, IP *mask);
void PPBuildNetworkListStr(char *str, UINT size, LIST *networks);
bool PPCheckNetworkListContains(LIST *networks, IP *ip);
UINT PPParseNetworkListStr(LIST *networks, char *str);
bool PPIsNetworkListEmpty(LIST *networks);

#endif	// PROXY_PROTOCOL_H
