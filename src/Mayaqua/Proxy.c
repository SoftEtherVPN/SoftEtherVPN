#include "Proxy.h"

// TODO: Mayaqua should not depend on Cedar.
#include "Cedar/WinUi.h"

#include "DNS.h"
#include "Memory.h"
#include "Str.h"

SOCK *Internal_ProxyTcpConnect(PROXY_PARAM_IN *param, volatile bool *cancel_flag, IP *resolved_ip)
{
#ifdef OS_WIN32
	if (param->Hwnd != NULL)
	{
		return WinConnectEx3((HWND)param->Hwnd, param->Hostname, param->Port, param->Timeout, 0, NULL, NULL, NULL, NULL, false);
	}
#endif

	return ConnectEx4(param->Hostname, param->Port, param->Timeout, (bool *)cancel_flag, NULL, NULL, false, true, resolved_ip);
}

// Connect to an HTTP proxy
UINT ProxyHttpConnect(PROXY_PARAM_OUT *out, PROXY_PARAM_IN *in, volatile bool *cancel_flag)
{
	bool dummy_cancel_flag = false, use_auth = false;
	char target_hostname[MAX_HOST_NAME_LEN + 1];
	char target_hostname_port[MAX_SIZE];
	HTTP_HEADER *h;
	UINT i, ret;
	SOCK *s;
	// Validate arguments
	if (out == NULL || in == NULL || in->Port == 0 || in->TargetPort == 0 || IsEmptyStr(in->Hostname) || IsEmptyStr(in->TargetHostname))
	{
		return PROXY_ERROR_PARAMETER;
	}

	if (cancel_flag == NULL)
	{
		cancel_flag = &dummy_cancel_flag;
	}
	else if (*cancel_flag)
	{
		return PROXY_ERROR_CANCELED;
	}

	Zero(out, sizeof(PROXY_PARAM_OUT));

	// Open TCP connection to the proxy server
	s = Internal_ProxyTcpConnect(in, cancel_flag, &out->ResolvedIp);
	if (s == NULL)
	{
		return PROXY_ERROR_CONNECTION;
	}

	SetTimeout(s, MIN(PROXY_CONNECTION_TIMEOUT, (in->Timeout == 0 ? INFINITE : in->Timeout)));

	if ((IsEmptyStr(in->Username) || IsEmptyStr(in->Password)) == false)
	{
		use_auth = true;
	}

	Zero(target_hostname, sizeof(target_hostname));
	StrCpy(target_hostname, sizeof(target_hostname), in->TargetHostname);

	for (i = 0; i < StrLen(target_hostname); ++i)
	{
		if (target_hostname[i] == '/')
		{
			target_hostname[i] = 0;
		}
	}

	// Generate HTTP header
	if (IsStrIPv6Address(target_hostname))
	{
		IP ip;
		char iptmp[MAX_PATH];

		StrToIP(&ip, target_hostname);
		IPToStr(iptmp, sizeof(iptmp), &ip);

		Format(target_hostname_port, sizeof(target_hostname_port), "[%s]:%hu", iptmp, in->TargetPort);
	}
	else
	{
		Format(target_hostname_port, sizeof(target_hostname_port), "%s:%hu", target_hostname, in->TargetPort);
	}

	h = NewHttpHeader("CONNECT", target_hostname_port, "HTTP/1.0");

	if (IsEmptyStr(in->HttpCustomHeader) == false)
	{
		TOKEN_LIST *tokens = ParseToken(in->HttpCustomHeader, "\r\n");
		if (tokens != NULL)
		{
			for (i = 0; i < tokens->NumTokens; i++)
			{
				AddHttpValueStr(h, tokens->Token[i]);
			}

			FreeToken(tokens);
		}
	}

	if (GetHttpValue(h, "User-Agent") == NULL)
	{
		AddHttpValue(h, NewHttpValue("User-Agent", IsEmptyStr(in->HttpUserAgent) ? DEFAULT_USER_AGENT : in->HttpUserAgent));
	}

	if (GetHttpValue(h, "Host") == NULL)
	{
		AddHttpValue(h, NewHttpValue("Host", target_hostname));
	}

	if (GetHttpValue(h, "Content-Length") == NULL)
	{
		AddHttpValue(h, NewHttpValue("Content-Length", "0"));
	}

	if (GetHttpValue(h, "Proxy-Connection") == NULL)
	{
		AddHttpValue(h, NewHttpValue("Proxy-Connection", "Keep-Alive"));
	}

	if (GetHttpValue(h, "Pragma") == NULL)
	{
		AddHttpValue(h, NewHttpValue("Pragma", "no-cache"));
	}

	if (use_auth && GetHttpValue(h, "Proxy-Authorization") == NULL)
	{
		char auth_str[MAX_SIZE * 2], auth_b64_str[MAX_SIZE * 2];

		// Generate the authentication string
		Format(auth_str, sizeof(auth_str), "%s:%s", in->Username, in->Password);

		// Base64 encode
		Zero(auth_b64_str, sizeof(auth_b64_str));
		Encode64(auth_b64_str, auth_str);

		// Generate final string
		Format(auth_str, sizeof(auth_str), "Basic %s", auth_b64_str);

		AddHttpValue(h, NewHttpValue("Proxy-Authorization", auth_str));
	}

	// Transmission
	ret = SendHttpHeader(s, h);

	FreeHttpHeader(h);

	if (ret == false)
	{
		ret = PROXY_ERROR_DISCONNECTED;
		goto FAILURE;
	}

	if (*cancel_flag)
	{
		ret = PROXY_ERROR_CANCELED;
		goto FAILURE;
	}

	// Receive the results
	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		FreeHttpHeader(h);
		ret = PROXY_ERROR_GENERIC;
		goto FAILURE;
	}

	ret = 0;
	if (StrLen(h->Method) == 8)
	{
		if (Cmp(h->Method, "HTTP/1.", 7) == 0)
		{
			ret = ToInt(h->Target);
		}
	}
	FreeHttpHeader(h);

	// Check the code
	switch (ret)
	{
	case 401:
	case 403:
	case 407:
		// Authentication failure
		ret = PROXY_ERROR_AUTHENTICATION;
		goto FAILURE;

	default:
		if ((ret / 100) == 2)
		{
			// Success
			SetTimeout(s, INFINITE);
			out->Sock = s;
			return PROXY_ERROR_SUCCESS;
		}
		else
		{
			// Unknown result
			ret = PROXY_ERROR_GENERIC;
		}
	}

FAILURE:
	Disconnect(s);
	ReleaseSock(s);
	return ret;
}

// Connect to a SOCKS5 proxy (RFC1928, RFC1929 defines username/password authentication)
UINT ProxySocks5Connect(PROXY_PARAM_OUT *out, PROXY_PARAM_IN *in, volatile bool *cancel_flag)
{
	bool dummy_cancel_flag = false;
	UCHAR tmp, recv_buf[2], *recv_buf_final;
	USHORT target_port;
	IP target_ip;
	UINT ret;
	SOCK *s;
	BUF *b;
	// Validate arguments
	if (out == NULL || in == NULL || in->Port == 0 || in->TargetPort == 0 || IsEmptyStr(in->Hostname) || IsEmptyStr(in->TargetHostname))
	{
		return PROXY_ERROR_PARAMETER;
	}

	if (cancel_flag == NULL)
	{
		cancel_flag = &dummy_cancel_flag;
	}
	else if (*cancel_flag)
	{
		return PROXY_ERROR_CANCELED;
	}

	Zero(out, sizeof(PROXY_PARAM_OUT));

	// Open TCP connection to the proxy server
	s = Internal_ProxyTcpConnect(in, cancel_flag, &out->ResolvedIp);
	if (s == NULL)
	{
		return PROXY_ERROR_CONNECTION;
	}

	SetTimeout(s, MIN(PROXY_CONNECTION_TIMEOUT, (in->Timeout == 0 ? INFINITE : in->Timeout)));

	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	//
	// X'00'			NO AUTHENTICATION REQUIRED
	// X'01'			GSSAPI
	// X'02'			USERNAME/PASSWORD
	// X'03' to X'7F'	IANA ASSIGNED
	// X'80' to X'FE'	RESERVED FOR PRIVATE METHODS
	// X'FF'			NO ACCEPTABLE METHOD

	b = NewBuf();
	tmp = 5;
	WriteBuf(b, &tmp, sizeof(tmp));	// SOCKS version
	tmp = 2;
	WriteBuf(b, &tmp, sizeof(tmp));	// Number of supported methods
	tmp = 0;
	WriteBuf(b, &tmp, sizeof(tmp));	// No authentication
	tmp = 2;
	WriteBuf(b, &tmp, sizeof(tmp));	// Username/password

	ret = SendAll(s, b->Buf, b->Size, false);

	if (ret == false)
	{
		FreeBuf(b);
		Debug("ProxySocks5Connect(): [Phase 1] Failed to send initial data to the server.\n");
		ret = PROXY_ERROR_DISCONNECTED;
		goto FAILURE;
	}

	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+

	if (RecvAll(s, recv_buf, sizeof(recv_buf), false) == false)
	{
		FreeBuf(b);
		Debug("ProxySocks5Connect(): [Phase 1] Failed to receive initial data response from the server.\n");
		ret = PROXY_ERROR_DISCONNECTED;
		goto FAILURE;
	}

	if (recv_buf[0] != 5)
	{
		FreeBuf(b);
		Debug("ProxySocks5Connect(): [Phase 1] Unmatching version: %u.\n", recv_buf[0]);
		ret = PROXY_ERROR_VERSION;
		goto FAILURE;
	}

	ClearBuf(b);

	// Username/password authentication (RFC1929)
	if (recv_buf[1] == 2)
	{
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+

		tmp = 1;
		WriteBuf(b, &tmp, sizeof(tmp));	// Authentication protocol version
		tmp = StrLen(in->Username);
		WriteBuf(b, &tmp, sizeof(tmp));	// Username length
		WriteBuf(b, in->Username, tmp);	// Username
		tmp = StrLen(in->Password);
		WriteBuf(b, &tmp, sizeof(tmp));	// Password length
		WriteBuf(b, in->Password, tmp);	// Password

		ret = SendAll(s, b->Buf, b->Size, false);

		ClearBuf(b);

		if (ret == false)
		{
			Debug("ProxySocks5Connect(): [Phase 1] Failed to send authentication data to the server.\n");
			ret = PROXY_ERROR_DISCONNECTED;
			goto FAILURE;
		}

		// +----+--------+
		// |VER | STATUS |
		// +----+--------+
		// | 1  |   1    |
		// +----+--------+

		if (RecvAll(s, recv_buf, sizeof(recv_buf), false) == false)
		{
			Debug("ProxySocks5Connect(): [Phase 1] Failed to receive authentication data response from the server.\n");
			ret = PROXY_ERROR_DISCONNECTED;
			goto FAILURE;
		}

		if (recv_buf[1] != 0)
		{
			Debug("ProxySocks5Connect(): [Phase 1] Authentication failure, error code sent by the server: %u.\n", recv_buf[1]);
			ret = PROXY_ERROR_AUTHENTICATION;
			goto FAILURE;
		}
	}

	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	//
	// VER				protocol version: X'05'
	// CMD
	// CONNECT			X'01'
	// BIND				X'02'
	// UDP ASSOCIATE	X'03'
	// RSV				RESERVED
	// ATYP				address type of following address
	// IP V4 address	X'01'
	// DOMAINNAME		X'03'
	// IP V6 address	X'04'
	// DST.ADDR			desired destination address
	// DST.PORT			desired destination port in network octet order

	// Prepare data to send
	tmp = 5;
	WriteBuf(b, &tmp, sizeof(tmp));	// SOCKS version
	tmp = 1;
	WriteBuf(b, &tmp, sizeof(tmp));	// Command
	tmp = 0;
	WriteBuf(b, &tmp, sizeof(tmp));	// Reserved byte

	// Convert the hostname to an IP structure (if it's an IP address)
	StrToIP(&target_ip, in->TargetHostname);

	// If the IP structure doesn't contain an IP address, the string should be an hostname
	if (IsZeroIP(&target_ip))
	{
		UCHAR dest_length = StrLen(in->TargetHostname);
		tmp = 3;
		WriteBuf(b, &tmp, sizeof(tmp));									// Destination type (hostname)
		WriteBuf(b, &dest_length, sizeof(dest_length));					// Destination hostname length
		WriteBuf(b, in->TargetHostname, dest_length);					// Destination hostname
	}
	else
	{
		if (IsIP6(&target_ip))
		{
			tmp = 4;
			WriteBuf(b, &tmp, sizeof(tmp));								// Destination type (IPv6)
			WriteBuf(b, target_ip.address, sizeof(target_ip.address));	// Destination IPv6 address
		}
		else
		{
			tmp = 1;
			WriteBuf(b, &tmp, sizeof(tmp));								// Destination type (IPv4)
			WriteBuf(b, IPV4(target_ip.address), IPV4_SIZE);			// Destination IPv4 address
		}
	}

	// Convert the port in network octet order
	target_port = Endian16(in->TargetPort);
	WriteBuf(b, &target_port, sizeof(target_port));							// Destination port

	// Send data
	ret = SendAll(s, b->Buf, b->Size, false);
	FreeBuf(b);

	if (ret == false)
	{
		Debug("ProxySocks5Connect(): [Phase 2] Failed to send data to the server.\n");
		ret = PROXY_ERROR_DISCONNECTED;
		goto FAILURE;
	}

	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X’00’ |  1   | Variable |   2      |
	// +----+-----+-------+------+----------+----------+
	//
	// VER protocol version: X’05’
	// REP Reply field:
	// X’00’	succeeded
	// X’01’	general SOCKS server failure
	// X’02’	connection not allowed by ruleset
	// X’03’	Network unreachable
	// X’04’	Host unreachable
	// X’05’	Connection refused
	// X’06’	TTL expired
	// X’07’	Command not supported
	// X’08’	Address type not supported
	// X’09’	to X’FF’ unassigned

	// The packet sent by the server should always have the same size as the one we sent to it.
	// However, there are some implementations which send fixed values (aside from the first 2 bytes).
	// In order to support such implementations, we read the first 4 bytes in order to know the address type before trying to read the rest of the packet.
	recv_buf_final = Malloc(4);

	if (RecvAll(s, recv_buf_final, 4, false) == false)
	{
		Free(recv_buf_final);
		Debug("ProxySocks5Connect(): [Phase 2] Failed to receive response from the server.\n");
		ret = PROXY_ERROR_DISCONNECTED;
		goto FAILURE;
	}

	// We only need the first two bytes (version and response code), but we have to read the entire packet from the socket
	recv_buf[0] = recv_buf_final[0];
	recv_buf[1] = recv_buf_final[1];

	// We receive the rest of the packet by knowing the size according to the address type
	switch (recv_buf_final[3])
	{
	case 1:
		// IPv4
		recv_buf_final = ReAlloc(recv_buf_final, 6);			// 4 bytes (IPv4) + 2 bytes (port)
		ret = RecvAll(s, recv_buf_final, 6, false);
		break;
	case 4:
		// IPv6
		recv_buf_final = ReAlloc(recv_buf_final, 18);			// 16 bytes (IPv6) + 2 bytes (port)
		ret = RecvAll(s, recv_buf_final, 18, false);
		break;
	case 3:
		// Hostname
		ret = RecvAll(s, &tmp, 1, false);
		if (ret == true)
		{
			recv_buf_final = ReAlloc(recv_buf_final, tmp + 2);	// Hostname length + 2 bytes (port)
			ret = RecvAll(s, recv_buf_final, tmp + 2, false);
		}
	}

	Free(recv_buf_final);

	if (ret == false)
	{
		Debug("ProxySocks5Connect(): [Phase 2] Malformed response received from the server.\n");
		ret = PROXY_ERROR_DISCONNECTED;
		goto FAILURE;
	}

	if (recv_buf[0] != 5)
	{
		Debug("ProxySocks5Connect(): [Phase 2] Unmatching version: %u.\n", recv_buf_final[0]);
		ret = PROXY_ERROR_VERSION;
		goto FAILURE;
	}

	switch (recv_buf[1])
	{
	case 0:
		// Success
		SetTimeout(s, INFINITE);
		out->Sock = s;
		return PROXY_ERROR_SUCCESS;
	case 3:
	case 4:
	case 5:
		Debug("ProxySocks5Connect(): [Phase 2] Connection to target failed with error: %u\n", recv_buf[1]);
		ret = PROXY_ERROR_TARGET;
		goto FAILURE;
	default:
		Debug("ProxySocks5Connect(): [Phase 2] Connection failed with error: %u\n", recv_buf[1]);
		ret = PROXY_ERROR_GENERIC;
		goto FAILURE;
	}

FAILURE:
	Disconnect(s);
	ReleaseSock(s);
	return ret;
}

// Connect to a SOCKS4 proxy
UINT ProxySocks4Connect(PROXY_PARAM_OUT *out, PROXY_PARAM_IN *in, volatile bool *cancel_flag)
{
	bool dummy_cancel_flag = false;
	UCHAR tmp, recv_buf[8];
	USHORT target_port;
	IP target_ip;
	UINT ret;
	SOCK *s;
	BUF *b;
	// Validate arguments
	if (out == NULL || in == NULL || in->Port == 0 || in->TargetPort == 0 || IsEmptyStr(in->Hostname) || IsEmptyStr(in->TargetHostname))
	{
		return PROXY_ERROR_PARAMETER;
	}

	if (cancel_flag == NULL)
	{
		cancel_flag = &dummy_cancel_flag;
	}
	else if (*cancel_flag)
	{
		return PROXY_ERROR_CANCELED;
	}

	Zero(out, sizeof(PROXY_PARAM_OUT));

	// Get the IPv4 address of the destination server (SOCKS4 does not support IPv6).
	if (GetIP4(&target_ip, in->TargetHostname) == false)
	{
		return PROXY_ERROR_CONNECTION;
	}

	// Open TCP connection to the proxy server
	s = Internal_ProxyTcpConnect(in, cancel_flag, &out->ResolvedIp);
	if (s == NULL)
	{
		return PROXY_ERROR_CONNECTION;
	}

	SetTimeout(s, MIN(PROXY_CONNECTION_TIMEOUT, (in->Timeout == 0 ? INFINITE : in->Timeout)));

	// Send request packet
	b = NewBuf();
	tmp = 4;
	WriteBuf(b, &tmp, sizeof(tmp));
	tmp = 1;
	WriteBuf(b, &tmp, sizeof(tmp));
	target_port = Endian16(in->TargetPort);
	WriteBuf(b, &target_port, sizeof(target_port));
	WriteBuf(b, IPV4(target_ip.address), IPV4_SIZE);
	WriteBuf(b, in->Username, StrLen(in->Username) + 1);

	ret = SendAll(s, b->Buf, b->Size, false);

	FreeBuf(b);

	if (ret == false)
	{
		ret = PROXY_ERROR_DISCONNECTED;
		goto FAILURE;
	}

	// Receive response packet
	if (RecvAll(s, recv_buf, sizeof(recv_buf), false) == false)
	{
		ret = PROXY_ERROR_DISCONNECTED;
		goto FAILURE;
	}

	if (recv_buf[0] != 0)
	{
		ret = PROXY_ERROR_GENERIC;
		goto FAILURE;
	}

	switch (recv_buf[1])
	{
	case 90:
		// Success
		SetTimeout(s, INFINITE);
		out->Sock = s;
		return PROXY_ERROR_SUCCESS;
	case 93:
		// Authentication failure
		ret = PROXY_ERROR_AUTHENTICATION;
		goto FAILURE;
	default:
		// Failed to connect to the target server
		ret = PROXY_ERROR_TARGET;
	}

FAILURE:
	Disconnect(s);
	ReleaseSock(s);
	return ret;
}
