#ifndef PROXY_H
#define PROXY_H

#include "HTTP.h"
#include "Network.h"

#define PROXY_CONNECTION_TIMEOUT	(4 * 1000)

#define PROXY_MAX_USERNAME_LEN		255
#define PROXY_MAX_PASSWORD_LEN		255

#define PROXY_ERROR_SUCCESS			0
#define PROXY_ERROR_GENERIC			1
#define PROXY_ERROR_PARAMETER		2
#define PROXY_ERROR_CANCELED		3
#define PROXY_ERROR_CONNECTION		4
#define PROXY_ERROR_DISCONNECTED	5
#define PROXY_ERROR_VERSION			6
#define PROXY_ERROR_AUTHENTICATION	7
#define PROXY_ERROR_TARGET			8

struct PROXY_PARAM_IN
{
	char Hostname[MAX_HOST_NAME_LEN + 1];
	USHORT Port;
	char TargetHostname[MAX_HOST_NAME_LEN + 1];
	USHORT TargetPort;
	char Username[PROXY_MAX_USERNAME_LEN + 1];
	char Password[PROXY_MAX_PASSWORD_LEN + 1];
	UINT Timeout;
	char HttpCustomHeader[HTTP_CUSTOM_HEADER_MAX_SIZE];
	char HttpUserAgent[HTTP_HEADER_USER_AGENT_MAX_SIZE + 1];
	IP   *BindLocalIP;											// Source IP address for outgoing connection
	UINT BindLocalPort;					// UINT used not USHORT	// Source port number for outgoing connection
#ifdef OS_WIN32
	void *Hwnd;
#endif
};

struct PROXY_PARAM_OUT
{
	SOCK *Sock;
	IP ResolvedIp;
};

UINT ProxyHttpConnect(PROXY_PARAM_OUT *out, PROXY_PARAM_IN *in, volatile bool *cancel_flag);
UINT ProxySocks5Connect(PROXY_PARAM_OUT *out, PROXY_PARAM_IN *in, volatile bool *cancel_flag);
UINT ProxySocks4Connect(PROXY_PARAM_OUT *out, PROXY_PARAM_IN *in, volatile bool *cancel_flag);

// New function named with prefix "Bind" binds outgoing connection to a specific address. New one is wrapped in original one.
UINT BindProxyHttpConnect(PROXY_PARAM_OUT *out, PROXY_PARAM_IN *in, volatile bool *cancel_flag);
UINT BindProxySocks5Connect(PROXY_PARAM_OUT *out, PROXY_PARAM_IN *in, volatile bool *cancel_flag);
UINT BindProxySocks4Connect(PROXY_PARAM_OUT *out, PROXY_PARAM_IN *in, volatile bool *cancel_flag);

#endif
