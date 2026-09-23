#include "Socket.h"

#include "Memory.h"
#include "Network.h"
#include "Object.h"
#include "Str.h"

#ifdef OS_UNIX
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#endif

static int SocketGetLastError()
{
#ifdef OS_WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}

static SOCKET_RET SocketInterpretError(const int error)
{
	switch (error)
	{
#ifdef OS_WIN32
	case WSAEWOULDBLOCK:
		return SOCKET_BUSY;
	case WSAEHOSTUNREACH:
	case WSAENETUNREACH:
	case WSAECONNRESET:
	case WSAENETRESET:
	case WSAEMSGSIZE:
	case WSAENOBUFS:
		return SOCKET_OTHER;
	default:
		return SOCKET_FAIL;
#else
#if EAGAIN != EWOULDBLOCK
	case EAGAIN:
#endif
	case EWOULDBLOCK:
		return SOCKET_BUSY;
	case ECONNREFUSED:
	case ECONNRESET:
	case EMSGSIZE:
	case ENOBUFS:
	case ENOMEM:
		return SOCKET_OTHER;
	default:
		return SOCKET_FAIL;
#endif
	}
}

SOCKET SocketOpen(const bool raw, const int type, const int protocol)
{
	SOCKET s = socket(raw ? SOCK_RAW : PF_INET6, type, protocol);
	if (s == SOCKET_INVALID)
	{
		Debug("SocketOpen(): socket() failed with error %d!\n", SocketGetLastError());
	}

	return s;
}

bool SocketClose(const SOCKET socket)
{
	if (socket == SOCKET_INVALID)
	{
		return false;
	}
#ifdef OS_WIN32
	return closesocket(socket) == 0;
#else
	return close(socket) == 0;
#endif
}

bool SocketShutdown(const SOCKET socket)
{
	if (socket == SOCKET_INVALID)
	{
		return false;
	}
#ifdef OS_WIN32
	return shutdown(socket, SD_BOTH) == 0;
#else
	return shutdown(socket, SHUT_RDWR) == 0;
#endif
}

bool SocketBind(const SOCKET socket, const IP *ip, const PORT port)
{
	if (socket == SOCKET_INVALID)
	{
		return false;
	}

	int value = IsIP6(ip) ? 1 : 0;
	if (setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)) != 0)
	{
		Debug("SocketBind(): setsockopt() failed to %s IPV6_V6ONLY with error %d!\n", value ? "enable" : "disable", SocketGetLastError());
		return false;
	}

	struct sockaddr_in6 addr;
	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_scope_id = ip->ipv6_scope_id;
	IPToInAddr6(&addr.sin6_addr, ip);

	if (bind(socket, (struct sockaddr *)&addr, sizeof(addr)) == 0)
	{
		return true;
	}

	if (port == 0)
	{
		// Random port chosen by the OS, the failure is not due to a conflict.
		Debug("SocketBind(): #1 bind() failed with error %d!\n", SocketGetLastError());
		return false;
	}

	value = 1;
#ifdef SO_EXCLUSIVEADDRUSE
	if (setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &value, sizeof(value)) != 0)
	{
		Debug("SocketBind(): setsocketopt() failed to enable SO_EXCLUSIVEADDRUSE with error %d!\n", SocketGetLastError());
		return false;
	}
#endif
	if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) != 0)
	{
		Debug("SocketBind(): setsocketopt() failed to enable SO_REUSEADDR with error %d!\n", SocketGetLastError());
		return false;
	}
		
	if (bind(socket, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		Debug("SocketBind(): #2 bind() failed with error %d!\n", SocketGetLastError());
		return false;
	}

	return true;
}

bool SocketSetBlocking(const SOCKET socket, const bool enable)
{
	if (socket == SOCKET_INVALID)
	{
		return false;
	}
#ifdef OS_WIN32
	const u_long value = !enabled;
	return ioctlsocket(socket, FIONBIO, &value) == 0;
#else
	const int flags = fcntl(socket, F_GETFL, 0);
	if (flags == -1)
	{
		return false;
	}

	const int new_flags = enable ? flags & ~O_NONBLOCK : flags | O_NONBLOCK;
	if (flags == new_flags)
	{
		return true;
	}

	return fcntl(socket, F_SETFL, new_flags) == 0;
#endif
}

bool SocketSetBroadcast(const SOCKET socket, const bool enable)
{
	if (socket == SOCKET_INVALID)
	{
		return false;
	}

	const int value = enable;
	return setsockopt(socket, SOL_SOCKET, SO_BROADCAST, &value, sizeof(value)) == 0;
}

bool SocketSetHeaderInclusion(const SOCKET socket, const bool enable)
{
	if (socket == SOCKET_INVALID)
	{
		return false;
	}

	bool ok = true;

	const int value = enable;
	if (setsockopt(socket, IPPROTO_IPV6, IPV6_HDRINCL, &value, sizeof(value)) != 0)
	{
		Debug("SocketSetHeaderInclusion(): setsockopt() failed to %s IPV6_HDRINCL with error %d!\n", value ? "enable" : "disable", SocketGetLastError());
		ok = false;
	}

	if (setsockopt(socket, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value)) != 0)
	{
		Debug("SocketSetHeaderInclusion(): setsockopt() failed to %s IP_HDRINCL with error %d!\n", value ? "enable" : "disable", SocketGetLastError());
		ok = false;
	}

	return ok;
}

int SocketRecvFrom(const SOCKET socket, IP *ip, PORT *port, void *data, const UINT size)
{
	if (socket == SOCKET_INVALID || data == NULL || size == 0)
	{
		return SOCKET_PARAM;
	}

	struct sockaddr_in6 addr;
#ifdef OS_WIN32
	int socklen = sizeof(addr);
#else
	socklen_t socklen = sizeof(addr);
#endif
	const int ret = recvfrom(socket, data, size, 0, (struct sockaddr *)&addr, &socklen);
	if (ret > -1)
	{
		if (ip != NULL)
		{
			InAddrToIP6(ip, &addr.sin6_addr);
			ip->ipv6_scope_id = addr.sin6_scope_id;
		}

		if (port != NULL)
		{
			*port = ntohs(addr.sin6_port);
		}

		return ret;
	}

	return SocketInterpretError(SocketGetLastError());
}

int SocketSendTo(const SOCKET socket, const IP *ip, const PORT port, const void *data, const UINT size)
{
	if (socket == SOCKET_INVALID || data == NULL || size == 0)
	{
		return SOCKET_PARAM;
	}

	struct sockaddr_in6 addr;
	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_scope_id = ip->ipv6_scope_id;
	IPToInAddr6(&addr.sin6_addr, ip);

	const int ret = sendto(socket, data, size, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret > -1)
	{
		return ret;
	}

	return SocketInterpretError(SocketGetLastError());
}

SOCKET_BOX *SocketBoxNew(const SOCKET socket)
{
	if (socket == SOCKET_INVALID)
	{
		return NULL;
	}

	struct sockaddr_in6 addr;
#ifdef OS_WIN32
	int size = sizeof(addr);
#else
	socklen_t size = sizeof(addr);
#endif
	if (getsockname(socket, (struct sockaddr *)&addr, &size) != 0)
	{
		Debug("SockerBoxNew(): getsockname() failed with error %d!\n", SocketGetLastError());
		return NULL;
	}

	SOCKET_BOX *box = Malloc(sizeof(SOCKET_BOX));

	box->Socket = socket;
	InAddrToIP6(&box->IP, &addr.sin6_addr);
	box->IP.ipv6_scope_id = addr.sin6_scope_id;
	box->Port = ntohs(addr.sin6_port);
	box->Ref = NewRef();

	return box;
}

void SocketBoxFree(SOCKET_BOX *box)
{
	if (box == NULL || Release(box->Ref) != 0)
	{
		return;
	}

	SocketShutdown(box->Socket);
	SocketClose(box->Socket);

	Free(box);
}

SOCKET_MONITOR *SocketMonitorNew(const SOCKET socket, const bool in, const bool out)
{
	if (SocketSetBlocking(socket, false) == false)
	{
		return false;
	}
#ifdef OS_WIN32
	void *handle = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (handle == NULL)
	{
		return NULL;
	}

	long flags = FD_ACCEPT | FD_CONNECT | FD_CLOSE;
	if (in)
	{
		flags |= FD_READ;
	}
	if (out)
	{
		flags |= FD_WRITE;
	}

	if (WSAEventSelect(socket, monitor->Handle, flags) != 0)
	{
		CloseHandle(handle);
		return false;
	}

	SOCKET_MONITOR *watcher = Malloc(sizeof(SOCKET_MONITOR));
	watcher->Handle = handle;
#else
	SOCKET fds[2];
	if (socketpair(PF_LOCAL, SOCK_DGRAM, 0, fds) != 0)
	{
		return NULL;
	}

	SOCKET_MONITOR *monitor = Malloc(sizeof(SOCKET_MONITOR));
	monitor->Triggerer = fds[0];

	monitor->PollFds = ZeroMalloc(sizeof(struct pollfd) * 2);
	monitor->PollFds[0].fd = fds[1];
	monitor->PollFds[0].events = POLLIN;
	monitor->PollFds[1].fd = socket;
	if (in)
	{
		monitor->PollFds[1].events |= POLLIN;
	}
	if (out)
	{
		monitor->PollFds[1].events |= POLLOUT;
	}
#endif
	return monitor;
}

void SocketMonitorFree(SOCKET_MONITOR *monitor)
{
	if (monitor == NULL)
	{
		return;
	}
#ifdef OS_WIN32
	CloseHandle(monitor->Handle);
#else
	SocketClose(monitor->Triggerer);
	SocketClose(monitor->PollFds[0].fd);
	Free(monitor->PollFds);
#endif
	Free(monitor);
}

bool SocketMonitorTrigger(SOCKET_MONITOR *monitor)
{
	if (monitor == NULL)
	{
		return false;
	}
#ifdef OS_WIN32
	return SetEvent(monitor->Handle) != 0;
#else
	const BYTE byte = 0;
	if (send(monitor->Triggerer, &byte, sizeof(byte), 0) < sizeof(byte))
	{
		return false;
	}

	return true;
#endif
}

bool SocketMonitorWait(SOCKET_MONITOR *monitor, const UINT timeout)
{
	if (monitor == NULL)
	{
		return false;
	}
#ifdef OS_WIN32
	return WaitForSingleObject(monitor->Handle, timeout) == WAIT_OBJECT_0;
#else
	const int ret = poll(monitor->PollFds, 2, timeout == INFINITE ? -1 : timeout);
	if (ret < 1)
	{
		return false;
	}

	if (monitor->PollFds[0].revents & POLLIN)
	{
		BYTE byte;
		recv(monitor->PollFds[0].fd, &byte, sizeof(byte), 0);
	}

	return true;
#endif
}
