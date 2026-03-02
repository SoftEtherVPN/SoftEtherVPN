#ifndef SOCKET_H
#define SOCKET_H

#include "Network.h"

#define SOCKET_INVALID (-1)

enum SOCKET_RET
{
	SOCKET_OK    =  0,
	SOCKET_PARAM = -1,
	SOCKET_BUSY  = -2,
	SOCKET_FAIL  = -3,
	SOCKET_OTHER = -4
};

struct SOCKET_BOX
{
	SOCKET Socket;
	IP IP;
	PORT Port;
	REF *Ref;
};

struct SOCKET_MONITOR
{
#ifdef OS_WIN32
	void *Handle;
#else
	SOCKET Triggerer;
	struct pollfd *PollFds;
#endif
};

SOCKET SocketOpen(const bool raw, const int type, const int protocol);
bool SocketClose(const SOCKET socket);

bool SocketShutdown(const SOCKET socket);

bool SocketBind(const SOCKET socket, const IP *ip, const PORT port);

bool SocketSetBlocking(const SOCKET socket, const bool enable);
bool SocketSetBroadcast(const SOCKET socket, const bool enable);
bool SocketSetHeaderInclusion(const SOCKET socket, const bool enable);

int SocketRecvFrom(const SOCKET socket, IP *ip, PORT *port, void *data, const UINT size);
int SocketSendTo(const SOCKET socket, const IP *ip, const PORT port, const void *data, const UINT size);

SOCKET_BOX *SocketBoxNew(const SOCKET socket);
void SocketBoxFree(SOCKET_BOX *box);

SOCKET_MONITOR *SocketMonitorNew(const SOCKET socket, const bool in, const bool out);
void SocketMonitorFree(SOCKET_MONITOR *monitor);

bool SocketMonitorTrigger(SOCKET_MONITOR *monitor);
bool SocketMonitorWait(SOCKET_MONITOR *monitor, const UINT timeout);

#endif
