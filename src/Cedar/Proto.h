#ifndef PROTO_H
#define PROTO_H

// OpenVPN sends 2 bytes, thus this is the buffer size.
// If another protocol requires more bytes to be detected, the buffer size must be increased.
#define PROTO_CHECK_BUFFER_SIZE	2

#define PROTO_TCP_BUFFER_SIZE	(128 * 1024)

typedef enum PROTO_MODE
{
	PROTO_MODE_UNKNOWN = 0,
	PROTO_MODE_TCP = 1,
	PROTO_MODE_UDP = 2
} PROTO_MODE;

typedef struct PROTO
{
	CEDAR *Cedar;
	LIST *Containers;
	HASH_LIST *Sessions;
	UDPLISTENER *UdpListener;
} PROTO;

typedef struct PROTO_IMPL
{
	const char *(*Name)();
	bool (*Init)(void **param, CEDAR *cedar, INTERRUPT_MANAGER *im, SOCK_EVENT *se, const char *cipher, const char *hostname);
	void (*Free)(void *param);
	bool (*IsPacketForMe)(const PROTO_MODE mode, const UCHAR *data, const UINT size);
	bool (*ProcessData)(void *param, TCP_RAW_DATA *in, FIFO *out);
	bool (*ProcessDatagrams)(void *param, LIST *in, LIST *out);
} PROTO_IMPL;

typedef struct PROTO_CONTAINER
{
	const char *Name;
	const PROTO_IMPL *Impl;
} PROTO_CONTAINER;

typedef struct PROTO_SESSION
{
	void *Param;
	const PROTO *Proto;
	const PROTO_IMPL *Impl;
	IP SrcIp;
	USHORT SrcPort;
	IP DstIp;
	USHORT DstPort;
	LIST *DatagramsIn;
	LIST *DatagramsOut;
	SOCK_EVENT *SockEvent;
	INTERRUPT_MANAGER *InterruptManager;
	THREAD *Thread;
	LOCK *Lock;
	volatile bool Halt;
} PROTO_SESSION;

int ProtoContainerCompare(void *p1, void *p2);
int ProtoSessionCompare(void *p1, void *p2);

UINT ProtoSessionHash(void *p);

PROTO *ProtoNew(CEDAR *cedar);
void ProtoDelete(PROTO *proto);

PROTO_CONTAINER *ProtoContainerNew(const PROTO_IMPL *impl);
void ProtoContainerDelete(PROTO_CONTAINER *container);

const PROTO_CONTAINER *ProtoDetect(const PROTO *proto, const PROTO_MODE mode, const UCHAR *data, const UINT size);

PROTO_SESSION *ProtoNewSession(PROTO *proto, const PROTO_CONTAINER *container, const IP *src_ip, const USHORT src_port, const IP *dst_ip, const USHORT dst_port);
void ProtoDeleteSession(PROTO_SESSION *session);

bool ProtoSetListenIP(PROTO *proto, const IP *ip);
bool ProtoSetUdpPorts(PROTO *proto, const LIST *ports);

bool ProtoHandleConnection(PROTO *proto, SOCK *sock, const char *protocol);
void ProtoHandleDatagrams(UDPLISTENER *listener, LIST *datagrams);
void ProtoSessionThread(THREAD *thread, void *param);

#endif
