#ifndef PROTO_H
#define PROTO_H

// OpenVPN sends 2 bytes, thus this is the buffer size.
// If another protocol requires more bytes to be detected, the buffer size must be increased.
#define PROTO_CHECK_BUFFER_SIZE	2

#define PROTO_TCP_BUFFER_SIZE	(128 * 1024)

#define PROTO_MODE_TCP			1
#define PROTO_MODE_UDP			2

typedef struct PROTO_IMPL
{
	bool (*Init)(void **param, CEDAR *cedar, INTERRUPT_MANAGER *im, SOCK_EVENT *se);
	void (*Free)(void *param);
	char *(*Name)();
	UINT (*SupportedModes)();
	bool (*IsPacketForMe)(const UCHAR *data, const UINT size);
	bool (*ProcessData)(void *param, TCP_RAW_DATA *received_data, FIFO *data_to_send);
	void (*BufferLimit)(void *param, const bool reached);
	bool (*IsOk)(void *param);
	UINT (*EstablishedSessions)(void *param);
} PROTO_IMPL;

typedef struct PROTO
{
	PROTO_IMPL *impl;
} PROTO;

int ProtoCompare(void *p1, void *p2);

void ProtoInit();
void ProtoFree();

bool ProtoAdd(PROTO_IMPL *impl);

UINT ProtoNum();
PROTO *ProtoGet(const UINT index);
PROTO *ProtoDetect(SOCK *sock);

bool ProtoHandleConnection(CEDAR *cedar, SOCK *sock);

#endif
