#include "CedarPch.h"

#include "Proto_OpenVPN.h"

int ProtoImplCompare(void *p1, void *p2)
{
	PROTO_IMPL *impl_1 = p1, *impl_2 = p2;

	if (impl_1 == NULL || impl_2 == NULL)
	{
		return 0;
	}

	if (StrCmp(impl_1->Name(), impl_2->Name()) == 0)
	{
		return true;
	}

	return false;
}

PROTO *ProtoNew(CEDAR *cedar)
{
	PROTO *proto;

	if (cedar == NULL)
	{
		return NULL;
	}

	proto = Malloc(sizeof(PROTO));
	proto->Cedar = cedar;
	proto->Impls = NewList(ProtoImplCompare);

	AddRef(cedar->ref);

	// OpenVPN
	ProtoImplAdd(proto, OvsGetProtoImpl());

	return proto;
}

void ProtoDelete(PROTO *proto)
{
	if (proto == NULL)
	{
		return;
	}

	ReleaseList(proto->Impls);
	ReleaseCedar(proto->Cedar);
	Free(proto);
}

bool ProtoImplAdd(PROTO *proto, PROTO_IMPL *impl) {
	if (proto == NULL || impl == NULL)
	{
		return false;
	}

	Add(proto->Impls, impl);

	Debug("ProtoImplAdd(): added %s\n", impl->Name());

	return true;
}

PROTO_IMPL *ProtoImplDetect(PROTO *proto, const PROTO_MODE mode, const UCHAR *data, const UINT size)
{
	UINT i;

	if (proto == NULL || data == NULL || size == 0)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(proto->Impls); ++i)
	{
		PROTO_IMPL *impl = LIST_DATA(proto->Impls, i);
		if (impl->IsPacketForMe(mode, data, size) == false)
		{
			continue;
		}

		if (StrCmp(impl->Name(), "OpenVPN") == 0 && proto->Cedar->Server->DisableOpenVPNServer)
		{
			Debug("ProtoImplDetect(): OpenVPN detected, but it's disabled\n");
			continue;
		}

		Debug("ProtoImplDetect(): %s detected\n", impl->Name());
		return impl;
	}

	Debug("ProtoImplDetect(): unrecognized protocol\n");
	return NULL;
}

bool ProtoHandleConnection(PROTO *proto, SOCK *sock)
{
	void *impl_data = NULL;
	const PROTO_IMPL *impl;

	UCHAR *buf;
	TCP_RAW_DATA *recv_raw_data;
	FIFO *send_fifo;
	INTERRUPT_MANAGER *im;
	SOCK_EVENT *se;

	if (proto == NULL || sock == NULL)
	{
		return false;
	}

	{
		UCHAR tmp[PROTO_CHECK_BUFFER_SIZE];
		if (Peek(sock, tmp, sizeof(tmp)) == 0)
		{
			return false;
		}

		impl = ProtoImplDetect(proto, PROTO_MODE_TCP, tmp, sizeof(tmp));
		if (impl == NULL)
		{
			return false;
		}
	}

	im = NewInterruptManager();
	se = NewSockEvent();

	if (impl->Init != NULL && impl->Init(&impl_data, proto->Cedar, im, se) == false)
	{
		Debug("ProtoHandleConnection(): failed to initialize %s\n", impl->Name());
		FreeInterruptManager(im);
		ReleaseSockEvent(se);
		return false;
	}

	SetTimeout(sock, TIMEOUT_INFINITE);
	JoinSockToSockEvent(sock, se);

	recv_raw_data = NewTcpRawData(&sock->RemoteIP, sock->RemotePort, &sock->LocalIP, sock->LocalPort);
	send_fifo = NewFifoFast();

	buf = Malloc(PROTO_TCP_BUFFER_SIZE);

	Debug("ProtoHandleConnection(): entering main loop\n");

	// Receive data from the TCP socket
	while (true)
	{
		UINT next_interval;
		bool stop = false;

		while (true)
		{
			const UINT ret = Recv(sock, buf, PROTO_TCP_BUFFER_SIZE, false);

			if (ret == SOCK_LATER)
			{
				// No more data to read
				break;
			}
			else if (ret == 0)
			{
				// Disconnected
				stop = true;
				break;
			}
			else
			{
				// Write the received data into the FIFO
				WriteFifo(recv_raw_data->Data, buf, ret);
			}
		}

		if (impl->ProcessData(impl_data, recv_raw_data, send_fifo) == false)
		{
			stop = true;
		}

		// Send data to the TCP socket
		while (FifoSize(send_fifo) >= 1)
		{
			const UINT ret = Send(sock, FifoPtr(send_fifo), FifoSize(send_fifo), false);

			if (ret == SOCK_LATER)
			{
				// Can not write anymore
				break;
			}
			else if (ret == 0)
			{
				// Disconnected
				stop = true;
				break;
			}
			else
			{
				// Remove data that has been sent from the FIFO
				ReadFifo(send_fifo, NULL, ret);
			}
		}

		impl->BufferLimit(impl_data, FifoSize(send_fifo) > MAX_BUFFERING_PACKET_SIZE);

		if (stop)
		{
			// Error or disconnection occurs
			Debug("ProtoHandleConnection(): breaking main loop\n");
			break;
		}

		// Wait until the next event occurs
		next_interval = GetNextIntervalForInterrupt(im);
		next_interval = MIN(next_interval, UDPLISTENER_WAIT_INTERVAL);
		WaitSockEvent(se, next_interval);
	}

	impl->Free(impl_data);

	FreeInterruptManager(im);
	ReleaseSockEvent(se);
	FreeTcpRawData(recv_raw_data);
	ReleaseFifo(send_fifo);
	Free(buf);

	return true;
}
