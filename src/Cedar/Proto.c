#include "CedarPch.h"

#include "Proto_OpenVPN.h"

static LIST *protocols = NULL;

int ProtoCompare(void *p1, void *p2)
{
	PROTO *proto_1, *proto_2;

	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	proto_1 = (PROTO *)p1;
	proto_2 = (PROTO *)p2;

	if (StrCmp(proto_1->impl->Name(), proto_2->impl->Name()) == 0)
	{
		return true;
	}

	return false;
}

void ProtoInit()
{
	if (protocols != NULL)
	{
		ProtoFree();
	}

	protocols = NewList(ProtoCompare);

	// OpenVPN
	ProtoAdd(OvsGetProtoImpl());
}

void ProtoFree()
{
	UINT i;
	PROTO_IMPL *impl;

	for (i = 0; i < ProtoNum(); ++i)
	{
		PROTO *proto = ProtoGet(i);
		impl = proto->impl;
		Free(proto);
	}

	ReleaseList(protocols);
	protocols = NULL;
}

bool ProtoAdd(PROTO_IMPL *impl)
{
	PROTO *proto;

	if (protocols == NULL || impl == NULL)
	{
		return false;
	}

	proto = Malloc(sizeof(PROTO));
	proto->impl = impl;

	Add(protocols, proto);

	Debug("ProtoAdd(): added %s\n", proto->impl->Name());

	return true;
}

UINT ProtoNum()
{
	return LIST_NUM(protocols);
}

PROTO *ProtoGet(const UINT index)
{
	return LIST_DATA(protocols, index);
}

PROTO *ProtoDetect(SOCK *sock)
{
	UCHAR buf[PROTO_CHECK_BUFFER_SIZE];
	UINT i;

	if (sock == NULL)
	{
		return NULL;
	}

	if (Peek(sock, buf, sizeof(buf)) == 0)
	{
		return false;
	}

	for (i = 0; i < ProtoNum(); ++i)
	{
		PROTO *p = ProtoGet(i);
		if (p->impl->IsPacketForMe(buf, sizeof(buf)))
		{
			Debug("ProtoDetect(): %s detected\n", p->impl->Name());
			return p;
		}
	}

	return NULL;
}

bool ProtoHandleConnection(CEDAR *cedar, SOCK *sock)
{
	void *impl_data;
	const PROTO_IMPL *impl;
	const PROTO *proto;

	UCHAR *buf;
	TCP_RAW_DATA *recv_raw_data;
	FIFO *send_fifo;
	INTERRUPT_MANAGER *im;
	SOCK_EVENT *se;

	const UINT64 giveup = Tick64() + (UINT64)OPENVPN_NEW_SESSION_DEADLINE_TIMEOUT;

	if (cedar == NULL || sock == NULL)
	{
		return false;
	}

	proto = ProtoDetect(sock);

	if (proto == NULL)
	{
		Debug("ProtoHandleConnection(): unrecognized protocol\n");
		return false;
	}

	impl = proto->impl;

	if (StrCmp(impl->Name(), "OpenVPN") == 0 && cedar->Server->DisableOpenVPNServer == true)
	{
		Debug("ProtoHandleConnection(): OpenVPN detected, but it's disabled\n");
		return false;
	}

	if ((impl->SupportedModes() & PROTO_MODE_TCP) == false)
	{
		return false;
	}

	im = NewInterruptManager();
	se = NewSockEvent();

	if (impl->Init != NULL && impl->Init(&impl_data, cedar, im, se) == false)
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

		if (impl->IsOk(impl_data) == false)
		{
			if (impl->EstablishedSessions(impl_data) == 0)
			{
				if (Tick64() >= giveup)
				{
					Debug("ProtoHandleConnection(): I waited too much for the session to start, I give up!\n");
					stop = true;
				}
			}
			else
			{
				Debug("ProtoHandleConnection(): implementation not OK, stopping the server\n");
				stop = true;
			}
		}

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
