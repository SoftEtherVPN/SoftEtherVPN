#include "CedarPch.h"

#include "Proto_OpenVPN.h"

int ProtoOptionCompare(void *p1, void *p2)
{
	PROTO_OPTION *option_1, *option_2;

	if (p1 == NULL || p2 == NULL)
	{
		return (p1 == NULL && p2 == NULL ? 0 : (p1 == NULL ? -1 : 1));
	}

	option_1 = *(PROTO_OPTION **)p1;
	option_2 = *(PROTO_OPTION **)p2;

	return StrCmpi(option_1->Name, option_2->Name);
}

int ProtoContainerCompare(void *p1, void *p2)
{
	PROTO_CONTAINER *container_1, *container_2;

	if (p1 == NULL || p2 == NULL)
	{
		return (p1 == NULL && p2 == NULL ? 0 : (p1 == NULL ? -1 : 1));
	}

	container_1 = *(PROTO_CONTAINER **)p1;
	container_2 = *(PROTO_CONTAINER **)p2;

	return StrCmpi(container_1->Name, container_2->Name);
}

int ProtoSessionCompare(void *p1, void *p2)
{
	int ret;
	PROTO_SESSION *session_1, *session_2;

	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	session_1 = *(PROTO_SESSION **)p1;
	session_2 = *(PROTO_SESSION **)p2;

	// The source port must match
	ret = COMPARE_RET(session_1->SrcPort, session_2->SrcPort);
	if (ret != 0)
	{
		return ret;
	}

	// The destination port must match
	ret = COMPARE_RET(session_1->DstPort, session_2->DstPort);
	if (ret != 0)
	{
		return ret;
	}

	// The source IP address must match
	ret = CmpIpAddr(&session_1->SrcIp, &session_2->SrcIp);
	if (ret != 0)
	{
		return ret;
	}

	// The destination IP address must match
	return CmpIpAddr(&session_1->DstIp, &session_2->DstIp);
}

UINT ProtoSessionHash(void *p)
{
	IP *ip;
	UINT ret = 0;
	PROTO_SESSION *session = p;

	if (session == NULL)
	{
		return 0;
	}

	ip = &session->SrcIp;
	if (IsIP6(ip))
	{
		UINT i;
		for (i = 0; i < sizeof(ip->ipv6_addr); ++i)
		{
			ret += ip->ipv6_addr[i];
		}

		ret += ip->ipv6_scope_id;
	}
	else
	{
		UINT i;
		for (i = 0; i < sizeof(ip->addr); ++i)
		{
			ret += ip->addr[i];
		}
	}

	ret += session->SrcPort;

	ip = &session->DstIp;
	if (IsIP6(ip))
	{
		UINT i;
		for (i = 0; i < sizeof(ip->ipv6_addr); ++i)
		{
			ret += ip->ipv6_addr[i];
		}

		ret += ip->ipv6_scope_id;
	}
	else
	{
		UINT i;
		for (i = 0; i < sizeof(ip->addr); ++i)
		{
			ret += ip->addr[i];
		}
	}

	ret += session->DstPort;

	return ret;
}

bool ProtoEnabled(const PROTO *proto, const char *name)
{
	PROTO_OPTION *option, tmp_o;
	PROTO_CONTAINER *container, tmp_c;

	if (proto == NULL || name == NULL)
	{
		return false;
	}

	tmp_c.Name = name;

	container = Search(proto->Containers, &tmp_c);
	if (container == NULL)
	{
		return false;
	}

	tmp_o.Name = PROTO_OPTION_TOGGLE_NAME;

	option = Search(container->Options, &tmp_o);
	if (option == NULL || option->Type != PROTO_OPTION_BOOL)
	{
		return false;
	}

	return option->Bool;
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
	proto->Containers = NewList(ProtoContainerCompare);
	proto->Sessions = NewHashList(ProtoSessionHash, ProtoSessionCompare, 0, true);

	AddRef(cedar->ref);

	// OpenVPN
	Add(proto->Containers, ProtoContainerNew(OvsGetProtoImpl()));
	// SSTP
	Add(proto->Containers, ProtoContainerNew(SstpGetProtoImpl()));

	proto->UdpListener = NewUdpListener(ProtoHandleDatagrams, proto, &cedar->Server->ListenIP);

	return proto;
}

void ProtoDelete(PROTO *proto)
{
	UINT i = 0;

	if (proto == NULL)
	{
		return;
	}

	StopUdpListener(proto->UdpListener);

	for (i = 0; i < HASH_LIST_NUM(proto->Sessions); ++i)
	{
		ProtoDeleteSession(LIST_DATA(proto->Sessions->AllList, i));
	}
	ReleaseHashList(proto->Sessions);

	for (i = 0; i < LIST_NUM(proto->Containers); ++i)
	{
		ProtoContainerDelete(LIST_DATA(proto->Containers, i));
	}
	ReleaseList(proto->Containers);

	FreeUdpListener(proto->UdpListener);
	ReleaseCedar(proto->Cedar);
	Free(proto);
}

PROTO_CONTAINER *ProtoContainerNew(const PROTO_IMPL *impl)
{
	UINT i;
	PROTO_OPTION *option;
	PROTO_CONTAINER *container;
	const PROTO_OPTION *impl_options;

	if (impl == NULL)
	{
		return false;
	}

	container = Malloc(sizeof(PROTO_CONTAINER));
	container->Name = impl->Name();
	container->Options = NewList(ProtoOptionCompare);
	container->Impl = impl;

	option = ZeroMalloc(sizeof(PROTO_OPTION));
	option->Name = PROTO_OPTION_TOGGLE_NAME;
	option->Type = PROTO_OPTION_BOOL;
	option->Bool = true;

	Add(container->Options, option);

	impl_options = impl->Options();

	for (i = 0; impl_options[i].Name != NULL; ++i)
	{
		const PROTO_OPTION *impl_option = &impl_options[i];

		option = ZeroMalloc(sizeof(PROTO_OPTION));
		option->Name = impl_option->Name;
		option->Type = impl_option->Type;

		switch (impl_option->Type)
		{
		case PROTO_OPTION_BOOL:
			option->Bool = impl_option->Bool;
			break;
		case PROTO_OPTION_STRING:
			option->String = CopyStr(impl_option->String);
			break;
		default:
			Debug("ProtoContainerNew(): unhandled option type %u!\n", impl_option->Type);
			Free(option);
			continue;
		}

		Add(container->Options, option);
	}

	Debug("ProtoContainerNew(): %s\n", container->Name);

	return container;
}

void ProtoContainerDelete(PROTO_CONTAINER *container)
{
	UINT i;
	LIST *options;

	if (container == NULL)
	{
		return;
	}

	options = container->Options;

	for (i = 0; i < LIST_NUM(options); ++i)
	{
		PROTO_OPTION *option = LIST_DATA(options, i);
		if (option->Type == PROTO_OPTION_STRING)
		{
			Free(option->String);
		}

		Free(option);
	}

	ReleaseList(options);
	Free(container);
}

const PROTO_CONTAINER *ProtoDetect(const PROTO *proto, const PROTO_MODE mode, const UCHAR *data, const UINT size)
{
	UINT i;

	if (proto == NULL || data == NULL || size == 0)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(proto->Containers); ++i)
	{
		const PROTO_CONTAINER *container = LIST_DATA(proto->Containers, i);
		const PROTO_IMPL *impl = container->Impl;

		if (ProtoEnabled(proto, container->Name) == false)
		{
			Debug("ProtoDetect(): skipping %s because it's disabled\n", container->Name);
			continue;
		}

		if (impl->IsPacketForMe != NULL && impl->IsPacketForMe(mode, data, size))
		{
			Debug("ProtoDetect(): %s detected\n", container->Name);
			return container;
		}
	}

	Debug("ProtoDetect(): unrecognized protocol\n");
	return NULL;
}

PROTO_SESSION *ProtoNewSession(PROTO *proto, const PROTO_CONTAINER *container, const IP *src_ip, const USHORT src_port, const IP *dst_ip, const USHORT dst_port)
{
	LIST *options;
	PROTO_SESSION *session;
	const PROTO_IMPL *impl;

	if (container == NULL || src_ip == NULL || src_port == 0 || dst_ip == NULL || dst_port == 0)
	{
		return NULL;
	}

	options = container->Options;
	impl = container->Impl;

	session = ZeroMalloc(sizeof(PROTO_SESSION));
	session->SockEvent = NewSockEvent();
	session->InterruptManager = NewInterruptManager();

	LockList(options);

	if (impl->Init != NULL && impl->Init(&session->Param, container->Options, proto->Cedar, session->InterruptManager, session->SockEvent, NULL, NULL) == false)
	{
		Debug("ProtoNewSession(): failed to initialize %s\n", container->Name);

		UnlockList(options);
		ReleaseSockEvent(session->SockEvent);
		FreeInterruptManager(session->InterruptManager);
		Free(session);

		return NULL;
	}

	UnlockList(options);

	session->Proto = proto;
	session->Impl = impl;

	CopyIP(&session->SrcIp, src_ip);
	session->SrcPort = src_port;
	CopyIP(&session->DstIp, dst_ip);
	session->DstPort = dst_port;

	session->DatagramsIn = NewListFast(NULL);
	session->DatagramsOut = NewListFast(NULL);

	session->Lock = NewLock();
	session->Thread = NewThread(ProtoSessionThread, session);

	return session;
}

void ProtoDeleteSession(PROTO_SESSION *session)
{
	if (session == NULL)
	{
		return;
	}

	session->Halt = true;
	SetSockEvent(session->SockEvent);

	WaitThread(session->Thread, INFINITE);
	ReleaseThread(session->Thread);

	session->Impl->Free(session->Param);

	ReleaseSockEvent(session->SockEvent);
	FreeInterruptManager(session->InterruptManager);

	ReleaseList(session->DatagramsIn);
	ReleaseList(session->DatagramsOut);

	DeleteLock(session->Lock);

	Free(session);
}

bool ProtoSetListenIP(PROTO *proto, const IP *ip)
{
	if (proto == NULL || ip == NULL)
	{
		return false;
	}

	Copy(&proto->UdpListener->ListenIP, ip, sizeof(proto->UdpListener->ListenIP));

	return true;
}

bool ProtoSetUdpPorts(PROTO *proto, const LIST *ports)
{
	UINT i = 0;

	if (proto == NULL || ports == NULL)
	{
		return false;
	}

	DeleteAllPortFromUdpListener(proto->UdpListener);

	for (i = 0; i < LIST_NUM(ports); ++i)
	{
		UINT port = *((UINT *)LIST_DATA(ports, i));
		if (port >= 1 && port <= 65535)
		{
			AddPortToUdpListener(proto->UdpListener, port);
		}
	}

	return true;
}

bool ProtoHandleConnection(PROTO *proto, SOCK *sock, const char *protocol)
{
	const PROTO_IMPL *impl;
	void *impl_data = NULL;

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
		const PROTO_CONTAINER *container = NULL;
		LIST *options;

		if (protocol != NULL)
		{
			UINT i;
			for (i = 0; i < LIST_NUM(proto->Containers); ++i)
			{
				const PROTO_CONTAINER *tmp = LIST_DATA(proto->Containers, i);
				if (StrCmp(tmp->Name, protocol) == 0)
				{
					impl = container->Impl;
					break;
				}
			}
		}
		else
		{
			UCHAR tmp[PROTO_CHECK_BUFFER_SIZE];

			if (Peek(sock, tmp, sizeof(tmp)) == 0)
			{
				return false;
			}

			container = ProtoDetect(proto, PROTO_MODE_TCP, tmp, sizeof(tmp));
		}

		if (container == NULL)
		{
			return false;
		}

		options = container->Options;
		impl = container->Impl;

		im = NewInterruptManager();
		se = NewSockEvent();

		LockList(options);

		if (impl->Init != NULL && impl->Init(&impl_data, options, proto->Cedar, im, se, sock->CipherName, sock->RemoteHostname) == false)
		{
			Debug("ProtoHandleConnection(): failed to initialize %s\n", container->Name);

			UnlockList(options);
			FreeInterruptManager(im);
			ReleaseSockEvent(se);

			return false;
		}

		UnlockList(options);
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
			const UINT ret = Recv(sock, buf, PROTO_TCP_BUFFER_SIZE, sock->SecureMode);

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
			const UINT ret = Send(sock, FifoPtr(send_fifo), FifoSize(send_fifo), sock->SecureMode);

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

void ProtoHandleDatagrams(UDPLISTENER *listener, LIST *datagrams)
{
	UINT i;
	PROTO *proto;
	HASH_LIST *sessions;

	if (listener == NULL || datagrams == NULL)
	{
		return;
	}

	proto = listener->Param;
	sessions = proto->Sessions;

	for (i = 0; i < LIST_NUM(datagrams); ++i)
	{
		UDPPACKET *datagram = LIST_DATA(datagrams, i);
		PROTO_SESSION *session, tmp;

		CopyIP(&tmp.SrcIp, &datagram->SrcIP);
		tmp.SrcPort = datagram->SrcPort;
		CopyIP(&tmp.DstIp, &datagram->DstIP);
		tmp.DstPort = datagram->DestPort;

		session = SearchHash(sessions, &tmp);
		if (session == NULL)
		{
			const PROTO_CONTAINER *container = ProtoDetect(proto, PROTO_MODE_UDP, datagram->Data, datagram->Size);
			if (container == NULL)
			{
				continue;
			}

			session = ProtoNewSession(proto, container, &tmp.SrcIp, tmp.SrcPort, &tmp.DstIp, tmp.DstPort);
			if (session == NULL)
			{
				continue;
			}

			AddHash(proto->Sessions, session);
		}

		if (session->Halt)
		{
			DeleteHash(sessions, session);
			ProtoDeleteSession(session);
			continue;
		}

		Lock(session->Lock);
		{
			void *data = Clone(datagram->Data, datagram->Size);
			UDPPACKET *packet = NewUdpPacket(&datagram->SrcIP, datagram->SrcPort, &datagram->DstIP, datagram->DestPort, data, datagram->Size);
			Add(session->DatagramsIn, packet);
		}
		Unlock(session->Lock);
	}

	for (i = 0; i < LIST_NUM(sessions->AllList); ++i)
	{
		PROTO_SESSION *session = LIST_DATA(sessions->AllList, i);
		if (LIST_NUM(session->DatagramsIn) > 0)
		{
			SetSockEvent(session->SockEvent);
		}
	}
}

void ProtoSessionThread(THREAD *thread, void *param)
{
	PROTO_SESSION *session = param;

	if (thread == NULL || session == NULL)
	{
		return;
	}

	while (session->Halt == false)
	{
		bool ok;
		UINT interval;
		void *param = session->Param;
		const PROTO_IMPL *impl = session->Impl;
		LIST *received = session->DatagramsIn;
		LIST *to_send = session->DatagramsOut;

		Lock(session->Lock);
		{
			UINT i;

			ok = impl->ProcessDatagrams(param, received, to_send);

			UdpListenerSendPackets(session->Proto->UdpListener, to_send);

			for (i = 0; i < LIST_NUM(received); ++i)
			{
				FreeUdpPacket(LIST_DATA(received, i));
			}

			DeleteAll(received);
			DeleteAll(to_send);
		}
		Unlock(session->Lock);

		if (ok == false)
		{
			Debug("ProtoSessionThread(): breaking main loop\n");
			session->Halt = true;
			break;
		}

		// Wait until the next event occurs
		interval = GetNextIntervalForInterrupt(session->InterruptManager);
		interval = MIN(interval, UDPLISTENER_WAIT_INTERVAL);
		WaitSockEvent(session->SockEvent, interval);
	}
}
