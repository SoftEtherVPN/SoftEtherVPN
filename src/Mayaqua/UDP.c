#include "UDP.h"

#include "Kernel.h"
#include "Memory.h"
#include "Object.h"
#include "Queue.h"
#include "Socket.h"
#include "Str.h"
#include "Tick64.h"

UDP_PACKET *UdpPacketNew(void *data, const UINT size, const IP *local_ip, const IP *remote_ip, const PORT local_port, const PORT remote_port)
{
	UDP_PACKET *packet = Malloc(sizeof(UDP_PACKET));

	packet->Tick = Tick64();
	packet->Data = data;
	packet->Size = size;
	Copy(&packet->LocalIP, local_ip, sizeof(packet->LocalIP));
	Copy(&packet->RemoteIP, remote_ip, sizeof(packet->RemoteIP));
	packet->LocalPort = local_port;
	packet->RemotePort = remote_port;
	packet->Ref = NewRef();

	return packet;
}

void UdpPacketFree(UDP_PACKET *packet)
{
	if (packet == NULL || Release(packet->Ref) != 0)
	{
		return;
	}

	Free(packet->Data);
	Free(packet);
}

UDP_MANAGER *UdpManagerNew()
{
	UDP_MANAGER *manager = Malloc(sizeof(UDP_MANAGER));

	manager->InEvent = NewEvent();
	manager->InQueue = QueueMpscNew();
	manager->InThreads = NewHashList(UdpConveyorHash, UdpConveyorCompare, 0, true);
	manager->OutThreads = NewHashList(UdpConveyorHash, UdpConveyorCompare, 0, true);
	manager->Ref = NewRef();

	return manager;
}

void UdpManagerFree(UDP_MANAGER *manager)
{
	if (manager == NULL || Release(manager->Ref) != 0)
	{
		return;
	}

	for (UINT i = 0; i < LIST_NUM(manager->InThreads->AllList); ++i)
	{
		UdpConveyorFree(LIST_DATA(manager->InThreads->AllList, i));
	}
	ReleaseHashList(manager->InThreads);

	for (UINT i = 0; i < LIST_NUM(manager->OutThreads->AllList); ++i)
	{
		UdpConveyorFree(LIST_DATA(manager->OutThreads->AllList, i));
	}
	ReleaseHashList(manager->OutThreads);

	QueueMpscFree(manager->InQueue);
	ReleaseEvent(manager->InEvent);

	Free(manager);
}

bool UdpManagerAdd(UDP_MANAGER *manager, const IP *ip, const PORT port)
{
	if (manager == NULL || ip == NULL)
	{
		return false;
	}

	SOCKET socket = SocketOpen(false, SOCK_DGRAM, IPPROTO_UDP);
	if (socket == SOCKET_INVALID)
	{
		return false;
	}

	if (SocketBind(socket, ip, port) == false)
	{
		SocketClose(socket);
		return false;
	}

	SOCKET_BOX *box = SocketBoxNew(socket);

	AddHash(manager->InThreads, UdpConveyorNewIn(box, manager->InEvent, manager->InQueue));
	AddRef(box->Ref);
	AddHash(manager->OutThreads, UdpConveyorNewOut(box));

	return true;
}

void UdpManagerDel(UDP_MANAGER *manager, const IP *ip, const PORT port)
{
	if (manager == NULL || ip == NULL)
	{
		return;
	}

	SOCKET_BOX tmp_box;
	Copy(&tmp_box.IP, ip, sizeof(tmp_box.IP));
	tmp_box.Port = port;

	UDP_CONVEYOR tmp_conveyor;
	tmp_conveyor.Box = &tmp_box;

	UDP_CONVEYOR *in_conveyor = SearchHash(manager->InThreads, &tmp_conveyor);
	UDP_CONVEYOR *out_conveyor = SearchHash(manager->OutThreads, &tmp_conveyor);

	UdpConveyorFree(in_conveyor);
	UdpConveyorFree(out_conveyor);
}

bool UdpManagerSend(UDP_MANAGER *manager, UDP_PACKET *packet)
{
	if (manager == NULL || packet == NULL)
	{
		return false;
	}

	SOCKET_BOX tmp_box;
	Copy(&tmp_box.IP, &packet->LocalIP, sizeof(tmp_box.IP));
	tmp_box.Port = packet->LocalPort;

	UDP_CONVEYOR tmp_conveyor;
	tmp_conveyor.Box = &tmp_box;

	UDP_CONVEYOR *conveyor = SearchHash(manager->OutThreads, &tmp_conveyor);
	if (conveyor == NULL)
	{
		return false;
	}

	AddRef(packet->Ref);
	QueueMpscPushValue(conveyor->Queue, packet);

	SocketMonitorTrigger(conveyor->Monitor);

	return true;
}

UDP_PACKET *UdpManagerRecv(UDP_MANAGER *manager)
{
	if (manager == NULL)
	{
		return NULL;
	}

	return QueueMpscPopValue(manager->InQueue);
}

void UdpManagerWakeUp(UDP_MANAGER *manager)
{
	if (manager != NULL)
	{
		Set(manager->InEvent);
	}
}

int UdpConveyorCompare(void *p1, void *p2)
{
	if (p1 == NULL || p2 == NULL)
	{
		return COMPARE_RET(p1, p2);
	}

	UDP_CONVEYOR *conveyor_1 = *(UDP_CONVEYOR **)p1;
	UDP_CONVEYOR *conveyor_2 = *(UDP_CONVEYOR **)p2;

	SOCKET_BOX *box_1 = conveyor_1->Box;
	SOCKET_BOX *box_2 = conveyor_2->Box;

	const int ret = CmpIpAddr(&box_1->IP, &box_2->IP);
	if (ret != 0)
	{
		return ret;
	}

	return COMPARE_RET(box_1->Port, box_2->Port);
}

UINT UdpConveyorHash(void *p)
{
	if (p == NULL)
	{
		return 0;
	}

	UINT ret = 0;

	SOCKET_BOX *box = ((UDP_CONVEYOR *)p)->Box;
	IP *ip = &box->IP;

	for (BYTE i = 0; i < sizeof(ip->address); ++i)
	{
		ret += ip->address[i];
	}

	ret += ip->ipv6_scope_id;
	ret += box->Port;

	return ret;
}

UDP_CONVEYOR *UdpConveyorNewIn(SOCKET_BOX *box, EVENT *event, QUEUE_MPSC *queue)
{
	if (box == NULL || event == NULL || queue == NULL)
	{
		return NULL;
	}

	SOCKET_MONITOR *monitor = SocketMonitorNew(box->Socket, true, false);
	if (monitor == NULL)
	{
		return NULL;
	}

	AddRef(event->ref);
	AddRef(queue->Ref);

	UDP_CONVEYOR *conveyor = Malloc(sizeof(UDP_CONVEYOR));

	conveyor->Halt = false;
	conveyor->Event = event;
	conveyor->Box = box;
	conveyor->Monitor = monitor;
	conveyor->Queue = queue;
	conveyor->Thread = NewThread(UdpConveyorIn, conveyor);

	return conveyor;
}

UDP_CONVEYOR *UdpConveyorNewOut(SOCKET_BOX *box)
{
	if (box == NULL)
	{
		return NULL;
	}

	SOCKET_MONITOR *monitor = SocketMonitorNew(box->Socket, false, true);
	if (monitor == NULL)
	{
		return NULL;
	}

	UDP_CONVEYOR *conveyor = Malloc(sizeof(UDP_CONVEYOR));

	conveyor->Halt = false;
	conveyor->Event = NewEvent();
	conveyor->Box = box;
	conveyor->Monitor = monitor;
	conveyor->Queue = QueueMpscNew();
	conveyor->Thread = NewThread(UdpConveyorOut, conveyor);

	return conveyor;
}

void UdpConveyorFree(UDP_CONVEYOR *conveyor)
{
	if (conveyor == NULL)
	{
		return;
	}

	conveyor->Halt = true;
	Set(conveyor->Event);
	SocketMonitorTrigger(conveyor->Monitor);
	WaitThread(conveyor->Thread, INFINITE);

	ReleaseThread(conveyor->Thread);
	QueueMpscFree(conveyor->Queue);
	SocketMonitorFree(conveyor->Monitor);
	SocketBoxFree(conveyor->Box);
	ReleaseEvent(conveyor->Event);
}

void UdpConveyorIn(THREAD *thread, void *param)
{
	if (thread == NULL || param == NULL)
	{
		return;
	}

	void *buf = Malloc(UDP_CONVEYOR_BUFFER);

	UDP_CONVEYOR *conveyor = param;
	SOCKET_BOX *box = conveyor->Box;

	while (conveyor->Halt == false)
	{
		IP ip;
		PORT port;
		const int ret = SocketRecvFrom(box->Socket, &ip, &port, buf, UDP_CONVEYOR_BUFFER);
		if (ret > 0)
		{
			UDP_PACKET *packet = UdpPacketNew(Clone(buf, ret), ret, &box->IP, &ip, box->Port, port);
			QueueMpscPushValue(conveyor->Queue, packet);
		}
		else
		{
			switch (ret)
			{
			case SOCKET_BUSY:
				SocketMonitorWait(conveyor->Monitor, INFINITE);
				break;
			case SOCKET_FAIL:
				Debug("UdpConveyorIn(): SocketRecvFrom() failed!\n");
				conveyor->Halt = true;
			}
		}
	}

	Free(buf);
}

void UdpConveyorOut(THREAD *thread, void *param)
{
	if (thread == NULL || param == NULL)
	{
		return;
	}

	UDP_CONVEYOR *conveyor = param;

	while (conveyor->Halt == false)
	{
		UDP_PACKET *packet = QueueMpscPopValue(conveyor->Queue);
		if (packet == NULL)
		{
			Wait(conveyor->Event, INFINITE);
			continue;
		}
RETRY:	;
		const int ret = SocketSendTo(conveyor->Box->Socket, &packet->RemoteIP, packet->RemotePort, packet->Data, packet->Size);
		switch (ret)
		{
		case SOCKET_BUSY:
			SocketMonitorWait(conveyor->Monitor, INFINITE);

			if (conveyor->Halt == false)
			{
				goto RETRY;
			}

			break;
		case SOCKET_FAIL:
			Debug("UdpConveyorOut(): SocketSendTo() failed!\n");
			conveyor->Halt = true;
		}
	}
}
