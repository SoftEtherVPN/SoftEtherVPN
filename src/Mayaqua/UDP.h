#ifndef UDP_H
#define UDP_H

#include "Network.h"

#define UDP_CONVEYOR_BUFFER 65536

struct UDP_PACKET
{
	UINT64 Tick;
	void *Data;
	UINT Size;
	IP LocalIP;
	IP RemoteIP;
	PORT LocalPort;
	PORT RemotePort;
	REF *Ref;
};

struct UDP_MANAGER
{
	EVENT *InEvent;
	QUEUE_MPSC *InQueue;
	HASH_LIST *InThreads;
	HASH_LIST *OutThreads;
	REF *Ref;
};

struct UDP_CONVEYOR
{
	volatile bool Halt;
	EVENT *Event;
	SOCKET_BOX *Box;
	SOCKET_MONITOR *Monitor;
	QUEUE_MPSC *Queue;
	THREAD *Thread;
};

UDP_PACKET *UdpPacketNew(void *data, const UINT size, const IP *local_ip, const IP *remote_ip, const PORT local_port, const PORT remote_port);
void UdpPacketFree(UDP_PACKET *packet);

UDP_MANAGER *UdpManagerNew();
void UdpManagerFree(UDP_MANAGER *manager);

bool UdpManagerAdd(UDP_MANAGER *manager, const IP *ip, const PORT port);
void UdpManagerDel(UDP_MANAGER *manager, const IP *ip, const PORT port);

bool UdpManagerSend(UDP_MANAGER *manager, UDP_PACKET *packet);
UDP_PACKET *UdpManagerRecv(UDP_MANAGER *manager);

void UdpManagerWakeUp(UDP_MANAGER *manager);

int UdpConveyorCompare(void *p1, void *p2);
UINT UdpConveyorHash(void *p);

UDP_CONVEYOR *UdpConveyorNewIn(SOCKET_BOX *box, EVENT *event, QUEUE_MPSC *queue);
UDP_CONVEYOR *UdpConveyorNewOut(SOCKET_BOX *box);
void UdpConveyorFree(UDP_CONVEYOR *conveyor);

void UdpConveyorIn(THREAD *thread, void *param);
void UdpConveyorOut(THREAD *thread, void *param);

#endif
