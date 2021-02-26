// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// NullLan.c
// Virtual LAN card device driver for testing

#include "CedarPch.h"

static UCHAR null_lan_broadcast_address[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

// Get the packet adapter
PACKET_ADAPTER *NullGetPacketAdapter()
{
	PACKET_ADAPTER *pa = NewPacketAdapter(NullPaInit, NullPaGetCancel, NullPaGetNextPacket,
		NullPaPutPacket, NullPaFree);

	return pa;
}

// Generate MAC address
void NullGenerateMacAddress(UCHAR *mac, UINT id, UINT seq)
{
	UCHAR hash[SHA1_SIZE];
	char name[MAX_SIZE];
	BUF *b;
	// Validate arguments
	if (mac == NULL)
	{
		return;
	}

	b = NewBuf();
	WriteBufInt(b, id);
	WriteBufInt(b, seq);
	GetMachineHostName(name, sizeof(name));
#ifdef	OS_WIN32
	WriteBufInt(b, MsGetCurrentProcessId());
#endif	// OS_WIN32
	WriteBufStr(b, name);

	Sha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Copy(mac, hash, 6);
	mac[0] = 0x7E;
}

// Packet generation thread
void NullPacketGenerateThread(THREAD *t, void *param)
{
	NULL_LAN *n = (NULL_LAN *)param;
	UINT64 end_tick = Tick64() + (UINT64)(60 * 1000);
	UINT seq = 0;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		/*if (Tick64() >= end_tick)
		{
			break;
		}*/

		Wait(n->Event, Rand32() % 1500);
		if (n->Halt)
		{
			break;
		}

		LockQueue(n->PacketQueue);
		{
			UCHAR *data;
			BLOCK *b;
			UINT size = Rand32() % 1500 + 14;
			UCHAR dst_mac[6];

			NullGenerateMacAddress(n->MacAddr, n->Id, seq);

			//NullGenerateMacAddress(dst_mac, n->Id + 1, 0);
			//StrToMac(dst_mac, "00-1B-21-A9-47-E6");
			StrToMac(dst_mac, "00-AC-7A-EF-83-FD");

			data = Malloc(size);
			Copy(data, null_lan_broadcast_address, 6);
			//Copy(data, dst_mac, 6);
			Copy(data + 6, n->MacAddr, 6);
			b = NewBlock(data, size, 0);
			InsertQueue(n->PacketQueue, b);
		}
		UnlockQueue(n->PacketQueue);
		Cancel(n->Cancel);

		//seq++;
	}
}

// Initialize the packet adapter
bool NullPaInit(SESSION *s)
{
	NULL_LAN *n;
	static UINT id_seed = 0;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	id_seed++;

	n = ZeroMalloc(sizeof(NULL_LAN));
	n->Id = id_seed;
	s->PacketAdapter->Param = (void *)n;

	n->Cancel = NewCancel();
	n->PacketQueue = NewQueue();
	n->Event = NewEvent();

	NullGenerateMacAddress(n->MacAddr, n->Id, 0);

	n->PacketGeneratorThread = NewThread(NullPacketGenerateThread, n);

	return true;
}

// Get the cancel object
CANCEL *NullPaGetCancel(SESSION *s)
{
	// Validate arguments
	NULL_LAN *n;
	if (s == NULL || (n = s->PacketAdapter->Param) == NULL)
	{
		return NULL;
	}

	AddRef(n->Cancel->ref);

	return n->Cancel;
}

// Get the next packet
UINT NullPaGetNextPacket(SESSION *s, void **data)
{
	UINT size = 0;
	// Validate arguments
	NULL_LAN *n;
	if (s == NULL || (n = s->PacketAdapter->Param) == NULL)
	{
		return INFINITE;
	}

	LockQueue(n->PacketQueue);
	{
		BLOCK *b = GetNext(n->PacketQueue);

		if (b != NULL)
		{
			*data = b->Buf;
			size = b->Size;
			Free(b);
		}
	}
	UnlockQueue(n->PacketQueue);

	return size;
}

// Write the packet
bool NullPaPutPacket(SESSION *s, void *data, UINT size)
{
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}
	if (data == NULL)
	{
		return true;
	}

	// Packet ignored
	Free(data);

	return true;
}

// Release
void NullPaFree(SESSION *s)
{
	// Validate arguments
	NULL_LAN *n;
	BLOCK *b;
	if (s == NULL || (n = s->PacketAdapter->Param) == NULL)
	{
		return;
	}

	n->Halt = true;
	Set(n->Event);

	WaitThread(n->PacketGeneratorThread, INFINITE);
	ReleaseThread(n->PacketGeneratorThread);

	LockQueue(n->PacketQueue);
	{
		while (b = GetNext(n->PacketQueue))
		{
			FreeBlock(b);
		}
	}
	UnlockQueue(n->PacketQueue);

	ReleaseQueue(n->PacketQueue);

	ReleaseCancel(n->Cancel);

	ReleaseEvent(n->Event);

	s->PacketAdapter->Param = NULL;
	Free(n);
}


