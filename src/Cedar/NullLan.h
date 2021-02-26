// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// NullLan.h
// Header of NullLan.c

#ifndef	NULLLAN_H
#define	NULLLAN_H


#define	NULL_PACKET_GENERATE_INTERVAL		100000000		// Packet generation interval

// NULL device structure
struct NULL_LAN
{
	THREAD *PacketGeneratorThread;
	CANCEL *Cancel;
	QUEUE *PacketQueue;
	volatile bool Halt;
	EVENT *Event;
	UCHAR MacAddr[6];
	UCHAR Padding[2];
	UINT Id;
};

PACKET_ADAPTER *NullGetPacketAdapter();
bool NullPaInit(SESSION *s);
CANCEL *NullPaGetCancel(SESSION *s);
UINT NullPaGetNextPacket(SESSION *s, void **data);
bool NullPaPutPacket(SESSION *s, void *data, UINT size);
void NullPaFree(SESSION *s);
void NullPacketGenerateThread(THREAD *t, void *param);
void NullGenerateMacAddress(UCHAR *mac, UINT id, UINT seq);

#endif	// NULLAN_H



