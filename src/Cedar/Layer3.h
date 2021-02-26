// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Layer3.h
// Header of Layer3.c

#ifndef	LAYER3_H
#define	LAYER3_H

// Constants
#define	L3_USERNAME					"L3SW_"


// L3 ARP table entry
struct L3ARPENTRY
{
	UINT IpAddress;					// IP address
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	UINT64 Expire;					// Expiration date
};

// L3 ARP resolution waiting list entry
struct L3ARPWAIT
{
	UINT IpAddress;					// IP address
	UINT64 LastSentTime;			// Time which the data has been sent last
	UINT64 Expire;					// Expiration date
};

// L3 IP packet table
struct L3PACKET
{
	PKT *Packet;					// Packet data body
	UINT64 Expire;					// Expiration date
	UINT NextHopIp;					// Local delivery destination IP address
};

// L3 routing table definition
struct L3TABLE
{
	UINT NetworkAddress;			// Network address
	UINT SubnetMask;				// Subnet mask
	UINT GatewayAddress;			// Gateway address
	UINT Metric;					// Metric
};

// L3 interface definition
struct L3IF
{
	L3SW *Switch;					// Layer-3 switch
	char HubName[MAX_HUBNAME_LEN + 1];	// Virtual HUB name
	UINT IpAddress;					// IP address
	UINT SubnetMask;				// Subnet mask

	HUB *Hub;						// Virtual HUB
	SESSION *Session;				// Session
	LIST *ArpTable;					// ARP table
	LIST *ArpWaitTable;				// ARP waiting table
	QUEUE *IpPacketQueue;			// IP packet queue (for reception from other interfaces)
	LIST *IpWaitList;				// IP waiting list
	QUEUE *SendQueue;				// Transmission queue
	UCHAR MacAddress[6];			// MAC address
	UCHAR Padding[2];
	UINT64 LastDeleteOldArpTable;	// Time that old ARP table entries are cleared
	LIST *CancelList;				// Cancellation list
	UINT64 LastBeaconSent;			// Time which the beacon has been sent last
};

// L3 switch definition
struct L3SW
{
	char Name[MAX_HUBNAME_LEN + 1];	// Name
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	CEDAR *Cedar;					// Cedar
	bool Active;					// During operation flag
	bool Online;					// Online flag
	volatile bool Halt;				// Halting flag
	LIST *IfList;					// Interface list
	LIST *TableList;				// Routing table list
	THREAD *Thread;					// Thread
};



// Function prototype
int CmpL3Sw(void *p1, void *p2);
int CmpL3ArpEntry(void *p1, void *p2);
int CmpL3ArpWaitTable(void *p1, void *p2);
int CmpL3Table(void *p1, void *p2);
int CmpL3If(void *p1, void *p2);
void InitCedarLayer3(CEDAR *c);
void FreeCedarLayer3(CEDAR *c);
L3SW *NewL3Sw(CEDAR *c, char *name);
void ReleaseL3Sw(L3SW *s);
void CleanupL3Sw(L3SW *s);
bool L3AddIf(L3SW *s, char *hubname, UINT ip, UINT subnet);
bool L3DelIf(L3SW *s, char *hubname);
bool L3AddTable(L3SW *s, L3TABLE *tbl);
bool L3DelTable(L3SW *s, L3TABLE *tbl);
L3IF *L3SearchIf(L3SW *s, char *hubname);
L3SW *L3GetSw(CEDAR *c, char *name);
L3SW *L3AddSw(CEDAR *c, char *name);
bool L3DelSw(CEDAR *c, char *name);
void L3FreeAllSw(CEDAR *c);
void L3SwStart(L3SW *s);
void L3SwStop(L3SW *s);
void L3SwThread(THREAD *t, void *param);
void L3Test(SERVER *s);
void L3InitAllInterfaces(L3SW *s);
void L3FreeAllInterfaces(L3SW *s);
void L3IfThread(THREAD *t, void *param);
void L3InitInterface(L3IF *f);
void L3FreeInterface(L3IF *f);
L3IF *L3GetNextIf(L3SW *s, UINT ip, UINT *next_hop);
L3TABLE *L3GetBestRoute(L3SW *s, UINT ip);
UINT L3GetNextPacket(L3IF *f, void **data);
void L3Polling(L3IF *f);
void L3PollingBeacon(L3IF *f);
void L3DeleteOldArpTable(L3IF *f);
void L3DeleteOldIpWaitList(L3IF *f);
void L3PollingArpWaitTable(L3IF *f);
void L3SendL2Now(L3IF *f, UCHAR *dest_mac, UCHAR *src_mac, USHORT protocol, void *data, UINT size);
void L3SendArpRequestNow(L3IF *f, UINT dest_ip);
void L3SendArpResponseNow(L3IF *f, UCHAR *dest_mac, UINT dest_ip, UINT src_ip);
void L3GenerateMacAddress(L3IF *f);
L3ARPENTRY *L3SearchArpTable(L3IF *f, UINT ip);
void L3SendIpNow(L3IF *f, L3ARPENTRY *a, L3PACKET *p);
void L3SendIp(L3IF *f, L3PACKET *p);
void L3RecvArp(L3IF *f, PKT *p);
void L3RecvArpRequest(L3IF *f, PKT *p);
void L3RecvArpResponse(L3IF *f, PKT *p);
void L3KnownArp(L3IF *f, UINT ip, UCHAR *mac);
void L3SendArp(L3IF *f, UINT ip);
void L3InsertArpTable(L3IF *f, UINT ip, UCHAR *mac);
void L3SendWaitingIp(L3IF *f, UCHAR *mac, UINT ip, L3ARPENTRY *a);
void L3PutPacket(L3IF *f, void *data, UINT size); 
void L3RecvL2(L3IF *f, PKT *p);
void L3StoreIpPacketToIf(L3IF *src_if, L3IF *dst_if, L3PACKET *p);
void L3RecvIp(L3IF *f, PKT *p, bool self);
void L3PollingIpQueue(L3IF *f);


#endif	// LAYER3_H



