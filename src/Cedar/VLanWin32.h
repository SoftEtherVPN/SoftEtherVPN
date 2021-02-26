// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// VLanWin32.h
// Header of VLanWin32.c

#ifndef	VLANWIN32_H
#define	VLANWIN32_H

// Routing table tracking timer
#define	TRACKING_INTERVAL_INITIAL		444		// Initial
#define	TRACKING_INTERVAL_ADD			444		// Adding value
#define	TRACKING_INTERVAL_MAX			12345	// Maximum value
#define	TRACKING_INTERVAL_MAX_RC		87654	// Maximum value (OS which change detection mechanism enabled)


typedef void *HANDLE;

// Routing tracking state machine
struct ROUTE_TRACKING
{
	UINT VLanInterfaceId;
	ROUTE_ENTRY *RouteToServer;
	bool RouteToServerAlreadyExists;
	ROUTE_ENTRY *DefaultGatewayByVLan;
	ROUTE_ENTRY *VistaDefaultGateway1, *VistaDefaultGateway2, *VistaOldDefaultGatewayByVLan;
	ROUTE_ENTRY *RouteToDefaultDns;
	ROUTE_ENTRY *RouteToEight;
	ROUTE_ENTRY *RouteToNatTServer;
	ROUTE_ENTRY *RouteToRealServerGlobal;
	UINT64 NextTrackingTime;
	UINT64 NextTrackingTimeAdd;
	UINT64 NextRouteChangeCheckTime;
	UINT LastRoutingTableHash;
	QUEUE *DeletedDefaultGateway;
	UINT OldDefaultGatewayMetric;
	IP OldDnsServer;
	bool VistaAndUsingPPP;
	ROUTE_CHANGE *RouteChange;
};

// VLAN structure
struct VLAN
{
	volatile bool Halt;			// Halting flag
	bool Win9xMode;				// Windows 9x
	char *InstanceName;			// Instance name
	char *DeviceNameWin32;		// Win32 device name
	char *EventNameWin32;		// Win32 event name
	HANDLE Handle;				// Device driver file
	HANDLE Event;				// Handle of the event
	void *GetBuffer;			// Sent packet capturing buffer
	UINT CurrentPacketCount;	// Packet number to be read next
	void *PutBuffer;			// Buffer for writing received packet
	ROUTE_TRACKING *RouteState;	// Routing tracking state machine
};

// Instance list
struct INSTANCE_LIST
{
	UINT NumInstance;
	char **InstanceName;
};


// Function prototype
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param);
void FreeVLan(VLAN *v);
CANCEL *VLanGetCancel(VLAN *v);
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size);
bool VLanGetPacketsFromDriver(VLAN *v);
bool VLanPutPacketsToDriver(VLAN *v);
bool VLanPutPacket(VLAN *v, void *buf, UINT size);

PACKET_ADAPTER *VLanGetPacketAdapter();
bool VLanPaInit(SESSION *s);
CANCEL *VLanPaGetCancel(SESSION *s);
UINT VLanPaGetNextPacket(SESSION *s, void **data);
bool VLanPaPutPacket(SESSION *s, void *data, UINT size);
void VLanPaFree(SESSION *s);

INSTANCE_LIST *GetInstanceList();
void FreeInstanceList(INSTANCE_LIST *n);
UINT GetInstanceId(char *name);

void RouteTrackingStart(SESSION *s);
void RouteTrackingStop(SESSION *s, ROUTE_TRACKING *t);
void RouteTrackingMain(SESSION *s);
void Win32ReleaseAllDhcp9x(bool wait);

void Win32GetWinVer(RPC_WINVER *v);

#endif	// VLANWIN32_H
