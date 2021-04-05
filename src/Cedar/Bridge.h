// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Bridge.h
// Header of Bridge.c

#ifndef	BRIDGE_H
#define	BRIDGE_H

#include "Cedar.h"

// Constants
#define	BRIDGE_SPECIAL_IPRAW_NAME "ipv4_rawsocket_virtual_router"

// Bridge
struct BRIDGE
{
	bool Active;			// Status
	CEDAR *Cedar;			// Cedar
	HUB *Hub;				// HUB
	SESSION *Session;		// Session
	POLICY *Policy;			// Policy
	ETH *Eth;				// Ethernet
	char Name[MAX_SIZE];	// Device name
	UINT64 LastBridgeTry;	// Time to try to bridge at last
	bool Local;				// Local mode
	bool Monitor;			// Monitor mode
	bool TapMode;			// Tap mode
	bool LimitBroadcast;	// Broadcasts limiting mode
	UCHAR TapMacAddress[6];	// MAC address of the tap
	UINT LastNumDevice;		// Number of device (Number of last checked)
	UINT64 LastNumDeviceCheck;	// Time at which to check the number of devices at last
	UINT64 LastChangeMtuError;	// Time that recorded the error to change the MTU at last
	LOCALBRIDGE *ParentLocalBridge;	// Parent Local Bridge
};

// Local bridge
struct LOCALBRIDGE
{
	char HubName[MAX_HUBNAME_LEN + 1];			// Virtual HUB name
	char DeviceName[MAX_SIZE];					// Device name
	bool Local;									// Local mode
	bool Monitor;								// Monitor mode
	bool TapMode;								// Tap mode
	bool LimitBroadcast;						// Broadcast packets limiting mode
	UCHAR TapMacAddress[6];						// MAC address of the tap
	BRIDGE *Bridge;								// Bridge
};

BRIDGE *BrNewBridge(HUB *h, char *name, POLICY *p, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast, LOCALBRIDGE *parent_local_bridge);
void BrBridgeThread(THREAD *thread, void *param);
void BrFreeBridge(BRIDGE *b);
void InitLocalBridgeList(CEDAR *c);
void FreeLocalBridgeList(CEDAR *c);
void AddLocalBridge(CEDAR *c, char *hubname, char *devicename, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast);
bool DeleteLocalBridge(CEDAR *c, char *hubname, char *devicename);
bool IsBridgeSupported();
bool IsNeedWinPcap();
UINT GetEthDeviceHash();
bool IsRawIpBridgeSupported();

#endif	// BRIDGE_H



