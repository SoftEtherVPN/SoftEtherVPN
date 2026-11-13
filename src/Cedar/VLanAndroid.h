// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module

// VLanAndroid.h
// Packet adapter for the Android VpnService (L3 TUN) virtual NIC

#ifndef	VLAN_ANDROID_H
#define	VLAN_ANDROID_H

#ifdef UNIX_ANDROID

#include "Cedar.h"
#include "Session.h"
#include "IPC.h"

#include "Mayaqua/Network.h"
#include "Mayaqua/TcpIp.h"

#define ANDROID_GETNEXT_TIMEOUT_MS		10
#define ANDROID_TUN_READ_BUF			2048
#define ANDROID_TUN_DRAIN_PKTS			128
#define ANDROID_TUN_DRAIN_BYTES			(128 * 1024)

// IPv6 Router Solicitation driver (client side; RA/NDT tracking is in IPC.c)
#define ANDROID_IPV6_RS_MAX				20
#define ANDROID_IPV6_RS_INTERVAL_MS		4000

typedef struct VLAN_ANDROID VLAN_ANDROID;

// Android VpnService virtual NIC state
struct VLAN_ANDROID
{
	IPC *Ipc;
	SOCK *Sock;
	TUBE *TubeToIpc;			// hub -> device (written by PaPutPacket, popped by IPC)
	TUBE *TubeFromIpc;			// device -> hub (pushed by IPCSendL2, popped by PaGetNextPacket)

	TUBE *DhcpHaltTube;			// polled by IPCDhcpAllocateIP; TubeDisconnect on it aborts the wait
	TUBE *DhcpHaltPeer;			// the other end of the halt-notify pair, disconnected together

	int TunFd;					// TUN fd supplied by VpnService (-1: not yet)
	THREAD *Thread;
	volatile bool Halt;
	volatile bool ConfigOk;		// IPv4 configuration completed
	volatile bool ErrorOccured;	// Configuration error
	char *ErrorMsg;

	bool StaticMode;
	IP StaticIp, StaticMask, StaticGw, StaticDns1, StaticDns2;

	bool Ipv4Enabled;
	bool Ipv6Enabled;

	bool Ipv6StaticMode;
	IP Ipv6StaticAddr, Ipv6StaticMask, Ipv6StaticGw, Ipv6StaticDns;

	// IPv6 Router Solicitation pacing gate (runs in parallel with the IPv4
	// DHCP acquisition)
	volatile bool Ipv6Configuring;	// RA acquisition window is active
	volatile bool Ipv6GateStop;		// stop request for the gate thread
	THREAD *Ipv6GateThread;
	UINT Ipv6RsTries;				// RS sent so far (shared with the main loop)
	UINT64 Ipv6RsNext;				// Tick64() of the next RS

	UCHAR MacAddress[6];
	IP ConfigIp, ConfigMask, ConfigGw, ConfigDns1, ConfigDns2;
	DHCP_CLASSLESS_ROUTE_TABLE ClasslessRoute;

	SESSION *Session;
	void *Account;				// optional Cedar ACCOUNT for server-cert verification;
								// owned by the JNI bridge, freed after ReleaseSession
};

PACKET_ADAPTER *VLanAndroidGetPacketAdapter(VLAN_ANDROID *v);
VLAN_ANDROID *VLanAndroidNew(CEDAR *cedar);
void VLanAndroidFree(VLAN_ANDROID *v);
void VLanAndroidSetTunFd(VLAN_ANDROID *v, int fd);
void VLanAndroidSetStaticIPv4(VLAN_ANDROID *v, IP *ip, IP *mask, IP *gw, IP *dns1, IP *dns2);
void VLanAndroidSetIPv4Enabled(VLAN_ANDROID *v, bool enabled);
void VLanAndroidSetIPv6Enabled(VLAN_ANDROID *v, bool enabled);
void VLanAndroidSetStaticIPv6(VLAN_ANDROID *v, IP *addr, IP *mask, IP *gw, IP *dns);
bool VLanAndroidStart(VLAN_ANDROID *v);
void VLanAndroidAbortDhcp(VLAN_ANDROID *v);
bool VLanAndroidIsConfigReady(VLAN_ANDROID *v);
bool VLanAndroidIsError(VLAN_ANDROID *v);
char *VLanAndroidGetErrorText(VLAN_ANDROID *v);
bool VLanAndroidGetIPv4Config(VLAN_ANDROID *v, IP *ip, IP *mask, IP *gw, IP *dns1, IP *dns2);
bool VLanAndroidGetIPv6Config(VLAN_ANDROID *v, IP *addr, IP *prefix, IP *mask, IP *router, IP *dns);
const UCHAR *VLanAndroidGetMacAddress(VLAN_ANDROID *v);

#endif	// UNIX_ANDROID

#endif	// VLAN_ANDROID_H
