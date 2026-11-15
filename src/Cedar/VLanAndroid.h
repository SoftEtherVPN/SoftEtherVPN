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

// Cap for the stale-queue drop at TUN handover (see VLanAndroidSetTunFd)
#define ANDROID_TUN_STALE_DRAIN_MAX		512

// IPv6 Router Solicitation driver (client side; RA/NDT tracking is in IPC.c).
//
// The 4000 ms interval is RFC 4861's MAX_RTR_SOLICITATION_INTERVAL, kept because it
// is the one pacing rule the hub also expects on the segment and it bounds the
// link-local multicast rate. The 20-try budget is the client's own patience, not the
// RFC's (which sends only three and waits for the RA's ReachableTime instead): this
// server's Router Advertisement can take far longer to arrive than the IPv4 step
// allows - a device run sent 17 solicitations and received its first RA after 67 s -
// so the budget is generous, and where the hub's answer of the previous session is
// cached it is not even a limit (VLanIPv6NeedsRouterSolicitation): solicitation just
// keeps running in the packet pump until the hub answers, because a missing answer
// must not fail a session that already has one.
#define ANDROID_IPV6_RS_MAX				20
#define ANDROID_IPV6_RS_INTERVAL_MS		4000

// Lease-keep of a reused DHCP lease (see the renewal in the pump loop). The
// interval is a third of the lease the hub granted, which is the core's own rule
// for the client side of an IPC L3 session (IPC.c:150-165), with the same 600 s
// fallback for a server that states no lease time. The floor keeps a hub
// configured with a very short lease from making this client broadcast every few
// seconds on a cellular link; the cap bounds how long the hub's lease entry may
// go unrefreshed (a hub's own DHCP default expiry is 7200 s, Nat.c:1314).
#define ANDROID_DHCP_RENEW_DEFAULT_SEC	(600 / 3)
#define ANDROID_DHCP_RENEW_MIN_SEC		60
#define ANDROID_DHCP_RENEW_MAX_SEC		3600

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

	// The hub's IPv4 answer of the previous session, seeded for this one so that a
	// reconnect can configure the NIC without running a fresh DISCOVER/REQUEST
	// exchange. Only usable together with the same inner MAC, because that is the
	// key the hub's DHCP server uses for its lease table (Virtual.c:9561-9621).
	bool HasCachedIPv4;
	IP CachedIp, CachedMask, CachedGw, CachedDns1, CachedDns2, CachedDhcpServer;
	DHCP_CLASSLESS_ROUTE_TABLE CachedRoutes;
	UCHAR CachedMac[6];
	UINT CachedLeaseSec;

	// The hub's IPv6 answer of the previous session, seeded for this one: the routed
	// prefix and mask of its Router Advertisement, the router's address and MAC (the
	// MAC that IPCIPv6SendUnicast encapsulates off-prefix frames to), and the DNS it
	// advertised. The client address is not stored because it is not a fact of its
	// own - it derives from the prefix together with this MAC (VLanIPv6SLAAC), so the
	// same prefix over the same MAC yields the byte-identical address. Nothing here
	// is owned by a session: the hub's MAC on the segment is a hash of the hub's name
	// (GenHubMacAddress, Hub.c:6870) and its RAs answer Router Solicitation
	// unreliably on this server (a device run: 17 solicitations, 67 s), so the point
	// of the cache is to skip that wait, not to carry anything per-session. Usable
	// only with the same inner MAC, as with the IPv4 cache.
	bool HasCachedIPv6;
	IP CachedV6Prefix, CachedV6Mask, CachedV6Router, CachedV6Dns;
	UCHAR CachedV6Mac[6], CachedV6RouterMac[6];
	// The flag byte of the Router Advertisement's prefix option that the cached
	// prefix came from (ICMPV6_OPTION_PREFIX_FLAG_* in TcpIp.h). It travels with the
	// prefix because the right to derive an address from a prefix is the router's and
	// is expressed only in that byte, and the cache would otherwise replay an address
	// the hub's current Router Advertisement would not have granted.
	UCHAR CachedV6PrefixFlags;
	// This session's Router Advertisements of the hub, as the core learned them
	// (IPC->IPv6RouterAdvs), plus the one entry this bridge seeded from the previous
	// session's answer (VLanIPv6SeedFromCache). SeededRA points at that entry while it
	// is still in the list and is NULL once the hub's own answer of this session has
	// taken over: that list deduplicates by prefix and never revisits a known prefix, so
	// a seed left in place would suppress this session's entry for the prefix it matches
	// and keep the cached router identity for it, and while it stands it is the entry at
	// index 0 - what IPCIPv6SendUnicast falls back to for a source address in no
	// advertised prefix (IPC.c:2665-2668). Owned here, and freed only by the code that
	// removes it from the list - the core frees every entry it added itself
	// (IPCIPv6Free, IPC.c:2159).
	IPC_IPV6_ROUTER_ADVERTISEMENT *SeededRA;

	// The lease of this session, for the lease-keep of the hub's entry (a DHCP
	// REQUEST for the current address; see ANDROID_DHCP_RENEW_* above)
	UINT DhcpLeaseSec;
	IP DhcpServer;
	UINT64 DhcpRenewNext;

	SESSION *Session;
	void *Account;				// optional Cedar ACCOUNT for server-cert verification;
								// owned by the JNI bridge, freed after ReleaseSession
};

PACKET_ADAPTER *VLanAndroidGetPacketAdapter(VLAN_ANDROID *v);
// mac_address: the profile's own inner MAC, which keeps the hub's DHCP lease and
// the MAC-derived IPv6 link-local address stable across reconnects; pass NULL to
// take a fresh random MAC for this connect.
VLAN_ANDROID *VLanAndroidNew(CEDAR *cedar, const UCHAR *mac_address);
void VLanAndroidFree(VLAN_ANDROID *v);
void VLanAndroidSetTunFd(VLAN_ANDROID *v, int fd);
void VLanAndroidSetStaticIPv4(VLAN_ANDROID *v, IP *ip, IP *mask, IP *gw, IP *dns1, IP *dns2);
// Seed the adapter with the hub's IPv4 answer of a previous session so that a
// reconnect can configure the NIC without a fresh DISCOVER/REQUEST exchange with
// the hub; call before VLanAndroidStart (the pump thread is created there).
// mac_address is the inner MAC the lease was granted to: the answer is ignored if
// it is not this adapter's MAC, because that is the key of the hub's lease table.
void VLanAndroidSetCachedIPv4(VLAN_ANDROID *v, IP *ip, IP *mask, IP *gw, IP *dns1, IP *dns2,
	DHCP_CLASSLESS_ROUTE_TABLE *routes, IP *dhcp_server, UINT lease_sec, const UCHAR *mac_address);
// Seed the adapter with the hub's IPv6 answer of a previous session - the prefix
// and mask its Router Advertisement routed, the router's address and MAC, and the
// DNS it advertised - so that a reconnect configures the NIC and sends off-prefix
// frames without waiting for this session's Router Advertisement; call before
// VLanAndroidStart(). Solicitation keeps running in the main loop either way,
// because the hub's own answer stays better than the seed and retires it when it
// arrives (VLanIPv6ReconcileSeed). mac_address is the inner MAC that answer belongs
// to - the client address derives from prefix + MAC, so the seed is ignored unless
// it is this adapter's MAC; router_mac may be NULL or zero, in which case
// off-prefix frames wait for the router MAC as they do with no answer at all.
// prefix_flags is the flag byte that came with that prefix, so that the seed does not
// grant an address the previous session only had because the router allowed it.
void VLanAndroidSetCachedIPv6(VLAN_ANDROID *v, IP *prefix, IP *mask, IP *router,
	const UCHAR *router_mac, IP *dns, UCHAR prefix_flags, const UCHAR *mac_address);
void VLanAndroidSetIPv4Enabled(VLAN_ANDROID *v, bool enabled);
void VLanAndroidSetIPv6Enabled(VLAN_ANDROID *v, bool enabled);
void VLanAndroidSetStaticIPv6(VLAN_ANDROID *v, IP *addr, IP *mask, IP *gw, IP *dns);
bool VLanAndroidStart(VLAN_ANDROID *v);
void VLanAndroidAbortDhcp(VLAN_ANDROID *v);
bool VLanAndroidIsConfigReady(VLAN_ANDROID *v);
bool VLanAndroidIsError(VLAN_ANDROID *v);
char *VLanAndroidGetErrorText(VLAN_ANDROID *v);
// lease_sec and dhcp_server are optional out-params for the lease-keep of the
// hub's entry (0 / zero IP when the hub stated no lease or the address is static)
bool VLanAndroidGetIPv4Config(VLAN_ANDROID *v, IP *ip, IP *mask, IP *gw, IP *dns1, IP *dns2,
	UINT *lease_sec, IP *dhcp_server);
// router_mac is an optional out-param (may be NULL) for the MAC that off-prefix
// frames are encapsulated to this session - the router's MAC of the Router
// Advertisement in use, or of the seed standing in for it. The JNI bridge caches it
// for the next connect's seed.
// prefix_flags is an optional out-param (may be NULL) for the flag byte of the prefix
// option that the reported prefix came from, so that the cache can carry the router's
// own ruling about that prefix (see PrefixFlags in IPC.h).
// addr is left as the unspecified address when the hub advertised no autonomous
// prefix: RFC 4861 section 4.6.2 lets a prefix route without granting an address, and
// this client has no DHCPv6 client to ask for one, so the interface keeps its
// link-local and the prefix stays usable for on-link decisions. The call still
// succeeds in that case, because the router identity it reports is real.
bool VLanAndroidGetIPv6Config(VLAN_ANDROID *v, IP *addr, IP *prefix, IP *mask, IP *router,
	UCHAR *router_mac, IP *dns, UCHAR *prefix_flags);
const UCHAR *VLanAndroidGetMacAddress(VLAN_ANDROID *v);

#endif	// UNIX_ANDROID

#endif	// VLAN_ANDROID_H
