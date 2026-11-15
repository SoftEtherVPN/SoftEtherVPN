// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module

// VLanAndroid.c
// Packet adapter for the Android VpnService (L3 TUN) virtual NIC.
// The TUN file descriptor is supplied by the Java VpnService. An in-process
// socket over a tube pair is bridged to the IPC (L2) engine, so that the
// SoftEther hub's Ethernet segment is converted to IPv4 by the built-in
// ARP / DHCP / IPv6 ND machinery of IPC.c.

#ifdef UNIX_ANDROID
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#endif // UNIX_ANDROID

#include "VLanAndroid.h"

#include "Connection.h"

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Tick64.h"

#ifdef UNIX_ANDROID


// Prototypes
static void VLanSetError(VLAN_ANDROID *v, char *msg);
static VLAN_ANDROID *VLanAndroidGetParam(SESSION *s);
static void VLanAndroidThread(THREAD *thread, void *param);
static void VLanIPv6GateThread(THREAD *thread, void *param);
static UINT VLanDhcpRenewIntervalSec(VLAN_ANDROID *v);
static bool VLanIPv6CachedUsable(VLAN_ANDROID *v);
static bool VLanIPv6HasAddressGrantingAnswer(VLAN_ANDROID *v);
static bool VLanIPv6NeedsRouterSolicitation(VLAN_ANDROID *v);
static void VLanIPv6InitClientEUI(VLAN_ANDROID *v);
static void VLanIPv6SeedFromCache(VLAN_ANDROID *v);
static void VLanIPv6ReconcileSeed(VLAN_ANDROID *v);
static bool VLanIPv6AutonomousPrefix(const IPC_IPV6_ROUTER_ADVERTISEMENT *ra);
static IPC_IPV6_ROUTER_ADVERTISEMENT *VLanIPv6AddressEntry(VLAN_ANDROID *v);
static void VLanIPv6SLAAC(VLAN_ANDROID *v, IP *prefix, IP *addr);

static void VLanSetError(VLAN_ANDROID *v, char *msg)
{
	if (v == NULL)
	{
		return;
	}

	Free(v->ErrorMsg);
	v->ErrorMsg = CopyStr(msg);
	v->ErrorOccured = true;
}

// Interval of the lease-keep REQUEST for the hub's entry (see ANDROID_DHCP_RENEW_*
// in the header): a third of the lease the hub granted, floored and capped so
// that neither a short-lease hub nor a long-lease one decides the cadence alone.
static UINT VLanDhcpRenewIntervalSec(VLAN_ANDROID *v)
{
	UINT sec = (v != NULL && v->DhcpLeaseSec > 0) ?
		(v->DhcpLeaseSec / 3) : ANDROID_DHCP_RENEW_DEFAULT_SEC;

	return MAX(ANDROID_DHCP_RENEW_MIN_SEC, MIN(ANDROID_DHCP_RENEW_MAX_SEC, sec));
}

// Whether the hub's IPv6 answer of a previous session may stand in for this
// session's: it must be present, and it must belong to this adapter's MAC, because
// the client address derives from the cached prefix together with that MAC
// (VLanIPv6SLAAC). Everything that decides "the hub's last IPv6 answer is ours"
// goes through here, so the Router Advertisement wait, the Router Solicitation
// budget and the seed cannot drift apart.
static bool VLanIPv6CachedUsable(VLAN_ANDROID *v)
{
	return (v != NULL && v->HasCachedIPv6 &&
			Cmp(v->MacAddress, v->CachedV6Mac, 6) == 0);
}

// Whether this session has an answer from the hub that can grant an address: a Router
// Advertisement arrived as a frame and one of its prefixes carries the autonomous bit.
// The entry seeded from the previous session is deliberately excluded - it is this
// bridge's placeholder, not the hub's answer of this session, and identity is by
// pointer because this bridge made that one entry and no one else can (SeededRA is NULL
// once it has been retired, and then every entry of the list is the hub's own).
//
// The autonomous bit is part of this predicate rather than a detail of it because a
// Router Advertisement of this hub's upstream arrives in more than one frame and a
// session can learn the route prefixes without learning the address-granting one
// (device, a reconnect: 2 entry(s) 2001:470:2099:1::=L, 2001:470:2099:2::=L and no
// autonomous entry for the rest of the session), so "the hub answered" is not enough to
// stop soliciting or to retire the cached answer - only an answer that can grant an
// address is.
static bool VLanIPv6HasAddressGrantingAnswer(VLAN_ANDROID *v)
{
	UINT i;

	if (v == NULL || v->Ipc == NULL || v->Ipc->IPv6RouterAdvs == NULL)
	{
		return false;
	}

	for (i = 0; i < LIST_NUM(v->Ipc->IPv6RouterAdvs); i++)
	{
		IPC_IPV6_ROUTER_ADVERTISEMENT *ra = LIST_DATA(v->Ipc->IPv6RouterAdvs, i);

		if (ra != NULL && ra != v->SeededRA && VLanIPv6AutonomousPrefix(ra))
		{
			return true;
		}
	}

	return false;
}

// Whether Router Solicitation still has to be paced: this session has no answer of the
// hub that can grant an address. While a cached answer stands in, the ANDROID_IPV6_RS_MAX
// budget does not stop it - this hub's first answer can take many retries (device:
// 17 solicitations at 4 s each) and one link-local multicast per interval is free,
// so asking until the hub supplies an address-granting prefix. With no cached answer the
// budget ends in the fatal "no router advertisement" error, so pacing may stop.
static bool VLanIPv6NeedsRouterSolicitation(VLAN_ANDROID *v)
{
	if (VLanIPv6HasAddressGrantingAnswer(v))
	{
		return false;
	}

	if (v == NULL || v->Ipc == NULL)
	{
		return false;
	}

	if (LIST_NUM(v->Ipc->IPv6RouterAdvs) > 0)
	{
		return true;
	}

	return v->Ipv6RsTries < ANDROID_IPV6_RS_MAX;
}

// Set the EUI-64 that the core's IPv6 auto-configuration state machine derives the
// client's link-local address from, which is also the source address of its Router
// Solicitation: IPCSendIPv6RouterSoliciation returns without sending anything when
// the field is zero. Nothing else sets it for a bridged adapter - the field's only
// other producer is PPP's IPv6CP option (Proto_PPP.c:2302), a path this transport
// does not run - so on Android the value stayed zero, every Router Solicitation was
// silently skipped, and the hub's tap saw none at all (server: "tcpdump -i tap_vpn0
// shows no router solicitations"), which left only the router's own periodic Router
// Advertisement to be caught - the 19-67 s wait measured on device.
static void VLanIPv6InitClientEUI(VLAN_ANDROID *v)
{
	UCHAR eui[8];
	IP link_local;
	char str[MAX_SIZE];

	if (v == NULL || v->Ipc == NULL)
	{
		return;
	}

	GenerateEui64Address6(eui, v->MacAddress);

	// IPC.c builds the address as fe80:: plus the raw memory bytes of this field
	// (Copy(&linkLocal.Value[8], &ipc->IPv6ClientEUI, 8)), so the eight bytes go in in
	// that order. The PPP path fills the same field with the big-endian READ_UINT64 of
	// the option, which on a little-endian host reverses them - and since no code in
	// this tree ever assigns IPv6ServerEUI, there is no other convention to match than
	// the copy above.
	Copy(&v->Ipc->IPv6ClientEUI, eui, sizeof(UINT64));

	GenerateEui64LocalAddress(&link_local, v->MacAddress);

	str[0] = 0;
	IPToStr6(str, sizeof(str), &link_local);

	Debug("VLanAndroid: our IPv6 link-local address is %s (Router Solicitation is sent from it)\n", str);
}

// Put the hub's IPv6 answer of the previous session into this session's list of
// Router Advertisements so that the interface inputs are known and off-prefix frames
// already have a router MAC at the first frame, instead of waiting for this session's
// answer, which on this hub can take a minute. The answer is a placeholder and stays
// one: solicitation keeps running (VLanIPv6NeedsRouterSolicitation) and the hub's own
// first Router Advertisement retires this entry (VLanIPv6ReconcileSeed), so a seed
// that has gone stale is corrected rather than trusted. Must be called after the
// adapter's MAC is known.
static void VLanIPv6SeedFromCache(VLAN_ANDROID *v)
{
	IPC_IPV6_ROUTER_ADVERTISEMENT *ra;
	IP client;
	char pfx_str[MAX_SIZE], mask_str[MAX_SIZE], cli_str[MAX_SIZE], rt_str[MAX_SIZE], mac_str[MAX_SIZE];

	if (v == NULL || v->Ipc == NULL || v->Ipc->IPv6RouterAdvs == NULL ||
		LIST_NUM(v->Ipc->IPv6RouterAdvs) > 0 || !VLanIPv6CachedUsable(v))
	{
		return;
	}

	ra = Malloc(sizeof(IPC_IPV6_ROUTER_ADVERTISEMENT));

	CopyIP(&ra->RoutedPrefix, &v->CachedV6Prefix);
	CopyIP(&ra->RoutedMask, &v->CachedV6Mask);
	CopyIP(&ra->RouterAddress, &v->CachedV6Router);

	// Both MAC fields of the core's entry get the cached router MAC, because
	// IPCIPv6SendUnicast prefers RouterMacAddress and falls back to
	// RouterLinkLayerAddress only if that is not a usable unicast address.
	Copy(ra->RouterMacAddress, v->CachedV6RouterMac, 6);
	Copy(ra->RouterLinkLayerAddress, v->CachedV6RouterMac, 6);

	// Carry the router's own ruling about this prefix across the session boundary, so
	// that the seed cannot grant an address the hub would not grant now.
	ra->PrefixFlags = v->CachedV6PrefixFlags;

	Add(v->Ipc->IPv6RouterAdvs, ra);

	// This bridge owns this entry and no one else: the core frees only the entries it
	// added itself (IPCIPv6Free, IPC.c:2159).
	v->SeededRA = ra;

	Zero(&client, sizeof(client));
	cli_str[0] = 0;

	if (VLanIPv6AutonomousPrefix(ra))
	{
		VLanIPv6SLAAC(v, &v->CachedV6Prefix, &client);

		IPToStr6(cli_str, sizeof(cli_str), &client);
	}

	pfx_str[0] = mask_str[0] = rt_str[0] = mac_str[0] = 0;

	IPToStr6(pfx_str, sizeof(pfx_str), &v->CachedV6Prefix);
	IPToStr6(mask_str, sizeof(mask_str), &v->CachedV6Mask);
	IPToStr6(rt_str, sizeof(rt_str), &v->CachedV6Router);
	MacToStr(mac_str, sizeof(mac_str), v->CachedV6RouterMac);

	Debug("VLanAndroid: reusing the hub's IPv6: prefix %s mask %s, our address %s, router %s, "
		"router MAC %s, prefix flags 0x%02X\n", pfx_str, mask_str,
		(cli_str[0] != 0) ? cli_str : "-", rt_str, mac_str,
		(UINT)ra->PrefixFlags);
}

// Retire the entry seeded from the previous session's answer once this session has a
// Router Advertisement entry of the hub's that can grant an address, i.e. one carrying
// the autonomous bit (VLanIPv6HasAddressGrantingAnswer). Retiring it rather than keeping
// it alongside is a property of the core's list: IPCIPv6AddRouterPrefixes deduplicates by
// prefix and never revisits a known prefix (IPC.c), so a seed whose prefix the hub
// advertises again suppresses this session's entry for it, and while it stands the seed
// is also the entry at index 0 - the one IPCIPv6SendUnicast falls back to when the
// packet's source address belongs to no advertised prefix (IPC.c:2665-2668).
//
// The address-granting condition, and not "the hub answered at all", is what the
// retirement waits for: a hub prefix change arrives with a prefix of its own that grants
// the address (device, before this was fixed: a prefix change came back as the old
// prefix), whereas an answer of route prefixes only has nothing to take the seed's place.
// In that case the seed keeps the address until the hub supplies an answer that can
// (vc59; device, a reconnect: 2001:470:2099:1:: and 2001:470:2099:2:: with no
// address-granting prefix for the rest of the session).
static void VLanIPv6ReconcileSeed(VLAN_ANDROID *v)
{
	UINT i;

	if (v == NULL || v->SeededRA == NULL || v->Ipc == NULL || v->Ipc->IPv6RouterAdvs == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(v->Ipc->IPv6RouterAdvs); i++)
	{
		IPC_IPV6_ROUTER_ADVERTISEMENT *ra = LIST_DATA(v->Ipc->IPv6RouterAdvs, i);

		// A live entry that can grant an address: this dial has the hub's answer of
		// the kind the seed was standing in for, so the placeholder is stale by
		// definition - including the prefix-change case, whose new prefix comes with
		// the autonomous bit that grants this client's address.
		if (ra != NULL && ra != v->SeededRA && VLanIPv6AutonomousPrefix(ra))
		{
			Delete(v->Ipc->IPv6RouterAdvs, v->SeededRA);
			Free(v->SeededRA);
			v->SeededRA = NULL;

			Debug("VLanAndroid: the hub's Router Advertisement of this session replaced the "
				"answer cached from the previous session\n");

			return;
		}
	}

	// Reached when the hub answered for this session but with route prefixes only (or
	// not at all). Keeping the seed is the correction rather than the bug: it is the
	// only address-granting prefix this session has, and dropping it cost the client its
	// IPv6 address for the whole session (device, a reconnect: 2 entry(s)
	// 2001:470:2099:1::=L, 2001:470:2099:2::=L and no autonomous prefix thereafter,
	// address reported empty from then on). Solicitation continues in that case
	// (VLanIPv6NeedsRouterSolicitation), so the hub's address-granting prefix is still
	// chased and retires the seed the moment it arrives.
}

// Whether an address may be formed from this entry's prefix. RFC 4861 section 4.6.2
// makes that the router's decision, carried in the prefix option's flag byte (the
// ICMPV6_OPTION_PREFIX_FLAG_AUTO bit), and the core records it per entry
// (PrefixFlags, IPC.h) without judging it - a prefix without that bit is still valid
// for on-link determination (section 5.5.6), which is what the core's own consumers of
// this list use it for (IPCIPv6CheckUnicastFromRouterPrefix, IPC.c:2435).
static bool VLanIPv6AutonomousPrefix(const IPC_IPV6_ROUTER_ADVERTISEMENT *ra)
{
	return ra != NULL && (ra->PrefixFlags & ICMPV6_OPTION_PREFIX_FLAG_AUTO) != 0;
}

// The entry to take this client's address from: the first of the hub's prefixes that
// it authorised for autonomous address configuration, since a Router Advertisement may
// advertise up to ICMPV6_OPTION_PREFIXES_MAX_COUNT prefixes and only some of them carry
// the autonomous bit - this hub's Router Advertisement carries three prefixes and the
// hub's configuration grants address configuration to one of them, which the device
// confirms: two of them appear as prefix routes only, while addresses (ours and the
// kernel's) form on the third. Falling back to no entry - rather than to the first
// prefix of the list - is what keeps an address from being invented for a prefix the
// router offered for routing alone; VLanAndroidGetIPv6Config then reports the first
// entry's router identity instead, which is what the core falls back to as well.
static IPC_IPV6_ROUTER_ADVERTISEMENT *VLanIPv6AddressEntry(VLAN_ANDROID *v)
{
	UINT i;

	if (v == NULL || v->Ipc == NULL || v->Ipc->IPv6RouterAdvs == NULL)
	{
		return NULL;
	}

	for (i = 0; i < LIST_NUM(v->Ipc->IPv6RouterAdvs); i++)
	{
		IPC_IPV6_ROUTER_ADVERTISEMENT *ra = LIST_DATA(v->Ipc->IPv6RouterAdvs, i);

		if (VLanIPv6AutonomousPrefix(ra))
		{
			return ra;
		}
	}

	return NULL;
}

// Get the VLAN_ANDROID pointer from a session
static VLAN_ANDROID *VLanAndroidGetParam(SESSION *s)
{
	if (s == NULL || s->PacketAdapter == NULL)
	{
		return NULL;
	}

	return (VLAN_ANDROID *)s->PacketAdapter->Param;
}

// Initialization of the packet adapter
bool VLanAndroidPaInit(SESSION *s)
{
	// The adapter and its IPC object are created by VLanAndroidNew(), and
	// the SESSION pointer is bound by the JNI layer before the session
	// thread starts.
	if (s == NULL || s->PacketAdapter == NULL || s->PacketAdapter->Param == NULL)
	{
		return false;
	}

	return true;
}

// Get the cancel object
CANCEL *VLanAndroidPaGetCancel(SESSION *s)
{
	return NewCancel();
}

// Get the next packet from the hub side (device RX)
UINT VLanAndroidPaGetNextPacket(SESSION *s, void **data)
{
	VLAN_ANDROID *v;
	TUBEDATA *d;
	void *buf;
	UINT size;

	if (s == NULL || data == NULL)
	{
		return INFINITE;
	}

	v = VLanAndroidGetParam(s);
	if (v == NULL)
	{
		return INFINITE;
	}

	d = TubeRecvSync(v->TubeFromIpc, ANDROID_GETNEXT_TIMEOUT_MS);

	if (d == NULL)
	{
		// No packet (also on tube disconnect: the session checks the
		// connection state separately)
		*data = NULL;

		return 0;
	}

	buf = Malloc(d->DataSize);
	Copy(buf, d->Data, d->DataSize);

	*data = buf;

	size = d->DataSize;

	FreeTubeData(d);

	return size;
}

// Send a packet to the hub side (device TX)
bool VLanAndroidPaPutPacket(SESSION *s, void *data, UINT size)
{
	VLAN_ANDROID *v;

	if (s == NULL)
	{
		Free(data);

		return false;
	}

	v = VLanAndroidGetParam(s);

	if (v == NULL || data == NULL || size == 0)
	{
		// Flush
		Free(data);

		return true;
	}

	TubeSendEx(v->TubeToIpc, data, size, NULL, false);

	Free(data);

	return true;
}

// Free of the packet adapter (the tubes and the IPC are freed by
// VLanAndroidFree())
void VLanAndroidPaFree(SESSION *s)
{
}

// IPv6 Router Solicitation pacing thread: sends one Router Solicitation
// every ANDROID_IPV6_RS_INTERVAL_MS until the hub segment's router answers
// with at least one prefix, the RS budget is exhausted, or the gate is
// stopped. Only the non-blocking RS sender is called here (a tube write plus
// constant EUI/MAC reads), so it is safe while the main thread runs the IPC
// pumps (the DHCP request loop in IPC.c pumps IPCProcessL3Events on every
// pass and consumes the Router Advertisements); a second concurrent
// IPCProcessL3Events pump from this thread is what must be avoided.
static void VLanIPv6GateThread(THREAD *thread, void *param)
{
	VLAN_ANDROID *v = (VLAN_ANDROID *)param;
	UINT64 next = 0;

	if (v == NULL)
	{
		return;
	}

	while (!v->Halt && !v->Ipv6GateStop && !v->ErrorOccured)
	{
		if (v->Session != NULL && (v->Session->Halt || v->Session->ForceStopFlag))
		{
			break;
		}

		// Stop once the pacing budget is spent with no cached answer to stand in
		// for the hub. Whether the hub has answered is judged by the main thread's
		// pump, not here: this thread must stay off the list of Router
		// Advertisements because the main thread's IPCProcessL3Events passes add to
		// it concurrently, and a seeded entry is in it from the first moment of a
		// reconnect. Solicitation that continues a few seconds past an early answer
		// is a harmless link-local multicast.
		if (v->Ipv6RsTries >= ANDROID_IPV6_RS_MAX && !VLanIPv6CachedUsable(v))
		{
			break;
		}

		if (Tick64() >= next)
		{
			IPCSendIPv6RouterSoliciation(v->Ipc, false);

			v->Ipv6RsTries++;
			next = Tick64() + ANDROID_IPV6_RS_INTERVAL_MS;

			Debug("VLanAndroid: sending IPv6 Router Solicitation %u/%u\n",
				v->Ipv6RsTries, ANDROID_IPV6_RS_MAX);
		}

		SleepThread(100);
	}

	// Hand the pacing state over to the main loop's RS block so that it can
	// continue where we left (late/unsolicited RAs are still consumed by the
	// loop's IPCProcessL3Events passes).
	v->Ipv6RsNext = next;
}

// Stop and join the IPv6 pacing gate thread (idempotent)
static void VLanStopIpv6Gate(VLAN_ANDROID *v)
{
	if (v == NULL)
	{
		return;
	}

	v->Ipv6GateStop = true;

	if (v->Ipv6GateThread != NULL)
	{
		WaitThread(v->Ipv6GateThread, INFINITE);
		ReleaseThread(v->Ipv6GateThread);
		v->Ipv6GateThread = NULL;
	}
}

// Start thread (the session setup thread)
static void VLanAndroidThread(THREAD *thread, void *param)
{
	VLAN_ANDROID *v = (VLAN_ANDROID *)param;
	SESSION *s;
	DHCP_OPTION_LIST *opt;
	bool ret;

	if (v == NULL)
	{
		return;
	}

	s = v->Session;

	// Wait until the L2 connection to the hub is established. The session
	// thread owns the connect/login retries (NumRetry/RetryInterval) and its
	// own timeouts; just track when it gives up. The Kotlin side enforces an
	// overall deadline.
	while (true)
	{
		if (v->Halt)
		{
			VLanSetError(v, "The connection to the server was lost.");
			return;
		}

		if (s->ConnectSucceed)
		{
			break;
		}

		if (s->ForceStopFlag || s->ClientStatus == CLIENT_STATUS_IDLE ||
			(s->Halt && !s->RetryFlag))
		{
			// The session gave up (or is about to); the session's own error
			// value provides the status text.
			return;
		}

		SleepThread(100);
	}

	// The core's IPv6 auto-configuration keys the client's link-local address, and
	// with it the Router Solicitation, on the EUI-64 of this adapter's MAC.
	if (v->Ipv6Enabled)
	{
		VLanIPv6InitClientEUI(v);
	}

	// Open the IPv6 state machine early so that Router Advertisement and ND
	// processing is active while the IPv4 acquisition below runs: the DHCP
	// request loop in IPC.c pumps IPCProcessL3Events on every pass, which
	// also learns RA prefixes into the IPv6RouterAdvs list.
	if (v->Ipv6Enabled)
	{
		IPC_PROTO_SET_STATUS(v->Ipc, IPv6State, IPC_PROTO_STATUS_OPENED);
	}

	// Reconnect: put the hub's IPv6 answer of the previous session into this
	// session's list so that the interface inputs and the router MAC for
	// off-prefix frames exist from here on, before anything can ask for them.
	if (v->Ipv6Enabled && v->Ipv6StaticMode == false)
	{
		VLanIPv6SeedFromCache(v);
	}

	// Drive Router Solicitations from a pacing thread so that the RA window
	// overlaps with the (blocking) DHCP acquisition below instead of running
	// serially after it.
	if (v->Ipv6Enabled && v->Ipv6StaticMode == false)
	{
		v->Ipv6Configuring = true;

		v->Ipv6GateThread = NewThread(VLanIPv6GateThread, v);
	}

	// Configure the L3 parameters of the IPC
	if (v->Ipv4Enabled)
	{
		if (v->StaticMode)
		{
			IPCSetIPv4Parameters(v->Ipc, &v->StaticIp, &v->StaticMask,
				IsZeroIP(&v->StaticGw) ? NULL : &v->StaticGw, NULL);

			Copy(v->ConfigIp.address, v->StaticIp.address, 16);
			Copy(v->ConfigMask.address, v->StaticMask.address, 16);
			Copy(v->ConfigGw.address, v->StaticGw.address, 16);
			Copy(v->ConfigDns1.address, v->StaticDns1.address, 16);
			Copy(v->ConfigDns2.address, v->StaticDns2.address, 16);

			ret = true;
		}
		else
		{
			opt = ZeroMalloc(sizeof(DHCP_OPTION_LIST));

			if (v->HasCachedIPv4 && Cmp(v->MacAddress, v->CachedMac, 6) == 0)
			{
				// Reconnect over the same inner MAC: the address below is the hub's own
				// answer for that MAC and the interface is unchanged, so configure from
				// it and skip the two round trips of IPCDhcpAllocateIP. Nothing has been
				// *asked* of the hub though, and the hub's built-in DHCP creates its
				// lease entry only on a DHCP REQUEST (Virtual.c:9584-9621), so the pump
				// loop below keeps that entry alive instead.
				opt->ClientAddress = IPToUINT(&v->CachedIp);
				opt->SubnetMask = IPToUINT(&v->CachedMask);
				opt->Gateway = IPToUINT(&v->CachedGw);
				opt->DnsServer = IPToUINT(&v->CachedDns1);
				opt->DnsServer2 = IPToUINT(&v->CachedDns2);
				opt->ServerAddress = IPToUINT(&v->CachedDhcpServer);
				opt->LeaseTime = v->CachedLeaseSec;
				Copy(&opt->ClasslessRoute, &v->CachedRoutes, sizeof(DHCP_CLASSLESS_ROUTE_TABLE));

				ret = true;

				{
					char ipstr[MAX_SIZE];

					ipstr[0] = 0;
					IPToStr(ipstr, sizeof(ipstr), &v->CachedIp);

					Debug("VLanAndroid: reusing the hub's IPv4 lease %s (no DHCP exchange)\n",
						ipstr);
				}
			}
			else
			{
				ret = IPCDhcpAllocateIP(v->Ipc, opt, v->DhcpHaltTube);
			}

			if (ret)
			{
				IP ip, mask, gw;

				UINTToIP(&ip, opt->ClientAddress);
				UINTToIP(&mask, opt->SubnetMask);
				UINTToIP(&gw, opt->Gateway);

				IPCSetIPv4Parameters(v->Ipc, &ip, &mask,
					IsZeroIP(&gw) ? NULL : &gw,
					(opt->ClasslessRoute.NumExistingRoutes > 0) ? &opt->ClasslessRoute : NULL);

				Copy(v->ConfigIp.address, ip.address, 16);
				Copy(v->ConfigMask.address, mask.address, 16);
				Copy(v->ConfigGw.address, gw.address, 16);

				if (opt->DnsServer != 0)
				{
					IP dns;

					UINTToIP(&dns, opt->DnsServer);
					Copy(v->ConfigDns1.address, dns.address, 16);
				}

				if (opt->DnsServer2 != 0)
				{
					IP dns;

					UINTToIP(&dns, opt->DnsServer2);
					Copy(v->ConfigDns2.address, dns.address, 16);
				}

				v->ClasslessRoute = opt->ClasslessRoute;

				// The hub's lease entry for this MAC is created by the REQUEST of a real
				// exchange, and must be refreshed by us when the exchange was skipped;
				// remember what the hub granted so that the pump can do that in time.
				v->DhcpLeaseSec = opt->LeaseTime;
				UINTToIP(&v->DhcpServer, opt->ServerAddress);

				// No server address means there is nothing to unicast a renewal to
				v->DhcpRenewNext = IsZeroIP(&v->DhcpServer) ? 0 :
					Tick64() + (UINT64)VLanDhcpRenewIntervalSec(v) * 1000;
			}
			else
			{
				Free(opt);
			}

			if (!ret)
			{
				VLanStopIpv6Gate(v);

				// "false" is also returned when the user aborted the wait via the halt tube
				if (IsTubeConnected(v->DhcpHaltTube))
				{
					VLanSetError(v, "No DHCP server responded on this hub. The hub's virtual "
						"LAN has no DHCP server: enable one, or switch to Static IPv4 in the "
						"connection settings.");
				}

				return;
			}

			Free(opt);
		}
	}

	if (v->Ipv4Enabled)
	{
		IPC_PROTO_SET_STATUS(v->Ipc, IPv4State, IPC_PROTO_STATUS_OPENED);
	}

	// Stop and join the Router Solicitation pacing thread; if the hub
	// segment's router answered within the window, the prefix is already in
	// IPC.c's IPv6RouterAdvs list (learned by the pumps running meanwhile:
	// the DHCP request loop and, for static IPv4, the pump below). In IPv6
	// static mode no gate was started; the kernel configures the interface
	// itself from the parameters set over JNI.
	VLanStopIpv6Gate(v);

	if (v->Ipv6Enabled && v->Ipv6StaticMode == false)
	{
		// Wait for the hub's answer for this session only while we have no answer of
		// our own: with the previous session's answer seeded above, the client
		// address derives from that prefix and this MAC and the router's MAC is
		// seeded, so the list is not empty and this loop does not run at all. On this
		// hub that wait is the expensive part of a reconnect - one device run sent 17
		// Router Solicitations at 4 s each and waited 67 s for the Router
		// Advertisement - and an answer that is slow must not hold up, let alone
		// fail, a session that already has one. Solicitation continues in the main
		// loop below and is not limited to the budget there, so the seed gets
		// confirmed by the hub when it can be (IPCIPv6SeedFromCache).
		while (LIST_NUM(v->Ipc->IPv6RouterAdvs) == 0 &&
			v->Ipv6RsTries < ANDROID_IPV6_RS_MAX)
		{
			if (v->Halt || s->Halt || s->ForceStopFlag)
			{
				break;
			}

			IPCProcessL3EventsEx(v->Ipc, Tick64());

			if (LIST_NUM(v->Ipc->IPv6RouterAdvs) == 0 && Tick64() >= v->Ipv6RsNext)
			{
				IPCSendIPv6RouterSoliciation(v->Ipc, false);

				v->Ipv6RsTries++;
				v->Ipv6RsNext = Tick64() + ANDROID_IPV6_RS_INTERVAL_MS;

				Debug("VLanAndroid: sending IPv6 Router Solicitation %u/%u\n",
					v->Ipv6RsTries, ANDROID_IPV6_RS_MAX);
			}

			SleepThread(100);
		}

		// Process the queued frames one last time before judging
		IPCProcessL3EventsEx(v->Ipc, Tick64());

		if (v->Halt || s->Halt || s->ForceStopFlag)
		{
			v->Ipv6Configuring = false;

			VLanSetError(v, "The connection to the server was lost.");
			return;
		}

		// Nothing to configure the interface from: no answer from the hub within the
		// window and no answer of the previous session to seed. That is fatal only in
		// this case - with a seed, the session stands on its own and the hub's answer
		// is adopted later or never, both of which are survivable.
		if (LIST_NUM(v->Ipc->IPv6RouterAdvs) == 0)
		{
			v->Ipv6Configuring = false;

			VLanSetError(v, "No IPv6 router advertisement received on this hub. "
				"Set a static IPv6 address in the connection settings, or disable "
				"IPv6 for this connection.");
			return;
		}
	}

	if (v->Ipv6Enabled)
	{
		v->Ipv6Configuring = false;
	}

	v->ConfigOk = true;

	// Main data transfer loop
	{
		BLOCK *pending = NULL;	// RX block partially written to the TUN
		int pending_ofs = 0;
		UCHAR tun_buf[ANDROID_TUN_READ_BUF];
		int tun_bytes = 0;
		int tun_pkt = 0;
		int tun_dbytes = 0;

		while (true)
		{
			int i;

			if (v->Halt || s->Halt || s->ForceStopFlag)
			{
				break;
			}

			// L3 event processing (ARP, DHCP renew, IPv6 ND/RA, received queues)
			IPCProcessL3EventsEx(v->Ipc, Tick64());

			// Retire the answer seeded from the previous session as soon as the hub has
			// answered for this one. This is not cosmetic: while the placeholder stands it
			// is the entry at index 0 of the core's list, which is what
			// IPCIPv6SendUnicast falls back to for a source address in no advertised
			// prefix, and it suppresses the hub's own entry for the prefix it matches.
			VLanIPv6ReconcileSeed(v);

			// Drive IPv6 Router Solicitation while the hub's answer for this session is
			// outstanding; the pacing state is shared with the RA gate thread so this
			// continues where the gate left off. Note that a seeded answer does not
			// silence this - it is what keeps the seed under verification until the hub
			// confirms its own router identity (VLanIPv6NeedsRouterSolicitation).
			if (v->Ipv6Enabled && v->Ipv6StaticMode == false &&
				VLanIPv6NeedsRouterSolicitation(v) && Tick64() >= v->Ipv6RsNext)
			{
				IPCSendIPv6RouterSoliciation(v->Ipc, false);

				v->Ipv6RsTries++;
				v->Ipv6RsNext = Tick64() + ANDROID_IPV6_RS_INTERVAL_MS;

				Debug("VLanAndroid: sending IPv6 Router Solicitation %u\n",
					v->Ipv6RsTries);
			}

			// Lease-keep of the hub's DHCP entry. A dial that reused the cached answer
			// sent no DHCP REQUEST, and the hub's built-in DHCP creates/refreshes the
			// entry for this MAC only on a REQUEST (Virtual.c:9584-9621), so without
			// this the hub would let the lease expire during a long session and could
			// hand the address to another client. Unicast and fire-and-forget: with no
			// reply awaited, IPCSendDhcpRequest returns as soon as the frame is queued
			// (IPC.c:952-958), so the packet pump is not held up; and a REQUEST whose
			// granted address differs from the frame's source IP is answered with a NAK
			// that IPCDhcpRenewIP ignores, which keeps the old address in use until the
			// Kotlin side rebuilds the interface (see the vc48 quick-drop rule).
			if (v->DhcpRenewNext != 0 && Tick64() >= v->DhcpRenewNext)
			{
				UINT interval = VLanDhcpRenewIntervalSec(v);
				char ipstr[MAX_SIZE];

				ipstr[0] = 0;
				IPToStr(ipstr, sizeof(ipstr), &v->ConfigIp);

				IPCDhcpRenewIP(v->Ipc, &v->DhcpServer);

				Debug("VLanAndroid: refreshed the hub's DHCP lease %s (every %u s)\n",
					ipstr, interval);

				v->DhcpRenewNext = Tick64() + (UINT64)interval * 1000;
			}

			if (v->TunFd < 0)
			{
				FreeBlock(pending);

				pending = NULL;
				pending_ofs = 0;
				tun_bytes = 0;
				tun_pkt = 0;
				tun_dbytes = 0;

				SleepThread(ANDROID_GETNEXT_TIMEOUT_MS);

				continue;
			}

			// Wait for outbound packets; only block in poll() when the TUN
			// buffer is empty, so a busy TUN is drained without any sleep
			if (tun_bytes == 0)
			{
				struct pollfd pfd;

				pfd.fd = v->TunFd;
				pfd.events = POLLIN;
				pfd.revents = 0;

				poll(&pfd, 1, ANDROID_GETNEXT_TIMEOUT_MS);

				i = read(v->TunFd, tun_buf, ANDROID_TUN_READ_BUF);

				if (i > 0)
				{
					tun_bytes = i;
				}
				else if (i < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
				{
					tun_bytes = 0;
				}
				else
				{
					// The TUN fd has been closed by the Java side
					break;
				}
			}

			if (tun_bytes > 0)
			{
				switch (tun_buf[0] >> 4)
				{
				case 4:
					IPCSendIPv4(v->Ipc, tun_buf, tun_bytes);
					break;
				case 6:
					IPCIPv6Send(v->Ipc, tun_buf, tun_bytes);
					break;
				default:
					// Ignore non-IP data
					break;
				}

				tun_pkt++;
				tun_dbytes += tun_bytes;
				tun_bytes = 0;

				if (tun_pkt >= ANDROID_TUN_DRAIN_PKTS || tun_dbytes >= ANDROID_TUN_DRAIN_BYTES)
				{
					// Flush the hub-side queues during a long outbound burst
					// so that the reply direction keeps flowing
					IPCProcessL3EventsEx(v->Ipc, Tick64());

					tun_pkt = 0;
					tun_dbytes = 0;
				}
			}

			// IPC (hub) -> TUN; a partially written block is kept as the
			// head of the queue and resumed on the next pass
			while (true)
			{
				if (pending == NULL)
				{
					pending = IPCRecvIPv4(v->Ipc);

					if (pending == NULL && v->Ipv6Enabled)
					{
						pending = IPCIPv6Recv(v->Ipc);
					}

					pending_ofs = 0;

					if (pending == NULL)
					{
						break;
					}

					if (pending->Size == 0)
					{
						FreeBlock(pending);
						pending = NULL;
						continue;
					}
				}

				i = write(v->TunFd, ((UCHAR *)pending->Buf) + pending_ofs,
					pending->Size - pending_ofs);

				if (i > 0)
				{
					pending_ofs += i;

					if (pending_ofs >= pending->Size)
					{
						FreeBlock(pending);
						pending = NULL;
						pending_ofs = 0;
					}
				}
				else if (i < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
				{
					// The TUN receive buffer is full; resume on the next pass
					break;
				}
				else if (i < 0 && (errno == EINTR))
				{
					continue;
				}
				else
				{
					// The TUN fd has been closed by the Java side
					break;
				}
			}

			// Yield the CPU; pending traffic is detected by the poll()
			// timeout on the next pass, so no unconditional sleep here
			SleepThread(0);
		}

		FreeBlock(pending);
	}
}

// Get the packet adapter instance
PACKET_ADAPTER *VLanAndroidGetPacketAdapter(VLAN_ANDROID *v)
{
	PACKET_ADAPTER *pa;

	if (v == NULL)
	{
		return NULL;
	}

	pa = NewPacketAdapter(VLanAndroidPaInit, VLanAndroidPaGetCancel,
		VLanAndroidPaGetNextPacket, VLanAndroidPaPutPacket, VLanAndroidPaFree);

	pa->Param = v;

	return pa;
}

// Create a new adapter object. mac_address is the profile's own inner MAC (see
// the header); NULL means take a fresh random MAC for this connect.
VLAN_ANDROID *VLanAndroidNew(CEDAR *cedar, const UCHAR *mac_address)
{
	VLAN_ANDROID *v;

	if (cedar == NULL)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(VLAN_ANDROID));

	v->TunFd = -1;
	v->Ipv4Enabled = true;
	v->Ipv6Enabled = false;

	if (mac_address != NULL)
	{
		Copy(v->MacAddress, mac_address, 6);

		// A hand-edited MAC may name any vendor OUI, so only clear the multicast bit
		// to keep it a valid source address.
		v->MacAddress[0] &= 0xFE;
	}
	else
	{
		Rand(v->MacAddress, 6);
		// Locally administered, unicast
		v->MacAddress[0] = (v->MacAddress[0] & 0xFE) | 0x02;
	}

	// t_out: IPC -> device, t_in: device -> IPC
	NewTubePair(&v->TubeFromIpc, &v->TubeToIpc, 0);

	v->Sock = NewInProcSocket(v->TubeFromIpc, v->TubeToIpc);

	v->Ipc = NewIPCBySock(cedar, v->Sock, v->MacAddress);
	StrCpy(v->Ipc->ClientHostname, sizeof(v->Ipc->ClientHostname), "android");

	// Halt-notify pair polled by IPCDhcpAllocateIP (TubeDisconnect wakes a pending wait)
	NewTubePair(&v->DhcpHaltTube, &v->DhcpHaltPeer, 0);

	return v;
}

// Abort a pending DHCP wait in the pump thread (user-initiated disconnect
// during the IPv4 configuration phase; TubeDisconnect wakes it immediately)
void VLanAndroidAbortDhcp(VLAN_ANDROID *v)
{
	if (v == NULL)
	{
		return;
	}

	TubeDisconnect(v->DhcpHaltTube);
	TubeDisconnect(v->DhcpHaltPeer);
}

// Release the adapter object
void VLanAndroidFree(VLAN_ANDROID *v)
{
	if (v == NULL)
	{
		return;
	}

	v->Halt = true;

	// Wake the pump thread even if it is still inside IPCDhcpAllocateIP
	TubeDisconnect(v->DhcpHaltTube);
	TubeDisconnect(v->DhcpHaltPeer);

	VLanStopIpv6Gate(v);

	if (v->Thread != NULL)
	{
		WaitThread(v->Thread, INFINITE);
		ReleaseThread(v->Thread);
		v->Thread = NULL;
	}

	// This disconnects the socket and releases the reference of the
	// socket added by NewIPCBySock() (the socket object itself still
	// has our reference).
	FreeIPC(v->Ipc);

	// Release our reference of the socket; this cleans the socket up,
	// which disconnects and releases the tube references that were
	// added by NewInProcSocket().
	ReleaseSock(v->Sock);

	// Release our own references of the tube pair
	ReleaseTube(v->TubeToIpc);
	ReleaseTube(v->TubeFromIpc);

	ReleaseTube(v->DhcpHaltTube);
	ReleaseTube(v->DhcpHaltPeer);

	Free(v->ErrorMsg);

	Free(v);
}

// Set the TUN file descriptor
void VLanAndroidSetTunFd(VLAN_ANDROID *v, int fd)
{
	if (v == NULL)
	{
		return;
	}

	if (fd >= 0)
	{
		char *buf;
		UINT dropped = 0;
		int n;

		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

		// A reconnect may hand over the *same* interface (the Java side keeps the
		// VpnService interface while the session is re-dialled), and the kernel has
		// queued whatever the apps sent while no session was reading. Those packets
		// predate this session, so drop them here - before the reader thread is
		// allowed to see the descriptor - instead of pushing a stale burst through a
		// stack that has not resolved its inner ARP state yet. A fresh interface has
		// an empty queue, so this costs one EAGAIN.
		buf = Malloc(ANDROID_TUN_READ_BUF);

		while (dropped < ANDROID_TUN_STALE_DRAIN_MAX)
		{
			n = read(fd, buf, ANDROID_TUN_READ_BUF);

			if (n <= 0)
			{
				// The fd is non-blocking: n == -1 with EAGAIN/EWOULDBLOCK (or EINTR)
				// means the queue is drained; n == 0 would mean the fd is gone.
				break;
			}

			dropped++;
		}

		Free(buf);

		if (dropped != 0)
		{
			Debug("VLanAndroidSetTunFd(): dropped %u stale TUN packet(s)\n", dropped);
		}
	}

	v->TunFd = fd;
}

// Set the static IPv4 parameters (must be called before VLanAndroidStart())
void VLanAndroidSetStaticIPv4(VLAN_ANDROID *v, IP *ip, IP *mask, IP *gw, IP *dns1, IP *dns2)
{
	if (v == NULL || ip == NULL || mask == NULL)
	{
		return;
	}

	v->StaticMode = true;

	Copy(v->StaticIp.address, ip->address, 16);
	Copy(v->StaticMask.address, mask->address, 16);

	if (gw != NULL)
	{
		Copy(v->StaticGw.address, gw->address, 16);
	}

	if (dns1 != NULL)
	{
		Copy(v->StaticDns1.address, dns1->address, 16);
	}

	if (dns2 != NULL)
	{
		Copy(v->StaticDns2.address, dns2->address, 16);
	}
}

// Seed the hub's IPv4 answer of a previous session (must be called before
// VLanAndroidStart()). The pump configures the NIC from it instead of running
// IPCDhcpAllocateIP, and only if mac_address is this adapter's MAC: the hub's DHCP
// keys its lease table on the client MAC (Virtual.c:9561-9621), so an answer that
// belongs to another MAC would be simply the wrong address. The address itself is
// not re-validated here - it went through the core's own DHCP checks when the hub
// granted it.
void VLanAndroidSetCachedIPv4(VLAN_ANDROID *v, IP *ip, IP *mask, IP *gw, IP *dns1, IP *dns2,
	DHCP_CLASSLESS_ROUTE_TABLE *routes, IP *dhcp_server, UINT lease_sec, const UCHAR *mac_address)
{
	IP empty;

	if (v == NULL || ip == NULL || mask == NULL || mac_address == NULL ||
		IsZeroIP(ip) || IsZeroIP(mask))
	{
		return;
	}

	Zero(&empty, sizeof(IP));

	v->HasCachedIPv4 = true;

	Copy(v->CachedIp.address, ip->address, 16);
	Copy(v->CachedMask.address, mask->address, 16);
	Copy(v->CachedGw.address, (gw != NULL) ? gw->address : empty.address, 16);
	Copy(v->CachedDns1.address, (dns1 != NULL) ? dns1->address : empty.address, 16);
	Copy(v->CachedDns2.address, (dns2 != NULL) ? dns2->address : empty.address, 16);
	Copy(v->CachedDhcpServer.address,
		(dhcp_server != NULL) ? dhcp_server->address : empty.address, 16);

	if (routes != NULL)
	{
		v->CachedRoutes = *routes;
	}
	v->CachedLeaseSec = lease_sec;

	Copy(v->CachedMac, mac_address, 6);
}

// Seed the hub's IPv6 answer of a previous session (must be called before
// VLanAndroidStart()). prefix/mask are the routed prefix of the Router
// Advertisement the session had configured from, router and router_mac the address
// and MAC of the hub's router at that time, and dns what it advertised (the hub's
// RA carries no RDNSS, so today that is always empty). The client address is not
// passed: it derives from prefix + MAC (VLanIPv6SLAAC) together with prefix_flags,
// which is also why mac_address guards the whole seed. router_mac may be NULL,
// meaning the next session solicits the router MAC as it would with no cache at all.
// Only prefix and mask are required, the rest may be zero. prefix_flags is the flag
// byte of the prefix option that came with this prefix, so that the seed cannot grant
// an address the hub's current Router Advertisement would not grant.
void VLanAndroidSetCachedIPv6(VLAN_ANDROID *v, IP *prefix, IP *mask, IP *router,
	const UCHAR *router_mac, IP *dns, UCHAR prefix_flags, const UCHAR *mac_address)
{
	IP empty;
	UCHAR no_mac[6];

	if (v == NULL || prefix == NULL || mask == NULL || mac_address == NULL ||
		IsZeroIP(prefix) || IsZeroIP(mask))
	{
		return;
	}

	Zero(&empty, sizeof(IP));
	Zero(no_mac, sizeof(no_mac));

	v->HasCachedIPv6 = true;

	Copy(v->CachedV6Prefix.address, prefix->address, 16);
	Copy(v->CachedV6Mask.address, mask->address, 16);
	Copy(v->CachedV6Router.address, (router != NULL) ? router->address : empty.address, 16);
	Copy(v->CachedV6Dns.address, (dns != NULL) ? dns->address : empty.address, 16);
	v->CachedV6PrefixFlags = prefix_flags;

	if (router_mac != NULL)
	{
		Copy(v->CachedV6RouterMac, router_mac, 6);
	}
	else
	{
		Copy(v->CachedV6RouterMac, no_mac, 6);
	}

	Copy(v->CachedV6Mac, mac_address, 6);
}

// Enable or disable IPv4 (must be called before VLanAndroidStart())
void VLanAndroidSetIPv4Enabled(VLAN_ANDROID *v, bool enabled)
{
	if (v == NULL)
	{
		return;
	}

	v->Ipv4Enabled = enabled;
}

// Enable or disable IPv6 (must be called before VLanAndroidStart())
void VLanAndroidSetIPv6Enabled(VLAN_ANDROID *v, bool enabled)
{
	if (v == NULL)
	{
		return;
	}

	v->Ipv6Enabled = enabled;
}

// Set the static IPv6 parameters (must be called before VLanAndroidStart();
// implies IPv6 enabled in static mode, no RA acquisition)
void VLanAndroidSetStaticIPv6(VLAN_ANDROID *v, IP *addr, IP *mask, IP *gw, IP *dns)
{
	if (v == NULL || addr == NULL || mask == NULL)
	{
		return;
	}

	v->Ipv6StaticMode = true;

	Copy(v->Ipv6StaticAddr.address, addr->address, 16);
	Copy(v->Ipv6StaticMask.address, mask->address, 16);

	if (gw != NULL)
	{
		Copy(v->Ipv6StaticGw.address, gw->address, 16);
	}

	if (dns != NULL)
	{
		Copy(v->Ipv6StaticDns.address, dns->address, 16);
	}
}

// Start the adapter (after the session has been assigned)
bool VLanAndroidStart(VLAN_ANDROID *v)
{
	if (v == NULL || v->Session == NULL || v->Thread != NULL)
	{
		return false;
	}

	v->Thread = NewThread(VLanAndroidThread, v);

	return true;
}

// Whether the configuration has been completed
bool VLanAndroidIsConfigReady(VLAN_ANDROID *v)
{
	return (v != NULL) ? v->ConfigOk : false;
}

// Whether a configuration error has occurred
bool VLanAndroidIsError(VLAN_ANDROID *v)
{
	return (v != NULL) ? v->ErrorOccured : false;
}

// Get the error text
char *VLanAndroidGetErrorText(VLAN_ANDROID *v)
{
	if (v == NULL || v->ErrorMsg == NULL)
	{
		return NULL;
	}

	return v->ErrorMsg;
}

// Get the acquired IPv4 configuration. Answers as soon as the address is
// known (static parameters at bring-up start, DHCP lease the moment it is
// in hand), not only after the unified ConfigOk gate — so the UI can show
// the lease while the IPv6 router advertisement is still pending.
bool VLanAndroidGetIPv4Config(VLAN_ANDROID *v, IP *ip, IP *mask, IP *gw, IP *dns1, IP *dns2,
	UINT *lease_sec, IP *dhcp_server)
{
	if (v == NULL || v->Ipv4Enabled == false || IsZeroIP(&v->ConfigIp))
	{
		return false;
	}

	if (ip != NULL)
	{
		Copy(ip->address, v->ConfigIp.address, 16);
	}

	if (mask != NULL)
	{
		Copy(mask->address, v->ConfigMask.address, 16);
	}

	if (gw != NULL)
	{
		Copy(gw->address, v->ConfigGw.address, 16);
	}

	if (dns1 != NULL)
	{
		Copy(dns1->address, v->ConfigDns1.address, 16);
	}

	if (dns2 != NULL)
	{
		Copy(dns2->address, v->ConfigDns2.address, 16);
	}

	// Lease bookkeeping of the hub's entry (zero for a static configuration)
	if (lease_sec != NULL)
	{
		*lease_sec = v->DhcpLeaseSec;
	}

	if (dhcp_server != NULL)
	{
		Copy(dhcp_server->address, v->DhcpServer.address, 16);
	}

	return true;
}

// Compute the SLAAC (EUI-64) interface address from the first RA prefix
static void VLanIPv6SLAAC(VLAN_ANDROID *v, IP *prefix, IP *addr)
{
	if (v == NULL || prefix == NULL || addr == NULL)
	{
		return;
	}

	CopyIP(addr, prefix);

	addr->address[8] = v->MacAddress[0] ^ 0x02;	// flip the U/L bit
	addr->address[9] = v->MacAddress[1];
	addr->address[10] = v->MacAddress[2];
	addr->address[11] = 0xff;
	addr->address[12] = 0xfe;
	addr->address[13] = v->MacAddress[3];
	addr->address[14] = v->MacAddress[4];
	addr->address[15] = v->MacAddress[5];
}

// Get the effective IPv6 configuration (static parameters, or the SLAAC address from
// the prefix the hub authorised for autonomous address configuration together with the
// router prefix learned from a Router Advertisement on the hub segment).
// router_mac, if not NULL, receives the MAC that off-prefix frames of this session
// are encapsulated to: the router's own MAC from IPCIPv6SendUnicast's point of view
// (it prefers RouterMacAddress and falls back to RouterLinkLayerAddress), or zeros
// where no hub-side MAC is known - in static mode, or from a seed that carried none.
// addr is left as the unspecified address if the hub advertised no autonomous prefix
// (see VLanIPv6AddressEntry), while this call still succeeds: the router identity is a
// fact of the hub's own and stands on its own, and the interface of such a session
// keeps its link-local address, as RFC 4861 section 4.6.2 intends.
bool VLanAndroidGetIPv6Config(VLAN_ANDROID *v, IP *addr, IP *prefix, IP *mask, IP *router,
	UCHAR *router_mac, IP *dns, UCHAR *prefix_flags)
{
	IPC_IPV6_ROUTER_ADVERTISEMENT *ra, *rep;

	if (v == NULL || v->Ipc == NULL || v->Ipv6Enabled == false)
	{
		return false;
	}

	if (v->Ipv6StaticMode)
	{
		if (router_mac != NULL)
		{
			// The interface is configured by the kernel from the parameters set over
			// JNI, and no Router Advertisement is involved: there is no router MAC.
			Zero(router_mac, 6);
		}

		if (addr != NULL)
		{
			CopyIP(addr, &v->Ipv6StaticAddr);
		}

		if (mask != NULL)
		{
			CopyIP(mask, &v->Ipv6StaticMask);
		}

		if (prefix != NULL)
		{
			// Network part of the static address
			IP np;
			int i;

			Zero(np.address, 16);

			for (i = 0; i < 16; i++)
			{
				np.address[i] = v->Ipv6StaticAddr.address[i] & v->Ipv6StaticMask.address[i];
			}

			CopyIP(prefix, &np);
		}

		if (router != NULL)
		{
			CopyIP(router, &v->Ipv6StaticGw);
		}

		if (dns != NULL)
		{
			CopyIP(dns, &v->Ipv6StaticDns);
		}

		if (prefix_flags != NULL)
		{
			// No Router Advertisement is involved, so there is no flag byte to carry
			// into the cache of the next connect.
			*prefix_flags = 0;
		}

		return true;
	}

	// The seed is retired on the session's pump path (VLanAndroidThread, which is where
	// the core's L3 events are processed), not here: this getter is called from the JNI
	// thread, and removing an entry from the core's list would make this thread a writer
	// of a list that the pump threads already write (Add from
	// IPCIPv6AddRouterPrefixes). A view one pump pass behind costs at most the first
	// interface build of a session whose hub prefix changed, which the next status poll
	// corrects by rebuilding the interface.

	if (LIST_NUM(v->Ipc->IPv6RouterAdvs) == 0)
	{
		return false;
	}

	ra = LIST_DATA(v->Ipc->IPv6RouterAdvs, 0);

	if (ra == NULL)
	{
		return false;
	}

	// The entry that describes this client's session: the first of the hub's prefixes
	// that it authorised for autonomous address configuration, which need not be the
	// first of the Router Advertisement's and may be none of them (this hub's Router
	// Advertisement carries three prefixes and only one of them is address-forming, so
	// taking the first prefix unconditionally - what this function did until now - made
	// the installed address a property of whichever prefix happened to be listed first;
	// device, an older session: prefix 2001:470:7ccf:: mask ffff:ffff:ffff::, i.e. a /48
	// route prefix, with our address 2001:470:7ccf:0:5cc2:b4ff:fe96:9a46 on it).
	//
	// Address, prefix, mask and the router identity are read from that one entry so
	// that they describe a single prefix, and it is also the entry the core resolves
	// our off-prefix traffic by: IPCIPv6SendUnicast looks the router up by the packet's
	// source address (IPC.c:2662) and that source is the address derived from this
	// prefix, so it matches this entry and takes its router MAC (IPC.c:2678). The first
	// entry of the list is used only as the fallback when the source address belongs to
	// none of the advertised prefixes (IPC.c:2665-2668) - the case when no autonomous
	// prefix exists and the interface's global source is therefore absent, which is what
	// rep = NULL below reproduces.
	rep = VLanIPv6AddressEntry(v);

	if (rep == NULL)
	{
		rep = ra;
	}

	if (addr != NULL)
	{
		if (VLanIPv6AutonomousPrefix(rep))
		{
			VLanIPv6SLAAC(v, &rep->RoutedPrefix, addr);
		}
		else
		{
			// The hub offered no autonomous prefix: nothing to install, and the
			// interface keeps its link-local address.
			Zero(addr->address, 16);
		}
	}

	if (prefix != NULL)
	{
		CopyIP(prefix, &rep->RoutedPrefix);
	}

	if (mask != NULL)
	{
		CopyIP(mask, &rep->RoutedMask);
	}

	if (router != NULL)
	{
		// The router address with its MAC as one pair, from the entry above: one Router
		// Advertisement names one router for all of its prefixes (the sender address and
		// the source link-layer option are per-Router-Advertisement, and
		// IPCIPv6AddRouterPrefixes copies them to every entry of that RA), while two
		// RAs from two routers merged into one list can name different routers - and
		// then the core would also pick the one for our own prefix.
		CopyIP(router, &rep->RouterAddress);
	}

	if (prefix_flags != NULL)
	{
		*prefix_flags = rep->PrefixFlags;
	}

	if (router_mac != NULL)
	{
		// The same preference IPCIPv6SendUnicast applies to the entry above: the frame's
		// source MAC of the Router Advertisement, falling back to the source link-layer
		// address of the RA options when that is not a usable unicast address.
		if (IsMacUnicast(rep->RouterMacAddress) || IsMacInvalid(rep->RouterLinkLayerAddress))
		{
			Copy(router_mac, rep->RouterMacAddress, 6);
		}
		else
		{
			Copy(router_mac, rep->RouterLinkLayerAddress, 6);
		}
	}

	if (dns != NULL)
	{
		// The hub segment's RA carries no recursive DNS server option
		Zero(dns->address, 16);
	}

	return true;
}

// Get the MAC address of the adapter
const UCHAR *VLanAndroidGetMacAddress(VLAN_ANDROID *v)
{
	if (v == NULL)
	{
		return NULL;
	}

	return v->MacAddress;
}

#endif	// UNIX_ANDROID
