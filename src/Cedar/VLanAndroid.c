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

		if (LIST_NUM(v->Ipc->IPv6RouterAdvs) > 0)
		{
			break;
		}

		if (v->Ipv6RsTries >= ANDROID_IPV6_RS_MAX)
		{
			break;
		}

		if (Tick64() >= next)
		{
			IPCSendIPv6RouterSoliciation(v->Ipc, false);

			v->Ipv6RsTries++;
			next = Tick64() + ANDROID_IPV6_RS_INTERVAL_MS;

			Debug("VLanAndroid: sent IPv6 Router Solicitation %u/%u\n",
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

	// Open the IPv6 state machine early so that Router Advertisement and ND
	// processing is active while the IPv4 acquisition below runs: the DHCP
	// request loop in IPC.c pumps IPCProcessL3Events on every pass, which
	// also learns RA prefixes into the IPv6RouterAdvs list.
	if (v->Ipv6Enabled)
	{
		IPC_PROTO_SET_STATUS(v->Ipc, IPv6State, IPC_PROTO_STATUS_OPENED);
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

			ret = IPCDhcpAllocateIP(v->Ipc, opt, v->DhcpHaltTube);

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
		// The gate thread only paced Router Solicitations while the IPv4
		// acquisition ran (a few seconds in the common case); continue the
		// pacing here until the shared budget is exhausted or the router
		// answers. The DHCP pump is done, so this thread is the only IPC
		// pump again and may run IPCProcessL3EventsEx itself.
		while (v->Ipv6RsTries < ANDROID_IPV6_RS_MAX &&
			LIST_NUM(v->Ipc->IPv6RouterAdvs) == 0)
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

				Debug("VLanAndroid: sent IPv6 Router Solicitation %u/%u\n",
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

			// Drive IPv6 Router Solicitation until the hub segment's router
			// answers with at least one RA prefix (learned into IPC.c's
			// IPv6RouterAdvs list); the pacing state is shared with the RA
			// gate thread so this continues where the gate left off
			if (v->Ipv6Enabled && v->Ipv6StaticMode == false &&
				v->Ipv6RsTries < ANDROID_IPV6_RS_MAX &&
				LIST_NUM(v->Ipc->IPv6RouterAdvs) == 0 && Tick64() >= v->Ipv6RsNext)
			{
				IPCSendIPv6RouterSoliciation(v->Ipc, false);

				v->Ipv6RsTries++;
				v->Ipv6RsNext = Tick64() + ANDROID_IPV6_RS_INTERVAL_MS;

				Debug("VLanAndroid: sent IPv6 Router Solicitation %u/%u\n",
					v->Ipv6RsTries, ANDROID_IPV6_RS_MAX);
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

// Create a new adapter object
VLAN_ANDROID *VLanAndroidNew(CEDAR *cedar)
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

	Rand(v->MacAddress, 6);
	// Locally administered, unicast
	v->MacAddress[0] = (v->MacAddress[0] & 0xFE) | 0x02;

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
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
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
bool VLanAndroidGetIPv4Config(VLAN_ANDROID *v, IP *ip, IP *mask, IP *gw, IP *dns1, IP *dns2)
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

// Get the effective IPv6 configuration (static parameters, or the SLAAC
// address and first router prefix learned from RA on the hub segment)
bool VLanAndroidGetIPv6Config(VLAN_ANDROID *v, IP *addr, IP *prefix, IP *mask, IP *router, IP *dns)
{
	IPC_IPV6_ROUTER_ADVERTISEMENT *ra;

	if (v == NULL || v->Ipc == NULL || v->Ipv6Enabled == false)
	{
		return false;
	}

	if (v->Ipv6StaticMode)
	{
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

		return true;
	}

	if (LIST_NUM(v->Ipc->IPv6RouterAdvs) == 0)
	{
		return false;
	}

	ra = LIST_DATA(v->Ipc->IPv6RouterAdvs, 0);

	if (ra == NULL)
	{
		return false;
	}

	if (addr != NULL)
	{
		VLanIPv6SLAAC(v, &ra->RoutedPrefix, addr);
	}

	if (prefix != NULL)
	{
		CopyIP(prefix, &ra->RoutedPrefix);
	}

	if (mask != NULL)
	{
		CopyIP(mask, &ra->RoutedMask);
	}

	if (router != NULL)
	{
		CopyIP(router, &ra->RouterAddress);
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
