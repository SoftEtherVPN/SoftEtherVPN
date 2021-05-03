// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// BridgeUnix.c
// Ethernet Bridge Program (for UNIX)

#ifdef OS_UNIX

#include "BridgeUnix.h"

#include "Server.h"
#include "VLanUnix.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Unix.h"

#include <string.h>

#include <errno.h>
#include <fcntl.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#ifndef UNIX_OPENBSD
#include <net/ethernet.h>
#endif

#ifdef UNIX_SOLARIS
#include <sys/sockio.h>
#endif

#ifdef BRIDGE_PCAP
#include <pcap.h>
#endif

#ifdef BRIDGE_BPF
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#endif

#ifdef UNIX_LINUX
#include <linux/if_packet.h>

struct my_tpacket_auxdata
{
	UINT tp_status;
	UINT tp_len;
	UINT tp_snaplen;
	USHORT tp_mac;
	USHORT tp_net;
	USHORT tp_vlan_tci;
	USHORT tp_vlan_tpid;
};
#define MY_TP_STATUS_VLAN_VALID (1 << 4)
#define MY_TP_STATUS_VLAN_TPID_VALID (1 << 6)
#define	MY_PACKET_AUXDATA 8
#endif	// UNIX_LINUX

static LIST *eth_offload_list = NULL;

// Initialize
void InitEth()
{
	eth_offload_list = NewList(NULL);
}

// Free
void FreeEth()
{
	if (eth_offload_list != NULL)
	{
		FreeStrList(eth_offload_list);
		eth_offload_list = NULL;
	}
}

// Check whether interface description string of Ethernet device can be retrieved in this system
bool EthIsInterfaceDescriptionSupportedUnix()
{
	bool ret = false;
	DIRLIST *d = EnumDir("/etc/sysconfig/networking/devices/");

	if (d == NULL)
	{
		return false;
	}

	if (d->NumFiles >= 1)
	{
		ret = true;
	}

	FreeDir(d);

	return ret;
}

// Get interface description string
bool EthGetInterfaceDescriptionUnix(char *name, char *str, UINT size)
{
	char tmp[MAX_SIZE];
	bool ret = false;
	BUF *b;
	// Validate arguments
	if (name == NULL || str == NULL)
	{
		return false;
	}

	StrCpy(str, size, name);

	Format(tmp, sizeof(tmp), "/etc/sysconfig/networking/devices/ifcfg-%s", name);

	b = ReadDump(tmp);
	if (b != NULL)
	{
		char *line = CfgReadNextLine(b);

		if (IsEmptyStr(line) == false)
		{
			if (StartWith(line, "#"))
			{
				char tmp[MAX_SIZE];

				StrCpy(tmp, sizeof(tmp), line + 1);

				Trim(tmp);
				tmp[60] = 0;

				StrCpy(str, size, tmp);

				ret = true;
			}
		}

		Free(line);

		FreeBuf(b);
	}

	return ret;
}

// Open raw socket
int UnixEthOpenRawSocket()
{
#ifdef	UNIX_LINUX
	int s;

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0)
	{
		return INVALID_SOCKET;
	}
	else
	{
		return s;
	}
#else	// UNIX_LINUX
	return -1;
#endif	// UNIX_LINUX
}

// Is Ethernet device control supported?
bool IsEthSupported()
{

#if	defined(UNIX_LINUX)
	return IsEthSupportedLinux();
#elif	defined(UNIX_BSD)
	return true;
#elif	defined(UNIX_SOLARIS)
	return IsEthSupportedSolaris();
#else
	return false;
#endif

}

#ifdef	UNIX_LINUX
bool IsEthSupportedLinux()
{
	int s;

	// Try to open a raw socket
	s = UnixEthOpenRawSocket();
	if (s == INVALID_SOCKET)
	{
		// fail
		return false;
	}

	// success
	closesocket(s);

	return true;
}
#endif	// UNIX_LINUX

#ifdef	UNIX_SOLARIS
bool IsEthSupportedSolaris()
{
	return true;
}
#endif	// UNIX_SOLARIS

#ifdef	UNIX_SOLARIS
// Get Ethernet device list on Solaris
TOKEN_LIST *GetEthListSolaris()
{
	TOKEN_LIST *t;
	int i, s;
	LIST *o;


	o = NewListFast(CompareStr);
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != INVALID_SOCKET)
	{
		struct lifnum lifn;
		lifn.lifn_family = AF_INET;
		lifn.lifn_flags = 0;
		if (ioctl(s, SIOCGLIFNUM, (char *)&lifn) >= 0)
		{
			struct lifconf lifc;
			struct lifreq *buf;
			UINT numifs;
			UINT bufsize;

			numifs = lifn.lifn_count;
			Debug("NumIFs:%d\n",numifs);
			bufsize = numifs * sizeof(struct lifreq);
			buf = Malloc(bufsize);

			lifc.lifc_family = AF_INET;
			lifc.lifc_flags = 0;
			lifc.lifc_len = bufsize;
			lifc.lifc_buf = (char *) buf;
			if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) >= 0)
			{
				for (i = 0; i<numifs; i++)
				{
					if(StartWith(buf[i].lifr_name, "lo") == false) {
						Add(o, CopyStr(buf[i].lifr_name));
					}
				}
			}
			Free(buf);
		}
		closesocket(s);
	}

	Sort(o);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0; i < LIST_NUM(o); i++)
	{
		char *name = LIST_DATA(o, i);
		t->Token[i] = name;
	}

	ReleaseList(o);

	return t;
}
#endif	// UNIX_SOLARIS

#ifdef	UNIX_LINUX
// Get Ethernet device list on Linux
TOKEN_LIST *GetEthListLinux(bool enum_normal, bool enum_rawip)
{
	struct ifreq ifr;
	TOKEN_LIST *t;
	UINT i, n;
	int s;
	LIST *o;
	char name[MAX_SIZE];

	if (enum_normal == false && enum_rawip)
	{
		return ParseToken(BRIDGE_SPECIAL_IPRAW_NAME, NULL);
	}

	o = NewListFast(CompareStr);

	s = UnixEthOpenRawSocket();
	if (s != INVALID_SOCKET)
	{
		n = 0;
		for (i = 0;; i++)
		{
			Zero(&ifr, sizeof(ifr));
			ifr.ifr_ifindex = i;

			if (ioctl(s, SIOCGIFNAME, &ifr) >= 0)
			{
				n = 0;
				StrCpy(name, sizeof(name), ifr.ifr_name);

				Zero(&ifr, sizeof(ifr));
				StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), name);
				if (ioctl(s, SIOCGIFHWADDR, &ifr) >= 0)
				{
					UINT type = ifr.ifr_hwaddr.sa_family;
					if (type == 1 || type == 2 || type == 6 || type == 800 || type == 801)
					{
						if (IsInListStr(o, name) == false)
						{
							if (StartWith(name, "tap_") == false)
							{
								Add(o, CopyStr(name));
							}
						}
					}
				}
			}
			else
			{
				n++;
				if (n >= 64)
				{
					break;
				}
			}
		}
		closesocket(s);
	}

	Sort(o);

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o) + (enum_rawip ? 1 : 0);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0; i < LIST_NUM(o); i++)
	{
		char *name = LIST_DATA(o, i);
		t->Token[i] = name;
	}

	if (enum_rawip)
	{
		t->Token[t->NumTokens - 1] = CopyStr(BRIDGE_SPECIAL_IPRAW_NAME);
	}

	ReleaseList(o);

	return t;
}
#endif	// UNIX_LINUX

#ifdef BRIDGE_PCAP
// Ethernet device list by Pcap API
TOKEN_LIST *GetEthListPcap()
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	LIST *o;
	TOKEN_LIST *t;
	int i;

	o = NewListFast(CompareStr);

	if( pcap_findalldevs(&alldevs,errbuf) != -1)
	{
		pcap_if_t *dev = alldevs;
		while(dev != NULL)
		{
			pcap_t *p;
			// Device type will be unknown until open the device?
			p = pcap_open_live(dev->name, 0, false, 0, errbuf);
			if(p != NULL)
			{
				int datalink = pcap_datalink(p);
				//			Debug("type:%s\n",pcap_datalink_val_to_name(datalink));
				pcap_close(p);
				if(datalink == DLT_EN10MB) {
					// Enumerate only Ethernet type device
					Add(o, CopyStr(dev->name));
				}
			}
			dev = dev->next;
		}
		pcap_freealldevs(alldevs);
	}

	Sort(o);
	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0; i < LIST_NUM(o); i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}
	ReleaseList(o);
	return t;
}
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
// Ethernet device list by BPF API
TOKEN_LIST *GetEthListBpf()
{
	struct ifaddrs *ifadrs;
	struct sockaddr_dl *sockadr;
	LIST *o;
	TOKEN_LIST *t;
	int i;

	o = NewListFast(CompareStr);

	// Enumerate network devices
	if(getifaddrs( &ifadrs ) == 0)
	{
		struct ifaddrs *ifadr = ifadrs;
		while(ifadr)
		{
			sockadr = (struct sockaddr_dl *)ifadr->ifa_addr;
			if(sockadr->sdl_family == AF_LINK && sockadr->sdl_type == IFT_ETHER)
			{
				// Is this Ethernet device?
				if(!IsInListStr(o,ifadr->ifa_name))
				{
					// Ignore the foregoing device (for device which have multiple MAC address)
					Add(o, CopyStr(ifadr->ifa_name));
				}
			}
			ifadr = ifadr -> ifa_next;
		}
		freeifaddrs(ifadrs);
	}

	Sort(o);
	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0; i < LIST_NUM(o); i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}
	ReleaseList(o);
	return t;
}
#endif // BRIDGE_BPF

// Enumerate Ethernet devices
TOKEN_LIST *GetEthList()
{
	return GetEthListEx(NULL, true, false);
}
TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden, bool enum_normal, bool enum_rawip)
{

#if	defined(UNIX_LINUX)
	return GetEthListLinux(enum_normal, enum_rawip);
#elif	defined(UNIX_SOLARIS)
	return GetEthListSolaris();
#elif	defined(BRIDGE_PCAP)
	return GetEthListPcap();
#elif	defined(BRIDGE_BPF)
	return GetEthListBpf();
#else
	return NULL;
#endif

}

#ifdef	UNIX_LINUX
// Open Ethernet device (Linux)
ETH *OpenEthLinux(char *name, bool local, bool tapmode, char *tapaddr)
{
	ETH *e;
	struct ifreq ifr;
	struct sockaddr_ll addr;
	int s;
	int index;
	bool aux_ok = false;
	CANCEL *c;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	if (StrCmpi(name, BRIDGE_SPECIAL_IPRAW_NAME) == 0)
	{
		return OpenEthLinuxIpRaw();
	}

	if (tapmode)
	{
#ifndef	NO_VLAN
		// In tap mode
		VLAN *v = NewTap(name, tapaddr, true);
		if (v == NULL)
		{
			return NULL;
		}

		e = ZeroMalloc(sizeof(ETH));
		e->Name = CopyStr(name);
		e->Title = CopyStr(name);
		e->Cancel = VLanGetCancel(v);
		e->IfIndex = 0;
		e->Socket = INVALID_SOCKET;
		e->Tap = v;

		return e;
#else	// NO_VLAN
		return NULL;
#endif	// NO_VLAN
	}

	s = UnixEthOpenRawSocket();
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	Zero(&ifr, sizeof(ifr));
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), name);

	if (ioctl(s, SIOCGIFINDEX, &ifr) < 0)
	{
		closesocket(s);
		return NULL;
	}

	index = ifr.ifr_ifindex;

	Zero(&addr, sizeof(addr));
	addr.sll_family = PF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = index;

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		closesocket(s);
		return NULL;
	}

	if (local == false)
	{
		// Enable promiscuous mode
		Zero(&ifr, sizeof(ifr));
		StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), name);
		if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
		{
			// Failed
			closesocket(s);
			return NULL;
		}

		ifr.ifr_flags |= IFF_PROMISC;

		if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
		{
			// Failed
			closesocket(s);
			return NULL;
		}
	}

	if (true)
	{
		int val = 1;
		int ss_ret = setsockopt(s, SOL_PACKET, MY_PACKET_AUXDATA, &val, sizeof(val));

		if (ss_ret < 0)
		{
			Debug("eth(%s): setsockopt: PACKET_AUXDATA failed.\n", name);
		}
		else
		{
			Debug("eth(%s): setsockopt: PACKET_AUXDATA ok.\n", name);
			aux_ok = true;
		}
	}

	e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(name);
	e->Title = CopyStr(name);
	e->IfIndex = index;
	e->Socket = s;

	e->Linux_IsAuxDataSupported = aux_ok;

	c = NewCancel();
	UnixDeletePipe(c->pipe_read, c->pipe_write);
	c->pipe_read = c->pipe_write = -1;

	UnixSetSocketNonBlockingMode(s, true);

	c->SpecialFlag = true;
	c->pipe_read = s;

	e->Cancel = c;

	// Get MTU
	e->InitialMtu = EthGetMtu(e);

	if (tapmode == false)
	{
		if (GetGlobalServerFlag(GSF_LOCALBRIDGE_NO_DISABLE_OFFLOAD) == false)
		{
			bool b = false;

			LockList(eth_offload_list);
			{
				if (IsInListStr(eth_offload_list, name) == false)
				{
					b = true;

					Add(eth_offload_list, CopyStr(name));
				}
			}
			UnlockList(eth_offload_list);

			if (b)
			{
				// Disable hardware offloading
				UnixDisableInterfaceOffload(name);
			}
		}
	}

	return e;
}
#endif	// UNIX_LINUX

// Get the MTU value
UINT EthGetMtu(ETH *e)
{
#if	defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	UINT ret = 0;
#ifdef	UNIX_SOLARIS
	struct lifreq ifr;
#else	// UNIX_SOLARIS
	struct ifreq ifr;
#endif	// UNIX_SOLARIS
	int s;
	// Validate arguments
	if (e == NULL || e->Tap != NULL)
	{
		return 0;
	}
	if (e->IsRawIpMode)
	{
		return 0;
	}

	if (e->CurrentMtu != 0)
	{
		return e->CurrentMtu;
	}

#if	defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	s = e->SocketBsdIf;
#else	// defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	s = e->Socket;
#endif	// defined(UNIX_BSD) || defined(UNIX_SOLARIS)

	Zero(&ifr, sizeof(ifr));

#ifdef	UNIX_SOLARIS
	StrCpy(ifr.lifr_name, sizeof(ifr.lifr_name), e->Name);
#else	// UNIX_SOLARIS
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), e->Name);
#endif	// UNIX_SOLARIS

#ifdef	UNIX_SOLARIS
	if (ioctl(s, SIOCGLIFMTU, &ifr) < 0)
	{
		// failed
		return 0;
	}
#else	// UNIX_SOLARIS
	if (ioctl(s, SIOCGIFMTU, &ifr) < 0)
	{
		// failed
		return 0;
	}
#endif	// UNIX_SOLARIS

#ifdef	UNIX_SOLARIS
	ret = ifr.lifr_mtu + 14;
#else	// UNIX_SOLARIS
	ret = ifr.ifr_mtu + 14;
#endif	// UNIX_SOLARIS

	e->CurrentMtu = ret;

	Debug("%s: GetMtu: %u\n", e->Name, ret);

	return ret;
#else	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	return 0;
#endif	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
}

// Set the MTU value
bool EthSetMtu(ETH *e, UINT mtu)
{
#if	defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	UINT ret = 0;
#ifdef	UNIX_SOLARIS
	struct lifreq ifr;
#else	// UNIX_SOLARIS
	struct ifreq ifr;
#endif	// UNIX_SOLARIS
	int s;
	// Validate arguments
	if (e == NULL || e->Tap != NULL || (mtu > 1 && mtu < 1514))
	{
		return false;
	}
	if (mtu == 0 && e->InitialMtu == 0)
	{
		return false;
	}
	if (e->IsRawIpMode)
	{
		return false;
	}

	if (mtu == 0)
	{
		// Restore initial MTU value when parameter mtu == 0
		mtu = e->InitialMtu;
	}

#if	defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	s = e->SocketBsdIf;
#else	// defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	s = e->Socket;
#endif	// defined(UNIX_BSD) || defined(UNIX_SOLARIS)

	if (e->CurrentMtu == mtu)
	{
		// No need to change
		return true;
	}

	Zero(&ifr, sizeof(ifr));

#ifdef	UNIX_SOLARIS
	StrCpy(ifr.lifr_name, sizeof(ifr.lifr_name), e->Name);
	ifr.lifr_mtu = mtu - 14;
#else	// UNIX_SOLARIS
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), e->Name);
	ifr.ifr_mtu = mtu - 14;
#endif	// UNIX_SOLARIS

#ifdef	UNIX_SOLARIS
	if (ioctl(s, SIOCSLIFMTU, &ifr) < 0)
	{
		// Failed
		return false;
	}
#else	// UNIX_SOLARIS
	if (ioctl(s, SIOCSIFMTU, &ifr) < 0)
	{
		// Failed
		return false;
	}
#endif	// UNIX_SOLARIS

	e->CurrentMtu = mtu;

	Debug("%s: SetMtu: %u\n", e->Name, mtu);

	return true;
#else	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	return false;
#endif	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
}

// Is changing MTU supported?
bool EthIsChangeMtuSupported(ETH *e)
{
#if	defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	// Validate arguments
	if (e == NULL || e->Tap != NULL)
	{
		return false;
	}

	if (e->IsRawIpMode)
	{
		return false;
	}

	return true;
#else	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
	return false;
#endif	// defined(UNIX_LINUX) || defined(UNIX_BSD) || defined(UNIX_SOLARIS)
}

#ifdef	UNIX_SOLARIS
// Open Ethernet adapter (Solaris)
ETH *OpenEthSolaris(char *name, bool local, bool tapmode, char *tapaddr)
{
	char devname[MAX_SIZE];
	int fd;
	ETH *e;
	CANCEL *c;
	struct strioctl sioc;

	// Validate arguments
	if (name == NULL || tapmode != false)
	{
		return NULL;
	}

	// Parse device name
	if (ParseUnixEthDeviceName(devname, sizeof(devname), name) == false)
	{
		return NULL;
	}

	// Open the device - use style 1 attachment
	fd = open(devname, O_RDWR);
	if (fd == -1)
	{
		// Failed
		return NULL;
	}

	// Bind to SAP
	if (DlipBindRequest(fd) == false)
	{
		// Failed
		close(fd);
		return NULL;
	}

	// Verify ACK message
	if (DlipReceiveAck(fd) == false)
	{
		// Failed
		close(fd);
		return NULL;
	}

	// Set to ignore SAP and promiscuous mode
	if (DlipPromiscuous(fd, DL_PROMISC_SAP) == false)
	{
		// Failed
		close(fd);
		return NULL;
	}

	// Verify ACK message
	if (DlipReceiveAck(fd) == false)
	{
		// Failed
		close(fd);
		return NULL;
	}

	// Set to the mode to receive self sending packet
	if (DlipPromiscuous(fd, DL_PROMISC_PHYS) == false)
	{
		// Failed
		close(fd);
		return NULL;
	}

	// Verify ACK message
	if (DlipReceiveAck(fd) == false)
	{
		// Failed
		close(fd);
		return NULL;
	}

	// Set to raw mode
	sioc.ic_cmd = DLIOCRAW;
	sioc.ic_timout = -1;
	sioc.ic_len = 0;
	sioc.ic_dp = NULL;
	if (ioctl(fd, I_STR, &sioc) < 0)
	{
		// Failed
		close(fd);
		return NULL;
	}

	if (ioctl(fd, I_FLUSH, FLUSHR) < 0)
	{
		// Failed
		close(fd);
		return NULL;
	}

	e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(name);
	e->Title = CopyStr(name);

	c = NewCancel();
	UnixDeletePipe(c->pipe_read, c->pipe_write);
	c->pipe_read = c->pipe_write = -1;

	c->SpecialFlag = true;
	c->pipe_read = fd;

	e->Cancel = c;

	e->IfIndex = -1;
	e->Socket = fd;

	UnixSetSocketNonBlockingMode(fd, true);

	// Get control interface
	e->SocketBsdIf = socket(AF_INET, SOCK_DGRAM, 0);

	// Get MTU value
	e->InitialMtu = EthGetMtu(e);

	return e;
}

// Set to promiscuous mode
bool DlipPromiscuous(int fd, UINT level)
{
	dl_promiscon_req_t req;
	struct strbuf ctl;
	int flags;
	// Validate arguments
	if (fd == -1)
	{
		return false;
	}

	Zero(&req, sizeof(req));
	req.dl_primitive = DL_PROMISCON_REQ;
	req.dl_level = level;

	Zero(&ctl, sizeof(ctl));
	ctl.maxlen = 0;
	ctl.len = sizeof(req);
	ctl.buf = (char *)&req;

	flags = 0;

	if (putmsg(fd, &ctl, NULL, flags) < 0)
	{
		return false;
	}

	return true;
}

// Bind to a SAP
bool DlipBindRequest(int fd)
{
	dl_bind_req_t	req;
	struct strbuf ctl;

	if (fd == -1)
	{
		return false;
	}

	Zero(&req, sizeof(req));
	req.dl_primitive = DL_BIND_REQ;
	req.dl_service_mode = DL_CLDLS;
	req.dl_sap = 0;

	Zero(&ctl, sizeof(ctl));
	ctl.maxlen = 0;
	ctl.len = sizeof(req);
	ctl.buf = (char *)&req;

	if (putmsg(fd, &ctl, NULL, 0) < 0)
	{
		return false;
	}
	return true;
}

// Verify the ACK message
bool DlipReceiveAck(int fd)
{
	union DL_primitives *dlp;
	struct strbuf ctl;
	int flags = 0;
	char *buf;
	// Validate arguments
	if (fd == -1)
	{
		return false;
	}

	buf = MallocFast(SOLARIS_MAXDLBUF);

	Zero(&ctl, sizeof(ctl));
	ctl.maxlen = SOLARIS_MAXDLBUF;
	ctl.len = 0;
	ctl.buf = buf;

	if (getmsg(fd, &ctl, NULL, &flags) < 0)
	{
		return false;
	}

	dlp = (union DL_primitives *)ctl.buf;
	if (dlp->dl_primitive != (UINT)DL_OK_ACK && dlp->dl_primitive != (UINT)DL_BIND_ACK)
	{
		Free(buf);
		return false;
	}

	Free(buf);

	return true;
}

#endif	// UNIX_SOLARIS

// Validate device name and return proper device path according to system type
bool ParseUnixEthDeviceName(char *dst_devname, UINT dst_devname_size, char *src_name)
{
	UINT len, i;
	struct stat s;
	int err;
	char *device_path;
	int device_pathlen;

	// Validate arguments
	if (dst_devname == NULL || src_name == NULL)
	{
		return false;
	}

	// Check string length
	if (IsEmptyStr(src_name))
	{
		return false;
	}

	// Solaris 10 and higher make real and virtual devices available in /dev/net
	err = stat("/dev/net", &s);
	if (err != -1 && S_ISDIR(s.st_mode))
	{
		device_path = "/dev/net/";
	}
	else
	{
		device_path = "/dev/";
	}

	device_pathlen = StrLen(device_path);

	// Last character must be a number
	if (src_name[i] < '0' || '9' < src_name[i])
	{
		if (src_name[i + 1] == 0)
		{
			return false;
		}
	}

	StrCpy(dst_devname, dst_devname_size, device_path);
	StrCpy(dst_devname + device_pathlen, dst_devname_size - device_pathlen, src_name);
	dst_devname[device_pathlen + len] = 0;

	return true;
}

#if defined(BRIDGE_BPF) || defined(BRIDGE_PCAP)
// Initialize captured packet data structure
struct CAPTUREBLOCK *NewCaptureBlock(UCHAR *data, UINT size) {
	struct CAPTUREBLOCK *block = Malloc(sizeof(struct CAPTUREBLOCK));
	block->Buf = data;
	block->Size = size;
	return block;
}

// Free captured packet data structure
void FreeCaptureBlock(struct CAPTUREBLOCK *block) {
	Free(block);
}
#endif // BRIDGE_BPF || BRIDGE_PCAP

#ifdef	BRIDGE_PCAP
// Callback function to receive arriving packet (Pcap)
void PcapHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	ETH *e = (ETH *) user;
	struct CAPTUREBLOCK *block;
	UCHAR *data;

	data = Malloc(h->caplen);
	Copy(data, bytes, h->caplen);
	block = NewCaptureBlock(data, h->caplen);
	LockQueue(e->Queue);
	// Discard arriving packet when queue filled
	if(e->QueueSize < BRIDGE_MAX_QUEUE_SIZE) {
		InsertQueue(e->Queue, block);
		e->QueueSize += h->caplen;
	}
	UnlockQueue(e->Queue);
	Cancel(e->Cancel);
	return;
}

// Relay thread for captured packet (Pcap)
void PcapThread(THREAD *thread, void *param)
{
	ETH *e = (ETH *)param;
	pcap_t *p = e->Pcap;
	int ret;

	// Notify initialize completed
	NoticeThreadInit(thread);

	// Return -1:Error -2:Terminated externally
	ret = pcap_loop(p, -1, PcapHandler, (u_char *) e);
	if(ret == -1) {
		e->Socket = INVALID_SOCKET;
		pcap_perror(p, "capture");
	}
	return;
}


// Open Ethernet adapter (Pcap)
ETH *OpenEthPcap(char *name, bool local, bool tapmode, char *tapaddr)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	ETH *e;
	pcap_t *p;

	// Validate arguments
	if (name == NULL || tapmode != false)
	{
		return NULL;
	}

	// Initialize error message buffer
	errbuf[0] = 0;

	// Open capturing device
	p = pcap_open_live(name, 65535, (local == false), 1, errbuf);
	if(p==NULL)
	{
		return NULL;
	}

	// Set to non-block mode
	// (In old BSD OSs, 'select(2)' don't block normally for BPF device. To prevent busy loop)
	/*
	if(pcap_setnonblock(p, true, errbuf) == -1)
	{
		Debug("pcap_setnonblock:%s\n",errbuf);
		pcap_close(p);
		return NULL;
	}
	*/

	e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(name);
	e->Title = CopyStr(name);
	e->Queue = NewQueue();
	e->QueueSize = 0;
	e->Cancel = NewCancel();
	e->IfIndex = -1;
	e->Socket = pcap_get_selectable_fd(p);
	e->Pcap = p;

	e->CaptureThread = NewThread(PcapThread, e);
	WaitThreadInit(e->CaptureThread);

	return e;
}
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
#ifdef BRIDGE_BPF_THREAD
// Relay thread for captured packet (BPF)
void BpfThread(THREAD *thread, void *param)
{
	ETH *e = (ETH *)param;
	int fd = e->Socket;
	int len;
	int rest;	// Rest size in buffer
	UCHAR *next;	// Head of next packet in buffer
	struct CAPTUREBLOCK *block;	// Data to enqueue
	UCHAR *data;
	struct bpf_hdr *hdr;

	// Allocate the buffer
	UCHAR *buf = Malloc(e->BufSize);

	// Notify initialize completed
	NoticeThreadInit(thread);

	while(1) {
		// Determining to exit loop
		if(e->Socket == INVALID_SOCKET) {
			break;
		}

		rest = read(fd, buf, e->BufSize);
		if(rest < 0 && errno != EAGAIN) {
			// Error
			close(fd);
			e->Socket = INVALID_SOCKET;
			Free(buf);
			Cancel(e->Cancel);
			return;
		}
		next = buf;
		LockQueue(e->Queue);
		while(rest>0) {
			// Cut out a packet
			hdr = (struct bpf_hdr *)next;

			// Discard arriving packet when queue filled
			if(e->QueueSize < BRIDGE_MAX_QUEUE_SIZE) {
				data = Malloc(hdr->bh_caplen);
				Copy(data, next+(hdr->bh_hdrlen), hdr->bh_caplen);
				block = NewCaptureBlock(data, hdr->bh_caplen);
				InsertQueue(e->Queue, block);
				e->QueueSize += hdr->bh_caplen;
			}

			// Find the head of next packet
			rest -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
			next += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
		}
		UnlockQueue(e->Queue);
		Cancel(e->Cancel);
	}
	Free(buf);
	Cancel(e->Cancel);
	return;
}
#endif // BRIDGE_BPF_THREAD

// Open Ethernet adapter (BPF)
ETH *OpenEthBpf(char *name, bool local, bool tapmode, char *tapaddr)
{
	ETH *e;
	CANCEL *c;
	char devname[MAX_SIZE];
	int n = 0;
	int fd;
	int ret;
	UINT bufsize;
	struct ifreq ifr;
	struct timeval to;

	// Find unused bpf device and open it
	do {
		Format(devname, sizeof(devname), "/dev/bpf%d", n++);
		fd = open (devname, O_RDWR);
		if(fd<0) {
			perror("open");
		}
	} while(fd < 0 && errno == EBUSY);

	// No free bpf device was found
	if(fd < 0) {
		Debug("BPF: No minor number are free.\n");
		return NULL;
	}

	// Enlarge buffer size
	n = 524288; // Somehow(In libpcap, this size is 32768)
	while(true) {
		// Specify buffer size
		ioctl(fd, BIOCSBLEN, &n);

		// Bind to the network device
		StrCpy(ifr.ifr_name, IFNAMSIZ, name);
		ret = ioctl(fd, BIOCSETIF, &ifr);
		if(ret < 0) {
			if(ret == ENOBUFS && n>1500) {
				// Inappropriate buffer size
				// Retry with half buffer size
				// If buffer size is under 1500 bytes, something goes wrong
				n /= 2;
				continue;
			}
			Debug("bpf: binding network failed.\n");
			close(fd);
			return NULL;
		} else {
			break;
		}
	}
	bufsize = n;

	// Set to promiscuous mode
	if(local == false) {
		if (ioctl(fd, BIOCPROMISC, NULL) < 0) {
			printf("bpf: promisc mode failed.\n");
			close(fd);
			return NULL;
		}
	}


	// Set to immediate mode (Return immediately when packet arrives)
	n = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &n) < 0) {
		Debug("BPF: non-block mode failed.\n");
		close(fd);
		return NULL;
	}

	// Set receiving self sending packet
	n = 1;
	if (ioctl(fd, BIOCGSEESENT, &n) < 0) {
		Debug("BPF: see sent mode failed.\n");
		close(fd);
		return NULL;
	}

	// Header complete mode (Generate whole header of sending packet)
	n = 1;
	if (ioctl(fd, BIOCSHDRCMPLT, &n) < 0) {
		Debug("BPF: Header complete mode failed.\n");
		close(fd);
		return NULL;
	}

	// Set timeout delay to 1 second
	to.tv_sec = 1;
	to.tv_usec = 0;
	if (ioctl(fd, BIOCSRTIMEOUT, &to) < 0) {
		Debug("BPF: Read timeout setting failed.\n");
		close(fd);
		return NULL;
	}

	e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(name);
	e->Title = CopyStr(name);
	e->IfIndex = -1;
	e->Socket = fd;
	e->BufSize = bufsize;

#ifdef BRIDGE_BPF_THREAD
	e->Queue = NewQueue();
	e->QueueSize = 0;
	e->Cancel = NewCancel();

	// Start capture thread
	e->CaptureThread = NewThread(BpfThread, e);
	WaitThreadInit(e->CaptureThread);

#else // BRIDGE_BPF_THREAD
	c = NewCancel();
	UnixDeletePipe(c->pipe_read, c->pipe_write);
	c->pipe_read = c->pipe_write = -1;
	c->SpecialFlag = true;
	c->pipe_read = fd;
	e->Cancel = c;
	e->Buffer = Malloc(bufsize);
	e->Next = e->Buffer;
	e->Rest = 0;

	// Set to non-blocking mode
	UnixSetSocketNonBlockingMode(fd, true);
#endif // BRIDGE_BPF_THREAD

	// Open interface control socket for FreeBSD
	e->SocketBsdIf = socket(AF_LOCAL, SOCK_DGRAM, 0);

	// Get MTU value
	e->InitialMtu = EthGetMtu(e);

	return e;
}
#endif // BRIDGE_BPF

#ifdef UNIX_BSD
ETH *OpenEthBSD(char *name, bool local, bool tapmode, char *tapaddr)
{
	if (tapmode)
	{
#ifndef	NO_VLAN
		// In tap mode
		VLAN *v = NewTap(name, tapaddr, true);
		if (v == NULL)
		{
			return NULL;
		}

		ETH *e;
		e = ZeroMalloc(sizeof(ETH));
		e->Name = CopyStr(name);
		e->Title = CopyStr(name);
		e->Cancel = VLanGetCancel(v);
		e->IfIndex = 0;
		e->Socket = INVALID_SOCKET;
		e->Tap = v;

		return e;
#else	// NO_VLAN
return NULL:
#endif	// NO_VLAN
	}

#if	defined(BRIDGE_BPF)
	return OpenEthBpf(name, local, tapmode, tapaddr);
#elif	defined(BRIDGE_PCAP)
	return OpenEthPcap(name, local, tapmode, tapaddr);
#else
	return NULL;
#endif
}
#endif // UNIX_BSD

// Open Ethernet adapter
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr)
{

#if	defined(UNIX_LINUX)
	return OpenEthLinux(name, local, tapmode, tapaddr);
#elif	defined(UNIX_BSD)
	return OpenEthBSD(name, local, tapmode, tapaddr);
#elif	defined(UNIX_SOLARIS)
	return OpenEthSolaris(name, local, tapmode, tapaddr);
#elif	defined(BRIDGE_PCAP)
	return OpenEthPcap(name, local, tapmode, tapaddr);
#elif	defined(BRIDGE_BPF)
	return OpenEthBpf(name, local, tapmode, tapaddr);
#else
	return NULL;
#endif

}

typedef struct UNIXTHREAD
{
	pthread_t thread;
	bool finished;
} UNIXTHREAD;

// Close Ethernet adapter
void CloseEth(ETH *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	if (e->IsRawIpMode)
	{
		CloseEthLinuxIpRaw(e);

		return;
	}

	if (e->Tap != NULL)
	{
#ifndef	NO_VLAN
		FreeTap(e->Tap);
#endif	// NO_VLAN
	}

#ifdef BRIDGE_PCAP
	{
		struct CAPTUREBLOCK *block;
		pcap_breakloop(e->Pcap);
		WaitThread(e->CaptureThread, INFINITE);
		ReleaseThread(e->CaptureThread);
		pcap_close(e->Pcap);
		while (block = GetNext(e->Queue)) {
			Free(block->Buf);
			FreeCaptureBlock(block);
		}
		ReleaseQueue(e->Queue);
	}
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
#ifdef BRIDGE_BPF_THREAD
	{
		struct CAPTUREBLOCK *block;
		int fd = e->Socket;
		e->Socket = INVALID_SOCKET;
		WaitThread(e->CaptureThread, INFINITE);
		ReleaseThread(e->CaptureThread);
		e->Socket = fd; // restore to close after
		while (block = GetNext(e->Queue)) {
			Free(block->Buf);
			FreeCaptureBlock(block);
		}
		ReleaseQueue(e->Queue);
	}
#else // BRIDGE_BPF_THREAD
	Free(e->Buffer);
#endif // BRIDGE_BPF_THREAD
#endif // BRIDGE_BPF

	ReleaseCancel(e->Cancel);
	Free(e->Name);
	Free(e->Title);

	// Restore MTU value
	EthSetMtu(e, 0);

	if (e->Socket != INVALID_SOCKET)
	{
#if defined(BRIDGE_BPF) || defined(BRIDGE_PCAP) || defined(UNIX_SOLARIS)
		close(e->Socket);
#else // BRIDGE_PCAP
		closesocket(e->Socket);
#endif // BRIDGE_PCAP
#if defined(BRIDGE_BPF) || defined(UNIX_SOLARIS)
		if (e->SocketBsdIf != INVALID_SOCKET)
		{
			close(e->SocketBsdIf);
		}
#endif	// BRIDGE_BPF || UNIX_SOLARIS
	}

	Free(e);
}

// Get cancel object
CANCEL *EthGetCancel(ETH *e)
{
	CANCEL *c;
	// Validate arguments
	if (e == NULL)
	{
		return NULL;
	}

	c = e->Cancel;
	AddRef(c->ref);

	return c;
}

// Read a packet
UINT EthGetPacket(ETH *e, void **data)
{
	// Validate arguments
	if (e == NULL || data == NULL)
	{
		return INFINITE;
	}

#ifdef	UNIX_LINUX
	if (e->IsRawIpMode)
	{
		return EthGetPacketLinuxIpRaw(e, data);
	}
#endif

	if (e->Tap != NULL)
	{
#ifndef	NO_VLAN
		// TAP mode
		void *buf;
		UINT size;

		if (VLanGetNextPacket(e->Tap, &buf, &size) == false)
		{
			return INFINITE;
		}

		*data = buf;
		return size;
#else
		return INFINITE;
#endif
	}

#if		defined(UNIX_LINUX)
	return EthGetPacketLinux(e, data);
#elif	defined(UNIX_SOLARIS)
	return EthGetPacketSolaris(e, data);
#elif	defined(BRIDGE_PCAP)
	return EthGetPacketPcap(e, data);
#elif	defined(BRIDGE_BPF)
	return EthGetPacketBpf(e, data);
#endif
}

#ifdef	UNIX_LINUX

UINT EthGetPacketLinux(ETH *e, void **data)
{
	int s, ret;
	UCHAR tmp[UNIX_ETH_TMP_BUFFER_SIZE];
	struct iovec msg_iov;
	struct msghdr msg_header;
	struct cmsghdr *cmsg;
	union
	{
		struct cmsghdr cmsg;
		char buf[CMSG_SPACE(sizeof(struct my_tpacket_auxdata))];
	} cmsg_buf;

	s = e->Socket;

	if (s == INVALID_SOCKET)
	{
		return INFINITE;
	}

	// Read
	msg_iov.iov_base = tmp;
	msg_iov.iov_len = sizeof(tmp);

	msg_header.msg_name = NULL;
	msg_header.msg_namelen = 0;
	msg_header.msg_iov = &msg_iov;
	msg_header.msg_iovlen = 1;
	if (e->Linux_IsAuxDataSupported)
	{
		memset(&cmsg_buf, 0, sizeof(cmsg_buf));

		msg_header.msg_control = &cmsg_buf;
		msg_header.msg_controllen = sizeof(cmsg_buf);
	}
	else
	{
		msg_header.msg_control = NULL;
		msg_header.msg_controllen = 0;
	}
	msg_header.msg_flags = 0;

	ret = recvmsg(s, &msg_header, 0);
	if (ret == 0 || (ret == -1 && errno == EAGAIN))
	{
		// No packet
		*data = NULL;
		return 0;
	}
	else if (ret == -1 || ret > sizeof(tmp))
	{
		// Error
		*data = NULL;
		e->Socket = INVALID_SOCKET;
		return INFINITE;
	}
	else
	{
		bool flag = false;
		USHORT api_vlan_id = 0;
		USHORT api_vlan_tpid = 0;

		if (e->Linux_IsAuxDataSupported)
		{
			for (cmsg = CMSG_FIRSTHDR(&msg_header); cmsg; cmsg = CMSG_NXTHDR(&msg_header, cmsg))
			{
				struct my_tpacket_auxdata *aux;
				UINT len;
				USHORT vlan_tpid = 0x8100;
				USHORT vlan_id = 0;

				if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct my_tpacket_auxdata)) ||
				        cmsg->cmsg_level != SOL_PACKET ||
				        cmsg->cmsg_type != MY_PACKET_AUXDATA)
				{
					continue;
				}

				aux = (struct my_tpacket_auxdata *)CMSG_DATA(cmsg);

				if (aux != NULL)
				{
					if (aux->tp_vlan_tci != 0)
					{
						vlan_id = aux->tp_vlan_tci;
					}
				}

				if (vlan_id != 0)
				{
					api_vlan_id = vlan_id;
					api_vlan_tpid = vlan_tpid;
					break;
				}
			}

			if (api_vlan_id != 0 && api_vlan_tpid != 0)
			{
				// VLAN ID has been received with PACKET_AUXDATA.
				// Insert the tag.
				USHORT vlan_id_ne = Endian16(api_vlan_id);
				USHORT vlan_tpid_ne = Endian16(api_vlan_tpid);

				if (ret >= 14)
				{
					if (*((USHORT *)(tmp + 12)) != vlan_tpid_ne)
					{
						*data = MallocFast(ret + 4);
						Copy(*data, tmp, 12);
						Copy(((UCHAR *)*data) + 12, &vlan_tpid_ne, 2);
						Copy(((UCHAR *)*data) + 14, &vlan_id_ne, 2);
						Copy(((UCHAR *)*data) + 16, tmp + 12, ret - 12);

						flag = true;

						ret += 4;
					}
				}
			}
		}

		// Success to read a packet (No VLAN)
		if (flag == false)
		{
			*data = MallocFast(ret);
			Copy(*data, tmp, ret);
		}
		return ret;
	}

	return 0;
}
#endif	// UNIX_LINUX

#ifdef	UNIX_SOLARIS
UINT EthGetPacketSolaris(ETH *e, void **data)
{
	UCHAR tmp[UNIX_ETH_TMP_BUFFER_SIZE];
	struct strbuf buf;
	int s;
	int flags = 0;
	int ret;

	s = e->Socket;
	if (s == INVALID_SOCKET)
	{
		return INFINITE;
	}

	Zero(&buf, sizeof(buf));
	buf.buf = tmp;
	buf.maxlen = sizeof(tmp);

	ret = getmsg(s, NULL, &buf, &flags);

	if (ret < 0 || ret > sizeof(tmp))
	{
		if (errno == EAGAIN)
		{
			// No packet
			*data = NULL;
			return 0;
		}
		// Error
		*data = NULL;
		return INFINITE;
	}

	ret = buf.len;

	*data = MallocFast(ret);
	Copy(*data, tmp, ret);
	return ret;
}
#endif	// UNIX_SOLARIS

#ifdef	BRIDGE_PCAP
UINT EthGetPacketPcap(ETH *e, void **data)
{
	struct CAPTUREBLOCK *block;
	UINT size;

	LockQueue(e->Queue);
	block = GetNext(e->Queue);
	if(block != NULL) {
		e->QueueSize -= block->Size;
	}
	UnlockQueue(e->Queue);

	if(block == NULL) {
		*data = NULL;
		if(e->Socket == INVALID_SOCKET) {
			return INFINITE;
		}
		return 0;
	}

	*data = block->Buf;
	size = block->Size;
	FreeCaptureBlock(block);

	return size;
}
#endif // BRIDGE_PCAP

#ifdef	BRIDGE_BPF
#ifdef BRIDGE_BPF_THREAD
UINT EthGetPacketBpf(ETH *e, void **data)
{
	struct CAPTUREBLOCK *block;
	UINT size;

	LockQueue(e->Queue);
	block = GetNext(e->Queue);
	if(block != NULL) {
		e->QueueSize -= block->Size;
	}
	UnlockQueue(e->Queue);

	if(block == NULL) {
		*data = NULL;
		if(e->Socket == INVALID_SOCKET) {
			return INFINITE;
		}
		return 0;
	}

	*data = block->Buf;
	size = block->Size;
	FreeCaptureBlock(block);

	return size;
}
#else // BRIDGE_BPF_THREAD
UINT EthGetPacketBpf(ETH *e, void **data)
{
	struct bpf_hdr *hdr;

	if(e->Rest<=0) {
		e->Rest = read(e->Socket, e->Buffer, e->BufSize);
		if(e->Rest < 0) {
			*data = NULL;
			if(errno != EAGAIN) {
				// Error
				return INFINITE;
			}
			// No packet
			return 0;
		}
		e->Next = e->Buffer;
	}
	// Cut out a packet
	hdr = (struct bpf_hdr *)e->Next;
	*data = Malloc(hdr->bh_caplen);
	Copy(*data, e->Next+(hdr->bh_hdrlen), hdr->bh_caplen);

	// Find the head of next packet
	e->Rest -= BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
	e->Next += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);

	return hdr->bh_caplen;
}
#endif // BRIDGE_BPF_THREAD
#endif // BRIDGE_BPF


// Send multiple packets
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes)
{
	UINT i;
	// Validate arguments
	if (e == NULL || num == 0 || datas == NULL || sizes == NULL)
	{
		return;
	}

	for (i = 0; i < num; i++)
	{
		EthPutPacket(e, datas[i], sizes[i]);
	}
}

// Send a packet
void EthPutPacket(ETH *e, void *data, UINT size)
{
	int s, ret;
	// Validate arguments
	if (e == NULL || data == NULL)
	{
		return;
	}
	if (e->IsRawIpMode)
	{
		EthPutPacketLinuxIpRaw(e, data, size);
		return;
	}
	if (size < 14 || size > MAX_PACKET_SIZE)
	{
		Free(data);
		return;
	}

	if (e->Tap != NULL)
	{
#ifndef	NO_VLAN
		// tap mode
		VLanPutPacket(e->Tap, data, size);
#endif	// NO_VLAN
		return;
	}

	s = e->Socket;

	if (s == INVALID_SOCKET)
	{
		Free(data);
		return;
	}

	// Send to device
#ifdef BRIDGE_PCAP
	ret = pcap_inject(e->Pcap, data, size);
	if( ret == -1 ) {
#ifdef _DEBUG
		pcap_perror(e->Pcap, "inject");
#endif // _DEBUG
		Debug("EthPutPacket: ret:%d size:%d\n", ret, size);
	}
#else // BRIDGE_PCAP
#ifndef	UNIX_LINUX
	ret = write(s, data, size);
	if (ret<0)
	{
		Debug("EthPutPacket: ret:%d errno:%d  size:%d\n", ret, errno, size);
	}
#else	// UNIX_LINUX
	{
		struct iovec msg_iov;
		struct msghdr msg_header;

		msg_iov.iov_base = data;
		msg_iov.iov_len = size;

		msg_header.msg_name = NULL;
		msg_header.msg_namelen = 0;
		msg_header.msg_iov = &msg_iov;
		msg_header.msg_iovlen = 1;
		msg_header.msg_control = NULL;
		msg_header.msg_controllen = 0;
		msg_header.msg_flags = 0;

		ret = sendmsg(s, &msg_header, 0);

		if (ret<0)
		{
			Debug("EthPutPacket: ret:%d errno:%d  size:%d\n", ret, errno, size);
		}
	}
#endif	// UNIX_LINUX
#endif //BRIDGE_PCAP

	Free(data);
}

// Open ETH by using IP raw packets
ETH *OpenEthLinuxIpRaw()
{
	ETH *e;

	if (IsRawIpBridgeSupported() == false)
	{
		return NULL;
	}

	e = ZeroMalloc(sizeof(ETH));

	e->IsRawIpMode = true;

	e->RawTcp = NewUDP4(MAKE_SPECIAL_PORT(IPPROTO_TCP), NULL);
	e->RawUdp = NewUDP4(MAKE_SPECIAL_PORT(IPPROTO_UDP), NULL);
	e->RawIcmp = NewUDP4(MAKE_SPECIAL_PORT(IPPROTO_ICMP), NULL);

	if (e->RawTcp == NULL || e->RawUdp == NULL || e->RawIcmp == NULL)
	{
		ReleaseSock(e->RawTcp);
		ReleaseSock(e->RawUdp);
		ReleaseSock(e->RawIcmp);

		Free(e);
		return NULL;
	}

	ClearSockDfBit(e->RawTcp);
	ClearSockDfBit(e->RawUdp);
	ClearSockDfBit(e->RawIcmp);

	SetRawSockHeaderIncludeOption(e->RawTcp, true);
	SetRawSockHeaderIncludeOption(e->RawUdp, true);
	SetRawSockHeaderIncludeOption(e->RawIcmp, true);

	e->Name = CopyStr(BRIDGE_SPECIAL_IPRAW_NAME);
	e->Title = CopyStr(BRIDGE_SPECIAL_IPRAW_NAME);
	e->Cancel = NewCancel();

	UnixDeletePipe(e->Cancel->pipe_read, e->Cancel->pipe_write);
	e->Cancel->pipe_read = e->Cancel->pipe_write = -1;

	UnixSetSocketNonBlockingMode(e->RawTcp->socket, true);
	UnixSetSocketNonBlockingMode(e->RawUdp->socket, true);
	UnixSetSocketNonBlockingMode(e->RawIcmp->socket, true);

	e->Cancel->SpecialFlag = true;
	e->Cancel->pipe_read = e->RawTcp->socket;
	e->Cancel->pipe_special_read2 = e->RawUdp->socket;
	e->Cancel->pipe_special_read3 = e->RawIcmp->socket;

	e->RawIpMyMacAddr[2] = 0x01;
	e->RawIpMyMacAddr[5] = 0x01;

	SetIP(&e->MyIP, 10, 171, 7, 253);
	SetIP(&e->YourIP, 10, 171, 7, 254);

	e->RawIpSendQueue = NewQueueFast();

	e->RawIP_TmpBufferSize = 67000;
	e->RawIP_TmpBuffer = Malloc(e->RawIP_TmpBufferSize);

	return e;
}

// Close ETH by using IP raw packets
void CloseEthLinuxIpRaw(ETH *e)
{
	if (e == NULL)
	{
		return;
	}

	while (true)
	{
		BUF *buf = GetNext(e->RawIpSendQueue);
		if (buf == NULL)
		{
			break;
		}

		FreeBuf(buf);
	}
	ReleaseQueue(e->RawIpSendQueue);

	Free(e->Name);
	Free(e->Title);

	ReleaseSock(e->RawTcp);
	ReleaseSock(e->RawUdp);
	ReleaseSock(e->RawIcmp);

	ReleaseCancel(e->Cancel);

	Free(e->RawIP_TmpBuffer);

	Free(e);
}

// Receive an IP raw packet
UINT EthGetPacketLinuxIpRaw(ETH *e, void **data)
{
	UINT r;
	BUF *b;
	// Validate arguments
	if (e == NULL || data == NULL)
	{
		return INFINITE;
	}
	if (e->RawIp_HasError)
	{
		return INFINITE;
	}

	b = GetNext(e->RawIpSendQueue);
	if (b != NULL)
	{
		UINT size;

		*data = b->Buf;
		size = b->Size;

		Free(b);

		return size;
	}

	r = EthGetPacketLinuxIpRawForSock(e, data, e->RawTcp, IP_PROTO_TCP);
	if (r == 0)
	{
		r = EthGetPacketLinuxIpRawForSock(e, data, e->RawUdp, IP_PROTO_UDP);
		if (r == 0)
		{
			r = EthGetPacketLinuxIpRawForSock(e, data, e->RawIcmp, IP_PROTO_ICMPV4);
		}
	}

	if (r == INFINITE)
	{
		e->RawIp_HasError = true;
	}

	return r;
}

// Receive an IP raw packet for the specified socket
UINT EthGetPacketLinuxIpRawForSock(ETH *e, void **data, SOCK *s, UINT proto)
{
	UCHAR *tmp;
	UINT r;
	IP src_addr;
	UINT src_port;
	UINT ret = INFINITE;
	UCHAR *retbuf;
	PKT *p;
	bool ok = false;
	// Validate arguments
	if (e == NULL || data == NULL)
	{
		return INFINITE;
	}

	tmp = e->RawIP_TmpBuffer;

LABEL_RETRY:
	*data = NULL;

	r = RecvFrom(s, &src_addr, &src_port, tmp, e->RawIP_TmpBufferSize);
	if (r == SOCK_LATER)
	{
		return 0;
	}

	if (r == 0)
	{
		if (s->IgnoreRecvErr)
		{
			return 0;
		}
		else
		{
			return INFINITE;
		}
	}

	ret = 14 + r;
	retbuf = Malloc(ret);
	*data = retbuf;

	Copy(retbuf, e->RawIpYourMacAddr, 6);
	Copy(retbuf + 6, e->RawIpMyMacAddr, 6);
	retbuf[12] = 0x08;
	retbuf[13] = 0x00;
	Copy(retbuf + 14, tmp, r);

	// Mangle packet
	p = ParsePacket(retbuf, ret);
	if (p != NULL)
	{
		if (p->TypeL3 == L3_IPV4)
		{
			IPV4_HEADER *ip;
			IP original_dest_ip;

			ip = p->L3.IPv4Header;

			UINTToIP(&original_dest_ip, ip->DstIP);

			if (IsZeroIP(&e->MyPhysicalIPForce) == false && CmpIpAddr(&e->MyPhysicalIPForce, &original_dest_ip) == 0 ||
			        (IsIPMyHost(&original_dest_ip) && IsLocalHostIP(&original_dest_ip) == false && IsHostIPAddress4(&original_dest_ip)))
			{
				if (IsZeroIP(&e->MyPhysicalIPForce) && CmpIpAddr(&e->MyPhysicalIP, &original_dest_ip) != 0)
				{
					// Update MyPhysicalIP
					Copy(&e->MyPhysicalIP, &original_dest_ip, sizeof(IP));
//					Debug("e->MyPhysicalIP = %r\n", &e->MyPhysicalIP);
				}

				if (IsZeroIP(&e->MyPhysicalIPForce) == false)
				{
					Copy(&e->MyPhysicalIP, &e->MyPhysicalIPForce, sizeof(IP));
				}

				ip->DstIP = IPToUINT(&e->YourIP);
				ip->Checksum = 0;
				ip->Checksum = IpChecksum(ip, IPV4_GET_HEADER_LEN(ip) * 5);

				if (p->TypeL4 == L4_TCP)
				{
					TCP_HEADER *tcp = p->L4.TCPHeader;
					/*
										if (Endian16(tcp->SrcPort) == 80)
										{
											IP a, b;
											UINTToIP(&a, ip->SrcIP);
											UINTToIP(&b, ip->DstIP);
											Debug("%r %r %u %u\n", &a, &b, Endian16(tcp->SrcPort), Endian16(tcp->DstPort));
										}*/

					ok = true;
				}
				else if (p->TypeL4 == L4_UDP)
				{
					UDP_HEADER *udp = p->L4.UDPHeader;

					udp->Checksum = 0;

					ok = true;
				}
				else if (p->TypeL4 == L4_ICMPV4)
				{
					ICMP_HEADER *icmp = p->L4.ICMPHeader;

					if (icmp->Type == ICMP_TYPE_DESTINATION_UNREACHABLE || icmp->Type == ICMP_TYPE_TIME_EXCEEDED)
					{
						// Rewrite the Src IP of the IPv4 header of the ICMP response packet
						UINT size = p->PacketSize - ((UCHAR *)icmp - (UCHAR *)p->PacketData);
						UCHAR *data = (UCHAR *)icmp;
						IPV4_HEADER *orig_ipv4 = (IPV4_HEADER *)(((UCHAR *)data) + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));
						UINT orig_ipv4_size = size - (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));

						UINT orig_ipv4_header_size = GetIpHeaderSize((UCHAR *)orig_ipv4, orig_ipv4_size);

						if (orig_ipv4_header_size >= sizeof(IPV4_HEADER) && orig_ipv4_size >= orig_ipv4_header_size)
						{
							if (orig_ipv4->Protocol == IP_PROTO_ICMPV4)
							{
								// Search the inner ICMP header
								UINT inner_icmp_size = orig_ipv4_size - orig_ipv4_header_size;

								if (inner_icmp_size >= (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO)))
								{
									ICMP_HEADER *inner_icmp = (ICMP_HEADER *)(((UCHAR *)data) +
									                          sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + orig_ipv4_header_size);

									if (inner_icmp->Type == ICMP_TYPE_ECHO_REQUEST)
									{
										ICMP_ECHO *inner_echo = (ICMP_ECHO *)(((UCHAR *)inner_icmp) + sizeof(ICMP_HEADER));

										inner_icmp->Checksum = 0;
										orig_ipv4->SrcIP = IPToUINT(&e->YourIP);
										orig_ipv4->Checksum = 0;
										orig_ipv4->Checksum = IpChecksum(orig_ipv4, orig_ipv4_header_size);

										// Rewrite the outer ICMP header
										if (true)
										{
											UCHAR *payload;
											UINT payload_size;
											ICMP_ECHO *echo;

											// Echo Response
											echo = (ICMP_ECHO *)(((UCHAR *)data) + sizeof(ICMP_HEADER));

											if (size >= (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO)))
											{
												payload = ((UCHAR *)data) + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO);
												payload_size = size - (sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO));

												// Rewrite the header
												icmp->Checksum = 0;
												icmp->Checksum = IpChecksum(icmp, size);
											}
										}
									}
								}
							}
						}
					}

					icmp->Checksum = 0;
					icmp->Checksum = IpChecksum(icmp, p->PayloadSize);

					ok = true;
				}
				else if (p->TypeL4 == L4_FRAGMENT)
				{
					ok = true;
				}
			}
		}

		FreePacket(p);
	}

	if (ok == false)
	{
		Free(*data);
		*data = NULL;

		goto LABEL_RETRY;
	}

	return ret;
}

// Send internal IP packet (insert into the send queue)
void EthSendIpPacketInnerIpRaw(ETH *e, void *data, UINT size, USHORT protocol)
{
	BUF *b;
	if (e == NULL || data == NULL || size == 0)
	{
		return;
	}

	if (e->RawIpSendQueue->num_item >= 1024)
	{
		return;
	}

	b = NewBuf();
	WriteBuf(b, e->RawIpYourMacAddr, 6);
	WriteBuf(b, e->RawIpMyMacAddr, 6);
	WriteBufShort(b, protocol);
	WriteBuf(b, data, size);
	SeekBufToBegin(b);

	InsertQueue(e->RawIpSendQueue, b);
}

// Process the packet internal if necessary
bool EthProcessIpPacketInnerIpRaw(ETH *e, PKT *p)
{
	bool ret = false;
	if (e == NULL || p == NULL)
	{
		return false;
	}

	if (p->TypeL3 == L3_ARPV4)
	{
		// ARP processing
		ARPV4_HEADER *arp = p->L3.ARPv4Header;

		if (Endian16(arp->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
		        Endian16(arp->ProtocolType) == MAC_PROTO_IPV4 &&
		        arp->HardwareSize == 6 && arp->ProtocolType == 4)
		{
			if (IPToUINT(&e->MyIP) == arp->TargetIP)
			{
				if (Endian16(arp->Operation) == ARP_OPERATION_REQUEST)
				{
					ARPV4_HEADER r;

					Zero(&r, sizeof(r));
					r.HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
					r.ProtocolType = Endian16(MAC_PROTO_IPV4);
					r.HardwareSize = 6;
					r.ProtocolSize = 4;
					r.Operation = Endian16(ARP_OPERATION_RESPONSE);
					Copy(r.SrcAddress, e->RawIpMyMacAddr, 6);
					Copy(r.TargetAddress, arp->SrcAddress, 6);
					r.SrcIP = IPToUINT(&e->MyIP);
					r.TargetIP = arp->SrcIP;

					EthSendIpPacketInnerIpRaw(e, &r, sizeof(ARPV4_HEADER), MAC_PROTO_ARPV4);
				}
			}
		}
	}
	else if (p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4)
	{
		// DHCP processing
		DHCPV4_HEADER *dhcp;
		UCHAR *data;
		UINT size;
		UINT dhcp_header_size;
		UINT dhcp_data_offset;
		UINT tran_id;
		UINT magic_cookie = Endian32(DHCP_MAGIC_COOKIE);
		bool ok;
		DHCP_OPTION_LIST *opt;

		dhcp = p->L7.DHCPv4Header;
		tran_id = Endian32(dhcp->TransactionId);

		// Get the DHCP data and size
		dhcp_header_size = sizeof(DHCPV4_HEADER);
		dhcp_data_offset = (UINT)(((UCHAR *)p->L7.DHCPv4Header) - ((UCHAR *)p->MacHeader) + dhcp_header_size);
		data = ((UCHAR *)dhcp) + dhcp_header_size;
		size = p->PacketSize - dhcp_data_offset;
		if (dhcp_header_size < 5)
		{
			// Data size is invalid
			return false;
		}

		// Search for Magic Cookie
		ok = false;
		while (size >= 5)
		{
			if (Cmp(data, &magic_cookie, sizeof(magic_cookie)) == 0)
			{
				// Found
				data += 4;
				size -= 4;
				ok = true;
				break;
			}
			data++;
			size--;
		}

		if (ok == false)
		{
			// The packet is invalid
			return false;
		}

		// Parse DHCP options list
		opt = ParseDhcpOptionList(data, size);
		if (opt == NULL)
		{
			// The packet is invalid
			return false;
		}

		if (dhcp->OpCode == 1 && (opt->Opcode == DHCP_DISCOVER || opt->Opcode == DHCP_REQUEST || opt->Opcode == DHCP_INFORM))
		{
			// Operate as the server
			UINT ip = IPToUINT(&e->YourIP);
			if (ip != 0 || opt->Opcode == DHCP_INFORM)
			{
				// Respond if there is providable IP address
				DHCP_OPTION_LIST ret;
				LIST *o;
				UINT hw_type = 0U;
				UINT hw_addr_size = 0U;
				UINT new_ip = ip;
				IP default_dns;

				Zero(&default_dns, sizeof(default_dns));

				Zero(&ret, sizeof(ret));

				ret.Opcode = (opt->Opcode == DHCP_DISCOVER ? DHCP_OFFER : DHCP_ACK);
				ret.ServerAddress = IPToUINT(&e->MyIP);
				ret.LeaseTime = 3600;
				if (opt->Opcode == DHCP_INFORM)
				{
					ret.LeaseTime = 0;
				}

				ret.SubnetMask = SetIP32(255, 255, 255, 252);

				if (UnixGetDefaultDns(&default_dns) && IsZeroIp(&default_dns) == false)
				{
					ret.DnsServer = IPToUINT(&default_dns);
					ret.DnsServer2 = SetIP32(8, 8, 8, 8);
				}
				else
				{
					ret.DnsServer = SetIP32(8, 8, 8, 8);
					ret.DnsServer2 = SetIP32(8, 8, 4, 4);
				}

				ret.Gateway = IPToUINT(&e->MyIP);

				if (opt->Opcode != DHCP_INFORM)
				{
					char client_mac[MAX_SIZE];
					char client_ip[64];
					IP ips;
					BinToStr(client_mac, sizeof(client_mac), p->MacAddressSrc, 6);
					UINTToIP(&ips, ip);
					IPToStr(client_ip, sizeof(client_ip), &ips);
					Debug("IP_RAW: DHCP %s : %s given %s\n",
					      ret.Opcode == DHCP_OFFER ? "DHCP_OFFER" : "DHCP_ACK",
					      client_mac, client_ip);
				}

				// Build a DHCP option
				o = BuildDhcpOption(&ret);
				if (o != NULL)
				{
					BUF *b = BuildDhcpOptionsBuf(o);
					if (b != NULL)
					{
						UINT dest_ip = p->L3.IPv4Header->SrcIP;
						UINT blank_size = 128 + 64;
						UINT dhcp_packet_size;
						UINT magic = Endian32(DHCP_MAGIC_COOKIE);
						DHCPV4_HEADER *dhcp;
						void *magic_cookie_addr;
						void *buffer_addr;

						if (dest_ip == 0)
						{
							dest_ip = 0xffffffff;
						}

						// Calculate the DHCP packet size
						dhcp_packet_size = blank_size + sizeof(DHCPV4_HEADER) + sizeof(magic) + b->Size;

						if (dhcp_packet_size < DHCP_MIN_SIZE)
						{
							// Padding
							dhcp_packet_size = DHCP_MIN_SIZE;
						}

						// Create a header
						dhcp = ZeroMalloc(dhcp_packet_size);

						dhcp->OpCode = 2;
						dhcp->HardwareType = hw_type;
						dhcp->HardwareAddressSize = hw_addr_size;
						dhcp->Hops = 0;
						dhcp->TransactionId = Endian32(tran_id);
						dhcp->Seconds = 0;
						dhcp->Flags = 0;
						dhcp->YourIP = new_ip;
						dhcp->ServerIP = IPToUINT(&e->MyIP);
						Copy(dhcp->ClientMacAddress, p->MacAddressSrc, 6);

						// Calculate the address
						magic_cookie_addr = (((UCHAR *)dhcp) + sizeof(DHCPV4_HEADER) + blank_size);
						buffer_addr = ((UCHAR *)magic_cookie_addr) + sizeof(magic);

						// Magic Cookie
						Copy(magic_cookie_addr, &magic, sizeof(magic));

						// Buffer
						Copy(buffer_addr, b->Buf, b->Size);

						if (true)
						{
							UCHAR *data = ZeroMalloc(sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + dhcp_packet_size);
							IPV4_HEADER *ipv4 = (IPV4_HEADER *)(data);
							UDP_HEADER *udp = (UDP_HEADER *)(data + sizeof(IPV4_HEADER));

							Copy(data + sizeof(IPV4_HEADER) + sizeof(UDP_HEADER), dhcp, dhcp_packet_size);

							IPV4_SET_VERSION(ipv4, 4);
							IPV4_SET_HEADER_LEN(ipv4, 5);
							ipv4->TotalLength = Endian16(sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + dhcp_packet_size);
							ipv4->TimeToLive = 63;
							ipv4->Protocol = IP_PROTO_UDP;
							ipv4->SrcIP = IPToUINT(&e->MyIP);
							ipv4->DstIP = dest_ip;
							ipv4->Checksum = IpChecksum(ipv4, sizeof(IPV4_HEADER));

							udp->SrcPort = Endian16(NAT_DHCP_SERVER_PORT);
							udp->DstPort = Endian16(NAT_DHCP_CLIENT_PORT);
							udp->PacketLength = Endian16(sizeof(UDP_HEADER) + dhcp_packet_size);
							udp->Checksum = CalcChecksumForIPv4(ipv4->SrcIP, ipv4->DstIP, IP_PROTO_UDP,
							                                    dhcp, dhcp_packet_size, 0);
							if (udp->Checksum == 0)
							{
								udp->Checksum = 0xffff;
							}

							EthSendIpPacketInnerIpRaw(e, data, sizeof(IPV4_HEADER) + sizeof(UDP_HEADER) + dhcp_packet_size, MAC_PROTO_IPV4);

							Free(data);
						}

						// Release the memory
						Free(dhcp);
						FreeBuf(b);
					}
					FreeDhcpOptions(o);
				}
			}
		}

		Free(opt);
	}

	return ret;
}

// Send an IP raw packet
void EthPutPacketLinuxIpRaw(ETH *e, void *data, UINT size)
{
	PKT *p;
	SOCK *s = NULL;
	// Validate arguments
	if (e == NULL || data == NULL)
	{
		return;
	}
	if (size < 14 || size > MAX_PACKET_SIZE || e->RawIp_HasError)
	{
		Free(data);
		return;
	}

	p = ParsePacket(data, size);
	if (p == NULL)
	{
		Free(data);
		return;
	}

	if (p->BroadcastPacket || Cmp(p->MacAddressDest, e->RawIpMyMacAddr, 6) == 0)
	{
		if (IsMacUnicast(p->MacAddressSrc))
		{
			Copy(e->RawIpYourMacAddr, p->MacAddressSrc, 6);
		}
	}

	if (IsZero(e->RawIpYourMacAddr, 6) || IsMacUnicast(p->MacAddressSrc) == false ||
	        (p->BroadcastPacket == false && Cmp(p->MacAddressDest, e->RawIpMyMacAddr, 6) != 0))
	{
		Free(data);
		FreePacket(p);
		return;
	}


	if (p->TypeL3 == L3_IPV4)
	{
		if (p->TypeL4 == L4_TCP)
		{
			if (IsZeroIP(&e->MyPhysicalIP) == false)
			{
				s = e->RawTcp;
			}
		}
		else if (p->TypeL4 == L4_UDP)
		{
			if (EthProcessIpPacketInnerIpRaw(e, p) == false)
			{
				s = e->RawUdp;
			}
		}
		else if (p->TypeL4 == L4_ICMPV4)
		{
			if (IsZeroIP(&e->MyPhysicalIP) == false)
			{
				s = e->RawIcmp;
			}
		}
		else if (p->TypeL4 == L4_FRAGMENT)
		{
			if (IsZeroIP(&e->MyPhysicalIP) == false)
			{
				s = e->RawIcmp;
			}
		}
	}
	else if (p->TypeL3 == L3_ARPV4)
	{
		EthProcessIpPacketInnerIpRaw(e, p);
	}

	if (s != NULL && p->L3.IPv4Header->DstIP != 0xffffffff && p->BroadcastPacket == false &&
	        p->L3.IPv4Header->SrcIP == IPToUINT(&e->YourIP))
	{
		UCHAR *send_data = p->IPv4PayloadData;
		UCHAR *head = p->PacketData;
		UINT remove_header_size = (UINT)(send_data - head);

		if (p->PacketSize > remove_header_size)
		{
			IP dest;
			UINT send_data_size = p->PacketSize - remove_header_size;

			// checksum
			if (p->TypeL4 == L4_UDP)
			{
				p->L4.UDPHeader->Checksum = 0;
			}
			else if (p->TypeL4 == L4_TCP)
			{
				p->L4.TCPHeader->Checksum = 0;
				p->L4.TCPHeader->Checksum = CalcChecksumForIPv4(IPToUINT(&e->MyPhysicalIP),
				                            p->L3.IPv4Header->DstIP, IP_PROTO_TCP,
				                            p->L4.TCPHeader, p->IPv4PayloadSize, 0);
			}

			UINTToIP(&dest, p->L3.IPv4Header->DstIP);

			if (s->RawIP_HeaderIncludeFlag == false)
			{
				SendTo(s, &dest, 0, send_data, send_data_size);
			}
			else
			{
				IPV4_HEADER *ip = p->L3.IPv4Header;

				ip->SrcIP = IPToUINT(&e->MyPhysicalIP);
				ip->Checksum = 0;
				ip->Checksum = IpChecksum(ip, IPV4_GET_HEADER_LEN(ip) * 4);

				SendTo(s, &dest, 0, ip, ((UCHAR *)p->PacketData - (UCHAR *)ip) + p->PacketSize);
			}
		}
	}

	FreePacket(p);
	Free(data);
}

#endif
