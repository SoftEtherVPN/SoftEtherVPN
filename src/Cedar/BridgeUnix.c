// SoftEther VPN Source Code
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


// BridgeUnix.c
// Ethernet Bridge Program (for UNIX)
//#define	BRIDGE_C
//#define	UNIX_LINUX

#include <GlobalConst.h>

#ifdef	BRIDGE_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

#ifdef UNIX_SOLARIS
#include <sys/sockio.h>
#endif

#ifdef BRIDGE_PCAP
#include <pcap.h>
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#endif // BRIDGE_BPF

#ifdef	UNIX_LINUX
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
	bool ret = false;

#if		defined(UNIX_LINUX)
	ret = IsEthSupportedLinux();
#elif	defined(UNIX_SOLARIS)
	ret = IsEthSupportedSolaris();
#elif	defined(BRIDGE_PCAP)
	ret = true;
#elif	defined(BRIDGE_BPF)
	ret = true;
#endif
	return ret;
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
			lifc.lifc_buf = (char*) buf;
			if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) >= 0)
			{
				for (i = 0; i<numifs; i++)
				{
					if(StartWith(buf[i].lifr_name, "lo") == false){
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

	for (i = 0;i < LIST_NUM(o);i++)
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
TOKEN_LIST *GetEthListLinux()
{
	struct ifreq ifr;
	TOKEN_LIST *t;
	UINT i, n;
	int s;
	LIST *o;
	char name[MAX_SIZE];

	o = NewListFast(CompareStr);

	s = UnixEthOpenRawSocket();
	if (s != INVALID_SOCKET)
	{
		n = 0;
		for (i = 0;;i++)
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
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char *name = LIST_DATA(o, i);
		t->Token[i] = name;
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
				if(datalink == DLT_EN10MB){
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
	for (i = 0;i < LIST_NUM(o);i++)
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
			sockadr = (struct sockaddr_dl*)ifadr->ifa_addr;
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
	for (i = 0;i < LIST_NUM(o);i++)
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
	TOKEN_LIST *t = NULL;

#if	defined(UNIX_LINUX)
	t = GetEthListLinux();
#elif	defined(UNIX_SOLARIS)
	t = GetEthListSolaris();
#elif	defined(BRIDGE_PCAP)
	t = GetEthListPcap();
#elif	defined(BRIDGE_BPF)
	t = GetEthListBpf();
#endif

	return t;
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

	if (tapmode)
	{
#ifndef	NO_VLAN
		// In tap mode
		VLAN *v = NewTap(name, tapaddr);
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
		// Enable promiscious mode
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
	UINT devid;
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
	if (ParseUnixEthDeviceName(devname, sizeof(devname), &devid, name) == false)
	{
		return NULL;
	}

	// Open the device
	fd = open(devname, O_RDWR);
	if (fd == -1)
	{
		// Failed
		return NULL;
	}

	// Attach to the device
	if (DlipAttatchRequest(fd, devid) == false)
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

// Attach to the device
bool DlipAttatchRequest(int fd, UINT devid)
{
	dl_attach_req_t req;
	struct strbuf ctl;
	int flags;
	// Validate arguments
	if (fd == -1)
	{
		return false;
	}

	Zero(&req, sizeof(req));
	req.dl_primitive = DL_ATTACH_REQ;
	req.dl_ppa = devid;

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

// Separate UNIX device name string into device name and id number
bool ParseUnixEthDeviceName(char *dst_devname, UINT dst_devname_size, UINT *dst_devid, char *src_name)
{
	UINT len, i, j;

	// Validate arguments
	if (dst_devname == NULL || dst_devid == NULL || src_name == NULL)
	{
		return false;
	}

	len = strlen(src_name);
	// Check string length
	if(len == 0)
	{
		return false;
	}

	for (i = len-1; i+1 != 0; i--)
	{
		// Find last non-numeric character
		if (src_name[i] < '0' || '9' < src_name[i])
		{
			// last character must be a number
			if(src_name[i+1]==0)
			{
				return false;
			}
			*dst_devid = ToInt(src_name + i + 1);
			StrCpy(dst_devname, dst_devname_size, "/dev/");
			for (j = 0; j<i+1 && j<dst_devname_size-6; j++)
			{
				dst_devname[j+5] = src_name[j];
			}
			dst_devname[j+5]=0;
			return true;
		}
	}
	// All characters in the string was numeric: error
	return false;
}

#if defined(BRIDGE_BPF) || defined(BRIDGE_PCAP)
// Initialize captured packet data structure
struct CAPTUREBLOCK *NewCaptureBlock(UCHAR *data, UINT size){
	struct CAPTUREBLOCK *block = Malloc(sizeof(struct CAPTUREBLOCK));
	block->Buf = data;
	block->Size = size;
	return block;
}

// Free captured packet data structure
void FreeCaptureBlock(struct CAPTUREBLOCK *block){
	Free(block);
}
#endif // BRIDGE_BPF || BRIDGE_PCAP

#ifdef	BRIDGE_PCAP
// Callback function to receive arriving packet (Pcap)
void PcapHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	ETH *e = (ETH*) user;
	struct CAPTUREBLOCK *block;
	UCHAR *data;
	
	data = Malloc(h->caplen);
	Copy(data, bytes, h->caplen);
	block = NewCaptureBlock(data, h->caplen);
	LockQueue(e->Queue);
	// Discard arriving packet when queue filled
	if(e->QueueSize < BRIDGE_MAX_QUEUE_SIZE){
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
	ETH *e = (ETH*)param;
	pcap_t *p = e->Pcap;
	int ret;

	// Notify initialize completed
	NoticeThreadInit(thread);

	// Return -1:Error -2:Terminated externally
	ret = pcap_loop(p, -1, PcapHandler, (u_char*) e);
	if(ret == -1){
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
	CANCEL *c;

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
	ETH *e = (ETH*)param;
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

	while(1){
		// Determining to exit loop
		if(e->Socket == INVALID_SOCKET){
			break;
		}
		
		rest = read(fd, buf, e->BufSize);
		if(rest < 0 && errno != EAGAIN){
			// Error
			close(fd);
			e->Socket = INVALID_SOCKET;
			Free(buf);
			Cancel(e->Cancel);
			return;
		}
		next = buf;
		LockQueue(e->Queue);
		while(rest>0){
			// Cut out a packet
			hdr = (struct bpf_hdr*)next;

			// Discard arriving packet when queue filled
			if(e->QueueSize < BRIDGE_MAX_QUEUE_SIZE){
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
	do{
		Format(devname, sizeof(devname), "/dev/bpf%d", n++);
		fd = open (devname, O_RDWR);
		if(fd<0){
			perror("open");
		}
	}while(fd < 0 && errno == EBUSY);
	
	// No free bpf device was found
	if(fd < 0){
		Debug("BPF: No minor number are free.\n");
		return NULL;
	}
	
	// Enlarge buffer size
	n = 524288; // Somehow(In libpcap, this size is 32768)
	while(true){
		// Specify buffer size
		ioctl(fd, BIOCSBLEN, &n);

		// Bind to the network device
		StrCpy(ifr.ifr_name, IFNAMSIZ, name);
		ret = ioctl(fd, BIOCSETIF, &ifr);
		if(ret < 0){
			if(ret == ENOBUFS && n>1500){
				// Inappropriate buffer size
				// Retry with half buffer size
				// If buffer size is under 1500 bytes, something goes wrong
				n /= 2;
				continue;
			}
			Debug("bpf: binding network failed.\n");
			close(fd);
			return NULL;
		}else{
			break;
		}
	}
	bufsize = n;

	// Set to promiscuous mode
	if(local == false){
		if (ioctl(fd, BIOCPROMISC, NULL) < 0){
			printf("bpf: promisc mode failed.\n");
			close(fd);
			return NULL;
		}
	}

	
	// Set to immediate mode (Return immediately when packet arrives)
	n = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &n) < 0){
		Debug("BPF: non-block mode failed.\n");
		close(fd);
		return NULL;
	}

	// Set receiving self sending packet
	n = 1;
	if (ioctl(fd, BIOCGSEESENT, &n) < 0){
		Debug("BPF: see sent mode failed.\n");
		close(fd);
		return NULL;
	}

	// Header complete mode (Generate whole header of sending packet)
	n = 1;
	if (ioctl(fd, BIOCSHDRCMPLT, &n) < 0){
		Debug("BPF: Header complete mode failed.\n");
		close(fd);
		return NULL;
	}
	
	// Set timeout delay to 1 second
	to.tv_sec = 1;
	to.tv_usec = 0;
	if (ioctl(fd, BIOCSRTIMEOUT, &to) < 0){
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

// Open Ethernet adapter
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr)
{
	ETH *ret = NULL;

#if		defined(UNIX_LINUX)
	ret = OpenEthLinux(name, local, tapmode, tapaddr);
#elif	defined(UNIX_SOLARIS)
	ret = OpenEthSolaris(name, local, tapmode, tapaddr);
#elif	defined(BRIDGE_PCAP)
	ret = OpenEthPcap(name, local, tapmode, tapaddr);
#elif	defined(BRIDGE_BPF)
	ret = OpenEthBpf(name, local, tapmode, tapaddr);
#endif

	return ret;
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
		while (block = GetNext(e->Queue)){
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
		while (block = GetNext(e->Queue)){
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
	UINT ret = 0;

#if		defined(UNIX_LINUX)
	ret = EthGetPacketLinux(e, data);
#elif	defined(UNIX_SOLARIS)
	ret = EthGetPacketSolaris(e, data);
#elif	defined(BRIDGE_PCAP)
	ret = EthGetPacketPcap(e, data);
#elif	defined(BRIDGE_BPF)
	ret = EthGetPacketBpf(e, data);
#endif

	return ret;
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
	// Validate arguments
	if (e == NULL || data == NULL)
	{
		return INFINITE;
	}

	if (e->Tap != NULL)
	{
#ifndef	NO_VLAN
		// tap mode
		void *buf;
		UINT size;

		if (VLanGetNextPacket(e->Tap, &buf, &size) == false)
		{
			return INFINITE;
		}

		*data = buf;
		return size;
#else	// NO_VLAN
		return INFINITE;
#endif
	}

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
	// Validate arguments
	if (e == NULL || data == NULL)
	{
		return INFINITE;
	}

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
	if(block != NULL){
		e->QueueSize -= block->Size;
	}
	UnlockQueue(e->Queue);
	
	if(block == NULL){
		*data = NULL;
		if(e->Socket == INVALID_SOCKET){
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
	if(block != NULL){
		e->QueueSize -= block->Size;
	}
	UnlockQueue(e->Queue);
	
	if(block == NULL){
		*data = NULL;
		if(e->Socket == INVALID_SOCKET){
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
	
	if(e->Rest<=0){
		e->Rest = read(e->Socket, e->Buffer, e->BufSize);
		if(e->Rest < 0){
			*data = NULL;
			if(errno != EAGAIN){
				// Error
				return INFINITE;
			}
			// No packet
			return 0;
		}
		e->Next = e->Buffer;
	}
	// Cut out a packet
	hdr = (struct bpf_hdr*)e->Next;
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

	for (i = 0;i < num;i++)
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
	if( ret == -1 ){
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

#endif	// BRIDGE_C



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
