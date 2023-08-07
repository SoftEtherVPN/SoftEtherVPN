// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// VLanUnix.c
// Virtual device driver library for UNIX

#ifdef UNIX

#include "VLanUnix.h"

#include "Connection.h"
#include "Session.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TunTap.h"

#ifdef UNIX_BSD
// For "sockaddr" in <net/if_arp.h>
#include <sys/socket.h>
#endif

#include <errno.h>
#include <fcntl.h> 
#include <net/if_arp.h>
#include <net/if.h>
#include <sys/ioctl.h>

#if defined(UNIX_OPENBSD) || defined(UNIX_SOLARIS)
#include <netinet/if_ether.h>
#else
#include <net/ethernet.h>
#endif

static LIST *unix_vlan = NULL;

#ifndef NO_VLAN

// Get the PACKET_ADAPTER
PACKET_ADAPTER *VLanGetPacketAdapter()
{
	PACKET_ADAPTER *pa;

	pa = NewPacketAdapter(VLanPaInit, VLanPaGetCancel,
		VLanPaGetNextPacket, VLanPaPutPacket, VLanPaFree);
	if (pa == NULL)
	{
		return NULL;
	}

	return pa;
}

// PA initialization
bool VLanPaInit(SESSION *s)
{
	VLAN *v;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	// Connect to the driver
	v = NewVLan(s->ClientOption->DeviceName, NULL);
	if (v == NULL)
	{
		// Failure
		return false;
	}

	s->PacketAdapter->Param = v;

	return true;
}

// Get the cancel object
CANCEL *VLanPaGetCancel(SESSION *s)
{
	VLAN *v;
	// Validate arguments
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return NULL;
	}

	return VLanGetCancel(v);
}

// Release the packet adapter
void VLanPaFree(SESSION *s)
{
	VLAN *v;
	// Validate arguments
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return;
	}

	// End the virtual LAN card
	FreeVLan(v);

	s->PacketAdapter->Param = NULL;
}

// Write a packet
bool VLanPaPutPacket(SESSION *s, void *data, UINT size)
{
	VLAN *v;
	// Validate arguments
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return false;
	}

	return VLanPutPacket(v, data, size);
}

// Get the next packet
UINT VLanPaGetNextPacket(SESSION *s, void **data)
{
	VLAN *v;
	UINT size;
	// Validate arguments
	if (data == NULL || (s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return INFINITE;
	}

	if (VLanGetNextPacket(v, data, &size) == false)
	{
		return INFINITE;
	}

	return size;
}

// Write a packet to the virtual LAN card
bool VLanPutPacket(VLAN *v, void *buf, UINT size)
{
	UINT ret;
	// Validate arguments
	if (v == NULL)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}
	if (size > MAX_PACKET_SIZE)
	{
		return false;
	}
	if (buf == NULL || size == 0)
	{
		if (buf != NULL)
		{
			Free(buf);
		}
		return true;
	}

	ret = write(v->fd, buf, size);

	if (ret >= 1)
	{
		Free(buf);
		return true;
	}

	if (errno == EAGAIN || ret == 0)
	{
		Free(buf);
		return true;
	}

	return false;
}

// Get the next packet from the virtual LAN card
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size)
{
	UCHAR tmp[TAP_READ_BUF_SIZE];
	int ret;
	// Validate arguments
	if (v == NULL || buf == NULL || size == 0)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}

	// Read
	ret = read(v->fd, tmp, sizeof(tmp));

	if (ret == 0 ||
		(ret == -1 && errno == EAGAIN))
	{
		// No packet
		*buf = NULL;
		*size = 0;
		return true;
	}
	else if (ret == -1 || ret > TAP_READ_BUF_SIZE)
	{
		// Error
		return false;
	}
	else
	{
		// Reading packet success
		*buf = Malloc(ret);
		Copy(*buf, tmp, ret);
		*size = ret;
		return true;
	}
}

// Get the cancel object
CANCEL *VLanGetCancel(VLAN *v)
{
	CANCEL *c;
	int fd;
	int yes = 0;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	c = NewCancel();
	UnixDeletePipe(c->pipe_read, c->pipe_write);
	c->pipe_read = c->pipe_write = -1;

	fd = v->fd;

	UnixSetSocketNonBlockingMode(fd, true);

	c->SpecialFlag = true;
	c->pipe_read = fd;

	return c;
}

// Close the Virtual LAN card
void FreeVLan(VLAN *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	Free(v->InstanceName);

	Free(v);
}

// Create a tap
VLAN *NewBridgeTap(char *name, char *mac_address, bool create_up)
{
	int fd;
	VLAN *v;
	// Validate arguments
	if (name == NULL || mac_address == NULL)
	{
		return NULL;
	}

	fd = UnixCreateTapDeviceEx(name, UNIX_VLAN_BRIDGE_IFACE_PREFIX, mac_address, create_up);
	if (fd == -1)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(VLAN));
	v->Halt = false;
	v->InstanceName = CopyStr(name);
	v->fd = fd;

	return v;
}

// Close the tap
void FreeBridgeTap(VLAN *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	UnixCloseTapDevice(v->fd);
#ifdef	UNIX_BSD
	UnixDestroyBridgeTapDevice(v->InstanceName);
#endif

	FreeVLan(v);
}

// Get the Virtual LAN card list
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param)
{
	int fd;
	VLAN *v;
	// Validate arguments
	if (instance_name == NULL)
	{
		return NULL;
	}

	// Open the tap
	fd = UnixVLanGet(instance_name);
	if (fd == -1)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(VLAN));
	v->Halt = false;
	v->InstanceName = CopyStr(instance_name);
	v->fd = fd;

	return v;
}

// Generate TUN interface name
void GenerateTunName(char *name, char *prefix, char *tun_name, size_t tun_name_len)
{
	char instance_name_lower[MAX_SIZE];

	// Generate the device name
	StrCpy(instance_name_lower, sizeof(instance_name_lower), name);
	Trim(instance_name_lower);
	StrLower(instance_name_lower);
	Format(tun_name, tun_name_len, "%s_%s", prefix, instance_name_lower);

	tun_name[15] = 0;
}
// Create a tap device
int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address, bool create_up)
{
	int fd = -1, s = -1;
	char tap_name[MAX_SIZE], tap_path[MAX_SIZE];
	struct ifreq ifr;

	// Validate arguments
	if (name == NULL)
	{
		return -1;
	}

	GenerateTunName(name, prefix, tap_name, sizeof(tap_name));

	// Open the tun / tap
#ifndef	UNIX_BSD
	if (GetOsInfo()->OsType == OSTYPE_LINUX)
	{
		// Linux
		if (IsFile(TAP_FILENAME_1) == false)
		{
			char tmp[MAX_SIZE];

			Format(tmp, sizeof(tmp), "%s c 10 200", TAP_FILENAME_1);
			Run("mknod", tmp, true, true);

			Format(tmp, sizeof(tmp), "600 %s", TAP_FILENAME_1);
			Run("chmod", tmp, true, true);
		}
	}

	fd = open(TAP_FILENAME_1, O_RDWR);
	if (fd == -1)
	{
		// Failure
		fd = open(TAP_FILENAME_2, O_RDWR);
		if (fd == -1)
		{
			return -1;
		}
	}
#else	// UNIX_BSD
	{
		sprintf(tap_path, "%s", TAP_DIR TAP_NAME);
		for (int i = 0; i < TAP_MAX; i++) {
			sprintf(tap_path + StrLen(TAP_DIR TAP_NAME), "%d", i);
			fd = open(tap_path, O_RDWR);
			if (fd != -1)
			{
				break;
			}
		}

		if (fd == -1)
		{
			return -1;
		}
	}
#endif	// UNIX_BSD

#ifdef	UNIX_LINUX
	// Create a TAP device for Linux

	// Set the name and the flags
	Zero(&ifr, sizeof(ifr));
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_name);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (ioctl(fd, TUNSETIFF, &ifr) == -1)
	{
		// Failure
		close(fd);
		return -1;
	}

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1)
	{
		// Set the MAC address
		if (mac_address != NULL)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_name);
			ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
			Copy(&ifr.ifr_hwaddr.sa_data, mac_address, ETHER_ADDR_LEN);
			ioctl(s, SIOCSIFHWADDR, &ifr);
		}

		if (create_up)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_name);
			ioctl(s, SIOCGIFFLAGS, &ifr);
			ifr.ifr_flags |= IFF_UP;
			ioctl(s, SIOCSIFFLAGS, &ifr);
		}

		close(s);
	}
#endif	// UNIX_LINUX

#ifdef	UNIX_BSD
	// Create a TAP device for BSD
	Zero(&ifr, sizeof(ifr));

	// Get the current name
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_path + StrLen(TAP_DIR));

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1)
	{
		// Set the name, if possible
#ifdef	SIOCSIFNAME
		ifr.ifr_data = tap_name;
		ioctl(s, SIOCSIFNAME, &ifr);
#else	// SIOCSIFNAME
		StrCpy(tap_name, sizeof(tap_name), ifr.ifr_name);
#endif	// SIOCSIFNAME

		// Set the MAC address
		if (mac_address != NULL)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_name);
			ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
			ifr.ifr_addr.sa_family = AF_LINK;
			Copy(&ifr.ifr_addr.sa_data, mac_address, ETHER_ADDR_LEN);
			ioctl(s, SIOCSIFLLADDR, &ifr);
		}

		// Set interface description
#ifdef	SIOCSIFDESCR
		{
			char desc[] = CEDAR_PRODUCT_STR " Virtual Network Adapter";

			ifr.ifr_buffer.buffer = desc;
			ifr.ifr_buffer.length = StrLen(desc) + 1;
			ioctl(s, SIOCSIFDESCR, &ifr);
		}
#endif

		// Set interface group
		UnixSetIfGroup(s, tap_name, CEDAR_PRODUCT_STR);

		if (create_up)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), tap_name);
			ioctl(s, SIOCGIFFLAGS, &ifr);
			ifr.ifr_flags |= IFF_UP;
			ioctl(s, SIOCSIFFLAGS, &ifr);
		}

		close(s);
	}
#endif	// UNIX_BSD

#ifdef	UNIX_SOLARIS
	// Create a TAP device for Solaris
	{
		int ip_fd;
		int tun_fd;
		int ppa;

		tun_fd = open(tap_name, O_RDWR);
		if (tun_fd == -1)
		{
			// Failure
			close(fd);
			return -1;
		}

		ip_fd = open("/dev/ip", O_RDWR);
		if (ip_fd == -1)
		{
			// Failure
			close(tun_fd);
			close(fd);
			return -1;
		}

		ppa = -1;
		ppa = ioctl(tun_fd, TUNNEWPPA, ppa);
		if (ppa == -1)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(fd, I_PUSH, "ip") < 0)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(fd, IF_UNITSEL, (char *)&ppa) < 0)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		if (ioctl(ip_fd, I_LINK, fd) < 0)
		{
			// Failure
			close(tun_fd);
			close(fd);
			close(ip_fd);
			return -1;
		}

		close(tun_fd);
		close(ip_fd);
	}
#endif	// UNIX_SOLARIS

	return fd;
}
int UnixCreateTapDevice(char *name, UCHAR *mac_address, bool create_up)
{
	return UnixCreateTapDeviceEx(name, UNIX_VLAN_CLIENT_IFACE_PREFIX, mac_address, create_up);
}

// Close the tap device
void UnixCloseTapDevice(int fd)
{
	// Validate arguments
	if (fd == -1)
	{
		return;
	}

	close(fd);
}

// Destroy the tap device (for FreeBSD)
// FreeBSD tap device is still plumbed after closing fd so need to destroy after close
void UnixDestroyTapDeviceEx(char *name, char *prefix)
{
#ifdef UNIX_BSD
	struct ifreq ifr;
	char eth_name[MAX_SIZE];
	int s;

	Zero(&ifr, sizeof(ifr));
	GenerateTunName(name, prefix, eth_name, sizeof(eth_name));
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
	{
		return;
	}
	ioctl(s, SIOCIFDESTROY, &ifr);

	close(s);
#endif	// UNIX_BSD
}

void UnixDestroyBridgeTapDevice(char *name)
{
#ifdef UNIX_BSD
	UnixDestroyTapDeviceEx(name, UNIX_VLAN_BRIDGE_IFACE_PREFIX);
#endif	// UNIX_BSD
}

void UnixDestroyClientTapDevice(char *name)
{
#ifdef UNIX_BSD
	UnixDestroyTapDeviceEx(name, UNIX_VLAN_CLIENT_IFACE_PREFIX);
#endif	// UNIX_BSD
}

void UnixSetIfGroup(int fd, const char *name, const char *group_name)
{
#ifdef	SIOCAIFGROUP
	struct ifgroupreq ifgr;
	char *tmp;

	tmp = CopyStr((char *)group_name);
	StrLower(tmp);
	Zero(&ifgr, sizeof(ifgr));

	StrCpy(ifgr.ifgr_name, sizeof(ifgr.ifgr_name), (char *) name);
	StrCpy(ifgr.ifgr_group, sizeof(ifgr.ifgr_group), tmp);
	ioctl(fd, SIOCAIFGROUP, &ifgr);

	Free(tmp);
#endif
}

#else	// NO_VLAN

void UnixCloseDevice(int fd)
{
}

void UnixDestroyTapDevice(char *name)
{
}

void UnixDestroyTapDeviceEx(char *name, char *prefix)
{
}

void UnixSetIfGroup()
{
}

int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address, bool create_up)
{
	return -1;
}
int UnixCreateTapDevice(char *name, UCHAR *mac_address, bool create_up)
{
	return -1;
}

#endif	// NO_VLAN

// Comparison of the VLAN list entries
int UnixCompareVLan(void *p1, void *p2)
{
	UNIX_VLAN_LIST *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(UNIX_VLAN_LIST **)p1;
	v2 = *(UNIX_VLAN_LIST **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return StrCmpi(v1->Name, v2->Name);
}

// Initialize the VLAN list
void UnixVLanInit()
{
	unix_vlan = NewList(UnixCompareVLan);
}

// Create a VLAN
bool UnixVLanCreateEx(char *name, char *prefix, UCHAR *mac_address, bool create_up)
{
	// Validate arguments
	char tmp[MAX_SIZE];
	if (name == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), name);
	Trim(tmp);
	name = tmp;

	LockList(unix_vlan);
	{
		UNIX_VLAN_LIST *t, tt;
		int fd;

		// Check whether a device with the same name exists
		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			// Already exist
			UnlockList(unix_vlan);
			return false;
		}

		// Create a tap device
		fd = UnixCreateTapDeviceEx(name, prefix, mac_address, create_up);
		if (fd == -1)
		{
			// Failure to create
			UnlockList(unix_vlan);
			return false;
		}

		t = ZeroMalloc(sizeof(UNIX_VLAN_LIST));
		t->fd = fd;
		StrCpy(t->Name, sizeof(t->Name), name);

		Insert(unix_vlan, t);
	}
	UnlockList(unix_vlan);

	return true;
}
bool UnixVLanCreate(char *name, UCHAR *mac_address, bool create_up)
{
	return UnixVLanCreateEx(name, UNIX_VLAN_CLIENT_IFACE_PREFIX, mac_address, create_up);
}

// Set a VLAN up/down
bool UnixVLanSetState(char* name, bool state_up)
{
#if defined(UNIX_LINUX) || defined(UNIX_BSD)
	UNIX_VLAN_LIST *t, tt;
	struct ifreq ifr;
	int s;
	char eth_name[MAX_SIZE];

	LockList(unix_vlan);
	{
		int result;
		// Find a device with the same name
		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t == NULL)
		{
			// No such device
			UnlockList(unix_vlan);
			return false;
		}

		GenerateTunName(name, UNIX_VLAN_CLIENT_IFACE_PREFIX, eth_name, sizeof(eth_name));
		Zero(&ifr, sizeof(ifr));
		StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);

		s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s == -1)
		{
			// Failed to create socket
			UnlockList(unix_vlan);
			return false;
		}

		ioctl(s, SIOCGIFFLAGS, &ifr);
		if (state_up)
		{
			ifr.ifr_flags |= IFF_UP;
		}
		else
		{
			ifr.ifr_flags &= ~IFF_UP;
		}
		result = ioctl(s, SIOCSIFFLAGS, &ifr);
		close(s);
	}
	UnlockList(unix_vlan);
#endif // UNIX_LINUX || UNIX_BSD

	return true;
}

// Enumerate VLANs
TOKEN_LIST *UnixVLanEnum()
{
	TOKEN_LIST *ret;
	UINT i;
	if (unix_vlan == NULL)
	{
		return NullToken();
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));

	LockList(unix_vlan);
	{
		ret->NumTokens = LIST_NUM(unix_vlan);
		ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);

		for (i = 0;i < ret->NumTokens;i++)
		{
			UNIX_VLAN_LIST *t = LIST_DATA(unix_vlan, i);

			ret->Token[i] = CopyStr(t->Name);
		}
	}
	UnlockList(unix_vlan);

	return ret;
}

// Delete the VLAN
void UnixVLanDelete(char *name)
{
	// Validate arguments
	if (name == NULL || unix_vlan == NULL)
	{
		return;
	}

	LockList(unix_vlan);
	{
		UINT i;
		UNIX_VLAN_LIST *t, tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			UnixCloseTapDevice(t->fd);
#ifdef UNIX_BSD
			UnixDestroyClientTapDevice(t->Name);
#endif
			Delete(unix_vlan, t);
			Free(t);
		}
	}
	UnlockList(unix_vlan);
}

// Get the VLAN
int UnixVLanGet(char *name)
{
	int fd = -1;
	// Validate arguments
	if (name == NULL || unix_vlan == NULL)
	{
		return -1;
	}

	LockList(unix_vlan);
	{
		UINT i;
		UNIX_VLAN_LIST *t, tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), name);

		t = Search(unix_vlan, &tt);
		if (t != NULL)
		{
			fd = t->fd;
		}
	}
	UnlockList(unix_vlan);

	return fd;
}

// Release the VLAN list
void UnixVLanFree()
{
	UINT i;

	for (i = 0;i < LIST_NUM(unix_vlan);i++)
	{
		UNIX_VLAN_LIST *t = LIST_DATA(unix_vlan, i);

		UnixCloseTapDevice(t->fd);
#ifdef UNIX_BSD
		UnixDestroyClientTapDevice(t->Name);
#endif
		Free(t);
	}

	ReleaseList(unix_vlan);
	unix_vlan = NULL;
}

#endif
