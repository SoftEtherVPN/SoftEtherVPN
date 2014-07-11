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
// Contributors:
// - nattoheaven (https://github.com/nattoheaven)
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


// VLanUnix.c
// Virtual device driver library for UNIX

#include <GlobalConst.h>

#ifdef	VLAN_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#ifdef	UNIX_MACOS
#include <net/ethernet.h>
#endif

#ifdef	OS_UNIX

static LIST *unix_vlan = NULL;

#ifndef	NO_VLAN

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
VLAN *NewTap(char *name, char *mac_address)
{
	int fd;
	VLAN *v;
	// Validate arguments
	if (name == NULL || mac_address == NULL)
	{
		return NULL;
	}

	fd = UnixCreateTapDeviceEx(name, "tap", mac_address);
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
void FreeTap(VLAN *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	close(v->fd);
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

// Create a tap device
int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address)
{
	int fd;
	struct ifreq ifr;
	char eth_name[MAX_SIZE];
	char instance_name_lower[MAX_SIZE];
	struct sockaddr sa;
	char *tap_name = TAP_FILENAME_1;
	int s;
#ifdef	UNIX_MACOS
	char tap_macos_name[256] = TAP_MACOS_DIR TAP_MACOS_FILENAME;
#endif
	// Validate arguments
	if (name == NULL)
	{
		return -1;
	}

	// Generate the device name
	StrCpy(instance_name_lower, sizeof(instance_name_lower), name);
	Trim(instance_name_lower);
	StrLower(instance_name_lower);
	Format(eth_name, sizeof(eth_name), "%s_%s", prefix, instance_name_lower);

	eth_name[15] = 0;

	// Open the tun / tap
#ifndef	UNIX_MACOS
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
	// Other than MacOS X
	fd = open(TAP_FILENAME_1, O_RDWR);
	if (fd == -1)
	{
		// Failure
		fd = open(TAP_FILENAME_2, O_RDWR);
		if (fd == -1)
		{
			return -1;
		}
		tap_name = TAP_FILENAME_2;
	}
#else	// UNIX_MACOS
	{
		int i;
		fd = -1;
		for (i = 0; i < TAP_MACOS_NUMBER; i++) {
			sprintf(tap_macos_name + strlen(TAP_MACOS_DIR TAP_MACOS_FILENAME), "%d", i);
			fd = open(tap_macos_name, O_RDWR);
			if (fd != -1)
			{
				tap_name = tap_macos_name;
				break;
			}
		}
		if (fd == -1)
		{
			return -1;
		}
	}
#endif	// UNIX_MACOS

#ifdef	UNIX_LINUX
	// Create a tap for Linux

	// Set the device name
	Zero(&ifr, sizeof(ifr));

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);

	if (ioctl(fd, TUNSETIFF, &ifr) == -1)
	{
		// Failure
		close(fd);
		return -1;
	}

	// MAC address setting
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1)
	{
		if (mac_address != NULL)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);
			ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
			Copy(&ifr.ifr_addr.sa_data, mac_address, 6);
			ioctl(s, SIOCSIFHWADDR, &ifr);
		}

		Zero(&ifr, sizeof(ifr));
		StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), eth_name);
		ioctl(s, SIOCGIFFLAGS, &ifr);

		ifr.ifr_flags |= IFF_UP;
		ioctl(s, SIOCSIFFLAGS, &ifr);

		close(s);
	}

#else	// UNIX_LINUX
#ifdef	UNIX_MACOS
	// MAC address setting
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s != -1)
	{
		char *macos_eth_name;
		macos_eth_name = tap_macos_name + strlen(TAP_MACOS_DIR);

		if (mac_address != NULL)
		{
			Zero(&ifr, sizeof(ifr));
			StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), macos_eth_name);
			ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
			ifr.ifr_addr.sa_family = AF_LINK;
			Copy(&ifr.ifr_addr.sa_data, mac_address, ETHER_ADDR_LEN);
			ioctl(s, SIOCSIFLLADDR, &ifr);
		}

		Zero(&ifr, sizeof(ifr));
		StrCpy(ifr.ifr_name, sizeof(ifr.ifr_name), macos_eth_name);
		ioctl(s, SIOCGIFFLAGS, &ifr);

		ifr.ifr_flags |= IFF_UP;
		ioctl(s, SIOCSIFFLAGS, &ifr);

		close(s);
	}
#endif	// UNIX_MACOS
#ifdef	UNIX_SOLARIS
	// Create a tap for Solaris
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
#endif	// UNIX_LINUX

	return fd;
}
int UnixCreateTapDevice(char *name, UCHAR *mac_address)
{
	return UnixCreateTapDeviceEx(name, "vpn", mac_address);
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

#else	// NO_VLAN

void UnixCloseTapDevice(int fd)
{
}

int UnixCreateTapDeviceEx(char *name, char *prefix, UCHAR *mac_address)
{
	return -1;
}
int UnixCreateTapDevice(char *name, UCHAR *mac_address)
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
bool UnixVLanCreateEx(char *name, char *prefix, UCHAR *mac_address)
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
		fd = UnixCreateTapDeviceEx(name, prefix, mac_address);
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
bool UnixVLanCreate(char *name, UCHAR *mac_address)
{
	return UnixVLanCreateEx(name, "vpn", mac_address);
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
		Free(t);
	}

	ReleaseList(unix_vlan);
	unix_vlan = NULL;
}

#endif	// OS_UNIX

#endif	// VLAN_C


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
