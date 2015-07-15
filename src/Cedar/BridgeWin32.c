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


// BridgeWin32.c
// Ethernet Bridge Program (Win32)

#include <GlobalConst.h>

#ifdef	BRIDGE_C

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Packet32.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>


static WP *wp = NULL;
static LIST *eth_list = NULL;

static LOCK *eth_list_lock = NULL;
static bool is_see_mode = false;
static bool is_using_selow = false;
static bool enable_selow = true;

static bool g_bridge_win32_show_all_if = false;

#define	LOAD_DLL_ADDR(name)				\
	{									\
		void *addr = GetProcAddress(h, #name);	\
		Copy(&wp->name, &addr, sizeof(void *));	\
	}

// Set the flag which indicates whether using SeLow
void Win32SetEnableSeLow(bool b)
{
	enable_selow = b;
}

// Get the flag which indicates whether using SeLow
bool Win32GetEnableSeLow()
{
	return enable_selow;
}

// Set the flag which indicates whether enumerating all interfaces
void Win32EthSetShowAllIf(bool b)
{
	g_bridge_win32_show_all_if = b;
}

// Get the flag which indicates whether enumerating all interfaces
bool Win32EthGetShowAllIf()
{
	return g_bridge_win32_show_all_if;
}

// Compare Ethernet device list
int CmpRpcEnumEthVLan(void *p1, void *p2)
{
	RPC_ENUM_ETH_VLAN_ITEM *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *((RPC_ENUM_ETH_VLAN_ITEM **)p1);
	v2 = *((RPC_ENUM_ETH_VLAN_ITEM **)p2);
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return StrCmpi(v1->DeviceName, v2->DeviceName);
}

// Get the value of MTU (Not supported in Windows)
UINT EthGetMtu(ETH *e)
{
	return 0;
}

// Set the value of MTU (Not supported in Windows)
bool EthSetMtu(ETH *e, UINT mtu)
{
	return false;
}

// Check whether setting MEU value (Not supported in Windows)
bool EthIsChangeMtuSupported(ETH *e)
{
	return false;
}

// Set the state of VLAN tag pass-through 
bool SetVLanEnableStatus(char *title, bool enable)
{
	RPC_ENUM_ETH_VLAN t;
	RPC_ENUM_ETH_VLAN_ITEM *e;
	bool ret = false;
	char key[MAX_SIZE];
	char tcpkey[MAX_SIZE];
	char short_key[MAX_SIZE];
	// Validate arguments
	if (title == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (EnumEthVLanWin32(&t) == false)
	{
		return false;
	}

	e = FindEthVLanItem(&t, title);

	if (e != NULL)
	{
		if (GetClassRegKeyWin32(key, sizeof(key), short_key, sizeof(short_key), e->Guid))
		{
			if (StrCmpi(e->DriverType, "Intel") == 0)
			{
				if (enable)
				{
					MsRegWriteStr(REG_LOCAL_MACHINE, key, "VlanFiltering", "0");
					MsRegWriteStr(REG_LOCAL_MACHINE, key, "TaggingMode", "0");
					MsRegWriteInt(REG_LOCAL_MACHINE, key, "MonitorMode", 1);
					MsRegWriteInt(REG_LOCAL_MACHINE, key, "MonitorModeEnabled", 1);
				}
				else
				{
					if (MsRegReadInt(REG_LOCAL_MACHINE, key, "TaggingMode") == 0)
					{
						MsRegDeleteValue(REG_LOCAL_MACHINE, key, "TaggingMode");
					}

					if (MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorMode") == 1)
					{
						MsRegDeleteValue(REG_LOCAL_MACHINE, key, "MonitorMode");
					}

					if (MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorModeEnabled") == 1)
					{
						MsRegDeleteValue(REG_LOCAL_MACHINE, key, "MonitorModeEnabled");
					}
				}

				ret = true;
			}
			else if (StrCmpi(e->DriverType, "Broadcom") == 0)
			{
				if (enable)
				{
					MsRegWriteStr(REG_LOCAL_MACHINE, key, "PreserveVlanInfoInRxPacket", "1");
				}
				else
				{
					MsRegDeleteValue(REG_LOCAL_MACHINE, key, "PreserveVlanInfoInRxPacket");
				}

				ret = true;
			}
			else if (StrCmpi(e->DriverType, "Marvell") == 0)
			{
				if (enable)
				{
					MsRegWriteInt(REG_LOCAL_MACHINE, key, "SkDisableVlanStrip", 1);
				}
				else
				{
					MsRegDeleteValue(REG_LOCAL_MACHINE, key, "SkDisableVlanStrip");
				}

				ret = true;
			}

			Format(tcpkey, sizeof(tcpkey),
				"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
				e->Guid);

			if (enable)
			{
				if (MsRegIsValue(REG_LOCAL_MACHINE, tcpkey, "MTU") == false)
				{
					MsRegWriteInt(REG_LOCAL_MACHINE, tcpkey, "MTU", 1500);
				}
			}
			else
			{
				UINT mtu = MsRegReadInt(REG_LOCAL_MACHINE, tcpkey, "MTU");
				if (mtu == 1500)
				{
					MsRegDeleteValue(REG_LOCAL_MACHINE, tcpkey, "MTU");
				}
			}
		}
	}

	FreeRpcEnumEthVLan(&t);

	return ret;
}

// Find Ethernet device
RPC_ENUM_ETH_VLAN_ITEM *FindEthVLanItem(RPC_ENUM_ETH_VLAN *t, char *name)
{
	UINT i;
	// Validate arguments
	if (t == NULL || name == NULL)
	{
		return NULL;
	}

	for (i = 0;i < t->NumItem;i++)
	{
		if (StrCmpi(t->Items[i].DeviceName, name) == 0)
		{
			return &t->Items[i];
		}
	}

	return NULL;
}

// Get the state of VLAN tag pass-through 
void GetVLanEnableStatus(RPC_ENUM_ETH_VLAN_ITEM *e)
{
	char key[MAX_SIZE];
	char short_key[MAX_SIZE];
	char tcpkey[MAX_SIZE];
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	e->Enabled = false;

	if (e->Support == false)
	{
		return;
	}

	if (GetClassRegKeyWin32(key, sizeof(key), short_key, sizeof(short_key), e->Guid) == false)
	{
		return;
	}

	Format(tcpkey, sizeof(tcpkey),
		"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
		e->Guid);

	if (StrCmpi(e->DriverType, "Intel") == 0)
	{
		char *VlanFiltering = MsRegReadStr(REG_LOCAL_MACHINE, key, "VlanFiltering");
		UINT MonitorMode = MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorMode");
		UINT MonitorModeEnabled = MsRegReadInt(REG_LOCAL_MACHINE, key, "MonitorModeEnabled");
		char *TaggingMode = MsRegReadStr(REG_LOCAL_MACHINE, key, "TaggingMode");

		if (StrCmpi(VlanFiltering, "0") == 0 &&
			MonitorMode == 1 &&
			MonitorModeEnabled == 1 &&
			StrCmpi(TaggingMode, "0") == 0)
		{
			e->Enabled = true;
		}

		Free(VlanFiltering);
		Free(TaggingMode);
	}
	else if (StrCmpi(e->DriverType, "Broadcom") == 0)
	{
		char *PreserveVlanInfoInRxPacket = MsRegReadStr(REG_LOCAL_MACHINE,
			key, "PreserveVlanInfoInRxPacket");

		if (StrCmpi(PreserveVlanInfoInRxPacket, "1") == 0)
		{
			e->Enabled = true;
		}

		Free(PreserveVlanInfoInRxPacket);
	}
	else if (StrCmpi(e->DriverType, "Marvell") == 0)
	{
		DWORD SkDisableVlanStrip = MsRegReadInt(REG_LOCAL_MACHINE,
			key, "SkDisableVlanStrip");

		if (SkDisableVlanStrip == 1)
		{
			e->Enabled = true;
		}
	}

	if (MsRegIsValue(REG_LOCAL_MACHINE, tcpkey, "MTU") == false)
	{
		e->Enabled = false;
	}
}

// Get VLAN tag pass-through availability of the device
void GetVLanSupportStatus(RPC_ENUM_ETH_VLAN_ITEM *e)
{
	BUF *b;
	char filename[MAX_SIZE];
	void *wow;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	wow = MsDisableWow64FileSystemRedirection();

	// Read the device driver file
	CombinePath(filename, sizeof(filename), MsGetSystem32Dir(), "drivers");
	CombinePath(filename, sizeof(filename), filename, e->DriverName);

	b = ReadDump(filename);

	if (b != NULL)
	{
		char intel1[] = "VlanFiltering";
		char intel2[] = "V\0l\0a\0n\0F\0i\0l\0t\0e\0r\0i\0n\0g";
		char intel3[] = "MonitorMode";
		char intel4[] = "M\0o\0n\0i\0t\0o\0r\0M\0o\0d\0e";
		char intel5[] = "TaggingMode";
		char intel6[] = "T\0a\0g\0g\0i\0n\0g\0M\0o\0d\0e";
		char broadcom1[] = "PreserveVlanInfoInRxPacket";
		char broadcom2[] = "P\0r\0e\0s\0e\0r\0v\0e\0V\0l\0a\0n\0I\0n\0f\0o\0I\0n\0R\0x\0P\0a\0c\0k\0e\0t";
		char marvell1[] = "SkDisableVlanStrip";
		char marvell2[] = "S\0k\0D\0i\0s\0a\0b\0l\0e\0V\0l\0a\0n\0S\0t\0r\0i\0p";
		char *driver_type = "";

		if (SearchBin(b->Buf, 0, b->Size, intel1, sizeof(intel1)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel2, sizeof(intel2)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel3, sizeof(intel3)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel4, sizeof(intel4)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel5, sizeof(intel5)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, intel6, sizeof(intel6)) != INFINITE)
		{
			driver_type = "Intel";
		}
		else if (SearchBin(b->Buf, 0, b->Size, broadcom1, sizeof(broadcom1)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, broadcom2, sizeof(broadcom2)) != INFINITE)
		{
			driver_type = "Broadcom";
		}
		else if (SearchBin(b->Buf, 0, b->Size, marvell1, sizeof(marvell1)) != INFINITE
			|| SearchBin(b->Buf, 0, b->Size, marvell2, sizeof(marvell2)) != INFINITE)
		{
			driver_type = "Marvell";
		}

		if (IsEmptyStr(driver_type) == false)
		{
			StrCpy(e->DriverType, sizeof(e->DriverType), driver_type);
			e->Support = true;
		}

		FreeBuf(b);
	}

	MsRestoreWow64FileSystemRedirection(wow);
}

// Get the device instance id from short_key
char *SearchDeviceInstanceIdFromShortKey(char *short_key)
{
	char *ret = NULL;
	TOKEN_LIST *t1;
	// Validate arguments
	if (short_key == NULL)
	{
		return NULL;
	}

	t1 = MsRegEnumKey(REG_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum");

	if (t1 != NULL)
	{
		TOKEN_LIST *t2;
		char tmp[MAX_SIZE];
		UINT i;

		for (i = 0;i < t1->NumTokens;i++)
		{
			Format(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Enum\\%s", t1->Token[i]);

			t2 = MsRegEnumKey(REG_LOCAL_MACHINE, tmp);

			if (t2 != NULL)
			{
				TOKEN_LIST *t3;
				UINT i;

				for (i = 0;i < t2->NumTokens;i++)
				{
					char tmp2[MAX_SIZE];

					Format(tmp2, sizeof(tmp2), "%s\\%s", tmp, t2->Token[i]);

					t3 = MsRegEnumKey(REG_LOCAL_MACHINE, tmp2);

					if (t3 != NULL)
					{
						UINT i;

						for (i = 0;i < t3->NumTokens;i++)
						{
							char tmp3[MAX_SIZE];
							char *s;

							Format(tmp3, sizeof(tmp3), "%s\\%s", tmp2, t3->Token[i]);

							s = MsRegReadStr(REG_LOCAL_MACHINE, tmp3, "Driver");

							if (s != NULL)
							{
								if (StrCmpi(s, short_key) == 0)
								{
									if (ret != NULL)
									{
										Free(ret);
									}

									ret = CopyStr(tmp3 + StrLen("SYSTEM\\CurrentControlSet\\Enum\\"));
								}

								Free(s);
							}
						}

						FreeToken(t3);
					}
				}

				FreeToken(t2);
			}
		}

		FreeToken(t1);
	}

	return ret;
}

// Get VLAN tag pass-through availability of all devices
bool EnumEthVLanWin32(RPC_ENUM_ETH_VLAN *t)
{
	UINT i;
	LIST *o;
	// Validate arguments
	if (t == NULL)
	{
		return false;
	}

	Zero(t, sizeof(RPC_ENUM_ETH_VLAN));

	if (MsIsWin2000OrGreater() == false)
	{
		return false;
	}

	if (IsEthSupported() == false)
	{
		return false;
	}

	// Get device list
	Lock(eth_list_lock);

	InitEthAdaptersList();

	o = NewListFast(CmpRpcEnumEthVLan);

	for (i = 0;i < LIST_NUM(eth_list);i++)
	{
		WP_ADAPTER *a = LIST_DATA(eth_list, i);

		if (IsEmptyStr(a->Guid) == false)
		{
			char class_key[MAX_SIZE];
			char short_key[MAX_SIZE];

			if (GetClassRegKeyWin32(class_key, sizeof(class_key),
				short_key, sizeof(short_key), a->Guid))
			{
				char *device_instance_id = MsRegReadStr(REG_LOCAL_MACHINE, class_key, "DeviceInstanceID");

				if (IsEmptyStr(device_instance_id))
				{
					Free(device_instance_id);
					device_instance_id = SearchDeviceInstanceIdFromShortKey(short_key);
				}

				if (IsEmptyStr(device_instance_id) == false)
				{
					char device_key[MAX_SIZE];
					char *service_name;

					Format(device_key, sizeof(device_key), "SYSTEM\\CurrentControlSet\\Enum\\%s",
						device_instance_id);

					service_name = MsRegReadStr(REG_LOCAL_MACHINE, device_key, "Service");
					if (IsEmptyStr(service_name) == false)
					{
						char service_key[MAX_SIZE];
						char *sys;

						Format(service_key, sizeof(service_key),
							"SYSTEM\\CurrentControlSet\\services\\%s",
							service_name);

						sys = MsRegReadStr(REG_LOCAL_MACHINE, service_key, "ImagePath");

						if (IsEmptyStr(sys) == false)
						{
							char sysname[MAX_PATH];

							GetFileNameFromFilePath(sysname, sizeof(sysname), sys);

							Trim(sysname);

							if (EndWith(sysname, ".sys"))
							{
								// device found
								RPC_ENUM_ETH_VLAN_ITEM *e = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM));

								StrCpy(e->DeviceName, sizeof(e->DeviceName), a->Title);
								StrCpy(e->Guid, sizeof(e->Guid), a->Guid);
								StrCpy(e->DeviceInstanceId, sizeof(e->DeviceInstanceId), device_instance_id);
								StrCpy(e->DriverName, sizeof(e->DriverName), sysname);

								// Get VLAN tag pass-through availability of the device
								GetVLanSupportStatus(e);

								// Get current pass-through setting of the device
								GetVLanEnableStatus(e);

								Insert(o, e);
							}
						}

						Free(sys);
					}

					Free(service_name);
				}

				Free(device_instance_id);
			}
		}
	}

	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_ETH_VLAN_ITEM) * i);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = LIST_DATA(o, i);

		Copy(&t->Items[i], e, sizeof(RPC_ENUM_ETH_VLAN_ITEM));

		Free(e);
	}

	ReleaseList(o);

	Unlock(eth_list_lock);

	return true;
}

// Get registry key of the network class data by GUID
bool GetClassRegKeyWin32(char *key, UINT key_size, char *short_key, UINT short_key_size, char *guid)
{
	TOKEN_LIST *t;
	bool ret = false;
	UINT i;
	// Validate arguments
	if (key == NULL || short_key == NULL || guid == NULL)
	{
		return false;
	}

	t = MsRegEnumKey(REG_LOCAL_MACHINE,
		"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
	if (t == NULL)
	{
		return false;
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		char keyname[MAX_SIZE];
		char *value;

		Format(keyname, sizeof(keyname),
			"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s",
			t->Token[i]);

		value = MsRegReadStr(REG_LOCAL_MACHINE, keyname, "NetCfgInstanceId");

		if (StrCmpi(value, guid) == 0)
		{
			ret = true;

			StrCpy(key, key_size, keyname);

			Format(short_key, short_key_size, "{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s",
				t->Token[i]);
		}

		Free(value);
	}

	FreeToken(t);

	return ret;
}

// Send multiple packets
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes)
{
	UINT i, total_size;
	UCHAR *buf;
	UINT write_pointer;
	UINT err = 0;
	// Validate arguments
	if (e == NULL || num == 0 || datas == NULL || sizes == NULL)
	{
		return;
	}
	if (e->HasFatalError)
	{
		return;
	}

	if (e->SuAdapter != NULL)
	{
		bool ok = true;

		// Send packets with SeLow
		for (i = 0;i < num;i++)
		{
			UCHAR *data = datas[i];
			UINT size = sizes[i];

			if (ok)
			{
				// Actually, only enqueuing
				ok = SuPutPacket(e->SuAdapter, data, size);
			}

			if (ok == false)
			{
				// Free memory on write error
				Free(data);
			}
		}

		if (ok)
		{
			// Send all data in queue at once
			ok = SuPutPacket(e->SuAdapter, NULL, 0);
		}

		if (ok == false)
		{
			// Error occurred
			e->HasFatalError = true;
		}

		return;
	}

	if (IsWin32BridgeWithSee() == false)
	{
		if (e->LastSetSingleCpu == 0 || (e->LastSetSingleCpu + 10000) <= Tick64())
		{
			e->LastSetSingleCpu = Tick64();
			MsSetThreadSingleCpu();
		}
	}

	// Calculate buffer size
	total_size = 0;
	for (i = 0;i < num;i++)
	{
		void *data = datas[i];
		UINT size = sizes[i];
		if (data != NULL && size >= 14 && size <= MAX_PACKET_SIZE)
		{
			total_size += size + sizeof(struct dump_bpf_hdr);
		}
	}

	buf = MallocFast(total_size * 100 / 75 + 1600);

	write_pointer = 0;
	// Enqueue
	for (i = 0;i < num;i++)
	{
		void *data = datas[i];
		UINT size = sizes[i];
		if (data != NULL && size >= 14 && size <= MAX_PACKET_SIZE)
		{
			struct dump_bpf_hdr *h;

			h = (struct dump_bpf_hdr *)(buf + write_pointer);
			Zero(h, sizeof(struct dump_bpf_hdr));
			h->caplen = h->len = size;
			write_pointer += sizeof(struct dump_bpf_hdr);
			Copy(buf + write_pointer, data, size);
			write_pointer += size;

			PROBE_DATA2("EthPutPackets", data, size);
		}
		// Free original buffer
		Free(data);
	}

	// Send
	if (total_size != 0)
	{
		err = wp->PacketSendPackets(e->Adapter, buf, total_size, true);
	}

	Free(buf);

	if (err == 0x7FFFFFFF)
	{
		// Critical error (infinite loop) occurred on sending
		e->HasFatalError = true;
	}
}

// Send a packet
void EthPutPacket(ETH *e, void *data, UINT size)
{
	// Validate arguments
	if (e == NULL || data == NULL || size == 0)
	{
		return;
	}

	EthPutPackets(e, 1, &data, &size);
}

// Read next packet
UINT EthGetPacket(ETH *e, void **data)
{
	BLOCK *b;
	bool flag = false;
	// Validate arguments
	if (e == NULL || data == NULL)
	{
		return INFINITE;
	}
	if (e->HasFatalError)
	{
		return INFINITE;
	}

	if (e->SuAdapter != NULL)
	{
		// Read packet with SeLow
		UINT size;
		if (SuGetNextPacket(e->SuAdapter, data, &size) == false)
		{
			// Error occurred
			e->HasFatalError = true;
			return INFINITE;
		}

		return size;
	}

RETRY:
	// Check the presence of the packet in queue
	b = GetNext(e->PacketQueue);
	if (b != NULL)
	{
		UINT size;
		size = b->Size;
		*data = b->Buf;
		Free(b);

		if (e->PacketQueue->num_item == 0)
		{
			e->Empty = true;
		}

		return size;
	}

	if (e->Empty)
	{
		e->Empty = false;
		return 0;
	}

	if (flag == false)
	{
		// Try to get next packet
		PROBE_STR("EthGetPacket: PacketInitPacket");
		wp->PacketInitPacket(e->Packet, e->Buffer, e->BufferSize);
		PROBE_STR("EthGetPacket: PacketReceivePacket");
		if (wp->PacketReceivePacket(e->Adapter, e->Packet, false) == false)
		{
			// Failed
			return INFINITE;
		}
		else
		{
			UCHAR *buf;
			UINT total;
			UINT offset;

			buf = (UCHAR *)e->Packet->Buffer;
			total = e->Packet->ulBytesReceived;
			offset = 0;

			while (offset < total)
			{
				struct bpf_hdr *header;
				UINT packet_size;
				UCHAR *packet_data;

				header = (struct bpf_hdr *)(buf + offset);
				packet_size = header->bh_caplen;
				offset += header->bh_hdrlen;
				packet_data = buf + offset;
				offset = Packet_WORDALIGN(offset + packet_size);

				if (packet_size >= 14)
				{
					UCHAR *tmp;
					BLOCK *b;

					PROBE_DATA2("EthGetPacket: NewBlock", packet_data, packet_size);
					
					tmp = MallocFast(packet_size);

					Copy(tmp, packet_data, packet_size);
					b = NewBlock(tmp, packet_size, 0);
					InsertQueue(e->PacketQueue, b);
				}
			}

			flag = true;
			goto RETRY;
		}
	}

	// No more packet
	return 0;
}

// Get cancel object
CANCEL *EthGetCancel(ETH *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return NULL;
	}

	AddRef(e->Cancel->ref);

	return e->Cancel;
}

// Close adapter
void CloseEth(ETH *e)
{
	BLOCK *b;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	ReleaseCancel(e->Cancel);

	if (e->SuAdapter != NULL)
	{
		// Close SeLow adapter
		SuCloseAdapter(e->SuAdapter);
		SuFree(e->Su);
	}
	else
	{
		// Close SEE adapter
		wp->PacketCloseAdapter(e->Adapter);
		wp->PacketFreePacket(e->Packet);
		wp->PacketFreePacket(e->PutPacket);
	}

	while (b = GetNext(e->PacketQueue))
	{
		FreeBlock(b);
	}
	ReleaseQueue(e->PacketQueue);

	Free(e->Name);
	Free(e->Title);
	Free(e->Buffer);

	Free(e);
}

// Search adapter with the name
struct WP_ADAPTER *Win32EthSearch(char *name)
{
	UINT i;
	UINT id;
	char simple_name[MAX_SIZE];
	WP_ADAPTER *ret = NULL;

	id = Win32EthGetNameAndIdFromCombinedName(simple_name, sizeof(simple_name), name);

	if (id != 0)
	{
		UINT num_match = 0;
		// Search with ID when ID is specified
		for (i = 0;i < LIST_NUM(eth_list);i++)
		{
			WP_ADAPTER *a = LIST_DATA(eth_list, i);

			if (a->Id != 0 && a->Id == id)
			{
				ret = a;
				num_match++;
			}
		}

		if (num_match >= 2)
		{
			// If the ID matches to 2 or more devices, search with the name
			for (i = 0;i < LIST_NUM(eth_list);i++)
			{
				WP_ADAPTER *a = LIST_DATA(eth_list, i);

				if (a->Id != 0 && a->Id == id)
				{
					if (StrCmpi(a->Title, name) == 0)
					{
						ret = a;
						break;
					}
				}
			}
		}
	}
	else
	{
		// Search with name when ID is not specified
		for (i = 0;i < LIST_NUM(eth_list);i++)
		{
			WP_ADAPTER *a = LIST_DATA(eth_list, i);

			if (StrCmpi(a->Title, name) == 0)
			{
				ret = a;
				break;
			}
		}
	}

	return ret;
}

// Open adapter
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr)
{
	ETH *ret;
	void *p;

	p = MsDisableWow64FileSystemRedirection();

	ret = OpenEthInternal(name, local, tapmode, tapaddr);

	MsRestoreWow64FileSystemRedirection(p);

	return ret;
}
ETH *OpenEthInternal(char *name, bool local, bool tapmode, char *tapaddr)
{
	WP_ADAPTER *t;
	ETH *e;
	ADAPTER *a = NULL;
	HANDLE h;
	CANCEL *c;
	MS_ADAPTER *ms;
	char name_with_id[MAX_SIZE];
	SU *su = NULL;
	SU_ADAPTER *su_adapter = NULL;
	// Validate arguments
	if (name == NULL || IsEthSupported() == false)
	{
		return NULL;
	}

	if (tapmode)
	{
		// Tap is not supported in Windows
		return NULL;
	}

	Lock(eth_list_lock);

	InitEthAdaptersList();

	t = Win32EthSearch(name);

	if (t == NULL)
	{
		Unlock(eth_list_lock);
		return NULL;
	}

	Debug("OpenEthInternal: %s\n", t->Name);

	if (StartWith(t->Name, SL_ADAPTER_ID_PREFIX))
	{
		// Open with SU
		su = SuInit();
		if (su == NULL)
		{
			// Fail to initialize SU
			Unlock(eth_list_lock);
			return NULL;
		}

		su_adapter = SuOpenAdapter(su, t->Name);

		if (su_adapter == NULL)
		{
			// Fail to get adapter
			SuFree(su);
			Unlock(eth_list_lock);
			return NULL;
		}

		is_using_selow = true;
	}
	else
	{
		// Open with SEE
		a = wp->PacketOpenAdapter(t->Name);
		if (a == NULL)
		{
			Unlock(eth_list_lock);
			return NULL;
		}

		if (IsWin32BridgeWithSee() == false)
		{
			MsSetThreadSingleCpu();
		}

		is_using_selow = false;
	}

	e = ZeroMalloc(sizeof(ETH));
	e->Name = CopyStr(t->Name);

	Win32EthMakeCombinedName(name_with_id, sizeof(name_with_id), t->Title, t->Guid);
	e->Title = CopyStr(name_with_id);

	if (su_adapter != NULL)
	{
		// SU
		e->SuAdapter = su_adapter;
		e->Su = su;

		// Get event object
		h = e->SuAdapter->hEvent;

		c = NewCancelSpecial(h);
		e->Cancel = c;
	}
	else
	{
		// SEE
		e->Adapter = a;

		wp->PacketSetBuff(e->Adapter, BRIDGE_WIN32_ETH_BUFFER);
		wp->PacketSetHwFilter(e->Adapter, local ? 0x0080 : 0x0020);
		wp->PacketSetMode(e->Adapter, PACKET_MODE_CAPT);
		wp->PacketSetReadTimeout(e->Adapter, -1);
		wp->PacketSetNumWrites(e->Adapter, 1);

		if (wp->PacketSetLoopbackBehavior != NULL)
		{
			// Filter loopback packet in kernel
			if (GET_KETA(GetOsType(), 100) >= 3)
			{
				if (MsIsWindows8() == false)
				{
					// Enable for Windows XP, Server 2003 or later
					// But disable for Windows 8 or later
					bool ret = wp->PacketSetLoopbackBehavior(e->Adapter, 1);
					Debug("*** PacketSetLoopbackBehavior: %u\n", ret);

					e->LoopbackBlock = ret;
				}
			}
		}

		// Get event object
		h = wp->PacketGetReadEvent(e->Adapter);

		c = NewCancelSpecial(h);
		e->Cancel = c;

		e->Packet = wp->PacketAllocatePacket();

		e->PutPacket = wp->PacketAllocatePacket();
	}

	e->Buffer = Malloc(BRIDGE_WIN32_ETH_BUFFER);
	e->BufferSize = BRIDGE_WIN32_ETH_BUFFER;

	e->PacketQueue = NewQueue();

	// Get MAC address by GUID
	ms = MsGetAdapterByGuid(t->Guid);
	if (ms != NULL)
	{
		if (ms->AddressSize == 6)
		{
			Copy(e->MacAddress, ms->Address, 6);
		}

		MsFreeAdapter(ms);
	}

	Unlock(eth_list_lock);

	return e;
}

// Generate a combined name from NIC name and GUID
void Win32EthMakeCombinedName(char *dst, UINT dst_size, char *nicname, char *guid)
{
	// Validate arguments
	if (dst == NULL || nicname == NULL || guid == NULL)
	{
		return;
	}

	if (IsEmptyStr(guid) == false)
	{
		Format(dst, dst_size, "%s (ID=%010u)", nicname, Win32EthGenIdFromGuid(guid));
	}
	else
	{
		StrCpy(dst, dst_size, nicname);
	}
}

// Decompose combined name
UINT Win32EthGetNameAndIdFromCombinedName(char *name, UINT name_size, char *str)
{
	UINT ret = 0;
	char id_str[MAX_SIZE];
	UINT len;
	// Validate arguments
	ClearStr(name, name_size);
	StrCpy(name, name_size, str);
	if (name == NULL || str == NULL)
	{
		return 0;
	}

	len = StrLen(str);

	if (len >= 16)
	{
		StrCpy(id_str, sizeof(id_str), str + len - 16);

		if (StartWith(id_str, " (ID="))
		{
			if (EndWith(id_str, ")"))
			{
				char num[MAX_SIZE];

				Zero(num, sizeof(num));
				StrCpy(num, sizeof(num), id_str + 5);

				num[StrLen(num) - 1] = 0;

				ret = ToInt(num);

				if (ret != 0)
				{
					name[len - 16] = 0;
				}
			}
		}
	}

	return ret;
}

// Generate an ID from GUID
UINT Win32EthGenIdFromGuid(char *guid)
{
	char tmp[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	UINT i;
	// Validate arguments
	if (guid == NULL)
	{
		return 0;
	}

	StrCpy(tmp, sizeof(tmp), guid);
	Trim(tmp);
	StrUpper(tmp);

	HashSha1(hash, tmp, StrLen(tmp));

	Copy(&i, hash, sizeof(UINT));

	i = Endian32(i);

	if (i == 0)
	{
		i = 1;
	}

	return i;
}

// Get Ethernet adapter list
TOKEN_LIST *GetEthList()
{
	UINT v;

	return GetEthListEx(&v);
}
TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden)
{
	TOKEN_LIST *ret;
	UINT i;
	UINT j;
	UINT dummy_int;
	MS_ADAPTER_LIST *adapter_list;

	if (IsEthSupported() == false)
	{
		return NULL;
	}

	if (total_num_including_hidden == NULL)
	{
		total_num_including_hidden = &dummy_int;
	}

	*total_num_including_hidden = 0;

	Lock(eth_list_lock);

	InitEthAdaptersList();

	adapter_list = MsCreateAdapterList();

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = LIST_NUM(eth_list);
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	j = 0;
	for (i = 0;i < ret->NumTokens;i++)
	{
		char tmp[MAX_SIZE];
		WP_ADAPTER *a = LIST_DATA(eth_list, i);
		MS_ADAPTER *msa = NULL;
		bool show = true;

		if (Win32EthGetShowAllIf() == false)
		{
			msa = MsGetAdapterByGuidFromList(adapter_list, a->Guid);

			if (InStr(a->Title, "vpn client adapter"))
			{
				// Hide virtual NIC for VPN client
				show = false;
			}

			if (InStr(a->Title, "tunnel adapter"))
			{
				// Hide tunnel adapter
				show = false;
			}

			if (InStr(a->Title, "teredo tunnel"))
			{
				// Hide tunnel adapter
				show = false;
			}

			if (InStr(a->Title, "MS Tunnel Interface"))
			{
				// Hide tunnel adapter
				show = false;
			}

			if (InStr(a->Title, "pseudo-interface"))
			{
				// Hide tunnel adapter
				show = false;
			}
		}

		if (msa != NULL)
		{
			// Hide except physical Ethernet NIC
			if (msa->IsNotEthernetLan)
			{
				show = false;
			}

			MsFreeAdapter(msa);
		}

		Win32EthMakeCombinedName(tmp, sizeof(tmp), a->Title, a->Guid);

		if (show)
		{
			ret->Token[j++] = CopyStr(tmp);

			Debug("%s - %s\n", a->Guid, a->Title);
		}
	}

	*total_num_including_hidden = ret->NumTokens;

	ret->NumTokens = j;

	Unlock(eth_list_lock);

	MsFreeAdapterList(adapter_list);

	return ret;
}

// Compare the name of WP_ADAPTER
int CompareWpAdapter(void *p1, void *p2)
{
	int i;
	WP_ADAPTER *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(WP_ADAPTER **)p1;
	a2 = *(WP_ADAPTER **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	i = StrCmpi(a1->Title, a2->Title);
	return i;
}

// Get whether the SeLow is used 
bool Win32IsUsingSeLow()
{
	return is_using_selow;
}

// Get Ethernet adapter list
LIST *GetEthAdapterList()
{
	void *p;
	LIST *o;

	p = MsDisableWow64FileSystemRedirection();

	o = GetEthAdapterListInternal();

	MsRestoreWow64FileSystemRedirection(p);

	return o;
}
LIST *GetEthAdapterListInternal()
{
	LIST *o;
	LIST *ret;
	UINT size;
	char *buf;
	UINT i, j;
	char *qos_tag = " (Microsoft's Packet Scheduler)";
	SU *su = NULL;
	LIST *su_adapter_list = NULL;

	// Try to use SeLow
	if (enable_selow)
	{
		su = SuInit();
	}

	o = NewListFast(CompareWpAdapter);

	size = 200000;
	buf = ZeroMalloc(size);

	// Try to enumerate with SeLow
	if (su != NULL)
	{
		su_adapter_list = SuGetAdapterList(su);

		if (su_adapter_list == NULL)
		{
			// Fail to enumerate
			SuFree(su);
			su = NULL;
			//WHERE;
			is_using_selow = false;
		}
		else
		{
			//WHERE;
			is_using_selow = true;
		}
	}
	else
	{
		is_using_selow = false;
	}

	if (su_adapter_list != NULL)
	{
		// If 1 or more adapters are enumerated by SeLow, create adapter list object
		UINT i;

		for (i = 0;i < LIST_NUM(su_adapter_list);i++)
		{
			SU_ADAPTER_LIST *t = LIST_DATA(su_adapter_list, i);
			WP_ADAPTER *a = ZeroMalloc(sizeof(WP_ADAPTER));

			StrCpy(a->Name, sizeof(a->Name), t->Name);
			StrCpy(a->Guid, sizeof(a->Guid), t->Guid);
			StrCpy(a->Title, sizeof(a->Title), t->Info.FriendlyName);

			TrimCrlf(a->Title);
			Trim(a->Title);
			TrimCrlf(a->Title);
			Trim(a->Title);

			if (EndWith(a->Title, qos_tag))
			{
				a->Title[StrLen(a->Title) - StrLen(qos_tag)] = 0;
				TrimCrlf(a->Title);
				Trim(a->Title);
				TrimCrlf(a->Title);
				Trim(a->Title);
			}

			Add(o, a);
		}
	}
	else
	{
		// When SeLow is not used, create adapter list with SEE or WinPcap
		if (wp->PacketGetAdapterNames(buf, &size) == false)
		{
			Free(buf);
			return o;
		}

		i = 0;

		if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType))
		{
			// Windows NT
			if (size >= 2 && buf[0] != 0 && buf[1] != 0)
			{
				goto ANSI_STR;
			}

			while (true)
			{
				wchar_t tmp[MAX_SIZE];
				WP_ADAPTER *a;
				UniStrCpy(tmp, sizeof(tmp), L"");

				if (*((wchar_t *)(&buf[i])) == 0)
				{
					i += sizeof(wchar_t);
					break;
				}

				for (;*((wchar_t *)(&buf[i])) != 0;i += sizeof(wchar_t))
				{
					wchar_t str[2];
					str[0] = *((wchar_t *)(&buf[i]));
					str[1] = 0;
					UniStrCat(tmp, sizeof(tmp), str);
				}

				i += sizeof(wchar_t);

				a = ZeroMalloc(sizeof(WP_ADAPTER));
				UniToStr(a->Name, sizeof(a->Name), tmp);

				Add(o, a);
			}
		}
		else
		{
			// Windows 9x
ANSI_STR:
			while (true)
			{
				char tmp[MAX_SIZE];
				WP_ADAPTER *a;
				StrCpy(tmp, sizeof(tmp), "");

				if (*((char *)(&buf[i])) == 0)
				{
					i += sizeof(char);
					break;
				}

				for (;*((char *)(&buf[i])) != 0;i += sizeof(char))
				{
					char str[2];
					str[0] = *((char *)(&buf[i]));
					str[1] = 0;
					StrCat(tmp, sizeof(tmp), str);
				}

				i += sizeof(char);

				a = ZeroMalloc(sizeof(WP_ADAPTER));
				StrCpy(a->Name, sizeof(a->Name), tmp);

				Add(o, a);
			}
		}

		for (j = 0;j < LIST_NUM(o);j++)
		{
			WP_ADAPTER *a = LIST_DATA(o, j);

			StrCpy(a->Title, sizeof(a->Title), &buf[i]);
			i += StrSize(a->Title);

			// If device description is "Unknown" in Win9x, skip 1 byte
			if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType))
			{
				if (StrCmp(a->Title, "Unknown") == 0)
				{
					if (buf[i] == 0)
					{
						i+=sizeof(char);
					}
				}
			}

			TrimCrlf(a->Title);
			Trim(a->Title);
			TrimCrlf(a->Title);
			Trim(a->Title);

			if (EndWith(a->Title, qos_tag))
			{
				a->Title[StrLen(a->Title) - StrLen(qos_tag)] = 0;
				TrimCrlf(a->Title);
				Trim(a->Title);
				TrimCrlf(a->Title);
				Trim(a->Title);
			}
		}
	}

	for (j = 0;j < LIST_NUM(o);j++)
	{
		// Extract GUID
		WP_ADAPTER *a = LIST_DATA(o, j);

		if (IsEmptyStr(a->Guid))
		{
			StrCpy(a->Guid, sizeof(a->Guid), a->Name);
			ReplaceStr(a->Guid, sizeof(a->Guid), a->Guid, "\\Device\\SEE_", "");
			ReplaceStr(a->Guid, sizeof(a->Guid), a->Guid, "\\Device\\NPF_", "");
			ReplaceStr(a->Guid, sizeof(a->Guid), a->Guid, "\\Device\\PCD_", "");
		}
	}

	// Sort
	if (su_adapter_list != NULL)
	{
		// Since adapter list made by SeLow is already sorted, don't sort here
		Sort(o);
	}

	ret = NewListFast(CompareWpAdapter);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		WP_ADAPTER *a = LIST_DATA(o, i);
		ADAPTER *ad;
		bool is_ethernet = false;
		bool ok = false;

		if (SearchStrEx(a->Title, "ppp", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "wan", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "dialup", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "pptp", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "telepho", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "modem", 0, false) != INFINITE ||
			SearchStrEx(a->Title, "ras", 0, false) != INFINITE)
		{
			Free(a);
			continue;
		}

		// Determine whether the adapter type is Ethernet
		if (su == NULL)
		{
			// Determine with See
			ad = wp->PacketOpenAdapter(a->Name);
			if (ad != NULL)
			{
				NetType type;
				if (wp->PacketGetNetType(ad, &type))
				{
					if (type.LinkType == 0)
					{
						is_ethernet = true;
					}
				}

				wp->PacketCloseAdapter(ad);
			}
		}
		else
		{
			// In using SeLow, all devices should be Ethernet device
			is_ethernet = true;
		}

		if (is_ethernet)
		{
			// Add only Ethernet device
			char tmp[MAX_SIZE];
			UINT k;

			StrCpy(tmp, sizeof(tmp), a->Title);

			for (k = 0;;k++)
			{
				if (k == 0)
				{
					StrCpy(tmp, sizeof(tmp), a->Title);
				}
				else
				{
					Format(tmp, sizeof(tmp), "%s (%u)", a->Title, k + 1);
				}

				ok = true;
				for (j = 0;j < LIST_NUM(ret);j++)
				{
					WP_ADAPTER *aa = LIST_DATA(ret, j);
					if (StrCmpi(aa->Title, tmp) == 0)
					{
						ok = false;
					}
				}

				if (ok)
				{
					break;
				}
			}

			StrCpy(a->Title, sizeof(a->Title), tmp);
			a->Id = Win32EthGenIdFromGuid(a->Guid);
			Add(ret, a);
		}

		if (ok == false)
		{
			Free(a);
		}
	}

	Free(buf);

	Sort(ret);

	ReleaseList(o);

	if (su != NULL)
	{
		SuFreeAdapterList(su_adapter_list);

		SuFree(su);
	}

	return ret;
}

// Initialize Ethernet adapter list
void InitEthAdaptersList()
{
	if (eth_list != NULL)
	{
		FreeEthAdaptersList();
		eth_list = NULL;
	}
	eth_list = GetEthAdapterList();
}

// Free Ethernet adapter list
void FreeEthAdaptersList()
{
	UINT i;
	if (eth_list == NULL)
	{
		return;
	}
	for (i = 0;i < LIST_NUM(eth_list);i++)
	{
		WP_ADAPTER *a = LIST_DATA(eth_list, i);
		Free(a);
	}
	ReleaseList(eth_list);
	eth_list = NULL;
}

// Is the SU supported
bool Win32EthIsSuSupported()
{
	bool ret = false;
	SU *su = SuInit();

	if (su != NULL)
	{
		ret = true;
	}

	SuFree(su);

	return ret;
}

// Is the Ethernet supported
bool IsEthSupported()
{
	bool ret = IsEthSupportedInner();

	if (ret == false)
	{
		ret = Win32EthIsSuSupported();
	}

	return ret;
}
bool IsEthSupportedInner()
{
	if (wp == NULL)
	{
		return false;
	}

	return wp->Inited;
}

// Is the PCD driver supported in current OS
bool IsPcdSupported()
{
	UINT type;
	OS_INFO *info = GetOsInfo();

	if (MsIsWindows10())
	{
		// Windows 10 or later never supports PCD driver.
		return false;
	}

	type = info->OsType;

	if (OS_IS_WINDOWS_NT(type) == false)
	{
		// Only on Windows NT series
		return false;
	}

	if (GET_KETA(type, 100) >= 2)
	{
		// Good for Windows 2000 or later
		return true;
	}

	// Not good for Windows NT 4.0 or Longhorn
	return false;
}

// Save build number of PCD driver
void SavePcdDriverBuild(UINT build)
{
	MsRegWriteInt(REG_LOCAL_MACHINE, BRIDGE_WIN32_PCD_REGKEY, BRIDGE_WIN32_PCD_BUILDVALUE,
		build);
}

// Load build number of PCD driver
UINT LoadPcdDriverBuild()
{
	return MsRegReadInt(REG_LOCAL_MACHINE, BRIDGE_WIN32_PCD_REGKEY, BRIDGE_WIN32_PCD_BUILDVALUE);
}

// Try to install PCD driver
HINSTANCE InstallPcdDriver()
{
	HINSTANCE ret;
	void *p = MsDisableWow64FileSystemRedirection();

	ret = InstallPcdDriverInternal();

	MsRestoreWow64FileSystemRedirection(p);

	return ret;
}
HINSTANCE InstallPcdDriverInternal()
{
	char tmp[MAX_PATH];
	bool install_driver = true;
	HINSTANCE h;
	char *dll_filename;

	// Confirm whether the see.sys is installed in system32\drivers folder
	Format(tmp, sizeof(tmp), "%s\\drivers\\see.sys", MsGetSystem32Dir());

	if (IsFileExists(tmp))
	{
		// If driver file is exist, try to get build number from registry
		if (LoadPcdDriverBuild() >= CEDAR_BUILD)
		{
			// Already latest driver is installed
			install_driver = false;
		}
	}

	if (install_driver)
	{
		char *src_filename = BRIDGE_WIN32_PCD_SYS;
		// If need to install the driver, confirm user is administrator
		if (MsIsAdmin() == false)
		{
			// Non administrator can't install driver
			return NULL;
		}

		if (MsIsX64())
		{
			src_filename = BRIDGE_WIN32_PCD_SYS_X64;
		}

		// Copy see.sys
		if (FileCopy(src_filename, tmp) == false)
		{
			return NULL;
		}

		// Save build number
		SavePcdDriverBuild(CEDAR_BUILD);
	}

	dll_filename = BRIDGE_WIN32_PCD_DLL;

	if (Is64())
	{
		if (MsIsX64())
		{
			dll_filename = BRIDGE_WIN32_PCD_DLL_X64;
		}
	}

	// Try to load see.dll and initialize
	h = MsLoadLibrary(dll_filename);
	if (h == NULL)
	{
		return NULL;
	}

	return h;
}

// Initialize Ethernet
void InitEth()
{
	HINSTANCE h;
	if (wp != NULL)
	{
		// Already initialized
		return;
	}

	eth_list_lock = NewLock();

	wp = ZeroMalloc(sizeof(WP));

	is_see_mode = false;

	if (IsPcdSupported())
	{
		// PCD is supported in this OS
		h = InstallPcdDriver();
		if (h != NULL)
		{
			// Try to initialize with PCD
			if (InitWpWithLoadLibrary(wp, h) == false)
			{
				Debug("InitEth: SEE Failed.\n");
				FreeLibrary(h);
			}
			else
			{
				Debug("InitEth: SEE Loaded.\n");
				is_see_mode = true;
			}
		}
	}

	if (wp->Inited == false)
	{
		// Try to initialize with Packet.dll of WinPcap
		h = LoadLibrary(BRIDGE_WIN32_PACKET_DLL);
		if (h != NULL)
		{
			if (InitWpWithLoadLibrary(wp, h) == false)
			{
				Debug("InitEth: Packet.dll Failed.\n");
				FreeLibrary(h);
			}
			else
			{
				Debug("InitEth: Packet.dll Loaded.\n");
			}
		}
	}
}

// Get whether local-bridge uses see.sys
bool IsWin32BridgeWithSee()
{
	return is_see_mode;
}

// Initialize WP structure with DLL
bool InitWpWithLoadLibrary(WP *wp, HINSTANCE h)
{
	TOKEN_LIST *o;
	UINT total_num = 0;
	// Validate arguments
	if (wp == NULL || h == NULL)
	{
		return false;
	}
	wp->Inited = true;
	wp->hPacketDll = h;

	LOAD_DLL_ADDR(PacketGetVersion);
	LOAD_DLL_ADDR(PacketGetDriverVersion);
	LOAD_DLL_ADDR(PacketSetMinToCopy);
	LOAD_DLL_ADDR(PacketSetNumWrites);
	LOAD_DLL_ADDR(PacketSetMode);
	LOAD_DLL_ADDR(PacketSetReadTimeout);
	LOAD_DLL_ADDR(PacketSetBpf);
	LOAD_DLL_ADDR(PacketSetSnapLen);
	LOAD_DLL_ADDR(PacketGetStats);
	LOAD_DLL_ADDR(PacketGetStatsEx);
	LOAD_DLL_ADDR(PacketSetBuff);
	LOAD_DLL_ADDR(PacketGetNetType);
	LOAD_DLL_ADDR(PacketOpenAdapter);
	LOAD_DLL_ADDR(PacketSendPacket);
	LOAD_DLL_ADDR(PacketSendPackets);
	LOAD_DLL_ADDR(PacketAllocatePacket);
	LOAD_DLL_ADDR(PacketInitPacket);
	LOAD_DLL_ADDR(PacketFreePacket);
	LOAD_DLL_ADDR(PacketReceivePacket);
	LOAD_DLL_ADDR(PacketSetHwFilter);
	LOAD_DLL_ADDR(PacketGetAdapterNames);
	LOAD_DLL_ADDR(PacketGetNetInfoEx);
	LOAD_DLL_ADDR(PacketRequest);
	LOAD_DLL_ADDR(PacketGetReadEvent);
	LOAD_DLL_ADDR(PacketSetDumpName);
	LOAD_DLL_ADDR(PacketSetDumpLimits);
	LOAD_DLL_ADDR(PacketSetDumpLimits);
	LOAD_DLL_ADDR(PacketIsDumpEnded);
	LOAD_DLL_ADDR(PacketStopDriver);
	LOAD_DLL_ADDR(PacketCloseAdapter);
	LOAD_DLL_ADDR(PacketSetLoopbackBehavior);

	if (wp->PacketSetMinToCopy == NULL ||
		wp->PacketSetNumWrites == NULL ||
		wp->PacketSetMode == NULL ||
		wp->PacketSetReadTimeout == NULL ||
		wp->PacketSetBuff == NULL ||
		wp->PacketGetNetType == NULL ||
		wp->PacketOpenAdapter == NULL ||
		wp->PacketSendPacket == NULL ||
		wp->PacketSendPackets == NULL ||
		wp->PacketAllocatePacket == NULL ||
		wp->PacketInitPacket == NULL ||
		wp->PacketFreePacket == NULL ||
		wp->PacketReceivePacket == NULL ||
		wp->PacketSetHwFilter == NULL ||
		wp->PacketGetAdapterNames == NULL ||
		wp->PacketGetNetInfoEx == NULL ||
		wp->PacketCloseAdapter == NULL)
	{
RELEASE:
		wp->Inited = false;
		wp->hPacketDll = NULL;

		return false;
	}

	o = GetEthListEx(&total_num);
	if (o == NULL || total_num == 0)
	{
		FreeToken(o);
		goto RELEASE;
	}

	FreeToken(o);

	return true;
}

// Free Ethernet
void FreeEth()
{
	if (wp == NULL)
	{
		// Not initialized
		return;
	}

	// Free adapter list
	FreeEthAdaptersList();

	if (wp->Inited)
	{
		// Free DLL
		FreeLibrary(wp->hPacketDll);
	}

	Free(wp);
	wp = NULL;

	DeleteLock(eth_list_lock);
	eth_list_lock = NULL;
}

// Get network connection name from Ethernet device name
void GetEthNetworkConnectionName(wchar_t *dst, UINT size, char *device_name)
{
	WP_ADAPTER *t;
	char *tmp = NULL, guid[MAX_SIZE];
	wchar_t *ncname = NULL;

	UniStrCpy(dst, size, L"");

	// Validate arguments
	if (device_name == NULL || IsEthSupported() == false || 
		IsNt() == false || MsIsWin2000OrGreater() == false)
	{
		return;
	}

	Lock(eth_list_lock);

	InitEthAdaptersList();

	t = Win32EthSearch(device_name);

	if (t == NULL)
	{
		Unlock(eth_list_lock);
		return;
	}

	tmp = CopyStr(t->Name);
	Unlock(eth_list_lock);

	if (IsEmptyStr(t->Guid) == false)
	{
		StrCpy(guid, sizeof(guid), t->Guid);

		Free(tmp);
	}
	else
	{
		ReplaceStr(guid, sizeof(guid), tmp, "\\Device\\SEE_", "");
		Free(tmp);

		ReplaceStr(guid, sizeof(guid), guid, "\\Device\\NPF_", "");
		ReplaceStr(guid, sizeof(guid), guid, "\\Device\\PCD_", "");
	}

	if(guid == NULL)
	{
		return;
	}

	ncname = MsGetNetworkConnectionName(guid);
	if(ncname != NULL)
	{
		UniStrCpy(dst, size, ncname);
	}
	Free(ncname);
}

#endif	// BRIDGE_C



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
