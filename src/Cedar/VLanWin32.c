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


// VLanWin32.c
// Virtual device driver library for Win32

#include <GlobalConst.h>

#ifdef	VLAN_C

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

#ifdef	OS_WIN32

typedef DWORD(CALLBACK* OPENVXDHANDLE)(HANDLE);

// Get the version information of Windows
void Win32GetWinVer(RPC_WINVER *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	Zero(v, sizeof(RPC_WINVER));

	v->IsWindows = true;

	if (OS_IS_WINDOWS_NT(GetOsType()) == false)
	{
		// Windows 9x
		OSVERSIONINFO os;
		Zero(&os, sizeof(os));
		os.dwOSVersionInfoSize = sizeof(os);
		GetVersionEx(&os);

		v->Build = LOWORD(os.dwBuildNumber);
		v->VerMajor = os.dwMajorVersion;
		v->VerMinor = os.dwMinorVersion;

		Format(v->Title, sizeof(v->Title), "%s %s",
			GetOsInfo()->OsProductName,
			GetOsInfo()->OsVersion);
		Trim(v->Title);
	}
	else
	{
		// Windows NT 4.0 SP6 or later
		OSVERSIONINFOEX os;
		Zero(&os, sizeof(os));
		os.dwOSVersionInfoSize = sizeof(os);
		Win32GetVersionExInternal((LPOSVERSIONINFOA)&os);

		v->IsNT = true;
		v->Build = os.dwBuildNumber;
		v->ServicePack = os.wServicePackMajor;

		if (os.wProductType != VER_NT_WORKSTATION)
		{
			v->IsServer = true;
		}
		v->VerMajor = os.dwMajorVersion;
		v->VerMinor = os.dwMinorVersion;

		if (GetOsInfo()->OsServicePack == 0)
		{
			StrCpy(v->Title, sizeof(v->Title), GetOsInfo()->OsProductName);
		}
		else
		{
			Format(v->Title, sizeof(v->Title), "%s Service Pack %u",
				GetOsInfo()->OsProductName,
				GetOsInfo()->OsServicePack);
		}
		Trim(v->Title);

		if (InStr(GetOsInfo()->OsVersion, "rc") ||
			InStr(GetOsInfo()->OsVersion, "beta"))
		{
			v->IsBeta = true;
		}
	}
}

// Release the DHCP addresses of all virtual LAN cards
void Win32ReleaseAllDhcp9x(bool wait)
{
	TOKEN_LIST *t;
	UINT i;

	t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, VLAN_ADAPTER_NAME_OLD);
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		UINT id = GetInstanceId(name);
		if (id != 0)
		{
			Win32ReleaseDhcp9x(id, wait);
		}
	}

	FreeToken(t);
}

// Routing table tracking main
void RouteTrackingMain(SESSION *s)
{
	ROUTE_TRACKING *t;
	UINT64 now;
	ROUTE_TABLE *table;
	ROUTE_ENTRY *rs;
	bool changed = false;
	bool check = false;
	bool any_modified = false;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}
	if (s->ClientModeAndUseVLan == false)
	{
		return;
	}

	// Get the state
	t = ((VLAN *)s->PacketAdapter->Param)->RouteState;
	if (t == NULL)
	{
		return;
	}

	// Current time
	PROBE_STR("RouteTrackingMain 1");
	now = Tick64();

	if (t->RouteChange != NULL)
	{
		if (t->NextRouteChangeCheckTime == 0 ||
			t->NextRouteChangeCheckTime <= now)
		{
			t->NextRouteChangeCheckTime = now + 1000ULL;

			check = IsRouteChanged(t->RouteChange);

			if (check)
			{
				Debug("*** Routing Table Changed ***\n");
				t->NextTrackingTime = 0;
			}
		}
	}
	if (t->NextTrackingTime != 0 && t->NextTrackingTime > now)
	{
		if (s->UseUdpAcceleration && s->UdpAccel != NULL && s->UdpAccel->NatT_IP_Changed)
		{
			// Check always if the IP address of the NAT-T server has changed
		}
		else
		{
			PROBE_STR("RouteTrackingMain 2");
			return;
		}
	}
	PROBE_STR("RouteTrackingMain 3");

	if (s->UseUdpAcceleration && s->UdpAccel != NULL)
	{
		IP nat_t_ip;

		s->UdpAccel->NatT_IP_Changed = false;

		Zero(&nat_t_ip, sizeof(nat_t_ip));

		Lock(s->UdpAccel->NatT_Lock);
		{
			Copy(&nat_t_ip, &s->UdpAccel->NatT_IP, sizeof(IP));
		}
		Unlock(s->UdpAccel->NatT_Lock);

		// Add a route to the NAT-T server
		if (IsZeroIp(&nat_t_ip) == false)
		{
			if (t->RouteToNatTServer == NULL)
			{
				if (t->RouteToEight != NULL)
				{
					ROUTE_ENTRY *e = Clone(t->RouteToEight, sizeof(ROUTE_ENTRY));
					char ip_str[64];
					char ip_str2[64];

					Copy(&e->DestIP, &nat_t_ip, sizeof(IP));
					e->Metric = e->OldIfMetric;

					IPToStr(ip_str, sizeof(ip_str), &e->DestIP);
					IPToStr(ip_str2, sizeof(ip_str2), &e->GatewayIP);

					t->RouteToNatTServer = e;

					if (AddRouteEntry(t->RouteToNatTServer))
					{
						Debug("Adding Static Route to %s via %s metric %u: ok.\n", ip_str, ip_str2, e->Metric);
					}
					else
					{
						FreeRouteEntry(t->RouteToNatTServer);
						t->RouteToNatTServer = NULL;
					}
				}
			}
		}
	}

	// Get the current routing table
	table = GetRouteTable();
	rs = t->RouteToServer;
	if (table != NULL)
	{
		UINT i;
		bool route_to_server_erased = true;
		bool is_vlan_want_to_be_default_gateway = false;
		UINT vlan_default_gatewat_metric = 0;
		UINT other_if_default_gateway_metric_min = INFINITE;

		// Get whether the routing table have been changed
		if (t->LastRoutingTableHash != table->HashedValue)
		{
			t->LastRoutingTableHash = table->HashedValue;
			changed = true;
		}

		//DebugPrintRouteTable(table);

		// Scan the routing table
		for (i = 0;i < table->NumEntry;i++)
		{
			ROUTE_ENTRY *e = table->Entry[i];

			if (rs != NULL)
			{
				if (CmpIpAddr(&e->DestIP, &rs->DestIP) == 0 &&
					CmpIpAddr(&e->DestMask, &rs->DestMask) == 0
//					&& CmpIpAddr(&e->GatewayIP, &rs->GatewayIP) == 0
//					&& e->InterfaceID == rs->InterfaceID &&
//					e->LocalRouting == rs->LocalRouting &&
//					e->Metric == rs->Metric
					)
				{
					// Routing entry to the server that added at the time of connection is found
					route_to_server_erased = false;
				}
			}

			// Search for the default gateway
			if (IPToUINT(&e->DestIP) == 0 &&
				IPToUINT(&e->DestMask) == 0)
			{
				Debug("e->InterfaceID = %u, t->VLanInterfaceId = %u\n",
					e->InterfaceID, t->VLanInterfaceId);

				if (e->InterfaceID == t->VLanInterfaceId)
				{
					// The virtual LAN card think that he want to be a default gateway
					is_vlan_want_to_be_default_gateway = true;
					vlan_default_gatewat_metric = e->Metric;

					if (vlan_default_gatewat_metric >= 2 &&
						t->OldDefaultGatewayMetric == (vlan_default_gatewat_metric - 1))
					{
						// Restore because the PPP server rewrites
						// the routing table selfishly
						DeleteRouteEntry(e);
						e->Metric--;
						AddRouteEntry(e);
						Debug("** Restore metric destroyed by PPP.\n");

						any_modified = true;
					}

					// Keep this entry
					if (t->DefaultGatewayByVLan != NULL)
					{
						// Delete if there is one added last time
						FreeRouteEntry(t->DefaultGatewayByVLan);
					}

					t->DefaultGatewayByVLan = ZeroMalloc(sizeof(ROUTE_ENTRY));
					Copy(t->DefaultGatewayByVLan, e, sizeof(ROUTE_ENTRY));

					t->OldDefaultGatewayMetric = vlan_default_gatewat_metric;
				}
				else
				{
					// There are default gateway other than the virtual LAN card
					// Save the metric value of the default gateway
					if (other_if_default_gateway_metric_min > e->Metric)
					{
						// Ignore the metric value of all PPP connection in the case of Windows Vista
						if (MsIsVista() == false || e->PPPConnection == false)
						{
							other_if_default_gateway_metric_min = e->Metric;
						}
						else
						{
							// a PPP is used to Connect to the network
							// in using Windows Vista
							t->VistaAndUsingPPP = true;
						}
					}
				}
			}
		}

		if (t->VistaAndUsingPPP)
		{
			if (t->DefaultGatewayByVLan != NULL)
			{
				if (is_vlan_want_to_be_default_gateway)
				{
					if (t->VistaOldDefaultGatewayByVLan == NULL || Cmp(t->VistaOldDefaultGatewayByVLan, t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY)) != 0)
					{
						ROUTE_ENTRY *e;
						// Add the route of 0.0.0.0/1 and 128.0.0.0/1
						// to the system if the virtual LAN card should be
						// the default gateway in the case of the connection
						// using PPP in Windows Vista

						if (t->VistaOldDefaultGatewayByVLan != NULL)
						{
							FreeRouteEntry(t->VistaOldDefaultGatewayByVLan);
						}

						if (t->VistaDefaultGateway1 != NULL)
						{
							DeleteRouteEntry(t->VistaDefaultGateway1);
							FreeRouteEntry(t->VistaDefaultGateway1);

							DeleteRouteEntry(t->VistaDefaultGateway2);
							FreeRouteEntry(t->VistaDefaultGateway2);
						}

						t->VistaOldDefaultGatewayByVLan = Clone(t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY));

						e = Clone(t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY));
						SetIP(&e->DestIP, 0, 0, 0, 0);
						SetIP(&e->DestMask, 128, 0, 0, 0);
						t->VistaDefaultGateway1 = e;

						e = Clone(t->DefaultGatewayByVLan, sizeof(ROUTE_ENTRY));
						SetIP(&e->DestIP, 128, 0, 0, 0);
						SetIP(&e->DestMask, 128, 0, 0, 0);
						t->VistaDefaultGateway2 = e;

						AddRouteEntry(t->VistaDefaultGateway1);
						AddRouteEntry(t->VistaDefaultGateway2);

						Debug("Vista PPP Fix Route Table Added.\n");

						any_modified = true;
					}
				}
				else
				{
					if (t->VistaOldDefaultGatewayByVLan != NULL)
					{
						FreeRouteEntry(t->VistaOldDefaultGatewayByVLan);
						t->VistaOldDefaultGatewayByVLan = NULL;
					}

					if (t->VistaDefaultGateway1 != NULL)
					{
						Debug("Vista PPP Fix Route Table Deleted.\n");
						DeleteRouteEntry(t->VistaDefaultGateway1);
						FreeRouteEntry(t->VistaDefaultGateway1);

						DeleteRouteEntry(t->VistaDefaultGateway2);
						FreeRouteEntry(t->VistaDefaultGateway2);

						any_modified = true;

						t->VistaDefaultGateway1 = t->VistaDefaultGateway2 = NULL;
					}
				}
			}
		}

		// If the virtual LAN card want to be the default gateway and
		// there is no LAN card with smaller metric of 0.0.0.0/0 than
		// the virtual LAN card, delete other default gateway entries
		// to elect the virtual LAN card as the default gateway
//		Debug("is_vlan_want_to_be_default_gateway = %u, rs = %u, route_to_server_erased = %u, other_if_default_gateway_metric_min = %u, vlan_default_gatewat_metric = %u\n",
//			is_vlan_want_to_be_default_gateway, rs, route_to_server_erased, other_if_default_gateway_metric_min, vlan_default_gatewat_metric);
		if (is_vlan_want_to_be_default_gateway && (rs != NULL && route_to_server_erased == false) &&
			other_if_default_gateway_metric_min >= vlan_default_gatewat_metric)
		{
			// Scan the routing table again
			for (i = 0;i < table->NumEntry;i++)
			{
				ROUTE_ENTRY *e = table->Entry[i];

				if (e->InterfaceID != t->VLanInterfaceId)
				{
					if (IPToUINT(&e->DestIP) == 0 &&
					IPToUINT(&e->DestMask) == 0)
					{
						char str[64];
						// Default gateway is found
						ROUTE_ENTRY *r = ZeroMalloc(sizeof(ROUTE_ENTRY));

						Copy(r, e, sizeof(ROUTE_ENTRY));

						// Put in the queue
						InsertQueue(t->DeletedDefaultGateway, r);

						// Delete this gateway entry once
						DeleteRouteEntry(e);

						IPToStr(str, sizeof(str), &e->GatewayIP);
						Debug("Default Gateway %s Deleted.\n", str);

						any_modified = true;
					}
				}
			}
		}

		if (rs != NULL && route_to_server_erased)
		{
			// Physical entry to the server has disappeared
			Debug("Route to Server entry ERASED !!!\n");

			// Forced disconnection (reconnection enabled)
			s->RetryFlag = true;
			s->Halt = true;
		}

		// Release the routing table
		FreeRouteTable(table);
	}

	// Set the time to perform the next track
	if (t->NextTrackingTimeAdd == 0 || changed)
	{
		t->NextTrackingTimeAdd = TRACKING_INTERVAL_INITIAL;
	}
	else
	{
		UINT64 max_value = TRACKING_INTERVAL_MAX;
		if (t->RouteChange != NULL)
		{
			max_value = TRACKING_INTERVAL_MAX_RC;
		}

		t->NextTrackingTimeAdd += TRACKING_INTERVAL_ADD;

		if (t->NextTrackingTimeAdd >= max_value)
		{
			t->NextTrackingTimeAdd = max_value;
		}
	}
	//Debug("t->NextTrackingTimeAdd = %I64u\n", t->NextTrackingTimeAdd);
	t->NextTrackingTime = now + t->NextTrackingTimeAdd;

	if (any_modified)
	{
		// Clear the DNS cache
		Win32FlushDnsCache();
	}
}

// Start tracking of the routing table
void RouteTrackingStart(SESSION *s)
{
	VLAN *v;
	ROUTE_TRACKING *t;
	UINT if_id = 0;
	ROUTE_ENTRY *e;
	ROUTE_ENTRY *dns = NULL;
	ROUTE_ENTRY *route_to_real_server_global = NULL;
	char tmp[64];
	UINT exclude_if_id = 0;
	bool already_exists = false;
	bool already_exists_by_other_account = false;
	IP eight;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	v = (VLAN *)s->PacketAdapter->Param;
	if (v->RouteState != NULL)
	{
		return;
	}

	// Get the interface ID of the virtual LAN card
	if_id = GetInstanceId(v->InstanceName);
	Debug("[InstanceId of %s] = 0x%x\n", v->InstanceName, if_id);

	if (MsIsVista())
	{
		// The routing table by the virtual LAN card body should be
		// excluded explicitly in Windows Vista
		exclude_if_id = if_id;
	}

	// Get the route to the server
	e = GetBestRouteEntryEx(&s->ServerIP, exclude_if_id);
	if (e == NULL)
	{
		// Acquisition failure
		Debug("Failed to get GetBestRouteEntry().\n");
		return;
	}
	IPToStr(tmp, sizeof(tmp), &e->GatewayIP);
	Debug("GetBestRouteEntry() Succeed. [Gateway: %s]\n", tmp);

	// Add a route
	if (MsIsVista())
	{
		e->Metric = e->OldIfMetric;
	}
	if (AddRouteEntryEx(e, &already_exists) == false)
	{
		FreeRouteEntry(e);
		e = NULL;
	}
	Debug("already_exists: %u\n", already_exists);

	if (already_exists)
	{
		if (s->Cedar->Client != NULL && s->Account != NULL)
		{
			UINT i;
			ACCOUNT *a;
			for (i = 0;i < LIST_NUM(s->Cedar->Client->AccountList);i++)
			{
				a = LIST_DATA(s->Cedar->Client->AccountList, i);
				Lock(a->lock);
				{
					SESSION *sess = a->ClientSession;
					if (sess != NULL && sess != s)
					{
						VLAN *v = sess->PacketAdapter->Param;
						if (v != NULL)
						{
							ROUTE_TRACKING *tr = v->RouteState;
							if (tr != NULL && e != NULL)
							{
								if (Cmp(tr->RouteToServer, e, sizeof(ROUTE_ENTRY)) == 0)
								{
									already_exists_by_other_account = true;
								}
							}
						}
					}
				}
				Unlock(a->lock);
			}
		}

		if (already_exists_by_other_account)
		{
			Debug("already_exists_by_other_account = %u\n", already_exists_by_other_account);
			already_exists = false;
		}
	}

	// Get the routing table to the DNS server
	// (If the DNS server is this PC itself, there's no need to get)
	if (IsZeroIP(&s->DefaultDns) == false)
	{
		if (IsMyIPAddress(&s->DefaultDns) == false)
		{
			dns = GetBestRouteEntryEx(&s->DefaultDns, exclude_if_id);
			if (dns == NULL)
			{
				// Getting failure
				Debug("Failed to get GetBestRouteEntry DNS.\n");
			}
			else
			{
				// Add a route
				if (MsIsVista())
				{
					dns->Metric = dns->OldIfMetric;

					if (AddRouteEntry(dns) == false)
					{
						FreeRouteEntry(dns);
						dns = NULL;
					}
				}
			}
		}
	}

	if (s->IsAzureSession && IsZeroIP(&s->AzureRealServerGlobalIp) == false)
	{
		// Add also a static route to the real server in the case of via VPN Azure
		if (IsMyIPAddress(&s->AzureRealServerGlobalIp) == false)
		{
			route_to_real_server_global = GetBestRouteEntryEx(&s->AzureRealServerGlobalIp, exclude_if_id);

			if (route_to_real_server_global != NULL)
			{
				if (MsIsVista())
				{
					route_to_real_server_global->Metric = route_to_real_server_global->OldIfMetric;
				}

				if (AddRouteEntry(route_to_real_server_global) == false)
				{
					FreeRouteEntry(route_to_real_server_global);
					route_to_real_server_global = NULL;
				}
			}
		}
	}

	// Initialize
	if (s->Cedar->Client != NULL && s->Account != NULL)
	{
		Lock(s->Account->lock);
	}

	t = ZeroMalloc(sizeof(ROUTE_TRACKING));
	v->RouteState = t;

	t->RouteToServerAlreadyExists = already_exists;
	t->RouteToServer = e;
	t->RouteToDefaultDns = dns;
	t->RouteToRealServerGlobal = route_to_real_server_global;
	t->VLanInterfaceId = if_id;
	t->NextTrackingTime = 0;
	t->DeletedDefaultGateway = NewQueue();
	t->OldDefaultGatewayMetric = 0x7fffffff;

	if (s->Cedar->Client != NULL && s->Account != NULL)
	{
		Unlock(s->Account->lock);
	}

	// Get the route to 8.8.8.8
	SetIP(&eight, 8, 8, 8, 8);
	t->RouteToEight = GetBestRouteEntryEx(&eight, exclude_if_id);

	// Get the current default DNS server to detect network changes
	GetDefaultDns(&t->OldDnsServer);

	// Get as soon as releasing the IP address in the case of using DHCP
	if (IsNt())
	{
		char tmp[MAX_SIZE];
		MS_ADAPTER *a;

		Format(tmp, sizeof(tmp), VLAN_ADAPTER_NAME_TAG, v->InstanceName);
		a = MsGetAdapter(tmp);

		if (a != NULL)
		{
			if (a->UseDhcp)
			{
				bool ret = Win32ReleaseAddressByGuidEx(a->Guid, 100);
				Debug("*** Win32ReleaseAddressByGuidEx = %u\n", ret);

				ret = Win32RenewAddressByGuidEx(a->Guid, 100);
				Debug("*** Win32RenewAddressByGuidEx = %u\n", ret);
			}

			MsFreeAdapter(a);
		}
	}
	else
	{
		// For Win9x
		Win32RenewDhcp9x(if_id);
	}

	// Clear the DNS cache
	Win32FlushDnsCache();

	// Detect a change in the routing table (for only supported OS)
	t->RouteChange = NewRouteChange();
	Debug("t->RouteChange = 0x%p\n", t->RouteChange);
}

// End the tracking of the routing table
void RouteTrackingStop(SESSION *s, ROUTE_TRACKING *t)
{
	ROUTE_ENTRY *e;
	ROUTE_TABLE *table;
	IP dns_ip;
	bool network_has_changed = false;
	bool do_not_delete_routing_entry = false;
	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	Zero(&dns_ip, sizeof(dns_ip));

	// Remove the default gateway added by the virtual LAN card
	if (MsIsVista() == false)
	{
		if (t->DefaultGatewayByVLan != NULL)
		{
			Debug("Default Gateway by VLAN was deleted.\n");
			DeleteRouteEntry(t->DefaultGatewayByVLan);
		}

		if (t->VistaOldDefaultGatewayByVLan != NULL)
		{
			FreeRouteEntry(t->VistaOldDefaultGatewayByVLan);
		}
	}

	if (t->DefaultGatewayByVLan != NULL)
	{
		FreeRouteEntry(t->DefaultGatewayByVLan);
		t->DefaultGatewayByVLan = NULL;
	}

	if (t->VistaDefaultGateway1 != NULL)
	{
		Debug("Vista PPP Fix Route Table Deleted.\n");
		DeleteRouteEntry(t->VistaDefaultGateway1);
		FreeRouteEntry(t->VistaDefaultGateway1);

		DeleteRouteEntry(t->VistaDefaultGateway2);
		FreeRouteEntry(t->VistaDefaultGateway2);
	}

	if (MsIsNt() == false)
	{
		// Only in the case of Windows 9x, release the DHCP address of the virtual LAN card
		Win32ReleaseDhcp9x(t->VLanInterfaceId, false);
	}

	// Clear the DNS cache
	Win32FlushDnsCache();

	if (s->Cedar->Client != NULL && s->Account != NULL)
	{
		UINT i;
		ACCOUNT *a;
		for (i = 0;i < LIST_NUM(s->Cedar->Client->AccountList);i++)
		{
			a = LIST_DATA(s->Cedar->Client->AccountList, i);
			Lock(a->lock);
			{
				SESSION *sess = a->ClientSession;
				if (sess != NULL && sess != s)
				{
					VLAN *v = sess->PacketAdapter->Param;
					if (v != NULL)
					{
						ROUTE_TRACKING *tr = v->RouteState;
						if (tr != NULL)
						{
							if (Cmp(tr->RouteToServer, t->RouteToServer, sizeof(ROUTE_ENTRY)) == 0)
							{
								do_not_delete_routing_entry = true;
							}
						}
					}
				}
			}
			Unlock(a->lock);
		}

		Lock(s->Account->lock);
	}

	if (do_not_delete_routing_entry == false)
	{
		// Delete the route that is added firstly
		if (t->RouteToServerAlreadyExists == false)
		{
			DeleteRouteEntry(t->RouteToServer);
		}

		DeleteRouteEntry(t->RouteToDefaultDns);

		DeleteRouteEntry(t->RouteToNatTServer);

		DeleteRouteEntry(t->RouteToRealServerGlobal);
	}

	FreeRouteEntry(t->RouteToDefaultDns);
	FreeRouteEntry(t->RouteToServer);
	FreeRouteEntry(t->RouteToEight);
	FreeRouteEntry(t->RouteToNatTServer);
	FreeRouteEntry(t->RouteToRealServerGlobal);
	t->RouteToDefaultDns = t->RouteToServer = t->RouteToEight =
		t->RouteToNatTServer = t->RouteToRealServerGlobal = NULL;

	if (s->Cedar->Client != NULL && s->Account != NULL)
	{
		Unlock(s->Account->lock);
	}

#if	0
	// Get the current DNS server
	if (GetDefaultDns(&dns_ip))
	{
		if (IPToUINT(&t->OldDnsServer) != 0)
		{
			if (IPToUINT(&t->OldDnsServer) != IPToUINT(&dns_ip))
			{
				char s1[MAX_SIZE], s2[MAX_SIZE];
				network_has_changed = true;
				IPToStr(s1, sizeof(s1), &t->OldDnsServer);
				IPToStr(s2, sizeof(s2), &dns_ip);
				Debug("Old Dns: %s, New Dns: %s\n",
					s1, s2);
			}
		}
	}

	if (network_has_changed == false)
	{
		Debug("Network: not changed.\n");
	}
	else
	{
		Debug("Network: Changed.\n");
	}

#endif

	// Get the current routing table
	table = GetRouteTable();

	// Restore the routing table which has been removed so far
	while (e = GetNext(t->DeletedDefaultGateway))
	{
		bool restore = true;
		UINT i;
		// If the restoring routing entry is a default gateway and
		// the existing routing table contains another default gateway
		// on the interface, give up restoring the entry
		if (IPToUINT(&e->DestIP) == 0 && IPToUINT(&e->DestMask) == 0)
		{
			for (i = 0;i < table->NumEntry;i++)
			{
				ROUTE_ENTRY *r = table->Entry[i];
				if (IPToUINT(&r->DestIP) == 0 && IPToUINT(&r->DestMask) == 0)
				{
					if (r->InterfaceID == e->InterfaceID)
					{
						restore = false;
					}
				}
			}
			if (network_has_changed)
			{
				restore = false;
			}
		}

		if (restore)
		{
			// Routing table restoration
			AddRouteEntry(e);
		}

		// Memory release
		FreeRouteEntry(e);
	}

	// Release
	FreeRouteTable(table);
	ReleaseQueue(t->DeletedDefaultGateway);

	FreeRouteChange(t->RouteChange);

	Free(t);
}

// Get the instance ID of the virtual LAN card
UINT GetInstanceId(char *name)
{
	char tmp[MAX_SIZE];
	UINT id = 0;
	// Validate arguments
	if (name == NULL)
	{
		return 0;
	}

	Format(tmp, sizeof(tmp), VLAN_ADAPTER_NAME_TAG, name);

	id = GetVLanInterfaceID(tmp);
	if (id != 0)
	{
		return id;
	}
	else
	{
		Format(tmp, sizeof(tmp), VLAN_ADAPTER_NAME_TAG_OLD, name);

		id = GetVLanInterfaceID(tmp);
		return id;
	}
}

// Get the instance list of virtual LAN card
INSTANCE_LIST *GetInstanceList()
{
	INSTANCE_LIST *n = ZeroMalloc(sizeof(INSTANCE_LIST));

	// Enumeration
	char **ss = EnumVLan(VLAN_ADAPTER_NAME);

	if (ss == NULL)
	{
		// Failure
		n->NumInstance = 0;
		n->InstanceName = Malloc(0);
		return n;
	}
	else
	{
		UINT i, num;
		i = num = 0;
		while (true)
		{
			if (ss[i++] == NULL)
			{
				break;
			}
			num++;
		}
		i = 0;
		n->NumInstance = num;
		n->InstanceName = (char **)ZeroMalloc(sizeof(char *) * n->NumInstance);
		for (i = 0;i < num;i++)
		{
			char *s = ss[i] + StrLen(VLAN_ADAPTER_NAME) + StrLen(" - ");
			if (StrLen(ss[i]) > StrLen(VLAN_ADAPTER_NAME) + StrLen(" - "))
			{
				n->InstanceName[i] = CopyStr(s);
			}
		}
		FreeEnumVLan(ss);
	}

	ss = EnumVLan(VLAN_ADAPTER_NAME_OLD);
	if (ss != NULL)
	{
		UINT i, num, j;

		i = num = 0;
		while (true)
		{
			if (ss[i++] == NULL)
			{
				break;
			}
			num++;
		}
		j = n->NumInstance;
		n->NumInstance += num;
		n->InstanceName = (char **)ReAlloc(n->InstanceName, sizeof(char) * n->NumInstance);
		for (i = 0;i < num;i++)
		{
			char *s = ss[i] + StrLen(VLAN_ADAPTER_NAME_OLD) + StrLen(" - ");
			if (StrLen(ss[i]) > StrLen(VLAN_ADAPTER_NAME_OLD) + StrLen(" - "))
			{
				n->InstanceName[j] = CopyStr(s);
			}
			j++;
		}
		FreeEnumVLan(ss);
	}

	return n;
}

// Release the instance list
void FreeInstanceList(INSTANCE_LIST *n)
{
	UINT i;
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	for (i = 0;i < n->NumInstance;i++)
	{
		Free(n->InstanceName[i]);
	}
	Free(n->InstanceName);
	Free(n);
}

// Release the packet adapter
void VLanPaFree(SESSION *s)
{
	VLAN *v;
	ROUTE_TRACKING *t;
	// Validate arguments
	if ((s == NULL) || ((v = s->PacketAdapter->Param) == NULL))
	{
		return;
	}

	// Release the IP address if you are using DHCP
	if (IsNt())
	{
		char tmp[MAX_SIZE];
		MS_ADAPTER *a;

		Format(tmp, sizeof(tmp), VLAN_ADAPTER_NAME_TAG, v->InstanceName);
		a = MsGetAdapter(tmp);

		if (a != NULL)
		{
			if (a->UseDhcp)
			{
				bool ret = Win32ReleaseAddressByGuidEx(a->Guid, 50);
				Debug("*** Win32ReleaseAddressByGuid = %u\n", ret);
			}

			MsFreeAdapter(a);
		}
	}

	t = v->RouteState;
	// End the virtual LAN card
	FreeVLan(v);

	// End the routing table tracking 
	if (s->ClientModeAndUseVLan)
	{
		RouteTrackingStop(s, t);
	}
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
		return 0;
	}

	RouteTrackingMain(s);

	if (VLanGetNextPacket(v, data, &size) == false)
	{
		return INFINITE;
	}

	return size;
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

// Initialize the packet adapter
bool VLanPaInit(SESSION *s)
{
	VLAN *v;
	// Validate arguments
	if ((s == NULL)/* || (s->ServerMode != false) || (s->ClientOption == NULL)*/)
	{
		return false;
	}

	// Get the IP address of the DNS server at the time just before the connection
	if (s->ClientModeAndUseVLan)
	{
		Zero(&s->DefaultDns, sizeof(IP));
		GetDefaultDns(&s->DefaultDns);
	}

	// Normalize the setting of interface metric of the default gateway
	if (s->ClientModeAndUseVLan)
	{
		if (MsIsVista())
		{
			MsNormalizeInterfaceDefaultGatewaySettings(VLAN_ADAPTER_NAME_TAG, s->ClientOption->DeviceName);
			MsNormalizeInterfaceDefaultGatewaySettings(VLAN_ADAPTER_NAME_TAG_OLD, s->ClientOption->DeviceName);
		}
	}

	// Connect to the driver
	v = NewVLan(s->ClientOption->DeviceName, NULL);
	if (v == NULL)
	{
		// Failure
		return false;
	}

	s->PacketAdapter->Param = v;

	// Routing table tracking start
	if (s->ClientModeAndUseVLan)
	{
		RouteTrackingStart(s);
	}

	return true;
}

// Get the packet adapter of the VLAN
PACKET_ADAPTER *VLanGetPacketAdapter()
{
	PACKET_ADAPTER *pa;

	pa = NewPacketAdapter(VLanPaInit, VLanPaGetCancel,
		VLanPaGetNextPacket, VLanPaPutPacket, VLanPaFree);
	if (pa == NULL)
	{
		return NULL;
	}

	pa->Id = PACKET_ADAPTER_ID_VLAN_WIN32;

	return pa;
}


// Write the next received packet to the driver
bool VLanPutPacket(VLAN *v, void *buf, UINT size)
{
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

	// First, examine whether the current buffer is full
	if ((NEO_NUM_PACKET(v->PutBuffer) >= NEO_MAX_PACKET_EXCHANGE) ||
		(buf == NULL && NEO_NUM_PACKET(v->PutBuffer) != 0))
	{
#ifdef	USE_PROBE
		{
			char tmp[MAX_SIZE];
			snprintf(tmp, sizeof(tmp), "VLanPutPacket: NEO_NUM_PACKET(v->PutBuffer) = %u", NEO_NUM_PACKET(v->PutBuffer));
			PROBE_DATA2(tmp, NULL, 0);
		}
#endif	// USE_PROBE
		// Write a packet to the driver
		if (VLanPutPacketsToDriver(v) == false)
		{
			return false;
		}
		NEO_NUM_PACKET(v->PutBuffer) = 0;
	}

	// Add the next packet to the buffer
	if (buf != NULL)
	{
		UINT i = NEO_NUM_PACKET(v->PutBuffer);
		NEO_NUM_PACKET(v->PutBuffer)++;

		NEO_SIZE_OF_PACKET(v->PutBuffer, i) = size;
		Copy(NEO_ADDR_OF_PACKET(v->PutBuffer, i), buf, size);
		Free(buf);
	}

	return true;
}

// Read the next sent packet from the driver
bool VLanGetNextPacket(VLAN *v, void **buf, UINT *size)
{
	// Validate arguments
	if (v == NULL || buf == NULL || size == NULL)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}

	PROBE_STR("VLanGetNextPacket");

	while (true)
	{
		if (v->CurrentPacketCount < NEO_NUM_PACKET(v->GetBuffer))
		{
			// There are still packets that have been read already
			*size = NEO_SIZE_OF_PACKET(v->GetBuffer, v->CurrentPacketCount);
			*buf = MallocFast(*size);
			Copy(*buf, NEO_ADDR_OF_PACKET(v->GetBuffer, v->CurrentPacketCount), *size);

			// Increment the packet number
			v->CurrentPacketCount++;

			return true;
		}
		else
		{
			// Read the next packet from the driver
			if (VLanGetPacketsFromDriver(v) == false)
			{
				return false;
			}

			if (NEO_NUM_PACKET(v->GetBuffer) == 0)
			{
				// Packet is not received currently
				*buf = NULL;
				*size = 0;
				return true;
			}

			v->CurrentPacketCount = 0;
		}
	}
}

// Write all the current packets to the driver
bool VLanPutPacketsToDriver(VLAN *v)
{
	DWORD write_size;
	// Validate arguments
	if (v == NULL)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}

	if (v->Win9xMode == false)
	{
		// Windows NT
		PROBE_STR("VLanPutPacketsToDriver: WriteFile");
		if (WriteFile(v->Handle, v->PutBuffer, NEO_EXCHANGE_BUFFER_SIZE, &write_size,
			NULL) == false)
		{
			v->Halt = true;
			return false;
		}
		PROBE_STR("VLanPutPacketsToDriver: WriteFile Completed.");

		if (write_size != NEO_EXCHANGE_BUFFER_SIZE)
		{
			v->Halt = true;
			return false;
		}
	}
	else
	{
		// Windows 9x
		if (DeviceIoControl(v->Handle, NEO_IOCTL_PUT_PACKET, v->PutBuffer,
			NEO_EXCHANGE_BUFFER_SIZE, NULL, 0, &write_size, NULL) == false)
		{
			v->Halt = true;
			return false;
		}
	}

	return true;
}

// Read the next packet from the driver
bool VLanGetPacketsFromDriver(VLAN *v)
{
	DWORD read_size;
	// Validate arguments
	if (v == NULL)
	{
		return false;
	}
	if (v->Halt)
	{
		return false;
	}

	if (v->Win9xMode == false)
	{
		// Windows NT
		PROBE_STR("VLanGetPacketsFromDriver: ReadFile");
		if (ReadFile(v->Handle, v->GetBuffer, NEO_EXCHANGE_BUFFER_SIZE,
			&read_size, NULL) == false)
		{
			v->Halt = true;
			return false;
		}
	}
	else
	{
		// Windows 9x
		if (DeviceIoControl(v->Handle, NEO_IOCTL_GET_PACKET, NULL, 0,
			v->GetBuffer, NEO_EXCHANGE_BUFFER_SIZE, &read_size, NULL) == false)
		{
			v->Halt = true;
			return false;
		}
	}

	if (read_size != NEO_EXCHANGE_BUFFER_SIZE)
	{
		v->Halt = true;
		return false;
	}

	return true;
}

// Get the cancel object
CANCEL *VLanGetCancel(VLAN *v)
{
	CANCEL *c;
	// Validate arguments
	if (v == NULL)
	{
		return NULL;
	}

	// Create a cancel object
	c = NewCancel();
	c->SpecialFlag = true;
	CloseHandle(c->hEvent);

	c->hEvent = v->Event;

	return c;
}

// Release the VLAN object
void FreeVLan(VLAN *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	// Close the handle
	CloseHandle(v->Event);
	CloseHandle(v->Handle);

	// Memory release
	Free(v->InstanceName);
	Free(v->EventNameWin32);
	Free(v->DeviceNameWin32);
	Free(v->PutBuffer);
	Free(v->GetBuffer);
	Free(v);
}

// Create a VLAN object
VLAN *NewVLan(char *instance_name, VLAN_PARAM *param)
{
	VLAN *v;
	HANDLE h = INVALID_HANDLE_VALUE;
	HANDLE e = INVALID_HANDLE_VALUE;
	char tmp[MAX_SIZE];
	char name_upper[MAX_SIZE];
	// Validate arguments
	if (instance_name == NULL)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(VLAN));

	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType))
	{
		v->Win9xMode = true;
	}

	// Initialize the name
	Format(name_upper, sizeof(name_upper), "%s", instance_name);
	StrUpper(name_upper);
	v->InstanceName = CopyStr(name_upper);
	Format(tmp, sizeof(tmp), NDIS_NEO_DEVICE_FILE_NAME, v->InstanceName);
	v->DeviceNameWin32 = CopyStr(tmp);

	if (v->Win9xMode == false)
	{
		Format(tmp, sizeof(tmp), NDIS_NEO_EVENT_NAME_WIN32, v->InstanceName);
		v->EventNameWin32 = CopyStr(tmp);
	}

	// Connect to the device
	h = CreateFile(v->DeviceNameWin32,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		// Connection failure
		goto CLEANUP;
	}

	if (v->Win9xMode == false)
	{
		// Connect to the event
		e = OpenEvent(SYNCHRONIZE, FALSE, v->EventNameWin32);
		if (e == INVALID_HANDLE_VALUE)
		{
			// Connection failure
			goto CLEANUP;
		}
	}
	else
	{
		OPENVXDHANDLE OpenVxDHandle;
		DWORD vxd_handle;
		UINT bytes_returned;

		OpenVxDHandle = (OPENVXDHANDLE)GetProcAddress(GetModuleHandle("KERNEL32"),
			"OpenVxDHandle");

		// Deliver to the driver by creating an event
		e = CreateEvent(NULL, FALSE, FALSE, NULL);
		vxd_handle = (DWORD)OpenVxDHandle(e);

		DeviceIoControl(h, NEO_IOCTL_SET_EVENT, &vxd_handle, sizeof(DWORD),
			NULL, 0, &bytes_returned, NULL);
	}

	v->Event = e;
	v->Handle = h;

	v->GetBuffer = ZeroMalloc(NEO_EXCHANGE_BUFFER_SIZE);
	v->PutBuffer = ZeroMalloc(NEO_EXCHANGE_BUFFER_SIZE);

	return v;

CLEANUP:
	if (h != INVALID_HANDLE_VALUE)
	{
		CloseHandle(h);
	}
	if (e != INVALID_HANDLE_VALUE)
	{
		CloseHandle(e);
	}

	Free(v->InstanceName);
	Free(v->EventNameWin32);
	Free(v->DeviceNameWin32);
	Free(v);

	return NULL;
}

#endif	// OS_WIN32

#endif	//VLAN_C


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
