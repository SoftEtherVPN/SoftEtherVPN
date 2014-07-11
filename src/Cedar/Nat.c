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


// Nat.c
// User-mode Router

#include "CedarPch.h"

static LOCK *nat_lock = NULL;
static NAT *nat = NULL;


// Disconnect the connection for the NAT administrator
void NatAdminDisconnect(RPC *r)
{
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	EndRpc(r);
}

// Connection for NAT administrator
RPC *NatAdminConnect(CEDAR *cedar, char *hostname, UINT port, void *hashed_password, UINT *err)
{
	UCHAR secure_password[SHA1_SIZE];
	UCHAR random[SHA1_SIZE];
	SOCK *sock;
	RPC *rpc;
	PACK *p;
	UINT error;
	// Validate arguments
	if (cedar == NULL || hostname == NULL || port == 0 || hashed_password == NULL || err == NULL)
	{
		if (err != NULL)
		{
			*err = ERR_INTERNAL_ERROR;
		}
		return NULL;
	}

	// Connection
	sock = Connect(hostname, port);
	if (sock == NULL)
	{
		*err = ERR_CONNECT_FAILED;
		return NULL;
	}

	if (StartSSL(sock, NULL, NULL) == false)
	{
		*err = ERR_PROTOCOL_ERROR;
		ReleaseSock(sock);
		return NULL;
	}

	SetTimeout(sock, 5000);

	p = HttpClientRecv(sock);
	if (p == NULL)
	{
		*err = ERR_DISCONNECTED;
		ReleaseSock(sock);
		return NULL;
	}

	if (PackGetData2(p, "auth_random", random, SHA1_SIZE) == false)
	{
		FreePack(p);
		*err = ERR_PROTOCOL_ERROR;
		ReleaseSock(sock);
		return NULL;
	}

	FreePack(p);

	SecurePassword(secure_password, hashed_password, random);

	p = NewPack();
	PackAddData(p, "secure_password", secure_password, SHA1_SIZE);

	if (HttpClientSend(sock, p) == false)
	{
		FreePack(p);
		*err = ERR_DISCONNECTED;
		ReleaseSock(sock);
		return NULL;
	}

	FreePack(p);

	p = HttpClientRecv(sock);
	if (p == NULL)
	{
		*err = ERR_DISCONNECTED;
		ReleaseSock(sock);
		return NULL;
	}

	error = GetErrorFromPack(p);

	FreePack(p);

	if (error != ERR_NO_ERROR)
	{
		*err = error;
		ReleaseSock(sock);
		return NULL;
	}

	SetTimeout(sock, TIMEOUT_INFINITE);

	rpc = StartRpcClient(sock, NULL);
	ReleaseSock(sock);

	return rpc;
}

// RPC functional related macro
#define	DECLARE_RPC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type t;													\
		Zero(&t, sizeof(t));											\
		in_rpc(&t, p);													\
		err = function(n, &t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, &t);											\
		}																\
		free_rpc(&t);													\
		ok = true;														\
	}
#define	DECLARE_RPC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	else if (StrCmpi(name, rpc_name) == 0)								\
	{																	\
		data_type t;													\
		Zero(&t, sizeof(t));											\
		in_rpc(&t, p);													\
		err = function(n, &t);											\
		if (err == ERR_NO_ERROR)										\
		{																\
			out_rpc(ret, &t);											\
		}																\
		ok = true;														\
	}
#define	DECLARE_SC_EX(rpc_name, data_type, function, in_rpc, out_rpc, free_rpc)	\
	UINT function(RPC *r, data_type *t)									\
	{																	\
		PACK *p, *ret;													\
		UINT err;														\
		if (r == NULL || t == NULL)										\
		{																\
			return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		free_rpc(t);													\
		Zero(t, sizeof(data_type));										\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
			in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}
#define	DECLARE_SC(rpc_name, data_type, function, in_rpc, out_rpc)		\
	UINT function(RPC *r, data_type *t)									\
	{																	\
		PACK *p, *ret;													\
		UINT err;														\
		if (r == NULL || t == NULL)										\
		{																\
			return ERR_INTERNAL_ERROR;									\
		}																\
		p = NewPack();													\
		out_rpc(p, t);													\
		ret = AdminCall(r, rpc_name, p);								\
		err = GetErrorFromPack(ret);									\
		if (err == ERR_NO_ERROR)										\
		{																\
			in_rpc(t, ret);												\
		}																\
		FreePack(ret);													\
		return err;														\
	}

// RPC server function
PACK *NiRpcServer(RPC *r, char *name, PACK *p)
{
	NAT *n = (NAT *)r->Param;
	PACK *ret;
	UINT err;
	bool ok;
	// Validate arguments
	if (r == NULL || name == NULL || p == NULL)
	{
		return NULL;
	}

	ret = NewPack();
	err = ERR_NO_ERROR;
	ok = false;

	if (0) {}

	// RPC function definition: From here

//	DECLARE_RPC("Online", RPC_DUMMY, NtOnline, InRpcDummy, OutRpcDummy)
//	DECLARE_RPC("Offline", RPC_DUMMY, NtOffline, InRpcDummy, OutRpcDummy)
	DECLARE_RPC("SetHostOption", VH_OPTION, NtSetHostOption, InVhOption, OutVhOption)
	DECLARE_RPC("GetHostOption", VH_OPTION, NtGetHostOption, InVhOption, OutVhOption)
//	DECLARE_RPC_EX("SetClientConfig", RPC_CREATE_LINK, NtSetClientConfig, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
//	DECLARE_RPC_EX("GetClientConfig", RPC_CREATE_LINK, NtGetClientConfig, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
	DECLARE_RPC_EX("GetStatus", RPC_NAT_STATUS, NtGetStatus, InRpcNatStatus, OutRpcNatStatus, FreeRpcNatStatus)
//	DECLARE_RPC_EX("GetInfo", RPC_NAT_INFO, NtGetInfo, InRpcNatInfo, OutRpcNatInfo, FreeRpcNatInfo)
	DECLARE_RPC_EX("EnumNatList", RPC_ENUM_NAT, NtEnumNatList, InRpcEnumNat, OutRpcEnumNat, FreeRpcEnumNat)
	DECLARE_RPC_EX("EnumDhcpList", RPC_ENUM_DHCP, NtEnumDhcpList, InRpcEnumDhcp, OutRpcEnumDhcp, FreeRpcEnumDhcp)
//	DECLARE_RPC("SetPassword", RPC_SET_PASSWORD, NtSetPassword, InRpcSetPassword, OutRpcSetPassword)

	// RPC function definition: To here

	if (ok == false)
	{
		err = ERR_NOT_SUPPORTED;
	}

	PackAddInt(ret, "error", err);

	return ret;
}




// RPC call definition: From here

DECLARE_SC("Online", RPC_DUMMY, NcOnline, InRpcDummy, OutRpcDummy)
DECLARE_SC("Offline", RPC_DUMMY, NcOffline, InRpcDummy, OutRpcDummy)
DECLARE_SC("SetHostOption", VH_OPTION, NcSetHostOption, InVhOption, OutVhOption)
DECLARE_SC("GetHostOption", VH_OPTION, NcGetHostOption, InVhOption, OutVhOption)
DECLARE_SC_EX("SetClientConfig", RPC_CREATE_LINK, NcSetClientConfig, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("GetClientConfig", RPC_CREATE_LINK, NcGetClientConfig, InRpcCreateLink, OutRpcCreateLink, FreeRpcCreateLink)
DECLARE_SC_EX("GetStatus", RPC_NAT_STATUS, NcGetStatus, InRpcNatStatus, OutRpcNatStatus, FreeRpcNatStatus)
DECLARE_SC_EX("GetInfo", RPC_NAT_INFO, NcGetInfo, InRpcNatInfo, OutRpcNatInfo, FreeRpcNatInfo)
DECLARE_SC_EX("EnumNatList", RPC_ENUM_NAT, NcEnumNatList, InRpcEnumNat, OutRpcEnumNat, FreeRpcEnumNat)
DECLARE_SC_EX("EnumDhcpList", RPC_ENUM_DHCP, NcEnumDhcpList, InRpcEnumDhcp, OutRpcEnumDhcp, FreeRpcEnumDhcp)
DECLARE_SC("SetPassword", RPC_SET_PASSWORD, NcSetPassword, InRpcSetPassword, OutRpcSetPassword)

// RPC call definition: To here



// Set a password
UINT NtSetPassword(NAT *n, RPC_SET_PASSWORD *t)
{
	Copy(n->HashedPassword, t->HashedPassword, SHA1_SIZE);

	NiWriteConfig(n);

	return ERR_NO_ERROR;
}

// Online
UINT NtOnline(NAT *n, RPC_DUMMY *t)
{
	UINT ret = ERR_NO_ERROR;

	Lock(n->lock);
	{
		if (n->Online)
		{
			// It is already online
			ret = ERR_ALREADY_ONLINE;
		}
		else
		{
			if (n->ClientOption == NULL || n->ClientAuth == NULL)
			{
				// Setting is not yet done
				ret = ERR_ACCOUNT_NOT_PRESENT;
			}
			else
			{
				// OK
				n->Online = true;

				// Start connection
				n->Virtual = NewVirtualHostEx(n->Cedar, n->ClientOption, n->ClientAuth,
					&n->Option, n);
			}
		}
	}
	Unlock(n->lock);

	NiWriteConfig(n);

	return ret;
}

// Offline
UINT NtOffline(NAT *n, RPC_DUMMY *t)
{
	UINT ret = ERR_NO_ERROR;

	Lock(n->lock);
	{
		if (n->Online == false)
		{
			// It is offline
			ret = ERR_OFFLINE;
		}
		else
		{
			// Offline
			StopVirtualHost(n->Virtual);
			ReleaseVirtual(n->Virtual);
			n->Virtual = NULL;

			n->Online = false;
		}
	}
	Unlock(n->lock);

	NiWriteConfig(n);

	return ret;
}

// Set host options
UINT NtSetHostOption(NAT *n, VH_OPTION *t)
{
	UINT ret = ERR_NO_ERROR;

	Lock(n->lock);
	{
		Copy(&n->Option, t, sizeof(VH_OPTION));
	}
	Unlock(n->lock);

	SetVirtualHostOption(n->Virtual, t);

	NiWriteConfig(n);

	return ret;
}

// Get host options
UINT NtGetHostOption(NAT *n, VH_OPTION *t)
{
	UINT ret = ERR_NO_ERROR;

	Lock(n->lock);
	{
		Copy(t, &n->Option, sizeof(VH_OPTION));
	}
	Unlock(n->lock);

	return ret;
}

// Set the connection settings
UINT NtSetClientConfig(NAT *n, RPC_CREATE_LINK *t)
{
	Lock(n->lock);
	{
		if (n->ClientOption != NULL || n->ClientAuth != NULL)
		{
			Free(n->ClientOption);
			CiFreeClientAuth(n->ClientAuth);
		}

		n->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		Copy(n->ClientOption, t->ClientOption, sizeof(CLIENT_OPTION));
		n->ClientAuth = CopyClientAuth(t->ClientAuth);
	}
	Unlock(n->lock);

	NiWriteConfig(n);

	if (n->Online)
	{
		NtOffline(n, NULL);
		NtOnline(n, NULL);
	}

	return ERR_NO_ERROR;
}

// Get the connection settings
UINT NtGetClientConfig(NAT *n, RPC_CREATE_LINK *t)
{
	UINT err = ERR_NO_ERROR;

	Lock(n->lock);
	{
		if (n->ClientOption == NULL || n->ClientAuth == NULL)
		{
			err = ERR_ACCOUNT_NOT_PRESENT;
		}
		else
		{
			FreeRpcCreateLink(t);

			Zero(t, sizeof(RPC_CREATE_LINK));
			t->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
			Copy(t->ClientOption, n->ClientOption, sizeof(CLIENT_OPTION));
			t->ClientAuth = CopyClientAuth(n->ClientAuth);
		}
	}
	Unlock(n->lock);

	return err;
}

// Get the state
UINT NtGetStatus(NAT *n, RPC_NAT_STATUS *t)
{
	Lock(n->lock);
	{
		VH *v = n->Virtual;
		FreeRpcNatStatus(t);
		Zero(t, sizeof(RPC_NAT_STATUS));

		LockVirtual(v);
		{
			UINT i;

			LockList(v->NatTable);
			{
				for (i = 0;i < LIST_NUM(v->NatTable);i++)
				{
					NAT_ENTRY *e = LIST_DATA(v->NatTable, i);

					switch (e->Protocol)
					{
					case NAT_TCP:
						t->NumTcpSessions++;
						break;

					case NAT_UDP:
						t->NumUdpSessions++;
						break;

					case NAT_ICMP:
						t->NumIcmpSessions++;
						break;

					case NAT_DNS:
						t->NumDnsSessions++;
						break;
					}
				}

				if (NnIsActive(v) && v->NativeNat != NULL)
				{
					NATIVE_NAT *nn = v->NativeNat;

					for (i = 0;i < LIST_NUM(nn->NatTableForSend->AllList);i++)
					{
						NATIVE_NAT_ENTRY *e = LIST_DATA(nn->NatTableForSend->AllList, i);

						switch (e->Protocol)
						{
						case NAT_TCP:
							t->NumTcpSessions++;
							break;

						case NAT_UDP:
							t->NumUdpSessions++;
							break;

						case NAT_ICMP:
							t->NumIcmpSessions++;
							break;

						case NAT_DNS:
							t->NumDnsSessions++;
							break;
						}
					}
				}
			}
			UnlockList(v->NatTable);

			t->NumDhcpClients = LIST_NUM(v->DhcpLeaseList);

			t->IsKernelMode = NnIsActive(v);
		}
		UnlockVirtual(v);
	}
	Unlock(n->lock);

	return ERR_NO_ERROR;
}

// Get the information
UINT NtGetInfo(NAT *n, RPC_NAT_INFO *t)
{
	OS_INFO *info;
	FreeRpcNatInfo(t);
	Zero(t, sizeof(RPC_NAT_INFO));

	StrCpy(t->NatProductName, sizeof(t->NatProductName), CEDAR_ROUTER_STR);
	StrCpy(t->NatVersionString, sizeof(t->NatVersionString), n->Cedar->VerString);
	StrCpy(t->NatBuildInfoString, sizeof(t->NatBuildInfoString), n->Cedar->BuildInfo);
	t->NatVerInt = n->Cedar->Build;
	t->NatBuildInt = n->Cedar->Build;

	GetMachineName(t->NatHostName, sizeof(t->NatHostName));

	info = GetOsInfo();

	CopyOsInfo(&t->OsInfo, info);

	GetMemInfo(&t->MemInfo);

	return ERR_NO_ERROR;
}

// Get the NAT list
UINT NtEnumNatList(NAT *n, RPC_ENUM_NAT *t)
{
	UINT ret = ERR_NO_ERROR;
	VH *v = NULL;

	Lock(n->lock);
	{
		v = n->Virtual;

		if (n->Online == false || v == NULL)
		{
			ret = ERR_OFFLINE;
		}
		else
		{
			LockVirtual(v);
			{
				if (v->Active == false)
				{
					ret = ERR_OFFLINE;
				}
				else
				{
					FreeRpcEnumNat(t);
					Zero(t, sizeof(RPC_ENUM_NAT));

					LockList(v->NatTable);
					{
						UINT i;
						UINT num_usermode_nat = LIST_NUM(v->NatTable);
						UINT num_kernel_mode_nat = 0;
						NATIVE_NAT *native = NULL;

						if (NnIsActive(v) && (v->NativeNat != NULL))
						{
							native = v->NativeNat;

							num_kernel_mode_nat = LIST_NUM(native->NatTableForSend->AllList);
						}

						t->NumItem = num_usermode_nat + num_kernel_mode_nat;
						t->Items = ZeroMalloc(sizeof(RPC_ENUM_NAT_ITEM) * t->NumItem);

						// Enumerate entries of the user mode NAT
						for (i = 0;i < num_usermode_nat;i++)
						{
							NAT_ENTRY *nat = LIST_DATA(v->NatTable, i);
							RPC_ENUM_NAT_ITEM *e = &t->Items[i];

							e->Id = nat->Id;
							e->Protocol = nat->Protocol;
							e->SrcIp = nat->SrcIp;
							e->DestIp = nat->DestIp;
							e->SrcPort = nat->SrcPort;
							e->DestPort = nat->DestPort;

							e->CreatedTime = TickToTime(nat->CreatedTime);
							e->LastCommTime = TickToTime(nat->LastCommTime);

							IPToStr32(e->SrcHost, sizeof(e->SrcHost), e->SrcIp);
							IPToStr32(e->DestHost, sizeof(e->DestHost), e->DestIp);

							if (nat->Sock != NULL)
							{
								e->SendSize = nat->Sock->SendSize;
								e->RecvSize = nat->Sock->RecvSize;

								if (nat->Sock->Type == SOCK_TCP)
								{
									StrCpy(e->DestHost, sizeof(e->DestHost), nat->Sock->RemoteHostname);
								}
							}

							e->TcpStatus = nat->TcpStatus;
						}

						// Enumerate the entries in the kernel-mode NAT
						if (native != NULL)
						{
							for (i = 0;i < num_kernel_mode_nat;i++)
							{
								NATIVE_NAT_ENTRY *nat = LIST_DATA(native->NatTableForSend->AllList, i);
								RPC_ENUM_NAT_ITEM *e = &t->Items[num_usermode_nat + i];

								e->Id = nat->Id;
								e->Protocol = nat->Protocol;
								e->SrcIp = nat->SrcIp;
								e->DestIp = nat->DestIp;
								e->SrcPort = nat->SrcPort;
								e->DestPort = nat->DestPort;
								e->CreatedTime = TickToTime(nat->CreatedTime);
								e->LastCommTime = TickToTime(nat->LastCommTime);

								IPToStr32(e->SrcHost, sizeof(e->SrcHost), e->SrcIp);
								IPToStr32(e->DestHost, sizeof(e->DestHost), e->DestIp);

								e->SendSize = nat->TotalSent;
								e->RecvSize = nat->TotalRecv;

								e->TcpStatus = nat->Status;
							}
						}
					}
					UnlockList(v->NatTable);
				}
			}
			UnlockVirtual(v);
		}
	}
	Unlock(n->lock);

	return ret;
}

UINT NtEnumDhcpList(NAT *n, RPC_ENUM_DHCP *t)
{
	UINT ret = ERR_NO_ERROR;
	VH *v = NULL;

	Lock(n->lock);
	{
		v = n->Virtual;

		if (n->Online == false || v == NULL)
		{
			ret = ERR_OFFLINE;
		}
		else
		{
			LockVirtual(v);
			{
				if (v->Active == false)
				{
					ret = ERR_OFFLINE;
				}
				else
				{
					FreeRpcEnumDhcp(t);
					Zero(t, sizeof(RPC_ENUM_DHCP));

					LockList(v->DhcpLeaseList);
					{
						UINT i;
						t->NumItem = LIST_NUM(v->DhcpLeaseList);
						t->Items = ZeroMalloc(sizeof(RPC_ENUM_DHCP_ITEM) * t->NumItem);

						for (i = 0;i < t->NumItem;i++)
						{
							DHCP_LEASE *dhcp = LIST_DATA(v->DhcpLeaseList, i);
							RPC_ENUM_DHCP_ITEM *e = &t->Items[i];

							e->Id = dhcp->Id;
							e->LeasedTime = TickToTime(dhcp->LeasedTime);
							e->ExpireTime = TickToTime(dhcp->ExpireTime);
							Copy(e->MacAddress, dhcp->MacAddress, 6);
							e->IpAddress = dhcp->IpAddress;
							e->Mask = dhcp->Mask;
							StrCpy(e->Hostname, sizeof(e->Hostname), dhcp->Hostname);
						}
					}
					UnlockList(v->DhcpLeaseList);
				}
			}
			UnlockVirtual(v);
		}
	}
	Unlock(n->lock);

	return ret;
}

// VH_OPTION
void InVhOption(VH_OPTION *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(VH_OPTION));
	PackGetData2(p, "MacAddress", t->MacAddress, 6);
	PackGetIp(p, "Ip", &t->Ip);
	PackGetIp(p, "Mask", &t->Mask);
	t->UseNat = PackGetBool(p, "UseNat");
	t->Mtu = PackGetInt(p, "Mtu");
	t->NatTcpTimeout = PackGetInt(p, "NatTcpTimeout");
	t->NatUdpTimeout = PackGetInt(p, "NatUdpTimeout");
	t->UseDhcp = PackGetBool(p, "UseDhcp");
	PackGetIp(p, "DhcpLeaseIPStart", &t->DhcpLeaseIPStart);
	PackGetIp(p, "DhcpLeaseIPEnd", &t->DhcpLeaseIPEnd);
	PackGetIp(p, "DhcpSubnetMask", &t->DhcpSubnetMask);
	t->DhcpExpireTimeSpan = PackGetInt(p, "DhcpExpireTimeSpan");
	PackGetIp(p, "DhcpGatewayAddress", &t->DhcpGatewayAddress);
	PackGetIp(p, "DhcpDnsServerAddress", &t->DhcpDnsServerAddress);
	PackGetIp(p, "DhcpDnsServerAddress2", &t->DhcpDnsServerAddress2);
	PackGetStr(p, "DhcpDomainName", t->DhcpDomainName, sizeof(t->DhcpDomainName));
	t->SaveLog = PackGetBool(p, "SaveLog");
	PackGetStr(p, "RpcHubName", t->HubName, sizeof(t->HubName));
	t->ApplyDhcpPushRoutes = PackGetBool(p, "ApplyDhcpPushRoutes");
	PackGetStr(p, "DhcpPushRoutes", t->DhcpPushRoutes, sizeof(t->DhcpPushRoutes));
}
void OutVhOption(PACK *p, VH_OPTION *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddData(p, "MacAddress", t->MacAddress, 6);
	PackAddIp(p, "Ip", &t->Ip);
	PackAddIp(p, "Mask", &t->Mask);
	PackAddBool(p, "UseNat", t->UseNat);
	PackAddInt(p, "Mtu", t->Mtu);
	PackAddInt(p, "NatTcpTimeout", t->NatTcpTimeout);
	PackAddInt(p, "NatUdpTimeout", t->NatUdpTimeout);
	PackAddBool(p, "UseDhcp", t->UseDhcp);
	PackAddIp(p, "DhcpLeaseIPStart", &t->DhcpLeaseIPStart);
	PackAddIp(p, "DhcpLeaseIPEnd", &t->DhcpLeaseIPEnd);
	PackAddIp(p, "DhcpSubnetMask", &t->DhcpSubnetMask);
	PackAddInt(p, "DhcpExpireTimeSpan", t->DhcpExpireTimeSpan);
	PackAddIp(p, "DhcpGatewayAddress", &t->DhcpGatewayAddress);
	PackAddIp(p, "DhcpDnsServerAddress", &t->DhcpDnsServerAddress);
	PackAddIp(p, "DhcpDnsServerAddress2", &t->DhcpDnsServerAddress2);
	PackAddStr(p, "DhcpDomainName", t->DhcpDomainName);
	PackAddBool(p, "SaveLog", t->SaveLog);
	PackAddStr(p, "RpcHubName", t->HubName);
	PackAddBool(p, "ApplyDhcpPushRoutes", true);
	PackAddStr(p, "DhcpPushRoutes", t->DhcpPushRoutes);
}

// RPC_ENUM_DHCP
void InRpcEnumDhcp(RPC_ENUM_DHCP *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_DHCP));
	t->NumItem = PackGetInt(p, "NumItem");
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_DHCP_ITEM) * t->NumItem);
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_DHCP_ITEM *e = &t->Items[i];

		e->Id = PackGetIntEx(p, "Id", i);
		e->LeasedTime = PackGetInt64Ex(p, "LeasedTime", i);
		e->ExpireTime = PackGetInt64Ex(p, "ExpireTime", i);
		PackGetDataEx2(p, "MacAddress", e->MacAddress, 6, i);
		e->IpAddress = PackGetIp32Ex(p, "IpAddress", i);
		e->Mask = PackGetIntEx(p, "Mask", i);
		PackGetStrEx(p, "Hostname", e->Hostname, sizeof(e->Hostname), i);
	}
}
void OutRpcEnumDhcp(PACK *p, RPC_ENUM_DHCP *t)
{
	UINT i;
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);
	PackAddStr(p, "HubName", t->HubName);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_DHCP_ITEM *e = &t->Items[i];

		PackAddIntEx(p, "Id", e->Id, i, t->NumItem);
		PackAddInt64Ex(p, "LeasedTime", e->LeasedTime, i, t->NumItem);
		PackAddInt64Ex(p, "ExpireTime", e->ExpireTime, i, t->NumItem);
		PackAddDataEx(p, "MacAddress", e->MacAddress, 6, i, t->NumItem);
		PackAddIp32Ex(p, "IpAddress", e->IpAddress, i, t->NumItem);
		PackAddIntEx(p, "Mask", e->Mask, i, t->NumItem);
		PackAddStrEx(p, "Hostname", e->Hostname, i, t->NumItem);
	}
}
void FreeRpcEnumDhcp(RPC_ENUM_DHCP *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_ENUM_NAT
void InRpcEnumNat(RPC_ENUM_NAT *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_NAT));
	t->NumItem = PackGetInt(p, "NumItem");
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_NAT_ITEM) * t->NumItem);
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_NAT_ITEM *e = &t->Items[i];

		e->Id = PackGetIntEx(p, "Id", i);
		e->Protocol = PackGetIntEx(p, "Protocol", i);
		e->SrcIp = PackGetIntEx(p, "SrcIp", i);
		PackGetStrEx(p, "SrcHost", e->SrcHost, sizeof(e->SrcHost), i);
		e->SrcPort = PackGetIntEx(p, "SrcPort", i);
		e->DestIp = PackGetIntEx(p, "DestIp", i);
		PackGetStrEx(p, "DestHost", e->DestHost, sizeof(e->DestHost), i);
		e->DestPort = PackGetIntEx(p, "DestPort", i);
		e->CreatedTime = PackGetInt64Ex(p, "CreatedTime", i);
		e->LastCommTime = PackGetInt64Ex(p, "LastCommTime", i);
		e->SendSize = PackGetInt64Ex(p, "SendSize", i);
		e->RecvSize = PackGetInt64Ex(p, "RecvSize", i);
		e->TcpStatus = PackGetIntEx(p, "TcpStatus", i);
	}
}
void OutRpcEnumNat(PACK *p, RPC_ENUM_NAT *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "NumItem", t->NumItem);
	PackAddStr(p, "HubName", t->HubName);
	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_NAT_ITEM *e = &t->Items[i];

		PackAddIntEx(p, "Id", e->Id, i, t->NumItem);
		PackAddIntEx(p, "Protocol", e->Protocol, i, t->NumItem);
		PackAddIp32Ex(p, "SrcIp", e->SrcIp, i, t->NumItem);
		PackAddStrEx(p, "SrcHost", e->SrcHost, i, t->NumItem);
		PackAddIntEx(p, "SrcPort", e->SrcPort, i, t->NumItem);
		PackAddIp32Ex(p, "DestIp", e->DestIp, i, t->NumItem);
		PackAddStrEx(p, "DestHost", e->DestHost, i, t->NumItem);
		PackAddIntEx(p, "DestPort", e->DestPort, i, t->NumItem);
		PackAddInt64Ex(p, "CreatedTime", e->CreatedTime, i, t->NumItem);
		PackAddInt64Ex(p, "LastCommTime", e->LastCommTime, i, t->NumItem);
		PackAddInt64Ex(p, "SendSize", e->SendSize, i, t->NumItem);
		PackAddInt64Ex(p, "RecvSize", e->RecvSize, i, t->NumItem);
		PackAddIntEx(p, "TcpStatus", e->TcpStatus, i, t->NumItem);
	}
}
void FreeRpcEnumNat(RPC_ENUM_NAT *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t->Items);
}

// RPC_NAT_INFO
void InRpcNatInfo(RPC_NAT_INFO *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_NAT_INFO));
	PackGetStr(p, "NatProductName", t->NatProductName, sizeof(t->NatProductName));
	PackGetStr(p, "NatVersionString", t->NatVersionString, sizeof(t->NatVersionString));
	PackGetStr(p, "NatBuildInfoString", t->NatBuildInfoString, sizeof(t->NatBuildInfoString));
	t->NatVerInt = PackGetInt(p, "NatVerInt");
	t->NatBuildInt = PackGetInt(p, "NatBuildInt");
	PackGetStr(p, "NatHostName", t->NatHostName, sizeof(t->NatHostName));
	InRpcOsInfo(&t->OsInfo, p);
	InRpcMemInfo(&t->MemInfo, p);
}
void OutRpcNatInfo(PACK *p, RPC_NAT_INFO *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "NatProductName", t->NatProductName);
	PackAddStr(p, "NatVersionString", t->NatVersionString);
	PackAddStr(p, "NatBuildInfoString", t->NatBuildInfoString);
	PackAddInt(p, "NatVerInt", t->NatVerInt);
	PackAddInt(p, "NatBuildInt", t->NatBuildInt);
	PackAddStr(p, "NatHostName", t->NatHostName);
	OutRpcOsInfo(p, &t->OsInfo);
	OutRpcMemInfo(p, &t->MemInfo);
}
void FreeRpcNatInfo(RPC_NAT_INFO *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	FreeRpcOsInfo(&t->OsInfo);
}

// RPC_NAT_STATUS
void InRpcNatStatus(RPC_NAT_STATUS *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_NAT_STATUS));
	t->NumTcpSessions = PackGetInt(p, "NumTcpSessions");
	t->NumUdpSessions = PackGetInt(p, "NumUdpSessions");
	t->NumIcmpSessions = PackGetInt(p, "NumIcmpSessions");
	t->NumDnsSessions = PackGetInt(p, "NumDnsSessions");
	t->NumDhcpClients = PackGetInt(p, "NumDhcpClients");
	t->IsKernelMode = PackGetBool(p, "IsKernelMode");
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
}
void OutRpcNatStatus(PACK *p, RPC_NAT_STATUS *t)
{
	// Validate arguments
	if (p == NULL || t == NULL)
	{
		return;
	}

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "NumTcpSessions", t->NumTcpSessions);
	PackAddInt(p, "NumUdpSessions", t->NumUdpSessions);
	PackAddInt(p, "NumIcmpSessions", t->NumIcmpSessions);
	PackAddInt(p, "NumDnsSessions", t->NumDnsSessions);
	PackAddInt(p, "NumDhcpClients", t->NumDhcpClients);
	PackAddBool(p, "IsKernelMode", t->IsKernelMode);
}
void FreeRpcNatStatus(RPC_NAT_STATUS *t)
{
}

// RPC_DUMMY
void InRpcDummy(RPC_DUMMY *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_DUMMY));
	t->DummyValue = PackGetInt(p, "DummyValue");
}
void OutRpcDummy(PACK *p, RPC_DUMMY *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "DummyValue", t->DummyValue);
}

// Main procedure for management
void NiAdminMain(NAT *n, SOCK *s)
{
	RPC *r;
	PACK *p;
	// Validate arguments
	if (n == NULL || s == NULL)
	{
		return;
	}

	p = NewPack();
	HttpServerSend(s, p);
	FreePack(p);

	r = StartRpcServer(s, NiRpcServer, n);

	RpcServer(r);

	RpcFree(r);
}

// Management thread
void NiAdminThread(THREAD *thread, void *param)
{
	NAT_ADMIN *a = (NAT_ADMIN *)param;
	NAT *n;
	SOCK *s;
	UCHAR random[SHA1_SIZE];
	UINT err;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// Random number generation
	Rand(random, sizeof(random));

	a->Thread = thread;
	AddRef(a->Thread->ref);
	s = a->Sock;
	AddRef(s->ref);

	n = a->Nat;

	LockList(n->AdminList);
	{
		Add(n->AdminList, a);
	}
	UnlockList(n->AdminList);

	NoticeThreadInit(thread);

	err = ERR_AUTH_FAILED;

	if (StartSSL(s, n->AdminX, n->AdminK))
	{
		PACK *p;

		// Send the random number
		p = NewPack();
		PackAddData(p, "auth_random", random, sizeof(random));

		if (HttpServerSend(s, p))
		{
			PACK *p;
			// Receive a password
			p = HttpServerRecv(s);
			if (p != NULL)
			{
				UCHAR secure_password[SHA1_SIZE];
				UCHAR secure_check[SHA1_SIZE];

				if (PackGetData2(p, "secure_password", secure_password, sizeof(secure_password)))
				{
					SecurePassword(secure_check, n->HashedPassword, random);

					if (Cmp(secure_check, secure_password, SHA1_SIZE) == 0)
					{
						UCHAR test[SHA1_SIZE];
						// Password match
						Hash(test, "", 0, true);
						SecurePassword(test, test, random);

#if	0
						if (Cmp(test, secure_check, SHA1_SIZE) == 0 && s->RemoteIP.addr[0] != 127)
						{
							// A client can not connect from the outside with blank password
							err = ERR_NULL_PASSWORD_LOCAL_ONLY;
						}
						else
#endif

						{
							// Successful connection
							err = ERR_NO_ERROR;
							NiAdminMain(n, s);
						}
					}
				}

				FreePack(p);
			}
		}

		FreePack(p);

		if (err != ERR_NO_ERROR)
		{
			p = PackError(err);
			HttpServerSend(s, p);
			FreePack(p);
		}
	}

	Disconnect(s);
	ReleaseSock(s);
}

// Management port Listen thread
void NiListenThread(THREAD *thread, void *param)
{
	NAT *n = (NAT *)param;
	SOCK *a;
	UINT i;
	bool b = false;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// Initialize the management list
	n->AdminList = NewList(NULL);

	while (true)
	{
		a = Listen(DEFAULT_NAT_ADMIN_PORT);
		if (b == false)
		{
			b = true;
			NoticeThreadInit(thread);
		}
		if (a != NULL)
		{
			break;
		}

		Wait(n->HaltEvent, NAT_ADMIN_PORT_LISTEN_INTERVAL);
		if (n->Halt)
		{
			return;
		}
	}

	n->AdminListenSock = a;
	AddRef(a->ref);

	// Waiting
	while (true)
	{
		SOCK *s = Accept(a);
		THREAD *t;
		NAT_ADMIN *admin;
		if (s == NULL)
		{
			break;
		}
		if (n->Halt)
		{
			ReleaseSock(s);
			break;
		}

		admin = ZeroMalloc(sizeof(NAT_ADMIN));
		admin->Nat = n;
		admin->Sock = s;
		t = NewThread(NiAdminThread, admin);
		WaitThreadInit(t);
		ReleaseThread(t);
	}

	// Disconnect all management connections
	LockList(n->AdminList);
	{
		for (i = 0;i < LIST_NUM(n->AdminList);i++)
		{
			NAT_ADMIN *a = LIST_DATA(n->AdminList, i);
			Disconnect(a->Sock);
			WaitThread(a->Thread, INFINITE);
			ReleaseThread(a->Thread);
			ReleaseSock(a->Sock);
			Free(a);
		}
	}
	UnlockList(n->AdminList);

	ReleaseList(n->AdminList);

	ReleaseSock(a);
}

// Initialize receiving management command
void NiInitAdminAccept(NAT *n)
{
	THREAD *t;
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	t = NewThread(NiListenThread, n);
	WaitThreadInit(t);
	n->AdminAcceptThread = t;
}

// Complete receiving management command
void NiFreeAdminAccept(NAT *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	n->Halt = true;
	Disconnect(n->AdminListenSock);
	Set(n->HaltEvent);

	while (true)
	{
		if (WaitThread(n->AdminAcceptThread, 1000) == false)
		{
			Disconnect(n->AdminListenSock);
		}
		else
		{
			break;
		}
	}
	ReleaseThread(n->AdminAcceptThread);

	ReleaseSock(n->AdminListenSock);
}

// Clear the DHCP options that are not supported by the dynamic Virtual HUB
void NiClearUnsupportedVhOptionForDynamicHub(VH_OPTION *o, bool initial)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	o->UseNat = false;

	if (initial)
	{
		Zero(&o->DhcpGatewayAddress, sizeof(IP));
		Zero(&o->DhcpDnsServerAddress, sizeof(IP));
		Zero(&o->DhcpDnsServerAddress2, sizeof(IP));
		StrCpy(o->DhcpDomainName, sizeof(o->DhcpDomainName), "");
	}
}

// Initialize the options for the virtual host
void NiSetDefaultVhOption(NAT *n, VH_OPTION *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	Zero(o, sizeof(VH_OPTION));
	GenMacAddress(o->MacAddress);

	// Set the virtual IP to 192.168.30.1/24
	SetIP(&o->Ip, 192, 168, 30, 1);
	SetIP(&o->Mask, 255, 255, 255, 0);
	o->UseNat = true;
	o->Mtu = 1500;
	o->NatTcpTimeout = 1800;
	o->NatUdpTimeout = 60;
	o->UseDhcp = true;
	SetIP(&o->DhcpLeaseIPStart, 192, 168, 30, 10);
	SetIP(&o->DhcpLeaseIPEnd, 192, 168, 30, 200);
	SetIP(&o->DhcpSubnetMask, 255, 255, 255, 0);
	o->DhcpExpireTimeSpan = 7200;
	o->SaveLog = true;

	SetIP(&o->DhcpGatewayAddress, 192, 168, 30, 1);
	SetIP(&o->DhcpDnsServerAddress, 192, 168, 30, 1);

	GetDomainName(o->DhcpDomainName, sizeof(o->DhcpDomainName));
}

// Reset the setting of NAT to the default
void NiInitDefaultConfig(NAT *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	// Initialize the virtual host option
	NiSetDefaultVhOption(n, &n->Option);

	// Initialize management port
	n->AdminPort = DEFAULT_NAT_ADMIN_PORT;

	// Offline
	n->Online = false;

	// Save the log
	n->Option.SaveLog = true;
}

// Initialize the NAT configuration
void NiInitConfig(NAT *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	// Initial state
	NiInitDefaultConfig(n);
}

// Read the virtual host option (extended)
void NiLoadVhOptionEx(VH_OPTION *o, FOLDER *root)
{
	FOLDER *host, *nat, *dhcp;
	char mac_address[MAX_SIZE];
	// Validate arguments
	if (o == NULL || root == NULL)
	{
		return;
	}

	host = CfgGetFolder(root, "VirtualHost");
	nat = CfgGetFolder(root, "VirtualRouter");
	dhcp = CfgGetFolder(root, "VirtualDhcpServer");

	Zero(o, sizeof(VH_OPTION));

	GenMacAddress(o->MacAddress);
	if (CfgGetStr(host, "VirtualHostMacAddress", mac_address, sizeof(mac_address)))
	{
		BUF *b = StrToBin(mac_address);
		if (b != NULL)
		{
			if (b->Size == 6)
			{
				Copy(o->MacAddress, b->Buf, 6);
			}
		}
		FreeBuf(b);
	}
	CfgGetIp(host, "VirtualHostIp", &o->Ip);
	CfgGetIp(host, "VirtualHostIpSubnetMask", &o->Mask);

	o->UseNat = CfgGetBool(nat, "NatEnabled");
	o->Mtu = CfgGetInt(nat, "NatMtu");
	o->NatTcpTimeout = CfgGetInt(nat, "NatTcpTimeout");
	o->NatUdpTimeout = CfgGetInt(nat, "NatUdpTimeout");

	o->UseDhcp = CfgGetBool(dhcp, "DhcpEnabled");
	CfgGetIp(dhcp, "DhcpLeaseIPStart", &o->DhcpLeaseIPStart);
	CfgGetIp(dhcp, "DhcpLeaseIPEnd", &o->DhcpLeaseIPEnd);
	CfgGetIp(dhcp, "DhcpSubnetMask", &o->DhcpSubnetMask);
	o->DhcpExpireTimeSpan = CfgGetInt(dhcp, "DhcpExpireTimeSpan");
	CfgGetIp(dhcp, "DhcpGatewayAddress", &o->DhcpGatewayAddress);
	CfgGetIp(dhcp, "DhcpDnsServerAddress", &o->DhcpDnsServerAddress);
	CfgGetIp(dhcp, "DhcpDnsServerAddress2", &o->DhcpDnsServerAddress2);
	CfgGetStr(dhcp, "DhcpDomainName", o->DhcpDomainName, sizeof(o->DhcpDomainName));

	CfgGetStr(dhcp, "DhcpPushRoutes", o->DhcpPushRoutes, sizeof(o->DhcpPushRoutes));

// Test code
//	StrCpy(o->DhcpPushRoutes, sizeof(o->DhcpPushRoutes),
//		"130.158.6.0/24/192.168.9.2 130.158.80.244/255.255.255.255/192.168.9.2");

	NormalizeClasslessRouteTableStr(o->DhcpPushRoutes, sizeof(o->DhcpPushRoutes), o->DhcpPushRoutes);
	o->ApplyDhcpPushRoutes = true;

	Trim(o->DhcpDomainName);
	if (StrLen(o->DhcpDomainName) == 0)
	{
		//GetDomainName(o->DhcpDomainName, sizeof(o->DhcpDomainName));
	}

	o->SaveLog = CfgGetBool(root, "SaveLog");
}

// Read the virtual host option
void NiLoadVhOption(NAT *n, FOLDER *root)
{
	VH_OPTION *o;
	FOLDER *host, *nat, *dhcp;
	char mac_address[MAX_SIZE];
	// Validate arguments
	if (n == NULL || root == NULL)
	{
		return;
	}

	host = CfgGetFolder(root, "VirtualHost");
	nat = CfgGetFolder(root, "VirtualRouter");
	dhcp = CfgGetFolder(root, "VirtualDhcpServer");

	o = &n->Option;
	Zero(o, sizeof(VH_OPTION));

	GenMacAddress(o->MacAddress);
	if (CfgGetStr(host, "VirtualHostMacAddress", mac_address, sizeof(mac_address)))
	{
		BUF *b = StrToBin(mac_address);
		if (b != NULL)
		{
			if (b->Size == 6)
			{
				Copy(o->MacAddress, b->Buf, 6);
			}
		}
		FreeBuf(b);
	}
	CfgGetIp(host, "VirtualHostIp", &o->Ip);
	CfgGetIp(host, "VirtualHostIpSubnetMask", &o->Mask);

	o->UseNat = CfgGetBool(nat, "NatEnabled");
	o->Mtu = CfgGetInt(nat, "NatMtu");
	o->NatTcpTimeout = CfgGetInt(nat, "NatTcpTimeout");
	o->NatUdpTimeout = CfgGetInt(nat, "NatUdpTimeout");

	o->UseDhcp = CfgGetBool(dhcp, "DhcpEnabled");
	CfgGetIp(dhcp, "DhcpLeaseIPStart", &o->DhcpLeaseIPStart);
	CfgGetIp(dhcp, "DhcpLeaseIPEnd", &o->DhcpLeaseIPEnd);
	CfgGetIp(dhcp, "DhcpSubnetMask", &o->DhcpSubnetMask);
	o->DhcpExpireTimeSpan = CfgGetInt(dhcp, "DhcpExpireTimeSpan");
	CfgGetIp(dhcp, "DhcpGatewayAddress", &o->DhcpGatewayAddress);
	CfgGetIp(dhcp, "DhcpDnsServerAddress", &o->DhcpDnsServerAddress);
	CfgGetIp(dhcp, "DhcpDnsServerAddress2", &o->DhcpDnsServerAddress2);
	CfgGetStr(dhcp, "DhcpDomainName", o->DhcpDomainName, sizeof(o->DhcpDomainName));

	o->SaveLog = CfgGetBool(root, "SaveLog");
}

// Read connection options from the VPN server
void NiLoadClientData(NAT *n, FOLDER *root)
{
	FOLDER *co, *ca;
	// Validate arguments
	if (n == NULL || root == NULL)
	{
		return;
	}

	co = CfgGetFolder(root, "VpnClientOption");
	ca = CfgGetFolder(root, "VpnClientAuth");
	if (co == NULL || ca == NULL)
	{
		return;
	}

	n->ClientOption = CiLoadClientOption(co);
	n->ClientAuth = CiLoadClientAuth(ca);
}

// Write connection options to the VPN server
void NiWriteClientData(NAT *n, FOLDER *root)
{
	// Validate arguments
	if (n == NULL || root == NULL || n->ClientOption == NULL || n->ClientAuth == NULL)
	{
		return;
	}

	CiWriteClientOption(CfgCreateFolder(root, "VpnClientOption"), n->ClientOption);
	CiWriteClientAuth(CfgCreateFolder(root, "VpnClientAuth"), n->ClientAuth);
}

// Write the virtual host option (extended)
void NiWriteVhOptionEx(VH_OPTION *o, FOLDER *root)
{
	FOLDER *host, *nat, *dhcp;
	char mac_address[MAX_SIZE];
	// Validate arguments
	if (o == NULL || root == NULL)
	{
		return;
	}

	host = CfgCreateFolder(root, "VirtualHost");
	nat = CfgCreateFolder(root, "VirtualRouter");
	dhcp = CfgCreateFolder(root, "VirtualDhcpServer");

	MacToStr(mac_address, sizeof(mac_address), o->MacAddress);
	CfgAddStr(host, "VirtualHostMacAddress", mac_address);
	CfgAddIp(host, "VirtualHostIp", &o->Ip);
	CfgAddIp(host, "VirtualHostIpSubnetMask", &o->Mask);

	CfgAddBool(nat, "NatEnabled", o->UseNat);
	CfgAddInt(nat, "NatMtu", o->Mtu);
	CfgAddInt(nat, "NatTcpTimeout", o->NatTcpTimeout);
	CfgAddInt(nat, "NatUdpTimeout", o->NatUdpTimeout);

	CfgAddBool(dhcp, "DhcpEnabled", o->UseDhcp);
	CfgAddIp(dhcp, "DhcpLeaseIPStart", &o->DhcpLeaseIPStart);
	CfgAddIp(dhcp, "DhcpLeaseIPEnd", &o->DhcpLeaseIPEnd);
	CfgAddIp(dhcp, "DhcpSubnetMask", &o->DhcpSubnetMask);
	CfgAddInt(dhcp, "DhcpExpireTimeSpan", o->DhcpExpireTimeSpan);
	CfgAddIp(dhcp, "DhcpGatewayAddress", &o->DhcpGatewayAddress);
	CfgAddIp(dhcp, "DhcpDnsServerAddress", &o->DhcpDnsServerAddress);
	CfgAddIp(dhcp, "DhcpDnsServerAddress2", &o->DhcpDnsServerAddress2);
	CfgAddStr(dhcp, "DhcpDomainName", o->DhcpDomainName);
	CfgAddStr(dhcp, "DhcpPushRoutes", o->DhcpPushRoutes);

	CfgAddBool(root, "SaveLog", o->SaveLog);
}

// Write the virtual host option
void NiWriteVhOption(NAT *n, FOLDER *root)
{
	VH_OPTION *o;
	FOLDER *host, *nat, *dhcp;
	char mac_address[MAX_SIZE];
	// Validate arguments
	if (n == NULL || root == NULL)
	{
		return;
	}

	host = CfgCreateFolder(root, "VirtualHost");
	nat = CfgCreateFolder(root, "VirtualRouter");
	dhcp = CfgCreateFolder(root, "VirtualDhcpServer");

	o = &n->Option;

	MacToStr(mac_address, sizeof(mac_address), o->MacAddress);
	CfgAddStr(host, "VirtualHostMacAddress", mac_address);
	CfgAddIp(host, "VirtualHostIp", &o->Ip);
	CfgAddIp(host, "VirtualHostIpSubnetMask", &o->Mask);

	CfgAddBool(nat, "NatEnabled", o->UseNat);
	CfgAddInt(nat, "NatMtu", o->Mtu);
	CfgAddInt(nat, "NatTcpTimeout", o->NatTcpTimeout);
	CfgAddInt(nat, "NatUdpTimeout", o->NatUdpTimeout);

	CfgAddBool(dhcp, "DhcpEnabled", o->UseDhcp);
	CfgAddIp(dhcp, "DhcpLeaseIPStart", &o->DhcpLeaseIPStart);
	CfgAddIp(dhcp, "DhcpLeaseIPEnd", &o->DhcpLeaseIPEnd);
	CfgAddIp(dhcp, "DhcpSubnetMask", &o->DhcpSubnetMask);
	CfgAddInt(dhcp, "DhcpExpireTimeSpan", o->DhcpExpireTimeSpan);
	CfgAddIp(dhcp, "DhcpGatewayAddress", &o->DhcpGatewayAddress);
	CfgAddIp(dhcp, "DhcpDnsServerAddress", &o->DhcpDnsServerAddress);
	CfgAddIp(dhcp, "DhcpDnsServerAddress2", &o->DhcpDnsServerAddress2);
	CfgAddStr(dhcp, "DhcpDomainName", o->DhcpDomainName);

	CfgAddBool(root, "SaveLog", o->SaveLog);
}

// Read the configuration file
bool NiLoadConfig(NAT *n, FOLDER *root)
{
	FOLDER *host;
	BUF *b;
	// Validate arguments
	if (n == NULL || root == NULL)
	{
		return false;
	}

	host = CfgGetFolder(root, "VirtualHost");
	if (host == NULL)
	{
		return false;
	}

	CfgGetByte(root, "HashedPassword", n->HashedPassword, sizeof(n->HashedPassword));
	n->AdminPort = CfgGetInt(root, "AdminPort");
	n->Online = CfgGetBool(root, "Online");

	b = CfgGetBuf(root, "AdminCert");
	if (b != NULL)
	{
		n->AdminX = BufToX(b, false);
		FreeBuf(b);
	}

	b = CfgGetBuf(root, "AdminKey");
	if (b != NULL)
	{
		n->AdminK = BufToK(b, true, false, NULL);
		FreeBuf(b);
	}

	NiLoadVhOption(n, root);

	NiLoadClientData(n, root);

	return true;
}

// Write the configuration to a file
void NiWriteConfig(NAT *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	Lock(n->lock);
	{
		FOLDER *root = CfgCreateFolder(NULL, TAG_ROOT);
		BUF *b;

		// Certificate
		b = XToBuf(n->AdminX, false);
		CfgAddBuf(root, "AdminCert", b);
		FreeBuf(b);

		// Secret key
		b = KToBuf(n->AdminK, false, NULL);
		CfgAddBuf(root, "AdminKey", b);
		FreeBuf(b);

		// Password
		CfgAddByte(root, "HashedPassword", n->HashedPassword, sizeof(n->HashedPassword));
		CfgAddInt(root, "AdminPort", n->AdminPort);
		CfgAddBool(root, "Online", n->Online);

		// Virtual host option
		NiWriteVhOption(n, root);

		// Connection options
		if (n->ClientOption != NULL && n->ClientAuth != NULL)
		{
			NiWriteClientData(n, root);
		}

		SaveCfgRw(n->CfgRw, root);
		CfgDeleteFolder(root);
	}
	Unlock(n->lock);
}

// Release the NAT configuration
void NiFreeConfig(NAT *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	// Write the latest configuration
	NiWriteConfig(n);

	// Release the configuration R/W
	FreeCfgRw(n->CfgRw);
	n->CfgRw = NULL;

	Free(n->ClientOption);
	CiFreeClientAuth(n->ClientAuth);

	FreeX(n->AdminX);
	FreeK(n->AdminK);
}

// Create a NAT
NAT *NiNewNatEx(SNAT *snat, VH_OPTION *o)
{
	NAT *n = ZeroMalloc(sizeof(NAT));

	n->lock = NewLock();
	Hash(n->HashedPassword, "", 0, true);
	n->HaltEvent = NewEvent();

	//n->Cedar = NewCedar(NULL, NULL);

	n->SecureNAT = snat;

	// Raise the priority
	//OSSetHighPriority();

	// Initialize the settings
	NiInitConfig(n);

#if	0
	// Start the operation of the virtual host
	if (n->Online && n->ClientOption != NULL)
	{
		n->Virtual = NewVirtualHostEx(n->Cedar, n->ClientOption, n->ClientAuth, &n->Option, n);
	}
	else
	{
		n->Online = false;
		n->Virtual = NULL;
	}
#else
	n->Virtual = NewVirtualHostEx(n->Cedar, NULL, NULL, o, n);
	n->Online = true;
#endif

	// Start management command
	//NiInitAdminAccept(n);

	return n;
}
NAT *NiNewNat()
{
	return NiNewNatEx(NULL, NULL);
}

// Release the NAT
void NiFreeNat(NAT *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	// Complete management command
	//NiFreeAdminAccept(n);

	// Stop if the virtual host is running
	Lock(n->lock);
	{
		if (n->Virtual != NULL)
		{
			StopVirtualHost(n->Virtual);
			ReleaseVirtual(n->Virtual);
			n->Virtual = NULL;
		}
	}
	Unlock(n->lock);

	// Release the settings
	NiFreeConfig(n);

	// Delete the object
	ReleaseCedar(n->Cedar);
	ReleaseEvent(n->HaltEvent);
	DeleteLock(n->lock);

	Free(n);
}

// Stop the NAT
void NtStopNat()
{
	Lock(nat_lock);
	{
		if (nat != NULL)
		{
			NiFreeNat(nat);
			nat = NULL;
		}
	}
	Unlock(nat_lock);
}

// Start the NAT
void NtStartNat()
{
	Lock(nat_lock);
	{
		if (nat == NULL)
		{
			nat = NiNewNat();
		}
	}
	Unlock(nat_lock);
}

// Initialize the NtXxx function
void NtInit()
{
	if (nat_lock != NULL)
	{
		return;
	}

	nat_lock = NewLock();
}

// Release the NtXxx function
void NtFree()
{
	if (nat_lock == NULL)
	{
		return;
	}

	DeleteLock(nat_lock);
	nat_lock = NULL;
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
