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


// IPsec_EtherIP.c
// EtherIP protocol stack

#include "CedarPch.h"

// IPC connection processing thread
void EtherIPIpcConnectThread(THREAD *t, void *p)
{
	ETHERIP_SERVER *s;
	IPC *ipc = NULL;
	UINT error_code = 0;
	char tmp[MAX_SIZE];
	ETHERIP_ID id;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	s = (ETHERIP_SERVER *)p;

	GetHostName(tmp, sizeof(tmp), &s->ClientIP);

	// Get the setting of the virtual HUB to be connected based on the client ID presented
	if (SearchEtherIPId(s->Ike->IPsec, &id, s->ClientId) == false &&
		SearchEtherIPId(s->Ike->IPsec, &id, "*") == false)
	{
		// Failed to get the settings for the virtual HUB
		Debug("Not Found: EtherIP Settings for Client ID \"%s\".\n", s->ClientId);

		EtherIPLog(s, "LE_NO_SETTING", s->ClientId);
	}
	else
	{
		UINT mss = CalcEtherIPTcpMss(s);
		char client_name[MAX_SIZE];

		if (s->L2TPv3 == false)
		{
			StrCpy(client_name, sizeof(client_name), ETHERIP_CLIENT_NAME);
		}
		else
		{
			if (IsEmptyStr(s->VendorName))
			{
				StrCpy(client_name, sizeof(client_name), ETHERIP_L2TPV3_CLIENT_NAME);
			}
			else
			{
				Format(client_name, sizeof(client_name), ETHERIP_L2TPV3_CLIENT_NAME_EX, s->VendorName);
			}
		}

		// Execution of IPC connection process
		EtherIPLog(s, "LE_START_IPC", id.HubName, id.UserName, mss);
		ipc = NewIPC(s->Cedar, client_name,
			(s->L2TPv3 ? ETHERIP_L2TPV3_POSTFIX : ETHERIP_POSTFIX),
			id.HubName, id.UserName, id.Password,
			&error_code,
			&s->ClientIP, s->ClientPort,
			&s->ServerIP, s->ServerPort,
			tmp,
			s->CryptName, true, mss);

		if (ipc != NULL)
		{
			Copy(&s->CurrentEtherIPIdSetting, &id, sizeof(ETHERIP_ID));
			EtherIPLog(s, "LE_IPC_CONNECT_OK", id.HubName);
		}
		else
		{
			EtherIPLog(s, "LE_IPC_CONNECT_ERROR", id.HubName, error_code, _E(error_code));
		}
	}

	Lock(s->Lock);
	{
		// Set the results
		ReleaseThread(s->IpcConnectThread);
		s->IpcConnectThread = NULL;

		s->Ipc = ipc;

		s->LastConnectFailedTick = Tick64();
	}
	Unlock(s->Lock);

	// Hit the event to cause interrupt
	SetSockEvent(s->SockEvent);

	// Release the EtherIP object that is hold by this thread
	ReleaseEtherIPServer(s);
}

// Processing of the interrupt
void EtherIPProcInterrupts(ETHERIP_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// If EtherIP settings have been changed, and the change may effect to this connection, disconnect
	if (s->Ipc != NULL)
	{
		if (s->Ike->IPsec->EtherIPIdListSettingVerNo != s->LastEtherIPSettingVerNo)
		{
			ETHERIP_ID id;
			bool ok = true;

			s->LastEtherIPSettingVerNo = s->Ike->IPsec->EtherIPIdListSettingVerNo;

			if (SearchEtherIPId(s->IPsec, &id, s->ClientId) == false &&
				SearchEtherIPId(s->IPsec, &id, "*") == false)
			{
				ok = false;
			}
			else
			{
				if (StrCmpi(s->CurrentEtherIPIdSetting.HubName, id.HubName) != 0 ||
					StrCmpi(s->CurrentEtherIPIdSetting.UserName, id.UserName) != 0 ||
					StrCmp(s->CurrentEtherIPIdSetting.Password, id.Password) != 0)
				{
					ok = false;
				}
			}

			if (ok == false)
			{
				// Disconnect immediately since setting of EtherIP seems to have been changed
				FreeIPC(s->Ipc);
				s->Ipc = NULL;

				EtherIPLog(s, "LE_RECONNECT");
			}
		}
	}

	// Connect if IPC connection is not completed
	Lock(s->Lock);
	{
		if (s->Ipc == NULL)
		{
			if (s->IpcConnectThread == NULL)
			{
				if ((s->LastConnectFailedTick == 0) || ((s->LastConnectFailedTick + (UINT64)ETHERIP_VPN_CONNECT_RETRY_INTERVAL) <= s->Now))
				{
					Lock(s->IPsec->LockSettings);
					{
						Copy(&s->CurrentIPSecServiceSetting, &s->IPsec->Services, sizeof(IPSEC_SERVICES));
					}
					Unlock(s->IPsec->LockSettings);

					s->IpcConnectThread = NewThread(EtherIPIpcConnectThread, s);
					AddThreadToThreadList(s->Ike->ThreadList, s->IpcConnectThread);
					AddRef(s->Ref);
				}
			}
		}
	}
	Unlock(s->Lock);

	if (s->Ipc != NULL)
	{
		// Set to get hit the SockEvent when a packet arrives via the IPC
		IPCSetSockEventWhenRecvL2Packet(s->Ipc, s->SockEvent);

		// IPC interrupt processing
		IPCProcessInterrupts(s->Ipc);

		// Receive the MAC frame which arrived via the IPC
		while (true)
		{
			BLOCK *b = IPCRecvL2(s->Ipc);
			UCHAR *dst;
			UINT dst_size;

			if (b == NULL)
			{
				break;
			}

			if (b->Size >= 14)
			{
				BLOCK *block;

				// Store the arrived MAC frame by adding an EtherIP header to the reception packet queue

				if (s->L2TPv3 == false)
				{
					dst_size = b->Size + 2;
					dst = Malloc(dst_size);

					dst[0] = 0x30;
					dst[1] = 0x00;

					Copy(dst + 2, b->Buf, b->Size);
				}
				else
				{
					dst = Clone(b->Buf, b->Size);
					dst_size = b->Size;
				}

				block = NewBlock(dst, dst_size, 0);

				Add(s->SendPacketList, block);
			}

			FreeBlock(b);
		}

		if (IsIPCConnected(s->Ipc) == false)
		{
			// IPC connection is disconnected
			FreeIPC(s->Ipc);
			s->Ipc = NULL;
		}
	}
}

// Process the received packet
void EtherIPProcRecvPackets(ETHERIP_SERVER *s, BLOCK *b)
{
	UCHAR *src;
	UINT src_size;
	// Validate arguments
	if (s == NULL || b == NULL)
	{
		return;
	}

	if (s->Ipc == NULL)
	{
		// Not connected to the Virtual HUB
		return;
	}

	src = b->Buf;
	src_size = b->Size;

	if (s->L2TPv3 == false)
	{
		// EtherIP header confirmation
		if (src_size < 2)
		{
			return;
		}

		if ((src[0] & 0xf0) != 0x30)
		{
			return;
		}

		src += 2;
		src_size -= 2;
	}

	if (src_size < 14)
	{
		// The size of the MAC frame is less than 14 bytes
		return;
	}

	// Send by IPC since a MAC frame has been received
	IPCSendL2(s->Ipc, src, src_size);
}

// Create a new EtherIP server
ETHERIP_SERVER *NewEtherIPServer(CEDAR *cedar, IPSEC_SERVER *ipsec, IKE_SERVER *ike,
								 IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, char *crypt_name,
								 bool is_tunnel_mode, UINT crypt_block_size,
								 char *client_id, UINT id)
{
	ETHERIP_SERVER *s;
	// Validate arguments
	if (cedar == NULL || ipsec == NULL || ike == NULL || client_ip == NULL || server_ip == NULL || client_id == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(ETHERIP_SERVER));

	s->Ref = NewRef();

	s->Id = id;

	s->Cedar = cedar;
	AddRef(s->Cedar->ref);
	s->IPsec = ipsec;
	s->Ike = ike;
	s->IsTunnelMode = is_tunnel_mode;

	StrCpy(s->ClientId, sizeof(s->ClientId), client_id);

	s->SendPacketList = NewList(NULL);

	s->Now = Tick64();

	s->Lock = NewLock();

	Copy(&s->ClientIP, client_ip, sizeof(IP));
	s->ClientPort = client_port;

	Copy(&s->ServerIP, server_ip, sizeof(IP));
	s->ServerPort = server_port;

	StrCpy(s->CryptName, sizeof(s->CryptName), crypt_name);
	s->CryptBlockSize = crypt_block_size;

	EtherIPLog(s, "LE_START_MODULE");

	return s;
}

// Release the EtherIP server
void ReleaseEtherIPServer(ETHERIP_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (Release(s->Ref) == 0)
	{
		CleanupEtherIPServer(s);
	}
}
void CleanupEtherIPServer(ETHERIP_SERVER *s)
{
	UINT i;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	EtherIPLog(s, "LE_STOP");

	if (s->IpcConnectThread != NULL)
	{
		ReleaseThread(s->IpcConnectThread);
	}

	if (s->Ipc != NULL)
	{
		FreeIPC(s->Ipc);
	}

	for (i = 0;i < LIST_NUM(s->SendPacketList);i++)
	{
		BLOCK *b = LIST_DATA(s->SendPacketList, i);

		FreeBlock(b);
	}

	ReleaseList(s->SendPacketList);

	ReleaseSockEvent(s->SockEvent);

	ReleaseCedar(s->Cedar);

	DeleteLock(s->Lock);

	Free(s);
}


// Set SockEvent to EtherIP server
void SetEtherIPServerSockEvent(ETHERIP_SERVER *s, SOCK_EVENT *e)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (e != NULL)
	{
		AddRef(e->ref);
	}

	if (s->SockEvent != NULL)
	{
		ReleaseSockEvent(s->SockEvent);
		s->SockEvent = NULL;
	}

	s->SockEvent = e;
}

// Calculate the proper TCP MSS in EtherIP communication
UINT CalcEtherIPTcpMss(ETHERIP_SERVER *s)
{
	UINT ret = MTU_FOR_PPPOE;
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	// IPv4 / IPv6
	if (IsIP4(&s->ClientIP))
	{
		ret -= 20;
	}
	else
	{
		ret -= 40;
	}

	// IPsec UDP
	ret -= 8;

	// IPsec ESP
	ret -= 20;
	ret -= s->CryptBlockSize * 2;

	// IPsec Tunnel Mode IPv4 / IPv6 Header
	if (s->IsTunnelMode)
	{
		if (IsIP4(&s->ClientIP))
		{
			ret -= 20;
		}
		else
		{
			ret -= 40;
		}
	}

	if (s->L2TPv3 == false)
	{
		// EtherIP
		ret -= 2;
	}
	else
	{
		// L2TPv3
		ret -= 2;
	}

	// Ethernet
	ret -= 14;

	// IPv4
	ret -= 20;

	// TCP
	ret -= 20;

	return ret;
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
