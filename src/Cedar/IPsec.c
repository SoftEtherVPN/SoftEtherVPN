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


// IPsec.c
// IPsec module

#include "CedarPch.h"


static bool ipsec_disable = false;

// Disabling whole IPsec
void IPSecSetDisable(bool b)
{
	ipsec_disable = b;
}


// Monitor the IPsec service of the OS, and stop it if it will conflict
void IPsecOsServiceCheckThread(THREAD *t, void *p)
{
	UINT interval = IPSEC_CHECK_OS_SERVICE_INTERVAL_INITIAL;
	IPSEC_SERVER *s = (IPSEC_SERVER *)p;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	s->HostIPAddressListChanged = true;
	s->OsServiceStoped = false;

	while (s->Halt == false)
	{
		if (IPsecCheckOsService(s))
		{
			interval = IPSEC_CHECK_OS_SERVICE_INTERVAL_INITIAL;
		}

		if (Wait(s->OsServiceCheckThreadEvent, interval) == false)
		{
			interval = MIN(interval * 2, IPSEC_CHECK_OS_SERVICE_INTERVAL_MAX);
		}
		else
		{
			interval = IPSEC_CHECK_OS_SERVICE_INTERVAL_INITIAL;
		}
	}

	IPsecCheckOsService(s);
}

// Monitoring process main
bool IPsecCheckOsService(IPSEC_SERVER *s)
{
	bool b_ipsec;
	IPSEC_SERVICES sl;
	bool ret = false;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	IPsecServerGetServices(s, &sl);

	b_ipsec = (sl.EtherIP_IPsec || sl.L2TP_IPsec);

	if (b_ipsec != s->Check_LastEnabledStatus)
	{
		s->Check_LastEnabledStatus = b_ipsec;

		if (b_ipsec)
		{
			// Use of IPsec has been started
#ifdef	OS_WIN32
			if (s->Win7 == NULL)
			{
				s->Win7 = IPsecWin7Init();
				s->HostIPAddressListChanged = true;
			}

			s->OsServiceStoped = false;
#else	// OS_WIN32
#endif	// OS_WIN32
		}
		else
		{
			// Use of IPsec is stopped
#ifdef	OS_WIN32
			if (s->Win7 != NULL)
			{
				IPsecWin7Free(s->Win7);
				s->Win7 = NULL;
			}

			if (s->OsServiceStoped)
			{
				MsStartIPsecService();
				s->OsServiceStoped = false;
			}
#else	// OS_WIN32
			UnixSetEnableKernelEspProcessing(true);
#endif	// OS_WIN32
		}
	}

	if (b_ipsec)
	{
#ifdef	OS_WIN32
		if (MsStopIPsecService())
		{
			s->OsServiceStoped = true;
			ret = true;
		}
#else	// OS_WIN32
		UnixSetEnableKernelEspProcessing(false);
#endif	// OS_WIN32
	}

#ifdef	OS_WIN32
	if (s->Win7 != NULL)
	{
		IPsecWin7UpdateHostIPAddressList(s->Win7);
		s->HostIPAddressListChanged = false;
	}
#endif	// OS_WIN32

	return ret;
}

// Processing of UDP packets (one by one)
void IPsecProcPacket(IPSEC_SERVER *s, UDPPACKET *p)
{
	L2TP_SERVER *l2tp;
	IKE_SERVER *ike;
	void *old_data_ptr;
	UINT old_data_size;
	bool proc_this_packet = true;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	old_data_ptr = p->Data;
	old_data_size = p->Size;

	l2tp = s->L2TP;
	ike = s->Ike;

	// UDP decapsulation process
	if (p->DestPort == IPSEC_PORT_IPSEC_ESP_UDP)
	{
#ifdef	OS_WIN32
		if (p->Size >= 12 && IsZero(p->Data, 4))
		{
			if (((*((UINT *)(((UCHAR *)p->Data) + sizeof(UINT) * 1))) == WFP_ESP_PACKET_TAG_1) &&
				((*((UINT *)(((UCHAR *)p->Data) + sizeof(UINT) * 2))) == WFP_ESP_PACKET_TAG_2))
			{
				// Truncate the head because the packet was modified by WFP
				p->Data = ((UCHAR *)p->Data) + 12;
				p->Size -= 12;
			}
		}
#endif	// OS_WIN32

		if (p->Size >= 4 && IsZero(p->Data, 4))
		{
			// Truncate the Non-ESP Marker
			p->Data = ((UCHAR *)p->Data) + 4;
			p->Size -= 4;

			p->Type = IKE_UDP_TYPE_ISAKMP;
		}
		else
		{
			p->Type = IKE_UDP_TYPE_ESP;
		}
	}
	else if (p->DestPort == IPSEC_PORT_IPSEC_ISAKMP)
	{
		if (p->Size >= 8 && IsZero(p->Data, 8))
		{
			// Truncate the Non-IKE Maker
			p->Data = ((UCHAR *)p->Data) + 8;
			p->Size -= 8;

			p->Type = IKE_UDP_TYPE_ESP;
		}
		else
		{
			p->Type = IKE_UDP_TYPE_ISAKMP;
		}
	}
	else if (p->DestPort == IPSEC_PORT_IPSEC_ESP_RAW)
	{
		// Raw ESP
		p->Type = IKE_UDP_TYPE_ESP;
	}


	if (proc_this_packet)
	{
		switch (p->DestPort)
		{
		case IPSEC_PORT_L2TP:
			// L2TP
			ProcL2TPPacketRecv(l2tp, p);
			break;

		case IPSEC_PORT_IPSEC_ISAKMP:
		case IPSEC_PORT_IPSEC_ESP_UDP:
		case IPSEC_PORT_IPSEC_ESP_RAW:
			// IPsec
			ProcIKEPacketRecv(ike, p);
			break;
		}
	}

	p->Data = old_data_ptr;
	p->Size = old_data_size;
}

// Packet reception procedure of UDP listener
void IPsecServerUdpPacketRecvProc(UDPLISTENER *u, LIST *packet_list)
{
	UINT i;
	IPSEC_SERVER *s;
	L2TP_SERVER *l2tp;
	IKE_SERVER *ike;
	UINT64 now;
	static UCHAR zero8[8] = {0, 0, 0, 0, 0, 0, 0, 0, };
	// Validate arguments
	if (u == NULL || packet_list == NULL)
	{
		return;
	}
	s = (IPSEC_SERVER *)u->Param;
	if (s == NULL)
	{
		return;
	}

	if (u->HostIPAddressListChanged)
	{
		u->HostIPAddressListChanged = false;

		s->HostIPAddressListChanged = true;

		Set(s->OsServiceCheckThreadEvent);
	}

	now = Tick64();

	// Adjustment about L2TP server timing
	l2tp = s->L2TP;

	if (l2tp->Interrupts == NULL)
	{
		l2tp->Interrupts = u->Interrupts;
	}

	if (l2tp->SockEvent == NULL)
	{
		SetL2TPServerSockEvent(l2tp, u->Event);
	}

	l2tp->Now = now;

	// Adjustment about IKE server timing
	ike = s->Ike;

	if (ike->Interrupts == NULL)
	{
		ike->Interrupts = u->Interrupts;
	}

	if (ike->SockEvent == NULL)
	{
		SetIKEServerSockEvent(ike, u->Event);
	}

	ike->Now = now;

	if (ipsec_disable == false)
	{
		{
			// Process the received packet
			for (i = 0;i < LIST_NUM(packet_list);i++)
			{
				UDPPACKET *p = LIST_DATA(packet_list, i);

				IPsecProcPacket(s, p);
			}
		}
	}

	// Interrupt processing of L2TP server
	L2TPProcessInterrupts(l2tp);

	// L2TP packet transmission processing
	UdpListenerSendPackets(u, l2tp->SendPacketList);
	DeleteAll(l2tp->SendPacketList);

	// Interrupt processing of IKE server
	ProcessIKEInterrupts(ike);

	// UDP encapsulation process of IKE server packet scheduled for transmission
	for (i = 0;i < LIST_NUM(ike->SendPacketList);i++)
	{
		UDPPACKET *p = LIST_DATA(ike->SendPacketList, i);

		if (p->Type == IKE_UDP_TYPE_ISAKMP && p->SrcPort == IPSEC_PORT_IPSEC_ESP_UDP)
		{
			// Add the Non-ESP Marker
			void *old_data = p->Data;

			p->Data = AddHead(p->Data, p->Size, zero8, 4);
			p->Size += 4;

			Free(old_data);
		}
		else if (p->Type == IKE_UDP_TYPE_ESP && p->SrcPort == IPSEC_PORT_IPSEC_ISAKMP)
		{
			// Add the Non-IKE Marker
			void *old_data = p->Data;

			p->Data = AddHead(p->Data, p->Size, zero8, 8);
			p->Size += 8;

			Free(old_data);
		}
	}

	// IKE server packet transmission processing
	UdpListenerSendPackets(u, ike->SendPacketList);
	DeleteAll(ike->SendPacketList);
}

// Get the service list
void IPsecServerGetServices(IPSEC_SERVER *s, IPSEC_SERVICES *sl)
{
	// Validate arguments
	if (s == NULL || sl == NULL)
	{
		return;
	}

	Lock(s->LockSettings);
	{
		IPsecNormalizeServiceSetting(s);

		Copy(sl, &s->Services, sizeof(IPSEC_SERVICES));
	}
	Unlock(s->LockSettings);
}

// Normalize the IPsec service setttings
void IPsecNormalizeServiceSetting(IPSEC_SERVER *s)
{
	CEDAR *c;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	c = s->Cedar;

	Lock(s->LockSettings);
	{
		bool reset_hub_setting = false;

		if (IsEmptyStr(s->Services.IPsec_Secret))
		{
			// If the secret is not set, set the default one
			StrCpy(s->Services.IPsec_Secret, sizeof(s->Services.IPsec_Secret), IPSEC_DEFAULT_SECRET);
		}

		LockList(c->HubList);
		{
			if (IsEmptyStr(s->Services.L2TP_DefaultHub))
			{
				reset_hub_setting = true;
			}
			else
			{
				if (IsHub(c, s->Services.L2TP_DefaultHub) == false)
				{
					reset_hub_setting = true;
				}
			}

			if (reset_hub_setting)
			{
				// Select the first Virtual HUB if there is no HUB
				HUB *h = NULL;
				
				if (LIST_NUM(c->HubList) >= 1)
				{
					h = LIST_DATA(c->HubList, 0);
				}

				if (h != NULL)
				{
					StrCpy(s->Services.L2TP_DefaultHub, sizeof(s->Services.L2TP_DefaultHub), h->Name);
				}
				else
				{
					StrCpy(s->Services.L2TP_DefaultHub, sizeof(s->Services.L2TP_DefaultHub), "");
				}
			}
		}
		UnlockList(c->HubList);
	}
	Unlock(s->LockSettings);
}

// Set the service list
void IPsecServerSetServices(IPSEC_SERVER *s, IPSEC_SERVICES *sl)
{
	// Validate arguments
	if (s == NULL || sl == NULL)
	{
		return;
	}

	if (IsZero(sl, sizeof(IPSEC_SERVICES)) == false)
	{
		if (s->NoMoreChangeSettings)
		{
			return;
		}
	}

	Lock(s->LockSettings);
	{
		Copy(&s->Services, sl, sizeof(IPSEC_SERVICES));

		if (sl->L2TP_Raw)
		{
			AddPortToUdpListener(s->UdpListener, IPSEC_PORT_L2TP);
		}
		else
		{
			DeletePortFromUdpListener(s->UdpListener, IPSEC_PORT_L2TP);
		}

		if (sl->L2TP_IPsec || sl->EtherIP_IPsec)
		{
			AddPortToUdpListener(s->UdpListener, IPSEC_PORT_IPSEC_ISAKMP);
			AddPortToUdpListener(s->UdpListener, IPSEC_PORT_IPSEC_ESP_UDP);
			AddPortToUdpListener(s->UdpListener, IPSEC_PORT_IPSEC_ESP_RAW);
			AddPortToUdpListener(s->UdpListener, IPSEC_PORT_IPSEC_ESP_RAW_WPF);
		}
		else
		{
			DeletePortFromUdpListener(s->UdpListener, IPSEC_PORT_IPSEC_ISAKMP);
			DeletePortFromUdpListener(s->UdpListener, IPSEC_PORT_IPSEC_ESP_UDP);
			DeletePortFromUdpListener(s->UdpListener, IPSEC_PORT_IPSEC_ESP_RAW);
			DeletePortFromUdpListener(s->UdpListener, IPSEC_PORT_IPSEC_ESP_RAW_WPF);
		}

		if (IsEmptyStr(sl->IPsec_Secret) == false)
		{
			StrCpy(s->Ike->Secret, sizeof(s->Ike->Secret), sl->IPsec_Secret);
		}

		IPsecNormalizeServiceSetting(s);
	}
	Unlock(s->LockSettings);

	Set(s->OsServiceCheckThreadEvent);
}

// Add the EtherIP key
void AddEtherIPId(IPSEC_SERVER *s, ETHERIP_ID *id)
{
	// Validate arguments
	if (s == NULL || id == NULL)
	{
		return;
	}

	Lock(s->LockSettings);
	{
		// If there is the same key, remove them
		ETHERIP_ID t, *k;

		Zero(&t, sizeof(t));

		StrCpy(t.Id, sizeof(t.Id), id->Id);

		k = Search(s->EtherIPIdList, &t);

		if (k != NULL)
		{
			Delete(s->EtherIPIdList, k);

			Free(k);
		}

		// Add
		k = Clone(id, sizeof(ETHERIP_ID));

		Insert(s->EtherIPIdList, k);

		s->EtherIPIdListSettingVerNo++;
	}
	Unlock(s->LockSettings);
}

// Delete the EtherIP key
bool DeleteEtherIPId(IPSEC_SERVER *s, char *id_str)
{
	bool ret = false;
	// Validate arguments
	if (s == NULL || id_str == NULL)
	{
		return false;
	}

	Lock(s->LockSettings);
	{
		// If there is the same key, remove them
		ETHERIP_ID t, *k;

		Zero(&t, sizeof(t));

		StrCpy(t.Id, sizeof(t.Id), id_str);

		k = Search(s->EtherIPIdList, &t);

		if (k != NULL)
		{
			Delete(s->EtherIPIdList, k);

			Free(k);

			ret = true;

			s->EtherIPIdListSettingVerNo++;
		}
	}
	Unlock(s->LockSettings);

	return ret;
}

// Search the EtherIP key
bool SearchEtherIPId(IPSEC_SERVER *s, ETHERIP_ID *id, char *id_str)
{
	bool ret = false;
	// Validate arguments
	if (s == NULL || id == NULL || id_str == NULL)
	{
		return false;
	}

	Lock(s->LockSettings);
	{
		ETHERIP_ID t, *k;

		Zero(&t, sizeof(t));

		StrCpy(t.Id, sizeof(t.Id), id_str);

		k = Search(s->EtherIPIdList, &t);

		if (k != NULL)
		{
			Copy(id, k, sizeof(ETHERIP_ID));

			ret = true;
		}
	}
	Unlock(s->LockSettings);

	return ret;
}

// Comparison of key EtherIP list entries
int CmpEtherIPId(void *p1, void *p2)
{
	ETHERIP_ID *k1, *k2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	k1 = *(ETHERIP_ID **)p1;
	k2 = *(ETHERIP_ID **)p2;
	if (k1 == NULL || k2 == NULL)
	{
		return 0;
	}

	return StrCmpi(k1->Id, k2->Id);
}

// Release and stop the IPsec server
void FreeIPsecServer(IPSEC_SERVER *s)
{
	UINT i;
	IPSEC_SERVICES sl;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->NoMoreChangeSettings = true;

	// Stopp the L2TP server
	StopL2TPServer(s->L2TP, false);

	// Stop the IKE server
	StopIKEServer(s->Ike);

	// Stop all the services explicitly
	Zero(&sl, sizeof(sl));
	IPsecServerSetServices(s, &sl);

	// Releasing process
	FreeUdpListener(s->UdpListener);

	ReleaseCedar(s->Cedar);

	FreeL2TPServer(s->L2TP);

	FreeIKEServer(s->Ike);

	for (i = 0;i < LIST_NUM(s->EtherIPIdList);i++)
	{
		ETHERIP_ID *k = LIST_DATA(s->EtherIPIdList, i);

		Free(k);
	}

	ReleaseList(s->EtherIPIdList);

	// Stop the OS monitoring thread
	s->Halt = true;
	Set(s->OsServiceCheckThreadEvent);
	WaitThread(s->OsServiceCheckThread, INFINITE);
	ReleaseThread(s->OsServiceCheckThread);
	ReleaseEvent(s->OsServiceCheckThreadEvent);

	DeleteLock(s->LockSettings);

	Free(s);
}

// Initialize the IPsec server
IPSEC_SERVER *NewIPsecServer(CEDAR *cedar)
{
	IPSEC_SERVER *s;
	// Validate arguments
	if (cedar == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(IPSEC_SERVER));

	s->LockSettings = NewLock();

	s->Cedar = cedar;

	AddRef(s->Cedar->ref);

	s->L2TP = NewL2TPServer(cedar);

	s->Ike = NewIKEServer(cedar, s);
	StrCpy(s->Ike->Secret, sizeof(s->Ike->Secret), IPSEC_DEFAULT_SECRET);

	s->UdpListener = NewUdpListener(IPsecServerUdpPacketRecvProc, s);

	s->EtherIPIdList = NewList(CmpEtherIPId);

	// Start an OS service monitoring thread
	s->OsServiceCheckThreadEvent = NewEvent();
	s->OsServiceCheckThread = NewThread(IPsecOsServiceCheckThread, s);

	return s;
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
