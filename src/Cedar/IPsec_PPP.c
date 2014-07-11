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


// IPsec_PPP.c
// PPP protocol stack

#include "CedarPch.h"

// PPP thread
void PPPThread(THREAD *thread, void *param)
{
	PPP_SESSION *p = (PPP_SESSION *)param;
	UINT i;
	PPP_LCP *c;
	USHORT us;
	UINT ui;
	USHORT next_protocol = 0;
	bool ret = false;
	char ipstr1[128], ipstr2[128];
	bool established = false;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// Initialize
	p->Mru1 = p->Mru2 = PPP_MRU_DEFAULT;
	p->RecvPacketList = NewList(NULL);

	//// Link establishment phase
	IPToStr(ipstr1, sizeof(ipstr1), &p->ClientIP);
	IPToStr(ipstr2, sizeof(ipstr2), &p->ServerIP);
	PPPLog(p, "LP_CONNECTED", p->Postfix, ipstr1, p->ClientHostname, p->ClientPort, ipstr2, p->ServerPort,
		p->ClientSoftwareName, p->AdjustMss);

	// Request the use of PAP
	c = NewPPPLCP(PPP_LCP_CODE_REQ, 0);
	us = Endian16(PPP_LCP_AUTH_PAP);
	Add(c->OptionList, NewPPPOption(PPP_LCP_OPTION_AUTH, &us, sizeof(USHORT)));
	ret = PPPSendRequest(p, PPP_PROTOCOL_LCP, c);
	FreePPPLCP(c);
	if (ret == false)
	{
		if (IsTubeConnected(p->TubeRecv))
		{
			// PAP protocol is denied
			p->DisconnectCauseCode = 15;
			p->DisconnectCauseDirection = 1;
			Debug("PPP: PAP Rejected.\n");

			if (p->EnableMSCHAPv2)
			{
				// Try to request the use of MS-CHAPv2
				UCHAR ms_chap_v2_code[3];
				WRITE_USHORT(ms_chap_v2_code, PPP_LCP_AUTH_CHAP);
				ms_chap_v2_code[2] = PPP_CHAP_ALG_MS_CHAP_V2;

				c = NewPPPLCP(PPP_LCP_CODE_REQ, 0);
				Add(c->OptionList, NewPPPOption(PPP_LCP_OPTION_AUTH, ms_chap_v2_code, sizeof(ms_chap_v2_code)));
				ret = PPPSendRequest(p, PPP_PROTOCOL_LCP, c);
				FreePPPLCP(c);

				if (ret == false)
				{
					if (IsTubeConnected(p->TubeRecv))
					{
						// MS-CHAPv2 protocol was also rejected
						p->DisconnectCauseCode = 15;
						p->DisconnectCauseDirection = 1;
						Debug("PPP: MS-CHAPv2 Rejected.\n");
						PPPLog(p, "LP_PAP_MSCHAPV2_REJECTED");
					}
				}
				else
				{
					// It is to be used for the MS-CHAPv2
					p->AuthProtocol = PPP_PROTOCOL_CHAP;
				}
			}
			else
			{
				PPPLog(p, "LP_PAP_REJECTED");
			}
		}

		if (ret == false)
		{
			goto LABEL_CLEANUP;
		}
	}

	//// Authentication phase

	if (p->AuthProtocol == PPP_PROTOCOL_PAP)
	{
		// PAP
		next_protocol = PPPContinueCurrentProtocolRequestListening(p, PPP_PROTOCOL_LCP);
		if (next_protocol == 0)
		{
			goto LABEL_CLEANUP;
		}

		Debug("next_protocol = 0x%x\n", next_protocol);

		if (next_protocol != PPP_PROTOCOL_PAP)
		{
			Debug("next_protocol is not PAP !!\n");
			PPPLog(p, "LP_NEXT_PROTOCOL_IS_NOT_PAP", next_protocol);
			goto LABEL_CLEANUP;
		}

		next_protocol = PPPContinueCurrentProtocolRequestListening(p, PPP_PROTOCOL_PAP);
		if (next_protocol == 0 || p->AuthOk == false)
		{
			if (IsTubeConnected(p->TubeRecv))
			{
				//  PAP authentication failed
				p->DisconnectCauseCode = 15;
				p->DisconnectCauseDirection = 1;
				Debug("PPP: PAP Failed.\n");
				PPPLog(p, "LP_PAP_FAILED");
			}
			goto LABEL_CLEANUP;
		}
	}
	else
	{
		// MS-CHAP v2
		PPP_PACKET *pp, *pp_ret;
		BUF *b;
		char machine_name[MAX_SIZE];
		UINT64 start_tick = Tick64();
		UINT64 timeout_tick = start_tick + (UINT64)PPP_PACKET_RECV_TIMEOUT;
		UINT64 next_send_tick = 0;
		USHORT pp_ret_protocol;

		PPPContinueUntilFinishAllLCPOptionRequestsDetermined(p);

		// Generate a Server Challenge packet of MS-CHAP v2
		GetMachineHostName(machine_name, sizeof(machine_name));
		MsChapV2Server_GenerateChallenge(p->MsChapV2_ServerChallenge);

		pp = ZeroMalloc(sizeof(PPP_PACKET));
		pp->Protocol = PPP_PROTOCOL_CHAP;
		pp->IsControl = true;
		pp->Lcp = NewPPPLCP(PPP_CHAP_CODE_CHALLENGE, 0);

		b = NewBuf();
		WriteBufChar(b, 16);
		WriteBuf(b, p->MsChapV2_ServerChallenge, sizeof(p->MsChapV2_ServerChallenge));
		WriteBuf(b, machine_name, StrLen(machine_name));
		pp->Lcp->Data = Clone(b->Buf, b->Size);
		pp->Lcp->DataSize = b->Size;
		FreeBuf(b);

		PPPSendPacket(p, pp);

		pp_ret_protocol = 0;
		pp_ret = PPPRecvResponsePacket(p, pp, 0, &pp_ret_protocol, false);

		if (pp_ret != NULL)
		{
			FreePPPPacket(pp_ret);
		}

		FreePPPPacket(pp);

		if (pp_ret_protocol == 0 || p->AuthOk == false)
		{
			if (IsTubeConnected(p->TubeRecv))
			{
				// MS-CHAPv2 authentication failed
				p->DisconnectCauseCode = 15;
				p->DisconnectCauseDirection = 1;
				Debug("PPP: MS-CHAPv2 Failed.\n");
				PPPLog(p, "LP_MSCHAPV2_FAILED");
			}
			goto LABEL_CLEANUP;
		}

		next_protocol = pp_ret_protocol;
	}

	Debug("next_protocol = 0x%x\n", next_protocol);

	if (next_protocol != PPP_PROTOCOL_IPCP)
	{
		// Receive the protocol of non-IPCP
		Debug("Not IPCP Protocol.\n");
		PPPLog(p, "LP_NEXT_PROTOCOL_IS_NOT_IPCP", next_protocol);
		goto LABEL_CLEANUP;
	}

	// Notify the IP address of the PPP server
	c = NewPPPLCP(PPP_LCP_CODE_REQ, 0);
	ui = Endian32(0x01000001);	// 1.0.0.1
	Add(c->OptionList, NewPPPOption(PPP_IPCP_OPTION_IP, &ui, sizeof(UINT)));
	ret = PPPSendRequest(p, PPP_PROTOCOL_IPCP, c);
	FreePPPLCP(c);
	if (ret == false)
	{
		goto LABEL_CLEANUP;
	}

	next_protocol = PPPContinueCurrentProtocolRequestListening(p, PPP_PROTOCOL_IPCP);
	Debug("next_protocol = 0x%x\n", next_protocol);

	if (p->Ipc == NULL || IsZeroIP(&p->Ipc->ClientIPAddress))
	{
		// IP address is undetermined
		PPPLog(p, "LP_IP_ADDRESS_NOT_DETERMIND");
		goto LABEL_CLEANUP;
	}

	if (next_protocol == PPP_PROTOCOL_IP)
	{
		established = true;

		// Do the IP communication
		while (true)
		{
			TUBE *tubes[2];
			UINT64 now = Tick64();
			UINT r;

			// Flush the ARP table of the IPC
			IPCFlushArpTable(p->Ipc);

			// Packet of client to server direction
			while (true)
			{
				PPP_PACKET *pp = PPPRecvPacketForCommunication(p);
				if (pp == NULL)
				{
					break;
				}

				if (pp->Protocol == PPP_PROTOCOL_IP)
				{
					// Since I want to send the IP packet, pass it to the IPC
					IPCSendIPv4(p->Ipc, pp->Data, pp->DataSize);
				}

				FreePPPPacket(pp);
			}

			if (p->DhcpAllocated)
			{
				if (now >= p->DhcpNextRenewTime)
				{
					IP ip;

					// DHCP renewal procedure
					p->DhcpNextRenewTime = now + p->DhcpRenewInterval;

					UINTToIP(&ip, p->ClientAddressOption.ServerAddress);

					IPCDhcpRenewIP(p->Ipc, &ip);
				}
			}

			// Happy procedure
			IPCProcessL3Events(p->Ipc);

			// Packet of server to client direction
			while (true)
			{
				BLOCK *b = IPCRecvIPv4(p->Ipc);
				PPP_PACKET *pp;
				PPP_PACKET tmp;
				if (b == NULL)
				{
					break;
				}

				// Since receiving the IP packet, send it to the client by PPP
				pp = &tmp;
				pp->IsControl = false;
				pp->Protocol = PPP_PROTOCOL_IP;
				pp->Lcp = NULL;
				pp->Data = b->Buf;
				pp->DataSize = b->Size;

				PPPSendPacketEx(p, pp, true);

				FreePPPPacketEx(pp, true);
				Free(b);
			}

			FlushTubeFlushList(p->FlushList);

			// PPP Echo Request
			if (p->NextEchoSendTime == 0 || now >= p->NextEchoSendTime)
			{
				p->NextEchoSendTime = now + (UINT64)PPP_ECHO_SEND_INTERVAL;
				AddInterrupt(p->Ipc->Interrupt, p->NextEchoSendTime);

				PPPSendEchoRequest(p);
			}

			// Terminate if any tube is disconnected
			if (IsTubeConnected(p->TubeRecv) == false || IsTubeConnected(p->TubeSend) == false)
			{
				// Higher-level protocol is disconnected
				PPPLog(p, "LP_UPPER_PROTOCOL_DISCONNECTED", p->Postfix);
				break;
			}
			if (IsIPCConnected(p->Ipc) == false)
			{
				// IPC VPN session is disconnected
				PPPLog(p, "LP_VPN_SESSION_TERMINATED");
				break;
			}

			// Time-out inspection
			if ((p->LastRecvTime + (UINT64)PPP_DATA_TIMEOUT) <= now)
			{
				// Communication time-out occurs
				PPPLog(p, "LP_DATA_TIMEOUT");
				break;
			}

			// Terminate if the PPP disconnected
			if (p->IsTerminateReceived)
			{
				PPPLog(p, "LP_NORMAL_TERMINATE");
				break;
			}

			// Wait until the next packet arrives
			tubes[0] = p->TubeRecv;
			tubes[1] = p->Ipc->Sock->RecvTube;

			r = GetNextIntervalForInterrupt(p->Ipc->Interrupt);
			WaitForTubes(tubes, 2, MIN(r, 1234));
		}

		// Disconnected normally
		PPPLog(p, "LP_DISCONNECTED");
	}

	if (p->DhcpAllocated)
	{
		// If any address is assigned from the DHCP, release it
		IP ip;
		char tmp[MAX_SIZE];

		UINTToIP(&ip, p->ClientAddressOption.ServerAddress);

		IPToStr(tmp, sizeof(tmp), &ip);
		Debug("Releasing IP Address from DHCP Server %s...\n", tmp);

		IPCDhcpFreeIP(p->Ipc, &ip);
		IPCProcessL3Events(p->Ipc);

		SleepThread(300);
	}

LABEL_CLEANUP:

	if (established == false)
	{
		//  Disconnected Abnormally
		PPPLog(p, "LP_DISCONNECTED_ABNORMAL");
	}

	// Disconnection process
	PPPCleanTerminate(p);

	// Release the memory
	for (i = 0;i < LIST_NUM(p->RecvPacketList);i++)
	{
		PPP_PACKET *pp = LIST_DATA(p->RecvPacketList, i);

		FreePPPPacket(pp);
	}
	ReleaseList(p->RecvPacketList);

	// Release the PPP session
	FreePPPSession(p);
}

// Disconnect the PPP cleanly
void PPPCleanTerminate(PPP_SESSION *p)
{
	PPP_PACKET *pp;
	PPP_PACKET *res;
	UINT64 giveup_tick = Tick64() + (UINT64)PPP_TERMINATE_TIMEOUT;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	// Send a Terminate Request
	pp = ZeroMalloc(sizeof(PPP_PACKET));
	pp->IsControl = true;
	pp->Protocol = PPP_PROTOCOL_LCP;
	pp->Lcp = NewPPPLCP(PPP_LCP_CODE_TERMINATE_REQ, p->NextId++);
	Debug("PPP: Terminate Request is Sent.\n");
	if (PPPSendPacket(p, pp) == false)
	{
		goto LABEL_CLEANUP;
	}

	// Wait for Terminate ACK
	while (true)
	{
		UINT64 now = Tick64();
		UINT interval;

		if (now >= giveup_tick)
		{
			break;
		}

		while (true)
		{
			if (IsTubeConnected(p->TubeRecv) == false)
			{
				break;
			}

			res = PPPRecvPacket(p, true);

			if (res == NULL)
			{
				break;
			}

			if (res->IsControl && res->Protocol == PPP_PROTOCOL_LCP && res->Lcp->Code == PPP_LCP_CODE_TERMINATE_ACK)
			{
				Debug("PPP: Terminate ACK is Received.\n");
				FreePPPPacket(res);
				goto LABEL_CLEANUP;
			}

			FreePPPPacket(res);
		}

		interval = (UINT)(giveup_tick - now);

		Wait(p->TubeRecv->Event, interval);
	}

LABEL_CLEANUP:
	FreePPPPacket(pp);
}

// Wait until all pending LCP option are determined
bool PPPContinueUntilFinishAllLCPOptionRequestsDetermined(PPP_SESSION *p)
{
	USHORT received_protocol = 0;
	// Validate arguments
	if (p == NULL)
	{
		return false;
	}

	PPPRecvResponsePacket(p, NULL, PPP_PROTOCOL_LCP, &received_protocol, true);

	return p->ClientLCPOptionDetermined;
}

// Continue the processing of the request packet protocol on the current PPP
USHORT PPPContinueCurrentProtocolRequestListening(PPP_SESSION *p, USHORT protocol)
{
	USHORT received_protocol = 0;
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	PPPRecvResponsePacket(p, NULL, protocol, &received_protocol, false);

	return received_protocol;
}

// Send the PPP Echo Request
void PPPSendEchoRequest(PPP_SESSION *p)
{
	PPP_PACKET *pp;
	char echo_data[]= "\0\0\0\0Aho Baka Manuke";
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	pp = ZeroMalloc(sizeof(PPP_PACKET));
	pp->Protocol = PPP_PROTOCOL_LCP;
	pp->IsControl = true;
	pp->Lcp = NewPPPLCP(PPP_LCP_CODE_ECHO_REQUEST, p->NextId++);

	pp->Lcp->Data = Clone(echo_data, sizeof(echo_data));
	pp->Lcp->DataSize = sizeof(echo_data);

	PPPSendPacket(p, pp);

	FreePPPPacket(pp);
}

// Send a request packet in the PPP
bool PPPSendRequest(PPP_SESSION *p, USHORT protocol, PPP_LCP *c)
{
	PPP_PACKET *pp;
	PPP_PACKET *pp2;
	bool ret = false;
	// Validate arguments
	if (p == NULL || c == NULL)
	{
		return false;
	}

	pp = ZeroMalloc(sizeof(PPP_PACKET));
	pp->Protocol = protocol;
	pp->IsControl = true;
	pp->Lcp = c;
	pp->Lcp->Id = p->NextId++;

	// Send the PPP packet
	if (PPPSendPacket(p, pp) == false)
	{
		goto LABEL_ERROR;
	}

	// Receive a corresponding PPP packet
	pp2 = PPPRecvResponsePacket(p, pp, 0, NULL, false);

	if (pp2 != NULL)
	{
		if (protocol == PPP_PROTOCOL_LCP || protocol == PPP_PROTOCOL_IPCP)
		{
			if (!PPP_LCP_CODE_IS_NEGATIVE(pp2->Lcp->Code))
			{
				// A positive response is received
				ret = true;
			}
		}
	}

	FreePPPPacket(pp2);
	Free(pp);

	return ret;

LABEL_ERROR:
	Free(pp);
	return false;
}

// Check whether the Virtual HUB with the specified name exist?
bool IsHubExistsWithLock(CEDAR *cedar, char *hubname)
{
	bool ret = false;
	// Validate arguments
	if (cedar == NULL || hubname == NULL)
	{
		return false;
	}

	LockList(cedar->HubList);
	{
		ret = IsHub(cedar, hubname);
	}
	UnlockList(cedar->HubList);

	return ret;
}

// Separate into the user name and the Virtual HUB name by analyzing the string
bool PPPParseUsername(CEDAR *cedar, char *src_username, ETHERIP_ID *dst)
{
	UINT i, len, last_at, first_en;
	char token1[MAX_SIZE];	// username
	char token2[MAX_SIZE];	// hub_name
	char src[MAX_SIZE];
	// Validate arguments
	Zero(dst, sizeof(ETHERIP_ID));
	if (cedar == NULL || src == NULL || dst == NULL)
	{
		return false;
	}

	StrCpy(src, sizeof(src), src_username);
	Trim(src);

	// Search for the first "\\" in the string
	len = StrLen(src);

	first_en = SearchStrEx(src, "\\", 0, true);

	if (first_en != INFINITE && first_en >= 1 && (first_en < (len - 1)))
	{
		StrCpy(token1, sizeof(token1), src + first_en + 1);
		StrCpy(token2, sizeof(token2), src);
		token2[first_en] = 0;

		// Confirm whether the hubname exists if the virtual HUB name is
		// specified like as hubname\username
		if (IsHubExistsWithLock(cedar, token2) == false)
		{
			// If the hubname does not exist, restore to the original name
			StrCpy(token1, sizeof(token1), src);
			ClearStr(token2, sizeof(token2));
		}
	}
	else
	{
		// Search for the last "@" in the string
		len = StrLen(src);
		last_at = INFINITE;
		for (i = 0;i < len;i++)
		{
			char c = src[i];

			if (c == '@')
			{
				last_at = i;
			}
		}

		Zero(token1, sizeof(token1));
		Zero(token2, sizeof(token2));

		if (last_at == INFINITE)
		{
			// "@" is not specified
			StrCpy(token1, sizeof(token1), src);
		}
		else
		{
			// Split with last "@"
			StrCpy(token1, sizeof(token1), src);
			token1[last_at] = 0;

			StrCpy(token2, sizeof(token2), src + last_at + 1);
		}

		// Check whether such Virtual HUB exists If the virtual HUB name is specified
		if (IsEmptyStr(token2) == false)
		{
			if (IsHubExistsWithLock(cedar, token2) == false)
			{
				// Because the specified virtual HUB name doesn't exist, it's considered to be a part of the user name
				StrCpy(token1, sizeof(token1), src);

				ClearStr(token2, sizeof(token2));
			}
		}
	}

	if (IsEmptyStr(token2))
	{
		// Select the default Virtual HUB if the Virtual HUB name is not specified
		StrCpy(token2, sizeof(token2), SERVER_DEFAULT_HUB_NAME);
		if (cedar->Server != NULL && cedar->Server->IPsecServer != NULL)
		{
			Lock(cedar->Server->IPsecServer->LockSettings);
			{
				IPsecNormalizeServiceSetting(cedar->Server->IPsecServer);

				StrCpy(token2, sizeof(token2), cedar->Server->IPsecServer->Services.L2TP_DefaultHub);
			}
			Unlock(cedar->Server->IPsecServer->LockSettings);
		}

	}

	// Return the results
	StrCpy(dst->HubName, sizeof(dst->HubName), token2);
	StrCpy(dst->UserName, sizeof(dst->UserName), token1);

	return true;
}

// Process the PPP request packet
PPP_PACKET *PPPProcessRequestPacket(PPP_SESSION *p, PPP_PACKET *req)
{
	UINT i;
	PPP_PACKET *ret = NULL;
	UINT num_not_supported = 0;
	UINT num_not_accepted = 0;
	bool no_return_option_list = false;
	UINT return_code = 0;
	BUF *lcp_ret_data = NULL;
	// Validate arguments
	if (p == NULL || req == NULL || req->Lcp == NULL)
	{
		return NULL;
	}

	// Initialize
	for (i = 0;i < LIST_NUM(req->Lcp->OptionList);i++)
	{
		PPP_OPTION *t = LIST_DATA(req->Lcp->OptionList, i);

		t->IsAccepted = false;
		t->IsSupported = false;
		t->AltDataSize = 0;
		Zero(t->AltData, sizeof(t->AltData));
	}

	// Process by scanning the specified option value
	if (req->Protocol == PPP_PROTOCOL_LCP)
	{
		// LCP
		if (req->Lcp == NULL)
		{
			return NULL;
		}
		for (i = 0;i < LIST_NUM(req->Lcp->OptionList);i++)
		{
			PPP_OPTION *t = LIST_DATA(req->Lcp->OptionList, i);

			switch (t->Type)
			{
			case PPP_LCP_OPTION_MRU:
				// MRU
				t->IsSupported = true;
				if (t->DataSize == sizeof(USHORT))
				{
					UINT value = READ_USHORT(t->Data);
					if (value < PPP_MRU_MIN || value > PPP_MRU_MAX)
					{
						t->IsAccepted = false;
						value = MAKESURE(value, PPP_MRU_MIN, PPP_MRU_MAX);
						WRITE_USHORT(t->AltData, value);
						t->AltDataSize = sizeof(USHORT);
					}
					else
					{
						p->Mru1 = value;
						Debug("PPP: Client set %u as MRU\n", p->Mru1);
						t->IsAccepted = true;
					}
				}
				break;
			}
		}
	}
	else if (req->Protocol == PPP_PROTOCOL_CHAP)
	{
		bool ok = false;
		char ret_str[MAX_SIZE];

		no_return_option_list = true;

		if (p->Ipc == NULL)
		{
			// MS-CHAPv2
			if (req->Lcp->DataSize >= 51)
			{
				BUF *b;

				b = NewBuf();

				WriteBuf(b, req->Lcp->Data, req->Lcp->DataSize);
				SeekBuf(b, 0, 0);

				if (ReadBufChar(b) == 49)
				{
					UCHAR client_response_buffer[49];
					UCHAR *client_challenge_16;
					UCHAR *client_response_24;
					char username_tmp[MAX_SIZE];
					IPC *ipc = NULL;
					char id[MAX_SIZE];
					char hub[MAX_SIZE];
					char password[MAX_SIZE];
					char server_challenge_hex[MAX_SIZE];
					char client_challenge_hex[MAX_SIZE];
					char client_response_hex[MAX_SIZE];
					ETHERIP_ID d;
					UINT error_code;

					ReadBuf(b, client_response_buffer, 49);

					Zero(username_tmp, sizeof(username_tmp));
					ReadBuf(b, username_tmp, sizeof(username_tmp));

					client_challenge_16 = client_response_buffer + 0;
					client_response_24 = client_response_buffer + 16 + 8;

					Copy(p->MsChapV2_ClientChallenge, client_challenge_16, 16);
					Copy(p->MsChapV2_ClientResponse, client_response_24, 24);

					Debug("MS-CHAPv2: id=%s\n", username_tmp);

					Zero(id, sizeof(id));
					Zero(hub, sizeof(hub));

					// The user name is divided into the ID and the virtual HUB name
					Zero(&d, sizeof(d));
					PPPParseUsername(p->Cedar, username_tmp, &d);

					StrCpy(id, sizeof(id), d.UserName);
					StrCpy(hub, sizeof(hub), d.HubName);

					// Convert the MS-CHAPv2 data to a password string
					BinToStr(server_challenge_hex, sizeof(server_challenge_hex),
						p->MsChapV2_ServerChallenge, sizeof(p->MsChapV2_ServerChallenge));
					BinToStr(client_challenge_hex, sizeof(client_challenge_hex),
						p->MsChapV2_ClientChallenge, sizeof(p->MsChapV2_ClientChallenge));
					BinToStr(client_response_hex, sizeof(client_response_hex),
						p->MsChapV2_ClientResponse, sizeof(p->MsChapV2_ClientResponse));

					Format(password, sizeof(password), "%s%s:%s:%s:%s",
						IPC_PASSWORD_MSCHAPV2_TAG,
						username_tmp,
						server_challenge_hex,
						client_challenge_hex,
						client_response_hex);

					// Attempt to connect with IPC
					ipc = NewIPC(p->Cedar, p->ClientSoftwareName, p->Postfix, hub, id, password,
						&error_code, &p->ClientIP, p->ClientPort, &p->ServerIP, p->ServerPort,
						p->ClientHostname, p->CryptName, false, p->AdjustMss);

					if (ipc != NULL)
					{
						p->Ipc = ipc;

						Copy(p->MsChapV2_ServerResponse, ipc->MsChapV2_ServerResponse, 20);

						ok = true;
					}
					else
					{
						switch (error_code)
						{
						default:
							// Normal authentication error
							p->MsChapV2_ErrorCode = 691;
							break;

						case ERR_MSCHAP2_PASSWORD_NEED_RESET:
							// Authentication errors due to compatibility issues of the password
							p->MsChapV2_ErrorCode = 942;
							break;
						}
					}
				}

				FreeBuf(b);
			}
		}
		else
		{
			// Return success for a request from the second time when it is successfully authenticated once
			ok = true;
		}

		// Generate a response options string
		if (ok == false)
		{
			// In the case of failure
			char hex[MAX_SIZE];
			BinToStr(hex, sizeof(hex), p->MsChapV2_ServerChallenge, 16);

			Format(ret_str, sizeof(ret_str),
				"E=%u R=0 C=%s V=3", p->MsChapV2_ErrorCode, hex);

			return_code = PPP_CHAP_CODE_FAILURE;
		}
		else
		{
			// In the case of success
			char hex[MAX_SIZE];
			BinToStr(hex, sizeof(hex), p->MsChapV2_ServerResponse, 20);

			Format(ret_str, sizeof(ret_str),
				"S=%s", hex);

			return_code = PPP_CHAP_CODE_SUCCESS;

			p->AuthOk = true;
		}

		lcp_ret_data = NewBuf();
		WriteBuf(lcp_ret_data, ret_str, StrLen(ret_str));
	}
	else if (req->Protocol == PPP_PROTOCOL_PAP)
	{
		UCHAR *data;
		UINT size;
		bool ok = false;

		no_return_option_list = true;

		if (p->Ipc == NULL)
		{
			// PAP

			// Extract the ID and the password
			data = req->Lcp->Data;
			size = req->Lcp->DataSize;

			if (size >= 1)
			{
				UCHAR len_id = data[0];
				data++;
				size--;

				if (size >= len_id)
				{
					char username[256];
					char password[256];

					Zero(username, sizeof(username));
					Zero(password, sizeof(password));

					Copy(username, data, len_id);
					data += len_id;
					size -= len_id;

					if (size >= 1)
					{
						UCHAR len_pass = data[0];
						data++;
						size--;

						if (size >= len_pass)
						{
							IPC *ipc;
							char id[MAX_SIZE];
							char hub[MAX_SIZE];
							ETHERIP_ID d;

							Zero(id, sizeof(id));
							Zero(hub, sizeof(hub));

							Copy(password, data, len_pass);

							Debug("PPP: id=%s, pw=%s\n", username, password);

							// The user name is divided into the ID and the virtual HUB name
							Zero(&d, sizeof(d));
							PPPParseUsername(p->Cedar, username, &d);

							StrCpy(id, sizeof(id), d.UserName);
							StrCpy(hub, sizeof(hub), d.HubName);

							if (IsEmptyStr(id) == false)
							{
								// Attempt to connect with IPC
								UINT error_code;

								ipc = NewIPC(p->Cedar, p->ClientSoftwareName, p->Postfix, hub, id, password,
									&error_code, &p->ClientIP, p->ClientPort, &p->ServerIP, p->ServerPort,
									p->ClientHostname, p->CryptName, false, p->AdjustMss);

								if (ipc != NULL)
								{
									p->Ipc = ipc;
									ok = true;
								}
							}
						}
					}
				}
			}
		}
		else
		{
			// Return success for a request from the second time when it is successfully authenticated once
			ok = true;
		}

		if (ok == false)
		{
			// Authentication failure
			return_code = PPP_PAP_CODE_NAK;
		}
		else
		{
			// Authentication success
			return_code = PPP_PAP_CODE_ACK;

			p->AuthOk = true;
		}
	}
	else if (req->Protocol == PPP_PROTOCOL_IPCP)
	{
		PPP_IPOPTION o;
		// Get the IP options data from the request data
		if (PPPGetIPOptionFromLCP(&o, req->Lcp))
		{
			PPP_IPOPTION res;
			IP subnet;
			IP gw;

			if (IsZeroIP(&o.IpAddress) == false)
			{
				if (p->Ipc->Policy->DHCPForce == false)
				{
					if (p->DhcpAllocated == false)
					{
						if (p->UseStaticIPAddress == false)
						{
							DHCP_OPTION_LIST cao;

							// The client specify an IP address
							Zero(&cao, sizeof(cao));

							cao.ClientAddress = IPToUINT(&o.IpAddress);

							Copy(&p->ClientAddressOption, &cao, sizeof(cao));

							p->UseStaticIPAddress = true;
						}
					}
				}
			}
			else
			{
				p->UseStaticIPAddress = false;
			}

			if (p->UseStaticIPAddress)
			{
				if (p->DhcpIpInformTried == false)
				{
					// Get additional information such as the subnet mask from the DHCP server
					DHCP_OPTION_LIST cao;
					IP client_ip;

					IP subnet;
					IP zero;

					SetIP(&subnet, 255, 0, 0, 0);
					Zero(&zero, sizeof(zero));

					UINTToIP(&client_ip, p->ClientAddressOption.ClientAddress);

					Zero(&cao, sizeof(cao));

					IPCSetIPv4Parameters(p->Ipc, &client_ip, &subnet, &zero, NULL);

					p->DhcpIpInformTried = true;

					PPPLog(p, "LP_DHCP_INFORM_TRYING");

					if (IPCDhcpRequestInformIP(p->Ipc, &cao, p->TubeRecv, &client_ip))
					{
						Debug("IPCDhcpRequestInformIP ok.\n");
						Copy(&p->ClientAddressOption, &cao, sizeof(cao));
						p->ClientAddressOption.ClientAddress = IPToUINT(&client_ip);

						if (true)
						{
							char server_ip_str[64];
							char subnet_str[64], defgw_str[64];
							char dns1_str[64], dns2_str[64];
							char wins1_str[64], wins2_str[64];

							IPToStr32(server_ip_str, sizeof(server_ip_str), cao.ServerAddress);
							IPToStr32(subnet_str, sizeof(subnet_str), cao.SubnetMask);
							IPToStr32(defgw_str, sizeof(defgw_str), cao.Gateway);
							IPToStr32(dns1_str, sizeof(dns1_str), cao.DnsServer);
							IPToStr32(dns2_str, sizeof(dns2_str), cao.DnsServer2);
							IPToStr32(wins1_str, sizeof(wins1_str), cao.WinsServer);
							IPToStr32(wins2_str, sizeof(wins2_str), cao.WinsServer2);

							PPPLog(p, "LP_DHCP_INFORM_OK",
								subnet_str, defgw_str, cao.DomainName,
								dns1_str, dns2_str, wins1_str, wins2_str,
								server_ip_str);
						}
					}
					else
					{
						Debug("IPCDhcpRequestInformIP failed.\n");

						PPPLog(p, "LP_DHCP_INFORM_NG");
					}

					IPCSetIPv4Parameters(p->Ipc, &zero, &zero, &zero, NULL);
				}
			}
			else
			{
				// Get an IP address from a DHCP server
				if (p->DhcpIpAllocTried == false)
				{
					DHCP_OPTION_LIST cao;

					Zero(&cao, sizeof(cao));
					p->DhcpIpAllocTried = true;

					PPPLog(p, "LP_DHCP_REQUEST_TRYING");

					if (IPCDhcpAllocateIP(p->Ipc, &cao, p->TubeRecv))
					{
						UINT t;

						Debug("IPCDhcpAllocateIP ok.\n");

						// IP address has been determined
						Copy(&p->ClientAddressOption, &cao, sizeof(cao));

						p->DhcpAllocated = true;

						// Determine the DHCP update interval
						t = cao.LeaseTime;
						if (t == 0)
						{
							t = 600;
						}

						t = t / 3;

						if (t == 0)
						{
							t = 1;
						}

						p->DhcpRenewInterval = (UINT64)(t * 1000);
						p->DhcpNextRenewTime = Tick64() + p->DhcpRenewInterval;

						if (true)
						{
							char client_ip_str[64], server_ip_str[64];
							char subnet_str[64], defgw_str[64];
							char dns1_str[64], dns2_str[64];
							char wins1_str[64], wins2_str[64];

							IPToStr32(client_ip_str, sizeof(client_ip_str), cao.ClientAddress);
							IPToStr32(server_ip_str, sizeof(server_ip_str), cao.ServerAddress);
							IPToStr32(subnet_str, sizeof(subnet_str), cao.SubnetMask);
							IPToStr32(defgw_str, sizeof(defgw_str), cao.Gateway);
							IPToStr32(dns1_str, sizeof(dns1_str), cao.DnsServer);
							IPToStr32(dns2_str, sizeof(dns2_str), cao.DnsServer2);
							IPToStr32(wins1_str, sizeof(wins1_str), cao.WinsServer);
							IPToStr32(wins2_str, sizeof(wins2_str), cao.WinsServer2);

							PPPLog(p, "LP_DHCP_REQUEST_OK",
								client_ip_str, subnet_str, defgw_str, cao.DomainName,
								dns1_str, dns2_str, wins1_str, wins2_str,
								server_ip_str, cao.LeaseTime);
						}
					}
					else
					{
						Debug("IPCDhcpAllocateIP failed.\n");

						PPPLog(p, "LP_DHCP_REQUEST_NG");
					}
				}
			}

			if (IsValidUnicastIPAddressUINT4(p->ClientAddressOption.ClientAddress) &&
				p->ClientAddressOption.SubnetMask != 0)
			{
				// Success to determine the address
				UINTToIP(&subnet, p->ClientAddressOption.SubnetMask);
				UINTToIP(&gw, p->ClientAddressOption.Gateway);

				Zero(&res, sizeof(res));
				UINTToIP(&res.IpAddress, p->ClientAddressOption.ClientAddress);
				UINTToIP(&res.DnsServer1, p->ClientAddressOption.DnsServer);
				UINTToIP(&res.DnsServer2, p->ClientAddressOption.DnsServer2);
				UINTToIP(&res.WinsServer1, p->ClientAddressOption.WinsServer);
				UINTToIP(&res.WinsServer2, p->ClientAddressOption.WinsServer2);

				if (IPCSetIPv4Parameters(p->Ipc, &res.IpAddress, &subnet, &gw, &p->ClientAddressOption.ClasslessRoute))
				{
					char client_ip_str[64];
					char subnet_str[64], defgw_str[64];
					char dns1_str[64], dns2_str[64];
					char wins1_str[64], wins2_str[64];

					// IPv4 parameters have been set for the first time
					Debug("Param First Set.\n");

					IPToStr(client_ip_str, sizeof(client_ip_str), &res.IpAddress);
					IPToStr(subnet_str, sizeof(subnet_str), &subnet);
					IPToStr(defgw_str, sizeof(defgw_str), &gw);
					IPToStr(dns1_str, sizeof(dns1_str), &res.DnsServer1);
					IPToStr(dns2_str, sizeof(dns2_str), &res.DnsServer2);
					IPToStr(wins1_str, sizeof(wins1_str), &res.WinsServer1);
					IPToStr(wins2_str, sizeof(wins2_str), &res.WinsServer2);

					PPPLog(p, "LP_SET_IPV4_PARAM", client_ip_str, subnet_str,
						defgw_str, dns1_str, dns2_str, wins1_str, wins2_str);
				}

				PPPSetIPOptionToLCP(&res, req->Lcp, true);
			}
			else
			{
				// Failed to determine the address
				Debug("IP Address Determination Failed.\n");

				Zero(&res, sizeof(res));

				PPPSetIPOptionToLCP(&res, req->Lcp, true);
			}
		}
	}

	// Assemble the LCP response packet based on the results
	for (i = 0;i < LIST_NUM(req->Lcp->OptionList);i++)
	{
		PPP_OPTION *t = LIST_DATA(req->Lcp->OptionList, i);

		if (t->IsSupported == false)
		{
			num_not_supported++;
		}

		if (t->IsAccepted == false)
		{
			num_not_accepted++;
		}
	}

	// Create a PPP response packet
	ret = ZeroMalloc(sizeof(PPP_PACKET));
	ret->IsControl = true;
	ret->Protocol = req->Protocol;

	if (no_return_option_list == false)
	{
		// Response by attaching an optional list
		if (num_not_supported >= 1)
		{
			// Return a Reject if there are unsupported parameters
			ret->Lcp = NewPPPLCP(PPP_LCP_CODE_REJECT, req->Lcp->Id);

			for (i = 0;i < LIST_NUM(req->Lcp->OptionList);i++)
			{
				PPP_OPTION *t = LIST_DATA(req->Lcp->OptionList, i);

				if (t->IsSupported == false)
				{
					// Attach the original option value as is
					Add(ret->Lcp->OptionList, NewPPPOption(t->Type, t->Data, t->DataSize));
				}
			}
		}
		else if (num_not_accepted >= 1)
		{
			// Return a NAK if there are any unacceptable parameter
			// even that all parameters are supported
			ret->Lcp = NewPPPLCP(PPP_LCP_CODE_NAK, req->Lcp->Id);

			for (i = 0;i < LIST_NUM(req->Lcp->OptionList);i++)
			{
				PPP_OPTION *t = LIST_DATA(req->Lcp->OptionList, i);

				if (t->IsAccepted == false)
				{
					// Replace the original option value with an acceptable value
					Add(ret->Lcp->OptionList, NewPPPOption(t->Type, t->AltData, t->AltDataSize));
				}
			}
		}
		else
		{
			// Return an ACK if all parameters are accepted
			ret->Lcp = NewPPPLCP(PPP_LCP_CODE_ACK, req->Lcp->Id);

			for (i = 0;i < LIST_NUM(req->Lcp->OptionList);i++)
			{
				PPP_OPTION *t = LIST_DATA(req->Lcp->OptionList, i);

				// Attach the original option value as is
				Add(ret->Lcp->OptionList, NewPPPOption(t->Type, t->Data, t->DataSize));
			}

			if (req->Protocol == PPP_PROTOCOL_LCP)
			{
				p->ClientLCPOptionDetermined = true;
			}
		}
	}
	else
	{
		// Response without attaching a list of options
		ret->Lcp = NewPPPLCP(return_code, req->Lcp->Id);

		if (lcp_ret_data != NULL && lcp_ret_data->Size >= 1)
		{
			ret->Lcp->Data = Clone(lcp_ret_data->Buf, lcp_ret_data->Size);
			ret->Lcp->DataSize = lcp_ret_data->Size;
		}
	}

	if (lcp_ret_data != NULL)
	{
		FreeBuf(lcp_ret_data);
	}

	return ret;
}

// Set the IP options of PPP to LCP
bool PPPSetIPOptionToLCP(PPP_IPOPTION *o, PPP_LCP *c, bool only_modify)
{
	bool ret = false;
	// Validate arguments
	if (c == NULL || o == NULL)
	{
		return false;
	}

	ret = PPPSetIPAddressValueToLCP(c, PPP_IPCP_OPTION_IP, &o->IpAddress, only_modify);

	PPPSetIPAddressValueToLCP(c, PPP_IPCP_OPTION_DNS1, &o->DnsServer1, only_modify);
	PPPSetIPAddressValueToLCP(c, PPP_IPCP_OPTION_DNS2, &o->DnsServer2, only_modify);
	PPPSetIPAddressValueToLCP(c, PPP_IPCP_OPTION_WINS1, &o->WinsServer1, only_modify);
	PPPSetIPAddressValueToLCP(c, PPP_IPCP_OPTION_WINS2, &o->WinsServer2, only_modify);

	return ret;
}

// Get the IP options of PPP from LCP
bool PPPGetIPOptionFromLCP(PPP_IPOPTION *o, PPP_LCP *c)
{
	bool ret;
	// Validate arguments
	if (c == NULL || o == NULL)
	{
		return false;
	}

	Zero(o, sizeof(PPP_IPOPTION));

	ret = PPPGetIPAddressValueFromLCP(c, PPP_IPCP_OPTION_IP, &o->IpAddress);

	PPPGetIPAddressValueFromLCP(c, PPP_IPCP_OPTION_DNS1, &o->DnsServer1);
	PPPGetIPAddressValueFromLCP(c, PPP_IPCP_OPTION_DNS2, &o->DnsServer2);
	PPPGetIPAddressValueFromLCP(c, PPP_IPCP_OPTION_WINS1, &o->WinsServer1);
	PPPGetIPAddressValueFromLCP(c, PPP_IPCP_OPTION_WINS2, &o->WinsServer2);

	return ret;
}

// Set the IP address data to the option list of the LCP
bool PPPSetIPAddressValueToLCP(PPP_LCP *c, UINT type, IP *ip, bool only_modify)
{
	IP ip2;
	UINT ui;
	// Validate arguments
	if (c == NULL || ip == NULL)
	{
		return false;
	}

	ui = IPToUINT(ip);

	if (PPPGetIPAddressValueFromLCP(c, type, &ip2))
	{
		PPP_OPTION *opt;
		opt = GetOptionValue(c, type);

		if (opt != NULL)
		{
			if (IsZeroIP(ip) == false)
			{
				if (CmpIpAddr(&ip2, ip) == 0)
				{
					// No change
					opt->IsAccepted = true;
					opt->IsSupported = true;
				}
				else
				{
					// Changed
					opt->IsAccepted = false;
					opt->IsSupported = true;
					opt->AltDataSize = 4;
					Copy(opt->AltData, &ui, 4);
				}
			}
			else
			{
				// The parameter itself is not supported
				// (if the IP address is 0.0.0.0)
				opt->IsSupported = false;
				opt->IsAccepted = false;
			}
		}

		return true;
	}
	else
	{
		if (IsZeroIP(ip) == false)
		{
			// Add as a new item
			if (only_modify != false)
			{
				return false;
			}
			else
			{
				PPP_OPTION *opt2 = NewPPPOption(type, &ui, 4);
				opt2->IsAccepted = opt2->IsSupported = true;

				Add(c->OptionList, opt2);

				return true;
			}
		}
		else
		{
			return false;
		}
	}
}

// Get the IP address data from the option list of the LCP
bool PPPGetIPAddressValueFromLCP(PPP_LCP *c, UINT type, IP *ip)
{
	PPP_OPTION *opt;
	UINT ui;
	// Validate arguments
	if (c == NULL || ip == NULL)
	{
		return false;
	}

	opt = GetOptionValue(c, type);
	if (opt == NULL)
	{
		return false;
	}

	if (opt->DataSize != 4)
	{
		return false;
	}

	opt->IsSupported = true;

	ui = *((UINT *)opt->Data);

	UINTToIP(ip, ui);

	return true;
}

// Process corresponding to the incoming request while receiving a PPP packet corresponding to the transmitted request.
// (If req == NULL, process on that protocol while the protocol specified in expected_protocol have received.
//If other protocols has arrived, without further processing, and then store that packet in the session context once,
// return NULL by setting the received_protocol.)
PPP_PACKET *PPPRecvResponsePacket(PPP_SESSION *p, PPP_PACKET *req, USHORT expected_protocol, USHORT *received_protocol, bool finish_when_all_lcp_acked)
{
	UINT64 giveup_tick = Tick64() + (UINT64)PPP_PACKET_RECV_TIMEOUT;
	UINT64 next_resend = Tick64() + (UINT64)PPP_PACKET_RESEND_INTERVAL;
	PPP_PACKET *ret = NULL;
	USHORT tmp_us = 0;
	// Validate arguments
	if (p == NULL || req != NULL && req->Lcp == NULL)
	{
		return NULL;
	}

	if (received_protocol == NULL)
	{
		received_protocol = &tmp_us;
	}

	if (req != NULL)
	{
		expected_protocol = req->Protocol;
	}

	*received_protocol = 0;

	// Receive the next packet (Retransmission repeatedly the last packet until the reception is completed)
	while (true)
	{
		UINT64 now = Tick64();
		UINT interval;

		if (IsTubeConnected(p->TubeRecv) == false)
		{
			return NULL;
		}

		while (true)
		{
			PPP_PACKET *pp;
			PPP_PACKET *response;

			if (p->LastStoredPacket != NULL)
			{
				pp = p->LastStoredPacket;
				p->LastStoredPacket = NULL;
			}
			else
			{
				pp = PPPRecvPacketWithLowLayerProcessing(p, true);
			}

			if (pp == NULL)
			{
				break;
			}

			if (req != NULL)
			{
				// Determine whether the packet is corresponding to the request that was sent at the last
				if (pp->IsControl && pp->Protocol == req->Protocol && pp->Lcp->Id == req->Lcp->Id &&
					PPP_CODE_IS_RESPONSE(pp->Protocol, pp->Lcp->Code))
				{
					return pp;
				}
			}

			// Return a response immediately without processing if a protocol other than the expected received
			if ((pp->IsControl && pp->Protocol != expected_protocol) || pp->IsControl == false)
			{
				if (PPP_IS_SUPPORTED_PROTOCOL(pp->Protocol))
				{
					// This is another supported protocol
					// Store this packet
					PPPStoreLastPacket(p, pp);

					*received_protocol = pp->Protocol;
					return NULL;
				}
				else
				{
					// Unsupported protocol
					Debug("Unsupported Protocol: 0x%x\n", pp->Protocol);
					FreePPPPacket(pp);

					return NULL;
				}
			}

			if (pp->IsControl && PPP_CODE_IS_REQUEST(pp->Protocol, pp->Lcp->Code))
			{
				// Process when the received packet is a request packet
				response = PPPProcessRequestPacket(p, pp);
				FreePPPPacket(pp);

				if (response == NULL)
				{
					return NULL;
				}
				else
				{
					bool is_pap_and_disconnect_now = false;
					bool is_chap_and_disconnect_now = false;

					if (PPPSendPacket(p, response) == false)
					{
						FreePPPPacket(response);
						return NULL;
					}

					if (response->Protocol == PPP_PROTOCOL_PAP && response->IsControl &&
						response->Lcp->Code != PPP_PAP_CODE_ACK)
					{
						is_pap_and_disconnect_now = true;
					}

					if (response->Protocol == PPP_PROTOCOL_CHAP && response->IsControl &&
						response->Lcp->Code == PPP_CHAP_CODE_FAILURE)
					{
						is_chap_and_disconnect_now = true;
					}

					FreePPPPacket(response);

					if (is_pap_and_disconnect_now)
					{
						// Disconnect immediately if user authentication fails at least once in the PAP authentication protocol
						Debug("Disconnecting because PAP failed.\n");
						SleepThread(300);
						return NULL;
					}

					if (is_chap_and_disconnect_now)
					{
						// Disconnect immediately if it fails to user authentication at least once in the CHAP authentication protocol
						Debug("Disconnecting because CHAP failed.\n");
						SleepThread(300);
						return NULL;
					}
				}
			}
			else
			{
				// Ignore in the case of the other packets
				FreePPPPacket(pp);
			}
		}

		// Packet retransmission
		if (req != NULL)
		{
			if (now >= next_resend)
			{
				next_resend = now + PPP_PACKET_RESEND_INTERVAL;

				if (PPPSendPacket(p, req) == false)
				{
					return NULL;
				}
			}
		}

		if (req == NULL)
		{
			giveup_tick = now + (UINT64)PPP_PACKET_RECV_TIMEOUT;
		}

		// Time-out decision
		if (now >= giveup_tick)
		{
			PPPLog(p, "LP_CONTROL_TIMEOUT");
			return NULL;
		}

		// Wait
		if (req != NULL)
		{
			interval = MIN((UINT)(giveup_tick - now), (UINT)(next_resend - now));
		}
		else
		{
			interval = (UINT)(giveup_tick - now);
		}

		if (finish_when_all_lcp_acked && p->ClientLCPOptionDetermined)
		{
			return NULL;
		}

		Wait(p->TubeRecv->Event, interval);
	}
}

// Store the last packet in the session (to be read the next time)
void PPPStoreLastPacket(PPP_SESSION *p, PPP_PACKET *pp)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->LastStoredPacket != NULL)
	{
		FreePPPPacket(p->LastStoredPacket);
	}

	p->LastStoredPacket = pp;
}

// Receive a PPP communication packet
PPP_PACKET *PPPRecvPacketForCommunication(PPP_SESSION *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	if (p->LastStoredPacket != NULL)
	{
		PPP_PACKET *pp = p->LastStoredPacket;
		p->LastStoredPacket = NULL;
		return pp;
	}

	return PPPRecvPacketWithLowLayerProcessing(p, true);
}

// Receive a PPP packet (Also performs low layer processing)
PPP_PACKET *PPPRecvPacketWithLowLayerProcessing(PPP_SESSION *p, bool async)
{
	PPP_PACKET *pp = NULL;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

LABEL_LOOP:
	pp = PPPRecvPacket(p, async);
	if (pp == NULL)
	{
		return NULL;
	}

	if (PPP_IS_SUPPORTED_PROTOCOL(pp->Protocol) == false)
	{
		// Unsupported algorithm
		PPP_PACKET *pp2 = ZeroMalloc(sizeof(PPP_PACKET));
		BUF *buf;
		UCHAR c;
		USHORT us;

		pp2->Protocol = PPP_PROTOCOL_LCP;
		pp2->IsControl = false;

		buf = NewBuf();

		// Code
		c = PPP_LCP_CODE_PROTOCOL_REJECT;
		WriteBuf(buf, &c, 1);

		// ID
		c = p->NextId++;
		WriteBuf(buf, &c, 1);

		// Length
		us = Endian16(pp->DataSize + 6);
		WriteBuf(buf, &us, 2);

		// Rejected Protocol
		us = Endian16(pp->Protocol);
		WriteBuf(buf, &us, 2);

		// Packet Data
		WriteBuf(buf, pp->Data, pp->DataSize);

		pp2->Data = Clone(buf->Buf, buf->Size);
		pp2->DataSize = buf->Size;

		FreePPPPacket(pp);

		FreeBuf(buf);

		if (PPPSendPacket(p, pp2) == false)
		{
			FreePPPPacket(pp2);
			return NULL;
		}

		FreePPPPacket(pp2);
		goto LABEL_LOOP;
	}

	if (pp->IsControl && pp->Protocol == PPP_PROTOCOL_LCP)
	{
		if (pp->Lcp->Code == PPP_LCP_CODE_ECHO_REQUEST)
		{
			// Immediately return the echo response to the echo request
			PPP_PACKET *pp2 = ZeroMalloc(sizeof(PPP_PACKET));

			pp2->IsControl = true;
			pp2->Protocol = PPP_PROTOCOL_LCP;
			pp2->Lcp = NewPPPLCP(PPP_LCP_CODE_ECHO_RESPONSE, pp->Lcp->Id);
			pp2->Lcp->Data = Clone(pp->Lcp->Data, pp->Lcp->DataSize);
			pp2->Lcp->DataSize = pp->Lcp->DataSize;

			FreePPPPacket(pp);

			if (PPPSendPacket(p, pp2) == false)
			{
				FreePPPPacket(pp2);
				return NULL;
			}

			FreePPPPacket(pp2);
			goto LABEL_LOOP;
		}
		else if (pp->Lcp->Code == PPP_LCP_CODE_ECHO_RESPONSE)
		{
			// Ignore the Echo response packet
			FreePPPPacket(pp);
			goto LABEL_LOOP;
		}
		else if (pp->Lcp->Code == PPP_LCP_CODE_DROP)
		{
			// Ignore the Drop packet
			FreePPPPacket(pp);
			goto LABEL_LOOP;
		}
		else if (pp->Lcp->Code == PPP_LCP_CODE_IDENTIFICATION)
		{
			// Ignore the Identification packet
			FreePPPPacket(pp);
			WHERE;
			goto LABEL_LOOP;
		}
		else if (pp->Lcp->Code == PPP_LCP_CODE_TERMINATE_REQ)
		{
			// Return the Terminate ACK If a Terminate Request has been received
			PPP_PACKET *pp2 = ZeroMalloc(sizeof(PPP_PACKET));

			pp2->IsControl = true;
			pp2->Protocol = PPP_PROTOCOL_LCP;
			pp2->Lcp = NewPPPLCP(PPP_LCP_CODE_TERMINATE_ACK, pp->Lcp->Id);
			pp2->Lcp->Data = Clone(pp->Lcp->Data, pp->Lcp->DataSize);
			pp2->Lcp->DataSize = pp->Lcp->DataSize;

			p->IsTerminateReceived = true;

			FreePPPPacket(pp);

			if (PPPSendPacket(p, pp2) == false)
			{
				FreePPPPacket(pp2);
				return NULL;
			}

			SleepThread(100);

			FreePPPPacket(pp2);
			goto LABEL_LOOP;
		}
	}

	return pp;
}

// Receive a PPP packet
PPP_PACKET *PPPRecvPacket(PPP_SESSION *p, bool async)
{
	TUBEDATA *d;
	PPP_PACKET *pp;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

LABEL_LOOP:

	if (async == false)
	{
		d = TubeRecvSync(p->TubeRecv, PPP_PACKET_RECV_TIMEOUT);
	}
	else
	{
		d = TubeRecvAsync(p->TubeRecv);
	}

	if (d == NULL)
	{
		return NULL;
	}

	pp = ParsePPPPacket(d->Data, d->DataSize);
	FreeTubeData(d);

	if (pp == NULL)
	{
		// A broken packet is received
		goto LABEL_LOOP;
	}

	p->LastRecvTime = Tick64();

	return pp;
}

// Send the PPP packet
bool PPPSendPacket(PPP_SESSION *p, PPP_PACKET *pp)
{
	return PPPSendPacketEx(p, pp, false);
}
bool PPPSendPacketEx(PPP_SESSION *p, PPP_PACKET *pp, bool no_flush)
{
	bool ret = false;
	BUF *b;
	// Validate arguments
	if (p == NULL || pp == NULL)
	{
		return false;
	}

	b = BuildPPPPacketData(pp);
	if (b == NULL)
	{
		return false;
	}

	ret = TubeSendEx(p->TubeSend, b->Buf, b->Size, NULL, no_flush);

	if (no_flush)
	{
		AddTubeToFlushList(p->FlushList, p->TubeSend);
	}

	FreeBuf(b);

	return ret;
}

// Create a new PPP options
PPP_OPTION *NewPPPOption(UCHAR type, void *data, UINT size)
{
	PPP_OPTION *o;
	// Validate arguments
	if (size != 0 && data == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(PPP_OPTION));

	o->Type = type;
	Copy(o->Data, data, size);
	o->DataSize = size;

	return o;
}

// Analyse the PPP packet
PPP_PACKET *ParsePPPPacket(void *data, UINT size)
{
	PPP_PACKET *pp;
	UCHAR *buf;
	// Validate arguments
	if (data == NULL || size == 0)
	{
		return NULL;
	}

	pp = ZeroMalloc(sizeof(PPP_PACKET));

	buf = (UCHAR *)data;

	// Address
	if (size < 1)
	{
		goto LABEL_ERROR;
	}
	if (buf[0] != 0xff)
	{
		goto LABEL_ERROR;
	}
	size--;
	buf++;

	// Control
	if (size < 1)
	{
		goto LABEL_ERROR;
	}
	if (buf[0] != 0x03)
	{
		goto LABEL_ERROR;
	}
	size--;
	buf++;

	// Protocol
	if (size < 2)
	{
		goto LABEL_ERROR;
	}
	pp->Protocol = READ_USHORT(buf);
	size -= 2;
	buf += 2;

	if (pp->Protocol == PPP_PROTOCOL_LCP || pp->Protocol == PPP_PROTOCOL_PAP || pp->Protocol == PPP_PROTOCOL_CHAP || pp->Protocol == PPP_PROTOCOL_IPCP)
	{
		pp->IsControl = true;
	}

	pp->Data = Clone(buf, size);
	pp->DataSize = size;

	if (pp->IsControl)
	{
		pp->Lcp = ParseLCP(pp->Protocol, pp->Data, pp->DataSize);
		if (pp->Lcp == NULL)
		{
			goto LABEL_ERROR;
		}
	}

	return pp;

LABEL_ERROR:
	FreePPPPacket(pp);
	return NULL;
}

// Build a PPP packet data
BUF *BuildPPPPacketData(PPP_PACKET *pp)
{
	BUF *ret;
	UCHAR c;
	USHORT us;
	// Validate arguments
	if (pp == NULL)
	{
		return NULL;
	}

	ret = NewBuf();

	// Address
	c = 0xff;
	WriteBuf(ret, &c, 1);

	// Control
	c = 0x03;
	WriteBuf(ret, &c, 1);

	// Protocol
	us = Endian16(pp->Protocol);
	WriteBuf(ret, &us, 2);

	if (pp->IsControl)
	{
		// LCP
		BUF *b = BuildLCPData(pp->Lcp);

		WriteBufBuf(ret, b);

		FreeBuf(b);
	}
	else
	{
		// Data
		WriteBuf(ret, pp->Data, pp->DataSize);
	}

	SeekBuf(ret, 0, 0);

	return ret;
}

// Build the LCP packet data
BUF *BuildLCPData(PPP_LCP *c)
{
	BUF *b;
	UCHAR zero = 0;
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	// Code
	WriteBuf(b, &c->Code, 1);

	// ID
	WriteBuf(b, &c->Id, 1);

	// Length (to be updated later)
	zero = 0;
	WriteBuf(b, &zero, 1);
	WriteBuf(b, &zero, 1);

	if (c->Data == NULL)
	{
		// Option List
		for (i = 0;i < LIST_NUM(c->OptionList);i++)
		{
			PPP_OPTION *o = LIST_DATA(c->OptionList, i);
			UCHAR sz = o->DataSize + 2;

			WriteBuf(b, &o->Type, 1);
			WriteBuf(b, &sz, 1);

			WriteBuf(b, o->Data, o->DataSize);
		}
	}
	else
	{
		// Data
		WriteBuf(b, c->Data, c->DataSize);
	}

	SeekBuf(b, 0, 0);

	// Update Length
	WRITE_USHORT(((UCHAR *)b->Buf) + 2, b->Size);

	return b;
}

// Analyse the LCP data
PPP_LCP *ParseLCP(USHORT protocol, void *data, UINT size)
{
	UCHAR *buf;
	PPP_LCP *c;
	USHORT len;
	bool has_option_list = false;
	// Validate arguments
	if (data == NULL || size == 0)
	{
		return NULL;
	}

	buf = (UCHAR *)data;
	c = ZeroMalloc(sizeof(PPP_LCP));

	c->OptionList = NewListFast(NULL);

	// Code
	if (size < 1)
	{
		goto LABEL_ERROR;
	}
	c->Code = buf[0];
	buf++;
	size--;

	// ID
	if (size < 1)
	{
		goto LABEL_ERROR;
	}
	c->Id = buf[0];
	buf++;
	size--;

	// Length
	if (size < 2)
	{
		goto LABEL_ERROR;
	}
	len = READ_USHORT(buf);
	if (len < 4)
	{
		goto LABEL_ERROR;
	}
	len -= 4;
	buf += 2;
	size -= 2;

	// Options or Data
	if (size < len)
	{
		goto LABEL_ERROR;
	}

	has_option_list = PPP_CODE_IS_WITH_OPTION_LIST(protocol, c->Code);

	if (has_option_list == false)
	{
		c->Data = Clone(buf, size);
		c->DataSize = size;
	}
	else
	{
		// Option List
		while (len >= 1)
		{
			PPP_OPTION o;

			Zero(&o, sizeof(o));

			// Type
			if (len < 1)
			{
				goto LABEL_ERROR;
			}
			o.Type = buf[0];
			buf++;
			len--;

			// Length
			if (len < 1)
			{
				goto LABEL_ERROR;
			}
			o.DataSize = buf[0];
			if (o.DataSize < 2)
			{
				goto LABEL_ERROR;
			}
			o.DataSize -= 2;
			buf++;
			len--;

			// Data
			if (len < o.DataSize)
			{
				goto LABEL_ERROR;
			}
			Copy(o.Data, buf, o.DataSize);
			buf += o.DataSize;
			len -= o.DataSize;

			Add(c->OptionList, Clone(&o, sizeof(o)));
		}
	}

	return c;

LABEL_ERROR:
	FreePPPLCP(c);
	return NULL;
}

// Release the PPP packet
void FreePPPPacket(PPP_PACKET *pp)
{
	FreePPPPacketEx(pp, false);
}
void FreePPPPacketEx(PPP_PACKET *pp, bool no_free_struct)
{
	// Validate arguments
	if (pp == NULL)
	{
		return;
	}

	FreePPPLCP(pp->Lcp);

	Free(pp->Data);

	if (no_free_struct == false)
	{
		Free(pp);
	}
}

// Release the PPP session
void FreePPPSession(PPP_SESSION *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->TubeRecv != NULL)
	{
		// Record the PPP disconnect reason code for L2TP
		p->TubeRecv->IntParam1 = p->DisconnectCauseCode;
		p->TubeRecv->IntParam2 = p->DisconnectCauseDirection;
	}

	FreeTubeFlushList(p->FlushList);

	TubeDisconnect(p->TubeRecv);
	TubeDisconnect(p->TubeSend);

	ReleaseCedar(p->Cedar);

	ReleaseTube(p->TubeRecv);
	ReleaseTube(p->TubeSend);

	PPPStoreLastPacket(p, NULL);

	if (p->Ipc != NULL)
	{
		FreeIPC(p->Ipc);
	}

	Free(p);
}

// Get the option value
PPP_OPTION *GetOptionValue(PPP_LCP *c, UCHAR type)
{
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(c->OptionList);i++)
	{
		PPP_OPTION *t = LIST_DATA(c->OptionList, i);

		if (t->Type == type)
		{
			return t;
		}
	}

	return NULL;
}

// Create the LCP
PPP_LCP *NewPPPLCP(UCHAR code, UCHAR id)
{
	PPP_LCP *c = ZeroMalloc(sizeof(PPP_LCP));

	c->Code = code;
	c->Id = id;
	c->OptionList = NewListFast(NULL);

	return c;
}

// Release the LCP
void FreePPPLCP(PPP_LCP *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	FreePPPOptionList(c->OptionList);

	Free(c->Data);

	Free(c);
}

// Release the PPP options list
void FreePPPOptionList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		PPP_OPTION *t = LIST_DATA(o, i);

		Free(t);
	}

	ReleaseList(o);
}

// Create a new PPP session
THREAD *NewPPPSession(CEDAR *cedar, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, TUBE *send_tube, TUBE *recv_tube, char *postfix, char *client_software_name, char *client_hostname, char *crypt_name, UINT adjust_mss)
{
	PPP_SESSION *p;
	THREAD *t;
	// Validate arguments
	if (cedar == NULL || client_ip == NULL || server_ip == NULL || send_tube == NULL || recv_tube == NULL)
	{
		return NULL;
	}
	if (IsEmptyStr(postfix))
	{
		postfix = "PPP";
	}
	if (IsEmptyStr(crypt_name))
	{
		crypt_name = "";
	}
	if (IsEmptyStr(client_software_name))
	{
		client_software_name = "PPP VPN Client";
	}

	// Data structure initialization
	p = ZeroMalloc(sizeof(PPP_SESSION));

	p->EnableMSCHAPv2 = true;
	p->AuthProtocol = PPP_PROTOCOL_PAP;
	p->MsChapV2_ErrorCode = 691;

	p->Cedar = cedar;
	AddRef(cedar->ref);

	p->AdjustMss = adjust_mss;

	StrCpy(p->CryptName, sizeof(p->CryptName), crypt_name);

	Copy(&p->ClientIP, client_ip, sizeof(IP));
	p->ClientPort = client_port;

	Copy(&p->ServerIP, server_ip, sizeof(IP));
	p->ServerPort = server_port;

	p->TubeRecv = recv_tube;
	p->TubeSend = send_tube;

	AddRef(p->TubeRecv->Ref);
	AddRef(p->TubeSend->Ref);

	StrCpy(p->Postfix, sizeof(p->Postfix), postfix);
	StrCpy(p->ClientSoftwareName, sizeof(p->ClientSoftwareName), client_software_name);

	if (IsEmptyStr(client_hostname))
	{
		IPToStr(p->ClientHostname, sizeof(p->ClientHostname), client_ip);
	}
	else
	{
		StrCpy(p->ClientHostname, sizeof(p->ClientHostname), client_hostname);
	}

	p->FlushList = NewTubeFlushList();

	// Thread creation
	t = NewThread(PPPThread, p);

	return t;
}

// Generate the NT hash of the password
void GenerateNtPasswordHash(UCHAR *dst, char *password)
{
	UCHAR *tmp;
	UINT tmp_size;
	UINT i, len;
	// Validate arguments
	if (dst == NULL || password == NULL)
	{
		return;
	}

	// Generate a Unicode password
	len = StrLen(password);
	tmp_size = len * 2;

	tmp = ZeroMalloc(tmp_size);

	for (i = 0;i < len;i++)
	{
		tmp[i * 2] = password[i];
	}

	// Hashing
	HashMd4(dst, tmp, tmp_size);

	Free(tmp);
}

// Generate the MS-CHAPv2 server-side challenge
void MsChapV2Server_GenerateChallenge(UCHAR *dst)
{
	// Validate arguments
	if (dst == NULL)
	{
		return;
	}

	Rand(dst, 16);
}

// Generate the MS-CHAPv2 client-side challenge
void MsChapV2Client_GenerateChallenge(UCHAR *dst)
{
	// Validate arguments
	if (dst == NULL)
	{
		return;
	}

	Rand(dst, 16);
}

// Generate a 8 bytes challenge
void MsChapV2_GenerateChallenge8(UCHAR *dst, UCHAR *client_challenge, UCHAR *server_challenge, char *username)
{
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	char username2[MAX_SIZE];
	char domainname2[MAX_SIZE];
	// Validate arguments
	if (dst == NULL || client_challenge == NULL || server_challenge == NULL)
	{
		return;
	}

	b = NewBuf();

	WriteBuf(b, client_challenge, 16);
	WriteBuf(b, server_challenge, 16);

	ParseNtUsername(username, username2, sizeof(username2), domainname2, sizeof(domainname2), true);

	if (IsEmptyStr(username2) == false)
	{
		WriteBuf(b, username2, StrLen(username2));
	}

	HashSha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Copy(dst, hash, 8);
}

// Generate the MS-CHAPv2 client response
void MsChapV2Client_GenerateResponse(UCHAR *dst, UCHAR *challenge8, UCHAR *nt_password_hash)
{
	UCHAR password_hash_2[21];
	UCHAR key1[8], key2[8], key3[8];
	// Validate arguments
	if (dst == NULL || challenge8 == NULL || nt_password_hash == NULL)
	{
		return;
	}

	Zero(password_hash_2, sizeof(password_hash_2));
	Copy(password_hash_2, nt_password_hash, 16);

	Zero(key1, sizeof(key1));
	Zero(key2, sizeof(key2));
	Zero(key3, sizeof(key3));

	Copy(key1, password_hash_2 + 0, 7);
	Copy(key2, password_hash_2 + 7, 7);
	Copy(key3, password_hash_2 + 14, 7);

	DesEcbEncrypt(dst + 0, challenge8, key1);
	DesEcbEncrypt(dst + 8, challenge8, key2);
	DesEcbEncrypt(dst + 16, challenge8, key3);
}

// Generate a hash of the hash of the NT password
void GenerateNtPasswordHashHash(UCHAR *dst_hash, UCHAR *src_hash)
{
	// Validate arguments
	if (dst_hash == NULL || src_hash == NULL)
	{
		return;
	}

	HashMd4(dst_hash, src_hash, 16);
}

// Generate the MS-CHAPv2 server response
void MsChapV2Server_GenerateResponse(UCHAR *dst, UCHAR *nt_password_hash_hash, UCHAR *client_response, UCHAR *challenge8)
{
	UCHAR digest[SHA1_SIZE];
	BUF *b;
	char *magic1 = "Magic server to client signing constant";
	char *magic2 = "Pad to make it do more than one iteration";
	// Validate arguments
	if (dst == NULL || nt_password_hash_hash == NULL || client_response == NULL || challenge8 == NULL)
	{
		return;
	}

	b = NewBuf();
	WriteBuf(b, nt_password_hash_hash, 16);
	WriteBuf(b, client_response, 24);
	WriteBuf(b, magic1, StrLen(magic1));
	HashSha1(digest, b->Buf, b->Size);
	FreeBuf(b);

	b = NewBuf();
	WriteBuf(b, digest, sizeof(digest));
	WriteBuf(b, challenge8, 8);
	WriteBuf(b, magic2, StrLen(magic2));
	HashSha1(dst, b->Buf, b->Size);
	FreeBuf(b);
}

// Verify whether the password matches one that is specified by the user in the MS-CHAPv2
bool MsChapV2VerityPassword(IPC_MSCHAP_V2_AUTHINFO *d, char *password)
{
	UCHAR ntlm_hash[MD5_SIZE];
	UCHAR challenge8[8];
	UCHAR client_response[24];
	// Validate arguments
	if (d == NULL || password == NULL)
	{
		return false;
	}

	GenerateNtPasswordHash(ntlm_hash, password);
	MsChapV2_GenerateChallenge8(challenge8, d->MsChapV2_ClientChallenge, d->MsChapV2_ServerChallenge, d->MsChapV2_PPPUsername);
	MsChapV2Client_GenerateResponse(client_response, challenge8, ntlm_hash);

	if (Cmp(client_response, d->MsChapV2_ClientResponse, 24) != 0)
	{
		return false;
	}

	return true;
}

// Estimate the password in the brute force for the request packet of MS-CHAPv2
char *MsChapV2DoBruteForce(IPC_MSCHAP_V2_AUTHINFO *d, LIST *password_list)
{
	UINT i;
	// Validate arguments
	if (d == NULL || password_list == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(password_list);i++)
	{
		char *s = LIST_DATA(password_list, i);
		char tmp[MAX_SIZE];
		UINT j, max;
		UINT len;

		StrCpy(tmp, sizeof(tmp), s);

		len = StrLen(tmp);
		max = Power(2, MIN(len, 9));

		for (j = 0;j < max;j++)
		{
			SetStrCaseAccordingToBits(tmp, j);
			if (MsChapV2VerityPassword(d, tmp))
			{
				return CopyStr(tmp);
			}
		}
	}

	return NULL;
}




// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
