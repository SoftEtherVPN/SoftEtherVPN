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


// Interop_OpenVPN.c
// OpenVPN protocol stack

#include "CedarPch.h"


static bool g_no_openvpn_tcp = false;
static bool g_no_openvpn_udp = false;

// Ping signature of the OpenVPN protocol
static UCHAR ping_signature[] =
{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

// Set the OpenVPN over TCP disabling flag
void OvsSetNoOpenVpnTcp(bool b)
{
	g_no_openvpn_tcp = b;
}

// Get the OpenVPN over TCP disabling flag
bool OvsGetNoOpenVpnTcp()
{
	return g_no_openvpn_tcp;
}

// Set the OpenVPN over UDP disabling flag
void OvsSetNoOpenVpnUdp(bool b)
{
	g_no_openvpn_udp = b;
}

// Get the OpenVPN over UDP disabling flag
bool OvsGetNoOpenVpnUdp()
{
	return g_no_openvpn_udp;
}


// Write the OpenVPN log
void OvsLog(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c, char *name, ...)
{
	wchar_t prefix[MAX_SIZE * 2];
	wchar_t buf2[MAX_SIZE * 2];
	va_list args;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}
	if (se == NULL)
	{
		UniStrCpy(prefix, sizeof(prefix), _UU("LO_PREFIX_RAW"));
	}
	else
	{
		if (c == NULL)
		{
			UniFormat(prefix, sizeof(prefix), _UU("LO_PREFIX_SESSION"),
				se->Id, &se->ClientIp, se->ClientPort, &se->ServerIp, se->ServerPort);
		}
		else
		{
			UniFormat(prefix, sizeof(prefix), _UU("LO_PREFIX_CHANNEL"),
				se->Id, &se->ClientIp, se->ClientPort, &se->ServerIp, se->ServerPort,
				c->KeyId);
		}
	}
	va_start(args, name);
	UniFormatArgs(buf2, sizeof(buf2), _UU(name), args);
	va_end(args);

	UniStrCat(prefix, sizeof(prefix), buf2);

	WriteServerLog(s->Cedar, prefix);
}

// Process the received packet
void OvsProceccRecvPacket(OPENVPN_SERVER *s, UDPPACKET *p, UINT protocol)
{
	OPENVPN_SESSION *se;
	OPENVPN_PACKET *recv_packet;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}


	// Search for the session
	se = OvsFindOrCreateSession(s, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort, protocol);
	if (se == NULL)
	{
		return;
	}

	// Parse the packet
	recv_packet = OvsParsePacket(p->Data, p->Size);

	if (recv_packet != NULL)
	{
		OPENVPN_CHANNEL *c = NULL;
		if (recv_packet->OpCode != OPENVPN_P_DATA_V1 && recv_packet->MySessionId != 0)
		{
			Debug("RECV PACKET: %u %I64u\n", recv_packet->KeyId, recv_packet->MySessionId);
		}
		if (recv_packet->OpCode != OPENVPN_P_DATA_V1)
		{
			Debug("   PKT %u %u\n", recv_packet->OpCode, recv_packet->KeyId);
		}

		if (recv_packet->OpCode != OPENVPN_P_DATA_V1)
		{
			// Control packet
			if (recv_packet->OpCode == OPENVPN_P_CONTROL_HARD_RESET_CLIENT_V2 ||
				recv_packet->OpCode == OPENVPN_P_CONTROL_SOFT_RESET_V1)
			{
				// Connection request packet
				if (se->Channels[recv_packet->KeyId] != NULL)
				{
					// Release when there is a channel data already
					OvsFreeChannel(se->Channels[recv_packet->KeyId]);
					se->Channels[recv_packet->KeyId] = NULL;
				}

				// Create a new channel
				c = OvsNewChannel(se, recv_packet->KeyId);
				if (se->ClientSessionId == 0)
				{
					se->ClientSessionId = recv_packet->MySessionId;
				}
				se->Channels[recv_packet->KeyId] = c;
				Debug("OpenVPN New Channel :%u\n", recv_packet->KeyId);
				OvsLog(s, se, c, "LO_NEW_CHANNEL");
			}
/*			else if (recv_packet->OpCode == OPENVPN_P_CONTROL_SOFT_RESET_V1)
			{
				// Response to soft reset request packet
				OPENVPN_PACKET *p;

				p = OvsNewControlPacket(OPENVPN_P_CONTROL_SOFT_RESET_V1, recv_packet->KeyId, se->ServerSessionId,
					0, NULL, 0, 0, 0, NULL);

				OvsSendPacketNow(s, se, p);

				OvsFreePacket(p);
			}*/
			else
			{
				// Packet other than the connection request
				if (se->Channels[recv_packet->KeyId] != NULL)
				{
					c = se->Channels[recv_packet->KeyId];
				}
			}

			if (c != NULL)
			{
				// Delete the send packet list by looking the packet ID in the ACK list of arrived packet
				OvsDeleteFromSendingControlPacketList(c, recv_packet->NumAck, recv_packet->AckPacketId);

				if (recv_packet->OpCode != OPENVPN_P_ACK_V1)
				{
					// Add the Packet ID of arrived packet to the list
					InsertIntDistinct(c->AckReplyList, recv_packet->PacketId);
					Debug("Recv Packet ID (c=%u): %u\n", c->KeyId, recv_packet->PacketId);

					if ((recv_packet->PacketId > c->MaxRecvPacketId)
						|| (recv_packet->OpCode == OPENVPN_P_CONTROL_HARD_RESET_CLIENT_V2)
						|| (recv_packet->OpCode == OPENVPN_P_CONTROL_SOFT_RESET_V1))
					{
						c->MaxRecvPacketId = recv_packet->PacketId;

						// Process the received control packet
						OvsProcessRecvControlPacket(s, se, c, recv_packet);
					}
				}
			}
		}
		else
		{
			// Data packet
			if (se->Channels[recv_packet->KeyId] != NULL)
			{
				OPENVPN_CHANNEL *c = se->Channels[recv_packet->KeyId];
				if (c->Status == OPENVPN_CHANNEL_STATUS_ESTABLISHED)
				{
					UCHAR *data;
					UINT size;

					data = recv_packet->Data;
					size = recv_packet->DataSize;

					if (size >= (c->MdRecv->Size + c->CipherDecrypt->IvSize + sizeof(UINT)))
					{
						UCHAR *hmac;
						UCHAR *iv;
						UCHAR hmac_test[128];

						// HMAC
						hmac = data;
						data += c->MdRecv->Size;
						size -= c->MdRecv->Size;

						// Confirmation of HMAC
						MdProcess(c->MdRecv, hmac_test, data, size);
						if (Cmp(hmac_test, hmac, c->MdRecv->Size) == 0)
						{
							// Update of last communication time
							se->LastCommTick = s->Now;

							// IV
							iv = data;
							data += c->CipherDecrypt->IvSize;
							size -= c->CipherDecrypt->IvSize;

							// Payload
							if (size >= 1 && (c->CipherDecrypt->BlockSize == 0 || (size % c->CipherDecrypt->BlockSize) == 0))
							{
								UINT data_packet_id;

								// Decryption
								size = CipherProcess(c->CipherDecrypt, iv, s->TmpBuf, data, size);

								data = s->TmpBuf;

								if (size >= sizeof(UINT))
								{
									data_packet_id = READ_UINT(data);

									data += sizeof(UINT);
									size -= sizeof(UINT);

									if (size >= sizeof(ping_signature) &&
										Cmp(data, ping_signature, sizeof(ping_signature)) == 0)
									{
										// Ignore since a ping packet has been received
										DoNothing();
									}
									else
									{
										// Receive a packet!!
										if (se->Ipc != NULL)
										{
											switch (se->Mode)
											{
											case OPENVPN_MODE_L2:	// Send an Ethernet packet to a session
												IPCSendL2(se->Ipc, data, size);
												break;

											case OPENVPN_MODE_L3:	// Send an IPv4 packet to a session
												IPCSendIPv4(se->Ipc, data, size);
												break;
											}
										}
									}
								}
							}
						}
						else
						{
//							Debug("HMAC Failed (c=%u)\n", c->KeyId);
						}
					}
				}
			}
		}

		OvsFreePacket(recv_packet);
	}
}

// Remove a packet which the opponent has received from the transmission list
void OvsDeleteFromSendingControlPacketList(OPENVPN_CHANNEL *c, UINT num_acks, UINT *acks)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (c == NULL || num_acks == 0)
	{
		return;
	}

	o = NewListFast(NULL);
	for (i = 0;i < num_acks;i++)
	{
		UINT ack = acks[i];
		UINT j;

		for (j = 0;j < LIST_NUM(c->SendControlPacketList);j++)
		{
			OPENVPN_CONTROL_PACKET *p = LIST_DATA(c->SendControlPacketList, j);

			if (p->PacketId == ack)
			{
				AddDistinct(o, p);
			}
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		OPENVPN_CONTROL_PACKET *p = LIST_DATA(o, i);

		Delete(c->SendControlPacketList, p);

		OvsFreeControlPacket(p);
	}

	ReleaseList(o);
}

// Process the received control packet
void OvsProcessRecvControlPacket(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c, OPENVPN_PACKET *p)
{
	FIFO *recv_fifo = NULL;
	FIFO *send_fifo = NULL;
	// Validate arguments
	if (s == NULL || se == NULL || c == NULL || p == NULL)
	{
		return;
	}

	if (p->OpCode == OPENVPN_P_CONTROL_V1)
	{
		Debug("SSL (c=%u): %u\n", c->KeyId, p->DataSize);

		if (c->SslPipe == NULL)
		{
			// Create an SSL pipe
			Lock(s->Cedar->lock);
			{
				c->SslPipe = NewSslPipe(true, s->Cedar->ServerX, s->Cedar->ServerK, s->Dh);
			}
			Unlock(s->Cedar->lock);

			Debug("SSL Pipe Created (c=%u).\n", c->KeyId);
		}

		if (c->SslPipe->IsDisconnected == false)
		{
			// Pour the physically received data into SSL pipe
			if (FifoSize(c->SslPipe->RawIn->SendFifo) < OPENVPN_MAX_SSL_RECV_BUF_SIZE)
			{
				Debug("SSL_Write: %u\n", p->DataSize);
				WriteFifo(c->SslPipe->RawIn->SendFifo, p->Data, p->DataSize);
			}
			SyncSslPipe(c->SslPipe);
		}
	}

	if (c->SslPipe != NULL && c->SslPipe->IsDisconnected == false)
	{
		recv_fifo = c->SslPipe->SslInOut->RecvFifo;
		send_fifo = c->SslPipe->SslInOut->SendFifo;
	}

	Debug("SIZE: recv_fifo = %u, send_fifo = %u\n", FifoSize(recv_fifo), FifoSize(send_fifo));

	switch (c->Status)
	{
	case OPENVPN_CHANNEL_STATUS_INIT:
		switch (p->OpCode)
		{
		case OPENVPN_P_CONTROL_SOFT_RESET_V1:
			// Key update (soft reset)
			if (se->Established)
			{
				if (c->IsInitiatorServer == false)
				{
					OvsSendControlPacket(c, OPENVPN_P_CONTROL_SOFT_RESET_V1, NULL, 0);
				}

				c->Status = OPENVPN_CHANNEL_STATUS_TLS_WAIT_CLIENT_KEY;
				c->IsRekeyChannel = true;
			}
			break;

		case OPENVPN_P_CONTROL_HARD_RESET_CLIENT_V2:
			// New connection (hard reset)
			OvsSendControlPacket(c, OPENVPN_P_CONTROL_HARD_RESET_SERVER_V2, NULL, 0);

			c->Status = OPENVPN_CHANNEL_STATUS_TLS_WAIT_CLIENT_KEY;
			break;
		}
		break;

	case OPENVPN_CHANNEL_STATUS_TLS_WAIT_CLIENT_KEY:
		if (FifoSize(recv_fifo) >= 1)
		{
			OPENVPN_KEY_METHOD_2 data;
			UCHAR *ptr = FifoPtr(recv_fifo);

			// Parse OPENVPN_KEY_METHOD_2
			UINT read_size = OvsParseKeyMethod2(&data, ptr, FifoSize(recv_fifo), true);
			if (read_size != 0)
			{
				BUF *b;

				// Success in parsing key information
				ReadFifo(recv_fifo, NULL, read_size);

				// Set session parameters
				OvsSetupSessionParameters(s, se, c, &data);

				// Build OPENVPN_KEY_METHOD_2 to respond
				b = OvsBuildKeyMethod2(&c->ServerKey);

				// Transmission of the response data
				if (b != NULL)
				{
					WriteFifo(send_fifo, b->Buf, b->Size);

					FreeBuf(b);
				}

				// State transition
				c->Status = OPENVPN_CHANNEL_STATUS_TLS_WAIT_CLIENT_PUSH_REQUEST;
				if (c->IsRekeyChannel)
				{
					c->Status = OPENVPN_CHANNEL_STATUS_ESTABLISHED;
					c->EstablishedTick = s->Now;
					Debug("OpenVPN Channel %u Established (re-key).\n", c->KeyId);
					OvsLog(s, se, c, "LO_CHANNEL_ESTABLISHED_NEWKEY");
				}
			}
		}
		break;

	case OPENVPN_CHANNEL_STATUS_TLS_WAIT_CLIENT_PUSH_REQUEST:
		if (FifoSize(recv_fifo) >= 1)
		{
			char tmp[MAX_SIZE];
			UINT read_size = OvsPeekStringFromFifo(recv_fifo, tmp, sizeof(tmp));

			if (read_size >= 1)
			{
				Debug("Client->Server (c=%u): %s\n", c->KeyId, tmp);

				ReadFifo(recv_fifo, NULL, read_size);

				if (StartWith(tmp, "PUSH_REQUEST"))
				{
					// Since connection requested, start VPN connection
					// When the IPC VPN connection has not been started yet, start it
					OvsBeginIPCAsyncConnectionIfEmpty(s, se, c);

					// State transition
					c->Status = OPENVPN_CHANNEL_STATUS_TLS_VPN_CONNECTING;
				}
			}
		}
		break;

	case OPENVPN_CHANNEL_STATUS_TLS_VPN_CONNECTING:
	case OPENVPN_CHANNEL_STATUS_ESTABLISHED:
		if (FifoSize(recv_fifo) >= 1)
		{
			char tmp[MAX_SIZE];
			UINT read_size = OvsPeekStringFromFifo(recv_fifo, tmp, sizeof(tmp));

			if (read_size >= 1)
			{
				Debug("Client->Server (c=%u): %s\n", c->KeyId, tmp);

				ReadFifo(recv_fifo, NULL, read_size);

				if (StartWith(tmp, "PUSH_REQUEST"))
				{
					WriteFifo(send_fifo, se->PushReplyStr, StrLen(se->PushReplyStr));
				}
			}
		}
		break;
	}
}

// Calculate the proper MSS
UINT OvsCalcTcpMss(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c)
{
	UINT ret = MTU_FOR_PPPOE;
	// Validate arguments
	if (s == NULL || se == NULL || c == NULL)
	{
		return 0;
	}

	if (c->MdSend == NULL || c->CipherEncrypt == NULL)
	{
		return 0;
	}

	if (se->Protocol == OPENVPN_PROTOCOL_TCP)
	{
		// Calculation is not required for TCP mode
		return 0;
	}

	// IPv4 / IPv6
	if (IsIP4(&se->ClientIp))
	{
		ret -= 20;
	}
	else
	{
		ret -= 40;
	}

	// UDP
	ret -= 8;

	// opcode
	ret -= 1;

	// HMAC
	ret -= c->MdSend->Size;

	// IV
	ret -= c->CipherEncrypt->IvSize;

	// Packet ID
	ret -= 4;

	if (c->CipherEncrypt->IsNullCipher == false)
	{
		// block
		ret -= c->CipherEncrypt->BlockSize;
	}

	if (se->Mode == OPENVPN_MODE_L2)
	{
		// Inner Ethernet Header
		ret -= 14;
	}

	// Inner IPv4
	ret -= 20;

	// Inner TCP
	ret -= 20;

	return ret;
}

// When the IPC VPN connection has not been started yet, start it
void OvsBeginIPCAsyncConnectionIfEmpty(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c)
{
	// Validate arguments
	if (s == NULL || se == NULL || c == NULL)
	{
		return;
	}

	if (IsIPCConnected(se->Ipc) == false)
	{
		FreeIPC(se->Ipc);

		se->Ipc = NULL;
	}

	if (se->IpcAsync == NULL)
	{
		IPC_PARAM p;
		ETHERIP_ID id;

		Zero(&p, sizeof(p));
		Zero(&id, sizeof(id));

		// Parse the user name
		PPPParseUsername(s->Cedar, c->ClientKey.Username, &id);


		// Build IPC connection parameters
		StrCpy(p.ClientName, sizeof(p.ClientName), OPENVPN_IPC_CLIENT_NAME);
		StrCpy(p.Postfix, sizeof(p.Postfix), (se->Mode == OPENVPN_MODE_L3 ? OPENVPN_IPC_POSTFIX_L3 : OPENVPN_IPC_POSTFIX_L2));

		StrCpy(p.UserName, sizeof(p.UserName), id.UserName);
		StrCpy(p.HubName, sizeof(p.HubName), id.HubName);
		StrCpy(p.Password, sizeof(p.Password), c->ClientKey.Password);

		Copy(&p.ClientIp, &se->ClientIp, sizeof(IP));
		p.ClientPort = se->ClientPort;

		Copy(&p.ServerIp, &se->ServerIp, sizeof(IP));
		p.ServerPort = se->ServerPort;

		if (c->CipherEncrypt->IsNullCipher == false)
		{
			StrCpy(p.CryptName, sizeof(p.CryptName), c->CipherEncrypt->Name);
		}

		if (se->Mode == OPENVPN_MODE_L3)
		{
			// L3 Mode
			p.IsL3Mode = true;
		}
		else
		{
			// L2 Mode
			p.BridgeMode = true;
		}

		p.IsOpenVPN = true;

		// Calculate the MSS
		p.Mss = OvsCalcTcpMss(s, se, c);
		Debug("MSS=%u\n", p.Mss);

		// Start an IPC connection
		se->IpcAsync = NewIPCAsync(s->Cedar, &p, s->SockEvent);
	}
}

// Peek a NULL-terminated string from the FIFO
UINT OvsPeekStringFromFifo(FIFO *f, char *str, UINT str_size)
{
	UINT i;
	bool ok = false;
	// Validate arguments
	if (f == NULL || str == NULL || str_size == 0)
	{
		return 0;
	}

	StrCpy(str, str_size, "");

	for (i = 0;i < MIN(str_size, FifoSize(f));i++)
	{
		char c = *(((char *)FifoPtr(f)) + i);

		if (c != 0)
		{
			str[i] = c;
		}
		else
		{
			str[i] = 0;
			i++;
			ok = true;
			break;
		}
	}

	if (ok == false)
	{
		return 0;
	}

	return i;
}

// Set session parameters
void OvsSetupSessionParameters(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_CHANNEL *c, OPENVPN_KEY_METHOD_2 *data)
{
	LIST *o;
	BUF *b;
	char opt_str[MAX_SIZE];
	// Validate arguments
	if (s == NULL || se == NULL || c == NULL || data == NULL)
	{
		return;
	}

	Copy(&c->ClientKey, data, sizeof(OPENVPN_KEY_METHOD_2));

	// Parse the parameter string
	Debug("Parsing Option Str: %s\n", data->OptionString);

	OvsLog(s, se, c, "LO_OPTION_STR_RECV", data->OptionString);

	Zero(opt_str, sizeof(opt_str));
	StrCpy(opt_str, sizeof(opt_str), data->OptionString);
	if (s->Cedar != NULL && (IsEmptyStr(opt_str) || StartWith(opt_str, "V0 UNDEF") || InStr(opt_str, ",") == false))
	{
		StrCpy(opt_str, sizeof(opt_str), s->Cedar->OpenVPNDefaultClientOption);
	}

	o = OvsParseOptions(opt_str);

	if (se->Mode == OPENVPN_MODE_UNKNOWN)
	{
		UINT mtu;
		// Layer
		if (StrCmpi(IniStrValue(o, "dev-type"), "tun") == 0)
		{
			// L3
			se->Mode = OPENVPN_MODE_L3;
		}
		else
		{
			// L2
			se->Mode = OPENVPN_MODE_L2;
		}

		// Link MTU
		mtu = IniIntValue(o, "link-mtu");
		if (mtu == 0)
		{
			mtu = OPENVPN_MTU_LINK;
		}
		se->LinkMtu = mtu;

		// Tun MTU
		mtu = IniIntValue(o, "tun-mtu");
		if (mtu == 0)
		{
			mtu = OPENVPN_MTU_TUN;
		}
		se->TunMtu = mtu;
	}

	// Protocol
	if (se->Protocol == OPENVPN_PROTOCOL_TCP)
	{
		// TCP
		// UDP
		if (IsIP6(&se->ClientIp) == false)
		{
			StrCpy(c->Proto, sizeof(c->Proto), "TCPv4_SERVER");
		}
		else
		{
			StrCpy(c->Proto, sizeof(c->Proto), "TCPv6_SERVER");
		}
	}
	else
	{
		// UDP
		if (IsIP6(&se->ClientIp) == false)
		{
			StrCpy(c->Proto, sizeof(c->Proto), "UDPv4");
		}
		else
		{
			StrCpy(c->Proto, sizeof(c->Proto), "UDPv6");
		}
	}

	// Encryption algorithm
	c->CipherEncrypt = OvsGetCipher(IniStrValue(o, "cipher"));
	c->CipherDecrypt = NewCipher(c->CipherEncrypt->Name);

	// Hash algorithm
	c->MdSend = OvsGetMd(IniStrValue(o, "auth"));
	c->MdRecv = NewMd(c->MdSend->Name);

	// Random number generation
	Rand(c->ServerKey.Random1, sizeof(c->ServerKey.Random1));
	Rand(c->ServerKey.Random2, sizeof(c->ServerKey.Random2));

	// Generate the Master Secret
	b = NewBuf();
	WriteBuf(b, OPENVPN_PREMASTER_LABEL, StrLen(OPENVPN_PREMASTER_LABEL));
	WriteBuf(b, c->ClientKey.Random1, sizeof(c->ClientKey.Random1));
	WriteBuf(b, c->ServerKey.Random1, sizeof(c->ServerKey.Random1));
	Enc_tls1_PRF(b->Buf, b->Size,
		c->ClientKey.PreMasterSecret, sizeof(c->ClientKey.PreMasterSecret),
		c->MasterSecret, sizeof(c->MasterSecret));
	FreeBuf(b);

	// Generate an Expansion Key
	b = NewBuf();
	WriteBuf(b, OPENVPN_EXPANSION_LABEL, StrLen(OPENVPN_EXPANSION_LABEL));
	WriteBuf(b, c->ClientKey.Random2, sizeof(c->ClientKey.Random2));
	WriteBuf(b, c->ServerKey.Random2, sizeof(c->ServerKey.Random2));
	WriteBufInt64(b, se->ClientSessionId);
	WriteBufInt64(b, se->ServerSessionId);
	Enc_tls1_PRF(b->Buf, b->Size, c->MasterSecret, sizeof(c->MasterSecret),
		c->ExpansionKey, sizeof(c->ExpansionKey));
	FreeBuf(b);

	// Set the key
	SetCipherKey(c->CipherDecrypt, c->ExpansionKey + 0, false);
	SetCipherKey(c->CipherEncrypt, c->ExpansionKey + 128, true);
	SetMdKey(c->MdRecv, c->ExpansionKey + 64, c->MdRecv->Size);
	SetMdKey(c->MdSend, c->ExpansionKey + 192, c->MdSend->Size);

	OvsFreeOptions(o);

	// Generate the response option string
	Format(c->ServerKey.OptionString, sizeof(c->ServerKey.OptionString),
		"V4,dev-type %s,link-mtu %u,tun-mtu %u,proto %s,"
		"cipher %s,auth %s,keysize %u,key-method 2,tls-server",
		(se->Mode == OPENVPN_MODE_L2 ? "tap" : "tun"),
		se->LinkMtu,
		se->TunMtu,
		c->Proto,
		c->CipherEncrypt->Name, c->MdSend->Name, c->CipherEncrypt->KeySize * 8);
	Debug("Building OptionStr: %s\n", c->ServerKey.OptionString);

	OvsLog(s, se, c, "LO_OPTION_STR_SEND", c->ServerKey.OptionString);
}

// Get the encryption algorithm
CIPHER *OvsGetCipher(char *name)
{
	CIPHER *c = NULL;

	if (IsEmptyStr(name) == false && IsStrInStrTokenList(OPENVPN_CIPHER_LIST, name, NULL, false))
	{
		c = NewCipher(name);
	}

	if (c == NULL)
	{
		c = NewCipher(OPENVPN_DEFAULT_CIPHER);
	}

	return c;
}

// Get the hash algorithm
MD *OvsGetMd(char *name)
{
	MD *m = NULL;

	if (IsEmptyStr(name) == false && IsStrInStrTokenList(OPENVPN_MD_LIST, name, NULL, false))
	{
		m = NewMd(name);
	}

	if (m == NULL)
	{
		m = NewMd(OPENVPN_DEFAULT_MD);
	}

	return m;
}

// Parse the option string
LIST *OvsParseOptions(char *str)
{
	LIST *o = NewListFast(NULL);
	TOKEN_LIST *t;

	t = ParseTokenWithoutNullStr(str, ",");
	if (t != NULL)
	{
		UINT i;

		for (i = 0;i < t->NumTokens;i++)
		{
			char key[MAX_SIZE];
			char value[MAX_SIZE];
			char *line = t->Token[i];
			Trim(line);

			if (GetKeyAndValue(line, key, sizeof(key), value, sizeof(value), " \t"))
			{
				INI_ENTRY *e = ZeroMalloc(sizeof(INI_ENTRY));

				e->Key = CopyStr(key);
				e->Value = CopyStr(value);

				Add(o, e);
			}
		}

		FreeToken(t);
	}

	return o;
}

// Release the option list
void OvsFreeOptions(LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	FreeIni(o);
}

// Create an Option List
LIST *OvsNewOptions()
{
	return NewListFast(NULL);
}

// Add a value to the option list
void OvsAddOption(LIST *o, char *key, char *value)
{
	INI_ENTRY *e;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	e = GetIniEntry(o, key);
	if (e != NULL)
	{
		// Overwrite existing keys
		Free(e->Key);
		e->Key = CopyStr(key);

		Free(e->Value);
		e->Value = CopyStr(value);
	}
	else
	{
		// Create a new key
		e = ZeroMalloc(sizeof(INI_ENTRY));

		e->Key = CopyStr(key);
		e->Value = CopyStr(value);

		Add(o, e);
	}
}

// Confirm whether there is specified option key string
bool OvsHasOption(LIST *o, char *key)
{
	// Validate arguments
	if (o == NULL || key == NULL)
	{
		return false;
	}

	if (GetIniEntry(o, key) != NULL)
	{
		return true;
	}

	return false;
}

// Build the data from KEY_METHOD2
BUF *OvsBuildKeyMethod2(OPENVPN_KEY_METHOD_2 *d)
{
	BUF *b;
	UCHAR uc;
	// Validate arguments
	if (d == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	// Reserved
	WriteBufInt(b, 0);

	// Method
	uc = 2;
	WriteBuf(b, &uc, sizeof(UCHAR));

	// Random1
	WriteBuf(b, d->Random1, sizeof(d->Random1));

	// Random2
	WriteBuf(b, d->Random2, sizeof(d->Random2));

	// Option String
	OvsWriteStringToBuf(b, d->OptionString, sizeof(d->OptionString));

	// Username
	OvsWriteStringToBuf(b, d->Username, sizeof(d->Username));

	// Password
	OvsWriteStringToBuf(b, d->Password, sizeof(d->Password));

	// PeerInfo
	OvsWriteStringToBuf(b, d->PeerInfo, sizeof(d->PeerInfo));

	return b;
}

// Append a string to buf
void OvsWriteStringToBuf(BUF *b, char *str, UINT max_size)
{
	USHORT us;
	UINT i;
	char *tmp;
	// Validate arguments
	if (b == NULL)
	{
		return;
	}
	if (str == NULL)
	{
		str = "";
	}

	if (StrLen(str) == 0)
	{
		us = 0;
		WriteBuf(b, &us, sizeof(USHORT));
		return;
	}

	i = StrSize(str);
	i = MIN(i, max_size);
	us = Endian16((USHORT)i);
	WriteBuf(b, &us, sizeof(USHORT));

	tmp = Malloc(i);
	Copy(tmp, str, i);
	tmp[i - 1] = 0;
	WriteBuf(b, tmp, i);

	Free(tmp);
}

// Parse the KEY_METHOD2
UINT OvsParseKeyMethod2(OPENVPN_KEY_METHOD_2 *ret, UCHAR *data, UINT size, bool client_mode)
{
	BUF *b;
	UINT read_size = 0;
	UINT ui;
	UCHAR uc;
	// Validate arguments
	Zero(ret, sizeof(OPENVPN_KEY_METHOD_2));
	if (ret == NULL || data == NULL || size == 0)
	{
		return 0;
	}

	b = NewBuf();
	WriteBuf(b, data, size);
	SeekBuf(b, 0, 0);

	// Reserved
	if (ReadBuf(b, &ui, sizeof(UINT)) == sizeof(UINT))
	{
		// Method
		if (ReadBuf(b, &uc, sizeof(UCHAR)) == sizeof(UCHAR) && uc == 2)
		{
			// Pre Master Secret
			if (client_mode == false || ReadBuf(b, ret->PreMasterSecret, sizeof(ret->PreMasterSecret)) == sizeof(ret->PreMasterSecret))
			{
				// Random1
				if (ReadBuf(b, ret->Random1, sizeof(ret->Random1)) == sizeof(ret->Random1))
				{
					// Random2
					if (ReadBuf(b, ret->Random2, sizeof(ret->Random2)) == sizeof(ret->Random2))
					{
						// String
						if (OvsReadStringFromBuf(b, ret->OptionString, sizeof(ret->OptionString)) &&
							OvsReadStringFromBuf(b, ret->Username, sizeof(ret->Username)) &&
							OvsReadStringFromBuf(b, ret->Password, sizeof(ret->Password)) &&
							OvsReadStringFromBuf(b, ret->PeerInfo, sizeof(ret->PeerInfo)))
						{
							read_size = b->Current;
						}
					}
				}
			}
		}
	}

	FreeBuf(b);

	return read_size;
}

// Read a string from BUF
bool OvsReadStringFromBuf(BUF *b, char *str, UINT str_size)
{
	USHORT us;
	// Validate arguments
	if (b == NULL || str == NULL)
	{
		return false;
	}

	if (ReadBuf(b, &us, sizeof(USHORT)) != sizeof(USHORT))
	{
		return false;
	}

	us = Endian16(us);

	if (us == 0)
	{
		StrCpy(str, str_size, "");
		return true;
	}

	if (us > str_size)
	{
		return false;
	}

	if (ReadBuf(b, str, us) != us)
	{
		return false;
	}

	if (str[us - 1] != 0)
	{
		return false;
	}

	return true;
}

// Transmission of control packet (Automatic segmentation with the maximum size)
void OvsSendControlPacketWithAutoSplit(OPENVPN_CHANNEL *c, UCHAR opcode, UCHAR *data, UINT data_size)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || (data_size != 0 && data == NULL))
	{
		return;
	}

	b = NewBuf();
	WriteBuf(b, data, data_size);
	SeekBuf(b, 0, 0);

	while (true)
	{
		UCHAR tmp[OPENVPN_CONTROL_PACKET_MAX_DATASIZE];
		UINT size = ReadBuf(b, tmp, sizeof(tmp));

		if (size == 0)
		{
			break;
		}

		OvsSendControlPacket(c, opcode, tmp, size);
		//Debug(" *** CNT SEND %u\n", size);
	}

	FreeBuf(b);
}

// Send the control packet
void OvsSendControlPacket(OPENVPN_CHANNEL *c, UCHAR opcode, UCHAR *data, UINT data_size)
{
	OPENVPN_CONTROL_PACKET *p;
	// Validate arguments
	if (c == NULL || (data_size != 0 && data == NULL))
	{
		return;
	}

	p = ZeroMalloc(sizeof(OPENVPN_CONTROL_PACKET));

	p->OpCode = opcode;
	p->PacketId = c->NextSendPacketId++;

	if (data != NULL)
	{
		p->Data = Clone(data, data_size);
		p->DataSize = data_size;
	}

	p->NextSendTime = 0;

	Add(c->SendControlPacketList, p);
}

// Release the control packet being transmitted
void OvsFreeControlPacket(OPENVPN_CONTROL_PACKET *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->Data != NULL)
	{
		Free(p->Data);
	}

	Free(p);
}

// Get a list of packet ID to be responded
UINT OvsGetAckReplyList(OPENVPN_CHANNEL *c, UINT *ret)
{
	UINT i;
	LIST *o = NULL;
	UINT num;
	// Validate arguments
	if (c == NULL || ret == NULL)
	{
		return 0;
	}

	num = MIN(LIST_NUM(c->AckReplyList), OPENVPN_MAX_NUMACK);

	for (i = 0;i < num;i++)
	{
		UINT *v = LIST_DATA(c->AckReplyList, i);

		if (o == NULL)
		{
			o = NewListFast(NULL);
		}

		Add(o, v);

		ret[i] = *v;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT *v = LIST_DATA(o, i);

		Delete(c->AckReplyList, v);

		Free(v);
	}

	ReleaseList(o);

	return num;
}

// Release the channel
void OvsFreeChannel(OPENVPN_CHANNEL *c)
{
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (c->SslPipe != NULL)
	{
		FreeSslPipe(c->SslPipe);
	}

	ReleaseIntList(c->AckReplyList);

	for (i = 0;i < LIST_NUM(c->SendControlPacketList);i++)
	{
		OPENVPN_CONTROL_PACKET *p = LIST_DATA(c->SendControlPacketList, i);

		OvsFreeControlPacket(p);
	}

	ReleaseList(c->SendControlPacketList);

	FreeCipher(c->CipherDecrypt);
	FreeCipher(c->CipherEncrypt);

	FreeMd(c->MdRecv);
	FreeMd(c->MdSend);

	Free(c);
}

// Create a new channel
OPENVPN_CHANNEL *OvsNewChannel(OPENVPN_SESSION *se, UCHAR key_id)
{
	OPENVPN_CHANNEL *c;
	// Validate arguments
	if (se == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(OPENVPN_CHANNEL));

	c->Session = se;
	c->Server = se->Server;

	c->Status = OPENVPN_CHANNEL_STATUS_INIT;

	c->AckReplyList = NewIntList(true);

	c->SendControlPacketList = NewListFast(NULL);

	c->KeyId = key_id;

	Rand(c->NextIv, sizeof(c->NextIv));

	//c->NextRekey = se->Server->Now + (UINT64)5000;

	se->LastCreatedChannelIndex = key_id;

	return c;
}

// Create a new server-side channel ID
UINT64 OvsNewServerSessionId(OPENVPN_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	while (true)
	{
		UINT64 id = Rand64();
		UINT i;
		bool exists = false;

		if (id == 0 || id == (UINT64)(0xFFFFFFFFFFFFFFFFULL))
		{
			continue;
		}

		for (i = 0;i < LIST_NUM(s->SessionList);i++)
		{
			OPENVPN_SESSION *se = LIST_DATA(s->SessionList, i);
			if (se->ServerSessionId == id)
			{
				exists = true;
			}
		}

		if (exists == false)
		{
			return id;
		}
	}
}

// Build and submit the OpenVPN data packet
void OvsSendDataPacket(OPENVPN_CHANNEL *c, UCHAR key_id, UINT data_packet_id, void *data, UINT data_size)
{
	UCHAR uc;
	UCHAR *encrypted_data;
	UINT encrypted_size;
	UCHAR *dest_data;
	UINT dest_size;
	UINT r;

	// Validate arguments
	if (c == NULL || data == NULL || data_size == 0)
	{
		return;
	}

	uc = ((OPENVPN_P_DATA_V1 << 3) & 0xF8) | (key_id & 0x07);

	// Generate the data to be encrypted

	encrypted_size = sizeof(UINT) + data_size;
	encrypted_data = ZeroMalloc(encrypted_size);

	WRITE_UINT(encrypted_data, data_packet_id);
	Copy(encrypted_data + sizeof(UINT), data, data_size);

	// Prepare a buffer to store the results
	dest_data = Malloc(sizeof(UCHAR) + c->MdSend->Size + c->CipherEncrypt->IvSize + encrypted_size + 256);

	// Encrypt
	r = CipherProcess(c->CipherEncrypt, c->NextIv, dest_data + sizeof(UCHAR) + c->MdSend->Size + c->CipherEncrypt->IvSize,
		encrypted_data, encrypted_size);
	dest_size = sizeof(UCHAR) + c->MdSend->Size + c->CipherEncrypt->IvSize + r;

	// Copy the IV
	Copy(dest_data + sizeof(UCHAR) + c->MdSend->Size, c->NextIv, c->CipherEncrypt->IvSize);

	// Calculate the HMAC
	MdProcess(c->MdSend, dest_data + sizeof(UCHAR), dest_data + sizeof(UCHAR) + c->MdSend->Size,
		dest_size - sizeof(UCHAR) - c->MdSend->Size);

	// Update the NextIV
	Copy(c->NextIv, dest_data + dest_size - c->CipherEncrypt->IvSize, c->CipherEncrypt->IvSize);

	// Op-code
	dest_data[0] = uc;

	OvsSendPacketRawNow(c->Server, c->Session, dest_data, dest_size);

	Free(encrypted_data);
}

// Build an OpenVPN control packet
BUF *OvsBuildPacket(OPENVPN_PACKET *p)
{
	BUF *b;
	UCHAR uc;
	UINT num_ack;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	// OpCode + KeyID
	uc = ((p->OpCode << 3) & 0xF8) | (p->KeyId & 0x07);
	WriteBufChar(b, uc);

	if (p->OpCode == OPENVPN_P_DATA_V1)
	{
		// Data Packet
		WriteBuf(b, p->Data, p->DataSize);
		SeekBuf(b, 0, 0);
		return b;
	}

	// Sender Channel ID
	WriteBufInt64(b, p->MySessionId);

	// NumAck
	num_ack = MIN(p->NumAck, OPENVPN_MAX_NUMACK);
	WriteBufChar(b, (UCHAR)num_ack);

	if (p->NumAck >= 1)
	{
		UINT i;

		for (i = 0;i < num_ack;i++)
		{
			WriteBufInt(b, (UCHAR)p->AckPacketId[i]);
		}

		// Received Channel ID
		WriteBufInt64(b, p->YourSessionId);
	}

	if (p->OpCode != OPENVPN_P_ACK_V1)
	{
		// Packet ID
		WriteBufInt(b, p->PacketId);

		// Payload
		if (p->DataSize >= 1 && p->Data != NULL)
		{
			WriteBuf(b, p->Data, p->DataSize);
		}
	}

	SeekBuf(b, 0, 0);

	return b;
}

// Parse the OpenVPN packet
OPENVPN_PACKET *OvsParsePacket(UCHAR *data, UINT size)
{
	UCHAR uc;
	OPENVPN_PACKET *ret = NULL;
	// Validate arguments
	if (data == NULL || size == 0)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(OPENVPN_PACKET));

	// OpCode + KeyID
	if (size < 1)
	{
		goto LABEL_ERROR;
	}
	uc = *((UCHAR *)data);
	data++;
	size--;

	ret->OpCode = ((uc & 0xF8) >> 3) & 0x1F;
	ret->KeyId = uc & 0x07;

	if (ret->OpCode == OPENVPN_P_DATA_V1)
	{
		// Data packet
		ret->DataSize = size;
		ret->Data = Clone(data, size);
		return ret;
	}

	// Sender Channel ID
	if (size < sizeof(UINT64))
	{
		goto LABEL_ERROR;
	}
	ret->MySessionId = READ_UINT64(data);
	data += sizeof(UINT64);
	size -= sizeof(UINT64);

	// ACK
	if (size < 1)
	{
		goto LABEL_ERROR;
	}
	uc = *((UCHAR *)data);
	data++;
	size--;

	ret->NumAck = uc;

	if (ret->NumAck > 4)
	{
		goto LABEL_ERROR;
	}

	if (ret->NumAck >= 1)
	{
		UINT i;

		if (size < (sizeof(UINT) * (UINT)ret->NumAck + sizeof(UINT64)))
		{
			goto LABEL_ERROR;
		}

		for (i = 0;i < ret->NumAck;i++)
		{
			UINT ui;

			ui = READ_UINT(data);

			ret->AckPacketId[i] = ui;

			data += sizeof(UINT);
			size -= sizeof(UINT);
		}

		ret->YourSessionId = READ_UINT64(data);
		data += sizeof(UINT64);
		size -= sizeof(UINT64);
	}

	if (ret->OpCode != OPENVPN_P_ACK_V1)
	{
		// Read the Packet ID Because in the case of other than ACK
		if (size < sizeof(UINT))
		{
			goto LABEL_ERROR;
		}

		ret->PacketId = READ_UINT(data);
		data += sizeof(UINT);
		size -= sizeof(UINT);

		// Payload
		ret->DataSize = size;
		if (size >= 1)
		{
			ret->Data = Clone(data, size);
		}
	}

	return ret;

LABEL_ERROR:
	Debug("OvsParsePacket Error.\n");
	if (ret != NULL)
	{
		OvsFreePacket(ret);
	}
	return NULL;
}

// Release the OpenVPN packet
void OvsFreePacket(OPENVPN_PACKET *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->Data != NULL)
	{
		Free(p->Data);
	}

	Free(p);
}

// If the session does not exist, create a session
OPENVPN_SESSION *OvsFindOrCreateSession(OPENVPN_SERVER *s, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, UINT protocol)
{
	OPENVPN_SESSION *se;
	// Validate arguments
	if (s == NULL || server_ip == NULL || server_port == 0 || client_ip	== NULL || client_port == 0)
	{
		return NULL;
	}

	se = OvsSearchSession(s, server_ip, server_port, client_ip, client_port, protocol);
	if (se == NULL)
	{
		se = OvsNewSession(s, server_ip, server_port, client_ip, client_port, protocol);

		if (se != NULL)
		{
			Insert(s->SessionList, se);
		}
	}

	return se;
}

// Get the number of sessions currently connected from the IP address of the client
UINT OvsGetNumSessionByClientIp(OPENVPN_SERVER *s, IP *ip)
{
	UINT i;
	UINT ret = 0;
	// Validate arguments
	if (s == NULL || ip == NULL)
	{
		return 0;
	}

	for (i = 0;i < LIST_NUM(s->SessionList);i++)
	{
		OPENVPN_SESSION *se = LIST_DATA(s->SessionList, i);

		if (CmpIpAddr(&se->ClientIp, ip) == 0)
		{
			ret++;
		}
	}

	return ret;
}

// Create a new session
OPENVPN_SESSION *OvsNewSession(OPENVPN_SERVER *s, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, UINT protocol)
{
	OPENVPN_SESSION *se;
	char server_ip_str[MAX_SIZE];
	char client_ip_str[MAX_SIZE];
	// Validate arguments
	if (s == NULL || server_ip == NULL || server_port == 0 || client_ip	== NULL || client_port == 0)
	{
		return NULL;
	}


	if (OvsGetNumSessionByClientIp(s, client_ip) > OPENVPN_QUOTA_MAX_NUM_SESSIONS_PER_IP)
	{
		// Number of sessions from the same IP address too many
		return NULL;
	}

	if (LIST_NUM(s->SessionList) > OPENVPN_QUOTA_MAX_NUM_SESSIONS)
	{
		// Too many OpenVPN sessions
		return NULL;
	}

	se = ZeroMalloc(sizeof(OPENVPN_SESSION));

	se->Server = s;

	Copy(&se->ClientIp, client_ip, sizeof(IP));
	se->ClientPort = client_port;

	Copy(&se->ServerIp, server_ip, sizeof(IP));
	se->ServerPort = server_port;

	se->LastCommTick = s->Now;

	se->Protocol = protocol;

	se->ServerSessionId = OvsNewServerSessionId(se->Server);

	se->CreatedTick = s->Now;

	se->Id = s->NextSessionId;
	s->NextSessionId++;

	IPToStr(server_ip_str, sizeof(server_ip_str), server_ip);
	IPToStr(client_ip_str, sizeof(client_ip_str), client_ip);
	Debug("OpenVPN New Session: %s:%u -> %s:%u Proto=%u\n", server_ip_str, server_port,
		client_ip_str, client_port, protocol);

	OvsLog(s, se, NULL, "LO_NEW_SESSION", (protocol == OPENVPN_PROTOCOL_UDP ? "UDP" : "TCP"));

	return se;
}

// Release the session
void OvsFreeSession(OPENVPN_SESSION *se)
{
	UINT i;
	// Validate arguments
	if (se == NULL)
	{
		return;
	}

	// If there is IP addresses which is got from a DHCP server in the session, release it
	if (se->Ipc != NULL)
	{
		if (se->Mode == OPENVPN_MODE_L3)
		{
			if (se->IpcAsync != NULL)
			{
				IP dhcp_ip;

				UINTToIP(&dhcp_ip, se->IpcAsync->L3ClientAddressOption.ServerAddress);

				IPCDhcpFreeIP(se->Ipc, &dhcp_ip);
				IPCProcessL3Events(se->Ipc);
			}
		}
	}

	// Release the channel
	for (i = 0;i < OPENVPN_NUM_CHANNELS;i++)
	{
		OPENVPN_CHANNEL *c = se->Channels[i];

		if (c != NULL)
		{
			OvsFreeChannel(c);
		}
	}

	// Release the IPC
	if (se->Ipc != NULL)
	{
		FreeIPC(se->Ipc);
	}

	if (se->IpcAsync != NULL)
	{
		FreeIPCAsync(se->IpcAsync);
	}

	Free(se);
}

// Search the session from the endpoint information
OPENVPN_SESSION *OvsSearchSession(OPENVPN_SERVER *s, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, UINT protocol)
{
	OPENVPN_SESSION *se;
	OPENVPN_SESSION t;
	// Validate arguments
	if (s == NULL || server_ip == NULL || server_port == 0 || client_ip	== NULL || client_port == 0)
	{
		return NULL;
	}

	Copy(&t.ClientIp, client_ip, sizeof(IP));
	t.ClientPort = client_port;
	Copy(&t.ServerIp, server_ip, sizeof(IP));
	t.ServerPort = server_port;
	t.Protocol = protocol;

	se = Search(s->SessionList, &t);

	return se;
}

// Receive packets in the OpenVPN server
void OvsRecvPacket(OPENVPN_SERVER *s, LIST *recv_packet_list, UINT protocol)
{
	UINT i, j;
	LIST *delete_session_list = NULL;
	// Validate arguments
	if (s == NULL || recv_packet_list == NULL)
	{
		return;
	}

	s->Now = Tick64();

	// Process for all sessions
	for (i = 0;i < LIST_NUM(s->SessionList);i++)
	{
		OPENVPN_SESSION *se = LIST_DATA(s->SessionList, i);

		if (se->Ipc != NULL)
		{
			if (se->Mode == OPENVPN_MODE_L3)
			{
				// Flush the ARP table of the IPC
				IPCFlushArpTableEx(se->Ipc, s->Now);
			}
		}
	}

	// Process received packets
	for (i = 0;i < LIST_NUM(recv_packet_list);i++)
	{
		UDPPACKET *p = LIST_DATA(recv_packet_list, i);

		OvsProceccRecvPacket(s, p, protocol);
	}

	// Treat for all sessions and all channels
	for (i = 0;i < LIST_NUM(s->SessionList);i++)
	{
		OPENVPN_CHANNEL *latest_channel = NULL;
		UINT64 max_tick = 0;
		OPENVPN_SESSION *se = LIST_DATA(s->SessionList, i);
		bool is_disconnected = false;

		if (se->Ipc != NULL)
		{
			if (se->Mode == OPENVPN_MODE_L3)
			{
				IPCProcessL3Events(se->Ipc);
			}
		}

		for (j = 0;j < OPENVPN_NUM_CHANNELS;j++)
		{
			OPENVPN_CHANNEL *c = se->Channels[j];

			if (c != NULL)
			{
				if (c->RekeyInitiated == false && ((c->NextRekey <= s->Now && c->NextRekey != 0) || (c->LastDataPacketId >= OPENVPN_MAX_PACKET_ID_FOR_TRIGGER_REKEY)))
				{
					OPENVPN_CHANNEL *c2;
					// Send a soft reset by creating a new channel
					UINT next_channel_id = se->LastCreatedChannelIndex + 1;
					if (next_channel_id >= OPENVPN_NUM_CHANNELS)
					{
						next_channel_id = 1;
					}
					if (se->Channels[next_channel_id] != NULL)
					{
						// Release when there is a channel data already
						OvsFreeChannel(se->Channels[next_channel_id]);
						se->Channels[next_channel_id] = NULL;
					}

					// Create a new channel
					c2 = OvsNewChannel(se, (UCHAR)next_channel_id);
					c2->IsInitiatorServer = true;
					se->Channels[next_channel_id] = c2;
					Debug("OpenVPN New Channel for Re-Keying :%u\n", next_channel_id);
					OvsLog(s, se, c, "LO_INITIATE_REKEY");

					// Send a soft reset
					OvsSendControlPacket(c2, OPENVPN_P_CONTROL_SOFT_RESET_V1, NULL, 0);

					c->RekeyInitiated = true;
				}
			}

			if (c != NULL)
			{
				switch (c->Status)
				{
				case OPENVPN_CHANNEL_STATUS_TLS_VPN_CONNECTING:
					// Check whether the connection process completed if there is a channel running a VPN connection process
					if (se->IpcAsync != NULL)
					{
						if (se->IpcAsync->Done)
						{
							if (se->IpcAsync->Ipc != NULL)
							{
								char option_str[4096];
								char l3_options[MAX_SIZE];

								// Successful in VPN connection
								Debug("OpenVPN Channel %u Established (new key).\n", j);
								OvsLog(s, se, c, "LO_CHANNEL_ESTABLISHED");

								// Return the PUSH_REPLY
								Format(option_str, sizeof(option_str),
									"PUSH_REPLY,ping %u,ping-restart %u",
									(OPENVPN_PING_SEND_INTERVAL / 1000),
									(OPENVPN_RECV_TIMEOUT / 1000));

								if (se->Mode == OPENVPN_MODE_L3)
								{
									// Add such as the IP address that was acquired from the DHCP server
									// if the L3 mode to the option character string
									DHCP_OPTION_LIST *cao = &se->IpcAsync->L3ClientAddressOption;
									char ip_client[64];
									char ip_tunnel_endpoint[64];
									UINT ip_tunnel_endpoint_32;
									char ip_network[64];
									char ip_subnet_mask[64];
									char ip_dns1[64];
									char ip_dns2[64];
									char ip_wins1[64];
									char ip_wins2[64];
									char ip_defgw[64];

									ClearStr(ip_dns1, sizeof(ip_dns1));
									ClearStr(ip_dns2, sizeof(ip_dns2));
									ClearStr(ip_wins1, sizeof(ip_wins1));
									ClearStr(ip_wins2, sizeof(ip_wins2));
									ClearStr(ip_defgw, sizeof(ip_defgw));

									IPToStr32(ip_client, sizeof(ip_client),
										cao->ClientAddress);

									// Generate a virtual gateway address to be passed to the OpenVPN
									ip_tunnel_endpoint_32 = Endian32(cao->ClientAddress);
									ip_tunnel_endpoint_32++;
									ip_tunnel_endpoint_32 = Endian32(ip_tunnel_endpoint_32);
									IPToStr32(ip_tunnel_endpoint, sizeof(ip_tunnel_endpoint), ip_tunnel_endpoint_32);

									// Create a subnet information for the LAN
									IPToStr32(ip_network, sizeof(ip_network),
										GetNetworkAddress(cao->ClientAddress,
										cao->SubnetMask));

									IPToStr32(ip_subnet_mask, sizeof(ip_subnet_mask),
										cao->SubnetMask);

									Format(l3_options, sizeof(l3_options),
										",ifconfig %s %s",
//										",ifconfig %s %s,route %s %s %s 1",
										ip_client, ip_tunnel_endpoint, ip_network, ip_subnet_mask,
										ip_tunnel_endpoint);
									StrCat(option_str, sizeof(option_str), l3_options);

									// Domain name
									if (IsEmptyStr(cao->DomainName) == false)
									{
										Format(l3_options, sizeof(l3_options),
											",dhcp-option DOMAIN %s", cao->DomainName);
										StrCat(option_str, sizeof(option_str), l3_options);
									}

									// DNS server address 1
									if (cao->DnsServer != 0)
									{
										char ip_str[64];
										IPToStr32(ip_str, sizeof(ip_str), cao->DnsServer);
										Format(l3_options, sizeof(l3_options),
											",dhcp-option DNS %s", ip_str);
										StrCat(option_str, sizeof(option_str), l3_options);

										StrCpy(ip_dns1, sizeof(ip_dns1), ip_str);
									}

									// DNS server address 2
									if (cao->DnsServer2 != 0)
									{
										char ip_str[64];
										IPToStr32(ip_str, sizeof(ip_str), cao->DnsServer2);
										Format(l3_options, sizeof(l3_options),
											",dhcp-option DNS %s", ip_str);
										StrCat(option_str, sizeof(option_str), l3_options);

										StrCpy(ip_dns2, sizeof(ip_dns2), ip_str);
									}

									// WINS address 1
									if (cao->WinsServer != 0)
									{
										char ip_str[64];
										IPToStr32(ip_str, sizeof(ip_str), cao->WinsServer);
										Format(l3_options, sizeof(l3_options),
											",dhcp-option WINS %s", ip_str);
										StrCat(option_str, sizeof(option_str), l3_options);

										StrCpy(ip_wins1, sizeof(ip_wins1), ip_str);
									}

									// WINS address 2
									if (cao->WinsServer2 != 0)
									{
										char ip_str[64];
										IPToStr32(ip_str, sizeof(ip_str), cao->WinsServer2);
										Format(l3_options, sizeof(l3_options),
											",dhcp-option WINS %s", ip_str);
										StrCat(option_str, sizeof(option_str), l3_options);

										StrCpy(ip_wins2, sizeof(ip_wins2), ip_str);
									}

									// Default gateway
									if (cao->Gateway != 0)
									{
										Format(l3_options, sizeof(l3_options),
											",route-gateway %s,redirect-gateway def1", ip_tunnel_endpoint);
										StrCat(option_str, sizeof(option_str), l3_options);

										IPToStr32(ip_defgw, sizeof(ip_defgw), cao->Gateway);
									}
									else
									{
#if	0	// Currently disabled
										// If the default gateway is not specified, add the static routing table
										// entry for the local IP subnet
										IP local_network;
										IP client_ip;
										IP subnet_mask;

										UINTToIP(&client_ip, cao->ClientAddress);
										UINTToIP(&subnet_mask, cao->SubnetMask);

										Zero(&local_network, sizeof(IP));
										IPAnd4(&local_network, &client_ip, &subnet_mask);

										Format(l3_options, sizeof(l3_options),
											",route %r %r vpn_gateway",
											&local_network,
											&cao->SubnetMask);

										StrCat(option_str, sizeof(option_str), l3_options);
#endif
									}

									// Classless routing table
									if (cao->ClasslessRoute.NumExistingRoutes >= 1)
									{
										UINT i;
										for (i = 0;i < MAX_DHCP_CLASSLESS_ROUTE_ENTRIES;i++)
										{
											DHCP_CLASSLESS_ROUTE *r = &cao->ClasslessRoute.Entries[i];

											if (r->Exists)
											{
												Format(l3_options, sizeof(l3_options),
													",route %r %r vpn_gateway",
													&r->Network, &r->SubnetMask);

												StrCat(option_str, sizeof(option_str), l3_options);
											}
										}
									}

									OvsLog(s, se, c, "LP_SET_IPV4_PARAM",
										ip_client, ip_subnet_mask, ip_defgw, ip_dns1, ip_dns2, ip_wins1, ip_wins2);
								}

								WriteFifo(c->SslPipe->SslInOut->SendFifo, option_str, StrSize(option_str));

								Debug("Push Str: %s\n", option_str);
								OvsLog(s, se, c, "LO_PUSH_REPLY", option_str);

								StrCpy(se->PushReplyStr, sizeof(se->PushReplyStr), option_str);

								se->Ipc = se->IpcAsync->Ipc;
								se->IpcAsync->Ipc = NULL;

								s->SessionEstablishedCount++;

								// Set a Sock Event of IPC to Sock Event of the UDP Listener
								IPCSetSockEventWhenRecvL2Packet(se->Ipc, s->SockEvent);

								// State transition
								c->Status = OPENVPN_CHANNEL_STATUS_ESTABLISHED;
								c->EstablishedTick = s->Now;
								se->Established = true;
								se->LastCommTick = Tick64();
							}
							else
							{
								char *str;

								if (se->IpcAsync->DhcpAllocFailed)
								{
									OvsLog(s, se, c, "LP_DHCP_REQUEST_NG");
								}

								// Failed to connect VPN
								Debug("OpenVPN Channel %u Failed.\n", j);
								OvsLog(s, se, c, "LO_CHANNEL_FAILED");

								// Return the AUTH_FAILED
								str = "AUTH_FAILED";
								WriteFifo(c->SslPipe->SslInOut->SendFifo, str, StrSize(str));

								s->SessionEstablishedCount++;

								// State transition
								c->Status = OPENVPN_CHANNEL_STATUS_DISCONNECTED;

								FreeIPCAsync(se->IpcAsync);
								se->IpcAsync = NULL;
							}
						}
					}
					break;

				case OPENVPN_CHANNEL_STATUS_ESTABLISHED:
					// Monitor the IPC whether not disconnected when there is a VPN connection completed channel
					if (IsIPCConnected(se->Ipc) == false)
					{
						// Send the RESTART since IPC is disconnected
						char *str = "RESTART";
						Debug("OpenVPN Channel %u Disconnected by HUB.\n", j);

						OvsLog(s, se, c, "LO_CHANNEL_DISCONNECTED_BY_HUB");

						WriteFifo(c->SslPipe->SslInOut->SendFifo, str, StrSize(str));

						// State transition
						c->Status = OPENVPN_CHANNEL_STATUS_DISCONNECTED;

						// Set the session to disconnected state
						se->Established = false;
						se->LastCommTick = s->Now;
					}
					break;
				}
			}

			if (c != NULL)
			{
				// If there is a packet to be transmitted physically in SSL, send it
				if (c->SslPipe != NULL && SyncSslPipe(c->SslPipe))
				{
					if (FifoSize(c->SslPipe->RawOut->RecvFifo) >= 1)
					{
						Debug("RawOut Fifo Size (c=%u): %u\n", c->KeyId, FifoSize(c->SslPipe->RawOut->RecvFifo));

						OvsSendControlPacketWithAutoSplit(c, OPENVPN_P_CONTROL_V1,
							FifoPtr(c->SslPipe->RawOut->RecvFifo),
							FifoSize(c->SslPipe->RawOut->RecvFifo));

						ReadFifo(c->SslPipe->RawOut->RecvFifo, NULL, FifoSize(c->SslPipe->RawOut->RecvFifo));
					}
				}
			}

			if (c != NULL)
			{
				UINT num;
				UINT acks[OPENVPN_MAX_NUMACK];
				UINT k;

				// Packet transmission
				for (k = 0;k < LIST_NUM(c->SendControlPacketList);k++)
				{
					OPENVPN_CONTROL_PACKET *cp = LIST_DATA(c->SendControlPacketList, k);

					if (cp->NextSendTime <= s->Now)
					{
						OPENVPN_PACKET *p;

						num = OvsGetAckReplyList(c, acks);

						p = OvsNewControlPacket(cp->OpCode, j, se->ServerSessionId, num, acks,
							se->ClientSessionId, cp->PacketId, cp->DataSize, cp->Data);

						OvsSendPacketNow(s, se, p);

						OvsFreePacket(p);

						cp->NextSendTime = s->Now + (UINT64)OPENVPN_CONTROL_PACKET_RESEND_INTERVAL;

						AddInterrupt(s->Interrupt, cp->NextSendTime);
					}
				}

				// If the response with an ACK-only packet is required, respond such that
				num = OvsGetAckReplyList(c, acks);

				if (num >= 1)
				{
					OPENVPN_PACKET *p = OvsNewControlPacket(OPENVPN_P_ACK_V1, j, se->ServerSessionId,
						num, acks, se->ClientSessionId, 0, 0, NULL);

					OvsSendPacketNow(s, se, p);

					OvsFreePacket(p);
				}
			}
		}

		if (se->Ipc != NULL)
		{
			if (se->Mode == OPENVPN_MODE_L3)
			{
				if (se->IpcAsync != NULL)
				{
					// Update DHCP address
					if (se->IpcAsync->L3NextDhcpRenewTick <= s->Now)
					{
						IP ip;

						se->IpcAsync->L3NextDhcpRenewTick = s->Now + se->IpcAsync->L3DhcpRenewInterval;

						UINTToIP(&ip, se->IpcAsync->L3ClientAddressOption.ServerAddress);

						IPCDhcpRenewIP(se->Ipc, &ip);
					}
				}

				IPCProcessL3Events(se->Ipc);
			}

			IPCProcessInterrupts(se->Ipc);
		}

		// Choose the latest channel in all established channels
		for (j = 0;j < OPENVPN_NUM_CHANNELS;j++)
		{
			OPENVPN_CHANNEL *c = se->Channels[j];

			if (c != NULL)
			{
				if (c->Status == OPENVPN_CHANNEL_STATUS_ESTABLISHED)
				{
					if (max_tick <= c->EstablishedTick)
					{
						max_tick = c->EstablishedTick;
						latest_channel = c;
					}
				}
			}
		}

		if (se->Established == false)
		{
			latest_channel = NULL;
		}

		// Send the data using the latest channel (when there is no transmission channel, suck out the queue simply)
		if (se->Mode == OPENVPN_MODE_L2)
		{
			// Get an Ethernet frame from IPC
			while (true)
			{
				BLOCK *b = IPCRecvL2(se->Ipc);
				if (b == NULL)
				{
					break;
				}

				if (latest_channel != NULL && s->SupressSendPacket == false)
				{
					OvsSendDataPacket(latest_channel, latest_channel->KeyId, ++latest_channel->LastDataPacketId, b->Buf, b->Size);
				}

				FreeBlock(b);
			}
		}
		else
		{
			// Get an IPv4 packet from IPC
			while (true)
			{
				BLOCK *b = IPCRecvIPv4(se->Ipc);
				if (b == NULL)
				{
					break;
				}

				if (latest_channel != NULL && s->SupressSendPacket == false)
				{
					OvsSendDataPacket(latest_channel, latest_channel->KeyId, ++latest_channel->LastDataPacketId, b->Buf, b->Size);
				}

				FreeBlock(b);
			}
		}

		// Send a Ping
		if (latest_channel != NULL)
		{
			if ((se->NextPingSendTick == 0) || (se->NextPingSendTick <= s->Now))
			{
				se->NextPingSendTick = s->Now + (UINT64)(OPENVPN_PING_SEND_INTERVAL);

				OvsSendDataPacket(latest_channel, latest_channel->KeyId, ++latest_channel->LastDataPacketId,
					ping_signature, sizeof(ping_signature));
				//Debug(".");

				AddInterrupt(s->Interrupt, se->NextPingSendTick);
			}
		}

		if ((se->Established == false) && (s->Now >= (se->CreatedTick + (UINT64)OPENVPN_NEW_SESSION_DEADLINE_TIMEOUT)))
		{
			is_disconnected = true;
		}

		if (se->Established && (s->Now >= (se->LastCommTick + (UINT64)OPENVPN_RECV_TIMEOUT)))
		{
			is_disconnected = true;
		}

		if (is_disconnected)
		{
			if (delete_session_list == NULL)
			{
				delete_session_list = NewListFast(NULL);
			}

			Add(delete_session_list, se);
		}
	}

	if (delete_session_list != NULL)
	{
		UINT i;

		for (i = 0;i < LIST_NUM(delete_session_list);i++)
		{
			OPENVPN_SESSION *se = LIST_DATA(delete_session_list, i);

			Debug("Deleting Session %p\n", se);
			OvsLog(s, se, NULL, "LO_DELETE_SESSION");

			OvsFreeSession(se);

			s->DisconnectCount++;

			Delete(s->SessionList, se);
		}

		ReleaseList(delete_session_list);
	}
}

// Send the packet now
void OvsSendPacketNow(OPENVPN_SERVER *s, OPENVPN_SESSION *se, OPENVPN_PACKET *p)
{
	BUF *b;
	UINT i;
	// Validate arguments
	if (s == NULL || se == NULL || p == NULL)
	{
		return;
	}

	Debug("Sending Opcode=%u  ", p->OpCode);
	if (p->NumAck >= 1)
	{
		Debug("Sending ACK Packet IDs (c=%u): ", p->KeyId);
		for (i = 0;i < p->NumAck;i++)
		{
			Debug("%u ", p->AckPacketId[i]);
		}
	}
	Debug("\n");

	b = OvsBuildPacket(p);

	OvsSendPacketRawNow(s, se, b->Buf, b->Size);

	Free(b);
}
void OvsSendPacketRawNow(OPENVPN_SERVER *s, OPENVPN_SESSION *se, void *data, UINT size)
{
	UDPPACKET *u;

	// Validate arguments
	if (s == NULL || se == NULL || data == NULL || size == 0)
	{
		Free(data);
		return;
	}

	u = NewUdpPacket(&se->ServerIp, se->ServerPort, &se->ClientIp, se->ClientPort,
		data, size);

	Add(s->SendPacketList, u);
}
// Create a new OpenVPN control packet
OPENVPN_PACKET *OvsNewControlPacket(UCHAR opcode, UCHAR key_id, UINT64 my_channel_id, UINT num_ack,
									UINT *ack_packet_ids, UINT64 your_channel_id, UINT packet_id,
									UINT data_size, UCHAR *data)
{
	OPENVPN_PACKET *p = ZeroMalloc(sizeof(OPENVPN_PACKET));
	UINT i;

	p->OpCode = opcode;
	p->KeyId = key_id;
	p->MySessionId = my_channel_id;
	p->NumAck = num_ack;

	for (i = 0;i < MIN(num_ack, OPENVPN_MAX_NUMACK);i++)
	{
		p->AckPacketId[i] = ack_packet_ids[i];
	}

	p->YourSessionId = your_channel_id;
	p->PacketId = packet_id;

	if (data_size != 0 && data != NULL)
	{
		p->Data = Clone(data, data_size);
		p->DataSize = data_size;
	}

	return p;
}

// Comparison function of the entries in the session list
int OvsCompareSessionList(void *p1, void *p2)
{
	OPENVPN_SESSION *s1, *s2;
	int i;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(OPENVPN_SESSION **)p1;
	s2 = *(OPENVPN_SESSION **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	i = CmpIpAddr(&s1->Protocol, &s2->Protocol);
	if (i != 0)
	{
		return i;
	}

	i = CmpIpAddr(&s1->ClientIp, &s2->ClientIp);
	if (i != 0)
	{
		return i;
	}

	i = COMPARE_RET(s1->ClientPort, s2->ClientPort);
	if (i != 0)
	{
		return i;
	}

	i = CmpIpAddr(&s1->ServerIp, &s2->ServerIp);
	if (i != 0)
	{
		return i;
	}

	i = COMPARE_RET(s1->ServerPort, s2->ServerPort);
	if (i != 0)
	{
		return i;
	}

	return 0;
}

// Identify whether the IP address is compatible to the tun device of OpenVPN
bool OvsIsCompatibleL3IP(UINT ip)
{
	IP p;

	UINTToIP(&p, ip);
	if ((p.addr[3] % 4) == 1)
	{
		return true;
	}

	return false;
}

// Get an IP address that is compatible to tun device of the OpenVPN after the specified IP address
UINT OvsGetCompatibleL3IPNext(UINT ip)
{
	ip = Endian32(ip);

	while (true)
	{
		if (OvsIsCompatibleL3IP(Endian32(ip)))
		{
			return Endian32(ip);
		}

		ip++;
	}
}

// Create a new OpenVPN server
OPENVPN_SERVER *NewOpenVpnServer(CEDAR *cedar, INTERRUPT_MANAGER *interrupt, SOCK_EVENT *sock_event)
{
	OPENVPN_SERVER *s;
	// Validate arguments
	if (cedar == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(OPENVPN_SERVER));

	s->Cedar = cedar;

	AddRef(s->Cedar->ref);

	s->Interrupt = interrupt;

	s->SessionList = NewList(OvsCompareSessionList);
	s->SendPacketList = NewListFast(NULL);

	s->Now = Tick64();

	s->NextSessionId = 1;

	if (sock_event != NULL)
	{
		s->SockEvent = sock_event;
		AddRef(s->SockEvent->ref);
	}

	OvsLog(s, NULL, NULL, "LO_START");

	s->Dh = DhNewGroup2();

	return s;
}

// Release the OpenVPN server
void FreeOpenVpnServer(OPENVPN_SERVER *s)
{
	UINT i;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	OvsLog(s, NULL, NULL, "LO_STOP");

	// Release the session list
	for (i = 0;i < LIST_NUM(s->SessionList);i++)
	{
		OPENVPN_SESSION *se = LIST_DATA(s->SessionList, i);

		OvsFreeSession(se);
	}

	ReleaseList(s->SessionList);

	// Release the packet which is attempting to send
	for (i = 0;i < LIST_NUM(s->SendPacketList);i++)
	{
		UDPPACKET *p = LIST_DATA(s->SendPacketList, i);

		FreeUdpPacket(p);
	}

	ReleaseList(s->SendPacketList);

	ReleaseCedar(s->Cedar);

	if (s->SockEvent != NULL)
	{
		ReleaseSockEvent(s->SockEvent);
	}

	DhFree(s->Dh);

	Free(s);
}

// UDP reception procedure
void OpenVpnServerUdpListenerProc(UDPLISTENER *u, LIST *packet_list)
{
	OPENVPN_SERVER_UDP *us;
	UINT64 now = Tick64();
	// Validate arguments
	if (u == NULL || packet_list == NULL)
	{
		return;
	}

	us = (OPENVPN_SERVER_UDP *)u->Param;

	if (OvsGetNoOpenVpnUdp())
	{
		// OpenVPN over UDP is disabled
		return;
	}

	if (us->OpenVpnServer != NULL)
	{
		{
			u->PollMyIpAndPort = false;

			ClearStr(us->Cedar->OpenVPNPublicPorts, sizeof(us->Cedar->OpenVPNPublicPorts));
		}

		OvsRecvPacket(us->OpenVpnServer, packet_list, OPENVPN_PROTOCOL_UDP);

		UdpListenerSendPackets(u, us->OpenVpnServer->SendPacketList);
		DeleteAll(us->OpenVpnServer->SendPacketList);
	}
}

// Create an OpenVPN server (UDP mode)
OPENVPN_SERVER_UDP *NewOpenVpnServerUdp(CEDAR *cedar)
{
	OPENVPN_SERVER_UDP *u;
	// Validate arguments
	if (cedar == NULL)
	{
		return NULL;
	}

	u = ZeroMalloc(sizeof(OPENVPN_SERVER_UDP));

	u->Cedar = cedar;

	AddRef(u->Cedar->ref);

	// Create a UDP listener
	u->UdpListener = NewUdpListener(OpenVpnServerUdpListenerProc, u);

	// Create an OpenVPN server
	u->OpenVpnServer = NewOpenVpnServer(cedar, u->UdpListener->Interrupts, u->UdpListener->Event);

	return u;
}

// Apply the port list to the OpenVPN server
void OvsApplyUdpPortList(OPENVPN_SERVER_UDP *u, char *port_list)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	DeleteAllPortFromUdpListener(u->UdpListener);

	o = StrToIntList(port_list, true);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT port = *((UINT *)LIST_DATA(o, i));

		if (port >= 1 && port <= 65535)
		{
			AddPortToUdpListener(u->UdpListener, port);
		}
	}

	ReleaseIntList(o);
}

// Release the OpenVPN server (UDP mode)
void FreeOpenVpnServerUdp(OPENVPN_SERVER_UDP *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	// Stop the UDP listener
	FreeUdpListener(u->UdpListener);

	// Release the OpenVPN server
	FreeOpenVpnServer(u->OpenVpnServer);

	ReleaseCedar(u->Cedar);

	Free(u);
}

// Check whether it's OpenSSL protocol by looking the first receive buffer of the TCP
bool OvsCheckTcpRecvBufIfOpenVPNProtocol(UCHAR *buf, UINT size)
{
	if (buf == NULL || size != 2)
	{
		return false;
	}

	if (buf[0] == 0x00 && buf[1] == 0x0E)
	{
		return true;
	}

	return false;
}

// Run the OpenVPN server in TCP mode
bool OvsPerformTcpServer(CEDAR *cedar, SOCK *sock)
{
	OPENVPN_SERVER *s;
	INTERRUPT_MANAGER *im;
	SOCK_EVENT *se;
	FIFO *tcp_recv_fifo;
	FIFO *tcp_send_fifo;
	UINT buf_size = (128 * 1024);
	UCHAR *buf;
	UINT64 giveup_time = Tick64() + (UINT64)OPENVPN_NEW_SESSION_DEADLINE_TIMEOUT;
	LIST *ovs_recv_packet;
	UINT i;
	bool ret = false;
	// Validate arguments
	if (cedar == NULL || sock == NULL)
	{
		return false;
	}

	// Initialize
	buf = Malloc(buf_size);
	im = NewInterruptManager();
	se = NewSockEvent();
	SetTimeout(sock, TIMEOUT_INFINITE);
	JoinSockToSockEvent(sock, se);

	tcp_recv_fifo = NewFifoFast();
	tcp_send_fifo = NewFifoFast();

	ovs_recv_packet = NewListFast(NULL);

	// Create an OpenVPN server
	s = NewOpenVpnServer(cedar, im, se);

	// Main loop
	Debug("Entering OpenVPN TCP Server Main Loop.\n");
	while (true)
	{
		UINT next_interval;
		bool disconnected = false;
		UINT64 now = Tick64();

		// Receive data from a TCP socket
		while (true)
		{
			UINT r = Recv(sock, buf, buf_size, false);
			if (r == SOCK_LATER)
			{
				// Can not read any more
				break;
			}
			else if (r == 0)
			{
				// Disconnected
				disconnected = true;
				break;
			}
			else
			{
				// Read
				WriteFifo(tcp_recv_fifo, buf, r);
			}
		}

		// Separate to a list of datagrams by interpreting the data received from the TCP socket
		while (true)
		{
			UINT r = FifoSize(tcp_recv_fifo);
			if (r >= sizeof(USHORT))
			{
				void *ptr = FifoPtr(tcp_recv_fifo);
				USHORT packet_size = READ_USHORT(ptr);
				if (packet_size <= OPENVPN_TCP_MAX_PACKET_SIZE)
				{
					UINT total_len = (UINT)packet_size + sizeof(USHORT);
					if (r >= total_len)
					{
						if (ReadFifo(tcp_recv_fifo, buf, total_len) != total_len)
						{
							// Mismatch
							disconnected = true;
							break;
						}
						else
						{
							// Read one packet
							UINT payload_len = packet_size;
							UCHAR *payload_ptr = buf + sizeof(USHORT);

							// Pass the packet to the OpenVPN server
							Add(ovs_recv_packet, NewUdpPacket(&sock->RemoteIP, sock->RemotePort,
								&sock->LocalIP, sock->LocalPort,
								Clone(payload_ptr, payload_len), payload_len));
						}
					}
					else
					{
						// Non-arrival
						break;
					}
				}
				else
				{
					// Invalid packet size
					disconnected = true;
					break;
				}
			}
			else
			{
				// Non-arrival
				break;
			}
		}

		// Pass a list of received datagrams to the OpenVPN server
		OvsRecvPacket(s, ovs_recv_packet, OPENVPN_PROTOCOL_TCP);

		// Release the received packet list
		for (i = 0;i < LIST_NUM(ovs_recv_packet);i++)
		{
			UDPPACKET *p = LIST_DATA(ovs_recv_packet, i);

			FreeUdpPacket(p);
		}

		DeleteAll(ovs_recv_packet);

		// Store in the queue by getting a list of the datagrams to be transmitted from the OpenVPN server
		for (i = 0;i < LIST_NUM(s->SendPacketList);i++)
		{
			UDPPACKET *p = LIST_DATA(s->SendPacketList, i);
			// Store the size to the TCP send queue first
			USHORT us = (USHORT)p->Size;
			//Debug(" *** TCP SEND %u\n", us);
			us = Endian16(us);
			WriteFifo(tcp_send_fifo, &us, sizeof(USHORT));

			// Write the data body
			WriteFifo(tcp_send_fifo, p->Data, p->Size);

			// Packet release
			FreeUdpPacket(p);
		}
		DeleteAll(s->SendPacketList);

		// Send data to the TCP socket
		while (FifoSize(tcp_send_fifo) >= 1)
		{
			UINT r = Send(sock, FifoPtr(tcp_send_fifo), FifoSize(tcp_send_fifo), false);

			if (r == SOCK_LATER)
			{
				// Can not write any more
				break;
			}
			else if (r == 0)
			{
				// Disconnected
				disconnected = true;
				break;
			}
			else
			{
				// Wrote out
				ReadFifo(tcp_send_fifo, NULL, r);
			}
		}

		if (FifoSize(tcp_send_fifo) > MAX_BUFFERING_PACKET_SIZE)
		{
			s->SupressSendPacket = true;
		}
		else
		{
			s->SupressSendPacket = false;
		}

		if (s->DisconnectCount >= 1)
		{
			// Session disconnection has occurred on OpenVPN server-side
			disconnected = true;
		}

		if (giveup_time <= now)
		{
			UINT i;
			UINT num_established_sessions = 0;
			for (i = 0;i < LIST_NUM(s->SessionList);i++)
			{
				OPENVPN_SESSION *se = LIST_DATA(s->SessionList, i);

				if (se->Established)
				{
					num_established_sessions++;
				}
			}

			if (num_established_sessions == 0)
			{
				// If the number of sessions is 0 even if wait a certain period of time after the start of server, abort
				disconnected = true;
			}
		}

		if (disconnected)
		{
			// Error or disconnect occurs
			Debug("Breaking OpenVPN TCP Server Main Loop.\n");
			break;
		}

		// Wait until the next event occurs
		next_interval = GetNextIntervalForInterrupt(im);
		next_interval = MIN(next_interval, UDPLISTENER_WAIT_INTERVAL);
		WaitSockEvent(se, next_interval);
	}

	if (s != NULL && s->SessionEstablishedCount != 0)
	{
		ret = true;
	}

	// Release the OpenVPN server
	FreeOpenVpnServer(s);

	// Release object
	FreeInterruptManager(im);
	ReleaseSockEvent(se);
	ReleaseFifo(tcp_recv_fifo);
	ReleaseFifo(tcp_send_fifo);
	Free(buf);

	// Release the received packet list
	for (i = 0;i < LIST_NUM(ovs_recv_packet);i++)
	{
		UDPPACKET *p = LIST_DATA(ovs_recv_packet, i);

		FreeUdpPacket(p);
	}

	ReleaseList(ovs_recv_packet);

	return ret;
}




// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
