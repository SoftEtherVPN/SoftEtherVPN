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


// Interop_SSTP.c
// SSTP (Microsoft Secure Socket Tunneling Protocol) protocol stack

#include "CedarPch.h"

static bool g_no_sstp = false;

// Get the SSTP disabling flag
bool GetNoSstp()
{

	return g_no_sstp;
}

// Set the SSTP disabling flag
void SetNoSstp(bool b)
{
	g_no_sstp = b;
}

// Process the SSTP control packet reception
void SstpProcessControlPacket(SSTP_SERVER *s, SSTP_PACKET *p)
{
	// Validate arguments
	if (s == NULL || p == NULL || p->IsControl == false)
	{
		return;
	}

	Debug("SSTP Control Packet Recv: Msg = %u, Num = %u\n", p->MessageType, LIST_NUM(p->AttibuteList));

	switch (p->MessageType)
	{
	case SSTP_MSG_CALL_CONNECT_REQUEST:		// Receive a connection request from a client
		if (s->Aborting == false && s->Disconnecting == false)
		{
			if (s->Status == SSTP_SERVER_STATUS_REQUEST_PENGING)
			{
				SSTP_ATTRIBUTE *protocol_id = SstpFindAttribute(p, SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID);
				if (protocol_id != NULL && protocol_id->DataSize == 2 &&
					READ_USHORT(protocol_id->Data) == SSTP_ENCAPSULATED_PROTOCOL_PPP)
				{
					// Accept the connection request by the PPP protocol
					SSTP_PACKET *ret;

					// Generation of random numbers
					Rand(s->SentNonce, SSTP_NONCE_SIZE);

					ret = SstpNewControlPacketWithAnAttribute(SSTP_MSG_CALL_CONNECT_ACK,
						SstpNewCryptoBindingRequestAttribute(CERT_HASH_PROTOCOL_SHA256, s->SentNonce));

					SstpSendPacket(s, ret);

					SstpFreePacket(ret);

					s->Status = SSTP_SERVER_STATUS_CONNECTED_PENDING;

					s->EstablishedCount++;
				}
				else
				{
					// Refuse to accept for a connection request other than the PPP protocol
					SSTP_PACKET *ret = SstpNewControlPacketWithAnAttribute(SSTP_MSG_CALL_CONNECT_NAK,
						SstpNewStatusInfoAttribute(SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID, ATTRIB_STATUS_VALUE_NOT_SUPPORTED));

					SstpSendPacket(s, ret);

					SstpFreePacket(ret);
				}
			}
		}
		break;

	case SSTP_MSG_CALL_CONNECTED:			// Connection from the client complete
		if (s->Aborting == false && s->Disconnecting == false)
		{
			if (s->Status == SSTP_SERVER_STATUS_CONNECTED_PENDING)
			{
				s->Status = SSTP_SERVER_STATUS_ESTABLISHED;

				Debug("SSTP Connected.\n");
			}
		}
		break;

	case SSTP_MSG_CALL_DISCONNECT:			// Receive a disconnect request from the client
	case SSTP_MSG_CALL_DISCONNECT_ACK:
		s->DisconnectRecved = true;
		SstpDisconnect(s);
		break;

	case SSTP_MSG_CALL_ABORT:				// Receive a disconnect request from the client
		s->AbortReceived = true;
		SstpAbort(s);
		break;
	}
}

// Process the SSTP received data packet
void SstpProcessDataPacket(SSTP_SERVER *s, SSTP_PACKET *p)
{
	// Validate arguments
	if (s == NULL || p == NULL || p->IsControl)
	{
		return;
	}

	//Debug("SSTP Data Packet Recv: Size = %u\n", p->DataSize);

	if (s->PPPThread == NULL)
	{
		// Create a thread to initialize the new PPP module
		s->PPPThread = NewPPPSession(s->Cedar, &s->ClientIp, s->ClientPort, &s->ServerIp, s->ServerPort,
			s->TubeSend, s->TubeRecv, SSTP_IPC_POSTFIX, SSTP_IPC_CLIENT_NAME,
			s->ClientHostName, s->ClientCipherName, 0);
	}

	// Pass the received data to the PPP module
	TubeSendEx(s->TubeRecv, p->Data, p->DataSize, NULL, true);
	s->FlushRecvTube = true;
}

// Process the SSTP received packet
void SstpProcessPacket(SSTP_SERVER *s, SSTP_PACKET *p)
{
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	s->LastRecvTick = s->Now;

	if (p->IsControl)
	{
		// Control packet
		SstpProcessControlPacket(s, p);
	}
	else
	{
		// Data packet
		SstpProcessDataPacket(s, p);
	}
}

// Send a SSTP packet
void SstpSendPacket(SSTP_SERVER *s, SSTP_PACKET *p)
{
	BUF *b;
	BLOCK *block;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	if (p->IsControl)
	{
		Debug("SSTP Control Packet Send: Msg = %u, Num = %u\n", p->MessageType, LIST_NUM(p->AttibuteList));
	}
	else
	{
		//Debug("SSTP Data Packet Send: Size=%u\n", p->DataSize);
	}

	b = SstpBuildPacket(p);
	if (b == NULL)
	{
		return;
	}

	block = NewBlock(b->Buf, b->Size, 0);
	block->PriorityQoS = p->IsControl;
	Free(b);

	InsertQueue(s->SendQueue, block);
}

// Process the timer interrupt
void SstpProcessInterrupt(SSTP_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->Now = Tick64();

	s->FlushRecvTube = false;

	// Process the received packet
	while (true)
	{
		BLOCK *b = GetNext(s->RecvQueue);
		SSTP_PACKET *p;

		if (b == NULL)
		{
			break;
		}

		p = SstpParsePacket(b->Buf, b->Size);
		if (p == NULL)
		{
			// Disconnect the SSTP since a bad packet received
			SstpAbort(s);
		}
		else
		{
			// Process the received packet
			SstpProcessPacket(s, p);

			SstpFreePacket(p);
		}

		FreeBlock(b);
	}

	if (s->FlushRecvTube)
	{
		TubeFlush(s->TubeRecv);
	}

	// Transmit a packet that the PPP module is trying to send via the SSTP
	while (true)
	{
		TUBEDATA *d = TubeRecvAsync(s->TubeSend);
		SSTP_PACKET *p;
		if (d == NULL)
		{
			break;
		}

		p = SstpNewDataPacket(d->Data, d->DataSize);

		SstpSendPacket(s, p);

		SstpFreePacket(p);

		FreeTubeData(d);
	}

	if (s->Status == SSTP_SERVER_STATUS_ESTABLISHED)
	{
		if (s->Disconnecting == false && s->Aborting == false)
		{
			// Periodic transmission of Echo Request
			if (s->NextSendEchoRequestTick == 0 || s->NextSendEchoRequestTick <= s->Now)
			{
				UINT64 next_interval = (UINT64)(SSTP_ECHO_SEND_INTERVAL_MIN + Rand32() % (SSTP_ECHO_SEND_INTERVAL_MAX - SSTP_ECHO_SEND_INTERVAL_MIN));
				SSTP_PACKET *p;

				s->NextSendEchoRequestTick = s->Now + next_interval;
				AddInterrupt(s->Interrupt, s->NextSendEchoRequestTick);

				p = SstpNewControlPacket(SSTP_MSG_ECHO_REQUEST);

				SstpSendPacket(s, p);

				SstpFreePacket(p);
			}
		}
	}

	if ((s->LastRecvTick + (UINT64)SSTP_TIMEOUT) <= s->Now)
	{
		// Disconnect the SSTP because a timeout occurred
		SstpAbort(s);
		s->Disconnected = true;
	}

	if (IsTubeConnected(s->TubeRecv) == false || IsTubeConnected(s->TubeSend) == false)
	{
		// Disconnect the SSTP since the PPP module is disconnected
		SstpDisconnect(s);
	}

	if (s->Disconnecting)
	{
		// Normal disconnection process
		if (s->DisconnectSent == false)
		{
			// Send a Disconnect
			SSTP_PACKET *ret = SstpNewControlPacket(s->DisconnectRecved ? SSTP_MSG_CALL_DISCONNECT_ACK : SSTP_MSG_CALL_DISCONNECT);

			SstpSendPacket(s, ret);

			SstpFreePacket(ret);

			s->DisconnectSent = true;
		}
	}

	if (s->Aborting)
	{
		// Abnormal disconnection processing
		if (s->AbortSent == false)
		{
			// Send the Abort
			SSTP_PACKET *ret = SstpNewControlPacket(SSTP_MSG_CALL_ABORT);

			SstpSendPacket(s, ret);

			SstpFreePacket(ret);

			s->AbortSent = true;
		}
	}

	if (s->DisconnectSent && s->DisconnectRecved)
	{
		// Disconnect after exchanging the Disconnect each other
		s->Disconnected = true;
	}

	if (s->AbortSent && s->AbortReceived)
	{
		// Disconnect after exchanging the Abort each other
		s->Disconnected = true;
	}
}

// Create a new SSTP control packet with an Attribute
SSTP_PACKET *SstpNewControlPacketWithAnAttribute(USHORT message_type, SSTP_ATTRIBUTE *a)
{
	SSTP_PACKET *p = SstpNewControlPacket(message_type);

	if (a != NULL)
	{
		Add(p->AttibuteList, a);
	}

	return p;
}

// Create a new SSTP control packet
SSTP_PACKET *SstpNewControlPacket(USHORT message_type)
{
	SSTP_PACKET *p = ZeroMalloc(sizeof(SSTP_PACKET));

	p->IsControl = true;
	p->MessageType = message_type;
	p->Version = SSTP_VERSION_1;
	p->AttibuteList = NewListFast(NULL);

	return p;
}

// Create a new SSTP data packet
SSTP_PACKET *SstpNewDataPacket(UCHAR *data, UINT size)
{
	SSTP_PACKET *p = ZeroMalloc(sizeof(SSTP_PACKET));

	p->IsControl = false;
	p->Data = Clone(data, size);
	p->DataSize = size;

	return p;
}

// Get the Attibute with the specified ID from SSTP packet
SSTP_ATTRIBUTE *SstpFindAttribute(SSTP_PACKET *p, UCHAR attribute_id)
{
	UINT i;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(p->AttibuteList);i++)
	{
		SSTP_ATTRIBUTE *a = LIST_DATA(p->AttibuteList, i);

		if (a->AttributeId == attribute_id)
		{
			return a;
		}
	}

	return NULL;
}

// Disconnect the SSTP normally
void SstpDisconnect(SSTP_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->Disconnecting = true;
}

// Disconnect the SSTP abnormally
void SstpAbort(SSTP_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->Aborting = true;
}

// Create a Crypto Binding Request Attribute
SSTP_ATTRIBUTE *SstpNewCryptoBindingRequestAttribute(UCHAR hash_protocol_bitmask, UCHAR *nonce_32bytes)
{
	SSTP_ATTRIBUTE *a;
	UCHAR uc;
	BUF *b = NewBuf();

	uc = 0;
	WriteBuf(b, &uc, 1);
	WriteBuf(b, &uc, 1);
	WriteBuf(b, &uc, 1);
	WriteBuf(b, &hash_protocol_bitmask, 1);

	WriteBuf(b, nonce_32bytes, SSTP_NONCE_SIZE);

	a = SstpNewAttribute(SSTP_ATTRIB_CRYPTO_BINDING_REQ, b->Buf, b->Size);

	FreeBuf(b);

	return a;
}

// Create a Status Info Attribute
SSTP_ATTRIBUTE *SstpNewStatusInfoAttribute(UCHAR attrib_id, UINT status)
{
	SSTP_ATTRIBUTE *a;
	UCHAR uc;
	BUF *b = NewBuf();

	uc = 0;
	WriteBuf(b, &uc, 1);
	WriteBuf(b, &uc, 1);
	WriteBuf(b, &uc, 1);
	WriteBuf(b, &attrib_id, 1);

	WriteBufInt(b, status);

	a = SstpNewAttribute(SSTP_ATTRIB_STATUS_INFO, b->Buf, b->Size);

	FreeBuf(b);

	return a;
}

// Create a New Attribute
SSTP_ATTRIBUTE *SstpNewAttribute(UCHAR attribute_id, UCHAR *data, UINT data_size)
{
	SSTP_ATTRIBUTE *a = ZeroMalloc(sizeof(SSTP_ATTRIBUTE));

	a->AttributeId = attribute_id;
	a->Data = Clone(data, data_size);
	a->DataSize = data_size;

	return a;
}

// Build the Attribute
BUF *SstpBuildAttribute(SSTP_ATTRIBUTE *a)
{
	UCHAR uc;
	USHORT us;
	BUF *b;
	// Validate arguments
	if (a == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	// Reserved
	uc = 0;
	WriteBuf(b, &uc, sizeof(UCHAR));

	// Attribute ID
	uc = a->AttributeId;
	WriteBuf(b, &uc, sizeof(UCHAR));

	// LengthPacket
	a->TotalLength = a->DataSize + 4;
	us = (USHORT)a->TotalLength;
	us = Endian16(us);
	WriteBuf(b, &us, sizeof(USHORT));

	// Data
	WriteBuf(b, a->Data, a->DataSize);

	return b;
}

// Build the Attribute list
BUF *SstpBuildAttributeList(LIST *o, USHORT message_type)
{
	UINT i;
	BUF *b;
	USHORT us;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	us = Endian16(message_type);
	WriteBuf(b, &us, sizeof(USHORT));

	us = Endian16((USHORT)LIST_NUM(o));
	WriteBuf(b, &us, sizeof(USHORT));

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SSTP_ATTRIBUTE *a = LIST_DATA(o, i);
		BUF *ab = SstpBuildAttribute(a);

		if (ab != NULL)
		{
			WriteBufBuf(b, ab);

			FreeBuf(ab);
		}
	}

	return b;
}

// Building the SSTP packet
BUF *SstpBuildPacket(SSTP_PACKET *p)
{
	BUF *b;
	UCHAR uc;
	USHORT us;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	if (p->IsControl)
	{
		BUF *ab;

		if (p->Data != NULL)
		{
			Free(p->Data);
		}

		ab = SstpBuildAttributeList(p->AttibuteList, p->MessageType);
		p->Data = ab->Buf;
		p->DataSize = ab->Size;
		Free(ab);
	}

	// Version
	uc = SSTP_VERSION_1;
	WriteBuf(b, &uc, sizeof(UCHAR));

	// Flag
	uc = p->IsControl ? 1 : 0;
	WriteBuf(b, &uc, sizeof(UCHAR));

	// Length Packet
	us = Endian16(p->DataSize + 4);
	WriteBuf(b, &us, sizeof(USHORT));

	// Data
	WriteBuf(b, p->Data, p->DataSize);

	return b;
}

// Parse the SSTP packet
SSTP_PACKET *SstpParsePacket(UCHAR *data, UINT size)
{
	SSTP_PACKET *p;
	USHORT len;
	// Validate arguments
	if (data == NULL || size == 0)
	{
		return NULL;
	}

	if (size < 4)
	{
		return NULL;
	}

	p = ZeroMalloc(sizeof(SSTP_PACKET));

	// Version
	p->Version = *((UCHAR *)data);
	data++;
	size--;

	if (p->Version != SSTP_VERSION_1)
	{
		// Invalid version
		SstpFreePacket(p);
		return NULL;
	}

	// Flag
	if ((*((UCHAR *)data)) & 0x01)
	{
		p->IsControl = true;
	}
	data++;
	size--;

	// Length
	len = READ_USHORT(data) & 0xFFF;
	data += sizeof(USHORT);
	size -= sizeof(USHORT);

	if (len < 4)
	{
		// Invalid size
		SstpFreePacket(p);
		return NULL;
	}

	if (((UINT)(len - 4)) > size)
	{
		// Oversized
		SstpFreePacket(p);
		return NULL;
	}

	// Data
	p->DataSize = len - 4;
	p->Data = Clone(data, p->DataSize);

	if (p->IsControl)
	{
		// Parse the Attribute list
		p->AttibuteList = SstpParseAttributeList(p->Data, p->DataSize, p);

		if (p->AttibuteList == NULL)
		{
			// Failure of parsing list
			SstpFreePacket(p);
			return NULL;
		}
	}

	return p;
}

// Parse the Attribute list
LIST *SstpParseAttributeList(UCHAR *data, UINT size, SSTP_PACKET *p)
{
	LIST *o;
	USHORT us;
	UINT num;
	// Validate arguments
	if (size == 0 || data == NULL || p == NULL)
	{
		return NULL;
	}

	if (size < 4)
	{
		return NULL;
	}

	// Message Type
	us = READ_USHORT(data);
	p->MessageType = us;
	data += sizeof(USHORT);
	size -= sizeof(USHORT);

	// Num Attributes
	num = READ_USHORT(data);
	data += sizeof(USHORT);
	size -= sizeof(USHORT);

	// Attibutes List
	o = NewListFast(NULL);

	while (LIST_NUM(o) < num)
	{
		SSTP_ATTRIBUTE *a = SstpParseAttribute(data, size);

		if (a == NULL)
		{
			SstpFreeAttributeList(o);
			return NULL;
		}

		if (a->TotalLength > size)
		{
			SstpFreeAttribute(a);
			SstpFreeAttributeList(o);
			return NULL;
		}

		Add(o, a);

		data += a->TotalLength;
		size -= a->TotalLength;
	}

	return o;
}

// Parse the Attribute
SSTP_ATTRIBUTE *SstpParseAttribute(UCHAR *data, UINT size)
{
	SSTP_ATTRIBUTE *a;
	// Validate arguments
	if (data == NULL || size == 0)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(SSTP_ATTRIBUTE));

	if (size < 4)
	{
		SstpFreeAttribute(a);
		return NULL;
	}

	data++;
	size--;

	// Attribute ID
	a->AttributeId = *((UCHAR *)data);
	data++;
	size--;

	// Length
	a->TotalLength = READ_USHORT(data) & 0xFFF;
	data += sizeof(USHORT);
	size -= sizeof(USHORT);

	if (a->TotalLength < 4)
	{
		// Length fraud
		SstpFreeAttribute(a);
		return NULL;
	}

	a->DataSize = a->TotalLength - 4;
	if (a->DataSize > size)
	{
		// Length excess
		SstpFreeAttribute(a);
		return NULL;
	}

	a->Data = Clone(data, a->DataSize);

	return a;
}

// Release the Attibute
void SstpFreeAttribute(SSTP_ATTRIBUTE *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	Free(a->Data);

	Free(a);
}

// Release the Attribute list
void SstpFreeAttributeList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SSTP_ATTRIBUTE *a = LIST_DATA(o, i);

		SstpFreeAttribute(a);
	}

	ReleaseList(o);
}

// Release the SSTP packet
void SstpFreePacket(SSTP_PACKET *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->AttibuteList != NULL)
	{
		SstpFreeAttributeList(p->AttibuteList);
	}

	if (p->Data != NULL)
	{
		Free(p->Data);
	}

	Free(p);
}

// Create a SSTP server
SSTP_SERVER *NewSstpServer(CEDAR *cedar, IP *client_ip, UINT client_port, IP *server_ip,
						   UINT server_port, SOCK_EVENT *se,
						   char *client_host_name, char *crypt_name)
{
	SSTP_SERVER *s = ZeroMalloc(sizeof(SSTP_SERVER));

	s->LastRecvTick = Tick64();

	StrCpy(s->ClientHostName, sizeof(s->ClientHostName), client_host_name);
	StrCpy(s->ClientCipherName, sizeof(s->ClientCipherName), crypt_name);

	s->Cedar = cedar;
	AddRef(s->Cedar->ref);

	NewTubePair(&s->TubeSend, &s->TubeRecv, 0);
	SetTubeSockEvent(s->TubeSend, se);

	s->Now = Tick64();

	Copy(&s->ClientIp, client_ip, sizeof(IP));
	s->ClientPort = client_port;
	Copy(&s->ServerIp, server_ip, sizeof(IP));
	s->ServerPort = server_port;

	s->SockEvent = se;

	AddRef(s->SockEvent->ref);

	s->RecvQueue = NewQueueFast();
	s->SendQueue = NewQueueFast();

	s->Interrupt = NewInterruptManager();

	return s;
}

// Release the SSTP server
void FreeSstpServer(SSTP_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	TubeDisconnect(s->TubeRecv);
	TubeDisconnect(s->TubeSend);

	WaitThread(s->PPPThread, INFINITE);
	ReleaseThread(s->PPPThread);

	while (true)
	{
		BLOCK *b = GetNext(s->RecvQueue);

		if (b == NULL)
		{
			break;
		}

		FreeBlock(b);
	}

	while (true)
	{
		BLOCK *b = GetNext(s->SendQueue);

		if (b == NULL)
		{
			break;
		}

		FreeBlock(b);
	}

	ReleaseQueue(s->RecvQueue);
	ReleaseQueue(s->SendQueue);

	ReleaseSockEvent(s->SockEvent);

	FreeInterruptManager(s->Interrupt);

	ReleaseCedar(s->Cedar);

	ReleaseTube(s->TubeSend);
	ReleaseTube(s->TubeRecv);

	Free(s);
}

// Handle the communication of SSTP protocol
bool ProcessSstpHttps(CEDAR *cedar, SOCK *s, SOCK_EVENT *se)
{
	UINT tmp_size = 65536;
	UCHAR *tmp_buf;
	FIFO *recv_fifo;
	FIFO *send_fifo;
	SSTP_SERVER *sstp;
	bool ret = false;
	// Validate arguments
	if (cedar == NULL || s == NULL || se == NULL)
	{
		return false;
	}

	tmp_buf = Malloc(tmp_size);
	recv_fifo = NewFifo();
	send_fifo = NewFifo();

	sstp = NewSstpServer(cedar, &s->RemoteIP, s->RemotePort, &s->LocalIP, s->LocalPort, se,
		s->RemoteHostname, s->CipherName);

	while (true)
	{
		UINT r;
		bool is_disconnected = false;
		bool state_changed = false;

		// Receive data over SSL
		while (true)
		{
			r = Recv(s, tmp_buf, tmp_size, true);
			if (r == 0)
			{
				// SSL is disconnected
				is_disconnected = true;
				break;
			}
			else if (r == SOCK_LATER)
			{
				// Data is not received any more
				break;
			}
			else
			{
				// Queue the received data
				WriteFifo(recv_fifo, tmp_buf, r);
				state_changed = true;
			}
		}

		while (recv_fifo->size >= 4)
		{
			UCHAR *first4;
			UINT read_size = 0;
			bool ok = false;
			// Read 4 bytes from the beginning of the receive queue
			first4 = ((UCHAR *)recv_fifo->p) + recv_fifo->pos;
			if (first4[0] == SSTP_VERSION_1)
			{
				USHORT len = READ_USHORT(first4 + 2) & 0xFFF;
				if (len >= 4)
				{
					ok = true;

					if (recv_fifo->size >= len)
					{
						UCHAR *data;
						BLOCK *b;

						read_size = len;
						data = Malloc(read_size);

						ReadFifo(recv_fifo, data, read_size);

						b = NewBlock(data, read_size, 0);

						InsertQueue(sstp->RecvQueue, b);
					}
				}
			}

			if (read_size == 0)
			{
				break;
			}

			if (ok == false)
			{
				// Disconnect the connection since a bad packet received
				is_disconnected = true;
				break;
			}
		}

		// Process the timer interrupt
		SstpProcessInterrupt(sstp);

		if (sstp->Disconnected)
		{
			is_disconnected = true;
		}

		// Put the transmission data that SSTP module has generated into the transmission queue
		while (true)
		{
			BLOCK *b = GetNext(sstp->SendQueue);

			if (b == NULL)
			{
				break;
			}

			// When transmit a data packet, If there are packets of more than about
			// 2.5 MB in the transmission queue of the TCP, discard without transmission
			if (b->PriorityQoS || (send_fifo->size <= MAX_BUFFERING_PACKET_SIZE))
			{
				WriteFifo(send_fifo, b->Buf, b->Size);
			}

			FreeBlock(b);
		}

		// Data is transmitted over SSL
		while (send_fifo->size != 0)
		{
			r = Send(s, ((UCHAR *)send_fifo->p) + send_fifo->pos, send_fifo->size, true);
			if (r == 0)
			{
				// SSL is disconnected
				is_disconnected = true;
				break;
			}
			else if (r == SOCK_LATER)
			{
				// Can not send any more
				break;
			}
			else
			{
				// Advance the transmission queue by the amount of the transmitted
				ReadFifo(send_fifo, NULL, r);
				state_changed = true;
			}
		}

		if (is_disconnected)
		{
			// Disconnected
			break;
		}

		// Wait for the next state change
		if (state_changed == false)
		{
			UINT select_time = SELECT_TIME;
			UINT r = GetNextIntervalForInterrupt(sstp->Interrupt);
			WaitSockEvent(se, MIN(r, select_time));
		}
	}

	if (sstp != NULL && sstp->EstablishedCount >= 1)
	{
		ret = true;
	}

	FreeSstpServer(sstp);

	ReleaseFifo(recv_fifo);
	ReleaseFifo(send_fifo);
	Free(tmp_buf);

	YieldCpu();
	Disconnect(s);

	return ret;
}

// Accept the SSTP connection
bool AcceptSstp(CONNECTION *c)
{
	SOCK *s;
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	bool ret;
	bool ret2 = false;
	SOCK_EVENT *se;
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	s = c->FirstSock;

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	// Return a response
	h = NewHttpHeader("HTTP/1.1", "200", "OK");
	AddHttpValue(h, NewHttpValue("Content-Length", "18446744073709551615"));
	AddHttpValue(h, NewHttpValue("Server", "Microsoft-HTTPAPI/2.0"));
	AddHttpValue(h, NewHttpValue("Date", date_str));

	ret = PostHttp(s, h, NULL, 0);

	FreeHttpHeader(h);

	if (ret)
	{
		SetTimeout(s, INFINITE);

		se = NewSockEvent();

		JoinSockToSockEvent(s, se);

		Debug("ProcessSstpHttps Start.\n");
		ret2 = ProcessSstpHttps(c->Cedar, s, se);
		Debug("ProcessSstpHttps End.\n");

		ReleaseSockEvent(se);
	}

	Disconnect(s);

	return ret2;
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
