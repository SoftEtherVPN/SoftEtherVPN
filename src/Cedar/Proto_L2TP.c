// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_L2TP.c
// L2TP protocol stack

#include "Proto_L2TP.h"

#include "Connection.h"
#include "Logging.h"
#include "Proto_EtherIP.h"
#include "Proto_IKE.h"
#include "Proto_IPsec.h"
#include "Proto_PPP.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

// Release the L2TP AVP value
void FreeL2TPAVP(L2TP_AVP *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (a->Data != NULL)
	{
		Free(a->Data);
	}

	Free(a);
}

// Release the L2TP packet
void FreeL2TPPacket(L2TP_PACKET *p)
{
	UINT i;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->AvpList != NULL)
	{
		for (i = 0;i < LIST_NUM(p->AvpList);i++)
		{
			L2TP_AVP *a = LIST_DATA(p->AvpList, i);

			FreeL2TPAVP(a);
		}

		ReleaseList(p->AvpList);
	}

	if (p->Data != NULL)
	{
		Free(p->Data);
	}

	Free(p);
}

// Send an L2TP control packet
void SendL2TPControlPacket(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, UINT session_id, L2TP_PACKET *p)
{
	BUF *buf;
	L2TP_QUEUE *q;
	// Validate arguments
	if (l2tp == NULL || t == NULL || p == NULL)
	{
		return;
	}

	p->IsControl = true;
	p->TunnelId = t->TunnelId1;
	p->SessionId = session_id;

	p->Ns = t->NextNs;
	t->NextNs++;

	p->Nr = t->LastNr + 1;

	buf = BuildL2TPPacketData(p, t);

	q = ZeroMalloc(sizeof(L2TP_QUEUE));
	q->Buf = buf;
	q->Ns = p->Ns;
	q->NextSendTick = l2tp->Now + (UINT64)L2TP_PACKET_RESEND_INTERVAL;
	SendL2TPControlPacketMain(l2tp, t, q);

	L2TPAddInterrupt(l2tp, q->NextSendTick);

	Add(t->SendQueue, q);

}

// Specify the interrupt occurrence time of the next
void L2TPAddInterrupt(L2TP_SERVER *l2tp, UINT64 next_tick)
{
	// Validate arguments
	if (l2tp == NULL || next_tick == 0)
	{
		return;
	}

	AddInterrupt(l2tp->Interrupts, next_tick);
}

// Send a L2TP data packet
void SendL2TPDataPacket(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s, void *data, UINT size)
{
	UDPPACKET *p;
	UCHAR *buf;
	UINT buf_size;
	// Validate arguments
	if (l2tp == NULL || t == NULL || s == NULL || (size != 0 && data == NULL))
	{
		return;
	}

	// Build a L2TP data packet
	if (s->IsV3 == false)
	{
		// L2TP Ver 2
		buf_size = 8 + size;
		buf = Malloc(buf_size);
		buf[0] = 0x40;
		buf[1] = 0x02;

		WRITE_USHORT(buf + 2, buf_size);
		WRITE_USHORT(buf + 4, t->TunnelId1);
		WRITE_USHORT(buf + 6, s->SessionId1);

		Copy(buf + 8, data, size);

		// Transmission
		p = NewUdpPacket(&t->ServerIp, t->ServerPort, &t->ClientIp, t->ClientPort, buf, buf_size);
	}
	else
	{
		// L2TPv3
		if (t->IsYamahaV3 == false)
		{
			buf_size = 4 + size;
			buf = Malloc(buf_size);

			WRITE_UINT(buf, s->SessionId1);

			Copy(buf + 4, data, size);

			// Transmission
			p = NewUdpPacket(&t->ServerIp, IPSEC_PORT_L2TPV3_VIRTUAL, &t->ClientIp, IPSEC_PORT_L2TPV3_VIRTUAL, buf, buf_size);
		}
		else
		{
			UINT header = 0x00030000;

			buf_size = 8 + size;
			buf = Malloc(buf_size);

			WRITE_UINT(buf, header);
			WRITE_UINT(buf + 4, s->SessionId1);

			Copy(buf + 8, data, size);

			// Transmission
			p = NewUdpPacket(&t->ServerIp, t->ServerPort, &t->ClientIp, t->ClientPort, buf, buf_size);
		}
	}

	L2TPSendUDP(l2tp, p);
}

// L2TP packet transmission main
void SendL2TPControlPacketMain(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_QUEUE *q)
{
	UDPPACKET *p;
	// Validate arguments
	if (l2tp == NULL || t == NULL || q == NULL)
	{
		return;
	}

	p = NewUdpPacket(&t->ServerIp, t->ServerPort, &t->ClientIp, t->ClientPort,
		Clone(q->Buf->Buf, q->Buf->Size), q->Buf->Size);

	// Update the received sequence number
	WRITE_USHORT(((UCHAR *)p->Data) + (p->SrcPort == IPSEC_PORT_L2TPV3_VIRTUAL ? 14 : 10), t->LastNr + 1);

	L2TPSendUDP(l2tp, p);
}

// Send a UDP packet
void L2TPSendUDP(L2TP_SERVER *l2tp, UDPPACKET *p)
{
	// Validate arguments
	if (l2tp == NULL || p == NULL)
	{
		return;
	}

	Add(l2tp->SendPacketList, p);
}

// Build a L2TP packet
BUF *BuildL2TPPacketData(L2TP_PACKET *pp, L2TP_TUNNEL *t)
{
	BUF *ret;
	UCHAR c;
	USHORT us;
	UINT ui;
	// Validate arguments
	if (pp == NULL || t == NULL)
	{
		return NULL;
	}

	ret = NewBuf();

	c = 0;

	if (pp->Ver == 3)
	{
		if (pp->SessionId != 0)
		{
			// Add the Remote Session ID AVP
			L2TP_AVP *a = GetAVPValue(pp, L2TP_AVP_TYPE_V3_SESSION_ID_REMOTE);
			if (a == NULL || a->DataSize != sizeof(UINT))
			{
				UINT ui = Endian32(pp->SessionId);
				Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_V3_SESSION_ID_REMOTE, true, 0, &ui, sizeof(UINT)));

				if (GetAVPValueEx(pp, L2TPV3_CISCO_AVP_SESSION_ID_LOCAL, L2TP_AVP_VENDOR_ID_CISCO) != NULL)
				{
					Add(pp->AvpList, NewAVP(L2TPV3_CISCO_AVP_SESSION_ID_REMOTE, true, L2TP_AVP_VENDOR_ID_CISCO, &ui, sizeof(UINT)));
				}
			}
		}
	}

	if (pp->Ver == 3)
	{
		if (t->IsYamahaV3 == false)
		{
			// Zero as Session ID
			ui = 0;
			WriteBuf(ret, &ui, sizeof(UINT));
		}
	}

	// Flags
	if (pp->IsControl)
	{
		c |= L2TP_HEADER_BIT_TYPE;
		c |= L2TP_HEADER_BIT_LENGTH;
		c |= L2TP_HEADER_BIT_SEQUENCE;
	}
	else
	{
		c |= L2TP_HEADER_BIT_OFFSET;
	}

	if (pp->IsControl == false && pp->Ver == 3 && t->IsYamahaV3)
	{
		c = 0;
	}

	WriteBuf(ret, &c, 1);

	// Ver
	c = 2;
	if (pp->Ver == 3)
	{
		c = 3;
	}
	WriteBuf(ret, &c, 1);

	// Length
	if (pp->IsControl)
	{
		us = 0;
		WriteBuf(ret, &us, sizeof(USHORT));
	}

	// Reserved
	if (pp->IsControl == false && pp->Ver == 3 && t->IsYamahaV3)
	{
		us = 0;
		WriteBuf(ret, &us, sizeof(USHORT));
	}

	// Tunnel ID
	if (pp->Ver != 3)
	{
		us = Endian16((USHORT)pp->TunnelId);
		WriteBuf(ret, &us, sizeof(USHORT));
	}
	else
	{
		ui = Endian32(pp->TunnelId);
		WriteBuf(ret, &ui, sizeof(UINT));
	}

	// Session ID
	if (pp->Ver != 3)
	{
		us = Endian16((USHORT)pp->SessionId);
		WriteBuf(ret, &us, sizeof(USHORT));
	}

	if (pp->IsControl)
	{
		// Ns
		us = Endian16(pp->Ns);
		WriteBuf(ret, &us, sizeof(USHORT));

		// Nr
		us = Endian16(pp->Nr);
		WriteBuf(ret, &us, sizeof(USHORT));
	}
	else
	{
		if (!(pp->IsControl == false && pp->Ver == 3 && t->IsYamahaV3))
		{
			// Offset Size = 0
			us = 0;
			WriteBuf(ret, &us, sizeof(USHORT));
		}
	}

	if (pp->IsControl)
	{
		// AVP
		UINT i;
		for (i = 0;i < LIST_NUM(pp->AvpList);i++)
		{
			L2TP_AVP *a = LIST_DATA(pp->AvpList, i);

			// Length and Flags
			us = Endian16(a->DataSize + 6);

			if (a->Mandatory)
			{
				*((UCHAR *)&us) |= L2TP_AVP_BIT_MANDATORY;
			}

			WriteBuf(ret, &us, sizeof(USHORT));

			// Vendor ID
			us = Endian16(a->VendorID);
			WriteBuf(ret, &us, sizeof(USHORT));

			// Type
			us = Endian16(a->Type);
			WriteBuf(ret, &us, sizeof(USHORT));

			// Data
			WriteBuf(ret, a->Data, a->DataSize);
		}
	}
	else
	{
		// Payload
		WriteBuf(ret, pp->Data, pp->DataSize);
	}

	if (pp->IsControl)
	{
		// Update Length
		bool l2tpv3_non_yamaha = ((pp->Ver == 3) && (t->IsYamahaV3 == false));
		WRITE_USHORT(((UCHAR *)ret->Buf) + 2 + (l2tpv3_non_yamaha ? sizeof(UINT) : 0), (USHORT)(ret->Size - (l2tpv3_non_yamaha ? sizeof(UINT) : 0)));
	}

	SeekBuf(ret, 0, 0);

	return ret;
}

// Parse the L2TP packet
L2TP_PACKET *ParseL2TPPacket(UDPPACKET *p)
{
	L2TP_PACKET *ret;
	UCHAR *buf;
	UINT size;
	bool is_l2tpv3 = false;
	bool is_l2tpv3_yamaha = false;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(L2TP_PACKET));

	if (p->SrcPort == IPSEC_PORT_L2TPV3_VIRTUAL)
	{
		// L2TPv3 (Cisco)
		is_l2tpv3 = true;
	}

	buf = p->Data;
	size = p->Size;

	if (size >= 2 && ((buf[1] & L2TP_HEADER_BIT_VER) == 3))
	{
		if (p->SrcPort != IPSEC_PORT_L2TPV3_VIRTUAL)
		{
			// L2TPv3 (YAMAHA)
			is_l2tpv3 = true;
			is_l2tpv3_yamaha = true;
		}
	}

	if (is_l2tpv3 && (is_l2tpv3_yamaha == false))
	{
		// L2TPv3 (Cisco)
		UINT session_id;
		if (size < 4)
		{
			goto LABEL_ERROR;
		}

		session_id = READ_UINT(buf);

		if (session_id != 0)
		{
			// L2TPv3 data packet reception
			ret->SessionId = session_id;

			buf += sizeof(UINT);
			size -= sizeof(UINT);

			ret->Data = Clone(buf, size);
			ret->DataSize = size;

			ret->Ver = 3;

			return ret;
		}
		else
		{
			// L2TPv3 control packet reception
			buf += sizeof(UINT);
			size -= sizeof(UINT);
		}
	}

	// L2TP
	if (size < 6)
	{
		goto LABEL_ERROR;
	}

	if (*buf & L2TP_HEADER_BIT_TYPE)
	{
		ret->IsControl = true;
	}

	if (*buf & L2TP_HEADER_BIT_LENGTH)
	{
		ret->HasLength = true;
	}

	if (*buf & L2TP_HEADER_BIT_SEQUENCE)
	{
		ret->HasSequence = true;
	}

	if (is_l2tpv3 == false)
	{
		if (*buf & L2TP_HEADER_BIT_OFFSET)
		{
			ret->HasOffset = true;
		}

		if (*buf & L2TP_HEADER_BIT_PRIORITY)
		{
			ret->IsPriority = true;
		}
	}

	buf++;
	size--;

	ret->Ver = *buf & L2TP_HEADER_BIT_VER;

	buf++;
	size--;

	if (is_l2tpv3 == false)
	{
		// L2TP
		if (ret->Ver != 2)
		{
			goto LABEL_ERROR;
		}
	}
	else
	{
		// L2TPv3
		if (ret->Ver != 3)
		{
			goto LABEL_ERROR;
		}
	}

	if (ret->IsControl)
	{
		if (ret->HasLength == false || ret->HasSequence == false)
		{
			goto LABEL_ERROR;
		}
	}
	else
	{
		/*if (ret->HasSequence)
		{
			goto LABEL_ERROR;
		}*/
	}

	if (ret->HasLength)
	{
		// Length
		if (size < 2)
		{
			goto LABEL_ERROR;
		}
		ret->Length = READ_USHORT(buf);
		buf += 2;
		size -= 2;

		if (size < (ret->Length - 4))
		{
			goto LABEL_ERROR;
		}

		size = ret->Length - 4;
	}

	if (is_l2tpv3)
	{
		if (p->SrcPort != IPSEC_PORT_L2TPV3_VIRTUAL)
		{
			if (ret->IsControl == false)
			{
				// Reserved
				if (size < 2)
				{
					goto LABEL_ERROR;
				}

				buf += 2;
				size -= 2;
			}
		}
	}

	// Tunnel ID, Session ID
	if (size < 4)
	{
		goto LABEL_ERROR;
	}

	if (is_l2tpv3 == false)
	{
		// L2TP
		ret->TunnelId = READ_USHORT(buf);
		buf += 2;
		size -= 2;

		ret->SessionId = READ_USHORT(buf);
		buf += 2;
		size -= 2;
	}
	else
	{
		// L2TPv3: Only tunnel ID is written in the header
		ret->TunnelId = READ_UINT(buf);
		buf += 4;
		size -= 4;

		// The session ID is not written in the header
		ret->SessionId = 0;

		if (ret->IsControl == false)
		{
			ret->SessionId = ret->TunnelId;
		}
	}

	if (ret->HasSequence)
	{
		// Ns, Nr
		if (size < 4)
		{
			goto LABEL_ERROR;
		}

		ret->Ns = READ_USHORT(buf);
		buf += 2;
		size -= 2;

		ret->Nr = READ_USHORT(buf);
		buf += 2;
		size -= 2;
	}

	if (ret->HasOffset)
	{
		// Offset
		if (size < 2)
		{
			goto LABEL_ERROR;
		}

		ret->OffsetSize = READ_USHORT(buf);
		buf += 2;
		size -= 2;

		if (size < ret->OffsetSize)
		{
			goto LABEL_ERROR;
		}

		buf += ret->OffsetSize;
		size -= ret->OffsetSize;
	}

	ret->DataSize = size;
	ret->Data = Clone(buf, ret->DataSize);

	if (ret->IsControl == false)
	{
		if (ret->DataSize == 0)
		{
			goto LABEL_ERROR;
		}
	}

	if (ret->IsControl)
	{
		if (ret->DataSize == 0)
		{
			ret->IsZLB = true;
		}
	}

	if (ret->IsControl)
	{
		ret->AvpList = NewListFast(NULL);

		// Parse the AVP field
		while (size != 0)
		{
			L2TP_AVP a;

			Zero(&a, sizeof(a));

			// Header
			if (size < 6)
			{
				goto LABEL_ERROR;
			}

			if (*buf & L2TP_AVP_BIT_MANDATORY)
			{
				a.Mandatory = true;
			}

			if (*buf & L2TP_AVP_BIT_HIDDEN)
			{
				goto LABEL_ERROR;
			}

			a.Length = READ_USHORT(buf) & L2TP_AVP_LENGTH;

			if (a.Length < 6)
			{
				goto LABEL_ERROR;
			}

			buf += 2;
			size -= 2;

			a.VendorID = READ_USHORT(buf);
			buf += 2;
			size -= 2;

			a.Type = READ_USHORT(buf);
			buf += 2;
			size -= 2;

			a.DataSize = a.Length - 6;

			if (a.DataSize > size)
			{
				goto LABEL_ERROR;
			}

			a.Data = Clone(buf, a.DataSize);

			buf += a.DataSize;
			size -= a.DataSize;

			Add(ret->AvpList, Clone(&a, sizeof(a)));
		}
	}

	if (ret->IsControl && ret->IsZLB == false)
	{
		// Get the MessageType in the case of Control packet
		L2TP_AVP *a = GetAVPValue(ret, L2TP_AVP_TYPE_MESSAGE_TYPE);
		if (a == NULL || a->DataSize != 2)
		{
			goto LABEL_ERROR;
		}

		ret->MessageType = READ_USHORT(a->Data);
	}

	if (ret->Ver == 3 && ret->IsControl)
	{
		// Get the Remote Session ID in the case of L2TPv3
		L2TP_AVP *a = GetAVPValue(ret, L2TP_AVP_TYPE_V3_SESSION_ID_REMOTE);
		if (a != NULL && a->DataSize == sizeof(UINT))
		{
			ret->SessionId = READ_UINT(a->Data);
		}
	}

	ret->IsYamahaV3 = is_l2tpv3_yamaha;

	return ret;

LABEL_ERROR:
	FreeL2TPPacket(ret);
	return NULL;
}

// Get the AVP value
L2TP_AVP *GetAVPValue(L2TP_PACKET *p, UINT type)
{
	return GetAVPValueEx(p, type, 0);
}
L2TP_AVP *GetAVPValueEx(L2TP_PACKET *p, UINT type, UINT vendor_id)
{
	UINT i;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(p->AvpList);i++)
	{
		L2TP_AVP *a = LIST_DATA(p->AvpList, i);

		if (a->Type == type && a->VendorID == vendor_id)
		{
			return a;
		}
	}

	if (vendor_id == 0)
	{
		if (type == L2TP_AVP_TYPE_V3_TUNNEL_ID)
		{
			return GetAVPValueEx(p, L2TPV3_CISCO_AVP_TUNNEL_ID, L2TP_AVP_VENDOR_ID_CISCO);
		}
		else if (type == L2TP_AVP_TYPE_V3_SESSION_ID_LOCAL)
		{
			return GetAVPValueEx(p, L2TPV3_CISCO_AVP_SESSION_ID_LOCAL, L2TP_AVP_VENDOR_ID_CISCO);
		}
		else if (type == L2TP_AVP_TYPE_V3_SESSION_ID_REMOTE)
		{
			return GetAVPValueEx(p, L2TPV3_CISCO_AVP_SESSION_ID_REMOTE, L2TP_AVP_VENDOR_ID_CISCO);
		}
	}

	return NULL;
}

// Release the L2TP transmission queue
void FreeL2TPQueue(L2TP_QUEUE *q)
{
	// Validate arguments
	if (q == NULL)
	{
		return;
	}

	FreeBuf(q->Buf);

	FreeL2TPPacket(q->L2TPPacket);

	Free(q);
}

// Sort function of L2TP reception queue
int CmpL2TPQueueForRecv(void *p1, void *p2)
{
	L2TP_QUEUE *q1, *q2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	q1 = *(L2TP_QUEUE **)p1;
	q2 = *(L2TP_QUEUE **)p2;
	if (q1 == NULL || q2 == NULL)
	{
		return 0;
	}

	if (L2TP_SEQ_LT(q1->Ns, q2->Ns))
	{
		return -1;
	}
	else if (q1->Ns == q2->Ns)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

// Create a L2TP tunnel
L2TP_TUNNEL *NewL2TPTunnel(L2TP_SERVER *l2tp, L2TP_PACKET *p, UDPPACKET *udp)
{
	L2TP_TUNNEL *t;
	L2TP_AVP *a;
	// Validate arguments
	if (l2tp == NULL || p == NULL || udp == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(L2TP_TUNNEL));

	if (p->Ver == 3)
	{
		t->IsV3 = true;
	}

	t->SessionList = NewList(NULL);

	Copy(&t->ClientIp, &udp->SrcIP, sizeof(IP));
	t->ClientPort = udp->SrcPort;

	Copy(&t->ServerIp, &udp->DstIP, sizeof(IP));
	t->ServerPort = udp->DestPort;

	// Hostname
	a = GetAVPValue(p, L2TP_AVP_TYPE_HOST_NAME);
	if (a != NULL && a->DataSize >= 1 && a->DataSize < sizeof(t->HostName))
	{
		Copy(t->HostName, a->Data, a->DataSize);
	}
	else
	{
		IPToStr(t->HostName, sizeof(t->HostName), &t->ClientIp);
	}

	// Vendor Name
	a = GetAVPValue(p, L2TP_AVP_TYPE_VENDOR_NAME);
	if (a != NULL && a->DataSize >= 1 && a->DataSize < sizeof(t->VendorName))
	{
		Copy(t->VendorName, a->Data, a->DataSize);
	}

	// Assigned Tunnel ID
	a = GetAVPValue(p, (p->Ver == 3 ? L2TP_AVP_TYPE_V3_TUNNEL_ID : L2TP_AVP_TYPE_ASSIGNED_TUNNEL));
	if (a == NULL || a->DataSize != (t->IsV3 ? sizeof(UINT) : sizeof(USHORT)))
	{
		goto LABEL_ERROR;
	}

	t->TunnelId1 = (t->IsV3 ? READ_UINT(a->Data) : READ_USHORT(a->Data));
	t->TunnelId2 = GenerateNewTunnelIdEx(l2tp, &t->ClientIp, t->IsV3);

	if (t->TunnelId2 == 0)
	{
		goto LABEL_ERROR;
	}

	if (p->Ver == 3)
	{
		// Identify whether it's Cisco
		a = GetAVPValueEx(p, L2TPV3_CISCO_AVP_TUNNEL_ID, L2TP_AVP_VENDOR_ID_CISCO);
		if (a != NULL)
		{
			t->IsCiscoV3 = true;
		}

		// L2TPv3 on YAMAHA
		t->IsYamahaV3 = p->IsYamahaV3;
	}

	// Transmission queue
	t->SendQueue = NewList(NULL);

	// Reception queue
	t->RecvQueue = NewList(CmpL2TPQueueForRecv);

	t->LastRecvTick = l2tp->Now;
	t->LastHelloSent = l2tp->Now;

	return t;

LABEL_ERROR:
	FreeL2TPTunnel(t);
	return NULL;
}

// Search a tunnel
L2TP_TUNNEL *GetTunnelFromId(L2TP_SERVER *l2tp, IP *client_ip, UINT tunnel_id, bool is_v3)
{
	UINT i;
	// Validate arguments
	if (l2tp == NULL || client_ip == 0 || tunnel_id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(l2tp->TunnelList);i++)
	{
		L2TP_TUNNEL *t = LIST_DATA(l2tp->TunnelList, i);

		if (t->TunnelId2 == tunnel_id && CmpIpAddr(&t->ClientIp, client_ip) == 0)
		{
			if (EQUAL_BOOL(t->IsV3, is_v3))
			{
				return t;
			}
		}
	}

	return NULL;
}

// Search the tunnel by the tunnel ID that is assigned by the client
L2TP_TUNNEL *GetTunnelFromIdOfAssignedByClient(L2TP_SERVER *l2tp, IP *client_ip, UINT tunnel_id)
{
	UINT i;
	// Validate arguments
	if (l2tp == NULL || client_ip == 0 || tunnel_id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(l2tp->TunnelList);i++)
	{
		L2TP_TUNNEL *t = LIST_DATA(l2tp->TunnelList, i);

		if (t->TunnelId1 == tunnel_id && CmpIpAddr(&t->ClientIp, client_ip) == 0)
		{
			return t;
		}
	}

	return NULL;
}
L2TP_TUNNEL *GetTunnelFromIdOfAssignedByClientEx(L2TP_SERVER *l2tp, IP *client_ip, UINT tunnel_id, bool is_v3)
{
	UINT i;
	// Validate arguments
	if (l2tp == NULL || client_ip == 0 || tunnel_id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(l2tp->TunnelList);i++)
	{
		L2TP_TUNNEL *t = LIST_DATA(l2tp->TunnelList, i);

		if (t->TunnelId1 == tunnel_id && CmpIpAddr(&t->ClientIp, client_ip) == 0)
		{
			if (EQUAL_BOOL(t->IsV3, is_v3))
			{
				return t;
			}
		}
	}

	return NULL;
}

// Create a new tunnel ID
UINT GenerateNewTunnelId(L2TP_SERVER *l2tp, IP *client_ip)
{
	return GenerateNewTunnelIdEx(l2tp, client_ip, false);
}
UINT GenerateNewTunnelIdEx(L2TP_SERVER *l2tp, IP *client_ip, bool is_32bit)
{
	UINT id;
	UINT max_number = 0xffff;
	// Validate arguments
	if (l2tp == NULL || client_ip == NULL)
	{
		return 0;
	}

	if (is_32bit)
	{
		max_number = 0xfffffffe;
	}

	for (id = 1;id <= max_number;id++)
	{
		if (GetTunnelFromId(l2tp, client_ip, id, is_32bit) == NULL)
		{
			return id;
		}
	}

	return 0;
}

// Release the L2TP tunnel
void FreeL2TPTunnel(L2TP_TUNNEL *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->SessionList);i++)
	{
		L2TP_SESSION *s = LIST_DATA(t->SessionList, i);

		FreeL2TPSession(s);
	}

	ReleaseList(t->SessionList);

	for (i = 0;i < LIST_NUM(t->SendQueue);i++)
	{
		L2TP_QUEUE *q = LIST_DATA(t->SendQueue, i);

		FreeL2TPQueue(q);
	}

	ReleaseList(t->SendQueue);

	for (i = 0;i < LIST_NUM(t->RecvQueue);i++)
	{
		L2TP_QUEUE *q = LIST_DATA(t->RecvQueue, i);

		FreeL2TPQueue(q);
	}

	ReleaseList(t->RecvQueue);

	Free(t);
}

// Generate a new L2TP control packet
L2TP_PACKET *NewL2TPControlPacket(UINT message_type, bool is_v3)
{
	L2TP_PACKET *p = ZeroMalloc(sizeof(L2TP_PACKET));

	p->IsControl = true;
	p->HasLength = true;
	p->HasSequence = true;
	p->Ver = (is_v3 ? 3 : 2);
	p->MessageType = message_type;

	p->AvpList = NewListFast(NULL);

	if (message_type != 0)
	{
		L2TP_AVP *a;
		USHORT us;

		a = ZeroMalloc(sizeof(L2TP_AVP));

		a->Type = L2TP_AVP_TYPE_MESSAGE_TYPE;
		a->Mandatory = true;

		us = Endian16(message_type);
		a->Data = Clone(&us, sizeof(USHORT));
		a->DataSize = sizeof(USHORT);

		Add(p->AvpList, a);
	}

	return p;
}

// Create a new AVP value
L2TP_AVP *NewAVP(USHORT type, bool mandatory, USHORT vendor_id, void *data, UINT data_size)
{
	L2TP_AVP *a;
	// Validate arguments
	if (data_size != 0 && data == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(L2TP_AVP));

	a->Type = type;
	a->Mandatory = mandatory;
	a->VendorID = vendor_id;
	a->Data = Clone(data, data_size);
	a->DataSize = data_size;

	return a;
}

// Process a received L2TP packet
void L2TPProcessRecvControlPacket(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_PACKET *p)
{
	// Validate arguments
	if (l2tp == NULL || t == NULL || p == NULL)
	{
		return;
	}

	if (p->SessionId == 0)
	{
		if (p->MessageType == L2TP_MESSAGE_TYPE_SCCCN && l2tp->Halt == false)
		{
			// Tunnel establishment completed
			if (t->Established == false)
			{
				if (t->Disconnecting == false)
				{
					t->Established = true;
					t->LastHelloSent = l2tp->Now;
				}
			}
		}

		if (t->Established)
		{
			if (p->MessageType == L2TP_MESSAGE_TYPE_ICRQ && t->WantToDisconnect == false && l2tp->Halt == false)
			{
				// Request to establish a new session arrives
				L2TP_AVP *a = GetAVPValue(p,
					(t->IsV3 ? L2TP_AVP_TYPE_V3_SESSION_ID_LOCAL : L2TP_AVP_TYPE_ASSIGNED_SESSION));
				if (a != NULL && a->DataSize == (t->IsV3 ? sizeof(UINT) : sizeof(USHORT)) && IsZero(a->Data, (t->IsV3 ? sizeof(UINT) : sizeof(USHORT))) == false)
				{
					UINT session_id = (t->IsV3 ? READ_UINT(a->Data) : READ_USHORT(a->Data));

					// Check whether there is other same session ID
					if (GetSessionFromIdAssignedByClient(t, session_id) == NULL)
					{
						// Create a session
						L2TP_SESSION *s = NewL2TPSession(l2tp, t, session_id);

						if (s != NULL)
						{
							L2TP_PACKET *pp;
							USHORT us;
							UINT ui;

							// Get the PseudowireType
							if (t->IsV3)
							{
								s->PseudowireType = L2TPV3_PW_TYPE_ETHERNET;

								a = GetAVPValue(p, L2TP_AVP_TYPE_V3_PW_TYPE);

								if (a != NULL && a->DataSize == sizeof(USHORT))
								{
									ui = READ_USHORT(a->Data);

									s->PseudowireType = ui;
								}
							}

							Add(t->SessionList, s);
							Debug("L2TP New Session: ID = %u/%u on Tunnel %u/%u\n", s->SessionId1, s->SessionId2,
								t->TunnelId1, t->TunnelId2);

							// Respond the session creation completion notice
							pp = NewL2TPControlPacket(L2TP_MESSAGE_TYPE_ICRP, s->IsV3);

							// Assigned Session AVP
							if (s->IsV3 == false)
							{
								us = Endian16(s->SessionId2);
								Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_ASSIGNED_SESSION, true, 0, &us, sizeof(USHORT)));
							}
							else
							{
								ui = Endian32(s->SessionId2);
								Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_V3_SESSION_ID_LOCAL, true, 0, &ui, sizeof(UINT)));

								if (s->IsCiscoV3)
								{
									Add(pp->AvpList, NewAVP(L2TPV3_CISCO_AVP_SESSION_ID_LOCAL, true, L2TP_AVP_VENDOR_ID_CISCO, &ui, sizeof(UINT)));
								}
							}

							if (s->IsV3)
							{
								if (t->IsYamahaV3 == false)
								{
									// Pseudowire AVP
									us = Endian16(s->PseudowireType);
									Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_V3_PW_TYPE, true, 0, &us, sizeof(USHORT)));
								}

								if (s->IsCiscoV3)
								{
									Add(pp->AvpList, NewAVP(L2TPV3_CISCO_AVP_PW_TYPE, true, L2TP_AVP_VENDOR_ID_CISCO, &us, sizeof(USHORT)));
								}

								if (t->IsYamahaV3)
								{
									us = Endian16(0x0003);
									Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_V3_CIRCUIT_STATUS, true, 0, &us, sizeof(USHORT)));
								}
							}

							SendL2TPControlPacket(l2tp, t, session_id, pp);

							FreeL2TPPacket(pp);
						}
					}
				}
			}
			else if (p->MessageType == L2TP_MESSAGE_TYPE_STOPCCN)
			{
				// Tunnel disconnect request arrives
				L2TP_AVP *a = GetAVPValue(p, (t->IsV3 ? L2TP_AVP_TYPE_V3_TUNNEL_ID : L2TP_AVP_TYPE_ASSIGNED_TUNNEL));
				if (a != NULL && a->DataSize == (t->IsV3 ? sizeof(UINT) : sizeof(USHORT)))
				{
					UINT ui = (t->IsV3 ? READ_UINT(a->Data) : READ_USHORT(a->Data));

					if (ui == t->TunnelId1)
					{
						// Disconnect the tunnel
						DisconnectL2TPTunnel(t);
					}
				}
			}
		}
	}
	else
	{
		// Search a session
		L2TP_SESSION *s = GetSessionFromId(t, p->SessionId);

		if (s != NULL)
		{
			if (s->Established == false)
			{
				if (p->MessageType == L2TP_MESSAGE_TYPE_ICCN)
				{
					// Session establishment completed
					if (s->Disconnecting == false)
					{
						s->Established = true;
					}
				}
			}
			else
			{
				if (p->MessageType == L2TP_MESSAGE_TYPE_CDN)
				{
					// Received a session disconnection request
					L2TP_AVP *a = GetAVPValue(p,
						(t->IsV3 ? L2TP_AVP_TYPE_V3_SESSION_ID_LOCAL : L2TP_AVP_TYPE_ASSIGNED_SESSION));
					if (a != NULL && a->DataSize == (t->IsV3 ? sizeof(UINT) : sizeof(USHORT)))
					{
						UINT ui = (t->IsV3 ? READ_UINT(a->Data) : READ_USHORT(a->Data));

						if (ui == s->SessionId1)
						{
							// Disconnect the session
							DisconnectL2TPSession(t, s);
						}
					}
				}
			}
		}
		else
		{
			Debug("Session ID %u not found in Tunnel ID %u/%u\n", p->SessionId, t->TunnelId1, t->TunnelId2);
		}
	}
}

// Disconnect the L2TP tunnel
void DisconnectL2TPTunnel(L2TP_TUNNEL *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (/*t->Established && */t->Disconnecting == false && t->WantToDisconnect == false)
	{
		UINT i;

		Debug("Trying to Disconnect Tunnel ID %u/%u\n", t->TunnelId1, t->TunnelId2);
		t->WantToDisconnect = true;

		// Disconnect all sessions within the tunnel
		for (i = 0;i < LIST_NUM(t->SessionList);i++)
		{
			L2TP_SESSION *s = LIST_DATA(t->SessionList, i);

			DisconnectL2TPSession(t, s);
		}
	}
}

// Disconnect the L2TP session
void DisconnectL2TPSession(L2TP_TUNNEL *t, L2TP_SESSION *s)
{
	// Validate arguments
	if (t == NULL || s == NULL)
	{
		return;
	}

	if (s->Established && s->Disconnecting == false && s->WantToDisconnect == false)
	{
		Debug("Trying to Disconnect Session ID %u/%u on Tunnel %u/%u\n", s->SessionId1, s->SessionId2,
			t->TunnelId1, t->TunnelId2);
		s->WantToDisconnect = true;
	}
}

// Create a new session
L2TP_SESSION *NewL2TPSession(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, UINT session_id_by_client)
{
	L2TP_SESSION *s;
	UINT session_id_by_server;
	// Validate arguments
	if (l2tp == NULL || t == NULL || session_id_by_client == 0)
	{
		return NULL;
	}

	if (LIST_NUM(t->SessionList) >= L2TP_QUOTA_MAX_NUM_SESSIONS_PER_TUNNEL)
	{
		return NULL;
	}

	if (t->IsV3 == false)
	{
		session_id_by_server = GenerateNewSessionIdEx(t, t->IsV3);
	}
	else
	{
		session_id_by_server = GenerateNewSessionIdForL2TPv3(l2tp);
	}
	if (session_id_by_server == 0)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(L2TP_SESSION));

	s->SessionId1 = session_id_by_client;
	s->SessionId2 = session_id_by_server;

	s->IsV3 = t->IsV3;
	s->IsCiscoV3 = t->IsCiscoV3;

	s->Tunnel = t;

	return s;
}

// Retrieve a session from L2TP session ID
L2TP_SESSION *SearchL2TPSessionById(L2TP_SERVER *l2tp, bool is_v3, UINT id)
{
	UINT i, j;
	// Validate arguments
	if (l2tp == NULL || id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(l2tp->TunnelList);i++)
	{
		L2TP_TUNNEL *t = LIST_DATA(l2tp->TunnelList, i);

		for (j = 0;j < LIST_NUM(t->SessionList);j++)
		{
			L2TP_SESSION *s = LIST_DATA(t->SessionList, j);

			if (s->SessionId2 == id)
			{
				if (EQUAL_BOOL(s->IsV3, is_v3))
				{
					return s;
				}
			}
		}
	}

	return NULL;
}

// Create a new session ID
UINT GenerateNewSessionId(L2TP_TUNNEL *t)
{
	return GenerateNewSessionIdEx(t, false);
}
UINT GenerateNewSessionIdEx(L2TP_TUNNEL *t, bool is_32bit)
{
	UINT i;
	UINT max_number = 0xffff;
	// Validate arguments
	if (t == NULL)
	{
		return 0;
	}

	if (is_32bit)
	{
		max_number = 0xfffffffe;
	}

	for (i = 1;i <= max_number;i++)
	{
		if (GetSessionFromId(t, i) == NULL)
		{
			return i;
		}
	}

	return 0;
}
UINT GenerateNewSessionIdForL2TPv3(L2TP_SERVER *l2tp)
{
	// Validate arguments
	if (l2tp == NULL)
	{
		return 0;
	}

	while (true)
	{
		UINT id = Rand32();

		if (id == 0 || id == 0xffffffff)
		{
			continue;
		}

		if (SearchL2TPSessionById(l2tp, true, id) == false)
		{
			return id;
		}
	}
}

// Release the session
void FreeL2TPSession(L2TP_SESSION *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Free(s);
}

// Search a session from the session ID
L2TP_SESSION *GetSessionFromId(L2TP_TUNNEL *t, UINT session_id)
{
	UINT i;
	// Validate arguments
	if (t == NULL || session_id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(t->SessionList);i++)
	{
		L2TP_SESSION *s = LIST_DATA(t->SessionList, i);

		if (s->SessionId2 == session_id)
		{
			return s;
		}
	}

	return NULL;
}

// Search a session from the session ID (Search by ID assigned from the client side)
L2TP_SESSION *GetSessionFromIdAssignedByClient(L2TP_TUNNEL *t, UINT session_id)
{
	UINT i;
	// Validate arguments
	if (t == NULL || session_id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(t->SessionList);i++)
	{
		L2TP_SESSION *s = LIST_DATA(t->SessionList, i);

		if (s->SessionId1 == session_id)
		{
			return s;
		}
	}

	return NULL;
}

// Get the number of L2TP sessions connected from the client IP address
UINT GetNumL2TPTunnelsByClientIP(L2TP_SERVER *l2tp, IP *client_ip)
{
	UINT i, ret;
	// Validate arguments
	if (l2tp == NULL || client_ip == NULL)
	{
		return 0;
	}

	ret = 0;

	for (i = 0;i < LIST_NUM(l2tp->TunnelList);i++)
	{
		L2TP_TUNNEL *t = LIST_DATA(l2tp->TunnelList, i);

		if (CmpIpAddr(&t->ClientIp, client_ip) == 0)
		{
			ret++;
		}
	}

	return ret;
}

// Performs processing L2TP received packets.
void ProcL2TPPacketRecv(L2TP_SERVER *l2tp, UDPPACKET *p)
{
	L2TP_PACKET *pp;
	bool no_free = false;
	// Validate arguments
	if (l2tp == NULL || p == NULL)
	{
		return;
	}

	// Parse a packet.
	pp = ParseL2TPPacket(p);
	if (pp == NULL)
	{
		return;
	}

	if (pp->MessageType == L2TP_MESSAGE_TYPE_SCCRQ && pp->SessionId == 0 && pp->TunnelId == 0 &&
		pp->Nr == 0 && pp->Ns == 0 && l2tp->Halt == false)
	{
		{
			L2TP_AVP *a = GetAVPValue(pp, (pp->Ver == 3 ? L2TP_AVP_TYPE_V3_TUNNEL_ID : L2TP_AVP_TYPE_ASSIGNED_TUNNEL));
			if (a != NULL && a->DataSize == (pp->Ver == 3 ? sizeof(UINT) : sizeof(USHORT)))
			{
				UINT client_assigned_id = (pp->Ver == 3 ? READ_UINT(a->Data) : READ_USHORT(a->Data));
				if (GetTunnelFromIdOfAssignedByClient(l2tp, &p->SrcIP, client_assigned_id) == NULL)
				{
					if (LIST_NUM(l2tp->TunnelList) < L2TP_QUOTA_MAX_NUM_TUNNELS && GetNumL2TPTunnelsByClientIP(l2tp, &p->SrcIP) < L2TP_QUOTA_MAX_NUM_TUNNELS_PER_IP)
					{
						char ipstr[MAX_SIZE];
						L2TP_PACKET *pp2;
						UCHAR protocol_version[2];
						UCHAR caps_data[4];
						USHORT us;
						char hostname[MAX_SIZE];

						// Begin Tunneling
						L2TP_TUNNEL *t = NewL2TPTunnel(l2tp, pp, p);

						if (t != NULL)
						{
							IPToStr(ipstr, sizeof(ipstr), &t->ClientIp);
							Debug("L2TP New Tunnel From %s (%s, %s): New Tunnel ID = %u/%u\n", ipstr, t->HostName, t->VendorName,
								t->TunnelId1, t->TunnelId2);

							// Add the tunnel to the list
							Add(l2tp->TunnelList, t);

							// Respond with SCCEP to SCCRQ
							pp2 = NewL2TPControlPacket(L2TP_MESSAGE_TYPE_SCCRP, t->IsV3);

							if (t->IsYamahaV3 == false)
							{
								// Protocol Version
								protocol_version[0] = 1;
								protocol_version[1] = 0;
								Add(pp2->AvpList, NewAVP(L2TP_AVP_TYPE_PROTOCOL_VERSION, true, 0, protocol_version, sizeof(protocol_version)));

								// Framing Capabilities
								Zero(caps_data, sizeof(caps_data));
								if (t->IsV3 == false)
								{
									caps_data[3] = 3;
								}
								Add(pp2->AvpList, NewAVP(L2TP_AVP_TYPE_FRAME_CAP, false, 0, caps_data, sizeof(caps_data)));
							}

							if (t->IsV3 == false)
							{
								// Bearer Capabilities
								Zero(caps_data, sizeof(caps_data));
								caps_data[3] = 3;
								Add(pp2->AvpList, NewAVP(L2TP_AVP_TYPE_BEARER_CAP, false, 0, caps_data, sizeof(caps_data)));
							}

							// Host Name
							GetMachineHostName(hostname, sizeof(hostname));
							if (IsEmptyStr(hostname))
							{
								StrCpy(hostname, sizeof(hostname), "vpn");
							}
							Add(pp2->AvpList, NewAVP(L2TP_AVP_TYPE_HOST_NAME, true, 0, hostname, StrLen(hostname)));

							// Vendor Name
							if (t->IsYamahaV3 == false)
							{
								Add(pp2->AvpList, NewAVP(L2TP_AVP_TYPE_VENDOR_NAME, false, 0, L2TP_VENDOR_NAME, StrLen(L2TP_VENDOR_NAME)));
							}
							else
							{
								char *yamaha_str = "YAMAHA Corporation";
								Add(pp2->AvpList, NewAVP(L2TP_AVP_TYPE_VENDOR_NAME, false, 0, yamaha_str, StrLen(yamaha_str)));
							}

							if (t->IsYamahaV3)
							{
								UINT zero = 0;
								Add(pp2->AvpList, NewAVP(L2TP_AVP_TYPE_V3_ROUTER_ID, true, 0, &zero, sizeof(UINT)));
							}

							// Assigned Tunnel ID
							if (t->IsV3 == false)
							{
								us = Endian16(t->TunnelId2);
								Add(pp2->AvpList, NewAVP(L2TP_AVP_TYPE_ASSIGNED_TUNNEL, true, 0, &us, sizeof(USHORT)));
							}
							else
							{
								UINT ui = Endian32(t->TunnelId2);
								Add(pp2->AvpList, NewAVP(L2TP_AVP_TYPE_V3_TUNNEL_ID, true, 0, &ui, sizeof(UINT)));

								if (t->IsCiscoV3)
								{
									Add(pp2->AvpList, NewAVP(L2TPV3_CISCO_AVP_TUNNEL_ID, true, L2TP_AVP_VENDOR_ID_CISCO, &ui, sizeof(UINT)));
								}
							}

							// Pseudowire Capabilities List
							if (t->IsV3)
							{
								// Only Ethernet
								USHORT cap_list[2];
								cap_list[0] = Endian16(L2TPV3_PW_TYPE_ETHERNET);
								cap_list[1] = Endian16(L2TPV3_PW_TYPE_ETHERNET_VLAN);
								Add(pp2->AvpList, NewAVP(L2TP_AVP_TYPE_V3_PW_CAP_LIST, true, 0, cap_list, sizeof(cap_list)));

								if (t->IsCiscoV3)
								{
									Add(pp2->AvpList, NewAVP(L2TPV3_CISCO_AVP_PW_CAP_LIST, true, L2TP_AVP_VENDOR_ID_CISCO, cap_list, sizeof(cap_list)));
								}
							}

							// Cisco AVP
							if (t->IsCiscoV3)
							{
								USHORT us = Endian16(1);
								Add(pp2->AvpList, NewAVP(L2TPV3_CISCO_AVP_DRAFT_AVP_VERSION, true, L2TP_AVP_VENDOR_ID_CISCO, &us, sizeof(USHORT)));
							}

							// Recv Window Size
							if (t->IsYamahaV3 == false)
							{
								us = Endian16(L2TP_WINDOW_SIZE);
								Add(pp2->AvpList, NewAVP(L2TP_AVP_TYPE_RECV_WINDOW_SIZE, false, 0, &us, sizeof(USHORT)));
							}

							SendL2TPControlPacket(l2tp, t, 0, pp2);

							FreeL2TPPacket(pp2);
						}
					}
				}
			}
		}
	}
	else
	{
		// Process related to the existing tunnel
		// Find the tunnel
		L2TP_TUNNEL *t = NULL;
		L2TP_SESSION *l2tpv3_session = NULL;

		if (pp->IsControl || pp->Ver != 3)
		{
			t = GetTunnelFromId(l2tp, &p->SrcIP, pp->TunnelId, pp->Ver == 3);
		}
		else
		{
			l2tpv3_session = SearchL2TPSessionById(l2tp, true, pp->SessionId);
			if (l2tpv3_session != NULL)
			{
				t = l2tpv3_session->Tunnel;

				pp->TunnelId = t->TunnelId2;
			}
		}

		if (t == NULL)
		{
			char ipstr[MAX_SIZE];

			IPToStr(ipstr, sizeof(ipstr), &p->SrcIP);
			Debug("L2TP Tunnel From %s ID=%u Not Found on the Table.\n", ipstr, pp->TunnelId);
		}
		else
		{
			// Update last reception time
			t->LastRecvTick = l2tp->Now;

			if (pp->IsControl)
			{
				// Control packet
				UINT i;
				LIST *o = NULL;
				L2TP_QUEUE *q;
				L2TP_QUEUE tt;

				// Delete the queue that the other party has already received from the retransmission queue
				for (i = 0;i < LIST_NUM(t->SendQueue);i++)
				{
					L2TP_QUEUE *q = LIST_DATA(t->SendQueue, i);
					if (L2TP_SEQ_LT(q->Ns, pp->Nr))
					{
						if (o == NULL)
						{
							o = NewListFast(NULL);
						}

						Add(o, q);
					}
				}

				if (o != NULL)
				{
					for (i = 0;i < LIST_NUM(o);i++)
					{
						L2TP_QUEUE *q = LIST_DATA(o, i);

						Delete(t->SendQueue, q);

						FreeL2TPQueue(q);
					}

					ReleaseList(o);
				}

				if ((!L2TP_SEQ_LT(pp->Ns, t->LastNr)) && (pp->Ns != t->LastNr))
				{
					// Add the packet received from the opposite to the queue
					if (LIST_NUM(t->RecvQueue) < L2TP_WINDOW_SIZE)
					{
						Zero(&tt, sizeof(tt));
						tt.Ns = pp->Ns;

						if (Search(t->RecvQueue, &tt) == NULL)
						{
							q = ZeroMalloc(sizeof(L2TP_QUEUE));
							q->Ns = pp->Ns;
							q->L2TPPacket = pp;
							no_free = true;
							Insert(t->RecvQueue, q);

							// Read to the end of completed part from the head of the queue
							while (true)
							{
								L2TP_QUEUE *q;
								if (LIST_NUM(t->RecvQueue) == 0)
								{
									break;
								}

								q = LIST_DATA(t->RecvQueue, 0);
								if (!L2TP_SEQ_EQ(q->Ns, t->LastNr + 1))
								{
									break;
								}

								if (q->L2TPPacket->IsZLB == false)
								{
									t->LastNr = q->Ns;

									// The packet other than ZLB is treated
									t->StateChanged = true;
								}

								Delete(t->RecvQueue, q);

								// Process the received packet
								L2TPProcessRecvControlPacket(l2tp, t, q->L2TPPacket);

								FreeL2TPQueue(q);
							}
						}
					}
				}
				else
				{
					// Reply ACK for already-received packets
					if (pp->IsZLB == false)
					{
						// The packet other than ZLB is treated
						t->StateChanged = true;
					}
				}
			}
			else
			{
				// Data packet
				L2TP_SESSION *s = GetSessionFromId(t, pp->SessionId);

				if (s != NULL && s->Established)
				{
					if (s->IsV3 == false)
					{
						// Start the L2TP thread (If not already started)
						StartL2TPThread(l2tp, t, s);

						// Pass the data
						TubeSendEx(s->TubeRecv, pp->Data, pp->DataSize, NULL, true);
						AddTubeToFlushList(l2tp->FlushList, s->TubeRecv);
					}
					else
					{
						BLOCK *b;

						// Start the EtherIP session (If it's not have yet started)
						L2TPSessionManageEtherIPServer(l2tp, s);

						// Pass the data
						b = NewBlock(pp->Data, pp->DataSize, 0);

						EtherIPProcRecvPackets(s->EtherIP, b);

						Free(b);
					}
				}
			}
		}
	}

	if (no_free == false)
	{
		FreeL2TPPacket(pp);
	}
}

// Manage the EtherIP server that is associated with the L2TP session
void L2TPSessionManageEtherIPServer(L2TP_SERVER *l2tp, L2TP_SESSION *s)
{
	IKE_SERVER *ike;
	IKE_CLIENT *c;
	// Validate arguments
	if (l2tp == NULL || s == NULL)
	{
		return;
	}

	if (l2tp->IkeClient == NULL || l2tp->IkeServer == NULL)
	{
		return;
	}

	ike = l2tp->IkeServer;
	c = l2tp->IkeClient;

	if (s->EtherIP == NULL)
	{
		char crypt_name[MAX_SIZE];
		UINT crypt_block_size = IKE_MAX_BLOCK_SIZE;

		Zero(crypt_name, sizeof(crypt_name));

		if (c->CurrentIpSecSaRecv != NULL)
		{
			Format(crypt_name, sizeof(crypt_name),
				"IPsec - %s (%u bits)",
				c->CurrentIpSecSaRecv->TransformSetting.Crypto->Name,
				c->CurrentIpSecSaRecv->TransformSetting.CryptoKeySize * 8);

			crypt_block_size = c->CurrentIpSecSaRecv->TransformSetting.Crypto->BlockSize;
		}

		s->EtherIP = NewEtherIPServer(ike->Cedar, ike->IPsec, ike,
			&c->ClientIP, c->ClientPort,
			&c->ServerIP, c->ServerPort, crypt_name,
			c->IsL2TPOnIPsecTunnelMode, crypt_block_size, c->ClientId,
			++ike->CurrentEtherId);

		StrCpy(s->EtherIP->VendorName, sizeof(s->EtherIP->VendorName), s->Tunnel->VendorName);

		s->EtherIP->L2TPv3 = true;

		Debug("IKE_CLIENT 0x%X: EtherIP Server Started.\n", c);

		IPsecLog(ike, c, NULL, NULL, NULL, "LI_ETHERIP_SERVER_STARTED", ike->CurrentEtherId);
	}
	else
	{
		StrCpy(s->EtherIP->ClientId, sizeof(s->EtherIP->ClientId), c->ClientId);
	}

	if (s->EtherIP->Interrupts == NULL)
	{
		s->EtherIP->Interrupts = l2tp->Interrupts;
	}

	if (s->EtherIP->SockEvent == NULL)
	{
		SetEtherIPServerSockEvent(s->EtherIP, l2tp->SockEvent);
	}

	s->EtherIP->Now = l2tp->Now;
}

// Calculate the appropriate MSS of the L2TP
UINT CalcL2TPMss(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s)
{
	UINT ret;
	// Validate arguments
	if (l2tp == NULL || t == NULL || s == NULL)
	{
		return 0;
	}

	ret = MTU_FOR_PPPOE;

	if (l2tp->IkeServer != NULL)
	{
		// On IPsec
		if (l2tp->IsIPsecIPv6)
		{
			ret -= 40;
		}
		else
		{
			ret -= 20;
		}

		// UDP
		ret -= 8;

		// ESP
		ret -= 20 + l2tp->CryptBlockSize * 2;
	}
	else
	{
		// Raw L2TP
		if (IsIP6(&t->ClientIp))
		{
			ret -= 40;
		}
		else
		{
			ret -= 20;
		}
	}

	// L2TP UDP
	ret -= 8;

	// L2TP
	ret -= 8;

	// PPP
	ret -= 4;

	// Target communication
	ret -= 20;

	// TCP header
	ret -= 20;

	return ret;
}

// Start the L2TP thread
void StartL2TPThread(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s)
{
	// Validate arguments
	if (l2tp == NULL || t == NULL || s == NULL)
	{
		return;
	}

	if (s->HasThread == false)
	{
		char tmp[MAX_SIZE];

		Debug("Thread Created for Session %u/%u on Tunnel %u/%u\n",
			s->SessionId1, s->SessionId2, t->TunnelId1, t->TunnelId2);

		s->HasThread = true;

		NewTubePair(&s->TubeSend, &s->TubeRecv, 0);
		SetTubeSockEvent(s->TubeSend, l2tp->SockEvent);

		if (IsEmptyStr(t->VendorName) == false)
		{
			Format(tmp, sizeof(tmp), L2TP_IPC_CLIENT_NAME_TAG, t->VendorName);
		}
		else
		{
			StrCpy(tmp, sizeof(tmp), L2TP_IPC_CLIENT_NAME_NO_TAG);
		}

		// Create a PPP thread
		s->Thread = NewPPPSession(l2tp->Cedar, &t->ClientIp, t->ClientPort, &t->ServerIp, t->ServerPort,
			s->TubeSend, s->TubeRecv, L2TP_IPC_POSTFIX, tmp, t->HostName, l2tp->CryptName,
			CalcL2TPMss(l2tp, t, s));
	}
}

// Stop the L2TP thread
void StopL2TPThread(L2TP_SERVER *l2tp, L2TP_TUNNEL *t, L2TP_SESSION *s)
{
	THREAD *thread;
	// Validate arguments
	if (l2tp == NULL || t == NULL || s == NULL)
	{
		return;
	}

	if (s->IsV3)
	{
		// Process the L2TPv3
		if (s->EtherIP != NULL)
		{
			// Release the EtherIP server
			ReleaseEtherIPServer(s->EtherIP);
			s->EtherIP = NULL;
		}
		return;
	}

	if (s->HasThread == false)
	{
		return;
	}
	thread = s->Thread;
	s->Thread = NULL;
	s->HasThread = false;

	// Disconnect the tube
	TubeDisconnect(s->TubeRecv);
	TubeDisconnect(s->TubeSend);

	// Release the tube
	ReleaseTube(s->TubeRecv);
	ReleaseTube(s->TubeSend);

	s->TubeRecv = NULL;
	s->TubeSend = NULL;

	// Pass the thread to termination list
	if (l2tp->IkeServer == NULL)
	{
		AddThreadToThreadList(l2tp->ThreadList, thread);
	}
	else
	{
		AddThreadToThreadList(l2tp->IkeServer->ThreadList, thread);
	}

	Debug("Thread Stopped for Session %u/%u on Tunnel %u/%u\n",
		s->SessionId1, s->SessionId2, t->TunnelId1, t->TunnelId2);

	// Release the thread
	ReleaseThread(thread);
}

// Interrupt processing of L2TP server
void L2TPProcessInterrupts(L2TP_SERVER *l2tp)
{
	UINT i, j;
	LIST *delete_tunnel_list = NULL;
	// Validate arguments
	if (l2tp == NULL)
	{
		return;
	}

	if (l2tp->Halt)
	{
		if (l2tp->Halting == false)
		{
			l2tp->Halting = true;

			// Disconnect all tunnels
			for (i = 0;i < LIST_NUM(l2tp->TunnelList);i++)
			{
				L2TP_TUNNEL *t = LIST_DATA(l2tp->TunnelList, i);

				DisconnectL2TPTunnel(t);
			}
		}
	}

	// Flush
	FlushTubeFlushList(l2tp->FlushList);

	// Enumerate all tunnels
	for (i = 0;i < LIST_NUM(l2tp->TunnelList);i++)
	{
		L2TP_TUNNEL *t = LIST_DATA(l2tp->TunnelList, i);
		LIST *delete_session_list = NULL;
		UINT64 l2tpTimeout = L2TP_TUNNEL_TIMEOUT;

		// If we got on ANY session a higher timeout than the default L2TP tunnel timeout, increase it
		for (i = 0; i < LIST_NUM(t->SessionList); i++)
		{
			L2TP_SESSION* s = LIST_DATA(t->SessionList, i);

			if (s->TubeRecv != NULL && s->TubeRecv->DataTimeout > l2tpTimeout)
			{
				l2tpTimeout = s->TubeRecv->DataTimeout;
			}
		}


		if ((l2tp->Now >= (t->LastRecvTick + (UINT64)l2tpTimeout)) && t->Timedout == false)
		{
			// Disconnect the tunnel forcibly if data can not be received for a certain period of time
			t->Timedout = true;

			Debug("L2TP Tunnel %u/%u Timed out.\n", t->TunnelId1, t->TunnelId2);
			DisconnectL2TPTunnel(t);
		}

		if (t->Established && (l2tp->Now >= (t->LastHelloSent + (UINT64)L2TP_HELLO_INTERVAL)))
		{
			if (LIST_NUM(t->SendQueue) <= L2TP_HELLO_SUPRESS_MAX_THRETHORD_NUM_SEND_QUEUE)
			{
				L2TP_PACKET *pp = NewL2TPControlPacket(L2TP_MESSAGE_TYPE_HELLO, t->IsV3);

				// Send a Hello message
				t->LastHelloSent = l2tp->Now;
				//Debug("L2TP Sending Hello %u/%u: tick=%I64u\n", t->TunnelId1, t->TunnelId2, l2tp->Now);

				SendL2TPControlPacket(l2tp, t, 0, pp);

				FreeL2TPPacket(pp);

				L2TPAddInterrupt(l2tp, t->LastHelloSent + (UINT64)L2TP_HELLO_INTERVAL);
			}
		}

		// Enumerate all sessions
		for (j = 0;j < LIST_NUM(t->SessionList);j++)
		{
			L2TP_SESSION *s = LIST_DATA(t->SessionList, j);

			if (s->HasThread)
			{
				// Send packet data
				while (true)
				{
					TUBEDATA *d = TubeRecvAsync(s->TubeSend);

					if (d == NULL)
					{
						break;
					}

					SendL2TPDataPacket(l2tp, t, s, d->Data, d->DataSize);

					FreeTubeData(d);
				}

				if (IsTubeConnected(s->TubeSend) == false)
				{
					// Disconnect the this session because the PPP thread ends
					DisconnectL2TPSession(t, s);
				}
			}

			if (s->IsV3)
			{
				if (s->EtherIP != NULL)
				{
					UINT k;

					L2TPSessionManageEtherIPServer(l2tp, s);

					// Notify an interrupt to the EtherIP module
					EtherIPProcInterrupts(s->EtherIP);

					// Send an EtherIP packet data
					for (k = 0;k < LIST_NUM(s->EtherIP->SendPacketList);k++)
					{
						BLOCK *b = LIST_DATA(s->EtherIP->SendPacketList, k);

						SendL2TPDataPacket(l2tp, t, s, b->Buf, b->Size);

						FreeBlock(b);
					}

					DeleteAll(s->EtherIP->SendPacketList);
				}
			}

			if (s->WantToDisconnect && s->Disconnecting == false)
			{
				// Disconnect the session
				UCHAR error_data[4];
				USHORT us;
				UINT ui;
				UINT ppp_error_1 = 0, ppp_error_2 = 0;

				// Send the session disconnection response
				L2TP_PACKET *pp = NewL2TPControlPacket(L2TP_MESSAGE_TYPE_CDN, s->IsV3);

				if (s->TubeRecv != NULL)
				{
					ppp_error_1 = s->TubeRecv->IntParam1;
					ppp_error_2 = s->TubeRecv->IntParam2;
				}

				// Assigned Session ID
				if (s->IsV3 == false)
				{
					us = Endian16(s->SessionId2);
					Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_ASSIGNED_SESSION, true, 0,
						&us, sizeof(USHORT)));
				}
				else
				{
					ui = Endian16(s->SessionId2);
					Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_V3_SESSION_ID_LOCAL, true, 0,
						&ui, sizeof(UINT)));

					if (t->IsCiscoV3)
					{
						Add(pp->AvpList, NewAVP(L2TPV3_CISCO_AVP_SESSION_ID_LOCAL, true, L2TP_AVP_VENDOR_ID_CISCO,
							&ui, sizeof(UINT)));
					}
				}

				// Result-Error Code
				Zero(error_data, sizeof(error_data));
				error_data[1] = 0x03;
				Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_RESULT_CODE, true, 0,
					error_data, sizeof(error_data)));

				if (ppp_error_1 != 0)
				{
					// PPP Disconnect Cause Code AVP
					BUF *b = NewBuf();
					UCHAR uc;
					USHORT us;

					// Disconnect Code
					us = Endian16(ppp_error_1);
					WriteBuf(b, &us, sizeof(USHORT));

					// Control Protocol Number
					us = Endian16(0xc021);
					WriteBuf(b, &us, sizeof(USHORT));

					// Direction
					uc = (UCHAR)ppp_error_2;
					WriteBuf(b, &uc, sizeof(UCHAR));

					Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_PPP_DISCONNECT_CAUSE, false, 0,
						b->Buf, b->Size));

					FreeBuf(b);
				}

				SendL2TPControlPacket(l2tp, t, s->SessionId1, pp);

				FreeL2TPPacket(pp);

				// Disconnect the session
				Debug("L2TP Session %u/%u on Tunnel %u/%u Disconnected.\n", s->SessionId1, s->SessionId2,
					t->TunnelId1, t->TunnelId2);
				s->Disconnecting = true;
				s->Established = false;
				s->DisconnectTimeout = l2tp->Now + (UINT64)L2TP_TUNNEL_DISCONNECT_TIMEOUT;

				// Stop the thread
				StopL2TPThread(l2tp, t, s);

				L2TPAddInterrupt(l2tp, s->DisconnectTimeout);
			}

			if (s->Disconnecting && ((l2tp->Now >= s->DisconnectTimeout) || LIST_NUM(t->SendQueue) == 0))
			{
				// Delete the session if synchronization between the client
				// and the server is complete or a time-out occurs
				if (delete_session_list == NULL)
				{
					delete_session_list = NewListFast(NULL);
				}

				Add(delete_session_list, s);
			}
		}

		if (delete_session_list != NULL)
		{
			// Session deletion process
			for (j = 0;j < LIST_NUM(delete_session_list);j++)
			{
				L2TP_SESSION *s = LIST_DATA(delete_session_list, j);

				Debug("L2TP Session %u/%u on Tunnel %u/%u Cleaned up.\n", s->SessionId1, s->SessionId2,
					t->TunnelId1, t->TunnelId2);

				FreeL2TPSession(s);
				Delete(t->SessionList, s);
			}

			ReleaseList(delete_session_list);
		}

		if (t->WantToDisconnect && t->Disconnecting == false)
		{
			// Disconnect the tunnel
			USHORT error_data[4];
			USHORT us;
			UINT ui;
			// Reply the tunnel disconnection response
			L2TP_PACKET *pp = NewL2TPControlPacket(L2TP_MESSAGE_TYPE_STOPCCN, t->IsV3);

			// Assigned Tunnel ID
			if (t->IsV3 == false)
			{
				us = Endian16(t->TunnelId2);
				Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_ASSIGNED_TUNNEL, true, 0,
					&us, sizeof(USHORT)));
			}
			else
			{
				ui = Endian32(t->TunnelId2);
				Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_V3_TUNNEL_ID, true, 0,
					&ui, sizeof(UINT)));

				if (t->IsCiscoV3)
				{
					Add(pp->AvpList, NewAVP(L2TPV3_CISCO_AVP_TUNNEL_ID, true, L2TP_AVP_VENDOR_ID_CISCO,
						&ui, sizeof(UINT)));
				}
			}

			// Result-Error Code
			Zero(error_data, sizeof(error_data));
			error_data[1] = 0x06;
			Add(pp->AvpList, NewAVP(L2TP_AVP_TYPE_RESULT_CODE, true, 0,
				error_data, sizeof(error_data)));

			SendL2TPControlPacket(l2tp, t, 0, pp);

			FreeL2TPPacket(pp);

			Debug("L2TP Tunnel %u/%u is Disconnected.\n", t->TunnelId1, t->TunnelId2);
			t->Disconnecting = true;
			t->Established = false;
			t->DisconnectTimeout = l2tp->Now + (UINT64)L2TP_TUNNEL_DISCONNECT_TIMEOUT;
			L2TPAddInterrupt(l2tp, t->DisconnectTimeout);
		}

		if (t->Disconnecting && (((LIST_NUM(t->SendQueue) == 0) && LIST_NUM(t->SessionList) == 0) || (l2tp->Now >= t->DisconnectTimeout)))
		{
			// Delete the tunnel if there is no session in the tunnel when synchronization
			// between the client and the server has been completed or a time-out occurs
			if (delete_tunnel_list == NULL)
			{
				delete_tunnel_list = NewListFast(NULL);
			}

			Add(delete_tunnel_list, t);
		}
	}

	if (delete_tunnel_list != NULL)
	{
		for (i = 0;i < LIST_NUM(delete_tunnel_list);i++)
		{
			L2TP_TUNNEL *t = LIST_DATA(delete_tunnel_list, i);

			Debug("L2TP Tunnel %u/%u Cleaned up.\n", t->TunnelId1, t->TunnelId2);

			FreeL2TPTunnel(t);
			Delete(l2tp->TunnelList, t);
		}

		ReleaseList(delete_tunnel_list);
	}

	// Re-transmit packets
	for (i = 0;i < LIST_NUM(l2tp->TunnelList);i++)
	{
		L2TP_TUNNEL *t = LIST_DATA(l2tp->TunnelList, i);
		UINT j;

		if (LIST_NUM(t->SendQueue) >= 1)
		{
			// Packet to be transmitted exists one or more
			for (j = 0;j < LIST_NUM(t->SendQueue);j++)
			{
				L2TP_QUEUE *q = LIST_DATA(t->SendQueue, j);

				if (l2tp->Now >= q->NextSendTick)
				{
					q->NextSendTick = l2tp->Now + (UINT64)L2TP_PACKET_RESEND_INTERVAL;

					L2TPAddInterrupt(l2tp, q->NextSendTick);

					SendL2TPControlPacketMain(l2tp, t, q);
				}
			}
		}
		else
		{
			// There is no packet to be transmitted, but the state of the tunnel is changed
			if (t->StateChanged)
			{
				// Send a ZLB
				L2TP_QUEUE *q = ZeroMalloc(sizeof(L2TP_QUEUE));
				L2TP_PACKET *pp = NewL2TPControlPacket(0, t->IsV3);

				pp->TunnelId = t->TunnelId1;
				pp->Ns = t->NextNs;
				q->Buf = BuildL2TPPacketData(pp, t);

				SendL2TPControlPacketMain(l2tp, t, q);

				FreeL2TPQueue(q);
				FreeL2TPPacket(pp);
			}
		}

		t->StateChanged = false;
	}

	if (l2tp->Halting)
	{
		if (LIST_NUM(l2tp->TunnelList) == 0)
		{
			// Stop all the L2TP tunnel completed
			if (l2tp->HaltCompleted == false)
			{
				l2tp->HaltCompleted = true;

				Set(l2tp->HaltCompletedEvent);
			}
		}
	}

	// Maintenance the thread list
	if (l2tp->IkeServer == NULL)
	{
		MaintainThreadList(l2tp->ThreadList);
		//Debug("l2tp->ThreadList: %u\n", LIST_NUM(l2tp->ThreadList));
	}
}

// Create a new L2TP server
L2TP_SERVER *NewL2TPServer(CEDAR *cedar)
{
	return NewL2TPServerEx(cedar, NULL, false, 0);
}
L2TP_SERVER *NewL2TPServerEx(CEDAR *cedar, IKE_SERVER *ike, bool is_ipv6, UINT crypt_block_size)
{
	L2TP_SERVER *l2tp;
	// Validate arguments
	if (cedar == NULL)
	{
		return NULL;
	}

	l2tp = ZeroMalloc(sizeof(L2TP_SERVER));

	l2tp->FlushList = NewTubeFlushList();

	l2tp->Cedar = cedar;
	AddRef(l2tp->Cedar->ref);

	l2tp->SendPacketList = NewList(NULL);
	l2tp->TunnelList = NewList(NULL);

	l2tp->HaltCompletedEvent = NewEvent();

	l2tp->ThreadList = NewThreadList();

	l2tp->IkeServer = ike;

	l2tp->IsIPsecIPv6 = is_ipv6;
	l2tp->CryptBlockSize = crypt_block_size;

	return l2tp;
}

// Stop the L2TP server
void StopL2TPServer(L2TP_SERVER *l2tp, bool no_wait)
{
	// Validate arguments
	if (l2tp == NULL)
	{
		return;
	}
	if (l2tp->Halt)
	{
		return;
	}

	// Begin to shut down
	l2tp->Halt = true;
	Debug("Shutting down L2TP Server...\n");

	// Hit the event
	SetSockEvent(l2tp->SockEvent);

	if (no_wait == false)
	{
		// Wait until complete stopping all tunnels
		Wait(l2tp->HaltCompletedEvent, INFINITE);
	}
	else
	{
		UINT i, j;
		// Kill the thread of all sessions
		for (i = 0;i < LIST_NUM(l2tp->TunnelList);i++)
		{
			L2TP_TUNNEL *t = LIST_DATA(l2tp->TunnelList, i);

			for (j = 0;j < LIST_NUM(t->SessionList);j++)
			{
				L2TP_SESSION *s = LIST_DATA(t->SessionList, j);

				StopL2TPThread(l2tp, t, s);
			}
		}
	}

	// Thread stop
	Debug("Stopping all L2TP PPP Threads...\n");
	StopThreadList(l2tp->ThreadList);
	Debug("L2TP Server Shutdown Completed.\n");
}

// Release the L2TP server
void FreeL2TPServer(L2TP_SERVER *l2tp)
{
	UINT i;
	// Validate arguments
	if (l2tp == NULL)
	{
		return;
	}

	FreeThreadList(l2tp->ThreadList);

	for (i = 0;i < LIST_NUM(l2tp->SendPacketList);i++)
	{
		UDPPACKET *p = LIST_DATA(l2tp->SendPacketList, i);

		FreeUdpPacket(p);
	}

	ReleaseList(l2tp->SendPacketList);

	for (i = 0;i < LIST_NUM(l2tp->TunnelList);i++)
	{
		L2TP_TUNNEL *t = LIST_DATA(l2tp->TunnelList, i);

		FreeL2TPTunnel(t);
	}

	ReleaseList(l2tp->TunnelList);

	ReleaseSockEvent(l2tp->SockEvent);

	ReleaseEvent(l2tp->HaltCompletedEvent);

	ReleaseCedar(l2tp->Cedar);

	FreeTubeFlushList(l2tp->FlushList);

	Free(l2tp);
}

// Set a SockEvent to the L2TP server
void SetL2TPServerSockEvent(L2TP_SERVER *l2tp, SOCK_EVENT *e)
{
	// Validate arguments
	if (l2tp == NULL)
	{
		return;
	}

	if (e != NULL)
	{
		AddRef(e->ref);
	}

	if (l2tp->SockEvent != NULL)
	{
		ReleaseSockEvent(l2tp->SockEvent);
		l2tp->SockEvent = NULL;
	}

	l2tp->SockEvent = e;
}

