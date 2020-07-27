// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_SSTP.c
// SSTP (Microsoft Secure Socket Tunneling Protocol) protocol stack

#include "CedarPch.h"

const PROTO_IMPL *SstpGetProtoImpl()
{
	static const PROTO_IMPL impl =
	{
		SstpName,
		SstpOptions,
		SstpInit,
		SstpFree,
		NULL,
		SstpProcessData,
		NULL
	};

	return &impl;
}

const char *SstpName()
{
	return "SSTP";
}

const PROTO_OPTION *SstpOptions()
{
	static const PROTO_OPTION options[] =
	{
		{ .Name = NULL, .Type = PROTO_OPTION_UNKNOWN }
	};

	return options;
}

bool SstpInit(void **param, const LIST *options, CEDAR *cedar, INTERRUPT_MANAGER *im, SOCK_EVENT *se, const char *cipher, const char *hostname)
{
	if (param == NULL || options == NULL || cedar == NULL || im == NULL || se == NULL)
	{
		return false;
	}

	Debug("SstpInit(): cipher: %s, hostname: %s\n", cipher, hostname);

	*param = NewSstpServer(cedar, im, se, cipher, hostname);

	return true;
}

void SstpFree(void *param)
{
	FreeSstpServer(param);
}

bool SstpProcessData(void *param, TCP_RAW_DATA *in, FIFO *out)
{
	FIFO *recv_fifo;
	bool disconnected = false;
	SSTP_SERVER *server = param;

	if (server == NULL || in == NULL || out == NULL)
	{
		return false;
	}

	if (server->Status == SSTP_SERVER_STATUS_NOT_INITIALIZED)
	{
		HTTP_HEADER *header;
		char *header_str, date_str[MAX_SIZE];

		GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

		header = NewHttpHeader("HTTP/1.1", "200", "OK");
		AddHttpValue(header, NewHttpValue("Content-Length", "18446744073709551615"));
		AddHttpValue(header, NewHttpValue("Server", "Microsoft-HTTPAPI/2.0"));
		AddHttpValue(header, NewHttpValue("Date", date_str));

		header_str = HttpHeaderToStr(header);

		FreeHttpHeader(header);

		if (header_str == NULL)
		{
			return false;
		}

		WriteFifo(out, header_str, StrLen(header_str));

		Free(header_str);

		Copy(&server->ClientIp, &in->SrcIP, sizeof(server->ClientIp));
		server->ClientPort = in->SrcPort;
		Copy(&server->ServerIp, &in->DstIP, sizeof(server->ServerIp));
		server->ServerPort = in->DstPort;

		server->Status = SSTP_SERVER_STATUS_REQUEST_PENGING;

		return true;
	}

	recv_fifo = in->Data;

	while (recv_fifo->size >= 4)
	{
		UCHAR *first4;
		bool ok = false;
		UINT read_size = 0;

		// Read 4 bytes from the beginning of the received queue.
		first4 = ((UCHAR *)recv_fifo->p) + recv_fifo->pos;
		if (first4[0] == SSTP_VERSION_1)
		{
			const USHORT len = READ_USHORT(first4 + 2) & 0xFFF;
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

					InsertQueue(server->RecvQueue, b);
				}
			}
		}

		if (read_size == 0)
		{
			break;
		}

		if (ok == false)
		{
			// Bad packet received, trigger disconnection.
			disconnected = true;
			break;
		}
	}

	// Process the timer interrupt
	SstpProcessInterrupt(server);

	if (server->Disconnected)
	{
		disconnected = true;
	}

	while (true)
	{
		BLOCK *b = GetNext(server->SendQueue);
		if (b == NULL)
		{
			break;
		}

		// Discard the data block if the transmission queue's size is greater than ~2.5 MB.
		if (b->PriorityQoS || (FifoSize(out) <= MAX_BUFFERING_PACKET_SIZE))
		{
			WriteFifo(out, b->Buf, b->Size);
		}

		FreeBlock(b);
	}

	if (disconnected)
	{
		return false;
	}

	return true;
}

// Process the SSTP control packet reception
void SstpProcessControlPacket(SSTP_SERVER *s, SSTP_PACKET *p)
{
	// Validate arguments
	if (s == NULL || p == NULL || p->IsControl == false)
	{
		return;
	}

	Debug("SSTP Control Packet Recv: Msg = %u, Num = %u\n", p->MessageType, LIST_NUM(p->AttributeList));

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
	PPP_SESSION *underlyingSession;

	// Validate arguments
	if (s == NULL || p == NULL || p->IsControl)
	{
		return;
	}

	//Debug("SSTP Data Packet Recv: Size = %u\n", p->DataSize);

	if (s->PPPThread == NULL)
	{
		// Create a thread to initialize the new PPP module
		underlyingSession = NewPPPSession(s->Cedar, &s->ClientIp, s->ClientPort, &s->ServerIp, s->ServerPort,
			s->TubeSend, s->TubeRecv, SSTP_IPC_POSTFIX, SSTP_IPC_CLIENT_NAME,
			s->ClientHostName, s->ClientCipherName, 0);
		s->PPPSession = underlyingSession;
		s->PPPThread = underlyingSession->SessionThread;
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
		Debug("SSTP Control Packet Send: Msg = %u, Num = %u\n", p->MessageType, LIST_NUM(p->AttributeList));
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
	UINT64 sstpTimeout = SSTP_TIMEOUT;
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

	if (s->PPPSession != NULL && s->PPPSession->DataTimeout > sstpTimeout)
	{
		sstpTimeout = s->PPPSession->DataTimeout;
	}

	if ((s->LastRecvTick + sstpTimeout) <= s->Now)
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
		Add(p->AttributeList, a);
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
	p->AttributeList = NewListFast(NULL);

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

// Get the Attribute with the specified ID from SSTP packet
SSTP_ATTRIBUTE *SstpFindAttribute(SSTP_PACKET *p, UCHAR attribute_id)
{
	UINT i;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(p->AttributeList);i++)
	{
		SSTP_ATTRIBUTE *a = LIST_DATA(p->AttributeList, i);

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

		ab = SstpBuildAttributeList(p->AttributeList, p->MessageType);
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
		p->AttributeList = SstpParseAttributeList(p->Data, p->DataSize, p);

		if (p->AttributeList == NULL)
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

	// Attributes List
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

// Release the Attribute
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

	if (p->AttributeList != NULL)
	{
		SstpFreeAttributeList(p->AttributeList);
	}

	if (p->Data != NULL)
	{
		Free(p->Data);
	}

	Free(p);
}

// Create a SSTP server
SSTP_SERVER *NewSstpServer(CEDAR *cedar, INTERRUPT_MANAGER *im, SOCK_EVENT *se, const char *cipher, const char *hostname)
{
	SSTP_SERVER *s = ZeroMalloc(sizeof(SSTP_SERVER));

	s->Status = SSTP_SERVER_STATUS_NOT_INITIALIZED;

	s->Now = Tick64();
	s->LastRecvTick = s->Now;

	s->Cedar = cedar;
	s->Interrupt = im;
	s->SockEvent = se;

	StrCpy(s->ClientHostName, sizeof(s->ClientHostName), hostname);
	StrCpy(s->ClientCipherName, sizeof(s->ClientCipherName), cipher);

	NewTubePair(&s->TubeSend, &s->TubeRecv, 0);
	SetTubeSockEvent(s->TubeSend, se);

	s->RecvQueue = NewQueueFast();
	s->SendQueue = NewQueueFast();

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

	ReleaseTube(s->TubeSend);
	ReleaseTube(s->TubeRecv);

	Free(s);
}
