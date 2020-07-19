// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_OpenVPN.c
// OpenVPN protocol stack

#include "CedarPch.h"

// Ping signature of the OpenVPN protocol
static UCHAR ping_signature[] =
{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

const PROTO_IMPL *OvsGetProtoImpl()
{
	static const PROTO_IMPL impl =
	{
		OvsName,
		OvsOptions,
		OvsInit,
		OvsFree,
		OvsIsPacketForMe,
		OvsProcessData,
		OvsProcessDatagrams
	};

	return &impl;
}

const char *OvsName()
{
	return "OpenVPN";
}

const PROTO_OPTION *OvsOptions()
{
	static const PROTO_OPTION options[] =
	{
		{ .Name = "DefaultClientOption", .Type = PROTO_OPTION_STRING, .String = "dev-type tun,link-mtu 1500,tun-mtu 1500,cipher AES-128-CBC,auth SHA1,keysize 128,key-method 2,tls-client" },
		{ .Name = "Obfuscation", .Type = PROTO_OPTION_BOOL, .Bool = false },
		{ .Name = "ObfuscationMask", .Type = PROTO_OPTION_STRING, .String = ""},
		{ .Name = "PushDummyIPv4AddressOnL2Mode", .Type = PROTO_OPTION_BOOL, .Bool = true },
		{ .Name = NULL, .Type = PROTO_OPTION_UNKNOWN }
	};

	return options;
}

bool OvsInit(void **param, const LIST *options, CEDAR *cedar, INTERRUPT_MANAGER *im, SOCK_EVENT *se, const char *cipher, const char *hostname)
{
	if (param == NULL || options == NULL || cedar == NULL || im == NULL || se == NULL)
	{
		return false;
	}

	Debug("OvsInit(): cipher: %s, hostname: %s\n", cipher, hostname);

	*param = NewOpenVpnServer(options, cedar, im, se);

	return true;
}

void OvsFree(void *param)
{
	FreeOpenVpnServer(param);
}

// Check whether it's an OpenVPN packet
bool OvsIsPacketForMe(const PROTO_MODE mode, const UCHAR *data, const UINT size)
{
	if (mode == PROTO_MODE_TCP)
	{
		if (data == NULL || size < 2)
		{
			return false;
		}

		if (data[0] == 0x00 && data[1] == 0x0E)
		{
			return true;
		}
	}
	else if (mode == PROTO_MODE_UDP)
	{
		OPENVPN_PACKET *packet = OvsParsePacket(data, size);
		if (packet == NULL)
		{
			return false;
		}

		OvsFreePacket(packet);
		return true;
	}

	return false;
}

bool OvsProcessData(void *param, TCP_RAW_DATA *in, FIFO *out)
{
	bool ret = true;
	UINT i;
	OPENVPN_SERVER *server = param;
	UCHAR buf[OPENVPN_TCP_MAX_PACKET_SIZE];

	if (server == NULL || in == NULL || out == NULL)
	{
		return false;
	}

	// Separate to a list of datagrams by interpreting the data received from the TCP socket
	while (true)
	{
		UDPPACKET *packet;
		USHORT payload_size, packet_size;
		FIFO *fifo = in->Data;
		const UINT fifo_size = FifoSize(fifo);

		if (fifo_size < sizeof(USHORT))
		{
			// Non-arrival
			break;
		}

		// The beginning of a packet contains the data size
		payload_size = READ_USHORT(FifoPtr(fifo));
		packet_size = payload_size + sizeof(USHORT);

		if (payload_size == 0 || packet_size > sizeof(buf))
		{
			ret = false;
			Debug("OvsProcessData(): Invalid payload size: %u bytes\n", payload_size);
			break;
		}

		if (fifo_size < packet_size)
		{
			// Non-arrival
			break;
		}

		if (ReadFifo(fifo, buf, packet_size) != packet_size)
		{
			ret = false;
			Debug("OvsProcessData(): ReadFifo() failed to read the packet\n");
			break;
		}

		// Insert packet into the list
		packet = NewUdpPacket(&in->SrcIP, in->SrcPort, &in->DstIP, in->DstPort, Clone(buf + sizeof(USHORT), payload_size), payload_size);
		Add(server->RecvPacketList, packet);
	}

	// Process the list of received datagrams
	OvsRecvPacket(server, server->RecvPacketList, OPENVPN_PROTOCOL_TCP);

	// Release the received packet list
	for (i = 0; i < LIST_NUM(server->RecvPacketList); ++i)
	{
		UDPPACKET *p = LIST_DATA(server->RecvPacketList, i);
		FreeUdpPacket(p);
	}

	DeleteAll(server->RecvPacketList);

	// Store in the queue by getting a list of the datagrams to be transmitted from the OpenVPN server
	for (i = 0; i < LIST_NUM(server->SendPacketList); ++i)
	{
		UDPPACKET *p = LIST_DATA(server->SendPacketList, i);

		// Store the size in the TCP send queue first
		USHORT us = Endian16((USHORT)p->Size);

		WriteFifo(out, &us, sizeof(USHORT));

		// Write the data body
		WriteFifo(out, p->Data, p->Size);

		// Packet release
		FreeUdpPacket(p);
	}

	DeleteAll(server->SendPacketList);

	if (server->Giveup <= server->Now)
	{
		UINT i;
		for (i = 0; i < LIST_NUM(server->SessionList); ++i)
		{
			OPENVPN_SESSION *se = LIST_DATA(server->SessionList, i);

			if (se->Established)
			{
				return ret && server->DisconnectCount < 1;
			}
		}

		return false;
	}

	server->SupressSendPacket = FifoSize(out) > MAX_BUFFERING_PACKET_SIZE;

	return ret;
}

bool OvsProcessDatagrams(void *param, LIST *in, LIST *out)
{
	UINT i;
	LIST *to_send;
	OPENVPN_SERVER *server = param;

	if (server == NULL || in == NULL || out == NULL)
	{
		return false;
	}

	OvsRecvPacket(server, in, OPENVPN_PROTOCOL_UDP);

	to_send = server->SendPacketList;

	for (i = 0; i < LIST_NUM(to_send); ++i)
	{
		Add(out, LIST_DATA(to_send, i));
	}

	DeleteAll(server->SendPacketList);

	if (server->Giveup <= server->Now)
	{
		UINT i;
		for (i = 0; i < LIST_NUM(server->SessionList); ++i)
		{
			OPENVPN_SESSION *se = LIST_DATA(server->SessionList, i);

			if (se->Established)
			{
				return server->DisconnectCount < 1;
			}
		}

		return false;
	}

	return true;
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

// Encrypt the data
UINT OvsEncrypt(CIPHER *cipher, MD *md, UCHAR *iv, UCHAR *tag, UCHAR *dest, UCHAR *src, UINT src_size, UCHAR *aad, UINT aad_size)
{
	// Validate arguments
	if (cipher == NULL || (cipher->IsAeadCipher == false && md == NULL))
	{
		return 0;
	}

	if (cipher->IsAeadCipher)
	{
		// Encrypt in AEAD mode (no HMAC)
		UINT dest_size = CipherProcessAead(cipher, iv, tag, 16, dest, src, src_size, aad, aad_size);
		if (dest_size == 0)
		{
			Debug("OvsEncrypt(): CipherProcessAead() failed!\n");
			return 0;
		}

		return dest_size;
	}
	else
	{
		// Encrypt in non-AEAD mode (with HMAC)
		UINT ret;
		UINT dest_size = CipherProcess(cipher, iv, dest + md->Size + cipher->IvSize, src, src_size);
		if (dest_size == 0)
		{
			Debug("OvsEncrypt(): CipherProcess() failed!\n");
			return 0;
		}

		// Copy the IV
		Copy(dest + md->Size, iv, cipher->IvSize);
		dest_size += cipher->IvSize;

		// Calculate the HMAC
		ret = MdProcess(md, dest, dest + md->Size, dest_size);
		if (ret == 0)
		{
			Debug("OvsEncrypt(): MdProcess() failed!\n");
			return 0;
		}

		return dest_size + ret;
	}
}

// Decrypt the data
UINT OvsDecrypt(CIPHER *cipher, MD *md, UCHAR *iv, UCHAR *dest, UCHAR *src, UINT size)
{
	// Validate arguments
	if (cipher == NULL)
	{
		return 0;
	}

	if (cipher->IsAeadCipher)
	{
		UCHAR *tag = src;

		if (iv == NULL || size <= OPENVPN_TAG_SIZE)
		{
			return 0;
		}

		src += OPENVPN_TAG_SIZE;
		size -= OPENVPN_TAG_SIZE;

		// Payload
		if (size >= 1 && (cipher->BlockSize == 0 || (size % cipher->BlockSize) == 0))
		{
			// Decryption
			UINT ret = CipherProcessAead(cipher, iv, tag, OPENVPN_TAG_SIZE, dest, src, size, iv, sizeof(UINT));
			if (ret == 0)
			{
				Debug("OvsDecrypt(): CipherProcessAead() failed!\n");
			}

			return ret;
		}
	}
	else
	{
		UCHAR *hmac;
		UCHAR hmac_test[128];

		if (md == NULL || iv == NULL || size < (md->Size + cipher->IvSize + sizeof(UINT)))
		{
			return 0;
		}

		// HMAC
		hmac = src;
		src += md->Size;
		size -= md->Size;

		if (MdProcess(md, hmac_test, src, size) == 0)
		{
			Debug("OvsDecrypt(): MdProcess() failed!\n");
			return 0;
		}

		if (Cmp(hmac_test, hmac, md->Size) != 0)
		{
			Debug("OvsDecrypt(): HMAC verification failed!\n");
			return 0;
		}

		// IV
		Copy(iv, src, cipher->IvSize);
		src += cipher->IvSize;
		size -= cipher->IvSize;

		// Payload
		if (size >= 1 && (cipher->BlockSize == 0 || (size % cipher->BlockSize) == 0))
		{
			// Decryption
			UINT ret = CipherProcess(cipher, iv, dest, src, size);
			if (ret == 0)
			{
				Debug("OvsDecrypt(): CipherProcess() failed!\n");
			}

			return ret;
		}
	}

	return 0;
}

// XOR the bytes with the specified string
void OvsDataXorMask(void *data, const UINT data_size, const char *mask, const UINT mask_size)
{
	UINT i;
	UCHAR *buf;
	// Validate arguments
	if (data == NULL || data_size == 0 || mask == NULL || mask_size == 0)
	{
		return;
	}

	for (i = 0, buf = data; i < data_size; i++, buf++)
	{
		*buf = *buf ^ mask[i % mask_size];
	}
}

// XOR each byte with its position within the buffer
void OvsDataXorPtrPos(void *data, const UINT size)
{
	UINT i;
	UCHAR *buf;
	// Validate arguments
	if (data == NULL || size == 0)
	{
		return;
	}

	for (i = 0, buf = data; i < size; i++, buf++)
	{
		*buf = *buf ^ i + 1;
	}
}

// Reverse bytes order if they're more than 2, keeping the first byte unchanged
void OvsDataReverse(void *data, const UINT size)
{
	UINT i;
	UCHAR tmp;
	UCHAR *buf_start, *buf_end;
	// Validate arguments
	if (data == NULL || size < 3)
	{
		return;
	}

	for (i = 0, buf_start = (UCHAR *)data + 1, buf_end = (UCHAR *)data + (size - 1); i < (size - 1 ) / 2; i++, buf_start++, buf_end--)
	{
		tmp = *buf_start;
		*buf_start = *buf_end;
		*buf_end = tmp;
	}
}

// Detects the method used to obfuscate the packet
UINT OvsDetectObfuscation(void *data, UINT size, char *xormask)
{
	UINT ret;
	void *tmp;
	OPENVPN_PACKET *parsed_packet;
	// Validate arguments
	if (data == NULL || size == 0)
	{
		return INFINITE;
	}

	ret = INFINITE;
	tmp = NULL;

	// OPENVPN_SCRAMBLE_MODE_DISABLED
	parsed_packet = OvsParsePacket(data, size);
	if (parsed_packet != NULL)
	{
		ret = OPENVPN_SCRAMBLE_MODE_DISABLED;
		goto final;
	}

	// OPENVPN_SCRAMBLE_MODE_XORMASK
	tmp = Clone(data, size);

	OvsDataXorMask(tmp, size, xormask, StrLen(xormask));

	parsed_packet = OvsParsePacket(tmp, size);
	if (parsed_packet != NULL)
	{
		ret = OPENVPN_SCRAMBLE_MODE_XORMASK;
		goto final;
	}

	Free(tmp);

	// OPENVPN_SCRAMBLE_MODE_XORPTRPOS
	tmp = Clone(data, size);

	OvsDataXorPtrPos(tmp, size);

	parsed_packet = OvsParsePacket(tmp, size);
	if (parsed_packet != NULL)
	{
		ret = OPENVPN_SCRAMBLE_MODE_XORPTRPOS;
		goto final;
	}

	Free(tmp);

	// OPENVPN_SCRAMBLE_MODE_REVERSE
	tmp = Clone(data, size);

	OvsDataReverse(tmp, size);

	parsed_packet = OvsParsePacket(tmp, size);
	if (parsed_packet != NULL)
	{
		ret = OPENVPN_SCRAMBLE_MODE_REVERSE;
		goto final;
	}

	Free(tmp);

	// OPENVPN_SCRAMBLE_MODE_OBFUSCATE
	tmp = Clone(data, size);

	OvsDataXorMask(tmp, size, xormask, StrLen(xormask));
	OvsDataXorPtrPos(tmp, size);
	OvsDataReverse(tmp, size);
	OvsDataXorPtrPos(tmp, size);

	parsed_packet = OvsParsePacket(tmp, size);
	if (parsed_packet != NULL)
	{
		ret = OPENVPN_SCRAMBLE_MODE_OBFUSCATE;
		goto final;
	}

final:
	OvsFreePacket(parsed_packet);
	Free(tmp);
	return ret;
}

// Process the received packet
void OvsProceccRecvPacket(OPENVPN_SERVER *s, UDPPACKET *p, UINT protocol)
{
	OPENVPN_CHANNEL *c;
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

	// Detect obfuscation mode and save it for the next packets in the same session
	if (se->ObfuscationMode == INFINITE)
	{
		se->ObfuscationMode = OvsDetectObfuscation(p->Data, p->Size, s->ObfuscationMask);
		if (se->ObfuscationMode != INFINITE)
		{
			Debug("OvsProceccRecvPacket(): detected packet obfuscation/scrambling mode: %u\n", se->ObfuscationMode);
		}
		else
		{
			Debug("OvsProceccRecvPacket(): failed to detect packet obfuscation/scrambling mode!\n");
			return;
		}
	}

	// Handle scrambled packet
	switch (se->ObfuscationMode)
	{
	case OPENVPN_SCRAMBLE_MODE_DISABLED:
		break;
	case OPENVPN_SCRAMBLE_MODE_XORMASK:
		OvsDataXorMask(p->Data, p->Size, s->ObfuscationMask, StrLen(s->ObfuscationMask));
		break;
	case OPENVPN_SCRAMBLE_MODE_XORPTRPOS:
		OvsDataXorPtrPos(p->Data, p->Size);
		break;
	case OPENVPN_SCRAMBLE_MODE_REVERSE:
		OvsDataReverse(p->Data, p->Size);
		break;
	case OPENVPN_SCRAMBLE_MODE_OBFUSCATE:
		OvsDataXorMask(p->Data, p->Size, s->ObfuscationMask, StrLen(s->ObfuscationMask));
		OvsDataXorPtrPos(p->Data, p->Size);
		OvsDataReverse(p->Data, p->Size);
		OvsDataXorPtrPos(p->Data, p->Size);
	}

	// Parse the packet
	recv_packet = OvsParsePacket(p->Data, p->Size);
	if (recv_packet == NULL)
	{
		Debug("OvsProceccRecvPacket(): OvsParsePacket() returned NULL!\n");
		return;
	}

	c = se->Channels[recv_packet->KeyId];

	if (recv_packet->OpCode != OPENVPN_P_DATA_V1)
	{
		// Control packet
		Debug("OvsProceccRecvPacket(): Received control packet. PacketId: %u, OpCode: %u, KeyId: %u, MySessionId: %I64u\n",
		      recv_packet->PacketId, recv_packet->OpCode, recv_packet->KeyId, recv_packet->MySessionId);

		if (recv_packet->OpCode == OPENVPN_P_CONTROL_HARD_RESET_CLIENT_V2 ||
		        recv_packet->OpCode == OPENVPN_P_CONTROL_SOFT_RESET_V1)
		{
			// Connection request packet
			if (c != NULL && c->Status == OPENVPN_CHANNEL_STATUS_ESTABLISHED)
			{
				// If there's already an established data channel, release it
				OvsFreeChannel(se->Channels[recv_packet->KeyId]);
				c = se->Channels[recv_packet->KeyId] = NULL;
				Debug("OvsProceccRecvPacket(): Released established data channel: %u\n", recv_packet->KeyId);
			}

			if (c == NULL)
			{
				// Create a new channel
				c = OvsNewChannel(se, recv_packet->KeyId);
				if (se->ClientSessionId == 0)
				{
					se->ClientSessionId = recv_packet->MySessionId;
				}
				se->Channels[recv_packet->KeyId] = c;
				Debug("OvsProceccRecvPacket(): Created a new channel: %u\n", recv_packet->KeyId);
				OvsLog(s, se, c, "LO_NEW_CHANNEL");
			}
		}
		/*		else if (recv_packet->OpCode == OPENVPN_P_CONTROL_SOFT_RESET_V1)
				{
					// Response to soft reset request packet
					OPENVPN_PACKET *p;

					p = OvsNewControlPacket(OPENVPN_P_CONTROL_SOFT_RESET_V1, recv_packet->KeyId, se->ServerSessionId,
						0, NULL, 0, 0, 0, NULL);

					OvsSendPacketNow(s, se, p);

					OvsFreePacket(p);
				}
		*/
		if (c != NULL)
		{
			// Delete the send packet list by looking the packet ID in the ACK list of arrived packet
			OvsDeleteFromSendingControlPacketList(c, recv_packet->NumAck, recv_packet->AckPacketId);

			if (recv_packet->OpCode != OPENVPN_P_ACK_V1)
			{
				// Add the Packet ID of arrived packet to the list
				InsertIntDistinct(c->AckReplyList, recv_packet->PacketId);

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
		if (c != NULL && c->Status == OPENVPN_CHANNEL_STATUS_ESTABLISHED)
		{
			UINT size;
			UCHAR *data = s->TmpBuf;
			if (c->CipherDecrypt->IsAeadCipher)
			{
				// Update variable part (packet ID) of IV
				Copy(c->IvRecv, recv_packet->Data, sizeof(recv_packet->PacketId));

				// Decrypt
				size = OvsDecrypt(c->CipherDecrypt, NULL, c->IvRecv, data, recv_packet->Data + sizeof(UINT), recv_packet->DataSize - sizeof(UINT));
			}
			else
			{
				// Decrypt
				size = OvsDecrypt(c->CipherDecrypt, c->MdRecv, c->IvRecv, data, recv_packet->Data, recv_packet->DataSize);
				if (size > sizeof(UINT))
				{
					// Seek buffer after the packet ID
					data += sizeof(UINT);
					size -= sizeof(UINT);
				}
			}

			// Update of last communication time
			se->LastCommTick = s->Now;

			if (size < sizeof(ping_signature) || Cmp(data, ping_signature, sizeof(ping_signature)) != 0)
			{
				// Receive a packet!
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

	OvsFreePacket(recv_packet);
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
	for (i = 0; i < num_acks; i++)
	{
		UINT ack = acks[i];
		UINT j;

		for (j = 0; j < LIST_NUM(c->SendControlPacketList); j++)
		{
			OPENVPN_CONTROL_PACKET *p = LIST_DATA(c->SendControlPacketList, j);

			if (p->PacketId == ack)
			{
				AddDistinct(o, p);
			}
		}
	}

	for (i = 0; i < LIST_NUM(o); i++)
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
				if (s->Dh->Size != s->Cedar->DhParamBits)
				{
					DhFree(s->Dh);
					s->Dh = DhNewFromBits(s->Cedar->DhParamBits);
				}

				c->SslPipe = NewSslPipeEx(true, s->Cedar->ServerX, s->Cedar->ServerK, s->Dh, true, &c->ClientCert);
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
			OvsSendControlPacketEx(c, OPENVPN_P_CONTROL_HARD_RESET_SERVER_V2, NULL, 0, true);

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
		LIST *pi;
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

		// OpenVPN sends the default gateway's MAC address,
		// if the option --push-peer-info is enabled.
		// It also sends all of the client's environment
		// variables whose names start with "UV_".
		pi = NewEntryList(c->ClientKey.PeerInfo, "\n", "=\t");

		// Check presence of custom hostname
		if (EntryListHasKey(pi, "UV_HOSTNAME"))
		{
			StrCpy(p.ClientHostname, sizeof(p.ClientHostname), EntryListStrValue(pi, "UV_HOSTNAME"));
		}
		else // Use the default gateway's MAC address
		{
			StrCpy(p.ClientHostname, sizeof(p.ClientHostname), EntryListStrValue(pi, "IV_HWADDR"));
		}

		FreeEntryList(pi);

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

		if (IsEmptyStr(c->ClientKey.Username) || IsEmptyStr(c->ClientKey.Password))
		{
			// OpenVPN X.509 certificate authentication will be used only when no username / password is specified
			if (c->ClientCert.X != NULL)
			{
				p.ClientCertificate = c->ClientCert.X;
			}
		}

		p.Layer = (se->Mode == OPENVPN_MODE_L2) ? IPC_LAYER_2 : IPC_LAYER_3;

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

	for (i = 0; i < MIN(str_size, FifoSize(f)); i++)
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
	char *cipher_name, *md_name;
	// Validate arguments
	if (s == NULL || se == NULL || c == NULL || data == NULL)
	{
		return;
	}

	Copy(&c->ClientKey, data, sizeof(OPENVPN_KEY_METHOD_2));

	// Parse the parameter string
	Debug("Parsing Option Str: %s\n", data->OptionString);

	OvsLog(s, se, c, "LO_OPTION_STR_RECV", data->OptionString);

	if (c->ClientCert.X != NULL)
	{
		if (c->ClientCert.X->subject_name != NULL)
		{
			OvsLog(s, se, c, "LO_CLIENT_CERT", c->ClientCert.X->subject_name->CommonName);
		}
		else
		{
			OvsLog(s, se, c, "LO_CLIENT_CERT", "(unknown CN)");
		}
	}
	else if (!c->ClientCert.PreverifyErr)
	{
		OvsLog(s, se, c, "LO_CLIENT_NO_CERT");
	}
	else
	{
		OvsLog(s, se, c, "LO_CLIENT_UNVERIFIED_CERT", c->ClientCert.PreverifyErrMessage);
	}

	Zero(opt_str, sizeof(opt_str));
	StrCpy(opt_str, sizeof(opt_str), data->OptionString);
	if (s->Cedar != NULL && (IsEmptyStr(opt_str) || StartWith(opt_str, "V0 UNDEF") || InStr(opt_str, ",") == false))
	{
		StrCpy(opt_str, sizeof(opt_str), s->DefaultClientOption);
	}

	o = NewEntryList(opt_str, ",", " \t");

	if (se->Mode == OPENVPN_MODE_UNKNOWN)
	{
		UINT mtu;
		// Layer
		if (StrCmpi(EntryListStrValue(o, "dev-type"), "tun") == 0)
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
		mtu = EntryListIntValue(o, "link-mtu");
		if (mtu == 0)
		{
			mtu = OPENVPN_MTU_LINK;
		}
		se->LinkMtu = mtu;

		// Tun MTU
		mtu = EntryListIntValue(o, "tun-mtu");
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
	cipher_name = EntryListStrValue(o, "cipher");

	// Hash algorithm
	md_name = EntryListStrValue(o, "auth");

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

	// Set up the encryption algorithm
	c->CipherEncrypt = OvsGetCipher(cipher_name);
	c->CipherDecrypt = OvsGetCipher(cipher_name);
	SetCipherKey(c->CipherDecrypt, c->ExpansionKey + 0, false);
	SetCipherKey(c->CipherEncrypt, c->ExpansionKey + 128, true);

	if (c->CipherDecrypt->IsAeadCipher)
	{
		// In AEAD mode the IV is composed by the packet ID and a part of the HMAC key
		Copy(c->IvRecv + sizeof(c->LastDataPacketId), c->ExpansionKey + 64, c->CipherDecrypt->IvSize - sizeof(c->LastDataPacketId));
		Copy(c->IvSend + sizeof(c->LastDataPacketId), c->ExpansionKey + 192, c->CipherEncrypt->IvSize - sizeof(c->LastDataPacketId));
	}
	else
	{
		// Set up the hash algorithm
		c->MdSend = OvsGetMd(md_name);
		c->MdRecv = OvsGetMd(md_name);
		SetMdKey(c->MdRecv, c->ExpansionKey + 64, c->MdRecv->Size);
		SetMdKey(c->MdSend, c->ExpansionKey + 192, c->MdSend->Size);
	}

	// We pass the cipher name sent from the OpenVPN client, unless it's a different cipher, to prevent a message such as:
	// WARNING: 'cipher' is used inconsistently, local='cipher AES-128-GCM', remote='cipher aes-128-gcm'
	// It happens because OpenVPN uses "strcmp()" to compare the local and remote parameters:
	// https://github.com/OpenVPN/openvpn/blob/a6fd48ba36ede465b0905a95568c3ec0d425ca71/src/openvpn/options.c#L3819-L3831
	if (StrCmpi(cipher_name, c->CipherEncrypt->Name) != 0)
	{
		cipher_name = c->CipherEncrypt->Name;
	}

	// Generate the response option string
	Format(c->ServerKey.OptionString, sizeof(c->ServerKey.OptionString),
	       "V4,dev-type %s,link-mtu %u,tun-mtu %u,proto %s,"
	       "cipher %s,auth %s,keysize %u,key-method 2,tls-server",
	       (se->Mode == OPENVPN_MODE_L2 ? "tap" : "tun"),
	       se->LinkMtu,
	       se->TunMtu,
	       c->Proto,
	       cipher_name, md_name, c->CipherEncrypt->KeySize * 8);

	FreeEntryList(o);

	Debug("OvsSetupSessionParameters(): Built OptionString: %s\n", c->ServerKey.OptionString);
	OvsLog(s, se, c, "LO_OPTION_STR_SEND", c->ServerKey.OptionString);
}

// Get the encryption algorithm
CIPHER *OvsGetCipher(char *name)
{
	CIPHER *c = NULL;

	// OpenVPN sends the cipher name in uppercase, even if it's not standard,
	// thus we have to convert it to lowercase for EVP_get_cipherbyname().
	char lowercase_name[MAX_SIZE];
	StrCpy(lowercase_name, sizeof(lowercase_name), name);
	StrLower(lowercase_name);

	if (IsEmptyStr(lowercase_name) == false)
	{
		c = NewCipher(lowercase_name);
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

	if (IsEmptyStr(name) == false)
	{
		m = NewMd(name);
	}

	if (m == NULL)
	{
		m = NewMd(OPENVPN_DEFAULT_MD);
	}

	return m;
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
						        OvsReadStringFromBuf(b, ret->Password, sizeof(ret->Password)))
						{
							if (!OvsReadStringFromBuf(b, ret->PeerInfo, sizeof(ret->PeerInfo)))
							{
								Zero(ret->PeerInfo, sizeof(ret->PeerInfo));
							}
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
	OvsSendControlPacketEx(c, opcode, data, data_size, false);
}
void OvsSendControlPacketEx(OPENVPN_CHANNEL *c, UCHAR opcode, UCHAR *data, UINT data_size, bool no_resend)
{
	OPENVPN_CONTROL_PACKET *p;
	// Validate arguments
	if (c == NULL || (data_size != 0 && data == NULL))
	{
		return;
	}

	p = ZeroMalloc(sizeof(OPENVPN_CONTROL_PACKET));

	p->NoResend = no_resend;

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

	for (i = 0; i < num; i++)
	{
		UINT *v = LIST_DATA(c->AckReplyList, i);

		if (o == NULL)
		{
			o = NewListFast(NULL);
		}

		Add(o, v);

		ret[i] = *v;
	}

	for (i = 0; i < LIST_NUM(o); i++)
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

	for (i = 0; i < LIST_NUM(c->SendControlPacketList); i++)
	{
		OPENVPN_CONTROL_PACKET *p = LIST_DATA(c->SendControlPacketList, i);

		OvsFreeControlPacket(p);
	}

	ReleaseList(c->SendControlPacketList);

	FreeCipher(c->CipherDecrypt);
	FreeCipher(c->CipherEncrypt);

	FreeMd(c->MdRecv);
	FreeMd(c->MdSend);

	if (c->ClientCert.X != NULL)
	{
		FreeX(c->ClientCert.X);
	}

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

	Rand(c->IvSend, sizeof(c->IvSend));
	Rand(c->IvRecv, sizeof(c->IvRecv));

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

		for (i = 0; i < LIST_NUM(s->SessionList); i++)
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
	const UCHAR op = ((OPENVPN_P_DATA_V1 << 3) & 0xF8) | (key_id & 0x07);
	UCHAR *dest_data;
	UINT dest_size;
	// Validate arguments
	if (c == NULL || data == NULL || data_size == 0)
	{
		return;
	}

	// [ xxx ]		= unprotected
	// [ - xxx - ]	= authenticated
	// [ * xxx * ]	= encrypted and authenticated

	if (c->CipherEncrypt->IsAeadCipher)
	{
		// [ opcode ] [ - packet ID - ] [ TAG ] [ * packet payload * ]
		UCHAR tag[16];

		// Update variable part (packet ID) of IV
		WRITE_UINT(c->IvSend, data_packet_id);

		// Prepare a buffer to store the results
		dest_data = Malloc(sizeof(op) + sizeof(data_packet_id) + sizeof(tag) + data_size + 256);

		// Set data size to the maximum known
		dest_size = sizeof(op) + sizeof(data_packet_id) + sizeof(tag);

		// Write opcode
		dest_data[0] = op;

		// Write packet ID
		WRITE_UINT(dest_data + sizeof(op), data_packet_id);

		// Write encrypted payload
		dest_size += OvsEncrypt(c->CipherEncrypt, NULL, c->IvSend, tag, dest_data + dest_size, data, data_size, c->IvSend, sizeof(data_packet_id));

		// Write authentication tag
		Copy(dest_data + sizeof(op) + sizeof(data_packet_id), tag, sizeof(tag));
	}
	else
	{
		// [ opcode ] [ HMAC ] [ - IV - ] [ * packet ID * ] [ * packet payload * ]
		UINT encrypted_size = sizeof(data_packet_id) + data_size;
		UCHAR *encrypted_data = ZeroMalloc(encrypted_size);
		WRITE_UINT(encrypted_data, data_packet_id);
		Copy(encrypted_data + sizeof(data_packet_id), data, data_size);

		// Prepare a buffer to store the results
		dest_data = Malloc(sizeof(op) + c->MdSend->Size + c->CipherEncrypt->IvSize + encrypted_size + 256);

		// Set data size to the maximum known
		dest_size = sizeof(op);

		// Write opcode
		dest_data[0] = op;

		// Write IV, encrypted packet ID and payload
		dest_size += OvsEncrypt(c->CipherEncrypt, c->MdSend, c->IvSend, NULL, dest_data + sizeof(op), encrypted_data, encrypted_size, NULL, 0);

		Free(encrypted_data);

		// Update the IV
		Copy(c->IvSend, dest_data + dest_size - c->CipherEncrypt->IvSize, c->CipherEncrypt->IvSize);
	}

	OvsSendPacketRawNow(c->Server, c->Session, dest_data, dest_size);
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

		for (i = 0; i < num_ack; i++)
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

		for (i = 0; i < ret->NumAck; i++)
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
	OvsFreePacket(ret);
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

	for (i = 0; i < LIST_NUM(s->SessionList); i++)
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

	se->ObfuscationMode = s->Obfuscation ? INFINITE : OPENVPN_SCRAMBLE_MODE_DISABLED;

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
				IPC_PROTO_SET_STATUS(se->Ipc, IPv6State, IPC_PROTO_STATUS_CLOSED);
				IPCProcessL3EventsIPv4Only(se->Ipc);
			}
		}
	}

	// Release the channel
	for (i = 0; i < OPENVPN_NUM_CHANNELS; i++)
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
	for (i = 0; i < LIST_NUM(s->SessionList); i++)
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
	for (i = 0; i < LIST_NUM(recv_packet_list); i++)
	{
		UDPPACKET *p = LIST_DATA(recv_packet_list, i);

		OvsProceccRecvPacket(s, p, protocol);
	}

	// Treat for all sessions and all channels
	for (i = 0; i < LIST_NUM(s->SessionList); i++)
	{
		OPENVPN_CHANNEL *latest_channel = NULL;
		UINT64 max_tick = 0;
		OPENVPN_SESSION *se = LIST_DATA(s->SessionList, i);
		bool is_disconnected = false;

		if (se->Ipc != NULL)
		{
			if (se->Mode == OPENVPN_MODE_L3)
			{
				IPCProcessL3EventsIPv4Only(se->Ipc);
			}
		}

		for (j = 0; j < OPENVPN_NUM_CHANNELS; j++)
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

									IPToStr32(ip_subnet_mask, sizeof(ip_subnet_mask),
									          cao->SubnetMask);

									Format(l3_options, sizeof(l3_options),
									       ",topology subnet");
									StrCat(option_str, sizeof(option_str), l3_options);

									Format(l3_options, sizeof(l3_options),
									       ",ifconfig %s %s",
									       ip_client,
									       ip_subnet_mask);
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
										char ip_str[64];
										IPToStr32(ip_str, sizeof(ip_str), cao->Gateway);
										Format(l3_options, sizeof(l3_options),
										       ",route-gateway %s,redirect-gateway def1", ip_str);
										StrCat(option_str, sizeof(option_str), l3_options);

										StrCpy(ip_defgw, sizeof(ip_defgw), ip_str);
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
										for (i = 0; i < MAX_DHCP_CLASSLESS_ROUTE_ENTRIES; i++)
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
								else
								{
									// OpenVPN L2 mode. To fix the bug of OpenVPN 2.4.6 and particular version of kernel mode TAP driver
									// on Linux, the TAP device must be up after the OpenVPN client is connected.
									// However there is no direct push instruction to do so to OpenVPN client.
									// Therefore we push the dummy IPv4 address (RFC7600) to the OpenVPN client.
									if (s->PushDummyIPv4AddressOnL2Mode)
									{
										StrCat(option_str, sizeof(option_str), ",ifconfig 192.0.0.8 255.255.255.240");
									}
								}

								// From https://community.openvpn.net/openvpn/wiki/Openvpn23ManPage:
								//
								// --block-outside-dns
								// Block DNS servers on other network adapters to prevent DNS leaks.
								// This option prevents any application from accessing TCP or UDP port 53 except one inside the tunnel.
								// It uses Windows Filtering Platform (WFP) and works on Windows Vista or later.
								// This option is considered unknown on non-Windows platforms and unsupported on Windows XP, resulting in fatal error.
								// You may want to use --setenv opt or --ignore-unknown-option (not suitable for Windows XP) to ignore said error.
								// Note that pushing unknown options from server does not trigger fatal errors.
								StrCat(option_str, sizeof(option_str), ",block-outside-dns");

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
				for (k = 0; k < LIST_NUM(c->SendControlPacketList); k++)
				{
					OPENVPN_CONTROL_PACKET *cp = LIST_DATA(c->SendControlPacketList, k);

					if (cp->NextSendTime <= s->Now)
					{
						if (cp->NoResend == false || cp->NumSent == 0) // To address the UDP reflection amplification attack: https://github.com/SoftEtherVPN/SoftEtherVPN/issues/1001
						{
							OPENVPN_PACKET *p;

							cp->NumSent++;

							num = OvsGetAckReplyList(c, acks);

							p = OvsNewControlPacket(cp->OpCode, j, se->ServerSessionId, num, acks,
							                        se->ClientSessionId, cp->PacketId, cp->DataSize, cp->Data);

							OvsSendPacketNow(s, se, p);

							OvsFreePacket(p);

							cp->NextSendTime = s->Now + (UINT64)OPENVPN_CONTROL_PACKET_RESEND_INTERVAL;

							AddInterrupt(s->Interrupt, cp->NextSendTime);
						}
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

				IPCProcessL3EventsIPv4Only(se->Ipc);
			}

			IPCProcessInterrupts(se->Ipc);
		}

		// Choose the latest channel in all established channels
		for (j = 0; j < OPENVPN_NUM_CHANNELS; j++)
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

		for (i = 0; i < LIST_NUM(delete_session_list); i++)
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
		for (i = 0; i < p->NumAck; i++)
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

	// Scramble the packet
	switch (se->ObfuscationMode)
	{
	case OPENVPN_SCRAMBLE_MODE_DISABLED:
		break;
	case OPENVPN_SCRAMBLE_MODE_XORMASK:
		OvsDataXorMask(data, size, s->ObfuscationMask, StrLen(s->ObfuscationMask));
		break;
	case OPENVPN_SCRAMBLE_MODE_XORPTRPOS:
		OvsDataXorPtrPos(data, size);
		break;
	case OPENVPN_SCRAMBLE_MODE_REVERSE:
		OvsDataReverse(data, size);
		break;
	case OPENVPN_SCRAMBLE_MODE_OBFUSCATE:
		OvsDataXorPtrPos(data, size);
		OvsDataReverse(data, size);
		OvsDataXorPtrPos(data, size);
		OvsDataXorMask(data, size, s->ObfuscationMask, StrLen(s->ObfuscationMask));
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

	for (i = 0; i < MIN(num_ack, OPENVPN_MAX_NUMACK); i++)
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

// Create a new OpenVPN server
OPENVPN_SERVER *NewOpenVpnServer(const LIST *options, CEDAR *cedar, INTERRUPT_MANAGER *interrupt, SOCK_EVENT *sock_event)
{
	UINT i;
	OPENVPN_SERVER *s;

	if (options == NULL || cedar == NULL || interrupt == NULL || sock_event == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(OPENVPN_SERVER));

	for (i = 0; i < LIST_NUM(options); ++i)
	{
		const PROTO_OPTION *option = LIST_DATA(options, i);
		if (StrCmp(option->Name, "DefaultClientOption") == 0)
		{
			s->DefaultClientOption = CopyStr(option->String);
		}
		else if (StrCmp(option->Name, "Obfuscation") == 0)
		{
			s->Obfuscation = option->Bool;
		}
		else if (StrCmp(option->Name, "ObfuscationMask") == 0)
		{
			s->ObfuscationMask = CopyStr(option->String);
		}
		else if (StrCmp(option->Name, "PushDummyIPv4AddressOnL2Mode") == 0)
		{
			s->PushDummyIPv4AddressOnL2Mode = option->Bool;
		}
	}

	s->Cedar = cedar;
	s->Interrupt = interrupt;
	s->SockEvent = sock_event;

	s->SessionList = NewList(OvsCompareSessionList);
	s->RecvPacketList = NewListFast(NULL);
	s->SendPacketList = NewListFast(NULL);

	s->Now = Tick64();
	s->Giveup = s->Now + OPENVPN_NEW_SESSION_DEADLINE_TIMEOUT;

	s->NextSessionId = 1;

	OvsLog(s, NULL, NULL, "LO_START");

	s->Dh = DhNewFromBits(cedar->DhParamBits);

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

	// Release the sessions list
	for (i = 0; i < LIST_NUM(s->SessionList); ++i)
	{
		OPENVPN_SESSION *se = LIST_DATA(s->SessionList, i);
		OvsFreeSession(se);
	}

	ReleaseList(s->SessionList);

	// Release the incoming packets list
	for (i = 0; i < LIST_NUM(s->RecvPacketList); ++i)
	{
		UDPPACKET *p = LIST_DATA(s->RecvPacketList, i);
		FreeUdpPacket(p);
	}

	ReleaseList(s->RecvPacketList);

	// Release the outgoing packets list
	for (i = 0; i < LIST_NUM(s->SendPacketList); ++i)
	{
		UDPPACKET *p = LIST_DATA(s->SendPacketList, i);
		FreeUdpPacket(p);
	}

	ReleaseList(s->SendPacketList);

	DhFree(s->Dh);

	Free(s->DefaultClientOption);
	Free(s->ObfuscationMask);

	Free(s);
}
