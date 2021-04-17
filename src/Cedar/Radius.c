// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Radius.c
// Radius authentication module

#include "Radius.h"

#include "Connection.h"
#include "IPC.h"
#include "Server.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

// send PEAP-MSCHAPv2 auth client response
bool PeapClientSendMsChapv2AuthClientResponse(EAP_CLIENT *e, UCHAR *client_response, UCHAR *client_challenge)
{
	bool ret = false;
	EAP_MSCHAPV2_RESPONSE msg1;
	EAP_MESSAGE msg2;
	EAP_MESSAGE msg4;
	if (e == NULL || client_response == NULL || client_challenge == NULL)
	{
		return false;
	}

	Zero(&msg1, sizeof(msg1));
	Zero(&msg2, sizeof(msg2));
	Zero(&msg4, sizeof(msg4));

	msg1.Type = EAP_TYPE_MS_AUTH;
	msg1.Chap_Opcode = EAP_MSCHAPV2_OP_RESPONSE;
	msg1.Chap_Id = e->MsChapV2Challenge.Chap_Id;
	msg1.Chap_Len = Endian16(54 + StrLen(e->Username));
	msg1.Chap_ValueSize = 49;
	Copy(msg1.Chap_PeerChallenge, client_challenge, 16);
	Copy(msg1.Chap_NtResponse, client_response, 24);
	Copy(msg1.Chap_Name, e->Username, MIN(StrLen(e->Username), 255));

	if (SendPeapPacket(e, &msg1, 59 + StrLen(e->Username)) &&
		GetRecvPeapMessage(e, &msg2))
	{
		if (msg2.Type == EAP_TYPE_MS_AUTH &&
			((EAP_MSCHAPV2_GENERAL *)&msg2)->Chap_Opcode == EAP_MSCHAPV2_OP_SUCCESS)
		{
			EAP_MSCHAPV2_SUCCESS_SERVER *eaps = (EAP_MSCHAPV2_SUCCESS_SERVER *)&msg2;

			if (StartWith(eaps->Message, "S="))
			{
				BUF *buf = StrToBin(eaps->Message + 2);

				if (buf && buf->Size == 20)
				{
					Copy(&e->MsChapV2Success, eaps, sizeof(EAP_MSCHAPV2_SUCCESS_SERVER));
					Copy(e->ServerResponse, buf->Buf, 20);

					if (true)
					{
						EAP_MSCHAPV2_SUCCESS_CLIENT msg3;

						Zero(&msg3, sizeof(msg3));
						msg3.Type = EAP_TYPE_MS_AUTH;
						msg3.Chap_Opcode = EAP_MSCHAPV2_OP_SUCCESS;

						if (SendPeapPacket(e, &msg3, 6) && GetRecvPeapMessage(e, &msg4))
						{
							UCHAR *rd = ((UCHAR *)&msg4);
							if (rd[4] == 0x01 && rd[8] == 0x21 && rd[9] == 0x80 &&
								rd[10] == 0x03 && rd[11] == 0x00 && rd[12] == 0x02 &&
								rd[13] == 0x00 && rd[14] == 0x01)
							{
								UCHAR reply[15];
								Zero(reply, sizeof(reply));
								reply[4] = 0x02;	reply[5] = rd[5];	reply[6] = 0x00;	reply[7] = 0x0b;
								reply[8] = 0x21;	reply[9] = 0x80;	reply[10] = 0x03;	reply[11] = 0x00;
								reply[12] = 0x02;	reply[13] = 0x00;	reply[14] = 0x01;
								if (SendPeapPacket(e, reply, sizeof(reply)))
								{
									if (e->RecvLastCode == RADIUS_CODE_ACCESS_ACCEPT)
									{
										ret = true;
									}
								}
							}
						}
					}
				}

				FreeBuf(buf);
			}
		}
	}

	return ret;
}

// send PEAP-MSCHAPv2 auth request
bool PeapClientSendMsChapv2AuthRequest(EAP_CLIENT *eap)
{
	bool ret = false;
	UINT num_retry = 0;
	if (eap == NULL)
	{
		return false;
	}

	if (StartPeapClient(eap))
	{
		if (StartPeapSslClient(eap))
		{
			EAP_MESSAGE recv_msg;
			EAP_MESSAGE send_msg;

			if (GetRecvPeapMessage(eap, &recv_msg) && recv_msg.Type == EAP_TYPE_IDENTITY)
			{
LABEL_RETRY:
				num_retry++;
				if (num_retry >= 10)
				{
					return false;
				}
				Zero(&send_msg, sizeof(send_msg));
				send_msg.Type = EAP_TYPE_IDENTITY;
				send_msg.Len = Endian16(5 + StrLen(eap->Username));
				Copy(send_msg.Data, eap->Username, StrLen(eap->Username));

				if (SendPeapPacket(eap, &send_msg, 5 + StrLen(eap->Username)) &&
					GetRecvPeapMessage(eap, &recv_msg))
				{
LABEL_RETRY2:
					num_retry++;
					if (num_retry >= 10)
					{
						return false;
					}
					if (recv_msg.Type == EAP_TYPE_MS_AUTH &&
						((EAP_MSCHAPV2_GENERAL *)&recv_msg)->Chap_Opcode == EAP_MSCHAPV2_OP_CHALLENGE)
					{
						EAP_MSCHAPV2_CHALLENGE *svr_challenge = (EAP_MSCHAPV2_CHALLENGE *)&recv_msg;

						Copy(&eap->MsChapV2Challenge, svr_challenge, sizeof(EAP_MSCHAPV2_CHALLENGE));

						ret = true;

						eap->PeapMode = true;
					}
					else if (recv_msg.Type == EAP_TYPE_IDENTITY)
					{
						UCHAR *rd = ((UCHAR *)&recv_msg);
						if (rd[4] == 0x01 && rd[8] == 0x21 && rd[9] == 0x80 &&
							rd[10] == 0x03 && rd[11] == 0x00 && rd[12] == 0x02 &&
							rd[13] == 0x00)
						{
							if (rd[14] == 0x02)
							{
								// Fail
								return false;
							}
						}

						goto LABEL_RETRY;
					}
					else
					{
						EAP_MESSAGE nak;

						Zero(&nak, sizeof(nak));
						nak.Type = EAP_TYPE_LEGACY_NAK;
						nak.Data[0] = EAP_TYPE_MS_AUTH;

						if (SendPeapPacket(eap, &nak, 6) &&
							GetRecvPeapMessage(eap, &recv_msg))
						{
							goto LABEL_RETRY2;
						}
					}
				}
			}
		}
	}
	return ret;
}

// Send a PEAP packet (encrypted)
bool SendPeapRawPacket(EAP_CLIENT *e, UCHAR *peap_data, UINT peap_size)
{
	LIST *fragments = NULL;
	bool ret = false;
	BUF *buf = NULL;
	UINT i;
	UINT num;
	bool send_empty = false;
	bool include_len = false;
	if (e == NULL)
	{
		return false;
	}

	// divide into 1024 bytes
	buf = NewBuf();

	// size
	if ((peap_size + 6 + 2) >= 256)
	{
		WriteBufInt(buf, peap_size);
		include_len = true;
	}

	// data
	WriteBuf(buf, peap_data, peap_size);

	if (peap_data == NULL)
	{
		send_empty = true;
	}

	SeekBufToBegin(buf);

	fragments = NewListFast(NULL);
	for (num = 0;;num++)
	{
		UCHAR tmp[200];
		EAP_PEAP *send_peap_message;
		UINT sz;

		sz = ReadBuf(buf, tmp, sizeof(tmp));

		if (sz == 0)
		{
			break;
		}

		// add header
		send_peap_message = ZeroMalloc(sizeof(EAP_PEAP) + sz);
		send_peap_message->Code = EAP_CODE_RESPONSE;
		send_peap_message->Id = e->LastRecvEapId + num;
		send_peap_message->Len = Endian16((UINT)(((UINT)sizeof(EAP_PEAP) + (UINT)sz)));
		send_peap_message->Type = EAP_TYPE_PEAP;
		send_peap_message->TlsFlags = 0;

		if (num == 0 && include_len)
		{
			send_peap_message->TlsFlags |= EAP_TLS_FLAGS_LEN;
		}
		if (ReadBufRemainSize(buf) != 0)
		{
			send_peap_message->TlsFlags |= EAP_TLS_FLAGS_MORE_FRAGMENTS;
		}

		Copy(((UCHAR *)send_peap_message) + sizeof(EAP_PEAP), tmp, sz);
	
		Add(fragments, MemToBuf(send_peap_message, sizeof(EAP_PEAP) + sz));

		Free(send_peap_message);
	}

	if (num == 0 && send_empty)
	{
		Add(fragments, MemToBuf("\0", 1));
	}

	// send each of packets
	for (i = 0;i < LIST_NUM(fragments);i++)
	{
		BUF *b = LIST_DATA(fragments, i);
		RADIUS_AVP *eap_avp;
		RADIUS_PACKET *response_packet;

		RADIUS_PACKET *send_packet = NewRadiusPacket(RADIUS_CODE_ACCESS_REQUEST, e->NextRadiusPacketId++);
		EapSetRadiusGeneralAttributes(send_packet, e);

		if (e->LastStateSize != 0)
		{
			Add(send_packet->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_STATE, 0, 0,
				e->LastState, e->LastStateSize));
		}

		if (send_empty == false)
		{
			eap_avp = NewRadiusAvp(RADIUS_ATTRIBUTE_EAP_MESSAGE, 0, 0, b->Buf, b->Size);
		}
		else
		{
			EAP_PEAP empty_peap;

			Zero(&empty_peap, sizeof(empty_peap));
			empty_peap.Code = EAP_CODE_RESPONSE;
			empty_peap.Id = e->LastRecvEapId;
			empty_peap.Len = Endian16(sizeof(EAP_PEAP));
			empty_peap.Type = EAP_TYPE_PEAP;

			eap_avp = NewRadiusAvp(RADIUS_ATTRIBUTE_EAP_MESSAGE, 0, 0, &empty_peap, sizeof(EAP_PEAP));
		}

		Add(send_packet->AvpList, eap_avp);

		response_packet = EapSendPacketAndRecvResponse(e, send_packet);

		if (response_packet != NULL)
		{
			e->RecvLastCode = response_packet->Code;

			if (response_packet->Parse_EapMessage != NULL && response_packet->Parse_EapMessage_DataSize >= sizeof(EAP_PEAP))
			{
				// Received SSL stream
				EAP_PEAP *peap_msg = (EAP_PEAP *)response_packet->Parse_EapMessage;

				if (peap_msg->Type == EAP_TYPE_PEAP)
				{
					if (peap_msg->TlsFlags & EAP_TLS_FLAGS_LEN)
					{
						UINT total_size = READ_UINT(((UCHAR *)peap_msg) + sizeof(EAP_PEAP));

						if (total_size <= (response_packet->Parse_EapMessage_DataSize - sizeof(EAP_PEAP) - sizeof(UINT)))
						{
							WriteFifo(e->SslPipe->RawIn->SendFifo, ((UCHAR *)peap_msg) + sizeof(EAP_PEAP) + sizeof(UINT), total_size);
						}
					}
					else
					{
						WriteFifo(e->SslPipe->RawIn->SendFifo, ((UCHAR *)peap_msg) + sizeof(EAP_PEAP),
							response_packet->Parse_EapMessage_DataSize - sizeof(EAP_PEAP));
					}
				}
			}
		}

		FreeRadiusPacket(send_packet);
		FreeRadiusPacket(response_packet);
	}

	FreeBuf(buf);

	if (fragments != NULL)
	{
		for (i = 0;i < LIST_NUM(fragments);i++)
		{
			BUF *b = LIST_DATA(fragments, i);

			FreeBuf(b);
		}

		ReleaseList(fragments);
	}

	SyncSslPipe(e->SslPipe);

	return ret;
}

// Send an encrypted message of PEAP
bool SendPeapPacket(EAP_CLIENT *e, void *msg, UINT msg_size)
{
	bool ret = false;
	FIFO *send_fifo;
	FIFO *recv_fifo;
	BUF *buf;
	EAP_MESSAGE tmpmsg;
	if (e == NULL || msg == NULL || msg_size == 0)
	{
		return false;
	}
	if (e->SslPipe == NULL)
	{
		return false;
	}

	send_fifo = e->SslPipe->RawOut->RecvFifo;
	recv_fifo = e->SslPipe->RawIn->SendFifo;

	Zero(&tmpmsg, sizeof(tmpmsg));
	Copy(&tmpmsg, msg, MIN(msg_size, sizeof(EAP_MESSAGE)));

	WriteFifo(e->SslPipe->SslInOut->SendFifo, &tmpmsg.Type, msg_size - 4);

	SyncSslPipe(e->SslPipe);

	buf = ReadFifoAll(send_fifo);

	while (true)
	{
		ret = SendPeapRawPacket(e, buf->Buf, buf->Size);
		FreeBuf(buf);

		if (send_fifo->size == 0)
		{
			break;
		}

		buf = ReadFifoAll(send_fifo);
	}

	return !e->SslPipe->IsDisconnected;
}

// Start a PEAP SSL client
bool StartPeapSslClient(EAP_CLIENT *e)
{
	bool ret = false;
	FIFO *send_fifo;
	FIFO *recv_fifo;
	BUF *buf;
	if (e == NULL)
	{
		return false;
	}
	if (e->SslPipe != NULL)
	{
		return false;
	}

	e->SslPipe = NewSslPipe(false, NULL, NULL, NULL);
	send_fifo = e->SslPipe->RawOut->RecvFifo;
	recv_fifo = e->SslPipe->RawIn->SendFifo;

	SyncSslPipe(e->SslPipe);

	buf = ReadFifoAll(send_fifo);

	while (true)
	{
		ret = SendPeapRawPacket(e, buf->Buf, buf->Size);
		FreeBuf(buf);

		if (send_fifo->size == 0)
		{
			break;
		}

		buf = ReadFifoAll(send_fifo);
	}

	SendPeapRawPacket(e, NULL, 0);

	return !e->SslPipe->IsDisconnected;
}

// Get a received PEAP message (unencrypted)
bool GetRecvPeapMessage(EAP_CLIENT *e, EAP_MESSAGE *msg)
{
	BUF *b;
	bool ret = false;
	if (e == NULL)
	{
		return false;
	}
	if (e->SslPipe == NULL)
	{
		return false;
	}

	b = ReadFifoAll(e->SslPipe->SslInOut->RecvFifo);

	if (b->Size >= 1)
	{
		Zero(msg, sizeof(EAP_MESSAGE));

		msg->Len = Endian16(b->Size + 4);
		Copy(&msg->Type, b->Buf, MIN(b->Size, 1501));

		ret = true;
	}

	FreeBuf(b);

	return ret;
}

// Start a PEAP client
bool StartPeapClient(EAP_CLIENT *e)
{
	bool ret = false;
	RADIUS_PACKET *request1 = NULL;
	RADIUS_PACKET *response1 = NULL;
	RADIUS_PACKET *request2 = NULL;
	RADIUS_PACKET *response2 = NULL;
	EAP_MESSAGE *eap1 = NULL;
	EAP_MESSAGE *eap2 = NULL;
	if (e == NULL)
	{
		return false;
	}
	if (e->SslPipe != NULL)
	{
		return false;
	}

	request1 = NewRadiusPacket(RADIUS_CODE_ACCESS_REQUEST, e->NextRadiusPacketId++);
	EapSetRadiusGeneralAttributes(request1, e);

	eap1 = ZeroMalloc(sizeof(EAP_MESSAGE));
	eap1->Code = EAP_CODE_RESPONSE;
	eap1->Id = e->LastRecvEapId;
	eap1->Len = Endian16(StrLen(e->Username) + 5);
	eap1->Type = EAP_TYPE_IDENTITY;
	Copy(eap1->Data, e->Username, StrLen(e->Username));
	Add(request1->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_EAP_MESSAGE, 0, 0, eap1, StrLen(e->Username) + 5));

	response1 = EapSendPacketAndRecvResponse(e, request1);

	if (response1 != NULL)
	{
		if (response1->Parse_EapMessage_DataSize != 0 && response1->Parse_EapMessage != NULL)
		{
			EAP_MESSAGE *eap = response1->Parse_EapMessage;
			if (eap->Code == EAP_CODE_REQUEST)
			{
				if (eap->Type != EAP_TYPE_PEAP)
				{
					// Unsupported auth type. Request PEAP.
					request2 = NewRadiusPacket(RADIUS_CODE_ACCESS_REQUEST, e->NextRadiusPacketId++);
					EapSetRadiusGeneralAttributes(request2, e);

					if (response1->Parse_StateSize != 0)
					{
						Add(request2->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_STATE, 0, 0,
							response1->Parse_State, response1->Parse_StateSize));
					}

					eap2 = ZeroMalloc(sizeof(EAP_MESSAGE));
					eap2->Code = EAP_CODE_RESPONSE;
					eap2->Id = e->LastRecvEapId;
					eap2->Len = Endian16(6);
					eap2->Type = EAP_TYPE_LEGACY_NAK;
					eap2->Data[0] = EAP_TYPE_PEAP;

					Add(request2->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_EAP_MESSAGE, 0, 0, eap2, 6));

					response2 = EapSendPacketAndRecvResponse(e, request2);

					if (response2 != NULL && response2->Parse_EapMessage_DataSize != 0 && response2->Parse_EapMessage != NULL)
					{
						eap = response2->Parse_EapMessage;

						if (eap->Code == EAP_CODE_REQUEST && eap->Type == EAP_TYPE_PEAP)
						{
							goto LABEL_PARSE_PEAP;
						}
					}
				}
				else
				{
					EAP_PEAP *peap;
LABEL_PARSE_PEAP:
					peap = (EAP_PEAP *)eap;

					if (peap->TlsFlags == 0x20)
					{
						ret = true;
					}
				}
			}
		}
	}

	FreeRadiusPacket(request1);
	FreeRadiusPacket(request2);
	FreeRadiusPacket(response1);
	FreeRadiusPacket(response2);
	Free(eap1);
	Free(eap2);

	return ret;
}

// Set RADIUS general attributes
void EapSetRadiusGeneralAttributes(RADIUS_PACKET *r, EAP_CLIENT *e)
{
	UINT ui;
	char *str;
	if (r == NULL || e == NULL)
	{
		return;
	}

	ui = Endian32(2);
	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_SERVICE_TYPE, 0, 0, &ui, sizeof(UINT)));

	ui = Endian32(1);
	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_FRAMED_PROTOCOL, 0, 0, &ui, sizeof(UINT)));

	ui = Endian32(5);
	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_NAS_PORT_TYPE, 0, 0, &ui, sizeof(UINT)));

	if (IsEmptyStr(e->CalledStationStr) == false)
	{
		Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_CALLED_STATION_ID, 0, 0, e->CalledStationStr, StrLen(e->CalledStationStr)));
	}

	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_CALLING_STATION_ID, 0, 0, e->ClientIpStr, StrLen(e->ClientIpStr)));

	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_TUNNEL_CLIENT_ENDPOINT, 0, 0, e->ClientIpStr, StrLen(e->ClientIpStr)));

	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_USER_NAME, 0, 0, e->Username, StrLen(e->Username)));

	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_NAS_ID, 0, 0, CEDAR_SERVER_STR, StrLen(CEDAR_SERVER_STR)));

	if (IsEmptyStr(e->In_VpnProtocolState) == false)
	{
		Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_PROXY_STATE, 0, 0, e->In_VpnProtocolState, StrLen(e->In_VpnProtocolState)));
	}

	ui = Endian32(2);
	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT,
		RADIUS_MS_NETWORK_ACCESS_SERVER_TYPE, &ui, sizeof(UINT)));

	ui = Endian32(RADIUS_VENDOR_MICROSOFT);
	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT,
		RADIUS_MS_RAS_VENDOR, &ui, sizeof(UINT)));

	str = "MSRASV5.20";
	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT,
		RADIUS_MS_VERSION, str, StrLen(str)));

	str = "{5DC53D72-9815-4E97-AC91-339BAFEA6C48}";
	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT,
		RADIUS_MS_RAS_CORRELATION, str, StrLen(str)));

	str = "MSRASV5.20";
	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT,
		RADIUS_MS_RAS_CLIENT_VERSION, str, StrLen(str)));

	str = "MSRASV5.20";
	Add(r->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT,
		RADIUS_MS_RAS_CLIENT_NAME, str, StrLen(str)));
}

// Send a MSCHAPv2 client auth response1
bool EapClientSendMsChapv2AuthClientResponse(EAP_CLIENT *e, UCHAR *client_response, UCHAR *client_challenge)
{
	bool ret = false;
	RADIUS_PACKET *request1 = NULL;
	RADIUS_PACKET *response1 = NULL;
	RADIUS_PACKET *request2 = NULL;
	RADIUS_PACKET *response2 = NULL;
	EAP_MSCHAPV2_RESPONSE *eap1 = NULL;
	EAP_MSCHAPV2_SUCCESS_CLIENT *eap2 = NULL;
	if (e == NULL || client_response == NULL || client_challenge == NULL)
	{
		return false;
	}

	request1 = NewRadiusPacket(RADIUS_CODE_ACCESS_REQUEST, e->NextRadiusPacketId++);
	EapSetRadiusGeneralAttributes(request1, e);

	if (e->LastStateSize != 0)
	{
		Add(request1->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_STATE, 0, 0,
			e->LastState, e->LastStateSize));
	}

	eap1 = ZeroMalloc(sizeof(EAP_MSCHAPV2_RESPONSE));
	eap1->Code = EAP_CODE_RESPONSE;
	eap1->Id = e->NextEapId++;
	eap1->Len = Endian16(59 + StrLen(e->Username));
	eap1->Type = EAP_TYPE_MS_AUTH;
	eap1->Chap_Opcode = EAP_MSCHAPV2_OP_RESPONSE;
	eap1->Chap_Id = e->MsChapV2Challenge.Chap_Id;
	eap1->Chap_Len = Endian16(54 + StrLen(e->Username));
	eap1->Chap_ValueSize = 49;
	Copy(eap1->Chap_PeerChallenge, client_challenge, 16);
	Copy(eap1->Chap_NtResponse, client_response, 24);
	Copy(eap1->Chap_Name, e->Username, MIN(StrLen(e->Username), 255));

	Add(request1->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_EAP_MESSAGE, 0, 0, eap1, StrLen(e->Username) + 59));

	response1 = EapSendPacketAndRecvResponse(e, request1);

	if (response1 != NULL)
	{
		if (response1->Parse_EapMessage_DataSize != 0 && response1->Parse_EapMessage != NULL)
		{
			EAP_MESSAGE *eap = response1->Parse_EapMessage;
			if (eap->Code == EAP_CODE_REQUEST)
			{
				if (eap->Type == EAP_TYPE_MS_AUTH)
				{
					if (((EAP_MSCHAPV2_GENERAL *)eap)->Chap_Opcode != EAP_MSCHAPV2_OP_SUCCESS)
					{
						// Auth fail
					}
					else
					{
						// Auth ok
						EAP_MSCHAPV2_SUCCESS_SERVER *eaps = (EAP_MSCHAPV2_SUCCESS_SERVER *)eap;

						if (StartWith(eaps->Message, "S="))
						{
							BUF *buf = StrToBin(eaps->Message + 2);

							if (buf && buf->Size == 20)
							{
								Copy(&e->MsChapV2Success, eaps, sizeof(EAP_MSCHAPV2_SUCCESS_SERVER));
								Copy(e->ServerResponse, buf->Buf, 20);

								if (true)
								{
									// Send the final packet
									request2 = NewRadiusPacket(RADIUS_CODE_ACCESS_REQUEST, e->NextRadiusPacketId++);
									EapSetRadiusGeneralAttributes(request2, e);

									if (e->LastStateSize != 0)
									{
										Add(request2->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_STATE, 0, 0,
											e->LastState, e->LastStateSize));
									}

									eap2 = ZeroMalloc(sizeof(EAP_MSCHAPV2_SUCCESS_CLIENT));
									eap2->Code = EAP_CODE_RESPONSE;
									eap2->Id = e->NextEapId++;
									eap2->Len = Endian16(6);
									eap2->Type = EAP_TYPE_MS_AUTH;
									eap2->Chap_Opcode = EAP_MSCHAPV2_OP_SUCCESS;

									Add(request2->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_EAP_MESSAGE, 0, 0, eap2, 6));

									response2 = EapSendPacketAndRecvResponse(e, request2);

									if (response2 != NULL)
									{
										if (response2->Code == RADIUS_CODE_ACCESS_ACCEPT)
										{
											ret = true;
										}
									}
								}
							}

							FreeBuf(buf);
						}
					}
				}
			}
		}
	}

	FreeRadiusPacket(request1);
	FreeRadiusPacket(request2);
	FreeRadiusPacket(response1);
	FreeRadiusPacket(response2);
	Free(eap1);
	Free(eap2);

	return ret;
}

// Send a MSCHAPv2 client auth request
bool EapClientSendMsChapv2AuthRequest(EAP_CLIENT *e)
{
	bool ret = false;
	RADIUS_PACKET *request1 = NULL;
	RADIUS_PACKET *response1 = NULL;
	RADIUS_PACKET *request2 = NULL;
	RADIUS_PACKET *response2 = NULL;
	EAP_MESSAGE *eap1 = NULL;
	EAP_MESSAGE *eap2 = NULL;
	if (e == NULL)
	{
		return false;
	}

	request1 = NewRadiusPacket(RADIUS_CODE_ACCESS_REQUEST, e->NextRadiusPacketId++);
	EapSetRadiusGeneralAttributes(request1, e);

	eap1 = ZeroMalloc(sizeof(EAP_MESSAGE));
	eap1->Code = EAP_CODE_RESPONSE;
	eap1->Id = e->NextEapId++;
	eap1->Len = Endian16(StrLen(e->Username) + 5);
	eap1->Type = EAP_TYPE_IDENTITY;
	Copy(eap1->Data, e->Username, StrLen(e->Username));
	Add(request1->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_EAP_MESSAGE, 0, 0, eap1, StrLen(e->Username) + 5));

	response1 = EapSendPacketAndRecvResponse(e, request1);

	if (response1 != NULL)
	{
		if (response1->Parse_EapMessage_DataSize != 0 && response1->Parse_EapMessage != NULL)
		{
			EAP_MESSAGE *eap = response1->Parse_EapMessage;
			if (eap->Code == EAP_CODE_REQUEST)
			{
				if (eap->Type != EAP_TYPE_MS_AUTH)
				{
					// Unsupported auth type. Request MS-CHAP-v2.
					request2 = NewRadiusPacket(RADIUS_CODE_ACCESS_REQUEST, e->NextRadiusPacketId++);
					EapSetRadiusGeneralAttributes(request2, e);

					if (response1->Parse_StateSize != 0)
					{
						Add(request2->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_STATE, 0, 0,
							response1->Parse_State, response1->Parse_StateSize));
					}

					eap2 = ZeroMalloc(sizeof(EAP_MESSAGE));
					eap2->Code = EAP_CODE_RESPONSE;
					eap2->Id = e->NextEapId++;
					eap2->Len = Endian16(6);
					eap2->Type = EAP_TYPE_LEGACY_NAK;
					eap2->Data[0] = EAP_TYPE_MS_AUTH;

					Add(request2->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_EAP_MESSAGE, 0, 0, eap2, 6));

					response2 = EapSendPacketAndRecvResponse(e, request2);

					if (response2 != NULL && response2->Parse_EapMessage_DataSize != 0 && response2->Parse_EapMessage != NULL)
					{
						eap = response2->Parse_EapMessage;

						if (eap->Code == EAP_CODE_REQUEST && eap->Type == EAP_TYPE_MS_AUTH)
						{
							goto LABEL_PARSE_EAP;
						}
					}
				}
				else
				{
					EAP_MSCHAPV2_GENERAL *ms_g;
LABEL_PARSE_EAP:
					ms_g = (EAP_MSCHAPV2_GENERAL *)eap;

					if (ms_g->Chap_Opcode == EAP_MSCHAPV2_OP_CHALLENGE)
					{
						EAP_MSCHAPV2_CHALLENGE *ms_c = (EAP_MSCHAPV2_CHALLENGE *)eap;
						if (ms_c->Chap_ValueSize == 16)
						{
							Copy(&e->MsChapV2Challenge, ms_c, sizeof(EAP_MSCHAPV2_CHALLENGE));

							ret = true;
						}
					}
				}
			}
		}
	}

	FreeRadiusPacket(request1);
	FreeRadiusPacket(request2);
	FreeRadiusPacket(response1);
	FreeRadiusPacket(response2);
	Free(eap1);
	Free(eap2);

	return ret;
}

// Send a packet and recv a response
RADIUS_PACKET *EapSendPacketAndRecvResponse(EAP_CLIENT *e, RADIUS_PACKET *r)
{
	SOCKSET set;
	UINT64 giveup_tick = 0;
	UINT64 next_send_tick = 0;
	bool select_inited = false;
	bool free_r = false;
	RADIUS_PACKET *ret = NULL;
	if (e == NULL || r == NULL)
	{
		return NULL;
	}

	ClearBuf(e->PEAP_CurrentReceivingMsg);
	e->PEAP_CurrentReceivingTotalSize = 0;

	InitSockSet(&set);
	AddSockSet(&set, e->UdpSock);

	while (true)
	{
		UINT64 now = Tick64();
		UINT wait_time = INFINITE;
		bool is_finish = false;

		if (giveup_tick == 0)
		{
			giveup_tick = now + (UINT64)e->GiveupTimeout;
		}

		if (giveup_tick <= now)
		{
			break;
		}

		if (select_inited)
		{
			UINT num_error = 0;

			while (true)
			{
				IP from_ip;
				UINT from_port;
				UINT size;
				UCHAR *tmp = e->TmpBuffer;

				size = RecvFrom(e->UdpSock, &from_ip, &from_port, tmp, sizeof(e->TmpBuffer));
				if (size == 0 && e->UdpSock->IgnoreRecvErr == false)
				{
					// UDP socket error
					is_finish = true;
					break;
				}
				else if (size == SOCK_LATER)
				{
					break;
				}
				if (size == 0 && e->UdpSock->IgnoreRecvErr)
				{
					num_error++;
					if (num_error >= 100)
					{
						is_finish = true;
						break;
					}
				}

				// Receive a response packet
				if (size != SOCK_LATER && size >= 1)
				{
					if (CmpIpAddr(&from_ip, &e->ServerIp) == 0 && from_port == e->ServerPort)
					{
						RADIUS_PACKET *rp = ParseRadiusPacket(tmp, size);
						if (rp != NULL)
						{
							RADIUS_AVP *eap_msg = GetRadiusAvp(rp, RADIUS_ATTRIBUTE_EAP_MESSAGE);
							RADIUS_AVP *vlan_avp = GetRadiusAvp(rp, RADIUS_ATTRIBUTE_VLAN_ID);
							RADIUS_AVP *framed_interface_id_avp = GetRadiusAvp(rp, RADIUS_ATTRIBUTE_FRAMED_INTERFACE_ID);
							if (eap_msg != NULL)
							{
								e->LastRecvEapId = ((EAP_MESSAGE *)(eap_msg->Data))->Id;
							}

							if (framed_interface_id_avp != NULL)
							{
								// FRAMED_INTERFACE_ID
								char tmp_str[64];
								UCHAR mac_address[6];

								Zero(tmp_str, sizeof(tmp_str));
								Copy(tmp_str, framed_interface_id_avp->Data, MIN(framed_interface_id_avp->DataSize, sizeof(tmp_str) - 1));

								if (StrToMac(mac_address, tmp_str))
								{
									Copy(e->LastRecvVirtualMacAddress, mac_address, 6);
								}
							}

							if (vlan_avp != NULL)
							{
								// VLAN ID
								UINT vlan_id = 0;
								char tmp[32];

								Zero(tmp, sizeof(tmp));

								Copy(tmp, vlan_avp->Data, MIN(vlan_avp->DataSize, sizeof(tmp) - 1));

								vlan_id = ToInt(tmp);

								e->LastRecvVLanId = vlan_id;
							}

							// Validate the received packet
							if (rp->Parse_EapAuthMessagePos != 0 && rp->Parse_AuthenticatorPos != 0)
							{
								UCHAR *tmp_buffer = Clone(tmp, size);
								UCHAR auth1[16];
								UCHAR auth2[16];

								Copy(auth1, &tmp_buffer[rp->Parse_EapAuthMessagePos], 16);

								Zero(&tmp_buffer[rp->Parse_EapAuthMessagePos], 16);
								Copy(&tmp_buffer[rp->Parse_AuthenticatorPos], r->Authenticator, 16);

								HMacMd5(auth2, e->SharedSecret, StrLen(e->SharedSecret),
									tmp_buffer, size);

								if (Cmp(auth1, auth2, 16) == 0)
								{
									bool send_ack_packet = false;

									// ok
									Copy(e->LastState, rp->Parse_State, rp->Parse_StateSize);
									e->LastStateSize = rp->Parse_StateSize;

									if (rp->Parse_EapMessage_DataSize != 0 && rp->Parse_EapMessage != NULL)
									{
										EAP_MESSAGE *eap_msg = (EAP_MESSAGE *)rp->Parse_EapMessage;

										if (eap_msg->Type == EAP_TYPE_PEAP)
										{
											EAP_PEAP *peap_message = (EAP_PEAP *)eap_msg;

											if (peap_message->TlsFlags & EAP_TLS_FLAGS_MORE_FRAGMENTS || e->PEAP_CurrentReceivingTotalSize != 0)
											{
												// more fragments: reply ack
												RADIUS_PACKET *ack_packet = NewRadiusPacket(RADIUS_CODE_ACCESS_REQUEST, e->NextRadiusPacketId++);
												EAP_PEAP *ack_msg = ZeroMalloc(sizeof(EAP_PEAP));

												EapSetRadiusGeneralAttributes(ack_packet, e);
												if (e->LastStateSize != 0)
												{
													Add(ack_packet->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_STATE, 0, 0,
														e->LastState, e->LastStateSize));
												}

												ack_msg->Code = EAP_CODE_RESPONSE;
												ack_msg->Id = e->LastRecvEapId;
												ack_msg->Len = Endian16(6);
												ack_msg->Type = EAP_TYPE_PEAP;
												ack_msg->TlsFlags = 0;

												Add(ack_packet->AvpList, NewRadiusAvp(RADIUS_ATTRIBUTE_EAP_MESSAGE, 0, 0,
													ack_msg, sizeof(EAP_PEAP)));

												next_send_tick = 0;

												if (free_r)
												{
													FreeRadiusPacket(r);
												}

												r = ack_packet;
												free_r = true;

												Free(ack_msg);

												send_ack_packet = true;

												if (e->PEAP_CurrentReceivingTotalSize == 0)
												{
													if (peap_message->TlsFlags & EAP_TLS_FLAGS_LEN)
													{
														if (Endian16(peap_message->Len) >= 9)
														{
															UINT total_size = READ_UINT(((UCHAR *)peap_message) + sizeof(EAP_PEAP));

															if (total_size < 65536)
															{
																if (rp->Parse_EapMessage_DataSize >= 1)
																{
																	e->PEAP_CurrentReceivingTotalSize = total_size;

																	WriteBuf(e->PEAP_CurrentReceivingMsg,
																		((UCHAR *)peap_message), 
																		rp->Parse_EapMessage_DataSize);
																}
															}
														}
													}
												}
												else
												{
													if ((!(peap_message->TlsFlags & EAP_TLS_FLAGS_LEN)) &&
														rp->Parse_EapMessage_DataSize >= sizeof(EAP_PEAP))
													{
														WriteBuf(e->PEAP_CurrentReceivingMsg,
															((UCHAR *)peap_message) + sizeof(EAP_PEAP), 
															rp->Parse_EapMessage_DataSize - sizeof(EAP_PEAP));

														if (e->PEAP_CurrentReceivingTotalSize <= e->PEAP_CurrentReceivingMsg->Size)
														{
															// all fragmented segments are arrived
															send_ack_packet = false;

															is_finish = true;

															Free(rp->Parse_EapMessage);
															rp->Parse_EapMessage = Clone(e->PEAP_CurrentReceivingMsg->Buf, e->PEAP_CurrentReceivingMsg->Size);
															rp->Parse_EapMessage_DataSize = e->PEAP_CurrentReceivingMsg->Size;
														}
													}
												}
											}
										}
									}

									if (send_ack_packet == false)
									{
										ret = rp;
									}
								}

								Free(tmp_buffer);
							}

							if (ret != NULL)
							{
								is_finish = true;
								break;
							}
							else
							{
								FreeRadiusPacket(rp);
							}
						}
					}
				}
			}
		}

		if (is_finish)
		{
			break;
		}

		if (next_send_tick == 0 || next_send_tick <= now)
		{
			next_send_tick = now + (UINT64)e->ResendTimeout;

			if (EapSendPacket(e, r) == false)
			{
				is_finish = true;
			}
		}

		wait_time = MIN(wait_time, (UINT)(next_send_tick - now));
		wait_time = MIN(wait_time, (UINT)(giveup_tick - now));
		wait_time = MAX(wait_time, 1);

		if (is_finish)
		{
			break;
		}

		Select(&set, wait_time, NULL, NULL);
		select_inited = true;
	}

	if (free_r)
	{
		FreeRadiusPacket(r);
	}

	return ret;
}

// Send a RADIUS packet
bool EapSendPacket(EAP_CLIENT *e, RADIUS_PACKET *r)
{
	BUF *b;
	bool ret = false;
	if (e == NULL || r == NULL)
	{
		return false;
	}

	b = GenerateRadiusPacket(r, e->SharedSecret);
	if (b != NULL)
	{
		UINT r = SendTo(e->UdpSock, &e->ServerIp, e->ServerPort, b->Buf, b->Size);
		if (!(r == 0 && e->UdpSock->IgnoreSendErr == false))
		{
			ret = true;
		}


		FreeBuf(b);
	}

	return ret;
}

// New EAP client
EAP_CLIENT *NewEapClient(IP *server_ip, UINT server_port, char *shared_secret, UINT resend_timeout, UINT giveup_timeout, char *client_ip_str, char *username, char *hubname)
{
	EAP_CLIENT *e;
	if (server_ip == NULL)
	{
		return NULL;
	}
	if (resend_timeout == 0)
	{
		resend_timeout = RADIUS_RETRY_INTERVAL;
	}
	if (giveup_timeout == 0)
	{
		giveup_timeout = RADIUS_RETRY_TIMEOUT;
	}

	e = ZeroMalloc(sizeof(EAP_CLIENT));

	e->Ref = NewRef();

	e->NextRadiusPacketId = 1;

	e->UdpSock = NewUDPEx(0, IsIP6(server_ip));
	Copy(&e->ServerIp, server_ip, sizeof(IP));
	e->ServerPort = server_port;
	e->ResendTimeout = resend_timeout;
	e->GiveupTimeout = giveup_timeout;
	StrCpy(e->SharedSecret, sizeof(e->SharedSecret), shared_secret);

	StrCpy(e->CalledStationStr, sizeof(e->CalledStationStr), hubname);
	StrCpy(e->ClientIpStr, sizeof(e->ClientIpStr), client_ip_str);
	StrCpy(e->Username, sizeof(e->Username), username);
	e->LastRecvEapId = 0;

	e->PEAP_CurrentReceivingMsg = NewBuf();

	return e;
}

// Free a EAP client
void ReleaseEapClient(EAP_CLIENT *e)
{
	if (e == NULL)
	{
		return;
	}

	if (Release(e->Ref) == 0)
	{
		CleanupEapClient(e);
	}
}
void CleanupEapClient(EAP_CLIENT *e)
{
	if (e == NULL)
	{
		return;
	}

	Disconnect(e->UdpSock);
	ReleaseSock(e->UdpSock);

	FreeSslPipe(e->SslPipe);

	FreeBuf(e->PEAP_CurrentReceivingMsg);

	Free(e);
}

// New RADIUS AVP value
RADIUS_AVP *NewRadiusAvp(UCHAR type, UINT vendor_id, UCHAR vendor_code, void *data, UINT size)
{
	RADIUS_AVP *p = ZeroMalloc(sizeof(RADIUS_AVP));

	p->Type = type;
	p->VendorId = vendor_id;
	p->VendorCode = vendor_code;
	p->DataSize = (UCHAR)size;
	Copy(p->Data, data, (UCHAR)size);

	if (size >= 256)
	{
		Debug("!! size = %u\n", size);
	}

	return p;
}

// New RADIUS packet
RADIUS_PACKET *NewRadiusPacket(UCHAR code, UCHAR packet_id)
{
	RADIUS_PACKET *r = ZeroMalloc(sizeof(RADIUS_PACKET));

	r->Code = code;
	r->PacketId = packet_id;

	r->AvpList = NewListFast(NULL);

	return r;
}

// Get RADIUS AVP
RADIUS_AVP *GetRadiusAvp(RADIUS_PACKET *p, UCHAR type)
{
	UINT i;
	if (p == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(p->AvpList);i++)
	{
		RADIUS_AVP *avp = LIST_DATA(p->AvpList, i);

		if (avp->Type == type)
		{
			return avp;
		}
	}

	return NULL;
}

// Free a RADIUS packet
void FreeRadiusPacket(RADIUS_PACKET *p)
{
	UINT i;
	if (p == NULL)
	{
		return;
	}

	if (p->AvpList != NULL)
	{
		for (i = 0;i < LIST_NUM(p->AvpList);i++)
		{
			RADIUS_AVP *a = LIST_DATA(p->AvpList, i);

			Free(a);
		}

		ReleaseList(p->AvpList);
	}

	Free(p->Parse_EapMessage);

	Free(p);
}

// Generate a RADIUS packet
BUF *GenerateRadiusPacket(RADIUS_PACKET *p, char *shared_secret)
{
	BUF *b;
	UINT i;
	UCHAR zero16[16];
	UINT len_pos = 0;
	UINT eap_auth_pos = 0;
	bool exist_eap_msg = false;
	bool exist_eap_auth = false;
	if (p == NULL)
	{
		return NULL;
	}

	Zero(zero16, sizeof(zero16));

	// Add EAP message auth packet
	for (i = 0;i < LIST_NUM(p->AvpList);i++)
	{
		RADIUS_AVP *a = (RADIUS_AVP *)LIST_DATA(p->AvpList, i);

		if (a->Type == RADIUS_ATTRIBUTE_EAP_MESSAGE)
		{
			exist_eap_msg = true;
		}
		if (a->Type == RADIUS_ATTRIBUTE_EAP_AUTHENTICATOR)
		{
			exist_eap_auth = true;
		}
	}

	if (exist_eap_msg && exist_eap_auth == false)
	{
		RADIUS_AVP *a = NewRadiusAvp(RADIUS_ATTRIBUTE_EAP_AUTHENTICATOR, 0, 0, zero16, sizeof(zero16));

		Add(p->AvpList, a);
	}

	if (IsZero(p->Authenticator, 16))
	{
		UCHAR rand16[16];

		Rand(rand16, sizeof(rand16));
		Copy(p->Authenticator, rand16, 16);
	}

	b = NewBuf();

	WriteBufChar(b, p->Code);
	WriteBufChar(b, p->PacketId);
	len_pos = b->Current;
	WriteBufShort(b, 0);
	WriteBuf(b, p->Authenticator, 16);

	for (i = 0;i < LIST_NUM(p->AvpList);i++)
	{
		RADIUS_AVP *a = (RADIUS_AVP *)LIST_DATA(p->AvpList, i);

		WriteBufChar(b, a->Type);

		if (a->Type != RADIUS_ATTRIBUTE_VENDOR_SPECIFIC)
		{
			WriteBufChar(b, (UCHAR)((UINT)a->DataSize + 2));

			if (a->Type == RADIUS_ATTRIBUTE_EAP_AUTHENTICATOR)
			{
				eap_auth_pos = b->Current;

				if (a->DataSize == 16)
				{
					Zero(a->Data, sizeof(a->Data));
				}
			}

			WriteBuf(b, a->Data, a->DataSize);
		}
		else
		{
			WriteBufChar(b, (UCHAR)((UINT)a->DataSize + 8));
			WriteBufInt(b, a->VendorId);
			WriteBufChar(b, a->VendorCode);
			WriteBufChar(b, (UCHAR)((UINT)a->DataSize + 2));
			WriteBuf(b, a->Data, a->DataSize);
		}
	}

	WRITE_USHORT(((UCHAR *)b->Buf) + len_pos, b->Size);

	if (eap_auth_pos != 0)
	{
		UCHAR eap_auth[16];

		HMacMd5(eap_auth, shared_secret, StrLen(shared_secret), b->Buf, b->Size);

		Copy(((UCHAR *)b->Buf) + eap_auth_pos, eap_auth, 16);
	}

	SeekBufToBegin(b);

	return b;
}

// Parse a RADIUS packet
RADIUS_PACKET *ParseRadiusPacket(void *data, UINT size)
{
	RADIUS_PACKET *p = NULL;
	BUF *buf = NULL;
	USHORT len;
	UCHAR auth[16];
	if (data == NULL || size == 0)
	{
		return NULL;
	}

	p = ZeroMalloc(sizeof(RADIUS_PACKET));

	p->AvpList = NewListFast(NULL);

	buf = MemToBuf(data, size);

	// Code
	p->Code = ReadBufChar(buf);
	p->PacketId = ReadBufChar(buf);
	len = ReadBufShort(buf);

	p->Parse_AuthenticatorPos = buf->Current;
	if (ReadBuf(buf, auth, 16) != 16)
	{
		goto LABEL_ERROR;
	}

	if ((UINT)len < 20)
	{
		goto LABEL_ERROR;
	}
	if ((UINT)len > buf->Size)
	{
		goto LABEL_ERROR;
	}
	else if ((UINT)len < buf->Size)
	{
		buf->Size = len;
	}

	while (true)
	{
		RADIUS_AVP a;
		UCHAR uc;
		UINT data_size;

		Zero(&a, sizeof(a));

		if (ReadBuf(buf, &a.Type, 1) == 0)
		{
			break;
		}

		if (a.Type != RADIUS_ATTRIBUTE_VENDOR_SPECIFIC)
		{
			if (ReadBuf(buf, &uc, 1) == 0)
			{
				break;
			}

			data_size = (UINT)uc;

			if (data_size < 2)
			{
				goto LABEL_ERROR;
			}

			data_size -= 2;

			a.DataSize = (UCHAR)data_size;

			if (a.Type == RADIUS_ATTRIBUTE_EAP_AUTHENTICATOR && a.DataSize == 16)
			{
				p->Parse_EapAuthMessagePos = buf->Current;
			}

			if (ReadBuf(buf, a.Data, a.DataSize) != a.DataSize)
			{
				goto LABEL_ERROR;
			}

			if (a.Type == RADIUS_ATTRIBUTE_EAP_MESSAGE && a.DataSize >= 5)
			{
				UINT sz_tmp = Endian16(((EAP_MESSAGE *)a.Data)->Len);

				if (sz_tmp >= 5 && sz_tmp <= a.DataSize)
				{
					if (p->Parse_EapMessage == NULL)
					{
						EAP_MESSAGE *eap = Clone(a.Data, a.DataSize);

						p->Parse_EapMessage_DataSize = sz_tmp;

						p->Parse_EapMessage = eap;
					}
				}
			}
		}
		else
		{
			if (ReadBuf(buf, &uc, 1) == 0)
			{
				break;
			}

			data_size = (UINT)uc;
			if (data_size < 8)
			{
				goto LABEL_ERROR;
			}

			data_size -= 8;

			a.VendorId = ReadBufInt(buf);
			a.VendorCode = ReadBufChar(buf);
			if (ReadBuf(buf, &uc, 1) == 0)
			{
				break;
			}

			if (((UINT)uc - 2) != data_size)
			{
				goto LABEL_ERROR;
			}

			a.DataSize = (UINT)data_size;

			if (ReadBuf(buf, a.Data, a.DataSize) != a.DataSize)
			{
				goto LABEL_ERROR;
			}
		}

		Add(p->AvpList, Clone(&a, sizeof(RADIUS_AVP)));
	}

	FreeBuf(buf);

	if (true)
	{
		UINT num, i;
		RADIUS_AVP *avp = GetRadiusAvp(p, RADIUS_ATTRIBUTE_STATE);

		if (avp != NULL)
		{
			Copy(p->Parse_State, avp->Data, avp->DataSize);
			p->Parse_StateSize = avp->DataSize;
		}

		num = 0;
		for (i = 0;i < LIST_NUM(p->AvpList);i++)
		{
			RADIUS_AVP *avp = LIST_DATA(p->AvpList, i);

			if (avp->Type == RADIUS_ATTRIBUTE_EAP_MESSAGE)
			{
				num++;
			}
		}

		if (num >= 2)
		{
			// Reassemble multiple EAP messages
			BUF *b = NewBuf();

			for (i = 0;i < LIST_NUM(p->AvpList);i++)
			{
				RADIUS_AVP *avp = LIST_DATA(p->AvpList, i);

				if (avp->Type == RADIUS_ATTRIBUTE_EAP_MESSAGE)
				{
					WriteBuf(b, avp->Data, avp->DataSize);
				}
			}

			if (Endian16(((EAP_MESSAGE *)b->Buf)->Len) <= b->Size)
			{
				if (p->Parse_EapMessage != NULL)
				{
					Free(p->Parse_EapMessage);
				}

				p->Parse_EapMessage_DataSize = b->Size;
				p->Parse_EapMessage_DataSize = MIN(p->Parse_EapMessage_DataSize, 1500);
				p->Parse_EapMessage = Clone(b->Buf, p->Parse_EapMessage_DataSize);
			}

			FreeBuf(b);
		}
	}

	return p;

LABEL_ERROR:

	FreeRadiusPacket(p);
	FreeBuf(buf);

	return NULL;
}


////////// Classical implementation

// Attempts Radius authentication (with specifying retry interval and multiple server)
bool RadiusLogin(CONNECTION *c, char *server, UINT port, UCHAR *secret, UINT secret_size, wchar_t *username, char *password, UINT interval, UCHAR *mschap_v2_server_response_20,
				 RADIUS_LOGIN_OPTION *opt, char *hubname)
{
	UCHAR random[MD5_SIZE];
	UCHAR id;
	BUF *encrypted_password = NULL;
	BUF *user_name = NULL;
	//IP ip;
	bool ret = false;
	TOKEN_LIST *token;
	UINT i;
	LIST *ip_list;
	IPC_MSCHAP_V2_AUTHINFO mschap;
	bool is_mschap;
	char client_ip_str[MAX_SIZE];
	RADIUS_LOGIN_OPTION opt_dummy;
	static UINT packet_id = 0;
	// Validate arguments
	if (server == NULL || port == 0 || (secret_size != 0 && secret == NULL) || username == NULL || password == NULL)
	{
		return false;
	}

	if (opt == NULL)
	{
		Zero(&opt_dummy, sizeof(opt_dummy));

		opt = &opt_dummy;
	}

	opt->Out_VLanId = 0;

	Zero(client_ip_str, sizeof(client_ip_str));
	if (c != NULL && c->FirstSock != NULL)
	{
		IPToStr(client_ip_str, sizeof(client_ip_str), &c->FirstSock->RemoteIP);
	}

	// Parse the MS-CHAP v2 authentication data
	Zero(&mschap, sizeof(mschap));
	is_mschap = ParseAndExtractMsChapV2InfoFromPassword(&mschap, password);

	if (is_mschap && mschap.MsChapV2_EapClient != NULL)
	{
		// Try the EAP authentication for RADIUS first
		EAP_CLIENT *eap = mschap.MsChapV2_EapClient;

		if (IsEmptyStr(opt->In_VpnProtocolState) == false)
		{
			StrCpy(eap->In_VpnProtocolState, sizeof(eap->In_VpnProtocolState), opt->In_VpnProtocolState);
		}

		if (eap->PeapMode == false)
		{
			ret = EapClientSendMsChapv2AuthClientResponse(eap, mschap.MsChapV2_ClientResponse,
				mschap.MsChapV2_ClientChallenge);
		}
		else
		{
			ret = PeapClientSendMsChapv2AuthClientResponse(eap, mschap.MsChapV2_ClientResponse,
				mschap.MsChapV2_ClientChallenge);
		}

		if (ret)
		{
			Copy(mschap_v2_server_response_20, eap->ServerResponse, 20);

			if (opt->In_CheckVLanId)
			{
				opt->Out_VLanId = eap->LastRecvVLanId;
			}

			Copy(opt->Out_VirtualMacAddress, eap->LastRecvVirtualMacAddress, 6);

			return true;
		}
		else
		{
			return false;
		}
	}

	// Split the server into tokens
	token = ParseToken(server, " ,;\t");

	// Get the IP address of the server
	ip_list = NewListFast(NULL);
	for(i = 0; i < token->NumTokens; i++)
	{
		IP *tmp_ip = Malloc(sizeof(IP));
		if (GetIP(tmp_ip, token->Token[i]))
		{
			Add(ip_list, tmp_ip);
		}
		else if (GetIP(tmp_ip, token->Token[i]))
		{
			Add(ip_list, tmp_ip);
		}
		else
		{
			Free(tmp_ip);
		}
	}

	FreeToken(token);

	if(LIST_NUM(ip_list) == 0)
	{
		ReleaseList(ip_list);
		return false;
	}

	// Random number generation
	Rand(random, sizeof(random));

	// ID generation
	id = (UCHAR)(packet_id % 254 + 1);
	packet_id++;

	if (is_mschap == false)
	{
		// Encrypt the password
		encrypted_password = RadiusEncryptPassword(password, random, secret, secret_size);
		if (encrypted_password == NULL)
		{
			// Encryption failure

			// Release the ip_list
			for(i = 0; i < LIST_NUM(ip_list); i++)
			{
				IP *tmp_ip = LIST_DATA(ip_list, i);
				Free(tmp_ip);
			}
			ReleaseList(ip_list);
			return false;
		}
	}

	// Generate the user name packet
	user_name = RadiusCreateUserName(username);

	if (user_name != NULL)
	{
		// Generate a password packet
		BUF *user_password = (is_mschap ? NULL : RadiusCreateUserPassword(encrypted_password->Buf, encrypted_password->Size));
		BUF *nas_id;

		if (IsEmptyStr(opt->NasId))
		{
			nas_id = RadiusCreateNasId(CEDAR_SERVER_STR);
		}
		else
		{
			nas_id = RadiusCreateNasId(opt->NasId);
		}

		if (is_mschap || user_password != NULL)
		{
			UINT64 start;
			UINT64 next_send_time;
			UCHAR tmp[MAX_SIZE];
			UINT recv_buf_size = 32768;
			UCHAR *recv_buf = MallocEx(recv_buf_size, true);
			// Generate an UDP packet
			BUF *p = NewBuf();
			UCHAR type = 1;
			SOCK *sock;
			USHORT sz = 0;
			UINT pos = 0;
			bool *finish = ZeroMallocEx(sizeof(bool) * LIST_NUM(ip_list), true);

			Zero(tmp, sizeof(tmp));

			WriteBuf(p, &type, 1);
			WriteBuf(p, &id, 1);
			WriteBuf(p, &sz, 2);
			WriteBuf(p, random, 16);
			WriteBuf(p, user_name->Buf, user_name->Size);

			if (is_mschap == false)
			{
				UINT ui;
				// PAP
				WriteBuf(p, user_password->Buf, user_password->Size);
				WriteBuf(p, nas_id->Buf, nas_id->Size);

				// Service-Type
				ui = Endian32(2);
				RadiusAddValue(p, RADIUS_ATTRIBUTE_SERVICE_TYPE, 0, 0, &ui, sizeof(ui));

				// NAS-Port-Type
				ui = Endian32(5);
				RadiusAddValue(p, RADIUS_ATTRIBUTE_NAS_PORT_TYPE, 0, 0, &ui, sizeof(ui));

				// Tunnel-Type
				ui = Endian32(1);
				RadiusAddValue(p, RADIUS_ATTRIBUTE_TUNNEL_TYPE, 0, 0, &ui, sizeof(ui));

				// Tunnel-Medium-Type
				ui = Endian32(1);
				RadiusAddValue(p, RADIUS_ATTRIBUTE_TUNNEL_MEDIUM_TYPE, 0, 0, &ui, sizeof(ui));

				// Called-Station-ID - VPN Hub Name
				if (IsEmptyStr(hubname) == false)
				{
					RadiusAddValue(p, RADIUS_ATTRIBUTE_CALLED_STATION_ID, 0, 0, hubname, StrLen(hubname));
				}

				// Calling-Station-Id
				RadiusAddValue(p, RADIUS_ATTRIBUTE_CALLING_STATION_ID, 0, 0, client_ip_str, StrLen(client_ip_str));

				// Tunnel-Client-Endpoint
				RadiusAddValue(p, RADIUS_ATTRIBUTE_TUNNEL_CLIENT_ENDPOINT, 0, 0, client_ip_str, StrLen(client_ip_str));
			}
			else
			{
				// MS-CHAP v2
				static UINT session_id = 0;
				USHORT us;
				UINT ui;
				char *ms_ras_version = "MSRASV5.20";
				UCHAR ms_chapv2_response[50];

				// Acct-Session-Id
				us = Endian16(session_id % 254 + 1);
				session_id++;
				RadiusAddValue(p, RADIUS_ATTRIBUTE_ACCT_SESSION_ID, 0, 0, &us, sizeof(us));

				// NAS-IP-Address
				if (c != NULL && c->FirstSock != NULL && c->FirstSock->IPv6 == false)
				{
					ui = IPToUINT(&c->FirstSock->LocalIP);
					RadiusAddValue(p, RADIUS_ATTRIBUTE_NAS_IP, 0, 0, &ui, sizeof(ui));
				}

				// Service-Type
				ui = Endian32(2);
				RadiusAddValue(p, RADIUS_ATTRIBUTE_SERVICE_TYPE, 0, 0, &ui, sizeof(ui));

				// MS-RAS-Vendor
				ui = Endian32(RADIUS_VENDOR_MICROSOFT);
				RadiusAddValue(p, RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT, RADIUS_MS_RAS_VENDOR, &ui, sizeof(ui));

				// MS-RAS-Version
				RadiusAddValue(p, RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT, RADIUS_MS_VERSION, ms_ras_version, StrLen(ms_ras_version));

				// NAS-Port-Type
				ui = Endian32(5);
				RadiusAddValue(p, RADIUS_ATTRIBUTE_NAS_PORT_TYPE, 0, 0, &ui, sizeof(ui));

				// Tunnel-Type
				ui = Endian32(1);
				RadiusAddValue(p, RADIUS_ATTRIBUTE_TUNNEL_TYPE, 0, 0, &ui, sizeof(ui));

				// Tunnel-Medium-Type
				ui = Endian32(1);
				RadiusAddValue(p, RADIUS_ATTRIBUTE_TUNNEL_MEDIUM_TYPE, 0, 0, &ui, sizeof(ui));

				// Called-Station-ID - VPN Hub Name
				if (IsEmptyStr(hubname) == false)
				{
					RadiusAddValue(p, RADIUS_ATTRIBUTE_CALLED_STATION_ID, 0, 0, hubname, StrLen(hubname));
				}

				// Calling-Station-Id
				RadiusAddValue(p, RADIUS_ATTRIBUTE_CALLING_STATION_ID, 0, 0, client_ip_str, StrLen(client_ip_str));

				// Tunnel-Client-Endpoint
				RadiusAddValue(p, RADIUS_ATTRIBUTE_TUNNEL_CLIENT_ENDPOINT, 0, 0, client_ip_str, StrLen(client_ip_str));

				// MS-RAS-Client-Version
				RadiusAddValue(p, RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT, RADIUS_MS_RAS_CLIENT_VERSION, ms_ras_version, StrLen(ms_ras_version));

				// MS-RAS-Client-Name
				RadiusAddValue(p, RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT, RADIUS_MS_RAS_CLIENT_NAME, client_ip_str, StrLen(client_ip_str));

				// MS-CHAP-Challenge
				RadiusAddValue(p, RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT, RADIUS_MS_CHAP_CHALLENGE, mschap.MsChapV2_ServerChallenge, sizeof(mschap.MsChapV2_ServerChallenge));

				// MS-CHAP2-Response
				Zero(ms_chapv2_response, sizeof(ms_chapv2_response));
				Copy(ms_chapv2_response + 2, mschap.MsChapV2_ClientChallenge, 16);
				Copy(ms_chapv2_response + 2 + 16 + 8, mschap.MsChapV2_ClientResponse, 24);
				RadiusAddValue(p, RADIUS_ATTRIBUTE_VENDOR_SPECIFIC, RADIUS_VENDOR_MICROSOFT, RADIUS_MS_CHAP2_RESPONSE, ms_chapv2_response, sizeof(ms_chapv2_response));

				// NAS-ID
				WriteBuf(p, nas_id->Buf, nas_id->Size);
			}

			if (IsEmptyStr(opt->In_VpnProtocolState) == false)
			{
				// Proxy state as protocol details
				RadiusAddValue(p, RADIUS_ATTRIBUTE_PROXY_STATE, 0, 0, opt->In_VpnProtocolState, StrLen(opt->In_VpnProtocolState));
			}

			SeekBuf(p, 0, 0);

			WRITE_USHORT(((UCHAR *)p->Buf) + 2, (USHORT)p->Size);

			// Create a socket
			sock = NewUDPEx(0, IsIP6(LIST_DATA(ip_list, pos)));

			// Transmission process start
			start = Tick64();
			if(interval < RADIUS_RETRY_INTERVAL)
			{
				interval = RADIUS_RETRY_INTERVAL;
			}
			else if(interval > RADIUS_RETRY_TIMEOUT)
			{
				interval = RADIUS_RETRY_TIMEOUT;
			}
			next_send_time = start + (UINT64)interval;

			while (true)
			{
				UINT server_port;
				UINT recv_size;
				//IP server_ip;
				SOCKSET set;
				UINT64 now;

SEND_RETRY:
				//SendTo(sock, &ip, port, p->Buf, p->Size);
				SendTo(sock, LIST_DATA(ip_list, pos), port, p->Buf, p->Size);

				Debug("send to host:%u\n", pos);

				next_send_time = Tick64() + (UINT64)interval;

RECV_RETRY:
				now = Tick64();
				if (next_send_time <= now)
				{
					// Switch the host to refer
					pos++;
					pos = pos % LIST_NUM(ip_list);

					goto SEND_RETRY;
				}

				if ((start + RADIUS_RETRY_TIMEOUT) < now)
				{
					// Time-out
					break;
				}

				InitSockSet(&set);
				AddSockSet(&set, sock);
				Select(&set, (UINT)(next_send_time - now), NULL, NULL);

				recv_size = RecvFrom(sock, LIST_DATA(ip_list, pos), &server_port, recv_buf, recv_buf_size);

				if (recv_size == 0)
				{
					Debug("Radius recv_size 0\n");
					finish[pos] = true;
					for (i = 0; i < LIST_NUM(ip_list); ++i)
					{
						if (finish[i] == false)
						{
							// Switch the host to refer
							pos++;
							pos = pos % LIST_NUM(ip_list);
							goto SEND_RETRY;
						}
					}
					// Failure
					break;
				}
				else if (recv_size == SOCK_LATER)
				{
					// Waiting
					goto RECV_RETRY;
				}
				else
				{
					// Check such as the IP address
					if (/*Cmp(&server_ip, &ip, sizeof(IP)) != 0 || */server_port != port)
					{
						goto RECV_RETRY;
					}
					// Success
					if (recv_buf[0] == 2)
					{
						LIST *o;
						BUF *buf = NewBufFromMemory(recv_buf, recv_size);

						ret = true;

						if (is_mschap && mschap_v2_server_response_20 != NULL)
						{
							// Cutting corners Zurukko
							UCHAR signature[] = {0x1A, 0x33, 0x00, 0x00, 0x01, 0x37, 0x1A, 0x2D, 0x00, 0x53, 0x3D, };
							UINT i = SearchBin(recv_buf, 0, recv_buf_size, signature, sizeof(signature));

							if (i == INFINITE || ((i + sizeof(signature) + 40) > recv_buf_size))
							{
								ret = false;
							}
							else
							{
								char tmp[MAX_SIZE];
								BUF *b;

								Zero(tmp, sizeof(tmp));
								Copy(tmp, recv_buf + i + sizeof(signature), 40);

								b = StrToBin(tmp);

								if (b != NULL && b->Size == 20)
								{
									WHERE;
									Copy(mschap_v2_server_response_20, b->Buf, 20);
								}
								else
								{
									WHERE;
									ret = false;
								}

								FreeBuf(b);
							}
						}

						o = RadiusParseOptions(buf);
						if (o != NULL)
						{
							DHCP_OPTION *framed_interface_id_option = GetDhcpOption(o, RADIUS_ATTRIBUTE_FRAMED_INTERFACE_ID);

							if (framed_interface_id_option != NULL)
							{
								char tmp_str[64];
								UCHAR mac_address[6];

								Zero(tmp_str, sizeof(tmp_str));
								Copy(tmp_str, framed_interface_id_option->Data, MIN(framed_interface_id_option->Size, sizeof(tmp_str) - 1));

								if (StrToMac(mac_address, tmp_str))
								{
									Copy(opt->Out_VirtualMacAddress, mac_address, 6);
								}
							}

							if (opt->In_CheckVLanId)
							{
								DHCP_OPTION *vlan_option = GetDhcpOption(o, RADIUS_ATTRIBUTE_VLAN_ID);

								if (vlan_option != NULL)
								{
									UINT vlan_id = 0;
									char tmp[32];

									Zero(tmp, sizeof(tmp));

									Copy(tmp, vlan_option->Data, MIN(vlan_option->Size, sizeof(tmp) - 1));

									vlan_id = ToInt(tmp);

									opt->Out_VLanId = vlan_id;
								}
							}

							FreeDhcpOptions(o);
						}

						FreeBuf(buf);
					}
					break;
				}
			}

			Free(finish);

			// Release the socket
			ReleaseSock(sock);

			FreeBuf(p);
			FreeBuf(user_password);

			Free(recv_buf);
		}

		FreeBuf(nas_id);
		FreeBuf(user_name);
	}

	// Release the ip_list
	for(i = 0; i < LIST_NUM(ip_list); i++)
	{
		IP *tmp_ip = LIST_DATA(ip_list, i);
		Free(tmp_ip);
	}
	ReleaseList(ip_list);

	// Release the memory
	FreeBuf(encrypted_password);

	return ret;
}

// Parse RADIUS attributes
LIST *RadiusParseOptions(BUF *b)
{
	LIST *o;
	UCHAR code;
	UCHAR id;
	USHORT len;
	UCHAR auth[16];
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	o = NewList(NULL);

	ReadBuf(b, &code, 1);
	ReadBuf(b, &id, 1);
	len = 0;
	ReadBuf(b, &len, 2);
	len = Endian16(len);
	ReadBuf(b, auth, 16);

	while (true)
	{
		UCHAR attribute_id;
		UCHAR size;
		UCHAR data[256];
		DHCP_OPTION *d;

		if (ReadBuf(b, &attribute_id, 1) != 1)
		{
			break;
		}

		if (ReadBuf(b, &size, 1) != 1)
		{
			break;
		}

		if (size <= 2)
		{
			break;
		}

		size -= 2;
		if (ReadBuf(b, data, size) != size)
		{
			break;
		}

		d = ZeroMalloc(sizeof(DHCP_OPTION));
		d->Id = attribute_id;
		d->Size = size;
		d->Data = Clone(data, d->Size);

		Add(o, d);
	}

	return o;
}

// Adding Attributes
void RadiusAddValue(BUF *b, UCHAR t, UINT v, UCHAR vt, void *data, UINT size)
{
	UINT len;
	// Validate arguments
	if (b == NULL || (data == NULL && size != 0))
	{
		return;
	}

	// type
	WriteBufChar(b, t);

	// length
	len = 2 + size;
	if (t == 26)
	{
		len += 6;
	}
	WriteBufChar(b, (UCHAR)len);

	if (t != 26)
	{
		// value
		WriteBuf(b, data, size);
	}
	else
	{
		// vendor
		WriteBufInt(b, v);

		// vendor type
		WriteBufChar(b, vt);

		// length2
		len = size + 2;
		WriteBufChar(b, (UCHAR)len);

		// value
		WriteBuf(b, data, size);
	}
}

// Create a password attribute for Radius
BUF *RadiusCreateUserPassword(void *data, UINT size)
{
	BUF *b;
	UCHAR code, sz;
	// Validate arguments
	if (size != 0 && data == NULL || size >= 253)
	{
		return NULL;
	}

	b = NewBuf();
	code = 2;
	sz = 2 + (UCHAR)size;
	WriteBuf(b, &code, 1);
	WriteBuf(b, &sz, 1);
	WriteBuf(b, data, size);

	return b;
}

// Generate an ID attribute of Nas
BUF *RadiusCreateNasId(char *name)
{
	BUF *b;
	UCHAR code, size;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}
	if (StrLen(name) == 0 || StrLen(name) >= 128)
	{
		return NULL;
	}

	b = NewBuf();
	code = 32;
	size = 2 + (UCHAR)StrLen(name);
	WriteBuf(b, &code, 1);
	WriteBuf(b, &size, 1);
	WriteBuf(b, name, StrLen(name));

	return b;
}

// Create a user name attribute for Radius
BUF *RadiusCreateUserName(wchar_t *username)
{
	BUF *b;
	UCHAR code, size;
	UCHAR utf8[254];
	// Validate arguments
	if (username == NULL)
	{
		return NULL;
	}

	// Convert the user name to a Unicode string
	UniToStr(utf8, sizeof(utf8), username);
	utf8[253] = 0;

	b = NewBuf();
	code = 1;
	size = 2 + (UCHAR)StrLen(utf8);
	WriteBuf(b, &code, 1);
	WriteBuf(b, &size, 1);
	WriteBuf(b, utf8, StrLen(utf8));

	return b;
}

// Encrypt the password for the Radius
BUF *RadiusEncryptPassword(char *password, UCHAR *random, UCHAR *secret, UINT secret_size)
{
	UINT n, i;
	BUF *buf;
	UCHAR c[16][16];		// Result
	UCHAR b[16][16];		// Result
	UCHAR p[16][16];		// Password
	// Validate arguments
	if (password == NULL || random == NULL || (secret_size != 0 && secret == NULL))
	{
		return NULL;
	}
	if (StrLen(password) > 256)
	{
		// Password is too long
		return NULL;
	}

	// Initialize
	Zero(c, sizeof(c));
	Zero(p, sizeof(p));
	Zero(b, sizeof(b));

	// Divide the password per 16 characters
	Copy(p, password, StrLen(password));
	// Calculate the number of blocks
	n = StrLen(password) / 16;
	if ((StrLen(password) % 16) != 0)
	{
		n++;
	}

	// Encryption processing
	for (i = 0;i < n;i++)
	{
		// Calculation of b[i]
		UINT j;
		BUF *tmp = NewBuf();
		WriteBuf(tmp, secret, secret_size);
		if (i == 0)
		{
			WriteBuf(tmp, random, 16);
		}
		else
		{
			WriteBuf(tmp, c[i - 1], 16);
		}
		Md5(b[i], tmp->Buf, tmp->Size);
		FreeBuf(tmp);

		// Calculation of c[i]
		for (j = 0;j < 16;j++)
		{
			c[i][j] = p[i][j] ^ b[i][j];
		}
	}

	// Return the results
	buf = NewBuf();
	WriteBuf(buf, c, n * 16);
	return buf;
}

