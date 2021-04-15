#include "Proto_WireGuard.h"

#include "Connection.h"
#include "IPC.h"
#include "Logging.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

#include <blake2.h>

const PROTO_IMPL *WgsGetProtoImpl()
{
	static const PROTO_IMPL impl =
	{
		WgsName,
		WgsOptions,
		WgsOptionStringValue,
		WgsInit,
		WgsFree,
		WgsIsPacketForMe,
		NULL,
		WgsProcessDatagrams
	};

	return &impl;
}

const char *WgsName()
{
	return "WireGuard";
}

const PROTO_OPTION *WgsOptions()
{
	static const PROTO_OPTION options[] =
	{
		{ .Name = "PresharedKey", .Type = PROTO_OPTION_STRING, .String = NULL},
		{ .Name = "PrivateKey", .Type = PROTO_OPTION_STRING, .String = NULL },
		{ .Name = NULL, .Type = PROTO_OPTION_UNKNOWN }
	};

	return options;
}

char *WgsOptionStringValue(const char *name)
{
	if (name == NULL)
	{
		return NULL;
	}

	if (StrCmp(name, "PresharedKey") == 0 || StrCmp(name, "PrivateKey") == 0)
	{
		unsigned char buf[WG_KEY_SIZE];
		const UINT size = sodium_base64_ENCODED_LEN(sizeof(buf), sodium_base64_VARIANT_ORIGINAL);
		char *str = Malloc(size);
		Rand(buf, sizeof(buf));
		sodium_bin2base64(str, size, buf, sizeof(buf), sodium_base64_VARIANT_ORIGINAL);
		Zero(buf, sizeof(buf));
		return str;
	}

	return NULL;
}

bool WgsInit(void **param, const LIST *options, CEDAR *cedar, INTERRUPT_MANAGER *im, SOCK_EVENT *se, const char *cipher, const char *hostname)
{
	UINT i;
	WG_SERVER *server;

	if (param == NULL || options == NULL || cedar == NULL || im == NULL || se == NULL)
	{
		return false;
	}

	Debug("WgsInit(): cipher: %s, hostname: %s\n", cipher, hostname);

	server = ZeroMalloc(sizeof(WG_SERVER));

	for (i = 0; i < LIST_NUM(options); ++i)
	{
		const PROTO_OPTION *option = LIST_DATA(options, i);
		if (StrCmp(option->Name, "PresharedKey") == 0)
		{
			if (IsEmptyStr(option->String) == false)
			{
				sodium_base642bin(server->PresharedKey, sizeof(server->PresharedKey), option->String, StrLen(option->String), NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL);
			}
		}
		else if (StrCmp(option->Name, "PrivateKey") == 0)
		{
			sodium_base642bin(server->StaticPrivate, sizeof(server->StaticPrivate), option->String, StrLen(option->String), NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL);
			crypto_scalarmult_curve25519_base(server->StaticPublic, server->StaticPrivate);
		}
	}

	server->Cedar = cedar;
	server->SockEvent = se;
	server->InterruptManager = im;

	blake2s(server->HandshakeInitChainingKey, sizeof(server->HandshakeInitChainingKey), WG_CONSTRUCTION, StrLen(WG_CONSTRUCTION), NULL, 0);

	blake2s_state b2s_state;
	blake2s_init(&b2s_state, sizeof(server->HandshakeInitHash));
	blake2s_update(&b2s_state, server->HandshakeInitChainingKey, sizeof(server->HandshakeInitChainingKey));
	blake2s_update(&b2s_state, WG_IDENTIFIER, StrLen(WG_IDENTIFIER));
	blake2s_final(&b2s_state, server->HandshakeInitHash, sizeof(server->HandshakeInitHash));

	server->CreationTime = Tick64();
	AddInterrupt(im, server->CreationTime + WG_INITIATION_GIVEUP);

	*param = server;

	return true;
}

void WgsFree(void *param)
{
	WG_SERVER *server = param;
	WG_SESSION *session;
	WG_KEYPAIRS *keypairs;

	if (server == NULL)
	{
		return;
	}

	session = &server->Session;
	keypairs = &session->Keypairs;

	FreeIPC(session->IPC);

	Zero(keypairs->Current, sizeof(WG_KEYPAIR));
	Free(keypairs->Current);

	Zero(keypairs->Next, sizeof(WG_KEYPAIR));
	Free(keypairs->Next);

	Zero(keypairs->Previous, sizeof(WG_KEYPAIR));
	Free(keypairs->Previous);

	Zero(server, sizeof(WG_SERVER));
	Free(server);
}

bool WgsIsPacketForMe(const PROTO_MODE mode, const void *data, const UINT size)
{
	if (mode != PROTO_MODE_UDP)
	{
		return false;
	}

	return WgsDetectMessageType(data, size);
}

bool WgsProcessDatagrams(void *param, LIST *in, LIST *out)
{
	UINT i;
	WG_SERVER *server = param;
	WG_SESSION *session;
	WG_KEYPAIRS *keypairs;

	if (server == NULL || in == NULL || out == NULL)
	{
		return false;
	}

	server->Now = Tick64();

	session = &server->Session;
	keypairs = &session->Keypairs;

	if (keypairs->Current != NULL)
	{
		const WG_KEYPAIR *current = keypairs->Current;
		if (server->Now - current->CreationTime >= WG_REJECT_AFTER_TIME)
		{
			WgsLog(server, "LW_KEYPAIR_EXPIRED", current->IndexRemote, current->IndexLocal);
			return false;
		}
	}
	else if (server->Now - server->CreationTime >= WG_INITIATION_GIVEUP)
	{
		Debug("WgsProcessDatagrams(): current keypair not present, giving up!\n");
		return false;
	}

	if (keypairs->Previous != NULL)
	{
		WG_KEYPAIR *previous = keypairs->Previous;
		if (server->Now - previous->CreationTime >= WG_REJECT_AFTER_TIME)
		{
			Debug("WgsProcessDatagrams(): deleting keypair: %x -> %x\n", previous->IndexRemote, previous->IndexLocal);
			Zero(previous, sizeof(WG_KEYPAIR));
			Free(previous);
			keypairs->Previous = NULL;
		}
	}

	for (i = 0; i < LIST_NUM(in); ++i)
	{
		const UDPPACKET *packet = LIST_DATA(in, i);
		const UINT size = packet->Size;
		void *data = packet->Data;

		const WG_MSG_TYPE message_type = WgsDetectMessageType(data, size);
		switch (message_type)
		{
		case WG_MSG_HANDSHAKE_INIT:
		{
			WG_KEYPAIR *keypair;
			UDPPACKET *udp_reply;
			WG_HANDSHAKE_REPLY *reply;
			BYTE ephemeral_remote[WG_KEY_SIZE];

			if (session->LastInitiationReceived + 1000 / WG_MAX_INITIATIONS_PER_SECOND > server->Now)
			{
				WgsLog(server, "LW_FLOOD_ATTACK");
				return false;
			}

			session->LastInitiationReceived = server->Now;

			keypair = WgsProcessHandshakeInit(server, data, ephemeral_remote);
			if (keypair == NULL)
			{
				Debug("WgsProcessDatagrams(): WgsProcessHandshakeInit() failed!\n");
				Zero(ephemeral_remote, sizeof(ephemeral_remote));
				return false;
			}

			reply = WgsCreateHandshakeReply(server, keypair, ephemeral_remote);

			Zero(ephemeral_remote, sizeof(ephemeral_remote));

			if (reply == NULL)
			{
				Debug("WgsProcessDatagrams(): WgsCreateHandshakeReply() failed!\n");
				Zero(keypair, sizeof(WG_KEYPAIR));
				Free(keypair);
				return false;
			}

			Copy(&session->IPLocal, &packet->DstIP, sizeof(session->IPLocal));
			Copy(&session->IPRemote, &packet->SrcIP, sizeof(session->IPRemote));
			session->PortLocal = packet->DestPort;
			session->PortRemote = packet->SrcPort;

			udp_reply = NewUdpPacket(&session->IPLocal, session->PortLocal, &session->IPRemote, session->PortRemote, reply, sizeof(WG_HANDSHAKE_REPLY));
			Add(out, udp_reply);

			AddInterrupt(server->InterruptManager, keypair->CreationTime + WG_REJECT_AFTER_TIME);
			break;
		}
		case WG_MSG_HANDSHAKE_COOKIE:
			// TODO: reply to message.
			continue;
		case WG_MSG_TRANSPORT_DATA:
			if (keypairs->Current == NULL)
			{
				continue;
			}

			if (WgsProcessTransportData(server, data, size) == false)
			{
				Debug("WgsProcessDatagrams(): WgsProcessTransportData() failed!\n");
				return false;
			}

			session->LastDataReceived = server->Now;
			break;
		default:
			Debug("WgsProcessDatagrams(): unrecognized packet type %u\n", message_type);
			return false;
		}
	}

	if (session->IPC == NULL)
	{
		return true;
	}

	if (IsIPCConnected(session->IPC) == false)
	{
		WgsLog(server, "LW_HUB_DISCONNECT");
		return false;
	}

	IPCProcessL3Events(session->IPC);

	while (true)
	{
		UDPPACKET *udp;
		UINT final_size = 0;
		WG_TRANSPORT_DATA *data;
		BLOCK *block = IPCRecvIPv4(session->IPC);
		if (block == NULL)
		{
			break;
		}

		data = WgsCreateTransportData(server, block->Buf, block->Size, &final_size);

		FreeBlock(block);

		if (data == NULL)
		{
			continue;
		}

		udp = NewUdpPacket(&session->IPLocal, session->PortLocal, &session->IPRemote, session->PortRemote, data, final_size);
		Add(out, udp);
	}

	if (LIST_NUM(out) > 0)
	{
		session->LastDataSent = server->Now;
	}
	else if (session->LastDataReceived >= session->LastDataSent)
	{
		if (server->Now - session->LastDataSent >= WG_KEEPALIVE_TIMEOUT)
		{
			UINT final_size = 0;
			WG_TRANSPORT_DATA *data = WgsCreateTransportData(server, NULL, 0, &final_size);
			UDPPACKET *udp = NewUdpPacket(&session->IPLocal, session->PortLocal, &session->IPRemote, session->PortRemote, data, final_size);
			Add(out, udp);

			Debug("WgsProcessDatagrams(): sending keepalive packet\n");

			session->LastDataSent = server->Now;

			// Schedule next keepalive.
			AddInterrupt(server->InterruptManager, server->Now + WG_KEEPALIVE_TIMEOUT);
		}
	}

	return true;
}

void WgsLog(const WG_SERVER *server, const char *name, ...)
{
	wchar_t message[MAX_SIZE * 2];
	const WG_SESSION *session;
	UINT current_len;
	va_list args;

	if (server == NULL)
	{
		return;
	}

	session = &server->Session;

	UniFormat(message, sizeof(message), _UU("LW_PREFIX_SESSION"), &session->IPRemote, session->PortRemote, &session->IPLocal, session->PortLocal);

	current_len = UniStrLen(message);

	va_start(args, name);
	UniFormatArgs(message + current_len, sizeof(message) - current_len, _UU(name), args);
	va_end(args);

	WriteServerLog(server->Cedar, message);
}

WG_MSG_TYPE WgsDetectMessageType(const void *data, const UINT size)
{
	const WG_COMMON *packet = data;

	if (packet == NULL || size < sizeof(WG_COMMON))
	{
		return WG_MSG_INVALID;
	}

	switch (packet->Header.Type)
	{
		case WG_MSG_HANDSHAKE_INIT:
			if (size != sizeof(WG_HANDSHAKE_INIT))
			{
				return WG_MSG_INVALID;
			}

			break;
		case WG_MSG_HANDSHAKE_REPLY:
			if (size != sizeof(WG_HANDSHAKE_REPLY))
			{
				return WG_MSG_INVALID;
			}

			break;
		case WG_MSG_HANDSHAKE_COOKIE:
			if (size != sizeof(WG_COOKIE_REPLY))
			{
				return WG_MSG_INVALID;
			}

			break;
		case WG_MSG_TRANSPORT_DATA:
			if (size < sizeof(WG_TRANSPORT_DATA) + WG_AEAD_SIZE(0))
			{
				return WG_MSG_INVALID;
			}

			break;
		default:
			return WG_MSG_INVALID;
	}

	if (IsZero(packet->Header.Reserved, sizeof(packet->Header.Reserved)) == false)
	{
		return WG_MSG_INVALID;
	}

	if (packet->Index == 0)
	{
		return WG_MSG_INVALID;
	}

	return packet->Header.Type;
}

UINT WgsMSS(const WG_SESSION *session)
{
	UINT ret = MTU_FOR_PPPOE;

	if (session == NULL)
	{
		return 0;
	}

	// IPv4 / IPv6
	if (IsIP4(&session->IPRemote))
	{
		ret -= 20;
	}
	else
	{
		ret -= 40;
	}

	// UDP
	ret -= 8;

	// WireGuard packet
	ret -= sizeof(WG_TRANSPORT_DATA);

	// Inner IPv4
	ret -= 20;

	// Inner TCP
	ret -= 20;

	return ret;
}

IPC *WgsIPCNew(WG_SERVER *server)
{
	UINT err;
	IPC *ipc;
	IPC_PARAM param;
	WG_SESSION *session;

	if (server == NULL)
	{
		return NULL;
	}

	session = &server->Session;

	Zero(&param, sizeof(param));

	StrCpy(param.ClientName, sizeof(param.ClientName), WgsName());
	StrCpy(param.Postfix, sizeof(param.Postfix), WG_IPC_POSTFIX);

	sodium_bin2base64(param.WgKey, sizeof(param.WgKey), session->StaticRemote, sizeof(session->StaticRemote), sodium_base64_VARIANT_ORIGINAL);

	Copy(&param.ServerIp, &session->IPLocal, sizeof(param.ServerIp));
	Copy(&param.ClientIp, &session->IPRemote, sizeof(param.ClientIp));
	param.ServerPort = session->PortLocal;
	param.ClientPort = session->PortRemote;

	StrCpy(param.CryptName, sizeof(param.CryptName), WG_CIPHER);

	param.Layer = IPC_LAYER_3;
	param.Mss = WgsMSS(session);

	ipc = NewIPCByParam(server->Cedar, &param, &err);
	if (ipc == NULL)
	{
		Debug("WgsIPCNew(): NewIPCByParam() failed with error %u!\n", err);
	}

	return ipc;
}

WG_KEYPAIR *WgsProcessHandshakeInit(WG_SERVER *server, const WG_HANDSHAKE_INIT *init, BYTE *ephemeral_remote)
{
	WG_SESSION *session;
	WG_KEYPAIR *keypair = NULL;
	BYTE hash[WG_HASH_SIZE];
	BYTE key[WG_KEY_SIZE];
	BYTE chaining_key[WG_HASH_SIZE];
	BYTE timestamp[WG_TIMESTAMP_SIZE];
	BYTE static_remote[WG_KEY_SIZE];

	if (server == NULL || init == NULL || ephemeral_remote == NULL)
	{
		return NULL;
	}

	session = &server->Session;

	Copy(hash, server->HandshakeInitHash, sizeof(server->HandshakeInitHash));
	Copy(chaining_key, server->HandshakeInitChainingKey, sizeof(server->HandshakeInitChainingKey));
	WgsMixHash(hash, server->StaticPublic, sizeof(server->StaticPublic));

	WgsEphemeral(ephemeral_remote, init->UnencryptedEphemeral, chaining_key, hash);

	if (WgsMixDh(chaining_key, key, server->StaticPrivate, ephemeral_remote) == 0)
	{
		Debug("WgsProcessHandshakeInit(): WgsMixDh() failed!\n");
		goto FINAL;
	}

	if (WgsDecryptWithHash(static_remote, init->EncryptedStatic, sizeof(init->EncryptedStatic), hash, key) == false)
	{
		Debug("WgsProcessHandshakeInit(): WgsDecryptWithHash() failed to decrypt the static key!\n");
		goto FINAL;
	}

	if (IsZero(session->StaticRemote, sizeof(session->StaticRemote)) == false)
	{
		if (Cmp(static_remote, session->StaticRemote, sizeof(static_remote)) != 0)
		{
			Debug("WgsProcessHandshakeInit(): static remote key doesn't match!\n");
			goto FINAL;
		}
	}

	if (IsZero(session->PrecomputedStaticStatic, sizeof(session->PrecomputedStaticStatic)))
	{
		Debug("WgsProcessHandshakeInit(): precomputing static static...\n");
		if (crypto_scalarmult_curve25519(session->PrecomputedStaticStatic, server->StaticPrivate, static_remote) != 0)
		{
			Debug("WgsProcessHandshakeInit(): crypto_scalarmult_curve25519() failed!\n");
			goto FINAL;
		}
	}

	WgsHKDF(chaining_key, key, NULL, session->PrecomputedStaticStatic, sizeof(session->PrecomputedStaticStatic), chaining_key);

	if (WgsDecryptWithHash(&timestamp, init->EncryptedTimestamp, sizeof(init->EncryptedTimestamp), hash, key) == false)
	{
		Debug("WgsProcessHandshakeInit(): WgsDecrypt() failed to decrypt the timestamp!\n");
		goto FINAL;
	}

	if (Cmp(&timestamp, session->LastTimestamp, sizeof(timestamp) <= 0))
	{
		WgsLog(server, "LW_REPLAY_ATTACK");
		goto FINAL;
	}

	Copy(session->LastTimestamp, &timestamp, sizeof(session->LastTimestamp));

	Copy(session->Hash, hash, sizeof(session->Hash));
	Copy(session->ChainingKey, chaining_key, sizeof(session->ChainingKey));
	Copy(session->StaticRemote, static_remote, sizeof(session->StaticRemote));

	keypair = ZeroMalloc(sizeof(WG_KEYPAIR));
	keypair->State = WG_KEYPAIR_INITIATED;
	keypair->CreationTime = server->Now;
	keypair->IndexLocal = Rand32();
	keypair->IndexRemote = init->SenderIndex;
FINAL:
	Zero(key, sizeof(key));
	Zero(hash, sizeof(hash));
	Zero(chaining_key, sizeof(chaining_key));
	Zero(static_remote, sizeof(static_remote));

	return keypair;
}

WG_HANDSHAKE_REPLY *WgsCreateHandshakeReply(WG_SERVER *server, WG_KEYPAIR *keypair, const BYTE *ephemeral_remote)
{
	bool ok = false;
	WG_SESSION *session;
	WG_HANDSHAKE_REPLY *ret;
	BYTE hash[WG_HASH_SIZE];
	BYTE key[WG_KEY_SIZE];
	BYTE ephemeral[WG_KEY_SIZE];

	if (server == NULL || keypair == NULL || ephemeral_remote == NULL)
	{
		return NULL;
	}

	if (keypair->State != WG_KEYPAIR_INITIATED)
	{
		Debug("WgsCreateHandshakeReply(): unexpected keypair state %u!\n", keypair->State);
		return NULL;
	}

	session = &server->Session;

	ret = ZeroMalloc(sizeof(WG_HANDSHAKE_REPLY));
	ret->Header.Type = WG_MSG_HANDSHAKE_REPLY;
	ret->SenderIndex = keypair->IndexLocal;
	ret->ReceiverIndex = keypair->IndexRemote;

	crypto_box_curve25519xsalsa20poly1305_keypair(ret->UnencryptedEphemeral, ephemeral);

	WgsEphemeral(ret->UnencryptedEphemeral, ret->UnencryptedEphemeral, session->ChainingKey, session->Hash);

	if (WgsMixDh(session->ChainingKey, NULL, ephemeral, ephemeral_remote) == 0)
	{
		Debug("WgsCreateHandshakeReply(): WgsMixDh() failed to mix ephemeral public!\n");
		goto FINAL;
	}

	if (WgsMixDh(session->ChainingKey, NULL, ephemeral, session->StaticRemote) == 0)
	{
		Debug("WgsCreateHandshakeReply(): WgsMixDh() failed to mix static public!\n");
		goto FINAL;
	}

	WgsHKDF(session->ChainingKey, hash, key, server->PresharedKey, sizeof(server->PresharedKey), session->ChainingKey);
	WgsMixHash(session->Hash, hash, sizeof(hash));

	if (WgsEncryptWithHash(ret->EncryptedNothing, NULL, 0, session->Hash, key) == false)
	{
		Debug("WgsCreateHandshakeReply(): WgsEncryptWithHash() failed!\n");
		goto FINAL;
	}

	WgsMixHash(session->Hash, ret->EncryptedNothing, sizeof(ret->EncryptedNothing));

	blake2s_state blake;
	blake2s_init(&blake, sizeof(key));
	blake2s_update(&blake, WG_LABEL_MAC1, StrLen(WG_LABEL_MAC1));
	blake2s_update(&blake, session->StaticRemote, sizeof(session->StaticRemote));
	blake2s_final(&blake, key, sizeof(key));

	blake2s(ret->Macs.Mac1, sizeof(ret->Macs.Mac1), ret, sizeof(WG_HANDSHAKE_REPLY) - sizeof(WG_MACS), key, sizeof(key));

	ok = true;
FINAL:
	Zero(key, sizeof(key));
	Zero(hash, sizeof(hash));
	Zero(ephemeral, sizeof(ephemeral));

	if (ok)
	{
		WG_KEYPAIRS *keypairs = &session->Keypairs;

		WgsHKDF(keypair->KeyRemote, keypair->KeyLocal, NULL, NULL, 0, session->ChainingKey);
		keypair->State = WG_KEYPAIR_CONFIRMED;

		Debug("WgsCreateHandshakeReply(): new keypair available: %x -> %x\n", keypair->IndexRemote, keypair->IndexLocal);

		if (keypairs->Next != NULL)
		{
			WG_KEYPAIR *next = keypairs->Next;
			Debug("WgsCreateHandshakeReply(): deleting keypair: %x -> %x\n", next->IndexRemote, next->IndexLocal);
			Zero(next, sizeof(WG_KEYPAIR));
			Free(next);
		}

		if (keypairs->Current == NULL)
		{
			Debug("WgsCreateHandshakeReply(): switched to keypair: %x -> %x\n", keypair->IndexRemote, keypair->IndexLocal);
			keypairs->Current = keypair;
			keypairs->Next = NULL;
			return ret;
		}

		keypairs->Next = keypair;
		return ret;
	}

	Zero(ret, sizeof(WG_HANDSHAKE_REPLY));
	Free(ret);

	return NULL;
}

bool WgsProcessTransportData(WG_SERVER *server, WG_TRANSPORT_DATA *data, const UINT size)
{
	UINT written;
	UINT encrypted_size;
	WG_KEYPAIR *keypair;
	WG_KEYPAIRS *keypairs;

	if (server == NULL || data == NULL || size < sizeof(WG_TRANSPORT_DATA))
	{
		return false;
	}

	encrypted_size = size - sizeof(WG_TRANSPORT_DATA);
	if (encrypted_size < WG_TAG_SIZE)
	{
		return false;
	}

	keypairs = &server->Session.Keypairs;
	keypair = keypairs->Current;

	if (data->ReceiverIndex != keypair->IndexLocal)
	{
		WG_KEYPAIR *previous = keypairs->Previous;

		if (keypairs->Next != NULL && data->ReceiverIndex == keypairs->Next->IndexLocal)
		{
			if (previous != NULL)
			{
				Debug("WgsProcessTransportData(): deleting keypair: %x -> %x\n", previous->IndexRemote, previous->IndexLocal);
				Zero(previous, sizeof(WG_KEYPAIR));
				Free(previous);
			}

			keypairs->Previous = keypair;
			keypairs->Current = keypair = keypairs->Next;
			keypairs->Next = NULL;
			Debug("WgsProcessTransportData(): switched to keypair: %x -> %x\n", keypair->IndexRemote, keypair->IndexLocal);
		}
		else if (previous != NULL && data->ReceiverIndex == previous->IndexLocal)
		{
			keypair = previous;
		}
		else
		{
			WgsLog(server, "LW_KEYPAIR_UNKNOWN");
			return false;
		}
	}

	if (WgsIsInReplayWindow(keypair, data->Counter))
	{
		WgsLog(server, "LW_REPLAY_ATTACK");
		return false;
	}

	written = WgsDecryptData(keypair->KeyRemote, data->Counter, data->EncapsulatedPacket, data->EncapsulatedPacket, encrypted_size);
	if (written == INFINITE)
	{
		WgsLog(server, "LW_DECRYPT_FAIL");
		return false;
	}

	if (data->Counter > WG_REJECT_AFTER_MESSAGES)
	{
		WgsLog(server, "LW_KEYPAIR_EXPIRED", keypair->IndexRemote, keypair->IndexLocal);
		return false;
	}

	WgsUpdateReplayWindow(keypair, data->Counter);

	if (written > 0)
	{
		WG_SESSION *session = &server->Session;
		if (session->IPC == NULL)
		{
			IP ip;
			PKT pkt;
			IPC *ipc;

			ipc = WgsIPCNew(server);
			if (ipc == NULL)
			{
				Debug("WgsProcessTransportData(): WgsCreateIPC() returned NULL!\n");
				return false;
			}

			if (ParsePacketIPv4(&pkt, data->EncapsulatedPacket, written) == false)
			{
				Debug("WgsProcessTransportData(): ParsePacketIPv4() failed!\n");
				return false;
			}

			UINTToIP(&ip, pkt.L3.IPv4Header->SrcIP);
			IPCSetIPv4Parameters(ipc, &ip, &ipc->SubnetMask, &ipc->DefaultGateway, NULL);

			IPCSetSockEventWhenRecvL2Packet(ipc, server->SockEvent);

			IPC_PROTO_SET_STATUS(ipc, IPv4State, IPC_PROTO_STATUS_OPENED);

			session->IPC = ipc;
		}

		IPCSendIPv4(session->IPC, data->EncapsulatedPacket, written);
	}

	return true;
}

WG_TRANSPORT_DATA *WgsCreateTransportData(WG_SERVER *server, const void *data, const UINT size, UINT *final_size)
{
	UINT pad_size;
	UINT encrypted_size;
	WG_KEYPAIR *keypair;
	WG_TRANSPORT_DATA *ret;

	if (server == NULL || (data == NULL && size > 0) || final_size == NULL)
	{
		return NULL;
	}

	keypair = server->Session.Keypairs.Current;
	if (keypair == NULL)
	{
		Debug("WgsCreateTransportData(): no keypair!\n");
		return NULL;
	}

	if (keypair->CounterLocal > WG_REJECT_AFTER_MESSAGES)
	{
		WgsLog(server, "LW_KEYPAIR_EXPIRED", keypair->IndexRemote, keypair->IndexLocal);
		return false;
	}

	pad_size = (WG_BLOCK_SIZE - (size % WG_BLOCK_SIZE)) % WG_BLOCK_SIZE;
	encrypted_size = WG_AEAD_SIZE(size + pad_size);

	*final_size = sizeof(WG_TRANSPORT_DATA) + encrypted_size;

	ret = ZeroMalloc(*final_size);
	ret->Header.Type = WG_MSG_TRANSPORT_DATA;
	ret->ReceiverIndex = keypair->IndexRemote;
	ret->Counter = keypair->CounterLocal;

	Copy(ret->EncapsulatedPacket, data, size);

	if (WgsEncryptData(keypair->KeyLocal, ret->Counter, ret->EncapsulatedPacket, ret->EncapsulatedPacket, size + pad_size) != encrypted_size)
	{
		Debug("WgsCreateTransportData(): WgsEncryptData() didn't write the expected number of bytes!\n");
		Free(ret);
		return NULL;
	}

	++keypair->CounterLocal;

	return ret;
}

// RFC 6479: ipsec_check_replay_window()
bool WgsIsInReplayWindow(const WG_KEYPAIR *keypair, const UINT64 counter)
{
	int bit_location;
	int index;

	if (keypair == NULL || counter == 0)
	{
		return false;
	}

	if (counter > keypair->CounterRemote)
	{
		return false;
	}

	if (counter + sizeof(keypair->ReplayWindow) < keypair->CounterRemote)
	{
		return false;
	}

	bit_location = counter & WG_REPLAY_BITMAP_LOC_MASK;
	index = counter >> WG_REPLAY_REDUNDANT_BIT_SHIFTS & WG_REPLAY_BITMAP_INDEX_MASK;

	if (keypair->ReplayWindow[index] & (1 << bit_location))
	{
		return true;
	}

	return false;
}

// RFC 6479: ipsec_update_replay_window()
void WgsUpdateReplayWindow(WG_KEYPAIR *keypair, const UINT64 counter)
{
	int bit_location;
	int index;

	if (keypair == NULL || counter == 0)
	{
		return;
	}

	if (counter + sizeof(keypair->ReplayWindow) < keypair->CounterRemote)
	{
		return;
	}

	index = counter >> WG_REPLAY_REDUNDANT_BIT_SHIFTS;

	if (counter > keypair->CounterRemote)
	{
		const int index_cur = keypair->CounterRemote >> WG_REPLAY_REDUNDANT_BIT_SHIFTS;
		int diff = index - index_cur;
		int id;

		if (diff > WG_REPLAY_BITMAP_SIZE)
		{
			diff = WG_REPLAY_BITMAP_SIZE;
		}

		for (id = 0; id < diff; ++id)
		{
			keypair->ReplayWindow[(id + index_cur + 1) & WG_REPLAY_BITMAP_INDEX_MASK] = 0;
		}

		keypair->CounterRemote = counter;
	}

	index &= WG_REPLAY_BITMAP_INDEX_MASK;
	bit_location = counter & WG_REPLAY_BITMAP_LOC_MASK;

	if (keypair->ReplayWindow[index] & 1 << bit_location)
	{
		return;
	}

	keypair->ReplayWindow[index] |= 1 << bit_location;
}

UINT WgsEncryptData(void *key, const UINT64 counter, void *dst, const void *src, const UINT src_size)
{
	unsigned long long written;
	BYTE iv[WG_IV_SIZE];

	if (key == NULL || dst == NULL || (src == NULL && src_size > 0))
	{
		return INFINITE;
	}

	Zero(iv, sizeof(iv) - sizeof(counter));
	Copy(iv + sizeof(iv) - sizeof(counter), &counter, sizeof(counter));

	crypto_aead_chacha20poly1305_ietf_encrypt(dst, &written, src, src_size, NULL, 0, NULL, iv, key);

	return written;
}

UINT WgsDecryptData(void *key, const UINT64 counter, void *dst, const void *src, const UINT src_size)
{
	unsigned long long written;
	BYTE iv[WG_IV_SIZE];

	if (key == NULL || src == NULL || src_size == 0)
	{
		return INFINITE;
	}

	Zero(iv, sizeof(iv) - sizeof(counter));
	Copy(iv + sizeof(iv) - sizeof(counter), &counter, sizeof(counter));

	if (crypto_aead_chacha20poly1305_ietf_decrypt(dst, &written, NULL, src, src_size, NULL, 0, iv, key) != 0)
	{
		return INFINITE;
	}

	return written;
}

bool WgsEncryptWithHash(void *dst, const void *src, const UINT src_size, BYTE *hash, const BYTE *key)
{
	unsigned long long written;
	BYTE iv[WG_IV_SIZE];

	if (dst == NULL || (src == NULL && src_size > 0) || hash == NULL || key == NULL)
	{
		return false;
	}

	Zero(iv, sizeof(iv));

	crypto_aead_chacha20poly1305_ietf_encrypt(dst, &written, src, src_size, hash, WG_HASH_SIZE, NULL, iv, key);

	WgsMixHash(hash, dst, WG_AEAD_SIZE(src_size));

	return (written > 0);
}

bool WgsDecryptWithHash(void *dst, const void *src, const UINT src_size, BYTE *hash, const BYTE *key)
{
	unsigned long long written;
	BYTE iv[WG_IV_SIZE];

	if ((src == NULL && src_size > 0) || hash == NULL || key == NULL)
	{
		return false;
	}

	Zero(iv, sizeof(iv));

	if (crypto_aead_chacha20poly1305_ietf_decrypt(dst, &written, NULL, src, src_size, hash, WG_HASH_SIZE, iv, key) != 0)
	{
		return false;
	}

	WgsMixHash(hash, src, src_size);

	return (written > 0);
}

void WgsEphemeral(BYTE *ephemeral_dst, const BYTE *ephemeral_src, BYTE *chaining_key, BYTE *hash)
{
	Copy(ephemeral_dst, ephemeral_src, WG_KEY_SIZE);
	WgsMixHash(hash, ephemeral_src, WG_HASH_SIZE);
	WgsHKDF(chaining_key, NULL, NULL, ephemeral_src, WG_KEY_SIZE, chaining_key);
}

void WgsHKDF(BYTE *dst_1, BYTE *dst_2, BYTE *dst_3, const BYTE *data, const UINT data_size, const BYTE *chaining_key)
{
	BYTE output[WG_HASH_SIZE + 1];
	BYTE secret[WG_HASH_SIZE];

	MD *md = NewMd("BLAKE2s256");
	SetMdKey(md, chaining_key, WG_HASH_SIZE);

	// Extract entropy from data into secret.
	MdProcess(md, secret, data, data_size);

	if (dst_1 == NULL)
	{
		goto FINAL;
	}

	SetMdKey(md, secret, sizeof(secret));

	// Expand first key
	output[0] = 1;
	MdProcess(md, output, output, 1);
	Copy(dst_1, output, WG_KEY_SIZE);

	if (dst_2 == NULL)
	{
		goto FINAL;
	}

	// Expand second key
	output[sizeof(output) - 1] = 2;
	MdProcess(md, output, output, sizeof(output));
	Copy(dst_2, output, WG_KEY_SIZE);

	if (dst_3 == NULL)
	{
		goto FINAL;
	}

	// Expand third key
	output[sizeof(output) - 1] = 3;
	MdProcess(md, output, output, sizeof(output));
	Copy(dst_3, output, WG_KEY_SIZE);
FINAL:
	FreeMd(md);
	Zero(secret, sizeof(secret));
	Zero(output, sizeof(output));
}

void WgsMixHash(void *dst, const void *src, const UINT size)
{
	blake2s_state b2s_state;

	if (dst == NULL || (src == NULL && size > 0))
	{
		return;
	}

	blake2s_init(&b2s_state, WG_HASH_SIZE);
	blake2s_update(&b2s_state, dst, WG_HASH_SIZE);
	blake2s_update(&b2s_state, src, size);
	blake2s_final(&b2s_state, dst, WG_HASH_SIZE);
}

bool WgsMixDh(BYTE *chaining_key, BYTE *key, const BYTE *priv, const BYTE *pub)
{
	BYTE dh[WG_HASH_SIZE];

	if (chaining_key == NULL || priv == NULL || pub == NULL)
	{
		return false;
	}

	if (crypto_scalarmult_curve25519(dh, priv, pub) != 0)
	{
		Debug("WgsMixDh(): crypto_scalarmult_curve25519() failed!\n");
		return false;
	}

	WgsHKDF(chaining_key, key, NULL, dh, sizeof(dh), chaining_key);

	Zero(dh, sizeof(dh));

	return true;
}
