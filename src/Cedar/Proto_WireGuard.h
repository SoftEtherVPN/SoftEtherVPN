#ifndef PROTO_WIREGUARD_H
#define PROTO_WIREGUARD_H

#include "Proto.h"

#include <sodium.h>

#define WG_IPC_POSTFIX "WIREGUARD"

#define WG_CIPHER "ChaCha20-Poly1305"

#define WG_CONSTRUCTION "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
#define WG_IDENTIFIER "WireGuard v1 zx2c4 Jason@zx2c4.com"
#define WG_LABEL_COOKIE "cookie--"
#define WG_LABEL_MAC1 "mac1----"

#define WG_MAX_INITIATIONS_PER_SECOND 50

#define WG_KEEPALIVE_TIMEOUT 10000 // 10 seconds
#define WG_INITIATION_GIVEUP 30000 // 30 seconds

#define WG_REJECT_AFTER_TIME 180000 // 180 seconds
#define WG_REJECT_AFTER_MESSAGES (UINT64_MAX - 16 - 1)

#define WG_KEY_SIZE crypto_aead_chacha20poly1305_ietf_KEYBYTES
#define WG_IV_SIZE crypto_aead_chacha20poly1305_ietf_NPUBBYTES
#define WG_TAG_SIZE crypto_aead_chacha20poly1305_ietf_ABYTES

#define WG_COOKIE_IV_SIZE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define WG_COOKIE_TAG_SIZE crypto_aead_xchacha20poly1305_ietf_ABYTES

#define WG_HASH_SIZE 32
#define WG_BLOCK_SIZE 16
#define WG_COOKIE_SIZE 16
#define WG_TIMESTAMP_SIZE (sizeof(UINT64) + sizeof(UINT))

#define WG_KEY_BASE64_SIZE (sodium_base64_ENCODED_LEN(WG_KEY_SIZE, sodium_base64_VARIANT_ORIGINAL))

#define WG_AEAD_SIZE(plain_size) (plain_size + WG_TAG_SIZE)
#define WG_PLAIN_SIZE(aead_size) (aead_size - WG_TAG_SIZE)

// RFC 6479
#define WG_REPLAY_WINDOW_SIZE 1024
#define WG_REPLAY_BITMAP_SIZE (WG_REPLAY_WINDOW_SIZE / (sizeof(int) * 8))
#define WG_REPLAY_BITMAP_INDEX_MASK (WG_REPLAY_BITMAP_SIZE - 1)
#define WG_REPLAY_REDUNDANT_BIT_SHIFTS 5
#define WG_REPLAY_REDUNDANT_BITS (1 << WG_REPLAY_REDUNDANT_BIT_SHIFTS)
#define WG_REPLAY_BITMAP_LOC_MASK (WG_REPLAY_REDUNDANT_BITS - 1)

typedef enum WG_MSG_TYPE
{
	WG_MSG_INVALID = 0,
	WG_MSG_HANDSHAKE_INIT,
	WG_MSG_HANDSHAKE_REPLY,
	WG_MSG_HANDSHAKE_COOKIE,
	WG_MSG_TRANSPORT_DATA
} WG_MSG_TYPE;

typedef enum WG_KEYPAIR_STATE
{
	WG_KEYPAIR_INVALID = 0,
	WG_KEYPAIR_INITIATED,
	WG_KEYPAIR_CONFIRMED
} WG_KEYPAIR_STATE;

typedef struct WG_HEADER
{
	BYTE Type;
	BYTE Reserved[3];
} WG_HEADER;

typedef struct WG_COMMON
{
	WG_HEADER Header;
	UINT Index;
} WG_COMMON;

typedef struct WG_MACS
{
	BYTE Mac1[WG_COOKIE_SIZE];
	BYTE Mac2[WG_COOKIE_SIZE];
} WG_MACS;

typedef struct WG_HANDSHAKE_INIT
{
	WG_HEADER Header;
	UINT SenderIndex;
	BYTE UnencryptedEphemeral[WG_KEY_SIZE];
	BYTE EncryptedStatic[WG_AEAD_SIZE(WG_KEY_SIZE)];
	BYTE EncryptedTimestamp[WG_AEAD_SIZE(WG_TIMESTAMP_SIZE)];
	WG_MACS Macs;
} WG_HANDSHAKE_INIT;

typedef struct WG_HANDSHAKE_REPLY
{
	WG_HEADER Header;
	UINT SenderIndex;
	UINT ReceiverIndex;
	BYTE UnencryptedEphemeral[WG_KEY_SIZE];
	BYTE EncryptedNothing[WG_AEAD_SIZE(0)];
	WG_MACS Macs;
} WG_HANDSHAKE_REPLY;

typedef struct WG_COOKIE_REPLY
{
	WG_HEADER Header;
	UINT ReceiverIndex;
	BYTE Nonce[WG_COOKIE_IV_SIZE];
	BYTE EncryptedCookie[WG_COOKIE_SIZE + WG_COOKIE_TAG_SIZE];
} WG_COOKIE_REPLY;

typedef struct WG_TRANSPORT_DATA
{
	WG_HEADER Header;
	UINT ReceiverIndex;
	UINT64 Counter;
	BYTE EncapsulatedPacket[];
} WG_TRANSPORT_DATA;

typedef struct WG_KEYPAIR
{
	WG_KEYPAIR_STATE State;
	UINT64 CreationTime;
	UINT IndexLocal;
	UINT IndexRemote;
	UINT64 CounterLocal;
	UINT64 CounterRemote;
	BYTE KeyLocal[WG_KEY_SIZE];
	BYTE KeyRemote[WG_KEY_SIZE];
	UINT64 ReplayWindow[WG_REPLAY_WINDOW_SIZE];
} WG_KEYPAIR;

typedef struct WG_KEYPAIRS
{
	WG_KEYPAIR *Current;
	WG_KEYPAIR *Next;
	WG_KEYPAIR *Previous;
} WG_KEYPAIRS;

typedef struct WG_SESSION
{
	WG_KEYPAIRS Keypairs;
	IPC *IPC;
	IP IPLocal;
	IP IPRemote;
	USHORT PortLocal;
	USHORT PortRemote;
	UINT64 LastInitiationReceived;
	UINT64 LastDataReceived;
	UINT64 LastDataSent;
	BYTE StaticRemote[WG_KEY_SIZE];
	BYTE LastTimestamp[WG_TIMESTAMP_SIZE];
	BYTE Hash[WG_HASH_SIZE];
	BYTE ChainingKey[WG_HASH_SIZE];
	BYTE PrecomputedStaticStatic[WG_KEY_SIZE];
} WG_SESSION;

typedef struct WG_SERVER
{
	UINT64 Now;
	UINT64 CreationTime;
	WG_SESSION Session;
	CEDAR *Cedar;
	SOCK_EVENT *SockEvent;
	INTERRUPT_MANAGER *InterruptManager;
	BYTE PresharedKey[WG_KEY_SIZE];
	BYTE StaticPublic[WG_KEY_SIZE];
	BYTE StaticPrivate[WG_KEY_SIZE];
	BYTE HandshakeInitHash[WG_HASH_SIZE];
	BYTE HandshakeInitChainingKey[WG_HASH_SIZE];
} WG_SERVER;

const PROTO_IMPL *WgsGetProtoImpl();
const char *WgsName();
const PROTO_OPTION *WgsOptions();
char *WgsOptionStringValue(const char *name);
bool WgsInit(void **param, const LIST *options, CEDAR *cedar, INTERRUPT_MANAGER *im, SOCK_EVENT *se, const char *cipher, const char *hostname);
void WgsFree(void *param);
bool WgsIsPacketForMe(const PROTO_MODE mode, const void *data, const UINT size);
bool WgsProcessDatagrams(void *param, LIST *in, LIST *out);

void WgsLog(const WG_SERVER *server, const char *name, ...);

WG_MSG_TYPE WgsDetectMessageType(const void *data, const UINT size);

UINT WgsMSS(const WG_SESSION *session);

IPC *WgsIPCNew(WG_SERVER *server);

WG_KEYPAIR *WgsProcessHandshakeInit(WG_SERVER *server, const WG_HANDSHAKE_INIT *init, BYTE *ephemeral_remote);
WG_HANDSHAKE_REPLY *WgsCreateHandshakeReply(WG_SERVER *server, WG_KEYPAIR *keypair, const BYTE *ephemeral_remote);

bool WgsProcessTransportData(WG_SERVER *server, WG_TRANSPORT_DATA *data, const UINT size);
WG_TRANSPORT_DATA *WgsCreateTransportData(WG_SERVER *server, const void *data, const UINT size, UINT *final_size);

bool WgsIsInReplayWindow(const WG_KEYPAIR *keypair, const UINT64 counter);
void WgsUpdateReplayWindow(WG_KEYPAIR *keypair, const UINT64 counter);

UINT WgsEncryptData(void *key, const UINT64 counter, void *dst, const void *src, const UINT src_size);
UINT WgsDecryptData(void *key, const UINT64 counter, void *dst, const void *src, const UINT src_size);

bool WgsEncryptWithHash(void *dst, const void *src, const UINT src_size, BYTE *hash, const BYTE *key);
bool WgsDecryptWithHash(void *dst, const void *src, const UINT src_size, BYTE *hash, const BYTE *key);

void WgsEphemeral(BYTE *ephemeral_dst, const BYTE *ephemeral_src, BYTE *chaining_key, BYTE *hash);
void WgsHKDF(BYTE *dst_1, BYTE *dst_2, BYTE *dst_3, const BYTE *data, const UINT data_size, const BYTE *chaining_key);

void WgsMixHash(void *dst, const void *src, const UINT size);
bool WgsMixDh(BYTE *chaining_key, BYTE *key, const BYTE *priv, const BYTE *pub);

#endif
