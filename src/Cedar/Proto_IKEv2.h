// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_IKEv2.h
// Header for IKEv2 (RFC 7296) implementation

#ifndef PROTO_IKEV2_H
#define PROTO_IKEV2_H

#include "Proto_IKE.h"
#include "Proto_IkePacket.h"

//// IKEv2 Header Flags (RFC 7296 Section 3.1)
#define IKEv2_FLAG_RESPONSE       0x20
#define IKEv2_FLAG_VERSION        0x10
#define IKEv2_FLAG_INITIATOR      0x08

//// IKEv2 Payload Types (RFC 7296 Section 3.3)
#define IKEv2_PAYLOAD_NONE        0
#define IKEv2_PAYLOAD_SA          33
#define IKEv2_PAYLOAD_KE          34
#define IKEv2_PAYLOAD_IDi         35
#define IKEv2_PAYLOAD_IDr         36
#define IKEv2_PAYLOAD_CERT        37
#define IKEv2_PAYLOAD_CERTREQ     38
#define IKEv2_PAYLOAD_AUTH        39
#define IKEv2_PAYLOAD_NONCE       40
#define IKEv2_PAYLOAD_NOTIFY      41
#define IKEv2_PAYLOAD_DELETE      42
#define IKEv2_PAYLOAD_VENDOR      43
#define IKEv2_PAYLOAD_TSi         44
#define IKEv2_PAYLOAD_TSr         45
#define IKEv2_PAYLOAD_SK          46
#define IKEv2_PAYLOAD_CP          47
#define IKEv2_PAYLOAD_EAP         48

//// IKEv2 Transform Types
#define IKEv2_TF_ENCR             1
#define IKEv2_TF_PRF              2
#define IKEv2_TF_INTEG            3
#define IKEv2_TF_DH               4
#define IKEv2_TF_ESN              5

//// IKEv2 Encryption Algorithm IDs
#define IKEv2_ENCR_3DES           3
#define IKEv2_ENCR_AES_CBC        12

//// IKEv2 PRF Algorithm IDs
#define IKEv2_PRF_HMAC_MD5        1
#define IKEv2_PRF_HMAC_SHA1       2
#define IKEv2_PRF_HMAC_SHA2_256   5
#define IKEv2_PRF_HMAC_SHA2_384   6
#define IKEv2_PRF_HMAC_SHA2_512   7

//// IKEv2 Integrity Algorithm IDs
#define IKEv2_INTEG_HMAC_MD5_96        1   // key=16,  icv=12
#define IKEv2_INTEG_HMAC_SHA1_96       2   // key=20,  icv=12
#define IKEv2_INTEG_HMAC_SHA2_256_128  12  // key=32,  icv=16
#define IKEv2_INTEG_HMAC_SHA2_384_192  13  // key=48,  icv=24
#define IKEv2_INTEG_HMAC_SHA2_512_256  14  // key=64,  icv=32

//// IKEv2 DH Groups (same wire values as IKEv1)
#define IKEv2_DH_1024_MODP        2
#define IKEv2_DH_1536_MODP        5
#define IKEv2_DH_2048_MODP        14
#define IKEv2_DH_3072_MODP        15
#define IKEv2_DH_4096_MODP        16

//// IKEv2 ESN Values
#define IKEv2_ESN_NO_ESN          0
#define IKEv2_ESN_YES             1

//// IKEv2 Notify Message Types (error types < 16384)
#define IKEv2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD  1
#define IKEv2_NOTIFY_INVALID_IKE_SPI               4
#define IKEv2_NOTIFY_INVALID_MAJOR_VERSION         5
#define IKEv2_NOTIFY_INVALID_SYNTAX                7
#define IKEv2_NOTIFY_INVALID_MESSAGE_ID            9
#define IKEv2_NOTIFY_INVALID_SPI                   11
#define IKEv2_NOTIFY_NO_PROPOSAL_CHOSEN            14
#define IKEv2_NOTIFY_INVALID_KE_PAYLOAD            17
#define IKEv2_NOTIFY_AUTHENTICATION_FAILED         24
#define IKEv2_NOTIFY_TS_UNACCEPTABLE               38

//// IKEv2 Notify status types (>= 16384)
#define IKEv2_NOTIFY_NAT_DETECTION_SOURCE_IP       16388
#define IKEv2_NOTIFY_NAT_DETECTION_DESTINATION_IP  16389
#define IKEv2_NOTIFY_USE_TRANSPORT_MODE            16391
#define IKEv2_NOTIFY_ESP_TFC_PADDING_NOT_SUPPORTED 16394

//// IKEv2 ID Types
#define IKEv2_ID_IPV4_ADDR        1
#define IKEv2_ID_FQDN             2
#define IKEv2_ID_RFC822_ADDR      3
#define IKEv2_ID_IPV6_ADDR        5
#define IKEv2_ID_KEY_ID           11

//// IKEv2 Authentication Methods
#define IKEv2_AUTH_RSA_SIGN       1
#define IKEv2_AUTH_PSK            2

//// IKEv2 Traffic Selector Types
#define IKEv2_TS_IPV4_ADDR_RANGE  7
#define IKEv2_TS_IPV6_ADDR_RANGE  8

//// IKEv2 Protocol IDs
#define IKEv2_PROTO_IKE           1
#define IKEv2_PROTO_AH            2
#define IKEv2_PROTO_ESP           3

//// SA states
#define IKEv2_SA_STATE_HALF_OPEN  0
#define IKEv2_SA_STATE_ESTABLISHED 1

//// Sizes and limits
#define IKEv2_MAX_KEYMAT_SIZE     128
#define IKEv2_NONCE_SIZE          32
#define IKEv2_NONCE_MIN_SIZE      16
#define IKEv2_NONCE_MAX_SIZE      256
#define IKEv2_PSK_PAD             "Key Pad for IKEv2"
#define IKEv2_PSK_PAD_LEN         17

//// Timeouts
#define IKEv2_SA_TIMEOUT_HALF_OPEN    30000
#define IKEv2_SA_TIMEOUT_ESTABLISHED  (86400ULL * 1000)
#define IKEv2_SA_RESEND_INTERVAL      2000
#define IKEv2_CHILD_SA_LIFETIME_SECS  3600


//// Structures

// Negotiated IKE SA transform parameters
struct IKEv2_IKETF
{
    UINT EncrAlg;        // Encryption algorithm
    UINT EncrKeyLen;     // Encryption key length (bytes)
    UINT PrfAlg;         // PRF algorithm
    UINT IntegAlg;       // Integrity algorithm
    UINT DhGroup;        // DH group number
    UINT BlockSize;      // Cipher block size (bytes)
    UINT PrfKeyLen;      // PRF key length (bytes)
    UINT PrfOutLen;      // PRF output length (bytes)
    UINT IntegKeyLen;    // Integrity key length (bytes)
    UINT IntegIcvLen;    // Integrity ICV length (bytes)
};
typedef struct IKEv2_IKETF IKEv2_IKETF;

// Negotiated Child SA transform parameters
struct IKEv2_CHILDTF
{
    UINT EncrAlg;        // Encryption algorithm
    UINT EncrKeyLen;     // Encryption key length (bytes)
    UINT IntegAlg;       // Integrity algorithm
    UINT IntegKeyLen;    // Integrity key length (bytes)
    UINT IntegIcvLen;    // Integrity ICV length (bytes)
    UINT DhGroup;        // DH group (0 if none)
    bool UseTransport;   // True = transport mode
    UINT BlockSize;      // Cipher block size
};
typedef struct IKEv2_CHILDTF IKEv2_CHILDTF;

// IKEv2 SA (one per IKEv2 connection attempt)
struct IKEv2_SA
{
    UINT         Id;
    UINT64       InitiatorSPI;
    UINT64       ResponderSPI;

    IP           ClientIP;
    UINT         ClientPort;
    IP           ServerIP;
    UINT         ServerPort;
    bool         IsNatT;

    UINT         State;
    bool         Deleting;
    UINT64       FirstCommTick;
    UINT64       LastCommTick;

    IKEv2_IKETF  Transform;

    // Nonces
    BUF         *Ni;
    BUF         *Nr;

    // DH
    DH_CTX      *Dh;
    BUF         *GxI;     // initiator KE value
    BUF         *GxR;     // responder KE value (our public key)

    // Derived IKE SA keys  (max 64 bytes each)
    UCHAR        SK_d [IKEv2_MAX_KEYMAT_SIZE];
    UCHAR        SK_ai[IKEv2_MAX_KEYMAT_SIZE];
    UCHAR        SK_ar[IKEv2_MAX_KEYMAT_SIZE];
    UCHAR        SK_ei[IKEv2_MAX_KEYMAT_SIZE];
    UCHAR        SK_er[IKEv2_MAX_KEYMAT_SIZE];
    UCHAR        SK_pi[IKEv2_MAX_KEYMAT_SIZE];
    UCHAR        SK_pr[IKEv2_MAX_KEYMAT_SIZE];

    // Crypto key objects for SK payload
    IKE_CRYPTO_KEY *EncKeyI;   // key for SK_ei (decrypt received)
    IKE_CRYPTO_KEY *EncKeyR;   // key for SK_er (encrypt sent)

    // Original IKE_SA_INIT messages for AUTH
    BUF         *InitMsg;   // IKE_SA_INIT request (from initiator)
    BUF         *RespMsg;   // IKE_SA_INIT response (from us)

    // Initiator identity from IKE_AUTH
    UCHAR        IDi_Type;
    BUF         *IDi_Data;

    // Message ID tracking
    UINT         NextExpectedMsgId;

    // Retransmission: cache last response
    BUF         *LastResponse;
    UINT         LastRespMsgId;
    UINT64       LastRespTick;
    UINT         NumResends;

    // Pointer to IKEv1 IKE_CLIENT created after AUTH
    IKE_CLIENT  *IkeClient;
};
typedef struct IKEv2_SA IKEv2_SA;


//// Function prototypes

void  ProcIKEv2PacketRecv(IKE_SERVER *ike, UDPPACKET *p);
void  ProcessIKEv2Interrupts(IKE_SERVER *ike);

IKEv2_SA *IKEv2NewSA(IKE_SERVER *ike);
void  IKEv2FreeSA(IKE_SERVER *ike, IKEv2_SA *sa);
void  IKEv2MarkDeleting(IKE_SERVER *ike, IKEv2_SA *sa);
void  IKEv2PurgeDeleting(IKE_SERVER *ike);
IKEv2_SA *IKEv2FindByInitSPI(IKE_SERVER *ike, UINT64 init_spi, IP *client_ip, UINT client_port);
IKEv2_SA *IKEv2FindBySPIPair(IKE_SERVER *ike, UINT64 init_spi, UINT64 resp_spi);
int   CmpIKEv2SA(void *p1, void *p2);

void  IKEv2ProcSAInit(IKE_SERVER *ike, UDPPACKET *p, IKE_HEADER *hdr);
void  IKEv2ProcAuth(IKE_SERVER *ike, UDPPACKET *p, IKE_HEADER *hdr, IKEv2_SA *sa,
                    void *payload_data, UINT payload_size);
void  IKEv2ProcInformational(IKE_SERVER *ike, UDPPACKET *p, IKE_HEADER *hdr, IKEv2_SA *sa,
                              void *payload_data, UINT payload_size);

bool  IKEv2DeriveKeys(IKE_SERVER *ike, IKEv2_SA *sa);
void  IKEv2PRF(UINT prf_alg, void *key, UINT key_len,
               void *data, UINT data_len, void *out);
void  IKEv2PRFPlus(UINT prf_alg, void *key, UINT key_len,
                   void *seed, UINT seed_len, void *out, UINT out_len);

bool  IKEv2VerifyAuth(IKE_SERVER *ike, IKEv2_SA *sa,
                      UCHAR auth_method, void *auth_data, UINT auth_len);
void  IKEv2ComputeOurAuth(IKE_SERVER *ike, IKEv2_SA *sa, void *out, UINT *out_len);

bool  IKEv2CreateChildSAForClient(IKE_SERVER *ike, IKEv2_SA *sa,
                                   IKEv2_CHILDTF *ctf, UINT spi_i, UINT spi_r,
                                   BUF *ni, BUF *nr);

bool  IKEv2ParseSAProposalIKE(void *data, UINT size, IKEv2_IKETF *out);
bool  IKEv2ParseSAProposalChild(void *data, UINT size, IKEv2_CHILDTF *out, UINT *out_spi_i);
UINT  IKEv2BuildSAProposalIKE(IKEv2_SA *sa, void *buf, UINT buf_size);
UINT  IKEv2BuildSAProposalChild(IKEv2_CHILDTF *ctf, UINT spi_r, void *buf, UINT buf_size);

void  IKEv2SendResponse(IKE_SERVER *ike, IKEv2_SA *sa, IKE_HEADER *req_hdr,
                        UCHAR exchange_type, void *payloads, UINT payloads_size,
                        bool encrypt);
void  IKEv2SendNotifyError(IKE_SERVER *ike, UDPPACKET *p, IKE_HEADER *hdr,
                            UINT64 resp_spi, USHORT notify_type);

BUF  *IKEv2EncryptSK(IKE_SERVER *ike, IKEv2_SA *sa, UCHAR next_payload,
                      void *inner, UINT inner_size);
BUF  *IKEv2DecryptSK(IKE_SERVER *ike, IKEv2_SA *sa, bool is_init_sending,
                      void *sk_data, UINT sk_size, UCHAR *out_next_payload);

UINT  IKEv2PrfKeyLen(UINT prf_alg);
UINT  IKEv2PrfOutLen(UINT prf_alg);
UINT  IKEv2IntegKeyLen(UINT integ_alg);
UINT  IKEv2IntegIcvLen(UINT integ_alg);
UINT  IKEv2EncrKeyLen(UINT encr_alg, UINT requested);
UINT  IKEv2EncrBlockSize(UINT encr_alg);
IKE_HASH   *IKEv2GetHashForPrf(IKE_SERVER *ike, UINT prf_alg);
IKE_HASH   *IKEv2GetHashForInteg(IKE_SERVER *ike, UINT integ_alg);
IKE_CRYPTO *IKEv2GetCrypto(IKE_SERVER *ike, UINT encr_alg);
IKE_DH     *IKEv2GetDh(IKE_SERVER *ike, UINT dh_group);

#endif // PROTO_IKEV2_H
