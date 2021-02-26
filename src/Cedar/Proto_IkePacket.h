// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_IkePacket.h
// Header of Proto_IkePacket.c

#ifndef	PROTO_IKEPACKET_H
#define	PROTO_IKEPACKET_H

// Constants
#ifdef	OS_WIN32
#pragma pack(push, 1)
#endif	// OS_WIN32

// Maximum hash size
#define	IKE_MAX_HASH_SIZE				64		// Size of SHA-2-512 is the maximum for now

// Maximum block size
#define	IKE_MAX_BLOCK_SIZE				16		// Size of AES is maximum at the moment

// Maximum key size
#define	IKE_MAX_KEY_SIZE				32		// Size of AES-256 is the maximum for now

// IKE version
#define IKE_VERSION						0x10	// 1.0

// IKE payload type
#define	IKE_PAYLOAD_NONE				0		// No payload
#define IKE_PAYLOAD_SA					1		// SA payload
#define IKE_PAYLOAD_PROPOSAL			2		// Proposal payload
#define IKE_PAYLOAD_TRANSFORM			3		// Transform payload
#define IKE_PAYLOAD_KEY_EXCHANGE		4		// Key exchange payload
#define IKE_PAYLOAD_ID					5		// ID payload
#define IKE_PAYLOAD_CERT				6		// Certificate payload
#define IKE_PAYLOAD_CERT_REQUEST		7		// Certificate request payload
#define IKE_PAYLOAD_HASH				8		// Hash payload
#define IKE_PAYLOAD_SIGN				9		// Signature payload
#define IKE_PAYLOAD_RAND				10		// Random number payload
#define IKE_PAYLOAD_NOTICE				11		// Notification Payload
#define IKE_PAYLOAD_DELETE				12		// Deletion payload
#define IKE_PAYLOAD_VENDOR_ID			13		// Vendor ID payload
#define	IKE_PAYLOAD_NAT_D				20		// NAT-D payload
#define	IKE_PAYLOAD_NAT_OA				21		// NAT-OA payload
#define	IKE_PAYLOAD_NAT_D_DRAFT			130		// NAT-D payload draft
#define	IKE_PAYLOAD_NAT_OA_DRAFT		16		// NAT-OA payload draft
#define	IKE_PAYLOAD_NAT_OA_DRAFT_2		131		// NAT-OA payload draft 2

// Macro to check whether the payload type is supported
#define IKE_IS_SUPPORTED_PAYLOAD_TYPE(i) ((((i) >= IKE_PAYLOAD_SA) && ((i) <= IKE_PAYLOAD_VENDOR_ID)) || ((i) == IKE_PAYLOAD_NAT_D) || ((i) == IKE_PAYLOAD_NAT_OA) || ((i) == IKE_PAYLOAD_NAT_OA_DRAFT) || ((i) == IKE_PAYLOAD_NAT_OA_DRAFT_2) || ((i) == IKE_PAYLOAD_NAT_D_DRAFT))

// IKE header flag
#define IKE_HEADER_FLAG_ENCRYPTED			1	// Encryption
#define IKE_HEADER_FLAG_COMMIT				2	// Commit
#define IKE_HEADER_FLAG_AUTH_ONLY			4	// Only authentication

// IKE payload common header
struct IKE_COMMON_HEADER
{
	UCHAR NextPayload;
	UCHAR Reserved;
	USHORT PayloadSize;
} GCC_PACKED;

// IKE SA payload header
struct IKE_SA_HEADER
{
	UINT DoI;									// DOI value
	UINT Situation;								// Situation value
} GCC_PACKED;

// DOI value in the IKE SA payload
#define IKE_SA_DOI_IPSEC				1		// IPsec

// Situation value in the IKE SA payload
#define IKE_SA_SITUATION_IDENTITY		1		// Only authentication

// IKE proposal payload header
struct IKE_PROPOSAL_HEADER
{
	UCHAR Number;								// Number
	UCHAR ProtocolId;							// Protocol ID
	UCHAR SpiSize;								// Length of SPI
	UCHAR NumTransforms;						// Transform number
} GCC_PACKED;

// Protocol ID in the IKE proposal payload header
#define IKE_PROTOCOL_ID_IKE				1		// IKE
#define IKE_PROTOCOL_ID_IPSEC_AH		2		// AH
#define IKE_PROTOCOL_ID_IPSEC_ESP		3		// ESP
#define	IKE_PROTOCOL_ID_IPV4			4		// IP
#define	IKE_PROTOCOL_ID_IPV6			41		// IPv6

// IKE transform payload header
struct IKE_TRANSFORM_HEADER
{
	UCHAR Number;								// Number
	UCHAR TransformId;							// Transform ID
	USHORT Reserved;							// Reserved
} GCC_PACKED;

// Transform ID (Phase 1) in IKE transform payload header
#define IKE_TRANSFORM_ID_P1_KEY_IKE				1	// IKE

// Transform ID (Phase 2) in IKE transform payload header
#define IKE_TRANSFORM_ID_P2_ESP_DES				2	// DES-CBC
#define IKE_TRANSFORM_ID_P2_ESP_3DES			3	// 3DES-CBC
#define IKE_TRANSFORM_ID_P2_ESP_CAST			6	// CAST
#define IKE_TRANSFORM_ID_P2_ESP_BLOWFISH		7	// BLOWFISH
#define IKE_TRANSFORM_ID_P2_ESP_AES				12	// AES

// IKE transform value (fixed length)
struct IKE_TRANSFORM_VALUE
{
	UCHAR AfBit;								// AF bit (0: Fixed length, 1: Variable length)
	UCHAR Type;									// Type
	USHORT Value;								// Value data (16bit)
} GCC_PACKED;

// The Type value in IKE transform value (Phase 1)
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_TRANSFORM_VALUE_P1_CRYPTO			1	// Encryption algorithm
#define IKE_TRANSFORM_VALUE_P1_HASH				2	// Hash algorithm
#define IKE_TRANSFORM_VALUE_P1_AUTH_METHOD		3	// Authentication method
#define IKE_TRANSFORM_VALUE_P1_DH_GROUP			4	// DH group number
#define IKE_TRANSFORM_VALUE_P1_LIFE_TYPE		11	// Expiration date type
#define IKE_TRANSFORM_VALUE_P1_LIFE_VALUE		12	// Expiration date
#define IKE_TRANSFORM_VALUE_P1_KET_SIZE			14	// Key size

// The Type value in IKE transform values (Phase 2)
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_TRANSFORM_VALUE_P2_LIFE_TYPE	1	// Expiration date type
#define IKE_TRANSFORM_VALUE_P2_LIFE_VALUE	2	// Expiration date
#define IKE_TRANSFORM_VALUE_P2_DH_GROUP		3	// DH group number
#define IKE_TRANSFORM_VALUE_P2_CAPSULE		4	// Encapsulation mode
#define IKE_TRANSFORM_VALUE_P2_HMAC			5	// HMAC algorithm
#define IKE_TRANSFORM_VALUE_P2_KEY_SIZE		6	// Key size

// Phase 1: The encryption algorithm in the IKE transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P1_CRYPTO_DES_CBC				1
#define IKE_P1_CRYPTO_BLOWFISH				3
#define IKE_P1_CRYPTO_3DES_CBC				5
#define IKE_P1_CRYPTO_CAST_CBC				6
#define IKE_P1_CRYPTO_AES_CBC				7

// Phase 1: The hash algorithm in IKE transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define	IKE_P1_HASH_MD5						1
#define IKE_P1_HASH_SHA1					2
#define IKE_P1_HASH_SHA2_256				4
#define IKE_P1_HASH_SHA2_384				5
#define IKE_P1_HASH_SHA2_512				6

// Phase 1: The authentication method in the IKE transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P1_AUTH_METHOD_PRESHAREDKEY		1
#define IKE_P1_AUTH_METHOD_RSA_SIGN			3

// Phase 1: The DH group number in the IKE transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P1_DH_GROUP_768_MODP			1
#define IKE_P1_DH_GROUP_1024_MODP			2
#define IKE_P1_DH_GROUP_1536_MODP			5
#define IKE_P1_DH_GROUP_2048_MODP			14
#define IKE_P1_DH_GROUP_3072_MODP			15
#define IKE_P1_DH_GROUP_4096_MODP			16

// Phase 1: The expiration date type in IKE transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P1_LIFE_TYPE_SECONDS			1
#define IKE_P1_LIFE_TYPE_KILOBYTES			2

// Phase 2: The HMAC algorithm in IPsec transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P2_HMAC_MD5_96					1
#define IKE_P2_HMAC_SHA1_96					2

// Phase 2: The DH group number in the IPsec transform value
// MUST BE LESS THAN "MAX_IKE_ENGINE_ELEMENTS" !!!
#define IKE_P2_DH_GROUP_768_MODP			1
#define IKE_P2_DH_GROUP_1024_MODP			2
#define IKE_P2_DH_GROUP_1536_MODP			5
#define IKE_P2_DH_GROUP_2048_MODP			14
#define IKE_P2_DH_GROUP_3072_MODP			15
#define IKE_P2_DH_GROUP_4096_MODP			16

// Phase 2: The encapsulation mode in IPsec transform value
#define IKE_P2_CAPSULE_TUNNEL				1
#define IKE_P2_CAPSULE_TRANSPORT			2
#define IKE_P2_CAPSULE_NAT_TUNNEL_1			3
#define IKE_P2_CAPSULE_NAT_TUNNEL_2			61443
#define IKE_P2_CAPSULE_NAT_TRANSPORT_1		4
#define IKE_P2_CAPSULE_NAT_TRANSPORT_2		61444

// Phase 2: The expiration date type in IPsec transform value
#define IKE_P2_LIFE_TYPE_SECONDS			1
#define IKE_P2_LIFE_TYPE_KILOBYTES			2


// IKE ID payload header
struct IKE_ID_HEADER
{
	UCHAR IdType;								// Type of ID
	UCHAR ProtocolId;							// Protocol ID
	USHORT Port;								// Port
} GCC_PACKED;

// Type of ID in the IKE ID payload header
#define IKE_ID_IPV4_ADDR				1		// IPv4 address (32 bit)
#define IKE_ID_FQDN						2		// FQDN
#define IKE_ID_USER_FQDN				3		// User FQDN
#define IKE_ID_IPV4_ADDR_SUBNET			4		// IPv4 + subnet (64 bit)
#define IKE_ID_IPV6_ADDR				5		// IPv6 address (128 bit)
#define IKE_ID_IPV6_ADDR_SUBNET			6		// IPv6 + subnet (256 bit)
#define IKE_ID_DER_ASN1_DN				9		// X.500 Distinguished Name
#define IKE_ID_DER_ASN1_GN				10		// X.500 General Name
#define IKE_ID_KEY_ID					11		// Key

// The protocol ID in the IKE ID payload
#define IKE_ID_PROTOCOL_UDP			IP_PROTO_UDP	// UDP

// IKE certificate payload header
struct IKE_CERT_HEADER
{
	UCHAR CertType;								// Certificate Type
} GCC_PACKED;

// The certificate type in IKE certificate payload header
#define IKE_CERT_TYPE_X509				4		// X.509 certificate (for digital signature)

// IKE certificate payload header
struct IKE_CERT_REQUEST_HEADER
{
	UCHAR CertType;								// Certificate Type
} GCC_PACKED;

// IKE notification payload header
struct IKE_NOTICE_HEADER
{
	UINT DoI;									// DOI value
	UCHAR ProtocolId;							// Protocol ID
	// Same to the protocol ID in the IKE proposal payload header
	UCHAR SpiSize;								// SPI size
	USHORT MessageType;							// Message type
} GCC_PACKED;

// IKE Deletion payload header
struct IKE_DELETE_HEADER
{
	UINT DoI;									// DOI value
	UCHAR ProtocolId;							// Protocol ID
	// Same to the protocol ID in the IKE proposal payload header
	UCHAR SpiSize;								// SPI size
	USHORT NumSpis;								// SPI number
} GCC_PACKED;

// IKE NAT-OA payload header
struct IKE_NAT_OA_HEADER
{
	UCHAR IdType;								// Type of ID
	UCHAR Reserved1;
	USHORT Reserved2;
} GCC_PACKED;


#ifdef	OS_WIN32
#pragma pack(pop)
#endif	// OS_WIN32



//
// IKE internal data structure
//

// IKE packet SA payload
struct IKE_PACKET_SA_PAYLOAD
{
	LIST *PayloadList;						// Proposal payload list
};

// IKE proposal packet payload
struct IKE_PACKET_PROPOSAL_PAYLOAD
{
	UCHAR Number;							// Number
	UCHAR ProtocolId;						// Protocol ID
	BUF *Spi;								// SPI data

	LIST *PayloadList;						// Payload list
};

// IKE packet transform payload
struct IKE_PACKET_TRANSFORM_PAYLOAD
{
	UCHAR Number;								// Number
	UCHAR TransformId;							// Transform ID

	LIST *ValueList;							// Value list
};

// IKE packet transform value
struct IKE_PACKET_TRANSFORM_VALUE
{
	UCHAR Type;									// Type
	UINT Value;									// Value
};

// IKE generic data payload
struct IKE_PACKET_DATA_PAYLOAD
{
	BUF *Data;									// Generic data
};

// IKE packet ID payload
struct IKE_PACKET_ID_PAYLOAD
{
	UCHAR Type;									// Type
	UCHAR ProtocolId;							// Protocol ID
	USHORT Port;								// Port number
	BUF *IdData;								// ID data
	char StrData[128];							// Data of the result of converting to a string
};

// IKE packet certificate payload
struct IKE_PACKET_CERT_PAYLOAD
{
	UCHAR CertType;								// Certificate type
	BUF *CertData;								// Certificate data
};

// IKE packet certificate request payload
struct IKE_PACKET_CERT_REQUEST_PAYLOAD
{
	UCHAR CertType;								// Certificate type
	BUF *Data;									// Request data
};

// IKE packet notification payload
struct IKE_PACKET_NOTICE_PAYLOAD
{
	UCHAR ProtocolId;							// Protocol ID
	USHORT MessageType;							// Message type
	BUF *Spi;									// SPI data
	BUF *MessageData;							// Message data
};

// IKE notification message type
// Error
#define	IKE_NOTICE_ERROR_INVALID_COOKIE			4	// Invalid cookie
#define	IKE_NOTICE_ERROR_INVALID_EXCHANGE_TYPE	7	// Invalid exchange type
#define	IKE_NOTICE_ERROR_INVALID_SPI			11	// Invalid SPI
#define	IKE_NOTICE_ERROR_NO_PROPOSAL_CHOSEN		14	// There is nothing worth mentioning in the presented proposal

// DPD
#define	IKE_NOTICE_DPD_REQUEST					36136	// R-U-THERE
#define	IKE_NOTICE_DPD_RESPONSE					36137	// R-U-THERE-ACK


// IKE packet deletion payload
struct IKE_PACKET_DELETE_PAYLOAD
{
	UCHAR ProtocolId;							// Protocol ID
	LIST *SpiList;								// SPI list
};

// IKE NAT-OA payload
struct IKE_PACKET_NAT_OA_PAYLOAD
{
	IP IpAddress;								// IP address
};

// IKE packet payload
struct IKE_PACKET_PAYLOAD
{
	UCHAR PayloadType;							// Payload type
	UCHAR Padding[3];
	BUF *BitArray;								// Bit array

	union
	{
		IKE_PACKET_SA_PAYLOAD Sa;				// SA payload
		IKE_PACKET_PROPOSAL_PAYLOAD Proposal;	// Proposal payload
		IKE_PACKET_TRANSFORM_PAYLOAD Transform;	// Transform payload
		IKE_PACKET_DATA_PAYLOAD KeyExchange;	// Key exchange payload
		IKE_PACKET_ID_PAYLOAD Id;				// ID payload
		IKE_PACKET_CERT_PAYLOAD Cert;			// Certificate payload
		IKE_PACKET_CERT_REQUEST_PAYLOAD CertRequest;	// Certificate request payload
		IKE_PACKET_DATA_PAYLOAD Hash;			// Hash payload
		IKE_PACKET_DATA_PAYLOAD Sign;			// Signature payload
		IKE_PACKET_DATA_PAYLOAD Rand;			// Random number payload
		IKE_PACKET_NOTICE_PAYLOAD Notice;		// Notification Payload
		IKE_PACKET_DELETE_PAYLOAD Delete;		// Deletion payload
		IKE_PACKET_DATA_PAYLOAD VendorId;		// Vendor ID payload
		IKE_PACKET_NAT_OA_PAYLOAD NatOa;		// NAT-OA payload
		IKE_PACKET_DATA_PAYLOAD GeneralData;	// Generic data payload
	} Payload;
};

struct IKE_PACKET
{
	UINT64 InitiatorCookie;						// Initiator cookie
	UINT64 ResponderCookie;						// Responder cookie
	UCHAR ExchangeType;							// Exchange type
	bool FlagEncrypted;							// Encryption flag
	bool FlagCommit;							// Commit flag
	bool FlagAuthOnly;							// Flag only authentication
	UINT MessageId;								// Message ID
	LIST *PayloadList;							// Payload list
	BUF *DecryptedPayload;						// Decrypted payload
	UINT MessageSize;							// Original size
};

// IKE P1 key set
struct IKE_P1_KEYSET
{
	BUF *SKEYID_d;									// IPsec SA key
	BUF *SKEYID_a;									// IKE SA authentication key
	BUF *SKEYID_e;									// IKE SA encryption key
};

// Number and name of the encryption algorithm for IKE
#define	IKE_CRYPTO_DES_ID						0
#define	IKE_CRYPTO_DES_STRING					"DES-CBC"

#define	IKE_CRYPTO_3DES_ID						1
#define	IKE_CRYPTO_3DES_STRING					"3DES-CBC"

#define	IKE_CRYPTO_AES_ID						2
#define	IKE_CRYPTO_AES_STRING					"AES-CBC"

#define	IKE_CRYPTO_BLOWFISH_ID					3
#define	IKE_CRYPTO_BLOWFISH_STRING				"Blowfish-CBC"

#define	IKE_CRYPTO_CAST_ID						4
#define	IKE_CRYPTO_CAST_STRING					"CAST-128-CBC"

// Number and name of the IKE hash algorithm
#define	IKE_HASH_MD5_ID							0
#define	IKE_HASH_MD5_STRING						"MD5"

#define	IKE_HASH_SHA1_ID						1
#define	IKE_HASH_SHA1_STRING					"SHA-1"

#define	IKE_HASH_SHA2_256_ID					2
#define	IKE_HASH_SHA2_256_STRING				"SHA-2-256"

#define	IKE_HASH_SHA2_384_ID					3
#define	IKE_HASH_SHA2_384_STRING				"SHA-2-384"

#define	IKE_HASH_SHA2_512_ID					4
#define	IKE_HASH_SHA2_512_STRING				"SHA-2-512"

// Number and name of DH algorithm for IKE
#define	IKE_DH_1_ID								0
#define	IKE_DH_1_STRING							"MODP 768 (Group 1)"

#define	IKE_DH_2_ID								1
#define	IKE_DH_2_STRING							"MODP 1024 (Group 2)"

#define	IKE_DH_5_ID								2
#define	IKE_DH_5_STRING							"MODP 1536 (Group 5)"

#define IKE_DH_2048_ID							14
#define IKE_DH_2048_STRING						"MODP 2048 (Group 14)"

#define IKE_DH_3072_ID							15
#define IKE_DH_3072_STRING						"MODP 3072 (Group 15)"

#define IKE_DH_4096_ID							16
#define IKE_DH_4096_STRING						"MODP 4096 (Group 16)"


// Encryption algorithm for IKE
struct IKE_CRYPTO
{
	UINT CryptoId;								// ID
	char *Name;									// Name
	UINT KeySizes[16];							// Key size candidate
	UINT BlockSize;								// Block size
	bool VariableKeySize;						// Whether the key size is variable
};

// IKE encryption key
struct IKE_CRYPTO_KEY
{
	IKE_CRYPTO *Crypto;
	void *Data;									// Key data
	UINT Size;									// Key size

	DES_KEY_VALUE *DesKey1, *DesKey2, *DesKey3;	// DES key
	AES_KEY_VALUE *AesKey;						// AES key
};

// IKE hash algorithm
struct IKE_HASH
{
	UINT HashId;								// ID
	char *Name;									// Name
	UINT HashSize;								// Output size
};

// DH algorithm for IKE
struct IKE_DH
{
	UINT DhId;									// ID
	char *Name;									// Name
	UINT KeySize;								// Key size
};

#define	MAX_IKE_ENGINE_ELEMENTS					64

// Encryption engine for IKE
struct IKE_ENGINE
{
	IKE_CRYPTO *IkeCryptos[MAX_IKE_ENGINE_ELEMENTS];	// Encryption algorithm list that is used in the IKE
	IKE_HASH *IkeHashes[MAX_IKE_ENGINE_ELEMENTS];		// Hash algorithm list that is used in the IKE
	IKE_DH *IkeDhs[MAX_IKE_ENGINE_ELEMENTS];			// DH algorithm list that is used in the IKE

	IKE_CRYPTO *EspCryptos[MAX_IKE_ENGINE_ELEMENTS];	// Encryption algorithm list that is used by ESP
	IKE_HASH *EspHashes[MAX_IKE_ENGINE_ELEMENTS];		// Hash algorithm list that is used by ESP
	IKE_DH *EspDhs[MAX_IKE_ENGINE_ELEMENTS];			// DH algorithm list that is used by ESP

	LIST *CryptosList;
	LIST *HashesList;
	LIST *DhsList;
};

// IKE encryption parameters
struct IKE_CRYPTO_PARAM
{
	IKE_CRYPTO_KEY *Key;						// Key
	UCHAR Iv[IKE_MAX_BLOCK_SIZE];				// IV
	UCHAR NextIv[IKE_MAX_BLOCK_SIZE];			// IV to be used next
};


// Function prototype
IKE_PACKET *IkeParseHeader(void *data, UINT size, IKE_CRYPTO_PARAM *cparam);
IKE_PACKET *IkeParse(void *data, UINT size, IKE_CRYPTO_PARAM *cparam);
IKE_PACKET *IkeParseEx(void *data, UINT size, IKE_CRYPTO_PARAM *cparam, bool header_only);
void IkeFree(IKE_PACKET *p);
IKE_PACKET *IkeNew(UINT64 init_cookie, UINT64 resp_cookie, UCHAR exchange_type,
				   bool encrypted, bool commit, bool auth_only, UINT msg_id,
				   LIST *payload_list);

void IkeDebugPrintPayloads(LIST *o, UINT depth);
void IkeDebugUdpSendRawPacket(IKE_PACKET *p);

BUF *IkeEncrypt(void *data, UINT size, IKE_CRYPTO_PARAM *cparam);
BUF *IkeEncryptWithPadding(void *data, UINT size, IKE_CRYPTO_PARAM *cparam);
BUF *IkeDecrypt(void *data, UINT size, IKE_CRYPTO_PARAM *cparam);

LIST *IkeParsePayloadList(void *data, UINT size, UCHAR first_payload);
LIST *IkeParsePayloadListEx(void *data, UINT size, UCHAR first_payload, UINT *total_read_size);
void IkeFreePayloadList(LIST *o);
UINT IkeGetPayloadNum(LIST *o, UINT payload_type);
IKE_PACKET_PAYLOAD *IkeGetPayload(LIST *o, UINT payload_type, UINT index);

IKE_PACKET_PAYLOAD *IkeParsePayload(UINT payload_type, BUF *b);
void IkeFreePayload(IKE_PACKET_PAYLOAD *p);
bool IkeParseDataPayload(IKE_PACKET_DATA_PAYLOAD *t, BUF *b);
void IkeFreeDataPayload(IKE_PACKET_DATA_PAYLOAD *t);
bool IkeParseSaPayload(IKE_PACKET_SA_PAYLOAD *t, BUF *b);
void IkeFreeSaPayload(IKE_PACKET_SA_PAYLOAD *t);
bool IkeParseProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t, BUF *b);
void IkeFreeProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t);
bool IkeParseTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t, BUF *b);
void IkeFreeTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t);
LIST *IkeParseTransformValueList(BUF *b);
void IkeFreeTransformValueList(LIST *o);
bool IkeParseIdPayload(IKE_PACKET_ID_PAYLOAD *t, BUF *b);
void IkeFreeIdPayload(IKE_PACKET_ID_PAYLOAD *t);
bool IkeParseCertPayload(IKE_PACKET_CERT_PAYLOAD *t, BUF *b);
void IkeFreeCertPayload(IKE_PACKET_CERT_PAYLOAD *t);
bool IkeParseCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t, BUF *b);
void IkeFreeCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t);
bool IkeParseNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t, BUF *b);
void IkeFreeNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t);
bool IkeParseDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t, BUF *b);
void IkeFreeDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t);
bool IkeParseNatOaPayload(IKE_PACKET_NAT_OA_PAYLOAD *t, BUF *b);


bool IkeCompareHash(IKE_PACKET_PAYLOAD *hash_payload, void *hash_data, UINT hash_size);

IKE_PACKET_PAYLOAD *IkeNewPayload(UINT payload_type);
IKE_PACKET_PAYLOAD *IkeNewDataPayload(UCHAR payload_type, void *data, UINT size);
IKE_PACKET_PAYLOAD *IkeNewNatOaPayload(UCHAR payload_type, IP *ip);
IKE_PACKET_PAYLOAD *IkeNewSaPayload(LIST *payload_list);
IKE_PACKET_PAYLOAD *IkeNewProposalPayload(UCHAR number, UCHAR protocol_id, void *spi, UINT spi_size, LIST *payload_list);
IKE_PACKET_PAYLOAD *IkeNewTransformPayload(UCHAR number, UCHAR transform_id, LIST *value_list);
IKE_PACKET_TRANSFORM_VALUE *IkeNewTransformValue(UCHAR type, UINT value);
IKE_PACKET_PAYLOAD *IkeNewIdPayload(UCHAR id_type, UCHAR protocol_id, USHORT port, void *id_data, UINT id_size);
IKE_PACKET_PAYLOAD *IkeNewNoticePayload(UCHAR protocol_id, USHORT message_type,
										void *spi, UINT spi_size,
										void *message, UINT message_size);
IKE_PACKET_PAYLOAD *IkeNewDeletePayload(UCHAR protocol_id, LIST *spi_list);

IKE_PACKET_PAYLOAD *IkeNewNoticeErrorInvalidCookiePayload(UINT64 init_cookie, UINT64 resp_cookie);
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorInvalidSpiPayload(UINT spi);
IKE_PACKET_PAYLOAD *IkeNewNoticeErrorNoProposalChosenPayload(bool quick_mode, UINT64 init_cookie, UINT64 resp_cookie);
IKE_PACKET_PAYLOAD *IkeNewNoticeDpdPayload(bool ack, UINT64 init_cookie, UINT64 resp_cookie, UINT seq_no);

UCHAR IkeGetFirstPayloadType(LIST *o);
BUF *IkeBuild(IKE_PACKET *p, IKE_CRYPTO_PARAM *cparam);
BUF *IkeBuildEx(IKE_PACKET *p, IKE_CRYPTO_PARAM *cparam, bool use_original_decrypted);
BUF *IkeBuildPayloadList(LIST *o);
BUF *IkeBuildPayload(IKE_PACKET_PAYLOAD *p);
BUF *IkeBuildDataPayload(IKE_PACKET_DATA_PAYLOAD *t);
BUF *IkeBuildSaPayload(IKE_PACKET_SA_PAYLOAD *t);
BUF *IkeBuildProposalPayload(IKE_PACKET_PROPOSAL_PAYLOAD *t);
BUF *IkeBuildTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t);
BUF *IkeBuildTransformValue(IKE_PACKET_TRANSFORM_VALUE *v);
BUF *IkeBuildTransformValueList(LIST *o);
BUF *IkeBuildIdPayload(IKE_PACKET_ID_PAYLOAD *t);
BUF *IkeBuildCertPayload(IKE_PACKET_CERT_PAYLOAD *t);
BUF *IkeBuildCertRequestPayload(IKE_PACKET_CERT_REQUEST_PAYLOAD *t);
BUF *IkeBuildNoticePayload(IKE_PACKET_NOTICE_PAYLOAD *t);
BUF *IkeBuildDeletePayload(IKE_PACKET_DELETE_PAYLOAD *t);

BUF *IkeBuildTransformPayload(IKE_PACKET_TRANSFORM_PAYLOAD *t);
UINT IkeGetTransformValue(IKE_PACKET_TRANSFORM_PAYLOAD *t, UINT type, UINT index);
UINT IkeGetTransformValueNum(IKE_PACKET_TRANSFORM_PAYLOAD *t, UINT type);

BUF *IkeStrToPassword(char *str);

IKE_ENGINE *NewIkeEngine();
IKE_CRYPTO *NewIkeCrypto(IKE_ENGINE *e, UINT crypto_id, char *name, UINT *key_sizes, UINT num_key_sizes, UINT block_size);
IKE_HASH *NewIkeHash(IKE_ENGINE *e, UINT hash_id, char *name, UINT size);
IKE_DH *NewIkeDh(IKE_ENGINE *e, UINT dh_id, char *name, UINT key_size);
void FreeIkeEngine(IKE_ENGINE *e);
void FreeIkeCrypto(IKE_CRYPTO *c);
void FreeIkeHash(IKE_HASH *h);
void FreeIkeDh(IKE_DH *d);
IKE_CRYPTO *GetIkeCrypto(IKE_ENGINE *e, bool for_esp, UINT i);
IKE_HASH *GetIkeHash(IKE_ENGINE *e, bool for_esp, UINT i);
IKE_DH *GetIkeDh(IKE_ENGINE *e, bool for_esp, UINT i);

void IkeHash(IKE_HASH *h, void *dst, void *src, UINT size);
void IkeHMac(IKE_HASH *h, void *dst, void *key, UINT key_size, void *data, UINT data_size);
void IkeHMacBuf(IKE_HASH *h, void *dst, BUF *key, BUF *data);

IKE_CRYPTO_KEY *IkeNewKey(IKE_CRYPTO *c, void *data, UINT size);
bool IkeCheckKeySize(IKE_CRYPTO *c, UINT size);
void IkeFreeKey(IKE_CRYPTO_KEY *k);
void IkeCryptoEncrypt(IKE_CRYPTO_KEY *k, void *dst, void *src, UINT size, void *ivec);
void IkeCryptoDecrypt(IKE_CRYPTO_KEY *k, void *dst, void *src, UINT size, void *ivec);

DH_CTX *IkeDhNewCtx(IKE_DH *d);
void IkeDhFreeCtx(DH_CTX *dh);


#endif	// PROTO_IKEPACKET_H
