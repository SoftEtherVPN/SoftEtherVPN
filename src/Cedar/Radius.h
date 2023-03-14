// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Radius.h
// Header of Radius.c

#ifndef	RADIUS_H
#define	RADIUS_H

#include "Cedar.h"

#include "Mayaqua/Mayaqua.h"

#define	RADIUS_DEFAULT_PORT		1812			// The default port number
#define	RADIUS_RETRY_INTERVAL	1000				// Retransmission interval
#define	RADIUS_RETRY_TIMEOUT	(15 * 1000)		// Time-out period, keep it 2FA friendly
#define	RADIUS_INITIAL_EAP_TIMEOUT	1600		// Initial timeout for EAP


// RADIUS attributes
#define	RADIUS_ATTRIBUTE_USER_NAME					1
#define	RADIUS_ATTRIBUTE_NAS_IP						4
#define	RADIUS_ATTRIBUTE_NAS_PORT					5
#define	RADIUS_ATTRIBUTE_SERVICE_TYPE				6
#define	RADIUS_ATTRIBUTE_FRAMED_PROTOCOL			7
#define	RADIUS_ATTRIBUTE_FRAMED_MTU					12
#define	RADIUS_ATTRIBUTE_STATE						24
#define	RADIUS_ATTRIBUTE_VENDOR_SPECIFIC			26
#define	RADIUS_ATTRIBUTE_CALLED_STATION_ID			30
#define	RADIUS_ATTRIBUTE_CALLING_STATION_ID			31
#define	RADIUS_ATTRIBUTE_NAS_ID						32
#define	RADIUS_ATTRIBUTE_PROXY_STATE				33
#define	RADIUS_ATTRIBUTE_ACCT_SESSION_ID			44
#define	RADIUS_ATTRIBUTE_NAS_PORT_TYPE				61
#define	RADIUS_ATTRIBUTE_TUNNEL_TYPE				64
#define	RADIUS_ATTRIBUTE_TUNNEL_MEDIUM_TYPE			65
#define	RADIUS_ATTRIBUTE_TUNNEL_CLIENT_ENDPOINT		66
#define	RADIUS_ATTRIBUTE_TUNNEL_SERVER_ENDPOINT		67
#define	RADIUS_ATTRIBUTE_EAP_MESSAGE				79
#define	RADIUS_ATTRIBUTE_EAP_AUTHENTICATOR			80
#define	RADIUS_ATTRIBUTE_VLAN_ID					81
#define RADIUS_ATTRIBUTE_FRAMED_INTERFACE_ID		96
#define	RADIUS_MAX_NAS_ID_LEN						253

// RADIUS codes
#define	RADIUS_CODE_ACCESS_REQUEST					1
#define	RADIUS_CODE_ACCESS_ACCEPT					2
#define	RADIUS_CODE_ACCESS_REJECT					3
#define	RADIUS_CODE_ACCESS_CHALLENGE				11

// RADIUS vendor ID
#define	RADIUS_VENDOR_MICROSOFT						311

// RADIUS MS attributes
#define	RADIUS_MS_RAS_VENDOR						9
#define	RADIUS_MS_CHAP_CHALLENGE					11
#define	RADIUS_MS_VERSION							18
#define	RADIUS_MS_CHAP2_RESPONSE					25
#define	RADIUS_MS_RAS_CLIENT_NAME					34
#define	RADIUS_MS_RAS_CLIENT_VERSION				35
#define	RADIUS_MS_NETWORK_ACCESS_SERVER_TYPE		47
#define	RADIUS_MS_RAS_CORRELATION					56

// EAP code
#define	EAP_CODE_REQUEST							1
#define	EAP_CODE_RESPONSE							2
#define	EAP_CODE_SUCCESS							3
#define	EAP_CODE_FAILURE							4

// EAP type
#define	EAP_TYPE_IDENTITY							1
#define	EAP_TYPE_LEGACY_NAK							3
#define	EAP_TYPE_PEAP								25
#define	EAP_TYPE_MS_AUTH							26

// MS-CHAPv2 opcodes
#define	EAP_MSCHAPV2_OP_CHALLENGE					1
#define	EAP_MSCHAPV2_OP_RESPONSE					2
#define	EAP_MSCHAPV2_OP_SUCCESS						3

// EAP-TLS flags
#define	EAP_TLS_FLAGS_LEN							0x80
#define	EAP_TLS_FLAGS_MORE_FRAGMENTS				0x40
#define	EAP_TLS_FLAGS_START							0x20


////////// Modern implementation

#ifdef	OS_WIN32
#pragma pack(push, 1)
#endif	// OS_WIN32

struct EAP_MESSAGE
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Data[1500];
} GCC_PACKED;

struct EAP_MSCHAPV2_GENERAL
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Chap_Opcode;
} GCC_PACKED;

struct EAP_MSCHAPV2_CHALLENGE
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Chap_Opcode;
	UCHAR Chap_Id;
	USHORT Chap_Len;
	UCHAR Chap_ValueSize;	// = 16
	UCHAR Chap_ChallengeValue[16];
	char Chap_Name[256];
} GCC_PACKED;

struct EAP_MSCHAPV2_RESPONSE
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Chap_Opcode;
	UCHAR Chap_Id;
	USHORT Chap_Len;
	UCHAR Chap_ValueSize;	// = 49
	UCHAR Chap_PeerChallenge[16];
	UCHAR Chap_Reserved[8];
	UCHAR Chap_NtResponse[24];
	UCHAR Chap_Flags;
	char Chap_Name[256];
} GCC_PACKED;

struct EAP_MSCHAPV2_SUCCESS_SERVER
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Chap_Opcode;
	UCHAR Chap_Id;
	USHORT Chap_Len;
	char Message[256];
} GCC_PACKED;

struct EAP_MSCHAPV2_SUCCESS_CLIENT
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR Chap_Opcode;
} GCC_PACKED;

struct EAP_PEAP
{
	UCHAR Code;
	UCHAR Id;
	USHORT Len;		// = sizeof(Data) + 5
	UCHAR Type;
	UCHAR TlsFlags;
} GCC_PACKED;

#ifdef	OS_WIN32
#pragma pack(pop)
#endif	// OS_WIN32

struct RADIUS_PACKET
{
	UCHAR Code;
	UCHAR PacketId;
	LIST *AvpList;
	UCHAR Authenticator[16];

	UINT Parse_EapAuthMessagePos;
	UINT Parse_AuthenticatorPos;

	EAP_MESSAGE *Parse_EapMessage;
	UINT Parse_EapMessage_DataSize;

	UINT Parse_StateSize;
	UCHAR Parse_State[256];
};

struct RADIUS_AVP
{
	UCHAR Type;
	UINT VendorId;
	UCHAR VendorCode;
	UCHAR Padding[3];
	UCHAR DataSize;
	UCHAR Data[256];
};

struct EAP_CLIENT
{
	REF *Ref;

	SOCK *UdpSock;
	IP ServerIp;
	UINT ServerPort;
	char SharedSecret[MAX_SIZE];
	char ClientIpStr[256];
	char CalledStationStr[256];
	char Username[MAX_USERNAME_LEN + 1];
	UINT ResendTimeout;
	UINT GiveupTimeout;
	UCHAR TmpBuffer[4096];
	UCHAR LastRecvEapId;

	bool PeapMode;

	UCHAR LastState[256];
	UINT LastStateSize;

	EAP_MSCHAPV2_CHALLENGE MsChapV2Challenge;
	EAP_MSCHAPV2_SUCCESS_SERVER MsChapV2Success;
	UCHAR ServerResponse[20];

	SSL_PIPE *SslPipe;
	UCHAR NextRadiusPacketId;

	BUF *PEAP_CurrentReceivingMsg;
	UINT PEAP_CurrentReceivingTotalSize;
	UCHAR RecvLastCode;

	UINT LastRecvVLanId;
	UCHAR LastRecvVirtualMacAddress[6];

	char In_VpnProtocolState[64];
};

void FreeRadiusPacket(RADIUS_PACKET *p);
BUF *GenerateRadiusPacket(RADIUS_PACKET *p, char *shared_secret);
RADIUS_PACKET *ParseRadiusPacket(void *data, UINT size);
RADIUS_PACKET *NewRadiusPacket(UCHAR code, UCHAR packet_id);
RADIUS_AVP *NewRadiusAvp(UCHAR type, UINT vendor_id, UCHAR vendor_code, void *data, UINT size);
RADIUS_AVP *GetRadiusAvp(RADIUS_PACKET *p, UCHAR type);
void RadiusTest();


EAP_CLIENT *NewEapClient(IP *server_ip, UINT server_port, char *shared_secret, UINT resend_timeout, UINT giveup_timeout, char *client_ip_str, 
						char *username, char *hubname, UCHAR last_recv_eapid);
void ReleaseEapClient(EAP_CLIENT *e);
void CleanupEapClient(EAP_CLIENT *e);
bool EapClientSendMsChapv2AuthRequest(EAP_CLIENT *e);
bool EapClientSendMsChapv2AuthClientResponse(EAP_CLIENT *e, UCHAR *client_response, UCHAR *client_challenge, char *username);
PPP_LCP *EapClientSendEapIdentity(EAP_CLIENT *e);
PPP_LCP *EapClientSendEapRequest(EAP_CLIENT *e, PPP_EAP *eap_request, UINT request_datasize);
void EapSetRadiusGeneralAttributes(RADIUS_PACKET *r, EAP_CLIENT *e);
bool EapSendPacket(EAP_CLIENT *e, RADIUS_PACKET *r);
RADIUS_PACKET *EapSendPacketAndRecvResponse(EAP_CLIENT *e, RADIUS_PACKET *r, bool parse_inner);

bool PeapClientSendMsChapv2AuthRequest(EAP_CLIENT *eap);
bool PeapClientSendMsChapv2AuthClientResponse(EAP_CLIENT *e, UCHAR *client_response, UCHAR *client_challenge, char *username);

bool StartPeapClient(EAP_CLIENT *e);
bool StartPeapSslClient(EAP_CLIENT *e);
bool SendPeapRawPacket(EAP_CLIENT *e, UCHAR *peap_data, UINT peap_size);
bool SendPeapPacket(EAP_CLIENT *e, void *msg, UINT msg_size);
bool GetRecvPeapMessage(EAP_CLIENT *e, EAP_MESSAGE *msg);


////////// Classical implementation
struct RADIUS_LOGIN_OPTION
{
	bool In_CheckVLanId;
	bool In_DenyNoVlanId;
	UINT Out_VLanId;
	bool Out_IsRadiusLogin;
	char NasId[RADIUS_MAX_NAS_ID_LEN + 1];	// NAS-Identifier
	char Out_VirtualMacAddress[6];
	char In_VpnProtocolState[64];
};

// Function prototype
bool RadiusLogin(CONNECTION *c, char *server, UINT port, UCHAR *secret, UINT secret_size, wchar_t *username, char *password, UINT interval, UCHAR *mschap_v2_server_response_20,
				 RADIUS_LOGIN_OPTION *opt, char *hubname);
BUF *RadiusEncryptPassword(char *password, UCHAR *random, UCHAR *secret, UINT secret_size);
BUF *RadiusCreateUserName(wchar_t *username);
BUF *RadiusCreateUserPassword(void *data, UINT size);
BUF *RadiusCreateNasId(char *name);
void RadiusAddValue(BUF *b, UCHAR t, UINT v, UCHAR vt, void *data, UINT size);
LIST *RadiusParseOptions(BUF *b);

#endif	// RADIUS_H



