// SoftEther VPN Source Code - Stable Edition Repository
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under the Apache License, Version 2.0.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on SoftEther VPN project in GitHub.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// This stable branch is officially managed by Daiyuu Nobori, the owner of SoftEther VPN Project.
// Pull requests should be sent to the Developer Edition Master Repository on https://github.com/SoftEtherVPN/SoftEtherVPN
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI OR OTHER
// SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND
// OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. THE SOFTETHER VPN PROJECT HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
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


// Radius.h
// Header of Radius.c

#ifndef	RADIUS_H
#define	RADIUS_H

#define	RADIUS_DEFAULT_PORT		1812			// The default port number
#define	RADIUS_RETRY_INTERVAL	500				// Retransmission interval
#define	RADIUS_RETRY_TIMEOUT	(10 * 1000)		// Time-out period
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
	UCHAR Chap_PeerChallange[16];
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
	UCHAR NextEapId;
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


EAP_CLIENT *NewEapClient(IP *server_ip, UINT server_port, char *shared_secret, UINT resend_timeout, UINT giveup_timeout, char *client_ip_str, char *username, char *hubname);
void ReleaseEapClient(EAP_CLIENT *e);
void CleanupEapClient(EAP_CLIENT *e);
bool EapClientSendMsChapv2AuthRequest(EAP_CLIENT *e);
bool EapClientSendMsChapv2AuthClientResponse(EAP_CLIENT *e, UCHAR *client_response, UCHAR *client_challenge);
void EapSetRadiusGeneralAttributes(RADIUS_PACKET *r, EAP_CLIENT *e);
bool EapSendPacket(EAP_CLIENT *e, RADIUS_PACKET *r);
RADIUS_PACKET *EapSendPacketAndRecvResponse(EAP_CLIENT *e, RADIUS_PACKET *r);

bool PeapClientSendMsChapv2AuthRequest(EAP_CLIENT *eap);
bool PeapClientSendMsChapv2AuthClientResponse(EAP_CLIENT *e, UCHAR *client_response, UCHAR *client_challenge);

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



