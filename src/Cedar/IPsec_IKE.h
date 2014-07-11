// SoftEther VPN Source Code
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.
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


// IPsec_IKE.h
// Header of IPsec_IKE.c

#ifndef	IPSEC_IKE_H
#define	IPSEC_IKE_H

//// Macro

//// Constants

// State
#define	IKE_SA_MAIN_MODE					0	// Main mode
#define	IKE_SA_AGRESSIVE_MODE				1	// Aggressive mode

#define	IKE_SA_MM_STATE_1_SA				0	// Main mode state 1 (SA exchange is complete. Wait for key exchange)
#define	IKE_SA_MM_STATE_2_KEY				1	// Main mode state 2 (Key exchange is complete. Wait for exchange ID)
#define	IKE_SA_MM_STATE_3_ESTABLISHED		2	// Main mode state 3 (ID exchange is complete. Established)

#define	IKE_SA_AM_STATE_1_SA				0	// Aggressive mode state 1 (SA exchange is completed. Wait for hash)
#define	IKE_SA_AM_STATE_2_ESTABLISHED		1	// Aggressive mode state 2 (Hash exchange is completed. Established)

#define	IKE_SA_RESEND_INTERVAL				(2 * 1000)	// IKE SA packet retransmission interval
#define	IKE_SA_RAND_SIZE					16	// Size of the random number

// ESP
#define	IKE_ESP_HASH_SIZE					12	// The hash size for the ESP packet

// Type of UDP packet
#define	IKE_UDP_TYPE_ISAKMP					0	// ISAKMP packet (destination 500)
#define	IKE_UDP_TYPE_ESP					1	// ESP packet (destination 4500)
#define	IKE_UDP_KEEPALIVE					2	// KeepAlive packet
#define	IKE_UDP_SPECIAL						3	// Special packet

// String for Vendor ID
#define	IKE_VENDOR_ID_RFC3947_NAT_T			"0x4a131c81070358455c5728f20e95452f"
#define	IKE_VENDOR_ID_IPSEC_NAT_T_IKE_03	"0x7d9419a65310ca6f2c179d9215529d56"
#define	IKE_VENDOR_ID_IPSEC_NAT_T_IKE_02	"0x90cb80913ebb696e086381b5ec427b1f"
#define	IKE_VENDOR_ID_IPSEC_NAT_T_IKE_02_2	"0xcd60464335df21f87cfdb2fc68b6a448"
#define	IKE_VENDOR_ID_IPSEC_NAT_T_IKE_00	"0x4485152d18b6bbcd0be8a8469579ddcc"
#define	IKE_VENDOR_ID_RFC3706_DPD			"0xafcad71368a1f1c96b8696fc77570100"
#define	IKE_VENDOR_ID_MICROSOFT_L2TP		"0x4048b7d56ebce88525e7de7f00d6c2d3"
#define	IKE_VENDOR_ID_MS_NT5_ISAKMPOAKLEY	"0x1e2b516905991c7d7c96fcbfb587e461"
#define	IKE_VENDOR_ID_MS_VID_INITIALCONTACT	"0x26244d38eddb61b3172a36e3d0cfb819"

// Quota
#define	IKE_QUOTA_MAX_NUM_CLIENTS_PER_IP	1000			// The number of IKE_CLIENT per IP address
#define	IKE_QUOTA_MAX_NUM_CLIENTS			30000			// Limit number of IKE_CLIENT
#define	IKE_QUOTA_MAX_SA_PER_CLIENT			100				// The limit number of SA for each IKE_CLIENT

// Time-out
#define	IKE_TIMEOUT_FOR_IKE_CLIENT			150000			// IKE_CLIENT non-communication disconnect time
#define	IKE_TIMEOUT_FOR_IKE_CLIENT_FOR_NOT_ESTABLISHED		10000 // IKE_CLIENT non-communication disconnect time (connection incomplete)
#define	IKE_INTERVAL_UDP_KEEPALIVE			5000			// UDP KeepAlive transmission interval
#define	IKE_QUICKMODE_START_INTERVAL		2000			// QuickMode start interval
#define	IKE_QUICKMODE_FAILED_TIMEOUT		10000			// Maximum time to tolerant that to fail to establish a QuickMode
#define	IKE_INTERVAL_DPD_KEEPALIVE			10000			// DPD KeepAlive transmission interval

// Expiration margin
#define	IKE_SOFT_EXPIRES_MARGIN				1000			// Expiration margin


//// Type

// IKE SA transform data
struct IKE_SA_TRANSFORM_SETTING
{
	IKE_CRYPTO *Crypto;
	UINT CryptoKeySize;
	IKE_HASH *Hash;
	IKE_DH *Dh;
	UINT CryptoId;
	UINT HashId;
	UINT DhId;
	UINT LifeKilobytes;
	UINT LifeSeconds;
};

// IPsec SA transforms data
struct IPSEC_SA_TRANSFORM_SETTING
{
	IKE_CRYPTO *Crypto;
	UINT CryptoKeySize;
	IKE_HASH *Hash;
	IKE_DH *Dh;
	UINT CryptoId;
	UINT HashId;
	UINT DhId;
	UINT LifeKilobytes;
	UINT LifeSeconds;
	UINT SpiServerToClient;
	UINT CapsuleMode;
	bool OnlyCapsuleModeIsInvalid;
};

// Function support information
struct IKE_CAPS
{
	// Support Information
	bool NatTraversalRfc3947;		// RFC 3947 Negotiation of NAT-Traversal in the IKE
	bool NatTraversalDraftIetf;		// draft-ietf-ipsec-nat-t-ike
	bool DpdRfc3706;				// RFC 3706 A Traffic-Based Method of Detecting Dead Internet Key Exchange (IKE) Peers
	bool MS_L2TPIPSecVPNClient;		// Vendor ID: Microsoft L2TP/IPSec VPN Client
	bool MS_NT5_ISAKMP_OAKLEY;		// Vendor ID: MS NT5 ISAKMPOAKLEY
	bool MS_Vid_InitialContact;		// Vendor ID: Microsoft Vid-Initial-Contact

	// Use information
	bool UsingNatTraversalRfc3947;
	bool UsingNatTraversalDraftIetf;
};

// IKE / IPsec client
struct IKE_CLIENT
{
	UINT Id;
	IP ClientIP;
	UINT ClientPort;
	IP ServerIP;
	UINT ServerPort;
	IKE_SA *CurrentIkeSa;						// IKE SA to be used currently
	IPSECSA *CurrentIpSecSaRecv;				// IPsec SA to be used currently (receive direction)
	IPSECSA *CurrentIpSecSaSend;				// IPsec SA to be currently in use (transmit direction)
	UINT64 FirstCommTick;						// Time the first data communication
	UINT64 LastCommTick;						// Time that made the last communication (received data) time
	bool Deleting;								// Deleting
	UINT64 NextKeepAliveSendTick;				// Time to send the next KeepAlive
	UINT64 NextDpdSendTick;						// Time to send the next DPD
	UINT DpdSeqNo;								// DPD sequence number
	char ClientId[128];							// ID presented by the client
	char Secret[MAX_SIZE];						// Secret value of the authentication is successful

	bool IsMicrosoft;							// Whether the client is Microsoft's

	IPSEC_SA_TRANSFORM_SETTING CachedTransformSetting;	// Cached transform attribute value
	UINT64 CurrentExpiresSoftTick_StoC;			// The maximum value of the flexible expiration date of the current (server -> client)
	UINT64 CurrentExpiresSoftTick_CtoS;			// The maximum value of the flexible expiration date of the current (client -> server)
	UINT CurrentNumEstablishedIPsecSA_StoC;		// The number of IPsec SA currently active (server -> client)
	UINT CurrentNumEstablishedIPsecSA_CtoS;		// The number of IPsec SA currently active (client -> server)
	UINT CurrentNumHealtyIPsecSA_CtoS;			// The number of currently available IPsec SA which expiration well within (client -> server)
	UINT CurrentNumHealtyIPsecSA_StoC;			// The number of currently available IPsec SA which expiration well within (server -> client)
	bool SendID1andID2;							// Whether to send the ID in QM
	UCHAR SendID1_Type, SendID2_Type;
	UCHAR SendID1_Protocol, SendID2_Protocol;
	USHORT SendID1_Port, SendID2_Port;
	BUF *SendID1_Buf, *SendID2_Buf;
	bool SendNatOaDraft1, SendNatOaDraft2, SendNatOaRfc;	// Whether to send the NAT-OA in QM
	bool StartQuickModeAsSoon;					// Flag to indicate to the start of the Quick Mode as soon as possible
	UINT64 LastQuickModeStartTick;				// Time which the last QuickMode started
	UINT64 NeedQmBeginTick;						// Time which a start-up of QuickMode is required

	// L2TP related
	L2TP_SERVER *L2TP;							// L2TP server
	UINT L2TPClientPort;						// Client-side port number of L2TP
	IP L2TPServerIP, L2TPClientIP;				// IP address used by the L2TP processing
	bool IsL2TPOnIPsecTunnelMode;				// Whether the L2TP is working on IPsec tunnel mode

	// EtherIP related
	ETHERIP_SERVER *EtherIP;					// EtherIP server
	bool IsEtherIPOnIPsecTunnelMode;			// Whether the EtherIP is working on IPsec tunnel mode

	// Transport mode related
	IP TransportModeServerIP;
	IP TransportModeClientIP;
	bool ShouldCalcChecksumForUDP;				// Flag to calculate the checksum for the UDP packet

	// Tunnel mode related
	IP TunnelModeServerIP;						// Server-side internal IP address
	IP TunnelModeClientIP;						// Client-side internal IP address
	USHORT TunnelSendIpId;						// ID of the transmission IP header
};

// IKE SA
struct IKE_SA
{
	UINT Id;
	IKE_CLIENT *IkeClient;						// Pointer to the IKE client
	UINT64 InitiatorCookie, ResponderCookie;	// Cookie
	UINT Mode;									// Mode
	UINT State;									// State
	BUF *SendBuffer;							// Buffer during transmission
	UINT64 NextSendTick;						// Next transmission time
	UINT64 FirstCommTick;						// Time that the first data communication
	UINT64 EstablishedTick;						// Time that the SA has been established
	UINT64 LastCommTick;						// Time that made the last communication (received data) time
	IKE_SA_TRANSFORM_SETTING TransformSetting;	// Transform Configuration
	IKE_CAPS Caps;								// IKE Caps
	BUF *InitiatorRand, *ResponderRand;			// Random number
	BUF *DhSharedKey;							// DH common key
	BUF *GXi, *GXr;								// DH exchange data
	BUF *SAi_b;									// Data needed for authentication
	BUF *YourIDPayloadForAM;					// Copy the ID payload of the client-side
	UCHAR SKEYID[IKE_MAX_HASH_SIZE];			// Key set
	UCHAR SKEYID_d[IKE_MAX_HASH_SIZE];
	UCHAR SKEYID_a[IKE_MAX_HASH_SIZE];
	UCHAR SKEYID_e[IKE_MAX_HASH_SIZE];
	UCHAR InitiatorHashForAM[IKE_MAX_HASH_SIZE];
	IKE_CRYPTO_KEY *CryptoKey;					// Common encryption key
	UINT HashSize;								// Hash size
	UINT KeySize;								// Key size
	UINT BlockSize;								// Block size
	UCHAR Iv[IKE_MAX_BLOCK_SIZE];				// IV
	bool IsIvExisting;							// Whether an IV exists
	bool Established;							// Established flag
	bool Deleting;								// Deleting
	UINT NumResends;							// The number of retransmissions
	char Secret[MAX_SIZE];						// Secret value of the authentication is successful
};

// IPsec SA
struct IPSECSA
{
	UINT Id;
	IKE_CLIENT *IkeClient;						// Pointer to the IKE client
	IKE_SA *IkeSa;								// Pointer to IKE_SA to use for transmission
	UCHAR Iv[IKE_MAX_BLOCK_SIZE];				// IV used in the Quick Mode exchange
	bool IsIvExisting;							// Whether the IV exists
	UINT MessageId;								// Message ID used in Quick Mode exchange
	UINT Spi;									// SPI
	UINT CurrentSeqNo;							// Send sequence number
	BUF *SendBuffer;							// Buffer during transmission
	UINT NumResends;							// The number of retransmissions
	UINT64 NextSendTick;						// Next transmission date and time
	UINT64 FirstCommTick;						// Time the last data sent
	UINT64 EstablishedTick;						// Time that the SA has been established
	UINT64 LastCommTick;						// Time that made the last communication (received data) time
	UINT64 ExpiresHardTick;						// Exact expiration time
	UINT64 ExpiresSoftTick;						// Flexible expiration time
	UINT64 TotalSize;							// Size sent to and received
	IPSEC_SA_TRANSFORM_SETTING TransformSetting;	// Transform Configuration
	bool ServerToClient;						// Whether is upload direction
	IPSECSA *PairIPsecSa;						// IPsec SA that are paired
	bool Established;							// Established flag
	BUF *InitiatorRand, *ResponderRand;			// Random number
	BUF *SharedKey;								// PFS shared key
	UCHAR Hash3[IKE_MAX_HASH_SIZE];				// Hash 3
	UCHAR KeyMat[IKE_MAX_KEY_SIZE + IKE_MAX_HASH_SIZE];	// Encryption key
	UCHAR HashKey[IKE_MAX_HASH_SIZE];			// Hash key
	IKE_CRYPTO_KEY *CryptoKey;					// Key data
	bool Deleting;								// Deleting
	UCHAR EspIv[IKE_MAX_BLOCK_SIZE];			// IV for ESP communication
	bool Initiated;								// The server-side is initiator
	DH_CTX *Dh;									// DH (only if the server-side is initiator)
	bool StartQM_FlagSet;						// Whether the flag to indicate to do the QM is set to the IKE_CLIENT
	UCHAR SKEYID_d[IKE_MAX_HASH_SIZE];
	UCHAR SKEYID_a[IKE_MAX_HASH_SIZE];
	IKE_HASH *SKEYID_Hash;
};

// IKE server
struct IKE_SERVER
{
	CEDAR *Cedar;
	IPSEC_SERVER *IPsec;
	UINT64 Now;									// Current time
	LIST *SendPacketList;						// Transmission packet
	INTERRUPT_MANAGER *Interrupts;				// Interrupt manager
	SOCK_EVENT *SockEvent;						// SockEvent
	IKE_ENGINE *Engine;							// Encryption engine
	LIST *ClientList;							// Client list
	LIST *IkeSaList;							// SA list
	LIST *IPsecSaList;							// IPsec SA list
	LIST *ThreadList;							// L2TP thread list
	bool StateHasChanged;						// Flag whether the state has changed
	UINT CurrentIkeSaId, CurrentIPsecSaId, CurrentIkeClientId, CurrentEtherId;	// Serial number ID

	// Setting data
	char Secret[MAX_SIZE];						// Pre-shared key
};


//// Function prototype
IKE_SERVER *NewIKEServer(CEDAR *cedar, IPSEC_SERVER *ipsec);
void FreeIKEServer(IKE_SERVER *ike);
void SetIKEServerSockEvent(IKE_SERVER *ike, SOCK_EVENT *e);
void ProcIKEPacketRecv(IKE_SERVER *ike, UDPPACKET *p);
void StopIKEServer(IKE_SERVER *ike);
void ProcessIKEInterrupts(IKE_SERVER *ike);
IKE_PACKET *ParseIKEPacketHeader(UDPPACKET *p);
void ProcIkeMainModePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header);
void ProcIkeQuickModePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header);
void ProcIkeAggressiveModePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header);
void ProcIkeInformationalExchangePacketRecv(IKE_SERVER *ike, UDPPACKET *p, IKE_PACKET *header);
void FreeIkeSa(IKE_SA *sa);
void FreeIkeClient(IKE_SERVER *ike, IKE_CLIENT *c);
UINT64 GenerateNewResponserCookie(IKE_SERVER *ike);
bool GetBestTransformSettingForIkeSa(IKE_SERVER *ike, IKE_PACKET *pr, IKE_SA_TRANSFORM_SETTING *setting);
bool TransformPayloadToTransformSettingForIkeSa(IKE_SERVER *ike, IKE_PACKET_TRANSFORM_PAYLOAD *transform, IKE_SA_TRANSFORM_SETTING *setting);
IKE_CLIENT *SearchIkeClientForIkePacket(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, IKE_PACKET *pr);
IKE_CLIENT *SearchOrCreateNewIkeClientForIkePacket(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, IKE_PACKET *pr);
UINT GetNumberOfIkeClientsFromIP(IKE_SERVER *ike, IP *client_ip);
UINT GetNumberOfIPsecSaOfIkeClient(IKE_SERVER *ike, IKE_CLIENT *c);
UINT GetNumberOfIkeSaOfIkeClient(IKE_SERVER *ike, IKE_CLIENT *c);
int CmpIkeClient(void *p1, void *p2);
int CmpIkeSa(void *p1, void *p2);
int CmpIPsecSa(void *p1, void *p2);
IKE_SA *FindIkeSaByEndPointAndInitiatorCookie(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port, UINT64 init_cookie, UINT mode);
IKE_SA *FindIkeSaByResponderCookie(IKE_SERVER *ike, UINT64 responder_cookie);
IKE_SA *FindIkeSaByResponderCookieAndClient(IKE_SERVER *ike, UINT64 responder_cookie, IKE_CLIENT *c);
IKE_CLIENT *NewIkeClient(IKE_SERVER *ike, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port);
IKE_CLIENT *SetIkeClientEndpoint(IKE_SERVER *ike, IKE_CLIENT *c, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port);
IKE_SA *NewIkeSa(IKE_SERVER *ike, IKE_CLIENT *c, UINT64 init_cookie, UINT mode, IKE_SA_TRANSFORM_SETTING *setting);
IKE_PACKET_PAYLOAD *TransformSettingToTransformPayloadForIke(IKE_SERVER *ike, IKE_SA_TRANSFORM_SETTING *setting);
void IkeSaSendPacket(IKE_SERVER *ike, IKE_SA *sa, IKE_PACKET *p);
IKE_PACKET *IkeSaRecvPacket(IKE_SERVER *ike, IKE_SA *sa, void *data, UINT size);
void IkeSendUdpPacket(IKE_SERVER *ike, UINT type, IP *server_ip, UINT server_port, IP *client_ip, UINT client_port, void *data, UINT size);
void IkeAddVendorIdPayloads(IKE_PACKET *p);
BUF *IkeStrToVendorId(char *str);
void IkeAddVendorId(IKE_PACKET *p, char *str);
bool IkeIsVendorIdExists(IKE_PACKET *p, char *str);
void IkeCheckCaps(IKE_CAPS *caps, IKE_PACKET *p);
BUF *IkeCalcNatDetectHash(IKE_SERVER *ike, IKE_HASH *hash, UINT64 initiator_cookie, UINT64 responder_cookie, IP *ip, UINT port);
void IkeCalcSaKeySet(IKE_SERVER *ike, IKE_SA *sa, char *secret);
IKE_CRYPTO_KEY *IkeNewCryptoKeyFromK(IKE_SERVER *ike, void *k, UINT k_size, IKE_HASH *h, IKE_CRYPTO *c, UINT crypto_key_size);
BUF *IkeExpandKeySize(IKE_HASH *h, void *k, UINT k_size, UINT target_size);
void IkeSaUpdateIv(IKE_SA *sa, void *iv, UINT iv_size);
IPSECSA *NewIPsecSa(IKE_SERVER *ike, IKE_CLIENT *c, IKE_SA *ike_sa, bool initiate, UINT message_id, bool server_to_client, void *iv, UINT spi, void *init_rand_data, UINT init_rand_size, void *res_rand_data, UINT res_rand_size, IPSEC_SA_TRANSFORM_SETTING *setting, void *shared_key_data, UINT shared_key_size);
void IkeCalcPhase2InitialIv(void *iv, IKE_SA *sa, UINT message_id);
bool GetBestTransformSettingForIPsecSa(IKE_SERVER *ike, IKE_PACKET *pr, IPSEC_SA_TRANSFORM_SETTING *setting, IP *server_ip);
bool TransformPayloadToTransformSettingForIPsecSa(IKE_SERVER *ike, IKE_PACKET_TRANSFORM_PAYLOAD *transform, IPSEC_SA_TRANSFORM_SETTING *setting, IP *server_ip);
IKE_PACKET_PAYLOAD *TransformSettingToTransformPayloadForIPsec(IKE_SERVER *ike, IPSEC_SA_TRANSFORM_SETTING *setting);
UINT GenerateNewIPsecSaSpi(IKE_SERVER *ike, UINT counterpart_spi);
IPSECSA *SearchClientToServerIPsecSaBySpi(IKE_SERVER *ike, UINT spi);
IPSECSA *SearchIPsecSaBySpi(IKE_SERVER *ike, IKE_CLIENT *c, UINT spi);
IPSECSA *SearchIPsecSaByMessageId(IKE_SERVER *ike, IKE_CLIENT *c, UINT message_id);
void IPsecSaSendPacket(IKE_SERVER *ike, IPSECSA *sa, IKE_PACKET *p);
IKE_PACKET *IPsecSaRecvPacket(IKE_SERVER *ike, IPSECSA *sa, void *data, UINT size);
void IPsecSaUpdateIv(IPSECSA *sa, void *iv, UINT iv_size);
void ProcDeletePayload(IKE_SERVER *ike, IKE_CLIENT *c, IKE_PACKET_DELETE_PAYLOAD *d);
void MarkIPsecSaAsDeleted(IKE_SERVER *ike, IPSECSA *sa);
void MarkIkeSaAsDeleted(IKE_SERVER *ike, IKE_SA *sa);
void PurgeDeletingSAsAndClients(IKE_SERVER *ike);
void PurgeIPsecSa(IKE_SERVER *ike, IPSECSA *sa);
void PurgeIkeSa(IKE_SERVER *ike, IKE_SA *sa);
void PurgeIkeClient(IKE_SERVER *ike, IKE_CLIENT *c);
void FreeIPsecSa(IPSECSA *sa);
void MarkIkeClientAsDeleted(IKE_SERVER *ike, IKE_CLIENT *c);
IKE_SA *GetOtherLatestIkeSa(IKE_SERVER *ike, IKE_SA *sa);
IPSECSA *GetOtherLatestIPsecSa(IKE_SERVER *ike, IPSECSA *sa);
void SendInformationalExchangePacket(IKE_SERVER *ike, IKE_CLIENT *c, IKE_PACKET_PAYLOAD *payload);
void SendInformationalExchangePacketEx(IKE_SERVER *ike, IKE_CLIENT *c, IKE_PACKET_PAYLOAD *payload, bool force_plain, UINT64 init_cookie, UINT64 resp_cookie);
void SendDeleteIkeSaPacket(IKE_SERVER *ike, IKE_CLIENT *c, UINT64 init_cookie, UINT64 resp_cookie);
void SendDeleteIPsecSaPacket(IKE_SERVER *ike, IKE_CLIENT *c, UINT spi);
void IPsecCalcKeymat(IKE_SERVER *ike, IKE_HASH *h, void *dst, UINT dst_size, void *skeyid_d_data, UINT skeyid_d_size, UCHAR protocol, UINT spi, void *rand_init_data, UINT rand_init_size,
					 void *rand_resp_data, UINT rand_resp_size, void *df_key_data, UINT df_key_size);

void ProcIPsecEspPacketRecv(IKE_SERVER *ike, UDPPACKET *p);
void ProcIPsecUdpPacketRecv(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size);
void IPsecSendPacketByIPsecSa(IKE_SERVER *ike, IPSECSA *sa, UCHAR *data, UINT data_size, UCHAR protocol_id);
void IPsecSendPacketByIPsecSaInner(IKE_SERVER *ike, IPSECSA *sa, UCHAR *data, UINT data_size, UCHAR protocol_id);
void IPsecSendPacketByIkeClient(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size, UCHAR protocol_id);
void IPsecSendUdpPacket(IKE_SERVER *ike, IKE_CLIENT *c, UINT src_port, UINT dst_port, UCHAR *data, UINT data_size);
void IPsecIkeClientManageL2TPServer(IKE_SERVER *ike, IKE_CLIENT *c);
void IPsecIkeClientSendL2TPPackets(IKE_SERVER *ike, IKE_CLIENT *c, L2TP_SERVER *l2tp);
void IPsecIkeSendUdpForDebug(UINT dst_port, UINT dst_ip, void *data, UINT size);
void StartQuickMode(IKE_SERVER *ike, IKE_CLIENT *c);
UINT GenerateNewMessageId(IKE_SERVER *ike);

void IPsecIkeClientManageEtherIPServer(IKE_SERVER *ike, IKE_CLIENT *c);
void IPsecIkeClientSendEtherIPPackets(IKE_SERVER *ike, IKE_CLIENT *c, ETHERIP_SERVER *s);
void ProcIPsecEtherIPPacketRecv(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size, bool is_tunnel_mode);
bool IsIPsecSaTunnelMode(IPSECSA *sa);
void ProcL2TPv3PacketRecv(IKE_SERVER *ike, IKE_CLIENT *c, UCHAR *data, UINT data_size, bool is_tunnel_mode);

IKE_SA *SearchIkeSaByCookie(IKE_SERVER *ike, UINT64 init_cookie, UINT64 resp_cookie);

#endif	// IPSEC_IKE_H


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
