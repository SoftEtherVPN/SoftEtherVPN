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


// Protocol.h
// Header of Protocol.c

#ifndef	PROTOCOL_H
#define	PROTOCOL_H

// MIME types
struct HTTP_MIME_TYPE
{
	char *Extension;
	char *MimeType;
};

// The parameters that will be passed to the certificate confirmation thread
struct CHECK_CERT_THREAD_PROC
{
	CONNECTION *Connection;
	X *ServerX;
	CHECK_CERT_PROC *CheckCertProc;
	bool UserSelected;
	bool Exipred;
	bool Ok;
};

// The parameters that will be passed to the secure device signature thread
struct SECURE_SIGN_THREAD_PROC
{
	SECURE_SIGN_PROC *SecureSignProc;
	CONNECTION *Connection;
	SECURE_SIGN *SecureSign;
	bool UserFinished;
	bool Ok;
};

// Signature sending thread parameters
struct SEND_SIGNATURE_PARAM
{
	char Hostname[MAX_PATH];		// Host name
	UINT Port;						// Port number
	BUF *Buffer;					// Packet contents
};

// Software update client callback
typedef void (UPDATE_NOTIFY_PROC)(UPDATE_CLIENT *c, UINT latest_build, UINT64 latest_date, char *latest_ver, char *url, volatile bool *halt_flag, void *param);
typedef bool (UPDATE_ISFOREGROUND_PROC)(UPDATE_CLIENT *c, void *param);

// Configure the software update client
struct UPDATE_CLIENT_SETTING
{
	bool DisableCheck;				// Disable the update check
	UINT LatestIgnoreBuild;			// Ignore for earlier or identical to this build number
};

// Software update client
struct UPDATE_CLIENT
{
	char FamilyName[MAX_SIZE];		// Product family name
	char SoftwareName[MAX_SIZE];	// Software Name
	wchar_t SoftwareTitle[MAX_SIZE];	// Software display name
	char ClientId[128];				// Client ID
	UINT MyBuild;					// Build number of myself
	UINT64 MyDate;					// Build date of myself
	char MyLanguage[MAX_SIZE];		// My language
	UPDATE_CLIENT_SETTING Setting;	// Setting
	UINT LatestBuild;				// Latest build number that was successfully acquired
	volatile bool HaltFlag;			// Halting flag
	EVENT *HaltEvent;				// Halting event
	void *Param;					// Any parameters
	THREAD *Thread;					// Thread
	UPDATE_NOTIFY_PROC *Callback;	// Callback function
	UPDATE_ISFOREGROUND_PROC *IsForegroundCb;	// Callback function for retrieving whether foreground
};

//// Constant related to updating of the software

// Family
#define	UPDATE_FAMILY_NAME			_SS("PRODUCT_FAMILY_NAME")

// Software update server certificate hash
#define	UPDATE_SERVER_CERT_HASH		DDNS_CERT_HASH

// URL
#define	UPDATE_SERVER_URL_GLOBAL	"https://update-check.softether-network.net/update/update.aspx?family=%s&software=%s&mybuild=%u&lang=%s"
#define	UPDATE_SERVER_URL_CHINA		"https://update-check.uxcom.jp/update/update.aspx?family=%s&software=%s&mybuild=%u&lang=%s"

// Update check interval
#define	UPDATE_CHECK_INTERVAL_MIN		(12 * 3600 * 1000)
#define	UPDATE_CHECK_INTERVAL_MAX		(24 * 7200 * 1000)

// Connection parameters
#define	UPDATE_CONNECT_TIMEOUT			5000
#define	UPDATE_COMM_TIMEOUT				5000

// Dynamic root cert fetch function
#define	CERT_HTTP_DOWNLOAD_MAXSIZE	65536
#define	CERT_HTTP_DOWNLOAD_TIMEOUT	(10 * 1000)
#define	ROOT_CERTS_FILENAME			"|root_certs.dat"
#define	AUTO_DOWNLOAD_CERTS_PREFIX	L".autodownload_"
#define	FIND_CERT_CHAIN_MAX_DEPTH	16

#define	PROTO_SUPPRESS_CLIENT_UPDATE_NOTIFICATION_REGKEY	"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Client Update Notification"
#define	PROTO_SUPPRESS_CLIENT_UPDATE_NOTIFICATION_REGVALUE	"Suppress"

// WebSocket
struct WS
{
	SOCK *Sock;
	WSP *Wsp;
	REF *Ref;
	bool Disconnected;
	UINT MaxBufferSize;
	UCHAR TmpBuf[65536];
};

// WebSocket Protocol
struct WSP
{
	UINT MaxBufferSize;
	FIFO *PhysicalSendFifo;		// WSP -> Network
	FIFO *PhysicalRecvFifo;		// WSP <- Network
	FIFO *AppSendFifo;			// APP -> WSP
	FIFO *AppRecvFifo;			// APP <- WSP
	bool HasError;
};

// WebSocket constants
#define WS_MAX_PAYLOAD_LEN_PER_FRAME	(8 * 1024 * 1024)
#define WS_SEND_SINGLE_FRAGMENT_SIZE	(32 * 1024)

#define WS_OPCODE_CONTINUE		0x00
#define WS_OPCODE_TEXT			0x01
#define WS_OPCODE_BIN			0x02
#define WS_OPCODE_CLOSE			0x08
#define WS_OPCODE_PING			0x09
#define WS_OPCODE_PONG			0x0A

// MVPN constants
#define MVPN_VERSION_MIN			100
#define MVPN_VERSION_CURRENT		100
#define MVPN_MAX_AUTH_RETRY			10
#define	MVPN_CLIENT_NAME			"Modern VPN Client"
#define	NVPN_POSTFIX				"MVPN"

// MVPN protocol constants
#define MVPN_AUTHTYPE_ANONYMOUS				"anonymous"
#define MVPN_AUTHTYPE_PASSWORD_PLAIN		"password_plain"
#define MVPN_AUTHTYPE_PASSWORD_MSCHAPV2		"password_mschapv2"
#define MVPN_AUTHTYPE_CERT					"x509cert"

#define MVPN_HEARTBEAT_INTERVAL_DEFAULT		1234
#define	MVPN_HEARTBEAT_INTERVAL_MIN			100
#define	MVPN_HEARTBEAT_INTERVAL_MAX			15000

#define MVPN_DISCONNECT_TIMEOUT_DEFAULT		15000
#define MVPN_DISCONNECT_TIMEOUT_MIN			5000
#define MVPN_DISCONNECT_TIMEOUT_MAX			60000

#define MVPN_PACKET_MAGIC_NUMBER		0xCAFEBEEF
#define MVPN_PACKET_TYPE_ETHERNET		0
#define MVPN_PACKET_TYPE_IPV4			1
#define MVPN_PACKET_TYPE_HEARTBEAT		254

#define MVPN_ADDRESS_TYPE_STATIC		"static"
#define MVPN_ADDRESS_TYPE_DYNAMIC		"dynamic"



#define MVPN_AUTHTYPE_ALL_SUPPORTED			MVPN_AUTHTYPE_ANONYMOUS "," MVPN_AUTHTYPE_PASSWORD_PLAIN "," MVPN_AUTHTYPE_PASSWORD_MSCHAPV2 "," MVPN_AUTHTYPE_CERT





// Function prototype
UPDATE_CLIENT *NewUpdateClient(UPDATE_NOTIFY_PROC *cb, UPDATE_ISFOREGROUND_PROC *isforeground_cb, void *param, char *family_name, char *software_name, wchar_t *software_title, UINT my_build, UINT64 my_date, char *my_lang, UPDATE_CLIENT_SETTING *current_setting, char *client_id);
void FreeUpdateClient(UPDATE_CLIENT *c);
void UpdateClientThreadProc(THREAD *thread, void *param);
void UpdateClientThreadMain(UPDATE_CLIENT *c);
void UpdateClientThreadProcessResults(UPDATE_CLIENT *c, BUF *b);
void SetUpdateClientSetting(UPDATE_CLIENT *c, UPDATE_CLIENT_SETTING *s);
UINT64 ShortStrToDate64(char *str);


bool ServerAccept(CONNECTION *c);
bool ClientConnect(CONNECTION *c);
SOCK *ClientConnectToServer(CONNECTION *c);
SOCK *TcpIpConnect(char *hostname, UINT port, bool try_start_ssl, bool ssl_no_tls);
SOCK *TcpIpConnectEx(char *hostname, UINT port, bool *cancel_flag, void *hWnd, UINT *nat_t_error_code, bool no_nat_t, bool try_start_ssl, bool ssl_no_tls, IP *ret_ip);
bool ClientUploadSignature(SOCK *s);
bool ClientDownloadHello(CONNECTION *c, SOCK *s);
bool ServerDownloadSignature(CONNECTION *c, char **error_detail_str);
bool ServerUploadHello(CONNECTION *c);
bool ClientUploadAuth(CONNECTION *c);
SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect, bool no_tls);
SOCK *TcpConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, bool try_start_ssl, bool ssl_no_tls);
SOCK *TcpConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, bool no_nat_t, UINT *nat_t_error_code, bool try_start_ssl, bool ssl_no_tls, IP *ret_ip);

void InitProtocol();
void FreeProtocol();



POLICY *PackGetPolicy(PACK *p);
void PackAddPolicy(PACK *p, POLICY *y);
PACK *PackWelcome(SESSION *s);
PACK *PackHello(void *random, UINT ver, UINT build, char *server_str);
bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size);
PACK *PackLoginWithAnonymous(char *hubname, char *username);
PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password);
PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password);
PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size);
PACK *PackLoginWithOpenVPNCertificate(char *hubname, char *username, X *x);
bool GetMethodFromPack(PACK *p, char *method, UINT size);
bool GetHubnameAndUsernameFromPack(PACK *p, char *username, UINT username_size,
								   char *hubname, UINT hubname_size);
PACK *PackAdditionalConnect(UCHAR *session_key);
UINT GetAuthTypeFromPack(PACK *p);
UINT GetProtocolFromPack(PACK *p);
bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
						  char *connection_name, UINT connection_name_size,
						  POLICY **policy);


bool ClientAdditionalConnect(CONNECTION *c, THREAD *t);
SOCK *ClientAdditionalConnectToServer(CONNECTION *c);
bool ClientUploadAuth2(CONNECTION *c, SOCK *s);
bool GetSessionKeyFromPack(PACK *p, UCHAR *session_key, UINT *session_key_32);
void GenerateRC4KeyPair(RC4_KEY_PAIR *k);

SOCK *ProxyConnect(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, char *password, bool additional_connect);
SOCK *ProxyConnectEx(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
					 char *server_host_name, UINT server_port,
					 char *username, char *password, bool additional_connect,
					 bool *cancel_flag, void *hWnd);
SOCK *ProxyConnectEx2(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
					 char *server_host_name, UINT server_port,
					 char *username, char *password, bool additional_connect,
					 bool *cancel_flag, void *hWnd, UINT timeout);
SOCK *SocksConnect(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
				   char *server_host_name, UINT server_port,
				   char *username, bool additional_connect);
SOCK *SocksConnectEx(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
					 char *server_host_name, UINT server_port,
					 char *username, bool additional_connect,
					 bool *cancel_flag, void *hWnd);
SOCK *SocksConnectEx2(CONNECTION *c, char *proxy_host_name, UINT proxy_port,
					 char *server_host_name, UINT server_port,
					 char *username, bool additional_connect,
					 bool *cancel_flag, void *hWnd, UINT timeout, IP *ret_ip);
bool SocksSendRequestPacket(CONNECTION *c, SOCK *s, UINT dest_port, IP *dest_ip, char *userid);
bool SocksRecvResponsePacket(CONNECTION *c, SOCK *s);
void CreateNodeInfo(NODE_INFO *info, CONNECTION *c);
UINT SecureSign(SECURE_SIGN *sign, UINT device_id, char *pin);
void ClientUploadNoop(CONNECTION *c);
bool ClientCheckServerCert(CONNECTION *c, bool *expired);
void ClientCheckServerCertThread(THREAD *thread, void *param);
bool ClientSecureSign(CONNECTION *c, UCHAR *sign, UCHAR *random, X **x);
void ClientSecureSignThread(THREAD *thread, void *param);
UINT SecureWrite(UINT device_id, char *cert_name, X *x, char *key_name, K *k, char *pin);
UINT SecureEnum(UINT device_id, char *pin, TOKEN_LIST **cert_list, TOKEN_LIST **key_list);
UINT SecureDelete(UINT device_id, char *pin, char *cert_name, char *key_name);
TOKEN_LIST *EnumHub(SESSION *s);
UINT ChangePasswordAccept(CONNECTION *c, PACK *p);
UINT ChangePassword(CEDAR *cedar, CLIENT_OPTION *o, char *hubname, char *username, char *old_pass, char *new_pass);
void PackAddClientVersion(PACK *p, CONNECTION *c);
void NodeInfoToStr(wchar_t *str, UINT size, NODE_INFO *info);
void GenerateMachineUniqueHash(void *data);

LIST *NewCertList(bool load_root_and_chain);
void FreeCertList(LIST *o);
bool IsXInCertList(LIST *o, X *x);
void AddXToCertList(LIST *o, X *x);
void AddAllRootCertsToCertList(LIST *o);
void AddAllChainCertsToCertList(LIST *o);
X *DownloadCert(char *url);
X *FindCertIssuerFromCertList(LIST *o, X *x);
bool TryGetRootCertChain(LIST *o, X *x, bool auto_save, X **found_root_x);
bool TryGetParentCertFromCertList(LIST *o, X *x, LIST *found_chain);
bool DownloadAndSaveIntermediateCertificatesIfNecessary(X *x);
char *GetMimeTypeFromFileName(char *filename);

void MvpnProcGet(CONNECTION *c, SOCK *s, HTTP_HEADER *h, char *url_target);
bool MvpnSendReply(SOCK *s, UINT status_code, char *status_string, UCHAR *data, UINT data_size, char *content_type,
						char *add_header_name, char *add_header_value, HTTP_HEADER *request_headers);
void MvpnAccept(CONNECTION *c, SOCK *s);
UINT MvpnDoAccept(CONNECTION *c, WS *w);


WS *NewWs(SOCK *s);
void ReleaseWs(WS *w);
void CleanupWs(WS *w);
UINT WsRecvSync(WS *w, void *data, UINT size);
bool WsRecvSyncAll(WS *w, void *data, UINT size);
bool WsSendSync(WS *w, void *data, UINT size);
UINT WsRecvAsync(WS *w, void *data, UINT size);
UINT WsSendAsync(WS *w, void *data, UINT size);
bool WsTrySendAsync(WS *w);
PACK *WsRecvPack(WS *w);
bool WsSendPack(WS *w, PACK *p);
PACK *WsNewErrorPack(UINT err);
char *WsErrorCodeToString(UINT err);

WSP *NewWsp();
void FreeWsp(WSP *p);
void WspTry(WSP *p);
BLOCK *WspTryRecvNextFrame(WSP *p, UINT *read_buffer_size);
void WspTrySendFrame(WSP *p, UCHAR opcode, void *data, UINT size);




#endif	// PROTOCOL_H
