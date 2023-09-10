// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Protocol.h
// Header of Protocol.c

#ifndef	PROTOCOL_H
#define	PROTOCOL_H

#include "Connection.h"

// The parameters that will be passed to the certificate confirmation thread
struct CHECK_CERT_THREAD_PROC
{
	CONNECTION *Connection;
	X *ServerX;
	CHECK_CERT_PROC *CheckCertProc;
	bool UserSelected;
	bool Expired;
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
SOCK *TcpIpConnectEx(char *hostname, UINT port, bool *cancel_flag, void *hWnd, UINT *nat_t_error_code, bool no_nat_t, bool try_start_ssl, IP *ret_ip);
SOCK *TcpIpConnectEx2(char *hostname, UINT port, bool *cancel_flag, void *hWnd, UINT *nat_t_error_code, bool no_nat_t, bool try_start_ssl, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err, char *hint_str, IP *ret_ip);

// New function named with prefix "Bind" binds outgoing connection to a specific address. New one is wrapped in original one.
SOCK* BindTcpIpConnectEx(IP *localIP, UINT localport, char *hostname, UINT port, bool *cancel_flag, void *hWnd, UINT *nat_t_error_code, bool no_nat_t, bool try_start_ssl, IP *ret_ip);
SOCK* BindTcpIpConnectEx2(IP *localIP, UINT localport, char *hostname, UINT port, bool *cancel_flag, void *hWnd, UINT *nat_t_error_code, bool no_nat_t, bool try_start_ssl, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err, char *hint_str, IP *ret_ip);

bool ClientUploadSignature(SOCK *s);
bool ClientDownloadHello(CONNECTION *c, SOCK *s);
bool ServerDownloadSignature(CONNECTION *c, char **error_detail_str);
bool ServerUploadHello(CONNECTION *c);
bool ClientUploadAuth(CONNECTION *c);
SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect);
SOCK *TcpConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, bool no_nat_t, UINT *nat_t_error_code, bool try_start_ssl, IP *ret_ip);
SOCK *TcpConnectEx4(char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, bool no_nat_t, UINT *nat_t_error_code, bool try_start_ssl, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err, char *hint_str, IP *ret_ip);

// New function named with prefix "Bind" binds outgoing connection to a specific address. New one is wrapped in original one.
SOCK* BindTcpConnectEx3(IP *localIP, UINT localport, char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, bool no_nat_t, UINT *nat_t_error_code, bool try_start_ssl, IP *ret_ip);
SOCK* BindTcpConnectEx4(IP *localIP, UINT localport, char *hostname, UINT port, UINT timeout, bool *cancel_flag, void *hWnd, bool no_nat_t, UINT *nat_t_error_code, bool try_start_ssl, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err, char *hint_str, IP *ret_ip);

UINT ProxyCodeToCedar(UINT code);

void InitProtocol();
void FreeProtocol();

POLICY *PackGetPolicy(PACK *p);
void PackAddPolicy(PACK *p, POLICY *y);
PACK *PackWelcome(SESSION *s);
PACK *PackHello(void *random, UINT ver, UINT build, char *server_str);
bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size);
PACK *PackLoginWithExternal(char *hubname, char *username);
PACK *PackLoginWithAnonymous(char *hubname, char *username);
PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password);
PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password);
PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size);
PACK *PackLoginWithWireGuardKey(char *key);
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

void CreateNodeInfo(NODE_INFO *info, CONNECTION *c);
UINT SecureSign(SECURE_SIGN *sign, UINT device_id, char *pin);
void ClientUploadNoop(CONNECTION *c);
bool ClientCheckServerCert(CONNECTION *c, bool *expired);
void ClientCheckServerCertThread(THREAD *thread, void *param);
bool ClientSecureSign(CONNECTION *c, UCHAR *sign, UCHAR *random, X **x);
void ClientSecureSignThread(THREAD *thread, void *param);
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

#endif	// PROTOCOL_H
