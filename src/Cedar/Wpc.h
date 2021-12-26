// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Wpc.h
// Header of Wpc.c

#ifndef	WPC_H
#define	WPC_H

#include "Cedar.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/HTTP.h"

// Constant
#define WPC_HTTP_POST_NAME			"POST"		// POST
#define WPC_HTTP_GET_NAME			"GET"		// GET
#define WPC_USER_AGENT				DEFAULT_USER_AGENT	// User Agent
#define WPC_TIMEOUT					(15 * 1000)	// Time-out
#define WPC_RECV_BUF_SIZE			64000		// Receive buffer size
#define WPC_DATA_ENTRY_SIZE			4			// Data entry size
#define WPC_MAX_HTTP_DATASIZE		(134217728)	// Maximum HTTP data size

// Connection parameters
struct WPC_CONNECT
{
	char HostName[MAX_HOST_NAME_LEN + 1];					// Host name
	UINT Port;												// Port number
	UINT ProxyType;											// Type of proxy server
	char ProxyHostName[MAX_HOST_NAME_LEN + 1];				// Proxy server host name
	UINT ProxyPort;											// Proxy server port number
	char ProxyUsername[MAX_USERNAME_LEN + 1];				// Proxy server user name
	char ProxyPassword[MAX_USERNAME_LEN + 1];				// Proxy server password
	char CustomHttpHeader[HTTP_CUSTOM_HEADER_MAX_SIZE];		// Custom HTTP header
	bool UseCompress;										// Use of compression
	bool DontCheckCert;										// Do not check the certificate
};

// Internet connection settings
struct INTERNET_SETTING
{
	UINT ProxyType;											// Type of proxy server
	char ProxyHostName[MAX_HOST_NAME_LEN + 1];				// Proxy server host name
	UINT ProxyPort;											// Proxy server port number
	char ProxyUsername[MAX_USERNAME_LEN + 1];				// Proxy server user name
	char ProxyPassword[MAX_USERNAME_LEN + 1];				// Proxy server password
	char CustomHttpHeader[HTTP_CUSTOM_HEADER_MAX_SIZE];		// Custom HTTP header
};

// URL
struct URL_DATA
{
	bool Secure;							// Whether HTTPS
	char HostName[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT Port;								// Port number
	char HeaderHostName[MAX_HOST_NAME_LEN + 16];	// Host name on the header
	char Method[32];						// Method
	char Target[MAX_SIZE * 3];				// Target
	char Referer[MAX_SIZE * 3];				// Referer
	char AdditionalHeaderName[128];			// Additional header name
	char AdditionalHeaderValue[MAX_SIZE];	// Additional header value
	char SniString[MAX_SIZE];				// SNI String
};

// WPC entry
struct WPC_ENTRY
{
	char EntryName[WPC_DATA_ENTRY_SIZE];		// Entry name
	void *Data;									// Data
	UINT Size;									// Data size
};

// WPC packet
struct WPC_PACKET
{
	PACK *Pack;								// Pack (data body)
	UCHAR Hash[SHA1_SIZE];					// Data hash
	X *Cert;								// Certificate
	UCHAR Sign[128];						// Digital signature
};

// Reception callback
typedef bool (WPC_RECV_CALLBACK)(void *param, UINT total_size, UINT current_size, BUF *recv_buf);

// Function prototype
void Base64ToSafe64(char *str, const UINT size);
void Safe64ToBase64(char *str, const UINT size);
UINT DecodeSafe64(void *dst, const char *src, UINT size);
void EncodeSafe64(char *dst, const void *src, const UINT size);
bool ParseUrl(URL_DATA *data, char *str, bool is_post, char *referrer);
void CreateUrl(char *url, UINT url_size, URL_DATA *data);
void GetSystemInternetSetting(INTERNET_SETTING *setting);
bool GetProxyServerNameAndPortFromIeProxyRegStr(char *name, UINT name_size, UINT *port, char *str, char *server_type);
BUF *HttpRequest(URL_DATA *data, INTERNET_SETTING *setting,
				 UINT timeout_connect, UINT timeout_comm,
				 UINT *error_code, bool check_ssl_trust, char *post_data,
				 WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash);
BUF *HttpRequestEx(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size);
BUF *HttpRequestEx2(URL_DATA *data, INTERNET_SETTING *setting,
				   UINT timeout_connect, UINT timeout_comm,
				   UINT *error_code, bool check_ssl_trust, char *post_data,
				   WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash,
				   bool *cancel, UINT max_recv_size, char *header_name, char *header_value);
BUF *HttpRequestEx3(URL_DATA *data, INTERNET_SETTING *setting,
					UINT timeout_connect, UINT timeout_comm,
					UINT *error_code, bool check_ssl_trust, char *post_data,
					WPC_RECV_CALLBACK *recv_callback, void *recv_callback_param, void *sha1_cert_hash, UINT num_hashes,
					bool *cancel, UINT max_recv_size, char *header_name, char *header_value);
SOCK *WpcSockConnect(WPC_CONNECT *param, UINT *error_code, UINT timeout);
SOCK *WpcSockConnectEx(WPC_CONNECT *param, UINT *error_code, UINT timeout, bool *cancel);
SOCK *WpcSockConnect2(char *hostname, UINT port, INTERNET_SETTING *t, UINT *error_code, UINT timeout);
INTERNET_SETTING *GetNullInternetSetting();
void WpcAddDataEntry(BUF *b, char *name, void *data, UINT size);
void WpcAddDataEntryBin(BUF *b, char *name, void *data, UINT size);
void WpcFillEntryName(char *dst, char *name);
LIST *WpcParseDataEntry(BUF *b);
void WpcFreeDataEntryList(LIST *o);
WPC_ENTRY *WpcFindDataEntry(LIST *o, char *name);
BUF *WpcDataEntryToBuf(WPC_ENTRY *e);
BUF *WpcGeneratePacket(PACK *pack, X *cert, K *key);
bool WpcParsePacket(WPC_PACKET *packet, BUF *buf);
void WpcFreePacket(WPC_PACKET *packet);
PACK *WpcCall(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
			  char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash);
PACK *WpcCallEx(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
			  char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash, bool *cancel, UINT max_recv_size,
			  char *additional_header_name, char *additional_header_value);
PACK *WpcCallEx2(char *url, INTERNET_SETTING *setting, UINT timeout_connect, UINT timeout_comm,
				char *function_name, PACK *pack, X *cert, K *key, void *sha1_cert_hash, UINT num_hashes, bool *cancel, UINT max_recv_size,
				char *additional_header_name, char *additional_header_value, char *sni_string);
bool IsProxyPrivateIp(INTERNET_SETTING *s);

#endif	// WPC_H


