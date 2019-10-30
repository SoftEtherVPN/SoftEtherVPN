#ifndef HTTP_H
#define HTTP_H

#define	DEFAULT_USER_AGENT	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0"
#define	DEFAULT_ACCEPT		"image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, application/msword, application/vnd.ms-powerpoint, application/vnd.ms-excel, */*"
#define	DEFAULT_ENCODING	"gzip, deflate"
#define	HTTP_CONTENT_TYPE	"text/html; charset=iso-8859-1"
#define	HTTP_CONTENT_TYPE2	"application/octet-stream"
#define	HTTP_CONTENT_TYPE3	"image/jpeg"
#define	HTTP_CONTENT_TYPE4	"text/html"
#define	HTTP_CONTENT_TYPE5	"message/rfc822"
#define	HTTP_KEEP_ALIVE		"timeout=15; max=19"
#define	HTTP_VPN_TARGET		"/vpnsvc/vpn.cgi"
#define	HTTP_VPN_TARGET2	"/vpnsvc/connect.cgi"
#define HTTP_VPN_TARGET_POSTDATA	"VPNCONNECT"
#define	HTTP_SAITAMA		"/saitama.jpg"
#define	HTTP_PICTURES		"/picture"
// Maximum size of the custom HTTP header
#define	HTTP_CUSTOM_HEADER_MAX_SIZE		1024
// Maximum size of a single line in the HTTP header
#define	HTTP_HEADER_LINE_MAX_SIZE		4096
// Maximum number of lines in the HTTP header
#define	HTTP_HEADER_MAX_LINES			128
// Maximum size of the user agent string
#define	HTTP_HEADER_USER_AGENT_MAX_SIZE	512
// Maximum size of the random number to be included in the PACK
#define	HTTP_PACK_RAND_SIZE_MAX			1000
// Maximum PACK size in the HTTP
#define	HTTP_PACK_MAX_SIZE				65536

// HTTP value
struct HTTP_VALUE
{
	char *Name;						// Name
	char *Data;						// Data
};

// HTTP header
struct HTTP_HEADER
{
	char *Method;					// Method
	char *Target;					// Target
	char *Version;					// Version
	LIST *ValueList;				// Value list
};

// MIME type
struct HTTP_MIME_TYPE
{
	char *Extension;
	char *MimeType;
};

char *GetMimeTypeFromFileName(char *filename);
void GetHttpDateStr(char *str, UINT size, UINT64 t);
void ReplaceUnsafeCharInHttpTarget(char *target);
HTTP_HEADER *NewHttpHeader(char *method, char *target, char *version);
HTTP_HEADER *NewHttpHeaderEx(char *method, char *target, char *version, bool no_sort);
void FreeHttpHeader(HTTP_HEADER *header);
HTTP_VALUE *NewHttpValue(char *name, char *data);
void FreeHttpValue(HTTP_VALUE *value);
int CompareHttpValue(void *p1, void *p2);
HTTP_VALUE *GetHttpValue(HTTP_HEADER *header, char *name);
void AddHttpValue(HTTP_HEADER *header, HTTP_VALUE *value);
bool AddHttpValueStr(HTTP_HEADER* header, char *string);
UINT GetContentLength(HTTP_HEADER *header);
bool PostHttp(SOCK *s, HTTP_HEADER *header, void *post_data, UINT post_size);
char *HttpHeaderToStr(HTTP_HEADER *header);
bool SendHttpHeader(SOCK *s, HTTP_HEADER *header);
HTTP_HEADER *RecvHttpHeader(SOCK *s);
bool HttpClientSend(SOCK *s, PACK *p);
PACK *HttpClientRecv(SOCK *s);
bool HttpServerSend(SOCK *s, PACK *p);
PACK *HttpServerRecv(SOCK *s);
PACK *HttpServerRecvEx(SOCK *s, UINT max_data_size);
bool HttpSendForbidden(SOCK *s, char *target, char *server_id);
bool HttpSendNotFound(SOCK *s, char *target);
bool HttpSendNotImplemented(SOCK *s, char *method, char *target, char *version);

#endif
