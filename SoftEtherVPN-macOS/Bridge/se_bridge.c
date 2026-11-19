// SoftEther VPN for macOS - plain-C bridge to the SoftEther core (see se_bridge.h)
//
// The session runs in-process on the core's own client code
// (NewClientSessionEx) with the L3 TUN packet adapter of
// src/Cedar/VLanAndroid.c, which converts the hub's Ethernet segment to raw IP
// (ARP, DHCP and IPv6 neighbor discovery in user space). The adapter's "TUN"
// is one end of a datagram socket pair; the other end is what the packet
// tunnel provider reads and writes.
//
// Portable POSIX on purpose: the same file builds on Linux, where
// Bridge/test exercises it against a real vpnserver.

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Kernel.h"

#include "Cedar/Cedar.h"
#include "Cedar/Account.h"
#include "Cedar/Connection.h"
#include "Cedar/Session.h"
#include "Cedar/Client.h"
#include "Cedar/VLanAndroid.h"

#include "se_bridge.h"

#define SE_DEF_PORT				443
#define SE_DEVICE_NAME			"SoftEtherVPN macOS"
#define SE_PACKET_SOCK_BUF		(1024 * 1024)
#define SE_MAX_CERT_SIZE		65536

struct se_session
{
	VLAN_ANDROID *V;
	int FdCore;				// adapter's end of the packet socket pair
	int FdApp;				// provider's end
};

static CEDAR *g_cedar = NULL;

// Serializes every access that dereferences or frees the live session, so a
// status poll can never race the teardown
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static se_session *g_session = NULL;

// The certificate the server offered on the last refused attempt. Written by
// the core's certificate-check thread, which can run before se_connect returns.
static pthread_mutex_t g_cert_lock = PTHREAD_MUTEX_INITIALIZER;
static UCHAR *g_offered_cert = NULL;
static UINT g_offered_cert_size = 0;

static void SeCopyStr(char *dst, size_t dst_size, const char *src)
{
	if (dst == NULL || dst_size == 0)
	{
		return;
	}

	StrCpy(dst, (UINT)dst_size, (char *)(src != NULL ? src : ""));
}

static void SeSetErr(char *err, size_t err_size, const char *text)
{
	SeCopyStr(err, err_size, text);
}

// DER or PEM, decided by content
static bool SeIsPem(const uint8_t *data, size_t len)
{
	return len >= 10 && memcmp(data, "-----BEGIN", 10) == 0;
}

static X *SeLoadX(const uint8_t *data, size_t len)
{
	BUF *b;
	X *x;

	if (data == NULL || len == 0 || len > SE_MAX_CERT_SIZE)
	{
		return NULL;
	}

	b = MemToBuf((void *)data, (UINT)len);
	x = BufToX(b, SeIsPem(data, len));
	FreeBuf(b);

	return x;
}

static K *SeLoadPrivateK(const uint8_t *data, size_t len)
{
	BUF *b;
	K *k;

	if (data == NULL || len == 0 || len > SE_MAX_CERT_SIZE)
	{
		return NULL;
	}

	b = MemToBuf((void *)data, (UINT)len);
	k = BufToK(b, true, SeIsPem(data, len), NULL);
	FreeBuf(b);

	return k;
}

static void SeClearOfferedCert(void)
{
	pthread_mutex_lock(&g_cert_lock);

	if (g_offered_cert != NULL)
	{
		Free(g_offered_cert);
		g_offered_cert = NULL;
	}
	g_offered_cert_size = 0;

	pthread_mutex_unlock(&g_cert_lock);
}

// CHECK_CERT_PROC: the core calls this when TLS verification of the server
// certificate failed. There is no dialog to show from here; the certificate is
// kept for the UI (se_get_offered_server_cert) and the attempt is refused. The
// UI pins the certificate in the profile if the user accepts it, and dials again.
static bool SeCheckCertProc(SESSION *s, CONNECTION *c, X *server_x, bool *expired)
{
	BUF *b;

	if (expired != NULL)
	{
		*expired = false;
	}

	if (server_x == NULL)
	{
		return false;
	}

	b = XToBuf(server_x, false);
	if (b != NULL)
	{
		pthread_mutex_lock(&g_cert_lock);

		if (g_offered_cert != NULL)
		{
			Free(g_offered_cert);
		}
		g_offered_cert = Clone(b->Buf, b->Size);
		g_offered_cert_size = b->Size;

		pthread_mutex_unlock(&g_cert_lock);

		FreeBuf(b);
	}

	return false;
}

static void SeErrToText(UINT err, char *dst, UINT dst_size)
{
	wchar_t *uni;
	UINT u8_size;
	char *u8;

	if (dst == NULL || dst_size == 0)
	{
		return;
	}

	dst[0] = 0;

	if (err == 0)
	{
		return;
	}

	uni = GetUniErrorStr(err);
	if (uni == NULL || *uni == 0)
	{
		Format(dst, dst_size, "Error %u", err);

		return;
	}

	u8_size = CalcUniToUtf8(uni) + 1;
	u8 = ZeroMalloc(u8_size);
	UniToUtf8((BYTE *)u8, u8_size, uni);
	StrCpy(dst, dst_size, u8);
	Free(u8);
}

// Caller holds g_lock
static bool SeIsLive(se_session *s)
{
	return s != NULL && s == g_session && s->V != NULL;
}

// Full path of the running executable. The core refuses to start unless
// argv[0] resolves to an existing file (Mayaqua.c), and a process hosted by
// launchd / the system extension machinery has no usable argv to pass along.
static void SeGetExePath(char *dst, size_t dst_size)
{
	dst[0] = 0;

#ifdef __APPLE__
	{
		uint32_t size = (uint32_t)dst_size;

		if (_NSGetExecutablePath(dst, &size) != 0)
		{
			dst[0] = 0;
		}
	}
#else	// __APPLE__
	{
		ssize_t n = readlink("/proc/self/exe", dst, dst_size - 1);

		dst[(n > 0) ? n : 0] = 0;
	}
#endif	// __APPLE__
}

int se_init(const char *hamcore_path, const char *temp_dir)
{
	static char argv0[MAX_PATH * 4];
	char *argv[] = { argv0 };

	SeGetExePath(argv0, sizeof(argv0));

	if (argv0[0] == 0)
	{
		return 0;
	}

	pthread_mutex_lock(&g_lock);

	if (g_cedar != NULL)
	{
		pthread_mutex_unlock(&g_lock);

		return 1;
	}

	if (hamcore_path != NULL && hamcore_path[0] != 0)
	{
		SetHamcorePath((char *)hamcore_path);
	}

	if (temp_dir != NULL && temp_dir[0] != 0)
	{
		setenv("TMPDIR", temp_dir, 1);
	}

	InitMayaqua(false, false, 1, argv);
	InitCedar();

	g_cedar = NewCedar(NULL, NULL);

	pthread_mutex_unlock(&g_lock);

	return g_cedar != NULL ? 1 : 0;
}

void se_shutdown(void)
{
	se_session *s;

	pthread_mutex_lock(&g_lock);
	s = g_session;
	pthread_mutex_unlock(&g_lock);

	if (s != NULL)
	{
		se_disconnect(s);
	}

	SeClearOfferedCert();

	pthread_mutex_lock(&g_lock);

	if (g_cedar != NULL)
	{
		ReleaseCedar(g_cedar);
		g_cedar = NULL;

		FreeCedar();
		FreeMayaqua();
	}

	pthread_mutex_unlock(&g_lock);
}

void se_core_version(char *dst, size_t dst_size)
{
	char ver[MAX_SIZE];

	ver[0] = 0;

	if (g_cedar != NULL)
	{
		GetCedarVersion(ver, sizeof(ver));
	}

	SeCopyStr(dst, dst_size, ver);
}

int se_add_trusted_ca(const uint8_t *cert, size_t len)
{
	X *x;
	int ret = 0;

	pthread_mutex_lock(&g_lock);

	if (g_cedar != NULL)
	{
		x = SeLoadX(cert, len);

		if (x != NULL)
		{
			AddCa(g_cedar, x);
			FreeX(x);

			ret = 1;
		}
	}

	pthread_mutex_unlock(&g_lock);

	return ret;
}

// Build the core's ACCOUNT from the profile. Returns NULL with a message.
static ACCOUNT *SeNewAccount(const se_profile *p, char *err, size_t err_size)
{
	ACCOUNT *a;
	CLIENT_OPTION *o;
	CLIENT_AUTH *au;

	if (p->host == NULL || p->host[0] == 0)
	{
		SeSetErr(err, err_size, "The server address is empty.");

		return NULL;
	}

	if (p->hub == NULL || p->hub[0] == 0)
	{
		SeSetErr(err, err_size, "The Virtual Hub name is empty.");

		return NULL;
	}

	if (p->auth_type != SE_AUTH_ANONYMOUS && (p->username == NULL || p->username[0] == 0))
	{
		SeSetErr(err, err_size, "The user name is empty.");

		return NULL;
	}

	a = ZeroMalloc(sizeof(ACCOUNT));
	a->lock = NewLock();
	a->ClientOption = o = ZeroMalloc(sizeof(CLIENT_OPTION));
	a->ClientAuth = au = ZeroMalloc(sizeof(CLIENT_AUTH));

	// Connection options
	StrToUni(o->AccountName, sizeof(o->AccountName), (char *)p->host);
	StrCpy(o->Hostname, sizeof(o->Hostname), (char *)p->host);
	o->Port = (p->port != 0) ? p->port : SE_DEF_PORT;
	StrCpy(o->HubName, sizeof(o->HubName), (char *)p->hub);
	StrCpy(o->DeviceName, sizeof(o->DeviceName), SE_DEVICE_NAME);

	o->MaxConnection = (p->max_connections > 0) ? (UINT)p->max_connections : 1;
	o->UseEncrypt = true;
	o->UseCompress = p->use_compress ? true : false;
	o->NoUdpAcceleration = p->disable_udp_acceleration ? true : false;
	o->AdditionalConnectionInterval = 1;

	// One connect / login attempt per session: the packet tunnel provider owns
	// reconnection, because each new session needs its interface settings
	// re-evaluated (same policy as the Android bridge)
	o->NumRetry = 0;
	o->RetryInterval = 0;

	switch (p->proxy_type)
	{
	case SE_PROXY_HTTP:
		o->ProxyType = PROXY_HTTP;
		break;
	case SE_PROXY_SOCKS4:
		o->ProxyType = PROXY_SOCKS;
		break;
	case SE_PROXY_SOCKS5:
		o->ProxyType = PROXY_SOCKS5;
		break;
	default:
		o->ProxyType = PROXY_DIRECT;
		break;
	}

	if (o->ProxyType != PROXY_DIRECT)
	{
		if (p->proxy_host == NULL || p->proxy_host[0] == 0 || p->proxy_port == 0)
		{
			SeSetErr(err, err_size, "The proxy server address or port is empty.");

			CiFreeAccount(a);

			return NULL;
		}

		StrCpy(o->ProxyName, sizeof(o->ProxyName), (char *)p->proxy_host);
		o->ProxyPort = p->proxy_port;

		if (p->proxy_username != NULL)
		{
			StrCpy(o->ProxyUsername, sizeof(o->ProxyUsername), (char *)p->proxy_username);
		}
		if (p->proxy_password != NULL)
		{
			StrCpy(o->ProxyPassword, sizeof(o->ProxyPassword), (char *)p->proxy_password);
		}
	}

	// Credentials
	if (p->username != NULL)
	{
		StrCpy(au->Username, sizeof(au->Username), (char *)p->username);
	}

	switch (p->auth_type)
	{
	case SE_AUTH_ANONYMOUS:
		au->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;
		break;

	case SE_AUTH_PASSWORD:
		au->AuthType = CLIENT_AUTHTYPE_PASSWORD;
		HashPassword(au->HashedPassword, au->Username, (char *)(p->password != NULL ? p->password : ""));
		break;

	case SE_AUTH_PLAIN_PASSWORD:
		au->AuthType = CLIENT_AUTHTYPE_PLAIN_PASSWORD;
		StrCpy(au->PlainPassword, sizeof(au->PlainPassword), (char *)(p->password != NULL ? p->password : ""));
		break;

	case SE_AUTH_CERT:
		au->AuthType = CLIENT_AUTHTYPE_CERT;
		au->ClientX = SeLoadX(p->client_cert, p->client_cert_len);
		au->ClientK = SeLoadPrivateK(p->client_key, p->client_key_len);

		if (au->ClientX == NULL || au->ClientK == NULL)
		{
			SeSetErr(err, err_size, "The client certificate or its private key could not be read.");

			CiFreeAccount(a);

			return NULL;
		}

		if (CheckXandK(au->ClientX, au->ClientK) == false)
		{
			SeSetErr(err, err_size, "The private key does not belong to the client certificate.");

			CiFreeAccount(a);

			return NULL;
		}
		break;

	default:
		SeSetErr(err, err_size, "Unsupported authentication type.");

		CiFreeAccount(a);

		return NULL;
	}

	au->CheckCertProc = SeCheckCertProc;

	// Server certificate policy
	a->CheckServerCert = p->verify_server_cert ? true : false;
	a->AddDefaultCA = p->use_default_trust ? true : false;
	a->RetryOnServerCert = false;

	if (p->pinned_server_cert != NULL && p->pinned_server_cert_len != 0)
	{
		a->ServerCert = SeLoadX(p->pinned_server_cert, p->pinned_server_cert_len);

		if (a->ServerCert == NULL)
		{
			SeSetErr(err, err_size, "The saved server certificate could not be read.");

			CiFreeAccount(a);

			return NULL;
		}
	}

	return a;
}

static void SeSetSockBuf(int fd)
{
	int size = SE_PACKET_SOCK_BUF;

	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
}

se_session *se_connect(const se_profile *p, char *err, size_t err_size)
{
	se_session *ss;
	ACCOUNT *acc;
	CLIENT_OPTION option;
	CLIENT_AUTH auth;
	VLAN_ANDROID *v;
	SESSION *s;
	int fds[2];
	bool use_v4, use_v6;

	SeSetErr(err, err_size, "");

	if (p == NULL)
	{
		SeSetErr(err, err_size, "No profile.");

		return NULL;
	}

	pthread_mutex_lock(&g_lock);

	if (g_cedar == NULL)
	{
		pthread_mutex_unlock(&g_lock);

		SeSetErr(err, err_size, "The VPN core is not initialized.");

		return NULL;
	}

	if (g_session != NULL)
	{
		pthread_mutex_unlock(&g_lock);

		SeSetErr(err, err_size, "A session is already running.");

		return NULL;
	}

	use_v4 = p->use_ipv4 ? true : false;
	use_v6 = p->use_ipv6 ? true : false;

	if (use_v4 == false && use_v6 == false)
	{
		pthread_mutex_unlock(&g_lock);

		SeSetErr(err, err_size, "Both IPv4 and IPv6 are disabled.");

		return NULL;
	}

	acc = SeNewAccount(p, err, err_size);
	if (acc == NULL)
	{
		pthread_mutex_unlock(&g_lock);

		return NULL;
	}

	SeClearOfferedCert();

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0)
	{
		pthread_mutex_unlock(&g_lock);

		CiFreeAccount(acc);

		SeSetErr(err, err_size, "Could not create the packet channel.");

		return NULL;
	}

	SeSetSockBuf(fds[0]);
	SeSetSockBuf(fds[1]);
	fcntl(fds[0], F_SETFD, FD_CLOEXEC);
	fcntl(fds[1], F_SETFD, FD_CLOEXEC);

	// The inner MAC is resolved before the adapter exists: VLanAndroidNew hands
	// it straight to the IPC engine
	v = VLanAndroidNew(g_cedar, (UCHAR *)p->mac_address);
	if (v == NULL)
	{
		pthread_mutex_unlock(&g_lock);

		close(fds[0]);
		close(fds[1]);
		CiFreeAccount(acc);

		SeSetErr(err, err_size, "Could not create the virtual network adapter.");

		return NULL;
	}

	VLanAndroidSetIPv4Enabled(v, use_v4);
	VLanAndroidSetIPv6Enabled(v, use_v6);
	VLanAndroidSetTunFd(v, fds[0]);

	// The account is the client's own state: the core enables TLS peer
	// verification from it and clones the client certificate while connecting
	v->Account = acc;

	option = *acc->ClientOption;
	auth = *acc->ClientAuth;

	s = NewClientSessionEx(g_cedar, &option, &auth, VLanAndroidGetPacketAdapter(v), acc);
	if (s == NULL)
	{
		pthread_mutex_unlock(&g_lock);

		v->Account = NULL;
		VLanAndroidFree(v);
		close(fds[0]);
		close(fds[1]);
		CiFreeAccount(acc);

		SeSetErr(err, err_size, "Could not start the VPN session.");

		return NULL;
	}

	v->Session = s;

	// The account-ownership reference of the desktop connection protocol: the
	// client thread releases one session reference when the session halts, so
	// take it here to keep se_disconnect's ReleaseSession the last one
	AddRef(s->ref);

	if (VLanAndroidStart(v) == false)
	{
		pthread_mutex_unlock(&g_lock);

		StopSession(s);
		ReleaseSession(s);

		v->Account = NULL;
		VLanAndroidFree(v);
		close(fds[0]);
		close(fds[1]);
		CiFreeAccount(acc);

		SeSetErr(err, err_size, "Could not start the virtual network adapter.");

		return NULL;
	}

	ss = ZeroMalloc(sizeof(se_session));
	ss->V = v;
	ss->FdCore = fds[0];
	ss->FdApp = fds[1];

	g_session = ss;

	pthread_mutex_unlock(&g_lock);

	return ss;
}

void se_disconnect(se_session *ss)
{
	VLAN_ANDROID *v;

	pthread_mutex_lock(&g_lock);

	// Idempotent: only the first call for the live session tears it down
	if (SeIsLive(ss) == false)
	{
		pthread_mutex_unlock(&g_lock);

		return;
	}

	g_session = NULL;
	v = ss->V;

	// Wake a pending DHCP wait in the pump thread before touching the session
	VLanAndroidAbortDhcp(v);

	if (v->Session != NULL)
	{
		StopSession(v->Session);
		ReleaseSession(v->Session);
		v->Session = NULL;
	}

	// Safe after ReleaseSession joined the session thread
	if (v->Account != NULL)
	{
		CiFreeAccount((ACCOUNT *)v->Account);
		v->Account = NULL;
	}

	VLanAndroidFree(v);

	close(ss->FdCore);
	close(ss->FdApp);

	Free(ss);

	pthread_mutex_unlock(&g_lock);
}

int se_packet_fd(se_session *ss)
{
	int fd = -1;

	pthread_mutex_lock(&g_lock);

	if (SeIsLive(ss))
	{
		fd = ss->FdApp;
	}

	pthread_mutex_unlock(&g_lock);

	return fd;
}

// Caller holds g_lock and has checked SeIsLive
static int SeStatus(VLAN_ANDROID *v)
{
	SESSION *s = v->Session;

	if (s == NULL)
	{
		return SE_STATUS_DISCONNECTED;
	}

	if (v->ErrorOccured)
	{
		return SE_STATUS_CONFIG_ERROR;
	}

	if (s->ForceStopFlag || s->Halt || s->ClientStatus == CLIENT_STATUS_IDLE)
	{
		return SE_STATUS_DISCONNECTED;
	}

	if (v->ConfigOk)
	{
		return SE_STATUS_CONNECTED;
	}

	return SE_STATUS_CONNECTING;
}

int se_get_status(se_session *ss)
{
	int ret = SE_STATUS_DISCONNECTED;

	pthread_mutex_lock(&g_lock);

	if (SeIsLive(ss))
	{
		ret = SeStatus(ss->V);
	}

	pthread_mutex_unlock(&g_lock);

	return ret;
}

int se_get_error(se_session *ss)
{
	int ret = 0;

	pthread_mutex_lock(&g_lock);

	if (SeIsLive(ss) && ss->V->Session != NULL)
	{
		ret = (int)ss->V->Session->Err;
	}

	pthread_mutex_unlock(&g_lock);

	return ret;
}

void se_get_status_text(se_session *ss, char *dst, size_t dst_size)
{
	char buf[MAX_SIZE];
	char tmp[MAX_SIZE];
	VLAN_ANDROID *v;
	SESSION *s;

	if (dst == NULL || dst_size == 0)
	{
		return;
	}

	StrCpy(buf, sizeof(buf), "Disconnected.");

	pthread_mutex_lock(&g_lock);

	if (SeIsLive(ss) && ss->V->Session != NULL)
	{
		v = ss->V;
		s = v->Session;

		switch (SeStatus(v))
		{
		case SE_STATUS_CONFIG_ERROR:
			StrCpy(buf, sizeof(buf), (v->ErrorMsg != NULL) ? v->ErrorMsg :
				"The network configuration could not be obtained from the VPN.");
			break;

		case SE_STATUS_DISCONNECTED:
			if (s->Err != 0)
			{
				SeErrToText(s->Err, tmp, sizeof(tmp));
				Format(buf, sizeof(buf), "%s (%u)", tmp, s->Err);
			}
			break;

		case SE_STATUS_CONNECTED:
			StrCpy(buf, sizeof(buf), "Connected.");
			break;

		default:
			switch (s->ClientStatus)
			{
			case CLIENT_STATUS_NEGOTIATION:
				StrCpy(buf, sizeof(buf), "Negotiating with the server...");
				break;
			case CLIENT_STATUS_AUTH:
				StrCpy(buf, sizeof(buf), "Authenticating...");
				break;
			case CLIENT_STATUS_ESTABLISHED:
				StrCpy(buf, sizeof(buf), "Obtaining the network configuration...");
				break;
			default:
				StrCpy(buf, sizeof(buf), "Connecting to the server...");
				break;
			}
			break;
		}
	}

	pthread_mutex_unlock(&g_lock);

	SeCopyStr(dst, dst_size, buf);
}

static void SeIPv4ToStr(char *dst, UINT dst_size, IP *ip)
{
	dst[0] = 0;

	if (IsZeroIP(ip) == false)
	{
		IPToStr(dst, dst_size, ip);
	}
}

static void SeIPv6ToStr(char *dst, UINT dst_size, IP *ip)
{
	IPV6_ADDR a6;

	dst[0] = 0;

	if (IsZeroIP(ip) == false && IPToIPv6Addr(&a6, ip))
	{
		IP6AddrToStr(dst, dst_size, &a6);
	}
}

int se_get_ipv4_config(se_session *ss, se_ipv4_config *out)
{
	IP ip, mask, gw, dns1, dns2;
	DHCP_CLASSLESS_ROUTE_TABLE routes;
	UINT i;
	int ret = 0;

	if (out == NULL)
	{
		return 0;
	}

	memset(out, 0, sizeof(se_ipv4_config));
	Zero(&routes, sizeof(routes));

	pthread_mutex_lock(&g_lock);

	if (SeIsLive(ss) && VLanAndroidGetIPv4Config(ss->V, &ip, &mask, &gw, &dns1, &dns2, NULL, NULL))
	{
		SeIPv4ToStr(out->address, sizeof(out->address), &ip);
		SeIPv4ToStr(out->mask, sizeof(out->mask), &mask);
		SeIPv4ToStr(out->gateway, sizeof(out->gateway), &gw);
		SeIPv4ToStr(out->dns1, sizeof(out->dns1), &dns1);
		SeIPv4ToStr(out->dns2, sizeof(out->dns2), &dns2);

		VLanAndroidGetDomainName(ss->V, out->domain, sizeof(out->domain));
		VLanAndroidGetClasslessRoutes(ss->V, &routes);

		ret = 1;
	}

	pthread_mutex_unlock(&g_lock);

	if (ret)
	{
		for (i = 0; i < MAX_DHCP_CLASSLESS_ROUTE_ENTRIES && out->num_routes < SE_MAX_ROUTES; i++)
		{
			DHCP_CLASSLESS_ROUTE *e = &routes.Entries[i];
			se_route *r;

			if (e->Exists == false)
			{
				continue;
			}

			r = &out->routes[out->num_routes++];

			IPToStr(r->network, sizeof(r->network), &e->Network);
			r->prefix_len = (int)e->SubnetMaskLen;
			SeIPv4ToStr(r->gateway, sizeof(r->gateway), &e->Gateway);
		}
	}

	return ret;
}

int se_get_ipv6_config(se_session *ss, se_ipv6_config *out)
{
	IP addr, prefix, mask, router, dns;
	int ret = 0;

	if (out == NULL)
	{
		return 0;
	}

	memset(out, 0, sizeof(se_ipv6_config));

	pthread_mutex_lock(&g_lock);

	if (SeIsLive(ss) && VLanAndroidGetIPv6Config(ss->V, &addr, &prefix, &mask, &router, NULL, &dns, NULL))
	{
		SeIPv6ToStr(out->address, sizeof(out->address), &addr);
		SeIPv6ToStr(out->router, sizeof(out->router), &router);
		SeIPv6ToStr(out->prefix, sizeof(out->prefix), &prefix);
		SeIPv6ToStr(out->dns, sizeof(out->dns), &dns);

		if (IsZeroIP(&mask) == false)
		{
			out->prefix_len = (int)SubnetMaskToInt6(&mask);
		}

		ret = 1;
	}

	pthread_mutex_unlock(&g_lock);

	return ret;
}

int se_get_server_address(se_session *ss, char *dst, size_t dst_size)
{
	char str[MAX_SIZE];
	int ret = 0;

	str[0] = 0;

	pthread_mutex_lock(&g_lock);

	if (SeIsLive(ss) && ss->V->Session != NULL)
	{
		SESSION *s = ss->V->Session;

		Lock(s->lock);

		// Set once the first TCP connection of the session is made
		if (IsZeroIP(&s->ServerIP) == false)
		{
			IPToStr(str, sizeof(str), &s->ServerIP);

			ret = 1;
		}

		Unlock(s->lock);
	}

	pthread_mutex_unlock(&g_lock);

	SeCopyStr(dst, dst_size, str);

	return ret;
}

int se_get_traffic(se_session *ss, se_traffic *out)
{
	int ret = 0;

	if (out == NULL)
	{
		return 0;
	}

	memset(out, 0, sizeof(se_traffic));

	pthread_mutex_lock(&g_lock);

	if (SeIsLive(ss) && ss->V->Session != NULL)
	{
		SESSION *s = ss->V->Session;

		Lock(s->lock);
		out->bytes_sent = s->TotalSendSizeReal;
		out->bytes_received = s->TotalRecvSizeReal;
		Unlock(s->lock);

		ret = 1;
	}

	pthread_mutex_unlock(&g_lock);

	return ret;
}

size_t se_get_offered_server_cert(uint8_t *buf, size_t buf_size, uint8_t *sha256)
{
	size_t ret;

	pthread_mutex_lock(&g_cert_lock);

	ret = g_offered_cert_size;

	if (ret != 0)
	{
		if (buf != NULL && buf_size != 0)
		{
			memcpy(buf, g_offered_cert, (ret < buf_size) ? ret : buf_size);
		}

		if (sha256 != NULL)
		{
			Sha2_256(sha256, g_offered_cert, g_offered_cert_size);
		}
	}

	pthread_mutex_unlock(&g_cert_lock);

	return ret;
}
