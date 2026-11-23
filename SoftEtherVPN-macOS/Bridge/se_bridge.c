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

// One running session. The handle the caller holds is Id, never this
// address: memory is reused, a number that only counts up is not, so a handle
// of an ended session can never come to mean a later one.
typedef struct SE_REC
{
	se_session Id;
	VLAN_ANDROID *V;
	void *Account;			// key of this session's slot in g_certs
	int FdCore;				// adapter's end of the packet socket pair
	int FdApp;				// provider's end
} SE_REC;

static CEDAR *g_cedar = NULL;

// Serializes every access that dereferences or frees the live session, so a
// status poll can never race the teardown
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static SE_REC *g_sessions[SE_MAX_SESSIONS];
static se_session g_next_id = 1;
static UINT g_teardowns = 0;			// se_disconnect calls past their unlink
static pthread_cond_t g_teardown_cond = PTHREAD_COND_INITIALIZER;
static bool g_shutting_down = false;

// The certificate each session's server offered when its connection attempt
// was refused, keyed by the session's ACCOUNT. Written by the core's
// certificate-check thread, which can run before se_connect returns and while
// se_disconnect waits for the session to end - hence a lock of its own, never
// held together with a wait for the core.
static pthread_mutex_t g_cert_lock = PTHREAD_MUTEX_INITIALIZER;
static struct
{
	void *Account;
	UCHAR *Cert;
	UINT Size;
} g_certs[SE_MAX_SESSIONS];

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

// Reserve the certificate slot of a new session's account
static bool SeCertSlotAdd(void *account)
{
	UINT i;
	bool ret = false;

	pthread_mutex_lock(&g_cert_lock);

	for (i = 0; i < SE_MAX_SESSIONS; i++)
	{
		if (g_certs[i].Account == NULL)
		{
			g_certs[i].Account = account;
			g_certs[i].Cert = NULL;
			g_certs[i].Size = 0;

			ret = true;
			break;
		}
	}

	pthread_mutex_unlock(&g_cert_lock);

	return ret;
}

static void SeCertSlotRemove(void *account)
{
	UINT i;

	if (account == NULL)
	{
		return;
	}

	pthread_mutex_lock(&g_cert_lock);

	for (i = 0; i < SE_MAX_SESSIONS; i++)
	{
		if (g_certs[i].Account == account)
		{
			if (g_certs[i].Cert != NULL)
			{
				Free(g_certs[i].Cert);
			}

			g_certs[i].Account = NULL;
			g_certs[i].Cert = NULL;
			g_certs[i].Size = 0;
		}
	}

	pthread_mutex_unlock(&g_cert_lock);
}

// CHECK_CERT_PROC: the core calls this when TLS verification of the server
// certificate failed. There is no dialog to show from here; the certificate is
// kept for the UI (se_get_offered_server_cert) and the attempt is refused. The
// UI pins the certificate in the profile if the user accepts it, and dials again.
static bool SeCheckCertProc(SESSION *s, CONNECTION *c, X *server_x, bool *expired)
{
	BUF *b;
	UINT i;

	if (expired != NULL)
	{
		*expired = false;
	}

	if (s == NULL || s->Account == NULL || server_x == NULL)
	{
		return false;
	}

	b = XToBuf(server_x, false);
	if (b != NULL)
	{
		pthread_mutex_lock(&g_cert_lock);

		for (i = 0; i < SE_MAX_SESSIONS; i++)
		{
			if (g_certs[i].Account == (void *)s->Account)
			{
				if (g_certs[i].Cert != NULL)
				{
					Free(g_certs[i].Cert);
				}

				g_certs[i].Cert = Clone(b->Buf, b->Size);
				g_certs[i].Size = b->Size;
				break;
			}
		}

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

// The live session of a handle, or NULL. Caller holds g_lock.
static SE_REC *SeFind(se_session id)
{
	UINT i;

	if (id == 0)
	{
		return NULL;
	}

	for (i = 0; i < SE_MAX_SESSIONS; i++)
	{
		if (g_sessions[i] != NULL && g_sessions[i]->Id == id)
		{
			return g_sessions[i];
		}
	}

	return NULL;
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

	pthread_mutex_lock(&g_lock);

	if (g_cedar != NULL)
	{
		pthread_mutex_unlock(&g_lock);

		return 1;
	}

	// The core keeps pointing at argv, hence static; written under the lock
	// because several tunnels can start at once in one process
	SeGetExePath(argv0, sizeof(argv0));

	if (argv0[0] == 0 || g_shutting_down)
	{
		pthread_mutex_unlock(&g_lock);

		return 0;
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
	UINT i;

	// No new session from here on
	pthread_mutex_lock(&g_lock);
	g_shutting_down = true;
	pthread_mutex_unlock(&g_lock);

	for (i = 0; i < SE_MAX_SESSIONS; i++)
	{
		se_session id;

		pthread_mutex_lock(&g_lock);
		id = (g_sessions[i] != NULL) ? g_sessions[i]->Id : 0;
		pthread_mutex_unlock(&g_lock);

		if (id != 0)
		{
			se_disconnect(id);
		}
	}

	pthread_mutex_lock(&g_lock);

	// A session another thread is tearing down right now is no longer in the
	// table, but still uses the core
	while (g_teardowns != 0)
	{
		pthread_cond_wait(&g_teardown_cond, &g_lock);
	}

	if (g_cedar != NULL)
	{
		ReleaseCedar(g_cedar);
		g_cedar = NULL;

		FreeCedar();
		FreeMayaqua();
	}

	g_shutting_down = false;

	pthread_mutex_unlock(&g_lock);
}

void se_core_version(char *dst, size_t dst_size)
{
	char ver[MAX_SIZE];

	ver[0] = 0;

	pthread_mutex_lock(&g_lock);

	if (g_cedar != NULL)
	{
		GetCedarVersion(ver, sizeof(ver));
	}

	pthread_mutex_unlock(&g_lock);

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
		if (p->password_hash != NULL)
		{
			Copy(au->HashedPassword, (void *)p->password_hash, SHA1_SIZE);
		}
		else
		{
			HashPassword(au->HashedPassword, au->Username, (char *)(p->password != NULL ? p->password : ""));
		}
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

se_session se_connect(const se_profile *p, char *err, size_t err_size)
{
	SE_REC *ss;
	se_session id;
	ACCOUNT *acc;
	CLIENT_OPTION option;
	CLIENT_AUTH auth;
	VLAN_ANDROID *v;
	SESSION *s;
	int fds[2];
	bool use_v4, use_v6;
	UINT slot;

	SeSetErr(err, err_size, "");

	if (p == NULL)
	{
		SeSetErr(err, err_size, "No profile.");

		return 0;
	}

	pthread_mutex_lock(&g_lock);

	if (g_cedar == NULL || g_shutting_down)
	{
		pthread_mutex_unlock(&g_lock);

		SeSetErr(err, err_size, "The VPN core is not initialized.");

		return 0;
	}

	for (slot = 0; slot < SE_MAX_SESSIONS; slot++)
	{
		if (g_sessions[slot] == NULL)
		{
			break;
		}
	}

	if (slot >= SE_MAX_SESSIONS)
	{
		pthread_mutex_unlock(&g_lock);

		SeSetErr(err, err_size, "Too many VPN sessions are running.");

		return 0;
	}

	use_v4 = p->use_ipv4 ? true : false;
	use_v6 = p->use_ipv6 ? true : false;

	if (use_v4 == false && use_v6 == false)
	{
		pthread_mutex_unlock(&g_lock);

		SeSetErr(err, err_size, "Both IPv4 and IPv6 are disabled.");

		return 0;
	}

	acc = SeNewAccount(p, err, err_size);
	if (acc == NULL)
	{
		pthread_mutex_unlock(&g_lock);

		return 0;
	}

	// Where the certificate-check procedure leaves the server's certificate
	// if this attempt is refused for it
	if (SeCertSlotAdd(acc) == false)
	{
		pthread_mutex_unlock(&g_lock);

		CiFreeAccount(acc);

		SeSetErr(err, err_size, "Too many VPN sessions are running.");

		return 0;
	}

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0)
	{
		pthread_mutex_unlock(&g_lock);

		SeCertSlotRemove(acc);
		CiFreeAccount(acc);

		SeSetErr(err, err_size, "Could not create the packet channel.");

		return 0;
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
		SeCertSlotRemove(acc);
		CiFreeAccount(acc);

		SeSetErr(err, err_size, "Could not create the virtual network adapter.");

		return 0;
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
		SeCertSlotRemove(acc);
		CiFreeAccount(acc);

		SeSetErr(err, err_size, "Could not start the VPN session.");

		return 0;
	}

	v->Session = s;

	// The session has its own copies now
	Zero(&option, sizeof(option));
	Zero(&auth, sizeof(auth));

	// NewClientSessionEx took a second reference for us (it is built with
	// SE_CLIENT_SESSION_EXTRA_REF): the client thread releases the first one
	// when the session ends, and ours keeps the object readable until
	// se_disconnect.
#ifndef SE_CLIENT_SESSION_EXTRA_REF
#error "the core must be built with SE_CLIENT_SESSION_EXTRA_REF"
#endif

	if (VLanAndroidStart(v) == false)
	{
		pthread_mutex_unlock(&g_lock);

		StopSession(s);
		ReleaseSession(s);

		v->Account = NULL;
		VLanAndroidFree(v);
		close(fds[0]);
		close(fds[1]);
		SeCertSlotRemove(acc);
		CiFreeAccount(acc);

		SeSetErr(err, err_size, "Could not start the virtual network adapter.");

		return 0;
	}

	ss = ZeroMalloc(sizeof(SE_REC));
	ss->Id = id = g_next_id++;
	ss->V = v;
	ss->Account = acc;
	ss->FdCore = fds[0];
	ss->FdApp = fds[1];

	g_sessions[slot] = ss;

	pthread_mutex_unlock(&g_lock);

	return id;
}

// Passwords and keys do not outlive the account in freed memory
static void SeWipeAccount(ACCOUNT *a)
{
	if (a->ClientOption != NULL)
	{
		Zero(a->ClientOption->ProxyPassword, sizeof(a->ClientOption->ProxyPassword));
	}

	if (a->ClientAuth != NULL)
	{
		Zero(a->ClientAuth->HashedPassword, sizeof(a->ClientAuth->HashedPassword));
		Zero(a->ClientAuth->PlainPassword, sizeof(a->ClientAuth->PlainPassword));
	}
}

static void SeTeardownDone(void)
{
	pthread_mutex_lock(&g_lock);
	g_teardowns--;
	pthread_cond_broadcast(&g_teardown_cond);
	pthread_mutex_unlock(&g_lock);
}

void se_disconnect(se_session id)
{
	SE_REC *ss;
	VLAN_ANDROID *v;
	SESSION *s;
	ACCOUNT *acc;
	UINT i;

	pthread_mutex_lock(&g_lock);

	// Idempotent: only the first call for a live session tears it down
	if ((ss = SeFind(id)) == NULL)
	{
		pthread_mutex_unlock(&g_lock);

		return;
	}

	for (i = 0; i < SE_MAX_SESSIONS; i++)
	{
		if (g_sessions[i] == ss)
		{
			g_sessions[i] = NULL;
		}
	}

	// se_shutdown waits for teardowns in flight before it frees the core
	g_teardowns++;

	pthread_mutex_unlock(&g_lock);

	// From here the handle is stale for every other caller, so the teardown
	// (which waits for the session's threads) does not block the status calls
	// of the other sessions
	v = ss->V;
	s = v->Session;
	acc = (ACCOUNT *)v->Account;

	// Wake a pending DHCP wait in the pump thread before touching the session
	VLanAndroidAbortDhcp(v);

	// 1. End the session; this waits for the session thread, and with it for
	//    the certificate-check thread that looks the account up.
	if (s != NULL)
	{
		StopSession(s);
	}

	// 2. Stop the adapter's own threads. They read the SESSION object until
	//    they are joined, so it has to stay allocated (and v->Session set)
	//    until this returns.
	VLanAndroidFree(v);

	// 3. Only now let go of the session and of what it pointed to.
	if (s != NULL)
	{
		ReleaseSession(s);
	}

	SeCertSlotRemove(acc);

	if (acc != NULL)
	{
		SeWipeAccount(acc);
		CiFreeAccount(acc);
	}

	close(ss->FdCore);
	close(ss->FdApp);

	Free(ss);

	SeTeardownDone();
}

int se_packet_fd(se_session id)
{
	SE_REC *ss;
	int fd = -1;

	pthread_mutex_lock(&g_lock);

	if ((ss = SeFind(id)) != NULL)
	{
		fd = ss->FdApp;
	}

	pthread_mutex_unlock(&g_lock);

	return fd;
}

// Caller holds g_lock
static int SeStatus(VLAN_ANDROID *v)
{
	SESSION *s = v->Session;

	if (s == NULL)
	{
		return SE_STATUS_DISCONNECTED;
	}

	// A session that has ended is disconnected, whatever the adapter made of
	// it: the adapter flags an error of its own when the session drops while
	// it is still waiting for DHCP, and that must not hide the session's error
	if (s->ForceStopFlag || s->Halt || s->ClientStatus == CLIENT_STATUS_IDLE)
	{
		return SE_STATUS_DISCONNECTED;
	}

	if (v->ErrorOccured)
	{
		return SE_STATUS_CONFIG_ERROR;
	}

	if (v->ConfigOk)
	{
		return SE_STATUS_CONNECTED;
	}

	return SE_STATUS_CONNECTING;
}

int se_get_status(se_session id)
{
	SE_REC *ss;
	int ret = SE_STATUS_DISCONNECTED;

	pthread_mutex_lock(&g_lock);

	if ((ss = SeFind(id)) != NULL)
	{
		ret = SeStatus(ss->V);
	}

	pthread_mutex_unlock(&g_lock);

	return ret;
}

int se_get_error(se_session id)
{
	SE_REC *ss;
	int ret = 0;

	pthread_mutex_lock(&g_lock);

	if ((ss = SeFind(id)) != NULL && ss->V->Session != NULL)
	{
		ret = (int)ss->V->Session->Err;
	}

	pthread_mutex_unlock(&g_lock);

	return ret;
}

void se_get_status_text(se_session id, char *dst, size_t dst_size)
{
	SE_REC *ss;
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

	if ((ss = SeFind(id)) != NULL && ss->V->Session != NULL)
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
			else if (v->ErrorOccured && v->ErrorMsg != NULL)
			{
				StrCpy(buf, sizeof(buf), v->ErrorMsg);
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

int se_get_ipv4_config(se_session id, se_ipv4_config *out)
{
	SE_REC *ss;
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

	// Only a complete configuration: the adapter's thread writes the fields one
	// by one and sets ConfigOk after the last
	if ((ss = SeFind(id)) != NULL && VLanAndroidIsConfigReady(ss->V) &&
		VLanAndroidGetIPv4Config(ss->V, &ip, &mask, &gw, &dns1, &dns2, NULL, NULL))
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

int se_get_ipv6_config(se_session id, se_ipv6_config *out)
{
	SE_REC *ss;
	IP addr, prefix, mask, router, dns;
	int ret = 0;

	if (out == NULL)
	{
		return 0;
	}

	memset(out, 0, sizeof(se_ipv6_config));

	pthread_mutex_lock(&g_lock);

	if ((ss = SeFind(id)) != NULL && VLanAndroidIsConfigReady(ss->V) &&
		VLanAndroidGetIPv6Config(ss->V, &addr, &prefix, &mask, &router, NULL, &dns, NULL))
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

int se_get_server_address(se_session id, char *dst, size_t dst_size)
{
	SE_REC *ss;
	char str[MAX_SIZE];
	int ret = 0;

	str[0] = 0;

	pthread_mutex_lock(&g_lock);

	if ((ss = SeFind(id)) != NULL && ss->V->Session != NULL)
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

int se_get_traffic(se_session id, se_traffic *out)
{
	SE_REC *ss;
	int ret = 0;

	if (out == NULL)
	{
		return 0;
	}

	memset(out, 0, sizeof(se_traffic));

	pthread_mutex_lock(&g_lock);

	if ((ss = SeFind(id)) != NULL && ss->V->Session != NULL)
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

size_t se_get_offered_server_cert(se_session id, uint8_t *buf, size_t buf_size, uint8_t *sha256)
{
	SE_REC *ss;
	void *account = NULL;
	size_t ret = 0;
	UINT i;

	pthread_mutex_lock(&g_lock);

	if ((ss = SeFind(id)) != NULL)
	{
		account = ss->Account;
	}

	pthread_mutex_unlock(&g_lock);

	if (account == NULL)
	{
		return 0;
	}

	pthread_mutex_lock(&g_cert_lock);

	for (i = 0; i < SE_MAX_SESSIONS; i++)
	{
		if (g_certs[i].Account == account && g_certs[i].Cert != NULL)
		{
			ret = g_certs[i].Size;

			if (buf != NULL && buf_size != 0)
			{
				memcpy(buf, g_certs[i].Cert, (ret < buf_size) ? ret : buf_size);
			}

			if (sha256 != NULL)
			{
				Sha2_256(sha256, g_certs[i].Cert, g_certs[i].Size);
			}

			break;
		}
	}

	pthread_mutex_unlock(&g_cert_lock);

	return ret;
}

// DER bytes of a certificate / private key into a fixed buffer; 0 if absent.
// *too_large is set when it exists but does not fit.
static size_t SeXToBlob(X *x, uint8_t *dst, size_t dst_size, bool *too_large)
{
	BUF *b;
	size_t ret = 0;

	if (x == NULL)
	{
		return 0;
	}

	b = XToBuf(x, false);
	if (b != NULL)
	{
		if (b->Size <= dst_size)
		{
			memcpy(dst, b->Buf, b->Size);
			ret = b->Size;
		}
		else
		{
			*too_large = true;
		}

		FreeBuf(b);
	}

	return ret;
}

static size_t SeKToBlob(K *k, uint8_t *dst, size_t dst_size, bool *too_large)
{
	BUF *b;
	size_t ret = 0;

	if (k == NULL)
	{
		return 0;
	}

	b = KToBuf(k, false, NULL);
	if (b != NULL)
	{
		if (b->Size <= dst_size)
		{
			memcpy(dst, b->Buf, b->Size);
			ret = b->Size;
		}
		else
		{
			*too_large = true;
		}

		Zero(b->Buf, b->Size);
		FreeBuf(b);
	}

	return ret;
}

int se_import_vpn_file(const uint8_t *data, size_t len, se_imported_profile *out,
	char *err, size_t err_size)
{
	RPC_CLIENT_CREATE_ACCOUNT *t;
	CLIENT_OPTION *o;
	CLIENT_AUTH *au;
	BUF *b;
	UCHAR zero_hash[SHA1_SIZE];
	bool too_large = false;

	SeSetErr(err, err_size, "");

	if (out == NULL)
	{
		return 0;
	}

	memset(out, 0, sizeof(se_imported_profile));

	if (data == NULL || len == 0 || len > 1024 * 1024)
	{
		SeSetErr(err, err_size, "The file is empty or too large.");

		return 0;
	}

	// The parser needs the core; hold it in place while it runs
	pthread_mutex_lock(&g_lock);

	if (g_cedar == NULL || g_shutting_down)
	{
		pthread_mutex_unlock(&g_lock);

		SeSetErr(err, err_size, "The VPN core is not initialized.");

		return 0;
	}

	b = MemToBuf((void *)data, (UINT)len);
	t = CiCfgToAccount(b);
	Zero(b->Buf, b->Size);
	FreeBuf(b);

	pthread_mutex_unlock(&g_lock);

	if (t == NULL || t->ClientOption == NULL || t->ClientAuth == NULL)
	{
		if (t != NULL)
		{
			CiFreeClientCreateAccount(t);
			Free(t);
		}

		SeSetErr(err, err_size, "This is not a SoftEther VPN connection setting file.");

		return 0;
	}

	o = t->ClientOption;
	au = t->ClientAuth;

	// UniToUtf8 does not terminate a result that fills the buffer
	UniToUtf8((BYTE *)out->name, sizeof(out->name) - 1, o->AccountName);
	StrCpy(out->host, sizeof(out->host), o->Hostname);
	out->port = (int)o->Port;
	StrCpy(out->hub, sizeof(out->hub), o->HubName);

	StrCpy(out->username, sizeof(out->username), au->Username);

	switch (au->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		out->auth_type = SE_AUTH_ANONYMOUS;
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		out->auth_type = SE_AUTH_PASSWORD;

		// An all-zero hash is an account exported without a saved password
		Zero(zero_hash, sizeof(zero_hash));
		if (Cmp(au->HashedPassword, zero_hash, SHA1_SIZE) != 0)
		{
			Copy(out->password_hash, au->HashedPassword, SHA1_SIZE);
			out->has_password_hash = 1;
		}
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		out->auth_type = SE_AUTH_PLAIN_PASSWORD;
		StrCpy(out->plain_password, sizeof(out->plain_password), au->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		out->auth_type = SE_AUTH_CERT;
		out->client_cert_len = SeXToBlob(au->ClientX, out->client_cert, sizeof(out->client_cert), &too_large);
		out->client_key_len = SeKToBlob(au->ClientK, out->client_key, sizeof(out->client_key), &too_large);
		break;

	default:
		out->auth_type = -1;
		break;
	}

	out->verify_server_cert = t->CheckServerCert ? 1 : 0;
	out->use_default_trust = t->AddDefaultCA ? 1 : 0;
	out->server_cert_len = SeXToBlob(t->ServerCert, out->server_cert, sizeof(out->server_cert), &too_large);

	out->max_connections = (int)o->MaxConnection;
	out->use_compress = o->UseCompress ? 1 : 0;
	out->disable_udp_acceleration = o->NoUdpAcceleration ? 1 : 0;

	switch (o->ProxyType)
	{
	case PROXY_HTTP:
		out->proxy_type = SE_PROXY_HTTP;
		break;
	case PROXY_SOCKS:
		out->proxy_type = SE_PROXY_SOCKS4;
		break;
	case PROXY_SOCKS5:
		out->proxy_type = SE_PROXY_SOCKS5;
		break;
	default:
		out->proxy_type = SE_PROXY_DIRECT;
		break;
	}

	StrCpy(out->proxy_host, sizeof(out->proxy_host), o->ProxyName);
	out->proxy_port = (int)o->ProxyPort;
	StrCpy(out->proxy_username, sizeof(out->proxy_username), o->ProxyUsername);
	StrCpy(out->proxy_password, sizeof(out->proxy_password), o->ProxyPassword);

	// The parsed account holds the same secrets
	Zero(au->HashedPassword, sizeof(au->HashedPassword));
	Zero(au->PlainPassword, sizeof(au->PlainPassword));
	Zero(o->ProxyPassword, sizeof(o->ProxyPassword));

	CiFreeClientCreateAccount(t);
	Free(t);

	if (too_large)
	{
		// Dropping a certificate silently would turn a pinned server into an
		// unpinned one, or a usable profile into one that fails at connect
		memset(out, 0, sizeof(se_imported_profile));

		SeSetErr(err, err_size, "A certificate or key in this file is too large for this app.");

		return 0;
	}

	return 1;
}
