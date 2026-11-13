// SoftEther VPN for Android - JNI shim
// Drives CEDAR + the VLanAndroid packet adapter from the VpnService.

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include <jni.h>

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
#include "Mayaqua/Cfg.h"

#include "Cedar/Cedar.h"
#include "Cedar/Account.h"
#include "Cedar/Connection.h"
#include "Cedar/Session.h"
#include "Cedar/Client.h"
#include "Cedar/VLanAndroid.h"

#include "se_cfg.h"

#define DEF_PORT				5555
#define DEF_RETRY				3
#define DEF_RETRY_INTERVAL		(10 * 1000)

// Connection status (mirrored in Kotlin SeNative)
#define STATUS_CONNECTING		0
#define STATUS_CONFIG_OK		1
#define STATUS_CONFIG_ERROR		2
#define STATUS_DISCONNECTED		3

static CEDAR *cedar = NULL;

// The live connection object. All accesses that dereference or free it are
// serialized on g_lock so a UI-thread status poll can never race a
// disconnect teardown.
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static VLAN_ANDROID *g_v = NULL;

// Paths supplied from the Java layer before nativeInit()
static char g_hamcore_path[MAX_SIZE] = "";
static char g_tmp_dir[MAX_SIZE] = "";

// Get a malloc'ed UTF-8 copy of a jstring ("" for NULL)
static char *SeGetStr(JNIEnv *env, jstring s)
{
	const char *p;
	char *ret;

	if (s == NULL)
	{
		return CopyStr("");
	}

	p = (*env)->GetStringUTFChars(env, s, NULL);
	ret = CopyStr((char *)p);
	(*env)->ReleaseStringUTFChars(env, s, p);

	return ret;
}

static jstring SeNewStringTake(JNIEnv *env, char *text)
{
	jstring ret = (*env)->NewStringUTF(env, (text != NULL) ? text : "");

	Free(text);

	return ret;
}

JNIEXPORT jstring JNICALL
Java_org_softether_android_SeNative_nativeCfgDefault(JNIEnv *env, jobject thiz, jstring name_j)
{
	FOLDER *root, *db, *acc, *fo, *fa, *ao;
	CLIENT_OPTION o;
	CLIENT_AUTH a;
	char *name = SeGetStr(env, name_j);
	char *text;

	root = CfgCreateFolder(NULL, TAG_ROOT);
	db = CfgCreateFolder(root, "AccountDatabase");
	acc = CfgCreateFolder(db, "Account0");
	fo = CfgCreateFolder(acc, "ClientOption");
	fa = CfgCreateFolder(acc, "ClientAuth");
	ao = CfgCreateFolder(acc, "AndroidOptions");

	Zero(&o, sizeof(o));
	Zero(&a, sizeof(a));

	{
		wchar_t uni[MAX_SIZE];
		StrToUni(uni, sizeof(uni), name);
		UniStrCpy(o.AccountName, sizeof(o.AccountName), uni);
	}

	StrCpy(o.HubName, sizeof(o.HubName), "CUPAYAM");
	o.Port = DEF_PORT;
	o.MaxConnection = 1;
	o.UseEncrypt = true;
	o.HalfConnection = true;
	o.NoRoutingTracking = true;
	o.NumRetry = DEF_RETRY;
	o.RetryInterval = DEF_RETRY_INTERVAL;
	StrCpy(o.DeviceName, sizeof(o.DeviceName), "SoftEtherVPN Android");

	a.AuthType = CLIENT_AUTHTYPE_ANONYMOUS;

	CiWriteClientOption(fo, &o);
	CiWriteClientAuth(fa, &a);

	CfgAddBool(acc, "StartupAccount", false);
	CfgAddBool(acc, "CheckServerCert", false);
	CfgAddBool(acc, "RetryOnServerCert", false);
	CfgAddBool(acc, "AddDefaultCA", false);

	// Android-only options in their own folder (never inside the native
	// ClientOption, which upstream parsers ignore anyway)
	CfgAddBool(ao, "UseIPv4", true);
	CfgAddBool(ao, "UseIPv6", false);
	CfgAddStr(ao, "IPv4Mode", "dhcp");
	CfgAddStr(ao, "IPv6Mode", "ra");

	text = SeCfgRootToText(root);

	CfgDeleteFolder(root);
	Free(name);

	return SeNewStringTake(env, text);
}

JNIEXPORT jobjectArray JNICALL
Java_org_softether_android_SeNative_nativeCfgParse(JNIEnv *env, jobject thiz, jstring cfg_j)
{
	char *text = SeGetStr(env, cfg_j);
	FOLDER *root;
	char **arr = NULL;
	UINT num = 0, alloc = 0;
	jobjectArray ret;
	UINT i;

	root = SeCfgTextToRoot(text);
	Free(text);

	if (root == NULL)
	{
		return NULL;
	}

	SeCfgPushTriple(&arr, &num, &alloc, "", "root", root->Name);
	SeCfgFlatten(root, "", &arr, &num, &alloc);

	CfgDeleteFolder(root);

	ret = (*env)->NewObjectArray(env, num, (*env)->FindClass(env, "java/lang/String"), NULL);
	if (ret == NULL)
	{
		for (i = 0; i < num; i++)
		{
			Free(arr[i]);
		}
		Free(arr);

		return NULL;
	}

	for (i = 0; i < num; i++)
	{
		jstring js = (*env)->NewStringUTF(env, arr[i]);

		(*env)->SetObjectArrayElement(env, ret, i, js);
		(*env)->DeleteLocalRef(env, js);
	}

	for (i = 0; i < num; i++)
	{
		Free(arr[i]);
	}
	Free(arr);

	return ret;
}

JNIEXPORT jstring JNICALL
Java_org_softether_android_SeNative_nativeCfgCompose(JNIEnv *env, jobject thiz, jobjectArray triples)
{
	int n = (triples != NULL) ? (*env)->GetArrayLength(env, triples) : 0;
	char **t;
	FOLDER *root;
	char *text;
	jstring ret;
	int i;

	if (n == 0)
	{
		return (*env)->NewStringUTF(env, "");
	}

	t = ZeroMalloc(sizeof(char *) * n);

	for (i = 0; i < n; i++)
	{
		jstring e = (*env)->GetObjectArrayElement(env, triples, i);
		char *s = SeGetStr(env, e);

		(*env)->DeleteLocalRef(env, e);
		t[i] = s;
	}

	root = SeCfgFromTriples(t, n);
	text = SeCfgRootToText(root);

	if (root != NULL)
	{
		CfgDeleteFolder(root);
	}

	for (i = 0; i < n; i++)
	{
		Free(t[i]);
	}
	Free(t);

	ret = (*env)->NewStringUTF(env, (text != NULL) ? text : "");
	Free(text);

	return ret;
}

JNIEXPORT jstring JNICALL
Java_org_softether_android_SeNative_nativeHashPassword(JNIEnv *env, jobject thiz, jstring user_j, jstring pass_j)
{
	char *user = SeGetStr(env, user_j);
	char *pass = SeGetStr(env, pass_j);
	UCHAR hash[SHA1_SIZE];
	char *b64;
	jstring ret;

	HashPassword(hash, user, pass);

	b64 = Base64FromBin(NULL, hash, SHA1_SIZE);

	ret = (*env)->NewStringUTF(env, (b64 != NULL) ? b64 : "");

	Free(user);
	Free(pass);

	return ret;
}

JNIEXPORT jstring JNICALL
Java_org_softether_android_SeNative_nativeEncryptPassword(JNIEnv *env, jobject thiz, jstring pass_j)
{
	char *pass = SeGetStr(env, pass_j);
	BUF *b = EncryptPassword(pass);
	char *b64 = (b->Size > 0) ? (char *)Base64FromBin(NULL, b->Buf, b->Size) : NULL;
	jstring ret = (*env)->NewStringUTF(env, (b64 != NULL) ? b64 : "0");

	FreeBuf(b);
	Free(pass);

	return ret;
}

JNIEXPORT jstring JNICALL
Java_org_softether_android_SeNative_nativeDecryptPassword(JNIEnv *env, jobject thiz, jstring b64_j)
{
	char *b64 = SeGetStr(env, b64_j);
	BUF *b = NewBuf();
	UINT size = 0;
	void *bin = Base64ToBin(&size, b64, StrLen(b64));
	char *plain;
	jstring ret;

	if (bin != NULL && size > 0)
	{
		WriteBuf(b, bin, size);
		SeekBuf(b, 0, 0);
	}

	plain = DecryptPassword(b);

	ret = (*env)->NewStringUTF(env, (plain != NULL) ? plain : "");

	Free(plain);
	FreeBuf(b);
	Free(bin);
	Free(b64);

	return ret;
}

static void SeErrToText(UINT err, char *dst, UINT dst_size)
{
	wchar_t *uni;
	char *u8;

	if (err == 0 || dst == NULL || dst_size == 0)
	{
		*dst = 0;

		return;
	}

	uni = GetUniErrorStr(err);
	if (uni == NULL || *uni == 0)
	{
		Format(dst, dst_size, "Error %u", err);

		return;
	}

	u8 = Malloc(CalcUniToUtf8(uni) + 1);
	u8[0] = 0;
	UniToUtf8((BYTE *)u8, CalcUniToUtf8(uni) + 1, uni);
	StrCpy(dst, dst_size, u8);
	Free(u8);
}

static jstring GetStatusText(JNIEnv *env, VLAN_ANDROID *v, SESSION *s)
{
	char buf[MAX_SIZE];
	char tmp[MAX_SIZE];
	char status[MAX_SIZE];
	char *txt;

	buf[0] = 0;
	status[0] = 0;

	if (v != NULL && v->ErrorMsg != NULL)
	{
		txt = v->ErrorMsg;
	}
	else if (s == NULL)
	{
		txt = "Disconnected.";
	}
	else if (s->Halt || s->ForceStopFlag || s->ClientStatus == CLIENT_STATUS_IDLE)
	{
		if (s->Err != 0)
		{
			SeErrToText(s->Err, tmp, sizeof(tmp));
			Format(buf, sizeof(buf), "Disconnected: %s (%u)", tmp, s->Err);
		}
		else
		{
			StrCpy(buf, sizeof(buf), "Disconnected.");
		}

		txt = buf;
	}
	else if (v != NULL && v->ConfigOk)
	{
		txt = "Connected.";
	}
	else if (v != NULL && v->Ipv6Configuring)
	{
		// The IPv6 router-advertisement window is open (running in parallel
		// with the IPv4 DHCP acquisition when IPv4 is enabled)
		if (v->Ipv4Enabled)
		{
			StrCpy(buf, sizeof(buf), "Applying IPv4/IPv6 configuration (DHCP and router advertisement)...");
		}
		else
		{
			StrCpy(buf, sizeof(buf), "Applying IPv6 configuration (waiting for router advertisement)...");
		}

		txt = buf;
	}
	else
	{
		switch (s->ClientStatus)
		{
		case CLIENT_STATUS_NEGOTIATION:
			StrCpy(status, sizeof(status), "Negotiating with the server...");
			break;
		case CLIENT_STATUS_AUTH:
			StrCpy(status, sizeof(status), "Authenticating...");
			break;
		case CLIENT_STATUS_ESTABLISHED:
			StrCpy(status, sizeof(status), "Applying IPv4 configuration...");
			break;
		case CLIENT_STATUS_RETRY:
			Format(status, sizeof(status), "Reconnecting (retry %u/%u)...", s->CurrentRetryCount + 1,
				(s->ClientOption != NULL) ? s->ClientOption->NumRetry : 0);
			break;
		default:
			StrCpy(status, sizeof(status), "Connecting to the server...");
			break;
		}

		if (s->Err != 0)
		{
			SeErrToText(s->Err, tmp, sizeof(tmp));
			Format(buf, sizeof(buf), "%s  [last error: %s (%u)]", status, tmp, s->Err);
		}
		else
		{
			StrCpy(buf, sizeof(buf), status);
		}

		txt = buf;
	}

	return (*env)->NewStringUTF(env, txt);
}

JNIEXPORT void JNICALL
Java_org_softether_android_SeNative_nativeInit(JNIEnv *env, jobject thiz)
{
	char *argv0 = "softether-android";
	char *argv[] = { argv0 };

	if (cedar != NULL)
	{
		return;
	}

	Debug("init: begin");

	if (g_hamcore_path[0] != 0)
	{
		SetHamcorePath(g_hamcore_path);
	}
	if (g_tmp_dir[0] != 0)
	{
		setenv("TMPDIR", g_tmp_dir, 1);
	}

#ifdef SE_DEBUG_LOG
	InitMayaqua(false, true, 1, argv);
#else	// SE_DEBUG_LOG
	InitMayaqua(false, false, 1, argv);
#endif	// SE_DEBUG_LOG
	Debug("init: mayaqua done");

	InitCedar();
	Debug("init: cedar done");

	cedar = NewCedar(NULL, NULL);
	Debug("init: newcedar done");
}

JNIEXPORT void JNICALL
Java_org_softether_android_SeNative_nativeRelease(JNIEnv *env, jobject thiz)
{
	if (cedar == NULL)
	{
		return;
	}

	ReleaseCedar(cedar);
	cedar = NULL;

	FreeCedar();
	FreeMayaqua();
}

// Add one DER-encoded X.509 certificate to Cedar's trusted CA list; the anchors
// come from the Android system trust store (incl. user-imported CAs) harvested
// by the Java layer. Returns 1 on success.
JNIEXPORT jint JNICALL
Java_org_softether_android_SeNative_nativeAddCaCert(JNIEnv *env, jobject thiz, jbyteArray der)
{
	jsize len;
	jbyte *p;
	BUF *b;
	X *x;

	if (cedar == NULL || der == NULL)
	{
		return 0;
	}

	len = (*env)->GetArrayLength(env, der);
	if (len <= 0 || len > 65536)
	{
		return 0;
	}

	p = (*env)->GetByteArrayElements(env, der, NULL);
	b = MemToBuf(p, len);
	(*env)->ReleaseByteArrayElements(env, der, p, JNI_ABORT);

	if (b == NULL)
	{
		return 0;
	}

	x = BufToX(b, false);
	FreeBuf(b);

	if (x == NULL)
	{
		return 0;
	}

	AddCa(cedar, x);
	FreeX(x);

	return 1;
}

JNIEXPORT jlong JNICALL
Java_org_softether_android_SeNative_nativeConnect(JNIEnv *env, jobject thiz, jstring cfg_j)
{
	char *cfg;
	CLIENT_OPTION option;
	CLIENT_AUTH auth;
	VLAN_ANDROID *v;
	SESSION *s;
	bool dhcp = true;
	bool use_v4 = true, use_v6 = false;
	bool v6_static = false;
	IP sip, smask, sgw, sdns1, sdns2;
	IP v6ip, s6_mask, s6_gw, s6_dns;
	ACCOUNT *acc = NULL;

	if (cedar == NULL || cfg_j == NULL)
	{
		return 0;
	}

	{
		int ulen = (*env)->GetStringUTFLength(env, cfg_j);
		jsize clen = (*env)->GetStringLength(env, cfg_j);

		if (ulen < 0 || ulen > 1024 * 1024)
		{
			return 0;
		}

		cfg = Malloc(ulen + 1);
		cfg[0] = 0;

		// GetStringUTFRegion takes the length in UTF-16 code units and always
		// NUL-terminates; ulen bytes is exactly the modified-UTF-8 size.
		(*env)->GetStringUTFRegion(env, cfg_j, 0, clen, cfg);
		cfg[ulen] = 0;
	}

	Zero(&option, sizeof(option));
	Zero(&auth, sizeof(auth));

	Zero(&sip, sizeof(IP));
	Zero(&smask, sizeof(IP));
	Zero(&sgw, sizeof(IP));
	Zero(&sdns1, sizeof(IP));
	Zero(&sdns2, sizeof(IP));
	Zero(&v6ip, sizeof(IP));
	Zero(&s6_mask, sizeof(IP));
	Zero(&s6_gw, sizeof(IP));
	Zero(&s6_dns, sizeof(IP));

	{
		SE_NETCFG n;

		// The profile text is always a SoftEther account CFG ("declare root"),
		// loaded by the core's own account reader: the connection options and
		// the credentials (password, plain password or client certificate) come
		// from the profile itself, never from a bridge-side re-interpretation.
		if (!SeCfgLoadAccount(cfg, &acc, &n))
		{
			Debug("connect: CFG account text required");

			Free(cfg);

			return 0;
		}

		option = *acc->ClientOption;
		auth = *acc->ClientAuth;

		dhcp = n.dhcp;
		use_v4 = n.use_v4;
		use_v6 = n.use_v6;
		v6_static = n.v6_static;
		sip = n.ip;
		smask = n.mask;
		sgw = n.gw;
		sdns1 = n.dns1;
		sdns2 = n.dns2;
		v6ip = n.v6ip;
		s6_mask = n.s6_mask;
		s6_gw = n.s6_gw;
		s6_dns = n.s6_dns;

		// Android-side essentials: this bridge owns the virtual NIC name, and a
		// profile is not required to carry these values.
		StrCpy(option.DeviceName, sizeof(option.DeviceName), "SoftEtherVPN Android");

		if (IsEmptyStr(option.HubName))
		{
			StrCpy(option.HubName, sizeof(option.HubName), "SERVERVPN");
		}
		if (option.Port == 0)
		{
			option.Port = DEF_PORT;
		}
		if (option.MaxConnection == 0)
		{
			option.MaxConnection = 1;
		}
		if (option.NumRetry == 0)
		{
			option.NumRetry = DEF_RETRY;
			option.RetryInterval = DEF_RETRY_INTERVAL;
		}
	}

	Free(cfg);

	// Android-bridge policy (this file only; Cedar/Session core is untouched):
	// Kotlin (VpnEngine worker loop) owns all connection retries and applies the
	// profile's NumRetry/RetryInterval itself, so the C session performs exactly
	// one connect/login attempt per session.
	option.NumRetry = 0;

	Debug("connect: %s:%u hub=%s user=%s authtype=%u enc=%s cmp=%s dhcp=%s v4=%s v6=%s mode6=%s cert=%s pinned=%s",
		option.Hostname, option.Port,
		option.HubName, auth.Username, auth.AuthType, option.UseEncrypt ? "true" : "false",
		option.UseCompress ? "true" : "false", dhcp ? "true" : "false",
		use_v4 ? "true" : "false", use_v6 ? "true" : "false",
		use_v6 ? (v6_static ? "static" : "ra") : "-",
		acc->CheckServerCert ? "true" : "false", acc->ServerCert != NULL ? "true" : "false");

	if (option.Hostname[0] == 0)
	{
		CiFreeAccount(acc);

		return 0;
	}

	v = VLanAndroidNew(cedar);
	if (v == NULL)
	{
		Debug("connect: vlan new failed");

		CiFreeAccount(acc);

		return 0;
	}

	if (!dhcp)
	{
		VLanAndroidSetStaticIPv4(v, &sip, &smask, &sgw,
			IsZeroIP(&sdns1) ? NULL : &sdns1,
			IsZeroIP(&sdns2) ? NULL : &sdns2);
	}

	VLanAndroidSetIPv4Enabled(v, use_v4);
	VLanAndroidSetIPv6Enabled(v, use_v6);

	if (use_v6 && v6_static)
	{
		VLanAndroidSetStaticIPv6(v, &v6ip, &s6_mask,
			IsZeroIP(&s6_gw) ? NULL : &s6_gw,
			IsZeroIP(&s6_dns) ? NULL : &s6_dns);
	}

	// The account is the client's own state, not a cert-checking special case:
	// the C core enables TLS peer verification from Account->CheckServerCert and
	// pins Account->ServerCert (the desktop TOFU anchor) through it (Session.c
	// NewSessionX), and it owns the client certificate/key that the session
	// clones while connecting.
	v->Account = acc;

	s = NewClientSessionEx(cedar, &option, &auth, VLanAndroidGetPacketAdapter(v), acc);

	if (s == NULL)
	{
		Debug("connect: session failed");

		CiFreeAccount(acc);
		v->Account = NULL;

		VLanAndroidFree(v);

		return 0;
	}
	v->Session = s;

	// The account-ownership reference of the desktop connection protocol:
	// NewSessionX only stores the account pointer, and ClientThread releases
	// the account-owned session reference when the session halts. Taking it
	// here keeps the reference balance so that the disconnect-side
	// ReleaseSession is the last one (double-free otherwise).
	AddRef(s->ref);

	if (!VLanAndroidStart(v))
	{
		Debug("connect: vlan start failed");

		StopSession(s);
		ReleaseSession(s);

		CiFreeAccount(acc);
		v->Account = NULL;

		VLanAndroidFree(v);

		return 0;
	}
	pthread_mutex_lock(&g_lock);
	g_v = v;
	pthread_mutex_unlock(&g_lock);

	return (jlong)v;
}

JNIEXPORT jint JNICALL
Java_org_softether_android_SeNative_nativeGetStatus(JNIEnv *env, jobject thiz, jlong handle)
{
	VLAN_ANDROID *v = (VLAN_ANDROID *)handle;
	int ret;

	if (v == NULL)
	{
		return STATUS_DISCONNECTED;
	}

	pthread_mutex_lock(&g_lock);

	if (v != g_v || v->Session == NULL)
	{
		pthread_mutex_unlock(&g_lock);

		return STATUS_DISCONNECTED;
	}

	if (v->ErrorOccured)
	{
		ret = STATUS_CONFIG_ERROR;
	}
	else if (v->Session->ForceStopFlag || v->Session->Halt ||
		v->Session->ClientStatus == CLIENT_STATUS_IDLE)
	{
		ret = STATUS_DISCONNECTED;
	}
	else if (v->ConfigOk)
	{
		ret = STATUS_CONFIG_OK;
	}
	else
	{
		ret = STATUS_CONNECTING;
	}

	pthread_mutex_unlock(&g_lock);

	return ret;
}

JNIEXPORT jstring JNICALL
Java_org_softether_android_SeNative_nativeGetCoreVersion(JNIEnv *env, jobject thiz)
{
	char ver[MAX_SIZE];

	// SoftEther core version ("major.minor.build") for the app title bar
	GetCedarVersion(ver, sizeof(ver));

	return (*env)->NewStringUTF(env, ver);
}

JNIEXPORT jstring JNICALL
Java_org_softether_android_SeNative_nativeGetStatusText(JNIEnv *env, jobject thiz, jlong handle)
{
	VLAN_ANDROID *v = (VLAN_ANDROID *)handle;
	jstring ret;

	pthread_mutex_lock(&g_lock);

	if (v == NULL || v != g_v)
	{
		pthread_mutex_unlock(&g_lock);

		return (*env)->NewStringUTF(env, "Disconnected.");
	}

	ret = GetStatusText(env, v, v->Session);

	pthread_mutex_unlock(&g_lock);

	return ret;
}

JNIEXPORT jobjectArray JNICALL
Java_org_softether_android_SeNative_nativeGetIPv4Info(JNIEnv *env, jobject thiz, jlong handle)
{
	VLAN_ANDROID *v = (VLAN_ANDROID *)handle;
	IP ip, mask, gw, dns1, dns2;
	DHCP_CLASSLESS_ROUTE_TABLE routes;
	char routes_str[MAX_DHCP_CLASSLESS_ROUTE_TABLE_STR_SIZE];
	jobjectArray ret;
	IP *src[5];
	int i;

	if (v == NULL)
	{
		return NULL;
	}

	pthread_mutex_lock(&g_lock);

	if (v != g_v || !VLanAndroidGetIPv4Config(v, &ip, &mask, &gw, &dns1, &dns2))
	{
		pthread_mutex_unlock(&g_lock);

		return NULL;
	}

	routes = v->ClasslessRoute;

	pthread_mutex_unlock(&g_lock);

	// Serialize the DHCP classless static routes (option 121) as
	// "dest/prefixlen@gateway;..." entries for the Kotlin VPN builder
	routes_str[0] = 0;

	for (i = 0; i < (int)routes.NumExistingRoutes; i++)
	{
		DHCP_CLASSLESS_ROUTE *e = &routes.Entries[i];
		char nstr[MAX_SIZE], gstr[MAX_SIZE], line[MAX_SIZE];

		if (!e->Exists)
		{
			continue;
		}

		nstr[0] = 0;
		gstr[0] = 0;

		IPToStr(nstr, sizeof(nstr), &e->Network);

		if (!IsZeroIP(&e->Gateway))
		{
			IPToStr(gstr, sizeof(gstr), &e->Gateway);
		}

		Format(line, sizeof(line), "%s/%u@%s;", nstr, e->SubnetMaskLen, gstr);
		StrCat(routes_str, sizeof(routes_str), line);
	}

	ret = (*env)->NewObjectArray(env, 6, (*env)->FindClass(env, "java/lang/String"), NULL);
	if (ret == NULL)
	{
		return NULL;
	}

	src[0] = &ip;
	src[1] = &mask;
	src[2] = &gw;
	src[3] = &dns1;
	src[4] = &dns2;

	for (i = 0; i < 5; i++)
	{
		char str[MAX_SIZE];

		str[0] = 0;

		if (!IsZeroIP(src[i]))
		{
			IPToStr(str, sizeof(str), src[i]);
		}

		jstring js = (*env)->NewStringUTF(env, str);

		(*env)->SetObjectArrayElement(env, ret, i, js);
		(*env)->DeleteLocalRef(env, js);
	}

	{
		jstring js = (*env)->NewStringUTF(env, routes_str);

		(*env)->SetObjectArrayElement(env, ret, 5, js);
		(*env)->DeleteLocalRef(env, js);
	}

	return ret;
}

// Get the effective IPv6 configuration of the running session;
// returns {client address, prefix length, router, routed prefix, DNS}
// as strings (empty when unset; prefix length as a decimal string), or
// NULL while no configuration is available yet (no RA learned, or IPv6
// disabled for this profile)
JNIEXPORT jobjectArray JNICALL
Java_org_softether_android_SeNative_nativeGetIPv6Config(JNIEnv *env, jobject thiz, jlong handle)
{
	VLAN_ANDROID *v = (VLAN_ANDROID *)handle;
	IP addr, prefix, mask, router, dns;
	jobjectArray ret;
	IP *src[5];
	int i;

	if (v == NULL)
	{
		return NULL;
	}

	pthread_mutex_lock(&g_lock);

	if (v != g_v || !VLanAndroidGetIPv6Config(v, &addr, &prefix, &mask, &router, &dns))
	{
		pthread_mutex_unlock(&g_lock);

		return NULL;
	}

	pthread_mutex_unlock(&g_lock);

	ret = (*env)->NewObjectArray(env, 5, (*env)->FindClass(env, "java/lang/String"), NULL);
	if (ret == NULL)
	{
		return NULL;
	}

	src[0] = &addr;
	src[1] = &mask;
	src[2] = &router;
	src[3] = &prefix;
	src[4] = &dns;

	for (i = 0; i < 5; i++)
	{
		char str[MAX_SIZE];
		IPV6_ADDR a6;
		jstring js;

		str[0] = 0;

		if (i == 1)
		{
			// Prefix length of the routed/static mask, as a decimal string
			if (!IsZeroIP(&mask))
			{
				IP mask_copy;

				CopyIP(&mask_copy, &mask);

				snprintf(str, sizeof(str), "%u", SubnetMaskToInt6(&mask_copy));
			}
		}
		else if (!IsZeroIP(src[i]))
		{
			if (IPToIPv6Addr(&a6, src[i]))
			{
				IP6AddrToStr(str, sizeof(str), &a6);
			}
		}

		js = (*env)->NewStringUTF(env, str);

		(*env)->SetObjectArrayElement(env, ret, i, js);
		(*env)->DeleteLocalRef(env, js);
	}

	return ret;
}

JNIEXPORT void JNICALL
Java_org_softether_android_SeNative_nativeSetTunFd(JNIEnv *env, jobject thiz, jlong handle, jint fd)
{
	Debug("set tun fd: %d", fd);

	VLanAndroidSetTunFd((VLAN_ANDROID *)handle, fd);
}

static char *SeGetPathString(JNIEnv *env, jstring s, char *buf, unsigned int buf_size)
{
	int len;

	buf[0] = 0;
	if (s == NULL)
		return buf;

	len = (*env)->GetStringUTFLength(env, s);
	if (len < 0)
		return buf;
	if (len > (int)buf_size - 1)
		len = buf_size - 1;

	(*env)->GetStringUTFRegion(env, s, 0, len, buf);
	buf[len] = 0;

	return buf;
}

JNIEXPORT void JNICALL
Java_org_softether_android_SeNative_nativeSetPaths(JNIEnv *env, jobject thiz, jstring hamcore_j, jstring tmpdir_j)
{
	char hc_path[MAX_SIZE];
	char tmp_path[MAX_SIZE];

	SeGetPathString(env, hamcore_j, hc_path, sizeof(hc_path));
	SeGetPathString(env, tmpdir_j, tmp_path, sizeof(tmp_path));

	StrCpy(g_hamcore_path, sizeof(g_hamcore_path), hc_path);
	StrCpy(g_tmp_dir, sizeof(g_tmp_dir), tmp_path);

	Debug("paths: hamcore=%s tmp=%s", g_hamcore_path, g_tmp_dir);
}

// Convert a wide (UTF-16 code unit) string to UTF-8, with surrogate pairing
static void SeWToUtf8(const wchar_t *src, char *dst, int dst_size)
{
	int i = 0, o = 0;

	dst[0] = 0;

	if (src == NULL || dst_size < 5)
	{
		return;
	}

	while (src[i] != 0 && o < dst_size - 4)
	{
		unsigned int cp = (unsigned int)src[i];

		i++;

		if (cp >= 0xD800 && cp <= 0xDBFF && src[i] >= 0xDC00 && src[i] <= 0xDFFF)
		{
			cp = 0x10000 + ((cp - 0xD800) << 10) + ((unsigned int)src[i] - 0xDC00);
			i++;
		}

		if (cp < 0x80)
		{
			dst[o++] = (char)cp;
		}
		else if (cp < 0x800)
		{
			dst[o++] = (char)(0xC0 | (cp >> 6));
			dst[o++] = (char)(0x80 | (cp & 0x3F));
		}
		else if (cp < 0x10000)
		{
			dst[o++] = (char)(0xE0 | (cp >> 12));
			dst[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
			dst[o++] = (char)(0x80 | (cp & 0x3F));
		}
		else
		{
			dst[o++] = (char)(0xF0 | (cp >> 18));
			dst[o++] = (char)(0x80 | ((cp >> 12) & 0x3F));
			dst[o++] = (char)(0x80 | ((cp >> 6) & 0x3F));
			dst[o++] = (char)(0x80 | (cp & 0x3F));
		}
	}

	dst[o] = 0;
}

// Connection/TLS/server-cert info for the "server cert check" UI.
// Mirrors the CiGetSessionStatus read path: SESSION lock -> CONNECTION lock.
JNIEXPORT jobjectArray JNICALL
Java_org_softether_android_SeNative_nativeGetConnInfo(JNIEnv *env, jobject thiz, jlong handle)
{
	VLAN_ANDROID *v = (VLAN_ANDROID *)handle;
	char elems[8][MAX_SIZE];
	jobjectArray ret;
	int i;

	for (i = 0; i < 8; i++)
	{
		elems[i][0] = 0;
	}

	if (v == NULL)
	{
		return NULL;
	}

	pthread_mutex_lock(&g_lock);

	if (v != g_v || v->Session == NULL)
	{
		pthread_mutex_unlock(&g_lock);

		return NULL;
	}

	{
		SESSION *s = v->Session;

		Lock(s->lock);

		if (s->ClientStatus == CLIENT_STATUS_ESTABLISHED && s->Connection != NULL)
		{
			CONNECTION *c = s->Connection;

			Lock(c->lock);

			StrCpy(elems[0], MAX_SIZE, (s->UseEncrypt && c->CipherName != NULL) ? "on" : "off");
			StrCpy(elems[1], MAX_SIZE, c->SslVersion != NULL ? c->SslVersion : "");
			StrCpy(elems[2], MAX_SIZE, c->CipherName != NULL ? c->CipherName : "");

			if (c->ServerX != NULL)
			{
				X *x = c->ServerX;

				LoadXNames(x);
				LoadXDates(x);

				GetPrintNameFromXA(elems[3], MAX_SIZE, x);

				if (x->issuer_name != NULL)
				{
					wchar_t wname[MAX_SIZE];

					GetPrintNameFromName(wname, sizeof(wchar_t) * MAX_SIZE, x->issuer_name);

					SeWToUtf8(wname, elems[4], MAX_SIZE);
				}

				if (x->notAfter != 0)
				{
					SYSTEMTIME st;

					Zero(&st, sizeof(st));

					// Mayaqua stores UINT64 system times as (UTC ms + 9 h)
					if (x->notAfter > 32400000ULL)
					{
						UINT64ToSystem(&st, x->notAfter - 32400000ULL);
					}

					snprintf(elems[5], MAX_SIZE, "%04u-%02u-%02u %02u:%02u UTC",
						st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
				}

				{
					UCHAR hash[20];
					int pos = 0;

					GetXDigest(x, hash, true);

					for (i = 0; i < 20 && pos < MAX_SIZE - 8; i++)
					{
						pos += sprintf(elems[6] + pos, (i == 0) ? "%02X" : ":%02X", hash[i]);
					}
				}

				StrCpy(elems[7], MAX_SIZE, (s->SslOption != NULL) ? "CA-verified" : "unverified");
			}

			Unlock(c->lock);
		}

		Unlock(s->lock);
	}

	pthread_mutex_unlock(&g_lock);

	ret = (*env)->NewObjectArray(env, 8, (*env)->FindClass(env, "java/lang/String"), NULL);
	if (ret == NULL)
	{
		return NULL;
	}

	for (i = 0; i < 8; i++)
	{
		jstring js = (*env)->NewStringUTF(env, elems[i]);

		(*env)->SetObjectArrayElement(env, ret, i, js);
		(*env)->DeleteLocalRef(env, js);
	}

	return ret;
}

JNIEXPORT void JNICALL
Java_org_softether_android_SeNative_nativeDisconnect(JNIEnv *env, jobject thiz, jlong handle)
{
	VLAN_ANDROID *v = (VLAN_ANDROID *)handle;

	pthread_mutex_lock(&g_lock);

	// Idempotent: only the first matching call performs the teardown.
	if (v == NULL || v != g_v)
	{
		pthread_mutex_unlock(&g_lock);

		return;
	}
	g_v = NULL;

	// Wake a pending DHCP wait in the pump thread before touching the session
	VLanAndroidAbortDhcp(v);

	if (v->Session != NULL)
	{
		StopSession(v->Session);
		ReleaseSession(v->Session);
		v->Session = NULL;
	}

	// Safe after ReleaseSession joined the session thread (the session reads
	// its Account copy members until termination)
	if (v->Account != NULL)
	{
		CiFreeAccount((ACCOUNT *)v->Account);
		v->Account = NULL;
	}

	VLanAndroidFree(v);

	pthread_mutex_unlock(&g_lock);
}
