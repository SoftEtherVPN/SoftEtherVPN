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

#ifdef __ANDROID__
#include <android/log.h>
#define SELOG(...)	__android_log_print(ANDROID_LOG_INFO, "SETH", __VA_ARGS__)
#else	// __ANDROID__
#define SELOG(...)
#endif	// __ANDROID__

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

// Parse one "key=value" configuration line set (newline separated)
static void ParseCfg(char *cfg, CLIENT_OPTION *o, CLIENT_AUTH *a,
					bool *dhcp, IP *ip, IP *mask, IP *gw, IP *dns1, IP *dns2)
{
	char *line, *save;

	for (line = strtok_r(cfg, "\r\n", &save); line != NULL; line = strtok_r(NULL, "\r\n", &save))
	{
		char *eq, *k, *v;

		if (line[0] == '#' || line[0] == 0)
		{
			continue;
		}

		eq = strchr(line, '=');
		if (eq == NULL)
		{
			continue;
		}

		*eq = 0;
		k = line;
		v = eq + 1;

		if (strcmp(k, "host") == 0)
		{
			StrCpy(o->Hostname, sizeof(o->Hostname), v);
		}
		else if (strcmp(k, "port") == 0)
		{
			o->Port = ToInt(v);
		}
		else if (strcmp(k, "udp_port") == 0)
		{
			o->PortUDP = ToInt(v);
		}
		else if (strcmp(k, "hub") == 0)
		{
			StrCpy(o->HubName, sizeof(o->HubName), v);
		}
		else if (strcmp(k, "user") == 0)
		{
			StrCpy(a->Username, sizeof(a->Username), v);
		}
		else if (strcmp(k, "pass") == 0)
		{
			StrCpy(a->PlainPassword, sizeof(a->PlainPassword), v);
		}
		else if (strcmp(k, "encrypt") == 0)
		{
			o->UseEncrypt = (strcmp(v, "false") != 0);
		}
		else if (strcmp(k, "compress") == 0)
		{
			o->UseCompress = (strcmp(v, "true") == 0);
		}
		else if (strcmp(k, "proxy_host") == 0)
		{
			StrCpy(o->ProxyName, sizeof(o->ProxyName), v);
			o->ProxyType = PROXY_SOCKS5;
		}
		else if (strcmp(k, "proxy_port") == 0)
		{
			o->ProxyPort = ToInt(v);
		}
		else if (strcmp(k, "ipv4") == 0)
		{
			*dhcp = (strcmp(v, "static") != 0);
		}
		else if (strcmp(k, "static_ip") == 0)
		{
			StrToIP(ip, v);
		}
		else if (strcmp(k, "static_mask") == 0)
		{
			StrToIP(mask, v);
		}
		else if (strcmp(k, "static_gw") == 0)
		{
			StrToIP(gw, v);
		}
		else if (strcmp(k, "dns1") == 0)
		{
			StrToIP(dns1, v);
		}
		else if (strcmp(k, "dns2") == 0)
		{
			StrToIP(dns2, v);
		}
	}
}

// ---------------------------------------------------------------------------
// New-format CFG text bridge ("declare root { ... }", see Mayaqua/Cfg.c).
// The raw profile text is exchanged with the VPN Client's own account
// database format, so files written by the desktop vpnclient load as-is.

static FOLDER *SeCfgTextToRoot(const char *text)
{
	BUF *b;
	FOLDER *root;
	const char *p;

	if (text == NULL || text[0] == 0)
	{
		return NULL;
	}

	p = text;

	// Skip the UTF-8 BOM which CfgFolderToBufEx writes in the banner
	if (((UCHAR)p[0] == 0xEF) && ((UCHAR)p[1] == 0xBB) && ((UCHAR)p[2] == 0xBF))
	{
		p += 3;
	}

	b = NewBuf();
	WriteBuf(b, (void *)p, StrLen(p));
	SeekBuf(b, 0, 0);

	root = CfgBufTextToFolder(b);

	FreeBuf(b);

	return root;
}

static char *SeCfgRootToText(FOLDER *root)
{
	BUF *b;
	char *ret;

	if (root == NULL)
	{
		return NULL;
	}

	b = CfgFolderToBufEx(root, true, false);
	if (b == NULL)
	{
		return NULL;
	}

	ret = Malloc(b->Size + 1);
	if (b->Size > 0)
	{
		Copy(ret, b->Buf, b->Size);
	}
	ret[b->Size] = 0;

	FreeBuf(b);

	return ret;
}

// Item value in its flat textual representation (malloc'ed, NULL on unknown type)
static char *SeCfgItemValue(ITEM *t)
{
	switch (t->Type)
	{
	case ITEM_TYPE_INT:
		{
			char *s = Malloc(32);
			ToStr(s, *((UINT *)t->Buf));
			return s;
		}
	case ITEM_TYPE_INT64:
		{
			char *s = Malloc(64);
			ToStr64(s, *((UINT64 *)t->Buf));
			return s;
		}
	case ITEM_TYPE_BOOL:
		return CopyStr(*((bool *)t->Buf) ? TAG_TRUE : TAG_FALSE);
	case ITEM_TYPE_BYTE:
		if (t->size == 0)
		{
			return CopyStr("0");
		}
		{
			char *b64 = Base64FromBin(NULL, t->Buf, t->size);

			if (b64 == NULL)
			{
				return CopyStr("0");
			}

			return CopyStr(b64);
		}
	case ITEM_TYPE_STRING:
		{
			UINT utf8_size = CalcUniToUtf8((wchar_t *)t->Buf) + 1;
			char *utf8 = ZeroMalloc(utf8_size);
			UniToUtf8((BYTE *)utf8, utf8_size, (wchar_t *)t->Buf);
			return utf8;
		}
	}
	return NULL;
}

static char *SeCfgJoinPath(const char *path, const char *name)
{
	char *ret;
	UINT size;

	size = StrLen(path) + StrLen(name) + 2;
	ret = Malloc(size);
	ret[0] = 0;
	StrCpy(ret, size, path);
	if (path[0] != 0)
	{
		StrCat(ret, size, "/");
	}
	StrCat(ret, size, name);

	return ret;
}

static void SeCfgPushTriple(char ***arr, UINT *num, UINT *alloc, char *path, char *type, char *value)
{
	if (*num + 3 > *alloc)
	{
		UINT new_alloc = (*alloc == 0) ? 96 : (*alloc * 2);
		char **na = Malloc(sizeof(char *) * new_alloc);

		if (*arr != NULL)
		{
			Copy(na, *arr, sizeof(char *) * *num);
			Free(*arr);
		}

		*arr = na;
		*alloc = new_alloc;
	}

	(*arr)[*num] = CopyStr(path);
	(*arr)[*num + 1] = CopyStr(type);
	(*arr)[*num + 2] = CopyStr(value);
	*num += 3;
}

// depth-first walk: emits (path, type, value) string triples
static void SeCfgFlatten(FOLDER *f, char *path, char ***arr, UINT *num, UINT *alloc)
{
	UINT i;

	for (i = 0; i < LIST_NUM(f->Items); i++)
	{
		ITEM *t = (ITEM *)LIST_DATA(f->Items, i);
		char *value = SeCfgItemValue(t);
		char *jp;

		if (value == NULL)
		{
			continue;
		}

		jp = SeCfgJoinPath(path, t->Name);
		SeCfgPushTriple(arr, num, alloc, jp, CfgTypeToStr(t->Type), value);
		Free(jp);
		Free(value);
	}

	for (i = 0; i < LIST_NUM(f->Folders); i++)
	{
		FOLDER *sub = (FOLDER *)LIST_DATA(f->Folders, i);
		char *jp = SeCfgJoinPath(path, sub->Name);

		SeCfgPushTriple(arr, num, alloc, jp, "folder", sub->Name);

		SeCfgFlatten(sub, jp, arr, num, alloc);

		Free(jp);
	}
}

// Walk 'path' (slash separated) below 'root', creating folders as needed
static FOLDER *SeCfgWalk(FOLDER *root, char *path, char *last_name, UINT path_len)
{
	FOLDER *cur = root;
	char seg[MAX_SIZE];
	UINT i;

	seg[0] = 0;

	for (i = 0; i <= path_len; i++)
	{
		char c = (i < path_len) ? path[i] : '/';

		if (c != '/')
		{
			UINT l = StrLen(seg);

			if (l < sizeof(seg) - 1)
			{
				seg[l] = c;
				seg[l + 1] = 0;
			}
		}
		else
		{
			FOLDER *nf;

			if (seg[0] == 0)
			{
				continue;
			}

			if (i == path_len && last_name != NULL)
			{
				// last segment is the item name
				StrCpy(last_name, MAX_SIZE, seg);
				seg[0] = 0;
				continue;
			}

			nf = CfgFindFolder(cur, seg);
			if (nf == NULL)
			{
				nf = CfgCreateFolder(cur, seg);
			}
			cur = nf;

			seg[0] = 0;
		}
	}

	return cur;
}

static FOLDER *SeCfgFromTriples(char **t, UINT n)
{
	FOLDER *root, *parent;
	char root_name[MAX_SIZE];
	char path[MAX_SIZE];
	char name[MAX_SIZE];
	UINT i;

	root_name[0] = 0;

	for (i = 0; i + 2 < n; i += 3)
	{
		if (StrCmp(t[i + 1], "root") == 0)
		{
			StrCpy(root_name, sizeof(root_name), t[i + 2]);
			break;
		}
	}
	if (root_name[0] == 0)
	{
		StrCpy(root_name, sizeof(root_name), TAG_ROOT);
	}

	root = CfgCreateFolder(NULL, root_name);

	// pass 1: folders
	for (i = 0; i + 2 < n; i += 3)
	{
		if (StrCmp(t[i + 1], "folder") != 0)
		{
			continue;
		}

		StrCpy(path, sizeof(path), t[i]);
		SeCfgWalk(root, path, NULL, StrLen(path));
	}

	// pass 2: items
	for (i = 0; i + 2 < n; i += 3)
	{
		char *type = t[i + 1];
		char *value = t[i + 2];

		if (StrCmp(type, "folder") == 0 || StrCmp(type, "root") == 0)
		{
			continue;
		}

		StrCpy(path, sizeof(path), t[i]);
		name[0] = 0;

		parent = SeCfgWalk(root, path, name, StrLen(path));

		if (parent == NULL || name[0] == 0)
		{
			continue;
		}

		if (StrCmp(type, TAG_INT) == 0)
		{
			UINT v = ToInt(value);
			CfgCreateItem(parent, name, ITEM_TYPE_INT, &v, sizeof(UINT));
		}
		else if (StrCmp(type, TAG_INT64) == 0)
		{
			UINT64 v = ToInt64(value);
			CfgCreateItem(parent, name, ITEM_TYPE_INT64, &v, sizeof(UINT64));
		}
		else if (StrCmp(type, TAG_BOOL) == 0)
		{
			bool b = (StrCmpi(value, TAG_TRUE) == 0) || (ToInt(value) != 0);
			CfgCreateItem(parent, name, ITEM_TYPE_BOOL, &b, sizeof(bool));
		}
		else if (StrCmp(type, TAG_BYTE) == 0)
		{
			if (value[0] != 0 && StrCmp(value, "0") != 0)
			{
				UINT size = 0;
				void *bin = Base64ToBin(&size, value, StrLen(value));

				if (bin != NULL)
				{
					CfgCreateItem(parent, name, ITEM_TYPE_BYTE, bin, size);
					Free(bin);
				}
			}
		}
		else if (StrCmp(type, TAG_STRING) == 0)
		{
			UINT uni_size = CalcUtf8ToUni((BYTE *)value, StrLen(value));

			if (uni_size == 0)
			{
				wchar_t empty = 0;
				CfgCreateItem(parent, name, ITEM_TYPE_STRING, &empty, sizeof(wchar_t));
			}
			else
			{
				wchar_t *uni = Malloc(uni_size);
				Utf8ToUni(uni, uni_size, (BYTE *)value, StrLen(value));
				CfgCreateItem(parent, name, ITEM_TYPE_STRING, uni, uni_size);
				Free(uni);
			}
		}
	}

	return root;
}

// Android-only network options (kept in a separate "AndroidOptions" folder so
// that the native SoftEther ClientOption folder is never polluted with keys
// that a stock vpncmd/vpnclient CFG would not contain)
typedef struct
{
	bool dhcp;			// IPv4 mode (true = DHCP, false = static)
	bool use_v4;		// IPv4 protocol enabled
	bool use_v6;		// IPv6 protocol enabled
	bool v6_static;		// IPv6 mode (false = router RA/SLAAC, true = manual)
	IP ip, mask, gw, dns1, dns2;			// static IPv4 parameters
	IP v6ip, s6_mask, s6_gw, s6_dns;	// static IPv6 parameters
} SE_NETCFG;

// AndroidOptions string getter with NULL-folder tolerance
static bool SeCfgGetOpt(FOLDER *ao, char *name, char *dst, UINT size)
{
	return ao != NULL && CfgGetStr(ao, name, dst, size);
}

// Boolean option with a default for "key not present" (CFG bool items are
// typed natively; CfgGetStr does not read them, so CfgIsItem/CfgGetBool
// must be used)
static bool SeCfgGetBoolDef(FOLDER *ao, char *name, bool def_value)
{
	if (ao != NULL && CfgIsItem(ao, name))
	{
		return CfgGetBool(ao, name);
	}

	return def_value;
}

// Load the connect parameters out of a CFG text profile (first account)
static bool SeCfgLoadConnectParam(const char *text, CLIENT_OPTION **opt_out, CLIENT_AUTH **auth_out,
	SE_NETCFG *n)
{
	FOLDER *root, *db, *acc, *fo, *fa, *ao;
	char tmp[MAX_SIZE];

	*opt_out = NULL;
	*auth_out = NULL;

	Zero(n, sizeof(SE_NETCFG));
	n->dhcp = true;
	n->use_v4 = true;
	n->use_v6 = false;

	root = SeCfgTextToRoot(text);
	if (root == NULL)
	{
		return false;
	}

	db = CfgGetFolder(root, "AccountDatabase");
	acc = (db != NULL && LIST_NUM(db->Folders) > 0) ? (FOLDER *)LIST_DATA(db->Folders, 0) : NULL;

	if (acc == NULL)
	{
		CfgDeleteFolder(root);
		return false;
	}

	fo = CfgGetFolder(acc, "ClientOption");
	fa = CfgGetFolder(acc, "ClientAuth");
	ao = CfgGetFolder(acc, "AndroidOptions");

	if (fo == NULL || fa == NULL)
	{
		CfgDeleteFolder(root);
		return false;
	}

	*opt_out = CiLoadClientOption(fo);
	*auth_out = CiLoadClientAuth(fa);

	// IPv4 mode / enable flags (vpncmd VPN_IP / VPN_IP6 semantics; defaults:
	// IPv4 enabled, IPv6 disabled)
	if (SeCfgGetOpt(ao, "IPv4Mode", tmp, sizeof(tmp)))
	{
		n->dhcp = (StrCmp(tmp, "static") != 0);
	}

	n->use_v4 = SeCfgGetBoolDef(ao, "UseIPv4", true);
	n->use_v6 = SeCfgGetBoolDef(ao, "UseIPv6", false);

	if (SeCfgGetOpt(ao, "IPv6Mode", tmp, sizeof(tmp)))
	{
		n->v6_static = (StrCmp(tmp, "static") == 0);
	}

	// Static IPv4
	if (SeCfgGetOpt(ao, "StaticIp", tmp, sizeof(tmp)))
	{
		StrToIP(&n->ip, tmp);
	}
	if (SeCfgGetOpt(ao, "StaticMask", tmp, sizeof(tmp)))
	{
		StrToIP(&n->mask, tmp);
	}
	if (SeCfgGetOpt(ao, "StaticGw", tmp, sizeof(tmp)))
	{
		StrToIP(&n->gw, tmp);
	}
	if (SeCfgGetOpt(ao, "Dns1", tmp, sizeof(tmp)))
	{
		StrToIP(&n->dns1, tmp);
	}
	if (SeCfgGetOpt(ao, "Dns2", tmp, sizeof(tmp)))
	{
		StrToIP(&n->dns2, tmp);
	}

	// Static IPv6 (manual mode)
	if (SeCfgGetOpt(ao, "StaticIPv6", tmp, sizeof(tmp)))
	{
		StrToIP6(&n->v6ip, tmp);
	}
	if (SeCfgGetOpt(ao, "StaticMask6", tmp, sizeof(tmp)))
	{
		UINT plen = ToInt(tmp);

		if (plen == 0 || plen > 128)
		{
			plen = 64;
		}

		IntToSubnetMask6(&n->s6_mask, plen);
	}
	if (SeCfgGetOpt(ao, "StaticGw6", tmp, sizeof(tmp)))
	{
		StrToIP6(&n->s6_gw, tmp);
	}
	if (SeCfgGetOpt(ao, "StaticDns6", tmp, sizeof(tmp)))
	{
		StrToIP6(&n->s6_dns, tmp);
	}

	CfgDeleteFolder(root);

	return true;
}

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

	SELOG("init: begin");

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
	SELOG("init: mayaqua done");

	InitCedar();
	SELOG("init: cedar done");

	cedar = NewCedar(NULL, NULL);
	SELOG("init: newcedar done");
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

	StrCpy(option.HubName, sizeof(option.HubName), "SERVERVPN");
	option.Port = DEF_PORT;
	option.MaxConnection = 1;
	option.UseEncrypt = true;
	option.HalfConnection = true;
	option.NumRetry = DEF_RETRY;
	option.RetryInterval = DEF_RETRY_INTERVAL;
	StrCpy(option.DeviceName, sizeof(option.DeviceName), "SoftEtherVPN Android");

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
		CLIENT_OPTION *co = NULL;
		CLIENT_AUTH *ca = NULL;
		SE_NETCFG n;

		if (InStr(cfg, "declare") &&
			SeCfgLoadConnectParam(cfg, &co, &ca, &n))
		{
			option = *co;
			auth = *ca;

			Free(co);
			Free(ca);

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
		else
		{
			ParseCfg(cfg, &option, &auth, &dhcp, &sip, &smask, &sgw, &sdns1, &sdns2);

			if (auth.PlainPassword[0] != 0)
			{
				auth.AuthType = CLIENT_AUTHTYPE_PASSWORD;
				HashPassword(auth.HashedPassword, auth.Username, auth.PlainPassword);
			}
			else
			{
				auth.AuthType = CLIENT_AUTHTYPE_ANONYMOUS;
			}
		}
	}

	Free(cfg);

	// Android-bridge policy (this file only; Cedar/Session core is untouched):
	// Kotlin (VpnEngine worker loop) owns all connection retries and applies the
	// profile's NumRetry/RetryInterval itself, so the C session performs exactly
	// one connect/login attempt per session.
	option.NumRetry = 0;

	SELOG("connect: %s:%u hub=%s user=%s enc=%s cmp=%s dhcp=%s v4=%s v6=%s mode6=%s", option.Hostname, option.Port,
		option.HubName, auth.Username, option.UseEncrypt ? "true" : "false",
		option.UseCompress ? "true" : "false", dhcp ? "true" : "false",
		use_v4 ? "true" : "false", use_v6 ? "true" : "false",
		use_v6 ? (v6_static ? "static" : "ra") : "-");

	if (option.Hostname[0] == 0)
	{
		return 0;
	}

	v = VLanAndroidNew(cedar);
	if (v == NULL)
	{
		SELOG("connect: vlan new failed");

		return 0;
	}
	SELOG("connect: vlan ok");

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

	s = NewClientSessionEx(cedar, &option, &auth, VLanAndroidGetPacketAdapter(v), NULL);

	// The session clones client certificate/key during connection setup;
	// release our references (only ever set by a CFG-text profile).
	if (auth.ClientX != NULL)
	{
		FreeX(auth.ClientX);
	}
	if (auth.ClientK != NULL)
	{
		FreeK(auth.ClientK);
	}

	if (s == NULL)
	{
		SELOG("connect: session failed");

		VLanAndroidFree(v);

		return 0;
	}
	SELOG("connect: session ok");

	v->Session = s;

	if (!VLanAndroidStart(v))
	{
		SELOG("connect: vlan start failed");

		StopSession(s);
		ReleaseSession(s);
		VLanAndroidFree(v);

		return 0;
	}
	SELOG("connect: started");

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
	SELOG("set tun fd: %d", fd);

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

	SELOG("paths: hamcore=%s tmp=%s", g_hamcore_path, g_tmp_dir);
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

	SELOG("disconnect");

	if (v->Session != NULL)
	{
		StopSession(v->Session);
		ReleaseSession(v->Session);
		v->Session = NULL;
	}

	VLanAndroidFree(v);

	pthread_mutex_unlock(&g_lock);
}
