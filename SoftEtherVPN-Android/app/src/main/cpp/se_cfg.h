// SoftEther VPN for Android - CFG text bridge ("declare root { ... }", see
// Mayaqua/Cfg.c). The raw profile text is exchanged with the VPN Client's own
// account database format, so files written by the desktop vpnclient load
// as-is. This layer is JNI-free; se_jni.c owns the JNIEnv marshalling.

#ifndef SE_CFG_H
#define SE_CFG_H

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Cfg.h"
#include "Cedar/Cedar.h"

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

FOLDER *SeCfgTextToRoot(const char *text);

// Item list / folder tree text conversion helpers (see se_jni.c usage)
char *SeCfgRootToText(FOLDER *root);
void SeCfgPushTriple(char ***arr, UINT *num, UINT *alloc, char *path, char *type, char *value);
void SeCfgFlatten(FOLDER *f, char *path, char ***arr, UINT *num, UINT *alloc);
FOLDER *SeCfgFromTriples(char **t, UINT n);

// Load the first account of a CFG text profile ("declare root" account
// database) with the core's own reader, so that a desktop-written or hand-edited
// profile keeps everything it carries: every ClientOption key, every
// ClientAuth form (hashed password, plain password, client certificate, secure
// token), the account-root flags, the pinned ServerCert and the shortcut key —
// nothing is filtered out by the Android bridge.
bool SeCfgLoadAccount(const char *text, ACCOUNT **acc_out, SE_NETCFG *n);

#endif
