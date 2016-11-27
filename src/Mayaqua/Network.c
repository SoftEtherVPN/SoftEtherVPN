// SoftEther VPN Source Code
// Mayaqua Kernel
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2016 Daiyuu Nobori.
// Copyright (c) 2012-2016 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2016 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Contributors:
// - nattoheaven (https://github.com/nattoheaven)
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


// Network.c
// Network communication module

#include <GlobalConst.h>

#define	ENCRYPT_C
#define	NETWORK_C

#define	__WINCRYPT_H__

#ifdef	WIN32
// Include windows.h for Socket API
#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <Ws2tcpip.h>
#include <Wspiapi.h>
#include <winsock2.h>
#include <windows.h>
#include <Iphlpapi.h>
#include <ws2ipdef.h>
#include <netioapi.h>
#include <Icmpapi.h>
#endif	// WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <Mayaqua/Mayaqua.h>
#ifdef	UNIX_MACOS
#include <sys/event.h>
#endif	// UNIX_MACOS

#ifdef	OS_WIN32
NETWORK_WIN32_FUNCTIONS *w32net;
struct ROUTE_CHANGE_DATA
{
	OVERLAPPED Overlapped;
	HANDLE Handle;
	UINT NumCalled;
};
#endif	// OS_WIN32

// Whether the blocking occurs in SSL
#if	defined(UNIX_BSD) || defined(UNIX_MACOS)
#define	FIX_SSL_BLOCKING
#endif

// IPV6_V6ONLY constant
#ifdef	UNIX_LINUX
#ifndef	IPV6_V6ONLY
#define	IPV6_V6ONLY	26
#endif	// IPV6_V6ONLY
#endif	// UNIX_LINUX

#ifdef	UNIX_SOLARIS
#ifndef	IPV6_V6ONLY
#define	IPV6_V6ONLY	0x27
#endif	// IPV6_V6ONLY
#endif	// UNIX_SOLARIS



// HTTP constant
static char http_404_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>404 Not Found</TITLE>\r\n</HEAD><BODY>\r\n<H1>Not Found</H1>\r\nThe requested URL $TARGET$ was not found on this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_403_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>403 Forbidden</TITLE>\r\n</HEAD><BODY>\r\n<H1>Forbidden</H1>\r\nYou don't have permission to access $TARGET$\r\non this server.<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_500_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>500 Server Error</TITLE>\r\n</HEAD><BODY>\r\n<H1>Server Error</H1>\r\nServer Error<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_501_str[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>501 Method Not Implemented</TITLE>\r\n</HEAD><BODY>\r\n<H1>Method Not Implemented</H1>\r\n$METHOD$ to $TARGET$ not supported.<P>\r\nInvalid method in request $METHOD$ $TARGET$ $VERSION$<P>\r\n<HR>\r\n<ADDRESS>HTTP Server at $HOST$ Port $PORT$</ADDRESS>\r\n</BODY></HTML>\r\n";
static char http_detect_server_startwith[] = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>403 Forbidden</TITLE>\r\n</HEAD><BODY>\r\n<H1>Forbidden</H1>\r\nYou don't have permission to access ";
static char http_detect_server_tag_future[] = "9C37197CA7C2428388C2E6E59B829B30";

// DNS cache list
static LIST *DnsCache;

// Lock related
static LOCK *machine_name_lock = NULL;
static LOCK *disconnect_function_lock = NULL;
static LOCK *aho = NULL;
static LOCK *socket_library_lock = NULL;
extern LOCK *openssl_lock;
static LOCK *ssl_accept_lock = NULL;
static LOCK *ssl_connect_lock = NULL;
static TOKEN_LIST *cipher_list_token = NULL;
static COUNTER *num_tcp_connections = NULL;
static LOCK *dns_lock = NULL;
static LOCK *unix_dns_server_addr_lock = NULL;
static IP unix_dns_server;
static LIST *HostCacheList = NULL;
static LIST *WaitThreadList = NULL;
static bool disable_cache = false;
static bool NetworkReleaseMode = false;			// Network release mode
static UCHAR machine_ip_process_hash[SHA1_SIZE];
static LOCK *machine_ip_process_hash_lock = NULL;
static LOCK *current_global_ip_lock = NULL;
static LOCK *current_fqdn_lock = NULL;
static bool current_global_ip_set = false;
static IP current_glocal_ipv4 = {0};
static IP current_glocal_ipv6 = {0};
static char current_fqdn[MAX_SIZE];
static bool g_no_rudp_server = false;
static bool g_no_rudp_register = false;
static bool g_natt_low_priority = false;
static LOCK *host_ip_address_list_cache_lock = NULL;
static UINT64 host_ip_address_list_cache_last = 0;
static LIST *host_ip_address_cache = NULL;
static bool disable_gethostname_by_accept = false;
static COUNTER *getip_thread_counter = NULL;
static UINT max_getip_thread = 0;


static char *cipher_list = "RC4-MD5 RC4-SHA AES128-SHA AES256-SHA DES-CBC-SHA DES-CBC3-SHA DHE-RSA-AES128-SHA DHE-RSA-AES256-SHA AES128-GCM-SHA256 AES128-SHA256 AES256-GCM-SHA384 AES256-SHA256 DHE-RSA-AES128-GCM-SHA256 DHE-RSA-AES128-SHA256 DHE-RSA-AES256-GCM-SHA384 DHE-RSA-AES256-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-SHA256 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-SHA384";
static LIST *ip_clients = NULL;

static LIST *local_mac_list = NULL;
static LOCK *local_mac_list_lock = NULL;

static UINT rand_port_numbers[256] = {0};


static bool g_use_privateip_file = false;
static bool g_source_ip_validation_force_disable = false;

static DH_CTX *dh_2048 = NULL;

typedef struct PRIVATE_IP_SUBNET
{
	UINT Ip, Mask, Ip2;
} PRIVATE_IP_SUBNET;

static LIST *g_private_ip_list = NULL;


static LIST *g_dyn_value_list = NULL;



//#define	RUDP_DETAIL_LOG




// Get a value from a dynamic value list (Returns a default value if the value is not found)
UINT64 GetDynValueOrDefault(char *name, UINT64 default_value, UINT64 min_value, UINT64 max_value)
{
	UINT64 ret = GetDynValue(name);

	if (ret == 0)
	{
		return default_value;
	}

	if (ret < min_value)
	{
		ret = min_value;
	}

	if (ret > max_value)
	{
		ret = max_value;
	}

	return ret;
}

// Get a value from a dynamic value list (Returns a default value if the value is not found)
// The value is limited to 1/5 to 50 times of the default value for safety
UINT64 GetDynValueOrDefaultSafe(char *name, UINT64 default_value)
{
	return GetDynValueOrDefault(name, default_value, default_value / (UINT64)5, default_value * (UINT64)50);
}

// Get a value from a dynamic value list
UINT64 GetDynValue(char *name)
{
	UINT64 ret = 0;
	// Validate arguments
	if (name == NULL)
	{
		return 0;
	}

	if (g_dyn_value_list == NULL)
	{
		return 0;
	}

	LockList(g_dyn_value_list);
	{
		UINT i;

		for (i = 0; i < LIST_NUM(g_dyn_value_list);i++)
		{
			DYN_VALUE *vv = LIST_DATA(g_dyn_value_list, i);

			if (StrCmpi(vv->Name, name) == 0)
			{
				ret = vv->Value;
				break;
			}
		}
	}
	UnlockList(g_dyn_value_list);

	return ret;
}

// Set the value to the dynamic value list
void SetDynListValue(char *name, UINT64 value)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	if (g_dyn_value_list == NULL)
	{
		return;
	}

	LockList(g_dyn_value_list);
	{
		UINT i;
		DYN_VALUE *v = NULL;

		for (i = 0; i < LIST_NUM(g_dyn_value_list);i++)
		{
			DYN_VALUE *vv = LIST_DATA(g_dyn_value_list, i);

			if (StrCmpi(vv->Name, name) == 0)
			{
				v = vv;
				break;
			}
		}

		if (v == NULL)
		{
			v = ZeroMalloc(sizeof(DYN_VALUE));
			StrCpy(v->Name, sizeof(v->Name), name);

			Add(g_dyn_value_list, v);
		}

		v->Value = value;
	}
	UnlockList(g_dyn_value_list);
}

// Apply by extracting dynamic value list from the specified PACK
void ExtractAndApplyDynList(PACK *p)
{
	BUF *b;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	b = PackGetBuf(p, "DynList");
	if (b == NULL)
	{
		return;
	}

	AddDynList(b);

	FreeBuf(b);
}

// Insert the data to the dynamic value list
void AddDynList(BUF *b)
{
	PACK *p;
	TOKEN_LIST *t;
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	SeekBufToBegin(b);

	p = BufToPack(b);
	if (p == NULL)
	{
		return;
	}

	t = GetPackElementNames(p);
	if (t != NULL)
	{
		UINT i;

		for (i = 0;i < t->NumTokens;i++)
		{
			char *name = t->Token[i];
			UINT64 v = PackGetInt64(p, name);

			SetDynListValue(name, v);
		}

		FreeToken(t);
	}

	FreePack(p);
}

// Initialization of the dynamic value list
void InitDynList()
{
	g_dyn_value_list = NewList(NULL);
}

// Solution of dynamic value list
void FreeDynList()
{
	UINT i;
	if (g_dyn_value_list == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(g_dyn_value_list);i++)
	{
		DYN_VALUE *d = LIST_DATA(g_dyn_value_list, i);

		Free(d);
	}

	ReleaseList(g_dyn_value_list);

	g_dyn_value_list = NULL;
}

// Check whether the string in the string list appears in the specified string
bool IsInStrByStrList(char *str, char *str_list)
{
	TOKEN_LIST *t;
	bool ret = false;
	// Validate arguments
	if (str == NULL || str_list == NULL)
	{
		return false;
	}

	t = ParseTokenWithoutNullStr(str_list, ", \t\r\n");
	if (t != NULL)
	{
		UINT i;

		for (i = 0;i < t->NumTokens;i++)
		{
			char *s = t->Token[i];

			if (StrLen(s) >= 1)
			{
				if (InStrEx(str, s, true))
				{
					ret = true;
					break;
				}
			}
		}
	}

	FreeToken(t);

	return ret;
}


// Search whether the IP address exists on the IP address list string
bool IsIpInStrList(IP *ip, char *ip_list)
{
	char ip_str[128];
	TOKEN_LIST *t;
	bool ret = false;
	// Validate arguments
	if (ip == NULL || ip_list == NULL)
	{
		return false;
	}

	Zero(ip_str, sizeof(ip_str));
	IPToStr(ip_str, sizeof(ip_str), ip);

	t = ParseTokenWithoutNullStr(ip_list, ", \t\r\n");

	if (t != NULL)
	{
		UINT i;

		for (i = 0;i < t->NumTokens;i++)
		{
			char *s = t->Token[i];

			if (StrCmpi(s, ip_str) == 0)
			{
				ret = true;
				break;
			}
		}
	}

	FreeToken(t);

	return ret;
}


// Disable NAT-T function globally
void DisableRDUPServerGlobally()
{
	g_no_rudp_server = true;
}

// Disable NAT-T registration globally
void DisableRUDPRegisterGlobally()
{
	g_no_rudp_register = true;
}

// Lower the priority of the host at NAT-T
void SetNatTLowPriority()
{
	g_natt_low_priority = true;
}

// Extract only the host name part from FQDN
void GetSimpleHostname(char *hostname, UINT hostname_size, char *fqdn)
{
	UINT i;
	ClearStr(hostname, hostname_size);
	// Validate arguments
	if (hostname == NULL || fqdn == NULL)
	{
		return;
	}

	StrCpy(hostname, hostname_size, fqdn);
	Trim(hostname);

	i = SearchStrEx(hostname, ".", 0, true);
	if (i != INFINITE)
	{
		hostname[i] = 0;
	}
}

// Get the current time zone
int GetCurrentTimezone()
{
	int ret = 0;

#ifdef	OS_WIN32
	ret = GetCurrentTimezoneWin32();
#else	// OS_WIN32
	{
#if	defined(UNIX_MACOS) || defined(UNIX_BSD)
		struct timeval tv;
		struct timezone tz;

		Zero(&tv, sizeof(tv));
		Zero(&tz, sizeof(tz));

		gettimeofday(&tv, &tz); 

		ret = tz.tz_minuteswest;

#else	// defined(UNIX_MACOS) || defined(UNIX_BSD)
		tzset();

		ret = timezone / 60;
#endif	// defined(UNIX_MACOS) || defined(UNIX_BSD)
	}
#endif	// OS_WIN32

	return ret;
}

// Flag of whether to use the DNS proxy
bool IsUseDnsProxy()
{
	return false;
}

// Flag of whether to use an alternate host name
bool IsUseAlternativeHostname()
{

	return false;
}

#ifdef	OS_WIN32
// Get the current time zone (Win32)
int GetCurrentTimezoneWin32()
{
	TIME_ZONE_INFORMATION info;
	Zero(&info, sizeof(info));

	if (GetTimeZoneInformation(&info) == TIME_ZONE_ID_INVALID)
	{
		return 0;
	}

	return info.Bias;
}
#endif	// OS_WIN32


// Set the current FQDN of the DDNS
void SetCurrentDDnsFqdn(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	Lock(current_fqdn_lock);
	{
		StrCpy(current_fqdn, sizeof(current_fqdn), name);
	}
	Unlock(current_fqdn_lock);
}

// Get the current DDNS FQDN hash
UINT GetCurrentDDnsFqdnHash()
{
	UINT ret;
	UCHAR hash[SHA1_SIZE];
	char name[MAX_SIZE];

	ClearStr(name, sizeof(name));
	GetCurrentDDnsFqdn(name, sizeof(name));

	Trim(name);
	StrUpper(name);

	HashSha1(hash, name, StrLen(name));

	Copy(&ret, hash, sizeof(UINT));

	return ret;
}

// Get the current DDNS FQDN
void GetCurrentDDnsFqdn(char *name, UINT size)
{
	ClearStr(name, size);
	// Validate arguments
	if (name == NULL || size == 0)
	{
		return;
	}

	Lock(current_fqdn_lock);
	{
		StrCpy(name, size, current_fqdn);
	}
	Unlock(current_fqdn_lock);

	Trim(name);
}

// Check whether the specified MAC address exists on the local host (high speed)
bool IsMacAddressLocalFast(void *addr)
{
	bool ret = false;
	// Validate arguments
	if (addr == NULL)
	{
		return false;
	}

	Lock(local_mac_list_lock);
	{
		if (local_mac_list == NULL)
		{
			// First enumeration
			RefreshLocalMacAddressList();
		}

		ret = IsMacAddressLocalInner(local_mac_list, addr);
	}
	Unlock(local_mac_list_lock);

	return ret;
}

// Update the local MAC address list
void RefreshLocalMacAddressList()
{
	Lock(local_mac_list_lock);
	{
		if (local_mac_list != NULL)
		{
			FreeNicList(local_mac_list);
		}

		local_mac_list = GetNicList();
	}
	Unlock(local_mac_list_lock);
}

// Check whether the specified MAC address exists on the local host
bool IsMacAddressLocal(void *addr)
{
	LIST *o;
	bool ret;
	// Validate arguments
	if (addr == NULL)
	{
		return false;
	}

	o = GetNicList();

	ret = IsMacAddressLocalInner(o, addr);

	FreeNicList(o);

	return ret;
}
bool IsMacAddressLocalInner(LIST *o, void *addr)
{
	bool ret = false;
	UINT i;
	// Validate arguments
	if (o == NULL || addr == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		NIC_ENTRY *e = LIST_DATA(o, i);

		if (Cmp(e->MacAddress, addr, 6) == 0)
		{
			ret = true;
			break;
		}
	}

	return ret;
}

// Get a list of the NICs on the computer
LIST *GetNicList()
{
	LIST *o = NULL;

#ifdef	OS_WIN32
	o = Win32GetNicList();
#endif	// OS_WIN32

#ifdef	UNIX_LINUX
#endif	// UNIX_LINUX

	if (o == NULL)
	{
		return NewListFast(NULL);
	}

	return o;
}

#ifdef	OS_WIN32
LIST *Win32GetNicList()
{
	UINT i;
	LIST *o = NewListFast(NULL);
	MS_ADAPTER_LIST *al = MsCreateAdapterList();

	if (al == NULL)
	{
		return NULL;
	}

	for (i = 0;i < al->Num;i++)
	{
		MS_ADAPTER *a = al->Adapters[i];

		if (a->Type == 6 && a->AddressSize == 6)
		{
			NIC_ENTRY *e = ZeroMalloc(sizeof(NIC_ENTRY));

			StrCpy(e->IfName, sizeof(e->IfName), a->Title);
			Copy(e->MacAddress, a->Address, 6);

			Add(o, e);
		}
	}

	MsFreeAdapterList(al);

	return o;
}
#endif	// OS_WIN32

// Release the NIC list
void FreeNicList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		NIC_ENTRY *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

// If the computer is connected to the FLET'S line currently, detect the type of the line (obsolete)
UINT DetectFletsType()
{
	UINT ret = 0;
	//LIST *o = GetHostIPAddressList();
//	UINT i;

/*
	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP *ip = LIST_DATA(o, i);

		if (IsIP6(ip))
		{
			char ip_str[MAX_SIZE];

			IPToStr(ip_str, sizeof(ip_str), ip);

			if (IsInSameNetwork6ByStr(ip_str, "2001:c90::", "/32"))
			{
				// NTT East B-FLETs
				ret |= FLETS_DETECT_TYPE_EAST_BFLETS_PRIVATE;
			}

			if (IsInSameNetwork6ByStr(ip_str, "2408:200::", "/23"))
			{
				// Wrapping in network of NTT East NGN
				ret |= FLETS_DETECT_TYPE_EAST_NGN_PRIVATE;
			}

			if (IsInSameNetwork6ByStr(ip_str, "2001:a200::", "/23"))
			{
				// Wrapping in network of NTT West NGN
				ret |= FLETS_DETECT_TYPE_WEST_NGN_PRIVATE;
			}
		}
	}

	FreeHostIPAddressList(o);
*/
	return ret;
}

// Query for the IP address using the DNS proxy for the B FLETs
bool GetIPViaDnsProxyForJapanFlets(IP *ip_ret, char *hostname, bool ipv6, UINT timeout, bool *cancel, char *dns_proxy_hostname)
{
	SOCK *s;
	char connect_hostname[MAX_SIZE];
	char connect_hostname2[MAX_SIZE];
	IP dns_proxy_ip;
	bool ret = false;
	bool dummy_flag = false;
	char request_str[512];
	// Validate arguments
	if (ip_ret == NULL || hostname == NULL)
	{
		return false;
	}
	if (timeout == 0)
	{
		timeout = BFLETS_DNS_PROXY_TIMEOUT_FOR_QUERY;
	}
	if (cancel == NULL)
	{
		cancel = &dummy_flag;
	}

	// Get the IP address of the DNS proxy server
	if (IsEmptyStr(dns_proxy_hostname))
	{
		// B FLETs
		if (GetDnsProxyIPAddressForJapanBFlets(&dns_proxy_ip, BFLETS_DNS_PROXY_TIMEOUT_FOR_GET_F, cancel) == false)
		{
			return false;
		}
	}
	else
	{
		// FLET'S NEXT
		if (GetIP4Ex6Ex2(&dns_proxy_ip, dns_proxy_hostname, FLETS_NGN_DNS_QUERY_TIMEOUT, true, cancel, true) == false)
		{
			return false;
		}
	}

	if (*cancel)
	{
		return false;
	}

	IPToStr(connect_hostname, sizeof(connect_hostname), &dns_proxy_ip);

	/*{
		StrCpy(connect_hostname, sizeof(connect_hostname), "2409:250:62c0:100:6a05:caff:fe09:5158");
	}*/

	StrCpy(connect_hostname2, sizeof(connect_hostname2), connect_hostname);
	if (IsIP6(&dns_proxy_ip))
	{
		Format(connect_hostname2, sizeof(connect_hostname2), "[%s]", connect_hostname);
	}

	s = ConnectEx3(connect_hostname, BFLETS_DNS_PROXY_PORT, timeout, cancel, NULL, NULL, false, false, false);

	if (s == NULL)
	{
		return false;
	}

	if (*cancel)
	{
		Disconnect(s);
		ReleaseSock(s);

		return false;
	}

	SetTimeout(s, timeout);

	// Start the SSL
	if (StartSSLEx(s, NULL, NULL, true, 0, NULL) && (*cancel == false))
	{
		UCHAR hash[SHA1_SIZE];
		BUF *hash2 = StrToBin(BFLETS_DNS_PROXY_CERT_HASH);

		Zero(hash, sizeof(hash));
		GetXDigest(s->RemoteX, hash, true);

		if (Cmp(hash, hash2->Buf, SHA1_SIZE) == 0)
		{
			// Send the HTTP Request
			Format(request_str, sizeof(request_str),
				"GET " BFLETS_DNS_PROXY_PATH "?q=%s&ipv6=%u\r\n"
				"\r\n",
				hostname, ipv6, connect_hostname2);

			if (SendAll(s, request_str, StrLen(request_str), true))
			{
				if (*cancel == false)
				{
					BUF *recv_buf = NewBuf();
					UINT port_ret;

					while (true)
					{
						UCHAR tmp[MAX_SIZE];
						UINT r;

						r = Recv(s, tmp, sizeof(tmp), true);

						if (r == 0 || (recv_buf->Size > 65536))
						{
							break;
						}
						else
						{
							WriteBuf(recv_buf, tmp, r);
						}
					}

					ret = RUDPParseIPAndPortStr(recv_buf->Buf, recv_buf->Size, ip_ret, &port_ret);

					FreeBuf(recv_buf);
				}
			}
		}

		FreeBuf(hash2);
	}

	Disconnect(s);
	ReleaseSock(s);

	if (ret)
	{
		NewDnsCache(hostname, ip_ret);
	}

	return ret;
}

// Get the IP address of the available DNS proxy in B-FLET'S service that is provided by NTT East of Japan
bool GetDnsProxyIPAddressForJapanBFlets(IP *ip_ret, UINT timeout, bool *cancel)
{
	BUF *b;
	LIST *o;
	bool ret = false;
	// Validate arguments
	if (ip_ret == NULL)
	{
		return false;
	}
	if (timeout == 0)
	{
		timeout = BFLETS_DNS_PROXY_TIMEOUT_FOR_GET_F;
	}

	b = QueryFileByUdpForJapanBFlets(timeout, cancel);

	if (b == NULL)
	{
		return false;
	}

	o = ReadIni(b);

	if (o != NULL)
	{
		INI_ENTRY *e = GetIniEntry(o, "DDnsServerForBFlets");

		if (e != NULL)
		{
			char *s = e->Value;

			if (IsEmptyStr(s) == false)
			{
				IP ip;

				if (StrToIP(&ip, s))
				{
					if (IsZeroIp(&ip) == false)
					{
						Copy(ip_ret, &ip, sizeof(IP));
						ret = true;
					}
				}
			}
		}
	}

	FreeIni(o);
	FreeBuf(b);

	return ret;
}

// Get a valid F.txt file in B-FLET'S service that is provided by NTT East of Japan
BUF *QueryFileByUdpForJapanBFlets(UINT timeout, bool *cancel)
{
	bool dummy_flag = false;
	BUF *txt_buf = NULL;
	BUF *ret = NULL;
	LIST *ip_list = NULL;
	UINT i;
	// Validate arguments
	if (cancel == NULL)
	{
		cancel = &dummy_flag;
	}
	if (timeout == 0)
	{
		timeout = BFLETS_DNS_PROXY_TIMEOUT_FOR_GET_F;
	}

	txt_buf = ReadDump(UDP_FILE_QUERY_BFLETS_TXT_FILENAME);
	if (txt_buf == NULL)
	{
		return NULL;
	}

	ip_list = NewListFast(NULL);

	while (true)
	{
		char *line = CfgReadNextLine(txt_buf);
		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false && StartWith(line, "#") == false)
		{
			IP ip;

			if (StrToIP6(&ip, line))
			{
				if (IsZeroIp(&ip) == false)
				{
					if (IsIPv6LocalNetworkAddress(&ip) == false)
					{
						Add(ip_list, Clone(&ip, sizeof(IP)));
					}
				}
			}
		}

		Free(line);
	}

	FreeBuf(txt_buf);

	ret = QueryFileByIPv6Udp(ip_list, timeout, cancel);

	for (i = 0;i < LIST_NUM(ip_list);i++)
	{
		IP *ip = LIST_DATA(ip_list, i);

		Free(ip);
	}

	ReleaseList(ip_list);

	return ret;
}

// Request a file by UDP (send the requests to the multiple IP addresses at the same time)
BUF *QueryFileByIPv6Udp(LIST *ip_list, UINT timeout, bool *cancel)
{
	bool dummy_flag = false;
	UINT64 start_tick, giveup_tick;
	UINT64 next_send_tick;
	SOCK *s;
	INTERRUPT_MANAGER *interrupt;
	BUF *buf = NULL;
	SOCK_EVENT *se;
	UCHAR *tmp_buf;
	UINT tmp_buf_size = 65535;
	// Validate arguments
	if (cancel == NULL)
	{
		cancel = &dummy_flag;
	}
	if (ip_list == NULL)
	{
		return NULL;
	}

	s = NewUDP6(0, NULL);
	if (s == NULL)
	{
		return NULL;
	}

	tmp_buf = Malloc(tmp_buf_size);

	start_tick = Tick64();
	giveup_tick = start_tick + (UINT64)timeout;
	next_send_tick = 0;

	interrupt = NewInterruptManager();

	AddInterrupt(interrupt, giveup_tick);

	se = NewSockEvent();
	JoinSockToSockEvent(s, se);

	while (true)
	{
		UINT64 now = Tick64();

		if (now >= giveup_tick)
		{
			// Time-out
			break;
		}

		if (*cancel)
		{
			// User canceled
			break;
		}

		// Receive
		while (true)
		{
			IP src_ip;
			UINT src_port;
			UINT r;

			r = RecvFrom(s, &src_ip, &src_port, tmp_buf, tmp_buf_size);

			if (r == SOCK_LATER || r == 0)
			{
				break;
			}

			if (src_port == UDP_FILE_QUERY_DST_PORT)
			{
				if (r >= 40)
				{
					if (Cmp(tmp_buf, UDP_FILE_QUERY_MAGIC_NUMBER, StrLen(UDP_FILE_QUERY_MAGIC_NUMBER)) == 0)
					{
						// Successful reception
						buf = NewBuf();
						WriteBuf(buf, tmp_buf, r);
						SeekBuf(buf, 0, 0);
						break;
					}
				}
			}
		}

		if (buf != NULL)
		{
			// Successful reception
			break;
		}

		if (next_send_tick == 0 || (now >= next_send_tick))
		{
			// Transmission
			UINT i;
			for (i = 0;i < LIST_NUM(ip_list);i++)
			{
				IP *ip = LIST_DATA(ip_list, i);
				UCHAR c = 'F';

				SendTo(s, ip, UDP_FILE_QUERY_DST_PORT, &c, 1);
			}

			next_send_tick = now + (UINT64)UDP_FILE_QUERY_RETRY_INTERVAL;
			AddInterrupt(interrupt, next_send_tick);
		}

		WaitSockEvent(se, GetNextIntervalForInterrupt(interrupt));
	}

	FreeInterruptManager(interrupt);

	Disconnect(s);
	ReleaseSock(s);

	ReleaseSockEvent(se);

	Free(tmp_buf);

	return buf;
}

// Parse the user name of the NT
void ParseNtUsername(char *src_username, char *dst_username, UINT dst_username_size, char *dst_domain, UINT dst_domain_size, bool do_not_parse_atmark)
{
	char tmp_username[MAX_SIZE];
	char tmp_domain[MAX_SIZE];
	TOKEN_LIST *t;

	if (src_username != dst_username)
	{
		ClearStr(dst_username, dst_username_size);
	}

	ClearStr(dst_domain, dst_domain_size);
	// Validate arguments
	if (src_username == NULL || dst_username == NULL || dst_domain == NULL)
	{
		return;
	}

	StrCpy(tmp_username, sizeof(tmp_username), src_username);
	ClearStr(tmp_domain, sizeof(tmp_domain));

	// Analysis of username@domain.name format
	if (do_not_parse_atmark == false)
	{
		t = ParseTokenWithNullStr(tmp_username, "@");
		if (t->NumTokens >= 1)
		{
			StrCpy(tmp_username, sizeof(tmp_username), t->Token[0]);
		}
		if (t->NumTokens >= 2)
		{
			StrCpy(tmp_domain, sizeof(tmp_domain), t->Token[1]);
		}
		FreeToken(t);
	}

	// If the username part is in "domain\username" format, split it
	t = ParseTokenWithNullStr(tmp_username, "\\");
	if (t->NumTokens >= 2)
	{
		if (IsEmptyStr(tmp_domain))
		{
			StrCpy(tmp_domain, sizeof(tmp_domain), t->Token[0]);
		}

		StrCpy(tmp_username, sizeof(tmp_username), t->Token[1]);
	}
	FreeToken(t);

	StrCpy(dst_username, dst_username_size, tmp_username);
	StrCpy(dst_domain, dst_domain_size, tmp_domain);
}

// The calculation of the optimum MSS value for use in TCP/IP packet in the payload of bulk transfer in R-UDP session
UINT RUDPCalcBestMssForBulk(RUDP_STACK *r, RUDP_SESSION *se)
{
	UINT ret;
	// Validate arguments
	if (r == NULL || se == NULL)
	{
		return 0;
	}

	ret = MTU_FOR_PPPOE;

	// IPv4
	if (IsIP6(&se->YourIp) == false)
	{
		ret -= 20;
	}
	else
	{
		ret -= 40;
	}

	if (r->Protocol == RUDP_PROTOCOL_ICMP)
	{
		// ICMP
		ret -= 8;

		ret -= SHA1_SIZE;
	}
	else if (r->Protocol == RUDP_PROTOCOL_DNS)
	{
		// UDP
		ret -= 8;

		// DNS
		ret -= 42;
	}

	// IV
	ret -= SHA1_SIZE;

	// Sign
	ret -= SHA1_SIZE;

	// SEQ_NO
	ret -= sizeof(UINT64);

	// Padding Max
	ret -= 31;

	// Ethernet header (target packets of communication)
	ret -= 14;

	// IPv4 Header (target packet of communication)
	ret -= 20;

	// TCP header (target packet of communication)
	ret -= 20;

	// I don't know well, but subtract 24 bytes
	ret -= 24;

	return ret;
}

// Processing of the reply packet from the NAT-T server
void RUDPProcess_NatT_Recv(RUDP_STACK *r, UDPPACKET *udp)
{
	BUF *b;
	PACK *p;
	// Validate arguments
	if (r == NULL || udp == NULL)
	{
		return;
	}

	if (udp->Size >= 8)
	{
		char tmp[128];

		Zero(tmp, sizeof(tmp));
		Copy(tmp, udp->Data, MIN(udp->Size, sizeof(tmp) - 1));

		if (StartWith(tmp, "IP="))
		{
			IP my_ip;
			UINT my_port;

			// There was a response to the packet to determine the NAT state
			if (IsEmptyStr(r->NatT_Registered_IPAndPort) == false)
			{
				if (StrCmpi(r->NatT_Registered_IPAndPort, tmp) != 0)
				{
					// Redo getting the token and registration because the NAT state is changed
					ClearStr(r->NatT_Registered_IPAndPort, sizeof(r->NatT_Registered_IPAndPort));

					r->NatT_GetTokenNextTick = 0;
					r->NatT_GetTokenFailNum = 0;
					r->NatT_Token_Ok = false;
					Zero(r->NatT_Token, sizeof(r->NatT_Token));

					r->NatT_RegisterNextTick = 0;
					r->NatT_RegisterFailNum = 0;
					r->NatT_Register_Ok = false;
				}
			}

			if (RUDPParseIPAndPortStr(udp->Data, udp->Size, &my_ip, &my_port))
			{
				if (r->NatTGlobalUdpPort != NULL)
				{
					*r->NatTGlobalUdpPort = my_port;
				}
			}

			return;
		}
	}

	// Interpret the UDP packet
	b = NewBuf();
	WriteBuf(b, udp->Data, udp->Size);
	SeekBuf(b, 0, 0);

	p = BufToPack(b);

	if (p != NULL)
	{
		bool is_ok = PackGetBool(p, "ok");
		UINT64 tran_id = PackGetInt64(p, "tran_id");

		ExtractAndApplyDynList(p);

		if (r->ServerMode)
		{
			if (PackCmpStr(p, "opcode", "get_token"))
			{
				// Get the Token
				if (is_ok && (tran_id == r->NatT_TranId))
				{
					char tmp[MAX_SIZE];

					if (PackGetStr(p, "token", tmp, sizeof(tmp)) && IsEmptyStr(tmp) == false)
					{
						char myip[MAX_SIZE];
						// Acquisition success
						StrCpy(r->NatT_Token, sizeof(r->NatT_Token), tmp);
						r->NatT_Token_Ok = true;
						r->NatT_GetTokenNextTick = r->Now + (UINT64)GenRandInterval(UDP_NAT_T_GET_TOKEN_INTERVAL_2_MIN, UDP_NAT_T_GET_TOKEN_INTERVAL_2_MAX);
						r->NatT_GetTokenFailNum = 0;

						// Since success to obtain the self global IPv4 address,
						// re-obtain the destination NAT-T host from this IPv4 address
						if (PackGetStr(p, "your_ip", myip, sizeof(myip)))
						{
							IP ip;
							char new_hostname[MAX_SIZE];

							StrToIP(&ip, myip);

							SetCurrentGlobalIP(&ip, false);

							RUDPGetRegisterHostNameByIP(new_hostname,
								sizeof(new_hostname), &ip);

							Lock(r->Lock);
							{
								if (StrCmpi(r->CurrentRegisterHostname, new_hostname) != 0)
								{
									r->NumChangedHostname++;

									if (r->NumChangedHostname <= RUDP_NATT_MAX_CONT_CHANGE_HOSTNAME)
									{
										if (r->NumChangedHostnameValueResetTick == 0)
										{
											r->NumChangedHostnameValueResetTick = r->Now + (UINT64)RUDP_NATT_CONT_CHANGE_HOSTNAME_RESET_INTERVAL;
										}

										// Change the host name
										Debug("CurrentRegisterHostname Changed: New=%s\n", new_hostname);
										StrCpy(r->CurrentRegisterHostname, sizeof(r->CurrentRegisterHostname), new_hostname);

										Zero(&r->NatT_IP, sizeof(r->NatT_IP));
										//Zero(&r->NatT_IP_Safe, sizeof(r->NatT_IP_Safe));

										Set(r->HaltEvent);
									}
									else
									{
										if (r->NumChangedHostnameValueResetTick == 0)
										{
											r->NumChangedHostnameValueResetTick = r->Now + (UINT64)RUDP_NATT_CONT_CHANGE_HOSTNAME_RESET_INTERVAL;
										}

										if (r->Now >= r->NumChangedHostnameValueResetTick)
										{
											r->NumChangedHostname = 0;
											r->NumChangedHostnameValueResetTick = 0;
										}
									}
								}
								else
								{
									r->NumChangedHostname = 0;
									r->NumChangedHostnameValueResetTick = 0;
								}
							}
							Unlock(r->Lock);
						}

						AddInterrupt(r->Interrupt, r->NatT_GetTokenNextTick);
					}
				}
			}
			else if (PackCmpStr(p, "opcode", "nat_t_register"))
			{
				// NAT-T server registration result
				if (is_ok && (tran_id == r->NatT_TranId))
				{
					UINT my_global_port;
					// Successful registration
					r->NatT_Register_Ok = true;
					r->NatT_RegisterNextTick = r->Now + (UINT64)GenRandInterval(UDP_NAT_T_REGISTER_INTERVAL_MIN, UDP_NAT_T_REGISTER_INTERVAL_MAX);
					r->NatT_RegisterFailNum = 0;

					Debug("NAT-T Registered.\n");

					// Save the IP address and port number at the time of registration
					PackGetStr(p, "your_ip_and_port", r->NatT_Registered_IPAndPort, sizeof(r->NatT_Registered_IPAndPort));

					if (g_source_ip_validation_force_disable == false)
					{
						// Enable the source IP address validation mechanism
						r->NatT_EnableSourceIpValidation = PackGetBool(p, "enable_source_ip_validation");

					}
					else
					{
						// Force disable the source IP address validation mechanism
						r->NatT_EnableSourceIpValidation = false;
					}

					// Global port of itself
					my_global_port = PackGetInt(p, "your_port");

					if (my_global_port != 0)
					{
						if (r->NatTGlobalUdpPort != NULL)
						{
							*r->NatTGlobalUdpPort = my_global_port;
						}
					}

					AddInterrupt(r->Interrupt, r->NatT_RegisterNextTick);
				}
			}
			else if (PackCmpStr(p, "opcode", "nat_t_connect_relay"))
			{
				// Connection request from the client via the NAT-T server
				if (is_ok && (PackGetInt64(p, "session_key") == r->NatT_SessionKey))
				{
					char client_ip_str[MAX_SIZE];
					UINT client_port;
					IP client_ip;

					PackGetStr(p, "client_ip", client_ip_str, sizeof(client_ip_str));
					client_port = PackGetInt(p, "client_port");
					StrToIP(&client_ip, client_ip_str);

					if (IsZeroIp(&client_ip) == false && client_port != 0)
					{
						UCHAR *rand_data;
						UINT rand_size;

						if (r->NatT_EnableSourceIpValidation)
						{
							RUDPAddIpToValidateList(r, &client_ip);
						}

						rand_size = Rand32() % 19;
						rand_data = Malloc(rand_size);

						Rand(rand_data, rand_size);

						RUDPSendPacket(r, &client_ip, client_port, rand_data, rand_size, 0);

						Free(rand_data);
					}
				}
			}
		}

		FreePack(p);
	}

	FreeBuf(b);
}

// Set the flag of the source IP address validation function
void RUDPSetSourceIpValidationForceDisable(bool b)
{
	g_source_ip_validation_force_disable = b;
}

// Process such as packet transmission for NAT-T server
void RUDPDo_NatT_Interrupt(RUDP_STACK *r)
{
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	if (r->ServerMode)
	{

		if (g_no_rudp_register == false && IsZeroIp(&r->NatT_IP_Safe) == false)
		{
			if (r->NatT_GetTokenNextTick == 0 || r->Now >= r->NatT_GetTokenNextTick)
			{
				// Try to get a token from the NAT-T server periodically
				PACK *p = NewPack();
				BUF *b;

				PackAddStr(p, "opcode", "get_token");
				PackAddInt64(p, "tran_id", r->NatT_TranId);
				PackAddInt(p, "nat_traversal_version", UDP_NAT_TRAVERSAL_VERSION);

				b = PackToBuf(p);
				FreePack(p);

				RUDPSendPacket(r, &r->NatT_IP_Safe, UDP_NAT_T_PORT, b->Buf, b->Size, 0);

				FreeBuf(b);

				// Determine the next acquisition time
				r->NatT_GetTokenFailNum++;
				r->NatT_GetTokenNextTick = r->Now + (UINT64)(UDP_NAT_T_GET_TOKEN_INTERVAL_1 * (UINT64)MIN(r->NatT_GetTokenFailNum, UDP_NAT_T_GET_TOKEN_INTERVAL_FAIL_MAX));
				AddInterrupt(r->Interrupt, r->NatT_GetTokenNextTick);
				r->NatT_Token_Ok = false;
			}
		}

		{
			if (IsZeroIp(&r->NatT_IP_Safe) == false)
			{
				// Normal servers: Send request packets to the NAT-T server
				if (r->NatT_NextNatStatusCheckTick == 0 || r->Now >= r->NatT_NextNatStatusCheckTick)
				{
					UCHAR a = 'A';
					UINT ddns_hash;
					// Check of the NAT state
					RUDPSendPacket(r, &r->NatT_IP_Safe, UDP_NAT_T_PORT, &a, 1, 0);

					// Execution time of the next
					r->NatT_NextNatStatusCheckTick = r->Now + (UINT64)GenRandInterval(UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MIN, UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MAX);
					AddInterrupt(r->Interrupt, r->NatT_NextNatStatusCheckTick);

					// Check whether the DDNS host name changing have not occurred
					ddns_hash = GetCurrentDDnsFqdnHash();

					if (r->LastDDnsFqdnHash != ddns_hash)
					{
						r->LastDDnsFqdnHash = ddns_hash;
						// Do the Register immediately if there is a change in the DDNS host name
						r->NatT_RegisterNextTick = 0;
					}
				}
			}
		}

		if (r->NatT_Token_Ok && g_no_rudp_register == false && IsZeroIp(&r->NatT_IP_Safe) == false)
		{
			if (r->NatT_RegisterNextTick == 0 || r->Now >= r->NatT_RegisterNextTick)
			{
				// Try to register itself periodically for NAT-T server
				PACK *p = NewPack();
				BUF *b;
				char private_ip_str[MAX_SIZE];
				char machine_key[MAX_SIZE];
				char machine_name[MAX_SIZE];
				UCHAR hash[SHA1_SIZE];
				char ddns_fqdn[MAX_SIZE];

				Debug("NAT-T Registering...\n");

				GetCurrentDDnsFqdn(ddns_fqdn, sizeof(ddns_fqdn));

				PackAddStr(p, "opcode", "nat_t_register");
				PackAddInt64(p, "tran_id", r->NatT_TranId);
				PackAddStr(p, "token", r->NatT_Token);
				PackAddStr(p, "svc_name", r->SvcName);
				PackAddStr(p, "product_str", CEDAR_PRODUCT_STR);
				PackAddInt64(p, "session_key", r->NatT_SessionKey);
				PackAddInt(p, "nat_traversal_version", UDP_NAT_TRAVERSAL_VERSION);


				if (g_natt_low_priority)
				{
					PackAddBool(p, "low_priority", g_natt_low_priority);
				}

				Zero(private_ip_str, sizeof(private_ip_str));
				if (IsZeroIp(&r->My_Private_IP_Safe) == false)
				{
					IPToStr(private_ip_str, sizeof(private_ip_str), &r->My_Private_IP_Safe);
					PackAddStr(p, "private_ip", private_ip_str);
				}

				PackAddInt(p, "private_port", r->UdpSock->LocalPort);

				Zero(hash, sizeof(hash));
				GetCurrentMachineIpProcessHash(hash);
				BinToStr(machine_key, sizeof(machine_key), hash, sizeof(hash));
				PackAddStr(p, "machine_key", machine_key);

				Zero(machine_name, sizeof(machine_name));
				GetMachineName(machine_name, sizeof(machine_name));
				PackAddStr(p, "host_name", machine_name);
				PackAddStr(p, "ddns_fqdn", ddns_fqdn);

				b = PackToBuf(p);
				FreePack(p);

				RUDPSendPacket(r, &r->NatT_IP_Safe, UDP_NAT_T_PORT, b->Buf, b->Size, 0);
				//RUDPSendPacket(r, &r->NatT_IP_Safe, UDP_NAT_T_PORT, "a", 1);

				FreeBuf(b);

				// Determine the next acquisition time
				r->NatT_RegisterFailNum++;
				r->NatT_RegisterNextTick = r->Now + (UINT64)UDP_NAT_T_REGISTER_INTERVAL_INITIAL * (UINT64)MIN(r->NatT_RegisterFailNum, UDP_NAT_T_REGISTER_INTERVAL_FAIL_MAX);
				AddInterrupt(r->Interrupt, r->NatT_RegisterNextTick);
				r->NatT_Register_Ok = false;
			}
		}
	}
}

// R-UDP packet reception procedure
void RUDPRecvProc(RUDP_STACK *r, UDPPACKET *p)
{
	RUDP_SESSION *se = NULL;
	// Validate arguments
	if (r == NULL || p == NULL)
	{
		return;
	}

	if (r->ServerMode)
	{
		if (g_no_rudp_server)
		{
			return;
		}
	}

	if (r->ServerMode && r->NoNatTRegister == false)
	{

		if (p->SrcPort == UDP_NAT_T_PORT && CmpIpAddr(&p->SrcIP, &r->NatT_IP_Safe) == 0)
		{
			// There was a response from the NAT-T server
			RUDPProcess_NatT_Recv(r, p);
			return;
		}
	}

	if (r->ServerMode)
	{
		if (r->ProcRpcRecv != NULL)
		{
			if (r->ProcRpcRecv(r, p))
			{
				return;
			}
		}
	}

	if (r->ServerMode)
	{
		// Search the session by the end-point information if in the server mode
		se = RUDPSearchSession(r, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort);
	}
	else
	{
		// Session should exist only one in the case of client mode
		if (LIST_NUM(r->SessionList) >= 1)
		{
			se = LIST_DATA(r->SessionList, 0);
		}
		else
		{
			se = NULL;
		}
	}

	if (p->Size < 20)
	{
		// The received packet is too small
		if (r->ServerMode == false)
		{
			if (se != NULL && se->Status == RUDP_SESSION_STATUS_CONNECT_SENT)
			{
				if (CmpIpAddr(&se->YourIp, &p->SrcIP) == 0)
				{
					// If the connection initialization packet which is shorter than 20 bytes
					// has been received from the server side, overwrite the source port number
					// of the packet to the client-side session information (for some NAT)
					se->YourPort = p->SrcPort;
				}
			}
		}
		return;
	}

	if (se == NULL && r->ServerMode && p->Size >= 40)
	{
		// Corresponding to a sudden change of port number on the client side.
		// The target session is a session which matches the client side IP address
		// and the key and the signature is verified
		UINT i;
		for (i = 0; i < LIST_NUM(r->SessionList);i++)
		{
			RUDP_SESSION *s = LIST_DATA(r->SessionList, i);

			if (CmpIpAddr(&s->YourIp, &p->SrcIP) == 0)
			{
				if (RUDPCheckSignOfRecvPacket(r, s, p->Data, p->Size))
				{
					// Signature matched
					se = s;
					break;
				}
			}
		}
	}

	if (se == NULL)
	{
		// There is no session
		if (r->ServerMode)
		{
			if (p->Size < 40)
			{
				bool ok = true;
				UCHAR ctoken_hash[SHA1_SIZE];

				Zero(ctoken_hash, sizeof(ctoken_hash));

				// Examine the quota of new session creation
				if (LIST_NUM(r->SessionList) >= RUDP_QUOTA_MAX_NUM_SESSIONS)
				{
					// Entire number of sessions exceeds the limit
					ok = false;
				}
				else if (r->NatT_EnableSourceIpValidation && RUDPIsIpInValidateList(r, &p->SrcIP) == false)
				{
					// Invalid source IP address, which is not registered on the validated source IP address list
					ok = false;
				}
				else
				{
					UINT i;
					// Check the number of sessions per IP address
					UINT num = 0;

					for (i = 0;i < LIST_NUM(r->SessionList);i++)
					{
						RUDP_SESSION *se = LIST_DATA(r->SessionList, i);

						if (CmpIpAddr(&se->YourIp, &p->SrcIP) == 0)
						{
							num++;
						}
					}

					if (num >= RUDP_QUOTA_MAX_NUM_SESSIONS_PER_IP)
					{
						// Limit exceeded the number of sessions per IP address
						ok = false;
					}
				}


				if (ok)
				{
					char ip_str[64];

					// Create a session since a new session creation request packet was received
					se = RUDPNewSession(true, &p->DstIP, p->DestPort, &p->SrcIP, p->SrcPort, p->Data);
					se->Status = RUDP_SESSION_STATUS_ESTABLISHED;
					Insert(r->SessionList, se);

					IPToStr(ip_str, sizeof(ip_str), &p->SrcIP);
					Debug("RUDPNewSession %X %s:%u\n", se, ip_str, p->SrcPort);

					if (r->Protocol == RUDP_PROTOCOL_ICMP)
					{
						// In case of ICMP, save the ICMP TYPE number to use
						se->Icmp_Type = (p->Type == ICMP_TYPE_INFORMATION_REQUEST ? ICMP_TYPE_INFORMATION_REPLY : p->Type);
					}
					else if (r->Protocol == RUDP_PROTOCOL_DNS)
					{
						// Save the Tran ID to be used if it's a DNS
						se->Dns_TranId = (USHORT)p->Type;
					}
				}
			}
		}
	}
	else
	{
		if (p->Size < 40)
		{
			if (r->ServerMode)
			{
				if (Cmp(se->Key_Init, p->Data, SHA1_SIZE) == 0)
				{
					// New session creation request packet have received more than once. reply an ACK immediately for second and subsequent
					se->LastSentTick = 0;

					// Update the endpoint information
					Copy(&se->YourIp, &p->SrcIP, sizeof(IP));
					se->YourPort = p->SrcPort;

					if (r->Protocol == RUDP_PROTOCOL_ICMP)
					{
						// In case of ICMP, save the ICMP TYPE number to use
						se->Icmp_Type = (p->Type == ICMP_TYPE_INFORMATION_REQUEST ? ICMP_TYPE_INFORMATION_REPLY : p->Type);
					}
					else if (r->Protocol == RUDP_PROTOCOL_DNS)
					{
						// Save the Tran ID to be used if it's a DNS
						se->Dns_TranId = (USHORT)p->Type;
					}
				}
				else
				{
					// Since the different session creation request packet have been received from the same end point, ignore it
				}
			}
		}
		else
		{
			// Process the received packet
			if (RUDPProcessRecvPacket(r, se, p->Data, p->Size) || RUDPProcessBulkRecvPacket(r, se, p->Data, p->Size))
			{
				// Update endpoint information (only the port number)
				//Copy(&se->YourIp, &p->SrcIP, sizeof(IP));
				se->YourPort = p->SrcPort;

				if (r->Protocol == RUDP_PROTOCOL_ICMP)
				{
					// In case of ICMP, save the ICMP TYPE number to use
					if (r->ServerMode)
					{
						se->Icmp_Type = (p->Type == ICMP_TYPE_INFORMATION_REQUEST ? ICMP_TYPE_INFORMATION_REPLY : p->Type);
					}
					else
					{
						se->Icmp_Type = (p->Type == ICMP_TYPE_INFORMATION_REPLY ? ICMP_TYPE_INFORMATION_REQUEST : p->Type);
					}
				}
				else if (r->Protocol == RUDP_PROTOCOL_DNS)
				{
					if (r->ServerMode)
					{
						// Save the Tran ID to be used if it's a DNS
						se->Dns_TranId = (USHORT)p->Type;
					}
				}
			}
		}
	}
}

// Check whether the specificed IP address is in the validated source IP address list
bool RUDPIsIpInValidateList(RUDP_STACK *r, IP *ip)
{
	UINT i;
	UINT64 now = Tick64();
	LIST *o = NULL;
	bool ret = false;
	// Validate arguments
	if (r == NULL || ip == NULL)
	{
		return false;
	}

	// Always allow private IP addresses
	if (IsIPPrivate(ip))
	{
		return true;
	}

	if (IsIPAddressInSameLocalNetwork(ip))
	{
		return true;
	}

	for (i = 0;i < LIST_NUM(r->NatT_SourceIpList);i++)
	{
		RUDP_SOURCE_IP *s = (RUDP_SOURCE_IP *)LIST_DATA(r->NatT_SourceIpList, i);

		if (s->ExpiresTick <= now)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Add(o, s);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			RUDP_SOURCE_IP *s = (RUDP_SOURCE_IP *)LIST_DATA(o, i);

			Delete(r->NatT_SourceIpList, s);

			Free(s);
		}

		ReleaseList(o);
	}

	for (i = 0;i < LIST_NUM(r->NatT_SourceIpList);i++)
	{
		RUDP_SOURCE_IP *s = (RUDP_SOURCE_IP *)LIST_DATA(r->NatT_SourceIpList, i);

		if (CmpIpAddr(&s->ClientIP, ip) == 0)
		{
			ret = true;
			break;
		}
	}

	Debug("RUDP: NAT-T: Validate IP: %r, ret=%u (current list len = %u)\n", ip, ret, LIST_NUM(r->NatT_SourceIpList));

	return ret;
}

// Add an IP address to the validated source IP address list
void RUDPAddIpToValidateList(RUDP_STACK *r, IP *ip)
{
	UINT i;
	RUDP_SOURCE_IP *sip;
	UINT64 now = Tick64();
	LIST *o = NULL;
	// Validate arguments
	if (r == NULL || ip == NULL)
	{
		return;
	}

	if (LIST_NUM(r->NatT_SourceIpList) >= RUDP_MAX_VALIDATED_SOURCE_IP_ADDRESSES)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(r->NatT_SourceIpList);i++)
	{
		RUDP_SOURCE_IP *s = (RUDP_SOURCE_IP *)LIST_DATA(r->NatT_SourceIpList, i);

		if (s->ExpiresTick <= now)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Add(o, s);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			RUDP_SOURCE_IP *s = (RUDP_SOURCE_IP *)LIST_DATA(o, i);

			Delete(r->NatT_SourceIpList, s);

			Free(s);
		}

		ReleaseList(o);
	}

	sip = NULL;

	for (i = 0;i < LIST_NUM(r->NatT_SourceIpList);i++)
	{
		RUDP_SOURCE_IP *s = (RUDP_SOURCE_IP *)LIST_DATA(r->NatT_SourceIpList, i);

		if (CmpIpAddr(&s->ClientIP, ip) == 0)
		{
			sip = s;
			break;
		}
	}

	if (sip == NULL)
	{
		sip = ZeroMalloc(sizeof(RUDP_SOURCE_IP));

		Copy(&sip->ClientIP, ip, sizeof(IP));

		Add(r->NatT_SourceIpList, sip);
	}

	sip->ExpiresTick = now + (UINT64)RUDP_VALIDATED_SOURCE_IP_ADDRESS_EXPIRES;

	Debug("RUDP: NAT-T: Src IP added: %r (current list len = %u)\n", ip, LIST_NUM(r->NatT_SourceIpList));
}

// R-UDP interrupt processing procedure
void RUDPInterruptProc(RUDP_STACK *r)
{
	UINT i;
	LIST *o;
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	// Packet transmission and other process for NAT-T server
	if (r->NoNatTRegister == false)
	{
		RUDPDo_NatT_Interrupt(r);
	}

	if (r->ServerMode == false)
	{
		if (r->ClientInitiated == false)
		{
			bool client_target_inited = false;
			Lock(r->Lock);
			{
				client_target_inited = r->TargetIpAndPortInited;
			}
			Unlock(r->Lock);

			if (client_target_inited)
			{
				// Start a connection when there is the end point information of the destination server to connect as a client
				RUDP_SESSION *se;
				UCHAR init_key[SHA1_SIZE];
				char ip_str[128];
				UINT64 ui;

				Rand(init_key, SHA1_SIZE);

				se = RUDPNewSession(false, &r->UdpSock->LocalIP, r->UdpSock->LocalPort,
					&r->TargetIp, r->TargetPort, init_key);

				IPToStr(ip_str, sizeof(ip_str), &r->TargetIp);
				Debug("RUDPNewSession %X %s:%u\n", se, ip_str, r->TargetPort);

				Insert(r->SessionList, se);

				ui = Endian64(se->Magic_Disconnect);
				WriteFifo(se->SendFifo, &ui, sizeof(UINT64));

				r->ClientInitiated = true;
			}
		}
	}

	// Process for all the sessions
	for (i = 0;i < LIST_NUM(r->SessionList);i++)
	{
		RUDP_SESSION *se = LIST_DATA(r->SessionList, i);

		if (r->Halt)
		{
			// Disconnect all the sessions if the R-UDP stack stopped
			RUDPDisconnectSession(r, se, false);
		}

		if (se->FlushBulkSendTube)
		{
			if (se->TcpSock != NULL && se->TcpSock->BulkSendTube != NULL)
			{
				TubeFlush(se->TcpSock->BulkSendTube);
			}

			se->FlushBulkSendTube = false;
		}

		if (se->Status == RUDP_SESSION_STATUS_ESTABLISHED)
		{
			// Process for all of the sessions which is established a connection
			UINT j;

			if (r->Now >= (se->LatestRecvMyTick + (UINT64)RUDP_TIMEOUT))
			{
				// Disconnect the session because the fully communication failure is detected for a while
				Debug("R-UDP Session %X Timed Out.\n", se);

				RUDPDisconnectSession(r, se, false);
			}

			// If there are received segments, read to the part that has arrived in succession
			if (FifoSize(se->RecvFifo) <= RUDP_MAX_FIFO_SIZE)
			{
				LIST *o;
				UINT64 current_seq_no;

				o = NULL;
				current_seq_no = se->LastRecvCompleteSeqNo;
				for (j = 0;j < LIST_NUM(se->RecvSegmentList);j++)
				{
					RUDP_SEGMENT *s;

					current_seq_no++;

					s = LIST_DATA(se->RecvSegmentList, j);

					if (s->SeqNo == current_seq_no)
					{
#ifdef	RUDP_DETAIL_LOG
						Debug("%X s->SeqNo = %I64u, current_seq_no = %I64u\n", se, s->SeqNo, current_seq_no);
#endif	// RUDP_DETAIL_LOG

						if (s->Size == sizeof(se->Magic_KeepAliveRequest) && Cmp(s->Data, se->Magic_KeepAliveRequest, sizeof(se->Magic_KeepAliveRequest)) == 0)
						{
							// Receive the KeepAlive Request
#ifdef	RUDP_DETAIL_LOG
							Debug("Recv KeepAlive Request\n");
#endif	// RUDP_DETAIL_LOG

							// Send a KeepAlive Response if the transmisson queue is empty
							if (LIST_NUM(se->SendSegmentList) == 0)
							{
#ifdef	RUDP_DETAIL_LOG
								Debug("Send KeepAlive Response\n");
#endif	// RUDP_DETAIL_LOG

								RUDPSendSegment(r, se, se->Magic_KeepAliveResponse, sizeof(se->Magic_KeepAliveResponse));
							}
						}
						else if (s->Size == sizeof(se->Magic_KeepAliveResponse) && Cmp(s->Data, se->Magic_KeepAliveResponse, sizeof(se->Magic_KeepAliveResponse)) == 0)
						{
							// Receive the KeepAlive Response
#ifdef	RUDP_DETAIL_LOG
							Debug("Recv KeepAlive Response\n");
#endif	// RUDP_DETAIL_LOG
						}
						else
						{
							// Write to the receive FIFO
							WriteFifo(se->RecvFifo, s->Data, s->Size);
						}
						r->TotalLogicalReceived += s->Size;

						// Advance the SEQ NO which has been received completely
						se->LastRecvCompleteSeqNo = s->SeqNo;

						// Add to the Delete list
						if (o == NULL)
						{
							o = NewListFast(NULL);
						}
						Add(o, s);
					}
					else
					{
						// Continuous reading is interrupted
#ifdef	RUDP_DETAIL_LOG
						Debug("%X s->SeqNo = %I64u, current_seq_no = %I64u\n", se, s->SeqNo, current_seq_no);
						WHERE;
#endif	// RUDP_DETAIL_LOG
						break;
					}
				}

				// Delete the segment which has been received completely
				if (o != NULL)
				{
					for (j = 0;j < LIST_NUM(o);j++)
					{
						RUDP_SEGMENT *s = LIST_DATA(o, j);

						Delete(se->RecvSegmentList, s);
						Free(s);
					}
					ReleaseList(o);
				}
			}

			if (r->ServerMode && se->Magic_Disconnect == 0)
			{
				if (FifoSize(se->RecvFifo) >= sizeof(UINT64))
				{
					UINT64 ui;

					if (ReadFifo(se->RecvFifo, &ui, sizeof(UINT64)) == sizeof(UINT64))
					{
						ui = Endian64(ui);

						if ((ui & 0xffffffff00000000ULL) != 0ULL)
						{
							se->Magic_Disconnect = ui;
						}
					}
				}
			}

			// If the data remains in FIFO, write it to the TCP socket as possible
			if (r->ServerMode == false || se->Magic_Disconnect != 0)
			{
				while (FifoSize(se->RecvFifo) >= 1)
				{
					UINT ret;

					RUDPInitSock(r, se);

					ret = Send(se->TcpSock, FifoPtr(se->RecvFifo), FifoSize(se->RecvFifo), false);

					if (ret == SOCK_LATER)
					{
						// Can not write any more
						break;
					}
					else if (ret == 0)
					{
						// Disconnected
						Disconnect(se->TcpSock);
						RUDPDisconnectSession(r, se, false);
						break;
					}
					else
					{
						// Writing success
						ReadFifo(se->RecvFifo, NULL, ret);
					}
				}
			}

			// Read the data as much as possible from the TCP socket and store it to FIFO
			if (se->TcpSock != NULL)
			{
				SetNoNeedToRead(se->TcpSock);

				while (FifoSize(se->SendFifo) <= RUDP_MAX_FIFO_SIZE)
				{
					UINT ret = Recv(se->TcpSock, r->TmpBuf, sizeof(r->TmpBuf), false);

					if (ret == SOCK_LATER)
					{
						// Can not read any more
						break;
					}
					else if (ret == 0)
					{
						// Disconnected
						Disconnect(se->TcpSock);
						RUDPDisconnectSession(r, se, false);
						break;
					}
					else
					{
						// Reading success
						WriteFifo(se->SendFifo, r->TmpBuf, ret);
					}
				}
			}

			// Attempt to send a divided segment
			while (true)
			{
				UINT64 seq_no_min, seq_no_max;

				seq_no_min = RUDPGetCurrentSendingMinSeqNo(se);
				seq_no_max = RUDPGetCurrentSendingMaxSeqNo(se);

#ifdef	RUDP_DETAIL_LOG
				Debug("min=%I64u max=%I64u\n", seq_no_min, seq_no_max);
#endif	// RUDP_DETAIL_LOG

				if (seq_no_min == 0 || ((seq_no_min + RUDP_MAX_NUM_ACK - 1) >= se->NextSendSeqNo))
				{
					// Because there is a room to send a new segment, send a segment
					UINT size = MIN(FifoSize(se->SendFifo), RUDP_MAX_SEGMENT_SIZE);

					if (size == 0)
					{
						// There is no more data to send in FIFO
						break;
					}

					// Transmission
					RUDPSendSegment(r, se, FifoPtr(se->SendFifo), size);

					r->TotalLogicalSent += size;

					// Advance the FIFO
					ReadFifo(se->SendFifo, NULL, size);
				}
				else
				{
					// There is no room to send a new segment further
					break;
				}
			}

			if (se->DisconnectFlag == false)
			{
				UINT64 seq_no_min;

				if (se->LastSentTick == 0 || (r->Now >= (se->LastSentTick + (UINT64)se->NextKeepAliveInterval)))
				{
					if (LIST_NUM(se->SendSegmentList) == 0)
					{
						// Send a Keep-Alive if no data was sent for a while and the transmission queue is empty
						RUDPSendSegment(r, se, se->Magic_KeepAliveRequest, sizeof(se->Magic_KeepAliveRequest));

#ifdef	RUDP_DETAIL_LOG
						Debug("Sent KeepAlive Request\n");
#endif	// RUDP_DETAIL_LOG
					}

					se->NextKeepAliveInterval = RUDP_KEEPALIVE_INTERVAL_MIN + (Rand32() % (RUDP_KEEPALIVE_INTERVAL_MAX - RUDP_KEEPALIVE_INTERVAL_MIN));

					AddInterrupt(r->Interrupt, r->Now + se->NextKeepAliveInterval);
				}

				seq_no_min = RUDPGetCurrentSendingMinSeqNo(se);
				for (j = 0;j < LIST_NUM(se->SendSegmentList);j++)
				{
					RUDP_SEGMENT *s = LIST_DATA(se->SendSegmentList, j);

					if (s->SeqNo <= (seq_no_min + RUDP_MAX_NUM_ACK - 1))
					{
						if (s->NextSendTick == 0 || r->Now >= s->NextSendTick)
						{
							UINT next_interval;
							// Transmits a segment which has not been sent even once yet, or whose retransmission time has arrived
							RUDPSendSegmentNow(r, se, s->SeqNo, s->Data, s->Size);

							if (se->CurrentRtt != 0)
							{
								next_interval = (se->CurrentRtt * 120 / 100) * Power(2, MIN(s->NumSent, 10));
							}
							else
							{
								next_interval = RUDP_RESEND_TIMER * Power(2, MIN(s->NumSent, 10));
							}

							next_interval = MIN(next_interval, RUDP_RESEND_TIMER_MAX);

							s->NumSent++;

							s->NextSendTick = r->Now + next_interval;

							AddInterrupt(r->Interrupt, s->NextSendTick);
						}
					}
				}

				while (LIST_NUM(se->ReplyAckList) >= 1)
				{
					// If there are ACKs which is not responded yet in the list, send all of them
					RUDPSendSegmentNow(r, se, se->NextSendSeqNo, NULL, 0);
				}

				// Send all if there are bulk transfer data
				if (se->TcpSock != NULL)
				{
					SOCK *s = se->TcpSock;

					if (s->BulkRecvTube != NULL)
					{
						TUBE *t = s->BulkRecvTube;

						while (true)
						{
							TUBEDATA *d = TubeRecvAsync(t);

							if (d == NULL)
							{
								break;
							}

							if (d->Header != NULL && d->HeaderSize == sizeof(TCP_PAIR_HEADER))
							{
								TCP_PAIR_HEADER *h = d->Header;

								if (h->EnableHMac)
								{
									se->UseHMac = true;
								}
							}

							RUDPBulkSend(r, se, d->Data, d->DataSize);

							FreeTubeData(d);
						}
					}
				}
			}
		}

		if (r->ServerMode == false)
		{
			if (se->Status == RUDP_SESSION_STATUS_CONNECT_SENT)
			{
				// Send a connection request periodically from the client side
				if (se->LastSentTick == 0 || ((se->LastSentTick + (UINT64)RUDP_RESEND_TIMER) <= r->Now))
				{
					UCHAR tmp[40];
					UINT size_of_padding = 19;
					UINT size = size_of_padding + SHA1_SIZE;

					se->LastSentTick = r->Now;

					Copy(tmp, se->Key_Init, SHA1_SIZE);
					Rand(tmp + SHA1_SIZE, size_of_padding);

					if (r->Protocol == RUDP_PROTOCOL_ICMP)
					{
						// ICMP packet
						UCHAR *rand_data;
						UINT rand_size;

						rand_size = Rand32() % 64 + 64;
						rand_data = Malloc(rand_size);
						Rand(rand_data, rand_size);

						RUDPSendPacket(r, &se->YourIp, se->YourPort, rand_data, rand_size, ICMP_TYPE_ECHO_REQUEST);
						Free(rand_data);

						se->Client_Icmp_NextSendEchoRequest = r->Now + GenRandInterval(RUDP_CLIENT_ECHO_REQUEST_SEND_INTERVAL_MIN, RUDP_CLIENT_ECHO_REQUEST_SEND_INTERVAL_MAX);
						AddInterrupt(r->Interrupt, se->Client_Icmp_NextSendEchoRequest);

						// Try in both INFORMATION_REQUEST and ECHO_RESPONSE from the client side first
						RUDPSendPacket(r, &se->YourIp, se->YourPort, tmp, size, ICMP_TYPE_ECHO_RESPONSE);
						RUDPSendPacket(r, &se->YourIp, se->YourPort, tmp, size, ICMP_TYPE_INFORMATION_REQUEST);
					}
					else if (r->Protocol == RUDP_PROTOCOL_DNS)
					{
						// DNS
						RUDPSendPacket(r, &se->YourIp, se->YourPort, tmp, size, se->Dns_TranId);
					}
					else
					{
						// Normal UDP
						RUDPSendPacket(r, &se->YourIp, se->YourPort, tmp, size, 0);
					}

					AddInterrupt(r->Interrupt, r->Now + (UINT64)RUDP_RESEND_TIMER);
				}
			}

			if (r->Protocol == RUDP_PROTOCOL_ICMP)
			{
				if (se->Client_Icmp_NextSendEchoRequest == 0 || (r->Now >= se->Client_Icmp_NextSendEchoRequest))
				{
					// Periodic ICMP Echo transmission from the client side when R-UDP used in ICMP mode
					// (To maintain the mapping table of the NAT)
					UCHAR *rand_data;
					UINT rand_size;

					rand_size = Rand32() % 64 + 64;
					rand_data = Malloc(rand_size);
					Rand(rand_data, rand_size);

					RUDPSendPacket(r, &se->YourIp, se->YourPort, rand_data, rand_size, ICMP_TYPE_ECHO_REQUEST);
					Free(rand_data);

					se->Client_Icmp_NextSendEchoRequest = r->Now + GenRandInterval(RUDP_CLIENT_ECHO_REQUEST_SEND_INTERVAL_MIN, RUDP_CLIENT_ECHO_REQUEST_SEND_INTERVAL_MAX);
					AddInterrupt(r->Interrupt, se->Client_Icmp_NextSendEchoRequest);
				}
			}
		}
	}

	// Release the disconnected sessions
	o = NULL;
	for (i = 0;i < LIST_NUM(r->SessionList);i++)
	{
		RUDP_SESSION *se = LIST_DATA(r->SessionList, i);

		if (se->DisconnectFlag)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Add(o, se);
		}
	}
	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			RUDP_SESSION *se = LIST_DATA(o, i);

			Delete(r->SessionList, se);

			RUDPFreeSession(se);
		}

		ReleaseList(o);
	}
}

// Do the bulk send
void RUDPBulkSend(RUDP_STACK *r, RUDP_SESSION *se, void *data, UINT data_size)
{
	UCHAR *buf;
	UINT buf_size;
	UINT padding_size;
	UINT i;
	CRYPT *c;
	UCHAR crypt_key_src[SHA1_SIZE * 2];
	UCHAR crypt_key[SHA1_SIZE];
	UINT icmp_type;
	UCHAR sign[SHA1_SIZE];
	UCHAR iv[SHA1_SIZE + 1];
	// Validate arguments
	if (r == NULL || se == NULL || (data == NULL && data_size != 0))
	{
		return;
	}

	padding_size = Rand32() % 31 + 1;

	buf_size = SHA1_SIZE + SHA1_SIZE + sizeof(UINT64) + data_size + padding_size;
	buf = Malloc(buf_size);

	// SEQ NO
	WRITE_UINT64(buf + SHA1_SIZE + SHA1_SIZE, se->BulkNextSeqNo);
	se->BulkNextSeqNo++;

	// Data
	Copy(buf + SHA1_SIZE + SHA1_SIZE + sizeof(UINT64), data, data_size);

	// Padding
	for (i = 0;i < padding_size;i++)
	{
		buf[SHA1_SIZE + SHA1_SIZE + sizeof(UINT64) + data_size + i] = (UCHAR)padding_size;
	}

	// Encryption
	Copy(iv, se->BulkNextIv, SHA1_SIZE);
	Copy(crypt_key_src + 0, se->BulkSendKey->Data, SHA1_SIZE);
	Copy(crypt_key_src + SHA1_SIZE, iv, SHA1_SIZE);
	HashSha1(crypt_key, crypt_key_src, SHA1_SIZE * 2);
	c = NewCrypt(crypt_key, sizeof(crypt_key));
	Encrypt(c, buf + SHA1_SIZE + SHA1_SIZE, buf + SHA1_SIZE + SHA1_SIZE, sizeof(UINT64) + data_size + padding_size);
	FreeCrypt(c);

	// IV
	Copy(buf + SHA1_SIZE, iv, SHA1_SIZE);

	// Sign
	if (se->UseHMac == false)
	{
		Copy(buf + 0, se->BulkSendKey->Data, SHA1_SIZE);
		HashSha1(sign, buf, SHA1_SIZE + SHA1_SIZE + sizeof(UINT64) + data_size + padding_size);
		Copy(buf + 0, sign, SHA1_SIZE);
	}
	else
	{
		HMacSha1(buf + 0, se->BulkSendKey->Data, SHA1_SIZE, buf + SHA1_SIZE, SHA1_SIZE + sizeof(UINT64) + data_size + padding_size);
	}

	// Next IV
	Copy(se->BulkNextIv, buf + buf_size - SHA1_SIZE, SHA1_SIZE);

	if (r->Protocol == RUDP_PROTOCOL_ICMP)
	{
		icmp_type = se->Icmp_Type;
	}
	else if (r->Protocol == RUDP_PROTOCOL_DNS)
	{
		icmp_type = se->Dns_TranId;
	}
	RUDPSendPacket(r, &se->YourIp, se->YourPort, buf, buf_size, icmp_type);

	Free(buf);
}

// Start a socket for R-UDP Listening
SOCK *ListenRUDP(char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, bool no_natt_register, bool over_dns_mode)
{
	return ListenRUDPEx(svc_name, proc_interrupts, proc_rpc_recv, param, port, no_natt_register, over_dns_mode, NULL, 0);
}
SOCK *ListenRUDPEx(char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, bool no_natt_register, bool over_dns_mode,
				   volatile UINT *natt_global_udp_port, UCHAR rand_port_id)
{
	SOCK *s;
	RUDP_STACK *r;

	// Creating a R-UDP stack
	r = NewRUDPServer(svc_name, proc_interrupts, proc_rpc_recv, param, port, no_natt_register, over_dns_mode, natt_global_udp_port, rand_port_id);
	if (r == NULL)
	{
		return NULL;
	}

	s = NewSock();

	s->Type = SOCK_RUDP_LISTEN;
	s->ListenMode = true;
	s->Connected = true;

	s->LocalPort = r->UdpSock->LocalPort;

	s->R_UDP_Stack = r;

	return s;
}

// Accept on the R-UDP socket
SOCK *AcceptRUDP(SOCK *s)
{
	// Validate arguments
	if (s == NULL || s->Type != SOCK_RUDP_LISTEN || s->ListenMode == false)
	{
		return NULL;
	}

	while (true)
	{
		RUDP_STACK *r = s->R_UDP_Stack;
		SOCK *ret;

		if (s->Disconnecting || s->CancelAccept)
		{
			return NULL;
		}

		ret = GetNextWithLock(r->NewSockQueue);

		if (ret != NULL)
		{
			switch (r->Protocol)
			{
			case RUDP_PROTOCOL_UDP:
				StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), SOCK_UNDERLAY_NAT_T);
				break;

			case RUDP_PROTOCOL_DNS:
				StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), SOCK_UNDERLAY_DNS);
				break;

			case RUDP_PROTOCOL_ICMP:
				StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), SOCK_UNDERLAY_ICMP);
				break;
			}

			return ret;
		}

		Wait(r->NewSockConnectEvent, INFINITE);
	}
}

// Verify the signature of the received packet
bool RUDPCheckSignOfRecvPacket(RUDP_STACK *r, RUDP_SESSION *se, void *recv_data, UINT recv_size)
{
	UCHAR sign[SHA1_SIZE];
	UCHAR sign2[SHA1_SIZE];
	UCHAR *p;
	UINT size;
	// Validate arguments
	if (r == NULL || se == NULL || recv_data == NULL || recv_size == 0)
	{
		return false;
	}

	p = (UCHAR *)recv_data;
	size = recv_size;
	if (size < SHA1_SIZE)
	{
		return false;
	}

	// Verification the signature (segment packet)
	Copy(sign, p, SHA1_SIZE);
	Copy(p, se->Key_Recv, SHA1_SIZE);
	HashSha1(sign2, p, recv_size);

	if (r->Protocol == RUDP_PROTOCOL_DNS || r->Protocol == RUDP_PROTOCOL_ICMP)
	{
		XorData(sign2, sign2, r->SvcNameHash, SHA1_SIZE);
	}

	Copy(p, sign, SHA1_SIZE);
	if (Cmp(sign, sign2, SHA1_SIZE) == 0)
	{
		return true;
	}

	if (se->BulkRecvKey == NULL)
	{
		return false;
	}

	// Verification signature (bulk packet)
	if (se->UseHMac == false)
	{
		Copy(sign, p, SHA1_SIZE);
		Copy(p, se->BulkRecvKey->Data, SHA1_SIZE);
		HashSha1(sign2, p, recv_size);
		Copy(p, sign, SHA1_SIZE);

		if (Cmp(sign, sign2, SHA1_SIZE) == 0)
		{
			return true;
		}
	}

	HMacSha1(sign2, se->BulkRecvKey->Data, SHA1_SIZE, p + SHA1_SIZE, size - SHA1_SIZE);
	if (Cmp(p, sign2, SHA1_SIZE) == 0)
	{
		se->UseHMac = true;
		return true;
	}

	return false;
}

// Process the received packet (bulk)
bool RUDPProcessBulkRecvPacket(RUDP_STACK *r, RUDP_SESSION *se, void *recv_data, UINT recv_size)
{
	UCHAR sign[SHA1_SIZE];
	UCHAR sign2[SHA1_SIZE];
	UCHAR *p;
	UCHAR *iv;
	UINT size;
	UCHAR keygen[SHA1_SIZE * 2];
	UCHAR key[SHA1_SIZE];
	CRYPT *c;
	UCHAR padlen;
	UINT64 seq_no;
	UCHAR *payload;
	UINT payload_size;
	// Validate arguments
	if (r == NULL || se == NULL || recv_data == NULL || recv_size == 0 || se->BulkRecvKey == NULL)
	{
		return false;
	}

	p = (UCHAR *)recv_data;
	size = recv_size;
	if (size < SHA1_SIZE)
	{
		return false;
	}

	// Validate the signature
	if (se->UseHMac == false)
	{
		Copy(sign, p, SHA1_SIZE);
		Copy(p, se->BulkRecvKey->Data, SHA1_SIZE);
		HashSha1(sign2, p, recv_size);
		Copy(p, sign, SHA1_SIZE);

		if (Cmp(sign, sign2, SHA1_SIZE) != 0)
		{
			HMacSha1(sign2, se->BulkRecvKey->Data, SHA1_SIZE, p + SHA1_SIZE, recv_size - SHA1_SIZE);

			if (Cmp(p, sign2, SHA1_SIZE) != 0)
			{
				return false;
			}
			else
			{
				se->UseHMac = true;
			}
		}
		else
		{
		}
	}
	else
	{
		HMacSha1(sign2, se->BulkRecvKey->Data, SHA1_SIZE, p + SHA1_SIZE, recv_size - SHA1_SIZE);

		if (Cmp(p, sign2, SHA1_SIZE) != 0)
		{
			return false;
		}
	}

	p += SHA1_SIZE;
	size -= SHA1_SIZE;

	// IV
	if (size < SHA1_SIZE)
	{
		return false;
	}
	iv = p;
	p += SHA1_SIZE;
	size -= SHA1_SIZE;

	// Decrypt
	if (size < 1)
	{
		return false;
	}
	Copy(keygen + 0, se->BulkRecvKey->Data, SHA1_SIZE);
	Copy(keygen + SHA1_SIZE, iv, SHA1_SIZE);
	HashSha1(key, keygen, sizeof(keygen));

	c = NewCrypt(key, sizeof(key));
	Encrypt(c, p, p, size);
	FreeCrypt(c);

	// padlen
	padlen = p[size - 1];
	if (padlen == 0)
	{
		return false;
	}
	if (size < padlen)
	{
		return false;
	}
	size -= padlen;

	// SEQ NO
	seq_no = READ_UINT64(p);
	p += sizeof(UINT64);
	size -= sizeof(UINT64);

	if (seq_no == 0 || seq_no >= (0xF000000000000000ULL))
	{
		// Sequence number is invalid
		return false;
	}

	if ((seq_no + RUDP_BULK_SEQ_NO_RANGE) < se->BulkRecvSeqNoMax)
	{
		// Sequence number is too small
		return false;
	}

	se->LastRecvTick = r->Now;

	payload = p;
	payload_size = size;

	se->BulkRecvSeqNoMax = MAX(seq_no, se->BulkRecvSeqNoMax);

	// Send the received bulk packet to the Tube of the socket
	RUDPInitSock(r, se);

	if (se->TcpSock != NULL)
	{
		SOCK *s = se->TcpSock;
		TUBE *t = s->BulkSendTube;

		if (t != NULL)
		{
			TubeSendEx2(t, payload, payload_size, NULL, true, RUDP_BULK_MAX_RECV_PKTS_IN_QUEUE);

			se->FlushBulkSendTube = true;
		}
	}

	return true;
}

// Process the received packet (segment)
bool RUDPProcessRecvPacket(RUDP_STACK *r, RUDP_SESSION *se, void *recv_data, UINT recv_size)
{
	UCHAR sign[SHA1_SIZE];
	UCHAR sign2[SHA1_SIZE];
	UCHAR *p;
	UCHAR *iv;
	UINT size;
	UCHAR keygen[SHA1_SIZE * 2];
	UCHAR key[SHA1_SIZE];
	CRYPT *c;
	UCHAR padlen;
	UINT num_ack;
	UINT i;
	UINT64 seq_no;
	UCHAR *payload;
	UINT payload_size;
	UINT64 max_ack;
	UINT64 my_tick, your_tick;
	// Validate arguments
	if (r == NULL || se == NULL || recv_data == NULL || recv_size == 0)
	{
		return false;
	}

	p = (UCHAR *)recv_data;
	size = recv_size;
	if (size < SHA1_SIZE)
	{
		return false;
	}

	// Validate the signature
	Copy(sign, p, SHA1_SIZE);
	Copy(p, se->Key_Recv, SHA1_SIZE);
	HashSha1(sign2, p, recv_size);
	Copy(p, sign, SHA1_SIZE);

	if (r->Protocol == RUDP_PROTOCOL_DNS || r->Protocol == RUDP_PROTOCOL_ICMP)
	{
		XorData(sign2, sign2, r->SvcNameHash, SHA1_SIZE);
	}

	if (Cmp(sign, sign2, SHA1_SIZE) != 0)
	{
		//WHERE;
		return false;
	}
	p += SHA1_SIZE;
	size -= SHA1_SIZE;

	// IV
	if (size < SHA1_SIZE)
	{
		return false;
	}
	iv = p;
	p += SHA1_SIZE;
	size -= SHA1_SIZE;

	// Decrypt
	if (size < 1)
	{
		return false;
	}
	Copy(keygen + 0, iv, SHA1_SIZE);
	Copy(keygen + SHA1_SIZE, se->Key_Recv, SHA1_SIZE);
	HashSha1(key, keygen, sizeof(keygen));

	c = NewCrypt(key, sizeof(key));
	Encrypt(c, p, p, size);
	FreeCrypt(c);

	// padlen
	padlen = p[size - 1];
	if (padlen == 0)
	{
		return false;
	}
	if (size < padlen)
	{
		return false;
	}
	size -= padlen;

	// MyTick
	if (size < sizeof(UINT64))
	{
		return false;
	}
	my_tick = READ_UINT64(p);
	p += sizeof(UINT64);
	size -= sizeof(UINT64);

	// YourTick
	if (size < sizeof(UINT64))
	{
		return false;
	}
	your_tick = READ_UINT64(p);
	p += sizeof(UINT64);
	size -= sizeof(UINT64);

	if (your_tick > r->Now)
	{
		return false;
	}

	// MAX_ACK
	if (size < sizeof(UINT64))
	{
		return false;
	}
	max_ack = READ_UINT64(p);
	p += sizeof(UINT64);
	size -= sizeof(UINT64);

	// num_ack
	if (size < sizeof(UINT))
	{
		return false;
	}

	num_ack = READ_UINT(p);
	if (num_ack > RUDP_MAX_NUM_ACK)
	{
		return false;
	}
	p += sizeof(UINT);
	size -= sizeof(UINT);

	// ACKs
	if (size < (sizeof(UINT64) * num_ack + sizeof(UINT64)))
	{
		return false;
	}

	if (max_ack >= 1)
	{
		RUDPProcessAck2(r, se, max_ack);
	}

	for (i = 0;i < num_ack;i++)
	{
		UINT64 seq = READ_UINT64(p);

		RUDPProcessAck(r, se, seq);

		p += sizeof(UINT64);
		size -= sizeof(UINT64);
	}

	// Processing of the Tick (Calculation of RTT)
	if (my_tick >= 2)
	{
		my_tick--;
	}
	se->YourTick = MAX(se->YourTick, my_tick);

	se->LatestRecvMyTick = MAX(se->LatestRecvMyTick, your_tick);

	if (se->LatestRecvMyTick2 != se->LatestRecvMyTick)
	{
		se->LatestRecvMyTick2 = se->LatestRecvMyTick;
		se->CurrentRtt = (UINT)(r->Now - se->LatestRecvMyTick);

#ifdef	RUDP_DETAIL_LOG
		Debug("CurrentRTT = %u\n", se->CurrentRtt);
#endif	// RUDP_DETAIL_LOG
	}

	// SEQ NO
	seq_no = READ_UINT64(p);
	p += sizeof(UINT64);
	size -= sizeof(UINT64);

	if (seq_no == 0)
	{
		// Sequence number of 0 is a invalid packet
		return true;
	}

	if (seq_no == se->Magic_Disconnect)
	{
		// Disconnected from opponent
		RUDPDisconnectSession(r, se, true);
		return true;
	}

	// Update the last reception date and time
	se->LastRecvTick = r->Now;

	payload = p;
	payload_size = size;

#ifdef	RUDP_DETAIL_LOG
	Debug("RUDP %X Segment Recv: %I64u (num_ack=%u, size=%u)\n", se, seq_no, num_ack, size);
#endif	// RUDP_DETAIL_LOG

	if (payload_size >= 1 && payload_size <= RUDP_MAX_SEGMENT_SIZE)
	{
		// Received one or more bytes of data

#ifdef	RUDP_DETAIL_LOG
		Debug("Recv Size: %X %I64u %u %u\n", se, seq_no, payload_size, recv_size);
#endif	// RUDP_DETAIL_LOG

		RUDPProcessRecvPayload(r, se, seq_no, payload, payload_size);
	}

	if (r->ServerMode == false)
	{
		if (se->Status == RUDP_SESSION_STATUS_CONNECT_SENT)
		{
			// Shift to the established state if the connection is not yet in established state
			se->Status = RUDP_SESSION_STATUS_ESTABLISHED;

			RUDPInitSock(r, se);
		}
	}

	return true;
}

// Disconnect the session
void RUDPDisconnectSession(RUDP_STACK *r, RUDP_SESSION *se, bool disconnected_by_you)
{
	// Validate arguments
	if (r == NULL || se == NULL)
	{
		return;
	}

	if (se->DisconnectFlag == false)
	{
		UINT i;

		se->DisconnectFlag = true;
		se->DisconnectedByYou = disconnected_by_you;

		Debug("R-UDP Session %X Disconnected. by you flag: %u\n", se, disconnected_by_you);

		if (se->TcpSock != NULL)
		{
			// Disconnect a TCP socket
			Disconnect(se->TcpSock);
			ReleaseSock(se->TcpSock);

			se->TcpSock = NULL;
		}

		// Send 5 disconnect signals serially if to disconnect from here
		if (disconnected_by_you == false)
		{
			for (i = 0;i < 5;i++)
			{
				RUDPSendSegmentNow(r, se, se->Magic_Disconnect, NULL, 0);
			}
		}
	}
}

// Initialize the TCP socket for the session
void RUDPInitSock(RUDP_STACK *r, RUDP_SESSION *se)
{
	SOCK *s1, *s2;
	UINT mss;
	// Validate arguments
	if (r == NULL || se == NULL || se->DisconnectFlag)
	{
		return;
	}

	if (se->TcpSock != NULL)
	{
		// It has already been created
		return;
	}

	// Creating a TCP socket pair
	if (NewTcpPair(&s1, &s2) == false)
	{
		// Failed to create. Disconnect the session
		RUDPDisconnectSession(r, se, false);
		return;
	}

	// Calculate the optimal MSS
	mss = RUDPCalcBestMssForBulk(r, se);

	if (r->ServerMode)
	{
		// Server mode
		se->TcpSock = s2;

		JoinSockToSockEvent(s2, r->SockEvent);

		// Update the end point information of the socket s1
		ZeroIP4(&s1->LocalIP);
		s1->LocalPort = se->MyPort;
		Copy(&s1->RemoteIP, &se->YourIp, sizeof(IP));
		s1->RemotePort = se->YourPort;
		if (IsLocalHostIP(&s1->RemoteIP) == false)
		{
			AddIpClient(&s1->RemoteIP);
			s1->IpClientAdded = true;
		}
		s1->IsRUDPSocket = true;

		s1->BulkSendKey = se->BulkSendKey;
		s1->BulkRecvKey = se->BulkRecvKey;

		AddRef(s1->BulkSendKey->Ref);
		AddRef(s1->BulkRecvKey->Ref);

		s1->RUDP_OptimizedMss = mss;

		// Enqueue the newly created socket, and set the event
		InsertQueueWithLock(r->NewSockQueue, s1);
		Set(r->NewSockConnectEvent);
	}
	else
	{
		// Client mode
		Lock(r->Lock);
		{
			if (r->TargetConnectedSock == NULL && r->DoNotSetTargetConnectedSock == false)
			{
				// Update the end point information of the socket s2
				Copy(&s2->LocalIP, &r->UdpSock->LocalIP, sizeof(IP));
				s2->LocalPort = se->MyPort;
				Copy(&s2->RemoteIP, &se->YourIp, sizeof(IP));
				s2->RemotePort = se->YourPort;
				if (IsLocalHostIP(&s2->RemoteIP) == false)
				{
					AddIpClient(&s2->RemoteIP);
					s2->IpClientAdded = true;
				}
				s2->IsRUDPSocket = true;

				s2->BulkSendKey = se->BulkSendKey;
				s2->BulkRecvKey = se->BulkRecvKey;

				AddRef(s2->BulkSendKey->Ref);
				AddRef(s2->BulkRecvKey->Ref);

				s2->RUDP_OptimizedMss = mss;

				// Register the socket to the RUDP stack
				r->TargetConnectedSock = s2;
				s2->R_UDP_Stack = r;
				se->TcpSock = s1;

				JoinSockToSockEvent(s1, r->SockEvent);

				// Set the event to be set when the connection is successful
				Set(r->TargetConnectedEvent);
			}
			else
			{
				Disconnect(s1);
				Disconnect(s2);
				ReleaseSock(s1);
				ReleaseSock(s2);
			}
		}
		Unlock(r->Lock);
	}
}

// Process the received payload
void RUDPProcessRecvPayload(RUDP_STACK *r, RUDP_SESSION *se, UINT64 seq, void *payload_data, UINT payload_size)
{
	RUDP_SEGMENT t;
	RUDP_SEGMENT *s;
	// Validate arguments
	if (r == NULL || se == NULL || seq == 0 || payload_data == NULL || payload_size == 0 || payload_size > RUDP_MAX_SEGMENT_SIZE)
	{
		return;
	}

	if (seq > (se->LastRecvCompleteSeqNo + RUDP_MAX_NUM_ACK))
	{
		// Ignore the segment which have sequence number beyond the window size, and also not to reply an ACK
		return;
	}

	if (seq <= se->LastRecvCompleteSeqNo)
	{
		// Do not receive the segment which have the sequence number that has been already received. However, reply an ACK for it
		AddInt64Distinct(se->ReplyAckList, seq);
		return;
	}

	Zero(&t, sizeof(t));
	t.SeqNo = seq;

	s = Search(se->RecvSegmentList, &t);
	if (s != NULL)
	{
		// Do not receive the segment which have the sequence number that has been already received. However, reply an ACK for it
		AddInt64Distinct(se->ReplyAckList, seq);
		return;
	}

	// Received a segment of the new sequence number
	s = ZeroMalloc(sizeof(RUDP_SEGMENT));
	s->SeqNo = seq;
	Copy(s->Data, payload_data, payload_size);
	s->Size = payload_size;
	Insert(se->RecvSegmentList, s);

	// Reply an ACK
	AddInt64Distinct(se->ReplyAckList, seq);

	// Create a socket for session if it have not been created yet
	//RUDPInitSock(r, se);
}

// Process the incoming ACK
void RUDPProcessAck(RUDP_STACK *r, RUDP_SESSION *se, UINT64 seq)
{
	RUDP_SEGMENT t;
	RUDP_SEGMENT *s;
	// Validate arguments
	if (r == NULL || se == NULL || seq == 0)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.SeqNo = seq;

	s = Search(se->SendSegmentList, &t);
	if (s == NULL)
	{
		return;
	}

	Delete(se->SendSegmentList, s);
	Free(s);
}

// Remove all segments which are preceding max_seq as already delivered
void RUDPProcessAck2(RUDP_STACK *r, RUDP_SESSION *se, UINT64 max_seq)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (r == NULL || se == NULL || max_seq == 0)
	{
		return;
	}

	o = NULL;

	for (i = 0;i < LIST_NUM(se->SendSegmentList);i++)
	{
		RUDP_SEGMENT *s = LIST_DATA(se->SendSegmentList, i);

		if (s->SeqNo <= max_seq)
		{
			if (o == NULL)
			{
				o = NewListFast(NULL);
			}

			Add(o, s);
		}
	}

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			RUDP_SEGMENT *s = LIST_DATA(o, i);

			Delete(se->SendSegmentList, s);

			Free(s);
		}

		ReleaseList(o);
	}
}

// Get the minimum sequence number which is trying to send
UINT64 RUDPGetCurrentSendingMinSeqNo(RUDP_SESSION *se)
{
	RUDP_SEGMENT *s;
	// Validate arguments
	if (se == NULL)
	{
		return 0;
	}

	if (LIST_NUM(se->SendSegmentList) == 0)
	{
		return 0;
	}

	s = LIST_DATA(se->SendSegmentList, 0);

	return s->SeqNo;
}

// Get the maximum sequence number which is trying to send
UINT64 RUDPGetCurrentSendingMaxSeqNo(RUDP_SESSION *se)
{
	RUDP_SEGMENT *s;
	// Validate arguments
	if (se == NULL)
	{
		return 0;
	}

	if (LIST_NUM(se->SendSegmentList) == 0)
	{
		return 0;
	}

	s = LIST_DATA(se->SendSegmentList, (LIST_NUM(se->SendSegmentList) - 1));

	return s->SeqNo;
}

// R-UDP segment transmission
void RUDPSendSegmentNow(RUDP_STACK *r, RUDP_SESSION *se, UINT64 seq_no, void *data, UINT size)
{
	UCHAR dst[RUDP_MAX_PACKET_SIZE];
	UCHAR *p;
	UCHAR *iv;
	LIST *o = NULL;
	UINT i;
	UCHAR padlen;
	UINT current_size;
	UCHAR sign[SHA1_SIZE];
	UCHAR key[SHA1_SIZE];
	UCHAR keygen[SHA1_SIZE * 2];
	CRYPT *c;
	UINT next_iv_pos;
	UINT num_ack;
	UINT icmp_type = 0;
	// Validate arguments
	if (r == NULL || se == NULL || (size != 0 && data == NULL) || (size > RUDP_MAX_SEGMENT_SIZE))
	{
		return;
	}

	Zero(dst, sizeof(dst));
	p = dst;

	// SIGN
	Copy(p, se->Key_Send, SHA1_SIZE);
	p += SHA1_SIZE;

	// IV
	iv = p;
	Copy(iv, se->NextIv, SHA1_SIZE);
	p += SHA1_SIZE;

	for (i = 0;i < MIN(LIST_NUM(se->ReplyAckList), RUDP_MAX_NUM_ACK);i++)
	{
		UINT64 *seq = LIST_DATA(se->ReplyAckList, i);

		if (o == NULL)
		{
			o = NewListFast(NULL);
		}

		Add(o, seq);
	}

	// MyTick
	WRITE_UINT64(p, r->Now);
	p += sizeof(UINT64);

	// YourTick
	WRITE_UINT64(p, se->YourTick);
	p += sizeof(UINT64);

	// MAX_ACK
	WRITE_UINT64(p, se->LastRecvCompleteSeqNo);
	p += sizeof(UINT64);

	// NUM_ACK
	num_ack = LIST_NUM(o);
	WRITE_UINT(p, num_ack);
	p += sizeof(UINT);

	if (o != NULL)
	{
		// ACK body
		for (i = 0;i < LIST_NUM(o);i++)
		{
			UINT64 *seq = LIST_DATA(o, i);

			WRITE_UINT64(p, *seq);
			p += sizeof(UINT64);

			Delete(se->ReplyAckList, seq);

			Free(seq);
		}
		ReleaseList(o);
	}

	// SEQ
	WRITE_UINT64(p, seq_no);
	p += sizeof(UINT64);

	// data
	Copy(p, data, size);
	p += size;

	// padding
	padlen = Rand8();
	padlen = MAX(padlen, 1);

	for (i = 0;i < padlen;i++)
	{
		*p = padlen;
		p++;
	}

	current_size = (UINT)(p - dst);

	// Encrypt
	Copy(keygen + 0, iv, SHA1_SIZE);
	Copy(keygen + SHA1_SIZE, se->Key_Send, SHA1_SIZE);
	HashSha1(key, keygen, sizeof(keygen));
	c = NewCrypt(key, sizeof(key));
	Encrypt(c, dst + SHA1_SIZE * 2, dst + SHA1_SIZE * 2, current_size - (SHA1_SIZE * 2));
	FreeCrypt(c);

	// Sign
	HashSha1(sign, dst, current_size);
	if (r->Protocol == RUDP_PROTOCOL_DNS || r->Protocol == RUDP_PROTOCOL_ICMP)
	{
		XorData(sign, sign, r->SvcNameHash, SHA1_SIZE);
	}
	Copy(dst, sign, SHA1_SIZE);

	if (r->Protocol == RUDP_PROTOCOL_ICMP)
	{
		icmp_type = se->Icmp_Type;
	}
	else if (r->Protocol == RUDP_PROTOCOL_DNS)
	{
		icmp_type = se->Dns_TranId;
	}
	RUDPSendPacket(r, &se->YourIp, se->YourPort, dst, current_size, icmp_type);

	if (size >= 1)
	{
		se->LastSentTick = r->Now;
	}

	// Next IV
	next_iv_pos = Rand32() % (current_size - SHA1_SIZE);
	Copy(se->NextIv, dst + next_iv_pos, SHA1_SIZE);

#ifdef	RUDP_DETAIL_LOG
	Debug("RUDP %X Segment Sent: %I64u (num_ack=%u, size=%u)\n", se, seq_no, num_ack, size);
#endif	// RUDP_DETAIL_LOG

	if (size >= 1)
	{
#ifdef	RUDP_DETAIL_LOG
		Debug("Send Size: %X %I64u %u %u\n", se, seq_no, size, current_size);
#endif	// RUDP_DETAIL_LOG
	}
}

// R-UDP segment transmission (only put into the queue)
void RUDPSendSegment(RUDP_STACK *r, RUDP_SESSION *se, void *data, UINT size)
{
	RUDP_SEGMENT *s;
	// Validate arguments
	if (r == NULL || se == NULL || (size != 0 && data == NULL) || (size > RUDP_MAX_SEGMENT_SIZE))
	{
		return;
	}

	s = ZeroMalloc(sizeof(RUDP_SEGMENT));

	Copy(s->Data, data, size);
	s->Size = size;

	s->SeqNo = se->NextSendSeqNo++;

	Insert(se->SendSegmentList, s);
}

// Search for a session
RUDP_SESSION *RUDPSearchSession(RUDP_STACK *r, IP *my_ip, UINT my_port, IP *your_ip, UINT your_port)
{
	RUDP_SESSION t;
	RUDP_SESSION *se;
	// Validate arguments
	if (r == NULL || my_ip == NULL || your_ip == NULL)
	{
		return NULL;
	}

	Copy(&t.MyIp, my_ip, sizeof(IP));
	t.MyPort = my_port;
	Copy(&t.YourIp, your_ip, sizeof(IP));
	t.YourPort = your_port;

	se = Search(r->SessionList, &t);

	return se;
}

// Release of the session
void RUDPFreeSession(RUDP_SESSION *se)
{
	UINT i;
	// Validate arguments
	if (se == NULL)
	{
		return;
	}

	Debug("RUDPFreeSession %X\n", se);

	for (i = 0;i < LIST_NUM(se->SendSegmentList);i++)
	{
		RUDP_SEGMENT *s = LIST_DATA(se->SendSegmentList, i);

		Free(s);
	}

	ReleaseList(se->SendSegmentList);

	for (i = 0;i < LIST_NUM(se->RecvSegmentList);i++)
	{
		RUDP_SEGMENT *s = LIST_DATA(se->RecvSegmentList, i);

		Free(s);
	}

	ReleaseList(se->RecvSegmentList);

	if (se->TcpSock != NULL)
	{
		Disconnect(se->TcpSock);
		ReleaseSock(se->TcpSock);
	}

	ReleaseInt64List(se->ReplyAckList);

	ReleaseFifo(se->RecvFifo);
	ReleaseFifo(se->SendFifo);

	ReleaseSharedBuffer(se->BulkSendKey);
	ReleaseSharedBuffer(se->BulkRecvKey);

	Free(se);
}

// Create a new session
RUDP_SESSION *RUDPNewSession(bool server_mode, IP *my_ip, UINT my_port, IP *your_ip, UINT your_port, UCHAR *init_key)
{
	RUDP_SESSION *se;
	UCHAR key1[SHA1_SIZE];
	UCHAR key2[SHA1_SIZE];
	UCHAR bulk_send_key[SHA1_SIZE];
	UCHAR bulk_recv_key[SHA1_SIZE];
	BUF *b;

	se = ZeroMalloc(sizeof(RUDP_SESSION));

	Copy(&se->MyIp, my_ip, sizeof(IP));
	se->MyPort = my_port;

	Copy(&se->YourIp, your_ip, sizeof(IP));
	se->YourPort = your_port;

	Copy(se->Key_Init, init_key, SHA1_SIZE);
	se->LastSentTick = 0;
	se->LastRecvTick = Tick64();
	se->LatestRecvMyTick = Tick64();

	se->NextSendSeqNo = 1;

	se->ServerMode = server_mode;

	se->SendSegmentList = NewList(RUDPCompareSegmentList);
	se->RecvSegmentList = NewList(RUDPCompareSegmentList);

	// Generate the two keys
	b = NewBuf();
	WriteBuf(b, init_key, SHA1_SIZE);
	WriteBufStr(b, "zurukko");
	HashSha1(key1, b->Buf, b->Size);
	FreeBuf(b);

	b = NewBuf();
	WriteBuf(b, init_key, SHA1_SIZE);
	WriteBuf(b, key1, SHA1_SIZE);
	WriteBufStr(b, "yasushineko");
	HashSha1(key2, b->Buf, b->Size);
	FreeBuf(b);

	// Generate the magic number for the KeepAlive
	b = NewBuf();
	WriteBuf(b, init_key, SHA1_SIZE);
	WriteBufStr(b, "Magic_KeepAliveRequest");
	HashSha1(se->Magic_KeepAliveRequest, b->Buf, b->Size);
	FreeBuf(b);
	b = NewBuf();
	WriteBuf(b, init_key, SHA1_SIZE);
	WriteBufStr(b, "Magic_KeepAliveResponse");
	HashSha1(se->Magic_KeepAliveResponse, b->Buf, b->Size);
	FreeBuf(b);

	if (server_mode == false)
	{
		se->Magic_Disconnect = 0xffffffff00000000ULL | (UINT64)(Rand32());
	}

	Copy(se->Key_Init, init_key, SHA1_SIZE);

	if (se->ServerMode)
	{
		Copy(se->Key_Send, key1, SHA1_SIZE);
		Copy(se->Key_Recv, key2, SHA1_SIZE);
	}
	else
	{
		Copy(se->Key_Send, key2, SHA1_SIZE);
		Copy(se->Key_Recv, key1, SHA1_SIZE);
	}

	Rand(se->NextIv, sizeof(se->NextIv));

	se->ReplyAckList = NewInt64List(true);

	se->NextKeepAliveInterval = RUDP_KEEPALIVE_INTERVAL_MIN + (Rand32() % (RUDP_KEEPALIVE_INTERVAL_MAX - RUDP_KEEPALIVE_INTERVAL_MIN));

	se->RecvFifo = NewFifo();
	se->SendFifo = NewFifo();

	se->Dns_TranId = Rand16() % 65535 + 1;

	// Generate the bulk transfer key
	Rand(bulk_send_key, sizeof(bulk_send_key));
	Rand(bulk_recv_key, sizeof(bulk_recv_key));

	se->BulkSendKey = NewSharedBuffer(bulk_send_key, sizeof(bulk_send_key));
	se->BulkRecvKey = NewSharedBuffer(bulk_recv_key, sizeof(bulk_recv_key));

	Rand(se->BulkNextIv, sizeof(se->BulkNextIv));
	se->BulkNextSeqNo = 1;

	return se;
}

// Comparison function of the segment list items
int RUDPCompareSegmentList(void *p1, void *p2)
{
	RUDP_SEGMENT *s1, *s2;
	UINT r;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *((RUDP_SEGMENT **)p1);
	s2 = *((RUDP_SEGMENT **)p2);
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	r = COMPARE_RET(s1->SeqNo, s2->SeqNo);

	return r;
}

// Send a UDP packet
void RUDPSendPacket(RUDP_STACK *r, IP *dest_ip, UINT dest_port, void *data, UINT size, UINT icmp_type)
{
	UDPPACKET *p;
	// Validate arguments
	if (r == NULL || dest_ip == NULL || dest_port == 0 || data == NULL || size == 0)
	{
		return;
	}

	p = NewUdpPacket(&r->UdpSock->LocalIP, r->UdpSock->LocalPort,
		dest_ip, dest_port,
		Clone(data, size), size);

	if (r->Protocol == RUDP_PROTOCOL_ICMP || r->Protocol == RUDP_PROTOCOL_DNS)
	{
		// ICMP Type / DNS Tran ID
		p->Type = icmp_type;
	}

	Add(r->SendPacketList, p);
}

// R-UDP main thread
void RUDPMainThread(THREAD *thread, void *param)
{
	RUDP_STACK *r;
	bool halt_flag = false;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	r = (RUDP_STACK *)param;

	AddWaitThread(thread);
	NoticeThreadInit(thread);

	while (true)
	{
		UINT wait_interval;
		UINT i;
		UINT min_wait_interval;
		UINT num_ignore_errors = 0;

		r->Now = Tick64();

		Lock(r->Lock);
		{
			Copy(&r->NatT_IP_Safe, &r->NatT_IP, sizeof(IP));
			Copy(&r->My_Private_IP_Safe, &r->My_Private_IP, sizeof(IP));
		}
		Unlock(r->Lock);

		// Receive the data from the UDP socket
		while (true)
		{
			UINT ret;
			IP ip_src;
			UINT port_src;

			ret = RecvFrom(r->UdpSock, &ip_src, &port_src, r->TmpBuf, sizeof(r->TmpBuf));

			if (ret == SOCK_LATER)
			{
				// There is no packet more
				break;
			}
			else if (ret != 0)
			{
				// Receive a Packet
				bool ok = false;
				UDPPACKET *p = NewUdpPacket(&ip_src, port_src,
					&r->UdpSock->LocalIP, r->UdpSock->LocalPort,
					Clone(r->TmpBuf, ret), ret);

				if (r->Protocol == RUDP_PROTOCOL_ICMP)
				{
					// Analyse the incoming ICMP packet
					UINT ip_header_size = GetIpHeaderSize(p->Data, p->Size);

					if (ip_header_size >= sizeof(IPV4_HEADER))
					{
						if (p->Size >= (ip_header_size + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + SHA1_SIZE))
						{
							IPV4_HEADER *ip_header = (IPV4_HEADER *)(((UCHAR *)p->Data) + 0);
							ICMP_HEADER *icmp_header = (ICMP_HEADER *)(((UCHAR *)p->Data) + ip_header_size);
							ICMP_ECHO *echo_header = (ICMP_ECHO *)(((UCHAR *)p->Data) + ip_header_size + sizeof(ICMP_HEADER));

							if (icmp_header->Type == ICMP_TYPE_ECHO_RESPONSE || 
								icmp_header->Type == (r->ServerMode ? ICMP_TYPE_INFORMATION_REQUEST : ICMP_TYPE_INFORMATION_REPLY))
							{
								UCHAR hash[SHA1_SIZE];

								HashSha1(hash, ((UCHAR *)p->Data) + ip_header_size + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + SHA1_SIZE,
									p->Size - (ip_header_size + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + SHA1_SIZE));

								if (Cmp(hash, ((UCHAR *)p->Data) + ip_header_size + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO), SHA1_SIZE) == 0)
								{
									UCHAR *new_data;
									UINT new_data_size;
									if (r->ServerMode)
									{
										// On the server side, the ICMP ID and the SEQ NO of received messages are treated as a source port number 
										Copy(&p->SrcPort, echo_header, sizeof(UINT));
									}

									// Record the Type
									p->Type = icmp_header->Type;

									// Erase the header part
									new_data_size = p->Size - (ip_header_size + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + SHA1_SIZE);
									new_data = Clone(((UCHAR *)p->Data) + ip_header_size + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + SHA1_SIZE, new_data_size);
									Free(p->Data);
									p->Data = new_data;
									p->Size = new_data_size;

									ok = true;
								}
							}
						}
					}
				}
				else if (r->Protocol == RUDP_PROTOCOL_DNS)
				{
					// Analyse the incoming DNS packet
					UINT offset;

					if (r->ServerMode == false)
					{
						offset = 42;
					}
					else
					{
						offset = 37;
					}

					if (p->Size > offset)
					{
						UCHAR *new_data;
						UINT new_size = p->Size - offset;

						p->Type = *((USHORT *)p->Data);

						new_data = Clone(((UCHAR *)p->Data) + offset, new_size);

						Free(p->Data);
						p->Data = new_data;
						p->Size = new_size;

						ok = true;
					}
				}
				else
				{
					// Don't do anything for ordinary UDP packet
					ok = true;
				}

				if (ok)
				{
					// Process the received packet
					RUDPRecvProc(r, p);

					r->TotalPhysicalReceived += ret;
				}

				FreeUdpPacket(p);
			}
			else
			{
				if (r->UdpSock->IgnoreRecvErr)
				{
					// An ignorable reception error occurs
					if ((num_ignore_errors++) >= MAX_NUM_IGNORE_ERRORS)
					{
						break;
					}
				}
				else
				{
					// A non-ignorable reception error occurs
					break;
				}
			}
		}

		// Call the interrupt notification callback function
		if (r->ProcInterrupts != NULL)
		{
			r->ProcInterrupts(r);
		}

		RUDPInterruptProc(r);

		// Send all packets in the transmission packet list
		for (i = 0;i < LIST_NUM(r->SendPacketList);i++)
		{
			UDPPACKET *p = LIST_DATA(r->SendPacketList, i);

			if (r->Protocol == RUDP_PROTOCOL_ICMP)
			{
				// In case of the ICMP protocol, assemble an ICMP header
				UINT dst_size = sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + SHA1_SIZE + p->Size;
				UCHAR *dst_data = ZeroMalloc(dst_size);

				ICMP_HEADER *icmp_header = (ICMP_HEADER *)dst_data;
				ICMP_ECHO *icmp_echo = (ICMP_ECHO *)(dst_data + sizeof(ICMP_HEADER));
				UCHAR *hash = dst_data + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO);
				UCHAR *icmp_data = dst_data + sizeof(ICMP_HEADER) + sizeof(ICMP_ECHO) + SHA1_SIZE;

				// Header
				icmp_header->Type = (UCHAR)p->Type;
				icmp_header->Code = 0;
				icmp_header->Checksum = 0;

				if (r->ServerMode)
				{
					// On the server side, use the port number in the opponent internal data as ICMP ID and SEQ NO 
					Copy(icmp_echo, &p->DestPort, 4);
				}
				else
				{
					// Use the fixed ICMP ID and SEQ NO on the client side
					icmp_echo->Identifier = Endian16(r->Client_IcmpId);
					icmp_echo->SeqNo = Endian16(r->Client_IcmpSeqNo);
				}

				// Data body
				Copy(icmp_data, p->Data, p->Size);

				// Hash
				HashSha1(hash, icmp_data, p->Size);

				// Checksum calculation
				icmp_header->Checksum = IpChecksum(dst_data, dst_size);

				// Replacement
				Free(p->Data);
				p->Data = dst_data;
				p->Size = dst_size;
			}
			else if (r->Protocol == RUDP_PROTOCOL_DNS)
			{
				BUF *b = NewBuf();
				// In case of over DNS protocol, assemble a header that conforms to the DNS protocol
				if (r->ServerMode == false)
				{
					// DNS query header
					USHORT us = Rand16() % 65535 + 1;
					static UCHAR dns_query_header_1[] = 
					{
						0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08,
					};
					static UCHAR dns_query_header_2[] = 
					{
						0x00, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10,
						0x00, 0x00, 0x00, 0x80, 0x00,
					};
					UCHAR rand_data[4];
					char rand_str[MAX_SIZE];

					Rand(rand_data, sizeof(rand_data));
					BinToStr(rand_str, sizeof(rand_str), rand_data, sizeof(rand_data));
					StrLower(rand_str);

					WriteBuf(b, &us, sizeof(USHORT));
					WriteBuf(b, dns_query_header_1, sizeof(dns_query_header_1));
					WriteBuf(b, rand_str, 8);
					WriteBuf(b, dns_query_header_2, sizeof(dns_query_header_2));
					us = Endian16((USHORT)p->Size);
					WriteBuf(b, &us, sizeof(USHORT));
					WriteBuf(b, p->Data, p->Size);
				}
				else
				{
					// DNS response header
					USHORT us = p->Type;
					UINT ui;
					static UCHAR dns_response_header_1[] =
					{
						0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
						0x00, 0x00, 0x08,
					};
					static UCHAR dns_response_header_2[] =
					{
						0x00, 0x00, 0x30, 0x00, 0x01,
						0xc0, 0x0c, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 0xa4, 0x5b,
					};
					static UCHAR dns_response_header_3[] =
					{
						0x01, 0x00, 0x03, 0x08,
					};
					UCHAR rand_data[4];
					char rand_str[MAX_SIZE];

					Rand(rand_data, sizeof(rand_data));
					BinToStr(rand_str, sizeof(rand_str), rand_data, sizeof(rand_data));
					StrLower(rand_str);

					WriteBuf(b, &us, sizeof(USHORT));
					WriteBuf(b, dns_response_header_1, sizeof(dns_response_header_1));
					WriteBuf(b, rand_str, 8);
					WriteBuf(b, dns_response_header_2, sizeof(dns_response_header_2));
					us = Endian16((USHORT)(p->Size + 4));
					WriteBuf(b, &us, sizeof(USHORT));
					WriteBuf(b, dns_response_header_3, sizeof(dns_response_header_3));
					WriteBuf(b, p->Data, p->Size);

					ui = Rand16() % (60 * 60 * 12) + (60 * 60 * 12);
					WRITE_UINT(((UCHAR *)b->Buf) + 0x20, ui);
				}
				Free(p->Data);
				p->Data = b->Buf;
				p->Size = b->Size;
				Free(b);
			}

			SendTo(r->UdpSock, &p->DstIP, p->DestPort, p->Data, p->Size);

			r->TotalPhysicalSent += p->Size;

			FreeUdpPacket(p);
		}
		DeleteAll(r->SendPacketList);

		if (r->Halt)
		{
			// If it is necessary to stop, stop it after cycling through a loop
			if (halt_flag == false)
			{
				halt_flag = true;
				continue;
			}
			else
			{
				break;
			}
		}

		// Rest the CPU until the next event
		wait_interval = GetNextIntervalForInterrupt(r->Interrupt);
		if (r->ServerMode)
		{
			min_wait_interval = RUDP_LOOP_WAIT_INTERVAL_S;
		}
		else
		{
			min_wait_interval = RUDP_LOOP_WAIT_INTERVAL_C;
		}

		if (wait_interval == INFINITE)
		{
			wait_interval = min_wait_interval;
		}
		else
		{
			wait_interval = MIN(min_wait_interval, wait_interval);
		}

#ifdef	RUDP_DETAIL_LOG
		Debug("wait_interval = %u\n", wait_interval);
#endif	// RUDP_DETAIL_LOG

		if (wait_interval >= 1)
		{
			WaitSockEvent(r->SockEvent, wait_interval);
		}

#ifdef	RUDP_DETAIL_LOG
		if (r->ServerMode)
		{
			char str1[MAX_SIZE];
			char str2[MAX_SIZE];
			double rate = 0.0;

			ToStr64(str1, r->TotalPhysicalReceived);
			ToStr64(str2, r->TotalLogicalReceived);

			if (r->TotalPhysicalReceived >= 1)
			{
				rate = (double)r->TotalLogicalReceived / (double)r->TotalPhysicalReceived;
			}

			Debug("%s / %s %.4f\n", str1, str2, rate);
		}
#endif	// RUDP_DETAIL_LOG
	}

	Disconnect(r->UdpSock);

	DelWaitThread(thread);
}

// Generate a appropriate register host name from the IP address
void RUDPGetRegisterHostNameByIP(char *dst, UINT size, IP *ip)
{
	char tmp[16];
	// Validate arguments
	if (dst == NULL)
	{
		return;
	}

	if (ip != NULL && IsIP4(ip))
	{
		UCHAR hash[SHA1_SIZE];

		HashSha1(hash, ip->addr, 4);
		BinToStr(tmp, sizeof(tmp), hash, 2);
	}
	else
	{
		UCHAR rand[2];
		Rand(rand, 2);
		BinToStr(tmp, sizeof(tmp), rand, 2);
	}

	StrLower(tmp);
	Format(dst, size,
		(IsUseAlternativeHostname() ? UDP_NAT_T_SERVER_TAG_ALT : UDP_NAT_T_SERVER_TAG),
		tmp[2], tmp[3]);


	if (false)
	{
		Debug("Hash Src IP: %r\n"
			  "Hash Dst HN: %s\n",
			  ip,
			  dst);
	}
}

// Analyze the IP address and port number from the string
bool RUDPParseIPAndPortStr(void *data, UINT data_size, IP *ip, UINT *port)
{
	char tmp[MAX_SIZE];
	UINT i;
	char ipstr[MAX_SIZE];
	char *portstr;
	// Validate arguments
	if (data == NULL || ip == NULL || port == NULL)
	{
		return false;
	}

	Zero(tmp, sizeof(tmp));

	Copy(tmp, data, MIN(data_size, sizeof(tmp) - 1));

	if (StartWith(tmp, "IP=") == false)
	{
		return false;
	}

	i = SearchStrEx(tmp, "#", 0, true);
	if (i != INFINITE)
	{
		tmp[i] = 0;
	}

	StrCpy(ipstr, sizeof(ipstr), tmp + 3);

	i = SearchStrEx(ipstr, ",PORT=", 0, true);
	if (i == INFINITE)
	{
		return false;
	}

	ipstr[i] = 0;
	portstr = ipstr + i + 6;

	StrToIP(ip, ipstr);
	*port = ToInt(portstr);

	return true;
}

// R-UDP NAT-T IP address acquisition thread
void RUDPIpQueryThread(THREAD *thread, void *param)
{
	RUDP_STACK *r;
	UINT64 next_getip_tick = 0;
	UINT64 next_getprivate_ip_tick = 0;
	UINT last_ip_hash = 0;
	void *route_change_poller = NULL;
	char current_hostname[MAX_SIZE];
	bool last_time_ip_changed = false;
	UINT num_retry = 0;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	r = (RUDP_STACK *)param;

	last_ip_hash = GetHostIPAddressHash32();

	route_change_poller = NewRouteChange();
	IsRouteChanged(route_change_poller);

	Zero(current_hostname, sizeof(current_hostname));

	while (r->Halt == false)
	{
		UINT ip_hash = GetHostIPAddressHash32();
		UINT64 now = Tick64();
		bool ip_changed = false;

		if (ip_hash != last_ip_hash)
		{
			last_time_ip_changed = false;
		}

		if ((ip_hash != last_ip_hash) || (IsRouteChanged(route_change_poller)))
		{
			if (last_time_ip_changed == false)
			{
				// Call all getting functions from the beginning
				// if the routing table or the IP address of this host has changed
				next_getip_tick = 0;
				next_getprivate_ip_tick = 0;
				ip_changed = true;

				last_ip_hash = ip_hash;

				last_time_ip_changed = true;
			}
		}
		else
		{
			last_time_ip_changed = false;
		}

		Lock(r->Lock);
		{
			if (StrCmpi(current_hostname, r->CurrentRegisterHostname) != 0)
			{
				// The target host name has changed
				next_getip_tick = 0;
				StrCpy(current_hostname, sizeof(current_hostname), r->CurrentRegisterHostname);
			}
		}
		Unlock(r->Lock);

		// Get the IP address of the NAT-T server with DNS
		if (next_getip_tick == 0 || now >= next_getip_tick)
		{
			IP ip;

			if (GetIP4(&ip, current_hostname) && IsZeroIp(&ip) == false)
			{
				Lock(r->Lock);
				{
//					Debug("%r  %r\n",&r->NatT_IP, &ip);
					if (CmpIpAddr(&r->NatT_IP, &ip) != 0)
					{
//						WHERE;
						ip_changed = true;
						Copy(&r->NatT_IP, &ip, sizeof(IP));
					}
				}
				Unlock(r->Lock);
			}

			if (IsZeroIp(&r->NatT_IP))
			{
				num_retry++;

				next_getip_tick = now + MIN((UINT64)UDP_NAT_T_GET_IP_INTERVAL * (UINT64)num_retry, (UINT64)UDP_NAT_T_GET_IP_INTERVAL_MAX);
			}
			else
			{
				next_getip_tick = now + (UINT64)UDP_NAT_T_GET_IP_INTERVAL_AFTER;
			}

			if (ip_changed)
			{
				Debug("NAT-T: NAT-T Server IP (%s): %r\n", current_hostname, &r->NatT_IP);

				r->NatT_GetTokenNextTick = 0;
				r->NatT_RegisterNextTick = 0;
				r->NatT_GetTokenFailNum = 0;
				r->NatT_RegisterFailNum = 0;

				r->NatT_TranId = Rand64();

				SetSockEvent(r->SockEvent);
			}
		}

		// Get a private IP address of this host using TCP
		if (next_getprivate_ip_tick == 0 || now >= next_getprivate_ip_tick)
		{
			IP ip;

			if (GetMyPrivateIP(&ip, false))
			{
				Lock(r->Lock);
				{
					Copy(&r->My_Private_IP, &ip, sizeof(IP));
				}
				Unlock(r->Lock);
			}

			if (IsZeroIp(&r->My_Private_IP))
			{
				next_getprivate_ip_tick = now + (UINT64)UDP_NAT_T_GET_PRIVATE_IP_INTERVAL;
			}
			else
			{
				next_getprivate_ip_tick = now + (UINT64)GenRandInterval(UDP_NAT_T_GET_PRIVATE_IP_INTERVAL_AFTER_MIN, UDP_NAT_T_GET_PRIVATE_IP_INTERVAL_AFTER_MAX);
			}

			Debug("NAT-T: My Private IP: %r\n", &r->My_Private_IP);
		}

		if (r->Halt)
		{
			break;
		}

		Wait(r->HaltEvent, RUDP_LOOP_WAIT_INTERVAL_S);
	}

	FreeRouteChange(route_change_poller);
}

// Generate a random intervals
UINT GenRandInterval(UINT min, UINT max)
{
	UINT a, b;

	a = MIN(min, max);
	b = MAX(min, max);

	if (a == b)
	{
		return a;
	}

	return (Rand32() % (b - a)) + a;
}

// Identify the private IP of the interface which is used to connect to the Internet currently
bool GetMyPrivateIP(IP *ip, bool from_vg)
{
	SOCK *s;
	IP t;
	char *hostname = UDP_NAT_T_GET_PRIVATE_IP_TCP_SERVER;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	s = ConnectEx(hostname, UDP_NAT_T_PORT_FOR_TCP_1, UDP_NAT_T_GET_PRIVATE_IP_CONNECT_TIMEOUT);

	if (s == NULL)
	{
		s = ConnectEx(hostname, UDP_NAT_T_PORT_FOR_TCP_2, UDP_NAT_T_GET_PRIVATE_IP_CONNECT_TIMEOUT);

		if (s == NULL)
		{
			s = ConnectEx(GetRandHostNameForGetMyPrivateIP(), UDP_NAT_T_PORT_FOR_TCP_1, UDP_NAT_T_GET_PRIVATE_IP_CONNECT_TIMEOUT);

			if (s == NULL)
			{
				return false;
			}
		}
	}

	Copy(&t, &s->LocalIP, sizeof(IP));

	Disconnect(s);
	ReleaseSock(s);

	if (IsZeroIp(&t))
	{
		return false;
	}

	Copy(ip, &t, sizeof(IP));

	return true;
}
char *GetRandHostNameForGetMyPrivateIP()
{
	char *hosts[] =
	{
		"www.microsoft.com",
		"www.yahoo.com",
		"www.bing.com",
	};
	UINT num_hosts = 3;

	return hosts[Rand32() % num_hosts];
}

// Function to wait until changing any IP address of the host or expiring the specified time or waking the event
void WaitUntilHostIPAddressChanged(void *p, EVENT *event, UINT timeout, UINT ip_check_interval)
{
	UINT64 start, end;
	UINT last_hash;
	// Validate arguments
	if (timeout == 0x7FFFFFFF)
	{
		timeout = 0xFFFFFFFF;
	}
	if (ip_check_interval == 0)
	{
		ip_check_interval = 0xFFFFFFFF;
	}
	if (event == NULL || timeout == 0)
	{
		return;
	}

	start = Tick64();
	end = start + (UINT64)timeout;
	last_hash = GetHostIPAddressHash32();

	while (true)
	{
		UINT64 now = Tick64();
		UINT next_interval;

		if (now >= end)
		{
			break;
		}

		if (p != NULL)
		{
			if (IsRouteChanged(p))
			{
				break;
			}
		}

		if (last_hash != GetHostIPAddressHash32())
		{
			break;
		}

		next_interval = (UINT)(end - now);
		next_interval = MIN(next_interval, ip_check_interval);

		if (Wait(event, next_interval))
		{
			break;
		}
	}
}
void *InitWaitUntilHostIPAddressChanged()
{
	void *p = NewRouteChange();

	if (p != NULL)
	{
		IsRouteChanged(p);
	}

	return p;
}
void FreeWaitUntilHostIPAddressChanged(void *p)
{
	FreeRouteChange(p);
}

// Get whether the specified IPv6 address is on the local network
bool IsIPv6LocalNetworkAddress(IP *ip)
{
	UINT type;
	LIST *o;
	UINT i;
	bool ret = false;
	IP mask64;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}
	if (IsIP6(ip) == false)
	{
		return false;
	}
	if (IsZeroIp(ip))
	{
		return false;
	}

	type = GetIPAddrType6(ip);

	if (type & IPV6_ADDR_LOCAL_UNICAST)
	{
		return true;
	}

	if ((type & IPV6_ADDR_GLOBAL_UNICAST) == 0)
	{
		return false;
	}

	IntToSubnetMask6(&mask64, 64);

	o = GetHostIPAddressList();

	ret = false;

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP *p = LIST_DATA(o, i);

		if (IsIP6(p))
		{
			if (IsZeroIp(p) == false)
			{
				if (IsLocalHostIP6(p) == false)
				{
					if (IsInSameNetwork6(p, ip, &mask64))
					{
						ret = true;
					}
				}
			}
		}
	}

	FreeHostIPAddressList(o);

	return ret;
}

// Check whether the specified IP address is localhost or the IP address of the local interface of itself
bool IsIPLocalHostOrMySelf(IP *ip)
{
	LIST *o;
	bool ret = false;
	UINT i;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	o = GetHostIPAddressList();
	if (o == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP *p = LIST_DATA(o, i);

		if (CmpIpAddr(p, ip) == 0)
		{
			ret = true;

			break;
		}
	}

	FreeHostIPAddressList(o);

	if (IsLocalHostIP4(ip) || IsLocalHostIP6(ip))
	{
		ret = true;
	}

	return ret;
}

// Get the results of the port number that is determined at random
UINT RUDPGetRandPortNumber(UCHAR rand_port_id)
{
	UINT ret;
	// Validate arguments
	if (rand_port_id == 0)
	{
		return 0;
	}

	ret = rand_port_numbers[rand_port_id];

	Debug("rand_port_id[%u] = %u\n", rand_port_id, ret);
	return ret;
}

// Obtain the hash value of combining all of the IP address assigned to the host
UINT GetHostIPAddressHash32()
{
	BUF *b;
	UINT i;
	UCHAR hash[SHA1_SIZE];
	UINT ret;
	LIST *o = GetHostIPAddressList();

	if (o == NULL)
	{
		return 0;
	}

	b = NewBuf();
	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP *ip = LIST_DATA(o, i);

		WriteBuf(b, ip, sizeof(IP));

		WriteBufStr(b, ":-) yas (-:");
	}
	FreeHostIPAddressList(o);

	WriteBuf(b, rand_port_numbers, sizeof(rand_port_numbers));

	HashSha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Copy(&ret, hash, sizeof(UINT));

	return ret;
}

// Create an IPv4 UDP socket destined for a particular target
SOCK *NewUDP4ForSpecificIp(IP *target_ip, UINT port)
{
	SOCK *s;
	IP local_ip;
	// Validate arguments
	if (target_ip == NULL || IsZeroIP(target_ip) || IsIP4(target_ip) == false)
	{
		target_ip = NULL;
	}

	Zero(&local_ip, sizeof(local_ip));
	GetBestLocalIpForTarget(&local_ip, target_ip);

	s = NewUDP4(port, &local_ip);

	if (s == NULL)
	{
		s = NewUDP4(port, NULL);
	}

	return s;
}

// Get the best self IPv4 address to connect to the target IPv4 address
bool GetBestLocalIpForTarget(IP *local_ip, IP *target_ip)
{
	bool ret = false;
	ROUTE_ENTRY *e;
	IP ip2;
	UINT n = 0;
	IP zero_ip;
	// Validate arguments
	Zero(local_ip, sizeof(IP));
	ZeroIP4(&zero_ip);
	if (target_ip == NULL)
	{
		target_ip = &zero_ip;
	}
	if (local_ip == NULL || IsIP4(target_ip) == false)
	{
		return false;
	}

	Copy(&ip2, target_ip, sizeof(IP));

	while (true)
	{
		n++;
		if (n >= 64)
		{
			break;
		}

		e = GetBestRouteEntry(&ip2);
		if (e != NULL)
		{
			if (IsZeroIp(&e->GatewayIP))
			{
				Free(e);
				break;
			}

			if (e->LocalRouting)
			{
				ret = true;
				Copy(local_ip, &e->GatewayIP, sizeof(IP));
				Free(e);
				break;
			}
			else
			{
				Copy(&ip2, &e->GatewayIP, sizeof(IP));
			}

			Free(e);
		}
	}

	if (ret == false)
	{
		if (IsLocalHostIP4(target_ip))
		{
			GetLocalHostIP4(local_ip);
			ret = true;
		}
	}

	return ret;
}

// Create a R-UDP client (Connection via NAT-T gateway)
SOCK *NewRUDPClientNatT(char *svc_name, IP *ip, UINT *error_code, UINT timeout, bool *cancel, char *hint_str, char *target_hostname)
{
	IP nat_t_ip;
	UINT dummy_int = 0;
	UINT64 giveup_tick;
	bool dummy_bool = false;
	SOCK_EVENT *sock_event;
	SOCK *sock;
	bool same_lan = false;
	char hostname[MAX_SIZE];



	if (timeout == 0)
	{
		timeout = RUDP_TIMEOUT;
	}
	if (error_code == NULL)
	{
		error_code = &dummy_int;
	}
	if (cancel == NULL)
	{
		cancel = &dummy_bool;
	}
	*error_code = RUDP_ERROR_UNKNOWN;
	if (svc_name == NULL || ip == NULL)
	{
		return NULL;
	}

	ListenTcpForPopupFirewallDialog();

	giveup_tick = Tick64() + (UINT64)timeout;

	// Get the IP address of the NAT-T server
	RUDPGetRegisterHostNameByIP(hostname, sizeof(hostname), ip);
	if (GetIP4Ex(&nat_t_ip, hostname, 0, cancel) == false)
	{
		*error_code = RUDP_ERROR_NAT_T_NO_RESPONSE;
		return NULL;
	}

	if (Tick64() >= giveup_tick)
	{
		*error_code = RUDP_ERROR_TIMEOUT;
		return NULL;
	}
	if (*cancel)
	{
		*error_code = RUDP_ERROR_USER_CANCELED;
		return NULL;
	}

	sock = NewUDP4ForSpecificIp(&nat_t_ip, 0);
	if (sock == NULL)
	{
		*error_code = RUDP_ERROR_UNKNOWN;
		return NULL;
	}
	else
	{
		UINT64 next_send_request_tick = 0;
		INTERRUPT_MANAGER *interrupt = NewInterruptManager();
		UINT64 tran_id = Rand64();
		UINT tmp_size = 65536;
		UCHAR *tmp = Malloc(tmp_size);
		char result_ip_str[MAX_SIZE];
		IP result_ip;
		UINT result_port;
		SOCK *ret = NULL;
		UINT num_tries = 0;
		UINT64 current_cookie = 0;

		AddInterrupt(interrupt, giveup_tick);

		sock_event = NewSockEvent();
		JoinSockToSockEvent(sock, sock_event);

		// Communication with the NAT-T server
		while (true)
		{
			UINT64 now = Tick64();
			UINT interval;
			UINT r;
			IP src_ip;
			UINT src_port;
			UINT err;
			UINT num_ignore_errors = 0;

			if (now >= giveup_tick)
			{
				// Time-out
LABEL_TIMEOUT:
				*error_code = RUDP_ERROR_NAT_T_NO_RESPONSE;
				break;
			}

			if (*cancel)
			{
				// User canceled
				*error_code = RUDP_ERROR_USER_CANCELED;
				break;
			}

			err = INFINITE;

			// Receive a response packet from the NAT-T server
			while (err == INFINITE)
			{
				r = RecvFrom(sock, &src_ip, &src_port, tmp, tmp_size);
				if (r == SOCK_LATER)
				{
					// No packet
					break;
				}
				else if (r == 0)
				{
					if (sock->IgnoreRecvErr == false)
					{
						// Communication error
						goto LABEL_TIMEOUT;
					}
					else
					{
						if ((num_ignore_errors++) >= MAX_NUM_IGNORE_ERRORS)
						{
							goto LABEL_TIMEOUT;
						}
					}
				}
				else
				{
					// Check the source IP address and the port number
					if (CmpIpAddr(&src_ip, &nat_t_ip) == 0 && src_port == UDP_NAT_T_PORT)
					{
						BUF *b = NewBuf();
						PACK *p;

						WriteBuf(b, tmp, r);
						SeekBuf(b, 0, 0);


						p = BufToPack(b);

						if (p != NULL)
						{
							UINT64 cookie = PackGetInt64(p, "cookie");
							if (cookie != 0)
							{
								current_cookie = cookie;
							}

							// Compare tran_id
							if (PackGetInt64(p, "tran_id") == tran_id)
							{
								// Compare opcode
								if (PackCmpStr(p, "opcode", "nat_t_connect_request"))
								{
									bool ok = PackGetBool(p, "ok");
									bool multi_candidate = PackGetBool(p, "multi_candidates");

									if (ok)
									{
										// Success
										PackGetStr(p, "result_ip", result_ip_str, sizeof(result_ip_str));
										StrToIP(&result_ip, result_ip_str);

										result_port = PackGetInt(p, "result_port");

										same_lan = PackGetBool(p, "same_lan");

										if (result_port != 0)
										{
											if (IsZeroIp(&result_ip) == false)
											{
												if ((sock->IPv6 == false && IsIP4(&result_ip)) ||
													(sock->IPv6 && IsIP6(&result_ip)))
												{
													err = RUDP_ERROR_OK;
												}
											}
										}
									}
									else if (multi_candidate)
									{
										// There are two or more computers behind the specified IP address
										err = RUDP_ERROR_NAT_T_TWO_OR_MORE;
									}
									else
									{
										// Failure
										err = RUDP_ERROR_NAT_T_NOT_FOUND;
									}
								}
							}

							FreePack(p);
						}

						FreeBuf(b);
					}
				}
			}

			if (err != INFINITE)
			{
				*error_code = err;
				break;
			}

			if (next_send_request_tick == 0 || now >= next_send_request_tick)
			{
				// Send a connection request to the NAT-T server
				BUF *b;
				char ip_str[MAX_SIZE];
				PACK *p = NewPack();

				PackAddStr(p, "opcode", "nat_t_connect_request");
				PackAddInt64(p, "tran_id", tran_id);
				IPToStr(ip_str, sizeof(ip_str), ip);
				PackAddStr(p, "dest_ip", ip_str);
				PackAddInt64(p, "cookie", current_cookie);
				if (IsEmptyStr(hint_str) == false)
				{
					PackAddStr(p, "hint", hint_str);
				}
				if (IsEmptyStr(target_hostname) == false)
				{
					PackAddStr(p, "target_hostname", target_hostname);
				}
				PackAddStr(p, "svc_name", svc_name);

				PackAddInt(p, "nat_traversal_version", UDP_NAT_TRAVERSAL_VERSION);

				b = PackToBuf(p);
				FreePack(p);

				SendTo(sock, &nat_t_ip, UDP_NAT_T_PORT, b->Buf, b->Size);
				FreeBuf(b);

				// Determine the next transmission time
				next_send_request_tick = now + (UINT64)UDP_NAT_T_CONNECT_INTERVAL * (UINT64)(Power(2, MAX(num_tries, 6)));
				num_tries++;
				AddInterrupt(interrupt, next_send_request_tick);
			}

			interval = GetNextIntervalForInterrupt(interrupt);
			interval = MIN(interval, 50);

			WaitSockEvent(sock_event, interval);
		}

		Free(tmp);
		FreeInterruptManager(interrupt);

		if (*error_code == RUDP_ERROR_OK)
		{
			UINT remain_timeout;
			UINT64 now = Tick64();
			// Success to get the IP address and the port number of the target

			// Get the rest timeout tolerance
			if (now <= giveup_tick)
			{
				remain_timeout = (UINT)(giveup_tick - now);
			}
			else
			{
				remain_timeout = 0;
			}

			remain_timeout = MAX(remain_timeout, 2000);

			if (same_lan)
			{
				// Discard current UDP socket and create a new UDP socket in NewRUDPClientDirect().
				// Because using a UDP socket which used for communication with the NAT-T server
				// can cause trouble when the client and the server exists in the same LAN.
				ReleaseSockEvent(sock_event);
				ReleaseSock(sock);

				sock = NULL;
				sock_event = NULL;
			}

			ret = NewRUDPClientDirect(svc_name, &result_ip, result_port, error_code, remain_timeout, cancel,
				sock, sock_event, 0, false);
		}

		if (sock_event != NULL)
		{
			ReleaseSockEvent(sock_event);
		}

		if (sock != NULL)
		{
			if (ret == NULL)
			{
				Disconnect(sock);
			}

			ReleaseSock(sock);
		}

		return ret;
	}
}

// Listen to the TCP for a moment to show the firewall dialog
void ListenTcpForPopupFirewallDialog()
{
#ifdef	OS_WIN32
	static bool tried = false;

	if (tried == false)
	{
		SOCK *s;
		tried = true;
		s = ListenAnyPortEx2(false, true);

		if (s != NULL)
		{
			Disconnect(s);
			ReleaseSock(s);
		}
	}
#endif	// OS_WIN32
}

// Create a R-UDP client (direct connection)
SOCK *NewRUDPClientDirect(char *svc_name, IP *ip, UINT port, UINT *error_code, UINT timeout, bool *cancel, SOCK *sock, SOCK_EVENT *sock_event, UINT local_port, bool over_dns_mode)
{
	RUDP_STACK *r;
	UINT dummy_int = 0;
	SOCK *ret = NULL;
	// Validate arguments
	if (error_code == NULL)
	{
		error_code = &dummy_int;
	}
	if (timeout == 0)
	{
		timeout = RUDP_TIMEOUT;
	}
	*error_code = RUDP_ERROR_UNKNOWN;
	if (svc_name == NULL || ip == NULL || port == 0)
	{
		return NULL;
	}

	r = NewRUDP(false, svc_name, NULL, NULL, NULL, local_port, sock, sock_event, false, over_dns_mode, ip, NULL, 0);
	if (r == NULL)
	{
		*error_code = RUDP_ERROR_UNKNOWN;
		return NULL;
	}

	// Set the port number and the target IP address
	Lock(r->Lock);
	{
		Copy(&r->TargetIp, ip, sizeof(IP));
		r->TargetPort = port;
		r->TargetIpAndPortInited = true;
	}
	Unlock(r->Lock);
	SetSockEvent(r->SockEvent);

	// Wait for a connection success/failure to the target IP address
	WaitEx(r->TargetConnectedEvent, timeout, cancel);
	Lock(r->Lock);
	{
		if (r->TargetConnectedSock != NULL)
		{
			// The connection succeeded
			ret = r->TargetConnectedSock;
			r->TargetConnectedSock = NULL;
		}
		else
		{
			r->DoNotSetTargetConnectedSock = true;
		}
	}
	Unlock(r->Lock);

	if (ret == NULL)
	{
		// Stop the R-UDP stack if the connection has failed
		*error_code = RUDP_ERROR_TIMEOUT;
		FreeRUDP(r);
	}
	else if (cancel != NULL && (*cancel))
	{
		// User canceled
		*error_code = RUDP_ERROR_USER_CANCELED;

		Disconnect(ret);
		ReleaseSock(ret);

		ret = NULL;
	}
	else
	{
		*error_code = RUDP_ERROR_OK;
	}

	return ret;
}

// Creating a R-UDP server
RUDP_STACK *NewRUDPServer(char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, bool no_natt_register, bool over_dns_mode, volatile UINT *natt_global_udp_port, UCHAR rand_port_id)
{
	RUDP_STACK *r;
	// Validate arguments
	if (IsEmptyStr(svc_name))
	{
		return NULL;
	}

	if (g_no_rudp_server)
	{
		return NULL;
	}

	ListenTcpForPopupFirewallDialog();

	r = NewRUDP(true, svc_name, proc_interrupts, proc_rpc_recv, param, port, NULL, NULL, no_natt_register, over_dns_mode, NULL, natt_global_udp_port, rand_port_id);

	if (r == NULL)
	{
		return NULL;
	}

	return r;
}

// Creating a R-UDP
RUDP_STACK *NewRUDP(bool server_mode, char *svc_name, RUDP_STACK_INTERRUPTS_PROC *proc_interrupts, RUDP_STACK_RPC_RECV_PROC *proc_rpc_recv, void *param, UINT port, SOCK *sock, SOCK_EVENT *sock_event, bool server_no_natt_register, bool over_dns_mode, IP *client_target_ip, volatile UINT *natt_global_udp_port, UCHAR rand_port_id)
{
	RUDP_STACK *r;
	char tmp[MAX_SIZE];
	UCHAR pid_hash[SHA1_SIZE];
	UINT pid;
	USHORT pid_us;

	// Validate arguments
	if (IsEmptyStr(svc_name))
	{
		return NULL;
	}

	ListenTcpForPopupFirewallDialog();

	if (sock == NULL)
	{
		if (server_mode == false && client_target_ip != NULL)
		{
			sock = NewUDP4ForSpecificIp(client_target_ip, port);
		}
		else
		{
			if (rand_port_id == 0)
			{
				sock = NewUDP(port);
			}
			else
			{
				sock = NewUDPEx2RandMachineAndExePath(false, NULL, 0, rand_port_id);
			}
		}

		if (sock == NULL)
		{
			return NULL;
		}
	}
	else
	{
		AddRef(sock->ref);
	}

	if (port == 0)
	{
		port = sock->LocalPort;
	}

	if (rand_port_id != 0)
	{
		rand_port_numbers[rand_port_id] = port;
	}

	if (sock_event == NULL)
	{
		sock_event = NewSockEvent();
	}
	else
	{
		AddRef(sock_event->ref);
	}

	r = ZeroMalloc(sizeof(RUDP_STACK));

	r->NatT_SessionKey = Rand64();

	StrCpy(r->SvcName, sizeof(r->SvcName), svc_name);
	r->RandPortId = rand_port_id;
	r->NatTGlobalUdpPort = natt_global_udp_port;
	r->ServerMode = server_mode;
	r->Interrupt = NewInterruptManager();
	r->SessionList = NewList(RUDPCompareSessionList);
	r->UdpSock = sock;
	r->Port = port;
	r->SockEvent = sock_event;
	r->HaltEvent = NewEvent();
	r->Now = Tick64();
	r->Lock = NewLock();
	r->Param = param;
	r->TargetConnectedEvent = NewEvent();
	r->SendPacketList = NewList(NULL);
	r->NewSockConnectEvent = NewEvent();
	r->NewSockQueue = NewQueue();
	r->NatT_TranId = Rand64();

	r->NatT_SourceIpList = NewListFast(NULL);

	StrCpy(tmp, sizeof(tmp), r->SvcName);
	Trim(tmp);
	StrLower(tmp);

	HashSha1(r->SvcNameHash, tmp, StrLen(tmp));

	r->Client_IcmpId = (USHORT)(Rand32() % 65534 + 1);
	r->Client_IcmpSeqNo = (USHORT)(Rand32() % 65534 + 1);

	// Determination of the type of the protocol
	r->Protocol = RUDP_PROTOCOL_UDP;
	if (r->Port == MAKE_SPECIAL_PORT(IP_PROTO_ICMPV4))
	{
		r->Protocol = RUDP_PROTOCOL_ICMP;

		// Generate the ICMP ID based on the process ID
#ifdef	OS_WIN32
		pid = (UINT)MsGetProcessId();
#else	// OS_WIN32
		pid = (UINT)getpid();
#endif	// OS_WIN32

		pid = Endian32(pid);
		HashSha1(pid_hash, &pid, sizeof(UINT));

		pid_us = READ_USHORT(pid_hash);
		if (pid_us == 0 || pid_us == 0xFFFF)
		{
			pid_us = 1;
		}

		r->Client_IcmpId = pid_us;
	}
	else if (over_dns_mode)
	{
		r->Protocol = RUDP_PROTOCOL_DNS;
	}

	if (r->ServerMode)
	{
		r->NoNatTRegister = server_no_natt_register;

		if (r->Protocol == RUDP_PROTOCOL_ICMP || r->Protocol == RUDP_PROTOCOL_DNS)
		{
			// Never register to the NAT-T server in case of using the DNS or the ICMP
			r->NoNatTRegister = true;
		}
	}

	if (true
		)
	{
		RUDPGetRegisterHostNameByIP(r->CurrentRegisterHostname, sizeof(r->CurrentRegisterHostname), NULL);
	}

	if (r->ServerMode)
	{
		r->ProcInterrupts = proc_interrupts;
		r->ProcRpcRecv = proc_rpc_recv;
	}

	if (r->ServerMode && r->NoNatTRegister == false
		)
	{
		r->IpQueryThread = NewThread(RUDPIpQueryThread, r);
	}

	JoinSockToSockEvent(r->UdpSock, r->SockEvent);

	r->Thread = NewThread(RUDPMainThread, r);
	WaitThreadInit(r->Thread);

	return r;
}

// R-UDP session comparison function
int RUDPCompareSessionList(void *p1, void *p2)
{
	RUDP_SESSION *s1, *s2;
	UINT r;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *((RUDP_SESSION **)p1);
	s2 = *((RUDP_SESSION **)p2);
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	r = CmpIpAddr(&s1->YourIp, &s2->YourIp);
	if (r != 0)
	{
		return r;
	}

	r = COMPARE_RET(s1->YourPort, s2->YourPort);
	if (r != 0)
	{
		return r;
	}

	r = CmpIpAddr(&s1->MyIp, &s2->MyIp);
	if (r != 0)
	{
		return r;
	}

	r = COMPARE_RET(s1->MyPort, s2->MyPort);
	if (r != 0)
	{
		return r;
	}

	return 0;
}

// Release of the R-UDP
void FreeRUDP(RUDP_STACK *r)
{
	UINT i;
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	r->Halt = true;
	Set(r->HaltEvent);
	SetSockEvent(r->SockEvent);

	if (r->ServerMode && r->NoNatTRegister == false)
	{
		if (r->IpQueryThread != NULL)
		{
			WaitThread(r->IpQueryThread, INFINITE);
			ReleaseThread(r->IpQueryThread);
		}
	}

	WaitThread(r->Thread, INFINITE);
	ReleaseThread(r->Thread);

	for (i = 0;i < LIST_NUM(r->SessionList);i++)
	{
		RUDP_SESSION *se = LIST_DATA(r->SessionList, i);

		RUDPFreeSession(se);
	}

	ReleaseList(r->SessionList);

	for (i = 0;i < LIST_NUM(r->SendPacketList);i++)
	{
		UDPPACKET *p = LIST_DATA(r->SendPacketList, i);

		FreeUdpPacket(p);
	}

	while (true)
	{
		SOCK *s = GetNext(r->NewSockQueue);
		if (s == NULL)
		{
			break;
		}

		Disconnect(s);
		ReleaseSock(s);
	}

	for (i = 0;i < LIST_NUM(r->NatT_SourceIpList);i++)
	{
		RUDP_SOURCE_IP *sip = (RUDP_SOURCE_IP *)LIST_DATA(r->NatT_SourceIpList, i);

		Free(sip);
	}

	ReleaseList(r->NatT_SourceIpList);

	ReleaseQueue(r->NewSockQueue);

	ReleaseList(r->SendPacketList);

	FreeInterruptManager(r->Interrupt);

	Disconnect(r->UdpSock);
	ReleaseSock(r->UdpSock);
	ReleaseSockEvent(r->SockEvent);
	ReleaseEvent(r->HaltEvent);
	ReleaseEvent(r->TargetConnectedEvent);

	ReleaseEvent(r->NewSockConnectEvent);

	Disconnect(r->TargetConnectedSock);
	ReleaseSock(r->TargetConnectedSock);

	DeleteLock(r->Lock);

	if (r->RandPortId != 0)
	{
		rand_port_numbers[r->RandPortId] = 0;
	}

	Free(r);
}

// Generate a hash from the current computer name and the process name
void GetCurrentMachineIpProcessHash(void *hash)
{
	// Validate arguments
	if (hash == NULL)
	{
		return;
	}

	Lock(machine_ip_process_hash_lock);
	{
		if (IsZero(machine_ip_process_hash, SHA1_SIZE))
		{
			GetCurrentMachineIpProcessHashInternal(machine_ip_process_hash);
		}

		Copy(hash, machine_ip_process_hash, SHA1_SIZE);
	}
	Unlock(machine_ip_process_hash_lock);
}
void GetCurrentMachineIpProcessHashInternal(void *hash)
{
	BUF *b;
	LIST *ip_list;
	char machine_name[MAX_SIZE];
	wchar_t exe_path[MAX_PATH];
	char *product_id = NULL;
	// Validate arguments
	if (hash == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId");
	if (product_id == NULL)
	{
		product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId");
	}
#endif	// OS_WIN32

	b = NewBuf();

	GetMachineHostName(machine_name, sizeof(machine_name));
	Trim(machine_name);
	StrUpper(machine_name);

	GetExeNameW(exe_path, sizeof(exe_path));
	UniTrim(exe_path);
	UniStrUpper(exe_path);

	WriteBuf(b, machine_name, StrSize(machine_name));
	WriteBuf(b, exe_path, UniStrSize(exe_path));
	WriteBuf(b, product_id, StrSize(product_id));

	ip_list = GetHostIPAddressList();
	if (ip_list != NULL)
	{
		UINT i;
		for (i = 0;i < LIST_NUM(ip_list);i++)
		{
			IP *ip = LIST_DATA(ip_list, i);

			WriteBuf(b, ip, sizeof(IP));
		}
	}
	FreeHostIPAddressList(ip_list);

	HashSha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Free(product_id);
}

// Create a pair of pre-bound TCP sockets
bool NewTcpPair(SOCK **s1, SOCK **s2)
{
	SOCK *a;
	SOCK *s, *c;
	TUBE *t1, *t2;
	SOCK_EVENT *e1, *e2;
	// Validate arguments
	if (s1 == NULL || s2 == NULL)
	{
		return false;
	}

	a = ListenAnyPortEx2(true, true);
	if (a == NULL)
	{
		return false;
	}

	c = Connect("127.0.0.1", a->LocalPort);
	if (c == NULL)
	{
		ReleaseSock(a);
		return false;
	}

	s = Accept(a);
	if (s == NULL)
	{
		ReleaseSock(c);
		ReleaseSock(a);
		return false;
	}

	ReleaseSock(a);

	if ((s->LocalPort != c->RemotePort) || (s->RemotePort != c->LocalPort))
	{
		ReleaseSock(s);
		ReleaseSock(c);
		return false;
	}

	NewTubePair(&t1, &t2, sizeof(TCP_PAIR_HEADER));

	// Creating a socket event
	e1 = NewSockEvent();
	e2 = NewSockEvent();

	SetTubeSockEvent(t1, e1);
	SetTubeSockEvent(t2, e2);

	AddRef(t1->Ref);
	AddRef(t2->Ref);
	s->BulkRecvTube = c->BulkSendTube = t1;
	s->BulkSendTube = c->BulkRecvTube = t2;

	ReleaseSockEvent(e1);
	ReleaseSockEvent(e2);

	*s1 = s;
	*s2 = c;

	return true;
}

// Listen in any available port
SOCK *ListenAnyPortEx(bool local_only)
{
	return ListenAnyPortEx2(local_only, false);
}
SOCK *ListenAnyPortEx2(bool local_only, bool disable_ca)
{
	UINT i;
	SOCK *s;
	for (i = 40000;i < 65536;i++)
	{
		s = ListenEx(i, local_only);
		if (s != NULL)
		{
			return s;
		}
	}

	return NULL;
}

int cb_test(int a, X509_STORE_CTX *ctx)
{
	WHERE;
	return 1;
}

// Create a new SSL pipe
SSL_PIPE *NewSslPipe(bool server_mode, X *x, K *k, DH_CTX *dh)
{
	SSL_PIPE *s;
	SSL *ssl;
	SSL_CTX *ssl_ctx = NewSSLCtx(server_mode);

	Lock(openssl_lock);
	{
		if (server_mode)
		{
			SSL_CTX_set_ssl_version(ssl_ctx, SSLv23_method());
			SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

			AddChainSslCertOnDirectory(ssl_ctx);

			if (dh != NULL)
			{
				SSL_CTX_set_tmp_dh(ssl_ctx, dh->dh);
			}
		}
		else
		{
			SSL_CTX_set_ssl_version(ssl_ctx, SSLv23_client_method());
		}

		//SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, cb_test);

		if (dh != NULL)
		{
			SSL_CTX_set_options(ssl_ctx, SSL_OP_SINGLE_DH_USE);
		}

		if (server_mode == false)
		{
			SSL_CTX_set_options(ssl_ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
		}

		ssl = SSL_new(ssl_ctx);
	}
	Unlock(openssl_lock);

	s = ZeroMalloc(sizeof(SSL_PIPE));

	s->ssl = ssl;
	s->ssl_ctx = ssl_ctx;
	s->ServerMode = server_mode;

	s->SslInOut = NewSslBioSsl();
	s->RawIn = NewSslBioMem();
	s->RawOut = NewSslBioMem();

	if (x != NULL && k != NULL)
	{
		Lock(openssl_lock);
		{
			SSL_use_certificate(s->ssl, x->x509);
			SSL_use_PrivateKey(s->ssl, k->pkey);
		}
		Unlock(openssl_lock);
	}

	if (s->ServerMode == false)
	{
		SSL_set_connect_state(s->ssl);
	}
	else
	{
		SSL_set_accept_state(s->ssl);
	}

	SSL_set_bio(s->ssl, s->RawIn->bio, s->RawOut->bio);
	BIO_set_ssl(s->SslInOut->bio, s->ssl, BIO_NOCLOSE);

	//s->RawIn->NoFree = true;
	s->RawOut->NoFree = true;

	return s;
}

// Synchronization of the SSL pipe
bool SyncSslPipe(SSL_PIPE *s)
{
	UINT i;
	// Validate arguments
	if (s == NULL || s->IsDisconnected)
	{
		return false;
	}

	for (i = 0;i < 2;i++)
	{
		if (SslBioSync(s->RawIn, true, false) == false)
		{
			s->IsDisconnected = true;
			Debug("SyncSslPipe: s->RawIn error.\n");
			return false;
		}

		if (SslBioSync(s->RawOut, false, true) == false)
		{
			s->IsDisconnected = true;
			Debug("SyncSslPipe: s->RawOut error.\n");
			return false;
		}

		if (SslBioSync(s->SslInOut, true, true) == false)
		{
			s->IsDisconnected = true;
			Debug("SyncSslPipe: s->SslInOut error.\n");
			return false;
		}
	}

	return true;
}

// Release of the SSL pipe
void FreeSslPipe(SSL_PIPE *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	FreeSslBio(s->SslInOut);
	FreeSslBio(s->RawIn);
	FreeSslBio(s->RawOut);

	SSL_free(s->ssl);
	SSL_CTX_free(s->ssl_ctx);

	Free(s);
}

// Release of the SSL BIO
void FreeSslBio(SSL_BIO *b)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	if (b->NoFree == false)
	{
		BIO_free(b->bio);
	}

	ReleaseFifo(b->RecvFifo);
	ReleaseFifo(b->SendFifo);

	Free(b);
}

// Create a new SSL BIO (SSL)
SSL_BIO *NewSslBioSsl()
{
	SSL_BIO *b = ZeroMalloc(sizeof(SSL_BIO));

	b->bio = BIO_new(BIO_f_ssl());

	b->RecvFifo = NewFifo();
	b->SendFifo = NewFifo();

	return b;
}

// Create a new SSL BIO (memory)
SSL_BIO *NewSslBioMem()
{
	SSL_BIO *b = ZeroMalloc(sizeof(SSL_BIO));

	b->bio = BIO_new(BIO_s_mem());

	b->RecvFifo = NewFifo();
	b->SendFifo = NewFifo();

	return b;
}

// Synchronize memory contents of the SSL BIO with the FIFO
bool SslBioSync(SSL_BIO *b, bool sync_send, bool sync_recv)
{
	// Validate arguments
	if (b == NULL)
	{
		return false;
	}

	if (b->IsDisconnected)
	{
		return false;
	}

	// Write the contents of the SendFifo to the BIO
	if (sync_send)
	{
		while (b->SendFifo->size >= 1)
		{
			int r = BIO_write(b->bio, GetFifoPointer(b->SendFifo), FifoSize(b->SendFifo));

			if (r == 0)
			{
				b->IsDisconnected = true;
				WHERE;
				return false;
			}
			else
			{
				if (r < 0)
				{
					if (BIO_should_retry(b->bio))
					{
						break;
					}
					else
					{
						b->IsDisconnected = true;
						WHERE;
						return false;
					}
				}
				else
				{
					ReadFifo(b->SendFifo, NULL, (UINT)r);
				}
			}
		}
	}

	// Save to the RecvFifo by reading from the BIO
	if (sync_recv)
	{
		while (true)
		{
			UCHAR tmp[4096];
			int r;

			r = BIO_read(b->bio, tmp, sizeof(tmp));

			if (r == 0)
			{
				b->IsDisconnected = true;
				WHERE;
				return false;
			}
			else
			{
				if (r < 0)
				{
					if (BIO_should_retry(b->bio))
					{
						break;
					}
					else
					{
						b->IsDisconnected = true;
						WHERE;
						Debug("OpenSSL Error: %s\n", ERR_error_string(ERR_peek_last_error(), NULL));
						return false;
					}
				}
				else
				{
					WriteFifo(b->RecvFifo, tmp, (UINT)r);
				}
			}
		}
	}

	return true;
}

// Release the memory for the return value of the ICMP API
void IcmpApiFreeResult(ICMP_RESULT *ret)
{
	// Validate arguments
	if (ret == NULL)
	{
		return;
	}

	if (ret->Data != NULL)
	{
		Free(ret->Data);
	}

	Free(ret);
}

// Send an ICMP Echo using ICMP API
ICMP_RESULT *IcmpApiEchoSend(IP *dest_ip, UCHAR ttl, UCHAR *data, UINT size, UINT timeout)
{
#ifdef	OS_WIN32
	// Validate arguments
	if (dest_ip == NULL || IsIP4(dest_ip) == false || (size != 0 && data == NULL))
	{
		return NULL;
	}
	if (ttl == 0)
	{
		ttl = 127;
	}

	if (IsIcmpApiSupported())
	{
		HANDLE h;
		DWORD dw;
		IPAddr dest_addr;
		UINT reply_size;
		ICMP_ECHO_REPLY *reply;
		ICMP_RESULT *ret = NULL;
		IP_OPTION_INFORMATION opt;

		h = w32net->IcmpCreateFile();

		if (h == INVALID_HANDLE_VALUE)
		{
			return NULL;
		}

		Zero(&opt, sizeof(opt));
		opt.Ttl = ttl;

		IPToInAddr((struct in_addr *)&dest_addr, dest_ip);

		reply_size = sizeof(*reply) + size + 64;
		reply = ZeroMalloc(reply_size);

		dw = w32net->IcmpSendEcho(h, dest_addr, data, size, &opt, reply, reply_size, timeout);

		ret = ZeroMalloc(sizeof(ICMP_RESULT));

		if (dw >= 1 && reply->Status == IP_SUCCESS)
		{
			ret->Ok = true;
		}
		else
		{
			switch (reply->Status)
			{
			case IP_DEST_NET_UNREACHABLE:
				ret->Type = ICMP_TYPE_DESTINATION_UNREACHABLE;
				ret->Code = ICMP_CODE_NET_UNREACHABLE;
				break;

			case IP_DEST_HOST_UNREACHABLE:
				ret->Type = ICMP_TYPE_DESTINATION_UNREACHABLE;
				ret->Code = ICMP_CODE_HOST_UNREACHABLE;
				break;

			case IP_DEST_PROT_UNREACHABLE:
				ret->Type = ICMP_TYPE_DESTINATION_UNREACHABLE;
				ret->Code = ICMP_CODE_PROTOCOL_UNREACHABLE;
				break;

			case IP_DEST_PORT_UNREACHABLE:
				ret->Type = ICMP_TYPE_DESTINATION_UNREACHABLE;
				ret->Code = ICMP_CODE_PORT_UNREACHABLE;
				break;

			case IP_TTL_EXPIRED_TRANSIT:
				ret->Type = ICMP_TYPE_TIME_EXCEEDED;
				ret->Code = ICMP_CODE_TTL_EXCEEDED_IN_TRANSIT;
				break;

			case IP_TTL_EXPIRED_REASSEM:
				ret->Type = ICMP_TYPE_TIME_EXCEEDED;
				ret->Code = ICMP_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDED;
				break;

			default:
				ret->Timeout = true;
				break;
			}
		}

		if (ret->Timeout == false)
		{
			ret->Ttl = reply->Options.Ttl;
			ret->Rtt = reply->RoundTripTime;
			InAddrToIP(&ret->IpAddress, (struct in_addr *)&reply->Address);

			if (reply->DataSize >= 1 && reply->Data != NULL)
			{
				ret->DataSize = reply->DataSize;
				ret->Data = Clone(reply->Data, reply->DataSize);
			}
		}

		Free(reply);

		w32net->IcmpCloseHandle(h);

		return ret;
	}
	else
	{
		return NULL;
	}

#else	// OS_WIN32
	return NULL;
#endif	// OS_WIN32
}

// Detect whether the ICMP API is supported
bool IsIcmpApiSupported()
{
#ifdef	OS_WIN32
	if (w32net->IcmpCloseHandle != NULL &&
		w32net->IcmpCreateFile != NULL &&
		w32net->IcmpSendEcho != NULL)
	{
		return true;
	}
#endif	// OS_WIN32

	return false;
}

// Initialize the routing table change detector
ROUTE_CHANGE *NewRouteChange()
{
#ifdef	OS_WIN32
	return Win32NewRouteChange();
#else	// OS_WIN32
	return NULL;
#endif	// OS_WIN32
}

// Release the routing table change detector
void FreeRouteChange(ROUTE_CHANGE *r)
{
#ifdef	OS_WIN32
	Win32FreeRouteChange(r);
#endif	// OS_WIN32
}

// Get whether the routing table has been changed
bool IsRouteChanged(ROUTE_CHANGE *r)
{
#ifdef	OS_WIN32
	return Win32IsRouteChanged(r);
#else	// OS_WIN32
	return false;
#endif	// OS_WIN32
}

// Routing table change detector function (Win32)
#ifdef	OS_WIN32
ROUTE_CHANGE *Win32NewRouteChange()
{
	ROUTE_CHANGE *r;
	bool ret;

	if (MsIsNt() == false)
	{
		return NULL;
	}

	if (w32net->CancelIPChangeNotify == NULL ||
		w32net->NotifyRouteChange == NULL)
	{
		return NULL;
	}

	r = ZeroMalloc(sizeof(ROUTE_CHANGE));

	r->Data = ZeroMalloc(sizeof(ROUTE_CHANGE_DATA));

	r->Data->Overlapped.hEvent = CreateEventA(NULL, false, true, NULL);

	ret = w32net->NotifyRouteChange(&r->Data->Handle, &r->Data->Overlapped);
	if (!(ret == NO_ERROR || ret == WSA_IO_PENDING || WSAGetLastError() == WSA_IO_PENDING))
	{
		Free(r->Data);
		Free(r);

		return NULL;
	}

	return r;
}

void Win32FreeRouteChange(ROUTE_CHANGE *r)
{
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	w32net->CancelIPChangeNotify(&r->Data->Overlapped);
	CloseHandle(r->Data->Overlapped.hEvent);

	Free(r->Data);
	Free(r);
}

bool Win32IsRouteChanged(ROUTE_CHANGE *r)
{
	// Validate arguments
	if (r == NULL)
	{
		return false;
	}

	if ((r->Data->NumCalled++) == 0)
	{
		return true;
	}

	if (WaitForSingleObject(r->Data->Overlapped.hEvent, 0) == WAIT_OBJECT_0)
	{
		w32net->NotifyRouteChange(&r->Data->Handle, &r->Data->Overlapped);
		return true;
	}

	return false;
}

typedef struct WIN32_ACCEPT_CHECK_DATA
{
	bool IsIPv6;
	bool Rejected;
} WIN32_ACCEPT_CHECK_DATA;

// Function for determining  whether accept or not in Win32
int CALLBACK Win32AcceptCheckCallback_Delay(LPWSABUF lpCallerId, LPWSABUF lpCallerData, LPQOS pQos,
									  LPQOS lpGQOS, LPWSABUF lpCalleeId, LPWSABUF lpCalleeData,
									  GROUP FAR * g, DWORD_PTR dwCallbackData)
{
	return CF_DEFER;
}

int CALLBACK Win32AcceptCheckCallback(LPWSABUF lpCallerId, LPWSABUF lpCallerData, LPQOS pQos,
									  LPQOS lpGQOS, LPWSABUF lpCalleeId, LPWSABUF lpCalleeData,
									  GROUP FAR * g, DWORD_PTR dwCallbackData)
{
	return CF_ACCEPT;
}

// Accept function for Win32
SOCKET Win32Accept_XP(SOCK *sock, SOCKET s, struct sockaddr *addr, int *addrlen, bool ipv6)
{
	SOCKET ret;
	WIN32_ACCEPT_CHECK_DATA d;
	UINT err;
	int initial_addrlen = *addrlen;
	UINT num_error = 0;
	// Validate arguments
	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

L_LOOP:

	Zero(&d, sizeof(d));

	d.IsIPv6 = ipv6;

	*addrlen = initial_addrlen;
	Zero(addr, initial_addrlen);
	ret = WSAAccept(s, addr, addrlen, Win32AcceptCheckCallback, (DWORD_PTR)&d);

	if (ret == INVALID_SOCKET)
	{
		err = WSAGetLastError();

		num_error++;

		Debug("!!! WSAAccept Error: %u  rej=%u  num=%u  tick=%I64u\n", WSAGetLastError(), d.Rejected, num_error, Tick64());

		if (d.Rejected && err == WSAECONNREFUSED)
		{
			goto L_LOOP;
		}

		if (err == WSAETIMEDOUT)
		{
			goto L_LOOP;
		}
	}

	return ret;
}

// Accept function for Win32
SOCKET Win32Accept(SOCK *sock, SOCKET s, struct sockaddr *addr, int *addrlen, bool ipv6)
{
	SOCKET ret;
	WIN32_ACCEPT_CHECK_DATA d;
	UINT err;
	int initial_addrlen = *addrlen;
	UINT num_error = 0;
	UINT zero = 0;
	UINT tmp = 0;
	UINT ret_size = 0;
	// Validate arguments
	if (sock == NULL || s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	if (sock->hAcceptEvent == NULL)
	{
		sock->hAcceptEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

		WSAEventSelect(s, sock->hAcceptEvent, FD_ACCEPT | FD_CLOSE);
	}

L_LOOP:

	if (sock->CancelAccept)
	{
		return INVALID_SOCKET;
	}

	Zero(&d, sizeof(d));

	d.IsIPv6 = ipv6;

	*addrlen = initial_addrlen;
	Zero(addr, initial_addrlen);
	ret = WSAAccept(s, addr, addrlen, Win32AcceptCheckCallback, (DWORD_PTR)&d);

	if (ret == INVALID_SOCKET)
	{
		err = WSAGetLastError();

		if (err == WSAEWOULDBLOCK)
		{
			//Debug("!!! WSAAccept: WSAEWOULDBLOCK\n");
			UINT wait_ret = WaitForSingleObject(sock->hAcceptEvent, 1234);

			if (wait_ret == WAIT_OBJECT_0 || wait_ret == WAIT_TIMEOUT)
			{
				goto L_LOOP;
			}

			Debug("!!! WaitForSingleObject Error. ret=%u GetLastError=%u\n", wait_ret, GetLastError());
		}

		num_error++;

		Debug("!!! WSAAccept Error: %u  rej=%u  num=%u  tick=%I64u\n", err, d.Rejected, num_error, Tick64());

		if (d.Rejected && err == WSAECONNREFUSED)
		{
			goto L_LOOP;
		}

		if (err == WSAETIMEDOUT)
		{
			goto L_LOOP;
		}
	}
	else
	{
		// Remove a new socket from the event
		WSAEventSelect(ret, sock->hAcceptEvent, 0);

		// Restore the new socket to synchronized
		WSAIoctl(ret, FIONBIO, &zero, sizeof(zero), &tmp, sizeof(tmp), &ret_size, NULL, NULL);
	}

	return ret;
}

#endif	// OS_WIN32


// Get whether the aquirement of the Process ID of the TCP connection succeed
bool CanGetTcpProcessId()
{
	UINT i;
	bool ret = false;
	LIST *o = GetTcpTableList();

	if (o == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		TCPTABLE *t = LIST_DATA(o, i);

		if (t->ProcessId != 0)
		{
			ret = true;
			break;
		}
	}

	FreeTcpTableList(o);

	return ret;
}




#define	USE_OLD_GETIP

// Set the arp_filter in Linux
void SetLinuxArpFilter()
{
	char *filename = "/proc/sys/net/ipv4/conf/all/arp_filter";
	char *data = "1\n";
	IO *o;

	o = FileCreate(filename);
	if (o == NULL)
	{
		return;
	}

	FileWrite(o, data, StrLen(data));
	FileFlush(o);

	FileClose(o);
}

// Determine whether the string is a IPv6 mask
bool IsIpMask6(char *str)
{
	IP mask;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	return StrToMask6(&mask, str);
}

// Determine whether the string is a IPv6 address
bool IsStrIPv6Address(char *str)
{
	IP ip;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	if (StrToIP6(&ip, str) == false)
	{
		return false;
	}

	return true;
}

// Convert the subnet mask to an integer
UINT SubnetMaskToInt6(IP *a)
{
	UINT i;
	// Validate arguments
	if (IsIP6(a) == false)
	{
		return 0;
	}

	for (i = 0;i <= 128;i++)
	{
		IP tmp;

		IntToSubnetMask6(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return i;
		}
	}

	return 0;
}
UINT SubnetMaskToInt4(IP *a)
{
	UINT i;
	// Validate arguments
	if (IsIP4(a) == false)
	{
		return 0;
	}

	for (i = 0;i <= 32;i++)
	{
		IP tmp;

		IntToSubnetMask4(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return i;
		}
	}

	return 0;
}
UINT SubnetMaskToInt(IP *a)
{
	if (IsIP6(a))
	{
		return SubnetMaskToInt6(a);
	}
	else
	{
		return SubnetMaskToInt4(a);
	}
}

// Determine whether the specified IP address is a subnet mask
bool IsSubnetMask6(IP *a)
{
	UINT i;
	// Validate arguments
	if (IsIP6(a) == false)
	{
		return false;
	}

	for (i = 0;i <= 128;i++)
	{
		IP tmp;

		IntToSubnetMask6(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return true;
		}
	}

	return false;
}

// Generate a global address from the MAC address
void GenerateEui64GlobalAddress(IP *ip, IP *prefix, IP *subnet, UCHAR *mac)
{
	UCHAR tmp[8];
	IP a;
	IP subnet_not;
	IP or1, or2;
	// Validate arguments
	if (ip == NULL || prefix == NULL || subnet == NULL || mac == NULL)
	{
		return;
	}

	GenerateEui64Address6(tmp, mac);

	ZeroIP6(&a);

	Copy(&a.ipv6_addr[8], tmp, 8);

	IPNot6(&subnet_not, subnet);
	IPAnd6(&or1, &a, &subnet_not);
	IPAnd6(&or2, prefix, subnet);

	IPOr6(ip, &or1, &or2);
}

// Generate a local address from the MAC address
void GenerateEui64LocalAddress(IP *a, UCHAR *mac)
{
	UCHAR tmp[8];
	// Validate arguments
	if (a == NULL || mac == NULL)
	{
		return;
	}

	GenerateEui64Address6(tmp, mac);

	ZeroIP6(a);
	a->ipv6_addr[0] = 0xfe;
	a->ipv6_addr[1] = 0x80;

	Copy(&a->ipv6_addr[8], tmp, 8);
}

// Generate the EUI-64 address from the MAC address
void GenerateEui64Address6(UCHAR *dst, UCHAR *mac)
{
	// Validate arguments
	if (dst == NULL || mac == NULL)
	{
		return;
	}

	Copy(dst, mac, 3);
	Copy(dst + 5, mac, 3);

	dst[3] = 0xff;
	dst[4] = 0xfe;
	dst[0] = ((~(dst[0] & 0x02)) & 0x02) | (dst[0] & 0xfd);
}

// Examine whether two IP addresses are in the same network
bool IsInSameNetwork6ByStr(char *ip1, char *ip2, char *subnet)
{
	IP p1, p2, s;

	if (StrToIP6(&p1, ip1) == false)
	{
		return false;
	}

	if (StrToIP6(&p2, ip2) == false)
	{
		return false;
	}

	if (StrToMask6(&s, subnet) == false)
	{
		return false;
	}

	return IsInSameNetwork6(&p1, &p2, &s);
}
bool IsInSameNetwork6(IP *a1, IP *a2, IP *subnet)
{
	IP prefix1, prefix2;
	// Validate arguments
	if (IsIP6(a1) == false || IsIP6(a2) == false || IsIP6(subnet) == false)
	{
		return false;
	}

	if (a1->ipv6_scope_id != a2->ipv6_scope_id)
	{
		return false;
	}

	GetPrefixAddress6(&prefix1, a1, subnet);
	GetPrefixAddress6(&prefix2, a2, subnet);

	if (CmpIpAddr(&prefix1, &prefix2) == 0)
	{
		return true;
	}

	return false;
}
bool IsInSameNetwork4(IP *a1, IP *a2, IP *subnet)
{
	IP net1, net2;
	// Validate arguments
	if (IsIP4(a1) == false || IsIP4(a2) == false || IsIP4(subnet) == false)
	{
		return false;
	}

	IPAnd4(&net1, a1, subnet);
	IPAnd4(&net2, a2, subnet);

	if (CmpIpAddr(&net1, &net2) == 0)
	{
		return true;
	}

	return false;
}
bool IsInSameNetwork4Standard(IP *a1, IP *a2)
{
	IP subnet;

	SetIP(&subnet, 255, 255, 0, 0);

	return IsInSameNetwork4(a1, a2, &subnet);
}
bool IsInSameLocalNetworkToMe4(IP *a)
{
	IP g1, g2;

	Zero(&g1, sizeof(g1));
	Zero(&g2, sizeof(g2));

	GetCurrentGlobalIPGuess(&g1, false);

	if (IsZeroIp(&g1) == false)
	{
		if (IsInSameNetwork4Standard(&g1, a))
		{
			return true;
		}
	}

	if (GetCurrentGlobalIP(&g2, false))
	{
		if (IsInSameNetwork4Standard(&g2, a))
		{
			return true;
		}
	}

	if (IsIPAddressInSameLocalNetwork(a))
	{
		return true;
	}

	return false;
}

// Check whether it is a network address prefix
bool IsNetworkAddress6(IP *ip, IP *subnet)
{
	return IsNetworkPrefixAddress6(ip, subnet);
}
bool IsNetworkPrefixAddress6(IP *ip, IP *subnet)
{
	IP host;
	// Validate arguments
	if (ip == NULL || subnet == NULL)
	{
		return false;
	}

	if (IsIP6(ip) == false || IsIP6(subnet) == false)
	{
		return false;
	}

	GetHostAddress6(&host, ip, subnet);

	if (IsZeroIp(&host))
	{
		return true;
	}

	return false;
}

// Check whether the unicast address is available
bool CheckUnicastAddress(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	if ((GetIPAddrType6(ip) & IPV6_ADDR_UNICAST) == 0)
	{
		return false;
	}

	return true;
}

// Get the host address
void GetHostAddress6(IP *dst, IP *ip, IP *subnet)
{
	IP not;
	// Validate arguments
	if (dst == NULL || ip == NULL || subnet == NULL)
	{
		return;
	}

	IPNot6(&not, subnet);

	IPAnd6(dst, ip, &not);

	dst->ipv6_scope_id = ip->ipv6_scope_id;
}

// Get the prefix address
void GetPrefixAddress6(IP *dst, IP *ip, IP *subnet)
{
	// Validate arguments
	if (dst == NULL || ip == NULL || subnet == NULL)
	{
		return;
	}

	IPAnd6(dst, ip, subnet);

	dst->ipv6_scope_id = ip->ipv6_scope_id;
}

// Get the solicited-node multicast address
void GetSoliciationMulticastAddr6(IP *dst, IP *src)
{
	IP prefix;
	IP mask104;
	IP or1, or2;

	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	ZeroIP6(&prefix);
	prefix.ipv6_addr[0] = 0xff;
	prefix.ipv6_addr[1] = 0x02;
	prefix.ipv6_addr[11] = 0x01;
	prefix.ipv6_addr[12] = 0xff;

	IntToSubnetMask6(&mask104, 104);

	IPAnd6(&or1, &prefix, &mask104);
	IPAnd6(&or2, src, &mask104);

	IPOr6(dst, &or1, &or2);

	dst->ipv6_scope_id = src->ipv6_scope_id;
}

// Generate a MAC address corresponding to the multicast address
void GenerateMulticastMacAddress6(UCHAR *mac, IP *ip)
{
	// Validate arguments
	if (mac == NULL)
	{
		return;
	}

	mac[0] = 0x33;
	mac[1] = 0x33;
	mac[2] = ip->ipv6_addr[12];
	mac[3] = ip->ipv6_addr[13];
	mac[4] = ip->ipv6_addr[14];
	mac[5] = ip->ipv6_addr[15];
}

// Get the type of the IPv6 address
UINT GetIPv6AddrType(IPV6_ADDR *addr)
{
	IP ip;
	// Validate arguments
	if (addr == NULL)
	{
		return 0;
	}

	IPv6AddrToIP(&ip, addr);

	return GetIPAddrType6(&ip);
}
UINT GetIPAddrType6(IP *ip)
{
	UINT ret = 0;
	// Validate arguments
	if (IsIP6(ip) == false)
	{
		return 0;
	}

	if (ip->ipv6_addr[0] == 0xff)
	{
		IP all_node, all_router;

		GetAllNodeMulticaseAddress6(&all_node);

		GetAllRouterMulticastAddress6(&all_router);

		ret |= IPV6_ADDR_MULTICAST;

		if (Cmp(ip->ipv6_addr, all_node.ipv6_addr, 16) == 0)
		{
			ret |= IPV6_ADDR_ALL_NODE_MULTICAST;
		}
		else if (Cmp(ip->ipv6_addr, all_router.ipv6_addr, 16) == 0)
		{
			ret |= IPV6_ADDR_ALL_ROUTER_MULTICAST;
		}
		else
		{
			if (ip->ipv6_addr[1] == 0x02 && ip->ipv6_addr[2] == 0 && ip->ipv6_addr[3] == 0 &&
				ip->ipv6_addr[4] == 0 && ip->ipv6_addr[5] == 0 && ip->ipv6_addr[6] == 0 &&
				ip->ipv6_addr[7] == 0 && ip->ipv6_addr[8] == 0 && ip->ipv6_addr[9] == 0 &&
				ip->ipv6_addr[10] == 0 && ip->ipv6_addr[11] == 0x01 && ip->ipv6_addr[12] == 0xff)
			{
				ret |= IPV6_ADDR_SOLICIATION_MULTICAST;
			}
		}
	}
	else
	{
		ret |= IPV6_ADDR_UNICAST;

		if (ip->ipv6_addr[0] == 0xfe && (ip->ipv6_addr[1] & 0xc0) == 0x80)
		{
			ret |= IPV6_ADDR_LOCAL_UNICAST;
		}
		else
		{
			ret |= IPV6_ADDR_GLOBAL_UNICAST;

			if (IsZero(&ip->ipv6_addr, 16))
			{
				ret |= IPV6_ADDR_ZERO;
			}
			else
			{
				IP loopback;

				GetLoopbackAddress6(&loopback);

				if (Cmp(ip->ipv6_addr, loopback.ipv6_addr, 16) == 0)
				{
					ret |= IPV6_ADDR_LOOPBACK;
				}
			}
		}
	}

	return ret;
}

// Address that all of the bits are set
void GetAllFilledAddress6(IP *ip)
{
	UINT i;
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	ZeroIP6(ip);

	for (i = 0;i < 15;i++)
	{
		ip->ipv6_addr[i] = 0xff;
	}
}

// Loopback address
void GetLoopbackAddress6(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	ZeroIP6(ip);

	ip->ipv6_addr[15] = 0x01;
}

// All-nodes multicast address
void GetAllNodeMulticaseAddress6(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	ZeroIP6(ip);

	ip->ipv6_addr[0] = 0xff;
	ip->ipv6_addr[1] = 0x02;
	ip->ipv6_addr[15] = 0x01;
}

// All-routers multicast address
void GetAllRouterMulticastAddress6(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	ZeroIP6(ip);

	ip->ipv6_addr[0] = 0xff;
	ip->ipv6_addr[1] = 0x02;
	ip->ipv6_addr[15] = 0x02;
}

// Logical operation of the IPv4 address
void IPNot4(IP *dst, IP *a)
{
	UINT i;
	// Validate arguments
	if (dst == NULL || a == NULL || IsIP4(a) == false)
	{
		Zero(dst, sizeof(IP));
		return;
	}

	i = IPToUINT(a);
	i = ~i;

	UINTToIP(dst, i);
}
void IPOr4(IP *dst, IP *a, IP *b)
{
	UINT i;
	// Validate arguments
	if (dst == NULL || a == NULL || b == NULL || IsIP4(a) == false || IsIP4(b) == false)
	{
		Zero(dst, sizeof(IP));
		return;
	}

	i = IPToUINT(a) | IPToUINT(b);

	UINTToIP(dst, i);
}
void IPAnd4(IP *dst, IP *a, IP *b)
{
	UINT i;
	// Validate arguments
	if (dst == NULL || a == NULL || b == NULL || IsIP4(a) == false || IsIP4(b) == false)
	{
		Zero(dst, sizeof(IP));
		return;
	}

	i = IPToUINT(a) & IPToUINT(b);

	UINTToIP(dst, i);
}

// Logical operation of the IPv6 address
void IPAnd6(IP *dst, IP *a, IP *b)
{
	UINT i;
	// Validate arguments
	if (dst == NULL || IsIP6(a) == false || IsIP6(b) == false)
	{
		ZeroIP6(dst);
		return;
	}

	ZeroIP6(dst);
	for (i = 0;i < 16;i++)
	{
		dst->ipv6_addr[i] = a->ipv6_addr[i] & b->ipv6_addr[i];
	}
}
void IPOr6(IP *dst, IP *a, IP *b)
{
	UINT i;
	// Validate arguments
	if (dst == NULL || IsIP6(a) == false || IsIP6(b) == false)
	{
		ZeroIP6(dst);
		return;
	}

	ZeroIP6(dst);
	for (i = 0;i < 16;i++)
	{
		dst->ipv6_addr[i] = a->ipv6_addr[i] | b->ipv6_addr[i];
	}
}
void IPNot6(IP *dst, IP *a)
{
	UINT i;
	// Validate arguments
	if (dst == NULL || IsIP6(a) == false)
	{
		ZeroIP6(dst);
		return;
	}

	ZeroIP6(dst);
	for (i = 0;i < 16;i++)
	{
		dst->ipv6_addr[i] = ~(a->ipv6_addr[i]);
	}
}

// Creating a subnet mask
void IntToSubnetMask6(IP *ip, UINT i)
{
	UINT j = i / 8;
	UINT k = i % 8;
	UINT z;
	IP a;

	ZeroIP6(&a);

	for (z = 0;z < 16;z++)
	{
		if (z < j)
		{
			a.ipv6_addr[z] = 0xff;
		}
		else if (z == j)
		{
			a.ipv6_addr[z] = ~(0xff >> k);
		}
	}

	Copy(ip, &a, sizeof(IP));
}

// Convert the IP address to a string
void IP6AddrToStr(char *str, UINT size, IPV6_ADDR *addr)
{
	// Validate arguments
	if (str == NULL || addr == NULL)
	{
		return;
	}

	IPToStr6Array(str, size, addr->Value);
}
void IPToStr6Array(char *str, UINT size, UCHAR *bytes)
{
	IP ip;
	// Validate arguments
	if (str == NULL || bytes == NULL)
	{
		return;
	}

	SetIP6(&ip, bytes);

	IPToStr6(str, size, &ip);
}
void IPToStr6(char *str, UINT size, IP *ip)
{
	char tmp[MAX_SIZE];

	IPToStr6Inner(tmp, ip);

	StrCpy(str, size, tmp);
}
void IPToStr6Inner(char *str, IP *ip)
{
	UINT i;
	USHORT values[8];
	UINT zero_started_index;
	UINT max_zero_len;
	UINT max_zero_start;
	IP a;
	// Validate arguments
	if (str == NULL || ip == NULL)
	{
		return;
	}

	Copy(&a, ip, sizeof(IP));

	for (i = 0;i < 8;i++)
	{
		Copy(&values[i], &a.ipv6_addr[i * 2], sizeof(USHORT));
		values[i] = Endian16(values[i]);
	}

	// Search for omitable part
	zero_started_index = INFINITE;
	max_zero_len = 0;
	max_zero_start = INFINITE;
	for (i = 0;i < 9;i++)
	{
		USHORT v = (i != 8 ? values[i] : 1);

		if (v == 0)
		{
			if (zero_started_index == INFINITE)
			{
				zero_started_index = i;
			}
		}
		else
		{
			UINT zero_len;

			if (zero_started_index != INFINITE)
			{
				zero_len = i - zero_started_index;
				if (zero_len >= 2)
				{
					if (max_zero_len < zero_len)
					{
						max_zero_start = zero_started_index;
						max_zero_len = zero_len;
					}
				}

				zero_started_index = INFINITE;
			}
		}
	}

	// Format a string
	StrCpy(str, 0, "");
	for (i = 0;i < 8;i++)
	{
		char tmp[16];

		ToHex(tmp, values[i]);
		StrLower(tmp);

		if (i == max_zero_start)
		{
			if (i == 0)
			{
				StrCat(str, 0, "::");
			}
			else
			{
				StrCat(str, 0, ":");
			}
			i += max_zero_len - 1;
		}
		else
		{
			StrCat(str, 0, tmp);
			if (i != 7)
			{
				StrCat(str, 0, ":");
			}
		}
	}

	// Scope ID
	if (ip->ipv6_scope_id != 0)
	{
		char tmp[64];

		StrCat(str, 0, "%");
		ToStr(tmp, ip->ipv6_scope_id);

		StrCat(str, 0, tmp);
	}
}

// Convert the string to an IP address
bool StrToIP6(IP *ip, char *str)
{
	TOKEN_LIST *t;
	char tmp[MAX_PATH];
	IP a;
	UINT i;
	UINT scope_id = 0;
	// Validate arguments
	if (str == NULL || ip == NULL)
	{
		return false;
	}

	ZeroIP6(&a);

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	if (StartWith(tmp, "[") && EndWith(tmp, "]"))
	{
		// If the string is enclosed in square brackets, remove brackets
		StrCpy(tmp, sizeof(tmp), &tmp[1]);

		if (StrLen(tmp) >= 1)
		{
			tmp[StrLen(tmp) - 1] = 0;
		}
	}

	// Remove the scope ID by analyzing if there is it
	i = SearchStrEx(tmp, "%", 0, false);
	if (i != INFINITE)
	{
		char ss[MAX_PATH];

		StrCpy(ss, sizeof(ss), &tmp[i + 1]);

		tmp[i] = 0;

		Trim(tmp);

		Trim(ss);

		scope_id = ToInt(ss);
	}

	// Tokenize
	t = ParseTokenWithNullStr(tmp, ":");
	if (t->NumTokens >= 3 && t->NumTokens <= 8)
	{
		UINT i, n;
		bool b = true;
		UINT k = 0;

		n = 0;

		for (i = 0;i < t->NumTokens;i++)
		{
			char *str = t->Token[i];

			if (i != 0 && i != (t->NumTokens - 1) && StrLen(str) == 0)
			{
				n++;
				if (n == 1)
				{
					k += 2 * (8 - t->NumTokens + 1);
				}
				else
				{
					b = false;
					break;
				}
			}
			else
			{
				UCHAR chars[2];

				if (CheckIPItemStr6(str) == false)
				{
					b = false;
					break;
				}

				IPItemStrToChars6(chars, str);

				a.ipv6_addr[k++] = chars[0];
				a.ipv6_addr[k++] = chars[1];
			}
		}

		if (n != 0 && n != 1)
		{
			b = false;
		}
		else if (n == 0 && t->NumTokens != 8)
		{
			b = false;
		}

		if (b == false)
		{
			FreeToken(t);
			return false;
		}
	}
	else
	{
		FreeToken(t);
		return false;
	}

	FreeToken(t);

	Copy(ip, &a, sizeof(IP));

	ip->ipv6_scope_id = scope_id;

	return true;
}
bool StrToIP6Addr(IPV6_ADDR *ip, char *str)
{
	IP ip2;
	// Validate arguments
	if (ip == NULL || str == NULL)
	{
		Zero(ip, sizeof(IPV6_ADDR));
		return false;
	}

	if (StrToIP6(&ip2, str) == false)
	{
		return false;
	}

	if (IPToIPv6Addr(ip, &ip2) == false)
	{
		return false;
	}

	return true;
}

// Convert an IP address character to the UCHAR type
void IPItemStrToChars6(UCHAR *chars, char *str)
{
	char tmp[5];
	BUF *b;
	UINT len;
	// Validate arguments
	if (chars == NULL)
	{
		return;
	}

	Zero(tmp, sizeof(tmp));

	len = StrLen(str);
	switch (len)
	{
	case 0:
		tmp[0] = tmp[1] = tmp[2] = tmp[3] = '0';
		break;

	case 1:
		tmp[0] = tmp[1] = tmp[2] = '0';
		tmp[3] = str[0];
		break;

	case 2:
		tmp[0] = tmp[1] = '0';
		tmp[2] = str[0];
		tmp[3] = str[1];
		break;

	case 3:
		tmp[0] = '0';
		tmp[1] = str[0];
		tmp[2] = str[1];
		tmp[3] = str[2];
		break;

	case 4:
		tmp[0] = str[0];
		tmp[1] = str[1];
		tmp[2] = str[2];
		tmp[3] = str[3];
		break;
	}

	b = StrToBin(tmp);

	chars[0] = ((UCHAR *)b->Buf)[0];
	chars[1] = ((UCHAR *)b->Buf)[1];

	FreeBuf(b);
}

// Check whether invalid characters are included in the element string of the IP address
bool CheckIPItemStr6(char *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);
	if (len >= 5)
	{
		// Invalid length
		return false;
	}

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= 'a' && c <= 'f') ||
			(c >= 'A' && c <= 'F') ||
			(c >= '0' && c <= '9'))
		{
		}
		else
		{
			return false;
		}
	}

	return true;
}

// Create an IPv4 address of all zero
void ZeroIP4(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));
}

// Create an IPv6 address of all zero
void ZeroIP6(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	SetIP6(ip, NULL);
}

// Get the IP address of the localhost
void GetLocalHostIP6(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}
	ZeroIP6(ip);

	ip->ipv6_addr[15] = 1;
}
void GetLocalHostIP4(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	SetIP(ip, 127, 0, 0, 1);
}

// Check whether the specified address is a localhost
bool IsLocalHostIP6(IP *ip)
{
	IP local;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}
	if (IsIP6(ip) == false)
	{
		return false;
	}

	GetLocalHostIP6(&local);

	if (CmpIpAddr(&local, ip) == 0)
	{
		return true;
	}

	return false;
}
bool IsLocalHostIP4(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}
	if (IsIP4(ip) == false)
	{
		return false;
	}

	if (ip->addr[0] == 127)
	{
		return true;
	}

	return false;
}
bool IsLocalHostIP(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		return IsLocalHostIP4(ip);
	}
	else
	{
		return IsLocalHostIP6(ip);
	}
}

// Convert the IPV6_ADDR to an IP
void IPv6AddrToIP(IP *ip, IPV6_ADDR *addr)
{
	// Validate arguments
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	SetIP6(ip, addr->Value);
}

// Convert the IP to an IPV6_ADDR
bool IPToIPv6Addr(IPV6_ADDR *addr, IP *ip)
{
	UINT i;
	// Validate arguments
	if (addr == NULL || ip == NULL)
	{
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	if (IsIP6(ip) == false)
	{
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	for (i = 0;i < 16;i++)
	{
		addr->Value[i] = ip->ipv6_addr[i];
	}

	return true;
}

// Set an IPv6 address
void SetIP6(IP *ip, UCHAR *value)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->addr[0] = 223;
	ip->addr[1] = 255;
	ip->addr[2] = 255;
	ip->addr[3] = 254;

	if (value != NULL)
	{
		UINT i;

		for (i = 0;i < 16;i++)
		{
			ip->ipv6_addr[i] = value[i];
		}
	}
}

// Check whether the specified address is a IPv6 address
bool IsIP6(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	if (ip->addr[0] == 223 && ip->addr[1] == 255 && ip->addr[2] == 255 && ip->addr[3] == 254)
	{
		return true;
	}

	return false;
}
bool IsIP4(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	return (IsIP6(ip) ? false : true);
}

// Examine whether the version of the two IP addresses are same
bool IsSameIPVer(IP *ip1, IP *ip2)
{
	// Validate arguments
	if (ip1 == NULL || ip2 == NULL)
	{
		return false;
	}

	if (IsIP4(ip1) && IsIP4(ip2))
	{
		return true;
	}

	if (IsIP6(ip1) && IsIP6(ip2))
	{
		return true;
	}

	return false;
}

// Copy the IP address
void CopyIP(IP *dst, IP *src)
{
	Copy(dst, src, sizeof(IP));
}

// Check the length of the IPv6 subnet
bool CheckSubnetLength6(UINT i)
{
	if (i >= 1 && i <= 127)
	{
		return true;
	}

	return false;
}

// Get the process ID of the corresponding TCP connection by the socket
UINT GetTcpProcessIdFromSocket(SOCK *s)
{
	LIST *o;
	TCPTABLE *t;
	UINT pid = 0;
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	o = GetTcpTableList();
	if (o == NULL)
	{
		return 0;
	}

	t = GetTcpTableFromEndPoint(o, &s->LocalIP, s->LocalPort,
		&s->RemoteIP, s->RemotePort);

	if (t != NULL)
	{
		pid = t->ProcessId;
	}

	FreeTcpTableList(o);

	return pid;
}
UINT GetTcpProcessIdFromSocketReverse(SOCK *s)
{
	LIST *o;
	TCPTABLE *t;
	UINT pid = 0;
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	o = GetTcpTableList();
	if (o == NULL)
	{
		return 0;
	}

	t = GetTcpTableFromEndPoint(o, &s->RemoteIP, s->RemotePort,
		&s->LocalIP, s->LocalPort);

	if (t != NULL)
	{
		pid = t->ProcessId;
	}

	FreeTcpTableList(o);

	return pid;
}

// Search in the TCP table by the end point
TCPTABLE *GetTcpTableFromEndPoint(LIST *o, IP *local_ip, UINT local_port, IP *remote_ip, UINT remote_port)
{
	IP local;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	SetIP(&local, 127, 0, 0, 1);

	if (local_ip == NULL)
	{
		local_ip = &local;
	}

	if (remote_ip == NULL)
	{
		remote_ip = &local;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		TCPTABLE *t = LIST_DATA(o, i);

		if (t->Status == TCP_STATE_SYN_SENT || t->Status == TCP_STATE_SYN_RCVD ||
			t->Status == TCP_STATE_ESTAB)
		{
			if (CmpIpAddr(&t->LocalIP, local_ip) == 0)
			{
				if (CmpIpAddr(&t->RemoteIP, remote_ip) == 0)
				{
					if (t->LocalPort == local_port)
					{
						if (t->RemotePort == remote_port)
						{
							return t;
						}
					}
				}
			}
		}
	}

	return NULL;
}

// Get the TCP table list (Win32)
#ifdef	OS_WIN32
LIST *Win32GetTcpTableList()
{
	LIST *o;

	// Windows XP SP2 or later
	o = Win32GetTcpTableListByGetExtendedTcpTable();
	if (o != NULL)
	{
		return o;
	}

	// Windows XP or later
	o = Win32GetTcpTableListByAllocateAndGetTcpExTableFromStack();
	if (o != NULL)
	{
		return o;
	}

	// For legacy Windows
	return Win32GetTcpTableListByGetTcpTable();
}

// Get the TCP table list (for Windows XP SP2 or later)
LIST *Win32GetTcpTableListByGetExtendedTcpTable()
{
	UINT need_size;
	UINT i;
	MIB_TCPTABLE_OWNER_PID *table;
	bool ok = false;
	LIST *o;
	if (w32net->GetExtendedTcpTable == NULL)
	{
		return NULL;
	}

	for (i = 0;i < 128;i++)
	{
		UINT ret;
		table = MallocFast(sizeof(MIB_TCPTABLE_OWNER_PID));
		need_size = sizeof(MIB_TCPTABLE_OWNER_PID);
		ret = w32net->GetExtendedTcpTable(table, &need_size, true, AF_INET, _TCP_TABLE_OWNER_PID_ALL, 0);
		if (ret == NO_ERROR)
		{
			ok = true;
			break;
		}
		else
		{
			Free(table);
			if (ret != ERROR_INSUFFICIENT_BUFFER)
			{
				return NULL;
			}
		}

		table = MallocFast(need_size);

		ret = w32net->GetExtendedTcpTable(table, &need_size, true, AF_INET, _TCP_TABLE_OWNER_PID_ALL, 0);
		if (ret == NO_ERROR)
		{
			ok = true;
			break;
		}
		else
		{
			Free(table);

			if (ret != ERROR_INSUFFICIENT_BUFFER)
			{
				return NULL;
			}
		}
	}

	if (ok == false)
	{
		return NULL;
	}

	o = NewListEx(NULL, true);

	for (i = 0;i < table->dwNumEntries;i++)
	{
		MIB_TCPROW_OWNER_PID *r = &table->table[i];
		TCPTABLE *t = ZeroMallocFast(sizeof(TCPTABLE));

		UINTToIP(&t->LocalIP, r->dwLocalAddr);
		t->LocalPort = Endian16((USHORT)r->dwLocalPort);

		if (r->dwState != TCP_STATE_LISTEN)
		{
			UINTToIP(&t->RemoteIP, r->dwRemoteAddr);
			t->RemotePort = Endian16((USHORT)r->dwRemotePort);
		}

		t->Status = r->dwState;
		t->ProcessId = r->dwOwningPid;

		Add(o, t);
	}

	Free(table);

	return o;
}

// Get the TCP table list (Windows XP or later)
LIST *Win32GetTcpTableListByAllocateAndGetTcpExTableFromStack()
{
	HANDLE heap;
	UINT i;
	MIB_TCPTABLE_OWNER_PID *table;
	bool ok = false;
	LIST *o;
	if (w32net->AllocateAndGetTcpExTableFromStack == NULL)
	{
		return NULL;
	}

	heap = GetProcessHeap();

	if (w32net->AllocateAndGetTcpExTableFromStack(&table, true, heap, HEAP_GROWABLE, AF_INET) != ERROR_SUCCESS)
	{
		return NULL;
	}

	o = NewListEx(NULL, true);

	for (i = 0;i < table->dwNumEntries;i++)
	{
		MIB_TCPROW_OWNER_PID *r = &table->table[i];
		TCPTABLE *t = ZeroMallocFast(sizeof(TCPTABLE));

		UINTToIP(&t->LocalIP, r->dwLocalAddr);
		t->LocalPort = Endian16((USHORT)r->dwLocalPort);

		if (r->dwState != TCP_STATE_LISTEN)
		{
			UINTToIP(&t->RemoteIP, r->dwRemoteAddr);
			t->RemotePort = Endian16((USHORT)r->dwRemotePort);
		}

		t->ProcessId = r->dwOwningPid;
		t->Status = r->dwState;

		Add(o, t);
	}

	HeapFree(heap, 0, table);

	return o;
}

// Get the TCP table list (For legacy Windows)
LIST *Win32GetTcpTableListByGetTcpTable()
{
	UINT need_size;
	UINT i;
	MIB_TCPTABLE *table;
	bool ok = false;
	LIST *o;
	if (w32net->GetTcpTable == NULL)
	{
		return NULL;
	}

	for (i = 0;i < 128;i++)
	{
		UINT ret;
		table = MallocFast(sizeof(MIB_TCPTABLE));
		need_size = sizeof(MIB_TCPTABLE);
		ret = w32net->GetTcpTable(table, &need_size, true);
		if (ret == NO_ERROR)
		{
			ok = true;
			break;
		}
		else
		{
			Free(table);
			if (ret != ERROR_INSUFFICIENT_BUFFER)
			{
				return NULL;
			}
		}

		table = MallocFast(need_size);

		ret = w32net->GetTcpTable(table, &need_size, true);
		if (ret == NO_ERROR)
		{
			ok = true;
			break;
		}
		else
		{
			Free(table);

			if (ret != ERROR_INSUFFICIENT_BUFFER)
			{
				return NULL;
			}
		}
	}

	if (ok == false)
	{
		return NULL;
	}

	o = NewListEx(NULL, true);

	for (i = 0;i < table->dwNumEntries;i++)
	{
		MIB_TCPROW *r = &table->table[i];
		TCPTABLE *t = ZeroMallocFast(sizeof(TCPTABLE));

		UINTToIP(&t->LocalIP, r->dwLocalAddr);
		t->LocalPort = Endian16((USHORT)r->dwLocalPort);

		if (r->dwState != TCP_STATE_LISTEN)
		{
			UINTToIP(&t->RemoteIP, r->dwRemoteAddr);
			t->RemotePort = Endian16((USHORT)r->dwRemotePort);
		}

		t->Status = r->dwState;

		Add(o, t);
	}

	Free(table);

	return o;
}

#endif	// OS_WIN32

// Display the TCP table
void PrintTcpTableList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		Print("o == NULL\n\n");
		return;
	}

	Print("--- TCPTABLE: %u Entries ---\n", LIST_NUM(o));
	for (i = 0;i < LIST_NUM(o);i++)
	{
		char tmp1[MAX_PATH], tmp2[MAX_PATH];
		TCPTABLE *t = LIST_DATA(o, i);

		IPToStr(tmp1, sizeof(tmp1), &t->LocalIP);
		IPToStr(tmp2, sizeof(tmp2), &t->RemoteIP);

		Print("%s:%u <--> %s:%u  state=%u  pid=%u\n",
			tmp1, t->LocalPort,
			tmp2, t->RemotePort,
			t->Status,
			t->ProcessId);
	}
	Print("------\n\n");
}

// Comparison of TCP table items
int CompareTcpTable(void *p1, void *p2)
{
	TCPTABLE *t1, *t2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	t1 = *(TCPTABLE **)p1;
	t2 = *(TCPTABLE **)p2;
	if (t1 == NULL || t2 == NULL)
	{
		return 0;
	}

	return Cmp(t1, t2, sizeof(TCPTABLE));
}

// Get the TCP table list
LIST *GetTcpTableList()
{
#ifdef	OS_WIN32
	return Win32GetTcpTableList();
#else	// OS_WIN32
	return NULL;
#endif	// OS_WIN32
}

// Release the TCP table list
void FreeTcpTableList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		TCPTABLE *t = LIST_DATA(o, i);

		Free(t);
	}

	ReleaseList(o);
}

// Get the number of clients connected from the specified IP address
UINT GetNumIpClient(IP *ip)
{
	IP_CLIENT *c;
	UINT ret = 0;
	// Validate arguments
	if (ip == NULL)
	{
		return 0;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL)
		{
			ret = c->NumConnections;
		}
	}
	UnlockList(ip_clients);

	return ret;
}

// Add to the IP client entry
void AddIpClient(IP *ip)
{
	IP_CLIENT *c;
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c == NULL)
		{
			c = ZeroMallocFast(sizeof(IP_CLIENT));
			Copy(&c->IpAddress, ip, sizeof(IP));
			c->NumConnections = 0;

			Add(ip_clients, c);
		}

		c->NumConnections++;
	}
	UnlockList(ip_clients);

	//Debug("AddIpClient: %r\n", ip);
}

// Remove from the IP client list
void DelIpClient(IP *ip)
{
	IP_CLIENT *c;
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL)
		{
			c->NumConnections--;

			if (c->NumConnections == 0)
			{
				Delete(ip_clients, c);
				Free(c);
			}
		}
	}
	UnlockList(ip_clients);

	//Debug("DelIpClient: %r\n", ip);
}

// Search for the IP client entry
IP_CLIENT *SearchIpClient(IP *ip)
{
	IP_CLIENT t;
	// Validate arguments
	if (ip == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	Copy(&t.IpAddress, ip, sizeof(IP));

	return Search(ip_clients, &t);
}

// Initialization of the client list
void InitIpClientList()
{
	ip_clients = NewList(CompareIpClientList);
}

// Release of the client list
void FreeIpClientList()
{
	UINT i;

	for (i = 0;i < LIST_NUM(ip_clients);i++)
	{
		IP_CLIENT *c = LIST_DATA(ip_clients, i);

		Free(c);
	}

	ReleaseList(ip_clients);
	ip_clients = NULL;
}

// Comparison of the client list entries
int CompareIpClientList(void *p1, void *p2)
{
	IP_CLIENT *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(IP_CLIENT **)p1;
	c2 = *(IP_CLIENT **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return CmpIpAddr(&c1->IpAddress, &c2->IpAddress);
}

// Normalization of the MAC address
bool NormalizeMacAddress(char *dst, UINT size, char *src)
{
	BUF *b;
	bool ret = false;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return false;
	}

	b = StrToBin(src);

	if (b != NULL && b->Size == 6)
	{
		ret = true;

		BinToStr(dst, size, b->Buf, b->Size);
	}

	FreeBuf(b);

	return ret;
}

// Identify whether the IP address is empty
bool IsZeroIP(IP *ip)
{
	return IsZeroIp(ip);
}
bool IsZeroIp(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return true;
	}

	if (IsIP6(ip) == false)
	{
		return IsZero(ip->addr, sizeof(ip->addr));
	}
	else
	{
		return IsZero(ip->ipv6_addr, sizeof(ip->ipv6_addr));
	}
}
bool IsZeroIP6Addr(IPV6_ADDR *addr)
{
	// Validate arguments
	if (addr == NULL)
	{
		return true;
	}

	return IsZero(addr, sizeof(IPV6_ADDR));
}

// Examine whether the specified IP address is meaningful as a host
bool IsHostIPAddress4(IP *ip)
{
	UINT a;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	a = IPToUINT(ip);

	if (a == 0 || a == 0xffffffff)
	{
		return false;
	}

	return true;
}
bool IsHostIPAddress32(UINT ip)
{
	IP p;

	UINTToIP(&p, ip);

	return IsHostIPAddress4(&p);
}

// Check whether the specified IP address and subnet mask indicates a network correctly
bool IsNetworkAddress(IP *ip, IP *mask)
{
	if (IsIP4(ip))
	{
		return IsNetworkAddress4(ip, mask);
	}
	else
	{
		return IsNetworkAddress6(ip, mask);
	}
}
bool IsNetworkAddress4(IP *ip, IP *mask)
{
	UINT a, b;
	// Validate arguments
	if (ip == NULL || mask == NULL)
	{
		return false;
	}

	if (IsIP4(ip) == false || IsIP4(mask) == false)
	{
		return false;
	}

	if (IsSubnetMask4(mask) == false)
	{
		return false;
	}

	a = IPToUINT(ip);
	b = IPToUINT(mask);

	if ((a & b) == a)
	{
		return true;
	}

	return false;
}
bool IsNetworkAddress32(UINT ip, UINT mask)
{
	IP a, b;

	UINTToIP(&a, ip);
	UINTToIP(&b, mask);

	return IsNetworkAddress4(&a, &b);
}

// Convert the integer to a subnet mask
UINT IntToSubnetMask32(UINT i)
{
	UINT ret = 0xFFFFFFFF;

	switch (i)
	{
	case 0:		ret = 0x00000000;	break;
	case 1:		ret = 0x80000000;	break;
	case 2:		ret = 0xC0000000;	break;
	case 3:		ret = 0xE0000000;	break;
	case 4:		ret = 0xF0000000;	break;
	case 5:		ret = 0xF8000000;	break;
	case 6:		ret = 0xFC000000;	break;
	case 7:		ret = 0xFE000000;	break;
	case 8:		ret = 0xFF000000;	break;
	case 9:		ret = 0xFF800000;	break;
	case 10:	ret = 0xFFC00000;	break;
	case 11:	ret = 0xFFE00000;	break;
	case 12:	ret = 0xFFF00000;	break;
	case 13:	ret = 0xFFF80000;	break;
	case 14:	ret = 0xFFFC0000;	break;
	case 15:	ret = 0xFFFE0000;	break;
	case 16:	ret = 0xFFFF0000;	break;
	case 17:	ret = 0xFFFF8000;	break;
	case 18:	ret = 0xFFFFC000;	break;
	case 19:	ret = 0xFFFFE000;	break;
	case 20:	ret = 0xFFFFF000;	break;
	case 21:	ret = 0xFFFFF800;	break;
	case 22:	ret = 0xFFFFFC00;	break;
	case 23:	ret = 0xFFFFFE00;	break;
	case 24:	ret = 0xFFFFFF00;	break;
	case 25:	ret = 0xFFFFFF80;	break;
	case 26:	ret = 0xFFFFFFC0;	break;
	case 27:	ret = 0xFFFFFFE0;	break;
	case 28:	ret = 0xFFFFFFF0;	break;
	case 29:	ret = 0xFFFFFFF8;	break;
	case 30:	ret = 0xFFFFFFFC;	break;
	case 31:	ret = 0xFFFFFFFE;	break;
	case 32:	ret = 0xFFFFFFFF;	break;
	}

	if (IsLittleEndian())
	{
		ret = Swap32(ret);
	}

	return ret;
}
void IntToSubnetMask4(IP *ip, UINT i)
{
	UINT m;
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	m = IntToSubnetMask32(i);

	UINTToIP(ip, m);
}

// Examine whether the specified IP address is a subnet mask
bool IsSubnetMask(IP *ip)
{
	if (IsIP6(ip))
	{
		return IsSubnetMask6(ip);
	}
	else
	{
		return IsSubnetMask4(ip);
	}
}
bool IsSubnetMask4(IP *ip)
{
	UINT i;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	if (IsIP6(ip))
	{
		return false;
	}

	i = IPToUINT(ip);

	if (IsLittleEndian())
	{
		i = Swap32(i);
	}

	switch (i)
	{
	case 0x00000000:
	case 0x80000000:
	case 0xC0000000:
	case 0xE0000000:
	case 0xF0000000:
	case 0xF8000000:
	case 0xFC000000:
	case 0xFE000000:
	case 0xFF000000:
	case 0xFF800000:
	case 0xFFC00000:
	case 0xFFE00000:
	case 0xFFF00000:
	case 0xFFF80000:
	case 0xFFFC0000:
	case 0xFFFE0000:
	case 0xFFFF0000:
	case 0xFFFF8000:
	case 0xFFFFC000:
	case 0xFFFFE000:
	case 0xFFFFF000:
	case 0xFFFFF800:
	case 0xFFFFFC00:
	case 0xFFFFFE00:
	case 0xFFFFFF00:
	case 0xFFFFFF80:
	case 0xFFFFFFC0:
	case 0xFFFFFFE0:
	case 0xFFFFFFF0:
	case 0xFFFFFFF8:
	case 0xFFFFFFFC:
	case 0xFFFFFFFE:
	case 0xFFFFFFFF:
		return true;
	}

	return false;
}
bool IsSubnetMask32(UINT ip)
{
	IP p;

	UINTToIP(&p, ip);

	return IsSubnetMask4(&p);
}

// Network release mode
void SetNetworkReleaseMode()
{
	NetworkReleaseMode = true;
}

#ifdef	OS_UNIX			// Code for UNIX

// Turn on and off the non-blocking mode of the socket
void UnixSetSocketNonBlockingMode(int fd, bool nonblock)
{
	UINT flag = 0;
	// Validate arguments
	if (fd == INVALID_SOCKET)
	{
		return;
	}

	if (nonblock)
	{
		flag = 1;
	}

#ifdef	FIONBIO
	ioctl(fd, FIONBIO, &flag);
#else	// FIONBIO
	{
		int flag = fcntl(fd, F_GETFL, 0);
		if (flag != -1)
		{
			if (nonblock)
			{
				flag |= O_NONBLOCK;
			}
			else
			{
				flag = flag & ~O_NONBLOCK;

				fcntl(fd, F_SETFL, flag);
			}
		}
	}
#endif	// FIONBIO
}

// Do Nothing
void UnixIpForwardRowToRouteEntry(ROUTE_ENTRY *entry, void *ip_forward_row)
{
}

// Do Nothing
void UnixRouteEntryToIpForwardRow(void *ip_forward_row, ROUTE_ENTRY *entry)
{
}

// Do Nothing
int UnixCompareRouteEntryByMetric(void *p1, void *p2)
{
	return 1;
}

// Do Nothing
ROUTE_TABLE *UnixGetRouteTable()
{
	ROUTE_TABLE *ret = ZeroMalloc(sizeof(ROUTE_TABLE));
	ret->NumEntry = 0;
	ret->Entry = ZeroMalloc(0);

	return ret;
}

// Do Nothing
bool UnixAddRouteEntry(ROUTE_ENTRY *e, bool *already_exists)
{
	return true;
}

// Do Nothing
void UnixDeleteRouteEntry(ROUTE_ENTRY *e)
{
	return;
}

// Do Nothing
UINT UnixGetVLanInterfaceID(char *instance_name)
{
	return 1;
}

// Do Nothing
char **UnixEnumVLan(char *tag_name)
{
	char **list;

	list = ZeroMalloc(sizeof(char *));

	return list;
}

// Do Nothing
void UnixRenewDhcp()
{
}

// Get the IP address of the default DNS server
bool UnixGetDefaultDns(IP *ip)
{
	BUF *b;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	Lock(unix_dns_server_addr_lock);
	{
		if (IsZero(&unix_dns_server, sizeof(IP)) == false)
		{
			Copy(ip, &unix_dns_server, sizeof(IP));
			Unlock(unix_dns_server_addr_lock);
			return true;
		}

		ip->addr[0] = 127;
		ip->addr[1] = 0;
		ip->addr[2] = 0;
		ip->addr[3] = 1;

		b = ReadDump("/etc/resolv.conf");
		if (b != NULL)
		{
			char *s;
			bool f = false;
			while ((s = CfgReadNextLine(b)) != NULL)
			{
				TOKEN_LIST *t = ParseToken(s, "\" \t,");
				if (t->NumTokens == 2)
				{
					if (StrCmpi(t->Token[0], "nameserver") == 0)
					{
						StrToIP(ip, t->Token[1]);
						f = true;
					}
				}
				FreeToken(t);

				Free(s);

				if (f)
				{
					break;
				}
			}
			FreeBuf(b);
		}
		Copy(&unix_dns_server, ip, sizeof(IP));
	}
	Unlock(unix_dns_server_addr_lock);

	return true;
}


// Select procedure
void UnixSelect(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2)
{
	UINT reads[MAXIMUM_WAIT_OBJECTS];
	UINT writes[MAXIMUM_WAIT_OBJECTS];
	UINT num_read, num_write, i;
	UINT p1, p2;
	SOCK_EVENT *sock_events[MAXIMUM_WAIT_OBJECTS];
	UINT num_sock_events;
	SOCK *s;
	UCHAR tmp[MAX_SIZE];
	int ret;
	bool any_of_tubes_are_readable = false;
	// Initialization of array
	Zero(reads, sizeof(reads));
	Zero(writes, sizeof(writes));
	Zero(sock_events, sizeof(sock_events));
	num_read = num_write = num_sock_events = 0;

	// Setting the event array
	if (set != NULL)
	{
		for (i = 0;i < set->NumSocket;i++)
		{
			s = set->Sock[i];
			if (s != NULL)
			{
				UnixInitAsyncSocket(s);
				if (s->Type == SOCK_INPROC)
				{
					TUBE *t = s->RecvTube;
					if (t != NULL)
					{
						reads[num_read++] = t->SockEvent->pipe_read;

						sock_events[num_sock_events++] = t->SockEvent;

						if (t->SockEvent->current_pipe_data != 0)
						{
							any_of_tubes_are_readable = true;
						}
					}
				}
				else
				{
					if (s->NoNeedToRead == false)
					{
						reads[num_read++] = s->socket;
					}
				}

				if (s->BulkRecvTube != NULL)
				{
					TUBE *t = s->BulkRecvTube;
					if (t != NULL)
					{
						reads[num_read++] = t->SockEvent->pipe_read;

						sock_events[num_sock_events++] = t->SockEvent;

						if (t->SockEvent->current_pipe_data != 0)
						{
							any_of_tubes_are_readable = true;
						}
					}
				}

				if (s->WriteBlocked)
				{
					writes[num_write++] = s->socket;
				}
			}
		}
	}

	if (timeout == 0)
	{
		return;
	}

	p1 = p2 = -1;

	if (c1 != NULL)
	{
		reads[num_read++] = p1 = c1->pipe_read;

		if (c1->SpecialFlag)
		{
			if (c1->pipe_special_read2 != -1 && c1->pipe_special_read2 != 0)
			{
				reads[num_read++] = c1->pipe_special_read2;
			}

			if (c1->pipe_special_read3 != -1 && c1->pipe_special_read3 != 0)
			{
				reads[num_read++] = c1->pipe_special_read3;
			}
		}
	}
	if (c2 != NULL)
	{
		reads[num_read++] = p2 = c2->pipe_read;

		if (c2->SpecialFlag)
		{
			if (c2->pipe_special_read2 != -1 && c2->pipe_special_read2 != 0)
			{
				reads[num_read++] = c2->pipe_special_read2;
			}

			if (c2->pipe_special_read3 != -1 && c2->pipe_special_read3 != 0)
			{
				reads[num_read++] = c2->pipe_special_read3;
			}
		}
	}

	// Call the select
	if (any_of_tubes_are_readable == false)
	{
		UnixSelectInner(num_read, reads, num_write, writes, timeout);
	}

	// Read from the pipe
	if (c1 != NULL && c1->SpecialFlag == false && p1 != -1)
	{
		do
		{
			ret = read(p1, tmp, sizeof(tmp));
		}
		while (ret >= 1);
	}
	if (c2 != NULL && c2->SpecialFlag == false && p2 != -1)
	{
		do
		{
			ret = read(p2, tmp, sizeof(tmp));
		}
		while (ret >= 1);
	}

	// Read from the pipe of sockevent
	for (i = 0;i < num_sock_events;i++)
	{
		SOCK_EVENT *e = sock_events[i];

		e->current_pipe_data = 0;

		do
		{
			ret = read(e->pipe_read, tmp, sizeof(tmp));
		}
		while (ret >= 1);
	}
}

// Cancel
void UnixCancel(CANCEL *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	UnixWritePipe(c->pipe_write);
}

// Release of the cancel object
void UnixCleanupCancel(CANCEL *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (c->SpecialFlag == false)
	{
		UnixDeletePipe(c->pipe_read, c->pipe_write);
	}

	Free(c);
}

// Creating a new cancel object
CANCEL *UnixNewCancel()
{
	CANCEL *c = ZeroMallocFast(sizeof(CANCEL));

	c->ref = NewRef();
	c->SpecialFlag = false;

	UnixNewPipe(&c->pipe_read, &c->pipe_write);

	c->pipe_special_read2 = c->pipe_special_read3 = -1;

	return c;
}

// Add the socket to the socket event
void UnixJoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event)
{
	// Validate arguments
	if (sock == NULL || event == NULL || sock->AsyncMode)
	{
		return;
	}
	if (sock->ListenMode != false || (sock->Type == SOCK_TCP && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	LockList(event->SockList);
	{
		Add(event->SockList, sock);
		AddRef(sock->ref);
	}
	UnlockList(event->SockList);

	// Make the socket asynchronous mode
	if (sock->Type != SOCK_INPROC)
	{
		UnixSetSocketNonBlockingMode(sock->socket, true);
	}

	// Increase the reference count of the SOCK_EVENT
	AddRef(event->ref);
	sock->SockEvent = event;

	// Set the socket event
	SetSockEvent(event);
}

// Wait for a socket event
bool UnixWaitSockEvent(SOCK_EVENT *event, UINT timeout)
{
	UINT num_read, num_write;
	UINT *reads, *writes;
	UINT n;
	char tmp[MAX_SIZE];
	int readret = 0;
	bool event_pipe_is_readable = false;
	// Validate arguments
	if (event == NULL)
	{
		return false;
	}

	LockList(event->SockList);
	{
		UINT i;
		reads = ZeroMallocFast(sizeof(SOCK *) * (LIST_NUM(event->SockList) + 1));

		num_write = 0;
		num_read = 0;

		for (i = 0;i < LIST_NUM(event->SockList);i++)
		{
			SOCK *s = LIST_DATA(event->SockList, i);

			if (s->NoNeedToRead == false)
			{
				reads[num_read++] = s->socket;
			}

			if (s->WriteBlocked)
			{
				num_write++;
			}
		}

		reads[num_read++] = event->pipe_read;

		if (event->current_pipe_data != 0)
		{
			event_pipe_is_readable = true;
		}

		writes = ZeroMallocFast(sizeof(SOCK *) * num_write);

		n = 0;

		for (i = 0;i < (num_read - 1);i++)
		{
			SOCK *s = LIST_DATA(event->SockList, i);
			if (s->WriteBlocked)
			{
				writes[n++] = s->socket;
			}
		}
	}
	UnlockList(event->SockList);

	if (event_pipe_is_readable == false)
	{
		UnixSelectInner(num_read, reads, num_write, writes, timeout);
	}

	event->current_pipe_data = 0;
	do
	{
		readret = read(event->pipe_read, tmp, sizeof(tmp));
	}
	while (readret >= 1);

	Free(reads);
	Free(writes);

	return true;
}

// Set the socket event
void UnixSetSockEvent(SOCK_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

	if (event->current_pipe_data <= 100)
	{
		UnixWritePipe(event->pipe_write);
		event->current_pipe_data++;
	}
}

// This is a helper function for select()
int safe_fd_set(int fd, fd_set* fds, int* max_fd) {
	FD_SET(fd, fds);
	if (fd > *max_fd) {
		*max_fd = fd;
    }
	return 0;
}

// Execute 'select' for the socket
void UnixSelectInner(UINT num_read, UINT *reads, UINT num_write, UINT *writes, UINT timeout)
{
#ifdef	UNIX_MACOS
	fd_set rfds; //read descriptors
	fd_set wfds; //write descriptors
	int max_fd = 0; //maximum descriptor id
	struct timeval tv; //timeval for timeout
#else	// UNIX_MACOS
	struct pollfd *p;
#endif	// UNIX_MACOS
	UINT num;
	UINT i;
	UINT n;
	UINT num_read_total, num_write_total;

	if (num_read != 0 && reads == NULL)
	{
		num_read = 0;
	}
	if (num_write != 0 && writes == NULL)
	{
		num_write = 0;
	}

	if (timeout == 0)
	{
		return;
	}

	num_read_total = num_write_total = 0;
	for (i = 0;i < num_read;i++)
	{
		if (reads[i] != INVALID_SOCKET)
		{
			num_read_total++;
		}
	}
	for (i = 0;i < num_write;i++)
	{
		if (writes[i] != INVALID_SOCKET)
		{
			num_write_total++;
		}
	}

	num = num_read_total + num_write_total;
#ifdef	UNIX_MACOS
	FD_ZERO(&rfds); //zero out descriptor set for read descriptors
	FD_ZERO(&wfds); //same for write
#else	// UNIX_MACOS
	p = ZeroMallocFast(sizeof(struct pollfd) * num);
#endif	// UNIX_MACOS

	n = 0;

	for (i = 0;i < num_read;i++)
	{
		if (reads[i] != INVALID_SOCKET)
		{
#ifdef	UNIX_MACOS
			safe_fd_set(reads[i], &rfds, &max_fd);
#else	// UNIX_MACOS
			struct pollfd *pfd = &p[n++];
			pfd->fd = reads[i];
			pfd->events = POLLIN | POLLPRI | POLLERR | POLLHUP;
#endif	// UNIX_MACOS
		}
	}

	for (i = 0;i < num_write;i++)
	{
		if (writes[i] != INVALID_SOCKET)
		{
#ifdef	UNIX_MACOS
			safe_fd_set(writes[i], &wfds, &max_fd);
#else	// UNIX_MACOS
			struct pollfd *pfd = &p[n++];
			pfd->fd = writes[i];
			pfd->events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLOUT;
#endif	// UNIX_MACOS
		}
	}

	if (num != 0)
	{
#ifdef	UNIX_MACOS
		if (timeout == INFINITE) {
			tv.tv_sec = 0;
			tv.tv_usec = 0;
		} else {
			tv.tv_sec = timeout / 1000;
			tv.tv_usec = (timeout % 1000) * 1000l;
		}
		select(max_fd + 1, &rfds, &wfds, NULL, &tv);
#else	// UNIX_MACOS
		poll(p, num, timeout == INFINITE ? -1 : (int)timeout);
#endif	// UNIX_MACOS
	}
	else
	{
		SleepThread(timeout);
	}

#ifndef	UNIX_MACOS
	Free(p);
#endif	// not UNIX_MACOS
}

// Clean-up of the socket event
void UnixCleanupSockEvent(SOCK_EVENT *event)
{
	UINT i;
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(event->SockList);i++)
	{
		SOCK *s = LIST_DATA(event->SockList, i);

		ReleaseSock(s);
	}

	ReleaseList(event->SockList);

	UnixDeletePipe(event->pipe_read, event->pipe_write);

	Free(event);
}

// Create a socket event
SOCK_EVENT *UnixNewSockEvent()
{
	SOCK_EVENT *e = ZeroMallocFast(sizeof(SOCK_EVENT));

	e->SockList = NewList(NULL);
	e->ref = NewRef();

	UnixNewPipe(&e->pipe_read, &e->pipe_write);

	return e;
}

// Close the pipe
void UnixDeletePipe(int p1, int p2)
{
	if (p1 != -1)
	{
		close(p1);
	}

	if (p2 != -1)
	{
		close(p2);
	}
}

// Write to the pipe
void UnixWritePipe(int pipe_write)
{
	char c = 1;
	write(pipe_write, &c, 1);
}

// Create a new pipe
void UnixNewPipe(int *pipe_read, int *pipe_write)
{
	int fd[2];
	// Validate arguments
	if (pipe_read == NULL || pipe_write == NULL)
	{
		return;
	}

	fd[0] = fd[1] = 0;

	pipe(fd);

	*pipe_read = fd[0];
	*pipe_write = fd[1];

	UnixSetSocketNonBlockingMode(*pipe_write, true);
	UnixSetSocketNonBlockingMode(*pipe_read, true);
}

// Release the asynchronous socket
void UnixFreeAsyncSocket(SOCK *sock)
{
	UINT p;
	// Validate arguments
	if (sock == NULL)
	{
		return;
	}

	Lock(sock->lock);
	{
		if (sock->AsyncMode == false)
		{
			Unlock(sock->lock);
			return;
		}

		sock->AsyncMode = false;

		// Examine whether this socket are associated to SockEvent
		if (sock->SockEvent != NULL)
		{
			SOCK_EVENT *e = sock->SockEvent;

			AddRef(e->ref);

			p = e->pipe_write;
			LockList(e->SockList);
			{
				if (Delete(e->SockList, sock))
				{
					ReleaseSock(sock);
				}
			}
			UnlockList(e->SockList);

			// Release the socket event
			ReleaseSockEvent(sock->SockEvent);
			sock->SockEvent = NULL;

			SetSockEvent(e);

			ReleaseSockEvent(e);
		}
	}
	Unlock(sock->lock);
}

// Set the socket to asynchronous mode
void UnixInitAsyncSocket(SOCK *sock)
{
	// Validate arguments
	if (sock == NULL)
	{
		return;
	}
	if (sock->AsyncMode)
	{
		// The socket has been set in asynchronous mode already
		return;
	}
	if (sock->ListenMode != false || ((sock->Type == SOCK_TCP || sock->Type == SOCK_INPROC) && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	if (sock->Type != SOCK_INPROC)
	{
		UnixSetSocketNonBlockingMode(sock->socket, true);
	}

	if (sock->ssl != NULL && sock->ssl->s3 != NULL)
	{
		sock->Ssl_Init_Async_SendAlert[0] = sock->ssl->s3->send_alert[0];
		sock->Ssl_Init_Async_SendAlert[1] = sock->ssl->s3->send_alert[1];
	}
}

// Initializing the socket library
void UnixInitSocketLibrary()
{
	// Do not do anything special
}

// Release of the socket library
void UnixFreeSocketLibrary()
{
	// Do not do anything special
}

#endif	// OS_UNIX

#ifdef	OS_WIN32		// Code for Windows

NETWORK_WIN32_FUNCTIONS *w32net;

// Comparison of IP_ADAPTER_INDEX_MAP
int CompareIpAdapterIndexMap(void *p1, void *p2)
{
	IP_ADAPTER_INDEX_MAP *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(IP_ADAPTER_INDEX_MAP **)p1;
	a2 = *(IP_ADAPTER_INDEX_MAP **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}

	if (a1->Index > a2->Index)
	{
		return 1;
	}
	else if (a1->Index < a2->Index)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// Update the IP address of the adapter
bool Win32RenewAddressByGuid(char *guid)
{
	IP_ADAPTER_INDEX_MAP a;
	// Validate arguments
	if (guid == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));
	if (Win32GetAdapterFromGuid(&a, guid) == false)
	{
		return false;
	}

	return Win32RenewAddress(&a);
}
bool Win32RenewAddress(void *a)
{
	DWORD ret;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}
	if (w32net->IpRenewAddress == NULL)
	{
		return false;
	}

	ret = w32net->IpRenewAddress(a);

	if (ret == NO_ERROR)
	{
		return true;
	}
	else
	{
		Debug("IpRenewAddress: Error: %u\n", ret);
		return false;
	}
}

// Release the IP address of the adapter
bool Win32ReleaseAddress(void *a)
{
	DWORD ret;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}
	if (w32net->IpReleaseAddress == NULL)
	{
		return false;
	}

	ret = w32net->IpReleaseAddress(a);

	if (ret == NO_ERROR)
	{
		return true;
	}
	else
	{
		Debug("IpReleaseAddress: Error: %u\n", ret);
		return false;
	}
}
bool Win32ReleaseAddressByGuid(char *guid)
{
	IP_ADAPTER_INDEX_MAP a;
	// Validate arguments
	if (guid == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));
	if (Win32GetAdapterFromGuid(&a, guid) == false)
	{
		return false;
	}

	return Win32ReleaseAddress(&a);
}
void Win32ReleaseAddressByGuidExThread(THREAD *t, void *param)
{
	WIN32_RELEASEADDRESS_THREAD_PARAM *p;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	p = (WIN32_RELEASEADDRESS_THREAD_PARAM *)param;

	AddRef(p->Ref);

	NoticeThreadInit(t);

	AddWaitThread(t);

	if (p->Renew == false)
	{
		p->Ok = Win32ReleaseAddressByGuid(p->Guid);
	}
	else
	{
		p->Ok = Win32RenewAddressByGuid(p->Guid);
	}

	ReleaseWin32ReleaseAddressByGuidThreadParam(p);

	DelWaitThread(t);
}
bool Win32RenewAddressByGuidEx(char *guid, UINT timeout)
{
	return Win32ReleaseOrRenewAddressByGuidEx(guid, timeout, true);
}
bool Win32ReleaseAddressByGuidEx(char *guid, UINT timeout)
{
	return Win32ReleaseOrRenewAddressByGuidEx(guid, timeout, false);
}
bool Win32ReleaseOrRenewAddressByGuidEx(char *guid, UINT timeout, bool renew)
{
	THREAD *t;
	WIN32_RELEASEADDRESS_THREAD_PARAM *p;
	bool ret = false;
	UINT64 start_tick = 0;
	UINT64 end_tick = 0;
	// Validate arguments
	if (guid == NULL)
	{
		return false;
	}
	if (timeout == 0)
	{
		timeout = INFINITE;
	}

	p = ZeroMalloc(sizeof(WIN32_RELEASEADDRESS_THREAD_PARAM));
	p->Ref = NewRef();
	StrCpy(p->Guid, sizeof(p->Guid), guid);
	p->Timeout = timeout;
	p->Renew = renew;

	t = NewThread(Win32ReleaseAddressByGuidExThread, p);
	WaitThreadInit(t);
	start_tick = Tick64();
	end_tick = start_tick + (UINT64)timeout;

	while (true)
	{
		UINT64 now = Tick64();
		UINT64 remain;
		UINT remain32;

		if (now >= end_tick)
		{
			break;
		}

		remain = end_tick - now;
		remain32 = MIN((UINT)remain, 100);

		if (WaitThread(t, remain32))
		{
			break;
		}
	}

	ReleaseThread(t);

	if (p->Ok)
	{
		ret = true;
	}

	ReleaseWin32ReleaseAddressByGuidThreadParam(p);

	return ret;
}
void ReleaseWin32ReleaseAddressByGuidThreadParam(WIN32_RELEASEADDRESS_THREAD_PARAM *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (Release(p->Ref) == 0)
	{
		Free(p);
	}
}

// Get the adapter by the GUID
bool Win32GetAdapterFromGuid(void *a, char *guid)
{
	bool ret = false;
	IP_INTERFACE_INFO *info;
	UINT size;
	int i;
	LIST *o;
	wchar_t tmp[MAX_SIZE];

	// Validate arguments
	if (a == NULL || guid == NULL)
	{
		return false;
	}
	if (w32net->GetInterfaceInfo == NULL)
	{
		return false;
	}

	UniFormat(tmp, sizeof(tmp), L"\\DEVICE\\TCPIP_%S", guid);

	size = sizeof(IP_INTERFACE_INFO);
	info = ZeroMallocFast(size);

	if (w32net->GetInterfaceInfo(info, &size) == ERROR_INSUFFICIENT_BUFFER)
	{
		Free(info);
		info = ZeroMallocFast(size);
	}

	if (w32net->GetInterfaceInfo(info, &size) != NO_ERROR)
	{
		Free(info);
		return false;
	}

	o = NewListFast(CompareIpAdapterIndexMap);

	for (i = 0;i < info->NumAdapters;i++)
	{
		IP_ADAPTER_INDEX_MAP *a = &info->Adapter[i];

		Add(o, a);
	}

	Sort(o);

	for (i = 0;i < (int)(LIST_NUM(o));i++)
	{
		IP_ADAPTER_INDEX_MAP *e = LIST_DATA(o, i);

		if (UniStrCmpi(e->Name, tmp) == 0)
		{
			Copy(a, e, sizeof(IP_ADAPTER_INDEX_MAP));
			ret = true;
			break;
		}
	}

	ReleaseList(o);

	Free(info);

	return ret;
}

// Test
void Win32NetworkTest()
{
	IP_INTERFACE_INFO *info;
	UINT size;
	int i;
	LIST *o;

	size = sizeof(IP_INTERFACE_INFO);
	info = ZeroMallocFast(size);

	if (w32net->GetInterfaceInfo(info, &size) == ERROR_INSUFFICIENT_BUFFER)
	{
		Free(info);
		info = ZeroMallocFast(size);
	}

	if (w32net->GetInterfaceInfo(info, &size) != NO_ERROR)
	{
		Free(info);
		return;
	}

	o = NewListFast(CompareIpAdapterIndexMap);

	for (i = 0;i < info->NumAdapters;i++)
	{
		IP_ADAPTER_INDEX_MAP *a = &info->Adapter[i];

		Add(o, a);
	}

	Sort(o);

	for (i = 0;i < (int)(LIST_NUM(o));i++)
	{
		IP_ADAPTER_INDEX_MAP *a = LIST_DATA(o, i);

		DoNothing();
	}

	ReleaseList(o);

	Free(info);
}

// Clear the DNS cache on Win32
void Win32FlushDnsCache()
{
	Run("ipconfig.exe", "/flushdns", true, false);
}

// Update the DHCP address of the specified LAN card
void Win32RenewDhcp9x(UINT if_id)
{
	IP_INTERFACE_INFO *info;
	UINT size;
	int i;
	LIST *o;
	// Validate arguments
	if (if_id == 0)
	{
		return;
	}

	size = sizeof(IP_INTERFACE_INFO);
	info = ZeroMallocFast(size);

	if (w32net->GetInterfaceInfo(info, &size) == ERROR_INSUFFICIENT_BUFFER)
	{
		Free(info);
		info = ZeroMallocFast(size);
	}

	if (w32net->GetInterfaceInfo(info, &size) != NO_ERROR)
	{
		Free(info);
		return;
	}

	o = NewListFast(CompareIpAdapterIndexMap);

	for (i = 0;i < info->NumAdapters;i++)
	{
		IP_ADAPTER_INDEX_MAP *a = &info->Adapter[i];

		Add(o, a);
	}

	Sort(o);

	for (i = 0;i < (int)(LIST_NUM(o));i++)
	{
		IP_ADAPTER_INDEX_MAP *a = LIST_DATA(o, i);

		if (a->Index == if_id)
		{
			char arg[MAX_PATH];
			Format(arg, sizeof(arg), "/renew %u", i);
			Run("ipconfig.exe", arg, true, false);
		}
	}

	ReleaseList(o);

	Free(info);
}

// Release the DHCP address of the specified LAN card
void Win32ReleaseDhcp9x(UINT if_id, bool wait)
{
	IP_INTERFACE_INFO *info;
	UINT size;
	int i;
	LIST *o;
	// Validate arguments
	if (if_id == 0)
	{
		return;
	}

	size = sizeof(IP_INTERFACE_INFO);
	info = ZeroMallocFast(size);

	if (w32net->GetInterfaceInfo(info, &size) == ERROR_INSUFFICIENT_BUFFER)
	{
		Free(info);
		info = ZeroMallocFast(size);
	}

	if (w32net->GetInterfaceInfo(info, &size) != NO_ERROR)
	{
		Free(info);
		return;
	}

	o = NewListFast(CompareIpAdapterIndexMap);

	for (i = 0;i < info->NumAdapters;i++)
	{
		IP_ADAPTER_INDEX_MAP *a = &info->Adapter[i];

		Add(o, a);
	}

	Sort(o);

	for (i = 0;i < (int)(LIST_NUM(o));i++)
	{
		IP_ADAPTER_INDEX_MAP *a = LIST_DATA(o, i);

		if (a->Index == if_id)
		{
			char arg[MAX_PATH];
			Format(arg, sizeof(arg), "/release %u", i);
			Run("ipconfig.exe", arg, true, wait);
		}
	}

	ReleaseList(o);

	Free(info);
}

// Re-obtain an IP address from a DHCP server
void Win32RenewDhcp()
{
	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType))
	{
		Run("ipconfig.exe", "/renew", true, false);
		if (MsIsVista())
		{
			Run("ipconfig.exe", "/renew6", true, false);
		}
		else
		{
			Run("netsh.exe", "int ipv6 renew", true, false);
		}
	}
	else
	{
		Run("ipconfig.exe", "/renew_all", true, false);
	}
}

// Enumerate a list of virtual LAN cards that contains the specified string
char **Win32EnumVLan(char *tag_name)
{
	MIB_IFTABLE *p;
	UINT ret;
	UINT size_needed;
	UINT num_retry = 0;
	UINT i;
	LIST *o;
	char **ss;
	// Validate arguments
	if (tag_name == 0)
	{
		return NULL;
	}

RETRY:
	p = ZeroMallocFast(sizeof(MIB_IFTABLE));
	size_needed = 0;

	// Examine the needed size
	ret = w32net->GetIfTable(p, &size_needed, 0);
	if (ret == ERROR_INSUFFICIENT_BUFFER)
	{
		// Re-allocate the memory block of the needed size
		Free(p);
		p = ZeroMallocFast(size_needed);
	}
	else if (ret != NO_ERROR)
	{
		// Acquisition failure
FAILED:
		Free(p);
		return NULL;
	}

	// Actually get
	ret = w32net->GetIfTable(p, &size_needed, FALSE);
	if (ret != NO_ERROR)
	{
		// Acquisition failure
		if ((++num_retry) >= 5)
		{
			goto FAILED;
		}
		Free(p);
		goto RETRY;
	}

	// Search
	ret = 0;
	o = NewListFast(CompareStr);
	for (i = 0;i < p->dwNumEntries;i++)
	{
		MIB_IFROW *r = &p->table[i];
		if (SearchStrEx(r->bDescr, tag_name, 0, false) != INFINITE)
		{
			char *s = CopyStr(r->bDescr);
			Add(o, s);
		}
	}

	Free(p);

	// Sort
	Sort(o);

	// Convert to string
	ss = ZeroMallocFast(sizeof(char *) * (LIST_NUM(o) + 1));
	for (i = 0;i < LIST_NUM(o);i++)
	{
		ss[i] = LIST_DATA(o, i);
	}
	ss[LIST_NUM(o)] = NULL;

	ReleaseList(o);

	return ss;
}

// Get the ID of the virtual LAN card from the instance name of the virtual LAN card
UINT Win32GetVLanInterfaceID(char *instance_name)
{
	MIB_IFTABLE *p;
	UINT ret;
	UINT size_needed;
	UINT num_retry = 0;
	UINT i;
	char ps_miniport_str[MAX_SIZE];
	char ps_miniport_str2[MAX_SIZE];
	UINT min_len = 0x7FFFFFFF;
	// Validate arguments
	if (instance_name == 0)
	{
		return 0;
	}

RETRY:
	p = ZeroMallocFast(sizeof(MIB_IFTABLE));
	size_needed = 0;

	// Examine the needed size
	ret = w32net->GetIfTable(p, &size_needed, 0);
	if (ret == ERROR_INSUFFICIENT_BUFFER)
	{
		// Re-allocate the memory block of the needed size
		Free(p);
		p = ZeroMallocFast(size_needed);
	}
	else if (ret != NO_ERROR)
	{
		// Acquisition failure
FAILED:
		Free(p);
		Debug("******** GetIfTable Failed 1. Err = %u\n", ret);
		return 0;
	}

	// Actually get
	ret = w32net->GetIfTable(p, &size_needed, FALSE);
	if (ret != NO_ERROR)
	{
		// Acquisition failure
		if ((++num_retry) >= 5)
		{
			goto FAILED;
		}
		Free(p);
		Debug("******** GetIfTable Failed 2. Err = %u\n", ret);
		goto RETRY;
	}

	// "%s - Packet scheduler miniport"
	Format(ps_miniport_str, sizeof(ps_miniport_str), "%s - ", instance_name);
	Format(ps_miniport_str2, sizeof(ps_miniport_str2), "%s (Microsoft", instance_name);

	// Search
	ret = 0;
	for (i = 0;i < p->dwNumEntries;i++)
	{
		MIB_IFROW *r = &p->table[i];
		if (instance_name[0] != '@')
		{
			if (StrCmpi(r->bDescr, instance_name) == 0 || StartWith(r->bDescr, ps_miniport_str) || StartWith(r->bDescr, ps_miniport_str2))
			{
				UINT len = StrLen(r->bDescr);

				if (len < min_len)
				{
					ret = r->dwIndex;

					min_len = len;
				}
			}
		}
		else
		{
			if (SearchStrEx(r->bDescr, &instance_name[1], 0, false) != INFINITE)
			{
				ret = r->dwIndex;
			}
		}

		//Debug("if[%u] (dwIndex=%u): %u, %s\n", i, r->dwIndex, r->dwType, r->bDescr);
	}

	Free(p);

	return ret;
}

// Get the DNS suffix in another way
bool Win32GetDnsSuffix(char *domain, UINT size)
{
	IP_ADAPTER_ADDRESSES_XP *info;
	IP_ADAPTER_ADDRESSES_XP *cur;
	UINT info_size;
	bool ret = false;
	// Validate arguments
	ClearStr(domain, size);
	if (domain == NULL)
	{
		return false;
	}
	if (w32net->GetAdaptersAddresses == NULL)
	{
		return false;
	}

	info_size = 0;
	info = ZeroMalloc(sizeof(IP_ADAPTER_ADDRESSES_XP));
	if (w32net->GetAdaptersAddresses(AF_INET, 0, NULL, info, &info_size) == ERROR_BUFFER_OVERFLOW)
	{
		Free(info);
		info = ZeroMalloc(info_size);
	}
	if (w32net->GetAdaptersAddresses(AF_INET, 0, NULL, info, &info_size) != NO_ERROR)
	{
		Free(info);
		return false;
	}

	cur = info;

	while (cur != NULL)
	{
		if (UniIsEmptyStr(cur->DnsSuffix) == false)
		{
			UniToStr(domain, size, cur->DnsSuffix);
			ret = true;
			break;
		}

		cur = cur->Next;
	}

	Free(info);

	return ret;
}

// Get the DNS server address of the default
bool Win32GetDefaultDns(IP *ip, char *domain, UINT size)
{
	FIXED_INFO *info;
	UINT info_size;
	char *dns_name;
	// Validate arguments
	ClearStr(domain, size);
	if (ip == NULL)
	{
		return false;
	}
	Zero(ip, sizeof(IP));
	if (w32net->GetNetworkParams == NULL)
	{
		return false;
	}
	info_size = 0;
	info = ZeroMallocFast(sizeof(FIXED_INFO));
	if (w32net->GetNetworkParams(info, &info_size) == ERROR_BUFFER_OVERFLOW)
	{
		Free(info);
		info = ZeroMallocFast(info_size);
	}
	if (w32net->GetNetworkParams(info, &info_size) != NO_ERROR)
	{
		Free(info);
		return false;
	}

	if (info->DnsServerList.IpAddress.String == NULL)
	{
		Free(info);
		return false;
	}

	dns_name = info->DnsServerList.IpAddress.String;
	StrToIP(ip, dns_name);

	if (domain != NULL)
	{
		StrCpy(domain, size, info->DomainName);
		Trim(domain);
	}

	Free(info);

	return true;
}

// IP conversion function for Win32
void Win32UINTToIP(IP *ip, UINT i)
{
	UINTToIP(ip, i);
}

// IP conversion function for Win32
UINT Win32IPToUINT(IP *ip)
{
	return IPToUINT(ip);
}

// Remove a routing entry from the routing table
void Win32DeleteRouteEntry(ROUTE_ENTRY *e)
{
	MIB_IPFORWARDROW *p;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	p = ZeroMallocFast(sizeof(MIB_IPFORWARDROW));
	Win32RouteEntryToIpForwardRow(p, e);

	// Delete
	w32net->DeleteIpForwardEntry(p);

	Free(p);
}

// Add a routing entry to the routing table
bool Win32AddRouteEntry(ROUTE_ENTRY *e, bool *already_exists)
{
	bool ret = false;
	bool dummy = false;
	MIB_IPFORWARDROW *p;
	UINT err = 0;
	// Validate arguments
	if (e == NULL)
	{
		return false;
	}
	if (already_exists == NULL)
	{
		already_exists = &dummy;
	}

	*already_exists = false;

	p = ZeroMallocFast(sizeof(MIB_IPFORWARDROW));
	Win32RouteEntryToIpForwardRow(p, e);

	// Adding
	err = w32net->CreateIpForwardEntry(p);
	if (err != 0)
	{
		if (err == ERROR_OBJECT_ALREADY_EXISTS)
		{
			Debug("CreateIpForwardEntry: Already Exists\n");
			*already_exists = true;
			ret = true;
		}
		else
		{
			Debug("CreateIpForwardEntry Error: %u\n", err);
			ret = false;
		}
	}
	else
	{
		ret = true;
	}

	Free(p);

	return ret;
}

// Get the routing table
ROUTE_TABLE *Win32GetRouteTable()
{
	ROUTE_TABLE *t = ZeroMallocFast(sizeof(ROUTE_TABLE));
	MIB_IPFORWARDTABLE *p;
	UINT ret;
	UINT size_needed;
	UINT num_retry = 0;
	LIST *o;
	UINT i;
	ROUTE_ENTRY *e;

RETRY:
	p = ZeroMallocFast(sizeof(MIB_IFTABLE));
	size_needed = 0;

	// Examine the needed size
	ret = w32net->GetIpForwardTable(p, &size_needed, 0);
	if (ret == ERROR_INSUFFICIENT_BUFFER)
	{
		// Re-allocate the memory block of the needed size
		Free(p);
		p = ZeroMallocFast(size_needed);
	}
	else if (ret != NO_ERROR)
	{
		// Acquisition failure
FAILED:
		Free(p);
		t->Entry = MallocFast(0);
		return t;
	}

	// Actually get
	ret = w32net->GetIpForwardTable(p, &size_needed, FALSE);
	if (ret != NO_ERROR)
	{
		// Acquisition failure
		if ((++num_retry) >= 5)
		{
			goto FAILED;
		}
		Free(p);
		goto RETRY;
	}

	// Add to the list along
	o = NewListFast(Win32CompareRouteEntryByMetric);
	for (i = 0;i < p->dwNumEntries;i++)
	{
		e = ZeroMallocFast(sizeof(ROUTE_ENTRY));
		Win32IpForwardRowToRouteEntry(e, &p->table[i]);
		Add(o, e);
	}
	Free(p);

	// Sort by metric
	Sort(o);

	// Combine the results
	t->NumEntry = LIST_NUM(o);
	t->Entry = ToArrayEx(o, true);
	ReleaseList(o);

	return t;
}

// Sort the routing entries by metric
int Win32CompareRouteEntryByMetric(void *p1, void *p2)
{
	ROUTE_ENTRY *e1, *e2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	e1 = *(ROUTE_ENTRY **)p1;
	e2 = *(ROUTE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}

	if (e1->Metric > e2->Metric)
	{
		return 1;
	}
	else if (e1->Metric == e2->Metric)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

// Convert the ROUTE_ENTRY to a MIB_IPFORWARDROW
void Win32RouteEntryToIpForwardRow(void *ip_forward_row, ROUTE_ENTRY *entry)
{
	MIB_IPFORWARDROW *r;
	// Validate arguments
	if (entry == NULL || ip_forward_row == NULL)
	{
		return;
	}

	r = (MIB_IPFORWARDROW *)ip_forward_row;
	Zero(r, sizeof(MIB_IPFORWARDROW));

	// IP address
	r->dwForwardDest = Win32IPToUINT(&entry->DestIP);
	// Subnet mask
	r->dwForwardMask = Win32IPToUINT(&entry->DestMask);
	// Gateway IP address
	r->dwForwardNextHop = Win32IPToUINT(&entry->GatewayIP);
	// Local routing flag
	if (entry->LocalRouting)
	{
		// Local
		r->dwForwardType = 3;
	}
	else
	{
		// Remote router
		r->dwForwardType = 4;
	}
	// Protocol
	r->dwForwardProto = r->dwForwardType - 1;	// Subtract by 1 in most cases
	if (entry->PPPConnection)
	{
		// Isn't this a PPP? Danger!
		r->dwForwardProto++;
	}
	// Metric
	r->dwForwardMetric1 = entry->Metric;

	if (MsIsVista() == false)
	{
		r->dwForwardMetric2 = r->dwForwardMetric3 = r->dwForwardMetric4 = r->dwForwardMetric5 = INFINITE;
	}
	else
	{
		r->dwForwardMetric2 = r->dwForwardMetric3 = r->dwForwardMetric4 = r->dwForwardMetric5 = 0;
		r->dwForwardAge = 163240;
	}

	// Interface ID
	r->dwForwardIfIndex = entry->InterfaceID;

	Debug("Win32RouteEntryToIpForwardRow()\n");
	Debug(" r->dwForwardDest=%X\n", r->dwForwardDest);
	Debug(" r->dwForwardMask=%X\n", r->dwForwardMask);
	Debug(" r->dwForwardNextHop=%X\n", r->dwForwardNextHop);
	Debug(" r->dwForwardType=%u\n", r->dwForwardType);
	Debug(" r->dwForwardProto=%u\n", r->dwForwardProto);
	Debug(" r->dwForwardMetric1=%u\n", r->dwForwardMetric1);
	Debug(" r->dwForwardMetric2=%u\n", r->dwForwardMetric2);
	Debug(" r->dwForwardIfIndex=%u\n", r->dwForwardIfIndex);
}

// Convert the MIB_IPFORWARDROW to a ROUTE_ENTRY
void Win32IpForwardRowToRouteEntry(ROUTE_ENTRY *entry, void *ip_forward_row)
{
	MIB_IPFORWARDROW *r;
	// Validate arguments
	if (entry == NULL || ip_forward_row == NULL)
	{
		return;
	}

	r = (MIB_IPFORWARDROW *)ip_forward_row;

	Zero(entry, sizeof(ROUTE_ENTRY));
	// IP address
	Win32UINTToIP(&entry->DestIP, r->dwForwardDest);
	// Subnet mask
	Win32UINTToIP(&entry->DestMask, r->dwForwardMask);
	// Gateway IP address
	Win32UINTToIP(&entry->GatewayIP, r->dwForwardNextHop);
	// Local routing flag
	if (r->dwForwardType == 3)
	{
		entry->LocalRouting = true;
	}
	else
	{
		entry->LocalRouting = false;
	}
	if (entry->LocalRouting && r->dwForwardProto == 3)
	{
		// PPP. Danger!
		entry->PPPConnection = true;
	}
	// Metric
	entry->Metric = r->dwForwardMetric1;
	// Interface ID
	entry->InterfaceID = r->dwForwardIfIndex;
}

// Initializing the socket library
void Win32InitSocketLibrary()
{
	WSADATA data;
	Zero(&data, sizeof(data));
	WSAStartup(MAKEWORD(2, 2), &data);

	// Load the DLL functions
	w32net = ZeroMalloc(sizeof(NETWORK_WIN32_FUNCTIONS));
	w32net->hIpHlpApi32 = LoadLibrary("iphlpapi.dll");
	w32net->hIcmp = LoadLibrary("icmp.dll");

	if (w32net->hIpHlpApi32 != NULL)
	{
		w32net->CreateIpForwardEntry =
			(DWORD (__stdcall *)(PMIB_IPFORWARDROW))
			GetProcAddress(w32net->hIpHlpApi32, "CreateIpForwardEntry");

		w32net->DeleteIpForwardEntry =
			(DWORD (__stdcall *)(PMIB_IPFORWARDROW))
			GetProcAddress(w32net->hIpHlpApi32, "DeleteIpForwardEntry");

		w32net->GetIfTable =
			(DWORD (__stdcall *)(PMIB_IFTABLE, PULONG, BOOL))
			GetProcAddress(w32net->hIpHlpApi32, "GetIfTable");

		w32net->GetIfTable2 =
			(DWORD (__stdcall *)(void **))
			GetProcAddress(w32net->hIpHlpApi32, "GetIfTable2");

		w32net->FreeMibTable =
			(void (__stdcall *)(PVOID))
			GetProcAddress(w32net->hIpHlpApi32, "FreeMibTable");

		w32net->GetIpForwardTable =
			(DWORD (__stdcall *)(PMIB_IPFORWARDTABLE, PULONG, BOOL))
			GetProcAddress(w32net->hIpHlpApi32, "GetIpForwardTable");

		w32net->GetNetworkParams =
			(DWORD (__stdcall *)(PFIXED_INFO,PULONG))
			GetProcAddress(w32net->hIpHlpApi32, "GetNetworkParams");

		w32net->GetAdaptersAddresses =
			(ULONG (__stdcall *)(ULONG,ULONG,PVOID,PIP_ADAPTER_ADDRESSES,PULONG))
			GetProcAddress(w32net->hIpHlpApi32, "GetAdaptersAddresses");

		w32net->IpRenewAddress =
			(DWORD (__stdcall *)(PIP_ADAPTER_INDEX_MAP))
			GetProcAddress(w32net->hIpHlpApi32, "IpRenewAddress");

		w32net->IpReleaseAddress =
			(DWORD (__stdcall *)(PIP_ADAPTER_INDEX_MAP))
			GetProcAddress(w32net->hIpHlpApi32, "IpReleaseAddress");

		w32net->GetInterfaceInfo =
			(DWORD (__stdcall *)(PIP_INTERFACE_INFO, PULONG))
			GetProcAddress(w32net->hIpHlpApi32, "GetInterfaceInfo");

		w32net->GetAdaptersInfo =
			(DWORD (__stdcall *)(PIP_ADAPTER_INFO, PULONG))
			GetProcAddress(w32net->hIpHlpApi32, "GetAdaptersInfo");

		w32net->GetExtendedTcpTable =
			(DWORD (__stdcall *)(PVOID,PDWORD,BOOL,ULONG,_TCP_TABLE_CLASS,ULONG))
			GetProcAddress(w32net->hIpHlpApi32, "GetExtendedTcpTable");

		w32net->AllocateAndGetTcpExTableFromStack =
			(DWORD (__stdcall *)(PVOID *,BOOL,HANDLE,DWORD,DWORD))
			GetProcAddress(w32net->hIpHlpApi32, "AllocateAndGetTcpExTableFromStack");

		w32net->GetTcpTable =
			(DWORD (__stdcall *)(PMIB_TCPTABLE,PDWORD,BOOL))
			GetProcAddress(w32net->hIpHlpApi32, "GetTcpTable");

		w32net->NotifyRouteChange =
			(DWORD (__stdcall *)(PHANDLE,LPOVERLAPPED))
			GetProcAddress(w32net->hIpHlpApi32, "NotifyRouteChange");

		w32net->CancelIPChangeNotify =
			(BOOL (__stdcall *)(LPOVERLAPPED))
			GetProcAddress(w32net->hIpHlpApi32, "CancelIPChangeNotify");

		w32net->NhpAllocateAndGetInterfaceInfoFromStack =
			(DWORD (__stdcall *)(IP_INTERFACE_NAME_INFO **,PDWORD,BOOL,HANDLE,DWORD))
			GetProcAddress(w32net->hIpHlpApi32, "NhpAllocateAndGetInterfaceInfoFromStack");

		w32net->IcmpCreateFile =
			(HANDLE (__stdcall *)())
			GetProcAddress(w32net->hIpHlpApi32, "IcmpCreateFile");

		w32net->IcmpCloseHandle =
			(BOOL (__stdcall *)(HANDLE))
			GetProcAddress(w32net->hIpHlpApi32, "IcmpCloseHandle");

		w32net->IcmpSendEcho =
			(DWORD (__stdcall *)(HANDLE,IPAddr,LPVOID,WORD,PIP_OPTION_INFORMATION,LPVOID,DWORD,DWORD))
			GetProcAddress(w32net->hIpHlpApi32, "IcmpSendEcho");
	}

	if (w32net->hIcmp != NULL)
	{
		if (w32net->IcmpCreateFile == NULL || w32net->IcmpCloseHandle == NULL || w32net->IcmpSendEcho == NULL)
		{
			w32net->IcmpCreateFile =
				(HANDLE (__stdcall *)())
				GetProcAddress(w32net->hIcmp, "IcmpCreateFile");

			w32net->IcmpCloseHandle =
				(BOOL (__stdcall *)(HANDLE))
				GetProcAddress(w32net->hIcmp, "IcmpCloseHandle");

			w32net->IcmpSendEcho =
				(DWORD (__stdcall *)(HANDLE,IPAddr,LPVOID,WORD,PIP_OPTION_INFORMATION,LPVOID,DWORD,DWORD))
				GetProcAddress(w32net->hIcmp, "IcmpSendEcho");
		}
	}

	if (w32net->IcmpCreateFile == NULL || w32net->IcmpCloseHandle == NULL || w32net->IcmpSendEcho == NULL)
	{
		w32net->IcmpCreateFile = NULL;
		w32net->IcmpCloseHandle = NULL;
		w32net->IcmpSendEcho = NULL;
	}
}

// Release of the socket library
void Win32FreeSocketLibrary()
{
	if (w32net != NULL)
	{
		if (w32net->hIpHlpApi32 != NULL)
		{
			FreeLibrary(w32net->hIpHlpApi32);
		}

		if (w32net->hIcmp != NULL)
		{
			FreeLibrary(w32net->hIcmp);
		}

		Free(w32net);
		w32net = NULL;
	}

	WSACleanup();
}

// Cancel
void Win32Cancel(CANCEL *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	SetEvent((HANDLE)c->hEvent);
}

// Cleanup of the cancel object
void Win32CleanupCancel(CANCEL *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (c->SpecialFlag == false)
	{
		CloseHandle(c->hEvent);
	}

	Free(c);
}

// New cancel object
CANCEL *Win32NewCancel()
{
	CANCEL *c = ZeroMallocFast(sizeof(CANCEL));
	c->ref = NewRef();
	c->SpecialFlag = false;
	c->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	return c;
}

// Waiting for a socket event
bool Win32WaitSockEvent(SOCK_EVENT *event, UINT timeout)
{
	// Validate arguments
	if (event == NULL || timeout == 0)
	{
		return false;
	}

	if (WaitForSingleObject((HANDLE)event->hEvent, timeout) == WAIT_OBJECT_0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Clean-up of the socket event
void Win32CleanupSockEvent(SOCK_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

	CloseHandle((HANDLE)event->hEvent);

	Free(event);
}

// Set of the socket event
void Win32SetSockEvent(SOCK_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

	SetEvent((HANDLE)event->hEvent);
}

// Creating a socket event
SOCK_EVENT *Win32NewSockEvent()
{
	SOCK_EVENT *e = ZeroMallocFast(sizeof(SOCK_EVENT));

	e->ref = NewRef();
	e->hEvent = (void *)CreateEvent(NULL, FALSE, FALSE, NULL);

	return e;
}

// Associate the socket with socket event and set it to asynchronous mode
void Win32JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event)
{
	HANDLE hEvent;
	// Validate arguments
	if (sock == NULL || event == NULL || sock->AsyncMode)
	{
		return;
	}
	if (sock->ListenMode != false || (sock->Type != SOCK_UDP && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	hEvent = event->hEvent;

	// Association
	WSAEventSelect(sock->socket, hEvent, FD_READ | FD_WRITE | FD_CLOSE);

	// Increase the reference count of the SOCK_EVENT
	AddRef(event->ref);
	sock->SockEvent = event;
}

// Set the socket to asynchronous mode
void Win32InitAsyncSocket(SOCK *sock)
{
	// Validate arguments
	if (sock == NULL)
	{
		return;
	}
	if (sock->AsyncMode)
	{
		// This socket is already in asynchronous mode
		return;
	}
	if (sock->ListenMode || ((sock->Type == SOCK_TCP || sock->Type == SOCK_INPROC) && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	if (sock->Type == SOCK_INPROC)
	{
		// Fetch the event of the TUBE
		TUBE *t = sock->RecvTube;

		if (t != NULL)
		{
			if (t->SockEvent != NULL)
			{
				sock->hEvent = t->SockEvent->hEvent;
			}
		}
	}
	else
	{
		// Creating an Event
		sock->hEvent = (void *)CreateEvent(NULL, FALSE, FALSE, NULL);

		// Association
		WSAEventSelect(sock->socket, sock->hEvent, FD_READ | FD_WRITE | FD_CLOSE);
	}
}

// Release the asynchronous socket
void Win32FreeAsyncSocket(SOCK *sock)
{
	// Validate arguments
	if (sock == NULL)
	{
		return;
	}

	// Asynchronous socket
	if (sock->hEvent != NULL)
	{
		if (sock->Type != SOCK_INPROC)
		{
			CloseHandle((HANDLE)sock->hEvent);
		}
	}
	sock->hEvent = NULL;
	sock->AsyncMode = false;

	// Socket event
	if (sock->SockEvent != NULL)
	{
		ReleaseSockEvent(sock->SockEvent);
		sock->SockEvent = NULL;
	}
}

// Select function for Win32
void Win32Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2)
{
	HANDLE array[MAXIMUM_WAIT_OBJECTS];
	UINT n, i;
	SOCK *s;
	// Initialization of array
	Zero(array, sizeof(array));
	n = 0;

	// Setting the event array
	if (set != NULL)
	{
		for (i = 0;i < set->NumSocket;i++)
		{
			s = set->Sock[i];
			if (s != NULL)
			{
				Win32InitAsyncSocket(s);
				if (s->hEvent != NULL)
				{
					array[n++] = (HANDLE)s->hEvent;
				}

				if (s->BulkRecvTube != NULL)
				{
					array[n++] = (HANDLE)s->BulkRecvTube->SockEvent->hEvent;
				}
			}
		}
	}
	if (c1 != NULL && c1->hEvent != NULL)
	{
		array[n++] = c1->hEvent;
	}
	if (c2 != NULL && c2->hEvent != NULL)
	{
		array[n++] = c2->hEvent;
	}

	if (timeout == 0)
	{
		return;
	}

	if (n == 0)
	{
		// Call normal waiting function if no events to wait are registered
		SleepThread(timeout);
	}
	else
	{
		// Wait for the event if events are registered at least one
		if (n == 1)
		{
			// Calling a lightweight version If the event is only one
			WaitForSingleObject(array[0], timeout);
		}
		else
		{
			// In case of multiple events
			WaitForMultipleObjects(n, array, false, timeout);
		}
	}
}

#endif	// OS_WIN32

// Check whether the IPv6 is supported
bool IsIPv6Supported()
{
#ifdef	NO_IPV6
	return false;
#else	// NO_IPV6
	SOCKET s;

	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	closesocket(s);

	return true;
#endif	// NO_IPV6
}

// Get the host name from the host cache
bool GetHostCache(char *hostname, UINT size, IP *ip)
{
	bool ret;
	// Validate arguments
	if (hostname == NULL || ip == NULL)
	{
		return false;
	}

	ret = false;

	LockList(HostCacheList);
	{
		HOSTCACHE t, *c;
		Zero(&t, sizeof(t));
		Copy(&t.IpAddress, ip, sizeof(IP));

		c = Search(HostCacheList, &t);
		if (c != NULL)
		{
			if (IsEmptyStr(c->HostName) == false)
			{
				ret = true;
				StrCpy(hostname, size, c->HostName);
			}
			else
			{
				ret = true;
				StrCpy(hostname, size, "");
			}
		}
	}
	UnlockList(HostCacheList);

	return ret;
}

// Add to the host name cache
void AddHostCache(IP *ip, char *hostname)
{
	// Validate arguments
	if (ip == NULL || hostname == NULL)
	{
		return;
	}
	if (IsNetworkNameCacheEnabled() == false)
	{
		return;
	}

	LockList(HostCacheList);
	{
		HOSTCACHE t, *c;
		UINT i;
		LIST *o;

		Zero(&t, sizeof(t));
		Copy(&t.IpAddress, ip, sizeof(IP));

		c = Search(HostCacheList, &t);
		if (c == NULL)
		{
			c = ZeroMalloc(sizeof(HOSTCACHE));
			Copy(&c->IpAddress, ip, sizeof(IP));
			Add(HostCacheList, c);
		}

		StrCpy(c->HostName, sizeof(c->HostName), hostname);
		c->Expires = Tick64() + (UINT64)EXPIRES_HOSTNAME;

		o = NewListFast(NULL);

		for (i = 0;i < LIST_NUM(HostCacheList);i++)
		{
			HOSTCACHE *c = LIST_DATA(HostCacheList, i);

			if (c->Expires <= Tick64())
			{
				Add(o, c);
			}
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			HOSTCACHE *c = LIST_DATA(o, i);

			if (Delete(HostCacheList, c))
			{
				Free(c);
			}
		}

		ReleaseList(o);
	}
	UnlockList(HostCacheList);
}

// Comparison of host name cache entries
int CompareHostCache(void *p1, void *p2)
{
	HOSTCACHE *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(HOSTCACHE **)p1;
	c2 = *(HOSTCACHE **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return CmpIpAddr(&c1->IpAddress, &c2->IpAddress);
}

// Release of the host name cache
void FreeHostCache()
{
	UINT i;

	for (i = 0;i < LIST_NUM(HostCacheList);i++)
	{
		HOSTCACHE *c = LIST_DATA(HostCacheList, i);

		Free(c);
	}

	ReleaseList(HostCacheList);
	HostCacheList = NULL;
}

// Initialization of the host name cache
void InitHostCache()
{
	HostCacheList = NewList(CompareHostCache);
}

// Get the number of wait threads
UINT GetNumWaitThread()
{
	UINT ret = 0;

	LockList(WaitThreadList);
	{
		ret = LIST_NUM(WaitThreadList);
	}
	UnlockList(WaitThreadList);

	return ret;
}

// Add the thread to the thread waiting list
void AddWaitThread(THREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	AddRef(t->ref);

	LockList(WaitThreadList);
	{
		Add(WaitThreadList, t);
	}
	UnlockList(WaitThreadList);
}

// Remove the thread from the waiting list
void DelWaitThread(THREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	LockList(WaitThreadList);
	{
		if (Delete(WaitThreadList, t))
		{
			ReleaseThread(t);
		}
	}
	UnlockList(WaitThreadList);
}

// Creating a thread waiting list
void InitWaitThread()
{
	WaitThreadList = NewList(NULL);
}

// Release of the thread waiting list
void FreeWaitThread()
{
	UINT i, num;
	THREAD **threads;

	LockList(WaitThreadList);
	{
		num = LIST_NUM(WaitThreadList);
		threads = ToArray(WaitThreadList);
		DeleteAll(WaitThreadList);
	}
	UnlockList(WaitThreadList);

	for (i = 0;i < num;i++)
	{
		THREAD *t = threads[i];
		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	Free(threads);

	ReleaseList(WaitThreadList);
	WaitThreadList = NULL;
}

// Check the cipher list name
bool CheckCipherListName(char *name)
{
	UINT i;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	for (i = 0;i < cipher_list_token->NumTokens;i++)
	{
		if (StrCmpi(cipher_list_token->Token[i], name) == 0)
		{
			return true;
		}
	}

	return false;
}

// Renewing the IP address of the DHCP server
void RenewDhcp()
{
#ifdef	OS_WIN32
	Win32RenewDhcp();
#else
	UnixRenewDhcp();
#endif
}

// Get a domain name for UNIX
bool UnixGetDomainName(char *name, UINT size)
{
	bool ret = false;
	BUF *b = ReadDump("/etc/resolv.conf");

	if (b == NULL)
	{
		return false;
	}

	while (true)
	{
		char *s = CfgReadNextLine(b);
		TOKEN_LIST *t;

		if (s == NULL)
		{
			break;
		}

		Trim(s);

		t = ParseToken(s, " \t");
		if (t != NULL)
		{
			if (t->NumTokens == 2)
			{
				if (StrCmpi(t->Token[0], "domain") == 0)
				{
					StrCpy(name, size, t->Token[1]);
					ret = true;
				}
			}
			FreeToken(t);
		}

		Free(s);
	}

	FreeBuf(b);

	return ret;
}

// Get the domain name
bool GetDomainName(char *name, UINT size)
{
	bool ret = false;
	IP ip;
	// Validate arguments
	ClearStr(name, size);
	if (name == NULL)
	{
		return false;
	}

#ifdef	OS_WIN32
	ClearStr(name, size);
	ret = Win32GetDefaultDns(&ip, name, size);

	if (ret == false || IsEmptyStr(name))
	{
		ret = Win32GetDnsSuffix(name, size);
	}
#else	// OS_WIN32
	ret = UnixGetDomainName(name, size);
#endif	// OS_WIN32

	if (ret == false)
	{
		return false;
	}

	return (IsEmptyStr(name) ? false : true);
}

// Get the default DNS server
bool GetDefaultDns(IP *ip)
{
	bool ret = false;
#ifdef	OS_WIN32
	ret = Win32GetDefaultDns(ip, NULL, 0);
#else
	ret = UnixGetDefaultDns(ip);
#endif	// OS_WIN32
	return ret;
}

// Creating a socket event
SOCK_EVENT *NewSockEvent()
{
	SOCK_EVENT *e = NULL;
#ifdef	OS_WIN32
	e = Win32NewSockEvent();
#else
	e = UnixNewSockEvent();
#endif	// OS_WIN32
	return e;
}

// Set of the socket event
void SetSockEvent(SOCK_EVENT *event)
{
#ifdef	OS_WIN32
	Win32SetSockEvent(event);
#else
	UnixSetSockEvent(event);
#endif	// OS_WIN32
}

// Clean-up of the socket event
void CleanupSockEvent(SOCK_EVENT *event)
{
#ifdef	OS_WIN32
	Win32CleanupSockEvent(event);
#else
	UnixCleanupSockEvent(event);
#endif	// OS_WIN32
}

// Waiting for the socket event
bool WaitSockEvent(SOCK_EVENT *event, UINT timeout)
{
	bool ret = false;
#ifdef	OS_WIN32
	ret = Win32WaitSockEvent(event, timeout);
#else
	ret = UnixWaitSockEvent(event, timeout);
#endif	// OS_WIN32
	return ret;
}

// Release of the socket event
void ReleaseSockEvent(SOCK_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

	if (Release(event->ref) == 0)
	{
		CleanupSockEvent(event);
	}
}

// Let belonging the socket to the socket event
void JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event)
{
	// Validate arguments
	if (sock == NULL || event == NULL)
	{
		return;
	}

	if (sock->Type == SOCK_INPROC)
	{
		// Set the SockEvent on the receiver TUBE for in-process type socket
		SetTubeSockEvent(sock->RecvTube, event);
		return;
	}

	if (sock->BulkRecvTube != NULL)
	{
		// Set the SockEvent on the receiver TUBE in case of R-UDP socket
		SetTubeSockEvent(sock->BulkRecvTube, event);
	}

#ifdef	OS_WIN32
	Win32JoinSockToSockEvent(sock, event);
#else
	UnixJoinSockToSockEvent(sock, event);
#endif	// OS_WIN32
}

// New special cancel object
CANCEL *NewCancelSpecial(void *hEvent)
{
	CANCEL *c;
	// Validate arguments
	if (hEvent == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CANCEL));
	c->ref = NewRef();
	c->SpecialFlag = true;

#ifdef	OS_WIN32
	c->hEvent = (HANDLE)hEvent;
#else	// OS_WIN32
	c->pipe_read = (int)hEvent;
	c->pipe_write = -1;
#endif	// OS_WIN32

	return c;
}

// Creating a cancel object
CANCEL *NewCancel()
{
	CANCEL *c = NULL;
#ifdef	OS_WIN32
	c = Win32NewCancel();
#else
	c = UnixNewCancel();
#endif	// OS_WIN32
	return c;
}

// Release of the cancel object
void ReleaseCancel(CANCEL *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		CleanupCancel(c);
	}
}

// Clean up of the cancel object
void CleanupCancel(CANCEL *c)
{
#ifdef	OS_WIN32
	Win32CleanupCancel(c);
#else
	UnixCleanupCancel(c);
#endif
}

// Cancellation triggered
void Cancel(CANCEL *c)
{
#ifdef	OS_WIN32
	Win32Cancel(c);
#else
	UnixCancel(c);
#endif
}

// Calculate the optimal route from the specified routing table
ROUTE_ENTRY *GetBestRouteEntryFromRouteTable(ROUTE_TABLE *table, IP *ip)
{
	return GetBestRouteEntryFromRouteTableEx(table, ip, 0);
}
ROUTE_ENTRY *GetBestRouteEntryFromRouteTableEx(ROUTE_TABLE *table, IP *ip, UINT exclude_if_id)
{
	UINT i;
	ROUTE_ENTRY *ret = NULL;
	ROUTE_ENTRY *tmp = NULL;
	UINT64 min_score = 0;
	// Validate arguments
	if (ip == NULL || table == NULL)
	{
		return NULL;
	}

	if (IsIP6(ip))
	{
		// IPv6 is not supported
		return NULL;
	}

	// Select routing table entry by following rule
	// 1. Largest subnet mask
	// 2. Smallest metric value 
	for (i = 0;i < table->NumEntry;i++)
	{
		ROUTE_ENTRY *e = table->Entry[i];
		UINT dest, net, mask;

		dest = IPToUINT(ip);
		net = IPToUINT(&e->DestIP);
		mask = IPToUINT(&e->DestMask);

		if (exclude_if_id != 0)
		{
			if (e->InterfaceID == exclude_if_id)
			{
				continue;
			}
		}

		// Mask test
		if ((dest & mask) == (net & mask))
		{
			// Calculate the score
			UINT score_high32 = mask;
			UINT score_low32 = 0xFFFFFFFF - e->Metric;
			UINT64 score64 = (UINT64)score_high32 * (UINT64)0x80000000 * (UINT64)2 + (UINT64)score_low32;
			if (score64 == 0)
			{
				score64 = 1;
			}

			e->InnerScore = score64;
		}
	}

	tmp = NULL;

	// Search for the item with maximum score
	for (i = 0;i < table->NumEntry;i++)
	{
		ROUTE_ENTRY *e = table->Entry[i];

		if (e->InnerScore != 0)
		{
			if (e->InnerScore >= min_score)
			{
				tmp = e;
				min_score = e->InnerScore;
			}
		}
	}

	if (tmp != NULL)
	{
		UINT dest, gateway, mask;

		// Generate an entry
		ret = ZeroMallocFast(sizeof(ROUTE_ENTRY));

		Copy(&ret->DestIP, ip, sizeof(IP));
		ret->DestMask.addr[0] = 255;
		ret->DestMask.addr[1] = 255;
		ret->DestMask.addr[2] = 255;
		ret->DestMask.addr[3] = 255;
		Copy(&ret->GatewayIP, &tmp->GatewayIP, sizeof(IP));
		ret->InterfaceID = tmp->InterfaceID;
		ret->LocalRouting = tmp->LocalRouting;
		ret->OldIfMetric = tmp->Metric;
		ret->Metric = 1;
		ret->PPPConnection = tmp->PPPConnection;

		// Calculation related to routing control
		dest = IPToUINT(&tmp->DestIP);
		gateway = IPToUINT(&tmp->GatewayIP);
		mask = IPToUINT(&tmp->DestMask);
		if ((dest & mask) == (gateway & mask))
		{
#ifdef	OS_WIN32
			if (MsIsVista() == false)
			{
				// Adjust for Windows
				ret->PPPConnection = true;
			}
#endif	// OS_WIN32
		}
	}

	return ret;
}

// Release the routing entry
void FreeRouteEntry(ROUTE_ENTRY *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	Free(e);
}

// Get the best route entry by analyzing the current routing table
ROUTE_ENTRY *GetBestRouteEntry(IP *ip)
{
	return GetBestRouteEntryEx(ip, 0);
}
ROUTE_ENTRY *GetBestRouteEntryEx(IP *ip, UINT exclude_if_id)
{
	ROUTE_TABLE *table;
	ROUTE_ENTRY *e = NULL;
	// Validate arguments
	if (ip == NULL)
	{
		return NULL;
	}

	table = GetRouteTable();
	if (table == NULL)
	{
		return NULL;
	}

	e = GetBestRouteEntryFromRouteTableEx(table, ip, exclude_if_id);
	FreeRouteTable(table);

	return e;
}

// Get the interface ID of the virtual LAN card
UINT GetVLanInterfaceID(char *tag_name)
{
	UINT ret = 0;
#ifdef	OS_WIN32
	ret = Win32GetVLanInterfaceID(tag_name);
#else	// OS_WIN32
	ret = UnixGetVLanInterfaceID(tag_name);
#endif	// OS_WIN32
	return ret;
}

// Release of enumeration variable of virtual LAN card
void FreeEnumVLan(char **s)
{
	char *a;
	UINT i;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	i = 0;
	while (true)
	{
		a = s[i++];
		if (a == NULL)
		{
			break;
		}
		Free(a);
	}

	Free(s);
}

// Enumeration of virtual LAN cards
char **EnumVLan(char *tag_name)
{
	char **ret = NULL;
#ifdef	OS_WIN32
	ret = Win32EnumVLan(tag_name);
#else	// OS_WIN32
	ret = UnixEnumVLan(tag_name);
#endif	// OS_WIN32
	return ret;
}

// Display the routing table
void DebugPrintRouteTable(ROUTE_TABLE *r)
{
	UINT i;
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	if (IsDebug() == false)
	{
		return;
	}

	Debug("---- Routing Table (%u Entries) ----\n", r->NumEntry);

	for (i = 0;i < r->NumEntry;i++)
	{
		Debug("   ");

		DebugPrintRoute(r->Entry[i]);
	}

	Debug("------------------------------------\n");
}

// Display the routing table entry
void DebugPrintRoute(ROUTE_ENTRY *e)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	if (IsDebug() == false)
	{
		return;
	}

	RouteToStr(tmp, sizeof(tmp), e);

	Debug("%s\n", tmp);
}

// Convert the routing table entry to string
void RouteToStr(char *str, UINT str_size, ROUTE_ENTRY *e)
{
	char dest_ip[MAX_PATH];
	char dest_mask[MAX_PATH];
	char gateway_ip[MAX_PATH];
	// Validate arguments
	if (str == NULL || e == NULL)
	{
		return;
	}

	IPToStr(dest_ip, sizeof(dest_ip), &e->DestIP);
	IPToStr(dest_mask, sizeof(dest_mask), &e->DestMask);
	IPToStr(gateway_ip, sizeof(gateway_ip), &e->GatewayIP);

	Format(str, str_size, "%s/%s %s m=%u oif=%u if=%u lo=%u p=%u",
		dest_ip, dest_mask, gateway_ip,
		e->Metric, e->OldIfMetric, e->InterfaceID,
		e->LocalRouting, e->PPPConnection);
}

// Delete the routing table
void DeleteRouteEntry(ROUTE_ENTRY *e)
{
	Debug("DeleteRouteEntry();\n");
#ifdef	OS_WIN32
	Win32DeleteRouteEntry(e);
#else	// OS_WIN32
	UnixDeleteRouteEntry(e);
#endif
}

// Add to the routing table
bool AddRouteEntry(ROUTE_ENTRY *e)
{
	bool dummy = false;
	return AddRouteEntryEx(e, &dummy);
}
bool AddRouteEntryEx(ROUTE_ENTRY *e, bool *already_exists)
{
	bool ret = false;
	Debug("AddRouteEntryEx();\n");
#ifdef	OS_WIN32
	ret = Win32AddRouteEntry(e, already_exists);
#else	// OS_WIN32
	ret = UnixAddRouteEntry(e, already_exists);
#endif
	return ret;
}

// Get the routing table
ROUTE_TABLE *GetRouteTable()
{
	ROUTE_TABLE *t = NULL;
	UINT i;
	BUF *buf = NewBuf();
	UCHAR hash[MD5_SIZE];

#ifdef	OS_WIN32
	t = Win32GetRouteTable();
#else	//OS_WIN32
	t = UnixGetRouteTable();
#endif	// OS_WIN32

	WriteBuf(buf, &t->NumEntry, sizeof(t->NumEntry));

	for (i = 0;i < t->NumEntry;i++)
	{
		ROUTE_ENTRY *e = t->Entry[i];

		WriteBuf(buf, e, sizeof(ROUTE_ENTRY));
	}

	Hash(hash, buf->Buf, buf->Size, false);

	FreeBuf(buf);

	Copy(&t->HashedValue, hash, sizeof(t->HashedValue));

	return t;
}

// Release of the routing table
void FreeRouteTable(ROUTE_TABLE *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumEntry;i++)
	{
		Free(t->Entry[i]);
	}
	Free(t->Entry);
	Free(t);
}

// UDP receiving
UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size)
{
	SOCKET s;
	int ret, sz;
	struct sockaddr_in addr;
	// Validate arguments
	if (sock != NULL)
	{
		sock->IgnoreRecvErr = false;
	}
	if (sock == NULL || src_addr == NULL || src_port == NULL || data == NULL)
	{
		return false;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return false;
	}
	if (size == 0)
	{
		return false;
	}

	if (sock->IPv6)
	{
		return RecvFrom6(sock, src_addr, src_port, data, size);
	}

	s = sock->socket;

	sz = sizeof(addr);
	ret = recvfrom(s, data, size, 0, (struct sockaddr *)&addr, (int *)&sz);
	if (ret > 0)
	{
		InAddrToIP(src_addr, &addr.sin_addr);
		*src_port = (UINT)ntohs(addr.sin_port);
		if (sock->IsRawSocket)
		{
			*src_port = sock->LocalPort;
/*
			{
				char tmp[MAX_SIZE];

				IPToStr(tmp, sizeof(tmp), &sock->LocalIP);
				Debug("Raw: %u from %s\n", sock->LocalPort, tmp);
			}*/
		}

		Lock(sock->lock);
		{
			sock->RecvNum++;
			sock->RecvSize += (UINT64)ret;
		}
		Unlock(sock->lock);

		// Debug("UDP RecvFrom: %u\n", ret);

		return (UINT)ret;
	}
	else
	{
		sock->IgnoreRecvErr = false;

#ifdef	OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
			WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEADDRNOTAVAIL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		else
		{
			UINT e = WSAGetLastError();
//			Debug("RecvFrom Error: %u\n", e);
		}
#else	// OS_WIN32
		if (errno == ECONNREFUSED || errno == ECONNRESET || errno == EMSGSIZE || errno == ENOBUFS || errno == ENOMEM || errno == EINTR)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (errno == EAGAIN)
		{
			return SOCK_LATER;
		}
#endif	// OS_WIN32
		return 0;
	}
}
UINT RecvFrom6(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size)
{
	SOCKET s;
	int ret, sz;
	struct sockaddr_in6 addr;
	// Validate arguments
	if (sock != NULL)
	{
		sock->IgnoreRecvErr = false;
	}
	if (sock == NULL || src_addr == NULL || src_port == NULL || data == NULL)
	{
		return false;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return false;
	}
	if (size == 0)
	{
		return false;
	}

	s = sock->socket;

	sz = sizeof(addr);
	ret = recvfrom(s, data, size, 0, (struct sockaddr *)&addr, (int *)&sz);
	if (ret > 0)
	{
		InAddrToIP6(src_addr, &addr.sin6_addr);
		src_addr->ipv6_scope_id = addr.sin6_scope_id;
		*src_port = (UINT)ntohs(addr.sin6_port);
		if (sock->IsRawSocket)
		{
			*src_port = sock->LocalPort;
		}

		Lock(sock->lock);
		{
			sock->RecvNum++;
			sock->RecvSize += (UINT64)ret;
		}
		Unlock(sock->lock);

		// Debug("UDP RecvFrom: %u\n", ret);

		return (UINT)ret;
	}
	else
	{
		sock->IgnoreRecvErr = false;

#ifdef	OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
			WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEADDRNOTAVAIL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		else
		{
			UINT e = WSAGetLastError();
			//			Debug("RecvFrom Error: %u\n", e);
		}
#else	// OS_WIN32
		if (errno == ECONNREFUSED || errno == ECONNRESET || errno == EMSGSIZE || errno == ENOBUFS || errno == ENOMEM || errno == EINTR)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (errno == EAGAIN)
		{
			return SOCK_LATER;
		}
#endif	// OS_WIN32
		return 0;
	}
}

// Lock the OpenSSL
void LockOpenSSL()
{
	Lock(openssl_lock);
}

// Unlock the OpenSSL
void UnlockOpenSSL()
{
	Unlock(openssl_lock);
}

// UDP transmission
UINT SendTo(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size)
{
	return SendToEx(sock, dest_addr, dest_port, data, size, false);
}
UINT SendToEx(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast)
{
	SOCKET s;
	int ret;
	struct sockaddr_in addr;
	// Validate arguments
	if (sock != NULL)
	{
		sock->IgnoreSendErr = false;
	}
	if (sock == NULL || dest_addr == NULL || (sock->IsRawSocket == false && dest_port == 0) || data == NULL)
	{
		return 0;
	}
	if (dest_port >= 65536 && sock->IsRawSocket == false)
	{
		return 0;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (size == 0)
	{
		return 0;
	}

	if (sock->IPv6)
	{
		return SendTo6Ex(sock, dest_addr, dest_port, data, size, broadcast);
	}

	if (IsIP4(dest_addr) == false)
	{
		return 0;
	}

	s = sock->socket;
	Zero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	if (sock->IsRawSocket == false)
	{
		addr.sin_port = htons((USHORT)dest_port);
	}
	IPToInAddr(&addr.sin_addr, dest_addr);

	if ((dest_addr->addr[0] == 255 && dest_addr->addr[1] == 255 && 
		dest_addr->addr[2] == 255 && dest_addr->addr[3] == 255) ||
		(dest_addr->addr[0] >= 224 && dest_addr->addr[0] <= 239)
		|| broadcast)
	{
		if (sock->UdpBroadcast == false)
		{
			bool yes = true;

			sock->UdpBroadcast = true;

			setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
		}
	}

	ret = sendto(s, data, size, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != (int)size)
	{
		sock->IgnoreSendErr = false;

#ifdef	OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
			WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEINVAL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreSendErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		else
		{
			UINT e = WSAGetLastError();
			Debug("SendTo Error; %u\n", e);
		}
#else	// OS_WIN32
		if (errno == ECONNREFUSED || errno == ECONNRESET || errno == EMSGSIZE || errno == ENOBUFS || errno == ENOMEM || errno == EINTR)
		{
			sock->IgnoreSendErr = true;
		}
		else if (errno == EAGAIN)
		{
			return SOCK_LATER;
		}
#endif	// OS_WIN32
		return 0;
	}

	Lock(sock->lock);
	{
		sock->SendSize += (UINT64)size;
		sock->SendNum++;
	}
	Unlock(sock->lock);

	return ret;
}
UINT SendTo6(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size)
{
	return SendTo6Ex(sock, dest_addr, dest_port, data, size, false);
}
UINT SendTo6Ex(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast)
{
	SOCKET s;
	int ret;
	struct sockaddr_in6 addr;
	UINT type;
	// Validate arguments
	if (sock != NULL)
	{
		sock->IgnoreSendErr = false;
	}
	if (sock == NULL || dest_addr == NULL || (sock->IsRawSocket == false && dest_port == 0) || data == NULL)
	{
		return 0;
	}
	if (dest_port >= 65536 && sock->IsRawSocket == false)
	{
		return 0;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (size == 0)
	{
		return 0;
	}

	if (IsIP6(dest_addr) == false)
	{
		return 0;
	}

	s = sock->socket;
	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	if (sock->IsRawSocket == false)
	{
		addr.sin6_port = htons((USHORT)dest_port);
	}
	IPToInAddr6(&addr.sin6_addr, dest_addr);
	addr.sin6_scope_id = dest_addr->ipv6_scope_id;

	type = GetIPAddrType6(dest_addr);

	if ((type & IPV6_ADDR_MULTICAST) || broadcast)
	{
		if (sock->UdpBroadcast == false)
		{
			bool yes = true;

			sock->UdpBroadcast = true;

			setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
		}
	}

	ret = sendto(s, data, size, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != (int)size)
	{
		sock->IgnoreSendErr = false;

#ifdef	OS_WIN32
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
			WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEINVAL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreSendErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		else
		{
			UINT e = WSAGetLastError();
		}
#else	// OS_WIN32
		if (errno == ECONNREFUSED || errno == ECONNRESET || errno == EMSGSIZE || errno == ENOBUFS || errno == ENOMEM || errno == EINTR)
		{
			sock->IgnoreSendErr = true;
		}
		else if (errno == EAGAIN)
		{
			return SOCK_LATER;
		}
#endif	// OS_WIN32
		return 0;
	}

	Lock(sock->lock);
	{
		sock->SendSize += (UINT64)size;
		sock->SendNum++;
	}
	Unlock(sock->lock);

	return ret;
}

// Disable the UDP checksum
void DisableUDPChecksum(SOCK *s)
{
	bool true_flag = true;
	// Validate arguments
	if (s == NULL || s->Type != SOCK_UDP)
	{
		return;
	}

	if (s->socket != INVALID_SOCKET)
	{
		if (s->IPv6 == false)
		{
#ifdef	UDP_NOCHECKSUM
			setsockopt(s->socket, IPPROTO_UDP, UDP_NOCHECKSUM, (char *)&true_flag, sizeof(bool));
#endif	// UDP_NOCHECKSUM
		}
	}
}

// Set the socket to asynchronous mode
void InitAsyncSocket(SOCK *sock)
{
#ifdef	OS_WIN32
	Win32InitAsyncSocket(sock);
#else	// OS_WIN32
	UnixInitAsyncSocket(sock);
#endif	// OS_WIN32
}

// Get a new available UDP port number
UINT GetNewAvailableUdpPortRand()
{
	UINT num_retry = 8;
	UINT i;
	UINT ret = 0;
	UCHAR seed[SHA1_SIZE];

	Rand(seed, sizeof(seed));

	for (i = 0;i < num_retry;i++)
	{
		SOCK *s = NewUDPEx2Rand(false, NULL, seed, sizeof(seed), RAND_UDP_PORT_DEFAULT_NUM_RETRY);

		if (s != NULL)
		{
			ret = s->LocalPort;

			Disconnect(s);
			ReleaseSock(s);
		}

		if (ret != 0)
		{
			break;
		}
	}

	return ret;
}

// Open a UDP port (port number is random, but determine the randomness in the seed)
SOCK *NewUDPEx2Rand(bool ipv6, IP *ip, void *rand_seed, UINT rand_seed_size, UINT num_retry)
{
	UINT i;
	// Validate arguments
	if (rand_seed == NULL || rand_seed_size == 0)
	{
		return NULL;
	}
	if (num_retry == 0)
	{
		num_retry = RAND_UDP_PORT_DEFAULT_NUM_RETRY;
	}

	for (i = 0; i < (num_retry + 1);i++)
	{
		BUF *buf = NewBuf();
		UCHAR hash[SHA1_SIZE];
		UINT port = 0;
		SOCK *s;

		WriteBuf(buf, rand_seed, rand_seed_size);
		WriteBufInt(buf, i);

		HashSha1(hash, buf->Buf, buf->Size);

		FreeBuf(buf);

		port = READ_UINT(hash);

		port = RAND_UDP_PORT_START + (port % (RAND_UDP_PORT_END - RAND_UDP_PORT_START));

		s = NewUDPEx2(port, ipv6, ip);

		if (s != NULL)
		{
			return s;
		}
	}

	return NewUDPEx2(0, ipv6, ip);
}

// Generate a random port number (based on the EXE path and machine key)
UINT NewRandPortByMachineAndExePath(UINT start_port, UINT end_port, UINT additional_int)
{
	BUF *b;
	char machine_name[MAX_SIZE];
	wchar_t exe_path[MAX_PATH];
	char *product_id = NULL;
	UCHAR hash[SHA1_SIZE];

#ifdef	OS_WIN32
	product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId");
	if (product_id == NULL)
	{
		product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId");
	}
#endif	// OS_WIN32

	b = NewBuf();

	GetMachineHostName(machine_name, sizeof(machine_name));
	Trim(machine_name);
	StrUpper(machine_name);

	GetExeNameW(exe_path, sizeof(exe_path));
	UniTrim(exe_path);
	UniStrUpper(exe_path);

	WriteBuf(b, machine_name, StrSize(machine_name));
	WriteBuf(b, exe_path, UniStrSize(exe_path));
	WriteBuf(b, product_id, StrSize(product_id));
	WriteBufInt(b, additional_int);

	HashSha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Free(product_id);

	return (READ_UINT(hash) % (end_port - start_port)) + start_port;
}

// Open the UDP port (based on the EXE path and machine key)
SOCK *NewUDPEx2RandMachineAndExePath(bool ipv6, IP *ip, UINT num_retry, UCHAR rand_port_id)
{
	BUF *b;
	char machine_name[MAX_SIZE];
	wchar_t exe_path[MAX_PATH];
	char *product_id = NULL;
	UCHAR hash[SHA1_SIZE];

#ifdef	OS_WIN32
	product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId");
	if (product_id == NULL)
	{
		product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId");
	}
#endif	// OS_WIN32

	b = NewBuf();

	GetMachineHostName(machine_name, sizeof(machine_name));
	Trim(machine_name);
	StrUpper(machine_name);

	GetExeNameW(exe_path, sizeof(exe_path));
	UniTrim(exe_path);
	UniStrUpper(exe_path);

	WriteBuf(b, machine_name, StrSize(machine_name));
	WriteBuf(b, exe_path, UniStrSize(exe_path));
	WriteBuf(b, product_id, StrSize(product_id));
	WriteBufChar(b, rand_port_id);
	//WriteBufInt(b, GetHostIPAddressHash32());

	HashSha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Free(product_id);

	return NewUDPEx2Rand(ipv6, ip, hash, sizeof(hash), num_retry);
}

// Set the DF bit of the socket
void ClearSockDfBit(SOCK *s)
{
#ifdef	IP_PMTUDISC_DONT
#ifdef	IP_MTU_DISCOVER
	UINT value = IP_PMTUDISC_DONT;
	if (s == NULL)
	{
		return;
	}

	setsockopt(s->socket, IPPROTO_IP, IP_MTU_DISCOVER, (char *)&value, sizeof(value));
#endif	// IP_MTU_DISCOVER
#endif	// IP_PMTUDISC_DONT
}

// Set the header-include option
void SetRawSockHeaderIncludeOption(SOCK *s, bool enable)
{
	UINT value = BOOL_TO_INT(enable);
	if (s == NULL || s->IsRawSocket == false)
	{
		return;
	}

	setsockopt(s->socket, IPPROTO_IP, IP_HDRINCL, (char *)&value, sizeof(value));

	s->RawIP_HeaderIncludeFlag = enable;
}

// Create and initialize the UDP socket
// If port is specified as 0, system assigns a certain port.
SOCK *NewUDP(UINT port)
{
	return NewUDPEx(port, false);
}
SOCK *NewUDPEx(UINT port, bool ipv6)
{
	return NewUDPEx2(port, ipv6, NULL);
}
SOCK *NewUDPEx2(UINT port, bool ipv6, IP *ip)
{
	if (ipv6 == false)
	{
		return NewUDP4(port, ip);
	}
	else
	{
		return NewUDP6(port, ip);
	}
}
SOCK *NewUDPEx3(UINT port, IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return NewUDPEx2(port, false, NULL);
	}

	if (IsIP4(ip))
	{
		return NewUDPEx2(port, false, ip);
	}
	else
	{
		return NewUDPEx2(port, true, ip);
	}
}
SOCK *NewUDP4(UINT port, IP *ip)
{
	SOCK *sock;
	SOCKET s;
	struct sockaddr_in addr;
	// Validate arguments
	if (ip != NULL && IsIP4(ip) == false)
	{
		return NULL;
	}

	if (IS_SPECIAL_PORT(port) == false)
	{
		s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	else
	{
		s = socket(AF_INET, SOCK_RAW, GET_SPECIAL_PORT(port));
	}
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;

	if (ip == NULL || IsZeroIP(ip))
	{
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else
	{
		IPToInAddr(&addr.sin_addr, ip);
	}

	if (port == 0 || IS_SPECIAL_PORT(port))
	{
		addr.sin_port = 0;
	}
	else
	{
		addr.sin_port = htons((USHORT)port);
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		// Failure
		if (port != 0)
		{
			bool true_flag = true;
			setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(bool));
			if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
			{
				bool false_flag = false;
				setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&false_flag, sizeof(bool));
#ifdef	SO_EXCLUSIVEADDRUSE
				setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&true_flag, sizeof(bool));
#endif	// SO_EXCLUSIVEADDRUSE
				if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
				{
					closesocket(s);
					return NULL;
				}
			}
		}
		else
		{
			closesocket(s);
			return NULL;
		}
	}

	sock = NewSock();

	sock->Type = SOCK_UDP;
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = false;
	if (port != 0)
	{
		sock->ServerMode = true;
	}

	sock->socket = s;

	InitUdpSocketBufferSize((int)s);

	if (IS_SPECIAL_PORT(port))
	{
		bool no = false;
		setsockopt(sock->socket, IPPROTO_IP, IP_HDRINCL, (char *)&no, sizeof(no));

		sock->IsRawSocket = true;
		sock->RawSocketIPProtocol = GET_SPECIAL_PORT(port);
	}

	QuerySocketInformation(sock);

	return sock;
}
SOCK *NewUDP6(UINT port, IP *ip)
{
	SOCK *sock;
	SOCKET s;
	struct sockaddr_in6 addr;
	// Validate arguments
	if (ip != NULL && IsIP6(ip) == false)
	{
		return NULL;
	}

	if (IS_SPECIAL_PORT(port) == false)
	{
		s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else
	{
		s = socket(AF_INET6, SOCK_RAW, GET_SPECIAL_PORT(port));
	}
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	if (port == 0)
	{
		addr.sin6_port = 0;
	}
	else
	{
		addr.sin6_port = htons((USHORT)port);
	}

	if (ip != NULL && IsZeroIP(ip) == false)
	{
		IPToInAddr6(&addr.sin6_addr, ip);
		addr.sin6_scope_id = ip->ipv6_scope_id;
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		// Failure
		if (port != 0)
		{
			bool true_flag = true;
			setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(bool));
			if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
			{
				bool false_flag = false;
				setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&false_flag, sizeof(bool));
#ifdef	SO_EXCLUSIVEADDRUSE
				setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&true_flag, sizeof(bool));
#endif	// SO_EXCLUSIVEADDRUSE
				if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
				{
					closesocket(s);
					return NULL;
				}
			}
		}
		else
		{
			closesocket(s);
			return NULL;
		}
	}

	sock = NewSock();

	sock->Type = SOCK_UDP;
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = false;
	sock->IPv6 = true;
	if (port != 0)
	{
		sock->ServerMode = true;
	}

	sock->socket = s;

	InitUdpSocketBufferSize(s);

	if (IS_SPECIAL_PORT(port))
	{
		bool no = false;
#ifdef	IPV6_HDRINCL
		setsockopt(sock->socket, IPPROTO_IP, IPV6_HDRINCL, (char *)&no, sizeof(no));
#endif	// IPV6_HDRINCL
		setsockopt(sock->socket, IPPROTO_IP, IP_HDRINCL, (char *)&no, sizeof(no));

		sock->IsRawSocket = true;
		sock->RawSocketIPProtocol = GET_SPECIAL_PORT(port);
	}

	QuerySocketInformation(sock);

	return sock;
}

// Select function
void Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2)
{
#ifdef	OS_WIN32
	Win32Select(set, timeout, c1, c2);
#else
	UnixSelect(set, timeout, c1, c2);
#endif	// OS_WIN32
}

// Add a socket to the socket set
void AddSockSet(SOCKSET *set, SOCK *sock)
{
	// Validate arguments
	if (set == NULL || sock == NULL)
	{
		return;
	}
	if (sock->Type == SOCK_TCP && sock->Connected == false)
	{
		return;
	}

	if (set->NumSocket >= MAX_SOCKSET_NUM)
	{
		// Upper limit
		return;
	}
	set->Sock[set->NumSocket++] = sock;
}

// Initializing the socket set
void InitSockSet(SOCKSET *set)
{
	// Validate arguments
	if (set == NULL)
	{
		return;
	}

	Zero(set, sizeof(SOCKSET));
}

// Receive all by TCP
bool RecvAll(SOCK *sock, void *data, UINT size, bool secure)
{
	UINT recv_size, sz, ret;
	// Validate arguments
	if (sock == NULL || data == NULL)
	{
		return false;
	}
	if (size == 0)
	{
		return true;
	}
	if (sock->AsyncMode)
	{
		return false;
	}

	recv_size = 0;

	while (true)
	{
		sz = size - recv_size;
		ret = Recv(sock, (UCHAR *)data + recv_size, sz, secure);
		if (ret == 0)
		{
			return false;
		}
		recv_size += ret;
		if (recv_size >= size)
		{
			return true;
		}
	}
}

// Send the TCP send buffer
bool SendNow(SOCK *sock, int secure)
{
	bool ret;
	// Validate arguments
	if (sock == NULL || sock->AsyncMode != false)
	{
		return false;
	}
	if (sock->SendBuf->Size == 0)
	{
		return true;
	}

	ret = SendAll(sock, sock->SendBuf->Buf, sock->SendBuf->Size, secure);
	ClearBuf(sock->SendBuf);

	return ret;
}

// Append to the TCP send buffer
void SendAdd(SOCK *sock, void *data, UINT size)
{
	// Validate arguments
	if (sock == NULL || data == NULL || size == 0 || sock->AsyncMode != false)
	{
		return;
	}

	WriteBuf(sock->SendBuf, data, size);
}

// Send all by TCP
bool SendAll(SOCK *sock, void *data, UINT size, bool secure)
{
	UCHAR *buf;
	UINT sent_size;
	UINT ret;
	// Validate arguments
	if (sock == NULL || data == NULL)
	{
		return false;
	}
	if (sock->AsyncMode)
	{
		return false;
	}
	if (size == 0)
	{
		return true;
	}

	buf = (UCHAR *)data;
	sent_size = 0;

	while (true)
	{
		ret = Send(sock, buf, size - sent_size, secure);
		if (ret == 0)
		{
			return false;
		}
		sent_size += ret;
		buf += ret;
		if (sent_size >= size)
		{
			return true;
		}
	}
}

// Set the cipher algorithm name to want to use
void SetWantToUseCipher(SOCK *sock, char *name)
{
	char tmp[1024];
	// Validate arguments
	if (sock == NULL || name == NULL)
	{
		return;
	}

	if (sock->WaitToUseCipher)
	{
		Free(sock->WaitToUseCipher);
	}

	Zero(tmp, sizeof(tmp));
	StrCpy(tmp, sizeof(tmp), name);
	StrCat(tmp, sizeof(tmp), " ");
	StrCat(tmp, sizeof(tmp), cipher_list);

	sock->WaitToUseCipher = CopyStr(tmp);
}

// Add all the chain certificates in the chain_certs directory
void AddChainSslCertOnDirectory(struct ssl_ctx_st *ctx)
{
	wchar_t dirname[MAX_SIZE];
	wchar_t exedir[MAX_SIZE];
	wchar_t txtname[MAX_SIZE];
	DIRLIST *dir;
	LIST *o;
	UINT i;

	// Validate arguments
	if (ctx == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	GetExeDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");

	MakeDirExW(dirname);

	CombinePathW(txtname, sizeof(txtname), dirname, L"Readme_Chain_Certs.txt");

	if (IsFileExistsW(txtname) == false)
	{
		FileCopyW(L"|chain_certs.txt", txtname);
	}

	dir = EnumDirW(dirname);

	if (dir != NULL)
	{
		for (i = 0;i < dir->NumFiles;i++)
		{
			DIRENT *e = dir->File[i];

			if (e->Folder == false)
			{
				wchar_t tmp[MAX_SIZE];
				X *x;

				CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

				x = FileToXW(tmp);

				if (x != NULL)
				{
					UINT j;
					bool exists = false;
					UCHAR hash[SHA1_SIZE];

					GetXDigest(x, hash, true);

					for (j = 0;j < LIST_NUM(o);j++)
					{
						UCHAR *hash2 = LIST_DATA(o, j);

						if (Cmp(hash, hash2, SHA1_SIZE) == 0)
						{
							exists = true;
						}
					}

					if (exists == false)
					{
						AddChainSslCert(ctx, x);

						Add(o, Clone(hash, SHA1_SIZE));
					}

					FreeX(x);
				}
			}
		}

		FreeDir(dir);
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UCHAR *hash = LIST_DATA(o, i);

		Free(hash);
	}

	ReleaseList(o);
}

// Add the chain certificate
bool AddChainSslCert(struct ssl_ctx_st *ctx, X *x)
{
	bool ret = false;
	X *x_copy;
	// Validate arguments
	if (ctx == NULL || x == NULL)
	{
		return ret;
	}

	x_copy = CloneX(x);

	if (x_copy != NULL)
	{
		SSL_CTX_add_extra_chain_cert(ctx, x_copy->x509);
		x_copy->do_not_free = true;

		ret = true;

		FreeX(x_copy);
	}

	return ret;
}

// Start a TCP-SSL communication
bool StartSSL(SOCK *sock, X *x, K *priv)
{
	return StartSSLEx(sock, x, priv, true, 0, NULL);
}
bool StartSSLEx(SOCK *sock, X *x, K *priv, bool client_tls, UINT ssl_timeout, char *sni_hostname)
{
	X509 *x509;
	EVP_PKEY *key;
	UINT prev_timeout = 1024;
	SSL_CTX *ssl_ctx;

#ifdef UNIX_SOLARIS
	SOCKET_TIMEOUT_PARAM *ttparam;
#endif //UNIX_SOLARIS

	// Validate arguments
	if (sock == NULL)
	{
		Debug("StartSSL Error: #0\n");
		return false;
	}
	if (sock->Connected && sock->Type == SOCK_INPROC && sock->ListenMode == false)
	{
		sock->SecureMode = true;
		return true;
	}
	if (sock->Connected == false || sock->socket == INVALID_SOCKET ||
		sock->ListenMode != false)
	{
		Debug("StartSSL Error: #1\n");
		return false;
	}
	if (x != NULL && priv == NULL)
	{
		Debug("StartSSL Error: #2\n");
		return false;
	}
	if (ssl_timeout == 0)
	{
		ssl_timeout = TIMEOUT_SSL_CONNECT;
	}

	if (sock->SecureMode)
	{
		//Debug("StartSSL Error: #3\n");
		// SSL communication has already started
		return true;
	}

	Lock(sock->ssl_lock);
	if (sock->SecureMode)
	{
		//Debug("StartSSL Error: #4\n");
		// SSL communication has already started
		Unlock(sock->ssl_lock);
		return true;
	}

	ssl_ctx = NewSSLCtx(sock->ServerMode);

	Lock(openssl_lock);
	{
		if (sock->ServerMode)
		{
			SSL_CTX_set_ssl_version(ssl_ctx, SSLv23_method());

#ifdef	SSL_OP_NO_SSLv2
			SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
#endif	// SSL_OP_NO_SSLv2

			if (sock->SslAcceptSettings.AcceptOnlyTls)
			{
#ifdef	SSL_OP_NO_SSLv3
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv3);
#endif	// SSL_OP_NO_SSLv3
			}

			if (sock->SslAcceptSettings.Tls_Disable1_0)
			{
#ifdef	SSL_OP_NO_TLSv1
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1);
#endif	// SSL_OP_NO_TLSv1
			}

			if (sock->SslAcceptSettings.Tls_Disable1_1)
			{
#ifdef	SSL_OP_NO_TLSv1_1
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_1);
#endif	// SSL_OP_NO_TLSv1_1
			}

			if (sock->SslAcceptSettings.Tls_Disable1_2)
			{
#ifdef	SSL_OP_NO_TLSv1_2
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2);
#endif	// SSL_OP_NO_TLSv1_2
			}

			Unlock(openssl_lock);
			AddChainSslCertOnDirectory(ssl_ctx);
			Lock(openssl_lock);
		}
		else
		{
			if (client_tls == false)
			{
				SSL_CTX_set_ssl_version(ssl_ctx, SSLv3_method());
			}
			else
			{
				SSL_CTX_set_ssl_version(ssl_ctx, SSLv23_client_method());
			}
		}
		sock->ssl = SSL_new(ssl_ctx);
		SSL_set_fd(sock->ssl, (int)sock->socket);

#ifdef	SSL_CTRL_SET_TLSEXT_HOSTNAME
		if (sock->ServerMode == false && client_tls)
		{
			if (IsEmptyStr(sni_hostname) == false)
			{
				// Set the SNI host name
				SSL_set_tlsext_host_name(sock->ssl, sni_hostname);
			}
		}
#endif	// SSL_CTRL_SET_TLSEXT_HOSTNAME

	}
	Unlock(openssl_lock);

	if (x != NULL)
	{
		// Check the certificate and the private key
		if (CheckXandK(x, priv))
		{
			// Use the certificate
			x509 = x->x509;
			key = priv->pkey;

			Lock(openssl_lock);
			{
				SSL_use_certificate(sock->ssl, x509);
				SSL_use_PrivateKey(sock->ssl, key);
			}
			Unlock(openssl_lock);
		}
	}

	if (sock->WaitToUseCipher != NULL)
	{
		// Set the cipher algorithm name to want to use
		Lock(openssl_lock);
		{
			SSL_set_cipher_list(sock->ssl, sock->WaitToUseCipher);
		}
		Unlock(openssl_lock);
	}

	if (sock->ServerMode)
	{
//		Lock(ssl_connect_lock);

// Run the time-out thread for SOLARIS
#ifdef UNIX_SOLARIS
		ttparam = NewSocketTimeout(sock);
#endif // UNIX_SOLARIS

		// Server mode
		if (SSL_accept(sock->ssl) <= 0)
		{

// Stop the timeout thread
#ifdef UNIX_SOLARIS
			FreeSocketTimeout(ttparam);
#endif // UNIX_SOLARIS

			//			Unlock(ssl_connect_lock);
			// SSL-Accept failure
			Lock(openssl_lock);
			{
				SSL_free(sock->ssl);
				sock->ssl = NULL;
			}
			Unlock(openssl_lock);

			Unlock(sock->ssl_lock);
			Debug("StartSSL Error: #5\n");
			FreeSSLCtx(ssl_ctx);
			return false;
		}

#ifdef	SSL_CTRL_SET_TLSEXT_HOSTNAME
#ifdef	TLSEXT_NAMETYPE_host_name
		if (true)
		{
			// Get the SNI host name
			const char *sni_recv_hostname = SSL_get_servername(sock->ssl, TLSEXT_NAMETYPE_host_name);

			if (IsEmptyStr((char *)sni_recv_hostname) == false)
			{
				StrCpy(sock->SniHostname, sizeof(sock->SniHostname), (char *)sni_recv_hostname);
			}
		}
#endif	// TLSEXT_NAMETYPE_host_name
#endif	// SSL_CTRL_SET_TLSEXT_HOSTNAME

// Stop the timeout thread
#ifdef UNIX_SOLARIS
		FreeSocketTimeout(ttparam);
#endif // UNIX_SOLARIS

		//		Unlock(ssl_connect_lock);
	}
	else
	{
		prev_timeout = GetTimeout(sock);
		SetTimeout(sock, ssl_timeout);
		Lock(ssl_connect_lock);
		// Client mode
		if (SSL_connect(sock->ssl) <= 0)
		{
			Unlock(ssl_connect_lock);
			// SSL-connect failure
			Lock(openssl_lock);
			{
				SSL_free(sock->ssl);
				sock->ssl = NULL;
			}
			Unlock(openssl_lock);

			Unlock(sock->ssl_lock);
			Debug("StartSSL Error: #5\n");
			SetTimeout(sock, prev_timeout);
			FreeSSLCtx(ssl_ctx);
			return false;
		}
		Unlock(ssl_connect_lock);
		SetTimeout(sock, prev_timeout);
	}

	// SSL communication is initiated
	sock->SecureMode = true;

	// Get the certificate of the remote host
	Lock(openssl_lock);
	{
		x509 = SSL_get_peer_certificate(sock->ssl);

		sock->SslVersion = SSL_get_version(sock->ssl);
	}
	Unlock(openssl_lock);

	if (x509 == NULL)
	{
		// The certificate does not exist on the remote host
		sock->RemoteX = NULL;
	}
	else
	{
		// Got a certificate
		sock->RemoteX = X509ToX(x509);
	}

	// Get the certificate of local host
	Lock(openssl_lock);
	{
		x509 = SSL_get_certificate(sock->ssl);
	}
	Unlock(openssl_lock);

	if (x509 == NULL)
	{
		// The certificate does not exist on the remote host
		sock->LocalX = NULL;
	}
	else
	{
		X *local_x;
		// Got a certificate
		local_x = X509ToX(x509);
		local_x->do_not_free = true;
		sock->LocalX = CloneX(local_x);
		FreeX(local_x);
	}

	// Automatic retry mode
	SSL_set_mode(sock->ssl, SSL_MODE_AUTO_RETRY);

	// Strange flag
	SSL_set_mode(sock->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	sock->ssl_ctx = ssl_ctx;

	// Get the algorithm name used to encrypt
	Lock(openssl_lock);
	{
		sock->CipherName = CopyStr((char *)SSL_get_cipher(sock->ssl));
	}
	Unlock(openssl_lock);

	Unlock(sock->ssl_lock);

#ifdef	ENABLE_SSL_LOGGING
	if (sock->ServerMode)
	{
		SockEnableSslLogging(sock);
	}
#endif	// ENABLE_SSL_LOGGING

	return true;
}



#ifdef	ENABLE_SSL_LOGGING

// Enable SSL logging
void SockEnableSslLogging(SOCK *s)
{
	char dirname[MAX_PATH];
	char tmp[MAX_PATH];
	char dtstr[MAX_PATH];
	char fn1[MAX_PATH], fn2[MAX_PATH];
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (s->IsSslLoggingEnabled)
	{
		return;
	}

	s->IsSslLoggingEnabled = true;

	GetDateTimeStrMilli64ForFileName(dtstr, sizeof(dtstr), LocalTime64());
	Format(tmp, sizeof(tmp), "%s__%r_%u__%r_%u", dtstr,
		&s->LocalIP, s->LocalPort, &s->RemoteIP, s->RemotePort);

	CombinePath(dirname, sizeof(dirname), SSL_LOGGING_DIRNAME, tmp);

	MakeDirEx(dirname);

	CombinePath(fn1, sizeof(fn1), dirname, "send.c");
	CombinePath(fn2, sizeof(fn2), dirname, "recv.c");

	s->SslLogging_Send = FileCreate(fn1);
	s->SslLogging_Recv = FileCreate(fn2);

	s->SslLogging_Lock = NewLock();
}

// Close SSL logging
void SockCloseSslLogging(SOCK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (s->IsSslLoggingEnabled == false)
	{
		return;
	}

	s->IsSslLoggingEnabled = false;

	FileClose(s->SslLogging_Recv);
	s->SslLogging_Recv = NULL;

	FileClose(s->SslLogging_Send);
	s->SslLogging_Send = NULL;

	DeleteLock(s->SslLogging_Lock);
	s->SslLogging_Lock = NULL;
}

// Write SSL log
void SockWriteSslLog(SOCK *s, void *send_data, UINT send_size, void *recv_data, UINT recv_size)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (s->IsSslLoggingEnabled == false)
	{
		return;
	}

	Lock(s->SslLogging_Lock);
	{
		if (s->SslLogging_Send != NULL)
		{
			if (send_size >= 1 && send_data != NULL)
			{
				FileWrite(s->SslLogging_Send, send_data, send_size);
			}
		}

		if (s->SslLogging_Recv != NULL)
		{
			if (recv_size >= 1 && recv_data != NULL)
			{
				FileWrite(s->SslLogging_Recv, recv_data, recv_size);
			}
		}
	}
	Unlock(s->SslLogging_Lock);
}

#endif	// ENABLE_SSL_LOGGING

// Set the flag to indicate that the socket doesn't require reading
void SetNoNeedToRead(SOCK *sock)
{
	// Validate arguments
	if (sock == NULL)
	{
		return;
	}

	sock->NoNeedToRead = true;
}

// TCP-SSL receive
UINT SecureRecv(SOCK *sock, void *data, UINT size)
{
	SOCKET s;
	int ret, e = 0;
	SSL *ssl;

#ifdef UNIX_SOLARIS
	SOCKET_TIMEOUT_PARAM *ttparam;
#endif //UNIX_SOLARIS

	s = sock->socket;
	ssl = sock->ssl;

	if (sock->AsyncMode)
	{
		// Confirm whether the data is readable even 1 byte in the case of asynchronous mode.
		// To read data results blocking, if there is no readable data.
		// We must avoid blocking.
		char c;
		Lock(sock->ssl_lock);
		{
			if (sock->Connected == false)
			{
				Unlock(sock->ssl_lock);
				Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
				return 0;
			}
			ret = SSL_peek(ssl, &c, sizeof(c));
		}
		Unlock(sock->ssl_lock);
		if (ret == 0)
		{
			// The communication have been disconnected
			Disconnect(sock);
			Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
			return 0;
		}
		if (ret < 0)
		{
			// An error has occurred
			e = SSL_get_error(ssl, ret);
			if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL)
			{
				if (e == SSL_ERROR_SSL &&
					sock->ssl->s3->send_alert[0] == SSL3_AL_FATAL &&
					sock->ssl->s3->send_alert[0] != sock->Ssl_Init_Async_SendAlert[0] &&
					sock->ssl->s3->send_alert[1] != sock->Ssl_Init_Async_SendAlert[1])
				{
					Debug("%s %u SSL Fatal Error on ASYNC socket !!!\n", __FILE__, __LINE__);
					Disconnect(sock);
					return 0;
				}
				// Packet has not arrived yet, that is not to be read
				return SOCK_LATER;
			}
		}
	}

	// Receive
	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false)
		{
			Unlock(sock->ssl_lock);
			Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
			return 0;
		}

#ifdef	OS_UNIX
		if (sock->AsyncMode == false)
		{
			sock->CallingThread = pthread_self();
		}
#endif	// OS_UNIX

// Run the time-out thread for SOLARIS
#ifdef UNIX_SOLARIS
		ttparam = NewSocketTimeout(sock);
#endif // UNIX_SOLARIS

		ret = SSL_read(ssl, data, size);

// Stop the timeout thread
#ifdef UNIX_SOLARIS
		FreeSocketTimeout(ttparam);
#endif // UNIX_SOLARIS


#ifdef	OS_UNIX
		if (sock->AsyncMode == false)
		{
			sock->CallingThread = 0;
		}
#endif	// OS_UNIX

		if (ret < 0)
		{
			e = SSL_get_error(ssl, ret);
		}

	}
	Unlock(sock->ssl_lock);

#ifdef	ENABLE_SSL_LOGGING
	if (ret > 0)
	{
		SockWriteSslLog(sock, NULL, 0, data, ret);
	}
#endif	// ENABLE_SSL_LOGGING

	if (ret > 0)
	{
		// Successful reception
		sock->RecvSize += (UINT64)ret;
		sock->RecvNum++;

		return (UINT)ret;
	}
	if (ret == 0)
	{
		// Disconnect the communication
		Disconnect(sock);
		//Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
		return 0;
	}
	if (sock->AsyncMode)
	{
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL)
		{
			if (e == SSL_ERROR_SSL &&
				sock->ssl->s3->send_alert[0] == SSL3_AL_FATAL &&
				sock->ssl->s3->send_alert[0] != sock->Ssl_Init_Async_SendAlert[0] &&
				sock->ssl->s3->send_alert[1] != sock->Ssl_Init_Async_SendAlert[1])
			{
				Debug("%s %u SSL Fatal Error on ASYNC socket !!!\n", __FILE__, __LINE__);
				Disconnect(sock);
				return 0;
			}

			// Packet has not yet arrived
			return SOCK_LATER;
		}
	}
	Disconnect(sock);
	Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
	return 0;
}

// TCP-SSL transmission
UINT SecureSend(SOCK *sock, void *data, UINT size)
{
	SOCKET s;
	int ret, e;
	SSL *ssl;
	s = sock->socket;
	ssl = sock->ssl;

	if (sock->AsyncMode)
	{
		// Asynchronous mode
		SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
	}

	// Transmission
	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false)
		{
			Unlock(sock->ssl_lock);
			Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
			return 0;
		}

		ret = SSL_write(ssl, data, size);
		if (ret < 0)
		{
			e = SSL_get_error(ssl, ret);
		}
	}
	Unlock(sock->ssl_lock);

#ifdef	ENABLE_SSL_LOGGING
	if (ret > 0)
	{
		SockWriteSslLog(sock, data, ret, NULL, 0);
	}
#endif	// ENABLE_SSL_LOGGING

	if (ret > 0)
	{
		// Successful transmission
		sock->SendSize += (UINT64)ret;
		sock->SendNum++;
		sock->WriteBlocked = false;
		return (UINT)ret;
	}
	if (ret == 0)
	{
		// Disconnect
		Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
		Disconnect(sock);
		return 0;
	}

	if (sock->AsyncMode)
	{
		// Confirmation of the error value
		if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL)
		{
			sock->WriteBlocked = true;
			return SOCK_LATER;
		}
		Debug("%s %u e=%u\n", __FILE__, __LINE__, e);
	}
	//Debug("%s %u SecureRecv() Disconnect\n", __FILE__, __LINE__);
	Disconnect(sock);
	return 0;
}

// Peep the TCP
UINT Peek(SOCK *sock, void *data, UINT size)
{
	SOCKET s;
	int ret;

	// Validate arguments
	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	if (sock->Type == SOCK_INPROC)
	{
		return 0;
	}
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
		sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (sock->AsyncMode)
	{
		return 0;
	}

	// Receive
	s = sock->socket;

	ret = recv(s, data, size, MSG_PEEK);

	//Debug("Peek: %u\n", ret);

	if (ret > 0)
	{
		return ret;
	}

	return 0;
}

// TCP receive
UINT Recv(SOCK *sock, void *data, UINT size, bool secure)
{
	SOCKET s;
	int ret;

#ifdef UNIX_SOLARIS
	SOCKET_TIMEOUT_PARAM *ttparam;
#endif //UNIX_SOLARIS

	// Validate arguments
	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}

	sock->NoNeedToRead = false;

	if (sock->Type == SOCK_INPROC)
	{
		return RecvInProc(sock, data, size);
	}
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
		sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (secure != false && sock->SecureMode == false)
	{
		return 0;
	}

	if (secure)
	{
		return SecureRecv(sock, data, size);
	}

	// Receive
	s = sock->socket;


#ifdef	OS_UNIX
	if (sock->AsyncMode == false)
	{
		sock->CallingThread = pthread_self();
	}
#endif	// OS_UNIX

// Start of the timeout thread for SOLARIS
#ifdef UNIX_SOLARIS
	ttparam = NewSocketTimeout(sock);
#endif // UNIX_SOLARIS

	ret = recv(s, data, size, 0);

// Stop the timeout thread
#ifdef UNIX_SOLARIS
	FreeSocketTimeout(ttparam);
#endif // UNIX_SOLARIS

#ifdef	OS_UNIX
	if (sock->AsyncMode == false)
	{
		sock->CallingThread = 0;
	}
#endif	// OS_UNIX

	if (ret > 0)
	{
		// Successful reception
		Lock(sock->lock);
		{
			sock->RecvSize += (UINT64)ret;
			sock->SendNum++;
		}
		Unlock(sock->lock);
		return (UINT)ret;
	}

	// Transmission failure
	if (sock->AsyncMode)
	{
		// In asynchronous mode, examine the error
		if (ret == SOCKET_ERROR)
		{
#ifdef	OS_WIN32
			if (WSAGetLastError() == WSAEWOULDBLOCK)
			{
				// In blocking
				return SOCK_LATER;
			}
			else
			{
				//Debug("Socket Error: %u\n", WSAGetLastError());
			}
#else	// OS_WIN32
			if (errno == EAGAIN)
			{
				// In blocking
				return SOCK_LATER;
			}
#endif	// OS_WIN32
		}
	}

	// Disconnected
	Disconnect(sock);
	return 0;
}

// TCP transmission
UINT Send(SOCK *sock, void *data, UINT size, bool secure)
{
	SOCKET s;
	int ret;
	// Validate arguments
	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	if (sock->Type == SOCK_INPROC)
	{
		return SendInProc(sock, data, size);
	}
	size = MIN(size, MAX_SEND_BUF_MEM_SIZE);
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
		sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (secure != false && sock->SecureMode == false)
	{
		return 0;
	}

	if (secure)
	{
		return SecureSend(sock, data, size);
	}

	// Transmission
	s = sock->socket;
	ret = send(s, data, size, 0);
	if (ret > 0)
	{
		// Successful transmission
		Lock(sock->lock);
		{
			sock->SendSize += (UINT64)ret;
			sock->SendNum++;
		}
		Unlock(sock->lock);
		sock->WriteBlocked = false;
		return (UINT)ret;
	}

	// Transmission failure
	if (sock->AsyncMode)
	{
		// In asynchronous mode, examine the error
		if (ret == SOCKET_ERROR)
		{
#ifdef	OS_WIN32
			if (WSAGetLastError() == WSAEWOULDBLOCK)
			{
				// In blocking
				sock->WriteBlocked = true;
				return SOCK_LATER;
			}
			else
			{
				//Debug("Socket Error: %u\n", WSAGetLastError());
			}
#else	// OS_WIN32
			if (errno == EAGAIN)
			{
				// In blocking
				sock->WriteBlocked = true;
				return SOCK_LATER;
			}
#endif	// OS_WIN32
		}
	}

	// Disconnected
	Disconnect(sock);
	return 0;
}

// Get the time-out value (in milliseconds)
UINT GetTimeout(SOCK *sock)
{
	// Validate arguments
	if (sock == NULL)
	{
		return INFINITE;
	}
	if (sock->Type != SOCK_TCP && sock->Type != SOCK_INPROC)
	{
		return INFINITE;
	}

	return sock->TimeOut;
}

// Setting the time-out value (in milliseconds)
void SetTimeout(SOCK *sock, UINT timeout)
{
	// Validate arguments
	if (sock == NULL)
	{
		return;
	}
	if (sock->Type == SOCK_UDP)
	{
		return;
	}

	if (timeout == INFINITE)
	{
		timeout = TIMEOUT_INFINITE;
	}

	sock->TimeOut = timeout;

//	Debug("SetTimeout(%u)\n",timeout);

	if (sock->Type != SOCK_INPROC)
	{
#ifdef OS_WIN32
		setsockopt(sock->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(UINT));
		setsockopt(sock->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(UINT));
#endif

#ifdef OS_UNIX
#ifndef UNIX_SOLARIS
		{
			struct timeval tv_timeout;

			tv_timeout.tv_sec = timeout / 1000; // miliseconds to seconds
			tv_timeout.tv_usec = (timeout % 1000) * 1000; // miliseconds to microseconds

			setsockopt(sock->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv_timeout, sizeof(tv_timeout));
			setsockopt(sock->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv_timeout, sizeof(tv_timeout));
		}
#endif // UNIX_SOLARIS
#endif // OS_UNIX
	}
}

// Disable GetHostName call by accepting new TCP connection
void DisableGetHostNameWhenAcceptInit()
{
	disable_gethostname_by_accept = true;
}

// Initialize the connection acceptance
void AcceptInit(SOCK *s)
{
	AcceptInitEx(s, false);
}
void AcceptInitEx(SOCK *s, bool no_lookup_hostname)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Zero(tmp, sizeof(tmp));

	if (disable_gethostname_by_accept == false && no_lookup_hostname == false)
	{
		if (GetHostName(tmp, sizeof(tmp), &s->RemoteIP) == false ||
			IsEmptyStr(tmp))
		{
			IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
		}
	}
	else
	{
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	}

	if (s->RemoteHostname != NULL)
	{
		Free(s->RemoteHostname);
	}

	s->RemoteHostname = CopyStr(tmp);
}

// TCP connection acceptance (IPv4)
SOCK *Accept(SOCK *sock)
{
	SOCK *ret;
	SOCKET s, new_socket;
	int size;
	struct sockaddr_in addr;
	bool true_flag = true;
	// Validate arguments
	if (sock == NULL)
	{
		return NULL;
	}
	if (sock->Type == SOCK_INPROC)
	{
		return AcceptInProc(sock);
	}
	if (sock->Type == SOCK_REVERSE_LISTEN)
	{
		return AcceptReverse(sock);
	}
	if (sock->Type == SOCK_RUDP_LISTEN)
	{
		return AcceptRUDP(sock);
	}
	if (sock->ListenMode == false || sock->Type != SOCK_TCP || sock->ServerMode == false)
	{
		return NULL;
	}
	if (sock->CancelAccept)
	{
		return NULL;
	}
	if (sock->IPv6)
	{
		return Accept6(sock);
	}

	s = sock->socket;
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}
	Zero(&addr, sizeof(addr));
	size = sizeof(addr);

#ifdef	OS_UNIX
#if	defined(UNIX_LINUX) || defined(UNIX_MACOS)
	UnixIgnoreSignalForThread(SIGUSR1);
#endif	// defined(UNIX_LINUX) || defined(UNIX_MACOS)
	sock->CallingThread = pthread_self();
#endif	// OS_UNIX

#ifdef	OS_WIN32
	if (sock->EnableConditionalAccept)
	{
		new_socket = Win32Accept(sock, s, (struct sockaddr *)&addr,(int *)&size, false);
	}
	else
	{
		new_socket = accept(s, (struct sockaddr *)&addr,(int *)&size);
	}
#else	// OS_WIN32
	new_socket = accept(s, (struct sockaddr *)&addr,(int *)&size);
#endif	// OS_WIN32

#ifdef	OS_UNIX
	sock->CallingThread = 0;
#endif	// OS_UNIX

	if (new_socket == INVALID_SOCKET)
	{
		if (sock->CancelAccept)
		{
			sock->AcceptCanceled = true;
		}
		return NULL;
	}
	if (sock->CancelAccept)
	{
		sock->AcceptCanceled = true;
		closesocket(new_socket);
		return NULL;
	}

	ret = NewSock();
	ret->socket = new_socket;
	ret->Connected = true;
	ret->AsyncMode = false;
	ret->Type = SOCK_TCP;
	ret->ServerMode = true;
	ret->SecureMode = false;

	// Configuring the TCP options
	setsockopt(ret->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(bool));

	// Initialization of the time-out value
	SetTimeout(ret, TIMEOUT_INFINITE);

	// Socket information
	QuerySocketInformation(ret);

	if (IsLocalHostIP(&ret->RemoteIP) == false)
	{
		ret->IpClientAdded = true;
		AddIpClient(&ret->RemoteIP);
	}

	if (IsZeroIp(&sock->LocalIP) == false && IsLocalHostIP(&sock->LocalIP) == false)
	{
		IP current_ip;

		if (GetCurrentGlobalIP(&current_ip, false) == false)
		{
			SetCurrentGlobalIP(&sock->LocalIP, false);
		}
	}

	StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), SOCK_UNDERLAY_NATIVE_V4);

	return ret;
}

// TCP connection acceptance (IPv6)
SOCK *Accept6(SOCK *sock)
{
	SOCK *ret;
	SOCKET s, new_socket;
	int size;
	struct sockaddr_in6 addr;
	bool true_flag = true;
	// Validate arguments
	if (sock == NULL)
	{
		return NULL;
	}
	if (sock->ListenMode == false || sock->Type != SOCK_TCP || sock->ServerMode == false)
	{
		return NULL;
	}
	if (sock->CancelAccept)
	{
		return NULL;
	}
	if (sock->IPv6 == false)
	{
		return NULL;
	}

	s = sock->socket;
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}
	Zero(&addr, sizeof(addr));
	size = sizeof(addr);

#ifdef	OS_UNIX
#if	defined(UNIX_LINUX) || defined(UNIX_MACOS)
	UnixIgnoreSignalForThread(SIGUSR1);
#endif	// defined(UNIX_LINUX) || defined(UNIX_MACOS)
	sock->CallingThread = pthread_self();
#endif	// OS_UNIX

#ifdef	OS_WIN32
	if (sock->EnableConditionalAccept)
	{
		new_socket = Win32Accept(sock, s, (struct sockaddr *)&addr,(int *)&size, true);
	}
	else
	{
		new_socket = accept(s, (struct sockaddr *)&addr,(int *)&size);
	}
#else	// OS_WIN32
	new_socket = accept(s, (struct sockaddr *)&addr,(int *)&size);
#endif	// OS_WIN32

#ifdef	OS_UNIX
	sock->CallingThread = 0;
#endif	// OS_UNIX

	if (new_socket == INVALID_SOCKET)
	{
		if (sock->CancelAccept)
		{
			sock->AcceptCanceled = true;
		}
		return NULL;
	}
	if (sock->CancelAccept)
	{
		sock->AcceptCanceled = true;
		closesocket(new_socket);
		return NULL;
	}

	ret = NewSock();
	ret->socket = new_socket;
	ret->Connected = true;
	ret->AsyncMode = false;
	ret->Type = SOCK_TCP;
	ret->ServerMode = true;
	ret->SecureMode = false;

	// Configuring the TCP options
	setsockopt(ret->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(bool));

	// Initialize the time-out value
	SetTimeout(ret, TIMEOUT_INFINITE);

	// Socket information
	QuerySocketInformation(ret);

	if (IsLocalHostIP(&ret->RemoteIP) == false)
	{
		ret->IpClientAdded = true;
		AddIpClient(&ret->RemoteIP);
	}
	if (IsZeroIp(&sock->LocalIP) == false && IsLocalHostIP(&sock->LocalIP) == false)
	{
		IP current_ip;

		if (GetCurrentGlobalIP(&current_ip, true) == false)
		{
			SetCurrentGlobalIP(&sock->LocalIP, true);
		}
	}

	StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), SOCK_UNDERLAY_NATIVE_V6);

	return ret;
}

// Standby for TCP (IPv6)
SOCK *Listen6(UINT port)
{
	return ListenEx6(port, false);
}
SOCK *ListenEx6(UINT port, bool local_only)
{
	return ListenEx62(port, local_only, false);
}
SOCK *ListenEx62(UINT port, bool local_only, bool enable_ca)
{
	SOCKET s;
	SOCK *sock;
	struct sockaddr_in6 addr;
	struct in6_addr in;
	bool true_flag = true;
	bool disable_conditional_accept = false;
	IP localhost;
	UINT backlog = SOMAXCONN;
	// Validate arguments
	if (port == 0 || port >= 65536)
	{
		return NULL;
	}

#ifdef	OS_WIN32
	if (MsIsVista() == false)
	{
		// Disable the Conditional Accept due to a bug in Windows
		enable_ca = false;
	}
#endif	// OS_WIN32

	// Initialization
	Zero(&addr, sizeof(addr));
	Zero(&in, sizeof(in));
	GetLocalHostIP6(&localhost);

	addr.sin6_port = htons((UINT)port);
	addr.sin6_family = AF_INET6;

	if (local_only)
	{
		IPToInAddr6(&addr.sin6_addr, &localhost);

		enable_ca = false;
	}

	// Creating a socket
	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

#ifdef	OS_UNIX
	// It is necessary to set the IPv6 Only flag on a UNIX system
	setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &true_flag, sizeof(true_flag));
#endif	// OS_UNIX

	//SetSocketSendRecvBufferSize(s, SOCKET_BUFFER_SIZE);

#ifdef	OS_UNIX
	// This only have enabled for UNIX system since there is a bug
	// in the implementation of REUSEADDR in Windows OS
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(bool));
#endif	// OS_UNIX

	if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) != 0)
	{
		// Bind failure
		closesocket(s);
		return NULL;
	}

#ifdef	OS_WIN32
	if (enable_ca)
	{
		if (MsIsWinXPOrGreater())
		{
			setsockopt(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (char *)&true_flag, sizeof(bool));

			backlog = 1;
		}
	}
#endif	// OS_WIN32

	if (listen(s, backlog))
	{
		// Listen failure
		closesocket(s);
		return NULL;
	}

	// Success
	sock = NewSock();
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = true;
	sock->Type = SOCK_TCP;
	sock->socket = s;
	sock->ListenMode = true;
	sock->SecureMode = false;
	sock->LocalPort = port;
	sock->IPv6 = true;
	sock->LocalOnly = local_only;
	sock->EnableConditionalAccept = enable_ca;

	return sock;
}

// Standby for the TCP
SOCK *Listen(UINT port)
{
	return ListenEx(port, false);
}
SOCK *ListenEx(UINT port, bool local_only)
{
	return ListenEx2(port, local_only, false);
}
SOCK *ListenEx2(UINT port, bool local_only, bool enable_ca)
{
	SOCKET s;
	SOCK *sock;
	struct sockaddr_in addr;
	struct in_addr in;
	bool true_flag = true;
	IP localhost;
	UINT backlog = SOMAXCONN;
	// Validate arguments
	if (port == 0 || port >= 65536)
	{
		return NULL;
	}

#ifdef	OS_WIN32
	if (MsIsVista() == false)
	{
		// Disable the Conditional Accept due to a bug in Windows
		enable_ca = false;
	}
#endif	// OS_WIN32

	// Initialization
	Zero(&addr, sizeof(addr));
	Zero(&in, sizeof(in));
	SetIP(&localhost, 127, 0, 0, 1);

	addr.sin_port = htons((UINT)port);
	*((UINT *)&addr.sin_addr) = htonl(INADDR_ANY);
	addr.sin_family = AF_INET;

	if (local_only)
	{
		IPToInAddr(&addr.sin_addr, &localhost);

		enable_ca = false;
	}

	// Creating a socket
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	//SetSocketSendRecvBufferSize(s, SOCKET_BUFFER_SIZE);

#ifdef	OS_UNIX
	// This only have enabled for UNIX system since there is a bug
	// in the implementation of REUSEADDR in Windows OS
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(bool));
#endif	// OS_UNIX

	if (bind(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != 0)
	{
		// Bind failure
		closesocket(s);
		return NULL;
	}

#ifdef	OS_WIN32
	if (enable_ca)
	{
		if (MsIsWinXPOrGreater())
		{
			setsockopt(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (char *)&true_flag, sizeof(bool));

			backlog = 1;
		}
	}
#endif	// OS_WIN32

	if (listen(s, backlog))
	{
		// Listen failure
		closesocket(s);
		return NULL;
	}

	// Success
	sock = NewSock();
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = true;
	sock->Type = SOCK_TCP;
	sock->socket = s;
	sock->ListenMode = true;
	sock->SecureMode = false;
	sock->LocalPort = port;
	sock->LocalOnly = local_only;
	sock->EnableConditionalAccept = enable_ca;

	return sock;
}

// TCP disconnect
void Disconnect(SOCK *sock)
{
	SOCKET s;
	bool true_flag = true;
	bool false_flag = false;
	// Validate arguments
	if (sock == NULL)
	{
		return;
	}

	sock->Disconnecting = true;

#ifdef	ENABLE_SSL_LOGGING
	SockCloseSslLogging(sock);
#endif	// ENABLE_SSL_LOGGING

#ifdef	OS_UNIX
	UnixFreeAsyncSocket(sock);
#endif	// UnixFreeAsyncSocket

	if (sock->Type == SOCK_TCP && sock->ListenMode)
	{
		bool no_tcp_check_port = false;

		// Connect to localhost if the socket is in listening
		sock->CancelAccept = true;

#if	defined(UNIX_LINUX) || defined(UNIX_MACOS)
		{
			pthread_t t = sock->CallingThread;

			// Send a signal to the socket to abort accept() forcibly on Linux
			if (t != 0)
			{
				pthread_kill(t, SIGUSR1);

				SleepThread(200);
			}
		}
#endif	// defined(UNIX_LINUX) || defined(UNIX_MACOS)

#ifdef	OS_WIN32
		if (sock->hAcceptEvent != NULL)
		{
			SetEvent(sock->hAcceptEvent);

			no_tcp_check_port = true;
		}
#endif	// OS_WIN32

		if (sock->AcceptCanceled == false)
		{
			if (no_tcp_check_port == false)
			{
				if (sock->IPv6 == false)
				{
					CheckTCPPort("127.0.0.1", sock->LocalPort);
				}
				else
				{
					CheckTCPPort("::1", sock->LocalPort);
				}
			}
		}
	}

	Lock(disconnect_function_lock);

	Lock(sock->disconnect_lock);

	if (sock->Type == SOCK_TCP)
	{
		if (sock->socket != INVALID_SOCKET)
		{
			// Forced disconnection flag
			#ifdef	SO_DONTLINGER
				setsockopt(sock->socket, SOL_SOCKET, SO_DONTLINGER, (char *)&true_flag, sizeof(bool));
			#else	// SO_DONTLINGER
				setsockopt(sock->socket, SOL_SOCKET, SO_LINGER, (char *)&false_flag, sizeof(bool));
			#endif	// SO_DONTLINGER
//			setsockopt(sock->socket, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(bool));
		}

		// TCP socket
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET)
			{
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				Unlock(disconnect_function_lock);
				return;
			}
			s = sock->socket;

			if (sock->Connected)
			{
				struct linger ling;
				Zero(&ling, sizeof(ling));


#if	0
				// SSL disconnect
				Lock(sock->ssl_lock);
				{
					if (sock->SecureMode)
					{
						SSL_shutdown(sock->ssl);
					}
				}
				Unlock(sock->ssl_lock);
#endif
				// Disconnect
				shutdown(s, 2);
			}

			// Close the socket
			closesocket(s);

#ifdef	OS_UNIX
#ifdef	FIX_SSL_BLOCKING
			if (sock->CallingThread != NULL)
			{
				pthread_kill(sock->CallingThread, 64);
			}
#endif	// FIX_SSL_BLOCKING
#endif	// OS_UNIX

			// Release the SSL
			Lock(sock->ssl_lock);
			{
				if (sock->SecureMode)
				{
					if (sock->ssl != NULL)
					{
						Lock(openssl_lock);
						{
							SSL_free(sock->ssl);
							FreeSSLCtx(sock->ssl_ctx);
						}
						Unlock(openssl_lock);
						sock->ssl = NULL;
						sock->ssl_ctx = NULL;
					}
					sock->Connected = false;
					sock->SecureMode = false;
				}
			}
			Unlock(sock->ssl_lock);

			// Initialization
			sock->socket = INVALID_SOCKET;
			sock->Type = 0;
			sock->AsyncMode = false;
			sock->Connected = false;
			sock->ListenMode = false;
			sock->SecureMode = false;

			if (sock->IpClientAdded)
			{
				DelIpClient(&sock->RemoteIP);
				sock->IpClientAdded = false;
			}
		}
		Unlock(sock->lock);

		if (sock->BulkSendTube != NULL)
		{
			TubeDisconnect(sock->BulkSendTube);
		}

		if (sock->BulkRecvTube != NULL)
		{
			TubeDisconnect(sock->BulkRecvTube);
		}
	}
	else if (sock->Type == SOCK_UDP)
	{
		// UDP socket
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET)
			{
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				Unlock(disconnect_function_lock);
				return;
			}

			s = sock->socket;

			// Close the socket
			closesocket(s);

			// Initialization
			sock->socket = INVALID_SOCKET;
			sock->Type = 0;
			sock->AsyncMode = false;
			sock->Connected = false;
			sock->ListenMode = false;
			sock->SecureMode = false;
		}
		Unlock(sock->lock);
	}
	else if (sock->Type == SOCK_INPROC)
	{
		// In-process socket
		if (sock->ListenMode)
		{
			// Stop the Accept process
			sock->CancelAccept = true;

			Set(sock->InProcAcceptEvent);

			LockQueue(sock->InProcAcceptQueue);
			{
				while (true)
				{
					SOCK *ss = GetNext(sock->InProcAcceptQueue);
					if (ss == NULL)
					{
						break;
					}

					Disconnect(ss);
					ReleaseSock(ss);
				}
			}
			UnlockQueue(sock->InProcAcceptQueue);
		}
		else
		{
			// Disconnect the Tube
			TubeDisconnect(sock->SendTube);
			TubeDisconnect(sock->RecvTube);

			sock->socket = INVALID_SOCKET;
			sock->AsyncMode = false;
			sock->Connected = false;
			sock->ListenMode = false;
			sock->SecureMode = false;
		}
	}
	else if (sock->Type == SOCK_RUDP_LISTEN)
	{
		// RUDP Listen socket
		if (sock->ListenMode)
		{
			// Stop the Accept process
			sock->CancelAccept = true;

			Set(sock->R_UDP_Stack->NewSockConnectEvent);

			sock->R_UDP_Stack->Halt = true;
			Set(sock->R_UDP_Stack->HaltEvent);
			SetSockEvent(sock->R_UDP_Stack->SockEvent);
		}
	}
	else if (sock->Type == SOCK_REVERSE_LISTEN)
	{
		// Reverse Listen socket
		if (sock->ListenMode)
		{
			// Stop the Accept process
			sock->CancelAccept = true;

			Set(sock->ReverseAcceptEvent);

			LockQueue(sock->ReverseAcceptQueue);
			{
				while (true)
				{
					SOCK *ss = GetNext(sock->ReverseAcceptQueue);
					if (ss == NULL)
					{
						break;
					}

					Disconnect(ss);
					ReleaseSock(ss);
				}
			}
			UnlockQueue(sock->ReverseAcceptQueue);
		}
	}
	Unlock(sock->disconnect_lock);

	Unlock(disconnect_function_lock);
}

typedef struct TCP_PORT_CHECK
{
	REF *ref;
	char hostname[MAX_SIZE];
	UINT port;
	bool ok;
} TCP_PORT_CHECK;

// The thread to check the TCP port
void CheckTCPPortThread(THREAD *thread, void *param)
{
	TCP_PORT_CHECK *c;
	SOCK *s;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	c = (TCP_PORT_CHECK *)param;
	AddRef(c->ref);
	NoticeThreadInit(thread);

	AddWaitThread(thread);

	s = Connect(c->hostname, c->port);
	if (s != NULL)
	{
		c->ok = true;
		Disconnect(s);
		ReleaseSock(s);
	}

	if (Release(c->ref) == 0)
	{
		Free(c);
	}

	DelWaitThread(thread);
}

// Check whether the TCP port can be connected
bool CheckTCPPortEx(char *hostname, UINT port, UINT timeout)
{
	SOCK *s;
	// Validate arguments
	if (hostname == NULL || port == 0 || port >= 65536)
	{
		return false;
	}

	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}

	s = ConnectEx(hostname, port, timeout);
	if (s == NULL)
	{
		return false;
	}
	else
	{
		Disconnect(s);
		ReleaseSock(s);
		return true;
	}
}
bool CheckTCPPort(char *hostname, UINT port)
{
	return CheckTCPPortEx(hostname, port, TIMEOUT_TCP_PORT_CHECK);
}

#ifdef	OS_UNIX
// Connection with timeout (UNIX version)
int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag)
{
	SOCKSET set;
	bool ok = false;
	UINT64 start_time;
	// Validate arguments
	if (s == INVALID_SOCKET || addr == NULL)
	{
		return -1;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}

	UnixSetSocketNonBlockingMode(s, true);

	start_time = Tick64();

	while (true)
	{
		int ret;
		ret = connect(s, addr, size);
		if (ret == 0 || errno == EISCONN)
		{
			ok = true;
			break;
		}
		else
		{
			if (((start_time + (UINT64)timeout) <= Tick64()) || (errno != EAGAIN && errno != EINPROGRESS && errno != EALREADY))
			{
				// Failure
				break;
			}
			else if (*cancel_flag)
			{
				// Cancel
				break;
			}
			else
			{
				// Connecting
				SleepThread(50);
				UnixSelectInner(1, (UINT *)&s, 1, (UINT *)&s, 100);
			}
		}
	}

	UnixSetSocketNonBlockingMode(s, false);

	if (ok)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}
#else
// Connection with timeout (Win32 version)
int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag)
{
	UINT64 start_time;
	bool ok = false;
	bool timeouted = false;
	WSAEVENT hEvent;
	UINT zero = 0;
	UINT tmp = 0;
	UINT ret_size = 0;
	bool is_nt = false;
	// Validate arguments
	if (s == INVALID_SOCKET || addr == NULL)
	{
		return -1;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}

	is_nt = OS_IS_WINDOWS_NT(GetOsInfo()->OsType);

	// Create an event
	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	// Associate the socket with the event
	WSAEventSelect(s, hEvent, FD_CONNECT);

	start_time = Tick64();

	while (true)
	{
		int ret;
		
		ret = connect(s, addr, size);

		if (ret == 0)
		{
			ok = true;
			break;
		}
		else
		{
			int err = WSAGetLastError();
			//Debug("err=%u\n", err);
			//Debug("cancel_flag=%u\n", *cancel_flag);
			if (timeouted && ((err == WSAEALREADY) || (err == WSAEWOULDBLOCK && !is_nt)))
			{
				// Time-out
				ok = false;
				break;
			}
			if (*cancel_flag)
			{
				// Cancel
				ok = false;
				break;
			}
			if (err == WSAEISCONN || (err == WSAEINVAL && is_nt))
			{
				ok = true;
				break;
			}
			if (((start_time + (UINT64)timeout) <= Tick64()) || (err != WSAEWOULDBLOCK && err != WSAEALREADY && (is_nt || err != WSAEINVAL)))
			{
				// Failure (timeout)
				break;
			}
			else
			{
				SleepThread(10);
				// Connecting
				if (WaitForSingleObject(hEvent, 100) == WAIT_OBJECT_0)
				{
					timeouted = true;
				}
			}
		}
	}

	// Remove the socket from the event
	WSAEventSelect(s, hEvent, 0);

	// Restore to synchronized socket
	WSAIoctl(s, FIONBIO, &zero, sizeof(zero), &tmp, sizeof(tmp), &ret_size, NULL, NULL);

	// Close the event
	CloseHandle(hEvent);

	if (ok)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}
#endif	// OS_UNIX

// Set the TOS value of the socket
void SetSockTos(SOCK *s, int tos)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (s->CurrentTos == tos)
	{
		return;
	}

#ifdef	IP_TOS
	setsockopt(s->socket, IPPROTO_IP, IP_TOS, (char *)&tos, sizeof(int));
#endif	// IP_TOS

	s->CurrentTos = tos;
}

// Set the priority of the socket
void SetSockHighPriority(SOCK *s, bool flag)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	SetSockTos(s, (flag ? 16 : 0));
}

// Connect to the IPv4 host using a socket
SOCKET ConnectTimeoutIPv4(IP *ip, UINT port, UINT timeout, bool *cancel_flag)
{
	SOCKET s;
	struct sockaddr_in sockaddr4;
	struct in_addr addr4;

	Zero(&sockaddr4, sizeof(sockaddr4));
	Zero(&addr4, sizeof(addr4));

	// Generate a sockaddr_in
	IPToInAddr(&addr4, ip);
	sockaddr4.sin_port = htons((USHORT)port);
	sockaddr4.sin_family = AF_INET;
	sockaddr4.sin_addr.s_addr = addr4.s_addr;

	// Socket creation
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s != INVALID_SOCKET)
	{
		// Connection
		if (connect_timeout(s, (struct sockaddr *)&sockaddr4, sizeof(struct sockaddr_in), timeout, cancel_flag) != 0)
		{
			// Connection failure
			closesocket(s);
			s = INVALID_SOCKET;
		}
	}

	return s;
}

// Identify whether the HTTPS server to be connected is a SoftEther VPN
bool DetectIsServerSoftEtherVPN(SOCK *s)
{
	HTTP_HEADER *h;
	char ip_str[MAX_SIZE];
	char *send_str;
	UINT content_len;
	BUF *recv_buf;
	void *socket_buffer;
	UINT socket_buffer_size = 32768;
	bool ok = false;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	// Request generation
	h = NewHttpHeaderEx("GET", "/", "HTTP/1.1", true);
	AddHttpValue(h, NewHttpValue("X-VPN", "1"));
	AddHttpValue(h, NewHttpValue("Host", ip_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Accept-Language", "ja"));
	AddHttpValue(h, NewHttpValue("User-Agent", DEFAULT_USER_AGENT));
	AddHttpValue(h, NewHttpValue("Pragma", "no-cache"));
	AddHttpValue(h, NewHttpValue("Cache-Control", "no-cache"));



	send_str = HttpHeaderToStr(h);
	FreeHttpHeader(h);

	// Transmission
	if (SendAll(s, send_str, StrLen(send_str), true) == false)
	{
		Free(send_str);
		return false;
	}

	Free(send_str);

	// Receive
	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		return false;
	}

	// Get the length of the content
	content_len = GetContentLength(h);
	FreeHttpHeader(h);

	if (content_len == 0 || content_len >= (1024 * 1024))
	{
		return false;
	}

	// Receive contents
	recv_buf = NewBuf();
	socket_buffer = Malloc(socket_buffer_size);

	while (true)
	{
		UINT recvsize = MIN(socket_buffer_size, content_len - recv_buf->Size);
		UINT size;

		if (recvsize == 0)
		{
			ok = true;
			break;
		}

		size = Recv(s, socket_buffer, recvsize, true);
		if (size == 0)
		{
			// Disconnected
			break;
		}

		WriteBuf(recv_buf, socket_buffer, size);
	}

	SeekBuf(recv_buf, 0, 0);
	Free(socket_buffer);

	if (ok)
	{
		// Examine to confirm whether the incoming data is a SoftEther VPN protocol
		char tmp[1024];

		Zero(tmp, sizeof(tmp));

		Copy(tmp, recv_buf->Buf, MIN(recv_buf->Size, (sizeof(tmp) - 1)));

		ok = false;

		if (StartWith(tmp, http_detect_server_startwith))
		{
			ok = true;
		}
		else if (InStr(tmp, http_detect_server_tag_future))
		{
			ok = true;
		}
	}

	FreeBuf(recv_buf);

	return ok;
}

// TCP connection thread
void ConnectThreadForTcp(THREAD *thread, void *param)
{
	SOCK *sock;
	char hostname[MAX_SIZE];
	CONNECT_TCP_RUDP_PARAM *p = (CONNECT_TCP_RUDP_PARAM *)param;
	if (thread == NULL || p == NULL)
	{
		return;
	}

	// Delay
	if (p->Delay >= 1)
	{
		WaitEx(NULL, p->Delay, p->CancelFlag);
	}

	// Connecting process
	IPToStr(hostname, sizeof(hostname), &p->Ip);
	sock = ConnectEx3(hostname, p->Port, p->Timeout, p->CancelFlag, NULL, NULL, false, false, true);

	if (sock != NULL && p->Tcp_TryStartSsl)
	{
		bool ssl_ret = false;

		p->Tcp_InNegotiation = true;

		// Attempt the SSL negotiation to take this opportunity
		Lock(p->CancelLock);
		{
			if ((*p->CancelFlag) == false)
			{
				p->CancelDisconnectSock = sock;
				AddRef(sock->ref);
			}
			else
			{
				Debug("User Cancel to StartSSL.\n");
				goto LABEL_CANCEL;
			}
		}
		Unlock(p->CancelLock);

		// Start the SSL communication
		ssl_ret = StartSSLEx(sock, NULL, NULL, p->Tcp_SslNoTls, 0, p->Hostname);

		if (ssl_ret)
		{
			// Identify whether the HTTPS server to be connected is a SoftEther VPN
			SetTimeout(sock, (10 * 1000));
			ssl_ret = DetectIsServerSoftEtherVPN(sock);
			SetTimeout(sock, INFINITE);

			if (ssl_ret == false)
			{
				Debug("DetectIsServerSoftEtherVPN Error.\n");
			}
		}

		Lock(p->CancelLock);
		{
			ReleaseSock(p->CancelDisconnectSock);
			p->CancelDisconnectSock = NULL;
LABEL_CANCEL:
			DoNothing();
		}
		Unlock(p->CancelLock);

		if (ssl_ret == false)
		{
			// SSL negotiation failure
			Disconnect(sock);
			ReleaseSock(sock);

			Debug("Fail to StartSSL.\n");

			sock = NULL;
		}
	}

	p->Result_Tcp_Sock = sock;
	p->Ok = (p->Result_Tcp_Sock == NULL ? false : true);
	p->FinishedTick = Tick64();
	p->Finished = true;
	p->Tcp_InNegotiation = false;

	Set(p->FinishEvent);
}

// R-UDP over ICMP / over DNS connection thread
void ConnectThreadForOverDnsOrIcmp(THREAD *thread, void *param)
{
	SOCK *sock;
	CONNECT_TCP_RUDP_PARAM *p = (CONNECT_TCP_RUDP_PARAM *)param;
	if (thread == NULL || p == NULL)
	{
		return;
	}

	// Delay
	if (p->Delay >= 1)
	{
		WaitEx(NULL, p->Delay, p->CancelFlag);
	}

	// Connecting process
	sock = NewRUDPClientDirect(p->SvcName, &p->Ip,
		(p->RUdpProtocol == RUDP_PROTOCOL_DNS ? 53 : MAKE_SPECIAL_PORT(IP_PROTO_ICMPV4)),
		&p->NatT_ErrorCode, p->Timeout, p->CancelFlag, NULL, NULL,
		(p->RUdpProtocol == RUDP_PROTOCOL_DNS ? 0 : MAKE_SPECIAL_PORT(IP_PROTO_ICMPV4)),
		(p->RUdpProtocol == RUDP_PROTOCOL_DNS ? true : false));

	p->Result_Nat_T_Sock = sock;
	p->Ok = (p->Result_Nat_T_Sock == NULL ? false : true);
	p->FinishedTick = Tick64();
	p->Finished = true;

	Set(p->FinishEvent);
}

// R-UDP (via NAT-T) connection thread
void ConnectThreadForRUDP(THREAD *thread, void *param)
{
	SOCK *sock;
	CONNECT_TCP_RUDP_PARAM *p = (CONNECT_TCP_RUDP_PARAM *)param;
	if (thread == NULL || p == NULL)
	{
		return;
	}

	// Delay
	if (p->Delay >= 1)
	{
		WaitEx(NULL, p->Delay, p->CancelFlag);
	}

	// Connecting process
	sock = NewRUDPClientNatT(p->SvcName, &p->Ip, &p->NatT_ErrorCode, p->Timeout, p->CancelFlag, p->HintStr, p->TargetHostname);

	p->Result_Nat_T_Sock = sock;
	p->Ok = (p->Result_Nat_T_Sock == NULL ? false : true);
	p->FinishedTick = Tick64();
	p->Finished = true;

	Set(p->FinishEvent);
}

// TCP connection
SOCK *Connect(char *hostname, UINT port)
{
	return ConnectEx(hostname, port, 0);
}
SOCK *ConnectEx(char *hostname, UINT port, UINT timeout)
{
	return ConnectEx2(hostname, port, timeout, NULL);
}
SOCK *ConnectEx2(char *hostname, UINT port, UINT timeout, bool *cancel_flag)
{
	return ConnectEx3(hostname, port, timeout, cancel_flag, NULL, NULL, false, false, true);
}
SOCK *ConnectEx3(char *hostname, UINT port, UINT timeout, bool *cancel_flag, char *nat_t_svc_name, UINT *nat_t_error_code, bool try_start_ssl, bool ssl_no_tls, bool no_get_hostname)
{
	return ConnectEx4(hostname, port, timeout, cancel_flag, nat_t_svc_name, nat_t_error_code, try_start_ssl, ssl_no_tls,
		no_get_hostname, NULL);
}
SOCK *ConnectEx4(char *hostname, UINT port, UINT timeout, bool *cancel_flag, char *nat_t_svc_name, UINT *nat_t_error_code, bool try_start_ssl, bool ssl_no_tls, bool no_get_hostname, IP *ret_ip)
{
	SOCK *sock;
	SOCKET s;
	struct linger ling;
	IP ip4;
	IP ip6;
	bool true_flag = true;
	bool false_flag = false;
	char tmp[MAX_SIZE];
	IP current_ip;
	bool is_ipv6 = false;
	bool dummy = false;
	bool use_natt = false;
	char hostname_original[MAX_SIZE];
	char hint_str[MAX_SIZE];
	bool force_use_natt = false;
	UINT dummy_int = 0;
	IP dummy_ret_ip;
	// Validate arguments
	if (hostname == NULL || port == 0 || port >= 65536 || IsEmptyStr(hostname))
	{
		return NULL;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}
	if (cancel_flag == NULL)
	{
		cancel_flag = &dummy;
	}
	if (nat_t_error_code == NULL)
	{
		nat_t_error_code = &dummy_int;
	}

	Zero(&dummy_ret_ip, sizeof(IP));
	if (ret_ip == NULL)
	{
		ret_ip = &dummy_ret_ip;
	}

	Zero(hint_str, sizeof(hint_str));
	StrCpy(hostname_original, sizeof(hostname_original), hostname);

	use_natt = (IsEmptyStr(nat_t_svc_name) ? false : true);

	if (use_natt)
	{
		// In case of using NAT-T, split host name if the '/' is included in the host name
		UINT i = SearchStrEx(hostname, "/", 0, false);

		if (i == INFINITE)
		{
			// Not included
			StrCpy(hostname_original, sizeof(hostname_original), hostname);
		}
		else
		{
			// Included
			StrCpy(hostname_original, sizeof(hostname_original), hostname);
			hostname_original[i] = 0;

			// Force to use the NAT-T
			force_use_natt = true;

			// Copy the hint string
			StrCpy(hint_str, sizeof(hint_str), hostname + i + 1);

			if (StrCmpi(hint_str, "tcp") == 0 || StrCmpi(hint_str, "disable") == 0
				|| StrCmpi(hint_str, "disabled") == 0
				|| StrCmpi(hint_str, "no") == 0 || StrCmpi(hint_str, "none") == 0)
			{
				// Force not to use the NAT-T
				force_use_natt = false;
				use_natt = false;
			}
		}
	}
	else
	{
		StrCpy(hostname_original, sizeof(hostname_original), hostname);
	}

	Zero(&current_ip, sizeof(current_ip));

	Zero(&ip4, sizeof(ip4));
	Zero(&ip6, sizeof(ip6));

	if (IsZeroIp(ret_ip) == false)
	{
		// Skip name resolution
		if (IsIP6(ret_ip))
		{
			Copy(&ip6, ret_ip, sizeof(IP));
		}
		else
		{
			Copy(&ip4, ret_ip, sizeof(IP));
		}

		//Debug("Using cached IP address: %s = %r\n", hostname_original, ret_ip);
	}
	else
	{
		// Forward resolution
		if (GetIP46Ex(&ip4, &ip6, hostname_original, 0, cancel_flag) == false)
		{
			return NULL;
		}
	}

	if (IsZeroIp(&ip4) == false && IsIPLocalHostOrMySelf(&ip4))
	{
		// NAT-T isn't used in the case of connection to localhost
		force_use_natt = false;
		use_natt = false;
	}

	s = INVALID_SOCKET;

	// Attempt to connect with IPv4
	if (IsZeroIp(&ip4) == false)
	{
		if (use_natt == false)
		{
			// Normal connection without using NAT-T
			s = ConnectTimeoutIPv4(&ip4, port, timeout, cancel_flag);

			if (s != INVALID_SOCKET)
			{
				Copy(&current_ip, &ip4, sizeof(IP));

				Copy(ret_ip, &ip4, sizeof(IP));
			}
		}
		else if (force_use_natt)
		{
			// The connection by forcing the use of NAT-T (not to connection with normal TCP)
			SOCK *nat_t_sock = NewRUDPClientNatT(nat_t_svc_name, &ip4, nat_t_error_code, timeout, cancel_flag,
				hint_str, hostname);

			if (nat_t_sock != NULL)
			{
				StrCpy(nat_t_sock->UnderlayProtocol, sizeof(nat_t_sock->UnderlayProtocol), SOCK_UNDERLAY_NAT_T);
			}

			Copy(ret_ip, &ip4, sizeof(IP));

			return nat_t_sock;
		}
		else
		{
			// Use the connections using NAT-T with normal TCP connection together
			// (Use multiple threads to try to connect in four connection methods concurrently)
			CONNECT_TCP_RUDP_PARAM p1, p2, p3, p4;
			EVENT *finish_event;
			THREAD *t1, *t2, *t3, *t4;
			UINT64 start_tick = Tick64();
			UINT64 giveup_for_all_tick = start_tick + (UINT64)SOCK_CONNECT_WAIT_FOR_ICMP_AND_DNS_AT_LEAST;
			bool cancel_flag2 = false;
			SOCK *cancel_sock = NULL;

			finish_event = NewEvent();

			Zero(&p1, sizeof(p1));
			Zero(&p2, sizeof(p2));
			Zero(&p3, sizeof(p3));
			Zero(&p4, sizeof(p4));

			// p1: TCP
			StrCpy(p1.Hostname, sizeof(p1.Hostname), hostname_original);
			Copy(&p1.Ip, &ip4, sizeof(IP));
			p1.Port = port;
			p1.Timeout = timeout;
			p1.CancelFlag = &cancel_flag2;
			p1.FinishEvent = finish_event;
			p1.Tcp_TryStartSsl = try_start_ssl;
			p1.Tcp_SslNoTls = ssl_no_tls;
			p1.CancelLock = NewLock();

			// p2: NAT-T
			StrCpy(p2.Hostname, sizeof(p2.Hostname), hostname_original);
			Copy(&p2.Ip, &ip4, sizeof(IP));
			p2.Port = port;
			p2.Timeout = timeout;
			p2.CancelFlag = &cancel_flag2;
			p2.FinishEvent = finish_event;

			StrCpy(p2.HintStr, sizeof(p2.HintStr), hint_str);
			StrCpy(p2.TargetHostname, sizeof(p2.TargetHostname), hostname);
			StrCpy(p2.SvcName, sizeof(p2.SvcName), nat_t_svc_name);
			p2.Delay = 30;		// Delay by 30ms

			// p3: over ICMP
			StrCpy(p3.Hostname, sizeof(p3.Hostname), hostname_original);
			Copy(&p3.Ip, &ip4, sizeof(IP));
			p3.Port = port;
			p3.Timeout = timeout;
			p3.CancelFlag = &cancel_flag2;
			p3.FinishEvent = finish_event;
			StrCpy(p3.SvcName, sizeof(p3.SvcName), nat_t_svc_name);
			p3.RUdpProtocol = RUDP_PROTOCOL_ICMP;
			p3.Delay = 200;		// Delay by 200ms

			// p4: over DNS
			StrCpy(p4.Hostname, sizeof(p4.Hostname), hostname_original);
			Copy(&p4.Ip, &ip4, sizeof(IP));
			p4.Port = port;
			p4.Timeout = timeout;
			p4.CancelFlag = &cancel_flag2;
			p4.FinishEvent = finish_event;
			StrCpy(p4.SvcName, sizeof(p4.SvcName), nat_t_svc_name);
			p4.RUdpProtocol = RUDP_PROTOCOL_DNS;
			p4.Delay = 100;		// Delay by 100ms

			t1 = NewThread(ConnectThreadForTcp, &p1);
			t2 = NewThread(ConnectThreadForRUDP, &p2);
			t4 = NewThread(ConnectThreadForOverDnsOrIcmp, &p4);
			t3 = NewThread(ConnectThreadForOverDnsOrIcmp, &p3);

			while (true)
			{
				UINT64 now = Tick64();

				if (*cancel_flag)
				{
					// Cancel by the user
					break;
				}

				if (p1.Finished && p2.Finished)
				{
					// Results for both the TCP and the NAT-T were confirmed
					if (now >= giveup_for_all_tick)
					{
						// Wait at least minimum time until successful of the ICMP or the DNS
						break;
					}

					if (p3.Ok || p4.Ok)
					{
						// Exit the loop immediately if any of the ICMP or the DNS is successful
						break;
					}
				}

				if (p1.Finished && p1.Ok)
				{
					// Have successfully connected by TCP
					break;
				}

				if (p2.Finished && p2.Ok)
				{
					UINT p1_wait_time;
					UINT64 tcp_giveup_tick;
					UINT p2_spent_time;
					// Have successfully connected by R-UDP
					if (p1.Finished)
					{
						// Result of TCP is confirmed
						break;
					}

					// Calculate the time takes to complete connection of R-UDP
					p2_spent_time = (UINT)(p2.FinishedTick - start_tick);

					// Decide the grace time for results of TCP until settled.
					// The grace time is four times the duration of the R-UDP, and at least 400 milliseconds from the start,
					// and up to 2500 milliseconds after the R-UDP results settled
					p1_wait_time = p2_spent_time * 4;
					p1_wait_time = MAX(p1_wait_time, 400);
					//Debug("p2_spent_time = %u,   p1_wait_time = %u\n", p2_spent_time, p1_wait_time);

					tcp_giveup_tick = start_tick + (UINT64)p1_wait_time;
					tcp_giveup_tick = MIN(tcp_giveup_tick, (p2.FinishedTick + 2500ULL));

					if (now >= tcp_giveup_tick)
					{
						// Result of the TCP is uncertain, but give up
						if (p1.Finished || p1.Tcp_InNegotiation == false)
						{
							// Break only when TCP SSL negotiation is not being processed
							break;
						}
					}
				}

				Wait(finish_event, 25);
			}

			cancel_flag2 = true;

			Lock(p1.CancelLock);
			{
				if (p1.CancelDisconnectSock != NULL)
				{
					cancel_sock = p1.CancelDisconnectSock;

					AddRef(cancel_sock->ref);
				}
			}
			Unlock(p1.CancelLock);

			if (cancel_sock != NULL)
			{
				Disconnect(cancel_sock);
				ReleaseSock(cancel_sock);
			}

			WaitThread(t1, INFINITE);
			WaitThread(t2, INFINITE);
			WaitThread(t3, INFINITE);
			WaitThread(t4, INFINITE);
			ReleaseThread(t1);
			ReleaseThread(t2);
			ReleaseThread(t3);
			ReleaseThread(t4);
			ReleaseEvent(finish_event);

			DeleteLock(p1.CancelLock);

			if (*cancel_flag)
			{
				// Abandon all the results because the user canceled
				Disconnect(p1.Result_Nat_T_Sock);
				ReleaseSock(p1.Result_Nat_T_Sock);
				Disconnect(p2.Result_Nat_T_Sock);
				ReleaseSock(p2.Result_Nat_T_Sock);
				Disconnect(p3.Result_Nat_T_Sock);
				ReleaseSock(p3.Result_Nat_T_Sock);
				Disconnect(p4.Result_Nat_T_Sock);
				ReleaseSock(p4.Result_Nat_T_Sock);

				return NULL;
			}

			if (p1.Ok)
			{
				char hostname[MAX_SIZE];

				// Use the results of the TCP
				// Dispose other results
				Disconnect(p2.Result_Nat_T_Sock);
				ReleaseSock(p2.Result_Nat_T_Sock);
				Disconnect(p3.Result_Nat_T_Sock);
				ReleaseSock(p3.Result_Nat_T_Sock);
				Disconnect(p4.Result_Nat_T_Sock);
				ReleaseSock(p4.Result_Nat_T_Sock);

				if (GetHostName(hostname, sizeof(hostname), &ip4))
				{
					Free(p1.Result_Tcp_Sock->RemoteHostname);
					p1.Result_Tcp_Sock->RemoteHostname = CopyStr(hostname);
				}

				Copy(ret_ip, &ip4, sizeof(IP));

				return p1.Result_Tcp_Sock;
			}
			else if (p2.Ok)
			{
				// Use the results of the R-UDP
				// Dispose other results
				Disconnect(p3.Result_Nat_T_Sock);
				ReleaseSock(p3.Result_Nat_T_Sock);
				Disconnect(p4.Result_Nat_T_Sock);
				ReleaseSock(p4.Result_Nat_T_Sock);

				StrCpy(p2.Result_Nat_T_Sock->UnderlayProtocol, sizeof(p2.Result_Nat_T_Sock->UnderlayProtocol),
					SOCK_UNDERLAY_NAT_T);

				Copy(ret_ip, &ip4, sizeof(IP));

				return p2.Result_Nat_T_Sock;
			}
			else if (p4.Ok)
			{
				// Use this if over-DNS success
				// Dispose other results
				Disconnect(p3.Result_Nat_T_Sock);
				ReleaseSock(p3.Result_Nat_T_Sock);

				StrCpy(p4.Result_Nat_T_Sock->UnderlayProtocol, sizeof(p4.Result_Nat_T_Sock->UnderlayProtocol),
					SOCK_UNDERLAY_DNS);

				Copy(ret_ip, &ip4, sizeof(IP));

				return p4.Result_Nat_T_Sock;
			}
			else if (p3.Ok)
			{
				// Use this if over ICMP success
				StrCpy(p3.Result_Nat_T_Sock->UnderlayProtocol, sizeof(p3.Result_Nat_T_Sock->UnderlayProtocol),
					SOCK_UNDERLAY_ICMP);

				Copy(ret_ip, &ip4, sizeof(IP));

				return p3.Result_Nat_T_Sock;
			}
			else
			{
				// Continue the process if all trials failed
				*nat_t_error_code = p2.NatT_ErrorCode;
			}
		}
	}

	// Attempt to connect with IPv6
	if (s == INVALID_SOCKET && IsZeroIp(&ip6) == false)
	{
		struct sockaddr_in6 sockaddr6;
		struct in6_addr addr6;

		Zero(&sockaddr6, sizeof(sockaddr6));
		Zero(&addr6, sizeof(addr6));

		// Generation of the sockaddr_in6
		IPToInAddr6(&addr6, &ip6);
		sockaddr6.sin6_port = htons((USHORT)port);
		sockaddr6.sin6_family = AF_INET6;
		sockaddr6.sin6_scope_id = ip6.ipv6_scope_id;
		Copy(&sockaddr6.sin6_addr, &addr6, sizeof(addr6));

		// Socket creation
		s = socket(AF_INET6, SOCK_STREAM, 0);
		if (s != INVALID_SOCKET)
		{
			// Connection
			if (connect_timeout(s, (struct sockaddr *)&sockaddr6, sizeof(struct sockaddr_in6), timeout, cancel_flag) != 0)
			{
				// Connection failure
				closesocket(s);
				s = INVALID_SOCKET;
			}
			else
			{
				Copy(&current_ip, &ip6, sizeof(IP));

				is_ipv6 = true;

				Copy(ret_ip, &ip6, sizeof(IP));
			}
		}
	}

	if (s == INVALID_SOCKET)
	{
		// Connection fails on both of IPv4, IPv6
		return NULL;
	}

	// Creating a SOCK
	sock = NewSock();
	sock->socket = s;
	sock->Type = SOCK_TCP;
	sock->ServerMode = false;

	StrCpy(sock->UnderlayProtocol, sizeof(sock->UnderlayProtocol),
		(is_ipv6 ? SOCK_UNDERLAY_NATIVE_V6 : SOCK_UNDERLAY_NATIVE_V4));

	// Host name resolution
	if (no_get_hostname || (GetHostName(tmp, sizeof(tmp), &current_ip) == false))
	{
		StrCpy(tmp, sizeof(tmp), hostname_original);
	}

	//Debug("PTR: %s\n", tmp);

	sock->RemoteHostname = CopyStr(tmp);

//	Debug("new socket: %u\n", s);

	Zero(&ling, sizeof(ling));
	// Forced disconnection flag
#ifdef	SO_DONTLINGER
	setsockopt(sock->socket, SOL_SOCKET, SO_DONTLINGER, (char *)&true_flag, sizeof(bool));
#else	// SO_DONTLINGER
	setsockopt(sock->socket, SOL_SOCKET, SO_LINGER, (char *)&false_flag, sizeof(bool));
#endif	// SO_DONTLINGER
//	setsockopt(sock->socket, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(bool));

	// Configuring TCP options
	setsockopt(sock->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(bool));

	// Initialization of the time-out value
	SetTimeout(sock, TIMEOUT_INFINITE);

	// Get the socket information
	QuerySocketInformation(sock);

	if (IsZeroIp(&sock->LocalIP) == false && IsLocalHostIP(&sock->LocalIP) == false)
	{
		IP current_ip;

		if (GetCurrentGlobalIP(&current_ip, is_ipv6) == false)
		{
			SetCurrentGlobalIP(&sock->LocalIP, is_ipv6);
		}
	}

	sock->Connected = true;
	sock->AsyncMode = false;
	sock->SecureMode = false;
	sock->IPv6 = is_ipv6;

	return sock;
}

// Maximize the I/O buffer size of the socket
void SetSocketSendRecvBufferSize(SOCKET s, UINT size)
{
	int value = (int)size;
	// Validate arguments
	if (s == INVALID_SOCKET)
	{
		return;
	}

	setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char *)&value, sizeof(int));
	setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char *)&value, sizeof(int));
}

// Get the buffer size of the socket
UINT GetSocketBufferSize(SOCKET s, bool send)
{
	int value = 0;
	int len = sizeof(int);
	// Validate arguments
	if (s == INVALID_SOCKET)
	{
		return 0;
	}

	if (getsockopt(s, SOL_SOCKET, (send ? SO_SNDBUF : SO_RCVBUF), (char *)&value, &len) != 0)
	{
		return 0;
	}

	return value;
}

// Setting the buffer size of the socket
bool SetSocketBufferSize(SOCKET s, bool send, UINT size)
{
	int value = (int)size;
	// Validate arguments
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	if (setsockopt(s, SOL_SOCKET, (send ? SO_SNDBUF : SO_RCVBUF), (char *)&value, sizeof(int)) != 0)
	{
		return false;
	}

	return true;
}
UINT SetSocketBufferSizeWithBestEffort(SOCKET s, bool send, UINT size)
{
	// Validate arguments
	if (s == INVALID_SOCKET)
	{
		return 0;
	}

	while (true)
	{
		if (SetSocketBufferSize(s, send, size))
		{
			return size;
		}

		size = (UINT)((double)size / 1.5);

		if (size <= 32767)
		{
			return 0;
		}
	}
}

// Initialize the buffer size of the UDP socket
void InitUdpSocketBufferSize(SOCKET s)
{
	SetSocketBufferSizeWithBestEffort(s, true, UDP_MAX_BUFFER_SIZE);
	SetSocketBufferSizeWithBestEffort(s, false, UDP_MAX_BUFFER_SIZE);
}

// Get the socket information
void QuerySocketInformation(SOCK *sock)
{
	// Validate arguments
	if (sock == NULL)
	{
		return;
	}

	Lock(sock->lock);
	{
		struct sockaddr_in6 sockaddr6;
		struct in6_addr *addr6;
		int size;
		DWORD dw;
		UINT opt_value = 0;

		if (sock->Type == SOCK_TCP)
		{
			// Get the information of the remote host
			size = sizeof(sockaddr6);
			if (getpeername(sock->socket, (struct sockaddr *)&sockaddr6, (int *)&size) == 0)
			{
				if (size >= sizeof(struct sockaddr_in6))
				{
					sock->RemotePort = (UINT)ntohs(sockaddr6.sin6_port);
					addr6 = &sockaddr6.sin6_addr;
					InAddrToIP6(&sock->RemoteIP, addr6);
					sock->RemoteIP.ipv6_scope_id = sockaddr6.sin6_scope_id;
				}
				else
				{
					struct sockaddr_in *sockaddr;
					struct in_addr *addr;

					sockaddr = (struct sockaddr_in *)&sockaddr6;
					sock->RemotePort = (UINT)ntohs(sockaddr->sin_port);
					addr = &sockaddr->sin_addr;
					InAddrToIP(&sock->RemoteIP, addr);
				}
			}
		}

		// Get the local host information
		size = sizeof(sockaddr6);
		if (getsockname(sock->socket, (struct sockaddr *)&sockaddr6, (int *)&size) == 0)
		{
			if (size >= sizeof(struct sockaddr_in6))
			{
				sock->LocalPort = (UINT)ntohs(sockaddr6.sin6_port);
				addr6 = &sockaddr6.sin6_addr;
				InAddrToIP6(&sock->LocalIP, addr6);
				sock->LocalIP.ipv6_scope_id = sockaddr6.sin6_scope_id;
			}
			else
			{
				struct sockaddr_in *sockaddr;
				struct in_addr *addr;

				sockaddr = (struct sockaddr_in *)&sockaddr6;
				sock->LocalPort = (UINT)ntohs(sockaddr->sin_port);
				addr = &sockaddr->sin_addr;
				InAddrToIP(&sock->LocalIP, addr);
			}
		}

		if (sock->IsRawSocket)
		{
			sock->LocalPort = sock->RemotePort = MAKE_SPECIAL_PORT(sock->RawSocketIPProtocol);
		}

		if (sock->Type == SOCK_UDP)
		{
			sock->UdpMaxMsgSize = UDP_MAX_MSG_SIZE_DEFAULT;

#ifdef	OS_WIN32
			if (true)
			{
				// Get the buffer size that can be transmitted and received at once
				UINT max_value = 0;
				int len = sizeof(UINT);

				if (getsockopt(sock->socket, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&max_value, &len) == 0)
				{
					sock->UdpMaxMsgSize = max_value;
				}
			}
#endif	// OS_WIN32
		}

		if (sock->IPv6)
		{
#ifdef	IPV6_UNICAST_HOPS
			opt_value = IPV6_UNICAST_HOPS;
#endif	// IPV6_UNICAST_HOPS
		}
		else
		{
#ifdef	IP_TTL
			opt_value = IP_TTL;
#endif	// IP_TTL
		}

		// Support of the TTL value
		size = sizeof(DWORD);
		if (opt_value == 0 ||
			getsockopt(sock->socket, (sock->IPv6 ? IPPROTO_IPV6 : IPPROTO_IP), opt_value, (char *)&dw, &size) != 0)
		{
			sock->IsTtlSupported = false;
		}
		else
		{
			sock->IsTtlSupported = true;
			sock->CurrentTtl = dw;
		}
	}
	Unlock(sock->lock);
}

// Setting the TTL value
bool SetTtl(SOCK *sock, UINT ttl)
{
	DWORD dw;
	int size;
	UINT opt_value = 0;
	// Validate arguments
	if (sock == NULL)
	{
		return false;
	}

	if (sock->IsTtlSupported == false)
	{
		return false;
	}

	if (sock->CurrentTtl == ttl)
	{
		return true;
	}

	dw = ttl;
	size = sizeof(DWORD);

	if (sock->IPv6)
	{
#ifdef	IPV6_UNICAST_HOPS
		opt_value = IPV6_UNICAST_HOPS;
#endif	// IPV6_UNICAST_HOPS
	}
	else
	{
#ifdef	IP_TTL
		opt_value = IP_TTL;
#endif	// IP_TTL
	}

	if (opt_value == 0 ||
		setsockopt(sock->socket, (sock->IPv6 ? IPPROTO_IPV6 : IPPROTO_IP), opt_value, (char *)&dw, size) == false)
	{
		return false;
	}

	sock->CurrentTtl = ttl;

	return true;
}

// Release of the socket
void ReleaseSock(SOCK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		if (s->ListenMode == false && s->ServerMode)
		{
			Print("");
		}
		CleanupSock(s);
	}
}

// Clean-up of the socket
void CleanupSock(SOCK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

//	{Debug("CleanupSock: Disconnect() Called: %s %u\n", __FILE__, __LINE__);Disconnect(s);}
	Disconnect(s);

	if (s->InProcAcceptQueue != NULL)
	{
		while (true)
		{
			SOCK *ss = GetNext(s->InProcAcceptQueue);
			if (ss == NULL)
			{
				break;
			}

			Disconnect(ss);
			ReleaseSock(ss);
		}

		ReleaseQueue(s->InProcAcceptQueue);
	}

	if (s->InProcAcceptEvent != NULL)
	{
		ReleaseEvent(s->InProcAcceptEvent);
	}

	if (s->ReverseAcceptQueue != NULL)
	{
		while (true)
		{
			SOCK *ss = GetNext(s->ReverseAcceptQueue);
			if (ss == NULL)
			{
				break;
			}

			Disconnect(ss);
			ReleaseSock(ss);
		}

		ReleaseQueue(s->ReverseAcceptQueue);
	}

	if (s->ReverseAcceptEvent != NULL)
	{
		ReleaseEvent(s->ReverseAcceptEvent);
	}

	if (s->SendTube != NULL)
	{
		TubeDisconnect(s->SendTube);
		ReleaseTube(s->SendTube);
	}

	if (s->RecvTube != NULL)
	{
		TubeDisconnect(s->RecvTube);
		ReleaseTube(s->RecvTube);
	}

	if (s->BulkRecvTube != NULL)
	{
		TubeDisconnect(s->BulkRecvTube);
		ReleaseTube(s->BulkRecvTube);
	}

	if (s->BulkSendTube != NULL)
	{
		TubeDisconnect(s->BulkSendTube);
		ReleaseTube(s->BulkSendTube);
	}

	if (s->BulkSendKey != NULL)
	{
		ReleaseSharedBuffer(s->BulkSendKey);
	}

	if (s->BulkRecvKey != NULL)
	{
		ReleaseSharedBuffer(s->BulkRecvKey);
	}

	if (s->InProcRecvFifo != NULL)
	{
		ReleaseFifo(s->InProcRecvFifo);
	}

	if (s->R_UDP_Stack != NULL)
	{
		FreeRUDP(s->R_UDP_Stack);
	}

#ifdef	OS_WIN32
	Win32FreeAsyncSocket(s);
#else	// OS_WIN32
	UnixFreeAsyncSocket(s);
#endif	// OS_WIN32

	FreeBuf(s->SendBuf);
	if (s->socket != INVALID_SOCKET)
	{
#ifdef	OS_WIN32
		closesocket(s->socket);
#else	// OS_WIN32
		close(s->socket);
#endif	// OS_WIN32
	}
	Free(s->RemoteHostname);

#ifdef	OS_WIN32
	if (s->hAcceptEvent != NULL)
	{
		CloseHandle(s->hAcceptEvent);
	}
#endif	// OS_WIN32

	// Release the certificate
	if (s->RemoteX != NULL)
	{
		FreeX(s->RemoteX);
		s->RemoteX = NULL;
	}
	if (s->LocalX != NULL)
	{
		FreeX(s->LocalX);
		s->LocalX = NULL;
	}

	// Cipher algorithm name
	if (s->CipherName != NULL)
	{
		Free(s->CipherName);
		s->CipherName = NULL;
	}

	Free(s->WaitToUseCipher);
	DeleteLock(s->lock);
	DeleteLock(s->ssl_lock);
	DeleteLock(s->disconnect_lock);

	Dec(num_tcp_connections);

	Free(s);
}

// Creating a new socket
SOCK *NewSock()
{
	SOCK *s = ZeroMallocFast(sizeof(SOCK));

	s->ref = NewRef();
	s->lock = NewLock();
	s->SendBuf = NewBuf();
	s->socket = INVALID_SOCKET;
	s->ssl_lock = NewLock();
	s->disconnect_lock = NewLock();

	Inc(num_tcp_connections);

	return s;
}

// Convert the IP to UINT
UINT IPToUINT(IP *ip)
{
	UCHAR *b;
	UINT i, value = 0;
	// Validate arguments
	if (ip == NULL)
	{
		return 0;
	}

	b = (UCHAR *)&value;
	for (i = 0;i < 4;i++)
	{
		b[i] = ip->addr[i];
	}

	return value;
}

// Convert UINT to IP
void UINTToIP(IP *ip, UINT value)
{
	UCHAR *b;
	UINT i;
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	ZeroIP4(ip);

	b = (UCHAR *)&value;
	for (i = 0;i < 4;i++)
	{
		ip->addr[i] = b[i];
	}
}

// Get the host name of the computer
void GetMachineHostName(char *name, UINT size)
{
	char tmp[MAX_SIZE];
	UINT i, len;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	GetMachineName(tmp, sizeof(tmp));

	len = StrLen(tmp);
	for (i = 0;i < len;i++)
	{
		if (tmp[i] == '.')
		{
			tmp[i] = 0;
		}
	}

	ConvertSafeFileName(name, size, tmp);
}

// Get the IP address of this computer
void GetMachineIp(IP *ip)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));
	SetIP(ip, 127, 0, 0, 1);

	GetMachineName(tmp, sizeof(tmp));
	GetIP(ip, tmp);
}

// Get the computer name from 'hosts'
bool GetMachineNameFromHosts(char *name, UINT size)
{
	bool ret = false;
	char *s;
	BUF *b;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	b = ReadDump("/etc/hosts");
	if (b == NULL)
	{
		return false;
	}

	while (true)
	{
		s = CfgReadNextLine(b);
		if (s == NULL)
		{
			break;
		}
		else
		{
			TOKEN_LIST *t = ParseToken(s, " \t");

			if (t != NULL)
			{
				if (t->NumTokens >= 2)
				{
					if (StrCmpi(t->Token[0], "127.0.0.1") == 0)
					{
						UINT i;

						for (i = 1;i < t->NumTokens;i++)
						{
							if (StartWith(t->Token[i], "localhost") == false)
							{
								StrCpy(name, size, t->Token[i]);
								ret = true;
							}
						}
					}
				}
			}
			FreeToken(t);
		}

		Free(s);
	}

	FreeBuf(b);

	return ret;
}

// Get the computer name of this computer
void GetMachineName(char *name, UINT size)
{
	GetMachineNameEx(name, size, false);
}
void GetMachineNameEx(char *name, UINT size, bool no_load_hosts)
{
	static char name_cache[MAX_SIZE];
	static bool name_cached = false;
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	Lock(machine_name_lock);
	{
		if (name_cached != false)
		{
			StrCpy(name, size, name_cache);
			Unlock(machine_name_lock);
			return;
		}
		ClearStr(tmp, sizeof(tmp));
		if (gethostname(tmp, MAX_SIZE) != 0)
		{
			StrCpy(name, size, "Unknown");
			Unlock(machine_name_lock);
			return;
		}
		ClearStr(name, size);
		StrCpy(name, size, tmp);
		if (IsEmptyStr(name) || StartWith(name, "localhost"))
		{
#ifdef	OS_WIN32
			ClearStr(name, size);
			MsGetComputerName(name, size);
#endif	// OS_WIN32
		}
		if (IsEmptyStr(name) || StartWith(name, "localhost"))
		{
			if (no_load_hosts == false && OS_IS_UNIX(GetOsInfo()->OsType))
			{
				if (GetMachineNameFromHosts(tmp2, sizeof(tmp2)))
				{
					StrCpy(name, sizeof(name), tmp2);
				}
			}
		}

		StrCpy(name_cache, sizeof(name_cache), name);
		name_cached = true;
	}
	Unlock(machine_name_lock);
}

// Host name acquisition thread
void GetHostNameThread(THREAD *t, void *p)
{
	IP *ip;
	char hostname[256];
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	ip = (IP *)p;

	AddWaitThread(t);

	NoticeThreadInit(t);

	if (GetHostNameInner(hostname, sizeof(hostname), ip))
	{
		AddHostCache(ip, hostname);
	}

	Free(ip);

	DelWaitThread(t);
}

// Get the host name
bool GetHostName(char *hostname, UINT size, IP *ip)
{
	THREAD *t;
	IP *p_ip;
	bool ret;
	// Validate arguments
	if (hostname == NULL || ip == NULL)
	{
		return false;
	}

	if (GetHostCache(hostname, size, ip))
	{
		if (IsEmptyStr(hostname) == false)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	p_ip = ZeroMalloc(sizeof(IP));
	Copy(p_ip, ip, sizeof(IP));

	t = NewThread(GetHostNameThread, p_ip);

	WaitThreadInit(t);

	WaitThread(t, TIMEOUT_HOSTNAME);

	ReleaseThread(t);

	ret = GetHostCache(hostname, size, ip);
	if (ret == false)
	{
		if (IsIP4(ip))
		{
			ret = GetNetBiosName(hostname, size, ip);
			if (ret)
			{
				AddHostCache(ip, hostname);
			}
		}
	}
	else
	{
		if (IsEmptyStr(hostname))
		{
			ret = false;
		}
	}
	if (ret == false)
	{
		AddHostCache(ip, "");
		StrCpy(hostname, size, "");
	}

	return ret;
}

// Perform a DNS reverse query
bool GetHostNameInner(char *hostname, UINT size, IP *ip)
{
	struct in_addr addr;
	struct sockaddr_in sa;
	char tmp[MAX_SIZE];
	char ip_str[64];
	// Validate arguments
	if (hostname == NULL || ip == NULL)
	{
		return false;
	}

	if (IsIP6(ip))
	{
		return GetHostNameInner6(hostname, size, ip);
	}

	// Reverse resolution
	IPToInAddr(&addr, ip);
	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;

#if	defined(UNIX_BSD) || defined(UNIX_MACOS)
	sa.sin_len = INET_ADDRSTRLEN;
#endif	// UNIX_BSD || UNIX_MACOS

	Copy(&sa.sin_addr, &addr, sizeof(struct in_addr));
	sa.sin_port = 0;

	if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), tmp, sizeof(tmp), NULL, 0, 0) != 0)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), ip);

	if (StrCmpi(tmp, ip_str) == 0)
	{
		return false;
	}

	if (IsEmptyStr(tmp))
	{
		return false;
	}

	StrCpy(hostname, size, tmp);

	return true;
}
bool GetHostNameInner6(char *hostname, UINT size, IP *ip)
{
	struct in6_addr addr;
	struct sockaddr_in6 sa;
	char tmp[MAX_SIZE];
	char ip_str[256];
	// Validate arguments
	if (hostname == NULL || ip == NULL)
	{
		return false;
	}

	// Reverse resolution
	IPToInAddr6(&addr, ip);
	Zero(&sa, sizeof(sa));
	sa.sin6_family = AF_INET6;

#if	defined(UNIX_BSD) || defined(UNIX_MACOS)
	sa.sin6_len = INET6_ADDRSTRLEN;
#endif	// UNIX_BSD || UNIX_MACOS

	Copy(&sa.sin6_addr, &addr, sizeof(struct in6_addr));
	sa.sin6_port = 0;

	if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), tmp, sizeof(tmp), NULL, 0, 0) != 0)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), ip);

	if (StrCmpi(tmp, ip_str) == 0)
	{
		return false;
	}

	if (IsEmptyStr(tmp))
	{
		return false;
	}

	StrCpy(hostname, size, tmp);

	return true;
}

#define	NUM_NBT_QUERYS_SEND			3

// Get the NetBIOS name of the machine from the IP address
bool GetNetBiosName(char *name, UINT size, IP *ip)
{
	SOCK *s;
	UINT i, j;
	bool flag = false;
	bool ok = false;
	NBTREQUEST req;
	UCHAR buf[1024];
	USHORT tran_id[NUM_NBT_QUERYS_SEND];
	UINT64 timeout_tick;
	// Validate arguments
	if (name == NULL || ip == NULL)
	{
		return false;
	}

	IPToStr(name, size, ip);

	for (i = 0;i < NUM_NBT_QUERYS_SEND;i++)
	{
		tran_id[i] = Rand16();
	}

	s = NewUDP(0);
	if (s == NULL)
	{
		return false;
	}

	for (j = 0;j < NUM_NBT_QUERYS_SEND;j++)
	{
		Zero(&req, sizeof(req));
		req.TransactionId = Endian16(tran_id[j]);
		req.NumQuestions = Endian16(1);
		req.Query[0] = 0x20;
		req.Query[1] = 0x43;
		req.Query[2] = 0x4b;
		for (i = 3;i <= 32;i++)
		{
			req.Query[i] = 0x41;
		}
		req.Query[35] = 0x21;
		req.Query[37] = 0x01;

		if (SendTo(s, ip, 137, &req, sizeof(req)) == 0)
		{
			ReleaseSock(s);
			return false;
		}
	}

	timeout_tick = Tick64() + (UINT64)TIMEOUT_NETBIOS_HOSTNAME;

	while (1)
	{
		UINT ret;
		IP src_ip;
		UINT src_port;
		SOCKSET set;
		if (Tick64() >= timeout_tick)
		{
			break;
		}
		InitSockSet(&set);
		AddSockSet(&set, s);
		Select(&set, 100, NULL, NULL);

		if (flag == false)
		{
			flag = true;
		}
		else
		{
			SleepThread(10);
		}

		ret = RecvFrom(s, &src_ip, &src_port, buf, sizeof(buf));

		if (ret == SOCK_LATER)
		{
			continue;
		}
		else if (ret == 0)
		{
			break;
		}
		else
		{
			if (ret >= sizeof(NBTRESPONSE))
			{
				NBTRESPONSE *r = (NBTRESPONSE *)buf;
				bool b = false;
				UINT i;
				USHORT id = Endian16(r->TransactionId);
				for (i = 0;i < NUM_NBT_QUERYS_SEND;i++)
				{
					if (id == tran_id[i])
					{
						b = true;
						break;
					}
				}
				if (b)
				{
					if (r->Flags != 0 && r->NumQuestions == 0 && r->AnswerRRs >= 1)
					{
						if (r->Response[0] == 0x20 && r->Response[1] == 0x43 &&
							r->Response[2] == 0x4b)
						{
							if (r->Response[34] == 0x00 && r->Response[35] == 0x21 &&
								r->Response[36] == 0x00 && r->Response[37] == 0x01)
							{
								char *a = (char *)(&r->Response[45]);
								if (StrCheckLen(a, 15))
								{
									if (IsEmptyStr(a) == false)
									{
										StrCpy(name, size, a);
										Trim(name);
										ok = true;
									}
									else
									{
										ok = false;
										break;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	ReleaseSock(s);
	return ok;
}

// Set the IP address
void SetIP(IP *ip, UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));
	ip->addr[0] = a1;
	ip->addr[1] = a2;
	ip->addr[2] = a3;
	ip->addr[3] = a4;
}
UINT SetIP32(UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4)
{
	IP ip;

	Zero(&ip, sizeof(ip));
	SetIP(&ip, a1, a2, a3, a4);

	return IPToUINT(&ip);
}

// Get either of v4 and v6 results with a DNS forward lookup (The IPv4 precedes in the case of both results)
bool GetIP46Any4(IP *ip, char *hostname)
{
	IP ip4, ip6;
	bool b = false;
	// Validate arguments
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	if (GetIP46(&ip4, &ip6, hostname) == false)
	{
		return false;
	}

	if (IsZeroIp(&ip6) == false)
	{
		Copy(ip, &ip6, sizeof(IP));

		b = true;
	}

	if (IsZeroIp(&ip4) == false)
	{
		Copy(ip, &ip4, sizeof(IP));

		b = true;
	}

	return b;
}

// Get either of v4 and v6 results with a DNS forward lookup (The IPv6 precedes in the case of both)
bool GetIP46Any6(IP *ip, char *hostname)
{
	IP ip4, ip6;
	bool b = false;
	// Validate arguments
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	if (GetIP46(&ip4, &ip6, hostname) == false)
	{
		return false;
	}

	if (IsZeroIp(&ip4) == false)
	{
		Copy(ip, &ip4, sizeof(IP));

		b = true;
	}

	if (IsZeroIp(&ip6) == false)
	{
		Copy(ip, &ip6, sizeof(IP));

		b = true;
	}

	return b;
}

// Obtain in both v4 and v6 results with a DNS forward lookup
bool GetIP46(IP *ip4, IP *ip6, char *hostname)
{
	return GetIP46Ex(ip4, ip6, hostname, 0, NULL);
}
bool GetIP46Ex(IP *ip4, IP *ip6, char *hostname, UINT timeout, bool *cancel)
{
	IP a, b;
	bool ok_a, ok_b;
	// Validate arguments
	if (ip4 == NULL || ip6 == NULL || hostname == NULL)
	{
		return false;
	}

	ZeroIP4(ip4);
	ZeroIP6(ip6);

	ok_a = ok_b = false;

	if (GetIP6Ex(&a, hostname, timeout, cancel))
	{
		ok_a = true;
	}

	if (GetIP4Ex(&b, hostname, timeout, cancel))
	{
		ok_b = true;
	}

	if (ok_a)
	{
		if (IsIP4(&a))
		{
			Copy(ip4, &a, sizeof(IP));
		}
	}
	if (ok_b)
	{
		if (IsIP4(&b))
		{
			Copy(ip4, &b, sizeof(IP));
		}

		if (IsIP6(&b))
		{
			Copy(ip6, &b, sizeof(IP));
		}
	}
	if (ok_a)
	{
		if (IsIP6(&a))
		{
			Copy(ip6, &a, sizeof(IP));
		}
	}

	if (IsZeroIp(ip4) && IsZeroIp(ip6))
	{
		return false;
	}

	return true;
}

// Clean-up of the parameters for GetIP thread
void CleanupGetIPThreadParam(GETIP_THREAD_PARAM *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	Free(p);
}

// Release of the parameters of the GetIP for thread
void ReleaseGetIPThreadParam(GETIP_THREAD_PARAM *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (Release(p->Ref) == 0)
	{
		CleanupGetIPThreadParam(p);
	}
}

// Thread to perform to query the DNS forward lookup (with timeout)
void GetIP4Ex6ExThread(THREAD *t, void *param)
{
	GETIP_THREAD_PARAM *p;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	p = (GETIP_THREAD_PARAM *)param;

	AddRef(p->Ref);

	NoticeThreadInit(t);

	AddWaitThread(t);

	// Execution of resolution
	if (p->IPv6 == false)
	{
		// IPv4
		p->Ok = GetIP4Inner(&p->Ip, p->HostName);
	}
	else
	{
		// IPv6
		p->Ok = GetIP6Inner(&p->Ip, p->HostName);
	}

	ReleaseGetIPThreadParam(p);

	DelWaitThread(t);

	Dec(getip_thread_counter);
}

// Perform a forward DNS query (with timeout)
bool GetIP4Ex6Ex(IP *ip, char *hostname_arg, UINT timeout, bool ipv6, bool *cancel)
{
	return GetIP4Ex6Ex2(ip, hostname_arg, timeout, ipv6, cancel, false);
}
bool GetIP4Ex6Ex2(IP *ip, char *hostname_arg, UINT timeout, bool ipv6, bool *cancel, bool only_direct_dns)
{
	GETIP_THREAD_PARAM *p;
	THREAD *t;
	bool ret = false;
	UINT64 start_tick = 0;
	UINT64 end_tick = 0;
	UINT64 spent_time = 0;
	UINT64 now;
	UINT n;
	bool use_dns_proxy = false;
	char hostname[260];
	UINT i;
	bool timed_out;
	// Validate arguments
	if (ip == NULL || hostname_arg == NULL)
	{
		return false;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_GETIP;
	}

	Zero(hostname, sizeof(hostname));
	StrCpy(hostname, sizeof(hostname), hostname_arg);

	i = SearchStrEx(hostname, "/", 0, true);
	if (i != INFINITE)
	{
		hostname[i] = 0;
	}

	if (ipv6 == false)
	{
		IP ip2;

		if (StrToIP(&ip2, hostname) && IsZeroIp(&ip2) == false)
		{
			if (IsIP4(&ip2))
			{
				// IPv4 address direct specification
				Copy(ip, &ip2, sizeof(IP));
				return true;
			}
			else
			{
				// IPv6 address direct specification
				return false;
			}
		}
	}
	else
	{
		IP ip2;

		if (StrToIP(&ip2, hostname) && IsZeroIp(&ip2) == false)
		{
			if (IsIP6(&ip2))
			{
				// IPv6 address direct specification
				Copy(ip, &ip2, sizeof(IP));
				return true;
			}
			else
			{
				// IPv4 address direct specification
				return false;
			}
		}
	}

	if (only_direct_dns == false)
	{
		if (ipv6 == false)
		{
			if (IsUseDnsProxy())
			{
				use_dns_proxy = true;
			}
		}
	}


	// check the quota
	start_tick = Tick64();
	end_tick = start_tick + (UINT64)timeout;

	n = 0;

	timed_out = false;

	while (true)
	{
		UINT64 now = Tick64();
		UINT64 remain;
		UINT remain32;

		if (GetGetIpThreadMaxNum() > GetCurrentGetIpThreadNum())
		{
			// below the quota
			break;
		}

		if (now >= end_tick)
		{
			// timeouted
			timed_out = true;
			break;
		}

		if (cancel != NULL && (*cancel))
		{
			// cancelled
			timed_out = true;
			break;
		}

		remain = end_tick - now;
		remain32 = MIN((UINT)remain, 100);

		SleepThread(remain32);
		n++;
	}

	now = Tick64();
	spent_time = now - start_tick;

	if (n == 0)
	{
		spent_time = 0;
	}

	if ((UINT)spent_time >= timeout)
	{
		timed_out = true;
	}

	if (timed_out)
	{
		IP ip2;

		// timed out, cancelled
		if (QueryDnsCache(&ip2, hostname))
		{
			ret = true;

			Copy(ip, &ip2, sizeof(IP));
		}

		Debug("GetIP4Ex6Ex2: Worker thread quota exceeded: max=%u current=%u\n",
			GetGetIpThreadMaxNum(), GetCurrentGetIpThreadNum());

		return ret;
	}

	// Increment the counter
	Inc(getip_thread_counter);

	if (spent_time != 0)
	{
		Debug("GetIP4Ex6Ex2: Waited for %u msecs to create a worker thread.\n",
			spent_time);
	}

	timeout -= (UINT)spent_time;

	p = ZeroMalloc(sizeof(GETIP_THREAD_PARAM));
	p->Ref = NewRef();
	StrCpy(p->HostName, sizeof(p->HostName), hostname);
	p->IPv6 = ipv6;
	p->Timeout = timeout;
	p->Ok = false;

	t = NewThread(GetIP4Ex6ExThread, p);
	WaitThreadInit(t);

	if (cancel == NULL)
	{
		WaitThread(t, timeout);
	}
	else
	{
		start_tick = Tick64();
		end_tick = start_tick + (UINT64)timeout;

		while (true)
		{
			UINT64 now = Tick64();
			UINT64 remain;
			UINT remain32;

			if (*cancel)
			{
				break;
			}

			if (now >= end_tick)
			{
				break;
			}

			remain = end_tick - now;
			remain32 = MIN((UINT)remain, 100);

			if (WaitThread(t, remain32))
			{
				break;
			}
		}
	}

	ReleaseThread(t);

	if (p->Ok)
	{
		ret = true;
		Copy(ip, &p->Ip, sizeof(IP));
	}
	else
	{
		IP ip2;

#if	0
		if (only_direct_dns == false)
		{
			if (ipv6)
			{
				UINT flets_type = DetectFletsType();

				// if I'm in the FLETs of NTT East,
				// try to get an IP address using the DNS proxy server
				if ((flets_type & FLETS_DETECT_TYPE_EAST_BFLETS_PRIVATE) &&
					GetIPViaDnsProxyForJapanFlets(ip, hostname, true, 0, cancel, NULL))
				{
					// B FLETs
					ret = true;
				}
				else if ((flets_type & FLETS_DETECT_TYPE_EAST_NGN_PRIVATE) &&
					GetIPViaDnsProxyForJapanFlets(ip, hostname, true, 0, cancel, FLETS_NGN_EAST_DNS_PROXY_HOSTNAME))
				{
					// FLET'S Hikar-Next (NTT East)
					ret = true;
				}
				else if ((flets_type & FLETS_DETECT_TYPE_WEST_NGN_PRIVATE) &&
					GetIPViaDnsProxyForJapanFlets(ip, hostname, true, 0, cancel, FLETS_NGN_WEST_DNS_PROXY_HOSTNAME))
				{
					// FLET'S Hikar-Next (NTT West)
					ret = true;
				}
			}
		}
#endif

		if (QueryDnsCache(&ip2, hostname))
		{
			ret = true;

			Copy(ip, &ip2, sizeof(IP));
		}
	}


	ReleaseGetIPThreadParam(p);

	return ret;
}
bool GetIP4Ex(IP *ip, char *hostname, UINT timeout, bool *cancel)
{
	return GetIP4Ex6Ex(ip, hostname, timeout, false, cancel);
}
bool GetIP6Ex(IP *ip, char *hostname, UINT timeout, bool *cancel)
{
	return GetIP4Ex6Ex(ip, hostname, timeout, true, cancel);
}
bool GetIP4(IP *ip, char *hostname)
{
	return GetIP4Ex(ip, hostname, 0, NULL);
}
bool GetIP6(IP *ip, char *hostname)
{
	return GetIP6Ex(ip, hostname, 0, NULL);
}

// Perform a DNS forward lookup query
bool GetIP(IP *ip, char *hostname)
{
	return GetIPEx(ip, hostname, false);
}
bool GetIPEx(IP *ip, char *hostname, bool ipv6)
{
	if (ipv6 == false)
	{
		return GetIP4(ip, hostname);
	}
	else
	{
		return GetIP6(ip, hostname);
	}
}
bool GetIP6Inner(IP *ip, char *hostname)
{
	struct sockaddr_in6 in;
	struct in6_addr addr;
	struct addrinfo hint;
	struct addrinfo *info;
	// Validate arguments
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	if (IsEmptyStr(hostname))
	{
		return false;
	}

	if (StrCmpi(hostname, "localhost") == 0)
	{
		GetLocalHostIP6(ip);
		return true;
	}

	if (StrToIP6(ip, hostname) == false && StrToIP(ip, hostname) == false)
	{
		// Forward resolution
		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET6;
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_TCP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) != 0 ||
			info->ai_family != AF_INET6)
		{
			if (info)
			{
				freeaddrinfo(info);
			}
			return QueryDnsCacheEx(ip, hostname, true);
		}
		// Forward resolution success
		Copy(&in, info->ai_addr, sizeof(struct sockaddr_in6));
		freeaddrinfo(info);

		Copy(&addr, &in.sin6_addr, sizeof(addr));
		InAddrToIP6(ip, &addr);
	}

	// Save Cache
	NewDnsCache(hostname, ip);

	return true;
}
bool GetIP4Inner(IP *ip, char *hostname)
{
	struct sockaddr_in in;
	struct in_addr addr;
	struct addrinfo hint;
	struct addrinfo *info;
	// Validate arguments
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	if (IsEmptyStr(hostname))
	{
		return false;
	}

	if (StrCmpi(hostname, "localhost") == 0)
	{
		SetIP(ip, 127, 0, 0, 1);
		return true;
	}

	if (StrToIP6(ip, hostname) == false && StrToIP(ip, hostname) == false)
	{
		// Forward resolution
		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_TCP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) != 0 ||
			info->ai_family != AF_INET)
		{
			if (info)
			{
				freeaddrinfo(info);
			}
			return QueryDnsCache(ip, hostname);
		}
		// Forward resolution success
		Copy(&in, info->ai_addr, sizeof(struct sockaddr_in));
		freeaddrinfo(info);
		Copy(&addr, &in.sin_addr, sizeof(addr));
		InAddrToIP(ip, &addr);
	}

	// Save Cache
	NewDnsCache(hostname, ip);

	return true;
}

// Search in the DNS cache
bool QueryDnsCache(IP *ip, char *hostname)
{
	return QueryDnsCacheEx(ip, hostname, false);
}
bool QueryDnsCacheEx(IP *ip, char *hostname, bool ipv6)
{
	DNSCACHE *c;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (ip == NULL || hostname == NULL)
	{
		return false;
	}

	GenDnsCacheKeyName(tmp, sizeof(tmp), hostname, ipv6);

	c = FindDnsCache(tmp);
	if (c == NULL)
	{
		return false;
	}

	Copy(ip, &c->IpAddress, sizeof(IP));

	return true;
}

// Convert the IP to a string
void IPToUniStr(wchar_t *str, UINT size, IP *ip)
{
	char tmp[128];

	IPToStr(tmp, sizeof(tmp), ip);
	StrToUni(str, size, tmp);
}

// Convert the IP to a string (32bit UINT)
void IPToUniStr32(wchar_t *str, UINT size, UINT ip)
{
	char tmp[128];

	IPToStr32(tmp, sizeof(tmp), ip);
	StrToUni(str, size, tmp);
}

// Convert the IP to a string (128bit byte array)
void IPToStr128(char *str, UINT size, UCHAR *ip_bytes)
{
	IP ip_st;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	SetIP6(&ip_st, ip_bytes);
	IPToStr(str, size, &ip_st);
}

// Convert the IP to a string (32bit UINT)
void IPToStr32(char *str, UINT size, UINT ip)
{
	IP ip_st;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	UINTToIP(&ip_st, ip);
	IPToStr(str, size, &ip_st);
}

// Convert IPv4 or IPv6 to a string
void IPToStr4or6(char *str, UINT size, UINT ip_4_uint, UCHAR *ip_6_bytes)
{
	IP ip4;
	IP ip6;
	IP ip;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	Zero(&ip, sizeof(ip));

	UINTToIP(&ip4, ip_4_uint);
	SetIP6(&ip6, ip_6_bytes);

	if (IsIP6(&ip4) || (IsZeroIp(&ip4) && (IsZeroIp(&ip6) == false)))
	{
		Copy(&ip, &ip6, sizeof(IP));
	}
	else
	{
		Copy(&ip, &ip4, sizeof(IP));
	}

	IPToStr(str, size, &ip);
}

// Convert the IP to a string
void IPToStr(char *str, UINT size, IP *ip)
{
	// Validate arguments
	if (str == NULL || ip == NULL)
	{
		return;
	}

	if (IsIP6(ip))
	{
		IPToStr6(str, size, ip);
	}
	else
	{
		IPToStr4(str, size, ip);
	}
}

// Convert the IPv4 to a string
void IPToStr4(char *str, UINT size, IP *ip)
{
	// Validate arguments
	if (str == NULL || ip == NULL)
	{
		return;
	}

	// Conversion
	snprintf(str, size != 0 ? size : 64, "%u.%u.%u.%u", ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3]);
}

// Convert the string to an IP
bool StrToIP(IP *ip, char *str)
{
	TOKEN_LIST *token;
	char *tmp;
	UINT i;
	// Validate arguments
	if (ip == NULL || str == NULL)
	{
		return false;
	}

	if (StrToIP6(ip, str))
	{
		return true;
	}

	Zero(ip, sizeof(IP));

	tmp = CopyStr(str);
	Trim(tmp);
	token = ParseToken(tmp, ".");
	Free(tmp);

	if (token->NumTokens != 4)
	{
		FreeToken(token);
		return false;
	}
	for (i = 0;i < 4;i++)
	{
		char *s = token->Token[i];
		if (s[0] < '0' || s[0] > '9' ||
			(ToInt(s) >= 256))
		{
			FreeToken(token);
			return false;
		}
	}
	Zero(ip, sizeof(IP));
	for (i = 0;i < 4;i++)
	{
		ip->addr[i] = (UCHAR)ToInt(token->Token[i]);
	}

	FreeToken(token);

	return true;
}
UINT StrToIP32(char *str)
{
	IP ip;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	if (StrToIP(&ip, str) == false)
	{
		return 0;
	}

	return IPToUINT(&ip);
}
bool UniStrToIP(IP *ip, wchar_t *str)
{
	char *tmp;
	bool ret;

	tmp = CopyUniToStr(str);
	ret = StrToIP(ip, tmp);
	Free(tmp);

	return ret;
}
UINT UniStrToIP32(wchar_t *str)
{
	UINT ret;
	char *tmp;

	tmp = CopyUniToStr(str);
	ret = StrToIP32(tmp);
	Free(tmp);

	return ret;
}

// Convert the IP to the in_addr
void IPToInAddr(struct in_addr *addr, IP *ip)
{
	UINT i;
	// Validate arguments
	if (addr == NULL || ip == NULL)
	{
		return;
	}

	Zero(addr, sizeof(struct in_addr));

	if (IsIP6(ip) == false)
	{
		for (i = 0;i < 4;i++)
		{
			((UCHAR *)addr)[i] = ip->addr[i];
		}
	}
}

// Convert the IP to the in6_addr
void IPToInAddr6(struct in6_addr *addr, IP *ip)
{
	UINT i;
	// Validate arguments
	if (addr == NULL || ip == NULL)
	{
		return;
	}

	Zero(addr, sizeof(struct in_addr));

	if (IsIP6(ip))
	{
		for (i = 0;i < 16;i++)
		{
			((UCHAR *)addr)[i] = ip->ipv6_addr[i];
		}
	}
}

// Convert the in_addr to the IP
void InAddrToIP(IP *ip, struct in_addr *addr)
{
	UINT i;
	// Validate arguments
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	for (i = 0;i < 4;i++)
	{
		ip->addr[i] = ((UCHAR *)addr)[i];
	}
}

// Convert the in6_addr to the IP
void InAddrToIP6(IP *ip, struct in6_addr *addr)
{
	UINT i;
	// Validate arguments
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	ZeroIP6(ip);
	for (i = 0;i < 16;i++)
	{
		ip->ipv6_addr[i] = ((UCHAR *)addr)[i];
	}
}

// Search in the DNS cache
DNSCACHE *FindDnsCache(char *hostname)
{
	return FindDnsCacheEx(hostname, false);
}
DNSCACHE *FindDnsCacheEx(char *hostname, bool ipv6)
{
	DNSCACHE *c;
	char tmp[MAX_SIZE];
	if (hostname == NULL)
	{
		return NULL;
	}

	GenDnsCacheKeyName(tmp, sizeof(tmp), hostname, ipv6);

	LockDnsCache();
	{
		DNSCACHE t;
		t.HostName = tmp;
		c = Search(DnsCache, &t);
	}
	UnlockDnsCache();

	return c;
}

// Generate the IPv4 / IPv6 key name for the DNS cache
void GenDnsCacheKeyName(char *dst, UINT size, char *src, bool ipv6)
{
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	if (ipv6 == false)
	{
		StrCpy(dst, size, src);
	}
	else
	{
		Format(dst, size, "%s@ipv6", src);
	}
}

// Registration of the new DNS cache
void NewDnsCache(char *hostname, IP *ip)
{
	NewDnsCacheEx(hostname, ip, IsIP6(ip));
}
void NewDnsCacheEx(char *hostname, IP *ip, bool ipv6)
{
	DNSCACHE *c;
	char tmp[MAX_PATH];
	// Validate arguments
	if (hostname == NULL || ip == NULL)
	{
		return;
	}

	if (IsNetworkNameCacheEnabled() == false)
	{
		return;
	}

	GenDnsCacheKeyName(tmp, sizeof(tmp), hostname, ipv6);

	LockDnsCache();
	{
		DNSCACHE t;

		// Search for anything matches to the hostname first
		t.HostName = tmp;
		c = Search(DnsCache, &t);

		if (c == NULL)
		{
			// Newly register
			c = ZeroMalloc(sizeof(DNSCACHE));
			c->HostName = CopyStr(tmp);

			Copy(&c->IpAddress, ip, sizeof(IP));

			Add(DnsCache, c);
		}
		else
		{
			// Update
			Copy(&c->IpAddress, ip, sizeof(IP));
		}
	}
	UnlockDnsCache();
}

// Name comparison of the DNS cache entries
int CompareDnsCache(void *p1, void *p2)
{
	DNSCACHE *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(DNSCACHE **)p1;
	c2 = *(DNSCACHE **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return StrCmpi(c1->HostName, c2->HostName);
}

// Initialization of the DNS cache
void InitDnsCache()
{
	// Creating a List
	DnsCache = NewList(CompareDnsCache);
}

// Release of the DNS cache
void FreeDnsCache()
{
	LockDnsCache();
	{
		DNSCACHE *c;
		UINT i;
		for (i = 0;i < LIST_NUM(DnsCache);i++)
		{
			// Release the memory for the entry
			c = LIST_DATA(DnsCache, i);
			Free(c->HostName);
			Free(c);
		}
	}
	UnlockDnsCache();

	// Release the list
	ReleaseList(DnsCache);
	DnsCache = NULL;
}

// Lock the DNS cache
void LockDnsCache()
{
	LockList(DnsCache);
}

// Unlock the DNS cache
void UnlockDnsCache()
{
	UnlockList(DnsCache);
}

// DH temp key callback
DH *TmpDhCallback(SSL *ssl, int is_export, int keylength)
{
	DH *ret = NULL;

	if (dh_2048 != NULL)
	{
		ret = dh_2048->dh;
	}

	return ret;
}

// Create the SSL_CTX
struct ssl_ctx_st *NewSSLCtx(bool server_mode)
{
	struct ssl_ctx_st *ctx = SSL_CTX_new(SSLv23_method());

#ifdef	SSL_OP_NO_TICKET
	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
#endif	// SSL_OP_NO_TICKET

#ifdef	SSL_OP_CIPHER_SERVER_PREFERENCE
	if (server_mode)
	{
		SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	}
#endif	// SSL_OP_CIPHER_SERVER_PREFERENCE

	SSL_CTX_set_tmp_dh_callback(ctx, TmpDhCallback);

#ifdef	SSL_CTX_set_ecdh_auto
	SSL_CTX_set_ecdh_auto(ctx, 1);
#endif	// SSL_CTX_set_ecdh_auto

	return ctx;
}

// Release of the SSL_CTX
void FreeSSLCtx(struct ssl_ctx_st *ctx)
{
	// Validate arguments
	if (ctx == NULL)
	{
		return;
	}

	SSL_CTX_free(ctx);
}

// The number of get ip threads
void SetGetIpThreadMaxNum(UINT num)
{
	max_getip_thread = num;
}
UINT GetGetIpThreadMaxNum()
{
	UINT ret = max_getip_thread;

	if (ret == 0)
	{
		ret = 0x7FFFFFFF;
	}

	return ret;
}
UINT GetCurrentGetIpThreadNum()
{
	return Count(getip_thread_counter);
}

// Initialize the network communication module
void InitNetwork()
{
	disable_gethostname_by_accept = false;


	InitDynList();


	host_ip_address_list_cache_lock = NewLock();
	host_ip_address_list_cache_last = 0;

	num_tcp_connections = NewCounter();

	getip_thread_counter = NewCounter();

	// Initialization of client list
	InitIpClientList();

	// Thread related initialization
	InitWaitThread();

	// Initialization of the host name cache
	InitHostCache();

#ifdef	OS_WIN32
	// Initializing the socket library
	Win32InitSocketLibrary();
#else
	UnixInitSocketLibrary();
#endif	// OS_WIN32

	// Initialization of the DNS cache
	InitDnsCache();

	// Locking initialization
	machine_name_lock = NewLock();
	disconnect_function_lock = NewLock();
	aho = NewLock();
	machine_ip_process_hash_lock = NewLock();
	socket_library_lock = NewLock();
	//ssl_connect_lock = NewLock();  //2012.9.28 Not required for recent OpenSSL
//	ssl_accept_lock = NewLock();
	dns_lock = NewLock();
	unix_dns_server_addr_lock = NewLock();
	Zero(&unix_dns_server, sizeof(unix_dns_server));
	local_mac_list_lock = NewLock();

	cipher_list_token = ParseToken(cipher_list, " ");

	current_global_ip_lock = NewLock();
	current_fqdn_lock = NewLock();
	current_global_ip_set = false;

	disable_cache = false;


	dh_2048 = DhNew2048();

	Zero(rand_port_numbers, sizeof(rand_port_numbers));

	SetGetIpThreadMaxNum(DEFAULT_GETIP_THREAD_MAX_NUM);
}

// Enable the network name cache
void EnableNetworkNameCache()
{
	disable_cache = false;
}

// Disable the network name cache
void DisableNetworkNameCache()
{
	disable_cache = true;
}

// Get whether the network name cache is enabled
bool IsNetworkNameCacheEnabled()
{
	return !disable_cache;
}

// Get the cipher algorithm list
TOKEN_LIST *GetCipherList()
{
	return cipher_list_token;
}

// Get the TCP connections counter
COUNTER *GetNumTcpConnectionsCounter()
{
	return num_tcp_connections;
}

// Get the current global IP address
bool GetCurrentGlobalIP(IP *ip, bool ipv6)
{
	bool ret = false;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	Zero(ip, sizeof(IP));

	Lock(current_global_ip_lock);
	{
		if (ipv6 == false)
		{
			Copy(ip, &current_glocal_ipv4, sizeof(IP));
		}
		else
		{
			Copy(ip, &current_glocal_ipv6, sizeof(IP));
		}

		ret = current_global_ip_set;
	}
	Unlock(current_global_ip_lock);

	return ret;
}

// Check whether the specified IP address is assigned to the local host
bool IsIPMyHost(IP *ip)
{
	LIST *o;
	UINT i;
	bool ret = false;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	if (IsZeroIp(ip))
	{
		return false;
	}

	// Search to check whether it matches to any of the IP of the local host
	o = GetHostIPAddressList();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP *p = LIST_DATA(o, i);

		if (CmpIpAddr(p, ip) == 0)
		{
			// Matched
			ret = true;
			break;
		}
	}

	FreeHostIPAddressList(o);

	if (ret == false)
	{
		if (IsLocalHostIP(ip))
		{
			// localhost IP addresses
			ret = true;
		}
	}

	return ret;
}

// Check whether the specified IP address is a private IP address
bool IsIPPrivate(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	if (ip->addr[0] == 10)
	{
		return true;
	}

	if (ip->addr[0] == 172)
	{
		if (ip->addr[1] >= 16 && ip->addr[1] <= 31)
		{
			return true;
		}
	}

	if (ip->addr[0] == 192 && ip->addr[1] == 168)
	{
		return true;
	}

	if (ip->addr[0] == 169 && ip->addr[1] == 254)
	{
		return true;
	}

	if (ip->addr[0] == 100)
	{
		if (ip->addr[1] >= 64 && ip->addr[1] <= 127)
		{
			return true;
		}
	}

	if (g_private_ip_list != NULL)
	{
		if (IsIP4(ip))
		{
			UINT ip4 = IPToUINT(ip);

			return IsOnPrivateIPFile(ip4);
		}
	}

	return false;
}

// Is the IP address either local or private?
bool IsIPLocalOrPrivate(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	if (IsIPPrivate(ip))
	{
		return true;
	}

	if (IsLocalHostIP(ip))
	{
		return true;
	}

	if (IsIPMyHost(ip))
	{
		return true;
	}

	return false;
}

// Read a private IP list file
void LoadPrivateIPFile()
{
	BUF *b = ReadDump(PRIVATE_IP_TXT_FILENAME);
	LIST *o;
	if (b == NULL)
	{
		return;
	}

	o = NewList(NULL);

	while (true)
	{
		char *line = CfgReadNextLine(b);
		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false)
		{
			UINT ip = 0, mask = 0;

			if (ParseIpAndSubnetMask4(line, &ip, &mask))
			{
				PRIVATE_IP_SUBNET *p = ZeroMalloc(sizeof(PRIVATE_IP_SUBNET));

				p->Ip = ip;
				p->Mask = mask;
				p->Ip2 = ip & mask;

				Add(o, p);
			}
		}

		Free(line);
	}

	g_private_ip_list = o;
	g_use_privateip_file = true;

	FreeBuf(b);
}

// Examine whether the specified IP address is in the private IP file
bool IsOnPrivateIPFile(UINT ip)
{
	bool ret = false;

	if (g_private_ip_list != NULL)
	{
		LIST *o = g_private_ip_list;
		UINT i;

		for (i = 0;i < LIST_NUM(o);i++)
		{
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			if ((ip & p->Mask) == p->Ip2)
			{
				ret = true;
			}
		}
	}

	return ret;
}

// Free the private IP file
void FreePrivateIPFile()
{
	if (g_private_ip_list != NULL)
	{
		LIST *o = g_private_ip_list;
		UINT i;

		g_private_ip_list = NULL;

		for (i = 0;i < LIST_NUM(o);i++)
		{
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			Free(p);
		}

		ReleaseList(o);
	}

	g_use_privateip_file = false;
}

// Check whether the specified IP address is in the same network to this computer
bool IsIPAddressInSameLocalNetwork(IP *a)
{
	bool ret = false;
	LIST *o;
	UINT i;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}

	o = GetHostIPAddressList();

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			IP *p = LIST_DATA(o, i);

			if (IsIP4(p))
			{
				if (IsZeroIp(p) == false && p->addr[0] != 127)
				{
					if (IsInSameNetwork4Standard(p, a))
					{
						ret = true;
						break;
					}
				}
			}
		}

		FreeHostIPAddressList(o);
	}

	return ret;
}

// Guess the IPv4, IPv6 global address from the IP address list of the current interface
void GetCurrentGlobalIPGuess(IP *ip, bool ipv6)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	o = GetHostIPAddressList();

	if (ipv6 == false)
	{
		// IPv4
		for (i = 0;i < LIST_NUM(o);i++)
		{
			IP *p = LIST_DATA(o, i);

			if (IsIP4(p))
			{
				if (IsZeroIp(p) == false && IsIPPrivate(p) == false && p->addr[0] != 127)
				{
					Copy(ip, p, sizeof(IP));
				}
			}
		}

		if (IsZeroIp(ip))
		{
			for (i = 0;i < LIST_NUM(o);i++)
			{
				IP *p = LIST_DATA(o, i);

				if (IsIP4(p))
				{
					if (IsZeroIp(p) == false && IsIPPrivate(p) && p->addr[0] != 127)
					{
						Copy(ip, p, sizeof(IP));
					}
				}
			}
		}

		if (IsZeroIp(ip))
		{
			SetIP(ip, 127, 0, 0, 1);
		}
	}
	else
	{
		// IPv6
		for (i = 0;i < LIST_NUM(o);i++)
		{
			IP *p = LIST_DATA(o, i);

			if (IsIP6(p))
			{
				UINT type = GetIPAddrType6(p);

				if ((type & IPV6_ADDR_GLOBAL_UNICAST) && ((type & IPV6_ADDR_ZERO) == 0) && ((type & IPV6_ADDR_LOOPBACK) == 0))
				{
					Copy(ip, p, sizeof(IP));
				}
			}
		}
	}

	FreeHostIPAddressList(o);
}

// Record the current global IP address
void SetCurrentGlobalIP(IP *ip, bool ipv6)
{
	// Validate arguments
	if (ip == NULL)
	{
		return;
	}

	if (IsZeroIp(ip));
	{
		return;
	}

	Lock(current_global_ip_lock);
	{
		if (ipv6 == false)
		{
			Copy(&current_glocal_ipv4, ip, sizeof(IP));
		}
		else
		{
			Copy(&current_glocal_ipv6, ip, sizeof(IP));
		}

		current_global_ip_set = true;
	}
	Unlock(current_global_ip_lock);
}

// Release of the network communication module
void FreeNetwork()
{

	if (dh_2048 != NULL)
	{
		DhFree(dh_2048);
		dh_2048 = NULL;
	}

	// Release of thread-related
	FreeWaitThread();

	FreeToken(cipher_list_token);
	cipher_list_token = NULL;

	Zero(&unix_dns_server, sizeof(unix_dns_server));

	// Release the locks
	DeleteLock(unix_dns_server_addr_lock);
	DeleteLock(dns_lock);
	DeleteLock(ssl_accept_lock);
	DeleteLock(machine_name_lock);
	DeleteLock(disconnect_function_lock);
	DeleteLock(aho);
	DeleteLock(socket_library_lock);
	DeleteLock(ssl_connect_lock);
	DeleteLock(machine_ip_process_hash_lock);
	machine_name_lock = NULL;
	ssl_accept_lock = machine_name_lock = disconnect_function_lock =
		aho = socket_library_lock = ssl_connect_lock = machine_ip_process_hash_lock = NULL;

	// Release of the DNS cache
	FreeDnsCache();

	// Release of the host name cache
	FreeHostCache();

#ifdef	OS_WIN32
	// Release of the socket library
	Win32FreeSocketLibrary();
#else
	UnixFreeSocketLibrary();
#endif	// OS_WIN32

	DeleteCounter(num_tcp_connections);
	num_tcp_connections = NULL;

	// Release of client list
	FreeIpClientList();

	DeleteLock(current_global_ip_lock);
	current_global_ip_lock = NULL;

	DeleteLock(current_fqdn_lock);
	current_fqdn_lock = NULL;

	// Release of the local MAC list
	if (local_mac_list != NULL)
	{
		FreeNicList(local_mac_list);
		local_mac_list = NULL;
	}

	DeleteLock(local_mac_list_lock);
	local_mac_list_lock = NULL;

	DeleteLock(host_ip_address_list_cache_lock);
	host_ip_address_list_cache_lock = NULL;

	FreeHostIPAddressList(host_ip_address_cache);
	host_ip_address_cache = NULL;


	FreeDynList();

	DeleteCounter(getip_thread_counter);
	getip_thread_counter = NULL;

}

// Add a socket to socket list
void AddSockList(SOCKLIST *sl, SOCK *s)
{
	// Validate arguments
	if (sl == NULL || s == NULL)
	{
		return;
	}

	LockList(sl->SockList);
	{
		if (IsInList(sl->SockList, s) == false)
		{
			AddRef(s->ref);

			Insert(sl->SockList, s);
		}
	}
	UnlockList(sl->SockList);
}

// Remove the socket from socket list
void DelSockList(SOCKLIST *sl, SOCK *s)
{
	// Validate arguments
	if (sl == NULL || s == NULL)
	{
		return;
	}

	LockList(sl->SockList);
	{
		if (Delete(sl->SockList, s))
		{
			ReleaseSock(s);
		}
	}
	UnlockList(sl->SockList);
}

// Stop all the sockets in the list and delete it
void StopSockList(SOCKLIST *sl)
{
	SOCK **ss;
	UINT num, i;
	// Validate arguments
	if (sl == NULL)
	{
		return;
	}

	LockList(sl->SockList);
	{
		num = LIST_NUM(sl->SockList);
		ss = ToArray(sl->SockList);

		DeleteAll(sl->SockList);
	}
	UnlockList(sl->SockList);

	for (i = 0;i < num;i++)
	{
		SOCK *s = ss[i];

		Disconnect(s);
		ReleaseSock(s);
	}

	Free(ss);
}

// Delete the socket list
void FreeSockList(SOCKLIST *sl)
{
	// Validate arguments
	if (sl == NULL)
	{
		return;
	}

	StopSockList(sl);

	ReleaseList(sl->SockList);

	Free(sl);
}

// Creating a socket list
SOCKLIST *NewSockList()
{
	SOCKLIST *sl = ZeroMallocFast(sizeof(SOCKLIST));

	sl->SockList = NewList(NULL);

	return sl;
}

// Time-out thread of the socket on Solaris
void SocketTimeoutThread(THREAD *t, void *param)
{
	SOCKET_TIMEOUT_PARAM *ttparam;
	ttparam = (SOCKET_TIMEOUT_PARAM *)param;

	// Wait for time-out period
	Select(NULL, ttparam->sock->TimeOut, ttparam->cancel, NULL);

	// Disconnect if it is blocked
	if(! ttparam->unblocked)
	{
//		Debug("Socket timeouted\n");
		closesocket(ttparam->sock->socket);
	}
	else
	{
//		Debug("Socket timeout cancelled\n");
	}
}

// Initialize and start the thread for time-out
SOCKET_TIMEOUT_PARAM *NewSocketTimeout(SOCK *sock)
{
	SOCKET_TIMEOUT_PARAM *ttp;
	if(! sock->AsyncMode && sock->TimeOut != TIMEOUT_INFINITE)
	{
//		Debug("NewSockTimeout(%u)\n",sock->TimeOut);

		ttp = (SOCKET_TIMEOUT_PARAM*)Malloc(sizeof(SOCKET_TIMEOUT_PARAM));

		// Set the parameters of the time-out thread
		ttp->cancel = NewCancel();
		ttp->sock = sock;
		ttp->unblocked = false;
		ttp->thread = NewThread(SocketTimeoutThread, ttp);
		return ttp;
	}
	return NULL;
}

// Stop and free the thread for timeout
void FreeSocketTimeout(SOCKET_TIMEOUT_PARAM *ttp)
{
	if(ttp == NULL)
	{
		return;
	}

	ttp->unblocked = true;
	Cancel(ttp->cancel);
	WaitThread(ttp->thread, INFINITE);
	ReleaseCancel(ttp->cancel);
	ReleaseThread(ttp->thread);
	Free(ttp);
//	Debug("FreeSocketTimeout succeed\n");
	return;
}

// Parse the IP address and subnet mask
bool ParseIpAndSubnetMask46(char *src, IP *ip, IP *mask)
{
	// Validate arguments
	if (src == NULL || ip == NULL || mask == NULL)
	{
		return false;
	}

	if (ParseIpAndMask46(src, ip, mask) == false)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		return IsSubnetMask4(mask);
	}
	else
	{
		return IsSubnetMask6(mask);
	}
}
bool ParseIpAndSubnetMask6(char *src, IP *ip, IP *mask)
{
	if (ParseIpAndSubnetMask46(src, ip, mask) == false)
	{
		return false;
	}

	if (IsIP6(ip) == false)
	{
		return false;
	}

	return true;
}
bool ParseIpAndSubnetMask4(char *src, UINT *ip, UINT *mask)
{
	IP ip2, mask2;
	// Validate arguments
	if (src == NULL)
	{
		return false;
	}

	if (ParseIpAndSubnetMask46(src, &ip2, &mask2) == false)
	{
		return false;
	}

	if (IsIP4(&ip2) == false)
	{
		return false;
	}

	if (ip != NULL)
	{
		*ip = IPToUINT(&ip2);
	}

	if (mask != NULL)
	{
		*mask = IPToUINT(&mask2);
	}

	return true;
}


// Parse the IP address and the mask
bool ParseIpAndMask46(char *src, IP *ip, IP *mask)
{
	TOKEN_LIST *t;
	char *ipstr;
	char *subnetstr;
	bool ret = false;
	IP ip2;
	IP mask2;
	// Validate arguments
	if (src == NULL || ip == NULL || mask == NULL)
	{
		return false;
	}

	Zero(&ip2, sizeof(IP));
	Zero(&mask2, sizeof(IP));

	t = ParseToken(src, "/");
	if (t->NumTokens != 2)
	{
		FreeToken(t);
		return false;
	}

	ipstr = t->Token[0];
	subnetstr = t->Token[1];
	Trim(ipstr);
	Trim(subnetstr);

	if (StrToIP(&ip2, ipstr))
	{
		if (StrToIP(&mask2, subnetstr))
		{
			// Compare the kind of the mask part and the IP address part to confirm same
			if (IsIP6(&ip2) && IsIP6(&mask2))
			{
				// Both are IPv6
				ret = true;
				Copy(ip, &ip2, sizeof(IP));
				Copy(mask, &mask2, sizeof(IP));
			}
			else if (IsIP4(&ip2) && IsIP4(&mask2))
			{
				// Both are IPv4
				ret = true;
				Copy(ip, &ip2, sizeof(IP));
				Copy(mask, &mask2, sizeof(IP));
			}
		}
		else
		{
			if (IsNum(subnetstr))
			{
				UINT i = ToInt(subnetstr);
				// Mask part is a number
				if (IsIP6(&ip2) && i <= 128)
				{
					ret = true;
					Copy(ip, &ip2, sizeof(IP));
					IntToSubnetMask6(mask, i);
				}
				else if (i <= 32)
				{
					ret = true;
					Copy(ip, &ip2, sizeof(IP));
					IntToSubnetMask4(mask, i);
				}
			}
		}
	}

	FreeToken(t);

	return ret;
}
bool ParseIpAndMask4(char *src, UINT *ip, UINT *mask)
{
	IP ip_ip, ip_mask;
	if (ParseIpAndMask46(src, &ip_ip, &ip_mask) == false)
	{
		return false;
	}

	if (IsIP4(&ip_ip) == false)
	{
		return false;
	}

	if (ip != NULL)
	{
		*ip = IPToUINT(&ip_ip);
	}

	if (mask != NULL)
	{
		*mask = IPToUINT(&ip_mask);
	}

	return true;
}
bool ParseIpAndMask6(char *src, IP *ip, IP *mask)
{
	if (ParseIpAndMask46(src, ip, mask) == false)
	{
		return false;
	}

	if (IsIP6(ip) == false)
	{
		return false;
	}

	return true;
}


// Check whether the specification of the IPv4 address is correct
bool IsIpStr4(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	if (StrToIP32(str) == 0 && StrCmpi(str, "0.0.0.0") != 0)
	{
		return false;
	}

	return true;
}

// Check whether the specification of the IPv6 address is correct
bool IsIpStr6(char *str)
{
	IP ip;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	if (StrToIP6(&ip, str) == false)
	{
		return false;
	}

	return true;
}

// Check whether the IP address specification is correct
bool IsIpStr46(char *str)
{
	if (IsIpStr4(str) || IsIpStr6(str))
	{
		return true;
	}

	return false;
}


// Convert the string to an IPv4 mask
bool StrToMask4(IP *mask, char *str)
{
	// Validate arguments
	if (mask == NULL || str == NULL)
	{
		return false;
	}

	if (str[0] == '/')
	{
		str++;
	}

	if (IsNum(str))
	{
		UINT n = ToInt(str);

		if (n <= 32)
		{
			IntToSubnetMask4(mask, n);
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		if (StrToIP(mask, str) == false)
		{
			return false;
		}
		else
		{
			return IsIP4(mask);
		}
	}
}

// Convert the string to an IPv6 mask
bool StrToMask6(IP *mask, char *str)
{
	// Validate arguments
	if (mask == NULL || str == NULL)
	{
		return false;
	}

	if (str[0] == '/')
	{
		str++;
	}

	if (IsNum(str))
	{
		UINT n = ToInt(str);

		if (n <= 128)
		{
			IntToSubnetMask6(mask, n);
			return true;
		}
		else
		{
			return false;
		}
	}
	else
	{
		if (StrToIP(mask, str) == false)
		{
			return false;
		}
		else
		{
			return IsIP6(mask);
		}
	}
}
bool StrToMask6Addr(IPV6_ADDR *mask, char *str)
{
	IP ip;

	if (StrToMask6(&ip, str) == false)
	{
		return false;
	}

	if (IPToIPv6Addr(mask, &ip) == false)
	{
		return false;
	}

	return true;
}

// Convert the string to an IPv4 / IPv6 mask
bool StrToMask46(IP *mask, char *str, bool ipv6)
{
	if (ipv6)
	{
		return StrToMask6(mask, str);
	}
	else
	{
		return StrToMask4(mask, str);
	}
}


// Convert the IPv4 / IPv6 mask to a string
void MaskToStr(char *str, UINT size, IP *mask)
{
	MaskToStrEx(str, size, mask, false);
}
void MaskToStrEx(char *str, UINT size, IP *mask, bool always_full_address)
{
	// Validate arguments
	if (str == NULL || mask == NULL)
	{
		return;
	}

	if (always_full_address == false && IsSubnetMask(mask))
	{
		ToStr(str, SubnetMaskToInt(mask));
	}
	else
	{
		IPToStr(str, size, mask);
	}
}
void MaskToStr32(char *str, UINT size, UINT mask)
{
	MaskToStr32Ex(str, size, mask, false);
}
void MaskToStr32Ex(char *str, UINT size, UINT mask, bool always_full_address)
{
	IP ip;

	UINTToIP(&ip, mask);

	MaskToStrEx(str, size, &ip, always_full_address);
}
void Mask6AddrToStrEx(char *str, UINT size, IPV6_ADDR *mask, bool always_full_address)
{
	IP ip;

	// Validate arguments
	if (str == NULL || mask == NULL)
	{
		StrCpy(str, size, "");
		return;
	}

	IPv6AddrToIP(&ip, mask);

	MaskToStrEx(str, size, &ip, always_full_address);
}
void Mask6AddrToStr(char *str, UINT size, IPV6_ADDR *mask)
{
	Mask6AddrToStrEx(str, size, mask, false);
}

// Disconnecting of the tube
void TubeDisconnect(TUBE *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (t->TubePairData == NULL)
	{
		return;
	}

	Lock(t->TubePairData->Lock);
	{
		t->TubePairData->IsDisconnected = true;

		Set(t->TubePairData->Event1);
		Set(t->TubePairData->Event2);
		SetSockEvent(t->TubePairData->SockEvent1);
		SetSockEvent(t->TubePairData->SockEvent2);
	}
	Unlock(t->TubePairData->Lock);
}

// Creating a tube pair
void NewTubePair(TUBE **t1, TUBE **t2, UINT size_of_header)
{
	TUBEPAIR_DATA *d;
	// Validate arguments
	if (t1 == NULL || t2 == NULL)
	{
		return;
	}

	*t1 = NewTube(size_of_header);
	*t2 = NewTube(size_of_header);

	(*t1)->IndexInTubePair = 0;
	(*t2)->IndexInTubePair = 1;

	d = NewTubePairData();
	AddRef(d->Ref);

	(*t1)->TubePairData = d;
	(*t2)->TubePairData = d;

	d->Event1 = (*t1)->Event;
	d->Event2 = (*t2)->Event;

	AddRef(d->Event1->ref);
	AddRef(d->Event2->ref);
}

// Creating a tube pair data
TUBEPAIR_DATA *NewTubePairData()
{
	TUBEPAIR_DATA *d = ZeroMalloc(sizeof(TUBEPAIR_DATA));

	d->Ref = NewRef();

	d->Lock = NewLock();

	return d;
}

// Set the SockEvent to the tube
void SetTubeSockEvent(TUBE *t, SOCK_EVENT *e)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Lock(t->Lock);
	{
		TUBEPAIR_DATA *d;

		if (t->SockEvent != e)
		{
			if (t->SockEvent != NULL)
			{
				ReleaseSockEvent(t->SockEvent);
			}

			if (e != NULL)
			{
				AddRef(e->ref);
			}

			t->SockEvent = e;
		}

		d = t->TubePairData;

		if (d != NULL)
		{
			Lock(d->Lock);
			{
				SOCK_EVENT **sep = (t->IndexInTubePair == 0 ? &d->SockEvent1 : &d->SockEvent2);

				if (*sep != e)
				{
					if (*sep != NULL)
					{
						ReleaseSockEvent(*sep);
					}

					if (e != NULL)
					{
						AddRef(e->ref);
					}

					*sep = e;
				}
			}
			Unlock(d->Lock);
		}
	}
	Unlock(t->Lock);
}

// Release of the tube pair data
void ReleaseTubePairData(TUBEPAIR_DATA *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	if (Release(d->Ref) == 0)
	{
		CleanupTubePairData(d);
	}
}
void CleanupTubePairData(TUBEPAIR_DATA *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	ReleaseEvent(d->Event1);
	ReleaseEvent(d->Event2);

	ReleaseSockEvent(d->SockEvent1);
	ReleaseSockEvent(d->SockEvent2);

	DeleteLock(d->Lock);

	Free(d);
}

// Check whether the tube is connected to the opponent still
bool IsTubeConnected(TUBE *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return false;
	}

	if (t->TubePairData == NULL)
	{
		return true;
	}

	if (t->TubePairData->IsDisconnected)
	{
		return false;
	}

	return true;
}

// Send the data to the tube
bool TubeSend(TUBE *t, void *data, UINT size, void *header)
{
	return TubeSendEx(t, data, size, header, false);
}
bool TubeSendEx(TUBE *t, void *data, UINT size, void *header, bool no_flush)
{
	return TubeSendEx2(t, data, size, header, no_flush, 0);
}
bool TubeSendEx2(TUBE *t, void *data, UINT size, void *header, bool no_flush, UINT max_num_in_queue)
{
	// Validate arguments
	if (t == NULL || data == NULL || size == 0)
	{
		return false;
	}

	if (IsTubeConnected(t) == false)
	{
		return false;
	}

	LockQueue(t->Queue);
	{
		if (max_num_in_queue == 0 || (t->Queue->num_item <= max_num_in_queue))
		{
			InsertQueue(t->Queue, NewTubeData(data, size, header, t->SizeOfHeader));
		}
		else
		{
			no_flush = true;
		}
	}
	UnlockQueue(t->Queue);

	if (no_flush == false)
	{
		Set(t->Event);
		SetSockEvent(t->SockEvent);
	}

	return true;
}

// Flush the tube
void TubeFlush(TUBE *t)
{
	TubeFlushEx(t, false);
}
void TubeFlushEx(TUBE *t, bool force)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (IsTubeConnected(t) == false)
	{
		return;
	}

	if (force == false)
	{
		if (t->Queue->num_item == 0)
		{
			return;
		}
	}

	Set(t->Event);
	SetSockEvent(t->SockEvent);
}

// Receive the data from the tube (asynchronous)
TUBEDATA *TubeRecvAsync(TUBE *t)
{
	TUBEDATA *d;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	if (IsTubeConnected(t) == false)
	{
		return NULL;
	}

	LockQueue(t->Queue);
	{
		d = GetNext(t->Queue);
	}
	UnlockQueue(t->Queue);

	return d;
}

// Get the SockEvent associated with the tube
SOCK_EVENT *GetTubeSockEvent(TUBE *t)
{
	SOCK_EVENT *e = NULL;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Lock(t->Lock);
	{
		if (t->SockEvent != NULL)
		{
			AddRef(t->SockEvent->ref);

			e = t->SockEvent;
		}
	}
	Unlock(t->Lock);

	return e;
}

// Receive the data from the tube (synchronous)
TUBEDATA *TubeRecvSync(TUBE *t, UINT timeout)
{
	UINT64 start_tick, timeout_tick;
	TUBEDATA *d = NULL;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	if (IsTubeConnected(t) == false)
	{
		return NULL;
	}

	start_tick = Tick64();
	timeout_tick = start_tick + (UINT64)timeout;

	while (true)
	{
		UINT64 now = Tick64();
		UINT remain_time;
		SOCK_EVENT *e;
		UINT interval;

		d = NULL;

		if (IsTubeConnected(t) == false)
		{
			break;
		}

		LockQueue(t->Queue);
		{
			d = GetNext(t->Queue);
		}
		UnlockQueue(t->Queue);

		if (d != NULL)
		{
			break;
		}

		if (timeout != INFINITE && now >= timeout_tick)
		{
			return NULL;
		}

		remain_time = (UINT)(timeout_tick - now);

		e = GetTubeSockEvent(t);

		interval = (timeout == INFINITE ? INFINITE : remain_time);

		if (e == NULL)
		{
			Wait(t->Event, interval);
		}
		else
		{
			WaitSockEvent(e, interval);

			ReleaseSockEvent(e);
		}
	}

	return d;
}

// Creating a tube
TUBE *NewTube(UINT size_of_header)
{
	TUBE *t = ZeroMalloc(sizeof(TUBE));

	t->Event = NewEvent();
	t->Queue = NewQueue();
	t->Ref = NewRef();
	t->Lock = NewLock();
	t->SockEvent = NewSockEvent();

	t->SizeOfHeader = size_of_header;

	return t;
}

// Release of the tube
void ReleaseTube(TUBE *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	if (Release(t->Ref) == 0)
	{
		CleanupTube(t);
	}
}
void CleanupTube(TUBE *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	while (true)
	{
		TUBEDATA *d = GetNext(t->Queue);
		if (d == NULL)
		{
			break;
		}

		FreeTubeData(d);
	}

	ReleaseQueue(t->Queue);
	ReleaseEvent(t->Event);
	ReleaseSockEvent(t->SockEvent);

	ReleaseTubePairData(t->TubePairData);

	DeleteLock(t->Lock);

	Free(t);
}

// Creating a tube data
TUBEDATA *NewTubeData(void *data, UINT size, void *header, UINT header_size)
{
	TUBEDATA *d;
	// Validate arguments
	if (size == 0 || data == NULL)
	{
		return NULL;
	}

	d = ZeroMalloc(sizeof(TUBEDATA));

	d->Data = Clone(data, size);
	d->DataSize = size;
	if (header != NULL)
	{
		d->Header = Clone(header, header_size);
		d->HeaderSize = header_size;
	}
	else
	{
		d->Header = ZeroMalloc(header_size);
	}

	return d;
}

// Release of the tube data
void FreeTubeData(TUBEDATA *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	Free(d->Data);
	Free(d->Header);

	Free(d);
}

// Release of the IP address list of the host
void FreeHostIPAddressList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP *ip = LIST_DATA(o, i);

		Free(ip);
	}

	ReleaseList(o);
}

// Get whether the specified IP address is held by this host
bool IsMyIPAddress(IP *ip)
{
	LIST *o;
	UINT i;
	bool ret = false;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	o = GetHostIPAddressList();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP *a = LIST_DATA(o, i);

		if (CmpIpAddr(ip, a) == 0)
		{
			ret = true;
			break;
		}
	}

	FreeHostIPAddressList(o);

	return ret;
}

// Add the IP address to the list
void AddHostIPAddressToList(LIST *o, IP *ip)
{
	IP *r;
	// Validate arguments
	if (o == NULL || ip == NULL)
	{
		return;
	}

	r = Search(o, ip);
	if (r != NULL)
	{
		return;
	}

	Insert(o, Clone(ip, sizeof(IP)));
}

// Comparison of the IP address list items
int CmpIpAddressList(void *p1, void *p2)
{
	IP *ip1, *ip2;
	UINT r;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	ip1 = *(IP **)p1;
	ip2 = *(IP **)p2;
	if (ip1 == NULL || ip2 == NULL)
	{
		return 0;
	}

	// IPv4 < IPv6
	r = COMPARE_RET(IsIP6(ip1), IsIP6(ip2));
	if (r != 0)
	{
		return r;
	}

	// any > specified IP
	if (IsZeroIP(ip1) && IsZeroIP(ip2) == false)
	{
		return 1;
	}
	if (IsZeroIP(ip1) == false && IsZeroIP(ip2))
	{
		return -1;
	}

	// local > others
	if (IsLocalHostIP(ip1) && IsLocalHostIP(ip2) == false)
	{
		return 1;
	}
	if (IsLocalHostIP(ip1) == false && IsLocalHostIP(ip2))
	{
		return -1;
	}

	// ip address
	r = CmpIpAddr(ip1, ip2);
	if (r != 0)
	{
		return r;
	}

	// interface index
	if (IsIP6(ip1))
	{
		r = COMPARE_RET(ip1->ipv6_scope_id, ip2->ipv6_scope_id);
	}
	else
	{
		r = 0;
	}

	return r;
}

// Get the IP address list hash of the host
UINT64 GetHostIPAddressListHash()
{
	UINT i;
	LIST *o;
	BUF *buf = NewBuf();
	UCHAR hash[SHA1_SIZE];
	UINT64 ret = 0;

	o = GetHostIPAddressList();

	if (o != NULL)
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			IP *ip = LIST_DATA(o, i);
			char tmp[128];

			Zero(tmp, sizeof(tmp));
			IPToStr(tmp, sizeof(tmp), ip);

			WriteBufStr(buf, tmp);
		}

		FreeHostIPAddressList(o);
	}

	WriteBufStr(buf, "test");

	HashSha1(hash, buf->Buf, buf->Size);

	FreeBuf(buf);

	Copy(&ret, hash, sizeof(UINT64));

	ret = Endian64(ret);

	return ret;
}

// Get the IP address list of the host (using cache)
LIST *GetHostIPAddressList()
{
	LIST *o = NULL;
	if (host_ip_address_list_cache_lock == NULL)
	{
		return GetHostIPAddressListInternal();
	}

	Lock(host_ip_address_list_cache_lock);
	{
		UINT64 now = Tick64();

		if (host_ip_address_list_cache_last == 0 ||
			((host_ip_address_list_cache_last + (UINT64)HOST_IP_ADDRESS_LIST_CACHE) < now) ||
			host_ip_address_cache == NULL)
		{
			if (host_ip_address_cache != NULL)
			{
				FreeHostIPAddressList(host_ip_address_cache);
			}

			host_ip_address_cache = GetHostIPAddressListInternal();

			host_ip_address_list_cache_last = now;
		}

		o = CloneIPAddressList(host_ip_address_cache);
	}
	Unlock(host_ip_address_list_cache_lock);

	if (o == NULL)
	{
		o = GetHostIPAddressListInternal();
	}

	return o;
}

// Copy of the IP address list
LIST *CloneIPAddressList(LIST *o)
{
	LIST *ret;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	ret = NewListFast(CmpIpAddressList);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP *ip = LIST_DATA(o, i);

		if (ip != NULL)
		{
			ip = Clone(ip, sizeof(IP));

			Add(ret, ip);
		}
	}

	return ret;
}

// Get an IP address list of the host
LIST *GetHostIPAddressListInternal()
{
	char hostname[MAX_SIZE];
	LIST *o;
	IP any6, any4;
	IP local6, local4;
	bool is_v6_supported = IsIPv6Supported();

	GetLocalHostIP4(&local4);
	GetLocalHostIP6(&local6);

	ZeroIP4(&any4);
	ZeroIP6(&any6);

	Zero(hostname, sizeof(hostname));

	gethostname(hostname, sizeof(hostname));

	o = NewListFast(CmpIpAddressList);

	// any
	AddHostIPAddressToList(o, &any4);
	if (is_v6_supported)
	{
		AddHostIPAddressToList(o, &any6);
	}

	// localhost
	AddHostIPAddressToList(o, &local4);
	if (is_v6_supported)
	{
		AddHostIPAddressToList(o, &local6);
	}

#ifndef	MAYAQUA_SUPPORTS_GETIFADDRS
	// IPv4
	if (true)
	{
		struct sockaddr_in in;
		struct in_addr addr;
		struct addrinfo hint;
		struct addrinfo *info;

		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) == 0)
		{
			if (info->ai_family == AF_INET)
			{
				struct addrinfo *current = info;
				while (current != NULL)
				{
					IP ip;

					Copy(&in, current->ai_addr, sizeof(in));
					Copy(&addr, &in.sin_addr, sizeof(addr));

					InAddrToIP(&ip, &addr);
					AddHostIPAddressToList(o, &ip);

					current = current->ai_next;
				}
			}

			freeaddrinfo(info);
		}
	}

#ifndef	UNIX_LINUX
	// IPv6
	if (is_v6_supported)
	{
		struct sockaddr_in6 in;
		struct in6_addr addr;
		struct addrinfo hint;
		struct addrinfo *info;

		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET6;
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) == 0)
		{
			if (info->ai_family == AF_INET6)
			{
				struct addrinfo *current = info;
				while (current != NULL)
				{
					IP ip;

					Copy(&in, current->ai_addr, sizeof(in));
					Copy(&addr, &in.sin6_addr, sizeof(addr));

					InAddrToIP6(&ip, &addr);
					ip.ipv6_scope_id = in.sin6_scope_id;

					AddHostIPAddressToList(o, &ip);

					current = current->ai_next;
				}
			}

			freeaddrinfo(info);
		}
	}
#endif	// UNIX_LINUX
#endif	// MAYAQUA_SUPPORTS_GETIFADDRS

#ifdef	MAYAQUA_SUPPORTS_GETIFADDRS
	// If the getifaddrs is available, use this
	if (true)
	{
		struct ifaddrs *aa = NULL;

		if (getifaddrs(&aa) == 0)
		{
			struct ifaddrs *a = aa;

			while (a != NULL)
			{
				if (a->ifa_addr != NULL)
				{
					 struct sockaddr *addr = a->ifa_addr;

					 if (addr->sa_family == AF_INET)
					 {
						 IP ip;
						 struct sockaddr_in *d = (struct sockaddr_in *)addr;
						 struct in_addr *addr = &d->sin_addr;

						 InAddrToIP(&ip, addr);

						 AddHostIPAddressToList(o, &ip);
					 }
					 else if (addr->sa_family == AF_INET6)
					 {
						 IP ip;
						 struct sockaddr_in6 *d = (struct sockaddr_in6 *)addr;
						 UINT scope_id = d->sin6_scope_id;
						 struct in6_addr *addr = &d->sin6_addr;

						 InAddrToIP6(&ip, addr);
						 ip.ipv6_scope_id = scope_id;

						 AddHostIPAddressToList(o, &ip);
					 }
				}

				a = a->ifa_next;
			}

			freeifaddrs(aa);
		}
	}
#endif	// MAYAQUA_SUPPORTS_GETIFADDRS

	return o;
}

// Get whether the UDP listener opens the specified port
bool IsUdpPortOpened(UDPLISTENER *u, IP *server_ip, UINT port)
{
	UINT i;
	// Validate arguments
	if (u == NULL || port == 0)
	{
		return false;
	}

	if (server_ip != NULL)
	{
		for (i = 0;i < LIST_NUM(u->SockList);i++)
		{
			UDPLISTENER_SOCK *us = LIST_DATA(u->SockList, i);

			if (us->Sock != NULL && us->HasError == false)
			{
				if (us->Port == port)
				{
					if (CmpIpAddr(server_ip, &us->IpAddress) == 0)
					{
						return true;
					}
				}
			}
		}
	}

	for (i = 0;i < LIST_NUM(u->SockList);i++)
	{
		UDPLISTENER_SOCK *us = LIST_DATA(u->SockList, i);

		if (us->Sock != NULL && us->HasError == false)
		{
			if (us->Port == port)
			{
				if (IsZeroIP(&us->IpAddress))
				{
					return true;
				}
			}
		}
	}

	return false;
}

// IP address acquisition thread
void QueryIpThreadMain(THREAD *thread, void *param)
{
	QUERYIPTHREAD *t = (QUERYIPTHREAD *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (t->Halt == false)
	{
		UINT next_wait_time = 0;
		IP ip;
		bool ok = false;

		if (GetIP4Ex(&ip, t->Hostname, 5000, &t->Halt))
		{
			if (IsZeroIP(&ip) == false)
			{
				Lock(t->Lock);
				{
					Copy(&t->Ip, &ip, sizeof(IP));
				}
				Unlock(t->Lock);

				ok = true;
			}
		}

		if (ok == false)
		{
			next_wait_time = t->IntervalLastNg;
		}
		else
		{
			next_wait_time = t->IntervalLastOk;
		}

		if (t->Halt)
		{
			break;
		}

		Wait(t->HaltEvent, next_wait_time);
	}
}

// Creating an IP address acquisition thread
QUERYIPTHREAD *NewQueryIpThread(char *hostname, UINT interval_last_ok, UINT interval_last_ng)
{
	QUERYIPTHREAD *t;

	t = ZeroMalloc(sizeof(QUERYIPTHREAD));

	t->HaltEvent = NewEvent();
	t->Lock = NewLock();
	StrCpy(t->Hostname, sizeof(t->Hostname), hostname);
	t->IntervalLastOk = interval_last_ok;
	t->IntervalLastNg = interval_last_ng;

	t->Thread = NewThread(QueryIpThreadMain, t);

	return t;
}

// Get the results of the IP address acquisition thread
bool GetQueryIpThreadResult(QUERYIPTHREAD *t, IP *ip)
{
	bool ret = false;
	Zero(ip, sizeof(IP));
	// Validate arguments
	if (t == NULL || ip == NULL)
	{
		return false;
	}

	Lock(t->Lock);

	if (IsZero(&t->Ip, sizeof(IP)))
	{
		ret = false;
	}
	else
	{
		Copy(ip, &t->Ip, sizeof(IP));
	}

	Unlock(t->Lock);

	return ret;
}

// Release of the IP address acquisition thread
void FreeQueryIpThread(QUERYIPTHREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	t->Halt = true;
	Set(t->HaltEvent);

	WaitThread(t->Thread, INFINITE);
	ReleaseThread(t->Thread);

	ReleaseEvent(t->HaltEvent);

	DeleteLock(t->Lock);

	Free(t);
}

// Get a public port list which is known by UDP listener
void UdpListenerGetPublicPortList(UDPLISTENER *u, char *dst, UINT size)
{
	UINT k;
	// Validate arguments
	ClearStr(dst, size);
	if (u == NULL || dst == NULL)
	{
		return;
	}

	LockList(u->PortList);
	{
		for (k = 0;k < LIST_NUM(u->SockList);k++)
		{
			UDPLISTENER_SOCK *us = LIST_DATA(u->SockList, k);

			if (us->PublicPort != 0)
			{
				char tmp[64];
				ToStr(tmp, us->PublicPort);
				StrCat(dst, size, tmp);
				StrCat(dst, size, " ");
			}
		}
	}
	UnlockList(u->PortList);

	Trim(dst);
}

// UDP listener thread
void UdpListenerThread(THREAD *thread, void *param)
{
	UDPLISTENER *u = (UDPLISTENER *)param;
	UINT i, j, k;
	UINT buf_size = 65536;
	void *buf;
	bool cont_flag;
	BUF *ip_list_buf = NewBuf();
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	buf = Malloc(buf_size);

	// Initializing the socket list
	u->SockList = NewList(NULL);

	u->LastCheckTick = 0;

//	u->PollMyIpAndPort = true;

	// Main loop
	while (u->Halt == false)
	{
		LIST *recv_list;
		UINT64 now = Tick64();
		UINT interval;
		bool stage_changed = false;
		IP nat_t_ip;

		Zero(&nat_t_ip, sizeof(nat_t_ip));


		if (u->LastCheckTick == 0 || (now >= (u->LastCheckTick + UDPLISTENER_CHECK_INTERVAL)))
		{
			LIST *iplist;
			LIST *del_us_list = NewListFast(NULL);
			BUF *ip_list_buf_new = NewBuf();

			u->LastCheckTick = now;

			// Obtain an IP address list
			iplist = GetHostIPAddressList();

			LockList(u->PortList);
			{
				for (k = 0;k < LIST_NUM(u->SockList);k++)
				{
					UDPLISTENER_SOCK *us = LIST_DATA(u->SockList, k);

					us->Mark = false;
				}

				// If the combination of the IP address and the port number doesn't exist in the list, add it to the list
				for (i = 0;i < LIST_NUM(iplist);i++)
				{
					IP *ip = LIST_DATA(iplist, i);

					WriteBuf(ip_list_buf_new, ip, sizeof(IP));

					for (j = 0;j < LIST_NUM(u->PortList);j++)
					{
						UINT k;
						UINT *port = LIST_DATA(u->PortList, j);
						bool existing = false;

						if (IsZeroIP(ip) && (IS_SPECIAL_PORT(*port)))
						{
							continue;
						}


						for (k = 0;k < LIST_NUM(u->SockList);k++)
						{
							UDPLISTENER_SOCK *us = LIST_DATA(u->SockList, k);

							if (CmpIpAddr(&us->IpAddress, ip) == 0 && us->Port == *port)
							{
								existing = true;

								us->Mark = true;

								break;
							}
						}

						if (existing == false)
						{
							UDPLISTENER_SOCK *us = ZeroMalloc(sizeof(UDPLISTENER_SOCK));

							Copy(&us->IpAddress, ip, sizeof(IP));
							us->Port = *port;

							us->Mark = true;

							Add(u->SockList, us);
						}
					}
				}

				// If any errors suspected or the combination of IP address and port number
				// has been regarded to delete already, delete it
				for (k = 0;k < LIST_NUM(u->SockList);k++)
				{
					UDPLISTENER_SOCK *us = LIST_DATA(u->SockList, k);

					if (us->Mark == false || us->HasError)
					{
						Debug("mark=%u error=%u\n", us->Mark, us->HasError);
						Add(del_us_list, us);
					}
				}

				for (i = 0;i < LIST_NUM(del_us_list);i++)
				{
					UDPLISTENER_SOCK *us = LIST_DATA(del_us_list, i);

					char ipstr[MAX_SIZE];

					IPToStr(ipstr, sizeof(ipstr), &us->IpAddress);
					Debug("Closed UDP Port %u at %s.\n", us->Port, ipstr);

					Delete(u->SockList, us);

					if (us->Sock != NULL)
					{
						Disconnect(us->Sock);
						ReleaseSock(us->Sock);
					}

					Free(us);
				}
			}
			UnlockList(u->PortList);

			// Open the UDP sockets which is not opend yet
			for (k = 0;k < LIST_NUM(u->SockList);k++)
			{
				UDPLISTENER_SOCK *us = LIST_DATA(u->SockList, k);

				if (us->Sock == NULL)
				{
					char ipstr[MAX_SIZE];

					IPToStr(ipstr, sizeof(ipstr), &us->IpAddress);

					if (us->ErrorDebugDisplayed == false)
					{
						Debug("Opening UDP Port %u at %s ...", us->Port, ipstr);
					}

					us->Sock = NewUDPEx2(us->Port, IsIP6(&us->IpAddress), &us->IpAddress);

					if (us->Sock != NULL)
					{
						if (us->ErrorDebugDisplayed == false)
						{
							Debug("Ok.\n");
						}
						else
						{
							Debug("Opening UDP Port %u at %s ...", us->Port, ipstr);
							Debug("Ok.\n");
						}
						JoinSockToSockEvent(us->Sock, u->Event);

						us->ErrorDebugDisplayed = false;
					}
					else
					{
						if (us->ErrorDebugDisplayed == false)
						{
							Debug("Error.\n");
						}

						us->ErrorDebugDisplayed = true;
					}
				}
			}

			FreeHostIPAddressList(iplist);

			ReleaseList(del_us_list);

			if (CompareBuf(ip_list_buf, ip_list_buf_new) == false)
			{
				u->HostIPAddressListChanged = true;
			}

			FreeBuf(ip_list_buf);
			ip_list_buf = ip_list_buf_new;
		}

LABEL_RESTART:

		stage_changed = false;

		recv_list = NewListFast(NULL);

		if (u->PollMyIpAndPort)
		{
			{
				// Create a thread to get a NAT-T IP address if necessary
				if (u->GetNatTIpThread == NULL)
				{
					char natt_hostname[MAX_SIZE];

					RUDPGetRegisterHostNameByIP(natt_hostname, sizeof(natt_hostname), NULL);

					u->GetNatTIpThread = NewQueryIpThread(natt_hostname, QUERYIPTHREAD_INTERVAL_LAST_OK, QUERYIPTHREAD_INTERVAL_LAST_NG);
				}

				GetQueryIpThreadResult(u->GetNatTIpThread, &nat_t_ip);
			}
		}

		// Receive the data that is arriving at the socket
		for (k = 0;k < LIST_NUM(u->SockList);k++)
		{
			UDPLISTENER_SOCK *us = LIST_DATA(u->SockList, k);

			if (us->Sock != NULL)
			{
				UINT num_ignore_errors = 0;

				if (u->PollMyIpAndPort && IsIP4(&us->IpAddress))
				{
					if (us->NextMyIpAndPortPollTick == 0 || us->NextMyIpAndPortPollTick <= now)
					{
						// Examine the self IP address and the self port number by using NAT-T server
						us->NextMyIpAndPortPollTick = now + (UINT64)GenRandInterval(UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MIN, UDP_NAT_T_NAT_STATUS_CHECK_INTERVAL_MAX);

						if (IsZeroIP(&nat_t_ip) == false
							)
						{
							UCHAR c = 'A';

							SendTo(us->Sock, &nat_t_ip, UDP_NAT_T_PORT, &c, 1);
						}
					}
				}

				while (true)
				{
					IP src_addr;
					UINT src_port;
					UDPPACKET *p;

					UINT size = RecvFrom(us->Sock, &src_addr, &src_port, buf, buf_size);
					if (size == 0)
					{
						// Socket failure
						if (us->Sock->IgnoreRecvErr == false)
						{
LABEL_FATAL_ERROR:
							Debug("RecvFrom has Error.\n");
							us->HasError = true;
						}
						else
						{
							if ((num_ignore_errors++) >= MAX_NUM_IGNORE_ERRORS)
							{
								goto LABEL_FATAL_ERROR;
							}
						}
						break;
					}
					else if (size == SOCK_LATER)
					{
						// No packet
						break;
					}
					//Debug("UDP %u\n", size);

					if (src_port == UDP_NAT_T_PORT && CmpIpAddr(&src_addr, &nat_t_ip) == 0)
					{
						// Receive a packet in which the IP address and the port number are written from the NAT-T server
						if (size >= 8)
						{
							IP my_ip;
							UINT my_port;

							if (RUDPParseIPAndPortStr(buf, size, &my_ip, &my_port))
							{
								Copy(&us->PublicIpAddress, &my_ip, sizeof(IP));
								us->PublicPort = my_port;
							}
						}
					}
					else
					{
						// Receive a regular packet
						p = NewUdpPacket(&src_addr, src_port, &us->Sock->LocalIP, us->Sock->LocalPort,
							Clone(buf, size), size);

						if (p->SrcPort == MAKE_SPECIAL_PORT(52))
						{
							p->SrcPort = p->DestPort = MAKE_SPECIAL_PORT(50);
						}

						Add(recv_list, p);
					}

					stage_changed = true;
				}
			}
		}

		// Pass the received packet to the procedure
		u->RecvProc(u, recv_list);

		// Release the packet 
		for (i = 0;i < LIST_NUM(recv_list);i++)
		{
			UDPPACKET *p = LIST_DATA(recv_list, i);

			FreeUdpPacket(p);
		}

		ReleaseList(recv_list);

		cont_flag = true;

		do
		{
			// When there are packets to be transmitted, transmit it
			LockList(u->SendPacketList);
			{
				UDPLISTENER_SOCK *last_us = NULL;
				IP last_src_ip;
				UINT last_src_port;

				Zero(&last_src_ip, sizeof(IP));
				last_src_port = 0;

				for (i = 0;i < LIST_NUM(u->SendPacketList);i++)
				{
					UDPPACKET *p = LIST_DATA(u->SendPacketList, i);
					UDPLISTENER_SOCK *us;

					if (last_us != NULL && last_src_port == p->SrcPort && CmpIpAddr(&last_src_ip, &p->SrcIP) == 0)
					{
						us = last_us;
					}
					else
					{
						// Search for a good interface for the transmission
						us = DetermineUdpSocketForSending(u, p);

						if (us != NULL)
						{
							last_us = us;
							last_src_port = p->SrcPort;
							Copy(&last_src_ip, &p->SrcIP, sizeof(IP));
						}
					}

					if (us != NULL)
					{
						// Send
						UINT ret = SendTo(us->Sock, &p->DstIP, p->DestPort, p->Data, p->Size);

						if (ret == 0)
						{
							if (us->Sock->IgnoreSendErr == false)
							{
								// Socket failure
								Debug("SendTo has Error.\n");
								us->HasError = true;
								last_us = NULL;
							}
						}
						else
						{
							if (ret != SOCK_LATER)
							{
								stage_changed = true;
							}
						}
					}

					FreeUdpPacket(p);
				}
				DeleteAll(u->SendPacketList);
			}
			UnlockList(u->SendPacketList);

			if (LIST_NUM(u->SendPacketList) == 0)
			{
				cont_flag = false;
			}
		}
		while (cont_flag);

		if (stage_changed && u->Halt == false)
		{
			goto LABEL_RESTART;
		}

		// Timing adjustment
		interval = GetNextIntervalForInterrupt(u->Interrupts);

		if (interval == INFINITE)
		{
			interval = UDPLISTENER_WAIT_INTERVAL;
		}
		else
		{
			interval = MIN(UDPLISTENER_WAIT_INTERVAL, interval);
		}

		if (interval >= 1)
		{
			WaitSockEvent(u->Event, interval);
		}
	}

	if (u->GetNatTIpThread != NULL)
	{
		FreeQueryIpThread(u->GetNatTIpThread);
	}

	// Release of the socket list
	for (i = 0;i < LIST_NUM(u->SockList);i++)
	{
		UDPLISTENER_SOCK *us = (UDPLISTENER_SOCK *)LIST_DATA(u->SockList, i);

		Disconnect(us->Sock);
		ReleaseSock(us->Sock);

		Free(us);
	}
	ReleaseList(u->SockList);

	FreeBuf(ip_list_buf);

	Free(buf);
}

// Select the best UDP socket to be used for transmission
UDPLISTENER_SOCK *DetermineUdpSocketForSending(UDPLISTENER *u, UDPPACKET *p)
{
	UINT i;
	// Validate arguments
	if (u == NULL || p == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(u->SockList);i++)
	{
		UDPLISTENER_SOCK *us = LIST_DATA(u->SockList, i);

		if (us->Sock != NULL && us->HasError == false)
		{
			if (us->Port == p->SrcPort)
			{
				if (CmpIpAddr(&us->IpAddress, &p->SrcIP) == 0)
				{
					return us;
				}
			}
		}
	}

	for (i = 0;i < LIST_NUM(u->SockList);i++)
	{
		UDPLISTENER_SOCK *us = LIST_DATA(u->SockList, i);

		if (us->Sock != NULL && us->HasError == false)
		{
			if (us->Port == p->SrcPort)
			{
				if (IsZeroIP(&us->IpAddress))
				{
					if ((IsIP4(&p->DstIP) && IsIP4(&us->IpAddress)) ||
						(IsIP6(&p->DstIP) && IsIP6(&us->IpAddress)))
					{
						return us;
					}
				}
			}
		}
	}

	return NULL;
}

// Release of the UDP packet
void FreeUdpPacket(UDPPACKET *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	Free(p->Data);
	Free(p);
}

// Create a new UDP packet
UDPPACKET *NewUdpPacket(IP *src_ip, UINT src_port, IP *dst_ip, UINT dst_port, void *data, UINT size)
{
	UDPPACKET *p;
	// Validate arguments
	if (data == NULL || size == 0 || dst_ip == NULL || dst_port == 0)
	{
		return NULL;
	}

	p = ZeroMalloc(sizeof(UDPPACKET));

	p->Data = data;
	p->Size = size;

	Copy(&p->SrcIP, src_ip, sizeof(IP));
	p->SrcPort = src_port;

	Copy(&p->DstIP, dst_ip, sizeof(IP));
	p->DestPort = dst_port;

	return p;
}

// Transmit the packets via UDP Listener
void UdpListenerSendPackets(UDPLISTENER *u, LIST *packet_list)
{
	UINT num = 0;
	// Validate arguments
	if (u == NULL || packet_list == NULL)
	{
		return;
	}

	LockList(u->SendPacketList);
	{
		UINT i;

		num = LIST_NUM(packet_list);

		for (i = 0;i < LIST_NUM(packet_list);i++)
		{
			UDPPACKET *p = LIST_DATA(packet_list, i);

			Add(u->SendPacketList, p);
		}
	}
	UnlockList(u->SendPacketList);

	if (num >= 1)
	{
		SetSockEvent(u->Event);
	}
}
void UdpListenerSendPacket(UDPLISTENER *u, UDPPACKET *packet)
{
	LIST *o;
	// Validate arguments
	if (u == NULL || packet == NULL)
	{
		return;
	}

	o = NewListFast(NULL);
	Add(o, packet);

	UdpListenerSendPackets(u, o);

	ReleaseList(o);
}

// Creating a UDP listener
UDPLISTENER *NewUdpListener(UDPLISTENER_RECV_PROC *recv_proc, void *param)
{
	UDPLISTENER *u;
	// Validate arguments
	if (recv_proc == NULL)
	{
		return NULL;
	}
	
	u = ZeroMalloc(sizeof(UDPLISTENER));

	u->Param = param;

	u->PortList = NewList(NULL);
	u->Event = NewSockEvent();

	u->RecvProc = recv_proc;
	u->SendPacketList = NewList(NULL);

	u->Interrupts = NewInterruptManager();

	u->Thread = NewThread(UdpListenerThread, u);

	return u;
}

// Release the UDP listener
void FreeUdpListener(UDPLISTENER *u)
{
	UINT i;
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	u->Halt = true;
	SetSockEvent(u->Event);

	WaitThread(u->Thread, INFINITE);
	ReleaseThread(u->Thread);
	ReleaseSockEvent(u->Event);

	ReleaseIntList(u->PortList);

	for (i = 0;i < LIST_NUM(u->SendPacketList);i++)
	{
		UDPPACKET *p = LIST_DATA(u->SendPacketList, i);

		FreeUdpPacket(p);
	}

	ReleaseList(u->SendPacketList);

	FreeInterruptManager(u->Interrupts);

	Free(u);
}

// Add the UDP port
void AddPortToUdpListener(UDPLISTENER *u, UINT port)
{
	// Validate arguments
	if (u == NULL || port == 0)
	{
		return;
	}

	LockList(u->PortList);
	{
		AddIntDistinct(u->PortList, port);
	}
	UnlockList(u->PortList);

	SetSockEvent(u->Event);
}

// Get the port list
UINT GetUdpListenerPortList(UDPLISTENER *u, UINT **port_list)
{
	UINT num_ports;
	// Validate arguments
	if (u == NULL || port_list == NULL)
	{
		return 0;
	}

	LockList(u->PortList);
	{
		UINT *ports;
		UINT i;
		
		num_ports = LIST_NUM(u->PortList);
		ports = ZeroMalloc(sizeof(UINT) * num_ports);

		for (i = 0;i < num_ports;i++)
		{
			ports[i] = *((UINT *)(LIST_DATA(u->PortList, i)));
		}

		*port_list = ports;
	}
	UnlockList(u->PortList);

	return num_ports;
}

// Dekete all the UDP ports
void DeleteAllPortFromUdpListener(UDPLISTENER *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	LockList(u->PortList);
	{
		UINT num_ports = LIST_NUM(u->PortList);
		UINT *ports = ZeroMalloc(sizeof(UINT) * num_ports);
		UINT i;

		for (i = 0;i < num_ports;i++)
		{
			ports[i] = *((UINT *)(LIST_DATA(u->PortList, i)));
		}

		for (i = 0;i < num_ports;i++)
		{
			UINT port = ports[i];

			DelInt(u->PortList, port);
		}

		Free(ports);
	}
	UnlockList(u->PortList);

	SetSockEvent(u->Event);
}

// Delete the UDP port
void DeletePortFromUdpListener(UDPLISTENER *u, UINT port)
{
	// Validate arguments
	if (u == NULL || port == 0)
	{
		return;
	}

	LockList(u->PortList);
	{
		DelInt(u->PortList, port);
	}
	UnlockList(u->PortList);

	SetSockEvent(u->Event);
}

// Sort function of the interrupt management list
int CmpInterruptManagerTickList(void *p1, void *p2)
{
	UINT64 *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	v1 = *(UINT64 **)p1;
	v2 = *(UINT64 **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	if (*v1 > *v2)
	{
		return 1;
	}
	else if (*v1 < *v2)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// Initialization of the interrupt management
INTERRUPT_MANAGER *NewInterruptManager()
{
	INTERRUPT_MANAGER *m = ZeroMalloc(sizeof(INTERRUPT_MANAGER));

	m->TickList = NewList(CmpInterruptManagerTickList);

	return m;
}

// Release of the interrupt management
void FreeInterruptManager(INTERRUPT_MANAGER *m)
{
	UINT i;
	// Validate arguments
	if (m == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(m->TickList);i++)
	{
		UINT64 *v = LIST_DATA(m->TickList, i);

		Free(v);
	}

	ReleaseList(m->TickList);

	Free(m);
}

// Add a number to the interrupt management
void AddInterrupt(INTERRUPT_MANAGER *m, UINT64 tick)
{
	// Validate arguments
	if (tick == 0)
	{
		return;
	}

	LockList(m->TickList);
	{
		if (Search(m->TickList, &tick) == NULL)
		{
			Insert(m->TickList, Clone(&tick, sizeof(UINT64)));
		}
	}
	UnlockList(m->TickList);
}

// Get the interval to the next calling
UINT GetNextIntervalForInterrupt(INTERRUPT_MANAGER *m)
{
	UINT ret = INFINITE;
	UINT i;
	LIST *o = NULL;
	UINT64 now = Tick64();
	// Validate arguments
	if (m == NULL)
	{
		return 0;
	}

	LockList(m->TickList);
	{
		// Remove entries older than now already
		for (i = 0;i < LIST_NUM(m->TickList);i++)
		{
			UINT64 *v = LIST_DATA(m->TickList, i);

			if (now >= *v)
			{
				ret = 0;

				if (o == NULL)
				{
					o = NewListFast(NULL);
				}

				Add(o, v);
			}
			else
			{
				break;
			}
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			UINT64 *v = LIST_DATA(o, i);

			Free(v);

			Delete(m->TickList, v);
		}

		if (o != NULL)
		{
			ReleaseList(o);
		}

		if (ret == INFINITE)
		{
			if (LIST_NUM(m->TickList) >= 1)
			{
				UINT64 *v = LIST_DATA(m->TickList, 0);

				ret = (UINT)(*v - now);
			}
		}
	}
	UnlockList(m->TickList);

	return ret;
}

// Let that the listening socket for the reverse socket to accept the new socket
void InjectNewReverseSocketToAccept(SOCK *listen_sock, SOCK *s, IP *client_ip, UINT client_port)
{
	bool ok = false;
	// Validate arguments
	if (listen_sock == NULL || s == NULL)
	{
		return;
	}

	LockQueue(listen_sock->ReverseAcceptQueue);
	{
		if (listen_sock->CancelAccept == false && listen_sock->Disconnecting == false)
		{
			InsertQueue(listen_sock->ReverseAcceptQueue, s);

			ok = true;

			s->ServerMode = true;
			s->IsReverseAcceptedSocket = true;

			Copy(&s->RemoteIP, client_ip, sizeof(IP));
			s->RemotePort = client_port;
		}
	}
	UnlockQueue(listen_sock->ReverseAcceptQueue);

	if (ok == false)
	{
		Disconnect(s);
		ReleaseSock(s);
	}
	else
	{
		Set(listen_sock->ReverseAcceptEvent);
	}
}

// Create a listening socket for the reverse socket
SOCK *ListenReverse()
{
	SOCK *s = NewSock();

	s->Type = SOCK_REVERSE_LISTEN;
	s->ListenMode = true;
	s->ReverseAcceptQueue = NewQueue();
	s->ReverseAcceptEvent = NewEvent();
	s->Connected = true;

	return s;
}

// Accept on the reverse socket
SOCK *AcceptReverse(SOCK *s)
{
	// Validate arguments
	if (s == NULL || s->Type != SOCK_REVERSE_LISTEN || s->ListenMode == false)
	{
		return NULL;
	}

	while (true)
	{
		SOCK *ret;
		if (s->Disconnecting || s->CancelAccept)
		{
			return NULL;
		}

		LockQueue(s->ReverseAcceptQueue);
		{
			ret = GetNext(s->ReverseAcceptQueue);
		}
		UnlockQueue(s->ReverseAcceptQueue);

		if (ret != NULL)
		{
			StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), SOCK_UNDERLAY_AZURE);

			return ret;
		}

		Wait(s->ReverseAcceptEvent, INFINITE);
	}
}

// Start listening on the in-process socket
SOCK *ListenInProc()
{
	SOCK *s = NewSock();

	s->Type = SOCK_INPROC;
	s->ListenMode = true;
	s->InProcAcceptQueue = NewQueue();
	s->InProcAcceptEvent = NewEvent();
	s->Connected = true;

	return s;
}

// Accept at the in-process socket
SOCK *AcceptInProc(SOCK *s)
{
	// Validate arguments
	if (s == NULL || s->Type != SOCK_INPROC || s->ListenMode == false)
	{
		return NULL;
	}

	while (true)
	{
		SOCK *ret;
		if (s->Disconnecting || s->CancelAccept)
		{
			return NULL;
		}

		LockQueue(s->InProcAcceptQueue);
		{
			ret = GetNext(s->InProcAcceptQueue);
		}
		UnlockQueue(s->InProcAcceptQueue);

		if (ret != NULL)
		{
			StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), SOCK_UNDERLAY_INPROC);

			return ret;
		}

		Wait(s->InProcAcceptEvent, INFINITE);
	}
}

// Connect by the in-process socket
SOCK *ConnectInProc(SOCK *listen_sock, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port)
{
	SOCK *ss, *sc;
	bool ok = false;
	// Validate arguments
	if (listen_sock == NULL || listen_sock->Type != SOCK_INPROC || listen_sock->ListenMode == false)
	{
		return NULL;
	}

	NewSocketPair(&sc, &ss, client_ip, client_port, server_ip, server_port);

	LockQueue(listen_sock->InProcAcceptQueue);
	{
		if (listen_sock->CancelAccept == false && listen_sock->Disconnecting == false)
		{
			InsertQueue(listen_sock->InProcAcceptQueue, ss);

			ok = true;
		}
	}
	UnlockQueue(listen_sock->InProcAcceptQueue);

	if (ok == false)
	{
		ReleaseSock(ss);
		ReleaseSock(sc);
		return NULL;
	}

	Set(listen_sock->InProcAcceptEvent);

	return sc;
}

// Creating a new socket pair
void NewSocketPair(SOCK **client, SOCK **server, IP *client_ip, UINT client_port, IP *server_ip, UINT server_port)
{
	IP iptmp;
	TUBE *t1, *t2;
	SOCK *sc, *ss;
	SOCK_EVENT *e1, *e2;
	// Validate arguments
	if (client == NULL || server == NULL)
	{
		return;
	}

	SetIP(&iptmp, 127, 0, 0, 1);
	if (client_ip == NULL)
	{
		client_ip = &iptmp;
	}
	if (server_ip == NULL)
	{
		server_ip = &iptmp;
	}

	// Creating a tube
	NewTubePair(&t1, &t2, 0);	// t1: C -> S,  t2: S -> C

	// Creating a socket event
	e1 = NewSockEvent();
	e2 = NewSockEvent();

	SetTubeSockEvent(t1, e1);
	SetTubeSockEvent(t2, e2);

	sc = NewInProcSocket(t1, t2);
	ss = NewInProcSocket(t2, t1);

	Copy(&sc->LocalIP, client_ip, sizeof(IP));
	sc->LocalPort = client_port;
	Copy(&sc->RemoteIP, server_ip, sizeof(IP));
	sc->RemotePort = server_port;

	Copy(&ss->LocalIP, server_ip, sizeof(IP));
	ss->LocalPort = server_port;
	Copy(&ss->RemoteIP, client_ip, sizeof(IP));
	ss->RemotePort = client_port;

	sc->Connected = true;
	sc->ServerMode = false;

	ss->Connected = true;
	ss->ServerMode = true;

	SetTimeout(sc, INFINITE);
	SetTimeout(ss, INFINITE);

	QuerySocketInformation(sc);
	QuerySocketInformation(ss);

	ReleaseSockEvent(e1);
	ReleaseSockEvent(e2);

	ReleaseTube(t1);
	ReleaseTube(t2);

	*client = sc;
	*server = ss;
}

// Creating a new in-process socket
SOCK *NewInProcSocket(TUBE *tube_send, TUBE *tube_recv)
{
	SOCK *s;
	// Validate arguments
	if (tube_recv == NULL || tube_send == NULL)
	{
		return NULL;
	}

	s = NewSock();

	s->Type = SOCK_INPROC;

	s->SendTube = tube_send;
	s->RecvTube = tube_recv;

	AddRef(tube_send->Ref);
	AddRef(tube_recv->Ref);

	s->InProcRecvFifo = NewFifo();

	s->Connected = true;

	return s;
}

// Transmission process for the in-process socket
UINT SendInProc(SOCK *sock, void *data, UINT size)
{
	if (sock == NULL || sock->Type != SOCK_INPROC || sock->Disconnecting || sock->Connected == false)
	{
		return 0;
	}

	if (IsTubeConnected(sock->SendTube) == false)
	{
		return 0;
	}

	if (TubeSend(sock->SendTube, data, size, NULL) == false)
	{
		return 0;
	}

	return size;
}

// Receiving process for the in-process socket
UINT RecvInProc(SOCK *sock, void *data, UINT size)
{
	FIFO *f;
	UINT ret;
	UINT timeout;
	UINT64 giveup_time;
	TUBEDATA *d = NULL;
	if (sock == NULL || sock->Type != SOCK_INPROC || sock->Disconnecting || sock->Connected == false)
	{
		return 0;
	}

	if (IsTubeConnected(sock->SendTube) == false)
	{
		return 0;
	}

	f = sock->InProcRecvFifo;
	if (f == NULL)
	{
		return 0;
	}

	// If there is data in the FIFO, return it immediately
	ret = ReadFifo(f, data, size);
	if (ret != 0)
	{
		return ret;
	}

	timeout = GetTimeout(sock);

	giveup_time = Tick64() + (UINT)timeout;

	// When there is no data in the FIFO, read the next data from the tube
	d = NULL;

	while (true)
	{
		UINT64 now = 0;
		UINT interval;

		if (sock->AsyncMode == false)
		{
			now = Tick64();

			if (now >= giveup_time)
			{
				break;
			}
		}

		d = TubeRecvAsync(sock->RecvTube);

		if (d != NULL)
		{
			break;
		}

		if (IsTubeConnected(sock->RecvTube) == false)
		{
			break;
		}

		if (sock->AsyncMode)
		{
			break;
		}

		interval = (UINT)(giveup_time - now);

		Wait(sock->RecvTube->Event, interval);
	}

	if (d == NULL)
	{
		if (IsTubeConnected(sock->RecvTube) == false)
		{
			return 0;
		}

		if (sock->AsyncMode == false)
		{
			// If a timeout occurs in synchronous mode, disconnect ir
			Disconnect(sock);

			return 0;
		}
		else
		{
			// If a timeout occurs in asynchronous mode, returns the blocking error 
			return SOCK_LATER;
		}
	}
	else
	{
		// If the received data is larger than the requested size, write the rest to FIFO
		if (d->DataSize > size)
		{
			WriteFifo(f, ((UCHAR *)d->Data) + size, d->DataSize - size);
			ret = size;
		}
		else
		{
			ret = d->DataSize;
		}

		Copy(data, d->Data, ret);

		FreeTubeData(d);

		return ret;
	}
}

// Wait for the arrival of data on multiple tubes
void WaitForTubes(TUBE **tubes, UINT num, UINT timeout)
{
	// Validate arguments
	if (num != 0 && tubes == NULL)
	{
		return;
	}
	if (timeout == 0)
	{
		return;
	}
	if (num == 0)
	{
		SleepThread(timeout);
		return;
	}

#ifdef	OS_WIN32
	Win32WaitForTubes(tubes, num, timeout);
#else	// OS_WIN32
	UnixWaitForTubes(tubes, num, timeout);
#endif	// OS_WIN32
}

#ifdef	OS_WIN32
void Win32WaitForTubes(TUBE **tubes, UINT num, UINT timeout)
{
	HANDLE array[MAXIMUM_WAIT_OBJECTS];
	UINT i;

	Zero(array, sizeof(array));

	for (i = 0;i < num;i++)
	{
		TUBE *t = tubes[i];

		array[i] = t->Event->pData;
	}

	if (num == 1)
	{
		WaitForSingleObject(array[0], timeout);
	}
	else
	{
		WaitForMultipleObjects(num, array, false, timeout);
	}
}
#else	// OS_WIN32
void UnixWaitForTubes(TUBE **tubes, UINT num, UINT timeout)
{
	int *fds;
	UINT i;
	char tmp[MAX_SIZE];
	bool any_of_tubes_are_readable = false;

	fds = ZeroMalloc(sizeof(int) * num);

	for (i = 0;i < num;i++)
	{
		fds[i] = tubes[i]->SockEvent->pipe_read;

		if (tubes[i]->SockEvent->current_pipe_data != 0)
		{
			any_of_tubes_are_readable = true;
		}
	}

	if (any_of_tubes_are_readable == false)
	{
		UnixSelectInner(num, fds, 0, NULL, timeout);
	}

	for (i = 0;i < num;i++)
	{
		int fd = fds[i];
		int readret;

		tubes[i]->SockEvent->current_pipe_data = 0;

		do
		{
			readret = read(fd, tmp, sizeof(tmp));
		}
		while (readret >= 1);
	}

	Free(fds);
}
#endif	// OS_WIN32

// Creating a Tube Flush List
TUBE_FLUSH_LIST *NewTubeFlushList()
{
	TUBE_FLUSH_LIST *f = ZeroMalloc(sizeof(TUBE_FLUSH_LIST));

	f->List = NewListFast(NULL);

	return f;
}

// Release of the Tube Flush List
void FreeTubeFlushList(TUBE_FLUSH_LIST *f)
{
	UINT i;
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(f->List);i++)
	{
		TUBE *t = LIST_DATA(f->List, i);

		ReleaseTube(t);
	}

	ReleaseList(f->List);

	Free(f);
}

// Add a Tube to the Tube Flush List
void AddTubeToFlushList(TUBE_FLUSH_LIST *f, TUBE *t)
{
	// Validate arguments
	if (f == NULL || t == NULL)
	{
		return;
	}

	if (t->IsInFlushList)
	{
		return;
	}

	if (IsInList(f->List, t) == false)
	{
		Add(f->List, t);

		AddRef(t->Ref);

		t->IsInFlushList = true;
	}
}

// Flush the all tubes in the Tube Flush List
void FlushTubeFlushList(TUBE_FLUSH_LIST *f)
{
	UINT i;
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(f->List);i++)
	{
		TUBE *t = LIST_DATA(f->List, i);

		TubeFlush(t);
		t->IsInFlushList = false;

		ReleaseTube(t);
	}

	DeleteAll(f->List);
}

// The server receives a PACK from the client
PACK *HttpServerRecv(SOCK *s)
{
	BUF *b;
	PACK *p;
	HTTP_HEADER *h;
	UINT size;
	UCHAR *tmp;
	HTTP_VALUE *v;
	UINT num_noop = 0;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

START:

	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		goto BAD_REQUEST;
	}

	if (StrCmpi(h->Method, "POST") != 0 ||
		StrCmpi(h->Target, HTTP_VPN_TARGET) != 0 ||
		StrCmpi(h->Version, "HTTP/1.1") != 0)
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	v = GetHttpValue(h, "Content-Type");
	if (v == NULL || StrCmpi(v->Data, HTTP_CONTENT_TYPE2) != 0)
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	size = GetContentLength(h);
	if (size == 0 || size > HTTP_PACK_MAX_SIZE)
	{
		FreeHttpHeader(h);
		goto BAD_REQUEST;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		FreeHttpHeader(h);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);
	FreeHttpHeader(h);

	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);

	// Determine whether it's a NOOP
	if (PackGetInt(p, "noop") != 0)
	{
		Debug("recv: noop\n");
		FreePack(p);

		p = PackError(0);
		PackAddInt(p, "noop", 1);
		if (HttpServerSend(s, p) == false)
		{
			FreePack(p);
			return NULL;
		}

		FreePack(p);

		num_noop++;

		if (num_noop > MAX_NOOP_PER_SESSION)
		{
			return NULL;
		}

		goto START;
	}

	return p;

BAD_REQUEST:
	// Return an error


	return NULL;
}

// Store the error value into PACK
PACK *PackError(UINT error)
{
	PACK *p;

	p = NewPack();
	PackAddInt(p, "error", error);

	return p;
}

// Get the error value from PACK
UINT GetErrorFromPack(PACK *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	return PackGetInt(p, "error");
}

// Client receives a PACK from the server
PACK *HttpClientRecv(SOCK *s)
{
	BUF *b;
	PACK *p;
	HTTP_HEADER *h;
	UINT size;
	UCHAR *tmp;
	HTTP_VALUE *v;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	h = RecvHttpHeader(s);
	if (h == NULL)
	{
		return NULL;
	}

	if (StrCmpi(h->Method, "HTTP/1.1") != 0 ||
		StrCmpi(h->Target, "200") != 0)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	v = GetHttpValue(h, "Content-Type");
	if (v == NULL || StrCmpi(v->Data, HTTP_CONTENT_TYPE2) != 0)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	size = GetContentLength(h);
	if (size == 0 || size > MAX_PACK_SIZE)
	{
		FreeHttpHeader(h);
		return NULL;
	}

	tmp = MallocEx(size, true);
	if (RecvAll(s, tmp, size, s->SecureMode) == false)
	{
		Free(tmp);
		FreeHttpHeader(h);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	Free(tmp);
	FreeHttpHeader(h);

	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);

	return p;
}

// Create an entry to PACK for the dummy
void CreateDummyValue(PACK *p)
{
	UINT size;
	UCHAR *buf;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	size = Rand32() % HTTP_PACK_RAND_SIZE_MAX;
	buf = Malloc(size);
	Rand(buf, size);

	PackAddData(p, "pencore", buf, size);

	Free(buf);
}

// Client sends a PACK to the server
bool HttpClientSend(SOCK *s, PACK *p)
{
	BUF *b;
	bool ret;
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char ip_str[MAX_SIZE];

	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	CreateDummyValue(p);

	b = PackToBuf(p);
	if (b == NULL)
	{
		return false;
	}

	h = NewHttpHeader("POST", HTTP_VPN_TARGET, "HTTP/1.1");

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());
	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Host", ip_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE2));

	ret = PostHttp(s, h, b->Buf, b->Size);

	FreeHttpHeader(h);
	FreeBuf(b);

	return ret;
}

// Server sends a PACK to the client
bool HttpServerSend(SOCK *s, PACK *p)
{
	BUF *b;
	bool ret;
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return false;
	}

	CreateDummyValue(p);

	b = PackToBuf(p);
	if (b == NULL)
	{
		return false;
	}

	h = NewHttpHeader("HTTP/1.1", "200", "OK");

	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());
	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE2));

	ret = PostHttp(s, h, b->Buf, b->Size);

	FreeHttpHeader(h);
	FreeBuf(b);

	return ret;
}

// Replace unsafe characters in target
void ReplaceUnsafeCharInTarget(char *target){
	UINT i;
	for(i = 0; target[i] ; i++) {
		if(target[i] == '<')
			target[i] = '(';
		else if(target[i] == '>')
			target[i] = ')';
	}
}

// Sending the 400 Bad Request: Invalid Hostname
bool HttpSendInvalidHostname(SOCK *s, char *method)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	// Get the host name
	//GetMachineName(host, MAX_SIZE);
	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	// Get the port number
	port = s->LocalPort;

	// Creating a header
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "400", "Bad Request");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// Creating a Data
	str = "<h1>Bad Request (Invalid Hostname)</h1>\n";

	// Transmission
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);

	return ret;
}

// Sending the 501 Not Implemented error
bool HttpSendNotImplemented(SOCK *s, char *method, char *target, char *version)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	// Validate arguments
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// Get the host name
	//GetMachineName(host, MAX_SIZE);
	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	// Get the port number
	port = s->LocalPort;

	// Creating a header
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "501", "Method Not Implemented");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// Creating a Data
	str_size = sizeof(http_501_str) * 2 + StrLen(target) + StrLen(host) + StrLen(method) + StrLen(version);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_501_str);

	// TARGET
	ReplaceUnsafeCharInTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// METHOD
	ReplaceStri(str, str_size, str, "$METHOD$", method);

	// VERSION
	ReplaceStri(str, str_size, str, "$VERSION$", version);

	// Transmission
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

// Sending a 404 Not Found error
bool HttpSendNotFound(SOCK *s, char *target)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	// Validate arguments
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// Get the host name
	//GetMachineName(host, MAX_SIZE);
	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	// Get the port number
	port = s->LocalPort;

	// Creating a header
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "404", "Not Found");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// Creating a Data
	str_size = sizeof(http_404_str) * 2 + StrLen(target) + StrLen(host);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_404_str);

	// TARGET
	ReplaceUnsafeCharInTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// Transmission
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

// Sending a 500 Server Error
bool HttpSendServerError(SOCK *s, char *target)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	// Validate arguments
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// Get the host name
	//GetMachineName(host, MAX_SIZE);
	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	// Get the port number
	port = s->LocalPort;

	// Creating a header
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "500", "Server Error");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// Creating a Data
	str_size = sizeof(http_500_str) * 2 + StrLen(target) + StrLen(host);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_500_str);

	// TARGET
	ReplaceUnsafeCharInTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// Transmission
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

// Sending a 403 Forbidden error
bool HttpSendForbidden(SOCK *s, char *target, char *server_id)
{
	HTTP_HEADER *h;
	char date_str[MAX_SIZE];
	char *str;
	UINT str_size;
	char port_str[MAX_SIZE];
	bool ret;
	char host[MAX_SIZE];
	UINT port;
	// Validate arguments
	if (s == NULL || target == NULL)
	{
		return false;
	}

	// Get the host name
	//GetMachineName(host, MAX_SIZE);
	Zero(host, sizeof(host));
	IPToStr(host, sizeof(host), &s->LocalIP);
	// Get the port number
	port = s->LocalPort;

	// Creating a header
	GetHttpDateStr(date_str, sizeof(date_str), SystemTime64());

	h = NewHttpHeader("HTTP/1.1", "403", "Forbidden");

	AddHttpValue(h, NewHttpValue("Date", date_str));
	AddHttpValue(h, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE));

	// Creating a Data
	str_size = sizeof(http_403_str) * 2 + StrLen(target) + StrLen(host);
	str = Malloc(str_size);
	StrCpy(str, str_size, http_403_str);

	// TARGET
	ReplaceUnsafeCharInTarget(target);
	ReplaceStri(str, str_size, str, "$TARGET$", target);

	// HOST
	ReplaceStri(str, str_size, str, "$HOST$", host);

	// PORT
	ToStr(port_str, port);
	ReplaceStri(str, str_size, str, "$PORT$", port_str);

	// Transmission
	ret = PostHttp(s, h, str, StrLen(str));

	FreeHttpHeader(h);
	Free(str);

	return ret;
}

// Get the date and time string for the HTTP header
void GetHttpDateStr(char *str, UINT size, UINT64 t)
{
	SYSTEMTIME s;
	static char *wday[] =
	{
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
	};
	static char *month[] =
	{
		"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
		"Nov", "Dec",
	};
	// Validate arguments
	if (str == NULL)
	{
		return;
	}
	UINT64ToSystem(&s, t);

	Format(str, size, "%s, %02u %s %04u %02u:%02u:%02u GMT",
		wday[s.wDayOfWeek], s.wDay, month[s.wMonth - 1], s.wYear,
		s.wHour, s.wMinute, s.wSecond);
}

// Get the Content-Length from the HTTP header
UINT GetContentLength(HTTP_HEADER *header)
{
	UINT ret;
	HTTP_VALUE *v;
	// Validate arguments
	if (header == NULL)
	{
		return 0;
	}

	v = GetHttpValue(header, "Content-Length");
	if (v == NULL)
	{
		return 0;
	}

	ret = ToInt(v->Data);

	return ret;
}

// Send the data in the HTTP
bool PostHttp(SOCK *s, HTTP_HEADER *header, void *post_data, UINT post_size)
{
	char *header_str;
	BUF *b;
	bool ret;
	// Validate arguments
	if (s == NULL || header == NULL || (post_size != 0 && post_data == NULL))
	{
		return false;
	}

	// Check whether the Content-Lentgh exists?
	if (GetHttpValue(header, "Content-Length") == NULL)
	{
		char tmp[MAX_SIZE];
		// Add because it does not exist
		ToStr(tmp, post_size);
		AddHttpValue(header, NewHttpValue("Content-Length", tmp));
	}

	// Convert the header to string
	header_str = HttpHeaderToStr(header);
	if (header_str == NULL)
	{
		return false;
	}
	b = NewBuf();
	WriteBuf(b, header_str, StrLen(header_str));
	Free(header_str);

	// Append the data
	WriteBuf(b, post_data, post_size);

	// Send
	ret = SendAll(s, b->Buf, b->Size, s->SecureMode);

	FreeBuf(b);

	return ret;
}

// Convert a HTTP header to a string
char *HttpHeaderToStr(HTTP_HEADER *header)
{
	BUF *b;
	char *tmp;
	UINT i;
	char *s;
	// Validate arguments
	if (header == NULL)
	{
		return NULL;
	}

	tmp = Malloc(HTTP_HEADER_LINE_MAX_SIZE);
	b = NewBuf();

	// Header
	Format(tmp, HTTP_HEADER_LINE_MAX_SIZE,
		"%s %s %s\r\n", header->Method, header->Target, header->Version);
	WriteBuf(b, tmp, StrLen(tmp));

	// Value
	for (i = 0;i < LIST_NUM(header->ValueList);i++)
	{
		HTTP_VALUE *v = (HTTP_VALUE *)LIST_DATA(header->ValueList, i);
		Format(tmp, HTTP_HEADER_LINE_MAX_SIZE,
			"%s: %s\r\n", v->Name, v->Data);
		WriteBuf(b, tmp, StrLen(tmp));
	}

	// Trailing newline
	WriteBuf(b, "\r\n", 2);
	s = Malloc(b->Size + 1);
	Copy(s, b->Buf, b->Size);
	s[b->Size] = 0;

	FreeBuf(b);
	Free(tmp);

	return s;
}

// Send the HTTP header
bool SendHttpHeader(SOCK *s, HTTP_HEADER *header)
{
	char *str;
	bool ret;
	// Validate arguments
	if (s == NULL || header == NULL)
	{
		return false;
	}

	// Convert to string
	str = HttpHeaderToStr(header);

	// Transmission
	ret = SendAll(s, str, StrLen(str), s->SecureMode);

	Free(str);

	return ret;
}

// Receive an HTTP header
HTTP_HEADER *RecvHttpHeader(SOCK *s)
{
	TOKEN_LIST *token = NULL;
	char *str = NULL;
	HTTP_HEADER *header = NULL;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	// Get the first line
	str = RecvLine(s, HTTP_HEADER_LINE_MAX_SIZE);
	if (str == NULL)
	{
		goto LABEL_ERROR;
	}

	// Split into tokens
	token = ParseToken(str, " ");
	if (token->NumTokens < 3)
	{
		goto LABEL_ERROR;
	}

	Free(str);
	str = NULL;

	// Creating a header object
	header = NewHttpHeader(token->Token[0], token->Token[1], token->Token[2]);

	if (StrCmpi(header->Version, "HTTP/0.9") == 0)
	{
		// The header ends with this line
		FreeToken(token);
		return header;
	}

	// Get the subsequent lines
	while (true)
	{
		UINT pos;
		HTTP_VALUE *v;
		char *value_name, *value_data;
		str = RecvLine(s, HTTP_HEADER_LINE_MAX_SIZE);
		if (str == NULL)
		{
			goto LABEL_ERROR;
		}
		Trim(str);

		if (StrLen(str) == 0)
		{
			// End of header
			Free(str);
			str = NULL;
			break;
		}

		// Get the position of the colon
		pos = SearchStr(str, ":", 0);
		if (pos == INFINITE)
		{
			// The colon does not exist
			goto LABEL_ERROR;
		}
		if ((pos + 1) >= StrLen(str))
		{
			// There is no data
			goto LABEL_ERROR;
		}

		// Divide into the name and the data
		value_name = Malloc(pos + 1);
		Copy(value_name, str, pos);
		value_name[pos] = 0;
		value_data = &str[pos + 1];

		v = NewHttpValue(value_name, value_data);
		if (v == NULL)
		{
			Free(value_name);
			goto LABEL_ERROR;
		}

		Free(value_name);

		AddHttpValue(header, v);
		Free(str);
	}

	FreeToken(token);

	return header;

LABEL_ERROR:
	// Memory release
	if (token)
	{
		FreeToken(token);
	}
	if (str)
	{
		Free(str);
	}
	if (header)
	{
		FreeHttpHeader(header);
	}
	return NULL;
}

// Receive a line
char *RecvLine(SOCK *s, UINT max_size)
{
	BUF *b;
	char c;
	char *str;
	// Validate arguments
	if (s == NULL || max_size == 0)
	{
		return NULL;
	}

	b = NewBuf();
	while (true)
	{
		UCHAR *buf;
		if (RecvAll(s, &c, sizeof(c), s->SecureMode) == false)
		{
			FreeBuf(b);
			return NULL;
		}
		WriteBuf(b, &c, sizeof(c));
		buf = (UCHAR *)b->Buf;
		if (b->Size > max_size)
		{
			FreeBuf(b);
			return NULL;
		}
		if (b->Size >= 1)
		{
			if (buf[b->Size - 1] == '\n')
			{
				b->Size--;
				if (b->Size >= 1)
				{
					if (buf[b->Size - 1] == '\r')
					{
						b->Size--;
					}
				}
				str = Malloc(b->Size + 1);
				Copy(str, b->Buf, b->Size);
				str[b->Size] = 0;
				FreeBuf(b);

				return str;
			}
		}
	}
}

// Creating a new HTTP value
HTTP_VALUE *NewHttpValue(char *name, char *data)
{
	HTTP_VALUE *v;
	// Validate arguments
	if (name == NULL || data == NULL)
	{
		return NULL;
	}

	v = ZeroMalloc(sizeof(HTTP_VALUE));

	v->Name = CopyStr(name);
	v->Data = CopyStr(data);

	Trim(v->Name);
	Trim(v->Data);

	return v;
}

// Look for the HTTP value from the HTTP header
HTTP_VALUE *GetHttpValue(HTTP_HEADER *header, char *name)
{
	HTTP_VALUE *v, t;
	// Validate arguments
	if (header == NULL || name == NULL)
	{
		return NULL;
	}

	t.Name = name;
	v = Search(header->ValueList, &t);
	if (v == NULL)
	{
		return NULL;
	}

	return v;
}

// Add a HTTP value to the HTTP header
void AddHttpValue(HTTP_HEADER *header, HTTP_VALUE *value)
{
	// Validate arguments
	if (header == NULL || value == NULL)
	{
		return;
	}

	if (LIST_NUM(header->ValueList) < HTTP_HEADER_MAX_LINES)
	{
		Insert(header->ValueList, value);
	}
	else
	{
		FreeHttpValue(value);
	}
}

// Create an HTTP header
HTTP_HEADER *NewHttpHeader(char *method, char *target, char *version)
{
	return NewHttpHeaderEx(method, target, version, false);
}
HTTP_HEADER *NewHttpHeaderEx(char *method, char *target, char *version, bool no_sort)
{
	HTTP_HEADER *header;
	// Validate arguments
	if (method == NULL || target == NULL || version == NULL)
	{
		return NULL;
	}

	header = ZeroMalloc(sizeof(HTTP_HEADER));

	header->Method = CopyStr(method);
	header->Target = CopyStr(target);
	header->Version = CopyStr(version);
	header->ValueList = NewListFast(no_sort ? NULL : CompareHttpValue);

	return header;
}

// Comparison function of the HTTP value
int CompareHttpValue(void *p1, void *p2)
{
	HTTP_VALUE *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(HTTP_VALUE **)p1;
	v2 = *(HTTP_VALUE **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}
	return StrCmpi(v1->Name, v2->Name);
}

// Release the HTTP value
void FreeHttpValue(HTTP_VALUE *value)
{
	// Validate arguments
	if (value == NULL)
	{
		return;
	}

	Free(value->Data);
	Free(value->Name);

	Free(value);
}

// Release the HTTP header
void FreeHttpHeader(HTTP_HEADER *header)
{
	UINT i;
	HTTP_VALUE **values;
	// Validate arguments
	if (header == NULL)
	{
		return;
	}

	Free(header->Method);
	Free(header->Target);
	Free(header->Version);

	values = ToArray(header->ValueList);
	for (i = 0;i < LIST_NUM(header->ValueList);i++)
	{
		FreeHttpValue(values[i]);
	}
	Free(values);

	ReleaseList(header->ValueList);

	Free(header);
}

// Receive a PACK
PACK *RecvPack(SOCK *s)
{
	PACK *p;
	BUF *b;
	void *data;
	UINT sz;
	// Validate arguments
	if (s == NULL || s->Type != SOCK_TCP)
	{
		return false;
	}

	if (RecvAll(s, &sz, sizeof(UINT), s->SecureMode) == false)
	{
		return false;
	}
	sz = Endian32(sz);
	if (sz > MAX_PACK_SIZE)
	{
		return false;
	}
	data = MallocEx(sz, true);
	if (RecvAll(s, data, sz, s->SecureMode) == false)
	{
		Free(data);
		return false;
	}

	b = NewBuf();
	WriteBuf(b, data, sz);
	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);
	Free(data);

	return p;
}

// Receive a PACK (with checking the hash)
PACK *RecvPackWithHash(SOCK *s)
{
	PACK *p;
	BUF *b;
	void *data;
	UINT sz;
	UCHAR hash1[SHA1_SIZE];
	UCHAR hash2[SHA1_SIZE];
	// Validate arguments
	if (s == NULL || s->Type != SOCK_TCP)
	{
		return false;
	}

	if (RecvAll(s, &sz, sizeof(UINT), s->SecureMode) == false)
	{
		return false;
	}
	sz = Endian32(sz);
	if (sz > MAX_PACK_SIZE)
	{
		return false;
	}
	data = MallocEx(sz, true);
	if (RecvAll(s, data, sz, s->SecureMode) == false)
	{
		Free(data);
		return false;
	}

	HashSha1(hash1, data, sz);
	if (RecvAll(s, hash2, sizeof(hash2), s->SecureMode) == false)
	{
		Free(data);
		return false;
	}

	if (Cmp(hash1, hash2, SHA1_SIZE) != 0)
	{
		Free(data);
		return false;
	}

	b = NewBuf();
	WriteBuf(b, data, sz);
	SeekBuf(b, 0, 0);
	p = BufToPack(b);
	FreeBuf(b);
	Free(data);

	return p;
}

// Send a PACK
bool SendPack(SOCK *s, PACK *p)
{
	BUF *b;
	UINT sz;
	// Validate arguments
	if (s == NULL || p == NULL || s->Type != SOCK_TCP)
	{
		return false;
	}

	b = PackToBuf(p);
	sz = Endian32(b->Size);

	SendAdd(s, &sz, sizeof(UINT));
	SendAdd(s, b->Buf, b->Size);
	FreeBuf(b);

	return SendNow(s, s->SecureMode);
}

// Send a Pack (with adding a hash)
bool SendPackWithHash(SOCK *s, PACK *p)
{
	BUF *b;
	UINT sz;
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (s == NULL || p == NULL || s->Type != SOCK_TCP)
	{
		return false;
	}

	b = PackToBuf(p);
	sz = Endian32(b->Size);

	SendAdd(s, &sz, sizeof(UINT));
	SendAdd(s, b->Buf, b->Size);
	HashSha1(hash, b->Buf, b->Size);
	SendAdd(s, hash, sizeof(hash));

	FreeBuf(b);

	return SendNow(s, s->SecureMode);
}

// Get SNI name from the data that has arrived to the TCP connection before accepting an SSL connection
bool GetSniNameFromPreSslConnection(SOCK *s, char *sni, UINT sni_size)
{
	UCHAR tmp[1500];
	UINT size;
	// Validate arguments
	if (s == NULL || sni == NULL)
	{
		return false;
	}

	size = Peek(s, tmp, sizeof(tmp));
	if (size == 0)
	{
		return false;
	}

	return GetSniNameFromSslPacket(tmp, size, sni, sni_size);
}

// Get SNI name from the SSL packet
bool GetSniNameFromSslPacket(UCHAR *packet_buf, UINT packet_size, char *sni, UINT sni_size)
{
	BUF *buf;
	bool ret = false;
	UCHAR content_type;
	USHORT version;
	USHORT handshake_length;

	// Validate arguments
	if (packet_buf == NULL || packet_size <= 11)
	{
		return false;
	}

	if (!(packet_buf[0] == 0x16 && packet_buf[1] >= 0x03 &&
		packet_buf[5] == 0x01 && packet_buf[6] == 0x00 &&
		packet_buf[9] >= 0x03))
	{
		return false;
	}

	buf = NewBufFromMemory(packet_buf, packet_size);

	if (ReadBuf(buf, &content_type, sizeof(UCHAR)) == sizeof(UCHAR) &&
		ReadBuf(buf, &version, sizeof(USHORT)) == sizeof(USHORT) &&
		ReadBuf(buf, &handshake_length, sizeof(USHORT)) == sizeof(USHORT))
	{
		version = Endian16(version);
		handshake_length = Endian16(handshake_length);

		if (content_type == 0x16 && version >= 0x0301)
		{
			UCHAR *handshake_data = Malloc(handshake_length);

			if (ReadBuf(buf, handshake_data, handshake_length) == handshake_length)
			{
				BUF *buf2 = NewBufFromMemory(handshake_data, handshake_length);
				USHORT handshake_type;
				USHORT handshake_length_2;

				if (ReadBuf(buf2, &handshake_type, sizeof(USHORT)) == sizeof(USHORT) &&
					ReadBuf(buf2, &handshake_length_2, sizeof(USHORT)) == sizeof(USHORT))
				{
					handshake_type = Endian16(handshake_type);
					handshake_length_2 = Endian16(handshake_length_2);

					if (handshake_type == 0x0100 && handshake_length_2 <= (handshake_length - 4))
					{
						USHORT version2;

						if (ReadBuf(buf2, &version2, sizeof(USHORT)) == sizeof(USHORT))
						{
							version2 = Endian16(version2);

							if (version2 >= 0x0301)
							{
								UCHAR rand[32];

								if (ReadBuf(buf2, rand, sizeof(rand)) == sizeof(rand))
								{
									UCHAR session_id_len;

									if (ReadBuf(buf2, &session_id_len, sizeof(UCHAR)) == sizeof(UCHAR))
									{
										if (ReadBuf(buf2, NULL, session_id_len) == session_id_len)
										{
											USHORT cipher_len;

											if (ReadBuf(buf2, &cipher_len, sizeof(USHORT)) == sizeof(USHORT))
											{
												cipher_len = Endian16(cipher_len);

												if (ReadBuf(buf2, NULL, cipher_len) == cipher_len)
												{
													UCHAR comps_len;

													if (ReadBuf(buf2, &comps_len, sizeof(UCHAR)) == sizeof(UCHAR))
													{
														if (ReadBuf(buf2, NULL, comps_len) == comps_len)
														{
															USHORT ext_length;

															if (ReadBuf(buf2, &ext_length, sizeof(USHORT)) == sizeof(USHORT))
															{
																UCHAR *ext_buf;

																ext_length = Endian16(ext_length);

																ext_buf = Malloc(ext_length);

																if (ReadBuf(buf2, ext_buf, ext_length) == ext_length)
																{
																	BUF *ebuf = NewBufFromMemory(ext_buf, ext_length);

																	while (ret == false)
																	{
																		USHORT type;
																		USHORT data_len;
																		UCHAR *data;

																		if (ReadBuf(ebuf, &type, sizeof(USHORT)) != sizeof(USHORT))
																		{
																			break;
																		}

																		if (ReadBuf(ebuf, &data_len, sizeof(USHORT)) != sizeof(USHORT))
																		{
																			break;
																		}

																		type = Endian16(type);
																		data_len = Endian16(data_len);

																		data = Malloc(data_len);

																		if (ReadBuf(ebuf, data, data_len) != data_len)
																		{
																			Free(data);
																			break;
																		}

																		if (type == 0x0000)
																		{
																			BUF *dbuf = NewBufFromMemory(data, data_len);

																			USHORT total_len;

																			if (ReadBuf(dbuf, &total_len, sizeof(USHORT)) == sizeof(USHORT))
																			{
																				UCHAR c;
																				total_len = Endian16(total_len);

																				if (ReadBuf(dbuf, &c, sizeof(UCHAR)) == sizeof(UCHAR))
																				{
																					if (c == 0)
																					{
																						USHORT name_len;

																						if (ReadBuf(dbuf, &name_len, sizeof(USHORT)) == sizeof(USHORT))
																						{
																							char *name_buf;
																							name_len = Endian16(name_len);

																							name_buf = ZeroMalloc(name_len + 1);

																							if (ReadBuf(dbuf, name_buf, name_len) == name_len)
																							{
																								if (StrLen(name_buf) >= 1)
																								{
																									ret = true;

																									StrCpy(sni, sni_size, name_buf);
																								}
																							}

																							Free(name_buf);
																						}
																					}
																				}
																			}

																			FreeBuf(dbuf);
																		}

																		Free(data);
																	}

																	FreeBuf(ebuf);
																}

																Free(ext_buf);
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}

				FreeBuf(buf2);
			}

			Free(handshake_data);
		}
	}

	FreeBuf(buf);

	if (ret)
	{
		Trim(sni);

		if (IsEmptyStr(sni))
		{
			ret = false;
		}
	}

	return ret;
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
