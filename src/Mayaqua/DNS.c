#include "DNS.h"

#include "Memory.h"
#include "Network.h"
#include "Object.h"
#include "Str.h"
#include "Tick64.h"

#ifdef OS_WIN32
#include <WS2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#endif

#ifndef AI_ALL
#define AI_ALL 0
#endif

#ifndef AI_V4MAPPED
#define AI_V4MAPPED 0
#endif

static bool cache_enabled;

static LIST *cache;
static LIST *cache_reverse;

static COUNTER *threads_counter;
static UINT threads_max;

int DnsCacheCompare(void *p1, void *p2)
{
	if (p1 == NULL || p2 == NULL)
	{
		return (p1 == NULL && p2 == NULL ? 0 : (p1 == NULL ? -1 : 1));
	}

	const DNS_CACHE *c1 = *(DNS_CACHE **)p1;
	const DNS_CACHE *c2 = *(DNS_CACHE **)p2;

	return StrCmpi(c1->Hostname, c2->Hostname);
}

int DnsCacheReverseCompare(void *p1, void *p2)
{
	if (p1 == NULL || p2 == NULL)
	{
		return (p1 == NULL && p2 == NULL ? 0 : (p1 == NULL ? -1 : 1));
	}

	const DNS_CACHE_REVERSE *c1 = *(DNS_CACHE_REVERSE **)p1;
	const DNS_CACHE_REVERSE *c2 = *(DNS_CACHE_REVERSE **)p2;

	return CmpIpAddr(&c1->IP, &c2->IP);
}

void DnsInit()
{
	threads_counter = NewCounter();
	DnsThreadNumMaxSet(DNS_THREAD_DEFAULT_NUM_MAX);

	cache = NewList(DnsCacheCompare);
	cache_reverse = NewList(DnsCacheReverseCompare);
	DnsCacheToggle(true);
}

void DnsFree()
{
	DnsCacheToggle(false);

	LockList(cache);
	{
		for (UINT i = 0; i < LIST_NUM(cache); ++i)
		{
			DNS_CACHE *entry = LIST_DATA(cache, i);
			Free((void *)entry->Hostname);
			FreeHostIPAddressList(entry->IPList_v6);
			FreeHostIPAddressList(entry->IPList_v4);
			Free(entry);
		}
	}
	UnlockList(cache);

	ReleaseList(cache);
	cache = NULL;

	LockList(cache_reverse);
	{
		for (UINT i = 0; i < LIST_NUM(cache_reverse); ++i)
		{
			DNS_CACHE_REVERSE *entry = LIST_DATA(cache_reverse, i);
			Free(entry->Hostname);
			Free(entry);
		}
	}
	UnlockList(cache_reverse);

	ReleaseList(cache_reverse);
	cache_reverse = NULL;

	DeleteCounter(threads_counter);
	threads_counter = NULL;
}

UINT DnsThreadNum()
{
	return Count(threads_counter);
}

UINT DnsThreadNumMax()
{
	return threads_max;
}

void DnsThreadNumMaxSet(const UINT max)
{
	threads_max = max;
}

bool DnsCacheIsEnabled()
{
	return cache_enabled;
}

void DnsCacheToggle(const bool enabled)
{
	cache_enabled = enabled;
}

DNS_CACHE *DnsCacheFind(const char *hostname)
{
	if (DnsCacheIsEnabled() == false || IsEmptyStr(hostname))
	{
		return NULL;
	}

	DNS_CACHE *entry;

	LockList(cache);
	{
		DNS_CACHE t;
		t.Hostname = hostname;
		entry = Search(cache, &t);
	}
	UnlockList(cache);

	return entry;
}

DNS_CACHE *DnsCacheUpdate(const char *hostname, const IP *ipv6, const IP *ipv4)
{
	if (DnsCacheIsEnabled() == false || IsEmptyStr(hostname))
	{
		return NULL;
	}

	LIST *iplist_v6 = NULL;
	LIST *iplist_v4 = NULL;

	if (ipv6 != NULL)
	{
		iplist_v6 = NewListFast(NULL);
		AddHostIPAddressToList(iplist_v6, ipv6);
	}

	if (ipv4 != NULL)
	{
		iplist_v4 = NewListFast(NULL);
		AddHostIPAddressToList(iplist_v4, ipv4);
	}

	DNS_CACHE *ret = DnsCacheUpdateEx(hostname, iplist_v6, iplist_v4);

	FreeHostIPAddressList(iplist_v6);
	FreeHostIPAddressList(iplist_v4);

	return ret;
}
DNS_CACHE *DnsCacheUpdateEx(const char *hostname, const LIST *iplist_v6, const LIST *iplist_v4)
{
	if (DnsCacheIsEnabled() == false || IsEmptyStr(hostname))
	{
		return NULL;
	}

	DNS_CACHE *entry;

	LockList(cache);
	{
		DNS_CACHE t;
		t.Hostname = hostname;
		entry = Search(cache, &t);

		if (iplist_v6 == NULL && iplist_v4 == NULL)
		{
			if (entry != NULL)
			{
				Delete(cache, entry);
				Free((void *)entry->Hostname);
				FreeHostIPAddressList(entry->IPList_v6);
				FreeHostIPAddressList(entry->IPList_v4);
				Free(entry);
				entry = NULL;
			}
		}
		else
		{
			if (entry == NULL)
			{
				entry = ZeroMalloc(sizeof(DNS_CACHE));
				entry->Hostname = CopyStr(hostname);

				Add(cache, entry);
			}

			entry->Expiration = Tick64();

			FreeHostIPAddressList(entry->IPList_v6);
			FreeHostIPAddressList(entry->IPList_v4);

			if (iplist_v6 != NULL)
			{
				entry->IPList_v6 = CloneIPAddressList(iplist_v6);
			}
			else
			{
				entry->IPList_v6 = NULL;
			}

			if (iplist_v4 != NULL)
			{
				entry->IPList_v4 = CloneIPAddressList(iplist_v4);
			}
			else
			{
				entry->IPList_v4 = NULL;
			}
		}
	}
	UnlockList(cache);

	return entry;
}

DNS_CACHE_REVERSE *DnsCacheReverseFind(const IP *ip)
{
	if (DnsCacheIsEnabled() == false || ip == NULL)
	{
		return NULL;
	}

	DNS_CACHE_REVERSE *entry;

	LockList(cache_reverse);
	{
		DNS_CACHE_REVERSE t;
		Copy(&t.IP, ip, sizeof(t.IP));
		entry = Search(cache_reverse, &t);
	}
	UnlockList(cache_reverse);

	return entry;
}

DNS_CACHE_REVERSE *DnsCacheReverseUpdate(const IP *ip, const char *hostname)
{
	if (DnsCacheIsEnabled() == false || IsZeroIP(ip))
	{
		return NULL;
	}

	DNS_CACHE_REVERSE *entry;

	LockList(cache_reverse);
	{
		DNS_CACHE_REVERSE t;
		Copy(&t.IP, ip, sizeof(t.IP));
		entry = Search(cache_reverse, &t);

		if (IsEmptyStr(hostname))
		{
			if (entry != NULL)
			{
				Delete(cache_reverse, entry);
				Free(entry);
				entry = NULL;
			}
		}
		else
		{
			if (entry == NULL)
			{
				entry = ZeroMalloc(sizeof(DNS_CACHE_REVERSE));
				Copy(&entry->IP, ip, sizeof(entry->IP));

				Add(cache_reverse, entry);
			}

			entry->Expiration = Tick64();

			if (StrCmp(entry->Hostname, hostname) != 0)
			{
				Free(entry->Hostname);
				entry->Hostname = CopyStr(hostname);
			}
		}
	}
	UnlockList(cache_reverse);

	return entry;
}

bool DnsResolve(IP *ipv6, IP *ipv4, const char *hostname, UINT timeout, volatile const bool *cancel_flag)
{
	if ((ipv6 == NULL && ipv4 == NULL) || IsEmptyStr(hostname))
	{
		return false;
	}

	LIST *iplist_v6 = NULL;
	LIST *iplist_v4 = NULL;

	bool ret = DnsResolveEx(&iplist_v6, &iplist_v4, hostname, timeout, cancel_flag);

	if (ipv6 != NULL && LIST_NUM(iplist_v6) > 0)
	{
		IP *ip = LIST_DATA(iplist_v6, 0);
		Copy(ipv6, ip, sizeof(IP));
	}
	else
	{
		Zero(ipv6, sizeof(IP));
	}

	if (ipv4 != NULL && LIST_NUM(iplist_v4) > 0)
	{
		IP *ip = LIST_DATA(iplist_v4, 0);
		Copy(ipv4, ip, sizeof(IP));
	}
	else
	{
		ZeroIP4(ipv4);
	}

	FreeHostIPAddressList(iplist_v6);
	FreeHostIPAddressList(iplist_v4);

	return ret;
}
bool DnsResolveEx(LIST **iplist_v6, LIST **iplist_v4, const char *hostname, UINT timeout, volatile const bool *cancel_flag)
{
	if (iplist_v6 == NULL || iplist_v4 == NULL || IsEmptyStr(hostname))
	{
		return false;
	}

	if (StrCmpi(hostname, "localhost") == 0)
	{
		IP ipv6, ipv4;
		GetLocalHostIP6(&ipv6);
		GetLocalHostIP4(&ipv4);
		*iplist_v6 = NewListFast(NULL);
		*iplist_v4 = NewListFast(NULL);
		AddHostIPAddressToList(*iplist_v6, &ipv6);
		AddHostIPAddressToList(*iplist_v4, &ipv4);
		return true;
	}

	IP ip;
	if (StrToIP(&ip, hostname))
	{
		if (IsIP6(&ip))
		{
			*iplist_v6 = NewListFast(NULL);
			AddHostIPAddressToList(*iplist_v6, &ip);
			return true;
		}
		else
		{
			*iplist_v4 = NewListFast(NULL);
			AddHostIPAddressToList(*iplist_v4, &ip);
			return true;
		}

		return false;
	}

	if (DnsThreadNum() > DnsThreadNumMax())
	{
		Debug("DnsResolve(): Too many threads! Current: %u, Maximum: %u\n",
			  DnsThreadNum(), DnsThreadNumMax());

		goto CACHE;
	}

	if (cancel_flag != NULL && *cancel_flag)
	{
		return false;
	}

	if (timeout == 0)
	{
		timeout = DNS_RESOLVE_DEFAULT_TIMEOUT;
	}

	Inc(threads_counter);

	DNS_RESOLVER *resolver;
	resolver = ZeroMalloc(sizeof(DNS_RESOLVER));
	resolver->Ref = NewRef();
	resolver->IPList_v6 = NewListFast(NULL);
	resolver->IPList_v4 = NewListFast(NULL);
	resolver->Hostname = CopyStr(hostname);

	THREAD *worker = NewThread(DnsResolver, resolver);
	WaitThreadInit(worker);

	if (cancel_flag == NULL)
	{
		WaitThread(worker, timeout);
	}
	else
	{
		const UINT64 end = Tick64() + timeout;

		while (*cancel_flag == false)
		{
			const UINT64 now = Tick64();
			if (now >= end)
			{
				break;
			}

			BYTE next = MIN(end - now, 100);
			if (WaitThread(worker, next))
			{
				break;
			}
		}
	}

	ReleaseThread(worker);

	Dec(threads_counter);

	if (resolver->OK)
	{
		*iplist_v6 = resolver->IPList_v6;
		*iplist_v4 = resolver->IPList_v4;
		resolver->IPList_v6 = NULL;
		resolver->IPList_v4 = NULL;
		DnsCacheUpdateEx(hostname, *iplist_v6, *iplist_v4);
		ReleaseDnsResolver(resolver);

		return true;
	}

	ReleaseDnsResolver(resolver);

CACHE:
	Debug("DnsResolve(): Could not resolve \"%s\". Searching for it in the cache...\n", hostname);

	const DNS_CACHE *cached = DnsCacheFind(hostname);
	if (cached == NULL || cached->Expiration <= Tick64())
	{
		return false;
	}

	*iplist_v6 = CloneIPAddressList(cached->IPList_v6);
	*iplist_v4 = CloneIPAddressList(cached->IPList_v4);

	return true;
}

void DnsResolver(THREAD *t, void *param)
{
	if (t == NULL || param == NULL)
	{
		return;
	}

	DNS_RESOLVER *resolver = param;

	AddRef(resolver->Ref);

	NoticeThreadInit(t);
	AddWaitThread(t);

	struct addrinfo hints;
	Zero(&hints, sizeof(hints));

	if (HasIPv6Address())
	{
		hints.ai_family = AF_INET6;
		hints.ai_flags = AI_ALL | AI_ADDRCONFIG | AI_V4MAPPED;
	}
	else
	{
		hints.ai_family = AF_INET;
	}

	struct addrinfo *results;
	const int ret = getaddrinfo(resolver->Hostname, NULL, &hints, &results);
	if (ret == 0)
	{
		bool ipv6_ok = false;
		bool ipv4_ok = false;
		for (struct addrinfo *result = results; result != NULL; result = result->ai_next)
		{
			IP ip;
			if (hints.ai_family == AF_INET6)
			{
				const struct sockaddr_in6 *in = (struct sockaddr_in6 *)result->ai_addr;
				InAddrToIP6(&ip, &in->sin6_addr);
				if (IsIP6(&ip))
				{
					ip.ipv6_scope_id = in->sin6_scope_id;
					AddHostIPAddressToList(resolver->IPList_v6, &ip);
					ipv6_ok = true;
				}
				else if (IsIP4(&ip))
				{
					AddHostIPAddressToList(resolver->IPList_v4, &ip);
					ipv4_ok = true;
				}
			}
			else
			{
				const struct sockaddr_in *in = (struct sockaddr_in *)result->ai_addr;
				InAddrToIP(&ip, &in->sin_addr);
				if (IsIP4(&ip))
				{
					AddHostIPAddressToList(resolver->IPList_v4, &ip);
					ipv4_ok = true;
				}
			}
		}

		resolver->OK = true;

		freeaddrinfo(results);
	}
	else if (ret != EAI_NONAME)
	{
		Debug("DnsResolver(): getaddrinfo() failed with error %d!\n", ret);
	}

	ReleaseDnsResolver(resolver);

	DelWaitThread(t);
}

bool DnsResolveReverse(char *dst, const UINT size, const IP *ip, UINT timeout, volatile const bool *cancel_flag)
{
	if (dst == NULL || size == 0 || IsZeroIP(ip))
	{
		return false;
	}

	if (DnsThreadNum() > DnsThreadNumMax())
	{
		Debug("DnsResolveReverse(): Too many threads! Current: %u, Maximum: %u\n",
			  DnsThreadNum(), DnsThreadNumMax());

		goto CACHE;
	}

	if (cancel_flag != NULL && *cancel_flag)
	{
		return false;
	}

	if (timeout == 0)
	{
		timeout = DNS_RESOLVE_REVERSE_DEFAULT_TIMEOUT;
	}

	Inc(threads_counter);

	DNS_RESOLVER_REVERSE *resolver;
	resolver = ZeroMalloc(sizeof(DNS_RESOLVER_REVERSE));
	resolver->Ref = NewRef();
	Copy(&resolver->IP, ip, sizeof(resolver->IP));

	THREAD *worker = NewThread(DnsResolverReverse, resolver);
	WaitThreadInit(worker);

	if (cancel_flag == NULL)
	{
		WaitThread(worker, timeout);
	}
	else
	{
		const UINT64 end = Tick64() + timeout;

		while (*cancel_flag == false)
		{
			const UINT64 now = Tick64();
			if (now >= end)
			{
				break;
			}

			BYTE next = MIN(end - now, 100);
			if (WaitThread(worker, next))
			{
				break;
			}
		}
	}

	ReleaseThread(worker);

	Dec(threads_counter);

	if (resolver->OK)
	{
		StrCpy(dst, size, resolver->Hostname);
		DnsCacheReverseUpdate(ip, dst);
		ReleaseDnsResolverReverse(resolver);

		return true;
	}

	ReleaseDnsResolverReverse(resolver);

CACHE:
	Debug("DnsResolveReverse(): Could not resolve \"%r\". Searching for it in the cache...\n", ip);

	const DNS_CACHE_REVERSE *cached = DnsCacheReverseFind(ip);
	if (cached == NULL || cached->Expiration <= Tick64())
	{
		return false;
	}

	StrCpy(dst, size, cached->Hostname);

	return true;
}

void DnsResolverReverse(THREAD *t, void *param)
{
	if (t == NULL || param == NULL)
	{
		return;
	}

	DNS_RESOLVER_REVERSE *resolver = param;

	AddRef(resolver->Ref);

	NoticeThreadInit(t);
	AddWaitThread(t);

	struct sockaddr_in6 in;
	Zero(&in, sizeof(in));
	in.sin6_family = AF_INET6;
	IPToInAddr6(&in.sin6_addr, &resolver->IP);

	char tmp[NI_MAXHOST];
	const int ret = getnameinfo((struct sockaddr *)&in, sizeof(in), tmp, sizeof(tmp), NULL, 0, NI_NAMEREQD);
	if (ret == 0)
	{
		resolver->Hostname = CopyStr(tmp);
		resolver->OK = true;
	}
	else if (ret != EAI_NONAME)
	{
		Debug("DnsResolverReverse(): getnameinfo() failed with error %d!\n", ret);
	}

	ReleaseDnsResolverReverse(resolver);

	DelWaitThread(t);
}

bool GetIPEx(IP *ip, const char *hostname, UINT timeout, volatile const bool *cancel_flag)
{
	if (ip == NULL || IsEmptyStr(hostname))
	{
		return false;
	}

	IP ipv6, ipv4;
	if (DnsResolve(&ipv6, &ipv4, hostname, timeout, cancel_flag) == false)
	{
		return false;
	}

	if (IsZeroIP(&ipv6) == false)
	{
		Copy(ip, &ipv6, sizeof(IP));
		return true;
	}
	else if (IsZeroIP(&ipv4) == false)
	{
		Copy(ip, &ipv4, sizeof(IP));
		return true;
	}

	return false;
}

// Release of the parameters of the DNS Resolver thread
void ReleaseDnsResolver(DNS_RESOLVER *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (Release(p->Ref) == 0)
	{
		FreeHostIPAddressList(p->IPList_v6);
		FreeHostIPAddressList(p->IPList_v4);
		Free(p->Hostname);
		Free(p);
	}
}

// Release of the parameters of the DNS Resolver Reverse thread
void ReleaseDnsResolverReverse(DNS_RESOLVER_REVERSE *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (Release(p->Ref) == 0)
	{
		Free(p->Hostname);
		Free(p);
	}
}