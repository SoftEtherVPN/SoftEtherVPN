#ifndef DNS_H
#define DNS_H

#include "Network.h"

#define DNS_CACHE_EXPIRATION (10 * 60 * 1000)

#ifndef USE_STRATEGY_LOW_MEMORY
#define DNS_THREAD_DEFAULT_NUM_MAX (512)
#else
#define DNS_THREAD_DEFAULT_NUM_MAX (64)
#endif

#define DNS_RESOLVE_DEFAULT_TIMEOUT (2300)
#define DNS_RESOLVE_REVERSE_DEFAULT_TIMEOUT (500)

#define GetIP(ip, hostname) (GetIPEx(ip, hostname, 0, NULL))
#define GetIP4(ip, hostname) (GetIP4Ex(ip, hostname, 0, NULL))
#define GetIP6(ip, hostname) (GetIP6Ex(ip, hostname, 0, NULL))

#define GetIP4Ex(ip, hostname, timeout, cancel_flag) (DnsResolve(NULL, ip, hostname, timeout, cancel_flag))
#define GetIP6Ex(ip, hostname, timeout, cancel_flag) (DnsResolve(ip, NULL, hostname, timeout, cancel_flag))

struct DNS_CACHE
{
	const char *Hostname;
	IP IPv4;
	IP IPv6;
	UINT64 Expiration;
};

struct DNS_CACHE_REVERSE
{
	IP IP;
	char *Hostname;
	UINT64 Expiration;
};

struct DNS_RESOLVER
{
	const char *Hostname;
	IP IPv4;
	IP IPv6;
	bool OK;
};

struct DNS_RESOLVER_REVERSE
{
	IP IP;
	char *Hostname;
	bool OK;
};

void DnsInit();
void DnsFree();

UINT DnsThreadNum();
UINT DnsThreadNumMax();
void DnsThreadNumMaxSet(const UINT num);

bool DnsCacheIsEnabled();
void DnsCacheToggle(const bool enabled);

DNS_CACHE *DnsCacheFind(const char *hostname);
DNS_CACHE *DnsCacheUpdate(const char *hostname, const IP *ipv6, const IP *ipv4);

DNS_CACHE_REVERSE *DnsCacheReverseFind(const IP *ip);
DNS_CACHE_REVERSE *DnsCacheReverseUpdate(const IP *ip, const char *hostname);

bool DnsResolve(IP *ipv6, IP *ipv4, const char *hostname, UINT timeout, volatile const bool *cancel_flag);
void DnsResolver(THREAD *t, void *param);

bool DnsResolveReverse(char *dst, const UINT size, const IP *ip, UINT timeout, volatile const bool *cancel_flag);
void DnsResolverReverse(THREAD *t, void *param);

bool GetIPEx(IP *ip, const char *hostname, UINT timeout, volatile const bool *cancel_flag);

#endif
