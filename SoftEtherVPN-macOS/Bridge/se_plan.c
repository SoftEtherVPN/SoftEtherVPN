// SoftEther VPN for macOS - tunnel plan (see se_plan.h)

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "se_plan.h"

// Append one remark, whole or not at all: a message cut in half is worse than
// a missing one
static void PlanWarn(se_plan *p, const char *fmt, const char *arg)
{
	char msg[512];
	size_t len = strlen(p->warnings);
	size_t msg_len;

	snprintf(msg, sizeof(msg), fmt, arg);
	msg_len = strlen(msg);

	if (len + msg_len + 2 > sizeof(p->warnings))
	{
		return;
	}

	if (len != 0)
	{
		p->warnings[len++] = '\n';
	}

	memcpy(p->warnings + len, msg, msg_len + 1);
}

static void SetErr(char *err, size_t err_size, const char *text)
{
	if (err != NULL && err_size != 0)
	{
		snprintf(err, err_size, "%s", text);
	}
}

// Clear the host bits and write the canonical text forms
static int FinishNet(se_net *n, unsigned char *bytes, int prefix)
{
	int total = n->is_ipv6 ? 128 : 32;
	int i;

	if (prefix < 0 || prefix > total)
	{
		return 0;
	}

	for (i = 0; i < total / 8; i++)
	{
		int bits = prefix - i * 8;

		if (bits <= 0)
		{
			bytes[i] = 0;
		}
		else if (bits < 8)
		{
			bytes[i] &= (unsigned char)(0xFF << (8 - bits));
		}
	}

	n->prefix_len = prefix;
	n->mask[0] = 0;

	if (n->is_ipv6)
	{
		return inet_ntop(AF_INET6, bytes, n->address, sizeof(n->address)) != NULL;
	}
	else
	{
		unsigned int m = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));

		snprintf(n->mask, sizeof(n->mask), "%u.%u.%u.%u",
			(m >> 24) & 0xFF, (m >> 16) & 0xFF, (m >> 8) & 0xFF, m & 0xFF);

		return inet_ntop(AF_INET, bytes, n->address, sizeof(n->address)) != NULL;
	}
}

// Dotted IPv4 mask to prefix length; -1 if the mask is not contiguous
static int MaskToPrefix(const unsigned char *m)
{
	unsigned int v = ((unsigned int)m[0] << 24) | (m[1] << 16) | (m[2] << 8) | m[3];
	int prefix = 0;

	while (prefix < 32 && (v & 0x80000000u))
	{
		v <<= 1;
		prefix++;
	}

	return (v == 0) ? prefix : -1;
}

int se_parse_net(const char *text, se_net *out)
{
	char addr[SE_ADDR_LEN * 2];
	const char *slash;
	unsigned char bytes[16];
	int prefix;
	size_t addr_len;

	if (text == NULL || out == NULL)
	{
		return 0;
	}

	memset(out, 0, sizeof(se_net));
	memset(bytes, 0, sizeof(bytes));

	slash = strchr(text, '/');
	addr_len = (slash != NULL) ? (size_t)(slash - text) : strlen(text);

	if (addr_len == 0 || addr_len >= sizeof(addr))
	{
		return 0;
	}

	memcpy(addr, text, addr_len);
	addr[addr_len] = 0;

	if (inet_pton(AF_INET, addr, bytes) == 1)
	{
		out->is_ipv6 = 0;
		prefix = 32;
	}
	else if (inet_pton(AF_INET6, addr, bytes) == 1)
	{
		out->is_ipv6 = 1;
		prefix = 128;
	}
	else
	{
		return 0;
	}

	if (slash != NULL)
	{
		const char *p = slash + 1;
		unsigned char mask[4];

		if (*p == 0)
		{
			return 0;
		}

		if (out->is_ipv6 == 0 && strchr(p, '.') != NULL)
		{
			// a.b.c.d/255.255.0.0
			if (inet_pton(AF_INET, p, mask) != 1)
			{
				return 0;
			}

			prefix = MaskToPrefix(mask);
		}
		else
		{
			prefix = 0;

			for (; *p != 0; p++)
			{
				if (!isdigit((unsigned char)*p) || prefix > 128)
				{
					return 0;
				}

				prefix = prefix * 10 + (*p - '0');
			}
		}
	}

	return FinishNet(out, bytes, prefix);
}

static int NetBytes(const se_net *n, unsigned char *bytes)
{
	return inet_pton(n->is_ipv6 ? AF_INET6 : AF_INET, n->address, bytes) == 1;
}

// Is every address of inner inside outer?
static int NetContains(const se_net *outer, const se_net *inner)
{
	unsigned char a[16], b[16];
	int i;

	if (outer->is_ipv6 != inner->is_ipv6 || outer->prefix_len > inner->prefix_len)
	{
		return 0;
	}

	memset(a, 0, sizeof(a));
	memset(b, 0, sizeof(b));

	if (!NetBytes(outer, a) || !NetBytes(inner, b))
	{
		return 0;
	}

	for (i = 0; i < outer->prefix_len; i++)
	{
		if (((a[i / 8] ^ b[i / 8]) >> (7 - (i % 8))) & 1)
		{
			return 0;
		}
	}

	return 1;
}

static int NetEqual(const se_net *a, const se_net *b)
{
	return a->is_ipv6 == b->is_ipv6 && a->prefix_len == b->prefix_len &&
		strcmp(a->address, b->address) == 0;
}

// Returns 0 when the list is full
static int AddNet(se_net *list, int *num, const se_net *n)
{
	int i;

	for (i = 0; i < *num; i++)
	{
		if (NetEqual(&list[i], n))
		{
			return 1;
		}
	}

	if (*num >= SE_PLAN_MAX_NETS)
	{
		return 0;
	}

	list[(*num)++] = *n;

	return 1;
}

static int IsSep(char c)
{
	return c == ',' || c == ';' || c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

// Next entry of a free-text list. Returns 0 at the end, 1 for an entry, and 2
// for an entry that did not fit dst (dst then holds its beginning, for the
// warning only: a cut-off entry must never be parsed as if it were complete).
static int NextToken(const char **pos, char *dst, size_t dst_size)
{
	const char *p = *pos;
	size_t n = 0;
	int truncated = 0;

	if (p == NULL)
	{
		return 0;
	}

	while (*p != 0 && IsSep(*p))
	{
		p++;
	}

	if (*p == 0)
	{
		*pos = p;

		return 0;
	}

	while (*p != 0 && !IsSep(*p))
	{
		if (n + 1 < dst_size)
		{
			dst[n++] = *p;
		}
		else
		{
			truncated = 1;
		}

		p++;
	}

	dst[n] = 0;
	*pos = p;

	if (truncated)
	{
		// Leave something short enough to quote
		if (dst_size > 44)
		{
			memcpy(dst + 40, "...", 4);
		}

		return 2;
	}

	return 1;
}

// "Corp.Example." -> "corp.example". Rejects anything that is not a DNS name a
// resolver rule can sensibly be made for. ASCII rules on purpose (the C
// locale must not change what is accepted); internationalized names are given
// in their xn-- form.
static int NormalizeDomain(const char *src, char *dst, size_t dst_size)
{
	size_t len, i, label_len = 0;
	int has_alpha = 0;

	while (*src == '.' || *src == '*')
	{
		// "*.corp.example" and ".corp.example" mean the domain itself
		src++;
	}

	len = strlen(src);

	while (len > 0 && src[len - 1] == '.')
	{
		len--;
	}

	if (len == 0 || len >= dst_size || len > 253)
	{
		return 0;
	}

	for (i = 0; i < len; i++)
	{
		char c = src[i];

		if (c >= 'A' && c <= 'Z')
		{
			c = (char)(c - 'A' + 'a');
		}

		if (c == '.')
		{
			// No empty label, none ending in a hyphen
			if (label_len == 0 || dst[i - 1] == '-')
			{
				return 0;
			}

			label_len = 0;
		}
		else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')
		{
			// No label starting with a hyphen, none longer than DNS allows
			if ((label_len == 0 && c == '-') || ++label_len > 63)
			{
				return 0;
			}

			if ((c >= 'a' && c <= 'z') || c == '_')
			{
				has_alpha = 1;
			}
		}
		else
		{
			return 0;
		}

		dst[i] = c;
	}

	dst[len] = 0;

	if (dst[len - 1] == '-')
	{
		return 0;
	}

	// All digits and dots is an address, not a name. "local" belongs to
	// Bonjour (multicast DNS): routing it to a VPN resolver would break the
	// discovery of printers and other devices on the local network.
	if (!has_alpha || strcmp(dst, "local") == 0)
	{
		return 0;
	}

	return 1;
}

// Returns 0 when the list is full
static int AddDomain(char list[][SE_DOMAIN_LEN], int *num, const char *domain)
{
	int i;

	for (i = 0; i < *num; i++)
	{
		if (strcmp(list[i], domain) == 0)
		{
			return 1;
		}
	}

	if (*num >= SE_PLAN_MAX_DOMAINS)
	{
		return 0;
	}

	snprintf(list[(*num)++], SE_DOMAIN_LEN, "%s", domain);

	return 1;
}

// family_ok: is_ipv6 -> whether the VPN carries that family
static void AddDnsServer(se_plan *p, const char *addr, int has_v4, int has_v6)
{
	unsigned char bytes[16];
	int is_v6;
	int i;

	if (addr == NULL || addr[0] == 0)
	{
		return;
	}

	if (inet_pton(AF_INET, addr, bytes) == 1)
	{
		is_v6 = 0;
	}
	else if (inet_pton(AF_INET6, addr, bytes) == 1)
	{
		is_v6 = 1;
	}
	else
	{
		PlanWarn(p, "Ignored DNS server \"%s\": not an IP address.", addr);

		return;
	}

	// A resolver of a family the VPN does not carry cannot be reached through
	// it: the queries would leave outside the VPN, or nowhere at all
	if ((is_v6 && !has_v6) || (!is_v6 && !has_v4))
	{
		PlanWarn(p, is_v6 ? "Ignored DNS server %s: this VPN carries no IPv6."
			: "Ignored DNS server %s: this VPN carries no IPv4.", addr);

		return;
	}

	for (i = 0; i < p->num_dns_servers; i++)
	{
		if (strcmp(p->dns_servers[i], addr) == 0)
		{
			return;
		}
	}

	if (p->num_dns_servers >= SE_PLAN_MAX_DNS)
	{
		PlanWarn(p, "Ignored DNS server %s: too many DNS servers.", addr);

		return;
	}

	snprintf(p->dns_servers[p->num_dns_servers++], SE_ADDR_LEN, "%s", addr);
}

static int Covered(const se_net *list, int num, const se_net *n)
{
	int i;

	for (i = 0; i < num; i++)
	{
		if (NetContains(&list[i], n))
		{
			return 1;
		}
	}

	return 0;
}

// Covered by an entry that is strictly wider than n itself
static int CoveredByWider(const se_net *list, int num, const se_net *n)
{
	int i;

	for (i = 0; i < num; i++)
	{
		if (list[i].prefix_len < n->prefix_len && NetContains(&list[i], n))
		{
			return 1;
		}
	}

	return 0;
}

static void AddIncluded(se_plan *p, const se_net *n, int *overflow)
{
	if (!AddNet(p->included, &p->num_included, n))
	{
		*overflow = 1;
	}
}

int se_make_plan(const se_policy *policy, const se_ipv4_config *v4, const se_ipv6_config *v6,
	se_plan *p, char *err, size_t err_size)
{
	char tok[SE_DOMAIN_LEN];
	char cidr[SE_ADDR_LEN * 2 + 2];
	const char *pos;
	se_net n, vpn4, vpn6;
	int has_v4, has_v6, has_vpn4 = 0, has_vpn6 = 0;
	int full4, full6;
	int dns_mode;
	int overflow = 0, list_overflow = 0, domain_overflow = 0;
	int auto_host_dns = 0;
	int r, i;

	SetErr(err, err_size, "");

	if (policy == NULL || p == NULL)
	{
		SetErr(err, err_size, "Internal error: missing arguments.");

		return 0;
	}

	memset(p, 0, sizeof(se_plan));

	has_v4 = (v4 != NULL && v4->address[0] != 0);
	has_v6 = (v6 != NULL && v6->address[0] != 0);

	if (!has_v4 && !has_v6)
	{
		SetErr(err, err_size, "The VPN did not provide an IP address.");

		return 0;
	}

	// The VPN's own subnets
	if (has_v4)
	{
		snprintf(cidr, sizeof(cidr), "%s/%s", v4->address, v4->mask[0] != 0 ? v4->mask : "32");
		has_vpn4 = se_parse_net(cidr, &vpn4);
	}

	if (has_v6 && v6->prefix[0] != 0 && v6->prefix_len > 0)
	{
		snprintf(cidr, sizeof(cidr), "%s/%d", v6->prefix, v6->prefix_len);
		has_vpn6 = se_parse_net(cidr, &vpn6);
	}

	// ---- Full or split, per address family ----

	switch (policy->tunnel_mode)
	{
	case SE_TUNNEL_FULL:
	case SE_TUNNEL_EXCLUDE:
		full4 = full6 = 1;
		break;

	case SE_TUNNEL_INCLUDE:
		full4 = full6 = 0;
		break;

	case SE_TUNNEL_SERVER:
		// The server decides, the way a Windows client ends up routed.
		// IPv4, from the DHCP answer:
		//  - classless static routes pushed (option 121): exactly those, and
		//    the router option is ignored (RFC 3442) - a split tunnel, unless
		//    one of them is the default route;
		//  - none pushed, a default gateway handed out: everything;
		//  - neither: only the VPN's own subnet.
		// IPv6, independently, from the router advertisement: everything when
		// the hub has a router, else only the advertised prefix.
		full4 = 0;

		if (has_v4)
		{
			int pushed = 0, pushed_default = 0;

			for (i = 0; i < v4->num_routes && i < SE_MAX_ROUTES; i++)
			{
				snprintf(cidr, sizeof(cidr), "%s/%d", v4->routes[i].network, v4->routes[i].prefix_len);

				if (se_parse_net(cidr, &n) && !n.is_ipv6)
				{
					pushed++;

					if (n.prefix_len == 0)
					{
						pushed_default = 1;
					}
				}
			}

			full4 = (pushed > 0) ? pushed_default : (v4->gateway[0] != 0);
		}

		full6 = (has_v6 && v6->router[0] != 0) ? 1 : 0;
		break;

	default:
		SetErr(err, err_size, "Unknown tunnel mode.");

		return 0;
	}

	// What "everything goes through the VPN" means for DNS and the UI: the
	// outcome for IPv4, or for IPv6 on a VPN that carries nothing else
	p->full_tunnel = has_v4 ? full4 : full6;

	// ---- Routes ----

	if (has_v4)
	{
		if (full4)
		{
			if (se_parse_net("0.0.0.0/0", &n))
			{
				AddIncluded(p, &n, &overflow);
			}
		}
		else
		{
			// The VPN's own subnet is always reachable
			if (has_vpn4)
			{
				AddIncluded(p, &vpn4, &overflow);
			}

			if (policy->tunnel_mode == SE_TUNNEL_SERVER || policy->use_pushed_routes)
			{
				for (i = 0; i < v4->num_routes && i < SE_MAX_ROUTES; i++)
				{
					snprintf(cidr, sizeof(cidr), "%s/%d", v4->routes[i].network, v4->routes[i].prefix_len);

					// A pushed default route would turn a split tunnel the user
					// chose into a full one behind their back
					if (se_parse_net(cidr, &n) && !n.is_ipv6 && n.prefix_len != 0)
					{
						AddIncluded(p, &n, &overflow);
					}
				}
			}
		}
	}

	if (has_v6)
	{
		if (full6)
		{
			if (se_parse_net("::/0", &n))
			{
				AddIncluded(p, &n, &overflow);
			}
		}
		else if (has_vpn6)
		{
			AddIncluded(p, &vpn6, &overflow);
		}
	}
	else if (has_v4 && full4 && policy->block_ipv6 && se_parse_net("::/0", &n))
	{
		// Nothing to carry IPv6, but it must not go around the VPN either
		AddIncluded(p, &n, &overflow);
		p->blackhole_ipv6 = 1;
	}

	// The user's networks: routed (INCLUDE) or bypassed (EXCLUDE)
	if (policy->tunnel_mode == SE_TUNNEL_INCLUDE || policy->tunnel_mode == SE_TUNNEL_EXCLUDE)
	{
		int include = (policy->tunnel_mode == SE_TUNNEL_INCLUDE);

		pos = policy->networks;

		while ((r = NextToken(&pos, tok, sizeof(tok))) != 0)
		{
			if (r == 2)
			{
				PlanWarn(p, "Ignored network \"%s\": the entry is too long.", tok);

				continue;
			}

			if (!se_parse_net(tok, &n))
			{
				PlanWarn(p, "Ignored network \"%s\": not a valid address or prefix.", tok);

				continue;
			}

			if (n.prefix_len == 0)
			{
				PlanWarn(p, "Ignored network \"%s\": use the tunnel mode to route everything or nothing.", tok);

				continue;
			}

			if ((n.is_ipv6 && !has_v6) || (!n.is_ipv6 && !has_v4))
			{
				// The VPN does not carry that family: nothing of it can be
				// routed through, and nothing of it is routed that could bypass
				if (include)
				{
					PlanWarn(p, n.is_ipv6 ? "Ignored network \"%s\": this VPN carries no IPv6."
						: "Ignored network \"%s\": this VPN carries no IPv4.", tok);
				}
				else if (n.is_ipv6 && p->blackhole_ipv6)
				{
					PlanWarn(p, "Network \"%s\" cannot bypass the VPN while IPv6 is blocked.", tok);
				}

				continue;
			}

			if (!AddNet(include ? p->included : p->excluded,
				include ? &p->num_included : &p->num_excluded, &n))
			{
				list_overflow = 1;
			}
		}

		// A wide exclusion (say 192.168.0.0/16, to keep the home network
		// reachable) must not take the VPN's own subnet with it. The more
		// specific route wins, so including the subnet again restores it.
		// Excluding exactly the VPN's subnet, or part of it, stays the
		// user's decision.
		if (!include)
		{
			if (has_vpn4 && full4 && CoveredByWider(p->excluded, p->num_excluded, &vpn4))
			{
				AddIncluded(p, &vpn4, &overflow);
			}

			if (has_vpn6 && full6 && CoveredByWider(p->excluded, p->num_excluded, &vpn6))
			{
				AddIncluded(p, &vpn6, &overflow);
			}
		}
	}

	if (list_overflow)
	{
		PlanWarn(p, "The list of networks is too long; the entries after the first %s were ignored.", "128");
	}

	// ---- DNS ----

	dns_mode = policy->dns_mode;

	if (dns_mode != SE_DNS_AUTO && dns_mode != SE_DNS_ALL && dns_mode != SE_DNS_SPLIT &&
		dns_mode != SE_DNS_OFF)
	{
		dns_mode = SE_DNS_AUTO;
	}

	if (dns_mode != SE_DNS_OFF)
	{
		char hub_domain[SE_DOMAIN_LEN];

		// Servers: the user's override, else what the hub handed out
		pos = policy->dns_servers;

		while ((r = NextToken(&pos, tok, sizeof(tok))) != 0)
		{
			if (r == 2)
			{
				PlanWarn(p, "Ignored DNS server \"%s\": the entry is too long.", tok);

				continue;
			}

			AddDnsServer(p, tok, has_v4, has_v6);
		}

		if (p->num_dns_servers == 0)
		{
			if (has_v4)
			{
				AddDnsServer(p, v4->dns1, has_v4, has_v6);
				AddDnsServer(p, v4->dns2, has_v4, has_v6);
			}

			if (has_v6)
			{
				AddDnsServer(p, v6->dns, has_v4, has_v6);
			}
		}

		if (has_v4 && v4->domain[0] != 0)
		{
			if (NormalizeDomain(v4->domain, hub_domain, sizeof(hub_domain)))
			{
				AddDomain(p->search_domains, &p->num_search_domains, hub_domain);
				AddDomain(p->match_domains, &p->num_match_domains, hub_domain);
			}
			else
			{
				PlanWarn(p, "Ignored the DNS domain \"%s\" announced by the VPN: not usable as a domain.", v4->domain);
			}
		}

		pos = policy->dns_domains;

		while ((r = NextToken(&pos, tok, sizeof(tok))) != 0)
		{
			char d[SE_DOMAIN_LEN];

			if (r == 2 || !NormalizeDomain(tok, d, sizeof(d)))
			{
				PlanWarn(p, "Ignored DNS domain \"%s\": not a valid domain name.", tok);

				continue;
			}

			if (!AddDomain(p->match_domains, &p->num_match_domains, d))
			{
				domain_overflow = 1;
			}
		}

		if (domain_overflow)
		{
			PlanWarn(p, "The list of DNS domains is too long; the entries after the first %s were ignored.", "32");
		}

		if (dns_mode == SE_DNS_AUTO)
		{
			dns_mode = p->full_tunnel ? SE_DNS_ALL : SE_DNS_SPLIT;

			if (dns_mode == SE_DNS_SPLIT && p->num_match_domains == 0)
			{
				// Split tunnel, and neither the server nor the profile says
				// which names are internal: name lookups stay with this
				// machine's own DNS. Sending every lookup to the VPN's server
				// would hand it all the names of traffic that does not even
				// go through the VPN.
				auto_host_dns = 1;

				if (p->num_dns_servers != 0)
				{
					PlanWarn(p, "This VPN announces no DNS domain, so names are looked up by this "
						"Mac's own DNS, not the VPN's. Add the VPN's domains to the profile to look those up through the VPN.%s", "");
				}
			}
		}

		if (auto_host_dns)
		{
			// System resolver untouched
		}
		else if (p->num_dns_servers == 0)
		{
			// Nothing to point the resolver at
			if (dns_mode == SE_DNS_SPLIT || policy->dns_mode == SE_DNS_ALL)
			{
				PlanWarn(p, "This VPN has no usable DNS server; the system DNS settings are unchanged.%s", "");
			}
		}
		else if (dns_mode == SE_DNS_SPLIT && p->num_match_domains == 0)
		{
			PlanWarn(p, "Split DNS is selected but no domain is listed; the system DNS settings are unchanged.%s", "");
		}
		else
		{
			p->dns_enabled = 1;
			p->dns_match_all = (dns_mode == SE_DNS_ALL) ? 1 : 0;

			if (p->dns_match_all)
			{
				p->num_match_domains = 0;
			}
		}

		// The resolvers must be reachable through the tunnel: a host route for
		// each one that no included network covers, or that a bypassed
		// network would take away (the more specific route wins)
		if (p->dns_enabled)
		{
			for (i = 0; i < p->num_dns_servers; i++)
			{
				if (!se_parse_net(p->dns_servers[i], &n))
				{
					continue;
				}

				if (!Covered(p->included, p->num_included, &n) ||
					Covered(p->excluded, p->num_excluded, &n))
				{
					if (!AddNet(p->included, &p->num_included, &n))
					{
						PlanWarn(p, "DNS server %s may be unreachable: the list of networks is full.", p->dns_servers[i]);
					}
				}
			}
		}
	}

	if (overflow)
	{
		PlanWarn(p, "Too many networks: some routes of this VPN were left out.%s", "");
	}

	if (p->dns_enabled == 0)
	{
		p->num_dns_servers = 0;
		p->num_match_domains = 0;
		p->num_search_domains = 0;
		p->dns_match_all = 0;
	}

	return 1;
}

const se_net *se_plan_included(const se_plan *p, int i)
{
	return (p != NULL && i >= 0 && i < p->num_included) ? &p->included[i] : NULL;
}

const se_net *se_plan_excluded(const se_plan *p, int i)
{
	return (p != NULL && i >= 0 && i < p->num_excluded) ? &p->excluded[i] : NULL;
}

const char *se_plan_dns_server(const se_plan *p, int i)
{
	return (p != NULL && i >= 0 && i < p->num_dns_servers) ? p->dns_servers[i] : NULL;
}

const char *se_plan_match_domain(const se_plan *p, int i)
{
	return (p != NULL && i >= 0 && i < p->num_match_domains) ? p->match_domains[i] : NULL;
}

const char *se_plan_search_domain(const se_plan *p, int i)
{
	return (p != NULL && i >= 0 && i < p->num_search_domains) ? p->search_domains[i] : NULL;
}

const char *se_plan_warnings(const se_plan *p)
{
	return (p != NULL) ? p->warnings : "";
}

const char *se_net_address(const se_net *n)
{
	return (n != NULL) ? n->address : "";
}

const char *se_net_mask(const se_net *n)
{
	return (n != NULL) ? n->mask : "";
}
