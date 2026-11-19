// SoftEther VPN for macOS - tunnel plan (see se_plan.h)

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "se_plan.h"

static void PlanWarn(se_plan *p, const char *fmt, const char *arg)
{
	size_t len = strlen(p->warnings);

	if (len + 2 >= sizeof(p->warnings))
	{
		return;
	}

	if (len != 0)
	{
		p->warnings[len++] = '\n';
		p->warnings[len] = 0;
	}

	snprintf(p->warnings + len, sizeof(p->warnings) - len, fmt, arg);
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

static void AddNet(se_net *list, int *num, const se_net *n)
{
	int i;

	for (i = 0; i < *num; i++)
	{
		if (NetEqual(&list[i], n))
		{
			return;
		}
	}

	if (*num < SE_PLAN_MAX_NETS)
	{
		list[(*num)++] = *n;
	}
}

static int IsSep(char c)
{
	return c == ',' || c == ';' || isspace((unsigned char)c);
}

// Next entry of a free-text list; returns 0 at the end
static int NextToken(const char **pos, char *dst, size_t dst_size)
{
	const char *p = *pos;
	size_t n = 0;

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

		p++;
	}

	dst[n] = 0;
	*pos = p;

	return 1;
}

// "Corp.Example." -> "corp.example"; rejects anything that is not a host name
static int NormalizeDomain(const char *src, char *dst, size_t dst_size)
{
	size_t len, i;

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

	if (len == 0 || len >= dst_size)
	{
		return 0;
	}

	for (i = 0; i < len; i++)
	{
		unsigned char c = (unsigned char)src[i];

		if (!(isalnum(c) || c == '-' || c == '.' || c == '_'))
		{
			return 0;
		}

		dst[i] = (char)tolower(c);
	}

	dst[len] = 0;

	return strstr(dst, "..") == NULL;
}

static void AddDomain(char list[][SE_DOMAIN_LEN], int *num, const char *domain)
{
	int i;

	for (i = 0; i < *num; i++)
	{
		if (strcmp(list[i], domain) == 0)
		{
			return;
		}
	}

	if (*num < SE_PLAN_MAX_DOMAINS)
	{
		snprintf(list[(*num)++], SE_DOMAIN_LEN, "%s", domain);
	}
}

static void AddDnsServer(se_plan *p, const char *addr)
{
	unsigned char bytes[16];
	int i;

	if (addr == NULL || addr[0] == 0)
	{
		return;
	}

	if (inet_pton(AF_INET, addr, bytes) != 1 && inet_pton(AF_INET6, addr, bytes) != 1)
	{
		PlanWarn(p, "Ignored DNS server \"%s\": not an IP address.", addr);

		return;
	}

	for (i = 0; i < p->num_dns_servers; i++)
	{
		if (strcmp(p->dns_servers[i], addr) == 0)
		{
			return;
		}
	}

	if (p->num_dns_servers < SE_PLAN_MAX_DNS)
	{
		snprintf(p->dns_servers[p->num_dns_servers++], SE_ADDR_LEN, "%s", addr);
	}
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

int se_make_plan(const se_policy *policy, const se_ipv4_config *v4, const se_ipv6_config *v6,
	se_plan *p, char *err, size_t err_size)
{
	char tok[SE_DOMAIN_LEN];
	const char *pos;
	se_net n;
	int has_v4, has_v6;
	int dns_mode;
	int i;

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

	if (policy->tunnel_mode != SE_TUNNEL_FULL && policy->tunnel_mode != SE_TUNNEL_INCLUDE &&
		policy->tunnel_mode != SE_TUNNEL_EXCLUDE)
	{
		SetErr(err, err_size, "Unknown tunnel mode.");

		return 0;
	}

	// ---- Routes ----

	if (policy->tunnel_mode == SE_TUNNEL_INCLUDE)
	{
		// The VPN's own subnet is always reachable
		if (has_v4)
		{
			char cidr[SE_ADDR_LEN * 2 + 2];

			snprintf(cidr, sizeof(cidr), "%s/%s", v4->address, v4->mask[0] != 0 ? v4->mask : "32");

			if (se_parse_net(cidr, &n))
			{
				AddNet(p->included, &p->num_included, &n);
			}
		}

		if (has_v6 && v6->prefix[0] != 0 && v6->prefix_len > 0)
		{
			char cidr[SE_ADDR_LEN * 2];

			snprintf(cidr, sizeof(cidr), "%s/%d", v6->prefix, v6->prefix_len);

			if (se_parse_net(cidr, &n))
			{
				AddNet(p->included, &p->num_included, &n);
			}
		}

		if (policy->use_pushed_routes && has_v4)
		{
			for (i = 0; i < v4->num_routes && i < SE_MAX_ROUTES; i++)
			{
				char cidr[SE_ADDR_LEN * 2];

				snprintf(cidr, sizeof(cidr), "%s/%d", v4->routes[i].network, v4->routes[i].prefix_len);

				// A pushed default route would turn the split tunnel into a full
				// one behind the user's back; the mode is the user's choice
				if (se_parse_net(cidr, &n) && n.prefix_len != 0)
				{
					AddNet(p->included, &p->num_included, &n);
				}
			}
		}
	}
	else
	{
		// FULL / EXCLUDE: default route for every family the VPN carries
		if (has_v4 && se_parse_net("0.0.0.0/0", &n))
		{
			AddNet(p->included, &p->num_included, &n);
		}

		if (has_v6 && se_parse_net("::/0", &n))
		{
			AddNet(p->included, &p->num_included, &n);
		}
	}

	if (policy->tunnel_mode != SE_TUNNEL_FULL)
	{
		se_net *list = (policy->tunnel_mode == SE_TUNNEL_INCLUDE) ? p->included : p->excluded;
		int *num = (policy->tunnel_mode == SE_TUNNEL_INCLUDE) ? &p->num_included : &p->num_excluded;

		pos = policy->networks;

		while (NextToken(&pos, tok, sizeof(tok)))
		{
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
				// The VPN does not carry that family, so there is nothing to
				// include, and nothing of it is routed that could be excluded
				continue;
			}

			AddNet(list, num, &n);
		}
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
		int have_hub_domain;

		// Servers: the user's override, else what the hub handed out
		pos = policy->dns_servers;

		while (NextToken(&pos, tok, sizeof(tok)))
		{
			AddDnsServer(p, tok);
		}

		if (p->num_dns_servers == 0)
		{
			if (has_v4)
			{
				AddDnsServer(p, v4->dns1);
				AddDnsServer(p, v4->dns2);
			}

			if (has_v6)
			{
				AddDnsServer(p, v6->dns);
			}
		}

		have_hub_domain = has_v4 && NormalizeDomain(v4->domain, hub_domain, sizeof(hub_domain));

		if (have_hub_domain)
		{
			AddDomain(p->search_domains, &p->num_search_domains, hub_domain);
			AddDomain(p->match_domains, &p->num_match_domains, hub_domain);
		}

		pos = policy->dns_domains;

		while (NextToken(&pos, tok, sizeof(tok)))
		{
			char d[SE_DOMAIN_LEN];

			if (!NormalizeDomain(tok, d, sizeof(d)))
			{
				PlanWarn(p, "Ignored DNS domain \"%s\": not a valid domain name.", tok);

				continue;
			}

			AddDomain(p->match_domains, &p->num_match_domains, d);
		}

		if (dns_mode == SE_DNS_AUTO)
		{
			dns_mode = (policy->tunnel_mode == SE_TUNNEL_INCLUDE) ? SE_DNS_SPLIT : SE_DNS_ALL;

			if (dns_mode == SE_DNS_SPLIT && p->num_match_domains == 0)
			{
				// Split tunnel but nothing says which names are internal: the
				// VPN's resolver answers everything, so that internal names
				// work (the behavior of the desktop SoftEther client)
				dns_mode = SE_DNS_ALL;

				if (p->num_dns_servers != 0)
				{
					PlanWarn(p, "No DNS domain is known for this VPN, so all names are "
						"resolved by the VPN's DNS server. Add the internal domains to resolve only those there.%s", "");
				}
			}
		}

		if (p->num_dns_servers == 0)
		{
			// Nothing to point the resolver at
			if (dns_mode == SE_DNS_SPLIT || policy->dns_mode == SE_DNS_ALL)
			{
				PlanWarn(p, "The VPN did not provide a DNS server; the system DNS settings are unchanged.%s", "");
			}

			p->num_match_domains = 0;
			p->num_search_domains = 0;
		}
		else if (dns_mode == SE_DNS_SPLIT && p->num_match_domains == 0)
		{
			PlanWarn(p, "Split DNS is selected but no domain is listed; the system DNS settings are unchanged.%s", "");

			p->num_dns_servers = 0;
			p->num_search_domains = 0;
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

		// The resolvers must be reachable through the tunnel
		if (p->dns_enabled)
		{
			for (i = 0; i < p->num_dns_servers; i++)
			{
				if (!se_parse_net(p->dns_servers[i], &n))
				{
					continue;
				}

				if ((n.is_ipv6 && !has_v6) || (!n.is_ipv6 && !has_v4))
				{
					continue;
				}

				if (!Covered(p->included, p->num_included, &n))
				{
					AddNet(p->included, &p->num_included, &n);
				}

				if (Covered(p->excluded, p->num_excluded, &n))
				{
					PlanWarn(p, "DNS server %s is inside a network that bypasses the VPN.", p->dns_servers[i]);
				}
			}
		}
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
