// Unit test of the tunnel plan (Bridge/se_plan.c): full tunnel, split tunnel
// in both directions, and split DNS. No VPN server needed.

#include <stdio.h>
#include <string.h>

#include "se_plan.h"

static int g_failed = 0;
static int g_checks = 0;

#define CHECK(cond) \
	do { g_checks++; if (!(cond)) { g_failed++; printf("  FAIL  %s:%d  %s\n", __FILE__, __LINE__, #cond); } } while (0)

static int HasNet(const se_net *list, int num, const char *addr, int prefix)
{
	int i;

	for (i = 0; i < num; i++)
	{
		if (strcmp(list[i].address, addr) == 0 && list[i].prefix_len == prefix)
		{
			return 1;
		}
	}

	return 0;
}

static int HasStr(char list[][SE_DOMAIN_LEN], int num, const char *s)
{
	int i;

	for (i = 0; i < num; i++)
	{
		if (strcmp(list[i], s) == 0)
		{
			return 1;
		}
	}

	return 0;
}

static se_ipv4_config Hub4(const char *domain, int pushed)
{
	se_ipv4_config c;

	memset(&c, 0, sizeof(c));
	strcpy(c.address, "192.168.30.10");
	strcpy(c.mask, "255.255.255.0");
	strcpy(c.gateway, "192.168.30.1");
	strcpy(c.dns1, "192.168.30.1");
	strcpy(c.domain, domain);

	if (pushed)
	{
		c.num_routes = 2;
		strcpy(c.routes[0].network, "10.20.0.0");
		c.routes[0].prefix_len = 16;
		strcpy(c.routes[0].gateway, "192.168.30.1");
		strcpy(c.routes[1].network, "0.0.0.0");
		c.routes[1].prefix_len = 0;
		strcpy(c.routes[1].gateway, "192.168.30.1");
	}

	return c;
}

static se_ipv6_config Hub6(void)
{
	se_ipv6_config c;

	memset(&c, 0, sizeof(c));
	strcpy(c.address, "2001:db8:1::10");
	c.prefix_len = 64;
	strcpy(c.prefix, "2001:db8:1::");
	strcpy(c.router, "fe80::1");
	strcpy(c.dns, "2001:db8:1::53");

	return c;
}

static void TestParse(void)
{
	se_net n;

	printf("network parsing\n");

	CHECK(se_parse_net("10.1.2.3/8", &n) && strcmp(n.address, "10.0.0.0") == 0 &&
		n.prefix_len == 8 && strcmp(n.mask, "255.0.0.0") == 0 && !n.is_ipv6);
	CHECK(se_parse_net("172.16.5.0/255.255.240.0", &n) && strcmp(n.address, "172.16.0.0") == 0 && n.prefix_len == 20);
	CHECK(se_parse_net("192.168.1.7", &n) && n.prefix_len == 32 && strcmp(n.mask, "255.255.255.255") == 0);
	CHECK(se_parse_net("0.0.0.0/0", &n) && n.prefix_len == 0 && strcmp(n.mask, "0.0.0.0") == 0);
	CHECK(se_parse_net("10.0.0.0/31", &n) && strcmp(n.mask, "255.255.255.254") == 0);
	CHECK(se_parse_net("2001:db8:abcd:12::1/56", &n) && n.is_ipv6 && n.prefix_len == 56 &&
		strcmp(n.address, "2001:db8:abcd::") == 0);
	CHECK(se_parse_net("fd00::1", &n) && n.is_ipv6 && n.prefix_len == 128);

	CHECK(!se_parse_net("10.0.0.0/33", &n));
	CHECK(!se_parse_net("10.0.0.0/", &n));
	CHECK(!se_parse_net("10.0.0.0/255.0.255.0", &n));
	CHECK(!se_parse_net("10.0.0/8", &n));
	CHECK(!se_parse_net("example.com", &n));
	CHECK(!se_parse_net("2001:db8::/129", &n));
	CHECK(!se_parse_net("10.0.0.0/8x", &n));
	CHECK(!se_parse_net("", &n));
}

static void TestFull(void)
{
	se_policy pol;
	se_ipv4_config v4 = Hub4("corp.example", 1);
	se_ipv6_config v6 = Hub6();
	se_plan p;
	char err[256];

	printf("full tunnel\n");

	memset(&pol, 0, sizeof(pol));
	pol.tunnel_mode = SE_TUNNEL_FULL;
	pol.networks = "10.0.0.0/8";	// ignored in full mode

	// IPv4 only
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.num_included == 1 && HasNet(p.included, p.num_included, "0.0.0.0", 0));
	CHECK(p.num_excluded == 0);
	CHECK(p.dns_enabled && p.dns_match_all && p.num_match_domains == 0);
	CHECK(p.num_dns_servers == 1 && strcmp(p.dns_servers[0], "192.168.30.1") == 0);
	CHECK(HasStr(p.search_domains, p.num_search_domains, "corp.example"));
	CHECK(p.warnings[0] == 0);

	// Dual stack: both default routes, both resolvers
	CHECK(se_make_plan(&pol, &v4, &v6, &p, err, sizeof(err)) == 1);
	CHECK(p.num_included == 2 && HasNet(p.included, p.num_included, "0.0.0.0", 0) &&
		HasNet(p.included, p.num_included, "::", 0));
	CHECK(p.num_dns_servers == 2);

	// IPv6 leak protection only matters when the hub has no IPv6
	pol.block_ipv6 = 1;
	CHECK(se_make_plan(&pol, &v4, &v6, &p, err, sizeof(err)) == 1 && !p.blackhole_ipv6 && p.num_included == 2);
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1 && p.blackhole_ipv6);
	CHECK(p.num_included == 2 && HasNet(p.included, p.num_included, "::", 0));
	CHECK(p.num_dns_servers == 1);	// no IPv6 resolver appears
	pol.block_ipv6 = 0;
	CHECK(se_make_plan(&pol, &v4, &v6, &p, err, sizeof(err)) == 1);

	// Indexed accessors (the Swift side's view)
	CHECK(strcmp(se_net_address(se_plan_included(&p, 1)), "::") == 0 && se_plan_included(&p, 2) == NULL);
	CHECK(strcmp(se_net_mask(se_plan_included(&p, 0)), "0.0.0.0") == 0 && se_plan_excluded(&p, 0) == NULL);
	CHECK(strcmp(se_plan_dns_server(&p, 1), "2001:db8:1::53") == 0 && se_plan_dns_server(&p, 2) == NULL);
	CHECK(strcmp(se_plan_search_domain(&p, 0), "corp.example") == 0 && se_plan_match_domain(&p, 0) == NULL);
	CHECK(se_plan_warnings(&p)[0] == 0 && se_plan_included(&p, -1) == NULL);

	// DNS off leaves the resolver alone
	pol.dns_mode = SE_DNS_OFF;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(!p.dns_enabled && p.num_dns_servers == 0 && p.num_search_domains == 0);

	// Nothing from the hub at all
	CHECK(se_make_plan(&pol, NULL, NULL, &p, err, sizeof(err)) == 0 && err[0] != 0);
}

static void TestInclude(void)
{
	se_policy pol;
	se_ipv4_config v4 = Hub4("corp.example", 1);
	se_ipv4_config v4_nodomain = Hub4("", 0);
	se_ipv6_config v6 = Hub6();
	se_plan p;
	char err[256];

	printf("split tunnel: only listed networks\n");

	memset(&pol, 0, sizeof(pol));
	pol.tunnel_mode = SE_TUNNEL_INCLUDE;
	pol.networks = "10.1.0.0/16, 172.16.9.9/255.255.0.0\n10.1.0.0/16 bogus 0.0.0.0/0 fd00:1::/48";
	pol.use_pushed_routes = 1;

	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	// VPN subnet + two user networks (deduplicated) + the pushed 10.20/16.
	// Never a default route: neither the user's 0.0.0.0/0 nor the pushed one.
	CHECK(HasNet(p.included, p.num_included, "192.168.30.0", 24));
	CHECK(HasNet(p.included, p.num_included, "10.1.0.0", 16));
	CHECK(HasNet(p.included, p.num_included, "172.16.0.0", 16));
	CHECK(HasNet(p.included, p.num_included, "10.20.0.0", 16));
	CHECK(!HasNet(p.included, p.num_included, "0.0.0.0", 0));
	CHECK(p.num_included == 4);	// the IPv6 entry is dropped: the VPN carries no IPv6
	CHECK(p.num_excluded == 0);
	CHECK(strstr(p.warnings, "bogus") != NULL && strstr(p.warnings, "0.0.0.0/0") != NULL);

	// AUTO DNS in a split tunnel = split DNS on the hub's domain
	CHECK(p.dns_enabled && !p.dns_match_all);
	CHECK(p.num_match_domains == 1 && HasStr(p.match_domains, p.num_match_domains, "corp.example"));

	// Pushed routes can be declined
	pol.use_pushed_routes = 0;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(!HasNet(p.included, p.num_included, "10.20.0.0", 16) && p.num_included == 3);

	// With IPv6 on the hub the IPv6 networks are honored
	CHECK(se_make_plan(&pol, &v4, &v6, &p, err, sizeof(err)) == 1);
	CHECK(HasNet(p.included, p.num_included, "2001:db8:1::", 64));
	CHECK(HasNet(p.included, p.num_included, "fd00:1::", 48));
	CHECK(!HasNet(p.included, p.num_included, "::", 0));
	// ... and the IPv6 resolver gets a host route because it is outside them? No: it is in the /64.
	CHECK(!HasNet(p.included, p.num_included, "2001:db8:1::53", 128));

	// A resolver outside the routed networks gets its own host route
	pol.dns_servers = "10.99.0.53";
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.num_dns_servers == 1 && strcmp(p.dns_servers[0], "10.99.0.53") == 0);
	CHECK(HasNet(p.included, p.num_included, "10.99.0.53", 32));
	pol.dns_servers = NULL;

	// Split tunnel and no DNS domain known anywhere (none from the server, none
	// in the profile): lookups stay with the host's own DNS, and the VPN's
	// server gets no route of its own
	pol.networks = "10.1.0.0/16";
	CHECK(se_make_plan(&pol, &v4_nodomain, NULL, &p, err, sizeof(err)) == 1);
	CHECK(!p.dns_enabled && p.num_dns_servers == 0 && p.num_match_domains == 0 && !p.dns_match_all);
	CHECK(strstr(p.warnings, "this Mac's own DNS") != NULL);
	CHECK(p.num_included == 2 && !HasNet(p.included, p.num_included, "192.168.30.1", 32));

	// ... silently when the server set no DNS server either
	{
		se_ipv4_config bare = v4_nodomain;

		bare.dns1[0] = 0;
		CHECK(se_make_plan(&pol, &bare, NULL, &p, err, sizeof(err)) == 1);
		CHECK(!p.dns_enabled && p.warnings[0] == 0);
	}

	// A domain in the profile is enough to use the VPN's DNS for it
	pol.dns_domains = "intra.example";
	CHECK(se_make_plan(&pol, &v4_nodomain, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.dns_enabled && !p.dns_match_all && p.num_match_domains == 1 && p.num_dns_servers == 1);
	pol.dns_domains = NULL;

	// ... and asking for all names explicitly still works on a split tunnel
	pol.dns_mode = SE_DNS_ALL;
	CHECK(se_make_plan(&pol, &v4_nodomain, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.dns_enabled && p.dns_match_all && p.num_dns_servers == 1);
	pol.dns_mode = SE_DNS_AUTO;

	// The same when the server decided on the split
	pol.tunnel_mode = SE_TUNNEL_SERVER;
	{
		se_ipv4_config pushed = v4_nodomain;

		pushed.gateway[0] = 0;
		pushed.num_routes = 1;
		strcpy(pushed.routes[0].network, "10.20.0.0");
		pushed.routes[0].prefix_len = 16;
		CHECK(se_make_plan(&pol, &pushed, NULL, &p, err, sizeof(err)) == 1);
		CHECK(p.full_tunnel == 0 && !p.dns_enabled && strstr(p.warnings, "this Mac's own DNS") != NULL);

		// ... while a full tunnel decided by the server uses the VPN's DNS for everything
		CHECK(se_make_plan(&pol, &v4_nodomain, NULL, &p, err, sizeof(err)) == 1);
		CHECK(p.full_tunnel == 1 && p.dns_enabled && p.dns_match_all);
	}
	pol.tunnel_mode = SE_TUNNEL_INCLUDE;
}

static void TestExclude(void)
{
	se_policy pol;
	se_ipv4_config v4 = Hub4("corp.example", 1);
	se_ipv6_config v6 = Hub6();
	se_plan p;
	char err[256];

	printf("split tunnel: everything except listed networks\n");

	memset(&pol, 0, sizeof(pol));
	pol.tunnel_mode = SE_TUNNEL_EXCLUDE;
	pol.networks = "192.168.1.0/24;17.0.0.0/8 2620:149::/32";

	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.num_included == 1 && HasNet(p.included, p.num_included, "0.0.0.0", 0));
	CHECK(p.num_excluded == 2 && HasNet(p.excluded, p.num_excluded, "192.168.1.0", 24) &&
		HasNet(p.excluded, p.num_excluded, "17.0.0.0", 8));
	CHECK(p.dns_enabled && p.dns_match_all);

	CHECK(se_make_plan(&pol, &v4, &v6, &p, err, sizeof(err)) == 1);
	CHECK(p.num_included == 2 && p.num_excluded == 3 && HasNet(p.excluded, p.num_excluded, "2620:149::", 32));

	// Leak protection in EXCLUDE mode; never in INCLUDE mode
	pol.block_ipv6 = 1;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1 && p.blackhole_ipv6 &&
		HasNet(p.included, p.num_included, "::", 0) && p.num_excluded == 2);
	pol.tunnel_mode = SE_TUNNEL_INCLUDE;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1 && !p.blackhole_ipv6 &&
		!HasNet(p.included, p.num_included, "::", 0));
	pol.tunnel_mode = SE_TUNNEL_EXCLUDE;
	pol.block_ipv6 = 0;

	// Bypassing exactly the VPN's subnet is the user's decision, but the
	// resolver in it stays reachable through a host route
	pol.networks = "192.168.30.0/24";
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(HasNet(p.excluded, p.num_excluded, "192.168.30.0", 24) &&
		!HasNet(p.included, p.num_included, "192.168.30.0", 24) &&
		HasNet(p.included, p.num_included, "192.168.30.1", 32));

	// A wide bypass (keep the home network reachable) does not take the VPN's
	// own subnet with it: the subnet is routed again, more specifically
	pol.networks = "192.168.0.0/16 fd00::/8";
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(HasNet(p.excluded, p.num_excluded, "192.168.0.0", 16) &&
		HasNet(p.included, p.num_included, "192.168.30.0", 24) &&
		HasNet(p.included, p.num_included, "0.0.0.0", 0));
	CHECK(p.warnings[0] == 0);	// the IPv6 entry is moot, not an error

	// ... but with IPv6 blocked, an IPv6 bypass cannot be honored, and says so
	pol.block_ipv6 = 1;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.blackhole_ipv6 && strstr(p.warnings, "cannot bypass the VPN while IPv6 is blocked") != NULL);
	pol.block_ipv6 = 0;
}

static void TestSplitDns(void)
{
	se_policy pol;
	se_ipv4_config v4 = Hub4("Corp.Example.", 0);
	se_ipv4_config v4_nodns = Hub4("corp.example", 0);
	se_plan p;
	char err[256];

	printf("split DNS\n");

	v4_nodns.dns1[0] = 0;

	// Split DNS on a FULL tunnel: all traffic through the VPN, but only the
	// listed domains are resolved by the VPN's servers
	memset(&pol, 0, sizeof(pol));
	pol.tunnel_mode = SE_TUNNEL_FULL;
	pol.dns_mode = SE_DNS_SPLIT;
	pol.dns_domains = "*.Intra.Example, lab.example. bad/domain  .dev.example corp.example";

	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.dns_enabled && !p.dns_match_all);
	CHECK(p.num_match_domains == 4);
	CHECK(HasStr(p.match_domains, p.num_match_domains, "corp.example"));	// hub's, normalized, deduplicated
	CHECK(HasStr(p.match_domains, p.num_match_domains, "intra.example"));
	CHECK(HasStr(p.match_domains, p.num_match_domains, "lab.example"));
	CHECK(HasStr(p.match_domains, p.num_match_domains, "dev.example"));
	CHECK(p.num_search_domains == 1 && HasStr(p.search_domains, p.num_search_domains, "corp.example"));
	CHECK(strstr(p.warnings, "bad/domain") != NULL);

	// All names through the VPN on a split tunnel
	pol.tunnel_mode = SE_TUNNEL_INCLUDE;
	pol.networks = "10.0.0.0/8";
	pol.dns_mode = SE_DNS_ALL;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.dns_enabled && p.dns_match_all && p.num_match_domains == 0 && p.num_dns_servers == 1);

	// Split DNS without any domain cannot work: resolver untouched, reported
	pol.dns_mode = SE_DNS_SPLIT;
	pol.dns_domains = NULL;
	v4.domain[0] = 0;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(!p.dns_enabled && p.num_dns_servers == 0 && strstr(p.warnings, "no domain is listed") != NULL);

	// No resolver from the hub and none configured
	pol.dns_domains = "corp.example";
	CHECK(se_make_plan(&pol, &v4_nodns, NULL, &p, err, sizeof(err)) == 1);
	CHECK(!p.dns_enabled && strstr(p.warnings, "no usable DNS server") != NULL);

	// ... but a configured one is used
	pol.dns_servers = "10.0.0.53; 10.0.0.54, not-an-ip";
	CHECK(se_make_plan(&pol, &v4_nodns, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.dns_enabled && p.num_dns_servers == 2 && strstr(p.warnings, "not-an-ip") != NULL);
}

static void TestServerDecides(void)
{
	se_policy pol;
	se_ipv4_config v4;
	se_ipv6_config v6 = Hub6();
	se_plan p;
	char err[256];

	printf("server decides (Windows client behavior)\n");

	memset(&pol, 0, sizeof(pol));
	pol.tunnel_mode = SE_TUNNEL_SERVER;
	pol.networks = "172.31.0.0/16";	// the user's list plays no part in this mode
	pol.use_pushed_routes = 0;		// nor does this switch
	pol.block_ipv6 = 1;

	// Default gateway, nothing pushed: full tunnel, all names
	v4 = Hub4("corp.example", 0);
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.full_tunnel == 1 && HasNet(p.included, p.num_included, "0.0.0.0", 0));
	CHECK(!HasNet(p.included, p.num_included, "172.31.0.0", 16) && p.num_excluded == 0);
	CHECK(p.dns_enabled && p.dns_match_all);
	CHECK(p.blackhole_ipv6 == 1);	// leak protection follows the outcome

	// ... with IPv6 on the hub, that is routed too
	CHECK(se_make_plan(&pol, &v4, &v6, &p, err, sizeof(err)) == 1);
	CHECK(HasNet(p.included, p.num_included, "::", 0) && !p.blackhole_ipv6);

	// No gateway, routes pushed: SoftEther's documented split tunnel setup
	v4 = Hub4("corp.example", 0);
	v4.gateway[0] = 0;
	v4.num_routes = 2;
	strcpy(v4.routes[0].network, "10.20.0.0");
	v4.routes[0].prefix_len = 16;
	strcpy(v4.routes[0].gateway, "192.168.30.1");
	strcpy(v4.routes[1].network, "10.30.5.0");
	v4.routes[1].prefix_len = 24;
	strcpy(v4.routes[1].gateway, "192.168.30.1");
	CHECK(se_make_plan(&pol, &v4, &v6, &p, err, sizeof(err)) == 1);
	CHECK(p.full_tunnel == 0 && !HasNet(p.included, p.num_included, "0.0.0.0", 0));
	CHECK(HasNet(p.included, p.num_included, "192.168.30.0", 24) &&
		HasNet(p.included, p.num_included, "10.20.0.0", 16) &&
		HasNet(p.included, p.num_included, "10.30.5.0", 24));
	CHECK(!HasNet(p.included, p.num_included, "172.31.0.0", 16));
	// IPv6 is decided on its own, from the router advertisement: the hub has a
	// router, so IPv6 goes through the VPN even though IPv4 is split
	CHECK(HasNet(p.included, p.num_included, "::", 0) && !HasNet(p.included, p.num_included, "2001:db8:1::", 64));
	CHECK(p.dns_enabled && !p.dns_match_all && HasStr(p.match_domains, p.num_match_domains, "corp.example"));
	CHECK(!p.blackhole_ipv6);

	// ... and without a router, only the advertised prefix
	{
		se_ipv6_config v6_norouter = v6;

		v6_norouter.router[0] = 0;
		CHECK(se_make_plan(&pol, &v4, &v6_norouter, &p, err, sizeof(err)) == 1);
		CHECK(HasNet(p.included, p.num_included, "2001:db8:1::", 64) && !HasNet(p.included, p.num_included, "::", 0));
	}

	// Gateway AND pushed routes: the routes win and the gateway is ignored (RFC 3442)
	strcpy(v4.gateway, "192.168.30.1");
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.full_tunnel == 0 && !HasNet(p.included, p.num_included, "0.0.0.0", 0) && p.num_included == 3);

	// A pushed default route makes it a full tunnel
	v4 = Hub4("corp.example", 1);	// pushes 10.20.0.0/16 and 0.0.0.0/0
	v4.gateway[0] = 0;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.full_tunnel == 1 && HasNet(p.included, p.num_included, "0.0.0.0", 0) && p.dns_match_all);

	// Neither gateway nor routes: only the VPN's own subnet
	v4 = Hub4("", 0);
	v4.gateway[0] = 0;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.full_tunnel == 0 && p.num_included == 1 && HasNet(p.included, p.num_included, "192.168.30.0", 24));

	// The user's own modes still report their outcome
	pol.tunnel_mode = SE_TUNNEL_EXCLUDE;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1 && p.full_tunnel == 1);
	pol.tunnel_mode = SE_TUNNEL_INCLUDE;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1 && p.full_tunnel == 0);
	pol.tunnel_mode = 99;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 0);
}

static void TestRobustness(void)
{
	se_policy pol;
	se_ipv4_config v4 = Hub4("corp.example", 0);
	se_ipv6_config v6 = Hub6();
	static se_plan p;
	static char big[8192];
	char err[256];
	int i, n;

	printf("robustness\n");

	memset(&pol, 0, sizeof(pol));

	// A DNS server of a family the VPN does not carry is not used: with IPv6
	// blocked it would be unreachable, without it queries would bypass the VPN
	pol.tunnel_mode = SE_TUNNEL_FULL;
	pol.block_ipv6 = 1;
	pol.dns_servers = "2001:db8::53";
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(strstr(p.warnings, "carries no IPv6") != NULL);
	// ... and with nothing usable left of the override, the hub's own server serves
	CHECK(p.dns_enabled && p.num_dns_servers == 1 && strcmp(p.dns_servers[0], "192.168.30.1") == 0);
	pol.dns_servers = "2001:db8::53 10.0.0.53";
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.dns_enabled && p.num_dns_servers == 1 && strcmp(p.dns_servers[0], "10.0.0.53") == 0);
	CHECK(se_make_plan(&pol, &v4, &v6, &p, err, sizeof(err)) == 1 && p.num_dns_servers == 2);
	pol.dns_servers = "10.0.0.53";
	CHECK(se_make_plan(&pol, NULL, &v6, &p, err, sizeof(err)) == 1);
	CHECK(strstr(p.warnings, "carries no IPv4") != NULL &&
		p.dns_enabled && p.num_dns_servers == 1 && strcmp(p.dns_servers[0], "2001:db8:1::53") == 0);
	pol.dns_servers = "10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5";
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.num_dns_servers == SE_PLAN_MAX_DNS && strstr(p.warnings, "too many DNS servers") != NULL);
	pol.dns_servers = NULL;
	pol.block_ipv6 = 0;

	// An entry too long to hold is rejected, never parsed from its beginning
	n = snprintf(big, sizeof(big), "10.0.0.0/");
	memset(big + n, '0', 300);
	strcpy(big + n + 300, "8JUNK 10.9.0.0/16");
	pol.tunnel_mode = SE_TUNNEL_INCLUDE;
	pol.networks = big;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(!HasNet(p.included, p.num_included, "10.0.0.0", 8) && HasNet(p.included, p.num_included, "10.9.0.0", 16));
	CHECK(strstr(p.warnings, "too long") != NULL);

	// More networks than fit: said, not silent; the resolver's route survives
	// because it lies in the VPN's subnet, which is added first
	n = 0;
	for (i = 0; i < 200; i++)
	{
		n += snprintf(big + n, sizeof(big) - (size_t)n, "10.%d.0.0/16 ", i);
	}
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.num_included == SE_PLAN_MAX_NETS && strstr(p.warnings, "list of networks is too long") != NULL);
	CHECK(HasNet(p.included, p.num_included, "192.168.30.0", 24));
	// ... and a resolver that needs a host route that no longer fits is reported
	pol.dns_servers = "172.20.0.53";
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(strstr(p.warnings, "DNS server 172.20.0.53 may be unreachable") != NULL);
	pol.dns_servers = NULL;

	// Many warnings: each one whole, the buffer never overrun
	n = 0;
	for (i = 0; i < 300; i++)
	{
		n += snprintf(big + n, sizeof(big) - (size_t)n, "bad-entry-%d ", i);
	}
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(strlen(p.warnings) < sizeof(p.warnings) && p.warnings[strlen(p.warnings) - 1] == '.');
	pol.networks = NULL;

	// Domains: what cannot be a resolver rule is refused
	pol.tunnel_mode = SE_TUNNEL_FULL;
	pol.dns_mode = SE_DNS_SPLIT;
	v4.domain[0] = 0;
	pol.dns_domains = "local 10.0.0.1 -bad.example bad-.example a..b ok.local xn--bcher-kva.de _msdcs.ad.example lan";
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.num_match_domains == 4);
	CHECK(HasStr(p.match_domains, p.num_match_domains, "ok.local") &&
		HasStr(p.match_domains, p.num_match_domains, "xn--bcher-kva.de") &&
		HasStr(p.match_domains, p.num_match_domains, "_msdcs.ad.example") &&
		HasStr(p.match_domains, p.num_match_domains, "lan"));
	CHECK(strstr(p.warnings, "\"local\"") != NULL && strstr(p.warnings, "\"10.0.0.1\"") != NULL);

	// A label longer than DNS allows
	memset(big, 'a', 64);
	strcpy(big + 64, ".example");
	pol.dns_domains = big;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1 && p.num_match_domains == 0 && !p.dns_enabled);

	// The hub cannot claim Bonjour's domain either
	strcpy(v4.domain, "local");
	pol.dns_domains = "corp.example";
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.num_match_domains == 1 && p.num_search_domains == 0 && strstr(p.warnings, "announced by the VPN") != NULL);

	// More domains than fit
	n = 0;
	for (i = 0; i < 40; i++)
	{
		n += snprintf(big + n, sizeof(big) - (size_t)n, "d%d.example ", i);
	}
	pol.dns_domains = big;
	v4.domain[0] = 0;
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.num_match_domains == SE_PLAN_MAX_DOMAINS && strstr(p.warnings, "list of DNS domains is too long") != NULL);
}

int main(void)
{
	TestParse();
	TestFull();
	TestInclude();
	TestExclude();
	TestSplitDns();
	TestServerDecides();
	TestRobustness();

	printf("%s (%d checks, %d failure%s)\n", g_failed == 0 ? "PASSED" : "FAILED",
		g_checks, g_failed, g_failed == 1 ? "" : "s");

	return g_failed == 0 ? 0 : 1;
}
