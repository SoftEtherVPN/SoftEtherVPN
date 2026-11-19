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

	// No domain known anywhere: fall back to "all names", and say so
	CHECK(se_make_plan(&pol, &v4_nodomain, NULL, &p, err, sizeof(err)) == 1);
	CHECK(p.dns_enabled && p.dns_match_all && strstr(p.warnings, "No DNS domain") != NULL);
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

	// Bypassing the resolver's own network is reported
	pol.networks = "192.168.30.0/24";
	CHECK(se_make_plan(&pol, &v4, NULL, &p, err, sizeof(err)) == 1);
	CHECK(strstr(p.warnings, "bypasses the VPN") != NULL);
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
	CHECK(!p.dns_enabled && strstr(p.warnings, "did not provide a DNS server") != NULL);

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
	CHECK(HasNet(p.included, p.num_included, "2001:db8:1::", 64) && !HasNet(p.included, p.num_included, "::", 0));
	CHECK(p.dns_enabled && !p.dns_match_all && HasStr(p.match_domains, p.num_match_domains, "corp.example"));
	CHECK(!p.blackhole_ipv6);

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

int main(void)
{
	TestParse();
	TestFull();
	TestInclude();
	TestExclude();
	TestSplitDns();
	TestServerDecides();

	printf("%s (%d checks, %d failure%s)\n", g_failed == 0 ? "PASSED" : "FAILED",
		g_checks, g_failed, g_failed == 1 ? "" : "s");

	return g_failed == 0 ? 0 : 1;
}
