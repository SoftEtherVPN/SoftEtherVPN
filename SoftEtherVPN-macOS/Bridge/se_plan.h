// SoftEther VPN for macOS - tunnel plan: which networks and which DNS names go
// through the VPN.
//
// Pure C with no dependency on the SoftEther core, so the app can link it for
// previews and the logic is unit-tested on any platform (Bridge/test). The
// packet tunnel provider maps the result 1:1 onto NEPacketTunnelNetworkSettings.

#ifndef SE_PLAN_H
#define SE_PLAN_H

#include <stddef.h>

#include "se_bridge.h"

#ifdef __cplusplus
extern "C" {
#endif

// What is routed through the VPN
enum
{
	SE_TUNNEL_FULL = 0,		// everything
	SE_TUNNEL_INCLUDE = 1,	// only the VPN's own subnet and the listed networks
	SE_TUNNEL_EXCLUDE = 2,	// everything except the listed networks
	SE_TUNNEL_SERVER = 3,	// what the VPN server says, like the Windows client.
							// IPv4: its pushed routes (DHCP option 121) if there
							// are any, else everything if it hands out a default
							// gateway, else only the VPN's own subnet. IPv6:
							// everything if the hub advertises a router.
};

// Which names the VPN's DNS servers resolve
enum
{
	SE_DNS_AUTO = 0,		// all names when everything is routed; only the
							// VPN's domains when the tunnel is split - or all
							// names there too, with a warning, when no domain
							// is known at all
	SE_DNS_ALL = 1,			// all names
	SE_DNS_SPLIT = 2,		// only the listed domains (and the hub's DHCP domain)
	SE_DNS_OFF = 3,			// leave the system resolver alone
};

// List arguments are free text: entries separated by commas, semicolons or
// any whitespace. Networks are "a.b.c.d/len", "a.b.c.d" (/32), "a.b.c.d/mask",
// or the IPv6 equivalents. All pointers may be NULL.
typedef struct
{
	int tunnel_mode;				// SE_TUNNEL_*
	const char *networks;			// INCLUDE: routed networks; EXCLUDE: bypassed networks
	int use_pushed_routes;			// INCLUDE: also route what the hub's DHCP pushed (option 121)

	int block_ipv6;					// FULL / EXCLUDE on a VPN without IPv6: capture
									// IPv6 too and drop it, so it cannot leave
									// outside the VPN (see se_plan.blackhole_ipv6)

	int dns_mode;					// SE_DNS_*
	const char *dns_servers;		// override of the hub's DNS servers
	const char *dns_domains;		// domains resolved through the VPN (SE_DNS_SPLIT / AUTO)
} se_policy;

#define SE_PLAN_MAX_NETS		128

// Unique-local address the tunnel is given only to attract IPv6 for discarding
#define SE_BLACKHOLE_IPV6		"fd53:6f66:7445:7468::1"
#define SE_BLACKHOLE_IPV6_PREFIX	64
#define SE_PLAN_MAX_DNS			4
#define SE_PLAN_MAX_DOMAINS		32

typedef struct
{
	int is_ipv6;
	char address[SE_ADDR_LEN];		// network address, host bits cleared
	char mask[SE_ADDR_LEN];			// IPv4 only: dotted mask
	int prefix_len;
} se_net;

typedef struct
{
	// 1: everything is routed through the VPN (possibly minus excluded[]);
	// 0: a split tunnel. This is where SE_TUNNEL_SERVER's outcome shows. It is
	// the outcome for IPv4 (for IPv6 on a VPN that carries only IPv6).
	int full_tunnel;

	// Routes. A default route is the entry with prefix_len 0.
	int num_included;
	se_net included[SE_PLAN_MAX_NETS];
	int num_excluded;
	se_net excluded[SE_PLAN_MAX_NETS];

	// 1: the VPN carries no IPv6 but everything is to be routed through it.
	// The tunnel then takes an IPv6 address of its own (SE_BLACKHOLE_IPV6) with
	// a default route (already in included[]), and the provider discards every
	// IPv6 packet instead of forwarding it.
	int blackhole_ipv6;

	// DNS. dns_enabled 0: do not touch the system resolver.
	int dns_enabled;
	int num_dns_servers;
	char dns_servers[SE_PLAN_MAX_DNS][SE_ADDR_LEN];
	// dns_match_all 1: the VPN's servers resolve every name. Otherwise only
	// the names under match_domains go to them (split DNS).
	int dns_match_all;
	int num_match_domains;
	char match_domains[SE_PLAN_MAX_DOMAINS][SE_DOMAIN_LEN];
	// Suffixes appended to single-label names (the hub's DHCP domain)
	int num_search_domains;
	char search_domains[SE_PLAN_MAX_DOMAINS][SE_DOMAIN_LEN];

	// Non-fatal remarks for the UI / log, newline separated (e.g. an entry of
	// the network list that could not be parsed)
	char warnings[2048];
} se_plan;

// Build the plan from the user's policy and what the hub handed out. v4 and v6
// may each be NULL when that family is not configured, but not both. Returns 1
// on success; 0 with a message when nothing usable can be built.
int se_make_plan(const se_policy *policy, const se_ipv4_config *v4, const se_ipv6_config *v6,
	se_plan *out, char *err, size_t err_size);

// Parse one network entry (same syntax as the lists). Returns 1 on success.
int se_parse_net(const char *text, se_net *out);

// Indexed accessors (NULL when out of range). They exist for Swift, which
// imports the fixed-size arrays above as tuples that cannot be subscripted.
const se_net *se_plan_included(const se_plan *plan, int index);
const se_net *se_plan_excluded(const se_plan *plan, int index);
const char *se_plan_dns_server(const se_plan *plan, int index);
const char *se_plan_match_domain(const se_plan *plan, int index);
const char *se_plan_search_domain(const se_plan *plan, int index);
const char *se_plan_warnings(const se_plan *plan);
const char *se_net_address(const se_net *net);
const char *se_net_mask(const se_net *net);

#ifdef __cplusplus
}
#endif

#endif	// SE_PLAN_H
