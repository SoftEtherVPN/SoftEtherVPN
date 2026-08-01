/**
 * Central TanStack Query key factory.
 *
 * Keys are hierarchical because `invalidateQueries` matches on prefix: passing
 * `hubKeys.all` invalidates the hub list *and* every per-hub query, while
 * `hubKeys.groups(name)` invalidates that hub's group list and every single
 * group under it. Building the keys here instead of inline is what keeps that
 * relationship true — an inline `['hub', name]` next to an inline
 * `['dashboard', 'hub']` silently produces two disjoint trees.
 *
 * Rule of thumb: a query reading a resource uses the narrowest key; a mutation
 * changing it invalidates the narrowest key that still covers everything
 * derived from it.
 */

const server = ['server'] as const;
const connections = [...server, 'connections'] as const;

/** Server-wide settings and status. */
export const serverKeys = {
	all: server,
	/** `GetServerInfo` */
	info: () => [...server, 'info'] as const,
	/** `GetServerStatus` */
	status: () => [...server, 'status'] as const,
	/** `GetDDnsClientStatus` */
	ddns: () => [...server, 'ddns'] as const,
	/** `GetAzureStatus` */
	azure: () => [...server, 'azure'] as const,
	/** `EnumListener` */
	listeners: () => [...server, 'listeners'] as const,
	connections: {
		all: connections,
		/** `EnumConnection` */
		list: () => [...connections, 'list'] as const,
		/** `GetConnectionInfo` */
		detail: (name: string) => [...connections, 'detail', name] as const
	}
};

const hub = ['hub'] as const;
const hubDetail = (name: string) => [...hub, 'detail', name] as const;

/**
 * Virtual Hubs. `list` and `detail` share the same `hub` root so that creating
 * or deleting a hub invalidates both with a single `hubKeys.all`.
 */
export const hubKeys = {
	all: hub,
	/** `EnumHub` */
	list: () => [...hub, 'list'] as const,
	/** `GetHub` */
	detail: hubDetail,
	/** `EnumUser` */
	users: (name: string) => [...hubDetail(name), 'users'] as const,
	/** `GetUser` */
	user: (name: string, user: string) => [...hubDetail(name), 'users', user] as const,
	/** `EnumGroup` */
	groups: (name: string) => [...hubDetail(name), 'groups'] as const,
	/** `GetGroup` */
	group: (name: string, group: string) => [...hubDetail(name), 'groups', group] as const,
	/** `EnumLogFile` */
	logFiles: (name: string) => [...hubDetail(name), 'log-files'] as const
};

const ipsec = ['ipsec'] as const;

/** IPsec / L2TP settings. */
export const ipsecKeys = {
	all: ipsec,
	/** `GetIPsecServices` */
	services: () => [...ipsec, 'services'] as const,
	/** `EnumEtherIpId` */
	etherIpIds: () => [...ipsec, 'ether-ip-ids'] as const
};

const openVpn = ['openvpn'] as const;

/** OpenVPN / MS-SSTP settings. */
export const openVpnKeys = {
	all: openVpn,
	/** `GetOpenVpnSstpConfig` */
	config: () => [...openVpn, 'config'] as const
};
