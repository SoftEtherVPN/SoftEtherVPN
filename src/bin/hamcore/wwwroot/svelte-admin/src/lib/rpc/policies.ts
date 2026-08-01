import { m } from '$lib/paraglide/messages';

export type PolicyType = 'bool' | 'num';
export type PolicyUnit = 'seconds' | 'bps';

/** Shared form shape for the reusable policy editor (groups and users). */
export interface PolicyFormData {
	usePolicy: boolean;
	boolPolicies: Record<string, boolean>;
	numPolicies: Record<string, number>;
	numEnabled: Record<string, boolean>;
}

export interface PolicyItem {
	/** RPC field key on VpnRpcSetGroup, e.g. "policy:Access_bool" */
	key: string;
	type: PolicyType;
	/** Index into the POL_<n> (label) / POL_EX_<n> (description) message tables */
	index: number;
	/** Numeric policies only: allowed value range and optional unit. */
	min?: number;
	max?: number;
	unit?: PolicyUnit;
}

// Order matches the SoftEther policy table (POL_0 … POL_37).
const defs: ReadonlyArray<readonly [string, PolicyType]> = [
	['Access', 'bool'],
	['DHCPFilter', 'bool'],
	['DHCPNoServer', 'bool'],
	['DHCPForce', 'bool'],
	['NoBridge', 'bool'],
	['NoRouting', 'bool'],
	['CheckMac', 'bool'],
	['CheckIP', 'bool'],
	['ArpDhcpOnly', 'bool'],
	['PrivacyFilter', 'bool'],
	['NoServer', 'bool'],
	['NoBroadcastLimiter', 'bool'],
	['MonitorPort', 'bool'],
	['MaxConnection', 'num'],
	['TimeOut', 'num'],
	['MaxMac', 'num'],
	['MaxIP', 'num'],
	['MaxUpload', 'num'],
	['MaxDownload', 'num'],
	['FixPassword', 'bool'],
	['MultiLogins', 'num'],
	['NoQoS', 'bool'],
	['RSandRAFilter', 'bool'],
	['RAFilter', 'bool'],
	['DHCPv6Filter', 'bool'],
	['DHCPv6NoServer', 'bool'],
	['NoRoutingV6', 'bool'],
	['CheckIPv6', 'bool'],
	['NoServerV6', 'bool'],
	['MaxIPv6', 'num'],
	['NoSavePassword', 'bool'],
	['AutoDisconnect', 'num'],
	['FilterIPv4', 'bool'],
	['FilterIPv6', 'bool'],
	['FilterNonIP', 'bool'],
	['NoIPv6DefaultRouterInRA', 'bool'],
	['NoIPv6DefaultRouterInRAWhenIPv6', 'bool'],
	['VLanId', 'num']
];

const U32_MAX = 4294967295;

// Value constraints for the numeric policies.
const NUM_META: Record<string, { min: number; max: number; unit?: PolicyUnit }> = {
	'policy:MaxConnection_u32': { min: 1, max: 32 },
	'policy:TimeOut_u32': { min: 5, max: 60, unit: 'seconds' },
	'policy:MaxMac_u32': { min: 1, max: 65535 },
	'policy:MaxIP_u32': { min: 1, max: 65535 },
	'policy:MaxUpload_u32': { min: 1, max: U32_MAX, unit: 'bps' },
	'policy:MaxDownload_u32': { min: 1, max: U32_MAX, unit: 'bps' },
	'policy:MultiLogins_u32': { min: 1, max: 65535 },
	'policy:MaxIPv6_u32': { min: 1, max: 65535 },
	'policy:AutoDisconnect_u32': { min: 1, max: U32_MAX, unit: 'seconds' },
	'policy:VLanId_u32': { min: 1, max: 4095 }
};

export const POLICIES: PolicyItem[] = defs.map(([name, type], index) => {
	const key = `policy:${name}_${type === 'bool' ? 'bool' : 'u32'}`;
	return { key, type, index, ...(type === 'num' ? NUM_META[key] : {}) };
});

export const NUM_POLICIES = POLICIES.filter((p) => p.type === 'num');

const boolKeys = POLICIES.filter((p) => p.type === 'bool').map((p) => p.key);

export const emptyBoolPolicies = (): Record<string, boolean> =>
	Object.fromEntries(boolKeys.map((k) => [k, false]));

/** Every numeric policy disabled. */
export const emptyNumEnabled = (): Record<string, boolean> =>
	Object.fromEntries(NUM_POLICIES.map((p) => [p.key, false]));

/** Each numeric value seeded to its minimum (a valid starting point once enabled). */
export const emptyNumPolicies = (): Record<string, number> =>
	Object.fromEntries(NUM_POLICIES.map((p) => [p.key, p.min ?? 0]));

// SoftEther's default security policy (matches the server's GetDefaultPolicy):
// "Allow Access" enabled, and only the "Max TCP connections" (32) and "Time-out"
// (20s) numeric limits are active; every other policy is off.
export const defaultBoolPolicies = (): Record<string, boolean> => ({
	...emptyBoolPolicies(),
	['policy:Access_bool']: true
});

export const defaultNumEnabled = (): Record<string, boolean> => ({
	...emptyNumEnabled(),
	['policy:MaxConnection_u32']: true,
	['policy:TimeOut_u32']: true
});

export const defaultNumPolicies = (): Record<string, number> => ({
	...emptyNumPolicies(),
	['policy:MaxConnection_u32']: 32,
	['policy:TimeOut_u32']: 20
});

export function clampPolicy(item: PolicyItem, value: number): number {
	const min = item.min ?? 0;
	const max = item.max ?? U32_MAX;
	if (!Number.isFinite(value)) return min;
	return Math.min(max, Math.max(min, Math.trunc(value)));
}

// ── Localized labels ────────────────────────────────────────────────────────
// Policy names/descriptions live in the POL_<n> / POL_EX_<n> message tables,
// keyed by the policy's position in the SoftEther policy list.
const policyMessages = [
	[m.POL_0, m.POL_EX_0],
	[m.POL_1, m.POL_EX_1],
	[m.POL_2, m.POL_EX_2],
	[m.POL_3, m.POL_EX_3],
	[m.POL_4, m.POL_EX_4],
	[m.POL_5, m.POL_EX_5],
	[m.POL_6, m.POL_EX_6],
	[m.POL_7, m.POL_EX_7],
	[m.POL_8, m.POL_EX_8],
	[m.POL_9, m.POL_EX_9],
	[m.POL_10, m.POL_EX_10],
	[m.POL_11, m.POL_EX_11],
	[m.POL_12, m.POL_EX_12],
	[m.POL_13, m.POL_EX_13],
	[m.POL_14, m.POL_EX_14],
	[m.POL_15, m.POL_EX_15],
	[m.POL_16, m.POL_EX_16],
	[m.POL_17, m.POL_EX_17],
	[m.POL_18, m.POL_EX_18],
	[m.POL_19, m.POL_EX_19],
	[m.POL_20, m.POL_EX_20],
	[m.POL_21, m.POL_EX_21],
	[m.POL_22, m.POL_EX_22],
	[m.POL_23, m.POL_EX_23],
	[m.POL_24, m.POL_EX_24],
	[m.POL_25, m.POL_EX_25],
	[m.POL_26, m.POL_EX_26],
	[m.POL_27, m.POL_EX_27],
	[m.POL_28, m.POL_EX_28],
	[m.POL_29, m.POL_EX_29],
	[m.POL_30, m.POL_EX_30],
	[m.POL_31, m.POL_EX_31],
	[m.POL_32, m.POL_EX_32],
	[m.POL_33, m.POL_EX_33],
	[m.POL_34, m.POL_EX_34],
	[m.POL_35, m.POL_EX_35],
	[m.POL_36, m.POL_EX_36],
	[m.POL_37, m.POL_EX_37]
];

/** Localized policy name, e.g. "Allow Access". */
export function policyLabel(index: number): string {
	return policyMessages[index]![0]!() ?? '';
}

/** Localized policy description. */
export function policyDescription(index: number): string {
	return policyMessages[index]![1]!() ?? '';
}

/** Localized unit suffix for a numeric policy input. */
export function policyUnitLabel(unit?: PolicyUnit): string {
	// "seconds" has a dedicated translated string; "bps" is a universal unit.
	if (unit === 'seconds') return m.POL_INT_SEC({ input0: '' });
	if (unit === 'bps') return m.POL_INT_BPS({ input0: '' });
	return '';
}
