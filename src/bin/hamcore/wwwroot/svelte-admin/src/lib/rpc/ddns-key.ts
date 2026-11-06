import { rpc, Util_Base64_Decode } from '$lib/rpc';

/**
 * The DDNS private key is not exposed by any RPC. VPN Server Manager reads it
 * out of the server configuration file instead (`SmDdnsGetKey` in
 * `src/Cedar/SM.c`) and so do we: `GetConfig`, then pull `byte Key` out of the
 * `declare DDnsClient` block.
 *
 * The config stores the key base64-encoded, which is exactly the form the
 * Manager displays, so no decoding round-trip is needed here.
 *
 * Returns `null` when the directive is absent — a server with the Dynamic DNS
 * function disabled has no key.
 */
export async function getDDnsKey(): Promise<string | null> {
	const config = await rpc.GetConfig();

	// `_bin` fields are base64 strings at runtime despite the `Uint8Array` type
	// (see the reviver bug documented in CLAUDE.md).
	const text = new TextDecoder().decode(Util_Base64_Decode(config.FileData_bin));

	return findDDnsKey(text);
}

/** Exported for the sake of being testable without a server. */
export function findDDnsKey(config: string): string | null {
	const start = config.search(/^\s*declare\s+DDnsClient\s*$/m);
	if (start < 0) return null;

	// Stop at the closing brace of the directive so a `Key` belonging to some
	// later block can never be picked up by mistake.
	const body = config.slice(start);
	const end = body.search(/^\s*\}/m);

	const key = /^\s*byte\s+Key\s+(\S+)\s*$/m.exec(end < 0 ? body : body.slice(0, end));

	return key?.[1] ?? null;
}
