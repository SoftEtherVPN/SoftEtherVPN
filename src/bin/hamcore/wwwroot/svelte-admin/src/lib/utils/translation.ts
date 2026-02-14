import { m } from '$lib/paraglide/messages';

export function translateHubType(type: number) {
	switch (type) {
		case 1:
			return m.SM_HUB_STATIC();
		case 2:
			return m.SM_HUB_DYNAMIC();
		default:
			return m.SM_HUB_STANDALONE();
	}
}

export function translateHubOnline(value: boolean) {
	return value ? m.SM_HUB_ONLINE() : m.SM_HUB_OFFLINE();
}

export function translateSecureNat(value: boolean) {
	return value ? m.SM_HUB_SECURE_NAT_YES() : m.SM_HUB_SECURE_NAT_NO();
}
