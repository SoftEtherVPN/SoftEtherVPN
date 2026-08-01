import { m } from '$lib/paraglide/messages';
import { VpnRpcUserAuthType } from '$lib/rpc';

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

export function translateConnectionType(type: number) {
	switch (type) {
		case 0:
			return m.SM_CONNECTION_TYPE_0();
		case 1:
			return m.SM_CONNECTION_TYPE_1();
		case 2:
			return m.SM_CONNECTION_TYPE_2();
		case 3:
			return m.SM_CONNECTION_TYPE_3();
		case 4:
			return m.SM_CONNECTION_TYPE_4();
		case 5:
			return m.SM_CONNECTION_TYPE_5();
		case 6:
			return m.SM_CONNECTION_TYPE_6();
		case 7:
			return m.SM_CONNECTION_TYPE_7();
		case 8:
			return m.SM_CONNECTION_TYPE_8();
		case 9:
			return m.SM_CONNECTION_TYPE_9();
	}
}

export function translateAuthType(type: VpnRpcUserAuthType) {
	switch (type) {
		case VpnRpcUserAuthType.Anonymous:
			return m.SM_AUTHTYPE_0();
		case VpnRpcUserAuthType.Password:
			return m.SM_AUTHTYPE_1();
		case VpnRpcUserAuthType.UserCert:
			return m.SM_AUTHTYPE_2();
		case VpnRpcUserAuthType.RootCert:
			return m.SM_AUTHTYPE_3();
		case VpnRpcUserAuthType.Radius:
			return m.SM_AUTHTYPE_4();
		case VpnRpcUserAuthType.NTDomain:
			return m.SM_AUTHTYPE_5();
	}
}
