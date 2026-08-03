import { m } from '$lib/paraglide/messages';
import { VpnRpcServerType, VpnRpcUserAuthType } from '$lib/rpc';

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

export function translateServerType(type: VpnRpcServerType) {
	switch (type) {
		case VpnRpcServerType.Standalone:
			return m.SM_SERVER_STANDALONE();
		case VpnRpcServerType.FarmMember:
			return m.SM_FARM_MEMBER();
		case VpnRpcServerType.FarmController:
			return m.SM_FARM_CONTROLLER();
	}
}

export function translateHubOnline(value: boolean) {
	return value ? m.SM_HUB_ONLINE() : m.SM_HUB_OFFLINE();
}

export function translateSecureNat(value: boolean) {
	return value ? m.SM_HUB_SECURE_NAT_YES() : m.SM_HUB_SECURE_NAT_NO();
}

export function translateBoolean(value: boolean) {
	return value ? m.CAPS_YES() : m.CAPS_NO();
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

export function TranslateCap(cap: string): string | undefined {
	switch (cap) {
		case 'i_max_packet_size':
			return m.CT_i_max_packet_size();
		case 'i_max_hubs':
			return m.CT_i_max_hubs();
		case 'i_max_user_creation':
			return m.CT_i_max_user_creation();
		case 'i_max_sessions':
			return m.CT_i_max_sessions();
		case 'i_max_clients':
			return m.CT_i_max_clients();
		case 'i_max_bridges':
			return m.CT_i_max_bridges();
		case 'i_max_users_per_hub':
			return m.CT_i_max_users_per_hub();
		case 'i_max_groups_per_hub':
			return m.CT_i_max_groups_per_hub();
		case 'i_max_access_lists':
			return m.CT_i_max_access_lists();
		case 'i_max_mac_tables':
			return m.CT_i_max_mac_tables();
		case 'i_max_ip_tables':
			return m.CT_i_max_ip_tables();
		case 'i_max_secnat_tables':
			return m.CT_i_max_secnat_tables();
		case 'i_max_l3_sw':
			return m.CT_i_max_l3_sw();
		case 'i_max_l3_if':
			return m.CT_i_max_l3_if();
		case 'i_max_l3_table':
			return m.CT_i_max_l3_table();
		case 'b_bridge':
			return m.CT_b_bridge();
		case 'b_standalone':
			return m.CT_b_standalone();
		case 'b_cluster_controller':
			return m.CT_b_cluster_controller();
		case 'b_cluster_member':
			return m.CT_b_cluster_member();
		case 'b_vpn_client_connect':
			return m.CT_b_vpn_client_connect();
		case 'b_local_bridge':
			return m.CT_b_local_bridge();
		case 'b_must_install_pcap':
			return m.CT_b_must_install_pcap();
		case 'b_tap_supported':
			return m.CT_b_tap_supported();
		case 'b_support_config_hub':
			return m.CT_b_support_config_hub();
		case 'b_support_securenat':
			return m.CT_b_support_securenat();
		case 'b_virtual_nat_disabled':
			return m.CT_b_virtual_nat_disabled();
		case 'b_support_cascade':
			return m.CT_b_support_cascade();
		case 'b_support_cascade_cert':
			return m.CT_b_support_cascade_cert();
		case 'b_support_config_log':
			return m.CT_b_support_config_log();
		case 'b_support_autodelete':
			return m.CT_b_support_autodelete();
		case 'b_support_radius':
			return m.CT_b_support_radius();
		case 'b_support_config_rw':
			return m.CT_b_support_config_rw();
		case 'b_support_hub_admin_option':
			return m.CT_b_support_hub_admin_option();
		case 'b_support_cascade_client_cert':
			return m.CT_b_support_cascade_client_cert();
		case 'b_support_hide_hub':
			return m.CT_b_support_hide_hub();
		case 'b_support_cluster_admin':
			return m.CT_b_support_cluster_admin();
		case 'b_support_cluster':
			return m.CT_b_support_cluster();
		case 'b_support_cluster_controller':
			return m.CT_b_support_cluster_controller();
		case 'b_support_layer3':
			return m.CT_b_support_layer3();
		case 'b_support_crl':
			return m.CT_b_support_crl();
		case 'b_support_ac':
			return m.CT_b_support_ac();
		case 'b_support_read_log':
			return m.CT_b_support_read_log();
		case 'b_support_rename_cascade':
			return m.CT_b_support_rename_cascade();
		case 'b_support_license':
			return m.CT_b_support_license();
		case 'b_support_limit_multilogin':
			return m.CT_b_support_limit_multilogin();
		case 'b_support_qos':
			return m.CT_b_support_qos();
		case 'b_support_syslog':
			return m.CT_b_support_syslog();
		case 'b_cluster_hub_type_fixed':
			return m.CT_b_cluster_hub_type_fixed();
		case 'b_beta_version':
			return m.CT_b_beta_version();
		case 'b_support_check_mac':
			return m.CT_b_support_check_mac();
		case 'b_support_check_tcp_state':
			return m.CT_b_support_check_tcp_state();
		case 'b_support_network_connection_name':
			return m.CT_b_support_network_connection_name();
		case 'b_support_radius_retry_interval_and_several_servers':
			return m.CT_b_support_radius_retry_interval_and_several_servers();
		case 'b_support_vlan':
			return m.CT_b_support_vlan();
		case 'b_support_hub_ext_options':
			return m.CT_b_support_hub_ext_options();
		case 'b_support_policy_ver_3':
			return m.CT_b_support_policy_ver_3();
		case 'b_support_ipv6_acl':
			return m.CT_b_support_ipv6_acl();
		case 'b_support_ex_acl':
			return m.CT_b_support_ex_acl();
		case 'b_support_acl_group':
			return m.CT_b_support_acl_group();
		case 'b_support_ipv6_ac':
			return m.CT_b_support_ipv6_ac();
		case 'b_support_eth_vlan':
			return m.CT_b_support_eth_vlan();
		case 'b_support_msg':
			return m.CT_b_support_msg();
		case 'b_vpn3':
			return m.CT_b_vpn3();
		case 'b_vpn4':
			return m.CT_b_vpn4();
		case 'b_support_ipsec':
			return m.CT_b_support_ipsec();
		case 'b_support_sstp':
			return m.CT_b_support_sstp();
		case 'b_support_udp_acceleration':
			return m.CT_b_support_udp_acceleration();
		case 'b_support_openvpn':
			return m.CT_b_support_openvpn();
		case 'b_support_ddns':
			return m.CT_b_support_ddns();
		case 'b_support_ddns_proxy':
			return m.CT_b_support_ddns_proxy();
		case 'b_support_special_listener':
			return m.CT_b_support_special_listener();
		case 'b_support_redirect_url_acl':
			return m.CT_b_support_redirect_url_acl();
		case 'b_is_in_vm':
			return m.CT_b_is_in_vm();
		case 'b_support_azure':
			return m.CT_b_support_azure();
		case 'b_support_aes_ni':
			return m.CT_b_support_aes_ni();
		case 'b_using_selow_driver':
			return m.CT_b_using_selow_driver();
		case 'b_support_vgs':
			return m.CT_b_support_vgs();
		case 'b_support_vgs_in_client':
			return m.CT_b_support_vgs_in_client();
		case 'b_is_softether':
			return m.CT_b_is_softether();
		case 'b_suppport_push_route':
			return m.CT_b_suppport_push_route();
		case 'b_suppport_push_route_config':
			return m.CT_b_suppport_push_route_config();
	}
}
