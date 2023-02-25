// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Hub.c
// Virtual HUB module

#include "Hub.h"

#include "Admin.h"
#include "Bridge.h"
#include "Connection.h"
#include "Link.h"
#include "Nat.h"
#include "NativeStack.h"
#include "Protocol.h"
#include "Radius.h"
#include "SecureNAT.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#define GetHubAdminOptionDataAndSet(ao, name, dest) \
	value = GetHubAdminOptionData(ao, name);        \
	if (value != INFINITE)                          \
	{                                               \
		dest = value;                               \
	}

static UCHAR broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static char vgs_ua_str[9] = {0};
static bool g_vgs_emb_tag = false;

// A list of administration options that are currently supported and its default values
// These names must be shorter than 64 bytes
ADMIN_OPTION admin_options[] =
{
	{"allow_hub_admin_change_option", 0},
	{"max_users", 0},
	{"max_multilogins_per_user", 0},
	{"max_groups", 0},
	{"max_accesslists", 0},
	{"max_sessions_client_bridge_apply", 0},
	{"max_sessions", 0},
	{"max_sessions_client", 0},
	{"max_sessions_bridge", 0},
	{"max_bitrates_download", 0},
	{"max_bitrates_upload", 0},
	{"deny_empty_password", 0},
	{"deny_bridge", 0},
	{"deny_routing", 0},
	{"deny_qos", 0},
	{"deny_change_user_password", 0},
	{"no_change_users", 0},
	{"no_change_groups", 0},
	{"no_securenat", 0},
	{"no_securenat_enablenat", 0},
	{"no_securenat_enabledhcp", 0},
	{"no_cascade", 0},
	{"no_online", 0},
	{"no_offline", 0},
	{"no_change_log_config", 0},
	{"no_disconnect_session", 0},
	{"no_delete_iptable", 0},
	{"no_delete_mactable", 0},
	{"no_enum_session", 0},
	{"no_query_session", 0},
	{"no_change_admin_password", 0},
	{"no_change_log_switch_type", 0},
	{"no_change_access_list", 0},
	{"no_change_access_control_list", 0},
	{"no_change_cert_list", 0},
	{"no_change_crl_list", 0},
	{"no_read_log_file", 0},
	{"deny_hub_admin_change_ext_option", 0},
	{"no_delay_jitter_packet_loss", 0},
	{"no_change_msg", 0},
	{"no_access_list_include_file", 0},
};

UINT num_admin_options = sizeof(admin_options) / sizeof(ADMIN_OPTION);


// Create an EAP client for the specified Virtual Hub
EAP_CLIENT *HubNewEapClient(CEDAR *cedar, char *hubname, char *client_ip_str, char *username, char *vpn_protocol_state_str, bool proxy_only, 
							PPP_LCP **response, UCHAR last_recv_eapid)
{
	HUB *hub = NULL;
	EAP_CLIENT *ret = NULL;
	char radius_servers[MAX_PATH] = {0};
	UINT radius_port = 0;
	UINT radius_retry_interval = 0;
	char radius_secret[MAX_PATH] = {0};
	char radius_suffix_filter[MAX_PATH] = {0};
	if (cedar == NULL || hubname == NULL || client_ip_str == NULL || username == NULL)
	{
		return NULL;
	}

	// Find the Virtual Hub
	LockHubList(cedar);
	{
		hub = GetHub(cedar, hubname);
	}
	UnlockHubList(cedar);

	if (hub != NULL)
	{
		if (GetRadiusServerEx2(hub, radius_servers, sizeof(radius_servers), &radius_port, radius_secret,
			sizeof(radius_secret), &radius_retry_interval, radius_suffix_filter, sizeof(radius_suffix_filter)))
		{
			bool use_peap = hub->RadiusUsePeapInsteadOfEap;

			if (IsEmptyStr(radius_suffix_filter) || EndWith(username, radius_suffix_filter))
			{
				TOKEN_LIST *radius_servers_list = ParseToken(radius_servers, " ,;\t");

				if (radius_servers_list != NULL && radius_servers_list->NumTokens >= 1)
				{
					// Try for each of RADIUS servers
					UINT i;
					bool finish = false;

					for (i = 0;i < radius_servers_list->NumTokens;i++)
					{
						EAP_CLIENT *eap;
						IP ip;

						if (GetIP(&ip, radius_servers_list->Token[i]))
						{
							eap = NewEapClient(&ip, radius_port, radius_secret, radius_retry_interval,
								RADIUS_INITIAL_EAP_TIMEOUT, client_ip_str, username, hubname, last_recv_eapid);

							if (eap != NULL)
							{
								if (IsEmptyStr(vpn_protocol_state_str) == false)
								{
									StrCpy(eap->In_VpnProtocolState, sizeof(eap->In_VpnProtocolState), vpn_protocol_state_str);
								}

								if (proxy_only && response != NULL)
								{
									// EAP proxy for EAP-capable clients
									PPP_LCP *lcp = EapClientSendEapIdentity(eap);
									if (lcp != NULL)
									{
										*response = lcp;
										eap->GiveupTimeout = RADIUS_RETRY_TIMEOUT;
										ret = eap;
										finish = true;
									}
								}
								else if (use_peap == false)
								{
									// EAP
									if (EapClientSendMsChapv2AuthRequest(eap))
									{
										eap->GiveupTimeout = RADIUS_RETRY_TIMEOUT;
										ret = eap;
										finish = true;
									}
								}
								else
								{
									// PEAP
									if (PeapClientSendMsChapv2AuthRequest(eap))
									{
										eap->GiveupTimeout = RADIUS_RETRY_TIMEOUT;
										ret = eap;
										finish = true;
									}
								}

								if (finish == false)
								{
									ReleaseEapClient(eap);
								}
							}
						}

						if (finish)
						{
							break;
						}
					}
				}

				FreeToken(radius_servers_list);
			}
		}
	}

	ReleaseHub(hub);

	return ret;
}

// Create a user list
LIST *NewUserList()
{
	LIST *o = NewList(CompareUserList);

	return o;
}

// Search whether the specified user matches to the user list (with cache expiration)
bool IsUserMatchInUserListWithCacheExpires(LIST *o, char *filename, UINT64 user_hash, UINT64 lifetime)
{
	bool ret = false;
	UINT64 now = Tick64();
	// Validate arguments
	if (o == NULL || filename == NULL || user_hash == 0)
	{
		return false;
	}

	LockList(o);
	{
		if (lifetime != 0)
		{
			if (o->Param1 == 0 || (now >= (o->Param1 + lifetime)))
			{
				DeleteAllUserListCache(o);

				o->Param1 = now;
			}
		}

		ret = IsUserMatchInUserList(o, filename, user_hash);
	}
	UnlockList(o);

	return ret;
}
bool IsUserMatchInUserListWithCacheExpiresAcl(LIST *o, char *name_in_acl, UINT64 user_hash, UINT64 lifetime)
{
	char tmp[16];
	bool exclude = false;
	char filename[MAX_SIZE];
	char filename2[MAX_SIZE];
	bool is_full_path = false;
	bool ret = false;
	// Validate arguments
	if (o == NULL || name_in_acl == NULL || user_hash == 0 || StrLen(name_in_acl) < 9)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), name_in_acl);
	StrLower(tmp);

	tmp[8] = 0;

	if (Cmp(tmp, ACCESS_LIST_INCLUDED_PREFIX, 8) == 0)
	{
		// include
		exclude = false;
	}
	else
	{
		// exclude
		exclude = true;
	}

	// Extract the file name
	StrCpy(filename, sizeof(filename), name_in_acl + 8);
	Trim(filename);

	// Identify whether the file name is an absolute path
	if (filename[0] == '\\' || filename[0] == '/' || (filename[1] == ':' && filename[2] == '\\'))
	{
		is_full_path = true;
	}

	if (is_full_path == false)
	{
		// Prepend a '@' if the file name is a relative path
		StrCpy(filename2, sizeof(filename2), "@");
		StrCat(filename2, sizeof(filename2), filename);
		StrCpy(filename, sizeof(filename), filename2);
	}

	ret = IsUserMatchInUserListWithCacheExpires(o, filename, user_hash, lifetime);

	if (exclude)
	{
		ret = NEGATIVE_BOOL(ret);
	}

	return ret;
}

// Search whether the specified user matches to the user list
bool IsUserMatchInUserList(LIST *o, char *filename, UINT64 user_hash)
{
	USERLIST *u;
	bool ret = false;
	// Validate arguments
	if (o == NULL || filename == NULL || user_hash == 0)
	{
		return false;
	}

	LockList(o);
	{
		u = FindUserList(o, filename);
		if (u == NULL)
		{
			u = LoadUserList(o, filename);
		}

		if (u != NULL)
		{
			ret = IsInt64InList(u->UserHashList, user_hash);
		}
	}
	UnlockList(o);

	return ret;
}

// Read the user list
USERLIST *LoadUserList(LIST *o, char *filename)
{
	USERLIST *u;
	BUF *b;
	// Validate arguments
	if (o == NULL || filename == NULL)
	{
		return NULL;
	}

	u = FindUserList(o, filename);

	if (u != NULL)
	{
		Delete(o, u);

		FreeUserListEntry(u);
	}

	u = ZeroMalloc(sizeof(USERLIST));

	StrCpy(u->Filename, sizeof(u->Filename), filename);

	u->UserHashList = NewInt64List(false);

	b = ReadDumpWithMaxSize(filename, ACCESS_LIST_INCLUDE_FILE_MAX_SIZE);
	if (b != NULL)
	{
		while (true)
		{
			char *line = CfgReadNextLine(b);
			UINT64 ui;
			if (line == NULL)
			{
				break;
			}

			Trim(line);

			if (IsEmptyStr(line) == false)
			{
				if (StartWith(line, "#") == false &&
					StartWith(line, "//") == false &&
					StartWith(line, ";") == false)
				{
					ui = UsernameToInt64(line);

					AddInt64Distinct(u->UserHashList, ui);
				}
			}

			Free(line);
		}

		FreeBuf(b);
	}

	Add(o, u);

	return u;
}

// Release the user list entry
void FreeUserListEntry(USERLIST *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	ReleaseInt64List(u->UserHashList);

	Free(u);
}

// Search in user list
USERLIST *FindUserList(LIST *o, char *filename)
{
	USERLIST t, *u;
	// Validate arguments
	if (o == NULL || filename == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Filename, sizeof(t.Filename), filename);

	u = Search(o, &t);

	return u;
}

// User list entry comparison function
int CompareUserList(void *p1, void *p2)
{
	USERLIST *u1, *u2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	u1 = *(USERLIST **)p1;
	u2 = *(USERLIST **)p2;
	if (u1 == NULL || u2 == NULL)
	{
		return 0;
	}

	return StrCmpi(u1->Filename, u2->Filename);
}

// Delete the cache of the all user list
void DeleteAllUserListCache(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	LockList(o);
	{
		for (i = 0;i < LIST_NUM(o);i++)
		{
			USERLIST *u = LIST_DATA(o, i);

			FreeUserListEntry(u);
		}

		DeleteAll(o);
	}
	UnlockList(o);
}

// Release the user list
void FreeUserList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		USERLIST *u = LIST_DATA(o, i);

		FreeUserListEntry(u);
	}

	ReleaseList(o);
}

// Get whether the specified message is a URL string
bool IsURLMsg(wchar_t *str, char *url, UINT url_size)
{
	UNI_TOKEN_LIST *t;
	bool ret = false;
	UINT i;
	UINT n = 0;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	t = UniParseToken(str, L"\r\n");

	for (i = 0;i < t->NumTokens;i++)
	{
		wchar_t *str = t->Token[i];

		if (IsEmptyUniStr(str) == false)
		{
			n++;

			UniTrim(str);

			if (n == 1)
			{
				if (UniStartWith(str, L"http://") ||
					UniStartWith(str, L"https://") ||
					UniStartWith(str, L"ftp://"))
				{
					ret = true;

					UniToStr(url, url_size, str);
				}
			}
		}
	}

	if (n != 1)
	{
		ret = false;
	}

	UniFreeToken(t);

	return ret;
}

// Get data from RPC_ADMIN_OPTION
UINT GetHubAdminOptionData(RPC_ADMIN_OPTION *ao, char *name)
{
	UINT i;
	// Validate arguments
	if (ao == NULL || name == NULL)
	{
		return INFINITE;
	}

	for (i = 0;i < ao->NumItem;i++)
	{
		ADMIN_OPTION *a = &ao->Items[i];

		if (StrCmpi(a->Name, name) == 0)
		{
			return a->Value;
		}
	}

	return INFINITE;
}

// Set the contents of the HUB_OPTION based on the data
void DataToHubOptionStruct(HUB_OPTION *o, RPC_ADMIN_OPTION *ao)
{
	// Validate arguments
	if (o == NULL || ao == NULL)
	{
		return;
	}

	UINT value;

	GetHubAdminOptionDataAndSet(ao, "NoAddressPollingIPv4", o->NoArpPolling);
	GetHubAdminOptionDataAndSet(ao, "NoAddressPollingIPv6", o->NoIPv6AddrPolling);
	GetHubAdminOptionDataAndSet(ao, "NoIpTable", o->NoIpTable);
	GetHubAdminOptionDataAndSet(ao, "NoMacAddressLog", o->NoMacAddressLog);
	GetHubAdminOptionDataAndSet(ao, "ManageOnlyPrivateIP", o->ManageOnlyPrivateIP);
	GetHubAdminOptionDataAndSet(ao, "ManageOnlyLocalUnicastIPv6", o->ManageOnlyLocalUnicastIPv6);
	GetHubAdminOptionDataAndSet(ao, "DisableIPParsing", o->DisableIPParsing);
	GetHubAdminOptionDataAndSet(ao, "YieldAfterStorePacket", o->YieldAfterStorePacket);
	GetHubAdminOptionDataAndSet(ao, "NoSpinLockForPacketDelay", o->NoSpinLockForPacketDelay);
	GetHubAdminOptionDataAndSet(ao, "BroadcastStormDetectionThreshold", o->BroadcastStormDetectionThreshold);
	GetHubAdminOptionDataAndSet(ao, "ClientMinimumRequiredBuild", o->ClientMinimumRequiredBuild);
	GetHubAdminOptionDataAndSet(ao, "FilterPPPoE", o->FilterPPPoE);
	GetHubAdminOptionDataAndSet(ao, "FilterOSPF", o->FilterOSPF);
	GetHubAdminOptionDataAndSet(ao, "FilterIPv4", o->FilterIPv4);
	GetHubAdminOptionDataAndSet(ao, "FilterIPv6", o->FilterIPv6);
	GetHubAdminOptionDataAndSet(ao, "FilterNonIP", o->FilterNonIP);
	GetHubAdminOptionDataAndSet(ao, "NoIPv4PacketLog", o->NoIPv4PacketLog);
	GetHubAdminOptionDataAndSet(ao, "NoIPv6PacketLog", o->NoIPv6PacketLog);
	GetHubAdminOptionDataAndSet(ao, "FilterBPDU", o->FilterBPDU);
	GetHubAdminOptionDataAndSet(ao, "NoIPv6DefaultRouterInRAWhenIPv6", o->NoIPv6DefaultRouterInRAWhenIPv6);
	GetHubAdminOptionDataAndSet(ao, "NoLookBPDUBridgeId", o->NoLookBPDUBridgeId);
	GetHubAdminOptionDataAndSet(ao, "NoManageVlanId", o->NoManageVlanId);
	GetHubAdminOptionDataAndSet(ao, "VlanTypeId", o->VlanTypeId);
	GetHubAdminOptionDataAndSet(ao, "FixForDLinkBPDU", o->FixForDLinkBPDU);
	GetHubAdminOptionDataAndSet(ao, "RequiredClientId", o->RequiredClientId);
	GetHubAdminOptionDataAndSet(ao, "AdjustTcpMssValue", o->AdjustTcpMssValue);
	GetHubAdminOptionDataAndSet(ao, "DisableAdjustTcpMss", o->DisableAdjustTcpMss);
	GetHubAdminOptionDataAndSet(ao, "NoDhcpPacketLogOutsideHub", o->NoDhcpPacketLogOutsideHub);
	GetHubAdminOptionDataAndSet(ao, "DisableHttpParsing", o->DisableHttpParsing);
	GetHubAdminOptionDataAndSet(ao, "DisableUdpAcceleration", o->DisableUdpAcceleration);
	GetHubAdminOptionDataAndSet(ao, "DisableUdpFilterForLocalBridgeNic", o->DisableUdpFilterForLocalBridgeNic);
	GetHubAdminOptionDataAndSet(ao, "ApplyIPv4AccessListOnArpPacket", o->ApplyIPv4AccessListOnArpPacket);
	GetHubAdminOptionDataAndSet(ao, "RemoveDefGwOnDhcpForLocalhost", o->RemoveDefGwOnDhcpForLocalhost);
	GetHubAdminOptionDataAndSet(ao, "SecureNAT_MaxTcpSessionsPerIp", o->SecureNAT_MaxTcpSessionsPerIp);
	GetHubAdminOptionDataAndSet(ao, "SecureNAT_MaxTcpSynSentPerIp", o->SecureNAT_MaxTcpSynSentPerIp);
	GetHubAdminOptionDataAndSet(ao, "SecureNAT_MaxUdpSessionsPerIp", o->SecureNAT_MaxUdpSessionsPerIp);
	GetHubAdminOptionDataAndSet(ao, "SecureNAT_MaxDnsSessionsPerIp", o->SecureNAT_MaxDnsSessionsPerIp);
	GetHubAdminOptionDataAndSet(ao, "SecureNAT_MaxIcmpSessionsPerIp", o->SecureNAT_MaxIcmpSessionsPerIp);
	GetHubAdminOptionDataAndSet(ao, "AccessListIncludeFileCacheLifetime", o->AccessListIncludeFileCacheLifetime);
	GetHubAdminOptionDataAndSet(ao, "DisableKernelModeSecureNAT", o->DisableKernelModeSecureNAT);
	GetHubAdminOptionDataAndSet(ao, "DisableIpRawModeSecureNAT", o->DisableIpRawModeSecureNAT);
	GetHubAdminOptionDataAndSet(ao, "DisableUserModeSecureNAT", o->DisableUserModeSecureNAT);
	GetHubAdminOptionDataAndSet(ao, "DisableCheckMacOnLocalBridge", o->DisableCheckMacOnLocalBridge);
	GetHubAdminOptionDataAndSet(ao, "DisableCorrectIpOffloadChecksum", o->DisableCorrectIpOffloadChecksum);
	GetHubAdminOptionDataAndSet(ao, "BroadcastLimiterStrictMode", o->BroadcastLimiterStrictMode);
	GetHubAdminOptionDataAndSet(ao, "MaxLoggedPacketsPerMinute", o->MaxLoggedPacketsPerMinute);
	GetHubAdminOptionDataAndSet(ao, "DoNotSaveHeavySecurityLogs", o->DoNotSaveHeavySecurityLogs);
	GetHubAdminOptionDataAndSet(ao, "DropBroadcastsInPrivacyFilterMode", o->DropBroadcastsInPrivacyFilterMode);
	GetHubAdminOptionDataAndSet(ao, "DropArpInPrivacyFilterMode", o->DropArpInPrivacyFilterMode);
	GetHubAdminOptionDataAndSet(ao, "AllowSameUserInPrivacyFilterMode", o->AllowSameUserInPrivacyFilterMode);
	GetHubAdminOptionDataAndSet(ao, "SuppressClientUpdateNotification", o->SuppressClientUpdateNotification);
	GetHubAdminOptionDataAndSet(ao, "FloodingSendQueueBufferQuota", o->FloodingSendQueueBufferQuota);
	GetHubAdminOptionDataAndSet(ao, "AssignVLanIdByRadiusAttribute", o->AssignVLanIdByRadiusAttribute);
	GetHubAdminOptionDataAndSet(ao, "DenyAllRadiusLoginWithNoVlanAssign", o->DenyAllRadiusLoginWithNoVlanAssign);
	GetHubAdminOptionDataAndSet(ao, "SecureNAT_RandomizeAssignIp", o->SecureNAT_RandomizeAssignIp);
	GetHubAdminOptionDataAndSet(ao, "DetectDormantSessionInterval", o->DetectDormantSessionInterval);
	GetHubAdminOptionDataAndSet(ao, "NoPhysicalIPOnPacketLog", o->NoPhysicalIPOnPacketLog);
	GetHubAdminOptionDataAndSet(ao, "UseHubNameAsDhcpUserClassOption", o->UseHubNameAsDhcpUserClassOption);
	GetHubAdminOptionDataAndSet(ao, "UseHubNameAsRadiusNasId", o->UseHubNameAsRadiusNasId);
	GetHubAdminOptionDataAndSet(ao, "AllowEapMatchUserByCert", o->AllowEapMatchUserByCert);
}

// Convert the contents of the HUB_OPTION to data
void HubOptionStructToData(RPC_ADMIN_OPTION *ao, HUB_OPTION *o, char *hub_name)
{
	LIST *aol;
	UINT i;
	// Validate arguments
	if (ao == NULL || o == NULL || hub_name == NULL)
	{
		return;
	}

	aol = NewListFast(NULL);

	Add(aol, NewAdminOption("NoAddressPollingIPv4", o->NoArpPolling));
	Add(aol, NewAdminOption("NoAddressPollingIPv6", o->NoIPv6AddrPolling));
	Add(aol, NewAdminOption("NoIpTable", o->NoIpTable));
	Add(aol, NewAdminOption("NoMacAddressLog", o->NoMacAddressLog));
	Add(aol, NewAdminOption("ManageOnlyPrivateIP", o->ManageOnlyPrivateIP));
	Add(aol, NewAdminOption("ManageOnlyLocalUnicastIPv6", o->ManageOnlyLocalUnicastIPv6));
	Add(aol, NewAdminOption("DisableIPParsing", o->DisableIPParsing));
	Add(aol, NewAdminOption("YieldAfterStorePacket", o->YieldAfterStorePacket));
	Add(aol, NewAdminOption("NoSpinLockForPacketDelay", o->NoSpinLockForPacketDelay));
	Add(aol, NewAdminOption("BroadcastStormDetectionThreshold", o->BroadcastStormDetectionThreshold));
	Add(aol, NewAdminOption("ClientMinimumRequiredBuild", o->ClientMinimumRequiredBuild));
	Add(aol, NewAdminOption("FilterPPPoE", o->FilterPPPoE));
	Add(aol, NewAdminOption("FilterOSPF", o->FilterOSPF));
	Add(aol, NewAdminOption("FilterIPv4", o->FilterIPv4));
	Add(aol, NewAdminOption("FilterIPv6", o->FilterIPv6));
	Add(aol, NewAdminOption("FilterNonIP", o->FilterNonIP));
	Add(aol, NewAdminOption("NoIPv4PacketLog", o->NoIPv4PacketLog));
	Add(aol, NewAdminOption("NoIPv6PacketLog", o->NoIPv6PacketLog));
	Add(aol, NewAdminOption("FilterBPDU", o->FilterBPDU));
	Add(aol, NewAdminOption("NoIPv6DefaultRouterInRAWhenIPv6", o->NoIPv6DefaultRouterInRAWhenIPv6));
	Add(aol, NewAdminOption("NoLookBPDUBridgeId", o->NoLookBPDUBridgeId));
	Add(aol, NewAdminOption("NoManageVlanId", o->NoManageVlanId));
	Add(aol, NewAdminOption("VlanTypeId", o->VlanTypeId));
	Add(aol, NewAdminOption("FixForDLinkBPDU", o->FixForDLinkBPDU));
	Add(aol, NewAdminOption("RequiredClientId", o->RequiredClientId));
	Add(aol, NewAdminOption("AdjustTcpMssValue", o->AdjustTcpMssValue));
	Add(aol, NewAdminOption("DisableAdjustTcpMss", o->DisableAdjustTcpMss));
	Add(aol, NewAdminOption("NoDhcpPacketLogOutsideHub", o->NoDhcpPacketLogOutsideHub));
	Add(aol, NewAdminOption("DisableHttpParsing", o->DisableHttpParsing));
	Add(aol, NewAdminOption("DisableUdpAcceleration", o->DisableUdpAcceleration));
	Add(aol, NewAdminOption("DisableUdpFilterForLocalBridgeNic", o->DisableUdpFilterForLocalBridgeNic));
	Add(aol, NewAdminOption("ApplyIPv4AccessListOnArpPacket", o->ApplyIPv4AccessListOnArpPacket));
	Add(aol, NewAdminOption("RemoveDefGwOnDhcpForLocalhost", o->RemoveDefGwOnDhcpForLocalhost));
	Add(aol, NewAdminOption("SecureNAT_MaxTcpSessionsPerIp", o->SecureNAT_MaxTcpSessionsPerIp));
	Add(aol, NewAdminOption("SecureNAT_MaxTcpSynSentPerIp", o->SecureNAT_MaxTcpSynSentPerIp));
	Add(aol, NewAdminOption("SecureNAT_MaxUdpSessionsPerIp", o->SecureNAT_MaxUdpSessionsPerIp));
	Add(aol, NewAdminOption("SecureNAT_MaxDnsSessionsPerIp", o->SecureNAT_MaxDnsSessionsPerIp));
	Add(aol, NewAdminOption("SecureNAT_MaxIcmpSessionsPerIp", o->SecureNAT_MaxIcmpSessionsPerIp));
	Add(aol, NewAdminOption("AccessListIncludeFileCacheLifetime", o->AccessListIncludeFileCacheLifetime));
	Add(aol, NewAdminOption("DisableKernelModeSecureNAT", o->DisableKernelModeSecureNAT));
	Add(aol, NewAdminOption("DisableIpRawModeSecureNAT", o->DisableIpRawModeSecureNAT));
	Add(aol, NewAdminOption("DisableUserModeSecureNAT", o->DisableUserModeSecureNAT));
	Add(aol, NewAdminOption("DisableCheckMacOnLocalBridge", o->DisableCheckMacOnLocalBridge));
	Add(aol, NewAdminOption("DisableCorrectIpOffloadChecksum", o->DisableCorrectIpOffloadChecksum));
	Add(aol, NewAdminOption("BroadcastLimiterStrictMode", o->BroadcastLimiterStrictMode));
	Add(aol, NewAdminOption("MaxLoggedPacketsPerMinute", o->MaxLoggedPacketsPerMinute));
	Add(aol, NewAdminOption("DoNotSaveHeavySecurityLogs", o->DoNotSaveHeavySecurityLogs));
	Add(aol, NewAdminOption("DropBroadcastsInPrivacyFilterMode", o->DropBroadcastsInPrivacyFilterMode));
	Add(aol, NewAdminOption("DropArpInPrivacyFilterMode", o->DropArpInPrivacyFilterMode));
	Add(aol, NewAdminOption("AllowSameUserInPrivacyFilterMode", o->AllowSameUserInPrivacyFilterMode));
	Add(aol, NewAdminOption("SuppressClientUpdateNotification", o->SuppressClientUpdateNotification));
	Add(aol, NewAdminOption("FloodingSendQueueBufferQuota", o->FloodingSendQueueBufferQuota));
	Add(aol, NewAdminOption("AssignVLanIdByRadiusAttribute", o->AssignVLanIdByRadiusAttribute));
	Add(aol, NewAdminOption("DenyAllRadiusLoginWithNoVlanAssign", o->DenyAllRadiusLoginWithNoVlanAssign));
	Add(aol, NewAdminOption("SecureNAT_RandomizeAssignIp", o->SecureNAT_RandomizeAssignIp));
	Add(aol, NewAdminOption("DetectDormantSessionInterval", o->DetectDormantSessionInterval));
	Add(aol, NewAdminOption("NoPhysicalIPOnPacketLog", o->NoPhysicalIPOnPacketLog));
	Add(aol, NewAdminOption("UseHubNameAsDhcpUserClassOption", o->UseHubNameAsDhcpUserClassOption));
	Add(aol, NewAdminOption("UseHubNameAsRadiusNasId", o->UseHubNameAsRadiusNasId));
	Add(aol, NewAdminOption("AllowEapMatchUserByCert", o->AllowEapMatchUserByCert));

	Zero(ao, sizeof(RPC_ADMIN_OPTION));

	StrCpy(ao->HubName, sizeof(ao->HubName), hub_name);

	ao->NumItem = LIST_NUM(aol);
	ao->Items = ZeroMalloc(sizeof(ADMIN_OPTION) * ao->NumItem);

	for (i = 0;i < LIST_NUM(aol);i++)
	{
		ADMIN_OPTION *a = LIST_DATA(aol, i);

		UniStrCpy(a->Descrption, sizeof(a->Descrption), GetHubAdminOptionHelpString(a->Name));

		Copy(&ao->Items[i], a, sizeof(ADMIN_OPTION));

		Free(a);
	}

	ReleaseList(aol);
}

// Create a new ADMIN OPTION
ADMIN_OPTION *NewAdminOption(char *name, UINT value)
{
	ADMIN_OPTION *a;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(ADMIN_OPTION));
	StrCpy(a->Name, sizeof(a->Name), name);
	a->Value = value;

	return a;
}

// Clone the AC list
LIST *CloneAcList(LIST *o)
{
	LIST *ret;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	ret = NewAcList();
	SetAcList(ret, o);

	return ret;
}

// Set all the AC list
void SetAcList(LIST *o, LIST *src)
{
	UINT i;
	// Validate arguments
	if (o == NULL || src == NULL)
	{
		return;
	}

	DelAllAc(o);

	for (i = 0;i < LIST_NUM(src);i++)
	{
		AC *ac = LIST_DATA(src, i);

		AddAc(o, ac);
	}
}

// Remove all AC from the AC list
void DelAllAc(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		Free(ac);
	}

	DeleteAll(o);
}

// Release the AC list
void FreeAcList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		Free(ac);
	}

	ReleaseList(o);
}

// Generate a string that indicates the contents of the AC
char *GenerateAcStr(AC *ac)
{
	char tmp[MAX_SIZE];
	char ip[64], mask[64];

	if (ac == NULL)
	{
		return NULL;
	}

	IPToStr(ip, sizeof(ip), &ac->IpAddress);
	MaskToStr(mask, sizeof(mask), &ac->SubnetMask);

	if (ac->Masked == false)
	{
		Format(tmp, sizeof(tmp), "%s", ip);
	}
	else
	{
		Format(tmp, sizeof(tmp), "%s/%s", ip, mask);
	}

	return CopyStr(tmp);
}

// Calculate whether the specified IP address is rejected by the access list
bool IsIpDeniedByAcList(IP *ip, LIST *o)
{
	UINT i;
	// Validate arguments
	if (ip == NULL || o == NULL)
	{
		return false;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_AC) != 0)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		if (IsIpMaskedByAc(ip, ac))
		{
			if (ac->Deny == false)
			{
				return false;
			}
			else
			{
				return true;
			}
		}
	}

	return false;
}

// Calculate whether the specified IP address is masked by the AC
bool IsIpMaskedByAc(IP *ip, AC *ac)
{
	UINT uip, net, mask;
	// Validate arguments
	if (ip == NULL || ac == NULL)
	{
		return false;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_AC) != 0)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		// IPv4
		uip = IPToUINT(ip);
		net = IPToUINT(&ac->IpAddress);
		mask = IPToUINT(&ac->SubnetMask);

		if (ac->Masked == false)
		{
			if (uip == net)
			{
				return true;
			}
		}
		else
		{
			if ((uip & mask) == (net & mask))
			{
				return true;
			}
		}

		return false;
	}
	else
	{
		// IPv6
		if (ac->Masked == false)
		{
			if (CmpIpAddr(ip, &ac->IpAddress) == 0)
			{
				return true;
			}
		}
		else
		{
			IP and1, and2;

			IPAnd6(&and1, ip, &ac->SubnetMask);
			IPAnd6(&and2, &ac->IpAddress, &ac->SubnetMask);

			if (CmpIpAddr(&and1, &and2) == 0)
			{
				return true;
			}
		}

		return false;
	}
}

// Set the AC
void SetAc(LIST *o, UINT id, AC *ac)
{
	// Validate arguments
	if (o == NULL || id == 0 || ac == NULL)
	{
		return;
	}

	if (DelAc(o, id))
	{
		AddAc(o, ac);
	}
}

// Get the AC
AC *GetAc(LIST *o, UINT id)
{
	UINT i;
	// Validate arguments
	if (o == NULL || id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		if (ac->Id == id)
		{
			return Clone(ac, sizeof(AC));
		}
	}

	return NULL;
}

// Delete the AC
bool DelAc(LIST *o, UINT id)
{
	UINT i;
	// Validate arguments
	if (o == NULL || id == 0)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		if (ac->Id == id)
		{
			if (Delete(o, ac))
			{
				Free(ac);

				NormalizeAcList(o);

				return true;
			}
		}
	}

	return false;
}

// Add an AC to the list
void AddAc(LIST *o, AC *ac)
{
	// Validate arguments
	if (o == NULL || ac == NULL)
	{
		return;
	}

	if (LIST_NUM(o) < MAX_HUB_ACS)
	{
		Insert(o, Clone(ac, sizeof(AC)));

		NormalizeAcList(o);
	}
}

// Normalize the AC list
void NormalizeAcList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		AC *ac = LIST_DATA(o, i);

		if (IsIP6(&ac->IpAddress))
		{
			ac->IpAddress.ipv6_scope_id = 0;
		}

		ac->Id = (i + 1);
	}
}

// Create a new AC list
LIST *NewAcList()
{
	return NewList(CmpAc);
}

// AC comparison
int CmpAc(void *p1, void *p2)
{
	AC *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(AC **)p1;
	a2 = *(AC **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	if (a1->Priority > a2->Priority)
	{
		return 1;
	}
	else if (a1->Priority < a2->Priority)
	{
		return -1;
	}
	else if (a1->Deny > a2->Deny)
	{
		return 1;
	}
	else if (a1->Deny < a2->Deny)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// Copy the CRL
CRL *CopyCrl(CRL *crl)
{
	CRL *ret;
	// Validate arguments
	if (crl == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(CRL));

	if (crl->Serial != NULL)
	{
		ret->Serial = NewXSerial(crl->Serial->data, crl->Serial->size);
	}

	ret->Name = CopyName(crl->Name);

	Copy(ret->DigestMD5, crl->DigestMD5, MD5_SIZE);
	Copy(ret->DigestSHA1, crl->DigestSHA1, SHA1_SIZE);

	return ret;
}

// Release the CRL
void FreeCrl(CRL *crl)
{
	// Validate arguments
	if (crl == NULL)
	{
		return;
	}

	if (crl->Serial != NULL)
	{
		FreeXSerial(crl->Serial);
	}

	if (crl->Name != NULL)
	{
		FreeName(crl->Name);
	}

	Free(crl);
}

// Check whether the certificate has been disabled by searching the CRL list of Virtual HUB
bool IsValidCertInHub(HUB *h, X *x)
{
	bool ret;
	// Validate arguments
	if (h == NULL || x == NULL)
	{
		return false;
	}

	if (h->HubDb == NULL)
	{
		return false;
	}

	LockList(h->HubDb->CrlList);
	{
		ret = IsCertMatchCrlList(x, h->HubDb->CrlList);
	}
	UnlockList(h->HubDb->CrlList);

	if (ret)
	{
		// This is invalid because it was matched
		return false;
	}

	// This is valid because it wasn't matched
	return true;
}

// Search whether the certificate matches the CRL list
bool IsCertMatchCrlList(X *x, LIST *o)
{
	UINT i;
	// Validate arguments
	if (x == NULL || o == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CRL *crl = LIST_DATA(o, i);

		if (IsCertMatchCrl(x, crl))
		{
			return true;
		}
	}

	return false;
}

// Convert the CRL to a string
wchar_t *GenerateCrlStr(CRL *crl)
{
	wchar_t tmp[2048];
	// Validate arguments
	if (crl == NULL)
	{
		return NULL;
	}

	UniStrCpy(tmp, sizeof(tmp), L"");

	if (crl->Name != NULL)
	{
		// Name information
		wchar_t name[MAX_SIZE];

		UniStrCat(tmp, sizeof(tmp), L"Subject=\"");

		GetAllNameFromName(name, sizeof(name), crl->Name);
		UniStrCat(tmp, sizeof(tmp), name);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (crl->Serial != NULL)
	{
		// Serial information
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->Serial->data, crl->Serial->size);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"Serial=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (IsZero(crl->DigestMD5, MD5_SIZE) == false)
	{
		// MD5
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->DigestMD5, MD5_SIZE);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"MD5=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false)
	{
		// MD5
		char str[128];
		wchar_t uni[128];

		BinToStrEx(str, sizeof(str), crl->DigestSHA1, SHA1_SIZE);
		StrToUni(uni, sizeof(uni), str);
		UniStrCat(tmp, sizeof(tmp), L"SHA1=\"");
		UniStrCat(tmp, sizeof(tmp), uni);
		UniStrCat(tmp, sizeof(tmp), L"\", ");
	}

	if (UniEndWith(tmp, L", "))
	{
		tmp[UniStrLen(tmp) - 2] = 0;
	}

	return CopyUniStr(tmp);
}

// Check whether it matches the Certificate Revocation List entry
bool IsCertMatchCrl(X *x, CRL *crl)
{
	bool b = true;
	// Validate arguments
	if (x == NULL || crl == NULL)
	{
		return false;
	}

	if (crl->Serial != NULL)
	{
		// If a serial number is defined in the CRL
		if (x->serial == NULL || CompareXSerial(x->serial, crl->Serial) == false)
		{
			// Serial number mismatch
			b = false;
		}
	}

	if (IsZero(crl->DigestMD5, sizeof(crl->DigestMD5)) == false)
	{
		UCHAR test[MD5_SIZE];
		// If a DigestMD5 is defined in the CRL
		GetXDigest(x, test, false);

		if (Cmp(test, crl->DigestMD5, MD5_SIZE) != 0)
		{
			b = false;
		}
	}

	if (IsZero(crl->DigestSHA1, sizeof(crl->DigestSHA1)) == false)
	{
		UCHAR test[SHA1_SIZE];
		// If a DigestSHA1 is defined in the CRL
		GetXDigest(x, test, true);

		if (Cmp(test, crl->DigestSHA1, SHA1_SIZE) != 0)
		{
			b = false;
		}
	}

	if (crl->Name != NULL)
	{
		// If a name is defined in the CRL
		NAME *xn, *cn;
		xn = x->subject_name;
		cn = crl->Name;

		if (cn->CommonName != NULL && (UniIsEmptyStr(cn->CommonName) == false))
		{
			if (xn->CommonName == NULL || UniSoftStrCmp(xn->CommonName, cn->CommonName) != 0)
			{
				// CommonName mismatch
				b = false;
			}
		}

		if (cn->Organization != NULL && (UniIsEmptyStr(cn->Organization) == false))
		{
			if (xn->Organization == NULL || UniSoftStrCmp(xn->Organization, cn->Organization) != 0)
			{
				// Organization mismatch
				b = false;
			}
		}

		if (cn->Unit != NULL && (UniIsEmptyStr(cn->Unit) == false))
		{
			if (xn->Unit == NULL || UniSoftStrCmp(xn->Unit, cn->Unit) != 0)
			{
				// Unit mismatch
				b = false;
			}
		}

		if (cn->Country != NULL && (UniIsEmptyStr(cn->Country) == false))
		{
			if (xn->Country == NULL || UniSoftStrCmp(xn->Country, cn->Country) != 0)
			{
				// Country mismatch
				b = false;
			}
		}

		if (cn->State != NULL && (UniIsEmptyStr(cn->State) == false))
		{
			if (xn->State == NULL || UniSoftStrCmp(xn->State, cn->State) != 0)
			{
				// State mismatch
				b = false;
			}
		}

		if (cn->Local != NULL && (UniIsEmptyStr(cn->Local) == false))
		{
			if (xn->Local == NULL || UniSoftStrCmp(xn->Local, cn->Local) != 0)
			{
				// Local mismatch
				b = false;
			}
		}
	}

	return b;
}

// Get the help string of administration options
wchar_t *GetHubAdminOptionHelpString(char *name)
{
	char tmp[MAX_SIZE];
	wchar_t *ret;
	// Validate arguments
	if (name == NULL)
	{
		return L"";
	}

	Format(tmp, sizeof(tmp), "HUB_AO_%s", name);

	ret = _UU(tmp);
	if (UniIsEmptyStr(ret))
	{
		ret = _UU("HUB_AO_UNKNOWN");
	}

	return ret;
}

// Add the default administration options to the Virtual HUB
void AddHubAdminOptionsDefaults(HUB *h, bool lock)
{
	UINT i;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	if (lock)
	{
		LockList(h->AdminOptionList);
	}

	for (i = 0;i < num_admin_options;i++)
	{
		ADMIN_OPTION *e = &admin_options[i];
		ADMIN_OPTION t, *r;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), e->Name);

		r = Search(h->AdminOptionList, &t);
		if (r == NULL)
		{
			ADMIN_OPTION *a = ZeroMalloc(sizeof(ADMIN_OPTION));

			StrCpy(a->Name, sizeof(a->Name), e->Name);
			a->Value = e->Value;

			Insert(h->AdminOptionList, a);
		}
	}

	if (lock)
	{
		UnlockList(h->AdminOptionList);
	}
}

// Delete all administration options of Virtual HUB
void DeleteAllHubAdminOption(HUB *h, bool lock)
{
	UINT i;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	if (lock)
	{
		LockList(h->AdminOptionList);
	}

	for (i = 0;i < LIST_NUM(h->AdminOptionList);i++)
	{
		Free(LIST_DATA(h->AdminOptionList, i));
	}

	DeleteAll(h->AdminOptionList);

	if (lock)
	{
		UnlockList(h->AdminOptionList);
	}
}

// Get the administration options for the virtual HUB
UINT GetHubAdminOptionEx(HUB *h, char *name, UINT default_value)
{
	UINT ret = default_value;
	// Validate arguments
	if (h == NULL || name == NULL)
	{
		return 0;
	}

	LockList(h->AdminOptionList);
	{
		ADMIN_OPTION *a, t;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), name);
		Trim(t.Name);

		a = Search(h->AdminOptionList, &t);

		if (a != NULL)
		{
			ret = a->Value;
		}
	}
	UnlockList(h->AdminOptionList);

	return ret;
}
UINT GetHubAdminOption(HUB *h, char *name)
{
	return GetHubAdminOptionEx(h, name, 0);
}

// Administration options
int CompareAdminOption(void *p1, void *p2)
{
	ADMIN_OPTION *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(ADMIN_OPTION **)p1;
	a2 = *(ADMIN_OPTION **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	return StrCmpi(a1->Name, a2->Name);
}

// Start the watchdog
void StartHubWatchDog(HUB *h)
{
	THREAD *t;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	h->HaltWatchDog = false;
	h->WatchDogEvent = NewEvent();

	t = NewThread(HubWatchDogThread, h);
	WaitThreadInit(t);
	ReleaseThread(t);
}

// Stop the watchdog
void StopHubWatchDog(HUB *h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	h->HaltWatchDog = true;
	Set(h->WatchDogEvent);

	WaitThread(h->WatchDogThread, INFINITE);
	ReleaseThread(h->WatchDogThread);
	h->WatchDogThread = NULL;
	h->HaltWatchDog = false;

	ReleaseEvent(h->WatchDogEvent);
	h->WatchDogEvent = NULL;
}

// Watchdog thread
void HubWatchDogThread(THREAD *t, void *param)
{
	UINT num_packets_v4 = 0;
	UINT num_packets_v6 = 0;
	HUB *hub;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	hub = (HUB *)param;

	hub->WatchDogThread = t;
	AddRef(t->ref);

	NoticeThreadInit(t);

	while (true)
	{
		LIST *o;
		LIST *o2;
		UINT i, num;
		UINT interval;
		UINT wait_time = 100;
		if (hub->HaltWatchDog)
		{
			break;
		}

		o = NewListFast(NULL);
		o2 = NewListFast(NULL);

		// Send an ARP packet
		LockHashList(hub->MacHashTable);
		{
			num = LIST_NUM(hub->IpTable);
			for (i = 0;i < LIST_NUM(hub->IpTable);i++)
			{
				IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);

				if (e == NULL) continue;

				if ((e->UpdatedTime + (UINT64)(IP_TABLE_EXPIRE_TIME)) > Tick64())
				{
					if (e->MacAddress[0] != 0xff || e->MacAddress[1] != 0xff || e->MacAddress[2] != 0xff ||
						e->MacAddress[3] != 0xff || e->MacAddress[4] != 0xff || e->MacAddress[5] != 0xff)
					{
						if (hub->Option != NULL && hub->Option->NoArpPolling == false)
						{
							if (IsIP4(&e->Ip))
							{
								// IPv4
								MAC_HEADER *mac = ZeroMalloc(sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER));
								ARPV4_HEADER *p = (ARPV4_HEADER *)(((UCHAR *)mac) + sizeof(MAC_HEADER));

								Copy(mac->DestAddress, e->MacAddress, 6);
								Copy(mac->SrcAddress, hub->HubMacAddr, 6);
								mac->Protocol = Endian16(MAC_PROTO_ARPV4);

								p->HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
								p->ProtocolType = Endian16(MAC_PROTO_IPV4);
								p->HardwareSize = 6;
								p->ProtocolSize = 4;
								p->Operation = Endian16(ARP_OPERATION_REQUEST);
								Copy(p->SrcAddress, hub->HubMacAddr, 6);
								p->SrcIP = IPToUINT(&hub->HubIp);
								p->TargetAddress[0] =
									p->TargetAddress[1] =
									p->TargetAddress[2] =
									p->TargetAddress[3] =
									p->TargetAddress[4] =
									p->TargetAddress[5] = 0x00;
								p->TargetIP = IPToUINT(&e->Ip);
								Insert(o, mac);
							}
						}

						if (hub->Option != NULL && hub->Option->NoIPv6AddrPolling == false)
						{
							if (IsIP6(&e->Ip))
							{
								// IPv6
								BUF *buf;
								IPV6_ADDR ip6addr;

								if (IPToIPv6Addr(&ip6addr, &e->Ip))
								{
									buf = BuildICMPv6NeighborSoliciation(&hub->HubIpV6,
										&ip6addr,
										hub->HubMacAddr, ++hub->HubIP6Id, false);

									if (buf != NULL)
									{
										BUF *buf2 = NewBuf();
										MAC_HEADER mac;

										Zero(&mac, sizeof(mac));

										Copy(mac.DestAddress, e->MacAddress, 6);
										Copy(mac.SrcAddress, hub->HubMacAddr, 6);
										mac.Protocol = Endian16(MAC_PROTO_IPV6);

										WriteBuf(buf2, &mac, sizeof(MAC_HEADER));

										WriteBuf(buf2, buf->Buf, buf->Size);

										FreeBuf(buf);

										Insert(o2, buf2);
									}
								}
							}
						}
					}
				}
			}
		}
		UnlockHashList(hub->MacHashTable);

		if ((LIST_NUM(o) + LIST_NUM(o2)) != 0)
		{
			interval = HUB_ARP_SEND_INTERVAL / (LIST_NUM(o) + LIST_NUM(o2));
		}
		else
		{
			interval = HUB_ARP_SEND_INTERVAL;
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			PKT *packet;
			void *p = LIST_DATA(o, i);

			Wait(hub->WatchDogEvent, interval);
			if (hub->HaltWatchDog)
			{
				for (;i < LIST_NUM(o);i++)
				{
					Free(LIST_DATA(o, i));
				}
				ReleaseList(o);

				for (i = 0;i < LIST_NUM(o2);i++)
				{
					FreeBuf(LIST_DATA(o2, i));
				}
				ReleaseList(o2);
				goto ESCAPE;
			}

			packet = ParsePacket((UCHAR *)p, sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER));
			if (packet != NULL)
			{
				StorePacket(hub, NULL, packet);
				num_packets_v4++;
			}
			else
			{
				Free(p);
			}
		}

		for (i = 0;i < LIST_NUM(o2);i++)
		{
			PKT *packet;
			BUF *buf = LIST_DATA(o2, i);

			Wait(hub->WatchDogEvent, interval);
			if (hub->HaltWatchDog)
			{
				ReleaseList(o);

				for (;i < LIST_NUM(o2);i++)
				{
					FreeBuf(LIST_DATA(o2, i));
				}
				ReleaseList(o2);
				goto ESCAPE;
			}

			packet = ParsePacket(buf->Buf, buf->Size);
			if (packet != NULL)
			{
				StorePacket(hub, NULL, packet);
				num_packets_v6++;
			}
			else
			{
				Free(buf->Buf);
			}

			Free(buf);
		}

		ReleaseList(o);
		ReleaseList(o2);

		if (num == 0)
		{
			wait_time = HUB_ARP_SEND_INTERVAL;
		}

		Wait(hub->WatchDogEvent, wait_time);
	}
ESCAPE:
	return;
}

// Enable / disable the SecureNAT
void EnableSecureNAT(HUB *h, bool enable)
{
	EnableSecureNATEx(h, enable, false);
}
void EnableSecureNATEx(HUB *h, bool enable, bool no_change)
{
	bool for_cluster = false;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	if (h->Cedar->Server != NULL && h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		if (h->Type == HUB_TYPE_FARM_DYNAMIC)
		{
			for_cluster = true;
		}
	}

	Lock(h->lock_online);
	{
		if (no_change == false)
		{
			h->EnableSecureNAT = enable;
		}

		if (h->EnableSecureNAT == false)
		{
STOP:
			// Stop if it's already started
			if (h->SecureNAT != NULL)
			{
				SnFreeSecureNAT(h->SecureNAT);
				h->SecureNAT = NULL;
			}
		}
		else
		{
			if (for_cluster)
			{
				if ((h->SecureNAT != NULL && LIST_NUM(h->SessionList) <= 1) ||
					(h->SecureNAT == NULL && LIST_NUM(h->SessionList) == 0))
				{
					// It is in a start mode, but stop when there is no other sessions
					// in the case of dynamic Virtual HUB
					goto STOP;
				}
			}

			// Start if the HUB is online and not started
			if (h->SecureNAT == NULL && h->Offline == false)
			{
				h->SecureNAT = SnNewSecureNAT(h, h->SecureNATOption);
			}
		}
	}
	Unlock(h->lock_online);
}

// Convert an access list to a string
void GetAccessListStr(char *str, UINT size, ACCESS *a)
{
	char tmp[MAX_SIZE];
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	bool l3 = false;
	bool asterisk = false;
	// Validate arguments
	if (str == NULL || a == NULL)
	{
		return;
	}

	StrCpy(str, size, "");

	if (a->IsIPv6 == false)
	{
		if (a->SrcIpAddress != 0 || a->SrcSubnetMask != 0)
		{
			IPToStr32(tmp1, sizeof(tmp1), a->SrcIpAddress);
			MaskToStr32(tmp2, sizeof(tmp2), a->SrcSubnetMask);
			Format(tmp, sizeof(tmp), "SrcIPv4=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}

		if (a->DestIpAddress != 0 || a->DestSubnetMask != 0)
		{
			IPToStr32(tmp1, sizeof(tmp1), a->DestIpAddress);
			MaskToStr32(tmp2, sizeof(tmp2), a->DestSubnetMask);
			Format(tmp, sizeof(tmp), "DstIPv4=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}
	}
	else
	{
		if (IsZeroIP6Addr(&a->SrcIpAddress6) == false || IsZeroIP6Addr(&a->SrcSubnetMask6) == false)
		{
			IP6AddrToStr(tmp1, sizeof(tmp1), &a->SrcIpAddress6);
			Mask6AddrToStr(tmp2, sizeof(tmp2), &a->SrcSubnetMask6);
			Format(tmp, sizeof(tmp), "SrcIPv6=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}

		if (IsZeroIP6Addr(&a->DestIpAddress6) == false || IsZeroIP6Addr(&a->DestSubnetMask6) == false)
		{
			IP6AddrToStr(tmp1, sizeof(tmp1), &a->DestIpAddress6);
			Mask6AddrToStr(tmp2, sizeof(tmp2), &a->DestSubnetMask6);
			Format(tmp, sizeof(tmp), "DstIPv6=%s/%s, ", tmp1, tmp2);
			StrCat(str, size, tmp);

			l3 = true;
		}
	}

	if (a->Protocol != 0)
	{
		StrCpy(tmp1, sizeof(tmp1), "");
		switch (a->Protocol)
		{
		case 1:
			StrCpy(tmp1, sizeof(tmp1), "ICMPv4");
			break;
		case 3:
			StrCpy(tmp1, sizeof(tmp1), "GGP");
			break;
		case 6:
			StrCpy(tmp1, sizeof(tmp1), "TCP");
			break;
		case 8:
			StrCpy(tmp1, sizeof(tmp1), "EGP");
			break;
		case 12:
			StrCpy(tmp1, sizeof(tmp1), "PUP");
			break;
		case 17:
			StrCpy(tmp1, sizeof(tmp1), "UDP");
			break;
		case 20:
			StrCpy(tmp1, sizeof(tmp1), "HMP");
			break;
		case 22:
			StrCpy(tmp1, sizeof(tmp1), "XNS-IDP");
			break;
		case 27:
			StrCpy(tmp1, sizeof(tmp1), "RDP");
			break;
		case 58:
			StrCpy(tmp1, sizeof(tmp1), "ICMPv6");
			break;
		case 66:
			StrCpy(tmp1, sizeof(tmp1), "RVD");
			break;
		}

		if (IsEmptyStr(tmp1))
		{
			Format(tmp, sizeof(tmp), "Protocol=%s(%u), ", tmp1, a->Protocol);
		}
		else
		{
			Format(tmp, sizeof(tmp), "Protocol=%s, ", tmp1);
		}

		StrCat(str, size, tmp);

		l3 = true;
	}

	if (a->SrcPortStart != 0)
	{
		if (a->SrcPortEnd == a->SrcPortStart)
		{
			Format(tmp, sizeof(tmp), "SrcPort=%u, ", a->SrcPortStart);
			StrCat(str, size, tmp);
		}
		else
		{
			Format(tmp, sizeof(tmp), "SrcPort=%u-%u, ", a->SrcPortStart, a->SrcPortEnd);
			StrCat(str, size, tmp);
		}

		l3 = true;
	}

	if (a->DestPortStart != 0)
	{
		if (a->DestPortEnd == a->DestPortStart)
		{
			Format(tmp, sizeof(tmp), "DstPort=%u, ", a->DestPortStart);
			StrCat(str, size, tmp);
		}
		else
		{
			Format(tmp, sizeof(tmp), "DstPort=%u-%u, ", a->DestPortStart, a->DestPortEnd);
			StrCat(str, size, tmp);
		}

		l3 = true;
	}

	if (StrLen(a->SrcUsername) != 0)
	{
		Format(tmp, sizeof(tmp), "SrcUser=%s, ", a->SrcUsername);
		StrCat(str, size, tmp);
	}

	if (StrLen(a->DestUsername) != 0)
	{
		Format(tmp, sizeof(tmp), "DstUser=%s, ", a->DestUsername);
		StrCat(str, size, tmp);
	}

	if (a->CheckSrcMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->SrcMacAddress);
		MacToStr(mask, sizeof(mask), a->SrcMacMask);
		Format(tmp, sizeof(tmp), "SrcMac=%s/%s, ", mac, mask);
		StrCat(str, size, tmp);
	}
	if (a->CheckDstMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->DstMacAddress);
		MacToStr(mask, sizeof(mask), a->DstMacMask);
		Format(tmp, sizeof(tmp), "DstMac=%s/%s, ", mac, mask);
		StrCat(str, size, tmp);
	}

	if (a->CheckTcpState)
	{
		if(a->Established)
		{
			StrCat(str, size, "Established, ");
		}
		else
		{
			StrCat(str, size, "Unestablished, ");
		}

		l3 = true;
	}

	if (a->Discard == false)
	{
		if (a->Delay >= 1)
		{
			Format(tmp, sizeof(tmp), "Delay=%u, ", a->Delay);
			StrCat(str, size, tmp);
		}

		if (a->Jitter >= 1)
		{
			Format(tmp, sizeof(tmp), "Jitter=%u, ", a->Jitter);
			StrCat(str, size, tmp);
		}

		if (a->Loss >= 1)
		{
			Format(tmp, sizeof(tmp), "Loss=%u, " , a->Loss);
			StrCat(str, size, tmp);
		}
	}

	if (IsEmptyStr(a->RedirectUrl) == false)
	{
		Format(tmp, sizeof(tmp), "RedirectUrl=%s, ", a->RedirectUrl);
		StrCat(str, size, tmp);
	}

	if (StrLen(str) == 0)
	{
		asterisk = true;
	}

	if (l3)
	{
		if (a->IsIPv6)
		{
			StrCatLeft(str, size, "(ipv6) ");
		}
		else
		{
			StrCatLeft(str, size, "(ipv4) ");
		}
	}
	else
	{
		StrCatLeft(str, size, "(ether) ");
	}

	if (EndWith(str, ", "))
	{
		str[StrLen(str) - 2] = 0;
	}

	if (asterisk)
	{
		StrCat(str, size, "*");
	}
}

// Determine whether the access list can mask the packet
bool IsPacketMaskedByAccessList(SESSION *s, PKT *p, ACCESS *a, UINT64 dest_username, UINT64 dest_groupname, SESSION *dest_session)
{
	UINT64 src_username;
	UINT64 src_username_simple;
	UINT64 src_groupname;
	HUB_PA *pa;
	IPV4_HEADER *ip = NULL;
	IPV6_HEADER *ip6 = NULL;
	bool is_ipv4_packet = false;
	bool is_ipv6_packet = false;
	bool is_arp_packet = false;
	// Validate arguments
	if (s == NULL || p == NULL || a == NULL)
	{
		return false;
	}
	if (a->Active == false)
	{
		// Access list is inactive
		return false;
	}

	pa = (HUB_PA *)s->PacketAdapter->Param;

	// Hash of the source user name
	src_username = pa->UsernameHash;
	src_username_simple = pa->UsernameHashSimple;
	src_groupname = pa->GroupnameHash;

	// Determine the source and destination MAC address
	if (a->CheckSrcMac != false)
	{
		UINT i;
		for (i = 0; i < 6; i++)
		{
			if((a->SrcMacAddress[i] & a->SrcMacMask[i]) != (a->SrcMacMask[i] & p->MacAddressSrc[i]))
			{
				return false;
			}
		}
	}

	if (a->CheckDstMac != false)
	{
		UINT i;
		for (i = 0; i < 6; i++)
		{
			if ((a->DstMacAddress[i] & a->DstMacMask[i]) != (a->DstMacMask[i] & p->MacAddressDest[i]))
			{
				return false;
			}
		}
	}

	// Check the source user name / group name
	if (a->SrcUsernameHash != 0)
	{
		if (a->IsSrcUsernameIncludeOrExclude == false)
		{
			// It is specified as a regular user name
			if ((a->SrcUsernameHash != src_username) && (a->SrcUsernameHash != src_groupname))
			{
				return false;
			}
		}
		else
		{
			// It is specified in the form of a exclude:FILENAME or include:FILENAME
			HUB *hub = s->Hub;

			if (hub != NULL)
			{
				LIST *o = hub->UserList;

				if (s->NormalClient == false)
				{
					// The internal session don't become target for format exclude: or include:
					return false;
				}

				if (IsUserMatchInUserListWithCacheExpiresAcl(o, a->SrcUsername, src_username,
					hub->Option->AccessListIncludeFileCacheLifetime * 1000) == false)
				{
					return false;
				}
			}
		}
	}

	// Check the destination user name / group name
	if (a->DestUsernameHash != 0)
	{
		if (a->IsDestUsernameIncludeOrExclude == false)
		{
			// It is specified as a regular user name
			if ((a->DestUsernameHash != dest_username) && (a->DestUsernameHash != dest_groupname))
			{
				return false;
			}
		}
		else
		{
			// It is specified in the form of a exclude:FILENAME or include:FILENAME
			HUB *hub = s->Hub;

			if (hub != NULL)
			{
				LIST *o = hub->UserList;

				if (dest_session != NULL && dest_session->NormalClient == false)
				{
					// The internal session don't become target for format exclude: or include:
					return false;
				}

				if (IsUserMatchInUserListWithCacheExpiresAcl(o, a->DestUsername, dest_username,
					hub->Option->AccessListIncludeFileCacheLifetime * 1000) == false)
				{
					return false;
				}
			}
		}
	}

	// Determine of the IP packet
	if (p->TypeL3 != L3_IPV4)
	{
		is_ipv4_packet = false;
	}
	else
	{
		is_ipv4_packet = true;
	}

	if (p->TypeL3 != L3_IPV6)
	{
		is_ipv6_packet = false;
	}
	else
	{
		is_ipv6_packet = true;
	}

	if (p->TypeL3 == L3_ARPV4)
	{
		is_arp_packet = true;
	}

	if (is_ipv4_packet)
	{
		ip = p->L3.IPv4Header;
	}

	if (is_ipv6_packet)
	{
		ip6 = p->L3.IPv6Header;
	}

	if (a->IsIPv6 == false)
	{
		// IPv4

		// Check the source IP address
		if (a->SrcIpAddress != 0 || a->SrcSubnetMask != 0)
		{
			if (is_ipv4_packet == false)
			{
				if (p->TypeL3 == L3_ARPV4)
				{
					bool arp_match = false;
					if (p->L3.ARPv4Header->HardwareSize == 6 &&
						Endian16(p->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
						p->L3.ARPv4Header->ProtocolSize == 4 &&
						Endian16(p->L3.ARPv4Header->ProtocolType) == 0x0800)
					{
						UINT uint_ip = p->L3.ARPv4Header->SrcIP;

						if (uint_ip != 0 && uint_ip != 0xffffffff && !(IsHubIpAddress32(uint_ip) && IsHubMacAddress(p->MacAddressSrc)))
						{
							if ((uint_ip & a->SrcSubnetMask) != (a->SrcIpAddress & a->SrcSubnetMask))
							{
							}
							else
							{
								arp_match = true;
							}
						}
					}

					if (arp_match == false)
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}
			else
			{
				if ((ip->SrcIP & a->SrcSubnetMask) != (a->SrcIpAddress & a->SrcSubnetMask))
				{
					return false;
				}
			}
		}

		// Check the destination IP address
		if (a->DestIpAddress != 0 || a->DestSubnetMask != 0)
		{
			if (is_ipv4_packet == false)
			{
				if (p->TypeL3 == L3_ARPV4)
				{
					bool arp_match = false;
					if (p->L3.ARPv4Header->HardwareSize == 6 &&
						Endian16(p->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
						p->L3.ARPv4Header->ProtocolSize == 4 &&
						Endian16(p->L3.ARPv4Header->ProtocolType) == 0x0800)
					{
						UINT uint_ip = p->L3.ARPv4Header->TargetIP;

						if (uint_ip != 0 && uint_ip != 0xffffffff && !(IsHubIpAddress32(uint_ip) && IsHubMacAddress(p->MacAddressSrc)))
						{
							if ((uint_ip & a->DestSubnetMask) != (a->DestIpAddress & a->DestSubnetMask))
							{
							}
							else
							{
								arp_match = true;
							}
						}
					}

					if (arp_match == false)
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}
			else
			{
				if ((ip->DstIP & a->DestSubnetMask) != (a->DestIpAddress & a->DestSubnetMask))
				{
					return false;
				}
			}
		}
	}
	else
	{
		// IPv6

		// Check the source IP address
		if (IsZeroIP6Addr(&a->SrcIpAddress6) == false ||
			IsZeroIP6Addr(&a->SrcSubnetMask6) == false)
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				IP a_ip, a_subnet, p_ip;
				IP and1, and2;

				IPv6AddrToIP(&a_ip, &a->SrcIpAddress6);
				IPv6AddrToIP(&a_subnet, &a->SrcSubnetMask6);
				IPv6AddrToIP(&p_ip, &ip6->SrcAddress);

				IPAnd6(&and1, &a_ip, &a_subnet);
				IPAnd6(&and2, &p_ip, &a_subnet);

				if (CmpIpAddr(&and1, &and2) != 0)
				{
					return false;
				}
			}
		}

		// Check the destination IP address
		if (IsZeroIP6Addr(&a->DestIpAddress6) == false ||
			IsZeroIP6Addr(&a->DestSubnetMask6) == false)
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				IP a_ip, a_subnet, p_ip;
				IP and1, and2;

				IPv6AddrToIP(&a_ip, &a->DestIpAddress6);
				IPv6AddrToIP(&a_subnet, &a->DestSubnetMask6);
				IPv6AddrToIP(&p_ip, &ip6->DestAddress);

				IPAnd6(&and1, &a_ip, &a_subnet);
				IPAnd6(&and2, &p_ip, &a_subnet);

				if (CmpIpAddr(&and1, &and2) != 0)
				{
					return false;
				}
			}
		}
	}

	// Don't match the packet of non-IPv4 and non-IPv6
	if (is_arp_packet)
	{
		if (s->Hub != NULL && s->Hub->Option != NULL && s->Hub->Option->ApplyIPv4AccessListOnArpPacket)
		{
			// Match the ARP only if ApplyIPv4AccessListOnArpPacket option is enabled
		}
		else
		{
			return false;
		}
	}

	// Check the protocol number
	if (a->Protocol != 0)
	{
		if (a->IsIPv6 == false)
		{
			if (is_ipv4_packet == false)
			{
				return false;
			}
			else
			{
				if (ip->Protocol != a->Protocol)
				{
					return false;
				}
			}
		}
		else
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				if (p->IPv6HeaderPacketInfo.Protocol != a->Protocol)
				{
					return false;
				}
			}
		}
	}

	// Check the port number
	if (a->SrcPortStart != 0 || a->DestPortStart != 0 ||
		a->SrcPortEnd != 0 || a->DestPortEnd != 0)
	{
		if ((a->IsIPv6 == false && is_ipv4_packet == false) ||
			(a->IsIPv6 && is_ipv6_packet == false))
		{
			return false;
		}
		else
		{
			if (p->TypeL4 == L4_TCP)
			{
				TCP_HEADER *tcp = p->L4.TCPHeader;
				// Check the source port
				if (a->SrcPortStart != 0 || a->SrcPortEnd != 0)
				{
					UINT src_port = Endian16(tcp->SrcPort);
					if (src_port < a->SrcPortStart || src_port > a->SrcPortEnd)
					{
						return false;
					}
				}

				// Check the destination port number
				if (a->DestPortStart != 0 || a->DestPortEnd != 0)
				{
					UINT dest_port = Endian16(tcp->DstPort);
					if (dest_port < a->DestPortStart || dest_port > a->DestPortEnd)
					{
						return false;
					}
				}
			}
			else if (p->TypeL4 == L4_UDP)
			{
				UDP_HEADER *udp = p->L4.UDPHeader;
				// Check the source port
				if (a->SrcPortStart != 0 || a->SrcPortEnd != 0)
				{
					UINT src_port = Endian16(udp->SrcPort);
					if (src_port < a->SrcPortStart || src_port > a->SrcPortEnd)
					{
						return false;
					}
				}

				// Check the destination port number
				if (a->DestPortStart != 0 || a->DestPortEnd != 0)
				{
					UINT dest_port = Endian16(udp->DstPort);
					if (dest_port < a->DestPortStart || dest_port > a->DestPortEnd)
					{
						return false;
					}
				}
			}
			else
			{
				// When the port number is specified in the access list,
				// The rule is applied only for UDP or TCP packets
				return false;
			}
		}
	}

	// Check the status of the TCP connection
	if (a->CheckTcpState != false)
	{
		if ((a->IsIPv6 == false && is_ipv4_packet == false) ||
			(a->IsIPv6 && is_ipv6_packet == false))
		{
			return false;
		}
		else
		{
			if(p->TypeL4 == L4_TCP)
			{
				// by shimizu
				TCP_HEADER *tcp = p->L4.TCPHeader;
				bool est = true;

				if ((tcp->Flag & TCP_SYN) && (!(tcp->Flag & TCP_ACK)))
				{
					est = false;
				}

				if((MAKEBOOL(a->Established) ^ MAKEBOOL(est)))
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}
	}

	return true;
}

// Apply the access list for packets to forward
bool ApplyAccessListToForwardPacket(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *p)
{
	UINT i;
	bool pass = true;	// Pass by default
	bool skip = true;
	// Validate arguments
	if (hub == NULL || src_session == NULL || p == NULL || dest_session == NULL)
	{
		return false;
	}

	// The access list is not re-applied for packets that have been already checked
	if (p->AccessChecked)
	{
		return true;
	}

	LockList(hub->AccessList);
	{
		for (i = 0;i < LIST_NUM(hub->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(hub->AccessList, i);

			// Scan the entry only after the destination user name is specified.
			if (a->DestUsernameHash != 0)
			{
				skip = false;
			}

			if (skip == false)
			{
				if (IsPacketMaskedByAccessList(src_session, p, a,
					((HUB_PA *)dest_session->PacketAdapter->Param)->UsernameHash,
					((HUB_PA *)dest_session->PacketAdapter->Param)->GroupnameHash,
					dest_session))
				{
					// Determine the pass or discard the packet
					pass = a->Discard ? false : true;

					// Complete the scanning of the list here
					break;
				}
			}
		}
	}
	UnlockList(hub->AccessList);

	return pass;
}

// Generate a HTTP payload for redirect
BUF *BuildRedirectToUrlPayload(HUB *hub, SESSION *s, char *redirect_url)
{
	char html[MAX_REDIRECT_URL_LEN * 2 + 1 + MAX_SIZE];
	char header[MAX_REDIRECT_URL_LEN * 2 + 1 + MAX_SIZE];
	char redirect_url2[MAX_REDIRECT_URL_LEN * 2];
	BUF *b;
	// Validate arguments
	if (hub == NULL || s == NULL || redirect_url == NULL)
	{
		return NULL;
	}

	StrCpy(redirect_url2, sizeof(redirect_url2), redirect_url);
	Trim(redirect_url2);

	if (InStr(redirect_url2, ACCESS_LIST_URL_INFO_TAG))
	{
		// Get the secret key string
		char secret[MAX_SIZE];
		char tmp[MAX_SIZE];
		SYSTEMTIME st;
		UINT i, len, isp;

		isp = INFINITE;

		SystemTime(&st);
		ClearStr(secret, sizeof(secret));

		len = StrLen(redirect_url2);

		for (i = 0;i < len;i++)
		{
			char c = redirect_url2[i];
			if (c == '|')
			{
				isp = i;
			}
		}

		if (isp != INFINITE)
		{
			StrCpy(secret, sizeof(secret), redirect_url2 + isp + 1);
			redirect_url2[isp] = 0;
		}

		Format(tmp, sizeof(tmp), "%s|%s|%r|%04u%02u%02u%02u%02u%02u%s",
			s->Username, s->Name, &s->Connection->ClientIp,
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, (IsEmptyStr(secret) ? "" : "|"));

		if (IsEmptyStr(secret) == false)
		{
			// Calculate the hash
			UCHAR hash[SHA1_SIZE];
			char hash_str[MAX_SIZE];
			BUF *b2 = NewBuf();

			WriteBuf(b2, tmp, StrLen(tmp));
			WriteBuf(b2, secret, StrLen(secret));

			Sha1(hash, b2->Buf, b2->Size);

			BinToStr(hash_str, sizeof(hash_str), hash, sizeof(hash));

			FreeBuf(b2);

			StrCat(tmp, sizeof(tmp), hash_str);

			// Replace
			ReplaceStrEx(redirect_url2, sizeof(redirect_url2), redirect_url2,
				ACCESS_LIST_URL_INFO_TAG, tmp, false);
		}
	}

	Format(html, sizeof(html),
		"<html><head><title>Object moved</title></head><body>\r\n<h2>Object moved to <a href=\"%s\">here</a>.</h2>\r\n</body></html>\r\n\r\n",
		redirect_url2);

	Format(header, sizeof(header),
		"HTTP/1.1 302 Found\r\nLocation: %s\r\nCache-Control: private\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %u\r\n\r\n",
		redirect_url2, StrLen(redirect_url2));

	b = NewBuf();

	WriteBuf(b, header, StrLen(header));
	WriteBuf(b, html, StrLen(html));

	return b;
}

// Rpely a TCP response packet to redirect forcibly to the specified URL
void ForceRedirectToUrl(HUB *hub, SESSION *src_session, PKT *p, char *redirect_url)
{
	BUF *payload;
	UINT tcp_size;
	TCP_HEADER *tcp_data;
	TCP_HEADER *src_tcp;
	BUF *b;
	// Validate arguments
	if (hub == NULL || src_session == NULL || p == NULL || redirect_url == NULL)
	{
		return;
	}
	if (p->TypeL3 != L3_IPV4 && p->TypeL3 != L3_IPV6)
	{
		return;
	}
	if (p->TypeL4 != L4_TCP)
	{
		return;
	}

	src_tcp = p->L4.TCPHeader;
	if (src_tcp == NULL)
	{
		return;
	}

	// Generate a payload to be sent
	payload = BuildRedirectToUrlPayload(hub, src_session, redirect_url);
	if (payload == NULL)
	{
		return;
	}

	// Generate a TCP packet
	tcp_size = sizeof(TCP_HEADER) + payload->Size;
	tcp_data = (TCP_HEADER *)ZeroMalloc(tcp_size);
	tcp_data->SrcPort = src_tcp->DstPort;
	tcp_data->DstPort = src_tcp->SrcPort;
	tcp_data->SeqNumber = src_tcp->AckNumber;
	tcp_data->AckNumber = Endian32(Endian32(src_tcp->SeqNumber) + p->PayloadSize);
	TCP_SET_HEADER_SIZE(tcp_data, 5);
	tcp_data->Flag = TCP_ACK | TCP_PSH;
	tcp_data->WindowSize = Endian16(0xFFFF);
	Copy(((UCHAR *)tcp_data) + sizeof(TCP_HEADER), payload->Buf, payload->Size);

	// Calculate the TCP checksum
	if (p->TypeL3 == L3_IPV4)
	{
		// IPv4
		tcp_data->Checksum = CalcChecksumForIPv4(p->L3.IPv4Header->DstIP, p->L3.IPv4Header->SrcIP, IP_PROTO_TCP,
			tcp_data, tcp_size, 0);
	}
	else
	{
		// IPv6
		tcp_data->Checksum = CalcChecksumForIPv6(&p->IPv6HeaderPacketInfo.IPv6Header->DestAddress,
			&p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress, IP_PROTO_TCP, tcp_data, tcp_size, 0);
	}

	// Generate the Ethernet and IP packet
	b = NewBuf();

	// Destination MAC address
	WriteBuf(b, p->MacHeader->SrcAddress, 6);
	WriteBuf(b, p->MacHeader->DestAddress, 6);
	WriteBuf(b, &p->MacHeader->Protocol, 2);

	if (p->TypeL3 == L3_IPV4)
	{
		// IPv4
		IPV4_HEADER v4;

		Zero(&v4, sizeof(v4));

		IPV4_SET_VERSION(&v4, 4);
		IPV4_SET_HEADER_LEN(&v4, 5);
		v4.TotalLength = Endian16((USHORT)(sizeof(IPV4_HEADER) + tcp_size));
		v4.Identification = Endian16(Rand16());
		IPV4_SET_FLAGS(&v4, 0x02);
		v4.TimeToLive = 128;
		v4.Protocol = IP_PROTO_TCP;
		v4.SrcIP = p->L3.IPv4Header->DstIP;
		v4.DstIP = p->L3.IPv4Header->SrcIP;
		v4.Checksum = IpChecksum(&v4, sizeof(v4));

		WriteBuf(b, &v4, sizeof(v4));
	}
	else
	{
		// IPv6
		IPV6_HEADER v6;

		Zero(&v6, sizeof(v6));

		IPV6_SET_VERSION(&v6, 6);
		v6.PayloadLength = Endian16(tcp_size);
		v6.NextHeader = IP_PROTO_TCP;
		v6.HopLimit = 64;

		Copy(&v6.SrcAddress, &p->IPv6HeaderPacketInfo.IPv6Header->DestAddress, sizeof(IPV6_ADDR));
		Copy(&v6.DestAddress, &p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress, sizeof(IPV6_ADDR));

		WriteBuf(b, &v6, sizeof(v6));
	}

	WriteBuf(b, tcp_data, tcp_size);

	// Reply packet
	StorePacketToHubPa((HUB_PA *)src_session->PacketAdapter->Param,
		NULL, b->Buf, b->Size, NULL, false, false);

	// Release the memory
	Free(tcp_data);
	FreeBuf(payload);
	Free(b);
}

// Apply the access list for packets stored
bool ApplyAccessListToStoredPacket(HUB *hub, SESSION *s, PKT *p)
{
	UINT i;
	bool pass = true;	// Pass by default
	bool use_redirect_url = false;
	char redirect_url[MAX_REDIRECT_URL_LEN + 1];
	// Validate arguments
	if (hub == NULL || s == NULL || p == NULL)
	{
		return false;
	}

	if (hub->Option != NULL && hub->Option->FilterPPPoE)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x8863 || proto == 0x8864)
			{
				// PPPoE Filter
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterOSPF)
	{
		if (p->TypeL3 == L3_IPV4)
		{
			if (p->L3.IPv4Header != NULL)
			{
				if (p->L3.IPv4Header->Protocol == 89)
				{
					// OSPF Filter
					return false;
				}
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterIPv4)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x0800 || proto == 0x0806)
			{
				// IPv4 Filter
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterIPv6)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x86dd)
			{
				// IPv6 Filter
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterNonIP)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (!(proto == 0x86dd || proto == 0x0800 || proto == 0x0806))
			{
				// Non-IP Filter
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterBPDU)
	{
		if (p->MacHeader != NULL)
		{
			if (p->TypeL3 == L3_BPDU)
			{
				// BPDU Filter
				return false;
			}
		}
	}

	LockList(hub->AccessList);
	{
		for (i = 0;i < LIST_NUM(hub->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(hub->AccessList, i);

			if (a->DestUsernameHash != 0)
			{
				// If a destination user name is specified, suspend the scanning of the list.
				break;
			}

			if (IsPacketMaskedByAccessList(s, p, a, 0, 0, NULL))
			{
				// Determine the pass or discard the packet
				pass = a->Discard ? false : true;

				// Packets determined processing here is not scanned when leaving the HUB.
				p->AccessChecked = true;

				// Copy of the parameters of the delay jitter packet loss
				p->Delay = a->Delay;
				p->Jitter = a->Jitter;
				p->Loss = a->Loss;

				if (a->RedirectUrl[0] != 0)
				{
					// There is a setting of URL redirection in the access list
					if ((p->TypeL3 == L3_IPV4 || p->TypeL3 == L3_IPV6) &&
						p->TypeL4 == L4_TCP)
					{
						TCP_HEADER *tcp = p->L4.TCPHeader;

						// Examine whether this packet is a TCP data packet
						if (tcp != NULL)
						{
							if (tcp->Flag & TCP_ACK)
							{
								if ((tcp->Flag & TCP_SYN) == 0 &&
									(tcp->Flag & TCP_RST) == 0 &&
									(tcp->Flag & TCP_URG) == 0)
								{
									if (p->PayloadSize != 0)
									{
										// Do URL redirection
										use_redirect_url = true;
										StrCpy(redirect_url, sizeof(redirect_url), a->RedirectUrl);
									}
								}
							}
						}
					}
				}

				// Complete the scanning of the list here
				break;
			}
		}
	}
	UnlockList(hub->AccessList);

	if (pass)
	{
		if (s->FirstTimeHttpRedirect && s->FirstTimeHttpAccessCheckIp != 0)
		{
			if ((p->TypeL3 == L3_IPV4 || p->TypeL3 == L3_IPV6) &&
				p->TypeL4 == L4_TCP)
			{
				TCP_HEADER *tcp = p->L4.TCPHeader;

				// Examine whether this packet is a TCP data packet
				if (tcp != NULL)
				{
					if (tcp->DstPort == Endian16(80))
					{
						if (p->L3.IPv4Header->DstIP == s->FirstTimeHttpAccessCheckIp)
						{
							s->FirstTimeHttpRedirect = false;
						}
						else if (tcp->Flag & TCP_ACK)
						{
							if ((tcp->Flag & TCP_SYN) == 0 &&
								(tcp->Flag & TCP_RST) == 0 &&
								(tcp->Flag & TCP_URG) == 0)
							{
								if (p->PayloadSize != 0)
								{
									if (IsTcpPacketNcsiHttpAccess(p) == false)
									{
/*										char tmp[4000];
										Zero(tmp, sizeof(tmp));
										Copy(tmp, p->Payload, p->PayloadSize);
										Debug("HTTP: %s\n", tmp);*/
										if (IsEmptyStr(s->FirstTimeHttpRedirectUrl) == false)
										{
											use_redirect_url = true;
											StrCpy(redirect_url, sizeof(redirect_url), s->FirstTimeHttpRedirectUrl);
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if (use_redirect_url)
	{
		if (s->NormalClient)
		{
			// In the case of a normal VPN client (Not a local bridge, a SecureNAT, and not a virtual L3 switch),
			// process URL redirection and discard the packet
			ForceRedirectToUrl(hub, s, p, redirect_url);
		}
		else
		{
			// Discard packets that is sent from the sessions such as local bridge,
			// SecureNAT, virtual L3 switch
		}

		pass = false;
	}

	return pass;
}

// Check whether the TCP packet is NCSI accessing
bool IsTcpPacketNcsiHttpAccess(PKT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return false;
	}

	if (p->TypeL4 != L4_TCP)
	{
		return false;
	}

	if (p->Payload == NULL || p->PayloadSize == 0)
	{
		return false;
	}

	if (SearchBin(p->Payload, 0, p->PayloadSize, "NCSI", 4) != INFINITE)
	{
		return true;
	}

	if (SearchBin(p->Payload, 0, p->PayloadSize, ".jpeg", 5) != INFINITE)
	{
		return true;
	}

	if (SearchBin(p->Payload, 0, p->PayloadSize, ".jpg", 4) != INFINITE)
	{
		return true;
	}

	if (SearchBin(p->Payload, 0, p->PayloadSize, ".gif", 4) != INFINITE)
	{
		return true;
	}

	if (SearchBin(p->Payload, 0, p->PayloadSize, ".css", 4) != INFINITE)
	{
		return true;
	}

	return false;
}

// Adding Access List
void AddAccessList(HUB *hub, ACCESS *a)
{
	AddAccessListEx(hub, a, false, false);
}
void AddAccessListEx(HUB *hub, ACCESS *a, bool no_sort, bool no_reassign_id)
{
	// Validate arguments
	if (hub == NULL || a == NULL)
	{
		return;
	}

	LockList(hub->AccessList);
	{
		ACCESS *access;
		UINT i;

		// Check the number of items
		if (LIST_NUM(hub->AccessList) >= MAX_ACCESSLISTS)
		{
			UnlockList(hub->AccessList);
			return;
		}

		access = Malloc(sizeof(ACCESS));
		Copy(access, a, sizeof(ACCESS));

		access->IsSrcUsernameIncludeOrExclude = false;
		access->IsDestUsernameIncludeOrExclude = false;

		// User name correction
		if (IsEmptyStr(access->SrcUsername) == false)
		{
			if (StartWith(access->SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) == false && StartWith(access->SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX) == false)
			{
				MakeSimpleUsernameRemoveNtDomain(access->SrcUsername, sizeof(access->SrcUsername), access->SrcUsername);
			}
			else
			{
				access->IsSrcUsernameIncludeOrExclude = true;
			}
		}
		if (IsEmptyStr(access->DestUsername) == false)
		{
			if (StartWith(access->DestUsername, ACCESS_LIST_INCLUDED_PREFIX) == false && StartWith(access->DestUsername, ACCESS_LIST_EXCLUDED_PREFIX) == false)
			{
				MakeSimpleUsernameRemoveNtDomain(access->DestUsername, sizeof(access->DestUsername), access->DestUsername);
			}
			else
			{
				access->IsDestUsernameIncludeOrExclude = true;
			}
		}

		access->SrcUsernameHash = UsernameToInt64(access->SrcUsername);
		access->DestUsernameHash = UsernameToInt64(access->DestUsername);

		// Port number correction
		if (access->SrcPortStart != 0)
		{
			access->SrcPortEnd = MAX(access->SrcPortEnd, access->SrcPortStart);
		}
		if (access->DestPortStart != 0)
		{
			access->DestPortEnd = MAX(access->DestPortEnd, access->DestPortStart);
		}

		// Correct delay, jitter, and packet loss
		access->Delay = MAKESURE(access->Delay, 0, HUB_ACCESSLIST_DELAY_MAX);
		access->Jitter = MAKESURE(access->Jitter, 0, HUB_ACCESSLIST_JITTER_MAX);
		access->Loss = MAKESURE(access->Loss, 0, HUB_ACCESSLIST_LOSS_MAX);

		if (no_sort == false)
		{
			Insert(hub->AccessList, access);
		}
		else
		{
			Add(hub->AccessList, access);
		}

		// Reassign the ID
		if (no_reassign_id == false)
		{
			for (i = 0;i < LIST_NUM(hub->AccessList);i++)
			{
				ACCESS *a = LIST_DATA(hub->AccessList, i);
				a->Id = (i + 1);
			}
		}
	}
	UnlockList(hub->AccessList);
}

// Initialize the access list
void InitAccessList(HUB *hub)
{
	// Validate arguments
	if (hub == NULL)
	{
		return;
	}

	hub->AccessList = NewList(CmpAccessList);
}

// Release the access list
void FreeAccessList(HUB *hub)
{
	UINT i;
	// Validate arguments
	if (hub == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(hub->AccessList);i++)
	{
		ACCESS *a = LIST_DATA(hub->AccessList, i);
		Free(a);
	}

	ReleaseList(hub->AccessList);
	hub->AccessList = NULL;
}

// Comparison of the access list entry
int CmpAccessList(void *p1, void *p2)
{
	ACCESS *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(ACCESS **)p1;
	a2 = *(ACCESS **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	// Sort by priority
	if (a1->Priority > a2->Priority)
	{
		return 1;
	}
	else if (a1->Priority < a2->Priority)
	{
		return -1;
	}
	else if (a1->Discard > a2->Discard)
	{
		return 1;
	}
	else if (a1->Discard < a2->Discard)
	{
		return -1;
	}
	else
	{
		UINT64 size64 = ((UINT64)(&a1->UniqueId) - (UINT64)(&a1->Active));
		UINT size32 = (UINT)size64;

		return Cmp(&a1->Active, &a2->Active, size32);
	}
}

// Generate a user name without domain name of the Windows NT
void MakeSimpleUsernameRemoveNtDomain(char *dst, UINT dst_size, char *src)
{
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	ParseNtUsername(src, tmp1, sizeof(tmp1), tmp2, sizeof(tmp2), false);

	StrCpy(dst, dst_size, tmp1);
}

// Convert the user name to UINT
UINT64 UsernameToInt64(char *name)
{
	UCHAR hash[SHA1_SIZE];
	UINT64 ret;
	char tmp[MAX_USERNAME_LEN + 1];
	// Validate arguments
	if (name == 0 || IsEmptyStr(name))
	{
		return 0;
	}

	if (StartWith(name, ACCESS_LIST_INCLUDED_PREFIX) || StartWith(name, ACCESS_LIST_EXCLUDED_PREFIX))
	{
		return Rand64();
	}

	MakeSimpleUsernameRemoveNtDomain(tmp, sizeof(tmp), name);
	Trim(tmp);
	StrUpper(tmp);

	if (StrLen(tmp) == 0)
	{
		return 0;
	}

	Sha0(hash, tmp, StrLen(tmp));
	Copy(&ret, hash, sizeof(ret));

	return ret;
}

// Search the session from the session name
SESSION *GetSessionByName(HUB *hub, char *name)
{
	// Validate arguments
	if (hub == NULL || name == NULL)
	{
		return NULL;
	}

	LockList(hub->SessionList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(hub->SessionList);i++)
		{
			SESSION *s = LIST_DATA(hub->SessionList, i);
			if (StrCmpi(s->Name, name) == 0)
			{
				// Found
				AddRef(s->ref);
				UnlockList(hub->SessionList);
				return s;
			}
		}
	}
	UnlockList(hub->SessionList);

	return NULL;
}

// Sort of the STORM list
int CompareStormList(void *p1, void *p2)
{
	STORM *s1, *s2;
	UINT r;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(STORM **)p1;
	s2 = *(STORM **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}
	if (s1->StrictMode == false && s2->StrictMode == false)
	{
		// Normal mode
		r = CmpIpAddr(&s1->DestIp, &s2->DestIp);
		if (r != 0)
		{
			return r;
		}
		r = CmpIpAddr(&s1->SrcIp, &s2->SrcIp);
		if (r != 0)
		{
			return r;
		}
	}
	else
	{
		// Strict mode
		int r1, r2;
		r1 = CmpIpAddr(&s1->DestIp, &s2->DestIp);
		r2 = CmpIpAddr(&s1->SrcIp, &s2->SrcIp);
		if (r1 == 0 || r2 == 0)
		{
			// Either the source IP, and destination IP match
		}
		else
		{
			// Mismatch
			if (r1 != 0)
			{
				return r1;
			}

			if (r2 != 0)
			{
				return r2;
			}
		}
	}
	r = Cmp(s1->MacAddress, s2->MacAddress, 6);
	return r;
}

// Packet adapter initialization
bool HubPaInit(SESSION *s)
{
	// Initialize the packet adapter information
	HUB_PA *pa = ZeroMalloc(sizeof(HUB_PA));
	pa->Cancel = NewCancel();
	pa->PacketQueue = NewQueue();
	pa->Now = Tick64();
	pa->Session = s;
	pa->StormList = NewList(CompareStormList);
	pa->UsernameHash = UsernameToInt64(s->Username);
	pa->GroupnameHash = UsernameToInt64(s->GroupName);

	s->PacketAdapter->Param = pa;

	if (s->Policy->MonitorPort)
	{
		// Mark this port as monitoring port
		pa->MonitorPort = true;

		// Add this session to the list of monitoring port of the HUB
		LockList(s->Hub->MonitorList);
		{
			Insert(s->Hub->MonitorList, s);
		}
		UnlockList(s->Hub->MonitorList);
	}

	return true;
}

// Release the Packet adapter
void HubPaFree(SESSION *s)
{
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;
	HUB *hub = s->Hub;

	if (pa->MonitorPort)
	{
		// Remove the session from the list of monitor port of the HUB
		LockList(s->Hub->MonitorList);
		{
			Delete(s->Hub->MonitorList, s);
		}
		UnlockList(s->Hub->MonitorList);
	}

	// Erase MAC address table entries that is associated with this session
	LockHashList(hub->MacHashTable);
	{
		UINT i, num;
		MAC_TABLE_ENTRY **pp;
		LIST *o = NewListFast(NULL);

		pp = (MAC_TABLE_ENTRY **)HashListToArray(hub->MacHashTable, &num);
		for (i = 0;i < num;i++)
		{
			MAC_TABLE_ENTRY *e = (MAC_TABLE_ENTRY *)pp[i];
			if (e->Session == s)
			{
				Add(o, e);
			}
		}
		for (i = 0;i < LIST_NUM(o);i++)
		{
			MAC_TABLE_ENTRY *e = (MAC_TABLE_ENTRY *)LIST_DATA(o, i);
			DeleteHash(hub->MacHashTable, e);
			Free(e);
		}
		ReleaseList(o);
		Free(pp);
	}
	{
		UINT i, num = LIST_NUM(hub->IpTable);
		LIST *o = NewListFast(NULL);
		for (i = 0;i < num;i++)
		{
			IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);
			if (e->Session == s)
			{
				Add(o, e);
			}
		}
		for (i = 0;i < LIST_NUM(o);i++)
		{
			IP_TABLE_ENTRY *e = LIST_DATA(o, i);
			Delete(hub->IpTable, e);
			Free(e);
		}
		ReleaseList(o);
	}
	UnlockHashList(hub->MacHashTable);

	// Release the STORM list
	LockList(pa->StormList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(pa->StormList);i++)
		{
			STORM *s = (STORM *)LIST_DATA(pa->StormList, i);
			Free(s);
		}
		DeleteAll(pa->StormList);
	}
	UnlockList(pa->StormList);

	ReleaseList(pa->StormList);

	// Release the packets remaining in the queue
	LockQueue(pa->PacketQueue);
	{
		BLOCK *b;

		while (b = GetNext(pa->PacketQueue))
		{
			// Release the block
			if (b->IsFlooding)
			{
				CedarAddCurrentTcpQueueSize(s->Cedar, -((int)b->Size));
			}

			FreeBlock(b);
		}
	}
	UnlockQueue(pa->PacketQueue);

	// Release the queue
	ReleaseQueue(pa->PacketQueue);

	// Release the cancel object
	ReleaseCancel(pa->Cancel);

	// Release the packet adapter information
	Free(pa);
	s->PacketAdapter->Param = NULL;
}

// Get the cancel object
CANCEL *HubPaGetCancel(SESSION *s)
{
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	AddRef(pa->Cancel->ref);
	return pa->Cancel;
}

// Get the packet to be transmitted next
UINT HubPaGetNextPacket(SESSION *s, void **data)
{
	UINT ret = 0;
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	// Get one from the head of the queue
	LockQueue(pa->PacketQueue);
	{
		BLOCK *block = GetNext(pa->PacketQueue);
		if (block == NULL)
		{
			// No queue
			ret = 0;
		}
		else
		{
			if (block->IsFlooding)
			{
				CedarAddCurrentTcpQueueSize(s->Cedar, -((int)block->Size));
			}

			// Found
			*data = block->Buf;
			ret = block->Size;
			// Release the memory of the structure of the block
			Free(block);
		}
	}
	UnlockQueue(pa->PacketQueue);

	return ret;
}

// Receive a packet
bool HubPaPutPacket(SESSION *s, void *data, UINT size)
{
	PKT *packet;
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;
	bool b = false;
	HUB *hub;
	bool no_l3 = false;
	bool no_http = false;
	LIST *o = NULL;
	UINT i;
	UINT vlan_type_id = 0;
	bool no_look_bpdu_bridge_id = false;
	bool no_parse_dhcp = false;
	bool no_correct_checksum = false;

	hub = s->Hub;

	pa->Now = Tick64();

	// Processing of Adjust TCP MSS
	if (hub != NULL && hub->Option != NULL && hub->Option->DisableAdjustTcpMss == false && s != NULL)
	{
		UINT target_mss = (hub->Option->AdjustTcpMssValue == 0 ? INFINITE : hub->Option->AdjustTcpMssValue);
		UINT session_mss = (s->AdjustMss == 0 ? INFINITE : s->AdjustMss);

		target_mss = MIN(target_mss, session_mss);

		if (s->UseUdpAcceleration && s->UdpAccelMss != 0)
		{
			// If the link is established with UDP acceleration function, use optimum value of the UDP acceleration function
			target_mss = MIN(target_mss, s->UdpAccelMss);
		}
		else if (s->IsRUDPSession && s->RUdpMss != 0)
		{
			// If the link with UDP acceleration is not established, use the optimum value for R-UDP in the case of using R-UDP connection
			target_mss = MIN(target_mss, s->RUdpMss);
		}

		if (target_mss != INFINITE)
		{
			AdjustTcpMssL2(data, size, target_mss, hub->Option->VlanTypeId);
		}
	}

	if (data == NULL)
	{
		// Check the delayed packet
		o = NULL;
		LockList(s->DelayedPacketList);
		{
			UINT i;
			if (LIST_NUM(s->DelayedPacketList) >= 1)
			{
				UINT64 now = TickHighres64();
				for (i = 0;i < LIST_NUM(s->DelayedPacketList);i++)
				{
					PKT *p = LIST_DATA(s->DelayedPacketList, i);

					if (now >= p->DelayedForwardTick)
					{
						if (o == NULL)
						{
							o = NewListFast(NULL);
						}

						Add(o, p);
					}
				}
			}

			if (o != NULL)
			{
				for (i = 0;i < LIST_NUM(o);i++)
				{
					PKT *p = LIST_DATA(o, i);

					Delete(s->DelayedPacketList, p);
				}
			}
		}
		UnlockList(s->DelayedPacketList);

		// If there is a delayed packet, store it
		if (o != NULL)
		{
			for (i = 0;i < LIST_NUM(o);i++)
			{
				PKT *p = LIST_DATA(o, i);

				StorePacket(s->Hub, s, p);
			}

			ReleaseList(o);
		}

		// Reception of all packets from this session is complete
		CancelList(s->CancelList);

		// Yield
		if (hub != NULL)
		{
			if (hub->Option != NULL && hub->Option->YieldAfterStorePacket)
			{
				YieldCpu();
			}
		}

		return true;
	}

	if (hub != NULL && hub->Option != NULL)
	{
		no_l3 = hub->Option->DisableIPParsing;
		no_http = hub->Option->DisableHttpParsing;
		vlan_type_id = hub->Option->VlanTypeId;
		no_look_bpdu_bridge_id = hub->Option->NoLookBPDUBridgeId;
		no_correct_checksum = hub->Option->DisableCorrectIpOffloadChecksum;
	}

	// Insert a VLAN tag
	if (s->VLanId != 0)
	{
		VLanInsertTag(&data, &size, s->VLanId, vlan_type_id);
	}

LABEL_TRY_AGAIN:
	// Parse the packet
	packet = ParsePacketEx4(data, size, no_l3, vlan_type_id, !no_look_bpdu_bridge_id, no_http, !no_correct_checksum);

	if (packet != NULL)
	{
		if (packet->InvalidSourcePacket)
		{
			// Packet which have illegal source
			FreePacket(packet);
			packet = NULL;
		}
	}


	if (packet != NULL)
	{
		if (packet->TypeL7 == L7_DHCPV4)
		{
			if (packet->TypeL3 == L3_IPV4 && packet->TypeL4 == L4_UDP)
			{
				if (packet->L7.DHCPv4Header != NULL)
				{
					DHCPV4_HEADER *dhcp = packet->L7.DHCPv4Header;

					if (dhcp->OpCode == 1)
					{
						if (NsIsMacAddressOnLocalhost(dhcp->ClientMacAddress))
						{
							// Filter DHCP requests sent from local kernel-mode virtual NAT
							// not to re-enter it to the virtual HUB along the local bridge
							FreePacket(packet);
							packet = NULL;
						}
					}
				}
			}
		}
	}

	if (no_parse_dhcp == false && packet != NULL)
	{
		if (hub != NULL && hub->Option != NULL && hub->Option->RemoveDefGwOnDhcpForLocalhost)
		{
			// Remove the designation of the DHCP server from the DHCP response packet addressed to localhost
			if (packet->TypeL7 == L7_DHCPV4)
			{
				if (packet->TypeL3 == L3_IPV4)
				{
					if (packet->TypeL4 == L4_UDP)
					{
						if (packet->L7.DHCPv4Header != NULL)
						{
							DHCPV4_HEADER *dhcp = packet->L7.DHCPv4Header;

							if (dhcp->OpCode == 2)
							{
								if (IsMacAddressLocalFast(dhcp->ClientMacAddress))
								{
									BUF *new_buf;
									DHCP_MODIFY_OPTION m;
									WHERE;

									Zero(&m, sizeof(m));
									m.RemoveDefaultGatewayOnReply = true;

									new_buf = DhcpModifyIPv4(&m, data, size);

									if (new_buf != NULL)
									{
										Free(data);

										data = new_buf->Buf;
										size = new_buf->Size;

										Free(new_buf);

										no_parse_dhcp = true;

										FreePacket(packet);

										goto LABEL_TRY_AGAIN;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if (packet != NULL)
	{
		// Store packet
		StorePacket(s->Hub, s, packet);
	}
	else
	{
		// Release the packet data because it is a bad packet (not a correct MAC frame)
		Free(data);
	}

	return true;
}

// Checking algorithm to prevent broadcast-storm
// If broadcast from a specific endpoint came frequently, filter it
bool CheckBroadcastStorm(HUB *hub, SESSION *s, PKT *p)
{
	IP src_ip, dest_ip;
	HUB_PA *pa;
	UINT64 now = Tick64();
	UINT limit_start_count;
	SESSION *sess = s;
	bool ret = true;
	bool strict = false;
	bool no_heavy = false;
	// Validate arguments
	if (s == NULL || p == NULL || hub == NULL)
	{
		return false;
	}

	if (s->Policy->NoBroadcastLimiter)
	{
		// Unlimited the number of broadcasts
		return true;
	}

	if (hub->Option != NULL)
	{
		strict = hub->Option->BroadcastLimiterStrictMode;
		no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;
	}

	pa = (HUB_PA *)s->PacketAdapter->Param;

	Zero(&src_ip, sizeof(IP));
	Zero(&dest_ip, sizeof(IP));

	if (p->TypeL3 == L3_IPV4)
	{
		UINTToIP(&src_ip, p->L3.IPv4Header->SrcIP);
		UINTToIP(&dest_ip, p->L3.IPv4Header->DstIP);
	}
	else if (p->TypeL3 == L3_ARPV4)
	{
		UINTToIP(&src_ip, p->L3.ARPv4Header->SrcIP);
		Zero(&dest_ip, sizeof(IP));
	}
	else if (p->TypeL3 == L3_IPV6)
	{
		IPv6AddrToIP(&src_ip, &p->L3.IPv6Header->SrcAddress);
		IPv6AddrToIP(&dest_ip, &p->L3.IPv6Header->DestAddress);
	}

	// Number of broadcast to start limitation for a single interval
	limit_start_count = 32;

	if (s->Hub != NULL && s->Hub->Option->BroadcastStormDetectionThreshold != 0)
	{
		limit_start_count = s->Hub->Option->BroadcastStormDetectionThreshold;
	}

	LockList(pa->StormList);
	{
		STORM *s;
		UINT num;
		s = SearchStormList(pa, p->MacAddressSrc, &src_ip, &dest_ip, strict);
		if (s == NULL)
		{
			s = AddStormList(pa, p->MacAddressSrc, &src_ip, &dest_ip, strict);
		}

		s->CurrentBroadcastNum++;

		if ((s->CheckStartTick + STORM_CHECK_SPAN) < now ||
			s->CheckStartTick == 0 || s->CheckStartTick > now)
		{
			// Measure the number of broadcast periodically
			UINT64 diff_time;
			if (s->CheckStartTick < now)
			{
				diff_time = now - s->CheckStartTick;
			}
			else
			{
				diff_time = 0;
			}
			s->CheckStartTick = now;
			num = (UINT)((UINT64)s->CurrentBroadcastNum * (UINT64)1000 / (UINT64)STORM_CHECK_SPAN);
			s->CurrentBroadcastNum = 0;
			if (num >= limit_start_count)
			{
				char ip1[64];
				char ip2[64];
				char mac[MAX_SIZE];
				IPToStr(ip1, sizeof(ip1), &src_ip);
				IPToStr(ip2, sizeof(ip2), &dest_ip);
				ret = false;
				if (s->DiscardValue < STORM_DISCARD_VALUE_END)
				{
					s->DiscardValue = MAX(s->DiscardValue, 1) * 2;
				}
				Debug("s->DiscardValue: %u  (%u)\n", s->DiscardValue, num);

				MacToStr(mac, sizeof(mac), p->MacAddressSrc);

				if (no_heavy == false)
				{
					HLog(sess->Hub, "LH_BCAST_STORM", sess->Name, mac, ip1, ip2, num);
				}
			}
			else
			{
				if (s->DiscardValue >= 1)
				{
					s->DiscardValue = (UINT)((UINT64)s->DiscardValue / MAX((UINT64)2, (UINT64)diff_time / (UINT64)STORM_CHECK_SPAN));
				}
			}
		}

		if (s->DiscardValue >= STORM_DISCARD_VALUE_START)
		{
			if (s->DiscardValue >= 128)
			{
				ret = false;
			}
			else if ((rand() % s->DiscardValue) != 0)
			{
				ret = false;
			}
		}

	}
	UnlockList(pa->StormList);

	return ret;
}

// Store packet
void StorePacket(HUB *hub, SESSION *s, PKT *packet)
{
	MAC_TABLE_ENTRY *entry = NULL;
	MAC_TABLE_ENTRY t;
	void *data;
	UINT size;
	bool broadcast_mode;
	HUB_PA *dest_pa;
	SESSION *dest_session;
	UINT64 now = Tick64();
	bool no_heavy = false;
	bool drop_broadcast_packet_privacy = false;
	bool drop_arp_packet_privacy = false;
	bool allow_same_user_packet_privacy = false;
	UINT tcp_queue_quota = 0;
	UINT64 dormant_interval = 0;
	// Validate arguments
	if (hub == NULL || packet == NULL)
	{
		return;
	}

	if (s != NULL)
	{
		if (((HUB_PA *)s->PacketAdapter->Param)->MonitorPort)
		{
			// Not to forward packets received from the monitor port
			Free(packet->PacketData);
			FreePacket(packet);
			return;
		}
	}

	if (hub->Option != NULL)
	{
		no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;
		drop_broadcast_packet_privacy = hub->Option->DropBroadcastsInPrivacyFilterMode;
		drop_arp_packet_privacy = hub->Option->DropArpInPrivacyFilterMode;
		allow_same_user_packet_privacy = hub->Option->AllowSameUserInPrivacyFilterMode;
		tcp_queue_quota = hub->Option->FloodingSendQueueBufferQuota;
		if (hub->Option->DetectDormantSessionInterval != 0)
		{
			dormant_interval = (UINT64)hub->Option->DetectDormantSessionInterval * (UINT64)1000;
		}
	}

	if (dormant_interval != 0)
	{
		if (s != NULL && s->NormalClient)
		{
			if (packet->MacAddressSrc != NULL)
			{
				if (IsHubMacAddress(packet->MacAddressSrc) == false)
				{
					s->LastCommTimeForDormant = now;
				}
			}
		}
	}

	// Lock the entire MAC address table
	LockHashList(hub->MacHashTable);
	{
		// Filtering
		if (s != NULL && (packet->DelayedForwardTick == 0 && StorePacketFilter(s, packet) == false))
		{
DISCARD_PACKET:
			// Release a packet since passing has been disallowed
			Free(packet->PacketData);
			FreePacket(packet);
		}
		else // Passing is allowed
		{
			bool forward_now = true;

			if (packet->Loss >= 1)
			{
				// Cause packet loss
				UINT r = rand() % 100;
				if ((packet->Loss >= 100) || (r < packet->Loss))
				{
					// Packet loss
					goto DISCARD_PACKET;
				}
			}

			if (packet->Delay >= 1)
			{
				float delay = (float)packet->Delay;
				float jitter;
				UINT delay_uint;
				bool f = Rand1();
				if (packet->Jitter == 0)
				{
					jitter = 0;
				}
				else
				{
					jitter = (float)(Rand32() % (int)((float)packet->Jitter * delay / 100.0f));
				}

				delay += jitter * (f ? 1 : -1);
				delay_uint = (UINT)delay;

				if (delay_uint >= 1)
				{
					// Cause delay
					forward_now = false;
					packet->Loss = packet->Jitter = packet->Delay = 0;
					packet->DelayedForwardTick = TickHighres64() + (UINT64)delay_uint;
					packet->DelayedSrcSession = s;

					LockList(s->DelayedPacketList);
					{
						Add(s->DelayedPacketList, packet);
					}
					UnlockList(s->DelayedPacketList);
				}
			}

			if (forward_now)
			{
				if (Cmp(packet->MacAddressSrc, hub->HubMacAddr, 6) == 0)
				{
					if (s != NULL)
					{
						// Packets that this HUB itself sent is input from the outside
						goto DISCARD_PACKET;
					}
				}
				if (s != NULL && (Cmp(packet->MacAddressSrc, hub->HubMacAddr, 6) != 0))
				{
					// Check whether the source MAC address is registered in the table
					Copy(t.MacAddress, packet->MacAddressSrc, 6);
					if (hub->Option->NoManageVlanId == false)
					{
						t.VlanId = packet->VlanId;
					}
					else
					{
						t.VlanId = 0;
					}
					entry = SearchHash(hub->MacHashTable, &t);

					if (entry == NULL)
					{
						if (hub->LastFlushTick == 0 || (hub->LastFlushTick + (UINT64)OLD_MAC_ADDRESS_ENTRY_FLUSH_INTERVAL) < now)
						{
							hub->LastFlushTick = now;

							// Remove old entries
							DeleteExpiredMacTableEntry(hub->MacHashTable);
						}

						// Register since it is not registered
						if ((s->Policy->MaxMac != 0 || s->Policy->NoBridge) && (s->IsOpenVPNL3Session == false))
						{
							UINT i, num_mac_for_me = 0;
							UINT limited_count;
							MAC_TABLE_ENTRY **pp;
							UINT num_pp;

							pp = (MAC_TABLE_ENTRY **)HashListToArray(hub->MacHashTable, &num_pp);

							// Examine a number of MAC addresses that are registered in this current session
							for (i = 0;i < num_pp;i++)
							{
								MAC_TABLE_ENTRY *e = pp[i];
								if (e->Session == s)
								{
									num_mac_for_me++;
								}
							}

							Free(pp);

							limited_count = 0xffffffff;
							if (s->Policy->NoBridge)
							{
								limited_count = MIN(limited_count, MAC_MIN_LIMIT_COUNT);
							}
							if (s->Policy->MaxMac != 0)
							{
								limited_count = MIN(limited_count, s->Policy->MaxMac);
							}
							limited_count = MAX(limited_count, MAC_MIN_LIMIT_COUNT);

							if (num_mac_for_me >= limited_count)
							{
								// Number of MAC addresses that are registered already exceeds the upper limit
								char mac_str[64];

								if (s != NULL)
								{
									MacToStr(mac_str, sizeof(mac_str), packet->MacAddressSrc);
									if (s->Policy->NoBridge)
									{
										if (no_heavy == false)
										{
											HLog(hub, "LH_BRIDGE_LIMIT", s->Name, mac_str, num_mac_for_me, limited_count);
										}
									}
									else
									{
										if (no_heavy == false)
										{
											HLog(hub, "LH_MAC_LIMIT", s->Name, mac_str, num_mac_for_me, limited_count);
										}
									}
								}

								goto DISCARD_PACKET;	// Drop the packet
							}
						}

						if (HASH_LIST_NUM(hub->MacHashTable) >= MAX_MAC_TABLES)
						{
							// Number of MAC addresses exceeded, discard the packet
							goto DISCARD_PACKET;
						}

						entry = ZeroMalloc(sizeof(MAC_TABLE_ENTRY));
						entry->HubPa = (HUB_PA *)s->PacketAdapter->Param;
						Copy(entry->MacAddress, packet->MacAddressSrc, 6);
						if (hub->Option->NoManageVlanId == false)
						{
							entry->VlanId = packet->VlanId;
						}
						else
						{
							entry->VlanId = 0;
						}
						entry->Session = s;
						entry->UpdatedTime = entry->CreatedTime = now;

						AddHash(hub->MacHashTable, entry);

						if (hub->Option->NoMacAddressLog == false)
						{
							// Debug display
							char mac_address[32];

							if (s != NULL)
							{
								if (no_heavy == false)
								{
									MacToStr(mac_address, sizeof(mac_address), packet->MacAddressSrc);
	//								Debug("Register MAC Address %s to Session %X.\n", mac_address, s);

									if (packet->VlanId == 0)
									{
										HLog(hub, "LH_MAC_REGIST", s->Name, mac_address);
									}
									else
									{
										HLog(hub, "LH_MAC_REGIST_VLAN", s->Name, mac_address, packet->VlanId);
									}
								}
							}
						}
					}
					else
					{
						if (entry->Session == s)
						{
							// Do not do anything because it is already registered
							entry->UpdatedTime = now;
						}
						else
						{
							// Read the value of the policy CheckMac
							bool check_mac = s->Policy->CheckMac;

							if (check_mac == false)
							{
								if (s->BridgeMode)
								{
									// Enable the CheckMac policy for the local bridge session forcibly
									check_mac = true;

									if (hub->Option != NULL && hub->Option->DisableCheckMacOnLocalBridge)
									{
										// Disable if DisableCheckMacOnLocalBridge option is set
										check_mac = false;
									}
								}
							}

							// It's already registered and it's in another session
							if (check_mac && (Cmp(packet->MacAddressSrc, hub->HubMacAddr, 6) != 0) &&
								((entry->UpdatedTime + MAC_TABLE_EXCLUSIVE_TIME) >= now))
							{
								UCHAR *mac = packet->MacAddressSrc;
								if (hub->Option != NULL && hub->Option->FixForDLinkBPDU &&
									(mac[0] == 0x00 && mac[1] == 0x80 && mac[2] == 0xc8 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00) ||
									(mac[0] == 0x00 && mac[1] == 0x0d && mac[2] == 0x88 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00))
								{
									// Measures for D-Link. Spanning tree packet of D-Link is sent from the above address. 
									//CheckMac options for the local bridge may cause an adverse effect. So process this exceptionally.
									UCHAR hash[MD5_SIZE];
									UINT64 tick_diff = Tick64() - s->LastDLinkSTPPacketSendTick;

									Md5(hash, packet->PacketData, packet->PacketSize);

									if ((s->LastDLinkSTPPacketSendTick != 0) &&
										(tick_diff < 750ULL) &&
										(Cmp(hash, s->LastDLinkSTPPacketDataHash, MD5_SIZE) == 0))
									{
										// Discard if the same packet sent before 750ms ago
										Debug("D-Link Discard %u\n", (UINT)tick_diff);
										goto DISCARD_PACKET;	// Drop the packet
									}
									else
									{
										goto UPDATE_FDB;
									}
								}
								else
								{
									if (0)
									{
										// If the CheckMac policy-enabled, owning same
										// MAC address by other sessions are prohibited
										// (If the second byte is 0xAE, don't perform this check)
										char mac_address[32];
										BinToStr(mac_address, sizeof(mac_address), packet->MacAddressSrc, 6);
									}
								}

								goto DISCARD_PACKET;	// Drop the packet
							}
							else
							{
								// Rewrite the session of MAC address table and the HUB_PA
								char mac_address[32];
UPDATE_FDB:
								BinToStr(mac_address, sizeof(mac_address), packet->MacAddressSrc, 6);

								entry->Session = s;
								entry->HubPa = (HUB_PA *)s->PacketAdapter->Param;
								entry->UpdatedTime = entry->CreatedTime = now;

								if (1)
								{
									// Debug display
									char mac_address[32];

									if (s != NULL)
									{
										if (no_heavy == false)
										{
											MacToStr(mac_address, sizeof(mac_address), packet->MacHeader->SrcAddress);
											Debug("Register MAC Address %s to Session %X.\n", mac_address, s);
											if (packet->VlanId == 0)
											{
												HLog(hub, "LH_MAC_REGIST", s->Name, mac_address);
											}
											else
											{
												HLog(hub, "LH_MAC_REGIST_VLAN", s->Name, mac_address, packet->VlanId);
											}
										}
									}
								}
							}
						}
					}
				}

				broadcast_mode = false;
				dest_pa = NULL;
				dest_session = NULL;

				if (packet->BroadcastPacket)
				{
					// Broadcast packet
					broadcast_mode = true;
				}
				else
				{
					// Examine whether the destination MAC address is registered in the table
					Copy(t.MacAddress, packet->MacAddressDest, 6);
					if (hub->Option->NoManageVlanId == false)
					{
						t.VlanId = packet->VlanId;
					}
					else
					{
						t.VlanId = 0;
					}
					entry = SearchHash(hub->MacHashTable, &t);

					if (entry == NULL)
					{
						// Broadcast because the destination isn't found
						broadcast_mode = true;
					}
					else
					{
						if (entry->Session != s)
						{
							// Destination is found
							dest_pa = entry->HubPa;
							dest_session = entry->Session;
						}
						else
						{
							// Bad packet whose destination is its own
							goto DISCARD_PACKET;
						}
					}
				}

				if (s != NULL && hub->Option->NoIpTable == false)
				{
					if (packet->TypeL3 == L3_IPV6)
					{
						// IPv6 packet
						IP ip;
						bool b = true;
						UINT ip_type;
						bool dhcp_or_ra = false;

						IPv6AddrToIP(&ip, &packet->L3.IPv6Header->SrcAddress);
						ip_type = GetIPv6AddrType(&packet->L3.IPv6Header->SrcAddress);

						if (!(ip_type & IPV6_ADDR_UNICAST))
						{
							// Multicast address
							b = false;
						}
						else if ((ip_type & IPV6_ADDR_LOOPBACK) || (ip_type & IPV6_ADDR_ZERO))
						{
							// Loop-back address or all-zero address
							b = false;
						}

						if (packet->TypeL4 == L4_ICMPV6)
						{
							if (packet->ICMPv6HeaderPacketInfo.Type == 133 ||
								packet->ICMPv6HeaderPacketInfo.Type == 134)
							{
								// ICMPv6 RS/RA
								dhcp_or_ra = true;
							}
						}
						else if (packet->TypeL4 == L4_UDP)
						{
							if (Endian16(packet->L4.UDPHeader->DstPort) == 546 ||
								Endian16(packet->L4.UDPHeader->DstPort) == 547)
							{
								// DHCPv6
								dhcp_or_ra = true;
							}
						}

						if (IsHubMacAddress(packet->MacAddressSrc) &&
							IsHubIpAddress64(&packet->L3.IPv6Header->SrcAddress))
						{
							// The source address of the Virtual HUB for polling
							b = false;
						}

						if (b)
						{
							// Other than ICMPv6 RS/RA nor DHCPv6 packet
							IP_TABLE_ENTRY t, *e;

							Copy(&t.Ip, &ip, sizeof(IP));

							// Check whether it is registered to an existing table
							e = Search(hub->IpTable, &t);

							if (e == NULL)
							{
								// Register since it is not registered
								if (s->Policy->NoRoutingV6 || s->Policy->MaxIPv6 != 0)
								{
									UINT i, num_ip_for_me = 0;
									UINT limited_count = 0xffffffff;

									for (i = 0;i < LIST_NUM(hub->IpTable);i++)
									{
										IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);

										if (e->Session == s)
										{
											if (IsIP6(&e->Ip))
											{
												num_ip_for_me++;
											}
										}
									}

									if (s->Policy->NoRoutingV6)
									{
										limited_count = MIN(limited_count, IP_LIMIT_WHEN_NO_ROUTING_V6);
									}
									if (s->Policy->MaxIPv6 != 0)
									{
										limited_count = MIN(limited_count, s->Policy->MaxIPv6);
									}
									limited_count = MAX(limited_count, IP_MIN_LIMIT_COUNT_V6);

									if (dhcp_or_ra)
									{
										limited_count = 0xffffffff;
									}

									if (num_ip_for_me >= limited_count)
									{
										// Discard the packet because it exceeded the
										// upper limit of the IP address that can be used
										char tmp[64];
										IPToStr(tmp, sizeof(tmp), &ip);
										if (s->Policy->NoRoutingV6 == false)
										{
											if (no_heavy == false)
											{
												HLog(hub, "LH_IP_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
											}
										}
										else
										{
											if (no_heavy == false)
											{
												HLog(hub, "LH_ROUTING_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
											}
										}
										goto DISCARD_PACKET;
									}
								}

								if (IsIPManagementTargetForHUB(&ip, hub))
								{
									// Create a entry
									e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));
									e->CreatedTime = e->UpdatedTime = now;
									e->DhcpAllocated = false;
									Copy(&e->Ip, &ip, sizeof(IP));
									Copy(e->MacAddress, packet->MacAddressSrc, 6);
									e->Session = s;

									DeleteExpiredIpTableEntry(hub->IpTable);

									if (LIST_NUM(hub->IpTable) >= MAX_IP_TABLES)
									{
										// Delete old IP table entries
										DeleteOldIpTableEntry(hub->IpTable);
									}

									Insert(hub->IpTable, e);

									if (0)
									{
										char ip_address[64];
										IPToStr(ip_address, sizeof(ip_address), &ip);
										Debug("Registered IP Address %s to Session %X.\n",
											ip_address, s);
									}
								}
							}
							else
							{
								if (e->Session == s)
								{
									// Do not do anything because it is self session
									// Renew updated time
									e->UpdatedTime = now;
									Copy(e->MacAddress, packet->MacAddressSrc, 6);
								}
								else
								{
									// Another session was using this IP address before
									if ((s->Policy->CheckIPv6) &&
										((e->UpdatedTime + IP_TABLE_EXCLUSIVE_TIME) >= now))
									{
										// Discard the packet because another session uses this IP address
										char ip_address[32];
										char mac_str[48];
										IPToStr(ip_address, sizeof(ip_address), &ip);

										Debug("IP Address %s is Already used by Session %X.\n",
											ip_address, s);

										MacToStr(mac_str, sizeof(mac_str), e->MacAddress);

										if (no_heavy == false)
										{
											HLog(hub, "LH_IP_CONFLICT", s->Name, ip_address, e->Session->Name, mac_str,
												e->CreatedTime, e->UpdatedTime, e->DhcpAllocated, now);
										}

										goto DISCARD_PACKET;
									}
								}
							}
						}
					}
				}

				if (
					(s != NULL) &&
					(hub->Option->NoIpTable == false) &&
					(
						(packet->TypeL3 == L3_IPV4 ||
							(packet->TypeL3 == L3_ARPV4 && packet->L3.ARPv4Header->HardwareSize == 6 &&
							Endian16(packet->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
							packet->L3.ARPv4Header->ProtocolSize == 4 &&
							Endian16(packet->L3.ARPv4Header->ProtocolType) == 0x0800)
						) &&
						(packet->TypeL7 != L7_DHCPV4)
					)
					) // Other than DHCP packets
				{
					// In the case of the ARP response packet or the IP packet, search in the IP address table
					IP_TABLE_ENTRY t, *e;
					IP ip;
					UINT uint_ip = 0;

					if (packet->TypeL3 == L3_IPV4)
					{
						uint_ip = packet->L3.IPv4Header->SrcIP;
					}
					else if (packet->TypeL3 == L3_ARPV4)
					{
						uint_ip = packet->L3.ARPv4Header->SrcIP;
					}

					if (uint_ip != 0 && uint_ip != 0xffffffff && !(IsHubIpAddress32(uint_ip) && IsHubMacAddress(packet->MacAddressSrc)))
					{
						UINTToIP(&ip, uint_ip);
						Copy(&t.Ip, &ip, sizeof(IP));

						// Check whether it is registered to an existing table
						e = Search(hub->IpTable, &t);

						if (e == NULL)
						{
							// Register since it is not registered
							if (s->Policy->DHCPForce)
							{
								char ipstr[MAX_SIZE];

								// Discard the packet because this IP address isn't
								// assigned by the DHCP server
								IPToStr32(ipstr, sizeof(ipstr), uint_ip);
								if (no_heavy == false)
								{
									HLog(hub, "LH_DHCP_FORCE", s->Name, ipstr);
								}
								goto DISCARD_PACKET;
							}

	//						if (packet->TypeL3 == L3_ARPV4)
							{
								// Examine the number that are registered in this session already
								if (s->Policy->NoRouting || s->Policy->MaxIP != 0)
								{
									UINT i, num_ip_for_me = 0;
									UINT limited_count = 0xffffffff;

									for (i = 0;i < LIST_NUM(hub->IpTable);i++)
									{
										IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);

										if (e->Session == s)
										{
											if (IsIP4(&e->Ip))
											{
												num_ip_for_me++;
											}
										}
									}

									if (s->Policy->NoRouting)
									{
										limited_count = MIN(limited_count, IP_MIN_LIMIT_COUNT);
									}
									if (s->Policy->MaxIP != 0)
									{
										limited_count = MIN(limited_count, s->Policy->MaxIP);
									}
									limited_count = MAX(limited_count, IP_MIN_LIMIT_COUNT);

									if (num_ip_for_me >= limited_count)
									{
										// Discard the packet because it exceeded the
										// upper limit of the IP address that can be used
										char tmp[64];
										IPToStr32(tmp, sizeof(tmp), uint_ip);
										if (s->Policy->NoRouting == false)
										{
											if (no_heavy == false)
											{
												HLog(hub, "LH_IP_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
											}
										}
										else
										{
											if (no_heavy == false)
											{
												HLog(hub, "LH_ROUTING_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
											}
										}
										goto DISCARD_PACKET;
									}
								}

								if (IsIPManagementTargetForHUB(&ip, hub))
								{
									// Create a entry
									e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));
									e->CreatedTime = e->UpdatedTime = now;
									e->DhcpAllocated = false;
									Copy(&e->Ip, &ip, sizeof(IP));
									Copy(e->MacAddress, packet->MacAddressSrc, 6);
									e->Session = s;

									DeleteExpiredIpTableEntry(hub->IpTable);

									if (LIST_NUM(hub->IpTable) >= MAX_IP_TABLES)
									{
										// Delete old IP table entries
										DeleteOldIpTableEntry(hub->IpTable);
									}

									Insert(hub->IpTable, e);

									if (0)
									{
										char ip_address[64];
										IPToStr(ip_address, sizeof(ip_address), &ip);
										Debug("Registered IP Address %s to Session %X.\n",
											ip_address, s);
									}
								}
							}
						}
						else
						{
							if (e->Session == s)
							{
								// Do not do anything because it is self session
								// Renew update time
								e->UpdatedTime = now;
								Copy(e->MacAddress, packet->MacAddressSrc, 6);
							}
							else
							{
								// Another session was using this IP address before
								if ((s->Policy->CheckIP || s->Policy->DHCPForce) &&
									((e->UpdatedTime + IP_TABLE_EXCLUSIVE_TIME) >= now))
								{
									// Discard the packet because another session uses
									// this IP address
									char ip_address[32];
									char mac_str[48];
									IPToStr(ip_address, sizeof(ip_address), &ip);

									Debug("IP Address %s is Already used by Session %X.\n",
										ip_address, s);

									MacToStr(mac_str, sizeof(mac_str), e->MacAddress);

									if (no_heavy == false)
									{
										HLog(hub, "LH_IP_CONFLICT", s->Name, ip_address, e->Session->Name, mac_str,
											e->CreatedTime, e->UpdatedTime, e->DhcpAllocated, now);
									}

									goto DISCARD_PACKET;
								}

								if (s->Policy->DHCPForce)
								{
									if (e->DhcpAllocated == false)
									{
										char ipstr[MAX_SIZE];

										// Discard the packet because this IP address
										// isn't assigned by the DHCP server
										IPToStr32(ipstr, sizeof(ipstr), uint_ip);
										if (no_heavy == false)
										{
											HLog(hub, "LH_DHCP_FORCE", s->Name, ipstr);
										}
										goto DISCARD_PACKET;
									}
								}

								// Overwrite the entry
								e->Session = s;
								e->UpdatedTime = now;
								Copy(e->MacAddress, packet->MacAddressSrc, 6);
							}
						}
					}
				}

				if (s != NULL && broadcast_mode)
				{
					// Calling Broadcast Storm avoidance algorithm
					// in order to prevent occurrence of a broadcast packet loop
					// or a large number of broadcast
					if (CheckBroadcastStorm(hub, s, packet) == false)
					{
						goto DISCARD_PACKET;
					}
				}

				// Broadcast this packet to the monitor port of the HUB
				if (hub->MonitorList->num_item != 0)
				{
					LockList(hub->MonitorList);
					{
						UINT i;
						void *data;
						UINT size = packet->PacketSize;
						for (i = 0;i < LIST_NUM(hub->MonitorList);i++)
						{
							SESSION *monitor_session = (SESSION *)LIST_DATA(hub->MonitorList, i);

							// Flood the packet
							if (monitor_session->PacketAdapter->Param != NULL)
							{
								data = MallocFast(size);
								Copy(data, packet->PacketData, size);
								StorePacketToHubPa((HUB_PA *)monitor_session->PacketAdapter->Param,
									s, data, size, packet, false, false);
							}
						}
					}
					UnlockList(hub->MonitorList);
				}

				if (broadcast_mode == false)
				{
					// Unicast packet
					if (dest_pa != NULL)
					{
						if (dest_session->Policy->NoIPv6DefaultRouterInRA ||
							(dest_session->Policy->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session) ||
							(hub->Option->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session))
						{
							DeleteIPv6DefaultRouterInRA(packet);
						}
						if (dest_session->Policy->RSandRAFilter)
						{
							if (packet->TypeL3 == L3_IPV6 &&
								packet->TypeL4 == L4_ICMPV6 &&
								(packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
								 packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->DHCPFilter)
						{
							if (packet->TypeL3 == L3_IPV4 &&
								packet->TypeL4 == L4_UDP &&
								packet->TypeL7 == L7_DHCPV4)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->DHCPv6Filter)
						{
							if (packet->TypeL3 == L3_IPV6 &&
								packet->TypeL4 == L4_UDP &&
								(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->ArpDhcpOnly)
						{
							if (packet->BroadcastPacket)
							{
								bool b = true;

								if (packet->TypeL3 == L3_IPV4 &&
									packet->TypeL4 == L4_UDP &&
									packet->TypeL7 == L7_DHCPV4)
								{
									b = false;
								}
								else if (packet->TypeL3 == L3_ARPV4)
								{
									b = false;
								}
								else if (packet->TypeL3 == L3_IPV6 &&
									packet->TypeL4 == L4_UDP &&
									(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
								{
									b = false;
								}
								else if (packet->TypeL3 == L3_IPV6 &&
									packet->TypeL4 == L4_ICMPV6)
								{
									b = false;
								}

								if (b)
								{
									goto DISCARD_UNICAST_PACKET;
								}
							}
						}
						if (dest_session->Policy->FilterIPv4)
						{
							if (packet->TypeL3 == L3_IPV4 || packet->TypeL3 == L3_ARPV4)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->FilterIPv6)
						{
							if (packet->TypeL3 == L3_IPV6)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->FilterNonIP)
						{
							if (packet->TypeL3 != L3_IPV4 && packet->TypeL3 != L3_ARPV4 && packet->TypeL3 != L3_IPV6)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}

						if (s != NULL &&
							((drop_broadcast_packet_privacy || packet->BroadcastPacket == false) &&
							s->Policy->PrivacyFilter &&
							dest_session->Policy->PrivacyFilter)
							)
						{
							// Privacy filter
							if (drop_arp_packet_privacy || packet->TypeL3 != L3_ARPV4)
							{
								// Do not block sessions owned by the same user, if the corresponding option is enabled.
								if (allow_same_user_packet_privacy == false || StrCmp(s->Username, dest_session->Username))
								{
									goto DISCARD_UNICAST_PACKET;
								}
							}
						}

						if (s != NULL)
						{
							if (Cmp(packet->MacAddressSrc, s->Hub->HubMacAddr, 6) == 0 ||
								Cmp(packet->MacAddressDest, s->Hub->HubMacAddr, 6) == 0)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}

						// Take a packet log
						if (s != NULL)
						{
							if (PacketLog(s->Hub, s, dest_session, packet, now) == false)
							{
								// The packet drops because it have exceeded the allowable amount
								goto DISCARD_UNICAST_PACKET;
							}
						}

						// Store to the destination HUB_PA
						StorePacketToHubPa(dest_pa, s, packet->PacketData, packet->PacketSize, packet, false, false);
					}
					else
					{
DISCARD_UNICAST_PACKET:
						Free(packet->PacketData);
					}
				}
				else
				{
					// Flooding as a broadcast packet
					UINT current_tcp_queue_size = 0;

					// Take a packet log
					if (s != NULL)
					{
						if (PacketLog(s->Hub, s, NULL, packet, now) == false)
						{
							// The packet drops because It have exceeded the allowable amount
							goto DISCARD_BROADCAST_PACKET;
						}
					}

					// Store for all sessions
					LockList(hub->SessionList);
					{
						UINT i, num = LIST_NUM(hub->SessionList);
						for (i = 0;i < num;i++)
						{
							SESSION *dest_session = LIST_DATA(hub->SessionList, i);
							HUB_PA *dest_pa = (HUB_PA *)dest_session->PacketAdapter->Param;
							bool discard = false;

							if (dest_session != s)
							{
								bool delete_default_router_in_ra = false;

								if (dest_session->IsMonitorMode)
								{
									discard = true;
								}

								if (dest_session->NormalClient)
								{
									if (dormant_interval != 0)
									{
										if (dest_session->LastCommTimeForDormant == 0 ||
											(dest_session->LastCommTimeForDormant + dormant_interval) < now)
										{
											// This is dormant session
											discard = true;
										}
									}
								}

								if (tcp_queue_quota != 0)
								{
									current_tcp_queue_size = CedarGetCurrentTcpQueueSize(hub->Cedar);

									if (current_tcp_queue_size >= tcp_queue_quota)
									{
										// Quota exceeded. Discard the packet for normal session.
										if (dest_session->Connection != NULL &&
											dest_session->Connection->Protocol == CONNECTION_TCP)
										{
											discard = true;
										}

										if (dest_session->LinkModeServer)
										{
											LINK *k = dest_session->Link;

											discard = true;
										}
									}
								}

								if (dest_session->VLanId != 0 && packet->TypeL3 == L3_TAGVLAN &&
									packet->VlanId != dest_session->VLanId)
								{
									discard = true;
								}

								if (dest_session->Policy->NoIPv6DefaultRouterInRA ||
									(dest_session->Policy->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session) ||
									(hub->Option->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session))
								{
									if (packet->TypeL3 == L3_IPV6 && packet->TypeL4 == L4_ICMPV6 &&
										(packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
									{
										if (packet->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime != 0)
										{
											delete_default_router_in_ra = true;
										}
									}
								}
								if (dest_session->Policy->RSandRAFilter)
								{
									if (packet->TypeL3 == L3_IPV6 &&
										packet->TypeL4 == L4_ICMPV6 &&
										(packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
										 packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
									{
										discard = true;
									}
								}

								if (dest_session->Policy->DHCPFilter)
								{
									if (packet->TypeL3 == L3_IPV4 &&
										packet->TypeL4 == L4_UDP &&
										packet->TypeL7 == L7_DHCPV4)
									{
										discard = true;
									}
								}

								if (dest_session->Policy->DHCPv6Filter)
								{
									if (packet->TypeL3 == L3_IPV6 &&
										packet->TypeL4 == L4_UDP &&
										(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
									{
										discard = true;
									}
								}

								if (dest_session->Policy->ArpDhcpOnly)
								{
									if (packet->BroadcastPacket)
									{
										bool b = true;

										if (packet->TypeL3 == L3_IPV4 &&
											packet->TypeL4 == L4_UDP &&
											packet->TypeL7 == L7_DHCPV4)
										{
											b = false;
										}
										else if (packet->TypeL3 == L3_ARPV4)
										{
											b = false;
										}
										else if (packet->TypeL3 == L3_IPV6 &&
											packet->TypeL4 == L4_UDP &&
											(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
										{
											b = false;
										}
										else if (packet->TypeL3 == L3_IPV6 &&
											packet->TypeL4 == L4_ICMPV6)
										{
											b = false;
										}

										if (discard == false)
										{
											discard = b;
										}
									}
								}

								if (dest_session->Policy->FilterIPv4)
								{
									if (packet->TypeL3 == L3_IPV4 || packet->TypeL3 == L3_ARPV4)
									{
										discard = true;
									}
								}
								if (dest_session->Policy->FilterIPv6)
								{
									if (packet->TypeL3 == L3_IPV6)
									{
										discard = true;
									}
								}
								if (dest_session->Policy->FilterNonIP)
								{
									if (packet->TypeL3 != L3_IPV4 && packet->TypeL3 != L3_ARPV4 && packet->TypeL3 != L3_IPV6)
									{
										discard = true;
									}
								}

								if (s != NULL &&
									((drop_broadcast_packet_privacy || packet->BroadcastPacket == false) &&
									s->Policy->PrivacyFilter &&
									dest_session->Policy->PrivacyFilter)
									)
								{
									// Privacy filter
									if (drop_arp_packet_privacy || packet->TypeL3 != L3_ARPV4)
									{
										// Do not block sessions owned by the same user, if the corresponding option is enabled.
										if (allow_same_user_packet_privacy == false || StrCmp(s->Username, dest_session->Username))
										{
											discard = true;
										}
									}
								}

								if (s != NULL)
								{
									if (Cmp(packet->MacAddressSrc, s->Hub->HubMacAddr, 6) == 0 ||
										Cmp(packet->MacAddressDest, s->Hub->HubMacAddr, 6) == 0)
									{
										discard = true;
									}
								}

								if (discard == false && dest_pa != NULL)
								{
									if (s == NULL ||
										ApplyAccessListToForwardPacket(s->Hub, s, dest_pa->Session, packet))
									{
										// Store in session other than its own
										data = MallocFast(packet->PacketSize);
										Copy(data, packet->PacketData, packet->PacketSize);
										size = packet->PacketSize;

										if (delete_default_router_in_ra)
										{
											PKT *pkt2 = ParsePacket(data, size);

											DeleteIPv6DefaultRouterInRA(pkt2);

											FreePacket(pkt2);
										}

										StorePacketToHubPa(dest_pa, s, data, size, packet, true, true);
									}
								}
							}
						}
					}
					UnlockList(hub->SessionList);

DISCARD_BROADCAST_PACKET:
					Free(packet->PacketData);
				}
				FreePacket(packet);
			}
		}
	}
	UnlockHashList(hub->MacHashTable);
}

// Examine the maximum number of logging target packets per minute
bool CheckMaxLoggedPacketsPerMinute(SESSION *s, UINT max_packets, UINT64 now)
{
	UINT64 minute = 60 * 1000;
	// Validate arguments
	if (s == NULL || max_packets == 0)
	{
		return true;
	}

	if ((s->Policy != NULL && s->Policy->NoBroadcastLimiter) ||
		s->SecureNATMode || s->BridgeMode || s->LinkModeServer || s->LinkModeClient ||
		s->L3SwitchMode)
	{
		return true;
	}

	if (s->MaxLoggedPacketsPerMinuteStartTick == 0 ||
		((s->MaxLoggedPacketsPerMinuteStartTick + minute) <= now))
	{
		s->MaxLoggedPacketsPerMinuteStartTick = now;
		s->CurrentNumPackets = 0;
	}

	s->CurrentNumPackets++;
	if (s->CurrentNumPackets > max_packets)
	{
		return false;
	}

	return true;
}

// Confirm whether the specified IP address is managed by Virtual HUB
bool IsIPManagementTargetForHUB(IP *ip, HUB *hub)
{
	// Validate arguments
	if (ip == NULL || hub == NULL)
	{
		return false;
	}

	if (hub->Option == NULL)
	{
		return true;
	}

	if (IsIP4(ip))
	{
		if (hub->Option->ManageOnlyPrivateIP)
		{
			if (IsIPPrivate(ip) == false)
			{
				return false;
			}
		}
	}
	else
	{
		if (hub->Option->ManageOnlyLocalUnicastIPv6)
		{
			UINT ip_type = GetIPAddrType6(ip);

			if (!(ip_type & IPV6_ADDR_LOCAL_UNICAST))
			{
				return false;
			}
		}
	}

	return true;
}

// Delete old IP table entries
void DeleteOldIpTableEntry(LIST *o)
{
	UINT i;
	IP_TABLE_ENTRY *old = NULL;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(o, i);
		old = e;
	}

	if (old != NULL)
	{
		Delete(o, old);
		Free(old);
	}
}


// Add to Storm list
STORM *AddStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict)
{
	STORM *s;
	// Validate arguments
	if (pa == NULL || mac_address == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(STORM));
	if (src_ip != NULL)
	{
		Copy(&s->SrcIp, src_ip, sizeof(IP));
	}
	if (dest_ip != NULL)
	{
		Copy(&s->DestIp, dest_ip, sizeof(IP));
	}
	Copy(s->MacAddress, mac_address, 6);
	s->StrictMode = strict;

	Insert(pa->StormList, s);

	return s;
}

// Search in Storm list
STORM *SearchStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict)
{
	STORM t, *s;
	// Validate arguments
	if (pa == NULL || mac_address == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	if (src_ip != NULL)
	{
		Copy(&t.SrcIp, src_ip, sizeof(IP));
	}
	if (dest_ip != NULL)
	{
		Copy(&t.DestIp, dest_ip, sizeof(IP));
	}
	Copy(t.MacAddress, mac_address, 6);

	t.StrictMode = strict;

	s = Search(pa->StormList, &t);

	return s;
}

// Store the packet to destination HUB_PA
void StorePacketToHubPa(HUB_PA *dest, SESSION *src, void *data, UINT size, PKT *packet, bool is_flooding, bool no_check_acl)
{
	BLOCK *b;
	// Validate arguments
	if (dest == NULL || data == NULL)
	{
		return;
	}

	if (size < 14)
	{
		Free(data);
		return;
	}

	if (no_check_acl == false)
	{
		if (src != NULL)
		{
			// Apply the access list for forwarding
			if (ApplyAccessListToForwardPacket(src->Hub, src, dest->Session, packet) == false)
			{
				Free(data);
				return;
			}
		}
	}

	if (src != NULL)
	{
		if (dest->Session->Policy->MaxDownload != 0)
		{
			// Traffic limit
			if (packet != NULL && IsMostHighestPriorityPacket(dest->Session, packet) == false)
			{
				TRAFFIC_LIMITER *tr = &dest->DownloadLimiter;
				IntoTrafficLimiter(tr, packet);

				if ((tr->Value * (UINT64)1000 / (UINT64)LIMITER_SAMPLING_SPAN) > dest->Session->Policy->MaxDownload)
				{
					// Limit
					Free(data);
					return;
				}
			}
		}
	}

	if (packet != NULL && src != NULL && src->Hub != NULL && src->Hub->Option != NULL && src->Hub->Option->FixForDLinkBPDU)
	{
		// Measures for D-Link bug
		UCHAR *mac = packet->MacAddressSrc;
		if ((mac[0] == 0x00 && mac[1] == 0x80 && mac[2] == 0xc8 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00) ||
			(mac[0] == 0x00 && mac[1] == 0x0d && mac[2] == 0x88 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00))
		{
			SESSION *session = dest->Session;

			if (session != NULL)
			{
				if (session->Policy != NULL && session->Policy->CheckMac)
				{
					UCHAR hash[MD5_SIZE];
					Md5(hash, packet->PacketData, packet->PacketSize);

					Copy(session->LastDLinkSTPPacketDataHash, hash, MD5_SIZE);
					session->LastDLinkSTPPacketSendTick = Tick64();
				}
			}
		}
	}

	// Remove the VLAN tag
	if (dest->Session != NULL && dest->Session->VLanId != 0)
	{
		UINT vlan_tpid = 0;
		if (src != NULL && src->Hub != NULL && src->Hub->Option != NULL)
		{
			vlan_tpid = src->Hub->Option->VlanTypeId;
		}
		if (VLanRemoveTag(&data, &size, dest->Session->VLanId, vlan_tpid) == false)
		{
			Free(data);
			return;
		}
	}

	if (src != NULL && dest->Session != NULL && src->Hub != NULL && src->Hub->Option != NULL)
	{
		if (dest->Session->AdjustMss != 0 ||
			(dest->Session->UseUdpAcceleration && dest->Session->UdpAccelMss != 0) ||
			(dest->Session->IsRUDPSession && dest->Session->RUdpMss != 0))
		{
			if (src->Hub->Option->DisableAdjustTcpMss == false)
			{
				UINT target_mss = INFINITE;
				
				if (dest->Session->AdjustMss != 0)
				{
					target_mss = MIN(target_mss, dest->Session->AdjustMss);
				}

				if (dest->Session->UseUdpAcceleration && dest->Session->UdpAccelMss != 0)
				{
					target_mss = MIN(target_mss, dest->Session->UdpAccelMss);
				}
				else if (dest->Session->IsRUDPSession && dest->Session->RUdpMss != 0)
				{
					target_mss = MIN(target_mss, dest->Session->RUdpMss);
				}

				// Processing of Adjust TCP MSS
				if (target_mss != INFINITE)
				{
					AdjustTcpMssL2(data, size, target_mss, src->Hub->Option->VlanTypeId);
				}
			}
		}
	}

	// Create a block
	b = NewBlock(data, size, 0);

	LockQueue(dest->PacketQueue);
	{
		// Measure the length of queue
		if (dest->PacketQueue->num_item < MAX_STORED_QUEUE_NUM)
		{
			// Store
			InsertQueue(dest->PacketQueue, b);

			if (is_flooding)
			{
				if (src != NULL)
				{
					b->IsFlooding = true;
					CedarAddCurrentTcpQueueSize(src->Cedar, b->Size);
				}
			}
		}
		else
		{
			// Drop the packet
			FreeBlock(b);
		}
	}
	UnlockQueue(dest->PacketQueue);

	// Issue of cancellation
	if (src != NULL)
	{
		AddCancelList(src->CancelList, dest->Cancel);
	}
	else
	{
		Cancel(dest->Cancel);
	}
}

// Remove the default router specification from the IPv6 router advertisement
bool DeleteIPv6DefaultRouterInRA(PKT *p)
{
	if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
		(p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
	{
		if (p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime != 0)
		{
			p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime = 0;

			p->L4.ICMPHeader->Checksum = 0;
			p->L4.ICMPHeader->Checksum =
				CalcChecksumForIPv6(&p->L3.IPv6Header->SrcAddress,
					&p->L3.IPv6Header->DestAddress, IP_PROTO_ICMPV6,
					p->L4.ICMPHeader, p->IPv6HeaderPacketInfo.PayloadSize, 0);
		}
	}

	return false;
}

// Packet filter by policy
bool StorePacketFilterByPolicy(SESSION *s, PKT *p)
{
	POLICY *pol;
	HUB *hub;
	bool no_heavy = false;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return false;
	}

	hub = s->Hub;

	if (hub != NULL && hub->Option != NULL)
	{
		no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;
	}

	// Policy
	pol = s->Policy;

	// To prohibit the operation as a server
	if (pol->NoServer)
	{
		if (p->TypeL3 == L3_IPV4)
		{
			if (p->TypeL4 == L4_TCP)
			{
				UCHAR flag = p->L4.TCPHeader->Flag;
				if ((flag & TCP_SYN) && (flag & TCP_ACK))
				{
					char ip1[64], ip2[64];
					// Not to send a SYN + ACK packet
					Debug("pol->NoServer: Discard SYN+ACK Packet.\n");

					IPToStr32(ip1, sizeof(ip1), p->L3.IPv4Header->SrcIP);
					IPToStr32(ip2, sizeof(ip2), p->L3.IPv4Header->DstIP);

					if (no_heavy == false)
					{
						HLog(s->Hub, "LH_NO_SERVER", s->Name, ip2, p->L4.TCPHeader->DstPort,
							ip1, p->L4.TCPHeader->SrcPort);
					}

					return false;
				}
			}
		}
	}

	// Prohibit the operation as a server (IPv6)
	if (pol->NoServerV6)
	{
		if (p->TypeL3 == L3_IPV6)
		{
			if (p->TypeL4 == L4_TCP)
			{
				UCHAR flag = p->L4.TCPHeader->Flag;
				if ((flag & TCP_SYN) && (flag & TCP_ACK))
				{
					char ip1[128], ip2[128];
					// Not to send a SYN + ACK packet
					Debug("pol->NoServerV6: Discard SYN+ACK Packet.\n");

					IP6AddrToStr(ip1, sizeof(ip1), &p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress);
					IP6AddrToStr(ip2, sizeof(ip2), &p->IPv6HeaderPacketInfo.IPv6Header->DestAddress);

					if (no_heavy == false)
					{
						HLog(s->Hub, "LH_NO_SERVER", s->Name, ip2, p->L4.TCPHeader->DstPort,
							ip1, p->L4.TCPHeader->SrcPort);
					}

					return false;
				}
			}
		}
	}

	// Allow broadcast only DHCP and ARP
	if (pol->ArpDhcpOnly && p->BroadcastPacket)
	{
		bool ok = false;

		if (p->TypeL3 == L3_ARPV4)
		{
			ok = true;
		}
		if (p->TypeL3 == L3_IPV4)
		{
			if (p->TypeL4 == L4_UDP)
			{
				if (p->TypeL7 == L7_DHCPV4)
				{
					ok = true;
				}
			}
		}
		if (p->TypeL3 == L3_IPV6)
		{
			if (p->TypeL4 == L4_ICMPV6)
			{
				ok = true;
			}
		}

		if (p->TypeL3 == L3_IPV6 &&
			p->TypeL4 == L4_UDP &&
			(Endian16(p->L4.UDPHeader->DstPort) == 546 || Endian16(p->L4.UDPHeader->DstPort) == 547))
		{
			ok = true;
		}

		if (ok == false)
		{
			return false;
		}
	}

	// Filter IPv4 packets
	if (pol->FilterIPv4)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x0800 || proto == 0x0806)
			{
				return false;
			}
		}
	}

	// Filter IPv6 packets
	if (pol->FilterIPv6)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x86dd)
			{
				return false;
			}
		}
	}

	// Filter non-IP packets
	if (pol->FilterNonIP)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (!(proto == 0x86dd || proto == 0x0800 || proto == 0x0806))
			{
				return false;
			}
		}
	}

	// Filter DHCP packets
	if (pol->DHCPFilter)
	{
		if (p->TypeL3 == L3_IPV4 &&
			p->TypeL4 == L4_UDP &&
			p->TypeL7 == L7_DHCPV4)
		{
			// Discard the DHCP packet
			Debug("pol->DHCPFilter: Discard DHCP Packet.\n");

			return false;
		}
	}

	// DHCPv6 packet filtering
	if (pol->DHCPv6Filter)
	{
		if (p->TypeL3 == L3_IPV6 &&
			p->TypeL4 == L4_UDP)
		{
			if (Endian16(p->L4.UDPHeader->DstPort) == 546 ||
				Endian16(p->L4.UDPHeader->DstPort) == 547)
			{
				// Discard the DHCPv6 packet
				Debug("pol->DHCPv6Filter: Discard DHCPv6 Packet.\n");

				return false;
			}
		}
	}

	// The behavior as a DHCP server is prohibited
	if (pol->DHCPNoServer)
	{
		if (p->TypeL3 == L3_IPV4 &&
			p->TypeL4 == L4_UDP &&
			p->TypeL7 == L7_DHCPV4)
		{
			DHCPV4_HEADER *h = p->L7.DHCPv4Header;
			if (h->OpCode == 2)
			{
				char ip1[64], ip2[64];

				// Discard the DHCP packet
				IPToStr32(ip1, sizeof(ip1), p->L3.IPv4Header->SrcIP);
				IPToStr32(ip2, sizeof(ip2), p->L3.IPv4Header->DstIP);

				if (no_heavy == false)
				{
					HLog(s->Hub, "LH_NO_DHCP", s->Name, ip1, ip2);
				}

				// Discard the DHCP response packet
				Debug("pol->DHCPNoServer: Discard DHCP Response Packet.\n");
				return false;
			}
		}
	}

	// The behavior as a DHCPv6 server is prohibited
	if (pol->DHCPv6NoServer)
	{
		if (p->TypeL3 == L3_IPV6 &&
			p->TypeL4 == L4_UDP &&
			(Endian16(p->L4.UDPHeader->DstPort) == 546 || Endian16(p->L4.UDPHeader->SrcPort) == 547))
		{
			char ip1[128], ip2[128];

			// Discard the DHCP packet
			IP6AddrToStr(ip1, sizeof(ip1), &p->L3.IPv6Header->SrcAddress);
			IP6AddrToStr(ip2, sizeof(ip2), &p->L3.IPv6Header->DestAddress);

			if (no_heavy == false)
			{
				HLog(s->Hub, "LH_NO_DHCP", s->Name, ip1, ip2);
			}

			// Discard the DHCP response packet
			Debug("pol->DHCPv6NoServer: Discard DHCPv6 Response Packet.\n");
			return false;
		}
	}

	// Filter the Router Solicitation / Advertising packet (IPv6)
	if (pol->RSandRAFilter)
	{
		if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
			(p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
			 p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
		{
			return false;
		}
	}

	// Filter the router advertisement packet (IPv6)
	if (pol->RAFilter)
	{
		if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
			p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT)
		{
			return false;
		}
	}

	// Register to the IP table by recording the DHCP response packet
	if (p->TypeL3 == L3_IPV4 &&
		p->TypeL4 == L4_UDP &&
		p->TypeL7 == L7_DHCPV4 &&
		(s->Hub != NULL && s->Hub->Option->NoIpTable == false))
	{
		DHCPV4_HEADER *h = p->L7.DHCPv4Header;
		if (h->OpCode == 2 && p->DhcpOpCode == DHCP_ACK)
		{
			// Register to the IP table by peeking the contents of the DHCP response packet
			if (h->HardwareType == ARP_HARDWARE_TYPE_ETHERNET)
			{
				if (h->HardwareAddressSize == 6)
				{
					if (h->YourIP != 0 && h->YourIP != 0xffffffff)
					{
						UINT ip_uint = h->YourIP;
						IP ip;
						IP_TABLE_ENTRY *e, t;
						MAC_TABLE_ENTRY *mac_table, mt;
						mt.VlanId = 0;
						Copy(&mt.MacAddress, &h->ClientMacAddress, 6);
						mac_table = SearchHash(hub->MacHashTable, &mt);

						if (mac_table != NULL)
						{
							bool new_entry = true;
							UINTToIP(&ip, ip_uint);
							Copy(&t.Ip, &ip, sizeof(IP));

							e = Search(hub->IpTable, &t);
							if (e == NULL)
							{
								// Register as a new item
								e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));
UPDATE_DHCP_ALLOC_ENTRY:
								e->CreatedTime = e->UpdatedTime = Tick64();
								e->DhcpAllocated = true;
								Copy(&e->Ip, &ip, sizeof(IP));
								e->Session = mac_table->Session;
								Copy(e->MacAddress, p->MacAddressDest, 6);

								if (new_entry)
								{
									// Delete the expired IP table entries
									DeleteExpiredIpTableEntry(hub->IpTable);
									if (LIST_NUM(hub->IpTable) >= MAX_IP_TABLES)
									{
										// Remove old entries
										DeleteOldIpTableEntry(hub->IpTable);
									}
									Insert(hub->IpTable, e);

								
									if ((hub->Option != NULL && hub->Option->NoDhcpPacketLogOutsideHub == false) || mac_table->Session != s)
									{
										char dhcp_mac_addr[64];
										char dest_mac_addr[64];
										char dest_ip_addr[64];
										char server_ip_addr[64];
										MacToStr(dhcp_mac_addr, sizeof(dhcp_mac_addr), p->MacAddressSrc);
										MacToStr(dest_mac_addr, sizeof(dest_mac_addr), h->ClientMacAddress);
										IPToStr(dest_ip_addr, sizeof(dest_ip_addr), &ip);
										IPToStr32(server_ip_addr, sizeof(server_ip_addr), p->L3.IPv4Header->SrcIP);
										Debug("DHCP Allocated; dhcp server: %s, client: %s, new_ip: %s\n",
											dhcp_mac_addr, dest_mac_addr, dest_ip_addr);

										if (no_heavy == false)
										{
											HLog(s->Hub, "LH_REGIST_DHCP", s->Name, dhcp_mac_addr, server_ip_addr,
												mac_table->Session->Name, dest_mac_addr, dest_ip_addr);
										}
									}
								}
							}
							else
							{
								// Update
								new_entry = false;
								goto UPDATE_DHCP_ALLOC_ENTRY;
							}
						}
					}
				}
			}
		}
	}

	return true;
}

// Delete the expired MAC table entries
void DeleteExpiredMacTableEntry(HASH_LIST *h)
{
	LIST *o2;
	UINT i;
	MAC_TABLE_ENTRY **pp;
	UINT num;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	o2 = NewListFast(NULL);

	pp = (MAC_TABLE_ENTRY **)HashListToArray(h, &num);

	for (i = 0;i < num;i++)
	{
		MAC_TABLE_ENTRY *e = pp[i];
		if ((e->UpdatedTime + (UINT64)MAC_TABLE_EXPIRE_TIME) <= Tick64())
		{
			Add(o2, e);
		}
	}

	for (i = 0;i < LIST_NUM(o2);i++)
	{
		MAC_TABLE_ENTRY *e = LIST_DATA(o2, i);
		DeleteHash(h, e);
		Free(e);
	}

	ReleaseList(o2);

	Free(pp);
}

// Delete the expired IP table entries
void DeleteExpiredIpTableEntry(LIST *o)
{
	LIST *o2;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	o2 = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(o, i);
		if ((e->UpdatedTime + (UINT64)(e->DhcpAllocated ? IP_TABLE_EXPIRE_TIME_DHCP : IP_TABLE_EXPIRE_TIME)) <= Tick64())
		{
			Add(o2, e);
		}
	}

	for (i = 0;i < LIST_NUM(o2);i++)
	{
		IP_TABLE_ENTRY *e = LIST_DATA(o2, i);
		Delete(o, e);
		Free(e);
	}

	ReleaseList(o2);
}

// Determine whether the packet to be handled with priority
bool IsMostHighestPriorityPacket(SESSION *s, PKT *p)
{
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return false;
	}

	if (p->TypeL3 == L3_ARPV4)
	{
		// ARP packets
		return true;
	}

	if (p->TypeL3 == L3_IPV4)
	{
		if (p->TypeL4 == L4_ICMPV4)
		{
			// ICMP packets
			return true;
		}

		if (p->TypeL4 == L4_TCP)
		{
			if ((p->L4.TCPHeader->Flag & TCP_SYN) || (p->L4.TCPHeader->Flag & TCP_FIN)
				|| (p->L4.TCPHeader->Flag & TCP_RST))
			{
				// SYN, FIN, RST packet
				return true;
			}
		}

		if (p->TypeL4 == L4_UDP)
		{
			if (p->TypeL7 == L7_DHCPV4)
			{
				// DHCP packets
				return true;
			}
		}
	}

	return false;
}

// Add a packet to traffic limiter
void IntoTrafficLimiter(TRAFFIC_LIMITER *tr, PKT *p)
{
	UINT64 now = Tick64();
	// Validate arguments
	if (tr == NULL || p == NULL)
	{
		return;
	}

	if (tr->LastTime == 0 || tr->LastTime > now ||
		(tr->LastTime + LIMITER_SAMPLING_SPAN) < now)
	{
		// Sampling initialization
		tr->Value = 0;
		tr->LastTime = now;
	}

	// Value increase
	tr->Value += (UINT64)p->PacketSize * (UINT64)8;
}

// The bandwidth reduction by traffic limiter
bool StorePacketFilterByTrafficLimiter(SESSION *s, PKT *p)
{
	HUB_PA *pa;
	TRAFFIC_LIMITER *tr;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return false;
	}

	if (s->Policy->MaxUpload == 0)
	{
		// Unlimited
		return true;
	}

	pa = (HUB_PA *)s->PacketAdapter->Param;
	tr = &pa->UploadLimiter;

	// Restrictions are not applied for priority packets
	if (IsMostHighestPriorityPacket(s, p))
	{
		return true;
	}

	// Input packets to the limiter
	IntoTrafficLimiter(tr, p);

	// Compare the current bandwidth and limit value
	if ((tr->Value * (UINT64)1000 / (UINT64)LIMITER_SAMPLING_SPAN) > s->Policy->MaxUpload)
	{
		// Discard the packet
		return false;
	}

	return true;
}

// Filtering of packets to store
bool StorePacketFilter(SESSION *s, PKT *packet)
{
	// Validate arguments
	if (s == NULL || packet == NULL)
	{
		return false;
	}

	// The bandwidth reduction by traffic limiter
	if (StorePacketFilterByTrafficLimiter(s, packet) == false)
	{
		return false;
	}

	// Packet filter by policy
	if (StorePacketFilterByPolicy(s, packet) == false)
	{
		return false;
	}

	// The packet filter with Access Lists
	if (ApplyAccessListToStoredPacket(s->Hub, s, packet) == false)
	{
		return false;
	}

	return true;
}

// Get the packet adapter for the HUB
PACKET_ADAPTER *GetHubPacketAdapter()
{
	// Hand over by creating a function list
	PACKET_ADAPTER *pa = NewPacketAdapter(HubPaInit,
		HubPaGetCancel, HubPaGetNextPacket, HubPaPutPacket, HubPaFree);

	return pa;
}

// Stop all the SESSION of the HUB
void StopAllSession(HUB *h)
{
	SESSION **s;
	UINT i, num;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		num = LIST_NUM(h->SessionList);
		s = ToArray(h->SessionList);
		DeleteAll(h->SessionList);
	}
	UnlockList(h->SessionList);

	for (i = 0;i < num;i++)
	{
		StopSession(s[i]);
		ReleaseSession(s[i]);
	}

	Free(s);
}

// Remove the SESSION from HUB
void DelSession(HUB *h, SESSION *s)
{
	// Validate arguments
	if (h == NULL || s == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		if (Delete(h->SessionList, s))
		{
			Debug("Session %s was Deleted from %s.\n", s->Name, h->Name);
			ReleaseSession(s);
		}
	}
	UnlockList(h->SessionList);
}

// Add a SESSION to the HUB
void AddSession(HUB *h, SESSION *s)
{
	// Validate arguments
	if (h == NULL || s == NULL)
	{
		return;
	}

	LockList(h->SessionList);
	{
		Insert(h->SessionList, s);
		AddRef(s->ref);
		Debug("Session %s Inserted to %s.\n", s->Name, h->Name);

		if (s->InProcMode)
		{
			s->UniqueId = GetNewUniqueId(h);
		}
	}
	UnlockList(h->SessionList);
}

// Create a new unique ID of the HUB
UINT GetNewUniqueId(HUB *h)
{
	UINT id;
	// Validate arguments
	if (h == NULL)
	{
		return 0;
	}

	for (id = 1;;id++)
	{
		if (SearchSessionByUniqueId(h, id) == NULL)
		{
			return id;
		}
	}
}

// Search for a session by the unique session ID
SESSION *SearchSessionByUniqueId(HUB *h, UINT id)
{
	UINT i;
	// Validate arguments
	if (h == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(h->SessionList);i++)
	{
		SESSION *s = LIST_DATA(h->SessionList, i);

		if (s->UniqueId == id)
		{
			return s;
		}
	}

	return NULL;
}

// Stop the operation of the HUB
void StopHub(HUB *h)
{
	bool old_status = false;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	old_status = h->Offline;
	h->HubIsOnlineButHalting = true;

	SetHubOffline(h);

	if (h->Halt == false)
	{
		SLog(h->Cedar, "LS_HUB_STOP", h->Name);
		h->Halt = true;
	}

	h->Offline = old_status;
	h->HubIsOnlineButHalting = false;
}

// Online the Virtual HUB
void SetHubOnline(HUB *h)
{
	bool for_cluster = false;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	if (h->Cedar->Server != NULL && h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		if (h->Type == HUB_TYPE_FARM_DYNAMIC)
		{
			for_cluster = true;
		}
	}

	Lock(h->lock_online);
	{
		if (h->Offline == false)
		{
			Unlock(h->lock_online);
			return;
		}
		HLog(h, "LH_ONLINE");

		// Start all links
		StartAllLink(h);

		// Start the SecureNAT
		if (h->EnableSecureNAT)
		{
			if (h->SecureNAT == NULL)
			{
				if (for_cluster == false)
				{
					h->SecureNAT = SnNewSecureNAT(h, h->SecureNATOption);
				}
			}
		}

		// Start all of the local bridges that is associated with this HUB
		if (h->Type != HUB_TYPE_FARM_DYNAMIC)
		{
			LockList(h->Cedar->LocalBridgeList);
			{
				UINT i;
				for (i = 0;i < LIST_NUM(h->Cedar->LocalBridgeList);i++)
				{
					LOCALBRIDGE *br = LIST_DATA(h->Cedar->LocalBridgeList, i);

					if (StrCmpi(br->HubName, h->Name) == 0)
					{
						if (br->Bridge == NULL)
						{
							br->Bridge = BrNewBridge(h, br->DeviceName, NULL, br->Local, br->Monitor,
								br->TapMode, br->TapMacAddress, br->LimitBroadcast, br);
						}
					}
				}
			}
			UnlockList(h->Cedar->LocalBridgeList);
		}

		h->Offline = false;
	}
	Unlock(h->lock_online);

	if (h->Cedar->Server != NULL)
	{
		SiHubOnlineProc(h);
	}
}

// Offline the Virtual HUB
void SetHubOffline(HUB *h)
{
	UINT i;
	bool for_cluster = false;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	if (h->Cedar->Server != NULL && h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		if (h->Type == HUB_TYPE_FARM_DYNAMIC)
		{
			for_cluster = true;
		}
	}

	h->BeingOffline = true;

	Lock(h->lock_online);
	{
		if (h->Offline || h->Halt)
		{
			Unlock(h->lock_online);
			h->BeingOffline = false;
			return;
		}

		HLog(h, "LH_OFFLINE");

		// Stop all links
		StopAllLink(h);

		// Stop the SecureNAT
		SnFreeSecureNAT(h->SecureNAT);
		h->SecureNAT = NULL;

		// Stop all the local bridges that is associated with this HUB
		LockList(h->Cedar->LocalBridgeList);
		{
			for (i = 0;i < LIST_NUM(h->Cedar->LocalBridgeList);i++)
			{
				LOCALBRIDGE *br = LIST_DATA(h->Cedar->LocalBridgeList, i);

				if (StrCmpi(br->HubName, h->Name) == 0)
				{
					BrFreeBridge(br->Bridge);
					br->Bridge = NULL;
				}
			}
		}
		UnlockList(h->Cedar->LocalBridgeList);

		// Offline
		h->Offline = true;

		// Disconnect all sessions
		StopAllSession(h);
	}
	Unlock(h->lock_online);

	h->BeingOffline = false;

	if (h->Cedar->Server != NULL)
	{
		SiHubOfflineProc(h);
	}
}

// Get whether a HUB which have the specified name exists
bool IsHub(CEDAR *cedar, char *name)
{
	HUB *h;
	// Validate arguments
	if (cedar == NULL || name == NULL)
	{
		return false;
	}

	h = GetHub(cedar, name);
	if (h == NULL)
	{
		return false;
	}

	ReleaseHub(h);

	return true;
}

// Get the HUB
HUB *GetHub(CEDAR *cedar, char *name)
{
	HUB *h, t;
	// Validate arguments
	if (cedar == NULL || name == NULL)
	{
		return NULL;
	}

	LockHubList(cedar);

	t.Name = name;
	h = Search(cedar->HubList, &t);
	if (h == NULL)
	{
		UnlockHubList(cedar);
		return NULL;
	}

	AddRef(h->ref);

	UnlockHubList(cedar);

	return h;
}

// Lock the HUB list
void LockHubList(CEDAR *cedar)
{
	// Validate arguments
	if (cedar == NULL)
	{
		return;
	}

	LockList(cedar->HubList);
}

// Unlock the HUB list
void UnlockHubList(CEDAR *cedar)
{
	// Validate arguments
	if (cedar == NULL)
	{
		return;
	}

	UnlockList(cedar->HubList);
}

// Release the HUB
void ReleaseHub(HUB *h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	if (Release(h->ref) == 0)
	{
		CleanupHub(h);
	}
}

// Get the Radius server information
bool GetRadiusServer(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size)
{
	UINT interval;
	return GetRadiusServerEx(hub, name, size, port, secret, secret_size, &interval);
}
bool GetRadiusServerEx(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size, UINT *interval)
{
	return GetRadiusServerEx2(hub, name, size, port, secret, secret_size, interval, NULL, 0);
}
bool GetRadiusServerEx2(HUB *hub, char *name, UINT size, UINT *port, char *secret, UINT secret_size, UINT *interval, char *suffix_filter, UINT suffix_filter_size)
{
	bool ret = false;
	// Validate arguments
	if (hub == NULL || name == NULL || port == NULL || secret == NULL || interval == NULL)
	{
		return false;
	}

	Lock(hub->RadiusOptionLock);
	{
		if (hub->RadiusServerName != NULL)
		{
			char *tmp;
			UINT tmp_size;
			StrCpy(name, size, hub->RadiusServerName);
			*port = hub->RadiusServerPort;
			*interval = hub->RadiusRetryInterval;

			tmp_size = hub->RadiusSecret->Size + 1;
			tmp = ZeroMalloc(tmp_size);
			Copy(tmp, hub->RadiusSecret->Buf, hub->RadiusSecret->Size);
			StrCpy(secret, secret_size, tmp);
			Free(tmp);

			if (suffix_filter != NULL)
			{
				StrCpy(suffix_filter, suffix_filter_size, hub->RadiusSuffixFilter);
			}

			ret = true;
		}
	}
	Unlock(hub->RadiusOptionLock);

	return ret;
}

// Set the Radius server information
void SetRadiusServer(HUB *hub, char *name, UINT port, char *secret)
{
	SetRadiusServerEx(hub, name, port, secret, RADIUS_RETRY_INTERVAL);
}
void SetRadiusServerEx(HUB *hub, char *name, UINT port, char *secret, UINT interval)
{
	// Validate arguments
	if (hub == NULL)
	{
		return;
	}

	Lock(hub->RadiusOptionLock);
	{
		if (hub->RadiusServerName != NULL)
		{
			Free(hub->RadiusServerName);
		}

		if (name == NULL)
		{
			hub->RadiusServerName = NULL;
			hub->RadiusServerPort = 0;
			hub->RadiusRetryInterval = RADIUS_RETRY_INTERVAL;
			FreeBuf(hub->RadiusSecret);
		}
		else
		{
			hub->RadiusServerName = CopyStr(name);
			hub->RadiusServerPort = port;
			if (interval == 0)
			{
				hub->RadiusRetryInterval = RADIUS_RETRY_INTERVAL;
			}
			else if (interval > RADIUS_RETRY_TIMEOUT)
			{
				hub->RadiusRetryInterval = RADIUS_RETRY_TIMEOUT;
			}
			else
			{
				hub->RadiusRetryInterval = interval;
			}
			FreeBuf(hub->RadiusSecret);

			if (secret == NULL)
			{
				hub->RadiusSecret = NewBuf();
			}
			else
			{
				hub->RadiusSecret = NewBuf();
				WriteBuf(hub->RadiusSecret, secret, StrLen(secret));
				SeekBuf(hub->RadiusSecret, 0, 0);
			}
		}
	}
	Unlock(hub->RadiusOptionLock);
}

// Add the traffic information for Virtual HUB
void IncrementHubTraffic(HUB *h)
{
	TRAFFIC t;
	// Validate arguments
	if (h == NULL || h->FarmMember == false)
	{
		return;
	}

	Zero(&t, sizeof(t));

	Lock(h->TrafficLock);
	{
		t.Send.BroadcastBytes =
			h->Traffic->Send.BroadcastBytes - h->OldTraffic->Send.BroadcastBytes;
		t.Send.BroadcastCount =
			h->Traffic->Send.BroadcastCount - h->OldTraffic->Send.BroadcastCount;
		t.Send.UnicastBytes =
			h->Traffic->Send.UnicastBytes - h->OldTraffic->Send.UnicastBytes;
		t.Send.UnicastCount =
			h->Traffic->Send.UnicastCount - h->OldTraffic->Send.UnicastCount;
		t.Recv.BroadcastBytes =
			h->Traffic->Recv.BroadcastBytes - h->OldTraffic->Recv.BroadcastBytes;
		t.Recv.BroadcastCount =
			h->Traffic->Recv.BroadcastCount - h->OldTraffic->Recv.BroadcastCount;
		t.Recv.UnicastBytes =
			h->Traffic->Recv.UnicastBytes - h->OldTraffic->Recv.UnicastBytes;
		t.Recv.UnicastCount =
			h->Traffic->Recv.UnicastCount - h->OldTraffic->Recv.UnicastCount;
		Copy(h->OldTraffic, h->Traffic, sizeof(TRAFFIC));
	}
	Unlock(h->TrafficLock);

	if (IsZero(&t, sizeof(TRAFFIC)))
	{
		return;
	}

	AddTrafficDiff(h, h->Name, TRAFFIC_DIFF_HUB, &t);
}

// Adding Traffic information
void AddTrafficDiff(HUB *h, char *name, UINT type, TRAFFIC *traffic)
{
	TRAFFIC_DIFF *d;
	// Validate arguments
	if (h == NULL || h->FarmMember == false || name == NULL || traffic == NULL)
	{
		return;
	}

	if (LIST_NUM(h->Cedar->TrafficDiffList) > MAX_TRAFFIC_DIFF)
	{
		return;
	}

	d = ZeroMallocFast(sizeof(TRAFFIC_DIFF));
	d->HubName = CopyStr(h->Name);
	d->Name = CopyStr(name);
	d->Type = type;
	Copy(&d->Traffic, traffic, sizeof(TRAFFIC));

	LockList(h->Cedar->TrafficDiffList);
	{
		Insert(h->Cedar->TrafficDiffList, d);
	}
	UnlockList(h->Cedar->TrafficDiffList);
}

// Cleanup of HUB
void CleanupHub(HUB *h)
{
	UINT i;
	char name[MAX_SIZE];
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	StrCpy(name, sizeof(name), h->Name);

	if (h->WatchDogStarted)
	{
		StopHubWatchDog(h);
	}

	FreeAccessList(h);

	if (h->RadiusServerName != NULL)
	{
		Free(h->RadiusServerName);
		FreeBuf(h->RadiusSecret);
	}
	ReleaseAllLink(h);
	DeleteHubDb(h->HubDb);
	ReleaseCedar(h->Cedar);
	DeleteLock(h->lock);
	DeleteLock(h->lock_online);
	Free(h->Name);
	ReleaseList(h->SessionList);
	ReleaseHashList(h->MacHashTable);
	ReleaseList(h->IpTable);
	ReleaseList(h->MonitorList);
	ReleaseList(h->LinkList);
	DeleteCounter(h->NumSessions);
	DeleteCounter(h->NumSessionsClient);
	DeleteCounter(h->NumSessionsBridge);
	DeleteCounter(h->SessionCounter);
	FreeTraffic(h->Traffic);
	FreeTraffic(h->OldTraffic);
	Free(h->Option);

	Free(h->SecureNATOption);

	DeleteLock(h->TrafficLock);

	for (i = 0;i < LIST_NUM(h->TicketList);i++)
	{
		Free(LIST_DATA(h->TicketList, i));
	}

	ReleaseList(h->TicketList);

	DeleteLock(h->RadiusOptionLock);

	FreeLog(h->PacketLogger);
	FreeLog(h->SecurityLogger);

	for (i = 0;i < LIST_NUM(h->AdminOptionList);i++)
	{
		Free(LIST_DATA(h->AdminOptionList, i));
	}
	ReleaseList(h->AdminOptionList);

	if (h->Msg != NULL)
	{
		Free(h->Msg);
	}

	FreeUserList(h->UserList);

	Free(h);
}

// Comparison function of IP table entries
int CompareIpTable(void *p1, void *p2)
{
	IP_TABLE_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(IP_TABLE_ENTRY **)p1;
	e2 = *(IP_TABLE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	return CmpIpAddr(&e1->Ip, &e2->Ip);
}

// Get hash of MAC table entry
UINT GetHashOfMacTable(void *p)
{
	UINT v;
	MAC_TABLE_ENTRY *e = p;

	if (e == NULL)
	{
		return 0;
	}

	v = e->MacAddress[0] + e->MacAddress[1] + e->MacAddress[2] + 
		e->MacAddress[3] + e->MacAddress[4] + e->MacAddress[5] + 
		e->VlanId;

	return v;
}

// Comparison function of the MAC table entries
int CompareMacTable(void *p1, void *p2)
{
	int r;
	MAC_TABLE_ENTRY *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(MAC_TABLE_ENTRY **)p1;
	e2 = *(MAC_TABLE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	r = Cmp(e1->MacAddress, e2->MacAddress, 6);
	if (r != 0)
	{
		return r;
	}
	if (e1->VlanId > e2->VlanId)
	{
		return 1;
	}
	else if (e1->VlanId < e2->VlanId)
	{
		return -1;
	}
	return 0;
}

// Comparison function of HUB
int CompareHub(void *p1, void *p2)
{
	HUB *h1, *h2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	h1 = *(HUB **)p1;
	h2 = *(HUB **)p2;
	if (h1 == NULL || h2 == NULL)
	{
		return 0;
	}
	return StrCmpi(h1->Name, h2->Name);
}

// Examine whether the MAC address is for the ARP polling of the Virtual HUB
bool IsHubMacAddress(UCHAR *mac)
{
	// Validate arguments
	if (mac == NULL)
	{
		return false;
	}

	if (mac[0] == 0x00 && mac[1] == SE_HUB_MAC_ADDR_SIGN)
	{
		return true;
	}

	return false;
}

// Examine whether the IP address is for the ARP polling of the Virtual HUB
bool IsHubIpAddress32(UINT ip32)
{
	IP ip;

	UINTToIP(&ip, ip32);

	return IsHubIpAddress(&ip);
}
bool IsHubIpAddress(IP *ip)
{
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	if (ipv4[0] == 172 && ipv4[1] == 31)
	{
		if (ipv4[2] >= 1 && ipv4[2] <= 254)
		{
			if (ipv4[3] >= 1 && ipv4[3] <= 254)
			{
				return true;
			}
		}
	}

	return false;
}
bool IsHubIpAddress64(IPV6_ADDR *addr)
{
	// Validate arguments
	if (addr == NULL)
	{
		return false;
	}

	if (addr->Value[0] == 0xfe && addr->Value[1] == 0x80 &&
		addr->Value[2] == 0 &&
		addr->Value[3] == 0 &&
		addr->Value[4] == 0 &&
		addr->Value[5] == 0 &&
		addr->Value[6] == 0 &&
		addr->Value[7] == 0 &&
		addr->Value[8] == 0x02 && addr->Value[9] == 0xae && 
		addr->Value[11] == 0xff && addr->Value[12] == 0xfe)
	{
		return true;
	}

	return false;
}

// Generate an IP address for the Virtual HUB
void GenHubIpAddress(IP *ip, char *name)
{
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (ip == NULL || name == NULL)
	{
		return;
	}

	StrCpy(tmp1, sizeof(tmp1), name);
	Trim(tmp1);
	GenerateMachineUniqueHash(hash);
	BinToStr(tmp2, sizeof(tmp2), hash, sizeof(hash));
	StrCat(tmp2, sizeof(tmp2), tmp1);
	StrUpper(tmp2);

	Sha0(hash, tmp2, StrLen(tmp2));

	SetIP(ip, 172, 31, hash[0] % 254 + 1, hash[0] % 254 + 1);
}

// Generate a MAC address for the Virtual HUB
void GenHubMacAddress(UCHAR *mac, char *name)
{
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (mac == NULL || name == NULL)
	{
		return;
	}

	StrCpy(tmp1, sizeof(tmp1), name);
	Trim(tmp1);
	GenerateMachineUniqueHash(hash);
	BinToStr(tmp2, sizeof(tmp2), hash, sizeof(hash));
	StrCat(tmp2, sizeof(tmp2), tmp1);
	StrUpper(tmp2);

	Sha0(hash, tmp2, StrLen(tmp2));

	mac[0] = 0x00;
	mac[1] = SE_HUB_MAC_ADDR_SIGN;
	mac[2] = hash[0];
	mac[3] = hash[1];
	mac[4] = hash[2];
	mac[5] = hash[3];
}

// Get a message from HUB
wchar_t *GetHubMsg(HUB *h)
{
	wchar_t *ret = NULL;
	// Validate arguments
	if (h == NULL)
	{
		return NULL;
	}

	Lock(h->lock);
	{
		if (h->Msg != NULL)
		{
			ret = CopyUniStr(h->Msg);
		}
	}
	Unlock(h->lock);

	return ret;
}

// Set a message to the HUB
void SetHubMsg(HUB *h, wchar_t *msg)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	Lock(h->lock);
	{
		if (h->Msg != NULL)
		{
			Free(h->Msg);
			h->Msg = NULL;
		}

		if (UniIsEmptyStr(msg) == false)
		{
			h->Msg = UniCopyStr(msg);
		}
	}
	Unlock(h->lock);
}

// Creating a new HUB
HUB *NewHub(CEDAR *cedar, char *HubName, HUB_OPTION *option)
{
	HUB *h;
	char packet_logger_name[MAX_SIZE];
	char tmp[MAX_SIZE];
	char safe_hub_name[MAX_HUBNAME_LEN + 1];
	UCHAR hash[SHA1_SIZE];
	IP ip6;
	// Validate arguments
	if (cedar == NULL || option == NULL || HubName == NULL)
	{
		return NULL;
	}

	h = ZeroMalloc(sizeof(HUB));
	Sha0(h->HashedPassword, "", 0);
	HashPassword(h->SecurePassword, ADMINISTRATOR_USERNAME, "");
	h->lock = NewLock();
	h->lock_online = NewLock();
	h->ref = NewRef();
	h->Cedar = cedar;
	AddRef(h->Cedar->ref);
	h->Type = HUB_TYPE_STANDALONE;

	ConvertSafeFileName(safe_hub_name, sizeof(safe_hub_name), HubName);
	h->Name = CopyStr(safe_hub_name);


	h->AdminOptionList = NewList(CompareAdminOption);
	AddHubAdminOptionsDefaults(h, true);

	h->LastCommTime = SystemTime64();
	h->LastLoginTime = SystemTime64();
	h->NumLogin = 0;

	h->TrafficLock = NewLock();

	h->HubDb = NewHubDb();

	h->SessionList = NewList(NULL);
	h->SessionCounter = NewCounter();
	h->NumSessions = NewCounter();
	h->NumSessionsClient = NewCounter();
	h->NumSessionsBridge = NewCounter();
	h->MacHashTable = NewHashList(GetHashOfMacTable, CompareMacTable, 8, false);
	h->IpTable = NewList(CompareIpTable);
	h->MonitorList = NewList(NULL);
	h->LinkList = NewList(NULL);

	h->Traffic = NewTraffic();
	h->OldTraffic = NewTraffic();

	h->Option = ZeroMalloc(sizeof(HUB_OPTION));
	Copy(h->Option, option, sizeof(HUB_OPTION));

	if (h->Option->VlanTypeId == 0)
	{
		h->Option->VlanTypeId = MAC_PROTO_TAGVLAN;
	}

	h->Option->DropBroadcastsInPrivacyFilterMode = true;
	h->Option->DropArpInPrivacyFilterMode = true;
	h->Option->AllowSameUserInPrivacyFilterMode = false;

	Rand(h->HubSignature, sizeof(h->HubSignature));

	// SecureNAT related
	h->EnableSecureNAT = false;
	h->SecureNAT = NULL;
	h->SecureNATOption = ZeroMalloc(sizeof(VH_OPTION));
	NiSetDefaultVhOption(NULL, h->SecureNATOption);

	if (h->Cedar != NULL && h->Cedar->Server != NULL && h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		NiClearUnsupportedVhOptionForDynamicHub(h->SecureNATOption, true);
	}

	// Generate a temporary MAC address for the HUB
	GenerateMachineUniqueHash(hash);
	GenHubMacAddress(h->HubMacAddr, h->Name);
	GenHubIpAddress(&h->HubIp, h->Name);

	// IPv6 address for the HUB
	GenerateEui64LocalAddress(&ip6, h->HubMacAddr);
	IPToIPv6Addr(&h->HubIpV6, &ip6);

	h->RadiusOptionLock = NewLock();
	h->RadiusServerPort = RADIUS_DEFAULT_PORT;

	h->TicketList = NewList(NULL);

	InitAccessList(h);

	// Create a user list
	h->UserList = NewUserList();

	// Default logging settings
	h->LogSetting.SavePacketLog = h->LogSetting.SaveSecurityLog = true;
	h->LogSetting.PacketLogConfig[PACKET_LOG_TCP_CONN] =
		h->LogSetting.PacketLogConfig[PACKET_LOG_DHCP] = PACKET_LOG_HEADER;
	h->LogSetting.SecurityLogSwitchType = LOG_SWITCH_DAY;
	h->LogSetting.PacketLogSwitchType = LOG_SWITCH_DAY;

	MakeDir(HUB_SECURITY_LOG_DIR_NAME);
	MakeDir(HUB_PACKET_LOG_DIR_NAME);

	// Start the packet logger
	Format(packet_logger_name, sizeof(packet_logger_name), HUB_PACKET_LOG_FILE_NAME, h->Name);
	h->PacketLogger = NewLog(packet_logger_name, HUB_PACKET_LOG_PREFIX, h->LogSetting.PacketLogSwitchType);

	// Start the security logger
	Format(tmp, sizeof(tmp), HUB_SECURITY_LOG_FILE_NAME, h->Name);
	h->SecurityLogger = NewLog(tmp, HUB_SECURITY_LOG_PREFIX, h->LogSetting.SecurityLogSwitchType);

	if (h->Cedar->Server != NULL && h->Cedar->Server->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		h->FarmMember = true;
	}

	// Start the HUB
	SetHubOnline(h);

	if (h->Cedar->Bridge)
	{
		h->Option->NoArpPolling = true;
	}

	if (h->Option->NoArpPolling == false && h->Option->NoIpTable == false)
	{
		StartHubWatchDog(h);
		h->WatchDogStarted = true;
	}

	SLog(h->Cedar, "LS_HUB_START", h->Name);

	MacToStr(tmp, sizeof(tmp), h->HubMacAddr);
	SLog(h->Cedar, "LS_HUB_MAC", h->Name, tmp);

	return h;
}

// Delete the HUBDB
void DeleteHubDb(HUBDB *d)
{
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	LockList(d->UserList);
	{
		LockList(d->GroupList);
		{
			// Release all users and groups
			UINT i;
			USER **users;
			USERGROUP **groups;

			users = ToArray(d->UserList);
			groups = ToArray(d->GroupList);

			for (i = 0;i < LIST_NUM(d->UserList);i++)
			{
				ReleaseUser(users[i]);
			}
			for (i = 0;i < LIST_NUM(d->GroupList);i++)
			{
				ReleaseGroup(groups[i]);
			}

			Free(users);
			Free(groups);
		}
		UnlockList(d->GroupList);
	}
	UnlockList(d->UserList);

	// Release the root certificate list
	LockList(d->RootCertList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(d->RootCertList);i++)
		{
			X *x = LIST_DATA(d->RootCertList, i);
			FreeX(x);
		}
	}
	UnlockList(d->RootCertList);

	// Release the CRL
	LockList(d->CrlList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(d->CrlList);i++)
		{
			CRL *crl = LIST_DATA(d->CrlList, i);
			FreeCrl(crl);
		}
	}
	UnlockList(d->CrlList);

	// Release the AC list
	FreeAcList(d->AcList);

	ReleaseList(d->GroupList);
	ReleaseList(d->UserList);
	ReleaseList(d->RootCertList);
	ReleaseList(d->CrlList);
	Free(d);
}

// Get a log setting of the HUB
void GetHubLogSetting(HUB *h, HUB_LOG *setting)
{
	// Validate arguments
	if (setting == NULL || h == NULL)
	{
		return;
	}

	Copy(setting, &h->LogSetting, sizeof(HUB_LOG));
}

// Update the log settings of the HUB
void SetHubLogSettingEx(HUB *h, HUB_LOG *setting, bool no_change_switch_type)
{
	UINT i1, i2;
	// Validate arguments
	if (setting == NULL || h == NULL)
	{
		return;
	}

	i1 = h->LogSetting.PacketLogSwitchType;
	i2 = h->LogSetting.SecurityLogSwitchType;

	Copy(&h->LogSetting, setting, sizeof(HUB_LOG));

	if (no_change_switch_type)
	{
		h->LogSetting.PacketLogSwitchType = i1;
		h->LogSetting.SecurityLogSwitchType = i2;
	}

	// Packet logger configuration
	SetLogSwitchType(h->PacketLogger, setting->PacketLogSwitchType);
	SetLogSwitchType(h->SecurityLogger, setting->SecurityLogSwitchType);
}
void SetHubLogSetting(HUB *h, HUB_LOG *setting)
{
	SetHubLogSettingEx(h, setting, false);
}

// Add the trusted root certificate to the HUB
void AddRootCert(HUB *hub, X *x)
{
	HUBDB *db;
	// Validate arguments
	if (hub == NULL || x == NULL)
	{
		return;
	}

	db = hub->HubDb;
	if (db != NULL)
	{
		LockList(db->RootCertList);
		{
			if (LIST_NUM(db->RootCertList) < MAX_HUB_CERTS)
			{
				UINT i;
				bool ok = true;

				for (i = 0;i < LIST_NUM(db->RootCertList);i++)
				{
					X *exist_x = LIST_DATA(db->RootCertList, i);
					if (CompareX(exist_x, x))
					{
						ok = false;
						break;
					}
				}

				if (ok)
				{
					Insert(db->RootCertList, CloneX(x));
				}
			}
		}
		UnlockList(db->RootCertList);
	}
}

// Compare the list of certificates
int CompareCert(void *p1, void *p2)
{
	X *x1, *x2;
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	x1 = *(X **)p1;
	x2 = *(X **)p2;
	if (x1 == NULL || x2 == NULL)
	{
		return 0;
	}

	GetPrintNameFromX(tmp1, sizeof(tmp1), x1);
	GetPrintNameFromX(tmp2, sizeof(tmp2), x2);

	return UniStrCmpi(tmp1, tmp2);
}

// Creating a new HUBDB
HUBDB *NewHubDb()
{
	HUBDB *d = ZeroMalloc(sizeof(HUBDB));

	d->GroupList = NewList(CompareGroupName);
	d->UserList = NewList(CompareUserName);
	d->RootCertList = NewList(CompareCert);
	d->CrlList = NewList(NULL);
	d->AcList = NewAcList();

	return d;
}


