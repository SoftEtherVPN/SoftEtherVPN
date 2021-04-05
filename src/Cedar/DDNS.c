// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// DDNS.c
// Dynamic DNS Client

#include "DDNS.h"

#include "AzureClient.h"
#include "Server.h"
#include "Virtual.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

// Get the current status of the DDNS client
void DCGetStatus(DDNS_CLIENT *c, DDNS_CLIENT_STATUS *st)
{
	// Validate arguments
	if (c == NULL || st == NULL)
	{
		return;
	}

	Zero(st, sizeof(DDNS_CLIENT_STATUS));

	Lock(c->Lock);
	{
		st->Err_IPv4 = c->Err_IPv4;
		st->Err_IPv6 = c->Err_IPv6;

		StrCpy(st->CurrentHostName, sizeof(st->CurrentHostName), c->CurrentHostName);
		StrCpy(st->CurrentFqdn, sizeof(st->CurrentFqdn), c->CurrentFqdn);
		StrCpy(st->DnsSuffix, sizeof(st->DnsSuffix), c->DnsSuffix);
		StrCpy(st->CurrentIPv4, sizeof(st->CurrentIPv4), c->CurrentIPv4);
		StrCpy(st->CurrentIPv6, sizeof(st->CurrentIPv6), c->CurrentIPv6);

		StrCpy(st->CurrentAzureIp, sizeof(st->CurrentAzureIp), c->CurrentAzureIp);
		st->CurrentAzureTimestamp = c->CurrentAzureTimestamp;
		StrCpy(st->CurrentAzureSignature, sizeof(st->CurrentAzureSignature), c->CurrentAzureSignature);
		StrCpy(st->AzureCertHash, sizeof(st->AzureCertHash), c->AzureCertHash);

		Copy(&st->InternetSetting, &c->InternetSetting, sizeof(INTERNET_SETTING));
	}
	Unlock(c->Lock);

	UniStrCpy(st->ErrStr_IPv4, sizeof(st->ErrStr_IPv4), _E(st->Err_IPv4));
	UniStrCpy(st->ErrStr_IPv6, sizeof(st->ErrStr_IPv6), _E(st->Err_IPv6));
}

// Set the Internet settings
void DCSetInternetSetting(DDNS_CLIENT *c, INTERNET_SETTING *t)
{
	// Validate arguments
	if (c == NULL || t == NULL)
	{
		return;
	}

	Copy(&c->InternetSetting, t, sizeof(INTERNET_SETTING));
}

// Get the Internet settings
void DCGetInternetSetting(DDNS_CLIENT *c, INTERNET_SETTING *t)
{
	// Validate arguments
	if (c == NULL || t == NULL)
	{
		return;
	}

	Copy(t, &c->InternetSetting, sizeof(INTERNET_SETTING));
}

// Changing the host name
UINT DCChangeHostName(DDNS_CLIENT *c, char *hostname)
{
	UINT ret;
	DDNS_REGISTER_PARAM p;
	// Validate arguments
	if (c == NULL || hostname == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	if (StrLen(hostname) > 32)
	{
		// The host name is too long
		return ERR_DDNS_HOSTNAME_TOO_LONG;
	}

	Zero(&p, sizeof(p));

	StrCpy(p.NewHostname, sizeof(p.NewHostname), hostname);

	// Use one of IPv4 or IPv6 if it seems to be communication
	if (c->Err_IPv4 == ERR_NO_ERROR)
	{
		// IPv4
		ret = DCRegister(c, false, &p, NULL);
	}
	else if (c->Err_IPv6 == ERR_NO_ERROR)
	{
		// IPv6
		ret = DCRegister(c, true, &p, NULL);
	}
	else
	{
		// Try both
		ret = DCRegister(c, true, &p, NULL);
		if (ret != ERR_NO_ERROR)
		{
			ret = DCRegister(c, false, &p, NULL);
		}
	}

	if (ret == ERR_NO_ERROR)
	{
		DDNS_CLIENT_STATUS st;

		DCGetStatus(c, &st);

		SiApplyAzureConfig(c->Cedar->Server, &st);
	}

	return ret;
}

// DDNS client thread
void DCThread(THREAD *thread, void *param)
{
	DDNS_CLIENT *c;
	INTERRUPT_MANAGER *interrupt;
	UINT last_ip_hash = 0;
	void *route_change_poller = NULL;
	bool last_time_ip_changed = false;
	UINT last_azure_ddns_trigger_int = 0;
	UINT last_vgs_ddns_trigger_int = 0;
	UINT n;
	INTERNET_SETTING last_t;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	c = (DDNS_CLIENT *)param;

	interrupt = NewInterruptManager();

	route_change_poller = NewRouteChange();
	IsRouteChanged(route_change_poller);

	Zero(&last_t, sizeof(last_t));

	n = 0;

	while (c->Halt == false)
	{
		UINT ip_hash = GetHostIPAddressHash32();
		UINT interval;
		UINT64 now = Tick64();
		bool ip_changed = false;
		bool azure_client_triggered = false;
		bool internet_setting_changed = false;
		bool vgs_server_triggered = false;


		if (c->Cedar->Server != NULL && c->Cedar->Server->AzureClient != NULL)
		{
			if (c->Cedar->Server->AzureClient->DDnsTriggerInt != last_azure_ddns_trigger_int)
			{
				azure_client_triggered = true;
				last_azure_ddns_trigger_int = c->Cedar->Server->AzureClient->DDnsTriggerInt;
				last_time_ip_changed = false;
				Debug("DDNS Thread Triggered by AzureClient.\n");
			}
		}

		if (Cmp(&last_t, &c->InternetSetting, sizeof(INTERNET_SETTING)) != 0)
		{
			Copy(&last_t, &c->InternetSetting, sizeof(INTERNET_SETTING));
			internet_setting_changed = true;
			last_time_ip_changed = false;
		}

		if (ip_hash != last_ip_hash)
		{
			last_time_ip_changed = false;
			Debug("DDNS Thread Triggered by IP Hash Changed.\n");
		}

		if ((ip_hash != last_ip_hash) || (IsRouteChanged(route_change_poller)) || azure_client_triggered || internet_setting_changed || vgs_server_triggered)
		{
			if (last_time_ip_changed == false)
			{
				// Call all getting functions from the beginning if the routing
				//  table or the IP address of this host has changed
				c->NextRegisterTick_IPv4 = 0;
				c->NextRegisterTick_IPv6 = 0;
				c->NextGetMyIpTick_IPv4 = 0;
				c->NextGetMyIpTick_IPv6 = 0;

				last_ip_hash = ip_hash;

				last_time_ip_changed = true;

				ip_changed = true;

				Debug("DDNS Internet Condition Changed.\n");
			}
		}
		else
		{
			last_time_ip_changed = false;
		}

		if ((n++) >= 1)
		{
			// Self IPv4 address acquisition
			if (c->NextGetMyIpTick_IPv4 == 0 || now >= c->NextGetMyIpTick_IPv4)
			{
				UINT next_interval;
				char ip[MAX_SIZE];

				Zero(ip, sizeof(ip));
				c->Err_IPv4_GetMyIp = DCGetMyIp(c, false, ip, sizeof(ip), NULL);

				if (c->Err_IPv4_GetMyIp == ERR_NO_ERROR)
				{
					if (StrCmpi(c->LastMyIPv4, ip) != 0)
					{
						ip_changed = true;
						StrCpy(c->LastMyIPv4, sizeof(c->LastMyIPv4), ip);
					}

					next_interval = GenRandInterval(DDNS_GETMYIP_INTERVAL_OK_MIN, DDNS_GETMYIP_INTERVAL_OK_MAX);
				}
				else
				{
					if (IsEmptyStr(c->LastMyIPv4) == false)
					{
						ip_changed = true;
					}

					Zero(c->LastMyIPv4, sizeof(c->LastMyIPv4));
					next_interval = GenRandInterval(DDNS_GETMYIP_INTERVAL_NG_MIN, DDNS_GETMYIP_INTERVAL_NG_MAX);
				}

				c->NextGetMyIpTick_IPv4 = Tick64() + (UINT64)next_interval;

				AddInterrupt(interrupt, c->NextGetMyIpTick_IPv4);
			}

			// Self IPv6 address acquisition
			if (c->NextGetMyIpTick_IPv6 == 0 || now >= c->NextGetMyIpTick_IPv6)
			{
				UINT next_interval;
				char ip[MAX_SIZE];

				Zero(ip, sizeof(ip));
				c->Err_IPv6_GetMyIp = DCGetMyIp(c, true, ip, sizeof(ip), NULL);

				if (c->Err_IPv6_GetMyIp == ERR_NO_ERROR)
				{
					if (StrCmpi(c->LastMyIPv6, ip) != 0)
					{
						ip_changed = true;
						StrCpy(c->LastMyIPv6, sizeof(c->LastMyIPv6), ip);
					}

					next_interval = GenRandInterval(DDNS_GETMYIP_INTERVAL_OK_MIN, DDNS_GETMYIP_INTERVAL_OK_MAX);
				}
				else
				{
					if (IsEmptyStr(c->LastMyIPv6) == false)
					{
						ip_changed = true;
					}

					Zero(c->LastMyIPv6, sizeof(c->LastMyIPv6));
					next_interval = GenRandInterval(DDNS_GETMYIP_INTERVAL_NG_MIN, DDNS_GETMYIP_INTERVAL_NG_MAX);
				}

				c->NextGetMyIpTick_IPv6 = Tick64() + (UINT64)next_interval;

				AddInterrupt(interrupt, c->NextGetMyIpTick_IPv6);
			}
		}

		if (ip_changed)
		{
			c->NextRegisterTick_IPv4 = 0;
			c->NextRegisterTick_IPv6 = 0;
		}

		// IPv4 host registration
		if (c->NextRegisterTick_IPv4 == 0 || now >= c->NextRegisterTick_IPv4)
		{
			UINT next_interval;

			c->Err_IPv4 = DCRegister(c, false, NULL, NULL);

			if (c->Err_IPv4 == ERR_NO_ERROR)
			{
				next_interval = GenRandInterval(DDNS_REGISTER_INTERVAL_OK_MIN, DDNS_REGISTER_INTERVAL_OK_MAX);
			}
			else
			{
				next_interval = GenRandInterval(DDNS_REGISTER_INTERVAL_NG_MIN, DDNS_REGISTER_INTERVAL_NG_MAX);
			}
			//next_interval = 0;

			c->NextRegisterTick_IPv4 = Tick64() + (UINT64)next_interval;

			if (true)
			{
				DDNS_CLIENT_STATUS st;

				DCGetStatus(c, &st);

				SiApplyAzureConfig(c->Cedar->Server, &st);
			}

			AddInterrupt(interrupt, c->NextRegisterTick_IPv4);
		}

		if (c->Halt)
		{
			break;
		}

		// IPv6 host registration
		if (c->NextRegisterTick_IPv6 == 0 || now >= c->NextRegisterTick_IPv6)
		{
			UINT next_interval;

			c->Err_IPv6 = DCRegister(c, true, NULL, NULL);

			if (c->Err_IPv6 == ERR_NO_ERROR)
			{
				next_interval = GenRandInterval(DDNS_REGISTER_INTERVAL_OK_MIN, DDNS_REGISTER_INTERVAL_OK_MAX);
			}
			else
			{
				next_interval = GenRandInterval(DDNS_REGISTER_INTERVAL_NG_MIN, DDNS_REGISTER_INTERVAL_NG_MAX);
			}

			c->NextRegisterTick_IPv6 = Tick64() + (UINT64)next_interval;

			if (true)
			{
				DDNS_CLIENT_STATUS st;

				DCGetStatus(c, &st);

				SiApplyAzureConfig(c->Cedar->Server, &st);
			}

			AddInterrupt(interrupt, c->NextRegisterTick_IPv6);
		}

		interval = GetNextIntervalForInterrupt(interrupt);
		interval = MIN(interval, 1234);

		if (n == 1)
		{
			interval = 0;
		}

		if (c->Halt)
		{
			break;
		}

		if (c->KeyChanged)
		{
			c->KeyChanged = false;
			c->NextRegisterTick_IPv4 = c->NextRegisterTick_IPv6 = 0;

			interval = 0;
		}

		if (last_time_ip_changed)
		{
			if (c->Cedar->Server != NULL && c->Cedar->Server->AzureClient != NULL)
			{
				c->Cedar->Server->AzureClient->IpStatusRevision++;
			}
		}

		Wait(c->Event, interval);
	}

	FreeRouteChange(route_change_poller);
	FreeInterruptManager(interrupt);
}

// Execution of registration
UINT DCRegister(DDNS_CLIENT *c, bool ipv6, DDNS_REGISTER_PARAM *p, char *replace_v6)
{
	char *url;
	char url2[MAX_SIZE];
	char url3[MAX_SIZE];
	PACK *req, *ret;
	char key_str[MAX_SIZE];
	UCHAR machine_key[SHA1_SIZE];
	char machine_key_str[MAX_SIZE];
	char machine_name[MAX_SIZE];
	BUF *cert_hash = NULL;
	UINT err = ERR_INTERNAL_ERROR;
	UCHAR key_hash[SHA1_SIZE];
	char key_hash_str[MAX_SIZE];
	bool use_azure = false;
	char current_azure_ip[MAX_SIZE];
	INTERNET_SETTING t;
	UINT build = 0;
	char add_header_name[64];
	char add_header_value[64];
	// Validate arguments
	if (c == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	Zero(add_header_name, sizeof(add_header_name));
	Zero(add_header_value, sizeof(add_header_value));

	Zero(current_azure_ip, sizeof(current_azure_ip));

	GetCurrentMachineIpProcessHash(machine_key);
	BinToStr(machine_key_str, sizeof(machine_key_str), machine_key, sizeof(machine_key));

	GetMachineHostName(machine_name, sizeof(machine_name));
	StrLower(machine_name);

	if (ipv6 == false)
	{
		url = DDNS_URL_V4_GLOBAL;

		if (IsUseAlternativeHostname())
		{
			url = DDNS_URL_V4_ALT;
		}
	}
	else
	{
		url = DDNS_URL_V6_GLOBAL;

		if (IsUseAlternativeHostname())
		{
			url = DDNS_URL_V6_ALT;
		}

		if (replace_v6)
		{
			url = replace_v6;
		}
	}

	Zero(&t, sizeof(t));
	if (ipv6 == false)
	{
		// Proxy Setting
		Copy(&t, &c->InternetSetting, sizeof(INTERNET_SETTING));
	}

	if (ipv6 == false)
	{
		// Get the current status of the VPN Azure Client
		if (c->Cedar->Server != NULL)
		{
			AZURE_CLIENT *ac = c->Cedar->Server->AzureClient;

			if (ac != NULL)
			{
				use_azure = SiIsAzureEnabled(c->Cedar->Server);

				if (use_azure)
				{
					Lock(ac->Lock);
					{
						StrCpy(current_azure_ip, sizeof(current_azure_ip), ac->ConnectingAzureIp);
					}
					Unlock(ac->Lock);
				}
			}
		}
	}

	req = NewPack();
	BinToStr(key_str, sizeof(key_str), c->Key, sizeof(c->Key));
	StrUpper(key_str);
	PackAddStr(req, "key", key_str);

	// Build Number
	build = c->Cedar->Build;


	PackAddInt(req, "build", build);
	PackAddInt(req, "osinfo", GetOsInfo()->OsType);
	PackAddInt(req, "is_64bit", Is64());
#ifdef	OS_WIN32
	PackAddInt(req, "is_windows_64bit", MsIs64BitWindows());
#endif	// OS_WIN32
	PackAddBool(req, "is_softether", true);
	PackAddBool(req, "is_packetix", false);
	PackAddStr(req, "machine_key", machine_key_str);
	PackAddStr(req, "machine_name", machine_name);
	PackAddInt(req, "lasterror_ipv4", c->Err_IPv4_GetMyIp);
	PackAddInt(req, "lasterror_ipv6", c->Err_IPv6_GetMyIp);
	PackAddBool(req, "use_azure", use_azure);
	PackAddStr(req, "product_str", "SoftEther OSS");
	PackAddInt(req, "ddns_protocol_version", DDNS_VERSION);
	PackAddInt(req, "ddns_oss", 1);


	if (use_azure)
	{
		Debug("current_azure_ip = %s\n", current_azure_ip);
		PackAddStr(req, "current_azure_ip", current_azure_ip);
	}

	Sha1(key_hash, key_str, StrLen(key_str));
	BinToStr(key_hash_str, sizeof(key_hash_str), key_hash, sizeof(key_hash));
	StrLower(key_hash_str);

	if (p != NULL)
	{
		if (IsEmptyStr(p->NewHostname) == false)
		{
			PackAddStr(req, "new_hostname", p->NewHostname);
		}
	}



	Format(url2, sizeof(url2), "%s?v=%I64u", url, Rand64());
	Format(url3, sizeof(url3), url2, key_hash_str[2], key_hash_str[3]);

	ReplaceStr(url3, sizeof(url3), url3, "https://", "http://");

	ReplaceStr(url3, sizeof(url3), url3, ".servers", ".open.servers");

	cert_hash = StrToBin(DDNS_CERT_HASH);

	Debug("WpcCall: %s\n", url3);
	ret = WpcCallEx2(url3, &t, DDNS_CONNECT_TIMEOUT, DDNS_COMM_TIMEOUT, "register", req,
		NULL, NULL, ((cert_hash != NULL && ((cert_hash->Size % SHA1_SIZE) == 0)) ? cert_hash->Buf : NULL),
		(cert_hash != NULL ? cert_hash->Size / SHA1_SIZE : 0),
		NULL, DDNS_RPC_MAX_RECV_SIZE,
		add_header_name, add_header_value,
		DDNS_SNI_VER_STRING);
	Debug("WpcCall Ret: %u\n", ret);

	FreeBuf(cert_hash);

	FreePack(req);

	err = GetErrorFromPack(ret);

	ExtractAndApplyDynList(ret);

	// Status update
	Lock(c->Lock);
	{
		if (err == ERR_NO_ERROR)
		{
			char snat_t[MAX_SIZE];
			char current_region[128];

			// Current host name
			PackGetStr(ret, "current_hostname", c->CurrentHostName, sizeof(c->CurrentHostName));
			PackGetStr(ret, "current_fqdn", c->CurrentFqdn, sizeof(c->CurrentFqdn));
			PackGetStr(ret, "current_ipv4", c->CurrentIPv4, sizeof(c->CurrentIPv4));
			PackGetStr(ret, "current_ipv6", c->CurrentIPv6, sizeof(c->CurrentIPv6));
			PackGetStr(ret, "dns_suffix", c->DnsSuffix, sizeof(c->DnsSuffix));
			PackGetStr(ret, "current_region", current_region, sizeof(current_region));

			// SecureNAT connectivity check parameters
			Zero(snat_t, sizeof(snat_t));
			PackGetStr(ret, "snat_t", snat_t, sizeof(snat_t));
			NnSetSecureNatTargetHostname(snat_t);

			if (ipv6 == false)
			{
				char cert_hash[MAX_SIZE];

				PackGetStr(ret, "current_azure_ip", c->CurrentAzureIp, sizeof(c->CurrentAzureIp));
				c->CurrentAzureTimestamp = PackGetInt64(ret, "current_azure_timestamp");
				PackGetStr(ret, "current_azure_signature", c->CurrentAzureSignature, sizeof(c->CurrentAzureSignature));

				Zero(cert_hash, sizeof(cert_hash));
				PackGetStr(ret, "azure_cert_hash", cert_hash, sizeof(cert_hash));

				if (IsEmptyStr(cert_hash) == false)
				{
					StrCpy(c->AzureCertHash, sizeof(c->AzureCertHash), cert_hash);
				}
			}

			StrCpy(c->Cedar->CurrentDDnsFqdn, sizeof(c->Cedar->CurrentDDnsFqdn), c->CurrentFqdn);

			Debug("current_hostname=%s, current_fqdn=%s, current_ipv4=%s, current_ipv6=%s, current_azure_ip=%s, CurrentAzureTimestamp=%I64u, CurrentAzureSignature=%s, CertHash=%s\n",
				c->CurrentHostName, c->CurrentFqdn,
				c->CurrentIPv4, c->CurrentIPv6,
				c->CurrentAzureIp, c->CurrentAzureTimestamp, c->CurrentAzureSignature, c->AzureCertHash);

			if (IsEmptyStr(current_region) == false)
			{
				// Update the current region
				SiUpdateCurrentRegion(c->Cedar, current_region, false);
			}
		}
	}
	Unlock(c->Lock);

	if (IsEmptyStr(c->CurrentFqdn) == false)
	{
		SetCurrentDDnsFqdn(c->CurrentFqdn);
	}


	FreePack(ret);

	UniDebug(L"DCRegister Error: %s\n", _E(err));

	if (err == ERR_DUPLICATE_DDNS_KEY)
	{
		// Key duplication
		DCGenNewKey(c->Key);
		c->KeyChanged = true;
	}

	if (err == ERR_DISCONNECTED)
	{
		err = ERR_DDNS_DISCONNECTED;
	}

	if (IsUseAlternativeHostname() == false)
	{
		if (err == ERR_CONNECT_FAILED)
		{
			if (ipv6 && replace_v6 == NULL)
			{
				UINT type = DetectFletsType();

				if (type & FLETS_DETECT_TYPE_EAST_BFLETS_PRIVATE && err != ERR_NO_ERROR)
				{
					err = DCRegister(c, ipv6, p, DDNS_REPLACE_URL_FOR_EAST_BFLETS);
				}

				if (type & FLETS_DETECT_TYPE_EAST_NGN_PRIVATE && err != ERR_NO_ERROR)
				{
					err = DCRegister(c, ipv6, p, DDNS_REPLACE_URL_FOR_EAST_NGN);
				}

				if (type & FLETS_DETECT_TYPE_WEST_NGN_PRIVATE && err != ERR_NO_ERROR)
				{
					err = DCRegister(c, ipv6, p, DDNS_REPLACE_URL_FOR_WEST_NGN);
				}
			}
		}
	}

	return err;
}

// Get the self IP address
UINT DCGetMyIp(DDNS_CLIENT *c, bool ipv6, char *dst, UINT dst_size, char *replace_v6)
{
	UINT ret = ERR_INTERNAL_ERROR;

	ret = DCGetMyIpMain(c, ipv6, dst, dst_size, false, replace_v6);


	if (ret == ERR_NO_ERROR)
	{
		IP ip;

		if (StrToIP(&ip, dst))
		{
			if (ipv6 == false && IsIP4(&ip))
			{
				SetCurrentGlobalIP(&ip, false);
			}
			else if (ipv6 && IsIP6(&ip))
			{
				SetCurrentGlobalIP(&ip, true);
			}
		}
	}

	return ret;
}
UINT DCGetMyIpMain(DDNS_CLIENT *c, bool ipv6, char *dst, UINT dst_size, bool use_ssl, char *replace_v6)
{
	char *url;
	char url2[MAX_SIZE];
	UINT ret = ERR_INTERNAL_ERROR;
	URL_DATA data;
	BUF *recv;
	BUF *cert_hash = NULL;
	// Validate arguments
	if (dst == NULL || c == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	if (ipv6 == false)
	{
		url = DDNS_URL2_V4_GLOBAL;

		if (IsUseAlternativeHostname())
		{
			url = DDNS_URL2_V4_ALT;
		}
	}
	else
	{
		url = DDNS_URL2_V6_GLOBAL;

		if (IsUseAlternativeHostname())
		{
			url = DDNS_URL2_V6_ALT;
		}

		if (replace_v6)
		{
			url = replace_v6;
		}
	}

	Format(url2, sizeof(url2), "%s?v=%I64u", url, Rand64());

	if (use_ssl)
	{
		ReplaceStr(url2, sizeof(url2), url2, "http://", "https://");
	}


	if (ParseUrl(&data, url2, false, NULL) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	cert_hash = StrToBin(DDNS_CERT_HASH);

	StrCpy(data.SniString, sizeof(data.SniString), DDNS_SNI_VER_STRING);

	recv = HttpRequestEx3(&data, (ipv6 ? NULL : &c->InternetSetting), DDNS_CONNECT_TIMEOUT, DDNS_COMM_TIMEOUT, &ret, false, NULL, NULL,
		NULL, ((cert_hash != NULL && (cert_hash->Size % SHA1_SIZE) == 0) ? cert_hash->Buf : NULL),
		(cert_hash != NULL ? cert_hash->Size / SHA1_SIZE : 0), NULL, 0, NULL, NULL);

	FreeBuf(cert_hash);

	if (recv != NULL)
	{
		char *str = ZeroMalloc(recv->Size + 1);
		Copy(str, recv->Buf, recv->Size);

		if (StartWith(str, "IP=") == false)
		{
			ret = ERR_PROTOCOL_ERROR;
		}
		else
		{
			StrCpy(dst, dst_size, str + 3);
			ret = ERR_NO_ERROR;
		}

		Free(str);
		FreeBuf(recv);
	}

	if (IsUseAlternativeHostname() == false)
	{
		if (ret == ERR_CONNECT_FAILED)
		{
			if (ipv6 && replace_v6 == NULL && use_ssl == false)
			{
				UINT type = DetectFletsType();

				if (type & FLETS_DETECT_TYPE_EAST_BFLETS_PRIVATE && ret != ERR_NO_ERROR)
				{
					ret = DCGetMyIpMain(c, ipv6, dst, dst_size, use_ssl, DDNS_REPLACE_URL2_FOR_EAST_BFLETS);
				}

				if (type & FLETS_DETECT_TYPE_EAST_NGN_PRIVATE && ret != ERR_NO_ERROR)
				{
					ret = DCGetMyIpMain(c, ipv6, dst, dst_size, use_ssl, DDNS_REPLACE_URL2_FOR_EAST_NGN);
				}

				if (type & FLETS_DETECT_TYPE_WEST_NGN_PRIVATE && ret != ERR_NO_ERROR)
				{
					ret = DCGetMyIpMain(c, ipv6, dst, dst_size, use_ssl, DDNS_REPLACE_URL2_FOR_WEST_NGN);
				}
			}
		}
	}

	return ret;
}


// Creating a DDNS client
DDNS_CLIENT *NewDDNSClient(CEDAR *cedar, UCHAR *key, INTERNET_SETTING *t)
{
	DDNS_CLIENT *c;
	UCHAR key_hash[SHA1_SIZE];
	// Validate arguments
	if (cedar == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(DDNS_CLIENT));
	c->Cedar = cedar;
	AddRef(c->Cedar->ref);

	c->Err_IPv4 = c->Err_IPv6 = ERR_TRYING_TO_CONNECT;

	if (key == NULL)
	{
		// Create a new key
		DCGenNewKey(c->Key);
	}
	else
	{
		// Set the key
		Copy(c->Key, key, SHA1_SIZE);
	}

	Sha1(key_hash, c->Key, sizeof(c->Key));


	if (t != NULL)
	{
		Copy(&c->InternetSetting, t, sizeof(INTERNET_SETTING));
	}

	c->Lock = NewLock();

	// Thread creation
	c->Event = NewEvent();
	c->Thread = NewThread(DCThread, c);

	return c;
}

// Release of DDNS client
void FreeDDNSClient(DDNS_CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Stop the thread 
	c->Halt = true;
	Set(c->Event);

	WaitThread(c->Thread, INFINITE);
	ReleaseThread(c->Thread);

	ReleaseEvent(c->Event);

	ReleaseCedar(c->Cedar);
	DeleteLock(c->Lock);

	Free(c);
}

// Create a new key
void DCGenNewKey(UCHAR *key)
{
	BUF *b;
	UINT64 tick;
	UCHAR hash[SHA1_SIZE];
	UCHAR rand[SHA1_SIZE];
	UINT i;
	// Validate arguments
	if (key == NULL)
	{
		return;
	}

	b = NewBuf();

	Rand(rand, sizeof(rand));
	WriteBuf(b, rand, sizeof(rand));

	tick = TickHighres64();
	WriteBufInt64(b, tick);

	tick = Tick64();
	WriteBufInt64(b, tick);

	tick = SystemTime64();
	WriteBufInt64(b, tick);

	GetCurrentMachineIpProcessHash(hash);
	WriteBuf(b, hash, sizeof(hash));

	Sha1(key, b->Buf, b->Size);
	Rand(rand, sizeof(rand));

	for (i = 0;i < SHA1_SIZE;i++)
	{
		key[i] = key[i] ^ rand[i];
	}

	FreeBuf(b);
}


