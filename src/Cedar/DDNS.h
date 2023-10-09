// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// DDNS.h
// Header of DDNS.c

#ifndef	DDNS_H
#define	DDNS_H

#include "CedarType.h"
#include "Wpc.h"

#include <stddef.h>

// Certificate hash
#define	DDNS_CERT_HASH		"78BF0499A99396907C9F49DD13571C81FE26E6F5" \
							"439BAFA75A6EE5671FC9F9A02D34FF29881761A0" \
							"EFAC5FA0CDD14E0F864EED58A73C35D7E33B62F3" \
							"74DF99D4B1B5F0488A388B50D347D26013DC67A5" \
							"6EBB39AFCA8C900635CFC11218CF293A612457E4" \
							"05A9386C5E2B233F7BAB2479620EAAA2793709ED" \
							"A811C64BB715351E36B6C1E022648D8BE0ACD128" \
							"BD264DB3B0B1B3ABA0AF3074AA574ED1EF3B42D7" \
							"9AB61D691536645DD55A8730FC6D2CDF33C8C73F"

#define	DDNS_SNI_VER_STRING		"DDNS"


// Destination URL
#define	DDNS_URL_V4_GLOBAL	"https://x%c.x%c.dev.servers.ddns.softether-network.net/ddns/ddns.aspx"
#define	DDNS_URL_V6_GLOBAL	"https://x%c.x%c.dev.servers-v6.ddns.softether-network.net/ddns/ddns.aspx"
#define	DDNS_URL2_V4_GLOBAL	"http://get-my-ip.ddns.softether-network.net/ddns/getmyip.ashx"
#define	DDNS_URL2_V6_GLOBAL	"http://get-my-ip-v6.ddns.softether-network.net/ddns/getmyip.ashx"

#define	DDNS_REPLACE_URL_FOR_EAST_BFLETS	"https://senet-flets.v6.softether.co.jp/ddns/ddns.aspx"
#define	DDNS_REPLACE_URL_FOR_EAST_NGN		"https://senet.aoi.flets-east.jp/ddns/ddns.aspx"
#define	DDNS_REPLACE_URL_FOR_WEST_NGN		"https://senet.p-ns.flets-west.jp/ddns/ddns.aspx"

#define	DDNS_REPLACE_URL2_FOR_EAST_BFLETS	"http://senet-flets.v6.softether.co.jp/ddns/getmyip.ashx"
#define	DDNS_REPLACE_URL2_FOR_EAST_NGN		"http://senet.aoi.flets-east.jp/ddns/getmyip.ashx"
#define	DDNS_REPLACE_URL2_FOR_WEST_NGN		"http://senet.p-ns.flets-west.jp/ddns/getmyip.ashx"

// For China: Free version
#define	DDNS_URL_V4_ALT		"https://x%c.x%c.dev.servers.ddns.uxcom.jp/ddns/ddns.aspx"
#define	DDNS_URL_V6_ALT		"https://x%c.x%c.dev.servers-v6.ddns.uxcom.jp/ddns/ddns.aspx"
#define	DDNS_URL2_V4_ALT	"http://get-my-ip.ddns.uxcom.jp/ddns/getmyip.ashx"
#define	DDNS_URL2_V6_ALT	"http://get-my-ip-v6.ddns.uxcom.jp/ddns/getmyip.ashx"

#define	DDNS_RPC_MAX_RECV_SIZE				DYN32(DDNS_RPC_MAX_RECV_SIZE, (38 * 1024 * 1024))

// Connection Timeout
#define	DDNS_CONNECT_TIMEOUT		DYN32(DDNS_CONNECT_TIMEOUT, (15 * 1000))

// Communication time-out
#define	DDNS_COMM_TIMEOUT			DYN32(DDNS_COMM_TIMEOUT, (60 * 1000))

// Maximum length of the host name 
#define	DDNS_MAX_HOSTNAME			31

// DDNS Version
#define	DDNS_VERSION				1

// Period until the next registration in case of success
#define	DDNS_REGISTER_INTERVAL_OK_MIN		DYN32(DDNS_REGISTER_INTERVAL_OK_MIN, (1 * 60 * 60 * 1000))
#define	DDNS_REGISTER_INTERVAL_OK_MAX		DYN32(DDNS_REGISTER_INTERVAL_OK_MAX, (2 * 60 * 60 * 1000))

// Period until the next registration in case of failure
#define	DDNS_REGISTER_INTERVAL_NG_MIN		DYN32(DDNS_REGISTER_INTERVAL_NG_MIN, (1 * 60 * 1000))
#define	DDNS_REGISTER_INTERVAL_NG_MAX		DYN32(DDNS_REGISTER_INTERVAL_NG_MAX, (5 * 60 * 1000))

// The self IP address acquisition interval (If last trial succeeded)
#define	DDNS_GETMYIP_INTERVAL_OK_MIN		DYN32(DDNS_GETMYIP_INTERVAL_OK_MIN, (10 * 60 * 1000))
#define	DDNS_GETMYIP_INTERVAL_OK_MAX		DYN32(DDNS_GETMYIP_INTERVAL_OK_MAX, (20 * 60 * 1000))

// The self IP address acquisition interval (If last trial failed)
#define	DDNS_GETMYIP_INTERVAL_NG_MIN		DYN32(DDNS_GETMYIP_INTERVAL_NG_MIN, (1 * 60 * 1000))
#define	DDNS_GETMYIP_INTERVAL_NG_MAX		DYN32(DDNS_GETMYIP_INTERVAL_NG_MAX, (5 * 60 * 1000))

// Time difference to communicate with the DDNS server after a predetermined time has elapsed since the VPN Azure is disconnected
#define	DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF	DYN32(DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF, (120 * 1000))
#define	DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF_MAX	DYN32(DDNS_VPN_AZURE_CONNECT_ERROR_DDNS_RETRY_TIME_DIFF_MAX, (10 * 60 * 1000))

// DDNS Client
struct DDNS_CLIENT
{
	CEDAR *Cedar;							// Cedar
	THREAD *Thread;							// Thread
	UCHAR Key[SHA1_SIZE];					// Key
	LOCK *Lock;								// Lock
	volatile bool Halt;						// Halt flag
	EVENT *Event;							// Halt event
	char CurrentHostName[DDNS_MAX_HOSTNAME + 1];	// Current host name
	char CurrentFqdn[MAX_SIZE];				// Current FQDN
	char DnsSuffix[MAX_SIZE];				// DNS suffix
	char CurrentIPv4[MAX_SIZE];				// Current IPv4 address
	char CurrentIPv6[MAX_SIZE];				// Current IPv6 address
	UINT Err_IPv4, Err_IPv6;				// Last error
	UINT Err_IPv4_GetMyIp, Err_IPv6_GetMyIp;	// Last error (obtaining self IP address)
	bool KeyChanged;						// Flag to indicate that the key has been changed
	char LastMyIPv4[MAX_SIZE];				// Self IPv4 address that were acquired on last
	char LastMyIPv6[MAX_SIZE];				// Self IPv6 address that were acquired on last
	char CurrentAzureIp[MAX_SIZE];			// IP address of Azure Server to be used
	UINT64 CurrentAzureTimestamp;			// Time stamp to be presented to the Azure Server
	char CurrentAzureSignature[MAX_SIZE];	// Signature to be presented to the Azure Server
	char AzureCertHash[MAX_SIZE];			// Azure Server certificate hash
	INTERNET_SETTING InternetSetting;		// Internet connection settings

	UINT64 NextRegisterTick_IPv4, NextRegisterTick_IPv6;		// Next register time
	UINT64 NextGetMyIpTick_IPv4, NextGetMyIpTick_IPv6;			// Next self IP acquisition time
};

// DDNS Register Param
struct DDNS_REGISTER_PARAM
{
	char NewHostname[DDNS_MAX_HOSTNAME + 1];	// Host name after the change
};

// The current status of the DDNS
struct DDNS_CLIENT_STATUS
{
	UINT Err_IPv4, Err_IPv6;				// Last error
	wchar_t ErrStr_IPv4[MAX_SIZE];
	wchar_t ErrStr_IPv6[MAX_SIZE];
	char CurrentHostName[DDNS_MAX_HOSTNAME + 1];	// Current host name
	char CurrentFqdn[MAX_SIZE];				// Current FQDN
	char DnsSuffix[MAX_SIZE];				// DNS suffix
	char CurrentIPv4[MAX_SIZE];				// Current IPv4 address
	char CurrentIPv6[MAX_SIZE];				// Current IPv6 address
	char CurrentAzureIp[MAX_SIZE];			// IP address of Azure Server to be used
	UINT64 CurrentAzureTimestamp;			// Time stamp to be presented to the Azure Server
	char CurrentAzureSignature[MAX_SIZE];	// Signature to be presented to the Azure Server
	char AzureCertHash[MAX_SIZE];			// Azure Server certificate hash
	INTERNET_SETTING InternetSetting;		// Internet settings
};

// Function prototype
DDNS_CLIENT *NewDDNSClient(CEDAR *cedar, UCHAR *key, INTERNET_SETTING *t);
void FreeDDNSClient(DDNS_CLIENT *c);
void DCGenNewKey(UCHAR *key);
void DCThread(THREAD *thread, void *param);
UINT DCRegister(DDNS_CLIENT *c, bool ipv6, DDNS_REGISTER_PARAM *p, char *replace_v6);
UINT DCGetMyIpMain(DDNS_CLIENT *c, bool ipv6, char *dst, UINT dst_size, bool use_ssl, char *replace_v6);
UINT DCGetMyIp(DDNS_CLIENT *c, bool ipv6, char *dst, UINT dst_size, char *replace_v6);
void DCGetStatus(DDNS_CLIENT *c, DDNS_CLIENT_STATUS *st);
UINT DCChangeHostName(DDNS_CLIENT *c, char *hostname);
void DCSetInternetSetting(DDNS_CLIENT *c, INTERNET_SETTING *t);
void DCGetInternetSetting(DDNS_CLIENT *c, INTERNET_SETTING *t);



#endif	// DDNS_H


