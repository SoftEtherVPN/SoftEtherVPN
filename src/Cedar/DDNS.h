// SoftEther VPN Source Code - Stable Edition Repository
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under the Apache License, Version 2.0.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on SoftEther VPN project in GitHub.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// This stable branch is officially managed by Daiyuu Nobori, the owner of SoftEther VPN Project.
// Pull requests should be sent to the Developer Edition Master Repository on https://github.com/SoftEtherVPN/SoftEtherVPN
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI OR OTHER
// SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND
// OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. THE SOFTETHER VPN PROJECT HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


// DDNS.h
// Header of DDNS.c

#ifndef	DDNS_H
#define	DDNS_H

// Certificate hash
#define	DDNS_CERT_HASH		"78BF0499A99396907C9F49DD13571C81FE26E6F5" \
							"439BAFA75A6EE5671FC9F9A02D34FF29881761A0" \
							"EFAC5FA0CDD14E0F864EED58A73C35D7E33B62F3" \
							"74DF99D4B1B5F0488A388B50D347D26013DC67A5" \
							"6EBB39AFCA8C900635CFC11218CF293A612457E4"

#define	DDNS_SNI_VER_STRING		"DDNS"


// Destination URL
#define	DDNS_URL_V4_GLOBAL	"https://x%c.x%c.servers.ddns.softether-network.net/ddns/ddns.aspx"
#define	DDNS_URL_V6_GLOBAL	"https://x%c.x%c.servers-v6.ddns.softether-network.net/ddns/ddns.aspx"
#define	DDNS_URL2_V4_GLOBAL	"http://get-my-ip.ddns.softether-network.net/ddns/getmyip.ashx"
#define	DDNS_URL2_V6_GLOBAL	"http://get-my-ip-v6.ddns.softether-network.net/ddns/getmyip.ashx"

#define	DDNS_REPLACE_URL_FOR_EAST_BFLETS	"https://senet-flets.v6.softether.co.jp/ddns/ddns.aspx"
#define	DDNS_REPLACE_URL_FOR_EAST_NGN		"https://senet.aoi.flets-east.jp/ddns/ddns.aspx"
#define	DDNS_REPLACE_URL_FOR_WEST_NGN		"https://senet.p-ns.flets-west.jp/ddns/ddns.aspx"

#define	DDNS_REPLACE_URL2_FOR_EAST_BFLETS	"http://senet-flets.v6.softether.co.jp/ddns/getmyip.ashx"
#define	DDNS_REPLACE_URL2_FOR_EAST_NGN		"http://senet.aoi.flets-east.jp/ddns/getmyip.ashx"
#define	DDNS_REPLACE_URL2_FOR_WEST_NGN		"http://senet.p-ns.flets-west.jp/ddns/getmyip.ashx"

// For China: Free version
#define	DDNS_URL_V4_ALT		"https://x%c.x%c.servers.ddns.uxcom.jp/ddns/ddns.aspx"
#define	DDNS_URL_V6_ALT		"https://x%c.x%c.servers-v6.ddns.uxcom.jp/ddns/ddns.aspx"
#define	DDNS_URL2_V4_ALT	"http://get-my-ip.ddns.uxcom.jp/ddns/getmyip.ashx"
#define	DDNS_URL2_V6_ALT	"http://get-my-ip-v6.ddns.uxcom.jp/ddns/getmyip.ashx"

#define	DDNS_RPC_MAX_RECV_SIZE				DYN32(DDNS_RPC_MAX_RECV_SIZE, (128 * 1024 * 1024))

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
void DCUpdateNow(DDNS_CLIENT *c);
void DCGetStatus(DDNS_CLIENT *c, DDNS_CLIENT_STATUS *st);
UINT DCChangeHostName(DDNS_CLIENT *c, char *hostname);
void DCSetInternetSetting(DDNS_CLIENT *c, INTERNET_SETTING *t);
void DCGetInternetSetting(DDNS_CLIENT *c, INTERNET_SETTING *t);



#endif	// DDNS_H


