// SoftEther VPN Source Code
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.
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


// Account.h
// Header of Account.c

#ifndef	ACCOUNT_H
#define	ACCOUNT_H

// Policy item
struct POLICY_ITEM
{
	UINT Index;
	bool TypeInt;
	bool AllowZero;
	UINT MinValue;
	UINT MaxValue;
	UINT DefaultValue;
	char *FormatStr;
};

// Policy
struct POLICY
{
	// For Ver 2.0
	bool Access;					// Grant access
	bool DHCPFilter;				// Filter DHCP packets (IPv4)
	bool DHCPNoServer;				// Prohibit the behavior of the DHCP server (IPv4)
	bool DHCPForce;					// Force DHCP-assigned IP address (IPv4)
	bool NoBridge;					// Prohibit the bridge behavior
	bool NoRouting;					// Prohibit the router behavior (IPv4)
	bool CheckMac;					// Prohibit the duplicate MAC address
	bool CheckIP;					// Prohibit a duplicate IP address (IPv4)
	bool ArpDhcpOnly;				// Prohibit the broadcast other than ARP, DHCP, ICMPv6
	bool PrivacyFilter;				// Privacy filter mode
	bool NoServer;					// Prohibit to operate as a TCP/IP server (IPv4)
	bool NoBroadcastLimiter;		// Not to limit the number of broadcast
	bool MonitorPort;				// Allow monitoring mode
	UINT MaxConnection;				// Maximum number of TCP connections
	UINT TimeOut;					// Communication time-out period
	UINT MaxMac;					// Maximum number of MAC address
	UINT MaxIP;						// Maximum number of IP address (IPv4)
	UINT MaxUpload;					// Upload bandwidth
	UINT MaxDownload;				// Download bandwidth
	bool FixPassword;				// User can not change password
	UINT MultiLogins;				// Multiple logins limit
	bool NoQoS;						// Prohibit the use of VoIP / QoS features

	// For Ver 3.0
	bool RSandRAFilter;				// Filter the Router Solicitation / Advertising packet (IPv6)
	bool RAFilter;					// Filter the router advertisement packet (IPv6)
	bool DHCPv6Filter;				// Filter DHCP packets (IPv6)
	bool DHCPv6NoServer;			// Prohibit the behavior of the DHCP server (IPv6)
	bool NoRoutingV6;				// Prohibit the router behavior (IPv6)
	bool CheckIPv6;					// Prohibit the duplicate IP address (IPv6)
	bool NoServerV6;				// Prohibit to operate as a TCP/IP server (IPv6)
	UINT MaxIPv6;					// Maximum number of IP address (IPv6)
	bool NoSavePassword;			// Prohibit to save the password in the VPN Client
	UINT AutoDisconnect;			// Disconnect the VPN Client automatically at a certain period of time
	bool FilterIPv4;				// Filter all IPv4 packets
	bool FilterIPv6;				// Filter all IPv6 packets
	bool FilterNonIP;				// Filter all non-IP packets
	bool NoIPv6DefaultRouterInRA;	// Delete the default router specification from the IPv6 router advertisement
	bool NoIPv6DefaultRouterInRAWhenIPv6;	// Delete the default router specification from the IPv6 router advertisement (Enable IPv6 connection)
	UINT VLanId;					// Specify the VLAN ID

	bool Ver3;						// Whether version 3.0
};

// Group
struct USERGROUP
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	char *Name;						// Group name
	wchar_t *RealName;				// Display name
	wchar_t *Note;					// Note
	POLICY *Policy;					// Policy
	TRAFFIC *Traffic;				// Traffic data
};

// User
struct USER
{
	LOCK *lock;						// Lock
	REF *ref;						// Reference counter
	char *Name;						// User name
	wchar_t *RealName;				// Real name
	wchar_t *Note;					// Note
	char *GroupName;				// Group name
	USERGROUP *Group;				// Group
	UINT AuthType;					// Authentication type
	void *AuthData;					// Authentication data
	UINT64 CreatedTime;				// Creation date and time
	UINT64 UpdatedTime;				// Updating date
	UINT64 ExpireTime;				// Expiration date
	UINT64 LastLoginTime;			// Last login time
	UINT NumLogin;					// Total number of logins
	POLICY *Policy;					// Policy
	TRAFFIC *Traffic;				// Traffic data
};

// Password authentication data
struct AUTHPASSWORD
{
	UCHAR HashedKey[SHA1_SIZE];		// Hashed passwords
	UCHAR NtLmSecureHash[MD5_SIZE];	// Encrypted password for the NTLM
};

// User certificate authentication data
struct AUTHUSERCERT
{
	X *UserX;						// X509 certificate for the user
};

// Root certification authority authentication data
struct AUTHROOTCERT
{
	X_SERIAL *Serial;				// Serial number
	wchar_t *CommonName;			// CommonName
};

// Radius authentication data
struct AUTHRADIUS
{
	wchar_t *RadiusUsername;		// User name in the Radius
};

// Windows NT authentication data
struct AUTHNT
{
	wchar_t *NtUsername;			// User name on NT
};



// Macro
#define	POLICY_CURRENT_VERSION		3
#define	NUM_POLICY_ITEM		((sizeof(POLICY) / sizeof(UINT)) - 1)
#define	NUM_POLICY_ITEM_FOR_VER2	22
#define	NUM_POLICY_ITEM_FOR_VER3	38

#define	IS_POLICY_FOR_VER2(index)	(((index) >= 0) && ((index) < NUM_POLICY_ITEM_FOR_VER2))
#define	IS_POLICY_FOR_VER3(index)	(((index) >= 0) && ((index) < NUM_POLICY_ITEM_FOR_VER3))

#define	IS_POLICY_FOR_CURRENT_VER(index, ver)	((ver) >= 3 ? IS_POLICY_FOR_VER3(index) : IS_POLICY_FOR_VER2(index))

#define	POLICY_BOOL(p, i)	(((bool *)(p))[(i)])
#define	POLICY_INT(p, i)	(((UINT *)(p))[(i)])

extern POLICY_ITEM policy_item[];




// Function prototype
int CompareUserName(void *p1, void *p2);
int CompareGroupName(void *p1, void *p2);
void AcLock(HUB *h);
void AcUnlock(HUB *h);
USERGROUP *NewGroup(char *name, wchar_t *realname, wchar_t *note);
void ReleaseGroup(USERGROUP *g);
void CleanupGroup(USERGROUP *g);
USER *NewUser(char *name, wchar_t *realname, wchar_t *note, UINT authtype, void *authdata);
void ReleaseUser(USER *u);
void CleanupUser(USER *u);
void FreeAuthData(UINT authtype, void *authdata);
bool AcAddUser(HUB *h, USER *u);
bool AcAddGroup(HUB *h, USERGROUP *g);
USER *AcGetUser(HUB *h, char *name);
USERGROUP *AcGetGroup(HUB *h, char *name);
bool AcIsUser(HUB *h, char *name);
bool AcIsGroup(HUB *h, char *name);
bool AcDeleteUser(HUB *h, char *name);
bool AcDeleteGroup(HUB *h, char *name);
void JoinUserToGroup(USER *u, USERGROUP *g);
void SetUserTraffic(USER *u, TRAFFIC *t);
void SetGroupTraffic(USERGROUP *g, TRAFFIC *t);
void AddUserTraffic(USER *u, TRAFFIC *diff);
void AddGroupTraffic(USERGROUP *g, TRAFFIC *diff);
void SetUserAuthData(USER *u, UINT authtype, void *authdata);
void *NewPasswordAuthData(char *username, char *password);
void *NewPasswordAuthDataRaw(UCHAR *hashed_password, UCHAR *ntlm_secure_hash);
void *NewUserCertAuthData(X *x);
void *NewRootCertAuthData(X_SERIAL *serial, wchar_t *common_name);
void *NewRadiusAuthData(wchar_t *username);
void *NewNTAuthData(wchar_t *username);
void HashPassword(void *dst, char *username, char *password);
POLICY *GetDefaultPolicy();
POLICY *ClonePolicy(POLICY *policy);
void SetUserPolicy(USER *u, POLICY *policy);
void OverwritePolicy(POLICY **target, POLICY *p);
POLICY *GetUserPolicy(USER *u);
void SetGroupPolicy(USERGROUP *g, POLICY *policy);
POLICY *GetGroupPolicy(USERGROUP *g);
wchar_t *GetPolicyTitle(UINT id);
wchar_t *GetPolicyDescription(UINT id);
bool IsUserName(char *name);
void *CopyAuthData(void *authdata, UINT authtype);
UINT PolicyNum();
bool PolicyIsSupportedForCascade(UINT i);
UINT PolicyStrToId(char *name);
char *PolicyIdToStr(UINT i);
POLICY_ITEM *GetPolicyItem(UINT id);
void GetPolicyValueRangeStr(wchar_t *str, UINT size, UINT id);
void FormatPolicyValue(wchar_t *str, UINT size, UINT id, UINT value);
char *NormalizePolicyName(char *name);


#endif	// ACCOUNT_H



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
