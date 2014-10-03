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


// Account.c
// Account Manager

#include "CedarPch.h"

// Policy items
POLICY_ITEM policy_item[] =
{
//  ID,     Value,  Omittable, Min, Max, Default, Unit name
// Ver 2.0
	{0,		false,	false,	0,	0,	0,		NULL},			// Access
	{1,		false,	false,	0,	0,	0,		NULL},			// DHCPFilter
	{2,		false,	false,	0,	0,	0,		NULL},			// DHCPNoServer
	{3,		false,	false,	0,	0,	0,		NULL},			// DHCPForce
	{4,		false,	false,	0,	0,	0,		NULL},			// NoBridge
	{5,		false,	false,	0,	0,	0,		NULL},			// NoRouting
	{6,		false,	false,	0,	0,	0,		NULL},			// CheckMac
	{7,		false,	false,	0,	0,	0,		NULL},			// CheckIP
	{8,		false,	false,	0,	0,	0,		NULL},			// ArpDhcpOnly
	{9,		false,	false,	0,	0,	0,		NULL},			// PrivacyFilter
	{10,	false,	false,	0,	0,	0,		NULL},			// NoServer
	{11,	false,	false,	0,	0,	0,		NULL},			// NoBroadcastLimiter
	{12,	false,	false,	0,	0,	0,		NULL},			// MonitorPort
	{13,	true,	false,	1,	32,	32,		"POL_INT_COUNT"},	// MaxConnection
	{14,	true,	false,	5,	60,	20,		"POL_INT_SEC"},	// TimeOut
	{15,	true,	true,	1,	65535,	0,	"POL_INT_COUNT"},	// MaxMac
	{16,	true,	true,	1,	65535,	0,	"POL_INT_COUNT"},	// MaxIP
	{17,	true,	true,	1,	4294967295UL,	0,	"POL_INT_BPS"},	// MaxUpload
	{18,	true,	true,	1,	4294967295UL,	0,	"POL_INT_BPS"},	// MaxDownload
	{19,	false,	false,	0,	0,	0,		NULL},			// FixPassword
	{20,	true,	true,	1,	65535,	0,	"POL_INT_COUNT"},	// MultiLogins
	{21,	false,	false,	0,	0,	0,		NULL},			// NoQoS
// Ver 3.0
	{22,	false,	false,	0,	0,	0,		NULL},			// RSandRAFilter
	{23,	false,	false,	0,	0,	0,		NULL},			// RAFilter
	{24,	false,	false,	0,	0,	0,		NULL},			// DHCPv6Filter
	{25,	false,	false,	0,	0,	0,		NULL},			// DHCPv6NoServer
	{26,	false,	false,	0,	0,	0,		NULL},			// NoRoutingV6
	{27,	false,	false,	0,	0,	0,		NULL},			// CheckIPv6
	{28,	false,	false,	0,	0,	0,		NULL},			// NoServerV6
	{29,	true,	true,	1,	65535,	0,	"POL_INT_COUNT"},	// MaxIPv6
	{30,	false,	false,	0,	0,	0,		NULL},			// NoSavePassword
	{31,	true,	true,	1,	4294967295UL,	0,	"POL_INT_SEC"},	// AutoDisconnect
	{32,	false,	false,	0,	0,	0,		NULL},			// FilterIPv4
	{33,	false,	false,	0,	0,	0,		NULL},			// FilterIPv6
	{34,	false,	false,	0,	0,	0,		NULL},			// FilterNonIP
	{35,	false,	false,	0,	0,	0,		NULL},			// NoIPv6DefaultRouterInRA
	{36,	false,	false,	0,	0,	0,		NULL},			// NoIPv6DefaultRouterInRAWhenIPv6
	{37,	true,	true,	1,	4095,	0,	"POL_INT_VLAN"},	// VLanId
};

// Normalize policy name
char *NormalizePolicyName(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	return PolicyIdToStr(PolicyStrToId(name));
}

// Format policy value
void FormatPolicyValue(wchar_t *str, UINT size, UINT id, UINT value)
{
	POLICY_ITEM *p;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	p = GetPolicyItem(id);

	if (p->TypeInt == false)
	{
		// bool type
		if (value == 0)
		{
			UniStrCpy(str, size, L"No");
		}
		else
		{
			UniStrCpy(str, size, L"Yes");
		}
	}
	else
	{
		// int type
		if (value == 0 && p->AllowZero)
		{
			UniStrCpy(str, size, _UU("CMD_NO_SETTINGS"));
		}
		else
		{
			UniFormat(str, size, _UU(p->FormatStr), value);
		}
	}
}

// Get description string for range of the policy value
void GetPolicyValueRangeStr(wchar_t *str, UINT size, UINT id)
{
	POLICY_ITEM *p;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	p = GetPolicyItem(id);

	if (p->TypeInt == false)
	{
		// bool type
		UniStrCpy(str, size, _UU("CMD_PolicyList_Range_Bool"));
	}
	else
	{
		wchar_t *tag;
		wchar_t tmp1[256], tmp2[256];

		// int type
		if (p->AllowZero)
		{
			tag = _UU("CMD_PolicyList_Range_Int_2");
		}
		else
		{
			tag = _UU("CMD_PolicyList_Range_Int_1");
		}

		UniFormat(tmp1, sizeof(tmp1), _UU(p->FormatStr), p->MinValue);
		UniFormat(tmp2, sizeof(tmp2), _UU(p->FormatStr), p->MaxValue);

		UniFormat(str, size, tag, tmp1, tmp2);
	}
}

// Get a policy item for id
POLICY_ITEM *GetPolicyItem(UINT id)
{
	return &policy_item[id];
}

// Does cascade connection support the specified policy?
bool PolicyIsSupportedForCascade(UINT i)
{
	if (i == 0 || i == 4 || i == 5 || i == 12 || i == 13 ||
		i == 14 || i == 19 || i == 20 || i == 21 || i == 26 || i == 30 || i == 31 || i == 36)
	{
		// These items are not supported by cascade connection.
		return false;
	}

	return true;
}

// Get policy name
char *PolicyIdToStr(UINT i)
{
	switch (i)
	{
	// Ver 2.0
	case 0:		return "Access";
	case 1:		return "DHCPFilter";
	case 2:		return "DHCPNoServer";
	case 3:		return "DHCPForce";
	case 4:		return "NoBridge";
	case 5:		return "NoRouting";
	case 6:		return "CheckMac";
	case 7:		return "CheckIP";
	case 8:		return "ArpDhcpOnly";
	case 9:		return "PrivacyFilter";
	case 10:	return "NoServer";
	case 11:	return "NoBroadcastLimiter";
	case 12:	return "MonitorPort";
	case 13:	return "MaxConnection";
	case 14:	return "TimeOut";
	case 15:	return "MaxMac";
	case 16:	return "MaxIP";
	case 17:	return "MaxUpload";
	case 18:	return "MaxDownload";
	case 19:	return "FixPassword";
	case 20:	return "MultiLogins";
	case 21:	return "NoQoS";

	// Ver 3.0
	case 22:	return "RSandRAFilter";
	case 23:	return "RAFilter";
	case 24:	return "DHCPv6Filter";
	case 25:	return "DHCPv6NoServer";
	case 26:	return "NoRoutingV6";
	case 27:	return "CheckIPv6";
	case 28:	return "NoServerV6";
	case 29:	return "MaxIPv6";
	case 30:	return "NoSavePassword";
	case 31:	return "AutoDisconnect";
	case 32:	return "FilterIPv4";
	case 33:	return "FilterIPv6";
	case 34:	return "FilterNonIP";
	case 35:	return "NoIPv6DefaultRouterInRA";
	case 36:	return "NoIPv6DefaultRouterInRAWhenIPv6";
	case 37:	return "VLanId";
	}

	return NULL;
}

// Get policy id for name
UINT PolicyStrToId(char *name)
{
	UINT i;
	// Validate arguments
	if (name == NULL)
	{
		return INFINITE;
	}

	for (i = 0;i < NUM_POLICY_ITEM;i++)
	{
		if (StartWith(PolicyIdToStr(i), name))
		{
			return i;
		}
	}

	return INFINITE;
}

// Get number of policies
UINT PolicyNum()
{
	return NUM_POLICY_ITEM;
}

// Check the name is valid for account name
bool IsUserName(char *name)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), name);
	name = tmp;

	Trim(name);

	if (StrLen(name) == 0)
	{
		return false;
	}

	if (StrCmpi(name, "*") == 0)
	{
		return true;
	}

	if (IsSafeStr(name) == false)
	{
		return false;
	}

	if (StrCmpi(name, "link") == 0)
	{
		return false;
	}

	if (StrCmpi(name, LINK_USER_NAME) == 0)
	{
		return false;
	}

	if (StartWith(name, L3_USERNAME))
	{
		return false;
	}

	if (StrCmpi(name, LINK_USER_NAME_PRINT) == 0)
	{
		return false;
	}

	if (StrCmpi(name, SNAT_USER_NAME) == 0)
	{
		return false;
	}

	if (StrCmpi(name, SNAT_USER_NAME_PRINT) == 0)
	{
		return false;
	}

	if (StrCmpi(name, BRIDGE_USER_NAME) == 0)
	{
		return false;
	}

	if (StrCmpi(name, BRIDGE_USER_NAME_PRINT) == 0)
	{
		return false;
	}

	if (StrCmpi(name, ADMINISTRATOR_USERNAME) == 0)
	{
		return false;
	}

	return true;
}

// Get policy title
wchar_t *GetPolicyTitle(UINT id)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "POL_%u", id);

	return _UU(tmp);
}

// Get policy description
wchar_t *GetPolicyDescription(UINT id)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "POL_EX_%u", id);

	return _UU(tmp);
}

// Clone the policy value
POLICY *ClonePolicy(POLICY *policy)
{
	POLICY *ret;
	// Validate arguments
	if (policy == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(POLICY));
	Copy(ret, policy, sizeof(POLICY));

	return ret;
}

// Overwrite policy value (If old version data overwrites new version, leave new version value as it is.)
void OverwritePolicy(POLICY **target, POLICY *p)
{
	// Validate arguments
	if (target == NULL)
	{
		return;
	}

	if (p == NULL)
	{
		// Erase policy
		if (*target != NULL)
		{
			Free(*target);
			*target = NULL;
		}
	}
	else
	{
		if (p->Ver3)
		{
			// Ver 3
			if (*target != NULL)
			{
				Free(*target);
				*target = NULL;
			}

			*target = ClonePolicy(p);
		}
		else
		{
			// Ver 2
			if (*target == NULL)
			{
				*target = ClonePolicy(p);
			}
			else
			{
				Copy(*target, p, NUM_POLICY_ITEM_FOR_VER2 * sizeof(UINT));
			}
		}
	}
}

// Set user policy
void SetUserPolicy(USER *u, POLICY *policy)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		OverwritePolicy(&u->Policy, policy);
	}
	Unlock(u->lock);
}

// Get user policy
POLICY *GetUserPolicy(USER *u)
{
	POLICY *ret;
	// Validate arguments
	if (u == NULL)
	{
		return NULL;
	}

	Lock(u->lock);
	{
		if (u->Policy == NULL)
		{
			ret = NULL;
		}
		else
		{
			ret = ClonePolicy(u->Policy);
		}
	}
	Unlock(u->lock);

	return ret;
}

// Set group policy
void SetGroupPolicy(USERGROUP *g, POLICY *policy)
{
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	Lock(g->lock);
	{
		OverwritePolicy(&g->Policy, policy);
	}
	Unlock(g->lock);
}

// Get group policy
POLICY *GetGroupPolicy(USERGROUP *g)
{
	POLICY *ret;
	// Validate arguments
	if (g == NULL)
	{
		return NULL;
	}

	Lock(g->lock);
	{
		if (g->Policy == NULL)
		{
			ret = NULL;
		}
		else
		{
			ret = ClonePolicy(g->Policy);
		}
	}
	Unlock(g->lock);

	return ret;
}

// Get default policy template
POLICY *GetDefaultPolicy()
{
	static POLICY def_policy =
	{
		true,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		32,
		20,
		0,
		0,
		0,
		0,
		false,
		0,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		false,
		0,
		false,
		0,
		false,
		false,
		false,
		false,
		false,
	};

	return &def_policy;
}

// Create a NT authentication data
void *NewNTAuthData(wchar_t *username)
{
	AUTHNT *a;
	// Validate arguments
	a = ZeroMallocEx(sizeof(AUTHNT), true);
	a->NtUsername = CopyUniStr(username);

	return a;
}

// Create a Radius authentication data
void *NewRadiusAuthData(wchar_t *username)
{
	AUTHRADIUS *a;
	// Validate arguments
	a = ZeroMallocEx(sizeof(AUTHRADIUS), true);
	a->RadiusUsername = CopyUniStr(username);

	return a;
}

// Create a root certification authentication data
void *NewRootCertAuthData(X_SERIAL *serial, wchar_t *common_name)
{
	AUTHROOTCERT *a;

	a = ZeroMallocEx(sizeof(AUTHROOTCERT), true);
	if (common_name != NULL && UniIsEmptyStr(common_name) == false)
	{
		a->CommonName = CopyUniStr(common_name);
	}
	if (serial != NULL && serial->size >= 1)
	{
		a->Serial = CloneXSerial(serial);
	}

	return a;
}

// Create an authentication data for user certification
void *NewUserCertAuthData(X *x)
{
	AUTHUSERCERT *a;

	a = ZeroMalloc(sizeof(AUTHUSERCERT));
	a->UserX = CloneX(x);

	return a;
}

// Hash the password
void HashPassword(void *dst, char *username, char *password)
{
	BUF *b;
	char *username_upper;
	// Validate arguments
	if (dst == NULL || username == NULL || password == NULL)
	{
		return;
	}

	b = NewBuf();
	username_upper = CopyStr(username);
	StrUpper(username_upper);
	WriteBuf(b, password, StrLen(password));
	WriteBuf(b, username_upper, StrLen(username_upper));
	Hash(dst, b->Buf, b->Size, true);

	FreeBuf(b);
	Free(username_upper);
}

// Create a password authentication data
void *NewPasswordAuthData(char *username, char *password)
{
	AUTHPASSWORD *pw;
	// Validate arguments
	if (username == NULL || password == NULL)
	{
		return NULL;
	}

	pw = ZeroMalloc(sizeof(AUTHPASSWORD));
	HashPassword(pw->HashedKey, username, password);
	GenerateNtPasswordHash(pw->NtLmSecureHash, password);

	return pw;
}

// Create a password authentication data for the hashed password
void *NewPasswordAuthDataRaw(UCHAR *hashed_password, UCHAR *ntlm_secure_hash)
{
	AUTHPASSWORD *pw;
	// Validate arguments
	if (hashed_password == NULL)
	{
		return NULL;
	}

	pw = ZeroMalloc(sizeof(AUTHPASSWORD));
	Copy(pw->HashedKey, hashed_password, SHA1_SIZE);

	if (ntlm_secure_hash != NULL)
	{
		Copy(pw->NtLmSecureHash, ntlm_secure_hash, MD5_SIZE);
	}

	return pw;
}

// Clone authentication data
void *CopyAuthData(void *authdata, UINT authtype)
{
	AUTHPASSWORD *pw = (AUTHPASSWORD *)authdata;
	AUTHUSERCERT *usercert = (AUTHUSERCERT *)authdata;
	AUTHROOTCERT *rootcert = (AUTHROOTCERT *)authdata;
	AUTHRADIUS *radius = (AUTHRADIUS *)authdata;
	AUTHNT *nt = (AUTHNT *)authdata;
	// Validate arguments
	if (authdata == NULL || authtype == AUTHTYPE_ANONYMOUS)
	{
		return NULL;
	}

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		{
			AUTHPASSWORD *ret = ZeroMalloc(sizeof(AUTHPASSWORD));
			Copy(ret, pw, sizeof(AUTHPASSWORD));
			return ret;
		}
		break;

	case AUTHTYPE_USERCERT:
		{
			AUTHUSERCERT *ret = ZeroMalloc(sizeof(AUTHUSERCERT));
			ret->UserX = CloneX(usercert->UserX);
			return ret;
		}
		break;

	case AUTHTYPE_ROOTCERT:
		{
			AUTHROOTCERT *ret = ZeroMalloc(sizeof(AUTHROOTCERT));
			ret->CommonName = CopyUniStr(rootcert->CommonName);
			ret->Serial = CloneXSerial(rootcert->Serial);
			return ret;
		}
		break;

	case AUTHTYPE_RADIUS:
		{
			AUTHRADIUS *ret = ZeroMalloc(sizeof(AUTHRADIUS));
			ret->RadiusUsername = UniCopyStr(radius->RadiusUsername);
			return ret;
		}
		break;

	case AUTHTYPE_NT:
		{
			AUTHNT *ret = ZeroMalloc(sizeof(AUTHNT));
			ret->NtUsername = UniCopyStr(nt->NtUsername);
			return ret;
		}
		break;
	}

	return NULL;
}

// Set authentication data to the user
void SetUserAuthData(USER *u, UINT authtype, void *authdata)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}
	if (authtype != AUTHTYPE_ANONYMOUS && authdata == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		if (u->AuthType != AUTHTYPE_ANONYMOUS)
		{
			if (u->AuthType == AUTHTYPE_PASSWORD && authtype == AUTHTYPE_PASSWORD)
			{
				AUTHPASSWORD *pw_old = (AUTHPASSWORD *)u->AuthData;
				AUTHPASSWORD *pw_new = (AUTHPASSWORD *)authdata;

				// Copy NTLM hash for new password from old data, if the password is not changed 
				// and management tool don't send NTLM hash.

				if (Cmp(pw_old->HashedKey, pw_new->HashedKey, SHA1_SIZE) == 0)
				{
					if (IsZero(pw_new->NtLmSecureHash, MD5_SIZE))
					{
						Copy(pw_new->NtLmSecureHash, pw_old->NtLmSecureHash, MD5_SIZE);
					}
				}
			}

			// Free current authentication data
			FreeAuthData(u->AuthType, u->AuthData);
		}
		// Set new authentication data
		u->AuthType = authtype;
		u->AuthData = authdata;
	}
	Unlock(u->lock);
}

// Cumulate group traffic data
void AddGroupTraffic(USERGROUP *g, TRAFFIC *diff)
{
	// Validate arguments
	if (g == NULL || diff == NULL)
	{
		return;
	}

	Lock(g->lock);
	{
		AddTraffic(g->Traffic, diff);
	}
	Unlock(g->lock);
}

// Cumulate user traffic data
void AddUserTraffic(USER *u, TRAFFIC *diff)
{
	// Validate arguments
	if (u == NULL || diff == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		AddTraffic(u->Traffic, diff);
	}
	Unlock(u->lock);
}

// Set traffic data for group
void SetGroupTraffic(USERGROUP *g, TRAFFIC *t)
{
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	Lock(g->lock);
	{
		if (t != NULL)
		{
			Copy(g->Traffic, t, sizeof(TRAFFIC));
		}
		else
		{
			Zero(g->Traffic, sizeof(TRAFFIC));
		}
	}
	Unlock(g->lock);
}

// Set traffic data for user
void SetUserTraffic(USER *u, TRAFFIC *t)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		if (t != NULL)
		{
			Copy(u->Traffic, t, sizeof(TRAFFIC));
		}
		else
		{
			Zero(u->Traffic, sizeof(TRAFFIC));
		}
	}
	Unlock(u->lock);
}

// Join the user to the group
void JoinUserToGroup(USER *u, USERGROUP *g)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	if (g != NULL)
	{
		// Join
		Lock(u->lock);
		{
			Lock(g->lock);
			{
				if (u->Group != NULL)
				{
					// Remove the user from current group first
					// 
					ReleaseGroup(u->Group);
					u->Group = NULL;
					Free(u->GroupName);
					u->GroupName = NULL;
				}
				// Join the user to the group
				u->GroupName = CopyStr(g->Name);
				u->Group = g;
				AddRef(g->ref);
			}
			Unlock(g->lock);
		}
		Unlock(u->lock);
	}
	else
	{
		// Withdrawal
		Lock(u->lock);
		{
			if (u->Group != NULL)
			{
				// Remove the user from current group
				ReleaseGroup(u->Group);
				u->Group = NULL;
				Free(u->GroupName);
				u->GroupName = NULL;
			}
		}
		Unlock(u->lock);
	}
}

// Validate group name
bool AcIsGroup(HUB *h, char *name)
{
	USERGROUP *g;
	// Validate arguments
	if (h == NULL || name == NULL || NO_ACCOUNT_DB(h))
	{
		return false;
	}

	g = AcGetGroup(h, name);
	if (g == NULL)
	{
		return false;
	}
	ReleaseGroup(g);

	return true;
}

// Validate user name
bool AcIsUser(HUB *h, char *name)
{
	USER *u;
	// Validate arguments
	if (h == NULL || name == NULL || NO_ACCOUNT_DB(h))
	{
		return false;
	}

	u = AcGetUser(h, name);
	if (u == NULL)
	{
		return false;
	}
	ReleaseUser(u);

	return true;
}

// Get group object
USERGROUP *AcGetGroup(HUB *h, char *name)
{
	USERGROUP *g, t;
	// Validate arguments
	if (h == NULL || name == NULL || NO_ACCOUNT_DB(h))
	{
		return NULL;
	}

	t.Name = name;
	g = Search(h->HubDb->GroupList, &t);
	if (g == NULL)
	{
		return NULL;
	}
	AddRef(g->ref);

	return g;
}

// Get user object
USER *AcGetUser(HUB *h, char *name)
{
	USER *u, t;
	// Validate arguments
	if (h == NULL || name == NULL || NO_ACCOUNT_DB(h))
	{
		return NULL;
	}

	t.Name = name;
	u = Search(h->HubDb->UserList, &t);
	if (u == NULL)
	{
		return NULL;
	}
	AddRef(u->ref);

	return u;
}

// Delete the user
bool AcDeleteUser(HUB *h, char *name)
{
	USER *u;
	// Validate arguments
	if (h == NULL || name == NULL)
	{
		return false;
	}

	u = AcGetUser(h, name);
	if (u == NULL)
	{
		return false;
	}

	if (Delete(h->HubDb->UserList, u))
	{
		ReleaseUser(u);
	}

	ReleaseUser(u);

	return true;
}

// Delete the group
bool AcDeleteGroup(HUB *h, char *name)
{
	USERGROUP *g;
	UINT i;
	// Validate arguments
	if (h == NULL || name == NULL)
	{
		return false;
	}

	g = AcGetGroup(h, name);
	if (g == NULL)
	{
		return false;
	}

	if (Delete(h->HubDb->GroupList, g))
	{
		ReleaseGroup(g);
	}

	for (i = 0;i < LIST_NUM(h->HubDb->UserList);i++)
	{
		USER *u = LIST_DATA(h->HubDb->UserList, i);
		Lock(u->lock);
		{
			if (u->Group == g)
			{
				JoinUserToGroup(u, NULL);
			}
		}
		Unlock(u->lock);
	}

	ReleaseGroup(g);

	return true;
}

// Add new group to the hub
bool AcAddGroup(HUB *h, USERGROUP *g)
{
	// Validate arguments
	if (h == NULL || g == NULL || NO_ACCOUNT_DB(h))
	{
		return false;
	}

	if (LIST_NUM(h->HubDb->GroupList) >= MAX_GROUPS)
	{
		return false;
	}

	if (AcIsGroup(h, g->Name) != false)
	{
		return false;
	}

	Insert(h->HubDb->GroupList, g);
	AddRef(g->ref);

	return true;
}

// Add new user in the hub
bool AcAddUser(HUB *h, USER *u)
{
	// Validate arguments
	if (h == NULL || u == NULL || NO_ACCOUNT_DB(h))
	{
		return false;
	}

	if (LIST_NUM(h->HubDb->UserList) >= MAX_USERS)
	{
		return false;
	}

	if (AcIsUser(h, u->Name) != false)
	{
		return false;
	}

	Insert(h->HubDb->UserList, u);
	AddRef(u->ref);

	return true;
}

// Release user object (decrease reference counter)
void ReleaseUser(USER *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	if (Release(u->ref) == 0)
	{
		CleanupUser(u);
	}
}

// Cleanup the user object 
void CleanupUser(USER *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	DeleteLock(u->lock);
	Free(u->Name);
	Free(u->RealName);
	Free(u->Note);
	Free(u->GroupName);
	if (u->Group != NULL)
	{
		ReleaseGroup(u->Group);
	}

	// Free authntication data
	FreeAuthData(u->AuthType, u->AuthData);

	if (u->Policy)
	{
		// Free policy data
		Free(u->Policy);
	}

	FreeTraffic(u->Traffic);

	Free(u);
}

// Free authntication data
void FreeAuthData(UINT authtype, void *authdata)
{
	AUTHPASSWORD *pw = (AUTHPASSWORD *)authdata;
	AUTHUSERCERT *uc = (AUTHUSERCERT *)authdata;
	AUTHROOTCERT *rc = (AUTHROOTCERT *)authdata;
	AUTHRADIUS *rd = (AUTHRADIUS *)authdata;
	AUTHNT *nt = (AUTHNT *)authdata;
	// Validate arguments
	if (authtype == AUTHTYPE_ANONYMOUS || authdata == NULL)
	{
		return;
	}

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		// Password authentication
		// Nothing to free
		break;

	case AUTHTYPE_USERCERT:
		// User certification
		FreeX(uc->UserX);
		break;

	case AUTHTYPE_ROOTCERT:
		// Root certification
		if (rc->Serial != NULL)
		{
			FreeXSerial(rc->Serial);
		}
		if (rc->CommonName != NULL)
		{
			Free(rc->CommonName);
		}
		break;

	case AUTHTYPE_RADIUS:
		// Radius authentication
		Free(rd->RadiusUsername);
		break;

	case AUTHTYPE_NT:
		// Windows NT authentication
		Free(nt->NtUsername);
		break;
	}

	Free(authdata);
}

// Create new user object
USER *NewUser(char *name, wchar_t *realname, wchar_t *note, UINT authtype, void *authdata)
{
	USER *u;
	// Validate arguments
	if (name == NULL || realname == NULL || note == NULL)
	{
		return NULL;
	}
	if (authtype != AUTHTYPE_ANONYMOUS && authdata == NULL)
	{
		return NULL;
	}

	u = ZeroMalloc(sizeof(USER));
	u->lock = NewLock();
	u->ref = NewRef();
	u->Name = CopyStr(name);
	u->RealName = CopyUniStr(realname);
	u->Note = CopyUniStr(note);
	u->GroupName = NULL;
	u->Group = NULL;
	u->AuthType = authtype;
	u->AuthData = authdata;
	u->CreatedTime = SystemTime64();
	u->UpdatedTime = SystemTime64();

	u->Policy = NULL;
	u->Traffic = NewTraffic();

	return u;
}

// Release group object (decrease reference counter)
void ReleaseGroup(USERGROUP *g)
{
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	if (Release(g->ref) == 0)
	{
		CleanupGroup(g);
	}
}

// Cleanup the group object
void CleanupGroup(USERGROUP *g)
{
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	Free(g->Name);
	Free(g->RealName);
	Free(g->Note);

	if (g->Policy)
	{
		// Free policy data
		Free(g->Policy);
	}


	FreeTraffic(g->Traffic);

	DeleteLock(g->lock);
	Free(g);
}

// Create new group object
USERGROUP *NewGroup(char *name, wchar_t *realname, wchar_t *note)
{
	USERGROUP *g;
	// Validate arguments
	if (name == NULL || realname == NULL || note == NULL)
	{
		return NULL;
	}

	g = ZeroMalloc(sizeof(USERGROUP));
	g->lock = NewLock();
	g->ref = NewRef();
	g->Name = CopyStr(name);
	g->RealName = CopyUniStr(realname);
	g->Note = CopyUniStr(note);
	g->Policy = NULL;
	g->Traffic = NewTraffic();

	return g;
}

// Lock the account database for the hub
void AcLock(HUB *h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}
	if (NO_ACCOUNT_DB(h))
	{
		return;
	}

	// Lock group list and user list
	LockList(h->HubDb->GroupList);
	LockList(h->HubDb->UserList);
}

// Unlock the account database for the hub
void AcUnlock(HUB *h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}
	if (NO_ACCOUNT_DB(h))
	{
		return;
	}

	// Unlock group list and user list
	UnlockList(h->HubDb->UserList);
	UnlockList(h->HubDb->GroupList);
}

// Compare group names (for sort)
int CompareGroupName(void *p1, void *p2)
{
	USERGROUP *g1, *g2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	g1 = *(USERGROUP **)p1;
	g2 = *(USERGROUP **)p2;
	if (g1 == NULL || g2 == NULL)
	{
		return 0;
	}

	return StrCmpi(g1->Name, g2->Name);
}

// Compare user names (for sort)
int CompareUserName(void *p1, void *p2)
{
	USER *u1, *u2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	u1 = *(USER **)p1;
	u2 = *(USER **)p2;
	if (u1 == NULL || u2 == NULL)
	{
		return 0;
	}

	return StrCmpi(u1->Name, u2->Name);
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
