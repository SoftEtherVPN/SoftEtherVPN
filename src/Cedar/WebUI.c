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
// Author: Tetsuo Sugiyama
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


// WebUI.c
// Web User Interface module

#include "CedarPch.h"

static WU_CONTEXT *WuNewContext(WEBUI *wu, char *hubname);
static void WuFreeContext(WU_CONTEXT *context);
static WU_WEBPAGE *WuNewUniWebPage(wchar_t *content);
static WU_WEBPAGE *WuNewWebPage(char *content, UINT size, char *filename);
static wchar_t *WuErrorPage(UINT errorcode);
static wchar_t *WuRedirectPage(char *url);
static wchar_t *WuUniReadFile(char *filename);
static void WuUniReplace(wchar_t **buf, wchar_t *from, wchar_t *to);
static void WuUniInsertBefore(wchar_t **buf, wchar_t *insert, wchar_t *before);
static LIST *WuAnalyzeTarget(char *target,char *filename, UINT size);
static void WuFreeStrStrMap(LIST *params);
static void WuEnableTag(wchar_t **buf, wchar_t *keyword);
static char *WuNewSessionKey();
static void WuUniStrReplace(wchar_t **buf, wchar_t *from, char *to);
static wchar_t *WuUniGetTemplate(wchar_t **str, wchar_t *start, wchar_t *end, bool erase);
static void WuUniUintReplace(wchar_t **buf, wchar_t *key, UINT num);
static void WuUniUint64Replace(wchar_t **buf, wchar_t *key, UINT64 num);
static wchar_t *WuUniGetTemplate(wchar_t **str, wchar_t *start, wchar_t *end, bool erase);
static LIST *WuUniMakeTable(wchar_t *def);
static LIST *WuUniMakeTableFromTemplate(wchar_t **str, wchar_t *start, wchar_t *end);
static void WuExpireSessionKey(WEBUI *wu);
static WU_CONTEXT *WuGetContext(LIST *contexts, char *sessionkey);

#define WP_DEFAULT		"/webui/"
#define WP_LOGIN		"/webui/login.cgi"
#define WP_REDIRECT		"/webui/redirect.cgi"
#define WP_ERROR		"/webui/error.cgi"
#define WP_SERVER		"/webui/server.cgi"
#define WP_LISTENER		"/webui/listener.cgi"
#define WP_HUB			"/webui/hub.cgi"
#define WP_USER			"/webui/user.cgi"
#define WP_EDITUSER		"/webui/edituser.cgi"
#define WP_NEWHUB		"/webui/newhub.cgi"
#define WP_LICENSE		"/webui/license.cgi"
#define WP_LOCALBRIDGE	"/webui/localbridge.cgi"
#define WP_SECURENAT	"/webui/securenat.cgi"
#define WP_SESSION		"/webui/session.cgi"

static wchar_t *WpDefault(WEBUI *wu, LIST *params);
static wchar_t *WpLogin(WEBUI *wu, LIST *params);
static wchar_t *WpServer(WEBUI *wu, LIST *params);
static wchar_t *WpListener(WEBUI *wu, LIST *params);
static wchar_t *WpHub(WEBUI *wu, LIST *params);
static wchar_t *WpUser(WEBUI *wu, LIST *params);
static wchar_t *WpEditUser(WEBUI *wu, LIST *params);
static wchar_t *WpNewHub(WEBUI *wu, LIST *params);
static wchar_t *WpLicense(WEBUI *wu, LIST *params);
static wchar_t *WpLocalBridge(WEBUI *wu, LIST *params);
static wchar_t *WpSecureNAT(WEBUI *wu, LIST *params);
static wchar_t *WpSession(WEBUI *wu, LIST *params);

// WebUI page handler table
static STRMAP_ENTRY wu_pages[] = {
	{WP_DEFAULT, WpDefault},
	{WP_LOGIN, WpLogin},
	{WP_SERVER, WpServer},
	{WP_LISTENER, WpListener},
	{WP_HUB, WpHub},
	{WP_USER, WpUser},
	{WP_EDITUSER, WpEditUser},
	{WP_NEWHUB, WpNewHub},
	{WP_LICENSE, WpLicense},
	{WP_LOCALBRIDGE, WpLocalBridge},
	{WP_SECURENAT, WpSecureNAT},
	{WP_SESSION, WpSession},
};

// **** Page handlers

// Redirect the directory access to the login screen
static wchar_t *WpDefault(WEBUI *wu, LIST *params)
{
	return WuRedirectPage(WP_LOGIN);
}

// Login page
static wchar_t *WpLogin(WEBUI *wu, LIST *params)
{
	UINT result;
	char random[20], securepass[SHA1_SIZE];
	char *password = (char*)StrMapSearch(params, "PASS");
	char *hubname = (char*)StrMapSearch(params, "HUB");

	if(password == NULL)
	{
		wchar_t *buf = WuUniReadFile("|"WP_LOGIN);
		WuUniStrReplace(&buf, L"ACTION", WP_LOGIN);
		WuUniStrReplace(&buf, L"HUBNAME", hubname == NULL ? "" : hubname);
		return buf;
	}

	// Administrator authentication
	Rand(random,sizeof(random));
	Hash(securepass, password, StrLen(password), true);
	SecurePassword(securepass, securepass, random);
	result = AdminCheckPassword(wu->Cedar, random, securepass, hubname, false, NULL);

	if(result == ERR_NO_ERROR)
	{
		// Successful login
		char tmp[MAX_SIZE];
		STRMAP_ENTRY *context;

		// Create a new context
		context = Malloc(sizeof(STRMAP_ENTRY));
		context->Name = WuNewSessionKey();
		context->Value = WuNewContext(wu, hubname);
		Add(wu->Contexts, context);

		// Transfer to the server management screen
		Format(tmp, sizeof(tmp), "%s?KEY=%s", WP_SERVER, context->Name);
		return WuRedirectPage(tmp);
	}else{
		// Login failure
		wchar_t *buf = WuUniReadFile("|"WP_LOGIN);
		WuUniStrReplace(&buf, L"ACTION", WP_LOGIN);
		WuUniStrReplace(&buf, L"HUBNAME",hubname == NULL ? "" : hubname);
		WuUniReplace(&buf, L"<!--ERR1-->", GetUniErrorStr(result));
		return buf;
	}
}

// Server management
static wchar_t *WpServer(WEBUI *wu, LIST *params)
{
	char *sessionkey = (char*)StrMapSearch(params, "KEY");
	WU_CONTEXT *context = WuGetContext(wu->Contexts, sessionkey);
	UINT i;
	wchar_t *buf;
	LIST *strmap;

	if(context == NULL)
	{
		return WuRedirectPage(WP_LOGIN);
	}

	buf = WuUniReadFile("|"WP_SERVER);
	strmap = WuUniMakeTableFromTemplate(&buf, L"<!--STRMAP:", L":STRMAP-->");

	// Show the Virtual HUB list
	{
		wchar_t *tmpl = WuUniGetTemplate(&buf, L"<!--HUBS_TMPL:", L":HUBS_TMPL-->", true);
		RPC_ENUM_HUB t;

		t.Hubs = NULL;
		StEnumHub(context->Admin, &t);
		for(i=0; i<t.NumHub; i++)
		{
			wchar_t *tmp = UniCopyStr(tmpl);
			wchar_t lastlogin[MAX_SIZE], lastcomm[MAX_SIZE];
			RPC_ENUM_HUB_ITEM *item = &t.Hubs[i];

			GetDateTimeStr64Uni(lastlogin,sizeof(lastlogin), SystemToLocal64(item->LastLoginTime));
			GetDateTimeStr64Uni(lastcomm, sizeof(lastcomm), SystemToLocal64(item->LastCommTime));
			WuUniStrReplace(&tmp, L"{HUBNAME}", item->HubName);
			WuUniReplace(&tmp, L"{HUBSTATE}", item->Online ? StrMapSearch(strmap, "HUB_ONLINE") : StrMapSearch(strmap, "HUB_OFFLINE"));
			WuUniReplace(&tmp, L"{HUBTYPE}", item->HubType == HUB_TYPE_STANDALONE ? StrMapSearch(strmap, "HUB_STANDALONE") 
				: item->HubType == HUB_TYPE_FARM_DYNAMIC ? StrMapSearch(strmap,"HUB_DYNAMIC") : StrMapSearch(strmap, "HUB_STATIC"));
			WuUniUintReplace(&tmp, L"{HUBUSERS}", item->NumUsers);
			WuUniUintReplace(&tmp, L"{HUBGROUPS}", item->NumGroups);
			WuUniUintReplace(&tmp, L"{HUBSESSIONS}", item->NumSessions);
			WuUniUintReplace(&tmp, L"{HUBMACS}", item->NumMacTables);
			WuUniUintReplace(&tmp, L"{HUBIPS}", item->NumIpTables);
			WuUniUintReplace(&tmp, L"{HUBLOGINS}", item->NumLogin);
			WuUniReplace(&tmp, L"{HUBLASTLOGINDATE}", lastlogin);
			WuUniReplace(&tmp, L"{HUBLASTCOMMDATE}", lastcomm);

			WuUniInsertBefore(&buf, tmp, L"<!--HUBS-->");
			Free(tmp);
		}
		FreeRpcEnumHub(&t);
		Free(tmpl);
	}

	// Show the listener list
	{
		RPC_LISTENER_LIST t;
		wchar_t *tmpl = WuUniGetTemplate(&buf, L"<!--LISTENER_TMPL:", L":LISTENER_TMPL-->", true);
		Zero(&t, sizeof(t));
		StEnumListener(context->Admin, &t);
		for(i=0; i<t.NumPort; i++)
		{			
			wchar_t *tmp = UniCopyStr(tmpl);
			WuUniReplace(&tmp, L"{PORT_STATE}", t.Enables[i] == false ? StrMapSearch(strmap,"LISTENER_OFFLINE")
				: t.Errors[i] == true ? StrMapSearch(strmap,"LISTENER_ERROR") : StrMapSearch(strmap, "LISTENER_ONLINE"));
			WuUniUintReplace(&tmp, L"{PORTNUM}", t.Ports[i]);
			WuEnableTag(&tmp, t.Enables[i] ? L"STOPA" : L"STARTA");
			WuUniInsertBefore(&buf, tmp, L"<!--LISTENERS-->");
			Free(tmp);
		}
		FreeRpcListenerList(&t);
		Free(tmpl);
	}
	WuUniStrReplace(&buf, L"{LINK_HUB}", WP_HUB);
	WuUniStrReplace(&buf, L"{SESSIONKEY}", sessionkey);
	WuUniStrReplace(&buf, L"{LISTENER_LINK}", WP_LISTENER);
	WuUniStrReplace(&buf, L"{LINK_NEWHUB}", WP_NEWHUB);
	WuUniStrReplace(&buf, L"{LINK_SERVER}", WP_SERVER);
	WuUniStrReplace(&buf, L"{LINK_LICENSE}", WP_LICENSE);
	WuUniStrReplace(&buf, L"{LINK_LOCALBRIDGE}", WP_LOCALBRIDGE);

	WuFreeStrStrMap(strmap);

	return buf;
}

// Listener management
static wchar_t *WpListener(WEBUI *wu, LIST *params)
{
	char *sessionkey = (char*)StrMapSearch(params, "KEY");
	WU_CONTEXT *context = WuGetContext(wu->Contexts, sessionkey);
	char *cmd = (char*)StrMapSearch(params, "CMD");
	RPC_LISTENER t;
	UINT retcode;

	if(context == NULL)
	{
		return WuRedirectPage(WP_LOGIN);
	}

	t.Port = ToInt((char*)StrMapSearch(params, "PORT"));

	if( StrCmp(cmd, "CREATE") == 0 )
	{
		//  Create a new listener
		if(t.Port == 0)
		{
			wchar_t *buf = WuUniReadFile("|"WP_LISTENER);
			WuUniStrReplace(&buf, L"ACTION", WP_LISTENER);
			WuUniStrReplace(&buf, L"SESSIONKEY", sessionkey);
			return buf;
		}
		else
		{
			t.Enable = true;
			retcode = StCreateListener(context->Admin, &t);
		}
	}
	else if( StrCmp(cmd, "DEL")==0 )
	{
		retcode = StDeleteListener(context->Admin, &t);
	}
	else if(StrCmp(cmd, "START")==0 )
	{
		t.Enable = true;
		retcode = StEnableListener(context->Admin, &t);
	}
	else if(StrCmp(cmd, "STOP")==0 )
	{
		t.Enable = false;
		retcode = StEnableListener(context->Admin, &t);
	}

	if(retcode == ERR_NO_ERROR)
	{
		char tmp[MAX_SIZE];
		Format(tmp, sizeof(tmp), "%s?KEY=%s", WP_SERVER, sessionkey);
		return WuRedirectPage(tmp);
	}
	return WuErrorPage(retcode);
}

// Virtual HUB management
static wchar_t *WpHub(WEBUI *wu, LIST *params)
{
	char *hubname = (char*)StrMapSearch(params, "HUB");
	char *sessionkey = (char*)StrMapSearch(params, "KEY");
	char *cmd  = (char*)StrMapSearch(params, "CMD");
	WU_CONTEXT *context = WuGetContext(wu->Contexts, sessionkey);

	// Confirm the session
	if(context == NULL)
	{
		return WuRedirectPage(WP_LOGIN);
	}

	if(StrCmp(cmd, "ONLINE") == 0 || StrCmp(cmd, "OFFLINE") == 0)
	{
		// Online / offline switching
		UINT retcode;
		RPC_SET_HUB_ONLINE t;
		StrCpy(t.HubName, sizeof(t.HubName), hubname);
		t.Online  = (StrCmp(cmd, "ONLINE") == 0) ? true : false;
		retcode = StSetHubOnline(context->Admin, &t);
		if(retcode == ERR_NO_ERROR){
			char tmp[MAX_SIZE];
			Format(tmp, sizeof(tmp), "%s?HUB=%s&KEY=%s", WP_HUB, hubname, sessionkey);
			return WuRedirectPage(tmp);
		}else{
			return WuErrorPage(retcode);
		}
	}
	else if(StrCmp(cmd, "DELETE") == 0)
	{
		// Delete the Virtual HUB
		RPC_DELETE_HUB t;
		UINT retcode;
		StrCpy(t.HubName, sizeof(t.HubName), hubname);
		retcode = StDeleteHub(context->Admin, &t);
		if(retcode == ERR_NO_ERROR)
		{
			char tmp[MAX_SIZE];
			Format(tmp, sizeof(tmp), "%s?KEY=%s", WP_SERVER, sessionkey);
			return WuRedirectPage(tmp);
		}
		return WuErrorPage(retcode);
	}
	else
	{
		// Show the status and commands of the virtual HUB
		RPC_HUB_STATUS t;
		UINT retcode;
		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), hubname);
		retcode = StGetHubStatus(context->Admin, &t);
		if(retcode == ERR_NO_ERROR)
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t *buf = WuUniReadFile("|"WP_HUB);
			LIST *strmap = WuUniMakeTableFromTemplate(&buf, L"<!--STRMAP:", L":STRMAP-->");

			WuUniStrReplace(&buf, L"{HUBNAME}", t.HubName);
			WuUniReplace(&buf, L"{HUBSTATE}", StrMapSearch(strmap, t.Online == false ? "HUB_OFFLINE" : "HUB_ONLINE"));
			WuUniReplace(&buf, L"{HUBTYPE}", GetHubTypeStr(t.HubType));
			WuUniReplace(&buf, L"{HUBSNAT}", StrMapSearch(strmap, t.SecureNATEnabled == false ? "SECNAT_OFF" : "SECNAT_ON"));
			WuUniUintReplace(&buf, L"{HUBSESSIONS}", t.NumSessions);
			WuUniUintReplace(&buf, L"{HUBACLS}", t.NumAccessLists);
			WuUniUintReplace(&buf, L"{HUBUSERS}", t.NumUsers);
			WuUniUintReplace(&buf, L"{HUBGROUPS}", t.NumGroups);
			WuUniUintReplace(&buf, L"{HUBMACTBLS}", t.NumMacTables);
			WuUniUintReplace(&buf, L"{HUBIPTBLS}", t.NumIpTables);
			WuUniUintReplace(&buf, L"{HUBLOGINS}", t.NumLogin);
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastLoginTime));
			WuUniReplace(&buf, L"{HUBLASTLOGIN}", tmp);
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastCommTime));
			WuUniReplace(&buf, L"{HUBLASTCOMM}", tmp);
			WuUniUint64Replace(&buf, L"{HUBTXUNIPKTS}", t.Traffic.Send.UnicastCount);
			WuUniUint64Replace(&buf, L"{HUBTXUNISIZE}", t.Traffic.Send.UnicastBytes);
			WuUniUint64Replace(&buf, L"{HUBTXBRPKTS}", t.Traffic.Send.BroadcastCount);
			WuUniUint64Replace(&buf, L"{HUBTXBRSIZE}", t.Traffic.Send.BroadcastBytes);
			WuUniUint64Replace(&buf, L"{HUBRXUNIPKTS}", t.Traffic.Recv.UnicastCount);
			WuUniUint64Replace(&buf, L"{HUBRXUNISIZE}", t.Traffic.Recv.UnicastBytes);
			WuUniUint64Replace(&buf, L"{HUBRXBRPKTS}", t.Traffic.Recv.BroadcastCount);
			WuUniUint64Replace(&buf, L"{HUBRXBRSIZE}", t.Traffic.Recv.BroadcastBytes);

			WuEnableTag(&buf, t.Online ? L"ENABLE_OFFLINE" : L"ENABLE_ONLINE");

			WuUniStrReplace(&buf, L"{LINK_HUB}", WP_HUB);
			WuUniStrReplace(&buf, L"{LINK_USER}", WP_USER);
			WuUniStrReplace(&buf, L"{LINK_SERVER}", WP_SERVER);
			WuUniStrReplace(&buf, L"{LINK_SESSION}", WP_SESSION);
			WuUniStrReplace(&buf, L"{HUBNAME}", hubname);
			WuUniStrReplace(&buf, L"{SESSIONKEY}", sessionkey);
			WuUniStrReplace(&buf, L"{LINK_SECURENAT}", WP_SECURENAT);

			WuFreeStrStrMap(strmap);

			return buf;
		}else{
			return WuErrorPage(retcode);
		}
	}
}

// User list
static wchar_t *WpUser(WEBUI *wu, LIST *params)
{
	char *sessionkey = (char*)StrMapSearch(params, "KEY");
	WU_CONTEXT *context = WuGetContext(wu->Contexts, sessionkey);
	char *hubname = (char*)StrMapSearch(params, "HUB");
	char *cmd = (char*)StrMapSearch(params, "CMD");
	UINT retcode;
	RPC_ENUM_USER t;

	// Check the context
	if(context == NULL)
	{
		return WuRedirectPage(WP_LOGIN);
	}

	if(cmd != NULL && StrCmp(cmd, "DEL") == 0)
	{
		char *username = (char*)StrMapSearch(params, "USER");
		RPC_DELETE_USER t;
		UINT retcode;

		StrCpy(t.HubName, sizeof(t.HubName), hubname);
		StrCpy(t.Name, sizeof(t.Name), username);
		retcode = StDeleteUser(context->Admin, &t);
		if(retcode == ERR_NO_ERROR)
		{
			char tmp[MAX_SIZE];
			Format(tmp, sizeof(tmp), "%s?HUB=%s&KEY=%s", WP_USER, hubname, sessionkey);
			return WuRedirectPage(tmp);
		}else
		{
			return WuErrorPage(retcode);
		}
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), hubname);
	retcode = StEnumUser(context->Admin, &t);
	if(retcode == ERR_NO_ERROR)
	{
		UINT i;
		wchar_t *buf = WuUniReadFile("|"WP_USER);
		wchar_t *tmpl = WuUniGetTemplate(&buf, L"<!--USER_TMPL:", L"-->", true);
		wchar_t tmp[MAX_SIZE];
		wchar_t datestr[MAX_SIZE];

		for(i=0; i<t.NumUser; i++)
		{
			RPC_ENUM_USER_ITEM *item = &t.Users[i];
			GetDateTimeStr64Uni(datestr, sizeof(datestr), SystemToLocal64(item->LastLoginTime));
			UniFormat(tmp, sizeof(tmp), tmpl, item->Name, item->Name, item->Name, item->Realname, item->GroupName,
				item->Note, GetAuthTypeStr(item->AuthType), item->NumLogin, datestr);
			WuUniInsertBefore(&buf, tmp, L"<!--USERS-->");
		}
		WuUniStrReplace(&buf, L"{SESSIONKEY}", sessionkey);
		WuUniStrReplace(&buf, L"{HUBNAME}", hubname);
		WuUniStrReplace(&buf, L"{LINK_USER}", WP_USER);
		WuUniStrReplace(&buf, L"{LINK_EDITUSER}", WP_EDITUSER);
		WuUniStrReplace(&buf, L"{LINK_HUB}", WP_HUB);

		FreeRpcEnumUser(&t);
		Free(tmpl);
		return buf;
	}else{
		return WuErrorPage(retcode);
	}
}

// User edit page
static wchar_t *WpEditUser(WEBUI *wu, LIST *params)
{
	char *sessionkey = (char*)StrMapSearch(params, "KEY");
	WU_CONTEXT *context = WuGetContext(wu->Contexts, sessionkey);
	char *hubname = (char*)StrMapSearch(params, "HUB");
	char *username = (char*)StrMapSearch(params, "USER");
	char *cmd = (char*)StrMapSearch(params, "CMD");
	char tmp[MAX_SIZE];
	wchar_t utmp[MAX_SIZE];
	UINT retcode;
	RPC_SET_USER t;
	wchar_t *buf;

	// Check the context
	if(context == NULL)
	{
		return WuRedirectPage(WP_LOGIN);
	}

	if(cmd != NULL && (StrCmp(cmd, "SET") == 0 || StrCmp(cmd, "CREATE") == 0))
	{
		char *authtype = (char*)StrMapSearch(params, "AUTHTYPE");
		char *password = (char*)StrMapSearch(params, "PASSWORD");
		char *password2 = (char*)StrMapSearch(params, "PASSWORD2");
		bool create = (StrCmp(cmd, "CREATE") == 0);

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), username);
		StrCpy(t.HubName, sizeof(t.HubName), hubname);

		// Read the original user data in the case of edit mode.
		if(!create)
		{
			retcode = StGetUser(context->Admin, &t);
			if(retcode != ERR_NO_ERROR)
			{
				return WuErrorPage(retcode);
			}
		}

		// Set the authentication method
		if(StrCmp(authtype, "ANONYMOUS") == 0)
		{
			FreeAuthData(t.AuthType, t.AuthData);
			t.AuthType = AUTHTYPE_ANONYMOUS;
			t.AuthData = NULL;
		}
		else if(StrCmp(authtype, "PASSWORD") == 0)
		{
			if(StrCmp(password,password2) != 0)
			{
				// Password for confirmation is mismatched
				return WuErrorPage(ERR_INVALID_PARAMETER);
			}

			// If the password field has not changed, leave as is
			if(t.AuthType != AUTHTYPE_PASSWORD || StrCmp(password, WU_PASSWORD_NOCHANGE) != 0)
			{
				FreeAuthData(t.AuthType, t.AuthData);
				t.AuthType = AUTHTYPE_PASSWORD;
				t.AuthData = NewPasswordAuthData(username, password);
			}
		}
		else
		{
			// Parameters of the authentication method is invalid
			return WuErrorPage(ERR_INVALID_PARAMETER);
		}

		// Set the user information
		if(create)
		{
			retcode = StCreateUser(context->Admin, &t);
		}
		else
		{
			retcode = StSetUser(context->Admin, &t);
		}
		if(retcode != ERR_NO_ERROR)
		{
			return WuErrorPage(retcode);
		}

		Format(tmp, sizeof(tmp), "%s?KEY=%s&HUB=%s", WP_USER, sessionkey, hubname);
		return WuRedirectPage(tmp);
	}

	// Generate the user edit page
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), hubname);

	if( username == NULL )
	{
		t.AuthType = AUTHTYPE_PASSWORD;
	}else{
		UINT retcode;
		StrCpy(t.Name, sizeof(t.Name), username);
		retcode = StGetUser(context->Admin, &t);
		if(retcode != ERR_NO_ERROR)
		{
			return WuErrorPage(retcode);
		}
	}

	buf = WuUniReadFile("|"WP_EDITUSER);

	if( username == NULL)
	{
		WuEnableTag(&buf, L"{USERNAMEINPUT}");
		WuUniReplace(&buf, L"{USERNAME}", L"");
		WuUniReplace(&buf, L"{CMDNAME}", L"CREATE");
		WuUniReplace(&buf, L"{PASSWORD}", L"");
	}
	else
	{
		WuEnableTag(&buf, L"{USERNAMEHIDDEN}");
		WuUniStrReplace(&buf, L"{USERNAME}", username);
		WuUniReplace(&buf, L"{CMDNAME}", L"SET");
		WuUniStrReplace(&buf, L"{PASSWORD}", WU_PASSWORD_NOCHANGE);
	}

	// Select the authentication method
	if(t.AuthType == AUTHTYPE_ANONYMOUS)
	{
		WuUniReplace(&buf, L"{SELANONYM}", L"checked");
	}
	else
	{
		WuUniReplace(&buf, L"{SELANONYM}", L"");
		if(t.AuthType == AUTHTYPE_PASSWORD)
		{
			WuUniReplace(&buf, L"{SELPASSWD}", L"checked");
		}
		else
		{
			WuUniReplace(&buf, L"{SELPASSWD}", L"");
		}
	}

	WuUniReplace(&buf, L"{REALNAME}", t.Realname);
	WuUniReplace(&buf, L"{NOTETEXT}", t.Note);
	WuUniStrReplace(&buf, L"{GROUPNAME}", t.GroupName);
	GetDateTimeStr64Uni(utmp, sizeof(utmp), SystemToLocal64(t.ExpireTime));
	WuUniReplace(&buf, L"{EXPIREDATE}", utmp);

	WuUniStrReplace(&buf, L"{SESSIONKEY}", sessionkey);
	WuUniStrReplace(&buf, L"{HUBNAME}", hubname);
	WuUniStrReplace(&buf, L"{LINK_EDITUSER}", WP_EDITUSER);
	WuUniStrReplace(&buf, L"{LINK_USER}", WP_USER);

	return buf;
}

// Create a new Virtual HUB
static wchar_t *WpNewHub(WEBUI *wu, LIST *params)
{
	char *sessionkey = (char*)StrMapSearch(params, "KEY");
	WU_CONTEXT *context = WuGetContext(wu->Contexts, sessionkey);
	char *cmd = (char*)StrMapSearch(params, "CMD");
	wchar_t *buf;

	if(context == NULL)
	{
		return WuRedirectPage(WP_LOGIN);
	}

	if(StrCmp(cmd, "CREATE") == 0)
	{
		UINT retcode;
		char tmp[MAX_SIZE];
		RPC_CREATE_HUB t;
		RPC_SERVER_INFO t2;
		char *hubname = (char*)StrMapSearch(params, "NAME");
		char *passwd = (char*)StrMapSearch(params, "PASSWD");
		char *passwd2 = (char*)StrMapSearch(params, "PASSWD2");

		if(strcmp(passwd,passwd2) != 0)
		{
			return WuErrorPage(ERR_INVALID_PARAMETER);
		}

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), hubname);
		Hash(t.HashedPassword, passwd, StrLen(passwd), true);
		HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, passwd);
		t.Online = true;
		t.HubType = HUB_TYPE_STANDALONE;

		// Set to dynamic HUB in the case of cluster controller
		Zero(&t2, sizeof(t2));
		if (StGetServerInfo(context->Admin, &t2) == ERR_NO_ERROR)
		{
			if (t2.ServerType == SERVER_TYPE_FARM_CONTROLLER)
			{
				t.HubType = HUB_TYPE_FARM_DYNAMIC;
			}
			FreeRpcServerInfo(&t2);
		}
		
		retcode = StCreateHub(context->Admin, &t);
		if(retcode != ERR_NO_ERROR)
		{
			return WuErrorPage(retcode);
		}

		Format(tmp, sizeof(tmp), "%s?KEY=%s", WP_SERVER, sessionkey);
		return WuRedirectPage(tmp);
	}

	buf = WuUniReadFile("|"WP_NEWHUB);
	WuUniStrReplace(&buf, L"{SESSIONKEY}", sessionkey);
	WuUniStrReplace(&buf, L"{LINK_NEWHUB}", WP_NEWHUB);
	WuUniStrReplace(&buf, L"{LINK_SERVER}", WP_SERVER);
	return buf;
}

// License management page
static wchar_t *WpLicense(WEBUI *wu, LIST *params)
{
	char *sessionkey = (char*)StrMapSearch(params, "KEY");
	WU_CONTEXT *context = WuGetContext(wu->Contexts, sessionkey);
	char *cmd = (char*)StrMapSearch(params, "CMD");
	UINT retcode;
	wchar_t *buf;
	LIST *strmap;

	if(context == NULL)
	{
		return WuRedirectPage(WP_LOGIN);
	}

	// Add a license
	if(StrCmp(cmd, "ADD") == 0)
	{
		RPC_TEST t;
		char tmp[MAX_SIZE];
		char *licensekey = (char*)StrMapSearch(params, "KEYSTRINGS");


		Zero(&t, sizeof(t));
		StrCpy(t.StrValue, sizeof(t.StrValue), licensekey); 
		
		retcode = StAddLicenseKey(context->Admin, &t);
		if(retcode != ERR_NO_ERROR)
		{
			return WuErrorPage(retcode);
		}

		Format(tmp, sizeof(tmp), "%s?KEY=%s", WP_LICENSE, sessionkey);
		return WuRedirectPage(tmp);
		
	}
	// Remove the license
	else if(StrCmp(cmd, "DEL") == 0)
	{
		RPC_TEST t;
		char tmp[MAX_SIZE];
		char *id = (char*)StrMapSearch(params, "ID");

		Zero(&t, sizeof(t));
		t.IntValue = ToInt(id);
		
		retcode = StDelLicenseKey(context->Admin, &t);
		if(retcode != ERR_NO_ERROR)
		{
			return WuErrorPage(retcode);
		}

		Format(tmp, sizeof(tmp), "%s?KEY=%s", WP_LICENSE, sessionkey);
		return WuRedirectPage(tmp);
	}

	buf = WuUniReadFile("|"WP_LICENSE);
	strmap = WuUniMakeTableFromTemplate(&buf, L"<!--STRMAP:", L"-->");

	// Enumerate the license keys
	{
		UINT i;
		RPC_ENUM_LICENSE_KEY t;
		wchar_t *tmpl;
		Zero(&t, sizeof(t));

		retcode = StEnumLicenseKey(context->Admin, &t);

		if(retcode != ERR_NO_ERROR)
		{
			WuFreeStrStrMap(strmap);
			Free(buf);
			return WuErrorPage(retcode);
		}

		tmpl = WuUniGetTemplate(&buf, L"<!--LICENSES_TMPL:", L":LICENSES_TMPL-->", true);

		for(i = 0; i < t.NumItem; i++)
		{
			wchar_t *status, expires[128];
			wchar_t *tmp = UniCopyStr(tmpl);
			RPC_ENUM_LICENSE_KEY_ITEM *item = &t.Items[i];

			status = LiGetLicenseStatusStr(item->Status);

			if(item->Expires == 0)
			{
				UniStrCpy(expires, sizeof(expires), StrMapSearch(strmap, "EXPIRE_INFINITE"));
			}
			else
			{
				GetDateStrEx64(expires, sizeof(expires), item->Expires, NULL);
			}

			WuUniUintReplace(&tmp, L"{ID}", i);
			WuUniStrReplace(&tmp, L"{LICENSEKEY}", item->LicenseKey);
			WuUniStrReplace(&tmp, L"{LICENSENAME}", item->LicenseName);
			WuUniReplace(&tmp, L"{STATUS}", status);
			WuUniReplace(&tmp, L"{EXPIRES}", expires);
			WuUniStrReplace(&tmp, L"{LICENSEID}", item->LicenseId);
			WuUniUintReplace(&tmp, L"{PRODUCTID}", item->ProductId);
			WuUniUint64Replace(&tmp, L"{SYSTEMID}", item->SystemId);
			WuUniUintReplace(&tmp, L"{SERIALID}", item->SerialId);

			WuUniInsertBefore(&buf, tmp, L"<!--LICENSES-->");
			Free(tmp);
		}
		FreeRpcEnumLicenseKey(&t);
		Free(tmpl);
	}

	// Show the license status
	{	
		RPC_LICENSE_STATUS t;

		Zero(&t, sizeof(t));

		retcode = StGetLicenseStatus(context->Admin, &t);

		if(retcode != ERR_NO_ERROR)
		{
			WuFreeStrStrMap(strmap);
			Free(buf);
			return WuErrorPage(retcode);
		}

		WuUniStrReplace(&buf, L"{LSEDITIONNAME}", t.EditionStr);
		WuUniUint64Replace(&buf, L"{LSSERVERID}", t.SystemId);
		if(t.SystemExpires == 0)
		{
			WuUniReplace(&buf, L"{LSEXPIRES}", StrMapSearch(strmap, "NOEXPIRE"));
		}
		else
		{	
			wchar_t expires[128];
			GetDateStrEx64(expires, sizeof(expires), t.SystemExpires, NULL);
			WuUniReplace(&buf, L"{LSEXPIRES}", expires);
		}
		
		if(t.NumBridgeConnectLicense == INFINITE)
		{
			WuUniReplace(&buf, L"{LSNUMBRIDGES}", StrMapSearch(strmap, "LICENSE_INFINITE"));
		}
		else
		{
			WuUniUintReplace(&buf, L"{LSNUMBRIDGES}", t.NumBridgeConnectLicense);
		}

		if(t.NumClientConnectLicense == INFINITE)
		{
			WuUniReplace(&buf, L"{LSNUMCLIENTS}", StrMapSearch(strmap, "LICENSE_INFINITE"));
		}
		else
		{
			WuUniUintReplace(&buf, L"{LSNUMCLIENTS}", t.NumClientConnectLicense);
		}

	}

	WuUniStrReplace(&buf, L"{LINK_LICENSE}", WP_LICENSE);
	WuUniStrReplace(&buf, L"{LINK_SERVER}", WP_SERVER);
	WuUniStrReplace(&buf, L"{SESSIONKEY}", sessionkey);
	WuFreeStrStrMap(strmap);

	return buf;

}

// Local bridge setup page
static wchar_t *WpLocalBridge(WEBUI *wu, LIST *params)
{
	char *sessionkey = (char*)StrMapSearch(params, "KEY");
	WU_CONTEXT *context = WuGetContext(wu->Contexts, sessionkey);
	char *cmd = (char*)StrMapSearch(params, "CMD");
	UINT retcode;
	wchar_t *buf;
	LIST *strmap;

	if(context == NULL)
	{
		return WuRedirectPage(WP_LOGIN);
	}

	// Create a local bridge
	if(StrCmp(cmd, "CREATE") == 0)
	{
		RPC_LOCALBRIDGE t;
		RPC_ENUM_ETH eth;
		char tmp[MAX_SIZE];
		char *tapmode = (char*)StrMapSearch(params, "TAPMODE");
		char *tapname = (char*)StrMapSearch(params, "TAPNAME");
		char *devid = (char*)StrMapSearch(params, "DEVID");
		char *hubname = (char*)StrMapSearch(params, "LBHUBNAME");
		UINT id = ToInt(devid);

		Zero(&eth, sizeof(eth));
		retcode = StEnumEthernet(context->Admin, &eth);

		if(retcode != ERR_NO_ERROR)
		{
			FreeRpcEnumEth(&eth);
			return WuErrorPage(retcode);
		}

		Zero(&t, sizeof(t));
		t.Active = true;
		if(StrCmp(tapmode, "YES") == 0)
		{	
			t.TapMode = true;
			StrCpy(t.DeviceName, sizeof(t.DeviceName), tapname);
		}
		else
		{
			t.TapMode = false;
			StrCpy(t.DeviceName, sizeof(t.DeviceName), eth.Items[id].DeviceName);
		}
		StrCpy(t.HubName, sizeof(t.HubName), hubname);
		t.Online = true;
		FreeRpcEnumEth(&eth);

		retcode = StAddLocalBridge(context->Admin, &t);
		
		if(retcode != ERR_NO_ERROR)
		{
			return WuErrorPage(retcode);
		}

		Format(tmp, sizeof(tmp), "%s?KEY=%s", WP_LOCALBRIDGE, sessionkey);
		return WuRedirectPage(tmp);
	}

	// Delete the local bridge
	if(StrCmp(cmd, "DEL") == 0)
	{
		RPC_LOCALBRIDGE t;
		RPC_ENUM_LOCALBRIDGE et;
		char tmp[MAX_SIZE];
		char *listid = (char*)StrMapSearch(params, "LISTID");
		UINT id = ToInt(listid);

		Zero(&et, sizeof(et));
		retcode = StEnumLocalBridge(context->Admin, &et);
		if(retcode != ERR_NO_ERROR)
		{
			return WuErrorPage(retcode);
		}

		Zero(&t, sizeof(t));
		StrCpy(t.DeviceName, sizeof(t.DeviceName), et.Items[id].DeviceName);
		StrCpy(t.HubName, sizeof(t.HubName), et.Items[id].HubName);
		FreeRpcEnumLocalBridge(&et);
		
		retcode = StDeleteLocalBridge(context->Admin, &t);

		if(retcode != ERR_NO_ERROR)
		{
			return WuErrorPage(retcode);
		}

		Format(tmp, sizeof(tmp), "%s?KEY=%s", WP_LOCALBRIDGE, sessionkey);
		return WuRedirectPage(tmp);
	}

	// Show the current local bridge list and the Virtual HUB list and the device list to be bridged
	buf = WuUniReadFile("|"WP_LOCALBRIDGE);
	strmap = WuUniMakeTableFromTemplate(&buf, L"<!--STRMAP:", L"-->");

	// Show the current local bridge list
	{
		UINT i;
		RPC_ENUM_LOCALBRIDGE t;
		wchar_t *tmpl;

		Zero(&t, sizeof(t));
		retcode = StEnumLocalBridge(context->Admin, &t);

		if(retcode != ERR_NO_ERROR)
		{
			FreeRpcEnumLocalBridge(&t);
			Free(buf);
			WuFreeStrStrMap(strmap);
			return WuErrorPage(retcode);
		}

		tmpl = WuUniGetTemplate(&buf, L"<!--LBLIST_TMPL", L"LBLIST_TMPL-->", true);

		for(i = 0; i < t.NumItem; i++)
		{
			RPC_LOCALBRIDGE *item = &t.Items[i];
			wchar_t *tmp = UniCopyStr(tmpl);
			WuUniUintReplace(&tmp, L"{LISTID}", i);
			WuUniStrReplace(&tmp, L"{HUBNAME}", item->HubName);
			WuUniStrReplace(&tmp, L"{DEVICENAME}", item->DeviceName);
			WuUniReplace(&tmp, L"{STATUS}", item->Online ? item->Active ? StrMapSearch(strmap, "BRIDGE_ONLINE") 
				: StrMapSearch(strmap, "BRIDGE_ERROR") : StrMapSearch(strmap, "BRIDGE_OFFLINE"));
			WuUniInsertBefore(&buf, tmp, L"<!--LBLIST-->");
			Free(tmp);
		}
		Free(tmpl);
		FreeRpcEnumLocalBridge(&t);
	}

	// Show the Virtual HUB list
	{
		wchar_t *tmpl;
		RPC_ENUM_HUB t;
		UINT i;

		Zero(&t, sizeof(t));
		retcode = StEnumHub(context->Admin, &t);

		if(retcode != ERR_NO_ERROR)
		{
			FreeRpcEnumHub(&t);
			Free(buf);
			WuFreeStrStrMap(strmap);
			return WuErrorPage(retcode);
		}

		tmpl = WuUniGetTemplate(&buf, L"<!--HUBS_TMPL", L"HUBS_TMPL-->", true);
		for(i=0; i<t.NumHub; i++)
		{
			wchar_t *tmp = UniCopyStr(tmpl);
			WuUniStrReplace(&tmp, L"{LBHUBNAME}", t.Hubs[i].HubName);
			WuUniInsertBefore(&buf, tmp, L"<!--HUBS-->");
			Free(tmp);
		}
		FreeRpcEnumHub(&t);
		Free(tmpl);
	}

	// Get the device list to be bridge
	{
		UINT i;
		RPC_ENUM_ETH t;
		wchar_t *tmpl;

		Zero(&t, sizeof(t));
		retcode = StEnumEthernet(context->Admin, &t);

		if(retcode != ERR_NO_ERROR)
		{
			FreeRpcEnumEth(&t);
			Free(buf);
			WuFreeStrStrMap(strmap);
			return WuErrorPage(retcode);
		}

		tmpl = WuUniGetTemplate(&buf, L"<!--LBDEVLIST_TMPL", L"LBDEVLIST_TMPL-->", true);

		for(i = 0; i < t.NumItem; i++)
		{
			wchar_t *tmp = UniCopyStr(tmpl);
			WuUniUintReplace(&tmp, L"{DEVID}", i);
			WuUniStrReplace(&tmp, L"{ABLEDEVICE}", t.Items[i].DeviceName);
			WuUniInsertBefore(&buf, tmp, L"<!--LBDEVLIST-->");
			Free(tmp);
		}
		FreeRpcEnumEth(&t);
		Free(tmpl);
	}

	WuUniStrReplace(&buf, L"{LINK_LOCALBRIDGE}", WP_LOCALBRIDGE);
	WuUniStrReplace(&buf, L"{LINK_SERVER}", WP_SERVER);
	WuUniStrReplace(&buf, L"{SESSIONKEY}", sessionkey);
	WuFreeStrStrMap(strmap);

	return buf;

}

// Configure the virtual DHCP function and virtual NAT (SecureNAT)
static wchar_t *WpSecureNAT(WEBUI *wu, LIST *params)
{
	char *sessionkey = (char*)StrMapSearch(params, "KEY");

	WU_CONTEXT *context = WuGetContext(wu->Contexts, sessionkey);
	char *cmd = (char*)StrMapSearch(params, "CMD");
	char *hubname = (char*)StrMapSearch(params, "HUB");

	UINT retcode;
	wchar_t *buf;

	if(context == NULL)
	{
		return WuRedirectPage(WP_LOGIN);
	}

	// Enable / disable the SecureNAT function
	if(StrCmp(cmd, "ENABLE") == 0 || StrCmp(cmd, "DISABLE") == 0)
	{
		RPC_HUB t;
		char tmp[MAX_SIZE];

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), hubname);

		if(StrCmp(cmd, "ENABLE") == 0)
		{
			retcode = StEnableSecureNAT(context->Admin, &t);
		}
		else
		{
			retcode = StDisableSecureNAT(context->Admin, &t);
		}

		if(retcode != ERR_NO_ERROR)
		{
			return WuErrorPage(retcode);
		}

		Format(tmp, sizeof(tmp), "%s?HUB=%s&KEY=%s", WP_SECURENAT, hubname, sessionkey);
		return WuRedirectPage(tmp);
	}
	// Set the SecureNAT options
	else if(StrCmp(cmd, "SAVE") == 0)
	{
		char tmp[MAX_SIZE];
		VH_OPTION t;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), hubname);

		// Configure the a virtual host
		StrToMac(t.MacAddress, (char*)StrMapSearch(params, "HOSTMAC"));
		StrToIP(&t.Ip, (char*)StrMapSearch(params, "HOSTIP"));
		StrToIP(&t.Mask, (char*)StrMapSearch(params, "HOSTMASK"));

		// Configure the virtual NAT function
		t.UseNat = (StrCmp((char*)StrMapSearch(params, "NATCHECK"), "on") == 0);
		t.Mtu = ToInt((char*)StrMapSearch(params, "NATMTU"));
		t.NatTcpTimeout = ToInt((char*)StrMapSearch(params, "NATTCPTIMEOUT"));
		t.NatUdpTimeout = ToInt((char*)StrMapSearch(params, "NATUDPTIMEOUT"));
		t.SaveLog = (StrCmp((char*)StrMapSearch(params, "NATSAVELOG"), "on") == 0);

		// Configure the virtual DHCP server function
		t.UseDhcp = (StrCmp((char*)StrMapSearch(params, "DHCPCHECK"), "on") == 0);
		StrToIP(&t.DhcpLeaseIPStart, (char*)StrMapSearch(params, "DHCPIPS"));
		StrToIP(&t.DhcpLeaseIPEnd, (char*)StrMapSearch(params, "DHCPIPE"));
		StrToIP(&t.DhcpSubnetMask, (char*)StrMapSearch(params, "DHCPMASK"));
		t.DhcpExpireTimeSpan =  ToInt((char*)StrMapSearch(params, "DHCPEXPIRE"));
		StrToIP(&t.DhcpGatewayAddress, (char*)StrMapSearch(params, "DHCPGW"));
		StrToIP(&t.DhcpDnsServerAddress, (char*)StrMapSearch(params, "DHCPDNS"));
		StrCpy(t.DhcpDomainName, sizeof(t.DhcpDomainName), (char*)StrMapSearch(params, "DHCPDOMAIN"));

		retcode = StSetSecureNATOption(context->Admin, &t);
		if(retcode == ERR_NO_ERROR)
		{
			Format(tmp, sizeof(tmp), "%s?HUB=%s&KEY=%s", WP_SECURENAT, hubname, sessionkey);
			return WuRedirectPage(tmp);
		}
		return WuErrorPage(retcode);
	}

	buf = WuUniReadFile("|"WP_SECURENAT);

	// Get the enable / disable state of the current SecureNAT
	{
		RPC_HUB_STATUS t;
		Zero(&t, sizeof(&t));
		StrCpy(t.HubName, sizeof(t.HubName), hubname);

		retcode = StGetHubStatus(context->Admin, &t);

		if(retcode != ERR_NO_ERROR)
		{
			Free(buf);
			return WuErrorPage(retcode);
		}

		WuEnableTag(&buf, t.SecureNATEnabled ? L"DISABLESNAT" : L"ENABLESNAT");
	}

	// Show the advanced settings of the current SecureNAT
	{
		char mac[MAX_SIZE], ip[MAX_SIZE], mask[MAX_SIZE];
		char dhcpips[MAX_SIZE], dhcpipe[MAX_SIZE], dhcpmask[MAX_SIZE];
		char optgw[MAX_SIZE], optdns[MAX_SIZE];
		VH_OPTION t;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), hubname);

		retcode = StGetSecureNATOption(context->Admin, &t);


		// Configure the virtual interfaces
		MacToStr(mac, sizeof(mac), t.MacAddress);
		IPToStr(ip, sizeof(ip), &t.Ip);
		IPToStr(mask, sizeof(mask), &t.Mask);
		WuUniStrReplace(&buf, L"{HOSTMAC}", mac);
		WuUniStrReplace(&buf, L"{HOSTIP}", ip);
		WuUniStrReplace(&buf, L"{HOSTMASK}", mask);

		// Configure the Virtual NAT
		WuUniStrReplace(&buf, L"{NATCHECK}", t.UseNat ? "CHECKED" : "");
		WuUniUintReplace(&buf, L"{NATMTU}", t.Mtu);
		WuUniUintReplace(&buf, L"{NATTCPTIMEOUT}", t.NatTcpTimeout);
		WuUniUintReplace(&buf, L"{NATUDPTIMEOUT}", t.NatUdpTimeout);

		WuUniStrReplace(&buf, L"{NATSAVELOG}", t.SaveLog ? "CHECKED" : "");

		// Configure the Virtual DHCP server
		WuUniStrReplace(&buf, L"{DHCPCHECK}", t.UseDhcp ? "CHECKED" : "");

		IPToStr(dhcpips, sizeof(dhcpips), &t.DhcpLeaseIPStart);
		IPToStr(dhcpipe, sizeof(dhcpipe), &t.DhcpLeaseIPEnd);
		IPToStr(dhcpmask, sizeof(dhcpmask), &t.DhcpSubnetMask);
		WuUniStrReplace(&buf, L"{DHCPIPS}", dhcpips);
		WuUniStrReplace(&buf, L"{DHCPIPE}", dhcpipe);
		WuUniStrReplace(&buf, L"{DHCPMASK}", dhcpmask);
		WuUniUintReplace(&buf, L"{DHCPEXPIRE}", t.DhcpExpireTimeSpan);

		IPToStr(optgw, sizeof(optgw), &t.DhcpGatewayAddress);
		IPToStr(optdns, sizeof(optdns), &t.DhcpDnsServerAddress);
		WuUniStrReplace(&buf, L"{DHCPGW}", optgw);
		WuUniStrReplace(&buf, L"{DHCPDNS}", optdns);
		WuUniStrReplace(&buf, L"{DHCPDOMAIN}", t.DhcpDomainName);
	}

	WuUniStrReplace(&buf, L"{LINK_HUB}", WP_HUB);
	WuUniStrReplace(&buf, L"{LINK_SECURENAT}", WP_SECURENAT);
	WuUniStrReplace(&buf, L"{HUBNAME}", hubname);
	WuUniStrReplace(&buf, L"{SESSIONKEY}", sessionkey);

	return buf;
}

static wchar_t *WpSession(WEBUI *wu, LIST *params)
{
	char *sessionkey = (char*)StrMapSearch(params, "KEY");
	WU_CONTEXT *context = WuGetContext(wu->Contexts, sessionkey);
	char *hub = (char*)StrMapSearch(params, "HUB");
	char *cmd = (char*)StrMapSearch(params, "CMD");

	if(context == NULL)
	{
		return WuRedirectPage(WP_LOGIN);
	}

	if(StrCmp(cmd, "DEL") == 0)
	{
		char *session = (char*)StrMapSearch(params, "SESSION");
		RPC_DELETE_SESSION t;
		UINT retcode;
		char tmp[MAX_SIZE];

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), hub);
		StrCpy(t.Name, sizeof(t.Name), session);

		retcode = StDeleteSession(context->Admin, &t);
		if(retcode != ERR_NO_ERROR)
		{
			return WuErrorPage(retcode);
		}

		Format(tmp, sizeof(tmp), "%s?HUB=%s&KEY=%s", WP_SESSION, hub, session);
		return WuRedirectPage(tmp);
	}

	// Show the session list
	{
		RPC_ENUM_SESSION t;
		UINT retcode;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), hub);

		retcode = StEnumSession(context->Admin, &t);
		if(retcode != ERR_NO_ERROR)
		{
			return WuErrorPage(retcode);
		}else{
			wchar_t *buf = WuUniReadFile("|"WP_SESSION);
			wchar_t *tmpl = WuUniGetTemplate(&buf, L"<!--SESSION_TMPL:", L":SESSION_TMPL-->", true);
			UINT i;
			for(i=0; i<t.NumSession; i++){
				RPC_ENUM_SESSION_ITEM *item = &(t.Sessions[i]);
				wchar_t *tmp = CopyUniStr(tmpl);

				WuUniStrReplace(&tmp, L"{SESSION_NAME}", item->Name);
				WuUniStrReplace(&tmp, L"{SESSION_SERVER}", item->RemoteHostname);
				WuUniStrReplace(&tmp, L"{SESSION_USER}", item->Username);
				WuUniStrReplace(&tmp, L"{SESSION_HOST}", item->Hostname);
				WuUniUintReplace(&tmp, L"{SESSION_TCP}", item->CurrentNumTcp);
				WuUniUint64Replace(&tmp, L"{SESSION_BYTES}", item->PacketSize);
				WuUniUint64Replace(&tmp, L"{SESSION_PKTS}", item->PacketNum);
				WuUniStrReplace(&tmp, L"{SESSION}", item->Name);

				WuUniInsertBefore(&buf, tmp, L"<!--SESSIONS-->");
				Free(tmp);
			}

			WuUniStrReplace(&buf, L"{HUBNAME}", hub);
			WuUniStrReplace(&buf, L"{SESSIONKEY}", sessionkey);
			WuUniStrReplace(&buf, L"{LINK_HUB}", WP_HUB);
			WuUniStrReplace(&buf, L"{LINK_SESSION}", WP_SESSION);

			FreeRpcEnumSession(&t);
			Free(tmpl);
			return buf;
		}
	}
}


// **** Public interface of the WebUI module

// Get the page
WU_WEBPAGE *WuGetPage(char *target, WEBUI *wu)
{
	char filename[MAX_SIZE];
	LIST *params;
	wchar_t *(*handler)(WEBUI *wu, LIST *params);

	// Delete the expired session keys
	WuExpireSessionKey(wu);

	params = WuAnalyzeTarget(target, filename, sizeof(filename));

	// Search for the handler corresponding to the URL
	handler = StrMapSearch(wu->PageList, filename);

	// Call the handler
	if(handler != NULL)
	{
		wchar_t *unitmp;
		WU_WEBPAGE *page;
		unitmp = handler(wu, params);
		WuFreeStrStrMap(params);
		page = WuNewUniWebPage(unitmp);
		Free(unitmp);
		return page;
	}

	WuFreeStrStrMap(params);

	// If it missed, try to read the file directly
	if(StartWith(filename, WP_DEFAULT))
	{
		char tmp[MAX_SIZE] = "|";
		BUF *buf;
		WU_WEBPAGE *page;

		StrCat(tmp, sizeof(tmp), filename);
		buf = ReadDump(tmp);
		if(buf == NULL)
		{
			return NULL;
		}

		page = WuNewWebPage(buf->Buf, buf->Size, filename);
		FreeBuf(buf);
		return page;
	}

	return NULL;
}

// Start the WebUI
WEBUI *WuNewWebUI(CEDAR *cedar)
{
	WEBUI *wu = (WEBUI*)Malloc(sizeof(WEBUI));
	int i;

	wu->Cedar = cedar;

	wu->PageList = NewStrMap();
	for(i=0;i<sizeof(wu_pages)/sizeof(STRMAP_ENTRY);i++)
	{
		Add(wu->PageList, &wu_pages[i]);
	}

	wu->Contexts = NewStrMap();

	return wu;
}

// Release the WebUI
bool WuFreeWebUI(WEBUI *wu)
{
	UINT i;

	if(wu == NULL)
	{
		return false;
	}

	for(i=0; i<LIST_NUM(wu->Contexts); i++)
	{
		STRMAP_ENTRY *se = LIST_DATA(wu->Contexts, i);
		Free(se->Name);
		WuFreeContext((WU_CONTEXT*)se->Value);
		Free(se);
	}
	ReleaseList(wu->Contexts);

	ReleaseList(wu->PageList);
	Free(wu);
	return true;
}

void WuFreeWebPage(WU_WEBPAGE *page)
{
	if(page == NULL)
	{
		return;
	}

	FreeHttpHeader(page->header);
	Free(page->data);
	Free(page);
}

//  **** Module local utility functions

// Initialize the context
static WU_CONTEXT *WuNewContext(WEBUI *wu, char *hubname)
{
	WU_CONTEXT *context = (WU_CONTEXT*)Malloc(sizeof(WU_CONTEXT));

	if(StrLen(hubname) == 0)
	{
		hubname=NULL;
	}
	context->Admin = (ADMIN*)ZeroMalloc(sizeof(ADMIN));
	context->Admin->HubName = hubname != NULL ? CopyStr(hubname) : NULL;
	context->Admin->Server = wu->Cedar->Server;
	context->Admin->ServerAdmin = hubname == NULL ? true: false;
	context->Admin->Rpc = (RPC*)ZeroMalloc(sizeof(RPC));
	StrCpy(context->Admin->Rpc->Name, sizeof(context->Admin->Rpc->Name), "WEBUI");
	context->Admin->Rpc->Param = context->Admin;
	context->Admin->Rpc->ServerAdminMode = context->Admin->ServerAdmin;
	context->Admin->Rpc->ServerMode = true;
	context->Admin->Rpc->IsVpnServer = true;
	context->Admin->Rpc->Lock = NewLock();
	context->Admin->LogFileList = NULL;

	context->ExpireDate = Tick64() + WU_CONTEXT_EXPIRE;

	return context;
}

// Release the context
static void WuFreeContext(WU_CONTEXT *context)
{
	DeleteLock(context->Admin->Rpc->Lock);
	Free(context->Admin->Rpc);
	Free(context->Admin->HubName);
	Free(context->Admin);
	Free(context);
}

// Create a WebPage structure from the Unicode string
static WU_WEBPAGE *WuNewUniWebPage(wchar_t *content)
{
	WU_WEBPAGE *ret;

	if(content == NULL)
	{
		return NULL;
	}

	ret = (WU_WEBPAGE*)Malloc(sizeof(WU_WEBPAGE));
	ret->size = CalcUniToUtf8(content);
	ret->data = (char*)Malloc(ret->size);
	UniToUtf8(ret->data, ret->size, content);

	ret->header = NewHttpHeader("HTTP/1.1", "202", "OK");
	AddHttpValue(ret->header, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE4));
	AddHttpValue(ret->header, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(ret->header, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));

	return ret;
}

// Generate the WebPage structure from the raw data
static WU_WEBPAGE *WuNewWebPage(char *content, UINT size, char *filename)
{
	WU_WEBPAGE *ret;

	if(content == NULL)
	{
		return NULL;
	}

	ret = (WU_WEBPAGE*)Malloc(sizeof(WU_WEBPAGE));
	ret->size = size;
	ret->data = (char*)Malloc(size);
	Copy(ret->data, content, size);

	ret->header = NewHttpHeader("HTTP/1.1", "202", "OK");
	AddHttpValue(ret->header, NewHttpValue("Connection", "Keep-Alive"));
	AddHttpValue(ret->header, NewHttpValue("Keep-Alive", HTTP_KEEP_ALIVE));

	if(EndWith(filename, "jpg"))
	{
		AddHttpValue(ret->header, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE3));
	}
	AddHttpValue(ret->header, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE4));

	return ret;
}

// Return an error page
static wchar_t *WuErrorPage(UINT errorcode)
{
	wchar_t *buf = WuUniReadFile("|"WP_ERROR);
	wchar_t tmp[MAX_SIZE];
	UniFormat(tmp, sizeof(tmp), L"%d\n<H2>%s</H2>", errorcode, GetUniErrorStr(errorcode));
	WuUniReplace(&buf, L"ERRMSG", tmp);
	return buf;
}

// Redirect
static wchar_t *WuRedirectPage(char *url)
{
	wchar_t *buf = WuUniReadFile("|"WP_REDIRECT);
	wchar_t tmp[MAX_SIZE];
	StrToUni(tmp, sizeof(tmp), url);
	WuUniReplace(&buf, L"REDIRECT_TO", tmp);
	return buf;
}

// Analyse the URL
static LIST *WuAnalyzeTarget(char *target,char *filename, UINT size)
{
	char *start, tmp;

	if(target == NULL || filename == NULL)
	{
		return NULL;
	}

	// Process the absolute path specification
	if(StartWith(target,"http://"))
	{
		// Skip http://
		target += 7;

		// Skip the host name portion
		while(*target != '/' && *target != '\0')
		{
			target ++;
		}

		// Error if the "/" isn't included after "http://"
		if(*target == '\0')
		{
			return NULL;
		}

		target++;
	}

	// Unescape
	// (not implemented)

	// Extract the file name portion
	start = target;
	while(*target != '?' && *target != '\0')
	{
		target ++;
	}
	tmp = *target;
	*target = '\0';
	StrCpy(filename, size, start);
	*target = tmp;

	// Interpret if there are parameters
	if(*target == '?')
	{
		LIST *params = NewStrMap();
		UINT i;
		TOKEN_LIST *tl;
		target++;
		tl =ParseToken(target,"&");
		for(i=0;i<tl->NumTokens;i++)
		{
			char *token = tl->Token[i];
			char *body = token;
			STRMAP_ENTRY *newentry = (STRMAP_ENTRY*)Malloc(sizeof(STRMAP_ENTRY));

			while(*body != '=' && *body != '\0')
			{
				*body ++;
			}
			if(*body == '=')
			{
				*body = '\0';
				body++;
			}
			newentry->Name = CopyStr(token);
			newentry->Value = CopyStr(body);
			Add(params, newentry);
//			Debug("PARAMS: %s : %s\n",token,body);
		}
		FreeToken(tl);
		return params;
	}
	return NULL;
}

// Release the parameter list
static void WuFreeStrStrMap(LIST *params)
{
	UINT i;

	if(params == NULL)
	{
		return;
	}

	for(i=0; i<LIST_NUM(params); i++)
	{
		STRMAP_ENTRY *e = (STRMAP_ENTRY*)LIST_DATA(params, i);
		Free(e->Name);
		Free(e->Value);
		Free(e);
	}
	ReleaseList(params);
}

// Read the UTF-8 file and convert as an Unicode string
static wchar_t *WuUniReadFile(char *filename)
{
	IO *io;
	UINT size, usize;
	BYTE *utf8;
	wchar_t *wchars;

	// Validate arguments
	if (filename == NULL)
	{
		return NULL;
	}

	io = FileOpen(filename, false);
	if (io == NULL)
	{
		return NULL;
	}

	// Load the file
	size = FileSize(io);
	utf8 = (BYTE*)Malloc(size);
	FileRead(io, (void*)utf8, size);
	FileClose(io);

	usize = CalcUtf8ToUni(utf8, size);
	wchars = (wchar_t*)ZeroMalloc(usize+sizeof(wchar_t));
	Utf8ToUni(wchars, usize, utf8, size);
	Free(utf8);

	return wchars;
}

// Replace string (with memory reallocation)
static void WuUniReplace(wchar_t **buf, wchar_t *from, wchar_t *to)
{
	UINT dstsize;
	wchar_t *oldbuf = *buf;

	if(buf == NULL || from == NULL || to == NULL)
	{
		return;
	}

	dstsize = (UniCalcReplaceStrEx(*buf, from, to, true) + 1) * sizeof(wchar_t);
	*buf = (wchar_t*)Malloc(dstsize);
	UniReplaceStr(*buf, dstsize, oldbuf, from, to);
	Free(oldbuf);
}

// Insert the string in front of a specified pattern
static void WuUniInsertBefore(wchar_t **buf, wchar_t *insert, wchar_t *before)
{
	UINT tmpsize;
	wchar_t *tmp;

	if(buf == NULL || insert == NULL || before == NULL)
	{
		return;
	}

	tmpsize = (UniStrLen(insert)+UniStrLen(before)+1)*sizeof(wchar_t);
	tmp = (wchar_t*)Malloc(tmpsize);
	UniStrCpy(tmp, tmpsize, insert);
	UniStrCat(tmp, tmpsize, before);
	WuUniReplace(buf, before, tmp);
	Free(tmp);
}

// Uncomment the tag specified by the keyword
static void WuEnableTag(wchar_t **buf, wchar_t *keyword)
{
	wchar_t tmp[MAX_SIZE];
	if(buf == NULL || keyword == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), L"!--%s", keyword);
	WuUniReplace(buf, tmp, L"");

	UniFormat(tmp, sizeof(tmp), L"%s--", keyword);
	WuUniReplace(buf, tmp, L"");
	return;
}

// Generate a session key
static char *WuNewSessionKey()
{
	char tmp[MD5_SIZE], *ret;
	UINT size;
	Rand(tmp, sizeof(tmp));
	size = sizeof(tmp)*2+1;
	ret = Malloc(size);
	BinToStr(ret, size, tmp, sizeof(tmp));
	return ret;
}

// Replace the Unicode pattern in Unicode string with ASCII string
static void WuUniStrReplace(wchar_t **buf, wchar_t *from, char *to)
{
	UINT unisize;
	wchar_t *tmp;

	if(buf == NULL || *buf == NULL || from == NULL || to == NULL)
	{
		return;
	}

	unisize = CalcStrToUni(to);
	tmp = (wchar_t*)Malloc(unisize);
	StrToUni(tmp, unisize, to);
	WuUniReplace(buf, from, tmp);
	Free(tmp);
}

// Extract the template surrounded by specified Unicode string from Unicode string
static wchar_t *WuUniGetTemplate(wchar_t **str, wchar_t *start, wchar_t *end, bool erase)
{
	UINT startidx, endidx, len, size, i;
	wchar_t *ret;

	if(str == NULL || *str == NULL || start == NULL || end == NULL)
	{
		return NULL;
	}

	startidx =	UniSearchStr(*str, start, 0);
	if(startidx == INFINITE)
	{
		return NULL;
	}
	startidx += UniStrLen(start);

	endidx = UniSearchStr(*str, end, startidx);
	if(endidx == INFINITE)
	{
		return NULL;
	}

	len = endidx - startidx;
	size = (len + 1) * sizeof(wchar_t);
	ret = (wchar_t*)Malloc(size);
	for(i=0; i<len; i++)
	{
		ret[i] = (*str)[startidx + i];
	}
	ret[i] = 0;

	if(erase)
	{
		wchar_t tmp[MAX_SIZE*10];
		UniFormat(tmp, sizeof(tmp), L"%s%s%s", start, ret, end);
		WuUniReplace(str, tmp, L"");
	}
	return ret;
}

// Replace the Unicode pattern in the Unicode string with the UINT number
static void WuUniUintReplace(wchar_t **buf, wchar_t *key, UINT num)
{
	wchar_t tmp[MAX_SIZE];
	UniFormat(tmp, sizeof(tmp), L"%d", num);
	WuUniReplace(buf, key, tmp);
}

// Replace the Unicode pattern in the Unicode string with the UINT64 number
static void WuUniUint64Replace(wchar_t **buf, wchar_t *key, UINT64 num)
{
	wchar_t tmp[MAX_SIZE];
	UniFormat(tmp, sizeof(tmp), L"%I64d", num);
	WuUniReplace(buf, key, tmp);
}

// Copy the Unicode string until the appearance of the specified character (escapable with '\')
static wchar_t *WuUniCopyStrTill(wchar_t *str, wchar_t delimiter, wchar_t **ret){
	UINT num = 0, i;
	wchar_t *next = str;
	wchar_t *ptr = str;

	// Count the number of characters to copy
	while(*next)
	{
		if(*next==L'\\')
		{
			next++;
			if(*next == 0)
			{
				break;
			}
		}
		else
		{
			if(*next == delimiter)
			{
				break;
			}
		}
		next++;
		num++;
	}

	// Allocate the memory and copy the string
	*ret = (wchar_t*)Malloc((num+1)*sizeof(wchar_t));
	for(i=0;i<num;i++)
	{
		if(*ptr == L'\\')
		{
			ptr++;
		}
		(*ret)[i] = *ptr;
		ptr++;
	}
	(*ret)[num]=0;

	// Return a pointer to the next to the delimiter or the end of the string
	return *next ? next+1 : next;
}

// Create a string table from Unicode string
static LIST *WuUniMakeTable(wchar_t *def)
{
	LIST *table;
	STRMAP_ENTRY *entry;
	
	if(def==NULL)
	{
		return NULL;
	}

	table = NewStrMap();
	while(*def)
	{
		wchar_t *keytmp;
		UINT keylen;
		entry = (STRMAP_ENTRY*)Malloc(sizeof(STRMAP_ENTRY));
		def = WuUniCopyStrTill(def, L':', &keytmp);
		keylen = CalcUniToStr(keytmp);
		entry->Name = (char*)Malloc(keylen);
		UniToStr(entry->Name, keylen, keytmp);
		def = WuUniCopyStrTill(def, L',', (wchar_t**)&(entry->Value));
		Add(table, entry);
		Free(keytmp);
	}
	return table;
}

// Extract the template from Unicode string, and create a string table from it
static LIST *WuUniMakeTableFromTemplate(wchar_t **str, wchar_t *start, wchar_t *end)
{
	wchar_t *tmpl = WuUniGetTemplate(str, start, end, true);
	LIST *ret = WuUniMakeTable(tmpl);
	Free(tmpl);
	return ret;
}

// Delete the expired session key
static void WuExpireSessionKey(WEBUI *wu)
{
	LIST *Expired = NewList(NULL);
	UINT i;

	LockList(wu->Contexts);

	for(i=0; i<LIST_NUM(wu->Contexts); i++)
	{
		STRMAP_ENTRY *entry = (STRMAP_ENTRY*)LIST_DATA(wu->Contexts, i);
		WU_CONTEXT *context = (WU_CONTEXT*)entry->Value;
		if(context->ExpireDate < Tick64())
		{
			Add(Expired, entry);
		}
	}

	for(i=0; i<LIST_NUM(Expired); i++)
	{
		STRMAP_ENTRY *entry = LIST_DATA(Expired, i); 
		Delete(wu->Contexts, entry);
		Free(entry->Name);
		WuFreeContext(entry->Value);
		Free(entry);
	}
	ReleaseList(Expired);

	UnlockList(wu->Contexts);
}

// Get the context, and extend its expiration date
static WU_CONTEXT *WuGetContext(LIST *contexts, char *sessionkey)
{
	WU_CONTEXT *ret = StrMapSearch(contexts, sessionkey);
	if(ret != NULL)
	{
		ret->ExpireDate = Tick64() + WU_CONTEXT_EXPIRE;
	}
	return ret;
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
