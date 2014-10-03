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


// NM.c
// VPN User-mode Router Manager for Win32

#include <GlobalConst.h>

#ifdef	WIN32

#define	SM_C
#define	CM_C
#define	NM_C

#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "CMInner.h"
#include "SMInner.h"
#include "NMInner.h"
#include "EMInner.h"
#include "../PenCore/resource.h"

// Global variable
static NM *nm = NULL;

// Dialog proc for the push routing option
UINT NmEditPushRouteProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *r = (SM_HUB *)param;
	char *str = NULL;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetTextA(hWnd, E_TEXT, r->CurrentPushRouteStr);
		Focus(hWnd, E_TEXT);

		SetIcon(hWnd, 0, ICO_PROTOCOL);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			str = GetTextA(hWnd, E_TEXT);
			if (str != NULL)
			{
				bool ok = true;

				if (CheckClasslessRouteTableStr(str) == false)
				{
					if (MsgBox(hWnd, MB_ICONWARNING | MB_OKCANCEL | MB_DEFBUTTON2, _UU("NM_PUSH_ROUTE_WARNING")) == IDCANCEL)
					{
						ok = false;
					}
				}

				if (ok)
				{
					if (IsEmptyStr(str) == false)
					{
						if (GetCapsBool(r->p->CapsList, "b_suppport_push_route") == false)
						{
							MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("ERR_147"));
						}
					}

					StrCpy(r->CurrentPushRouteStr, sizeof(r->CurrentPushRouteStr), str);

					EndDialog(hWnd, 1);
				}

				Free(str);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// Edit dialog for the push routing option
bool NmEditPushRoute(HWND hWnd, SM_HUB *r)
{
	// Validate arguments
	if (r == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_NM_PUSH, NmEditPushRouteProc, r);
}

// Change Password dialog
UINT NmChangePasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	RPC *r = (RPC *)param;
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	RPC_SET_PASSWORD t;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, 0, r->Sock->RemoteHostname);
		FormatText(hWnd, S_TITLE, r->Sock->RemoteHostname);
		break;

	case WM_COMMAND:
		GetTxtA(hWnd, E_PASSWORD1, tmp1, sizeof(tmp1));
		GetTxtA(hWnd, E_PASSWORD2, tmp2, sizeof(tmp2));
		switch (LOWORD(wParam))
		{
		case E_PASSWORD1:
		case E_PASSWORD2:
			SetEnable(hWnd, IDOK, StrCmp(tmp1, tmp2) == 0);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			Zero(&t, sizeof(t));
			Hash(t.HashedPassword, tmp1, StrLen(tmp1), true);

			if (CALL(hWnd, NcSetPassword(r, &t)))
			{
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("NM_PASSWORD_MSG"));
				EndDialog(hWnd, true);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Change the password
void NmChangePassword(HWND hWnd, RPC *r)
{
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	Dialog(hWnd, D_NM_CHANGE_PASSWORD, NmChangePasswordProc, r);
}

// DHCP enumeration initialization
void NmDhcpInit(HWND hWnd, SM_HUB *r)
{
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_INTERNET);

	LvInit(hWnd, L_TABLE);
	LvInsertColumn(hWnd, L_TABLE, 0, _UU("DHCP_DHCP_ID"), 50);
	LvInsertColumn(hWnd, L_TABLE, 1, _UU("DHCP_LEASED_TIME"), 200);
	LvInsertColumn(hWnd, L_TABLE, 2, _UU("DHCP_EXPIRE_TIME"), 200);
	LvInsertColumn(hWnd, L_TABLE, 3, _UU("DHCP_MAC_ADDRESS"), 130);
	LvInsertColumn(hWnd, L_TABLE, 4, _UU("DHCP_IP_ADDRESS"), 100);
	LvInsertColumn(hWnd, L_TABLE, 5, _UU("DHCP_HOSTNAME"), 150);

	NmDhcpRefresh(hWnd, r);
}

// DHCP enumeration
void NmDhcpRefresh(HWND hWnd, SM_HUB *r)
{
	LVB *b;
	RPC_ENUM_DHCP t;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		Close(hWnd);
		return;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), r->HubName);

	if (CALL(hWnd, ScEnumDHCP(r->Rpc, &t)) == false)
	{
		return;
	}

	b = LvInsertStart();
	
	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_DHCP_ITEM *e = &t.Items[i];
		wchar_t tmp0[MAX_SIZE];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		wchar_t tmp5[MAX_SIZE];
		char str[MAX_SIZE];

		// ID
		UniToStru(tmp0, e->Id);

		// Time
		GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(e->LeasedTime), NULL);
		GetDateTimeStrEx64(tmp2, sizeof(tmp2), SystemToLocal64(e->ExpireTime), NULL);

		MacToStr(str, sizeof(str), e->MacAddress);
		StrToUni(tmp3, sizeof(tmp3), str);

		IPToStr32(str, sizeof(str), e->IpAddress);
		StrToUni(tmp4, sizeof(tmp4), str);

		StrToUni(tmp5, sizeof(tmp5), e->Hostname);

		LvInsertAdd(b, ICO_INTERNET, NULL, 6,
			tmp0, tmp1, tmp2, tmp3, tmp4, tmp5);
	}

	LvInsertEnd(b, hWnd, L_TABLE);

	FreeRpcEnumDhcp(&t);
}

// DHCP enumeration procedure
UINT NmDhcpProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *r = (SM_HUB *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		NmDhcpInit(hWnd, r);
		SetTimer(hWnd, 1, NM_DHCP_REFRESH_TIME, NULL);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			Close(hWnd);
			break;

		case B_REFRESH:
			NmDhcpRefresh(hWnd, r);
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			NmDhcpRefresh(hWnd, r);
			SetTimer(hWnd, 1, NM_DHCP_REFRESH_TIME, NULL);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_TABLE);

	return 0;
}

// DHCP enumeration
void NmDhcp(HWND hWnd, SM_HUB *r)
{
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	Dialog(hWnd, D_NM_DHCP, NmDhcpProc, r);
}


// NAT enumeration initialization
void NmNatInit(HWND hWnd, SM_HUB *r)
{
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_PROTOCOL);

	LvInit(hWnd, L_TABLE);
	LvInsertColumn(hWnd, L_TABLE, 0, _UU("NM_NAT_ID"), 50);
	LvInsertColumn(hWnd, L_TABLE, 1, _UU("NM_NAT_PROTOCOL"), 80);
	LvInsertColumn(hWnd, L_TABLE, 2, _UU("NM_NAT_SRC_HOST"), 100);
	LvInsertColumn(hWnd, L_TABLE, 3, _UU("NM_NAT_SRC_PORT"), 80);
	LvInsertColumn(hWnd, L_TABLE, 4, _UU("NM_NAT_DST_HOST"), 150);
	LvInsertColumn(hWnd, L_TABLE, 5, _UU("NM_NAT_DST_PORT"), 80);
	LvInsertColumn(hWnd, L_TABLE, 6, _UU("NM_NAT_CREATED"), 200);
	LvInsertColumn(hWnd, L_TABLE, 7, _UU("NM_NAT_LAST_COMM"), 200);
	LvInsertColumn(hWnd, L_TABLE, 8, _UU("NM_NAT_SIZE"), 120);
	LvInsertColumn(hWnd, L_TABLE, 9, _UU("NM_NAT_TCP_STATUS"), 120);

	NmNatRefresh(hWnd, r);
}

// NAT enumeration
void NmNatRefresh(HWND hWnd, SM_HUB *r)
{
	LVB *b;
	RPC_ENUM_NAT t;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), r->HubName);

	if (CALL(hWnd, ScEnumNAT(r->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	b = LvInsertStart();
	
	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_NAT_ITEM *e = &t.Items[i];
		wchar_t tmp0[MAX_SIZE];
		wchar_t *tmp1 = L"";
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		wchar_t tmp5[MAX_SIZE];
		wchar_t tmp6[MAX_SIZE];
		wchar_t tmp7[MAX_SIZE];
		wchar_t tmp8[MAX_SIZE];
		wchar_t *tmp9 = L"";
		char v1[128], v2[128];

		// ID
		UniToStru(tmp0, e->Id);

		// Protocol
		switch (e->Protocol)
		{
		case NAT_TCP:
			tmp1 = _UU("NM_NAT_PROTO_TCP");
			break;
		case NAT_UDP:
			tmp1 = _UU("NM_NAT_PROTO_UDP");
			break;
		case NAT_DNS:
			tmp1 = _UU("NM_NAT_PROTO_DNS");
			break;
		case NAT_ICMP:
			tmp1 = _UU("NM_NAT_PROTO_ICMP");
			break;
		}

		// Source host
		StrToUni(tmp2, sizeof(tmp2), e->SrcHost);

		// Source port
		UniToStru(tmp3, e->SrcPort);

		// Destination host
		StrToUni(tmp4, sizeof(tmp4), e->DestHost);

		// Destination port
		UniToStru(tmp5, e->DestPort);

		// Creation date and time of the session
		GetDateTimeStrEx64(tmp6, sizeof(tmp6), SystemToLocal64(e->CreatedTime), NULL);

		// Last communication date and time
		GetDateTimeStrEx64(tmp7, sizeof(tmp7), SystemToLocal64(e->LastCommTime), NULL);

		// Communication amount
		ToStr3(v1, sizeof(v1), e->RecvSize);
		ToStr3(v2, sizeof(v2), e->SendSize);
		UniFormat(tmp8, sizeof(tmp8), L"%S / %S", v1, v2);

		// TCP state
		if (e->Protocol == NAT_TCP)
		{
			switch (e->TcpStatus)
			{
			case NAT_TCP_CONNECTING:
				tmp9 = _UU("NAT_TCP_CONNECTING");
				break;
			case NAT_TCP_SEND_RESET:
				tmp9 = _UU("NAT_TCP_SEND_RESET");
				break;
			case NAT_TCP_CONNECTED:
				tmp9 = _UU("NAT_TCP_CONNECTED");
				break;
			case NAT_TCP_ESTABLISHED:
				tmp9 = _UU("NAT_TCP_ESTABLISHED");
				break;
			case NAT_TCP_WAIT_DISCONNECT:
				tmp9 = _UU("NAT_TCP_WAIT_DISCONNECT");
				break;
			}
		}

		LvInsertAdd(b, ICO_PROTOCOL, NULL, 10,
			tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9);
	}

	LvInsertEnd(b, hWnd, L_TABLE);

	FreeRpcEnumNat(&t);
}

// NAT enumeration procedure
UINT NmNatProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *r = (SM_HUB *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		NmNatInit(hWnd, r);
		SetTimer(hWnd, 1, NM_NAT_REFRESH_TIME, NULL);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			Close(hWnd);
			break;

		case B_REFRESH:
			NmNatRefresh(hWnd, r);
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			NmNatRefresh(hWnd, r);
			SetTimer(hWnd, 1, NM_NAT_REFRESH_TIME, NULL);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_TABLE);

	return 0;
}

// NAT enumeration
void NmNat(HWND hWnd, SM_HUB *r)
{
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	Dialog(hWnd, D_NM_NAT, NmNatProc, r);
}

// Show the information of the router
bool NmInfo(HWND hWnd, SM_SERVER *s, void *param)
{
	LVB *b;
	RPC_NAT_INFO t;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));

	if (CALL(hWnd, NcGetInfo(s->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	StrToUni(tmp, sizeof(tmp), t.NatProductName);
	LvInsertAdd(b, ICO_ROUTER, NULL, 2, _UU("NM_INFO_PRODUCT_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.NatVersionString);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("NM_INFO_VERSION_STR"), tmp);

	StrToUni(tmp, sizeof(tmp), t.NatBuildInfoString);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("NM_INFO_BUILD_INFO"), tmp);

	StrToUni(tmp, sizeof(tmp), t.NatHostName);
	LvInsertAdd(b, ICO_TOWER, NULL, 2, _UU("NM_INFO_HOSTNAME"), tmp);

	// OS
	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsSystemName);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_SYSTEM_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsProductName);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_PRODUCT_NAME"), tmp);

	if (t.OsInfo.OsServicePack != 0)
	{
		UniFormat(tmp, sizeof(tmp), _UU("SM_OS_SP_TAG"), t.OsInfo.OsServicePack);
		LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_SERVICE_PACK"), tmp);
	}

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsVendorName);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_VENDER_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsVersion);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_VERSION"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.KernelName);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_KERNEL_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.KernelVersion);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_OS_KERNEL_VERSION"), tmp);

	// Memory information
	if (t.MemInfo.TotalMemory != 0)
	{
		char vv[128];

		ToStr3(vv, sizeof(vv), t.MemInfo.TotalMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_TOTAL_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.UsedMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_USED_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.FreeMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_FREE_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.TotalPhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_TOTAL_PHYS"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.UsedPhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_USED_PHYS"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.FreePhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		LvInsertAdd(b, ICO_MEMORY, NULL, 2, _UU("SM_ST_FREE_PHYS"), tmp);
	}

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcNatInfo(&t);

	return true;
}

// Show the status of the router
bool NmStatus(HWND hWnd, SM_SERVER *s, void *param)
{
	LVB *b;
	RPC_NAT_STATUS t;
	wchar_t tmp[MAX_SIZE];
	SM_HUB *h = (SM_HUB *)param;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), h->HubName);

	if (CALL(hWnd, ScGetSecureNATStatus(s->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	StrToUni(tmp, sizeof(tmp), h->HubName);
	LvInsertAdd(b, ICO_HUB, NULL, 2, _UU("SM_HUB_COLUMN_1"), tmp);

	UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_SESSION"), t.NumTcpSessions);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("NM_STATUS_TCP"), tmp);

	UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_SESSION"), t.NumUdpSessions);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("NM_STATUS_UDP"), tmp);

	UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_SESSION"), t.NumIcmpSessions);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("NM_STATUS_ICMP"), tmp);

	UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_SESSION"), t.NumDnsSessions);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("NM_STATUS_DNS"), tmp);

	UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_CLIENT"), t.NumDhcpClients);
	LvInsertAdd(b, ICO_PROTOCOL_DHCP, NULL, 2, _UU("NM_STATUS_DHCP"), tmp);

	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_SNAT_IS_KERNEL"), t.IsKernelMode ? _UU("SEC_YES") : _UU("SEC_NO"));

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcNatStatus(&t);

	return true;
}

// Convert the contents of the form to the VH_OPTION
void NmEditVhOptionFormToVH(HWND hWnd, VH_OPTION *t)
{
	char tmp[MAX_SIZE];
	BUF *b;
	// Validate arguments
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	Zero(t, sizeof(VH_OPTION));

	GetTxtA(hWnd, E_MAC, tmp, sizeof(tmp));
	b = StrToBin(tmp);
	if (b != NULL)
	{
		if (b->Size == 6)
		{
			Copy(t->MacAddress, b->Buf, 6);
		}
		FreeBuf(b);
	}

	UINTToIP(&t->Ip, IpGet(hWnd, E_IP));
	UINTToIP(&t->Mask, IpGet(hWnd, E_MASK));

	t->UseNat = IsChecked(hWnd, R_USE_NAT);
	t->Mtu = GetInt(hWnd, E_MTU);
	t->NatTcpTimeout = GetInt(hWnd, E_TCP);
	t->NatUdpTimeout = GetInt(hWnd, E_UDP);

	t->UseDhcp = IsChecked(hWnd, R_USE_DHCP);
	UINTToIP(&t->DhcpLeaseIPStart, IpGet(hWnd, E_DHCP_START));
	UINTToIP(&t->DhcpLeaseIPEnd, IpGet(hWnd, E_DHCP_END));
	UINTToIP(&t->DhcpSubnetMask, IpGet(hWnd, E_DHCP_MASK));
	t->DhcpExpireTimeSpan = GetInt(hWnd, E_EXPIRES);
	UINTToIP(&t->DhcpGatewayAddress, IpGet(hWnd, E_GATEWAY));
	UINTToIP(&t->DhcpDnsServerAddress, IpGet(hWnd, E_DNS));
	UINTToIP(&t->DhcpDnsServerAddress2, IpGet(hWnd, E_DNS2));
	GetTxtA(hWnd, E_DOMAIN, t->DhcpDomainName, sizeof(t->DhcpDomainName));
	t->SaveLog = IsChecked(hWnd, R_SAVE_LOG);
}

// Initialize
void NmEditVhOptionInit(HWND hWnd, SM_HUB *r)
{
	char tmp[MAX_SIZE];
	VH_OPTION t;
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_ROUTER);

	FormatText(hWnd, S_TITLE, r->HubName);

	Zero(&t, sizeof(VH_OPTION));
	StrCpy(t.HubName, sizeof(t.HubName), r->HubName);
	if (CALL(hWnd, ScGetSecureNATOption(r->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	if (GetCapsBool(r->p->CapsList, "b_virtual_nat_disabled"))
	{
		SetEnable(hWnd, R_USE_NAT, false);
		Check(hWnd, R_USE_NAT, false);
	}

	MacToStr(tmp, sizeof(tmp), t.MacAddress);
	SetTextA(hWnd, E_MAC, tmp);
	IpSet(hWnd, E_IP, IPToUINT(&t.Ip));
	IpSet(hWnd, E_MASK, IPToUINT(&t.Mask));

	Check(hWnd, R_USE_NAT, t.UseNat);
	SetIntEx(hWnd, E_MTU, t.Mtu);
	SetIntEx(hWnd, E_TCP, t.NatTcpTimeout);
	SetIntEx(hWnd, E_UDP, t.NatUdpTimeout);

	Check(hWnd, R_USE_DHCP, t.UseDhcp);
	IpSet(hWnd, E_DHCP_START, IPToUINT(&t.DhcpLeaseIPStart));
	IpSet(hWnd, E_DHCP_END, IPToUINT(&t.DhcpLeaseIPEnd));
	IpSet(hWnd, E_DHCP_MASK, IPToUINT(&t.DhcpSubnetMask));
	SetIntEx(hWnd, E_EXPIRES, t.DhcpExpireTimeSpan);

	if (IPToUINT(&t.DhcpGatewayAddress) != 0)
	{
		IpSet(hWnd, E_GATEWAY, IPToUINT(&t.DhcpGatewayAddress));
	}

	if (IPToUINT(&t.DhcpDnsServerAddress) != 0)
	{
		IpSet(hWnd, E_DNS, IPToUINT(&t.DhcpDnsServerAddress));
	}

	if (IPToUINT(&t.DhcpDnsServerAddress2) != 0)
	{
		IpSet(hWnd, E_DNS2, IPToUINT(&t.DhcpDnsServerAddress2));
	}

	SetTextA(hWnd, E_DOMAIN, t.DhcpDomainName);
	Check(hWnd, R_SAVE_LOG, t.SaveLog);

	StrCpy(r->CurrentPushRouteStr, sizeof(r->CurrentPushRouteStr), t.DhcpPushRoutes);

	if (GetCapsBool(r->p->CapsList, "b_suppport_push_route_config") == false)
	{
		Disable(hWnd, S_1);
		Disable(hWnd, S_2);
		Disable(hWnd, B_PUSH);
	}

	NmEditVhOptionUpdate(hWnd, r);

}

void NmEditVhOptionUpdate(HWND hWnd, SM_HUB *r)
{
	VH_OPTION t;
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	NmEditVhOptionFormToVH(hWnd, &t);

	if (IsZero(t.MacAddress, 6))
	{
		ok = false;
	}

	if (IPToUINT(&t.Ip) == 0 || IPToUINT(&t.Mask) == 0)
	{
		ok = false;
	}

	if (IpIsFilled(hWnd, E_IP) == false || IpIsFilled(hWnd, E_MASK) == false)
	{
		ok = false;
	}

	if (IsHostIPAddress4(&t.Ip) == false || IsSubnetMask4(&t.Mask) == false)
	{
		ok = false;
	}

	if (t.UseNat)
	{
		if (t.Mtu < 64 || t.Mtu > 1500)
		{
			ok = false;
		}

		if (t.NatTcpTimeout < (NAT_TCP_MIN_TIMEOUT / 1000) || t.NatTcpTimeout > (NAT_TCP_MAX_TIMEOUT / 1000))
		{
			ok = false;
		}

		if (t.NatUdpTimeout < (NAT_UDP_MIN_TIMEOUT / 1000) || t.NatUdpTimeout > (NAT_UDP_MAX_TIMEOUT / 1000))
		{
			ok = false;
		}
	}

	if (t.UseDhcp)
	{
		if (IpIsFilled(hWnd, E_DHCP_START) == false || IpIsFilled(hWnd, E_DHCP_END) == false ||
			IpIsFilled(hWnd, E_DHCP_MASK) == false)
		{
			ok = false;
		}

		if (IpGetFilledNum(hWnd, E_GATEWAY) != 0 && IpGetFilledNum(hWnd, E_GATEWAY) != 4)
		{
			ok = false;
		}

		if (IpGetFilledNum(hWnd, E_DNS) != 0 && IpGetFilledNum(hWnd, E_DNS) != 4)
		{
			ok = false;
		}

		if (IpGetFilledNum(hWnd, E_DNS2) != 0 && IpGetFilledNum(hWnd, E_DNS2) != 4)
		{
			ok = false;
		}

		if (IPToUINT(&t.DhcpLeaseIPStart) == 0 || IPToUINT(&t.DhcpLeaseIPEnd) == 0 ||
			IPToUINT(&t.DhcpSubnetMask) == 0)
		{
			ok = false;
		}

		if (t.DhcpExpireTimeSpan < 15)
		{
			ok = false;
		}

		if (Endian32(IPToUINT(&t.DhcpLeaseIPStart)) > Endian32(IPToUINT(&t.DhcpLeaseIPEnd)))
		{
			ok = false;
		}

		if (IsHostIPAddress4(&t.DhcpLeaseIPStart) == false ||
			IsHostIPAddress4(&t.DhcpLeaseIPEnd) == false)
		{
			ok = false;
		}

		if (IsSubnetMask4(&t.DhcpSubnetMask) == false)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, E_MTU, t.UseNat);
	SetEnable(hWnd, E_TCP, t.UseNat);
	SetEnable(hWnd, E_UDP, t.UseNat);

	SetEnable(hWnd, E_DHCP_START, t.UseDhcp);
	SetEnable(hWnd, E_DHCP_END, t.UseDhcp);
	SetEnable(hWnd, E_DHCP_MASK, t.UseDhcp);
	SetEnable(hWnd, E_EXPIRES, t.UseDhcp);
	SetEnable(hWnd, E_GATEWAY, t.UseDhcp);
	SetEnable(hWnd, E_DNS, t.UseDhcp);
	SetEnable(hWnd, E_DNS2, t.UseDhcp);
	SetEnable(hWnd, E_DOMAIN, t.UseDhcp);

	SetEnable(hWnd, IDOK, ok);
}

// [OK] button
void NmEditVhOptionOnOk(HWND hWnd, SM_HUB *r)
{
	VH_OPTION t;
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	NmEditVhOptionFormToVH(hWnd, &t);
	StrCpy(t.HubName, sizeof(t.HubName), r->HubName);

	t.ApplyDhcpPushRoutes = true;
	StrCpy(t.DhcpPushRoutes, sizeof(t.DhcpPushRoutes), r->CurrentPushRouteStr);

	if (CALL(hWnd, ScSetSecureNATOption(r->Rpc, &t)))
	{
		EndDialog(hWnd, true);
	}
}

// Virtual host options editing dialog
UINT NmEditVhOptionProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *r = (SM_HUB *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		NmEditVhOptionInit(hWnd, r);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_MAC:
		case E_IP:
		case E_MASK:
		case R_USE_NAT:
		case E_MTU:
		case E_TCP:
		case E_UDP:
		case R_SAVE_LOG:
		case R_USE_DHCP:
		case E_DHCP_START:
		case E_DHCP_END:
		case E_DHCP_MASK:
		case E_EXPIRES:
		case E_GATEWAY:
		case E_DNS:
		case E_DNS2:
		case E_DOMAIN:
			NmEditVhOptionUpdate(hWnd, r);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			NmEditVhOptionOnOk(hWnd, r);
			break;

		case IDCANCEL:
			EndDialog(hWnd, false);
			break;

		case R_USE_NAT:
			if (IsChecked(hWnd, R_USE_NAT))
			{
				FocusEx(hWnd, E_MTU);
			}

			if (IsChecked(hWnd, R_USE_DHCP))
			{
				Focus(hWnd, E_DHCP_START);
			}
			break;

		case B_PUSH:
			NmEditPushRoute(hWnd, r);
			break;
		}

		break;
	}

	return 0;
}

// Edit the virtual host option
void NmEditVhOption(HWND hWnd, SM_HUB *r)
{
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	Zero(r->CurrentPushRouteStr, sizeof(r->CurrentPushRouteStr));
	Dialog(hWnd, D_NM_OPTION, NmEditVhOptionProc, r);
}

// Edit the client configuration
void NmEditClientConfig(HWND hWnd, RPC *r)
{
	CM_ACCOUNT a;
	RPC_CREATE_LINK t;
	bool ret = false;
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));
	Zero(&t, sizeof(t));

	a.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	a.NatMode = true;
	a.Rpc = r;

	if (CALLEX(hWnd, NcGetClientConfig(r, &t)) != ERR_NO_ERROR)
	{
		// Create New
		a.ClientOption->Port = 443;
		a.ClientOption->RetryInterval = 15;
		a.ClientOption->NumRetry = INFINITE;
		a.ClientOption->AdditionalConnectionInterval = 1;
		a.ClientOption->UseEncrypt = true;
		a.ClientOption->NoRoutingTracking = true;
		a.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
		a.ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
	}
	else
	{
		// Edit
		a.EditMode = true;
		Copy(a.ClientOption, t.ClientOption, sizeof(CLIENT_OPTION));
		a.ClientAuth = CopyClientAuth(t.ClientAuth);

		FreeRpcCreateLink(&t);
	}

	ret = CmEditAccountDlg(hWnd, &a);

	Free(a.ServerCert);
	Free(a.ClientOption);
	CiFreeClientAuth(a.ClientAuth);
}

// Initialize
void NmMainDlgInit(HWND hWnd, RPC *r)
{
	// Validate arguments
	if (r == NULL || hWnd == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_ROUTER);
	FormatText(hWnd, 0, r->Sock->RemoteHostname);
	DlgFont(hWnd, S_STATUS, 11, true);

	NmMainDlgRefresh(hWnd, r);
}

// Update
void NmMainDlgRefresh(HWND hWnd, RPC *r)
{
#if	0
	RPC_NAT_STATUS t;
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	// Validate arguments
	if (r == NULL || hWnd == NULL)
	{
		return;
	}

	Zero(&t, sizeof(RPC_NAT_STATUS));

	CALL(hWnd, NcGetStatus(r, &t));

	if (t.Online == false)
	{
		UniStrCpy(tmp, sizeof(tmp), _UU("NM_OFFLINE"));

		Enable(hWnd, B_CONNECT);
		Disable(hWnd, B_DISCONNECT);
	}
	else
	{
		if (t.Connected)
		{
			UniFormat(tmp, sizeof(tmp), _UU("NM_CONNECTED"), t.Status.ServerName);
		}
		else
		{
			if (t.LastError == ERR_NO_ERROR)
			{
				UniStrCpy(tmp, sizeof(tmp), _UU("NM_CONNECTING"));
			}
			else
			{
				UniFormat(tmp, sizeof(tmp), _UU("NM_CONNECT_ERROR"), t.LastError, _E(t.LastError));
			}
		}
		Disable(hWnd, B_CONNECT);
		Enable(hWnd, B_DISCONNECT);
	}

	UniFormat(tmp2, sizeof(tmp2), _UU("NM_STATUS_TAG"), tmp);

	SetText(hWnd, S_STATUS, tmp2);

	FreeRpcNatStatus(&t);
#endif
}

// Main dialog procedure
UINT NmMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
#if	0
	SM_HUB *r = (SM_HUB *)param;
	RPC_DUMMY dummy;
	SM_SERVER sm;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		NmMainDlgInit(hWnd, r);

		SetTimer(hWnd, 1, NM_REFRESH_TIME, NULL);

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_SETTING:
			// Connection setting
			NmEditClientConfig(hWnd, r);
			break;

		case B_CONNECT:
			// Connection
			Zero(&dummy, sizeof(dummy));
			CALL(hWnd, NcOnline(r, &dummy));
			NmMainDlgRefresh(hWnd, r);
			break;

		case B_DISCONNECT:
			// Disconnect
			Zero(&dummy, sizeof(dummy));
			CALL(hWnd, NcOffline(r, &dummy));
			NmMainDlgRefresh(hWnd, r);
			break;

		case B_OPTION:
			// Operation setting
			NmEditVhOption(hWnd, r->Rpc);
			break;

		case B_NAT:
			// NAT
			NmNat(hWnd, r);
			break;

		case B_DHCP:
			// DHCP
			NmDhcp(hWnd, r);
			break;

		case B_STATUS:
			// Status
			Zero(&sm, sizeof(sm));
			sm.Rpc = r;
			SmStatusDlg(hWnd, &sm, NULL, true, true, _UU("NM_STATUS"), ICO_ROUTER,
				NULL, NmStatus);
			break;

		case B_INFO:
			// Information
			Zero(&sm, sizeof(sm));
			sm.Rpc = r;
			SmStatusDlg(hWnd, &sm, NULL, false, true, _UU("NM_INFO"), ICO_ROUTER,
				NULL, NmInfo);
			break;

		case B_REFRESH:
			// Refresh
			NmMainDlgRefresh(hWnd, r);
			break;

		case B_PASSWORD:
			// Change the password
			NmChangePassword(hWnd, r);
			break;

		case B_ABOUT:
			// Version information
			About(hWnd, nm->Cedar, CEDAR_ROUTER_STR);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			if (IsEnable(hWnd, 0))
			{
				NmMainDlgRefresh(hWnd, r);
			}

			SetTimer(hWnd, 1, NM_REFRESH_TIME, NULL);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

#endif

	return 0;
}

// Main dialog
void NmMainDlg(RPC *r)
{
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	Dialog(NULL, D_NM_MAIN, NmMainDlgProc, r);
}

// Login dialog
UINT NmLogin(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NM_LOGIN *login = (NM_LOGIN *)param;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, S_TITLE, login->Hostname);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			GetTxtA(hWnd, E_PASSWORD, tmp, sizeof(tmp));
			Hash(login->hashed_password, tmp, StrLen(tmp), true);
			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Connecting dialog
UINT NmConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NM_CONNECT *t = (NM_CONNECT *)param;
	RPC *rpc;
	NM_LOGIN login;
	UINT err;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, S_TITLE, t->Hostname);
		SetTimer(hWnd, 1, 50, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			while (true)
			{
				bool flag = false;
RETRY_PASSWORD:
				// Password input dialog
				Zero(&login, sizeof(login));
				login.Hostname = t->Hostname;
				login.Port = t->Port;
				Hash(login.hashed_password, "", 0, true);

				if (flag)
				{
					if (Dialog(hWnd, D_NM_LOGIN, NmLogin, &login) == false)
					{
						EndDialog(hWnd, false);
						break;
					}
				}

RETRY_CONNECT:
				Refresh(DlgItem(hWnd, S_TITLE));
				Refresh(hWnd);
				// Connection
				rpc = NatAdminConnect(nm->Cedar, t->Hostname, t->Port, login.hashed_password, &err);
				if (rpc != NULL)
				{
					t->Rpc = rpc;
					EndDialog(hWnd, true);
					break;
				}

				// Error
				if (err == ERR_ACCESS_DENIED || err == ERR_AUTH_FAILED)
				{
					if (flag)
					{
						if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_RETRYCANCEL,
							_E(err)) == IDCANCEL)
						{
							EndDialog(hWnd, false);
							break;
						}
					}
					flag = true;
					goto RETRY_PASSWORD;
				}
				else
				{
					if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_RETRYCANCEL,
						_E(err)) == IDCANCEL)
					{
						EndDialog(hWnd, false);
						break;
					}
					goto RETRY_CONNECT;
				}
			}
			break;
		}
		break;
	}

	return 0;
}

// Connect to the User-mode NAT program
RPC *NmConnect(char *hostname, UINT port)
{
	NM_CONNECT t;
	// Validate arguments
	if (hostname == NULL || port == 0)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	t.Hostname = hostname;
	t.Port = port;

	Dialog(NULL, D_NM_CONNECT, NmConnectDlgProc, &t);

	return t.Rpc;
}

// Main process
void MainNM()
{
	UINT port;
	char hostname[MAX_HOST_NAME_LEN + 1];
	char *tmp =
		RemoteDlg(NULL, NM_SETTING_REG_KEY, ICO_ROUTER,
		_UU("NM_TITLE"), _UU("NM_CONNECT_TITLE"), NULL);
	TOKEN_LIST *t;

	Zero(hostname, sizeof(hostname));

	if (tmp == NULL)
	{
		return;
	}

	t = ParseToken(tmp, ":");
	port = DEFAULT_NAT_ADMIN_PORT;

	if (t->NumTokens >= 2)
	{
		UINT i = ToInt(t->Token[1]);
		if (i != 0)
		{
			port = i;
		}
	}
	if (t->NumTokens >= 1)
	{
		RPC *rpc;
		StrCpy(hostname, sizeof(hostname), t->Token[0]);

		// Connection
		Trim(hostname);

		if (StrLen(hostname) != 0)
		{
			rpc = NmConnect(hostname, port);
			if (rpc != NULL)
			{
				// Connected
				NmMainDlg(rpc);
				NatAdminDisconnect(rpc);
			}
		}
	}

	FreeToken(t);

	Free(tmp);
}

// Initialize
void InitNM()
{
	if (nm != NULL)
	{
		// Already initialized
		return;
	}

	nm = ZeroMalloc(sizeof(NM));

	InitWinUi(_UU("NM_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	nm->Cedar = NewCedar(NULL, NULL);

	InitCM(false);
	InitSM();
}

// Release
void FreeNM()
{
	if (nm == NULL)
	{
		// Uninitialized
		return;
	}

	FreeSM();
	FreeCM();

	ReleaseCedar(nm->Cedar);

	FreeWinUi();

	Free(nm);
	nm = NULL;
}

// Execution of NM
void NMExec()
{
	InitNM();
	MainNM();
	FreeNM();
}

#endif


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
