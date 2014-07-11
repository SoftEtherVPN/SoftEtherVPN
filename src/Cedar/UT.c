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


// UT.c
// SoftEther Network Utility For Win32

#include <GlobalConst.h>

#ifdef	WIN32

#define	UT_C

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
#include "../PenCore/resource.h"

static char *selected_adapter = NULL;

// Update status
void UtSpeedMeterDlgRefreshStatus(HWND hWnd)
{
	char *title;
	MS_ADAPTER *a;
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	title = selected_adapter;

	a = MsGetAdapter(title);
	if (a == NULL)
	{
		LbReset(hWnd, L_STATUS);
		Disable(hWnd, L_STATUS);
	}
	else
	{
		LVB *b;
		wchar_t tmp[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		char str[MAX_SIZE];
		b = LvInsertStart();

		UniStrCpy(tmp, sizeof(tmp), a->TitleW);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_TITLE"), tmp);

		StrToUni(tmp, sizeof(tmp), a->Guid);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_GUID"), tmp);

		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_TYPE"), MsGetAdapterTypeStr(a->Type));

		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_TYPE2"), (!a->IsNotEthernetLan ? _UU("SEC_YES") : _UU("SEC_NO")));

		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_STATUS"), MsGetAdapterStatusStr(a->Status));

		UniToStr3(tmp, sizeof(tmp), a->Mtu);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_MTU"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->Speed);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_SPEED"), tmp);

		Zero(str, sizeof(str));
		BinToStrEx2(str, sizeof(str), a->Address, a->AddressSize, '-');
		StrToUni(tmp, sizeof(tmp), str);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_ADDRESS"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->RecvBytes);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_RECV_BYTES"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->RecvPacketsBroadcast);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_RECV_BCASTS"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->RecvPacketsUnicast);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_RECV_UNICASTS"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->SendBytes);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_SEND_BYTES"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->SendPacketsBroadcast);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_SEND_BCASTS"), tmp);

		UniToStr3(tmp, sizeof(tmp), a->SendPacketsUnicast);
		LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_SEND_UNICASTS"), tmp);

		for (i = 0;i < a->NumIpAddress;i++)
		{
			UniFormat(tmp2, sizeof(tmp2), _UU("UT_SM_ST_IP"), i + 1);
			IPToUniStr(tmp, sizeof(tmp), &a->IpAddresses[i]);
			LvInsertAdd(b, 0, NULL, 2, tmp2, tmp);

			UniFormat(tmp2, sizeof(tmp2), _UU("UT_SM_ST_SUBNET"), i + 1);
			IPToUniStr(tmp, sizeof(tmp), &a->SubnetMasks[i]);
			LvInsertAdd(b, 0, NULL, 2, tmp2, tmp);
		}

		for (i = 0;i < a->NumGateway;i++)
		{
			UniFormat(tmp2, sizeof(tmp2), _UU("UT_SM_ST_GATEWAY"), i + 1);
			IPToUniStr(tmp, sizeof(tmp), &a->Gateways[i]);
			LvInsertAdd(b, 0, NULL, 2, tmp2, tmp);
		}

		if (a->UseDhcp)
		{
			IPToUniStr(tmp, sizeof(tmp), &a->DhcpServer);
			LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_DHCP"), tmp);

			GetDateTimeStrEx64(tmp, sizeof(tmp), a->DhcpLeaseStart, NULL);
			LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_DHCP_1"), tmp);

			GetDateTimeStrEx64(tmp, sizeof(tmp), a->DhcpLeaseExpires, NULL);
			LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_DHCP_2"), tmp);
		}

		if (a->UseWins)
		{
			IPToUniStr(tmp, sizeof(tmp), &a->PrimaryWinsServer);
			LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_WINS_1"), tmp);

			IPToUniStr(tmp, sizeof(tmp), &a->SecondaryWinsServer);
			LvInsertAdd(b, 0, NULL, 2, _UU("UT_SM_ST_WINS_2"), tmp);
		}

		LvInsertEnd(b, hWnd, L_STATUS);
		Enable(hWnd, L_STATUS);

		MsFreeAdapter(a);
	}

}

static bool g_ut_adapter_list_updating = false;

// Update the adapter list
void UtSpeedMeterDlgRefreshList(HWND hWnd)
{
	wchar_t *old;
	MS_ADAPTER_LIST *o;
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (g_ut_adapter_list_updating)
	{
		return;
	}
	g_ut_adapter_list_updating = true;

	// Get the current selection
	old = GetText(hWnd, E_LIST);
	if (old != NULL)
	{
		if (UniStrLen(old) == 0)
		{
			Free(old);
			old = NULL;
		}
	}

	o = MsCreateAdapterList();
	CbReset(hWnd, E_LIST);
	CbSetHeight(hWnd, E_LIST, 18);

	for (i = 0;i < o->Num;i++)
	{
		wchar_t tmp[MAX_SIZE];
		MS_ADAPTER *a = o->Adapters[i];

		if (a->Info)
		{
			StrToUni(tmp, sizeof(tmp), a->Title);
			CbAddStr(hWnd, E_LIST, tmp, 0);
		}
	}


	// Re-select the previous selection
	if (old != NULL)
	{
		CbSelectIndex(hWnd, E_LIST, CbFindStr(hWnd, E_LIST, old));
		Free(old);
	}

	MsFreeAdapterList(o);

	g_ut_adapter_list_updating = false;
}

// Speedometer dialog control update
void UtSpeedMeterDlgUpdate(HWND hWnd)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}
}

// Speedometer dialog initialization
void UtSpeedMeterDlgInit(HWND hWnd)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	LvInitEx(hWnd, L_STATUS, true);
	LvInsertColumn(hWnd, L_STATUS, 0, _UU("UT_SM_COLUMN_1"), 150);
	LvInsertColumn(hWnd, L_STATUS, 1, _UU("UT_SM_COLUMN_2"), 290);

	UtSpeedMeterDlgRefreshList(hWnd);
	selected_adapter = GetTextA(hWnd, E_LIST);
	UtSpeedMeterDlgRefreshStatus(hWnd);
	UtSpeedMeterDlgUpdate(hWnd);
}

// Speedometer dialog
UINT UtSpeedMeterDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_NIC_ONLINE);
		UtSpeedMeterDlgInit(hWnd);
		SetTimer(hWnd, 1, SPEED_METER_REFRESH_INTERVAL, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			UtSpeedMeterDlgRefreshStatus(hWnd);
			UtSpeedMeterDlgUpdate(hWnd);
			SetTimer(hWnd, 1, SPEED_METER_REFRESH_INTERVAL, NULL);
			break;
		}
		break;

	case WM_COMMAND:
		if (HIWORD(wParam) == CBN_SELCHANGE) {
			Free(selected_adapter);
			selected_adapter = GetTextA(hWnd, E_LIST);
			UtSpeedMeterDlgUpdate(hWnd);
		} else {
			switch (wParam)
			{
			case B_REFRESH:
				UtSpeedMeterDlgRefreshList(hWnd);
				Free(selected_adapter);
				selected_adapter = GetTextA(hWnd, E_LIST);
				UtSpeedMeterDlgUpdate(hWnd);
				break;

			case IDCANCEL:
				Close(hWnd);
				break;
			}
		}
		break;

	case WM_CLOSE:
		Free(selected_adapter);
		selected_adapter = NULL;
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// Speedometer
void UtSpeedMeter()
{
	UtSpeedMeterEx(NULL);
}
void UtSpeedMeterEx(void *hWnd)
{
	Dialog((HWND)hWnd, D_SPEEDMETER, UtSpeedMeterDlgProc, NULL);
}

#endif // WIN32


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
