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


// EM.c
// EtherLogger Manager for Win32

#include <GlobalConst.h>

#ifdef	WIN32

#define	SM_C
#define	CM_C
#define	NM_C
#define	EM_C

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


// License registration process
void EmLicenseAddDlgOnOk(HWND hWnd, RPC *s)
{
}

// Shift treatment of text input
void EmLicenseAddDlgShiftTextItem(HWND hWnd, UINT id1, UINT id2, UINT *next_focus)
{
	char *s;
	// Validate arguments
	if (hWnd == NULL || next_focus == NULL)
	{
		return;
	}

	s = GetTextA(hWnd, id1);
	if (StrLen(s) >= 6)
	{
		char *s2 = CopyStr(s);
		char tmp[MAX_SIZE];
		s2[6] = 0;
		SetTextA(hWnd, id1, s2);
		Free(s2);

		if (id2 != 0)
		{
			GetTxtA(hWnd, id2, tmp, sizeof(tmp));

			StrCat(tmp, sizeof(tmp), s + 6);
			ReplaceStrEx(tmp, sizeof(tmp), tmp, "-", "", false);

			SetTextA(hWnd, id2, tmp);

			*next_focus = id2;
		}
		else
		{
			*next_focus = IDOK;
		}
	}

	Free(s);
}

// Make a text from the input data
void EmLicenseAddDlgGetText(HWND hWnd, char *str, UINT size)
{
	char *k1, *k2, *k3, *k4, *k5, *k6;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	k1 = GetTextA(hWnd, B_KEY1);
	k2 = GetTextA(hWnd, B_KEY2);
	k3 = GetTextA(hWnd, B_KEY3);
	k4 = GetTextA(hWnd, B_KEY4);
	k5 = GetTextA(hWnd, B_KEY5);
	k6 = GetTextA(hWnd, B_KEY6);

	Format(str, size, "%s-%s-%s-%s-%s-%s", k1, k2, k3, k4, k5, k6);

	Free(k1);
	Free(k2);
	Free(k3);
	Free(k4);
	Free(k5);
	Free(k6);
}

// License addition dialog update
void EmLicenseAddDlgUpdate(HWND hWnd, RPC *s)
{
}

// License addition dialog initialization
void EmLicenseAddDlgInit(HWND hWnd, RPC *s)
{
	HFONT h;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	h = GetFont("Arial", 10, true, false, false, false);
	SetFont(hWnd, B_KEY1, h);
	SetFont(hWnd, B_KEY2, h);
	SetFont(hWnd, B_KEY3, h);
	SetFont(hWnd, B_KEY4, h);
	SetFont(hWnd, B_KEY5, h);
	SetFont(hWnd, B_KEY6, h);

	DlgFont(hWnd, S_INFO, 10, true);

	EmLicenseAddDlgUpdate(hWnd, s);
}

// License addition dialog
UINT EmLicenseAddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	RPC *s = (RPC *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		EmLicenseAddDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case B_KEY1:
		case B_KEY2:
		case B_KEY3:
		case B_KEY4:
		case B_KEY5:
		case B_KEY6:
			switch (HIWORD(wParam))
			{
			case EN_CHANGE:
				EmLicenseAddDlgUpdate(hWnd, s);

				switch (LOWORD(wParam))
				{
				case B_KEY2:
					if (GetTextLen(hWnd, B_KEY2, true) == 0)
					{
						FocusEx(hWnd, B_KEY1);
					}
					break;
				case B_KEY3:
					if (GetTextLen(hWnd, B_KEY3, true) == 0)
					{
						FocusEx(hWnd, B_KEY2);
					}
					break;
				case B_KEY4:
					if (GetTextLen(hWnd, B_KEY4, true) == 0)
					{
						FocusEx(hWnd, B_KEY3);
					}
					break;
				case B_KEY5:
					if (GetTextLen(hWnd, B_KEY5, true) == 0)
					{
						FocusEx(hWnd, B_KEY4);
					}
					break;
				case B_KEY6:
					if (GetTextLen(hWnd, B_KEY6, true) == 0)
					{
						FocusEx(hWnd, B_KEY5);
					}
					break;
				}
				break;
			}
			break;
		}

		switch (wParam)
		{
		case IDOK:
			EmLicenseAddDlgOnOk(hWnd, s);
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

// Add a license
bool EmLicenseAdd(HWND hWnd, RPC *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_EM_LICENSE_ADD, EmLicenseAddDlg, s);
}

// License dialog initialization
void EmLicenseDlgInit(HWND hWnd, RPC *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_CERT);

	DlgFont(hWnd, S_BOLD, 0, true);
	DlgFont(hWnd, S_BOLD2, 0, true);

	LvInit(hWnd, L_LIST);
	LvSetStyle(hWnd, L_LIST, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_LICENSE_COLUMN_1"), 50);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_LICENSE_COLUMN_2"), 100);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_LICENSE_COLUMN_3"), 290);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_LICENSE_COLUMN_4"), 150);
	LvInsertColumn(hWnd, L_LIST, 4, _UU("SM_LICENSE_COLUMN_5"), 120);
	LvInsertColumn(hWnd, L_LIST, 5, _UU("SM_LICENSE_COLUMN_6"), 250);
	LvInsertColumn(hWnd, L_LIST, 6, _UU("SM_LICENSE_COLUMN_7"), 100);
	LvInsertColumn(hWnd, L_LIST, 7, _UU("SM_LICENSE_COLUMN_8"), 100);
	LvInsertColumn(hWnd, L_LIST, 8, _UU("SM_LICENSE_COLUMN_9"), 100);

	LvInitEx(hWnd, L_STATUS, true);
	LvInsertColumn(hWnd, L_STATUS, 0, _UU("SM_STATUS_COLUMN_1"), 100);
	LvInsertColumn(hWnd, L_STATUS, 1, _UU("SM_STATUS_COLUMN_2"), 100);

	EmLicenseDlgRefresh(hWnd, s);
}

// License dialog update
void EmLicenseDlgRefresh(HWND hWnd, RPC *s)
{
	RPC_ENUM_LICENSE_KEY t;
	RPC_EL_LICENSE_STATUS st;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	LVB *b;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	if (CALL(hWnd, EcEnumLicenseKey(s, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumItem;i++)
	{
		wchar_t tmp1[32], tmp2[LICENSE_KEYSTR_LEN + 1], tmp3[LICENSE_MAX_PRODUCT_NAME_LEN + 1],
			*tmp4, tmp5[128], tmp6[LICENSE_LICENSEID_STR_LEN + 1], tmp7[64],
			tmp8[64], tmp9[64];
		RPC_ENUM_LICENSE_KEY_ITEM *e = &t.Items[i];

		UniToStru(tmp1, e->Id);
		StrToUni(tmp2, sizeof(tmp2), e->LicenseKey);
		StrToUni(tmp3, sizeof(tmp3), e->LicenseName);
		tmp4 = LiGetLicenseStatusStr(e->Status);
		if (e->Expires == 0)
		{
			UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_LICENSE_NO_EXPIRES"));
		}
		else
		{
			GetDateStrEx64(tmp5, sizeof(tmp5), e->Expires, NULL);
		}
		StrToUni(tmp6, sizeof(tmp6), e->LicenseId);
		UniToStru(tmp7, e->ProductId);
		UniFormat(tmp8, sizeof(tmp8), L"%I64u", e->SystemId);
		UniToStru(tmp9, e->SerialId);

		LvInsertAdd(b,
			e->Status == LICENSE_STATUS_OK ? ICO_PASS : ICO_DISCARD,
			(void *)e->Id, 9,
			tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9);
	}

	LvInsertEnd(b, hWnd, L_LIST);

	FreeRpcEnumLicenseKey(&t);

	Zero(&st, sizeof(st));

	if (CALL(hWnd, EcGetLicenseStatus(s, &st)) == false)
	{
		Close(hWnd);
		return;
	}

	b = LvInsertStart();

	if (st.Valid == false)
	{
		LvInsertAdd(b, 0, NULL, 2, _UU("EM_NO_LICENSE_COLUMN"), _UU("EM_NO_LICENSE"));
	}
	else
	{
		// Current system ID
		UniFormat(tmp, sizeof(tmp), L"%I64u", st.SystemId);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_SYSTEM_ID"), tmp);

		// Expiration date of the current license product
		if (st.SystemExpires == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_NO_EXPIRES"));
		}
		else
		{
			GetDateStrEx64(tmp, sizeof(tmp), st.SystemExpires, NULL);
		}
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_EXPIRES"), tmp);
	}

	LvInsertEnd(b, hWnd, L_STATUS);

	if (LvNum(hWnd, L_STATUS) >= 1)
	{
		LvAutoSize(hWnd, L_STATUS);
	}

	EmLicenseDlgUpdate(hWnd, s);
}

// License dialog control update
void EmLicenseDlgUpdate(HWND hWnd, RPC *s)
{
	bool b = false;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	b = LvIsSingleSelected(hWnd, L_LIST);

	SetEnable(hWnd, B_DEL, b);
	SetEnable(hWnd, IDOK, b);
}

// License dialog
UINT EmLicenseDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	RPC *s = (RPC *)param;
	NMHDR *n;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		EmLicenseDlgInit(hWnd, s);
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
			case L_STATUS:
				EmLicenseDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (IsEnable(hWnd, IDOK))
			{
				UINT i = LvGetSelected(hWnd, L_LIST);

				if (i != INFINITE)
				{
					char *s = LvGetStrA(hWnd, L_LIST, i, 5);
					char tmp[MAX_SIZE];

					Format(tmp, sizeof(tmp), _SS("LICENSE_SUPPORT_URL"), s);
					ShellExecute(hWnd, "open", tmp, NULL, NULL, SW_SHOW);

					Free(s);
				}
			}
			break;

		case B_OBTAIN:
			ShellExecute(hWnd, "open", _SS("LICENSE_INFO_URL"), NULL, NULL, SW_SHOW);
			break;

		case B_ADD:
			if (EmLicenseAdd(hWnd, s))
			{
				EmLicenseDlgRefresh(hWnd, s);
			}
			break;

		case B_DEL:
			if (IsEnable(hWnd, B_DEL))
			{
				UINT id = (UINT)LvGetParam(hWnd, L_LIST, LvGetSelected(hWnd, L_LIST));

				if (id != 0)
				{
					if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("SM_LICENSE_DELETE_MSG")) == IDYES)
					{
						RPC_TEST t;

						Zero(&t, sizeof(t));
						t.IntValue = id;

						if (CALL(hWnd, EcDelLicenseKey(s, &t)))
						{
							EmLicenseDlgRefresh(hWnd, s);
						}
					}
				}
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

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}





// Change Password dialog
UINT EmPasswordDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	RPC *r = (RPC *)param;
	char pass1[MAX_PATH];
	char pass2[MAX_PATH];
	UCHAR hash[SHA1_SIZE];
	RPC_SET_PASSWORD t;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		Focus(hWnd, E_PASSWORD1);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			GetTxtA(hWnd, E_PASSWORD1, pass1, sizeof(pass1));
			Hash(hash, pass1, StrLen(pass1), true);
			Zero(&t, sizeof(t));
			Copy(t.HashedPassword, hash, SHA1_SIZE);
			if (CALL(hWnd, EcSetPassword(r, &t)) == false)
			{
				break;
			}
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_PASSWORD_SET"));
			EndDialog(hWnd, 1);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}

		switch (LOWORD(wParam))
		{
		case E_PASSWORD1:
		case E_PASSWORD2:
			GetTxtA(hWnd, E_PASSWORD1, pass1, sizeof(pass1));
			GetTxtA(hWnd, E_PASSWORD2, pass2, sizeof(pass2));
			SetEnable(hWnd, IDOK, StrCmp(pass1, pass2) == 0 ? true : false);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// Copy the state of the dialog to the HUB_LOG
void EmDlgToHubLog(HWND hWnd, HUB_LOG *g)
{
	// Validate arguments
	if (hWnd == NULL || g == NULL)
	{
		return;
	}

	Zero(g, sizeof(HUB_LOG));
	g->PacketLogSwitchType = CbGetSelect(hWnd, C_PACKET_SWITCH);
	g->PacketLogConfig[0] = IsChecked(hWnd, B_PACKET_0_0) ? 0 : IsChecked(hWnd, B_PACKET_0_1) ? 1 : 2;
	g->PacketLogConfig[1] = IsChecked(hWnd, B_PACKET_1_0) ? 0 : IsChecked(hWnd, B_PACKET_1_1) ? 1 : 2;
	g->PacketLogConfig[2] = IsChecked(hWnd, B_PACKET_2_0) ? 0 : IsChecked(hWnd, B_PACKET_2_1) ? 1 : 2;
	g->PacketLogConfig[3] = IsChecked(hWnd, B_PACKET_3_0) ? 0 : IsChecked(hWnd, B_PACKET_3_1) ? 1 : 2;
	g->PacketLogConfig[4] = IsChecked(hWnd, B_PACKET_4_0) ? 0 : IsChecked(hWnd, B_PACKET_4_1) ? 1 : 2;
	g->PacketLogConfig[5] = IsChecked(hWnd, B_PACKET_5_0) ? 0 : IsChecked(hWnd, B_PACKET_5_1) ? 1 : 2;
	g->PacketLogConfig[6] = IsChecked(hWnd, B_PACKET_6_0) ? 0 : IsChecked(hWnd, B_PACKET_6_1) ? 1 : 2;
	g->PacketLogConfig[7] = IsChecked(hWnd, B_PACKET_7_0) ? 0 : IsChecked(hWnd, B_PACKET_7_1) ? 1 : 2;
}

// Copy the HUB_LOG to the state of the dialog 
void EmHubLogToDlg(HWND hWnd, HUB_LOG *g)
{
	// Validate arguments
	if (hWnd == NULL || g == NULL)
	{
		return;
	}

	CbSelect(hWnd, C_PACKET_SWITCH, g->PacketLogSwitchType);

	Check(hWnd, B_PACKET_0_0, g->PacketLogConfig[0] == 0);
	Check(hWnd, B_PACKET_0_1, g->PacketLogConfig[0] == 1);
	Check(hWnd, B_PACKET_0_2, g->PacketLogConfig[0] == 2);

	Check(hWnd, B_PACKET_1_0, g->PacketLogConfig[1] == 0);
	Check(hWnd, B_PACKET_1_1, g->PacketLogConfig[1] == 1);
	Check(hWnd, B_PACKET_1_2, g->PacketLogConfig[1] == 2);

	Check(hWnd, B_PACKET_2_0, g->PacketLogConfig[2] == 0);
	Check(hWnd, B_PACKET_2_1, g->PacketLogConfig[2] == 1);
	Check(hWnd, B_PACKET_2_2, g->PacketLogConfig[2] == 2);

	Check(hWnd, B_PACKET_3_0, g->PacketLogConfig[3] == 0);
	Check(hWnd, B_PACKET_3_1, g->PacketLogConfig[3] == 1);
	Check(hWnd, B_PACKET_3_2, g->PacketLogConfig[3] == 2);

	Check(hWnd, B_PACKET_4_0, g->PacketLogConfig[4] == 0);
	Check(hWnd, B_PACKET_4_1, g->PacketLogConfig[4] == 1);
	Check(hWnd, B_PACKET_4_2, g->PacketLogConfig[4] == 2);

	Check(hWnd, B_PACKET_5_0, g->PacketLogConfig[5] == 0);
	Check(hWnd, B_PACKET_5_1, g->PacketLogConfig[5] == 1);
	Check(hWnd, B_PACKET_5_2, g->PacketLogConfig[5] == 2);

	Check(hWnd, B_PACKET_6_0, g->PacketLogConfig[6] == 0);
	Check(hWnd, B_PACKET_6_1, g->PacketLogConfig[6] == 1);
	Check(hWnd, B_PACKET_6_2, g->PacketLogConfig[6] == 2);

	Check(hWnd, B_PACKET_7_0, g->PacketLogConfig[7] == 0);
	Check(hWnd, B_PACKET_7_1, g->PacketLogConfig[7] == 1);
	Check(hWnd, B_PACKET_7_2, g->PacketLogConfig[7] == 2);
}

// Initialize
void EmAddInit(HWND hWnd, EM_ADD *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	// Initialize controls
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_0"), 0);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_1"), 1);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_2"), 2);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_3"), 3);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_4"), 4);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_5"), 5);

	if (p->NewMode)
	{
		// Newly creation mode
		RPC_ENUM_DEVICE t;
		HUB_LOG g;

		Zero(&g, sizeof(g));
		g.PacketLogSwitchType = LOG_SWITCH_DAY;
		g.PacketLogConfig[PACKET_LOG_TCP_CONN] = g.PacketLogConfig[PACKET_LOG_DHCP] = 1;

		EmHubLogToDlg(hWnd, &g);

		Zero(&t, sizeof(t));
		if (CALL(hWnd, EcEnumAllDevice(p->Rpc, &t)))
		{
			UINT i;
			CbSetHeight(hWnd, C_DEVICE, 18);

			for (i = 0;i < t.NumItem;i++)
			{
				RPC_ENUM_DEVICE_ITEM *dev = &t.Items[i];
				wchar_t tmp[MAX_SIZE];

				StrToUni(tmp, sizeof(tmp), dev->DeviceName);

				CbAddStr(hWnd, C_DEVICE, tmp, 0);
			}

			FreeRpcEnumDevice(&t);
		}

		SetText(hWnd, 0, _UU("EM_ADD_NEW"));
	}
	else
	{
		// Edit mode (to obtain a configuration)
		wchar_t tmp[MAX_PATH];
		RPC_ADD_DEVICE t;
		Hide(hWnd, R_PROMISCUS);

		Zero(&t, sizeof(t));
		StrCpy(t.DeviceName, sizeof(t.DeviceName), p->DeviceName);

		if (CALL(hWnd, EcGetDevice(p->Rpc, &t)))
		{
			EmHubLogToDlg(hWnd, &t.LogSetting);
		}
		else
		{
			Close(hWnd);
		}

		StrToUni(tmp, sizeof(tmp), p->DeviceName);
		CbAddStr(hWnd, C_DEVICE, tmp, 0);

		Disable(hWnd, C_DEVICE);

		SetText(hWnd, 0, _UU("EM_ADD_EDIT"));
	}

	EmAddUpdate(hWnd, p);
}

// [OK] button
void EmAddOk(HWND hWnd, EM_ADD *p)
{
	RPC_ADD_DEVICE t;
	wchar_t *tmp;
	char *name;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	EmDlgToHubLog(hWnd, &t.LogSetting);
	tmp = CbGetStr(hWnd, C_DEVICE);
	name = CopyUniToStr(tmp);

	StrCpy(t.DeviceName, sizeof(t.DeviceName), name);

	if (p->NewMode)
	{
		t.NoPromiscus = IsChecked(hWnd, R_PROMISCUS);
	}

	if (p->NewMode)
	{
		if (CALL(hWnd, EcAddDevice(p->Rpc, &t)))
		{
			Close(hWnd);
		}
	}
	else
	{
		if (CALL(hWnd, EcSetDevice(p->Rpc, &t)))
		{
			Close(hWnd);
		}
	}

	Free(name);
	Free(tmp);
}

// Control update
void EmAddUpdate(HWND hWnd, EM_ADD *p)
{
	wchar_t *tmp;
	char *name;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	tmp = CbGetStr(hWnd, C_DEVICE);
	name = CopyUniToStr(tmp);

	Trim(name);

	if (StrLen(name) == 0)
	{
		Disable(hWnd, IDOK);
	}
	else
	{
		Enable(hWnd, IDCANCEL);
	}

	Free(name);
	Free(tmp);
}

// Device Add / Edit dialog
UINT EmAddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	EM_ADD *p = (EM_ADD *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		EmAddInit(hWnd, p);
		break;

	case WM_COMMAND:
		EmAddUpdate(hWnd, p);
		switch (wParam)
		{
		case IDOK:
			EmAddOk(hWnd, p);
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

// Add or edit
void EmAdd(HWND hWnd, RPC *r, char *device_name)
{
	EM_ADD p;
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	Zero(&p, sizeof(p));

	p.Rpc = r;

	if (device_name != NULL)
	{
		StrCpy(p.DeviceName, sizeof(p.DeviceName), device_name);
	}
	else
	{
		p.NewMode = true;
	}

	Dialog(hWnd, D_EM_ADD, EmAddDlg, &p);
}

// Initialize
void EmMainInit(HWND hWnd, RPC *r)
{
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("EM_MAIN_COLUMN_1"), 300);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("EM_MAIN_COLUMN_2"), 150);

	SetIcon(hWnd, 0, ICO_NIC_ONLINE);

	EmMainRefresh(hWnd, r);

	SetTimer(hWnd, 1, 1000, NULL);
}

// Control update
void EmMainUpdate(HWND hWnd, RPC *r)
{
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	SetEnable(hWnd, IDOK, LvIsMasked(hWnd, L_LIST) && LvIsMultiMasked(hWnd, L_LIST) == false);
	SetEnable(hWnd, B_DELETE, LvIsMasked(hWnd, L_LIST) && LvIsMultiMasked(hWnd, L_LIST) == false);
}

// Update
void EmMainRefresh(HWND hWnd, RPC *r)
{
	RPC_ENUM_DEVICE t;
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	if (CALL(hWnd, EcEnumDevice(r, &t)))
	{
		UINT i;
		LVB *b;

		b = LvInsertStart();

		for (i = 0;i < t.NumItem;i++)
		{
			wchar_t tmp[MAX_PATH];
			RPC_ENUM_DEVICE_ITEM *dev = &t.Items[i];

			StrToUni(tmp, sizeof(tmp), dev->DeviceName);

			LvInsertAdd(b,
				dev->Active ? ICO_NIC_ONLINE : ICO_NIC_OFFLINE,
				NULL,
				2,
				tmp,
				dev->Active ? _UU("EM_MAIN_OK") : _UU("EM_MAIN_ERROR"));
		}

		LvInsertEnd(b, hWnd, L_LIST);

		FreeRpcEnumDevice(&t);

		SetShow(hWnd, B_LICENSE, t.IsLicenseSupported);
	}
	else
	{
		Close(hWnd);
	}

	EmMainUpdate(hWnd, r);
}

// Main dialog procedure
UINT EmMainDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	RPC *r = (RPC *)param;
	UINT i;
	char *name;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		EmMainInit(hWnd, r);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// Edit
			i = LvGetSelected(hWnd, L_LIST);
			if (i != INFINITE)
			{
				wchar_t *tmp;
				tmp = LvGetStr(hWnd, L_LIST, i, 0);
				if (tmp != NULL)
				{
					name = CopyUniToStr(tmp);
					EmAdd(hWnd, r, name);
					Free(tmp);
					Free(name);
				}
			}
			break;

		case B_PASSWORD:
			// Admin password
			Dialog(hWnd, D_EM_PASSWORD, EmPasswordDlg, r);
			break;

		case B_LICENSE:
			// Admin password
			Dialog(hWnd, D_EM_LICENSE, EmLicenseDlg, r);
			break;

		case B_ADD:
			// Add
			EmAdd(hWnd, r, NULL);
			EmMainRefresh(hWnd, r);
			break;

		case B_DELETE:
			// Delete
			i = LvGetSelected(hWnd, L_LIST);
			if (i != INFINITE)
			{
				wchar_t *tmp;
				tmp = LvGetStr(hWnd, L_LIST, i, 0);
				if (tmp != NULL)
				{
					RPC_DELETE_DEVICE t;
					wchar_t msg[MAX_SIZE];
					name = CopyUniToStr(tmp);
					UniFormat(msg, sizeof(msg), _UU("EM_DELETE_CONFIRM"), name);
					if (MsgBox(hWnd, MB_YESNO | MB_ICONEXCLAMATION | MB_DEFBUTTON2, msg) == IDYES)
					{
						Zero(&t, sizeof(t));
						StrCpy(t.DeviceName, sizeof(t.DeviceName), name);
						if (CALL(hWnd, EcDelDevice(r, &t)))
						{
							EmMainRefresh(hWnd, r);
						}
					}
					Free(tmp);
					Free(name);
				}
			}
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
			EmMainRefresh(hWnd, r);
			SetTimer(hWnd, 1, 1000, NULL);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case NM_DBLCLK:
			switch (n->idFrom)
			{
			case L_LIST:
				if (IsEnable(hWnd, IDOK))
				{
					Command(hWnd, IDOK);
				}
				break;
			}
			break;
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
				EmMainUpdate(hWnd, r);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// Installation of WinPcap
void EmInstallWinPcap(HWND hWnd, RPC *r)
{
	wchar_t temp_name[MAX_SIZE];
	HGLOBAL g;
	HINSTANCE h;
	HRSRC hr;
	UINT size;
	void *data;
	IO *io;

	// Ask whether the user want to start the installation
	if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("EM_WPCAP_INSTALL")) == IDNO)
	{
		return;
	}

	// Generate a temporary file name
	UniFormat(temp_name, sizeof(temp_name), L"%s\\winpcap_installer.exe", MsGetTempDirW());

	// Read from the resource
	h = GetUiDll();
	hr = FindResource(h, MAKEINTRESOURCE(BIN_WINPCAP), "BIN");
	if (hr == NULL)
	{
RES_ERROR:
		MsgBox(hWnd, MB_ICONSTOP, _UU("EM_RESOURCE"));
		return;
	}

	g = LoadResource(h, hr);
	if (g == NULL)
	{
		goto RES_ERROR;
	}

	size = SizeofResource(h, hr);
	data = LockResource(g);

	if (data == NULL)
	{
		goto RES_ERROR;
	}

	// Write to a temporary file
	io = FileCreateW(temp_name);
	if (io == NULL)
	{
		goto RES_ERROR;
	}

	FileWrite(io, data, size);
	FileClose(io);

	// Run
	if (RunW(temp_name, NULL, false, true) == false)
	{
		// Failure
		FileDeleteW(temp_name);
		goto RES_ERROR;
	}

	FileDeleteW(temp_name);

	if (r == NULL)
	{
		return;
	}

	// Message after the end
	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) == false)
	{
		// Need to restart the computer
		MsgBox(hWnd, MB_ICONINFORMATION, _UU("EM_WPCAP_REBOOT1"));
	}
	else
	{
		// Need to restart the service
		if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("EM_WPCAP_REBOOT2")) == IDNO)
		{
			// Not restart
		}
		else
		{
			// Restart
			RPC_TEST t;
			RPC_BRIDGE_SUPPORT t2;
			Zero(&t, sizeof(t));
			EcRebootServer(r, &t);

			SleepThread(500);

			Zero(&t2, sizeof(t2));
			CALL(hWnd, EcGetBridgeSupport(r, &t2));
		}
	}
}

// Main screen
void EMMain(RPC *r)
{
	RPC_BRIDGE_SUPPORT t;

	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	// Examine the bridge support status of the server side first
	Zero(&t, sizeof(t));
	if (CALLEX(NULL, ScGetBridgeSupport(r, &t)) == ERR_NO_ERROR)
	{
		if (t.IsBridgeSupportedOs == false)
		{
			// OS does not support the bridge
			MsgBox(NULL, MB_ICONEXCLAMATION, _UU("EM_UNSUPPORTED"));
			return;
		}

		if (t.IsWinPcapNeeded)
		{
			if (r->Sock->RemoteIP.addr[0] != 127)
			{
				// WinPcap is required, but can not do anything because it is in remote management mode
				MsgBox(NULL, MB_ICONINFORMATION, _UU("EM_WPCAP_REMOTE"));
				return;
			}
			else
			{
				// WinPcap is required, and it's in local management mode
				if (MsIsAdmin())
				{
					// Administrators
					EmInstallWinPcap(NULL, r);
					return;
				}
				else
				{
					// Non-Administrators
					MsgBox(NULL, MB_ICONINFORMATION, _UU("EM_WPCAP_ROOT"));
					return;
				}
			}
		}
	}

	Dialog(NULL, D_EM_MAIN, EmMainDlg, r);
}

// Remote connection dialog procedure
UINT EmRemoteDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	WINUI_REMOTE *r = (WINUI_REMOTE *)param;
	CEDAR *c;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		RemoteDlgInit(hWnd, r);
		SetTimer(hWnd, 1, 100, NULL);
		break;
	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			RemoteDlgRefresh(hWnd, r);
			SetTimer(hWnd, 1, 100, NULL);
			break;
		}
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case R_LOCAL:
			if (IsChecked(hWnd, R_LOCAL) == false)
			{
				SetTextA(hWnd, C_HOSTNAME, "");
				RemoteDlgRefresh(hWnd, r);
				FocusEx(hWnd, C_HOSTNAME);
			}
			else
			{
				SetTextA(hWnd, C_HOSTNAME, "localhost");
				RemoteDlgRefresh(hWnd, r);
				Focus(hWnd, IDOK);
			}
			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		case IDOK:
			RemoteDlgOnOk(hWnd, r);
			break;
		case B_ABOUT:
			c = NewCedar(NULL, NULL);
			About(hWnd, c, _UU("PRODUCT_NAME_ELOGMGR"));
			ReleaseCedar(c);
		}
		switch (LOWORD(wParam))
		{
		case R_LOCAL:
		case C_HOSTNAME:
			RemoteDlgRefresh(hWnd, r);
			break;
		}
		break;
	case WM_CLOSE:
		FreeCandidateList(r->CandidateList);
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Remote connection dialog
char *EmRemoteDlg()
{
	WINUI_REMOTE r;

	Zero(&r, sizeof(r));
	r.RegKeyName = EM_REG_KEY;
	r.Caption = _UU("EM_TITLE");
	r.Title = _UU("EM_REMOTE_TITLE");
	r.Icon = ICO_USER_ADMIN;
	r.DefaultHostname = NULL;

	if (Dialog(NULL, D_EM_REMOTE, EmRemoteDlgProc, &r) == false)
	{
		return NULL;
	}

	return r.Hostname;
}

// Start the EtherLogger Manager
void EMExec()
{
	char *host;
	char *ret;
	bool cancel_now = false;
	TOKEN_LIST *t;
	UINT port = EL_ADMIN_PORT;
	InitWinUi(_UU("EM_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	while (true)
	{
		ret = EmRemoteDlg();

		if (ret != NULL)
		{
			t = ParseToken(ret, ":");
			if (t->NumTokens == 1 || t->NumTokens == 2)
			{
				RPC *rpc = NULL;
				bool ok = false;
				UINT ret;
				host = t->Token[0];
				if (t->NumTokens == 2)
				{
					port = ToInt(t->Token[1]);
				}
				else
				{
					port = EL_ADMIN_PORT;
				}

				// Try without a password first
				ret = EcConnect(host, port, "", &rpc);
RETRY:
				if (ret != ERR_NO_ERROR && ret != ERR_AUTH_FAILED)
				{
					// Connection failed
					CALL(NULL, ret);
				}
				else
				{
					if (ret == ERR_NO_ERROR)
					{
						// Successful connection
						ok = true;
					}
					else
					{
						// Password required
						char *pass = SmPassword(NULL, host);
						if (pass == NULL)
						{
							// Cancel
							cancel_now = true;
						}
						else
						{
							// Retry
							ret = EcConnect(host, port, pass, &rpc);
							Free(pass);
							if (ret == ERR_NO_ERROR)
							{
								ok = true;
							}
							else
							{
								goto RETRY;
							}
						}
					}
				}

				if (ok)
				{
					// Main screen
					EMMain(rpc);

					// Disconnect
					EcDisconnect(rpc);
					cancel_now = true;
				}
				FreeToken(t);
			}
			Free(ret);
		}
		else
		{
			cancel_now = true;
		}

		if (cancel_now)
		{
			break;
		}
	}

	FreeWinUi();
}

#endif	// WIN32

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
