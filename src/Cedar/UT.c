// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


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
void UtSpeedMeterEx(void *hWnd)
{
	Dialog((HWND)hWnd, D_SPEEDMETER, UtSpeedMeterDlgProc, NULL);
}

#endif // WIN32

