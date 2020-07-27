// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// CM.c
// VPN Client Connection Manager for Win32

#include <GlobalConst.h>

#ifdef	WIN32

#define	CM_C
#define	SM_C
#define	MICROSOFT_C

#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#define	SECURITY_WIN32
#include <winsock2.h>
#include <windows.h>
#include <Iphlpapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <setupapi.h>
#include <regstr.h>
#include <process.h>
#include <psapi.h>
#include <wtsapi32.h>
#include <Ntsecapi.h>
#include <security.h>
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


// Get the proxy server settings from the registry string of IE
bool CmGetProxyServerNameAndPortFromIeProxyRegStr(char *name, UINT name_size, UINT *port, char *str, char *server_type)
{
	TOKEN_LIST *t;
	UINT i;
	bool ret = false;
	// Validate arguments
	if (name == NULL || port == NULL || str == NULL || server_type == NULL)
	{
		return false;
	}

	t = ParseToken(str, ";");

	for (i = 0;i < t->NumTokens;i++)
	{
		char *s = t->Token[i];
		UINT i;

		Trim(s);

		i = SearchStrEx(s, "=", 0, false);
		if (i != INFINITE)
		{
			char tmp[MAX_PATH];

			StrCpy(name, name_size, s);
			name[i] = 0;

			if (StrCmpi(name, server_type) == 0)
			{
				char *host;
				StrCpy(tmp, sizeof(tmp), s + i + 1);

				if (ParseHostPort(tmp, &host, port, 0))
				{
					StrCpy(name, name_size, host);
					Free(host);

					if (*port != 0)
					{
						ret = true;
					}
					break;
				}
			}
		}
	}

	FreeToken(t);

	return ret;
}


// Reflect the contents of the proxy settings to the connection settings
void CmProxyDlgSet(HWND hWnd, CLIENT_OPTION *o, CM_INTERNET_SETTING *setting)
{
	// Validate arguments
	if(hWnd == NULL || setting == NULL)
	{
		return;
	}

	// Make check in check-box
	Check(hWnd, R_DIRECT_TCP,	setting->ProxyType == PROXY_DIRECT);
	Check(hWnd, R_HTTPS,		setting->ProxyType == PROXY_HTTP);
	Check(hWnd, R_SOCKS,		setting->ProxyType == PROXY_SOCKS);
	Check(hWnd, R_SOCKS5,		setting->ProxyType == PROXY_SOCKS5);

	// Proxy Settings
	if(setting->ProxyType != PROXY_DIRECT)
	{
		StrCpy(o->ProxyName, sizeof(setting->ProxyHostName), setting->ProxyHostName);
		o->ProxyPort = setting->ProxyPort;
	}
}

// Get the proxy settings of IE
void CmGetSystemInternetSetting(CM_INTERNET_SETTING *setting)
{
	bool use_proxy;
	// Validate arguments
	if (setting == NULL)
	{
		return;
	}

	Zero(setting, sizeof(CM_INTERNET_SETTING));

	use_proxy = MsRegReadInt(REG_CURRENT_USER,
		"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
		"ProxyEnable");

	if (use_proxy)
	{
		char *str = MsRegReadStr(REG_CURRENT_USER,
			"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
			"ProxyServer");
		if (str != NULL)
		{
			char name[MAX_HOST_NAME_LEN + 1];
			UINT port;

			if (CmGetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
				&port, str, "https"))
			{
				setting->ProxyType = PROXY_HTTP;
				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
				setting->ProxyPort = port;
			}
			else if (CmGetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
				&port, str, "http"))
			{
				setting->ProxyType = PROXY_HTTP;
				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
				setting->ProxyPort = port;
			}
			else if (CmGetProxyServerNameAndPortFromIeProxyRegStr(name, sizeof(name),
				&port, str, "socks"))
			{
				setting->ProxyType = PROXY_SOCKS;
				StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), name);
				setting->ProxyPort = port;
			}
			else
			{
				if (SearchStrEx(str, "=", 0, false) == INFINITE)
				{
					char *host;
					UINT port;
					if (ParseHostPort(str, &host, &port, 0))
					{
						if (port != 0)
						{
							setting->ProxyType = PROXY_HTTP;
							StrCpy(setting->ProxyHostName, sizeof(setting->ProxyHostName), host);
							setting->ProxyPort = port;
						}
						Free(host);
					}
				}
			}

			Free(str);
		}
	}
}

// For the proxy settings to go through, use the IE settings
void CmProxyDlgUseForIE(HWND hWnd, CLIENT_OPTION *o)
{
	CM_INTERNET_SETTING s;

	// Validate arguments
	if(hWnd == NULL)
	{
		return;
	}

	Zero(&s, sizeof(s));
	CmGetSystemInternetSetting(&s);
	
	CmProxyDlgSet(hWnd, o, &s);
}

// Determine the bitmap ID of the smart card authentication screen
UINT CmGetSecureBitmapId(char *dest_hostname)
{
	// Validate arguments
	if (dest_hostname == NULL)
	{
		return 0;
	}

	if (EndWith(dest_hostname, ".cc.tsukuba.ac.jp"))
	{
		return BMP_TSUKUBA;
	}

	return 0;
}

// Activate the window of UAC
void CmSetUacWindowActive()
{
	HWND hWnd;

	if (MsIsVista() == false)
	{
		return;
	}
	
	hWnd = FindWindowA("$$$Secure UAP Dummy Window Class For Interim Dialog", NULL);
	if (hWnd == NULL)
	{
		return;
	}

	SwitchToThisWindow(hWnd, true);
}

// UAC helper thread
void CmUacHelperThread(THREAD *thread, void *param)
{
	CM_UAC_HELPER *c = (CM_UAC_HELPER *)param;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	while (c->Halt == false)
	{
		CmSetUacWindowActive();

		Wait(c->HaltEvent, 200);
	}
}

// Start the UAC helper
void *CmStartUacHelper()
{
	CM_UAC_HELPER *c = ZeroMalloc(sizeof(CM_UAC_HELPER));

	c->HaltEvent = NewEvent();
	c->Thread = NewThread(CmUacHelperThread, c);

	return (void *)c;
}

// Stop the UAC helper
void CmStopUacHelper(void *p)
{
	CM_UAC_HELPER *c = (CM_UAC_HELPER *)p;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	c->Halt = true;
	Set(c->HaltEvent);
	WaitThread(c->Thread, INFINITE);
	ReleaseEvent(c->HaltEvent);
	ReleaseThread(c->Thread);

	Free(c);
}

// Command invocation of the simple connection manager
void CmEasyDlgOnCommand(HWND hWnd, CM_EASY_DLG *d, WPARAM wParam, LPARAM lParam)
{
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	switch (wParam)
	{
	case B_MODE:
		Command(hWnd, CMD_CM_SETTING);
		return;

	case B_STATUS:
		Command(hWnd, CMD_STATUS);
		return;

	case IDCANCEL:
		Close(hWnd);
		return;

	}

	if (wParam == CMD_CONNECT)
	{
		cm->ConnectStartedFlag = false;
	}

	CmMainWindowOnCommandEx(hWnd, wParam, lParam, true);

	if (wParam == CMD_CONNECT && cm->ConnectStartedFlag)
	{
		// Close the window when the connection started successfully
		Close(hWnd);
	}
}

// Keyboard pressing of the simple connection manager
void CmEasyDlgOnKey(HWND hWnd, CM_EASY_DLG *d, bool ctrl, bool alt, UINT key)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Single key
	switch (key)
	{
	case VK_RETURN:
		Command(hWnd, IDOK);
		break;
	case VK_DELETE:
		// Delete
		if (IsFocus(hWnd, L_ACCOUNT))
		{
			// Operation on the account list
			Command(hWnd, CMD_DELETE);
		}
		else
		{
			// Operation on the virtual LAN card list
			Command(hWnd, CMD_DELETE_VLAN);
		}
		break;
	case VK_F2:
		// Change the name
		Command(hWnd, CMD_RENAME);
		break;
	case VK_F5:
		// Update the status
		Command(hWnd, CMD_REFRESH);
		break;
	}

	if (alt)
	{
		switch (key)
		{
		case 'Q':
			// Close
			Command(hWnd, CMD_QUIT);
			break;
		}
	}

	if (ctrl)
	{
		switch (key)
		{
		case 'G':
			// Smart Card Manager
			Command(hWnd, CMD_SECURE_MANAGER);
			break;
		case 'S':
			// Show the status
			Command(hWnd, CMD_STATUS);
			break;
		case 'I':
			// Disconnect all connections
			Command(hWnd, CMD_DISCONNECT_ALL);
			break;
		case 'D':
			// Disconnect
			Command(hWnd, CMD_DISCONNECT);
			break;
		case 'N':
			// Create a new connection setting
			Command(hWnd, CMD_NEW);
			break;
		case 'C':
			// Creating a copy
			Command(hWnd, CMD_CLONE);
			break;
		case 'T':
			// Set to start-up connection
			Command(hWnd, CMD_STARTUP);
			break;
		case 'A':
			// Select all
			Command(hWnd, CMD_SELECT_ALL);
			break;
		case 'L':
			// Create a new virtual LAN card
			Command(hWnd, CMD_NEW_VLAN);
			break;
		case 'P':
			// Set the password
			Command(hWnd, CMD_PASSWORD);
			break;
		case 'O':
			// Option settings
			Command(hWnd, CMD_TRAFFIC);
			break;
		case 'R':
			// Certificate management
			Command(hWnd, CMD_TRUST);
			break;
		case 'Q':
			// Throughput
			Command(hWnd, CMD_TRAFFIC);
			break;
		}
	}
}

// Operation on the list view of the simple connection manager
void CmEasyDlgOnNotify(HWND hWnd, CM_EASY_DLG *d, NMHDR *n)
{
	NMLVDISPINFOW *disp_info;
	NMLVKEYDOWN *key;

	// Validate arguments
	if (hWnd == NULL || n == NULL)
	{
		return;
	}

	switch (n->idFrom)
	{
	case L_ACCOUNT:
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			CmEasyDlgUpdate(hWnd, d);
			break;
		case NM_DBLCLK:
			// Double click
			Command(hWnd, CMD_EASY_DBLCLICK);
			break;
		case NM_RCLICK:
			// Right click
			CmAccountListRightClick(hWnd);
			break;
		case LVN_ENDLABELEDITW:
			// Change the name
			disp_info = (NMLVDISPINFOW *)n;
			if (disp_info->item.pszText != NULL)
			{
				wchar_t *new_name = disp_info->item.pszText;
				wchar_t *old_name = LvGetStr(hWnd, L_ACCOUNT, disp_info->item.iItem, 0);

				if (old_name != NULL)
				{
					if (UniStrCmp(new_name, old_name) != 0 && UniIsEmptyStr(new_name) == false)
					{
						RPC_RENAME_ACCOUNT a;
						Zero(&a, sizeof(a));
						UniStrCpy(a.OldName, sizeof(a.OldName), old_name);
						UniStrCpy(a.NewName, sizeof(a.NewName), new_name);
						if (CALL(hWnd, CcRenameAccount(cm->Client, &a)))
						{
							LvSetItem(hWnd, L_ACCOUNT, disp_info->item.iItem, 0, new_name);
						}
					}

					Free(old_name);
				}
			}
			break;
		case LVN_KEYDOWN:
			// Key-press
			key = (NMLVKEYDOWN *)n;
			if (key != NULL)
			{
				bool ctrl, alt;
				UINT code = key->wVKey;
				ctrl = (GetKeyState(VK_CONTROL) & 0x8000) == 0 ? false : true;
				alt = (GetKeyState(VK_MENU) & 0x8000) == 0 ? false : true;
				CmEasyDlgOnKey(hWnd, d, ctrl, alt, code);
			}
			break;
		}
		break;
	}
}

// Send an update notification to the Simple Connection Manager
void CmRefreshEasy()
{
	if (cm->hEasyWnd == NULL)
	{
		return;
	}

	SendMessage(cm->hEasyWnd, WM_CM_EASY_REFRESH, 0, 0);
}

// Initialize the Simple Connect Manager
void CmEasyDlgInit(HWND hWnd, CM_EASY_DLG *d)
{
	HFONT hFontForList;
	HFONT hFontButton;
	HFONT hFontTitle;
	HFONT hFontInfo;
	HFONT hFontOther;
	UINT i, num, num2, j;
	bool b = false;
	char *font_name = NULL;
	bool font_bold = true;
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_VPN);

	// Window handle registration
	cm->hEasyWnd = hWnd;

	// Show in the center
	Center(hWnd);

	// Update the account list
	CmInitAccountListEx(hWnd, true);

	// Font settings of the list
	if (cm->VistaStyle)
	{
		if (_GETLANG() == 0)
		{
			font_name = "Meiryo";
			font_bold = false;
		}
		else if (_GETLANG() == 2)
		{
			font_name = "Microsoft YaHei";
			font_bold = false;
		}
	}

	hFontForList = GetFont(font_name, 14, font_bold, false, false, false);
	hFontButton = GetFont(font_name, 13, font_bold, false, false, false);
	hFontTitle = GetFont(font_name, 14, font_bold, false, false, false);
	hFontInfo = GetFont(font_name, 11, font_bold, false, false, false);
	hFontOther = GetDialogDefaultFont();

	if (cm->VistaStyle)
	{
		hFontOther = GetMeiryoFont();
	}

	SetFont(hWnd, L_ACCOUNT, hFontForList);
	SetFont(hWnd, IDOK, hFontButton);
	SetFont(hWnd, S_TITLE, hFontTitle);
	SetFont(hWnd, S_INFO, hFontInfo);
	SetFont(hWnd, B_MODE, hFontOther);
	SetFont(hWnd, IDCANCEL, hFontOther);
	SetFont(hWnd, B_VGC, hFontOther);

	SetShow(hWnd, B_VGC, cm->Client->IsVgcSupported);

	CmEasyDlgRefresh(hWnd, d);

	num = LvNum(hWnd, L_ACCOUNT);
	num2 = 0;
	j = 0;
	for (i = 0;i < num;i++)
	{
		wchar_t *str = LvGetStr(hWnd, L_ACCOUNT, i, 1);

		if (str != NULL)
		{
			if (UniStrCmpi(str, _UU("CM_ACCOUNT_ONLINE")) == 0 || UniStrCmpi(str, _UU("CM_ACCOUNT_CONNECTING")) == 0)
			{
				num2++;
				j = i;
			}
			Free(str);
		}
	}

	if (num2 == 1)
	{
		LvSelect(hWnd, L_ACCOUNT, j);
		b = true;
	}

	if (b == false)
	{
		if (UniIsEmptyStr(cm->EasyLastSelectedAccountName) == false)
		{
			i = LvSearchStr(hWnd, L_ACCOUNT, 0, cm->EasyLastSelectedAccountName);
			if (i != INFINITE)
			{
				LvSelect(hWnd, L_ACCOUNT, i);
				b = true;
			}
		}
	}

	if (b == false)
	{
		if (LvNum(hWnd, L_ACCOUNT) != 0)
		{
			LvSelect(hWnd, L_ACCOUNT, 0);
		}
	}

	Focus(hWnd, L_ACCOUNT);

	CmEasyDlgUpdate(hWnd, d);
}

// Update the Simple Connection Manager control
void CmEasyDlgUpdate(HWND hWnd, CM_EASY_DLG *d)
{
	bool ok = true;
	bool show_status = false;
	wchar_t *button_str = _UU("CM_EASY_CONNECT_BUTTON_1");
	wchar_t *info_str = _UU("CM_EASY_INFO_1");
	wchar_t *title_str = _UU("CM_EASY_TITLE");
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	if (LvIsSingleSelected(hWnd, L_ACCOUNT) == false)
	{
		ok = false;
	}

	if (ok)
	{
		UINT i = LvGetSelected(hWnd, L_ACCOUNT);
		wchar_t *str = LvGetStr(hWnd, L_ACCOUNT, i, 1);

		info_str = _UU("CM_EASY_INFO_2");

		if (str != NULL)
		{
			if (UniStrCmpi(str, _UU("CM_ACCOUNT_ONLINE")) == 0 || UniStrCmpi(str, _UU("CM_ACCOUNT_CONNECTING")) == 0)
			{
				button_str = _UU("CM_EASY_CONNECT_BUTTON_2");
				show_status = true;
				info_str = _UU("CM_EASY_INFO_3");

				if (UniStrCmpi(str, _UU("CM_ACCOUNT_ONLINE")) == 0)
				{
					title_str = _UU("CM_EASY_CONNECTED");
				}
				else
				{
					title_str = _UU("CM_EASY_CONNECTING");
				}
			}
			Free(str);
		}
	}

	SetShow(hWnd, B_STATUS, show_status);

	SetText(hWnd, IDOK, button_str);
	SetText(hWnd, S_INFO, info_str);
	SetText(hWnd, S_TITLE, title_str);

	SetShow(hWnd, IDOK, ok);
}

// Update the Simple Connect Manager content
void CmEasyDlgRefresh(HWND hWnd, CM_EASY_DLG *d)
{
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	// Update the account list
	CmRefreshAccountListEx(hWnd, true);

	CmEasyDlgUpdate(hWnd, d);
}

// Dialog procedure of the simple connection manager
UINT CmEasyDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CM_EASY_DLG *d = (CM_EASY_DLG *)param;
	NMHDR *n;
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CmEasyDlgInit(hWnd, d);
		SetTimer(hWnd, 1, 10, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			SetForegroundWindow(hWnd);
			SetActiveWindow(hWnd);
			break;
		}
		break;

	case WM_CM_EASY_REFRESH:
		CmEasyDlgRefresh(hWnd, d);
		break;

	case WM_COMMAND:
		CmEasyDlgOnCommand(hWnd, d, wParam, lParam);
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		CmEasyDlgOnNotify(hWnd, d, n);
		break;

	case WM_CLOSE:
		i = LvGetSelected(hWnd, L_ACCOUNT);
		if (i != INFINITE)
		{
			wchar_t *s = LvGetStr(hWnd, L_ACCOUNT, i, 0);
			if (s != NULL)
			{
				UniStrCpy(cm->EasyLastSelectedAccountName, sizeof(cm->EasyLastSelectedAccountName),
					s);
				Free(s);
			}
		}
		else
		{
			Zero(cm->EasyLastSelectedAccountName, sizeof(cm->EasyLastSelectedAccountName));
		}
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Show the window of the simple connection manager (This is called by a delaying timer)
void CmMainWindowOnShowEasy(HWND hWnd)
{
	CM_EASY_DLG d;

	Zero(&d, sizeof(d));

	if (cm->CmSetting.EasyMode == false)
	{
		// Not in simple mode
		return;
	}

	if (cm->hEasyWnd != NULL)
	{
		// It is shown already
		SetForegroundWindow(cm->hEasyWnd);
		SetActiveWindow(cm->hEasyWnd);
		return;
	}

	Dialog(NULL, D_CM_EASY, CmEasyDlg, &d);

	cm->hEasyWnd = NULL;
}

// Show the window of the simple connection manager
void CmShowEasy()
{
	SetTimer(cm->hMainWnd, 4, 2, NULL);
}

// Close the window of the simple connection manager
void CmCloseEasy()
{
	if (cm->hEasyWnd == NULL)
	{
		return;
	}

	SendMessage(cm->hEasyWnd, WM_CLOSE, 0, 0);
}

// Message processing for such as clicking on the tray icon
void CmMainWindowOnTrayClicked(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	bool easymode = cm->CmSetting.EasyMode;

	switch (wParam)
	{
	case 1:
		switch (lParam)
		{
		case WM_LBUTTONDOWN:
		case WM_RBUTTONDOWN:
			// Click
			if (easymode == false)
			{
				if (IsEnable(hWnd, 0))
				{
					CmShowTrayMenu(hWnd);
				}
				else
				{
					CmShowOrHideWindow(hWnd);
				}
			}
			else
			{
				if (cm->hEasyWnd == NULL || IsEnable(cm->hEasyWnd, 0))
				{
					CmShowTrayMenu(hWnd);
				}
				else
				{
					//CmShowOrHideWindow(hWnd);
				}
			}
			break;
		case WM_LBUTTONDBLCLK:
		case WM_RBUTTONDBLCLK:
			// Double click
			if (easymode == false)
			{
				if (IsEnable(hWnd, 0))
				{
					CmShowOrHideWindow(hWnd);
				}
			}
			else
			{
				if (cm->hEasyWnd == NULL)
				{
					CmShowEasy();
				}
				else
				{
					SetForegroundWindow(cm->hEasyWnd);
					SetActiveWindow(cm->hEasyWnd);
				}
			}
			break;
		}
		break;
	}
}

// Apply the setting of the operation mode
void CmApplyCmSetting()
{
	CM_SETTING a;
	bool changed = false;

	if (cm->CmSettingSupported == false)
	{
		return;
	}

	// Get the configuration of the current vpnclient
	Zero(&a, sizeof(a));
	CcGetCmSetting(cm->Client, &a);

	// Check whether there is change point as compared to the previous CM_SETTING
	if (cm->CmSetting.EasyMode != a.EasyMode)
	{
		changed = true;
	}
	if (cm->CmSetting.LockMode != a.LockMode)
	{
		changed = true;
	}

	Copy(&cm->CmSetting, &a, sizeof(CM_SETTING));

	if (changed == false)
	{
		return;
	}

	if (cm->StartupFinished)
	{
		if (IsShow(cm->hMainWnd, 0) && cm->CmSetting.EasyMode)
		{
			// Close the main window if it is shown
			Hide(cm->hMainWnd, 0);
		}
		else
		{
			WINDOWPLACEMENT current_pos;
			if (cm->CmSetting.EasyMode == false && IsShow(cm->hMainWnd, 0) == false)
			{
				// When restored to normal mode, restore the main window
				if (IsZero(&cm->FakeWindowPlacement, sizeof(cm->FakeWindowPlacement)) == false)
				{
					cm->FakeWindowPlacement.flags = cm->FakeWindowPlacement.flags & ~SW_MINIMIZE;
					SetWindowPlacement(cm->hMainWnd, &cm->FakeWindowPlacement);
					Zero(&cm->FakeWindowPlacement, sizeof(cm->FakeWindowPlacement));
					Hide(cm->hMainWnd, 0);
				}
				CmShowOrHideWindow(cm->hMainWnd);
			}

			if (cm->CmSetting.EasyMode == false)
			{
				if (GetWindowPlacement(cm->hMainWnd, &current_pos))
				{
					if (current_pos.rcNormalPosition.right < 0 ||
						current_pos.rcNormalPosition.bottom < 0)
					{
						// If the window is off the screen for some reason,
						// return it in a visible place
						SetWindowPos(cm->hMainWnd, NULL, 0, 0, CM_DEFAULT_WIDTH, CM_DEFAULT_HEIGHT, SWP_NOREDRAW | SWP_SHOWWINDOW);
						Center(cm->hMainWnd);
					}
				}
			}
		}

		Command(cm->hMainWnd, CMD_REFRESH);
	}

	if (cm->CmSetting.EasyMode)
	{
		if (cm->StartupFinished == false && cm->StartupMode)
		{
			// Don't show in the case of /startup
		}
		else
		{
			CmShowEasy();
		}
	}
	else
	{
		CmCloseEasy();
	}
}

// Initialize the operation mode changing dialog
void CmSettingDlgInit(HWND hWnd, CM_SETTING_DLG *d)
{
	CM_SETTING a;
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	// Get the configuration of the current vpnclient
	Zero(&a, sizeof(a));
	CcGetCmSetting(cm->Client, &a);

	Check(hWnd, R_EASY, a.EasyMode);
	Check(hWnd, R_NORMAL, a.EasyMode == false);

	if (a.EasyMode == false)
	{
		Focus(hWnd, R_NORMAL);
	}
	else
	{
		Focus(hWnd, R_EASY);
	}

	Check(hWnd, R_LOCK, a.LockMode);

	SetEnable(hWnd, R_EASY, cm->CmEasyModeSupported);

	if (a.LockMode)
	{
		if (IsZero(a.HashedPassword, sizeof(a.HashedPassword)) == false)
		{
			// Password is set
			SetText(hWnd, S_PASSWORD1, _UU("CM_SETTING_PASSWORD"));
			Hide(hWnd, S_PASSWORD3);
			Hide(hWnd, E_PASSWORD2);

			d->CheckPassword = true;
			Copy(d->HashedPassword, a.HashedPassword, sizeof(d->HashedPassword));
		}
	}

	SetShow(hWnd, S_VGS1, cm->Client->IsVgcSupported);
	SetShow(hWnd, S_VGS2, cm->Client->IsVgcSupported);
	SetShow(hWnd, S_VGS3, cm->Client->IsVgcSupported);
	SetShow(hWnd, B_VGS, cm->Client->IsVgcSupported);

	CmSettingDlgUpdate(hWnd, d);
}

// Update the operation mode changing dialog
void CmSettingDlgUpdate(HWND hWnd, CM_SETTING_DLG *d)
{
	bool ok = true;
	char tmp1[MAX_SIZE], tmp2[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_PASSWORD1, tmp1, sizeof(tmp1));
	GetTxtA(hWnd, E_PASSWORD2, tmp2, sizeof(tmp2));

	if (d->CheckPassword == false)
	{
		if (IsChecked(hWnd, R_LOCK))
		{
			if (StrCmp(tmp1, tmp2) != 0)
			{
				ok = false;
			}
		}
	}
	else
	{
		bool password_ok = false;
		UCHAR hash[SHA1_SIZE];

		Sha0(hash, tmp1, StrLen(tmp1));
		if (Cmp(hash, d->HashedPassword, sizeof(hash)) == 0)
		{
			password_ok = true;
		}

		if (password_ok == false)
		{
			Check(hWnd, R_LOCK, true);
			Disable(hWnd, R_LOCK);
		}
		else
		{
			Enable(hWnd, R_LOCK);
		}
	}

	SetEnable(hWnd, S_PASSWORD1, IsChecked(hWnd, R_LOCK));
	SetEnable(hWnd, S_PASSWORD2, IsChecked(hWnd, R_LOCK));
	SetEnable(hWnd, S_PASSWORD3, IsChecked(hWnd, R_LOCK));
	SetEnable(hWnd, E_PASSWORD1, IsChecked(hWnd, R_LOCK));
	SetEnable(hWnd, E_PASSWORD2, IsChecked(hWnd, R_LOCK));

	SetEnable(hWnd, IDOK, ok);
}

// Operation mode changing dialog OK
void CmSettingDlgOnOk(HWND hWnd, CM_SETTING_DLG *d)
{
	CM_SETTING a;
	char tmp1[MAX_SIZE], tmp2[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_PASSWORD1, tmp1, sizeof(tmp1));
	GetTxtA(hWnd, E_PASSWORD2, tmp2, sizeof(tmp2));

	Zero(&a, sizeof(a));

	a.EasyMode = IsChecked(hWnd, R_EASY);
	a.LockMode = IsChecked(hWnd, R_LOCK);

	if (a.LockMode)
	{
		if (d->CheckPassword && IsEnable(hWnd, R_LOCK) == false)
		{
			Copy(a.HashedPassword, d->HashedPassword, sizeof(a.HashedPassword));
		}
		else
		{
			if (StrLen(tmp1) >= 1)
			{
				Sha0(a.HashedPassword, tmp1, StrLen(tmp1));
			}
		}
	}

	CcSetCmSetting(cm->Client, &a);

	EndDialog(hWnd, true);
}

// Operation mode changing dialog
UINT CmSettingDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CM_SETTING_DLG *d = (CM_SETTING_DLG *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CmSettingDlgInit(hWnd, d);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_EASY:
		case R_NORMAL:
		case R_LOCK:
		case E_PASSWORD1:
		case E_PASSWORD2:
		case IDOK:
		case IDCANCEL:
			CmSettingDlgUpdate(hWnd, d);
			break;
		}
		switch (wParam)
		{
		case IDOK:
			CmSettingDlgOnOk(hWnd, d);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case R_LOCK:
			if (IsChecked(hWnd, R_LOCK))
			{
				if (IsEmpty(hWnd, E_PASSWORD1))
				{
					Focus(hWnd, E_PASSWORD1);
				}
			}
			break;

		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}


// Change operation mode 
bool CmSetting(HWND hWnd)
{
	CM_SETTING_DLG d;

	Zero(&d, sizeof(d));

	return Dialog(hWnd, D_CM_SETTING, CmSettingDlg, &d);
}


// Attempting thread for starting the UI Helper
void CmTryToExecUiHelperThread(THREAD *thread, void *param)
{
	bool first_flag = true;

	while (cm->TryExecUiHelperHalt == false && cm->WindowsShutdowning == false)
	{
		if (first_flag == false)
		{
			// Wait a little for other than the first time
			Wait(cm->TryExecUiHelperHaltEvent, CM_TRY_EXEC_UI_HELPER_INTERVAL * 2);

			if (cm->TryExecUiHelperHalt || cm->WindowsShutdowning)
			{
				break;
			}
		}
		first_flag = false;

		if (cm->TryExecUiHelperHalt == false && cm->WindowsShutdowning == false)
		{
			if (cm->TryExecUiHelperProcessHandle == NULL)
			{
				CmTryToExecUiHelper();
			}
		}

		if (cm->TryExecUiHelperHalt || cm->WindowsShutdowning)
		{
			break;
		}

		if (cm->TryExecUiHelperProcessHandle == NULL)
		{
			Wait(cm->TryExecUiHelperHaltEvent, CM_TRY_EXEC_UI_HELPER_INTERVAL);
		}
		else
		{
			HANDLE handles[2];
			handles[0] = cm->TryExecUiHelperProcessHandle;
			handles[1] = (HANDLE)cm->TryExecUiHelperHaltEvent->pData;
			WaitForMultipleObjects(2, handles, false, CM_TRY_EXEC_UI_HELPER_INTERVAL);

			if (WaitForSingleObject(cm->TryExecUiHelperProcessHandle, 0) != WAIT_TIMEOUT)
			{
				CloseHandle(cm->TryExecUiHelperProcessHandle);
				cm->TryExecUiHelperProcessHandle = NULL;
				if (cm->TryExecUiHelperHalt || cm->WindowsShutdowning)
				{
					break;
				}
				Wait(cm->TryExecUiHelperHaltEvent, CM_TRY_EXEC_UI_HELPER_INTERVAL * 2);
			}
		}
	}
}

// Stop the UI Helper
void CmFreeTryToExecUiHelper()
{
	cm->TryExecUiHelperHalt = true;
	Set(cm->TryExecUiHelperHaltEvent);

	WaitThread(cm->TryExecUiHelperThread, INFINITE);

	ReleaseThread(cm->TryExecUiHelperThread);
	cm->TryExecUiHelperThread = NULL;

	ReleaseEvent(cm->TryExecUiHelperHaltEvent);
	cm->TryExecUiHelperHaltEvent = NULL;

	cm->TryExecUiHelperHalt = false;
	cm->TryExecUiHelperProcessHandle = NULL;
}

// Initialize the UI Helper starting
void CmInitTryToExecUiHelper()
{
	cm->TryExecUiHelperProcessHandle = NULL;
	cm->TryExecUiHelperHalt = false;
	cm->TryExecUiHelperHaltEvent = NewEvent();
	cm->TryExecUiHelperThread = NewThread(CmTryToExecUiHelperThread, NULL);
}

// Start the UI Helper
void *CmExecUiHelperMain()
{
	HANDLE h;
	wchar_t tmp[MAX_SIZE];

	UniFormat(tmp, sizeof(tmp), L"%s\\%S", MsGetExeDirNameW(), CLIENT_WIN32_EXE_FILENAME);

	// Start
	h = Win32RunExW(tmp, SVC_ARG_UIHELP_W, false);

	return (void *)h;
}

// Attempt to start the UI Helper
void CmTryToExecUiHelper()
{
	HANDLE h;
	// Check that it isn't already running
	if (CnCheckAlreadyExists(false))
	{
		// It have already started
		return;
	}

	h = (HANDLE)CmExecUiHelperMain();

	if (h != NULL)
	{
		cm->TryExecUiHelperProcessHandle = h;
	}
}

// Initialize the dialog
void CmTrafficResultDlgInit(HWND hWnd, TT_RESULT *res)
{
	LVB *ct;
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	char str[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || res == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SWITCH);

	SetFont(hWnd, L_STATUS, GetFont(_SS("DEFAULT_FONT_2"), 10, false, false, false, false));

	LvInit(hWnd, L_STATUS);
	LvSetStyle(hWnd, L_STATUS, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_STATUS, 0, _UU("TTC_RES_COLUMN_1"), 100);
	LvInsertColumn(hWnd, L_STATUS, 1, _UU("TTC_RES_COLUMN_2"), 100);
	LvInsertColumn(hWnd, L_STATUS, 2, _UU("TTC_RES_COLUMN_3"), 100);

	ct = LvInsertStart();

	// Time that was used to measure
	GetSpanStrMilli(str, sizeof(str), res->Span);
	StrToUni(tmp, sizeof(tmp), str);
	LvInsertAdd(ct, ICO_DATETIME, NULL, 3, _UU("TTC_RES_SPAN"), tmp, L"");

	// Correct the data for Ethernet frame
	LvInsertAdd(ct, ICO_INFORMATION, NULL, 3, _UU("TTC_RES_ETHER"), res->Raw ? _UU("SEC_NO") : _UU("SEC_YES"), L"");

	// Amount of communication data of download direction
	ToStr3(str, sizeof(str), res->NumBytesDownload);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesDownload);
	StrToUni(tmp2, sizeof(tmp2), str);
	LvInsertAdd(ct, ICO_INFORMATION, NULL, 3, _UU("TTC_RES_BYTES_DOWNLOAD"), tmp1, tmp2);

	// Amount of communication data of upload direction
	ToStr3(str, sizeof(str), res->NumBytesUpload);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesUpload);
	StrToUni(tmp2, sizeof(tmp2), str);
	LvInsertAdd(ct, ICO_INFORMATION, NULL, 3, _UU("TTC_RES_BYTES_UPLOAD"), tmp1, tmp2);

	// Total amount of communication data
	ToStr3(str, sizeof(str), res->NumBytesTotal);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesTotal);
	StrToUni(tmp2, sizeof(tmp2), str);
	LvInsertAdd(ct, ICO_INFORMATION, NULL, 3, _UU("TTC_RES_BYTES_TOTAL"), tmp1, tmp2);

	// Calculate the total throughput of input and output of the relay equipment
	LvInsertAdd(ct, ICO_INFORMATION, NULL, 3, _UU("TTC_RES_DOUBLE"), (res->Double == false) ? _UU("SEC_NO") : _UU("SEC_YES"), L"");

	// Average throughput of download direction
	ToStr3(str, sizeof(str), res->BpsDownload);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsDownload);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	LvInsertAdd(ct, ICO_INFORMATION, NULL, 3, _UU("TTC_RES_BPS_DOWNLOAD"), tmp1, tmp2);

	// Average throughput of upload direction
	ToStr3(str, sizeof(str), res->BpsUpload);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsUpload);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	LvInsertAdd(ct, ICO_INFORMATION, NULL, 3, _UU("TTC_RES_BPS_UPLOAD"), tmp1, tmp2);

	// Total average throughput
	ToStr3(str, sizeof(str), res->BpsTotal);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsTotal);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	LvInsertAdd(ct, ICO_INFORMATION, NULL, 3, _UU("TTC_RES_BPS_TOTAL"), tmp1, tmp2);

	LvInsertEnd(ct, hWnd, L_STATUS);

	LvAutoSize(hWnd, L_STATUS);
}

// Dialog procedure to display results of traffic measurements
UINT CmTrafficResultDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	TT_RESULT *r = (TT_RESULT *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CmTrafficResultDlgInit(hWnd, r);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
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

// Display results of traffic measurement
void CmTrafficResult(HWND hWnd, TT_RESULT *r)
{
	// Validate arguments
	if (r == NULL)
	{
		return;
	}

	Dialog(hWnd, D_CM_TRAFFIC_RESULT, CmTrafficResultDlg, r);
}

// Thread to wait for the termination of the client
void CmTrafficRunDlgClientWaitThread(THREAD *t, void *param)
{
	CM_TRAFFIC_DLG *d = (CM_TRAFFIC_DLG *)param;
	TT_RESULT result;
	UINT ret;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	Zero(&result, sizeof(result));
	ret = FreeTtc(d->Ttc, &result);
	d->Ttc = NULL;

	d->RetCode = ret;
	Copy(&d->Result, &result, sizeof(TT_RESULT));

	PostMessage(d->hWnd, WM_APP + 66, 0, 0);
}

// Append the string
void CmTrafficRunDlgAddStr(HWND hWnd, wchar_t *str)
{
	wchar_t *tmp;
	UINT tmp_size;

	tmp_size = UniStrSize(str) + 32;
	tmp = Malloc(tmp_size);
	UniStrCpy(tmp, tmp_size, str);
	if (UniEndWith(str, L"\n") == false)
	{
		UniStrCat(tmp, tmp_size, L"\n");
	}

	UniReplaceStrEx(tmp, tmp_size, tmp, L"\r\n", L"\n", false);
	UniReplaceStrEx(tmp, tmp_size, tmp, L"\n", L"\r\n", false);

	if (MsIsNt())
	{
		SendMsg(hWnd, E_EDIT, EM_SETSEL, 0x7fffffff, 0x7fffffff);
		SendMsg(hWnd, E_EDIT, EM_REPLACESEL, false, (LPARAM)tmp);
	}
	else
	{
		char *s = CopyUniToStr(tmp);
		UINT len;

		len = GetWindowTextLength(DlgItem(hWnd, E_EDIT));
		SendMsg(hWnd, E_EDIT, EM_SETSEL, 0x7fffffff, 0x7fffffff);
		SendMsg(hWnd, E_EDIT, EM_SETSEL, len, len);
		SendMsg(hWnd, E_EDIT, EM_REPLACESEL, false, (LPARAM)s);
		Free(s);
	}

	Free(tmp);
}

// Show the string
void CmTrafficRunDlgPrintProc(void *param, wchar_t *str)
{
	CM_TRAFFIC_DLG *d = (CM_TRAFFIC_DLG *)param;
	HWND hWnd;
	// Validate arguments
	if (param == NULL || str == NULL)
	{
		return;
	}

	hWnd = d->hWnd;

	PostMessage(hWnd, WM_APP + 64, 0, (LPARAM)UniCopyStr(str));
}

// Thread for stop the measurement program
void CmTrafficRunDlgHaltThread(THREAD *t, void *param)
{
	CM_TRAFFIC_DLG *d = (CM_TRAFFIC_DLG *)param;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	if (d->Setting->ServerMode)
	{
		// Stop the server
		d->RetCode = FreeTts(d->Tts);

		PostMessage(d->hWnd, WM_APP + 65, 0, 0);
	}
}

// Stop the measurement program
void CmTrafficRunDlgHalt(HWND hWnd, CM_TRAFFIC_DLG *d)
{
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	if (d->Started == false)
	{
		return;
	}

	if (d->Setting->ServerMode)
	{
		if (d->HaltThread == NULL)
		{
			Disable(hWnd, IDCANCEL);
			d->HaltThread = NewThread(CmTrafficRunDlgHaltThread, d);
		}
	}
	else
	{
		if (d->ClientEndWaitThread != NULL)
		{
			StopTtc(d->Ttc);
		}
		else
		{
			EndDialog(hWnd, 0);
		}
	}
}

// Start the operation of traffic measurement
void CmTrafficRunDlgStart(HWND hWnd, CM_TRAFFIC_DLG *d)
{
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	if (d->Setting->ServerMode)
	{
		// Start the measurement server
		d->Tts = NewTts(d->Setting->Port, d, CmTrafficRunDlgPrintProc);
	}
	else
	{
		// Start the measurement client
		d->Ttc = NewTtc(d->Setting->Host, d->Setting->Port,
			d->Setting->NumTcp, d->Setting->Type, d->Setting->Span * 1000ULL,
			d->Setting->Double, d->Setting->Raw, CmTrafficRunDlgPrintProc, d);

		d->ClientEndWaitThread = NewThread(CmTrafficRunDlgClientWaitThread, d);
	}

	d->Started = true;
}

// Traffic measurement operation dialog initialization
void CmTrafficRunDlgInit(HWND hWnd, CM_TRAFFIC_DLG *d)
{
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	d->hWnd = hWnd;

	SetIcon(hWnd, 0, ICO_SWITCH);
	DlgFont(hWnd, S_INFO, 11, false);
	SetFont(hWnd, E_EDIT, GetFont(_SS("DEFAULT_FONT_2"), 0, false, false,
		false, false));

	Focus(hWnd, IDCANCEL);
}

// Traffic measurement operation dialog procedure
UINT CmTrafficRunDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CM_TRAFFIC_DLG *d = (CM_TRAFFIC_DLG *)param;
	wchar_t *s;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CmTrafficRunDlgInit(hWnd, d);

		SetTimer(hWnd, 1, 10, NULL);
		break;

	case WM_APP + 64:
		// Add a string
		s = (wchar_t *)lParam;
		if (s != NULL)
		{
			CmTrafficRunDlgAddStr(hWnd, s);
			Free(s);
		}
		break;

	case WM_APP + 65:
		// Stopping complete
		if (d->HaltThread != NULL)
		{
			WaitThread(d->HaltThread, INFINITE);
			ReleaseThread(d->HaltThread);
			d->HaltThread = NULL;
			EndDialog(hWnd, 0);
		}
		break;

	case WM_APP + 66:
		// Show results
		if (d->RetCode == ERR_NO_ERROR)
		{
			CmTrafficResult(hWnd, &d->Result);
		}

		if (d->ClientEndWaitThread != NULL)
		{
			WaitThread(d->ClientEndWaitThread, INFINITE);
			ReleaseThread(d->ClientEndWaitThread);
			d->ClientEndWaitThread = NULL;
		}

		if (d->CloseDialogAfter)
		{
			EndDialog(hWnd, 0);
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			CmTrafficRunDlgStart(hWnd, d);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		d->CloseDialogAfter = true;
		CmTrafficRunDlgHalt(hWnd, d);
		return 1;
	}

	return 0;
}

// Execute a traffic measurement
void CmExecTraffic(HWND hWnd, CM_TRAFFIC *t)
{
	CM_TRAFFIC_DLG d;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Zero(&d, sizeof(d));
	d.Setting = t;
	d.ResultShowEvent = NewEvent();

	MsSetThreadPriorityHigh();
	Dialog(hWnd, D_CM_TRAFFIC_RUN, CmTrafficRunDlg, &d);
	MsRestoreThreadPriority();

	ReleaseEvent(d.ResultShowEvent);
}

// Write the settings to the registry
void CmTrafficSaveToReg(CM_TRAFFIC *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	MsRegWriteInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "ServerMode", t->ServerMode ? 1 : 0);
	MsRegWriteInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Double", t->Double ? 1 : 0);
	MsRegWriteInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Raw", t->Raw ? 1 : 0);
	MsRegWriteInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Port", t->Port);
	MsRegWriteInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "NumTcp", t->NumTcp);
	MsRegWriteInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Type", t->Type);
	MsRegWriteInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Span", t->Span);
	MsRegWriteStr(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Host", t->Host);
}

// Read the settings from the registry
bool CmTrafficLoadFromReg(CM_TRAFFIC *t)
{
	char *s;
	// Validate arguments
	if (t == NULL)
	{
		return false;
	}

	Zero(t, sizeof(CM_TRAFFIC));

	if (MsRegIsKey(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY) == false)
	{
		return false;
	}

	t->Double = MsRegReadInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Double") == 0 ? false : true;
	t->Raw = MsRegReadInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Raw") == 0 ? false : true;
	t->Port = MsRegReadInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Port");
	if (t->Port == 0)
	{
		t->Port = TRAFFIC_DEFAULT_PORT;
	}

	s = MsRegReadStr(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Host");

	if (IsEmptyStr(s) == false)
	{
		Trim(s);
		StrCpy(t->Host, sizeof(t->Host), s);
	}

	Free(s);

	t->NumTcp = MsRegReadInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "NumTcp");
	t->NumTcp = MAKESURE(t->NumTcp, 1, TRAFFIC_NUMTCP_MAX);
	t->Type = MsRegReadInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Type");

	if (t->Type != TRAFFIC_TYPE_DOWNLOAD && t->Type != TRAFFIC_TYPE_UPLOAD &&
		t->Type != TRAFFIC_TYPE_FULL)
	{
		t->Type = TRAFFIC_TYPE_FULL;
	}

	t->Span = MsRegReadInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "Span");
	if (t->Span == 0)
	{
		t->Span = TRAFFIC_SPAN_DEFAULT;
	}

	t->ServerMode = MsRegReadInt(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "ServerMode") == 0 ? false : true;

	return true;
}

// Get the default settings
void CmTrafficGetDefaultSetting(CM_TRAFFIC *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Zero(t, sizeof(CM_TRAFFIC));

	t->Double = false;
	t->Raw = false;
	t->Port = TRAFFIC_DEFAULT_PORT;
	t->NumTcp = TRAFFIC_NUMTCP_DEFAULT;
	t->Type = TRAFFIC_TYPE_FULL;
	t->Span = TRAFFIC_SPAN_DEFAULT;
	t->ServerMode = false;
}

// Communication throughput measurement tool dialog initialization
void CmTrafficDlgInit(HWND hWnd)
{
	CM_TRAFFIC t;
	LIST *c1, *c2;
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	DlgFont(hWnd, S_8, 9, true);
	DlgFont(hWnd, S_3, 9, true);

	Zero(&t, sizeof(t));
	if (CmTrafficLoadFromReg(&t) == false)
	{
		CmTrafficGetDefaultSetting(&t);
	}

	// Write the settings to the dialog
	Check(hWnd, R_SERVER, t.ServerMode);
	Check(hWnd, R_CLIENT, t.ServerMode == false);

	c1 = ReadCandidateFromReg(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "HostCandidate");
	if (c1 != NULL)
	{
		UINT i;

		CbReset(hWnd, C_HOST);

		for (i = 0;i < LIST_NUM(c1);i++)
		{
			CANDIDATE *c = LIST_DATA(c1, i);

			CbAddStr(hWnd, C_HOST, c->Str, 0);
		}

		FreeCandidateList(c1);
	}

	if (CbNum(hWnd, C_HOST) == 0)
	{
		CbAddStr(hWnd, C_HOST, L"speed.softether.com", 0);
	}

	if (IsEmptyStr(t.Host) == false)
	{
		SetTextA(hWnd, C_HOST, t.Host);
	}

	c2 = ReadCandidateFromReg(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "PortCandidate");
	if (c2 != NULL)
	{
		UINT i;

		if (t.Port != 0)
		{
			wchar_t tmp[32];

			UniToStru(tmp, t.Port);

			AddCandidate(c2, tmp, 0);
		}

		CbReset(hWnd, C_PORT);

		for (i = 0;i < LIST_NUM(c2);i++)
		{
			CANDIDATE *c = LIST_DATA(c2, i);

			CbAddStr(hWnd, C_PORT, c->Str, 0);
		}

		FreeCandidateList(c2);
	}

	CbReset(hWnd, C_NUM);

	for (i = 1;i <= TRAFFIC_NUMTCP_MAX;i++)
	{
		wchar_t tmp[32];

		UniToStru(tmp, i);

		CbAddStr(hWnd, C_NUM, tmp, i);
	}

	CbSelect(hWnd, C_NUM, t.NumTcp);

	Check(hWnd, R_DOWNLOAD, t.Type == TRAFFIC_TYPE_DOWNLOAD);
	Check(hWnd, R_UPLOAD, t.Type == TRAFFIC_TYPE_UPLOAD);
	Check(hWnd, R_FULL, t.Type == TRAFFIC_TYPE_FULL);

	Check(hWnd, R_ETHERNET, t.Raw ? false : true);
	Check(hWnd, R_DOUBLE, t.Double);

	SetIntEx(hWnd, E_SPAN, t.Span);

	CmTrafficDlgUpdate(hWnd);
}

// Put the contents of the dialog to structure
void CmTrafficDlgToStruct(HWND hWnd, CM_TRAFFIC *t)
{
	// Validate arguments
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	Zero(t, sizeof(CM_TRAFFIC));
	t->ServerMode = IsChecked(hWnd, R_SERVER);
	GetTxtA(hWnd, C_HOST, t->Host, sizeof(t->Host));
	Trim(t->Host);

	t->Port = GetInt(hWnd, C_PORT);
	t->NumTcp = CbGetSelect(hWnd, C_NUM);
	t->Span = GetInt(hWnd, E_SPAN);
	t->Raw = IsChecked(hWnd, R_ETHERNET) ? false : true;
	t->Double = IsChecked(hWnd, R_DOUBLE);

	if (IsChecked(hWnd, R_DOWNLOAD))
	{
		t->Type = TRAFFIC_TYPE_DOWNLOAD;
	}
	else if (IsChecked(hWnd, R_UPLOAD))
	{
		t->Type = TRAFFIC_TYPE_UPLOAD;
	}
	else
	{
		t->Type = TRAFFIC_TYPE_FULL;
	}
}

// Communication throughput measurement tool dialog update
bool CmTrafficDlgUpdate(HWND hWnd)
{
	CM_TRAFFIC t;
	bool ok = true;
	bool client_only;
	// Validate arguments
	if (hWnd == NULL)
	{
		return false;
	}

	CmTrafficDlgToStruct(hWnd, &t);

	client_only = t.ServerMode ? false : true;

	SetEnable(hWnd, C_HOST, client_only);
	SetEnable(hWnd, S_5, client_only);
	SetEnable(hWnd, S_8, client_only);
	SetEnable(hWnd, S_9, client_only);
	SetEnable(hWnd, R_DOWNLOAD, client_only);
	SetEnable(hWnd, R_UPLOAD, client_only);
	SetEnable(hWnd, R_FULL, client_only);
	SetEnable(hWnd, S_10, client_only);
	SetEnable(hWnd, S_11, client_only);
	SetEnable(hWnd, C_NUM, client_only);
	SetEnable(hWnd, S_14, client_only);
	SetEnable(hWnd, S_12, client_only);
	SetEnable(hWnd, E_SPAN, client_only);
	SetEnable(hWnd, S_13, client_only);
	SetEnable(hWnd, R_ETHERNET, client_only);
	SetEnable(hWnd, R_DOUBLE, client_only);

	if (t.Port == 0 || t.Port >= 65536)
	{
		ok = false;
	}

	if (t.ServerMode == false)
	{
		if (IsEmptyStr(t.Host))
		{
			ok = false;
		}

		if (t.NumTcp == 0 || t.NumTcp >= 33)
		{
			ok = false;
		}

		if (t.Span == 0)
		{
			ok = false;
		}

		if (t.Type == TRAFFIC_TYPE_FULL && ((t.NumTcp % 2) != 0))
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);

	return ok;
}

// Communication throughput measurement tool dialog OK button
void CmTrafficDlgOnOk(HWND hWnd)
{
	CM_TRAFFIC t;
	LIST *c;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Get the basic data
	CmTrafficDlgToStruct(hWnd, &t);

	// Save to registry
	CmTrafficSaveToReg(&t);

	// Retrieve and save the server name candidate
	if (IsEmptyStr(t.Host) == false)
	{
		c = ReadCandidateFromReg(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "HostCandidate");
		if (c != NULL)
		{
			wchar_t tmp[MAX_SIZE];

			StrToUni(tmp, sizeof(tmp), t.Host);
			AddCandidate(c, tmp, 0);

			WriteCandidateToReg(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, c, "HostCandidate");

			FreeCandidateList(c);
		}
	}

	if (t.Port != 0 && t.Port <= 65536)
	{
		// Retrieve and store the port number candidate
		c = ReadCandidateFromReg(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, "PortCandidate");
		if (c != NULL)
		{
			wchar_t tmp[MAX_SIZE];

			UniToStru(tmp, t.Port);
			AddCandidate(c, tmp, 0);

			WriteCandidateToReg(REG_CURRENT_USER, CM_TRAFFIC_REG_KEY, c, "PortCandidate");

			FreeCandidateList(c);
		}
	}

	// Execute
	CmExecTraffic(hWnd, &t);

	// Update the dialog
	CmTrafficDlgInit(hWnd);
}

// Communication throughput measurement tool dialog procedure
UINT CmTrafficDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_SWITCH);
		CmTrafficDlgInit(hWnd);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_SERVER:
		case R_CLIENT:
		case C_HOST:
		case C_PORT:
		case R_DOWNLOAD:
		case R_UPLOAD:
		case R_FULL:
		case C_NUM:
		case E_SPAN:
		case R_ETHERNET:
		case R_DOUBLE:
			CmTrafficDlgUpdate(hWnd);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			CmTrafficDlgOnOk(hWnd);
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

// Communication throughput measurement tool
void CmTraffic(HWND hWnd)
{
	Dialog(hWnd, D_CM_TRAFFIC, CmTrafficDlgProc, NULL);
}

// Delete old startup file
void CmDeleteOldStartupTrayFile()
{
	char tmp[MAX_SIZE];
	char *tag = _SS("CM_JAPANESE_ONLY_OLD_STARTUP");
	if (IsEmptyStr(tag))
	{
		return;
	}

	Format(tmp, sizeof(tmp), tag, MsGetCommonStartupDir());

	FileDelete(tmp);
}

// PKCS license confirmation dialog
UINT CmPkcsEulaDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UINT id;
	SECURE_DEVICE *dev;
	char *name;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		id = (UINT)param;
		dev = GetSecureDevice(id);
		if (dev == NULL)
		{
			EndDialog(hWnd, 0);
			return 0;
		}

		name = dev->ModuleName;

		FormatText(hWnd, S_INFO_1, name);
		FormatText(hWnd, S_INFO_2, name, name);
		FormatText(hWnd, S_INFO_3, name);

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			EndDialog(hWnd, 1);
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

// Confirmation screen of whether the user accepts the EULA of the PKCS DLL
bool CmCheckPkcsEula(HWND hWnd, UINT id)
{
	return (Dialog(hWnd, D_CM_PKCSEULA, CmPkcsEulaDlg, (void *)id) == 0) ? false : true;
}

// Update controls
void CmSecurePinDlgUpdate(HWND hWnd)
{
	char *tmp1, *tmp2, *tmp3;
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	tmp1 = GetTextA(hWnd, E_PIN1);
	tmp2 = GetTextA(hWnd, E_PIN2);
	tmp3 = GetTextA(hWnd, E_PIN3);
	if (IsEmptyStr(tmp1))
	{
		ok = false;
	}
	if (IsEmptyStr(tmp2))
	{
		ok = false;
	}
	if (IsEmptyStr(tmp3))
	{
		ok = false;
	}
	if (StrCmp(tmp2, tmp3) != 0)
	{
		ok = false;
	}
	Free(tmp1);
	Free(tmp2);
	Free(tmp3);
	SetEnable(hWnd, IDOK, ok);
}

// PIN code changing dialog
UINT CmSecurePinDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UINT id = (UINT)param;
	char *src, *dst;
	SECURE *s;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CmSecurePinDlgUpdate(hWnd);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PIN1:
		case E_PIN2:
		case E_PIN3:
			CmSecurePinDlgUpdate(hWnd);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			src = GetTextA(hWnd, E_PIN1);
			dst = GetTextA(hWnd, E_PIN3);

			Disable(hWnd, IDOK);
			Disable(hWnd, IDCANCEL);

			s = OpenSec(id);
			if (s == NULL)
			{
				if (GetSecureDevice(id) != NULL)
				{
					MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SEC_PIN_DEVICE_OPEN_ERR"),
						GetSecureDevice(id)->DeviceName);
				}
				else
				{
					MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SEC_PIN_DEVICE_OPEN_ERR"),
						"Unknown");
				}
			}
			else
			{
				if (OpenSecSession(s, 0) == false)
				{
					if (GetSecureDevice(id) != NULL)
					{
						MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SEC_PIN_DEVICE_OPEN_ERR"),
							GetSecureDevice(id)->DeviceName);
					}
					else
					{
						MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SEC_PIN_DEVICE_OPEN_ERR"),
							"Unknown");
					}
				}
				else
				{
					if (LoginSec(s, src) == false)
					{
						MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SEC_PIN_CURRENT_BAD"));
						FocusEx(hWnd, E_PIN1);
					}
					else
					{
						if (ChangePin(s, src, dst) == false)
						{
							MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SEC_PIN_CHANGE_FAILED"));
							FocusEx(hWnd, E_PIN1);
						}
						else
						{
							// Clear the cache for PIN code
							cached_pin_code_expires = 0;
							cached_pin_code[0] = 0;
							MsgBox(hWnd, MB_ICONINFORMATION, _UU("SEC_PIN_OK"));
							EndDialog(hWnd, true);
						}

						LogoutSec(s);
					}

					CloseSecSession(s);
				}
				CloseSec(s);
			}

			Enable(hWnd, IDOK);
			Enable(hWnd, IDCANCEL);

			Free(src);
			Free(dst);
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

// Change the PIN code
void CmSecurePin(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL || id == 0 || CheckSecureDeviceId(id) == false)
	{
		return;
	}

	Dialog(hWnd, D_CM_SECURE_PIN, CmSecurePinDlg, (void *)id);
}

// Object type selection dialog
UINT CmSecureTypeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UINT type;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		type = MsRegReadInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "DefaultImportType");
		Check(hWnd, R_DATA, type == SEC_DATA);
		Check(hWnd, R_CERT, type == SEC_X);
		Check(hWnd, R_KEY, type == SEC_K);
		goto UPDATE_CONTROL;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			type = SEC_DATA;
			if (IsChecked(hWnd, R_CERT))
			{
				type = SEC_X;
			}
			else if (IsChecked(hWnd, R_KEY))
			{
				type = SEC_K;
			}

			MsRegWriteInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "DefaultImportType", type);

			EndDialog(hWnd, type);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		case R_CERT:
		case R_KEY:
		case R_DATA:
UPDATE_CONTROL:
			SetEnable(hWnd, IDOK, IsChecked(hWnd, R_CERT) || 
				IsChecked(hWnd, R_KEY) || 
				IsChecked(hWnd, R_DATA));
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, INFINITE);
		break;
	}

	return 0;
}

// Object type selection
UINT CmSecureType(HWND hWnd)
{
	return Dialog(hWnd, D_CM_SECURE_TYPE, CmSecureTypeDlg, NULL);
}

// Initialize the dialog
void CmSecureManagerDlgInit(HWND hWnd, UINT id)
{
	SECURE_DEVICE *dev;
	// Validate arguments
	if (hWnd == NULL || id == 0)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SECURE);

	dev = GetSecureDevice(id);
	if (dev != NULL)
	{
		FormatText(hWnd, S_INFO, dev->DeviceName);
	}

	SetFont(hWnd, B_BOLD, Font(0, true));

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SEC_MGR_COLUMN1"), 200);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SEC_MGR_COLUMN2"), 110);

	CmSecureManagerDlgUpdate(hWnd, id);
}

// Update controls
void CmSecureManagerDlgUpdate(HWND hWnd, UINT id)
{
	bool b = true;
	bool read_only = IsJPKI(id);
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (LvIsSingleSelected(hWnd, L_LIST) == false)
	{
		b = false;
	}

	SetEnable(hWnd, B_EXPORT, b && ((UINT)LvGetParam(hWnd, L_LIST, LvGetSelected(hWnd, L_LIST)) != SEC_K));
	SetEnable(hWnd, B_DELETE, b && (read_only == false));
	SetEnable(hWnd, B_PIN, (read_only == false));
	SetEnable(hWnd, B_IMPORT, (read_only == false));
	SetEnable(hWnd, B_NEW_CERT, (read_only == false));
}

// Content update
void CmSecureManagerDlgRefresh(HWND hWnd, UINT id)
{
	bool ret;
	LIST *o;
	WINUI_SECURE_BATCH batch[] =
	{
		{WINUI_SECURE_ENUM_OBJECTS, NULL, false, NULL, NULL, NULL, NULL, NULL, NULL},
	};
	// Validate arguments
	if (hWnd == NULL || id == 0)
	{
		return;
	}

	ret = SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), id, 0);

	if (ret == false)
	{
		return;
	}

	o = batch[0].EnumList;
	if (o != NULL)
	{
		CmSecureManagerDlgPrintList(hWnd, o);

		FreeEnumSecObject(o);
	}

	// update controls
	CmSecureManagerDlgUpdate(hWnd, id);
}

// Show the list of secure objects
void CmSecureManagerDlgPrintList(HWND hWnd, LIST *o)
{
	CmSecureManagerDlgPrintListEx(hWnd, L_LIST, o, INFINITE);
}
void CmSecureManagerDlgPrintListEx(HWND hWnd, UINT id, LIST *o, UINT type)
{
	UINT i;
	LVB *v;
	// Validate arguments
	if (hWnd == NULL || o == NULL)
	{
		return;
	}

	LvReset(hWnd, id);

	v = LvInsertStart();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT icon = ICO_LOG2;
		wchar_t tmp1[MAX_SIZE], *tmp2, *tmp3;
		SEC_OBJ *obj = LIST_DATA(o, i);

		if (type == INFINITE || obj->Type == type)
		{
			StrToUni(tmp1, sizeof(tmp1), obj->Name);
			tmp2 = CmSecureObjTypeToStr(obj->Type);
			tmp3 = obj->Private ? _UU("SEC_YES") : _UU("SEC_NO");

			if (obj->Type == SEC_X)
			{
				icon = ICO_CERT;
			}
			else if (obj->Type == SEC_K || obj->Type == SEC_P)
			{
				icon = ICO_KEY;
			}

			LvInsertAdd(v, icon, (void *)obj->Type, 2, tmp1, tmp2);
		}
	}

	LvInsertEnd(v, hWnd, id);
}

// Convert the type of secure object to a string
wchar_t *CmSecureObjTypeToStr(UINT type)
{
	wchar_t *ret = _UU("SEC_TYPE_DATA");

	if (type == SEC_X)
	{
		ret = _UU("SEC_TYPE_CERT");
	}
	else if (type == SEC_K)
	{
		ret = _UU("SEC_TYPE_KEY");
	}
	else if (type == SEC_P)
	{
		ret = _UU("SEC_TYPE_PUB");
	}

	return ret;
}

// Write by creating a new certificate
void CmSecureManagerDlgNewCert(HWND hWnd, UINT id)
{
	X *x;
	K *k;
	char default_name[MAX_SIZE];
	char *object_name;
	bool ok = false;
	WINUI_SECURE_BATCH batch[] =
	{
		{WINUI_SECURE_WRITE_CERT, NULL, true, NULL, NULL, NULL, NULL, NULL, NULL},
		{WINUI_SECURE_WRITE_KEY, NULL, true, NULL, NULL, NULL, NULL, NULL, NULL},
		{WINUI_SECURE_ENUM_OBJECTS, NULL, false, NULL, NULL, NULL, NULL, NULL, NULL},
	};
	// Validate arguments
	if (hWnd == NULL || id == 0)
	{
		return;
	}

	// Dialog for creating certificate
	if (SmCreateCert(hWnd, &x, &k, true, NULL, false) == false)
	{
		return;
	}
	// Generate the default name
	GetPrintNameFromXA(default_name, sizeof(default_name), x);
	ConvertSafeFileName(default_name, sizeof(default_name), default_name);

	object_name = StringDlgA(hWnd, _UU("SEC_OBJECT_NAME_TITLE"),
		_UU("SEC_OBJECT_NAME_INFO"), default_name, ICO_CERT, false, false);

	if (object_name != NULL)
	{
		// Enumerate and write
		batch[0].InputX = x;
		batch[0].Name = object_name;
		batch[1].InputK = k;
		batch[1].Name = object_name;

		if (SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), id, 0) == false)
		{
			// Failure
		}
		else
		{
			ok = true;
		}

		Free(object_name);
	}

	if (ok)
	{
		LIST *o = batch[2].EnumList;

		CmSecureManagerDlgPrintList(hWnd, o);

		FreeEnumSecObject(o);

		MsgBox(hWnd, MB_ICONINFORMATION, _UU("SEC_NEW_CERT_IMPORT_OK"));
	}

	FreeX(x);
	FreeK(k);
}

// Import
void CmSecureManagerDlgImport(HWND hWnd, UINT id)
{
	UINT type;
	char name[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	wchar_t *tmp;
	wchar_t *filename;
	BUF *b;
	K *k;
	bool ok = false;
	X *x;
	WINUI_SECURE_BATCH batch[] =
	{
		{WINUI_SECURE_WRITE_DATA, name, true, NULL, NULL, NULL, NULL, NULL, NULL},
		{WINUI_SECURE_ENUM_OBJECTS, NULL, false, NULL, NULL, NULL, NULL, NULL, NULL},
	};
	// Validate arguments
	if (hWnd == NULL || id == 0)
	{
		return;
	}

	// Select the type of secure object
	type = CmSecureType(hWnd);

	switch (type)
	{
	case SEC_DATA:
		// Data
		tmp = OpenDlg(hWnd, _UU("DLG_ALL_FILES"), _UU("SEC_IMPORT_DATA"));
		if (tmp == NULL)
		{
			return;
		}

		filename = CopyUniStr(tmp);
		Free(tmp);

		// Read the file
		b = ReadDumpW(filename);
		if (b == NULL)
		{
			// Read failure
			MsgBox(hWnd, MB_ICONSTOP, _UU("SEC_READ_FAILED"));
		}
		else
		{
			if (b->Size > MAX_SEC_DATA_SIZE)
			{
				// File size is too large
				MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SEC_DATA_TOO_BIG"), MAX_SEC_DATA_SIZE);
			}
			else
			{
				// Generate the default name
				char default_name[MAX_SIZE];
				wchar_t default_name_w[MAX_SIZE];
				char *object_name;
				GetFileNameFromFilePathW(default_name_w, sizeof(default_name_w), filename);
				UniToStr(default_name, sizeof(default_name), default_name_w);
				ConvertSafeFileName(default_name, sizeof(default_name), default_name);

				object_name = StringDlgA(hWnd, _UU("SEC_OBJECT_NAME_TITLE"),
					_UU("SEC_OBJECT_NAME_INFO"), default_name, ICO_LOG2, false, false);

				if (object_name != NULL)
				{
					// Enumerate and write
					batch[0].InputData = b;
					batch[0].Name = object_name;

					if (SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), id, 0) == false)
					{
						// Failure
					}
					else
					{
						ok = true;
					}

					Free(object_name);
				}
			}

			FreeBuf(b);
		}

		Free(filename);
		break;

	case SEC_X:
		// Read a certificate
		if (CmLoadXExW(hWnd, &x, tmp2, sizeof(tmp2)))
		{
			// Generate the default name
			char default_name[MAX_SIZE];
			wchar_t default_name_w[MAX_PATH];
			char *object_name;
			GetFileNameFromFilePathW(default_name_w, sizeof(default_name_w), tmp2);
			UniToStr(default_name, sizeof(default_name), default_name_w);
			ConvertSafeFileName(default_name, sizeof(default_name), default_name);

			object_name = StringDlgA(hWnd, _UU("SEC_OBJECT_NAME_TITLE"),
				_UU("SEC_OBJECT_NAME_INFO"), default_name, ICO_CERT, false, false);

			if (object_name != NULL)
			{
				// Enumerate and write
				batch[0].Type = WINUI_SECURE_WRITE_CERT;
				batch[0].InputX = x;
				batch[0].Name = object_name;

				if (SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), id, 0) == false)
				{
					// Failure
				}
				else
				{
					ok = true;
				}

				Free(object_name);
			}

			FreeX(x);
		}

		break;

	case SEC_K:
		// Secret key
		if (CmLoadKExW(hWnd, &k, tmp2, sizeof(tmp2)))
		{
			// Generate the default name
			char default_name[MAX_SIZE];
			wchar_t default_name_w[MAX_PATH];
			char *object_name;
			GetFileNameFromFilePathW(default_name_w, sizeof(default_name_w), tmp2);
			UniToStr(default_name, sizeof(default_name), default_name_w);
			ConvertSafeFileName(default_name, sizeof(default_name), default_name);

			object_name = StringDlgA(hWnd, _UU("SEC_OBJECT_NAME_TITLE"),
				_UU("SEC_OBJECT_NAME_INFO"), default_name, ICO_KEY, false, false);

			if (object_name != NULL)
			{
				// Enumerate and write
				batch[0].Type = WINUI_SECURE_WRITE_KEY;
				batch[0].InputK = k;
				batch[0].Name = object_name;

				if (SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), id, 0) == false)
				{
					// Failure
				}
				else
				{
					ok = true;
				}

				Free(object_name);
			}

			FreeK(k);
		}
		break;

	default:
		// Invalid
		return;
	}

	if (ok)
	{
		LIST *o = batch[1].EnumList;

		CmSecureManagerDlgPrintList(hWnd, o);

		FreeEnumSecObject(o);

		MsgBox(hWnd, MB_ICONINFORMATION, _UU("SEC_OBJECT_IMPORT_OK"));
	}
}

// Export the object
void CmSecureManagerDlgExport(HWND hWnd, UINT id)
{
	char name[MAX_SIZE];
	UINT method = WINUI_SECURE_READ_DATA;
	char *tmp;
	UINT type;
	wchar_t filename[MAX_PATH];
	wchar_t *uni_tmp;
	X *x;
	BUF *b;
	wchar_t default_name[128];
	WINUI_SECURE_BATCH batch[] =
	{
		{WINUI_SECURE_READ_DATA, name, true, NULL, NULL, NULL, NULL, NULL, NULL},
	};
	UINT i;
	// Validate arguments
	if (hWnd == NULL || id == 0)
	{
		return;
	}

	i = LvGetSelected(hWnd, L_LIST);
	if (i == INFINITE)
	{
		return;
	}

	tmp = LvGetStrA(hWnd, L_LIST, i, 0);
	StrCpy(name, sizeof(name), tmp);
	Free(tmp);

	type = (UINT)LvGetParam(hWnd, L_LIST, i);

	switch (type)
	{
	case SEC_X:
		method = WINUI_SECURE_READ_CERT;
		break;

	default:
		method = WINUI_SECURE_READ_DATA;
		break;
	}

	batch[0].Type = method;

	// Operate the smart card
	if (SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), id, 0) == false)
	{
		return;
	}

	switch (type)
	{
	case SEC_X:
		// Certificate
		x = batch[0].OutputX;

		CertDlg(hWnd, x, NULL, true);

		FreeX(x);
		break;

	default:
		// File
		b = batch[0].OutputData;
		StrToUni(default_name, sizeof(default_name), name);
		uni_tmp = SaveDlg(hWnd, _UU("DLG_ALL_FILES"), _UU("DLG_SAVE_FILE"), default_name, NULL);

		if (uni_tmp != NULL)
		{
			UniStrCpy(filename, sizeof(filename), uni_tmp);

			DumpBufW(b, filename);

			Free(uni_tmp);

			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SEC_OBJECT_EXPORT_OK"));
		}


		FreeBuf(b);
		break;
	}
}

// Delete the object
void CmSecureManagerDlgDelete(HWND hWnd, UINT id)
{
	char name[MAX_SIZE];
	UINT method = WINUI_SECURE_DELETE_DATA;
	char *tmp;
	UINT type;
	LIST *o;
	WINUI_SECURE_BATCH batch[] =
	{
		{WINUI_SECURE_DELETE_OBJECT, name, false, NULL, NULL, NULL, NULL, NULL, NULL},
		{WINUI_SECURE_ENUM_OBJECTS, NULL, false, NULL, NULL, NULL, NULL, NULL, NULL},
	};
	UINT i;
	// Validate arguments
	if (hWnd == NULL || id == 0)
	{
		return;
	}

	i = LvGetSelected(hWnd, L_LIST);
	if (i == INFINITE)
	{
		return;
	}

	tmp = LvGetStrA(hWnd, L_LIST, i, 0);
	StrCpy(name, sizeof(name), tmp);
	Free(tmp);

	type = (UINT)LvGetParam(hWnd, L_LIST, i);

	switch (type)
	{
	case SEC_X:
		method = WINUI_SECURE_DELETE_CERT;
		break;

	case SEC_K:
		method = WINUI_SECURE_DELETE_KEY;
		break;

	default:
		method = WINUI_SECURE_DELETE_DATA;
		break;
	}

	batch[0].Type = method;

	if (SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), id, 0) == false)
	{
		return;
	}

	o = batch[1].EnumList;

	CmSecureManagerDlgPrintList(hWnd, o);

	FreeEnumSecObject(o);
}

static bool cm_secure_manager_no_new_cert = false;

// Smart Card Manager dialog
UINT CmSecureManagerDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	UINT id = (UINT)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CmSecureManagerDlgInit(hWnd, id);

		if (cm_secure_manager_no_new_cert)
		{
			Hide(hWnd, B_NEW_CERT);
		}

		SetTimer(hWnd, 1, 1, NULL);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_REFRESH:
			CmSecureManagerDlgRefresh(hWnd, id);
			break;

		case B_IMPORT:
			CmSecureManagerDlgImport(hWnd, id);
			break;

		case B_EXPORT:
			CmSecureManagerDlgExport(hWnd, id);
			break;

		case B_DELETE:
			if (MsgBox(hWnd, MB_YESNO | MB_ICONEXCLAMATION | MB_DEFBUTTON2,
				_UU("SEC_DELETE_MSG")) == IDYES)
			{
				CmSecureManagerDlgDelete(hWnd, id);
			}
			break;

		case B_NEW_CERT:
			CmSecureManagerDlgNewCert(hWnd, id);
			break;

		case B_PIN:
			CmSecurePin(hWnd, id);
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

			CmSecureManagerDlgRefresh(hWnd, id);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				CmSecureManagerDlgUpdate(hWnd, id);
				break;
			}
			break;
		}
		break;
	}

	return 0;
}

// Smart Card Manager
void CmSecureManager(HWND hWnd, UINT id)
{
	CmSecureManagerEx(hWnd, id, false);
}
void CmSecureManagerEx(HWND hWnd, UINT id, bool no_new_cert)
{
	// Validate arguments
	if (hWnd == NULL || id == 0)
	{
		return;
	}

	// ID check
	if (CheckSecureDeviceId(id) == false)
	{
		MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SEC_INVALID_ID"));
		return;
	}

	if (no_new_cert)
	{
		cm_secure_manager_no_new_cert = true;
	}
	else
	{
		cm_secure_manager_no_new_cert = false;
	}

	Dialog(hWnd, D_CM_SECURE_MANAGER, CmSecureManagerDlg, (void *)id);
}

// Smart Card Manager for Client
void CmClientSecureManager(HWND hWnd)
{
	RPC_USE_SECURE t;
	UINT id;

	Zero(&t, sizeof(t));
	CcGetUseSecure(cm->Client, &t);

	id = t.DeviceId;

	if (id == 0 || CheckSecureDeviceId(id) == false)
	{
		id = CmClientSelectSecure(hWnd);
	}

	if (id == 0)
	{
		return;
	}

	CmSecureManager(hWnd, id);
}

// Initialize the dialog
void CmSelectSecureDlgInit(HWND hWnd, UINT default_id)
{
	UINT i;
	LIST *o;
	LVB *v;

	SetIcon(hWnd, 0, ICO_SECURE);

	o = GetSecureDeviceList();

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SEC_COLUMN1"), 150);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SEC_COLUMN2"), 100);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SEC_COLUMN3"), 130);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SEC_COLUMN4"), 100);

	v = LvInsertStart();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t tmp1[MAX_SIZE];
		wchar_t *tmp2;
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		SECURE_DEVICE *dev = LIST_DATA(o, i);

		StrToUni(tmp1, sizeof(tmp1), dev->DeviceName);
		tmp2 = (dev->Type == SECURE_IC_CARD) ? _UU("SEC_SMART_CARD") : _UU("SEC_USB_TOKEN");
		StrToUni(tmp3, sizeof(tmp3), dev->Manufacturer);
		StrToUni(tmp4, sizeof(tmp4), dev->ModuleName);

		LvInsertAdd(v, ICO_SECURE, (void *)dev->Id, 4, tmp1, tmp2, tmp3, tmp4);
	}

	LvInsertEnd(v, hWnd, L_LIST);

	if (default_id != 0)
	{
		LvSelect(hWnd, L_LIST, LvSearchParam(hWnd, L_LIST, (void *)default_id));
	}

	ReleaseList(o);

	// Control update
	CmSelectSecureDlgUpdate(hWnd);
}

// Update controls of the dialog
void CmSelectSecureDlgUpdate(HWND hWnd)
{
	SetEnable(hWnd, IDOK, LvIsSingleSelected(hWnd, L_LIST));
}

// Smart card selection dialog
UINT CmSelectSecureDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UINT default_id = (UINT)param;
	NMHDR *n = NULL;
	static UINT old_id;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		old_id = default_id;
		CmSelectSecureDlgInit(hWnd, default_id);

		if (LvNum(hWnd, L_LIST) == 0)
		{
			// There is no smart card
			SetTimer(hWnd, 1, 100, NULL);
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			Disable(hWnd, L_LIST);
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SEC_NO_SECURE_DEVICE"));
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
					UINT id = (UINT)LvGetParam(hWnd, L_LIST, i);

					if (old_id != id)
					{
						if (CmCheckPkcsEula(hWnd, id) == false)
						{
							break;
						}
					}
					EndDialog(hWnd, id);
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

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				CmSelectSecureDlgUpdate(hWnd);
				break;
			case NM_DBLCLK:
				Command(hWnd, IDOK);
				break;
			}
			break;
		}
		break;
	}

	return 0;
}

// Select the smart card device to be used
UINT CmSelectSecure(HWND hWnd, UINT current_id)
{
	return Dialog(hWnd, D_CM_SELECT_SECURE, CmSelectSecureDlg, (void *)current_id);
}

// Select the smart card device to be used (client)
UINT CmClientSelectSecure(HWND hWnd)
{
	UINT id;
	RPC_USE_SECURE t;

	if (cm->server_name != NULL)
	{
		MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("CM_SECURE_MUST_LOCAL"));
		return 0;
	}

	Zero(&t, sizeof(t));
	CcGetUseSecure(cm->Client, &t);

	id = t.DeviceId;

	id = CmSelectSecure(hWnd, id);
	if (id != 0)
	{
		Zero(&t, sizeof(t));
		t.DeviceId = id;

		CALL(hWnd, CcUseSecure(cm->Client, &t));

		SmWriteSelectSecureIdReg(id);
	}

	return id;
}

// Shortcut connection
void CmConnectShortcut(UCHAR *key)
{
	UINT ret;
	// Validate arguments
	if (key == NULL)
	{
		return;
	}

	// Attempt to connect
	ret = CcShortcut(key);

	if (ret != ERR_NO_ERROR)
	{
		if (ret == ERR_ACCOUNT_ACTIVE)
		{
			// Because it is currently connected, to query whether or not to disconnect
			if (MsgBox(NULL, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_SHORTCUT_DISCONNECT")) == IDYES)
			{
				// Try to disconnect
				ret = CcShortcutDisconnect(key);

				if (ret != ERR_NO_ERROR)
				{
					// Error
					MsgBox(NULL, MB_ICONEXCLAMATION, GetUniErrorStr(ret));
				}
			}
		}
		else
		{
			// Other errors
			MsgBox(NULL, MB_ICONEXCLAMATION, GetUniErrorStr(ret));
		}
	}
}

// Play the audio guide
void CmVoice(char *name)
{
	UINT i;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	// Voice guidance features disappeared!!
	return;

	if (cm->DisableVoice)
	{
		return;
	}

	for (i = 0;i < sizeof(cm_voice) / sizeof(CM_VOICE);i++)
	{
		if (cm_voice[i].voice_id == cm->VoiceId)
		{
			char tmp[MAX_SIZE];
			Format(tmp, sizeof(tmp), "%s_%s.wav", cm_voice[i].perfix, name);
			MsPlaySound(tmp);
			return;
		}
	}
}

// Update the password changing dialog
void CmChangePasswordUpdate(HWND hWnd, CM_CHANGE_PASSWORD *p)
{
	bool ok = true;
	char *s1, *s2;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	if (IsEmpty(hWnd, E_USERNAME))
	{
		ok = false;
	}

	s1 = GetTextA(hWnd, E_NEW_PASSWORD1);
	s2 = GetTextA(hWnd, E_NEW_PASSWORD2);

	if (StrCmp(s1, s2) != 0)
	{
		ok = false;
	}

	Free(s1);
	Free(s2);

	SetEnable(hWnd, IDOK, ok);
}

// Password changing dialog procedure
UINT CmChangePasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CM_CHANGE_PASSWORD *p = (CM_CHANGE_PASSWORD *)param;
	char username[MAX_USERNAME_LEN + 1];
	char old_pass[MAX_PASSWORD_LEN + 1];
	char new_pass[MAX_PASSWORD_LEN + 1];
	UINT ret;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetTextA(hWnd, E_HUBNAME, p->HubName);
		SetTextA(hWnd, E_USERNAME, p->Username);
		FormatText(hWnd, S_TITLE, p->ClientOption->Hostname);

		if (IsEmpty(hWnd, E_USERNAME))
		{
			FocusEx(hWnd, E_USERNAME);
		}
		else
		{
			FocusEx(hWnd, E_OLD_PASSWORD);
		}

		CmChangePasswordUpdate(hWnd, p);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_USERNAME:
		case E_OLD_PASSWORD:
		case E_NEW_PASSWORD1:
		case E_NEW_PASSWORD2:
			CmChangePasswordUpdate(hWnd, p);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			GetTxtA(hWnd, E_USERNAME, username, sizeof(username));
			GetTxtA(hWnd, E_OLD_PASSWORD, old_pass, sizeof(old_pass));
			GetTxtA(hWnd, E_NEW_PASSWORD1, new_pass, sizeof(new_pass));

			Disable(hWnd, E_USERNAME);
			Disable(hWnd, E_OLD_PASSWORD);
			Disable(hWnd, E_NEW_PASSWORD1);
			Disable(hWnd, E_NEW_PASSWORD2);
			Disable(hWnd, IDOK);
			Disable(hWnd, IDCANCEL);

			ret = ChangePassword(cm->Cedar, p->ClientOption, p->HubName, username, old_pass, new_pass);

			if (ret == ERR_NO_ERROR)
			{
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_PASSWORD_CHANGED"));
				EndDialog(hWnd, true);
			}
			else
			{
				MsgBox(hWnd, MB_ICONSTOP, _E(ret));
				Enable(hWnd, E_USERNAME);
				Enable(hWnd, E_OLD_PASSWORD);
				Enable(hWnd, E_NEW_PASSWORD1);
				Enable(hWnd, E_NEW_PASSWORD2);
				Enable(hWnd, IDOK);
				Enable(hWnd, IDCANCEL);

				SetTextA(hWnd, E_OLD_PASSWORD, "");
				SetTextA(hWnd, E_NEW_PASSWORD1, "");
				SetTextA(hWnd, E_NEW_PASSWORD2, "");

				Focus(hWnd, E_OLD_PASSWORD);
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

// Show the password changing dialog
void CmChangePassword(HWND hWnd, CLIENT_OPTION *o, char *hubname, char *username)
{
	CM_CHANGE_PASSWORD p;
	// Validate arguments
	if (hWnd == NULL || o == NULL || hubname == NULL || username == NULL)
	{
		return;
	}

	Zero(&p, sizeof(p));
	StrCpy(p.Username, sizeof(p.Username), username);
	StrCpy(p.HubName, sizeof(p.HubName), hubname);
	p.ClientOption = o;

	CmVoice("password");

	Dialog(hWnd, D_CM_CHANGE_PASSWORD, CmChangePasswordProc, &p);
}

// Prohibit the installation of the virtual LAN card
bool CmStopInstallVLan(HWND hWnd)
{
	if (cm->Client->Unix)
	{
		// There is no need to be prohibited if the client is an UNIX
		return true;
	}
	if (cm->Client->Win9x)
	{
		// There is no need to prohibit if the client is a Win9x
		return true;
	}

	return true;

	if (MsIsTerminalServiceInstalled() || MsIsUserSwitchingInstalled())
	{
		if (MsGetCurrentTerminalSessionId() == 0)
		{
			// There is no need to prohibit
			return true;
		}
		else
		{
			// Prohibit to install the device drivers since
			// the user logged in other than the console session
			wchar_t *user = MsGetSessionUserName(0);

			if (user == NULL)
			{
				MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("CM_STOP_INST_VLAN_2"),
					MsIsTerminalServiceInstalled() ? _UU("CM_DESKTOP_MSG_LOCAL_TS") : _UU("CM_DESKTOP_MSG_LOCAL_SW"),
					MsGetCurrentTerminalSessionId());
			}
			else
			{
				MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("CM_STOP_INST_VLAN_1"),
					MsIsTerminalServiceInstalled() ? _UU("CM_DESKTOP_MSG_LOCAL_TS") : _UU("CM_DESKTOP_MSG_LOCAL_SW"),
					MsGetCurrentTerminalSessionId(), 0, user);
			}

			if (user != NULL)
			{
				Free(user);
			}
			return false;
		}
	}
	else
	{
		// There is no need to prohibit
		return true;
	}
}

// Desktop difference warning message dialog initialization
void CmDesktopDlgInit(HWND hWnd, wchar_t *account_name)
{
	wchar_t tmp[2048];
	bool remote = false;
	bool user_switching = false;
	bool console_active = false;
	wchar_t *console_user = NULL;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	FormatText(hWnd, 0, account_name);
	FormatText(hWnd, S_TITLE, account_name);
	DlgFont(hWnd, S_TITLE, 11, true);
	DlgFont(hWnd, S_INFO, 11, true);
	if (cm->server_name == NULL)
	{
		UniStrCpy(tmp, sizeof(tmp), _UU("CM_DESKTOP_LOCAL_PC"));
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), _UU("CM_DESKTOP_REMOTE_PC"), cm->server_name);
	}
	FormatText(hWnd, S_WARNING, tmp);

	if (cm->server_name != NULL)
	{
		remote = true;
	}
	else
	{
		if (MsIsTerminalServiceInstalled())
		{
			user_switching = false;
		}
		else
		{
			user_switching = true;
		}

		console_user = MsGetSessionUserName(0);

		if (console_user == NULL)
		{
			console_active = false;
		}
		else
		{
			console_active = true;
		}
	}

	// MSG1
	if (remote == false)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CM_DESKTOP_MSG_LOCAL_1"),
			user_switching ? _UU("CM_DESKTOP_MSG_LOCAL_SW") : _UU("CM_DESKTOP_MSG_LOCAL_TS"));
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), _UU("CM_DESKTOP_MSG_REMOTE_1"),
			cm->server_name);
	}
	SetText(hWnd, S_MSG_1, tmp);

	// MSG2
	if (remote == false)
	{
		if (console_active)
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_DESKTOP_MSG_LOCAL_21"),
				console_user, MsGetCurrentTerminalSessionId());
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_DESKTOP_MSG_LOCAL_22"),
				MsGetCurrentTerminalSessionId());
		}
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), _UU("CM_DESKTOP_MSG_REMOTE_2"), cm->server_name);
	}
	SetText(hWnd, S_MSG_2, tmp);

	// MSG3
	if (remote == false)
	{
		if (console_active)
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_DESKTOP_MSG_LOCAL_31"),
				console_user, account_name);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_DESKTOP_MSG_LOCAL_32"),
				account_name);
		}
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), _UU("CM_DESKTOP_MSG_REMOTE_3"), cm->server_name,
			account_name);
	}
	SetText(hWnd, S_MSG_3, tmp);

	if (console_user != NULL)
	{
		Free(console_user);
	}
}

// Desktop difference warning message dialog
UINT CmDesktopDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	wchar_t *account_name = (wchar_t *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CmDesktopDlgInit(hWnd, account_name);
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
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

// Show a warning message that the desktop is different, if necessary
bool CmWarningDesktop(HWND hWnd, wchar_t *account_name)
{
	// Validate arguments
	if (hWnd == NULL || account_name == NULL)
	{
		return false;
	}

	if (cm->Client->Unix)
	{
		//There is no need for warning if the client is an UNIX
		return true;
	}

	if (/*MsIsTerminalServiceInstalled() || MsIsUserSwitchingInstalled() ||*/ (cm->server_name != NULL))
	{
		if (cm->server_name == NULL)
		{
			//if (MsGetCurrentTerminalSessionId() == 0)
			{
				// No need for warning
				return true;
			}
		}
		// There is a need for warning
		return Dialog(hWnd, D_CM_DESKTOP, CmDesktopDlgProc, account_name);
	}
	else
	{
		// No need for warning
		return true;
	}
}

// Update the password setting dialog
void CmPasswordRefresh(HWND hWnd)
{
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SetEnable(hWnd, E_PASSWORD, IsChecked(hWnd, R_USE_PASSWORD));
	SetEnable(hWnd, E_PASSWORD2, IsChecked(hWnd, R_USE_PASSWORD));
	SetEnable(hWnd, IDC_STATIC1, IsChecked(hWnd, R_USE_PASSWORD));
	SetEnable(hWnd, IDC_STATIC2, IsChecked(hWnd, R_USE_PASSWORD));
	SetEnable(hWnd, R_REMOTE_ONLY, IsChecked(hWnd, R_USE_PASSWORD));

	if (IsChecked(hWnd, R_USE_PASSWORD))
	{
		char tmp1[MAX_SIZE];
		char tmp2[MAX_SIZE];
		if (IsEmpty(hWnd, E_PASSWORD))
		{
			ok = false;
		}
		GetTxtA(hWnd, E_PASSWORD, tmp1, sizeof(tmp1));
		GetTxtA(hWnd, E_PASSWORD2, tmp2, sizeof(tmp2));
		if (StrCmp(tmp1, tmp2) != 0)
		{
			ok = false;
		}
		if (StrCmp(tmp1, HIDDEN_PASSWORD) == 0)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// Password setting procedure
UINT CmPasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	RPC_CLIENT_PASSWORD_SETTING c;
	RPC_CLIENT_PASSWORD p;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Get the password setting
		if (CALL(hWnd, CcGetPasswordSetting(cm->Client, &c)))
		{
			Check(hWnd, R_USE_PASSWORD, c.IsPasswordPresented);
			if (c.IsPasswordPresented)
			{
				SetTextA(hWnd, E_PASSWORD, HIDDEN_PASSWORD);
				SetTextA(hWnd, E_PASSWORD2, HIDDEN_PASSWORD);
				FocusEx(hWnd, E_PASSWORD);
				Check(hWnd, R_REMOTE_ONLY, c.PasswordRemoteOnly);
			}
			else
			{
				Focus(hWnd, R_USE_PASSWORD);
			}
		}
		CmPasswordRefresh(hWnd);
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case R_USE_PASSWORD:
			if (IsChecked(hWnd, R_USE_PASSWORD))
			{
				FocusEx(hWnd, E_PASSWORD);
			}
			break;
		case IDOK:
			GetTxtA(hWnd, E_PASSWORD, tmp, sizeof(tmp));
			Zero(&p, sizeof(p));
			if (IsChecked(hWnd, R_USE_PASSWORD))
			{
				StrCpy(p.Password, sizeof(p.Password), tmp);
				p.PasswordRemoteOnly = IsChecked(hWnd, R_REMOTE_ONLY);
			}

			if (CALL(hWnd, CcSetPassword(cm->Client, &p)))
			{
				if (StrLen(p.Password) > 0)
				{
					MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_PASSWORD_SET"));
				}
				else
				{
					MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_PASSWORD_REMOVE"));
				}
				EndDialog(hWnd, true);
			}
			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		switch (LOWORD(wParam))
		{
		case R_USE_PASSWORD:
		case R_REMOTE_ONLY:
		case E_PASSWORD:
		case E_PASSWORD2:
			CmPasswordRefresh(hWnd);
			break;
		}
		switch (wParam)
		{
		case R_REMOTE_ONLY:
		case R_USE_PASSWORD:
			if (IsChecked(hWnd, R_USE_PASSWORD))
			{
				FocusEx(hWnd, E_PASSWORD);
			}
			break;
		}
		break;
	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Set the password 
void CmPassword(HWND hWnd)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	Dialog(hWnd, D_CM_PASSWORD, CmPasswordProc, NULL);
}

// CA dialog update
void CmTrustDlgUpdate(HWND hWnd)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SetEnable(hWnd, B_EXPORT, LvIsSelected(hWnd, L_CERT));
	SetEnable(hWnd, B_DELETE, LvIsSelected(hWnd, L_CERT) && cm->CmSetting.LockMode == false);
	SetEnable(hWnd, IDOK, LvIsSelected(hWnd, L_CERT));
	SetEnable(hWnd, B_IMPORT, cm->CmSetting.LockMode == false);
}

// Update the list of certificates
void CmTrustDlgRefresh(HWND hWnd)
{
	RPC_CLIENT_ENUM_CA c;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (CALL(hWnd, CcEnumCa(cm->Client, &c)))
	{
		UINT i;
		LVB *b = LvInsertStart();
		for (i = 0;i < c.NumItem;i++)
		{
			RPC_CLIENT_ENUM_CA_ITEM *cert = c.Items[i];
			wchar_t tmp[MAX_SIZE];

			GetDateStrEx64(tmp, sizeof(tmp), SystemToLocal64(cert->Expires), NULL);
			LvInsertAdd(b, ICO_CERT, (void *)cert->Key, 3,
				cert->SubjectName, cert->IssuerName, tmp);
		}
		LvInsertEnd(b, hWnd, L_CERT);
		CiFreeClientEnumCa(&c);
	}

	CmTrustDlgUpdate(hWnd);
}

// Import
void CmTrustImport(HWND hWnd)
{
	X *x;
	RPC_CERT c;
	if (CmLoadXFromFileOrSecureCard(hWnd, &x) == false)
	{
		return;
	}

	Zero(&c, sizeof(c));
	c.x = x;

	CALL(hWnd, CcAddCa(cm->Client, &c));
	CmVoice("new_cert");

	FreeX(c.x);
	CmTrustDlgRefresh(hWnd);
}

// Export
void CmTrustExport(HWND hWnd)
{
	UINT key;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	key = (UINT)LvGetParam(hWnd, L_CERT, LvGetSelected(hWnd, L_CERT));
	if (key != INFINITE)
	{
		RPC_GET_CA a;
		Zero(&a, sizeof(a));
		a.Key = key;

		if (CALL(hWnd, CcGetCa(cm->Client, &a)))
		{
			wchar_t *name;
			X *x = CloneX(a.x);
			CiFreeGetCa(&a);

			// Save
			name = SaveDlg(hWnd, _UU("DLG_CERT_FILES"), _UU("DLG_SAVE_CERT"), NULL, L".cer");
			if (name != NULL)
			{
				wchar_t str[MAX_SIZE];
				UniStrCpy(str, sizeof(str), name);
				if (XToFileW(x, str, true))
				{
					MsgBox(hWnd, MB_ICONINFORMATION, _UU("DLG_CERT_SAVE_OK"));
				}
				else
				{
					MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_CERT_SAVE_ERROR"));
				}
				Free(name);
			}
			FreeX(x);
		}
	}
}

// Display
void CmTrustView(HWND hWnd)
{
	UINT key;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	key = (UINT)LvGetParam(hWnd, L_CERT, LvGetSelected(hWnd, L_CERT));
	if (key != INFINITE)
	{
		RPC_GET_CA a;
		Zero(&a, sizeof(a));
		a.Key = key;

		if (CALL(hWnd, CcGetCa(cm->Client, &a)))
		{
			X *x = CloneX(a.x);
			X *x_issuer;
			CiFreeGetCa(&a);

			x_issuer = CmGetIssuer(x);
			CertDlg(hWnd, x, x_issuer, true);
			FreeX(x);
			FreeX(x_issuer);
		}
	}
}

// CA dialog procedure
UINT CmTrustDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	UINT index;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		LvInit(hWnd, L_CERT);
		LvInsertColumn(hWnd, L_CERT, 0, _UU("CM_CERT_COLUMN_1"), 190);
		LvInsertColumn(hWnd, L_CERT, 1, _UU("CM_CERT_COLUMN_2"), 190);
		LvInsertColumn(hWnd, L_CERT, 2, _UU("CM_CERT_COLUMN_3"), 160);
		CmTrustDlgRefresh(hWnd);
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case B_IMPORT:
			CmTrustImport(hWnd);
			break;
		case B_EXPORT:
			CmTrustExport(hWnd);
			break;
		case B_DELETE:
			index = LvGetSelected(hWnd, L_CERT);
			if (index != INFINITE)
			{
				UINT key = (UINT)LvGetParam(hWnd, L_CERT, index);
				if (key != INFINITE)
				{
					if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_CERT_DELETE_MSG")) == IDYES)
					{
						RPC_CLIENT_DELETE_CA c;
						Zero(&c, sizeof(c));
						c.Key = key;
						if (CALL(hWnd, CcDeleteCa(cm->Client, &c)))
						{
							CmTrustDlgRefresh(hWnd);
						}
					}
				}
			}
			break;
		case IDOK:
			if (IsEnable(hWnd, IDOK))
			{
				CmTrustView(hWnd);
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
	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_CERT:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				CmTrustDlgUpdate(hWnd);
				break;
			case NM_DBLCLK:
				Command(hWnd, IDOK);
				break;
			}
			break;
		}
		break;
	}

	LvSortHander(hWnd, msg, wParam, lParam, L_CERT);

	return 0;
}

// Show the CA dialog
void CmTrustDlg(HWND hWnd)
{
	Dialog(hWnd, D_CM_TRUST, CmTrustDlgProc, NULL);
}

// Main window procedure
UINT CmMainWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	static UINT taskbar_msg = 0;
	COPYDATASTRUCT *cpy;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	if (taskbar_msg != 0 && msg == taskbar_msg)
	{
		// The task-bar is regenerated
		if (cm->TrayInited)
		{
			MsRestoreIconOnTray();
		}
	}

	// CmSetForegroundProcessToCnService();

	switch (msg)
	{
	case WM_CM_SETTING_CHANGED_MESSAGE:
		// CM_SETTING has changed
		CmApplyCmSetting();
		break;
	case WM_INITDIALOG:
		CmMainWindowOnInit(hWnd);
		taskbar_msg = RegisterWindowMessage("TaskbarCreated");
		CmEndStartupMutex();
		break;
	case WM_CM_SHOW:
		// Received a display request from another process
		if (cm->CmSetting.EasyMode == false)
		{
			ShowWindow(hWnd, SW_SHOWNORMAL);
		}
		else
		{
			if (cm->hEasyWnd == NULL)
			{
				CmShowEasy();
			}
			else
			{
				SetForegroundWindow(cm->hEasyWnd);
				SetActiveWindow(cm->hEasyWnd);
			}
		}
		break;
	case WM_COMMAND:
		CmMainWindowOnCommand(hWnd, wParam, lParam);
		break;
	case WM_SIZE:
		CmMainWindowOnSize(hWnd);
		break;
	case WM_CLOSE:
		if (cm->CmSetting.EasyMode == false)
		{
			CmShowOrHideWindow(hWnd);
		}
		else
		{
			if (cm->hEasyWnd == NULL)
			{
				CmShowEasy();
			}
			else
			{
				SetForegroundWindow(cm->hEasyWnd);
				SetActiveWindow(cm->hEasyWnd);
			}
		}
		return 1;
	case WM_INITMENUPOPUP:
		if (HIWORD(lParam) == false)
		{
			CmMainWindowOnPopupMenu(hWnd, (HMENU)wParam, LOWORD(lParam));
		}
		break;
	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		if (n->idFrom == L_ACCOUNT && (n->code == LVN_BEGINLABELEDITW || n->code == LVN_BEGINLABELEDITA))
		{
			wchar_t *tmp = LvGetSelectedStr(hWnd, L_ACCOUNT, 0);
			if (tmp != NULL)
			{
				if (UniStrCmpi(tmp, _UU("CM_NEW_ICON")) == 0 || UniStrCmpi(tmp, _UU("CM_VGC_ICON")) == 0 || UniStrCmpi(tmp, _UU("CM_VGC_LINK")) == 0
					)
				{
					SendMsg(hWnd, L_ACCOUNT, LVM_CANCELEDITLABEL, 0, 0);
					Free(tmp);
					return true;
				}
				Free(tmp);
			}
		}
		CmMainWindowOnNotify(hWnd, (NMHDR *)lParam);
		break;
	case WM_CM_NOTIFY:
		CmRefreshVLanList(hWnd);
		CmRefreshAccountList(hWnd);
		CmRefreshStatusBar(hWnd);
		break;
	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			CmSetForegroundProcessToCnService();
			break;
		case 2:
			CmPollingTray(hWnd);
			break;
		case 3:
			KillTimer(hWnd, 3);
			Hide(hWnd, 0);
			break;
		case 4:
			KillTimer(hWnd, 4);
			CmMainWindowOnShowEasy(hWnd);
			break;
		case 6:
			if (cm->Update == NULL)
			{
				if (cm->server_name == NULL)
				{
					if (CmGetNumConnected(hWnd) == 0)
					{
						cm->Update = InitUpdateUi(_UU("PRODUCT_NAME_VPN_CMGR"), NAME_OF_VPN_CLIENT_MANAGER, NULL,
							GetCurrentBuildDate(), CEDAR_VERSION_BUILD, GetCedarVersionNumber(), ((cm->Client == NULL) ? NULL : cm->Client->ClientId),
							true);
					}
				}
			}
			break;
		}
		break;
	case WM_CM_TRAY_MESSAGE:
		// Message from the icon in the task tray
		CmMainWindowOnTrayClicked(hWnd, wParam, lParam);
		break;
	case WM_COPYDATA:
		cpy = (COPYDATASTRUCT *)lParam;
		if (cpy != NULL)
		{
			if (cpy->dwData == CM_IMPORT_FILENAME_MSG || cpy->dwData == CM_IMPORT_FILENAME_MSG_OVERWRITE)
			{
				char *filename = (char *)cpy->lpData;

				if (cm->CmSetting.LockMode == false || cpy->dwData == CM_IMPORT_FILENAME_MSG_OVERWRITE)
				{
					wchar_t fullpath[MAX_PATH];

					if (StrLen(filename) >= 2 && IsFileExists(filename))
					{
						StrToUni(fullpath, sizeof(fullpath), filename);
					}
					else
					{
						UniStrCpy(fullpath, sizeof(fullpath), (wchar_t *)filename);
					}

					CmImportAccountMainEx(cm->hEasyWnd ? cm->hEasyWnd : hWnd, fullpath, cpy->dwData == CM_IMPORT_FILENAME_MSG_OVERWRITE);
				}
				else
				{
					MsgBox(cm->hEasyWnd ? cm->hEasyWnd : hWnd, MB_ICONEXCLAMATION | MB_SETFOREGROUND | MB_TOPMOST, _UU("CM_VPN_FILE_IMPORT_NG"));
				}
			}
		}
		break;
	case WM_QUERYENDSESSION:
		// Windows is about to terminate
		cm->WindowsShutdowning = true;
		CmSaveMainWindowPos(hWnd);
		SleepThread(256);
		break;
	case WM_ENDSESSION:
		// Windows has terminated
		_exit(0);
		break;
	}

	LvSortHander(hWnd, msg, wParam, lParam, L_ACCOUNT);
	LvSortHander(hWnd, msg, wParam, lParam, L_VLAN);

	return 0;
}

// Specify the notification service to the foreground process
void CmSetForegroundProcessToCnService()
{
	if (cm->PopupMenuOpen)
	{
		return;
	}
	if (cm->server_name == NULL)
	{
		if (CnCheckAlreadyExists(false))
		{
			AllowFGWindow(MsRegReadInt(REG_CURRENT_USER,
				CM_REG_KEY, "NotifyServerProcessId"));
		}
	}
}

// Show the [recent destination] sub-menu
HMENU CmCreateRecentSubMenu(HWND hWnd, UINT start_id)
{
	HMENU h = NULL;
	UINT i;
	RPC_CLIENT_ENUM_ACCOUNT a;
	LIST *o;

	Zero(&a, sizeof(a));

	if (CcEnumAccount(cm->Client, &a) == ERR_NO_ERROR)
	{
		o = NewListFast(CiCompareClientAccountEnumItemByLastConnectDateTime);

		for (i = 0;i < a.NumItem;i++)
		{
			RPC_CLIENT_ENUM_ACCOUNT_ITEM *item = a.Items[i];

			item->tmp1 = i;

			if (item->LastConnectDateTime != 0)
			{
				Add(o, item);
			}
		}

		Sort(o);

		for (i = 0;i < MIN(LIST_NUM(o), CM_NUM_RECENT);i++)
		{
			RPC_CLIENT_ENUM_ACCOUNT_ITEM *item = (RPC_CLIENT_ENUM_ACCOUNT_ITEM *)LIST_DATA(o, i);
			wchar_t tmp[MAX_PATH];
			wchar_t *account_name;
			char *server_name;
			UINT pos;

			if (h == NULL)
			{
				h = CreatePopupMenu();
			}

			account_name = item->AccountName;
			server_name = item->ServerName;

			UniStrCpy(tmp, sizeof(tmp), account_name);

			pos = LvSearchStr(hWnd, L_ACCOUNT, 0, account_name);
			if (pos != INFINITE)
			{
				MsAppendMenu(h, MF_STRING, start_id + pos, tmp);
			}
		}

		ReleaseList(o);

		CiFreeClientEnumAccount(&a);
	}

	return h;
}

// Show the sub-menu of the right-click menu in the task tray
HMENU CmCreateTraySubMenu(HWND hWnd, bool flag, UINT start_id)
{
	HMENU h = NULL;
	UINT i, num;
	bool easy;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	easy = cm->CmSetting.EasyMode;

	num = LvNum(hWnd, L_ACCOUNT);

	for (i = 0;i < num;i++)
	{
		wchar_t *status_str = LvGetStr(hWnd, L_ACCOUNT, i, 1);

		if (status_str != NULL)
		{
			bool b = false;

			if (UniStrCmpi(status_str, _UU("CM_ACCOUNT_OFFLINE")) == 0)
			{
				if (flag == false)
				{
					b = true;
				}
			}

			if (UniStrCmpi(status_str, _UU("CM_ACCOUNT_ONLINE")) == 0 ||
				UniStrCmpi(status_str, _UU("CM_ACCOUNT_CONNECTING")) == 0)
			{
				if (flag == true)
				{
					b = true;
				}
			}

			if (b)
			{
				wchar_t tmp[MAX_PATH];
				wchar_t *account_name, *server_name;
				wchar_t *hub_name;
				if (h == NULL)
				{
					h = CreatePopupMenu();
				}

				account_name = LvGetStr(hWnd, L_ACCOUNT, i, 0);
				server_name = LvGetStr(hWnd, L_ACCOUNT, i, 2);
				hub_name = LvGetStr(hWnd, L_ACCOUNT, i, 3);

				if (easy == false)
				{
					UniFormat(tmp, sizeof(tmp), L"%s\t- %s [%s]", account_name, server_name, hub_name);
				}
				else
				{
					UniStrCpy(tmp, sizeof(tmp), account_name);
				}

				MsAppendMenu(h, MF_STRING, start_id + i, tmp);

				Free(account_name);
				Free(server_name);
				Free(hub_name);
			}

			Free(status_str);
		}
	}

	return h;
}

// Display the right-click menu of the task tray
void CmShowTrayMenu(HWND hWnd)
{
	HMENU h;
	POINT p;
	HMENU sub1, sub2, sub3, sub4;
	bool locked;
	bool easy;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	cm->PopupMenuOpen = true;

	locked = cm->CmSetting.LockMode;
	easy = cm->CmSetting.EasyMode;

	// Create a menu
	h = CreatePopupMenu();

	// Cancel
	MsAppendMenu(h, MF_ENABLED | MF_STRING, 100007, _UU("CM_TRAY_MENU_CANCEL"));

	// Separator
	MsAppendMenu(h, MF_SEPARATOR, 10006, NULL);

	if (locked == false && easy == false)
	{
		// Creating a new connection settings
		MsAppendMenu(h, MF_ENABLED | MF_STRING, CMD_NEW, _UU("CM_TRAY_MENU_NEW"));

		// Separator
		MsAppendMenu(h, MF_SEPARATOR, 10005, NULL);
	}

	// Connection menu
	sub1 = CmCreateTraySubMenu(hWnd, false, CM_TRAY_MENU_CONNECT_ID_START);
	if (sub1 != NULL)
	{
		MsAppendMenu(h, MF_BYPOSITION | MF_ENABLED | MF_POPUP | MF_STRING,
			(UINT_PTR)sub1, _UU("CM_TRAY_MENU_CONNECT"));
	}

	// Disconnection menu
	sub2 = CmCreateTraySubMenu(hWnd, true, CM_TRAY_MENU_DISCONNECT_ID_START);
	if (sub2 != NULL)
	{
		MsAppendMenu(h, MF_BYPOSITION | MF_ENABLED | MF_POPUP | MF_STRING,
			(UINT_PTR)sub2, _UU("CM_TRAY_MENU_DISCONNECT"));
	}

	// Status Display menu
	sub3 = CmCreateTraySubMenu(hWnd, true, CM_TRAY_MENU_STATUS_ID_START);
	if (sub3 != NULL)
	{
		MsAppendMenu(h, MF_BYPOSITION | MF_ENABLED | MF_POPUP | MF_STRING,
			(UINT_PTR)sub3, _UU("CM_TRAY_MENU_STATUS"));
	}

	if (sub3 != NULL)
	{
		// Disconnect all connections
		MsAppendMenu(h, MF_ENABLED | MF_STRING, CMD_DISCONNECT_ALL, _UU("CM_TRAY_MENU_DISCONNECT_ALL"));
	}

	if (sub1 != NULL || sub2 != NULL || sub3 != NULL)
	{
		// Separator
		MsAppendMenu(h, MF_SEPARATOR, 10003, NULL);
	}

	// Connect to the recently connected VPN server
	sub4 = CmCreateRecentSubMenu(hWnd, CM_TRAY_MENU_RECENT_ID_START);
	if (sub4 != NULL)
	{
		MsAppendMenu(h, MF_BYPOSITION | MF_ENABLED | MF_POPUP | MF_STRING,
			(UINT_PTR)sub4, _UU("CM_TRAY_MENU_RECENT"));
		MsAppendMenu(h, MF_SEPARATOR, 10008, NULL);
	}

	if (locked == false && easy == false)
	{
		// Communication throughput measurement
		MsAppendMenu(h, MF_ENABLED | MF_STRING, CMD_TRAFFIC, _UU("CM_TRAY_MENU_TRAFFIC"));
	}

	if (easy == false)
	{
		// Network device status
		MsAppendMenu(h, MF_ENABLED | MF_STRING, CMD_NETIF, _UU("CM_TRAY_MENU_NETIF"));
	}

	// Version information
	MsAppendMenu(h, MF_ENABLED | MF_STRING, CMD_ABOUT, _UU("CM_TRAY_MENU_ABOUT"));

	// Separator
	MsAppendMenu(h, MF_SEPARATOR, 10001, NULL);

	// Change the operating mode
	MsAppendMenu(h, MF_ENABLED | MF_STRING, CMD_CM_SETTING, _UU("CM_TRAY_MENU_SETTING"));

	// Separator
	MsAppendMenu(h, MF_SEPARATOR, 10001, NULL);

	// Hide the icon
	MsAppendMenu(h, MF_ENABLED | MF_STRING, CMD_TRAYICON, _UU("CM_MENU@CMD_TRAYICON"));

	// Separator
	MsAppendMenu(h, MF_SEPARATOR, 10001, NULL);

	// Show or hide
	MsAppendMenu(h, MF_ENABLED | MF_STRING, CMD_EXIT,
		IsHide(hWnd, 0) ? _UU("CM_TRAY_MENU_1_SHOW") : _UU("CM_TRAY_MENU_1_HIDE"));

	// Quit
	MsAppendMenu(h, MF_ENABLED | MF_STRING, CMD_QUIT, _UU("CM_TRAY_MENU_2_QUIT"));

	// Show the menu
	GetCursorPos(&p);

	SetForegroundWindow(hWnd);
	TrackPopupMenu(h, TPM_LEFTALIGN, p.x, p.y, 0, hWnd, NULL);
	PostMessage(hWnd, WM_NULL, 0, 0);

	if (sub1 != NULL)
	{
		DestroyMenu(sub1);
	}

	if (sub2 != NULL)
	{
		DestroyMenu(sub2);
	}

	if (sub3 != NULL)
	{
		DestroyMenu(sub3);
	}

	DestroyMenu(h);

	cm->PopupMenuOpen = false;
}

// Hide or show the main window
void CmShowOrHideWindow(HWND hWnd)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (IsHide(hWnd, 0))
	{
		Show(hWnd, 0);
		if (IsIconic(hWnd))
		{
			ShowWindow(hWnd, SW_SHOWNORMAL);
		}
		SetForegroundWindow(hWnd);
		SetActiveWindow(hWnd);
	}
	else
	{
		CmSaveMainWindowPos(hWnd);
		Hide(hWnd, 0);

		if (cm->TrayInited == false)
		{
			Command(hWnd, CMD_QUIT);
			return;
		}
	}
}

// Right-clicked on the account list
void CmAccountListRightClick(HWND hWnd)
{
	HMENU h;
	HMENU parent;
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Load the menu
	h = LoadSubMenu(M_MAIN, 0, &parent);
	if (h == NULL)
	{
		return;
	}

	InitMenuInternational(h, "CM_MENU");

	// Remove the shortcut key
	RemoveShortcutKeyStrFromMenu(h);

	// Delete the exit menu
	i = GetMenuItemPos(h, CMD_QUIT);
	if (i != INFINITE)
	{
		DeleteMenuItem(h, i);
		DeleteMenuItem(h, i - 1);
		DeleteMenuItem(h, i - 2);
		DeleteMenuItem(h, i - 3);
	}

	// Set enable / disable
	CmMainWindowOnPopupMenu(hWnd, h, INFINITE);

	if (h != NULL)
	{
		// Determine whether the selected account is under connecting
		UINT i = LvGetSelected(hWnd, L_ACCOUNT);
		wchar_t *str;
		bool is_connected = false;
		if (i != INFINITE)
		{
			str = LvGetStr(hWnd, L_ACCOUNT, i, 1);
			if (str != NULL)
			{
				if (UniStrCmpi(str, _UU("CM_ACCOUNT_ONLINE")) == 0 || UniStrCmpi(str, _UU("CM_ACCOUNT_CONNECTING")) == 0)
				{
					// Connecting
					is_connected = true;
				}
				Free(str);
			}
		}

		if (i == INFINITE)
		{
			// Bold the New menu
			SetMenuItemBold(h, GetMenuItemPos(h, CMD_NEW), true);
		}
		else
		{
			if (is_connected == false)
			{
				// Bold the connection menu
				SetMenuItemBold(h, GetMenuItemPos(h, CMD_CONNECT), true);
			}
			else
			{
				// Bold the status menu
				SetMenuItemBold(h, GetMenuItemPos(h, CMD_STATUS), true);
			}
		}
	}

	// Show the menu
	PrintMenu(hWnd, h);

	DestroyMenu(parent);
}

// Right-clicked on the virtual LAN card list
void CmVLanListRightClick(HWND hWnd)
{
	HMENU h;
	HMENU parent;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Load the menu
	h = LoadSubMenu(M_MAIN, 3, &parent);
	if (h == NULL)
	{
		return;
	}

	InitMenuInternational(h, "CM_MENU");

	// Remove the shortcut key
	RemoveShortcutKeyStrFromMenu(h);

	// Set enable / disable
	CmMainWindowOnPopupMenu(hWnd, h, INFINITE);

	if (h != NULL)
	{
		// Examine whether the selected device is enabled
		UINT i = LvGetSelected(hWnd, L_VLAN);
		wchar_t *str;
		bool is_active = false;
		if (i != INFINITE)
		{
			str = LvGetStr(hWnd, L_VLAN, i, 1);
			if (str != NULL)
			{
				if (UniStrCmpi(str, _UU("CM_VLAN_ENABLED")) == 0)
				{
					// Enabled
					is_active = true;
				}
				Free(str);
			}
		}

		if (i == INFINITE)
		{
			// Bold the New menu
			SetMenuItemBold(h, GetMenuItemPos(h, CMD_NEW_VLAN), true);
		}
		else
		{
			if (is_active == false)
			{
				// Bold the enable menu
				SetMenuItemBold(h, GetMenuItemPos(h, CMD_ENABLE_VLAN), true);
			}
			else
			{
				// Bold the Windows Network Setup menu
				SetMenuItemBold(h, GetMenuItemPos(h, CMD_WINNET), true);
			}
		}
	}

	// Show the menu
	PrintMenu(hWnd, h);

	DestroyMenu(parent);
}

// Notify to the main window
void CmMainWindowOnNotify(HWND hWnd, NMHDR *n)
{
	bool item_vlan;
	NMLVDISPINFOW *disp_info;
	NMLVKEYDOWN *key;

	// Validate arguments
	if (hWnd == NULL || n == NULL)
	{
		return;
	}

	switch (n->idFrom)
	{
	case L_ACCOUNT:
	case L_VLAN:
		if (n->idFrom == L_ACCOUNT)
		{
			item_vlan = false;
		}
		else
		{
			item_vlan = true;
		}

		switch (n->code)
		{
		case NM_DBLCLK:
			// Double click
			CmOnKey(hWnd, false, false, VK_RETURN);
			break;
		case NM_RCLICK:
			// Right click
			if (item_vlan == false)
			{
				CmAccountListRightClick(hWnd);
			}
			else
			{
				CmVLanListRightClick(hWnd);
			}
			break;
		case LVN_ENDLABELEDITW:
			// Change the name
			disp_info = (NMLVDISPINFOW *)n;
			if (disp_info->item.pszText != NULL)
			{
				wchar_t *new_name = disp_info->item.pszText;
				wchar_t *old_name = LvGetStr(hWnd, L_ACCOUNT, disp_info->item.iItem, 0);

				if (old_name != NULL)
				{
					if (UniStrCmp(new_name, old_name) != 0 && UniIsEmptyStr(new_name) == false)
					{
						RPC_RENAME_ACCOUNT a;
						Zero(&a, sizeof(a));
						UniStrCpy(a.OldName, sizeof(a.OldName), old_name);
						UniStrCpy(a.NewName, sizeof(a.NewName), new_name);
						if (CALL(hWnd, CcRenameAccount(cm->Client, &a)))
						{
							LvSetItem(hWnd, L_ACCOUNT, disp_info->item.iItem, 0, new_name);
						}
					}

					Free(old_name);
				}
			}
			break;
		case LVN_KEYDOWN:
			// Key pressed
			key = (NMLVKEYDOWN *)n;
			if (key != NULL)
			{
				bool ctrl, alt;
				UINT code = key->wVKey;
				ctrl = (GetKeyState(VK_CONTROL) & 0x8000) == 0 ? false : true;
				alt = (GetKeyState(VK_MENU) & 0x8000) == 0 ? false : true;
				CmOnKey(hWnd, ctrl, alt, code);
			}
			break;
		}
		break;
	}
}

// Keyboard pressed
void CmOnKey(HWND hWnd, bool ctrl, bool alt, UINT key)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Single key
	switch (key)
	{
	case VK_RETURN:
		Command(hWnd, IDOK);
		break;
	case VK_DELETE:
		// Delete
		if (IsFocus(hWnd, L_ACCOUNT))
		{
			// Operation on the account list
			Command(hWnd, CMD_DELETE);
		}
		else
		{
			// Operation on the virtual LAN card list
			Command(hWnd, CMD_DELETE_VLAN);
		}
		break;
	case VK_F2:
		// Change the name
		Command(hWnd, CMD_RENAME);
		break;
	case VK_F5:
		// Update the status
		Command(hWnd, CMD_REFRESH);
		break;
	}

	if (alt)
	{
		switch (key)
		{
		case 'Q':
			// Close
			Command(hWnd, CMD_QUIT);
			break;
		}
	}

	if (ctrl)
	{
		switch (key)
		{
		case 'G':
			// Smart Card Manager
			Command(hWnd, CMD_SECURE_MANAGER);
			break;
		case 'S':
			// Show the state
			Command(hWnd, CMD_STATUS);
			break;
		case 'I':
			// Disconnect all connections
			Command(hWnd, CMD_DISCONNECT_ALL);
			break;
		case 'D':
			// Disconnect
			Command(hWnd, CMD_DISCONNECT);
			break;
		case 'N':
			// Create a new connection settings
			Command(hWnd, CMD_NEW);
			break;
		case 'C':
			// Creating a copy
			Command(hWnd, CMD_CLONE);
			break;
		case 'T':
			// Set to start-up connection
			Command(hWnd, CMD_STARTUP);
			break;
		case 'A':
			// Select all
			Command(hWnd, CMD_SELECT_ALL);
			break;
		case 'L':
			// Create a new virtual LAN card
			Command(hWnd, CMD_NEW_VLAN);
			break;
		case 'E':
			// Enable the virtual LAN card
			Command(hWnd, CMD_ENABLE_VLAN);
			break;
		case 'B':
			// Disable the virtual LAN card
			Command(hWnd, CMD_DISABLE_VLAN);
			break;
		case 'U':
			// Reinstall the driver
			Command(hWnd, CMD_REINSTALL);
			break;
		case 'W':
			// Configure Windows network connection
			Command(hWnd, CMD_WINNET);
			break;
		case 'P':
			// Set the password
			Command(hWnd, CMD_PASSWORD);
			break;
		case 'O':
			// Option settings
			Command(hWnd, CMD_TRAFFIC);
			break;
		case 'R':
			// Certificate management
			Command(hWnd, CMD_TRUST);
			break;
		case 'Q':
			// Throughput
			Command(hWnd, CMD_TRAFFIC);
			break;
		}
	}
}

// Command of the main window
void CmMainWindowOnCommand(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	CmMainWindowOnCommandEx(hWnd, wParam, lParam, false);
}
void CmMainWindowOnCommandEx(HWND hWnd, WPARAM wParam, LPARAM lParam, bool easy)
{
	wchar_t *tmp;
	char *name;
	UINT index;
	UINT id;
	bool ctrl, alt;
	UINT flag = 0;
	// Validate arguments
	wchar_t *selected_name = NULL;
	UINT starter_id = 0;
	if (hWnd == NULL)
	{
		return;
	}

	ctrl = (GetKeyState(VK_CONTROL) & 0x8000) == 0 ? false : true;
	alt = (GetKeyState(VK_MENU) & 0x8000) == 0 ? false : true;

	if (wParam == IDOK)
	{
		tmp = LvGetSelectedStr(hWnd, L_ACCOUNT, 0);
		if (tmp != NULL)
		{
			if (UniStrCmpi(tmp, _UU("CM_NEW_ICON")) == 0)
			{
				Free(tmp);
				Command(hWnd, CMD_NEW);
				return;
			}
			if (UniStrCmpi(tmp, _UU("CM_VGC_ICON")) == 0 || UniStrCmpi(tmp, _UU("CM_VGC_LINK")) == 0)
			{
				Free(tmp);
				Command(hWnd, CMD_VGC_CONNECT);
				return;
			}
			Free(tmp);
		}
	}

	if (CmIsEnabled(hWnd, (UINT)wParam) == false)
	{
		return;
	}

	if (CM_TRAY_IS_CONNECT_ID(wParam))
	{
		// Connection request
		starter_id = CM_TRAY_MENU_CONNECT_ID_START;
		flag = 1;
	}

	if (CM_TRAY_IS_STATUS_ID(wParam))
	{
		// Information display request
		starter_id = CM_TRAY_MENU_STATUS_ID_START;
		flag = 2;
	}

	if (CM_TRAY_IS_DISCONNECT_ID(wParam))
	{
		// Disconnect request
		starter_id = CM_TRAY_MENU_DISCONNECT_ID_START;
		flag = 3;
	}

	if (CM_TRAY_IS_RECENT_ID(wParam))
	{
		// Recent destinations
		starter_id = CM_TRAY_MENU_RECENT_ID_START;
		flag = 1;
	}

	if (starter_id != 0)
	{
		UINT num;

		id = (UINT)wParam - starter_id;

		num = LvNum(hWnd, L_ACCOUNT);

		if (id < num)
		{
			selected_name = LvGetStr(hWnd, L_ACCOUNT, id, 0);

			if (selected_name != NULL)
			{
				if (UniStrCmpi(selected_name, _UU("CM_NEW_ICON")) != 0 &&
					UniStrCmpi(selected_name, _UU("CM_VGC_ICON")) != 0 &&
					UniStrCmpi(selected_name, _UU("CM_VGC_LINK")) != 0)
				{
					switch (flag)
					{
					case 1:
						CmConnect(hWnd, selected_name);
						break;

					case 2:
						CmStatus(hWnd, selected_name);
						break;

					case 3:
						CmDisconnect(hWnd, selected_name);
						break;
					}
				}
			}

			Free(selected_name);
		}
	}

	switch (wParam)
	{
	case IDOK:
	case CMD_EASY_DBLCLICK:
		// Property or connection
		if (IsFocus(hWnd, L_ACCOUNT) || (hWnd == cm->hEasyWnd))
		{
			// Operation about the account list
			if (alt == false)
			{
				UINT index = LvGetSelected(hWnd, L_ACCOUNT);
				bool b = false;
				if (index != INFINITE)
				{
					wchar_t *s = LvGetStr(hWnd, L_ACCOUNT, index, 1);
					if (s != NULL)
					{
						if (UniStrCmpi(s, _UU("CM_ACCOUNT_ONLINE")) == 0 || UniStrCmpi(s, _UU("CM_ACCOUNT_CONNECTING")) == 0)
						{
							b = true;
						}
						Free(s);
					}
				}

				if (b == false)
				{
					// Connection
					Command(hWnd, CMD_CONNECT);
				}
				else
				{
					if (hWnd != cm->hEasyWnd || wParam == CMD_EASY_DBLCLICK)
					{
						// Display status
						Command(hWnd, CMD_STATUS);
					}
					else
					{
						// Disconnect
						Command(hWnd, CMD_DISCONNECT);
					}
				}
			}
			else
			{
				// Property
				Command(hWnd, CMD_PROPERTY);
			}
		}
		else
		{
			// Configure Windows network connection
			Command(hWnd, CMD_WINNET);
		}
		break;
	case CMD_CONNECT:
		// Connection
		tmp = LvGetStr(hWnd, L_ACCOUNT, LvGetSelected(hWnd, L_ACCOUNT), 0);
		if (tmp != NULL)
		{
			CmConnect(hWnd, tmp);
			Free(tmp);
		}
		break;
	case CMD_STATUS:
		// Show the status
		tmp = LvGetStr(hWnd, L_ACCOUNT, LvGetSelected(hWnd, L_ACCOUNT), 0);
		if (tmp != NULL)
		{
			CmStatus(hWnd, tmp);
			Free(tmp);
		}
		break;
	case CMD_DISCONNECT_ALL:
		// Disconnect all connections
		CmDisconnectAll(hWnd);
		break;
	case CMD_DISCONNECT:
		// Disconnect
		tmp = LvGetStr(hWnd, L_ACCOUNT, LvGetSelected(hWnd, L_ACCOUNT), 0);
		if (tmp != NULL)
		{
			CmDisconnect(hWnd, tmp);
			Free(tmp);
		}
		break;
	case CMD_NEW:
		// Create new
		CmNewAccount(hWnd);
		break;


	case CMD_CLONE:
		// Copy
		tmp = LvGetStr(hWnd, L_ACCOUNT, LvGetSelected(hWnd, L_ACCOUNT), 0);
		if (tmp != NULL)
		{
			CmCopyAccount(hWnd, tmp);
			Free(tmp);
		}
		break;
	case CMD_SHORTCUT:
		// Create a shortcut
		tmp = LvGetStr(hWnd, L_ACCOUNT, LvGetSelected(hWnd, L_ACCOUNT), 0);
		if (tmp != NULL)
		{
			CmSortcut(hWnd, tmp);
			Free(tmp);
		}
		break;
	case CMD_EXPORT_ACCOUNT:
		// Export settings
		tmp = LvGetStr(hWnd, L_ACCOUNT, LvGetSelected(hWnd, L_ACCOUNT), 0);
		if (tmp != NULL)
		{
			CmExportAccount(hWnd, tmp);
			Free(tmp);
		}
		break;
	case CMD_IMPORT_ACCOUNT:
		// Import settings
		CmImportAccount(hWnd);
		break;
	case CMD_STARTUP:
		// Set to start-up connection
		tmp = LvGetStr(hWnd, L_ACCOUNT, LvGetSelected(hWnd, L_ACCOUNT), 0);
		if (tmp != NULL)
		{
			RPC_CLIENT_DELETE_ACCOUNT c;
			Zero(&c, sizeof(c));
			UniStrCpy(c.AccountName, sizeof(c.AccountName), tmp);
			CALL(hWnd, CcSetStartupAccount(cm->Client, &c));
			CmVoice("set_startup");
			MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("CM_SET_STARTUP"), tmp);
			Free(tmp);
		}
		break;
	case CMD_NOSTARTUP:
		// Unset the start-up connection
		tmp = LvGetStr(hWnd, L_ACCOUNT, LvGetSelected(hWnd, L_ACCOUNT), 0);
		if (tmp != NULL)
		{
			if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
				_UU("CM_REMOVE_STARTUP"), tmp) == IDYES)
			{
				RPC_CLIENT_DELETE_ACCOUNT c;
				Zero(&c, sizeof(c));
				UniStrCpy(c.AccountName, sizeof(c.AccountName), tmp);
				CALL(hWnd, CcRemoveStartupAccount(cm->Client, &c));
				CmVoice("remove_startup");
			}
			Free(tmp);
		}
		break;
	case CMD_DELETE:
		// Delete
		tmp = LvGetStr(hWnd, L_ACCOUNT, LvGetSelected(hWnd, L_ACCOUNT), 0);
		if (tmp != NULL)
		{
			CmDeleteAccount(hWnd, tmp);
			Free(tmp);
		}
		break;
	case CMD_RENAME:
		// Change the name
		Focus(hWnd, L_ACCOUNT);
		LvRename(hWnd, L_ACCOUNT, LvGetSelected(hWnd, L_ACCOUNT));
		break;
	case CMD_PROPERTY:
		// Property
		tmp = LvGetStr(hWnd, L_ACCOUNT, LvGetSelected(hWnd, L_ACCOUNT), 0);
		if (tmp != NULL)
		{
			CmEditAccount(hWnd, tmp);
			Free(tmp);
		}
		break;
	case IDCANCEL:
	case CMD_EXIT:
		// Close
		Close(hWnd);
		break;
	case CMD_QUIT:
		// Exit
		CmMainWindowOnQuit(hWnd);
		break;
	case CMD_SELECT_ALL:
		// Select all
		LvSelectAll(hWnd, L_ACCOUNT);
		LvSelectAll(hWnd, L_VLAN);
		break;
	case CMD_SWITCH_SELECT:
		// Invert selection
		LvSwitchSelect(hWnd, L_ACCOUNT);
		LvSwitchSelect(hWnd, L_VLAN);
		break;
	case CMD_GRID:
		// Show grid
		cm->ShowGrid = !cm->ShowGrid;
		CmRefreshVLanListEx(hWnd, true);
		CmRefreshAccountListEx2(hWnd, false, true);
		break;
	case CMD_STATUSBAR:
		// Show the status bar
		if (cm->HideStatusBar == false)
		{
			cm->HideStatusBar = true;
			Hide(hWnd, S_STATUSBAR);
			CmMainWindowOnSize(hWnd);
		}
		else
		{
			cm->HideStatusBar = false;
			Show(hWnd, S_STATUSBAR);
			CmMainWindowOnSize(hWnd);
		}
		CmSaveMainWindowPos(hWnd);
		break;
	case CMD_VISTASTYLE:
		cm->VistaStyle = !cm->VistaStyle;
		CmRefreshEx(hWnd, true);
		CmSaveMainWindowPos(hWnd);
		break;
	case CMD_TRAYICON:
		// Tray icon display
		if (cm->HideTrayIcon == false)
		{
			cm->HideTrayIcon = true;
			CmFreeTray(hWnd);

			if (IsHide(hWnd, 0))
			{
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_TRAY_ICON_RESTORE"));
			}
		}
		else
		{
			cm->HideTrayIcon = false;
			if (cm->server_name == NULL)
			{
				CmInitTray(hWnd);
			}
		}
		break;
	case CMD_SHOWPORT:
		// Show the port number
		cm->ShowPort = !cm->ShowPort;
		CmRefresh(hWnd);
		break;
	case CMD_ICON:
		// Show the icon
		if (cm->IconView == false)
		{
			cm->IconView = true;
			CmRefresh(hWnd);
		}
		break;
	case CMD_DETAIL:
		// Show details
		if (cm->IconView)
		{
			cm->IconView = false;
			CmRefresh(hWnd);
		}
		break;
	case CMD_REFRESH:
		if (easy == false)
		{
			// Display update
			LvReset(hWnd, L_ACCOUNT);
			LvReset(hWnd, L_VLAN);
			CmRefresh(hWnd);
		}
		break;
	case CMD_NEW_VLAN:
		// Create a Virtual LAN card
		if (CmStopInstallVLan(hWnd) == false)
		{
			// Installation is prohibited
			break;
		}
		name = CmNewVLanDlg(hWnd);
		if (name != NULL)
		{
			wchar_t tmp[MAX_SIZE];
			void *helper = NULL;
			RPC_CLIENT_CREATE_VLAN c;
			Zero(&c, sizeof(c));
			StrCpy(c.DeviceName, sizeof(c.DeviceName), name);
			if (MsIsNt() == false)
			{
				// Change the title of the window
				GetTxt(hWnd, 0, tmp, sizeof(tmp));
				SetText(hWnd, 0, _UU("CM_VLAN_INSTALLING"));
			}
			// Minimize
			if (MsIsVista() == false)
			{
				ShowWindow(hWnd, SW_SHOWMINIMIZED);
			}

			if (MsIsVista())
			{
				helper = CmStartUacHelper();
			}

			if (CALL(hWnd, CcCreateVLan(cm->Client, &c)))
			{
				CmVoice("new_vlan");
			}

			CmStopUacHelper(helper);

			if (MsIsNt() == false)
			{
				// Restore the title of the window
				SetText(hWnd, 0, tmp);
			}
			// Restore
			if (MsIsVista() == false)
			{
				ShowWindow(hWnd, SW_SHOWNORMAL);
			}
			Free(name);
		}
		break;
	case CMD_DELETE_VLAN:
		// Delete the Virtual LAN card
		index = LvGetSelected(hWnd, L_VLAN);
		if (index != INFINITE)
		{
			if (cm->Client->Win9x == false)
			{
				// Windows 2000 or later
				wchar_t *s = LvGetStr(hWnd, L_VLAN, index, 0);
				if (s != NULL)
				{
					RPC_CLIENT_CREATE_VLAN c;
					char str[MAX_SIZE];
					CmVoice("delete_vlan_1");
					if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_DELETE_VLAN"), s) == IDYES)
					{
						Zero(&c, sizeof(c));
						UniToStr(str, sizeof(str), s);
						if (CmPrintNameToVLanName(c.DeviceName, sizeof(c.DeviceName), str))
						{
							if (CALL(hWnd, CcDeleteVLan(cm->Client, &c)))
							{
								CmVoice("delete_vlan_2");
							}
						}
					}
					Free(s);
				}
			}
			else
			{
				// Windows 9x
				if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("CM_9X_VLAN_UNINSTALL")) == IDYES)
				{
					Run("rundll32.exe", "shell32.dll,Control_RunDLL NETCPL.CPL",
						false, false);
				}
			}
		}
		break;
	case CMD_ENABLE_VLAN:
		// Enable the virtual LAN card
		index = LvGetSelected(hWnd, L_VLAN);
		if (index != INFINITE)
		{
			wchar_t *s = LvGetStr(hWnd, L_VLAN, index, 0);
			if (s != NULL)
			{
				RPC_CLIENT_CREATE_VLAN c;
				char str[MAX_SIZE];
				Zero(&c, sizeof(c));
				UniToStr(str, sizeof(str), s);
				if (CmPrintNameToVLanName(c.DeviceName, sizeof(c.DeviceName), str))
				{
					CALL(hWnd, CcEnableVLan(cm->Client, &c));
				}
				Free(s);
			}
		}
		break;
	case CMD_DISABLE_VLAN:
		// Disable the virtual LAN card
		index = LvGetSelected(hWnd, L_VLAN);
		if (index != INFINITE)
		{
			wchar_t *s = LvGetStr(hWnd, L_VLAN, index, 0);
			if (s != NULL)
			{
				RPC_CLIENT_CREATE_VLAN c;
				char str[MAX_SIZE];
				Zero(&c, sizeof(c));
				UniToStr(str, sizeof(str), s);
				if (CmPrintNameToVLanName(c.DeviceName, sizeof(c.DeviceName), str))
				{
					CALL(hWnd, CcDisableVLan(cm->Client, &c));
				}
				Free(s);
			}
		}
		break;
	case CMD_REINSTALL:
		// Reinstall the virtual LAN card
		if (CmStopInstallVLan(hWnd) == false)
		{
			// Installation is prohibited
			break;
		}
		// Warning message
		if (MsgBox(hWnd, MB_ICONINFORMATION | MB_OKCANCEL, _UU("CM_VLAN_REINSTALL_MSG")) == IDCANCEL)
		{
			// Cancel
			break;
		}
		index = LvGetSelected(hWnd, L_VLAN);
		if (index != INFINITE)
		{
			wchar_t *s = LvGetStr(hWnd, L_VLAN, index, 0);
			if (s != NULL)
			{
				RPC_CLIENT_CREATE_VLAN c;
				char str[MAX_SIZE];
				Zero(&c, sizeof(c));
				UniToStr(str, sizeof(str), s);
				if (CmPrintNameToVLanName(c.DeviceName, sizeof(c.DeviceName), str))
				{
					void *helper = NULL;

					if (MsIsVista() == false)
					{
						ShowWindow(hWnd, SW_SHOWMINIMIZED);
					}

					if (MsIsVista())
					{
						helper = CmStartUacHelper();
					}

					CALL(hWnd, CcUpgradeVLan(cm->Client, &c));

					CmStopUacHelper(helper);

					if (MsIsVista() == false)
					{
						ShowWindow(hWnd, SW_SHOWNORMAL);
					}
				}
				Free(s);
			}
		}
		break;
	case CMD_PASSWORD:
		// Password setting
		CmPassword(hWnd);
		break;
	case CMD_OPTION:
		// Option
		CmConfigDlg(hWnd);
		break;
	case CMD_LANGUAGE:
		// Language settings
		if (true)
		{
			wchar_t path[MAX_SIZE];

			CombinePathW(path, sizeof(path), MsGetExeDirNameW(), L"vpnsetup.exe");

			if (MsExecuteW(path, L"/language:yes") == false)
			{
				MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SW_CHILD_PROCESS_ERROR"));
			}
		}
		break;
	case CMD_TRUST:
		// Certificate management
		CmTrustDlg(hWnd);
		break;
	case CMD_ABOUT:
		// Version information
		if (IsEnable(hWnd, 0))
		{
			AboutEx(hWnd, cm->Cedar, _UU("PRODUCT_NAME_VPN_CMGR"), cm->Update);
		}
		break;
	case CMD_VOIDE_NONE:
		cm->DisableVoice = true;
		break;
	case CMD_VOICE_NORMAL:
		cm->DisableVoice = false;
		cm->VoiceId = VOICE_SSK;
		break;
	case CMD_VOICE_ODD:
		if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("CM_EXT_VOICE_MSG")) == IDYES)
		{
			cm->DisableVoice = false;
			cm->VoiceId = VOICE_AHO;
		}
		break;
	case CMD_SECURE_MANAGER:
		// Smart Card Manager
		CmClientSecureManager(hWnd);
		break;
	case CMD_SECURE_SELECT:
		// Select a smart card
		CmClientSelectSecure(hWnd);
		break;
	case CMD_NETIF:
		// State of the network device
		if (IsEnable(hWnd, 0))
		{
			UtSpeedMeterEx(hWnd);
		}
		break;
	case CMD_MMCSS:
		// Optimization utility for Windows Vista
		if (MsIsVista() == false)
		{
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("VISTA_MMCSS_MSG_4"));
		}
		else
		{
			if (MsIsAdmin() == false)
			{
				MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("VISTA_MMCSS_MSG_4"));
			}
			else
			{
				if (MsIsMMCSSNetworkThrottlingEnabled())
				{
					if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("VISTA_MMCSS_MSG")) == IDYES)
					{
						MsSetMMCSSNetworkThrottlingEnable(false);
						MsgBox(hWnd, MB_ICONINFORMATION, _UU("VISTA_MMCSS_MSG_5"));
					}
				}
				else
				{
					if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("VISTA_MMCSS_MSG_2")) == IDYES)
					{
						MsSetMMCSSNetworkThrottlingEnable(true);
						MsgBox(hWnd, MB_ICONINFORMATION, _UU("VISTA_MMCSS_MSG_6"));
					}
				}
			}
		}
		break;
	case CMD_TRAFFIC:
		// Communication traffic measurement
		if (IsEnable(hWnd, 0))
		{
			CmTraffic(hWnd);
		}
		break;
	case CMD_CM_SETTING:
		// Operation mode setting
		if (IsEnable(hWnd, 0))
		{
			if (CmSetting(hWnd))
			{
				CmApplyCmSetting();
			}
		}
		break;
	case CMD_WINNET:
		// Windows network settings
		ShowWindowsNetworkConnectionDialog();
		break;
	}
}

// Option dialog
void CmConfigDlg(HWND hWnd)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	Dialog(hWnd, D_CM_CONFIG, CmConfigDlgProc, NULL);
}

// Initialize the option dialog
void CmConfigDlgInit(HWND hWnd)
{
	bool use_alpha;
	UINT alpha_value;
	UINT os;
	CLIENT_CONFIG c;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	DlgFont(hWnd, S_WARNING, 10, true);
	DlgFont(hWnd, S_INFO, 10, false);

	Zero(&c, sizeof(c));
	if (CALL(hWnd, CcGetClientConfig(cm->Client, &c)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	Check(hWnd, R_ALLOW_REMOTE_CONFIG, c.AllowRemoteConfig);

	Check(hWnd, R_USE_KEEP_CONNECT, c.UseKeepConnect);
	SetTextA(hWnd, E_HOSTNAME, c.KeepConnectHost);
	SetIntEx(hWnd, E_PORT, c.KeepConnectPort);
	SetIntEx(hWnd, E_INTERVAL, c.KeepConnectInterval);

	Check(hWnd, R_TCP, c.KeepConnectProtocol == CONNECTION_TCP);
	Check(hWnd, R_UDP, c.KeepConnectProtocol == CONNECTION_UDP);

	use_alpha = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "UseAlpha") == 0 ? false : true;
	alpha_value = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "AlphaValue");
	alpha_value = MAKESURE(alpha_value, 0, 100);

	SetInt(hWnd, E_ALPHA_VALUE, alpha_value == 0 ? 50 : alpha_value);
	Check(hWnd, R_ALPHA, use_alpha);

	os = GetOsInfo()->OsType;
	if (OS_IS_WINDOWS_NT(os) && GET_KETA(os, 100) >= 2)
	{
		Enable(hWnd, R_ALPHA);
	}
	else
	{
		Disable(hWnd, R_ALPHA);
	}

	CmConfigDlgRefresh(hWnd);
}

// Update the option dialog
void CmConfigDlgRefresh(HWND hWnd)
{
	bool ok = true;
	bool use_keep_connect;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	use_keep_connect = IsChecked(hWnd, R_USE_KEEP_CONNECT);
	SetEnable(hWnd, S_HOSTNAME, use_keep_connect);
	SetEnable(hWnd, S_PORT, use_keep_connect);
	SetEnable(hWnd, S_INTERVAL, use_keep_connect);
	SetEnable(hWnd, S_INTERVAL2, use_keep_connect);
	SetEnable(hWnd, S_PROTOCOL, use_keep_connect);
	SetEnable(hWnd, S_INFO, use_keep_connect);
	SetEnable(hWnd, S_INFO2, use_keep_connect);
	SetEnable(hWnd, E_HOSTNAME, use_keep_connect);
	SetEnable(hWnd, E_PORT, use_keep_connect);
	SetEnable(hWnd, E_INTERVAL, use_keep_connect);
	SetEnable(hWnd, R_TCP, use_keep_connect);
	SetEnable(hWnd, R_UDP, use_keep_connect);

	SetEnable(hWnd, S_WARNING, IsChecked(hWnd, R_ALLOW_REMOTE_CONFIG));

	if (IsChecked(hWnd, R_USE_KEEP_CONNECT))
	{
		if (IsEmpty(hWnd, E_HOSTNAME))
		{
			ok = false;
		}
		if (IsChecked(hWnd, R_TCP) == false && IsChecked(hWnd, R_UDP) == false)
		{
			ok = false;
		}
		if (GetInt(hWnd, E_PORT) == 0 || GetInt(hWnd, E_PORT) >= 65536)
		{
			ok = false;
		}
		if (GetInt(hWnd, E_INTERVAL) == 0)
		{
			ok = false;
		}
	}

	if (IsChecked(hWnd, R_ALPHA))
	{
		UINT i = GetInt(hWnd, E_ALPHA_VALUE);
		if (i < 20 || i >= 100)
		{
			ok = false;
		}
		Enable(hWnd, E_ALPHA_VALUE);
	}
	else
	{
		Disable(hWnd, E_ALPHA_VALUE);
	}

	SetEnable(hWnd, IDOK, ok);
}

// Save the setting of the option dialog
void CmConfigDlgOnOk(HWND hWnd)
{
	CLIENT_CONFIG c;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	Zero(&c, sizeof(c));
	c.AllowRemoteConfig = IsChecked(hWnd, R_ALLOW_REMOTE_CONFIG);
	c.UseKeepConnect = IsChecked(hWnd, R_USE_KEEP_CONNECT);
	GetTxtA(hWnd, E_HOSTNAME, c.KeepConnectHost, sizeof(c.KeepConnectHost));
	c.KeepConnectPort = GetInt(hWnd, E_PORT);
	c.KeepConnectInterval = GetInt(hWnd, E_INTERVAL);
	if (IsChecked(hWnd, R_TCP))
	{
		c.KeepConnectProtocol = CONNECTION_TCP;
	}
	else if (IsChecked(hWnd, R_UDP))
	{
		c.KeepConnectProtocol = CONNECTION_UDP;
	}
	else
	{
		return;
	}

	if (c.UseKeepConnect)
	{
		if (c.KeepConnectInterval < KEEP_INTERVAL_MIN || c.KeepConnectInterval > KEEP_INTERVAL_MAX)
		{
			MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("CM_KEEP_INTERVAL_MSG"),
				KEEP_INTERVAL_MIN, KEEP_INTERVAL_MAX);
			FocusEx(hWnd, E_INTERVAL);
			return;
		}
	}

	if (CALL(hWnd, CcSetClientConfig(cm->Client, &c)) == false)
	{
		return;
	}

	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY, "AlphaValue", GetInt(hWnd, E_ALPHA_VALUE));
	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY, "UseAlpha", IsChecked(hWnd, R_ALPHA));

	EndDialog(hWnd, true);
}

// Option setting dialog procedure
UINT CmConfigDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CmConfigDlgInit(hWnd);
		break;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_ALLOW_REMOTE_CONFIG:
		case R_USE_KEEP_CONNECT:
		case E_HOSTNAME:
		case E_PORT:
		case E_INTERVAL:
		case R_ALPHA:
		case E_ALPHA_VALUE:
			CmConfigDlgRefresh(hWnd);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			CmConfigDlgRefresh(hWnd);
			CmConfigDlgOnOk(hWnd);
			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		case R_ALLOW_REMOTE_CONFIG:
			if (IsChecked(hWnd, R_ALLOW_REMOTE_CONFIG) == false)
			{
				if (cm->server_name != NULL)
				{
					// If the current user is remotely connected, show a warning
					// when the user choose to disable the remote management
					if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_DEFBUTTON2 | MB_YESNO, _UU("CM_REMOTE_WARNING"),
						cm->server_name, cm->server_name) == IDNO)
					{
						Check(hWnd, R_ALLOW_REMOTE_CONFIG, true);
					}
				}
			}
			break;
		case R_USE_KEEP_CONNECT:
			if (IsChecked(hWnd, R_USE_KEEP_CONNECT))
			{
				FocusEx(hWnd, E_HOSTNAME);
			}
			break;
		case R_ALPHA:
			if (IsChecked(hWnd, R_ALPHA))
			{
				FocusEx(hWnd, E_ALPHA_VALUE);
			}
			break;
		}
		break;
	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Create a shortcut
void CmSortcut(HWND hWnd, wchar_t *account_name)
{
	wchar_t tmp[MAX_SIZE];
	CM_ACCOUNT *a;
	wchar_t *filename;
	UCHAR key[SHA1_SIZE];
	// Validate arguments
	if (hWnd == NULL || account_name == NULL)
	{
		return;
	}

	// Get the account information
	a = CmGetExistAccountObject(hWnd, account_name);
	if (a == NULL)
	{
		return;
	}

	Copy(key, a->ShortcutKey, SHA1_SIZE);

	if (IsZero(key, SHA1_SIZE))
	{
		MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_SHORTCUT_UNSUPPORTED"));
	}
	else
	{
		// Determine the file name
		UniFormat(tmp, sizeof(tmp), L"%s.lnk", account_name);
		UniSafeFileName(tmp);

		filename = SaveDlg(hWnd, _UU("CM_SHORTCUT_FILE"),
			_UU("CM_SHORTCUT_SAVE_TITLE"), tmp, L".vpn");

		if (filename != NULL)
		{
			char key_str[64];
			wchar_t target[MAX_PATH];
			wchar_t workdir[MAX_PATH];
			wchar_t args[MAX_PATH];
			wchar_t comment[MAX_SIZE];
			wchar_t icon[MAX_PATH];

			BinToStr(key_str, sizeof(key_str), key, SHA1_SIZE);

			// Create a shortcut
			UniStrCpy(target, sizeof(target), MsGetExeFileNameW());
			UniStrCpy(workdir, sizeof(workdir), MsGetExeDirNameW());
			StrToUni(args, sizeof(args), key_str);
			UniFormat(comment, sizeof(comment), _UU("CM_SHORTCUT_COMMENT"), account_name);
			UniStrCpy(icon, sizeof(icon), MsGetExeFileNameW());

			if (CreateLink(filename, target, workdir, args, comment, icon, 1) == false)
			{
				MsgBox(hWnd, MB_ICONSTOP, _UU("CM_SHORTCUT_ERROR"));
			}

			Free(filename);
		}
	}

	CmFreeAccountObject(hWnd, a);
}

// Export the account
void CmExportAccount(HWND hWnd, wchar_t *account_name)
{
	wchar_t tmp[MAX_SIZE];
	CM_ACCOUNT *a;
	wchar_t *filename;
	// Validate arguments
	if (hWnd == NULL || account_name == NULL)
	{
		return;
	}

	// Get the account information
	a = CmGetExistAccountObject(hWnd, account_name);
	if (a == NULL)
	{
		return;
	}

	// Determine the file name
	UniFormat(tmp, sizeof(tmp), L"%s.vpn", account_name);
	UniSafeFileName(tmp);

	filename = SaveDlg(hWnd, _UU("CM_ACCOUNT_SETTING_FILE"),
		_UU("CM_ACCOUNT_SAVE_TITLE"), tmp, L".vpn");

	if (filename != NULL)
	{
		RPC_CLIENT_CREATE_ACCOUNT t;
		BUF *b;
		BUF *b2;
		wchar_t tmp[MAX_SIZE];
		UCHAR *buf;
		UINT buf_size;
		UCHAR bom[] = {0xef, 0xbb, 0xbf, };

		Zero(&t, sizeof(t));
		t.ClientOption = a->ClientOption;
		t.ClientAuth = a->ClientAuth;
		t.StartupAccount = a->Startup;
		t.CheckServerCert = a->CheckServerCert;
		t.RetryOnServerCert = a->RetryOnServerCert;
		t.ServerCert = a->ServerCert;
		t.ClientOption->FromAdminPack = false;

		b = CiAccountToCfg(&t);

		SeekBuf(b, 0, 0);

		// Check whether the password is contained
		if (CiHasAccountSensitiveInformation(b))
		{
			SeekBuf(b, 0, 0);

			// Confirm that the user want to clear the password
			if (MsgBox(hWnd, MB_YESNO | MB_ICONQUESTION, _UU("CM_ACCOUNT_MSG_SENSITIVE")) == IDYES)
			{
				// Erase
				CiEraseSensitiveInAccount(b);
			}
		}

		UniStrCpy(tmp, sizeof(tmp), filename);
		b2 = NewBuf();

		WriteBuf(b2, bom, sizeof(bom));

		// Add a header part
		buf_size = CalcUniToUtf8(_UU("CM_ACCOUNT_FILE_BANNER"));
		buf = ZeroMalloc(buf_size + 32);
		UniToUtf8(buf, buf_size, _UU("CM_ACCOUNT_FILE_BANNER"));

		WriteBuf(b2, buf, StrLen((char *)buf));
		WriteBuf(b2, b->Buf, b->Size);
		SeekBuf(b2, 0, 0);

		FreeBuf(b);

		if (DumpBufW(b2, tmp) == false)
		{
			MsgBox(hWnd, MB_ICONSTOP, _UU("CM_FAILED_TO_SAVE_FILE"));
		}

		Free(filename);
		FreeBuf(b2);
		Free(buf);
	}

	CmFreeAccountObject(hWnd, a);
}

// Main process of importing account
void CmImportAccountMain(HWND hWnd, wchar_t *filename)
{
	CmImportAccountMainEx(hWnd, filename, false);
}
void CmImportAccountMainEx(HWND hWnd, wchar_t *filename, bool overwrite)
{
	wchar_t name[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	BUF *b;
	RPC_CLIENT_CREATE_ACCOUNT *t;
	// Validate arguments
	if (hWnd == NULL || filename == NULL)
	{
		return;
	}

	UniStrCpy(tmp, sizeof(tmp), filename);

	b = ReadDumpW(tmp);
	if (b == NULL)
	{
		MsgBox(hWnd, MB_ICONSTOP, _UU("CM_FAILED_TO_OPEN_FILE"));
		return;
	}

	t = CiCfgToAccount(b);
	if (t == NULL)
	{
		FreeBuf(b);
		MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("CM_ACCOUNT_PARSE_FAILED"));
		return;
	}

	if (overwrite)
	{
		// If the same name already exists, remove it
		if (LvSearchStr(hWnd, L_ACCOUNT, 0, t->ClientOption->AccountName) != INFINITE)
		{
			RPC_CLIENT_DELETE_ACCOUNT d;
			RPC_CLIENT_GET_ACCOUNT get;
			HWND h = cm->hEasyWnd == NULL ? hWnd : cm->hEasyWnd;

			Zero(&d, sizeof(d));
			UniStrCpy(d.AccountName, sizeof(d.AccountName), t->ClientOption->AccountName);

			Zero(&get, sizeof(get));
			UniStrCpy(get.AccountName, sizeof(get.AccountName), t->ClientOption->AccountName);
			if (CcGetAccount(cm->Client, &get) == ERR_NO_ERROR)
			{
				// Inherit the information of some of the client option by getting
				// the account information of the same name that already exists
				if (get.ClientOption != NULL && get.ClientAuth != NULL)
				{
					CLIENT_OPTION *old_option = get.ClientOption;
					CLIENT_AUTH *old_auth = get.ClientAuth;

					// Inherit the connection parameters
					t->ClientOption->ProxyType = old_option->ProxyType;
					StrCpy(t->ClientOption->ProxyName, sizeof(t->ClientOption->ProxyName),
						old_option->ProxyName);
					t->ClientOption->ProxyPort = old_option->ProxyPort;
					StrCpy(t->ClientOption->ProxyUsername, sizeof(t->ClientOption->ProxyUsername),
						old_option->ProxyUsername);
					StrCpy(t->ClientOption->ProxyPassword, sizeof(t->ClientOption->ProxyPassword),
						old_option->ProxyPassword);
					t->ClientOption->NumRetry = old_option->NumRetry;
					t->ClientOption->RetryInterval = old_option->RetryInterval;
					t->ClientOption->MaxConnection = old_option->MaxConnection;
					t->ClientOption->UseEncrypt = old_option->UseEncrypt;
					t->ClientOption->UseCompress = old_option->UseCompress;
					t->ClientOption->HalfConnection = old_option->HalfConnection;
					t->ClientOption->NoRoutingTracking = old_option->NoRoutingTracking;
					StrCpy(t->ClientOption->DeviceName, sizeof(t->ClientOption->DeviceName),
						old_option->DeviceName);
					t->ClientOption->AdditionalConnectionInterval = old_option->AdditionalConnectionInterval;
					t->ClientOption->ConnectionDisconnectSpan = old_option->ConnectionDisconnectSpan;
					t->ClientOption->HideStatusWindow = old_option->HideStatusWindow;
					t->ClientOption->RequireMonitorMode = old_option->RequireMonitorMode;
					t->ClientOption->RequireBridgeRoutingMode = old_option->RequireBridgeRoutingMode;
					t->ClientOption->DisableQoS = old_option->DisableQoS;

					// Inherit the authentication data
					CiFreeClientAuth(t->ClientAuth);
					t->ClientAuth = CopyClientAuth(old_auth);

					// Other Settings
					t->StartupAccount = get.StartupAccount;
					t->CheckServerCert = get.CheckServerCert;
					t->RetryOnServerCert = get.RetryOnServerCert;
					if (t->ServerCert != NULL)
					{
						FreeX(t->ServerCert);
					}
					t->ServerCert = NULL;
					if (get.ServerCert != NULL)
					{
						t->ServerCert = CloneX(get.ServerCert);
					}
					Copy(t->ShortcutKey, get.ShortcutKey, sizeof(t->ShortcutKey));
				}

				CiFreeClientGetAccount(&get);
			}

			if (CALL(h, CcDeleteAccount(cm->Client, &d)) == false)
			{
				CiFreeClientCreateAccount(t);
				Free(t);
				return;
			}

			CmRefreshAccountList(hWnd);
		}
	}

	CmGenerateImportName(hWnd, name, sizeof(name), t->ClientOption->AccountName);
	UniStrCpy(t->ClientOption->AccountName, sizeof(t->ClientOption->AccountName), name);

	if (overwrite)
	{
		t->ClientOption->FromAdminPack = true;
	}

	CALL(hWnd, CcCreateAccount(cm->Client, t));

	CiFreeClientCreateAccount(t);
	Free(t);

	FreeBuf(b);

	if (overwrite)
	{
		// Start to connect the VPN 
		CmConnect(hWnd, name);
	}

	//MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("CM_IMPORT_MESSAGE"), filename, name);
}

// Import an account
void CmImportAccount(HWND hWnd)
{
	wchar_t *filename;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Open the file
	filename = OpenDlg(hWnd, _UU("CM_ACCOUNT_SETTING_FILE"), _UU("CM_ACCOUNT_OPEN_TITLE"));
	if (filename == NULL)
	{
		return;
	}

	UniStrCpy(tmp, sizeof(tmp), filename);
	Free(filename);

	CmImportAccountMain(hWnd, tmp);
}

// Create a copy of the account
void CmCopyAccount(HWND hWnd, wchar_t *account_name)
{
	wchar_t tmp[MAX_SIZE];
	CM_ACCOUNT *a;
	RPC_CLIENT_CREATE_ACCOUNT c;
	// Validate arguments
	if (hWnd == NULL || account_name == NULL)
	{
		return;
	}

	CmGenerateCopyName(hWnd, tmp, sizeof(tmp), account_name);

	// Get an account information
	a = CmGetExistAccountObject(hWnd, account_name);
	if (a == NULL)
	{
		return;
	}

	// Change the account name
	UniStrCpy(a->ClientOption->AccountName, sizeof(a->ClientOption->AccountName), tmp);

	// Write
	Zero(&c, sizeof(c));
	c.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	Copy(c.ClientOption, a->ClientOption, sizeof(CLIENT_OPTION));
	c.ClientAuth = CopyClientAuth(a->ClientAuth);
	if (a->ServerCert)
	{
		c.ServerCert = CloneX(a->ServerCert);
	}
	c.CheckServerCert = a->CheckServerCert;
	c.RetryOnServerCert = a->RetryOnServerCert;
	c.StartupAccount = false;		// Don't copy the startup attribute

	CALL(hWnd, CcCreateAccount(cm->Client, &c));
	CiFreeClientCreateAccount(&c);

	CmFreeAccountObject(hWnd, a);
}

// Update the Virtual LAN Card Name dialog
void CmNewVLanDlgUpdate(HWND hWnd)
{
	bool ok = true;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_NAME, tmp, sizeof(tmp));
	if (IsSafeStr(tmp) == false)
	{
		ok = false;
	}
	if (SearchStrEx(tmp, " ", 0, false) != INFINITE)
	{
		ok = false;
	}

	Trim(tmp);
	if (StrLen(tmp) == 0)
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
}

// Virtual LAN card name decision dialog procedure
UINT CmNewVLanDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	char *tmp = (char *)param;
	char default_name[MAX_SIZE];
	RPC_CLIENT_VERSION ver;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		LimitText(hWnd, E_NAME, cm->Client->Win9x ? MAX_DEVICE_NAME_LEN_9X : MAX_DEVICE_NAME_LEN);
		FormatText(hWnd, S_INFO, cm->Client->Win9x ? MAX_DEVICE_NAME_LEN_9X : MAX_DEVICE_NAME_LEN);

		Zero(&ver, sizeof(ver));

		if (CcGetClientVersion(cm->Client, &ver) == ERR_NO_ERROR)
		{
			if (ver.IsVLanNameRegulated)
			{
				Show(hWnd, S_WIN8);
			}
		}

		if (CiGetNextRecommendedVLanName(cm->Client, default_name, sizeof(default_name)))
		{
			// Show a default virtual LAN card name candidate
			SetTextA(hWnd, E_NAME, default_name);
		}

		CmNewVLanDlgUpdate(hWnd);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (cm->Client->Win9x)
			{
				// For Windows 9x, show a confirmation message
				if (MsgBox(hWnd, MB_ICONQUESTION | MB_OKCANCEL, _UU("CM_9X_VLAN_INSTALL")) == IDCANCEL)
				{
					break;
				}
			}
			GetTxtA(hWnd, E_NAME, tmp, (cm->Client->Win9x ? MAX_DEVICE_NAME_LEN_9X : MAX_DEVICE_NAME_LEN) + 1);
			Trim(tmp);

			if (CcGetClientVersion(cm->Client, &ver) == ERR_NO_ERROR)
			{
				if (ver.IsVLanNameRegulated)
				{
					if (CiIsValidVLanRegulatedName(tmp) == false)
					{
						// Virtual LAN card name isn't meeting the format
						MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("D_CM_NEW_VLAN@S_WIN8"));

						FocusEx(hWnd, E_NAME);
						break;
					}
				}
			}

			EndDialog(hWnd, true);
			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		switch (LOWORD(wParam))
		{
		case E_NAME:
			CmNewVLanDlgUpdate(hWnd);
			break;

		case R_USE_DISCONNECT:
			if (IsChecked(hWnd, R_USE_DISCONNECT))
			{
				FocusEx(hWnd, E_DISCONNECT_SPAN);
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Dialog to determine the new virtual LAN card name
char *CmNewVLanDlg(HWND hWnd)
{
	char tmp[MAX_DEVICE_NAME_LEN + 1];

	if (Dialog(hWnd, D_CM_NEW_VLAN, CmNewVLanDlgProc, tmp) == false)
	{
		return NULL;
	}

	return CopyStr(tmp);
}

// Update the advanced settings dialog
void CmDetailDlgUpdate(HWND hWnd, CM_ACCOUNT *a)
{
	bool ok = true;
	bool locked;
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	locked = a->LockMode;

	if (a->LinkMode || a->NatMode)
	{
		Disable(hWnd, R_NO_ROUTING);
	}
	else
	{
		if (cm->Client->Unix)
		{
			Disable(hWnd, R_NO_ROUTING);
		}
	}

	SetEnable(hWnd, E_DISCONNECT_SPAN, IsChecked(hWnd, R_USE_DISCONNECT));

	SetEnable(hWnd, IDOK, ok);

	if (locked)
	{
		Disable(hWnd, C_NUM_TCP);
		Disable(hWnd, S_STATIC5);
		Disable(hWnd, S_STATIC8);
		Disable(hWnd, E_INTERVAL);
		Disable(hWnd, S_STATIC9);
		Disable(hWnd, E_DISCONNECT_SPAN);
		Disable(hWnd, S_STATIC10);
		Disable(hWnd, S_STATIC11);
		Disable(hWnd, R_USE_DISCONNECT);
		Disable(hWnd, R_USE_HALF_CONNECTION);
		Disable(hWnd, R_DISABLE_QOS);
		Disable(hWnd, R_USE_ENCRYPT);
		Disable(hWnd, R_USE_COMPRESS);
		Disable(hWnd, R_BRIDGE);
		Disable(hWnd, R_MONITOR);
		Disable(hWnd, R_NO_ROUTING);
	}
}

// Advanced Settings dialog procedure
UINT CmDetailDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CM_ACCOUNT *a = (CM_ACCOUNT *)param;
	UINT i;
	UINT num;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Number of TCP connections
		for (i = 1;i <= MAX_TCP_CONNECTION;i++)
		{
			UniFormat(tmp, sizeof(tmp), L"%u", i);
			CbAddStr(hWnd, C_NUM_TCP, tmp, i);
		}
		CbSelect(hWnd, C_NUM_TCP, a->ClientOption->MaxConnection);

		// Connection establishment interval
		SetInt(hWnd, E_INTERVAL, a->ClientOption->AdditionalConnectionInterval);

		// Lifetime
		SetIntEx(hWnd, E_DISCONNECT_SPAN, a->ClientOption->ConnectionDisconnectSpan);
		Check(hWnd, R_USE_DISCONNECT, a->ClientOption->ConnectionDisconnectSpan != 0);
		Check(hWnd, R_USE_HALF_CONNECTION, a->ClientOption->HalfConnection);
		Check(hWnd, R_USE_ENCRYPT, a->ClientOption->UseEncrypt);
		Check(hWnd, R_USE_COMPRESS, a->ClientOption->UseCompress);
		Check(hWnd, R_NO_ROUTING, a->ClientOption->NoRoutingTracking);
		Check(hWnd, R_DISABLE_QOS, a->ClientOption->DisableQoS);
		Check(hWnd, R_DISABLE_UDP, a->ClientOption->NoUdpAcceleration);

		// Select the Connection Mode
		if (a->LinkMode == false)
		{
			Check(hWnd, R_BRIDGE, a->ClientOption->RequireBridgeRoutingMode);
			Check(hWnd, R_MONITOR, a->ClientOption->RequireMonitorMode);
		}
		else
		{
			Check(hWnd, R_BRIDGE, true);
			Check(hWnd, R_MONITOR, false);

			SetText(hWnd, S_MODE, _UU("CM_DETAIL_MODE_LINK_STR"));
			Disable(hWnd, R_BRIDGE);
			Disable(hWnd, R_MONITOR);
		}

		CmDetailDlgUpdate(hWnd, a);
		Focus(hWnd, IDOK);
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (IsChecked(hWnd, R_USE_DISCONNECT) && GetInt(hWnd, E_DISCONNECT_SPAN) == 0)
			{
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_NO_DISCONNECT_SPAN"));
				FocusEx(hWnd, E_DISCONNECT_SPAN);
				break;
			}
			num = GetInt(hWnd, C_NUM_TCP);
			if (num == 0)
			{
				break;
			}
			if (num == 1 && IsChecked(hWnd, R_USE_HALF_CONNECTION))
			{
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_HALF_MSG"));
				Focus(hWnd, C_NUM_TCP);
				break;
			}
			if (GetInt(hWnd, E_INTERVAL) < 1)
			{
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_TOO_SMALL_INTERVAL"));
				Focus(hWnd, E_INTERVAL);
				break;
			}

			a->ClientOption->MaxConnection = num;
			a->ClientOption->AdditionalConnectionInterval = GetInt(hWnd, E_INTERVAL);
			if (IsChecked(hWnd, R_USE_DISCONNECT) == false)
			{
				a->ClientOption->ConnectionDisconnectSpan = 0;
			}
			else
			{
				a->ClientOption->ConnectionDisconnectSpan = GetInt(hWnd, E_DISCONNECT_SPAN);
			}
			a->ClientOption->HalfConnection = IsChecked(hWnd, R_USE_HALF_CONNECTION);
			a->ClientOption->UseEncrypt = IsChecked(hWnd, R_USE_ENCRYPT);
			a->ClientOption->UseCompress = IsChecked(hWnd, R_USE_COMPRESS);
			a->ClientOption->NoRoutingTracking = IsChecked(hWnd, R_NO_ROUTING);
			a->ClientOption->DisableQoS = IsChecked(hWnd, R_DISABLE_QOS);
			a->ClientOption->NoUdpAcceleration = IsChecked(hWnd, R_DISABLE_UDP);

			if (a->LinkMode)
			{
				a->ClientOption->RequireBridgeRoutingMode = true;
				a->ClientOption->RequireMonitorMode = false;
			}
			else
			{
				a->ClientOption->RequireBridgeRoutingMode = IsChecked(hWnd, R_BRIDGE);
				a->ClientOption->RequireMonitorMode = IsChecked(hWnd, R_MONITOR);
			}

			EndDialog(hWnd, true);

			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		switch (LOWORD(wParam))
		{
		case C_NUM_TCP:
		case E_INTERVAL:
		case E_DISCONNECT_SPAN:
		case R_USE_DISCONNECT:
		case R_USE_HALF_CONNECTION:
			CmDetailDlgUpdate(hWnd, a);
			break;
		}
		switch (wParam)
		{
		case R_USE_DISCONNECT:
			if (IsChecked(hWnd, R_USE_DISCONNECT))
			{
				FocusEx(hWnd, E_DISCONNECT_SPAN);
			}
			break;
		}
		break;
	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Advanced Settings dialog
bool CmDetailDlg(HWND hWnd, CM_ACCOUNT *a)
{
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_CM_DETAIL, CmDetailDlgProc, a);
}

// Update the account editing dialog procedure
void CmEditAccountDlgUpdate(HWND hWnd, CM_ACCOUNT *a)
{
	bool ok = true;
	char str[MAX_SIZE];
	bool locked;
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	locked = a->LockMode;

	if (a->Inited == false)
	{
		return;
	}

	if (a->EditMode)
	{
		Disable(hWnd, E_ACCOUNT_NAME);
	}

	// The name of connection settings
	GetTxt(hWnd, E_ACCOUNT_NAME, a->ClientOption->AccountName, sizeof(a->ClientOption->AccountName));
	UniTrim(a->ClientOption->AccountName);

	// Host name
	GetTxtA(hWnd, E_HOSTNAME, a->ClientOption->Hostname, sizeof(a->ClientOption->Hostname));
	Trim(a->ClientOption->Hostname);

	if (InStr(a->ClientOption->Hostname, "/tcp"))
	{
		Check(hWnd, R_DISABLE_NATT, true);
	}
	else
	{
		Check(hWnd, R_DISABLE_NATT, false);
	}

	SetEnable(hWnd, R_DISABLE_NATT, !IsEmptyStr(a->ClientOption->Hostname));

	// Port number
	a->ClientOption->Port = GetInt(hWnd, C_PORT);

	// HUB name
	GetTxtA(hWnd,C_HUBNAME, a->ClientOption->HubName, sizeof(a->ClientOption->HubName));

	// Type of proxy
	a->ClientOption->ProxyType = PROXY_DIRECT;
	if (IsChecked(hWnd, R_HTTPS))
	{
		a->ClientOption->ProxyType = PROXY_HTTP;
	}
	if (IsChecked(hWnd, R_SOCKS))
	{
		a->ClientOption->ProxyType = PROXY_SOCKS;
	}
	if (IsChecked(hWnd, R_SOCKS5))
	{
		a->ClientOption->ProxyType = PROXY_SOCKS5;
	}

	// To validate the server certificate
	a->CheckServerCert = IsChecked(hWnd, R_CHECK_CERT);

	if (a->NatMode)
	{
		Disable(hWnd, R_CHECK_CERT);
		Disable(hWnd, B_TRUST);
	}

	if (a->HideTrustCert)
	{
		Disable(hWnd, B_TRUST);
	}

	// Device name
	StrCpy(a->ClientOption->DeviceName, sizeof(a->ClientOption->DeviceName), "");
	if (LvIsSelected(hWnd, L_VLAN))
	{
		wchar_t *s = LvGetStr(hWnd, L_VLAN, LvGetSelected(hWnd, L_VLAN), 0);
		if (s != NULL)
		{
			char str[MAX_SIZE];
			UniToStr(str, sizeof(str), s);
			CmPrintNameToVLanName(a->ClientOption->DeviceName, sizeof(a->ClientOption->DeviceName), str);
			Free(s);
		}
	}

	// User authentication
	a->ClientAuth->AuthType = CbGetSelect(hWnd, C_TYPE);
	GetTxtA(hWnd, E_USERNAME, a->ClientAuth->Username, sizeof(a->ClientAuth->Username));
	Trim(a->ClientAuth->Username);
	switch (a->ClientAuth->AuthType)
	{
	case CLIENT_AUTHTYPE_PASSWORD:
		// Password authentication
		GetTxtA(hWnd, E_PASSWORD, str, sizeof(str));
		if (StrCmp(str, HIDDEN_PASSWORD) != 0)
		{
			HashPassword(a->ClientAuth->HashedPassword, a->ClientAuth->Username, str);
		}
		break;
	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		// Plaintext password authentication
		GetTxtA(hWnd, E_PASSWORD, str, sizeof(str));
		if (StrCmp(str, HIDDEN_PASSWORD) != 0)
		{
			StrCpy(a->ClientAuth->PlainPassword, sizeof(a->ClientAuth->PlainPassword), str);
		}
		break;
	}

	// Reconnection option
	if ((a->LinkMode || a->NatMode) || a->ClientAuth->AuthType == CLIENT_AUTHTYPE_SECURE)
	{
		Disable(hWnd, R_RETRY);
	}
	else
	{
		Enable(hWnd, R_RETRY);
	}

	if (IsChecked(hWnd, R_RETRY) == false)
	{
		a->ClientOption->NumRetry = 0;
	}
	else
	{
		if (IsChecked(hWnd, R_INFINITE))
		{
			a->ClientOption->NumRetry = INFINITE;
		}
		else
		{
			a->ClientOption->NumRetry = GetInt(hWnd, E_RETRY_NUM);
		}
	}
	a->ClientOption->RetryInterval = GetInt(hWnd, E_RETRY_SPAN);

	// Information determining
	if (UniStrLen(a->ClientOption->AccountName) == 0 && a->NatMode == false)
	{
		ok = false;
	}
	if (StrLen(a->ClientOption->Hostname) == 0)
	{
		ok = false;
	}
	if (a->ClientOption->Port == 0 || a->ClientOption->Port >= 65536)
	{
		ok = false;
	}
	if (StrLen(a->ClientOption->HubName) == 0)
	{
		ok = false;
	}
	if (StrLen(a->ClientAuth->Username) == 0)
	{
		ok = false;
	}
	if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
	{
		if (a->ClientAuth->ClientK == NULL || a->ClientAuth->ClientX == NULL)
		{
			ok = false;
		}
	}
	if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_SECURE)
	{
		if (IsEmptyStr(a->ClientAuth->SecurePrivateKeyName) || IsEmptyStr(a->ClientAuth->SecurePublicCertName))
		{
			ok = false;
		}
	}

	// Display update
	if (IsChecked(hWnd, R_RETRY) && IsEnable(hWnd, R_RETRY))
	{
		if (a->LinkMode == false && a->NatMode == false)
		{
			Enable(hWnd, R_INFINITE);
			Enable(hWnd, E_RETRY_SPAN);
			Enable(hWnd, S_RETRY_SPAN_1);
			Enable(hWnd, S_RETRY_SPAN_2);
		}
		else
		{
			Disable(hWnd, R_INFINITE);
			Disable(hWnd, E_RETRY_SPAN);
			Disable(hWnd, S_RETRY_SPAN_1);
			Disable(hWnd, S_RETRY_SPAN_2);
		}
		if (IsChecked(hWnd, R_INFINITE) == false)
		{
			Enable(hWnd, E_RETRY_NUM);
			Enable(hWnd, S_RETRY_NUM_1);
			Enable(hWnd, S_RETRY_NUM_2);
			if (GetInt(hWnd, E_RETRY_NUM) == 0)
			{
				ok = false;
			}
		}
		else
		{
			Disable(hWnd, E_RETRY_NUM);
			Disable(hWnd, S_RETRY_NUM_1);
			Disable(hWnd, S_RETRY_NUM_2);
		}
	}
	else
	{
		Disable(hWnd, E_RETRY_NUM);
		Disable(hWnd, E_RETRY_SPAN);
		Disable(hWnd, R_INFINITE);
		Disable(hWnd, S_RETRY_NUM_1);
		Disable(hWnd, S_RETRY_NUM_2);
		Disable(hWnd, S_RETRY_SPAN_1);
		Disable(hWnd, S_RETRY_SPAN_2);
	}

	if (a->NatMode == false)
	{
		if (a->ServerCert == NULL)
		{
			SetText(hWnd, B_SERVER_CERT, _UU("CM_SERVER_CERT_1"));
			Disable(hWnd, B_VIEW_SERVER_CERT);
		}
		else
		{
			SetText(hWnd, B_SERVER_CERT, _UU("CM_SERVER_CERT_2"));
			Enable(hWnd, B_VIEW_SERVER_CERT);
		}
	}
	else
	{
		Disable(hWnd, B_VIEW_SERVER_CERT);
		Disable(hWnd, B_SERVER_CERT);
	}

	if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT || a->ClientAuth->AuthType == CLIENT_AUTHTYPE_SECURE)
	{
		wchar_t tmp[MAX_SIZE * 2];
		wchar_t issuer[MAX_SIZE];
		wchar_t subject[MAX_SIZE];
		wchar_t expires[MAX_SIZE];

		SetIcon(hWnd, S_CERT, (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT) ? ICO_CERT : ICO_SECURE);

		Hide(hWnd, S_PASSWORD);
		Hide(hWnd, E_PASSWORD);
		if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
		{
			if (a->ClientAuth->ClientX != NULL)
			{
				Enable(hWnd, B_VIEW_CLIENT_CERT);
				SetText(hWnd, B_REGIST_CLIENT_CERT, _UU("CM_CLIENT_CERT_2"));
				GetPrintNameFromName(issuer, sizeof(issuer), a->ClientAuth->ClientX->issuer_name);
				GetPrintNameFromName(subject, sizeof(subject), a->ClientAuth->ClientX->subject_name);
				GetDateStrEx64(expires, sizeof(expires), SystemToLocal64(a->ClientAuth->ClientX->notAfter), NULL);
				UniFormat(tmp, sizeof(tmp), _UU("CM_CERT_INFO"), subject, issuer, expires);
			}
			else
			{
				Disable(hWnd, B_VIEW_CLIENT_CERT);
				SetText(hWnd, B_REGIST_CLIENT_CERT, _UU("CM_CLIENT_CERT_1"));
				UniStrCpy(tmp, sizeof(tmp), _UU("CM_NO_CERT"));
			}
			SetText(hWnd, B_VIEW_CLIENT_CERT, _UU("CM_VIEW_CLIENT_CERT"));

			Enable(hWnd, B_REGIST_CLIENT_CERT);
		}
		else
		{
			if (IsEmptyStr(a->ClientAuth->SecurePrivateKeyName) || IsEmptyStr(a->ClientAuth->SecurePublicCertName))
			{
				UniStrCpy(tmp, sizeof(tmp), _UU("CM_NO_SECURE"));
			}
			else
			{
				UniFormat(tmp, sizeof(tmp), _UU("CM_CERT_SECURE_INFO"),
					a->ClientAuth->SecurePublicCertName, a->ClientAuth->SecurePrivateKeyName);
			}

			SetText(hWnd, B_VIEW_CLIENT_CERT, _UU("CM_SELECT_SECURE_DEVICE"));
			SetText(hWnd, B_REGIST_CLIENT_CERT, _UU("CM_SELECT_CERT_INCARD"));
			Enable(hWnd, B_VIEW_CLIENT_CERT);

			if (SmGetCurrentSecureIdFromReg() == 0)
			{
				Disable(hWnd, B_REGIST_CLIENT_CERT);
			}
			else
			{
				Enable(hWnd, B_REGIST_CLIENT_CERT);
			}
		}
		SetText(hWnd, S_CERT_INFO, tmp);
		Show(hWnd, S_CERT);
		Show(hWnd, S_CERT_INFO);
		Show(hWnd, B_VIEW_CLIENT_CERT);
		Show(hWnd, B_REGIST_CLIENT_CERT);
	}
	else
	{
		if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_ANONYMOUS)
		{
			Hide(hWnd, S_PASSWORD);
			Hide(hWnd, E_PASSWORD);
		}
		else
		{
			Show(hWnd, S_PASSWORD);
			Show(hWnd, E_PASSWORD);
		}
		Hide(hWnd, S_CERT);
		Hide(hWnd, S_CERT_INFO);
		Hide(hWnd, B_VIEW_CLIENT_CERT);
		Hide(hWnd, B_REGIST_CLIENT_CERT);
	}

	if (a->ClientOption->ProxyType != PROXY_DIRECT)
	{
		Enable(hWnd, B_PROXY_CONFIG);
		if (StrLen(a->ClientOption->ProxyName) == 0)
		{
			ok = false;
		}
		if (a->ClientOption->ProxyPort == 0)
		{
			ok = false;
		}
	}
	else
	{
		Disable(hWnd, B_PROXY_CONFIG);
	}

	if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD)
	{
		bool b = true;

		if (ok == false)
		{
			b = false;
		}

		if (a->LinkMode == false && a->NatMode == false)
		{
			SetEnable(hWnd, B_CHANGE_PASSWORD, b);
			SetEnable(hWnd, S_CHANGE_PASSWORD, b);
			Show(hWnd, B_CHANGE_PASSWORD);
			Show(hWnd, S_CHANGE_PASSWORD);
		}
		else
		{
			Hide(hWnd, B_CHANGE_PASSWORD);
			Hide(hWnd, S_CHANGE_PASSWORD);
		}
	}
	else
	{
		Hide(hWnd, B_CHANGE_PASSWORD);
		Hide(hWnd, S_CHANGE_PASSWORD);
	}

	if ((StrLen(a->ClientOption->DeviceName) == 0) && (a->LinkMode == false && a->NatMode == false))
	{
		ok = false;
	}

	if (a->LinkMode || a->NatMode)
	{
		Disable(hWnd, L_VLAN);
	}

	if (a->EditMode == false)
	{
		char tmp[MAX_SIZE];
		GetTxtA(hWnd, E_HOSTNAME, tmp, sizeof(tmp));
		Trim(tmp);

		if (StartWith(tmp, "127.") || (StrCmpi(tmp, "localhost") == 0))
		{
			if (a->Flag1 == false)
			{
				a->Flag1 = true;
				a->ClientOption->UseEncrypt = a->ClientOption->UseCompress = false;
				a->ClientOption->MaxConnection = 1;
			}
		}
	}

	a->ClientOption->HideStatusWindow = IsChecked(hWnd, R_HIDE);
	a->ClientOption->HideNicInfoWindow = IsChecked(hWnd, R_HIDE2);

	if (locked)
	{
		SetEnable(hWnd, E_HOSTNAME, false);
		SetEnable(hWnd, C_PORT, false);
		SetEnable(hWnd, C_HUBNAME, false);
		SetEnable(hWnd, S_STATIC2, false);
		SetEnable(hWnd, S_STATIC3, false);
		SetEnable(hWnd, S_STATIC4, false);
		SetEnable(hWnd, S_STATIC5, false);
		SetEnable(hWnd, S_STATIC66, false);
		SetEnable(hWnd, S_STATIC7, false);
		SetEnable(hWnd, S_STATIC11, false);
		SetEnable(hWnd, R_CHECK_CERT, false);
		SetEnable(hWnd, B_TRUST, false);
		SetEnable(hWnd, B_SERVER_CERT, false);
		SetEnable(hWnd, B_VIEW_SERVER_CERT, false);
		SetEnable(hWnd, R_RETRY, false);
		SetEnable(hWnd, S_RETRY_NUM_1, false);
		SetEnable(hWnd, E_RETRY_NUM, false);
		SetEnable(hWnd, S_RETRY_NUM_2, false);
		SetEnable(hWnd, S_RETRY_SPAN_1, false);
		SetEnable(hWnd, E_RETRY_SPAN, false);
		SetEnable(hWnd, S_RETRY_SPAN_2, false);
		SetEnable(hWnd, R_INFINITE, false);
	}

	SetEnable(hWnd, IDOK, ok);
}

// Initialize the account editing dialog
void CmEditAccountDlgInit(HWND hWnd, CM_ACCOUNT *a)
{
	RPC_CLIENT_ENUM_VLAN v;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	if (a->LockMode)
	{
		SetText(hWnd, S_STATIC1, _UU("CM_EASY_ACCOUNT_WARNING"));
	}

	// Connection settings name
	if (a->EditMode || a->NatMode)
	{
		Disable(hWnd, E_ACCOUNT_NAME);
	}

	if (a->NatMode || a->LinkMode)
	{
		Hide(hWnd, R_HIDE);
		Hide(hWnd, R_HIDE2);
	}

	Check(hWnd, R_HIDE, a->ClientOption->HideStatusWindow);
	Check(hWnd, R_HIDE2, a->ClientOption->HideNicInfoWindow);

	if (a->NatMode)
	{
		Hide(hWnd, E_ACCOUNT_NAME);
		Hide(hWnd, S_ACCOUNT_NAME);
	}

	if ((cm != NULL && cm->server_name != NULL) || a->LinkMode)
	{
		Hide(hWnd, B_IE);
	}

	SetText(hWnd, E_ACCOUNT_NAME, a->ClientOption->AccountName);

	// Host name
	SetTextA(hWnd, E_HOSTNAME, a->ClientOption->Hostname);
	StrCpy(a->old_server_name, sizeof(a->old_server_name), a->ClientOption->Hostname);

	if (InStr(a->ClientOption->Hostname, "/tcp"))
	{
		Check(hWnd, R_DISABLE_NATT, true);
	}
	else
	{
		Check(hWnd, R_DISABLE_NATT, false);
	}

	// Port number
	CbSetHeight(hWnd, C_PORT, 18);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_1"), 0);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_2"), 0);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_3"), 0);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_4"), 0);
	SetInt(hWnd, C_PORT, a->ClientOption->Port);

	// Virtual HUB name
	CbSetHeight(hWnd, C_HUBNAME, 18);
	SetTextA(hWnd, C_HUBNAME, a->ClientOption->HubName);

	// Type of proxy
	Check(hWnd, R_DIRECT_TCP, a->ClientOption->ProxyType == PROXY_DIRECT);
	Check(hWnd, R_HTTPS, a->ClientOption->ProxyType == PROXY_HTTP);
	Check(hWnd, R_SOCKS, a->ClientOption->ProxyType == PROXY_SOCKS);
	Check(hWnd, R_SOCKS5, a->ClientOption->ProxyType == PROXY_SOCKS5);

	// Verify the server certificate
	Check(hWnd, R_CHECK_CERT, a->CheckServerCert);

	// LAN card list
	if (a->NatMode == false && a->LinkMode == false)
	{
		Zero(&v, sizeof(v));
		CcEnumVLan(cm->Client, &v);
		LvInit(hWnd, L_VLAN);
		LvInsertColumn(hWnd, L_VLAN, 0, L"DeviceName", 345);
		for (i = 0;i < v.NumItem;i++)
		{
			wchar_t tmp[MAX_SIZE];
			char str[MAX_SIZE];
			CmVLanNameToPrintName(str, sizeof(str), v.Items[i]->DeviceName);
			StrToUni(tmp, sizeof(tmp), str);
			LvInsert(hWnd, L_VLAN, ICO_NIC_ONLINE, NULL, 1, tmp);
		}
//		LvAutoSize(hWnd, L_VLAN);

		if (v.NumItem == 1)
		{
			// If only one virtual LAN card exists, initially select it
			LvSelect(hWnd, L_VLAN, 0);
		}

		CiFreeClientEnumVLan(&v);
	}

	// Select the LAN card
	if (StrLen(a->ClientOption->DeviceName) != 0)
	{
		char str[MAX_SIZE];
		wchar_t tmp[MAX_SIZE];
		UINT index;
		CmVLanNameToPrintName(str, sizeof(str), a->ClientOption->DeviceName);
		StrToUni(tmp, sizeof(tmp), str);
		index = LvSearchStr(hWnd, L_VLAN, 0, tmp);
		if (index != INFINITE)
		{
			LvSelect(hWnd, L_VLAN, index);
		}
	}

	// Authentication type
	CbSetHeight(hWnd, C_TYPE, 18);
	CbAddStr(hWnd, C_TYPE, _UU("PW_TYPE_0"), CLIENT_AUTHTYPE_ANONYMOUS);
	CbAddStr(hWnd, C_TYPE, _UU("PW_TYPE_1"), CLIENT_AUTHTYPE_PASSWORD);
	CbAddStr(hWnd, C_TYPE, _UU("PW_TYPE_2"), CLIENT_AUTHTYPE_PLAIN_PASSWORD);

	if (a->HideClientCertAuth == false)
	{
		// Certificate authentication is not available when HideClientCertAuth is true
		CbAddStr(hWnd, C_TYPE, _UU("PW_TYPE_3"), CLIENT_AUTHTYPE_CERT);
	}

	if (a->HideSecureAuth == false)
	{
		// Authentication using a smart card
		CbAddStr(hWnd, C_TYPE, _UU("PW_TYPE_4"), CLIENT_AUTHTYPE_SECURE);
	}

	// Select an authentication
	CbSelect(hWnd, C_TYPE, a->ClientAuth->AuthType);

	// User name
	SetTextA(hWnd, E_USERNAME, a->ClientAuth->Username);

	// Password
	if (a->EditMode)
	{
		SetTextA(hWnd, E_PASSWORD, HIDDEN_PASSWORD);
	}

	// Reconnection times
	if (a->ClientOption->NumRetry == 0)
	{
		Check(hWnd, R_RETRY, false);
	}
	else
	{
		Check(hWnd, R_RETRY, true);
		if (a->ClientOption->NumRetry == INFINITE)
		{
			Check(hWnd, R_INFINITE, true);
		}
		else
		{
			Check(hWnd, R_INFINITE, false);
			SetInt(hWnd, E_RETRY_NUM, a->ClientOption->NumRetry);
		}
	}
	SetIntEx(hWnd, E_RETRY_SPAN, a->ClientOption->RetryInterval);

	// Title
	if (a->NatMode == false)
	{
		if (a->EditMode == false)
		{
			SetText(hWnd, 0, _UU("CM_ACCOUNT_TITLE_1"));
			FocusEx(hWnd, E_ACCOUNT_NAME);
		}
		else
		{
			SetText(hWnd, 0, _UU("CM_ACCOUNT_TITLE_2"));
			FormatText(hWnd, 0, a->ClientOption->AccountName);
			FocusEx(hWnd, E_HOSTNAME);
		}
	}
	else
	{
		SetText(hWnd, 0, _UU("NM_ACCOUNT_TITLE"));
		FocusEx(hWnd, E_HOSTNAME);
	}

	if (a->LinkMode || a->NatMode)
	{
		Hide(hWnd, L_VLAN);

		if (a->NatMode == false)
		{
			SetText(hWnd, S_VLAN_GROUP, _UU("SM_LINK_POLICY_GROUP"));
			Show(hWnd, S_POLICY_1);
			Show(hWnd, S_POLICY_2);
			Show(hWnd, B_POLICY);
		}
		else
		{
			Hide(hWnd, S_VLAN_GROUP);
			Show(hWnd, S_ROUTER_LOGO);
		}
	}

	// Display update
	a->Inited = true;
	CmEditAccountDlgUpdate(hWnd, a);
}

// Account editing dialog procedure
UINT CmEditAccountDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CM_ACCOUNT *a = (CM_ACCOUNT *)param;
	NMHDR *n;
	X *x;
	K *k;
	char tmp[MAX_PATH];
	bool no_update_natt_check = false;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CmEditAccountDlgInit(hWnd, a);
		if (a->EditMode == false && a->LinkMode == false && a->NatMode == false)
		{
			SetTimer(hWnd, 1, 100, NULL);
		}
		break;
	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			{
				CM_INTERNET_SETTING s;

				KillTimer(hWnd, 1);

				Zero(&s, sizeof(s));
				CmGetSystemInternetSetting(&s);

				if (s.ProxyType != PROXY_DIRECT)
				{
					if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO,
						_UU("CM_WOULDYOULOAD_IE_PROXY"),
						s.ProxyHostName) == IDYES)
					{
						Command(hWnd, B_IE);
					}
				}
			}
			break;
		}
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case R_DISABLE_NATT:
			Zero(tmp, sizeof(tmp));
			GetTxtA(hWnd, E_HOSTNAME, tmp, sizeof(tmp));

			if (IsChecked(hWnd, R_DISABLE_NATT))
			{
				if (InStr(tmp, "/tcp") == false)
				{
					Trim(tmp);

					StrCat(tmp, sizeof(tmp), "/tcp");

					SetTextA(hWnd, E_HOSTNAME, tmp);
				}
			}
			else
			{
				if (InStr(tmp, "/tcp"))
				{
					UINT i = SearchStrEx(tmp, "/tcp", 0, false);

					if (i != INFINITE)
					{
						tmp[i] = 0;

						Trim(tmp);

						SetTextA(hWnd, E_HOSTNAME, tmp);
					}
				}
			}

			CmEditAccountDlgStartEnumHub(hWnd, a);
			break;
		}
		switch (LOWORD(wParam))
		{
		case E_ACCOUNT_NAME:
		case E_HOSTNAME:
		case C_PORT:
		case C_HUBNAME:
		case R_DIRECT_TCP:
		case R_HTTPS:
		case R_SOCKS:
		case R_CHECK_CERT:
		case C_TYPE:
		case E_USERNAME:
		case E_PASSWORD:
		case R_RETRY:
		case E_RETRY_NUM:
		case E_RETRY_SPAN:
		case R_INFINITE:
			CmEditAccountDlgUpdate(hWnd, a);
			break;
		}
		switch (HIWORD(wParam))
		{
		case EN_KILLFOCUS:
			switch (LOWORD(wParam))
			{
			case E_HOSTNAME:
				CmEditAccountDlgStartEnumHub(hWnd, a);
				break;
			}
			break;
		case BN_KILLFOCUS:
			switch (LOWORD(wParam))
			{
			case R_DIRECT_TCP:
			case R_HTTPS:
			case R_SOCKS:
				CmEditAccountDlgStartEnumHub(hWnd, a);
				break;
			}
			break;
		case CBN_KILLFOCUS:
			switch (LOWORD(wParam))
			{
			case C_PORT:
				CmEditAccountDlgStartEnumHub(hWnd, a);
				break;
			}
			break;
		case BN_PUSHED:
			switch (LOWORD(wParam))
			{
			case R_DISABLE_NATT:
				break;
			}
			break;
		}
		if (HIWORD(wParam) == 0)
		{
			CmEditAccountDlgUpdate(hWnd, a);
		}
		switch (wParam)
		{
		case B_POLICY:
			// Policy
			if (a->LinkMode || a->NatMode)
			{
				a->Policy.Access = true;
				a->Policy.MonitorPort = false;
				SmPolicyDlgEx2(hWnd, &a->Policy, _UU("SM_LINK_POLICY_CAPTION"), true, a->PolicyVer);
				a->Policy.Access = true;
				a->Policy.MonitorPort = false;
			}
			break;
		case IDOK:
			CmEditAccountDlgUpdate(hWnd, a);
			CmEditAccountDlgOnOk(hWnd, a);
			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		case B_PROXY_CONFIG:
			// Proxy Settings
			if (CmProxyDlg(hWnd, a->ClientOption))
			{
				UINT n = GetInt(hWnd, C_PORT);
				if (a->ClientOption->ProxyType == PROXY_HTTP &&
					n != 443)
				{
					// Show a warning message if the destination port is
					// other than 443 and HTTP proxy is used
					if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("CM_HTTP_PROXY_WARNING"), n) == IDYES)
					{
						// Change the port number to 443
						SetText(hWnd, C_PORT, _UU("CM_PORT_2"));
					}
				}
				CmEditAccountDlgStartEnumHub(hWnd, a);
				CmEditAccountDlgUpdate(hWnd, a);
			}
			break;
		case B_IE:
			// Use the IE settings
			if(cm->server_name == NULL)
			{
				CmProxyDlgUseForIE(hWnd, a->ClientOption);
				CmEditAccountDlgUpdate(hWnd, a);
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_PROXY_FROM_IE"));
			}
			break;
		case B_TRUST:
			// CA
			if (a->LinkMode == false)
			{
				CmTrustDlg(hWnd);
			}
			else
			{
				SmCaDlg(hWnd, a->Hub);
			}
			break;
		case B_SERVER_CERT:
			// Server certificate registration / delete
			if (a->ServerCert == NULL)
			{
				if (CmLoadXFromFileOrSecureCard(hWnd, &x))
				{
					a->ServerCert = x;
					CmEditAccountDlgUpdate(hWnd, a);
				}
			}
			else
			{
				if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_DELETE_SERVER_CERT")) == IDYES)
				{
					FreeX(a->ServerCert);
					a->ServerCert = NULL;
					CmEditAccountDlgUpdate(hWnd, a);
				}
			}
			break;
		case B_VIEW_SERVER_CERT:
			// Show the server certificate
			if (a->ServerCert != NULL)
			{
				X *issuer = CmGetIssuer(a->ServerCert);
				CertDlg(hWnd, a->ServerCert, issuer, true);
				FreeX(issuer);
			}
			break;
		case B_VIEW_CLIENT_CERT:
			if (a->ClientAuth->AuthType != CLIENT_AUTHTYPE_SECURE)
			{
				// Show the client certificate
				if (a->ClientAuth->ClientX != NULL)
				{
					X *issuer = CmGetIssuer(a->ClientAuth->ClientX);
					CertDlg(hWnd, a->ClientAuth->ClientX, issuer, true);
					FreeX(issuer);
				}
			}
			else
			{
				UINT id;
				// Select the type of smart card
				SmSelectSecureId(hWnd);
				id = SmGetCurrentSecureIdFromReg();
				if (id != 0)
				{
					if (cm->server_name == NULL)
					{
						RPC_USE_SECURE t;

						Zero(&t, sizeof(t));
						t.DeviceId = id;
						CcUseSecure(cm->Client, &t);
					}
				}
				CmEditAccountDlgUpdate(hWnd, a);
			}
			break;
		case B_REGIST_CLIENT_CERT:
			if (a->ClientAuth->AuthType != CLIENT_AUTHTYPE_SECURE)
			{
				// Client certificate registration / deletion
				if (a->ClientAuth->ClientX == NULL)
				{
					if (CmLoadXAndK(hWnd, &x, &k))
					{
						a->ClientAuth->ClientX = x;
						a->ClientAuth->ClientK = k;
						CmEditAccountDlgUpdate(hWnd, a);
					}
				}
				else
				{
					if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_DELETE_CLIENT_CERT")) == IDYES)
					{
						FreeX(a->ClientAuth->ClientX);
						FreeK(a->ClientAuth->ClientK);
						a->ClientAuth->ClientX = NULL;
						a->ClientAuth->ClientK = NULL;
						CmEditAccountDlgUpdate(hWnd, a);
					}
				}
			}
			else
			{
				char cert[MAX_SECURE_DEVICE_FILE_LEN + 1], priv[MAX_SECURE_DEVICE_FILE_LEN + 1];

				// Select a certificate in the smart card
				if (SmSelectKeyPairEx(hWnd, cert, sizeof(cert), priv, sizeof(priv), CmGetSecureBitmapId(a->ClientOption->Hostname)))
				{
					StrCpy(a->ClientAuth->SecurePublicCertName, sizeof(a->ClientAuth->SecurePublicCertName), cert);
					StrCpy(a->ClientAuth->SecurePrivateKeyName, sizeof(a->ClientAuth->SecurePrivateKeyName), priv);
					CmEditAccountDlgUpdate(hWnd, a);
				}
			}
			break;
		case B_DETAIL:
			// Advanced communication settings
			if (CmDetailDlg(hWnd, a))
			{
				CmEditAccountDlgUpdate(hWnd, a);
			}
			break;
		case B_CHANGE_PASSWORD:
			// Change the password
			CmChangePassword(hWnd, a->ClientOption, a->ClientOption->HubName,
				a->ClientAuth->Username);
			break;
		}
		break;
	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_VLAN:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				CmEditAccountDlgUpdate(hWnd, a);
				break;
			}
			break;
		}
		break;
	}

	return 0;
}

// Update the custom proxy HTTP header dialog
void CmProxyHttpHeaderDlgUpdate(HWND hWnd)
{
	UINT i = 0;
	bool ok = true;
	LIST *names_list;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	names_list = NewList(NULL);

	for (; i < LvNum(hWnd, L_VALUES_LIST); i++)
	{
		wchar_t *str = LvGetStr(hWnd, L_VALUES_LIST, i, 0);
		UniTrim(str);
		if (IsEmptyUniStr(str) || IsInListUniStr(names_list, str))
		{
			Free(str);
			ok = false;
			break;
		}

		Add(names_list, str);
	}

	FreeStrList(names_list);
	SetEnable(hWnd, IDOK, ok);
}

// Update the custom proxy HTTP header dialog content
void CmProxyHttpHeaderDlgRefresh(HWND hWnd, CM_PROXY_HTTP_HEADER_DLG *d)
{
	UINT i = 0;
	LIST *list;
	LVB *b;
	CLIENT_OPTION *a;
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	a = (CLIENT_OPTION *)d->ClientOption;

	list = NewEntryList(a->CustomHttpHeader, "\r\n", ":");

	b = LvInsertStart();

	for (; i < LIST_NUM(list); i++)
	{
		INI_ENTRY *e = LIST_DATA(list, i);
		wchar_t *name = CopyStrToUni(e->Key);
		wchar_t *value = CopyStrToUni(e->Value);
		UniTrimLeft(value);

		LvInsertAdd(b, 0, NULL, 2, name, value);

		Free(name);
		Free(value);
	}

	LvInsertEnd(b, hWnd, L_VALUES_LIST);
	FreeEntryList(list);
}

// Initialize the custom proxy HTTP header dialog
void CmProxyHttpHeaderDlgInit(HWND hWnd, CM_PROXY_HTTP_HEADER_DLG *d)
{
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}
	
	LvSetEnhanced(hWnd, L_VALUES_LIST, true);
	LvInitEx(hWnd, L_VALUES_LIST, true);
	LvInsertColumn(hWnd, L_VALUES_LIST, 0, _UU("CM_HTTP_HEADER_COLUMN_0"), 150);
	LvInsertColumn(hWnd, L_VALUES_LIST, 1, _UU("CM_HTTP_HEADER_COLUMN_1"), 150);

	LvSetStyle(hWnd, L_VALUES_LIST, LVS_EX_GRIDLINES);

	CmProxyHttpHeaderDlgRefresh(hWnd, d);
}

// Custom proxy HTTP header dialog control
UINT CmProxyHttpHeaderDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CM_PROXY_HTTP_HEADER_DLG *d = (CM_PROXY_HTTP_HEADER_DLG *)param;
	CLIENT_OPTION *a = (d == NULL ? NULL : d->ClientOption);
	UINT i = INFINITE;
	// Validate arguments
	if (hWnd == NULL || d == NULL || a == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CmProxyHttpHeaderDlgInit(hWnd, d);
		break;
	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	case WM_NOTIFY:
	{
		switch (((LPNMHDR)lParam)->code)
		{
		// Header divider being dragged (resizing columns)
		case HDN_ITEMCHANGINGA:
		case HDN_ITEMCHANGINGW:
			if (d->EditBox != NULL)
			{
				RECT rect;
				ListView_GetSubItemRect(DlgItem(hWnd, L_VALUES_LIST), d->CurrentItem, d->CurrentSubItem, LVIR_LABEL, &rect);
				MoveWindow(d->EditBox, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, true);
				RedrawWindow(d->EditBox, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_UPDATENOW);
			}
			break;
		case LVN_ITEMCHANGED:
			if (((LPNMHDR)lParam)->idFrom == L_VALUES_LIST)
			{
				CmProxyHttpHeaderDlgUpdate(hWnd);
			}
			break;
		case NM_DBLCLK:
		{
			RECT rect;
			LPNMLISTVIEW list_view = (LPNMLISTVIEW)lParam;
			wchar_t *str;

			d->CurrentItem = list_view->iItem;
			d->CurrentSubItem = list_view->iSubItem;
			str = LvGetStr(DlgItem(hWnd, L_VALUES_LIST), 0, d->CurrentItem, d->CurrentSubItem);
			ListView_GetSubItemRect(DlgItem(hWnd, L_VALUES_LIST), d->CurrentItem, d->CurrentSubItem, LVIR_LABEL, &rect);

			d->EditBox = CreateWindowExW(0, L"EDIT", str, WS_BORDER | WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_LEFT | ES_MULTILINE | ES_WANTRETURN, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, DlgItem(hWnd, L_VALUES_LIST), NULL, GetModuleHandle(NULL), NULL);
			Free(str);

			DlgFont(d->EditBox, 0, 8, false);
			EditBoxSetEnhanced(d->EditBox, 0, true);
			FocusEx(d->EditBox, 0);
			break;
		}
		case NM_CLICK:
		case NM_RETURN:
			if (d->EditBox != NULL)
			{
				wchar_t *new_name = GetText(d->EditBox, 0);
				wchar_t *old_name = LvGetStr(hWnd, L_VALUES_LIST, d->CurrentItem, d->CurrentSubItem);

				if (old_name != NULL)
				{
					if (UniStrCmp(new_name, old_name) != 0)
					{
						LvSetItem(hWnd, L_VALUES_LIST, d->CurrentItem, d->CurrentSubItem, new_name);
					}

					Free(old_name);
				}

				Free(new_name);

				DestroyWindow(d->EditBox);
				d->EditBox = NULL;
			}
		}
		break;
	}
	case WM_COMMAND:
		switch (wParam)
		{
		case B_NEW:
			{
				NMLISTVIEW lv;

				if (d->EditBox != NULL)
				{
					DestroyWindow(d->EditBox);
				}

				i = LvInsertItem(hWnd, L_VALUES_LIST, 0, NULL, L"");
				LvSelect(hWnd, L_VALUES_LIST, i);

				Zero(&lv, sizeof(lv));
				lv.hdr.code = NM_DBLCLK;
				lv.iItem = i;
				lv.iSubItem = 0;

				SendMsg(hWnd, 0, WM_NOTIFY, 0, (LPARAM)&lv);
			}
			break;
		case B_DELETE:
			if (d->EditBox != NULL)
			{
				DestroyWindow(d->EditBox);
			}

			i = LvGetSelected(hWnd, L_VALUES_LIST);
			if (i != INFINITE)
			{
				LvDeleteItem(hWnd, L_VALUES_LIST, i);
			}
			CmProxyHttpHeaderDlgUpdate(hWnd);
			break;
		case B_CLEAR:
			if (d->EditBox != NULL)
			{
				DestroyWindow(d->EditBox);
			}

			LvReset(hWnd, L_VALUES_LIST);
			CmProxyHttpHeaderDlgUpdate(hWnd);
			break;
		case IDOK:
		{
			UINT index = 0;
			char *name = NULL;
			char *value = NULL;
			char http_header[HTTP_CUSTOM_HEADER_MAX_SIZE];

			Zero(http_header, sizeof(http_header));
			i = LvNum(hWnd, L_VALUES_LIST);

			for (; index < i; index++)
			{
				char str[HTTP_CUSTOM_HEADER_MAX_SIZE];
				name = LvGetStrA(hWnd, L_VALUES_LIST, index, 0);
				value = LvGetStrA(hWnd, L_VALUES_LIST, index, 1);

				Trim(name);
				TrimLeft(value);

				Format(str, sizeof(str), "%s: %s\r\n", name, value);
				EnSafeHttpHeaderValueStr(str, ' ');

				Free(name);
				Free(value);

				if ((StrLen(http_header) + StrLen(str)) < sizeof(a->CustomHttpHeader))
				{
					StrCat(http_header, sizeof(str), str);
				}
				else
				{
					MsgBox(hWnd, MB_ICONEXCLAMATION | MB_OK, _E(ERR_TOO_MANT_ITEMS));
					return 1;
				}
			}

			Zero(a->CustomHttpHeader, sizeof(a->CustomHttpHeader));
			StrCpy(a->CustomHttpHeader, sizeof(a->CustomHttpHeader), http_header);

			EndDialog(hWnd, true);
			break;
		}
		case IDCANCEL:
			Close(hWnd);
		}
	}

	return 0;
}

// Custom proxy HTTP header dialog
bool CmProxyHttpHeaderDlg(HWND hWnd, CLIENT_OPTION *a)
{
	CM_PROXY_HTTP_HEADER_DLG d;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}

	Zero(&d, sizeof(d));

	d.ClientOption = a;

	return Dialog(hWnd, D_CM_PROXY_HTTP_HEADER, CmProxyHttpHeaderDlgProc, &d);
}

// Update the proxy server settings
void CmProxyDlgUpdate(HWND hWnd, CLIENT_OPTION *a)
{
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	SetEnable(hWnd, B_HTTP_HEADER, a->ProxyType == PROXY_HTTP);

	if (IsEmpty(hWnd, E_HOSTNAME))
	{
		ok = false;
	}
	if (GetInt(hWnd, C_PORT) == 0)
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
}

// Proxy server settings dialog c
UINT CmProxyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CLIENT_OPTION *a = (CLIENT_OPTION *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetTextA(hWnd, E_HOSTNAME, a->ProxyName);
		CbSetHeight(hWnd, C_PORT, 18);
		CbAddStr(hWnd, C_PORT, L"8080", 0);
		CbAddStr(hWnd, C_PORT, L"1080", 0);
		CbAddStr(hWnd, C_PORT, L"80", 0);
		CbAddStr(hWnd, C_PORT, L"3128", 0);
		CbAddStr(hWnd, C_PORT, L"443", 0);
		CbAddStr(hWnd, C_PORT, L"9821", 0);
		CbAddStr(hWnd, C_PORT, L"9801", 0);
		SetIntEx(hWnd, C_PORT, a->ProxyPort);
		SetTextA(hWnd, E_USERNAME, a->ProxyUsername);
		SetTextA(hWnd, E_PASSWORD, a->ProxyPassword);
		if (a->ProxyPort == 0)
		{
			if (a->ProxyType == PROXY_HTTP)
			{
				SetInt(hWnd, C_PORT, 8080);
			}
			else
			{
				SetInt(hWnd, C_PORT, 1080);
			}
		}
		CmProxyDlgUpdate(hWnd, a);
		break;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_HOSTNAME:
		case C_PORT:
		case E_USERNAME:
		case E_PASSWORD:
			CmProxyDlgUpdate(hWnd, a);
			break;
		}

		switch (wParam)
		{
		case B_HTTP_HEADER:
			CmProxyHttpHeaderDlg(hWnd, a);
			break;
		case IDOK:
			GetTxtA(hWnd, E_HOSTNAME, a->ProxyName, sizeof(a->ProxyName));
			GetTxtA(hWnd, E_USERNAME, a->ProxyUsername, sizeof(a->ProxyUsername));
			GetTxtA(hWnd, E_PASSWORD, a->ProxyPassword, sizeof(a->ProxyPassword));
			a->ProxyPort = GetInt(hWnd, C_PORT);
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

// Proxy server settings
bool CmProxyDlg(HWND hWnd, CLIENT_OPTION *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_CM_PROXY, CmProxyDlgProc, a);
}

// Get issuer of the specified certificate if it is known
X *CmGetIssuer(X *x)
{
	RPC_GET_ISSUER a;
	X *ret;
	// Validate arguments
	if (x == NULL)
	{
		return NULL;
	}

	Zero(&a, sizeof(a));
	a.x = CloneX(x);
	if (CALLEX(cm->hMainWnd, CcGetIssuer(cm->Client, &a)) == 0)
	{
		ret = CloneX(a.issuer_x);
	}
	else
	{
		ret = NULL;
	}

	CiFreeGetIssuer(&a);

	return ret;
}

// Initialize the dialog
void CmLoadXFromFileOrSecureCardDlgInit(HWND hWnd, CM_LOADX *p)
{
	UINT current;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	current = MsRegReadInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "CertLoadSource");

	Check(hWnd, R_FROM_FILE, current == 0);
	Check(hWnd, R_FROM_SECURE, current != 0);

	SetFont(hWnd, S_INFO, Font(0, true));

	CmLoadXFromFileOrSecureCardDlgUpdate(hWnd, p);
}

// Update the dialog control
void CmLoadXFromFileOrSecureCardDlgUpdate(HWND hWnd, CM_LOADX *p)
{
	SECURE_DEVICE *dev;
	wchar_t tmp[MAX_SIZE];
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	dev = GetSecureDevice(SmGetCurrentSecureIdFromReg());
	if (dev == NULL)
	{
		UniStrCpy(tmp, sizeof(tmp), _UU("SEC_CURRENT_NO_DEVICE"));
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), _UU("SEC_CURRENT_DEVICE"), dev->DeviceName);
	}

	SetText(hWnd, S_INFO, tmp);

	if (IsChecked(hWnd, R_FROM_SECURE))
	{
		if (dev == NULL)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
	SetEnable(hWnd, B_SELECT, IsChecked(hWnd, R_FROM_SECURE));
	SetEnable(hWnd, S_CERT, IsChecked(hWnd, R_FROM_SECURE));
	SetEnable(hWnd, S_FILE, IsChecked(hWnd, R_FROM_FILE));
}

// Certificate reading selection dialog procedure
UINT CmLoadXFromFileOrSecureCardDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CM_LOADX *p = (CM_LOADX *)param;
	X *x;
	UINT current;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CmLoadXFromFileOrSecureCardDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			current = (IsChecked(hWnd, R_FROM_FILE)) ? 0 : 1;
			MsRegWriteInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "CertLoadSource", current);

			if (current == 0)
			{
				// From file
				if (CmLoadX(hWnd, &x))
				{
					p->x = x;
					EndDialog(hWnd, true);
				}
			}
			else
			{
				// From the smart card
				char name[MAX_SIZE];

				// Select the certificate name in the card
				if (SmSelectKeyPair(hWnd, name, sizeof(name), NULL, 0))
				{
					// Read
					WINUI_SECURE_BATCH batch[] =
					{
						{WINUI_SECURE_READ_CERT, name, true, NULL, NULL, NULL, NULL, NULL, NULL},
					};

					// Do reading
					if (SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), SmGetCurrentSecureIdFromReg(), 0))
					{
						// Success
						p->x = batch[0].OutputX;
						EndDialog(hWnd, true);
					}
				}
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case R_FROM_FILE:
			CmLoadXFromFileOrSecureCardDlgUpdate(hWnd, p);
			break;

		case R_FROM_SECURE:
			CmLoadXFromFileOrSecureCardDlgUpdate(hWnd, p);
			break;

		case B_SELECT:
			SmSelectSecureId(hWnd);
			CmLoadXFromFileOrSecureCardDlgUpdate(hWnd, p);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Read certificate from a file or a smart card
bool CmLoadXFromFileOrSecureCard(HWND hWnd, X **x)
{
	CM_LOADX p;
	// Validate arguments
	if (x == NULL)
	{
		return false;
	}

	Zero(&p, sizeof(p));
	if (Dialog(hWnd, D_CM_LOAD_X, CmLoadXFromFileOrSecureCardDlgProc, &p) == false)
	{
		return false;
	}

	*x = p.x;

	return true;
}

// Read the certificate
bool CmLoadX(HWND hWnd, X **x)
{
	return CmLoadXEx(hWnd, x, NULL, 0);
}
bool CmLoadXEx(HWND hWnd, X **x, char *filename, UINT size)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	bool ret;

	ret = CmLoadXExW(hWnd, x, filename_w, size);

	Free(filename_w);

	return ret;
}
bool CmLoadXExW(HWND hWnd, X **x, wchar_t *filename, UINT size)
{
	wchar_t *s;
	bool is_p12;
	wchar_t tmp[MAX_SIZE];
	K *k;
	// Validate arguments
	if (x == NULL)
	{
		return false;
	}

	// Read the certificate
	s = OpenDlg(hWnd, _UU("DLG_CERT_OR_P12_FILTER"), _UU("DLG_OPEN_CERT"));
	if (s == NULL)
	{
		return false;
	}
	UniStrCpy(tmp, sizeof(tmp), s);
	if (filename != NULL)
	{
		UniStrCpy(filename, size, tmp);
	}
	Free(s);
	if (UniEndWith(tmp, L".p12") || UniEndWith(tmp, L".pfx"))
	{
		is_p12 = true;
	}
	else
	{
		is_p12 = false;
	}

	if (is_p12)
	{
		// Processing of PKCS#12
		BUF *b = ReadDumpW(tmp);
		P12 *p12;
		if (b == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_OPEN_FILE_ERROR_W"), tmp);
			return false;
		}
		p12 = BufToP12(b);
		if (p12 == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_P12_W"), tmp);
			FreeBuf(b);
			return false;
		}
		if (IsEncryptedP12(p12) == false)
		{
			if (ParseP12(p12, x, &k, NULL) == false)
			{
				MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_P12_W"), tmp);
				FreeP12(p12);
				FreeBuf(b);
				return false;
			}
		}
		else
		{
			char password[MAX_SIZE];
			if (PassphraseDlg(hWnd, password, sizeof(password), b, true) == false)
			{
				FreeP12(p12);
				FreeBuf(b);
				return false;
			}
			else
			{
				if (ParseP12(p12, x, &k, password) == false)
				{
					MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_P12_W"), tmp);
					FreeP12(p12);
					FreeBuf(b);
					return false;
				}
			}
		}
		FreeP12(p12);
		FreeBuf(b);
		FreeK(k);
		return true;
	}
	else
	{
		// Processing of X509
		BUF *b = ReadDumpW(tmp);
		X *x509;
		if (b == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_OPEN_FILE_ERROR_W"), tmp);
			return false;
		}

		x509 = BufToX(b, IsBase64(b));
		FreeBuf(b);
		if (x509 == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_X509_W"), tmp);
			return false;
		}

		*x = x509;
		return true;
	}
}

// Read the secret key
bool CmLoadKEx(HWND hWnd, K **k, char *filename, UINT size)
{
	wchar_t *filename_w = CopyStrToUni(filename);
	bool ret;

	ret = CmLoadKExW(hWnd, k, filename_w, size);

	Free(filename_w);

	return ret;
}
bool CmLoadKExW(HWND hWnd, K **k, wchar_t *filename, UINT size)
{
	wchar_t *s;
	bool is_p12;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (k == NULL)
	{
		return false;
	}

	// Read the certificate
	s = OpenDlg(hWnd, _UU("DLG_KEY_OR_P12_FILTER"), _UU("DLG_OPEN_KEY"));
	if (s == NULL)
	{
		return false;
	}
	UniStrCpy(tmp, sizeof(tmp), s);
	Free(s);
	if (filename != NULL)
	{
		UniStrCpy(filename, size, tmp);
	}
	if (UniEndWith(tmp, L".p12") || UniEndWith(tmp, L".pfx"))
	{
		is_p12 = true;
	}
	else
	{
		is_p12 = false;
	}

	if (is_p12)
	{
		// Processing of PKCS#12
		BUF *b = ReadDumpW(tmp);
		P12 *p12;
		if (b == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_OPEN_FILE_ERROR_W"), tmp);
			return false;
		}
		p12 = BufToP12(b);
		if (p12 == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_P12_W"), tmp);
			FreeBuf(b);
			return false;
		}
		if (IsEncryptedP12(p12) == false)
		{
			X *x;
			if (ParseP12(p12, &x, k, NULL) == false)
			{
				MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_P12_W"), tmp);
				FreeP12(p12);
				FreeBuf(b);
				return false;
			}

			FreeX(x);
		}
		else
		{
			char password[MAX_SIZE];
			if (PassphraseDlg(hWnd, password, sizeof(password), b, true) == false)
			{
				FreeP12(p12);
				FreeBuf(b);
				return false;
			}
			else
			{
				X *x;
				if (ParseP12(p12, &x, k, password) == false)
				{
					MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_P12_W"), tmp);
					FreeP12(p12);
					FreeBuf(b);
					return false;
				}

				FreeX(x);
			}
		}
		FreeP12(p12);
		FreeBuf(b);
		return true;
	}
	else
	{
		// Processing of private key
		BUF *b = ReadDumpW(tmp);
		K *key;
		if (b == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_OPEN_FILE_ERROR_W"), tmp);
			return false;
		}

		if (IsEncryptedK(b, true) == false)
		{
			key = BufToK(b, true, IsBase64(b), NULL);
		}
		else
		{
			char pass[MAX_SIZE];
			if (PassphraseDlg(hWnd, pass, sizeof(pass), b, false) == false)
			{
				FreeBuf(b);
				return false;
			}
			key = BufToK(b, true, IsBase64(b), pass);
		}

		if (key == NULL)
		{
			FreeBuf(b);
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_KEY_W"), tmp);
			return false;
		}

		FreeBuf(b);
		*k = key;
		return true;
	}
}

// Read a set of certificate and private key
bool CmLoadXAndK(HWND hWnd, X **x, K **k)
{
	wchar_t *s;
	bool is_p12;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (x == NULL || k == NULL)
	{
		return false;
	}
START_FIRST:

	// Read the certificate
	s = OpenDlg(hWnd, _UU("DLG_CERT_OR_P12_FILTER"), _UU("DLG_OPEN_CERT"));
	if (s == NULL)
	{
		return false;
	}
	UniStrCpy(tmp, sizeof(tmp), s);
	Free(s);
	if (UniEndWith(tmp, L".p12") || UniEndWith(tmp, L".pfx"))
	{
		is_p12 = true;
	}
	else
	{
		is_p12 = false;
	}

	if (is_p12)
	{
		// Processing of PKCS#12
		BUF *b = ReadDumpW(tmp);
		P12 *p12;
		if (b == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_OPEN_FILE_ERROR_W"), tmp);
			return false;
		}
		p12 = BufToP12(b);
		if (p12 == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_P12_W"), tmp);
			FreeBuf(b);
			return false;
		}
		if (IsEncryptedP12(p12) == false)
		{
			if (ParseP12(p12, x, k, NULL) == false)
			{
				MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_P12_W"), tmp);
				FreeP12(p12);
				FreeBuf(b);
				return false;
			}
		}
		else
		{
			char password[MAX_SIZE];
			if (PassphraseDlg(hWnd, password, sizeof(password), b, true) == false)
			{
				FreeP12(p12);
				FreeBuf(b);
				return false;
			}
			else
			{
				if (ParseP12(p12, x, k, password) == false)
				{
					MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_P12_W"), tmp);
					FreeP12(p12);
					FreeBuf(b);
					return false;
				}
			}
		}
		if (CheckXandK(*x, *k) == false)
		{
			FreeX(*x);
			FreeK(*k);
			FreeP12(p12);
			FreeBuf(b);
			if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_RETRYCANCEL, _UU("DLG_BAD_SIGNATURE")) == IDRETRY)
			{
				goto START_FIRST;
			}
			return false;
		}
		FreeP12(p12);
		FreeBuf(b);
		return true;
	}
	else
	{
		// Processing of X509
		BUF *b = ReadDumpW(tmp);
		X *x509;
		K *key;
		if (b == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_OPEN_FILE_ERROR_W"), tmp);
			return false;
		}

		x509 = BufToX(b, IsBase64(b));
		FreeBuf(b);
		if (x509 == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_X509_W"), tmp);
			return false;
		}

		// Read the secret key
		s = OpenDlg(hWnd, _UU("DLG_KEY_FILTER"), _UU("DLG_OPEN_KEY_WITH_CERT"));
		if (s == NULL)
		{
			FreeX(x509);
			return false;
		}
		UniStrCpy(tmp, sizeof(tmp), s);
		Free(s);

		b = ReadDumpW(tmp);
		if (b == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_OPEN_FILE_ERROR_W"), tmp);
			FreeX(x509);
			return false;
		}

		if (IsEncryptedK(b, true) == false)
		{
			key = BufToK(b, true, IsBase64(b), NULL);
		}
		else
		{
			char pass[MAX_SIZE];
			if (PassphraseDlg(hWnd, pass, sizeof(pass), b, false) == false)
			{
				FreeBuf(b);
				FreeX(x509);
				return false;
			}
			key = BufToK(b, true, IsBase64(b), pass);
		}

		if (key == NULL)
		{
			FreeBuf(b);
			FreeX(x509);
			MsgBoxEx(hWnd, MB_ICONSTOP, _UU("DLG_BAD_KEY_W"), tmp);
			return false;
		}

		if (CheckXandK(x509, key) == false)
		{
			FreeBuf(b);
			FreeX(x509);
			FreeK(key);
			if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_RETRYCANCEL, _UU("DLG_BAD_SIGNATURE")) == IDRETRY)
			{
				goto START_FIRST;
			}
			return false;
		}

		FreeBuf(b);
		*x = x509;
		*k = key;
		return true;
	}
}

// Virtual HUB enumeration start
void CmEditAccountDlgStartEnumHub(HWND hWnd, CM_ACCOUNT *a)
{
	char server_name[MAX_HOST_NAME_LEN + 1];
	UINT old_proxy_type;
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}


	if (StrLen(a->ClientOption->Hostname) == 0)
	{
		return;
	}
	if (a->ClientOption->Port == 0)
	{
		return;
	}
	if (a->ClientOption->ProxyType != PROXY_DIRECT &&
		(StrLen(a->ClientOption->ProxyName) == 0 ||
		a->ClientOption->ProxyPort == 0))
	{
		return;
	}

	GetTxtA(hWnd, E_HOSTNAME, server_name, sizeof(server_name));

	if (StrCmpi(server_name, a->old_server_name) == 0)
	{
		if (CbNum(hWnd, C_HUBNAME) != 0)
		{
			return;
		}
	}
	else
	{
		StrCpy(a->old_server_name, sizeof(a->old_server_name), server_name);
		CbReset(hWnd, C_HUBNAME);
	}

	old_proxy_type = a->ClientOption->ProxyType;

	if (IsChecked(hWnd, R_DIRECT_TCP))
	{
		a->ClientOption->ProxyType = PROXY_DIRECT;
	}
	if (IsChecked(hWnd, R_HTTPS))
	{
		a->ClientOption->ProxyType = PROXY_HTTP;
	}
	if (IsChecked(hWnd, R_SOCKS))
	{
		a->ClientOption->ProxyType = PROXY_SOCKS;
	}
	if (IsChecked(hWnd, R_SOCKS5))
	{
		a->ClientOption->ProxyType = PROXY_SOCKS5;
	}

	CmEnumHubStart(hWnd, a->ClientOption);

	a->ClientOption->ProxyType = old_proxy_type;
}

// [OK] button
void CmEditAccountDlgOnOk(HWND hWnd, CM_ACCOUNT *a)
{
	RPC_CLIENT_CREATE_ACCOUNT c;
	bool b;
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}
	if (a->ClientOption->NumRetry != 0 && a->ClientOption->RetryInterval < 5)
	{
		MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_RETRY_INTERVAL_ERROR"));
		FocusEx(hWnd, E_RETRY_SPAN);
		return;
	}

	CmEditAccountDlgUpdate(hWnd, a);

	if (a->LinkMode == false && a->NatMode == false)
	{
		// Save the account
		Zero(&c, sizeof(c));
		c.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		Copy(c.ClientOption, a->ClientOption, sizeof(CLIENT_OPTION));
		c.ClientAuth = CopyClientAuth(a->ClientAuth);
		c.CheckServerCert = a->CheckServerCert;
		if (a->ServerCert != NULL)
		{
			c.ServerCert = CloneX(a->ServerCert);
		}
		c.StartupAccount = a->Startup;

		if (a->EditMode == false)
		{
			b = CALL(hWnd, CcCreateAccount(cm->Client, &c));
		}
		else
		{
			b = CALL(hWnd, CcSetAccount(cm->Client, &c));
		}

		CiFreeClientCreateAccount(&c);

		// Check whether this account is currently running
		if (b)
		{
			RPC_CLIENT_GET_CONNECTION_STATUS st;
			Zero(&st, sizeof(st));
			UniStrCpy(st.AccountName, sizeof(st.AccountName), a->ClientOption->AccountName);
			if (CALL(hWnd, CcGetAccountStatus(cm->Client, &st)))
			{
				if (st.Active)
				{
					MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("CM_CURRENT_ACTIVE"),
						st.AccountName);
				}
			}
		}

		if (b)
		{
			EndDialog(hWnd, true);
		}
	}
	else
	{
		if (a->LinkMode)
		{
			// Link mode
			RPC_CREATE_LINK t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), a->Hub->HubName);
			t.Online = a->OnlineFlag;
			Copy(&t.Policy, &a->Policy, sizeof(POLICY));
			t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
			Copy(t.ClientOption, a->ClientOption, sizeof(CLIENT_OPTION));
			t.ClientAuth = CopyClientAuth(a->ClientAuth);
			t.CheckServerCert = a->CheckServerCert;
			t.ServerCert = CloneX(a->ServerCert);

			// Save the settings for cascade connection
			if (a->EditMode)
			{
				if (CALL(hWnd, ScSetLink(a->Hub->Rpc, &t)))
				{
					if (a->OnlineFlag)
					{
						MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("SM_LINK_SAVE_ONLINE"), a->ClientOption->AccountName);
					}
					EndDialog(hWnd, true);
				}
			}
			else
			{
				if (CALL(hWnd, ScCreateLink(a->Hub->Rpc, &t)))
				{
					if (a->Link_ConnectNow)
					{
						RPC_LINK tt;

						Zero(&tt, sizeof(tt));
						UniStrCpy(tt.AccountName, sizeof(tt.AccountName), a->ClientOption->AccountName);
						StrCpy(tt.HubName, sizeof(tt.HubName), a->Hub->HubName);

						CALL(hWnd, ScSetLinkOnline(a->Hub->Rpc, &tt));
					}
					EndDialog(hWnd, true);
				}
			}

			FreeRpcCreateLink(&t);
		}
		else
		{
			// NAT mode
			RPC_CREATE_LINK t;
			Zero(&t, sizeof(t));

			t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
			Copy(t.ClientOption, a->ClientOption, sizeof(CLIENT_OPTION));
			t.ClientAuth = CopyClientAuth(a->ClientAuth);

			if (CALL(hWnd, NcSetClientConfig(a->Rpc, &t)))
			{
				EndDialog(hWnd, true);
			}

			FreeRpcCreateLink(&t);
		}
	}
}

// Show the account editing dialog
bool CmEditAccountDlg(HWND hWnd, CM_ACCOUNT *a)
{
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_CM_ACCOUNT, CmEditAccountDlgProc, a);
}

// Edit the account
void CmEditAccount(HWND hWnd, wchar_t *account_name)
{
	CM_ACCOUNT *a;
	// Validate arguments
	if (hWnd == NULL || account_name == NULL)
	{
		return;
	}

	a = CmGetExistAccountObject(hWnd, account_name);
	if (a == NULL)
	{
		return;
	}

	CmVoice("input_config");
	if (CmEditAccountDlg(hWnd, a))
	{
		CmVoice("set_config");
	}

	CmFreeAccountObject(hWnd, a);
}

// Create an account
void CmNewAccount(HWND hWnd)
{
	CM_ACCOUNT *a;
	RPC_CLIENT_ENUM_VLAN t;
	UINT num_vlan = 0;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (IsEnable(hWnd, 0) == false)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CcEnumVLan(cm->Client, &t) == ERR_NO_ERROR)
	{
		num_vlan = t.NumItem;

		CiFreeClientEnumVLan(&t);
	}

	if (num_vlan == 0)
	{
		if (MsgBox(hWnd, MB_ICONINFORMATION | MB_YESNO, _UU("CM_NO_VLAN")) == IDNO)
		{
			return;
		}
		else
		{
			if (cm->server_name == NULL || cm->Client->Unix)
			{
				Command(hWnd, CMD_NEW_VLAN);
				return;
			}
			else
			{
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_VLAN_REMOTE_ERROR"));
			}
			return;
		}
	}

	a = CmCreateNewAccountObject(hWnd);
	if (a == NULL)
	{
		return;
	}

	CmVoice("input_config");
	if (CmEditAccountDlg(hWnd, a))
	{
		CmVoice("new_config");
	}

	CmFreeAccountObject(hWnd, a);
}

// Release the account object
void CmFreeAccountObject(HWND hWnd, CM_ACCOUNT *a)
{
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	Free(a->ClientOption);
	CiFreeClientAuth(a->ClientAuth);
	if (a->ServerCert != NULL)
	{
		FreeX(a->ServerCert);
	}
	Free(a);
}

// Get an existing account object
CM_ACCOUNT *CmGetExistAccountObject(HWND hWnd, wchar_t *account_name)
{
	RPC_CLIENT_GET_ACCOUNT c;
	CM_ACCOUNT *a;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	Zero(&c, sizeof(c));
	UniStrCpy(c.AccountName, sizeof(c.AccountName), account_name);
	if (CALL(hWnd, CcGetAccount(cm->Client, &c)) == false)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(CM_ACCOUNT));
	a->EditMode = true;
	a->CheckServerCert = c.CheckServerCert;
	a->RetryOnServerCert = c.RetryOnServerCert;
	a->Startup = c.StartupAccount;
	if (c.ServerCert != NULL)
	{
		a->ServerCert = CloneX(c.ServerCert);
	}
	a->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	Copy(a->ClientOption, c.ClientOption, sizeof(CLIENT_OPTION));
	a->ClientAuth = CopyClientAuth(c.ClientAuth);
	Copy(a->ShortcutKey, c.ShortcutKey, SHA1_SIZE);
	CiFreeClientGetAccount(&c);

	a->LockMode = cm->CmSetting.LockMode;

	return a;
}

// Create a new account object
CM_ACCOUNT *CmCreateNewAccountObject(HWND hWnd)
{
	CM_ACCOUNT *a;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(CM_ACCOUNT));
	a->EditMode = false;
	a->CheckServerCert = false;
	a->RetryOnServerCert = false;
	a->Startup = false;
	a->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));

	// Initialize the client options
	CmGenerateNewAccountName(hWnd, a->ClientOption->AccountName, sizeof(a->ClientOption->AccountName));
	a->ClientOption->Port = 443;	// Default port number
	a->ClientOption->NumRetry = INFINITE;
	a->ClientOption->RetryInterval = 15;
	a->ClientOption->MaxConnection = 1;
	a->ClientOption->HalfConnection = false;
	a->ClientOption->UseEncrypt = true;
	a->ClientOption->AdditionalConnectionInterval = 1;

	if (cm->Client->Unix)
	{
		a->ClientOption->NoRoutingTracking = true;
	}

	a->ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));

	// Password authentication
	a->ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;

	return a;
}

// Create an imported account name
void CmGenerateImportName(HWND hWnd, wchar_t *name, UINT size, wchar_t *old_name)
{
	UINT i;
	// Validate arguments
	if (name == NULL || hWnd == NULL)
	{
		return;
	}

	for (i = 1;;i++)
	{
		wchar_t tmp[MAX_SIZE];
		if (i == 1)
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_IMPORT_NAME_1"), old_name);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_IMPORT_NAME_2"), old_name, i);
		}

		if (LvSearchStr(hWnd, L_ACCOUNT, 0, tmp) == INFINITE)
		{
			UniStrCpy(name, size, tmp);
			return;
		}
	}
}

// Create a copy name
void CmGenerateCopyName(HWND hWnd, wchar_t *name, UINT size, wchar_t *old_name)
{
	UINT i;
	// Validate arguments
	if (name == NULL || hWnd == NULL)
	{
		return;
	}

	for (i = 1;;i++)
	{
		wchar_t tmp[MAX_SIZE];
		if (i == 1)
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_COPY_NAME_1"), old_name);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_COPY_NAME_2"), i, old_name);
		}

		if (LvSearchStr(hWnd, L_ACCOUNT, 0, tmp) == INFINITE)
		{
			UniStrCpy(name, size, tmp);
			return;
		}
	}
}

// Create a new account name
void CmGenerateNewAccountName(HWND hWnd, wchar_t *name, UINT size)
{
	UINT i;
	// Validate arguments
	if (name == NULL || hWnd == NULL)
	{
		return;
	}

	for (i = 1;;i++)
	{
		wchar_t tmp[MAX_SIZE];
		if (i == 1)
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_NEW_ACCOUNT_NAME_1"));
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_NEW_ACCOUNT_NAME_2"), i);
		}

		if (LvSearchStr(hWnd, L_ACCOUNT, 0, tmp) == INFINITE)
		{
			UniStrCpy(name, size, tmp);
			return;
		}
	}
}

// Show the policy list
void CmPolicyDlgPrint(HWND hWnd, CM_POLICY *p)
{
	CmPolicyDlgPrintEx(hWnd, p, false);
}
void CmPolicyDlgPrintEx(HWND hWnd, CM_POLICY *p, bool cascade_mode)
{
	CmPolicyDlgPrintEx2(hWnd, p, cascade_mode, POLICY_CURRENT_VERSION);
}
void CmPolicyDlgPrintEx2(HWND hWnd, CM_POLICY *p, bool cascade_mode, UINT ver)
{
	POLICY *pol;
	UINT i;
	LVB *b;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	pol = p->Policy;

	b = LvInsertStart();

	for (i = 0;i < NUM_POLICY_ITEM;i++)
	{
		wchar_t tmp[MAX_SIZE];

		if (cascade_mode)
		{
			if (PolicyIsSupportedForCascade(i) == false)
			{
				continue;
			}
		}

		if (IS_POLICY_FOR_CURRENT_VER(i, ver))
		{
			if (policy_item[i].TypeInt == false)
			{
				// bool type
				UniStrCpy(tmp, sizeof(tmp), POLICY_BOOL(pol, i) ? _UU("POL_BOOL_ENABLE") : (p->Extension ? _UU("POL_BOOL_DISABLE_EX") : _UU("POL_BOOL_DISABLE")));
			}
			else
			{
				// int type
				if (policy_item[i].AllowZero && POLICY_INT(pol, i) == 0)
				{
					UniStrCpy(tmp, sizeof(tmp), _UU("POL_INT_ZERO"));
				}
				else
				{
					UniFormat(tmp, sizeof(tmp), _UU(policy_item[i].FormatStr), POLICY_INT(pol, i));
				}
			}

			LvInsertAdd(b, ICO_MACHINE, (void *)i, 2, GetPolicyTitle(i), tmp);
		}
	}

	LvInsertEnd(b, hWnd, L_POLICY);
}

// Policy list dialog box
UINT CmPolicyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CM_POLICY *p = (CM_POLICY *)param;
	NMHDR *n;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, 0, p->AccountName);
		FormatText(hWnd, S_TITLE, p->AccountName);
		p->hWnd = hWnd;
		if (p->CmStatus != NULL)
		{
			p->CmStatus->hWndPolicy = hWnd;
		}

		// Initialize the column
		LvInit(hWnd, L_POLICY);
		LvInsertColumn(hWnd, L_POLICY, 0, _UU("POL_TITLE_STR"), 375);
		LvInsertColumn(hWnd, L_POLICY, 1, _UU("POL_VALUE_STR"), 100);

		// Display
		CmPolicyDlgPrint(hWnd, p);

		// Select the first
		LvSelect(hWnd, L_POLICY, 0);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_POLICY:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				// Change selection
				if (LvIsSelected(hWnd, L_POLICY) == false)
				{
					SetText(hWnd, S_DESCRIPTION, L"");
				}
				else
				{
					UINT index = LvGetSelected(hWnd, L_POLICY);
					UINT id = (UINT)LvGetParam(hWnd, L_POLICY, index);
					if (id < NUM_POLICY_ITEM)
					{
						SetText(hWnd, S_DESCRIPTION, GetPolicyDescription(id));
					}
				}
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	LvSortHander(hWnd, msg, wParam, lParam, L_POLICY);

	return 0;
}

// Show the policy list dialog
void CmPolicyDlg(HWND hWnd, CM_STATUS *st)
{
	RPC_CLIENT_GET_CONNECTION_STATUS s;
	POLICY *policy;
	CM_POLICY cp;
	// Validate arguments
	if (hWnd == NULL || st == NULL)
	{
		return;
	}

	// Get the policy
	Zero(&s, sizeof(s));
	UniStrCpy(s.AccountName, sizeof(s.AccountName), st->AccountName);
	if (CALL(hWnd, CcGetAccountStatus(cm->Client, &s)) == false)
	{
		return;
	}
	if (s.Active == false)
	{
		return;
	}

	policy = &s.Policy;

	Zero(&cp, sizeof(cp));
	UniStrCpy(cp.AccountName, sizeof(cp.AccountName), st->AccountName);
	cp.Policy = policy;
	cp.CmStatus = st;

	Dialog(hWnd, D_CM_POLICY, CmPolicyDlgProc, &cp);

	st->hWndPolicy = NULL;

	CiFreeClientGetConnectionStatus(&s);
}

// Show the certificate
void CmStatusDlgPrintCert(HWND hWnd, CM_STATUS *st, bool server)
{
	RPC_CLIENT_GET_CONNECTION_STATUS s;
	X *x, *issuer;
	// Validate arguments
	if (hWnd == NULL || st == NULL)
	{
		return;
	}

	// Get the latest information
	Zero(&s, sizeof(s));
	UniStrCpy(s.AccountName, sizeof(s.AccountName), st->AccountName);
	if (CALL(hWnd, CcGetAccountStatus(cm->Client, &s)) == false)
	{
		Close(hWnd);
		return;
	}

	if (s.Active == false)
	{
		// Disconnect
		Close(hWnd);
		return;
	}

	if (server == false)
	{
		// Show the client certificate
		x = s.ClientX;
	}
	else
	{
		// Show the server certificate
		x = s.ServerX;
	}

	cm->WindowCount++;
	issuer = CmGetIssuer(x);
	CertDlg(hWnd, x, issuer, true);
	FreeX(issuer);
	cm->WindowCount--;

	CiFreeClientGetConnectionStatus(&s);
}

// Show the information of the status dialog
void CmStatusDlgPrint(HWND hWnd, CM_STATUS *cmst)
{
	RPC_CLIENT_GET_CONNECTION_STATUS s;
	LVB *b;
	// Validate arguments
	if (hWnd == NULL || cmst == NULL)
	{
		return;
	}

	// Get the latest information
	Zero(&s, sizeof(s));
	UniStrCpy(s.AccountName, sizeof(s.AccountName), cmst->AccountName);
	if (CALL(hWnd, CcGetAccountStatus(cm->Client, &s)) == false)
	{
		Close(hWnd);
		return;
	}

	if (s.Active == false)
	{
		// Disconnect
		Close(hWnd);
		return;
	}

	// Show the status in the list box in the status dialog
	b = LvInsertStart();
	CmPrintStatusToListView(b, &s);
	LvInsertEnd(b, hWnd, L_STATUS);

	LvAutoSize(hWnd, L_STATUS);

	SetEnable(hWnd, B_POLICY, s.Connected);

	SetEnable(hWnd, B_SERVER_CERT, s.ServerX != NULL);
	SetEnable(hWnd, B_CLIENT_CERT, s.ClientX != NULL);

	CiFreeClientGetConnectionStatus(&s);
}

// Show the status in the list box in the status dialog
void CmPrintStatusToListView(LVB *b, RPC_CLIENT_GET_CONNECTION_STATUS *s)
{
	CmPrintStatusToListViewEx(b, s, false);
}
void CmPrintStatusToListViewEx(LVB *b, RPC_CLIENT_GET_CONNECTION_STATUS *s, bool server_mode)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	char vv[128];
	// Validate arguments
	if (b == NULL || s == NULL)
	{
		return;
	}

	if (server_mode == false)
	{
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_ACCOUNT_NAME"), s->AccountName);

		if (s->Connected == false)
		{
			wchar_t *st = _UU("CM_ST_CONNECTED_FALSE");
			switch (s->SessionStatus)
			{
			case CLIENT_STATUS_CONNECTING:
				st = _UU("CM_ST_CONNECTING");
				break;
			case CLIENT_STATUS_NEGOTIATION:
				st = _UU("CM_ST_NEGOTIATION");
				break;
			case CLIENT_STATUS_AUTH:
				st = _UU("CM_ST_AUTH");
				break;
			case CLIENT_STATUS_ESTABLISHED:
				st = _UU("CM_ST_ESTABLISHED");
				break;
			case CLIENT_STATUS_RETRY:
				st = _UU("CM_ST_RETRY");
				break;
			case CLIENT_STATUS_IDLE:
				st = _UU("CM_ST_IDLE");
				break;
			}
			LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_CONNECTED"), st);
		}
		else
		{
			LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_CONNECTED"), _UU("CM_ST_CONNECTED_TRUE"));
		}
	}

	if (s->Connected)
	{
		if (s->VLanId == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_NO_VLAN"));
		}
		else
		{
			UniToStru(tmp, s->VLanId);
		}

		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_VLAN_ID"), tmp);

		if (server_mode == false)
		{
			StrToUni(tmp, sizeof(tmp), s->ServerName);
			LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SERVER_NAME"), tmp);

			UniFormat(tmp, sizeof(tmp), _UU("CM_ST_PORT_TCP"), s->ServerPort);
			LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SERVER_PORT"), tmp);
		}

		StrToUni(tmp, sizeof(tmp), s->ServerProductName);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SERVER_P_NAME"), tmp);

		UniFormat(tmp, sizeof(tmp), L"%u.%02u", s->ServerProductVer / 100, s->ServerProductVer % 100);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SERVER_P_VER"), tmp);
		UniFormat(tmp, sizeof(tmp), L"Build %u", s->ServerProductBuild);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SERVER_P_BUILD"), tmp);
	}

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->StartTime), NULL);
	LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_START_TIME"), tmp);
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->FirstConnectionEstablisiedTime), NULL);
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_FIRST_ESTAB_TIME"), s->FirstConnectionEstablisiedTime == 0 ? _UU("CM_ST_NONE") : tmp);

	if (s->Connected)
	{
		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->CurrentConnectionEstablishTime), NULL);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_CURR_ESTAB_TIME"), tmp);
	}

	if (server_mode == false)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_STR"), s->NumConnectionsEstablished);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_NUM_ESTABLISHED"), tmp);
	}

	if (s->Connected)
	{
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_HALF_CONNECTION"), s->HalfConnection ? _UU("CM_ST_HALF_TRUE") : _UU("CM_ST_HALF_FALSE"));

		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_QOS"), s->QoS ? _UU("CM_ST_QOS_TRUE") : _UU("CM_ST_QOS_FALSE"));

		UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnections);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_NUM_TCP"), tmp);

		if (s->HalfConnection)
		{
			UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnectionsUpload);
			LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_NUM_TCP_UPLOAD"), tmp);
			UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnectionsDownload);
			LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_NUM_TCP_DOWNLOAD"), tmp);
		}

		UniFormat(tmp, sizeof(tmp), L"%u", s->MaxTcpConnections);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_MAX_TCP"), tmp);

		if (s->UseEncrypt == false)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_FALSE"));
		}
		else
		{
			if (StrLen(s->CipherName) != 0)
			{
				UniFormat(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_TRUE"), s->CipherName);
			}
			else
			{
				UniFormat(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_TRUE2"));
			}
		}
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_USE_ENCRYPT"), tmp);

		if (s->UseCompress)
		{
			UINT percent = 0;
			if ((s->TotalRecvSize + s->TotalSendSize) > 0)
			{
				percent = (UINT)((UINT64)100 - (UINT64)(s->TotalRecvSizeReal + s->TotalSendSizeReal) * (UINT64)100 /
					(s->TotalRecvSize + s->TotalSendSize));
				percent = MAKESURE(percent, 0, 100);
			}

			UniFormat(tmp, sizeof(tmp), _UU("CM_ST_COMPRESS_TRUE"), percent);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_COMPRESS_FALSE"));
		}
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_USE_COMPRESS"), tmp);

		if (IsEmptyStr(s->UnderlayProtocol) == false)
		{
			StrToUni(tmp, sizeof(tmp), s->UnderlayProtocol);
			LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_UNDERLAY_PROTOCOL"), tmp);
		}

		if (IsEmptyStr(s->ProtocolDetails) == false)
		{
			StrToUni(tmp, sizeof(tmp), s->ProtocolDetails);
			LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_PROTOCOL_DETAILS"), tmp);
		}

		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_UDP_ACCEL_ENABLED"), (s->IsUdpAccelerationEnabled ? _UU("CM_ST_YES") : _UU("CM_ST_NO")));
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_UDP_ACCEL_USING"), (s->IsUsingUdpAcceleration ? _UU("CM_ST_YES") : _UU("CM_ST_NO")));

		StrToUni(tmp, sizeof(tmp), s->SessionName);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SESSION_NAME"), tmp);

		StrToUni(tmp, sizeof(tmp), s->ConnectionName);
		if (UniStrCmpi(tmp, L"INITING") != 0)
		{
			LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_CONNECTION_NAME"), tmp);
		}

		BinToStr(str, sizeof(str), s->SessionKey, sizeof(s->SessionKey));
		StrToUni(tmp, sizeof(tmp), str);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SESSION_KEY"), tmp);

		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_BRIDGE_MODE"), s->IsBridgeMode ? _UU("CM_ST_YES") : _UU("CM_ST_NO"));

		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_MONITOR_MODE"), s->IsMonitorMode ? _UU("CM_ST_YES") : _UU("CM_ST_NO"));

		ToStr3(vv, sizeof(vv), s->TotalSendSize);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SEND_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->TotalRecvSize);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_RECV_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.UnicastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SEND_UCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.UnicastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SEND_UCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.BroadcastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SEND_BCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.BroadcastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_SEND_BCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.UnicastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_RECV_UCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.UnicastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_RECV_UCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.BroadcastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_RECV_BCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.BroadcastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		LvInsertAdd(b, 0, NULL, 2, _UU("CM_ST_RECV_BCAST_SIZE"), tmp);
	}
}

// Status dialog procedure
UINT CmStatusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	wchar_t tmp[MAX_SIZE];
	CM_STATUS *s = (CM_STATUS *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_TOWER);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_TITLE"), s->AccountName);
		SetText(hWnd, 0, tmp);
		FormatText(hWnd, S_TITLE, s->AccountName);
		DlgFont(hWnd, S_TITLE, 0, 1);

		Add(cm->StatusWindowList, hWnd);

		SetTimer(hWnd, 1, 500, NULL);

		LvInitEx(hWnd, L_STATUS, true);
		ListView_SetImageList(DlgItem(hWnd, L_STATUS), NULL, LVSIL_NORMAL);
		ListView_SetImageList(DlgItem(hWnd, L_STATUS), NULL, LVSIL_SMALL);
		LvInsertColumn(hWnd, L_STATUS, 0, _UU("CM_ST_COLUMN_1"), 160);
		LvInsertColumn(hWnd, L_STATUS, 1, _UU("CM_ST_COLUMN_2"), 270);

		CmStatusDlgPrint(hWnd, s);

		break;
	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			CmStatusDlgPrint(hWnd, s);
			SetTimer(hWnd, 1, 500, NULL);
			break;
		}
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			// Close
			Close(hWnd);
			break;
		case B_POLICY:
			// Show the policy
			CmPolicyDlg(hWnd, s);
			break;
		case B_SERVER_CERT:
			CmStatusDlgPrintCert(hWnd, s, true);
			break;
		case B_CLIENT_CERT:
			CmStatusDlgPrintCert(hWnd, s, false);
			break;
		}
		break;
	case WM_CLOSE:
		Delete(cm->StatusWindowList, hWnd);
		if (s->hWndPolicy != NULL)
		{
			EndDialog(s->hWndPolicy, false);
			s->hWndPolicy = NULL;
		}
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Show the status dialog
void CmStatusDlg(HWND hWnd, wchar_t *account_name)
{
	CM_STATUS *s;
	// Validate arguments
	if (hWnd == NULL || account_name == NULL)
	{
		return;
	}

	s = ZeroMalloc(sizeof(CM_STATUS));
	UniStrCpy(s->AccountName, sizeof(s->AccountName), account_name);

	Dialog(hWnd, D_CONNECTION_STATUS, CmStatusDlgProc, s);

	Free(s);
}

// Show the status
void CmStatus(HWND hWnd, wchar_t *account_name)
{
	UINT i;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || account_name == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), _UU("CM_ST_TITLE"), account_name);

	for (i = 0;i < LIST_NUM(cm->StatusWindowList);i++)
	{
		HWND h = LIST_DATA(cm->StatusWindowList, i);
		if (h != NULL)
		{
			wchar_t tmp2[MAX_SIZE];
			if (GetTxt(h, 0, tmp2, sizeof(tmp2)))
			{
				if (UniStrCmpi(tmp2, tmp) == 0)
				{
					SetActiveWindow(h);
					return;
				}
			}
		}
	}

	CmStatusDlg(hWnd, account_name);
}

// Delete
void CmDeleteAccount(HWND hWnd, wchar_t *account_name)
{
	RPC_CLIENT_DELETE_ACCOUNT c;
	// Validate arguments
	if (hWnd == NULL || account_name == NULL)
	{
		return;
	}
	Zero(&c, sizeof(c));
	UniStrCpy(c.AccountName, sizeof(c.AccountName), account_name);

	CmVoice("delete_config_1");
	if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_DELETE_ACCOUNT_MSG"), account_name)
		== IDNO)
	{
		return;
	}

	CALL(hWnd, CcDeleteAccount(cm->Client, &c));
	CmVoice("delete_config_2");
}

// Disconnect
void CmDisconnect(HWND hWnd, wchar_t *account_name)
{
	RPC_CLIENT_CONNECT c;
	// Validate arguments
	if (hWnd == NULL || account_name == NULL)
	{
		return;
	}

	Zero(&c, sizeof(c));
	UniStrCpy(c.AccountName, sizeof(c.AccountName), account_name);

	cm->PositiveDisconnectFlag = true;

	CALL(hWnd, CcDisconnect(cm->Client, &c));
}

// Show the promotional window
void SmShowPublicVpnServerHtml(HWND hWnd)
{
	char *langstr = _SS("LANGSTR");

	if(StrCmpi(langstr, "Japanese") == 0)
	{
		ShowHtml(hWnd, PUBLIC_SERVER_HTML, PUBLIC_SERVER_TAG);
	}
	else
	{
		ShowHtml(hWnd, PUBLIC_SERVER_HTML_EN, PUBLIC_SERVER_TAG);
	}
}

// Connection
void CmConnect(HWND hWnd, wchar_t *account_name)
{
	RPC_CLIENT_CONNECT c;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || account_name == NULL)
	{
		return;
	}

	if (IsEnable(hWnd, 0) == false)
	{
		return;
	}

	if (hWnd == cm->hMainWnd)
	{
		if (LvNum(hWnd, L_VLAN) == 0 && cm->Client->Win9x)
		{
			if (MsgBox(hWnd, MB_ICONINFORMATION | MB_YESNO, _UU("CM_NO_VLAN_2")) == IDNO)
			{
				return;
			}
			else
			{
				if (cm->server_name == NULL || cm->Client->Unix)
				{
					Command(hWnd, CMD_NEW_VLAN);
					return;
				}
				else
				{
					MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_VLAN_REMOTE_ERROR"));
				}
				return;
			}
		}
	}

	// (If necessary) display a warning
	if (CmWarningDesktop(hWnd, account_name) == false)
	{
		return;
	}

	if (cm->server_name == NULL)
	{
		if (cm->BadProcessChecked == false)
		{
			cm->BadProcessChecked = true;

			CheckBadProcesses(hWnd);
		}
	}

	if (cm->server_name == NULL)
	{
		// Check the Windows version
		RPC_WINVER winver;
		wchar_t winver_msg_client[3800];

		GetWinVer(&winver);
		Zero(winver_msg_client, sizeof(winver_msg_client));

		if (IsSupportedWinVer(&winver) == false)
		{
			SYSTEMTIME st;

			LocalTime(&st);

			UniFormat(winver_msg_client, sizeof(winver_msg_client), _UU("WINVER_ERROR_FORMAT"),
				_UU("WINVER_ERROR_PC_LOCAL"),
				winver.Title,
				_UU("WINVER_ERROR_VPNCLIENT"),
				SUPPORTED_WINDOWS_LIST,
				_UU("WINVER_ERROR_PC_LOCAL"),
				_UU("WINVER_ERROR_VPNCLIENT"),
				_UU("WINVER_ERROR_VPNCLIENT"),
				_UU("WINVER_ERROR_VPNCLIENT"),
				st.wYear, st.wMonth);
		}

		if (UniIsEmptyStr(winver_msg_client) == false)
		{
			OnceMsgEx(hWnd, _UU("WINVER_TITLE"), winver_msg_client,
				true, ICO_WARNING, NULL);
		}
	}

	i = LvSearchStr(hWnd, L_ACCOUNT, 0, account_name);
	if (i != INFINITE)
	{
		wchar_t *tmp = LvGetStr(hWnd, L_ACCOUNT, i, 2);
		if (tmp != NULL)
		{
			wchar_t tag[MAX_SIZE];
			StrToUni(tag, sizeof(tag), PUBLIC_SERVER_NAME);

			if (UniSearchStrEx(tmp, tag, 0, false) != INFINITE)
			{
				SmShowPublicVpnServerHtml(hWnd);
			}

			Free(tmp);
		}
	}

	if (cm->CheckedAndShowedAdminPackMessage == false)
	{
		cm->CheckedAndShowedAdminPackMessage = true;
		//CmCheckAndShowAdminPackTrialVersionNoticeMessage(NULL);
	}

	Zero(&c, sizeof(c));
	UniStrCpy(c.AccountName, sizeof(c.AccountName), account_name);

	CmSetForegroundProcessToCnService();

	if (CALL(hWnd, CcConnect(cm->Client, &c)))
	{
		cm->ConnectStartedFlag = true;
	}
}

// Determine whether to bold the specified menu item
bool CmIsBold(UINT id)
{
	return false;
}

// Determine whether to enable the specified menu item
bool CmIsEnabled(HWND hWnd, UINT id)
{
	UINT index;
	wchar_t *name;
	bool locked = false;
	// Validate arguments
	if (hWnd == NULL)
	{
		return false;
	}

	locked = cm->CmSetting.LockMode;

	if (locked)
	{
		switch (id)
		{
		case CMD_NEW:
		case CMD_CLONE:
		case CMD_IMPORT_ACCOUNT:
		case CMD_DELETE:
		case CMD_OPTION:
		case CMD_VOIDE_NONE:
		case CMD_VOICE_NORMAL:
		case CMD_VOICE_ODD:
		case CMD_STARTUP:
		case CMD_NOSTARTUP:
		case CMD_TRAFFIC:
		case CMD_MMCSS:
			return false;
		case CMD_NEW_VLAN:
		case CMD_ENABLE_VLAN:
		case CMD_DISABLE_VLAN:
		case CMD_DELETE_VLAN:
		case CMD_REINSTALL:
		case CMD_WINNET:
			if (cm->CmEasyModeSupported)
			{
				return false;
			}
		}
	}

	switch (id)
	{
	case CMD_LANGUAGE:
		return MsIsNt();
	case CMD_SHOWPORT:
	case CMD_GRID:
		if (cm->IconView)
		{
			return false;
		}
		return true;
	case CMD_MMCSS:
		if (MsIsVista() == false || IsEmptyStr(cm->server_name) == false)
		{
			return false;
		}
		if (OS_IS_SERVER(GetOsType()))
		{
			return false;
		}
		return true;
	case CMD_TRAYICON:
	case CMD_TRAFFIC:
		return (cm->server_name == NULL);
	case CMD_NETIF:
		if (MsIsNt() == false)
		{
			return false;
		}
		return (cm->server_name == NULL);
	case CMD_CM_SETTING:
		return cm->CmSettingSupported;
	case CMD_CONNECT:
	case CMD_DISCONNECT:
	case CMD_STATUS:
	case CMD_RENAME:
	case CMD_DELETE:
		if (LvIsMultiMasked(hWnd, L_ACCOUNT))
		{
			return false;
		}
		if (LvIsSelected(hWnd, L_ACCOUNT) == false)
		{
			return false;
		}
		else
		{
			// Determine whether the selected account is under connecting
			UINT i = LvGetSelected(hWnd, L_ACCOUNT);
			wchar_t *str = LvGetStr(hWnd, L_ACCOUNT, i, 1);
			wchar_t *name = LvGetStr(hWnd, L_ACCOUNT, i, 0);
			bool is_connected = false;
			if (str != NULL)
			{
				if (UniStrCmpi(str, _UU("CM_ACCOUNT_ONLINE")) == 0 || UniStrCmpi(str, _UU("CM_ACCOUNT_CONNECTING")) == 0)
				{
					is_connected = true;
				}
				Free(str);
			}
			if (name != NULL)
			{
				if (UniStrCmpi(name, _UU("CM_NEW_ICON")) == 0 || UniStrCmpi(name, _UU("CM_VGC_ICON")) == 0 || UniStrCmpi(name, _UU("CM_VGC_LINK")) == 0)
				{
					Free(name);
					return false;
				}
				Free(name);
			}
			if (id == CMD_CONNECT || id == CMD_RENAME || id == CMD_DELETE)
			{
				return !is_connected;
			}
			else
			{
				return is_connected;
			}
		}
		break;
	case CMD_DISCONNECT_ALL:
		if (CmGetNumConnected(hWnd) == 0)
		{
			return false;
		}
		else
		{
			return true;
		}
	case CMD_SHORTCUT:
		// Create a shortcut
		if (cm->Client->Rpc->Sock->RemoteIP.addr[0] != 127)
		{
			return false;
		}
	case CMD_EXPORT_ACCOUNT:
		if (LvIsMultiMasked(hWnd, L_ACCOUNT))
		{
			return false;
		}
		name = LvGetSelectedStr(hWnd, L_ACCOUNT, 0);
		if (name != NULL)
		{
			if (UniStrCmpi(name, _UU("CM_NEW_ICON")) == 0 || UniStrCmpi(name, _UU("CM_VGC_ICON")) == 0 || UniStrCmpi(name, _UU("CM_VGC_LINK")) == 0
				)
			{
				Free(name);
				return false;
			}
			Free(name);
		}
		return LvIsSelected(hWnd, L_ACCOUNT);
	case CMD_CLONE:
		if (LvIsMultiMasked(hWnd, L_ACCOUNT))
		{
			return false;
		}
		name = LvGetSelectedStr(hWnd, L_ACCOUNT, 0);
		if (name != NULL)
		{
			if (UniStrCmpi(name, _UU("CM_NEW_ICON")) == 0 || UniStrCmpi(name, _UU("CM_VGC_ICON")) == 0 || UniStrCmpi(name, _UU("CM_VGC_LINK")) == 0
				)
			{
				Free(name);
				return false;
			}
			Free(name);
		}
		return LvIsSelected(hWnd, L_ACCOUNT);
	case CMD_STARTUP:
	case CMD_NOSTARTUP:
		name = LvGetSelectedStr(hWnd, L_ACCOUNT, 0);
		if (name != NULL)
		{
			if (UniStrCmpi(name, _UU("CM_NEW_ICON")) == 0 || UniStrCmpi(name, _UU("CM_VGC_ICON")) == 0 || UniStrCmpi(name, _UU("CM_VGC_LINK")) == 0
				)
			{
				Free(name);
				return false;
			}
			Free(name);
		}
		if (LvIsMultiMasked(hWnd, L_ACCOUNT))
		{
			return false;
		}
		if (LvIsSelected(hWnd, L_ACCOUNT) == false)
		{
			return false;
		}
		else
		{
			// Determine whether the selected account is a startup account
			UINT i = LvGetSelected(hWnd, L_ACCOUNT);
			bool is_startup = (bool)LvGetParam(hWnd, L_ACCOUNT, i);
			if (id == CMD_STARTUP)
			{
				return !is_startup;
			}
			else
			{
				return is_startup;
			}
		}
		break;
	case CMD_NEW_VLAN:
		if (cm->Client->Unix == false && cm->Client->Win9x == false)
		{
			if (cm->server_name != NULL)
			{
				return false;
			}
		}
		if (cm->Client->Win9x)
		{
			if (LvNum(hWnd, L_VLAN) >= 1)
			{
				// You can not install two or more virtual LAN cards in Win9x
				return false;
			}
		}
		break;
	case CMD_PROPERTY:
		name = LvGetSelectedStr(hWnd, L_ACCOUNT, 0);
		if (name != NULL)
		{
			if (UniStrCmpi(name, _UU("CM_NEW_ICON")) == 0 || UniStrCmpi(name, _UU("CM_VGC_ICON")) == 0 || UniStrCmpi(name, _UU("CM_VGC_LINK")) == 0)
			{
				Free(name);
				return false;
			}
			Free(name);
		}
		if (LvIsMultiMasked(hWnd, L_ACCOUNT))
		{
			return false;
		}
		return LvIsSelected(hWnd, L_ACCOUNT);
	case CMD_DELETE_VLAN:
		if (LvIsMultiMasked(hWnd, L_VLAN))
		{
			return false;
		}
		return LvIsSelected(hWnd, L_VLAN);
	case CMD_ENABLE_VLAN:
		if (cm->Client->Win9x)
		{
			return false;
		}
		if (LvIsMultiMasked(hWnd, L_VLAN))
		{
			return false;
		}
		index = LvGetSelected(hWnd, L_VLAN);
		if (index == INFINITE)
		{
			return false;
		}
		else
		{
			wchar_t *s = LvGetStr(hWnd, L_VLAN, index, 1);
			if (s != NULL)
			{
				if (UniStrCmpi(s, _UU("CM_VLAN_DISABLED")) == 0)
				{
					Free(s);
					return true;
				}
				Free(s);
			}
			return false;
		}
		break;
	case CMD_DISABLE_VLAN:
		if (cm->Client->Win9x)
		{
			return false;
		}
		if (LvIsMultiMasked(hWnd, L_VLAN))
		{
			return false;
		}
		index = LvGetSelected(hWnd, L_VLAN);
		if (index == INFINITE)
		{
			return false;
		}
		else
		{
			wchar_t *s = LvGetStr(hWnd, L_VLAN, index, 1);
			if (s != NULL)
			{
				if (UniStrCmpi(s, _UU("CM_VLAN_ENABLED")) == 0)
				{
					Free(s);
					return true;
				}
				Free(s);
			}
			return false;
		}
		break;
	case CMD_REINSTALL:
		if (cm->server_name != NULL)
		{
			return false;
		}
		if (cm->Client->Win9x || cm->Client->Unix)
		{
			// Upgrading the virtual LAN card on a UNIX system or Win9x is unavailable
			return false;
		}
		if (LvIsMultiMasked(hWnd, L_VLAN))
		{
			return false;
		}
		return LvIsSelected(hWnd, L_VLAN);
	case CMD_WINNET:
		{
			UINT os_type = GetOsInfo()->OsType;

			if (OS_IS_WINDOWS_NT(os_type) && GET_KETA(os_type, 100) >= 2)
			{
				if (cm->server_name != NULL)
				{
					return false;
				}

				return true;
			}
			else
			{
				return false;
			}
		}
		break;
	case CMD_EXIT:
		return cm->TrayInited;
	}
	return true;
}

// Convert a VLAN device name to the display name
void CmVLanNameToPrintName(char *str, UINT size, char *name)
{
	// Validate arguments
	if (str == NULL || name == NULL)
	{
		return;
	}

	Format(str, size, VLAN_ADAPTER_NAME_TAG, name);
}

// Convert a display name to a VLAN device name
bool CmPrintNameToVLanName(char *name, UINT size, char *str)
{
	// Validate arguments
	if (name == NULL || str == NULL)
	{
		return false;
	}

	if (StartWith(str, VLAN_ADAPTER_NAME))
	{
		if (StrLen(str) < (StrLen(VLAN_ADAPTER_NAME) + 3))
		{
			return false;
		}

		StrCpy(name, size, str + StrLen(VLAN_ADAPTER_NAME) + 3);

		return true;
	}

	if (StartWith(str, VLAN_ADAPTER_NAME_OLD))
	{
		if (StrLen(str) < (StrLen(VLAN_ADAPTER_NAME_OLD) + 3))
		{
			return false;
		}

		StrCpy(name, size, str + StrLen(VLAN_ADAPTER_NAME_OLD) + 3);

		return true;
	}

	return false;
}

// Initialize the account list
void CmInitAccountList(HWND hWnd)
{
	CmInitAccountListEx(hWnd, false);
}
void CmInitAccountListEx(HWND hWnd, bool easy)
{
	UINT width[5];
	BUF *b;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Read the setting
	b = MsRegReadBin(REG_CURRENT_USER, CM_REG_KEY, "AccountListColumnWidth");
	if ((b != NULL) && (b->Size == sizeof(width)))
	{
		Copy(width, b->Buf, sizeof(width));
	}
	else if ((b != NULL) && (b->Size == (sizeof(width) - sizeof(UINT))))
	{
		// Migrating from previous versions
		Zero(width, sizeof(width));
		Copy(width, b->Buf, sizeof(width) - sizeof(UINT));
		width[4] = width[3];
		width[3] = 0;
	}
	else
	{
		Zero(width, sizeof(width));
	}
	FreeBuf(b);

	LvInitEx2(hWnd, L_ACCOUNT, false, easy);

//	LvSetStyle(hWnd, L_ACCOUNT, LVS_EX_TRACKSELECT);

	// Initialize the column
	if (easy == false)
	{
		LvInsertColumn(hWnd, L_ACCOUNT, 0, _UU("CM_ACCOUNT_COLUMN_1"), width[0] == 0 ? 215 : width[0]);
		LvInsertColumn(hWnd, L_ACCOUNT, 1, _UU("CM_ACCOUNT_COLUMN_2"), width[1] == 0 ? 80 : width[1]);
		LvInsertColumn(hWnd, L_ACCOUNT, 2, _UU("CM_ACCOUNT_COLUMN_3"), width[2] == 0 ? 220 : width[2]);
		LvInsertColumn(hWnd, L_ACCOUNT, 3, _UU("CM_ACCOUNT_COLUMN_3_2"), width[3] == 0 ? 90 : width[3]);
		LvInsertColumn(hWnd, L_ACCOUNT, 4, _UU("CM_ACCOUNT_COLUMN_4"), (width[4] == 0 || width[4] == 250) ? 120 : width[4]);
	}
	else
	{
		LvInsertColumn(hWnd, L_ACCOUNT, 0, _UU("CM_ACCOUNT_COLUMN_1"), 345);
		LvInsertColumn(hWnd, L_ACCOUNT, 1, _UU("CM_ACCOUNT_COLUMN_2"), 140);
		LvInsertColumn(hWnd, L_ACCOUNT, 2, _UU("CM_ACCOUNT_COLUMN_3"), 0);
		LvInsertColumn(hWnd, L_ACCOUNT, 3, _UU("CM_ACCOUNT_COLUMN_3_2"), 0);
		LvInsertColumn(hWnd, L_ACCOUNT, 4, _UU("CM_ACCOUNT_COLUMN_4"), 0);
	}
}

// Release the account list
void CmSaveAccountListPos(HWND hWnd)
{
	UINT width[5];
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	for (i = 0;i < 5;i++)
	{
		width[i] = LvGetColumnWidth(hWnd, L_ACCOUNT, i);
	}

	MsRegWriteBin(REG_CURRENT_USER, CM_REG_KEY, "AccountListColumnWidth", width, sizeof(width));
}

// Initialize the VLAN list
void CmInitVLanList(HWND hWnd)
{
	UINT width[4];
	BUF *b;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Read the setting
	b = MsRegReadBin(REG_CURRENT_USER, CM_REG_KEY, "VLanListColumnWidth");
	if ((b != NULL) && (b->Size == sizeof(width)))
	{
		Copy(width, b->Buf, sizeof(width));
	}
	else
	{
		Zero(width, sizeof(width));
	}
	FreeBuf(b);

	LvInit(hWnd, L_VLAN);

//	LvSetStyle(hWnd, L_ACCOUNT, LVS_EX_TRACKSELECT);

	// Initialize the column
	LvInsertColumn(hWnd, L_VLAN, 0, _UU("CM_VLAN_COLUMN_1"), width[0] == 0 ? 310 : width[0]);
	LvInsertColumn(hWnd, L_VLAN, 1, _UU("CM_VLAN_COLUMN_2"), width[1] == 0 ? 120 : width[1]);
	LvInsertColumn(hWnd, L_VLAN, 2, _UU("CM_VLAN_COLUMN_3"), width[2] == 0 ? 175 : width[2]);
	LvInsertColumn(hWnd, L_VLAN, 3, _UU("CM_VLAN_COLUMN_4"), width[3] == 0 ? 120 : width[3]);
}

// Release the VLAN list
void CmSaveVLanListPos(HWND hWnd)
{
	UINT width[4];
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	for (i = 0;i < 4;i++)
	{
		width[i] = LvGetColumnWidth(hWnd, L_VLAN, i);
	}

	MsRegWriteBin(REG_CURRENT_USER, CM_REG_KEY, "VLanListColumnWidth", width, sizeof(width));
}

// Update the account list
void CmRefreshAccountList(HWND hWnd)
{
	CmRefreshAccountListEx(hWnd, false);
	CmRefreshEasy();
}
void CmRefreshAccountListEx(HWND hWnd, bool easy)
{
	CmRefreshAccountListEx2(hWnd, easy, false);
}
void CmRefreshAccountListEx2(HWND hWnd, bool easy, bool style_changed)
{
	UINT num = 0;
	RPC_CLIENT_ENUM_ACCOUNT a;
	UINT num_connecting = 0, num_connected = 0;
	wchar_t tmp[MAX_SIZE];
	wchar_t new_inserted_item[MAX_ACCOUNT_NAME_LEN + 1];
	bool select_new_inserted_item = true;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Switching of icon / detail view
	LvSetView(hWnd, L_ACCOUNT, cm->IconView == false || easy);

	// Show grid
	if (cm->ShowGrid || easy)
	{
		LvSetStyle(hWnd, L_ACCOUNT, LVS_EX_GRIDLINES);
	}
	else
	{
		LvRemoveStyle(hWnd, L_ACCOUNT, LVS_EX_GRIDLINES);
	}

	if (style_changed)
	{
		// Change the font
		if (easy == false)
		{
			if (cm->VistaStyle)
			{
				SetFontMeiryo(hWnd, L_ACCOUNT, 9);
			}
			else
			{
				SetFontDefault(hWnd, L_ACCOUNT);
			}

			if (cm->VistaStyle && (cm->IconView == false))
			{
				LvSetStyle(hWnd, L_ACCOUNT, LVS_EX_FULLROWSELECT);
			}
			else
			{
				LvRemoveStyle(hWnd, L_ACCOUNT, LVS_EX_FULLROWSELECT);
			}
		}
	}

	Zero(new_inserted_item, sizeof(new_inserted_item));

	if (LvNum(hWnd, L_ACCOUNT) == 0)
	{
		select_new_inserted_item = false;
	}

	// Enumerate the account list
	if (CALL(hWnd, CcEnumAccount(cm->Client, &a)))
	{
		UINT i;
		LVB *b = LvInsertStart();

		if (cm->CmSetting.LockMode == false && (easy == false))
		{
			// Creating a new connection
			LvInsertAdd(b, ICO_NEW, NULL, 4, _UU("CM_NEW_ICON"), L"", L"", L"");

			if (cm->Client->IsVgcSupported)
			{
				// VPN Gate
				LvInsertAdd(b, ICO_RESEARCH, NULL, 4, _UU("CM_VGC_ICON"), L"", L"", L"");
			}
			else if (cm->Client->ShowVgcLink)
			{
				// VPN Gate Link
				LvInsertAdd(b, ICO_INTERNET, NULL, 4, _UU("CM_VGC_LINK"), L"", L"", L"");
			}
		}

		for (i = 0;i < a.NumItem;i++)
		{
			RPC_CLIENT_ENUM_ACCOUNT_ITEM *t = a.Items[i];
			UINT icon;
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			char tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			IP ip;
			char ip_str[MAX_SIZE];

			// Special treatment in the case of IPv6 address
			if (StrToIP6(&ip, t->ServerName) && StartWith(t->ServerName, "[") == false)
			{
				Format(ip_str, sizeof(ip_str),
					"[%s]", t->ServerName);
			}
			else
			{
				StrCpy(ip_str, sizeof(ip_str), t->ServerName);
			}

			// Determine the icon
			if (t->Active == false)
			{
				if (t->StartupAccount == false)
				{
					icon = ICO_SERVER_OFFLINE;
				}
				else
				{
					icon = ICO_SERVER_OFFLINE_EX;
				}
			}
			else
			{
				num++;
				if (t->StartupAccount == false)
				{
					icon = ICO_SERVER_ONLINE;
				}
				else
				{
					icon = ICO_SERVER_ONLINE_EX;
				}
			}

			// Adding
			if (easy == false)
			{
				//CmVLanNameToPrintName(tmp3, sizeof(tmp3), t->DeviceName);
				StrCpy(tmp3, sizeof(tmp3), t->DeviceName);
				StrToUni(tmp, sizeof(tmp), tmp3);
			}
			else
			{
				StrToUni(tmp, sizeof(tmp), t->DeviceName);
			}

			if (t->Port == 0 || cm->ShowPort == false)
			{
				// Port number is unknown
				UniFormat(tmp2, sizeof(tmp2), L"%S (%s)", ip_str, CmGetProtocolName(t->ProxyType));
			}
			else
			{
				// Port number are also shown
				UniFormat(tmp2, sizeof(tmp2), L"%S:%u (%s)", ip_str, t->Port, CmGetProtocolName(t->ProxyType));
			}

			if (LvSearchStr(hWnd, L_ACCOUNT, 0, t->AccountName) == INFINITE)
			{
				UniStrCpy(new_inserted_item, sizeof(new_inserted_item), t->AccountName);
			}

			// Virtual HUB name
			StrToUni(tmp4, sizeof(tmp4), t->HubName);

			if (easy == false)
			{
				LvInsertAdd(b, icon, (void *)t->StartupAccount, 5, t->AccountName,
					t->Active == false ? _UU("CM_ACCOUNT_OFFLINE") :
					(t->Connected ? _UU("CM_ACCOUNT_ONLINE") : _UU("CM_ACCOUNT_CONNECTING")),
					tmp2, tmp4,
					tmp);
			}
			else
			{
				LvInsertAdd(b, icon, (void *)t->StartupAccount, 5, t->AccountName,
					t->Active == false ? _UU("CM_ACCOUNT_OFFLINE") :
					(t->Connected ? _UU("CM_ACCOUNT_ONLINE") : _UU("CM_ACCOUNT_CONNECTING")),
					tmp2, tmp4,
					tmp);
			}

			if (t->Active)
			{
				if (t->Connected)
				{
					num_connected++;
				}
				else
				{
					num_connecting++;
				}
			}
		}

		LvInsertEnd(b, hWnd, L_ACCOUNT);

		CiFreeClientEnumAccount(&a);

		if (select_new_inserted_item)
		{
			if (UniStrLen(new_inserted_item) >= 1)
			{
				LvSelect(hWnd, L_ACCOUNT, INFINITE);
				LvSelect(hWnd, L_ACCOUNT, LvSearchStr(hWnd, L_ACCOUNT, 0, new_inserted_item));
			}
		}
	}

	if (easy == false)
	{
		// For voice guidance, detect new connection and connection lost
		if (cm->UpdateConnectedNumFlag == false)
		{
			cm->UpdateConnectedNumFlag = true;
			cm->OldConnectedNum = num;
		}
		else
		{
			if (cm->OldConnectedNum != num)
			{
				if (cm->OldConnectedNum < num)
				{
					CmVoice("connect");
				}
				else
				{
					CmVoice("disconnect");

					if (cm->CmSetting.EasyMode && cm->PositiveDisconnectFlag == false)
					{
						CmShowEasy();
					}

					cm->PositiveDisconnectFlag = false;
				}
				cm->OldConnectedNum = num;
			}
		}

		if (num_connecting == 0 && num_connected == 0)
		{
			// There is no connecting or connected account
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_TRAY_NOT_CONNECTED"));
		}
		else if (num_connected == 0)
		{
			// There is only connecting account
			UniFormat(tmp, sizeof(tmp), _UU("CM_TRAY_CONNECTED_1"), num_connecting);
		}
		else if (num_connecting == 0)
		{
			// There is only connected account
			UniFormat(tmp, sizeof(tmp), _UU("CM_TRAY_CONNECTED_2"), num_connected);
		}
		else
		{
			// There are both
			UniFormat(tmp, sizeof(tmp), _UU("CM_TRAY_CONNECTED_0"), num_connected, num_connecting);
		}

		if (num_connecting == 0 && num_connected == 0)
		{
			cm->TrayAnimation = false;
			cm->TraySpeedAnimation = false;
		}
		else
		{
			cm->TrayAnimation = true;

			if (num_connecting == 0)
			{
				cm->TraySpeedAnimation = false;
			}
			else
			{
				cm->TraySpeedAnimation = true;
			}
		}

		CmChangeTrayString(hWnd, tmp);
	}

	Refresh(hWnd);

	//Updated the Jump List
	CmUpdateJumpList(0);
}

// Updating the VLAN list
void CmRefreshVLanList(HWND hWnd)
{
	CmRefreshVLanListEx(hWnd, false);
}
void CmRefreshVLanListEx(HWND hWnd, bool style_changed)
{
	RPC_CLIENT_ENUM_VLAN e;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	LvSetView(hWnd, L_VLAN, cm->IconView == false);

	// Show grid
	if (cm->ShowGrid)
	{
		LvSetStyle(hWnd, L_VLAN, LVS_EX_GRIDLINES);
	}
	else
	{
		LvRemoveStyle(hWnd, L_VLAN, LVS_EX_GRIDLINES);
	}

	if (style_changed)
	{
		// Change the font
		if (cm->VistaStyle)
		{
			SetFontMeiryo(hWnd, L_VLAN, 9);
		}
		else
		{
			SetFontDefault(hWnd, L_VLAN);
		}

		if (cm->VistaStyle && (cm->IconView == false))
		{
			LvSetStyle(hWnd, L_VLAN, LVS_EX_FULLROWSELECT);
		}
		else
		{
			LvRemoveStyle(hWnd, L_VLAN, LVS_EX_FULLROWSELECT);
		}
	}

	// Enumeration
	Zero(&e, sizeof(e));
	if (CALL(hWnd, CcEnumVLan(cm->Client, &e)))
	{
		LVB *b = LvInsertStart();
		UINT i;
		for (i = 0;i < e.NumItem;i++)
		{
			wchar_t name[MAX_SIZE];
			wchar_t mac[MAX_SIZE];
			wchar_t ver[MAX_SIZE];
			char str[MAX_SIZE];
			wchar_t *status;
			RPC_CLIENT_ENUM_VLAN_ITEM *v = e.Items[i];

			// Device name
			CmVLanNameToPrintName(str, sizeof(str), v->DeviceName);
			StrToUni(name, sizeof(name), str);

			// Status
			status = v->Enabled ? _UU("CM_VLAN_ENABLED") : _UU("CM_VLAN_DISABLED");

			// MAC address
			StrToUni(mac, sizeof(mac), v->MacAddress);

			// Version
			StrToUni(ver, sizeof(ver), v->Version);

			LvInsertAdd(b, v->Enabled ? ICO_NIC_ONLINE : ICO_NIC_OFFLINE, NULL, 4,
				name, status, mac, ver);
		}
		LvInsertEnd(b, hWnd, L_VLAN);

		CiFreeClientEnumVLan(&e);
	}
}

// Get a protocol name string
wchar_t *CmGetProtocolName(UINT n)
{
	return GetProtocolName(n);
}

// Display update
void CmRefresh(HWND hWnd)
{
	CmRefreshEx(hWnd, false);
}
void CmRefreshEx(HWND hWnd, bool style_changed)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Update size
	CmMainWindowOnSize(hWnd);

	// Updating the VLAN list
	CmRefreshVLanListEx(hWnd, style_changed);

	// Update the account list
	CmRefreshAccountListEx2(hWnd, false, style_changed);

	// Update the status bar
	CmRefreshStatusBar(hWnd);
}

// Determine whether to check the specified menu item
bool CmIsChecked(UINT id)
{
	switch (id)
	{
	case CMD_TRAYICON:
		return cm->HideTrayIcon == false;
	case CMD_STATUSBAR:
		return cm->HideStatusBar == false;
	case CMD_VISTASTYLE:
		return cm->VistaStyle;
	case CMD_ICON:
		return cm->IconView;
	case CMD_DETAIL:
		return cm->IconView == false;
	case CMD_GRID:
		return cm->ShowGrid;
	case CMD_VOIDE_NONE:
		return cm->DisableVoice;
	case CMD_SHOWPORT:
		return cm->ShowPort;
	case CMD_VOICE_NORMAL:
		if (cm->DisableVoice)
		{
			return false;
		}
		else
		{
			return cm->VoiceId == VOICE_SSK;
		}
	case CMD_VOICE_ODD:
		if (cm->DisableVoice)
		{
			return false;
		}
		else
		{
			return cm->VoiceId == VOICE_AHO;
		}
	}
	return false;
}

// The menu popped-up
void CmMainWindowOnPopupMenu(HWND hWnd, HMENU hMenu, UINT pos)
{
	UINT num_menu, i, id;
	// Validate arguments
	if (hWnd == NULL || hMenu == NULL)
	{
		return;
	}

	num_menu = GetMenuItemCount(hMenu);
	for (i = 0;i < num_menu;i++)
	{
		id = GetMenuItemID(hMenu, i);

		if (id != INFINITE)
		{
			bool enable_flag = CmIsEnabled(hWnd, id);
			bool checked_flag = CmIsChecked(id);
			bool bold_flag = CmIsBold(id);
			MENUITEMINFO info;

			Zero(&info, sizeof(info));
			info.cbSize = sizeof(info);
			info.fMask = MIIM_STATE;
			info.fState = (enable_flag ? MFS_ENABLED : MFS_DISABLED) |
				(checked_flag ? MFS_CHECKED : MFS_UNCHECKED) |
				(bold_flag ? MFS_DEFAULT : 0);

			if (id == CMD_ICON || id == CMD_DETAIL || id == CMD_VOIDE_NONE ||
				id == CMD_VOICE_NORMAL || id == CMD_VOICE_ODD)
			{
				info.fMask |= MIIM_FTYPE;
				info.fType = MFT_RADIOCHECK;
			}

			SetMenuItemInfo(hMenu, id, false, &info);
		}

		if (id == CMD_RECENT)
		{
			HMENU sub = CmCreateRecentSubMenu(hWnd, CM_TRAY_MENU_RECENT_ID_START);

			if (sub != NULL)
			{
				DeleteMenu(hMenu, i, MF_BYPOSITION);
				MsInsertMenu(hMenu, i, MF_BYPOSITION | MF_ENABLED | MF_POPUP | MF_STRING,
					(UINT_PTR)sub, _UU("CM_TRAY_MENU_RECENT"));
			}
			else
			{
				MENUITEMINFO info;

				Zero(&info, sizeof(info));
				info.cbSize = sizeof(info);
				info.fMask = MIIM_STATE;
				info.fState = MFS_DISABLED;

				SetMenuItemInfo(hMenu, id, false, &info);
			}
		}
	}
}

// Set the main window title
wchar_t *CmGenerateMainWindowTitle()
{
	wchar_t tmp[MAX_SIZE];
	if (cm->server_name == NULL)
	{
		UniFormat(tmp, sizeof(tmp), L"%s", _UU("CM_TITLE"));
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), L"%s - %S", _UU("CM_TITLE"), cm->server_name);
	}

	return CopyUniStr(tmp);
}

// Initialize the task tray
void CmInitTray(HWND hWnd)
{
	bool ret;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (cm->server_name != NULL)
	{
		return;
	}

	if (cm->TrayInited)
	{
		return;
	}

	ret = MsShowIconOnTray(hWnd, LoadSmallIcon(CmGetTrayIconId(false, 0)), _UU("CM_TRAY_INITING"), WM_CM_TRAY_MESSAGE);

	cm->TrayInited = true;
	cm->TrayAnimation = false;
	cm->TraySucceed = ret;

	SetTimer(hWnd, 2, CM_TRAY_ANIMATION_INTERVAL / 4, NULL);
}

// Change the string in the task tray
void CmChangeTrayString(HWND hWnd, wchar_t *str)
{
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return;
	}
	if (cm->TrayInited == false)
	{
		return;
	}

	MsChangeIconOnTray(NULL, str);
}

// Release the task tray
void CmFreeTray(HWND hWnd)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (cm->TrayInited == false)
	{
		return;
	}

	MsHideIconOnTray();

	cm->TrayInited = false;
}
void CmFreeTrayExternal(void *hWnd)
{
	CmFreeTray((HWND)hWnd);
}

// Periodical processing to the task tray
void CmPollingTray(HWND hWnd)
{
	UINT interval;
	bool ret;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (cm->TrayInited == false)
	{
		return;
	}

	ret = MsChangeIconOnTrayEx(LoadSmallIcon(CmGetTrayIconId(cm->TrayAnimation, cm->TrayAnimationCounter)),
		NULL, NULL, NULL, NIIF_NONE, !cm->TraySucceed);

	if (cm->TraySucceed == false)
	{
		cm->TraySucceed = ret;
	}

	cm->TrayAnimationCounter++;

	KillTimer(hWnd, 2);
	interval = CM_TRAY_ANIMATION_INTERVAL / 4;
	if (cm->TraySpeedAnimation)
	{
		interval /= 4;
	}
	SetTimer(hWnd, 2, interval, NULL);
}

// Get the icon ID of the task tray for animation
UINT CmGetTrayIconId(bool animation, UINT animation_counter)
{
	if (animation == false)
	{
		return ICO_TRAY0;
	}
	else
	{
		switch (animation_counter % 4)
		{
		case 0:
			return ICO_TRAY1;

		case 1:
			return ICO_TRAY2;

		case 2:
			return ICO_TRAY3;

		default:
			return ICO_TRAY4;
		}
	}
}

// Initialize the main window
void CmMainWindowOnInit(HWND hWnd)
{
	wchar_t *s;
	BUF *b;
	bool startup_mode = cm->StartupMode;
	CM_SETTING a;
	bool fake = false;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Font settings of list
	SetFontMeiryo(hWnd, L_ACCOUNT, 9);
	SetFontMeiryo(hWnd, L_VLAN, 9);

	// Get the configuration of the current vpnclient
	Zero(&a, sizeof(a));
	CcGetCmSetting(cm->Client, &a);

	if (a.EasyMode)
	{
		fake = true;
	}

	InitMenuInternational(GetMenu(hWnd), "CM_MENU");

	cm->HideStatusBar = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "HideStatusBar");
	cm->HideTrayIcon = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "HideTrayIcon");
	cm->IconView = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "IconView");
	cm->ShowGrid = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "ShowGrid");

	if (MsRegIsValue(REG_CURRENT_USER, CM_REG_KEY, "VistaStyle"))
	{
		cm->VistaStyle = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "VistaStyle");
	}
	else
	{
		cm->VistaStyle = MsIsVista();
	}

	if (MsRegIsValue(REG_CURRENT_USER, CM_REG_KEY, "ShowPort"))
	{
		cm->ShowPort = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "ShowPort");
	}
	else
	{
		cm->ShowPort = false;
	}

	if (MsRegIsValue(REG_CURRENT_USER, CM_REG_KEY, "DisableVoice"))
	{
		cm->DisableVoice = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "DisableVoice");
	}
	else
	{
		cm->DisableVoice = true;
	}
	cm->VoiceId = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "VoiceId");

	cm->StatusWindowList = NewList(NULL);

	SetIcon(hWnd, 0, ICO_VPN);

	s = CmGenerateMainWindowTitle();
	SetText(hWnd, 0, s);
	Free(s);

	// Initialize the window position
	b = MsRegReadBin(REG_CURRENT_USER, CM_REG_KEY, "WindowPlacement");
	if (b != NULL && b->Size == sizeof(WINDOWPLACEMENT))
	{
		// Restore the window position
		WINDOWPLACEMENT *p;
		p = ZeroMalloc(b->Size);
		Copy(p, b->Buf, b->Size);

		if (startup_mode)
		{
			p->showCmd = SW_SHOWMINIMIZED;
		}

		if (fake)
		{
			Copy(&cm->FakeWindowPlacement, p, sizeof(WINDOWPLACEMENT));
		}
		else
		{
			SetWindowPlacement(hWnd, p);
		}
		Free(p);
	}
	else
	{
		// Initialize the window position
		SetWindowPos(hWnd, NULL, 0, 0, CM_DEFAULT_WIDTH, CM_DEFAULT_HEIGHT, SWP_NOREDRAW);
		Center(hWnd);
		if (startup_mode)
		{
			ShowWindow(hWnd, SW_SHOWMINIMIZED);
		}

		if (fake)
		{
			WINDOWPLACEMENT p;

			Zero(&p, sizeof(p));
			p.length = sizeof(p);
			GetWindowPlacement(hWnd, &p);
			Copy(&cm->FakeWindowPlacement, &p, sizeof(WINDOWPLACEMENT));
		}
	}
	FreeBuf(b);

	if (fake)
	{
		SetWindowPos(hWnd, NULL, -200, -200, 100, 100,
			SWP_NOREDRAW | SWP_SHOWWINDOW);
	}

	// Initialize the status bar related items
	cm->hMainWnd = hWnd;
	cm->hStatusBar = CreateStatusWindowW(WS_CHILD |
		(cm->HideStatusBar == false ? WS_VISIBLE : 0),
		_UU("CM_TITLE"),
		hWnd, S_STATUSBAR);

	UniStrCpy(cm->StatudBar1, sizeof(cm->StatudBar1), _UU("CM_TITLE"));
	UniStrCpy(cm->StatudBar2, sizeof(cm->StatudBar2), _UU("CM_CONN_NO"));
	UniFormat(cm->StatudBar3, sizeof(cm->StatudBar3), _UU("CM_PRODUCT_NAME"), CEDAR_VERSION_BUILD);

	cm->Icon2 = LoadSmallIcon(ICO_SERVER_OFFLINE);
	cm->Icon3 = LoadSmallIcon(ICO_VPN);

	// Initialize the account list
	CmInitAccountList(hWnd);

	// Initialize the VLAN list
	CmInitVLanList(hWnd);

	// Display update
	CmRefreshEx(hWnd, true);

	// Start a thread of notification client
	CmInitNotifyClientThread();

	// Timer setting
	SetTimer(hWnd, 1, 128, NULL);
	SetTimer(hWnd, 6, 5000, NULL);

	// Initialize the task tray
	if (cm->server_name == NULL)
	{
		if (cm->HideTrayIcon == false)
		{
			CmInitTray(hWnd);
		}
	}

	CmVoice("start");

	if (startup_mode || a.EasyMode)
	{
		SetTimer(hWnd, 3, 1, NULL);
	}

	if (cm->import_file_name != NULL)
	{
		// Import a file specified as an argument
		CmSendImportMessage(hWnd, cm->import_file_name, cm->CmSettingInitialFlag == CM_SETTING_INIT_NONE ? CM_IMPORT_FILENAME_MSG : CM_IMPORT_FILENAME_MSG_OVERWRITE);
		/*if (a.LockMode == false)
		{
			CmImportAccountMainEx(hWnd, cm->import_file_name, cm->CmSettingInitialFlag != CM_SETTING_INIT_NONE);
		}
		else
		{
			MsgBox(cm->hEasyWnd ? cm->hEasyWnd : hWnd, MB_ICONEXCLAMATION, _UU("CM_VPN_FILE_IMPORT_NG"));
		}*/
	}

	// Apply the CM_SETTING
	CmApplyCmSetting();

	cm->StartupFinished = true;
}

// Start a thread of notification client
void CmInitNotifyClientThread()
{
	cm->NotifyClient = CcConnectNotify(cm->Client);
	if (cm->NotifyClient == false)
	{
		Close(cm->hMainWnd);
		exit(0);
	}
	cm->NotifyClientThread = NewThread(CmNotifyClientThread, NULL);
}

// Notification client thread
void CmNotifyClientThread(THREAD *thread, void *param)
{
	NOTIFY_CLIENT *nc;
	// Validate arguments
	if (thread == NULL)
	{
		return;
	}

	nc = cm->NotifyClient;

	// Wait for the next notification
	while (cm->Halt == false)
	{
		if (CcWaitNotify(nc))
		{
			// Send a message
			PostMessage(cm->hMainWnd, WM_CM_NOTIFY, 0, 0);
		}
		else
		{
			// Disconnected
			if (cm->Halt == false)
			{
				if (cm != NULL)
				{
					CmFreeTrayExternal((void *)cm->hMainWnd);
				}
				CncExit();
				exit(0);
			}
			break;
		}
	}
}

// Stop the thread of the notification client
void CmFreeNotifyClientThread()
{
	cm->Halt = true;

	// Disconnect
	CcStopNotify(cm->NotifyClient);

	// Wait for the termination of the thread
	WaitThread(cm->NotifyClientThread, INFINITE);

	// Connection termination
	CcDisconnectNotify(cm->NotifyClient);
	ReleaseThread(cm->NotifyClientThread);
}

// Resize the main window
void CmMainWindowOnSize(HWND hWnd)
{
	RECT r;
	UINT client_width, client_height;
	UINT status_height;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Get the size of the client area of the main window
	GetClientRect(hWnd, &r);
	client_width = MAX(r.right - r.left, 0);
	client_height = MAX(r.bottom - r.top, 0);

	SendMsg(hWnd, S_STATUSBAR, WM_SIZE, 0, 0);

	// Get the size of the status bar
	GetWindowRect(DlgItem(hWnd, S_STATUSBAR), &r);
	status_height = MAX(r.bottom - r.top, 0);

	if (cm->HideStatusBar == false)
	{
		client_height = MAX(client_height - status_height, 0);
	}

	MoveWindow(DlgItem(hWnd, L_ACCOUNT), 0, 0, client_width, client_height * 3 / 5 - 3, true);
	MoveWindow(DlgItem(hWnd, L_VLAN), 0, client_height * 3 / 5, client_width, client_height * 2 / 5, true);

	// Re-draw the status bar
	CmRedrawStatusBar(hWnd);
}

// Disconnect all accounts currently connected
void CmDisconnectAll(HWND hWnd)
{
	UINT i, num;
	LIST *o;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Display a warning
	num = CmGetNumConnected(hWnd);
	if (num == 0)
	{
		return;
	}

	if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_DISCONNECT_ALL"), num) == IDNO)
	{
		return;
	}

	cm->PositiveDisconnectFlag = true;

	// Create a list of connected items
	o = NewListFast(NULL);

	num = LvNum(hWnd, L_ACCOUNT);
	for (i = 0;i < num;i++)
	{
		wchar_t *s = LvGetStr(hWnd, L_ACCOUNT, i, 1);
		if (s != NULL)
		{
			if (UniStrCmpi(s, _UU("CM_ACCOUNT_ONLINE")) == 0 || UniStrCmpi(s, _UU("CM_ACCOUNT_CONNECTING")) == 0)
			{
				Add(o, LvGetStr(hWnd, L_ACCOUNT, i, 0));
			}
			Free(s);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		if (s != NULL)
		{
			CmDisconnect(hWnd, s);
			Free(s);
		}
	}

	ReleaseList(o);
}

// Get a number of currently connected connection settings
UINT CmGetNumConnected(HWND hWnd)
{
	UINT i, num, num_active;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	num_active = 0;
	num = LvNum(hWnd, L_ACCOUNT);
	for (i = 0;i < num;i++)
	{
		wchar_t *s = LvGetStr(hWnd, L_ACCOUNT, i, 1);
		if (s != NULL)
		{
			if (UniStrCmpi(s, _UU("CM_ACCOUNT_ONLINE")) == 0 || UniStrCmpi(s, _UU("CM_ACCOUNT_CONNECTING")) == 0)
			{
				num_active++;
			}
			Free(s);
		}
	}

	return num_active;
}

// Update the status bar information
void CmRefreshStatusBar(HWND hWnd)
{
	UINT num_active = CmGetNumConnected(hWnd);
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (num_active == 0)
	{
		UniStrCpy(cm->StatudBar2, sizeof(cm->StatudBar2), _UU("CM_CONN_NO"));
		cm->Icon2 = LoadSmallIcon(ICO_SERVER_OFFLINE);
	}
	else
	{
		UniFormat(cm->StatudBar2, sizeof(cm->StatudBar2), _UU("CM_NUM_CONN_COUNT"), num_active);
		cm->Icon2 = LoadSmallIcon(ICO_SERVER_ONLINE);
	}

	CmRedrawStatusBar(hWnd);
}

// Re-draw the status bar
void CmRedrawStatusBar(HWND hWnd)
{
	HWND h;
	RECT r;
	int width;
	int x1, x2, x3;
	int xx[3];
	wchar_t tmp[MAX_SIZE];
	HICON icon;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	h = cm->hStatusBar;

	// Get the width of the status bar
	GetWindowRect(h, &r);
	width = MAX(r.right - r.left, 0);
	x2 = (UINT)(180.0 * GetTextScalingFactor());
	x3 = (UINT)(245.0 * GetTextScalingFactor());
	x1 = MAX(width - x2 - x3, 0);

	// Divide into three parts
	xx[0] = x1;
	xx[1] = x2 + x1;
	xx[2] = x3 + x2 + x1;
	SendMsg(h, 0, SB_SETPARTS, 3, (LPARAM)xx);

	// Set an icon
	icon = (HICON)SendMsg(h, 0, SB_GETICON, 1, 0);
	if (icon != cm->Icon2)
	{
		SendMsg(h, 0, SB_SETICON, 1, (LPARAM)cm->Icon2);
	}

	icon = (HICON)SendMsg(h, 0, SB_GETICON, 2, 0);
	if (icon != cm->Icon3)
	{
		SendMsg(h, 0, SB_SETICON, 2, (LPARAM)cm->Icon3);
	}

	// Set a string
	SendMsg(h, 0, SB_GETTEXTW, 0, (LPARAM)tmp);
	if (UniStrCmp(tmp, cm->StatudBar1))
	{
		SendMsg(h, 0, SB_SETTEXTW, 0, (LPARAM)cm->StatudBar1);
	}

	SendMsg(h, 0, SB_GETTEXTW, 1, (LPARAM)tmp);
	if (UniStrCmp(tmp, cm->StatudBar2))
	{
		SendMsg(h, 0, SB_SETTEXTW, 1, (LPARAM)cm->StatudBar2);
	}

	SendMsg(h, 0, SB_GETTEXTW, 2, (LPARAM)tmp);
	if (UniStrCmp(tmp, cm->StatudBar3))
	{
		SendMsg(h, 0, SB_SETTEXTW, 2, (LPARAM)cm->StatudBar3);
	}
}

// Save the position information of the main window
void CmSaveMainWindowPos(HWND hWnd)
{
	WINDOWPLACEMENT p;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	// Save settings
	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY, "HideStatusBar", cm->HideStatusBar);
	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY, "HideTrayIcon", cm->HideTrayIcon);
	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY, "IconView", cm->IconView);
	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY, "ShowGrid", cm->ShowGrid);
	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY, "DisableVoice", cm->DisableVoice);
	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY, "VoiceId", cm->VoiceId);
	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY, "VistaStyle", cm->VistaStyle);
	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY, "ShowPort", cm->ShowPort);

	// Save the window position
	Zero(&p, sizeof(p));
	p.length = sizeof(p);
	GetWindowPlacement(hWnd, &p);

	if (IsZero(&cm->FakeWindowPlacement, sizeof(cm->FakeWindowPlacement)) == false)
	{
		Copy(&p, &cm->FakeWindowPlacement, sizeof(cm->FakeWindowPlacement));
	}

	MsRegWriteBin(REG_CURRENT_USER, CM_REG_KEY, "WindowPlacement", &p, sizeof(p));

	CmSaveAccountListPos(hWnd);
	CmSaveVLanListPos(hWnd);
}

// Close the main window
void CmMainWindowOnQuit(HWND hWnd)
{
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (cm->TrayInited)
	{
		if (MsgBox(hWnd, MB_YESNO | MB_ICONQUESTION,
			_UU("CM_EXIT_MESSAGE")) == IDNO)
		{
			return;
		}
	}

	if (cm->OnCloseDispatched)
	{
		return;
	}
	cm->OnCloseDispatched = true;

	CmCloseEasy();

	// Release the tray icon
	CmFreeTray(hWnd);

	// Save the position information of the main window
	CmSaveMainWindowPos(hWnd);

	// Close the status window
	for (i = 0;i < LIST_NUM(cm->StatusWindowList);i++)
	{
		HWND h = LIST_DATA(cm->StatusWindowList, i);
		//EndDialog(h, 0);
		PostMessage(h, WM_CLOSE, 0, 0);
	}

	ReleaseList(cm->StatusWindowList);
	cm->StatusWindowList = NULL;

	if (cm->WindowCount != 0)
	{
		// Abort
		exit(0);
	}

	// Close
	CmFreeNotifyClientThread();

	EndDialog(hWnd, false);
}

// Start the mutex to be used in starting
bool CmStartStartupMutex()
{
	INSTANCE *o = NewSingleInstance(STARTUP_MUTEX_NAME);

	if (o == NULL)
	{
		return false;
	}

	cm->StartupMutex = o;

	return true;
}

// Release the mutex to be used in starting
void CmEndStartupMutex()
{
	if (cm->StartupMutex != NULL)
	{
		FreeSingleInstance(cm->StartupMutex);

		cm->StartupMutex = NULL;
	}
}

// Main window
void MainCMWindow()
{
	HWND h;
	wchar_t *s;
	CM_SETTING a;

	if (CmStartStartupMutex() == false)
	{
		return;
	}

	s = CmGenerateMainWindowTitle();
	h = SearchWindow(s);
	Free(s);

	Zero(&a, sizeof(a));
	CcGetCmSetting(cm->Client, &a);
	if (cm->server_name != NULL && a.EasyMode)
	{
		CmEndStartupMutex();
		MsgBox(NULL, MB_ICONEXCLAMATION, _UU("CM_EASY_MODE_NOT_ON_REMOTE"));
		return;
	}

	// Change the operating mode
	if (cm->CmSettingSupported)
	{
		if (cm->CmSettingInitialFlag == CM_SETTING_INIT_SELECT)
		{
			if (h != NULL)
			{
				CmEndStartupMutex();
			}

			// Show the selection screen
			CmSetting(NULL);

			if (h != NULL)
			{
				goto SEND_MESSAGES;
			}
			else
			{
				return;
			}
		}
		else if ((cm->CmSettingInitialFlag == CM_SETTING_INIT_EASY && cm->CmEasyModeSupported) || cm->CmSettingInitialFlag == CM_SETTING_INIT_NORMAL)
		{
			// State transition
			CM_SETTING a;

			Zero(&a, sizeof(a));
			CcGetCmSetting(cm->Client, &a);

			if (cm->CmSettingInitialFlag == CM_SETTING_INIT_EASY)
			{
				a.EasyMode = true;
			}
			else
			{
				a.EasyMode = false;
			}

			CcSetCmSetting(cm->Client, &a);
		}
	}

	if (h == NULL)
	{
		// Create a window because there is no window of the same title
		if (cm->server_name == NULL)
		{
			CmInitTryToExecUiHelper();

			if (IsDebug() == false)
			{
				CnWaitForCnServiceReady();
			}
		}
		Dialog(NULL, D_CM_MAIN, CmMainWindowProc, NULL);
		CmFreeTryToExecUiHelper();
	}
	else
	{
SEND_MESSAGES:
		CmEndStartupMutex();

		// If a window of the same title already exists, activate it and exit itself
		SetForegroundWindow(h);
		SendMessage(h, WM_CM_SHOW, 0, 0);
		SetForegroundWindow(h);

		if (cm->CmSettingInitialFlag != CM_SETTING_INIT_NONE && cm->CmSettingInitialFlag != CM_SETTING_INIT_CONNECT)
		{
			// Notify since CM_SETTING has been changed
			SendMessage(h, WM_CM_SETTING_CHANGED_MESSAGE, 0, 0);
		}

		if (cm->import_file_name != NULL)
		{
			UINT msg;
			if (cm->CmSettingInitialFlag == CM_SETTING_INIT_NONE)
			{
				msg = CM_IMPORT_FILENAME_MSG;
			}
			else
			{
				msg = CM_IMPORT_FILENAME_MSG_OVERWRITE;
			}

			CmSendImportMessage(h, cm->import_file_name, msg);
		}
	}

	CmEndStartupMutex();
}

// Send an import message
void CmSendImportMessage(HWND hWnd, wchar_t *filename, UINT msg)
{
	COPYDATASTRUCT cpy;
	// Validate arguments
	if (hWnd == NULL || filename == NULL)
	{
		return;
	}

	// Specify the file to be imported
	Zero(&cpy, sizeof(cpy));

	cpy.cbData = UniStrSize(filename);
	cpy.lpData = filename;
	cpy.dwData = msg;

	SendMessage(hWnd, WM_COPYDATA, 0, (LPARAM)&cpy);
}

// Login dialog
UINT CmLoginDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	// Validate arguments
	wchar_t server_name[MAX_SIZE];
	char password[MAX_PASSWORD_LEN + 1];
	bool bad_pass;
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		if (cm->server_name != NULL)
		{
			StrToUni(server_name, sizeof(server_name), cm->server_name);
		}
		else
		{
			UniStrCpy(server_name, sizeof(server_name), _UU("CM_PW_LOCALMACHINE"));
		}
		FormatText(hWnd, S_TITLE, server_name);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (cm->server_name != NULL)
			{
				StrToUni(server_name, sizeof(server_name), cm->server_name);
			}
			else
			{
				UniStrCpy(server_name, sizeof(server_name), _UU("CM_PW_LOCALMACHINE"));
			}
			GetTxtA(hWnd, E_PASSWORD, password, sizeof(password));
			cm->Client = CcConnectRpc(cm->server_name == NULL ? "127.0.0.1" : cm->server_name,
				password, &bad_pass, NULL, 0);
			if (cm->Client == NULL)
			{
				MsgBox(hWnd, MB_ICONSTOP, _UU("CM_BAD_PASSWORD"));
				FocusEx(hWnd, E_PASSWORD);
			}
			else
			{
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

// Login
bool LoginCM()
{
	// Try to login with an empty password first
	bool bad_pass, no_remote;
	wchar_t server_name[MAX_SIZE];
	RPC_CLIENT_VERSION a;

RETRY:
	if (cm->server_name != NULL)
	{
		StrToUni(server_name, sizeof(server_name), cm->server_name);
	}
	else
	{
		UniStrCpy(server_name, sizeof(server_name), _UU("CM_PW_LOCALMACHINE"));
	}

	// Attempt to connect
	if ((cm->Client = CcConnectRpc(
		cm->server_name == NULL ? "localhost" : cm->server_name,
		cm->password == NULL ? "" : cm->password, &bad_pass, &no_remote, cm->StartupMode == false ? 0 : 60000)) == NULL)
	{
		if (no_remote)
		{
			// Remote connection was denied
			if (MsgBoxEx(NULL, MB_ICONEXCLAMATION | MB_RETRYCANCEL, _UU("CM_NO_REMOTE"), server_name) == IDRETRY)
			{
				// Retry
				goto RETRY;
			}
			else
			{
				return false;
			}
		}
		else if (bad_pass)
		{
			if (Dialog(NULL, D_CM_LOGIN, CmLoginDlgProc, NULL) == false)
			{
				return false;
			}
		}
		else
		{
			// Connection failure
			if (cm->StartupMode == false && MsgBoxEx(NULL, MB_ICONEXCLAMATION | MB_RETRYCANCEL, _UU("CM_CONNECT_FAILED"), server_name) == IDRETRY)
			{
				// Retry
				goto RETRY;
			}
			else
			{
				return false;
			}
		}
	}

	Zero(&a, sizeof(a));
	CcGetClientVersion(cm->Client, &a);
	if (a.ClientBuildInt >= 5192)
	{
		cm->CmSettingSupported = true;
		cm->CmEasyModeSupported = true;
		if (OS_IS_WINDOWS_9X(a.OsType))
		{
			cm->CmEasyModeSupported = false;
		}
	}

	return true;
}

// Main process
void MainCM()
{
	// If there is /remote in the argument, show the screen of the remote connection
	TOKEN_LIST *cmdline = GetCommandLineToken();

	UINT i = 0;
	bool isRemote = false;

	if (cm->server_name != NULL)
	{
		Free(cm->server_name);
	}
	cm->server_name = NULL;

	if (cm->password != NULL)
	{
		Free(cm->password);
	}
	cm->password = NULL;

	for(i = 0; i < cmdline->NumTokens; ++i)
	{
		if (StrCmpi(cmdline->Token[i], "/remote") == 0)
		{
			isRemote = true;
		}
		else if (StrCmpi(cmdline->Token[i], "/hostname") == 0 && i + 1 < cmdline->NumTokens)
		{
			isRemote = true;
			if (cm->server_name != NULL)
			{
				Free(cm->server_name);
			}
			cm->server_name = CopyStr(cmdline->Token[++i]);
		}
		else if (StrCmpi(cmdline->Token[i], "/password") == 0 && i + 1 < cmdline->NumTokens)
		{
			if (cm->password != NULL)
			{
				Free(cm->password);
			}
			cm->password = CopyStr(cmdline->Token[++i]);
		}
		else if (StrCmpi(cmdline->Token[i], "/startup") == 0)
		{
			// Startup mode
			cm->StartupMode = true;
		}
	}

	if (isRemote && cm->server_name == NULL)
	{
		char *hostname = RemoteDlg(NULL, CM_REG_KEY, ICO_VPN, _UU("CM_TITLE"), _UU("CM_REMOTE_TITLE"), NULL);
		if (hostname == NULL)
		{
			return;
		}
		if (cm->server_name != NULL)
		{
			Free(cm->server_name);
		}
		cm->server_name = NULL;
		if (StrCmpi(hostname, "localhost") != 0 && StrCmpi(hostname, "127.0.0.1") != 0 )
		{
			cm->server_name = hostname;
		}
	}

	FreeToken(cmdline);

	if (IsZero(cm->ShortcutKey, SHA1_SIZE) == false)
	{
		//if (MsGetCurrentTerminalSessionId() == 0)
		{
			// Start the shortcut connection
			CmConnectShortcut(cm->ShortcutKey);
		}/*
		else
		{
			MsgBoxEx(NULL, MB_ICONEXCLAMATION, _UU("CM_SHORTCUT_DESKTOP_MSG"),
				MsGetCurrentTerminalSessionId());
		}*/
		return;
	}

	// Login
	if (LoginCM() == false)
	{
		return;
	}

	//Update the jump list
	CmUpdateJumpList(0);

	// Main window
	MainCMWindow();

	// Log out
	LogoutCM();

	if (cm->Update != NULL)
	{
		FreeUpdateUi(cm->Update);
		cm->Update = NULL;
	}
}

// Log out
void LogoutCM()
{
	if (cm->Client != NULL)
	{
		CcDisconnectRpc(cm->Client);
	}
}

// Client Connection Manager start function
void CMExec()
{
	// Initialize
	InitCM(true);

	// Main process
	MainCM();

	// Release
	FreeCM();
}

// HUB enumeration thread
void CmEnumHubThread(THREAD *t, void *param)
{
	CM_ENUM_HUB *e = (CM_ENUM_HUB *)param;
	HWND hWnd;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	e->Thread = t;
	hWnd = e->hWnd;
	LockList(cm->EnumHubList);
	{
		Add(cm->EnumHubList, e);
	}
	UnlockList(cm->EnumHubList);

	// Thread initialization is completed
	NoticeThreadInit(t);

	// Create a session
	e->Session = NewRpcSession(cm->Cedar, e->ClientOption);
	if (e->Session)
	{
		// Enumeration of HUB
		e->Hub = EnumHub(e->Session);

		if (e->Hub != NULL)
		{
			// Enumeration completed
			// Add to the combo box
			if (CbNum(hWnd, C_HUBNAME) == 0)
			{
				UINT i;
				wchar_t tmp[MAX_SIZE];
				for (i = 0;i < e->Hub->NumTokens;i++)
				{
					StrToUni(tmp, sizeof(tmp), e->Hub->Token[i]);
					CbAddStr(hWnd, C_HUBNAME, tmp, 0);
				}
			}

			// Release the memory
			FreeToken(e->Hub);
		}

		// Release the session
		ReleaseSession(e->Session);
	}

	LockList(cm->EnumHubList);
	{
		Delete(cm->EnumHubList, e);
	}
	UnlockList(cm->EnumHubList);

	Free(e->ClientOption);
	Free(e);
}

// The start of the HUB enumeration
void CmEnumHubStart(HWND hWnd, CLIENT_OPTION *o)
{
	CM_ENUM_HUB *e;
	THREAD *t;
	// Validate arguments
	if (hWnd == NULL || o == NULL)
	{
		return;
	}

	if (StrLen(o->Hostname) == 0 ||
		o->Port == 0)
	{
		return;
	}

	if (o->ProxyType != PROXY_DIRECT)
	{
		if (StrLen(o->ProxyName) == 0 ||
			o->ProxyPort == 0)
		{
			return;
		}
	}

	if (LvNum(hWnd, C_HUBNAME) != 0)
	{
		return;
	}

	e = ZeroMalloc(sizeof(CM_ENUM_HUB));
	e->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	e->hWnd = hWnd;
	Copy(e->ClientOption, o, sizeof(CLIENT_OPTION));

	t = NewThread(CmEnumHubThread, e);
	WaitThreadInit(t);
	ReleaseThread(t);
}

// Initialize the HUB enumeration process
void CmInitEnumHub()
{
	cm->EnumHubList = NewList(NULL);
}

// Release the HUB enumeration process
void CmFreeEnumHub()
{
	LIST *o;
	UINT i;
	if (cm->EnumHubList == NULL)
	{
		return;
	}

	o = NewList(NULL);
	LockList(cm->EnumHubList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(cm->EnumHubList);i++)
		{
			CM_ENUM_HUB *e = LIST_DATA(cm->EnumHubList, i);
			Add(o, e->Thread);
			AddRef(e->Thread->ref);
		}
	}
	UnlockList(cm->EnumHubList);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		THREAD *t = LIST_DATA(o, i);
		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}
	ReleaseList(o);

	ReleaseList(cm->EnumHubList);
}

// Initialize the Client Connection Manager

void InitCM(bool set_app_id)
{
	UNI_TOKEN_LIST *ut;
	if (cm != NULL)
	{
		return;
	}

	if (set_app_id)
	{
		if(JL_SetCurrentProcessExplicitAppUserModelID(APPID_CM) != S_OK)
		{
		}
	}

	CmDeleteOldStartupTrayFile();

	MsSetShutdownParameters(0x4ff, SHUTDOWN_NORETRY);

	// Memory allocation
	cm = ZeroMalloc(sizeof(CM));

	// If the command line argument is set treat it as a server name 
	ut = GetCommandLineUniToken();

	if (ut->NumTokens >= 1)
	{
		if (UniStrLen(ut->Token[0]) != 0)
		{
			if (UniStrCmpi(ut->Token[0], L"cm") != 0 && ut->Token[0][0] != L'/')
			{
				BUF *b = UniStrToBin(ut->Token[0]);
				if (b->Size == SHA1_SIZE)
				{
					// Treated as a shortcut key for the connection settings
					Copy(cm->ShortcutKey, b->Buf, SHA1_SIZE);
				}
				else
				{
					if (UniEndWith(ut->Token[0], L".vpn") == false)
					{
						// Treated as a server name
						cm->server_name = CopyUniToStr(ut->Token[0]);
					}
					else
					{
						// Treated as import file name
						cm->import_file_name = CopyUniStr(ut->Token[0]);
					}
				}
				FreeBuf(b);
			}
			else if (UniStrCmpi(ut->Token[0], L"/easy") == 0)
			{
				// Simple mode
				if (ut->NumTokens >= 2)
				{
					// Connection settings to be imported is specified
					cm->import_file_name = CopyUniStr(ut->Token[1]);
				}

				cm->CmSettingInitialFlag = CM_SETTING_INIT_EASY;
			}
			else if (UniStrCmpi(ut->Token[0], L"/normal") == 0)
			{
				// Normal mode
				if (ut->NumTokens >= 2)
				{
					// Connection settings to be imported is specified
					cm->import_file_name = CopyUniStr(ut->Token[1]);
				}

				cm->CmSettingInitialFlag = CM_SETTING_INIT_NORMAL;
			}
			else if (UniStrCmpi(ut->Token[0], L"/connect") == 0)
			{
				// Import process by the simple installer
				if (ut->NumTokens >= 2)
				{
					// Connection settings to be imported is specified
					cm->import_file_name = CopyUniStr(ut->Token[1]);
				}

				cm->CmSettingInitialFlag = CM_SETTING_INIT_CONNECT;
			}
			else if (UniStrCmpi(ut->Token[0], L"/select") == 0)
			{
				// Selection screen
				cm->CmSettingInitialFlag = CM_SETTING_INIT_SELECT;
			}
		}
	}

	UniFreeToken(ut);

	InitWinUi(_UU("CM_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	// Alpha blending related
	UseAlpha = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "UseAlpha");
	AlphaValue = MsRegReadInt(REG_CURRENT_USER, CM_REG_KEY, "AlphaValue");

	cm->Cedar = NewCedar(NULL, NULL);
	CmInitEnumHub();
}

// Stop the Client Connection Manager
void FreeCM()
{
	if (cm == NULL)
	{
		return;
	}

	CmFreeEnumHub();
	ReleaseCedar(cm->Cedar);

	FreeWinUi();

	// Release the memory
	if (cm->server_name != NULL)
	{
		Free(cm->server_name);
	}
	Free(cm);
	cm = NULL;
}



//////////////////////////////////////////////////////////////////////////
//JumpList ToDo
// By Takao Ito
void *CmUpdateJumpList(UINT start_id)
{
	HMENU h = NULL;
	UINT i;
	RPC_CLIENT_ENUM_ACCOUNT a;
	LIST *o;
	bool easy;

	JL_PCustomDestinationList pcdl;
	JL_PObjectCollection poc;
	JL_PShellLink shell;
	JL_PObjectArray poaRemoved;

	HRESULT hr;

	if (cm->server_name != NULL)
	{
		// Is not used in the case of an external PC
		return NULL;
	}

	//Try to add
	if(SUCCEEDED(JL_CreateCustomDestinationList(&pcdl,APPID_CM)))
	{

		JL_DeleteJumpList(pcdl,APPID_CM);

		easy = cm->CmSetting.EasyMode;

		Zero(&a, sizeof(a));

		
		if (CcEnumAccount(cm->Client, &a) == ERR_NO_ERROR)
		{
			o = NewListFast(CiCompareClientAccountEnumItemByLastConnectDateTime);

			for (i = 0;i < a.NumItem;i++)
			{
				RPC_CLIENT_ENUM_ACCOUNT_ITEM *item = a.Items[i];

				item->tmp1 = i;

				if (item->LastConnectDateTime != 0)
				{
					Add(o, item);
				}
			}

			Sort(o);

			if(LIST_NUM(o) > 0)
			{

				if(SUCCEEDED(JL_BeginList(pcdl, &poaRemoved)))
				{


					//Create a collection
					if(SUCCEEDED(JL_CreateObjectCollection(&poc)))
					{

						for (i = 0;i < MIN(LIST_NUM(o), CM_NUM_RECENT);i++)
						{

							RPC_CLIENT_ENUM_ACCOUNT_ITEM *item = (RPC_CLIENT_ENUM_ACCOUNT_ITEM *)LIST_DATA(o, i);
//							wchar_t tmp[MAX_PATH];
							wchar_t *account_name;
							char *server_name;
							char *hub_name;
//							CM_ACCOUNT *a;
							UCHAR key[SHA1_SIZE];
							RPC_CLIENT_GET_ACCOUNT c;


							account_name = item->AccountName;
							server_name = item->ServerName;
							hub_name = item->HubName;



							//
							//a = CmGetExistAccountObject(hWnd, account_name);


							//if (a == NULL)
							//{
							//continue;
							//}

							//Copy(key, a->ShortcutKey, SHA1_SIZE);
							//

							Zero(&c, sizeof(c));
							UniStrCpy(c.AccountName, sizeof(c.AccountName), account_name);
							if (CALL(NULL, CcGetAccount(cm->Client, &c)) == false)
							{
								break;
							}

							Copy(key, c.ShortcutKey, SHA1_SIZE);

							if (IsZero(key, SHA1_SIZE))
							{
								//MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_SHORTCUT_UNSUPPORTED"));
							}
							else
							{

								//wchar_t target[MAX_PATH];
								////wchar_t workdir[MAX_PATH];
								//wchar_t args[MAX_PATH];
								////wchar_t comment[MAX_SIZE];
								//wchar_t icon[MAX_PATH];

								char key_str[64];
								wchar_t target[MAX_PATH];
								//wchar_t workdir[MAX_PATH];
								wchar_t args[MAX_PATH];
								wchar_t commentW[MAX_SIZE];
								wchar_t icon[MAX_PATH];
								int iconNum;

								//char icon = "C:\\Server.ico";

								BinToStr(key_str, sizeof(key_str), key, SHA1_SIZE);
								UniStrCpy(target, sizeof(target), MsGetExeFileNameW());
								StrToUni(args, sizeof(args), key_str);
								UniStrCpy(icon, sizeof(icon), MsGetExeFileNameW());
								UniFormat(commentW, sizeof(commentW), _UU("CM_SHORTCUT_COMMENT"), account_name);

								if(item->Connected)
								{
									iconNum = 1;
								}
								else
								{
									iconNum = 2;
								}

								hr = JL_CreateShellLink(
									target,
									args,
									account_name,
									icon,iconNum,
									commentW,
									&shell);

								if(SUCCEEDED(hr))
								{

									if(SUCCEEDED(JL_ObjectCollectionAddShellLink(poc, shell)))
									{
										//Print("Add JumpList %d c:%s\n",i, comment);
										//wprintf(comment);
									}
									JL_ReleaseShellLink(shell);
								}
							}

							CiFreeClientGetAccount(&c);
						}

						hr = JL_AddCategoryToList(pcdl,poc,_UU("CM_JUMPLIST_RCCONNECT"),poaRemoved);

						if(SUCCEEDED(hr))
						{
							//wprintf(L"AddCategory\n");

							hr = JL_CommitList(pcdl);
							if(SUCCEEDED(hr))
							{
								//wprintf(L"JumpList Commit\n");
							}
						}
						else
						{
							//wprintf(L"Erro JumpList AddCategory %x\n", hr);
						}

						//Release
						JL_ReleaseObjectCollection(poc);
					}
				}

			}


			ReleaseList(o);

			CiFreeClientEnumAccount(&a);
		}

		


		/*
			JL_BeginList(pcdl, &poaRemoved);

			JL_CreateObjectCollection(&poc);

			// Tesht
			for (i = 0; i < 5; i++)
			{

				JL_CreateShellLink(
					"",
					"",
					L"Connect",
					NULL,0,
					NULL,
					&shell);
				JL_ObjectCollectionAddShellLink(poc, shell);

				JL_ReleaseShellLink(shell);

			}

			JL_AddCategoryToList(pcdl,poc,_UU("CM_JUMPLIST_RCCONNECT"),poaRemoved);
			JL_CommitList(pcdl);
			JL_ReleaseObjectCollection(poc);

		JL_ReleaseCustomDestinationList(pcdl);
		*/

	}

	return h;
}



#endif	// WIN32


