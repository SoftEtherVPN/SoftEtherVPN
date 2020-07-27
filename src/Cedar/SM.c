// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// SM.c
// VPN Server Manager for Win32

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
static SM *sm = NULL;
static bool link_create_now = false;


// Proxy Settings dialog initialization
void SmProxyDlgInit(HWND hWnd, INTERNET_SETTING *t)
{
	// Validate arguments
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	Check(hWnd, R_DIRECT_TCP, t->ProxyType == PROXY_DIRECT);
	Check(hWnd, R_HTTPS, t->ProxyType == PROXY_HTTP);
	Check(hWnd, R_SOCKS, t->ProxyType == PROXY_SOCKS);
	Check(hWnd, R_SOCKS5, t->ProxyType == PROXY_SOCKS5);

	SmProxyDlgUpdate(hWnd, t);
}

// Proxy Settings dialog update
void SmProxyDlgUpdate(HWND hWnd, INTERNET_SETTING *t)
{
	bool ok = false;
	// Validate arguments
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	if (t->ProxyType == PROXY_DIRECT)
	{
		ok = true;
	}
	else
	{
		if (IsEmptyStr(t->ProxyHostName) == false &&
			t->ProxyPort != 0)
		{
			ok = true;
		}
	}

	SetEnable(hWnd, IDOK, ok);

	SetEnable(hWnd, B_PROXY_CONFIG, !IsChecked(hWnd, R_DIRECT_TCP));
}

// Proxy settings generic dialog procedure
UINT SmProxyDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	INTERNET_SETTING *t = (INTERNET_SETTING *)param;
	CLIENT_OPTION a;

	switch (msg)
	{
	case WM_INITDIALOG:
		SmProxyDlgInit(hWnd, t);
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

		case R_DIRECT_TCP:
		case R_HTTPS:
		case R_SOCKS:
			if (IsChecked(hWnd, R_HTTPS))
			{
				t->ProxyType = PROXY_HTTP;
			}
			else if (IsChecked(hWnd, R_SOCKS))
			{
				t->ProxyType = PROXY_SOCKS;
			}
			else if (IsChecked(hWnd, R_SOCKS5))
			{
				t->ProxyType = PROXY_SOCKS5;
			}
			else
			{
				t->ProxyType = PROXY_DIRECT;
			}

			SmProxyDlgUpdate(hWnd, t);
			break;

		case B_PROXY_CONFIG:
			Zero(&a, sizeof(a));

			a.ProxyType = t->ProxyType;
			StrCpy(a.ProxyName, sizeof(a.ProxyName), t->ProxyHostName);
			a.ProxyPort = t->ProxyPort;
			StrCpy(a.ProxyUsername, sizeof(a.ProxyUsername), t->ProxyUsername);
			StrCpy(a.ProxyPassword, sizeof(a.ProxyPassword), t->ProxyPassword);
			StrCpy(a.CustomHttpHeader, sizeof(a.CustomHttpHeader), t->CustomHttpHeader);

			if (CmProxyDlg(hWnd, &a))
			{
				t->ProxyType = a.ProxyType;
				StrCpy(t->ProxyHostName, sizeof(t->ProxyHostName), a.ProxyName);
				t->ProxyPort = a.ProxyPort;
				StrCpy(t->ProxyUsername, sizeof(t->ProxyUsername), a.ProxyUsername);
				StrCpy(t->ProxyPassword, sizeof(t->ProxyPassword), a.ProxyPassword);
				StrCpy(t->CustomHttpHeader, sizeof(t->CustomHttpHeader), a.CustomHttpHeader);
			}

			SmProxyDlgUpdate(hWnd, t);

			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// Proxy Settings generic dialog
bool SmProxy(HWND hWnd, INTERNET_SETTING *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_SM_PROXY, SmProxyDlg, t);
}

// VPN Azure dialog procedure
UINT SmAzureDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_AZURE *a = (SM_AZURE *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		SmAzureDlgOnInit(hWnd, a);

		SetTimer(hWnd, 1, 1000, NULL);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_CHANGE:
			if (SmDDns(hWnd, a->s, false, true))
			{
				SmAzureDlgRefresh(hWnd, a);
			}
			break;

		case B_WEB:
			MsExecute(_SS("SE_VPNAZURE_URL"), NULL);
			break;

		case R_ENABLE:
		case R_DISABLE:
			if (IsChecked(hWnd, R_ENABLE) || IsChecked(hWnd, R_DISABLE))
			{
				Enable(hWnd, IDCANCEL);
				EnableClose(hWnd);
			}

			SmAzureSetStatus(hWnd, a);
			break;

		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (IsEnable(hWnd, 0))
			{
				KillTimer(hWnd, 1);

				SmAzureDlgRefresh(hWnd, a);

				SetTimer(hWnd, 1, 1000, NULL);
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

// Set the status
void SmAzureSetStatus(HWND hWnd, SM_AZURE *a)
{
	RPC_AZURE_STATUS st;
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	Zero(&st, sizeof(st));

	st.IsEnabled = IsChecked(hWnd, R_ENABLE);

	if (CALL(hWnd, ScSetAzureStatus(a->s->Rpc, &st)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	SmAzureDlgRefresh(hWnd, a);
}

// Initialize the dialog
void SmAzureDlgOnInit(HWND hWnd, SM_AZURE *a)
{
	RPC_AZURE_STATUS st;
	UINT current_lang_id;
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_AZURE);

	DlgFont(hWnd, S_TITLE, 14, true);
	DlgFont(hWnd, R_ENABLE, 0, true);

	SetFont(hWnd, E_HOST, GetFont("Verdana", 10, false, false, false, false));

	current_lang_id = GetCurrentLangId();

	// Japanese
	SetShow(hWnd, S_BMP_JA, current_lang_id == SE_LANG_JAPANESE);

	// Chinese
	SetShow(hWnd, S_BMP_CN, current_lang_id == SE_LANG_CHINESE_ZH);

	// Other languages
	SetShow(hWnd, S_BMP_EN, (current_lang_id != SE_LANG_JAPANESE) && (current_lang_id != SE_LANG_CHINESE_ZH));

	// Apply the current settings
	Zero(&st, sizeof(st));

	if (CALL(hWnd, ScGetAzureStatus(a->s->Rpc, &st)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	if (a->OnSetup == false || st.IsEnabled)
	{
		Check(hWnd, R_ENABLE, st.IsEnabled);
		Check(hWnd, R_DISABLE, !st.IsEnabled);
	}
	else
	{
		Disable(hWnd, IDCANCEL);
		DisableClose(hWnd);
	}

	SmAzureDlgRefresh(hWnd, a);
}

// Update the dialog 
void SmAzureDlgRefresh(HWND hWnd, SM_AZURE *a)
{
	RPC_AZURE_STATUS st;
	DDNS_CLIENT_STATUS ddns;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	Zero(&st, sizeof(st));
	Zero(&ddns, sizeof(ddns));

	if (CALL(hWnd, ScGetAzureStatus(a->s->Rpc, &st)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	if (CALL(hWnd, ScGetDDnsClientStatus(a->s->Rpc, &ddns)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	if (st.IsEnabled == false)
	{
		SetText(hWnd, S_STATUS, _UU("SM_AZURE_STATUS_NOT_CONNECTED"));
		Disable(hWnd, S_STATUS);
	}
	else
	{
		SetText(hWnd, S_STATUS, (st.IsConnected ? _UU("SM_AZURE_STATUS_CONNECTED") : _UU("SM_AZURE_STATUS_NOT_CONNECTED")));
		Enable(hWnd, S_STATUS);
	}

	SetShow(hWnd, S_HOSTNAME_BORDER, st.IsEnabled);
	SetShow(hWnd, S_HOSTNAME_INFO, st.IsEnabled);
	SetShow(hWnd, B_CHANGE, st.IsEnabled);

	if (st.IsEnabled == false || IsEmptyStr(ddns.CurrentHostName))
	{
		Hide(hWnd, E_HOST);
	}
	else
	{
		StrCpy(tmp, sizeof(tmp), ddns.CurrentHostName);
		StrCat(tmp, sizeof(tmp), AZURE_DOMAIN_SUFFIX);

		SetTextA(hWnd, E_HOST, tmp);

		Show(hWnd, E_HOST);
	}
}

// VPN Azure Setup screen
void SmAzure(HWND hWnd, SM_SERVER *s, bool on_setup)
{
	SM_AZURE a;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));

	a.s = s;
	a.OnSetup = on_setup;

	Dialog(hWnd, D_SM_AZURE, SmAzureDlg, &a);
}

// Notification screen about the bridge in VM
UINT SmVmBridgeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		DlgFont(hWnd, S_TITLE, 14, true);
		SetIcon(hWnd, 0, ICO_NIC_ONLINE);
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

// Setting screen of VPN over ICMP, etc.
void SmSpecialListener(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_SPECIALLISTENER, SmSpecialListenerDlg, s);
}
UINT SmSpecialListenerDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		SmSpecialListenerDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			SmSpecialListenerDlgOnOk(hWnd, s);
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
void SmSpecialListenerDlgInit(HWND hWnd, SM_SERVER *s)
{
	RPC_SPECIAL_LISTENER t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SPECIALLISTENER);

	DlgFont(hWnd, S_TITLE, 14, true);
	DlgFont(hWnd, S_1, 0, true);
	DlgFont(hWnd, R_OVER_ICMP, 0, true);
	DlgFont(hWnd, R_OVER_DNS, 0, true);

	Zero(&t, sizeof(t));

	if (CALL(hWnd, ScGetSpecialListener(s->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	Check(hWnd, R_OVER_ICMP, t.VpnOverIcmpListener);
	Check(hWnd, R_OVER_DNS, t.VpnOverDnsListener);
}
void SmSpecialListenerDlgOnOk(HWND hWnd, SM_SERVER *s)
{
	RPC_SPECIAL_LISTENER t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	t.VpnOverIcmpListener = IsChecked(hWnd, R_OVER_ICMP);
	t.VpnOverDnsListener = IsChecked(hWnd, R_OVER_DNS);

	if (CALL(hWnd, ScSetSpecialListener(s->Rpc, &t)) == false)
	{
		return;
	}

	EndDialog(hWnd, 1);
}


// DDNS dialog
bool SmDDns(HWND hWnd, SM_SERVER *s, bool silent, bool no_change_cert)
{
	SM_DDNS d;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	Zero(&d, sizeof(d));
	d.s = s;
	d.Silent = silent;
	d.NoChangeCert = no_change_cert;

	Dialog(hWnd, D_SM_DDNS, SmDDnsDlg, &d);

	return d.Changed;
}
UINT SmDDnsDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_DDNS *d = (SM_DDNS *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmDDnsDlgInit(hWnd, d);

		SetTimer(hWnd, 1, 1000, NULL);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_NEWHOST:
			SmDDnsDlgUpdate(hWnd, d);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmDDnsDlgOnOk(hWnd, d);
			break;

		case B_RESTORE:
			// Restore to original
			if (d->Status.Err_IPv4 == ERR_NO_ERROR || d->Status.Err_IPv6 == ERR_NO_ERROR)
			{
				SetTextA(hWnd, E_NEWHOST, d->Status.CurrentHostName);
				SmDDnsDlgUpdate(hWnd, d);
				FocusEx(hWnd, E_NEWHOST);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_DISABLE:
			d->DoNotPoll = true;

			OnceMsg(hWnd, _UU("SM_DISABLE_DDNS_HINT_CAPTION"), _UU("SM_DISABLE_DDNS_HINT"), false, ICO_INFORMATION);

			d->DoNotPoll = false;
			break;

		case B_HINT:
			// Hint
			if (d->Status.Err_IPv4 == ERR_NO_ERROR || d->Status.Err_IPv6 == ERR_NO_ERROR)
			{
				wchar_t tmp[MAX_SIZE * 4];
				wchar_t ipv4[MAX_SIZE], ipv6[MAX_SIZE];

				StrToUni(ipv4, sizeof(ipv4), d->Status.CurrentIPv4);
				StrToUni(ipv6, sizeof(ipv6), d->Status.CurrentIPv6);

				if (UniIsEmptyStr(ipv4))
				{
					UniStrCpy(ipv4, sizeof(ipv4), _UU("SM_DDNS_FQDN_EMPTY"));
				}

				if (UniIsEmptyStr(ipv6))
				{
					UniStrCpy(ipv6, sizeof(ipv6), _UU("SM_DDNS_FQDN_EMPTY"));
				}

				UniFormat(tmp, sizeof(tmp),
					_UU("SM_DDNS_OK_MSG"),
					d->Status.CurrentHostName, d->Status.DnsSuffix,
					ipv4, ipv6,
					d->Status.CurrentHostName, d->Status.DnsSuffix,
					d->Status.CurrentHostName, d->Status.DnsSuffix);

				d->DoNotPoll = true;

				OnceMsg(hWnd, _UU("SM_DDNS_OK_TITLE"), tmp, false, ICO_DISPLAY);

				d->DoNotPoll = false;
			}
			break;

		case B_HINT2:
			// Hint2 (for DDNS key)
			{
				wchar_t tmp[MAX_SIZE * 4];
				wchar_t *keystr;

				keystr = GetText(hWnd, E_KEY);
				UniFormat(tmp, sizeof(tmp), _UU("SM_DDNS_KEY_MSG"), keystr);
				Free(keystr);
				OnceMsg(hWnd, _UU("SM_DDNS_KEY_TITLE"), tmp, false, ICO_DISPLAY);
			}
			break;

		case B_PROXY:
			// Proxy settings
			if (true)
			{
				INTERNET_SETTING t;

				if (CALL(hWnd, ScGetDDnsInternetSetting(d->s->Rpc, &t)))
				{
					if (SmProxy(hWnd, &t))
					{
						if (CALL(hWnd, ScSetDDnsInternetSetting(d->s->Rpc, &t)))
						{
							SmDDnsRefresh(hWnd, d);
						}
					}
				}
			}
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (IsEnable(hWnd, 0))
			{
				KillTimer(hWnd, 1);

				SmDDnsRefresh(hWnd, d);

				SetTimer(hWnd, 1, 1000, NULL);
			}
			break;
		}
		break;

	case WM_CLOSE:
		if (d->Changed || d->Silent)
		{
			// Check the server certificate if the host name has been changed
			RPC_KEY_PAIR t;
			char fqdn[MAX_SIZE];
			bool is_vgs_enabled = false;


			StrCpy(fqdn, sizeof(fqdn), d->Status.CurrentFqdn);

			if (IsEmptyStr(fqdn) == false)
			{
				Zero(&t, sizeof(t));
				if (ScGetServerCert(d->s->Rpc, &t) == ERR_NO_ERROR)
				{
					if (t.Cert != NULL && t.Cert->root_cert && t.Cert->subject_name != NULL && is_vgs_enabled == false)
					{
						char cn[MAX_SIZE];

						UniToStr(cn, sizeof(cn), t.Cert->subject_name->CommonName);

						if ((StrCmpi(cn, fqdn) != 0) && (d->NoChangeCert == false))
						{
							// Confirm whether the user want to replace the server certificate
							if (d->Silent || (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO,
								_UU("SM_DDNS_SERVER_CERT_MSG"),
								fqdn, fqdn) == IDYES))
							{
								// Re-generate the server certificate
								RPC_TEST tt;

								Zero(&tt, sizeof(tt));

								StrCpy(tt.StrValue, sizeof(tt.StrValue), fqdn);

								SetText(hWnd, IDCANCEL, _UU("CM_VLAN_INSTALLING"));
								Refresh(DlgItem(hWnd, IDCANCEL));
								Refresh(hWnd);
								DoEvents(NULL);

								if (CALL(hWnd, ScRegenerateServerCert(d->s->Rpc, &tt)))
								{
									// Confirm whether the user want to save the server certificate
									if ((d->Silent == false) && (
										MsgBoxEx(hWnd, MB_ICONINFORMATION | MB_YESNO,
										_UU("SM_DDNS_SERVER_CERT_OK"),
										fqdn) == IDYES))
									{
										// Get the server certificate
										RPC_KEY_PAIR t2;

										Zero(&t2, sizeof(t2));
										if (CALL(hWnd, ScGetServerCert(d->s->Rpc, &t2)))
										{
											wchar_t *name;
											wchar_t defname[MAX_PATH];

											StrToUni(defname, sizeof(defname), fqdn);
											UniStrCat(defname, sizeof(defname), L".cer");
											
											name = SaveDlg(hWnd, _UU("DLG_CERT_FILES"), _UU("DLG_SAVE_CERT"), defname, L".cer");

											if (name != NULL)
											{
												if (XToFileW(t2.Cert, name, true))
												{
													MsgBox(hWnd, MB_ICONINFORMATION, _UU("DLG_CERT_SAVE_OK"));
												}
												else
												{
													MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_CERT_SAVE_ERROR"));
												}

												Free(name);
											}

											FreeRpcKeyPair(&t2);
										}
									}
								}
							}
						}
					}

					FreeRpcKeyPair(&t);
				}
			}
		}

		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// Get the ddns key from the server configuration file
static UINT SmDdnsGetKey(char *key, SM_DDNS *d){
	RPC_CONFIG config;
	UINT err;
	BUF *buf;
	FOLDER *root, *ddnsfolder;
	RPC *rpc;

	// Validate arguments
	if(d == NULL || d->s == NULL || key == NULL){
		return ERR_INTERNAL_ERROR;
	}

	rpc = d->s->Rpc;

	Zero(&config, sizeof(config));
	err = ScGetConfig(d->s->Rpc, &config);
	if(err != ERR_NO_ERROR){
		return err;
	}

	buf = NewBufFromMemory(config.FileData, StrLen(config.FileData));
	FreeRpcConfig(&config);

	root = CfgBufTextToFolder(buf);
	FreeBuf(buf);

	ddnsfolder = CfgGetFolder(root, "DDnsClient");
	err = CfgGetByte(ddnsfolder, "Key", key, 20);

	CfgDeleteFolder(root);

	return (err == 20) ? ERR_NO_ERROR : ERR_INTERNAL_ERROR;
}

void SmDDnsDlgInit(HWND hWnd, SM_DDNS *d)
{
	char key[20];
	char encodedkey[20 * 4 + 32];

	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	d->DoNotPoll = false;

	SetIcon(hWnd, 0, ICO_DISPLAY);

	DlgFont(hWnd, S_TITLE, 14, true);

	DlgFont(hWnd, S_BOLD, 0, true);
	DlgFont(hWnd, S_STATUS3, 0, true);
	DlgFont(hWnd, S_STATUS4, 0, true);
	DlgFont(hWnd, S_STATUS5, 0, true);
	DlgFont(hWnd, S_STATUS6, 0, true);
	DlgFont(hWnd, S_STATUS8, 0, true);

	SetFont(hWnd, S_SUFFIX, GetFont("Verdana", 10, false, false, false, false));
	SetFont(hWnd, E_NEWHOST, GetFont("Verdana", 10, false, false, false, false));

	SetFont(hWnd, E_HOST, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 10, false, false, false, false));
	SetFont(hWnd, E_IPV4, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 10, false, false, false, false));
	SetFont(hWnd, E_IPV6, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 10, false, false, false, false));
	SetFont(hWnd, E_KEY, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 8, false, false, false, false));

	DlgFont(hWnd, IDOK, 0, true);

	if (d->Silent)
	{
		Hide(hWnd, B_DISABLE);
	}

	Hide(hWnd, B_PROXY);

	if(SmDdnsGetKey(key, d) == ERR_NO_ERROR){
		encodedkey[ B64_Encode(encodedkey, key, 20) ] = 0;
		SetTextA(hWnd, E_KEY, encodedkey);
	}else{
		SetText(hWnd, E_KEY, _UU("SM_DDNS_KEY_ERR"));
	}

	SmDDnsRefresh(hWnd, d);
}

void SmDDnsRefresh(HWND hWnd, SM_DDNS *d)
{
	DDNS_CLIENT_STATUS st;
	INTERNET_SETTING t;

	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	if (d->DoNotPoll)
	{
		return;
	}

	Zero(&st, sizeof(st));
	Zero(&t, sizeof(t));

	// Get the status
	if (CALL(hWnd, ScGetDDnsClientStatus(d->s->Rpc, &st)) == false)
	{
		Close(hWnd);
		return;
	}

	ScGetDDnsInternetSetting(d->s->Rpc, &t);

	Copy(&d->Status, &st, sizeof(st));

	if (IsEmptyStr(st.CurrentFqdn) == false)
	{
		SetTextA(hWnd, E_HOST, st.CurrentFqdn);
	}
	else
	{
		SetText(hWnd, E_HOST, _UU("SM_DDNS_FQDN_EMPTY"));
	}

	if (st.Err_IPv4 == ERR_NO_ERROR)
	{
		SetTextA(hWnd, E_IPV4, st.CurrentIPv4);
	}
	else
	{
		if (st.Err_IPv4 == ERR_CONNECT_FAILED)
		{
			SetText(hWnd, E_IPV4, _UU("SM_DDNS_IPV4_ERROR"));
		}
		else
		{
			SetText(hWnd, E_IPV4, _E(st.Err_IPv4));
		}
	}

	if (st.Err_IPv6 == ERR_NO_ERROR)
	{
		SetTextA(hWnd, E_IPV6, st.CurrentIPv6);
	}
	else
	{
		if (st.Err_IPv6 == ERR_CONNECT_FAILED)
		{
			SetText(hWnd, E_IPV6, _UU("SM_DDNS_IPV6_ERROR"));
		}
		else
		{
			SetText(hWnd, E_IPV6, _E(st.Err_IPv6));
		}
	}

	if (st.Err_IPv4 == ERR_NO_ERROR || st.Err_IPv6 == ERR_NO_ERROR)
	{
		if (IsEmptyStr(st.DnsSuffix) == false)
		{
			SetTextA(hWnd, S_SUFFIX, st.DnsSuffix);
		}

		Enable(hWnd, S_STATUS6);
		Enable(hWnd, E_NEWHOST);
		Enable(hWnd, S_SUFFIX);
		Enable(hWnd, S_STATUS7);
		Enable(hWnd, B_HINT);
	}
	else
	{
		SetTextA(hWnd, S_SUFFIX, "");

		Disable(hWnd, S_STATUS6);
		Disable(hWnd, E_NEWHOST);
		Disable(hWnd, S_SUFFIX);
		Disable(hWnd, S_STATUS7);
		Disable(hWnd, B_HINT);
	}

	if (GetCapsBool(d->s->CapsList, "b_support_ddns_proxy"))
	{
		// Show the proxy button
		Show(hWnd, B_PROXY);
	}
	else
	{
		// Hide the proxy button
		Hide(hWnd, B_PROXY);
	}

	SmDDnsDlgUpdate(hWnd, d);

	if (d->Flag == false)
	{
		d->Flag = true;
	}

	if (IsEmptyStr(st.CurrentHostName) == false)
	{
		if (d->HostnameSetFlag == false)
		{
			d->HostnameSetFlag = true;

			SetTextA(hWnd, E_NEWHOST, st.CurrentHostName);

			FocusEx(hWnd, E_NEWHOST);
		}
	}
}
void SmDDnsDlgUpdate(HWND hWnd, SM_DDNS *d)
{
	char tmp[MAX_SIZE];
	bool b = false;

	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	if (GetTxtA(hWnd, E_NEWHOST, tmp, sizeof(tmp)))
	{
		Trim(tmp);

		// Get whether the host name have changed
		if (IsEmptyStr(tmp) == false)
		{
			if (StrCmpi(d->Status.CurrentHostName, tmp) != 0)
			{
				if (d->Status.Err_IPv4 == ERR_NO_ERROR || d->Status.Err_IPv6 == ERR_NO_ERROR)
				{
					b = true;
				}
			}
		}
	}

	SetEnable(hWnd, IDOK, b);
	SetEnable(hWnd, B_RESTORE, b);
}
void SmDDnsDlgOnOk(HWND hWnd, SM_DDNS *d)
{
	RPC_TEST t;
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	GetTxtA(hWnd, E_NEWHOST, t.StrValue, sizeof(t.StrValue));

	if (CALL(hWnd, ScChangeDDnsClientHostname(d->s->Rpc, &t)) == false)
	{
		return;
	}

	d->Changed = true;

	SmDDnsRefresh(hWnd, d);
	FocusEx(hWnd, E_NEWHOST);

	MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("SM_DDNS_OK_MSG2"), t.StrValue);
	FocusEx(hWnd, E_NEWHOST);
}

// Open the OpenVPN dialog 
void SmOpenVpn(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_OPENVPN, SmOpenVpnDlg, s);
}

// OpenVPN dialog
UINT SmOpenVpnDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmOpenVpnDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_OPENVPN:
		case R_SSTP:
			SmOpenVpnDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmOpenVpnDlgOnOk(hWnd, s, false);
			break;

		case B_CONFIG:
			// Create an OpenVPN configuration
			{
				OPENVPN_SSTP_CONFIG t2;
				RPC_READ_LOG_FILE t;

				Zero(&t2, sizeof(t2));

				if (CALL(hWnd, ScGetOpenVpnSstpConfig(s->Rpc, &t2)))
				{
					if (t2.EnableOpenVPN == false)
					{
						// Enable the OpenVPN first
						SmOpenVpnDlgOnOk(hWnd, s, true);

						Disable(hWnd, IDCANCEL);
					}
				}
				else
				{
					break;
				}

				Zero(&t, sizeof(t));

				if (CALL(hWnd, ScMakeOpenVpnConfigFile(s->Rpc, &t)))
				{
					// Generate a file name 
					wchar_t filename[MAX_SIZE];
					char safe_hostname[MAX_SIZE];
					SYSTEMTIME st;
					wchar_t *dst;

					MakeSafeFileName(safe_hostname, sizeof(safe_hostname), s->ServerName);

					LocalTime(&st);

					UniFormat(filename, sizeof(filename),
						L"OpenVPN_Sample_Config_%S_%04u%02u%02u_%02u%02u%02u.zip",
						safe_hostname,
						st.wYear, st.wMonth, st.wDay,
						st.wHour, st.wMinute, st.wSecond);

					dst = SaveDlg(hWnd, _UU("DLG_ZIP_FILER"), _UU("DLG_SAVE_OPENVPN_CONFIG"),
						filename, L".zip");

					if (dst != NULL)
					{
						// Save
						if (DumpBufW(t.Buffer, dst) == false)
						{
							// Failure
							MsgBoxEx(hWnd, MB_ICONSTOP, _UU("SM_OPENVPN_CONFIG_SAVE_NG"), dst);
						}
						else
						{
							// Success
							if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("SM_OPENVPN_CONFIG_SAVE_OK"), dst) == IDYES)
							{
								if (MsExecuteW(dst, L"") == false)
								{
									MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("SM_OPENVPN_CONFIG_OPEN_NG"), dst);
								}
							}
						}

						Free(dst);
					}

					FreeRpcReadLogFile(&t);
				}
			}
			break;

		case B_IPSEC:
			SmIPsec(hWnd, s);
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
void SmOpenVpnDlgInit(HWND hWnd, SM_SERVER *s)
{
	OPENVPN_SSTP_CONFIG t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScGetOpenVpnSstpConfig(s->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	Check(hWnd, R_OPENVPN, t.EnableOpenVPN);
	Check(hWnd, R_SSTP, t.EnableSSTP);

	SetIcon(hWnd, 0, ICO_OPENVPN);

	DlgFont(hWnd, S_TITLE, 14, true);

	DlgFont(hWnd, R_OPENVPN, 0, true);
	DlgFont(hWnd, S_TOOL, 11, true);
	DlgFont(hWnd, R_SSTP, 0, true);

	SmOpenVpnDlgUpdate(hWnd, s);
}
void SmOpenVpnDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	bool b1, b2;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	b1 = IsChecked(hWnd, R_OPENVPN);
	b2 = IsChecked(hWnd, R_SSTP);

	SetEnable(hWnd, S_TOOL, b1);
	SetEnable(hWnd, S_TOOL2, b1);
	SetEnable(hWnd, B_CONFIG, b1);

	SetEnable(hWnd, S_SSTP, b2);
}
void SmOpenVpnDlgOnOk(HWND hWnd, SM_SERVER *s, bool no_close)
{
	OPENVPN_SSTP_CONFIG t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	t.EnableOpenVPN = IsChecked(hWnd, R_OPENVPN);
	t.EnableSSTP = IsChecked(hWnd, R_SSTP);

	if (CALL(hWnd, ScSetOpenVpnSstpConfig(s->Rpc, &t)) == false)
	{
		return;
	}

	if (no_close == false)
	{
		EndDialog(hWnd, 1);
	}
}

// Open the EtherIP ID edit dialog
bool SmEtherIpId(HWND hWnd, SM_ETHERIP_ID *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return false;
	}

	if (Dialog(hWnd, D_SM_ETHERIP_ID, SmEtherIpIdDlg, t) == 0)
	{
		return false;
	}

	return true;
}

// EtherIP ID edit dialog procedure
UINT SmEtherIpIdDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_ETHERIP_ID *t = (SM_ETHERIP_ID *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmEtherIpIdDlgInit(hWnd, t);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_ID:
		case L_HUBNAME:
		case E_USERNAME:
			SmEtherIpIdDlgUpdate(hWnd, t);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmEtherIpIdDlgOnOk(hWnd, t);
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

// Initialize the EtherIP ID edit dialog
void SmEtherIpIdDlgInit(HWND hWnd, SM_ETHERIP_ID *t)
{
	RPC_ENUM_HUB tt;
	UINT sel_index;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_KEY);

	// Get the current data in the case of edit mode
	if (t->EditMode)
	{
		Zero(&t->Data, sizeof(t->Data));
		StrCpy(t->Data.Id, sizeof(t->Data.Id), t->EditId);

		if (CALL(hWnd, ScGetEtherIpId(t->s->Rpc, &t->Data)) == false)
		{
			EndDialog(hWnd, 0);
			return;
		}
	}

	// Enumerate the Virtual HUBs
	Zero(&tt, sizeof(tt));
	if (CALL(hWnd, ScEnumHub(t->s->Rpc, &tt)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	CbReset(hWnd, L_HUBNAME);
	CbSetHeight(hWnd, L_HUBNAME, 18);
	sel_index = INFINITE;

	for (i = 0;i < tt.NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &tt.Hubs[i];
		UINT index;

		index = CbAddStrA(hWnd, L_HUBNAME, e->HubName, 0);
		if (sel_index == INFINITE)
		{
			sel_index = index;
		}

		if (t->EditMode)
		{
			if (StrCmpi(e->HubName, t->Data.HubName) == 0)
			{
				sel_index = index;
			}
		}
	}

	if (sel_index != INFINITE)
	{
		CbSelectIndex(hWnd, L_HUBNAME, sel_index);
	}

	if (t->EditMode)
	{
		SetTextA(hWnd, E_ID, t->Data.Id);
		SetTextA(hWnd, E_USERNAME, t->Data.UserName);
		SetTextA(hWnd, E_PASSWORD, t->Data.Password);

		FocusEx(hWnd, E_PASSWORD);
	}
	else
	{
		Focus(hWnd, E_ID);
	}

	FreeRpcEnumHub(&tt);

	t->InitCompleted = true;
	SmEtherIpIdDlgUpdate(hWnd, t);
}

// EtherIP ID edit dialog: Click the OK button
void SmEtherIpIdDlgOnOk(HWND hWnd, SM_ETHERIP_ID *t)
{
	// Validate arguments
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	SmEtherIpIdDlgGetSetting(hWnd, t);

	if (t->EditMode)
	{
		ETHERIP_ID d;
		// Delete old items
		Zero(&d, sizeof(d));

		StrCpy(d.Id, sizeof(d.Id), t->EditId);

		ScDeleteEtherIpId(t->s->Rpc, &d);
	}

	if (CALL(hWnd, ScAddEtherIpId(t->s->Rpc, &t->Data)) == false)
	{
		return;
	}

	if (t->EditMode == false)
	{
		MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_ETHERIP_ADD_OK"));
	}

	EndDialog(hWnd, 1);
}

// EtherIP ID edit dialog: Update the controls
void SmEtherIpIdDlgUpdate(HWND hWnd, SM_ETHERIP_ID *t)
{
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	if (t->InitCompleted == false)
	{
		return;
	}

	SmEtherIpIdDlgGetSetting(hWnd, t);

	if (IsEmptyStr(t->Data.Id) ||
		IsEmptyStr(t->Data.HubName) ||
		IsEmptyStr(t->Data.UserName))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
}

// EtherIP ID edit dialog: Get the current settings
void SmEtherIpIdDlgGetSetting(HWND hWnd, SM_ETHERIP_ID *t)
{
	wchar_t *ws;
	// Validate arguments
	if (hWnd == NULL || t == NULL)
	{
		return;
	}

	Zero(&t->Data, sizeof(t->Data));

	GetTxtA(hWnd, E_ID, t->Data.Id, sizeof(t->Data.Id));
	GetTxtA(hWnd, E_USERNAME, t->Data.UserName, sizeof(t->Data.UserName));
	GetTxtA(hWnd, E_PASSWORD, t->Data.Password, sizeof(t->Data.Password));

	ws = CbGetStr(hWnd, L_HUBNAME);

	if (ws != NULL && IsEmptyUniStr(ws) == false)
	{
		UniToStr(t->Data.HubName, sizeof(t->Data.HubName), ws);
	}

	Free(ws);
}


// Open the EtherIP settings dialog
void SmEtherIp(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_ETHERIP, SmEtherIpDlg, s);
}

// EtherIP Setup dialog procedure
UINT SmEtherIpDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;
	NMHDR *n;
	char *id;
	SM_ETHERIP_ID t;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmEtherIpDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// Edit
			id = LvGetSelectedStrA(hWnd, L_LIST, 0);
			if (id != NULL)
			{
				Zero(&t, sizeof(t));
				StrCpy(t.EditId, sizeof(t.EditId), id);
				t.EditMode = true;
				t.s = s;

				if (SmEtherIpId(hWnd, &t))
				{
					SmEtherIpDlgRefresh(hWnd, s);
				}

				Free(id);
			}
			break;

		case B_ADD:
			// Add
			Zero(&t, sizeof(t));
			t.s = s;
			if (SmEtherIpId(hWnd, &t))
			{
				SmEtherIpDlgRefresh(hWnd, s);
			}
			break;

		case B_DELETE:
			// Delete
			if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("SM_CRL_DELETE_MSG")) == IDYES)
			{
				id = LvGetSelectedStrA(hWnd, L_LIST, 0);
				if (id != NULL)
				{
					ETHERIP_ID d;

					Zero(&d, sizeof(d));

					StrCpy(d.Id, sizeof(d.Id), id);

					if (CALL(hWnd, ScDeleteEtherIpId(s->Rpc, &d)))
					{
						SmEtherIpDlgRefresh(hWnd, s);
					}

					Free(id);
				}
			}
			break;

		case IDCANCEL:
			// Close
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmEtherIpDlgUpdate(hWnd, s);
				break;

			case NM_DBLCLK:
				Command(hWnd, IDOK);
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

// EtherIP Setup dialog data update
void SmEtherIpDlgRefresh(HWND hWnd, SM_SERVER *s)
{
	RPC_ENUM_ETHERIP_ID t;
	UINT i;
	LVB *b;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	// Data update
	Zero(&t, sizeof(t));

	if (CALL(hWnd, ScEnumEtherIpId(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumItem;i++)
	{
		ETHERIP_ID *d = &t.IdList[i];
		wchar_t id[MAX_SIZE], hubname[MAX_SIZE], username[MAX_SIZE];

		StrToUni(id, sizeof(id), d->Id);
		StrToUni(hubname, sizeof(hubname), d->HubName);
		StrToUni(username, sizeof(username), d->UserName);

		LvInsertAdd(b, ICO_CASCADE, NULL, 3, id, hubname, username);
	}

	LvInsertEnd(b, hWnd, L_LIST);

	FreeRpcEnumEtherIpId(&t);

	SmEtherIpDlgUpdate(hWnd, s);
}

// Initialize the EtherIP settings dialog
void SmEtherIpDlgInit(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_MACHINE);
	DlgFont(hWnd, S_TITLE, 14, true);
	DlgFont(hWnd, S_BOLD, 0, true);

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_ETHERIP_COLUMN_0"), 205);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_ETHERIP_COLUMN_1"), 179);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_ETHERIP_COLUMN_2"), 154);

	SmEtherIpDlgRefresh(hWnd, s);
}

// EtherIP Settings dialog controls update
void SmEtherIpDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetEnable(hWnd, IDOK, LvIsSingleSelected(hWnd, L_LIST));
	SetEnable(hWnd, B_DELETE, LvIsSingleSelected(hWnd, L_LIST));
}

// IPsec Settings dialog procedure
UINT SmIPsecDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmIPsecDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_L2TP_OVER_IPSEC:
		case R_L2TP_RAW:
		case R_ETHERIP:
		case E_SECRET:
		case L_HUBNAME:
			SmIPsecDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmIPsecDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_DETAIL:
			// Advanced Settings dialog for EtherIP function
			SmEtherIp(hWnd, s);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// IPsec Settings dialog: controls update
void SmIPsecDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	IPSEC_SERVICES sl;
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SmIPsecDlgGetSetting(hWnd, &sl);

	//SetEnable(hWnd, S_1, sl.L2TP_IPsec || sl.L2TP_Raw);
	//SetEnable(hWnd, S_2, sl.L2TP_IPsec || sl.L2TP_Raw);
	//SetEnable(hWnd, L_HUBNAME, sl.L2TP_IPsec || sl.L2TP_Raw);

	SetEnable(hWnd, S_PSK, sl.L2TP_IPsec || sl.EtherIP_IPsec);
	SetEnable(hWnd, S_PSK2, sl.L2TP_IPsec || sl.EtherIP_IPsec);
	SetEnable(hWnd, E_SECRET, sl.L2TP_IPsec || sl.EtherIP_IPsec);

	SetEnable(hWnd, B_DETAIL, sl.EtherIP_IPsec);

	if ((sl.L2TP_IPsec || sl.EtherIP_IPsec) && IsEmptyStr(sl.IPsec_Secret))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
}

// Get the IPsec configuration into the structure
void SmIPsecDlgGetSetting(HWND hWnd, IPSEC_SERVICES *sl)
{
	wchar_t *ws;
	// Validate arguments
	if (hWnd == NULL || sl == NULL)
	{
		return;
	}

	Zero(sl, sizeof(IPSEC_SERVICES));

	sl->L2TP_IPsec = IsChecked(hWnd, R_L2TP_OVER_IPSEC);
	sl->L2TP_Raw = IsChecked(hWnd, R_L2TP_RAW);
	sl->EtherIP_IPsec = IsChecked(hWnd, R_ETHERIP);

	ws = CbGetStr(hWnd, L_HUBNAME);
	if (ws != NULL && IsEmptyUniStr(ws) == false)
	{
		UniToStr(sl->L2TP_DefaultHub, sizeof(sl->L2TP_DefaultHub), ws);
	}

	Free(ws);

	GetTxtA(hWnd, E_SECRET, sl->IPsec_Secret, sizeof(sl->IPsec_Secret));
}

// IPsec Settings dialog initialization
void SmIPsecDlgInit(HWND hWnd, SM_SERVER *s)
{
	IPSEC_SERVICES sl;
	RPC_ENUM_HUB t;
	UINT i;
	UINT sel_index;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_IPSEC);

	DlgFont(hWnd, S_TITLE, 14, true);
	SetFont(hWnd, E_SECRET, GetFont("Verdana", 10, false, false, false, false));

	DlgFont(hWnd, R_L2TP_OVER_IPSEC, 0, true);
	DlgFont(hWnd, R_L2TP_RAW, 0, true);
	DlgFont(hWnd, R_ETHERIP, 0, true);

	// Get the configuration
	Zero(&sl, sizeof(sl));
	if (CALL(hWnd, ScGetIPsecServices(s->Rpc, &sl)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	SetTextA(hWnd, E_SECRET, sl.IPsec_Secret);

	Check(hWnd, R_L2TP_OVER_IPSEC, sl.L2TP_IPsec);
	Check(hWnd, R_L2TP_RAW, sl.L2TP_Raw);
	Check(hWnd, R_ETHERIP, sl.EtherIP_IPsec);

	// Enumerate the Virtual HUBs
	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumHub(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, 0);
		return;
	}

	CbReset(hWnd, L_HUBNAME);
	CbSetHeight(hWnd, L_HUBNAME, 18);

	sel_index = INFINITE;
	for (i = 0;i < t.NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];
		UINT index;

		index = CbAddStrA(hWnd, L_HUBNAME, e->HubName, 0);
		if (sel_index == INFINITE)
		{
			sel_index = index;
		}

		if (StrCmpi(e->HubName, sl.L2TP_DefaultHub) == 0)
		{
			sel_index = index;
		}
	}

	if (sel_index != INFINITE)
	{
		CbSelectIndex(hWnd, L_HUBNAME, sel_index);
	}

	FreeRpcEnumHub(&t);

	SmIPsecDlgUpdate(hWnd, s);
}

// IPsec Settings dialog: on click the OK button
void SmIPsecDlgOnOk(HWND hWnd, SM_SERVER *s)
{
	IPSEC_SERVICES sl;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SmIPsecDlgGetSetting(hWnd, &sl);

	// Confirm the length of the PSK
	if (StrLen(sl.IPsec_Secret) >= 10)
	{
		IPSEC_SERVICES sl_old;
		if (ScGetIPsecServices(s->Rpc, &sl_old) == ERR_NO_ERROR)
		{
			if (StrCmp(sl_old.IPsec_Secret, sl.IPsec_Secret) != 0 || ((sl_old.EtherIP_IPsec == false && sl_old.L2TP_IPsec == false)))
			{
				if (sl.EtherIP_IPsec || sl.L2TP_IPsec)
				{
					// Show a warning message if it exceeds 10 characters (Only if there is a change)
					if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO, _UU("SM_IPSEC_PSK_TOO_LONG")) == IDYES)
					{
						FocusEx(hWnd, E_SECRET);
						return;
					}
				}
			}
		}
	}

	if (CALL(hWnd, ScSetIPsecServices(s->Rpc, &sl)) == false)
	{
		return;
	}

	EndDialog(hWnd, 1);
}

// Start the IPsec Settings dialog
void SmIPsec(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_IPSEC, SmIPsecDlg, s);
}

// Message Settings
void SmHubMsg(HWND hWnd, SM_EDIT_HUB *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_MSG, SmHubMsgDlg, s);
}

// Message dialog procedure
UINT SmHubMsgDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_HUB *s = (SM_EDIT_HUB *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmHubMsgDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_TEXT:
			SmHubMsgDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmHubMsgDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case C_USEMSG:
			SmHubMsgDlgUpdate(hWnd, s);

			if (IsChecked(hWnd, C_USEMSG))
			{
				FocusEx(hWnd, E_TEXT);
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

// Message dialog initialization
void SmHubMsgDlgInit(HWND hWnd, SM_EDIT_HUB *s)
{
	RPC_MSG t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (MsIsVista())
	{
		SetFont(hWnd, E_TEXT, GetMeiryoFont());
	}
	else
	{
		DlgFont(hWnd, E_TEXT, 11, false);
	}

	FormatText(hWnd, S_MSG_2, s->HubName);

	LimitText(hWnd, E_TEXT, HUB_MAXMSG_LEN);

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (CALL(hWnd, ScGetHubMsg(s->p->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	if (UniIsEmptyStr(t.Msg) == false)
	{
		SetText(hWnd, E_TEXT, t.Msg);

		Check(hWnd, C_USEMSG, true);
	}
	else
	{
		Check(hWnd, C_USEMSG, false);
	}

	FreeRpcMsg(&t);

	SmHubMsgDlgUpdate(hWnd, s);
}

// [OK] button
void SmHubMsgDlgOnOk(HWND hWnd, SM_EDIT_HUB *s)
{
	RPC_MSG t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (IsChecked(hWnd, C_USEMSG) == false)
	{
		t.Msg = CopyUniStr(L"");
	}
	else
	{
		t.Msg = GetText(hWnd, E_TEXT);
	}

	if (CALL(hWnd, ScSetHubMsg(s->p->Rpc, &t)) == false)
	{
		return;
	}

	FreeRpcMsg(&t);

	EndDialog(hWnd, 1);
}

// Message dialog update
void SmHubMsgDlgUpdate(HWND hWnd, SM_EDIT_HUB *s)
{
	bool b = true;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetEnable(hWnd, E_TEXT, IsChecked(hWnd, C_USEMSG));

	if (IsChecked(hWnd, C_USEMSG))
	{
		wchar_t *s = GetText(hWnd, E_TEXT);

		b = !IsEmptyUniStr(s);

		Free(s);
	}

	SetEnable(hWnd, IDOK, b);
}

// VLAN utility
void SmVLan(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_VLAN, SmVLanDlg, s);
}

// VLAN dialog
UINT SmVLanDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;
	NMHDR *n;

	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmVLanDlgInit(hWnd, s);

		if (LvNum(hWnd, L_LIST) == 0)
		{
			Disable(hWnd, L_LIST);
			SetTimer(hWnd, 1, 100, NULL);
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("SM_VLAN_NOTHING"),
				s->CurrentSetting->ClientOption.Hostname);
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

		case B_ENABLE:
		case B_DISABLE:
			{
				UINT i = LvGetSelected(hWnd, L_LIST);
				if (i != INFINITE)
				{
					char *name = LvGetStrA(hWnd, L_LIST, i, 0);

					if (IsEmptyStr(name) == false)
					{
						RPC_TEST t;

						Zero(&t, sizeof(t));

						StrCpy(t.StrValue, sizeof(t.StrValue), name);
						t.IntValue = BOOL_TO_INT(wParam == B_ENABLE);

						if (CALL(hWnd, ScSetEnableEthVLan(s->Rpc, &t)))
						{
							SmVLanDlgRefresh(hWnd, s);

							if (wParam == B_ENABLE)
							{
								MsgBoxEx(hWnd, MB_ICONINFORMATION,
									_UU("SM_VLAN_MSG_1"),
									name, name, name);
							}
							else
							{
								MsgBoxEx(hWnd, MB_ICONINFORMATION,
									_UU("SM_VLAN_MSG_2"),
									name);
							}
						}
					}

					Free(name);
				}
				break;
			}
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmVLanDlgUpdate(hWnd, s);
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

// VLAN dialog initialization
void SmVLanDlgInit(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_VLAN_COLUMN_0"), 245);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_VLAN_COLUMN_1"), 75);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_VLAN_COLUMN_2"), 100);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_VLAN_COLUMN_3"), 100);
	LvInsertColumn(hWnd, L_LIST, 4, _UU("SM_VLAN_COLUMN_4"), 290);
	LvInsertColumn(hWnd, L_LIST, 5, _UU("SM_VLAN_COLUMN_5"), 430);

	SmVLanDlgRefresh(hWnd, s);
}

// VLAN dialog content update
void SmVLanDlgRefresh(HWND hWnd, SM_SERVER *s)
{
	LVB *b;
	RPC_ENUM_ETH_VLAN t;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumEthVLan(s->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_ETH_VLAN_ITEM *e = &t.Items[i];

		if (e->Support)
		{
			wchar_t tmp0[MAX_SIZE];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t *tmp3;
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];

			StrToUni(tmp0, sizeof(tmp0), e->DeviceName);
			StrToUni(tmp1, sizeof(tmp1), e->DriverType);
			StrToUni(tmp2, sizeof(tmp2), e->DriverName);
			tmp3 = (e->Enabled ? _UU("SM_VLAN_YES") : _UU("SM_VLAN_NO"));
			StrToUni(tmp4, sizeof(tmp4), e->Guid);
			StrToUni(tmp5, sizeof(tmp5), e->DeviceInstanceId);

			LvInsertAdd(b,
				e->Enabled ? ICO_NIC_ONLINE : ICO_NIC_OFFLINE, 0, 6,
				tmp0, tmp1, tmp2, tmp3, tmp4, tmp5);
		}
	}

	LvInsertEnd(b, hWnd, L_LIST);

	FreeRpcEnumEthVLan(&t);

	SmVLanDlgUpdate(hWnd, s);
}

// VLAN dialog control update
void SmVLanDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSingleSelected(hWnd, L_LIST) == false)
	{
		Disable(hWnd, B_ENABLE);
		Disable(hWnd, B_DISABLE);
	}
	else
	{
		UINT i = LvGetSelected(hWnd, L_LIST);
		if (i != INFINITE)
		{
			wchar_t *s = LvGetStr(hWnd, L_LIST, i, 3);

			if (UniStrCmpi(s, _UU("SM_VLAN_YES")) != 0)
			{
				Enable(hWnd, B_ENABLE);
				Disable(hWnd, B_DISABLE);
			}
			else
			{
				Enable(hWnd, B_DISABLE);
				Disable(hWnd, B_ENABLE);
			}

			Free(s);
		}
	}
}

// Examine whether the current state of VPN Server / VPN Bridge is the initial state
bool SmSetupIsNew(SM_SERVER *s)
{
	RPC *rpc;
	bool is_bridge;
	char hubname[MAX_HUBNAME_LEN + 1];
	bool check_hub = false;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	if (s->ServerAdminMode == false)
	{
		return false;
	}

	rpc = s->Rpc;
	is_bridge =s->Bridge;

	// Server type
	if (is_bridge == false)
	{
		bool b = false;
		RPC_SERVER_INFO t;

		Zero(&t, sizeof(t));
		if (ScGetServerInfo(rpc, &t) == ERR_NO_ERROR)
		{
			if (t.ServerType != SERVER_TYPE_STANDALONE)
			{
				b = true;
			}

			FreeRpcServerInfo(&t);
		}
		else
		{
			return false;
		}

		if (b)
		{
			return false;
		}
	}

	// Local bridge
	if (true)
	{
		RPC_ENUM_LOCALBRIDGE t;
		bool b = false;

		Zero(&t, sizeof(t));
		if (ScEnumLocalBridge(rpc, &t) == ERR_NO_ERROR)
		{
			if (t.NumItem != 0)
			{
				b = true;
			}
			FreeRpcEnumLocalBridge(&t);
		}

		if (b)
		{
			return false;
		}
	}

	// Virtual HUB

	check_hub = false;

	if (is_bridge == false)
	{
		RPC_ENUM_HUB t;
		bool b = false;

		Zero(&t, sizeof(t));
		if (ScEnumHub(rpc, &t) == ERR_NO_ERROR)
		{
			if (t.NumHub >= 2)
			{
				b = true;
			}
			else if (t.NumHub == 1)
			{
				if (StrCmpi(t.Hubs[0].HubName, SERVER_DEFAULT_HUB_NAME) != 0)
				{
					b = true;
				}
				else
				{
					check_hub = true;
				}
			}

			FreeRpcEnumHub(&t);
		}

		if (b)
		{
			return false;
		}
	}
	else
	{
		check_hub = true;
	}

	// Status of the virtual HUB
	if (is_bridge == false)
	{
		StrCpy(hubname, sizeof(hubname), SERVER_DEFAULT_HUB_NAME);
	}
	else
	{
		StrCpy(hubname, sizeof(hubname), SERVER_DEFAULT_BRIDGE_NAME);
	}

	if (check_hub)
	{
		if (true)
		{
			// Number of objects in the Virtual HUB
			RPC_HUB_STATUS t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScGetHubStatus(rpc, &t) == ERR_NO_ERROR)
			{
				if (t.NumSessions != 0 || t.NumAccessLists != 0 ||
					t.NumUsers != 0 || t.NumGroups != 0 ||
					t.NumMacTables != 0 || t.NumIpTables != 0 ||
					t.SecureNATEnabled)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (true)
		{
			// Cascade connection
			RPC_ENUM_LINK t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScEnumLink(rpc, &t) == ERR_NO_ERROR)
			{
				bool b = false;

				if (t.NumLink != 0)
				{
					b = true;
				}

				FreeRpcEnumLink(&t);

				if (b)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			// Certificate list to trust
			RPC_HUB_ENUM_CA t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScEnumCa(rpc, &t) == ERR_NO_ERROR)
			{
				bool b = false;

				if (t.NumCa != 0)
				{
					b = true;
				}

				FreeRpcHubEnumCa(&t);

				if (b)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			// Certificate revocation list
			RPC_ENUM_CRL t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScEnumCrl(rpc, &t) == ERR_NO_ERROR)
			{
				bool b = false;

				if (t.NumItem != 0)
				{
					b = true;
				}

				FreeRpcEnumCrl(&t);

				if (b)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			// Authentication server configuration
			RPC_RADIUS t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScGetHubRadius(rpc, &t) == ERR_NO_ERROR)
			{
				if (IsEmptyStr(t.RadiusServerName) == false)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			//  Virtual HUB configuration
			RPC_CREATE_HUB t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScGetHub(rpc, &t) == ERR_NO_ERROR)
			{
				if (t.HubOption.NoEnum || t.HubOption.MaxSession != 0 ||
					t.Online == false)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			// IP access control list
			RPC_AC_LIST t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScGetAcList(rpc, &t) == ERR_NO_ERROR)
			{
				bool b = false;
				if (LIST_NUM(t.o) != 0)
				{
					b = true;
				}
				FreeRpcAcList(&t);

				if (b)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}

		if (is_bridge == false)
		{
			// AO
			RPC_ADMIN_OPTION t;

			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), hubname);

			if (ScGetHubAdminOptions(rpc, &t) == ERR_NO_ERROR)
			{
				bool b = false;
				UINT i;

				for (i = 0;i < t.NumItem;i++)
				{
					if (t.Items[i].Value != 0)
					{
						b = true;
					}
				}

				FreeRpcAdminOption(&t);

				if (b)
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}
	}

	// Virtual layer 3 switch
	if (is_bridge == false)
	{
		RPC_ENUM_L3SW t;
		bool b = false;

		Zero(&t, sizeof(t));
		if (ScEnumL3Switch(rpc, &t) == ERR_NO_ERROR)
		{
			if (t.NumItem != 0)
			{
				b = true;
			}

			FreeRpcEnumL3Sw(&t);
		}
		else
		{
			return false;
		}

		if (b)
		{
			return false;
		}
	}

	return true;
}

// Setup procedure dialog initialization
void SmSetupStepDlgInit(HWND hWnd, SM_SETUP *s)
{
	bool b;
	RPC_ENUM_ETH t;
	UINT i;
	RPC_BRIDGE_SUPPORT bs;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SETUP);

	DlgFont(hWnd, S_1_1, 0, true);
	DlgFont(hWnd, S_2_1, 0, true);
	DlgFont(hWnd, S_3_1, 0, true);

	b = false;
	if (s->UseRemote)
	{
		b = true;
	}
	if (s->UseSite && s->UseSiteEdge == false)
	{
		b = true;
	}

	SetEnable(hWnd, S_1_1, b);
	SetEnable(hWnd, S_1_2, b);
	SetEnable(hWnd, B_USER, b);

	b = false;
	if (s->UseSiteEdge)
	{
		b = true;
	}

	SetEnable(hWnd, S_2_1, b);
	SetEnable(hWnd, S_2_2, b);
	SetEnable(hWnd, B_CASCADE, b);

	CbReset(hWnd, C_DEVICE);
	CbSetHeight(hWnd, C_DEVICE, 18);

	Zero(&t, sizeof(t));

	CbAddStr(hWnd, C_DEVICE, _UU("SM_SETUP_SELECT"), 0);

	Zero(&bs, sizeof(bs));
	if (CALL(hWnd, ScGetBridgeSupport(s->Rpc, &bs)) == false)
	{
		return;
	}

	if (bs.IsBridgeSupportedOs)
	{
		// Enumerate the local bridges
		if (ScEnumEthernet(s->Rpc, &t) == ERR_NO_ERROR)
		{
			for (i = 0;i < t.NumItem;i++)
			{
				wchar_t tmp[MAX_PATH];
				RPC_ENUM_ETH_ITEM *e = &t.Items[i];

				if (GetCapsBool(s->s->CapsList, "b_support_network_connection_name"))
				{
					UniFormat(tmp, sizeof(tmp), BRIDGE_NETWORK_CONNECTION_STR, e->NetworkConnectionName, e->DeviceName);
				}
				else
				{
					StrToUni(tmp, sizeof(tmp), e->DeviceName);
				}

				CbAddStr(hWnd, C_DEVICE, tmp, 1);
			}

			FreeRpcEnumEth(&t);
		}
		Show(hWnd, C_DEVICE);
		Hide(hWnd, B_SECURENAT);
	}
	else
	{
		RPC_HUB t;

		// Enable the SecureNAT automatically if the local bridge does not work in this environment
		SetText(hWnd, S_3_2, _UU("SM_SETUP_STEP_SECURENAT"));
		SetText(hWnd, S_3_1, _UU("SM_SETUP_STEP_SECURENAT_TITLE"));
		Hide(hWnd, C_DEVICE);
		Show(hWnd, B_SECURENAT);
		SetIcon(hWnd, S_ICON, ICO_ROUTER);

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

		ScEnableSecureNAT(s->Rpc, &t);
	}

	s->Flag1 = false;
	s->Flag2 = false;
}

// Close
void SmSetupOnClose(HWND hWnd, SM_SETUP *s)
{
	wchar_t *tmp;
	char name[MAX_PATH];
	RPC_BRIDGE_SUPPORT bs;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&bs, sizeof(bs));
	if (CALL(hWnd, ScGetBridgeSupport(s->Rpc, &bs)) == false)
	{
		return;
	}

	if (bs.IsBridgeSupportedOs)
	{
		// Add a Local Bridge
		tmp = CbGetStr(hWnd, C_DEVICE);

		if (tmp != NULL)
		{
			UniToStr(name, sizeof(name), tmp);

			if (CbGetSelect(hWnd, C_DEVICE) != 0)
			{
				// Show a warning message if the VPN Server is running in a VM
				if (GetCapsBool(s->s->CapsList, "b_is_in_vm"))
				{
					Dialog(hWnd, D_SM_VMBRIDGE, SmVmBridgeDlg, NULL);
				}

				if (GetCapsBool(s->s->CapsList, "b_support_network_connection_name") == false)
				{
					RPC_LOCALBRIDGE t;

					Zero(&t, sizeof(t));
					t.Active = true;
					StrCpy(t.DeviceName, sizeof(t.DeviceName), name);
					StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
					t.Online = true;
					t.TapMode = false;

					if (CALL(hWnd, ScAddLocalBridge(s->Rpc, &t)) == false)
					{
						Free(tmp);
						return;
					}
				}
				else
				{
					RPC_ENUM_ETH tt;
					UINT i;

					Zero(&tt, sizeof(tt));
					if (CALL(hWnd, ScEnumEthernet(s->Rpc, &tt)) == false)
					{
						Free(tmp);
						return;
					}

					for (i = 0;i < tt.NumItem;i++)
					{
						RPC_ENUM_ETH_ITEM *ti = &tt.Items[i];
						wchar_t fullname[MAX_SIZE];

						UniFormat(fullname, sizeof(fullname), BRIDGE_NETWORK_CONNECTION_STR, ti->NetworkConnectionName, ti->DeviceName);

						if (UniStrCmpi(fullname, tmp) == 0)
						{
							RPC_LOCALBRIDGE t;

							Zero(&t, sizeof(t));
							t.Active = true;
							StrCpy(t.DeviceName, sizeof(t.DeviceName), ti->DeviceName);
							StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
							t.Online = true;
							t.TapMode = false;

							if (CALL(hWnd, ScAddLocalBridge(s->Rpc, &t)) == false)
							{
								FreeRpcEnumEth(&tt);
								Free(tmp);
								return;
							}
							break;
						}
					}

					FreeRpcEnumEth(&tt);
				}

			}
			Free(tmp);
		}
	}
	else
	{
		// Enable the SecureNAT
	}

	EndDialog(hWnd, 0);
}

// Setup Procedure dialog procedure
UINT SmSetupStepDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SETUP *s = (SM_SETUP *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmSetupStepDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_USER:
			// User creation
			if (true)
			{
				SM_HUB h;

				Zero(&h, sizeof(h));
				h.HubName = s->HubName;
				h.p = s->s;
				h.Rpc = s->Rpc;

				SmUserListDlgEx(hWnd, &h, NULL, s->Flag1 ? false : true);

				s->Flag1 = true;
			}
			break;

		case B_CASCADE:
			// Create a cascade connection
			if (true)
			{
				SM_HUB h;

				Zero(&h, sizeof(h));
				h.HubName = s->HubName;
				h.p = s->s;
				h.Rpc = s->Rpc;

				SmLinkDlgEx(hWnd, &h, s->Flag2 ? false : true);
				s->Flag2 = true;
			}
			break;

		case B_SECURENAT:
			// Setting the SecureNAT
			if (true)
			{
				SM_HUB h;

				Zero(&h, sizeof(h));
				h.p = s->s;
				h.Rpc = s->Rpc;
				h.HubName = s->HubName;

				Dialog(hWnd, D_SM_SNAT, SmSNATDlgProc, &h);
			}
			break;

		case IDCANCEL:
			// Close button
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		// Exit
		SmSetupOnClose(hWnd, s);
		break;
	}

	return 0;
}

// Setup procedure dialog
void SmSetupStep(HWND hWnd, SM_SETUP *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_SETUP_STEP, SmSetupStepDlg, s);
}

// Initialize by setup
bool SmSetupInit(HWND hWnd, SM_SETUP *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	if (s->IsBridge == false)
	{
		if (SmSetupDeleteAllLayer3(hWnd, s) == false)
		{
			return false;
		}

		if (SmSetupDeleteAllHub(hWnd, s) == false)
		{
			return false;
		}
	}
	else
	{
		if (SmSetupDeleteAllObjectInBridgeHub(hWnd, s) == false)
		{
			return false;
		}
	}

	SmSetupDeleteAllLocalBridge(hWnd, s);

	if (s->IsBridge == false)
	{
		// Create a Virtual HUB
		RPC_CREATE_HUB t;
		char *password = "";

		Zero(&t, sizeof(t));
		Sha0(t.HashedPassword, password, StrLen(password));
		HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, password);
		StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
		t.HubType = HUB_TYPE_STANDALONE;
		t.Online = true;

		if (CALL(hWnd, ScCreateHub(s->Rpc, &t)) == false)
		{
			return false;
		}
	}

	return true;
}

// Remove all objects in the Virtual HUB of the VPN Bridge
bool SmSetupDeleteAllObjectInBridgeHub(HWND hWnd, SM_SETUP *s)
{
	char *hubname = SERVER_DEFAULT_BRIDGE_NAME;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	if (true)
	{
		RPC_ENUM_LINK t;
		UINT i;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), hubname);

		if (CALL(hWnd, ScEnumLink(s->Rpc, &t)) == false)
		{
			return false;
		}

		for (i = 0;i < t.NumLink;i++)
		{
			RPC_ENUM_LINK_ITEM *e = &t.Links[i];
			RPC_LINK a;

			Zero(&a, sizeof(a));
			StrCpy(a.HubName, sizeof(a.HubName), hubname);
			UniStrCpy(a.AccountName, sizeof(a.AccountName), e->AccountName);

			if (CALL(hWnd, ScDeleteLink(s->Rpc, &a)) == false)
			{
				FreeRpcEnumLink(&t);
				return false;
			}
		}

		FreeRpcEnumLink(&t);
	}

	if (true)
	{
		RPC_HUB t;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), hubname);

		if (CALL(hWnd, ScDisableSecureNAT(s->Rpc, &t)) == false)
		{
			return false;
		}
	}

	return true;
}

// Delete all Virtual Layer 3 Switches
bool SmSetupDeleteAllLayer3(HWND hWnd, SM_SETUP *s)
{
	RPC_ENUM_L3SW t;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if(CALL(hWnd, ScEnumL3Switch(s->Rpc, &t)) == false)
	{
		return false;
	}

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_L3SW_ITEM *e = &t.Items[i];
		RPC_L3SW tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.Name, sizeof(tt.Name), e->Name);

		if (CALL(hWnd, ScDelL3Switch(s->Rpc, &tt)) == false)
		{
			FreeRpcEnumL3Sw(&t);
			return false;
		}
	}

	FreeRpcEnumL3Sw(&t);

	return true;
}

// Delete all local bridges
bool SmSetupDeleteAllLocalBridge(HWND hWnd, SM_SETUP *s)
{
	RPC_ENUM_LOCALBRIDGE t;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (ScEnumLocalBridge(s->Rpc, &t) != ERR_NO_ERROR)
	{
		return false;
	}

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t.Items[i];

		if (CALL(hWnd, ScDeleteLocalBridge(s->Rpc, e)) == false)
		{
			FreeRpcEnumLocalBridge(&t);
			return false;
		}
	}

	FreeRpcEnumLocalBridge(&t);

	return true;
}

// Delete all Virtual HUBs
bool SmSetupDeleteAllHub(HWND hWnd, SM_SETUP *s)
{
	RPC_ENUM_HUB t;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumHub(s->Rpc, &t)) == false)
	{
		return false;
	}

	for (i = 0;i < t.NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];
		RPC_DELETE_HUB tt;

		Zero(&tt, sizeof(tt));
		StrCpy(tt.HubName, sizeof(tt.HubName), e->HubName);

		if (CALL(hWnd, ScDeleteHub(s->Rpc, &tt)) == false)
		{
			FreeRpcEnumHub(&t);
			return false;
		}
	}

	FreeRpcEnumHub(&t);

	return true;
}

// Update the control of the Virtual HUB
void SmSetupHubDlgUpdate(HWND hWnd, SM_SETUP *s)
{
	bool ok = true;
	char tmp[MAX_HUBNAME_LEN + 1];
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_HUBNAME, tmp, sizeof(tmp));

	if (IsEmptyStr(tmp) || IsSafeStr(tmp) == false)
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
}

// Virtual HUB creation dialog
UINT SmSetupHubDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SETUP *s = (SM_SETUP *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetTextA(hWnd, E_HUBNAME, "VPN");
		FocusEx(hWnd, E_HUBNAME);
		SmSetupHubDlgUpdate(hWnd, s);
		break;

	case WM_COMMAND:
		SmSetupHubDlgUpdate(hWnd, s);

		switch (wParam)
		{
		case IDOK:
			GetTxtA(hWnd, E_HUBNAME, s->HubName, sizeof(s->HubName));
			EndDialog(hWnd, true);
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

// Setup dialog: [Next] button
void SmSetupDlgOnOk(HWND hWnd, SM_SETUP *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (MsgBox(hWnd, MB_YESNO | MB_ICONEXCLAMATION, _UU("SM_SETUP_WARNING")) == IDNO)
	{
		return;
	}

	s->UseRemote = IsChecked(hWnd, C_REMOTE);
	s->UseSite = IsChecked(hWnd, C_SITE);
	s->UseSiteEdge = IsChecked(hWnd, C_EDGE);

	if (s->IsBridge)
	{
		StrCpy(s->HubName, sizeof(s->HubName), SERVER_DEFAULT_BRIDGE_NAME);
	}
	else
	{
		if (Dialog(hWnd, D_SM_SETUP_HUB, SmSetupHubDlg, s) == false)
		{
			return;
		}
	}

	// Initialize (Wipe existing objects)
	if (SmSetupInit(hWnd, s) == false)
	{
		return;
	}

	if (s->IsBridge == false)
	{
		if (GetCapsBool(s->s->CapsList, "b_support_ddns"))
		{
			if (s->UseRemote || (s->UseSite && s->UseSiteEdge == false))
			{
				DDNS_CLIENT_STATUS st;

				Zero(&st, sizeof(st));

				if (ScGetDDnsClientStatus(s->s->Rpc, &st) == ERR_NO_ERROR &&
					IsEmptyStr(st.CurrentHostName) == false)
				{
					// Display the Dynamic DNS setting screen
					SmDDns(hWnd, s->s, true, false);
				}
			}
		}

		// Configure the IPsec if the IPsec feature is available
		if (GetCapsBool(s->s->CapsList, "b_support_ipsec") && s->s->IPsecMessageDisplayed == false)
		{
			// Display a message about IPsec
			RPC_TEST flag;

			if (s->UseRemote || (s->UseSite && s->UseSiteEdge == false))
			{
				SmIPsec(hWnd, s->s);
			}

			Zero(&flag, sizeof(flag));
			flag.IntValue = 9;
			ToStr(flag.StrValue, 1);

			ScDebug(s->s->Rpc, &flag);

			s->s->IPsecMessageDisplayed = true;
		}

		// Configure the VPN Azure if VPN Azure feature is available
		if (GetCapsBool(s->s->CapsList, "b_support_azure"))
		{
			SmAzure(hWnd, s->s, true);
		}

	}

	// Execute the procedure
	SmSetupStep(hWnd, s);

	// Close the dialog
	EndDialog(hWnd, true);
}

// Setup dialog: initialization
void SmSetupDlgInit(HWND hWnd, SM_SETUP *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SETUP);
	DlgFont(hWnd, S_TITLE, 14, true);
	DlgFont(hWnd, C_REMOTE, 0, true);
	DlgFont(hWnd, C_SITE, 0, true);
	DlgFont(hWnd, C_OTHER, 0, true);

	if (s->IsBridge)
	{
		SetText(hWnd, B_BOLD, _UU("SM_SETUP_BRIDGE_ONLY"));
		SetText(hWnd, C_EDGE, _UU("SM_SETUP_BRIDGE_EDGE"));

		Check(hWnd, C_SITE, true);
		Check(hWnd, C_EDGE, true);
		Focus(hWnd, C_SITE);
	}

	SmSetupDlgUpdate(hWnd, s);
}

// Setup dialog: update
void SmSetupDlgUpdate(HWND hWnd, SM_SETUP *s)
{
	bool enable_remote = true;
	bool enable_site = true;
	bool enable_site_center = true;
	bool enable_detail = true;
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (s->IsBridge)
	{
		enable_remote = false;
		enable_site_center = false;
		enable_detail = false;
	}

	if (IsChecked(hWnd, C_OTHER))
	{
		ok = false;
	}

	SetEnable(hWnd, C_REMOTE, enable_remote && IsChecked(hWnd, C_OTHER) == false);
	SetEnable(hWnd, S_REMOTE_1, enable_remote && IsChecked(hWnd, C_OTHER) == false);

	SetEnable(hWnd, C_SITE, enable_site && IsChecked(hWnd, C_OTHER) == false);
	SetEnable(hWnd, S_SITE_1, enable_site && IsChecked(hWnd, C_OTHER) == false);
	SetEnable(hWnd, S_SITE_2, enable_site && IsChecked(hWnd, C_SITE) && IsChecked(hWnd, C_OTHER) == false);
	SetEnable(hWnd, C_CENTER, enable_site && enable_site_center && IsChecked(hWnd, C_SITE) && IsChecked(hWnd, C_OTHER) == false);
	SetEnable(hWnd, C_EDGE, enable_site && IsChecked(hWnd, C_SITE) && IsChecked(hWnd, C_OTHER) == false);

	SetEnable(hWnd, C_OTHER, enable_detail);
	SetEnable(hWnd, S_OTHER, enable_detail);

	if (IsChecked(hWnd, C_REMOTE) == false && IsChecked(hWnd, C_SITE) == false)
	{
		ok = false;
	}

	if (IsChecked(hWnd, C_SITE))
	{
		if (IsChecked(hWnd, C_CENTER) == false && IsChecked(hWnd, C_EDGE) == false)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);

	SetText(hWnd, S_INFO,
		IsChecked(hWnd, C_OTHER) ? _UU("SM_SETUP_INFO_2") : _UU("SM_SETUP_INFO_1"));
}

// Setup dialog
UINT SmSetupDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SETUP *s = (SM_SETUP *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmSetupDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		SmSetupDlgUpdate(hWnd, s);

		switch (wParam)
		{
		case IDOK:
			SmSetupDlgOnOk(hWnd, s);
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

// Setup
bool SmSetup(HWND hWnd, SM_SERVER *s)
{
	SM_SETUP ss;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	Zero(&ss, sizeof(ss));
	ss.s = s;
	ss.IsBridge = ss.s->Bridge;
	ss.Rpc = s->Rpc;

	if (Dialog(hWnd, D_SM_SETUP, SmSetupDlg, &ss) == false)
	{
		return false;
	}

	return true;
}

// License registration process
void SmLicenseAddDlgOnOk(HWND hWnd, SM_SERVER *s)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SmLicenseAddDlgGetText(hWnd, tmp, sizeof(tmp));

	if (LiIsLicenseKey(tmp))
	{
		RPC_TEST t;

		Disable(hWnd, IDOK);
		Disable(hWnd, IDCANCEL);

		Zero(&t, sizeof(t));
		StrCpy(t.StrValue, sizeof(t.StrValue), tmp);

		if (CALL(hWnd, ScAddLicenseKey(s->Rpc, &t)) == false)
		{
			FocusEx(hWnd, B_KEY6);
		}
		else
		{
			EndDialog(hWnd, true);
		}

		Enable(hWnd, IDOK);
		Enable(hWnd, IDCANCEL);
	}
}

// Shift treatment of text input
void SmLicenseAddDlgShiftTextItem(HWND hWnd, UINT id1, UINT id2, UINT *next_focus)
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
void SmLicenseAddDlgGetText(HWND hWnd, char *str, UINT size)
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
void SmLicenseAddDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	UINT next_focus = 0;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (s == NULL || hWnd == NULL)
	{
		return;
	}

	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY1, B_KEY2, &next_focus);
	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY2, B_KEY3, &next_focus);
	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY3, B_KEY4, &next_focus);
	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY4, B_KEY5, &next_focus);
	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY5, B_KEY6, &next_focus);
	SmLicenseAddDlgShiftTextItem(hWnd, B_KEY6, 0, &next_focus);

	if ((IsFocus(hWnd, B_KEY1) && GetTextLen(hWnd, B_KEY1, true) <= 5) ||
		(IsFocus(hWnd, B_KEY2) && GetTextLen(hWnd, B_KEY2, true) <= 5) ||
		(IsFocus(hWnd, B_KEY3) && GetTextLen(hWnd, B_KEY3, true) <= 5) ||
		(IsFocus(hWnd, B_KEY4) && GetTextLen(hWnd, B_KEY4, true) <= 5) ||
		(IsFocus(hWnd, B_KEY5) && GetTextLen(hWnd, B_KEY5, true) <= 5) ||
		(IsFocus(hWnd, B_KEY6) && GetTextLen(hWnd, B_KEY6, true) <= 5))
	{
		next_focus = 0;
	}

	if (next_focus != 0)
	{
		Focus(hWnd, next_focus);
	}

	SmLicenseAddDlgGetText(hWnd, tmp, sizeof(tmp));

	SetEnable(hWnd, IDOK, LiIsLicenseKey(tmp));
}

// License addition dialog initialization
void SmLicenseAddDlgInit(HWND hWnd, SM_SERVER *s)
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

	SmLicenseAddDlgUpdate(hWnd, s);
}

// License addition dialog
UINT SmLicenseAddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmLicenseAddDlgInit(hWnd, s);
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
				SmLicenseAddDlgUpdate(hWnd, s);

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
			SmLicenseAddDlgOnOk(hWnd, s);
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
bool SmLicenseAdd(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_SM_LICENSE_ADD, SmLicenseAddDlg, s);
}

// License dialog initialization
void SmLicenseDlgInit(HWND hWnd, SM_SERVER *s)
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

	SmLicenseDlgRefresh(hWnd, s);
}

// License dialog update
void SmLicenseDlgRefresh(HWND hWnd, SM_SERVER *s)
{
	RPC_ENUM_LICENSE_KEY t;
	RPC_LICENSE_STATUS st;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	LVB *b;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	if (CALL(hWnd, ScEnumLicenseKey(s->Rpc, &t)) == false)
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

	if (CALL(hWnd, ScGetLicenseStatus(s->Rpc, &st)) == false)
	{
		Close(hWnd);
		return;
	}

	b = LvInsertStart();

	if (st.EditionId == LICENSE_EDITION_VPN3_NO_LICENSE)
	{
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_NO_LICENSE_COLUMN"), _UU("SM_NO_LICENSE"));
	}
	else
	{
		// Product edition name
		StrToUni(tmp, sizeof(tmp), st.EditionStr);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_EDITION"), tmp);

		// Release date
		if (st.ReleaseDate != 0)
		{
			GetDateStrEx64(tmp, sizeof(tmp), st.ReleaseDate, NULL);
			LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_RELEASE"), tmp);
		}

		// Current system ID
		UniFormat(tmp, sizeof(tmp), L"%I64u", st.SystemId);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_SYSTEM_ID"), tmp);

		// Expiration date of the current product license
		if (st.SystemExpires == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_NO_EXPIRES"));
		}
		else
		{
			GetDateStrEx64(tmp, sizeof(tmp), st.SystemExpires, NULL);
		}
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_EXPIRES"), tmp);

		// Subscription (support) contract
		if (st.NeedSubscription == false)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_STATUS_SUBSCRIPTION_NONEED"));
		}
		else
		{
			if (st.SubscriptionExpires == 0)
			{
				UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_STATUS_SUBSCRIPTION_NONE"));
			}
			else
			{
				wchar_t dtstr[MAX_PATH];

				GetDateStrEx64(dtstr, sizeof(dtstr), st.SubscriptionExpires, NULL);

				UniFormat(tmp, sizeof(tmp),
					st.IsSubscriptionExpired ? _UU("SM_LICENSE_STATUS_SUBSCRIPTION_EXPIRED") :  _UU("SM_LICENSE_STATUS_SUBSCRIPTION_VALID"),
					dtstr);
			}
		}
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_SUBSCRIPTION"), tmp);

		if (st.NeedSubscription == false && st.SubscriptionExpires != 0)
		{
			wchar_t dtstr[MAX_PATH];

			GetDateStrEx64(dtstr, sizeof(dtstr), st.SubscriptionExpires, NULL);

			LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_SUBSCRIPTION_BUILD_STR"), tmp);
		}

		if (st.NeedSubscription && st.SubscriptionExpires != 0)
		{
			wchar_t dtstr[MAX_PATH];

			GetDateStrEx64(dtstr, sizeof(dtstr), st.SubscriptionExpires, NULL);

			UniFormat(tmp, sizeof(tmp), _UU("SM_LICENSE_STATUS_SUBSCRIPTION_BUILD_STR"), dtstr);

			LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_SUBSCRIPTION_BUILD"), tmp);
		}

		if (GetCapsBool(s->CapsList, "b_vpn3"))
		{
			// Maximum number of users
			if (st.NumUserCreationLicense == INFINITE)
			{
				UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
			}
			else
			{
				UniToStru(tmp, st.NumUserCreationLicense);
			}
			LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_NUM_USER"), tmp);
		}

		// Available number of concurrent client connections
		if (st.NumClientConnectLicense == INFINITE)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
		}
		else
		{
			UniToStru(tmp, st.NumClientConnectLicense);
		}
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_NUM_CLIENT"), tmp);

		// Available number of concurrent Bridge connections
		if (st.NumBridgeConnectLicense == INFINITE)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
		}
		else
		{
			UniToStru(tmp, st.NumBridgeConnectLicense);
		}
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_NUM_BRIDGE"), tmp);

		// Availability of enterprise features
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_LICENSE_STATUS_ENTERPRISE"),
			st.AllowEnterpriseFunction ? _UU("SM_LICENSE_STATUS_ENTERPRISE_YES") : _UU("SM_LICENSE_STATUS_ENTERPRISE_NO"));
	}

	LvInsertEnd(b, hWnd, L_STATUS);

	if (LvNum(hWnd, L_STATUS) >= 1)
	{
		LvAutoSize(hWnd, L_STATUS);
	}

	SmLicenseDlgUpdate(hWnd, s);
}

// License dialog control update
void SmLicenseDlgUpdate(HWND hWnd, SM_SERVER *s)
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
UINT SmLicenseDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;
	NMHDR *n;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmLicenseDlgInit(hWnd, s);
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
				SmLicenseDlgUpdate(hWnd, s);
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
					char *s = LvGetStrA(hWnd, L_LIST, i, 1);
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
			if (SmLicenseAdd(hWnd, s))
			{
				SmLicenseDlgRefresh(hWnd, s);
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

						if (CALL(hWnd, ScDelLicenseKey(s->Rpc, &t)))
						{
							SmLicenseDlgRefresh(hWnd, s);
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

// Add or Remove license
void SmLicense(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_LICENSE, SmLicenseDlg, s);

	FreeCapsList(s->CapsList);
	s->CapsList = ScGetCapsEx(s->Rpc);
}

// Log storing procedure
UINT SmSaveLogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_READ_LOG_FILE *p = (SM_READ_LOG_FILE *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, S_INFO, p->filepath);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case B_SAVE:
			if (p->Buffer != NULL)
			{
				char filename[MAX_PATH];

				Format(filename, sizeof(filename), "%s_%s", p->server_name, p->filepath);
				ConvertSafeFileName(filename, sizeof(filename), filename);

				if (wParam == IDOK)
				{
					// Open with an editor
					char fullpath[MAX_PATH];

					Format(fullpath, sizeof(fullpath), "%s\\%s",
						MsGetMyTempDir(), filename);

					if (DumpBuf(p->Buffer, fullpath) == false)
					{
						MsgBoxEx(hWnd, MB_ICONSTOP, _UU("SM_READ_SAVE_TMP_FAILED"),
							fullpath);
					}
					else
					{
						if (((UINT)ShellExecute(hWnd, "open", fullpath, NULL, NULL, SW_SHOWNORMAL)) > 32)
						{
							EndDialog(hWnd, true);
						}
						else
						{
							MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SM_READ_SAVE_OPEN_ERROR"), fullpath);
						}
					}
				}
				else
				{
					// Save to a file
					wchar_t def[MAX_PATH];
					wchar_t *uni_path;

					StrToUni(def, sizeof(def), filename);
					
					uni_path = SaveDlg(hWnd, _UU("SM_READ_SAVE_DLG_FILTER"), _UU("SM_READ_SAVE_DLG_TITLE"),
						def, L".log");

					if (uni_path != NULL)
					{
						char path[MAX_PATH];

						UniToStr(path, sizeof(path), uni_path);
						Free(uni_path);

						if (DumpBuf(p->Buffer, path) == false)
						{
							MsgBox(hWnd, MB_ICONSTOP, _UU("SM_READ_SAVE_FAILED"));
						}
						else
						{
							EndDialog(hWnd, true);
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
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Download callback procedure
bool SmReadLogFileProc(DOWNLOAD_PROGRESS *g)
{
	wchar_t tmp[MAX_SIZE];
	char size1[64], size2[64];
	SM_READ_LOG_FILE *p;
	HWND hWnd;
	// Validate arguments
	if (g == NULL)
	{
		return false;
	}

	p = (SM_READ_LOG_FILE *)g->Param;
	hWnd = p->hWnd;

	SetPos(hWnd, P_PROGRESS, g->ProgressPercent);

	ToStrByte(size1, sizeof(size1), g->CurrentSize);
	ToStrByte(size2, sizeof(size2), g->TotalSize);
	UniFormat(tmp, sizeof(tmp), _UU("SM_READ_LOG_FILE_INFO_2"), size2, size1);

	SetText(hWnd, S_INFO, tmp);

	DoEvents(hWnd);

	return p->cancel_flag ? false : true;
}

// Log file download dialog procedure
UINT SmReadLogFile(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_READ_LOG_FILE *p = (SM_READ_LOG_FILE *)param;
	BUF *buf;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		p->hWnd = hWnd;
		SetFont(hWnd, S_INFO, Font(11, true));
		SetText(hWnd, S_INFO, _UU("SM_READ_LOG_FILE_INFO_1"));
		DisableClose(hWnd);
		FormatText(hWnd, S_INFO2, p->filepath);
		SetRange(hWnd, P_PROGRESS, 0, 100);

		SetTimer(hWnd, 1, 100, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			buf = DownloadFileFromServer(p->s->Rpc, p->server_name, p->filepath, p->totalsize, SmReadLogFileProc, p);
			if (buf == NULL)
			{
				if (p->cancel_flag == false)
				{
					// Download failure
					MsgBox(hWnd, MB_ICONSTOP, _UU("SM_READ_LOG_FILE_ERROR"));
				}
				EndDialog(hWnd, false);
			}
			else
			{
				// Download success
				p->Buffer = buf;
				Dialog(hWnd, D_SM_SAVE_LOG, SmSaveLogProc, p);
				FreeBuf(buf);
				EndDialog(hWnd, true);
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			p->cancel_flag = true;
			break;
		}
		break;
	}

	return 0;
}

// Start the download of the log file
void SmLogFileStartDownload(HWND hWnd, SM_SERVER *s, char *server_name, char *filepath, UINT totalsize)
{
	SM_READ_LOG_FILE p;
	// Validate arguments
	if (hWnd == NULL || server_name == NULL || filepath == NULL || totalsize == 0)
	{
		return;
	}

	Zero(&p, sizeof(p));
	p.filepath = filepath;
	p.s = s;
	p.server_name = server_name;
	p.totalsize = totalsize;

	Dialog(hWnd, D_SM_READ_LOG_FILE, SmReadLogFile, &p);
}

// Initialize the dialog
void SmLogFileDlgInit(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_LOG2);

	LvInit(hWnd, L_LIST);

	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_LOG_FILE_COLUMN_1"), 250);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_LOG_FILE_COLUMN_2"), 100);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_LOG_FILE_COLUMN_3"), 130);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_LOG_FILE_COLUMN_4"), 110);

	SmLogFileDlgRefresh(hWnd, p);
}

// Dialog content update
void SmLogFileDlgRefresh(HWND hWnd, SM_SERVER *p)
{
	UINT i;
	LVB *v;
	RPC_ENUM_LOG_FILE t;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumLogFile(p->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	v = LvInsertStart();

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t.Items[i];
		wchar_t tmp1[MAX_PATH], tmp2[128], tmp3[128], tmp4[MAX_HOST_NAME_LEN + 1];
		char tmp[MAX_SIZE];

		StrToUni(tmp1, sizeof(tmp1), e->FilePath);

		ToStrByte(tmp, sizeof(tmp), e->FileSize);
		StrToUni(tmp2, sizeof(tmp2), tmp);

		GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->UpdatedTime));

		StrToUni(tmp4, sizeof(tmp4), e->ServerName);

		LvInsertAdd(v, ICO_LOG2, (void *)e->FileSize, 4, tmp1, tmp2, tmp3, tmp4);
	}

	LvInsertEndEx(v, hWnd, L_LIST, true);

	if (t.NumItem != 0)
	{
		LvAutoSize(hWnd, L_LIST);
	}

	FreeRpcEnumLogFile(&t);

	SmLogFileDlgUpdate(hWnd, p);
}

// Update the dialog control
void SmLogFileDlgUpdate(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetEnable(hWnd, IDOK, LvIsSingleSelected(hWnd, L_LIST));
}

// Log file dialog procedure
UINT SmLogFileDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_SERVER *p = (SM_SERVER *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmLogFileDlgInit(hWnd, p);
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
					UINT size = (UINT)LvGetParam(hWnd, L_LIST, i);
					char *server_name;
					char *filepath;

					server_name = LvGetStrA(hWnd, L_LIST, i, 3);
					filepath = LvGetStrA(hWnd, L_LIST, i, 0);
					SmLogFileStartDownload(hWnd, p, server_name, filepath, size);
					Free(filepath);
					Free(server_name);
				}
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_REFRESH:
			SmLogFileDlgRefresh(hWnd, p);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
				SmLogFileDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}

// Initialize the dialog
void SmHubEditAcDlgInit(HWND hWnd, SM_EDIT_AC *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetEnable(hWnd, R_IPV6, GetCapsBool(p->e->s->p->CapsList, "b_support_ipv6_ac"));

	if (p->id == 0)
	{
		UINT i, v;

		Check(hWnd, R_SINGLE, true);
		Check(hWnd, R_PASS, true);
		Check(hWnd, R_IPV4, true);

		v = 0;

		for (i = 0;i < LIST_NUM(p->e->AcList);i++)
		{
			AC *ac = LIST_DATA(p->e->AcList, i);

			v = MAX(v, ac->Priority);
		}

		v += 100;

		SetInt(hWnd, E_PRIORITY, v);
	}
	else
	{
		AC *ac = GetAc(p->e->AcList, p->id);

		if (ac == NULL)
		{
			EndDialog(hWnd, false);
			return;
		}

		Check(hWnd, R_SINGLE, ac->Masked == false);
		Check(hWnd, R_MASKED, ac->Masked);
		Check(hWnd, R_IPV4, IsIP4(&ac->IpAddress));
		Check(hWnd, R_IPV6, IsIP6(&ac->IpAddress));

		if (IsIP4(&ac->IpAddress))
		{
			IpSet(hWnd, E_IP, IPToUINT(&ac->IpAddress));
		}
		else
		{
			char tmp[MAX_SIZE];

			IPToStr(tmp, sizeof(tmp), &ac->IpAddress);
			SetTextA(hWnd, E_IPV6, tmp);
		}

		if (ac->Masked)
		{
			if (IsIP4(&ac->IpAddress))
			{
				IpSet(hWnd, E_MASK, IPToUINT(&ac->SubnetMask));
			}
			else
			{
				char tmp[MAX_SIZE];

				MaskToStrEx(tmp, sizeof(tmp), &ac->SubnetMask, false);

				if (IsNum(tmp))
				{
					StrCatLeft(tmp, sizeof(tmp), "/");
				}

				SetTextA(hWnd, E_MASKV6, tmp);
			}
		}

		Check(hWnd, R_PASS, ac->Deny == false);
		Check(hWnd, R_DENY, ac->Deny);
		SetInt(hWnd, E_PRIORITY, ac->Priority);

		Free(ac);
	}

	Focus(hWnd, E_IP);

	SmHubEditAcDlgUpdate(hWnd, p);
}

// Dialog update
void SmHubEditAcDlgUpdate(HWND hWnd, SM_EDIT_AC *p)
{
	bool b = true;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	if (IsChecked(hWnd, R_SINGLE))
	{
		if (IsChecked(hWnd, R_IPV6) == false)
		{
			Show(hWnd, E_IP);
			Hide(hWnd, E_IPV6);

			if (IpIsFilled(hWnd, E_IP) == false)
			{
				b = false;
			}

			if (IpGet(hWnd, E_IP) == 0 || IpGet(hWnd, E_IP) == 0xffffffff)
			{
				b = false;
			}
		}
		else
		{
			Show(hWnd, E_IPV6);
			Hide(hWnd, E_IP);

			GetTxtA(hWnd, E_IPV6, tmp, sizeof(tmp));

			if (IsStrIPv6Address(tmp) == false)
			{
				b = false;
			}
		}

		Hide(hWnd, S_MASK);
		Hide(hWnd, E_MASK);
		Hide(hWnd, E_MASKV6);
	}
	else
	{
		if (IsChecked(hWnd, R_IPV6) == false)
		{
			Show(hWnd, E_IP);
			Hide(hWnd, E_IPV6);

			if (IpIsFilled(hWnd, E_IP) == false || IpIsFilled(hWnd, E_MASK) == false)
			{
				b = false;
			}

			if (IpGet(hWnd, E_IP) == 0xffffffff)
			{
				b = false;
			}
		}
		else
		{
			char tmp1[MAX_SIZE], tmp2[MAX_SIZE];

			Show(hWnd, E_IPV6);
			Hide(hWnd, E_IP);

			GetTxtA(hWnd, E_IPV6, tmp1, sizeof(tmp1));
			GetTxtA(hWnd, E_MASKV6, tmp2, sizeof(tmp2));

			if (!(IsIpStr6(tmp1) && IsIpMask6(tmp2)))
			{
				b = false;
			}
		}

		Show(hWnd, S_MASK);
		SetShow(hWnd, E_MASK, !IsChecked(hWnd, R_IPV6));
		SetShow(hWnd, E_MASKV6, IsChecked(hWnd, R_IPV6));
	}

	if (GetInt(hWnd, E_PRIORITY) == 0)
	{
		b = false;
	}

	SetIcon(hWnd, S_ICON, IsChecked(hWnd, R_PASS) ? ICO_INTERNET : ICO_INTERNET_X);

	SetEnable(hWnd, IDOK, b);
}

// OK button is clicked in the dialog
void SmHubEditAcDlgOnOk(HWND hWnd, SM_EDIT_AC *p)
{
	AC ac;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Zero(&ac, sizeof(ac));
	ac.Deny = IsChecked(hWnd, R_DENY);
	ac.Priority = GetInt(hWnd, E_PRIORITY);

	if (IsChecked(hWnd, R_IPV6) == false)
	{
		UINTToIP(&ac.IpAddress, IpGet(hWnd, E_IP));
	}
	else
	{
		GetTxtA(hWnd, E_IPV6, tmp, sizeof(tmp));

		StrToIP6(&ac.IpAddress, tmp);
	}

	ac.Masked = IsChecked(hWnd, R_MASKED);

	if (ac.Masked)
	{
		if (IsChecked(hWnd, R_IPV6) == false)
		{
			UINTToIP(&ac.SubnetMask, IpGet(hWnd, E_MASK));
		}
		else
		{
			GetTxtA(hWnd, E_MASKV6, tmp, sizeof(tmp));

			StrToMask6(&ac.SubnetMask, tmp);
		}
	}

	if (p->id != 0)
	{
		SetAc(p->e->AcList, p->id, &ac);
	}
	else
	{
		AddAc(p->e->AcList, &ac);
	}

	EndDialog(hWnd, true);
}

// AC edit dialog
UINT SmHubEditAcDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_AC *p = (SM_EDIT_AC *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmHubEditAcDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_SINGLE:
		case R_MASKED:
		case E_IP:
		case E_MASK:
		case R_PASS:
		case R_DENY:
		case E_PRIORITY:
		case R_IPV4:
		case R_IPV6:
		case E_IPV6:
		case E_MASKV6:
			SmHubEditAcDlgUpdate(hWnd, p);
			break;
		}

		switch (wParam)
		{
		case R_IPV4:
		case R_IPV6:
		case R_SINGLE:
		case R_MASKED:
			if (IsChecked(hWnd, R_IPV6) == false)
			{
				if (IpIsFilled(hWnd, E_IP))
				{
					Focus(hWnd, E_MASK);
				}
				else
				{
					Focus(hWnd, E_IP);
				}
			}
			else
			{
				char tmp[MAX_SIZE];

				GetTxtA(hWnd, E_IPV6, tmp, sizeof(tmp));

				if (IsStrIPv6Address(tmp))
				{
					FocusEx(hWnd, E_MASKV6);
				}
				else
				{
					FocusEx(hWnd, E_IPV6);
				}
			}
			break;

		case IDOK:
			SmHubEditAcDlgOnOk(hWnd, p);
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

// Initialize the dialog
void SmHubAcDlgInit(HWND hWnd, SM_EDIT_AC_LIST *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_INTERNET);

	FormatText(hWnd, S_TITLE, p->s->HubName);

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_AC_COLUMN_1"), 40);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_AC_COLUMN_2"), 80);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_AC_COLUMN_3"), 90);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_AC_COLUMN_4"), 170);

	SmHubAcDlgRefresh(hWnd, p);
}

// Update the dialog control
void SmHubAcDlgUpdate(HWND hWnd, SM_EDIT_AC_LIST *p)
{
	bool b;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	b = LvIsSingleSelected(hWnd, L_LIST);

	SetEnable(hWnd, IDOK, b);
	SetEnable(hWnd, B_DELETE, b);
}

// Dialog content update
void SmHubAcDlgRefresh(HWND hWnd, SM_EDIT_AC_LIST *p)
{
	UINT i;
	LVB *v;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	v = LvInsertStart();

	for (i = 0;i < LIST_NUM(p->AcList);i++)
	{
		wchar_t tmp1[32], *tmp2, tmp3[MAX_SIZE], tmp4[32];
		char *tmp_str;
		AC *ac = LIST_DATA(p->AcList, i);

		UniToStru(tmp1, ac->Id);
		tmp2 = ac->Deny ? _UU("SM_AC_DENY") : _UU("SM_AC_PASS");
		tmp_str = GenerateAcStr(ac);
		StrToUni(tmp3, sizeof(tmp3), tmp_str);

		Free(tmp_str);

		UniToStru(tmp4, ac->Priority);

		LvInsertAdd(v, ac->Deny ? ICO_INTERNET_X : ICO_INTERNET,
			(void *)ac->Id, 4, tmp1, tmp4, tmp2, tmp3);
	}

	LvInsertEnd(v, hWnd, L_LIST);
	LvSortEx(hWnd, L_LIST, 0, false, true);


	SmHubAcDlgUpdate(hWnd, p);
}

// Access control list editing dialog
UINT SmHubAcDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_EDIT_AC_LIST *p = (SM_EDIT_AC_LIST *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmHubAcDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (IsEnable(hWnd, IDOK))
			{
				SM_EDIT_AC s;
				Zero(&s, sizeof(s));

				s.e = p;
				s.id = (UINT)LvGetParam(hWnd, L_LIST, LvGetSelected(hWnd, L_LIST));

				if (Dialog(hWnd, D_SM_AC, SmHubEditAcDlgProc, &s))
				{
					SmHubAcDlgRefresh(hWnd, p);
				}
			}
			break;

		case B_ADD:
			if (IsEnable(hWnd, B_ADD))
			{
				SM_EDIT_AC s;
				Zero(&s, sizeof(s));

				s.e = p;

				if (Dialog(hWnd, D_SM_AC, SmHubEditAcDlgProc, &s))
				{
					SmHubAcDlgRefresh(hWnd, p);
				}
			}
			break;

		case B_DELETE:
			if (IsEnable(hWnd, B_DELETE))
			{
				UINT id = (UINT)LvGetParam(hWnd, L_LIST, LvGetSelected(hWnd, L_LIST));

				if (DelAc(p->AcList, id))
				{
					SmHubAcDlgRefresh(hWnd, p);
				}
			}
			break;

		case B_SAVE:
			if (IsEnable(hWnd, B_SAVE))
			{
				RPC_AC_LIST t;

				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), p->s->HubName);
				t.o = CloneAcList(p->AcList);

				if (CALL(hWnd, ScSetAcList(p->s->p->Rpc, &t)))
				{
					EndDialog(hWnd, true);
				}

				FreeRpcAcList(&t);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
				SmHubAcDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}

// Access control list editing
void SmHubAc(HWND hWnd, SM_EDIT_HUB *s)
{
	SM_EDIT_AC_LIST p;
	RPC_AC_LIST t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (CALL(hWnd, ScGetAcList(s->p->Rpc, &t)) == false)
	{
		return;
	}

	Zero(&p, sizeof(p));
	p.s = s;
	p.AcList = CloneAcList(t.o);

	FreeRpcAcList(&t);

	Dialog(hWnd, D_SM_AC_LIST, SmHubAcDlgProc, &p);

	FreeAcList(p.AcList);
}

// Initialize the dialog
void SmEditCrlDlgInit(HWND hWnd, SM_EDIT_CRL *c)
{
	// Validate arguments
	if (hWnd == NULL || c == NULL)
	{
		return;
	}

	if (c->NewCrl == false)
	{
		RPC_CRL t;
		CRL *crl;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), c->s->HubName);
		t.Key = c->Key;

		if (CALL(hWnd, ScGetCrl(c->s->Rpc, &t)) == false)
		{
			EndDialog(hWnd, false);
			return;
		}

		crl = t.Crl;

		SmEditCrlDlgSetName(hWnd, crl->Name);
		SmEditCrlDlgSetSerial(hWnd, crl->Serial);
		SmEditCrlDlgSetHash(hWnd, crl->DigestMD5, crl->DigestSHA1);

		FreeRpcCrl(&t);
	}

	SmEditCrlDlgUpdate(hWnd, c);
}

// Update the controls
void SmEditCrlDlgUpdate(HWND hWnd, SM_EDIT_CRL *c)
{
	bool b = true;
	// Validate arguments
	if (hWnd == NULL || c == NULL)
	{
		return;
	}

	SetEnable(hWnd, E_CN, IsChecked(hWnd, R_CN));
	SetEnable(hWnd, E_O, IsChecked(hWnd, R_O));
	SetEnable(hWnd, E_OU, IsChecked(hWnd, R_OU));
	SetEnable(hWnd, E_C, IsChecked(hWnd, R_C));
	SetEnable(hWnd, E_ST, IsChecked(hWnd, R_ST));
	SetEnable(hWnd, E_L, IsChecked(hWnd, R_L));
	SetEnable(hWnd, E_SERI, IsChecked(hWnd, R_SERI));
	SetEnable(hWnd, E_MD5_HASH, IsChecked(hWnd, R_MD5_HASH));
	SetEnable(hWnd, E_SHA1_HASH, IsChecked(hWnd, R_SHA1_HASH));

	if (IsChecked(hWnd, R_CN))
	{
		if (IsEmpty(hWnd, E_CN))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_O))
	{
		if (IsEmpty(hWnd, E_O))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_OU))
	{
		if (IsEmpty(hWnd, E_OU))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_C))
	{
		if (IsEmpty(hWnd, E_C))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_ST))
	{
		if (IsEmpty(hWnd, E_ST))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_L))
	{
		if (IsEmpty(hWnd, E_L))
		{
			b = false;
		}
	}

	if (IsChecked(hWnd, R_SERI))
	{
		char tmp[MAX_SIZE];
		BUF *buf;

		GetTxtA(hWnd, E_SERI, tmp, sizeof(tmp));
		buf = StrToBin(tmp);

		if (buf->Size == 0)
		{
			b = false;
		}

		FreeBuf(buf);
	}

	if (IsChecked(hWnd, R_MD5_HASH))
	{
		char tmp[MAX_SIZE];
		BUF *buf;

		GetTxtA(hWnd, E_MD5_HASH, tmp, sizeof(tmp));
		buf = StrToBin(tmp);

		if (buf->Size != MD5_SIZE)
		{
			b = false;
		}

		FreeBuf(buf);
	}

	if (IsChecked(hWnd, R_SHA1_HASH))
	{
		char tmp[MAX_SIZE];
		BUF *buf;

		GetTxtA(hWnd, E_SHA1_HASH, tmp, sizeof(tmp));
		buf = StrToBin(tmp);

		if (buf->Size != SHA1_SIZE)
		{
			b = false;
		}

		FreeBuf(buf);
	}

	SetEnable(hWnd, IDOK, b);
}

// On click the OK button
void SmEditCrlDlgOnOk(HWND hWnd, SM_EDIT_CRL *c)
{
	CRL *crl;
	NAME *n;
	RPC_CRL t;
	bool empty = true;
	// Validate arguments
	if (hWnd == NULL || c == NULL)
	{
		return;
	}

	crl = ZeroMalloc(sizeof(CRL));
	crl->Name = ZeroMalloc(sizeof(NAME));
	n = crl->Name;

	if (IsChecked(hWnd, R_CN))
	{
		n->CommonName = GetText(hWnd, E_CN);
		empty = false;
	}

	if (IsChecked(hWnd, R_O))
	{
		n->Organization = GetText(hWnd, E_O);
		empty = false;
	}

	if (IsChecked(hWnd, R_OU))
	{
		n->Unit = GetText(hWnd, E_OU);
		empty = false;
	}

	if (IsChecked(hWnd, R_C))
	{
		n->Country = GetText(hWnd, E_C);
		empty = false;
	}

	if (IsChecked(hWnd, R_ST))
	{
		n->State = GetText(hWnd, E_ST);
		empty = false;
	}

	if (IsChecked(hWnd, R_L))
	{
		n->Local = GetText(hWnd, E_L);
		empty = false;
	}

	if (IsChecked(hWnd, R_SERI))
	{
		char tmp[MAX_SIZE];
		BUF *b;

		GetTxtA(hWnd, E_SERI, tmp, sizeof(tmp));
		b = StrToBin(tmp);

		if (b != NULL && b->Size >= 1)
		{
			crl->Serial = NewXSerial(b->Buf, b->Size);
		}

		FreeBuf(b);

		empty = false;
	}

	if (IsChecked(hWnd, R_MD5_HASH))
	{
		char tmp[MAX_SIZE];
		BUF *b;

		GetTxtA(hWnd, E_MD5_HASH, tmp, sizeof(tmp));
		b = StrToBin(tmp);

		if (b != NULL && b->Size == MD5_SIZE)
		{
			Copy(crl->DigestMD5, b->Buf, MD5_SIZE);
		}

		FreeBuf(b);

		empty = false;
	}

	if (IsChecked(hWnd, R_SHA1_HASH))
	{
		char tmp[MAX_SIZE];
		BUF *b;

		GetTxtA(hWnd, E_SHA1_HASH, tmp, sizeof(tmp));
		b = StrToBin(tmp);

		if (b != NULL && b->Size == SHA1_SIZE)
		{
			Copy(crl->DigestSHA1, b->Buf, SHA1_SIZE);
		}

		FreeBuf(b);

		empty = false;
	}

	if (empty)
	{
		if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("SM_CRL_EMPTY_MSG")) == IDNO)
		{
			return;
		}
	}

	if (c->NewCrl)
	{
		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), c->s->HubName);
		t.Crl = crl;

		if (CALL(hWnd, ScAddCrl(c->s->Rpc, &t)))
		{
			EndDialog(hWnd, true);
		}

		FreeRpcCrl(&t);
	}
	else
	{
		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), c->s->HubName);
		t.Crl = crl;
		t.Key = c->Key;

		if (CALL(hWnd, ScSetCrl(c->s->Rpc, &t)))
		{
			EndDialog(hWnd, true);
		}

		FreeRpcCrl(&t);
	}
}

// Read the certificate
void SmEditCrlDlgOnLoad(HWND hWnd, SM_EDIT_CRL *c)
{
	X *x;
	// Validate arguments
	if (hWnd == NULL || c == NULL)
	{
		return;
	}

	if (CmLoadXFromFileOrSecureCard(hWnd, &x))
	{
		UCHAR md5[MD5_SIZE], sha1[SHA1_SIZE];

		SmEditCrlDlgSetName(hWnd, x->subject_name);
		SmEditCrlDlgSetSerial(hWnd, x->serial);
		GetXDigest(x, md5, false);
		GetXDigest(x, sha1, true);
		SmEditCrlDlgSetHash(hWnd, md5, sha1);

		FreeX(x);

		SmEditCrlDlgUpdate(hWnd, c);
	}
}

// Set the hash information to the dialog
void SmEditCrlDlgSetHash(HWND hWnd, UCHAR *hash_md5, UCHAR *hash_sha1)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (hash_md5 != NULL && IsZero(hash_md5, MD5_SIZE) == false)
	{
		Check(hWnd, R_MD5_HASH, true);
		BinToStrEx(tmp, sizeof(tmp), hash_md5, MD5_SIZE);
		SetTextA(hWnd, E_MD5_HASH, tmp);
	}
	else
	{
		Check(hWnd, R_MD5_HASH, false);
	}

	if (hash_sha1 != NULL && IsZero(hash_sha1, SHA1_SIZE) == false)
	{
		Check(hWnd, R_SHA1_HASH, true);
		BinToStrEx(tmp, sizeof(tmp), hash_sha1, SHA1_SIZE);
		SetTextA(hWnd, E_SHA1_HASH, tmp);
	}
	else
	{
		Check(hWnd, R_SHA1_HASH, false);
	}
}

// Set the serial number to the dialog
void SmEditCrlDlgSetSerial(HWND hWnd, X_SERIAL *serial)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || serial == NULL)
	{
		return;
	}

	BinToStrEx(tmp, sizeof(tmp), serial->data, serial->size);

	Check(hWnd, R_SERI, true);

	SetTextA(hWnd, E_SERI, tmp);
}

// Set the name situation to the dialog
void SmEditCrlDlgSetName(HWND hWnd, NAME *name)
{
	// Validate arguments
	if (hWnd == NULL || name == NULL)
	{
		return;
	}

	// CN
	if (UniIsEmptyStr(name->CommonName))
	{
		Check(hWnd, R_CN, false);
	}
	else
	{
		Check(hWnd, R_CN, true);
		SetText(hWnd, E_CN, name->CommonName);
	}

	// O
	if (UniIsEmptyStr(name->Organization))
	{
		Check(hWnd, R_O, false);
	}
	else
	{
		Check(hWnd, R_O, true);
		SetText(hWnd, E_O, name->Organization);
	}

	// OU
	if (UniIsEmptyStr(name->Unit))
	{
		Check(hWnd, R_OU, false);
	}
	else
	{
		Check(hWnd, R_OU, true);
		SetText(hWnd, E_OU, name->Unit);
	}

	// C
	if (UniIsEmptyStr(name->Country))
	{
		Check(hWnd, R_C, false);
	}
	else
	{
		Check(hWnd, R_C, true);
		SetText(hWnd, E_C, name->Country);
	}

	// ST
	if (UniIsEmptyStr(name->State))
	{
		Check(hWnd, R_ST, false);
	}
	else
	{
		Check(hWnd, R_ST, true);
		SetText(hWnd, E_ST, name->State);
	}

	// L
	if (UniIsEmptyStr(name->Local))
	{
		Check(hWnd, R_L, false);
	}
	else
	{
		Check(hWnd, R_L, true);
		SetText(hWnd, E_L, name->Local);
	}
}

// CRL edit dialog procedure
UINT SmEditCrlDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_CRL *c = (SM_EDIT_CRL *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmEditCrlDlgInit(hWnd, c);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_CN:
		case E_CN:
		case R_O:
		case E_O:
		case R_OU:
		case E_OU:
		case R_C:
		case E_C:
		case R_ST:
		case E_ST:
		case R_L:
		case E_L:
		case R_SERI:
		case E_SERI:
		case R_MD5_HASH:
		case E_MD5_HASH:
		case R_SHA1_HASH:
		case E_SHA1_HASH:
			SmEditCrlDlgUpdate(hWnd, c);
			break;
		}

		switch (wParam)
		{
		case B_LOAD:
			SmEditCrlDlgOnLoad(hWnd, c);
			break;

		case IDOK:
			SmEditCrlDlgOnOk(hWnd, c);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case R_CN:
			FocusEx(hWnd, E_CN);
			break;

		case R_O:
			FocusEx(hWnd, E_O);
			break;

		case R_OU:
			FocusEx(hWnd, E_OU);
			break;

		case R_C:
			FocusEx(hWnd, E_C);
			break;

		case R_ST:
			FocusEx(hWnd, E_ST);
			break;

		case R_L:
			FocusEx(hWnd, E_L);
			break;

		case R_SERI:
			FocusEx(hWnd, E_SERI);
			break;

		case R_MD5_HASH:
			FocusEx(hWnd, E_MD5_HASH);
			break;

		case R_SHA1_HASH:
			FocusEx(hWnd, E_SHA1_HASH);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Initialize the dialog
void SmCrlDlgInit(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_CERT_X);

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_CRL_COLUMN_1"), 555);

	SmCrlDlgRefresh(hWnd, s);
}

// Update the control
void SmCrlDlgUpdate(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetEnable(hWnd, IDOK, LvIsSingleSelected(hWnd, L_LIST));
	SetEnable(hWnd, B_DELETE, LvIsSingleSelected(hWnd, L_LIST));
}

// Content update
void SmCrlDlgRefresh(HWND hWnd, SM_HUB *s)
{
	UINT i;
	RPC_ENUM_CRL t;
	LVB *v;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (CALL(hWnd, ScEnumCrl(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	v = LvInsertStart();

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_CRL_ITEM *e = &t.Items[i];
		LvInsertAdd(v, ICO_CERT_X, (void *)e->Key, 1, e->CrlInfo);
	}

	LvInsertEndEx(v, hWnd, L_LIST, true);

	if (t.NumItem >= 1)
	{
		LvAutoSize(hWnd, L_LIST);
	}

	FreeRpcEnumCrl(&t);

	SmCrlDlgUpdate(hWnd, s);
}

// Certificate revocation list dialog procedure
UINT SmCrlDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_CRL c;
	SM_HUB *s = (SM_HUB *)param;
	NMHDR *n;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmCrlDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_ADD:
			Zero(&c, sizeof(c));
			c.NewCrl = true;
			c.s = s;

			if (Dialog(hWnd, D_SM_EDIT_CRL, SmEditCrlDlgProc, &c))
			{
				SmCrlDlgRefresh(hWnd, s);
			}
			break;

		case B_DELETE:
			if (IsEnable(hWnd, B_DELETE))
			{
				if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("SM_CRL_DELETE_MSG")) == IDYES)
				{
					RPC_CRL t;

					Zero(&t, sizeof(t));
					StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
					t.Key = (UINT)LvGetParam(hWnd, L_LIST, LvGetSelected(hWnd, L_LIST));

					if (CALL(hWnd, ScDelCrl(s->Rpc, &t)))
					{
						SmCrlDlgRefresh(hWnd, s);
					}

					FreeRpcCrl(&t);
				}
			}
			break;

		case IDOK:
			if (IsEnable(hWnd, IDOK))
			{
				SM_EDIT_CRL c;

				Zero(&c, sizeof(c));
				c.NewCrl = false;
				c.s = s;
				c.Key = (UINT)LvGetParam(hWnd, L_LIST, LvGetSelected(hWnd, L_LIST));

				if (Dialog(hWnd, D_SM_EDIT_CRL, SmEditCrlDlgProc, &c))
				{
					SmCrlDlgRefresh(hWnd, s);
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
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
				SmCrlDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}

// Smart Card Manager
void SmSecureManager(HWND hWnd)
{
	UINT id = SmGetCurrentSecureIdFromReg();

	if (id == 0)
	{
		id = SmSelectSecureId(hWnd);
	}

	if (id == 0)
	{
		return;
	}

	CmSecureManager(hWnd, id);
}

// Initialize the dialog
void SmSelectKeyPairDlgInit(HWND hWnd, SM_SECURE_KEYPAIR *k)
{
	SECURE_DEVICE *dev;
	// Validate arguments
	if (hWnd == NULL || k == NULL)
	{
		return;
	}

	dev = GetSecureDevice(k->Id);
	if (dev != NULL)
	{
		FormatText(hWnd, S_INFO, dev->DeviceName);
	}

	LvInit(hWnd, L_CERT);
	LvInsertColumn(hWnd, L_CERT, 0, _UU("SEC_MGR_COLUMN1"), 200);
	LvInsertColumn(hWnd, L_CERT, 1, _UU("SEC_MGR_COLUMN2"), 110);

	LvInit(hWnd, L_KEY);
	LvInsertColumn(hWnd, L_KEY, 0, _UU("SEC_MGR_COLUMN1"), 200);
	LvInsertColumn(hWnd, L_KEY, 1, _UU("SEC_MGR_COLUMN2"), 110);

	SetEnable(hWnd, L_CERT, k->UseCert);
	SetEnable(hWnd, B_BOLD1, k->UseCert);
	SetEnable(hWnd, L_KEY, k->UseKey);
	SetEnable(hWnd, B_BOLD2, k->UseKey);

	SetFont(hWnd, B_BOLD1, Font(0, true));
	SetFont(hWnd, B_BOLD2, Font(0, true));

	SmSelectKeyPairDlgUpdate(hWnd, k);
}

// Update the dialog control
void SmSelectKeyPairDlgUpdate(HWND hWnd, SM_SECURE_KEYPAIR *k)
{
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || k == NULL)
	{
		return;
	}

	if (k->UseCert)
	{
		if (LvIsSingleSelected(hWnd, L_CERT) == false)
		{
			ok = false;
		}
		else
		{
			char *name = LvGetSelectedStrA(hWnd, L_CERT, 0);
			if (name != NULL)
			{
				if (LvIsSingleSelected(hWnd, L_KEY) == false)
				{
					if ((k->Flag++) == 0)
					{
						LvSelect(hWnd, L_KEY, LvSearchStrA(hWnd, L_KEY, 0, name));
					}
				}
				Free(name);
			}
		}
	}

	if (k->UseKey)
	{
		if (LvIsSingleSelected(hWnd, L_KEY) == false)
		{
			ok = false;
		}
		else
		{
			char *name = LvGetSelectedStrA(hWnd, L_KEY, 0);
			if (name != NULL)
			{
				if (LvIsSingleSelected(hWnd, L_CERT) == false)
				{
					if ((k->Flag++) == 0)
					{
						LvSelect(hWnd, L_CERT, LvSearchStrA(hWnd, L_CERT, 0, name));
					}
				}
				Free(name);
			}
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// Update the contents
void SmSelectKeyPairDlgRefresh(HWND hWnd, SM_SECURE_KEYPAIR *k)
{
	bool ret;
	LIST *o;
	WINUI_SECURE_BATCH batch[] =
	{
		{WINUI_SECURE_ENUM_OBJECTS, NULL, false, NULL, NULL, NULL, NULL, NULL, NULL},
	};
	// Validate arguments
	if (hWnd == NULL || k == NULL)
	{
		return;
	}

	ret = SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), k->Id, k->BitmapId);

	if (ret == false)
	{
		Close(hWnd);
		return;
	}

	o = batch[0].EnumList;
	if (o != NULL)
	{
		if (k->UseCert)
		{
			CmSecureManagerDlgPrintListEx(hWnd, L_CERT, o, SEC_X);
		}

		if (k->UseKey)
		{
			CmSecureManagerDlgPrintListEx(hWnd, L_KEY, o, SEC_K);
		}

		FreeEnumSecObject(o);
	}

	// Update the control
	SmSelectKeyPairDlgUpdate(hWnd, k);
}

// Key pair import dialog procedure
UINT SmSelectKeyPairDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_SECURE_KEYPAIR *k = (SM_SECURE_KEYPAIR *)param;
	char *s1, *s2;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmSelectKeyPairDlgInit(hWnd, k);

		SetTimer(hWnd, 1, 1, NULL);
		SetTimer(hWnd, 2, 100, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			SmSelectKeyPairDlgRefresh(hWnd, k);
			break;

		case 2:
			SmSelectKeyPairDlgUpdate(hWnd, k);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			s1 = LvGetSelectedStrA(hWnd, L_CERT, 0);
			s2 = LvGetSelectedStrA(hWnd, L_KEY, 0);
			if (k->UseCert)
			{
				StrCpy(k->CertName, sizeof(k->CertName), s1);
			}
			if (k->UseKey)
			{
				StrCpy(k->KeyName, sizeof(k->KeyName), s2);
			}
			Free(s1);
			Free(s2);
			EndDialog(hWnd, true);
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
		case L_KEY:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmSelectKeyPairDlgUpdate(hWnd, k);
				break;
			}
			break;
		}
		break;
	}

	return 0;
}

// Read a key pair from the smart card
bool SmSelectKeyPair(HWND hWnd, char *cert_name, UINT cert_name_size, char *key_name, UINT key_name_size)
{
	return SmSelectKeyPairEx(hWnd, cert_name, cert_name_size, key_name, key_name_size, 0);
}
bool SmSelectKeyPairEx(HWND hWnd, char *cert_name, UINT cert_name_size, char *key_name, UINT key_name_size, UINT bitmap_id)
{
	SM_SECURE_KEYPAIR p;
	// Validate arguments
	if (hWnd == NULL || (cert_name == NULL && key_name == NULL))
	{
		return false;
	}

	Zero(&p, sizeof(p));
	p.Id = SmGetCurrentSecureId(hWnd);
	if (p.Id == 0)
	{
		return false;
	}

	p.UseCert = (cert_name == NULL) ? false : true;
	p.UseKey = (key_name == NULL) ? false : true;
	p.BitmapId = bitmap_id;

	if (Dialog(hWnd, D_SM_SELECT_KEYPAIR, SmSelectKeyPairDlg, &p) == false)
	{
		return false;
	}

	if (p.UseCert)
	{
		StrCpy(cert_name, cert_name_size, p.CertName);
	}
	if (p.UseKey)
	{
		StrCpy(key_name, key_name_size, p.KeyName);
	}

	return true;
}

// Make the user select the smart card number
UINT SmSelectSecureId(HWND hWnd)
{
	UINT id = MsRegReadInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "DeviceId");
	UINT ret;

	if (id != 0 && CheckSecureDeviceId(id) == false)
	{
		id = 0;
	}

	ret = CmSelectSecure(hWnd, id);
	if (ret == 0)
	{
		return 0;
	}

	SmWriteSelectSecureIdReg(ret);

	return ret;
}

// Write the current smart card number to the registry
void SmWriteSelectSecureIdReg(UINT id)
{
	MsRegWriteInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "DeviceId", id);
}

// Get the current smart card number
UINT SmGetCurrentSecureId(HWND hWnd)
{
	// Load the current settings
	UINT id = MsRegReadInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "DeviceId");

	// Check whether it's valid
	if (id == 0 || CheckSecureDeviceId(id) == false)
	{
		// Select a smart card device number if it's invalid
		id = SmSelectSecureId(hWnd);
	}

	return id;
}

// Get the current smart card number from the registry
UINT SmGetCurrentSecureIdFromReg()
{
	// Load the current settings
	UINT id = MsRegReadInt(REG_CURRENT_USER, SECURE_MANAGER_KEY, "DeviceId");

	// Check whether normal
	if (id == 0 || CheckSecureDeviceId(id) == false)
	{
		id = 0;
	}

	return id;
}

// Get whether the specified L3 switch started
bool SmL3IsSwActive(SM_SERVER *s, char *name)
{
	bool ret = false;
	UINT i;
	RPC_ENUM_L3SW t;
	// Validate arguments
	if (s == NULL || name == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (ScEnumL3Switch(s->Rpc, &t) == ERR_NO_ERROR)
	{
		for (i = 0;i < t.NumItem;i++)
		{
			RPC_ENUM_L3SW_ITEM *e = &t.Items[i];
			if (StrCmpi(e->Name, name) == 0)
			{
				if (e->Active)
				{
					ret = true;
					break;
				}
			}
		}
		FreeRpcEnumL3Sw(&t);
	}

	return ret;
}

// Initialize the dialog
void SmL3SwTableDlgInit(HWND hWnd, SM_L3SW *w)
{
	// Validate arguments
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	SmL3SwTableDlgUpdate(hWnd, w);
}

// Update the control
void SmL3SwTableDlgUpdate(HWND hWnd, SM_L3SW *w)
{
	bool b = true;
	UINT ip;
	// Validate arguments
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	if (IpIsFilled(hWnd, E_NETWORK) == false ||
		IpIsFilled(hWnd, E_MASK) == false ||
		IpIsFilled(hWnd, E_GATEWAY) == false)
	{
		b = false;
	}

	ip = IpGet(hWnd, E_GATEWAY);
	if (ip == 0 || ip == 0xffffffff)
	{
		b = false;
	}

	if (GetInt(hWnd, E_METRIC) == 0)
	{
		b = false;
	}

	if (IsNetworkAddress32(IpGet(hWnd, E_NETWORK), IpGet(hWnd, E_MASK)) == false)
	{
		b = false;
	}

	SetEnable(hWnd, IDOK, b);
}

UINT SmL3SwTableDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_L3SW *w = (SM_L3SW *)param;
	RPC_L3TABLE t;

	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmL3SwTableDlgInit(hWnd, w);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_NETWORK:
		case E_MASK:
		case E_GATEWAY:
		case E_METRIC:
			SmL3SwTableDlgUpdate(hWnd, w);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			Zero(&t, sizeof(t));
			StrCpy(t.Name, sizeof(t.Name), w->SwitchName);
			t.NetworkAddress = IpGet(hWnd, E_NETWORK);
			t.SubnetMask = IpGet(hWnd, E_MASK);
			t.GatewayAddress = IpGet(hWnd, E_GATEWAY);
			t.Metric = GetInt(hWnd, E_METRIC);

			if (CALL(hWnd, ScAddL3Table(w->s->Rpc, &t)))
			{
				EndDialog(hWnd, 1);
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

// Initialize the dialog
void SmL3SwIfDlgInit(HWND hWnd, SM_L3SW *w)
{
	RPC_ENUM_HUB t;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	if (CALL(hWnd, ScEnumHub(w->s->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	CbReset(hWnd, E_HUBNAME);
	CbSetHeight(hWnd, E_HUBNAME, 18);

	for (i = 0;i < t.NumHub;i++)
	{
		RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];

		if (e->HubType != HUB_TYPE_FARM_DYNAMIC)
		{
			CbAddStrA(hWnd, E_HUBNAME, e->HubName, 0);
		}
	}

	FreeRpcEnumHub(&t);

	SetTextA(hWnd, E_HUBNAME, "");

	SmL3SwIfDlgUpdate(hWnd, w);
}

// Update the control
void SmL3SwIfDlgUpdate(HWND hWnd, SM_L3SW *w)
{
	bool b = true;
	// Validate arguments
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	if (IsEmpty(hWnd, E_HUBNAME))
	{
		b = false;
	}

	if (IpIsFilled(hWnd, E_IP) == false || IpIsFilled(hWnd, E_MASK) == false)
	{
		b = false;
	}

	if (IpGet(hWnd, E_IP) == 0 || IpGet(hWnd, E_IP) == 0xffffffff)
	{
		b = false;
	}

	if (IsSubnetMask32(IpGet(hWnd, E_MASK)) == false)
	{
		b = false;
	}

	SetEnable(hWnd, IDOK, b);
}

// Dialog for adding a virtual interface
UINT SmL3SwIfDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_L3SW *w = (SM_L3SW *)param;
	char *hubname;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmL3SwIfDlgInit(hWnd, w);

		SetTimer(hWnd, 1, 250, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (IsEnable(hWnd, 0))
			{
				SmL3SwIfDlgUpdate(hWnd, w);
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_HUBNAME:
		case E_IP:
		case E_MASK:
			SmL3SwIfDlgUpdate(hWnd, w);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			hubname = GetTextA(hWnd, E_HUBNAME);
			if (hubname != NULL)
			{
				RPC_L3IF t;
				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), hubname);
				t.IpAddress = IpGet(hWnd, E_IP);
				t.SubnetMask = IpGet(hWnd, E_MASK);
				StrCpy(t.Name, sizeof(t.Name), w->SwitchName);

				if (CALL(hWnd, ScAddL3If(w->s->Rpc, &t)))
				{
					EndDialog(hWnd, 1);
				}

				Free(hubname);
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

// Initialize
void SmL3SwDlgInit(HWND hWnd, SM_L3SW *w)
{
	// Validate arguments
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SWITCH_OFFLINE);

	FormatText(hWnd, 0, w->SwitchName);

	SetFont(hWnd, S_BOLD1, Font(0, true));
	SetFont(hWnd, S_BOLD2, Font(0, true));

	LvInit(hWnd, L_IF);
	LvInsertColumn(hWnd, L_IF, 0, _UU("SM_L3_SW_IF_COLUMN1"), 150);
	LvInsertColumn(hWnd, L_IF, 1, _UU("SM_L3_SW_IF_COLUMN2"), 150);
	LvInsertColumn(hWnd, L_IF, 2, _UU("SM_L3_SW_IF_COLUMN3"), 180);

	LvInit(hWnd, L_TABLE);
	LvInsertColumn(hWnd, L_TABLE, 0, _UU("SM_L3_SW_TABLE_COLUMN1"), 130);
	LvInsertColumn(hWnd, L_TABLE, 1, _UU("SM_L3_SW_TABLE_COLUMN2"), 130);
	LvInsertColumn(hWnd, L_TABLE, 2, _UU("SM_L3_SW_TABLE_COLUMN3"), 130);
	LvInsertColumn(hWnd, L_TABLE, 3, _UU("SM_L3_SW_TABLE_COLUMN4"), 100);

	w->Enable = SmL3IsSwActive(w->s, w->SwitchName) ? false : true;

	SmL3SwDlgRefresh(hWnd, w);
}

// Update the control
void SmL3SwDlgUpdate(HWND hWnd, SM_L3SW *w)
{
	// Validate arguments
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	SetEnable(hWnd, B_ADD_IF, w->s->ServerAdminMode && w->Enable);
	SetEnable(hWnd, B_ADD_TABLE, w->s->ServerAdminMode && w->Enable);
	SetEnable(hWnd, B_DEL_IF, LvIsSingleSelected(hWnd, L_IF) && w->s->ServerAdminMode && w->Enable);
	SetEnable(hWnd, B_DEL_TABLE, LvIsSingleSelected(hWnd, L_TABLE) && w->s->ServerAdminMode && w->Enable);
	SetEnable(hWnd, B_START, w->s->ServerAdminMode && w->Enable);
	SetEnable(hWnd, B_STOP, w->s->ServerAdminMode && (w->Enable == false));
}

// Content update
void SmL3SwDlgRefresh(HWND hWnd, SM_L3SW *w)
{
	UINT i;
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	wchar_t tmp3[MAX_SIZE];
	wchar_t tmp4[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	// Virtual interface list
	{
		RPC_ENUM_L3IF t;
		LVB *v;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), w->SwitchName);

		if (CALL(hWnd, ScEnumL3If(w->s->Rpc, &t)) == false)
		{
			Close(hWnd);
			return;
		}

		v = LvInsertStart();

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_L3IF *e = &t.Items[i];

			IPToUniStr32(tmp1, sizeof(tmp1), e->IpAddress);
			IPToUniStr32(tmp2, sizeof(tmp2), e->SubnetMask);
			StrToUni(tmp3, sizeof(tmp3), e->HubName);

			LvInsertAdd(v, ICO_NIC_ONLINE, NULL, 3, tmp1, tmp2, tmp3);
		}

		LvReset(hWnd, L_IF);

		LvInsertEnd(v, hWnd, L_IF);

		FreeRpcEnumL3If(&t);
	}

	// Routing Table Entry List
	{
		RPC_ENUM_L3TABLE t;
		LVB *v;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), w->SwitchName);

		if (CALL(hWnd, ScEnumL3Table(w->s->Rpc, &t)) == false)
		{
			Close(hWnd);
			return;
		}

		v = LvInsertStart();

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_L3TABLE *e = &t.Items[i];

			IPToUniStr32(tmp1, sizeof(tmp1), e->NetworkAddress);
			IPToUniStr32(tmp2, sizeof(tmp2), e->SubnetMask);
			IPToUniStr32(tmp3, sizeof(tmp3), e->GatewayAddress);
			UniToStru(tmp4, e->Metric);

			LvInsertAdd(v, ICO_PROTOCOL, NULL, 4, tmp1, tmp2, tmp3, tmp4);
		}

		LvReset(hWnd, L_TABLE);

		LvInsertEnd(v, hWnd, L_TABLE);

		FreeRpcEnumL3Table(&t);
	}

	SmL3SwDlgUpdate(hWnd, w);
}

// Edit dialog of L3 switch
UINT SmL3SwDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_L3SW *w = (SM_L3SW *)param;
	NMHDR *n;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmL3SwDlgInit(hWnd, w);

		SetTimer(hWnd, 1, 1000, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (IsEnable(hWnd, 0))
			{
				KillTimer(hWnd, 1);
				w->Enable = SmL3IsSwActive(w->s, w->SwitchName) ? false : true;
				SmL3SwDlgUpdate(hWnd, w);
				SetTimer(hWnd, 1, 1000, NULL);
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_START:
			if (IsEnable(hWnd, B_START))
			{
				RPC_L3SW t;

				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), w->SwitchName);

				if (CALL(hWnd, ScStartL3Switch(w->s->Rpc, &t)))
				{
					SmL3SwDlgUpdate(hWnd, w);
				}
			}
			break;

		case B_STOP:
			if (IsEnable(hWnd, B_STOP))
			{
				RPC_L3SW t;

				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), w->SwitchName);

				if (CALL(hWnd, ScStopL3Switch(w->s->Rpc, &t)))
				{
					SmL3SwDlgUpdate(hWnd, w);
				}
			}
			break;

		case B_ADD_IF:
			if (Dialog(hWnd, D_SM_L3_SW_IF, SmL3SwIfDlg, w))
			{
				SmL3SwDlgRefresh(hWnd, w);
			}
			break;

		case B_DEL_IF:
			if (LvIsSingleSelected(hWnd, L_IF))
			{
				RPC_L3IF t;
				char *tmp1, *tmp2, *tmp3;

				tmp1 = LvGetSelectedStrA(hWnd, L_IF, 0);
				tmp2 = LvGetSelectedStrA(hWnd, L_IF, 1);
				tmp3 = LvGetSelectedStrA(hWnd, L_IF, 2);

				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), w->SwitchName);
				t.IpAddress = StrToIP32(tmp1);
				t.SubnetMask = StrToIP32(tmp2);
				StrCpy(t.HubName, sizeof(t.HubName), tmp3);

				if (CALL(hWnd, ScDelL3If(w->s->Rpc, &t)))
				{
					SmL3SwDlgRefresh(hWnd, w);
				}

				Free(tmp1);
				Free(tmp2);
				Free(tmp3);
			}
			break;

		case B_ADD_TABLE:
			if (Dialog(hWnd, D_SM_L3_SW_TABLE, SmL3SwTableDlg, w))
			{
				SmL3SwDlgRefresh(hWnd, w);
			}
			break;

		case B_DEL_TABLE:
			if (LvIsSingleSelected(hWnd, L_TABLE))
			{
				RPC_L3TABLE t;
				char *tmp1, *tmp2, *tmp3, *tmp4;

				tmp1 = LvGetSelectedStrA(hWnd, L_TABLE, 0);
				tmp2 = LvGetSelectedStrA(hWnd, L_TABLE, 1);
				tmp3 = LvGetSelectedStrA(hWnd, L_TABLE, 2);
				tmp4 = LvGetSelectedStrA(hWnd, L_TABLE, 3);

				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), w->SwitchName);
				t.NetworkAddress = StrToIP32(tmp1);
				t.SubnetMask = StrToIP32(tmp2);
				t.GatewayAddress = StrToIP32(tmp3);
				t.Metric = ToInt(tmp4);

				if (CALL(hWnd, ScDelL3Table(w->s->Rpc, &t)))
				{
					SmL3SwDlgRefresh(hWnd, w);
				}

				Free(tmp1);
				Free(tmp2);
				Free(tmp3);
				Free(tmp4);
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
		case L_IF:
		case L_TABLE:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmL3SwDlgUpdate(hWnd, w);
				break;
			}
			break;
		}
		break;
	}

	return 0;
}

// Update the control
void SmL3AddDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	char *tmp;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	tmp = GetTextA(hWnd, E_NAME);

	SetEnable(hWnd, IDOK, IsEmptyStr(tmp) == false && IsSafeStr(tmp));

	Free(tmp);
}

// The dialog box to create a new L3 switch
UINT SmL3AddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *s = (SM_SERVER *)param;
	RPC_L3SW t;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		LimitText(hWnd, E_NAME, MAX_HUBNAME_LEN);
		SmL3AddDlgUpdate(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_NAME:
			SmL3AddDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			Zero(&t, sizeof(t));
			GetTxtA(hWnd, E_NAME, t.Name, sizeof(t.Name));
			if (CALL(hWnd, ScAddL3Switch(s->Rpc, &t)))
			{
				EndDialog(hWnd, 1);
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

// Initialize the dialog
void SmL3DlgInit(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetFont(hWnd, S_BOLD, Font(0, true));

	SetIcon(hWnd, 0, ICO_SWITCH);

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_L3_SW_COLUMN1"), 150);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_L3_SW_COLUMN2"), 120);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_L3_SW_COLUMN3"), 100);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_L3_SW_COLUMN4"), 100);

	SmL3DlgRefresh(hWnd, s);
}

// Update the dialog control
void SmL3DlgUpdate(HWND hWnd, SM_SERVER *s)
{
	bool b = false;
	bool active = false;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSingleSelected(hWnd, L_LIST))
	{
		wchar_t *tmp;
		UINT i;
		b = true;
		i = LvGetSelected(hWnd, L_LIST);
		if (i != INFINITE)
		{
			tmp = LvGetStr(hWnd, L_LIST, i, 1);
			if (UniStrCmpi(tmp, _UU("SM_L3_SW_ST_F_F")) != 0)
			{
				active = true;
			}
			Free(tmp);
		}
	}

	SetEnable(hWnd, B_START, b && (active == false));
	SetEnable(hWnd, B_STOP, b && (active != false));
	SetEnable(hWnd, IDOK, b);
	SetEnable(hWnd, B_DELETE, b);
}

// Dialog content update
void SmL3DlgRefresh(HWND hWnd, SM_SERVER *s)
{
	RPC_ENUM_L3SW t;
	UINT i;
	LVB *v;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumL3Switch(s->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	v = LvInsertStart();

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_L3SW_ITEM *e = &t.Items[i];
		wchar_t tmp1[MAX_SIZE], *tmp2, tmp3[64], tmp4[64];

		StrToUni(tmp1, sizeof(tmp1), e->Name);
		if (e->Active == false)
		{
			tmp2 = _UU("SM_L3_SW_ST_F_F");
		}
		else if (e->Online == false)
		{
			tmp2 = _UU("SM_L3_SW_ST_T_F");
		}
		else
		{
			tmp2 = _UU("SM_L3_SW_ST_T_T");
		}
		UniToStru(tmp3, e->NumInterfaces);
		UniToStru(tmp4, e->NumTables);

		LvInsertAdd(v, e->Active ? ICO_SWITCH : ICO_SWITCH_OFFLINE, NULL,
			4, tmp1, tmp2, tmp3, tmp4);
	}

	LvInsertEnd(v, hWnd, L_LIST);

	FreeRpcEnumL3Sw(&t);

	SmL3DlgUpdate(hWnd, s);
}

// L3 dialog procedure
UINT SmL3Dlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_SERVER *s = (SM_SERVER *)param;
	RPC_L3SW t;
	char *name;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmL3DlgInit(hWnd, s);

		SetTimer(hWnd, 1, 1000, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (IsEnable(hWnd, 0))
			{
				KillTimer(hWnd, 1);
				SmL3DlgRefresh(hWnd, s);
				SetTimer(hWnd, 1, 1000, NULL);
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_ADD:
			// Add
			if (Dialog(hWnd, D_SM_L3_ADD, SmL3AddDlg, s))
			{
				SmL3DlgRefresh(hWnd, s);
			}
			break;

		case B_START:
			// Operation start
			name = LvGetSelectedStrA(hWnd, L_LIST, 0);
			if (name != NULL)
			{
				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), name);

				if (CALL(hWnd, ScStartL3Switch(s->Rpc, &t)))
				{
					SmL3DlgRefresh(hWnd, s);
				}

				Free(name);
			}
			break;

		case B_STOP:
			// Operation stop
			name = LvGetSelectedStrA(hWnd, L_LIST, 0);
			if (name != NULL)
			{
				Zero(&t, sizeof(t));
				StrCpy(t.Name, sizeof(t.Name), name);

				if (CALL(hWnd, ScStopL3Switch(s->Rpc, &t)))
				{
					SmL3DlgRefresh(hWnd, s);
				}

				Free(name);
			}
			break;

		case IDOK:
			// Edit
			if (IsEnable(hWnd, IDOK))
			{
				name = LvGetSelectedStrA(hWnd, L_LIST, 0);
				if (name != NULL)
				{
					SM_L3SW w;
					Zero(&w, sizeof(w));
					w.s = s;
					w.SwitchName = name;

					Dialog(hWnd, D_SM_L3_SW, SmL3SwDlg, &w);

					Free(name);
				}
			}
			break;

		case B_DELETE:
			// Delete
			name = LvGetSelectedStrA(hWnd, L_LIST, 0);
			if (name != NULL)
			{
				if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2,
					_UU("SM_L3_SW_DEL_MSG"), name) == IDYES)
				{
					Zero(&t, sizeof(t));
					StrCpy(t.Name, sizeof(t.Name), name);

					if (CALL(hWnd, ScDelL3Switch(s->Rpc, &t)))
					{
						SmL3DlgRefresh(hWnd, s);
					}
				}

				Free(name);
			}
			break;

		case IDCANCEL:
			// Close
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmL3DlgUpdate(hWnd, s);
				break;

			case NM_DBLCLK:
				Command(hWnd, IDOK);
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

// L3 dialog
void SmL3(HWND hWnd, SM_SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_L3, SmL3Dlg, s);
}

// Dialog for management option value
UINT SmHubAdminOptionValueDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_AO *a = (SM_EDIT_AO *)param;
	UINT i;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		CbReset(hWnd, C_NAME);
		for (i = 0;i < a->DefaultOptions.NumItem;i++)
		{
			wchar_t tmp[MAX_PATH];
			StrToUni(tmp, sizeof(tmp), a->DefaultOptions.Items[i].Name);
			CbAddStr(hWnd, C_NAME, tmp, 0);
		}
		if (a->NewMode == false)
		{
			char tmp[MAX_SIZE];

			SetTextA(hWnd, C_NAME, a->Name);
			ToStr(tmp, a->Value);

			SetTextA(hWnd, E_VALUE, tmp);
		}
		else
		{
			SetTextA(hWnd, C_NAME, "");
		}
		SmHubAdminOptionValueDlgUpdate(hWnd, a);
		if (a->NewMode == false)
		{
			FocusEx(hWnd, E_VALUE);
			Disable(hWnd, C_NAME);
		}
		else
		{
			FocusEx(hWnd, C_NAME);
		}

		SetTimer(hWnd, 1, 100, NULL);
		break;

	case WM_TIMER:
		if (IsEnable(hWnd, 0))
		{
			SmHubAdminOptionValueDlgUpdate(hWnd, a);
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (a->NewMode)
			{
				GetTxtA(hWnd, C_NAME, a->Name, sizeof(a->Name));
			}

			GetTxtA(hWnd, E_VALUE, tmp, sizeof(tmp));
			a->Value = ToInt(tmp);

			Trim(a->Name);

			if (StartWith(a->Name, "no") || StartWith(a->Name, "allow") || StartWith(a->Name, "deny")
				 || StartWith(a->Name, "filter") || StartWith(a->Name, "fix") || StartWith(a->Name, "force")
				 || StartWith(a->Name, "use") || StartWith(a->Name, "b_") || StartWith(a->Name, "is")
				 || StartWith(a->Name, "manage") || StartWith(a->Name, "yield")
				 || StartWith(a->Name, "permit") || StartWith(a->Name, "yes") || StartWith(a->Name, "ok")
				 || StartWith(a->Name, "do") || StartWith(a->Name, "only") || StartWith(a->Name, "disable"))
			{
				if (StrCmpi(tmp, "0") != 0 && StrCmpi(tmp, "1") != 0)
				{
					MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SM_TRUE_OR_FALSE"));
					FocusEx(hWnd, E_VALUE);
					break;
				}
			}

			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}

		SmHubAdminOptionValueDlgUpdate(hWnd, a);

		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Update the dialog controls for management option value
void SmHubAdminOptionValueDlgUpdate(HWND hWnd, SM_EDIT_AO *a)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	GetTxtA(hWnd, C_NAME, tmp, sizeof(tmp));

	SetEnable(hWnd, IDOK, IsEmpty(hWnd, C_NAME) == false && IsEmpty(hWnd, E_VALUE) == false &&
		IsSafeStr(tmp));
}

// Initialize
void SmHubAdminOptionDlgInit(HWND hWnd, SM_EDIT_AO *a)
{
	UINT i;
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_USER_ADMIN);

	if (a->e->p->ServerAdminMode)
	{
		a->CanChange = true;
	}
	else
	{
		if (a->ExtOption == false)
		{
			for (i = 0;i < a->CurrentOptions.NumItem;i++)
			{
				if (StrCmpi(a->CurrentOptions.Items[i].Name, "allow_hub_admin_change_option") == 0)
				{
					if (a->CurrentOptions.Items[i].Value != 0)
					{
						a->CanChange = true;
					}
				}
			}
		}
		else
		{
			a->CanChange = true;
		}
	}

	FormatText(hWnd, S_INFO, a->e->HubName);

	DlgFont(hWnd, S_BOLD, 0, true);

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_AO_COLUMN_1"), 260);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_AO_COLUMN_2"), 100);

	for (i = 0;i < a->CurrentOptions.NumItem;i++)
	{
		ADMIN_OPTION *e = &a->CurrentOptions.Items[i];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];

		StrToUni(tmp1, sizeof(tmp1), e->Name);
		UniToStru(tmp2, e->Value);

		LvInsert(hWnd, L_LIST, ICO_LOG, NULL, 2, tmp1, tmp2);
			
	}

	if (a->ExtOption)
	{
		SetIcon(hWnd, S_ICON, ICO_LINK2);
		SetIcon(hWnd, 0, ICO_LINK2);

		SetText(hWnd, 0, _UU("SM_HUBEXT_OPTION_TITLE"));
		SetText(hWnd, S_STATIC1, _UU("SM_HUBEXT_OPTION_STATIC1"));
		SetText(hWnd, S_STATIC2, _UU("SM_HUBEXT_OPTION_STATIC2"));
	}

	// Update the control
	SmHubAdminOptionDlgUpdate(hWnd, a);
}

// Update the control
void SmHubAdminOptionDlgUpdate(HWND hWnd, SM_EDIT_AO *a)
{
	bool b = false;
	wchar_t *helpstr;
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	helpstr = _UU("HUB_AO_CLICK");

	SetEnable(hWnd, IDOK, a->CanChange);
	SetEnable(hWnd, B_ADD, a->CanChange);
	SetEnable(hWnd, B_EDIT, a->CanChange && (LvIsMasked(hWnd, L_LIST) && LvIsMultiMasked(hWnd, L_LIST) == false));

	if (LvIsMasked(hWnd, L_LIST) && LvIsMultiMasked(hWnd, L_LIST) == false)
	{
		UINT i;
		i = LvGetSelected(hWnd, L_LIST);

		if (a->CanChange)
		{

			b = true;

			if (i != INFINITE)
			{
				char *name = LvGetStrA(hWnd, L_LIST, i, 0);
				if (name != NULL)
				{
					UINT j;

					for (j = 0;j < a->DefaultOptions.NumItem;j++)
					{
						if (StrCmpi(a->DefaultOptions.Items[j].Name, name) == 0)
						{
							b = false;
						}
					}
					Free(name);
				}
			}
		}

		if (i != INFINITE)
		{
			char *name = LvGetStrA(hWnd, L_LIST, i, 0);
			if (name != NULL)
			{
				helpstr = GetHubAdminOptionHelpString(name);
			}
			Free(name);
		}
	}
	SetEnable(hWnd, B_DELETE, b);

	SetText(hWnd, E_HELP, helpstr);
}

// Save
void SmHubAdminOptionDlgOk(HWND hWnd, SM_EDIT_AO *a)
{
	UINT i, num;
	RPC_ADMIN_OPTION t;
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	num = LvNum(hWnd, L_LIST);

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), a->e->HubName);
	t.NumItem = num;
	t.Items = ZeroMalloc(sizeof(ADMIN_OPTION) * num);

	for (i = 0;i < num;i++)
	{
		char *name = LvGetStrA(hWnd, L_LIST, i, 0);
		char *s_value = LvGetStrA(hWnd, L_LIST, i, 1);
		ADMIN_OPTION *a = &t.Items[i];

		StrCpy(a->Name, sizeof(a->Name), name);
		a->Value = ToInt(s_value);

		Free(name);
		Free(s_value);
	}

	if (a->ExtOption == false)
	{
		if (CALL(hWnd, ScSetHubAdminOptions(a->e->p->Rpc, &t)))
		{
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_AO_SET_OK"));
			EndDialog(hWnd, true);
		}
	}
	else
	{
		if (CALL(hWnd, ScSetHubExtOptions(a->e->p->Rpc, &t)))
		{
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_EXT_OPTION_SET_OK"));
			EndDialog(hWnd, true);
		}
	}

	FreeRpcAdminOption(&t);
}

// Virtual HUB Management Options dialog
UINT SmHubAdminOptionDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_AO *a = (SM_EDIT_AO *)param;
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
		SmHubAdminOptionDlgInit(hWnd, a);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_ADD:
			a->NewMode = true;
			StrCpy(a->Name, sizeof(a->Name), "");
			a->Value = 0;
			if (Dialog(hWnd, D_SM_AO_VALUE, SmHubAdminOptionValueDlg,
				a))
			{
				wchar_t tmp1[MAX_SIZE];
				wchar_t tmp2[MAX_SIZE];
				StrToUni(tmp1, sizeof(tmp1), a->Name);
				UniToStru(tmp2, a->Value);

				LvInsert(hWnd, L_LIST, ICO_LOG, NULL, 2, tmp1, tmp2);
			}
			break;

		case B_EDIT:
			i = LvGetSelected(hWnd, L_LIST);
			if (i != INFINITE && a->CanChange)
			{
				char *name, *value;
				name = LvGetStrA(hWnd, L_LIST, i, 0);
				value = LvGetStrA(hWnd, L_LIST, i, 1);
				a->NewMode = false;
				StrCpy(a->Name, sizeof(a->Name), name);
				a->Value = ToInt(value);

				if (Dialog(hWnd, D_SM_AO_VALUE, SmHubAdminOptionValueDlg,
					a))
				{
					char tmp[MAX_PATH];
					ToStr(tmp, a->Value);
					LvSetItemA(hWnd, L_LIST, i, 1, tmp);
				}

				Free(name);
				Free(value);
			}
			break;

		case B_DELETE:
			i = LvGetSelected(hWnd, L_LIST);
			if (i != INFINITE)
			{
				LvDeleteItem(hWnd, L_LIST, i);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case IDOK:
			SmHubAdminOptionDlgOk(hWnd, a);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmHubAdminOptionDlgUpdate(hWnd, a);
				break;

			case NM_DBLCLK:
				Command(hWnd, B_EDIT);
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

// Virtual HUB extended options
void SmHubExtOption(HWND hWnd, SM_EDIT_HUB *e)
{
	SM_EDIT_AO a;
	// Validate arguments
	if (hWnd == NULL || e == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));
	a.e = e;
	a.ExtOption = true;

	StrCpy(a.CurrentOptions.HubName, sizeof(a.CurrentOptions.HubName), e->HubName);

	// Get the current options on the server
	if (CALL(hWnd, ScGetHubExtOptions(e->p->Rpc, &a.CurrentOptions)) == false)
	{
		return;
	}

	Dialog(hWnd, D_SM_ADMIN_OPTION, SmHubAdminOptionDlg, &a);

	FreeRpcAdminOption(&a.CurrentOptions);
	FreeRpcAdminOption(&a.DefaultOptions);
}

// Virtual HUB management options
void SmHubAdminOption(HWND hWnd, SM_EDIT_HUB *e)
{
	SM_EDIT_AO a;
	// Validate arguments
	if (hWnd == NULL || e == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));
	a.e = e;

	StrCpy(a.CurrentOptions.HubName, sizeof(a.CurrentOptions.HubName), e->HubName);

	// Get the current options on the server
	if (CALL(hWnd, ScGetHubAdminOptions(e->p->Rpc, &a.CurrentOptions)) == false)
	{
		return;
	}

	ScGetDefaultHubAdminOptions(e->p->Rpc, &a.DefaultOptions);

	Dialog(hWnd, D_SM_ADMIN_OPTION, SmHubAdminOptionDlg, &a);

	FreeRpcAdminOption(&a.CurrentOptions);
	FreeRpcAdminOption(&a.DefaultOptions);
}

// Initialize
void SmConfigDlgInit(HWND hWnd, SM_CONFIG *c)
{
	wchar_t *tmp;
	UINT tmp_size;
	// Validate arguments
	if (hWnd == NULL || c == NULL)
	{
		return;
	}

	Focus(hWnd, IDCANCEL);

	SetIcon(hWnd, 0, ICO_MACHINE);

	SetFont(hWnd, E_CONFIG, GetFont(_SS("DEFAULT_FONT_2"), 0, false, false,
		false, false));

	FormatText(hWnd, IDC_INFO, c->s->ServerName);

	// Convert from UTF-8 to Unicode
	tmp_size = CalcUtf8ToUni(c->Config.FileData, StrLen(c->Config.FileData)) + 1;
	tmp = ZeroMalloc(tmp_size);
	Utf8ToUni(tmp, tmp_size, c->Config.FileData, StrLen(c->Config.FileData));

	SetText(hWnd, E_CONFIG, tmp);

	Free(tmp);
}

// Config edit dialog
UINT SmConfigDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_CONFIG *c = (SM_CONFIG *)param;
	char *filename;
	wchar_t *filename_unicode;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmConfigDlgInit(hWnd, c);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_EXPORT:
			StrToUni(tmp, sizeof(tmp), c->Config.FileName);
			filename_unicode = SaveDlg(hWnd, _UU("DLG_CONFIG_FILES"), _UU("DLG_SAVE_CONFIG"), tmp, L".config");
			if (filename_unicode != NULL)
			{
				BUF *b = NewBuf();
				filename = CopyUniToStr(filename_unicode);
				WriteBuf(b, c->Config.FileData, StrLen(c->Config.FileData));
				if (DumpBuf(b, filename))
				{
					MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_CONFIG_SAVED"));
				}
				else
				{
					MsgBox(hWnd, MB_ICONSTOP, _UU("SM_CONFIG_SAVE_FAILED"));
				}
				FreeBuf(b);
				Free(filename);
				Free(filename_unicode);
			}
			break;

		case B_IMPORT:
			filename_unicode = OpenDlg(hWnd, _UU("DLG_CONFIG_FILES"), _UU("DLG_OPEN_CONFIG"));
			if (filename_unicode != NULL)
			{
				BUF *b;
				filename = CopyUniToStr(filename_unicode);
				b = ReadDump(filename);
				if (b != NULL)
				{
					RPC_CONFIG t;

					if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("SM_CONFIG_CONFIRM")) == IDYES)
					{
						Zero(&t, sizeof(t));
						t.FileData = ZeroMalloc(b->Size + 1);
						Copy(t.FileData, b->Buf, b->Size);

						if (CALL(hWnd, ScSetConfig(c->s->Rpc, &t)))
						{
							// Success
							MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_CONFIG_WRITE_OK"));
							_exit(0);
						}

						FreeRpcConfig(&t);

						FreeRpcConfig(&t);
						FreeBuf(b);
					}
				}
				else
				{
					MsgBox(hWnd, MB_ICONSTOP, _UU("SM_CONFIG_OPEN_FAILED"));
				}
				Free(filename);
				Free(filename_unicode);
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_FACTORY:
			if (MsgBox(hWnd, MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2, _UU("SM_FACTORY_DEFAULT_WARNING")) == IDYES)
			{
				RPC_TEST t;
				UINT ret;

				Zero(&t, sizeof(t));

				t.IntValue = 1;
				ret = ScRebootServer(c->s->Rpc, &t);

				if (ret == ERR_DISCONNECTED || ret == ERR_NO_ERROR)
				{
					MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_FACTORY_DEFAULT_PERFORMED"));

					exit(0);
				}
				else
				{
					CALL(hWnd, ret);
				}
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

// Show the config edit dialog
void SmConfig(HWND hWnd, SM_SERVER *s)
{
	SM_CONFIG c;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&c, sizeof(c));

	c.s = s;

	// Get current config from the server
	if (CALL(hWnd, ScGetConfig(s->Rpc, &c.Config)) == false)
	{
		return;
	}

	// Show the dialog
	Dialog(hWnd, D_SM_CONFIG, SmConfigDlg, &c);

	// Release
	FreeRpcConfig(&c.Config);
}

// Bridge dialog initialization
UINT SmBridgeDlgInit(HWND hWnd, SM_SERVER *s)
{
	UINT i;
	RPC_ENUM_ETH t;
	RPC_SERVER_INFO si;
	UINT num = 0;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return 0;
	}

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_BRIDGE_COLUMN_1"), 50);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_BRIDGE_COLUMN_2"), 145);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_BRIDGE_COLUMN_3"), 300);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_BRIDGE_COLUMN_4"), 100);

	SmBridgeDlgRefresh(hWnd, s);

	SetShow(hWnd, B_VLAN, GetCapsBool(s->CapsList, "b_support_eth_vlan"));

	SetIcon(hWnd, 0, ICO_BRIDGE);

	// Get the server information
	Zero(&si, sizeof(si));
	ScGetServerInfo(s->Rpc, &si);
	if (GetCapsBool(s->CapsList, "b_tap_supported") == false)
	{
		// Tap does not supported
		Hide(hWnd, R_TAP);
		Hide(hWnd, S_TAP_1);
		Hide(hWnd, E_TAPNAME);
		Hide(hWnd, S_TAP_2);
		Hide(hWnd, R_BRIDGE);
		Hide(hWnd, S_STATIC5);
	}
	Check(hWnd, R_BRIDGE, true);
	FreeRpcServerInfo(&si);

	// Enumerate the Ethernet devices
	Zero(&t, sizeof(t));
	ScEnumEthernet(s->Rpc, &t);

	CbReset(hWnd, E_NICNAME);
	CbSetHeight(hWnd, E_NICNAME, 18);

	num = t.NumItem;

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *e = &t.Items[i];
		if (GetCapsBool(s->CapsList, "b_support_network_connection_name"))
		{
			wchar_t ncname[MAX_SIZE * 2];
			UniFormat(ncname, sizeof(ncname), BRIDGE_NETWORK_CONNECTION_STR, e->NetworkConnectionName, e->DeviceName);
			CbAddStr(hWnd, E_NICNAME, ncname, 0);
		}
		else
		{
			wchar_t *s = CopyStrToUni(e->DeviceName);
			CbAddStr(hWnd, E_NICNAME, s, 0);
			Free(s);
		}
	}

	FreeRpcEnumEth(&t);

	// Enumerate the Virtual HUBs
	{
		RPC_ENUM_HUB t;
		Zero(&t, sizeof(t));

		ScEnumHub(s->Rpc, &t);

		CbReset(hWnd, E_HUBNAME);
		CbSetHeight(hWnd, E_HUBNAME, 18);

		for (i = 0;i < t.NumHub;i++)
		{
			RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];
			wchar_t *s = CopyStrToUni(e->HubName);

			if (e->HubType != HUB_TYPE_FARM_DYNAMIC)
			{
				CbAddStr(hWnd, E_HUBNAME, s, 0);
			}
			Free(s);
		}

		SetText(hWnd, E_HUBNAME, L"");

		FreeRpcEnumHub(&t);
	}

	if (s->Bridge)
	{
		SetTextA(hWnd, E_HUBNAME, "BRIDGE");
	}

	Focus(hWnd, E_HUBNAME);
	
	SmBridgeDlgUpdate(hWnd, s);

	SetTimer(hWnd, 1, 1000, NULL);

	return num;
}

// Bridge dialog control update
void SmBridgeDlgUpdate(HWND hWnd, SM_SERVER *s)
{
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsMasked(hWnd, L_LIST) && LvIsMultiMasked(hWnd, L_LIST) == false)
	{
		Enable(hWnd, B_DELETE);
	}
	else
	{
		Disable(hWnd, B_DELETE);
	}

	if (IsEmpty(hWnd, E_HUBNAME))
	{
		ok = false;
	}

	if (IsChecked(hWnd, R_TAP) == false)
	{
		// Bridge mode
		Enable(hWnd, S_ETH_1);
		Enable(hWnd, E_NICNAME);
		Disable(hWnd, S_TAP_1);
		Disable(hWnd, S_TAP_2);
		Disable(hWnd, E_TAPNAME);
		SetText(hWnd, S_INFO, _UU("SM_BRIDGE_INFO_1"));
		SetIcon(hWnd, S_ICON, ICO_NIC_ONLINE);
		if (IsEmpty(hWnd, E_NICNAME))
		{
			ok = false;
		}
	}
	else
	{
		char tmp[MAX_SIZE];
		// Tap mode
		Disable(hWnd, S_ETH_1);
		Disable(hWnd, E_NICNAME);
		Enable(hWnd, S_TAP_1);
		Enable(hWnd, S_TAP_2);
		Enable(hWnd, E_TAPNAME);
		SetText(hWnd, S_INFO, _UU("SM_BRIDGE_INFO_2"));
		SetIcon(hWnd, S_ICON, ICO_PROTOCOL);
		GetTxtA(hWnd, E_TAPNAME, tmp, sizeof(tmp));
		if (IsEmptyStr(tmp))
		{
			ok = false;
		}
		else
		{
			if (IsSafeStr(tmp) == false)
			{
				ok = false;
			}
			if (StrLen(tmp) >= 12)
			{
				ok = false;
			}
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// Bridge dialog update
void SmBridgeDlgRefresh(HWND hWnd, SM_SERVER *s)
{
	LVB *lvb;
	RPC_ENUM_LOCALBRIDGE t;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	lvb = LvInsertStart();

	Zero(&t, sizeof(t));

	ScEnumLocalBridge(s->Rpc, &t);

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t.Items[i];
		wchar_t name[MAX_SIZE];
		wchar_t nic[MAX_SIZE];
		wchar_t hub[MAX_SIZE];
		wchar_t *status = _UU("SM_BRIDGE_OFFLINE");

		UniToStru(name, i + 1);
		StrToUni(nic, sizeof(nic), e->DeviceName);
		StrToUni(hub, sizeof(hub), e->HubName);

		if (e->Online)
		{
			status = e->Active ? _UU("SM_BRIDGE_ONLINE") : _UU("SM_BRIDGE_ERROR");
		}

		LvInsertAdd(lvb, e->TapMode == false ? (e->Active ? ICO_NIC_ONLINE : ICO_NIC_OFFLINE) : ICO_PROTOCOL,
			NULL, 4, name, hub, nic, status);
	}

	FreeRpcEnumLocalBridge(&t);

	LvInsertEnd(lvb, hWnd, L_LIST);

	SmBridgeDlgUpdate(hWnd, s);
}

// Add a Local Bridge
void SmBridgeDlgOnOk(HWND hWnd, SM_SERVER *s)
{
	char nic[MAX_SIZE];
	char hub[MAX_SIZE];
	RPC_LOCALBRIDGE t;
	bool tapmode = false;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_HUBNAME, hub, sizeof(hub));

	Zero(nic, sizeof(nic));

	if (IsChecked(hWnd, R_TAP) == false)
	{
		wchar_t nctmp[MAX_SIZE * 2];
		if(GetCapsBool(s->CapsList, "b_support_network_connection_name") && GetTxt(hWnd, E_NICNAME, nctmp, sizeof(nctmp)))
		{
			RPC_ENUM_ETH et;
			UINT i;
			Zero(&et, sizeof(et));
			ScEnumEthernet(s->Rpc, &et);
			for(i = 0; i < et.NumItem; i++)
			{
				RPC_ENUM_ETH_ITEM *e = &et.Items[i];
				if(UniIsEmptyStr(e->NetworkConnectionName) == false)
				{
					wchar_t ncname[MAX_SIZE * 2];
					UniFormat(ncname, sizeof(ncname), BRIDGE_NETWORK_CONNECTION_STR, e->NetworkConnectionName, e->DeviceName);
					if(UniStrCmp(ncname, nctmp) == 0)
					{
						StrCpy(nic, sizeof(nic), e->DeviceName);
						break;
					}
				}		
			}
			FreeRpcEnumEth(&et);

			if (IsEmptyStr(nic))
			{
				GetTxtA(hWnd, E_NICNAME, nic, sizeof(nic));
			}
		}
		else
		{
			GetTxtA(hWnd, E_NICNAME, nic, sizeof(nic));
		}
	}
	else
	{
		tapmode = true;
		GetTxtA(hWnd, E_TAPNAME, nic, sizeof(nic));
	}

	Trim(hub);
	Trim(nic);

	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), nic);
	StrCpy(t.HubName, sizeof(t.HubName), hub);
	t.TapMode = tapmode;

	if (InStrEx(t.DeviceName, "vpn", false) || InStrEx(t.DeviceName, "tun", false)
		|| InStrEx(t.DeviceName, "tap", false))
	{
		// Trying to make a local bridge to the VPN device
		if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2,
			_UU("SM_BRIDGE_VPN"),
			t.DeviceName) == IDNO)
		{
			return;
		}
	}

	// Show a warning message if the VPN Server is running in a VM
	if (GetCapsBool(s->CapsList, "b_is_in_vm"))
	{
		Dialog(hWnd, D_SM_VMBRIDGE, SmVmBridgeDlg, NULL);
	}

	// Warning for such as Intel LAN cards
	if (tapmode == false)
	{
		MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_INTEL"));
	}

	if (CALL(hWnd, ScAddLocalBridge(s->Rpc, &t)) == false)
	{
		Focus(hWnd, E_HUBNAME);
		return;
	}

	SetText(hWnd, E_HUBNAME, L"");
	Focus(hWnd, E_HUBNAME);

	if (tapmode)
	{
		SetTextA(hWnd, E_TAPNAME, "");
	}

	SmBridgeDlgRefresh(hWnd, s);

	MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_OK"));
}

// Bridge dialog procedure
UINT SmBridgeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_SERVER *s = (SM_SERVER *)param;
	UINT i;
	UINT num;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		num = SmBridgeDlgInit(hWnd, s);

		if (num == 0)
		{
			SetTimer(hWnd, 2, 500, NULL);
		}
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_HUBNAME:
		case E_NICNAME:
		case R_BRIDGE:
		case R_TAP:
		case E_TAPNAME:
			SmBridgeDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case R_BRIDGE:
			Focus(hWnd, E_NICNAME);
			break;

		case R_TAP:
			FocusEx(hWnd, E_TAPNAME);
			break;

		case IDOK:
			// Add
			SmBridgeDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// Close
			Close(hWnd);
			break;

		case B_VLAN:
			// VLAN utility
			SmVLan(hWnd, s);
			break;

		case B_DELETE:
			// Delete
			i = LvGetSelected(hWnd, L_LIST);
			if (i != INFINITE)
			{
				wchar_t *nic, *hub;
				wchar_t tmp[MAX_SIZE];
				RPC_LOCALBRIDGE t;

				hub = LvGetStr(hWnd, L_LIST, i, 1);
				nic = LvGetStr(hWnd, L_LIST, i, 2);

				UniFormat(tmp, sizeof(tmp), _UU("SM_BRIDGE_DELETE"),
					hub, nic);

				if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, tmp) == IDYES)
				{
					Zero(&t, sizeof(t));
					UniToStr(t.DeviceName, sizeof(t.DeviceName), nic);
					UniToStr(t.HubName, sizeof(t.HubName), hub);

					if (CALL(hWnd, ScDeleteLocalBridge(s->Rpc, &t)))
					{
						MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_DELETE_OK"));
						SmBridgeDlgRefresh(hWnd, s);
					}
				}

				Free(hub);
				Free(nic);
			}
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (IsEnable(hWnd, 0))
			{
				KillTimer(hWnd, 1);
				SmBridgeDlgRefresh(hWnd, s);
				SetTimer(hWnd, 1, 1000, NULL);
			}
			break;

		case 2:
			KillTimer(hWnd, 2);

			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_NO_BRIDGE_NICS"));
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
				SmBridgeDlgUpdate(hWnd, s);
				break;
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

// Installation of WinPcap
void SmInstallWinPcap(HWND hWnd, SM_SERVER *s)
{
	wchar_t temp_name[MAX_SIZE];
	IO *io;
	BUF *buf;

	// Ask whether the user want to start the installation
	if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("SM_BRIDGE_WPCAP_INSTALL")) == IDNO)
	{
		return;
	}

	// Generate a temporary file name
	UniFormat(temp_name, sizeof(temp_name), L"%s\\winpcap_installer.exe", MsGetTempDirW());

	// Read from hamcore
	buf = ReadDump(MsIsNt() ? "|winpcap_installer.exe" : "|winpcap_installer_win9x.exe");
	if (buf == NULL)
	{
RES_ERROR:
		MsgBox(hWnd, MB_ICONSTOP, _UU("SM_BRIDGE_RESOURCE"));
		return;
	}

	// Write to a temporary file
	io = FileCreateW(temp_name);
	if (io == NULL)
	{
		FreeBuf(buf);
		goto RES_ERROR;
	}

	FileWrite(io, buf->Buf, buf->Size);
	FileClose(io);

	FreeBuf(buf);

	// Run
	if (RunW(temp_name, NULL, false, true) == false)
	{
		// Failure
		FileDeleteW(temp_name);
		goto RES_ERROR;
	}

	FileDeleteW(temp_name);

	if (s == NULL)
	{
		return;
	}

	// Message after completed
	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) == false)
	{
		// Need to restart the computer
		MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_WPCAP_REBOOT1"));
	}
	else
	{
		// Need to restart the service
		if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("SM_BRIDGE_WPCAP_REBOOT2")) == IDNO)
		{
			// Not restart
		}
		else
		{
			// Restart
			RPC_TEST t;
			Zero(&t, sizeof(t));
			ScRebootServer(s->Rpc, &t);

			SleepThread(500);

			Zero(&t, sizeof(t));
			CALL(hWnd, ScTest(s->Rpc, &t));
		}
	}
}

// Bridge dialog
void SmBridgeDlg(HWND hWnd, SM_SERVER *s)
{
	RPC_BRIDGE_SUPPORT t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	// Examine the bridge support status of the server side first
	Zero(&t, sizeof(t));
	if (CALLEX(hWnd, ScGetBridgeSupport(s->Rpc, &t)) != ERR_NO_ERROR)
	{
		// Not supported because it is old version
		MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SM_BRIDGE_TOO_OLD_VER"));
		return;
	}

	if (t.IsBridgeSupportedOs == false)
	{
		// OS does not support the bridge
		MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SM_BRIDGE_UNSUPPORTED"));
		return;
	}

	if (t.IsWinPcapNeeded)
	{
		if (s->Rpc->Sock->RemoteIP.addr[0] != 127)
		{
			// WinPcap is required, but can not do anything because it is in remote control mode
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_WPCAP_REMOTE"));
			return;
		}
		else
		{
			// WinPcap is required, and it's in local management mode
			if (MsIsAdmin())
			{
				// The user is an Administrators
				SmInstallWinPcap(hWnd, s);
				return;
			}
			else
			{
				// The user is a non-Administrators
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_BRIDGE_WPCAP_ROOT"));
				return;
			}
		}
	}

	Dialog(hWnd, D_SM_BRIDGE, SmBridgeDlgProc, s);
}

// SecureNAT screen update
void SmSNATDlgUpdate(HWND hWnd, SM_HUB *s)
{
	bool b;
	RPC_HUB_STATUS t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	if (CALL(hWnd, ScGetHubStatus(s->Rpc, &t)) == false)
	{
		Close(hWnd);
		return;
	}

	b = t.SecureNATEnabled;

	if (b)
	{
		Disable(hWnd, B_ENABLE);
		Enable(hWnd, B_DISABLE);
		Enable(hWnd, B_NAT);
		Enable(hWnd, B_DHCP);
		Enable(hWnd, B_STATUS);
	}
	else
	{
		Enable(hWnd, B_ENABLE);
		Disable(hWnd, B_DISABLE);
		Disable(hWnd, B_NAT);
		Disable(hWnd, B_DHCP);
		Disable(hWnd, B_STATUS);
	}
}

// SecureNAT configuration screen
UINT SmSNATDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	RPC_HUB t;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_ROUTER);
		DlgFont(hWnd, S_WARNING, (_GETLANG() == 0 || _GETLANG() == 2) ? 13 : 10, true);
		FormatText(hWnd, S_TITLE, s->HubName);
		SmSNATDlgUpdate(hWnd, s);

		SetTimer(hWnd, 1, 1000, NULL);
		break;

	case WM_TIMER:
		if (wParam == 1)
		{
			if (IsEnable(hWnd, 0))
			{
				KillTimer(hWnd, 1);

				SmSNATDlgUpdate(hWnd, s);

				SetTimer(hWnd, 1, 1000, NULL);
			}
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			Close(hWnd);
			break;

		case B_ENABLE:
			if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_OKCANCEL | MB_DEFBUTTON2,
				_UU("SM_SECURE_NAT_MSG")) == IDOK)
			{
				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
				CALL(hWnd, ScEnableSecureNAT(s->Rpc, &t));
				SmSNATDlgUpdate(hWnd, s);
			}
			break;

		case B_DISABLE:
			Zero(&t, sizeof(t));
			StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
			CALL(hWnd, ScDisableSecureNAT(s->Rpc, &t));
			SmSNATDlgUpdate(hWnd, s);
			break;

		case B_CONFIG:
			NmEditVhOption(hWnd, s);
			break;

		case B_NAT:
			NmNat(hWnd, s);
			break;

		case B_DHCP:
			NmDhcp(hWnd, s);
			break;

		case B_STATUS:
			SmStatusDlg(hWnd, s->p, s, false, true, _UU("SM_SNAT_STATUS"), ICO_ROUTER,
				NULL, NmStatus);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// Initialize
void SmCreateCertDlgInit(HWND hWnd, SM_CERT *s)
{
	UINT cert_sign;
	UINT cert_days;
	char *reg_o, *reg_ou, *reg_c, *reg_st, *reg_l;
	UINT bits[] = {1024, 1536, 2048, 3072, 4096 };
	UINT i;
	UINT last_bit;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetTextA(hWnd, E_CN, s->default_cn);

	last_bit = MsRegReadInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Bits");
	if (last_bit == 0)
	{
		last_bit = 2048;
	}

	CbReset(hWnd, C_BITS);
	for (i = 0;i < sizeof(bits) / sizeof(bits[0]);i++)
	{
		char tmp[MAX_PATH];
		UINT index;

		ToStr(tmp, bits[i]);

		index = CbAddStrA(hWnd, C_BITS, tmp, bits[i]);
	}

	CbSelect(hWnd, C_BITS, 1024);
	CbSelect(hWnd, C_BITS, last_bit);

	reg_o = MsRegReadStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "O");
	reg_ou = MsRegReadStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "OU");
	reg_c = MsRegReadStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "C");
	reg_st = MsRegReadStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "ST");
	reg_l = MsRegReadStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "L");
	SetTextA(hWnd, E_O, reg_o);
	SetTextA(hWnd, E_OU, reg_ou);
	SetTextA(hWnd, E_C, reg_c);
	SetTextA(hWnd, E_ST, reg_st);
	SetTextA(hWnd, E_L, reg_l);
	Free(reg_o);
	Free(reg_ou);
	Free(reg_c);
	Free(reg_st);
	Free(reg_l);

	LimitText(hWnd, E_C, 2);

	cert_sign = MsRegReadInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Sign");
	cert_days = MsRegReadInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Days");

	Check(hWnd, R_ROOT_CERT, cert_sign ? false : true);
	Check(hWnd, R_SIGNED_CERT, cert_sign ? true : false);

	if (cert_days == 0)
	{
		cert_days = 3650;
	}

	SetIntEx(hWnd, E_EXPIRE, cert_days);

	SmCreateCertDlgUpdate(hWnd, s);

	if (s->root_only)
	{
		Disable(hWnd, R_SIGNED_CERT);
	}

	// Font
	SetFont(hWnd, E_CN, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 0, false, false, false, false));
	SetFont(hWnd, E_O, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 0, false, false, false, false));
	SetFont(hWnd, E_OU, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 0, false, false, false, false));
	SetFont(hWnd, E_C, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 0, false, false, false, false));
	SetFont(hWnd, E_ST, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 0, false, false, false, false));
	SetFont(hWnd, E_L, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 0, false, false, false, false));
	SetFont(hWnd, E_SERIAL, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 0, false, false, false, false));
	SetFont(hWnd, E_EXPIRE, GetFont((MsIsWinXPOrGreater() ? "Verdana" : NULL), 0, false, false, false, false));
	SetFont(hWnd, C_BITS, GetFont("Verdana", 0, false, false, false, false));

	FocusEx(hWnd, E_CN);
}

// Update
void SmCreateCertDlgUpdate(HWND hWnd, SM_CERT *s)
{
	bool ok = true;
	bool b;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (IsEmpty(hWnd, E_CN) && IsEmpty(hWnd, E_O) && IsEmpty(hWnd, E_OU) &&
		IsEmpty(hWnd, E_ST) && IsEmpty(hWnd, E_L))
	{
		ok = false;
	}

	i = GetInt(hWnd, E_EXPIRE);
	if (i == 0 || i >= (365 * 30))
	{
		ok = false;
	}

	b = IsChecked(hWnd, R_SIGNED_CERT);

	SetEnable(hWnd, S_LOAD_1, b);
	SetEnable(hWnd, B_LOAD, b);
	SetEnable(hWnd, S_LOAD_2, b);

	if (b && (s->root_k == NULL || s->root_x == NULL))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
}

// [OK] button
void SmCreateCertDlgOnOk(HWND hWnd, SM_CERT *s)
{
	wchar_t cn[MAX_SIZE], o[MAX_SIZE], ou[MAX_SIZE], c[MAX_SIZE], st[MAX_SIZE], l[MAX_SIZE];
	char *reg_o, *reg_ou, *reg_c, *reg_st, *reg_l;
	UINT days;
	bool sign;
	char serial[MAX_SIZE * 2];
	X *x;
	K *pub;
	K *pri;
	NAME *n;
	X_SERIAL *x_serial;
	BUF *buf;
	UINT bits;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	GetTxt(hWnd, E_CN, cn, sizeof(cn));
	GetTxt(hWnd, E_O, o, sizeof(o));
	GetTxt(hWnd, E_OU, ou, sizeof(ou));
	GetTxt(hWnd, E_C, c, sizeof(c));
	GetTxt(hWnd, E_ST, st, sizeof(st));
	GetTxt(hWnd, E_L, l, sizeof(l));
	GetTxtA(hWnd, E_SERIAL, serial, sizeof(serial));

	bits = CbGetSelect(hWnd, C_BITS);
	if (bits == INFINITE)
	{
		bits = 1024;
	}

	buf = StrToBin(serial);
	if (buf == NULL)
	{
		return;
	}

	if (buf->Size > 1)
	{
		x_serial = NewXSerial(buf->Buf, buf->Size);
	}
	else
	{
		x_serial = NULL;
	}

	FreeBuf(buf);

	n = NewName(UniStrLen(cn) ? cn : NULL,
		UniStrLen(o) ? o : NULL,
		UniStrLen(ou) ? ou : NULL,
		UniStrLen(c) ? c : NULL,
		UniStrLen(st) ? st : NULL,
		UniStrLen(l) ? l : NULL);

	days = GetInt(hWnd, E_EXPIRE);

	sign = IsChecked(hWnd, R_SIGNED_CERT);

	MsRegWriteInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Sign", sign);
	MsRegWriteInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Days", days);
	MsRegWriteInt(REG_CURRENT_USER, SM_CERT_REG_KEY, "Bits", bits);

	RsaGen(&pri, &pub, bits);

	if (sign == false)
	{
		x = NewRootX(pub, pri, n, days, x_serial);
	}
	else
	{
		x = NewX(pub, s->root_k, s->root_x, n, days, x_serial);
	}

	FreeName(n);

	FreeXSerial(x_serial);

	if (x == NULL)
	{
		FreeX(x);
		FreeK(pub);
		FreeK(pri);
		return;
	}

	if (s->do_not_save == false)
	{
		if (SmSaveKeyPairDlg(hWnd, x, pri) == false)
		{
			FreeX(x);
			FreeK(pub);
			FreeK(pri);
			return;
		}
	}

	s->x = x;
	s->k = pri;
	FreeK(pub);

	reg_o = GetTextA(hWnd, E_O);
	reg_ou = GetTextA(hWnd, E_OU);
	reg_c = GetTextA(hWnd, E_C);
	reg_st = GetTextA(hWnd, E_ST);
	reg_l = GetTextA(hWnd, E_L);
	MsRegWriteStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "O", reg_o);
	MsRegWriteStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "OU", reg_ou);
	MsRegWriteStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "C", reg_c);
	MsRegWriteStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "ST", reg_st);
	MsRegWriteStr(REG_CURRENT_USER, SM_CERT_REG_KEY, "L", reg_l);
	Free(reg_o);
	Free(reg_ou);
	Free(reg_c);
	Free(reg_st);
	Free(reg_l);

	EndDialog(hWnd, true);
}

// Certificate creation screen
UINT SmCreateCertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_CERT *s = (SM_CERT *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmCreateCertDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_ROOT_CERT:
		case R_SIGNED_CERT:
		case B_LOAD:
		case E_CN:
		case E_O:
		case E_OU:
		case E_C:
		case E_ST:
		case E_L:
		case E_EXPIRE:
			SmCreateCertDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// [OK] button
			SmCreateCertDlgOnOk(hWnd, s);
			break;

		case R_ROOT_CERT:
			if (IsChecked(hWnd, R_ROOT_CERT))
			{
				FocusEx(hWnd, E_CN);
			}
			break;

		case B_LOAD:
			// Read a certificate
			if (1)
			{
				X *x;
				K *k;
				if (CmLoadXAndK(hWnd, &x, &k))
				{
					wchar_t tmp[MAX_SIZE];
					FreeX(s->root_x);
					FreeK(s->root_k);
					s->root_x = x;
					s->root_k = k;

					SmGetCertInfoStr(tmp, sizeof(tmp), x);
					SetText(hWnd, S_LOAD_2, tmp);
					SmCreateCertDlgUpdate(hWnd, s);
				}
			}
			break;

		case IDCANCEL:
			// Cancel button
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

// Certificate tool
bool SmCreateCert(HWND hWnd, X **x, K **k, bool do_not_save, char *default_cn, bool root_only)
{
	bool ret;
	SM_CERT s;
	Zero(&s, sizeof(s));

	if (default_cn == NULL)
	{
		default_cn = "";
	}

	s.default_cn = default_cn;

	s.do_not_save = do_not_save;

	s.root_only = root_only;

	ret = Dialog(hWnd, D_SM_CREATE_CERT, SmCreateCertDlgProc, &s);

	if (ret)
	{
		if (x != NULL)
		{
			*x = CloneX(s.x);
		}

		if (k != NULL)
		{
			*k = CloneK(s.k);
		}
	}

	FreeX(s.x);
	FreeK(s.k);
	FreeX(s.root_x);
	FreeK(s.root_k);

	return ret;
}

// Initialize
void SmIpTableDlgInit(HWND hWnd, SM_TABLE *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_PROTOCOL);
	FormatText(hWnd, S_TITLE, s->Hub->HubName);

	if (s->SessionName != NULL)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		GetTxt(hWnd, S_TITLE, tmp, sizeof(tmp));
		UniFormat(tmp2, sizeof(tmp2), _UU("SM_SESSION_FILTER"), s->SessionName);
		UniStrCat(tmp, sizeof(tmp), tmp2);
		SetText(hWnd, S_TITLE, tmp);
	}

	LvInit(hWnd, L_TABLE);
	LvInsertColumn(hWnd, L_TABLE, 0, _UU("SM_IP_COLUMN_1"), 190);
	LvInsertColumn(hWnd, L_TABLE, 1, _UU("SM_IP_COLUMN_2"), 140);
	LvInsertColumn(hWnd, L_TABLE, 2, _UU("SM_IP_COLUMN_3"), 133);
	LvInsertColumn(hWnd, L_TABLE, 3, _UU("SM_IP_COLUMN_4"), 133);
	LvInsertColumn(hWnd, L_TABLE, 4, _UU("SM_IP_COLUMN_5"), 133);
	LvSetStyle(hWnd, L_TABLE, LVS_EX_GRIDLINES);

	SmIpTableDlgRefresh(hWnd, s);
}

// Update the control
void SmIpTableDlgUpdate(HWND hWnd, SM_TABLE *s)
{
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_TABLE) == false || LvIsMultiMasked(hWnd, L_TABLE))
	{
		ok = false;
	}

	SetEnable(hWnd, B_DELETE, ok);
}

// Content update
void SmIpTableDlgRefresh(HWND hWnd, SM_TABLE *s)
{
	UINT i;
	RPC_ENUM_IP_TABLE t;
	UINT old_selected = 0;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);

	if (CALL(hWnd, ScEnumIpTable(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	i = LvGetSelected(hWnd, L_TABLE);
	if (i != INFINITE)
	{
		old_selected = (UINT)LvGetParam(hWnd, L_TABLE, i);
	}

	LvReset(hWnd, L_TABLE);

	for (i = 0;i < t.NumIpTable;i++)
	{
		char str[MAX_SIZE];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		wchar_t tmp5[MAX_SIZE];
		RPC_ENUM_IP_TABLE_ITEM *e = &t.IpTables[i];

		if (s->SessionName == NULL || StrCmpi(e->SessionName, s->SessionName) == 0)
		{
			StrToUni(tmp1, sizeof(tmp1), e->SessionName);

			if (e->DhcpAllocated == false)
			{
				IPToStr(str, sizeof(str), &e->IpV6);
				StrToUni(tmp2, sizeof(tmp2), str);
			}
			else
			{
				IPToStr(str, sizeof(str), &e->IpV6);
				UniFormat(tmp2, sizeof(tmp2), _UU("SM_MAC_IP_DHCP"), str);
			}

			GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

			GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

			if (StrLen(e->RemoteHostname) == 0)
			{
				UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_MACIP_LOCAL"));
			}
			else
			{
				UniFormat(tmp5, sizeof(tmp5), _UU("SM_MACIP_SERVER"), e->RemoteHostname);
			}

			LvInsert(hWnd, L_TABLE, e->DhcpAllocated ? ICO_PROTOCOL_DHCP : ICO_PROTOCOL, (void *)e->Key, 5,
				tmp1, tmp2, tmp3, tmp4, tmp5);
		}
	}

	FreeRpcEnumIpTable(&t);

	if (old_selected != 0)
	{
		LvSelect(hWnd, L_TABLE, LvSearchParam(hWnd, L_TABLE, (void *)old_selected));
	}

	SmIpTableDlgUpdate(hWnd, s);
}

// IP address table dialog procedure
UINT SmIpTableDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_TABLE *s = (SM_TABLE *)param;
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
		// Initialize
		SmIpTableDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_DELETE:
			// Delete
			i = LvGetSelected(hWnd, L_TABLE);
			if (i != INFINITE)
			{
				RPC_DELETE_TABLE t;
				UINT key = (UINT)LvGetParam(hWnd, L_TABLE, i);

				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
				t.Key = key;
				if (CALL(hWnd, ScDeleteIpTable(s->Rpc, &t)))
				{
					LvDeleteItem(hWnd, L_TABLE, i);
				}
			}
			break;

		case B_REFRESH:
			// Update
			SmIpTableDlgRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_TABLE:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmIpTableDlgUpdate(hWnd, s);
				break;
			}
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

// IP address table dialog
void SmIpTableDlg(HWND hWnd, SM_HUB *s, char *session_name)
{
	SM_TABLE t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.Hub = s;
	t.Rpc = s->Rpc;
	t.SessionName = session_name;

	Dialog(hWnd, D_SM_IP, SmIpTableDlgProc, &t);
}


// Initialize
void SmMacTableDlgInit(HWND hWnd, SM_TABLE *s)
{
	UINT i = 0;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_NIC_ONLINE);
	FormatText(hWnd, S_TITLE, s->Hub->HubName);

	if (s->SessionName != NULL)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		GetTxt(hWnd, S_TITLE, tmp, sizeof(tmp));
		UniFormat(tmp2, sizeof(tmp2), _UU("SM_SESSION_FILTER"), s->SessionName);
		UniStrCat(tmp, sizeof(tmp), tmp2);
		SetText(hWnd, S_TITLE, tmp);
	}

	LvInit(hWnd, L_TABLE);
	LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_1"), 190);
	if (GetCapsBool(s->Hub->p->CapsList, "b_support_vlan"))
	{
		LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_1A"), 65);
	}
	LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_2"), 140);
	LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_3"), 133);
	LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_4"), 133);
	LvInsertColumn(hWnd, L_TABLE, i++, _UU("SM_MAC_COLUMN_5"), 133);
	LvSetStyle(hWnd, L_TABLE, LVS_EX_GRIDLINES);

	SmMacTableDlgRefresh(hWnd, s);
}

// Update the control
void SmMacTableDlgUpdate(HWND hWnd, SM_TABLE *s)
{
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_TABLE) == false || LvIsMultiMasked(hWnd, L_TABLE))
	{
		ok = false;
	}

	SetEnable(hWnd, B_DELETE, ok);
}

// Content update
void SmMacTableDlgRefresh(HWND hWnd, SM_TABLE *s)
{
	UINT i;
	RPC_ENUM_MAC_TABLE t;
	UINT old_selected = 0;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);

	if (CALL(hWnd, ScEnumMacTable(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	i = LvGetSelected(hWnd, L_TABLE);
	if (i != INFINITE)
	{
		old_selected = (UINT)LvGetParam(hWnd, L_TABLE, i);
	}

	LvReset(hWnd, L_TABLE);

	for (i = 0;i < t.NumMacTable;i++)
	{
		char str[MAX_SIZE];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		wchar_t tmp5[MAX_SIZE];
		wchar_t tmp6[MAX_SIZE];
		RPC_ENUM_MAC_TABLE_ITEM *e = &t.MacTables[i];

		if (s->SessionName == NULL || StrCmpi(e->SessionName, s->SessionName) == 0)
		{
			StrToUni(tmp1, sizeof(tmp1), e->SessionName);

			MacToStr(str, sizeof(str), e->MacAddress);
			StrToUni(tmp2, sizeof(tmp2), str);

			GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

			GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

			if (StrLen(e->RemoteHostname) == 0)
			{
				UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_MACIP_LOCAL"));
			}
			else
			{
				UniFormat(tmp5, sizeof(tmp5), _UU("SM_MACIP_SERVER"), e->RemoteHostname);
			}

			UniToStru(tmp6, e->VlanId);
			if (e->VlanId == 0)
			{
				UniStrCpy(tmp6, sizeof(tmp6), _UU("CM_ST_NONE"));
			}

			if (GetCapsBool(s->Hub->p->CapsList, "b_support_vlan"))
			{
				LvInsert(hWnd, L_TABLE, ICO_NIC_ONLINE, (void *)e->Key, 6,
					tmp1, tmp6, tmp2, tmp3, tmp4, tmp5);
			}
			else
			{
				LvInsert(hWnd, L_TABLE, ICO_NIC_ONLINE, (void *)e->Key, 5,
					tmp1, tmp2, tmp3, tmp4, tmp5);
			}
		}
	}

	FreeRpcEnumMacTable(&t);

	if (old_selected != 0)
	{
		LvSelect(hWnd, L_TABLE, LvSearchParam(hWnd, L_TABLE, (void *)old_selected));
	}

	SmMacTableDlgUpdate(hWnd, s);
}

// MAC address table dialog procedure
UINT SmMacTableDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_TABLE *s = (SM_TABLE *)param;
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
		// Initialize
		SmMacTableDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_DELETE:
			// Delete
			i = LvGetSelected(hWnd, L_TABLE);
			if (i != INFINITE)
			{
				RPC_DELETE_TABLE t;
				UINT key = (UINT)LvGetParam(hWnd, L_TABLE, i);

				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
				t.Key = key;
				if (CALL(hWnd, ScDeleteMacTable(s->Rpc, &t)))
				{
					LvDeleteItem(hWnd, L_TABLE, i);
				}
			}
			break;

		case B_REFRESH:
			// Update
			SmMacTableDlgRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_TABLE:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmMacTableDlgUpdate(hWnd, s);
				break;
			}
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

// MAC address table dialog
void SmMacTableDlg(HWND hWnd, SM_HUB *s, char *session_name)
{
	SM_TABLE t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.Hub = s;
	t.Rpc = s->Rpc;
	t.SessionName = session_name;

	Dialog(hWnd, D_SM_MAC, SmMacTableDlgProc, &t);
}

// Initialize
void SmSessionDlgInit(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_VPN);
	FormatText(hWnd, 0, s->HubName);
	FormatText(hWnd, S_TITLE, s->HubName);

	LvInit(hWnd, L_LIST);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_SESS_COLUMN_1"), 176);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_SESS_COLUMN_8"), 58);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_SESS_COLUMN_2"), 62);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_SESS_COLUMN_3"), 78);
	LvInsertColumn(hWnd, L_LIST, 4, _UU("SM_SESS_COLUMN_4"), 122);
	LvInsertColumn(hWnd, L_LIST, 5, _UU("SM_SESS_COLUMN_5"), 68);
	LvInsertColumn(hWnd, L_LIST, 6, _UU("SM_SESS_COLUMN_6"), 100);
	LvInsertColumn(hWnd, L_LIST, 7, _UU("SM_SESS_COLUMN_7"), 100);
	LvSetStyle(hWnd, L_LIST, LVS_EX_GRIDLINES);

	if (s->p->ServerType == SERVER_TYPE_FARM_CONTROLLER && GetCapsBool(s->p->CapsList, "b_support_cluster_admin") == false)
	{
		Show(hWnd, S_FARM_INFO_1);
		Show(hWnd, S_FARM_INFO_2);
	}

	SmSessionDlgRefresh(hWnd, s);
}

// Update the control
void SmSessionDlgUpdate(HWND hWnd, SM_HUB *s)
{
	bool ok = true;
	bool ok2 = true;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_LIST) == false || LvIsMultiMasked(hWnd, L_LIST))
	{
		ok = false;
		ok2 = false;
	}
	else
	{
		UINT i = LvGetSelected(hWnd, L_LIST);
		if (i != INFINITE)
		{
			void *p = LvGetParam(hWnd, L_LIST, i);
			if (((bool)p) != false)
			{
				if (GetCapsBool(s->p->CapsList, "b_support_cluster_admin") == false)
				{
					ok = false;
				}
			}
		}
	}

	if (s->p->ServerInfo.ServerBuildInt < 2844)
	{
		// Old version doesn't support for remote management of the sessions
		ok2 = ok;
	}

	SetEnable(hWnd, IDOK, ok2);
	SetEnable(hWnd, B_DISCONNECT, ok2);
	SetEnable(hWnd, B_SESSION_IP_TABLE, ok);
	SetEnable(hWnd, B_SESSION_MAC_TABLE, ok);
}

// Update the list
void SmSessionDlgRefresh(HWND hWnd, SM_HUB *s)
{
	LVB *b;
	UINT i;
	wchar_t *old_select;
	RPC_ENUM_SESSION t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (CALL(hWnd, ScEnumSession(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	old_select = LvGetSelectedStr(hWnd, L_LIST, 0);

	LvReset(hWnd, L_LIST);

	b = LvInsertStart();

	for (i = 0;i < t.NumSession;i++)
	{
		RPC_ENUM_SESSION_ITEM *e = &t.Sessions[i];
		wchar_t tmp1[MAX_SIZE];
		wchar_t *tmp2;
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		wchar_t tmp5[MAX_SIZE];
		wchar_t tmp6[MAX_SIZE];
		wchar_t tmp7[MAX_SIZE];
		wchar_t tmp8[MAX_SIZE];
		bool free_tmp2 = false;
		UINT icon;

		StrToUni(tmp1, sizeof(tmp1), e->Name);

		tmp2 = _UU("SM_SESS_NORMAL");
		icon = ICO_VPN;
		if (s->p->ServerType != SERVER_TYPE_STANDALONE)
		{
			if (e->RemoteSession)
			{
				tmp2 = ZeroMalloc(MAX_SIZE);
				UniFormat(tmp2, MAX_SIZE, _UU("SM_SESS_REMOTE"), e->RemoteHostname);
				icon = ICO_VPN;
				free_tmp2 = true;
			}
			else
			{
				if (StrLen(e->RemoteHostname) == 0)
				{
					tmp2 = _UU("SM_SESS_LOCAL");
				}
				else
				{
					tmp2 = ZeroMalloc(MAX_SIZE);
					UniFormat(tmp2, MAX_SIZE, _UU("SM_SESS_LOCAL_2"), e->RemoteHostname);
					free_tmp2 = true;
				}
			}
		}
		if (e->LinkMode)
		{
			if (free_tmp2)
			{
				Free(tmp2);
				free_tmp2 = false;
			}
			tmp2 = _UU("SM_SESS_LINK");
			icon = ICO_CASCADE;
		}
		else if (e->SecureNATMode)
		{
			/*if (free_tmp2)
			{
				Free(tmp2);
				free_tmp2 = false;
			}
			tmp2 = _UU("SM_SESS_SNAT");*/
			icon = ICO_ROUTER;
		}
		else if (e->BridgeMode)
		{
			icon = ICO_BRIDGE;
		}
		else if (e->Layer3Mode)
		{
			icon = ICO_SWITCH;
		}

		StrToUni(tmp3, sizeof(tmp3), e->Username);

		StrToUni(tmp4, sizeof(tmp4), e->Hostname);
		if (e->LinkMode)
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_LINK_HOSTNAME"));
		}
		else if (e->SecureNATMode)
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_SNAT_HOSTNAME"));
		}
		else if (e->BridgeMode)
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_BRIDGE_HOSTNAME"));
		}
		else if (StartWith(e->Username, L3_USERNAME))
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_LAYER3_HOSTNAME"));
		}

		UniFormat(tmp5, sizeof(tmp5), L"%u / %u", e->CurrentNumTcp, e->MaxNumTcp);
		if (e->LinkMode)
		{
			UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_SESS_LINK_TCP"));
		}
		else if (e->SecureNATMode)
		{
			UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_SESS_SNAT_TCP"));
		}
		else if (e->BridgeMode)
		{
			UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_SESS_BRIDGE_TCP"));
		}

		if (e->VLanId == 0)
		{
			UniStrCpy(tmp8, sizeof(tmp8), _UU("CM_ST_NO_VLAN"));
		}
		else
		{
			UniToStru(tmp8, e->VLanId);
		}

		UniToStr3(tmp6, sizeof(tmp6), e->PacketSize);
		UniToStr3(tmp7, sizeof(tmp7), e->PacketNum);

		if (icon == ICO_VPN)
		{
			if (e->Client_BridgeMode)
			{
				icon = ICO_SESSION_BRIDGE;
			}
			else if (e->Client_MonitorMode)
			{
				icon = ICO_SESSION_MONITOR;
			}
		}

		if (e->IsDormantEnabled && e->IsDormant)
		{
			icon = ICO_TRAY0;
		}

		LvInsertAdd(b, icon, (void *)(e->RemoteSession), 8, tmp1, tmp8, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7);

		if (free_tmp2)
		{
			Free(tmp2);
		}
	}

	LvInsertEnd(b, hWnd, L_LIST);

	if (old_select != NULL && UniStrLen(old_select) != 0)
	{
		UINT i = LvSearchStr(hWnd, L_LIST, 0, old_select);
		if (i != INFINITE)
		{
			LvSelect(hWnd, L_LIST, i);
		}
	}

	Free(old_select);

	FreeRpcEnumSession(&t);

	SmSessionDlgUpdate(hWnd, s);
}

// Display the NODE_INFO
void SmPrintNodeInfo(LVB *b, NODE_INFO *info)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// Validate arguments
	if (b == NULL || info == NULL)
	{
		return;
	}

	StrToUni(tmp, sizeof(tmp), info->ClientProductName);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_NAME"), tmp);

	UniFormat(tmp, sizeof(tmp), L"%u.%02u", Endian32(info->ClientProductVer) / 100, Endian32(info->ClientProductVer) % 100);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_VER"), tmp);

	UniFormat(tmp, sizeof(tmp), L"Build %u", Endian32(info->ClientProductBuild));
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_BUILD"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsName);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_OS_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsVer);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_OS_VER"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsProductId);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_OS_PID"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientHostname);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_HOST"), tmp);

	IPToStr4or6(str, sizeof(str), info->ClientIpAddress, info->ClientIpAddress6);
	StrToUni(tmp, sizeof(tmp), str);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_IP"), tmp);

	UniToStru(tmp, Endian32(info->ClientPort));
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_CLIENT_PORT"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ServerHostname);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_SERVER_HOST"), tmp);

	IPToStr4or6(str, sizeof(str), info->ServerIpAddress, info->ServerIpAddress6);
	StrToUni(tmp, sizeof(tmp), str);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_SERVER_IP"), tmp);

	UniToStru(tmp, Endian32(info->ServerPort));
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_SERVER_PORT"), tmp);

	if (StrLen(info->ProxyHostname) != 0)
	{
		StrToUni(tmp, sizeof(tmp), info->ProxyHostname);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_PROXY_HOSTNAME"), tmp);

		IPToStr4or6(str, sizeof(str), info->ProxyIpAddress, info->ProxyIpAddress6);
		StrToUni(tmp, sizeof(tmp), str);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_PROXY_IP"), tmp);

		UniToStru(tmp, Endian32(info->ProxyPort));
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_NODE_PROXY_PORT"), tmp);
	}
}

// Update the session status
bool SmRefreshSessionStatus(HWND hWnd, SM_SERVER *s, void *param)
{
	LVB *b;
	SM_SESSION_STATUS *status = (SM_SESSION_STATUS *)param;
	RPC_SESSION_STATUS t;
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || s == NULL || param == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), status->Hub->HubName);
	StrCpy(t.Name, sizeof(t.Name), status->SessionName);

	if (CALL(hWnd, ScGetSessionStatus(s->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	if (t.ClientIp != 0)
	{
		IPToStr4or6(str, sizeof(str), t.ClientIp, t.ClientIp6);
		StrToUni(tmp, sizeof(tmp), str);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_CLIENT_IP"), tmp);
	}

	if (StrLen(t.ClientHostName) != 0)
	{
		StrToUni(tmp, sizeof(tmp), t.ClientHostName);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_CLIENT_HOSTNAME"), tmp);
	}

	StrToUni(tmp, sizeof(tmp), t.Username);
	LvInsertAdd(b, 0, NULL, 2, _UU("SM_SESS_STATUS_USERNAME"), tmp);

	if (StrCmpi(t.Username, LINK_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, SNAT_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, BRIDGE_USER_NAME_PRINT) != 0)
	{
		StrToUni(tmp, sizeof(tmp), t.RealUsername);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_SESS_STATUS_REALUSER"), tmp);
	}

	if (IsEmptyStr(t.GroupName) == false)
	{
		StrToUni(tmp, sizeof(tmp), t.GroupName);
		LvInsertAdd(b, 0, NULL, 2, _UU("SM_SESS_STATUS_GROUPNAME"), tmp);
	}

	CmPrintStatusToListViewEx(b, &t.Status, true);

	if (StrCmpi(t.Username, LINK_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, SNAT_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, BRIDGE_USER_NAME_PRINT) != 0 &&
		StartWith(t.Username, L3_USERNAME) == false)
	{
		SmPrintNodeInfo(b, &t.NodeInfo);
	}

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcSessionStatus(&t);

	return true;
}

// Session Management dialog procedure
UINT SmSessionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	wchar_t *tmp;
	wchar_t tmp2[MAX_SIZE];
	char name[MAX_SIZE];
	NMHDR *n;
	SM_SESSION_STATUS status;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	tmp = LvGetSelectedStr(hWnd, L_LIST, 0);
	UniToStr(name, sizeof(name), tmp);

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmSessionDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (IsEnable(hWnd, IDOK))
			{
				// Session status display
				UniFormat(tmp2, sizeof(tmp2), _UU("SM_SESS_STATUS_CAPTION"), name);
				Zero(&status, sizeof(status));
				status.Hub = s;
				status.SessionName = name;
				SmStatusDlg(hWnd, s->p, &status, true, true, tmp2, ICO_VPN,
					NULL, SmRefreshSessionStatus);
			}
			break;

		case B_DISCONNECT:
			// Disconnect
			if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
				_UU("SM_SESS_DISCONNECT_MSG"), name) == IDYES)
			{
				RPC_DELETE_SESSION t;
				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
				StrCpy(t.Name, sizeof(t.Name), name);

				if (CALL(hWnd, ScDeleteSession(s->Rpc, &t)))
				{
					SmSessionDlgRefresh(hWnd, s);
				}
			}
			break;

		case B_REFRESH:
			// Update
			SmSessionDlgRefresh(hWnd, s);
			break;

		case B_SESSION_IP_TABLE:
			// IP table
			SmIpTableDlg(hWnd, s, name);
			break;

		case B_SESSION_MAC_TABLE:
			// MAC table
			SmMacTableDlg(hWnd, s, name);
			break;

		case B_MAC_TABLE:
			// MAC Table List
			SmMacTableDlg(hWnd, s, NULL);
			break;

		case B_IP_TABLE:
			// IP Table List
			SmIpTableDlg(hWnd, s, NULL);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_LIST:
				SmSessionDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	Free(tmp);

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}

// Session Management dialog
void SmSessionDlg(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_SESSION, SmSessionDlgProc, s);
}

// Certificate List Update
void SmCaDlgRefresh(HWND hWnd, SM_HUB *s)
{
	LVB *b;
	UINT i;
	RPC_HUB_ENUM_CA t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	if (CALL(hWnd, ScEnumCa(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumCa;i++)
	{
		wchar_t tmp[MAX_SIZE];
		RPC_HUB_ENUM_CA_ITEM *e = &t.Ca[i];

		GetDateStrEx64(tmp, sizeof(tmp), SystemToLocal64(e->Expires), NULL);

		LvInsertAdd(b, ICO_SERVER_CERT, (void *)e->Key, 3,
			e->SubjectName, e->IssuerName, tmp);
	}

	LvInsertEnd(b, hWnd, L_CERT);

	FreeRpcHubEnumCa(&t);

	SmCaDlgUpdate(hWnd, s);
}

// Initialize
void SmCaDlgInit(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_SERVER_CERT);

	LvInit(hWnd, L_CERT);
	LvInsertColumn(hWnd, L_CERT, 0, _UU("CM_CERT_COLUMN_1"), 190);
	LvInsertColumn(hWnd, L_CERT, 1, _UU("CM_CERT_COLUMN_2"), 190);
	LvInsertColumn(hWnd, L_CERT, 2, _UU("CM_CERT_COLUMN_3"), 160);

	SmCaDlgRefresh(hWnd, s);
}

// Update the control
void SmCaDlgUpdate(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetEnable(hWnd, B_DELETE, LvIsSelected(hWnd, L_CERT));
	SetEnable(hWnd, IDOK, LvIsSelected(hWnd, L_CERT));
}

// OK
void SmCaDlgOnOk(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}
}

// CA Adding dialog
bool SmCaDlgAdd(HWND hWnd, SM_HUB *s)
{
	X *x;
	RPC_HUB_ADD_CA t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	if (CmLoadXFromFileOrSecureCard(hWnd, &x) == false)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	t.Cert = x;

	if (CALL(hWnd, ScAddCa(s->Rpc, &t)) == false)
	{
		return false;
	}

	FreeRpcHubAddCa(&t);

	return true;
}

// CA List dialog procedure
UINT SmCaDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	SM_HUB *s = (SM_HUB *)param;
	UINT i, key;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmCaDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_IMPORT:
			// Add
			if (SmCaDlgAdd(hWnd, s))
			{
				SmCaDlgRefresh(hWnd, s);
			}
			break;

		case B_DELETE:
			// Delete
			i = LvGetSelected(hWnd, L_CERT);
			if (i != INFINITE)
			{
				key = (UINT)LvGetParam(hWnd, L_CERT, i);
				if (key != 0)
				{
					if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
						_UU("CM_CERT_DELETE_MSG")) == IDYES)
					{
						RPC_HUB_DELETE_CA t;
						Zero(&t, sizeof(t));
						StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
						t.Key = key;

						if (CALL(hWnd, ScDeleteCa(s->Rpc, &t)))
						{
							SmCaDlgRefresh(hWnd, s);
						}
					}
				}
			}
			break;

		case IDOK:
			// Display
			i = LvGetSelected(hWnd, L_CERT);
			if (i != INFINITE)
			{
				key = (UINT)LvGetParam(hWnd, L_CERT, i);
				if (key != 0)
				{
					RPC_HUB_GET_CA t;
					Zero(&t, sizeof(t));
					StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
					t.Key = key;

					if (CALL(hWnd, ScGetCa(s->Rpc, &t)))
					{
						CertDlg(hWnd, t.Cert, NULL, true);
						FreeRpcHubGetCa(&t);
					}
				}
			}
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_CERT:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmCaDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_CERT);

	return 0;
}

// CA List dialog box
void SmCaDlg(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_CA, SmCaDlgProc, s);
}

// Initialize
void SmLogDlgInit(HWND hWnd, SM_HUB *s)
{
	RPC_HUB_LOG t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_LOG2);

	FormatText(hWnd, S_TITLE, s->HubName);

	CbSetHeight(hWnd, C_SEC_SWITCH, 18);
	CbSetHeight(hWnd, C_PACKET_SWITCH, 18);

	// Initialize the control
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_0"), 0);
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_1"), 1);
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_2"), 2);
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_3"), 3);
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_4"), 4);
	CbAddStr(hWnd, C_SEC_SWITCH, _UU("SM_LOG_SWITCH_5"), 5);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_0"), 0);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_1"), 1);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_2"), 2);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_3"), 3);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_4"), 4);
	CbAddStr(hWnd, C_PACKET_SWITCH, _UU("SM_LOG_SWITCH_5"), 5);

	// Get the log settings
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	if (CALL(hWnd, ScGetHubLog(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	Check(hWnd, B_SEC, t.LogSetting.SaveSecurityLog);
	CbSelect(hWnd, C_SEC_SWITCH, t.LogSetting.SecurityLogSwitchType);

	Check(hWnd, B_PACKET, t.LogSetting.SavePacketLog);
	CbSelect(hWnd, C_PACKET_SWITCH, t.LogSetting.PacketLogSwitchType);

	Check(hWnd, B_PACKET_0_0, t.LogSetting.PacketLogConfig[0] == 0);
	Check(hWnd, B_PACKET_0_1, t.LogSetting.PacketLogConfig[0] == 1);
	Check(hWnd, B_PACKET_0_2, t.LogSetting.PacketLogConfig[0] == 2);

	Check(hWnd, B_PACKET_1_0, t.LogSetting.PacketLogConfig[1] == 0);
	Check(hWnd, B_PACKET_1_1, t.LogSetting.PacketLogConfig[1] == 1);
	Check(hWnd, B_PACKET_1_2, t.LogSetting.PacketLogConfig[1] == 2);

	Check(hWnd, B_PACKET_2_0, t.LogSetting.PacketLogConfig[2] == 0);
	Check(hWnd, B_PACKET_2_1, t.LogSetting.PacketLogConfig[2] == 1);
	Check(hWnd, B_PACKET_2_2, t.LogSetting.PacketLogConfig[2] == 2);

	Check(hWnd, B_PACKET_3_0, t.LogSetting.PacketLogConfig[3] == 0);
	Check(hWnd, B_PACKET_3_1, t.LogSetting.PacketLogConfig[3] == 1);
	Check(hWnd, B_PACKET_3_2, t.LogSetting.PacketLogConfig[3] == 2);

	Check(hWnd, B_PACKET_4_0, t.LogSetting.PacketLogConfig[4] == 0);
	Check(hWnd, B_PACKET_4_1, t.LogSetting.PacketLogConfig[4] == 1);
	Check(hWnd, B_PACKET_4_2, t.LogSetting.PacketLogConfig[4] == 2);

	Check(hWnd, B_PACKET_5_0, t.LogSetting.PacketLogConfig[5] == 0);
	Check(hWnd, B_PACKET_5_1, t.LogSetting.PacketLogConfig[5] == 1);
	Check(hWnd, B_PACKET_5_2, t.LogSetting.PacketLogConfig[5] == 2);

	Check(hWnd, B_PACKET_6_0, t.LogSetting.PacketLogConfig[6] == 0);
	Check(hWnd, B_PACKET_6_1, t.LogSetting.PacketLogConfig[6] == 1);
	Check(hWnd, B_PACKET_6_2, t.LogSetting.PacketLogConfig[6] == 2);

	Check(hWnd, B_PACKET_7_0, t.LogSetting.PacketLogConfig[7] == 0);
	Check(hWnd, B_PACKET_7_1, t.LogSetting.PacketLogConfig[7] == 1);
	Check(hWnd, B_PACKET_7_2, t.LogSetting.PacketLogConfig[7] == 2);

	SmLogDlgUpdate(hWnd, s);
}

// Update the control
void SmLogDlgUpdate(HWND hWnd, SM_HUB *s)
{
	bool b;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	b = IsChecked(hWnd, B_SEC);
	SetEnable(hWnd, S_SEC, b);
	SetEnable(hWnd, C_SEC_SWITCH, b);

	b = IsChecked(hWnd, B_PACKET);
	SetEnable(hWnd, S_PACKET, b);
	SetEnable(hWnd, C_PACKET_SWITCH, b);
	SetEnable(hWnd, S_PACKET_0, b);
	SetEnable(hWnd, S_PACKET_1, b);
	SetEnable(hWnd, S_PACKET_2, b);
	SetEnable(hWnd, S_PACKET_3, b);
	SetEnable(hWnd, S_PACKET_4, b);
	SetEnable(hWnd, S_PACKET_5, b);
	SetEnable(hWnd, S_PACKET_6, b);
	SetEnable(hWnd, S_PACKET_7, b);
	SetEnable(hWnd, B_PACKET_0_0, b); SetEnable(hWnd, B_PACKET_0_1, b); SetEnable(hWnd, B_PACKET_0_2, b);
	SetEnable(hWnd, B_PACKET_1_0, b); SetEnable(hWnd, B_PACKET_1_1, b); SetEnable(hWnd, B_PACKET_1_2, b);
	SetEnable(hWnd, B_PACKET_2_0, b); SetEnable(hWnd, B_PACKET_2_1, b); SetEnable(hWnd, B_PACKET_2_2, b);
	SetEnable(hWnd, B_PACKET_3_0, b); SetEnable(hWnd, B_PACKET_3_1, b); SetEnable(hWnd, B_PACKET_3_2, b);
	SetEnable(hWnd, B_PACKET_4_0, b); SetEnable(hWnd, B_PACKET_4_1, b); SetEnable(hWnd, B_PACKET_4_2, b);
	SetEnable(hWnd, B_PACKET_5_0, b); SetEnable(hWnd, B_PACKET_5_1, b); SetEnable(hWnd, B_PACKET_5_2, b);
	SetEnable(hWnd, B_PACKET_6_0, b); SetEnable(hWnd, B_PACKET_6_1, b); SetEnable(hWnd, B_PACKET_6_2, b);
	SetEnable(hWnd, B_PACKET_7_0, b); SetEnable(hWnd, B_PACKET_7_1, b); SetEnable(hWnd, B_PACKET_7_2, b);
}

// OK
void SmLogDlgOnOk(HWND hWnd, SM_HUB *s)
{
	HUB_LOG g;
	RPC_HUB_LOG t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&g, sizeof(g));
	g.SaveSecurityLog = IsChecked(hWnd, B_SEC);
	g.SavePacketLog = IsChecked(hWnd, B_PACKET);
	g.SecurityLogSwitchType = CbGetSelect(hWnd, C_SEC_SWITCH);
	g.PacketLogSwitchType = CbGetSelect(hWnd, C_PACKET_SWITCH);

	g.PacketLogConfig[0] = IsChecked(hWnd, B_PACKET_0_0) ? 0 : IsChecked(hWnd, B_PACKET_0_1) ? 1 : 2;
	g.PacketLogConfig[1] = IsChecked(hWnd, B_PACKET_1_0) ? 0 : IsChecked(hWnd, B_PACKET_1_1) ? 1 : 2;
	g.PacketLogConfig[2] = IsChecked(hWnd, B_PACKET_2_0) ? 0 : IsChecked(hWnd, B_PACKET_2_1) ? 1 : 2;
	g.PacketLogConfig[3] = IsChecked(hWnd, B_PACKET_3_0) ? 0 : IsChecked(hWnd, B_PACKET_3_1) ? 1 : 2;
	g.PacketLogConfig[4] = IsChecked(hWnd, B_PACKET_4_0) ? 0 : IsChecked(hWnd, B_PACKET_4_1) ? 1 : 2;
	g.PacketLogConfig[5] = IsChecked(hWnd, B_PACKET_5_0) ? 0 : IsChecked(hWnd, B_PACKET_5_1) ? 1 : 2;
	g.PacketLogConfig[6] = IsChecked(hWnd, B_PACKET_6_0) ? 0 : IsChecked(hWnd, B_PACKET_6_1) ? 1 : 2;
	g.PacketLogConfig[7] = IsChecked(hWnd, B_PACKET_7_0) ? 0 : IsChecked(hWnd, B_PACKET_7_1) ? 1 : 2;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	Copy(&t.LogSetting, &g, sizeof(HUB_LOG));

	if (CALL(hWnd, ScSetHubLog(s->Rpc, &t)) == false)
	{
		return;
	}

	EndDialog(hWnd, true);
}

// Log storage settings dialog
UINT SmLogDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmLogDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case B_SEC:
		case B_PACKET:
			SmLogDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// [OK] button
			SmLogDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
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

// Show the status of the cascade connection
bool SmRefreshLinkStatus(HWND hWnd, SM_SERVER *s, void *param)
{
	SM_LINK *k = (SM_LINK *)param;
	RPC_LINK_STATUS t;
	LVB *b;
	// Validate arguments
	if (hWnd == NULL || s == NULL || param == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), k->Hub->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), k->AccountName);

	if (CALL(hWnd, ScGetLinkStatus(s->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	CmPrintStatusToListView(b, &t.Status);

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcLinkStatus(&t);

	return true;
}

// Edit the link
bool SmLinkEdit(HWND hWnd, SM_HUB *s, wchar_t *name)
{
	CM_ACCOUNT a;
	RPC_CREATE_LINK t;
	bool ret = false;
	// Validate arguments
	if (hWnd == NULL || s == NULL || name == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));
	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), name);

	if (CALL(hWnd, ScGetLink(s->Rpc, &t)) == false)
	{
		return false;
	}

	a.Hub = s;
	a.EditMode = true;
	a.LinkMode = true;
	a.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	a.OnlineFlag = t.Online;
	Copy(a.ClientOption, t.ClientOption, sizeof(CLIENT_OPTION));
	a.ClientAuth = CopyClientAuth(t.ClientAuth);
	Copy(&a.Policy, &t.Policy, sizeof(POLICY));
	a.CheckServerCert = t.CheckServerCert;
	a.ServerCert = CloneX(t.ServerCert);
	a.HideTrustCert = GetCapsBool(s->p->CapsList, "b_support_config_hub");
	FreeRpcCreateLink(&t);

	a.PolicyVer = s->p->PolicyVer;

	if (GetCapsBool(s->p->CapsList, "b_support_cascade_client_cert") == false)
	{
		a.HideClientCertAuth = true;
	}

	a.HideSecureAuth = true;

	ret = CmEditAccountDlg(hWnd, &a);

	FreeX(a.ServerCert);
	Free(a.ClientOption);
	CiFreeClientAuth(a.ClientAuth);

	return ret;
}

// Create a new link
bool SmLinkCreate(HWND hWnd, SM_HUB *s)
{
	return SmLinkCreateEx(hWnd, s, false);
}
bool SmLinkCreateEx(HWND hWnd, SM_HUB *s, bool connectNow)
{
	CM_ACCOUNT a;
	bool ret = false;;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));

	a.Hub = s;
	a.EditMode = false;
	a.LinkMode = true;
	a.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	a.OnlineFlag = false;
	a.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
	a.ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
	Copy(&a.Policy, GetDefaultPolicy(), sizeof(POLICY));
	a.ClientOption->Port = 443;	// Default port number
	a.ClientOption->NumRetry = INFINITE;
	a.ClientOption->RetryInterval = 15;
	a.ClientOption->MaxConnection = 8;
	a.ClientOption->UseEncrypt = true;
	a.ClientOption->HalfConnection = false;
	a.ClientOption->AdditionalConnectionInterval = 1;
	a.ClientOption->RequireBridgeRoutingMode = true;
	a.Link_ConnectNow = connectNow;

	a.PolicyVer = s->p->PolicyVer;

	if (GetCapsBool(s->p->CapsList, "b_support_cascade_client_cert") == false)
	{
		a.HideClientCertAuth = true;
	}

	a.HideSecureAuth = true;

	ret = CmEditAccountDlg(hWnd, &a);

	FreeX(a.ServerCert);
	Free(a.ClientOption);
	CiFreeClientAuth(a.ClientAuth);

	return ret;
}

// Initialize
void SmLinkDlgInit(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_LINK);

	FormatText(hWnd, 0, s->HubName);

	LvInit(hWnd, L_LINK);

	LvInsertColumn(hWnd, L_LINK, 0, _UU("SM_LINK_COLUMN_1"), 120);
	LvInsertColumn(hWnd, L_LINK, 1, _UU("SM_LINK_COLUMN_2"), 150);
	LvInsertColumn(hWnd, L_LINK, 2, _UU("SM_LINK_COLUMN_3"), 180);
	LvInsertColumn(hWnd, L_LINK, 3, _UU("SM_LINK_COLUMN_4"), 130);
	LvInsertColumn(hWnd, L_LINK, 4, _UU("SM_LINK_COLUMN_5"), 130);

	LvSetStyle(hWnd, L_LINK, LVS_EX_GRIDLINES);

	SmLinkDlgRefresh(hWnd, s);
}

// Update the controls
void SmLinkDlgUpdate(HWND hWnd, SM_HUB *s)
{
	bool ok = true;
	bool online = false;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_LINK) == false || LvIsMultiMasked(hWnd, L_LINK))
	{
		ok = false;
	}
	else
	{
		online = (bool)LvGetParam(hWnd, L_LINK, LvGetSelected(hWnd, L_LINK));
	}

	SetEnable(hWnd, B_EDIT, ok);
	SetEnable(hWnd, B_ONLINE, ok && (online == false));
	SetEnable(hWnd, B_OFFLINE, ok && online);
	SetEnable(hWnd, IDOK, ok && online);
	SetEnable(hWnd, B_DELETE, ok);
	SetEnable(hWnd, B_RENAME, ok);
}

// Content update
void SmLinkDlgRefresh(HWND hWnd, SM_HUB *s)
{
	LVB *b;
	RPC_ENUM_LINK t;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	if (CALL(hWnd, ScEnumLink(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumLink;i++)
	{
		RPC_ENUM_LINK_ITEM *e = &t.Links[i];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		UINT icon = ICO_CASCADE;

		GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(e->ConnectedTime), NULL);
		StrToUni(tmp2, sizeof(tmp2), e->Hostname);
		StrToUni(tmp3, sizeof(tmp3), e->HubName);

		if (e->Online == false)
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_OFFLINE"));
		}
		else
		{
			if (e->Connected)
			{
				UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_ONLINE"));
			}
			else
			{
				if (e->LastError != 0)
				{
					UniFormat(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_ERROR"), e->LastError, _E(e->LastError));
				}
				else
				{
					UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_CONNECTING"));
				}
			}
		}

		if (e->Online == false)
		{
			icon = ICO_CASCADE_OFFLINE;
		}
		else
		{
			if (e->Connected == false && e->LastError != 0)
			{
				icon = ICO_CASCADE_ERROR;
			}
			else
			{
				icon = ICO_CASCADE;
			}
		}

		LvInsertAdd(b,
			icon, (void *)e->Online, 5,
			e->AccountName, tmp4, tmp1, tmp2, tmp3);
	}

	LvInsertEnd(b, hWnd, L_LINK);

	FreeRpcEnumLink(&t);

	SmLinkDlgUpdate(hWnd, s);
}


// Link List dialog procedure
UINT SmLinkDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	wchar_t *str;
	NMHDR *n;
	NMLVDISPINFOW *disp_info;
	NMLVKEYDOWN *key;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	str = LvGetSelectedStr(hWnd, L_LINK, 0);

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmLinkDlgInit(hWnd, s);

		if (link_create_now)
		{
			if (SmLinkCreateEx(hWnd, s, true))
			{
				SmLinkDlgRefresh(hWnd, s);
			}
		}

		SetTimer(hWnd, 1, 1000, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (IsEnable(hWnd, 0))
			{
				KillTimer(hWnd, 1);
				SmLinkDlgRefresh(hWnd, s);
				SetTimer(hWnd, 1, 1000, NULL);
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_CREATE:
			// Create new
			if (SmLinkCreate(hWnd, s))
			{
				SmLinkDlgRefresh(hWnd, s);
			}
			break;

		case B_EDIT:
			// Edit
			if (str != NULL)
			{
				if (SmLinkEdit(hWnd, s, str))
				{
					SmLinkDlgRefresh(hWnd, s);
				}
			}
			break;

		case B_ONLINE:
			// Online
			if (str != NULL)
			{
				RPC_LINK t;
				Zero(&t, sizeof(t));
				UniStrCpy(t.AccountName, sizeof(t.AccountName), str);
				StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

				if (CALL(hWnd, ScSetLinkOnline(s->Rpc, &t)))
				{
					SmLinkDlgRefresh(hWnd, s);
				}
			}
			break;

		case B_OFFLINE:
			// Offline
			if (str != NULL)
			{
				RPC_LINK t;
				Zero(&t, sizeof(t));
				UniStrCpy(t.AccountName, sizeof(t.AccountName), str);
				StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

				if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2,
					_UU("SM_LINK_OFFLINE_MSG"), t.AccountName) == IDYES)
				{
					if (CALL(hWnd, ScSetLinkOffline(s->Rpc, &t)))
					{
						SmLinkDlgRefresh(hWnd, s);
					}
				}
			}
			break;

		case IDOK:
			// Status
			if (str != NULL)
			{
				wchar_t tmp[MAX_SIZE];
				SM_LINK t;
				Zero(&t, sizeof(t));
				t.Hub = s;
				t.AccountName = str;
				UniFormat(tmp, sizeof(tmp), _UU("SM_LINK_STATUS_CAPTION"), str);
				SmStatusDlg(hWnd, s->p, &t, true, true, tmp,
					ICO_CASCADE, NULL, SmRefreshLinkStatus);
			}
			break;

		case B_DELETE:
			// Delete
			if (str != NULL)
			{
				RPC_LINK t;
				Zero(&t, sizeof(t));
				UniStrCpy(t.AccountName, sizeof(t.AccountName), str);
				StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

				if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2,
					_UU("SM_LINK_DELETE_MSG"), t.AccountName) == IDYES)
				{
					if (CALL(hWnd, ScDeleteLink(s->Rpc, &t)))
					{
						SmLinkDlgRefresh(hWnd, s);
					}
				}
			}
			break;

		case B_REFRESH:
			// Update
			SmLinkDlgRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;

		case B_RENAME:
			// Change the name
			Focus(hWnd, L_LINK);
			LvRename(hWnd, L_LINK, LvGetSelected(hWnd, L_LINK));
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LINK:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				// Change the selection state
				SmLinkDlgUpdate(hWnd, s);
				break;

			case LVN_ENDLABELEDITW:
				// Change the name
				disp_info = (NMLVDISPINFOW *)n;
				if (disp_info->item.pszText != NULL)
				{
					wchar_t *new_name = disp_info->item.pszText;
					wchar_t *old_name = LvGetStr(hWnd, L_LINK, disp_info->item.iItem, 0);

					if (old_name != NULL)
					{
						if (UniStrCmp(new_name, old_name) != 0 && UniIsEmptyStr(new_name) == false)
						{
							RPC_RENAME_LINK t;
							Zero(&t, sizeof(t));
							StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
							UniStrCpy(t.OldAccountName, sizeof(t.OldAccountName), old_name);
							UniStrCpy(t.NewAccountName, sizeof(t.NewAccountName), new_name);
							if (CALL(hWnd, ScRenameLink(s->Rpc, &t)))
							{
								SmLinkDlgRefresh(hWnd, s);
							}
						}

						Free(old_name);
					}
				}
				break;

			case LVN_KEYDOWN:
				// Keypress
				key = (NMLVKEYDOWN *)n;
				if (key != NULL)
				{
					bool ctrl, alt;
					UINT code = key->wVKey;
					ctrl = (GetKeyState(VK_CONTROL) & 0x8000) == 0 ? false : true;
					alt = (GetKeyState(VK_MENU) & 0x8000) == 0 ? false : true;

					if (code == VK_F2)
					{
						Command(hWnd, B_RENAME);
					}
				}
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	Free(str);

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LINK);

	return 0;
}

// Link List dialog
void SmLinkDlg(HWND hWnd, SM_HUB *s)
{
	SmLinkDlgEx(hWnd, s, false);
}
void SmLinkDlgEx(HWND hWnd, SM_HUB *s, bool createNow)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	link_create_now = createNow;

	Dialog(hWnd, D_SM_LINK, SmLinkDlgProc, s);
}

// Initialize
void SmRadiusDlgInit(HWND hWnd, SM_HUB *s)
{
	RPC_RADIUS t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_TOWER);

	FormatText(hWnd, S_TITLE, s->HubName);
	FormatText(hWnd, S_RADIUS_7, RADIUS_RETRY_INTERVAL, RADIUS_RETRY_TIMEOUT);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (CALL(hWnd, ScGetHubRadius(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	Check(hWnd, R_USE_RADIUS, StrLen(t.RadiusServerName) != 0);

	if (StrLen(t.RadiusServerName) != 0)
	{
		SetTextA(hWnd, E_HOSTNAME, t.RadiusServerName);
		SetIntEx(hWnd, E_PORT, t.RadiusPort);
		SetTextA(hWnd, E_SECRET1, t.RadiusSecret);
		SetTextA(hWnd, E_SECRET2, t.RadiusSecret);
		SetIntEx(hWnd, E_RADIUS_RETRY_INTERVAL, t.RadiusRetryInterval);
		FocusEx(hWnd, E_HOSTNAME);
	}
	else
	{
		SetInt(hWnd, E_PORT, RADIUS_DEFAULT_PORT);
		SetInt(hWnd, E_RADIUS_RETRY_INTERVAL, RADIUS_RETRY_INTERVAL);
	}

	SmRadiusDlgUpdate(hWnd, s);
}

// Update the control
void SmRadiusDlgUpdate(HWND hWnd, SM_HUB *s)
{
	bool ok = true;
	bool b, b1;
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	b1 = GetCapsBool(s->p->CapsList, "b_support_radius_retry_interval_and_several_servers");
	if(b1 == false)
	{
		Hide(hWnd, S_RADIUS_7);
		Hide(hWnd, S_RADIUS_8);
		Hide(hWnd, S_RADIUS_9);
		Hide(hWnd, E_RADIUS_RETRY_INTERVAL);
	}

	b = IsChecked(hWnd, R_USE_RADIUS);

	SetEnable(hWnd, S_RADIUS_1, b);
	SetEnable(hWnd, S_RADIUS_2, b);
	SetEnable(hWnd, S_RADIUS_3, b);
	SetEnable(hWnd, S_RADIUS3, b);
	SetEnable(hWnd, S_RADIUS_4, b);
	SetEnable(hWnd, S_RADIUS_5, b);
	SetEnable(hWnd, S_RADIUS_6, b);
	SetEnable(hWnd, S_RADIUS_7, b);
	SetEnable(hWnd, S_RADIUS_8, b);
	SetEnable(hWnd, S_RADIUS_9, b);
	SetEnable(hWnd, E_HOSTNAME, b);
	SetEnable(hWnd, E_PORT, b);
	SetEnable(hWnd, E_SECRET1, b);
	SetEnable(hWnd, E_SECRET2, b);
	SetEnable(hWnd, E_RADIUS_RETRY_INTERVAL, b);

	if (b)
	{
		UINT p, m;
		GetTxtA(hWnd, E_SECRET1, tmp1, sizeof(tmp1));
		GetTxtA(hWnd, E_SECRET2, tmp2, sizeof(tmp2));

		if (StrCmp(tmp1, tmp2) != 0)
		{
			ok = false;
		}

		if (IsEmpty(hWnd, E_HOSTNAME))
		{
			ok = false;
		}

		p = GetInt(hWnd, E_PORT);

		if (p == 0 || p >= 65536)
		{
			ok = false;
		}

		m = GetInt(hWnd, E_RADIUS_RETRY_INTERVAL);
		if (m > RADIUS_RETRY_TIMEOUT || m < RADIUS_RETRY_INTERVAL)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// [OK] button
void SmRadiusDlgOnOk(HWND hWnd, SM_HUB *s)
{
	RPC_RADIUS t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);

	if (IsChecked(hWnd, R_USE_RADIUS))
	{
		GetTxtA(hWnd, E_HOSTNAME, t.RadiusServerName, sizeof(t.RadiusServerName));
		t.RadiusPort = GetInt(hWnd, E_PORT);
		GetTxtA(hWnd, E_SECRET1,t.RadiusSecret, sizeof(t.RadiusSecret));
		t.RadiusRetryInterval = GetInt(hWnd, E_RADIUS_RETRY_INTERVAL);
	}

	if (CALL(hWnd, ScSetHubRadius(s->Rpc, &t)) == false)
	{
		return;
	}

	EndDialog(hWnd, true);
}


// Radius dialog procedure
UINT SmRadiusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmRadiusDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_HOSTNAME:
		case E_PORT:
		case E_SECRET1:
		case E_SECRET2:
		case E_RADIUS_RETRY_INTERVAL:
		case R_USE_RADIUS:
			SmRadiusDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// [OK] button
			SmRadiusDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;

		case R_USE_RADIUS:
			if (IsChecked(hWnd, R_USE_RADIUS))
			{
				FocusEx(hWnd, E_HOSTNAME);
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

// Radius Setup dialog
void SmRadiusDlg(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_RADIUS, SmRadiusDlgProc, s);
}


// Initialize
void SmEditAccessInit(HWND hWnd, SM_EDIT_ACCESS *s)
{
	ACCESS *a;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_PASS);

	GetTxt(hWnd, 0, tmp, sizeof(tmp));

	UniStrCat(tmp, sizeof(tmp), s->Access->IsIPv6 ? L" (IPv6)" : L" (IPv4)");

	SetText(hWnd, 0, tmp);

	s->Inited = false;
	a = s->Access;

	SetText(hWnd, E_NOTE, a->Note);

	Check(hWnd, R_DISCARD, a->Discard);
	Check(hWnd, R_PASS, a->Discard == false);
	SetIntEx(hWnd, E_PRIORITY, a->Priority);

	if (a->IsIPv6 == false)
	{
		// IPv4
		if (a->SrcIpAddress == 0 && a->SrcSubnetMask == 0)
		{
			Check(hWnd, R_SRC_ALL, true);
		}
		else
		{
			IpSet(hWnd, E_SRC_IP, a->SrcIpAddress);
			IpSet(hWnd, E_SRC_MASK, a->SrcSubnetMask);
		}

		if (a->DestIpAddress == 0 && a->DestSubnetMask == 0)
		{
			Check(hWnd, R_DST_ALL, true);
		}
		else
		{
			IpSet(hWnd, E_DST_IP, a->DestIpAddress);
			IpSet(hWnd, E_DST_MASK, a->DestSubnetMask);
		}
	}
	else
	{
		// IPv6
		if (IsZeroIP6Addr(&a->SrcIpAddress6) && IsZeroIP6Addr(&a->SrcSubnetMask6))
		{
			Check(hWnd, R_SRC_ALL, true);
		}
		else
		{
			char tmp[MAX_SIZE];

			IP6AddrToStr(tmp, sizeof(tmp), &a->SrcIpAddress6);
			SetTextA(hWnd, E_SRC_IP_V6, tmp);

			Mask6AddrToStrEx(tmp, sizeof(tmp), &a->SrcSubnetMask6, false);

			if (IsNum(tmp))
			{
				StrCatLeft(tmp, sizeof(tmp), "/");
			}

			SetTextA(hWnd, E_SRC_MASK_V6, tmp);
		}

		if (IsZeroIP6Addr(&a->DestIpAddress6) && IsZeroIP6Addr(&a->DestSubnetMask6))
		{
			Check(hWnd, R_DST_ALL, true);
		}
		else
		{
			char tmp[MAX_SIZE];

			IP6AddrToStr(tmp, sizeof(tmp), &a->DestIpAddress6);
			SetTextA(hWnd, E_DST_IP_V6, tmp);

			Mask6AddrToStrEx(tmp, sizeof(tmp), &a->DestSubnetMask6, false);

			if (IsNum(tmp))
			{
				StrCatLeft(tmp, sizeof(tmp), "/");
			}

			SetTextA(hWnd, E_DST_MASK_V6, tmp);
		}
	}

	CbSetHeight(hWnd, C_PROTOCOL, 18);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_1"), 0);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_2"), 0);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_3"), 0);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_4"), 0);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_5"), 0);
	CbAddStr(hWnd, C_PROTOCOL, _UU("SM_ACCESS_PROTO_6"), 0);

	switch (a->Protocol)
	{
	case 0:
		CbSelectIndex(hWnd, C_PROTOCOL, 0);
		break;
	case 6:
		CbSelectIndex(hWnd, C_PROTOCOL, 1);
		break;
	case 17:
		CbSelectIndex(hWnd, C_PROTOCOL, 2);
		break;
	case 1:
		CbSelectIndex(hWnd, C_PROTOCOL, 3);
		break;
	case 58:
		CbSelectIndex(hWnd, C_PROTOCOL, 4);
		break;
	default:
		CbSelectIndex(hWnd, C_PROTOCOL, 5);
		break;
	}

	SetIntEx(hWnd, E_IP_PROTO, a->Protocol);

	SetIntEx(hWnd, E_SRC_PORT_1, a->SrcPortStart);
	SetIntEx(hWnd, E_SRC_PORT_2, a->SrcPortEnd);
	SetIntEx(hWnd, E_DST_PORT_1, a->DestPortStart);
	SetIntEx(hWnd, E_DST_PORT_2, a->DestPortEnd);

	SetTextA(hWnd, E_USERNAME1, a->SrcUsername);
	SetTextA(hWnd, E_USERNAME2, a->DestUsername);

	if(a->CheckSrcMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->SrcMacAddress);
		MacToStr(mask, sizeof(mask), a->SrcMacMask);
		SetTextA(hWnd, E_SRC_MAC, mac); 
		SetTextA(hWnd, E_SRC_MAC_MASK, mask);
	}
	if(a->CheckDstMac != false)
	{
		char mac[MAX_SIZE], mask[MAX_SIZE];
		MacToStr(mac, sizeof(mac), a->DstMacAddress);
		MacToStr(mask, sizeof(mask), a->DstMacMask);
		SetTextA(hWnd, E_DST_MAC, mac); 
		SetTextA(hWnd, E_DST_MAC_MASK, mask);
	}
	Check(hWnd, R_CHECK_SRC_MAC, !a->CheckSrcMac);
	Check(hWnd, R_CHECK_DST_MAC, !a->CheckDstMac);

	Check(hWnd, R_CHECK_TCP_STATE, a->CheckTcpState);
	if(a->CheckTcpState != false)
	{
		Check(hWnd, R_ESTABLISHED, a->Established);
		Check(hWnd, R_UNESTABLISHED, !a->Established);
	}

	if (GetCapsBool(s->Hub->p->CapsList, "b_support_acl_group") == false)
	{
		SetText(hWnd, S_STATIC11, _UU("D_SM_EDIT_ACCESS@STATIC11_OLD"));
		SetText(hWnd, S_STATIC12, _UU("D_SM_EDIT_ACCESS@STATIC12_OLD"));
		SetText(hWnd, S_STATIC15, _UU("D_SM_EDIT_ACCESS@STATIC15_OLD"));
	}

	SetEnable(hWnd, R_REDIRECT, GetCapsBool(s->Hub->p->CapsList, "b_support_redirect_url_acl"));
	Check(hWnd, R_REDIRECT, (IsEmptyStr(a->RedirectUrl) ? false : true));

	s->Inited = true;

	SmEditAccessUpdate(hWnd, s);
}

// HTTP Redirection Settings dialog
void SmRedirect(HWND hWnd, SM_EDIT_ACCESS *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_REDIRECT, SmRedirectDlg, s);
}
UINT SmRedirectDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_ACCESS *s = (SM_EDIT_ACCESS *)param;
	char tmp[MAX_REDIRECT_URL_LEN + 1];

	switch (msg)
	{
	case WM_INITDIALOG:
		SmRedirectDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_URL:
			SmRedirectDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			GetTxtA(hWnd, E_URL, tmp, sizeof(tmp));

			if (StartWith(tmp, "http://") == false &&
				StartWith(tmp, "https://") == false)
			{
				MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SM_ADVANCED_REDIRECT_URL_MSG"));

				FocusEx(hWnd, E_URL);
				break;
			}

			StrCpy(s->Access->RedirectUrl, sizeof(s->Access->RedirectUrl), tmp);

			EndDialog(hWnd, 1);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_HINT:
			OnceMsg(hWnd, _UU("SM_ADVANCED_REDIRECT_URL_HINT_TITLE"),
				_UU("SM_ADVANCED_REDIRECT_URL_HINT"), false, ICO_INTERNET);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}
void SmRedirectDlgInit(HWND hWnd, SM_EDIT_ACCESS *s)
{
	ACCESS *a;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	a = s->Access;

	DlgFont(hWnd, S_BOLD, 0, true);
	DlgFont(hWnd, S_BOLD2, 0, true);

	SetFont(hWnd, E_SAMPLE1, GetFont("Verdana", 0, false, false, false, false));
	SetFont(hWnd, E_SAMPLE2, GetFont("Verdana", 0, false, false, false, false));
	SetFont(hWnd, E_URL, GetFont("Verdana", 10, false, false, false, false));

	SetTextA(hWnd, E_SAMPLE1, "http://www.google.com/about/");
	SetTextA(hWnd, E_SAMPLE2, "http://www.google.com/search?q=<INFO>|secret");

	SetTextA(hWnd, E_URL, s->Access->RedirectUrl);

	if (IsEmpty(hWnd, E_URL))
	{
		SetTextA(hWnd, E_URL, "http://");

		SetCursorOnRight(hWnd, E_URL);
		Focus(hWnd, E_URL);
	}
	else
	{
		FocusEx(hWnd, E_URL);
	}

	SmRedirectDlgUpdate(hWnd, s);
}
void SmRedirectDlgUpdate(HWND hWnd, SM_EDIT_ACCESS *s)
{
	char tmp[MAX_REDIRECT_URL_LEN + 1];
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_URL, tmp, sizeof(tmp));

	if (IsEmptyStr(tmp))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
}

// Update the control
void SmEditAccessUpdate(HWND hWnd, SM_EDIT_ACCESS *s)
{
	bool ok = true;
	bool tcp;
	bool b;
	bool check_srcmac, check_dstmac, support_mac;
	bool check_state, support_check_state;
	char srcmac[MAX_SIZE], srcmac_mask[MAX_SIZE], dstmac[MAX_SIZE], dstmac_mask[MAX_SIZE];
	char tmp[MAX_SIZE];
	wchar_t unitmp[MAX_SIZE];
	ACCESS *a;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (s->Inited == false)
	{
		return;
	}

	a = s->Access;

	GetTxt(hWnd, E_NOTE, a->Note, sizeof(a->Note));

	a->Discard = IsChecked(hWnd, R_DISCARD);

	a->Priority = GetInt(hWnd, E_PRIORITY);
	if (a->Priority == 0)
	{
		ok = false;
	}


	b = IsChecked(hWnd, R_SRC_ALL) ? false : true;
	if (b == false)
	{
		if (a->IsIPv6 == false)
		{
			a->SrcIpAddress = 0;
			a->SrcSubnetMask = 0;
		}
		else
		{
			Zero(&a->SrcIpAddress6, sizeof(IPV6_ADDR));
			Zero(&a->SrcSubnetMask6, sizeof(IPV6_ADDR));
		}
	}
	else
	{
		if (a->IsIPv6 == false)
		{
			if (IpIsFilled(hWnd, E_SRC_IP) == false || IpIsFilled(hWnd, E_SRC_MASK) == false)
			{
				ok = false;
			}
			else
			{
				a->SrcIpAddress = IpGet(hWnd, E_SRC_IP);
				a->SrcSubnetMask = IpGet(hWnd, E_SRC_MASK);
			}
		}
		else
		{
			char tmp1[MAX_SIZE];
			char tmp2[MAX_SIZE];

			GetTxtA(hWnd, E_SRC_IP_V6, tmp1, sizeof(tmp1));
			GetTxtA(hWnd, E_SRC_MASK_V6, tmp2, sizeof(tmp2));

			if (StrToIP6Addr(&a->SrcIpAddress6, tmp1) == false ||
				StrToMask6Addr(&a->SrcSubnetMask6, tmp2) == false)
			{
				ok = false;
			}
		}
	}
	SetEnable(hWnd, S_SRC_IP_1, b);
	SetEnable(hWnd, S_SRC_IP_2, b);
	SetEnable(hWnd, S_SRC_IP_3, b);
	SetEnable(hWnd, E_SRC_IP, b);
	SetEnable(hWnd, E_SRC_MASK, b);
	SetEnable(hWnd, E_SRC_IP_V6, b);
	SetEnable(hWnd, E_SRC_MASK_V6, b);

	b = IsChecked(hWnd, R_DST_ALL) ? false : true;
	if (b == false)
	{
		if (a->IsIPv6 == false)
		{
			a->DestIpAddress = 0;
			a->DestSubnetMask = 0;
		}
		else
		{
			Zero(&a->DestIpAddress6, sizeof(IPV6_ADDR));
			Zero(&a->DestSubnetMask6, sizeof(IPV6_ADDR));
		}
	}
	else
	{
		if (a->IsIPv6 == false)
		{
			if (IpIsFilled(hWnd, E_DST_IP) == false || IpIsFilled(hWnd, E_DST_MASK) == false)
			{
				ok = false;
			}
			else
			{
				a->DestIpAddress = IpGet(hWnd, E_DST_IP);
				a->DestSubnetMask = IpGet(hWnd, E_DST_MASK);
			}
		}
		else
		{
			char tmp1[MAX_SIZE];
			char tmp2[MAX_SIZE];

			GetTxtA(hWnd, E_DST_IP_V6, tmp1, sizeof(tmp1));
			GetTxtA(hWnd, E_DST_MASK_V6, tmp2, sizeof(tmp2));

			if (StrToIP6Addr(&a->DestIpAddress6, tmp1) == false ||
				StrToMask6Addr(&a->DestSubnetMask6, tmp2) == false)
			{
				ok = false;
			}
		}
	}
	SetEnable(hWnd, S_IP_DST_1, b);
	SetEnable(hWnd, S_IP_DST_2, b);
	SetEnable(hWnd, S_IP_DST_3, b);
	SetEnable(hWnd, E_DST_IP, b);
	SetEnable(hWnd, E_DST_MASK, b);
	SetEnable(hWnd, E_DST_IP_V6, b);
	SetEnable(hWnd, E_DST_MASK_V6, b);

	a->Protocol = GetInt(hWnd, C_PROTOCOL);

	GetTxtA(hWnd, C_PROTOCOL, tmp, sizeof(tmp));
	GetTxt(hWnd, C_PROTOCOL, unitmp, sizeof(unitmp));

	if (UniStrCmpi(unitmp, _UU("SM_ACCESS_PROTO_6")) == 0 || StrCmpi(tmp, _SS("SM_ACCESS_PROTO_6")) == 0)
	{
		a->Protocol = GetInt(hWnd, E_IP_PROTO);

		if (IsEmpty(hWnd, E_IP_PROTO))
		{
			ok = false;
		}

		Enable(hWnd, S_PROTOID);
		Enable(hWnd, E_IP_PROTO);
	}
	else
	{
		Disable(hWnd, E_IP_PROTO);
		Disable(hWnd, S_PROTOID);
	}

	tcp = false;
	if (a->Protocol == 17 || a->Protocol == 6)
	{
		tcp = true;
	}

	SetEnable(hWnd, S_TCP_1, tcp);
	SetEnable(hWnd, S_TCP_2, tcp);
	SetEnable(hWnd, S_TCP_3, tcp);
	SetEnable(hWnd, S_TCP_4, tcp);
	SetEnable(hWnd, S_TCP_5, tcp);
	SetEnable(hWnd, S_TCP_6, tcp);
	SetEnable(hWnd, S_TCP_7, tcp);
	SetEnable(hWnd, E_SRC_PORT_1, tcp);
	SetEnable(hWnd, E_SRC_PORT_2, tcp);
	SetEnable(hWnd, E_DST_PORT_1, tcp);
	SetEnable(hWnd, E_DST_PORT_2, tcp);

	if (tcp == false)
	{
		a->SrcPortEnd = a->SrcPortStart = a->DestPortEnd = a->DestPortStart = 0;
	}
	else
	{
		a->SrcPortStart = GetInt(hWnd, E_SRC_PORT_1);
		a->SrcPortEnd = GetInt(hWnd, E_SRC_PORT_2);
		a->DestPortStart = GetInt(hWnd, E_DST_PORT_1);
		a->DestPortEnd = GetInt(hWnd, E_DST_PORT_2);

		if (a->SrcPortStart != 0)
		{
			if (a->SrcPortEnd != 0)
			{
				if (a->SrcPortStart > a->SrcPortEnd)
				{
					ok = false;
				}
			}
		}
		else
		{
			if (a->SrcPortEnd != 0)
			{
				ok = false;
			}
		}

		if (a->DestPortStart != 0)
		{
			if (a->DestPortEnd != 0)
			{
				if (a->DestPortStart > a->DestPortEnd)
				{
					ok = false;
				}
			}
		}
		else
		{
			if (a->DestPortEnd != 0)
			{
				ok = false;
			}
		}

		if (a->DestPortEnd < a->DestPortStart)
		{
			a->DestPortEnd = a->DestPortStart;
		}

		if (a->SrcPortEnd < a->SrcPortStart)
		{
			a->SrcPortEnd = a->SrcPortStart;
		}
	}

	a->SrcUsernameHash = a->DestUsernameHash = 0;
	GetTxtA(hWnd, E_USERNAME1, a->SrcUsername, sizeof(a->SrcUsername));
	GetTxtA(hWnd, E_USERNAME2, a->DestUsername, sizeof(a->DestUsername));

	if (StartWith(a->SrcUsername, ACCESS_LIST_INCLUDED_PREFIX) == false && 
		StartWith(a->SrcUsername, ACCESS_LIST_EXCLUDED_PREFIX) == false)
	{
		MakeSimpleUsernameRemoveNtDomain(a->SrcUsername, sizeof(a->SrcUsername), a->SrcUsername);
	}

	if (StartWith(a->DestUsername, ACCESS_LIST_INCLUDED_PREFIX) == false && 
		StartWith(a->DestUsername, ACCESS_LIST_EXCLUDED_PREFIX) == false)
	{
		MakeSimpleUsernameRemoveNtDomain(a->DestUsername, sizeof(a->DestUsername), a->DestUsername);
	}

	Trim(a->SrcUsername);
	/*
	if (StrLen(a->SrcUsername) != 0)
	{
		if (IsUserName(a->SrcUsername) == false)
		{
			ok = false;
		}
	}*/

	Trim(a->DestUsername);
	/*
	if (StrLen(a->DestUsername) != 0)
	{
		if (IsUserName(a->DestUsername) == false)
		{
			ok = false;
		}
	}*/

	support_mac = GetCapsBool(s->Hub->p->CapsList, "b_support_check_mac");

	// Set the source MAC address
	check_srcmac = a->CheckSrcMac = support_mac && (IsChecked(hWnd, R_CHECK_SRC_MAC) ? false : true);
	if(check_srcmac == false)
	{
		Zero(a->SrcMacAddress, sizeof(a->SrcMacAddress));
		Zero(a->SrcMacMask, sizeof(a->SrcMacMask));
	}
	else
	{
		GetTxtA(hWnd, E_SRC_MAC, srcmac, sizeof(srcmac));
		GetTxtA(hWnd, E_SRC_MAC_MASK, srcmac_mask, sizeof(srcmac_mask));
		Trim(srcmac);
		Trim(srcmac_mask);
		if(StrLen(srcmac) != 0 && StrLen(srcmac_mask) != 0)
		{
			UCHAR mac[6], mask[6];
			if(StrToMac(mac, srcmac) && StrToMac(mask, srcmac_mask))
			{
				Copy(a->SrcMacAddress, mac, 6);
				Copy(a->SrcMacMask, mask, 6);
			}
			else
			{
				ok = false;
			}
		}
		else
		{
			ok = false;
		}
	}
	SetEnable(hWnd, S_CHECK_SRC_MAC, support_mac);
	SetEnable(hWnd, R_CHECK_SRC_MAC, support_mac);
	SetEnable(hWnd, S_SRC_MAC, check_srcmac);
	SetEnable(hWnd, S_SRC_MAC_MASK, check_srcmac);
	SetEnable(hWnd, E_SRC_MAC, check_srcmac);
	SetEnable(hWnd, E_SRC_MAC_MASK, check_srcmac);

	// Set the destination MAC address
	check_dstmac = a->CheckDstMac = support_mac && (IsChecked(hWnd, R_CHECK_DST_MAC) ? false : true);
	if(check_dstmac == false)
	{
		Zero(a->DstMacAddress, sizeof(a->DstMacAddress));
		Zero(a->DstMacMask, sizeof(a->DstMacMask));
	}
	else
	{
		GetTxtA(hWnd, E_DST_MAC, dstmac, sizeof(dstmac));
		GetTxtA(hWnd, E_DST_MAC_MASK, dstmac_mask, sizeof(dstmac_mask));
		Trim(dstmac);
		Trim(dstmac_mask);
		if(StrLen(dstmac) != 0 && StrLen(dstmac_mask) != 0)
		{
			UCHAR mac[6], mask[6];
			if(StrToMac(mac, dstmac) && StrToMac(mask, dstmac_mask))
			{
				Copy(a->DstMacAddress, mac, 6);
				Copy(a->DstMacMask, mask, 6);
			}
			else
			{
				ok = false;
			}
		}
		else
		{
			ok = false;
		}
	}
	SetEnable(hWnd, S_CHECK_DST_MAC, support_mac);
	SetEnable(hWnd, R_CHECK_DST_MAC, support_mac);
	SetEnable(hWnd, S_DST_MAC, check_dstmac);
	SetEnable(hWnd, S_DST_MAC_MASK, check_dstmac);
	SetEnable(hWnd, E_DST_MAC, check_dstmac);
	SetEnable(hWnd, E_DST_MAC_MASK, check_dstmac);

	SetEnable(hWnd, S_MAC_NOTE, check_srcmac || check_dstmac);

	// Status of the TCP connection
	support_check_state = GetCapsBool(s->Hub->p->CapsList, "b_support_check_tcp_state") && a->Protocol == 6;
	SetEnable(hWnd, R_CHECK_TCP_STATE, support_check_state);
	check_state = a->CheckTcpState = support_check_state && IsChecked(hWnd, R_CHECK_TCP_STATE);

	a->Established = IsChecked(hWnd, R_ESTABLISHED) && check_state;
	SetEnable(hWnd, R_ESTABLISHED, check_state);
	SetEnable(hWnd, R_UNESTABLISHED, check_state);
	if(check_state != false && IsChecked(hWnd, R_ESTABLISHED) == false && IsChecked(hWnd, R_UNESTABLISHED) == false)
	{
		ok = false;
	}

	// Settings button such as delay
	SetEnable(hWnd, B_SIMULATION, a->Discard == false && GetCapsBool(s->Hub->p->CapsList, "b_support_ex_acl"));

	// HTTP redirection settings button
	SetEnable(hWnd, B_REDIRECT, IsChecked(hWnd, R_REDIRECT) && (a->Discard == false) && GetCapsBool(s->Hub->p->CapsList, "b_support_redirect_url_acl"));
	SetEnable(hWnd, R_REDIRECT, (a->Discard == false) && GetCapsBool(s->Hub->p->CapsList, "b_support_redirect_url_acl"));

	if (IsChecked(hWnd, R_REDIRECT) && (a->Discard == false) && GetCapsBool(s->Hub->p->CapsList, "b_support_redirect_url_acl"))
	{
		if (IsEmptyStr(a->RedirectUrl))
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// OK Click
void SmEditAccessOnOk(HWND hWnd, SM_EDIT_ACCESS *s)
{
	ACCESS *a;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	a = s->Access;

	SmEditAccessUpdate(hWnd, s);

	if (IsChecked(hWnd, R_REDIRECT) == false || (a->Discard) || GetCapsBool(s->Hub->p->CapsList, "b_support_redirect_url_acl") == false)
	{
		// Disable the HTTP redirection
		ClearStr(a->RedirectUrl, sizeof(a->RedirectUrl));
	}

	EndDialog(hWnd, true);
}


// Access list editing dialog
UINT SmEditAccessDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_ACCESS *s = (SM_EDIT_ACCESS *)param;
	UINT ico;
	ACCESS *a;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmEditAccessInit(hWnd, s);

		goto REFRESH_ICON;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_PASS:
		case R_DISCARD:
		case E_PRIORITY:
		case R_SRC_ALL:
		case E_SRC_IP:
		case E_SRC_MASK:
		case R_DST_ALL:
		case E_DST_MASK:
		case E_SRC_IP_V6:
		case E_SRC_MASK_V6:
		case E_DST_MASK_V6:
		case E_DST_IP_V6:
		case C_PROTOCOL:
		case E_SRC_PORT_1:
		case E_SRC_PORT_2:
		case E_DST_PORT_1:
		case E_DST_PORT_2:
		case E_USERNAME1:
		case E_USERNAME2:
		case E_IP_PROTO:
		case R_CHECK_SRC_MAC:
		case E_SRC_MAC:
		case E_SRC_MAC_MASK:
		case R_CHECK_DST_MAC:
		case E_DST_MAC:
		case E_DST_MAC_MASK:
		case R_CHECK_TCP_STATE:
		case R_ESTABLISHED:
		case R_UNESTABLISHED:
		case R_REDIRECT:
			SmEditAccessUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case B_USER1:
			if (GetTxtA(hWnd, E_USERNAME1, tmp, sizeof(tmp)))
			{
				char *ret = SmSelectUserDlgEx(hWnd, s->Hub, tmp, GetCapsBool(s->Hub->p->CapsList, "b_support_acl_group"));
				if (ret == NULL)
				{
					SetTextA(hWnd, E_USERNAME1, "");
				}
				else
				{
					SetTextA(hWnd, E_USERNAME1, ret);
					Free(ret);
				}
				FocusEx(hWnd, E_USERNAME1);
			}
			break;

		case B_USER2:
			if (GetTxtA(hWnd, E_USERNAME2, tmp, sizeof(tmp)))
			{
				char *ret = SmSelectUserDlgEx(hWnd, s->Hub, tmp, GetCapsBool(s->Hub->p->CapsList, "b_support_acl_group"));
				if (ret == NULL)
				{
					SetTextA(hWnd, E_USERNAME2, "");
				}
				else
				{
					SetTextA(hWnd, E_USERNAME2, ret);
					Free(ret);
				}
				FocusEx(hWnd, E_USERNAME2);
			}
			break;

		case IDOK:
			// [OK] button
			SmEditAccessOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;

		case R_SRC_ALL:
			if (IsChecked(hWnd, R_SRC_ALL) == false)
			{
				if (s->Access->IsIPv6)
				{
					FocusEx(hWnd, E_SRC_IP_V6);
				}
				else
				{
					Focus(hWnd, E_SRC_IP);
				}
			}
			break;

		case R_DST_ALL:
			if (IsChecked(hWnd, R_DST_ALL) == false)
			{
				if (s->Access->IsIPv6)
				{
					FocusEx(hWnd, E_DST_IP_V6);
				}
				else
				{
					Focus(hWnd, E_DST_IP);
				}
			}
			break;
		case R_CHECK_SRC_MAC:
			if(IsChecked(hWnd, R_CHECK_SRC_MAC) == false)
			{
				Focus(hWnd, E_SRC_MAC);
			}
			break;
		case R_CHECK_DST_MAC:
			if(IsChecked(hWnd, R_CHECK_DST_MAC) == false)
			{
				Focus(hWnd, E_DST_MAC);
			}
			break;

		case R_PASS:
		case R_DISCARD:
REFRESH_ICON:
			a = s->Access;
			if (a->Discard == false && a->Active == false)
			{
				ico = ICO_PASS_DISABLE;
			}
			else if (a->Discard == false && a->Active)
			{
				ico = ICO_PASS;
			}
			else if (a->Discard && a->Active == false)
			{
				ico = ICO_DISCARD_DISABLE;
			}
			else
			{
				ico = ICO_DISCARD;
			}

			SetIcon(hWnd, S_ICON, ico);
			break;

		case B_SIMULATION:
			// Simulation
			Dialog(hWnd, D_SM_SIMULATION, SmSimulationDlg, s);
			break;

		case B_REDIRECT:
			// Set the URL to redirect to
			SmRedirect(hWnd, s);
			SmEditAccessUpdate(hWnd, s);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Delay, jitter, packet-loss dialog
UINT SmSimulationDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_ACCESS *s = (SM_EDIT_ACCESS *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmSimulationInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_DELAY:
		case E_JITTER:
		case E_LOSS:
			SmSimulationUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmSimulationOnOk(hWnd, s);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case C_DELAY:
			SmSimulationUpdate(hWnd, s);
			if (IsChecked(hWnd, C_DELAY))
			{
				FocusEx(hWnd, E_DELAY);
			}
			break;

		case C_JITTER:
			SmSimulationUpdate(hWnd, s);
			if (IsChecked(hWnd, C_JITTER))
			{
				FocusEx(hWnd, E_JITTER);
			}
			break;

		case C_LOSS:
			SmSimulationUpdate(hWnd, s);
			if (IsChecked(hWnd, C_LOSS))
			{
				FocusEx(hWnd, E_LOSS);
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

// Update of delay, jitter, packet-loss dialog
void SmSimulationUpdate(HWND hWnd, SM_EDIT_ACCESS *s)
{
	bool b1, b2, b3;
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	b1 = IsChecked(hWnd, C_DELAY);
	b2 = IsChecked(hWnd, C_JITTER);
	b3 = IsChecked(hWnd, C_LOSS);

	SetEnable(hWnd, S_DELAY, b1);
	SetEnable(hWnd, S_DELAY2, b1);
	SetEnable(hWnd, E_DELAY, b1);

	SetEnable(hWnd, C_JITTER, b1);

	if (b1 == false)
	{
		b2 = false;
	}

	SetEnable(hWnd, S_JITTER, b2);
	SetEnable(hWnd, S_JITTER2, b2);
	SetEnable(hWnd, E_JITTER, b2);

	SetEnable(hWnd, S_LOSS, b3);
	SetEnable(hWnd, S_LOSS2, b3);
	SetEnable(hWnd, E_LOSS, b3);

	if (b1)
	{
		UINT i = GetInt(hWnd, E_DELAY);
		if (i == 0 || i > HUB_ACCESSLIST_DELAY_MAX)
		{
			ok = false;
		}
	}

	if (b2)
	{
		UINT i = GetInt(hWnd, E_JITTER);
		if (i == 0 || i > HUB_ACCESSLIST_JITTER_MAX)
		{
			ok = false;
		}
	}

	if (b3)
	{
		UINT i = GetInt(hWnd, E_LOSS);
		if (i == 0 || i > HUB_ACCESSLIST_LOSS_MAX)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// Initialization of delay, jitter, packet-loss dialog
void SmSimulationInit(HWND hWnd, SM_EDIT_ACCESS *s)
{
	ACCESS *a;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	a = s->Access;

	Check(hWnd, C_DELAY, a->Delay != 0);
	Check(hWnd, C_JITTER, a->Jitter != 0);
	Check(hWnd, C_LOSS, a->Loss != 0);

	SetIntEx(hWnd, E_DELAY, a->Delay);
	if (a->Delay != 0)
	{
		SetIntEx(hWnd, E_JITTER, a->Jitter);
	}
	SetIntEx(hWnd, E_LOSS, a->Loss);

	SmSimulationUpdate(hWnd, s);

	if (a->Delay != 0)
	{
		FocusEx(hWnd, E_DELAY);
	}
	else
	{
		Focus(hWnd, C_DELAY);
	}
}

// Saving of delay, jitter, packet-loss dialog
void SmSimulationOnOk(HWND hWnd, SM_EDIT_ACCESS *s)
{
	ACCESS *a;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	a = s->Access;

	a->Jitter = a->Loss = a->Delay = 0;

	if (IsChecked(hWnd, C_DELAY))
	{
		a->Delay = GetInt(hWnd, E_DELAY);
	}

	if (IsChecked(hWnd, C_JITTER))
	{
		a->Jitter = GetInt(hWnd, E_JITTER);
	}

	if (IsChecked(hWnd, C_LOSS))
	{
		a->Loss = GetInt(hWnd, E_LOSS);
	}

	EndDialog(hWnd, 1);
}

// Edit the access list
bool SmEditAccess(HWND hWnd, SM_ACCESS_LIST *s, ACCESS *a)
{
	SM_EDIT_ACCESS edit;
	bool ret;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&edit, sizeof(edit));
	edit.AccessList = s;
	edit.EditMode = true;
	edit.Access = ZeroMalloc(sizeof(ACCESS));
	edit.Hub = s->Hub;
	Copy(edit.Access, a, sizeof(ACCESS));

	if (edit.Access->IsIPv6 == false)
	{
		ret = Dialog(hWnd, D_SM_EDIT_ACCESS, SmEditAccessDlg, &edit);
	}
	else
	{
		ret = Dialog(hWnd, D_SM_EDIT_ACCESS_V6, SmEditAccessDlg, &edit);
	}

	if (ret)
	{
		Copy(a, edit.Access, sizeof(ACCESS));
		Free(edit.Access);
		Sort(s->AccessList);

		// Reassign the ID
		for (i = 0;i < LIST_NUM(s->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(s->AccessList, i);
			a->Id = (i + 1);
		}
	}
	else
	{
		Free(edit.Access);
	}

	return ret;
}

// Clone of the access list
bool SmCloneAccess(HWND hWnd, SM_ACCESS_LIST *s, ACCESS *t)
{
	SM_EDIT_ACCESS edit;
	bool ret;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL || t == NULL)
	{
		return false;
	}

	Zero(&edit, sizeof(edit));
	edit.AccessList = s;
	edit.Access = Clone(t, sizeof(ACCESS));
	edit.Access->Priority = 0;
	edit.Hub = s->Hub;

	// Generate a number that does not duplicate with other and is larger than the priority of the cloning original
	for (edit.Access->Priority = t->Priority;edit.Access->Priority != INFINITE;edit.Access->Priority++)
	{
		bool exists = false;

		for (i = 0;i < LIST_NUM(s->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(s->AccessList, i);

			if (a->Priority == edit.Access->Priority)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			break;
		}
	}

	if (edit.Access->IsIPv6 == false)
	{
		ret = Dialog(hWnd, D_SM_EDIT_ACCESS, SmEditAccessDlg, &edit);
	}
	else
	{
		ret = Dialog(hWnd, D_SM_EDIT_ACCESS_V6, SmEditAccessDlg, &edit);
	}

	if (ret)
	{
		Insert(s->AccessList, edit.Access);

		// Reassign the ID
		for (i = 0;i < LIST_NUM(s->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(s->AccessList, i);
			a->Id = (i + 1);
		}
	}
	else
	{
		Free(edit.Access);
	}

	return ret;
}

// Add to Access List
bool SmAddAccess(HWND hWnd, SM_ACCESS_LIST *s, bool ipv6)
{
	SM_EDIT_ACCESS edit;
	bool ret;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&edit, sizeof(edit));
	edit.AccessList = s;
	edit.Access = ZeroMalloc(sizeof(ACCESS));
	edit.Access->Active = true;
	edit.Access->Priority = 0;
	edit.Access->IsIPv6 = ipv6;
	edit.Hub = s->Hub;

	// Get the new priority
	for (i = 0;i < LIST_NUM(s->AccessList);i++)
	{
		ACCESS *a = LIST_DATA(s->AccessList, i);
		edit.Access->Priority = MAX(edit.Access->Priority, a->Priority);
	}

	if (edit.Access->Priority == 0)
	{
		edit.Access->Priority = 900;
	}

	edit.Access->Priority += 100;

	if (edit.Access->IsIPv6 == false)
	{
		ret = Dialog(hWnd, D_SM_EDIT_ACCESS, SmEditAccessDlg, &edit);
	}
	else
	{
		ret = Dialog(hWnd, D_SM_EDIT_ACCESS_V6, SmEditAccessDlg, &edit);
	}

	if (ret)
	{
		Insert(s->AccessList, edit.Access);

		// Reassign the ID
		for (i = 0;i < LIST_NUM(s->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(s->AccessList, i);
			a->Id = (i + 1);
		}
	}
	else
	{
		Free(edit.Access);
	}

	return ret;
}

// Initialize
void SmAccessListInit(HWND hWnd, SM_ACCESS_LIST *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_PASS);
	FormatText(hWnd, S_TITLE, s->Hub->HubName);

	LvInit(hWnd, L_ACCESS_LIST);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 0, _UU("SM_ACCESS_COLUMN_0"), 60);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 1, _UU("SM_ACCESS_COLUMN_1"), 60);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 2, _UU("SM_ACCESS_COLUMN_2"), 60);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 3, _UU("SM_ACCESS_COLUMN_3"), 70);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 4, _UU("SM_ACCESS_COLUMN_4"), 150);
	LvInsertColumn(hWnd, L_ACCESS_LIST, 5, _UU("SM_ACCESS_COLUMN_5"), 600);

	LvSetStyle(hWnd, L_ACCESS_LIST, LVS_EX_GRIDLINES);

	SetEnable(hWnd, B_ADD_V6, GetCapsBool(s->Hub->p->CapsList, "b_support_ipv6_acl"));

	SmAccessListRefresh(hWnd, s);
}

// Update the control
void SmAccessListUpdate(HWND hWnd, SM_ACCESS_LIST *s)
{
	bool ok = true;
	UINT max_access_lists = 0;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_ACCESS_LIST) == false || LvIsMultiMasked(hWnd, L_ACCESS_LIST))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
	SetEnable(hWnd, B_DELETE, ok);
	SetEnable(hWnd, B_CLONE, ok);

	if (ok == false)
	{
		SetEnable(hWnd, B_ENABLE, false);
		SetEnable(hWnd, B_DISABLE, false);
	}
	else
	{
		ACCESS *a = LvGetParam(hWnd, L_ACCESS_LIST, LvGetSelected(hWnd, L_ACCESS_LIST));

		if (a != NULL)
		{
			SetEnable(hWnd, B_ENABLE, (a->Active == false));
			SetEnable(hWnd, B_DISABLE, (a->Active == true));
		}
		else
		{
			SetEnable(hWnd, B_ENABLE, false);
			SetEnable(hWnd, B_DISABLE, false);
		}
	}

	max_access_lists = GetCapsInt(s->Hub->p->CapsList, "i_max_access_lists");

	SetEnable(hWnd, B_CREATE, LIST_NUM(s->AccessList) < max_access_lists);
}

// Content update
void SmAccessListRefresh(HWND hWnd, SM_ACCESS_LIST *s)
{
	LVB *b;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	b = LvInsertStart();

	Sort(s->AccessList);

	for (i = 0;i < LIST_NUM(s->AccessList);i++)
	{
		ACCESS *a = LIST_DATA(s->AccessList, i);
		char tmp[MAX_SIZE];
		UINT ico = ICO_PASS;
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		GetAccessListStr(tmp, sizeof(tmp), a);
		UniToStru(tmp1, a->Priority);
		StrToUni(tmp2, sizeof(tmp2), tmp);

		if (a->Discard == false && a->Active == false)
		{
			ico = ICO_PASS_DISABLE;
		}
		else if (a->Discard == false && a->Active)
		{
			ico = ICO_PASS;
		}
		else if (a->Discard && a->Active == false)
		{
			ico = ICO_DISCARD_DISABLE;
		}
		else
		{
			ico = ICO_DISCARD;
		}

		UniToStru(tmp3, a->Id);

		LvInsertAdd(b, ico, (void *)a, 6,
			tmp3,
			a->Discard ? _UU("SM_ACCESS_DISCARD") : _UU("SM_ACCESS_PASS"),
			a->Active ? _UU("SM_ACCESS_ENABLE") : _UU("SM_ACCESS_DISABLE"),
			tmp1,
			a->Note,
			tmp2);
	}

	LvInsertEnd(b, hWnd, L_ACCESS_LIST);
	LvSortEx(hWnd, L_ACCESS_LIST, 0, false, true);

	SmAccessListUpdate(hWnd, s);
}

// Access List dialog procedure
UINT SmAccessListProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_ACCESS_LIST *s = (SM_ACCESS_LIST *)param;
	NMHDR *n;
	ACCESS *a;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmAccessListInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_ADD:
			// Add (IPv4)
			if (SmAddAccess(hWnd, s, false))
			{
				SmAccessListRefresh(hWnd, s);
			}
			break;

		case B_ADD_V6:
			// Add (IPv6)
			if (SmAddAccess(hWnd, s, true))
			{
				SmAccessListRefresh(hWnd, s);
			}
			break;

		case IDOK:
			// Edit
			a = LvGetParam(hWnd, L_ACCESS_LIST, LvGetSelected(hWnd, L_ACCESS_LIST));
			if (a != NULL)
			{
				if (SmEditAccess(hWnd, s, a))
				{
					SmAccessListRefresh(hWnd, s);
				}
			}
			break;

		case B_CLONE:
			// Create by cloning
			a = LvGetParam(hWnd, L_ACCESS_LIST, LvGetSelected(hWnd, L_ACCESS_LIST));
			if (a != NULL)
			{
				if (SmCloneAccess(hWnd, s, a))
				{
					SmAccessListRefresh(hWnd, s);
				}
			}
			break;

		case B_ENABLE:
			a = LvGetParam(hWnd, L_ACCESS_LIST, LvGetSelected(hWnd, L_ACCESS_LIST));
			if (a != NULL)
			{
				a->Active = true;
				SmAccessListRefresh(hWnd, s);
			}
			break;

		case B_DISABLE:
			a = LvGetParam(hWnd, L_ACCESS_LIST, LvGetSelected(hWnd, L_ACCESS_LIST));
			if (a != NULL)
			{
				a->Active = false;
				SmAccessListRefresh(hWnd, s);
			}
			break;

		case B_DELETE:
			// Delete
			a = LvGetParam(hWnd, L_ACCESS_LIST, LvGetSelected(hWnd, L_ACCESS_LIST));
			if (a != NULL)
			{
				UINT i;
				if (IsInList(s->AccessList, a))
				{
					Delete(s->AccessList, a);
					Free(a);
					// Reassign the ID
					for (i = 0;i < LIST_NUM(s->AccessList);i++)
					{
						ACCESS *a = LIST_DATA(s->AccessList, i);
						a->Id = (i + 1);
					}
					SmAccessListRefresh(hWnd, s);
				}
			}
			break;

		case B_SAVE:
			// Save
			{
				UINT i;
				bool ok;
				// Save the access list
				RPC_ENUM_ACCESS_LIST t;
				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
				t.NumAccess = LIST_NUM(s->AccessList);
				t.Accesses = ZeroMalloc(sizeof(ACCESS) * t.NumAccess);
				for (i = 0;i < LIST_NUM(s->AccessList);i++)
				{
					ACCESS *access = LIST_DATA(s->AccessList, i);
					Copy(&t.Accesses[i], access, sizeof(ACCESS));
				}

				ok = CALL(hWnd, ScSetAccessList(s->Rpc, &t));
				FreeRpcEnumAccessList(&t);
				if (ok)
				{
					EndDialog(hWnd, true);
				}
			}
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_ACCESS_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmAccessListUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_ACCESS_LIST);

	return 0;
}


// Access List dialog
void SmAccessListDlg(HWND hWnd, SM_HUB *s)
{
	SM_ACCESS_LIST a;
	UINT i;
	RPC_ENUM_ACCESS_LIST t;
	bool ret;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));
	a.Hub = s;
	a.Rpc = s->Rpc;

	// Get the access list
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	if (CALL(hWnd, ScEnumAccess(s->Rpc, &t)) == false)
	{
		return;
	}

	a.AccessList = NewListFast(CmpAccessList);
	// Add to the list
	for (i = 0;i < t.NumAccess;i++)
	{
		ACCESS *access = ZeroMalloc(sizeof(ACCESS));
		Copy(access, &t.Accesses[i], sizeof(ACCESS));

		Add(a.AccessList, access);
	}

	// Sort
	Sort(a.AccessList);
	FreeRpcEnumAccessList(&t);

	// Show the dialog
	ret = Dialog(hWnd, D_SM_ACCESS_LIST, SmAccessListProc, &a);

	for (i = 0;i < LIST_NUM(a.AccessList);i++)
	{
		ACCESS *access = LIST_DATA(a.AccessList, i);
		Free(access);
	}
	ReleaseList(a.AccessList);
}

// Initialize
void SmEditGroupDlgInit(HWND hWnd, SM_EDIT_GROUP *g)
{
	RPC_SET_GROUP *group;
	LVB *b;
	// Validate arguments
	if (hWnd == NULL || g == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_GROUP);

	group = &g->SetGroup;

	if (g->EditMode == false)
	{
		SetText(hWnd, 0, _UU("SM_EDIT_GROUP_CAPTION_1"));
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("SM_EDIT_GROUP_CAPTION_2"), group->Name);
		SetText(hWnd, 0, tmp);
	}

	SetTextA(hWnd, E_GROUPNAME, group->Name);
	SetText(hWnd, E_REALNAME, group->Realname);
	SetText(hWnd, E_NOTE, group->Note);

	g->Inited = true;

	if (g->EditMode == false)
	{
		Disable(hWnd, L_STATUS);
	}
	else
	{
		LvInit(hWnd, L_STATUS);
		LvInsertColumn(hWnd, L_STATUS, 0, _UU("SM_STATUS_COLUMN_1"), 0);
		LvInsertColumn(hWnd, L_STATUS, 1, _UU("SM_STATUS_COLUMN_2"), 0);
		LvSetStyle(hWnd, L_STATUS, LVS_EX_GRIDLINES);

		b = LvInsertStart();

		SmInsertTrafficInfo(b, &group->Traffic);

		LvInsertEnd(b, hWnd, L_STATUS);

		LvAutoSize(hWnd, L_STATUS);
	}

	Check(hWnd, R_POLICY, group->Policy != NULL);

	if (g->EditMode)
	{
		Disable(hWnd, E_GROUPNAME);
		FocusEx(hWnd, E_REALNAME);
	}

	SmEditGroupDlgUpdate(hWnd, g);
}

// Update
void SmEditGroupDlgUpdate(HWND hWnd, SM_EDIT_GROUP *g)
{
	bool ok = true;
	RPC_SET_GROUP *group;
	// Validate arguments
	if (hWnd == NULL || g == NULL)
	{
		return;
	}

	if (g->Inited == false)
	{
		return;
	}

	group = &g->SetGroup;

	GetTxtA(hWnd, E_GROUPNAME, group->Name, sizeof(group->Name));
	Trim(group->Name);

	if (IsUserName(group->Name) == false)
	{
		ok = false;
	}

	GetTxt(hWnd, E_REALNAME, group->Realname, sizeof(group->Realname));
	UniTrim(group->Realname);

	GetTxt(hWnd, E_NOTE, group->Note, sizeof(group->Note));
	UniTrim(group->Note);

	SetEnable(hWnd, B_POLICY, IsChecked(hWnd, R_POLICY));

	if (IsChecked(hWnd, R_POLICY))
	{
		if (group->Policy == NULL)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// OK
void SmEditGroupDlgOnOk(HWND hWnd, SM_EDIT_GROUP *g)
{
	RPC_SET_GROUP *group;
	RPC_SET_GROUP t;
	// Validate arguments
	if (hWnd == NULL || g == NULL)
	{
		return;
	}

	SmEditGroupDlgUpdate(hWnd, g);

	group = &g->SetGroup;

	if (IsChecked(hWnd, R_POLICY) == false)
	{
		if (group->Policy != NULL)
		{
			Free(group->Policy);
			group->Policy = NULL;
		}
	}

	Zero(&t, sizeof(t));
	Copy(&t, group, sizeof(RPC_SET_GROUP));

	t.Policy = ClonePolicy(group->Policy);

	if (g->EditMode == false)
	{
		if (CALL(hWnd, ScCreateGroup(g->Rpc, &t)) == false)
		{
			FocusEx(hWnd, E_GROUPNAME);
			return;
		}
	}
	else
	{
		if (CALL(hWnd, ScSetGroup(g->Rpc, &t)) == false)
		{
			return;
		}
	}

	FreeRpcSetGroup(&t);

	if (g->EditMode == false)
	{
		MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("SM_GROUP_CREATED"), group->Name);
	}

	EndDialog(hWnd, true);
}

// Group editing dialog procedure
UINT SmEditGroupDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_GROUP *g = (SM_EDIT_GROUP *)param;
	wchar_t tmp[MAX_SIZE];
	NMHDR *n;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmEditGroupDlgInit(hWnd, g);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_GROUPNAME:
		case E_REALNAME:
		case E_NOTE:
		case R_POLICY:
			SmEditGroupDlgUpdate(hWnd, g);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// [OK] button
			SmEditGroupDlgOnOk(hWnd, g);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;

		case R_POLICY:
			if (IsChecked(hWnd, R_POLICY))
			{
				Focus(hWnd, B_POLICY);
			}
			break;

		case B_POLICY:
			// Security policy
			UniFormat(tmp, sizeof(tmp), _UU("SM_GROUP_POLICY_CAPTION"), g->SetGroup.Name);
			if (g->SetGroup.Policy == NULL)
			{
				POLICY *p = ClonePolicy(GetDefaultPolicy());
				if (SmPolicyDlgEx2(hWnd, p, tmp, false, g->p->PolicyVer))
				{
					g->SetGroup.Policy = p;
					SmEditGroupDlgUpdate(hWnd, g);
				}
				else
				{
					Free(p);
				}
			}
			else
			{
				SmPolicyDlgEx2(hWnd, g->SetGroup.Policy, tmp, false, g->p->PolicyVer);
			}
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_STATUS:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmEditGroupDlgUpdate(hWnd, g);
				break;
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

// Group editing dialog
bool SmEditGroupDlg(HWND hWnd, SM_GROUP *s, char *name)
{
	SM_EDIT_GROUP g;
	RPC_SET_GROUP *group;
	bool ret;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&g, sizeof(g));
	g.EditMode = true;
	g.Hub = s->Hub;
	g.p = s->p;
	g.Rpc = s->Rpc;

	group = &g.SetGroup;

	StrCpy(group->Name, sizeof(group->Name), name);
	StrCpy(group->HubName, sizeof(group->HubName), s->Hub->HubName);

	if (CALL(hWnd, ScGetGroup(s->Rpc, group)) == false)
	{
		return false;
	}

	ret = Dialog(hWnd, D_SM_EDIT_GROUP, SmEditGroupDlgProc, &g);

	FreeRpcSetGroup(group);

	return ret;
}

// Group creation dialog
bool SmCreateGroupDlg(HWND hWnd, SM_GROUP *s)
{
	SM_EDIT_GROUP g;
	RPC_SET_GROUP *group;
	bool ret;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&g, sizeof(g));
	g.EditMode = false;
	g.Hub = s->Hub;
	g.p = s->p;
	g.Rpc = s->Rpc;

	group = &g.SetGroup;

	StrCpy(group->HubName, sizeof(group->HubName), s->Hub->HubName);

	ret = Dialog(hWnd, D_SM_EDIT_GROUP, SmEditGroupDlgProc, &g);

	FreeRpcSetGroup(group);

	return ret;
}

// Initialize
void SmGroupListDlgInit(HWND hWnd, SM_GROUP *s)
{
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_GROUP);

	// Initialize the column
	LvInit(hWnd, L_GROUP);
	LvInsertColumn(hWnd, L_GROUP, 0, _UU("SM_GROUPLIST_NAME"), 130);
	LvInsertColumn(hWnd, L_GROUP, 1, _UU("SM_GROUPLIST_REALNAME"), 130);
	LvInsertColumn(hWnd, L_GROUP, 2, _UU("SM_GROUPLIST_NOTE"), 170);
	LvInsertColumn(hWnd, L_GROUP, 3, _UU("SM_GROUPLIST_NUMUSERS"), 80);
	LvSetStyle(hWnd, L_GROUP, LVS_EX_GRIDLINES);

	FormatText(hWnd, S_TITLE, s->Hub->HubName);

	SmGroupListDlgRefresh(hWnd, s);

	if (s->SelectMode)
	{
		SetStyle(hWnd, L_GROUP, LVS_SINGLESEL);
	}

	if (s->SelectMode)
	{
		wchar_t tmp[MAX_SIZE];
		SetText(hWnd, IDOK, _UU("SM_SELECT_GROUP"));

		if (s->SelectedGroupName != NULL)
		{
			UINT i;
			StrToUni(tmp, sizeof(tmp), s->SelectedGroupName);
			i = LvSearchStr(hWnd, L_GROUP, 0, tmp);
			if (i != INFINITE)
			{
				LvSelect(hWnd, L_GROUP, i);
			}
		}
	}
}

// Update the controls
void SmGroupListDlgUpdate(HWND hWnd, SM_GROUP *s)
{
	bool ok = true;
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_GROUP) == false || LvIsMultiMasked(hWnd, L_GROUP))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
	SetEnable(hWnd, B_USER, ok);
	SetEnable(hWnd, B_STATUS, ok);

	if (s->SelectMode == false)
	{
		SetEnable(hWnd, B_DELETE, ok);
	}
	else
	{
		SetEnable(hWnd, B_DELETE, false);
		SetEnable(hWnd, B_USER, false);
		SetText(hWnd, IDCANCEL, _UU("SM_SELECT_NO_GROUP"));
	}
}

// Content update
void SmGroupListDlgRefresh(HWND hWnd, SM_GROUP *s)
{
	RPC_ENUM_GROUP t;
	UINT i;
	LVB *b;
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);

	if (CALL(hWnd, ScEnumGroup(s->Rpc, &t)) == false)
	{
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumGroup;i++)
	{
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		RPC_ENUM_GROUP_ITEM *e = &t.Groups[i];

		StrToUni(tmp1, sizeof(tmp1), e->Name);
		UniToStru(tmp2, e->NumUsers);

		LvInsertAdd(b, e->DenyAccess == false ? ICO_GROUP : ICO_GROUP_DENY,
			NULL, 4, tmp1, e->Realname, e->Note, tmp2);
	}

	LvInsertEnd(b, hWnd, L_GROUP);

	SmGroupListDlgUpdate(hWnd, s);

	FreeRpcEnumGroup(&t);
}

// Group List dialog procedure
UINT SmGroupListDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_GROUP *s = (SM_GROUP *)param;
	NMHDR *n;
	wchar_t *tmp;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmGroupListDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_CREATE:
			// Create new
			if (SmCreateGroupDlg(hWnd, s))
			{
				SmGroupListDlgRefresh(hWnd, s);
			}
			break;

		case IDOK:
			// Edit
			tmp = LvGetSelectedStr(hWnd, L_GROUP, 0);
			if (tmp != NULL)
			{
				char name[MAX_SIZE];
				UniToStr(name, sizeof(name), tmp);

				if (s->SelectMode == false)
				{
					if (SmEditGroupDlg(hWnd, s, name))
					{
						SmGroupListDlgRefresh(hWnd, s);
					}
				}
				else
				{
					s->SelectedGroupName = CopyStr(name);
					EndDialog(hWnd, true);
				}
				Free(tmp);
			}
			break;

		case B_DELETE:
			// Delete
			tmp = LvGetSelectedStr(hWnd, L_GROUP, 0);
			if (tmp != NULL)
			{
				char name[MAX_SIZE];
				RPC_DELETE_USER t;
				UniToStr(name, sizeof(name), tmp);

				if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
					_UU("SM_GROUP_DELETE_MSG"), name) == IDYES)
				{
					Zero(&t, sizeof(t));
					StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
					StrCpy(t.Name, sizeof(t.Name), name);

					if (CALL(hWnd, ScDeleteGroup(s->Rpc, &t)))
					{
						SmGroupListDlgRefresh(hWnd, s);
					}
				}

				Free(tmp);
			}
			break;

		case B_USER:
			// Member List
			tmp = LvGetSelectedStr(hWnd, L_GROUP, 0);
			if (tmp != NULL)
			{
				char name[MAX_SIZE];
				UniToStr(name, sizeof(name), tmp);
				SmUserListDlgEx(hWnd, s->Hub, name, false);
				Free(tmp);
			}
			break;

		case B_REFRESH:
			// Update to the latest information
			SmGroupListDlgRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_GROUP:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmGroupListDlgUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_GROUP);

	return 0;
}

// Group List dialog (selection mode)
char *SmSelectGroupDlg(HWND hWnd, SM_HUB *s, char *default_name)
{
	SM_GROUP g;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return NULL;
	}

	Zero(&g, sizeof(g));
	g.Hub = s;
	g.p = s->p;
	g.Rpc = s->Rpc;
	g.SelectMode = true;
	g.SelectedGroupName = default_name;

	if (Dialog(hWnd, D_SM_GROUP, SmGroupListDlgProc, &g) == false)
	{
		return NULL;
	}

	return g.SelectedGroupName;
}

// Group List dialog
void SmGroupListDlg(HWND hWnd, SM_HUB *s)
{
	SM_GROUP g;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&g, sizeof(g));
	g.Hub = s;
	g.p = s->p;
	g.Rpc = s->Rpc;
	g.SelectMode = false;

	Dialog(hWnd, D_SM_GROUP, SmGroupListDlgProc, &g);
}

// Update the user information
bool SmRefreshUserInfo(HWND hWnd, SM_SERVER *s, void *param)
{
	RPC_SET_USER t;
	SM_USER_INFO *p = (SM_USER_INFO *)param;
	LVB *b;
	wchar_t tmp[MAX_SIZE];
	char *username;

	// Validate arguments
	if (hWnd == NULL || s == NULL || param == NULL)
	{
		return false;
	}

	username = p->Username;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), p->Hub->HubName);
	StrCpy(t.Name, sizeof(t.Name), username);

	if (CALL(hWnd, ScGetUser(s->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	StrToUni(tmp, sizeof(tmp), t.Name);
	LvInsertAdd(b, ICO_USER, NULL, 2, _UU("SM_USERINFO_NAME"), tmp);

	if (StrLen(t.GroupName) != 0)
	{
		StrToUni(tmp, sizeof(tmp), t.GroupName);
		LvInsertAdd(b, ICO_GROUP, NULL, 2, _UU("SM_USERINFO_GROUP"), tmp);
	}

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime), NULL);
	LvInsertAdd(b, ICO_USER_ADMIN, NULL, 2, _UU("SM_USERINFO_CREATE"), tmp);

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.UpdatedTime), NULL);
	LvInsertAdd(b, ICO_USER_ADMIN, NULL, 2, _UU("SM_USERINFO_UPDATE"), tmp);

	if (t.ExpireTime != 0)
	{
		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ExpireTime), NULL);
		LvInsertAdd(b, ICO_WARNING, NULL, 2, _UU("SM_USERINFO_EXPIRE"), tmp);
	}

	SmInsertTrafficInfo(b, &t.Traffic);

	UniToStru(tmp, t.NumLogin);
	LvInsertAdd(b, ICO_LINK, NULL, 2, _UU("SM_USERINFO_NUMLOGIN"), tmp);

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcSetUser(&t);

	return true;
}

// Initialize
void SmPolicyDlgInit(HWND hWnd, SM_POLICY *s)
{
	CM_POLICY cp;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_MACHINE);
	SetText(hWnd, 0, s->Caption);
	SetText(hWnd, S_TITLE, s->Caption);
	DlgFont(hWnd, S_BOLD, 10, true);
	DlgFont(hWnd, S_BOLD2, 10, true);

	DlgFont(hWnd, S_POLICY_TITLE, 11, false);
	DlgFont(hWnd, E_POLICY_DESCRIPTION, 10, false);

	Zero(&cp, sizeof(cp));
	cp.Policy = s->Policy;
	cp.Extension = true;

	LvInit(hWnd, L_POLICY);
	LvInsertColumn(hWnd, L_POLICY, 0, _UU("POL_TITLE_STR"), 250);
	LvInsertColumn(hWnd, L_POLICY, 1, _UU("POL_VALUE_STR"), 150);
	LvSetStyle(hWnd, L_POLICY, LVS_EX_GRIDLINES);

	CmPolicyDlgPrintEx2(hWnd, &cp, s->CascadeMode, s->Ver);

	LvSelect(hWnd, L_POLICY, 0);

	s->Inited = true;
	SmPolicyDlgUpdate(hWnd, s);
}

// Update
void SmPolicyDlgUpdate(HWND hWnd, SM_POLICY *s)
{
	bool ok = true;
	bool value_changed = false;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (s->Inited == false)
	{
		return;
	}

	i = LvGetSelected(hWnd, L_POLICY);
	if (i != INFINITE)
	{
		i = (UINT)LvGetParam(hWnd, L_POLICY, i);
	}
	if (i == INFINITE || i >= NUM_POLICY_ITEM)
	{
		SetText(hWnd, S_POLICY_TITLE, _UU("SM_POLICY_INIT_TITLE"));
		SetText(hWnd, E_POLICY_DESCRIPTION, L"");
		Disable(hWnd, S_POLICY_TITLE);
		Disable(hWnd, S_BOLD);
		Hide(hWnd, S_BOLD2);
		Hide(hWnd, R_ENABLE);
		Hide(hWnd, R_DISABLE);
		Hide(hWnd, R_DEFINE);
		Hide(hWnd, E_VALUE);
		Hide(hWnd, S_TANI);
		Hide(hWnd, S_LIMIT);
	}
	else
	{
		POLICY_ITEM *item = &policy_item[i];
		bool changed = false;
		wchar_t *tmp = GetText(hWnd, S_POLICY_TITLE);
		if (UniStrCmp(tmp, GetPolicyTitle(i)) != 0)
		{
			changed = true;
		}
		Free(tmp);
		SetText(hWnd, S_POLICY_TITLE, GetPolicyTitle(i));
		SetText(hWnd, E_POLICY_DESCRIPTION, GetPolicyDescription(i));
		Enable(hWnd, S_POLICY_TITLE);
		Enable(hWnd, S_BOLD);
		Show(hWnd, S_BOLD2);

		if (item->TypeInt == false)
		{
			Show(hWnd, R_ENABLE);
			Show(hWnd, R_DISABLE);
			Hide(hWnd, R_DEFINE);
			Hide(hWnd, E_VALUE);
			Hide(hWnd, S_TANI);
			Hide(hWnd, S_LIMIT);

			if (changed)
			{
				if (POLICY_BOOL(s->Policy, i))
				{
					Check(hWnd, R_ENABLE, true);
					Check(hWnd, R_DISABLE, false);
				}
				else
				{
					Check(hWnd, R_ENABLE, false);
					Check(hWnd, R_DISABLE, true);
				}
			}

			if ((!(POLICY_BOOL(s->Policy, i))) != (!(IsChecked(hWnd, R_ENABLE))))
			{
				POLICY_BOOL(s->Policy, i) = IsChecked(hWnd, R_ENABLE);
				value_changed = true;
			}
		}
		else
		{
			wchar_t tmp[MAX_SIZE];
			UINT value;
			if (item->AllowZero)
			{
				if (changed)
				{
					Check(hWnd, R_DEFINE, POLICY_INT(s->Policy, i) != 0);
					Enable(hWnd, R_DEFINE);
					SetIntEx(hWnd, E_VALUE, POLICY_INT(s->Policy, i));
				}

				SetEnable(hWnd, E_VALUE, IsChecked(hWnd, R_DEFINE));
				SetEnable(hWnd, S_TANI, IsChecked(hWnd, R_DEFINE));
				SetEnable(hWnd, S_LIMIT, IsChecked(hWnd, R_DEFINE));
			}
			else
			{
				if (changed)
				{
					Check(hWnd, R_DEFINE, true);
					Disable(hWnd, R_DEFINE);
					SetInt(hWnd, E_VALUE, POLICY_INT(s->Policy, i));
				}

				SetEnable(hWnd, E_VALUE, IsChecked(hWnd, R_DEFINE));
				SetEnable(hWnd, S_TANI, IsChecked(hWnd, R_DEFINE));
				SetEnable(hWnd, S_LIMIT, IsChecked(hWnd, R_DEFINE));
			}

			UniReplaceStrEx(tmp, sizeof(tmp), _UU(policy_item[i].FormatStr),
				L"%u ", L"", false);
			UniReplaceStrEx(tmp, sizeof(tmp), tmp,
				L"%u", L"", false);

			SetText(hWnd, S_TANI, tmp);

			UniFormat(tmp, sizeof(tmp), _UU("SM_LIMIT_STR"), policy_item[i].MinValue, policy_item[i].MaxValue);
			SetText(hWnd, S_LIMIT, tmp);

			Hide(hWnd, R_ENABLE);
			Hide(hWnd, R_DISABLE);
			Show(hWnd, E_VALUE);
			Show(hWnd, R_DEFINE);
			Show(hWnd, S_TANI);
			Show(hWnd, S_LIMIT);

			value = GetInt(hWnd, E_VALUE);

			if (item->AllowZero && (IsChecked(hWnd, R_DEFINE) == false))
			{
				value = 0;
			}
			else
			{
				if (value < policy_item[i].MinValue || value > policy_item[i].MaxValue)
				{
					ok = false;
				}
			}

			if (ok)
			{
				if (POLICY_INT(s->Policy, i) != value)
				{
					POLICY_INT(s->Policy, i) = value;
					value_changed = true;
				}
			}
		}
	}

	SetEnable(hWnd, IDOK, ok);
	SetEnable(hWnd, L_POLICY, ok);

	if (value_changed)
	{
		CM_POLICY cp;
		Zero(&cp, sizeof(cp));
		cp.Policy = s->Policy;
		cp.Extension = true;

		CmPolicyDlgPrintEx(hWnd, &cp, s->CascadeMode);
	}
}

// Confirmation
void SmPolicyDlgOk(HWND hWnd, SM_POLICY *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	EndDialog(hWnd, true);
}

// Policy dialog box procedure
UINT SmPolicyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_POLICY *s = (SM_POLICY *)param;
	NMHDR *n;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmPolicyDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_DEFINE:
		case R_ENABLE:
		case R_DISABLE:
		case E_VALUE:
			SmPolicyDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// [OK] button
			SmPolicyDlgOk(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;

		case R_DEFINE:
			if (IsChecked(hWnd, R_DEFINE))
			{
				FocusEx(hWnd, E_VALUE);
			}
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
				SmPolicyDlgUpdate(hWnd, s);
				break;
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

// Show Policies dialog box
bool SmPolicyDlg(HWND hWnd, POLICY *p, wchar_t *caption)
{
	return SmPolicyDlgEx(hWnd, p, caption, false);
}
bool SmPolicyDlgEx(HWND hWnd, POLICY *p, wchar_t *caption, bool cascade_mode)
{
	return SmPolicyDlgEx2(hWnd, p, caption, cascade_mode, POLICY_CURRENT_VERSION);
}
bool SmPolicyDlgEx2(HWND hWnd, POLICY *p, wchar_t *caption, bool cascade_mode, UINT ver)
{
	SM_POLICY s;
	bool ret;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	if (caption == NULL)
	{
		caption = _UU("SM_POLICY_DEF_CAPTION");
	}

	Zero(&s, sizeof(s));
	s.Caption = caption;
	s.Policy = ClonePolicy(p);
	s.CascadeMode = cascade_mode;
	s.Ver = ver;

	ret = Dialog(hWnd, D_SM_POLICY, SmPolicyDlgProc, &s);

	if (ret)
	{
		Copy(p, s.Policy, sizeof(POLICY));
	}

	Free(s.Policy);

	return ret;
}

// Edit user confirmed
void SmEditUserDlgOk(HWND hWnd, SM_EDIT_USER *s)
{
	RPC_SET_USER t;
	RPC_SET_USER *u;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SmEditUserDlgUpdate(hWnd, s);

	Zero(&t, sizeof(t));
	u = &s->SetUser;

	StrCpy(t.HubName, sizeof(t.HubName), u->HubName);
	StrCpy(t.Name, sizeof(t.Name), u->Name);
	StrCpy(t.GroupName, sizeof(t.GroupName), u->GroupName);
	UniStrCpy(t.Realname, sizeof(t.Realname), u->Realname);
	UniStrCpy(t.Note, sizeof(t.Note), u->Note);
	t.ExpireTime = u->ExpireTime;
	t.AuthType = u->AuthType;
	t.AuthData = CopyAuthData(u->AuthData, t.AuthType);

	if (IsChecked(hWnd, R_POLICY))
	{
		t.Policy = ClonePolicy(u->Policy);
	}
	else
	{
		t.Policy = NULL;
	}

	if (s->EditMode == false)
	{
		if (CALL(hWnd, ScCreateUser(s->Rpc, &t)) == false)
		{
			FocusEx(hWnd, E_USERNAME);
			return;
		}
		FreeRpcSetUser(&t);

		MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("SM_USER_CREATE_OK"), u->Name);
	}
	else
	{
		if (CALL(hWnd, ScSetUser(s->Rpc, &t)) == false)
		{
			FocusEx(hWnd, E_REALNAME);
			return;
		}
		FreeRpcSetUser(&t);
	}

	EndDialog(hWnd, true);
}

// Edit user initialization
void SmEditUserDlgInit(HWND hWnd, SM_EDIT_USER *s)
{
	RPC_SET_USER *u;
	wchar_t tmp[MAX_SIZE];
	UINT i;
	UINT icons[6] = {ICO_PASS, ICO_KEY, ICO_CERT, ICO_SERVER_CERT,
		ICO_TOWER, ICO_LINK};
	RECT rect;

	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_USER);

	u = &s->SetUser;

	// Initialize the column
	LvInit(hWnd, L_AUTH);
	LvSetStyle(hWnd, L_AUTH, LVS_EX_GRIDLINES);

	GetClientRect(DlgItem(hWnd, L_AUTH), &rect);
	LvInsertColumn(hWnd, L_AUTH, 0, L"Name", rect.right - rect.left);

	for (i = 0;i < 6;i++)
	{
		LvInsert(hWnd, L_AUTH, icons[i], (void *)i, 1, SmGetAuthTypeStr(i));
	}

	// User name, etc.
	SetTextA(hWnd, E_USERNAME, u->Name);
	SetText(hWnd, E_REALNAME, u->Realname);
	SetText(hWnd, E_NOTE, u->Note);


	// Expiration date
	if (u->ExpireTime == 0)
	{
		SYSTEMTIME st;
		Check(hWnd, R_EXPIRES, false);
		GetLocalTime(&st);
		UINT64ToSystem(&st, SystemToUINT64(&st) + (60 * 60 * 24 * 1000));
		st.wHour = st.wMinute = st.wSecond = st.wMilliseconds = 0;
		DateTime_SetSystemtime(DlgItem(hWnd, E_EXPIRES_DATE), GDT_VALID, &st);
		DateTime_SetSystemtime(DlgItem(hWnd, E_EXPIRES_TIME), GDT_VALID, &st);
	}
	else
	{
		SYSTEMTIME st;
		UINT64ToSystem(&st, SystemToLocal64(u->ExpireTime));
		Check(hWnd, R_EXPIRES, true);
		DateTime_SetSystemtime(DlgItem(hWnd, E_EXPIRES_DATE), GDT_VALID, &st);
		DateTime_SetSystemtime(DlgItem(hWnd, E_EXPIRES_TIME), GDT_VALID, &st);
	}

	if (GetCurrentOsLangId() == SE_LANG_JAPANESE || GetCurrentOsLangId() == SE_LANG_CHINESE_ZH)
	{
		SetStyle(hWnd, E_EXPIRES_DATE, DTS_LONGDATEFORMAT);
	}
	else
	{
		SetStyle(hWnd, E_EXPIRES_DATE, DTS_SHORTDATEFORMAT);
	}

	SetWindowLong(DlgItem(hWnd, E_EXPIRES_TIME), GWL_STYLE, WS_CHILDWINDOW | WS_VISIBLE | WS_TABSTOP | DTS_RIGHTALIGN | DTS_TIMEFORMAT | DTS_UPDOWN);

	// Group name
	SetTextA(hWnd, E_GROUP, u->GroupName);

	// Authentication method
	LvSelect(hWnd, L_AUTH, u->AuthType);

	SetText(hWnd, S_CERT_INFO, _UU("SM_EDIT_USER_CERT_INFO"));

	switch (u->AuthType)
	{
	case AUTHTYPE_PASSWORD:
		if (s->EditMode)
		{
			SetTextA(hWnd, E_PASSWORD1, HIDDEN_PASSWORD);
			SetTextA(hWnd, E_PASSWORD2, HIDDEN_PASSWORD);
		}
		break;

	case AUTHTYPE_USERCERT:
		SmGetCertInfoStr(tmp, sizeof(tmp), ((AUTHUSERCERT *)u->AuthData)->UserX);
		break;

	case AUTHTYPE_ROOTCERT:
		if (u->AuthData != NULL)
		{
			AUTHROOTCERT *c = (AUTHROOTCERT *)u->AuthData;
			if (c->CommonName != NULL && UniStrLen(c->CommonName) != 0)
			{
				Check(hWnd, R_CN, true);
				SetText(hWnd, E_CN, c->CommonName);
			}
			else
			{
				Check(hWnd, R_CN, false);
			}
			if (c->Serial != NULL && c->Serial->size != 0)
			{
				X_SERIAL *s = c->Serial;
				char *tmp;
				UINT tmp_size = s->size * 3 + 1;
				tmp = ZeroMalloc(tmp_size);
				BinToStrEx(tmp, tmp_size, s->data, s->size);
				SetTextA(hWnd, E_SERIAL, tmp);
				Free(tmp);
				Check(hWnd, R_SERIAL, true);
			}
			else
			{
				Check(hWnd, R_SERIAL, false);
			}
		}
		break;

	case AUTHTYPE_RADIUS:
		if (u->AuthData != NULL)
		{
			AUTHRADIUS *r = (AUTHRADIUS *)u->AuthData;
			if (UniStrLen(r->RadiusUsername) != 0)
			{
				Check(hWnd, R_SET_RADIUS_USERNAME, true);
				SetText(hWnd, E_RADIUS_USERNAME, r->RadiusUsername);
			}
			else
			{
				Check(hWnd, R_SET_RADIUS_USERNAME, false);
			}
		}
		break;

	case AUTHTYPE_NT:
		if (u->AuthData != NULL)
		{
			AUTHNT *n = (AUTHNT *)u->AuthData;
			if (UniStrLen(n->NtUsername) != 0)
			{
				Check(hWnd, R_SET_RADIUS_USERNAME, true);
				SetText(hWnd, E_RADIUS_USERNAME, n->NtUsername);
			}
			else
			{
				Check(hWnd, R_SET_RADIUS_USERNAME, false);
			}
		}
		break;
	}

	if (u->Policy != NULL)
	{
		Check(hWnd, R_POLICY, true);
	}

	s->Inited = true;

	SmEditUserDlgUpdate(hWnd, s);

	if (s->EditMode == false)
	{
		Focus(hWnd, E_USERNAME);
		SetText(hWnd, 0, _UU("SM_EDIT_USER_CAPTION_1"));
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("SM_EDIT_USER_CAPTION_2"), s->SetUser.Name);
		SetText(hWnd, 0, tmp);

		Disable(hWnd, E_USERNAME);
		FocusEx(hWnd, E_REALNAME);
	}

	SetShow(hWnd, S_HINT, (s->EditMode ? false : true));
}

// User edit control update
void SmEditUserDlgUpdate(HWND hWnd, SM_EDIT_USER *s)
{
	RPC_SET_USER *u;
	bool ok = true;
	UINT old_authtype;
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	bool authtype_changed = false;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (s->Inited == false)
	{
		return;
	}

	u = &s->SetUser;

	// User name
	GetTxtA(hWnd, E_USERNAME, u->Name, sizeof(u->Name));
	Trim(u->Name);
	if (StrLen(u->Name) == 0 || IsUserName(u->Name) == false)
	{
		ok = false;
	}

	// Real name
	GetTxt(hWnd, E_REALNAME, u->Realname, sizeof(u->Realname));
	UniTrim(u->Realname);

	// Note
	GetTxt(hWnd, E_NOTE, u->Note, sizeof(u->Note));
	UniTrim(u->Realname);

	// Group
	GetTxtA(hWnd, E_GROUP, u->GroupName, sizeof(u->GroupName));
	Trim(u->GroupName);

	// Expiration date
	if (IsChecked(hWnd, R_EXPIRES) == false)
	{
		u->ExpireTime = 0;
		Disable(hWnd, E_EXPIRES_DATE);
		Disable(hWnd, E_EXPIRES_TIME);
	}
	else
	{
		SYSTEMTIME st1, st2;
		Enable(hWnd, E_EXPIRES_DATE);
		Enable(hWnd, E_EXPIRES_TIME);
		DateTime_GetSystemtime(DlgItem(hWnd, E_EXPIRES_DATE), &st1);
		DateTime_GetSystemtime(DlgItem(hWnd, E_EXPIRES_TIME), &st2);
		st1.wHour = st2.wHour;
		st1.wMinute = st2.wMinute;
		st1.wSecond = st2.wSecond;
		st1.wMilliseconds = st2.wMilliseconds;
		u->ExpireTime = LocalToSystem64(SystemToUINT64(&st1));
	}

	// Authentication method
	old_authtype = u->AuthType;
	u->AuthType = LvGetSelected(hWnd, L_AUTH);

	if (StrCmpi(u->Name, "*") == 0)
	{
		if (u->AuthType != AUTHTYPE_RADIUS && u->AuthType != AUTHTYPE_NT)
		{
			ok = false;
		}
	}

	if (u->AuthType == INFINITE)
	{
		ok = false;
		u->AuthType = 0;
	}
	if (old_authtype != u->AuthType)
	{
		authtype_changed = true;
	}

	if (authtype_changed)
	{
		FreeAuthData(old_authtype, u->AuthData);
		u->AuthData = NULL;
		switch (u->AuthType)
		{
		case AUTHTYPE_ANONYMOUS:
			u->AuthData = NULL;
			break;

		case AUTHTYPE_PASSWORD:
			u->AuthData = NewPasswordAuthData("", "");
			GetTxtA(hWnd, E_PASSWORD1, tmp1, sizeof(tmp1));
			if (StrCmp(tmp1, HIDDEN_PASSWORD) == 0)
			{
				SetTextA(hWnd, E_PASSWORD1, "");
			}
			GetTxtA(hWnd, E_PASSWORD2, tmp2, sizeof(tmp2));
			if (StrCmp(tmp2, HIDDEN_PASSWORD) == 0)
			{
				SetTextA(hWnd, E_PASSWORD2, "");
			}
			break;

		case AUTHTYPE_USERCERT:
			u->AuthData = NewUserCertAuthData(NULL);
			SetText(hWnd, S_CERT_INFO, _UU("SM_EDIT_USER_CERT_INFO"));
			break;

		case AUTHTYPE_ROOTCERT:
			u->AuthData = NewRootCertAuthData(NULL, NULL);
			break;

		case AUTHTYPE_NT:
			u->AuthData = NewNTAuthData(L"");
			break;

		case AUTHTYPE_RADIUS:
			u->AuthData = NewRadiusAuthData(L"");
			break;
		}
	}

	SetEnable(hWnd, S_RADIUS_3, (u->AuthType == AUTHTYPE_RADIUS) || (u->AuthType == AUTHTYPE_NT));
	SetEnable(hWnd, R_SET_RADIUS_USERNAME, (u->AuthType == AUTHTYPE_RADIUS) || (u->AuthType == AUTHTYPE_NT));
	SetEnable(hWnd, S_RADIUS_1, (u->AuthType == AUTHTYPE_RADIUS) || (u->AuthType == AUTHTYPE_NT));

	if (StrCmp(u->Name, "*") == 0)
	{
		Check(hWnd, R_SET_RADIUS_USERNAME, false);
		Disable(hWnd, R_SET_RADIUS_USERNAME);
	}

	if ((u->AuthType == AUTHTYPE_RADIUS) || (u->AuthType == AUTHTYPE_NT))
	{
		SetEnable(hWnd, E_RADIUS_USERNAME, IsChecked(hWnd, R_SET_RADIUS_USERNAME));
		SetEnable(hWnd, S_RADIUS_2, IsChecked(hWnd, R_SET_RADIUS_USERNAME));
	}
	else
	{
		SetEnable(hWnd, E_RADIUS_USERNAME, false);
		SetEnable(hWnd, S_RADIUS_2, false);
	}

	SetEnable(hWnd, S_PASSWORD_1, u->AuthType == AUTHTYPE_PASSWORD);
	SetEnable(hWnd, S_PASSWORD_2, u->AuthType == AUTHTYPE_PASSWORD);
	SetEnable(hWnd, S_PASSWORD_3, u->AuthType == AUTHTYPE_PASSWORD);
	SetEnable(hWnd, E_PASSWORD1, u->AuthType == AUTHTYPE_PASSWORD);
	SetEnable(hWnd, E_PASSWORD2, u->AuthType == AUTHTYPE_PASSWORD);

	SetEnable(hWnd, S_USER_CERT_1, u->AuthType == AUTHTYPE_USERCERT);
	SetEnable(hWnd, S_CERT_INFO, u->AuthType == AUTHTYPE_USERCERT);
	SetEnable(hWnd, B_LOAD_CERT, u->AuthType == AUTHTYPE_USERCERT);

	if (u->AuthType == AUTHTYPE_USERCERT)
	{
		SetEnable(hWnd, B_VIEW_CERT, ((AUTHUSERCERT *)u->AuthData)->UserX != NULL);
	}
	else
	{
		SetEnable(hWnd, B_VIEW_CERT, false);
	}

	SetEnable(hWnd, S_ROOT_CERT_1, u->AuthType == AUTHTYPE_ROOTCERT);
	SetEnable(hWnd, S_ROOT_CERT_2, u->AuthType == AUTHTYPE_ROOTCERT);
	SetEnable(hWnd, S_ROOT_CERT_3, u->AuthType == AUTHTYPE_ROOTCERT);
	SetEnable(hWnd, R_CN, u->AuthType == AUTHTYPE_ROOTCERT);
	SetEnable(hWnd, R_SERIAL, u->AuthType == AUTHTYPE_ROOTCERT);

	if (u->AuthType == AUTHTYPE_ROOTCERT)
	{
		SetEnable(hWnd, E_CN, IsChecked(hWnd, R_CN));
		SetEnable(hWnd, E_SERIAL, IsChecked(hWnd, R_SERIAL));
	}
	else
	{
		Disable(hWnd, E_CN);
		Disable(hWnd, E_SERIAL);
	}

	switch (u->AuthType)
	{
	case AUTHTYPE_PASSWORD:
		GetTxtA(hWnd, E_PASSWORD1, tmp1, sizeof(tmp1));
		GetTxtA(hWnd, E_PASSWORD2, tmp2, sizeof(tmp2));
		if (StrCmp(tmp1, tmp2) != 0)
		{
			ok = false;
		}
		else
		{
			if (StrCmp(tmp1, HIDDEN_PASSWORD) != 0)
			{
				HashPassword(((AUTHPASSWORD *)u->AuthData)->HashedKey, u->Name, tmp1);
				GenerateNtPasswordHash(((AUTHPASSWORD *)u->AuthData)->NtLmSecureHash, tmp1);
			}
		}
		break;

	case AUTHTYPE_USERCERT:
		if (((AUTHUSERCERT *)u->AuthData)->UserX == NULL)
		{
			ok = false;
		}
		break;

	case AUTHTYPE_ROOTCERT:
		Free(((AUTHROOTCERT *)u->AuthData)->CommonName);
		((AUTHROOTCERT *)u->AuthData)->CommonName = NULL;
		if (IsChecked(hWnd, R_CN) && (IsEmpty(hWnd, E_CN) == false))
		{
			((AUTHROOTCERT *)u->AuthData)->CommonName = GetText(hWnd, E_CN);
			UniTrim(((AUTHROOTCERT *)u->AuthData)->CommonName);
		}
		if (IsChecked(hWnd, R_CN) && ((AUTHROOTCERT *)u->AuthData)->CommonName == NULL)
		{
			ok = false;
		}
		FreeXSerial(((AUTHROOTCERT *)u->AuthData)->Serial);
		((AUTHROOTCERT *)u->AuthData)->Serial = NULL;
		if (IsChecked(hWnd, R_SERIAL))
		{
			char *serial_str = GetTextA(hWnd, E_SERIAL);
			if (serial_str != NULL)
			{
				BUF *b = StrToBin(serial_str);
				if (b->Size >= 1)
				{
					((AUTHROOTCERT *)u->AuthData)->Serial = NewXSerial(b->Buf, b->Size);
				}
				FreeBuf(b);
				Free(serial_str);
			}
		}
		if (IsChecked(hWnd, R_SERIAL) && ((AUTHROOTCERT *)u->AuthData)->Serial == NULL)
		{
			ok = false;
		}
		break;

	case AUTHTYPE_RADIUS:
		Free(((AUTHRADIUS *)u->AuthData)->RadiusUsername);
		((AUTHRADIUS *)u->AuthData)->RadiusUsername = NULL;
		if (IsChecked(hWnd, R_SET_RADIUS_USERNAME) && (IsEmpty(hWnd, E_RADIUS_USERNAME) == false))
		{
			((AUTHRADIUS *)u->AuthData)->RadiusUsername = GetText(hWnd, E_RADIUS_USERNAME);
		}
		if (IsChecked(hWnd, R_SET_RADIUS_USERNAME) && ((AUTHRADIUS *)u->AuthData)->RadiusUsername == NULL)
		{
			ok = false;
		}
		break;

	case AUTHTYPE_NT:
		Free(((AUTHNT *)u->AuthData)->NtUsername);
		((AUTHNT *)u->AuthData)->NtUsername = NULL;
		if (IsChecked(hWnd, R_SET_RADIUS_USERNAME) && (IsEmpty(hWnd, E_RADIUS_USERNAME) == false))
		{
			((AUTHNT *)u->AuthData)->NtUsername = GetText(hWnd, E_RADIUS_USERNAME);
		}
		if (IsChecked(hWnd, R_SET_RADIUS_USERNAME) && ((AUTHNT *)u->AuthData)->NtUsername == NULL)
		{
			ok = false;
		}
		break;
	}

	SetEnable(hWnd, B_POLICY, IsChecked(hWnd, R_POLICY));
	if (IsChecked(hWnd, R_POLICY))
	{
		if (u->Policy == NULL)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, IDOK, ok);
}

// Edit User dialog procedure
UINT SmEditUserDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_USER *s = (SM_EDIT_USER *)param;
	NMHDR *n;
	POLICY *policy;
	X *x = NULL;
	wchar_t tmp[MAX_SIZE];
	char name[MAX_SIZE];
	char *ret;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmEditUserDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_USERNAME:
		case E_REALNAME:
		case E_NOTE:
		case R_EXPIRES:
		case E_EXPIRES_DATE:
		case E_EXPIRES_TIME:
		case E_GROUP:
		case L_AUTH:
		case R_SET_RADIUS_USERNAME:
		case E_RADIUS_USERNAME:
		case R_POLICY:
		case E_PASSWORD1:
		case E_PASSWORD2:
		case R_CN:
		case E_CN:
		case R_SERIAL:
		case E_SERIAL:
			SmEditUserDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// [OK] button
			SmEditUserDlgOk(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;

		case B_POLICY:
			UniFormat(tmp, sizeof(tmp), _UU("SM_EDIT_USER_POL_DLG"), s->SetUser.Name);
			// Policy
			if (s->SetUser.Policy == NULL)
			{
				policy = ClonePolicy(GetDefaultPolicy());
				if (SmPolicyDlgEx2(hWnd, policy, tmp, false, s->p->PolicyVer))
				{
					s->SetUser.Policy = policy;
					SmEditUserDlgUpdate(hWnd, s);
				}
				else
				{
					Free(policy);
				}
			}
			else
			{
				SmPolicyDlgEx2(hWnd, s->SetUser.Policy, tmp, false, s->p->PolicyVer);
			}
			break;

		case B_GROUP:
			// Browse for a Group
			GetTxtA(hWnd, E_GROUP, name, sizeof(name));
			Trim(name);
			ret = SmSelectGroupDlg(hWnd, s->Hub, StrLen(name) == 0 ? NULL : name);
			if (ret != NULL)
			{
				SetTextA(hWnd, E_GROUP, ret);
				Free(ret);
			}
			else
			{
				SetTextA(hWnd, E_GROUP, "");
			}
			FocusEx(hWnd, E_GROUP);
			break;

		case B_LOAD_CERT:
			// Specify the certificate
			if (CmLoadXFromFileOrSecureCard(hWnd, &x))
			{
UPDATE_CERT:
				if (s->SetUser.AuthType == AUTHTYPE_USERCERT)
				{
					wchar_t tmp[MAX_SIZE];
					FreeX(((AUTHUSERCERT *)s->SetUser.AuthData)->UserX);
					((AUTHUSERCERT *)s->SetUser.AuthData)->UserX = x;
					SmGetCertInfoStr(tmp, sizeof(tmp), x);
					SetText(hWnd, S_CERT_INFO, tmp);
					SmEditUserDlgUpdate(hWnd, s);
				}
				else
				{
					if (x != NULL)
					{
						FreeX(x);
						x = NULL;
					}
				}
			}
			break;

		case B_VIEW_CERT:
			// Show the certificate
			if (s->SetUser.AuthType == AUTHTYPE_USERCERT)
			{
				CertDlg(hWnd, ((AUTHUSERCERT *)s->SetUser.AuthData)->UserX, NULL, true);
			}
			break;

		case B_CREATE:
			// Create
			GetTxtA(hWnd, E_USERNAME, name, sizeof(name));
			Trim(name);
			if (SmCreateCert(hWnd, &x, NULL, false, name, false))
			{
				if (s->SetUser.AuthType != AUTHTYPE_USERCERT)
				{
					LvSelect(hWnd, L_AUTH, 2);
				}
				goto UPDATE_CERT;
			}
			break;

		case R_SET_RADIUS_USERNAME:
			if (IsChecked(hWnd, R_SET_RADIUS_USERNAME))
			{
				FocusEx(hWnd, E_RADIUS_USERNAME);
			}
			break;

		case R_EXPIRES:
			if (IsChecked(hWnd, R_EXPIRES))
			{
				Focus(hWnd, E_EXPIRES_DATE);
			}
			break;

		case R_POLICY:
			if (IsChecked(hWnd, R_POLICY))
			{
				Focus(hWnd, B_POLICY);
			}
			break;

		case R_CN:
			if (IsChecked(hWnd, R_CN))
			{
				Focus(hWnd, E_CN);
			}
			break;

		case R_SERIAL:
			if (IsChecked(hWnd, R_SERIAL))
			{
				Focus(hWnd, E_SERIAL);
			}
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_AUTH:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmEditUserDlgUpdate(hWnd, s);
				break;
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

// User editing dialog
bool SmEditUserDlg(HWND hWnd, SM_HUB *s, char *username)
{
	SM_EDIT_USER e;
	bool ret;
	// Validate arguments
	if (hWnd == NULL || s == NULL || username == NULL)
	{
		return false;
	}

	Zero(&e, sizeof(e));
	e.p = s->p;
	e.Rpc = s->Rpc;
	e.Hub = s;

	// Get the User
	StrCpy(e.SetUser.HubName, sizeof(e.SetUser.HubName), e.Hub->HubName);
	StrCpy(e.SetUser.Name, sizeof(e.SetUser.Name), username);

	if (CALL(hWnd, ScGetUser(s->Rpc, &e.SetUser)) == false)
	{
		return false;
	}

	e.EditMode = true;

	ret = Dialog(hWnd, D_SM_EDIT_USER, SmEditUserDlgProc, &e);

	FreeRpcSetUser(&e.SetUser);

	return ret;
}

// New user creation dialog
bool SmCreateUserDlg(HWND hWnd, SM_HUB *s)
{
	SM_EDIT_USER e;
	bool ret;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return false;
	}

	Zero(&e, sizeof(e));
	e.EditMode = false;
	e.p = s->p;
	e.Rpc = s->Rpc;
	e.Hub = s;

	// Set up a new user
	StrCpy(e.SetUser.HubName, sizeof(e.SetUser.HubName), e.Hub->HubName);
	e.SetUser.AuthType = CLIENT_AUTHTYPE_PASSWORD;
	e.SetUser.AuthData = NewPasswordAuthData("", "");

	ret = Dialog(hWnd, D_SM_EDIT_USER, SmEditUserDlgProc, &e);

	FreeRpcSetUser(&e.SetUser);

	return ret;
}

// Get a string of user authentication method
wchar_t *SmGetAuthTypeStr(UINT id)
{
	return GetAuthTypeStr(id);
}

// User list initialization
void SmUserListInit(HWND hWnd, SM_USER *s)
{
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_USER);

	// Initialize the column
	LvInit(hWnd, L_USER);
	LvSetStyle(hWnd, L_USER, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_USER, 0, _UU("SM_USER_COLUMN_1"), 120);
	LvInsertColumn(hWnd, L_USER, 1, _UU("SM_USER_COLUMN_2"), 100);
	LvInsertColumn(hWnd, L_USER, 2, _UU("SM_USER_COLUMN_3"), 100);
	LvInsertColumn(hWnd, L_USER, 3, _UU("SM_USER_COLUMN_4"), 130);
	LvInsertColumn(hWnd, L_USER, 4, _UU("SM_USER_COLUMN_5"), 100);
	LvInsertColumn(hWnd, L_USER, 5, _UU("SM_USER_COLUMN_6"), 90);
	LvInsertColumn(hWnd, L_USER, 6, _UU("SM_USER_COLUMN_7"), 120);
	LvInsertColumn(hWnd, L_USER, 7, _UU("SM_LICENSE_COLUMN_5"), 120);
	LvInsertColumn(hWnd, L_USER, 8, _UU("SM_SESS_COLUMN_6"), 100);
	LvInsertColumn(hWnd, L_USER, 9, _UU("SM_SESS_COLUMN_7"), 100);

	FormatText(hWnd, S_TITLE, s->Hub->HubName);

	if (s->GroupName != NULL)
	{
		GetTxt(hWnd, 0, tmp1, sizeof(tmp1));
		UniFormat(tmp2, sizeof(tmp2), _UU("SM_GROUP_MEMBER_STR"), s->GroupName);
		UniStrCat(tmp1, sizeof(tmp1), tmp2);
		SetText(hWnd, S_TITLE, tmp1);
		Disable(hWnd, B_CREATE);
	}

	if (s->SelectMode)
	{
		SetStyle(hWnd, L_USER, LVS_SINGLESEL);
	}

	SmUserListRefresh(hWnd, s);

	if (s->SelectMode)
	{
		wchar_t tmp[MAX_SIZE];
		UINT i;
		StrToUni(tmp, sizeof(tmp), s->SelectedName);
		i = LvSearchStr(hWnd, L_USER, 0, tmp);
		if (i != INFINITE)
		{
			LvSelect(hWnd, L_USER, i);
		}

		if (s->AllowGroup)
		{
			SetText(hWnd, B_DELETE, _UU("SM_SELECT_ALT_GROUP"));
		}
	}
}

// User list update
void SmUserListRefresh(HWND hWnd, SM_USER *s)
{
	LVB *b;
	RPC_ENUM_USER t;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
	if (CALL(hWnd, ScEnumUser(s->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumUser;i++)
	{
		RPC_ENUM_USER_ITEM *e = &t.Users[i];
		wchar_t name[MAX_SIZE];
		wchar_t group[MAX_SIZE];
		wchar_t num[MAX_SIZE];
		wchar_t time[MAX_SIZE];
		wchar_t exp[MAX_SIZE];
		wchar_t num1[64], num2[64];

		if (s->GroupName != NULL)
		{
			if (StrCmpi(s->GroupName, e->GroupName) != 0)
			{
				continue;
			}
		}

		StrToUni(name, sizeof(name), e->Name);

		if (StrLen(e->GroupName) != 0)
		{
			StrToUni(group, sizeof(group), e->GroupName);
		}
		else
		{
			UniStrCpy(group, sizeof(group), _UU("SM_NO_GROUP"));
		}

		UniToStru(num, e->NumLogin);

		GetDateTimeStrEx64(time, sizeof(time), SystemToLocal64(e->LastLoginTime), NULL);

		if (e->IsExpiresFilled == false)
		{
			UniStrCpy(exp, sizeof(exp), _UU("CM_ST_NONE"));
		}
		else
		{
			if (e->Expires == 0)
			{
				UniStrCpy(exp, sizeof(exp), _UU("SM_LICENSE_NO_EXPIRES"));
			}
			else
			{
				GetDateTimeStrEx64(exp, sizeof(exp), SystemToLocal64(e->Expires), NULL);
			}
		}

		if (e->IsTrafficFilled == false)
		{
			UniStrCpy(num1, sizeof(num1), _UU("CM_ST_NONE"));
			UniStrCpy(num2, sizeof(num2), _UU("CM_ST_NONE"));
		}
		else
		{
			UniToStr3(num1, sizeof(num1),
				e->Traffic.Recv.BroadcastBytes + e->Traffic.Recv.UnicastBytes +
				e->Traffic.Send.BroadcastBytes + e->Traffic.Send.UnicastBytes);

			UniToStr3(num2, sizeof(num2),
				e->Traffic.Recv.BroadcastCount + e->Traffic.Recv.UnicastCount +
				e->Traffic.Send.BroadcastBytes + e->Traffic.Send.UnicastCount);
		}

		LvInsertAdd(b, e->DenyAccess ? ICO_USER_DENY : ICO_USER, NULL, 10,
			name, e->Realname, group, e->Note, SmGetAuthTypeStr(e->AuthType),
			num, time, exp, num1, num2);
	}

	LvInsertEnd(b, hWnd, L_USER);

	FreeRpcEnumUser(&t);

	SmUserListUpdate(hWnd, s);
}

// User list control update
void SmUserListUpdate(HWND hWnd, SM_USER *s)
{
	bool b = true;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_USER) == false || LvIsMultiMasked(hWnd, L_USER))
	{
		b = false;
	}

	if (s->SelectMode)
	{
		SetText(hWnd, IDOK, _UU("SM_SELECT_USER"));
		SetText(hWnd, IDCANCEL, _UU("SM_SELECT_NO"));
		SetText(hWnd, S_TITLE, _UU("SM_PLEASE_SELECT"));
	}

	SetEnable(hWnd, IDOK, b);

	SetEnable(hWnd, B_STATUS, b);
	SetEnable(hWnd, B_DELETE, (b && s->SelectedName == false) || s->AllowGroup);
	SetEnable(hWnd, B_CREATE, s->SelectedName == false);
}

// User List dialog procedure
UINT SmUserListProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_USER *s = (SM_USER *)param;
	NMHDR *n;
	wchar_t *str;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmUserListInit(hWnd, s);

		if (s->CreateNow)
		{
			// Create instantly
			if (IsEnable(hWnd, B_CREATE))
			{
				Command(hWnd, B_CREATE);
			}
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			if (s->SelectMode == false)
			{
				// Property
				str = LvGetSelectedStr(hWnd, L_USER, 0);
				if (str != NULL)
				{
					char name[MAX_SIZE];
					UniToStr(name, sizeof(name), str);

					if (SmEditUserDlg(hWnd, s->Hub, name))
					{
						SmUserListRefresh(hWnd, s);
					}

					Free(str);
				}
			}
			else
			{
				// The user has been chosen
				str = LvGetSelectedStr(hWnd, L_USER, 0);
				if (str != NULL)
				{
					char name[MAX_SIZE];
					UniToStr(name, sizeof(name), str);

					s->SelectedName = CopyStr(name);

					EndDialog(hWnd, true);

					Free(str);
				}
			}
			break;

		case B_CREATE:
			// Create new
			if (SmCreateUserDlg(hWnd, s->Hub))
			{
				SmUserListRefresh(hWnd, s);
			}
			break;

		case B_DELETE:
			if (s->AllowGroup)
			{
				// Group selection
				EndDialog(hWnd, INFINITE);
			}
			else
			{
				// Delete
				str = LvGetSelectedStr(hWnd, L_USER, 0);
				if (str != NULL)
				{
					RPC_DELETE_USER t;
					char name[MAX_SIZE];
					UniToStr(name, sizeof(name), str);

					Zero(&t, sizeof(t));
					StrCpy(t.HubName, sizeof(t.HubName), s->Hub->HubName);
					StrCpy(t.Name, sizeof(t.Name), name);

					if (MsgBoxEx(hWnd, MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION,
						_UU("SM_USER_DELETE_MSG"), str) == IDYES)
					{
						if (CALL(hWnd, ScDeleteUser(s->Rpc, &t)))
						{
							SmUserListRefresh(hWnd, s);
						}
					}

					Free(str);
				}
			}
			break;

		case B_STATUS:
			// Display the User Information 
			str = LvGetSelectedStr(hWnd, L_USER, 0);
			if (str != NULL)
			{
				char name[MAX_SIZE];
				wchar_t tmp[MAX_SIZE];
				SM_USER_INFO info;
				UniToStr(name, sizeof(name), str);

				UniFormat(tmp, sizeof(tmp), _UU("SM_USERINFO_CAPTION"), name);

				Zero(&info, sizeof(info));
				info.p = s->p;
				info.Rpc = s->Rpc;
				info.Hub = s->Hub;
				info.Username = name;

				SmStatusDlg(hWnd, s->p, &info, false, true, tmp, ICO_USER, NULL, SmRefreshUserInfo);

				Free(str);
			}
			break;
			break;

		case B_REFRESH:
			// Update
			SmUserListRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_USER:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				// Update the control
				SmUserListUpdate(hWnd, s);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_USER);

	return 0;
}

// User List dialog (selection)
char *SmSelectUserDlg(HWND hWnd, SM_HUB *s, char *default_name)
{
	return SmSelectUserDlgEx(hWnd, s, default_name, false);
}
char *SmSelectUserDlgEx(HWND hWnd, SM_HUB *s, char *default_name, bool allow_group)
{
	UINT ret;
	SM_USER user;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return NULL;
	}

	Zero(&user, sizeof(user));
	user.Hub = s;
	user.p = s->p;
	user.Rpc = s->Rpc;
	user.GroupName = NULL;
	user.SelectedName = default_name;
	user.SelectMode = true;
	user.AllowGroup = allow_group;

	ret = Dialog(hWnd, D_SM_USER, SmUserListProc, &user);

	if (ret == 0)
	{
		return NULL;
	}
	else if (ret == INFINITE)
	{
		// Select a Group
		return SmSelectGroupDlg(hWnd, s, default_name);
	}
	else
	{
		return user.SelectedName;
	}
}

// User List dialog (filtered by group name)
void SmUserListDlgEx(HWND hWnd, SM_HUB *s, char *groupname, bool create)
{
	SM_USER user;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&user, sizeof(user));
	user.Hub = s;
	user.p = s->p;
	user.Rpc = s->Rpc;
	user.GroupName = groupname;
	user.CreateNow = create;

	Dialog(hWnd, D_SM_USER, SmUserListProc, &user);
}

// User List dialog
void SmUserListDlg(HWND hWnd, SM_HUB *s)
{
	SmUserListDlgEx(hWnd, s, NULL, false);
}

// Initialize
void SmHubDlgInit(HWND hWnd, SM_HUB *s)
{
	CAPSLIST *caps;
	bool support_user, support_group, support_accesslist, support_cascade,
		support_log, support_config_hub, support_secure_nat, support_config_radius;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	FormatText(hWnd, 0, s->HubName);
	FormatText(hWnd, S_TITLE, s->HubName);
	SetIcon(hWnd, 0, ICO_HUB);
	DlgFont(hWnd, S_TITLE, 15, true);

	LvInit(hWnd, L_STATUS);
	LvSetStyle(hWnd, L_STATUS, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_STATUS, 0, _UU("SM_STATUS_COLUMN_1"), 0);
	LvInsertColumn(hWnd, L_STATUS, 1, _UU("SM_STATUS_COLUMN_2"), 0);

	caps = s->p->CapsList;

	support_user = GetCapsInt(caps, "i_max_users_per_hub") == 0 ? false : true;
	support_group = GetCapsInt(caps, "i_max_groups_per_hub") == 0 ? false : true;
	support_accesslist = GetCapsInt(caps, "i_max_access_lists") == 0 ? false : true;
	support_cascade = GetCapsBool(caps, "b_support_cascade");
	support_log = GetCapsBool(caps, "b_support_config_log");
	support_config_hub = GetCapsBool(caps, "b_support_config_hub");
	support_secure_nat = GetCapsBool(caps, "b_support_securenat");
	support_config_radius = GetCapsBool(caps, "b_support_radius");

	SetEnable(hWnd, B_USER, support_user);
	SetEnable(hWnd, S_USER, support_user);

	SetEnable(hWnd, B_GROUP, support_group);
	SetEnable(hWnd, S_GROUP, support_group);

	SetEnable(hWnd, B_ACCESS, support_accesslist);
	SetEnable(hWnd, S_ACCESS, support_accesslist);

	SetEnable(hWnd, B_PROPERTY, s->p->ServerType != SERVER_TYPE_FARM_MEMBER);
	SetEnable(hWnd, S_PROPERTY, s->p->ServerType != SERVER_TYPE_FARM_MEMBER);

	SetEnable(hWnd, B_RADIUS, support_config_radius);
	SetEnable(hWnd, S_RADIUS, support_config_radius);

	SetEnable(hWnd, B_LINK, support_cascade);
	SetEnable(hWnd, S_LINK, support_cascade);

	SetEnable(hWnd, B_LOG, support_log);
	SetEnable(hWnd, S_LOG, support_log);

	SetEnable(hWnd, B_CA, support_config_hub);
	SetEnable(hWnd, S_CA, support_config_hub);

	SetEnable(hWnd, B_SNAT, support_secure_nat);
	SetEnable(hWnd, S_SNAT, support_secure_nat);

	SetEnable(hWnd, B_CRL, GetCapsBool(caps, "b_support_crl"));

	SetEnable(hWnd, B_LOG_FILE, GetCapsBool(caps, "b_support_read_log"));

	SmHubDlgRefresh(hWnd, s);
}

// Update the control
void SmHubDlgUpdate(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}
}

// Content update
void SmHubDlgRefresh(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SmRefreshHubStatus(hWnd, s->p, (void *)s->HubName);
	LvAutoSize(hWnd, L_STATUS);

	SmHubDlgUpdate(hWnd, s);
}

// HUB management dialog
UINT SmHubDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_HUB *s = (SM_HUB *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmHubDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_USER:
			// User
			SmUserListDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_GROUP:
			// Group
			SmGroupListDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_ACCESS:
			// Access list
			SmAccessListDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_PROPERTY:
			// Property
			if (SmEditHubDlg(hWnd, s->p, s->HubName))
			{
				SmHubDlgRefresh(hWnd, s);
			}
			break;

		case B_RADIUS:
			// Radius
			SmRadiusDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_LINK:
			// Cascade
			SmLinkDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_SESSION:
			// Session
			SmSessionDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_LOG:
			// Log
			Dialog(hWnd, D_SM_LOG, SmLogDlg, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_CA:
			// CA
			SmCaDlg(hWnd, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;

		case B_REFRESH:
			// Update
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_SNAT:
			// SecureNAT
			Dialog(hWnd, D_SM_SNAT, SmSNATDlgProc, s);
			SmHubDlgRefresh(hWnd, s);
			break;

		case B_CRL:
			// Certificate revocation list
			Dialog(hWnd, D_SM_CRL, SmCrlDlgProc, s);
			break;

		case B_LOG_FILE:
			// Log file
			Dialog(hWnd, D_SM_LOG_FILE, SmLogFileDlgProc, s->p);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Management of HUB
void SmHubDlg(HWND hWnd, SM_HUB *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_HUB, SmHubDlgProc, s);
}

// Change the server password
UINT SmChangeServerPasswordDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *p = (SM_SERVER *)param;
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	RPC_SET_PASSWORD t;
	SETTING *setting;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SetIcon(hWnd, 0, ICO_USER_ADMIN);
		FormatText(hWnd, 0, p->ServerName);
		FormatText(hWnd, S_TITLE, p->ServerName);
		Focus(hWnd, E_PASSWORD1);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PASSWORD1:
		case E_PASSWORD2:
			GetTxtA(hWnd, E_PASSWORD1, tmp1, sizeof(tmp1));
			GetTxtA(hWnd, E_PASSWORD2, tmp2, sizeof(tmp2));

			if (StrLen(tmp1) == 0 || StrLen(tmp2) == 0)
			{
				Disable(hWnd, IDOK);
			}
			else
			{
				Enable(hWnd, IDOK);
			}
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// [OK] button
			GetTxtA(hWnd, E_PASSWORD1, tmp1, sizeof(tmp1));
			GetTxtA(hWnd, E_PASSWORD2, tmp2, sizeof(tmp2));
			if (StrCmp(tmp1, tmp2) != 0)
			{
				MsgBox(hWnd, MB_ICONSTOP, _UU("SM_CHANGE_PASSWORD_1"));
				FocusEx(hWnd, E_PASSWORD2);
				break;
			}
			if (StrLen(tmp1) == 0)
			{
				if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("SM_CHANGE_PASSWORD_2")) == IDNO)
				{
					Focus(hWnd, E_PASSWORD1);
					break;
				}
			}
			Zero(&t, sizeof(t));
			Sha0(t.HashedPassword, tmp1, StrLen(tmp1));
			Copy(hash, t.HashedPassword, sizeof(hash));
			if (CALL(hWnd, ScSetServerPassword(p->Rpc, &t)) == false)
			{
				break;
			}
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SM_CHANGE_PASSWORD_3"));

			// Change the password for the connection setting
			setting = SmGetSetting(p->CurrentSetting->Title);
			if (setting != NULL && sm->TempSetting == NULL)
			{
				if (IsZero(setting->HashedPassword, SHA1_SIZE) == false)
				{
					Copy(setting->HashedPassword, hash, SHA1_SIZE);
					SmWriteSettingList();
				}
			}

			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			// Cancel button
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

// Update the status of the connection to the server farm controller
bool SmRefreshFarmConnectionInfo(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_FARM_CONNECTION_STATUS t;
	LVB *b;
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScGetFarmConnectionStatus(p->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	if (t.Online == false)
	{
		LvInsertAdd(b, ICO_FARM, NULL, 2, _UU("SM_FC_IP"), _UU("SM_FC_NOT_CONNECTED"));

		LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FC_PORT"), _UU("SM_FC_NOT_CONNECTED"));
	}
	else
	{
		IPToStr32(str, sizeof(str), t.Ip);
		StrToUni(tmp, sizeof(tmp), str);
		LvInsertAdd(b, ICO_FARM, NULL, 2, _UU("SM_FC_IP"), tmp);

		UniToStru(tmp, t.Port);
		LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FC_PORT"), tmp);
	}

	LvInsertAdd(b,
		t.Online ? ICO_SERVER_ONLINE_EX : ICO_PROTOCOL_X, NULL, 2,
		_UU("SM_FC_STATUS"),
		t.Online ? _UU("SM_FC_ONLINE") : _UU("SM_FC_OFFLINE"));

	if (t.Online == false)
	{
		UniFormat(tmp, sizeof(tmp), _UU("SM_FC_ERROR_TAG"), _E(t.LastError), t.LastError);
		LvInsertAdd(b, ICO_STOP, NULL, 2,
			_UU("SM_FC_LAST_ERROR"), tmp);
	}

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.StartedTime), NULL);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_FC_START_TIME"), tmp);

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.FirstConnectedTime), NULL);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_FC_FIRST_TIME"), tmp);

	//if (t.Online == false)
	{
		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.CurrentConnectedTime), NULL);
		LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_FC_CURRENT_TIME"), tmp);
	}

	UniToStru(tmp, t.NumTry);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FC_NUM_TRY"), tmp);

	UniToStru(tmp, t.NumConnected);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FC_NUM_CONNECTED"), tmp);

	UniToStru(tmp, t.NumFailed);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FC_NUM_FAILED"), tmp);

	LvInsertEnd(b, hWnd, L_STATUS);

	return true;
}

// Initialize
void SmFarmMemberDlgInit(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_FARM);

	FormatText(hWnd, S_TITLE, p->ServerName);

	// Initialize the column
	LvInit(hWnd, L_FARM_MEMBER);
	LvSetStyle(hWnd, L_FARM_MEMBER, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 0, _UU("SM_FM_COLUMN_1"), 90);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 1, _UU("SM_FM_COLUMN_2"), 150);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 2, _UU("SM_FM_COLUMN_3"), 140);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 3, _UU("SM_FM_COLUMN_4"), 60);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 4, _UU("SM_FM_COLUMN_5"), 80);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 5, _UU("SM_FM_COLUMN_6"), 80);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 6, _UU("SM_FM_COLUMN_7"), 80);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 7, _UU("SM_FM_COLUMN_8"), 160);
	LvInsertColumn(hWnd, L_FARM_MEMBER, 8, _UU("SM_FM_COLUMN_9"), 160);

	SmFarmMemberDlgRefresh(hWnd, p);
}

// Update
void SmFarmMemberDlgUpdate(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetEnable(hWnd, IDOK, LvIsSelected(hWnd, L_FARM_MEMBER) && (LvIsMultiMasked(hWnd, L_FARM_MEMBER) == false));
	SetEnable(hWnd, B_CERT, LvIsSelected(hWnd, L_FARM_MEMBER) && (LvIsMultiMasked(hWnd, L_FARM_MEMBER) == false));
}

// Content update
void SmFarmMemberDlgRefresh(HWND hWnd, SM_SERVER *p)
{
	RPC_ENUM_FARM t;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumFarmMember(p->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	LvReset(hWnd, L_FARM_MEMBER);

	for (i = 0;i < t.NumFarm;i++)
	{
		RPC_ENUM_FARM_ITEM *e = &t.Farms[i];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[64];
		wchar_t tmp4[64];
		wchar_t tmp5[64];
		wchar_t tmp6[64];
		wchar_t tmp7[64];
		wchar_t tmp8[64];

		GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(e->ConnectedTime), NULL);
		StrToUni(tmp2, sizeof(tmp2), e->Hostname);
		UniToStru(tmp3, e->Point);
		UniToStru(tmp4, e->NumSessions);
		UniToStru(tmp5, e->NumTcpConnections);
		UniToStru(tmp6, e->NumHubs);
		UniToStru(tmp7, e->AssignedClientLicense);
		UniToStru(tmp8, e->AssignedBridgeLicense);

		LvInsert(hWnd, L_FARM_MEMBER, e->Controller ? ICO_FARM : ICO_TOWER, (void *)e->Id, 9,
			e->Controller ? _UU("SM_FM_CONTROLLER") : _UU("SM_FM_MEMBER"),
			tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8);
	}

	FreeRpcEnumFarm(&t);

	SmFarmMemberDlgUpdate(hWnd, p);
}

// [OK] button
void SmFarmMemberDlgOnOk(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

}

// Display the farm member certificate
void SmFarmMemberCert(HWND hWnd, SM_SERVER *p, UINT id)
{
	RPC_FARM_INFO t;
	// Validate arguments
	if (hWnd == NULL || p == NULL || id == 0)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.Id = id;

	if (CALL(hWnd, ScGetFarmInfo(p->Rpc, &t)) == false)
	{
		return;
	}

	CertDlg(hWnd, t.ServerCert, NULL, true);

	FreeRpcFarmInfo(&t);
}

// Update the farm member information
bool SmRefreshFarmMemberInfo(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_FARM_INFO t;
	UINT id = (UINT)param;
	LVB *b;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || p == NULL || id == 0)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	t.Id = id;

	if (CALL(hWnd, ScGetFarmInfo(p->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	LvInsertAdd(b, ICO_FARM, NULL, 2, _UU("SM_FMINFO_TYPE"),
		t.Controller ? _UU("SM_FARM_CONTROLLER") : _UU("SM_FARM_MEMBER"));

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ConnectedTime), NULL);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_FMINFO_CONNECT_TIME"), tmp);

	IPToStr32(str, sizeof(str), t.Ip);
	StrToUni(tmp, sizeof(tmp), str);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FMINFO_IP"), tmp);

	StrToUni(tmp, sizeof(tmp), t.Hostname);
	LvInsertAdd(b, ICO_TOWER, NULL, 2, _UU("SM_FMINFO_HOSTNAME"), tmp);

	UniToStru(tmp, t.Point);
	LvInsertAdd(b, ICO_TEST, NULL, 2, _UU("SM_FMINFO_POINT"), tmp);

	UniToStru(tmp, t.Weight);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_FMINFO_WEIGHT"), tmp);

	UniToStru(tmp, t.NumPort);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FMINFO_NUM_PORT"), tmp);

	for (i = 0;i < t.NumPort;i++)
	{
		wchar_t tmp2[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("SM_FMINFO_PORT"), i + 1);
		UniToStru(tmp2, t.Ports[i]);
		LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, tmp, tmp2);
	}

	UniToStru(tmp, t.NumFarmHub);
	LvInsertAdd(b, ICO_HUB_OFFLINE, NULL, 2, _UU("SM_FMINFO_NUM_HUB"), tmp);

	for (i = 0;i < t.NumFarmHub;i++)
	{
		wchar_t tmp2[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("SM_FMINFO_HUB"), i + 1);
		UniFormat(tmp2, sizeof(tmp2),
			t.FarmHubs[i].DynamicHub ? _UU("SM_FMINFO_HUB_TAG_2") : _UU("SM_FMINFO_HUB_TAG_1"),
			t.FarmHubs[i].HubName);
		LvInsertAdd(b, ICO_HUB, NULL, 2, tmp, tmp2);
	}

	UniToStru(tmp, t.NumSessions);
	LvInsertAdd(b, ICO_VPN, NULL, 2, _UU("SM_FMINFO_NUM_SESSION"), tmp);

	UniToStru(tmp, t.NumTcpConnections);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_FMINFO_NUN_CONNECTION"), tmp);

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcFarmInfo(&t);

	return true;
}

// Farm Member List dialog
UINT SmFarmMemberDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *p = (SM_SERVER *)param;
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
		// Initialize
		SmFarmMemberDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// Display the information of farm members
			i = LvGetSelected(hWnd, L_FARM_MEMBER);
			if (i != INFINITE)
			{
				SmStatusDlg(hWnd, p, LvGetParam(hWnd, L_FARM_MEMBER, i), false, true,
					_UU("SM_FMINFO_CAPTION"), ICO_FARM, NULL, SmRefreshFarmMemberInfo);
			}
			break;

		case B_CERT:
			// Show the Server Certificate
			i = LvGetSelected(hWnd, L_FARM_MEMBER);
			if (i != INFINITE)
			{
				SmFarmMemberCert(hWnd, p, (UINT)LvGetParam(hWnd, L_FARM_MEMBER, i));
			}
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;

		case B_REFRESH:
			// Update
			SmFarmMemberDlgRefresh(hWnd, p);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->code)
		{
		case LVN_ITEMCHANGED:
			switch (n->idFrom)
			{
			case L_FARM_MEMBER:
				SmFarmMemberDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_FARM_MEMBER);

	return 0;
}

// Initialize the dialog
void SmFarmDlgInit(HWND hWnd, SM_SERVER *p)
{
	RPC_FARM t;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_FARM);

	// Get the current settings
	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScGetFarmSetting(p->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	if (t.Weight == 0)
	{
		t.Weight = FARM_DEFAULT_WEIGHT;
	}

	FormatText(hWnd, S_TITLE, p->ServerName);
	DlgFont(hWnd, S_CURRENT, 11, true);

	SetText(hWnd, S_CURRENT, GetServerTypeStr(t.ServerType));

	switch (t.ServerType)
	{
	case SERVER_TYPE_FARM_CONTROLLER:
		Check(hWnd, R_CONTROLLER, true);
		break;

	case SERVER_TYPE_FARM_MEMBER:
		Check(hWnd, R_MEMBER, true);
		break;

	default:
		Check(hWnd, R_STANDALONE, true);
		break;
	}

	SetInt(hWnd, E_WEIGHT, t.Weight);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		Check(hWnd, R_CONTROLLER_ONLY, t.ControllerOnly);
	}

	if (t.ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		char tmp[MAX_PUBLIC_PORT_NUM * 8];
		UINT i;
		if (t.PublicIp != 0)
		{
			IpSet(hWnd, E_IP, t.PublicIp);
		}
		StrCpy(tmp, sizeof(tmp), "");
		if (t.NumPort != 0)
		{
			for (i = 0;i < t.NumPort;i++)
			{
				Format(tmp, sizeof(tmp), "%s%u", tmp, t.Ports[i]);
				if (i != (t.NumPort - 1))
				{
					StrCat(tmp, sizeof(tmp), ", ");
				}
			}
			SetTextA(hWnd, E_PORT, tmp);
		}
		SetTextA(hWnd, E_CONTROLLER, t.ControllerName);
		SetIntEx(hWnd, E_CONTROLLER_PORT, t.ControllerPort);
		SetTextA(hWnd, E_PASSWORD, HIDDEN_PASSWORD);
	}
	else
	{
		// Write the port list
		RPC_LISTENER_LIST t;
		char tmp[MAX_PUBLIC_PORT_NUM * 8];
		Zero(&t, sizeof(t));
		StrCpy(tmp, sizeof(tmp), "");
		if (CALL(hWnd, ScEnumListener(p->Rpc, &t)))
		{
			UINT i;
			if (t.NumPort != 0)
			{
				for (i = 0;i < t.NumPort;i++)
				{
					Format(tmp, sizeof(tmp), "%s%u", tmp, t.Ports[i]);
					if (i != (t.NumPort - 1))
					{
						StrCat(tmp, sizeof(tmp), ", ");
					}
				}
				SetTextA(hWnd, E_PORT, tmp);
			}
			FreeRpcListenerList(&t);
		}
	}

	SmFarmDlgUpdate(hWnd, p);

	FreeRpcFarm(&t);

	Focus(hWnd, IDOK);
}

// Dialog update
void SmFarmDlgUpdate(HWND hWnd, SM_SERVER *p)
{
	bool ok = true;
	bool farm_member_control = false;
	char *s;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	if (IsChecked(hWnd, R_MEMBER))
	{
		LIST *o;
		UINT i = IpGetFilledNum(hWnd, E_IP);
		if (i != 0 && i != 4)
		{
			ok = false;
		}

		s = GetTextA(hWnd, E_PORT);
		o = StrToPortList(s, true);
		if (o == NULL)
		{
			ok = false;
		}
		else
		{
			ReleaseList(o);
		}
		Free(s);

		if (IsEmpty(hWnd, E_CONTROLLER))
		{
			ok = false;
		}

		i = GetInt(hWnd, E_CONTROLLER_PORT);
		if (i == 0 || i >= 65536)
		{
			ok = false;
		}

		farm_member_control = true;
	}

	if (IsChecked(hWnd, R_STANDALONE))
	{
		Disable(hWnd, S_1);
		Disable(hWnd, S_2);
		Disable(hWnd, E_WEIGHT);
	}
	else
	{
		Enable(hWnd, S_1);
		Enable(hWnd, S_2);
		Enable(hWnd, E_WEIGHT);
	}

	if (IsChecked(hWnd, R_CONTROLLER))
	{
		Enable(hWnd, R_CONTROLLER_ONLY);
	}
	else
	{
		Disable(hWnd, R_CONTROLLER_ONLY);
	}

	if (IsChecked(hWnd, R_CONTROLLER) || IsChecked(hWnd, R_MEMBER))
	{
		if (GetInt(hWnd, E_WEIGHT) == 0)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, S_IP_1, farm_member_control);
	SetEnable(hWnd, E_IP, farm_member_control);
	SetEnable(hWnd, S_IP_2, farm_member_control);
	SetEnable(hWnd, S_PORT_1, farm_member_control);
	SetEnable(hWnd, E_PORT, farm_member_control);
	SetEnable(hWnd, S_PORT_2, farm_member_control);
	SetEnable(hWnd, S_PORT_3, farm_member_control);
	SetEnable(hWnd, E_CONTROLLER, farm_member_control);
	SetEnable(hWnd, S_CONTROLLER, farm_member_control);
	SetEnable(hWnd, E_CONTROLLER_PORT, farm_member_control);
	SetEnable(hWnd, S_CONTROLLER_PORT, farm_member_control);
	SetEnable(hWnd, S_PASSWORD, farm_member_control);
	SetEnable(hWnd, E_PASSWORD, farm_member_control);
	SetEnable(hWnd, IDOK, ok);
}

// [OK] button
void SmFarmDlgOnOk(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	// Display the message
	if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_OKCANCEL | MB_DEFBUTTON2,
		_UU("SM_FARM_REBOOT_MSG")) == IDOK)
	{
		RPC_FARM t;
		Zero(&t, sizeof(t));
		t.ServerType = SERVER_TYPE_STANDALONE;
		if (IsChecked(hWnd, R_CONTROLLER))
		{
			t.ServerType = SERVER_TYPE_FARM_CONTROLLER;
		}
		if (IsChecked(hWnd, R_MEMBER))
		{
			t.ServerType = SERVER_TYPE_FARM_MEMBER;
		}

		t.ControllerOnly = IsChecked(hWnd, R_CONTROLLER_ONLY);
		t.Weight = GetInt(hWnd, E_WEIGHT);

		if (t.ServerType == SERVER_TYPE_FARM_MEMBER)
		{
			char *s;
			char pass[MAX_SIZE];
			t.PublicIp = IpGet(hWnd, E_IP);
			s = GetTextA(hWnd, E_PORT);
			if (s != NULL)
			{
				LIST *o = StrToPortList(s, true);
				if (o != NULL)
				{
					UINT i;
					t.NumPort = LIST_NUM(o);
					t.Ports = ZeroMalloc(sizeof(UINT) * t.NumPort);
					for (i = 0;i < t.NumPort;i++)
					{
						t.Ports[i] = (UINT)LIST_DATA(o, i);
					}
					ReleaseList(o);
				}
				Free(s);
			}
			GetTxtA(hWnd, E_CONTROLLER, t.ControllerName, sizeof(t.ControllerName));
			t.ControllerPort = GetInt(hWnd, E_CONTROLLER_PORT);
			GetTxtA(hWnd, E_PASSWORD, pass, sizeof(pass));
			if (StrCmp(pass, HIDDEN_PASSWORD) != 0)
			{
				Sha0(t.MemberPassword, pass, StrLen(pass));
			}
		}

		// Configuration update
		if (CALL(hWnd, ScSetFarmSetting(p->Rpc, &t)) == false)
		{
			return;
		}

		FreeRpcFarm(&t);

		EndDialog(hWnd, true);
	}
}

// Server farm dialog procedure
UINT SmFarmDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *p = (SM_SERVER *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmFarmDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_STANDALONE:
		case R_CONTROLLER:
		case R_MEMBER:
		case E_IP:
		case E_PORT:
		case E_CONTROLLER:
		case E_CONTROLLER_PORT:
		case E_PASSWORD:
		case R_CONTROLLER_ONLY:
		case E_WEIGHT:
			SmFarmDlgUpdate(hWnd, p);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// [OK] button
			SmFarmDlgOnOk(hWnd, p);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;

		case R_MEMBER:
			if (IsChecked(hWnd, R_MEMBER))
			{
				Focus(hWnd, E_IP);
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

// Server farm configuration
bool SmFarmDlg(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_SM_FARM, SmFarmDlgProc, p);
}

// Update the connection information
bool SmRefreshConnectionStatus(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_CONNECTION_INFO t;
	SM_CONNECTION_INFO *info = (SM_CONNECTION_INFO *)param;
	LVB *b;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || p == NULL || param == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.Name, sizeof(t.Name), info->ConnectionName);
	if (CALL(hWnd, ScGetConnectionInfo(p->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	StrToUni(tmp, sizeof(tmp), t.Name);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_CONNINFO_NAME"), tmp);

	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_CONNINFO_TYPE"), SmGetConnectionTypeStr(t.Type));

	StrToUni(tmp, sizeof(tmp), t.Hostname);
	LvInsertAdd(b, ICO_FARM, NULL, 2, _UU("SM_CONNINFO_HOSTNAME"), tmp);

	UniToStru(tmp, t.Port);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_CONNINFO_PORT"), tmp);

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ConnectedTime), NULL);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_CONNINFO_TIME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.ServerStr);
	LvInsertAdd(b, ICO_VPNSERVER, NULL, 2, _UU("SM_CONNINFO_SERVER_STR"), tmp);

	UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ServerVer / 100, t.ServerVer % 100);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_CONNINFO_SERVER_VER"), tmp);

	UniToStru(tmp, t.ServerBuild);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_CONNINFO_SERVER_BUILD"), tmp);

	if (StrLen(t.ClientStr) != 0)
	{
		StrToUni(tmp, sizeof(tmp), t.ClientStr);
		LvInsertAdd(b, ICO_VPN, NULL, 2, _UU("SM_CONNINFO_CLIENT_STR"), tmp);

		UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ClientVer / 100, t.ClientVer % 100);
		LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_CONNINFO_CLIENT_VER"), tmp);

		UniToStru(tmp, t.ClientBuild);
		LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_CONNINFO_CLIENT_BUILD"), tmp);
	}

	LvInsertEnd(b, hWnd, L_STATUS);

	return true;
}

// Initialize
void SmConnectionDlgInit(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_PROTOCOL);
	FormatText(hWnd, S_TITLE, p->ServerName);

	// Initialize the column
	LvInit(hWnd, L_LIST);
	LvSetStyle(hWnd, L_LIST, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_LIST, 0, _UU("SM_CONN_COLUMN_1"), 90);
	LvInsertColumn(hWnd, L_LIST, 1, _UU("SM_CONN_COLUMN_2"), 150);
	LvInsertColumn(hWnd, L_LIST, 2, _UU("SM_CONN_COLUMN_3"), 200);
	LvInsertColumn(hWnd, L_LIST, 3, _UU("SM_CONN_COLUMN_4"), 80);

	SmConnectionDlgRefresh(hWnd, p);
	SmConnectionDlgUpdate(hWnd, p);
}

// Update
void SmConnectionDlgRefresh(HWND hWnd, SM_SERVER *p)
{
	LVB *b;
	UINT i;
	RPC_ENUM_CONNECTION t;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumConnection(p->Rpc, &t)) == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < t.NumConnection;i++)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t name[MAX_SIZE];
		wchar_t datetime[MAX_SIZE];
		RPC_ENUM_CONNECTION_ITEM *e = &t.Connections[i];

		StrToUni(name, sizeof(name), e->Name);
		UniFormat(tmp, sizeof(tmp), _UU("SM_HOSTNAME_AND_PORT"), e->Hostname, e->Port);
		GetDateTimeStrEx64(datetime, sizeof(datetime), SystemToLocal64(e->ConnectedTime), NULL);

		LvInsertAdd(b, ICO_PROTOCOL, NULL, 4, name, tmp, datetime,
			SmGetConnectionTypeStr(e->Type));
	}

	LvInsertEnd(b, hWnd, L_LIST);

	FreeRpcEnumConnection(&t);
}

// Update the control
void SmConnectionDlgUpdate(HWND hWnd, SM_SERVER *p)
{
	bool b = false;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_LIST) && (LvIsMultiMasked(hWnd, L_LIST) == false))
	{
		b = true;
	}

	SetEnable(hWnd, IDOK, b);
	SetEnable(hWnd, B_DISCONNECT, b && p->ServerAdminMode);
}

// Connection List procedure
UINT SmConnectionDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *p = (SM_SERVER *)param;
	NMHDR *n;
	wchar_t *s;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmConnectionDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// Show the connection information
			s = LvGetSelectedStr(hWnd, L_LIST, 0);
			if (s != NULL)
			{
				wchar_t caption[MAX_SIZE];
				SM_CONNECTION_INFO info;
				UniFormat(caption, sizeof(caption), _UU("SM_CONNINFO_CAPTION"),
					s);
				Zero(&info, sizeof(info));
				info.ConnectionName = CopyUniToStr(s);
				info.p = p;
				SmStatusDlg(hWnd, p, &info, false, false, caption, ICO_PROTOCOL,
					NULL, SmRefreshConnectionStatus);
				Free(info.ConnectionName);
				Free(s);
			}
			break;

		case B_DISCONNECT:
			// Disconnect
			s = LvGetSelectedStr(hWnd, L_LIST, 0);
			if (s != NULL)
			{
				if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
					_UU("SM_CONN_DISCONNECT_MSG"), s) == IDYES)
				{
					char tmp[MAX_SIZE];
					RPC_DISCONNECT_CONNECTION t;

					UniToStr(tmp, sizeof(tmp), s);
					Zero(&t, sizeof(t));
					StrCpy(t.Name, sizeof(t.Name), tmp);

					if (CALL(hWnd, ScDisconnectConnection(p->Rpc, &t)))
					{
						SmConnectionDlgRefresh(hWnd, p);
					}
				}
				Free(s);
			}
			break;

		case B_REFRESH:
			// Update to the latest state
			SmConnectionDlgRefresh(hWnd, p);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmConnectionDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_LIST);

	return 0;
}

// Display the connection list
void SmConnectionDlg(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Dialog(hWnd, D_SM_CONNECTION, SmConnectionDlgProc, p);
}

// Get the connection type string
wchar_t *SmGetConnectionTypeStr(UINT type)
{
	return GetConnectionTypeStr(type);
}

// Update the server information
bool SmRefreshServerInfo(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_SERVER_INFO t;
	LVB *b;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScGetServerInfo(p->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	// Product name
	StrToUni(tmp, sizeof(tmp), t.ServerProductName);
	LvInsertAdd(b, ICO_VPNSERVER, NULL, 2, _UU("SM_INFO_PRODUCT_NAME"), tmp);

	// Version
	StrToUni(tmp, sizeof(tmp), t.ServerVersionString);
	LvInsertAdd(b, ICO_INFORMATION, NULL, 2, _UU("SM_INFO_VERSION"), tmp);

	// Build
	StrToUni(tmp, sizeof(tmp), t.ServerBuildInfoString);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_INFO_BUILD"), tmp);

	// Host name
	StrToUni(tmp, sizeof(tmp), t.ServerHostName);
	LvInsertAdd(b, ICO_TOWER, NULL, 2, _UU("SM_INFO_HOSTNAME"), tmp);

	// Type
	LvInsertAdd(b, t.ServerType == SERVER_TYPE_STANDALONE ? ICO_SERVER_ONLINE : ICO_FARM, 0,
		2, _UU("SM_ST_SERVER_TYPE"),
		GetServerTypeStr(t.ServerType));

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

	SmAddServerCaps(b, p->CapsList);

	LvInsertEnd(b, hWnd, L_STATUS);

	FreeRpcServerInfo(&t);

	return true;
}

// Display the Caps of the server on the screen
void SmAddServerCaps(LVB *b, CAPSLIST *t)
{
	UINT i;
	// Validate arguments
	if (b == NULL || t == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		CAPS *c = LIST_DATA(t->CapsList, i);
		wchar_t title[MAX_SIZE];
		char name[256];

		Format(name, sizeof(name), "CT_%s", c->Name);

		UniStrCpy(title, sizeof(title), _UU(name));

		if (UniIsEmptyStr(title))
		{
			UniFormat(title, sizeof(title), L"%S", (StrLen(c->Name) >= 2) ? c->Name + 2 : c->Name);
		}

		if (StartWith(c->Name, "b_"))
		{
			bool icon_pass = c->Value == 0 ? false : true;
			if (StrCmpi(c->Name, "b_must_install_pcap") == 0)
			{
				// Invert only the item of WinPcap
				icon_pass = !icon_pass;
			}
			LvInsertAdd(b, icon_pass == false ? ICO_DISCARD : ICO_PASS,
				NULL, 2, title, c->Value == 0 ? _UU("CAPS_NO") : _UU("CAPS_YES"));
		}
		else
		{
			wchar_t str[64];
			UniToStru(str, c->Value);
			LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, title, str);
		}
	}
}

// Update the server state
bool SmRefreshServerStatus(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_SERVER_STATUS t;
	LVB *b;
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScGetServerStatus(p->Rpc, &t)) == false)
	{
		return false;
	}

	b = LvInsertStart();

	// Type of server
	LvInsertAdd(b, t.ServerType == SERVER_TYPE_STANDALONE ? ICO_SERVER_ONLINE : ICO_FARM, 0,
		2, _UU("SM_ST_SERVER_TYPE"),
		GetServerTypeStr(t.ServerType));

	// Number of TCP connections
	UniToStru(tmp, t.NumTcpConnections);
	LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_ST_NUM_TCP"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// Number of Local TCP connections
		UniToStru(tmp, t.NumTcpConnectionsLocal);
		LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_ST_NUM_TCP_LOCAL"), tmp);

		// Number of remote TCP connections
		UniToStru(tmp, t.NumTcpConnectionsRemote);
		LvInsertAdd(b, ICO_PROTOCOL, NULL, 2, _UU("SM_ST_NUM_TCP_REMOTE"), tmp);
	}

	// Number of Virtual HUBs
	UniToStru(tmp, t.NumHubTotal);
	LvInsertAdd(b, ICO_HUB, NULL, 2, _UU("SM_ST_NUM_HUB_TOTAL"), tmp);

	if (t.ServerType != SERVER_TYPE_STANDALONE)
	{
		// Number of static HUBs
		UniToStru(tmp, t.NumHubStatic);
		LvInsertAdd(b, ICO_HUB, NULL, 2, _UU("SM_ST_NUM_HUB_STATIC"), tmp);

		// Number of Dynamic HUBs
		UniToStru(tmp, t.NumHubDynamic);
		LvInsertAdd(b, ICO_HUB, NULL, 2, _UU("SM_ST_NUM_HUB_DYNAMIC"), tmp);
	}

	// Number of sessions
	UniToStru(tmp, t.NumSessionsTotal);
	LvInsertAdd(b, ICO_VPN, NULL, 2, _UU("SM_ST_NUM_SESSION_TOTAL"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// Number of local sessions
		UniToStru(tmp, t.NumSessionsLocal);
		LvInsertAdd(b, ICO_VPN, NULL, 2, _UU("SM_ST_NUM_SESSION_LOCAL"), tmp);

		// Number of local sessions
		UniToStru(tmp, t.NumSessionsRemote);
		LvInsertAdd(b, ICO_VPN, NULL, 2, _UU("SM_ST_NUM_SESSION_REMOTE"), tmp);
	}

	// Number of MAC table entries
	UniToStru(tmp, t.NumMacTables);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_ST_NUM_MAC_TABLE"), tmp);

	// Number of IP table entries
	UniToStru(tmp, t.NumIpTables);
	LvInsertAdd(b, ICO_MACHINE, NULL, 2, _UU("SM_ST_NUM_IP_TABLE"), tmp);

	// Number of users
	UniToStru(tmp, t.NumUsers);
	LvInsertAdd(b, ICO_USER, NULL, 2, _UU("SM_ST_NUM_USERS"), tmp);

	// Number of groups
	UniToStru(tmp, t.NumGroups);
	LvInsertAdd(b, ICO_GROUP, NULL, 2, _UU("SM_ST_NUM_GROUPS"), tmp);

	// Number of assigned licenses
	UniToStru(tmp, t.AssignedClientLicenses);
	LvInsertAdd(b, ICO_CERT, NULL, 2, _UU("SM_ST_CLIENT_LICENSE"), tmp);
	UniToStru(tmp, t.AssignedBridgeLicenses);
	LvInsertAdd(b, ICO_CERT, NULL, 2, _UU("SM_ST_BRIDGE_LICENSE"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UniToStru(tmp, t.AssignedClientLicensesTotal);
		LvInsertAdd(b, ICO_CERT, NULL, 2, _UU("SM_ST_CLIENT_LICENSE_EX"), tmp);
		UniToStru(tmp, t.AssignedBridgeLicensesTotal);
		LvInsertAdd(b, ICO_CERT, NULL, 2, _UU("SM_ST_BRIDGE_LICENSE_EX"), tmp);
	}

	// Traffic
	SmInsertTrafficInfo(b, &t.Traffic);

	// Server start-up time
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.StartTime), NULL);
	LvInsertAdd(b, ICO_NULL, NULL, 2, _UU("SM_ST_START_TIME"), tmp);

	// Current time
	GetDateTimeStrMilli64(str, sizeof(str), SystemToLocal64(t.CurrentTime));
	StrToUni(tmp, sizeof(tmp), str);
	LvInsertAdd(b, ICO_NULL, NULL, 2, _UU("SM_ST_CURRENT_TIME"), tmp);

	// Tick value
	UniFormat(tmp, sizeof(tmp), L"%I64u", t.CurrentTick);
	LvInsertAdd(b, ICO_NULL, NULL, 2, _UU("SM_ST_CURRENT_TICK"), tmp);

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

	return true;
}

// Initialize
void SmSaveKeyPairDlgInit(HWND hWnd, SM_SAVE_KEY_PAIR *s)
{
	UINT current;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	current = MsRegReadInt(REG_CURRENT_USER, SM_REG_KEY, "SavePkcs12");

	if (current == 1)
	{
		Check(hWnd, R_PKCS12, true);
	}
	else if (current == 2)
	{
		Check(hWnd, R_SECURE, true);
	}
	else
	{
		Check(hWnd, R_X509_AND_KEY, true);
	}

	if (MsIsWine())
	{
		Disable(hWnd, R_SECURE);
	}

	SmSaveKeyPairDlgUpdate(hWnd, s);
}

// Update
void SmSaveKeyPairDlgUpdate(HWND hWnd, SM_SAVE_KEY_PAIR *s)
{
	SECURE_DEVICE *dev;
	bool ok = true;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || s == NULL)
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

	if (IsChecked(hWnd, R_USE_PASS))
	{
		char *s1, *s2;
		s1 = GetTextA(hWnd, E_PASS1);
		s2 = GetTextA(hWnd, E_PASS2);
		if (StrCmp(s1, s2) != 0)
		{
			ok = false;
		}
		Free(s1);
		Free(s2);
	}

	if (IsChecked(hWnd, R_SECURE))
	{
		if (dev == NULL)
		{
			ok = false;
		}
	}

	SetEnable(hWnd, B_SELECT, IsChecked(hWnd, R_SECURE));
	SetEnable(hWnd, B_SECURE_MANAGER, IsChecked(hWnd, R_SECURE));
	SetEnable(hWnd, S_INFO, IsChecked(hWnd, R_SECURE));

	SetEnable(hWnd, E_PASS1, IsChecked(hWnd, R_USE_PASS) && (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, E_PASS2, IsChecked(hWnd, R_USE_PASS) && (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, S_PASS1, IsChecked(hWnd, R_USE_PASS) && (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, S_PASS2, IsChecked(hWnd, R_USE_PASS) && (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, R_USE_PASS, (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, S_PASS3, (IsChecked(hWnd, R_SECURE) == false));
	SetEnable(hWnd, S_PASS4, (IsChecked(hWnd, R_SECURE) == false));

	SetEnable(hWnd, IDOK, ok);
}

// [OK] button
void SmSaveKeyPairDlgOnOk(HWND hWnd, SM_SAVE_KEY_PAIR *s)
{
	UINT pkcs12;
	char pass[MAX_SIZE];
	char *password;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	pkcs12 = 0;

	if (IsChecked(hWnd, R_PKCS12))
	{
		pkcs12 = 1;
	}
	else if (IsChecked(hWnd, R_SECURE))
	{
		pkcs12 = 2;
	}
	MsRegWriteInt(REG_CURRENT_USER, SM_REG_KEY, "SavePkcs12", pkcs12);

	if (pkcs12 != 2)
	{
		GetTxtA(hWnd, E_PASS1, pass, sizeof(pass));

		if (StrLen(pass) != 0)
		{
			password = pass;
		}
		else
		{
			password = NULL;
		}

		if (pkcs12 == false)
		{
			// Write to the X509 and KEY
			wchar_t *x509_name, *key_name;
			x509_name = SaveDlg(hWnd, _UU("DLG_CERT_FILES"), _UU("DLG_SAVE_CERT"), NULL, L".cer");
			if (x509_name == NULL)
			{
				// Cancel
				return;
			}
			else
			{
				wchar_t default_key_name[MAX_SIZE];
				UniReplaceStrEx(default_key_name, sizeof(default_key_name), x509_name,
					L".cer", L"", false);
				UniReplaceStrEx(default_key_name, sizeof(default_key_name), default_key_name,
								L".crt", L"", false);
				UniStrCat(default_key_name, sizeof(default_key_name), L".key");
				key_name = SaveDlg(hWnd, _UU("DLG_KEY_FILTER"), _UU("DLG_SAVE_KEY"),
					default_key_name, L".key");
				if (key_name == NULL)
				{
					// Cancel
					Free(x509_name);
					return;
				}
				else
				{
					bool ok = true;
					wchar_t filename1[MAX_SIZE];
					wchar_t filename2[MAX_SIZE];

					UniStrCpy(filename1, sizeof(filename1), x509_name);
					UniStrCpy(filename2, sizeof(filename2), key_name);

					// Save the certificate
					if (XToFileW(s->Cert, filename1, true) == false)
					{
						MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_CERT_SAVE_ERROR"));
						ok = false;
					}
					else
					{
						if (KToFileW(s->Key, filename2, true, password) == false)
						{
							MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_KEY_SAVE_ERROR"));
							ok = false;
						}
					}

					if (ok)
					{
						MsgBox(hWnd, MB_ICONINFORMATION, _UU("DLG_KEY_PAIR_SAVE_OK"));
						EndDialog(hWnd, true);
					}

					Free(key_name);
				}
				Free(x509_name);
			}
		}
		else
		{
			// Write to the PKCS#12
			wchar_t *name = SaveDlg(hWnd, _UU("DLG_PKCS12_FILTER"), _UU("DLG_SAVE_P12"), NULL, L".p12");
			if (name == NULL)
			{
				// Cancel
				return;
			}
			else
			{
				P12 *p12;
				wchar_t filename[MAX_SIZE];
				UniStrCpy(filename, sizeof(filename), name);

				// Convert to PKCS#12
				p12 = NewP12(s->Cert, s->Key, pass);
				if (p12 == NULL)
				{
					// Failure
					MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_KEY_PAIR_SAVE_ERROR"));
				}
				else
				{
					// Save
					if (P12ToFileW(p12, filename) == false)
					{
						// Failure
						MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_KEY_PAIR_SAVE_ERROR"));
					}
					else
					{
						// Success
						MsgBox(hWnd, MB_ICONINFORMATION, _UU("DLG_KEY_PAIR_SAVE_OK"));
						EndDialog(hWnd, true);
					}
					FreeP12(p12);
				}

				Free(name);
			}
		}
	}
	else
	{
		char default_name[MAX_SIZE];
		char *object_name;
		bool ok = false;
		X *x;
		K *k;
		WINUI_SECURE_BATCH batch[] =
		{
			{WINUI_SECURE_WRITE_CERT, NULL, true, NULL, NULL, NULL, NULL, NULL, NULL},
			{WINUI_SECURE_WRITE_KEY, NULL, true, NULL, NULL, NULL, NULL, NULL, NULL},
		};

		x = s->Cert;
		k = s->Key;

		// Generate the default name
		GetPrintNameFromXA(default_name, sizeof(default_name), x);
		ConvertSafeFileName(default_name, sizeof(default_name), default_name);

		object_name = StringDlgA(hWnd, _UU("SEC_OBJECT_NAME_TITLE"),
			_UU("SEC_OBJECT_NAME_INFO"), default_name, ICO_CERT, false, false);

		if (object_name != NULL)
		{
			// Write and enumerate
			batch[0].InputX = x;
			batch[0].Name = object_name;
			batch[1].InputK = k;
			batch[1].Name = object_name;

			if (SecureDeviceWindow(hWnd, batch, sizeof(batch) / sizeof(batch[0]), SmGetCurrentSecureIdFromReg(), 0) == false)
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
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SEC_NEW_CERT_IMPORT_OK"));

			EndDialog(hWnd, true);
		}
	}
}

// Saving dialog box of the certificate and private key
UINT SmSaveKeyPairDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SAVE_KEY_PAIR *s = (SM_SAVE_KEY_PAIR *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmSaveKeyPairDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PASS1:
		case E_PASS2:
		case R_USE_PASS:
		case R_SECURE:
		case R_X509_AND_KEY:
		case R_PKCS12:
			SmSaveKeyPairDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// [OK] button
			SmSaveKeyPairDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;

		case R_USE_PASS:
			if (IsChecked(hWnd, R_USE_PASS))
			{
				FocusEx(hWnd, E_PASS1);
			}
			break;

		case B_SELECT:
			SmSelectSecureId(hWnd);
			SmSaveKeyPairDlgUpdate(hWnd, s);
			break;

		case B_SECURE_MANAGER:
			CmSecureManagerEx(hWnd, SmGetCurrentSecureId(hWnd), true);
			SmSaveKeyPairDlgUpdate(hWnd, s);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Save the certificate and private key
bool SmSaveKeyPairDlg(HWND hWnd, X *x, K *k)
{
	SM_SAVE_KEY_PAIR s;
	// Validate arguments
	if (hWnd == NULL || x == NULL || k == NULL)
	{
		return false;
	}

	Zero(&s, sizeof(s));
	s.Cert = x;
	s.Key = k;

	return Dialog(hWnd,	D_SM_SAVE_KEY_PAIR, SmSaveKeyPairDlgProc, &s);
}

// OK is clicked on the SSL related dialog
void SmSslDlgOnOk(HWND hWnd, SM_SSL *s)
{
	char *name;
	RPC_KEEP t;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (s->p->ServerAdminMode == false)
	{
		EndDialog(hWnd, false);
		return;
	}

	name = GetTextA(hWnd, C_CIPHER);
	if (name == NULL)
	{
		return;
	}
	else
	{
		RPC_STR t;
		Zero(&t, sizeof(t));
		t.String = name;

		// Set the encryption algorithm
		if (CALL(hWnd, ScSetServerCipher(s->p->Rpc, &t)) == false)
		{
			Focus(hWnd, C_CIPHER);
			return;
		}
		FreeRpcStr(&t);
	}

	if (s->SetCertAndKey)
	{
		// Set the certificate
		RPC_KEY_PAIR t;
		Zero(&t, sizeof(t));

		t.Cert = CloneX(s->Cert);
		t.Key = CloneK(s->Key);

		if (CALL(hWnd, ScSetServerCert(s->p->Rpc, &t)) == false)
		{
			return;
		}

		if (t.Flag1 == 0)
		{
			// Show the warning message
			MsgBox(hWnd, MB_ICONWARNING, _UU("SM_CERT_NEED_ROOT"));
		}

		FreeRpcKeyPair(&t);

		MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_CERT_SET_MSG"));
	}

	Zero(&t, sizeof(t));
	t.UseKeepConnect = IsChecked(hWnd, R_USE_KEEP_CONNECT);
	GetTxtA(hWnd, E_HOSTNAME, t.KeepConnectHost, sizeof(t.KeepConnectHost));
	t.KeepConnectPort = GetInt(hWnd, E_PORT);
	t.KeepConnectInterval = GetInt(hWnd, E_INTERVAL);
	t.KeepConnectProtocol = IsChecked(hWnd, R_UDP) ? 1 : 0;

	CALL(hWnd, ScSetKeep(s->p->Rpc, &t));

	if (GetCapsBool(s->p->CapsList, "b_support_syslog"))
	{
		if (s->p->ServerAdminMode)
		{
			SYSLOG_SETTING set;

			Zero(&set, sizeof(set));
			GetTxtA(hWnd, E_SYSLOG_HOSTNAME, set.Hostname, sizeof(set.Hostname));
			set.Port = GetInt(hWnd, E_SYSLOG_PORT);
			set.SaveType = CbGetSelect(hWnd, C_SYSLOG);

			if (CALL(hWnd, ScSetSysLog(s->p->Rpc, &set)) == false)
			{
				return;
			}
		}
	}

	EndDialog(hWnd, true);
}

// SSL related dialog initialization
void SmSslDlgInit(HWND hWnd, SM_SSL *s)
{
	UINT i;
	TOKEN_LIST *cipher_list;
	RPC_KEEP t;
	bool private_key_exportable = false;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (s->p != NULL)
	{
		RPC_STR t;
		Zero(&t, sizeof(t));

		SetFont(hWnd, C_CIPHER, GetFont("Tahoma", 8, false, false, false, false));
		CbSetHeight(hWnd, C_CIPHER, 18);

		// Get the list of available encryption algorithms from the server
		if (ScGetServerCipherList(s->p->Rpc, &t) == ERR_NO_ERROR)
		{
			cipher_list = ParseToken(t.String, ";");

			FreeRpcStr(&t);
			Zero(&t, sizeof(t));

			for (i = 0; i < cipher_list->NumTokens; i++)
			{
				wchar_t tmp[MAX_SIZE];
				char *name = cipher_list->Token[i];
				StrToUni(tmp, sizeof(tmp), name);
				CbAddStr(hWnd, C_CIPHER, tmp, 0);
			}

			FreeToken(cipher_list);
		}

		// Get the current encryption algorithm's name from the server
		if (CALL(hWnd, ScGetServerCipher(s->p->Rpc, &t)))
		{
			wchar_t tmp[MAX_SIZE];
			StrToUni(tmp, sizeof(tmp), t.String);
			SetText(hWnd, C_CIPHER, tmp);
			FreeRpcStr(&t);
		}
		else
		{
			EndDialog(hWnd, 0);
			return;
		}
	}

	if (s->p != NULL)
	{
		wchar_t tmp[MAX_SIZE];
		// Get the SSL certificate and private key from the server
		RPC_KEY_PAIR t;
		s->SetCertAndKey = false;
		Zero(&t, sizeof(t));
		if (CALL(hWnd, ScGetServerCert(s->p->Rpc, &t)))
		{
			// Copy the certificate and key
			s->Cert = CloneX(t.Cert);
			s->Key = CloneK(t.Key);

			if (t.Key != NULL)
			{
				private_key_exportable = true;
			}

			FreeRpcKeyPair(&t);
		}
		else
		{
			EndDialog(hWnd, 0);
			return;
		}

		// Show the Certificate Information
		SmGetCertInfoStr(tmp, sizeof(tmp), s->Cert);
		SetText(hWnd, S_CERT_INFO, tmp);
	}

	// Password change
	SetEnable(hWnd, B_PASSWORD, s->p->ServerAdminMode);
	SetEnable(hWnd, S_INFO4, s->p->ServerAdminMode);

	// Enable / disable the button
	SetEnable(hWnd, B_IMPORT, s->p->ServerAdminMode);
	SetEnable(hWnd, B_EXPORT, s->p->ServerAdminMode && private_key_exportable);
	SetEnable(hWnd, B_REGENERATE, s->p->ServerAdminMode);
	SetEnable(hWnd, R_USE_KEEP_CONNECT, s->p->ServerAdminMode);
	SetEnable(hWnd, B_UPDATE_CONFIG, s->p->Update != NULL);

	if (s->p->ServerAdminMode && GetCapsBool(s->p->CapsList, "b_support_special_listener"))
	{
		SetEnable(hWnd, B_SPECIALLISTENER, true);
		SetEnable(hWnd, S_INFO5, true);
	}
	else
	{
		SetEnable(hWnd, B_SPECIALLISTENER, false);
		SetEnable(hWnd, S_INFO5, false);
	}

	if (s->p->ServerAdminMode == false)
	{
		Disable(hWnd, C_CIPHER);
	}

	if (CALL(hWnd, ScGetKeep(s->p->Rpc, &t)))
	{
		Check(hWnd, R_USE_KEEP_CONNECT, t.UseKeepConnect);
		SetTextA(hWnd, E_HOSTNAME, t.KeepConnectHost);
		SetIntEx(hWnd, E_PORT, t.KeepConnectPort);
		SetInt(hWnd, E_INTERVAL, t.KeepConnectInterval);
		Check(hWnd, R_TCP, t.KeepConnectProtocol == 0);
		Check(hWnd, R_UDP, t.KeepConnectProtocol != 0);
	}

	CbSetHeight(hWnd, C_SYSLOG, 18);
	CbReset(hWnd, C_SYSLOG);
	CbAddStr(hWnd, C_SYSLOG, _UU("SM_SYSLOG_0"), SYSLOG_NONE);
	CbAddStr(hWnd, C_SYSLOG, _UU("SM_SYSLOG_1"), SYSLOG_SERVER_LOG);
	CbAddStr(hWnd, C_SYSLOG, _UU("SM_SYSLOG_2"), SYSLOG_SERVER_AND_HUB_SECURITY_LOG);
	CbAddStr(hWnd, C_SYSLOG, _UU("SM_SYSLOG_3"), SYSLOG_SERVER_AND_HUB_ALL_LOG);

	if (GetCapsBool(s->p->CapsList, "b_support_syslog"))
	{
		SYSLOG_SETTING set;

		SetEnable(hWnd, C_SYSLOG, s->p->ServerAdminMode);
		SetEnable(hWnd, E_SYSLOG_HOSTNAME, s->p->ServerAdminMode);
		SetEnable(hWnd, E_SYSLOG_PORT, s->p->ServerAdminMode);
		SetEnable(hWnd, S_01, s->p->ServerAdminMode);
		SetEnable(hWnd, S_02, s->p->ServerAdminMode);

		Zero(&set, sizeof(set));

		if (CALL(hWnd, ScGetSysLog(s->p->Rpc, &set)))
		{
			SetTextA(hWnd, E_SYSLOG_HOSTNAME, set.Hostname);
			SetInt(hWnd, E_SYSLOG_PORT, set.Port == 0 ? SYSLOG_PORT : set.Port);
			CbSelect(hWnd, C_SYSLOG, set.SaveType);
		}
	}
	else
	{
		Disable(hWnd, C_SYSLOG);
		Disable(hWnd, E_SYSLOG_HOSTNAME);
		Disable(hWnd, E_SYSLOG_PORT);
		Disable(hWnd, S_01);
		Disable(hWnd, S_02);
	}

	SmSslDlgUpdate(hWnd, s);
}

// SSL related dialog control update
void SmSslDlgUpdate(HWND hWnd, SM_SSL *s)
{
	bool ok = true;
	bool b;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	if (IsChecked(hWnd, R_USE_KEEP_CONNECT))
	{
		UINT i;
		b = true;
		if (IsEmpty(hWnd, E_HOSTNAME))
		{
			ok = false;
		}
		i = GetInt(hWnd, E_PORT);
		if (i == 0 || i >= 65536)
		{
			ok = false;
		}
		i = GetInt(hWnd, E_INTERVAL);
		if (i < 5 || i > 600)
		{
			ok = false;
		}
	}
	else
	{
		b = false;
	}

	if (IsEnable(hWnd, C_SYSLOG))
	{
		UINT i = CbGetSelect(hWnd, C_SYSLOG);

		SetEnable(hWnd, E_SYSLOG_HOSTNAME, i != SYSLOG_NONE);
		SetEnable(hWnd, E_SYSLOG_PORT, i != SYSLOG_NONE);
		SetEnable(hWnd, S_01, i != SYSLOG_NONE);
		SetEnable(hWnd, S_02, i != SYSLOG_NONE);
	}

	SetEnable(hWnd, S_HOSTNAME, b);
	SetEnable(hWnd, E_HOSTNAME, b);
	SetEnable(hWnd, S_PORT, b);
	SetEnable(hWnd, E_PORT, b);
	SetEnable(hWnd, S_INTERVAL, b);
	SetEnable(hWnd, E_INTERVAL, b);
	SetEnable(hWnd, S_INTERVAL2, b);
	SetEnable(hWnd, S_PROTOCOL, b);
	SetEnable(hWnd, R_TCP, b);
	SetEnable(hWnd, R_UDP, b);
	SetEnable(hWnd, S_INFO, b);

	SetEnable(hWnd, IDOK, ok);
}

// Get the certificate information string
void SmGetCertInfoStr(wchar_t *str, UINT size, X *x)
{
	wchar_t subject[MAX_SIZE];
	wchar_t issuer[MAX_SIZE];
	wchar_t date[MAX_SIZE];
	// Validate arguments
	if (x == NULL || str == NULL)
	{
		if (str != NULL)
		{
			str[0] = 0;
		}
		return;
	}

	GetPrintNameFromName(subject, sizeof(subject), x->subject_name);
	GetPrintNameFromName(issuer, sizeof(issuer), x->issuer_name);
	GetDateStrEx64(date, sizeof(date), x->notAfter, NULL);

	UniFormat(str, size, _UU("CM_CERT_INFO"), subject, issuer, date);
}

// Regenerate the server certificate
bool SmRegenerateServerCert(HWND hWnd, SM_SERVER *server, char *default_cn, X **x, K **k, bool root_only)
{
	char defcn[MAX_SIZE];
	// Validate arguments
	if (server == NULL || x == NULL || k == NULL)
	{
		return false;
	}

	Zero(defcn, sizeof(defcn));
	if (IsEmptyStr(default_cn) == false)
	{
		StrCpy(defcn, sizeof(defcn), default_cn);
	}

	if (IsEmptyStr(defcn))
	{
		// If default CN is not specified, copy from the setting of the DDNS server
		DDNS_CLIENT_STATUS t;

		Zero(&t, sizeof(t));

		if (ScGetDDnsClientStatus(server->Rpc, &t) == ERR_NO_ERROR)
		{
			if (IsEmptyStr(t.CurrentFqdn) == false)
			{
				StrCpy(defcn, sizeof(defcn), t.CurrentFqdn);
			}
		}
	}

	if (IsEmptyStr(defcn))
	{
		// Copy from the certificate information of the current server
		RPC_KEY_PAIR t;

		Zero(&t, sizeof(t));

		if (ScGetServerCert(server->Rpc, &t) == ERR_NO_ERROR)
		{
			if (t.Cert != NULL)
			{
				if (t.Cert->subject_name != NULL)
				{
					UniToStr(defcn, sizeof(defcn), t.Cert->subject_name->CommonName);
				}
			}

			FreeRpcKeyPair(&t);
		}
	}

	if (IsEmptyStr(defcn))
	{
		// Copy from the destination server name of the current connection settings
		StrCpy(defcn, sizeof(defcn), server->ServerName);
	}

	// Create a new certificate in the Certificate Creation Tool
	if (SmCreateCert(hWnd, x, k, true, defcn, root_only) == false)
	{
		return false;
	}

	return true;
}

// SSL related dialog procedure
UINT SmSslDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SSL *s = (SM_SSL *)param;
	X *x;
	K *k;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SmSslDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_USE_KEEP_CONNECT:
		case E_HOSTNAME:
		case E_PORT:
		case E_INTERVAL:
		case R_TCP:
		case R_UDP:
		case C_SYSLOG:
		case E_SYSLOG_HOSTNAME:
		case E_SYSLOG_PORT:
			SmSslDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			// [OK] button
			SmSslDlgOnOk(hWnd, s);
			break;

		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;

		case B_UPDATE_CONFIG:
			// Update notification setting
			ConfigUpdateUi(s->p->Update, hWnd);
			break;

		case B_IMPORT:
			// Import
			if (CmLoadXAndK(hWnd, &x, &k))
			{
				wchar_t tmp[MAX_SIZE];

LABEL_APPLY_NEW_CERT:
				FreeX(s->Cert);
				FreeK(s->Key);
				s->Cert = x;
				s->Key = k;
				s->SetCertAndKey = true;
				// Show the Certificate Information
				SmGetCertInfoStr(tmp, sizeof(tmp), s->Cert);
				SetText(hWnd, S_CERT_INFO, tmp);
			}
			break;

		case B_EXPORT:
			// Export
			SmSaveKeyPairDlg(hWnd, s->Cert, s->Key);
			break;

		case B_VIEW:
			// Show the certificate
			CertDlg(hWnd, s->Cert, NULL, true);
			break;

		case B_SPECIALLISTENER:
			// Special listener configuration
			SmSpecialListener(hWnd, s->p);
			break;

		case B_REGENERATE:
			// Regenerating the certificate
			if (SmRegenerateServerCert(hWnd, s->p, NULL, &x, &k, false))
			{
				// Confirmation message
				if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO, _UU("SM_REGENERATE_CERT_MSG")) == IDYES)
				{
					goto LABEL_APPLY_NEW_CERT;
				}
				else
				{
					FreeX(x);
					FreeK(k);
				}
			}
			break;

		case B_PASSWORD:
			// Password change
			Dialog(hWnd, D_SM_CHANGE_PASSWORD, SmChangeServerPasswordDlg, s->p);
			break;

		case R_USE_KEEP_CONNECT:
			if (IsChecked(hWnd, R_USE_KEEP_CONNECT))
			{
				FocusEx(hWnd, E_HOSTNAME);
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

// Display the SSL related dialog
void SmSslDlg(HWND hWnd, SM_SERVER *p)
{
	SM_SSL s;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	Zero(&s, sizeof(s));
	s.p = p;

	Dialog(hWnd, D_SM_SSL, SmSslDlgProc, &s);

	// Cleanup
	FreeX(s.Cert);
	FreeK(s.Key);
}

// Listener creation dialog procedure
UINT SmCreateListenerDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UINT port;
	RPC_LISTENER t;
	SM_SERVER *p = (SM_SERVER *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		Focus(hWnd, E_PORT);
		Disable(hWnd, IDOK);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PORT:
			port = GetInt(hWnd, E_PORT);
			if (port == 0 || port >= 65536)
			{
				Disable(hWnd, IDOK);
			}
			else
			{
				Enable(hWnd, IDOK);
			}
			break;
		}

		switch (wParam)
		{
		case IDOK:
			port = GetInt(hWnd, E_PORT);
			Zero(&t, sizeof(t));
			t.Enable = true;
			t.Port = port;
			if (CALL(hWnd, ScCreateListener(p->Rpc, &t)))
			{
				EndDialog(hWnd, true);
			}
			break;
		case IDCANCEL:
			Close(hWnd);
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Listener creation dialog
bool SmCreateListenerDlg(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_SM_CREATE_LISTENER, SmCreateListenerDlgProc, p);
}

// HUB edit OK button
void SmEditHubOnOk(HWND hWnd, SM_EDIT_HUB *s)
{
	RPC_CREATE_HUB t;
	char pass1[MAX_SIZE];
	char pass2[MAX_SIZE];
	char hubname[MAX_HUBNAME_LEN + 1];
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (s->EditMode)
	{
		StrCpy(hubname, sizeof(hubname), s->HubName);
		StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
	}
	else
	{
		GetTxtA(hWnd, E_HUBNAME, t.HubName, sizeof(t.HubName));
		StrCpy(hubname, sizeof(hubname), t.HubName);
	}

	GetTxtA(hWnd, E_PASSWORD1, pass1, sizeof(pass1));
	GetTxtA(hWnd, E_PASSWORD2, pass2, sizeof(pass2));

	if (s->EditMode == false || StrCmp(pass1, HIDDEN_PASSWORD) != 0)
	{
		Sha0(t.HashedPassword, pass1, StrLen(pass1));
		HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pass1);
	}

	if (IsChecked(hWnd, R_LIMIT_MAX_SESSION))
	{
		t.HubOption.MaxSession = GetInt(hWnd, E_MAX_SESSION);
	}

	t.Online = IsChecked(hWnd, R_ONLINE);

	if (s->p->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		t.HubType = HUB_TYPE_FARM_STATIC;
		if (IsChecked(hWnd, R_DYNAMIC))
		{
			t.HubType = HUB_TYPE_FARM_DYNAMIC;
		}
	}

	t.HubOption.NoEnum = IsChecked(hWnd, R_NO_ENUM);

	if (s->EditMode == false)
	{
		if (CALL(hWnd, ScCreateHub(s->p->Rpc, &t)))
		{
			MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("CM_EDIT_HUB_CREATED"), hubname);
			EndDialog(hWnd, true);
		}
	}
	else
	{
		if (CALL(hWnd, ScSetHub(s->p->Rpc, &t)))
		{
			EndDialog(hWnd, true);
		}
	}
}

// HUB editing update
void SmEditHubUpdate(HWND hWnd, SM_EDIT_HUB *s)
{
	bool ok = true;
	char *s1, *s2;
	char hubname[MAX_HUBNAME_LEN + 1];
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	s1 = GetTextA(hWnd, E_PASSWORD1);
	s2 = GetTextA(hWnd, E_PASSWORD2);
	if (StrCmp(s1, s2) != 0)
	{
		ok = false;
	}
	Free(s1);
	Free(s2);

	GetTxtA(hWnd, E_HUBNAME, hubname, sizeof(hubname));
	Trim(hubname);
	if (StrLen(hubname) == 0 ||
		IsSafeStr(hubname) == false)
	{
		ok = false;
	}

	if (IsChecked(hWnd, R_LIMIT_MAX_SESSION))
	{
		Enable(hWnd, E_MAX_SESSION);
		Enable(hWnd, S_MAX_SESSION_1);
		Enable(hWnd, S_MAX_SESSION_2);
		if (GetInt(hWnd, E_MAX_SESSION) == 0)
		{
			ok = false;
		}
	}
	else
	{
		Disable(hWnd, E_MAX_SESSION);
		Disable(hWnd, S_MAX_SESSION_1);
		Disable(hWnd, S_MAX_SESSION_2);
	}

	SetEnable(hWnd, IDOK, ok);
}

// HUB editing initialization
void SmEditHubInit(HWND hWnd, SM_EDIT_HUB *s)
{
	RPC_CREATE_HUB t;
	bool b = false;
	bool support_extoption = false;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_HUB);

	Zero(&t, sizeof(t));

	if (s->EditMode == false)
	{
		// Create new
		SetText(hWnd, 0, _UU("CM_EDIT_HUB_1"));
		FocusEx(hWnd, E_HUBNAME);

		if (s->p->ServerType == SERVER_TYPE_STANDALONE)
		{
			// Stand-alone mode
			Disable(hWnd, R_STATIC);
			Disable(hWnd, R_DYNAMIC);
			SetText(hWnd, S_FARM_INFO, _UU("CM_EDIT_HUB_STANDALONE"));
		}
		else
		{
			Check(hWnd, R_STATIC, true);
		}

		Check(hWnd, R_ONLINE, true);

		Hide(hWnd, B_ACL);
		Hide(hWnd, S_ACL);
		Hide(hWnd, S_ACL_2);
		Hide(hWnd, S_ACL_3);
		Hide(hWnd, S_MSG_1);
		Hide(hWnd, S_MSG_4);
		Hide(hWnd, S_MSG_2);
		Hide(hWnd, B_MSG);
	}
	else
	{
		// Edit
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("CM_EDIT_HUB_2"), s->HubName);
		SetText(hWnd, 0, tmp);
		SetTextA(hWnd, E_HUBNAME, s->HubName);
		Disable(hWnd, E_HUBNAME);

		if (s->p->ServerType == SERVER_TYPE_STANDALONE)
		{
			// Stand-alone mode
			Disable(hWnd, R_STATIC);
			Disable(hWnd, R_DYNAMIC);
			SetText(hWnd, S_FARM_INFO, _UU("CM_EDIT_HUB_STANDALONE"));
		}

		if (s->p->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			// Controller
			if (GetCapsBool(s->p->CapsList, "b_cluster_hub_type_fixed"))
			{
				Disable(hWnd, R_STATIC);
				Disable(hWnd, R_DYNAMIC);
				SetText(hWnd, S_FARM_INFO, _UU("CM_EDIT_HUB_TYPE_FIXED"));
			}
		}

		// Get the HUB information
		StrCpy(t.HubName, sizeof(t.HubName), s->HubName);
		if (CALL(hWnd, ScGetHub(s->p->Rpc, &t)) == false)
		{
			EndDialog(hWnd, false);
			return;
		}

		SetTextA(hWnd, E_PASSWORD1, HIDDEN_PASSWORD);
		SetTextA(hWnd, E_PASSWORD2, HIDDEN_PASSWORD);

		if (t.HubOption.MaxSession == 0)
		{
			Check(hWnd, R_LIMIT_MAX_SESSION, false);
		}
		else
		{
			Check(hWnd, R_LIMIT_MAX_SESSION, true);
		}

		Check(hWnd, R_NO_ENUM, t.HubOption.NoEnum);

		SetIntEx(hWnd, E_MAX_SESSION, t.HubOption.MaxSession);

		Check(hWnd, R_ONLINE, t.Online);
		Check(hWnd, R_OFFLINE, t.Online ? false : true);

		Check(hWnd, R_STATIC, t.HubType == HUB_TYPE_FARM_STATIC);
		Check(hWnd, R_DYNAMIC, t.HubType == HUB_TYPE_FARM_DYNAMIC);

		SetShow(hWnd, B_ACL, GetCapsBool(s->p->CapsList, "b_support_ac"));
		SetShow(hWnd, S_ACL, GetCapsBool(s->p->CapsList, "b_support_ac"));
		SetShow(hWnd, S_ACL_2, GetCapsBool(s->p->CapsList, "b_support_ac"));
		SetShow(hWnd, S_ACL_3, GetCapsBool(s->p->CapsList, "b_support_ac"));

		SetShow(hWnd, S_MSG_1, GetCapsBool(s->p->CapsList, "b_support_msg"));
		SetShow(hWnd, S_MSG_4, GetCapsBool(s->p->CapsList, "b_support_msg"));
		SetShow(hWnd, S_MSG_2, GetCapsBool(s->p->CapsList, "b_support_msg"));
		SetShow(hWnd, B_MSG, GetCapsBool(s->p->CapsList, "b_support_msg"));
	}

	// Advanced options
	if (s->EditMode)
	{
		support_extoption = GetCapsBool(s->p->CapsList, "b_support_hub_ext_options");
	}

	SetEnable(hWnd, S_STATIC, support_extoption);
	SetEnable(hWnd, B_EXTOPTION, support_extoption);

	SetEnable(hWnd, R_NO_ENUM, GetCapsBool(s->p->CapsList, "b_support_hide_hub"));

	SmEditHubUpdate(hWnd, s);

	if (s->EditMode)
	{
		Focus(hWnd, IDOK);
	}

	if (s->EditMode)
	{
		if (GetCapsBool(s->p->CapsList, "b_support_hub_admin_option"))
		{
			b = true;
		}
	}

	SetShow(hWnd, S_AO_1, b);
	SetShow(hWnd, S_AO_2, b);
	SetShow(hWnd, S_AO_3, b);
	SetShow(hWnd, B_ADMINOPTION, b);
}

// HUB edit procedure
UINT SmEditHubProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_HUB *s = (SM_EDIT_HUB *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmEditHubInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_PASSWORD1:
		case E_PASSWORD2:
		case E_HUBNAME:
		case R_LIMIT_MAX_SESSION:
		case E_MAX_SESSION:
			SmEditHubUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmEditHubOnOk(hWnd, s);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case R_LIMIT_MAX_SESSION:
			if (IsChecked(hWnd, R_LIMIT_MAX_SESSION))
			{
				FocusEx(hWnd, E_MAX_SESSION);
			}
			break;

		case B_ADMINOPTION:
			SmHubAdminOption(hWnd, s);
			break;

		case B_EXTOPTION:
			SmHubExtOption(hWnd, s);
			break;

		case B_ACL:
			SmHubAc(hWnd, s);
			break;

		case B_MSG:
			SmHubMsg(hWnd, s);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// HUB edit dialog
bool SmEditHubDlg(HWND hWnd, SM_SERVER *p, char *hubname)
{
	SM_EDIT_HUB s;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	Zero(&s, sizeof(s));
	s.p = p;
	s.EditMode = true;
	StrCpy(s.HubName, sizeof(s.HubName), hubname);

	if (p->Bridge == false)
	{
		return Dialog(hWnd, D_SM_EDIT_HUB, SmEditHubProc, &s);
	}
	else
	{
		SmHubExtOption(hWnd, &s);
		return false;
	}
}

// HUB creation dialog
bool SmCreateHubDlg(HWND hWnd, SM_SERVER *p)
{
	SM_EDIT_HUB s;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return false;
	}

	Zero(&s, sizeof(s));
	s.p = p;
	s.EditMode = false;

	return Dialog(hWnd, D_SM_EDIT_HUB, SmEditHubProc, &s);
}

// Display the status of the virtual HUB
bool SmRefreshHubStatus(HWND hWnd, SM_SERVER *p, void *param)
{
	RPC_HUB_STATUS t;
	// Validate arguments
	if (hWnd == NULL || p == NULL || param == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(RPC_HUB_STATUS));
	StrCpy(t.HubName, sizeof(t.HubName), (char *)param);
	if (CALL(hWnd, ScGetHubStatus(p->Rpc, &t)))
	{
		wchar_t *s;
		wchar_t tmp[MAX_SIZE];
		LVB *b = LvInsertStart();

		// HUB name
		s = CopyStrToUni((char *)param);
		LvInsertAdd(b, ICO_HUB, 0, 2, _UU("SM_HUB_STATUS_HUBNAME"), s);
		Free(s);

		// Online
		LvInsertAdd(b, t.Online ? ICO_PROTOCOL : ICO_PROTOCOL_X, 0, 2, _UU("SM_HUB_STATUS_ONLINE"),
			t.Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"));

		// Type of HUB
		LvInsertAdd(b, t.HubType == HUB_TYPE_STANDALONE ? ICO_TOWER : ICO_FARM, 0, 2, _UU("SM_HUB_TYPE"),
			GetHubTypeStr(t.HubType));

		if (t.HubType == HUB_TYPE_STANDALONE)
		{
			// Enable / Disable the SecureNAT
			LvInsertAdd(b, ICO_ROUTER, NULL, 2, _UU("SM_HUB_SECURE_NAT"),
				t.SecureNATEnabled ? _UU("SM_HUB_SECURE_NAT_YES") : _UU("SM_HUB_SECURE_NAT_NO"));
		}

		// Other values
		UniToStru(tmp, t.NumSessions);
		LvInsertAdd(b, ICO_PROTOCOL, 0, 2, _UU("SM_HUB_NUM_SESSIONS"), tmp);
		if (t.NumSessionsClient != 0 || t.NumSessionsBridge != 0)
		{
			UniToStru(tmp, t.NumSessionsClient);
			LvInsertAdd(b, ICO_PROTOCOL, 0, 2, _UU("SM_HUB_NUM_SESSIONS_CLIENT"), tmp);
			UniToStru(tmp, t.NumSessionsBridge);
			LvInsertAdd(b, ICO_PROTOCOL, 0, 2, _UU("SM_HUB_NUM_SESSIONS_BRIDGE"), tmp);
		}

		UniToStru(tmp, t.NumAccessLists);
		LvInsertAdd(b, ICO_DISCARD, 0, 2, _UU("SM_HUB_NUM_ACCESSES"), tmp);

		if (p->ServerType != SERVER_TYPE_FARM_MEMBER)
		{
			UniToStru(tmp, t.NumUsers);
			LvInsertAdd(b, ICO_USER, 0, 2, _UU("SM_HUB_NUM_USERS"), tmp);
			UniToStru(tmp, t.NumGroups);
			LvInsertAdd(b, ICO_GROUP, 0, 2, _UU("SM_HUB_NUM_GROUPS"), tmp);
		}

		UniToStru(tmp, t.NumMacTables);
		LvInsertAdd(b, ICO_MACHINE, 0, 2, _UU("SM_HUB_NUM_MAC_TABLES"), tmp);
		UniToStru(tmp, t.NumIpTables);
		LvInsertAdd(b, ICO_MACHINE, 0, 2, _UU("SM_HUB_NUM_IP_TABLES"), tmp);

		// Usage status
		UniToStru(tmp, t.NumLogin);
		LvInsertAdd(b, ICO_KEY, NULL, 2, _UU("SM_HUB_NUM_LOGIN"), tmp);

		if (t.LastLoginTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastLoginTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		LvInsertAdd(b, ICO_DATETIME, NULL, 2, _UU("SM_HUB_LAST_LOGIN_TIME"), tmp);

		if (t.LastCommTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastCommTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		LvInsertAdd(b, ICO_DATETIME, NULL, 2, _UU("SM_HUB_LAST_COMM_TIME"), tmp);

		if (t.CreatedTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		LvInsertAdd(b, ICO_DATETIME, NULL, 2, _UU("SM_HUB_CREATED_TIME"), tmp);

		// Traffic information
		SmInsertTrafficInfo(b, &t.Traffic);

		LvInsertEnd(b, hWnd, L_STATUS);
	}
	else
	{
		return false;
	}

	return true;
}

// Add a traffic information to LVB
void SmInsertTrafficInfo(LVB *b, TRAFFIC *t)
{
	wchar_t tmp[MAX_SIZE];
	char vv[128];
	// Validate arguments
	if (b == NULL || t == NULL)
	{
		return;
	}

	// Transmission information
	ToStr3(vv, sizeof(vv), t->Send.UnicastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_SEND_UCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.UnicastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_SEND_UCAST_SIZE"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.BroadcastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_SEND_BCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.BroadcastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_SEND_BCAST_SIZE"), tmp);

	// Reception information
	ToStr3(vv, sizeof(vv), t->Recv.UnicastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_RECV_UCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.UnicastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_RECV_UCAST_SIZE"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.BroadcastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_RECV_BCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.BroadcastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	LvInsertAdd(b, ICO_INFORMATION, 0, 2, _UU("SM_ST_RECV_BCAST_SIZE"), tmp);
}

// Status display dialog procedure
UINT SmStatusDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_STATUS *s = (SM_STATUS *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		LvInitEx(hWnd, L_STATUS, s->NoImage);
		LvSetStyle(hWnd, L_STATUS, LVS_EX_GRIDLINES);
		SetIcon(hWnd, 0, s->Icon);
		SetIcon(hWnd, S_ICON, s->Icon);
		SetText(hWnd, 0, s->Caption);
		SetText(hWnd, S_TITLE, s->Caption);
		DlgFont(hWnd, S_TITLE, 15, true);
		if (s->InitProc != NULL)
		{
			s->InitProc(hWnd, s->p, s->Param);
		}
		else
		{
			// Initialize the column
			LvInsertColumn(hWnd, L_STATUS, 0, _UU("SM_STATUS_COLUMN_1"), 0);
			LvInsertColumn(hWnd, L_STATUS, 1, _UU("SM_STATUS_COLUMN_2"), 0);
		}
		if (s->RefreshProc(hWnd, s->p, s->Param) == false)
		{
			Close(hWnd);
		}
		LvAutoSize(hWnd, L_STATUS);
		Focus(hWnd, L_STATUS);

		if (s->show_refresh_button == false)
		{
			Hide(hWnd, IDOK);
		}

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// Update
			if (s->RefreshProc(hWnd, s->p, s->Param) == false)
			{
				Close(hWnd);
			}
			LvAutoSize(hWnd, L_STATUS);
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

	LvStandardHandler(hWnd, msg, wParam, lParam, L_STATUS);

	return 0;
}

// Status display dialog
void SmStatusDlg(HWND hWnd, SM_SERVER *p, void *param, bool no_image, bool show_refresh_button, wchar_t *caption, UINT icon,
				 SM_STATUS_INIT_PROC *init, SM_STATUS_REFRESH_PROC *refresh)
{
	SM_STATUS s;
	// Validate arguments
	if (hWnd == NULL || p == NULL || refresh == NULL)
	{
		return;
	}

	if (icon == 0)
	{
		icon = ICO_INFORMATION;
	}
	if (caption == NULL)
	{
		caption = _UU("SM_INFORMATION");
	}

	Zero(&s, sizeof(s));
	s.show_refresh_button = show_refresh_button;
	s.p = p;
	s.NoImage = no_image;
	s.Param = param;
	s.Icon = icon;
	s.Caption = caption;
	s.InitProc = init;
	s.RefreshProc = refresh;

	Dialog(hWnd, D_SM_STATUS, SmStatusDlgProc, &s);
}

// Server management dialog update
void SmServerDlgUpdate(HWND hWnd, SM_SERVER *p)
{
	bool hub_selected = false;
	bool hub_selected_online = false;
	bool hub_selected_offline = false;
	bool hub_have_admin_right = false;
	bool listener_selected = false;
	bool listener_selected_enabled = false;
	bool listener_selected_disabled = false;
	bool two_or_more_listener = false;
	bool bridge;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	bridge = GetCapsBool(p->CapsList, "b_bridge");

	hub_selected = LvIsSelected(hWnd, L_HUB);

	if (hub_selected)
	{
		if (p->ServerAdminMode)
		{
			hub_have_admin_right = true;
		}
		i = LvGetSelected(hWnd, L_HUB);
		if (i != INFINITE)
		{
			wchar_t *s = LvGetStr(hWnd, L_HUB, i, 1);
			if (p->ServerAdminMode == false)
			{
				char *hubname = LvGetStrA(hWnd, L_HUB, i, 0);
				if (hubname != NULL)
				{
					if (StrCmpi(hubname, p->HubName) == 0)
					{
						hub_have_admin_right = true;
					}
					Free(hubname);
				}
			}
			hub_selected_online = (UniStrCmpi(s, _UU("SM_HUB_ONLINE")) == 0);
			hub_selected_offline = hub_selected_online ? false : true;
			Free(s);
		}
	}

	listener_selected = LvIsSelected(hWnd, L_LISTENER);
	if (listener_selected)
	{
		wchar_t *s = LvGetSelectedStr(hWnd, L_LISTENER, 1);
		if (UniStrCmpi(s, _UU("CM_LISTENER_OFFLINE")) == 0)
		{
			listener_selected_disabled = true;
		}
		else
		{
			listener_selected_enabled = true;
		}
		Free(s);
	}

	if (LvNum(hWnd, L_LISTENER) >= 2)
	{
		two_or_more_listener = true;
	}

	SetEnable(hWnd, IDOK, bridge || (hub_selected && hub_have_admin_right));
	SetEnable(hWnd, B_ONLINE, bridge == false && hub_selected_offline && hub_have_admin_right && p->ServerType != SERVER_TYPE_FARM_MEMBER);
	SetEnable(hWnd, B_OFFLINE, bridge == false && hub_selected_online && hub_have_admin_right && p->ServerType != SERVER_TYPE_FARM_MEMBER);
	SetEnable(hWnd, B_HUB_STATUS, hub_selected && hub_have_admin_right);
	SetEnable(hWnd, B_DELETE, bridge == false && hub_selected && p->ServerAdminMode && p->ServerType != SERVER_TYPE_FARM_MEMBER);
	SetEnable(hWnd, B_EDIT, hub_selected && hub_have_admin_right && p->ServerType != SERVER_TYPE_FARM_MEMBER);
	SetEnable(hWnd, B_CREATE, bridge == false && p->ServerAdminMode && p->ServerType != SERVER_TYPE_FARM_MEMBER);

	SetEnable(hWnd, B_CREATE_LISTENER, p->ServerAdminMode);
	SetEnable(hWnd, B_DELETE_LISTENER, p->ServerAdminMode && listener_selected && two_or_more_listener);
	SetEnable(hWnd, B_START, p->ServerAdminMode && listener_selected_disabled);
	SetEnable(hWnd, B_STOP, p->ServerAdminMode && listener_selected_enabled);
	SetEnable(hWnd, B_FARM, GetCapsBool(p->CapsList, "b_support_cluster") && p->ServerAdminMode && GetCapsBool(p->CapsList, "b_support_vgs_in_client") == false);
	SetEnable(hWnd, B_FARM_STATUS, GetCapsBool(p->CapsList, "b_support_cluster") && p->ServerType != SERVER_TYPE_STANDALONE);
}

// Server management dialog initialization
void SmServerDlgInit(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	// Initialize the column
	LvInit(hWnd, L_HUB);
	LvSetStyle(hWnd, L_HUB, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_HUB, 0, _UU("SM_HUB_COLUMN_1"), 150);
	LvInsertColumn(hWnd, L_HUB, 1, _UU("SM_HUB_COLUMN_2"), 80);
	LvInsertColumn(hWnd, L_HUB, 2, _UU("SM_HUB_COLUMN_3"), 80);
	LvInsertColumn(hWnd, L_HUB, 3, _UU("SM_HUB_COLUMN_4"), 80);
	LvInsertColumn(hWnd, L_HUB, 4, _UU("SM_HUB_COLUMN_5"), 80);
	LvInsertColumn(hWnd, L_HUB, 5, _UU("SM_HUB_COLUMN_6"), 80);
	LvInsertColumn(hWnd, L_HUB, 6, _UU("SM_HUB_COLUMN_7"), 80);
	LvInsertColumn(hWnd, L_HUB, 7, _UU("SM_HUB_COLUMN_8"), 80);
	LvInsertColumn(hWnd, L_HUB, 8, _UU("SM_HUB_COLUMN_9"), 80);
	LvInsertColumn(hWnd, L_HUB, 9, _UU("SM_HUB_COLUMN_10"), 120);
	LvInsertColumn(hWnd, L_HUB, 10, _UU("SM_HUB_COLUMN_11"), 120);
	LvInsertColumn(hWnd, L_HUB, 11, _UU("SM_SESS_COLUMN_6"), 100);
	LvInsertColumn(hWnd, L_HUB, 12, _UU("SM_SESS_COLUMN_7"), 100);

	LvInit(hWnd, L_LISTENER);
	LvSetStyle(hWnd, L_LISTENER, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_LISTENER, 0, _UU("CM_LISTENER_COLUMN_1"), 90);
	LvInsertColumn(hWnd, L_LISTENER, 1, _UU("CM_LISTENER_COLUMN_2"), 80);

	SmServerDlgRefresh(hWnd, p);

	if (p->ServerAdminMode == false)
	{
		// Select the target HUB in the case of the Virtual HUB management mode
		wchar_t *s = CopyStrToUni(p->HubName);
		LvSelect(hWnd, L_HUB, LvSearchStr(hWnd, L_HUB, 0, s));
		Free(s);
	}
	else
	{
		// In the case of whole server management mode
		UINT num_hubs = LvNum(hWnd, L_HUB);

		if (num_hubs == 1)
		{
			// Select the Virtual HUB if Virtual HUB exists only one
			LvSelect(hWnd, L_HUB, 0);
		}
		else
		{
			// Select the Virtual HUB the last selected if there are some virtual HUBs
			char tmp[MAX_SIZE];
			char *hubname;

			Format(tmp, sizeof(tmp), "%s:%u:%s", p->CurrentSetting->ClientOption.Hostname,
				p->CurrentSetting->ClientOption.Port,
				p->CurrentSetting->ServerAdminMode ? "" : p->CurrentSetting->HubName);

			hubname = MsRegReadStr(REG_CURRENT_USER, SM_LASTHUB_REG_KEY, tmp);

			if (IsEmptyStr(hubname) == false)
			{
				LvSelect(hWnd, L_HUB, LvSearchStrA(hWnd, L_HUB, 0, hubname));
			}

			Free(hubname);
		}
	}

	Focus(hWnd, L_HUB);

	SmServerDlgUpdate(hWnd, p);

	if (GetCapsBool(p->CapsList, "b_bridge"))
	{
		Disable(hWnd, L_HUB);
	}

	// Enable Local bridge button, etc. in the case of the Admin of the Server
	SetEnable(hWnd, B_BRIDGE, GetCapsBool(p->CapsList, "b_local_bridge") && p->ServerAdminMode && GetCapsBool(p->CapsList, "b_support_vgs_in_client") == false);
	SetEnable(hWnd, B_CONNECTION, p->ServerAdminMode);

	// Config R/W button
	SetEnable(hWnd, B_CONFIG, GetCapsBool(p->CapsList, "b_support_config_rw") && p->ServerAdminMode && GetCapsBool(p->CapsList, "b_support_vgs_in_client") == false);

	// Layer 3 button
	SetEnable(hWnd, B_L3, GetCapsBool(p->CapsList, "b_support_layer3") && p->ServerAdminMode && GetCapsBool(p->CapsList, "b_support_vgs_in_client") == false);

	// License button
	SetShow(hWnd, B_LICENSE, GetCapsBool(p->CapsList, "b_support_license") && p->ServerAdminMode);
	SetShow(hWnd, S_LICENSE, GetCapsBool(p->CapsList, "b_support_license") && p->ServerAdminMode);
	SetShow(hWnd, S_BETA, GetCapsBool(p->CapsList, "b_beta_version") && (IsShow(hWnd, B_LICENSE) == false));

	// IPsec button
	SetEnable(hWnd, B_IPSEC, GetCapsBool(p->CapsList, "b_support_ipsec") && p->ServerAdminMode);

	// OpenVPN, SSTP button
	SetEnable(hWnd, B_OPENVPN, GetCapsBool(p->CapsList, "b_support_openvpn") && p->ServerAdminMode);

	// DDNS button
	SetEnable(hWnd, B_DDNS, GetCapsBool(p->CapsList, "b_support_ddns") && p->ServerAdminMode);

	// VPN Azure button
	SetEnable(hWnd, B_AZURE, GetCapsBool(p->CapsList, "b_support_azure") && p->ServerAdminMode);

	DlgFont(hWnd, S_BETA, 12, false);
	SetFont(hWnd, E_DDNS_HOST, GetFont("Verdana", 10, false, false, false, false));
	SetFont(hWnd, E_AZURE_HOST, GetFont("Verdana", 10, false, false, false, false));

	SetShow(hWnd, B_VPNGATE, false);
	SetShow(hWnd, S_ICO_VPNGATE, false);

	DlgFont(hWnd, IDOK, 0, true);
}

// Server management dialog update
void SmServerDlgRefresh(HWND hWnd, SM_SERVER *p)
{
	RPC_ENUM_HUB t;
	RPC_LISTENER_LIST t2;
	RPC_PORTS t3;
	DDNS_CLIENT_STATUS st;
	RPC_AZURE_STATUS sta;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	// Virtual HUB list update
	Zero(&t, sizeof(t));
	if (CALL(hWnd, ScEnumHub(p->Rpc, &t)))
	{
		LVB *b = LvInsertStart();
		for (i = 0;i < t.NumHub;i++)
		{
			RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];
			wchar_t name[MAX_HUBNAME_LEN + 1];
			wchar_t s1[64], s2[64], s3[64], s4[64], s5[64];
			wchar_t s6[64], s7[128], s8[128];
			wchar_t s9[64], s10[64];
			UINT icon;

			UniToStru(s1, e->NumUsers);
			UniToStru(s2, e->NumGroups);
			UniToStru(s3, e->NumSessions);
			UniToStru(s4, e->NumMacTables);
			UniToStru(s5, e->NumIpTables);

			UniToStru(s6, e->NumLogin);

			if (e->LastLoginTime != 0)
			{
				GetDateTimeStr64Uni(s7, sizeof(s7), SystemToLocal64(e->LastLoginTime));
			}
			else
			{
				UniStrCpy(s7, sizeof(s7), _UU("COMMON_UNKNOWN"));
			}

			if (e->LastCommTime != 0)
			{
				GetDateTimeStr64Uni(s8, sizeof(s8), SystemToLocal64(e->LastCommTime));
			}
			else
			{
				UniStrCpy(s8, sizeof(s8), _UU("COMMON_UNKNOWN"));
			}

			StrToUni(name, sizeof(name), e->HubName);

			icon = ICO_HUB;
			if (e->Online == false)
			{
				icon = ICO_HUB_OFFLINE;
			}

			if (e->IsTrafficFilled == false)
			{
				UniStrCpy(s9, sizeof(s9), _UU("CM_ST_NONE"));
				UniStrCpy(s10, sizeof(s10), _UU("CM_ST_NONE"));
			}
			else
			{
				UniToStr3(s9, sizeof(s9),
					e->Traffic.Recv.BroadcastBytes + e->Traffic.Recv.UnicastBytes +
					e->Traffic.Send.BroadcastBytes + e->Traffic.Send.UnicastBytes);

				UniToStr3(s10, sizeof(s10),
					e->Traffic.Recv.BroadcastCount + e->Traffic.Recv.UnicastCount +
					e->Traffic.Send.BroadcastCount + e->Traffic.Send.UnicastCount);
			}

			LvInsertAdd(b,
				icon,
				NULL,
				13,
				name,
				e->Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"),
				GetHubTypeStr(e->HubType),
				s1, s2, s3, s4, s5, s6, s7, s8, s9, s10);
		}
		LvInsertEnd(b, hWnd, L_HUB);
		FreeRpcEnumHub(&t);
	}

	// Listener list update
	Zero(&t2, sizeof(RPC_LISTENER_LIST));
	if (CALL(hWnd, ScEnumListener(p->Rpc, &t2)))
	{
		LVB *b = LvInsertStart();
		for (i = 0;i < t2.NumPort;i++)
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t *status;
			UINT icon;
			UniFormat(tmp, sizeof(tmp), _UU("CM_LISTENER_TCP_PORT"), t2.Ports[i]);

			status = _UU("CM_LISTENER_ONLINE");
			icon = ICO_PROTOCOL;
			if (t2.Errors[i])
			{
				status = _UU("CM_LISTENER_ERROR");
				icon = ICO_PROTOCOL_X;
			}
			else if (t2.Enables[i] == false)
			{
				status = _UU("CM_LISTENER_OFFLINE");
				icon = ICO_PROTOCOL_OFFLINE;
			}

			LvInsertAdd(b, icon, (void *)t2.Ports[i], 2, tmp, status);
		}
		LvInsertEnd(b, hWnd, L_LISTENER);
		FreeRpcListenerList(&t2);
	}

	// Get the UDP ports
	Zero(&t3, sizeof(RPC_PORTS));
	if (CALL(hWnd, ScGetPortsUDP(p->Rpc, &t3)))
	{
		char str[MAX_SIZE];

		Zero(str, sizeof(str));

		if (t3.Num > 0)
		{
			UINT i;

			Format(str, sizeof(str), "%u", t3.Ports[0]);

			for (i = 1; i < t3.Num; ++i)
			{
				char tmp[MAX_SIZE];
				Format(tmp, sizeof(tmp), ", %u", t3.Ports[i]);
				StrCat(str, sizeof(str), tmp);
			}
		}

		SetTextA(hWnd, E_UDP, str);
		FreeRpcPorts(&t3);
	}

	// Get the DDNS client state
	Zero(&st, sizeof(st));
	if (ScGetDDnsClientStatus(p->Rpc, &st) == ERR_NO_ERROR && IsEmptyStr(st.CurrentFqdn) == false)
	{
		SetTextA(hWnd, E_DDNS_HOST, st.CurrentFqdn);

		Show(hWnd, S_DDNS);
		Show(hWnd, E_DDNS_HOST);
	}
	else
	{
		Hide(hWnd, S_DDNS);
		Hide(hWnd, E_DDNS_HOST);
	}

	// VPN Azure client state acquisition
	Zero(&sta, sizeof(sta));
	if (ScGetAzureStatus(p->Rpc, &sta) == ERR_NO_ERROR && sta.IsEnabled && IsEmptyStr(st.CurrentFqdn) == false)
	{
		char tmp[MAX_SIZE];

		StrCpy(tmp, sizeof(tmp), st.CurrentHostName);
		StrCat(tmp, sizeof(tmp), AZURE_DOMAIN_SUFFIX);

		SetTextA(hWnd, E_AZURE_HOST, tmp);

		Show(hWnd, S_AZURE);
		Show(hWnd, E_AZURE_HOST);
	}
	else
	{
		Hide(hWnd, S_AZURE);
		Hide(hWnd, E_AZURE_HOST);
	}

	SmServerDlgUpdate(hWnd, p);
}

// Server management dialog procedure
UINT SmServerDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_SERVER *p = (SM_SERVER *)param;
	wchar_t *s;
	wchar_t tmp[MAX_SIZE];
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
		FormatText(hWnd, 0, p->Title);

		if (p->Bridge == false)
		{
			FormatText(hWnd, S_TITLE, p->ServerName);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("SM_SERVER_BRIDGE_TITLE"), p->ServerName);
			SetText(hWnd, S_TITLE, tmp);
		}

		DlgFont(hWnd, S_TITLE, 16, 1);

		SetIcon(hWnd, 0, p->Bridge == false ? ICO_VPNSERVER : ICO_BRIDGE);

		SmServerDlgInit(hWnd, p);

		SetTimer(hWnd, 1, 50, NULL);

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			// Management
			if (IsEnable(hWnd, IDOK))
			{
				if (p->Bridge == false)
				{
					s = LvGetSelectedStr(hWnd, L_HUB, 0);
				}
				else
				{
					s = CopyUniStr(L"BRIDGE");
				}
				if (s != NULL)
				{
					char hubname[MAX_HUBNAME_LEN + 1];
					SM_HUB hub;
					Zero(&hub, sizeof(hub));
					UniToStr(hubname, sizeof(hubname), s);
					hub.p = p;
					hub.Rpc = p->Rpc;
					hub.HubName = hubname;
					SmHubDlg(hWnd, &hub);
					//SmServerDlgRefresh(hWnd, p);
					Free(s);
				}
			}
			break;

		case B_ONLINE:
			// Online
			s = LvGetSelectedStr(hWnd, L_HUB, 0);
			if (s != NULL)
			{
				RPC_SET_HUB_ONLINE t;
				Zero(&t, sizeof(t));
				UniToStr(t.HubName, sizeof(t.HubName), s);
				t.Online = true;
				if (CALL(hWnd, ScSetHubOnline(p->Rpc, &t)))
				{
					SmServerDlgRefresh(hWnd, p);
				}
				Free(s);
			}
			break;

		case B_OFFLINE:
			// Offline
			s = LvGetSelectedStr(hWnd, L_HUB, 0);
			if (s != NULL)
			{
				RPC_SET_HUB_ONLINE t;
				Zero(&t, sizeof(t));
				// Confirmation message
				if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
					_UU("CM_OFFLINE_MSG"), s) == IDYES)
				{
					UniToStr(t.HubName, sizeof(t.HubName), s);
					t.Online = false;
					if (CALL(hWnd, ScSetHubOnline(p->Rpc, &t)))
					{
						SmServerDlgRefresh(hWnd, p);
					}
				}
				Free(s);
			}
			break;

		case B_HUB_STATUS:
			// Status of HUB
			s = LvGetSelectedStr(hWnd, L_HUB, 0);
			if (s != NULL)
			{
				wchar_t tmp[MAX_SIZE];
				char *hubname = CopyUniToStr(s);
				UniFormat(tmp, sizeof(tmp), _UU("SM_HUB_STATUS_CAPTION"), s);
				SmStatusDlg(hWnd, p, hubname, false, true, tmp, ICO_HUB,
					NULL, SmRefreshHubStatus);
				Free(hubname);
				Free(s);
			}
			break;

		case B_CREATE:
			// Create a HUB
			if (SmCreateHubDlg(hWnd, p))
			{
				SmServerDlgRefresh(hWnd, p);
			}
			break;

		case B_EDIT:
			// Edit the HUB
			s = LvGetSelectedStr(hWnd, L_HUB, 0);
			if (s != NULL)
			{
				char *name = CopyUniToStr(s);
				if (SmEditHubDlg(hWnd, p, name))
				{
					SmServerDlgRefresh(hWnd, p);
				}
				Free(name);
				Free(s);
			}
			break;

		case B_DELETE:
			// Delete the HUB
			s = LvGetSelectedStr(hWnd, L_HUB, 0);
			if (s != NULL)
			{
				char *name = CopyUniToStr(s);
				RPC_DELETE_HUB t;
				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), name);
				if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_DELETE_HUB_MSG"), name) == IDYES)
				{
					if (CALL(hWnd, ScDeleteHub(p->Rpc, &t)))
					{
						SmServerDlgRefresh(hWnd, p);
						MsgBoxEx(hWnd, MB_ICONINFORMATION, _UU("CM_HUB_DELETED_MSG"), name);
					}
				}
				Free(name);
				Free(s);
			}
			break;

		case B_CREATE_LISTENER:
			// Create a listener
			if (SmCreateListenerDlg(hWnd, p))
			{
				SmServerDlgRefresh(hWnd, p);
			}
			break;

		case B_DELETE_LISTENER:
			// Remove the listener
			i = LvGetSelected(hWnd, L_LISTENER);
			if (i != INFINITE)
			{
				UINT port = (UINT)LvGetParam(hWnd, L_LISTENER, i);
				if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_DELETE_LISTENER_MSG"), port) == IDYES)
				{
					RPC_LISTENER t;
					Zero(&t, sizeof(t));
					t.Enable = false;
					t.Port = port;

					if (CALL(hWnd, ScDeleteListener(p->Rpc, &t)))
					{
						SmServerDlgRefresh(hWnd, p);
					}
				}
			}
			break;

		case B_START:
			// Start
			i = LvGetSelected(hWnd, L_LISTENER);
			if (i != INFINITE)
			{
				UINT port = (UINT)LvGetParam(hWnd, L_LISTENER, i);
				RPC_LISTENER t;
				Zero(&t, sizeof(t));
				t.Enable = true;
				t.Port = port;

				if (CALL(hWnd, ScEnableListener(p->Rpc, &t)))
				{
					SmServerDlgRefresh(hWnd, p);
				}
			}
			break;

		case B_STOP:
			// Stop
			i = LvGetSelected(hWnd, L_LISTENER);
			if (i != INFINITE)
			{
				UINT port = (UINT)LvGetParam(hWnd, L_LISTENER, i);
				if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("CM_STOP_LISTENER_MSG"), port) == IDYES)
				{
					RPC_LISTENER t;
					Zero(&t, sizeof(t));
					t.Enable = false;
					t.Port = port;

					if (CALL(hWnd, ScEnableListener(p->Rpc, &t)))
					{
						SmServerDlgRefresh(hWnd, p);
					}
				}
			}
			break;

		case B_APPLY:
		{
			// Apply UDP ports
			bool ret;
			LIST* ports;
			RPC_PORTS t;
			char tmp[MAX_SIZE];

			GetTxtA(hWnd, E_UDP, tmp, sizeof(tmp));
			ports = StrToPortList(tmp, false);

			t.Num = LIST_NUM(ports);
			if (t.Num > 0)
			{
				UINT i;
				t.Ports = Malloc(sizeof(UINT) * t.Num);

				for (i = 0; i < t.Num; ++i)
				{
					t.Ports[i] = (UINT)LIST_DATA(ports, i);
				}
			}
			else
			{
				t.Ports = NULL;
			}

			ReleaseList(ports);

			if (CALL(hWnd, ScSetPortsUDP(p->Rpc, &t)))
			{
				SmServerDlgRefresh(hWnd, p);
			}

			Free(t.Ports);

			break;
		}

		case B_SSL:
			// SSL related
			SmSslDlg(hWnd, p);
			break;

		case B_STATUS:
			// Server status
			SmStatusDlg(hWnd, p, p, false, true, _UU("SM_SERVER_STATUS"), ICO_VPNSERVER,
				NULL, SmRefreshServerStatus);
			break;

		case B_INFO:
			// Server Information
			SmStatusDlg(hWnd, p, p, false, false, _UU("SM_INFO_TITLE"), ICO_VPNSERVER,
				NULL, SmRefreshServerInfo);
			break;

		case B_BRIDGE:
			// Local bridge configuration
			SmBridgeDlg(hWnd, p);
			SmServerDlgRefresh(hWnd, p);
			break;

		case B_FARM:
			// Server farm
			if (SmFarmDlg(hWnd, p))
			{
				// Close the dialog if the server farm configuration has changed
				Close(hWnd);
			}
			break;

		case B_FARM_STATUS:
			// Server farm status
			if (p->ServerType == SERVER_TYPE_FARM_CONTROLLER)
			{
				Dialog(hWnd, D_SM_FARM_MEMBER, SmFarmMemberDlgProc, p);
			}
			else if (p->ServerType == SERVER_TYPE_FARM_MEMBER)
			{
				SmStatusDlg(hWnd, p, NULL, false, true, _UU("SM_FC_STATUS_CAPTION"),
					ICO_FARM, NULL, SmRefreshFarmConnectionInfo);
			}
			break;

		case B_CONNECTION:
			// TCP connection list
			SmConnectionDlg(hWnd, p);
			break;

		case B_REFRESH:
			// Update to the latest state
			SmServerDlgRefresh(hWnd, p);
			break;

		case B_CONFIG:
			// Config edit
			SmConfig(hWnd, p);
			break;

		case B_L3:
			// L3 switch
			SmL3(hWnd, p);
			break;

		case B_LICENSE:
			// Add or Remove license
			SmLicense(hWnd, p);
			SmServerDlgUpdate(hWnd, p);
			break;

		case B_IPSEC:
			// IPsec Settings
			SmIPsec(hWnd, p);
			break;

		case B_OPENVPN:
			// OpenVPN, SSTP setting
			SmOpenVpn(hWnd, p);
			break;

		case B_DDNS:
			// DDNS setting
			if (SmDDns(hWnd, p, false, false))
			{
				SmServerDlgRefresh(hWnd, p);
			}
			break;

		case B_AZURE:
			// VPN Azure setting
			SmAzure(hWnd, p, false);

			SmServerDlgRefresh(hWnd, p);
			break;


		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		{
			// Save the HUB that was selected last
			char *hubname = NULL;
			char tmp[MAX_SIZE];


			Format(tmp, sizeof(tmp), "%s:%u:%s", p->CurrentSetting->ClientOption.Hostname,
				p->CurrentSetting->ClientOption.Port,
				p->CurrentSetting->ServerAdminMode ? "" : p->CurrentSetting->HubName);

			if (LvIsSingleSelected(hWnd, L_HUB))
			{
				hubname = LvGetSelectedStrA(hWnd, L_HUB, 0);
			}

			if (IsEmptyStr(hubname) == false)
			{
				MsRegWriteStr(REG_CURRENT_USER, SM_LASTHUB_REG_KEY, tmp, hubname);
			}
			else
			{
				MsRegDeleteValue(REG_CURRENT_USER, SM_LASTHUB_REG_KEY, tmp);
			}

			Free(hubname);

			EndDialog(hWnd, false);
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_HUB:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmServerDlgUpdate(hWnd, p);
				break;
			}
			break;
		case L_LISTENER:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SmServerDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			if (p->ServerAdminMode)
			{
				// Prompt the registration if the license key is not registered
				RPC_LICENSE_STATUS t;

				Zero(&t, sizeof(t));
				if (p->Bridge == false && GetCapsBool(p->CapsList, "b_support_license"))
				{
					if (ScGetLicenseStatus(p->Rpc, &t) == ERR_NO_ERROR)
					{
						if (t.EditionId == LICENSE_EDITION_VPN3_NO_LICENSE || (t.NeedSubscription && t.SubscriptionExpires == 0))
						{
							// Valid license key is not registered

							if (MsgBox(hWnd, MB_YESNO | MB_ICONINFORMATION,
								_UU("SM_SETUP_NO_LICENSE_KEY")) == IDYES)
							{
								SmLicense(hWnd, p);
							}
						}
					}
				}
			}

			SetTimer(hWnd, 2, 150, NULL);
			break;

		case 2:
			// Setup
			KillTimer(hWnd, 2);

			if (SmSetupIsNew(p))
			{
				if (SmSetup(hWnd, p))
				{
					SmServerDlgRefresh(hWnd, p);
				}
			}

			SmShowIPSecMessageIfNecessary(hWnd, p);

			SmShowCertRegenerateMessageIfNecessary(hWnd, p);

			SetTimer(hWnd, 3, 150, NULL);
			break;

		case 3:
			// Message for Administrators
			KillTimer(hWnd, 3);

			if (UniIsEmptyStr(p->AdminMsg) == false)
			{
				wchar_t tmp[MAX_SIZE];

				UniFormat(tmp, sizeof(tmp), _UU("SM_SERVER_ADMIN_MSG"), p->ServerName);
				OnceMsg(hWnd, tmp, p->AdminMsg, true, ICO_VPNSERVER);
			}
			break;
		}
		break;
	}

	LvStandardHandler(hWnd, msg, wParam, lParam, L_HUB);

	return 0;
}

// Display the message about the cert
void SmShowCertRegenerateMessageIfNecessary(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->ServerAdminMode && p->Bridge == false)
	{
		RPC_KEY_PAIR t;

		Zero(&t, sizeof(t));

		if (ScGetServerCert(p->Rpc, &t) == ERR_NO_ERROR)
		{
			if (t.Cert != NULL && t.Cert->has_basic_constraints == false)
			{
				if (t.Cert->root_cert)
				{
					if (MsRegReadInt(REG_CURRENT_USER, SM_HIDE_CERT_UPDATE_MSG_KEY, p->ServerName) == 0)
					{
						if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("SM_CERT_MESSAGE")) == IDYES)
						{
							X *x;
							K *k;

							// Regenerating the certificate
							if (SmRegenerateServerCert(hWnd, p, NULL, &x, &k, false))
							{
								// Confirmation message
								if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO, _UU("SM_REGENERATE_CERT_MSG")) == IDYES)
								{
									// Set the new certificate and private key
									RPC_KEY_PAIR t2;

									Zero(&t2, sizeof(t2));

									t2.Cert = CloneX(x);
									t2.Key = CloneK(k);

									if (CALL(hWnd, ScSetServerCert(p->Rpc, &t2)))
									{
										FreeRpcKeyPair(&t2);

										MsgBox(hWnd, MB_ICONINFORMATION, _UU("CM_CERT_SET_MSG"));
									}
								}

								FreeX(x);
								FreeK(k);
							}
						}
						else
						{
							MsRegWriteInt(REG_CURRENT_USER, SM_HIDE_CERT_UPDATE_MSG_KEY, p->ServerName, 1);
						}
					}
				}
			}

			FreeRpcKeyPair(&t);
		}
	}
}

// Display messages about IPsec, and prompt for the setting
void SmShowIPSecMessageIfNecessary(HWND hWnd, SM_SERVER *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (GetCapsBool(p->CapsList, "b_support_vgs_in_client") == false)
	{
		if (GetCapsBool(p->CapsList, "b_support_ipsec") && p->IPsecMessageDisplayed == false)
		{
			// Display a message about IPsec
			RPC_TEST flag;

			if (MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("SM_IPSEC_SETUP_QUESTION")) == IDYES)
			{
				// Display the IPsec dialog
				SmIPsec(hWnd, p);
			}

			Zero(&flag, sizeof(flag));
			flag.IntValue = 9;
			ToStr(flag.StrValue, 1);

			ScDebug(p->Rpc, &flag);

			p->IPsecMessageDisplayed = true;
		}

	}
}

// Connection
void SmConnect(HWND hWnd, SETTING *s)
{
	SmConnectEx(hWnd, s, false);
}
void SmConnectEx(HWND hWnd, SETTING *s, bool is_in_client)
{
	bool ok;
	RPC *rpc;
	char *pass;
	bool empty_password = false;
	bool first_bad_password = false;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Disable the control
	Disable(hWnd, L_SETTING);
	Disable(hWnd, B_NEW_SETTING);
	Disable(hWnd, B_EDIT_SETTING);
	Disable(hWnd, B_DELETE);
	Disable(hWnd, IDOK);
	Disable(hWnd, B_ABOUT);
	Disable(hWnd, IDCANCEL);
	Disable(hWnd, B_SECURE_MANAGER);
	Disable(hWnd, B_SELECT_SECURE);
	Disable(hWnd, B_CERT_TOOL);

	ok = true;

	if (IsZero(s->HashedPassword, SHA1_SIZE))
	{
		// Password input screen
ENTER_PASSWORD:
		pass = SmPassword(hWnd, s->ClientOption.Hostname);
		if (pass != NULL)
		{
			Sha0(s->HashedPassword, pass, StrLen(pass));
			Free(pass);
			ok = true;
		}
		else
		{
			ok = false;
		}
	}

	if (ok)
	{
		UINT err = ERR_INTERNAL_ERROR;
		// Connection
		rpc = AdminConnectEx2(sm->Cedar, &s->ClientOption, s->ServerAdminMode ? "" : s->HubName, s->HashedPassword, &err, NULL,
			hWnd);
		if (rpc == NULL)
		{
			// An error has occured
			if (err != ERR_ACCESS_DENIED || first_bad_password)
			{
				MsgBox(hWnd, MB_ICONSTOP, _E(err));
			}
			if (err == ERR_ACCESS_DENIED)
			{
				// Password incorrect
				first_bad_password = true;
				goto ENTER_PASSWORD;
			}
			else
			{
				// Other errors
			}
		}
		else
		{
			UCHAR test[SHA1_SIZE];
			SM_SERVER p;
			RPC_SERVER_STATUS status;
			RPC_SERVER_INFO info;
			SETTING *setting;
			RPC_MSG msg;
			RPC_TEST flag;
			bool cancel = false;

			Sha0(test, "", 0);

			if (Cmp(test, s->HashedPassword, SHA1_SIZE) == 0 || Cmp(test, rpc->VpnServerHashedPassword, SHA1_SIZE) == 0)
			{
				empty_password = true;
			}

			if (sm->TempSetting == NULL)
			{
				setting = SmGetSetting(s->Title);
				if (setting != NULL)
				{
					if (IsZero(setting->HashedPassword, SHA1_SIZE) == false)
					{
						Copy(setting->HashedPassword, s->HashedPassword, SHA1_SIZE);
						SmWriteSettingList();
					}
				}
			}

			rpc->ServerAdminMode = s->ServerAdminMode;
			if (s->ServerAdminMode == false)
			{
				StrCpy(rpc->HubName, sizeof(rpc->HubName), s->HubName);
			}

			Zero(&p, sizeof(p));
			p.IsInClient = is_in_client;
			p.CurrentSetting = s;
			p.Rpc = rpc;
			p.ServerAdminMode = rpc->ServerAdminMode;
			StrCpy(p.ServerName, sizeof(p.ServerName), s->ClientOption.Hostname);
			if (p.ServerAdminMode == false)
			{
				StrCpy(p.HubName, sizeof(p.HubName), rpc->HubName);
			}
			UniStrCpy(p.Title, sizeof(p.Title), s->Title);

			// Get the type of server
			Zero(&status, sizeof(status));
			ScGetServerStatus(rpc, &status);

			p.ServerType = status.ServerType;

			Zero(&info, sizeof(info));
			ScGetServerInfo(rpc, &info);

			Copy(&p.ServerInfo, &info, sizeof(RPC_SERVER_INFO));
			Copy(&p.ServerStatus, &status, sizeof(RPC_SERVER_STATUS));

			// Get the Admin Msg
			Zero(&msg, sizeof(msg));
			if (ScGetAdminMsg(rpc, &msg) == ERR_NO_ERROR)
			{
				p.AdminMsg = UniCopyStr(msg.Msg);
				FreeRpcMsg(&msg);
			}

			// IPsec related
			Zero(&flag, sizeof(flag));
			flag.IntValue = 8;
			if (ScDebug(rpc, &flag) == ERR_NO_ERROR)
			{
				p.IPsecMessageDisplayed = ToInt(flag.StrValue);
			}
			else
			{
				p.IPsecMessageDisplayed = true;
			}

			// VGS related
			Zero(&flag, sizeof(flag));
			flag.IntValue = 10;
			if (ScDebug(rpc, &flag) == ERR_NO_ERROR)
			{
				p.VgsMessageDisplayed = ToInt(flag.StrValue);
			}
			else
			{
				p.VgsMessageDisplayed = true;
			}

			// Get the Caps
			p.CapsList = ScGetCapsEx(p.Rpc);

			p.Bridge = GetCapsBool(p.CapsList, "b_bridge");

			if (GetCapsBool(p.CapsList, "b_support_policy_ver_3"))
			{
				p.PolicyVer = 3;
			}
			else
			{
				p.PolicyVer = 2;
			}

			if (empty_password && s->ServerAdminMode)
			{
				// Make the user set a password when a password empty (In the case of server management mode)
				if (Dialog(hWnd, D_SM_CHANGE_PASSWORD, SmChangeServerPasswordDlg, &p) == 0)
				{
					cancel = true;
				}
			}

			// Server management screen
			if (cancel == false)
			{
				// Update notification initialization
				WINUI_UPDATE *update = NULL;

				if (p.ServerAdminMode && is_in_client == false)
				{
					wchar_t update_software_title[MAX_SIZE];
					char update_software_name[MAX_SIZE];
					char server_name_safe[MAX_HOST_NAME_LEN + 1];
					char family_name[128];

					MakeSafeFileName(server_name_safe, sizeof(server_name_safe), p.ServerName);
					Format(update_software_name, sizeof(update_software_name), (p.Bridge ? NAME_OF_VPN_BRIDGE_TARGET : NAME_OF_VPN_SERVER_TARGET), server_name_safe);
					StrLower(update_software_name);
					Trim(update_software_name);

					Zero(family_name, sizeof(family_name));
					StrCpy(family_name, sizeof(family_name), p.ServerInfo.ServerFamilyName);

					if (IsEmptyStr(family_name))
					{
						if (InStr(p.ServerInfo.ServerProductName, "PacketiX"))
						{
							StrCpy(family_name, sizeof(family_name), "PacketiX");
						}
						else if (InStr(p.ServerInfo.ServerProductName, "UT-VPN") ||
							InStr(p.ServerInfo.ServerProductName, "SoftEther"))
						{
							StrCpy(family_name, sizeof(family_name), "softether");
						}
					}

					if (IsEmptyStr(family_name) == false)
					{
						UniFormat(update_software_title, sizeof(update_software_title), _UU(p.Bridge ? "SM_UPDATE_CHECK_TITLE_VPNBRIDGE" : "SM_UPDATE_CHECK_TITLE_VPNSERVER"),
							family_name, p.ServerName);

						update = InitUpdateUi(update_software_title, update_software_name, family_name, p.ServerInfo.ServerBuildDate,
							p.ServerInfo.ServerBuildInt, p.ServerInfo.ServerVerInt, NULL, false);
					}
				}

				p.Update = update;

				// Main screen
				Dialog(hWnd, D_SM_SERVER, SmServerDlgProc, &p);

				if (p.Update != NULL)
				{
					FreeUpdateUi(p.Update);
					p.Update = NULL;
				}
			}

			// Disconnect
			AdminDisconnect(rpc);

			// Release the Caps
			FreeCapsList(p.CapsList);

			Free(p.AdminMsg);
			p.AdminMsg = NULL;

			FreeRpcServerInfo(&info);
		}
	}

	// Enable the control
	Enable(hWnd, L_SETTING);
	Enable(hWnd, B_NEW_SETTING);
	Enable(hWnd, B_EDIT_SETTING);
	Enable(hWnd, B_DELETE);
	Enable(hWnd, IDOK);
	Enable(hWnd, B_ABOUT);
	Enable(hWnd, IDCANCEL);

	if (MsIsWine() == false)
	{
		Enable(hWnd, B_SECURE_MANAGER);
		Enable(hWnd, B_SELECT_SECURE);
	}

	Enable(hWnd, B_CERT_TOOL);
}

// Password input dialog
char *SmPassword(HWND hWnd, char *server_name)
{
	char *ret;
	UI_PASSWORD_DLG p;
	// Validate arguments
	if (server_name == NULL)
	{
		return NULL;
	}

	Zero(&p, sizeof(p));
	p.AdminMode = true;
	StrCpy(p.ServerName, sizeof(p.ServerName), server_name);

	if (PasswordDlg(hWnd, &p) == false)
	{
		return NULL;
	}

	ret = CopyStr(p.Password);

	return ret;
}

// Configuration editing dialog initialization
void SmEditSettingDlgInit(HWND hWnd, SM_EDIT_SETTING *p)
{
	SETTING *s;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	p->Inited = false;

	s = p->Setting;

	// Title
	if (p->EditMode == false)
	{
		SetText(hWnd, 0, _UU("SM_EDIT_CAPTION_1"));
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("SM_EDIT_CAPTION_2"), s->Title);
		SetText(hWnd, 0, tmp);
	}

	// Connection setting name
	SetText(hWnd, E_ACCOUNT_NAME, s->Title);

	// Host name
	SetTextA(hWnd, E_HOSTNAME, s->ClientOption.Hostname);

	// Port number
	CbSetHeight(hWnd, C_PORT, 18);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_1"), 0);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_2"), 0);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_3"), 0);
	CbAddStr(hWnd, C_PORT, _UU("CM_PORT_4"), 0);
	SetIntEx(hWnd, C_PORT, s->ClientOption.Port);

	// Proxy Settings
	Check(hWnd, R_DIRECT_TCP, s->ClientOption.ProxyType == PROXY_DIRECT);
	Check(hWnd, R_HTTPS, s->ClientOption.ProxyType == PROXY_HTTP);
	Check(hWnd, R_SOCKS, s->ClientOption.ProxyType == PROXY_SOCKS);
	Check(hWnd, R_SOCKS5, s->ClientOption.ProxyType == PROXY_SOCKS5);

	// Management mode setting
	Check(hWnd, R_SERVER_ADMIN, s->ServerAdminMode);
	Check(hWnd, R_HUB_ADMIN, s->ServerAdminMode == false ? true : false);
	CbSetHeight(hWnd, C_HUBNAME, 18);
	SetTextA(hWnd, C_HUBNAME, s->HubName);

	// Password
	if (IsZero(s->HashedPassword, SHA1_SIZE))
	{
		Check(hWnd, R_NO_SAVE, true);
	}
	else
	{
		UCHAR test[SHA1_SIZE];

		Sha0(test, "", 0);
		if (Cmp(test, s->HashedPassword, SHA1_SIZE) != 0)
		{
			SetTextA(hWnd, E_PASSWORD, HIDDEN_PASSWORD);
		}
	}

	if (p->EditMode == false)
	{
		FocusEx(hWnd, E_ACCOUNT_NAME);
	}
	else
	{
		FocusEx(hWnd, E_HOSTNAME);
	}

	p->Inited = true;

	// Start enumerating the Virtual HUBs
	CmEnumHubStart(hWnd, &s->ClientOption);

	SmEditSettingDlgUpdate(hWnd, p);
}

// Configuration editing dialog update
void SmEditSettingDlgUpdate(HWND hWnd, SM_EDIT_SETTING *p)
{
	bool ok = true;
	UINT delete_hub_list = 0;
	SETTING *s;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || p == NULL || p->Inited == false)
	{
		return;
	}

	s = p->Setting;

	GetTxt(hWnd, E_ACCOUNT_NAME, s->Title, sizeof(s->Title));
	UniTrim(s->Title);

	if (UniStrLen(s->Title) == 0)
	{
		ok = false;
	}

	if (IsChecked(hWnd, R_LOCALHOST))
	{
		SetTextA(hWnd, E_HOSTNAME, "localhost");
		Disable(hWnd, E_HOSTNAME);
	}
	else
	{
		Enable(hWnd, E_HOSTNAME);
	}

	GetTxtA(hWnd, E_HOSTNAME, tmp, sizeof(tmp));
	Trim(tmp);

	if (StrCmpi(tmp, s->ClientOption.Hostname) != 0)
	{
		delete_hub_list++;
	}

	StrCpy(s->ClientOption.Hostname, sizeof(s->ClientOption.Hostname), tmp);

	if (StrLen(s->ClientOption.Hostname) == 0)
	{
		ok = false;
	}

	s->ClientOption.Port = GetInt(hWnd, C_PORT);
	if (s->ClientOption.Port == 0)
	{
		ok = false;
	}

	if (IsChecked(hWnd, R_DIRECT_TCP))
	{
		s->ClientOption.ProxyType = PROXY_DIRECT;
	}
	else if (IsChecked(hWnd, R_HTTPS))
	{
		s->ClientOption.ProxyType = PROXY_HTTP;
	}
	else
	{
		s->ClientOption.ProxyType = PROXY_SOCKS;
	}

	SetEnable(hWnd, B_PROXY_CONFIG, s->ClientOption.ProxyType != PROXY_DIRECT);

	if (s->ClientOption.ProxyType != PROXY_DIRECT)
	{
		if (StrLen(s->ClientOption.ProxyName) == 0)
		{
			ok = false;
		}
		if (s->ClientOption.ProxyPort == 0)
		{
			ok = false;
		}
	}

	s->ServerAdminMode = IsChecked(hWnd, R_SERVER_ADMIN);

	SetEnable(hWnd, C_HUBNAME, s->ServerAdminMode == false ? true : false);
	SetEnable(hWnd, S_HUBNAME, s->ServerAdminMode == false ? true : false);

	GetTxtA(hWnd, C_HUBNAME, s->HubName, sizeof(s->HubName));
	Trim(s->HubName);
	if (StrLen(s->HubName) == 0)
	{
		if (s->ServerAdminMode == false)
		{
			ok = false;
		}
	}

	if (IsChecked(hWnd, R_NO_SAVE))
	{
		Zero(s->HashedPassword, SHA1_SIZE);
		SetTextA(hWnd, E_PASSWORD, "");
		Disable(hWnd, E_PASSWORD);
		Disable(hWnd, S_PASSWORD);
	}
	else
	{
		char tmp[MAX_PASSWORD_LEN + 1];
		Enable(hWnd, E_PASSWORD);
		Enable(hWnd, S_PASSWORD);
		GetTxtA(hWnd, E_PASSWORD, tmp, sizeof(tmp));
		if (StrCmp(tmp, HIDDEN_PASSWORD) != 0)
		{
			Sha0(s->HashedPassword, tmp, StrLen(tmp));
		}
	}

	if (delete_hub_list)
	{
		CbReset(hWnd, C_HUBNAME);
	}

	SetEnable(hWnd, IDOK, ok);
}

// Configuration Edit dialog OK button
void SmEditSettingDlgOnOk(HWND hWnd, SM_EDIT_SETTING *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	if (p->EditMode == false)
	{
		// Register new
		SETTING *s = ZeroMalloc(sizeof(SETTING));
		Copy(s, p->Setting, sizeof(SETTING));
		if (SmAddSetting(s) == false)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SM_SETTING_EXISTS"), s->Title);
			Free(s);
			FocusEx(hWnd, E_ACCOUNT_NAME);
			return;
		}
		EndDialog(hWnd, true);
	}
	else
	{
		// Update registration
		SETTING *t = SmGetSetting(p->Setting->Title);
		if (t != NULL && t != p->OldSetting)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SM_SETTING_EXISTS"), p->Setting->Title);
			FocusEx(hWnd, E_ACCOUNT_NAME);
			return;
		}

		Copy(p->OldSetting, p->Setting, sizeof(SETTING));
		Sort(sm->SettingList);
		SmWriteSettingList();

		EndDialog(hWnd, true);
	}
}

// Settings add / edit dialog
UINT SmEditSettingDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SM_EDIT_SETTING *p = (SM_EDIT_SETTING *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmEditSettingDlgInit(hWnd, p);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_LOCALHOST:
		case E_ACCOUNT_NAME:
		case E_HOSTNAME:
		case C_PORT:
		case R_DIRECT_TCP:
		case R_HTTPS:
		case R_SOCKS:
		case R_SERVER_ADMIN:
		case R_HUB_ADMIN:
		case C_HUBNAME:
		case E_PASSWORD:
		case R_NO_SAVE:
			SmEditSettingDlgUpdate(hWnd, p);
			break;
		}

		if (LOWORD(wParam) == R_LOCALHOST)
		{
			FocusEx(hWnd, E_HOSTNAME);
		}

		switch (LOWORD(wParam))
		{
		case E_HOSTNAME:
			if (HIWORD(wParam) == EN_KILLFOCUS)
			{
				CmEnumHubStart(hWnd, &p->Setting->ClientOption);
			}
			break;
		case C_PORT:
			if (HIWORD(wParam) == CBN_KILLFOCUS)
			{
				CmEnumHubStart(hWnd, &p->Setting->ClientOption);
			}
			break;
		case R_DIRECT_TCP:
		case R_HTTPS:
		case R_SOCKS:
			if (HIWORD(wParam) == BN_CLICKED)
			{
				CmEnumHubStart(hWnd, &p->Setting->ClientOption);
			}
			break;
		}

		switch (wParam)
		{
		case IDOK:
			SmEditSettingDlgOnOk(hWnd, p);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_PROXY_CONFIG:
			// Proxy Settings
			if (CmProxyDlg(hWnd, &p->Setting->ClientOption))
			{
				UINT n = GetInt(hWnd, C_PORT);
				if (p->Setting->ClientOption.ProxyType == PROXY_HTTP &&
					n != 443)
				{
					// Show a warning message if the destination port is
					// other than 443 in when HTTP proxy is used
					if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO, _UU("CM_HTTP_PROXY_WARNING"), n) == IDYES)
					{
						// Change the port number to 443
						SetText(hWnd, C_PORT, _UU("CM_PORT_2"));
					}
				}
				SmEditSettingDlgUpdate(hWnd, p);
				CmEnumHubStart(hWnd, &p->Setting->ClientOption);
			}
			break;

		case R_NO_SAVE:
			if (IsChecked(hWnd, R_NO_SAVE) == false)
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

// Show the Settings Adding dialog
bool SmAddSettingDlg(HWND hWnd, wchar_t *new_name, UINT new_name_size)
{
	SM_EDIT_SETTING p;
	SETTING s;
	UINT i;
	bool ret;
	// Validate arguments
	if (hWnd == NULL || new_name == NULL)
	{
		return false;
	}

	Zero(&p, sizeof(p));
	Zero(&s, sizeof(s));

	s.ClientOption.Port = 443;

	p.EditMode = false;
	p.Setting = &s;

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

		if (SmGetSetting(tmp) == NULL)
		{
			UniStrCpy(s.Title, sizeof(s.Title), tmp);
			Sha0(s.HashedPassword, "", 0);
			s.ServerAdminMode = true;
			break;
		}
	}

	ret = Dialog(hWnd, D_SM_EDIT_SETTING, SmEditSettingDlgProc, &p);

	if (ret)
	{
		UniStrCpy(new_name, new_name_size, s.Title);
	}

	return ret;
}

// Show the settings edit dialog
bool SmEditSettingDlg(HWND hWnd)
{
	SM_EDIT_SETTING p;
	SETTING s, *setting;
	UINT i;
	wchar_t *name;
	// Validate arguments
	if (hWnd == NULL)
	{
		return false;
	}

	i = LvGetSelected(hWnd, L_SETTING);
	if (i == INFINITE)
	{
		return false;
	}

	name = LvGetStr(hWnd, L_SETTING, i, 0);

	setting = SmGetSetting(name);
	if (setting == NULL)
	{
		Free(name);
		return false;
	}

	Free(name);

	Copy(&s, setting, sizeof(SETTING));

	Zero(&p, sizeof(p));

	p.EditMode = true;
	p.OldSetting = setting;
	p.Setting = &s;

	return Dialog(hWnd, D_SM_EDIT_SETTING, SmEditSettingDlgProc, &p);
}

// Update the configuration
bool SmCheckNewName(SETTING *s, wchar_t *new_title)
{
	UINT i;
	// Validate arguments
	if (new_title == NULL)
	{
		return false;
	}
	if (s != NULL)
	{
		if (IsInList(sm->SettingList, s) == false)
		{
			return false;
		}
	}

	// Check whether there is the same name in other
	for (i = 0;i < LIST_NUM(sm->SettingList);i++)
	{
		SETTING *t = LIST_DATA(sm->SettingList, i);

		if (s != t)
		{
			if (UniStrCmpi(t->Title, new_title) == 0)
			{
				return false;
			}
		}
	}

	return true;
}

// Delete the configuration
void SmDeleteSetting(wchar_t *title)
{
	SETTING *s;
	// Validate arguments
	if (title == NULL)
	{
		return;
	}

	s = SmGetSetting(title);
	if (s == NULL)
	{
		return;
	}

	Delete(sm->SettingList, s);
	Free(s);
	Sort(sm->SettingList);

	SmWriteSettingList();
}

// Add the settings
bool SmAddSetting(SETTING *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	if (SmGetSetting(s->Title) != NULL)
	{
		return false;
	}

	Insert(sm->SettingList, s);

	SmWriteSettingList();

	return true;
}

// Get the configuration
SETTING *SmGetSetting(wchar_t *title)
{
	SETTING s;
	// Validate arguments
	if (title == NULL)
	{
		return NULL;
	}

	Zero(&s, sizeof(SETTING));
	UniStrCpy(s.Title, sizeof(s.Title), title);

	return (SETTING *)Search(sm->SettingList, &s);
}

// Comparison of connection settings
int SmCompareSetting(void *p1, void *p2)
{
	SETTING *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(SETTING **)p1;
	s2 = *(SETTING **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	return UniStrCmpi(s1->Title, s2->Title);
}

// Initialize the configuration list
void SmInitSettingList()
{
	sm->SettingList = NewList(SmCompareSetting);

	SmLoadSettingList();

	SmInitDefaultSettingList();
}

// Release the configuration list
void SmFreeSettingList()
{
	UINT i;

	// Write
	SmWriteSettingList();

	for (i = 0;i < LIST_NUM(sm->SettingList);i++)
	{
		SETTING *s = LIST_DATA(sm->SettingList, i);
		Free(s);
	}
	ReleaseList(sm->SettingList);

	sm->SettingList = NULL;
}

// Write the configuration list
void SmWriteSettingList()
{
	TOKEN_LIST *t;
	UINT i;

	t = MsRegEnumValue(REG_CURRENT_USER, SM_SETTING_REG_KEY);
	if (t != NULL)
	{
		// Remove all existing values
		for (i = 0;i < t->NumTokens;i++)
		{
			char *name = t->Token[i];
			MsRegDeleteValue(REG_CURRENT_USER, SM_SETTING_REG_KEY, name);
		}

		FreeToken(t);
	}

	for (i = 0;i < LIST_NUM(sm->SettingList);i++)
	{
		char name[MAX_SIZE];
		SETTING *s = LIST_DATA(sm->SettingList, i);

		// Write
		Format(name, sizeof(name), "Setting%u", i + 1);
		MsRegWriteBin(REG_CURRENT_USER, SM_SETTING_REG_KEY, name, s, sizeof(SETTING));
	}
}

// Load the connection list
void SmLoadSettingList()
{
	TOKEN_LIST *t;
	UINT i;
	char *key_name = SM_SETTING_REG_KEY;

	t = MsRegEnumValue(REG_CURRENT_USER, key_name);
	if (t == NULL)
	{
		key_name = SM_SETTING_REG_KEY_OLD;
		t = MsRegEnumValue(REG_CURRENT_USER, key_name);
		if (t == NULL)
		{
			return;
		}
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		BUF *b = MsRegReadBin(REG_CURRENT_USER, key_name, name);
		if (b != NULL)
		{
			if (b->Size == sizeof(SETTING))
			{
				SETTING *s = ZeroMalloc(sizeof(SETTING));
				Copy(s, b->Buf, sizeof(SETTING));

				Add(sm->SettingList, s);
			}
			FreeBuf(b);
		}
	}

	FreeToken(t);

	Sort(sm->SettingList);
}

// Initialize the default setting list
void SmInitDefaultSettingList()
{
	if (LIST_NUM(sm->SettingList) == 0)
	{
		bool b = false;
		LIST *pl = MsGetProcessList();

		if (pl != NULL)
		{
			UINT i;
			for (i = 0;i < LIST_NUM(pl);i++)
			{
				MS_PROCESS *p = LIST_DATA(pl, i);

				if (UniInStr(p->ExeFilenameW, L"vpnserver.exe") || UniInStr(p->ExeFilenameW, L"vpnbridge.exe"))
				{
					b = true;
				}

				if (UniInStr(p->ExeFilenameW, L"sevpnserver.exe") || UniInStr(p->ExeFilenameW, L"sevpnbridge.exe"))
				{
					b = true;
				}

				if (UniInStr(p->ExeFilenameW, L"utvpnserver.exe") || UniInStr(p->ExeFilenameW, L"utvpnbridge.exe"))
				{
					b = true;
				}
			}
		}

		MsFreeProcessList(pl);

		if (b == false)
		{
			if (MsIsServiceRunning(GC_SVC_NAME_VPNSERVER) || MsIsServiceRunning(GC_SVC_NAME_VPNBRIDGE))
			{
				b = true;
			}
		}

		if (b)
		{
			SETTING *s = ZeroMalloc(sizeof(SETTING));

			UniStrCpy(s->Title, sizeof(s->Title), _UU("SM_LOCALHOST"));
			s->ServerAdminMode = true;
			Sha0(s->HashedPassword, "", 0);
			UniStrCpy(s->ClientOption.AccountName, sizeof(s->ClientOption.AccountName), s->Title);
			StrCpy(s->ClientOption.Hostname, sizeof(s->ClientOption.Hostname), "localhost");
			s->ClientOption.Port = GC_DEFAULT_PORT;

			Add(sm->SettingList, s);
		}
	}
}

// Main dialog initialization
void SmMainDlgInit(HWND hWnd)
{
	wchar_t *last_select;
	UINT i = INFINITE;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_VPNSERVER);

	LvInit(hWnd, L_SETTING);
	LvSetStyle(hWnd, L_SETTING, LVS_EX_GRIDLINES);
	LvInsertColumn(hWnd, L_SETTING, 0, _UU("SM_MAIN_COLUMN_1"), 145);
	LvInsertColumn(hWnd, L_SETTING, 1, _UU("SM_MAIN_COLUMN_2"), 129);
	LvInsertColumn(hWnd, L_SETTING, 2, _UU("SM_MAIN_COLUMN_3"), 125);

	SmRefreshSetting(hWnd);

	last_select = MsRegReadStrW(REG_CURRENT_USER, SM_REG_KEY, "Last Select");
	if (UniIsEmptyStr(last_select) == false)
	{
		i = LvSearchStr(hWnd, L_SETTING, 0, last_select);
	}
	Free(last_select);

	if (i == INFINITE)
	{
		LvSelect(hWnd, L_SETTING, 0);
	}
	else
	{
		LvSelect(hWnd, L_SETTING, i);
	}

	DlgFont(hWnd, IDOK, 10, true);

	if (MsIsWine())
	{
		Disable(hWnd, B_SECURE_MANAGER);
		Disable(hWnd, B_SELECT_SECURE);
	}

	Focus(hWnd, L_SETTING);

	SmMainDlgUpdate(hWnd);
}

// Update the configuration list
void SmRefreshSetting(HWND hWnd)
{
	SmRefreshSettingEx(hWnd, NULL);
}
void SmRefreshSettingEx(HWND hWnd, wchar_t *select_name)
{
	LVB *b;
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	b = LvInsertStart();

	for (i = 0;i < LIST_NUM(sm->SettingList);i++)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		SETTING *s = LIST_DATA(sm->SettingList, i);

		if (s->ServerAdminMode)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_MODE_SERVER"));
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("SM_MODE_HUB"), s->HubName);
		}

		StrToUni(tmp2, sizeof(tmp2), s->ClientOption.Hostname);

		LvInsertAdd(b,
			(s->ServerAdminMode ? ICO_SERVER_ONLINE : ICO_HUB),
			NULL,
			3,
			s->Title,
			tmp2,
			tmp);
	}

	LvInsertEnd(b, hWnd, L_SETTING);

	if (UniIsEmptyStr(select_name) == false)
	{
		LvSelect(hWnd, L_SETTING, INFINITE);
		LvSelect(hWnd, L_SETTING, LvSearchStr(hWnd, L_SETTING, 0, select_name));
	}
}

// Main dialog update
void SmMainDlgUpdate(HWND hWnd)
{
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_SETTING) == false)
	{
		ok = false;
	}
	if (LvIsMultiMasked(hWnd, L_SETTING))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
	SetEnable(hWnd, B_EDIT_SETTING, ok);
	SetEnable(hWnd, B_DELETE, ok);
}

// Main window procedure
UINT SmMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	NMHDR *n;
	NMLVDISPINFOW *info;
	NMLVKEYDOWN *key;
	wchar_t *tmp;
	UINT i;
	wchar_t new_name[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SmMainDlgInit(hWnd);
		SetTimer(hWnd, 4, 100, NULL);

		// Updater start
		sm->Update = InitUpdateUi(_UU("PRODUCT_NAME_VPN_SMGR"), NAME_OF_VPN_SERVER_MANAGER, NULL, GetCurrentBuildDate(),
			CEDAR_VERSION_BUILD, GetCedarVersionNumber(), NULL, false);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 4:
			KillTimer(hWnd, 4);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			DisableUpdateUi(sm->Update);

			// Connection
			i = LvGetSelected(hWnd, L_SETTING);
			if (i != INFINITE)
			{
				tmp = LvGetStr(hWnd, L_SETTING, i, 0);
				if (tmp != NULL)
				{
					SETTING *setting = SmGetSetting(tmp);
					if (setting != NULL)
					{
						SETTING s;

						// Record in the registry as the last choice
						MsRegWriteStrW(REG_CURRENT_USER, SM_REG_KEY, "Last Select", tmp);

						// Copy the configuration
						Copy(&s, setting, sizeof(SETTING));
						SmConnect(hWnd, &s);
					}
					Free(tmp);
				}
			}
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case B_NEW_SETTING:
			DisableUpdateUi(sm->Update);

			// Add
			if (SmAddSettingDlg(hWnd, new_name, sizeof(new_name)))
			{
				SmRefreshSettingEx(hWnd, new_name);
			}
			break;

		case B_EDIT_SETTING:
			DisableUpdateUi(sm->Update);

			// Edit
			if (SmEditSettingDlg(hWnd))
			{
				SmWriteSettingList();
				SmRefreshSetting(hWnd);
			}

			break;

		case B_DELETE:
			DisableUpdateUi(sm->Update);

			// Delete
			i = LvGetSelected(hWnd, L_SETTING);
			if (i != INFINITE)
			{
				tmp = LvGetStr(hWnd, L_SETTING, i, 0);
				if (tmp != NULL)
				{
					if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2,
						_UU("SM_SETTING_DELETE_MSG"), tmp) == IDYES)
					{
						SmDeleteSetting(tmp);
						SmWriteSettingList();
						SmRefreshSetting(hWnd);
					}
					Free(tmp);
				}
			}
			break;

		case B_ABOUT:
			// Version information
			AboutEx(hWnd, sm->Cedar, _UU("PRODUCT_NAME_VPN_SMGR"), sm->Update);
			break;

		case B_SECURE_MANAGER:
			DisableUpdateUi(sm->Update);

			// Smart Card Manager
			SmSecureManager(hWnd);
			break;

		case B_SELECT_SECURE:
			DisableUpdateUi(sm->Update);

			// Smart card selection
			SmSelectSecureId(hWnd);
			break;

		case B_CERT_TOOL:
			DisableUpdateUi(sm->Update);

			// Certificate Creation Tool
			SmCreateCert(hWnd, NULL, NULL, false, NULL, false);
			break;
		}

		break;

	case WM_CLOSE:
		// Updater terminate
		if (sm->Update != NULL)
		{
			FreeUpdateUi(sm->Update);
			sm->Update = NULL;
		}

		EndDialog(hWnd, 0);
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		switch (n->idFrom)
		{
		case L_SETTING:
			switch (n->code)
			{
			case NM_DBLCLK:
				Command(hWnd, IDOK);
				break;

			case LVN_KEYDOWN:
				key = (NMLVKEYDOWN *)n;
				if (key != NULL)
				{
					UINT code = key->wVKey;
					switch (code)
					{
					case VK_F2:
						if (LvIsSelected(hWnd, L_SETTING))
						{
							LvRename(hWnd, L_SETTING, LvGetSelected(hWnd, L_SETTING));
						}
						break;

					case VK_DELETE:
						Command(hWnd, B_DELETE);
						break;

					case VK_RETURN:
						Command(hWnd, IDOK);
						break;
					}
				}
				break;

			case LVN_ENDLABELEDITW:
				// Change the name
				info = (NMLVDISPINFOW *)n;
				if (info->item.pszText != NULL)
				{
					wchar_t *new_name = info->item.pszText;
					wchar_t *old_name = LvGetStr(hWnd, L_SETTING, info->item.iItem, 0);

					if (old_name != NULL)
					{
						if (UniStrCmp(new_name, old_name) != 0 && UniStrLen(new_name) != 0)
						{
							// Change the name
							SETTING *s = SmGetSetting(old_name);
							if (s != NULL)
							{
								if (SmGetSetting(new_name) != NULL)
								{
									MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SM_SETTING_EXISTS"),
										new_name);
								}
								else
								{
									UniStrCpy(s->Title, sizeof(s->Title), new_name);
									Sort(sm->SettingList);
									SmWriteSettingList();
									LvSetItem(hWnd, L_SETTING, info->item.iItem, 0, new_name);
								}
							}
						}

						Free(old_name);
					}
				}
				break;

			case LVN_ITEMCHANGED:
				SmMainDlgUpdate(hWnd);
				break;
			}
			break;
		}
		break;
	}

	LvSortHander(hWnd, msg, wParam, lParam, L_SETTING);

	return 0;
}

// Main window
void SmMainDlg()
{
	Dialog(NULL, D_SM_MAIN, SmMainDlgProc, NULL);
}

// Server Manager main process
void MainSM()
{
//	MsgBoxEx(NULL, 0, L"MsIsWine: %u\n", MsIsWine());

	if (sm->TempSetting == NULL)
	{
		// Open the main window
		SmMainDlg();
	}
	else
	{
		SmConnect(sm->hParentWnd, sm->TempSetting);
	}
}

// Initialize
void InitSM()
{
	InitSMEx(false);
}
void InitSMEx(bool from_cm)
{
	if (sm != NULL)
	{
		// Already initialized
		return;
	}

	sm = ZeroMalloc(sizeof(SM));

	if (from_cm == false)
	{
		InitWinUi(_UU("SM_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));
	}

	sm->Cedar = NewCedar(NULL, NULL);

	if (from_cm == false)
	{
		SmInitSettingList();
		InitCM(false);

		// Interpret the command line
		SmParseCommandLine();
	}
}

// Interpret the command line
void SmParseCommandLine()
{
	LIST *o;
	CONSOLE *c = NewLocalConsole(NULL, NULL);
	wchar_t *cmdline;
	PARAM args[] =
	{
		{"[vpnserver]", NULL, NULL, NULL, NULL,},
		{"HUB", NULL, NULL, NULL, NULL,},
		{"PASSWORD", NULL, NULL, NULL, NULL,},
		{"TITLE", NULL, NULL, NULL, NULL,},
		{"HWND", NULL, NULL, NULL, NULL,},
	};
	if (c == NULL)
	{
		return;
	}
	
	cmdline = GetCommandLineUniStr();

	if (UniIsEmptyStr(cmdline) == false)
	{
		o = ParseCommandList(c, "vpnsmgr", cmdline, args, sizeof(args) / sizeof(args[0]));
		if (o != NULL)
		{
			char *host;
			UINT port;

			if (ParseHostPort(GetParamStr(o, "[vpnserver]"), &host, &port, 443))
			{
				char *hub = GetParamStr(o, "HUB");
				char *password = GetParamStr(o, "PASSWORD");
				char *title = GetParamStr(o, "TITLE");
				char *hwndstr = GetParamStr(o, "HWND");

				if (hub == NULL || StrCmpi(hub, "\"") == 0)
				{
					hub = CopyStr("");
				}
				if (password == NULL)
				{
					password = CopyStr("");
				}
				if (title == NULL)
				{
					title = CopyStr(host);
				}

				if (IsEmptyStr(host) == false)
				{
					SETTING *s = ZeroMalloc(sizeof(SETTING));
					BUF *b;
					CLIENT_OPTION *o;

					StrToUni(s->Title, sizeof(s->Title), title);

					if (IsEmptyStr(hub))
					{
						s->ServerAdminMode = true;
					}
					else
					{
						s->ServerAdminMode = false;
						StrCpy(s->HubName, sizeof(s->HubName), hub);
					}

					b = StrToBin(password);
					if (b == NULL || b->Size != SHA1_SIZE)
					{
						Sha0(s->HashedPassword, password, StrLen(password));
					}
					else
					{
						Copy(s->HashedPassword, b->Buf, SHA1_SIZE);
					}
					FreeBuf(b);

					o = &s->ClientOption;

					UniStrCpy(o->AccountName, sizeof(o->AccountName), s->Title);
					StrCpy(o->Hostname, sizeof(o->Hostname), host);
					o->Port = port;
					o->ProxyType = PROXY_DIRECT;
					StrCpy(o->DeviceName, sizeof(o->DeviceName), "DUMMY");

					sm->TempSetting = s;

					if (IsEmptyStr(hwndstr) == false)
					{
						sm->hParentWnd = (HWND)ToInt64(hwndstr);
					}
				}

				Free(hwndstr);
				Free(title);
				Free(hub);
				Free(password);
				Free(host);
			}
		}
	}

	Free(cmdline);

	c->Free(c);
}

// Release
void FreeSM()
{
	FreeSMEx(false);
}
void FreeSMEx(bool from_cm)
{
	if (sm == NULL)
	{
		// Uninitialized
		return;
	}

	if (from_cm == false)
	{
		FreeCM();

		SmFreeSettingList();
	}

	ReleaseCedar(sm->Cedar);

	if (from_cm == false)
	{
		FreeWinUi();
	}

	if (sm->TempSetting != NULL)
	{
		Free(sm->TempSetting);
	}

	Free(sm);
	sm = NULL;
}

// Running the Server Manager
void SMExec()
{
	InitSM();
	MainSM();
	FreeSM();
}

#endif	// WIN32


