// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// WinUi.c
// User interface code for Win32

#include <GlobalConst.h>

#ifdef	WIN32

#define	WINUI_C

#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <Iphlpapi.h>
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

char cached_pin_code[MAX_SIZE] = {0};
UINT64 cached_pin_code_expires = 0;

static HINSTANCE hDll = NULL;
static wchar_t *title_bar = NULL;
static char *font_name = NULL;
static UINT font_size = 9;
static HIMAGELIST large_image_list = NULL, small_image_list = NULL;
static LIST *icon_list = NULL;
static HINSTANCE hMsHtml = NULL;
static UINT init_winui_counter = 0;
static HDC hCommonDC = NULL;
static LOCK *lock_common_dc = NULL;

bool UseAlpha = false;
UINT AlphaValue = 100;

static THREAD *led_thread = NULL;
static bool thread_stop = false;
static bool g_led_special = false;
static bool g_tcpip_topmost = false;
static DWORD tls_current_wizard = 0xFFFFFFFF;

#define WINUI_PSM_SHOWWIZBUTTONS              (WM_USER + 138)
#define WINUI_PropSheet_ShowWizButtons(hDlg, dwFlag, dwButton) \
	PSTMSG(hDlg, WINUI_PSM_SHOWWIZBUTTONS, (WPARAM)(dwFlag), (LPARAM)(dwButton))

typedef struct _WINUI_SHSTOCKICONINFO
{
	DWORD cbSize;
	HICON hIcon;
	int   iSysImageIndex;
	int   iIcon;
	WCHAR szPath[MAX_PATH];
} WINUI_SHSTOCKICONINFO;

// Get whether the current process is foreground
bool IsThisProcessForeground()
{
	HWND hWnd = GetForegroundWindow();
	DWORD proc_id, thread_id;

	if (hWnd == NULL)
	{
		return false;
	}

	proc_id = 0;
	thread_id = GetWindowThreadProcessId(hWnd, &proc_id);

	if (proc_id == MsGetCurrentProcessId())
	{
		return true;
	}

	return false;
}
bool IsThisProcessForegroundForUpdateUi(UPDATE_CLIENT *c, void *p)
{
	return IsThisProcessForeground();
}

// Update notification screen dialog procedure
UINT UpdateConfigDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	WINUI_UPDATE *u = (WINUI_UPDATE *)param;
	UPDATE_CLIENT_SETTING s;

	switch (msg)
	{
	case WM_INITDIALOG:
		SetTimer(hWnd, 1, 100, NULL);

		LoadUpdateUiSetting(u, &s);

		Check(hWnd, S_ENABLE, s.DisableCheck == false);
		Check(hWnd, S_DISABLE, s.DisableCheck);

		DlgFont(hWnd, S_TITLE, 10, true);
		FormatText(hWnd, S_TITLE, u->SoftwareTitle);
		FormatText(hWnd, S_INFO, u->SoftwareTitle);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (u->UpdateClient->HaltFlag)
			{
				goto LABEL_CLOSE;
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
LABEL_CLOSE:
		LoadUpdateUiSetting(u, &s);

		s.DisableCheck = IsChecked(hWnd, S_DISABLE);

		if (s.DisableCheck)
		{
			s.LatestIgnoreBuild = 0;
		}

		SaveUpdateUiSetting(u, &s);

		SetUpdateClientSetting(u->UpdateClient, &s);

		EndDialog(hWnd, !s.DisableCheck);

		break;
	}

	return 0;
}

// Show the update notification setting screen
bool ConfigUpdateUi(WINUI_UPDATE *u, HWND hWnd)
{
	// Validate arguments
	if (u == NULL)
	{
		return false;
	}

	return Dialog(hWnd, D_UPDATE_CONFIG, UpdateConfigDlgProc, u);
}

// Update notification dialog procedure
UINT UpdateNoticeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	WINUI_UPDATE_DLG_PARAM *p = (WINUI_UPDATE_DLG_PARAM *)param;
	WINUI_UPDATE *u = NULL;
	UPDATE_CLIENT_SETTING s;
	char date_current[64];
	char date_latest[64];
	wchar_t date_current_str[128];
	wchar_t date_latest_str[128];
	char *font_name = NULL;

	if (p != NULL)
	{
		u = p->Update;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		Zero(date_current_str, sizeof(date_current_str));
		Zero(date_latest_str, sizeof(date_latest_str));

		GetDateStr64(date_current, sizeof(date_current), u->CurrentDate);
		if (u->CurrentDate != 0)
		{
			UniFormat(date_current_str, sizeof(date_current_str), _UU("DLG_UPDATE_DATE"), date_current);
		}

		GetDateStr64(date_latest, sizeof(date_latest), p->LatestDate);
		if (p->LatestDate != 0)
		{
			UniFormat(date_latest_str, sizeof(date_latest_str), _UU("DLG_UPDATE_DATE"), date_latest);
		}

		FormatText(hWnd, 0, u->UpdateClient->SoftwareTitle);
		FormatText(hWnd, S_INFO, u->UpdateClient->SoftwareTitle);
		SetText(hWnd, S_PRODUCT_STR, u->UpdateClient->SoftwareTitle);

		FormatText(hWnd, S_CURRENT_STR, u->CurrentVer / 100, u->CurrentVer % 100, u->CurrentBuild, date_current_str);
		FormatText(hWnd, S_LATEST_STR, p->LatestVer, date_latest_str);

		if (MsIsWindows7())
		{
			if (_GETLANG() == 0)
			{
				font_name = GetMeiryoFontName();
			}
			else if (_GETLANG() == 2)
			{
				font_name = "Microsoft YaHei";
			}
			else if (_GETLANG() == 3)
			{
				font_name = "Microsoft JhengHei";
			}
		}

		SetFont(hWnd, S_INFO, GetFont(font_name, 11, false, false, false, false));
		SetFont(hWnd, IDOK, GetFont(font_name, 0, true, false, false, false));
		SetFont(hWnd, IDCANCEL, GetFont(font_name, 0, false, false, false, false));
		SetFont(hWnd, S_PRODUCT_STR, GetFont(font_name, 10, true, false, false, false));
		SetFont(hWnd, S_CURRENT_STR, GetFont(font_name, 10, true, false, false, false));
		SetFont(hWnd, S_LATEST_STR, GetFont(font_name, 10, true, false, false, false));

		SetFont(hWnd, S_PRODUCT, GetFont(font_name, 0, false, false, false, false));
		SetFont(hWnd, S_CURRENT, GetFont(font_name, 0, false, false, false, false));
		SetFont(hWnd, S_LATEST, GetFont(font_name, 0, false, false, false, false));
		SetFont(hWnd, B_CONFIG, GetFont(font_name, 0, false, false, false, false));

		SetTimer(hWnd, 1, 100, NULL);

		//MessageBeep(MB_ICONASTERISK);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:	// Web View
			OnceMsgEx(hWnd, NULL, _UU("DLG_UPDATE_HINT"), true, ICO_INTERNET, (bool *)p->halt_flag);

			ShellExecuteA(hWnd, "open", p->Url, NULL, NULL, SW_SHOWNORMAL);
			SleepThread(250);

			// Ignore the update notification of this version for future
			LoadUpdateUiSetting(u, &s);
			s.LatestIgnoreBuild = p->LatestBuild;
			SaveUpdateUiSetting(u, &s);

			EndDialog(hWnd, 1);
			break;

		case IDCANCEL:	// Ignore this version
			LoadUpdateUiSetting(u, &s);
			s.LatestIgnoreBuild = p->LatestBuild;
			SaveUpdateUiSetting(u, &s);
			Close(hWnd);
			break;

		case B_CONFIG:	// Show the notification settings screen
			p->IsInConfigDialog = true;

			if (ConfigUpdateUi(u, hWnd) == false)
			{
				// Decided not to notify any more as a result of setting
				Close(hWnd);
			}

			p->IsInConfigDialog = false;
			break;
		}
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (p->IsInConfigDialog == false)
			{
				if (*(p->halt_flag))
				{
					// Close the screen forcibly
					EndDialog(hWnd, 0);
				}
			}
			break;
		}
		break;

	case WM_CLOSE:	// Close
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// Update notification dialog
void UpdateNotifyProcUi(UPDATE_CLIENT *c, UINT latest_build, UINT64 latest_date, char *latest_ver, char *url, volatile bool *halt_flag, void *param)
{
	WINUI_UPDATE *u = (WINUI_UPDATE *)param;
	WINUI_UPDATE_DLG_PARAM p;
	// Validate arguments
	if (c == NULL || latest_build == 0 || latest_date == 0 || latest_ver == NULL || url == NULL || halt_flag == NULL || param == NULL)
	{
		return;
	}

	if (u->UseSuppressFlag)
	{
		// Check the suppress flag
		if (MsRegReadIntEx2(REG_LOCAL_MACHINE, PROTO_SUPPRESS_CLIENT_UPDATE_NOTIFICATION_REGKEY, 
			PROTO_SUPPRESS_CLIENT_UPDATE_NOTIFICATION_REGVALUE, false, true))
		{
			// Supress the dialog
			return;
		}
	}

	if (u->CurrentlyDisabled)
	{
		// Hide
		return;
	}

	// Show the update screen
	Zero(&p, sizeof(p));

	p.Update = u;
	p.LatestBuild = latest_build;
	p.LatestDate = latest_date;
	p.LatestVer = latest_ver;
	p.Url = url;
	p.halt_flag = halt_flag;

	Dialog(NULL, D_UPDATE_NOTICE, UpdateNoticeDlgProc, &p);
}

// Initialize the update notification
WINUI_UPDATE *InitUpdateUi(wchar_t *title, char *name, char *family_name, UINT64 current_date, UINT current_build, UINT current_ver, char *client_id, bool use_suppress_flag)
{
	WINUI_UPDATE *u;
	UPDATE_CLIENT_SETTING s;
	LANGLIST t;
	// Validate arguments
	if (title == NULL || name == NULL || current_build == 0 || current_ver == 0)
	{
	return NULL;
	}
	if (MsIsWine())
	{
		return false;
	}
	if (IsEmptyStr(family_name))
	{
		family_name = UPDATE_FAMILY_NAME;
	}

	u = ZeroMalloc(sizeof(WINUI_UPDATE));

	StrCpy(u->ClientId, sizeof(u->ClientId), client_id);
	UniStrCpy(u->SoftwareTitle, sizeof(u->SoftwareTitle), title);
	StrCpy(u->SoftwareName, sizeof(u->SoftwareName), name);
	u->CurrentDate = current_date;
	u->CurrentBuild = current_build;
	u->CurrentVer = current_ver;
	u->UseSuppressFlag = use_suppress_flag;

	Format(u->RegKey, sizeof(u->RegKey), WINUI_UPDATE_REGKEY, u->SoftwareName);

	Zero(&s, sizeof(s));
	LoadUpdateUiSetting(u, &s);

	Zero(&t, sizeof(t));
	GetCurrentLang(&t);

	u->UpdateClient = NewUpdateClient(UpdateNotifyProcUi, IsThisProcessForegroundForUpdateUi, u, family_name, u->SoftwareName, u->SoftwareTitle,
		u->CurrentBuild, u->CurrentDate, t.Name, &s, client_id);

	if (u->UpdateClient == NULL)
	{
		Free(u);
		return NULL;
	}

	return u;
}

// Disable the update notification UI
void DisableUpdateUi(WINUI_UPDATE *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	u->CurrentlyDisabled = true;
}

// Release the update notification
void FreeUpdateUi(WINUI_UPDATE *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	if (u->UpdateClient != NULL)
	{
		FreeUpdateClient(u->UpdateClient);
	}

	Free(u);
}

// Read the current settings from the registry
void LoadUpdateUiSetting(WINUI_UPDATE *u, UPDATE_CLIENT_SETTING *s)
{
	Zero(s, sizeof(UPDATE_CLIENT_SETTING));
	// Validate arguments
	if (u == NULL || s == NULL)
	{
		return;
	}

	s->DisableCheck = MsRegReadInt(REG_CURRENT_USER, u->RegKey, "DisableCheck");
	s->LatestIgnoreBuild = MsRegReadInt(REG_CURRENT_USER, u->RegKey, "LatestIgnoreBuild");
}

// Write the current settings to the registry
void SaveUpdateUiSetting(WINUI_UPDATE *u, UPDATE_CLIENT_SETTING *s)
{
	// Validate arguments
	if (u == NULL || s == NULL)
	{
		return;
	}

	MsRegWriteInt(REG_CURRENT_USER, u->RegKey, "DisableCheck", s->DisableCheck);
	MsRegWriteInt(REG_CURRENT_USER, u->RegKey, "LatestIgnoreBuild", s->LatestIgnoreBuild);
}

// Set the UAC icon to the control in the dialog
void SetUacIcon(HWND hWnd, UINT id)
{
	static HINSTANCE hShell32 = NULL;
	static HRESULT (__stdcall *_SHGetStockIconInfo)(UINT siid, UINT uFlags, void *psii) = NULL;
	bool ok = false;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (MsIsVista() == false)
	{
		goto LABEL_FAILED;
	}

	if (hShell32 == NULL)
	{
		hShell32 = LoadLibraryA("shell32.dll");
	}

	if (hShell32 != NULL)
	{
		if (_SHGetStockIconInfo == NULL)
		{
			_SHGetStockIconInfo = (HRESULT (__stdcall *)(UINT,UINT,void *))GetProcAddress(hShell32, "SHGetStockIconInfo");
		}
	}

	if (_SHGetStockIconInfo != NULL)
	{
		WINUI_SHSTOCKICONINFO sii;

		Zero(&sii, sizeof(sii));

		sii.cbSize = sizeof(sii);
		if (_SHGetStockIconInfo(77, 0x000000100 | 0x000000001, &sii) == S_OK)
		{
			SendMessage(DlgItem(hWnd, id), STM_SETICON, (WPARAM)sii.hIcon, 0);

			ok = true;
		}
	}

	if (ok)
	{
		return;
	}

LABEL_FAILED:

	Hide(hWnd, id);
}

// Procedure of the wizard page
UINT CALLBACK WizardPageDefDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	DIALOG_PARAM *dp = (DIALOG_PARAM *)GetParam(hWnd);
	WIZARD_PAGE *wizard_page = NULL;
	WIZARD *wizard = NULL;
	UINT ret_value = 0;
	bool do_not_send_msg = false;

	if (dp != NULL)
	{
		wizard_page = dp->wizard_page;
		wizard = wizard_page->Wizard;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		{
			PROPSHEETPAGEW_V3 *t = (PROPSHEETPAGEW_V3 *)lParam;
			dp = (DIALOG_PARAM *)t->lParam;
			wizard_page = dp->wizard_page;
			wizard = wizard_page->Wizard;

			wizard->hWndWizard = GetParent(hWnd);
			wizard_page->hWndPage = hWnd;

			SetParam(hWnd, dp);

			InitDialogInternational(hWnd, dp);
		}
		break;

	case WM_CTLCOLORBTN:
	case WM_CTLCOLORDLG:
	case WM_CTLCOLOREDIT:
	case WM_CTLCOLORLISTBOX:
	case WM_CTLCOLORMSGBOX:
	case WM_CTLCOLORSCROLLBAR:
	case WM_CTLCOLORSTATIC:
		return (UINT)GetStockObject(WHITE_BRUSH);
		break;

	case WM_NOTIFY:
		{
			NMHDR *pnmh = (NMHDR *)lParam;
			UINT ret = 0;
			UINT next_page = INFINITE;

			switch (pnmh->code)
			{
			case PSN_SETACTIVE:		// Activate
				SetWizardButton(wizard_page, true, true, true, false);
				dp->wizard_proc(hWnd, WM_WIZ_SHOW, 0, 0, wizard, wizard_page, wizard->Param);
				break;

			case PSN_KILLACTIVE:	// Deactivate
				dp->wizard_proc(hWnd, WM_WIZ_HIDE, 0, 0, wizard, wizard_page, wizard->Param);
				break;

			case PSN_WIZNEXT:		// Determine the destination of [Next] button
				ret = dp->wizard_proc(hWnd, WM_WIZ_NEXT, 0, 0, wizard, wizard_page, wizard->Param);
				do_not_send_msg = true;

				if (ret == 0)
				{
					SetWindowLong(hWnd, DWLP_MSGRESULT, -1);
				}
				else
				{
					SetWindowLong(hWnd, DWLP_MSGRESULT, ret);
				}

				ret_value = 1;
				break;

			case PSN_WIZBACK:		// Determine the destination of [back] button
				ret = dp->wizard_proc(hWnd, WM_WIZ_BACK, 0, 0, wizard, wizard_page, wizard->Param);
				do_not_send_msg = true;

				if (ret == 0)
				{
					SetWindowLong(hWnd, DWLP_MSGRESULT, -1);
				}
				else
				{
					SetWindowLong(hWnd, DWLP_MSGRESULT, ret);
				}

				ret_value = 1;
				break;

			case PSN_QUERYCANCEL:	// Determine the process of the [Cancel] button
				if (dp->wizard_page->EnableClose == false)
				{
					SetWindowLong(hWnd, DWLP_MSGRESULT, 1);
				}
				else
				{

					ret = dp->wizard_proc(hWnd, WM_WIZ_CLOSE, 0, 0, wizard, wizard_page, wizard->Param);

					if (ret == 0)
					{
						if (IsEmptyUniStr(wizard->CloseConfirmMsg) == false &&
							MsgBox(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, wizard->CloseConfirmMsg) == IDNO)
						{
							ret = 1;
						}
					}

					if (ret == 0)
					{
						SetWindowLong(hWnd, DWLP_MSGRESULT, 0);
					}
					else
					{
						SetWindowLong(hWnd, DWLP_MSGRESULT, 1);
					}
				}
				ret_value = 1;
				do_not_send_msg = true;
				break;
			}
			break;
		}
	}

	if (do_not_send_msg == false)
	{
		if (dp != NULL)
		{
			UINT ret = dp->wizard_proc(hWnd, msg, wParam, lParam, wizard, wizard_page, wizard->Param);

			if (ret != 0)
			{
				ret_value = ret;
			}
		}
	}

	if (msg == WM_INITDIALOG)
	{
		if (wizard->SetCenterFlag == false)
		{
			wizard->SetCenterFlag = true;

			Center(wizard->hWndWizard);
		}

		SetForegroundWindow(wizard->hWndWizard);
		SetActiveWindow(wizard->hWndWizard);
	}

	return ret_value;
}

// Button setting of the wizard
void SetWizardButton(WIZARD_PAGE *p, bool enable_next, bool enable_back, bool enable_close, bool is_finish)
{
	SetWizardButtonEx(p, enable_next, enable_back, enable_close, is_finish, false);
}
void SetWizardButtonEx(WIZARD_PAGE *p, bool enable_next, bool enable_back, bool enable_close, bool is_finish, bool shield_icon)
{
	DWORD flags = 0;
	DWORD flags2 = 0;
	DWORD flags3 = 0;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	p->EnableNext = enable_next;
	p->EnableBack = enable_back;
	p->EnableClose = enable_close;
	p->IsFinish = is_finish;

	if (is_finish == false)
	{
		if (p->EnableNext)
		{
			flags |= PSWIZB_NEXT;
			flags2 |= PSWIZB_NEXT;

			if (shield_icon)
			{
				if (p->Wizard->IsAreoStyle)
				{
					if (MsIsAdmin() == false)
					{
						flags3 |= PSWIZBF_ELEVATIONREQUIRED;
					}
				}
			}
		}
	}
	else
	{
		if (p->EnableNext)
		{
			flags |= PSWIZB_FINISH;
			flags2 |= PSWIZB_FINISH;
		}
		else
		{
			flags |= PSWIZB_DISABLEDFINISH;
			flags2 |= PSWIZB_FINISH;
		}
	}

	if (p->EnableBack)
	{
		flags |= PSWIZB_BACK;
		flags2 |= PSWIZB_BACK;
	}

	if (p->EnableClose)
	{
		flags2 |= 0x00000010;
	}

	PostMessage(p->Wizard->hWndWizard, PSM_SETWIZBUTTONS, flags3, flags);

	SetEnable(p->Wizard->hWndWizard, IDCANCEL, p->EnableClose);

	WINUI_PropSheet_ShowWizButtons(p->Wizard->hWndWizard,
		flags2, PSWIZB_BACK | PSWIZB_NEXT | PSWIZB_FINISH | 0x00000010);

	if (p->EnableClose)
	{
		EnableClose(p->Wizard->hWndWizard);
	}
	else
	{
		DisableClose(p->Wizard->hWndWizard);
	}
}

LRESULT CALLBACK WizardCustomizedWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WIZARD *wizard = (WIZARD *)TlsGetValue(tls_current_wizard);

	if (wizard != NULL)
	{
		switch (msg)
		{
		case WM_CTLCOLORBTN:
		case WM_CTLCOLORDLG:
		case WM_CTLCOLOREDIT:
		case WM_CTLCOLORLISTBOX:
		case WM_CTLCOLORMSGBOX:
		case WM_CTLCOLORSCROLLBAR:
		case WM_CTLCOLORSTATIC:
			return (UINT)GetStockObject(WHITE_BRUSH);
			break;
		}

		if (MsIsNt())
		{
			return CallWindowProcW(wizard->OriginalWindowProc, hWnd, msg, wParam, lParam);
		}
		else
		{
			return CallWindowProcA(wizard->OriginalWindowProc, hWnd, msg, wParam, lParam);
		}
	}
	else
	{
		return 0;
	}
}

// Procedure of the wizard
UINT CALLBACK WizardDlgProc(HWND hWnd, UINT msg, LPARAM lParam)
{
	WIZARD *wizard = (WIZARD *)TlsGetValue(tls_current_wizard);
	switch (msg)
	{
	case PSCB_INITIALIZED:
		if (wizard != NULL)
		{
			if (wizard->hWndWizard != NULL)
			{
				wizard->hWndWizard = hWnd;
			}

			if (wizard->ReplaceWindowProcFlag == false)
			{
				wizard->ReplaceWindowProcFlag = true;

				if (MsIsNt())
				{
					wizard->OriginalWindowProc = (void *)GetWindowLongPtrW(hWnd, GWLP_WNDPROC);
				}
				else
				{
					wizard->OriginalWindowProc = (void *)GetWindowLongPtrA(hWnd, GWLP_WNDPROC);
				}

				if (wizard->OriginalWindowProc != NULL)
				{
					if (MsIsNt())
					{
						SetWindowLongPtrW(hWnd, GWLP_WNDPROC, (LONG_PTR)WizardCustomizedWindowProc);
					}
					else
					{
						SetWindowLongPtrA(hWnd, GWLP_WNDPROC, (LONG_PTR)WizardCustomizedWindowProc);
					}
				}
			}
		}
		break;
	}

	return 0;
}

// Jump to another wizard page
void JumpWizard(WIZARD_PAGE *p, UINT next_id)
{
	// Validate arguments
	if (p == NULL || next_id == 0)
	{
		return;
	}

	PropSheet_SetCurSelByID(p->Wizard->hWndWizard, next_id);
}

// Close the wizard
void CloseWizard(WIZARD_PAGE *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	p->Wizard->CloseConfirmMsg = NULL;
	SetWizardButton(p, false, false, true, false);

	if (p->Wizard->IsAreoStyle)
	{
		PropSheet_PressButton(p->hWndPage, PSBTN_CANCEL);
	}
	else
	{
		Close(p->Wizard->hWndWizard);
	}
}

// Show the wizard
void ShowWizard(HWND hWndParent, WIZARD *w, UINT start_id)
{
	void **pages_array;
	UINT num_pages;
	UINT i;
	PROPSHEETHEADERW_V2 h;
	WIZARD_PAGE *start_page;
	// Validate arguments
	if (w == NULL)
	{
		return;
	}

	num_pages = LIST_NUM(w->Pages);
	pages_array = ZeroMalloc(sizeof(void *) * num_pages);

	for (i = 0;i < num_pages;i++)
	{
		WIZARD_PAGE *p = LIST_DATA(w->Pages, i);

		pages_array[i] = CreateWizardPageInstance(w, p);

		p->Index = i;
	}

	Zero(&h, sizeof(h));
	h.dwSize = sizeof(PROPSHEETHEADERW_V2);
	h.dwFlags = PSH_WIZARD97 | PSH_HEADER | PSH_USEICONID | PSH_USECALLBACK;

	if (MsIsVista() == false)
	{
		// Aero Wizard is unavailable in pre-Vista
		w->IsAreoStyle = false;
	}

	if (MsIsAeroColor() == false)
	{
		// Aero Wizard can not be used If the color of Aero is disabled
		// even in Vista or later (if the background color is not white)
		w->IsAreoStyle = false;
	}

	if (MsIsWindows10())
	{
		// Windows 10 Icon Bug: Disable Aero Style!
		w->IsAreoStyle = false;
	}

	if (w->IsAreoStyle)
	{
		// Aero Wizard
		h.dwFlags = PSH_WIZARD | 0x00004000 | PSH_HEADER | PSH_USEICONID | PSH_USECALLBACK;
	}

	h.hInstance = hDll;
	h.pszIcon = MAKEINTRESOURCEW(w->Icon);
	h.hwndParent = hWndParent;
	h.nPages = num_pages;
	h.phpage = (HPROPSHEETPAGE *)pages_array;
	h.pszbmHeader = MAKEINTRESOURCEW(w->Bitmap);
	h.pszCaption = w->Caption;
	h.pfnCallback = WizardDlgProc;

	start_page = GetWizardPage(w, start_id);
	if (start_page != NULL)
	{
		h.nStartPage = start_page->Index;
	}

	w->hWndParent = hWndParent;
	w->hWndWizard = NULL;
	w->SetCenterFlag = false;

	TlsSetValue(tls_current_wizard, w);

	PropertySheetW(&h);

	TlsSetValue(tls_current_wizard, NULL);

	Free(pages_array);
}

// Create an instance of the wizard page
void *CreateWizardPageInstance(WIZARD *w, WIZARD_PAGE *p)
{
	PROPSHEETPAGEW_V3 t;
	// Validate arguments
	if (w == NULL || p == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	t.dwSize = sizeof(PROPSHEETPAGEW_V3);
	t.dwFlags = PSP_USETITLE | PSP_USEHEADERTITLE;// | PSP_USEHEADERSUBTITLE;
	t.hInstance = hDll;
	t.pszTemplate = MAKEINTRESOURCEW(p->Id);
	t.pfnDlgProc = (DLGPROC)WizardPageDefDlgProc;
	t.pszHeaderTitle = p->Title;
	t.pszTitle = w->Caption;

	if (p->DialogParam != NULL)
	{
		FreeBitmapList(p->DialogParam->BitmapList);
		Free(p->DialogParam);
	}

	p->DialogParam = ZeroMalloc(sizeof(DIALOG_PARAM));

	p->DialogParam->BitmapList = NewBitmapList();
	p->DialogParam->wizard = w;
	p->DialogParam->wizard_page = p;
	p->DialogParam->wizard_proc = p->Proc;
	p->DialogParam->param = w->Param;
	p->DialogParam->white = false;
	p->DialogParam->meiryo = false;

	t.lParam = (LPARAM)p->DialogParam;

	return CreatePropertySheetPageW(&t);
}

// Create a new wizard
WIZARD *NewWizard(UINT icon, UINT bitmap, wchar_t *caption, void *param)
{
	WIZARD *w = ZeroMalloc(sizeof(WIZARD));

	w->Icon = icon;
	w->Pages = NewList(NULL);
	w->Param = param;
	w->Bitmap = bitmap;
	w->Caption = CopyUniStr(caption);

	return w;
}

// Release the wizard
void FreeWizard(WIZARD *w)
{
	UINT i;
	// Validate arguments
	if (w == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(w->Pages);i++)
	{
		WIZARD_PAGE *p = LIST_DATA(w->Pages, i);

		FreeWizardPage(p);
	}

	ReleaseList(w->Pages);

	Free(w->Caption);

	Free(w);
}

// Get the wizard page
WIZARD_PAGE *GetWizardPage(WIZARD *w, UINT id)
{
	UINT i;
	// Validate arguments
	if (w == NULL || id == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(w->Pages);i++)
	{
		WIZARD_PAGE *p = LIST_DATA(w->Pages, i);

		if (p->Id == id)
		{
			return p;
		}
	}

	return NULL;
}

// Add a wizard page
void AddWizardPage(WIZARD *w, WIZARD_PAGE *p)
{
	// Validate arguments
	if (w == NULL || p == NULL)
	{
		return;
	}

	Add(w->Pages, p);

	p->Wizard = w;
}

// Create a new wizard page
WIZARD_PAGE *NewWizardPage(UINT id, WINUI_WIZARD_PROC *proc, wchar_t *title)
{
	WIZARD_PAGE *p;
	// Validate arguments
	if (id == 0 || proc == NULL)
	{
		return NULL;
	}

	p = ZeroMalloc(sizeof(WIZARD_PAGE));
	p->Id = id;
	p->Proc = proc;
	p->Title = CopyUniStr(title);

	return p;
}

// Release the wizard page
void FreeWizardPage(WIZARD_PAGE *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (p->DialogParam != NULL)
	{
		FreeBitmapList(p->DialogParam->BitmapList);
		Free(p->DialogParam);
	}

	Free(p->Title);

	Free(p);
}

// NIC information dialog procedure
UINT NicInfoProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UI_NICINFO *info = (UI_NICINFO *)param;

	switch (msg)
	{
	case WM_INITDIALOG:
		NicInfoInit(hWnd, info);

		SetTimer(hWnd, 1, 50, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			NicInfoOnTimer(hWnd, info);

			SetTimer(hWnd, 1, 50, NULL);
			break;

		case 2:
			KillTimer(hWnd, 2);
			Close(hWnd);
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
		KillTimer(hWnd, 1);
		KillTimer(hWnd, 2);
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}
void NicInfoCloseAfterTime(HWND hWnd, UI_NICINFO *info, UINT tick)
{
	UINT64 now;
	UINT64 closetime;
	// Validate arguments
	if (hWnd == NULL || info == NULL)
	{
		return;
	}

	now = Tick64();
	closetime = now + (UINT64)tick;

	if (info->CloseAfterTime == 0 || info->CloseAfterTime >= closetime)
	{
		info->CloseAfterTime = closetime;
		KillTimer(hWnd, 2);
		SetTimer(hWnd, 2, tick, NULL);
	}
}
void NicInfoShowStatus(HWND hWnd, UI_NICINFO *info, wchar_t *msg1, wchar_t *msg2, UINT icon, bool animate)
{
	// Validate arguments
	if (hWnd == NULL || info == NULL)
	{
		return;
	}
	if (icon == 0)
	{
		icon = ICO_TEST;
	}
	if (msg1 == NULL)
	{
		msg1 = L"";
	}
	if (msg2 == NULL)
	{
		msg2 = L"";
	}

	if (info->CurrentIcon != icon)
	{
		SetIcon(hWnd, S_ICON, icon);
		info->CurrentIcon = icon;
	}

	SetText(hWnd, S_STATUS1, msg1);
	SetText(hWnd, S_STATUS2, msg2);

	SetShow(hWnd, P_BAR, animate && MsIsWinXPOrWinVista());
}
void NicInfoRefresh(HWND hWnd, UI_NICINFO *info)
{
	MS_ADAPTER *a;
	IP ip;
	char ip_str[MAX_SIZE];
	char title[MAX_SIZE];
	UINT i;
	wchar_t tmp[MAX_SIZE];
	bool has_ip = false;
	// Validate arguments
	if (hWnd == NULL || info == NULL)
	{
		return;
	}

	Format(title, sizeof(title), VLAN_ADAPTER_NAME_TAG, info->NicName);

	a = MsGetAdapter(title);
	if (a == NULL)
	{
		Close(hWnd);
		return;
	}

	// Check whether an IP address is assigned
	Zero(&ip, sizeof(ip));
	for (i = 0;i < MAX_MS_ADAPTER_IP_ADDRESS;i++)
	{
		if (IsZeroIP(&a->IpAddresses[i]) == false)
		{
			Copy(&ip, &a->IpAddresses[i], sizeof(IP));

			if (!(ip.addr[0] == 169 && ip.addr[1] == 254))
			{
				has_ip = true;
			}
		}
	}
	IPToStr(ip_str, sizeof(ip_str), &ip);

	if (has_ip == false)
	{
		if (a->UseDhcp)
		{
			NicInfoShowStatus(hWnd, info, _UU("NICINFO_1"), _UU("NICINFO_1_1"), ICO_NIC_OFFLINE, true);
		}
		else
		{
			NicInfoShowStatus(hWnd, info, _UU("NICINFO_1"), _UU("NICINFO_1_2"), ICO_NIC_OFFLINE, true);
		}
	}
	else
	{
		if (a->UseDhcp)
		{
			UniFormat(tmp, sizeof(tmp), _UU("NICINFO_2_1"), ip_str);
			NicInfoShowStatus(hWnd, info, _UU("NICINFO_2"), tmp, ICO_NIC_ONLINE, false);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("NICINFO_3_1"), ip_str);
			NicInfoShowStatus(hWnd, info, _UU("NICINFO_3"), tmp, ICO_NIC_ONLINE, false);
		}

		NicInfoCloseAfterTime(hWnd, info, NICINFO_AUTOCLOSE_TIME_2);
	}

	MsFreeAdapter(a);
}
void NicInfoInit(HWND hWnd, UI_NICINFO *info)
{
	// Validate arguments
	if (hWnd == NULL || info == NULL)
	{
		return;
	}

	if (MsIsWinXPOrWinVista())
	{
		// Show a progress bar for Windows XP or later
		SendMsg(hWnd, P_BAR, PBM_SETMARQUEE, TRUE, 150);
		SetStyle(hWnd, P_BAR, PBS_MARQUEE);
	}

	DlgFont(hWnd, S_STATUS1, 9, false);
	DlgFont(hWnd, S_STATUS2, 11, false);

	SetIcon(hWnd, 0, ICO_NIC_ONLINE);

	FormatText(hWnd, 0, info->NicName);

	NicInfoRefresh(hWnd, info);

	NicInfoCloseAfterTime(hWnd, info, NICINFO_AUTOCLOSE_TIME_1);
}
void NicInfoOnTimer(HWND hWnd, UI_NICINFO *info)
{
	// Validate arguments
	if (hWnd == NULL || info == NULL)
	{
		return;
	}

	if (info->Halt)
	{
		Close(hWnd);
		return;
	}

	if (info->RouteChange != NULL &&
		IsRouteChanged(info->RouteChange) == false)
	{
		return;
	}

	NicInfoRefresh(hWnd, info);
}

// Show the NIC information dialog
void NicInfo(UI_NICINFO *info)
{
	// Validate arguments
	if (info == NULL)
	{
		return;
	}

	info->RouteChange = NewRouteChange();

	DialogEx2(NULL, D_NICINFO, NicInfoProc, info, true, true);

	FreeRouteChange(info->RouteChange);
	info->RouteChange = NULL;
}

// TCP connection thread
void WinConnectDlgThread(THREAD *thread, void *param)
{
	SOCK *s;
	WINCONNECT_DLG_DATA *d = (WINCONNECT_DLG_DATA *)param;
	UINT nat_t_error_code;
	char *nat_t_svc_name = NULL;
	// Validate arguments
	if (d == NULL || thread == NULL)
	{
		return;
	}

	// Socket connection
	if (IsEmptyStr(d->nat_t_svc_name) == false)
	{
		nat_t_svc_name = d->nat_t_svc_name;
	}

	s = ConnectEx3(d->hostname, d->port, d->timeout, &d->cancel, nat_t_svc_name, &nat_t_error_code, d->try_start_ssl, false);

	d->ret_sock = s;
	d->nat_t_error_code = nat_t_error_code;

	PostMessageA(d->hWnd, WM_APP + 68, 0, 0);
}

// TCP connection dialog procedure
UINT WinConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	WINCONNECT_DLG_DATA *d = (WINCONNECT_DLG_DATA *)param;
	// Validate arguments
	if (hWnd == NULL || d == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// UI setting
		CenterParent(hWnd);
		SetText(hWnd, 0, d->caption);
		SetText(hWnd, S_INFO, d->info);
		SetIcon(hWnd, S_ICON, d->icon_id);
		d->hWnd = hWnd;

		if (MsIsWinXPOrWinVista())
		{
			// Show a progress bar for Windows XP or later
			SendMsg(hWnd, IDC_PROGRESS1, PBM_SETMARQUEE, TRUE, 100);
			SetStyle(hWnd, IDC_PROGRESS1, PBS_MARQUEE);
		}
		else
		{
			// Hide the progress bar in the case of pre-Windows 2000
			Hide(hWnd, IDC_PROGRESS1);
		}

		// Create a thread
		d->thread = NewThread(WinConnectDlgThread, d);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_APP + 68:
	case WM_CLOSE:
		if (d->cancel == false)
		{
			d->cancel = true;
			Disable(hWnd, IDCANCEL);
			if (d->ret_sock == NULL)
			{
				SetText(hWnd, S_INFO, _UU("CONNECTDLG_CANCELING"));
			}
			DoEvents(hWnd);
			Refresh(hWnd);
			WaitThread(d->thread, INFINITE);
			ReleaseThread(d->thread);
			EndDialog(hWnd, 0);
		}
		break;
	}

	return 0;
}

// TCP connection with showing the UI
SOCK *WinConnectEx3(HWND hWnd, char *server, UINT port, UINT timeout, UINT icon_id, wchar_t *caption, wchar_t *info, UINT *nat_t_error_code, char *nat_t_svc_name, bool try_start_ssl)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	WINCONNECT_DLG_DATA d;
	// Validate arguments
	if (server == NULL || port == 0)
	{
		return NULL;
	}
	if (icon_id == 0)
	{
		icon_id = ICO_USER_ADMIN;
	}
	if (caption == NULL)
	{
		if (hWnd == NULL)
		{
			caption = _UU("CONNECTDLG_CAPTION");
		}
		else
		{
			GetTxt(hWnd, 0, tmp2, sizeof(tmp2));
			caption = tmp2;
		}
	}
	if (info == NULL)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CONNECTDLG_MESSAGE"), server, port);

		info = tmp;
	}

	Zero(&d, sizeof(d));

	d.try_start_ssl = try_start_ssl;
	d.cancel = false;
	d.caption = caption;
	d.icon_id = icon_id;
	d.info = info;
	d.timeout = timeout;
	d.hostname = server;
	d.port = port;
	StrCpy(d.nat_t_svc_name, sizeof(d.nat_t_svc_name), nat_t_svc_name);

	Dialog(hWnd, D_CONNECT, WinConnectDlgProc, &d);

	if (nat_t_error_code != NULL)
	{
		*nat_t_error_code = d.nat_t_error_code;
	}

	return d.ret_sock;
}

// Show the Windows Network Setup screen
bool ShowWindowsNetworkConnectionDialog()
{
	wchar_t exe_name[MAX_SIZE];
	void *proc;

	CombinePathW(exe_name, sizeof(exe_name), MsGetSystem32DirW(), L"control.exe");

	proc = Win32RunEx2W(exe_name, L"netconnections", false, NULL);

	if (proc == NULL)
	{
		return false;
	}

	Win32CloseProcess(proc);

	return true;
}

// Get the best Meiryo font name for the current OS
char *GetMeiryoFontName()
{
	if (MsIsWindows7())
	{
		return "Meiryo UI";
	}
	else
	{
		if (MsIsVista())
		{
			return "Meiryo";
		}
		else
		{
			return "MS UI Gothic";
		}
	}
}

// Get the Meiryo font
HFONT GetMeiryoFont()
{
	return GetMeiryoFontEx(0);
}
HFONT GetMeiryoFontEx(UINT font_size)
{
	return GetMeiryoFontEx2(font_size, false);
}
HFONT GetMeiryoFontEx2(UINT font_size, bool bold)
{
	if (_GETLANG() == 0)
	{
		return GetFont(GetMeiryoFontName(), font_size, bold, false, false, false);
	}
	else if (_GETLANG() == 2)
	{
		return GetFont("Microsoft YaHei", font_size, bold, false, false, false);
	}
	else if (_GETLANG() == 3)
	{
		return GetFont("Microsoft JhengHei", font_size, bold, false, false, false);
	}
	else
	{
		return GetFont(NULL, font_size, bold, false, false, false);
	}
}

// Set font to Meiryo
void SetFontMeiryo(HWND hWnd, UINT id, UINT font_size)
{
	SetFont(hWnd, id, GetMeiryoFontEx(font_size));
}

// Set as the default font
void SetFontDefault(HWND hWnd, UINT id)
{
	SetFont(hWnd, id, GetDialogDefaultFont());
}

// Display the warning messages about bad process
void ShowBadProcessWarning(HWND hWnd, BAD_PROCESS *bad)
{
	wchar_t title[MAX_SIZE];
	wchar_t message[8192];
	// Validate arguments
	if (bad == NULL)
	{
		return;
	}

	UniFormat(title, sizeof(title), _UU("BAD_PROCESS_TITLE"), bad->Title);
	UniFormat(message, sizeof(message), _UU("BAD_PROCESS_MESSAGE"),
		bad->Title, bad->Title, bad->Title, bad->Title);

	OnceMsg(hWnd, title, message, true, ICO_WARNING);
}

// If there is process which is included in incompatible anti-virus software list, show appropriate
bool CheckBadProcesses(HWND hWnd)
{
	bool ret = true;
	UINT i;
	LIST *o;

	o = MsGetProcessList();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		MS_PROCESS *p = LIST_DATA(o, i);
		char exe[MAX_PATH];
		BAD_PROCESS *bad;

		GetFileNameFromFilePath(exe, sizeof(exe), p->ExeFilename);

		bad = IsBadProcess(exe);

		if (bad != NULL)
		{
			// Display the message because a bad process have been found
			ret = false;

			ShowBadProcessWarning(hWnd, bad);
		}
	}

	MsFreeProcessList(o);

	return ret;
}

// Search whether the specified process name is the appropriate to a bad process
BAD_PROCESS *IsBadProcess(char *exe)
{
	UINT i;
	// Validate arguments
	if (exe == NULL)
	{
		return NULL;
	}

	for (i = 0;i < num_bad_processes;i++)
	{
		BAD_PROCESS *bad = &bad_processes[i];

		if (StrCmpi(bad->ExeName, exe) == 0)
		{
			return bad;
		}
	}

	return NULL;
}

// Message display procedure
UINT OnceMsgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	ONCEMSG_DLG *d = (ONCEMSG_DLG *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetText(hWnd, 0, d->Title);
		SetText(hWnd, E_TEXT, d->Message);
		SetShow(hWnd, C_DONTSHOWAGAIN, d->ShowCheckbox);
		//DisableClose(hWnd);
		Focus(hWnd, IDCANCEL);
		if (d->Icon != 0)
		{
			SetIcon(hWnd, 0, d->Icon);
		}

		if (MsIsVista())
		{
			SetFont(hWnd, E_TEXT, GetMeiryoFont());
		}
		else
		{
			DlgFont(hWnd, E_TEXT, 11, false);
		}

		SetTimer(hWnd, 1, 50, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (*d->halt)
			{
				Close(hWnd);
			}
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
		KillTimer(hWnd, 1);
		d->Checked = IsChecked(hWnd, C_DONTSHOWAGAIN);
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// Show a message
void OnceMsg(HWND hWnd, wchar_t *title, wchar_t *message, bool show_checkbox, UINT icon)
{
	OnceMsgEx(hWnd, title, message, show_checkbox, icon, NULL);
}
void OnceMsgEx(HWND hWnd, wchar_t *title, wchar_t *message, bool show_checkbox, UINT icon, bool *halt)
{
	ONCEMSG_DLG d;
	UINT hash;
	char valuename[MAX_PATH];
	bool b_dummy = false;
	// Validate arguments
	if (title == NULL)
	{
		title = title_bar;
	}
	if (message == NULL)
	{
		message = L"message";
	}
	if (halt == NULL)
	{
		halt = &b_dummy;
	}

	Zero(&d, sizeof(d));
	d.Message = message;
	d.Title = title;
	d.ShowCheckbox = show_checkbox;
	d.Icon = icon;
	d.halt = halt;

	hash = GetOnceMsgHash(title, message);
	Format(valuename, sizeof(valuename), ONCE_MSG_REGVALUE, hash);

	if (MsRegReadInt(REG_CURRENT_USER, ONCE_MSG_REGKEY, valuename) == 0)
	{
		switch (icon)
		{
		case ICO_WARNING:
			MessageBeep(MB_ICONEXCLAMATION);
			break;

		case ICO_INFORMATION:
			MessageBeep(MB_ICONASTERISK);
			break;
		}

		Dialog(hWnd, D_ONCEMSG, OnceMsgProc, &d);

		if (show_checkbox)
		{
			if (d.Checked)
			{
				MsRegWriteInt(REG_CURRENT_USER, ONCE_MSG_REGKEY, valuename, 1);
			}
		}
	}
}

// Get the message hash
UINT GetOnceMsgHash(wchar_t *title, wchar_t *message)
{
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	UINT ret;
	// Validate arguments
	if (title == NULL)
	{
		title = title_bar;
	}
	if (message == NULL)
	{
		message = L"message";
	}

	b = NewBuf();
	// 2013.5.19: Exclude the title from the hash calculation
	//WriteBuf(b, title, UniStrSize(title));
	WriteBuf(b, message, UniStrSize(message));
	Sha1(hash, b->Buf, b->Size);
	FreeBuf(b);

	Copy(&ret, hash, sizeof(UINT));

	return ret;
}

// Set a theme for Windows Vista
void InitVistaWindowTheme(HWND hWnd)
{
	static HINSTANCE hInstDll = NULL;
	HRESULT (WINAPI *_SetWindowTheme)(HWND, LPCWSTR, LPCWSTR) = NULL;

	if (MsIsVista() == false)
	{
		return;
	}

	if (hInstDll == NULL)
	{
		hInstDll = LoadLibraryA("uxtheme.dll");
	}

	if (hInstDll == NULL)
	{
		return;
	}

	if (_SetWindowTheme == NULL)
	{
		_SetWindowTheme = (HRESULT (WINAPI *)(HWND,LPCWSTR,LPCWSTR))GetProcAddress(hInstDll, "SetWindowTheme");
	}

	if (_SetWindowTheme == NULL)
	{
		return;
	}

	_SetWindowTheme(hWnd, L"explorer", NULL);
}

// Register all applications to be registered in the Windows firewall
// that may be present in the current directory
void RegistWindowsFirewallAll()
{
	char exedir[MAX_SIZE];

	GetExeDir(exedir, sizeof(exedir));

	RegistWindowsFirewallAllEx(exedir);
}
void RegistWindowsFirewallAllEx(char *dir)
{
	MsRegistWindowsFirewallEx2(CEDAR_CLIENT_STR, "vpnclient.exe", dir);
	MsRegistWindowsFirewallEx2(CEDAR_CLIENT_MANAGER_STR, "vpncmgr.exe", dir);
	MsRegistWindowsFirewallEx2(CEDAR_MANAGER_STR, "vpnsmgr.exe", dir);
	MsRegistWindowsFirewallEx2(CEDAR_SERVER_STR, "vpnserver.exe", dir);
	MsRegistWindowsFirewallEx2(CEDAR_BRIDGE_STR, "vpnbridge.exe", dir);
	MsRegistWindowsFirewallEx2(CEDAR_CUI_STR, "vpncmd.exe", dir);
	MsRegistWindowsFirewallEx2(CEDAR_PRODUCT_STR, "vpntest.exe", dir);
}

// Check whether the notification service is already running
bool Win32CnCheckAlreadyExists(bool lock)
{
	char tmp[MAX_SIZE];
	HANDLE hMutex;

	HashInstanceNameLocal(tmp, sizeof(tmp), CLIENT_NOTIFY_SERVICE_INSTANCENAME);

	hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, tmp);
	if (hMutex != NULL)
	{
		CloseHandle(hMutex);
		return true;
	}

	if (lock == false)
	{
		return false;
	}

	hMutex = CreateMutex(NULL, FALSE, tmp);
	if (hMutex == NULL)
	{
		CloseHandle(hMutex);
		return true;
	}

	return false;
}

// Show the Easter Egg
void ShowEasterEgg(HWND hWnd)
{
}

void KakushiThread(THREAD *thread, void *param)
{
	KAKUSHI *k;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	k = (KAKUSHI *)param;

	k->Thread = thread;
	AddRef(k->Thread->ref);
	NoticeThreadInit(thread);

	Dialog(NULL, D_CM_KAKUSHI, KakushiDlgProc, k);
	k->hWnd = NULL;
}

KAKUSHI *InitKakushi()
{
	THREAD *t;
	KAKUSHI *k = ZeroMalloc(sizeof(KAKUSHI));

	t = NewThread(KakushiThread, k);

	WaitThreadInit(t);
	ReleaseThread(t);

	return k;
}

UINT KakushiDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	KAKUSHI *k = (KAKUSHI *)param;
	UINT64 now;
	bool b;
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetText(hWnd, S_INFO, _UU("CM_VLAN_CREATING"));

		b = false;

		if (MsIsVista())
		{
			if (_GETLANG() == 0)
			{
				SetFont(hWnd, S_INFO, GetFont(GetMeiryoFontName(), 11, false, false, false, false));
				b = true;
			}
			else if (_GETLANG() == 2)
			{
				SetFont(hWnd, S_INFO, GetFont("Microsoft YaHei", 11, false, false, false, false));
				b = true;
			}
			else if (_GETLANG() == 3)
			{
				SetFont(hWnd, S_INFO, GetFont("Microsoft JhengHei", 11, false, false, false, false));
				b = true;
			}
		}

		if (b == false)
		{
			DlgFont(hWnd, S_INFO, 11, false);
		}

		SetTimer(hWnd, 1, 50, NULL);
		k->hWnd = hWnd;

		k->Span = 20 * 1000;
		k->StartTick = Tick64();

		SetRange(hWnd, P_PROGRESS, 0, (UINT)k->Span);

	case WM_APP + 9821:
		now = Tick64();

		if (((k->StartTick + k->Span) <= now) || k->Halt)
		{
			EndDialog(hWnd, 0);
			break;
		}

		SetPos(hWnd, P_PROGRESS, (UINT)(now - k->StartTick));
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			AllowSetForegroundWindow(ASFW_ANY);
			SetForegroundWindow(hWnd);
			SetActiveWindow(hWnd);

			now = Tick64();

			if (((k->StartTick + k->Span) <= now) || k->Halt)
			{
				EndDialog(hWnd, 0);
				break;
			}

			SetPos(hWnd, P_PROGRESS, (UINT)(now - k->StartTick));
			break;
		}
		break;

	case WM_CLOSE:
		return 1;
	}

	return 0;
}

// Release the Kakushi screen 
void FreeKakushi(KAKUSHI *k)
{
	// Validate arguments
	if (k == NULL)
	{
		return;
	}

	k->Halt = true;

	if (k->hWnd != NULL)
	{
		PostMessage(k->hWnd, WM_APP + 9821, 0, 0);
	}

	WaitThread(k->Thread, INFINITE);
	ReleaseThread(k->Thread);

	Free(k);
}

// TCP/IP optimization selection dialog procedure
UINT TcpMsgDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UINT ret;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_SETUP);
		//DlgFont(hWnd, R_OPTIMIZE, 0, true);

		Check(hWnd, R_NO, true);

		if (g_tcpip_topmost)
		{
			Top(hWnd);
		}

		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			ret = 1;
			if (IsChecked(hWnd, R_MANUAL))
			{
				ret = 2;
			}
			else if (IsChecked(hWnd, R_NO))
			{
				ret = 0;
			}

			EndDialog(hWnd, ret);
			break;
		}
		break;

	case WM_CLOSE:
		return 1;
	}

	return 0;
}

// Initialize the dialog
void TcpIpDlgInit(HWND hWnd)
{
	MS_TCP tcp;

	SetIcon(hWnd, 0, ICO_SETUP);

	MsGetTcpConfig(&tcp);

	Check(hWnd, R_RECV_DISABLE, tcp.RecvWindowSize == 0);
	Check(hWnd, R_RECV_ENABLE, tcp.RecvWindowSize != 0);
	SetInt(hWnd, E_RECV, tcp.RecvWindowSize != 0 ? tcp.RecvWindowSize : DEFAULT_TCP_MAX_WINDOW_SIZE_RECV);

	Check(hWnd, R_SEND_DISABLE, tcp.SendWindowSize == 0);
	Check(hWnd, R_SEND_ENABLE, tcp.SendWindowSize != 0);
	SetInt(hWnd, E_SEND, tcp.SendWindowSize != 0 ? tcp.SendWindowSize : DEFAULT_TCP_MAX_WINDOW_SIZE_SEND);

	TcpIpDlgUpdate(hWnd);

	Top(hWnd);
}

// Update the dialog
void TcpIpDlgUpdate(HWND hWnd)
{
	bool ok = true;

	SetEnable(hWnd, E_RECV, IsChecked(hWnd, R_RECV_ENABLE));
	SetEnable(hWnd, S_RECV, IsChecked(hWnd, R_RECV_ENABLE));
	SetEnable(hWnd, E_SEND, IsChecked(hWnd, R_SEND_ENABLE));
	SetEnable(hWnd, S_SEND, IsChecked(hWnd, R_SEND_ENABLE));

	if (IsChecked(hWnd, R_RECV_ENABLE) && GetInt(hWnd, E_RECV) < 1454)
	{
		ok = false;
	}

	if (IsChecked(hWnd, R_SEND_ENABLE) && GetInt(hWnd, E_SEND) < 1454)
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);
}

// TCP/IP dialog procedure
UINT TcpIpDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	MS_TCP tcp, old;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		TcpIpDlgInit(hWnd);

		if (g_tcpip_topmost)
		{
			Top(hWnd);
		}

		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_RECV_DISABLE:
		case R_RECV_ENABLE:
		case R_SEND_DISABLE:
		case R_SEND_ENABLE:
		case E_RECV:
		case E_SEND:
			TcpIpDlgUpdate(hWnd);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			Zero(&tcp, sizeof(tcp));

			if (IsChecked(hWnd, R_RECV_ENABLE))
			{
				tcp.RecvWindowSize = GetInt(hWnd, E_RECV);
			}

			if (IsChecked(hWnd, R_SEND_ENABLE))
			{
				tcp.SendWindowSize = GetInt(hWnd, E_SEND);
			}

			MsGetTcpConfig(&old);

			MsSetTcpConfig(&tcp);
			MsSaveTcpConfigReg(&tcp);

			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;

		case R_RECV_ENABLE:
			FocusEx(hWnd, E_RECV);
			break;

		case R_SEND_ENABLE:
			FocusEx(hWnd, E_SEND);
			break;

		case B_RECV:
			SetInt(hWnd, E_RECV, DEFAULT_TCP_MAX_WINDOW_SIZE_RECV);
			Check(hWnd, R_RECV_DISABLE, false);
			Check(hWnd, R_RECV_ENABLE, true);
			TcpIpDlgUpdate(hWnd);
			FocusEx(hWnd, E_RECV);
			break;

		case B_SEND:
			SetInt(hWnd, E_SEND, DEFAULT_TCP_MAX_WINDOW_SIZE_SEND);
			Check(hWnd, R_SEND_DISABLE, false);
			Check(hWnd, R_SEND_ENABLE, true);
			TcpIpDlgUpdate(hWnd);
			FocusEx(hWnd, E_SEND);
			break;

		case B_DELETE:
			Zero(&tcp, sizeof(tcp));
			MsSetTcpConfig(&tcp);
			MsDeleteTcpConfigReg();
			EndDialog(hWnd, 0);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Warning dialog about 64-bit
UINT Cpu64DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_WARNING);
		DlgFont(hWnd, S_BOLD, 9, true);
		SetTimer(hWnd, 1, 30 * 1000, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			Command(hWnd, IDOK);
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
		EndDialog(hWnd, 0);
		break;
	}

	return 0;
}

// Display a warning dialog about 64-bit
void ShowCpu64Warning()
{
	Dialog(NULL, D_CPU64_WARNING, Cpu64DlgProc, NULL);
}

// Show the TCP/IP configuration utility
void ShowTcpIpConfigUtil(HWND hWnd, bool util_mode)
{
	if (MsIsTcpConfigSupported() == false)
	{
		if (util_mode)
		{
			// Show a message that is not supported by the current OS
			if (MsIsAdmin() == false)
			{
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("TCPOPT_NOT_ADMIN"));
			}
			else
			{
				MsgBox(hWnd, MB_ICONINFORMATION, _UU("TCPOPT_NOT_SUPPORTED"));
			}
		}
		return;
	}

	if (util_mode == false)
	{
		// Exit immediately by start the vpncmd
		wchar_t tmp[MAX_PATH];
		wchar_t exedir[MAX_PATH];
		HANDLE h;

		GetExeDirW(exedir, sizeof(exedir));

		if (IsX64())
		{
			UniFormat(tmp, sizeof(tmp), L"%s\\vpncmd_x64.exe", exedir);
		}
		else if (IsIA64())
		{
			UniFormat(tmp, sizeof(tmp), L"%s\\vpncmd_ia64.exe", exedir);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), L"%s\\vpncmd.exe", exedir);
		}

		if (IsFileW(tmp))
		{
			RunW(tmp, L"/tool /cmd:exit", true, false);
		}

		// Disable the task off-loading by netsh
		if (MsIsVista())
		{
			DIRLIST *dl;
			UINT i;
			bool b = false;

			dl = EnumDirW(exedir);

			for (i = 0;i < dl->NumFiles;i++)
			{
				if (UniInStr(dl->File[i]->FileNameW, L"vpnbridge") || 
					UniInStr(dl->File[i]->FileNameW, L"vpnserver"))
				{
					b = true;
				}
			}

			FreeDir(dl);

			if (b)
			{
				// Disable the off-loading
				MsDisableNetworkOffloadingEtc();
			}
		}

		// Windows Firewall registration
		RegistWindowsFirewallAll();

		SleepThread(1000);

		// Start vpnclient.exe /uihelp
		h = CmExecUiHelperMain();
		if (h != NULL)
		{
			CloseHandle(h);
		}

		if (Is64() == false)
		{
			if (MsIs64BitWindows())
			{
				// Show a warning message if a 32-bit version is used in 64-bit Windows
				ShowCpu64Warning();
			}
		}

		if (MsIsAdmin())
		{
			if (MsIsVista())
			{
				// If installing on Windows Vista,
				// dispel the network limitation of MMCSS
				if (MsIsMMCSSNetworkThrottlingEnabled())
				{
					MsSetMMCSSNetworkThrottlingEnable(false);
				}
			}
		}
	}

	if (util_mode == false && MsIsShouldShowTcpConfigApp() == false)
	{
		return;
	}

	if (util_mode == false)
	{
		// 2006.07.04 nobori
		// I decided not to show TCP/IP optimization utility in the installer
		return;
	}

	g_tcpip_topmost = util_mode ? false : true;

	if (util_mode == false)
	{
		UINT ret = Dialog(hWnd, D_TCP_MSG, TcpMsgDlgProc, NULL);

		if (ret == 0)
		{
			MS_TCP tcp;

			Zero(&tcp, sizeof(tcp));
			MsGetTcpConfig(&tcp);
			MsSaveTcpConfigReg(&tcp);
			return;
		}
		else if (ret == 1)
		{
			MS_TCP tcp;

			Zero(&tcp, sizeof(tcp));

			tcp.RecvWindowSize = DEFAULT_TCP_MAX_WINDOW_SIZE_RECV;
			tcp.SendWindowSize = DEFAULT_TCP_MAX_WINDOW_SIZE_SEND;
			MsSetTcpConfig(&tcp);
			MsSaveTcpConfigReg(&tcp);

			return;
		}
	}

	Dialog(hWnd, D_TCP, TcpIpDlgProc, NULL);
}

// Internationalization of menu (Unicode)
void InitMenuInternationalUni(HMENU hMenu, char *prefix)
{
	UINT i, num;
	// Validate arguments
	if (hMenu == NULL || prefix == NULL)
	{
		return;
	}

	// Get the number of items in the menu
	num = GetMenuItemCount(hMenu);

	// Enumerate the menu items
	for (i = 0;i < num;i++)
	{
		HMENU hSubMenu = GetSubMenu(hMenu, i);
		MENUITEMINFOW info;
		wchar_t tmp[MAX_SIZE];

		if (hSubMenu != NULL)
		{
			// If there is a sub-menu, call it recursively
			InitMenuInternational(hSubMenu, prefix);
		}

		// Get the menu item
		Zero(&info, sizeof(info));
		info.cbSize = sizeof(info);
		info.cch = sizeof(tmp);
		info.dwTypeData = tmp;
		info.fMask = MIIM_STRING;
		Zero(tmp, sizeof(tmp));

		if (GetMenuItemInfoW(hMenu, i, true, &info))
		{
			if (tmp[0] == L'@')
			{
				char name[256];
				wchar_t *ret;

				Format(name, sizeof(name), "%s@%S", prefix, &tmp[1]);

				ret = _UU(name);
				if (UniIsEmptyStr(ret) == false)
				{
					UniStrCpy(tmp, sizeof(tmp), ret);
					info.cch = UniStrLen(tmp);

					SetMenuItemInfoW(hMenu, i, true, &info);
				}
			}
		}
	}
}

// Internationalization of menu
void InitMenuInternational(HMENU hMenu, char *prefix)
{
	UINT i, num;
	// Validate arguments
	if (hMenu == NULL || prefix == NULL)
	{
		return;
	}

	if (MsIsNt())
	{
		InitMenuInternationalUni(hMenu, prefix);
		return;
	}

	// Get the number of items in the menu
	num = GetMenuItemCount(hMenu);

	// Enumerate the menu items
	for (i = 0;i < num;i++)
	{
		HMENU hSubMenu = GetSubMenu(hMenu, i);
		MENUITEMINFO info;
		char tmp[MAX_SIZE];

		if (hSubMenu != NULL)
		{
			// If there is a sub-menu, call it recursively
			InitMenuInternational(hSubMenu, prefix);
		}

		// Get the menu item
		Zero(&info, sizeof(info));
		info.cbSize = sizeof(info);
		info.cch = sizeof(tmp);
		info.dwTypeData = tmp;
		info.fMask = MIIM_STRING;
		Zero(tmp, sizeof(tmp));

		if (GetMenuItemInfo(hMenu, i, true, &info))
		{
			if (tmp[0] == '@')
			{
				char name[256];
				char *ret;

				Format(name, sizeof(name), "%s@%s", prefix, &tmp[1]);

				ret = _SS(name);
				if (IsEmptyStr(ret) == false)
				{
					StrCpy(tmp, sizeof(tmp), ret);
					info.cch = StrLen(tmp);

					SetMenuItemInfo(hMenu, i, true, &info);
				}
			}
		}
	}
}

// Get the default font for the dialog box
HFONT GetDialogDefaultFont()
{
	return GetDialogDefaultFontEx(false);
}
HFONT GetDialogDefaultFontEx(bool meiryo)
{
	char *default_font_name = _SS("DEFAULT_FONT");
	UINT default_font_size = _II("DEFAULT_FONT_SIZE");
	char *win7_font = _SS("DEFAULT_FONT_WIN7");

	if (meiryo)
	{
		if (_GETLANG() == 2)
		{
			default_font_name = "Microsoft YaHei";
		}
		if (_GETLANG() == 3)
		{
			default_font_name = "Microsoft JhengHei";
		}
		else
		{
			default_font_name = GetMeiryoFontName();
		}
	}

	if (MsIsWindows7())
	{
		if (IsEmptyStr(win7_font) == false)
		{
			default_font_name = win7_font;
		}

		if (GetTextScalingFactor() >= 1.44)
		{
			// Use a substitute font in the case of high-DPI in Windows 7 and later
			char *alternative_font = _SS("DEFAULT_FONT_HIGHDPI");

			if (IsEmptyStr(alternative_font) == false)
			{
				default_font_name = alternative_font;
			}
		}
	}

	if (IsEmptyStr(default_font_name))
	{
		default_font_name = font_name;
	}

	if (default_font_size == 0)
	{
		default_font_size = 9;
	}

	return GetFont(default_font_name, default_font_size, false, false, false, false);
}

// Adjust the control size and window size
void AdjustWindowAndControlSize(HWND hWnd, bool *need_resize, double *factor_x, double *factor_y)
{
	HFONT hDlgFont;
	UINT dlgfont_x, dlgfont_y;
	RECT rect, rect2;
	LIST *o;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || need_resize == NULL || factor_x == NULL || factor_y == NULL)
	{
		return;
	}

	*need_resize = true;

	// Get the font of the current window
	hDlgFont = (HFONT)SendMsg(hWnd, 0, WM_GETFONT, 0, 0);

	// Get the width and height of the font of the current window
	CalcFontSize(hDlgFont, &dlgfont_x, &dlgfont_y);

	if ((dlgfont_x == WINUI_DEFAULT_DIALOG_UNIT_X) &&
		(dlgfont_y == WINUI_DEFAULT_DIALOG_UNIT_Y))
	{
		// There is no need to adjust
		*need_resize = false;
		*factor_x = 1.0;
		*factor_y = 1.0;
		//Debug("// There is no need to adjust\n");
		return;
	}

	// Calculate the adjustment amount
	*factor_x = (double)dlgfont_x / (double)WINUI_DEFAULT_DIALOG_UNIT_X;
	*factor_y = (double)dlgfont_y / (double)WINUI_DEFAULT_DIALOG_UNIT_Y;
	//Debug("Factors: %f %f\n", *factor_x, *factor_y);

	if (MsIsVista())
	{
		// In Windows Vista or later, trust the size expansion by the OS to follow this (not adjusted)
		return;
	}

	// Adjust the size of the window
	if (GetWindowRect(hWnd, &rect))
	{
		if (GetClientRect(hWnd, &rect2))
		{
			UINT width = rect2.right - rect2.left;
			UINT height = rect2.bottom - rect2.top;

			AdjustDialogXY(&width, &height, dlgfont_x, dlgfont_y);

			width += (rect.right - rect.left) - (rect2.right - rect2.left);
			height += (rect.bottom - rect.top) - (rect2.bottom - rect2.top);

			if (true)
			{
				HWND hParent = GetParent(hWnd);

				if (hParent != NULL)
				{
					RECT r;

					Zero(&r, sizeof(r));

					if (GetWindowRect(hParent, &r))
					{
						RECT r2;

						rect.top = r.top + GetSystemMetrics(SM_CYCAPTION);

						Zero(&r2, sizeof(r2));
						if (SystemParametersInfo(SPI_GETWORKAREA, 0, &r2, 0))
						{
							if (r2.bottom < (rect.top + (int)height))
							{
								rect.top -= (rect.top + (int)height) - r2.bottom;

								if (rect.top < 0)
								{
									rect.top = 0;
								}
							}
						}
					}
				}
			}

			MoveWindow(hWnd, rect.left, rect.top, width, height, false);
		}
	}

	// Enumerate the child windows
	o = EnumAllChildWindowEx(hWnd, false, true, true);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		// Adjust the size of the child window
		HWND h = *((HWND *)LIST_DATA(o, i));
		HWND hWndParent = GetParent(h);
		RECT current_rect;
		char class_name[MAX_PATH];
		bool is_image = false;

		// Get the class name
		Zero(class_name, sizeof(class_name));
		GetClassNameA(h, class_name, sizeof(class_name));

		if (StrCmpi(class_name, "static") == 0)
		{
			if (SendMsg(h, 0, STM_GETIMAGE, IMAGE_BITMAP, 0) != 0 ||
				SendMsg(h, 0, STM_GETIMAGE, IMAGE_ICON, 0) != 0 ||
				SendMsg(h, 0, STM_GETICON, 0, 0) != 0)
			{
				is_image = true;
			}
		}

		// Get the position
		if (GetWindowRect(h, &current_rect))
		{
			// Convert to client coordinates
			POINT p1, p2;

			p1.x = current_rect.left;
			p1.y = current_rect.top;

			p2.x = current_rect.right;
			p2.y = current_rect.bottom;

			ScreenToClient(hWndParent, &p1);
			ScreenToClient(hWndParent, &p2);

			// Adjust the position
			AdjustDialogXY(&p1.x, &p1.y, dlgfont_x, dlgfont_y);
			AdjustDialogXY(&p2.x, &p2.y, dlgfont_x, dlgfont_y);

			if (is_image)
			{
				p2.x = p1.x + (current_rect.right - current_rect.left);
				p2.y = p1.y + (current_rect.bottom - current_rect.top);
			}

			// Move
			MoveWindow(h, p1.x, p1.y, p2.x - p1.x, p2.y - p1.y, false);
		}
	}

	FreeWindowList(o);
}

// Adjust the values of x and y according to the font
void AdjustDialogXY(UINT *x, UINT *y, UINT dlgfont_x, UINT dlgfont_y)
{
	if (x != NULL)
	{
		*x = (UINT)(((double)*x) * (double)WINUI_DEFAULT_DIALOG_UNIT_X / (double)dlgfont_x);
	}

	if (y != NULL)
	{
		*y = (UINT)(((double)*y) * (double)WINUI_DEFAULT_DIALOG_UNIT_Y / (double)dlgfont_y);
	}
}

// Internationalizing process for the dialog box
void InitDialogInternational(HWND hWnd, void *pparam)
{
	LIST *o;
	UINT i;
	bool is_managed_dialog = false;
	char caption[MAX_PATH];
	char *dialog_name;
	DIALOG_PARAM *param = (DIALOG_PARAM *)pparam;
	HDC hDC;
	bool need_resize = false;
	double factor_x = 0.0, factor_y = 0.0;
	// Validate arguments
	if (hWnd == NULL || param == NULL)
	{
		return;
	}

	hDC = CreateCompatibleDC(NULL);

	AdjustWindowAndControlSize(hWnd, &need_resize, &factor_x, &factor_y);

	GetTxtA(hWnd, 0, caption, sizeof(caption));
	if (caption[0] == '@')
	{
		dialog_name = &caption[1];

		is_managed_dialog = true;
	}

	// Enumerate all window handles
	o = EnumAllChildWindow(hWnd);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HWND hControl = *((HWND *)LIST_DATA(o, i));

		if (hControl != NULL)
		{
			bool set_font = true;
			HFONT hFont = GetDialogDefaultFontEx(param && ((DIALOG_PARAM *)param)->meiryo);

			if (MsIsWine())
			{
				char classname[MAX_PATH];
				char parent_classname[MAX_PATH];
				HWND hParent = GetParent(hControl);

				Zero(classname, sizeof(classname));
				Zero(parent_classname, sizeof(parent_classname));

				GetClassNameA(hControl, classname, sizeof(classname));

				if (hParent != NULL)
				{
					GetClassNameA(hParent, parent_classname, sizeof(parent_classname));
				}

				if (StrCmpi(classname, "edit") == 0)
				{
					set_font = false;
				}

				if (StrCmpi(classname, "combobox") == 0)
				{
					set_font = false;
				}

				if (StrCmpi(classname, "syslistview32") == 0)
				{
					set_font = false;
				}

				if (StrCmpi(classname, "sysheader32") == 0)
				{
					set_font = false;
				}

				if (StrCmpi(parent_classname, "SysIPAddress32") == 0 ||
					StrCmpi(classname, "SysIPAddress32") == 0)
				{
					set_font = true;
					hFont = GetFont("Tahoma", 8, false, false, false, false);
				}
			}

			if (set_font)
			{
				SetFont(hControl, 0, hFont);
			}

			if (MsIsVista())
			{
				char classname[MAX_PATH];
				GetClassNameA(hControl, classname, sizeof(classname));

				if (StrCmpi(classname, "syslistview32") == 0)
				{
					InitVistaWindowTheme(hControl);
				}
			}

			if (is_managed_dialog)
			{
				char str[MAX_PATH];

				GetTxtA(hControl, 0, str, sizeof(str));
				if (str[0] == '@')
				{
					char *control_name = &str[1];
					char tmp[MAX_PATH];
					wchar_t *ret;

					StrCpy(tmp, sizeof(tmp), dialog_name);
					StrCat(tmp, sizeof(tmp), "@");

					if (hWnd == hControl)
					{
						StrCat(tmp, sizeof(tmp), "CAPTION");
					}
					else
					{
						StrCat(tmp, sizeof(tmp), control_name);
					}

					ret = _UU(tmp);

					if (ret != NULL && UniIsEmptyStr(ret) == false)
					{
						SetText(hControl, 0, ret);
					}
				}
			}
		}
	}

	FreeWindowList(o);

	if (MsIsVista() && need_resize)
	{
		// Since the window size is changed automatically by the OS by the dpi setting
		// in Windows Vista or later, a static (bitmap) control needs to be expanded
		// by anticipating the size after changing

		// Enumerate all child window (not recursive)
		o = EnumAllChildWindowEx(hWnd, true, false, true);

		for (i = 0;i < LIST_NUM(o);i++)
		{
			HWND hControl = *((HWND *)LIST_DATA(o, i));

			if (hControl != NULL)
			{
				char class_name[MAX_SIZE];

				Zero(class_name, sizeof(class_name));
				GetClassNameA(hControl, class_name, sizeof(class_name));

				if (StrCmpi(class_name, "static") == 0)
				{
					UINT style = GetStyle(hControl, 0);

					if (style & SS_BITMAP)
					{
						// Get the Bitmap
						HBITMAP hBitmap = (HBITMAP)SendMessage(hControl, STM_GETIMAGE, IMAGE_BITMAP, 0);

						if (hBitmap != NULL)
						{
							// Get the size of this bitmap
							UINT src_x;
							UINT src_y;

							if (GetBitmapSize(hBitmap, &src_x, &src_y))
							{
								RECT ctl_rect;

								Zero(&ctl_rect, sizeof(ctl_rect));

								if (GetWindowRect(hControl, &ctl_rect))
								{
									// Use the smaller magnification of the height and the width
									//double scale_factor = 1.5;
									double scale_factor = MIN(factor_x, factor_y);
									UINT dst_x = (UINT)((double)src_x * scale_factor);
									UINT dst_y = (UINT)((double)src_y * scale_factor);

									HBITMAP hDst = ResizeBitmap(hBitmap, src_x, src_y, dst_x, dst_y);

									if (hDst != NULL)
									{
										Add(param->BitmapList, hDst);

										SendMessage(hControl, STM_SETIMAGE, IMAGE_BITMAP, (LPARAM)hDst);
									}
								}
							}
						}
					}
				}
			}
		}

		FreeWindowList(o);
	}

	DeleteDC(hDC);
}

// Get the size of the bitmap
bool GetBitmapSize(void *bmp, UINT *x, UINT *y)
{
	BITMAP info;
	// Validate arguments
	if (bmp == NULL || x == NULL || y == NULL)
	{
		return false;
	}

	Zero(&info, sizeof(info));
	if (GetObject((HANDLE)bmp, sizeof(info), &info) == 0)
	{
		return false;
	}

	*x = info.bmWidth;
	*y = info.bmHeight;

	return true;
}

// Resize the bitmap
HBITMAP ResizeBitmap(HBITMAP hSrc, UINT src_x, UINT src_y, UINT dst_x, UINT dst_y)
{
	HDC hMemDC;
	HDC hSrcDC;
	HBITMAP ret = NULL;
	BITMAPINFOHEADER h;
	BITMAPINFO bi;
	UCHAR *data = NULL;
	// Validate arguments
	if (hSrc == NULL)
	{
		return NULL;
	}

	hSrcDC = CreateCompatibleDC(NULL);
	if (hSrcDC != NULL)
	{
		HBITMAP hOld = SelectObject(hSrcDC, hSrc);

		if (hOld != NULL)
		{
			hMemDC = CreateCompatibleDC(NULL);

			if (hMemDC != NULL)
			{
				HBITMAP hOld;
				HBITMAP srcHbitMap;
				UCHAR* srcData;
				CT_RectF_c destRect;
				CT_RectF_c srcRect;

				Zero(&h, sizeof(h));
				h.biSize = sizeof(h);
				h.biWidth = src_x;
				h.biHeight = src_y;
				h.biPlanes = 1;
				h.biBitCount = 32;
				h.biXPelsPerMeter = 2834;
				h.biYPelsPerMeter = 2834;
				h.biCompression = BI_RGB;

				// Copy once the transfer source
				Zero(&bi, sizeof(bi));
				Copy(&bi.bmiHeader, &h, sizeof(BITMAPINFOHEADER));
				srcHbitMap = CreateDIBSection(hMemDC, &bi, DIB_RGB_COLORS, &srcData, NULL, 0);

				hOld = SelectObject(hMemDC, srcHbitMap);

				BitBlt(hMemDC,0,0,src_x,src_y,hSrcDC,0,0, SRCCOPY);

				GdiFlush();



				// Generate a resized version
				if(src_x != dst_x || src_y != dst_y)
				{
					h.biWidth = dst_x;
					h.biHeight = dst_y;
					Zero(&bi, sizeof(bi));
					Copy(&bi.bmiHeader, &h, sizeof(BITMAPINFOHEADER));

					ret = CreateDIBSection(hMemDC, &bi, DIB_RGB_COLORS, &data, NULL, 0);

					if(srcData != NULL && data != NULL)
					{
						destRect.X = 0; destRect.Y = 0;
						destRect.Width = (float)dst_x; destRect.Height = (float)dst_y;
						srcRect = destRect;
						srcRect.Width = (float)src_x; srcRect.Height = (float)src_y;

						CT_DrawImage((UCHAR*)data, destRect, dst_x,dst_y, 
							(UCHAR*)srcData, srcRect,src_x, src_y);
					}

					if(srcHbitMap != NULL)
					{
						DeleteObject(srcHbitMap);
					}
				}
				else
				{
					ret = srcHbitMap;
				}

				SelectObject(hMemDC, hOld);

				DeleteDC(hMemDC);
			}

			SelectObject(hSrcDC, hOld);
		}

		DeleteDC(hSrcDC);
	}

	return ret;
}

// Initialize the bitmap list
LIST *NewBitmapList()
{
	LIST *o = NewListFast(NULL);

	return o;
}

// Release the bitmap list
void FreeBitmapList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HBITMAP *h = LIST_DATA(o, i);

		DeleteObject(h);
	}

	ReleaseList(o);
}

// Child window enumeration procedure
// Initialize the dialog
void StringDlgInit(HWND hWnd, STRING_DLG *s)
{
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	SetText(hWnd, E_STRING, s->String);

	SetIcon(hWnd, S_ICON, s->Icon);
	SetText(hWnd, S_INFO, s->Info);
	SetText(hWnd, 0, s->Title);

	FocusEx(hWnd, E_STRING);

	StringDlgUpdate(hWnd, s);
}

// Update the dialog control
void StringDlgUpdate(HWND hWnd, STRING_DLG *s)
{
	wchar_t *tmp;
	bool b = true;
	// Validate arguments
	if (hWnd == NULL || s == NULL)
	{
		return;
	}

	tmp = GetText(hWnd, E_STRING);

	if (tmp != NULL)
	{
		if (s->AllowEmpty == false)
		{
			if (UniIsEmptyStr(tmp))
			{
				b = false;
			}
		}

		if (s->AllowUnsafe == false)
		{
			if (IsSafeUniStr(tmp) == false)
			{
				b = false;
			}
		}

		Free(tmp);
	}

	SetEnable(hWnd, IDOK, b);
}

// String dialog procedure
UINT StringDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	STRING_DLG *s = (STRING_DLG *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		StringDlgInit(hWnd, s);
		break;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case E_STRING:
			StringDlgUpdate(hWnd, s);
			break;
		}

		switch (wParam)
		{
		case IDOK:
			GetTxt(hWnd, E_STRING, s->String, sizeof(s->String));
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

// Show the string dialog
wchar_t *StringDlg(HWND hWnd, wchar_t *title, wchar_t *info, wchar_t *def, UINT icon, bool allow_empty, bool allow_unsafe)
{
	STRING_DLG s;
	// Validate arguments
	if (title == NULL)
	{
		title = _UU("DLG_STRING_DEFTITLE");
	}
	if (info == NULL)
	{
		info = _UU("DLG_STRING_DEFINFO");
	}
	if (def == NULL)
	{
		def = L"";
	}
	if (icon == 0)
	{
		icon = ICO_NULL;
	}

	Zero(&s, sizeof(s));
	s.Icon = icon;
	s.Info = info;
	s.Title = title;
	s.Icon = icon;
	UniStrCpy(s.String, sizeof(s.String), def);
	s.AllowEmpty = allow_empty;
	s.AllowUnsafe = allow_unsafe;

	if (Dialog(hWnd, D_STRING, StringDlgProc, &s) == false)
	{
		return NULL;
	}
	else
	{
		return CopyUniStr(s.String);
	}
}
char *StringDlgA(HWND hWnd, wchar_t *title, wchar_t *info, char *def, UINT icon, bool allow_empty, bool allow_unsafe)
{
	wchar_t unidef[MAX_SIZE];
	wchar_t *tmp;
	char *ret;
	if (def == NULL)
	{
		def = "";
	}

	StrToUni(unidef, sizeof(unidef), def);

	tmp = StringDlg(hWnd, title, info, unidef, icon, allow_empty, allow_unsafe);
	if (tmp == NULL)
	{
		return NULL;
	}

	ret = CopyUniToStr(tmp);
	Free(tmp);

	return ret;
}

// Restarting dialog
UINT Win9xRebootDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	WIN9X_REBOOT_DLG *d = (WIN9X_REBOOT_DLG *)param;
	UINT64 now;
	wchar_t tmp[MAX_PATH];
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		d->StartTime = Tick64();
		SetRange(hWnd, P_PROGRESS, 0, d->TotalTime);
		SetTimer(hWnd, 1, 100, NULL);
		goto UPDATE;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
UPDATE:
			now = Tick64();
			if ((d->StartTime + (UINT64)d->TotalTime) <= now)
			{
				KillTimer(hWnd, 1);
				UniStrCpy(tmp, sizeof(tmp), _UU("DLG_REBOOT_INFO_2"));
				SetText(hWnd, S_INFO, tmp);
				if (MsShutdown(true, false) == false)
				{
					MsgBox(hWnd, MB_ICONSTOP, _UU("DLG_REBOOT_ERROR"));
				}
				EndDialog(hWnd, 0);
			}
			else
			{
				SetPos(hWnd, P_PROGRESS, (UINT)(now - d->StartTime));
				UniFormat(tmp, sizeof(tmp), _UU("DLG_REBOOT_INFO"),
					(UINT)((UINT64)d->TotalTime - (now - d->StartTime)) / 1000 + 1);
				SetText(hWnd, S_INFO, tmp);
			}

			break;
		}
		break;
	}
	return 0;
}

// Restarting thread
void Win9xRebootThread(THREAD *t, void *p)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Win9xReboot(NULL);
}

// Restart automatically
void Win9xReboot(HWND hWnd)
{
	WIN9X_REBOOT_DLG d;

	Zero(&d, sizeof(d));
	d.TotalTime = 10 * 1000;

	Dialog(hWnd, D_WIN9X_REBOOT, Win9xRebootDlgProc, &d);
}

// Show a text file
void ShowTextFile(HWND hWnd, char *filename, wchar_t *caption, UINT icon)
{
	BUF *b;
	wchar_t *str;
	// Validate arguments
	if (filename == NULL || caption == NULL)
	{
		return;
	}
	if (icon == 0)
	{
		icon = ICO_NULL;
	}

	// Read the text file
	b = ReadDump(filename);
	if (b == NULL)
	{
		return;
	}

	SeekBufToEnd(b);
	WriteBufChar(b, 0);

	str = CopyUtfToUni(b->Buf);

	OnceMsg(hWnd, caption, str, false, icon);

	FreeBuf(b);
	Free(str);
}

// Initialize the version information
void AboutDlgInit(HWND hWnd, WINUI_ABOUT *a)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || a == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, ICO_INFORMATION);

	UniFormat(tmp, sizeof(tmp), _UU("ABOUT_CAPTION"), a->ProductName);
	SetText(hWnd, 0, tmp);

	SetFont(hWnd, S_INFO1, GetFont("Arial", 12, false, false, false, false));
	FormatText(hWnd, S_INFO1, CEDAR_VERSION_MAJOR, CEDAR_VERSION_MAJOR, CEDAR_VERSION_MINOR, CEDAR_VERSION_BUILD);

	SetFont(hWnd, S_INFO2, GetFont("Arial", 8, false, false, false, false));
	FormatText(hWnd, S_INFO2, BUILD_DATE_Y, a->Cedar->BuildInfo);

	SetFont(hWnd, S_INFO3, GetFont("Arial", 7, false, false, false, false));

	if (MsIsWine())
	{
		Disable(hWnd, B_LANGUAGE);
	}

	//DlgFont(hWnd, S_INFO4, 8, false);

	SetShow(hWnd, B_UPDATE_CONFIG, (a->Update != NULL));

	Show(hWnd, B_AUTHORS);
}

// Version information procedure
UINT AboutDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	WINUI_ABOUT *a = (WINUI_ABOUT *)param;
	char tmp[MAX_PATH];
	LANGLIST t;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		AboutDlgInit(hWnd, a);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			if ((GetKeyState(VK_SHIFT) & 0x8000) &&
				(GetKeyState(VK_CONTROL) & 0x8000) &&
				(GetKeyState(VK_MENU) & 0x8000))
			{
				ShowEasterEgg(hWnd);
			}
			EndDialog(hWnd, true);
			break;
		case B_WEB:
			ShellExecute(hWnd, "open", _SS("SE_COMPANY_URL"), NULL, NULL, SW_SHOW);
			break;
		case B_EULA:
			ShowTextFile(hWnd, "|eula.txt", _UU("SW_EULA_TITLE"), ICO_LOG);
			break;
		case B_IMPORTANT:
			GetCurrentLang(&t);
			Format(tmp, sizeof(tmp), "|warning_%s.txt", t.Name);
			ShowTextFile(hWnd, tmp, _UU("SW_WARNING_TITLE"), ICO_LOG);
			break;
		case B_LEGAL:
			ShowTextFile(hWnd, "|legal.txt", _UU("DLG_ABOUT_LEGAL"), ICO_LOG);
			break;
		case B_UPDATE_CONFIG:
			ConfigUpdateUi(a->Update, hWnd);
			break;
		case B_AUTHORS:
			ShowTextFile(hWnd, "|authors.txt", _UU("DLG_ABOUT_AUTHORS"), ICO_ZURUHAM);
			break;
		case B_LANGUAGE:
			// Language settings
			if (true)
			{
				wchar_t path[MAX_SIZE];

				CombinePathW(path, sizeof(path), MsGetExeDirNameW(), L"vpnsetup.exe");

				if (IsFileExistsW(path))
				{
					// with Installer
					if (MsExecuteW(path, L"/language:yes") == false)
					{
						MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SW_CHILD_PROCESS_ERROR"));
					}
				}
				else
				{
					// without Installer
					CombinePathW(path, sizeof(path), MsGetExeDirNameW(), L"lang.config");
					if (MsExecuteW(path, L"") == false)
					{
						MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SW_CHILD_PROCESS_ERROR"));
					}
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

// Version information
void About(HWND hWnd, CEDAR *cedar, wchar_t *product_name)
{
	AboutEx(hWnd, cedar, product_name, NULL);
}
void AboutEx(HWND hWnd, CEDAR *cedar, wchar_t *product_name, WINUI_UPDATE *u)
{
	WINUI_ABOUT a;
	// Validate arguments
	if (cedar == NULL || product_name == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));
	a.Cedar = cedar;
	a.ProductName = product_name;
	a.Update = u;

	Dialog(hWnd, D_ABOUT, AboutDlgProc, &a);
}

// Examine the number of fields that an IP address is entered
UINT IpGetFilledNum(HWND hWnd, UINT id)
{
	UINT ret;
	DWORD value;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	ret = SendMsg(hWnd, id, IPM_GETADDRESS, 0, (LPARAM)&value);

	return ret;
}

// Examine whether an IP address has been entered
bool IpIsFilled(HWND hWnd, UINT id)
{
	UINT ret;
	DWORD value;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	ret = SendMsg(hWnd, id, IPM_GETADDRESS, 0, (LPARAM)&value);

	if (ret != 4)
	{
		return false;
	}
	else
	{
		return true;
	}
}

// Get an IP address
UINT IpGet(HWND hWnd, UINT id)
{
	UINT ret;
	DWORD value;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	ret = SendMsg(hWnd, id, IPM_GETADDRESS, 0, (LPARAM)&value);

	if (ret != 4)
	{
		return 0;
	}
	else
	{
		return Endian32((UINT)value);
	}
}

// Set the IP addresses
void IpSet(HWND hWnd, UINT id, UINT ip)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, IPM_SETADDRESS, 0, Endian32(ip));
}

// Write the candidates to the registry
void WriteCandidateToReg(UINT root, char *key, LIST *o, char *name)
{
	BUF *b;
	// Validate arguments
	if (key == NULL || o == NULL || name == NULL)
	{
		return;
	}

	b = CandidateToBuf(o);
	if (b == NULL)
	{
		return;
	}

	MsRegWriteBin(root, key, name, b->Buf, b->Size);

	FreeBuf(b);
}

// Read the candidates from the registry
LIST *ReadCandidateFromReg(UINT root, char *key, char *name)
{
	BUF *b;
	// Validate arguments
	if (key == NULL || name == NULL)
	{
		return NULL;
	}

	b = MsRegReadBin(root, key, name);
	if (b == NULL)
	{
		return NewCandidateList();
	}
	else
	{
		LIST *o = BufToCandidate(b);
		FreeBuf(b);

		return o;
	}
}

// initialize the remote connection dialog
void RemoteDlgInit(HWND hWnd, WINUI_REMOTE *r)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	SetIcon(hWnd, 0, r->Icon);

	SetText(hWnd, 0, r->Caption);
	SetText(hWnd, S_TITLE, r->Title);
	SetIcon(hWnd, S_ICON, r->Icon);

	// Read candidates
	o = ReadCandidateFromReg(REG_CURRENT_USER, r->RegKeyName, "RemoteHostCandidate");
	r->CandidateList = o;

	// Show the candidates
	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANDIDATE *c = LIST_DATA(o, i);
		CbAddStr(hWnd, C_HOSTNAME, c->Str, 0);
	}

	if (r->DefaultHostname != NULL)
	{
		SetTextA(hWnd, C_HOSTNAME, r->DefaultHostname);
	}

	FocusEx(hWnd, C_HOSTNAME);

	RemoteDlgRefresh(hWnd, r);
}

// Remote connection dialog update
void RemoteDlgRefresh(HWND hWnd, WINUI_REMOTE *r)
{
	char *s;
	bool ok = true;
	bool localhost_mode = false;
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	s = GetTextA(hWnd, C_HOSTNAME);
	if (s != NULL)
	{
		Trim(s);
		if (StrCmpi(s, "localhost") == 0 || StartWith(s, "127."))
		{
			localhost_mode = true;
		}
		Free(s);
	}

	if (localhost_mode == false)
	{
		Enable(hWnd, C_HOSTNAME);
		Enable(hWnd, S_HOSTNAME);
		Check(hWnd, R_LOCAL, false);
	}
	else
	{
		if (r->Title != _UU("NM_CONNECT_TITLE"))
		{
			Disable(hWnd, C_HOSTNAME);
			Disable(hWnd, S_HOSTNAME);
		}
		Check(hWnd, R_LOCAL, true);
		SetTextA(hWnd, C_HOSTNAME, "localhost");

		if (r->flag1 == false)
		{
			Focus(hWnd, IDOK);
		}
	}

	if (IsEmpty(hWnd, C_HOSTNAME))
	{
		ok = false;
	}

	SetEnable(hWnd, IDOK, ok);

	r->flag1 = true;
}

// Remote connection dialog OK button
void RemoteDlgOnOk(HWND hWnd, WINUI_REMOTE *r)
{
	char *hostname;
	wchar_t *s;
	LIST *o;
	// Validate arguments
	if (hWnd == NULL || r == NULL)
	{
		return;
	}

	// Get the entered host name
	hostname = GetTextA(hWnd, C_HOSTNAME);
	if (hostname == NULL)
	{
		return;
	}
	Trim(hostname);

	// Add a candidate
	o = r->CandidateList;
	s = CopyStrToUni(hostname);
	AddCandidate(o, s, 64);
	Free(s);

	// Write the candidates
	WriteCandidateToReg(REG_CURRENT_USER, r->RegKeyName, o, "RemoteHostCandidate");
	FreeCandidateList(o);

	r->Hostname = hostname;

	EndDialog(hWnd, true);
}

// Remote connection dialog procedure
UINT RemoteDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	WINUI_REMOTE *r = (WINUI_REMOTE *)param;
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
char *RemoteDlg(HWND hWnd, char *regkey, UINT icon, wchar_t *caption, wchar_t *title, char *default_host)
{
	WINUI_REMOTE r;
	// Validate arguments
	if (regkey == NULL)
	{
		regkey = "Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\WinUI Common Module";
	}
	if (caption == NULL)
	{
		caption = _UU("REMOTE_DEF_CAPTION");
	}
	if (title == NULL)
	{
		title = _UU("REMOTE_DEF_TITLE");
	}
	if (icon == 0)
	{
		icon = ICO_INTERNET;
	}

	Zero(&r, sizeof(r));
	r.RegKeyName = regkey;
	r.Caption = caption;
	r.Title = title;
	r.Icon = icon;
	r.DefaultHostname = default_host;

	if (Dialog(hWnd, D_REMOTE, RemoteDlgProc, &r) == false)
	{
		return NULL;
	}

	return r.Hostname;
}

// Window Searching procedure
bool CALLBACK SearchWindowEnumProc(HWND hWnd, LPARAM lParam)
{
	if (hWnd != NULL && lParam != 0)
	{
		wchar_t *s = GetText(hWnd, 0);
		SEARCH_WINDOW_PARAM *p = (SEARCH_WINDOW_PARAM *)lParam;
		if (s != NULL)
		{
			if (UniStrCmpi(p->caption, s) == 0)
			{
				p->hWndFound = hWnd;
			}
			Free(s);
		}
	}
	return true;
}

// Search for the window
HWND SearchWindow(wchar_t *caption)
{
	SEARCH_WINDOW_PARAM p;
	// Validate arguments
	if (caption == NULL)
	{
		return NULL;
	}

	Zero(&p, sizeof(p));
	p.caption = caption;
	p.hWndFound = NULL;

	EnumWindows(SearchWindowEnumProc, (LPARAM)&p);

	return p.hWndFound;
}

// Allow for the specified process to become the foreground window
void AllowFGWindow(UINT process_id)
{
	if (process_id == 0)
	{
		return;
	}

	if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) &&
		GET_KETA(GetOsInfo()->OsType, 100) >= 2)
	{
		AllowSetForegroundWindow(process_id);
	}
}

// Rename the item
void LvRename(HWND hWnd, UINT id, UINT pos)
{
	// Validate arguments
	if (hWnd == NULL || pos == INFINITE)
	{
		return;
	}

	ListView_EditLabel(DlgItem(hWnd, id), pos);
}

// Enhanced function
LRESULT CALLBACK LvEnhancedProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WNDPROC func = NULL;

	if (MsIsNt())
	{
		func = (WNDPROC)GetPropW(hWnd, L"ORIGINAL_FUNC");
	}
	else
	{
		func = (WNDPROC)GetPropA(hWnd, "ORIGINAL_FUNC");
	}

	if (func == NULL)
	{
		Debug("LvEnhancedProc(): GetProp() returned NULL!\n");
		return 1;
	}

	switch (msg)
	{
	case WM_HSCROLL:
	case WM_VSCROLL:
	case WM_MOUSEWHEEL:
	{
		// Prevent graphical glitches with the edit box by sending the NM_RETURN signal
		// to the parent dialog (the parent dialog has to delete the edit box on NM_RETURN)
		NMHDR nmh;
		nmh.code = NM_RETURN;
		nmh.idFrom = GetDlgCtrlID(hWnd);
		nmh.hwndFrom = hWnd;
		SendMsg(GetParent(hWnd), 0, WM_NOTIFY, nmh.idFrom, (LPARAM)&nmh);

		break;
	}
	case WM_CLOSE:
		// Prevent list view from disappearing after pressing ESC in an edit box
		return 0;
	case WM_NCDESTROY:
		// Restore original function during destruction
		LvSetEnhanced(hWnd, 0, false);
	}

	if (MsIsNt())
	{
		return CallWindowProcW(func, hWnd, msg, wParam, lParam);
	}
	else
	{
		return CallWindowProcA(func, hWnd, msg, wParam, lParam);
	}
}

// Toggle enhanced function
void LvSetEnhanced(HWND hWnd, UINT id, bool enable)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (enable)
	{
		if (MsIsNt())
		{
			const HANDLE fn = (HANDLE)SetWindowLongPtrW(DlgItem(hWnd, id), GWLP_WNDPROC, (LONG_PTR)LvEnhancedProc);
			SetPropW(DlgItem(hWnd, id), L"ORIGINAL_FUNC", fn);
		}
		else
		{
			const HANDLE fn = (HANDLE)SetWindowLongPtrA(DlgItem(hWnd, id), GWLP_WNDPROC, (LONG_PTR)LvEnhancedProc);
			SetPropA(DlgItem(hWnd, id), "ORIGINAL_FUNC", fn);
		}
	}
	else
	{
		if (MsIsNt())
		{
			SetWindowLongPtrW(DlgItem(hWnd, id), GWLP_WNDPROC, (LONG_PTR)GetPropW(DlgItem(hWnd, id), L"ORIGINAL_FUNC"));
			RemovePropW(DlgItem(hWnd, id), L"ORIGINAL_FUNC");
		}
		else
		{
			SetWindowLongPtrA(DlgItem(hWnd, id), GWLP_WNDPROC, (LONG_PTR)GetPropA(DlgItem(hWnd, id), "ORIGINAL_FUNC"));
			RemovePropA(DlgItem(hWnd, id), "ORIGINAL_FUNC");
		}
	}
}

// Enhanced function
LRESULT CALLBACK EditBoxEnhancedProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	WNDPROC func = NULL;

	if (MsIsNt())
	{
		func = (WNDPROC)GetPropW(hWnd, L"ORIGINAL_FUNC");
	}
	else
	{
		func = (WNDPROC)GetPropA(hWnd, "ORIGINAL_FUNC");
	}

	if (func == NULL)
	{
		Debug("EditBoxEnhancedProc(): GetProp() returned NULL!\n");
		return 1;
	}

	switch (msg)
	{
	case WM_CHAR:
		switch (wParam)
		{
		// CTRL + A
		case 1:
			SelectEdit(hWnd, 0);
			return 0;
		case VK_RETURN:
			SendMsg(GetParent(hWnd), 0, WM_KEYDOWN, VK_RETURN, 0);
			return 0;
		case VK_ESCAPE:
			DestroyWindow(hWnd);
			return 0;
		}
		break;
	case WM_NCDESTROY:
		// Restore original function during destruction
		EditBoxSetEnhanced(hWnd, 0, false);
	}

	if (MsIsNt())
	{
		return CallWindowProcW(func, hWnd, msg, wParam, lParam);
	}
	else
	{
		return CallWindowProcA(func, hWnd, msg, wParam, lParam);
	}
}

// Toggle enhanced function
void EditBoxSetEnhanced(HWND hWnd, UINT id, bool enable)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (enable)
	{
		if (MsIsNt())
		{
			const HANDLE fn = (HANDLE)SetWindowLongPtrW(DlgItem(hWnd, id), GWLP_WNDPROC, (LONG_PTR)EditBoxEnhancedProc);
			SetPropW(DlgItem(hWnd, id), L"ORIGINAL_FUNC", fn);
		}
		else
		{
			const HANDLE fn = (HANDLE)SetWindowLongPtrA(DlgItem(hWnd, id), GWLP_WNDPROC, (LONG_PTR)EditBoxEnhancedProc);
			SetPropA(DlgItem(hWnd, id), "ORIGINAL_FUNC", fn);
		}
	}
	else
	{
		if (MsIsNt())
		{
			SetWindowLongPtrW(DlgItem(hWnd, id), GWLP_WNDPROC, (LONG_PTR)GetPropW(DlgItem(hWnd, id), L"ORIGINAL_FUNC"));
			RemovePropW(DlgItem(hWnd, id), L"ORIGINAL_FUNC");
		}
		else
		{
			SetWindowLongPtrA(DlgItem(hWnd, id), GWLP_WNDPROC, (LONG_PTR)GetPropA(DlgItem(hWnd, id), "ORIGINAL_FUNC"));
			RemovePropA(DlgItem(hWnd, id), "ORIGINAL_FUNC");
		}
	}
}

// Show the menu
void PrintMenu(HWND hWnd, HMENU hMenu)
{
	POINT p;
	// Validate arguments
	if (hMenu == NULL || hWnd == NULL)
	{
		return;
	}

	GetCursorPos(&p);

	TrackPopupMenu(hMenu, TPM_LEFTALIGN, p.x, p.y, 0, hWnd, NULL);
}

// Remove a shortcut string from the menu
void RemoveShortcutKeyStrFromMenu(HMENU hMenu)
{
	UINT i, num;
	// Validate arguments
	if (hMenu == NULL)
	{
		return;
	}

	num = GetMenuNum(hMenu);
	for (i = 0;i < num;i++)
	{
		wchar_t *str = GetMenuStr(hMenu, i);
		if (str != NULL)
		{
			UINT j, len;
			len = UniStrLen(str);
			for (j = 0;j < len;j++)
			{
				if (str[j] == L'\t')
				{
					str[j] = 0;
				}
			}
			SetMenuStr(hMenu, i, str);
			Free(str);
		}
	}
}

// Get the number of items in the menu
UINT GetMenuNum(HMENU hMenu)
{
	UINT ret;
	// Validate arguments
	if (hMenu == NULL)
	{
		return 0;
	}

	ret = GetMenuItemCount(hMenu);
	if (ret == INFINITE)
	{
		return 0;
	}
	else
	{
		return ret;
	}
}

// Set the string into the menu
void SetMenuStr(HMENU hMenu, UINT pos, wchar_t *str)
{
	MENUITEMINFOW info;
	// Validate arguments
	if (hMenu == NULL || pos == INFINITE || str == NULL)
	{
		return;
	}

	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(str);
		SetMenuStrA(hMenu, pos, s);
		Free(s);
		return;
	}

	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.fMask = MIIM_STRING;
	info.dwTypeData = str;
	SetMenuItemInfoW(hMenu, pos, true, &info);
}
void SetMenuStrA(HMENU hMenu, UINT pos, char *str)
{
	MENUITEMINFOA info;
	// Validate arguments
	if (hMenu == NULL || pos == INFINITE || str == NULL)
	{
		return;
	}

	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.fMask = MIIM_STRING;
	info.dwTypeData = str;
	SetMenuItemInfoA(hMenu, pos, true, &info);
}

// Get a string in the menu
wchar_t *GetMenuStr(HMENU hMenu, UINT pos)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hMenu == NULL || pos == INFINITE)
	{
		return NULL;
	}
	if (MsIsNt() == false)
	{
		char *s = GetMenuStrA(hMenu, pos);
		if (s == NULL)
		{
			return NULL;
		}
		else
		{
			wchar_t *ret = CopyStrToUni(s);
			Free(s);
			return ret;
		}
	}

	if (GetMenuStringW(hMenu, pos, tmp, sizeof(tmp), MF_BYPOSITION) == 0)
	{
		return NULL;
	}

	return UniCopyStr(tmp);
}
char *GetMenuStrA(HMENU hMenu, UINT pos)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hMenu == NULL || pos == INFINITE)
	{
		return NULL;
	}

	if (GetMenuString(hMenu, pos, tmp, sizeof(tmp), MF_BYPOSITION) == 0)
	{
		return NULL;
	}

	return CopyStr(tmp);
}

// Bold the menu item
void SetMenuItemBold(HMENU hMenu, UINT pos, bool bold)
{
	MENUITEMINFO info;
	// Validate arguments
	if (hMenu == NULL || pos == INFINITE)
	{
		return;
	}

	Zero(&info, sizeof(info));
	info.cbSize = sizeof(info);
	info.fMask = MIIM_STATE;

	if (GetMenuItemInfo(hMenu, pos, true, &info) == false)
	{
		return;
	}

	if (bold)
	{
		info.fState |= MFS_DEFAULT;
	}
	else
	{
		info.fState = info.fState & ~MFS_DEFAULT;
	}

	SetMenuItemInfo(hMenu, pos, true, &info);
}

// Remove a menu item
void DeleteMenuItem(HMENU hMenu, UINT pos)
{
	// Validate arguments
	if (hMenu == NULL || pos == INFINITE)
	{
		return;
	}

	DeleteMenu(hMenu, pos, MF_BYPOSITION);
}

// Get the position from the ID in the menu
UINT GetMenuItemPos(HMENU hMenu, UINT id)
{
	UINT num, i;
	// Validate arguments
	if (hMenu == NULL)
	{
		return INFINITE;
	}

	num = GetMenuItemCount(hMenu);
	if (num == INFINITE)
	{
		return INFINITE;
	}

	for (i = 0;i < num;i++)
	{
		if (GetMenuItemID(hMenu, i) == id)
		{
			return i;
		}
	}

	return INFINITE;
}

// Get a sub-menu
HMENU LoadSubMenu(UINT menu_id, UINT pos, HMENU *parent_menu)
{
	HMENU h = LoadMenu(hDll, MAKEINTRESOURCE(menu_id));
	HMENU ret;
	if (h == NULL)
	{
		return NULL;
	}

	ret = GetSubMenu(h, pos);

	if (parent_menu != NULL)
	{
		*parent_menu = h;
	}

	return ret;
}

// Get the DLL of the user interface
HINSTANCE GetUiDll()
{
	return hDll;
}

// Connection Error dialog procedure
UINT ConnectErrorDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UI_CONNECTERROR_DLG *p = (UI_CONNECTERROR_DLG *)param;
	wchar_t tmp[1024];
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		if (p->Err == ERR_DISCONNECTED || p->Err == ERR_SESSION_TIMEOUT)
		{
			// Message indicating that the connection has been disconnected
			SetText(hWnd, S_TITLE, _UU("ERRDLG_DISCONNECTED_MSG"));
		}
		if (p->HideWindow)
		{
			Hide(hWnd, R_HIDE);
		}
		FormatText(hWnd, 0, p->AccountName);
		FormatText(hWnd, S_TITLE, p->ServerName);
		UniFormat(tmp, sizeof(tmp), _UU("ERRDLG_ERRMSG"), p->Err, _E(p->Err));
		SetText(hWnd, E_ERROR, tmp);

		SetIcon(hWnd, 0, ICO_SERVER_OFFLINE);

		if (p->RetryIntervalSec == 0)
		{
			SetText(hWnd, S_COUNTDOWN, _UU("ERRDLG_INFORMATION"));
			Hide(hWnd, P_PROGRESS);
			Hide(hWnd, S_RETRYINFO);
		}
		else
		{
			if (p->RetryLimit != INFINITE)
			{
				UniFormat(tmp, sizeof(tmp), _UU("ERRDLG_RETRY_INFO_1"), p->CurrentRetryCount, p->RetryLimit);
			}
			else
			{
				UniFormat(tmp, sizeof(tmp), _UU("ERRDLG_RETRY_INFO_2"), p->CurrentRetryCount);
			}
			SetText(hWnd, S_RETRYINFO, tmp);
			SetRange(hWnd, P_PROGRESS, 0, p->RetryIntervalSec);
			SetPos(hWnd, P_PROGRESS, 0);
			SetTimer(hWnd, 1, 10, NULL);
			p->StartTick = Tick64();
		}
		SetTimer(hWnd, 2, 10, NULL);
		Focus(hWnd, IDOK);
		break;
	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (p->RetryIntervalSec != 0)
			{
				UINT64 start, end, now;
				now = Tick64();
				start = p->StartTick;
				end = start + (UINT64)p->RetryIntervalSec;

				if (end > now)
				{
					SetPos(hWnd, P_PROGRESS, (UINT)(now - start));
					UniFormat(tmp, sizeof(tmp), _UU("ERRDLG_RETRYCOUNT"), ((UINT)(end - now)) / 1000);
					SetText(hWnd, S_COUNTDOWN, tmp);
				}
				else
				{
					Command(hWnd, IDOK);
				}
			}
			break;
		case 2:
			if (p->CancelEvent != NULL)
			{
				if (WaitForSingleObject((HANDLE)p->CancelEvent->pData, 0) != WAIT_TIMEOUT)
				{
					// Forced Cancel
					Close(hWnd);
				}
			}
			break;
		}
		break;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case R_HIDE:
			p->HideWindow = IsChecked(hWnd, R_HIDE);
			break;
		}
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

// Show the connection error dialog
bool ConnectErrorDlg(UI_CONNECTERROR_DLG *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return false;
	}

	return DialogEx2(NULL, D_CONNECTERROR, ConnectErrorDlgProc, p, true, true);
}

// Display the contents of the certificate
void PrintCheckCertInfo(HWND hWnd, UI_CHECKCERT *p)
{
	wchar_t tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UCHAR md5[MD5_SIZE];
	UCHAR sha1[SHA1_SIZE];
	X *x;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	x = p->x;

	GetAllNameFromNameEx(tmp, sizeof(tmp), x->subject_name);
	SetText(hWnd, E_SUBJECT, tmp);

	GetAllNameFromNameEx(tmp, sizeof(tmp), x->issuer_name);
	SetText(hWnd, E_ISSUER, tmp);

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(x->notAfter), NULL);
	SetText(hWnd, E_EXPIRES, tmp);

	GetXDigest(x, md5, false);
	BinToStr(tmp2, sizeof(tmp2), md5, sizeof(md5));
	SetTextA(hWnd, E_MD5, tmp2);

	GetXDigest(x, sha1, true);
	BinToStr(tmp2, sizeof(tmp2), sha1, sizeof(sha1));
	SetTextA(hWnd, E_SHA1, tmp2);

	SetFont(hWnd, E_MD5, GetFont("Arial", 8, false, false, false, false));
	SetFont(hWnd, E_SHA1, GetFont("Arial", 8, false, false, false, false));
}

// Warn that the certificate is different
void ShowDlgDiffWarning(HWND hWnd, UI_CHECKCERT *p)
{
	UCHAR sha1_new[SHA1_SIZE], sha1_old[SHA1_SIZE];
	UCHAR md5_new[MD5_SIZE], md5_old[MD5_SIZE];
	char sha1_new_str[MAX_SIZE], sha1_old_str[MAX_SIZE];
	char md5_new_str[MAX_SIZE], md5_old_str[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || p == NULL || p->x == NULL || p->old_x == NULL)
	{
		return;
	}

	GetXDigest(p->x, sha1_new, true);
	GetXDigest(p->x, md5_new, false);

	GetXDigest(p->old_x, sha1_old, true);
	GetXDigest(p->old_x, md5_old, false);

	BinToStrEx(sha1_new_str, sizeof(sha1_new_str), sha1_new, sizeof(sha1_new));
	BinToStrEx(md5_new_str, sizeof(md5_new_str), md5_new, sizeof(md5_new));
	BinToStrEx(sha1_old_str, sizeof(sha1_old_str), sha1_old, sizeof(sha1_old));
	BinToStrEx(md5_old_str, sizeof(md5_old_str), md5_old, sizeof(md5_old));

	MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("CC_DANGEROUS_MSG"),
		p->ServerName, md5_old_str, sha1_old_str, md5_new_str, sha1_new_str);
}

// [OK] button is pressed
void CheckCertDialogOnOk(HWND hWnd, UI_CHECKCERT *p)
{
	UCHAR sha1_new[SHA1_SIZE];
	UCHAR md5_new[MD5_SIZE];
	char sha1_new_str[MAX_SIZE];
	char md5_new_str[MAX_SIZE];
	UINT ret;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	GetXDigest(p->x, sha1_new, true);
	GetXDigest(p->x, md5_new, false);
	BinToStrEx(sha1_new_str, sizeof(sha1_new_str), sha1_new, sizeof(sha1_new));
	BinToStrEx(md5_new_str, sizeof(md5_new_str), md5_new, sizeof(md5_new));

	ret = MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNOCANCEL | MB_DEFBUTTON2,
		_UU("CC_WARNING_MSG"),
		p->AccountName, sha1_new_str, md5_new_str);

	if (ret == IDYES)
	{
		p->SaveServerCert = true;
	}

	if (ret == IDCANCEL)
	{
		return;
	}

	p->Ok = true;
	EndDialog(hWnd, true);
}

// Certificate dialog procedure
UINT CheckCertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UI_CHECKCERT *p = (UI_CHECKCERT *)param;
	// Validate arguments
	if (hWnd == NULL || param == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, 0, p->AccountName);
		FormatText(hWnd, S_TITLE, p->ServerName);
		FormatText(hWnd, S_MSG1, p->ServerName);

		PrintCheckCertInfo(hWnd, p);

		Focus(hWnd, IDCANCEL);

		SetIcon(hWnd, 0, ICO_WARNING);

		if (p->DiffWarning)
		{
			SetTimer(hWnd, 1, 1, NULL);
		}

		SetTimer(hWnd, 2, 100, NULL);

		break;
	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			ShowDlgDiffWarning(hWnd, p);
			break;
		case 2:
			if ((p->Session != NULL && p->Session->Halt) ||
				(p->Halt))
			{
				p->Ok = false;
				EndDialog(hWnd, false);
			}
			break;
		}
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case B_SHOW:
			CertDlg(hWnd, p->x, p->parent_x, false);
			break;
		case IDOK:
			CheckCertDialogOnOk(hWnd, p);
			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;
	case WM_CLOSE:
		p->Ok = false;
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Certificate Check dialog
void CheckCertDlg(UI_CHECKCERT *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	Dialog(NULL, D_CHECKCERT, CheckCertDlgProc, p);
}

// Get the image list ID from the icon ID
UINT GetIcon(UINT icon_id)
{
	IMAGELIST_ICON *c, t;
	t.id = icon_id;

	c = Search(icon_list, &t);
	if (c == NULL)
	{
		if (icon_id != ICO_NULL)
		{
			return GetIcon(ICO_NULL);
		}
		else
		{
			return INFINITE;
		}
	}
	else
	{
		return c->Index;
	}
}

// Load an icon for the image list
IMAGELIST_ICON *LoadIconForImageList(UINT id)
{
	IMAGELIST_ICON *ret = ZeroMalloc(sizeof(IMAGELIST_ICON));
	HICON small_icon, large_icon;

	ret->id = id;

	large_icon = LoadLargeIcon(id);
	if (large_icon == NULL)
	{
		large_icon = LoadSmallIcon(id);
	}

	small_icon = LoadSmallIcon(id);
	if (small_icon == NULL)
	{
		small_icon = LoadLargeIcon(id);
	}

	ret->hSmallImage = small_icon;
	ret->hLargeImage = large_icon;
	ret->Index = ImageList_AddIcon(large_image_list, large_icon);
	ImageList_AddIcon(small_image_list, small_icon);

	return ret;
}

// Comparison of the image list icons
int CompareImageListIcon(void *p1, void *p2)
{
	IMAGELIST_ICON *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(IMAGELIST_ICON **)p1;
	c2 = *(IMAGELIST_ICON **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	if (c1->id > c2->id)
	{
		return 1;
	}
	else if (c1->id < c2->id)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// Initialize thr image list
void InitImageList()
{
	large_image_list = ImageList_Create(32, 32, ILC_COLOR32 | ILC_MASK, 1, 0);
	ImageList_SetBkColor(large_image_list, RGB(255, 255, 255));
	small_image_list = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 1, 0);
	ImageList_SetBkColor(small_image_list, RGB(255, 255, 255));
	icon_list = NewList(CompareImageListIcon);

	// Enumeration
	EnumResourceNames(hDll, RT_GROUP_ICON, EnumResNameProc, 0);
}

// Icon resource enumeration procedure
BOOL CALLBACK EnumResNameProc(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR lParam)
{
	if (IS_INTRESOURCE(lpszName))
	{
		UINT icon_id = (UINT)lpszName;
		IMAGELIST_ICON *img = LoadIconForImageList(icon_id);

		Add(icon_list, img);
	}

	return TRUE;
}

// Release the image list
void FreeImageList()
{
	UINT i;
	ImageList_Destroy(large_image_list);
	ImageList_Destroy(small_image_list);
	large_image_list = small_image_list = NULL;

	for (i = 0;i < LIST_NUM(icon_list);i++)
	{
		IMAGELIST_ICON *c = LIST_DATA(icon_list, i);
		Free(c);
	}

	ReleaseList(icon_list);
	icon_list = NULL;
}

// Get the width of the column of the list view
UINT LvGetColumnWidth(HWND hWnd, UINT id, UINT index)
{
	return (UINT)((double)ListView_GetColumnWidth(DlgItem(hWnd, id), index) / GetTextScalingFactor());
}

// Insert the column into the list view
void LvInsertColumn(HWND hWnd, UINT id, UINT index, wchar_t *str, UINT width)
{
	LVCOLUMNW c;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	width = (UINT)((double)width * GetTextScalingFactor());

	Zero(&c, sizeof(c));
	c.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;

	c.pszText = str;
	c.iSubItem = index;
	c.cx = width;

	SendMsg(hWnd, id, LVM_INSERTCOLUMNW, index, (LPARAM)&c);
}

// Remove all items from list view
void LvReset(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	ListView_DeleteAllItems(DlgItem(hWnd, id));
}

// Initialize the list view
void LvInitEx(HWND hWnd, UINT id, bool no_image)
{
	LvInitEx2(hWnd, id, no_image, false);
}
void LvInitEx2(HWND hWnd, UINT id, bool no_image, bool large_icon)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	ListView_SetUnicodeFormat(DlgItem(hWnd, id), true);

	if (no_image == false)
	{
		ListView_SetImageList(DlgItem(hWnd, id), large_image_list, LVSIL_NORMAL);
		ListView_SetImageList(DlgItem(hWnd, id), large_icon ? large_image_list : small_image_list, LVSIL_SMALL);
	}

	ListView_SetExtendedListViewStyle(DlgItem(hWnd, id), LVS_EX_FULLROWSELECT);

	if (MsIsVista())
	{
		LvSetStyle(hWnd, id, LVS_EX_DOUBLEBUFFER);
	}
}
void LvInit(HWND hWnd, UINT id)
{
	LvInitEx(hWnd, id, false);
}

// Adding batch complete (high-speed)
void LvInsertEnd(LVB *b, HWND hWnd, UINT id)
{
	LvInsertEndEx(b, hWnd, id, false);
}
void LvInsertEndEx(LVB *b, HWND hWnd, UINT id, bool force_reset)
{
	UINT i, num;
	LIST *new_list, *exist_list;
	wchar_t *last_selected = NULL;
	// Validate arguments
	if (b == NULL || hWnd == NULL)
	{
		return;
	}

	new_list = NewListFast(CompareUniStr);

	for (i = 0;i < LIST_NUM(b->ItemList);i++)
	{
		LVB_ITEM *t = LIST_DATA(b->ItemList, i);
		Add(new_list, t->Strings[0]);
	}

	Sort(new_list);

	if ((LIST_NUM(b->ItemList) >= LV_INSERT_RESET_ALL_ITEM_MIN) || force_reset)
	{
		last_selected = LvGetFocusedStr(hWnd, id, 0);
		LvReset(hWnd, id);
	}

	exist_list = NewListFast(CompareUniStr);

	num = LvNum(hWnd, id);

	// Delete the items which isn't contained in the batch list of existing items
	for (i = 0;i < num;i++)
	{
		bool exists = false;
		wchar_t *s = LvGetStr(hWnd, id, i, 0);
		if (Search(new_list, s) != NULL)
		{
			exists = true;
		}
		if (exists == false)
		{
			// Remove items that don't exist in the batch list of the adding plan from the list view
			LvDeleteItem(hWnd, id, i);
			num = LvNum(hWnd, id);
			i--;
			Free(s);
		}
		else
		{
			Add(exist_list, s);
		}
	}

	Sort(exist_list);

	// Add items in the batch one by one
	for (i = 0;i < LIST_NUM(b->ItemList);i++)
	{
		LVB_ITEM *t = LIST_DATA(b->ItemList, i);
		UINT index;
		UINT j;
		bool exists = false;

		if (Search(exist_list, t->Strings[0]) != NULL)
		{
			index = LvSearchStr(hWnd, id, 0, t->Strings[0]);
		}
		else
		{
			index = INFINITE;
		}

		if (index != INFINITE)
		{
			UINT j;
			// If an item with the string same to adding item already exists,
			// update instead of adding
			for (j = 0;j < t->NumStrings;j++)
			{
				LvSetItem(hWnd, id, index, j, t->Strings[j]);
			}
			LvSetItemImageByImageListId(hWnd, id, index, t->Image);
			LvSetItemParam(hWnd, id, index, t->Param);
		}
		else
		{
			// Add newly
			UINT index = INFINITE;
			UINT j;
			for (j = 0;j < t->NumStrings;j++)
			{
				if (j == 0)
				{
					index = LvInsertItemByImageListId(hWnd, id, t->Image, t->Param, t->Strings[j]);
				}
				else
				{
					LvSetItem(hWnd, id, index, j, t->Strings[j]);
				}
			}
		}

		// Release the memory
		for (j = 0;j < t->NumStrings;j++)
		{
			Free(t->Strings[j]);
		}
		Free(t->Strings);
		Free(t);
	}

	// Release the list
	ReleaseList(b->ItemList);

	// Release the memory
	Free(b);

	ReleaseList(new_list);

	for (i = 0;i < LIST_NUM(exist_list);i++)
	{
		Free(LIST_DATA(exist_list, i));
	}
	ReleaseList(exist_list);

	if (last_selected != NULL)
	{
		UINT pos = LvSearchStr(hWnd, id, 0, last_selected);

		if (pos != INFINITE)
		{
			LvSelect(hWnd, id, pos);
		}

		Free(last_selected);
	}
}

// Get the number of columns of the list view
UINT LvGetColumnNum(HWND hWnd, UINT id)
{
	UINT i;
	LVCOLUMN c;
	if (hWnd == NULL)
	{
		return 0;
	}

	for (i = 0;;i++)
	{
		Zero(&c, sizeof(c));
		c.mask = LVCF_SUBITEM;
		if (ListView_GetColumn(DlgItem(hWnd, id), i, &c) == false)
		{
			break;
		}
	}

	return i;
}

// List-view sort function
int CALLBACK LvSortProc(LPARAM param1, LPARAM param2, LPARAM sort_param)
{
	WINUI_LV_SORT *sort = (WINUI_LV_SORT *)sort_param;
	HWND hWnd;
	UINT id;
	UINT i1, i2;
	int ret = 0;
	wchar_t *s1, *s2;
	if (sort == NULL)
	{
		return 0;
	}

	hWnd = sort->hWnd;
	id = sort->id;

	if (hWnd == NULL)
	{
		return 0;
	}

	i1 = (UINT)param1;
	i2 = (UINT)param2;

	s1 = LvGetStr(hWnd, id, i1, sort->subitem);
	if (s1 == NULL)
	{
		return 0;
	}

	s2 = LvGetStr(hWnd, id, i2, sort->subitem);
	if (s2 == NULL)
	{
		Free(s1);
		return 0;
	}

	if (sort->numeric == false)
	{
		if (UniStrCmpi(s1, _UU("CM_NEW_ICON")) == 0 || UniStrCmpi(s1, _UU("CM_VGC_ICON")) == 0 || UniStrCmpi(s1, _UU("CM_VGC_LINK")) == 0)
		{
			ret = -1;
		}
		else if (UniStrCmpi(s2, _UU("CM_NEW_ICON")) == 0 || UniStrCmpi(s2, _UU("CM_VGC_ICON")) == 0 || UniStrCmpi(s1, _UU("CM_VGC_LINK")) == 0)
		{
			ret = 1;
		}
		else
		{
			ret = UniStrCmpi(s1, s2);
		}
	}
	else
	{
		UINT64 v1, v2;
		v1 = UniToInt64(s1);
		v2 = UniToInt64(s2);
		if (v1 > v2)
		{
			ret = 1;
		}
		else if (v1 < v2)
		{
			ret = -1;
		}
		else
		{
			ret = 0;
		}
	}

	Free(s1);
	Free(s2);

	if (sort->desc)
	{
		ret = -ret;
	}

	return ret;
}

// Standard handler
void LvStandardHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT id)
{
	NMHDR *n;
	NMLVKEYDOWN *key;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	LvSortHander(hWnd, msg, wParam, lParam, id);

	switch (msg)
	{
	case WM_NOTIFY:
		n = (NMHDR *)lParam;
		if (n->idFrom == id)
		{
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
					case VK_DELETE:
						Command(hWnd, B_DELETE);
						break;

					case VK_RETURN:
						Command(hWnd, IDOK);
						break;

					case VK_F5:
						Command(hWnd, B_REFRESH);
						break;
					}
				}
				break;
			}
		}
		break;
	}
}

// Sort header handler
void LvSortHander(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT id)
{
	NMHDR *nmhdr;
	UINT subitem;
	bool desc;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	switch (msg)
	{
	case WM_NOTIFY:
		nmhdr = (NMHDR *)lParam;

		if (nmhdr != NULL)
		{
			if (nmhdr->idFrom == id)
			{
				NMLISTVIEW *v;
				switch (nmhdr->code)
				{
				case LVN_COLUMNCLICK:
					desc = false;
					v = (NMLISTVIEW *)lParam;
					subitem = v->iSubItem;

					if ((GetStyle(hWnd, id) & LVS_SORTDESCENDING) == 0)
					{
						desc = true;
						SetStyle(hWnd, id, LVS_SORTDESCENDING);
						RemoveStyle(hWnd, id, LVS_SORTASCENDING);
					}
					else
					{
						SetStyle(hWnd, id, LVS_SORTASCENDING);
						RemoveStyle(hWnd, id, LVS_SORTDESCENDING);
					}

					LvSort(hWnd, id, subitem, desc);
					break;
				}
			}
		}
		break;
	}
}

// Do sort
void LvSort(HWND hWnd, UINT id, UINT subitem, bool desc)
{
	UINT i, num;
	bool numeric = true;
	wchar_t na[2] = {0xff0d, 0x0, };
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	num = LvNum(hWnd, id);
	for (i = 0;i < num;i++)
	{
		wchar_t *s = LvGetStr(hWnd, id, i, subitem);
		if (s != NULL)
		{
			if (UniIsNum(s) == false && UniStrCmp(s, na) != 0)
			{
				numeric = false;
				Free(s);
				break;
			}
			Free(s);
		}
		else
		{
			numeric = false;
			break;
		}
	}

	LvSortEx(hWnd, id, subitem, desc, numeric);
}

void LvSortEx(HWND hWnd, UINT id, UINT subitem, bool desc, bool numeric)
{
	WINUI_LV_SORT s;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}
	if (subitem >= LvGetColumnNum(hWnd, id))
	{
		return;
	}

	Zero(&s, sizeof(s));
	s.desc = desc;
	s.numeric = numeric;
	s.id = id;
	s.hWnd = hWnd;
	s.subitem = subitem;

	ListView_SortItemsEx(DlgItem(hWnd, id), LvSortProc, (LPARAM)&s);
}

// Add an item to adding batch
void LvInsertAdd(LVB *b, UINT icon, void *param, UINT num_str, ...)
{
	UINT i;
	va_list va;
	UINT index = 0;
	LVB_ITEM *t;
	// Validate arguments
	if (b == NULL || num_str == 0)
	{
		return;
	}

	t = ZeroMalloc(sizeof(LVB_ITEM));

	va_start(va, num_str);

	t->Strings = (wchar_t **)ZeroMalloc(sizeof(wchar_t *) * num_str);
	t->NumStrings = num_str;

	for (i = 0;i < num_str;i++)
	{
		wchar_t *s = va_arg(va, wchar_t *);

		t->Strings[i] = UniCopyStr(s);
	}

	t->Param = param;
	t->Image = GetIcon(icon);

	Add(b->ItemList, t);

	va_end(va);
}

// Start the item adding batch
LVB *LvInsertStart()
{
	LVB *b = ZeroMalloc(sizeof(LVB));
	b->ItemList = NewListFast(NULL);

	return b;
}

// Add items to the list view
void LvInsert(HWND hWnd, UINT id, UINT icon, void *param, UINT num_str, ...)
{
	UINT i;
	va_list va;
	UINT index = 0;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	va_start(va, num_str);

	for (i = 0;i < num_str;i++)
	{
		wchar_t *s = va_arg(va, wchar_t *);
		if (i == 0)
		{
			index = LvInsertItem(hWnd, id, icon, param, s);
		}
		else
		{
			LvSetItem(hWnd, id, index, i, s);
		}
	}

	va_end(va);
}

// Adjust the item size automatically
void LvAutoSize(HWND hWnd, UINT id)
{
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	i = 0;
	while (true)
	{
		if (ListView_SetColumnWidth(DlgItem(hWnd, id), i, LVSCW_AUTOSIZE) == false)
		{
			break;
		}
		i++;
	}
}

// Add an item
UINT LvInsertItem(HWND hWnd, UINT id, UINT icon, void *param, wchar_t *str)
{
	return LvInsertItemByImageListId(hWnd, id, GetIcon(icon), param, str);
}
UINT LvInsertItemByImageListId(HWND hWnd, UINT id, UINT image, void *param, wchar_t *str)
{
	LVITEMW t;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}
	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(str);
		UINT ret;
		ret = LvInsertItemByImageListIdA(hWnd, id, image, param, s);
		Free(s);
		return ret;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_IMAGE | LVIF_PARAM | LVIF_TEXT;
	t.pszText = str;
	t.iImage = image;
	t.lParam = (LPARAM)param;
	t.iItem = LvNum(hWnd, id);

	return SendMsg(hWnd, id, LVM_INSERTITEMW, 0, (LPARAM)&t);
}
UINT LvInsertItemByImageListIdA(HWND hWnd, UINT id, UINT image, void *param, char *str)
{
	LVITEM t;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_IMAGE | LVIF_PARAM | LVIF_TEXT;
	t.pszText = str;
	t.iImage = image;
	t.lParam = (LPARAM)param;
	t.iItem = LvNum(hWnd, id);

	return SendMsg(hWnd, id, LVM_INSERTITEM, 0, (LPARAM)&t);
}

// Change the image
void LvSetItemImageByImageListId(HWND hWnd, UINT id, UINT index, UINT image)
{
	LVITEM t;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_IMAGE;
	t.iImage = image;
	t.iItem = index;

	SendMsg(hWnd, id, LVM_SETITEM, 0, (LPARAM)&t);
}

// Set the parameters of the item
void LvSetItemParam(HWND hWnd, UINT id, UINT index, void *param)
{
	LvSetItemParamEx(hWnd, id, index, 0, param);
}
void LvSetItemParamEx(HWND hWnd, UINT id, UINT index, UINT subitem, void *param)
{
	LVITEM t;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_PARAM;
	t.iItem = index;
	t.iSubItem = subitem;
	t.lParam = (LPARAM)param;

	SendMsg(hWnd, id, LVM_SETITEM, 0, (LPARAM)&t);
}

// Set the item
void LvSetItem(HWND hWnd, UINT id, UINT index, UINT pos, wchar_t *str)
{
	LVITEMW t;
	wchar_t *old_str;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return;
	}
	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(str);
		LvSetItemA(hWnd, id, index, pos, s);
		Free(s);
		return;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_TEXT;
	t.pszText = str;
	t.iItem = index;
	t.iSubItem = pos;

	old_str = LvGetStr(hWnd, id, index, pos);

	if (UniStrCmp(old_str, str) != 0)
	{
		SendMsg(hWnd, id, LVM_SETITEMW, 0, (LPARAM)&t);
	}

	Free(old_str);
}
void LvSetItemA(HWND hWnd, UINT id, UINT index, UINT pos, char *str)
{
	LVITEM t;
	wchar_t *old_str;
	char *old_str_2;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_TEXT;
	t.pszText = str;
	t.iItem = index;
	t.iSubItem = pos;

	old_str = LvGetStr(hWnd, id, index, pos);
	old_str_2 = CopyUniToStr(old_str);

	if (StrCmp(old_str_2, str) != 0)
	{
		SendMsg(hWnd, id, LVM_SETITEM, 0, (LPARAM)&t);
	}

	Free(old_str_2);
	Free(old_str);
}

// Set the view of the list box
void LvSetView(HWND hWnd, UINT id, bool details)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (details)
	{
		RemoveStyle(hWnd, id, LVS_ICON);
		SetStyle(hWnd, id, LVS_REPORT);
	}
	else
	{
		RemoveStyle(hWnd, id, LVS_REPORT);
		SetStyle(hWnd, id, LVS_ICON);
	}
}

// Get whether there is currently selected item
bool LvIsSelected(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return false;
	}

	if (LvGetSelected(hWnd, id) == INFINITE)
	{
		return false;
	}

	return true;
}

// Get the currently selected item
UINT LvGetFocused(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return ListView_GetNextItem(DlgItem(hWnd, id), -1, LVNI_FOCUSED);
}

// Get the parameter of the currently selected item
void *LvGetSelectedParam(HWND hWnd, UINT id)
{
	UINT index;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	index = LvGetSelected(hWnd, id);

	if (index == INFINITE)
	{
		return NULL;
	}

	return LvGetParam(hWnd, id, index);
}

// Get a string that is currently selected
wchar_t *LvGetFocusedStr(HWND hWnd, UINT id, UINT pos)
{
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	i = LvGetFocused(hWnd, id);
	if (i == INFINITE)
	{
		return NULL;
	}

	return LvGetStr(hWnd, id, i, pos);
}

// Get the currently selected item
UINT LvGetSelected(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return ListView_GetNextItem(DlgItem(hWnd, id), -1, LVNI_FOCUSED | LVNI_SELECTED);
}

// Get a string that is currently selected
wchar_t *LvGetSelectedStr(HWND hWnd, UINT id, UINT pos)
{
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	i = LvGetSelected(hWnd, id);
	if (i == INFINITE)
	{
		return NULL;
	}

	return LvGetStr(hWnd, id, i, pos);
}
char *LvGetSelectedStrA(HWND hWnd, UINT id, UINT pos)
{
	char *ret;
	wchar_t *tmp = LvGetSelectedStr(hWnd, id, pos);
	if (tmp == NULL)
	{
		return NULL;
	}
	ret = CopyUniToStr(tmp);
	Free(tmp);
	return ret;
}

// Get whether two or more items are masked
bool LvIsMultiMasked(HWND hWnd, UINT id)
{
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return false;
	}

	i = INFINITE;
	i = LvGetNextMasked(hWnd, id, i);
	if (i != INFINITE)
	{
		if (LvGetNextMasked(hWnd, id, i) != INFINITE)
		{
			return true;
		}
	}

	return false;
}

// Examine whether just only one item is selected
bool LvIsSingleSelected(HWND hWnd, UINT id)
{
	return LvIsSelected(hWnd, id) && (LvIsMultiMasked(hWnd, id) == false);
}

// Get whether there are items that are currently masked
bool LvIsMasked(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return false;
	}

	if (LvGetNextMasked(hWnd, id, INFINITE) == INFINITE)
	{
		return false;
	}

	return true;
}

// Get the items that is currently masked
UINT LvGetNextMasked(HWND hWnd, UINT id, UINT start)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return ListView_GetNextItem(DlgItem(hWnd, id), start, LVNI_SELECTED);
}

// Search an item with the specified string
UINT LvSearchStr(HWND hWnd, UINT id, UINT pos, wchar_t *str)
{
	UINT i, num;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	num = LvNum(hWnd, id);

	for (i = 0;i < num;i++)
	{
		wchar_t *s = LvGetStr(hWnd, id, i, pos);
		if (s != NULL)
		{
			if (UniStrCmpi(s, str) == 0)
			{
				Free(s);
				return i;
			}
			else
			{
				Free(s);
			}
		}
	}

	return INFINITE;
}
UINT LvSearchStrA(HWND hWnd, UINT id, UINT pos, char *str)
{
	wchar_t *tmp = CopyStrToUni(str);
	UINT ret = LvSearchStr(hWnd, id, pos, tmp);
	Free(tmp);
	return ret;
}

// Search for item that have a specified param
UINT LvSearchParam(HWND hWnd, UINT id, void *param)
{
	UINT i, num;
	// Validate arguments
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	num = LvNum(hWnd, id);

	for (i = 0;i < num;i++)
	{
		if (LvGetParam(hWnd, id, i) == param)
		{
			return i;
		}
	}

	return INFINITE;
}

// Get the number of items
UINT LvNum(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	return ListView_GetItemCount(DlgItem(hWnd, id));
}

// Remove an item
void LvDeleteItem(HWND hWnd, UINT id, UINT index)
{
	UINT i;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	ListView_DeleteItem(DlgItem(hWnd, id), index);

	i = LvGetSelected(hWnd, id);
	if (i != INFINITE)
	{
		LvSelect(hWnd, id, i);
	}
}

// Get the data from the item
void *LvGetParam(HWND hWnd, UINT id, UINT index)
{
	return LvGetParamEx(hWnd, id, index, 0);
}
void *LvGetParamEx(HWND hWnd, UINT id, UINT index, UINT subitem)
{
	LVITEM t;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}
	if (index == INFINITE)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	t.mask = LVIF_PARAM;
	t.iItem = index;
	t.iSubItem = subitem;

	if (ListView_GetItem(DlgItem(hWnd, id), &t) == false)
	{
		return NULL;
	}

	return (void *)t.lParam;
}

// Get the string of item
wchar_t *LvGetStr(HWND hWnd, UINT id, UINT index, UINT pos)
{
	wchar_t *tmp;
	UINT size;
	LVITEMW t;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}
	if (MsIsNt() == false)
	{
		char *s = LvGetStrA(hWnd, id, index, pos);
		if (s == NULL)
		{
			return NULL;
		}
		else
		{
			wchar_t *ret = CopyStrToUni(s);
			Free(s);

			return ret;
		}
	}

	size = 65536;
	tmp = Malloc(size);

	Zero(&t, sizeof(t));
	t.mask = LVIF_TEXT;
	t.iItem = index;
	t.iSubItem = pos;
	t.pszText = tmp;
	t.cchTextMax = size;

	if (SendMsg(hWnd, id, LVM_GETITEMTEXTW, index, (LPARAM)&t) <= 0)
	{
		Free(tmp);
		return UniCopyStr(L"");
	}
	else
	{
		wchar_t *ret = UniCopyStr(tmp);
		Free(tmp);
		return ret;
	}
}
char *LvGetStrA(HWND hWnd, UINT id, UINT index, UINT pos)
{
	char *tmp;
	UINT size;
	LVITEM t;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	size = 65536;
	tmp = Malloc(size);

	Zero(&t, sizeof(t));
	t.mask = LVIF_TEXT;
	t.iItem = index;
	t.iSubItem = pos;
	t.pszText = tmp;
	t.cchTextMax = size;

	if (SendMsg(hWnd, id, LVM_GETITEMTEXT, index, (LPARAM)&t) <= 0)
	{
		Free(tmp);
		return CopyStr("");
	}
	else
	{
		char *ret = CopyStr(tmp);
		Free(tmp);
		return ret;
	}
}

// Set the style
void LvSetStyle(HWND hWnd, UINT id, UINT style)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if ((ListView_GetExtendedListViewStyle(DlgItem(hWnd, id)) & style) == 0)
	{
		ListView_SetExtendedListViewStyleEx(DlgItem(hWnd, id), style, style);
	}
}

// Remove the style
void LvRemoveStyle(HWND hWnd, UINT id, UINT style)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if ((ListView_GetExtendedListViewStyle(DlgItem(hWnd, id)) & style) != 0)
	{
		ListView_SetExtendedListViewStyleEx(DlgItem(hWnd, id), style, 0);
	}
}

// Invert the selection of items
void LvSwitchSelect(HWND hWnd, UINT id)
{
	UINT i, num;
	bool *states;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	num = LvNum(hWnd, id);
	states = ZeroMalloc(sizeof(bool) * num);

	i = INFINITE;
	while (true)
	{
		i = LvGetNextMasked(hWnd, id, i);
		if (i == INFINITE)
		{
			break;
		}

		states[i] = true;
	}

	for (i = 0;i < num;i++)
	{
		if (states[i] == false)
		{
			ListView_SetItemState(DlgItem(hWnd, id), i, LVIS_SELECTED, LVIS_SELECTED);
		}
		else
		{
			ListView_SetItemState(DlgItem(hWnd, id), i, 0, LVIS_SELECTED);
		}
	}

	Free(states);
}

// Select all items
void LvSelectAll(HWND hWnd, UINT id)
{
	UINT i, num;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	num = LvNum(hWnd, id);
	for (i = 0;i < num;i++)
	{
		ListView_SetItemState(DlgItem(hWnd, id), i, LVIS_SELECTED, LVIS_SELECTED);
	}
}

// Select the item by specifying the parameter
void LvSelectByParam(HWND hWnd, UINT id, void *param)
{
	UINT index;
	// Validate arguments
	if (hWnd == NULL || param == NULL)
	{
		return;
	}

	index = LvSearchParam(hWnd, id, param);
	if (index == INFINITE)
	{
		return;
	}

	LvSelect(hWnd, id, index);
}

// Select an item
void LvSelect(HWND hWnd, UINT id, UINT index)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (index == INFINITE)
	{
		UINT i, num;
		// Deselect all
		num = LvNum(hWnd, id);
		for (i = 0;i < num;i++)
		{
			ListView_SetItemState(DlgItem(hWnd, id), i, 0, LVIS_SELECTED);
		}
	}
	else
	{
		// Select
		ListView_SetItemState(DlgItem(hWnd, id), index, LVIS_FOCUSED | LVIS_SELECTED, LVIS_FOCUSED | LVIS_SELECTED);
		ListView_EnsureVisible(DlgItem(hWnd, id), index, true);
	}
}

// Show the certificate information
void PrintCertInfo(HWND hWnd, CERT_DLG *p)
{
	X *x;
	char *serial_tmp;
	UINT serial_size;
	wchar_t *wchar_tmp;
	wchar_t tmp[1024 * 5];
	UCHAR md5[MD5_SIZE];
	UCHAR sha1[SHA1_SIZE];
	char *s_tmp;
	K *k;
	// Validate arguments
	if (p == NULL || hWnd == NULL)
	{
		return;
	}

	x = p->x;

	// Serial number
	if (x->serial != NULL)
	{
		serial_size = x->serial->size * 3 + 1;
		serial_tmp = ZeroMalloc(serial_size);
		BinToStrEx(serial_tmp, serial_size, x->serial->data, x->serial->size);
		wchar_tmp = CopyStrToUni(serial_tmp);
		Free(serial_tmp);
	}
	else
	{
		wchar_tmp = CopyUniStr(_UU("CERT_NO_SERIAL"));
	}
	LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_SERIAL"), wchar_tmp);

	// Issuer
	GetAllNameFromName(tmp, sizeof(tmp), x->issuer_name);
	LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_ISSUER"), tmp);

	// Subject
	GetAllNameFromName(tmp, sizeof(tmp), x->subject_name);
	LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_SUBJECT"), tmp);

	// Not available before
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(x->notBefore), NULL);
	LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_NOT_BEFORE"), tmp);

	// Not available after
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(x->notAfter), NULL);
	LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_NOT_AFTER"), tmp);

	// Number of bits
	if (x->is_compatible_bit)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CERT_BITS_FORMAT"), x->bits);
		LvInsert(hWnd, L_CERTINFO, ICO_CERT, NULL, 2, _UU("CERT_BITS"), tmp);
	}

	// Public key
	k = GetKFromX(x);
	if (k != NULL)
	{
		BUF *b = KToBuf(k, false, NULL);
		s_tmp = CopyBinToStrEx(b->Buf, b->Size);
		StrToUni(tmp, sizeof(tmp), s_tmp);
		Free(s_tmp);
		LvInsert(hWnd, L_CERTINFO, ICO_KEY, NULL, 2, _UU("CERT_PUBLIC_KEY"), tmp);
		FreeBuf(b);
	}
	FreeK(k);

	GetXDigest(x, md5, false);
	GetXDigest(x, sha1, true);

	// Digest (MD5)
	s_tmp = CopyBinToStrEx(md5, sizeof(md5));
	StrToUni(tmp, sizeof(tmp), s_tmp);
	Free(s_tmp);
	LvInsert(hWnd, L_CERTINFO, ICO_KEY, NULL, 2, _UU("CERT_DIGEST_MD5"), tmp);

	// Digest (SHA-1)
	s_tmp = CopyBinToStrEx(sha1, sizeof(sha1));
	StrToUni(tmp, sizeof(tmp), s_tmp);
	Free(s_tmp);
	LvInsert(hWnd, L_CERTINFO, ICO_KEY, NULL, 2, _UU("CERT_DIGEST_SHA1"), tmp);

	Free(wchar_tmp);

	LvSelect(hWnd, L_CERTINFO, 0);
}

// Update the display
void CertDlgUpdate(HWND hWnd, CERT_DLG *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	if (LvIsSelected(hWnd, L_CERTINFO) == false)
	{
		SetText(hWnd, E_DETAIL, L"");
	}
	else
	{
		UINT i = LvGetSelected(hWnd, L_CERTINFO);
		wchar_t *tmp = LvGetStr(hWnd, L_CERTINFO, i, 1);
		SetText(hWnd, E_DETAIL, tmp);
		Free(tmp);
	}
}

// Save the certificate
void CertDlgSave(HWND hWnd, CERT_DLG *p)
{
	wchar_t *name;
	X *x;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	// Save to a file
	name = SaveDlg(hWnd, _UU("DLG_CERT_FILES"), _UU("DLG_SAVE_CERT"), NULL, L".cer");
	x = p->x;
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
}

// Certificate display dialog procedure
UINT CertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	CERT_DLG *p = (CERT_DLG *)param;
	X *x;
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
		SetIcon(hWnd, 0, ICO_CERT);
		x = p->x;
		GetAllNameFromNameEx(tmp, sizeof(tmp), x->subject_name);
		SetText(hWnd, E_SUBJECT, tmp);
		GetAllNameFromNameEx(tmp, sizeof(tmp), x->issuer_name);
		SetText(hWnd, E_ISSUER, tmp);
		GetDateStrEx64(tmp, sizeof(tmp), SystemToLocal64(x->notAfter), NULL);
		SetText(hWnd, E_EXPIRES, tmp);
		SetFont(hWnd, E_SUBJECT, Font(0, 1));
		SetFont(hWnd, E_ISSUER, Font(0, 1));
		SetFont(hWnd, E_EXPIRES, Font(0, 1));
		SetIcon(hWnd, B_PARENT, ICO_CERT);
		if (x->root_cert)
		{
			// Root certificate
			Hide(hWnd, S_WARNING_ICON);
			SetText(hWnd, S_PARENT, _UU("CERT_ROOT"));
			Hide(hWnd, B_PARENT);
			Hide(hWnd, S_PARENT_BUTTON_STR);
		}
		else if (p->issuer_x != NULL)
		{
			// Parent certificate exists
			Hide(hWnd, S_WARNING_ICON);
		}
		else
		{
			// There is no parent certificate
			Hide(hWnd, S_CERT_ICON);
			Hide(hWnd, B_PARENT);
			Hide(hWnd, S_PARENT_BUTTON_STR);
			SetText(hWnd, S_PARENT, _UU("CERT_NOT_FOUND"));
			if (p->ManagerMode)
			{
				Hide(hWnd, IDC_STATIC1);
				Hide(hWnd, S_PARENT);
				Hide(hWnd, S_WARNING_ICON);
				Hide(hWnd, S_CERT_ICON);
				Hide(hWnd, B_PARENT);
				Hide(hWnd, S_PARENT_BUTTON_STR);
			}
		}


		LvInit(hWnd, L_CERTINFO);
		LvInsertColumn(hWnd, L_CERTINFO, 0, _UU("CERT_LV_C1"), 130);
		LvInsertColumn(hWnd, L_CERTINFO, 1, _UU("CERT_LV_C2"), 250);

		PrintCertInfo(hWnd, p);
		Focus(hWnd, L_CERTINFO);

		CertDlgUpdate(hWnd, p);

		if (p->ManagerMode)
		{
			Show(hWnd, B_SAVE);
		}
		else
		{
			// Hide for security
			Hide(hWnd, B_SAVE);
		}

		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			Close(hWnd);
			break;
		case B_PARENT:
			CertDlg(hWnd, p->issuer_x, NULL, p->ManagerMode);
			break;
		case B_SAVE:
			// Save to the file
			CertDlgSave(hWnd, p);
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
		case L_CERTINFO:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				CertDlgUpdate(hWnd, p);
				break;
			}
			break;
		}
		break;
	}

	LvSortHander(hWnd, msg, wParam, lParam, L_CERTINFO);

	return 0;
}

// Certificate display dialog
void CertDlg(HWND hWnd, X *x, X *issuer_x, bool manager)
{
	CERT_DLG p;
	// Validate arguments
	if (x == NULL)
	{
		return;
	}

	Zero(&p, sizeof(p));
	p.x = x;
	if (CompareX(x, issuer_x) == false)
	{
		p.issuer_x = issuer_x;
	}
	p.ManagerMode = manager;
	Dialog(hWnd, D_CERT, CertDlgProc, &p);
}

// Status window dialog
UINT StatusPrinterWindowDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	STATUS_WINDOW_PARAM *p = (STATUS_WINDOW_PARAM *)param;
	PACK *pack;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		// Initialize
		SetIcon(hWnd, 0, ICO_SERVER_ONLINE);
		RemoveExStyle(hWnd, 0, WS_EX_APPWINDOW);
		p->hWnd = hWnd;
		NoticeThreadInit(p->Thread);
		FormatText(hWnd, 0, p->AccountName);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			// Cancel button
			Close(hWnd);
			break;
		}

		break;

	case WM_APP + 1:
		// Set a string
		SetText(hWnd, S_STATUS, (wchar_t *)lParam);
		break;

	case WM_APP + 2:
		// Close this window
		EndDialog(hWnd, false);
		break;

	case WM_CLOSE:
		// End the session
		pack = NewPack();
		SendPack(p->Sock, pack);
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// Status window control thread
void StatusPrinterWindowThread(THREAD *thread, void *param)
{
	STATUS_WINDOW_PARAM *p = (STATUS_WINDOW_PARAM *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	p->Thread = thread;
	DialogEx2(NULL, D_STATUS, StatusPrinterWindowDlg, p, true, true);

	Free(p);
}

// Show a message in the status window
void StatusPrinterWindowPrint(STATUS_WINDOW *sw, wchar_t *str)
{
	// Validate arguments
	if (sw == NULL)
	{
		return;
	}

	SendMessage(sw->hWnd, WM_APP + 1, 0, (LPARAM)str);
}

// End and release the status window
void StatusPrinterWindowStop(STATUS_WINDOW *sw)
{
	// Validate arguments
	if (sw == NULL)
	{
		return;
	}

	// Send stop message
	SendMessage(sw->hWnd, WM_APP + 2, 0, 0);

	// Wait until the thread terminates
	WaitThread(sw->Thread, INFINITE);

	// Release the memory
	ReleaseThread(sw->Thread);
	Free(sw);
}

// Initialize the status window
STATUS_WINDOW *StatusPrinterWindowStart(SOCK *s, wchar_t *account_name)
{
	STATUS_WINDOW_PARAM *p;
	STATUS_WINDOW *sw;
	THREAD *t;
	// Validate arguments
	if (s == NULL || account_name == NULL)
	{
		return NULL;
	}

	p = ZeroMalloc(sizeof(STATUS_WINDOW_PARAM));
	p->Sock = s;
	UniStrCpy(p->AccountName, sizeof(p->AccountName), account_name);

	// Create a thread
	t = NewThread(StatusPrinterWindowThread, p);
	WaitThreadInit(t);

	sw = ZeroMalloc(sizeof(STATUS_WINDOW));
	sw->hWnd = p->hWnd;
	sw->Thread = t;

	return sw;
}

// Remove all
void LbReset(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, LB_RESETCONTENT, 0, 0);
}

// Password input dialog state change
void PasswordDlgProcChange(HWND hWnd, UI_PASSWORD_DLG *p)
{
	bool b;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	b = true;
	if (IsEmpty(hWnd, E_USERNAME))
	{
		b = false;
	}

	SetEnable(hWnd, IDOK, b);

	p->StartTick = Tick64();
	if (p->RetryIntervalSec)
	{
		KillTimer(hWnd, 1);
		Hide(hWnd, P_PROGRESS);
		Hide(hWnd, S_COUNTDOWN);
	}
}

// Get the string
wchar_t *CbGetStr(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	return GetText(hWnd, id);
}

// String search
UINT CbFindStr(HWND hWnd, UINT id, wchar_t *str)
{
	UINT ret;
	if (MsIsNt() == false)
	{
		char *tmp = CopyUniToStr(str);
		ret = CbFindStr9xA(hWnd, id, tmp);
		Free(tmp);
		return ret;
	}
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, CB_FINDSTRINGEXACT, -1, (LPARAM)str);

	return ret;
}
UINT CbFindStr9xA(HWND hWnd, UINT id, char *str)
{
	UINT ret;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, CB_FINDSTRINGEXACT, -1, (LPARAM)str);

	return ret;
}

// Get the number of items
UINT CbNum(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return SendMsg(hWnd, id, CB_GETCOUNT, 0, 0);
}

// Add a string
UINT CbAddStrA(HWND hWnd, UINT id, char *str, UINT data)
{
	wchar_t *tmp;
	UINT ret;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}
	tmp = CopyStrToUni(str);
	ret = CbAddStr(hWnd, id, tmp, data);
	Free(tmp);
	return ret;
}
UINT CbAddStr(HWND hWnd, UINT id, wchar_t *str, UINT data)
{
	UINT ret;
	if (MsIsNt() == false)
	{
		char *s = CopyUniToStr(str);
		ret = CbAddStr9xA(hWnd, id, s, data);
		Free(s);
		return ret;
	}
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, CB_ADDSTRING, 0, (LPARAM)str);
	SendMsg(hWnd, id, CB_SETITEMDATA, ret, (LPARAM)data);

	if (CbNum(hWnd, id) == 1)
	{
		wchar_t tmp[MAX_SIZE];
		GetTxt(hWnd, id, tmp, sizeof(tmp));
		if (UniStrLen(tmp) == 0)
		{
			CbSelectIndex(hWnd, id, 0);
		}
	}

	return ret;
}
UINT CbAddStr9xA(HWND hWnd, UINT id, char *str, UINT data)
{
	UINT ret;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return INFINITE;
	}

	ret = SendMsg(hWnd, id, CB_ADDSTRING, 0, (LPARAM)str);
	SendMsg(hWnd, id, CB_SETITEMDATA, ret, (LPARAM)data);

	if (CbNum(hWnd, id) == 1)
	{
		wchar_t tmp[MAX_SIZE];
		GetTxt(hWnd, id, tmp, sizeof(tmp));
		if (UniStrLen(tmp) == 0)
		{
			CbSelectIndex(hWnd, id, 0);
		}
	}

	return ret;
}

// Remove all
void CbReset(HWND hWnd, UINT id)
{
	wchar_t *s;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	s = GetText(hWnd, id);

	SendMsg(hWnd, id, CB_RESETCONTENT, 0, 0);

	if (s != NULL)
	{
		SetText(hWnd, id, s);
		Free(s);
	}
}

// Select by specifying the index
void CbSelectIndex(HWND hWnd, UINT id, UINT index)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, CB_SETCURSEL, index, 0);
}

// Get the data
UINT CbGetData(HWND hWnd, UINT id, UINT index)
{
	// Validate arguments
	if (hWnd == NULL || index == INFINITE)
	{
		return INFINITE;
	}

	return SendMsg(hWnd, id, CB_GETITEMDATA, index, 0);
}

// Search for the data
UINT CbFindData(HWND hWnd, UINT id, UINT data)
{
	UINT i, num;
	// Validate arguments
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	num = CbNum(hWnd, id);
	if (num == INFINITE)
	{
		return INFINITE;
	}

	for (i = 0;i < num;i++)
	{
		if (CbGetData(hWnd, id, i) == data)
		{
			return i;
		}
	}

	return INFINITE;
}

// Set the height of the item
void CbSetHeight(HWND hWnd, UINT id, UINT value)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, CB_SETITEMHEIGHT, 0, (UINT)(GetTextScalingFactor() * (double)value));
}

// Search by specifying the data
void CbSelect(HWND hWnd, UINT id, int data)
{
	UINT index;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (data == INFINITE)
	{
		// Get the first item
		CbSelectIndex(hWnd, id, 0);
		return;
	}

	index = CbFindData(hWnd, id, data);
	if (index == INFINITE)
	{
		// Can not be found
		return;
	}

	// Select
	CbSelectIndex(hWnd, id, index);
}

// Get the currently selected item
UINT CbGetSelectIndex(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	return SendMsg(hWnd, id, CB_GETCURSEL, 0, 0);
}

// Get the value that is currently selected
UINT CbGetSelect(HWND hWnd, UINT id)
{
	UINT index;
	// Validate arguments
	if (hWnd == NULL)
	{
		return INFINITE;
	}

	index = CbGetSelectIndex(hWnd, id);
	if (index == INFINITE)
	{
		return INFINITE;
	}

	return CbGetData(hWnd, id, index);
}

// OK button is pressed
void PasswordDlgOnOk(HWND hWnd, UI_PASSWORD_DLG *p)
{
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	GetTxtA(hWnd, E_USERNAME, p->Username, sizeof(p->Username));
	GetTxtA(hWnd, E_PASSWORD, p->Password, sizeof(p->Password));
	p->Type = CbGetSelect(hWnd, C_TYPE);

	if (p->ShowNoSavePassword)
	{
		p->NoSavePassword = IsChecked(hWnd, R_NO_SAVE_PASSWORD);
	}

	EndDialog(hWnd, true);
}

// Password input dialog procedure
UINT PasswordDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	UI_PASSWORD_DLG *p = (UI_PASSWORD_DLG *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, 0, ICO_KEY);
		CbSetHeight(hWnd, C_TYPE, 18);
		if (p->ServerName != NULL)
		{
			FormatText(hWnd, 0, p->ServerName);
		}
		else
		{
			SetText(hWnd, 0, _UU("PW_LOGIN_DLG_TITLE"));
		}

		if (p->ProxyServer == false)
		{
			FormatText(hWnd, S_TITLE, p->ServerName == NULL ? "" : p->ServerName);
		}
		else
		{
			wchar_t tmp[MAX_SIZE];
			UniFormat(tmp, sizeof(tmp), _UU("PW_MSG_PROXY"), p->ServerName == NULL ? "" : p->ServerName);
			SetText(hWnd, S_TITLE, tmp);
		}

		// Enumerate the connection methods
		SendMsg(hWnd, C_TYPE, CBEM_SETUNICODEFORMAT, true, 0);

		if (StrCmpi(p->Username, WINUI_PASSWORD_NULL_USERNAME) != 0)
		{
			SetTextA(hWnd, E_USERNAME, p->Username);
			SetTextA(hWnd, E_PASSWORD, p->Password);
		}
		else
		{
			p->RetryIntervalSec = 0;
			SetTextA(hWnd, E_USERNAME, "");
			SetTextA(hWnd, E_PASSWORD, "");
		}

		if (p->AdminMode == false)
		{
			if (p->ProxyServer == false)
			{
				CbAddStr(hWnd, C_TYPE, _UU("PW_TYPE_1"), CLIENT_AUTHTYPE_PASSWORD);
				CbAddStr(hWnd, C_TYPE, _UU("PW_TYPE_2"), CLIENT_AUTHTYPE_PLAIN_PASSWORD);
			}
			else
			{
				CbAddStr(hWnd, C_TYPE, _UU("PW_TYPE_PROXY"), 0);
				Disable(hWnd, C_TYPE);
			}

			CbSelect(hWnd, C_TYPE, p->Type);
		}
		else
		{
			CbAddStr(hWnd, C_TYPE, _UU("SM_PASSWORD_TYPE_STR"), 0);
			Disable(hWnd, C_TYPE);
			SetTextA(hWnd, E_USERNAME, "Administrator");
			Disable(hWnd, E_USERNAME);
		}

		if (IsEmpty(hWnd, E_USERNAME))
		{
			FocusEx(hWnd, E_USERNAME);
		}
		else
		{
			FocusEx(hWnd, E_PASSWORD);
		}
		LimitText(hWnd, E_USERNAME, MAX_USERNAME_LEN);
		LimitText(hWnd, E_PASSWORD, MAX_PASSWORD_LEN);

		PasswordDlgProcChange(hWnd, p);

		if (p->RetryIntervalSec != 0)
		{
			SetTimer(hWnd, 1, 50, NULL);
			FormatText(hWnd, S_COUNTDOWN, p->RetryIntervalSec);
			Show(hWnd, S_COUNTDOWN);
			Show(hWnd, P_PROGRESS);
			SetRange(hWnd, P_PROGRESS, 0, p->RetryIntervalSec * 1000);
		}
		else
		{
			Hide(hWnd, S_COUNTDOWN);
			Hide(hWnd, P_PROGRESS);
		}

		if (p->ShowNoSavePassword)
		{
			Show(hWnd, R_NO_SAVE_PASSWORD);
			Check(hWnd, R_NO_SAVE_PASSWORD, p->NoSavePassword);
		}
		else
		{
			Hide(hWnd, R_NO_SAVE_PASSWORD);
		}

		p->StartTick = Tick64();

		if (p->CancelEvent != NULL)
		{
			SetTimer(hWnd, 2, 50, NULL);
		}

		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			if (p->RetryIntervalSec != 0)
			{
				wchar_t tmp[MAX_SIZE];
				UINT64 end, now, start;
				start = p->StartTick;
				end = p->StartTick + (UINT64)(p->RetryIntervalSec * 1000);
				now = Tick64();

				if (now <= end)
				{
					UniFormat(tmp, sizeof(tmp), _UU("PW_RETRYCOUNT"), (UINT)((end - now) / 1000));
					SetText(hWnd, S_COUNTDOWN, tmp);
					SetPos(hWnd, P_PROGRESS, (UINT)(now - start));
				}
				else
				{
					EndDialog(hWnd, true);
				}
			}
			break;

		case 2:
			if (p->CancelEvent != NULL)
			{
				// Wait for the end event
				HANDLE hEvent = (HANDLE)p->CancelEvent->pData;
				UINT ret = WaitForSingleObject(hEvent, 0);
				if (ret != WAIT_TIMEOUT)
				{
					// Forced termination event is set
					Close(hWnd);
				}
			}
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			PasswordDlgOnOk(hWnd, p);
			break;
		case IDCANCEL:
			Close(hWnd);
			break;
		}
		switch (HIWORD(wParam))
		{
		case EN_CHANGE:
			switch (LOWORD(wParam))
			{
			case E_USERNAME:
			case E_PASSWORD:
				PasswordDlgProcChange(hWnd, p);
				break;
			}
			break;
		case CBN_SELCHANGE:
			switch (LOWORD(wParam))
			{
			case C_TYPE:
				PasswordDlgProcChange(hWnd, p);
				if (IsEmpty(hWnd, E_USERNAME))
				{
					FocusEx(hWnd, E_USERNAME);
				}
				else
				{
					FocusEx(hWnd, E_PASSWORD);
				}
				break;
			}
			break;
		}
		break;
	}

	return 0;
}

// Set the position of the progress bar
void SetPos(HWND hWnd, UINT id, UINT pos)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, PBM_SETPOS, pos, 0);
}

// Set the range of the progress bar
void SetRange(HWND hWnd, UINT id, UINT start, UINT end)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, PBM_SETRANGE32, start, end);
}

// Password input dialog
bool PasswordDlg(HWND hWnd, UI_PASSWORD_DLG *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return false;
	}

	p->StartTick = Tick64();

	return Dialog(hWnd, D_PASSWORD, PasswordDlgProc, p);
}

// Passphrase input dialog
bool PassphraseDlg(HWND hWnd, char *pass, UINT pass_size, BUF *buf, bool p12)
{
	PASSPHRASE_DLG p;
	// Validate arguments
	if (pass == NULL || buf == NULL)
	{
		return false;
	}

	Zero(&p, sizeof(PASSPHRASE_DLG));

	p.buf = buf;
	p.p12 = p12;

	// Examine whether it is encrypted first
	if (p12 == false)
	{
		// Secret key
		if (IsEncryptedK(buf, true) == false)
		{
			// Unencrypted
			StrCpy(pass, pass_size, "");
			return true;
		}
	}
	else
	{
		// PKCS#12
		P12 *p12 = BufToP12(buf);
		if (p12 == NULL)
		{
			// It is in unknown format, but not encrypted
			StrCpy(pass, pass_size, "");
			return true;
		}

		if (IsEncryptedP12(p12) == false)
		{
			// Unencrypted
			StrCpy(pass, pass_size, "");
			FreeP12(p12);
			return true;
		}
		FreeP12(p12);
	}

	// Show the dialog
	if (Dialog(hWnd, D_PASSPHRASE, PassphraseDlgProc, &p) == false)
	{
		// Cancel
		return false;
	}

	StrCpy(pass, pass_size, p.pass);

	return true;
}

// WM_COMMAND handler
void PassphraseDlgProcCommand(HWND hWnd, PASSPHRASE_DLG *p)
{
	char *pass;
	bool ok;
	// Validate arguments
	if (hWnd == NULL || p == NULL)
	{
		return;
	}

	pass = GetTextA(hWnd, E_PASSPHRASE);
	if (pass == NULL)
	{
		return;
	}

	ok = false;

	if (p->p12 == false)
	{
		K *k;
		k = BufToK(p->buf, true, true, pass);
		if (k != NULL)
		{
			ok = true;
			FreeK(k);
		}
	}
	else
	{
		X *x;
		K *k;
		P12 *p12;
		p12 = BufToP12(p->buf);
		if (p12 != NULL)
		{
			if (ParseP12(p12, &x, &k, pass))
			{
				FreeX(x);
				FreeK(k);
				ok = true;
			}
			FreeP12(p12);
		}
	}

	Free(pass);

	SetEnable(hWnd, IDOK, ok);
}

// Passphrase input dialog procedure
UINT PassphraseDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	PASSPHRASE_DLG *p = (PASSPHRASE_DLG *)param;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		PassphraseDlgProcCommand(hWnd, p);
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			GetTxtA(hWnd, E_PASSPHRASE, p->pass, sizeof(p->pass));
			EndDialog(hWnd, true);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}

		switch (LOWORD(wParam))
		{
		case E_PASSPHRASE:
			PassphraseDlgProcCommand(hWnd, p);
			break;
		}
		break;

	case WM_CLOSE:
		EndDialog(hWnd, false);
		break;
	}

	return 0;
}

// [Save File] dialog
wchar_t *SaveDlg(HWND hWnd, wchar_t *filter, wchar_t *title, wchar_t *default_name, wchar_t *default_ext)
{
	wchar_t *filter_str;
	wchar_t tmp[MAX_SIZE];
	OPENFILENAMEW o;

	if (MsIsNt() == false)
	{
		char *ret, *s1, *s2, *s3, *s4;
		wchar_t *wr;
		s1 = CopyUniToStr(filter);
		s2 = CopyUniToStr(title);
		s3 = CopyUniToStr(default_name);
		s4 = CopyUniToStr(default_ext);
		ret = SaveDlgA(hWnd, s1, s2, s3, s4);
		Free(s1);
		Free(s2);
		Free(s3);
		Free(s4);
		wr = CopyStrToUni(ret);
		Free(ret);
		return wr;
	}

	// Validate arguments
	if (filter == NULL)
	{
		filter = _UU("DLG_ALL_FILES");
	}

	filter_str = MakeFilter(filter);

	Zero(&o, sizeof(o));
	Zero(tmp, sizeof(tmp));

	if (default_name != NULL)
	{
		UniStrCpy(tmp, sizeof(tmp), default_name);
	}

	o.lStructSize = sizeof(o);
	
	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType) || (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) && GET_KETA(GetOsInfo()->OsType, 100) <= 1))
	{
		o.lStructSize = OPENFILENAME_SIZE_VERSION_400W;
	}

	o.hwndOwner = hWnd;
	o.hInstance = GetModuleHandle(NULL);
	o.lpstrFile = tmp;
	o.lpstrTitle = title;
	o.lpstrFilter = filter_str;
	o.nMaxFile = sizeof(tmp);
	o.Flags = OFN_OVERWRITEPROMPT;
	o.lpstrDefExt = default_ext;

	if (GetSaveFileNameW(&o) == false)
	{
		Free(filter_str);
		return NULL;
	}

	Free(filter_str);

	return UniCopyStr(tmp);
}
char *SaveDlgA(HWND hWnd, char *filter, char *title, char *default_name, char *default_ext)
{
	char *filter_str;
	char tmp[MAX_SIZE];
	OPENFILENAME o;
	// Validate arguments
	if (filter == NULL)
	{
		filter = _SS("DLG_ALL_FILES");
	}

	filter_str = MakeFilterA(filter);

	Zero(&o, sizeof(o));
	Zero(tmp, sizeof(tmp));

	if (default_name != NULL)
	{
		StrCpy(tmp, sizeof(tmp), default_name);
	}

	o.lStructSize = sizeof(o);
	
	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType) || (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) && GET_KETA(GetOsInfo()->OsType, 100) <= 1))
	{
		o.lStructSize = OPENFILENAME_SIZE_VERSION_400A;
	}

	o.hwndOwner = hWnd;
	o.hInstance = GetModuleHandle(NULL);
	o.lpstrFile = tmp;
	o.lpstrTitle = title;
	o.lpstrFilter = filter_str;
	o.nMaxFile = sizeof(tmp);
	o.Flags = OFN_OVERWRITEPROMPT;
	o.lpstrDefExt = default_ext;

	if (GetSaveFileName(&o) == false)
	{
		Free(filter_str);
		return NULL;
	}

	Free(filter_str);

	return CopyStr(tmp);
}

// [Open File] dialog
wchar_t *OpenDlg(HWND hWnd, wchar_t *filter, wchar_t *title)
{
	wchar_t *filter_str;
	wchar_t tmp[MAX_SIZE];
	OPENFILENAMEW o;

	if (MsIsNt() == false)
	{
		char *ret;
		char *filter_a;
		char *title_a;
		wchar_t *w;
		filter_a = CopyUniToStr(filter);
		title_a = CopyUniToStr(title);
		ret = OpenDlgA(hWnd, filter_a, title_a);
		Free(filter_a);
		Free(title_a);
		w = CopyStrToUni(ret);
		Free(ret);
		return w;
	}

	// Validate arguments
	if (filter == NULL)
	{
		filter = _UU("DLG_ALL_FILES");
	}

	filter_str = MakeFilter(filter);

	Zero(&o, sizeof(OPENFILENAMEW));
	Zero(tmp, sizeof(tmp));

	o.lStructSize = sizeof(o);


	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType) || (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) && GET_KETA(GetOsInfo()->OsType, 100) <= 1))
	{
		o.lStructSize = OPENFILENAME_SIZE_VERSION_400W;
	}


	o.hwndOwner = hWnd;
	o.hInstance = GetModuleHandle(NULL);
	o.lpstrFilter = filter_str;
	o.lpstrFile = tmp;
	o.nMaxFile = sizeof(tmp);
	o.lpstrTitle = title;
	o.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

	if (GetOpenFileNameW(&o) == false)
	{
		Free(filter_str);
		return NULL;
	}

	Free(filter_str);

	return UniCopyStr(tmp);
}
char *OpenDlgA(HWND hWnd, char *filter, char *title)
{
	char *filter_str;
	char tmp[MAX_SIZE];
	OPENFILENAME o;
	// Validate arguments
	if (filter == NULL)
	{
		filter = _SS("DLG_ALL_FILES");
	}

	filter_str = MakeFilterA(filter);

	Zero(&o, sizeof(OPENFILENAME));
	Zero(tmp, sizeof(tmp));

	o.lStructSize = sizeof(o);

	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType) || (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) && GET_KETA(GetOsInfo()->OsType, 100) <= 1))
	{
		o.lStructSize = OPENFILENAME_SIZE_VERSION_400A;
	}

	o.hwndOwner = hWnd;
	o.hInstance = GetModuleHandle(NULL);
	o.lpstrFilter = filter_str;
	o.lpstrFile = tmp;
	o.nMaxFile = sizeof(tmp);
	o.lpstrTitle = title;
	o.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

	if (GetOpenFileName(&o) == false)
	{
		Free(filter_str);
		return NULL;
	}

	Free(filter_str);

	return CopyStr(tmp);
}

// Generate the filter string
wchar_t *MakeFilter(wchar_t *str)
{
	UINT i;
	wchar_t *ret;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(UniStrSize(str) + 32);

	for (i = 0;i < UniStrLen(str);i++)
	{
		if (str[i] == L'|')
		{
			ret[i] = L'\0';
		}
		else
		{
			ret[i] = str[i];
		}
	}

	return ret;
}
char *MakeFilterA(char *str)
{
	UINT i;
	char *ret;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(StrSize(str) + 32);

	for (i = 0;i < StrLen(str);i++)
	{
		if (str[i] == '|')
		{
			ret[i] = '\0';
		}
		else
		{
			ret[i] = str[i];
		}
	}

	return ret;
}

// Execution of batch
bool ExecuteSecureDeviceBatch(HWND hWnd, SECURE *sec, SECURE_DEVICE_THREAD *p, SECURE_DEVICE *dev, WINUI_SECURE_BATCH *batch)
{
	LIST *o;
	void *buf;
	UINT size = 10 * 1024;		// Maximum size of the data
	UINT type = INFINITE;
	// Validate arguments
	if (hWnd == NULL || p == NULL || dev == NULL || batch == NULL || sec == NULL)
	{
		return false;
	}

	switch (batch->Type)
	{
	case WINUI_SECURE_DELETE_CERT:
		type = SEC_X;
		goto DELETE_OBJECT;

	case WINUI_SECURE_DELETE_KEY:
		type = SEC_K;
		goto DELETE_OBJECT;

	case WINUI_SECURE_DELETE_DATA:
		type = SEC_DATA;
		goto DELETE_OBJECT;

	case WINUI_SECURE_DELETE_OBJECT:
		// Delete the object
DELETE_OBJECT:
		SetText(hWnd, S_STATUS, _UU("SEC_DELETE"));
		if (DeleteSecObjectByName(sec, batch->Name, type) == false)
		{
			p->ErrorMessage = UniCopyStr(_UU("SEC_ERROR_DELETE"));
			return false;
		}
		break;

	case WINUI_SECURE_ENUM_OBJECTS:
		// Enumerate objects
		SetText(hWnd, S_STATUS, _UU("SEC_ENUM"));
		o = EnumSecObject(sec);
		if (o == NULL)
		{
			p->ErrorMessage = UniCopyStr(_UU("SEC_ERROR_ENUM"));
			return false;
		}

		batch->EnumList = o;
		break;

	case WINUI_SECURE_WRITE_DATA:
		// Write the data
		SetText(hWnd, S_STATUS, _UU("SEC_WRITE_DATA"));
		if (WriteSecData(sec, batch->Private, batch->Name, batch->InputData->Buf, batch->InputData->Size) == false)
		{
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_WRITE_1") : _UU("SEC_ERROR_WRITE_2"));
			return false;
		}
		break;

	case WINUI_SECURE_READ_DATA:
		// Read the data
		SetText(hWnd, S_STATUS, _UU("SEC_READ_DATA"));
		buf = MallocEx(size, true);
		size = ReadSecData(sec, batch->Name, buf, size);
		if (size == 0)
		{
			Free(buf);
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_NOT_FOUND_1") : _UU("SEC_ERROR_NOT_FOUND_2"));
			return false;
		}
		batch->OutputData = NewBuf();
		WriteBuf(batch->OutputData, buf, size);
		SeekBuf(batch->OutputData, 0, 0);
		Free(buf);
		break;

	case WINUI_SECURE_WRITE_CERT:
		// Write the certificate
		SetText(hWnd, S_STATUS, _UU("SEC_WRITE_CERT"));
		if (WriteSecCert(sec, batch->Private, batch->Name, batch->InputX) == false)
		{
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_WRITE_1") : _UU("SEC_ERROR_WRITE_2"));
			return false;
		}
		break;

	case WINUI_SECURE_READ_CERT:
		// Read the certificate
		SetText(hWnd, S_STATUS, _UU("SEC_READ_CERT"));
		batch->OutputX = ReadSecCert(sec, batch->Name);
		if (batch->OutputX == NULL)
		{
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_NOT_FOUND_1") : _UU("SEC_ERROR_NOT_FOUND_2"));
			return false;
		}
		break;

	case WINUI_SECURE_WRITE_KEY:
		// Write the secret key
		SetText(hWnd, S_STATUS, _UU("SEC_WRITE_KEY"));
		if (WriteSecKey(sec, batch->Private, batch->Name, batch->InputK) == false)
		{
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_WRITE_1") : _UU("SEC_ERROR_WRITE_2"));
			return false;
		}
		break;

	case WINUI_SECURE_SIGN_WITH_KEY:
		// Signature
		SetText(hWnd, S_STATUS, _UU("SEC_SIGN"));
		if (SignSec(sec, batch->Name, batch->OutputSign, batch->InputData->Buf, batch->InputData->Size) == false)
		{
			p->ErrorMessage = UniCopyStr(dev->Type != SECURE_USB_TOKEN ?
				_UU("SEC_ERROR_SIGN_1") : _UU("SEC_ERROR_SIGN_2"));
			return false;
		}
		break;
	}

	return true;
}

// Run the secure device operations as a batch job
void SecureDeviceBatch(HWND hWnd, SECURE *sec, SECURE_DEVICE_THREAD *p, SECURE_DEVICE *dev)
{
	UINT i;
	// Validate arguments
	if (hWnd == NULL || p == NULL || dev == NULL || sec == NULL)
	{
		return;
	}

	// Sequential processing
	for (i = 0;i < p->w->num_batch;i++)
	{
		WINUI_SECURE_BATCH *batch = &p->w->batch[i];

		if (ExecuteSecureDeviceBatch(hWnd, sec, p, dev, batch) == false)
		{
			// If fail even one, abort immediately
			return;
		}
	}

	// All batch job succeeded
	p->Succeed = true;
}

// Thread to perform a secure device operation
void SecureDeviceThread(THREAD *t, void *param)
{
	SECURE *sec;
	SECURE_DEVICE_THREAD *p = (SECURE_DEVICE_THREAD *)param;
	SECURE_DEVICE *dev;
	HWND hWnd;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	p->Succeed = false;
	p->ErrorMessage = NULL;

	hWnd = p->hWnd;

	// Open the device
	dev = GetSecureDevice(p->w->device_id);
	SetText(hWnd, S_STATUS, _UU("SEC_OPENING"));
	sec = OpenSec(p->w->device_id);
	if (sec == NULL)
	{
		// Device open failure
		if (p->w->device_id != 9)
		{
			p->ErrorMessage = CopyUniFormat(_UU("SEC_ERROR_OPEN_DEVICE"), dev->DeviceName);
		}
		else
		{
			p->ErrorMessage = CopyUniFormat(_UU("SEC_ERROR_OPEN_DEVICEEX"), dev->DeviceName);
		}
	}
	else
	{
		// Open the session
		SetText(hWnd, S_STATUS, _UU("SEC_OPEN_SESSION"));
		if (OpenSecSession(sec, 0) == false)
		{
			// Session initialization failure
			p->ErrorMessage = CopyUniFormat(_UU("SEC_ERROR_OPEN_SESSION"), dev->DeviceName);
		}
		else
		{
			// Login
			SetText(hWnd, S_STATUS, _UU("SEC_LOGIN"));
			if (LoginSec(sec, p->pin) == false)
			{
				// Login failure
				p->ErrorMessage =UniCopyStr(_UU("SEC_ERROR_LOGIN"));
			}
			else
			{
				// Batch processing main
				SetText(hWnd, S_STATUS, _UU("SEC_INIT_BATCH"));
				SecureDeviceBatch(hWnd, sec, p, dev);

				// Logout
				SetText(hWnd, S_STATUS, _UU("SEC_LOGOUT"));
				LogoutSec(sec);
			}

			// Close the session
			SetText(hWnd, S_STATUS, _UU("SEC_CLOSE_SESSION"));
			CloseSecSession(sec);
		}

		// Close the device
		SetText(hWnd, S_STATUS, _UU("SEC_CLOSING"));
		CloseSec(sec);
	}

	if (p->Succeed)
	{
		// If successful, show the message for 150ms (service)
		SetText(hWnd, S_STATUS, _UU("SEC_FINISHED"));
		SleepThread(150);
	}

	SendMessage(p->hWnd, WM_APP + 1, 0, 0);
}

// Start a secure device operation
void StartSecureDevice(HWND hWnd, SECURE_DEVICE_WINDOW *w)
{
	SECURE_DEVICE_THREAD *p;
	// Validate arguments
	if (hWnd == NULL || w == NULL)
	{
		return;
	}

	// Disable the control
	EnableSecureDeviceWindowControls(hWnd, false);

	// Start the thread
	p = ZeroMalloc(sizeof(SECURE_DEVICE_THREAD));
	p->w = w;
	p->hWnd = hWnd;
	w->p = p;
	p->pin = GetTextA(hWnd, E_PIN);
	ReleaseThread(NewThread(SecureDeviceThread, p));
}

// Enable or disable the control of the secure device operation window
void EnableSecureDeviceWindowControls(HWND hWnd, bool enable)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (enable)
	{
		Show(hWnd, S_PIN_CODE);
		Show(hWnd, E_PIN);
		Show(hWnd, S_WARNING);
	}
	else
	{
		Hide(hWnd, S_PIN_CODE);
		Hide(hWnd, E_PIN);
		Hide(hWnd, S_WARNING);
	}

	SetEnable(hWnd, IDOK, enable);
	SetEnable(hWnd, IDCANCEL, enable);
	SetEnable(hWnd, S_TITLE, enable);
	SetEnable(hWnd, S_DEVICE_INFO, enable);
	SetEnable(hWnd, S_INSERT_SECURE, enable);

	if (enable == false)
	{
		DisableClose(hWnd);
		SetText(hWnd, S_STATUS, L"");
		Show(hWnd, S_STATUS);
		PlayAvi(hWnd, A_PROGRESS, true);
	}
	else
	{
		EnableClose(hWnd);
		SetText(hWnd, S_STATUS, L"");
		Hide(hWnd, S_STATUS);
		StopAvi(hWnd, A_PROGRESS);
	}
}

// Secure device operation window procedure
UINT SecureDeviceWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param)
{
	SECURE_DEVICE_WINDOW *w = (SECURE_DEVICE_WINDOW *)param;
	SECURE_DEVICE *dev = GetSecureDevice(w->device_id);

	switch (msg)
	{
	case WM_INITDIALOG:
		if (dev == NULL)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SEC_ERROR_INVALID_ID"), w->device_id);
			EndDialog(hWnd, 0);
			break;
		}

		if (IsJPKI(dev->Id))
		{
			// Juki card
			Hide(hWnd, S_IMAGE);
			Show(hWnd, S_IMAGE2);
			Hide(hWnd, S_IMAGE_TSUKUBA);
		}
		else
		{
			// Regular card
			Hide(hWnd, S_IMAGE2);

			if (w->BitmapId != 0)
			{
				// For University of Tsukuba
				Hide(hWnd, S_IMAGE);
				Show(hWnd, S_IMAGE_TSUKUBA);
			}
			else
			{
				// For general use
				Show(hWnd, S_IMAGE);
				Hide(hWnd, S_IMAGE_TSUKUBA);
			}
		}

		FormatText(hWnd, 0, dev->Type != SECURE_USB_TOKEN ? _UU("SEC_SMART_CARD") : _UU("SEC_USB_TOKEN"),
			dev->DeviceName);
		FormatText(hWnd, S_TITLE, dev->DeviceName);
		FormatText(hWnd, S_INSERT_SECURE,
			dev->Type != SECURE_USB_TOKEN ? _UU("SEC_INIT_MSG_1") : _UU("SEC_INIT_MSG_2"));
		FormatText(hWnd, S_DEVICE_INFO,
			dev->DeviceName, dev->Manufacturer, dev->ModuleName);

		DlgFont(hWnd, S_SOFTWARE_TITLE, 11, 0);
		SetText(hWnd, S_SOFTWARE_TITLE, title_bar);

		DlgFont(hWnd, S_TITLE, 14, true);
		DlgFont(hWnd, S_DEVICE_INFO, 11, false);
		DlgFont(hWnd, S_STATUS, 13, true);
		EnableSecureDeviceWindowControls(hWnd, true);
		OpenAvi(hWnd, A_PROGRESS, AVI_PROGRESS);

		SetIcon(hWnd, 0, ICO_KEY);

		// Initial PIN
		if ((w->default_pin != NULL && StrLen(w->default_pin) != 0) || (cached_pin_code_expires >= Tick64()))
		{
			if (w->default_pin != NULL && StrLen(w->default_pin) != 0)
			{
				SetTextA(hWnd, E_PIN, w->default_pin);
			}
			else
			{
				SetTextA(hWnd, E_PIN, cached_pin_code);
			}
			SetTimer(hWnd, 1, 1, NULL);
		}

		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);
			Command(hWnd, IDOK);
			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			StartSecureDevice(hWnd, w);
			break;

		case IDCANCEL:
			Close(hWnd);
			break;
		}
		break;

	case WM_CLOSE:
		if (IsEnable(hWnd, IDCANCEL))
		{
			CloseAvi(hWnd, A_PROGRESS);
			EndDialog(hWnd, false);
		}
		break;

	case WM_APP + 1:
		// There is a response from the thread
		if (w->p != NULL)
		{
			if (w->p->Succeed)
			{
				// Success
				if (w->default_pin != NULL)
				{
					StrCpy(w->default_pin, 128, w->p->pin);
				}
				StrCpy(cached_pin_code, sizeof(cached_pin_code), w->p->pin);
				cached_pin_code_expires = Tick64() + (UINT64)WINUI_SECUREDEVICE_PIN_CACHE_TIME;
				Free(w->p->pin);
				Free(w->p);
				EndDialog(hWnd, true);
			}
			else
			{
				// Failure
				cached_pin_code_expires = 0;
				EnableSecureDeviceWindowControls(hWnd, true);
				FocusEx(hWnd, E_PIN);
				MsgBox(hWnd, MB_ICONEXCLAMATION, w->p->ErrorMessage);
				Free(w->p->pin);
				Free(w->p->ErrorMessage);
				Free(w->p);
			}
		}
		break;
	}

	return 0;
}

// Send a WM_COMMAND
void Command(HWND hWnd, UINT id)
{
	SendMessage(hWnd, WM_COMMAND, id, 0);
}

// Show the secure device window
bool SecureDeviceWindow(HWND hWnd, WINUI_SECURE_BATCH *batch, UINT num_batch, UINT device_id, UINT bitmap_id)
{
	SECURE_DEVICE_WINDOW w;
	UINT i;
	// Validate arguments
	if (batch == NULL || num_batch == 0 || device_id == 0)
	{
		return false;
	}

	// Initialize the success flag
	for (i = 0;i < num_batch;i++)
	{
		batch[i].Succeed = false;
	}

	Zero(&w, sizeof(w));
	w.batch = batch;
	w.device_id = device_id;
	w.num_batch = num_batch;
	w.BitmapId = bitmap_id;

	// Open a dialog
	return (bool)Dialog(hWnd, D_SECURE, SecureDeviceWindowProc, &w);
}

// Stop playing the AVI
void StopAvi(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	Animate_Stop(DlgItem(hWnd, id));
	Hide(hWnd, id);
}

// Play an AVI
void PlayAvi(HWND hWnd, UINT id, bool repeat)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	Show(hWnd, id);
	Animate_Play(DlgItem(hWnd, id), 0, -1, (repeat ? -1 : 0));
}

// Close the AVI file
void CloseAvi(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	StopAvi(hWnd, id);
	Animate_Close(DlgItem(hWnd, id));
}

// Open an AVI file
void OpenAvi(HWND hWnd, UINT id, UINT avi_id)
{
	// Validate arguments
	if (hWnd == NULL || avi_id == 0)
	{
		return;
	}

	Hide(hWnd, id);
	Animate_OpenEx(DlgItem(hWnd, id), hDll, MAKEINTRESOURCE(avi_id));
}

// Set the font to the control
void DlgFont(HWND hWnd, UINT id, UINT size, UINT bold)
{
	DIALOG_PARAM *param = (DIALOG_PARAM *)GetParam(hWnd);

	if (param == NULL || param->meiryo == false)
	{
		SetFont(hWnd, id, Font(size, bold));
	}
	else
	{
		SetFont(hWnd, id, GetFont((_GETLANG() == 2 ? "Microsoft YaHei" : GetMeiryoFontName()), size, bold, false, false, false));
	}
}

// Generate a standard font
HFONT Font(UINT size, UINT bold)
{
	return GetFont(NULL, size, bold, false, false, false);
}

// Dialog procedure for internal management
UINT CALLBACK InternalDialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	DIALOG_PARAM *param = (DIALOG_PARAM *)GetParam(hWnd);
	void *app_param = NULL;
	bool white_flag = false;
	UINT ret;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	if (msg == WM_INITDIALOG)
	{
		DoEvents(hWnd);
	}

	if (param == NULL)
	{
		if (msg == WM_INITDIALOG)
		{
			param = (void *)lParam;
			InitDialogInternational(hWnd, param);
		}
	}
	if (param != NULL)
	{
		app_param = param->param;
		white_flag = param->white;
	}

	ret = DlgProc(hWnd, msg, wParam, lParam, white_flag);
	if (ret != 0)
	{
		return ret;
	}

	ret = 0;

	if (param != NULL)
	{
		if (param->proc != NULL)
		{
			ret = param->proc(hWnd, msg, wParam, lParam, app_param);
		}
		else
		{
			if (msg == WM_CLOSE)
			{
				EndDialog(hWnd, 0);
			}
			else if (msg == WM_COMMAND && (wParam == IDOK || wParam == IDCANCEL))
			{
				Close(hWnd);
			}
		}
	}

	if (msg == WM_INITDIALOG)
	{
		SetForegroundWindow(hWnd);
		SetActiveWindow(hWnd);
	}

	return ret;
}

// Show a dialog box
UINT Dialog(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param)
{
	bool white = true;

	return DialogEx(hWnd, id, proc, param, white);
}
UINT DialogEx(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white)
{
	return DialogEx2(hWnd, id, proc, param, white, false);
}
UINT DialogEx2(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white, bool meiryo)
{
	UINT ret;
	DIALOG_PARAM p;
	// Validate arguments
	if (id == 0)
	{
		return 0;
	}

	Zero(&p, sizeof(p));
	p.param = param;
	p.white = white;
	p.proc = proc;

	p.BitmapList = NewBitmapList();

	if (MsIsVista())
	{
		p.meiryo = meiryo;
	}

	ret = DialogInternal(hWnd, id, InternalDialogProc, &p);

	FreeBitmapList(p.BitmapList);

	return ret;
}

// Initialize the icon cache
void InitIconCache()
{
	if (icon_cache_list != NULL)
	{
		return;
	}

	icon_cache_list = NewList(NULL);
}

// Release the icon cache
void FreeIconCache()
{
	UINT i;
	if (icon_cache_list == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(icon_cache_list);i++)
	{
		ICON_CACHE *c = LIST_DATA(icon_cache_list, i);
		DestroyIcon(c->hIcon);
		Free(c);
	}

	ReleaseList(icon_cache_list);
	icon_cache_list = NULL;
}

// Get the Icon
HICON LoadIconEx(UINT id, bool small_icon)
{
	HICON h = NULL;
	UINT i;
	if (icon_cache_list == NULL)
	{
		return small_icon == false ? LoadLargeIconInner(id) : LoadSmallIconInner(id);
	}

	LockList(icon_cache_list);
	{
		for (i = 0;i < LIST_NUM(icon_cache_list);i++)
		{
			ICON_CACHE *c = LIST_DATA(icon_cache_list, i);
			if (c->id == id && c->small_icon == small_icon)
			{
				h = c->hIcon;
				break;
			}
		}

		if (h == NULL)
		{
			h = small_icon == false ? LoadLargeIconInner(id) : LoadSmallIconInner(id);
			if (h != NULL)
			{
				ICON_CACHE *c = ZeroMalloc(sizeof(ICON_CACHE));
				c->hIcon = h;
				c->id = id;
				c->small_icon = small_icon;
				Add(icon_cache_list, c);
			}
		}
	}
	UnlockList(icon_cache_list);

	return h;
}

// Get a large Icon
HICON LoadLargeIcon(UINT id)
{
	return LoadIconEx(id, false);
}

// Get a small icon
HICON LoadSmallIcon(UINT id)
{
	return LoadIconEx(id, true);
}

// Get a large icon
HICON LoadLargeIconInner(UINT id)
{
	HICON ret;
	ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 32, 32, 0);
	if (ret == NULL)
	{
		ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 32, 32, LR_VGACOLOR);
		if (ret == NULL)
		{
			ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 0, 0, 0);
			if (ret == NULL)
			{
				ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 0, 0, LR_VGACOLOR);
				if (ret == NULL)
				{
					ret = LoadIcon(hDll, MAKEINTRESOURCE(id));
				}
			}
		}
	}
	return ret;
}

// Get a small icon
HICON LoadSmallIconInner(UINT id)
{
	HICON ret;
	ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 16, 16, 0);
	if (ret == NULL)
	{
		ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 16, 16, LR_VGACOLOR);
		if (ret == NULL)
		{
			ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 0, 0, 0);
			if (ret == NULL)
			{
				ret = LoadImage(hDll, MAKEINTRESOURCE(id), IMAGE_ICON, 0, 0, LR_VGACOLOR);
				if (ret == NULL)
				{
					ret = LoadLargeIconInner(id);
				}
			}
		}
	}
	return ret;
}

// Set the icon to the button or window
void SetIcon(HWND hWnd, UINT id, UINT icon_id)
{
	HICON icon1, icon2;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	icon1 = LoadLargeIcon(icon_id);
	if (icon1 == NULL)
	{
		return;
	}

	if (id == 0)
	{
		SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM)icon1);
		icon2 = LoadSmallIcon(icon_id);
		if (icon2 == NULL)
		{
			icon2 = icon1;
		}
		SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)icon2);
	}
	else
	{
		bool is_btn = true;
		wchar_t *s = GetClass(hWnd, id);
		if (s != NULL)
		{
			if (UniStrCmpi(s, L"Static") == 0)
			{
				is_btn = false;
			}
			Free(s);
		}

		if (is_btn)
		{
			SendMsg(hWnd, id, BM_SETIMAGE, IMAGE_ICON, (LPARAM)icon1);
		}
		else
		{
			SendMsg(hWnd, id, STM_SETICON, (WPARAM)icon1, 0);
		}
	}
}

// Check whether the radio button is checked
bool IsChecked(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return false;
	}

	return IsDlgButtonChecked(hWnd, id) == BST_CHECKED ? true : false;
}

// Check the radio button
void Check(HWND hWnd, UINT id, bool b)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if ((!(!IsChecked(hWnd, id))) != (!(!b)))
	{
		CheckDlgButton(hWnd, id, b ? BST_CHECKED : BST_UNCHECKED);
	}
}

// Limit the number of characters that can be entered into the text-box
void LimitText(HWND hWnd, UINT id, UINT count)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SendMsg(hWnd, id, EM_LIMITTEXT, count, 0);
}

// Font settings
void SetFont(HWND hWnd, UINT id, HFONT hFont)
{
	SetFontEx(hWnd, id, hFont, false);
}
void SetFontEx(HWND hWnd, UINT id, HFONT hFont, bool no_adjust_font_size)
{
	// Validate arguments
	if (hWnd == NULL || hFont == NULL)
	{
		return;
	}

	SendMessage(DlgItem(hWnd, id), WM_SETFONT, (WPARAM)hFont, true);

	if (no_adjust_font_size == false)
	{
		AdjustFontSize(hWnd, id);
	}
}

// Calculate the font size
bool CalcFontSize(HFONT hFont, UINT *x, UINT *y)
{
	UINT xx = 0, yy = 0;
	TEXTMETRIC tm;
	SIZE sz;
	bool ret = false;
	HDC hDC;

	hDC = CreateCompatibleDC(NULL);

	SelectObject(hDC, hFont);

	Zero(&tm, sizeof(tm));
	Zero(&sz, sizeof(sz));

	if (GetTextMetrics(hDC, &tm))
	{
		xx = tm.tmAveCharWidth;
		yy = tm.tmHeight;

		ret = true;

		if (GetTextExtentPoint32(hDC,
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
			52, &sz))
		{
			xx = (sz.cx / 26 + 1) / 2;
		}
	}

	if (x != NULL)
	{
		*x = xx;
	}

	if (y != NULL)
	{
		*y = yy;
	}

	DeleteDC(hDC);

	return ret;
}

// Get the font magnification
double GetTextScalingFactor()
{
	static int cached_dpi = 0;
	double ret = 1.0;

	if (MsIsVista() == false)
	{
		// It's always 1.0 in Windows XP or earlier
		return 1.0;
	}

	if (cached_dpi == 0)
	{
		HDC hDC = CreateCompatibleDC(NULL);

		if (hDC != NULL)
		{
			cached_dpi = GetDeviceCaps(hDC, LOGPIXELSY);

			DeleteDC(hDC);
		}
	}

	if (cached_dpi != 0)
	{
		ret = (double)cached_dpi / 96.0;

		if (ret < 0)
		{
			ret = -ret;
		}
	}

	return ret;
}

// Get the parameters of the font that was created in the past
bool GetFontParam(HFONT hFont, struct FONT *f)
{
	bool ret = false;
	// Validate arguments
	if (hFont == NULL || f == NULL)
	{
		return false;
	}

	// Search for the existing font
	LockList(font_list);
	{
		UINT i;

		for (i = 0;i < LIST_NUM(font_list);i++)
		{
			FONT *n = LIST_DATA(font_list, i);

			if (n->hFont == hFont)
			{
				Copy(f, n, sizeof(FONT));

				ret = true;

				break;
			}
		}
	}
	UnlockList(font_list);

	return ret;
}

// Get the font
HFONT GetFont(char *name, UINT size, bool bold, bool italic, bool underline, bool strikeout)
{
	HFONT hFont;
	HDC hDC;
	// Validate arguments
	if (name == NULL)
	{
		name = font_name;
	}
	if (size == 0)
	{
		size = font_size;
		if (size == 0)
		{
			size = 9;
		}
	}

	// Search for the existing font
	LockList(font_list);
	{
		FONT *f, t;
		DWORD font_quality = ANTIALIASED_QUALITY;
		OS_INFO *os = GetOsInfo();
		UINT x = 0;
		UINT y = 0;
		int rotate = 0;
		UINT dpi;

		Zero(&t, sizeof(t));
		t.Bold = bold;
		t.Italic = italic;
		t.Size = size;
		t.StrikeOut = strikeout;
		t.UnderLine = underline;
		t.Name = CopyStr(name);
		f = Search(font_list, &t);
		Free(t.Name);

		if (f != NULL)
		{
			// Font is found
			UnlockList(font_list);
			return f->hFont;
		}

		// Create a new font
		hDC = CreateCompatibleDC(NULL);

		// Specify the ClearType in Windows XP or later
		if (OS_IS_WINDOWS_NT(os->OsType) && GET_KETA(os->OsType, 100) >= 3)
		{
			font_quality = CLEARTYPE_NATURAL_QUALITY;
			rotate = 3600;
		}

		if (MsIsVista())
		{
			dpi = GetDeviceCaps(hDC, LOGPIXELSY);
		}
		else
		{
			dpi = 96;
		}

		// Create a font
		hFont = CreateFontA(-MulDiv(size, dpi, 72),
			0, rotate, rotate, (bold == false ? 500 : FW_BOLD),
			italic, underline, strikeout, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
			CLIP_DEFAULT_PRECIS, font_quality, DEFAULT_PITCH, name);

		if (hFont == NULL)
		{
			// Failure
			DeleteDC(hDC);
			UnlockList(font_list);

			return NULL;
		}

		CalcFontSize(hFont, &x, &y);

		// Add to the table
		f = ZeroMalloc(sizeof(FONT));
		f->Bold = bold;
		f->hFont = hFont;
		f->Italic = italic;
		f->Name = CopyStr(name);
		f->Size = size;
		f->StrikeOut = strikeout;
		f->UnderLine = underline;
		f->x = x;
		f->y = y;

		Insert(font_list, f);

		DeleteDC(hDC);
	}
	UnlockList(font_list);

	return hFont;
}

// Comparison of the font
int CompareFont(void *p1, void *p2)
{
	FONT *f1, *f2;
	UINT r;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(FONT **)p1;
	f2 = *(FONT **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	r = StrCmpi(f1->Name, f2->Name);
	if (r != 0)
	{
		return r;
	}
	else
	{
		if (f1->Bold > f2->Bold)
		{
			return 1;
		}
		else if (f1->Bold < f2->Bold)
		{
			return -1;
		}
		else if (f1->Italic > f2->Italic)
		{
			return 1;
		}
		else if (f1->Italic < f2->Italic)
		{
			return -1;
		}
		else if (f1->Size > f2->Size)
		{
			return 1;
		}
		else if (f1->Size < f2->Size)
		{
			return -1;
		}
		else if (f1->StrikeOut > f2->StrikeOut)
		{
			return 1;
		}
		else if (f1->StrikeOut < f2->StrikeOut)
		{
			return -1;
		}
		else if (f1->UnderLine > f2->UnderLine)
		{
			return 1;
		}
		else if (f1->UnderLine < f2->UnderLine)
		{
			return -1;
		}
		else
		{
			return 0;
		}
	}
}

// Initialize the font
void InitFont()
{
	if (font_list != NULL)
	{
		return;
	}
	font_list = NewList(CompareFont);
}

// Release the font
void FreeFont()
{
	UINT i;
	if (font_list == NULL)
	{
		return;
	}
	for (i = 0;i < LIST_NUM(font_list);i++)
	{
		FONT *f = LIST_DATA(font_list, i);
		Free(f->Name);
		DeleteObject((HGDIOBJ)f->hFont);
		Free(f);
	}
	ReleaseList(font_list);
	font_list = NULL;
}

// Show a button to close the window
void EnableClose(HWND hWnd)
{
	HMENU h;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	h = GetSystemMenu(hWnd, false);
	EnableMenuItem(h, SC_CLOSE, MF_ENABLED);
	DrawMenuBar(hWnd);
}

// Hide the button to close the window
void DisableClose(HWND hWnd)
{
	HMENU h;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	h = GetSystemMenu(hWnd, false);
	EnableMenuItem(h, SC_CLOSE, MF_GRAYED);
	DrawMenuBar(hWnd);
}

// Move to the center of the parent window
void CenterParent(HWND hWnd)
{
	RECT rp;
	RECT r;
	HWND hWndParent = GetParent(hWnd);
	int win_x, win_y;
	int x, y;

	if (hWndParent == NULL || IsHide(hWndParent, 0) || IsIconic(hWndParent))
	{
		Center(hWnd);
		return;
	}

	if (GetWindowRect(hWndParent, &rp) == false)
	{
		Center(hWnd);
		return;
	}

	GetWindowRect(hWnd, &r);

	win_x = r.right - r.left;
	win_y = r.bottom - r.top;

	x = (rp.right - rp.left - win_x) / 2 + rp.left;
	y = (rp.bottom - rp.top - win_y) / 2 + rp.top;

	x = MAX(x, 0);
	y = MAX(y, 0);

	SetWindowPos(hWnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
}

// Move the window to the center
void Center(HWND hWnd)
{
	RECT screen;
	RECT win;
	UINT x, y;
	UINT win_x, win_y;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (SystemParametersInfo(SPI_GETWORKAREA, 0, &screen, 0) == false)
	{
		return;
	}

	GetWindowRect(hWnd, &win);
	win_x = win.right - win.left;
	win_y = win.bottom - win.top;

	if (win_x < (UINT)(screen.right - screen.left))
	{
		x = (screen.right - screen.left - win_x) / 2;
	}
	else
	{
		x = 0;
	}

	if (win_y < (UINT)(screen.bottom - screen.top))
	{
		y = (screen.bottom - screen.top - win_y) / 2;
	}
	else
	{
		y = 0;
	}

	SetWindowPos(hWnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
}

// Format the string in the window
void FormatText(HWND hWnd, UINT id, ...)
{
	va_list args;
	wchar_t *buf;
	UINT size;
	wchar_t *str;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	str = GetText(hWnd, id);
	if (str == NULL)
	{
		return;
	}

	size = MAX(UniStrSize(str) * 10, MAX_SIZE * 10);
	buf = MallocEx(size, true);

	va_start(args, id);
	UniFormatArgs(buf, size, str, args);

	SetText(hWnd, id, buf);

	Free(buf);

	Free(str);
	va_end(args);
}

// Show the variable-length message box
UINT MsgBoxEx(HWND hWnd, UINT flag, wchar_t *msg, ...)
{
	va_list args;
	wchar_t *buf;
	UINT size;
	UINT ret;
	// Validate arguments
	if (msg == NULL)
	{
		msg = L"MessageBox";
	}

	size = MAX(UniStrSize(msg) * 10, MAX_SIZE * 10);
	buf = MallocEx(size, true);

	va_start(args, msg);
	UniFormatArgs(buf, size, msg, args);

	ret = MsgBox(hWnd, flag, buf);
	Free(buf);
	va_end(args);

	return ret;
}

// Show the message box
UINT MsgBox(HWND hWnd, UINT flag, wchar_t *msg)
{
	UINT ret;
	wchar_t *title;
	// Validate arguments
	if (msg == NULL)
	{
		msg = L"MessageBox";
	}

	if (title_bar != NULL)
	{
		title = CopyUniStr(title_bar);
	}
	else
	{
		title = CopyStrToUni(CEDAR_PRODUCT_STR);
	}

	if (hWnd)
	{
		// Raise the message box to top-level if the parent window is the top-level window
		if (GetExStyle(hWnd, 0) & WS_EX_TOPMOST)
		{
			flag |= MB_SYSTEMMODAL;
		}
	}

	ret = MessageBoxW(hWnd, msg, title, flag);

	Free(title);

	return ret;
}

// Create a dialog (internal)
UINT DialogInternal(HWND hWnd, UINT id, DIALOG_PROC *proc, void *param)
{
	// Validate arguments
	if (proc == NULL)
	{
		return 0;
	}

	if (MsIsNt() == false)
	{
		// Win9x
		return (UINT)DialogBoxParam(hDll, MAKEINTRESOURCE(id), hWnd, (DLGPROC)proc, (LPARAM)param);
	}
	else
	{
		// WinNT
		return (UINT)DialogBoxParamW(hDll, MAKEINTRESOURCEW(id), hWnd, (DLGPROC)proc, (LPARAM)param);
	}
}

// Dialog box procedure managed by WinUi
UINT DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, bool white_color)
{
	void *param;
	HWND hWndParent;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		if (true)
		{
			RECT rect1;

			SetRect(&rect1, 0, 0, 100, 100);
			MapDialogRect(hWnd, &rect1);
			Debug("%u %u %u %u\n", rect1.left, rect1.right, rect1.top, rect1.bottom);
		}

		param = (void *)lParam;
		SetParam(hWnd, param);

		// Examine whether the parent window exists
		hWndParent = GetParent(hWnd);
		if (hWndParent == NULL || IsShow(hWndParent, 0) == false)
		{
			// Place in the center if parent does not exist
			Center(hWnd);
		}

		if (UseAlpha)
		{
			UINT os_type = GetOsInfo()->OsType;
			if (OS_IS_WINDOWS_NT(os_type) && GET_KETA(os_type, 100) >= 2)
			{
				bool (WINAPI *_SetLayeredWindowAttributes)(HWND, COLORREF, BYTE, DWORD);
				HINSTANCE hInst;

				hInst = LoadLibrary("user32.dll");
				_SetLayeredWindowAttributes =
					(bool (__stdcall *)(HWND,COLORREF,BYTE,DWORD))
					GetProcAddress(hInst, "SetLayeredWindowAttributes");

				if (_SetLayeredWindowAttributes != NULL)
				{
					// Only available on Windows 2000 or later
					SetExStyle(hWnd, 0, WS_EX_LAYERED);
					_SetLayeredWindowAttributes(hWnd, 0, AlphaValue * 255 / 100, LWA_ALPHA);
				}
			}
		}

		break;

	case WM_CTLCOLORBTN:
	case WM_CTLCOLORDLG:
	case WM_CTLCOLOREDIT:
	case WM_CTLCOLORLISTBOX:
	case WM_CTLCOLORMSGBOX:
	case WM_CTLCOLORSCROLLBAR:
	case WM_CTLCOLORSTATIC:
		if (white_color)
		{
			return (UINT)GetStockObject(WHITE_BRUSH);
		}
		break;
	}

	return 0;
}

// Set the parameters of the dialog box
void SetParam(HWND hWnd, void *param)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SetWindowLongPtr(hWnd, DWLP_USER, (LONG_PTR)param);
}

// Get the parameters of the dialog box
void *GetParam(HWND hWnd)
{
	void *ret;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	ret = (void *)GetWindowLongPtr(hWnd, DWLP_USER);
	return ret;
}

// Show the windows as foreground
void Top(HWND hWnd)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

// Hide the window
void Hide(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (IsShow(hWnd, id))
	{
		ShowWindow(DlgItem(hWnd, id), SW_HIDE);
	}
}

// Show the window
void Show(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (IsHide(hWnd, id))
	{
		ShowWindow(DlgItem(hWnd, id), SW_SHOW);
	}
}

// Change the display settings
void SetShow(HWND hWnd, UINT id, bool b)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (b)
	{
		Show(hWnd, id);
	}
	else
	{
		Hide(hWnd, id);
	}
}

// Get whether the window is shown
bool IsShow(HWND hWnd, UINT id)
{
	return IsHide(hWnd, id) ? false : true;
}

// Get whether the window is hidden
bool IsHide(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return true;
	}

	if (GetStyle(hWnd, id) & WS_VISIBLE)
	{
		return false;
	}
	else
	{
		return true;
	}
}

// Remove the window style
void RemoveExStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	old = GetExStyle(hWnd, id);
	if ((old & style) == 0)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_EXSTYLE, old & ~style);
	Refresh(DlgItem(hWnd, id));
}

// Set the window style
void SetExStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	old = GetExStyle(hWnd, id);
	if (old & style)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_EXSTYLE, old | style);
	Refresh(DlgItem(hWnd, id));
}

// Get the window style
UINT GetExStyle(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	return GetWindowLong(DlgItem(hWnd, id), GWL_EXSTYLE);
}

// Remove the window style
void RemoveStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	old = GetStyle(hWnd, id);
	if ((old & style) == 0)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_STYLE, old & ~style);
	Refresh(DlgItem(hWnd, id));
}

// Set the window style
void SetStyle(HWND hWnd, UINT id, UINT style)
{
	UINT old;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	old = GetStyle(hWnd, id);
	if (old & style)
	{
		return;
	}

	SetWindowLong(DlgItem(hWnd, id), GWL_STYLE, old | style);
	Refresh(DlgItem(hWnd, id));
}

// Get the window style
UINT GetStyle(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	return GetWindowLong(DlgItem(hWnd, id), GWL_STYLE);
}

// Get the number of characters in the text
UINT GetTextLen(HWND hWnd, UINT id, bool unicode)
{
	wchar_t *s;
	UINT ret;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	s = GetText(hWnd, id);
	if (s == NULL)
	{
		return 0;
	}

	if (unicode)
	{
		ret = UniStrLen(s);
	}
	else
	{
		char *tmp = CopyUniToStr(s);
		ret = StrLen(tmp);
		Free(tmp);
	}

	Free(s);

	return ret;
}

// Check whether the text is blank
bool IsEmpty(HWND hWnd, UINT id)
{
	bool ret;
	wchar_t *s;
	// Validate arguments
	if (hWnd == NULL)
	{
		return true;
	}

	s = GetText(hWnd, id);

	UniTrim(s);
	if (UniStrLen(s) == 0)
	{
		ret = true;
	}
	else
	{
		ret = false;
	}

	Free(s);

	return ret;
}

// Get the window class
wchar_t *GetClass(HWND hWnd, UINT id)
{
	wchar_t tmp[MAX_SIZE];

	if (MsIsNt() == false)
	{
		wchar_t *ret;
		char *s;
		s = GetClassA(hWnd, id);
		ret = CopyStrToUni(s);
		Free(s);
		return ret;
	}

	// Validate arguments
	if (hWnd == NULL)
	{
		return CopyUniStr(L"");
	}

	GetClassNameW(DlgItem(hWnd, id), tmp, sizeof(tmp));

	return UniCopyStr(tmp);
}
char *GetClassA(HWND hWnd, UINT id)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return CopyStr("");
	}

	GetClassName(DlgItem(hWnd, id), tmp, sizeof(tmp));

	return CopyStr(tmp);
}

// Transmit a message to the control
UINT SendMsg(HWND hWnd, UINT id, UINT msg, WPARAM wParam, LPARAM lParam)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	if (MsIsNt())
	{
		return (UINT)SendMessageW(DlgItem(hWnd, id), msg, wParam, lParam);
	}
	else
	{
		return (UINT)SendMessageA(DlgItem(hWnd, id), msg, wParam, lParam);
	}
}

// Move the cursor to the right edge of the text in the EDIT
void SetCursorOnRight(HWND hWnd, UINT id)
{
	wchar_t *class_name;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	class_name = GetClass(hWnd, id);

	if (class_name != NULL)
	{
		if (UniStrCmpi(class_name, L"edit") == 0)
		{
			wchar_t *str = GetText(hWnd, id);

			if (str != NULL)
			{
				UINT len = UniStrLen(str);

				SendMsg(hWnd, id, EM_SETSEL, len, len);

				Free(str);
			}
		}
		Free(class_name);
	}
}

// Select entire the text in the EDIT
void SelectEdit(HWND hWnd, UINT id)
{
	wchar_t *class_name;

	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	class_name = GetClass(hWnd, id);

	if (class_name != NULL)
	{
		if (UniStrCmpi(class_name, L"edit") == 0)
		{
			SendMsg(hWnd, id, EM_SETSEL, 0, -1);
		}
		Free(class_name);
	}
}

// Deselect the text of EDIT
void UnselectEdit(HWND hWnd, UINT id)
{
	wchar_t *class_name;

	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	class_name = GetClass(hWnd, id);

	if (class_name != NULL)
	{
		if (UniStrCmpi(class_name, L"edit") == 0)
		{
			SendMsg(hWnd, id, EM_SETSEL, -1, 0);
		}
		Free(class_name);
	}
}

// Select all by setting the focus to the EDIT
void FocusEx(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (IsEnable(hWnd, id) == false || IsShow(hWnd, id) == false)
	{
		return;
	}

	SelectEdit(hWnd, id);

	Focus(hWnd, id);
}

// Get whether the specified window has focus
bool IsFocus(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return false;
	}

	if (GetFocus() == DlgItem(hWnd, id))
	{
		return true;
	}

	return false;
}

// Set the focus
void Focus(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (IsEnable(hWnd, id) == false || IsShow(hWnd, id) == false)
	{
		return;
	}

	SetFocus(DlgItem(hWnd, id));
}

// Set the value of the int type
void SetInt(HWND hWnd, UINT id, UINT value)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	UniToStru(tmp, value);
	SetText(hWnd, id, tmp);
}
void SetIntEx(HWND hWnd, UINT id, UINT value)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (value == 0)
	{
		// Leave blank in the case of 0
		SetText(hWnd, id, L"");
	}
	else
	{
		SetInt(hWnd, id, value);
	}
}

// Get the value of the int type
UINT GetInt(HWND hWnd, UINT id)
{
	wchar_t *s;
	UINT ret;
	// Validate arguments
	if (hWnd == NULL)
	{
		return 0;
	}

	s = GetText(hWnd, id);
	if (s == NULL)
	{
		return 0;
	}

	ret = UniToInt(s);
	Free(s);

	return ret;
}

// Update the window appearance
void Refresh(HWND hWnd)
{
	HWND parent;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	DoEvents(hWnd);
	UpdateWindow(hWnd);
	DoEvents(hWnd);

	parent = GetParent(hWnd);
	if (parent != NULL)
	{
		Refresh(parent);
	}
}

// Handle the event
void DoEvents(HWND hWnd)
{
	MSG msg;

	if (PeekMessage(&msg, hWnd, 0, 0, PM_REMOVE))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	UpdateWindow(hWnd);

	if (hWnd)
	{
		DoEvents(NULL);
	}
}

// Close the window
void Close(HWND hWnd)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	SendMessage(hWnd, WM_CLOSE, 0, 0);
}

// Disable the window
void Disable(HWND hWnd, UINT id)
{
	SetEnable(hWnd, id, false);
}

// Enable the window
void Enable(HWND hWnd, UINT id)
{
	SetEnable(hWnd, id, true);
}

// Set the enabled state of a window
void SetEnable(HWND hWnd, UINT id, bool b)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	if (b == false)
	{
		if (IsEnable(hWnd, id))
		{
			if (id != 0 && IsFocus(hWnd, id))
			{
				Focus(hWnd, IDCANCEL);
				Focus(hWnd, IDOK);
			}
			EnableWindow(DlgItem(hWnd, id), false);
			Refresh(DlgItem(hWnd, id));
		}
	}
	else
	{
		if (IsDisable(hWnd, id))
		{
			EnableWindow(DlgItem(hWnd, id), true);
			Refresh(DlgItem(hWnd, id));
		}
	}
}

// Examine whether the window is disabled
bool IsDisable(HWND hWnd, UINT id)
{
	return IsEnable(hWnd, id) ? false : true;
}

// Examine whether the window is enabled
bool IsEnable(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return false;
	}

	return IsWindowEnabled(DlgItem(hWnd, id));
}

// If the control protrude by large font size, adjust into appropriate size
void AdjustFontSize(HWND hWnd, UINT id)
{
	char class_name[MAX_PATH];
	UINT style;
	UINT format = 0;
	HFONT current_font;
	FONT font;
	wchar_t *text;
	RECT rect;
	UINT width, height;
	HFONT new_font = NULL;
	UINT old_font_size;
	UINT style1;
	// Validate arguments
	if (hWnd == NULL)
	{
		return;
	}

	hWnd = DlgItem(hWnd, id);

	if (GetClassNameA(hWnd, class_name, sizeof(class_name)) == 0)
	{
		return;
	}

	if (StrCmpi(class_name, "static") != 0)
	{
		return;
	}

	style = GetStyle(hWnd, 0);

	if ((style & SS_ENDELLIPSIS) || (style & SS_PATHELLIPSIS))
	{
		return;
	}

	style1 = style & 0x0F;

	// Create a format for DrawText
	if (style1 == SS_RIGHT)
	{
		// Right justification
		format |= DT_RIGHT;
	}
	else if (style1 == SS_CENTER)
	{
		// Center justification
		format |= DT_CENTER;
	}
	else if (style1 == SS_LEFT)
	{
		// Left justification
		format |= DT_LEFT;
	}
	else
	{
		// Others
		return;
	}

	if (style & DT_NOPREFIX)
	{
		// Without prefix
		format |= DT_NOPREFIX;
	}

	// Get the font parameters currently set
	current_font = (HFONT)SendMessageA(hWnd, WM_GETFONT, 0, 0);
	if (current_font == NULL)
	{
		return;
	}

	Zero(&font, sizeof(font));
	if (GetFontParam(current_font, &font) == false)
	{
		return;
	}

	// Get the size of the static area
	Zero(&rect, sizeof(rect));
	if (GetWindowRect(hWnd, &rect) == false)
	{
		return;
	}

	// Get the text that is currently set
	text = GetText(hWnd, 0);
	if (text == NULL)
	{
		return;
	}

	if (IsEmptyUniStr(text))
	{
		Free(text);
		return;
	}

	width = GET_ABS(rect.right - rect.left);
	height = GET_ABS(rect.bottom - rect.top);

	new_font = NULL;
	old_font_size = font.Size;

	// Try to gradually reduce the font size until drawing succeeds
	while (font.Size != 0)
	{
		// Drawing test
		bool aborted = false;

		if (IsFontFitInRect(&font, width, height, text, format, &aborted))
		{
			// Drawing success
			if (old_font_size != font.Size)
			{
				// Font size is changed
				new_font = GetFont(font.Name, font.Size, font.Bold, font.Italic, font.UnderLine, font.StrikeOut);
			}
			break;
		}
		else
		{
			if (aborted)
			{
				// Fatal error
				break;
			}
		}

		font.Size--;

		if (font.Size == 1)
		{
			// Not supposed to become a font size like this. Fatal error
			break;
		}
	}

	Free(text);

	if (new_font != NULL)
	{
		// Change the font size
		SetFontEx(hWnd, 0, new_font, true);
	}
}

// Check whether the specified string can be drawn in the specified area with the specified font
bool IsFontFitInRect(struct FONT *f, UINT width, UINT height, wchar_t *text, UINT format, bool *aborted)
{
	RECT r;
	int i;
	bool dummy_bool;
	UINT new_height;
	HFONT hCreatedFont, hOldFont;
	// Validate arguments
	if (f == NULL || text == NULL)
	{
		return false;
	}
	if (aborted == NULL)
	{
		aborted = &dummy_bool;
	}

	format |= DT_CALCRECT | DT_WORDBREAK;

	*aborted = false;

	// Create a font
	hCreatedFont = GetFont(f->Name, f->Size, f->Bold, f->Italic, f->UnderLine, f->StrikeOut);
	if (hCreatedFont == NULL)
	{
		*aborted = true;
		return false;
	}

	Lock(lock_common_dc);
	{
		hOldFont = SelectObject(hCommonDC, hCreatedFont);

		Zero(&r, sizeof(r));
		r.left = r.top = 0;
		r.right = width;
		r.bottom = height;

		if (MsIsNt())
		{
			i = DrawTextW(hCommonDC, text, -1, &r, format);
		}
		else
		{
			char *a = CopyUniToStr(text);

			i = DrawTextA(hCommonDC, a, -1, &r, format);

			Free(a);
		}

		SelectObject(hCommonDC, hOldFont);
	}
	Unlock(lock_common_dc);

	if (i == 0)
	{
		*aborted = true;
		return false;
	}

	new_height = GET_ABS(r.bottom - r.top);

	if (new_height > height)
	{
		return false;
	}

	return true;
}

// Set a text string
void SetText(HWND hWnd, UINT id, wchar_t *str)
{
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	SetTextInner(hWnd, id, str);
}
void SetTextInner(HWND hWnd, UINT id, wchar_t *str)
{
	wchar_t *old;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	// Get the old string
	old = GetText(hWnd, id);
	if (UniStrCmp(str, old) == 0)
	{
		// Identity
		Free(old);
		return;
	}

	Free(old);

	if (MsIsNt())
	{
		SetWindowTextW(DlgItem(hWnd, id), str);
	}
	else
	{
		char *tmp = CopyUniToStr(str);

		if (MsIsNt() == false && StrLen(tmp) >= 32000)
		{
			// Truncate to less than 32k
			tmp[32000] = 0;
		}

		SetWindowTextA(DlgItem(hWnd, id), tmp);
		Free(tmp);
	}

	AdjustFontSize(hWnd, id);

	if (id != 0)
	{
		Refresh(DlgItem(hWnd, id));
	}
}
void SetTextA(HWND hWnd, UINT id, char *str)
{
	wchar_t *s;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return;
	}

	s = CopyStrToUni(str);
	if (s == NULL)
	{
		return;
	}

	SetText(hWnd, id, s);

	Free(s);
}

// Get the text string to the buffer
bool GetTxt(HWND hWnd, UINT id, wchar_t *str, UINT size)
{
	wchar_t *s;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return false;
	}

	s = GetText(hWnd, id);
	if (s == NULL)
	{
		UniStrCpy(str, size, L"");
		return false;
	}

	UniStrCpy(str, size, s);
	Free(s);

	return true;
}
bool GetTxtA(HWND hWnd, UINT id, char *str, UINT size)
{
	char *s;
	// Validate arguments
	if (hWnd == NULL || str == NULL)
	{
		return false;
	}

	s = GetTextA(hWnd, id);
	if (s == NULL)
	{
		StrCpy(str, size, "");
		return false;
	}

	StrCpy(str, size, s);
	Free(s);

	return true;
}

// Get the text string
wchar_t *GetText(HWND hWnd, UINT id)
{
	wchar_t *ret;
	UINT size, len;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	if (MsIsNt() == false)
	{
		char *s = GetTextA(hWnd, id);
		ret = CopyStrToUni(s);
		Free(s);

		return ret;
	}

	len = GetWindowTextLengthW(DlgItem(hWnd, id));
	if (len == 0)
	{
		return CopyUniStr(L"");
	}

	size = (len + 1) * 2;
	ret = ZeroMallocEx(size, true);

	GetWindowTextW(DlgItem(hWnd, id), ret, size);

	return ret;
}
char *GetTextA(HWND hWnd, UINT id)
{
	char *ret;
	UINT size, len;
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	len = GetWindowTextLengthA(DlgItem(hWnd, id));
	if (len == 0)
	{
		return CopyStr("");
	}

	size = len + 1;
	ret = ZeroMallocEx(size, true);

	GetWindowTextA(DlgItem(hWnd, id), ret, size);

	return ret;
}

// Get the item in the dialog
HWND DlgItem(HWND hWnd, UINT id)
{
	// Validate arguments
	if (hWnd == NULL)
	{
		return NULL;
	}

	if (id == 0)
	{
		return hWnd;
	}
	else
	{
		return GetDlgItem(hWnd, id);
	}
}

// Initialize the WinUi
void InitWinUi(wchar_t *software_name, char *font, UINT fontsize)
{
	if (tls_current_wizard == 0xffffffff)
	{
		tls_current_wizard = TlsAlloc();
	}

	if ((init_winui_counter++) != 0)
	{
		return;
	}

	if (hDll != NULL)
	{
		return;
	}

	if (MayaquaIsMinimalMode() == false)
	{
		if (Is64())
		{
			hDll = MsLoadLibraryAsDataFile(PENCORE_DLL_NAME);
		}
		else
		{
			hDll = MsLoadLibrary(PENCORE_DLL_NAME);
		}

		if (hDll == NULL)
		{
			Alert(PENCORE_DLL_NAME " not found. "CEDAR_PRODUCT_STR " VPN couldn't start.\r\n\r\n"
				"Please reinstall all files with "CEDAR_PRODUCT_STR " VPN Installer.",
				NULL);
			exit(0);
		}
	}
	else
	{
		hDll = LoadLibrary(MsGetExeFileName());

		if (hDll == NULL)
		{
			Alert("MsLoadLibrary() Error.",
				NULL);
			exit(0);
		}
	}

	if (software_name != NULL)
	{
		title_bar = CopyUniStr(software_name);
	}
	else
	{
		title_bar = CopyUniStr(CEDAR_PRODUCT_STR_W L" VPN");
	}

	if (font != NULL)
	{
		font_name = CopyStr(font);
	}
	else
	{
		font_name = CopyStr(_SS("DEFAULT_FONT"));
	}

	if (MsIsWindows7())
	{
		char *win7_font = _SS("DEFAULT_FONT_WIN7");

		if (IsEmptyStr(win7_font) == false)
		{
			Free(font_name);
			font_name = CopyStr(win7_font);
		}

		if (GetTextScalingFactor() >= 1.44)
		{
			// Use a substitute font in the case of high-DPI in Windows 7 and later
			char *alternative_font = _SS("DEFAULT_FONT_HIGHDPI");

			if (IsEmptyStr(alternative_font) == false)
			{
				Free(font_name);
				font_name = CopyStr(alternative_font);
			}
		}
	}

	if (fontsize != 0)
	{
		font_size = fontsize;
	}
	else
	{
		font_size = _II("DEFAULT_FONT_SIZE");
		if (font_size == 0)
		{
			font_size = 9;
		}
	}

	lock_common_dc = NewLock();

	hCommonDC = CreateCompatibleDC(NULL);

	InitIconCache();

	InitFont();

	InitImageList();
}

// Release the WinUi
void FreeWinUi()
{
	if ((--init_winui_counter) != 0)
	{
		return;
	}

	if (hDll == NULL)
	{
		return;
	}

	FreeImageList();

	FreeFont();

	FreeIconCache();

	FreeLibrary(hDll);
	hDll = NULL;

	Free(title_bar);
	title_bar = NULL;

	Free(font_name);
	font_name = NULL;

	if (hCommonDC != NULL)
	{
		DeleteDC(hCommonDC);
		hCommonDC = NULL;
	}

	DeleteLock(lock_common_dc);
	lock_common_dc = NULL;
}

#endif	// WIN32
