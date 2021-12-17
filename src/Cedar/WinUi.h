// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module



// WinUi.h
// User interface code for Win32

#ifdef OS_WIN32

#ifndef WINUI_H
#define WINUI_H

#include "Cedar.h"

#define	WINUI_DEBUG_TEXT							"@winui_debug.txt"

#define	LV_INSERT_RESET_ALL_ITEM_MIN				500

#define WINUI_PASSWORD_NULL_USERNAME				"NULL"

#define WINUI_DEFAULT_DIALOG_UNIT_X					7
#define WINUI_DEFAULT_DIALOG_UNIT_Y					14

// Constants
#define	FREE_REGKEY				"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN Client\\Free Edition Info"
#define ONCE_MSG_REGKEY			"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Common"
#define ONCE_MSG_REGVALUE		"HideMessage_%u"

#define	NICINFO_AUTOCLOSE_TIME_1	(20 * 1000)
#define	NICINFO_AUTOCLOSE_TIME_2	1800

extern bool UseAlpha;
extern UINT AlphaValue;


// Minimum font size
#define	WINUI_MIN_FONTSIZE			5


// Macro
#define	DIALOG			DIALOGEX(false)
#define	DIALOG_WHITE	DIALOGEX(true)
#define	DIALOGEX(white)								\
	void *param = GetParam(hWnd);					\
	{												\
		UINT ret;									\
		ret = DlgProc(hWnd, msg, wParam, lParam, white);	\
		if (ret != 0) return ret;					\
	}

typedef UINT (__stdcall DIALOG_PROC)(HWND, UINT, WPARAM, LPARAM);

typedef UINT (WINUI_DIALOG_PROC)(HWND, UINT, WPARAM, LPARAM, void *);

typedef UINT (WINUI_WIZARD_PROC)(HWND, UINT, WPARAM, LPARAM, WIZARD *, WIZARD_PAGE *, void *);


// Special message to be used for this wizard
#define	WM_WIZ_BASE						(WM_APP + 201)
#define	WM_WIZ_NEXT						(WM_WIZ_BASE + 0)
#define	WM_WIZ_BACK						(WM_WIZ_BASE + 1)
#define	WM_WIZ_CLOSE					(WM_WIZ_BASE + 2)
#define	WM_WIZ_SHOW						(WM_WIZ_BASE + 3)
#define	WM_WIZ_HIDE						(WM_WIZ_BASE + 4)


// Secure operation contents
#define	WINUI_SECURE_ENUM_OBJECTS		1			// Enumerate objects
#define	WINUI_SECURE_WRITE_DATA			2			// Write the data
#define	WINUI_SECURE_READ_DATA			3			// Read the data
#define	WINUI_SECURE_WRITE_CERT			4			// Write the certificate
#define	WINUI_SECURE_READ_CERT			5			// Read the certificate
#define	WINUI_SECURE_WRITE_KEY			6			// Write the secret key
#define	WINUI_SECURE_SIGN_WITH_KEY		7			// Signature by the private key
#define	WINUI_SECURE_DELETE_OBJECT		8			// Delete the object
#define	WINUI_SECURE_DELETE_CERT		9			// Delete the certificate
#define	WINUI_SECURE_DELETE_KEY			10			// Delete the private key
#define	WINUI_SECURE_DELETE_DATA		11			// Delete the Data

// Secure operation structure
typedef struct WINUI_SECURE_BATCH
{
	UINT Type;										// Type of operation
	char *Name;										// Name
	bool Private;									// Private mode
	BUF *InputData;									// Input data
	BUF *OutputData;								// Output data
	X *InputX;										// Input certificate
	X *OutputX;										// Output certificate
	K *InputK;										// Input secret key
	LIST *EnumList;									// Enumerated list
	UCHAR OutputSign[4096 / 8];						// Output signature
	bool Succeed;									// Success flag
} WINUI_SECURE_BATCH;

// Status window
typedef struct STATUS_WINDOW
{
	HWND hWnd;
	THREAD *Thread;
} STATUS_WINDOW;

// Batch processing items
typedef struct LVB_ITEM
{
	UINT NumStrings;				// The number of strings
	wchar_t **Strings;				// String buffer
	UINT Image;						// Image number
	void *Param;					// Parameters
} LVB_ITEM;

// LV insertion batch process
typedef struct LVB
{
	LIST *ItemList;					// Item list
} LVB;


#ifdef WINUI_C

// Internal code

// Font
typedef struct FONT
{
	UINT Size;						// Size
	bool Bold;						// Bold type
	bool Italic;					// Italic type
	bool UnderLine;					// Underline
	bool StrikeOut;					// Strike through
	char *Name;						// Font name
	HFONT hFont;					// Font
	UINT x, y;						// Font size
} FONT;

// Font cache list
static LIST *font_list = NULL;

// Dialog related
typedef struct DIALOG_PARAM
{
	bool white;
	void *param;
	WINUI_DIALOG_PROC *proc;
	bool meiryo;
	LIST *BitmapList;

	WIZARD *wizard;
	WIZARD_PAGE *wizard_page;
	WINUI_WIZARD_PROC *wizard_proc;
} DIALOG_PARAM;

// Secure device window related
typedef struct SECURE_DEVICE_WINDOW
{
	WINUI_SECURE_BATCH *batch;
	UINT num_batch;
	UINT device_id;
	struct SECURE_DEVICE_THREAD *p;
	char *default_pin;
	UINT BitmapId;
} SECURE_DEVICE_WINDOW;

// Thread
typedef struct SECURE_DEVICE_THREAD
{
	SECURE_DEVICE_WINDOW *w;
	HWND hWnd;
	bool Succeed;
	wchar_t *ErrorMessage;
	char *pin;
} SECURE_DEVICE_THREAD;

void StartSecureDevice(HWND hWnd, SECURE_DEVICE_WINDOW *w);

// Passphrase
typedef struct PASSPHRASE_DLG
{
	char pass[MAX_SIZE];
	BUF *buf;
	bool p12;
} PASSPHRASE_DLG;

void PassphraseDlgProcCommand(HWND hWnd, PASSPHRASE_DLG *p);

// Status window
typedef struct STATUS_WINDOW_PARAM
{
	HWND hWnd;
	SOCK *Sock;
	THREAD *Thread;
	wchar_t AccountName[MAX_ACCOUNT_NAME_LEN + 1];
} STATUS_WINDOW_PARAM;

// Certificate display dialog
typedef struct CERT_DLG
{
	X *x, *issuer_x;
	bool ManagerMode;
} CERT_DLG;


typedef struct IMAGELIST_ICON
{
	UINT id;
	HICON hSmallImage;
	HICON hLargeImage;
	UINT Index;
} IMAGELIST_ICON;

typedef struct SEARCH_WINDOW_PARAM
{
	wchar_t *caption;
	HWND hWndFound;
} SEARCH_WINDOW_PARAM;

// Remote connection screen setting
typedef struct WINUI_REMOTE
{
	bool flag1;
	char *RegKeyName;					// Registry key name
	UINT Icon;							// Icon
	wchar_t *Caption;					// Caption
	wchar_t *Title;						// Title
	char *Hostname;						// Host name
	char *DefaultHostname;				// Default host name
	LIST *CandidateList;				// Candidate list
} WINUI_REMOTE;

#define CALLBACK __stdcall

void InitImageList();
void FreeImageList();
IMAGELIST_ICON *LoadIconForImageList(UINT id);
int CompareImageListIcon(void *p1, void *p2);
BOOL CALLBACK EnumResNameProc(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR lParam);
void PrintCertInfo(HWND hWnd, CERT_DLG *p);
void CertDlgUpdate(HWND hWnd, CERT_DLG *p);
bool CALLBACK SearchWindowEnumProc(HWND hWnd, LPARAM lParam);
UINT RemoteDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void RemoteDlgInit(HWND hWnd, WINUI_REMOTE *r);
void RemoteDlgRefresh(HWND hWnd, WINUI_REMOTE *r);
void RemoteDlgOnOk(HWND hWnd, WINUI_REMOTE *r);
int CALLBACK LvSortProc(LPARAM param1, LPARAM param2, LPARAM sort_param);

// Icon cache
typedef struct ICON_CACHE
{
	UINT id;
	bool small_icon;
	HICON hIcon;
} ICON_CACHE;

static LIST *icon_cache_list = NULL;

// Sort related
typedef struct WINUI_LV_SORT
{
	HWND hWnd;
	UINT id;
	UINT subitem;
	bool desc;
	bool numeric;
} WINUI_LV_SORT;

// Version information
typedef struct WINUI_ABOUT
{
	CEDAR *Cedar;
	wchar_t *ProductName;
	UINT Bitmap;
	WINUI_UPDATE *Update;
} WINUI_ABOUT;

UINT AboutDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void AboutDlgInit(HWND hWnd, WINUI_ABOUT *a);

#define	LED_WIDTH	96
#define	LED_HEIGHT	16
#define	LED_FORCE_UPDATE	60000

// LED
struct LED
{
	HDC hDC;
	HBITMAP hBM;
	void *Buf;
	UCHAR px[LED_WIDTH][LED_HEIGHT];
	bool Updated;
	UINT64 LastUpdated;
};

void LedDrawString(LED *d, char *str, HFONT f);
void LedMainDraw(LED *d, HANDLE h);
void LedSpecial(LED *d, HANDLE h, UINT n);


// STRING
typedef struct STRING_DLG
{
	wchar_t String[MAX_SIZE];
	wchar_t *Title;
	wchar_t *Info;
	UINT Icon;
	bool AllowEmpty;
	bool AllowUnsafe;
} STRING_DLG;

void StringDlgInit(HWND hWnd, STRING_DLG *s);
void StringDlgUpdate(HWND hWnd, STRING_DLG *s);

// PIN code is cached for five minutes
#define	WINUI_SECUREDEVICE_PIN_CACHE_TIME		(5 * 60 * 1000)
extern char cached_pin_code[MAX_SIZE];
extern UINT64 cached_pin_code_expires;

// TCP connection dialog related
typedef struct WINCONNECT_DLG_DATA
{
	wchar_t *caption;
	wchar_t *info;
	UINT icon_id;
	UINT timeout;
	char *hostname;
	UINT port;
	bool cancel;
	SOCK *ret_sock;
	THREAD *thread;
	HWND hWnd;
	char nat_t_svc_name[MAX_SIZE];
	UINT nat_t_error_code;
	bool try_start_ssl;
	SSL_VERIFY_OPTION *ssl_option;
	UINT *ssl_err;
	char *hint_str;
} WINCONNECT_DLG_DATA;

HBITMAP ResizeBitmap(HBITMAP hSrc, UINT src_x, UINT src_y, UINT dst_x, UINT dst_y);
#else
typedef struct FONT FONT;
#endif	// WINUI_C

// The information screen about the free version
typedef struct FREEINFO
{
	char ServerName[MAX_SERVER_STR_LEN + 1];
	HWND hWnd;
	THREAD *Thread;
	EVENT *Event;
} FREEINFO;

// Message
typedef struct ONCEMSG_DLG
{
	UINT Icon;
	wchar_t *Title;
	wchar_t *Message;
	bool ShowCheckbox;
	bool Checked;
	UINT MessageHash;
	bool *halt;
} ONCEMSG_DLG;

// Definition of bad process
typedef struct BAD_PROCESS
{
	char *ExeName;
	char *Title;
} BAD_PROCESS;

// Page in the wizard
struct WIZARD_PAGE
{
	UINT Id;
	UINT Index;
	WINUI_WIZARD_PROC *Proc;
	wchar_t *Title;
	WIZARD *Wizard;

	struct DIALOG_PARAM *DialogParam;
	HWND hWndPage;
	bool EnableNext;
	bool EnableBack;
	bool EnableClose;
	bool IsFinish;
};

// Wizard
struct WIZARD
{
	UINT Icon;
	HWND hWndParent;
	LIST *Pages;
	void *Param;
	UINT Bitmap;
	wchar_t *Caption;
	wchar_t *CloseConfirmMsg;
	bool IsAreoStyle;

	HWND hWndWizard;
	bool SetCenterFlag;
	bool ReplaceWindowProcFlag;
	void *OriginalWindowProc;
};

// Update notification
struct WINUI_UPDATE
{
	wchar_t SoftwareTitle[MAX_SIZE];
	char SoftwareName[MAX_SIZE];
	UINT64 CurrentDate;
	UINT CurrentBuild;
	UINT CurrentVer;
	char ClientId[128];
	char RegKey[MAX_PATH];
	UPDATE_CLIENT *UpdateClient;
	bool UseSuppressFlag;
	bool CurrentlyDisabled;
};

// Update notification parameters
struct WINUI_UPDATE_DLG_PARAM
{
	WINUI_UPDATE *Update;
	UINT LatestBuild;
	UINT64 LatestDate;
	char *LatestVer;
	char *Url;
	volatile bool *halt_flag;
	bool IsInConfigDialog;
};

// Registry key to save the update notification settings
#define WINUI_UPDATE_REGKEY			"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Check Update\\%s"


// Function prototype
void InitWinUi(wchar_t *software_name, char *font, UINT fontsize);
void FreeWinUi();

WINUI_UPDATE *InitUpdateUi(wchar_t *title, char *name, char *family_name, UINT64 current_date, UINT current_build, UINT current_ver, char *client_id, bool use_suppress_flag);
void FreeUpdateUi(WINUI_UPDATE *u);
void DisableUpdateUi(WINUI_UPDATE *u);
void LoadUpdateUiSetting(WINUI_UPDATE *u, UPDATE_CLIENT_SETTING *s);
void SaveUpdateUiSetting(WINUI_UPDATE *u, UPDATE_CLIENT_SETTING *s);
void UpdateNotifyProcUi(UPDATE_CLIENT *c, UINT latest_build, UINT64 latest_date, char *latest_ver, char *url, volatile bool *halt_flag, void *param);
UINT UpdateNoticeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool ConfigUpdateUi(WINUI_UPDATE *u, HWND hWnd);
UINT UpdateConfigDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);

bool IsThisProcessForeground();
HWND DlgItem(HWND hWnd, UINT id);
void SetText(HWND hWnd, UINT id, wchar_t *str);
void SetTextInner(HWND hWnd, UINT id, wchar_t *str);
void SetTextA(HWND hWnd, UINT id, char *str);
wchar_t *GetText(HWND hWnd, UINT id);
char *GetTextA(HWND hWnd, UINT id);
bool GetTxt(HWND hWnd, UINT id, wchar_t *str, UINT size);
bool GetTxtA(HWND hWnd, UINT id, char *str, UINT size);
bool IsEnable(HWND hWnd, UINT id);
bool IsDisable(HWND hWnd, UINT id);
void Enable(HWND hWnd, UINT id);
void Disable(HWND hWnd, UINT id);
void SetEnable(HWND hWnd, UINT id, bool b);
void Close(HWND hWnd);
void DoEvents(HWND hWnd);
void Refresh(HWND hWnd);
UINT GetInt(HWND hWnd, UINT id);
void SetInt(HWND hWnd, UINT id, UINT value);
void SetIntEx(HWND hWnd, UINT id, UINT value);
void Focus(HWND hWnd, UINT id);
void FocusEx(HWND hWnd, UINT id);
bool IsFocus(HWND hWnd, UINT id);
wchar_t *GetClass(HWND hWnd, UINT id);
char *GetClassA(HWND hWnd, UINT id);
void SelectEdit(HWND hWnd, UINT id);
void SetCursorOnRight(HWND hWnd, UINT id);
void UnselectEdit(HWND hWnd, UINT id);
UINT SendMsg(HWND hWnd, UINT id, UINT msg, WPARAM wParam, LPARAM lParam);
bool IsEmpty(HWND hWnd, UINT id);
UINT GetTextLen(HWND hWnd, UINT id, bool unicode);
UINT GetStyle(HWND hWnd, UINT id);
void SetStyle(HWND hWnd, UINT id, UINT style);
void RemoveStyle(HWND hWnd, UINT id, UINT style);
UINT GetExStyle(HWND hWnd, UINT id);
void SetExStyle(HWND hWnd, UINT id, UINT style);
void RemoveExStyle(HWND hWnd, UINT id, UINT style);
void Hide(HWND hWnd, UINT id);
void Show(HWND hWnd, UINT id);
void SetShow(HWND hWnd, UINT id, bool b);
bool IsHide(HWND hWnd, UINT id);
bool IsShow(HWND hWnd, UINT id);
void Top(HWND hWnd);
void *GetParam(HWND hWnd);
void SetParam(HWND hWnd, void *param);
UINT DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, bool white_color);
UINT DialogInternal(HWND hWnd, UINT id, DIALOG_PROC *proc, void *param);
UINT MsgBox(HWND hWnd, UINT flag, wchar_t *msg);
UINT MsgBoxEx(HWND hWnd, UINT flag, wchar_t *msg, ...);
void FormatText(HWND hWnd, UINT id, ...);
void Center(HWND hWnd);
void CenterParent(HWND hWnd);
void DisableClose(HWND hWnd);
void EnableClose(HWND hWnd);
void InitFont();
void FreeFont();
int CompareFont(void *p1, void *p2);
HFONT GetFont(char *name, UINT size, bool bold, bool italic, bool underline, bool strikeout);
double GetTextScalingFactor();
bool CalcFontSize(HFONT hFont, UINT *x, UINT *y);
void SetFont(HWND hWnd, UINT id, HFONT hFont);
void SetFontEx(HWND hWnd, UINT id, HFONT hFont, bool no_adjust_font_size);
void LimitText(HWND hWnd, UINT id, UINT count);
void Check(HWND hWnd, UINT id, bool b);
bool IsChecked(HWND hWnd, UINT id);
void SetIcon(HWND hWnd, UINT id, UINT icon_id);
bool SecureDeviceWindow(HWND hWnd, WINUI_SECURE_BATCH *batch, UINT num_batch, UINT device_id, UINT bitmap_id);
UINT Dialog(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param);
UINT DialogEx(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white);
UINT DialogEx2(HWND hWnd, UINT id, WINUI_DIALOG_PROC *proc, void *param, bool white, bool meiryo);
UINT __stdcall InternalDialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
UINT SecureDeviceWindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
HFONT Font(UINT size, UINT bold);
void DlgFont(HWND hWnd, UINT id, UINT size, UINT bold);
void OpenAvi(HWND hWnd, UINT id, UINT avi_id);
void CloseAvi(HWND hWnd, UINT id);
void PlayAvi(HWND hWnd, UINT id, bool repeat);
void StopAvi(HWND hWnd, UINT id);
void EnableSecureDeviceWindowControls(HWND hWnd, bool enable);
void SecureDeviceThread(THREAD *t, void *param);
void Command(HWND hWnd, UINT id);
wchar_t *OpenDlg(HWND hWnd, wchar_t *filter, wchar_t *title);
char *OpenDlgA(HWND hWnd, char *filter, char *title);
wchar_t *SaveDlg(HWND hWnd, wchar_t *filter, wchar_t *title, wchar_t *default_name, wchar_t *default_ext);
char *SaveDlgA(HWND hWnd, char *filter, char *title, char *default_name, char *default_ext);
wchar_t *MakeFilter(wchar_t *str);
char *MakeFilterA(char *str);
bool PassphraseDlg(HWND hWnd, char *pass, UINT pass_size, BUF *buf, bool p12);
UINT PassphraseDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool PasswordDlg(HWND hWnd, UI_PASSWORD_DLG *p);
void PasswordDlgOnOk(HWND hWnd, UI_PASSWORD_DLG *p);
UINT PasswordDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void PasswordDlgProcChange(HWND hWnd, UI_PASSWORD_DLG *p);
UINT CbAddStr(HWND hWnd, UINT id, wchar_t *str, UINT data);
UINT CbAddStrA(HWND hWnd, UINT id, char *str, UINT data);
UINT CbAddStr9xA(HWND hWnd, UINT id, char *str, UINT data);
void CbSelectIndex(HWND hWnd, UINT id, UINT index);
UINT CbNum(HWND hWnd, UINT id);
UINT CbFindStr(HWND hWnd, UINT id, wchar_t *str);
UINT CbFindStr9xA(HWND hWnd, UINT id, char *str);
wchar_t *CbGetStr(HWND hWnd, UINT id);
UINT CbFindData(HWND hWnd, UINT id, UINT data);
UINT CbGetData(HWND hWnd, UINT id, UINT index);
void CbSelect(HWND hWnd, UINT id, int data);
void CbReset(HWND hWnd, UINT id);
void CbSetHeight(HWND hWnd, UINT id, UINT value);
UINT CbGetSelectIndex(HWND hWnd, UINT id);
UINT CbGetSelect(HWND hWnd, UINT id);
void SetRange(HWND hWnd, UINT id, UINT start, UINT end);
void SetPos(HWND hWnd, UINT id, UINT pos);
void LbReset(HWND hWnd, UINT id);
STATUS_WINDOW *StatusPrinterWindowStart(SOCK *s, wchar_t *account_name);
void StatusPrinterWindowStop(STATUS_WINDOW *sw);
void StatusPrinterWindowPrint(STATUS_WINDOW *sw, wchar_t *str);
void StatusPrinterWindowThread(THREAD *thread, void *param);
UINT StatusPrinterWindowDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void CertDlg(HWND hWnd, X *x, X *issuer_x, bool manager);
UINT CertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void LvInit(HWND hWnd, UINT id);
void LvInitEx(HWND hWnd, UINT id, bool no_image);
void LvInitEx2(HWND hWnd, UINT id, bool no_image, bool large_icon);
void LvReset(HWND hWnd, UINT id);
void LvInsertColumn(HWND hWnd, UINT id, UINT index, wchar_t *str, UINT width);
UINT GetIcon(UINT icon_id);
void LvInsert(HWND hWnd, UINT id, UINT icon, void *param, UINT num_str, ...);
UINT LvInsertItem(HWND hWnd, UINT id, UINT icon, void *param, wchar_t *str);
UINT LvInsertItemByImageListId(HWND hWnd, UINT id, UINT image, void *param, wchar_t *str);
UINT LvInsertItemByImageListIdA(HWND hWnd, UINT id, UINT image, void *param, char *str);
void LvSetItem(HWND hWnd, UINT id, UINT index, UINT pos, wchar_t *str);
void LvSetItemA(HWND hWnd, UINT id, UINT index, UINT pos, char *str);
void LvSetItemParam(HWND hWnd, UINT id, UINT index, void *param);
void LvSetItemImageByImageListId(HWND hWnd, UINT id, UINT index, UINT image);
void LvDeleteItem(HWND hWnd, UINT id, UINT index);
UINT LvNum(HWND hWnd, UINT id);
void *LvGetParam(HWND hWnd, UINT id, UINT index);
wchar_t *LvGetStr(HWND hWnd, UINT id, UINT index, UINT pos);
char *LvGetStrA(HWND hWnd, UINT id, UINT index, UINT pos);
UINT LvSearchParam(HWND hWnd, UINT id, void *param);
UINT LvSearchStr(HWND hWnd, UINT id, UINT pos, wchar_t *str);
UINT LvSearchStrA(HWND hWnd, UINT id, UINT pos, char *str);
UINT LvGetSelected(HWND hWnd, UINT id);
void *LvGetSelectedParam(HWND hWnd, UINT id);
UINT LvGetFocused(HWND hWnd, UINT id);
wchar_t *LvGetFocusedStr(HWND hWnd, UINT id, UINT pos);
wchar_t *LvGetSelectedStr(HWND hWnd, UINT id, UINT pos);
char *LvGetSelectedStrA(HWND hWnd, UINT id, UINT pos);
bool LvIsSelected(HWND hWnd, UINT id);
UINT LvGetNextMasked(HWND hWnd, UINT id, UINT start);
bool LvIsMasked(HWND hWnd, UINT id);
bool LvIsSingleSelected(HWND hWnd, UINT id);
bool LvIsMultiMasked(HWND hWnd, UINT id);
void LvAutoSize(HWND hWnd, UINT id);
void LvSelect(HWND hWnd, UINT id, UINT index);
void LvSelectByParam(HWND hWnd, UINT id, void *param);
void LvSelectAll(HWND hWnd, UINT id);
void LvSwitchSelect(HWND hWnd, UINT id);
void LvSetView(HWND hWnd, UINT id, bool details);
UINT LvGetColumnWidth(HWND hWnd, UINT id, UINT index);
void CheckCertDlg(UI_CHECKCERT *p);
UINT CheckCertDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void PrintCheckCertInfo(HWND hWnd, UI_CHECKCERT *p);
void ShowDlgDiffWarning(HWND hWnd, UI_CHECKCERT *p);
void CheckCertDialogOnOk(HWND hWnd, UI_CHECKCERT *p);
bool ConnectErrorDlg(UI_CONNECTERROR_DLG *p);
UINT ConnectErrorDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
HINSTANCE GetUiDll();
HICON LoadLargeIconInner(UINT id);
HICON LoadSmallIconInner(UINT id);
HICON LoadLargeIcon(UINT id);
HICON LoadSmallIcon(UINT id);
HICON LoadIconEx(UINT id, bool small_icon);
void InitIconCache();
void FreeIconCache();
LVB *LvInsertStart();
void LvInsertAdd(LVB *b, UINT icon, void *param, UINT num_str, ...);
void LvInsertEnd(LVB *b, HWND hWnd, UINT id);
void LvInsertEndEx(LVB *b, HWND hWnd, UINT id, bool force_reset);
void LvSetStyle(HWND hWnd, UINT id, UINT style);
void LvRemoveStyle(HWND hWnd, UINT id, UINT style);
HMENU LoadSubMenu(UINT menu_id, UINT pos, HMENU *parent_menu);
UINT GetMenuItemPos(HMENU hMenu, UINT id);
void DeleteMenuItem(HMENU hMenu, UINT pos);
void SetMenuItemBold(HMENU hMenu, UINT pos, bool bold);
wchar_t *GetMenuStr(HMENU hMenu, UINT pos);
char *GetMenuStrA(HMENU hMenu, UINT pos);
void SetMenuStr(HMENU hMenu, UINT pos, wchar_t *str);
void SetMenuStrA(HMENU hMenu, UINT pos, char *str);
void RemoveShortcutKeyStrFromMenu(HMENU hMenu);
UINT GetMenuNum(HMENU hMenu);
void PrintMenu(HWND hWnd, HMENU hMenu);
void LvRename(HWND hWnd, UINT id, UINT pos);
void LvSetEnhanced(HWND hWnd, UINT id, bool enable);
void EditBoxSetEnhanced(HWND hWnd, UINT id, bool enable);
void AllowFGWindow(UINT process_id);
HWND SearchWindow(wchar_t *caption);
char *RemoteDlg(HWND hWnd, char *regkey, UINT icon, wchar_t *caption, wchar_t *title, char *default_host);
LIST *ReadCandidateFromReg(UINT root, char *key, char *name);
void WriteCandidateToReg(UINT root, char *key, LIST *o, char *name);
UINT LvGetColumnNum(HWND hWnd, UINT id);
void LvSetItemParamEx(HWND hWnd, UINT id, UINT index, UINT subitem, void *param);
void LvSortEx(HWND hWnd, UINT id, UINT subitem, bool desc, bool numeric);
void LvSort(HWND hWnd, UINT id, UINT subitem, bool desc);
void *LvGetParamEx(HWND hWnd, UINT id, UINT index, UINT subitem);
void LvSortHander(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT id);
void LvStandardHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT id);
void IpSet(HWND hWnd, UINT id, UINT ip);
UINT IpGet(HWND hWnd, UINT id);
bool IpIsFilled(HWND hWnd, UINT id);
UINT IpGetFilledNum(HWND hWnd, UINT id);
void About(HWND hWnd, CEDAR *cedar, wchar_t *product_name);
void AboutEx(HWND hWnd, CEDAR *cedar, wchar_t *product_name, WINUI_UPDATE *u);
wchar_t *StringDlg(HWND hWnd, wchar_t *title, wchar_t *info, wchar_t *def, UINT icon, bool allow_empty, bool allow_unsafe);
char *StringDlgA(HWND hWnd, wchar_t *title, wchar_t *info, char *def, UINT icon, bool allow_empty, bool allow_unsafe);
UINT StringDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void InitDialogInternational(HWND hWnd, void *pparam);
void AdjustWindowAndControlSize(HWND hWnd, bool *need_resize, double *factor_x, double *factor_y);
void AdjustDialogXY(UINT *x, UINT *y, UINT dlgfont_x, UINT dlgfont_y);
HFONT GetDialogDefaultFont();
HFONT GetDialogDefaultFontEx(bool meiryo);
void InitMenuInternational(HMENU hMenu, char *prefix);
void InitMenuInternationalUni(HMENU hMenu, char *prefix);
void ShowTcpIpConfigUtil(HWND hWnd, bool util_mode);
void ShowCpu64Warning();
UINT Cpu64DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT TcpIpDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void TcpIpDlgInit(HWND hWnd);
void TcpIpDlgUpdate(HWND hWnd);
UINT TcpMsgDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void ShowEasterEgg(HWND hWnd);
bool Win32CnCheckAlreadyExists(bool lock);
void RegistWindowsFirewallAll();
void RegistWindowsFirewallAllEx(char *dir);
void InitVistaWindowTheme(HWND hWnd);
void OnceMsg(HWND hWnd, wchar_t *title, wchar_t *message, bool show_checkbox, UINT icon);
void OnceMsgEx(HWND hWnd, wchar_t *title, wchar_t *message, bool show_checkbox, UINT icon, bool *halt);
UINT GetOnceMsgHash(wchar_t *title, wchar_t *message);
UINT OnceMsgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool CheckBadProcesses(HWND hWnd);
BAD_PROCESS *IsBadProcess(char *exe);
void ShowBadProcessWarning(HWND hWnd, BAD_PROCESS *bad);
void SetFontMeiryo(HWND hWnd, UINT id, UINT font_size);
char *GetMeiryoFontName();
void SetFontDefault(HWND hWnd, UINT id);
HFONT GetMeiryoFont();
HFONT GetMeiryoFontEx(UINT font_size);
HFONT GetMeiryoFontEx2(UINT font_size, bool bold);
bool ShowWindowsNetworkConnectionDialog();
SOCK *WinConnectEx3(HWND hWnd, char *server, UINT port, UINT timeout, UINT icon_id, wchar_t *caption, wchar_t *info, UINT *nat_t_error_code, char *nat_t_svc_name, bool try_start_ssl);
SOCK *WinConnectEx4(HWND hWnd, char *server, UINT port, UINT timeout, UINT icon_id, wchar_t *caption, wchar_t *info, UINT *nat_t_error_code, char *nat_t_svc_name, bool try_start_ssl, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err, char *hint_str);
UINT WinConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void WinConnectDlgThread(THREAD *thread, void *param);
void NicInfo(UI_NICINFO *info);
UINT NicInfoProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NicInfoInit(HWND hWnd, UI_NICINFO *info);
void NicInfoOnTimer(HWND hWnd, UI_NICINFO *info);
void NicInfoRefresh(HWND hWnd, UI_NICINFO *info);
void NicInfoShowStatus(HWND hWnd, UI_NICINFO *info, wchar_t *msg1, wchar_t *msg2, UINT icon, bool animate);
void NicInfoCloseAfterTime(HWND hWnd, UI_NICINFO *info, UINT tick);

WIZARD *NewWizard(UINT icon, UINT bitmap, wchar_t *caption, void *param);
void FreeWizard(WIZARD *w);
WIZARD_PAGE *NewWizardPage(UINT id, WINUI_WIZARD_PROC *proc, wchar_t *title);
void FreeWizardPage(WIZARD_PAGE *p);
void AddWizardPage(WIZARD *w, WIZARD_PAGE *p);
WIZARD_PAGE *GetWizardPage(WIZARD *w, UINT id);
void *CreateWizardPageInstance(WIZARD *w, WIZARD_PAGE *p);
void ShowWizard(HWND hWndParent, WIZARD *w, UINT start_id);
void SetWizardButton(WIZARD_PAGE *p, bool enable_next, bool enable_back, bool enable_close, bool is_finish);
void SetWizardButtonEx(WIZARD_PAGE *p, bool enable_next, bool enable_back, bool enable_close, bool is_finish, bool shield_icon);
void JumpWizard(WIZARD_PAGE *p, UINT next_id);
void CloseWizard(WIZARD_PAGE *p);
void SetUacIcon(HWND hWnd, UINT id);

LIST *NewBitmapList();
void FreeBitmapList(LIST *o);

bool GetBitmapSize(void *bmp, UINT *x, UINT *y);

bool GetFontParam(HFONT hFont, FONT *f);
void AdjustFontSize(HWND hWnd, UINT id);
bool IsFontFitInRect(struct FONT *f, UINT width, UINT height, wchar_t *text, UINT format, bool *aborted);

void ShowTextFile(HWND hWnd, char *filename, wchar_t *caption, UINT icon);

#endif // WINUI_H

#endif // OS_WIN32
