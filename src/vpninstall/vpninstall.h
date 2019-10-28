// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpninstall.h
// Header of vpninstall.c

#ifndef	VPNINSTALL_H
#define	VPNINSTALL_H

// Constants
#define	VI_INF_FILENAME				"vpninstall.inf"
#define VI_INSTANCE_NAME			"VpnAutoInstaller"
#define	WM_VI_SETPOS				(WM_APP + 41)
#define WM_VI_SETTEXT				(WM_APP + 42)
#define WM_VI_CANCEL				(WM_APP + 43)
#define WM_VI_DOWNLOAD_FINISHED		(WM_APP + 44)
#define MESSAGE_OFFSET_JP  IDS_TITLE
#define MESSAGE_OFFSET_EN  IDS_TITLE_EN

// Macro
#define _U(id)		(ViGetString(id))
#define	_A(id)		(ViGetStringA(id))


// Type declaration
typedef struct VI_STRING
{
	UINT Id;
	wchar_t *String;
	char *StringA;
} VI_STRING;

typedef struct VI_SETTING_ARCH
{
	bool Supported;
	UINT Build;
	char Path[MAX_SIZE];
	char VpnCMgrExeFileName[MAX_PATH];
	bool CurrentInstalled;
	wchar_t CurrentInstalledPathW[MAX_PATH];
	UINT CurrentInstalledBuild;
} VI_SETTING_ARCH;

typedef struct VI_SETTING
{
	UINT VpnInstallBuild;
	VI_SETTING_ARCH x86;
	char SettingPath[MAX_SIZE];
	wchar_t DownloadedSettingPathW[MAX_PATH];
	wchar_t DownloadedInstallerPathW[MAX_PATH];
	bool DownloadNotRequired;
	bool WebMode;
	bool NormalMode;
} VI_SETTING;

typedef struct VI_INSTALL_DLG
{
	HWND hWnd;
	bool DownloadStarted;
	THREAD *DownloadThread;
	bool DialogCanceling;
	UINT BufSize;
	void *Buf;
	bool Halt;
	bool NoClose;
	bool WindowsShutdowning;
} VI_INSTALL_DLG;

typedef struct VI_FILE
{
	bool InternetFile;
	UINT FileSize;
	HINTERNET hInternet;
	HINTERNET hHttpFile;
	UINT IoReadFileSize;
	IO *io;
} VI_FILE;

typedef struct VI_DOWNLOAD_FILE
{
	char SrcPath[MAX_SIZE];
	char FileName[MAX_PATH];
	wchar_t DestPathW[MAX_SIZE];
} VI_DOWNLOAD_FILE;

// Function prototype
int main(int argc, char *argv[]);
void ViLoadStringTables();
void ViFreeStringTables();
wchar_t *ViLoadString(HINSTANCE hInst, UINT id);
char *ViLoadStringA(HINSTANCE hInst, UINT id);
int ViCompareString(void *p1, void *p2);
wchar_t *ViGetString(UINT id);
char *ViGetStringA(UINT id);
void ViMain();
bool ViLoadInf(VI_SETTING *set, char *filename);
bool ViLoadInfFromBuf(VI_SETTING *set, BUF *buf);
void ViLoadCurrentInstalledStates();
void ViLoadCurrentInstalledStatusForArch(VI_SETTING_ARCH *a);
bool ViMsiGetProductInfo(char *product_code, char *name, char *buf, UINT size);
UINT ViVersionStrToBuild(char *str);
VI_SETTING_ARCH *ViGetSuitableArchForCpu();
void ViInstallDlg();
UINT ViInstallDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void ViInstallDlgOnInit(HWND hWnd, VI_INSTALL_DLG *d);
void ViInstallDlgOnStart(HWND hWnd, VI_INSTALL_DLG *d);
void ViInstallDlgOnClose(HWND hWnd, VI_INSTALL_DLG *d);
VI_FILE *ViOpenFile(char *path);
UINT ViGetFileSize(VI_FILE *f);
UINT ViReadFile(VI_FILE *f, void *buf, UINT size);
void ViCloseFile(VI_FILE *f);
bool ViIsInternetFile(char *path);
void ViDownloadThreadStart(VI_INSTALL_DLG *d);
void ViDownloadThreadStop(VI_INSTALL_DLG *d);
void ViDownloadThread(THREAD *thread, void *param);
void ViInstallDlgSetPos(HWND hWnd, UINT pos);
void ViInstallDlgSetText(VI_INSTALL_DLG *d, HWND hWnd, UINT id,wchar_t *text);
void ViInstallDlgCancel(HWND hWnd);
void ViInstallProcessStart(HWND hWnd, VI_INSTALL_DLG *d);
bool ViExtractCabinetFile(char *exe, char *cab);
wchar_t *ViExtractEula(char *exe);
BUF *ViExtractResource(char *exe, char *type, char *name);
bool ViEulaDlg(HWND hWnd, wchar_t *text);
UINT ViEulaDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool ViCheckExeSign(HWND hWnd, wchar_t *exew);
char *ViUrlToFileName(char *url);
void ViGenerateVpnSMgrTempDirName(char *name, UINT size, UINT build);
void ViSetSkip();

#endif	// VPNINSTALL_H

