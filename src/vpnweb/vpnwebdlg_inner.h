// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpnwebdlg.h
// Header of vpnwebdlg.c (Inner)


#define	VPNINSTALL_EXE_FILENAME		"vpninstall.exe"
#define	VPNINSTALL_EXE_FILENAME_TMP	"vpninstall.exe.tmp"
#define VPNINSTALL_INF_FILENAME		"vpninstall.inf"
#define VPNINSTALL_INF_BUILDTAG		"VpnInstallBuild"

#include "resource.h"
extern HINSTANCE hDllInstance;
#define MESSAGE_OFFSET_JP  IDS_MESSAGE_APPTITLE
#define MESSAGE_OFFSET_EN  IDS_MESSAGE_APPTITLE_EN
#define MESSAGE_OFFSET_RES1 12000
#define MESSAGE_OFFSET_RES2 13000

static wchar_t *msgAppTitle = NULL;
static char *msgNotSupported = NULL;
static wchar_t *msgInfDownload = NULL;
static wchar_t *msgInfDownloadFailed = NULL;
static wchar_t *msgBadInfFile = NULL;
static wchar_t *msgWriteFailed = NULL;
static wchar_t *msgDownloading = NULL;
static wchar_t *msgProcessFailed = NULL;
static wchar_t *msgProcessCreating =NULL;
static wchar_t *msgProcessCreated = NULL;
static wchar_t *msgWarning = NULL;
static wchar_t *msgWarningTitle = NULL;
static wchar_t *msgUserCancel = NULL;
static wchar_t *msgStartTextForVpnServer = NULL;
static wchar_t *msgButtonForVpnServer = NULL;
static wchar_t *msgProcessCreatedForVpnServer = NULL;
static wchar_t *msgStartTextForVpnClient = NULL;
static wchar_t *msgButtonForVpnClient = NULL;
static char *msgNoParam = NULL;

static void **_messages;

typedef enum MessageType {
	_e_msgAppTitle,_e_msgNotSupported,_e_msgInfDownload,_e_msgInfDownloadFailed,
	_e_msgBadInfFile,_e_msgWriteFailed,_e_msgDownloading,_e_msgProcessFailed,
	_e_msgProcessCreating,_e_msgProcessCreated,_e_msgWarning,_e_msgWarningTitle,
	_e_msgUserCancel,_e_msgStartTextForVpnServer,_e_msgButtonForVpnServer,_e_msgProcessCreatedForVpnServer,
	_e_msgNoParam, _e_msgStartTextForVpnClient, _e_msgButtonForVpnClient, _e_msgEnd} MessageType_t;

	int currentPage=MESSAGE_OFFSET_EN;

int GetLocalizedMessageOffset(){
	return currentPage;
}
wchar_t *LoadMessageW(enum MessageType e){
	wchar_t *pTmp=(wchar_t*)calloc(sizeof(wchar_t),1024);
	LoadStringW(hDllInstance,GetLocalizedMessageOffset()+e,pTmp,1024);
	return pTmp;
}
char *LoadMessageA(enum MessageType e){
	char *pTmp=(char*)calloc(sizeof(char),1024);
	LoadStringA(hDllInstance,GetLocalizedMessageOffset()+e,pTmp,1024);
	return pTmp;
}
void FreeMessage(void *p){
	free(p);
}
int LoadTables(char *pTag){
	if( stricmp(pTag,"JP")==0 || stricmp(pTag,"JA")==0){
		currentPage=MESSAGE_OFFSET_JP;
		
	}else if( stricmp(pTag,"EN")==0)
	{
		currentPage=MESSAGE_OFFSET_EN;
	}
//		currentPage=MESSAGE_OFFSET_EN;

	msgAppTitle=LoadMessageW(_e_msgAppTitle);
	msgNotSupported=LoadMessageA(_e_msgNotSupported);
	msgInfDownload=LoadMessageW(_e_msgInfDownload);
	msgInfDownloadFailed=LoadMessageW(_e_msgInfDownloadFailed);
	msgBadInfFile=LoadMessageW(_e_msgBadInfFile);
	msgWriteFailed=LoadMessageW(_e_msgWriteFailed);
	msgDownloading=LoadMessageW(_e_msgDownloading);
	msgProcessFailed=LoadMessageW(_e_msgProcessFailed);
	msgProcessCreating=LoadMessageW(_e_msgProcessCreating);
	msgProcessCreated=LoadMessageW(_e_msgProcessCreated);
	msgWarning=LoadMessageW(_e_msgWarning);
	msgWarningTitle=LoadMessageW(_e_msgWarningTitle);
	msgUserCancel=LoadMessageW(_e_msgUserCancel);
	msgStartTextForVpnServer=LoadMessageW(_e_msgStartTextForVpnServer);
	msgButtonForVpnServer=LoadMessageW(_e_msgButtonForVpnServer);
	msgProcessCreatedForVpnServer=LoadMessageW(_e_msgProcessCreatedForVpnServer);
	msgNoParam=LoadMessageA(_e_msgNoParam);
	msgStartTextForVpnClient=LoadMessageW(_e_msgStartTextForVpnClient);
	msgButtonForVpnClient=LoadMessageW(_e_msgButtonForVpnClient);
	return 0;

}

#define false		0
#define true		1
#define	bool		UINT
#define MAX_SIZE	512

typedef struct VW_FILE
{
	UINT FileSize;
	HINTERNET hInternet;
	HINTERNET hHttpFile;
} VW_FILE;

typedef struct VW_TASK
{
	HANDLE Thread;
	bool Halt;
} VW_TASK;


INT_PTR CALLBACK VpnWebDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK VpnWebDummyDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

void VwOnInit(HWND hWnd);
void VwOnFree(HWND hWnd);
HANDLE VwNewThread(LPTHREAD_START_ROUTINE start, void *param);
void VwFreeThread(HANDLE h);
void VwCloseFile(VW_FILE *f);
UINT VwReadFile(VW_FILE *f, void *buf, UINT size);
UINT VwGetFileSize(VW_FILE *f);
VW_FILE *VwOpenFile(char *path);
void VwPrint(HWND hWnd, wchar_t *str);
DWORD CALLBACK VwTaskThread(void *param);
char *VwUrlToFileName(char *url);
UINT VwGetBuildFromVpnInstallInf(char *buf);
bool VwCheckFileDigitalSignature(HWND hWnd, char *name, bool *danger);
bool VwCheckExeSign(HWND hWnd, char *exe);

void *ZeroMalloc(UINT size);
void Free(void *p);
void *ReAlloc(void *p, UINT size);
void Zero(void *p, UINT size);
HANDLE FileCreate(char *name);
HANDLE FileOpen(char *name, bool write_mode);
void FileClose(HANDLE h);
bool FileRead(HANDLE h, void *buf, UINT size);
bool FileWrite(HANDLE h, void *buf, UINT size);
UINT64 FileSize(HANDLE h);
bool MakeDir(char *name);
UINT MsgBox(HWND hWnd, UINT flag, wchar_t *msg);
void Hide(HWND hWnd, UINT id);
void Show(HWND hWnd, UINT id);
void SetShow(HWND hWnd, UINT id, bool b);
bool IsShow(HWND hWnd, UINT id);
bool IsHide(HWND hWnd, UINT id);
void RemoveExStyle(HWND hWnd, UINT id, UINT style);
void SetExStyle(HWND hWnd, UINT id, UINT style);
UINT GetExStyle(HWND hWnd, UINT id);
void RemoveStyle(HWND hWnd, UINT id, UINT style);
void SetStyle(HWND hWnd, UINT id, UINT style);
UINT GetStyle(HWND hWnd, UINT id);
void Refresh(HWND hWnd);
void DoEvents(HWND hWnd);
void Disable(HWND hWnd, UINT id);
void Enable(HWND hWnd, UINT id);
void SetEnable(HWND hWnd, UINT id, bool b);
bool IsDisable(HWND hWnd, UINT id);
bool IsEnable(HWND hWnd, UINT id);
HWND DlgItem(HWND hWnd, UINT id);
bool IsSupportedOs();
void SetText(HWND hWnd, UINT id, wchar_t *str);
UINT SendMsg(HWND hWnd, UINT id, UINT msg, WPARAM wParam, LPARAM lParam);
void SetRange(HWND hWnd, UINT id, UINT start, UINT end);
void SetPos(HWND hWnd, UINT id, UINT pos);


