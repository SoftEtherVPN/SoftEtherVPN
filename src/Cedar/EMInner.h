// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// EMInner.h
// Inner header of EM.c

// Constants
#define	EM_REG_KEY			"Software\\" GC_REG_COMPANY_NAME "\\EtherLogger\\Manager"

// Inner structure
typedef struct EM_ADD
{
	RPC *Rpc;
	bool NewMode;
	char DeviceName[MAX_SIZE];
} EM_ADD;

// Inner functions
void EMMain(RPC *r);
UINT EmMainDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void EmMainInit(HWND hWnd, RPC *r);
void EmMainUpdate(HWND hWnd, RPC *r);
void EmMainRefresh(HWND hWnd, RPC *r);
void EmAdd(HWND hWnd, RPC *r, char *device_name);
UINT EmAddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void EmAddInit(HWND hWnd, EM_ADD *p);
void EmDlgToHubLog(HWND hWnd, HUB_LOG *g);
void EmHubLogToDlg(HWND hWnd, HUB_LOG *g);
void EmAddOk(HWND hWnd, EM_ADD *p);
void EmAddUpdate(HWND hWnd, EM_ADD *p);
UINT EmPasswordDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT EmLicenseDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void EmLicenseDlgInit(HWND hWnd, RPC *s);
void EmLicenseDlgRefresh(HWND hWnd, RPC *s);
void EmLicenseDlgUpdate(HWND hWnd, RPC *s);
bool EmLicenseAdd(HWND hWnd, RPC *s);
UINT EmLicenseAddDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void EmLicenseAddDlgInit(HWND hWnd, RPC *s);
void EmLicenseAddDlgUpdate(HWND hWnd, RPC *s);
void EmLicenseAddDlgShiftTextItem(HWND hWnd, UINT id1, UINT id2, UINT *next_focus);
void EmLicenseAddDlgGetText(HWND hWnd, char *str, UINT size);
void EmLicenseAddDlgOnOk(HWND hWnd, RPC *s);
