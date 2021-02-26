// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// NMInner.h
// The internal header of NM.c


// Constants
#define	NM_REG_KEY			"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\User-mode Router Manager"
#define	NM_SETTING_REG_KEY	"Software\\" GC_REG_COMPANY_NAME "\\PacketiX VPN\\User-mode Router Manager\\Settings"

#define	NM_REFRESH_TIME			1000
#define	NM_NAT_REFRESH_TIME		1000
#define	NM_DHCP_REFRESH_TIME	1000

// Nat Admin structure
typedef struct NM
{
	CEDAR *Cedar;				// Cedar
} NM;

// Connection structure
typedef struct NM_CONNECT
{
	RPC *Rpc;					// RPC
	char *Hostname;
	UINT Port;
} NM_CONNECT;

// Login
typedef struct NM_LOGIN
{
	char *Hostname;
	UINT Port;
	UCHAR hashed_password[SHA1_SIZE];
} NM_LOGIN;

// Internal function
void InitNM();
void FreeNM();
void MainNM();
RPC *NmConnect(char *hostname, UINT port);
UINT NmConnectDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
UINT NmLogin(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmMainDlg(RPC *r);
UINT NmMainDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmMainDlgInit(HWND hWnd, RPC *r);
void NmMainDlgRefresh(HWND hWnd, RPC *r);
void NmEditClientConfig(HWND hWnd, RPC *r);
void NmEditVhOption(HWND hWnd, SM_HUB *r);
UINT NmEditVhOptionProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmEditVhOptionInit(HWND hWnd, SM_HUB *r);
void NmEditVhOptionUpdate(HWND hWnd, SM_HUB *r);
void NmEditVhOptionOnOk(HWND hWnd, SM_HUB *r);
void NmEditVhOptionFormToVH(HWND hWnd, VH_OPTION *t);
bool NmStatus(HWND hWnd, SM_SERVER *s, void *param);
bool NmInfo(HWND hWnd, SM_SERVER *s, void *param);
void NmNat(HWND hWnd, SM_HUB *r);
UINT NmNatProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmNatInit(HWND hWnd, SM_HUB *r);
void NmNatRefresh(HWND hWnd, SM_HUB *r);
void NmDhcp(HWND hWnd, SM_HUB *r);
UINT NmDhcpProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
void NmDhcpRefresh(HWND hWnd, SM_HUB *r);
void NmDhcpInit(HWND hWnd, SM_HUB *r);
void NmChangePassword(HWND hWnd, RPC *r);
UINT NmChangePasswordProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);
bool NmEditPushRoute(HWND hWnd, SM_HUB *r);
UINT NmEditPushRouteProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, void *param);


