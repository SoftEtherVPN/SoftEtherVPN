// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// vpnwebdlg.h
// Header of vpnwebdlg.c

#ifndef VPNWEBDLG_H
#define VPNWEBDLG_H


#ifdef __cplusplus
extern "C" {
#endif

extern HINSTANCE hDllInstance;

typedef struct VPNWEBDLG_INIT
{
	char InstallerExeUrl[512];
	char InstallerInfUrl[512];
	char SettingUrl[512];
	BOOL VpnServerManagerMode;
	char VpnServerHostname[512];
	char VpnServerHubName[512];
	char VpnServerPassword[512];
	
	char LanguageId[32];
	HWND hControlWnd;
	HWND hWnd;
} VPNWEBDLG_INIT;

HWND InitVpnWebDlg(VPNWEBDLG_INIT *init);
void FreeVpnWebDlg();
void GetVpnWebDlgSize(SIZE *size);


#ifdef __cplusplus
}
#endif

#endif	// VPNWEBDLG_H
