// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// CM.h
// Header of CM.c

#ifndef	CM_H
#define	CM_H

// Constants
#define	CM_REG_KEY			"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Client Manager"
#define	SECURE_MANAGER_KEY	"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\SmartCard Manager"
#define	CM_TRAFFIC_REG_KEY	"Software\\" GC_REG_COMPANY_NAME "\\" CEDAR_PRODUCT_STR " VPN\\Traffic Test Tool"
#define	CM_VGC_REG_KEY		"Software\\University of Tsukuba\\VPN Gate Client Plugin"


#define	CM_TRY_EXEC_UI_HELPER_INTERVAL		5000

#define	CM_DEFAULT_WIDTH	800
#define	CM_DEFAULT_HEIGHT	600

#define	WM_CM_NOTIFY		(WM_APP + 999)

#define	CM_IMPORT_FILENAME_MSG	1267
#define	CM_IMPORT_FILENAME_MSG_OVERWRITE	1268

#define	CM_NUM_RECENT		8

#define	PUBLIC_SERVER_HTML	"http://www.softether.com/jp/special/se2hub.aspx"
#define PUBLIC_SERVER_HTML_EN "http://www.softether.com/jp/special/se2hub_en.aspx"
#define	PUBLIC_SERVER_TAG	L"help:no; status:no; DialogWidth:600px; dialogHeight=700px"
#define	PUBLIC_SERVER_NAME	"public.softether.com"

#define	VOICE_SSK			0	// ssk
#define	VOICE_AHO			1	// aho

// The code for external export

// Structure

// Function prototype
void CMExec();
void CmTraffic(HWND hWnd);
void *CmStartUacHelper();
void CmStopUacHelper(void *p);
void *CmExecUiHelperMain();
UINT CmGetSecureBitmapId(char *dest_hostname);

#endif	// CM_H


