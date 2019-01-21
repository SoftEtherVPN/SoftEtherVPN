// SoftEther VPN Source Code - Developer Edition Master Branch
// Global Constants Header

#pragma warning(disable : 4819)

#ifndef	GLOBAL_CONST_H
#define	GLOBAL_CONST_H

//// Brand
// (Define it if building SoftEther VPN Project.)
#define	GC_SOFTETHER_VPN
#define	GC_SOFTETHER_OSS

//// Basic Variables

#define	CEDAR_PRODUCT_STR			"SoftEther"
#define	CEDAR_PRODUCT_STR_W			L"SoftEther"
#define	CEDAR_SERVER_STR			"SoftEther VPN Server Developer Edition"
#define	CEDAR_BRIDGE_STR			"SoftEther VPN Bridge Developer Edition"
#define	CEDAR_BETA_SERVER			"SoftEther VPN Server Pre Release Developer Edition"
#define	CEDAR_MANAGER_STR			"SoftEther VPN Server Manager Developer Edition"
#define	CEDAR_CUI_STR				"SoftEther VPN Command-Line Admin Tool"
#define CEDAR_ELOG					"SoftEther EtherLogger Developer Edition"
#define	CEDAR_CLIENT_STR			"SoftEther VPN Client Developer Edition"
#define CEDAR_CLIENT_MANAGER_STR	"SoftEther VPN Client Connection Manager Developer Edition"
#define	CEDAR_ROUTER_STR			"SoftEther VPN User-mode Router Developer Edition"
#define	CEDAR_SERVER_LINK_STR		"SoftEther VPN Server Developer Edition (Cascade Mode)"
#define	CEDAR_BRIDGE_LINK_STR		"SoftEther VPN Bridge Developer Edition (Cascade Mode)"
#define	CEDAR_SERVER_FARM_STR		"SoftEther VPN Server Developer Edition (Cluster RPC Mode)"



//// Default Port Number

#define	GC_DEFAULT_PORT		5555
#define	GC_CLIENT_CONFIG_PORT	9931
#define	GC_CLIENT_NOTIFY_PORT	9984


//// Software Name

#define	GC_SVC_NAME_VPNSERVER		"SEVPNSERVERDEV"
#define	GC_SVC_NAME_VPNCLIENT		"SEVPNCLIENTDEV"
#define	GC_SVC_NAME_VPNBRIDGE		"SEVPNBRIDGEDEV"



//// Registry

#define	GC_REG_COMPANY_NAME			"SoftEther VPN Developer Edition"




//// Setup Wizard

#define	GC_SW_UIHELPER_REGVALUE		"SoftEther VPN Client UI Helper Developer Edition"
#define	GC_SW_SOFTETHER_PREFIX		"sedev"
#define	GC_SW_SOFTETHER_PREFIX_W	L"sedev"



//// VPN UI Components

#define	GC_UI_APPID_CM				L"SoftEther.SoftEther VPN Client Developer Edition"



#endif	// GLOBAL_CONST_H

