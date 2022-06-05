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

#define	CEDAR_PRODUCT_STR			"Unite Gaming"
#define	CEDAR_PRODUCT_STR_W			L"Unite Gaming"
#define	CEDAR_SERVER_STR			"Unite Gaming Game Server"
#define	CEDAR_BRIDGE_STR			"Unite Gaming Game Bridge"
#define	CEDAR_BETA_SERVER			"Unite Gaming Game Server"
#define	CEDAR_MANAGER_STR			"Unite Gaming Game Server Manager"
#define	CEDAR_CUI_STR				"Unite Gaming Game Command-Line Admin Tool"
#define CEDAR_ELOG					"Unite Gaming EtherLogger"
#define	CEDAR_CLIENT_STR			"Unite Gaming Game Client Developer Edition"
#define CEDAR_CLIENT_MANAGER_STR	"Unite Gaming Game Client Connection Manager Developer Edition"
#define	CEDAR_ROUTER_STR			"Unite Gaming Game User-mode Router"
#define	CEDAR_SERVER_LINK_STR		"Unite Gaming Game Server (Cascade Mode)"
#define	CEDAR_BRIDGE_LINK_STR		"Unite Gaming Game Bridge (Cascade Mode)"
#define	CEDAR_SERVER_FARM_STR		"Unite Gaming Game Server (Cluster RPC Mode)"



//// Default Port Number

#define	GC_DEFAULT_PORT		5555
#define	GC_CLIENT_CONFIG_PORT	9931
#define	GC_CLIENT_NOTIFY_PORT	9984


//// Software Name

#define	GC_SVC_NAME_VPNSERVER		"SEVPNSERVERDEV"
#define	GC_SVC_NAME_VPNCLIENT		"SEVPNCLIENTDEV"
#define	GC_SVC_NAME_VPNBRIDGE		"SEVPNBRIDGEDEV"



//// Registry

#define	GC_REG_COMPANY_NAME			"Unite Gaming Game"




//// Setup Wizard

#define	GC_SW_UIHELPER_REGVALUE		"Unite Gaming Game Client UI Helper Developer Edition"
#define	GC_SW_SOFTETHER_PREFIX		"ug"
#define	GC_SW_SOFTETHER_PREFIX_W	L"ug"



//// VPN UI Components

#define	GC_UI_APPID_CM				L"UniteGaming.Unite Gaming Game Client"

#endif	// GLOBAL_CONST_H
