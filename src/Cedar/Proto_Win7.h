// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_Win7.h
// Header of Proto_Win7.c

#ifndef	PROTO_WIN7_H
#define	PROTO_WIN7_H

// Constants
#define	IPSEC_WIN7_SRC_SYS_X86	"|pxwfp_x86.sys"
#define	IPSEC_WIN7_SRC_SYS_X64	"|pxwfp_x64.sys"
#define	IPSEC_WIN7_DST_SYS		"%s\\drivers\\pxwfp.sys"

#define	IPSEC_WIN7_DRIVER_NAME			"pxwfp"
#define	IPSEC_WIN7_DRIVER_TITLE			L"SoftEther PacketiX VPN IPsec WFP Callout Driver"
#define	IPSEC_WIN7_DRIVER_TITLE_V4		L"SoftEther PacketiX VPN IPsec WFP Callout for IPv4"
#define	IPSEC_WIN7_DRIVER_TITLE_V6		L"SoftEther PacketiX VPN IPsec WFP Callout for IPv6"
#define	IPSEC_WIN7_FILTER_TITLE_V4		CEDAR_PRODUCT_STR_W L" VPN IPsec Filter for IPv4"
#define	IPSEC_WIN7_FILTER_TITLE_V6		CEDAR_PRODUCT_STR_W L" VPN IPsec Filter for IPv6"
#define	IPSEC_WIN7_DRIVER_REGKEY		"SYSTEM\\CurrentControlSet\\services\\pxwfp"
#define	IPSEC_WIN7_DRIVER_BUILDNUMBER	"CurrentInstalledBuild"
#define	IPSEC_WIN7_DRIVER_BUILDNUMBER_WIN10	"CurrentInstalledBuild_Win10"


// Function prototype
IPSEC_WIN7 *IPsecWin7Init();
void IPsecWin7Free(IPSEC_WIN7 *w);
void IPsecWin7UpdateHostIPAddressList(IPSEC_WIN7 *w);

bool IPsecWin7InitDriver();
bool IPsecWin7InitDriverInner();
UINT GetCurrentIPsecWin7DriverBuild();
void SetCurrentIPsecWin7DriverBuild();
bool IPsecWin7InitApi();


#endif	// PROTO_WIN7_H
