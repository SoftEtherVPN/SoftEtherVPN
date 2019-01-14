// SoftEther VPN Source Code - Developer Edition Master Branch
// Windows Filtering Platform Callout Driver for Capturing IPsec Packets on Windows Vista / 7 / Server 2008


// Wfp.h
// Header File for WFP Callout Driver

#ifndef	WFP_H
#define	WFP_H

// Identify string
#define	WFP_DEVICE_NAME				L"\\Device\\PXWFP_DEVICE"
#define	WFP_DEVICE_NAME_WIN32		L"\\DosDevices\\PXWFP_DEVICE"
#define	WFP_DEVICE_FILE_NAME		"\\\\.\\PXWFP_DEVICE"
#define	WFP_EVENT_NAME				L"\\BaseNamedObjects\\PXWFP_EVENT"
#define	WFP_EVENT_NAME_WIN32		"Global\\PXWFP_EVENT"

// PXWFP Callout Driver
// {4E6F16C5-C266-440a-9382-22E7B1AA4411}
DEFINE_GUID(GUID_WFP_CALLOUT_DRIVER_V4,
			0x4e6f16c5, 0xc266, 0x440a, 0x93, 0x82, 0x22, 0xe7, 0xb1, 0xaa, 0x44, 0x11);
// {CAE3EC1F-E2F9-4b07-B910-1467E223E55E}
DEFINE_GUID(GUID_WFP_CALLOUT_DRIVER_V6, 
			0xcae3ec1f, 0xe2f9, 0x4b07, 0xb9, 0x10, 0x14, 0x67, 0xe2, 0x23, 0xe5, 0x5e);

// PXWFP Filter for IPsec
// {4FB80D9C-B3D3-433c-B707-9D6EDE3A9493}
//DEFINE_GUID(GUID_WFP_FILTER, 
//			0x4fb80d9c, 0xb3d3, 0x433c, 0xb7, 0x7, 0x9d, 0x6e, 0xde, 0x3a, 0x94, 0x94);

// WFP local IP address
typedef struct WFP_LOCAL_IP
{
	UINT IpVersion;
	UINT Padding;
	union
	{
		UCHAR IPv4Address[4];
		UCHAR IPv6Address[16];
	} IpAddress;
} WFP_LOCAL_IP;


#endif	// WFP_H


