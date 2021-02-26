// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_Win7Inner.h
// Internal header of Proto_Win7.c

#ifndef	PROTO_WIN7_INNER_H
#define	PROTO_WIN7_INNER_H

// API function
typedef struct IPSEC_WIN7_FUNCTIONS
{
	DWORD (WINAPI *FwpmEngineOpen0)(
		IN OPTIONAL const wchar_t* serverName,
		IN UINT32 authnService,
		IN OPTIONAL SEC_WINNT_AUTH_IDENTITY_W* authIdentity,
		IN OPTIONAL const FWPM_SESSION0* session,
		OUT HANDLE* engineHandle
		);

	DWORD (WINAPI *FwpmEngineClose0)(IN HANDLE engineHandle);

	void (WINAPI *FwpmFreeMemory0)(IN OUT void** p);

	DWORD (WINAPI *FwpmFilterAdd0)(
		IN HANDLE engineHandle,
		IN const FWPM_FILTER0* filter,
		IN OPTIONAL PSECURITY_DESCRIPTOR sd,
		OUT OPTIONAL UINT64* id
		);

	DWORD (WINAPI *IPsecSaContextCreate0)(
		IN HANDLE engineHandle,
		IN const IPSEC_TRAFFIC0* outboundTraffic,
		OUT OPTIONAL UINT64* inboundFilterId,
		OUT UINT64* id
		);

	DWORD (WINAPI *IPsecSaContextGetSpi0)(
		IN HANDLE engineHandle,
		IN UINT64 id,
		IN const IPSEC_GETSPI0* getSpi,
		OUT IPSEC_SA_SPI* inboundSpi
		);

	DWORD (WINAPI *IPsecSaContextAddInbound0)(
		IN HANDLE engineHandle,
		IN UINT64 id,
		IN const IPSEC_SA_BUNDLE0* inboundBundle
		);

	DWORD (WINAPI *IPsecSaContextAddOutbound0)(
		IN HANDLE engineHandle,
		IN UINT64 id,
		IN const IPSEC_SA_BUNDLE0* outboundBundle
		);

	DWORD (WINAPI *FwpmCalloutAdd0)(
		IN HANDLE engineHandle,
		IN const FWPM_CALLOUT0* callout,
		IN OPTIONAL PSECURITY_DESCRIPTOR sd,
		OUT OPTIONAL UINT32* id
		);

} IPSEC_WIN7_FUNCTIONS;

// Instance
struct IPSEC_WIN7
{
	HANDLE hEngine;
	HANDLE hDriverFile;
	UINT64 FilterIPv4Id, FilterIPv6Id;
};


#endif	// PROTO_WIN7_INNER_H
