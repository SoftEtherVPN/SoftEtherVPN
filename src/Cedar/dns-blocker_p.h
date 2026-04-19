// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// dns-blocker_p.h
// Private header of dns-blocker.cpp

#ifdef OS_WIN32

#ifndef DNSBLOCKER_P_H
#define DNSBLOCKER_P_H


#include "dns-blocker.h"

extern "C" {
#include "Proto_Win7.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Microsoft.h"
}

#include <Iphlpapi.h>
#include <objbase.h>
#include <ntstatus.h>


typedef NTSTATUS (WINAPI *ConvertInterfaceIndexToLuidPtr)(
	NET_IFINDEX InterfaceIndex,
	PNET_LUID InterfaceLuid
	);

typedef ULONG (WINAPI *GetAdaptersInfoPtr)(
	PIP_ADAPTER_INFO AdapterInfo,
	PULONG SizePointer
	);


#define DNSBLOCKER_LAYER_NAME_W CEDAR_PRODUCT_STR_W

// {067724c0-4cbb-a153-ccad-c87a0b6cb12a} => is MD5 of "SoftEtherDnsBlocker"
DEFINE_GUID( DnsBlockerGuid
	, 0x067724c0, 0x4cbb, 0xa153
	, 0xcc, 0xad, 0xc8, 0x7a, 0x0b, 0x6c, 0xb1, 0x2a);


class DnsBlockerPrivate {
public:
	DnsBlockerPrivate()
		: api(NULL), engine(NULL)
	{
	}

	~DnsBlockerPrivate()
	{
		// We don't really own the `api`, else would do:
		// ```
		// auto oldApi = this->api;
		// this->api = NULL;
		// ::free(oldApi);
		// ::FreeLibrary(ipLibrary);
		// ipLibrary = NULL;
		// ```
	}

	IP_ADAPTER_INFO *getAdapters() const;

public:
	/// Windows Filtering Platform.
	IPSEC_WIN7_FUNCTIONS *api;
	HANDLE engine;

	static HINSTANCE ipLibrary;
	static ConvertInterfaceIndexToLuidPtr convertInterfaceIndexToLuid;
	static GetAdaptersInfoPtr getAdaptersInfo;
};

#endif // DNSBLOCKER_P_H

#endif // OS_WIN32
