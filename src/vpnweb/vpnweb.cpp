#include "stdafx.h"
#include "resource.h"
#include "vpnweb.h"

extern "C" {
HINSTANCE hDllInstance;
}


class CvpnwebModule : public CAtlDllModuleT< CvpnwebModule >
{
public :
	DECLARE_LIBID(LIBID_vpnwebLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_VPNWEB, "{7CE8BF01-70D6-48F6-A83A-69CA03D885C9}")
};

CvpnwebModule _AtlModule;


#ifdef _MANAGED
#pragma managed(push, off)
#endif

extern "C" BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	hDllInstance = hInstance;
    return _AtlModule.DllMain(dwReason, lpReserved); 
}

#ifdef _MANAGED
#pragma managed(pop)
#endif




STDAPI DllCanUnloadNow(void)
{
    return _AtlModule.DllCanUnloadNow();
}


STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    return _AtlModule.DllGetClassObject(rclsid, riid, ppv);
}


STDAPI DllRegisterServer(void)
{
    HRESULT hr = _AtlModule.DllRegisterServer();
	return hr;
}


STDAPI DllUnregisterServer(void)
{
	HRESULT hr = _AtlModule.DllUnregisterServer();
	return hr;
}

