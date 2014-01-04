#pragma once
#include "resource.h"
#include <atlctl.h>
#include "vpnweb.h"
#include "vpnwebdlg.h"

#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
#error "DCOM is not supported."
#endif


// CVpnWebControl
class ATL_NO_VTABLE CVpnWebControl :
	public CComObjectRootEx<CComSingleThreadModel>,
	public IDispatchImpl<IVpnWebControl, &IID_IVpnWebControl, &LIBID_vpnwebLib, /*wMajor =*/ 1, /*wMinor =*/ 0>,
	public IPersistStreamInitImpl<CVpnWebControl>,
	public IOleControlImpl<CVpnWebControl>,
	public IOleObjectImpl<CVpnWebControl>,
	public IOleInPlaceActiveObjectImpl<CVpnWebControl>,
	public IViewObjectExImpl<CVpnWebControl>,
	public IOleInPlaceObjectWindowlessImpl<CVpnWebControl>,
	public ISupportErrorInfo,
	public IPersistStorageImpl<CVpnWebControl>,
	public IPersistPropertyBagImpl<CVpnWebControl>,
	public ISpecifyPropertyPagesImpl<CVpnWebControl>,
	public IQuickActivateImpl<CVpnWebControl>,
	public IObjectSafetyImpl<CVpnWebControl, INTERFACESAFE_FOR_UNTRUSTED_CALLER | INTERFACESAFE_FOR_UNTRUSTED_DATA>,
#ifndef _WIN32_WCE
	public IDataObjectImpl<CVpnWebControl>,
#endif
	public IProvideClassInfo2Impl<&CLSID_VpnWebControl, NULL, &LIBID_vpnwebLib>,
#ifdef _WIN32_WCE
	public IObjectSafetyImpl<CVpnWebControl, INTERFACESAFE_FOR_UNTRUSTED_CALLER>,
#endif
	public CComCoClass<CVpnWebControl, &CLSID_VpnWebControl>,
	public CComControl<CVpnWebControl>
{
public:

	HWND hDlg;

	CVpnWebControl()
	{
		hDlg = NULL;
		SIZE dlgSize;

		GetVpnWebDlgSize(&dlgSize);

		m_bWindowOnly = TRUE;
		m_bAutoSize = TRUE;
		m_bRecomposeOnResize = TRUE;
		m_bResizeNatural = TRUE;

		setSize(dlgSize.cx, dlgSize.cy);
	}

	DECLARE_OLEMISC_STATUS(OLEMISC_RECOMPOSEONRESIZE |
	OLEMISC_CANTLINKINSIDE |
		OLEMISC_INSIDEOUT |
		OLEMISC_ACTIVATEWHENVISIBLE |
		OLEMISC_SETCLIENTSITEFIRST
		)

		DECLARE_REGISTRY_RESOURCEID(IDR_VPNWEBCONTROL)


	BEGIN_COM_MAP(CVpnWebControl)
		COM_INTERFACE_ENTRY(IVpnWebControl)
		COM_INTERFACE_ENTRY(IDispatch)
		COM_INTERFACE_ENTRY(IViewObjectEx)
		COM_INTERFACE_ENTRY(IViewObject2)
		COM_INTERFACE_ENTRY(IViewObject)
		COM_INTERFACE_ENTRY(IOleInPlaceObjectWindowless)
		COM_INTERFACE_ENTRY(IOleInPlaceObject)
		COM_INTERFACE_ENTRY2(IOleWindow, IOleInPlaceObjectWindowless)
		COM_INTERFACE_ENTRY(IOleInPlaceActiveObject)
		COM_INTERFACE_ENTRY(IOleControl)
		COM_INTERFACE_ENTRY(IOleObject)
		COM_INTERFACE_ENTRY(IPersistStreamInit)
		COM_INTERFACE_ENTRY(IPersistPropertyBag)
		COM_INTERFACE_ENTRY2(IPersist, IPersistStreamInit)
		COM_INTERFACE_ENTRY(ISupportErrorInfo)
		COM_INTERFACE_ENTRY(ISpecifyPropertyPages)
		COM_INTERFACE_ENTRY(IQuickActivate)
		COM_INTERFACE_ENTRY(IPersistStorage)
		COM_INTERFACE_ENTRY(IObjectSafety)
#ifndef _WIN32_WCE
		COM_INTERFACE_ENTRY(IDataObject)
#endif
		COM_INTERFACE_ENTRY(IProvideClassInfo)
		COM_INTERFACE_ENTRY(IProvideClassInfo2)
#ifdef _WIN32_WCE
		COM_INTERFACE_ENTRY_IID(IID_IObjectSafety, IObjectSafety)
#endif
	END_COM_MAP()

	BEGIN_PROP_MAP(CVpnWebControl)
		//PROP_DATA_ENTRY("_cx", m_sizeExtent.cx, VT_UI4)
		//PROP_DATA_ENTRY("_cy", m_sizeExtent.cy, VT_UI4)
		PROP_ENTRY("InstallerExeUrl", 1, CVpnWebControl::GetObjectCLSID())
		PROP_ENTRY("InstallerInfUrl", 2, CVpnWebControl::GetObjectCLSID())
		PROP_ENTRY("SettingUrl", 3, CVpnWebControl::GetObjectCLSID())
		PROP_ENTRY("VpnServerManagerMode", 4, CVpnWebControl::GetObjectCLSID())
		PROP_ENTRY("VpnServerHostname", 5, CVpnWebControl::GetObjectCLSID())
		PROP_ENTRY("VpnServerHubName", 6, CVpnWebControl::GetObjectCLSID())
		PROP_ENTRY("VpnServerPassword", 7, CVpnWebControl::GetObjectCLSID())

		PROP_ENTRY("LanguageID", 8, CVpnWebControl::GetObjectCLSID())
		PROP_ENTRY("LanguageID", 9, CVpnWebControl::GetObjectCLSID())

	END_PROP_MAP()


	BEGIN_MSG_MAP(CVpnWebControl)
		MESSAGE_HANDLER(WM_CREATE, OnCreate)
		CHAIN_MSG_MAP(CComControl<CVpnWebControl>)
		DEFAULT_REFLECTION_HANDLER()
	END_MSG_MAP()
	//  LRESULT MessageHandler(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	//  LRESULT CommandHandler(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled);
	//  LRESULT NotifyHandler(int idCtrl, LPNMHDR pnmh, BOOL& bHandled);

	// ISupportsErrorInfo
	STDMETHOD(InterfaceSupportsErrorInfo)(REFIID riid)
	{
		static const IID* arr[] =
		{
			&IID_IVpnWebControl,
		};

		for (int i=0; i<sizeof(arr)/sizeof(arr[0]); i++)
		{
			if (InlineIsEqualGUID(*arr[i], riid))
				return S_OK;
		}
		return S_FALSE;
	}
/*
	// IObjectSafety
	STDMETHOD(SetInterfaceSafetyOptions)(REFIID riid, DWORD dwSupportedOptions, DWORD dwEnabledOptions)
	{
		if (riid == IID_IPersistPropertyBag)
		{
			if (dwEnabledOptions != INTERFACESAFE_FOR_UNTRUSTED_CALLER)
			{
				return E_FAIL;
			}
			return S_OK;
		}
		return IObjectSafetyImpl<CVpnWebControl,
			INTERFACESAFE_FOR_UNTRUSTED_CALLER>::SetInterfaceSafetyOptions(riid,
			dwSupportedOptions, dwEnabledOptions);
	}*/

	// IViewObjectEx
	DECLARE_VIEW_STATUS(0)

	void setSize(UINT width, UINT height)
	{
		SIZEL src;

		ZeroMemory(&src, sizeof(src));

		src.cx = width;
		src.cy = height;

		AtlPixelToHiMetric(&src, &m_sizeNatural);
		AtlPixelToHiMetric(&src, &m_sizeExtent);
	}

private:
	CComBSTR m_installer_exe_url, m_installer_inf_url, m_setting_url,
		m_vpnserver_manager_mode, m_vpnserver_hostname, m_vpnserver_hubname,
		m_vpnserver_password;
	CComBSTR m_language_id;

	// IVpnWebControl
public:
	LRESULT OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		RECT rc;
		GetWindowRect(&rc);
		rc.right -= rc.left;
		rc.bottom -= rc.top;
		rc.top = rc.left = 0;

		VPNWEBDLG_INIT init;
		ZeroMemory(&init, sizeof(init));
		init.hControlWnd = m_hWnd;

		CW2A installer_exe_url(m_installer_exe_url);
		CW2A installer_inf_url(m_installer_inf_url);
		CW2A setting_url(m_setting_url);
		CW2A vpnserver_manager_mode(m_vpnserver_manager_mode);
		CW2A vpnserver_hostname(m_vpnserver_hostname);
		CW2A vpnserver_hubname(m_vpnserver_hubname);
		CW2A vpnserver_password(m_vpnserver_password);
		CW2A language_id(m_language_id);

		if (installer_exe_url != NULL)
		{
			if (lstrlen(installer_exe_url) <= 256)
			{
				lstrcpy(init.InstallerExeUrl, installer_exe_url);
			}
		}

		if (installer_inf_url != NULL)
		{
			if (lstrlen(installer_inf_url) <= 256)
			{
				lstrcpy(init.InstallerInfUrl, installer_inf_url);
			}
		}

		if (setting_url != NULL)
		{
			if (lstrlen(setting_url) <= 256)
			{
				lstrcpy(init.SettingUrl, setting_url);
			}
		}

		if (vpnserver_manager_mode != NULL)
		{
			init.VpnServerManagerMode = (BOOL)strtod(vpnserver_manager_mode, NULL);
		}

		if( m_language_id!=NULL ){
			if (lstrlen(language_id) <= 32)
			{
				lstrcpy(init.LanguageId, language_id);
			}			
		}
		if (init.VpnServerManagerMode)
		{
			if (vpnserver_hostname != NULL)
			{
				if (lstrlen(vpnserver_hostname) <= 256)
				{
					lstrcpy(init.VpnServerHostname, vpnserver_hostname);
				}
			}

			if (vpnserver_hubname != NULL)
			{
				if (lstrlen(vpnserver_hubname) <= 256)
				{
					lstrcpy(init.VpnServerHubName, vpnserver_hubname);
				}
			}

			if (vpnserver_password != NULL)
			{
				if (lstrlen(vpnserver_password) <= 256)
				{
					lstrcpy(init.VpnServerPassword, vpnserver_password);
				}
			}
		}

		hDlg = InitVpnWebDlg(&init);

		return 0;
	}

	HRESULT OnDraw(ATL_DRAWINFO& di)
	{
		return S_OK;
	}


	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	void FinalRelease()
	{
		FreeVpnWebDlg();
	}

	STDMETHODIMP get_InstallerExeUrl(BSTR* pVal)
	{
		*pVal = m_installer_exe_url.Copy();
		return S_OK;
	}

	STDMETHODIMP put_InstallerExeUrl(BSTR newVal)
	{
		m_installer_exe_url = newVal;
		return S_OK;
	}

	STDMETHODIMP get_InstallerInfUrl(BSTR* pVal)
	{
		*pVal = m_installer_inf_url.Copy();
		return S_OK;
	}

	STDMETHODIMP put_InstallerInfUrl(BSTR newVal)
	{
		m_installer_inf_url = newVal;
		return S_OK;
	}

	STDMETHODIMP get_SettingUrl(BSTR* pVal)
	{
		*pVal = m_setting_url.Copy();
		return S_OK;
	}

	STDMETHODIMP put_SettingUrl(BSTR newVal)
	{
		m_setting_url = newVal;
		return S_OK;
	}

	STDMETHODIMP get_VpnServerManagerMode(BSTR* pVal)
	{
		*pVal = m_vpnserver_manager_mode.Copy();
		return S_OK;
	}

	STDMETHODIMP put_VpnServerManagerMode(BSTR newVal)
	{
		m_vpnserver_manager_mode = newVal;
		return S_OK;
	}

	STDMETHODIMP get_VpnServerHostname(BSTR* pVal)
	{
		*pVal = m_vpnserver_hostname.Copy();
		return S_OK;
	}

	STDMETHODIMP put_VpnServerHostname(BSTR newVal)
	{
		m_vpnserver_hostname = newVal;
		return S_OK;
	}

	STDMETHODIMP get_VpnServerHubName(BSTR* pVal)
	{
		*pVal = m_vpnserver_hubname.Copy();
		return S_OK;
	}

	STDMETHODIMP put_VpnServerHubName(BSTR newVal)
	{
		m_vpnserver_hubname = newVal;
		return S_OK;
	}

	STDMETHODIMP get_VpnServerPassword(BSTR* pVal)
	{
		*pVal = m_vpnserver_password.Copy();
		return S_OK;
	}

	STDMETHODIMP put_VpnServerPassword(BSTR newVal)
	{
		m_vpnserver_password = newVal;
		return S_OK;
	}

	STDMETHODIMP get_LanguageID(BSTR* pVal)
	{
		*pVal = m_language_id.Copy();
		return S_OK;
	}

	STDMETHODIMP put_LanguageID(BSTR newVal)
	{
		m_language_id = newVal;
		return S_OK;
	}
};

OBJECT_ENTRY_AUTO(__uuidof(VpnWebControl), CVpnWebControl)
