// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Win32Com.c
// Win32 COM module call

#include <GlobalConst.h>

#ifdef	WIN32

#define	WIN32COM_CPP

#define _WIN32_DCOM

//#define	_WIN32_WINNT		0x0502
//#define	WINVER				0x0502
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <Wbemidl.h>
#include <comdef.h>
#include <Mshtmhst.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <iphlpapi.h>
#include <Natupnp.h>
#include <devguid.h>
#include <regstr.h>
#include <cfgmgr32.h>
#include <tchar.h>
#include <objbase.h>
#include <Setupapi.h>
#include "netcfgn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
extern "C"
{
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
}
#include "../PenCore/resource.h"

// Add a UPnP port
bool Win32UPnPAddPort(UINT outside_port, UINT inside_port, bool udp, char *local_ip, wchar_t *description, bool remove_before_add)
{
	bool ret = false;
	HRESULT hr;
	IUPnPNAT *nat = NULL;
	wchar_t ip_str[MAX_SIZE];
	BSTR bstr_ip, bstr_description, bstr_protocol;
	const wchar_t *protocol_str = (udp ? L"UDP" : L"TCP");
	// Validate arguments
	if (outside_port == 0 || outside_port >= 65536 || inside_port == 0 || inside_port >= 65536 ||
		IsEmptyStr(local_ip) || UniIsEmptyStr(description))
	{
		return false;
	}

	StrToUni(ip_str, sizeof(ip_str), local_ip);
	bstr_ip = SysAllocString(ip_str);
	bstr_description = SysAllocString(description);
	bstr_protocol = SysAllocString(protocol_str);

	hr = CoCreateInstance(CLSID_UPnPNAT, NULL, CLSCTX_INPROC_SERVER, IID_IUPnPNAT, (void **)&nat);

	if (SUCCEEDED(hr))
	{
		if (nat != NULL)
		{
			IStaticPortMappingCollection *collection = NULL;
			hr = nat->get_StaticPortMappingCollection(&collection);

			if (SUCCEEDED(hr))
			{
				if (collection != NULL)
				{
					IStaticPortMapping *mapping = NULL;

					if (remove_before_add)
					{
						hr = collection->Remove((long)outside_port, bstr_protocol);
					}

					hr = collection->Add((long)outside_port, bstr_protocol, (long)inside_port,
						bstr_ip, VARIANT_TRUE, bstr_description, &mapping);

					if (SUCCEEDED(hr))
					{
						ret = true;

						if (mapping != NULL)
						{
							mapping->Release();
						}
					}

					collection->Release();
				}
				else
				{
					WHERE;
				}
			}
			else
			{
				WHERE;
			}

			nat->Release();
		}
		else
		{
			WHERE;
		}
	}
	else
	{
		WHERE;
	}

	SysFreeString(bstr_ip);
	SysFreeString(bstr_description);
	SysFreeString(bstr_protocol);

	return ret;
}

// Install the NDIS protocol driver
bool UninstallNdisProtocolDriver(wchar_t *id, UINT lock_timeout)
{
	bool ret = false;
	HRESULT hr;
	INetCfg *pNetCfg;
	// Validate arguments
	if (id == NULL)
	{
		return false;
	}

	hr = CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, IID_INetCfg, (void **)&pNetCfg);

	if (SUCCEEDED(hr))
	{
		INetCfgLock *pLock;

		hr = pNetCfg->QueryInterface(IID_INetCfgLock, (PVOID*)&pLock);

		if (SUCCEEDED(hr))
		{
			LPWSTR locked_by;

			hr = pLock->AcquireWriteLock(lock_timeout, L"SoftEther VPN", &locked_by);

			if (SUCCEEDED(hr))
			{
				hr = pNetCfg->Initialize(NULL);

				if (SUCCEEDED(hr))
				{
					INetCfgComponent *pncc = NULL;

					hr = pNetCfg->FindComponent(id, &pncc);

					if (pncc == NULL || hr == S_FALSE)
					{
						hr = E_FAIL;
					}

					if (SUCCEEDED(hr))
					{
						INetCfgClass *pncClass;

						hr = pNetCfg->QueryNetCfgClass(&GUID_DEVCLASS_NETTRANS, IID_INetCfgClass, (void **)&pncClass);
						if (SUCCEEDED(hr))
						{
							INetCfgClassSetup *pncClassSetup;

							hr = pncClass->QueryInterface(IID_INetCfgClassSetup, (void **)&pncClassSetup);
							if (SUCCEEDED(hr))
							{
								OBO_TOKEN obo;
								wchar_t *c = NULL;

								Zero(&obo, sizeof(obo));

								obo.Type = OBO_USER;

								hr = pncClassSetup->DeInstall(pncc, &obo, &c);

								if (SUCCEEDED(hr))
								{
									hr = pNetCfg->Apply();

									if (SUCCEEDED(hr))
									{
										ret = true;
									}
									else
									{
										WHERE;
										Debug("0x%x\n", hr);
									}
								}
								else
								{
									WHERE;
									Debug("0x%x\n", hr);
								}

								pncClassSetup->Release();
							}
							else
							{
								WHERE;
							}

							pncClass->Release();
						}
						else
						{
							WHERE;
						}

						pncc->Release();
					}
					else
					{
						WHERE;
					}
				}
				else
				{
					WHERE;
				}

				pLock->ReleaseWriteLock();
			}
			else
			{
				WHERE;
			}

			pLock->Release();
		}

		pNetCfg->Release();
	}
	else
	{
		WHERE;
	}

	return ret;
}

// Install the NDIS protocol driver
bool InstallNdisProtocolDriver(wchar_t *inf_path, wchar_t *id, UINT lock_timeout)
{
	bool ret = false;
	HRESULT hr;
	INetCfg *pNetCfg;
	HINSTANCE hSetupApiDll = NULL;
	BOOL (WINAPI *_SetupCopyOEMInfW)(PCWSTR, PCWSTR, DWORD, DWORD, PWSTR, DWORD, PDWORD, PWSTR *) = NULL;
	BOOL (WINAPI *_SetupUninstallOEMInfW)(PCWSTR, DWORD, PVOID) = NULL;
	// Validate arguments
	if (inf_path == NULL || id == NULL)
	{
		return false;
	}

	hSetupApiDll = LoadLibraryA("setupapi.dll");
	if (hSetupApiDll == NULL)
	{
		WHERE;
		goto LABEL_CLEANUP;
	}

	_SetupCopyOEMInfW =
		(UINT (__stdcall *)(PCWSTR,PCWSTR,DWORD,DWORD,PWSTR,DWORD,PDWORD,PWSTR *))
		GetProcAddress(hSetupApiDll, "SetupCopyOEMInfW");

	_SetupUninstallOEMInfW =
		(UINT (__stdcall *)(PCWSTR,DWORD,PVOID))
		GetProcAddress(hSetupApiDll, "SetupUninstallOEMInfW");

	if (_SetupCopyOEMInfW == NULL || _SetupUninstallOEMInfW == NULL)
	{
		WHERE;
		goto LABEL_CLEANUP;
	}

	hr = CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_INPROC_SERVER, IID_INetCfg, (void **)&pNetCfg);

	if (SUCCEEDED(hr))
	{
		INetCfgLock *pLock;

		hr = pNetCfg->QueryInterface(IID_INetCfgLock, (PVOID*)&pLock);

		if (SUCCEEDED(hr))
		{
			LPWSTR locked_by;

			hr = pLock->AcquireWriteLock(lock_timeout, L"SoftEther VPN", &locked_by);

			if (SUCCEEDED(hr))
			{
				hr = pNetCfg->Initialize(NULL);

				if (SUCCEEDED(hr))
				{
					wchar_t inf_dir[MAX_PATH];

					GetDirNameFromFilePathW(inf_dir, sizeof(inf_dir), inf_path);

					if (_SetupCopyOEMInfW(inf_path, inf_dir, SPOST_PATH, 0, NULL, 0, NULL, 0))
					{
						INetCfgClassSetup *pSetup;

						hr = pNetCfg->QueryNetCfgClass(&GUID_DEVCLASS_NETTRANS, IID_INetCfgClassSetup, (void **)&pSetup);

						if (SUCCEEDED(hr))
						{
							OBO_TOKEN token;
							INetCfgComponent *pComponent;

							Zero(&token, sizeof(token));

							token.Type = OBO_USER;

							hr = pSetup->Install(id, &token, 0, 0, NULL, NULL, &pComponent);

							if (SUCCEEDED(hr))
							{
								pNetCfg->Apply();

								ret = true;
							}
							else
							{
								WHERE;
								Debug("0x%x\n", hr);
							}

							pSetup->Release();
						}
						else
						{
							WHERE;
						}

						if (ret == false)
						{
							wchar_t dst_inf_name[MAX_PATH];
							DWORD dst_inf_name_size = MAX_PATH;

							if (_SetupCopyOEMInfW(inf_path, inf_dir, SPOST_PATH, SP_COPY_REPLACEONLY,
								dst_inf_name, dst_inf_name_size, &dst_inf_name_size, NULL) == false &&
								GetLastError() == ERROR_FILE_EXISTS)
							{
								_SetupUninstallOEMInfW(dst_inf_name, 0, NULL);
							}
						}
					}
					else
					{
						WHERE;
					}
				}
				else
				{
					WHERE;
				}

				pLock->ReleaseWriteLock();
			}
			else
			{
				WHERE;
			}

			pLock->Release();
		}

		pNetCfg->Release();
	}
	else
	{
		WHERE;
	}

LABEL_CLEANUP:

	if (hSetupApiDll != NULL)
	{
		FreeLibrary(hSetupApiDll);
	}

	return ret;
}

typedef struct FOLDER_DLG_INNER_DATA
{
	wchar_t *default_dir;
} FOLDER_DLG_INNER_DATA;

int CALLBACK FolderDlgInnerCallbackA(HWND hWnd, UINT msg, LPARAM lParam, LPARAM lData)
{
	FOLDER_DLG_INNER_DATA *data = (FOLDER_DLG_INNER_DATA *)lData;
	LPITEMIDLIST pidl;

	switch (msg)
	{
	case BFFM_INITIALIZED:
		if (data->default_dir != NULL)
		{
			char *default_dir_a = CopyUniToStr(data->default_dir);

			SendMessage(hWnd, BFFM_SETSELECTIONA, true, (LPARAM)default_dir_a);

			Free(default_dir_a);
		}
		break;

	case BFFM_SELCHANGED:
		pidl = (LPITEMIDLIST)lParam;

		if (pidl)
		{
			char tmp[MAX_PATH];

			Zero(tmp, sizeof(tmp));
			if (SHGetPathFromIDListA(pidl, tmp))
			{
				SendMessage(hWnd, BFFM_ENABLEOK, 0, 1);
			}
			else
			{
				SendMessage(hWnd, BFFM_ENABLEOK, 0, 0);
			}
		}
		break;
	}

	return 0;
}

char *FolderDlgInnerA(HWND hWnd, wchar_t *title, char *default_dir)
{
	BROWSEINFOA info;
	char display_name[MAX_PATH];
	FOLDER_DLG_INNER_DATA data;
	LPMALLOC pMalloc;
	char *ret = NULL;
	char *title_a;
	if (UniIsEmptyStr(title))
	{
		title = NULL;
	}
	if (IsEmptyStr(default_dir))
	{
		default_dir = NULL;
	}

	Zero(&data, sizeof(data));
	data.default_dir = CopyStrToUni(default_dir);

	Zero(display_name, sizeof(display_name));
	Zero(&info, sizeof(info));
	info.hwndOwner = hWnd;
	info.pidlRoot = NULL;
	info.pszDisplayName = display_name;
	title_a = CopyUniToStr(title);
	info.lpszTitle = title_a;
	info.ulFlags = BIF_NEWDIALOGSTYLE | BIF_RETURNONLYFSDIRS | BIF_VALIDATE | BIF_SHAREABLE;
	info.lpfn = FolderDlgInnerCallbackA;
	info.lParam = (LPARAM)&data;

	if (SUCCEEDED(SHGetMalloc(&pMalloc)))
	{
		LPITEMIDLIST pidl;

		pidl = SHBrowseForFolderA(&info);

		if (pidl)
		{
			char tmp[MAX_PATH];

			if (SHGetPathFromIDListA(pidl, tmp))
			{
				ret = CopyStr(tmp);
			}

			pMalloc->Free(pidl);
		}

		pMalloc->Release();
	}

	Free(data.default_dir);
	Free(title_a);

	return ret;
}

int CALLBACK FolderDlgInnerCallbackW(HWND hWnd, UINT msg, LPARAM lParam, LPARAM lData)
{
	FOLDER_DLG_INNER_DATA *data = (FOLDER_DLG_INNER_DATA *)lData;
	LPITEMIDLIST pidl;

	switch (msg)
	{
	case BFFM_INITIALIZED:
		if (data->default_dir != NULL)
		{
			SendMessage(hWnd, BFFM_SETSELECTIONW, true, (LPARAM)data->default_dir);
		}
		break;

	case BFFM_SELCHANGED:
		pidl = (LPITEMIDLIST)lParam;

		if (pidl)
		{
			wchar_t tmp[MAX_PATH];

			Zero(tmp, sizeof(tmp));
			if (SHGetPathFromIDListW(pidl, tmp))
			{
				SendMessage(hWnd, BFFM_ENABLEOK, 0, 1);
			}
			else
			{
				SendMessage(hWnd, BFFM_ENABLEOK, 0, 0);
			}
		}
		break;
	}

	return 0;
}

wchar_t *FolderDlgInnerW(HWND hWnd, wchar_t *title, wchar_t *default_dir)
{
	BROWSEINFOW info;
	wchar_t display_name[MAX_PATH];
	FOLDER_DLG_INNER_DATA data;
	LPMALLOC pMalloc;
	wchar_t *ret = NULL;
	if (UniIsEmptyStr(title))
	{
		title = NULL;
	}
	if (UniIsEmptyStr(default_dir))
	{
		default_dir = NULL;
	}

	Zero(&data, sizeof(data));
	data.default_dir = default_dir;

	Zero(display_name, sizeof(display_name));
	Zero(&info, sizeof(info));
	info.hwndOwner = hWnd;
	info.pidlRoot = NULL;
	info.pszDisplayName = display_name;
	info.lpszTitle = title;
	info.ulFlags = BIF_NEWDIALOGSTYLE | BIF_RETURNONLYFSDIRS | BIF_VALIDATE | BIF_SHAREABLE;
	info.lpfn = FolderDlgInnerCallbackW;
	info.lParam = (LPARAM)&data;

	if (SUCCEEDED(SHGetMalloc(&pMalloc)))
	{
		LPITEMIDLIST pidl;

		pidl = SHBrowseForFolderW(&info);

		if (pidl)
		{
			wchar_t tmp[MAX_PATH];

			if (SHGetPathFromIDListW(pidl, tmp))
			{
				ret = CopyUniStr(tmp);
			}

			pMalloc->Free(pidl);
		}

		pMalloc->Release();
	}

	return ret;
}


class CModule
{
public:
    CModule()
    {
        m_hInstLib = NULL;
    }
    CModule( HINSTANCE hInstLib )
    {
        m_hInstLib = NULL;
        this->Attach( hInstLib );
    }
    CModule( LPCTSTR pszModuleName )
    {
        m_hInstLib = NULL;
        this->LoadLibrary( pszModuleName );
    }
    virtual ~CModule()
    {
        this->FreeLibrary();
    }

public:
    BOOL Attach( HINSTANCE hInstLib )
    {
        this->FreeLibrary();
        m_hInstLib = hInstLib;
       
        return TRUE;
    }
    BOOL Detach()
    {
        m_hInstLib = NULL;
       
        return TRUE;
    }

public:
    HMODULE GetHandle()
    {
        return m_hInstLib;
    }
    // Load the DLL
    HINSTANCE LoadLibrary( LPCTSTR pszModuleName )
    {
        this->FreeLibrary();
        m_hInstLib = ::LoadLibrary( pszModuleName );
       
        return m_hInstLib;
    }
    // Release the DLL
    BOOL FreeLibrary()
    {
        if (m_hInstLib == NULL)
        {
            return FALSE;
        }
       
        BOOL bResult = ::FreeLibrary( m_hInstLib );
        m_hInstLib = NULL;
       
        return bResult;
    }
    // Get the address of the function
    FARPROC GetProcAddress( LPCTSTR pszProcName )
    {
        if (m_hInstLib == NULL)
        {
            return NULL;
        }
       
        return ::GetProcAddress(m_hInstLib, pszProcName);
    }
    // Get a handle to the information block of resource with the specified name and the type
    HRSRC FindResource(LPCTSTR lpName, LPCTSTR lpType)
    {
        if (m_hInstLib == NULL)
        {
            return NULL;
        }
       
        return ::FindResource(m_hInstLib, lpName, lpType);
    }
    // Load the specified resource
    HGLOBAL LoadResource(HRSRC hResInfo)
    {
        if (m_hInstLib == NULL)
        {
            return NULL;
        }
       
        return ::LoadResource(m_hInstLib, hResInfo);
    }

protected:
    HINSTANCE m_hInstLib;
};



static HRESULT _ShowHTMLDialog(
    HWND hwndParent,
    IMoniker* pMk,
    VARIANT* pvarArgIn = NULL,
    WCHAR* pchOptions = NULL,
    VARIANT* pvarArgOut = NULL)
{
    HRESULT hr = S_OK;
   
    try
    {
        CModule Module("MSHTML.DLL");
        if (Module.GetHandle() == NULL)
        {
            return E_FAIL;
        }
       
        SHOWHTMLDIALOGFN* fnShowHTMLDialog =
            (SHOWHTMLDIALOGFN*)Module.GetProcAddress("ShowHTMLDialog");
        if (fnShowHTMLDialog == NULL)
        {
            return E_FAIL;
        }
       
        hr = (*fnShowHTMLDialog)(hwndParent, pMk, pvarArgIn, pchOptions, pvarArgOut);
        if (FAILED(hr))
        {
            return hr;
        }
    }
    catch (...)
    {
        return E_FAIL;
    }
   
    return hr;
}

HRESULT ShowHTMLDialogFromURL(HWND hwndParent,wchar_t *szURL,VARIANT* pvarArgIn,WCHAR* pchOptions,VARIANT* pvarArgOut)
{
    HRESULT hr = S_OK;
   
    try
    {
        IMonikerPtr spMoniker;
        hr = ::CreateURLMoniker(NULL, szURL, &spMoniker);
        if (FAILED(hr))
        {
            return hr;
        }
       
        hr = ::_ShowHTMLDialog(hwndParent, spMoniker, pvarArgIn, pchOptions, pvarArgOut);
        if (FAILED(hr))
        {
            return hr;
        }
    }
    catch (...)
    {
        return E_FAIL;
    }
   
    return hr;
}

// Create a shortcut
bool CreateLinkInnerA(char *filename, char *target, char *workdir, char *args,
				     char *comment, char *icon, UINT icon_index)
{
	HRESULT r;
	wchar_t tmp[MAX_SIZE];
	IShellLinkA* pShellLink;
	IPersistFile* pPersistFile;

	r = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkA, (void **)&pShellLink);
	if (FAILED(r))
	{
		return false;
	}

	r = pShellLink->QueryInterface(IID_IPersistFile,(void **)&pPersistFile);
	if (FAILED(r))
	{
		pShellLink->Release();
		return false;
	}

	r = pShellLink->SetPath(target);
	if (FAILED(r))
	{
		pShellLink->Release();
		pPersistFile->Release();
		return false;
	}

	if (workdir != NULL)
	{
		r = pShellLink->SetWorkingDirectory(workdir);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (args != NULL)
	{
		r = pShellLink->SetArguments(args);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (comment != NULL)
	{
		r = pShellLink->SetDescription(comment);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (icon != NULL)
	{
		r = pShellLink->SetIconLocation(icon, icon_index);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	StrToUni(tmp, sizeof(tmp), filename);
	r = pPersistFile->Save(tmp, true);
	if (FAILED(r))
	{
		pShellLink->Release();
		pPersistFile->Release();
		return false;
	}

	pShellLink->Release();
	pPersistFile->Release();
	return true;
}
bool CreateLinkInner(wchar_t *filename, wchar_t *target, wchar_t *workdir, wchar_t *args,
				     wchar_t *comment, wchar_t *icon, UINT icon_index)
{
	HRESULT r;
	bool ret;
	IShellLinkW* pShellLink;
	IPersistFile* pPersistFile;

	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType))
	{
		char *a1, *a2, *a3, *a4, *a5, *a6;
		a1 = CopyUniToStr(filename);
		a2 = CopyUniToStr(target);
		a3 = CopyUniToStr(workdir);
		a4 = CopyUniToStr(args);
		a5 = CopyUniToStr(icon);
		a6 = CopyUniToStr(comment);

		ret = CreateLinkInnerA(a1, a2, a3, a4, a6, a5, icon_index);

		Free(a1);
		Free(a2);
		Free(a3);
		Free(a4);
		Free(a5);
		Free(a6);

		return ret;
	}

	r = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void **)&pShellLink);
	if (FAILED(r))
	{
		return false;
	}

	r = pShellLink->QueryInterface(IID_IPersistFile,(void **)&pPersistFile);
	if (FAILED(r))
	{
		pShellLink->Release();
		return false;
	}

	r = pShellLink->SetPath(target);
	if (FAILED(r))
	{
		pShellLink->Release();
		pPersistFile->Release();
		return false;
	}

	if (workdir != NULL)
	{
		r = pShellLink->SetWorkingDirectory(workdir);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (comment != NULL)
	{
		r = pShellLink->SetDescription(comment);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (args != NULL)
	{
		r = pShellLink->SetArguments(args);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	if (icon != NULL)
	{
		r = pShellLink->SetIconLocation(icon, icon_index);
		if (FAILED(r))
		{
			pShellLink->Release();
			pPersistFile->Release();
			return false;
		}
	}

	r = pPersistFile->Save(filename, true);
	if (FAILED(r))
	{
		pShellLink->Release();
		pPersistFile->Release();
		return false;
	}

	pShellLink->Release();
	pPersistFile->Release();
	return true;
}

extern "C"
{

// Show the folder selection dialog
wchar_t *FolderDlgW(HWND hWnd, wchar_t *title, wchar_t *default_dir)
{
	wchar_t *ret;

	if (MsIsNt() == false)
	{
		char *default_dir_a = CopyUniToStr(default_dir);
		char *ret_a = FolderDlgA(hWnd, title, default_dir_a);

		ret = CopyStrToUni(ret_a);
		Free(ret_a);
		Free(default_dir_a);

		return ret;
	}

	ret = FolderDlgInnerW(hWnd, title, default_dir);

	return ret;
}
char *FolderDlgA(HWND hWnd, wchar_t *title, char *default_dir)
{
	char *ret;

	ret = FolderDlgInnerA(hWnd, title, default_dir);

	return ret;
}

// Create a shortcut
bool CreateLink(wchar_t *filename, wchar_t *target, wchar_t *workdir, wchar_t *args,
				wchar_t *comment, wchar_t *icon, UINT icon_index)
{
	if (filename == NULL || target == NULL)
	{
		return false;
	}

	return CreateLinkInner(filename, target, workdir, args, comment, icon, icon_index);
}

// Show the HTML
void ShowHtml(HWND hWnd, char *url, wchar_t *option)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (url == NULL || option == NULL)
	{
		return;
	}

	StrToUni(tmp, sizeof(tmp), url);

	ShowHTMLDialogFromURL(hWnd, tmp, NULL, option, NULL);
}

}

#endif
