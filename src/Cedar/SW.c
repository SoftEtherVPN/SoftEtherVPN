// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// SW.c
// Setup Wizard for Win32

#include <GlobalConst.h>

#ifdef	WIN32

#define	SM_C
#define	CM_C
#define	NM_C
#define	SW_C

#define	_WIN32_WINNT		0x0502
#define	WINVER				0x0502
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "CMInner.h"
#include "SMInner.h"
#include "NMInner.h"
#include "EMInner.h"
#include "SWInner.h"
#include "../PenCore/resource.h"

//// Old MSI product information
// VPN Server
static SW_OLD_MSI old_msi_vpnserver[] =
{
	{"{B5B58F8A-D56C-4f3e-B400-235A6E007101}", "{1BDA6B01-2DB3-478c-AA5B-E973A7DC49A4}"},
	{"{124DDAE2-B9AF-4541-B3EF-B169D9007101}", "{BCDE5CF2-7413-47d0-92E1-F6F2189D8E60}"},
};
static SW_OLD_MSI old_msi_vpnclient[] =
{
	{"{54864EDD-4FC6-4269-AA17-3E7C13607101}", "{13ED64E0-532D-4ff0-A3A0-5D700C73259E}"},
	{"{8A215EB7-C5F2-4193-9D7D-1017F1007101}", "{AD593FE5-759E-46c6-9355-29031A8C7D44}"},
};
static SW_OLD_MSI old_msi_vpnbridge[] =
{
	{"{58CE8E96-1234-499D-CAFE-3E62261DF211}", "{211FA6A7-1234-4985-CAFE-3DD3E3151E7E}"},
};

// List of file names needed to SFX
static char *sfx_vpn_server_bridge_files[] =
{
	"vpnsetup.exe",
	"vpnserver.exe",
	"vpnbridge.exe",
	"vpnsmgr.exe",
	"vpncmd.exe",
	"hamcore.se2",
};
static char *sfx_vpn_client_files[] =
{
	"vpnsetup.exe",
	"vpnclient.exe",
	"vpncmgr.exe",
	"vpncmd.exe",
	//"vpninstall.exe",
	//"vpnweb.cab",
	"hamcore.se2",
};

// Global variables to be used out of necessity
static bool g_stop_flag = false;
static HANDLE g_wait_process_handle = NULL;


// SFX generation main
bool SwGenSfxModeMain(char *mode, wchar_t *dst)
{
	LIST *o;
	bool ret = false;
	// Validate arguments
	if (mode == NULL || dst == NULL)
	{
		return false;
	}

	o = SwNewSfxFileList();

	if (SwAddBasicFilesToList(o, mode))
	{
		if (SwCompileSfx(o, dst))
		{
			ret = true;
		}
	}

	SwFreeSfxFileList(o);

	return ret;
}

// Compile the SFX files
bool SwCompileSfx(LIST *o, wchar_t *dst_filename)
{
	bool ret = false;
	wchar_t exe_filename[MAX_PATH];
	HINSTANCE hKernel32 = LoadLibraryA("kernel32.dll");
	HANDLE (WINAPI *_BeginUpdateResourceW)(LPCWSTR, BOOL) = NULL;
	BOOL (WINAPI *_UpdateResourceA)(HANDLE, LPCSTR, LPCSTR, WORD, LPVOID, DWORD) = NULL;
	BOOL (WINAPI *_EndUpdateResourceW)(HANDLE, BOOL) = NULL;
	// Validate arguments
	if (o == NULL || dst_filename == NULL || hKernel32 == NULL)
	{
		return false;
	}

	// Get the API related to the resource editing 
	_BeginUpdateResourceW = (HANDLE (__stdcall *)(LPCWSTR,UINT))GetProcAddress(hKernel32, "BeginUpdateResourceW");
	_UpdateResourceA = (UINT (__stdcall *)(HANDLE,LPCSTR,LPCSTR,WORD,LPVOID,DWORD))GetProcAddress(hKernel32, "UpdateResourceA");
	_EndUpdateResourceW = (UINT (__stdcall *)(HANDLE,UINT))GetProcAddress(hKernel32, "EndUpdateResourceW");

	if (_BeginUpdateResourceW != NULL && _UpdateResourceA != NULL && _EndUpdateResourceW != NULL)
	{
		// Generate the setup.exe file in the Temp directory
		ConbinePathW(exe_filename, sizeof(exe_filename), MsGetMyTempDirW(), L"setup.exe");
		if (FileCopyW(L"vpnsetup.exe", exe_filename))
		{
			// Resource updating start
			HANDLE h = _BeginUpdateResourceW(exe_filename, false);

			if (h != NULL)
			{
				UINT i;
				bool ok = true;

				for (i = 0;i < LIST_NUM(o);i++)
				{
					SW_SFX_FILE *f = LIST_DATA(o, i);
					BUF *b;

					// Read the original file
					b = ReadDumpW(f->DiskFileName);
					if (b != NULL)
					{
						// Add resources
						char inner_name[MAX_PATH];
						BUF *b2;
						StrCpy(inner_name, sizeof(inner_name), f->InnerFileName);
						StrUpper(inner_name);

						if (StrCmpi(inner_name, "hamcore.se2") == 0)
						{
							// Not to re-compress the hamcore.se2 because they are already compressed
							// Prepend "raw_" to file name
							Format(inner_name, sizeof(inner_name), "raw_%s", f->InnerFileName);
							StrUpper(inner_name);
						}
						else
						{
							// Compress
							b2 = CompressBuf(b);
							FreeBuf(b);
							b = b2;
						}


						if (_UpdateResourceA(h, SW_SFX_RESOURCE_TYPE, inner_name, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
							b->Buf, b->Size) == false)
						{
							ok = false;
						}

						FreeBuf(b);
					}

					if (ok == false)
					{
						break;
					}
				}

				if (ok)
				{
					// Success to add all resources
					if (_EndUpdateResourceW(h, false))
					{
						h = NULL;

						// File Copy
						if (FileCopyW(exe_filename, dst_filename))
						{
							// All succeed
							ret = true;
						}
					}
				}

				if (ret == false)
				{
					// Failed to add resource
					if (h != NULL)
					{
						_EndUpdateResourceW(h, true);
						h = NULL;
					}
				}

				FileDeleteW(exe_filename);
			}
		}
	}

	FreeLibrary(hKernel32);

	return ret;
}

// Create new item in the SFX compression list
SW_SFX_FILE *SwNewSfxFile(char *inner_file_name, wchar_t *disk_file_name)
{
	SW_SFX_FILE *f = ZeroMalloc(sizeof(SW_SFX_FILE));

	StrCpy(f->InnerFileName, sizeof(f->InnerFileName), inner_file_name);
	UniStrCpy(f->DiskFileName, sizeof(f->DiskFileName), disk_file_name);

	return f;
}

// Add the basically required files for the components to SFX compressed files list
bool SwAddBasicFilesToList(LIST *o, char *component_name)
{
	UINT i;
	// Validate arguments
	if (o == NULL || component_name == NULL)
	{
		return false;
	}

	if (StrCmpi(component_name, "vpnserver_vpnbridge") == 0)
	{
		// VPN Server & VPN Bridge
		for (i = 0; i < (sizeof(sfx_vpn_server_bridge_files) / sizeof(char *)); i++)
		{
			char *name = sfx_vpn_server_bridge_files[i];
			wchar_t name_w[MAX_PATH];
			wchar_t src_file_name[MAX_PATH];

			StrToUni(name_w, sizeof(name_w), name);
			ConbinePathW(src_file_name, sizeof(src_file_name), MsGetExeFileDirW(), name_w);

			Add(o, SwNewSfxFile(name, src_file_name));
		}
	}
	else if (StrCmpi(component_name, "vpnclient") == 0)
	{
		// VPN Client
		for (i = 0; i < (sizeof(sfx_vpn_client_files) / sizeof(char *)); i++)
		{
			char *name = sfx_vpn_client_files[i];
			wchar_t name_w[MAX_PATH];
			wchar_t src_file_name[MAX_PATH];

			StrToUni(name_w, sizeof(name_w), name);
			ConbinePathW(src_file_name, sizeof(src_file_name), MsGetExeFileDirW(), name_w);

			Add(o, SwNewSfxFile(name, src_file_name));
		}
	}
	else
	{
		return false;
	}

	return true;
}

// Release the SFX file list
void SwFreeSfxFileList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SW_SFX_FILE *f = LIST_DATA(o, i);

		Free(f);
	}

	ReleaseList(o);
}

// Generate the SFX file list
LIST *SwNewSfxFileList()
{
	LIST *o = NewListFast(NULL);

	return o;
}

// Extract from the SFX files
bool SwSfxExtractFile(HWND hWnd, void *data, UINT size, wchar_t *dst, bool compressed)
{
	IO *io;
	bool ret = false;
	// Validate arguments
	if (data == NULL || size == 0 || dst == NULL)
	{
		return false;
	}

	io = FileCreateW(dst);

	if (compressed == false)
	{
		// Write uncompressed files as is
		ret = FileWrite(io, data, size);
	}
	else
	{
		// Unzip when the files are compressed
		BUF *src = NewBuf();
		BUF *dst;

		WriteBuf(src, data, size);

		dst = UncompressBuf(src);

		FreeBuf(src);

		ret = FileWrite(io, dst->Buf, dst->Size);

		FreeBuf(dst);
	}

	FileClose(io);

	if (ret == false)
	{
		FileDeleteW(dst);
	}

	return ret;
}

// SFX extraction process
bool SwSfxExtractProcess(HWND hWnd, bool *hide_error_msg)
{
	TOKEN_LIST *t;
	UINT i;
	bool ret = true;
	wchar_t exec_filename[MAX_SIZE];
	bool is_easy_installer = false;
	bool dummy_bool = false;

	if (hide_error_msg == NULL)
	{
		hide_error_msg = &dummy_bool;
	}

	*hide_error_msg = false;

	Zero(exec_filename, sizeof(exec_filename));

	// Enumerate the DATAFILE resources
	t = MsEnumResources(NULL, SW_SFX_RESOURCE_TYPE);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *resource_name = t->Token[i];
		char filename[MAX_PATH];
		wchar_t filename_w[MAX_PATH];
		wchar_t tmp_filename[MAX_PATH];
		HRSRC hr;
		bool ok = false;
		bool is_compressed = true;

		DoEvents(hWnd);

		if (g_stop_flag)
		{
			// User cancel
			ret = false;
			break;
		}

		StrCpy(filename, sizeof(filename), resource_name);

		StrLower(filename);

		if (EndWith(filename, ".vpn"))
		{
			is_easy_installer = true;
		}

		if (StartWith(filename, "raw_"))
		{
			StrToUni(filename_w, sizeof(filename_w), filename + 4);
			is_compressed = false;
		}
		else
		{
			StrToUni(filename_w, sizeof(filename_w), filename);
		}

		ConbinePathW(tmp_filename, sizeof(tmp_filename), MsGetMyTempDirW(), filename_w);

		if (EndWith(filename, "vpnsetup.exe"))
		{
			UniStrCpy(exec_filename, sizeof(exec_filename), tmp_filename);
		}

		// Find the resources
		hr = FindResourceA(MsGetCurrentModuleHandle(), resource_name, SW_SFX_RESOURCE_TYPE);
		if (hr != NULL)
		{
			HGLOBAL hg = LoadResource(MsGetCurrentModuleHandle(), hr);

			if (hg != NULL)
			{
				UINT size = SizeofResource(MsGetCurrentModuleHandle(), hr);
				void *ptr = LockResource(hg);

				if (size != 0 && ptr != NULL)
				{
					if (SwSfxExtractFile(hWnd, ptr, size, tmp_filename, is_compressed))
					{
						ok = true;
					}
				}
			}
		}

		DoEvents(hWnd);

		if (ok == false)
		{
			// Failure
			ret = false;
			break;
		}
	}

	FreeToken(t);

	if (ret)
	{
		wchar_t exe_name[MAX_PATH];
		wchar_t *exe_dir = MsGetExeFileDirW();

		GetFileNameFromFilePathW(exe_name, sizeof(exe_name), MsGetExeFileNameW());

	}

	if (ret)
	{
		// Start the vpnsetup.exe
		if (UniIsEmptyStr(exec_filename))
		{
			ret = false;
		}
		else
		{
			void *handle = NULL;
			wchar_t params[MAX_SIZE];
			wchar_t *current_params = GetCommandLineUniStr();
			wchar_t tmp[MAX_SIZE];
			char *last_lang;
			wchar_t copy_of_me[MAX_PATH];

			UniStrCpy(params, sizeof(params), current_params);

			// Copy itself to the Temp directory
			CombinePathW(copy_of_me, sizeof(copy_of_me), MsGetMyTempDirW(), L"installer.cache");
			if (FileCopyW(MsGetExeFileNameW(), copy_of_me) == false)
			{
				Zero(copy_of_me, sizeof(copy_of_me));
			}

			// Add a path of this own
			UniFormat(tmp, sizeof(tmp), L" /CALLERSFXPATH:\"%s\"", copy_of_me);
			UniStrCat(params, sizeof(params), tmp);

			// Add information of whether it's a simple installer
			UniFormat(tmp, sizeof(tmp), L" /ISEASYINSTALLER:%u", is_easy_installer);
			UniStrCat(params, sizeof(params), tmp);

			UniTrim(params);

			// Specify a language by the lang.config
			last_lang = MsRegReadStrEx2(REG_CURRENT_USER, SW_REG_KEY, "Last User Language", false, true);
			if (IsEmptyStr(last_lang) == false)
			{
				wchar_t lang_filename[MAX_PATH];
				BUF *buf;

				CombinePathW(lang_filename, sizeof(lang_filename), MsGetMyTempDirW(), L"lang.config");

				buf = NewBuf();
				WriteBufLine(buf, "");
				WriteBufLine(buf, last_lang);
				WriteBufLine(buf, "");
				DumpBufW(buf, lang_filename);
				FreeBuf(buf);
			}
			Free(last_lang);

			if (MsExecuteEx2W(exec_filename, params, &handle, false) == false)
			{
				ret = false;
			}
			else
			{
				g_wait_process_handle = handle;
			}
		}
	}

	return ret;
}

// Copy the files of VPN Gate
bool SwSfxCopyVgFiles(HWND hWnd, wchar_t *src, wchar_t *dst)
{
	wchar_t *msg;
	wchar_t srcfilename[MAX_PATH];
	wchar_t exefilename[MAX_PATH];

	GetFileNameFromFilePathW(srcfilename, sizeof(srcfilename), src);
	GetFileNameFromFilePathW(exefilename, sizeof(exefilename), MsGetExeFileNameW());

	if (FileCopyW(src, dst))
	{
		return true;
	}

	msg = L"The file \"%s\" was not found on the directory which the installer \"%s\" is located on.\r\n\r\n"
		L"To continue the installation, the file \"%s\" is required on the same directory.\r\n"
		L"If you have extracted the installer from a ZIP archive, you have to also extract the file \"%s\" from the ZIP archive together.";

	MsgBoxEx(hWnd, MB_ICONINFORMATION, msg, srcfilename, exefilename, srcfilename, srcfilename);

	return false;
}

// SFX extraction dialog procedure
bool CALLBACK SfxModeMainDialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	UINT ret;
	bool hide_msg = false;
	switch (msg)
	{
	case WM_INITDIALOG:
		SetTimer(hWnd, 1, 500, NULL);
		break;

	case WM_TIMER:
		switch (wParam)
		{
		case 1:
			KillTimer(hWnd, 1);

			ret = SW_EXIT_CODE_USER_CANCEL;
			if (SwSfxExtractProcess(hWnd, &hide_msg))
			{
				ret = 0;
			}
			else
			{
				if (g_stop_flag == false)
				{
					if (hide_msg == false)
					{
						MsgBoxEx(hWnd, MB_ICONSTOP, L"Fatal Error: Self extracting files to the temporary directory was failed.\r\n\r\n"
							L"Please try again after reboot Windows.");
					}
				}
			}

			EndDialog(hWnd, ret);

			break;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			g_stop_flag = true;
			Disable(hWnd, IDCANCEL);
			break;
		}
		break;

	case WM_CLOSE:
		break;
	}

	return false;
}

// Main process as SFX mode
UINT SwSfxModeMain()
{
	UINT ret;
	// Select either English or Japanese
	UINT dialog_id = (MsIsCurrentUserLocaleIdJapanese() ? 10001 : 10002);

	g_wait_process_handle = NULL;
	g_stop_flag = false;

	// Show the screen
	ret = (UINT)DialogBoxParamA(MsGetCurrentModuleHandle(), MAKEINTRESOURCEA(dialog_id), NULL, (DLGPROC)SfxModeMainDialogProc, 0);

	if (g_wait_process_handle != NULL)
	{
		// If this have started the vpnsetup.exe, wait for termination of the child process
		ret = MsWaitProcessExit(g_wait_process_handle);
	}

	return ret;
}

// Resource name enumeration procedure
bool CALLBACK SwEnumResourceNamesProc(HMODULE hModule, const char *type, char *name, LONG_PTR lParam)
{
	bool *b = (bool *)lParam;
	// Validate arguments
	if (type == NULL || name == NULL || lParam == 0)
	{
		return false;
	}

	*b = true;

	return true;
}

// Main process of vpnsetup.exe
UINT SWExec()
{
	UINT ret = 0;
	bool is_datafile_exists = false;

	// Examine whether DATAFILE resources are stored in setup.exe that is currently running
	EnumResourceNamesA(NULL, SW_SFX_RESOURCE_TYPE, SwEnumResourceNamesProc, (LONG_PTR)(&is_datafile_exists));

	if (is_datafile_exists)
	{
		// If DATAFILE resources are stored, extract it as SFX
		MayaquaMinimalMode();
	}

#if defined(_DEBUG) || defined(DEBUG)	// In VC++ compilers, the macro is "_DEBUG", not "DEBUG".
	// If set memcheck = true, the program will be vitally slow since it will log all malloc() / realloc() / free() calls to find the cause of memory leak.
	// For normal debug we set memcheck = false.
	// Please set memcheck = true if you want to test the cause of memory leaks.
	InitMayaqua(false, true, 0, NULL);
#else
	InitMayaqua(false, false, 0, NULL);
#endif
	InitCedar();

	if (is_datafile_exists == false)
	{
		// Start the Setup Wizard
		ret = SWExecMain();
	}
	else
	{
		// SFX mode
		ret = SwSfxModeMain();
	}

	FreeCedar();
	FreeMayaqua();

	return ret;
}

// Dialog procedure (for copy and paste)
UINT SwDefaultDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		break;

	case WM_WIZ_SHOW:
		SetWizardButton(wizard_page, true, true, true, false);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		break;

	case WM_WIZ_BACK:
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;
	}

	return 0;
}

// Update the file specification dialog
void SwWeb2Update(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page)
{
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || sw == NULL || wizard_page == NULL || wizard == NULL)
	{
		return;
	}

	if (IsEmptyUniStr(sw->Web_OutFile) || IsEmptyUniStr(sw->Web_SettingFile))
	{
		ok = false;
	}

	SetText(hWnd, E_SETTING, sw->Web_SettingFile);
	SetText(hWnd, E_OUT, sw->Web_OutFile);

	SetWizardButton(wizard_page, ok, true, true, false);
}

// Update the file specification dialog
void SwEasy2Update(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page)
{
	bool ok = true;
	// Validate arguments
	if (hWnd == NULL || sw == NULL || wizard_page == NULL || wizard == NULL)
	{
		return;
	}

	if (IsEmptyUniStr(sw->Easy_OutFile) || IsEmptyUniStr(sw->Easy_SettingFile))
	{
		ok = false;
	}

	SetText(hWnd, E_SETTING, sw->Easy_SettingFile);
	SetText(hWnd, E_OUT, sw->Easy_OutFile);

	SetWizardButton(wizard_page, ok, true, true, false);
}

// Generate a SFX file name of the default
void SwGenerateDefaultSfxFileName(wchar_t *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	UniFormat(name, size, L"easy-" GC_SW_SOFTETHER_PREFIX_W L"vpnclient-v%u.%02u-%u-%04u-%02u-%02u-windows.exe",
		CEDAR_VERSION_MAJOR, CEDAR_VERSION_MINOR, CEDAR_VERSION_BUILD,
		BUILD_DATE_Y, BUILD_DATE_M, BUILD_DATE_D);
}

// Generate a ZIP file name of the default
void SwGenerateDefaultZipFileName(wchar_t *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	UniFormat(name, size, L"web-" GC_SW_SOFTETHER_PREFIX_W L"vpnclient-v%u.%02u-%u-%04u-%02u-%02u-windows.zip",
		CEDAR_VERSION_MAJOR, CEDAR_VERSION_MINOR, CEDAR_VERSION_BUILD,
		BUILD_DATE_Y, BUILD_DATE_M, BUILD_DATE_D);
}

// Specify a file
UINT SwEasy2(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	wchar_t *fn;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		DlgFont(hWnd, S_BOLD1, 10, true);
		DlgFont(hWnd, S_BOLD2, 10, true);

		Check(hWnd, B_DELETE_SENSITIVE, sw->Easy_EraseSensitive);
		Check(hWnd, B_EASYMODE, sw->Easy_EasyMode);

		break;

	case WM_WIZ_SHOW:
		SwEasy2Update(hWnd, sw, wizard, wizard_page);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		// Save the Settings
		MsRegWriteInt(REG_CURRENT_USER, SW_REG_KEY, "Easy_EraseSensitive", sw->Easy_EraseSensitive);
		MsRegWriteInt(REG_CURRENT_USER, SW_REG_KEY, "Easy_EasyMode", sw->Easy_EasyMode);
		return D_SW_PERFORM;

	case WM_WIZ_BACK:
		return D_SW_EASY1;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_DELETE_SENSITIVE:
			sw->Easy_EraseSensitive = IsChecked(hWnd, B_DELETE_SENSITIVE);
			sw->Easy_EasyMode = IsChecked(hWnd, B_EASYMODE);
			break;

		case B_BROWSE_SETTING:
			fn = OpenDlg(hWnd, _UU("CM_ACCOUNT_SETTING_FILE"), _UU("CM_ACCOUNT_OPEN_TITLE"));

			if (fn != NULL)
			{
				// Parse
				if (CiTryToParseAccountFile(fn) == false)
				{
					// Failure
					MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("CM_ACCOUNT_PARSE_FAILED"));
				}
				else
				{
					// Success
					UniStrCpy(sw->Easy_SettingFile, sizeof(sw->Easy_SettingFile), fn);

					SwEasy2Update(hWnd, sw, wizard, wizard_page);

					FocusEx(hWnd, E_SETTING);
				}

				Free(fn);
			}
			break;

		case B_BROWSE_OUT:
			SwGenerateDefaultSfxFileName(tmp, sizeof(tmp));

			fn = SaveDlg(hWnd, _UU("SW_EXE_FILTER"), _UU("DLG_SAVE_FILE"), tmp, L".exe");

			if (fn != NULL)
			{
				UniStrCpy(sw->Easy_OutFile, sizeof(sw->Easy_OutFile), fn);

				SwEasy2Update(hWnd, sw, wizard, wizard_page);
			}
			break;

		case B_HINT:
			break;
		}
		break;
	}

	return 0;
}

// Specify a file
UINT SwWeb2(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	wchar_t *fn;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		DlgFont(hWnd, S_BOLD1, 10, true);
		DlgFont(hWnd, S_BOLD2, 10, true);

		Check(hWnd, B_DELETE_SENSITIVE, sw->Web_EraseSensitive);
		Check(hWnd, B_EASYMODE, sw->Web_EasyMode);

		break;

	case WM_WIZ_SHOW:
		SwWeb2Update(hWnd, sw, wizard, wizard_page);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		// Save the settings
		MsRegWriteInt(REG_CURRENT_USER, SW_REG_KEY, "Web_EraseSensitive", sw->Web_EraseSensitive);
		MsRegWriteInt(REG_CURRENT_USER, SW_REG_KEY, "Web_EasyMode", sw->Web_EasyMode);
		return D_SW_PERFORM;

	case WM_WIZ_BACK:
		return D_SW_WEB1;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_DELETE_SENSITIVE:
			sw->Web_EraseSensitive = IsChecked(hWnd, B_DELETE_SENSITIVE);
			sw->Web_EasyMode = IsChecked(hWnd, B_EASYMODE);
			break;

		case B_BROWSE_SETTING:
			fn = OpenDlg(hWnd, _UU("CM_ACCOUNT_SETTING_FILE"), _UU("CM_ACCOUNT_OPEN_TITLE"));

			if (fn != NULL)
			{
				// Parse
				if (CiTryToParseAccountFile(fn) == false)
				{
					// Failure
					MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("CM_ACCOUNT_PARSE_FAILED"));
				}
				else
				{
					// Success
					UniStrCpy(sw->Web_SettingFile, sizeof(sw->Web_SettingFile), fn);

					SwWeb2Update(hWnd, sw, wizard, wizard_page);

					FocusEx(hWnd, E_SETTING);
				}

				Free(fn);
			}
			break;

		case B_BROWSE_OUT:
			SwGenerateDefaultZipFileName(tmp, sizeof(tmp));

			fn = SaveDlg(hWnd, _UU("DLG_ZIP_FILER"), _UU("DLG_SAVE_FILE"), tmp, L".zip");

			if (fn != NULL)
			{
				UniStrCpy(sw->Web_OutFile, sizeof(sw->Web_OutFile), fn);

				SwWeb2Update(hWnd, sw, wizard, wizard_page);
			}
			break;

		case B_HINT:
			break;
		}
		break;
	}

	return 0;
}

// Start screen of the Web Installer Creation Wizard
UINT SwWeb1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		wizard->CloseConfirmMsg = NULL;
		DlgFont(hWnd, S_TITLE, 11, true);
		break;

	case WM_WIZ_SHOW:
		SetWizardButton(wizard_page, true, false, true, false);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		return D_SW_WEB2;

	case WM_WIZ_BACK:
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;
	}

	return 0;
}

// Start screen of the Simple installer creation wizard
UINT SwEasy1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		wizard->CloseConfirmMsg = NULL;
		DlgFont(hWnd, S_TITLE, 11, true);
		break;

	case WM_WIZ_SHOW:
		SetWizardButton(wizard_page, true, false, true, false);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		return D_SW_EASY2;

	case WM_WIZ_BACK:
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;
	}

	return 0;
}

// Get the icon for the language
UINT SwGetLangIcon(char *name)
{
	UINT ret = ICO_NULL;
	// Validate arguments
	if (name == NULL)
	{
		return ICO_NULL;
	}

	if (StrCmpi(name, "ja") == 0)
	{
		ret = ICO_LANG_JAPANESE;
	}
	else if (StrCmpi(name, "en") == 0)
	{
		ret = ICO_LANG_ENGLISH;
	}
	else if (StrCmpi(name, "cn") == 0)
	{
		ret = ICO_LANG_CHINESE;
	}
	else if (StrCmpi(name, "tw") == 0)
	{
		ret = ICO_LANG_TRADITIONAL_CHINESE;
	}

	return ret;
}

// Initialize the language list
void SwLang1Init(HWND hWnd, SW *sw)
{
	LVB *b;
	UINT i;
	SW_COMPONENT *default_select = NULL;
	LIST *o;
	UINT current_lang = GetCurrentLangId();
	UINT select_index = INFINITE;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return;
	}

	o = LoadLangList();

	LvReset(hWnd, L_LIST);

	b = LvInsertStart();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *t = LIST_DATA(o, i);
		wchar_t tmp[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];

		UniFormat(tmp, sizeof(tmp), L"(%s)", t->TitleLocal);
		UniFormat(tmp2, sizeof(tmp2), L" %s", t->TitleEnglish);

		LvInsertAdd(b, SwGetLangIcon(t->Name), (void *)(t->Id + 1), 2, tmp2, tmp);

		if (t->Id == current_lang)
		{
			select_index = i;
		}
	}

	LvInsertEnd(b, hWnd, L_LIST);

	if (sw->CurrentComponent == NULL)
	{
		LvSelectByParam(hWnd, L_LIST, default_select);
	}
	else
	{
		LvSelectByParam(hWnd, L_LIST, sw->CurrentComponent);
	}

	LvAutoSize(hWnd, L_LIST);

	FreeLangList(o);

	if (select_index != INFINITE)
	{
		LvSelect(hWnd, L_LIST, select_index);
	}

	LvSort(hWnd, L_LIST, 0, false);

	Focus(hWnd, L_LIST);

	// Show the current language
	if (true)
	{
		LANGLIST t;
		wchar_t tmp[MAX_SIZE];

		Zero(&t, sizeof(t));
		GetCurrentLang(&t);

		UniFormat(tmp, sizeof(tmp), L"%s (%s)", t.TitleEnglish, t.TitleLocal);

		SetText(hWnd, E_CURRENT, tmp);

		if (MsIsVista())
		{
			SetFont(hWnd, E_CURRENT, GetMeiryoFontEx(11));
		}
		else
		{
			DlgFont(hWnd, E_CURRENT, 11, false);
		}
	}
}

// Update of control
void SwLang1Update(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page)
{
	UINT id;
	// Validate arguments
	if (hWnd == NULL || sw == NULL || wizard == NULL || wizard_page == NULL)
	{
		return;
	}

	id = (UINT)LvGetSelectedParam(hWnd, L_LIST);

	if (id == 0)
	{
		SetWizardButtonEx(wizard_page, false, false, true, false, (MsIsAdmin() == false && sw->IsSystemMode));
	}
	else
	{
		SetWizardButtonEx(wizard_page, true, false, true, false, (MsIsAdmin() == false && sw->IsSystemMode));
	}
}

// Language setting screen
UINT SwLang1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	NMHDR *n;
	UINT id;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		LvInitEx2(hWnd, L_LIST, false, true);

		if (MsIsVista())
		{
			SetFont(hWnd, L_LIST, GetMeiryoFontEx(12));
		}
		else
		{
			DlgFont(hWnd, L_LIST, 12, false);
		}

		LvInsertColumn(hWnd, L_LIST, 0, L"English Name", 250);
		LvInsertColumn(hWnd, L_LIST, 1, L"Local Name", 250);

		SwLang1Update(hWnd, sw, wizard, wizard_page);
		break;

	case WM_WIZ_SHOW:
		SetWizardButtonEx(wizard_page, true, false, true, false, (MsIsAdmin() == false && sw->IsSystemMode));

		SwLang1Init(hWnd, sw);

		SwLang1Update(hWnd, sw, wizard, wizard_page);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		if (SwEnterSingle(sw) == false)
		{
			// Multiple-starts prevention
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SW_OTHER_INSTANCE_EXISTS"));
			break;
		}

		if (MsIsNt() == false)
		{
			// Win9x
			MsgBox(hWnd, MB_ICONSTOP,
				L"Windows 9x / Me doesn't support multi-language switcing.\r\n\r\nIf you want to switch to another language, please use Windows NT 4.0, 2000 or greater.");
			break;
		}

		// Get the current selection
		id = (UINT)LvGetSelectedParam(hWnd, L_LIST);
		if (id != 0)
		{
			id--;

			if (id == GetCurrentLangId())
			{
				// No change
				sw->LangNotChanged = true;

				sw->ExitCode = 0;

				return D_SW_ERROR;
			}
			else
			{
				wchar_t add_param[MAX_SIZE];
				LIST *o;
				LANGLIST *new_lang;
				LANGLIST old_lang;
				char new_lang_name[MAX_SIZE];
				char old_lang_name[MAX_SIZE];

				GetCurrentLang(&old_lang);

				o = LoadLangList();

				if (o == NULL)
				{
					MsgBox(hWnd, MB_ICONSTOP, _UU("SW_LANG_LIST_LOAD_FAILED"));
					break;
				}

				new_lang = GetLangById(o, id);

				if (new_lang == NULL)
				{
					MsgBox(hWnd, MB_ICONSTOP, _UU("SW_LANG_LIST_LOAD_FAILED"));
					FreeLangList(o);
					break;
				}

				StrCpy(new_lang_name, sizeof(new_lang_name), new_lang->Name);
				StrCpy(old_lang_name, sizeof(old_lang_name), old_lang.Name);

				FreeLangList(o);

				UniFormat(add_param, sizeof(add_param), L"/LANGID:%u", id);

				if (sw->DoubleClickBlocker)
				{
					break;
				}

				sw->DoubleClickBlocker = true;

				sw->LangId = id;

				if (sw->IsSystemMode == false)
				{
LABEL_RUN_CHILD_PROCESS:
					// Start the process immediately in the case of user mode
					if (SaveLangConfigCurrentDir(new_lang_name) == false)
					{
						sw->DoubleClickBlocker = false;
						MsgBox(hWnd, MB_ICONSTOP, _UU("SW_LANG_SET_FAILED"));
						break;
					}

					UniStrCat(add_param, sizeof(add_param), L" /LANGNOW:yes");
					if (SwReExecMyself(sw, add_param, false))
					{
						// Terminate itself if it succeeds to start the child process
						CloseWizard(wizard_page);
						break;
					}
					else
					{
						// Child process startup failure
						sw->DoubleClickBlocker = false;

						// Undo the language setting
						SaveLangConfigCurrentDir(old_lang_name);
						break;
					}
				}

				// In the case of system mode
				if (MsIsAdmin() == false)
				{
					if (MsIsVista())
					{
						if (sw->IsReExecForUac == false)
						{
							// If there is no Admin privileges in Vista or later, attempt to acquire Admin rights by UAC first during the first run
							UniStrCat(add_param, sizeof(add_param), L" /SETLANGANDREBOOT:true");

							if (SwReExecMyself(sw, add_param, true))
							{
								// Terminate itself if it succeeds to start the child process
								CloseWizard(wizard_page);
								break;
							}
							else
							{
								// Do nothing if it fails to start in the UAC
								sw->DoubleClickBlocker = false;
								break;
							}
						}
						else
						{
							// If no Admin privileges after being started by the UAC, jump to the guidance screen indicating it is not Admin
							return D_SW_NOT_ADMIN;
						}
					}
					else
					{
						// Jump to guide screen indicating that it is not the Admin in the case of XP or earlier
						return D_SW_NOT_ADMIN;
					}
				}
				else
				{
					// Start the process if there is a Admin privileges
					goto LABEL_RUN_CHILD_PROCESS;
				}
			}
		}
		break;

	case WM_WIZ_BACK:
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;

		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SwLang1Update(hWnd, sw, wizard, wizard_page);
				break;
			}
			break;
		}

		break;
	}

	return 0;
}

// Start the uninstallation
UINT SwUninst1(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, S_TITLE, sw->CurrentComponent->Title);
		FormatText(hWnd, S_WELCOME, sw->CurrentComponent->Title);
		break;

	case WM_WIZ_SHOW:
		DlgFont(hWnd, S_TITLE, 11, true);
		SetWizardButtonEx(wizard_page, true, false, true, false, sw->IsSystemMode);

		sw->DoubleClickBlocker = false;

		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		if (MsgBoxEx(hWnd, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("SW_UNINSTALL_CONFIRM"),
			sw->CurrentComponent->Title) == IDNO)
		{
			break;
		}

		if (SwEnterSingle(sw) == false)
		{
			// Multiple-starts prevention
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SW_OTHER_INSTANCE_EXISTS"));
			break;
		}

		if (sw->DoubleClickBlocker)
		{
			break;
		}

		sw->DoubleClickBlocker = true;

		if (sw->IsSystemMode == false)
		{
			// Start uninstallation immediately in the case of user mode
			return D_SW_PERFORM;
		}

		// In the case of system mode
		if (MsIsAdmin() == false)
		{
			if (MsIsVista())
			{
				if (sw->IsReExecForUac == false)
				{
					// If there is no Admin privileges in Vista or later, attempt to acquire Admin rights by UAC first during the first run
					if (SwReExecMyself(sw, NULL, true))
					{
						// Terminate itself if it succeeds to start the child process
						CloseWizard(wizard_page);
						break;
					}
					else
					{
						// If fail to run in UAC, jump to guide screen indicating that it is not Admin
						return D_SW_NOT_ADMIN;
					}
				}
				else
				{
					// If no Admin privileges after being started by the UAC, jump to the guidance screen indicating it is not Admin
					return D_SW_NOT_ADMIN;
				}
			}
			else
			{
				// Jump to guide screen indicating that it is not the Admin in the case of XP or earlier
				return D_SW_NOT_ADMIN;
			}
		}
		else
		{
			// Start the uninstallation if it has Admin privileges
			return D_SW_PERFORM;
		}
		break;

	case WM_WIZ_BACK:
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;
	}

	return 0;
}

// Completion screen
UINT SwFinish(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		if (sw->EasyMode)
		{
			SetIcon(hWnd, S_ICON, ICO_SETUP);
		}
		else if (sw->WebMode)
		{
			SetIcon(hWnd, S_ICON, ICO_INTERNET);
		}
		else
		{
			FormatText(hWnd, S_INFO, sw->CurrentComponent->Title);
			SetIcon(hWnd, S_ICON, sw->CurrentComponent->Icon);
		}

		wizard->CloseConfirmMsg = NULL;

		sw->ExitCode = 0;
		break;

	case WM_WIZ_SHOW:
		if (UniIsEmptyStr(sw->FinishMsg) == false)
		{
			SetText(hWnd, S_INFO, sw->FinishMsg);
		}

		SetWizardButton(wizard_page, true, false, false, true);

		if (sw->HideStartCommand || sw->UninstallMode || sw->LanguageMode || sw->EasyMode || sw->WebMode || UniIsEmptyStr(sw->CurrentComponent->StartExeName))
		{
			Hide(hWnd, B_RUN);
			sw->Run = false;
		}
		else
		{
			SetText(hWnd, B_RUN, sw->CurrentComponent->StartDescription);
			Show(hWnd, B_RUN);
			Format(tmp, sizeof(tmp), "UI_NoCheck_%s_%u", sw->CurrentComponent->Name, sw->IsSystemMode);
			Check(hWnd, B_RUN, !MsRegReadInt(REG_CURRENT_USER, SW_REG_KEY, tmp));
			sw->Run = IsChecked(hWnd, B_RUN);
		}
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		break;

	case WM_WIZ_BACK:
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_RUN:
			if (sw->HideStartCommand || sw->UninstallMode || sw->LanguageMode || sw->EasyMode || sw->WebMode || UniIsEmptyStr(sw->CurrentComponent->StartExeName))
			{
			}
			else
			{
				Format(tmp, sizeof(tmp), "UI_NoCheck_%s_%u", sw->CurrentComponent->Name, sw->IsSystemMode);
				sw->Run = IsChecked(hWnd, B_RUN);
				MsRegWriteInt(REG_CURRENT_USER, SW_REG_KEY, tmp, !sw->Run);
			}
			break;
		}
		break;
	}

	return 0;
}

// Error occurring screen
UINT SwError(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		wizard->CloseConfirmMsg = NULL;

		if (sw->EasyMode)
		{
			SetText(hWnd, S_INFO, _UU("SW_EASY_ERROR_MSG"));
		}
		else if (sw->WebMode)
		{
			SetText(hWnd, S_INFO, _UU("SW_WEB_ERROR_MSG"));
		}
		else
		{
			FormatText(hWnd, S_INFO, sw->CurrentComponent->Title);
		}

		if (sw->MsiRebootRequired)
		{
			// MSI requires a reboot
			wchar_t tmp[MAX_SIZE];

			SetIcon(hWnd, S_ICON, ICO_INFORMATION);

			UniFormat(tmp, sizeof(tmp), _UU("SW_MSI_UNINSTALL_REBOOT_REQUIRED"), sw->CurrentComponent->Title);

			SetText(hWnd, S_INFO, tmp);
		}

		if (sw->LangNotChanged)
		{
			// Language has not changed
			wchar_t tmp[MAX_SIZE];

			SetIcon(hWnd, S_ICON, ICO_INFORMATION);

			UniFormat(tmp, sizeof(tmp), _UU("SW_LANG_NOT_CHANGED"), sw->CurrentComponent->Title);

			SetText(hWnd, S_INFO, tmp);
		}

		break;

	case WM_WIZ_SHOW:
		SetWizardButton(wizard_page, true, false, false, true);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		break;

	case WM_WIZ_BACK:
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;
	}

	return 0;
}

// Execution thread of the setup process
void SwPerformThread(THREAD *thread, void *param)
{
	WIZARD_PAGE *wp = (WIZARD_PAGE *)param;
	SW *sw;
	SW_COMPONENT *c;
	bool ret;
	SW_UI ui;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	sw = (SW *)wp->Wizard->Param;

	sw->ExitCode = SW_EXIT_CODE_INTERNAL_ERROR;

	// Components to be installed
	c = sw->CurrentComponent;

	if (sw->EasyMode)
	{
		// Create a simple installer
		ret = SwEasyMain(sw, wp);
	}
	else if (sw->WebMode)
	{
		// Create a Web installer
		ret = SwWebMain(sw, wp);
	}
	else if (sw->UninstallMode == false)
	{
		// Installation
		ret = SwInstallMain(sw, wp, c);
	}
	else
	{
		// Uninstallation
		ret = SwUninstallMain(sw, wp, c);
	}

	// Notify the results to the window
	Zero(&ui, sizeof(ui));
	ui.Type = (ret ? SW_UI_TYPE_FINISH : SW_UI_TYPE_ERROR);
	SwInteractUi(wp, &ui);
}

// Create a file copy task
SW_TASK_COPY *SwNewCopyTask(wchar_t *srcfilename, wchar_t *dstfilename, wchar_t *srcdir, wchar_t *dstdir, bool overwrite, bool setup_file)
{
	SW_TASK_COPY *ct;
	// Validate arguments
	if (srcfilename == NULL || srcdir == NULL || dstdir == NULL)
	{
		return NULL;
	}

	ct = ZeroMalloc(sizeof(SW_TASK_COPY));

	UniStrCpy(ct->SrcFileName, sizeof(ct->SrcFileName), srcfilename);

	if (UniIsEmptyStr(dstfilename))
	{
		UniStrCpy(ct->DstFileName, sizeof(ct->DstFileName), srcfilename);
	}
	else
	{
		UniStrCpy(ct->DstFileName, sizeof(ct->DstFileName), dstfilename);
	}

	UniStrCpy(ct->SrcDir, sizeof(ct->SrcDir), srcdir);
	UniStrCpy(ct->DstDir, sizeof(ct->DstDir), dstdir);

	ct->Overwrite = overwrite;
	ct->SetupFile = setup_file;

	return ct;
}

// Release the file copy task
void SwFreeCopyTask(SW_TASK_COPY *ct)
{
	// Validate arguments
	if (ct == NULL)
	{
		return;
	}

	Free(ct);
}

// Create a link creation task
SW_TASK_LINK *SwNewLinkTask(wchar_t *target_dir, wchar_t *target_exe, wchar_t *target_arg,
							wchar_t *icon_exe, UINT icon_index,
							wchar_t *dest_dir, wchar_t *dest_name, wchar_t *dest_desc,
							bool no_delete_dir)
{
	SW_TASK_LINK *lt;
	// Validate arguments
	if (target_dir == NULL || target_exe == NULL || dest_dir == NULL || dest_name == NULL)
	{
		return NULL;
	}

	lt = ZeroMalloc(sizeof(SW_TASK_LINK));

	UniStrCpy(lt->TargetDir, sizeof(lt->TargetDir), target_dir);
	UniStrCpy(lt->TargetExe, sizeof(lt->TargetExe), target_exe);
	UniStrCpy(lt->TargetArg, sizeof(lt->TargetArg), target_arg);

	if (UniIsEmptyStr(icon_exe) == false)
	{
		UniStrCpy(lt->IconExe, sizeof(lt->IconExe), icon_exe);
	}
	else
	{
		UniStrCpy(lt->IconExe, sizeof(lt->IconExe), target_exe);
	}

	lt->IconIndex = icon_index;

	UniStrCpy(lt->DestDir, sizeof(lt->DestDir), dest_dir);
	UniStrCpy(lt->DestName, sizeof(lt->DestName), dest_name);
	UniStrCpy(lt->DestDescription, sizeof(lt->DestDescription), dest_desc);

	lt->NoDeleteDir = no_delete_dir;

	return lt;
}

// Release the link creation task
void SwFreeLinkTask(SW_TASK_LINK *lt)
{
	// Validate arguments
	if (lt == NULL)
	{
		return;
	}

	Free(lt);
}

// Create a Setup task
SW_TASK *SwNewTask()
{
	SW_TASK *t = ZeroMalloc(sizeof(SW_TASK));

	t->CopyTasks = NewListFast(NULL);

	t->SetSecurityPaths = NewListFast(NULL);

	t->LinkTasks = NewListFast(NULL);

	return t;
}

// Release the Setup Tasks
void SwFreeTask(SW_TASK *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->CopyTasks);i++)
	{
		SW_TASK_COPY *ct = LIST_DATA(t->CopyTasks, i);

		SwFreeCopyTask(ct);
	}

	ReleaseList(t->CopyTasks);

	FreeStrList(t->SetSecurityPaths);

	for (i = 0;i < LIST_NUM(t->LinkTasks);i++)
	{
		SW_TASK_LINK *lt = LIST_DATA(t->LinkTasks, i);

		SwFreeLinkTask(lt);
	}

	ReleaseList(t->LinkTasks);

	Free(t);
}

// Delete the shortcut file
void SwDeleteShortcuts(SW_LOGFILE *logfile)
{
	UINT i;
	LIST *o;
	// Validate arguments
	if (logfile == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(logfile->LogList);i++)
	{
		SW_LOG *g = LIST_DATA(logfile->LogList, LIST_NUM(logfile->LogList) - i - 1);

		switch (g->Type)
		{
		case SW_LOG_TYPE_LNK:
			FileDeleteW(g->Path);
			Add(o, g);
			break;

		case SW_LOG_TYPE_LNK_DIR:
			SleepThread(100);
			DeleteDirW(g->Path);
			Add(o, g);
			break;
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SW_LOG *g = LIST_DATA(o, i);

		Delete(logfile->LogList, g);

		Free(g);
	}

	ReleaseList(o);
}

// Uninstall main
bool SwUninstallMain(SW *sw, WIZARD_PAGE *wp, SW_COMPONENT *c)
{
	bool ok;
	wchar_t tmp[MAX_SIZE];
	UINT i;
	// Validate arguments
	if (sw == NULL || wp == NULL || c == NULL)
	{
		return false;
	}

	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_INIT_UNINST"));

	// Stop the Service
	ok = true;

	if (c->InstallService)
	{
		char svc_title_name[MAX_SIZE];
		wchar_t *svc_title;

		Format(svc_title_name, sizeof(svc_title_name), "SVC_%s_TITLE", c->SvcName);

		svc_title = _UU(svc_title_name);

		if (UniIsEmptyStr(svc_title) == false)
		{
			if (sw->IsSystemMode && MsIsNt())
			{
				// WinNT and system mode
				if (MsIsServiceRunning(c->SvcName))
				{
					wchar_t svc_exe[MAX_SIZE];
					UINT64 giveup_tick;
					UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_STOP_SVC"), svc_title);
					SwPerformPrint(wp, tmp);

LABEL_RETRY_3:
					if (MsStopService(c->SvcName) == false)
					{
						UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_STOP_SVC_ERROR"), svc_title, c->SvcName);
						if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_RETRYCANCEL, tmp) != IDRETRY)
						{
							// Cancel
							ok = false;
						}
						else
						{
							if (MsIsServiceRunning(c->SvcName))
							{
								goto LABEL_RETRY_3;
							}
						}
					}

					// Wait 5 seconds if stop the service
					SleepThread(5000);

					// Wait until the EXE file for the service become ready to write
					ConbinePathW(svc_exe, sizeof(svc_exe), sw->InstallDir, c->SvcFileName);

					giveup_tick = Tick64() + (UINT64)10000;
					while (IsFileWriteLockedW(svc_exe))
					{
						UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_WAIT_FOR_FILE_UNLOCK"), svc_exe);
						SwPerformPrint(wp, tmp);

						SleepThread(100);

						if (Tick64() >= giveup_tick)
						{
							break;
						}
					}
				}
			}
			else
			{
				// Win9x or user mode
				wchar_t svc_exe[MAX_SIZE];
				UINT64 giveup_tick;

				// Stop the Service
				MsStopUserModeSvc(c->SvcName);
				SleepThread(3000);

				// Wait until the EXE file for the service become ready to write
				ConbinePathW(svc_exe, sizeof(svc_exe), sw->InstallDir, c->SvcFileName);

				giveup_tick = Tick64() + (UINT64)10000;
				while (IsFileWriteLockedW(svc_exe))
				{
					UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_WAIT_FOR_FILE_UNLOCK"), svc_exe);
					SwPerformPrint(wp, tmp);

					SleepThread(100);

					if (Tick64() >= giveup_tick)
					{
						break;
					}
				}
			}
		}
	}

	if (ok == false)
	{
		goto LABEL_CLEANUP;
	}

	// Examine preliminary whether the files to be deleted can be written successfully
	ok = true;

	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_DELETE_PREPARE"));

	for (i = 0;i < LIST_NUM(sw->LogFile->LogList);i++)
	{
		SW_LOG *g = LIST_DATA(sw->LogFile->LogList, i);

		if (g->Type == SW_LOG_TYPE_FILE)
		{
			wchar_t fullpath[MAX_SIZE];
			IO *io;
			bool write_ok;
			bool new_file;

LABEL_RETRY_1:
			write_ok = new_file = false;

			UniStrCpy(fullpath, sizeof(fullpath), g->Path);

			// If the process with the same name is running, kill it
			if (MsKillProcessByExeName(fullpath) != 0)
			{
				// Wait for 1 second if kill the process
				SleepThread(1000);
			}

			// Writing check
			io = FileOpenExW(fullpath, true, true);
			if (io == NULL)
			{
				io = FileCreateW(fullpath);
				new_file = true;
			}
			if (io != NULL)
			{
				// Writing OK
				write_ok = true;

				FileCloseEx(io, true);

				if (new_file)
				{
					FileDeleteW(fullpath);
				}
			}

			if (write_ok == false)
			{
				// Show an error message if it fails
				UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_DELETE_ERROR"), fullpath, c->Title);
				if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_RETRYCANCEL, tmp) != IDRETRY)
				{
					// Cancel
					ok = false;
					break;
				}
				else
				{
					// Retry
					goto LABEL_RETRY_1;
				}
			}
		}
	}

	if (ok == false)
	{
		goto LABEL_CLEANUP;
	}

	// Delete the service
	if (c->InstallService)
	{
		char svc_title_name[MAX_SIZE];
		char svc_description_name[MAX_SIZE];
		wchar_t *svc_title;

		Format(svc_title_name, sizeof(svc_title_name), "SVC_%s_TITLE", c->SvcName);
		Format(svc_description_name, sizeof(svc_description_name), "SVC_%s_DESCRIPT", c->SvcName);

		svc_title = _UU(svc_title_name);

		if (UniIsEmptyStr(svc_title) == false)
		{
			if (sw->IsSystemMode == false || MsIsNt() == false)
			{
				// Win9x or user mode
				if (MsIsNt() == false)
				{
					// Remove the Run key from the registry for Win9x
					MsRegDeleteValue(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_1, c->SvcName);
					MsRegDeleteValue(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_2, c->SvcName);
				}
			}
			else
			{
				// System mode
				UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_UNINSTALL_SVC"), svc_title);
				SwPerformPrint(wp, tmp);

LABEL_RETRY_4:

				if (MsIsServiceInstalled(c->SvcName))
				{
					// Stop the service if it is running by any chance
					MsStopService(c->SvcName);
				}

				if (MsIsServiceInstalled(c->SvcName))
				{
					// Uninstall the service
					if (MsUninstallService(c->SvcName) == false)
					{
						// Show an error message if it fails
						UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_SVC_UNINSTALL_FAILED"), svc_title, c->SvcName);
						if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_RETRYCANCEL, tmp) != IDRETRY)
						{
							// Cancel
							ok = false;
						}
						else
						{
							// Retry
							goto LABEL_RETRY_4;
						}
					}
				}
			}
		}
	}

	// Delete the shortcut
	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_DELETE_LINKS"));
	SwDeleteShortcuts(sw->LogFile);

	// Delete the registry, files, and directories
	for (i = 0;i < LIST_NUM(sw->LogFile->LogList);i++)
	{
		SW_LOG *g = LIST_DATA(sw->LogFile->LogList, LIST_NUM(sw->LogFile->LogList) - i - 1);
		char tmpa[MAX_SIZE];

		UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_DELETE"), g->Path);

		switch (g->Type)
		{
		case SW_LOG_TYPE_FILE:	// File
			SwPerformPrint(wp, tmp);
			FileDeleteW(g->Path);
			break;

		case SW_LOG_TYPE_DIR:	// Directory
			SwPerformPrint(wp, tmp);
			SleepThread(100);
			DeleteDirW(g->Path);
			break;

		case SW_LOG_TYPE_REGISTRY:	// Registry
			SwPerformPrint(wp, tmp);
			UniToStr(tmpa, sizeof(tmpa), g->Path);
			MsRegDeleteKeyEx2(REG_LOCAL_MACHINE, tmpa, false, true);
			break;
		}
	}

	// Remove the installed build number from the registry
	if (true)
	{
		char keyname[MAX_SIZE];
		Format(keyname, sizeof(keyname), "%s\\%s", SW_REG_KEY, sw->CurrentComponent->Name);
		MsRegDeleteValueEx2(sw->IsSystemMode ? REG_LOCAL_MACHINE : REG_CURRENT_USER,
			keyname, "InstalledBuild", false, true);
	}

	// Remove the EULA agreement record
	MsRegDeleteValueEx2(REG_CURRENT_USER, SW_REG_KEY_EULA, sw->CurrentComponent->Name, false, true);

	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_DELETE_SETUP_INFO"));

	if (c->Id == SW_CMP_VPN_CLIENT)
	{
		// Remove the UI Helper
		MsRegDeleteValueEx2(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			SW_VPN_CLIENT_UIHELPER_REGVALUE, false, true);
	}

	// Remove the installation directory from the registry
	if (true)
	{
		// Remove the installed directory from the registry
		char keyname[MAX_SIZE];
		Format(keyname, sizeof(keyname), "%s\\%s", SW_REG_KEY, sw->CurrentComponent->Name);
		MsRegDeleteKeyEx2(sw->IsSystemMode ? REG_LOCAL_MACHINE : REG_CURRENT_USER, keyname, false, true);
	}

	// Delete the setuplog.dat
	if (true)
	{
		wchar_t setuplog[MAX_PATH];

		ConbinePathW(setuplog, sizeof(setuplog), MsGetExeDirNameW(), L"setuplog.dat");

		FileDeleteW(setuplog);
	}

	// Delete the existing Virtual Network Adapters
	// Currently disabled because of 32bit/64bit problems
#if	0
	if (c->Id == SW_CMP_VPN_CLIENT)
	{
		if (MsIsNt())
		{
			if (!(MsIs64BitWindows() && Is32()))
			{
				UINT i;
				TOKEN_LIST *t;

				SwPerformPrint(wp, _UU("SW_PERFORM_MSG_DELETE_NIC"));

				// Enumeration
				t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, VLAN_ADAPTER_NAME_OLD);
				if (t != NULL)
				{
					if (t->NumTokens >= 1)
					{
						if (SwPerformMsgBox(wp, MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2, _UU("SW_PERFORM_MSG_DELETE_NIC")) == IDYES)
						{
							for (i = 0;i < t->NumTokens;i++)
							{
								char *name = t->Token[i];

								MsUninstallVLan(name);
							}
						}
					}

					FreeToken(t);
				}
			}
		}
	}
#endif

	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_UPDATING"));

	// Notify the update to the system
	MsUpdateSystem();

	// Completion message
	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_FINISHED"));

	if (ok == false)
	{
		goto LABEL_CLEANUP;
	}

LABEL_CLEANUP:

	return ok;
}

// Create a Task List
void SwDefineTasks(SW *sw, SW_TASK *t, SW_COMPONENT *c)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t src_setup_exe_fullpath[MAX_PATH];
	wchar_t src_setup_exe_dir[MAX_PATH];
	wchar_t src_setup_exe_filename[MAX_PATH];
	wchar_t dir_desktop[MAX_PATH];
	wchar_t dir_startmenu[MAX_PATH];
	wchar_t dir_program[MAX_PATH];
	wchar_t dir_app_program[MAX_PATH];
	wchar_t dir_config_program[MAX_PATH];
	wchar_t dir_admin_tools[MAX_PATH];
	wchar_t dir_config_language[MAX_PATH];
	wchar_t dir_startup[MAX_PATH];
	wchar_t tmp1[MAX_SIZE], tmp2[MAX_SIZE];
	SW_TASK_COPY *setup_exe;
	// Validate arguments
	if (sw == NULL || t == NULL || c == NULL)
	{
		return;
	}

	//// Organize directory name for creating shortcut
	// Desktop
	UniStrCpy(dir_desktop, sizeof(dir_desktop), (sw->IsSystemMode ? MsGetCommonDesktopDirW() : MsGetPersonalDesktopDirW()));
	// Start menu
	UniStrCpy(dir_startmenu, sizeof(dir_startmenu), (sw->IsSystemMode ? MsGetCommonStartMenuDirW() : MsGetPersonalStartMenuDirW()));
	// Program
	UniStrCpy(dir_program, sizeof(dir_program), (sw->IsSystemMode ? MsGetCommonProgramsDirW() : MsGetPersonalProgramsDirW()));
	// Program directory for this application
	ConbinePathW(dir_app_program, sizeof(dir_app_program), dir_program, c->LongName);
	if (sw->IsSystemMode == false)
	{
		// User mode
		UniStrCat(dir_app_program, sizeof(dir_app_program), _UU("SW_TAG_USERNAME"));
	}
	// Configuration tool directory
	ConbinePathW(dir_config_program, sizeof(dir_config_program), dir_app_program, _UU("SW_DIRNAME_CONFIG_TOOLS"));
	// Language configuration directory
	ConbinePathW(dir_config_language, sizeof(dir_config_language), dir_app_program, _UU("SW_DIRNAME_LANGUAGE_TOOLS"));
	// Directory for System administrator tool
	ConbinePathW(dir_admin_tools, sizeof(dir_admin_tools), dir_app_program, _UU("SW_DIRNAME_ADMIN_TOOLS"));
	// Startup
	UniStrCpy(dir_startup, sizeof(dir_startup), (sw->IsSystemMode ? MsGetCommonStartupDirW() : MsGetPersonalStartupDirW()));

	// Get the path information related to vpnsetup.exe
	UniStrCpy(src_setup_exe_fullpath, sizeof(src_setup_exe_fullpath), MsGetExeFileNameW());
	GetDirNameFromFilePathW(src_setup_exe_dir, sizeof(src_setup_exe_dir), src_setup_exe_fullpath);
	GetFileNameFromFilePathW(src_setup_exe_filename, sizeof(src_setup_exe_filename), src_setup_exe_fullpath);

	// Add the Setup program (themselves) to the copy list
	Add(t->CopyTasks, (setup_exe = SwNewCopyTask(src_setup_exe_filename,
		L"vpnsetup.exe", src_setup_exe_dir, sw->InstallDir, true, true)));

	// Generate the file processing list for each component
	if (c->Id == SW_CMP_VPN_SERVER)
	{
		// VPN Server
		SW_TASK_COPY *ct;
		SW_TASK_COPY *vpnserver, *vpncmd, *vpnsmgr;

		CombinePathW(tmp, sizeof(tmp), sw->InstallDir, L"backup.vpn_server.config");
		Add(t->SetSecurityPaths, CopyUniStr(tmp));

		vpnserver = SwNewCopyTask(L"vpnserver.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);
		vpncmd = SwNewCopyTask(L"vpncmd.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);
		vpnsmgr = SwNewCopyTask(L"vpnsmgr.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);

		Add(t->CopyTasks, vpnserver);
		Add(t->CopyTasks, vpncmd);
		Add(t->CopyTasks, vpnsmgr);

		Add(t->CopyTasks, (ct = SwNewCopyTask(L"|empty.config", L"vpn_server.config", sw->InstallSrc, sw->InstallDir, false, false)));
		Add(t->CopyTasks, SwNewCopyTask(L"|backup_dir_readme.txt", L"readme.txt", sw->InstallSrc, tmp, false, false));

		CombinePathW(tmp, sizeof(tmp), ct->DstDir, ct->DstFileName);
		Add(t->SetSecurityPaths, CopyUniStr(tmp));

		//// Definition of the shortcuts
		// Desktop and Start menu
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnsmgr->DstFileName, NULL, NULL, 0, dir_desktop,
			_UU(sw->IsSystemMode ? "SW_LINK_NAME_VPNSMGR_SHORT" : "SW_LINK_NAME_VPNSMGR_SHORT_UM"),
			_UU("SW_LINK_NAME_VPNSMGR_COMMENT"), true));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnsmgr->DstFileName, NULL, NULL, 0, dir_startmenu,
			_UU(sw->IsSystemMode ? "SW_LINK_NAME_VPNSMGR_SHORT" : "SW_LINK_NAME_VPNSMGR_SHORT_UM"),
			_UU("SW_LINK_NAME_VPNSMGR_COMMENT"), true));

		// Programs\PacketiX VPN Server
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnsmgr->DstFileName, NULL, NULL, 0, dir_app_program,
			_UU("SW_LINK_NAME_VPNSMGR_FULL"),
			_UU("SW_LINK_NAME_VPNSMGR_COMMENT"), false));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmd->DstFileName, NULL, NULL, 0, dir_app_program,
			_UU("SW_LINK_NAME_VPNCMD"),
			_UU("SW_LINK_NAME_VPNCMD_COMMENT"), false));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnserver->DstFileName, L"/traffic", L"vpnsetup.exe", 2, dir_admin_tools,
			_UU("SW_LINK_NAME_TRAFFIC"),
			_UU("SW_LINK_NAME_TRAFFIC_COMMENT"), false));

		// Programs\PacketiX VPN Server\Configuration tool
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnserver->DstFileName, L"/tcp", L"vpnsetup.exe", 3, dir_config_program,
			_UU("SW_LINK_NAME_TCP"),
			_UU("SW_LINK_NAME_TCP_COMMENT"), false));

		if (MsIsWin2000OrGreater())
		{
			Add(t->LinkTasks, SwNewLinkTask(MsGetSystem32DirW(), L"services.msc", NULL, L"filemgmt.dll", 0, dir_config_program,
				_UU("SW_LINK_NAME_SERVICES"),
				_UU("SW_LINK_NAME_SERVICES_COMMENT"), false));

			if (sw->IsSystemMode)
			{
				// Debugging information collecting tool
				Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmd->DstFileName, L"/debug", L"vpnsetup.exe", 4, dir_admin_tools,
					_UU("SW_LINK_NAME_DEBUG"),
					_UU("SW_LINK_NAME_DEBUG_COMMENT"), false));
			}
		}

		if (sw->IsSystemMode == false)
		{
			// Register to the start-up in the case of user mode
			Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnserver->DstFileName, L"/usermode", NULL, 0, dir_startup,
				_UU("SW_LINK_NAME_VPNSERVER_SVC"),
				_UU("SW_LINK_NAME_VPNSERVER_SVC_COMMENT"), true));
		}
	}
	else if (c->Id == SW_CMP_VPN_BRIDGE)
	{
		// VPN Bridge
		SW_TASK_COPY *ct;
		SW_TASK_COPY *vpnbridge, *vpncmd, *vpnsmgr;

		CombinePathW(tmp, sizeof(tmp), sw->InstallDir, L"backup.vpn_bridge.config");
		Add(t->SetSecurityPaths, CopyUniStr(tmp));

		vpnbridge = SwNewCopyTask(L"vpnbridge.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);
		vpncmd = SwNewCopyTask(L"vpncmd.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);
		vpnsmgr = SwNewCopyTask(L"vpnsmgr.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);

		Add(t->CopyTasks, vpnbridge);
		Add(t->CopyTasks, vpncmd);
		Add(t->CopyTasks, vpnsmgr);

		Add(t->CopyTasks, (ct = SwNewCopyTask(L"|empty.config", L"vpn_bridge.config", sw->InstallSrc, sw->InstallDir, false, false)));
		Add(t->CopyTasks, SwNewCopyTask(L"|backup_dir_readme.txt", L"readme.txt", sw->InstallSrc, tmp, false, false));

		CombinePathW(tmp, sizeof(tmp), ct->DstDir, ct->DstFileName);
		Add(t->SetSecurityPaths, CopyUniStr(tmp));

		//// Definition of the shortcuts
		// Desktop and Start menu
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnsmgr->DstFileName, NULL, NULL, 0, dir_desktop,
			_UU(sw->IsSystemMode ? "SW_LINK_NAME_VPNSMGR_SHORT" : "SW_LINK_NAME_VPNSMGR_SHORT_UM"),
			_UU("SW_LINK_NAME_VPNSMGR_COMMENT"), true));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnsmgr->DstFileName, NULL, NULL, 0, dir_startmenu,
			_UU(sw->IsSystemMode ? "SW_LINK_NAME_VPNSMGR_SHORT" : "SW_LINK_NAME_VPNSMGR_SHORT_UM"),
			_UU("SW_LINK_NAME_VPNSMGR_COMMENT"), true));

		// Programs\PacketiX VPN Bridge
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnsmgr->DstFileName, NULL, NULL, 0, dir_app_program,
			_UU("SW_LINK_NAME_VPNSMGR_FULL"),
			_UU("SW_LINK_NAME_VPNSMGR_COMMENT"), false));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmd->DstFileName, NULL, NULL, 0, dir_app_program,
			_UU("SW_LINK_NAME_VPNCMD"),
			_UU("SW_LINK_NAME_VPNCMD_COMMENT"), false));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnbridge->DstFileName, L"/traffic", L"vpnsetup.exe", 2, dir_admin_tools,
			_UU("SW_LINK_NAME_TRAFFIC"),
			_UU("SW_LINK_NAME_TRAFFIC_COMMENT"), false));

		// Programs\PacketiX VPN Bridge\Configuration tool
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnbridge->DstFileName, L"/tcp", L"vpnsetup.exe", 3, dir_config_program,
			_UU("SW_LINK_NAME_TCP"),
			_UU("SW_LINK_NAME_TCP_COMMENT"), false));

		if (MsIsWin2000OrGreater())
		{
			Add(t->LinkTasks, SwNewLinkTask(MsGetSystem32DirW(), L"services.msc", NULL, L"filemgmt.dll", 0, dir_config_program,
				_UU("SW_LINK_NAME_SERVICES"),
				_UU("SW_LINK_NAME_SERVICES_COMMENT"), false));

			if (sw->IsSystemMode)
			{
				// Debugging information collecting tool
				Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmd->DstFileName, L"/debug", L"vpnsetup.exe", 4, dir_admin_tools,
					_UU("SW_LINK_NAME_DEBUG"),
					_UU("SW_LINK_NAME_DEBUG_COMMENT"), false));
			}
		}

		if (sw->IsSystemMode == false)
		{
			// Register to the start-up in the case of user mode
			Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnbridge->DstFileName, L"/usermode", NULL, 0, dir_startup,
				_UU("SW_LINK_NAME_VPNBRIDGE_SVC"),
				_UU("SW_LINK_NAME_VPNBRIDGE_SVC_COMMENT"), true));
		}
	}
	else if (c->Id == SW_CMP_VPN_CLIENT)
	{
		// VPN Client
		SW_TASK_COPY *ct;
		SW_TASK_COPY *vpnclient, *vpncmd, *vpncmgr;
		SW_TASK_COPY *sfx_cache = NULL;
		//SW_TASK_COPY *vpnweb;
		//SW_TASK_COPY *vpninstall;
		wchar_t *src_config_filename;

		CombinePathW(tmp, sizeof(tmp), sw->InstallDir, L"backup.vpn_client.config");
		Add(t->SetSecurityPaths, CopyUniStr(tmp));

		vpnclient = SwNewCopyTask(L"vpnclient.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);
		vpncmd = SwNewCopyTask(L"vpncmd.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);
		vpncmgr = SwNewCopyTask(L"vpncmgr.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);

		if (vpncmgr != NULL)
		{
			CombinePathW(sw->vpncmgr_path, sizeof(sw->vpncmgr_path),
				vpncmgr->DstDir, vpncmgr->DstFileName);
		}

		if (UniIsEmptyStr(sw->CallerSfxPath) == false)
		{
			if (IsFileExistsW(sw->CallerSfxPath))
			{
				// Cache the calling SFX file body to the installation directory
				wchar_t srcname[MAX_PATH];
				wchar_t srcdir[MAX_PATH];

				GetFileNameFromFilePathW(srcname, sizeof(srcname), sw->CallerSfxPath);
				GetDirNameFromFilePathW(srcdir, sizeof(srcdir), sw->CallerSfxPath);

				sfx_cache = SwNewCopyTask(srcname, SW_SFX_CACHE_FILENAME, srcdir, sw->InstallDir, true, false);
			}
		}

		//vpnweb = SwNewCopyTask(L"vpnweb.cab", NULL, sw->InstallSrc, sw->InstallDir, true, false);
		//vpninstall = SwNewCopyTask(L"vpninstall.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);

		Add(t->CopyTasks, vpnclient);
		Add(t->CopyTasks, vpncmd);
		Add(t->CopyTasks, vpncmgr);
		//Add(t->CopyTasks, vpnweb);
		//Add(t->CopyTasks, vpninstall);


		if (sfx_cache != NULL)
		{
			Add(t->CopyTasks, sfx_cache);
		}

		src_config_filename = L"|empty.config";

		Add(t->CopyTasks, (ct = SwNewCopyTask(src_config_filename, L"vpn_client.config", sw->InstallSrc, sw->InstallDir, false, false)));

		Add(t->CopyTasks, SwNewCopyTask(L"|backup_dir_readme.txt", L"readme.txt", sw->InstallSrc, tmp, false, false));

		CombinePathW(tmp, sizeof(tmp), ct->DstDir, ct->DstFileName);
		Add(t->SetSecurityPaths, CopyUniStr(tmp));

		//// Definition of the shortcuts
		// Desktop and Start menu
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmgr->DstFileName, NULL, NULL, 0, dir_desktop,
			_UU("SW_LINK_NAME_VPNCMGR_SHORT"),
			_UU("SW_LINK_NAME_VPNCMGR_COMMENT"), true));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmgr->DstFileName, NULL, NULL, 0, dir_startmenu,
			_UU("SW_LINK_NAME_VPNCMGR_SHORT"),
			_UU("SW_LINK_NAME_VPNCMGR_COMMENT"), true));

		// Programs\PacketiX VPN Client
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmgr->DstFileName, NULL, NULL, 0, dir_app_program,
			_UU("SW_LINK_NAME_VPNCMGR_FULL"),
			_UU("SW_LINK_NAME_VPNCMGR_COMMENT"), false));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmgr->DstFileName, L"/remote", L"vpnsetup.exe", 1, dir_app_program,
			_UU("SW_LINK_NAME_VPNCMGR2_FULL"),
			_UU("SW_LINK_NAME_VPNCMGR2_COMMENT"), false));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmd->DstFileName, NULL, NULL, 0, dir_app_program,
			_UU("SW_LINK_NAME_VPNCMD"),
			_UU("SW_LINK_NAME_VPNCMD_COMMENT"), false));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnclient->DstFileName, L"/traffic", L"vpnsetup.exe", 2, dir_admin_tools,
			_UU("SW_LINK_NAME_TRAFFIC"),
			_UU("SW_LINK_NAME_TRAFFIC_COMMENT"), false));

		// Programs\PacketiX VPN Client\Configuration Tools
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnclient->DstFileName, L"/tcp", L"vpnsetup.exe", 3, dir_config_program,
			_UU("SW_LINK_NAME_TCP"),
			_UU("SW_LINK_NAME_TCP_COMMENT"), false));

		if (MsIsWin2000OrGreater())
		{
			Add(t->LinkTasks, SwNewLinkTask(MsGetSystem32DirW(), L"services.msc", NULL, L"filemgmt.dll", 0, dir_config_program,
				_UU("SW_LINK_NAME_SERVICES"),
				_UU("SW_LINK_NAME_SERVICES_COMMENT"), false));

			if (sw->IsSystemMode)
			{
				// Debugging information collecting tool
				Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmd->DstFileName, L"/debug", L"vpnsetup.exe", 4, dir_admin_tools,
					_UU("SW_LINK_NAME_DEBUG"),
					_UU("SW_LINK_NAME_DEBUG_COMMENT"), false));
			}
		}

		// Programs\PacketiX VPN Client\System administrators tool
		if (MsIsNt())
		{
			Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, L"vpnsetup.exe", L"/easy:true", L"vpnsetup.exe", 12, dir_admin_tools,
				_UU("SW_LINK_NAME_EASYINSTALLER"),
				_UU("SW_LINK_NAME_EASYINSTALLER_COMMENT"), false));

			Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, L"vpnsetup.exe", L"/web:true", L"vpnsetup.exe", 1, dir_admin_tools,
				_UU("SW_LINK_NAME_WEBINSTALLER"),
				_UU("SW_LINK_NAME_WEBINSTALLER_COMMENT"), false));
		}

		// Startup
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmgr->DstFileName, L"/startup", NULL, 0, dir_startup,
			_UU("SW_LINK_NAME_VPNCMGRTRAY_FULL"),
			_UU("SW_LINK_NAME_VPNCMGRTRAY_COMMENT"), true));
	}
	else if (c->Id == SW_CMP_VPN_SMGR)
	{
		// VPN Server Manager (Tools Only)
		SW_TASK_COPY *vpncmd, *vpnsmgr;

		vpncmd = SwNewCopyTask(L"vpncmd.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);
		vpnsmgr = SwNewCopyTask(L"vpnsmgr.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);

		Add(t->CopyTasks, vpncmd);
		Add(t->CopyTasks, vpnsmgr);

		//// Definition of the shortcuts
		// Desktop and Start menu
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnsmgr->DstFileName, NULL, NULL, 0, dir_desktop,
			_UU(sw->IsSystemMode ? "SW_LINK_NAME_VPNSMGR_SHORT_TOOLSONLY" : "SW_LINK_NAME_VPNSMGR_SHORT_TOOLSONLY_UM"),
			_UU("SW_LINK_NAME_VPNSMGR_COMMENT"), true));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnsmgr->DstFileName, NULL, NULL, 0, dir_startmenu,
			_UU(sw->IsSystemMode ? "SW_LINK_NAME_VPNSMGR_SHORT_TOOLSONLY" : "SW_LINK_NAME_VPNSMGR_SHORT_TOOLSONLY_UM"),
			_UU("SW_LINK_NAME_VPNSMGR_COMMENT"), true));

		// Programs\PacketiX VPN Server Manager (Tools Only)
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpnsmgr->DstFileName, NULL, NULL, 0, dir_app_program,
			_UU("SW_LINK_NAME_VPNSMGR_FULL"),
			_UU("SW_LINK_NAME_VPNSMGR_COMMENT"), false));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmd->DstFileName, NULL, NULL, 0, dir_app_program,
			_UU("SW_LINK_NAME_VPNCMD"),
			_UU("SW_LINK_NAME_VPNCMD_COMMENT"), false));
	}
	else if (c->Id == SW_CMP_VPN_CMGR)
	{
		// VPN Client Manager (Tools Only)
		SW_TASK_COPY *vpncmd, *vpncmgr;

		vpncmd = SwNewCopyTask(L"vpncmd.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);
		vpncmgr = SwNewCopyTask(L"vpncmgr.exe", NULL, sw->InstallSrc, sw->InstallDir, true, false);

		Add(t->CopyTasks, vpncmd);
		Add(t->CopyTasks, vpncmgr);

		//// Definition of the shortcuts
		// Desktop and Start menu
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmgr->DstFileName, L"/remote", L"vpnsetup.exe", 1, dir_desktop,
			_UU(sw->IsSystemMode ? "SW_LINK_NAME_VPNCMGRTOOLS_SHORT" : "SW_LINK_NAME_VPNCMGRTOOLS_SHORT_UM"),
			_UU("SW_LINK_NAME_VPNCMGR2_COMMENT"), true));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmgr->DstFileName, L"/remote", L"vpnsetup.exe", 1, dir_startmenu,
			_UU(sw->IsSystemMode ? "SW_LINK_NAME_VPNCMGRTOOLS_SHORT" : "SW_LINK_NAME_VPNCMGRTOOLS_SHORT_UM"),
			_UU("SW_LINK_NAME_VPNCMGR2_COMMENT"), true));

		// Programs\PacketiX VPN Client Manager (Tools Only)
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmgr->DstFileName, L"/remote", L"vpnsetup.exe", 1, dir_app_program,
			_UU("SW_LINK_NAME_VPNCMGR2_FULL"),
			_UU("SW_LINK_NAME_VPNCMGR2_COMMENT"), false));
		Add(t->LinkTasks, SwNewLinkTask(sw->InstallDir, vpncmd->DstFileName, NULL, NULL, 0, dir_app_program,
			_UU("SW_LINK_NAME_VPNCMD"),
			_UU("SW_LINK_NAME_VPNCMD_COMMENT"), false));
	}

	// Uninstallation
	UniFormat(tmp1, sizeof(tmp1), _UU("SW_LINK_NAME_UNINSTALL"), c->Title);
	UniFormat(tmp2, sizeof(tmp2), _UU("SW_LINK_NAME_UNINSTALL_COMMENT"), c->Title);
	Add(t->LinkTasks, SwNewLinkTask(setup_exe->DstDir, setup_exe->DstFileName, NULL, NULL, 0, dir_config_program,
		tmp1,
		tmp2, false));

	// Language settings (except for Win9x)
	if (MsIsNt())
	{
		UniFormat(tmp1, sizeof(tmp1), _UU("SW_LINK_NAME_LANGUAGE"), c->Title);
		UniFormat(tmp2, sizeof(tmp2), _UU("SW_LINK_NAME_LANGUAGE_COMMENT"), c->Title);
		Add(t->LinkTasks, SwNewLinkTask(setup_exe->DstDir, setup_exe->DstFileName, L"/language:yes",
			L"vpnsetup.exe", 10, dir_config_language,
			tmp1,
			tmp2, false));
	}

	// Hamcore!
	Add(t->CopyTasks, SwNewCopyTask(L"hamcore.se2", NULL, sw->InstallSrc, sw->InstallDir, true, true));
}

// Build the Web installer
bool SwWebMain(SW *sw, WIZARD_PAGE *wp)
{
	bool ret = false;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (sw == NULL || wp == NULL)
	{
		return false;
	}

	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_WEB_INIT"));

	if (true)
	{
		wchar_t installer_src_exe[MAX_PATH];
		wchar_t src_cab[MAX_PATH];
		wchar_t vpninstall_exe[MAX_PATH];
		char inf_path[MAX_PATH];
		char htm_path[MAX_PATH];
		LANGLIST current_lang;
		BUF *inf_buf = NULL;
		BUF *htm_buf = NULL;
		BUF *setting_buf = NULL;
		char *inf_data = NULL;
		UINT inf_data_size;
		char *htm_data = NULL;
		UINT htm_data_size;
		char ver_major[64];
		char ver_minor[64];
		char ver_build[64];
		char *normal_mode = (sw->Web_EasyMode ? "false" : "true");
		char package_name[MAX_SIZE];
		ZIP_PACKER *z = NULL;

		ToStr(ver_major, CEDAR_VERSION_MAJOR);
		ToStr(ver_minor, CEDAR_VERSION_MINOR);
		ToStr(ver_build, CEDAR_VERSION_BUILD);

		Format(package_name, sizeof(package_name),
			GC_SW_SOFTETHER_PREFIX "vpnclient-v%u.%02u-%u-%04u-%02u-%02u-windows.exe",
			CEDAR_VERSION_MAJOR, CEDAR_VERSION_MINOR, CEDAR_VERSION_BUILD,
			BUILD_DATE_Y, BUILD_DATE_M, BUILD_DATE_D);

		GetCurrentLang(&current_lang);

		// Installer cache file
		CombinePathW(installer_src_exe, sizeof(installer_src_exe), MsGetExeDirNameW(), SW_SFX_CACHE_FILENAME);

		// Cab file
		CombinePathW(src_cab, sizeof(src_cab), MsGetExeDirNameW(), L"vpnweb.cab");

		// Vpninstall file
		CombinePathW(vpninstall_exe, sizeof(vpninstall_exe), MsGetExeDirNameW(), L"vpninstall.exe");

		// Confirm existence of the file
		if (IsFileExistsW(installer_src_exe) == false)
		{
			UniFormat(tmp, sizeof(tmp), _UU("SW_FILE_NOT_FOUNT"), installer_src_exe);
			SwPerformMsgBox(wp, MB_ICONSTOP, tmp);
			goto LABEL_CLEANUP;
		}
		if (IsFileExistsW(src_cab) == false)
		{
			UniFormat(tmp, sizeof(tmp), _UU("SW_FILE_NOT_FOUNT"), src_cab);
			SwPerformMsgBox(wp, MB_ICONSTOP, tmp);
			goto LABEL_CLEANUP;
		}
		if (IsFileExistsW(vpninstall_exe) == false)
		{
			UniFormat(tmp, sizeof(tmp), _UU("SW_FILE_NOT_FOUNT"), vpninstall_exe);
			SwPerformMsgBox(wp, MB_ICONSTOP, tmp);
			goto LABEL_CLEANUP;
		}

		// Read the configuration file
		setting_buf = ReadDumpW(sw->Web_SettingFile);
		if (setting_buf != NULL)
		{
			if (sw->Web_EraseSensitive)
			{
				// Remove the secret information
				CiEraseSensitiveInAccount(setting_buf);
			}
		}

		// Verify the signature of the installer cache file
		if (MsCheckFileDigitalSignatureW(NULL, installer_src_exe, NULL) == false)
		{
			// Installer cache file is not signed
			if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2,
				_UU("SW_INSTALLER_CACHE_IS_NOT_SIGNED")) == IDNO)
			{
				// Cancel
				goto LABEL_CLEANUP;
			}
		}

		// Read the .inf file
		Format(inf_path, sizeof(inf_path), "|vpninstall_%s.inf", current_lang.Name);

		inf_buf = ReadDump(inf_path);
		if (inf_buf == NULL)
		{
			goto LABEL_CLEANUP;
		}

		inf_data_size = (inf_buf->Size + 1024) * 2;
		inf_data = ZeroMalloc(inf_data_size);
		Copy(inf_data, inf_buf->Buf, inf_buf->Size);

		ReplaceStrEx(inf_data, inf_data_size, inf_data, "$VER_BUILD$", ver_build, false);
		ReplaceStrEx(inf_data, inf_data_size, inf_data, "$PACKAGE_FILENAME$", package_name, false);
		ReplaceStrEx(inf_data, inf_data_size, inf_data, "$NORMAL_MODE$", normal_mode, false);

		// Read the .htm file
		Format(htm_path, sizeof(htm_path), "|vpnweb_sample_%s.htm", current_lang.Name);

		htm_buf = ReadDump(htm_path);
		if (htm_buf == NULL)
		{
			goto LABEL_CLEANUP;
		}

		htm_data_size = (htm_buf->Size + 1024) * 2;
		htm_data = ZeroMalloc(htm_data_size);
		Copy(htm_data, htm_buf->Buf, htm_buf->Size);

		ReplaceStrEx(htm_data, htm_data_size, htm_data, "$VER_MAJOR$", ver_major, false);
		ReplaceStrEx(htm_data, htm_data_size, htm_data, "$VER_MINOR$", ver_minor, false);
		ReplaceStrEx(htm_data, htm_data_size, htm_data, "$VER_BUILD$", ver_build, false);

		// Creating a ZIP
		z = NewZipPacker();

		if (ZipAddRealFileW(z, "vpnweb.cab", 0, 0, src_cab) == false ||
			ZipAddRealFileW(z, "vpninstall.exe", 0, 0, vpninstall_exe) == false ||
			ZipAddRealFileW(z, package_name, 0, 0, installer_src_exe) == false)
		{
			goto LABEL_CLEANUP;
		}

		ZipAddFileSimple(z, "vpninstall.inf", 0, 0, inf_data, StrLen(inf_data));
		ZipAddFileSimple(z, "index.html", 0, 0, htm_data, StrLen(htm_data));
		ZipAddFileSimple(z, "auto_setting.vpn", 0, 0, setting_buf->Buf, setting_buf->Size);

		// Export
		if (ZipWriteW(z, sw->Web_OutFile))
		{
			ret = true;

			UniFormat(sw->FinishMsg, sizeof(sw->FinishMsg),
				_UU("SW_WEB_FINISHED"),
				sw->Web_OutFile);
		}

LABEL_CLEANUP:
		FreeZipPacker(z);
		FreeBuf(setting_buf);
		FreeBuf(inf_buf);
		FreeBuf(htm_buf);
		Free(inf_data);
		Free(htm_data);
	}


	return ret;
}

// Build a simple installer
bool SwEasyMain(SW *sw, WIZARD_PAGE *wp)
{
	LIST *o;
	BUF *b;
	bool ret = false;
	wchar_t account_tmp[MAX_PATH];
	// Validate arguments
	if (sw == NULL || wp == NULL)
	{
		return false;
	}

	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_EASY_INIT"));

	o = SwNewSfxFileList();

	SwAddBasicFilesToList(o, "vpnclient");

	// Load a connection setting file
	b = ReadDumpW(sw->Easy_SettingFile);
	if (b != NULL)
	{
		if (sw->Easy_EraseSensitive)
		{
			// Remove secret information
			CiEraseSensitiveInAccount(b);
		}

		// Save to a temporary folder
		CombinePathW(account_tmp, sizeof(account_tmp), MsGetMyTempDirW(), L"vpn_setting.vpn");
		if (DumpBufW(b, account_tmp))
		{
			// Add a connection settings to file list of SFX
			Add(o, SwNewSfxFile(SW_AUTO_CONNECT_ACCOUNT_FILE_NAME, account_tmp));

			if (sw->Easy_EasyMode)
			{
				// Set the connection manager to simple mode
				Add(o, SwNewSfxFile(SW_FLAG_EASY_MODE, account_tmp));
			}

			if (SwCompileSfx(o, sw->Easy_OutFile))
			{
				ret = true;
			}

			FileDeleteW(account_tmp);
		}

		FreeBuf(b);
	}

	SwFreeSfxFileList(o);

	if (ret)
	{
		// Completion message
		UniFormat(sw->FinishMsg, sizeof(sw->FinishMsg), _UU("SW_EASY_FINISHED_MSG"), sw->Easy_OutFile);
	}

	return ret;
}

// Installation main
bool SwInstallMain(SW *sw, WIZARD_PAGE *wp, SW_COMPONENT *c)
{
	SW_TASK *t;
	bool ret = false;
	UINT i;
	wchar_t tmp[MAX_SIZE * 2];
	bool ok;
	// Validate arguments
	if (sw == NULL || wp == NULL || c == NULL)
	{
		return false;
	}

	ok = true;
	t = NULL;

	// Create a Setup task
	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_INIT_TASKS"));
	t = SwNewTask();

	// Create a list of files to be installed
	SwDefineTasks(sw, t, c);

	if (sw->LanguageMode)
	{
		goto LABEL_CREATE_SHORTCUT;
	}

	if (sw->OnlyAutoSettingMode)
	{
		goto LABEL_IMPORT_SETTING;
	}

	// Install the SeLow
	if (SuIsSupportedOs(true))
	{
		// Only in the system mode
		if (c->InstallService && sw->IsSystemMode)
		{
			// Not to install in the case of the VPN Client
			bool install_su = false;

			if (c->Id != SW_CMP_VPN_CLIENT)
			{
				install_su = true;
			}


			if (install_su)
			{
				bool ret;

				SwPerformPrint(wp, _UU("SW_PERFORM_MSG_INSTALL_SELOW"));
				ret = SuInstallDriver(false);

				if (ret == false)
				{
					if (MsIs64BitWindows() && MsIsWindows10())
					{
						void *proc_handle = NULL;
						wchar_t exe[MAX_PATH];

						CombinePathW(exe, sizeof(exe), MsGetExeDirNameW(), L"vpnsetup.exe");

						if (MsExecuteEx2W(exe, L"/SUINSTMODE:yes", &proc_handle, true))
						{
							if (proc_handle != NULL)
							{
								MsWaitProcessExit(proc_handle);
							}
						}
					}
				}
			}
		}
	}

	// Uninstall the old MSI
	ok = true;
	if (sw->IsSystemMode && c->OldMsiList != NULL)
	{
		bool reboot_required = false;

		if (SwUninstallOldMsiInstalled(wp->Wizard->hWndWizard, wp, c, &reboot_required) == false)
		{
			// MSI uninstall Failed
			ok = false;
		}
		else if (reboot_required)
		{
			// Require to restart
			ok = false;

			sw->MsiRebootRequired = true;
		}
	}

	if (ok == false)
	{
		goto LABEL_CLEANUP;
	}

	// Stop the Service
	ok = true;

	if (c->InstallService)
	{
		char svc_title_name[MAX_SIZE];
		wchar_t *svc_title;

		Format(svc_title_name, sizeof(svc_title_name), "SVC_%s_TITLE", c->SvcName);

		svc_title = _UU(svc_title_name);

		if (UniIsEmptyStr(svc_title) == false)
		{
			if (sw->IsSystemMode && MsIsNt())
			{
				// WinNT and system mode
				if (MsIsServiceRunning(c->SvcName))
				{
					wchar_t svc_exe[MAX_SIZE];
					UINT64 giveup_tick;
					UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_STOP_SVC"), svc_title);
					SwPerformPrint(wp, tmp);

LABEL_RETRY_3:
					if (MsStopService(c->SvcName) == false)
					{
						UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_STOP_SVC_ERROR"), svc_title, c->SvcName);
						if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_RETRYCANCEL, tmp) != IDRETRY)
						{
							// Cancel
							ok = false;
						}
						else
						{
							if (MsIsServiceRunning(c->SvcName))
							{
								goto LABEL_RETRY_3;
							}
						}
					}

					// Wait for 5 seconds if stopped the service
					SleepThread(5000);

					// Wait until the EXE file for the service become ready to write
					ConbinePathW(svc_exe, sizeof(svc_exe), sw->InstallDir, c->SvcFileName);

					giveup_tick = Tick64() + (UINT64)10000;
					while (IsFileWriteLockedW(svc_exe))
					{
						UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_WAIT_FOR_FILE_UNLOCK"), svc_exe);
						SwPerformPrint(wp, tmp);

						SleepThread(100);

						if (Tick64() >= giveup_tick)
						{
							break;
						}
					}
				}
			}
			else
			{
				// In the case of Win9x or user mode
				wchar_t svc_exe[MAX_SIZE];
				UINT64 giveup_tick;

				// Stop the Service
				MsStopUserModeSvc(c->SvcName);
				SleepThread(3000);

				// Wait until the EXE file for the service become ready to write
				ConbinePathW(svc_exe, sizeof(svc_exe), sw->InstallDir, c->SvcFileName);

				giveup_tick = Tick64() + (UINT64)10000;
				while (IsFileWriteLockedW(svc_exe))
				{
					UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_WAIT_FOR_FILE_UNLOCK"), svc_exe);
					SwPerformPrint(wp, tmp);

					SleepThread(100);

					if (Tick64() >= giveup_tick)
					{
						break;
					}
				}
			}
		}
	}

	if (ok == false)
	{
		goto LABEL_CLEANUP;
	}

	// Examine preliminary whether files to be copied are writable successfully
	ok = true;

	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_COPY_PREPARE"));

	for (i = 0;i < LIST_NUM(t->CopyTasks);i++)
	{
		SW_TASK_COPY *ct = LIST_DATA(t->CopyTasks, i);

		wchar_t fullpath[MAX_SIZE];
		IO *io;
		bool write_ok;
		bool new_file;
		bool new_dir;
		UINT64 giveup_tick = Tick64() + 30000ULL;

LABEL_RETRY_1:
		new_dir = write_ok = new_file = false;

		CombinePathW(fullpath, sizeof(fullpath), ct->DstDir, ct->DstFileName);

		if (ct->Overwrite == false)
		{
			// Do not check if overwrite is Off
			continue;
		}

		// If the process with the same name is running, kill it
		if (MsKillProcessByExeName(fullpath) != 0)
		{
			// Wait for 1 second if killed the process
			SleepThread(1000);
		}

		new_dir = MakeDirExW(ct->DstDir);

		// Write check
		io = FileOpenExW(fullpath, true, true);
		if (io == NULL)
		{
			io = FileCreateW(fullpath);
			new_file = true;
		}
		if (io != NULL)
		{
			// Writing OK
			write_ok = true;

			FileCloseEx(io, true);

			if (new_file)
			{
				FileDeleteW(fullpath);
			}
		}

		if (new_dir)
		{
			DeleteDirW(ct->DstDir);
		}

		if (write_ok == false)
		{
			UINT64 now = Tick64();

			if (now <= giveup_tick)
			{
				// Do the auto-retry in 30 seconds
				SleepThread(1000);
				goto LABEL_RETRY_1;
			}

			// Show an error message if it fails
			UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_WRITE_ERROR"), fullpath, c->Title);
			if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_RETRYCANCEL, tmp) != IDRETRY)
			{
				// Cancel
				ok = false;
				break;
			}
			else
			{
				// Retry
				goto LABEL_RETRY_1;
			}
		}
	}

	if (ok == false)
	{
		goto LABEL_CLEANUP;
	}

	// File Copy
	ok = true;

	for (i = 0;i < LIST_NUM(t->CopyTasks);i++)
	{
		SW_TASK_COPY *ct = LIST_DATA(t->CopyTasks, i);
		wchar_t fullpath_src[MAX_SIZE];
		wchar_t fullpath_dst[MAX_SIZE];
		bool skip;

LABEL_RETRY_2:

		if (UniStartWith(ct->SrcFileName, L"|") == false)
		{
			CombinePathW(fullpath_src, sizeof(fullpath_src), ct->SrcDir, ct->SrcFileName);
		}
		else
		{
			UniStrCpy(fullpath_src, sizeof(fullpath_src), ct->SrcFileName);
		}

		CombinePathW(fullpath_dst, sizeof(fullpath_dst), ct->DstDir, ct->DstFileName);

		UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_COPY_FILE"), fullpath_dst);
		SwPerformPrint(wp, tmp);

		skip = false;

		if (ct->Overwrite == false)
		{
			if (IsFileExistsW(fullpath_dst))
			{
				// Do nothing because the destination file already exists
				skip = true;
			}
		}

		if (skip == false)
		{
			// Create a directory
			if (MakeDirExW(ct->DstDir))
			{
				SwAddLog(sw, sw->LogFile, SW_LOG_TYPE_DIR, ct->DstDir);
			}

			// Copy
			if (FileCopyW(fullpath_src, fullpath_dst) == false && ct->Overwrite)
			{
				// Show an error message if it fails
				UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_COPY_ERROR"), fullpath_dst);
				if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_RETRYCANCEL, tmp) != IDRETRY)
				{
					// Cancel
					ok = false;
					break;
				}
				else
				{
					// Retry
					goto LABEL_RETRY_2;
				}
			}
			else
			{
				if (ct->Overwrite && ct->SetupFile == false)
				{
					SwAddLog(sw, sw->LogFile, SW_LOG_TYPE_FILE, fullpath_dst);
				}
			}
		}
	}

	if (ok == false)
	{
		goto LABEL_CLEANUP;
	}


	if (sw->IsSystemMode && MsIsNt())
	{
		// ACL settings only in the system mode
		for (i = 0;i < LIST_NUM(t->SetSecurityPaths);i++)
		{
			// Security Settings
			wchar_t *path = LIST_DATA(t->SetSecurityPaths, i);

			UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_SET_SECURITY"), path);
			SwPerformPrint(wp, tmp);

			MsSetFileSecureAcl(path);
		}
	}

	// Set the language of the destination
	if (true)
	{
		LANGLIST current_lang;
		wchar_t langfilename[MAX_PATH];

		Zero(&current_lang, sizeof(current_lang));
		GetCurrentLang(&current_lang);

		ConbinePathW(langfilename, sizeof(langfilename), sw->InstallDir, L"lang.config");

		SaveLangConfig(langfilename, current_lang.Name);
	}

	// Firewall registration
	if (true)
	{
		char dira[MAX_PATH];

		UniToStr(dira, sizeof(dira), sw->InstallDir);

		RegistWindowsFirewallAllEx(dira);
	}

	if (c->Id == SW_CMP_VPN_SERVER || c->Id == SW_CMP_VPN_BRIDGE)
	{
		// Disable the off-loading
		MsDisableNetworkOffloadingEtc();
	}

	// Install the service
	ok = true;

	if (c->InstallService)
	{
		char svc_title_name[MAX_SIZE];
		char svc_description_name[MAX_SIZE];
		wchar_t *svc_title;

		Format(svc_title_name, sizeof(svc_title_name), "SVC_%s_TITLE", c->SvcName);
		Format(svc_description_name, sizeof(svc_description_name), "SVC_%s_DESCRIPT", c->SvcName);

		svc_title = _UU(svc_title_name);

		if (UniIsEmptyStr(svc_title) == false)
		{
			if (sw->IsSystemMode == false || MsIsNt() == false)
			{
				// Just simply start in user mode or Win9x mode
				wchar_t fullpath[MAX_SIZE];

LABEL_RETRY_USERMODE_EXEC:

				CombinePathW(fullpath, sizeof(fullpath), sw->InstallDir, c->SvcFileName);

				if (MsExecuteW(fullpath, (MsIsNt() ? L"/usermode" : L"/win9x_service")) == false)
				{
					UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_SVC_USERMODE_EXEC_FAILED"), fullpath);

					if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_RETRYCANCEL, tmp) != IDRETRY)
					{
						// Cancel
						ok = false;
					}
					else
					{
						// Retry
						goto LABEL_RETRY_USERMODE_EXEC;
					}
				}
				else
				{
					if (MsIsNt() == false)
					{
						// Register into the registry as a background service in the case of Win9x
						wchar_t fullpath2[MAX_SIZE];

						UniFormat(fullpath2, sizeof(fullpath2), L"\"%s\" /win9x_service", fullpath);

						MsRegWriteStrW(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_1, c->SvcName, fullpath2);
						MsRegWriteStrW(REG_LOCAL_MACHINE, WIN9X_SVC_REGKEY_2, c->SvcName, fullpath2);
					}
				}
			}
			else
			{
				// System mode
				UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_INSTALL_SVC"), svc_title);
				SwPerformPrint(wp, tmp);

LABEL_RETRY_4:

				if (MsIsServiceInstalled(c->SvcName))
				{
					// Stop the service if it is running by any chance
					MsStopService(c->SvcName);
				}

				if (MsIsServiceInstalled(c->SvcName))
				{
					// Uninstall the old service
					if (MsUninstallService(c->SvcName) == false)
					{
						// Show an error message if it fails
						UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_SVC_UNINSTALL_FAILED"), svc_title, c->SvcName);
						if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_RETRYCANCEL, tmp) != IDRETRY)
						{
							// Cancel
							ok = false;
						}
						else
						{
							// Retry
							goto LABEL_RETRY_4;
						}
					}
				}

				if (ok)
				{
					wchar_t fullpath[MAX_SIZE];
					wchar_t fullpath2[MAX_SIZE];

					CombinePathW(fullpath2, sizeof(fullpath), sw->InstallDir, c->SvcFileName);
					UniFormat(fullpath, sizeof(fullpath), L"\"%s\" /service", fullpath2);

					// Install a new service
					if (MsInstallServiceW(c->SvcName, svc_title, _UU(svc_description_name), fullpath) == false)
					{
						// Show the error message if it fails
						UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_SVC_INSTALL_FAILED"), svc_title, c->SvcName);
						if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_RETRYCANCEL, tmp) != IDRETRY)
						{
							// Cancel
							ok = false;
						}
						else
						{
							// Retry
							goto LABEL_RETRY_4;
						}
					}
					else
					{
						wchar_t wtmp[256];

						StrToUni(wtmp, sizeof(wtmp), c->SvcName);
						SwAddLog(sw, sw->LogFile, SW_LOG_TYPE_SVC, wtmp);
					}
				}

				if (ok)
				{
					UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_START_SVC"), svc_title);
					SwPerformPrint(wp, tmp);

					MsRegWriteIntEx2(REG_LOCAL_MACHINE, "Software\\" GC_REG_COMPANY_NAME "\\Update Service Config", c->SvcName, 0, false, true);

LABEL_RETRY_5:
					// Start the service
					if (MsStartService(c->SvcName) == false)
					{
						// Show the error message if it fails
						UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_START_SVC_ERROR"), svc_title, c->SvcName);
						if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_RETRYCANCEL, tmp) != IDRETRY)
						{
							// Cancel
							ok = false;
						}
						else
						{
							// Retry
							if (MsIsServiceRunning(c->SvcName) == false)
							{
								goto LABEL_RETRY_5;
							}
						}
					}
				}
			}

			if (c->Id == SW_CMP_VPN_CLIENT)
			{
				// In the VPN Client service, wait until the service port can be connected
				SwWaitForVpnClientPortReady(SW_VPNCLIENT_SERVICE_WAIT_READY_TIMEOUT);
			}
		}
	}

	if (ok == false)
	{
		goto LABEL_CLEANUP;
	}

LABEL_CREATE_SHORTCUT:

	// Create a shortcut
	SwInstallShortcuts(sw, wp, c, t);

	if (sw->LanguageMode)
	{
		// Update the Description of the service if in the language setting mode
		if (c->InstallService)
		{
			char svc_description_name[MAX_SIZE];
			wchar_t *svc_description;

			Format(svc_description_name, sizeof(svc_description_name), "SVC_%s_DESCRIPT", c->SvcName);

			svc_description = _UU(svc_description_name);

			if (UniIsEmptyStr(svc_description) == false)
			{
				if (sw->IsSystemMode && MsIsNt())
				{
					MsSetServiceDescription(c->SvcName, svc_description);
				}
			}
		}

		goto LABEL_REGISTER_UNINSTALL;
	}

	if (c->Id == SW_CMP_VPN_CLIENT)
	{
		// Register the UI Helper in the Run in the case of the VPN Client
		wchar_t fullpath[MAX_PATH];
		wchar_t fullcmd[MAX_SIZE];

		ConbinePathW(fullpath, sizeof(fullpath), sw->InstallDir, c->SvcFileName);

		UniFormat(fullcmd, sizeof(fullcmd), L"\"%s\" /uihelp", fullpath);

		MsRegWriteStrEx2W(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			SW_VPN_CLIENT_UIHELPER_REGVALUE, fullcmd, false, true);

		// Start the UI Helper
		MsExecuteW(fullpath, L"/uihelp");

		SleepThread(3000);
	}

	if (true)
	{
		// Run the vpncmd and exit immediately
		wchar_t fullpath[MAX_PATH];

		ConbinePathW(fullpath, sizeof(fullpath), sw->InstallDir, (L"vpncmd.exe"));

		RunW(fullpath, L"/?", true, false);
	}

	if (c->Id == SW_CMP_VPN_CLIENT)
	{
		wchar_t dst_vpnclient_exe[MAX_PATH];
		wchar_t vpnclient_arg[MAX_SIZE];

		ConbinePathW(dst_vpnclient_exe, sizeof(dst_vpnclient_exe), sw->InstallDir, c->SvcFileName);
		UniFormat(vpnclient_arg, sizeof(vpnclient_arg), L"\"%s\" \"%%1\"", dst_vpnclient_exe);

		// Register the association to .vpn file in the case of VPN Client
		MsRegWriteStrEx2(REG_LOCAL_MACHINE, SW_VPN_CLIENT_EXT_REGKEY, NULL, SW_VPN_CLIENT_EXT_REGVALUE, false, true);
		SwAddLogA(sw, sw->LogFile, SW_LOG_TYPE_REGISTRY, SW_VPN_CLIENT_EXT_REGKEY);

		MsRegNewKeyEx2(REG_LOCAL_MACHINE, SW_VPN_CLIENT_EXT_REGKEY_SUB1, false, true);
		MsRegNewKeyEx2(REG_LOCAL_MACHINE, SW_VPN_CLIENT_EXT_REGKEY_SUB2, false, true);
		SwAddLogA(sw, sw->LogFile, SW_LOG_TYPE_REGISTRY, SW_VPN_CLIENT_EXT_REGKEY_SUB1);
		SwAddLogA(sw, sw->LogFile, SW_LOG_TYPE_REGISTRY, SW_VPN_CLIENT_EXT_REGKEY_SUB2);

		MsRegWriteStrEx2(REG_LOCAL_MACHINE, SW_VPN_CLIENT_VPNFILE_REGKEY, NULL, SW_VPN_CLIENT_VPNFILE_REGVALUE, false, true);
		SwAddLogA(sw, sw->LogFile, SW_LOG_TYPE_REGISTRY, SW_VPN_CLIENT_VPNFILE_REGKEY);

		MsRegWriteStrEx2W(REG_LOCAL_MACHINE, SW_VPN_CLIENT_VPNFILE_ICON_REGKEY, NULL, dst_vpnclient_exe, false, true);
		SwAddLogA(sw, sw->LogFile, SW_LOG_TYPE_REGISTRY, SW_VPN_CLIENT_VPNFILE_ICON_REGKEY);

		MsRegWriteStrEx2W(REG_LOCAL_MACHINE, SW_VPN_CLIENT_VPNFILE_SHELLOPEN_CMD_REGKEY, NULL, vpnclient_arg, false, true);
		SwAddLogA(sw, sw->LogFile, SW_LOG_TYPE_REGISTRY, SW_VPN_CLIENT_VPNFILE_SHELLOPEN_CMD_REGKEY_SUB2);
		SwAddLogA(sw, sw->LogFile, SW_LOG_TYPE_REGISTRY, SW_VPN_CLIENT_VPNFILE_SHELLOPEN_CMD_REGKEY_SUB1);
		SwAddLogA(sw, sw->LogFile, SW_LOG_TYPE_REGISTRY, SW_VPN_CLIENT_VPNFILE_SHELLOPEN_CMD_REGKEY);
	}

	if (c->Id == SW_CMP_VPN_CLIENT)
	{
		// Disable the MMCSS
		MsSetMMCSSNetworkThrottlingEnable(false);
	}

LABEL_IMPORT_SETTING:
	if (c->Id == SW_CMP_VPN_CLIENT)
	{
		if (UniIsEmptyStr(sw->auto_setting_path) == false)
		{
			if (UniIsEmptyStr(sw->vpncmgr_path) == false)
			{
				if (sw->DisableAutoImport == false)
				{
					wchar_t tmp_setting_path[MAX_PATH];
					wchar_t arg[MAX_PATH];
					void *handle;
					bool easy_mode = IsFileExists(SW_FLAG_EASY_MODE_2);
					// Run the vpncmgr, and start a connection by importing the connection configuration file
					// Store a connection setting file to stable temporally directory

					SwPerformPrint(wp, _UU("SW_PERFORM_MSG_IMPORTING_ACCOUNT"));

					ConbinePathW(tmp_setting_path, sizeof(tmp_setting_path), MsGetTempDirW(), L"vpn_auto_connect.vpn");
					FileCopyW(sw->auto_setting_path, tmp_setting_path);

					// Start the vpncmgr
					UniFormat(arg, sizeof(arg), L"/%S \"%s\"", (easy_mode ? "easy" : "normal"), tmp_setting_path);
					handle = MsRunAsUserExW(sw->vpncmgr_path, arg, false);

					if (handle != NULL)
					{
						sw->HideStartCommand = true;

						CloseHandle(handle);
					}
				}
			}
		}
	}

	if (sw->OnlyAutoSettingMode)
	{
		goto LABEL_FINISHED;
	}

LABEL_REGISTER_UNINSTALL:
	// Register the uninstall information
	if (sw->IsSystemMode)
	{
		char uninstall_keyname[MAX_SIZE];
		wchar_t uninstall_keyname_w[MAX_SIZE];
		char uninstall_version[MAX_SIZE];
		wchar_t dst_setup_exe[MAX_PATH];
		wchar_t setup_icon[MAX_SIZE];
		wchar_t uninstaller_exe[MAX_PATH];
		SYSTEMTIME st;
		char install_date[MAX_PATH];

		SwPerformPrint(wp, _UU("SW_PERFORM_MSG_REGISTER_UNINSTALL"));

		Zero(&st, sizeof(st));
		LocalTime(&st);

		Format(install_date, sizeof(install_date), "%04u/%02u/%02u", st.wYear, st.wMonth, st.wDay);

		CombinePathW(dst_setup_exe, sizeof(dst_setup_exe), sw->InstallDir, L"vpnsetup.exe");

		Format(uninstall_keyname, sizeof(uninstall_keyname),
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\softether_" GC_SW_SOFTETHER_PREFIX "%s", c->Name);
		StrToUni(uninstall_keyname_w, sizeof(uninstall_keyname_w), uninstall_keyname);

		GetCedarVersion(uninstall_version, sizeof(uninstall_version));

		// Display name
		MsRegWriteStrEx2W(REG_LOCAL_MACHINE, uninstall_keyname, "DisplayName", c->LongName,
			false, true);

		// Version
		MsRegWriteStrEx2(REG_LOCAL_MACHINE, uninstall_keyname, "DisplayVersion", uninstall_version,
			false, true);

		// Icon
		UniFormat(setup_icon, sizeof(setup_icon), L"\"%s\",%u", dst_setup_exe, c->IconExeIndex);
		MsRegWriteStrEx2W(REG_LOCAL_MACHINE, uninstall_keyname, "DisplayIcon", setup_icon,
			false, true);

		// Information
		MsRegWriteIntEx2(REG_LOCAL_MACHINE, uninstall_keyname, "NoModify", 1, false, true);
		MsRegWriteIntEx2(REG_LOCAL_MACHINE, uninstall_keyname, "NoRepair", 1, false, true);

		// Link
		MsRegWriteStrEx2(REG_LOCAL_MACHINE, uninstall_keyname, "HelpLink", _SS("SW_UNINSTALLINFO_URL"),
			false, true);
		MsRegWriteStrEx2(REG_LOCAL_MACHINE, uninstall_keyname, "URLInfoAbout", _SS("SW_UNINSTALLINFO_URL"),
			false, true);
		MsRegWriteStrEx2(REG_LOCAL_MACHINE, uninstall_keyname, "URLUpdateInfo", _SS("SW_UNINSTALLINFO_URL"),
			false, true);

		// Publisher
		MsRegWriteStrEx2W(REG_LOCAL_MACHINE, uninstall_keyname, "Publisher", _UU("SW_UNINSTALLINFO_PUBLISHER"),
			false, true);

		// Date of installation
		MsRegWriteStrEx2(REG_LOCAL_MACHINE, uninstall_keyname, "InstallDate", install_date,
			false, true);

		// Uninstaller
		UniFormat(uninstaller_exe, sizeof(uninstaller_exe), L"\"%s\"", dst_setup_exe);
		MsRegWriteStrEx2W(REG_LOCAL_MACHINE, uninstall_keyname, "UninstallString", uninstaller_exe,
			false, true);

		if (sw->LanguageMode == false)
		{
			SwAddLog(sw, sw->LogFile, SW_LOG_TYPE_REGISTRY, uninstall_keyname_w);
		}
	}

	// Write the log
	if (true)
	{
		wchar_t log_filename[MAX_SIZE];

L_RETRY_LOG:

		SwPerformPrint(wp, _UU("SW_PERFORM_MSG_WRITE_LOG"));

		CombinePathW(log_filename, sizeof(log_filename), sw->InstallDir, L"setuplog.dat");

		if (sw->LanguageMode == false)
		{
			SwAddLog(sw, sw->LogFile, SW_LOG_TYPE_FILE, log_filename);
		}

		sw->LogFile->IsSystemMode = sw->IsSystemMode;
		sw->LogFile->Component = sw->CurrentComponent;
		sw->LogFile->Build = CEDAR_VERSION_BUILD;

		if (SwSaveLogFile(sw, log_filename, sw->LogFile) == false)
		{
			// Show the error message if it fails
			UINT msgret;
			UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_WRITE_LOG_ERROR"), log_filename);
			msgret = SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_YESNO, tmp);

			if (msgret == IDYES)
			{
				// Retry
				goto L_RETRY_LOG;
			}
		}
	}

	if (true)
	{
		// Record the installed build number and directory in the registry
		char keyname[MAX_SIZE];
		LANGLIST current_lang;
		LANGLIST current_os_lang;

		GetCurrentLang(&current_lang);
		GetCurrentLang(&current_os_lang);

		Format(keyname, sizeof(keyname), "%s\\%s", SW_REG_KEY, sw->CurrentComponent->Name);
		MsRegWriteStrEx2W(sw->IsSystemMode ? REG_LOCAL_MACHINE : REG_CURRENT_USER,
			keyname, "InstalledDir", sw->InstallDir, false, true);
		MsRegWriteIntEx2(sw->IsSystemMode ? REG_LOCAL_MACHINE : REG_CURRENT_USER,
			keyname, "InstalledBuild", CEDAR_VERSION_BUILD, false, true);

		// Set the language to registry
		MsRegWriteStrEx2(REG_CURRENT_USER, SW_REG_KEY, "Last User Language",
			current_lang.Name, false, true);
		MsRegWriteStrEx2(REG_CURRENT_USER, SW_REG_KEY, "Last Operating System Language",
			current_os_lang.Name, false, true);

		// Save the EULA agreement record
		if (sw->EulaAgreed && sw->CurrentEulaHash != 0)
		{
			MsRegWriteIntEx2(REG_CURRENT_USER, SW_REG_KEY_EULA, sw->CurrentComponent->Name,
				sw->CurrentEulaHash, false, true);
		}
	}

	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_UPDATING"));

	// Notify the update to the system
	MsUpdateSystem();

	if (sw->LanguageMode)
	{
		// Show a message that the language configuration is complete
		wchar_t msg[MAX_SIZE];

		UniFormat(msg, sizeof(msg), _UU("SW_LANG_OK"), c->Title, c->Title);

		if (c->InstallService)
		{
			UniStrCat(msg, sizeof(msg), _UU("SW_LANG_OK_SERVICE"));
		}

		if (c->Id == SW_CMP_VPN_CLIENT)
		{
			UniStrCat(msg, sizeof(msg), _UU("SW_LANG_OK_VPNCMGR"));
		}

		UniStrCpy(sw->FinishMsg, sizeof(sw->FinishMsg), msg);
	}

LABEL_FINISHED:

	// Completion message
	SwPerformPrint(wp, _UU("SW_PERFORM_MSG_FINISHED"));

	ret = true;

LABEL_CLEANUP:
	// Release the task
	if (t != NULL)
	{
		SwFreeTask(t);
	}

	return ret;
}

// Wait for that the listening port of the VPN Client service becomes available
bool SwWaitForVpnClientPortReady(UINT timeout)
{
	UINT64 start, giveup;
	bool ret = false;
	if (timeout == 0)
	{
		timeout = SW_VPNCLIENT_SERVICE_WAIT_READY_TIMEOUT;
	}

	start = Tick64();
	giveup = start + (UINT64)timeout;

	while (Tick64() < giveup)
	{
		if (CheckTCPPortEx("localhost", CLIENT_CONFIG_PORT, 1000))
		{
			ret = true;
			break;
		}

		SleepThread(1000);
	}

	return ret;
}

// Create a Shortcut file (Delete the old one)
void SwInstallShortcuts(SW *sw, WIZARD_PAGE *wp, SW_COMPONENT *c, SW_TASK *t)
{
	UINT i;
	wchar_t tmp[MAX_SIZE];
	wchar_t setuplog[MAX_PATH];
	LIST *o;
	SW_LOGFILE *oldlog;
	// Validate arguments
	if (sw == NULL || wp == NULL || c == NULL || t == NULL)
	{
		return;
	}

	// If there is an old setup log, read it
	CombinePathW(setuplog, sizeof(setuplog), sw->InstallDir, L"setuplog.dat");
	oldlog = SwLoadLogFile(sw, setuplog);
	if (oldlog != NULL)
	{
		SwPerformPrint(wp, _UU("SW_PERFORM_MSG_DELETE_OLD_LINKS"));

		SwDeleteShortcuts(oldlog);

		SwFreeLogFile(oldlog);
	}

	// Remove only the shortcut setup log from the current log
	o = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(sw->LogFile->LogList);i++)
	{
		SW_LOG *g = LIST_DATA(sw->LogFile->LogList, i);

		if (g->Type == SW_LOG_TYPE_LNK || g->Type == SW_LOG_TYPE_LNK_DIR)
		{
			Add(o, g);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SW_LOG *g = LIST_DATA(o, i);

		Delete(sw->LogFile->LogList, g);

		Free(g);
	}

	ReleaseList(o);

	for (i = 0;i < LIST_NUM(t->LinkTasks);i++)
	{
		SW_TASK_LINK *lt = LIST_DATA(t->LinkTasks, i);
		wchar_t lnk_fullpath[MAX_SIZE];
		wchar_t lnk_dirname[MAX_SIZE];
		wchar_t target_fullpath[MAX_SIZE];
		wchar_t target_dirname[MAX_SIZE];
		wchar_t icon_fullpath[MAX_SIZE];

L_RETRY_LINK:

		SwPerformPrint(wp, _UU("SW_PERFORM_MSG_CREATE_LINKS"));

		// Generate the full path of the LNK file
		CombinePathW(lnk_fullpath, sizeof(lnk_fullpath), lt->DestDir, lt->DestName);
		UniStrCat(lnk_fullpath, sizeof(lnk_fullpath), L".lnk");

		// Get the directory name to be saved the LNK file
		GetDirNameFromFilePathW(lnk_dirname, sizeof(lnk_dirname), lnk_fullpath);

		// Generate the full path to the link destination
		CombinePathW(target_fullpath, sizeof(target_fullpath), lt->TargetDir, lt->TargetExe);

		// Create the full path of the icon
		CombinePathW(icon_fullpath, sizeof(icon_fullpath), lt->TargetDir, lt->IconExe);

		// Get the directory name of the full path to the link destination
		GetDirNameFromFilePathW(target_dirname, sizeof(target_dirname), target_fullpath);

		// Create a directory
		MakeDirExW(lnk_dirname);
		if (lt->NoDeleteDir == false)
		{
			SwAddLog(sw, sw->LogFile, SW_LOG_TYPE_LNK_DIR, lnk_dirname);
		}

		// Create the LNK file
		if (CreateLink(lnk_fullpath, target_fullpath, target_dirname, lt->TargetArg,
			lt->DestDescription, icon_fullpath, lt->IconIndex) == false)
		{
			// Show the error message if it fails
			UINT msgret;
			UniFormat(tmp, sizeof(tmp), _UU("SW_PERFORM_MSG_CREATE_LINK_ERROR"), lnk_fullpath);
			msgret = SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_YESNO, tmp);

			if (msgret == IDYES)
			{
				// Retry
				goto L_RETRY_LINK;
			}
		}
		else
		{
			SwAddLog(sw, sw->LogFile, SW_LOG_TYPE_LNK, lnk_fullpath);
		}
	}
}

// Search component
SW_COMPONENT *SwFindComponent(SW *sw, char *name)
{
	UINT i;
	// Validate arguments
	if (sw == NULL || IsEmptyStr(name))
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(sw->ComponentList);i++)
	{
		SW_COMPONENT *c = LIST_DATA(sw->ComponentList, i);

		if (StrCmpi(c->Name, name) == 0)
		{
			return c;
		}
	}

	return NULL;
}

// Release the log file
void SwFreeLogFile(SW_LOGFILE *logfile)
{
	UINT i;
	// Validate arguments
	if (logfile == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(logfile->LogList);i++)
	{
		SW_LOG *g = LIST_DATA(logfile->LogList, i);

		Free(g);
	}

	ReleaseList(logfile->LogList);

	Free(logfile);
}

// Create a new log file
SW_LOGFILE *SwNewLogFile()
{
	SW_LOGFILE *logfile = ZeroMalloc(sizeof(SW_LOGFILE));

	logfile->LogList = NewListFast(NULL);

	return logfile;
}

// Read the log file
SW_LOGFILE *SwLoadLogFile(SW *sw, wchar_t *filename)
{
	FOLDER *r = NULL;
	FOLDER *items = NULL;
	FOLDER *info = NULL;
	UINT i;
	TOKEN_LIST *t = NULL;
	bool is_system_mode = false;
	char component_name[MAX_SIZE] = { 0 };
	UINT build;
	SW_COMPONENT *c = NULL;
	SW_LOGFILE *ret = NULL;
	// Validate arguments
	if (sw == NULL || filename == NULL)
	{
		return NULL;
	}

	r = CfgReadW(filename);
	if (r == NULL)
	{
		goto LABEL_CLEANUP;
	}

	items = CfgGetFolder(r, "Items");
	info = CfgGetFolder(r, "Info");
	if (items == NULL || info == NULL)
	{
		goto LABEL_CLEANUP;
	}

	t = CfgEnumFolderToTokenList(items);
	if (t == NULL)
	{
		goto LABEL_CLEANUP;
	}

	// Mode and components
	is_system_mode = CfgGetBool(info, "IsSystemMode");
	CfgGetStr(info, "ComponentName", component_name, sizeof(component_name));
	build = CfgGetInt(info, "Build");

	if (build == 0)
	{
		goto LABEL_CLEANUP;
	}

	c = SwFindComponent(sw, component_name);
	if (c == NULL)
	{
		goto LABEL_CLEANUP;
	}

	ret = ZeroMalloc(sizeof(SW_LOGFILE));
	ret->IsSystemMode = is_system_mode;
	ret->Component = c;
	ret->Build = build;
	ret->LogList = NewListFast(NULL);

	// Item List
	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		FOLDER *f = CfgGetFolder(items, name);

		if (f != NULL)
		{
			UINT type = CfgGetInt(f, "Type");
			wchar_t value[MAX_SIZE];

			if (CfgGetUniStr(f, "Path", value, sizeof(value)))
			{
				if (IsEmptyUniStr(value) == false && type != 0)
				{
					SW_LOG *g = ZeroMalloc(sizeof(SW_LOG));

					g->Type = type;
					UniStrCpy(g->Path, sizeof(g->Path), value);

					Add(ret->LogList, g);
				}
			}
		}
	}

LABEL_CLEANUP:
	if (r != NULL)
	{
		CfgDeleteFolder(r);
	}

	if (t != NULL)
	{
		FreeToken(t);
	}

	return ret;
}

// Save the log file
bool SwSaveLogFile(SW *sw, wchar_t *dst_name, SW_LOGFILE *logfile)
{
	FOLDER *r;
	FOLDER *items;
	FOLDER *info;
	UINT i;
	bool ret;
	// Validate arguments
	if (sw == NULL || dst_name == NULL || logfile == NULL)
	{
		return false;
	}

	r = CfgCreateRoot();

	items = CfgCreateFolder(r, "Items");

	info = CfgCreateFolder(r, "Info");

	CfgAddBool(info, "IsSystemMode", logfile->IsSystemMode);
	CfgAddStr(info, "ComponentName", logfile->Component->Name);
	CfgAddInt(info, "Build", logfile->Build);

	for (i = 0;i < LIST_NUM(logfile->LogList);i++)
	{
		FOLDER *f;
		SW_LOG *g = LIST_DATA(logfile->LogList, i);
		char name[MAX_PATH];

		Format(name, sizeof(name), "Item%04u", i);

		f = CfgCreateFolder(items, name);

		CfgAddInt(f, "Type", g->Type);
		CfgAddUniStr(f, "Path", g->Path);
	}

	ret = CfgSaveExW3(NULL, r, dst_name, NULL, true);

	CfgDeleteFolder(r);

	return ret;
}

// Display the string to the status screen
void SwPerformPrint(WIZARD_PAGE *wp, wchar_t *str)
{
	SW_UI ui;
	// Validate arguments
	if (wp == NULL || str == NULL)
	{
		return;
	}

	Zero(&ui, sizeof(ui));
	ui.Type = SW_UI_TYPE_PRINT;
	ui.Message = str;

	SwInteractUi(wp, &ui);
}

// Show a message box on the screen
UINT SwPerformMsgBox(WIZARD_PAGE *wp, UINT flags, wchar_t *msg)
{
	SW_UI ui;
	// Validate arguments
	if (wp == NULL || msg == NULL)
	{
		return 0;
	}

	Zero(&ui, sizeof(ui));
	ui.Type = SW_UI_TYPE_MSGBOX;
	ui.Message = msg;
	ui.Param = flags;

	return SwInteractUi(wp, &ui);
}

// Call the UI interaction
UINT SwInteractUi(WIZARD_PAGE *wp, SW_UI *ui)
{
	// Validate arguments
	if (wp == NULL || ui == NULL)
	{
		return 0;
	}

	SendMsg(wp->hWndPage, 0, WM_SW_INTERACT_UI, 0xCAFE, (LPARAM)ui);

	SleepThread(50);

	return ui->RetCode;
}

// UI interaction is called
void SwInteractUiCalled(HWND hWnd, SW *sw, WIZARD_PAGE *wp, SW_UI *ui)
{
	// Validate arguments
	if (hWnd == NULL || sw == NULL || wp == NULL || ui == NULL)
	{
		return;
	}

	switch (ui->Type)
	{
	case SW_UI_TYPE_PRINT:		// Display the message
		SetText(hWnd, S_STATUS, ui->Message);
		break;

	case SW_UI_TYPE_MSGBOX:		// Show a message box
		ui->RetCode = MsgBox(hWnd, ui->Param, ui->Message);
		break;

	case SW_UI_TYPE_FINISH:		// Complete
		PostMessageA(hWnd, WM_SW_EXIT, 0xCAFE, 1);
		break;

	case SW_UI_TYPE_ERROR:		// Error
		PostMessageA(hWnd, WM_SW_EXIT, 0xCAFE, 0);
		break;
	}
}

// Initialize the setup process screen
void SwPerformInit(HWND hWnd, SW *sw, WIZARD_PAGE *wp)
{
	// Validate arguments
	if (hWnd == NULL || sw == NULL || wp == NULL)
	{
		return;
	}

	DlgFont(hWnd, S_INFO, 10, true);

	if (sw->EasyMode)
	{
		SetIcon(hWnd, S_ICON, ICO_SETUP);

		SetText(hWnd, S_INFO, _UU("SW_PERFORM_MSG_EASY_INFO"));
	}
	else if (sw->WebMode)
	{
		SetIcon(hWnd, S_ICON, ICO_SETUP);

		SetText(hWnd, S_INFO, _UU("SW_PERFORM_MSG_WEB_INFO"));
	}
	else
	{
		SetIcon(hWnd, S_ICON, sw->CurrentComponent->Icon);

		FormatText(hWnd, S_INFO, sw->CurrentComponent->Title);
	}

	SetTextA(hWnd, S_STATUS, "");

	if (MsIsWinXPOrWinVista())
	{
		// Display the progress bar for Windows XP or later
		SendMsg(hWnd, IDC_PROGRESS1, PBM_SETMARQUEE, TRUE, 100);
		SetStyle(hWnd, IDC_PROGRESS1, PBS_MARQUEE);
	}
	else
	{
		// Hide the progress bar in the case of Windows 2000 or earlier
		Hide(hWnd, IDC_PROGRESS1);
	}
}

// Do the set-up process
UINT SwPerform(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SwPerformInit(hWnd, sw, wizard_page);
		break;

	case WM_WIZ_SHOW:
		SetWizardButton(wizard_page, false, false, false, false);

		SetTimer(hWnd, 1, 100, NULL);
		break;

	case WM_TIMER:
		KillTimer(hWnd, 1);

		// Main thread execution
		if (sw->PerformThread == NULL)
		{
			sw->PerformThread = NewThread(SwPerformThread, wizard_page);
		}
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		break;

	case WM_WIZ_BACK:
		break;

	case WM_SW_INTERACT_UI:
		// UI interaction is called
		if (wParam == 0xCAFE)
		{
			SwInteractUiCalled(hWnd, sw, wizard_page, (SW_UI *)lParam);
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;

	case WM_SW_EXIT:
		// Close this screen since the process completed
		if (wParam == 0xCAFE)
		{
			JumpWizard(wizard_page, (lParam == 0 ? D_SW_ERROR : D_SW_FINISH));

			if (sw->PerformThread != NULL)
			{
				WaitThread(sw->PerformThread, INFINITE);
				ReleaseThread(sw->PerformThread);
				sw->PerformThread = NULL;
			}
		}
		break;
	}

	return 0;
}

// Final confirmation screen
UINT SwReady(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		FormatText(hWnd, S_INFO, sw->CurrentComponent->Title);
		break;

	case WM_WIZ_SHOW:
		SetWizardButton(wizard_page, true, true, true, false);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		return D_SW_PERFORM;

	case WM_WIZ_BACK:
		return D_SW_DIR;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;
	}

	return 0;
}

// Uninstall all the old MSI products
bool SwUninstallOldMsiInstalled(HWND hWnd, WIZARD_PAGE *wp, SW_COMPONENT *c, bool *reboot_required)
{
	UINT i;
	bool dummy_bool = false;
	// Validate arguments
	if (c == NULL || wp == NULL)
	{
		return true;
	}
	if (reboot_required == NULL)
	{
		reboot_required = &dummy_bool;
	}

	*reboot_required = false;

	if (c->OldMsiList == NULL)
	{
		return true;
	}

	for (i = 0;i < c->NumOldMsi;i++)
	{
		SW_OLD_MSI *m = &c->OldMsiList[i];
		wchar_t tmp[MAX_SIZE];

		if (MsGetMsiInstalledDir(m->ComponentCode, tmp, sizeof(tmp)))
		{
			bool rr = false;
			wchar_t msg[MAX_SIZE];

LABEL_RETRY:

			UniFormat(msg, sizeof(msg), _UU("SW_PERFORM_MSG_UNINSTALL_MSI"), c->Title);
			SwPerformPrint(wp, msg);

			if (MsMsiUninstall(m->ProductCode, hWnd, &rr) == false)
			{
				UniFormat(msg, sizeof(msg), _UU("SW_MSI_UNINSTALL_FAILED"), c->Title, m->ProductCode);

				if (SwPerformMsgBox(wp, MB_ICONEXCLAMATION | MB_RETRYCANCEL, msg) == IDRETRY)
				{
					goto LABEL_RETRY;
				}

				return false;
			}
			else
			{
				if (rr)
				{
					*reboot_required = true;
					return true;
				}
			}
		}
	}

	return true;
}

// Get the directory where the old MSI products are installed
wchar_t *SwGetOldMsiInstalledDir(SW_COMPONENT *c)
{
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	if (c->OldMsiList == NULL)
	{
		return NULL;
	}

	for (i = 0;i < c->NumOldMsi;i++)
	{
		SW_OLD_MSI *m = &c->OldMsiList[i];
		wchar_t tmp[MAX_SIZE];

		if (MsGetMsiInstalledDir(m->ComponentCode, tmp, sizeof(tmp)))
		{
			return UniCopyStr(tmp);
		}
	}

	return NULL;
}

// Initialize the default installation directory
void SwInitDefaultInstallDir(SW *sw)
{
	char keyname[MAX_SIZE];
	wchar_t *reg_dir_system;
	wchar_t *reg_dir_user;
	wchar_t *msi_dir_system = NULL;
	// Validate arguments
	if (sw == NULL)
	{
		return;
	}

	msi_dir_system = SwGetOldMsiInstalledDir(sw->CurrentComponent);

	Format(keyname, sizeof(keyname), "%s\\%s", SW_REG_KEY, sw->CurrentComponent->Name);

	if (UniIsEmptyStr(msi_dir_system) == false)
	{
		MsRegWriteStrEx2W(REG_LOCAL_MACHINE, keyname, "InstalledDir", msi_dir_system, false, true);
	}

	reg_dir_system = MsRegReadStrEx2W(REG_LOCAL_MACHINE, keyname, "InstalledDir", false, true);
	reg_dir_user = MsRegReadStrEx2W(REG_CURRENT_USER, keyname, "InstalledDir", false, true);

	// Generate a directory name in the case of system mode
	CombinePathW(sw->DefaultInstallDir_System, sizeof(sw->DefaultInstallDir_System),
		MsGetProgramFilesDirX64W(), sw->CurrentComponent->DefaultDirName);

	// Generate a directory name in the case of user mode
	CombinePathW(sw->DefaultInstallDir_User, sizeof(sw->DefaultInstallDir_User),
		MsGetPersonalAppDataDirW(), sw->CurrentComponent->DefaultDirName);

	if (UniIsEmptyStr(reg_dir_system) == false)
	{
		UniStrCpy(sw->DefaultInstallDir_System, sizeof(sw->DefaultInstallDir_System), reg_dir_system);
	}

	if (UniIsEmptyStr(reg_dir_user) == false)
	{
		UniStrCpy(sw->DefaultInstallDir_User, sizeof(sw->DefaultInstallDir_User), reg_dir_user);
	}

	if (MsIsNt() == false)
	{
		// Set to system mode for Win9x
		sw->IsSystemMode = true;
	}

	if (MsIsAdmin() == false)
	{
		sw->IsAvailableSystemMode = false;
		sw->IsAvailableUserMode = true;
	}
	else if (MsIsNt() == false)
	{
		sw->IsAvailableSystemMode = true;
		sw->IsAvailableUserMode = false;
	}
	else
	{
		sw->IsAvailableSystemMode = true;
		sw->IsAvailableUserMode = !sw->CurrentComponent->SystemModeOnly;
	}

	sw->ShowWarningForUserMode = sw->CurrentComponent->InstallService;

	Free(reg_dir_system);
	Free(reg_dir_user);
	Free(msi_dir_system);
}

// Update the installation directory setting screen
void SwDirUpdate(HWND hWnd, SW *sw, WIZARD_PAGE *wizard_page)
{
	bool user_mode_selected;
	bool show_custom;
	bool change_dir;
	// Validate arguments
	if (hWnd == NULL || sw == NULL || wizard_page == NULL)
	{
		return;
	}

	change_dir = IsChecked(hWnd, R_CUSTOM);

	SetShow(hWnd, S_DEST, change_dir);
	SetShow(hWnd, E_DIR, change_dir);
	SetShow(hWnd, B_BROWSE, change_dir);

	show_custom = IsChecked(hWnd, R_SHOWCUSTOM);

	SetShow(hWnd, R_FOR_SYSTEM, show_custom);
	SetShow(hWnd, R_FOR_USER, show_custom);

	user_mode_selected = IsChecked(hWnd, R_FOR_USER);

	SetText(hWnd, R_DEFAULT, user_mode_selected ? sw->DefaultInstallDir_User : sw->DefaultInstallDir_System);

	if (user_mode_selected == false)
	{
		Hide(hWnd, S_WARNING);
		Hide(hWnd, S_WARNING2);
	}
	else
	{
		SetShow(hWnd, S_WARNING, sw->ShowWarningForUserMode);
		SetShow(hWnd, S_WARNING2, sw->ShowWarningForUserMode);
	}

	SetEnable(hWnd, R_SHOWCUSTOM, !user_mode_selected);

	DlgFont(hWnd, R_DEFAULT, 0, !change_dir);
}

// Check the directory name planned to be created newly
bool SwCheckNewDirName(wchar_t *name)
{
	char tmp[MAX_SIZE];
	UCHAR rand[16];
	wchar_t testname[MAX_SIZE];
	IO *io;
	bool new_dir;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	// Create a directory
	new_dir = MakeDirExW(name);

	// Writes the appropriate files
	Rand(rand, sizeof(rand));
	BinToStr(tmp, sizeof(tmp), rand, sizeof(rand));
	UniFormat(testname, sizeof(testname), L"%s\\%S.dat", name, tmp);

	io = FileCreateW(testname);

	if (io == NULL)
	{
		return false;
	}

	FileClose(io);

	FileDeleteW(testname);

	if (new_dir)
	{
		DeleteDirW(name);
	}

	return true;
}

// Set the installation directory
UINT SwDir(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	wchar_t tmp[MAX_SIZE];
	wchar_t setuplog[MAX_SIZE];
	wchar_t *s;
	SW_LOGFILE *logfile;
	bool is_system_mode;
	bool skip_ver_check = false;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		SetIcon(hWnd, S_ICON, sw->CurrentComponent->Icon);

		SwInitDefaultInstallDir(sw);

		FormatText(hWnd, S_INFO, sw->CurrentComponent->Title);
		FormatText(hWnd, R_FOR_USER, MsGetUserNameW());
		FormatText(hWnd, S_WARNING, MsGetUserNameW(), sw->CurrentComponent->Title);

		Check(hWnd, R_FOR_SYSTEM, sw->IsSystemMode);
		Check(hWnd, R_FOR_USER, !sw->IsSystemMode);

		if (sw->IsSystemMode == false)
		{
			Check(hWnd, R_SHOWCUSTOM, true);
		}

		SetText(hWnd, E_DIR, sw->IsSystemMode ? sw->DefaultInstallDir_System : sw->DefaultInstallDir_User);

		Check(hWnd, R_DEFAULT, true);

		SetEnable(hWnd, R_FOR_SYSTEM, sw->IsAvailableSystemMode);
		SetEnable(hWnd, R_FOR_USER, sw->IsAvailableUserMode);

		SwDirUpdate(hWnd, sw, wizard_page);

		break;

	case WM_WIZ_SHOW:
		SetWizardButton(wizard_page, true, false, true, false);

		SwDirUpdate(hWnd, sw, wizard_page);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		if (IsChecked(hWnd, R_CUSTOM))
		{
			GetTxt(hWnd, E_DIR, tmp, sizeof(tmp));
		}
		else
		{
			if (IsChecked(hWnd, R_FOR_SYSTEM))
			{
				UniStrCpy(tmp, sizeof(tmp), sw->DefaultInstallDir_System);
			}
			else
			{
				UniStrCpy(tmp, sizeof(tmp), sw->DefaultInstallDir_User);
			}
		}

		is_system_mode = IsChecked(hWnd, R_FOR_SYSTEM);

		if (is_system_mode == false)
		{
			if (sw->CurrentComponent->InstallService)
			{
				if (MsIsServiceInstalled(sw->CurrentComponent->SvcName))
				{
					// If the type of installation is user mode and the same software
					// is running in system mode already, warn about it
					if (MsgBoxEx(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("SW_SYSTEM_MODE_ALREADY_INSTALLED"),
						sw->CurrentComponent->Title) == IDNO)
					{
						break;
					}
				}
			}
		}

		UniTrim(tmp);

		Win32NukuEnW(tmp, sizeof(tmp), tmp);

		// Check Length
		if (UniStrLen(tmp) > 110)
		{
			MsgBox(hWnd, MB_ICONEXCLAMATION, _UU("SW_DIR_MORE_THAN_110"));
			FocusEx(hWnd, E_DIR);
			break;
		}

		// Check whether it's a full path
		if (UniStartWith(tmp, L"\\\\") == false &&
			(tmp[1] != L':' || tmp[2] != L'\\'))
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SW_DIR_IS_NOT_FULLPATH"), tmp);
			FocusEx(hWnd, E_DIR);
			break;
		}

		NormalizePathW(tmp, sizeof(tmp), tmp);

		// Check the type of the drive
		if (IsChecked(hWnd, R_FOR_SYSTEM))
		{
			// System mode service is installed only on the hard disk
			bool ok = true;

			if (UniStartWith(tmp, L"\\\\"))
			{
				ok = false;
			}
			else
			{
				char tmpa[MAX_SIZE];
				UINT ret;

				UniToStr(tmpa, sizeof(tmpa), tmp);

				tmpa[3] = 0;

				ret = GetDriveTypeA(tmpa);

				if (ret != DRIVE_FIXED && ret != DRIVE_RAMDISK)
				{
					ok = false;
				}
			}

			if (ok == false)
			{
				MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SW_DIR_IS_NOT_HDD"), tmp, sw->CurrentComponent->Title);
				FocusEx(hWnd, E_DIR);
				break;
			}
		}

		// Write check
		if (SwCheckNewDirName(tmp) == false)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SW_DIR_WRITE_ERROR"), tmp);
			FocusEx(hWnd, E_DIR);
			break;
		}

		// Analyze if there is a setuplog.dat on destination
		CombinePathW(setuplog, sizeof(setuplog), tmp, L"setuplog.dat");
		logfile = SwLoadLogFile(sw, setuplog);
		if (logfile == NULL && IsFileExistsW(setuplog))
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SW_DIR_DST_IS_BROKEN"), setuplog);
			FocusEx(hWnd, E_DIR);
			break;
		}

		if (logfile != NULL && (logfile->Build > CEDAR_VERSION_BUILD) && UniIsEmptyStr(sw->auto_setting_path) == false &&
			sw->CurrentComponent->Id == SW_CMP_VPN_CLIENT && logfile->Component->Id == SW_CMP_VPN_CLIENT)
		{
			// In the case of the VPN Client, show a message if a newer version is installed and
			// the automatic connection setting by simple installer should be applied
			if (MsgBox(hWnd, MB_ICONINFORMATION | MB_OKCANCEL, _UU("SW_DIR_DST_IS_NEWER_2")) == IDCANCEL)
			{
				// Cancel
				FocusEx(hWnd, E_DIR);
				break;
			}

			skip_ver_check = true;
		}

		if (logfile != NULL)
		{
			wchar_t *errmsg = NULL;
			if (logfile->Component != sw->CurrentComponent)
			{
				errmsg = _UU("SW_DIR_DST_IS_OTHER_PRODUCT");
			}
			else if ((skip_ver_check == false) && (logfile->Build > CEDAR_VERSION_BUILD))
			{
				errmsg = _UU("SW_DIR_DST_IS_NEWER");
			}
			else if (logfile->IsSystemMode && is_system_mode == false)
			{
				errmsg = _UU("SW_DIR_DST_IS_SYSTEM_MODE");
			}
			else if (logfile->IsSystemMode == false && is_system_mode)
			{
				errmsg = _UU("SW_DIR_DST_IS_USER_MODE");
			}

			SwFreeLogFile(logfile);

			if (errmsg != NULL)
			{
				MsgBox(hWnd, MB_ICONEXCLAMATION, errmsg);
				FocusEx(hWnd, E_DIR);
				break;
			}
		}

		// Check whether installation destination and installation source are not same
		if (UniStrCmpi(tmp, sw->InstallSrc) == 0)
		{
			MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SW_DIR_DST_IS_SAME_TO_SRC"), tmp);
			FocusEx(hWnd, E_DIR);
			break;
		}

		UniStrCpy(sw->InstallDir, sizeof(sw->InstallDir), tmp);
		sw->IsSystemMode = IsChecked(hWnd, R_FOR_SYSTEM);

		sw->OnlyAutoSettingMode = skip_ver_check;

		return D_SW_READY;

	case WM_WIZ_BACK:
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case R_DEFAULT:
		case R_CUSTOM:
		case R_SHOWCUSTOM:
		case R_FOR_SYSTEM:
		case R_FOR_USER:
			SwDirUpdate(hWnd, sw, wizard_page);
			break;
		}

		switch (wParam)
		{
		case R_FOR_SYSTEM:
			SetText(hWnd, E_DIR, sw->DefaultInstallDir_System);
			break;

		case R_FOR_USER:
			SetText(hWnd, E_DIR, sw->DefaultInstallDir_User);
			break;

		case B_BROWSE:
			GetTxt(hWnd, E_DIR, tmp, sizeof(tmp));
			s = FolderDlgW(hWnd, _UU("SW_DIR_SELECT"), tmp);

			if (s != NULL)
			{
				if (UniEndWith(s, sw->CurrentComponent->DefaultDirName))
				{
					UniStrCpy(tmp, sizeof(tmp), s);
				}
				else
				{
					CombinePathW(tmp, sizeof(tmp), s, sw->CurrentComponent->DefaultDirName);
				}

				SetText(hWnd, E_DIR, tmp);
				FocusEx(hWnd, E_DIR);

				Free(s);
			}
			break;
		}

		break;
	}

	return 0;
}

// Warning screen
UINT SwWarning(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	BUF *b;
	UCHAR c = 0;
	wchar_t *str;
	char warning_filename[MAX_PATH];
	LANGLIST t;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		break;

	case WM_WIZ_SHOW:
		DlgFont(hWnd, B_AGREE, 0, true);

		GetCurrentLang(&t);

		SetFont(hWnd, E_TEXT, GetFont((t.Id == SE_LANG_JAPANESE && MsIsWindows7()) ? "Meiryo UI" : NULL, 10, false , false, false, false));

		Format(warning_filename, sizeof(warning_filename), "|warning_%s.txt", t.Name);
		b = ReadDump(warning_filename);

		SeekBuf(b, b->Size, 0);
		c = 0;
		WriteBuf(b, &c, 1);

		str = CopyUtfToUni(b->Buf);

		UniIsEmptyStr(str);

		SetText(hWnd, E_TEXT, str);

		FreeBuf(b);

		Free(str);

		UnselectEdit(hWnd, E_TEXT);

		Focus(hWnd, E_TEXT);

		SetWizardButton(wizard_page, true, true, true, false);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		if (SwEnterSingle(sw) == false)
		{
			// Multiple-starts prevention
			MsgBox(hWnd, MB_ICONINFORMATION, _UU("SW_OTHER_INSTANCE_EXISTS"));
			break;
		}
		return D_SW_DIR;

	case WM_WIZ_BACK:
		return D_SW_EULA;

	case WM_COMMAND:
		break;
	}

	return 0;
}

// Update the license agreement screen
void SwEulaUpdate(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page)
{
	// Validate arguments
	if (hWnd == NULL || sw == NULL || wizard == NULL || wizard_page == NULL)
	{
		return;
	}

	sw->EulaAgreed = IsChecked(hWnd, B_AGREE);

	if (sw->EulaAgreed == false)
	{
		// Delete the agreement record in the case of non-agreement for the EULA
		MsRegDeleteValueEx2(REG_CURRENT_USER, SW_REG_KEY_EULA, sw->CurrentComponent->Name, false, true);
	}

	SetWizardButton(wizard_page, sw->EulaAgreed, true, true, false);
}

// License Agreement
UINT SwEula(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	BUF *b;
	UCHAR c = 0;
	wchar_t *str;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		break;

	case WM_WIZ_SHOW:
		SetFont(hWnd, E_TEXT, GetFont((MsIsWindows7() ? "Segoe UI" : "Verdana"), 10, false, false, false, false));
		//DlgFont(hWnd, B_AGREE, 10, true);

		b = ReadDump("|eula.txt");

		SeekBuf(b, b->Size, 0);
		c = 0;
		WriteBuf(b, &c, 1);

		str = CopyUtfToUni(b->Buf);

		UniIsEmptyStr(str);

		SetText(hWnd, E_TEXT, str);

		sw->CurrentEulaHash = HashToUINT(b->Buf, b->Size);

		FreeBuf(b);

		Free(str);

		if (sw->CurrentComponent != NULL && sw->CurrentEulaHash != 0 && sw->CurrentEulaHash == MsRegReadIntEx2(REG_CURRENT_USER, SW_REG_KEY_EULA, sw->CurrentComponent->Name, false, true))
		{
			// Check the consent check box in advance if the user accepts the same EULA during the last installation
			sw->EulaAgreed = true;
		}

		Check(hWnd, B_AGREE, sw->EulaAgreed);

		UnselectEdit(hWnd, E_TEXT);

		Focus(hWnd, E_TEXT);

		SwEulaUpdate(hWnd, sw, wizard, wizard_page);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		SwEulaUpdate(hWnd, sw, wizard, wizard_page);

		if (sw->EulaAgreed)
		{
			return D_SW_WARNING;
		}
		break;

	case WM_WIZ_BACK:
		sw->EulaAgreed = false;
		return D_SW_COMPONENTS;

	case WM_COMMAND:
		switch (wParam)
		{
		case B_AGREE:
			SwEulaUpdate(hWnd, sw, wizard, wizard_page);
			break;
		}
		break;
	}

	return 0;
}

// Initialize a component list
void SwComponentsInit(HWND hWnd, SW *sw)
{
	LVB *b;
	UINT i;
	SW_COMPONENT *default_select = NULL;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return;
	}

	LvReset(hWnd, L_LIST);

	b = LvInsertStart();

	for (i = 0;i < LIST_NUM(sw->ComponentList);i++)
	{
		SW_COMPONENT *c = LIST_DATA(sw->ComponentList, i);

		if (c->Detected)
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), L" %s", c->Title);

			LvInsertAdd(b, c->Icon, c, 1, tmp);

			if (c->SystemModeOnly == false || MsIsAdmin())
			{
				if (default_select == NULL)
				{
					default_select = c;
				}
			}
		}
	}

	LvInsertEnd(b, hWnd, L_LIST);

	if (sw->CurrentComponent == NULL)
	{
		LvSelectByParam(hWnd, L_LIST, default_select);
	}
	else
	{
		LvSelectByParam(hWnd, L_LIST, sw->CurrentComponent);
	}

	Focus(hWnd, L_LIST);
}

// Update the Component Selection screen
void SwComponentsUpdate(HWND hWnd, SW *sw, WIZARD *wizard, WIZARD_PAGE *wizard_page)
{
	SW_COMPONENT *c;
	// Validate arguments
	if (hWnd == NULL || sw == NULL || wizard == NULL || wizard_page == NULL)
	{
		return;
	}

	c = (SW_COMPONENT *)LvGetSelectedParam(hWnd, L_LIST);

	if (c == NULL)
	{
		Hide(hWnd, S_TITLE);
		Hide(hWnd, S_DESCRIPTION);
		Hide(hWnd, S_ICON);

		SetWizardButton(wizard_page, false, true, true, false);
	}
	else
	{
		wchar_t tmp[MAX_SIZE];

		if (c->SystemModeOnly && MsIsAdmin() == false)
		{
			// Components to be installed only in system mode is set to unselectable
			SetText(hWnd, S_TITLE, _UU("SW_COMPONENTS_REQUIRE_ADMIN"));
			UniFormat(tmp, sizeof(tmp), _UU("SW_COMPONENTS_REQUIRE_ADMIN_TEXT"), c->Title);
			SetText(hWnd, S_DESCRIPTION, tmp);
			SetIcon(hWnd, S_ICON, ICO_WARNING);

			SetWizardButton(wizard_page, false, true, true, false);
		}
		else
		{
			// Show the description of the component
			UniFormat(tmp, sizeof(tmp), _UU("SW_COMPONENTS_ABOUT_TAG"), c->Title);
			SetText(hWnd, S_TITLE, tmp);
			SetText(hWnd, S_DESCRIPTION, c->Description);
			SetIcon(hWnd, S_ICON, c->Icon);

			SetWizardButton(wizard_page, true, true, true, false);
		}

		Show(hWnd, S_TITLE);
		Show(hWnd, S_DESCRIPTION);
		Show(hWnd, S_ICON);
	}
}

// Component selection screen
UINT SwComponents(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	NMHDR *n;
	SW_COMPONENT *c;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		LvInitEx2(hWnd, L_LIST, false, true);

		if (MsIsVista())
		{
			SetFont(hWnd, L_LIST, GetMeiryoFontEx(12));
			SetFont(hWnd, S_TITLE, GetMeiryoFontEx(11));
		}
		else
		{
			DlgFont(hWnd, L_LIST, 12, false);
			DlgFont(hWnd, S_TITLE, 11, false);
		}

		LvInsertColumn(hWnd, L_LIST, 0, L"Component", 515);
		break;

	case WM_WIZ_SHOW:
		SetWizardButton(wizard_page, true, true, true, false);

		SwComponentsInit(hWnd, sw);

		SwComponentsUpdate(hWnd, sw, wizard, wizard_page);

		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		c = (SW_COMPONENT *)LvGetSelectedParam(hWnd, L_LIST);

		if (c != NULL)
		{
			if (SwCheckOs(sw, c) == false)
			{
				// OS Check Failed
				MsgBoxEx(hWnd, MB_ICONEXCLAMATION, _UU("SW_OS_FAILED"), c->Title);
				break;
			}

			sw->CurrentComponent = c;

			if (sw->CurrentComponent->SystemModeOnly == false || MsIsAdmin())
			{
				if (sw->CurrentComponent->Id == SW_CMP_VPN_SERVER && MsIsServiceInstalled(GC_SVC_NAME_VPNBRIDGE))
				{
					// The user is trying to install the VPN Server but, VPN Bridge already exists
					if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("SW_NOTICE_VPNBRIDGE_IS_INSTALLED")) == IDNO)
					{
						break;
					}
				}
				else if (sw->CurrentComponent->Id == SW_CMP_VPN_BRIDGE && MsIsServiceInstalled(GC_SVC_NAME_VPNSERVER))
				{
					// The user is trying to install the VPN Bridge, but a VPN Server already exists
					if (MsgBox(hWnd, MB_ICONEXCLAMATION | MB_YESNO | MB_DEFBUTTON2, _UU("SW_NOTICE_VPNSERVER_IS_INSTALLED")) == IDNO)
					{
						break;
					}
				}

				// Continue
				return D_SW_EULA;
			}
		}
		break;

	case WM_WIZ_BACK:
		if (MsIsAdmin())
		{
			return D_SW_WELCOME;
		}
		else
		{
			return D_SW_MODE;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;

	case WM_NOTIFY:
		n = (NMHDR *)lParam;

		switch (n->idFrom)
		{
		case L_LIST:
			switch (n->code)
			{
			case LVN_ITEMCHANGED:
				SwComponentsUpdate(hWnd, sw, wizard, wizard_page);
				break;
			}
			break;
		}

		break;
	}

	return 0;
}

// Screen that is displayed when the user don't have administrative privileges
UINT SwNotAdminDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		break;

	case WM_WIZ_SHOW:
		FormatText(hWnd, S_INFO, MsGetUserNameW());

		SetShow(hWnd, S_INFO2, (sw->UninstallMode ? false : true));

		SetWizardButton(wizard_page, true, ((sw->UninstallMode && sw->IsReExecForUac) ? false : true), true, true);
		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		break;

	case WM_WIZ_BACK:
		if (sw->UninstallMode == false)
		{
			return D_SW_MODE;
		}
		else
		{
			return D_SW_UNINST1;
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;
	}

	return 0;
}

// Choose the setup mode
UINT SwModeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		break;

	case WM_WIZ_SHOW:
		SetWizardButton(wizard_page, true, true, true, false);
		FormatText(hWnd, S_USER, MsGetUserNameW());

		// Choose the initial state
		Check(hWnd, R_SYSTEM, sw->IsSystemMode);
		Check(hWnd, R_USER, !sw->IsSystemMode);

		Focus(hWnd, (sw->IsSystemMode ? R_SYSTEM : R_USER));

		sw->DoubleClickBlocker = false;
		SetUacIcon(hWnd, S_UAC);

		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		// Mode
		sw->IsSystemMode = IsChecked(hWnd, R_SYSTEM);

		if (sw->DoubleClickBlocker)
		{
			break;
		}

		sw->DoubleClickBlocker = true;

		if (sw->IsSystemMode)
		{
			if (MsIsVista() && MsIsAdmin() == false && sw->IsReExecForUac == false)
			{
				// If UAC is available and this isn't invoked via UAC,
				// give the user a chance to get administrator privileges on UAC start again
				if (SwReExecMyself(sw, NULL, true))
				{
					// Terminate itself if it succeeds to start the child process
					CloseWizard(wizard_page);
				}
				else
				{
					// Jump to screen prompts to re-start as a administrator if it fails to start the child process
					return D_SW_NOT_ADMIN;
				}
			}
			else
			{
				if (MsIsAdmin())
				{
					// Jump to the component list screen if the user has administrator privileges
					return D_SW_COMPONENTS;
				}
				else
				{
					// Jump to screen prompts to re-start as a administrator if the user doesn't have administrator privileges
					return D_SW_NOT_ADMIN;
				}
			}
		}
		else
		{
			// Jump to the component list screen
			return D_SW_COMPONENTS;
		}

		break;

	case WM_WIZ_BACK:
		return D_SW_WELCOME;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;
	}

	return 0;
}

// Welcome screen
UINT SwWelcomeDlg(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, WIZARD *wizard, WIZARD_PAGE *wizard_page, void *param)
{
	SW *sw = (SW *)param;
	// Validate arguments
	if (hWnd == NULL || sw == NULL)
	{
		return 0;
	}

	switch (msg)
	{
	case WM_INITDIALOG:
		break;

	case WM_WIZ_SHOW:
		DlgFont(hWnd, S_WELCOME, 10, false);
		DlgFont(hWnd, S_TITLE, 11, true);
		SetWizardButtonEx(wizard_page, true, false, true, false, true);

		sw->DoubleClickBlocker = false;

		break;

	case WM_WIZ_HIDE:
		break;

	case WM_CLOSE:
		break;

	case WM_WIZ_NEXT:
		if (MsIsKB3033929RequiredAndMissing())
		{
			// KB3033929 is missing
			if (MsgBoxEx(hWnd, MB_ICONINFORMATION | MB_OKCANCEL, _UU("SW_KB3033929_REQUIRED")) == IDCANCEL)
			{
				break;
			}
		}

		if (sw->DoubleClickBlocker)
		{
			break;
		}

		sw->DoubleClickBlocker = true;

		if (MsIsAdmin() == false)
		{
			if (MsIsVista())
			{
				if (sw->IsReExecForUac == false)
				{
					// If there is no Admin privileges in Vista or later, attempt to acquire Admin rights by UAC first during the first run
					if (SwReExecMyself(sw, NULL, true))
					{
						// Terminate itself if it succeeds to start the child process
						CloseWizard(wizard_page);
						break;
					}
					else
					{
						// Jump to mode selection screen if it fails to start the
						// child process (including user presses the cancel of UAC)
						return D_SW_MODE;
					}
				}
				else
				{
					// Jump to mode selection screen when the user don't have Admin rights after being activated by UAC
					return D_SW_MODE;
				}
			}
			else
			{
				// Jump to the mode selection screen in the case of older than Vista
				return D_SW_MODE;
			}
		}
		else
		{
			// Skip to the component list screen if the user has Admin privileges
			return D_SW_COMPONENTS;
		}
		break;

	case WM_WIZ_BACK:
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		}
		break;
	}

	return 0;
}

// Restart itself
bool SwReExecMyself(SW *sw, wchar_t *additional_params, bool as_admin)
{
	wchar_t *current_params;
	wchar_t new_param[MAX_SIZE];
	void *handle;
	bool ret = false;
	// Validate arguments
	if (sw == NULL)
	{
		return false;
	}
	if (sw->ReExecProcessHandle != NULL)
	{
		return false;
	}

	current_params = GetCommandLineUniStr();

	if (IsEmptyUniStr(additional_params))
	{
		additional_params = L"";
	}

	UniFormat(new_param, sizeof(new_param), L"%s %s %s", current_params, (as_admin ? L"/UAC:true" : L""), additional_params);

	UniTrim(new_param);

	handle = NULL;
	ret = MsExecuteEx2W(MsGetExeFileNameW(), new_param, &handle, as_admin);

	Free(current_params);

	if (ret == false)
	{
		return false;
	}

	sw->ReExecProcessHandle = handle;

	return true;
}

// Show the UI
void SwUiMain(SW *sw)
{
	WIZARD *w;
	wchar_t verstr[MAX_SIZE];
	char ver[MAX_SIZE];
	// Validate arguments
	if (sw == NULL)
	{
		return;
	}

	// Define the wizard UI
	GetCedarVersion(ver, sizeof(ver));
	UniFormat(verstr, sizeof(verstr), _UU("SW_TITLE"), ver);

	w = NewWizard(ICO_SETUP, BMP_SELOGO49x49, verstr, sw);

	w->CloseConfirmMsg = _UU("SW_EXIT_CONFIRM");

	AddWizardPage(w, NewWizardPage(D_SW_WELCOME, SwWelcomeDlg, _UU("SW_WELCOME_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_MODE, SwModeDlg, _UU("SW_MODE_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_NOT_ADMIN, SwNotAdminDlg, _UU("SW_NOT_ADMIN_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_COMPONENTS, SwComponents, _UU("SW_COMPONENTS_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_EULA, SwEula, _UU("SW_EULA_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_WARNING, SwWarning, _UU("SW_WARNING_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_DIR, SwDir, _UU("SW_DIR_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_READY, SwReady, _UU("SW_READY_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_PERFORM, SwPerform, _UU("SW_PERFORM_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_ERROR, SwError, _UU("SW_ERROR_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_FINISH, SwFinish, _UU("SW_FINISH_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_UNINST1, SwUninst1, _UU("SW_UNINST1_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_LANG1, SwLang1, _UU("SW_LANG1_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_EASY1, SwEasy1, _UU("SW_EASY1_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_EASY2, SwEasy2, _UU("SW_EASY2_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_WEB1, SwWeb1, _UU("SW_WEB1_TITLE")));
	AddWizardPage(w, NewWizardPage(D_SW_WEB2, SwWeb2, _UU("SW_WEB2_TITLE")));

	if (MsIsVista())
	{
		w->IsAreoStyle = true;
	}

	if (sw->UninstallMode)
	{
		// Uninstall mode
		UINT start_page = D_SW_UNINST1;

		if (sw->IsReExecForUac)
		{
			// In the case of this have been executed for UAC
			if (MsIsAdmin())
			{
				// Uninstall
				start_page = D_SW_PERFORM;
			}
			else
			{
				// Error screen
				start_page = D_SW_NOT_ADMIN;
			}
		}

		ShowWizard(NULL, w, start_page);
	}
	else if (sw->WebMode)
	{
		// Web installer creation mode
		UINT start_page = D_SW_WEB1;

		ShowWizard(NULL, w, start_page);
	}
	else if (sw->EasyMode)
	{
		// Simple installer creation mode
		UINT start_page = D_SW_EASY1;

		ShowWizard(NULL, w, start_page);
	}
	else if (sw->LanguageMode)
	{
		// Language setting mode
		UINT start_page = D_SW_LANG1;

		w->CloseConfirmMsg = NULL;

		if (sw->IsReExecForUac)
		{
			// In the case of this have been executed for UAC
			if (MsIsAdmin())
			{
				// Do the language setting
				start_page = D_SW_PERFORM;
			}
			else
			{
				// Error screen
				start_page = D_SW_NOT_ADMIN;
			}
		}
		else
		{
			if (sw->LangNow)
			{
				// If not via UAC but Lang Now is set
				start_page = D_SW_PERFORM;
			}
		}

		if (sw->SetLangAndReboot && sw->LangNow == false)
		{
			// Restart myself immediately by changing the lang.config
			LIST *o = LoadLangList();

			if (o == NULL)
			{
				MsgBox(NULL, MB_ICONSTOP, _UU("SW_LANG_LIST_LOAD_FAILED"));
			}
			else
			{
				LANGLIST *new_lang = GetLangById(o, sw->LangId);
				LANGLIST old_lang;

				Zero(&old_lang, sizeof(old_lang));
				GetCurrentLang(&old_lang);

				if (new_lang == NULL)
				{
					MsgBox(NULL, MB_ICONSTOP, _UU("SW_LANG_LIST_LOAD_FAILED"));
				}
				else
				{
					if (SaveLangConfigCurrentDir(new_lang->Name) == false)
					{
						MsgBox(NULL, MB_ICONSTOP, _UU("SW_LANG_SET_FAILED"));
					}
					else
					{
						if (SwReExecMyself(sw, L"/LANGNOW:true ", false) == false)
						{
							SaveLangConfigCurrentDir(old_lang.Name);

							MsgBox(NULL, MB_ICONSTOP, _UU("SW_CHILD_PROCESS_ERROR"));

							sw->ExitCode = SW_EXIT_CODE_INTERNAL_ERROR;
						}
					}
				}

				FreeLangList(o);
			}
		}
		else
		{
			// Show the wizard
			ShowWizard(NULL, w, start_page);
		}
	}
	else
	{
		// Installation mode
		UINT start_page = D_SW_WELCOME;

		if (sw->IsReExecForUac)
		{
			// In the case of this have been executed for UAC
			if (MsIsAdmin())
			{
				// Jump to component list if the user have system administrator privileges
				start_page = D_SW_COMPONENTS;
			}
			else
			{
				// Jump to the setup mode selection screen when fail
				// to get admin privileges even executed by enabling UAC
				start_page = D_SW_MODE;
			}
		}

		ShowWizard(NULL, w, start_page);

		if (sw->Run)
		{
			// Auto run the app
			wchar_t tmp[MAX_PATH];
			HANDLE h;
			UNI_TOKEN_LIST *t;

			t = UniParseToken(sw->CurrentComponent->StartExeName, L" ");

			if (t != NULL)
			{
				wchar_t exe[MAX_PATH];
				wchar_t arg[MAX_PATH];

				Zero(exe, sizeof(exe));
				Zero(arg, sizeof(arg));

				if (t->NumTokens >= 1)
				{
					UniStrCpy(exe, sizeof(exe), t->Token[0]);
				}
				if (t->NumTokens >= 2)
				{
					UniStrCpy(arg, sizeof(arg), t->Token[1]);
				}

				if (UniIsEmptyStr(exe) == false)
				{
					CombinePathW(tmp, sizeof(tmp), sw->InstallDir, exe);

					h = MsRunAsUserExW(tmp, arg, false);
					if (h != NULL)
					{
						CloseHandle(h);
					}
				}

				UniFreeToken(t);
			}
		}
	}

	FreeWizard(w);
}

// Release the component
void SwFreeComponent(SW_COMPONENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	FreeStrList(c->NeedFiles);
	Free(c->Name);
	Free(c->SvcName);
	Free(c->LongName);
	Free(c->Title);
	Free(c->Description);
	Free(c->DefaultDirName);
	Free(c->SvcFileName);
	Free(c->StartExeName);
	Free(c->StartDescription);

	Free(c);
}

// Create a component
SW_COMPONENT *SwNewComponent(char *name, char *svc_name, UINT id, UINT icon, UINT icon_index, wchar_t *svc_filename,
							 wchar_t *long_name, bool system_mode_only, UINT num_files, char *files[],
							 wchar_t *start_exe_name, wchar_t *start_description,
							 SW_OLD_MSI *old_msis, UINT num_old_msis)
{
	SW_COMPONENT *c;
	UINT i;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL || files == NULL || long_name == NULL)
	{
		return NULL;
	}
	if (svc_name == NULL)
	{
		svc_name = name;
	}

	c = ZeroMalloc(sizeof(SW_COMPONENT));

	c->Id = id;

	c->NeedFiles = NewListFast(NULL);

	for (i = 0;i < num_files;i++)
	{
		Add(c->NeedFiles, CopyStr(files[i]));
	}

	c->SystemModeOnly = system_mode_only;
	c->Name = CopyStr(name);
	c->SvcName = CopyStr(svc_name);
	c->DefaultDirName = CopyUniStr(long_name);
	c->LongName = CopyUniStr(long_name);

	Format(tmp, sizeof(tmp), "SW_COMPONENT_%s_TITLE", name);
	c->Title = CopyUniStr(_UU(tmp));

	Format(tmp, sizeof(tmp), "SW_COMPONENT_%s_DESCRIPTION", name);
	c->Description = CopyUniStr(_UU(tmp));

	c->Icon = icon;
	c->IconExeIndex = icon_index;

	if (UniIsEmptyStr(svc_filename) == false)
	{
		c->InstallService = true;
		c->SvcFileName = UniCopyStr(svc_filename);
	}

	if (UniIsEmptyStr(start_exe_name) == false && UniIsEmptyStr(start_description) == false)
	{
		c->StartExeName = UniCopyStr(start_exe_name);
		c->StartDescription = UniCopyStr(start_description);
	}

	c->OldMsiList = old_msis;
	c->NumOldMsi = num_old_msis;

	return c;
}

// Examine the OS requirements
bool SwCheckOs(SW *sw, SW_COMPONENT *c)
{
	// Validate arguments
	if (sw == NULL || c == NULL)
	{
		return false;
	}

	if (c->Id == SW_CMP_VPN_CLIENT)
	{
		OS_INFO *info = GetOsInfo();

		if (OS_IS_WINDOWS_NT(info->OsType))
		{
			if (MsIsWin2000OrGreater() == false)
			{
				// It doesn't work with WinNT 4.0
				return false;
			}
		}
		else
		{
			if (GET_KETA(info->OsType, 100) <= 1)
			{
				// It doesn't work with Win95
				return false;
			}
			else if (info->OsType == OSTYPE_WINDOWS_98)
			{
				if (EndWith(info->OsVersion, "A") == false)
				{
					// It doesn't work in Win98 First Edition
					return false;
				}
			}
		}
	}

	return true;
}

// Define the component
void SwDefineComponents(SW *sw)
{
	SW_COMPONENT *c;
	char *vpn_server_files[] =
	{
		"vpnserver.exe",
		"vpnsmgr.exe",
		"vpncmd.exe",
		"hamcore.se2",
	};
	char *vpn_client_files[] =
	{
		"vpnclient.exe",
		"vpncmgr.exe",
		"vpncmd.exe",
		"hamcore.se2",
	};
	char *vpn_bridge_files[] =
	{
		"vpnbridge.exe",
		"vpnsmgr.exe",
		"vpncmd.exe",
		"hamcore.se2",
	};
	char *vpn_smgr_files[] =
	{
		"vpnsmgr.exe",
		"vpncmd.exe",
		"hamcore.se2",
	};
	char *vpn_cmgr_files[] =
	{
		"vpncmgr.exe",
		"vpncmd.exe",
		"hamcore.se2",
	};
	// Validate arguments
	if (sw == NULL)
	{
		return;
	}

	// VPN Server
	c = SwNewComponent(SW_NAME_VPNSERVER, GC_SVC_NAME_VPNSERVER, SW_CMP_VPN_SERVER, ICO_VPNSERVER, 5, L"vpnserver.exe",
		SW_LONG_VPNSERVER, false, sizeof(vpn_server_files) / sizeof(char *), vpn_server_files,
		L"vpnsmgr.exe", _UU("SW_RUN_TEXT_VPNSMGR"),
		old_msi_vpnserver, sizeof(old_msi_vpnserver) / sizeof(SW_OLD_MSI));
	Add(sw->ComponentList, c);

	// VPN Client
	c = SwNewComponent(SW_NAME_VPNCLIENT, GC_SVC_NAME_VPNCLIENT, SW_CMP_VPN_CLIENT, ICO_VPN, 6, L"vpnclient.exe",
		SW_LONG_VPNCLIENT, true, sizeof(vpn_client_files) / sizeof(char *), vpn_client_files,
		L"vpncmgr.exe", _UU("SW_RUN_TEXT_VPNCMGR"),
		old_msi_vpnclient, sizeof(old_msi_vpnclient) / sizeof(SW_OLD_MSI));

#ifdef	GC_ENABLE_VPNGATE
#endif	// GC_ENABLE_VPNGATE

	Add(sw->ComponentList, c);

	// VPN Bridge
	c = SwNewComponent(SW_NAME_VPNBRIDGE, GC_SVC_NAME_VPNBRIDGE, SW_CMP_VPN_BRIDGE, ICO_CASCADE, 7, L"vpnbridge.exe",
		SW_LONG_VPNBRIDGE, false, sizeof(vpn_bridge_files) / sizeof(char *), vpn_bridge_files,
		L"vpnsmgr.exe", _UU("SW_RUN_TEXT_VPNSMGR"),
		old_msi_vpnbridge, sizeof(old_msi_vpnbridge) / sizeof(SW_OLD_MSI));
	Add(sw->ComponentList, c);

	// VPN Server Manager (Tools Only)
	c = SwNewComponent(SW_NAME_VPNSMGR, NULL, SW_CMP_VPN_SMGR, ICO_USER_ADMIN, 8, NULL,
		SW_LONG_VPNSMGR, false, sizeof(vpn_smgr_files) / sizeof(char *), vpn_smgr_files,
		L"vpnsmgr.exe", _UU("SW_RUN_TEXT_VPNSMGR"),
		NULL, 0);
	Add(sw->ComponentList, c);

	// VPN Client Manager (Tools Only)
	c = SwNewComponent(SW_NAME_VPNCMGR, NULL, SW_CMP_VPN_CMGR, ICO_INTERNET, 9, NULL,
		SW_LONG_VPNCMGR, false, sizeof(vpn_cmgr_files) / sizeof(char *), vpn_cmgr_files,
		L"vpncmgr.exe /remote", _UU("SW_RUN_TEXT_VPNCMGR"),
		NULL, 0);
	Add(sw->ComponentList, c);
}

// Detect the available components
void SwDetectComponents(SW *sw)
{
	UINT i;
	// Validate arguments
	if (sw == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(sw->ComponentList);i++)
	{
		SW_COMPONENT *c = LIST_DATA(sw->ComponentList, i);

		c->Detected = SwIsComponentDetected(sw, c);
	}

	// Determine whether the automatic connection configuration file exists in the same directory
	if (true)
	{
		wchar_t tmp[MAX_PATH];

		ConbinePathW(tmp, sizeof(tmp), MsGetExeDirNameW(), SW_AUTO_CONNECT_ACCOUNT_FILE_NAME_W);

		if (IsFileExistsW(tmp))
		{
			// Exist
			UniStrCpy(sw->auto_setting_path, sizeof(sw->auto_setting_path), tmp);
		}
	}
}

// Determine whether detection of the component is successful
bool SwIsComponentDetected(SW *sw, SW_COMPONENT *c)
{
	UINT i;
	bool ret = true;
	// Validate arguments
	if (sw == NULL || c == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(c->NeedFiles);i++)
	{
		char *name = LIST_DATA(c->NeedFiles, i);
		wchar_t name_w[MAX_SIZE];
		wchar_t fullpath[MAX_SIZE];

		StrToUni(name_w, sizeof(name_w), name);

		CombinePathW(fullpath, sizeof(fullpath), sw->InstallSrc, name_w);

		if (IsFileExistsW(fullpath) == false)
		{
			ret = false;
			break;
		}
	}

	if (c->InstallService == false)
	{
		if (sw->IsEasyInstaller || sw->IsWebInstaller)
		{
			// Prevent installing only management tool
			// for Web installer or a simple installer
			ret = false;
		}
	}

	return ret;
}

// Add a new log
void SwAddLog(SW *sw, SW_LOGFILE *logfile, UINT type, wchar_t *path)
{
	SW_LOG *g;
	// Validate arguments
	if (sw == NULL || path == NULL || logfile == NULL)
	{
		return;
	}

	g = ZeroMalloc(sizeof(SW_LOG));
	g->Type = type;
	UniStrCpy(g->Path, sizeof(g->Path), path);

	Add(logfile->LogList, g);
}
void SwAddLogA(SW *sw, SW_LOGFILE *logfile, UINT type, char *path)
{
	wchar_t *w;
	// Validate arguments
	if (sw == NULL || path == NULL || logfile == NULL)
	{
		return;
	}

	w = CopyStrToUni(path);

	SwAddLog(sw, logfile, type, w);

	Free(w);
}

// Create a SW
SW *NewSw()
{
	SW *sw = ZeroMalloc(sizeof(SW));

	sw->IsSystemMode = true;

	sw->ComponentList = NewListFast(NULL);

	sw->ExitCode = SW_EXIT_CODE_USER_CANCEL;

	UniStrCpy(sw->InstallSrc, sizeof(sw->InstallSrc), MsGetExeDirNameW());

	SwDefineComponents(sw);

	return sw;
}

// Release the SW
UINT FreeSw(SW *sw)
{
	UINT i;
	UINT ret;
	// Validate arguments
	if (sw == NULL)
	{
		return SW_EXIT_CODE_INTERNAL_ERROR;
	}

	SwLeaveSingle(sw);

	for (i = 0;i < LIST_NUM(sw->ComponentList);i++)
	{
		SW_COMPONENT *c = LIST_DATA(sw->ComponentList, i);

		SwFreeComponent(c);
	}

	ReleaseList(sw->ComponentList);

	SwFreeLogFile(sw->LogFile);

	if (sw->ReExecProcessHandle != NULL)
	{
		// If you have started the child process, wait for the termination of child process
		sw->ExitCode = MsWaitProcessExit(sw->ReExecProcessHandle);
	}

	ret = sw->ExitCode;

	Free(sw);

	return ret;
}

// Exit the multi-starts prevention mode
void SwLeaveSingle(SW *sw)
{
	// Validate arguments
	if (sw == NULL)
	{
		return;
	}

	if (sw->Single != NULL)
	{
		FreeSingleInstance(sw->Single);
		sw->Single = NULL;
	}
}

// Enter multiple-starts prevention mode
bool SwEnterSingle(SW *sw)
{
	// Validate arguments
	if (sw == NULL)
	{
		return false;
	}

	if (sw->Single != NULL)
	{
		return true;
	}

	sw->Single = NewSingleInstance(SW_SINGLE_INSTANCE_NAME);

	if (sw->Single == NULL)
	{
		return false;
	}

	return true;
}

// Parse the command line
void SwParseCommandLine(SW *sw)
{
	CONSOLE *c;
	wchar_t *cmdline;
	LIST *o;
	PARAM args[] =
	{
		{"UAC", NULL, NULL, NULL, NULL, },
		{"LANGUAGE", NULL, NULL, NULL, NULL, },
		{"LANGID", NULL, NULL, NULL, NULL, },
		{"LANGNOW", NULL, NULL, NULL, NULL, },
		{"SETLANGANDREBOOT", NULL, NULL, NULL, NULL, },
		{"EASY", NULL, NULL, NULL, NULL, },
		{"WEB", NULL, NULL, NULL, NULL, },
		{"SFXMODE", NULL, NULL, NULL, NULL, },
		{"SFXOUT", NULL, NULL, NULL, NULL, },
		{"HIDESTARTCOMMAND", NULL, NULL, NULL, NULL, },
		{"CALLERSFXPATH", NULL, NULL, NULL, NULL, },
		{"ISEASYINSTALLER", NULL, NULL, NULL, NULL, },
		{"DISABLEAUTOIMPORT", NULL, NULL, NULL, NULL, },
		{"ISWEBINSTALLER", NULL, NULL, NULL, NULL, },
		{"SUINSTMODE", NULL, NULL, NULL, NULL, },
	};
	// Validate arguments
	if (sw == NULL)
	{
		return;
	}

	c = NewLocalConsole(NULL, NULL);
	if (c == NULL)
	{
		return;
	}

	cmdline = GetCommandLineUniStr();

	if (UniIsEmptyStr(cmdline) == false)
	{
		o = ParseCommandList(c, "setup", cmdline, args, sizeof(args) / sizeof(args[0]));

		if (o != NULL)
		{
			sw->IsReExecForUac = GetParamYes(o, "UAC");
			sw->LanguageMode = GetParamYes(o, "LANGUAGE");
			sw->LangId = GetParamInt(o, "LANGID");
			sw->LangNow = GetParamYes(o, "LANGNOW");
			sw->SetLangAndReboot = GetParamYes(o, "SETLANGANDREBOOT");
			sw->HideStartCommand = GetParamYes(o, "HIDESTARTCOMMAND");
			sw->SuInstMode = GetParamYes(o, "SUINSTMODE");

			// Special mode
			if (sw->LanguageMode == false)
			{
				sw->EasyMode = GetParamYes(o, "EASY");

				if (sw->EasyMode == false)
				{
					sw->WebMode = GetParamYes(o, "WEB");
				}
			}

			StrCpy(sw->SfxMode, sizeof(sw->SfxMode), GetParamStr(o, "SFXMODE"));
			UniStrCpy(sw->SfxOut, sizeof(sw->SfxOut), GetParamUniStr(o, "SFXOUT"));
			UniStrCpy(sw->CallerSfxPath, sizeof(sw->CallerSfxPath), GetParamUniStr(o, "CALLERSFXPATH"));
			sw->IsEasyInstaller = GetParamYes(o, "ISEASYINSTALLER");
			sw->IsWebInstaller = GetParamYes(o, "ISWEBINSTALLER");
			sw->DisableAutoImport = GetParamYes(o, "DISABLEAUTOIMPORT");

			FreeParamValueList(o);
		}
	}

	Free(cmdline);

	c->Free(c);
}

// Start the Setup Wizard
UINT SWExecMain()
{
	SW *sw;
	UINT ret;
	SW_LOGFILE *logfile = NULL;
	wchar_t verstr[MAX_SIZE];
	char ver[MAX_SIZE];

	// Define the wizard UI
	GetCedarVersion(ver, sizeof(ver));
	UniFormat(verstr, sizeof(verstr), _UU("SW_TITLE"), ver);

	InitWinUi(verstr, _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));

	// Create a SW
	sw = NewSw();

	// Read the setting
	sw->Easy_EraseSensitive = MsRegReadInt(REG_CURRENT_USER, SW_REG_KEY, "Easy_EraseSensitive");
	sw->Easy_EasyMode = MsRegReadInt(REG_CURRENT_USER, SW_REG_KEY, "Easy_EasyMode");
	sw->Web_EraseSensitive = MsRegReadInt(REG_CURRENT_USER, SW_REG_KEY, "Web_EraseSensitive");
	sw->Web_EasyMode = MsRegReadInt(REG_CURRENT_USER, SW_REG_KEY, "Web_EasyMode");

	// Parse the command line
	SwParseCommandLine(sw);

	// Test!
	//sw->WebMode = true;

	// Detect the installable components
	SwDetectComponents(sw);

	if (IsEmptyStr(sw->SfxMode) == false && UniIsEmptyStr(sw->SfxOut) == false)
	{
		// SFX generation mode
		if (SwGenSfxModeMain(sw->SfxMode, sw->SfxOut))
		{
			// Success
			sw->ExitCode = 0;
		}
	}
	else if (sw->SuInstMode)
	{
		// SuInst mode
		sw->ExitCode = 0;
		if (SuInstallDriver(false) == false)
		{
			sw->ExitCode = SW_EXIT_CODE_INTERNAL_ERROR;
		}
	}
	else
	{
		// Normal mode
		// Load setuplog.dat
		if (IsFileExistsW(L"@" L"setuplog.dat") && (logfile = SwLoadLogFile(sw, L"@" L"setuplog.dat")) == NULL)
		{
			// Setuplog.dat is broken
			MsgBox(NULL, MB_ICONSTOP, _UU("SW_SETUPLOG_CORRUPTED"));
		}
		else
		{
			sw->LogFile = logfile;
			if (sw->LogFile == NULL)
			{
				// Setuplog.dat does not exist
				sw->LogFile = SwNewLogFile();
			}
			else
			{
				// When setuplog.dat exists, it is in either of language-setting-change-mode, simple-installer-creation-mode, uninstall-mode
				sw->CurrentComponent = sw->LogFile->Component;
				sw->IsSystemMode = sw->LogFile->IsSystemMode;
				UniStrCpy(sw->InstallDir, sizeof(sw->InstallDir), MsGetExeDirNameW());

				if (sw->LanguageMode == false && sw->EasyMode == false && sw->WebMode == false)
				{
					// Uninstall mode
					sw->UninstallMode = true;
				}
			}

			// UI main
			SwUiMain(sw);
		}
	}

	// Release the SW
	ret = FreeSw(sw);

	FreeWinUi();

	return ret;
}


#endif	// WIN32



