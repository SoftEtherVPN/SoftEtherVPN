// SoftEther VPN Source Code - Developer Edition Master Branch
// SeLow: SoftEther Lightweight Network Protocol


// SeLowUser.c
// SoftEther Lightweight Network Protocol User-mode Library

#ifdef OS_WIN32

#include "SeLowUser.h"

#include "BridgeWin32.h"
#include "Win32Com.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "See/Devioctl.h"

// Load the drivers hive
bool SuLoadDriversHive()
{
	wchar_t config_dir[MAX_PATH];
	wchar_t filename[MAX_PATH];
	if (MsIsWindows10() == false)
	{
		return false;
	}

	MsEnablePrivilege(SE_RESTORE_NAME, true);
	MsEnablePrivilege(SE_BACKUP_NAME, true);

	CombinePathW(config_dir, sizeof(config_dir), MsGetSystem32DirW(), L"config");
	CombinePathW(filename, sizeof(filename), config_dir, L"DRIVERS");

	return MsRegLoadHive(REG_LOCAL_MACHINE, L"DRIVERS", filename);
}

// Unload the drivers hive
bool SuUnloadDriversHive()
{
	// todo: always failed.
	if (MsIsWindows10() == false)
	{
		return false;
	}

	return MsRegUnloadHive(REG_LOCAL_MACHINE, L"DRIVERS");
}

// Delete garbage inf files
void SuDeleteGarbageInfs()
{
	void *wow;
	bool load_hive = false;
	Debug("SuDeleteGarbageInfs()\n");

	wow = MsDisableWow64FileSystemRedirection();

	load_hive = SuLoadDriversHive();
	Debug("SuLoadDriversHive: %u\n", load_hive);

	SuDeleteGarbageInfsInner();

	/*
	if (load_hive)
	{
		Debug("SuUnloadDriversHive: %u\n", SuUnloadDriversHive());
	}*/

	MsRestoreWow64FileSystemRedirection(wow);
}
void SuDeleteGarbageInfsInner()
{
	char *base_key_name = "DRIVERS\\DriverDatabase\\DriverPackages";
	TOKEN_LIST *keys;
	HINSTANCE hSetupApiDll = NULL;
	BOOL (WINAPI *_SetupUninstallOEMInfA)(PCSTR, DWORD, PVOID) = NULL;

	if (MsIsWindows10() == false)
	{
		return;
	}

	hSetupApiDll = LoadLibraryA("setupapi.dll");
	if (hSetupApiDll == NULL)
	{
		return;
	}

    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wincompatible-function-pointer-types"
	_SetupUninstallOEMInfA =
		(UINT (__stdcall *)(PCSTR,DWORD,PVOID))
		GetProcAddress(hSetupApiDll, "SetupUninstallOEMInfA");
    #pragma clang diagnostic pop

	if (_SetupUninstallOEMInfA != NULL)
	{
		keys = MsRegEnumKeyEx2(REG_LOCAL_MACHINE, base_key_name, false, true);

		if (keys != NULL)
		{
			char full_key[MAX_PATH];
			UINT i;

			for (i = 0;i < keys->NumTokens;i++)
			{
				char *oem_name, *inf_name, *provider;

				Format(full_key, sizeof(full_key), "%s\\%s", base_key_name, keys->Token[i]);

				oem_name = MsRegReadStrEx2(REG_LOCAL_MACHINE, full_key, "", false, true);
				inf_name = MsRegReadStrEx2(REG_LOCAL_MACHINE, full_key, "InfName", false, true);
				provider = MsRegReadStrEx2(REG_LOCAL_MACHINE, full_key, "Provider", false, true);

				if (IsEmptyStr(oem_name) == false && IsEmptyStr(inf_name) == false)
				{
					if (StartWith(oem_name, "oem"))
					{
						if (StartWith(inf_name, "selow"))
						{
							if (InStr(provider, "softether"))
							{
								Debug("Delete OEM INF %s (%s): %u\n",
									oem_name, inf_name,
									_SetupUninstallOEMInfA(oem_name, 0x00000001, NULL));
							}
						}
					}
				}

				Free(oem_name);
				Free(inf_name);
				Free(provider);
			}

			FreeToken(keys);
		}
	}

	if (hSetupApiDll != NULL)
	{
		FreeLibrary(hSetupApiDll);
	}
}

// Install the driver
bool SuInstallDriver(bool force)
{
	bool ret;
	void *wow;

	wow = MsDisableWow64FileSystemRedirection();

	ret = SuInstallDriverInner(force);

	MsRestoreWow64FileSystemRedirection(wow);

	return ret;
}
bool SuInstallDriverInner(bool force)
{
	wchar_t sys_fullpath[MAX_PATH];
	UINT current_sl_ver = 0;
	bool ret = false;
	wchar_t src_cat[MAX_PATH];
	wchar_t src_inf[MAX_PATH];
	wchar_t src_sys[MAX_PATH];
	wchar_t dst_cat[MAX_PATH];
	wchar_t dst_inf[MAX_PATH];
	wchar_t dst_sys[MAX_PATH];
	wchar_t tmp_dir[MAX_PATH];
	char *cpu_type = MsIsX64() ? "x64" : "x86";

	if (SuIsSupportedOs(true) == false)
	{
		// Unsupported OS
		return false;
	}

	CombinePathW(tmp_dir, sizeof(tmp_dir), MsGetWindowsDirW(), L"Temp");
	MakeDirExW(tmp_dir);

	UniStrCat(tmp_dir, sizeof(tmp_dir), L"\\selowtmp");
	MakeDirExW(tmp_dir);

	// Confirm whether the driver is currently installed
	CombinePathW(sys_fullpath, sizeof(sys_fullpath), MsGetSystem32DirW(), L"drivers\\SeLow_%S.sys");
	UniFormat(sys_fullpath, sizeof(sys_fullpath), sys_fullpath, cpu_type);

	if (IsFileExistsW(sys_fullpath))
	{
		char *path;

		// Read the current version from the registry
		current_sl_ver = MsRegReadIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME,
			(MsIsWindows10() ? SL_REG_VER_VALUE_WIN10 : SL_REG_VER_VALUE),
			false, true);

		path = MsRegReadStrEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "ImagePath", false, true);

		if (IsEmptyStr(path) || IsFileExists(path) == false || MsIsServiceInstalled(SL_PROTOCOL_NAME) == false)
		{
			current_sl_ver = 0;
		}

		Free(path);
	}

	if (force == false && current_sl_ver >= SL_VER)
	{
		// Newer version has already been installed
		Debug("Newer SeLow is Installed. %u >= %u\n", current_sl_ver, SL_VER);
		return true;
	}

	// Copy necessary files to a temporary directory
	UniFormat(src_sys, sizeof(src_sys), L"|DriverPackages\\%S\\%S\\SeLow_%S.sys",
		(MsIsWindows10() ? "SeLow_Win10" : "SeLow_Win8"),
		cpu_type, cpu_type);
	if (MsIsWindows8() == false)
	{
		// Windows Vista and Windows 7 uses SHA-1 catalog files
		UniFormat(src_cat, sizeof(src_cat), L"|DriverPackages\\SeLow_Win8\\%S\\inf.cat", cpu_type);
	}
	else
	{
		// Windows 8 or above uses SHA-256 catalog files
		UniFormat(src_cat, sizeof(src_cat), L"|DriverPackages\\SeLow_Win8\\%S\\inf2.cat", cpu_type);

		if (MsIsWindows10())
		{
			// Windows 10 uses WHQL catalog files
			UniFormat(src_cat, sizeof(src_cat), L"|DriverPackages\\SeLow_Win10\\%S\\SeLow_Win10_%S.cat", cpu_type, cpu_type);
		}
	}
	UniFormat(src_inf, sizeof(src_inf), L"|DriverPackages\\%S\\%S\\SeLow_%S.inf",
		(MsIsWindows10() ? "SeLow_Win10" : "SeLow_Win8"),
		cpu_type, cpu_type);

	UniFormat(dst_sys, sizeof(dst_cat), L"%s\\SeLow_%S.sys", tmp_dir, cpu_type);
	UniFormat(dst_cat, sizeof(dst_cat), L"%s\\SeLow_%S_%S.cat", tmp_dir,
		(MsIsWindows10() ? "Win10" : "Win8"),
		cpu_type);

	UniFormat(dst_inf, sizeof(dst_inf), L"%s\\SeLow_%S.inf", tmp_dir, cpu_type);

	if (FileCopyW(src_sys, dst_sys) &&
		FileCopyW(src_cat, dst_cat) &&
		FileCopyW(src_inf, dst_inf))
	{
		NO_WARNING *nw;

		nw = MsInitNoWarningEx(SL_USER_AUTO_PUSH_TIMER);

		if (MsIsWindows10())
		{
			if (MsIsServiceInstalled(SL_PROTOCOL_NAME) == false && MsIsServiceRunning(SL_PROTOCOL_NAME) == false)
			{
				// On Windows 10, if there are no SwLow service installed, then uinstall the protocol driver first.
				// TODO: currently do nothing. On some versions of Windows 10 beta builds it is necessary to do something...
			}
		}

		if (MsIsWindows10())
		{
			// Delete garbage INFs
			SuDeleteGarbageInfs();
		}

		// Call the installer
		if (InstallNdisProtocolDriver(dst_inf, L"SeLow", SL_USER_INSTALL_LOCK_TIMEOUT) == false)
		{
			Debug("InstallNdisProtocolDriver Error.\n");
		}
		else
		{
			Debug("InstallNdisProtocolDriver Ok.\n");

			// Copy manually because there are cases where .sys file is not copied successfully for some reason
			Debug("SuCopySysFile from %S to %s: ret = %u\n", src_sys, sys_fullpath, SuCopySysFile(src_sys, sys_fullpath));

			ret = true;

			// Write the version number into the registry
			MsRegWriteIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME,
				(MsIsWindows10() ? SL_REG_VER_VALUE_WIN10 : SL_REG_VER_VALUE),
				SL_VER, false, true);

			// Set to automatic startup
			MsRegWriteIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "Start", SERVICE_SYSTEM_START, false, true);
		}

		MsFreeNoWarning(nw);
	}
	else
	{
		Debug("Fail Copying Files.\n");
	}

	if (ret)
	{
		// If the service is installed this time, start and wait until the enumeration is completed
		SuFree(SuInitEx(180 * 1000));
	}

	return ret;
}

// Copy a sys file
bool SuCopySysFile(wchar_t *src, wchar_t *dst)
{
	wchar_t dst_rename[MAX_PATH];
	UINT i;
	if (src == NULL || dst == NULL)
	{
		return false;
	}
	if (FileCopyW(src, dst))
	{
		for (i = 1;i <= 100;i++)
		{
			UniFormat(dst_rename, sizeof(dst_rename), L"%s.old%u", dst, i);

			FileDeleteW(dst_rename);
		}

		return true;
	}

	for (i = 1;;i++)
	{
		UniFormat(dst_rename, sizeof(dst_rename), L"%s.old%u", dst, i);

		if (IsFileExistsW(dst_rename) == false)
		{
			break;
		}

		if (i >= 100)
		{
			return false;
		}
	}

	if (MoveFileW(dst, dst_rename) == false)
	{
		return false;
	}

	if (FileCopyW(src, dst))
	{
		for (i = 1;i <= 100;i++)
		{
			UniFormat(dst_rename, sizeof(dst_rename), L"%s.old%u", dst, i);

			FileDeleteW(dst_rename);
		}

		return true;
	}

	MoveFileW(dst_rename, dst);

	return false;
}

// Get whether the current OS is supported by SeLow
bool SuIsSupportedOs(bool on_install)
{
	if (MsRegReadIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "EnableSeLow", false, true) != 0)
	{
		// Force enable
		return true;
	}

	if (MsRegReadIntEx2(REG_LOCAL_MACHINE, SL_REG_KEY_NAME, "DisableSeLow", false, true) != 0)
	{
		// Force disable
		return false;
	}

	if (MsIsWindows10())
	{
		// Windows 10 or later are always supported.
		return true;
	}

	if (on_install)
	{
		// If Microsoft Routing and Remote Access service is running,
		// then return false.
		if (MsIsServiceRunning("RemoteAccess"))
		{
			return false;
		}
	}

	// If the Su driver is currently running,
	// then return true.
	if (MsIsServiceRunning(SL_PROTOCOL_NAME))
	{
		return true;
	}

	// Currently Windows 8.1 or later are supported
	if (MsIsWindows81() == false)
	{
		return false;
	}

	if (on_install == false)
	{
		// If Microsoft Routing and Remote Access service is running,
		// then return false.
		if (MsIsServiceRunning("RemoteAccess"))
		{
			return false;
		}
	}

	return true;
}

// Write the next packet to the driver
bool SuPutPacket(SU_ADAPTER *a, void *buf, UINT size)
{
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}
	if (a->Halt)
	{
		return false;
	}
	if (size > MAX_PACKET_SIZE)
	{
		return false;
	}

	// First, examine whether the current buffer is full
	if ((SL_NUM_PACKET(a->PutBuffer) >= SL_MAX_PACKET_EXCHANGE) ||
		(buf == NULL && SL_NUM_PACKET(a->PutBuffer) != 0))
	{
		// Write all current packets to the driver
		if (SuPutPacketsToDriver(a) == false)
		{
			return false;
		}

		SL_NUM_PACKET(a->PutBuffer) = 0;
	}

	// Add the next packet to the buffer
	if (buf != NULL)
	{
		UINT i = SL_NUM_PACKET(a->PutBuffer);
		SL_NUM_PACKET(a->PutBuffer)++;

		SL_SIZE_OF_PACKET(a->PutBuffer, i) = size;
		Copy(SL_ADDR_OF_PACKET(a->PutBuffer, i), buf, size);

		Free(buf);
	}

	return true;
}

// Write all current packets to the driver
bool SuPutPacketsToDriver(SU_ADAPTER *a)
{
	DWORD write_size;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}
	if (a->Halt)
	{
		return false;
	}

	if (WriteFile(a->hFile, a->PutBuffer, SL_EXCHANGE_BUFFER_SIZE, &write_size, NULL) == false)
	{
		a->Halt = true;

		SuCloseAdapterHandleInner(a);
		return false;
	}

	if (write_size != SL_EXCHANGE_BUFFER_SIZE)
	{
		a->Halt = true;
		return false;
	}

	return true;
}

// Read the next packet from the driver
bool SuGetNextPacket(SU_ADAPTER *a, void **buf, UINT *size)
{
	// Validate arguments
	if (a == NULL || buf == NULL || size == NULL)
	{
		return false;
	}

	if (a->Halt)
	{
		return false;
	}

	while (true)
	{
		if (a->CurrentPacketCount < SL_NUM_PACKET(a->GetBuffer))
		{
			// There are still packets that have been already read
			*size = SL_SIZE_OF_PACKET(a->GetBuffer, a->CurrentPacketCount);
			*buf = Malloc(*size);
			Copy(*buf, SL_ADDR_OF_PACKET(a->GetBuffer, a->CurrentPacketCount), *size);

			// Increment the packet number
			a->CurrentPacketCount++;

			return true;
		}
		else
		{
			// Read the next packet from the driver
			if (SuGetPacketsFromDriver(a) == false)
			{
				return false;
			}

			if (SL_NUM_PACKET(a->GetBuffer) == 0)
			{
				// Packet is not received yet
				*buf = NULL;
				*size = 0;
				return true;
			}

			a->CurrentPacketCount = 0;
		}
	}
}

// Read the next packet from the driver
bool SuGetPacketsFromDriver(SU_ADAPTER *a)
{
	DWORD read_size;
	// Validate arguments
	if (a == NULL)
	{
		return false;
	}

	if (a->Halt)
	{
		return false;
	}

	if (ReadFile(a->hFile, a->GetBuffer, SL_EXCHANGE_BUFFER_SIZE, &read_size, NULL) == false)
	{
		a->Halt = true;

		SuCloseAdapterHandleInner(a);
		return false;
	}

	if (read_size != SL_EXCHANGE_BUFFER_SIZE)
	{
		a->Halt = true;
		return false;
	}

	return true;
}

// Close the adapter
void SuCloseAdapter(SU_ADAPTER *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (a->hEvent != NULL)
	{
		CloseHandle(a->hEvent);
	}

	if (a->hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(a->hFile);
		a->hFile = INVALID_HANDLE_VALUE;
	}

	Free(a);
}

// Close the adapter handle
void SuCloseAdapterHandleInner(SU_ADAPTER *a)
{
	return;//////////// ****************
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (a->hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(a->hFile);
		a->hFile = INVALID_HANDLE_VALUE;
	}
}

// Open the adapter
SU_ADAPTER *SuOpenAdapter(SU *u, char *adapter_id)
{
	char filename[MAX_PATH];
	void *h;
	SU_ADAPTER *a;
	SL_IOCTL_EVENT_NAME t;
	UINT read_size;
	// Validate arguments
	if (u == NULL || adapter_id == NULL)
	{
		return NULL;
	}

	Format(filename, sizeof(filename), SL_ADAPTER_DEVICE_FILENAME_WIN32, adapter_id);

	h = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		Debug("Create File %s failed. %u\n", filename, GetLastError());
		return NULL;
	}
	else
	{
		Debug("Create File %s ok.\n", filename);
	}

	a = ZeroMalloc(sizeof(SU_ADAPTER));

	StrCpy(a->AdapterId, sizeof(a->AdapterId), adapter_id);
	StrCpy(a->DeviceName, sizeof(a->DeviceName), filename);

	a->hFile = h;

	Zero(&t, sizeof(t));

	// Get the event name
	if (DeviceIoControl(h, SL_IOCTL_GET_EVENT_NAME, &t, sizeof(t), &t, sizeof(t), &read_size, NULL) == false)
	{
		// Acquisition failure
		SuCloseAdapter(a);
		return NULL;
	}

	Debug("Event Name: %s\n", t.EventNameWin32);

	// Get the event
	a->hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, t.EventNameWin32);

	if (a->hEvent == NULL)
	{
		// Acquisition failure
		SuCloseAdapter(a);
		return NULL;
	}

	return a;
}

// Enumerate adapters
TOKEN_LIST *SuEnumAdapters(SU *u)
{
	UINT i;
	UINT ret_size;
	TOKEN_LIST *ret;
	// Validate arguments
	if (u == NULL)
	{
		return NullToken();
	}

	Zero(&u->AdapterInfoList, sizeof(u->AdapterInfoList));
	if (ReadFile(u->hFile, &u->AdapterInfoList, sizeof(u->AdapterInfoList),
		&ret_size, NULL) == false ||
		u->AdapterInfoList.Signature != SL_SIGNATURE)
	{
		Debug("SuEnumAdapters: ReadFile error.\n");
		return NullToken();
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));

	ret->NumTokens = u->AdapterInfoList.NumAdapters;
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	Debug("SuEnumAdapters: u->AdapterInfoList.NumAdapters = %u\n", u->AdapterInfoList.NumAdapters);

	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = CopyUniToStr(u->AdapterInfoList.Adapters[i].AdapterId);

		UniPrint(L"%s %u %S\n",
			u->AdapterInfoList.Adapters[i].AdapterId,
			u->AdapterInfoList.Adapters[i].MtuSize,
			u->AdapterInfoList.Adapters[i].FriendlyName);
	}

	return ret;
}

// Create an adapters list
LIST *SuGetAdapterList(SU *u)
{
	LIST *ret;
	UINT read_size;
	UINT i;
	// Validate arguments
	if (u == NULL)
	{
		return NULL;
	}

	ret = NewList(SuCmpAdapterList);

	// Enumerate adapters
	Zero(&u->AdapterInfoList, sizeof(u->AdapterInfoList));
	if (ReadFile(u->hFile, &u->AdapterInfoList, sizeof(u->AdapterInfoList),
		&read_size, NULL) == false ||
		u->AdapterInfoList.Signature != SL_SIGNATURE)
	{
		SuFreeAdapterList(ret);
		return NULL;
	}

	for (i = 0;i < u->AdapterInfoList.NumAdapters;i++)
	{
		SL_ADAPTER_INFO *info = &u->AdapterInfoList.Adapters[i];
		SU_ADAPTER_LIST *a = SuAdapterInfoToAdapterList(info);

		if (a != NULL)
		{
			Add(ret, a);
		}
	}

	// Sort
	Sort(ret);

	return ret;
}

// Comparison function of the adapter list
int SuCmpAdapterList(void *p1, void *p2)
{
	int r;
	SU_ADAPTER_LIST *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(SU_ADAPTER_LIST **)p1;
	a2 = *(SU_ADAPTER_LIST **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}

	r = StrCmpi(a1->SortKey, a2->SortKey);
	if (r != 0)
	{
		return 0;
	}

	return StrCmpi(a1->Guid, a2->Guid);
}

// Release the adapter list
void SuFreeAdapterList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		SU_ADAPTER_LIST *a = LIST_DATA(o, i);

		Free(a);
	}

	ReleaseList(o);
}

// Create an adapter list item
SU_ADAPTER_LIST *SuAdapterInfoToAdapterList(SL_ADAPTER_INFO *info)
{
	SU_ADAPTER_LIST t;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (info == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	Copy(&t.Info, info, sizeof(SL_ADAPTER_INFO));

	UniToStr(tmp, sizeof(tmp), info->AdapterId);
	if (IsEmptyStr(tmp) || IsEmptyStr(info->FriendlyName) || StartWith(tmp, SL_ADAPTER_ID_PREFIX) == false)
	{
		// Name is invalid
		return NULL;
	}

	// GUID (Part after "SELOW_A_" prefix)
	StrCpy(t.Guid, sizeof(t.Guid), tmp + StrLen(SL_ADAPTER_ID_PREFIX));

	// Name
	StrCpy(t.Name, sizeof(t.Name), tmp);

	// Key for sort
	if (GetClassRegKeyWin32(t.SortKey, sizeof(t.SortKey), tmp, sizeof(tmp), t.Guid) == false)
	{
		// Can not be found
		return NULL;
	}

	return Clone(&t, sizeof(t));
}

// Initialize the driver 
SU *SuInit()
{
	return SuInitEx(0);
}
SU *SuInitEx(UINT wait_for_bind_complete_tick)
{
	void *h;
	SU *u;
	UINT read_size;
	bool flag = false;
	UINT64 giveup_tick = 0;
	static bool flag2 = false; // flag2 must be global

	if (SuIsSupportedOs(false) == false)
	{
		// Unsupported OS
		return NULL;
	}

LABEL_RETRY:

	// Open the device driver
	h = CreateFileA(SL_BASIC_DEVICE_FILENAME_WIN32, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (h == INVALID_HANDLE_VALUE)
	{
		Debug("CreateFileA(%s) Failed.\n", SL_BASIC_DEVICE_FILENAME_WIN32);

		// Start the service if it fails to start the device driver
		if (flag == false)
		{
			if (MsStartService(SL_PROTOCOL_NAME) == false)
			{
				Debug("MsStartService(%s) Failed.\n", SL_PROTOCOL_NAME);

				if (MsIsWindows10())
				{
					if (flag2 == false)
					{
						flag2 = true;

						if (SuInstallDriver(true))
						{
							goto LABEL_RETRY;
						}
					}
				}
			}
			else
			{
				Debug("MsStartService(%s) Ok.\n", SL_PROTOCOL_NAME);
				flag = true;

				goto LABEL_RETRY;
			}
		}
		return NULL;
	}

	//Debug("CreateFileA(%s) Ok.\n", SL_BASIC_DEVICE_FILENAME_WIN32);

	u = ZeroMalloc(sizeof(SU));

	giveup_tick = Tick64() + (UINT64)wait_for_bind_complete_tick;

	if (wait_for_bind_complete_tick == 0)
	{
		if (ReadFile(h, &u->AdapterInfoList, sizeof(u->AdapterInfoList), &read_size, NULL) == false ||
			u->AdapterInfoList.Signature != SL_SIGNATURE)
		{
			// Signature reception failure
			Debug("Bad Signature.\n");

			Free(u);
			CloseHandle(h);

			return NULL;
		}
	}
	else
	{
		while (giveup_tick >= Tick64())
		{
			// Wait until the enumeration is completed
			if (ReadFile(h, &u->AdapterInfoList, sizeof(u->AdapterInfoList), &read_size, NULL) == false ||
				u->AdapterInfoList.Signature != SL_SIGNATURE)
			{
				// Signature reception failure
				Debug("Bad Signature.\n");

				Free(u);
				CloseHandle(h);

				return NULL;
			}

			if (u->AdapterInfoList.EnumCompleted)
			{
				// Complete enumeration
				Debug("Bind Completed! %u\n", u->AdapterInfoList.EnumCompleted);
				break;
			}

			// Incomplete enumeration
			Debug("Waiting for Bind Complete.\n");

			SleepThread(25);
		}
	}

	u->hFile = h;

	return u;
}

// Release the driver
void SuFree(SU *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	CloseHandle(u->hFile);

	Free(u);
}

#endif	// WIN32

