#include "Device.h"

#include "Dialog.h"
#include "Driver.h"
#include "Str.h"

#include "Hamcore.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>

#include <cfgmgr32.h>
#include <devguid.h>
#include <newdev.h>
#include <RegStr.h>
#include <SetupAPI.h>

HDEVINFO GetDeviceInfo(SP_DEVINFO_DATA *devinfo_data, const char *instance)
{
	if (!devinfo_data || !instance)
	{
		return NULL;
	}

	HDEVINFO devinfo = SetupDiGetClassDevs(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
	if (devinfo == INVALID_HANDLE_VALUE)
	{
		ShowWarning("GetDeviceInfo()", "SetupDiGetClassDevs() failed with error %lu!", GetLastError());
		return NULL;
	}

	SP_DEVINFO_LIST_DETAIL_DATA detail_data;
	detail_data.cbSize = sizeof(detail_data);

	if (!SetupDiGetDeviceInfoListDetail(devinfo, &detail_data))
	{
		ShowWarning("GetDeviceInfo()", "SetupDiGetDeviceInfoListDetail() failed with error %lu!", GetLastError());
		FreeDeviceInfo(devinfo);
		return NULL;
	}

	char id[MAX_PATH];
	snprintf(id, sizeof(id), DRIVER_DEVICE_ID_TAG, instance);

	bool found = false;
	SP_DEVINFO_DATA data;
	data.cbSize = sizeof(data);

	for (DWORD i = 0; SetupDiEnumDeviceInfo(devinfo, i, &data); ++i)
	{
		DWORD size;
		if (!SetupDiGetDeviceRegistryProperty(devinfo, &data, SPDRP_HARDWAREID, NULL, NULL, 0, &size))
		{
			const DWORD error = GetLastError();
			if (error != ERROR_INSUFFICIENT_BUFFER)
			{
				ShowWarning("GetDeviceInfo()", "SetupDiGetDeviceRegistryProperty() failed with error %lu!", error);
				continue;
			}
		}

		char *buffer = malloc(size);
		if (!SetupDiGetDeviceRegistryProperty(devinfo, &data, SPDRP_HARDWAREID, NULL, (BYTE *)buffer, size, NULL))
		{
			ShowWarning("GetDeviceInfo()", "SetupDiGetDeviceRegistryProperty() failed with error %lu!", GetLastError());
			free(buffer);
			continue;
		}

		if (strcmp(buffer, id) == 0)
		{
			found = true;
		}

		free(buffer);

		if (found)
		{
			break;
		}
	}

	if (!found)
	{
		FreeDeviceInfo(devinfo);
		return NULL;
	}

	memcpy(devinfo_data, &data, sizeof(data));
	return devinfo;
}

void FreeDeviceInfo(HDEVINFO info)
{
	if (info)
	{
		SetupDiDestroyDeviceInfoList(info);
	}
}

bool ToggleDevice(const char *instance, const bool enable)
{
	if (!instance)
	{
		return false;
	}

	SP_DEVINFO_DATA data;
	HDEVINFO info = GetDeviceInfo(&data, instance);
	if (!info)
	{
		ShowWarning("ToggleDevice()", "The specified device was not found!");
		return false;
	}

	bool ok = false;

	SP_PROPCHANGE_PARAMS params;
	params.HwProfile = 0;
	params.Scope = DICS_FLAG_CONFIGSPECIFIC;
	params.StateChange = enable ? DICS_ENABLE : DICS_DISABLE;
	params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	params.ClassInstallHeader.cbSize = sizeof(params.ClassInstallHeader);

	if (!SetupDiSetClassInstallParams(info, &data, &params.ClassInstallHeader, sizeof(params)))
	{
		ShowWarning("ToggleDevice()", "SetupDiSetClassInstallParams() failed with error %lu!", GetLastError());
		goto FINAL;
	}

	if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, info, &data))
	{
		ShowWarning("ToggleDevice()", "SetupDiCallClassInstaller() failed with error %lu!", GetLastError());

		// Clear parameters, otherwise the device may remain in an inconsistent state
		// (e.g. with the enabled icon even if disabled).
		SetupDiSetClassInstallParams(info, &data, NULL, 0);

		goto FINAL;
	}

	ok = true;
FINAL:
	FreeDeviceInfo(info);
	return ok;
}

bool InstallDevice(const char *instance)
{
	if (!instance)
	{
		return false;
	}

	char mac[MAC_BUFFER_SIZE];
	GenMacAddress(mac, sizeof(mac));

	return InstallDeviceWithMac(instance, mac);
}

bool InstallDeviceWithMac(const char *instance, const char *mac)
{
	if (!instance || !mac)
	{
		return false;
	}

	SP_DEVINFO_DATA data;
	HDEVINFO info = GetDeviceInfo(&data, instance);
	if (info)
	{
		ShowWarning("InstallDevice()", "The specified device already exists!");
		return false;
	}

	HAMCORE *hamcore = HamcoreOpen("hamcore.se2");
	if (!hamcore)
	{
		ShowWarning("InstallDevice()", "Failed to open hamcore.se2!");
		return false;
	}

	bool ok = false;
	bool delete_files = false;

	if (!IsInstanceNameOK(hamcore, instance))
	{
		ShowWarning("InstallDevice()", "\"%s\" cannot be used as instance name, please choose another!", instance);
		goto FINAL;
	}

	char cat[MAX_PATH];
	if (!PrepareCat(hamcore, cat, sizeof(cat), instance))
	{
		goto FINAL;
	}

	char sys[MAX_PATH];
	if (!PrepareSys(hamcore, sys, sizeof(sys), instance))
	{
		goto FINAL;
	}

	char inf[MAX_PATH];
	if (!PrepareInf(hamcore, inf, sizeof(inf), instance, sys, mac))
	{
		goto FINAL;
	}

	delete_files = true;

	GUID inf_guid;
	char inf_class[MAX_CLASS_NAME_LEN];
	if (!SetupDiGetINFClass(inf, &inf_guid, inf_class, sizeof(inf_class), NULL))
	{
		ShowWarning("InstallDevice()", "SetupDiGetINFClass() failed with error %lu!", GetLastError());
		goto FINAL;
	}

	info = SetupDiCreateDeviceInfoList(&inf_guid, NULL);
	if (info == INVALID_HANDLE_VALUE)
	{
		ShowWarning("InstallDevice()", "SetupDiCreateDeviceInfoList() failed with error %lu!", GetLastError());
		goto FINAL;
	}

	SP_DEVINFO_DATA info_data;
	info_data.cbSize = sizeof(info_data);
	if (!SetupDiCreateDeviceInfo(info, inf_class, &inf_guid, NULL, NULL, DICD_GENERATE_ID, &info_data))
	{
		ShowWarning("InstallDevice()", "SetupDiCreateDeviceInfo() failed with error %lu!", GetLastError());
		goto FINAL;
	}

	char id[MAX_PATH];
	snprintf(id, sizeof(id), DRIVER_DEVICE_ID_TAG, instance);

	// Passing the full buffer size caused a second hardware ID containing random symbols to appear
	// on a fresh Windows 7 VM several times when using long instance names.
	// As a simple and effective solution, we simply pass the string length + 1 for the NULL char.
	if (!SetupDiSetDeviceRegistryProperty(info, &info_data, SPDRP_HARDWAREID, (BYTE *)id, (DWORD)strlen(id) + 1))
	{
		ShowWarning("InstallDevice()", "SetupDiSetDeviceRegistryProperty() failed with error %lu!", GetLastError());
		goto FINAL;
	}

	if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, info, &info_data))
	{
		ShowWarning("InstallDevice()", "SetupDiCallClassInstaller() failed with error %lu!", GetLastError());
		goto FINAL;
	}

	BOOL reboot_required;
	if (!UpdateDriverForPlugAndPlayDevices(NULL, id, inf, INSTALLFLAG_FORCE, &reboot_required))
	{
		ShowWarning("InstallDevice()", "UpdateDriverForPlugAndPlayDevices() failed with error %lu!", GetLastError());

		if (!SetupDiCallClassInstaller(DIF_REMOVE, info, &info_data))
		{
			ShowWarning("InstallDevice()", "SetupDiCallClassInstaller() failed with error %lu!", GetLastError());
		}

		if (!SetupDiRemoveDevice(info, &info_data))
		{
			ShowWarning("InstallDevice()", "SetupDiRemoveDevice() failed with error %lu!", GetLastError());
		}

		goto FINAL;
	}

	if (IsMacAddressManual())
	{
		SetDeviceMac(instance, mac);
	}

	SetDeviceNetConfig(instance);

	ok = true;
FINAL:
	if (delete_files)
	{
		DeleteFile(cat);
		DeleteFile(sys);
		DeleteFile(inf);
	}

	HamcoreClose(hamcore);
	FreeDeviceInfo(info);
	return ok;
}

bool UninstallDevice(const char *instance)
{
	if (!instance)
	{
		return false;
	}

	SP_DEVINFO_DATA info_data;
	HDEVINFO info = GetDeviceInfo(&info_data, instance);
	if (!info)
	{
		ShowWarning("UninstallDevice()", "The specified device was not found!");
		return false;
	}

	bool ok = false;

	SP_DEVINFO_LIST_DETAIL_DATA detail_data;
	detail_data.cbSize = sizeof(detail_data);
	if (!SetupDiGetDeviceInfoListDetail(info, &detail_data))
	{
		ShowWarning("UninstallDevice()", "SetupDiGetDeviceInfoListDetail() failed with error %lu!", GetLastError());
		goto FINAL;
	}

	SP_REMOVEDEVICE_PARAMS params;
	params.Scope = DI_REMOVEDEVICE_GLOBAL;
	params.ClassInstallHeader.InstallFunction = DIF_REMOVE;
	params.ClassInstallHeader.cbSize = sizeof(params.ClassInstallHeader);

	if (!SetupDiSetClassInstallParams(info, &info_data, &params.ClassInstallHeader, sizeof(params)))
	{
		ShowWarning("UninstallDevice()", "SetupDiSetClassInstallParams() failed with error %lu!", GetLastError());
		goto FINAL;
	}

	if (!SetupDiCallClassInstaller(DIF_REMOVE, info, &info_data))
	{
		ShowWarning("UninstallDevice()", "SetupDiCallClassInstaller() failed with error %lu!", GetLastError());
		goto FINAL;
	}

	ok = true;
FINAL:
	FreeDeviceInfo(info);
	return ok;
}

bool UpgradeDevice(const char *instance)
{
	if (!instance)
	{
		return false;
	}

	SP_DEVINFO_DATA data;
	HDEVINFO info = GetDeviceInfo(&data, instance);
	if (!info)
	{
		ShowWarning("UpgradeDevice()", "The specified device was not found!");
		return false;
	}

	FreeDeviceInfo(info);

	char mac[MAC_BUFFER_SIZE];
	if (!GetDeviceMac(instance, mac, sizeof(mac)))
	{
		return false;
	}

	if (!UninstallDevice(instance))
	{
		return false;
	}

	if (!InstallDeviceWithMac(instance, mac))
	{
		return false;
	}

	if (IsMacAddressManual())
	{
		SetDeviceMac(instance, mac);
	}

	return true;
}

bool GetDeviceMac(const char *instance, char *dst, const size_t size)
{
	if (!instance || !dst || size == 0)
	{
		return false;
	}

	HKEY key = GetDeviceRegKey(instance, false);
	if (!key)
	{
		return false;
	}

	DWORD buffer_size = (DWORD)size;
	LSTATUS ret = RegGetValue(key, NULL, "NetworkAddress", RRF_RT_REG_SZ, NULL, dst, &buffer_size);
	RegCloseKey(key);

	if (ret != ERROR_SUCCESS)
	{
		ShowWarning("GetDeviceMac()", "RegGetValue() failed with error %ld!", ret);
		return false;
	}

	return true;
}

bool SetDeviceMac(const char *instance, const char *src)
{
	if (!instance || !src)
	{
		return false;
	}

	HKEY key = GetDeviceRegKey(instance, true);
	if (!key)
	{
		return false;
	}

	LSTATUS ret = RegSetKeyValue(key, NULL, "NetworkAddress", REG_SZ, src, (DWORD)strlen(src) + 1);
	RegCloseKey(key);

	if (ret != ERROR_SUCCESS)
	{
		ShowWarning("SetDeviceMac()", "RegSetValue() failed with error %ld!", ret);
		return false;
	}

	ToggleDevice(instance, false);
	ToggleDevice(instance, true);

	return true;
}

bool SetDeviceNetConfig(const char *instance)
{
	if (!instance)
	{
		return false;
	}

	HKEY key = GetDeviceRegKey(instance, true);
	if (!key)
	{
		return false;
	}

	char path[MAX_PATH] = REGSTR_PATH_SERVICES "\\Tcpip\\Parameters\\Interfaces\\";
	const size_t path_len = strlen(path);

	DWORD buffer_size = sizeof(path) - path_len;
	LSTATUS ret = RegGetValue(key, NULL, "NetCfgInstanceId", RRF_RT_REG_SZ, NULL, path + path_len, &buffer_size);
	RegCloseKey(key);

	if (ret != ERROR_SUCCESS)
	{
		ShowWarning("SetDeviceNetConfig()", "RegGetValue() failed with error %ld!", ret);
		return false;
	}

	bool ok = true;

	DWORD tmp = 0;
	ret = RegSetKeyValue(HKEY_LOCAL_MACHINE, path, "EnableDeadGWDetect", REG_DWORD, &tmp, sizeof(tmp));
	if (ret != ERROR_SUCCESS)
	{
		ShowWarning("SetDeviceNetConfig()", "RegSetKeyValue() failed to set EnableDeadGWDetect with error %ld!", ret);
		ok = false;
	}

	tmp = 1;
	ret = RegSetKeyValue(HKEY_LOCAL_MACHINE, path, "InterfaceMetric", REG_DWORD, &tmp, sizeof(tmp));
	if (ret != ERROR_SUCCESS)
	{
		ShowWarning("SetDeviceNetConfig()", "RegSetKeyValue() failed to set InterfaceMetric with error %ld!", ret);
		ok = false;
	}

	return ok;
}

HKEY GetDeviceRegKey(const char *instance, const bool writable)
{
	if (!instance)
	{
		return NULL;
	}

	char path[MAX_PATH] = REGSTR_PATH_CLASS_NT "\\";
	const size_t path_len = strlen(path);
	StrFromGUID(path + path_len, sizeof(path) - path_len, &GUID_DEVCLASS_NET);

	HKEY key_list;
	LSTATUS ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &key_list);
	if (ret != ERROR_SUCCESS)
	{
		ShowWarning("GetDeviceRegKey()", "RegOpenKeyEx() failed to open \"%s\", with error %ld!", path, ret);
		return NULL;
	}

	char device_id[MAX_PATH];
	snprintf(device_id, sizeof(device_id), DRIVER_DEVICE_ID_TAG, instance);

	char driver_desc[MAX_PATH];
	snprintf(driver_desc, sizeof(driver_desc), VLAN_ADAPTER_NAME_TAG, instance);

	for (DWORD i = 0; ++i;)
	{
		char key_name[MAX_PATH];
		DWORD key_name_size = sizeof(key_name);
		ret = RegEnumKeyEx(key_list, i, key_name, &key_name_size, 0, NULL, 0, NULL);
		if (ret != ERROR_SUCCESS)
		{
			if (ret != ERROR_NO_MORE_ITEMS)
			{
				ShowWarning("GetDeviceRegKey()", "RegEnumKeyEx() failed at index %lu with error %ld!", i, ret);
			}

			break;
		}

		HKEY key;
		if (RegOpenKeyEx(key_list, key_name, 0, writable ? KEY_READ | KEY_WRITE : KEY_READ, &key) != ERROR_SUCCESS)
		{
			continue;
		}

		char buffer[MAX_PATH];
		DWORD buffer_size = sizeof(buffer);

		if (RegGetValue(key, NULL, REGSTR_VAL_MATCHINGDEVID, RRF_RT_REG_SZ, NULL, buffer, &buffer_size) != ERROR_SUCCESS)
		{
			RegCloseKey(key);
			continue;
		}

		if (strncmp(buffer, device_id, buffer_size) == 0)
		{
			return key;
		}

		buffer_size = sizeof(buffer);

		if (RegGetValue(key, NULL, REGSTR_VAL_DRVDESC, RRF_RT_REG_SZ, NULL, buffer, &buffer_size) != ERROR_SUCCESS)
		{
			RegCloseKey(key);
			continue;
		}

		if (strncmp(buffer, driver_desc, buffer_size) == 0)
		{
			return key;
		}
	}

	return NULL;
}
