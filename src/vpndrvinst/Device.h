#ifndef DEVICE_H
#define DEVICE_H

#include <stdbool.h>
#include <stddef.h>

typedef void *PVOID;
typedef PVOID HDEVINFO;

typedef struct HKEY__ *HKEY;
typedef struct _SP_DEVINFO_DATA SP_DEVINFO_DATA;

HDEVINFO GetDeviceInfo(SP_DEVINFO_DATA *devinfo_data, const char *instance);
void FreeDeviceInfo(HDEVINFO info);

bool ToggleDevice(const char *instance, const bool enable);

bool InstallDevice(const char *instance);
bool InstallDeviceWithMac(const char *instance, const char *mac);
bool UninstallDevice(const char *instance);
bool UpgradeDevice(const char *instance);

bool GetDeviceMac(const char *instance, char *dst, const size_t size);
bool SetDeviceMac(const char *instance, const char *src);

bool SetDeviceNetConfig(const char *instance);

HKEY GetDeviceRegKey(const char *instance, const bool writable);

#endif
