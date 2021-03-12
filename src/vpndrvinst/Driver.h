#ifndef DRIVER_H
#define DRIVER_H

#include <stdbool.h>
#include <stddef.h>

#define DRIVER_DEVICE_ID_TAG "NeoAdapter_%s"
#define VLAN_ADAPTER_NAME_TAG "VPN Client Adapter - %s"

typedef struct HAMCORE HAMCORE;

const char *GetArch();
const char *GetDriverPath();
const char *GetTmpPath();

void GetCatPath(char *dst, const size_t size, const char *instance);
void GetInfPath(char *dst, const size_t size, const char *instance);
void GetSysPath(char *dst, const size_t size, const char *instance);

bool IsInstanceNameOK(HAMCORE *hamcore, const char *instance);
bool IsMacAddressManual();

bool PrepareCat(HAMCORE *hamcore, char *dst, const size_t size, const char *instance);
bool PrepareInf(HAMCORE *hamcore, char *dst, const size_t size, const char *instance, const char *sys, const char *mac);
bool PrepareSys(HAMCORE *hamcore, char *dst, const size_t size, const char *instance);

#endif
