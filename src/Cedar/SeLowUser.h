// SoftEther VPN Source Code - Developer Edition Master Branch
// SeLow: SoftEther Lightweight Network Protocol


// SeLowUser.h
// Header for SeLowUser.c

#ifndef	SELOWUSER_H
#define	SELOWUSER_H

#include <SeLow/SeLowCommon.h>

//// Macro
#define	SL_USER_INSTALL_LOCK_TIMEOUT		60000		// Lock acquisition timeout
#define	SL_USER_AUTO_PUSH_TIMER				60000		// Timer to start the installation automatically

//// Type

// SU
struct SU
{
	void *hFile;							// File handle
	SL_ADAPTER_INFO_LIST AdapterInfoList;	// Adapter list cache
};

// Adapter
struct SU_ADAPTER
{
	char AdapterId[MAX_PATH];				// Adapter ID
	char DeviceName[MAX_PATH];				// Device name
	void *hFile;							// File handle
	void *hEvent;							// Event handle
	bool Halt;
	UINT CurrentPacketCount;
	UCHAR GetBuffer[SL_EXCHANGE_BUFFER_SIZE];	// Read buffer
	UCHAR PutBuffer[SL_EXCHANGE_BUFFER_SIZE];	// Write buffer
};

// Adapter list items
struct SU_ADAPTER_LIST
{
	SL_ADAPTER_INFO Info;					// Adapter information
	char Guid[128];							// GUID
	char Name[MAX_SIZE];					// Name
	char SortKey[MAX_SIZE];					// Sort key
};


//// Function prototype
SU *SuInit();
SU *SuInitEx(UINT wait_for_bind_complete_tick);
void SuFree(SU *u);
TOKEN_LIST *SuEnumAdapters(SU *u);
SU_ADAPTER *SuOpenAdapter(SU *u, char *adapter_id);
void SuCloseAdapter(SU_ADAPTER *a);
void SuCloseAdapterHandleInner(SU_ADAPTER *a);
bool SuGetPacketsFromDriver(SU_ADAPTER *a);
bool SuGetNextPacket(SU_ADAPTER *a, void **buf, UINT *size);
bool SuPutPacketsToDriver(SU_ADAPTER *a);
bool SuPutPacket(SU_ADAPTER *a, void *buf, UINT size);

SU_ADAPTER_LIST *SuAdapterInfoToAdapterList(SL_ADAPTER_INFO *info);
LIST *SuGetAdapterList(SU *u);
void SuFreeAdapterList(LIST *o);
int SuCmpAdapterList(void *p1, void *p2);

bool SuInstallDriver(bool force);
bool SuInstallDriverInner(bool force);
bool SuIsSupportedOs(bool on_install);
bool SuCopySysFile(wchar_t *src, wchar_t *dst);

void SuDeleteGarbageInfs();
void SuDeleteGarbageInfsInner();
bool SuLoadDriversHive();
bool SuUnloadDriversHive();

#endif	// SELOWUSER_H



