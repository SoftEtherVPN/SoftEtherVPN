// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// EtherLog.h
// Header of EtherLog.c

#ifndef	ETHERLOG_H
#define	ETHERLOG_H

// Whether this is a beta version
#define	ELOG_IS_BETA						true

// Beta expiration date
#define	ELOG_BETA_EXPIRES_YEAR				2008
#define	ELOG_BETA_EXPIRES_MONTH				12
#define ELOG_BETA_EXPIRES_DAY				2

// Version information
//#define	EL_VER							201
//#define	EL_BUILD						1600
//#define	EL_BETA							1
#define MAX_LOGGING_QUEUE_LEN 100000

// RPC related
struct RPC_ADD_DEVICE
{
	char DeviceName[MAX_SIZE];			// Device name
	HUB_LOG LogSetting;					// Log settings
	bool NoPromiscuous;					// Without promiscuous mode
};

struct RPC_DELETE_DEVICE
{
	char DeviceName[MAX_SIZE];			// Device name
};

struct RPC_ENUM_DEVICE_ITEM
{
	char DeviceName[MAX_SIZE];			// Device name
	bool Active;						// Running flag
};

struct RPC_ENUM_DEVICE
{
	UINT NumItem;						// Number of items
	RPC_ENUM_DEVICE_ITEM *Items;		// Items
	bool IsLicenseSupported;			// Whether the license system is supported
};

// License status of the service
struct RPC_EL_LICENSE_STATUS
{
	BOOL Valid;								// Enable flag
	UINT64 SystemId;						// System ID
	UINT64 SystemExpires;					// System expiration date
};

// Device
struct EL_DEVICE
{
	EL *el;								// EL
	char DeviceName[MAX_SIZE];			// Device name
	HUB_LOG LogSetting;					// Log settings
	THREAD *Thread;						// Thread
	CANCEL *Cancel1;					// Cancel 1
	CANCEL *Cancel2;					// Cancel 2
	volatile bool Halt;					// Halting flag
	bool Active;						// Running flag
	bool NoPromiscuous;					// Without promiscuous mode
	LOG *Logger;						// Logger
};

// License status
struct EL_LICENSE_STATUS
{
	BOOL Valid;				// Enable flag
	UINT64 SystemId;		// System ID
	UINT64 Expires;			// Expiration date
};

// EtherLogger
struct EL
{
	LOCK *lock;							// Lock
	REF *ref;							// Reference counter
	CEDAR *Cedar;						// Cedar
	LIST *DeviceList;					// Device list
	CFG_RW *CfgRw;						// Config R/W
	UINT Port;							// Port number
	LISTENER *Listener;					// Listener
	UCHAR HashedPassword[SHA1_SIZE];	// Password
	LIST *AdminThreadList;				// Management thread list
	LIST *AdminSockList;				// Management socket list
	LICENSE_SYSTEM *LicenseSystem;		// License system
	EL_LICENSE_STATUS *LicenseStatus;	// License status
	UINT64 AutoDeleteCheckDiskFreeSpaceMin;	// Minimum free disk space
	ERASER *Eraser;						// Eraser
};

// Function prototype
void ElStart();
void ElStop();
EL *NewEl();
void ReleaseEl(EL *e);
void CleanupEl(EL *e);
void ElInitConfig(EL *e);
void ElFreeConfig(EL *e);
bool ElLoadConfig(EL *e);
void ElLoadConfigFromFolder(EL *e, FOLDER *root);
void ElSaveConfig(EL *e);
void ElSaveConfigToFolder(EL *e, FOLDER *root);
int ElCompareDevice(void *p1, void *p2);
bool ElAddCaptureDevice(EL *e, char *name, HUB_LOG *log, bool no_promiscuous);
bool ElDeleteCaptureDevice(EL *e, char *name);
bool ElSetCaptureDeviceLogSetting(EL *e, char *name, HUB_LOG *log);
void ElCaptureThread(THREAD *thread, void *param);
void ElStartListener(EL *e);
void ElStopListener(EL *e);
void ElListenerProc(THREAD *thread, void *param);
PACK *ElRpcServer(RPC *r, char *name, PACK *p);
void ElParseCurrentLicenseStatus(LICENSE_SYSTEM *s, EL_LICENSE_STATUS *st);
bool ElIsBetaExpired();


UINT EtAddDevice(EL *e, RPC_ADD_DEVICE *t);
UINT EtDelDevice(EL *e, RPC_DELETE_DEVICE *t);
UINT EtSetDevice(EL *e, RPC_ADD_DEVICE *t);
UINT EtGetDevice(EL *e, RPC_ADD_DEVICE *t);
UINT EtEnumDevice(EL *e, RPC_ENUM_DEVICE *t);
UINT EtEnumAllDevice(EL *e, RPC_ENUM_DEVICE *t);
UINT EtSetPassword(EL *e, RPC_SET_PASSWORD *t);
UINT EtAddLicenseKey(EL *a, RPC_TEST *t);
UINT EtDelLicenseKey(EL *a, RPC_TEST *t);
UINT EtEnumLicenseKey(EL *a, RPC_ENUM_LICENSE_KEY *t);
UINT EtGetLicenseStatus(EL *a, RPC_EL_LICENSE_STATUS *t);
UINT EtGetBridgeSupport(EL *a, RPC_BRIDGE_SUPPORT *t);
UINT EtRebootServer(EL *a, RPC_TEST *t);

UINT EcAddDevice(RPC *r, RPC_ADD_DEVICE *t);
UINT EcDelDevice(RPC *r, RPC_DELETE_DEVICE *t);
UINT EcSetDevice(RPC *r, RPC_ADD_DEVICE *t);
UINT EcGetDevice(RPC *r, RPC_ADD_DEVICE *t);
UINT EcEnumDevice(RPC *r, RPC_ENUM_DEVICE *t);
UINT EcEnumAllDevice(RPC *r, RPC_ENUM_DEVICE *t);
UINT EcSetPassword(RPC *r, RPC_SET_PASSWORD *t);
UINT EcDelLicenseKey(RPC *r, RPC_TEST *t);
UINT EcEnumLicenseKey(RPC *r, RPC_ENUM_LICENSE_KEY *t);
UINT EcGetLicenseStatus(RPC *r, RPC_EL_LICENSE_STATUS *t);
UINT EcGetBridgeSupport(RPC *r, RPC_BRIDGE_SUPPORT *t);
UINT EcRebootServer(RPC *r, RPC_TEST *t);

UINT EcConnect(char *host, UINT port, char *password, RPC **rpc);
void EcDisconnect(RPC *rpc);

void InRpcAddDevice(RPC_ADD_DEVICE *t, PACK *p);
void OutRpcAddDevice(PACK *p, RPC_ADD_DEVICE *t);
void InRpcDeleteDevice(RPC_DELETE_DEVICE *t, PACK *p);
void OutRpcDeleteDevice(PACK *p, RPC_DELETE_DEVICE *t);
void InRpcEnumDevice(RPC_ENUM_DEVICE *t, PACK *p);
void OutRpcEnumDevice(PACK *p, RPC_ENUM_DEVICE *t);
void FreeRpcEnumDevice(RPC_ENUM_DEVICE *t);
void InRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t, PACK *p);
void OutRpcEnumLicenseKey(PACK *p, RPC_ENUM_LICENSE_KEY *t);
void FreeRpcEnumLicenseKey(RPC_ENUM_LICENSE_KEY *t);
void InRpcElLicenseStatus(RPC_EL_LICENSE_STATUS *t, PACK *p);
void OutRpcElLicenseStatus(PACK *p, RPC_EL_LICENSE_STATUS *t);

#endif	// ETHERLOG_H


