// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Secure.h
// Header of Secure.c

#ifndef	SECURE_H
#define	SECURE_H

#include "MayaType.h"

// Constant
#define	MAX_SEC_DATA_SIZE		4096

// Secure device
struct SECURE_DEVICE
{
	UINT Id;								// Device ID
	UINT Type;								// Type
	char *DeviceName;						// Device name
	char *Manufacturer;						// Manufacturer
	char *ModuleName;						// Module name
};

// Type of secure device
#define	SECURE_IC_CARD				0		// IC card
#define	SECURE_USB_TOKEN			1		// USB token

// Secure device information
struct SEC_INFO
{
	wchar_t *Label;							// Label
	wchar_t *ManufacturerId;					// Vendor ID
	wchar_t *Model;							// Model
	wchar_t *SerialNumber;						// Serial number
	UINT MaxSession;						// Maximum number of sessions
	UINT MaxRWSession;						// Maximum Number of R/W sessions
	UINT MinPinLen;							// Minimum length of the PIN string
	UINT MaxPinLen;							// Maximum length of the PIN string
	UINT TotalPublicMemory;					// Total memory capacity (Public)
	UINT FreePublicMemory;					// Free memory capacity (Public)
	UINT TotalPrivateMemory;				// Total memory capacity (Private)
	UINT FreePrivateMemory;					// Free memory capacity (Private)
	char *HardwareVersion;					// Hardware version
	char *FirmwareVersion;					// Firmware version
};

// Secure device structure
struct SECURE
{
	LOCK *lock;								// Lock
	SECURE_DEVICE *Dev;						// Device Information
	UINT Error;								// The error that last occurred
	struct CK_FUNCTION_LIST *Api;			// API
	bool Initialized;						// Initialization flag
	UINT NumSlot;							// The number of slots
	UINT *SlotIdList;						// Slot ID list
	bool SessionCreated;					// Session creation flags
	UINT SessionId;							// Session ID
	UINT SessionSlotNumber;					// Slot ID of the session
	bool LoginFlag;							// Logged-in flag
	SEC_INFO *Info;							// Token information
	LIST *EnumCache;						// Enumeration cache

	// Attribute value for the different behavior for each driver
	bool IsEPass1000;						// ePass 1000
	bool IsReadOnly;						// Read-only mode

#ifdef	OS_WIN32
	struct SEC_DATA_WIN32 *Data;			// Data
#endif	// OS_WIN32
};

// Secure device object structure
struct SEC_OBJ
{
	UINT Type;								// Type of object
	UINT Object;							// Object handle
	bool Private;							// Private flag
	char *Name;								// Name
};

#define	SEC_ERROR_NOERROR				0	// No Error
#define	SEC_ERROR_INVALID_SLOT_NUMBER	1	// Slot number is invalid
#define	SEC_ERROR_OPEN_SESSION			2	// Session creation failure
#define	SEC_ERROR_SESSION_EXISTS		3	// The session already exists
#define	SEC_ERROR_NO_PIN_STR			4	// PIN string is not specified
#define	SEC_ERROR_ALREADY_LOGIN			5	// Already logged in
#define	SEC_ERROR_BAD_PIN_CODE			6	// PIN code is invalid
#define	SEC_ERROR_NO_SESSION			7	// There is no session
#define	SEC_ERROR_DATA_TOO_BIG			8	// Data is too large
#define	SEC_ERROR_NOT_LOGIN				9	// Not logged in
#define	SEC_ERROR_BAD_PARAMETER			10	// Invalid Parameters
#define	SEC_ERROR_HARDWARE_ERROR		11	// Hardware error
#define	SEC_ERROR_OBJ_NOT_FOUND			12	// Object is not found
#define	SEC_ERROR_INVALID_CERT			13	// The certificate is invalid


#define	SEC_DATA						0	// Data
#define	SEC_X							1	// Certificate
#define	SEC_K							2	// Secret key
#define	SEC_P							3	// Public key



// Function prototype
void InitSecure();
void FreeSecure();
void InitSecureDeviceList();
void FreeSecureDeviceList();
bool IsDeviceSupported(SECURE_DEVICE *dev);
LIST *GetSupportedDeviceList();
LIST *GetSecureDeviceList();
bool CheckSecureDeviceId(UINT id);
SECURE_DEVICE *GetSecureDevice(UINT id);
SECURE *OpenSec(UINT id);
void CloseSec(SECURE *sec);
bool OpenSecSession(SECURE *sec, UINT slot_number);
void CloseSecSession(SECURE *sec);
bool LoginSec(SECURE *sec, char *pin);
void LogoutSec(SECURE *sec);
void PrintSecInfo(SECURE *sec);
LIST *EnumSecObject(SECURE *sec);
void FreeSecObject(SEC_OBJ *obj);
void FreeEnumSecObject(LIST *o);
SEC_OBJ *FindSecObject(SECURE *sec, char *name, UINT type);
bool CheckSecObject(SECURE *sec, char *name, UINT type);
bool DeleteSecObjectByName(SECURE *sec, char *name, UINT type);
SEC_OBJ *CloneSecObject(SEC_OBJ *obj);
LIST *CloneEnumSecObject(LIST *o);
void EraseEnumSecObjectCache(SECURE *sec);
void DeleteSecObjFromEnumCache(SECURE *sec, char *name, UINT type);
bool WriteSecData(SECURE *sec, bool private_obj, char *name, void *data, UINT size);
int ReadSecDataFromObject(SECURE *sec, SEC_OBJ *obj, void *data, UINT size);
int ReadSecData(SECURE *sec, char *name, void *data, UINT size);
bool DeleteSecObject(SECURE *sec, SEC_OBJ *obj);
bool DeleteSecData(SECURE *sec, char *name);
void UINT64ToCkDate(void *p_ck_date, UINT64 time64);
bool WriteSecCert(SECURE *sec, bool private_obj, char *name, X *x);
bool DeleteSecCert(SECURE *sec, char *name);
X *ReadSecCertFromObject(SECURE *sec, SEC_OBJ *obj);
X *ReadSecCert(SECURE *sec, char *name);
bool WriteSecKey(SECURE *sec, bool private_obj, char *name, K *k);
bool DeleteSecKey(SECURE *sec, char *name);
bool SignSecByObject(SECURE *sec, SEC_OBJ *obj, void *dst, void *src, UINT size);
bool SignSec(SECURE *sec, char *name, void *dst, void *src, UINT size);
bool ChangePin(SECURE *sec, char *old_pin, char *new_pin);
void TestSec();
void TestSecMain(SECURE *sec);
bool IsJPKI(bool id);

bool LoadSecModule(SECURE *sec);
void FreeSecModule(SECURE *sec);
void GetSecInfo(SECURE *sec);
void FreeSecInfo(SECURE *sec);
SEC_INFO *TokenInfoToSecInfo(void *p_t);
void FreeSecInfoMemory(SEC_INFO *s);

#ifdef	OS_WIN32

bool Win32IsDeviceSupported(SECURE_DEVICE *dev);
bool Win32LoadSecModule(SECURE *sec);
void Win32FreeSecModule(SECURE *sec);

#endif	// OS_WIN32

#endif	// SECURE_H
