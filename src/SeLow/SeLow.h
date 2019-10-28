// SoftEther VPN Source Code - Developer Edition Master Branch
// SeLow - SoftEther Lightweight Network Protocol


// SeLow.h
// Header of SeLow.c

#ifndef	SELOW_H
#define	SELOW_H

// Win32 DDK related
#ifndef	CPU_64
#define	_X86_
#else	// CPU_64
#ifndef	NEO_IA64
#define	_AMD64_
#define	AMD64
#else	// NEO_IA64
#define	_IA64_
#define	IA64
#endif	// NEO_IA64
#endif	// CPU_64
#define	NDIS_MINIPORT_DRIVER
// NDIS 6.2
#define	NDIS620_MINIPORT
#define	NDIS_SUPPORT_NDIS61			1
#define	NDIS_SUPPORT_NDIS620		1
#define NEO_NDIS_MAJOR_VERSION		6
#define NEO_NDIS_MINOR_VERSION		20
#define	NDIS_WDM					1

#include <wdm.h>
#include <wdmsec.h>
#include <ndis.h>
#include <stdio.h>
#include <string.h>

// OS determination
#ifdef	WIN32
#define	OS_WIN32	// Microsoft Windows
#else
#define	OS_UNIX		// UNIX / Linux
#endif


// Type declaration
#ifndef	WINDOWS_H_INCLUDED
#ifndef	WIN9X
typedef	unsigned long		BOOL;
#endif	// WIN9X
#define	TRUE				1
#define	FALSE				0
#endif
typedef	unsigned long		bool;
#define	true				1
#define	false				0
typedef	unsigned long long	UINT64;
typedef	signed long long	INT64;
typedef	unsigned short		WORD;
typedef	unsigned short		USHORT;
typedef	signed short		SHORT;
typedef	unsigned char		BYTE;
typedef	unsigned char		UCHAR;
typedef signed char			CHAR;
typedef	unsigned long		DWORD;
#define	INFINITE			0xFFFFFFFF

#define	LESS(a, max_value)	((a) < (max_value) ? (a) : (max_value))
#define	MORE(a, min_value)	((a) > (min_value) ? (a) : (min_value))
#define	INNER(a, b, c)		(((b) <= (c) && (a) >= (b) && (a) <= (c)) || ((b) >= (c) && (a) >= (c) && (a) <= (b)))
#define	OUTER(a, b, c)		(!INNER((a), (b), (c)))
#define	MAKESURE(a, b, c)		(((b) <= (c)) ? (MORE(LESS((a), (c)), (b))) : (MORE(LESS((a), (b)), (c))))
#define	MIN(a, b)			((a) >= (b) ? (b) : (a))
#define	MAX(a, b)			((a) >= (b) ? (a) : (b))
#define	EQUAL_BOOL(a, b)	(((a) && (b)) || ((!(a)) && (!(b))))

// Error checking macro
#define	OK(val)		((val) == STATUS_SUCCESS)
#define	NG(val)		(!OK(val))

#define	MAX_PATH					260
#define	MAX_SIZE					512
#define	STD_SIZE					512

#define	SL_WHERE	SlCrash(__LINE__, __LINE__, __LINE__, __LINE__)
#define	SL_CRUSH(x)	SlCrash(__LINE__, (UINT)(x), (UINT)(x), (UINT)(x))

// Common header
#include "SeLowCommon.h"


//// Utility data structure

// Lock
typedef struct SL_LOCK
{
	NDIS_SPIN_LOCK spin_lock;
} SL_LOCK;

// Event
typedef struct SL_EVENT
{
	KEVENT *event;
	HANDLE event_handle;
} SL_EVENT;

// Unicode string
typedef struct SL_UNICODE
{
	UNICODE_STRING String;
} SL_UNICODE;

// NDIS packet buffer
typedef struct SL_PACKET_BUFFER
{
	NDIS_HANDLE NetBufferListPool;		// NET_BUFFER_LIST Pool
	NET_BUFFER_LIST *NetBufferList;		// NET_BUFFER_LIST
} SL_PACKET_BUFFER;

// List
typedef struct SL_LIST
{
	UINT num_item, num_reserved;
	void **p;
	SL_LOCK *lock;
} SL_LIST;

#define	SL_LIST_DATA(o, i)		(((o) != NULL) ? ((o)->p[(i)]) : NULL)
#define	SL_LIST_NUM(o)			(((o) != NULL) ? (o)->num_item : 0)
#define	SL_INIT_NUM_RESERVED	32

//// SL data structure

// Packet queue
typedef struct SL_PACKET
{
	UCHAR Data[SL_MAX_PACKET_SIZE];		// Data
	UINT Size;							// Size

	struct SL_PACKET *Next;				// Next packet
} SL_PACKET;

// File context
typedef struct SL_FILE
{
	struct SL_DEVICE *Device;			// Device
	struct SL_ADAPTER *Adapter;			// Adapter
	FILE_OBJECT *FileObject;			// File object
	SL_EVENT *Event;					// Event
	char EventNameWin32[SL_EVENT_NAME_SIZE];	// Win32 event name

	SL_LOCK *RecvLock;					// Receive lock
	SL_PACKET *RecvPacketHead;			// Head of the received packet
	SL_PACKET *RecvPacketTail;			// Tail of the received packet
	UINT NumRecvPackets;				// Number of items of the received packet queue
	NDIS_HANDLE NetBufferListPool;		// NET_BUFFER_LIST Pool
	volatile UINT NumSendingPackets;	// Number of packets being transmitted
	bool SetEventFlag;					// Flag to set an event
	bool FinalWakeUp;
} SL_FILE;

// Device context
typedef struct SL_DEVICE
{
	DEVICE_OBJECT *DeviceObject;		// Device object
	SL_UNICODE *DeviceName;				// Device name
	SL_UNICODE *SymbolicLinkName;		// Symbolic link name
	volatile bool Halting;				// Halting

	bool IsBasicDevice;					// Whether basic device
	struct SL_ADAPTER *Adapter;			// Adapter

	SL_LIST *FileList;					// File List
	SL_LOCK *OpenCloseLock;				// Open / Close lock of the device
} SL_DEVICE;

// Adapter context
typedef struct SL_ADAPTER
{
	volatile bool Halt;					// Halt flag
	volatile bool Ready;				// Ready flag
	SL_UNICODE *AdapterName;			// Adapter name
	NDIS_BIND_PARAMETERS BindParamCopy;	// Copy of the bind parameters
	UCHAR MacAddress[6];				// MAC address
	UINT MtuSize;						// MTU size
	wchar_t AdapterId[SL_ADAPTER_ID_LEN];	// Adapter ID
	volatile bool IsOpenPending;		// Whether Open is Pending
	volatile bool IsClosePending;		// Whether Close is Pending
	NDIS_HANDLE BindingContext;			// Binding context
	NDIS_HANDLE AdapterHandle;			// Handle of the adapter
	NDIS_HANDLE AdapterHandle2;			// Handle of the adapter (receive-only)
	NDIS_HANDLE UnbindContext;			// Unbind context
	SL_LOCK *Lock;						// Lock object
	volatile UINT NumPendingOidRequests;	// Number of running OID requests
	volatile UINT NumPendingSendPackets;	// Number of packets being transmitted
	UCHAR TmpBuffer[SL_MAX_PACKET_SIZE];	// Temporally buffer size
	char FriendlyName[256];				// Adapter name
	bool SupportVLan;					// Supporting VLAN by hardware

	SL_DEVICE *Device;					// Handle of the device
} SL_ADAPTER;

// SL context
typedef struct SL_CTX
{
	DRIVER_OBJECT *DriverObject;		// Driver object
	NDIS_HANDLE ProtocolHandle;			// NDIS protocol handle
	SL_DEVICE *BasicDevice;				// Basic device
	SL_LIST *AdapterList;				// Adapter list

	volatile UINT IntCounter1;
	UINT DummyInt;
	volatile bool IsEnumCompleted;		// Enumeration completion flag
	volatile UINT NumBoundAdapters;
} SL_CTX;


//// SL function
NDIS_STATUS DriverEntry(DRIVER_OBJECT *driver_object, UNICODE_STRING *registry_path);

NTSTATUS SlDeviceOpenProc(DEVICE_OBJECT *device_object, IRP *irp);
NTSTATUS SlDeviceCloseProc(DEVICE_OBJECT *device_object, IRP *irp);
NTSTATUS SlDeviceReadProc(DEVICE_OBJECT *device_object, IRP *irp);
NTSTATUS SlDeviceWriteProc(DEVICE_OBJECT *device_object, IRP *irp);
NTSTATUS SlDeviceIoControlProc(DEVICE_OBJECT *device_object, IRP *irp);

void SlUnloadProc(DRIVER_OBJECT *driver_object);

NDIS_STATUS SlNdisBindAdapterExProc(NDIS_HANDLE protocol_driver_context, NDIS_HANDLE bind_context, NDIS_BIND_PARAMETERS *bind_parameters);
NDIS_STATUS SlNdisUnbindAdapterExProc(NDIS_HANDLE unbind_context, NDIS_HANDLE protocol_binding_context);
void SlNdisOpenAdapterCompleteExProc(NDIS_HANDLE protocol_binding_context, NDIS_STATUS status);
void SlNdisCloseAdapterCompleteExProc(NDIS_HANDLE protocol_binding_context);
NDIS_STATUS SlNdisNetPnPEventProc(NDIS_HANDLE protocol_binding_context, NET_PNP_EVENT_NOTIFICATION *net_pnp_event);
void SlNdisUninstallProc(void);
void SlNdisOidRequestCompleteProc(NDIS_HANDLE protocol_binding_context, NDIS_OID_REQUEST *oid_request, NDIS_STATUS status);
void SlNdisStatusExProc(NDIS_HANDLE protocol_binding_context, NDIS_STATUS_INDICATION *status_indication);
void SlNdisReceiveNetBufferListsProc(NDIS_HANDLE protocol_binding_context, NET_BUFFER_LIST *net_buffer_lists, NDIS_PORT_NUMBER port_number, ULONG NumberOfNetBufferLists, ULONG receive_flags);
void SlNdisSendNetBufferListsCompleteProc(NDIS_HANDLE protocol_binding_context, NET_BUFFER_LIST *net_buffer_lists, ULONG send_complete_flags);

SL_DEVICE *SlNewDevice(char *device_name, char *symbolic_link_name);
SL_DEVICE *SlNewDeviceUnicode(SL_UNICODE *u_device_name, SL_UNICODE *u_sym_name);
void SlFreeDevice(SL_DEVICE *dev);
void SlFreeAdapter(SL_ADAPTER *a);

void SlSendOidRequest(SL_ADAPTER *a, bool set, NDIS_OID oid, void *data, UINT size);

//// Utility function
void *SlMalloc(UINT size);
void *SlZeroMalloc(UINT size);
void SlFree(void *p);
void SlCopy(void *dst, void *src, UINT size);
void SlZero(void *dst, UINT size);
SL_LOCK *SlNewLock();
void SlLock(SL_LOCK *lock);
void SlUnlock(SL_LOCK *lock);
void SlFreeLock(SL_LOCK *lock);
SL_EVENT *SlNewEvent(char *name);
void SlFreeEvent(SL_EVENT *event);
void SlSet(SL_EVENT *event);
void SlReset(SL_EVENT *event);
SL_UNICODE *SlNewUnicode(char *str);
SL_UNICODE *SlNewUnicodeFromUnicodeString(UNICODE_STRING *src);
void SlFreeUnicode(SL_UNICODE *u);
NDIS_STRING *SlGetUnicode(SL_UNICODE *u);
void SlCrash(UINT a, UINT b, UINT c, UINT d);
SL_LIST *SlNewList();
void SlAdd(SL_LIST *o, void *p);
bool SlDelete(SL_LIST *o, void *p);
void SlDeleteAll(SL_LIST *o);
void SlLockList(SL_LIST *o);
void SlUnlockList(SL_LIST *o);
void SlFreeList(SL_LIST *o);
void *SlClone(void *p, UINT size);
void SlSleep(int milliSeconds);




#endif	// SELOW_H

