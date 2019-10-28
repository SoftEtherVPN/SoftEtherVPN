// SoftEther VPN Source Code - Developer Edition Master Branch
// Windows Filtering Platform Callout Driver for Capturing IPsec Packets on Windows Vista / 7 / Server 2008


// WfpInner.h
// Header File for WFP Callout Driver

#ifndef	WFPINNER_H
#define	WFPINNER_H

// Win32 DDK related
#ifndef	CPU_64
#define	_X86_
#define	i386
#else	// CPU_64
#define	_AMD64_
#define	AMD64
#define	x64
#endif	// CPU_64

#define	STD_CALL
#define	CONDITION_HANDLING			1
#define	NT_UP						1
#define	NT_INST						0
#define	_NT1X_						100
#define	_WIN32_WINNT				0x0600
#define	WINNT						1
#define	WINVER						0x0600
#define	_WIN32_IE					0x0700
#define	WIN32_LEAN_AND_MEAN			1
#define	DEVL						1
#define	__BUILDMACHINE__			WinDDK
#define	FPO							0
#define	BINARY_COMPATIBLE			0
#define	NT
#define	NDIS60						1
#define	NDIS_SUPPORT_NDIS6			1
#define	NTDDI_VERSION				0x06000100

#define	KMDF_MAJOR_VERSION_STRING	01
#define	KMDF_MINOR_VERSION_STRING	009

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ndis.h>
#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>
#include <stdio.h>
#include <string.h>
#define INITGUID
#include <guiddef.h>

#define	TRUE				1
#define	FALSE				0
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

// Error checking macro
#define	OK(val)		(val == STATUS_SUCCESS)
#define	NG(val)		(!OK(val))
#define	CRUSH_WHERE	//Crush(0xaaaaaaaa, __LINE__, __LINE__, __LINE__)

// Constants
#define	MEMPOOL_TAG				'wpfx'
#define	WFP_MAX_LOCAL_IP_COUNT	4096

// Tag constant
#define	WFP_ESP_PACKET_TAG_1		0x19841117
#define	WFP_ESP_PACKET_TAG_2		0x1accafe1

// ESP protocol number
#define	WFP_ESP_RAW_PROTOCOL_ID		50
#define	WFP_ESP_RAW_PROTOCOL_ID_DST	52

// Event
typedef struct EVENT
{
	KEVENT *EventObj;
	HANDLE Handle;
} EVENT;

// Spin lock
typedef struct SPINLOCK
{
	KSPIN_LOCK SpinLock;
	KIRQL OldIrql;
} SPINLOCK;

// Instance data
typedef struct WFP_CTX
{
	DEVICE_OBJECT *DeviceObject;
	UNICODE_STRING DeviceName;
	UNICODE_STRING DeviceNameWin32;
	EVENT *Event;
	HANDLE hEngine;
	bool Halting;
	UINT CalloutIdIPv4;
	UINT CalloutIdIPv6;
	UINT CalloutObjIdIPv4;
	UINT CalloutObjIdIPv6;
	SPINLOCK *LocalIPListLock;
	UCHAR *LocalIPListData;
	UINT LocalIPListSize;
	HANDLE hInjectionIPv4, hInjectionIPv6;
	NDIS_HANDLE hNdis;
} WFP_CTX;

#pragma pack(push, 1)

#define	WFP_IP_PROTO_UDP		0x11	// UDP protocol

// IPv4 header
typedef struct WFP_IPV4_HEADER
{
	UCHAR	VersionAndHeaderLength;		// Version and header size
	UCHAR	TypeOfService;				// Service Type
	USHORT	TotalLength;				// Total size
	USHORT	Identification;				// Identifier
	UCHAR	FlagsAndFragmentOffset[2];	// The flag and fragment offset
	UCHAR	TimeToLive;					// TTL
	UCHAR	Protocol;					// Protocol
	USHORT	Checksum;					// Checksum
	UINT	SrcIP;						// Source IP address
	UINT	DstIP;						// Destination IP address
} WFP_IPV4_HEADER;

// IPv6 header
typedef struct WFP_IPV6_HEADER
{
	UCHAR VersionAndTrafficClass1;		// Version Number (4 bit) and Traffic Class 1 (4 bit)
	UCHAR TrafficClass2AndFlowLabel1;	// Traffic Class 2 (4 bit) and Flow Label 1 (4 bit)
	UCHAR FlowLabel2;					// Flow Label 2 (8 bit)
	UCHAR FlowLabel3;					// Flow Label 3 (8 bit)
	USHORT PayloadLength;				// Length of the payload (including extension header)
	UCHAR NextHeader;					// The next header
	UCHAR HopLimit;						// Hop limit
	UCHAR SrcAddress[16];				// Source address
	UCHAR DestAddress[16];				// Destination address
} WFP_IPV6_HEADER;

// UDP header
typedef struct WFP_UDP_HEADER
{
	USHORT	SrcPort;					// Source port number
	USHORT	DstPort;					// Destination port number
	USHORT	PacketLength;				// Data length
	USHORT	Checksum;					// Checksum
} WFP_UDP_HEADER;

// Context of injected packet
typedef struct WFP_INJECTED_PACKET_CONTEXT
{
	NET_BUFFER OriginalNetBufferData;	// Data of the original NET_BUFFER
	NET_BUFFER *CurrentNetBuffer;		// Pointer of the current NET_BUFFER
	NET_BUFFER_LIST *AllocatedNetBufferList;	// Newly allocated NET_BUFFER_LIST
	MDL *AllocatedMdl;					// MDL that newly allocated
	void *AllocatedMemory;				// Newly allocated memory
} WFP_INJECTED_PACKET_CONTEXT;


#pragma pack(pop)


// Function prototype
NTSTATUS DriverEntry(DRIVER_OBJECT *driver_object, UNICODE_STRING *registry_path);
void DriverUnload(DRIVER_OBJECT *driver_object);
NTSTATUS DriverDispatch(DEVICE_OBJECT *device_object, IRP *irp);

void NTAPI CalloutClassify(const FWPS_INCOMING_VALUES0* inFixedValues,
						   const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
						   void* layerData,
						   const FWPS_FILTER0* filter,
						   UINT64 flowContext,
						   FWPS_CLASSIFY_OUT0* classifyOut);
NTSTATUS NTAPI CalloutNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType,
							 const GUID* filterKey, FWPS_FILTER0* filter);
bool IsIPAddressInList(struct WFP_LOCAL_IP *ip);
bool IsIPv4AddressInList(void *addr);
bool IsIPv6AddressInList(void *addr);
void FreeInjectionCtx(WFP_INJECTED_PACKET_CONTEXT *ctx);
UCHAR *ModificationOfIPsecESPPacket(UCHAR *ip_packet, UINT ip_packet_size, UINT ip_header_size, UINT *dst_size_ptr, bool isv6);
USHORT IpChecksum(void *buf, UINT size);
bool InjectPacket(HANDLE hInjection, NET_BUFFER_LIST *nbl, UCHAR *dst_data, UINT dst_size, const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues);

void *Malloc(UINT size);
void *ZeroMalloc(UINT size);
void Free(void *p);
void *ReAlloc(void *p, UINT size);
void Copy(void *dst, void *src, UINT size);
UINT GetMemSize(void *p);
void Zero(void *p, UINT size);
UINT Cmp(void *p1, void *p2, UINT size);
SPINLOCK *NewSpinLock();
void SpinLock(SPINLOCK *s);
void SpinUnlock(SPINLOCK *s);
void FreeSpinLock(SPINLOCK *s);
EVENT *NewEvent(wchar_t *name);
void FreeEvent(EVENT *e);
void SetEvent(EVENT *e);
void ResetEvent(EVENT *e);
void Sleep(int milliSeconds);
USHORT Swap16(USHORT value);
UINT Swap32(UINT value);
UINT64 Swap64(UINT64 value);
USHORT Endian16(USHORT src);
UINT Endian32(UINT src);
UINT64 Endian64(UINT64 src);

void Crush();


#endif	// WFPINNER_H

