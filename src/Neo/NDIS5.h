// SoftEther VPN Source Code - Developer Edition Master Branch
// Kernel Device Driver


// NDIS5.h
// Header of NDIS5.c

#ifndef	NDIS5_H
#define	NDIS5_H

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
#ifndef	WIN9X
// Windows 2000 or later: NDIS 5.0
#define	NDIS50_MINIPORT
#define NEO_NDIS_MAJOR_VERSION		5
#define NEO_NDIS_MINOR_VERSION		0
#else	// WIN9X
// Windows 9x: NDIS 4.0
#define	NDIS40_MINIPORT
#define NEO_NDIS_MAJOR_VERSION		4
#define NEO_NDIS_MINOR_VERSION		0
#define	BINARY_COMPATIBLE 			1
#endif	// WIN9X
#define	NDIS_WDM					1

#ifndef	WIN9X
#include <wdm.h>
#include <ndis.h>
#include <stdio.h>
#include <string.h>
#else	// WIN9X
#include <basedef.h>
#define	_LARGE_INTEGER	DUMMY__LARGE_INTEGER
#define	LARGE_INTEGER	DUMMY_LARGE_INTEGER
#define	PLARGE_INTEGER	DUMMY_PLARGE_INTEGER
#define	_ULARGE_INTEGER	DUMMY__ULARGE_INTEGER
#define	ULARGE_INTEGER	DUMMY_ULARGE_INTEGER
#define	PULARGE_INTEGER	DUMMY_PULARGE_INTEGER
#define	PSZ				DUMMY_PSZ
#include <ndis.h>
#include <vmm.h>
#include <vwin32.h>
#include <stdio.h>
#include <string.h>
#undef	_LARGE_INTEGER
#undef	LARGE_INTEGER
#undef	PLARGE_INTEGER
#undef	_ULARGE_INTEGER
#undef	ULARGE_INTEGER
#undef	PULARGE_INTEGER
#undef	PSZ
#endif	// WIN9X

// Error checking macro
#define	OK(val)		(val == STATUS_SUCCESS)
#define	NG(val)		(!OK(val))

// Constant
static UINT SupportedOids[] =
{
	OID_GEN_SUPPORTED_LIST,
	OID_GEN_HARDWARE_STATUS,
	OID_GEN_MEDIA_SUPPORTED,
	OID_GEN_MEDIA_IN_USE,
	OID_GEN_MAXIMUM_FRAME_SIZE,
	OID_GEN_MAXIMUM_TOTAL_SIZE,
	OID_GEN_MAC_OPTIONS,
	OID_GEN_MAXIMUM_LOOKAHEAD,
	OID_GEN_CURRENT_LOOKAHEAD,
	OID_GEN_LINK_SPEED,
	OID_GEN_MEDIA_CONNECT_STATUS,
	OID_GEN_TRANSMIT_BUFFER_SPACE,
	OID_GEN_RECEIVE_BUFFER_SPACE,
	OID_GEN_TRANSMIT_BLOCK_SIZE,
	OID_GEN_RECEIVE_BLOCK_SIZE,
	OID_GEN_VENDOR_DESCRIPTION,
	OID_GEN_VENDOR_ID,
	OID_GEN_DRIVER_VERSION,
	OID_GEN_VENDOR_DRIVER_VERSION,
	OID_GEN_XMIT_OK,
	OID_GEN_RCV_OK,
	OID_GEN_XMIT_ERROR,
	OID_GEN_RCV_ERROR,
	OID_GEN_RCV_NO_BUFFER,
	OID_GEN_CURRENT_PACKET_FILTER,
	OID_802_3_PERMANENT_ADDRESS,
	OID_802_3_CURRENT_ADDRESS,
	OID_802_3_MAXIMUM_LIST_SIZE,
	OID_802_3_RCV_ERROR_ALIGNMENT,
	OID_802_3_XMIT_ONE_COLLISION,
	OID_802_3_XMIT_MORE_COLLISIONS,
	OID_802_3_MULTICAST_LIST,
	//OID_GEN_PROTOCOL_OPTIONS,
	OID_GEN_MAXIMUM_SEND_PACKETS
	};
#define	NEO_MEDIA					NdisMedium802_3
#define	MAX_MULTICAST				32

#define	MAX_PATH					260
#define	MAX_SIZE					512
#define	STD_SIZE					512


// Macro
#define _NdisInitializeString(Destination,Source) \
{\
    PNDIS_STRING _D = (Destination);\
    UCHAR *_S = (Source);\
    WCHAR *_P;\
    _D->Length = (USHORT)((strlen(_S)) * sizeof(WCHAR));\
    _D->MaximumLength = _D->Length + sizeof(WCHAR);\
    NdisAllocateMemoryWithTag((PVOID *)&(_D->Buffer), _D->MaximumLength, 'SETH');\
    _P = _D->Buffer;\
    while(*_S != '\0'){\
        *_P = (WCHAR)(*_S);\
        _S++;\
        _P++;\
    }\
    *_P = UNICODE_NULL;\
}


// Unicode string
typedef struct _UNICODE
{
	UNICODE_STRING String;
} UNICODE;

typedef struct _PACKET_BUFFER PACKET_BUFFER;

// Function prototype
UNICODE *NewUnicode(char *str);
void FreeUnicode(UNICODE *u);
NDIS_STRING *GetUnicode(UNICODE *u);
PACKET_BUFFER *NeoNewPacketBuffer();
void NeoFreePacketBuffer(PACKET_BUFFER *p);
void NeoInitPacketArray();
void NeoFreePacketArray();
NDIS_STATUS DriverEntry(DRIVER_OBJECT *DriverObject, UNICODE_STRING *RegistryPath);
NDIS_STATUS NeoNdisInit(NDIS_STATUS *OpenErrorStatus,
					UINT *SelectedMediumIndex,
					NDIS_MEDIUM *MediumArray,
					UINT MediumArraySize,
					NDIS_HANDLE MiniportAdapterHandle,
					NDIS_HANDLE WrapperConfigurationContext);
NDIS_STATUS NeoNdisHalt(NDIS_HANDLE MiniportAdapterContext);
NDIS_STATUS NeoNdisReset(BOOLEAN *AddressingReset, NDIS_HANDLE MiniportAdapterContext);
NDIS_STATUS NeoNdisQuery(NDIS_HANDLE MiniportAdapterContext,
					NDIS_OID Oid,
					void *InformationBuffer,
					ULONG InformationBufferLength,
					ULONG *BytesWritten,
					ULONG *BytesNeeded);
NDIS_STATUS NeoNdisSet(
					NDIS_HANDLE MiniportAdapterContext,
					NDIS_OID Oid,
					void *InformationBuffer,
					ULONG InformationBufferLength,
					ULONG *BytesRead,
					ULONG *BytesNeeded);
void NeoNdisSendPackets(NDIS_HANDLE MiniportAdapterContext,
						NDIS_PACKET **PacketArray,
						UINT NumberOfPackets);
NDIS_STATUS NeoNdisSend(NDIS_HANDLE MiniportAdapterContext,
						NDIS_PACKET *Packet, UINT Flags);
BOOL NeoNdisSendPacketsHaltCheck(NDIS_PACKET **PacketArray, UINT NumberOfPackets);
BOOL NeoLoadRegistry();
void NeoInitControlDevice();
void NeoFreeControlDevice();
NTSTATUS NeoNdisDispatch(DEVICE_OBJECT *DeviceObject, IRP *Irp);
void NeoCheckConnectState();
void NeoSetConnectState(BOOL connected);
BOOL NeoNdisOnOpen(IRP *irp, IO_STACK_LOCATION *stack);
BOOL NeoNdisOnClose(IRP *irp, IO_STACK_LOCATION *stack);

#endif	// NDIS5_H

