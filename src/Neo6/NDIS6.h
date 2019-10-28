// SoftEther VPN Source Code - Developer Edition Master Branch
// Kernel Device Driver


// NDIS6.h
// Header of NDIS6.c

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
// NDIS 6.2
#define	NDIS620_MINIPORT
#define	NDIS_SUPPORT_NDIS61			1
#define	NDIS_SUPPORT_NDIS620		1
#define NEO_NDIS_MAJOR_VERSION		6
#define NEO_NDIS_MINOR_VERSION		20
#define	NDIS_WDM					1

#include <wdm.h>
#include <ndis.h>
#include <stdio.h>
#include <string.h>

// Error checking macro
#define	OK(val)		((val) == STATUS_SUCCESS)
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
	OID_GEN_MAXIMUM_SEND_PACKETS,
	OID_GEN_STATISTICS,
	OID_GEN_INTERRUPT_MODERATION,
	OID_GEN_LINK_PARAMETERS,
	OID_PNP_SET_POWER,
	OID_PNP_QUERY_POWER,
	};
#define	NEO_MEDIA					NdisMedium802_3
#define	MAX_MULTICAST				32

#define	MAX_PATH					260
#define	MAX_SIZE					512
#define	STD_SIZE					512



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
NDIS_STATUS NeoNdisInitEx(NDIS_HANDLE MiniportAdapterHandle,
						  NDIS_HANDLE MiniportDriverContext,
						  PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters);
void NeoNdisHaltEx(NDIS_HANDLE MiniportAdapterContext, NDIS_HALT_ACTION HaltAction);
VOID NeoNdisDriverUnload(PDRIVER_OBJECT DriverObject);
NDIS_STATUS NeoNdisResetEx(NDIS_HANDLE MiniportAdapterContext, PBOOLEAN AddressingReset);
BOOLEAN NeoNdisCheckForHangEx(NDIS_HANDLE MiniportAdapterContext);
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
NDIS_STATUS NeoNdisOidRequest(NDIS_HANDLE MiniportAdapterContext,
							  PNDIS_OID_REQUEST OidRequest);
void NeoNdisSendNetBufferLists(NDIS_HANDLE MiniportAdapterContext,
							   NET_BUFFER_LIST *NetBufferLists,
							   NDIS_PORT_NUMBER PortNumber,
							   ULONG SendFlags);
void NeoNdisSetNetBufferListsStatus(NET_BUFFER_LIST *nbl, UINT status);
BOOL NeoLoadRegistry();
void NeoInitControlDevice();
void NeoFreeControlDevice();
NTSTATUS NeoNdisDispatch(DEVICE_OBJECT *DeviceObject, IRP *Irp);
void NeoCheckConnectState();
void NeoSetConnectState(BOOL connected);
BOOL NeoNdisOnOpen(IRP *irp, IO_STACK_LOCATION *stack);
BOOL NeoNdisOnClose(IRP *irp, IO_STACK_LOCATION *stack);
void NeoNdisCrash();
void NeoNdisCrash2();

NDIS_STATUS NeoNdisSetOptions(NDIS_HANDLE NdisDriverHandle, NDIS_HANDLE DriverContext);
NDIS_STATUS NeoNdisPause(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters);
NDIS_STATUS NeoNdisRestart(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_RESTART_PARAMETERS MiniportRestartParameters);
void NeoNdisReturnNetBufferLists(NDIS_HANDLE MiniportAdapterContext, PNET_BUFFER_LIST NetBufferLists, ULONG ReturnFlags);
void NeoNdisCancelSend(NDIS_HANDLE MiniportAdapterContext, PVOID CancelId);
void NeoNdisDevicePnPEventNotify(NDIS_HANDLE MiniportAdapterContext, PNET_DEVICE_PNP_EVENT NetDevicePnPEvent);
void NeoNdisShutdownEx(NDIS_HANDLE MiniportAdapterContext, NDIS_SHUTDOWN_ACTION ShutdownAction);
void NeoNdisCancelOidRequest(NDIS_HANDLE MiniportAdapterContext, PVOID RequestId);

// 		NeoNdisCrash2(__LINE__, __LINE__, __LINE__, __LINE__);


#endif	// NDIS5_H

