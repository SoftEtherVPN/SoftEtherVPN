// SoftEther VPN Source Code
// Kernel Device Driver
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) 2012-2014 Daiyuu Nobori.
// Copyright (c) 2012-2014 SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) 2012-2014 SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


// NDIS6.c
// Windows NDIS 6.2 Routine

#include <GlobalConst.h>

#define	NEO_DEVICE_DRIVER

#include "Neo6.h"

static UINT64 max_speed = NEO_MAX_SPEED_DEFAULT;
static bool keep_link = false;

BOOLEAN
PsGetVersion(
			 PULONG MajorVersion OPTIONAL,
			 PULONG MinorVersion OPTIONAL,
			 PULONG BuildNumber OPTIONAL,
			 PUNICODE_STRING CSDVersion OPTIONAL
			 );

// Memory related
static NDIS_PHYSICAL_ADDRESS HighestAcceptableMax = NDIS_PHYSICAL_ADDRESS_CONST(-1, -1);
NDIS_HANDLE ndis_miniport_driver_handle = NULL;

// Flag for whether Windows 8
bool g_is_win8 = false;

// Win32 driver entry point
NDIS_STATUS DriverEntry(DRIVER_OBJECT *DriverObject, UNICODE_STRING *RegistryPath)
{
	NDIS_MINIPORT_DRIVER_CHARACTERISTICS miniport;
	ULONG os_major_ver = 0, os_minor_ver = 0;
	NDIS_STATUS ret;

	// Initialize the Neo library
	if (NeoInit() == FALSE)
	{
		// Initialization Failed
		return STATUS_UNSUCCESSFUL;
	}

	g_is_win8 = false;

	// Get the OS version
	PsGetVersion(&os_major_ver, &os_minor_ver, NULL, NULL);

	if (os_major_ver >= 7 || (os_major_ver == 6 && os_minor_ver >= 2))
	{
		// Windows 8
		g_is_win8 = true;
	}

	// Register a NDIS miniport driver
	NeoZero(&miniport, sizeof(NDIS_MINIPORT_DRIVER_CHARACTERISTICS));

	miniport.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
	miniport.Header.Revision = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
	miniport.Header.Size = NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;

	miniport.MajorNdisVersion = NEO_NDIS_MAJOR_VERSION;
	miniport.MinorNdisVersion = NEO_NDIS_MINOR_VERSION;

	// Register the handler
	miniport.InitializeHandlerEx = NeoNdisInitEx;
	miniport.HaltHandlerEx = NeoNdisHaltEx;
	miniport.OidRequestHandler = NeoNdisOidRequest;
	miniport.ResetHandlerEx = NeoNdisResetEx;
	miniport.CheckForHangHandlerEx = NeoNdisCheckForHangEx;
	miniport.UnloadHandler = NeoNdisDriverUnload;
	miniport.SendNetBufferListsHandler = NeoNdisSendNetBufferLists;

	miniport.SetOptionsHandler = NeoNdisSetOptions;
	miniport.PauseHandler = NeoNdisPause;
	miniport.RestartHandler = NeoNdisRestart;
	miniport.ReturnNetBufferListsHandler = NeoNdisReturnNetBufferLists;
	miniport.CancelSendHandler = NeoNdisCancelSend;
	miniport.DevicePnPEventNotifyHandler = NeoNdisDevicePnPEventNotify;
	miniport.ShutdownHandlerEx = NeoNdisShutdownEx;
	miniport.CancelOidRequestHandler = NeoNdisCancelOidRequest;

	ret = NdisMRegisterMiniportDriver(DriverObject, RegistryPath,
		NULL, &miniport, &ndis_miniport_driver_handle);

	if (NG(ret))
	{
		// Registration failure
		return STATUS_UNSUCCESSFUL;
	}

	// Initialization success
	return STATUS_SUCCESS;
}

NDIS_STATUS NeoNdisSetOptions(NDIS_HANDLE NdisDriverHandle, NDIS_HANDLE DriverContext)
{
	return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS NeoNdisPause(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_PAUSE_PARAMETERS MiniportPauseParameters)
{
	UINT counter_dbg = 0;

	ctx->Paused = true;

	NeoLockPacketQueue();
	NeoUnlockPacketQueue();

	// Wait for complete all tasks
	while (ctx->NumCurrentDispatch != 0)
	{
		NdisMSleep(10000);
		counter_dbg++;
		if (counter_dbg >= 1500)
		{
			break;
		}
	}

	return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS NeoNdisRestart(NDIS_HANDLE MiniportAdapterContext, PNDIS_MINIPORT_RESTART_PARAMETERS MiniportRestartParameters)
{
	ctx->Paused = false;

	return NDIS_STATUS_SUCCESS;
}

void NeoNdisReturnNetBufferLists(NDIS_HANDLE MiniportAdapterContext, PNET_BUFFER_LIST NetBufferLists, ULONG ReturnFlags)
{
}

void NeoNdisCancelSend(NDIS_HANDLE MiniportAdapterContext, PVOID CancelId)
{
	//NeoNdisCrash2(__LINE__, __LINE__, __LINE__, __LINE__);
}

void NeoNdisDevicePnPEventNotify(NDIS_HANDLE MiniportAdapterContext, PNET_DEVICE_PNP_EVENT NetDevicePnPEvent)
{
}

void NeoNdisShutdownEx(NDIS_HANDLE MiniportAdapterContext, NDIS_SHUTDOWN_ACTION ShutdownAction)
{
}

void NeoNdisCancelOidRequest(NDIS_HANDLE MiniportAdapterContext, PVOID RequestId)
{
	//NeoNdisCrash2(__LINE__, __LINE__, __LINE__, __LINE__);
}

// Initialization handler of adapter
NDIS_STATUS NeoNdisInitEx(NDIS_HANDLE MiniportAdapterHandle,
						  NDIS_HANDLE MiniportDriverContext,
						  PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters)
{
	NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES attr;
	NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES gen;
	NDIS_PM_CAPABILITIES pnpcap;

	if (ctx == NULL)
	{
		return NDIS_STATUS_FAILURE;
	}

	if (ctx->NdisMiniportDriverHandle == NULL)
	{
		ctx->NdisMiniportDriverHandle = ndis_miniport_driver_handle;
	}

	// Prevention of multiple start
	if (ctx->Initing != FALSE)
	{
		// Multiple started
		return NDIS_STATUS_FAILURE;
	}
	ctx->Initing = TRUE;

	// Examine whether it has already been initialized
	if (ctx->Inited != FALSE)
	{
		// Driver is started on another instance already.
		// VPN driver can start only one instance per one service.
		// User can start multiple drivers with different instance ID
		return NDIS_STATUS_FAILURE;
	}

	// Current value of the packet filter
	ctx->CurrentPacketFilter = NDIS_PACKET_TYPE_ALL_LOCAL | NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_ALL_FUNCTIONAL;

	// Initialize the adapter information
	ctx->NdisMiniport = MiniportAdapterHandle;
	ctx->NdisContext = ctx;
	ctx->HardwareStatus = NdisHardwareStatusReady;
	ctx->Halting = FALSE;
	ctx->Connected = ctx->ConnectedOld = FALSE;

	//if (keep_link == false)
	{
		ctx->ConnectedForce = TRUE;
	}

	// Read the information from the registry
	if (NeoLoadRegistory() == FALSE)
	{
		// Failure
		ctx->Initing = FALSE;
		return NDIS_STATUS_FAILURE;
	}

	// Register the device attributes
	NeoZero(&attr, sizeof(attr));
	attr.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
	attr.Header.Revision = NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
	attr.Header.Size = sizeof(NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES);
	attr.AttributeFlags = NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND;
	attr.InterfaceType = NdisInterfaceInternal;
	attr.MiniportAdapterContext = ctx->NdisContext;

	NdisMSetMiniportAttributes(ctx->NdisMiniport, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&attr);

	NeoZero(&pnpcap, sizeof(pnpcap));

	NeoZero(&gen, sizeof(gen));
	gen.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
	gen.Header.Revision = NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
	gen.Header.Size = NDIS_SIZEOF_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_2;
	gen.MediaType = NdisMedium802_3;
	gen.PhysicalMediumType = NdisPhysicalMedium802_3;
	gen.MtuSize = NEO_MAX_PACKET_SIZE_ANNOUNCE - NEO_MIN_PACKET_SIZE;
	gen.MaxXmitLinkSpeed = gen.MaxRcvLinkSpeed = max_speed;
	gen.RcvLinkSpeed = gen.XmitLinkSpeed = max_speed;
	gen.MediaConnectState = MediaConnectStateDisconnected;
	gen.LookaheadSize = NEO_MAX_PACKET_SIZE_ANNOUNCE - NEO_MIN_PACKET_SIZE;
	gen.MacOptions = NDIS_MAC_OPTION_TRANSFERS_NOT_PEND | NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | NDIS_MAC_OPTION_NO_LOOPBACK;
	gen.SupportedPacketFilters = NDIS_PACKET_TYPE_ALL_LOCAL | NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_ALL_FUNCTIONAL;
	gen.MaxMulticastListSize = NEO_MAX_MULTICASE;
	gen.MacAddressLength = NEO_MAC_ADDRESS_SIZE;
	NeoCopy(gen.PermanentMacAddress, ctx->MacAddress, NEO_MAC_ADDRESS_SIZE);
	NeoCopy(gen.CurrentMacAddress, ctx->MacAddress, NEO_MAC_ADDRESS_SIZE);
	gen.AccessType = NET_IF_ACCESS_BROADCAST;
	gen.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
	gen.ConnectionType = NET_IF_CONNECTION_DEDICATED;
	gen.IfType = IF_TYPE_ETHERNET_CSMACD;
	gen.IfConnectorPresent = TRUE;
	gen.SupportedStatistics =
		NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS |
		NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR |
		NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR |
		NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS |
		NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_RCV |
		NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_XMIT |
		NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_XMIT;
	gen.SupportedPauseFunctions = NdisPauseFunctionsUnsupported;
	gen.AutoNegotiationFlags = NDIS_LINK_STATE_XMIT_LINK_SPEED_AUTO_NEGOTIATED |
		NDIS_LINK_STATE_RCV_LINK_SPEED_AUTO_NEGOTIATED |
		NDIS_LINK_STATE_DUPLEX_AUTO_NEGOTIATED |
		NDIS_LINK_STATE_PAUSE_FUNCTIONS_AUTO_NEGOTIATED;
	gen.SupportedOidList = SupportedOids;
	gen.SupportedOidListLength = sizeof(SupportedOids);

	NeoZero(&pnpcap, sizeof(pnpcap));
	pnpcap.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	pnpcap.Header.Revision = NDIS_PM_CAPABILITIES_REVISION_1;
	pnpcap.Header.Size = NDIS_SIZEOF_NDIS_PM_CAPABILITIES_REVISION_1;
	pnpcap.MinMagicPacketWakeUp = NdisDeviceStateUnspecified;
	pnpcap.MinPatternWakeUp  = NdisDeviceStateUnspecified;
	pnpcap.MinLinkChangeWakeUp = NdisDeviceStateUnspecified;
	gen.PowerManagementCapabilitiesEx = &pnpcap;

	NdisMSetMiniportAttributes(ctx->NdisMiniport, (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&gen);

	// Initialize the received packet array
	NeoInitPacketArray();

	// Initialize the control device
	NeoInitControlDevice();

	// Start the adapter
	NeoStartAdapter();

	// Flag setting
	ctx->Initing = FALSE;
	ctx->Inited = TRUE;

	// Notify the connection state
	NeoSetConnectState(FALSE);

	return NDIS_STATUS_SUCCESS;
}

// Open the device
BOOL NeoNdisOnOpen(IRP *irp, IO_STACK_LOCATION *stack)
{
	char name[MAX_SIZE];

	if (ctx == NULL)
	{
		return FALSE;
	}

	if (ctx->Opened)
	{
		// Another client is connected already
		return FALSE;
	}
	ctx->Opened = TRUE;

	// Initialize the event name
	sprintf(name, NDIS_NEO_EVENT_NAME, ctx->HardwareID);

	// Register a Event
	ctx->Event = NeoNewEvent(name);
	if (ctx->Event == NULL)
	{
		ctx->Opened = FALSE;
		return FALSE;
	}

	// Set the connection state
	NeoSetConnectState(TRUE);

	return TRUE;
}

// Close the device
BOOL NeoNdisOnClose(IRP *irp, IO_STACK_LOCATION *stack)
{
	NEO_EVENT *free_event = NULL;
	if (ctx == NULL)
	{
		return FALSE;
	}

	if (ctx->Opened == FALSE)
	{
		// Client is not connected
		return FALSE;
	}
	ctx->Opened = FALSE;

	NeoLockPacketQueue();
	{
		// Release the event
		free_event = ctx->Event;
		ctx->Event = NULL;

		// Release all packets
		NeoClearPacketQueue(true);
	}
	NeoUnlockPacketQueue();

	if (free_event != NULL)
	{
		NeoFreeEvent(free_event);
	}

	NeoSetConnectState(FALSE);

	return TRUE;
}

// Crash 2
void NeoNdisCrash2(UINT a, UINT b, UINT c, UINT d)
{
	KeBugCheckEx(0x00000061, (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, (ULONG_PTR)d);
}

// Crash
void NeoNdisCrash()
{
	NEO_QUEUE *q;
	q = (NEO_QUEUE *)0xACACACAC;
	q->Size = 128;
	NeoCopy(q->Buf, "ABCDEFG", 8);
}

// Dispatch table for control
NTSTATUS NeoNdisDispatch(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
	NTSTATUS status;
	IO_STACK_LOCATION *stack;
	void *buf;
	BOOL ok;
	status = STATUS_SUCCESS;

	if (ctx == NULL)
	{
		return NDIS_STATUS_FAILURE;
	}

	InterlockedIncrement(&ctx->NumCurrentDispatch);

	// Get the IRP stack
	stack = IoGetCurrentIrpStackLocation(Irp);

	// Initialize the number of bytes
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	buf = Irp->UserBuffer;

	if (ctx->Halting != FALSE)
	{
		// Device driver is terminating
		Irp->IoStatus.Information = STATUS_UNSUCCESSFUL;
		InterlockedDecrement(&ctx->NumCurrentDispatch);

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}

	// Branch to each operation
	switch (stack->MajorFunction)
	{
	case IRP_MJ_CREATE:
		// Device is opened
		if (NeoNdisOnOpen(Irp, stack) == FALSE)
		{
			Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			status = STATUS_UNSUCCESSFUL;
		}
		break;

	case IRP_MJ_CLOSE:
		// Device is closed
		if (NeoNdisOnClose(Irp, stack) == FALSE)
		{
			Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			status = STATUS_UNSUCCESSFUL;
		}
		break;

	case IRP_MJ_READ:
		// Read (Reading of the received packet)
		ok = false;
		if (buf != NULL)
		{
			if (ctx->Opened && ctx->Inited)
			{
				if (stack->Parameters.Read.Length == NEO_EXCHANGE_BUFFER_SIZE)
				{
					// Address check
					MDL *mdl = IoAllocateMdl(buf, NEO_EXCHANGE_BUFFER_SIZE, false, false, NULL);

					if (mdl != NULL)
					{
						MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
					}

					if (NeoIsKernelAddress(buf) == FALSE)
					{
						// Read
						NeoRead(buf);
						Irp->IoStatus.Information = NEO_EXCHANGE_BUFFER_SIZE;
						ok = true;
					}

					if (mdl != NULL)
					{
						MmUnlockPages(mdl);
						IoFreeMdl(mdl);
					}
				}
			}
		}
		if (ok == FALSE)
		{
			// An error occurred
			Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			status = STATUS_UNSUCCESSFUL;
		}
		break;

	case IRP_MJ_WRITE:
		// Write (Writing of a transmission packet)
		ok = false;
		if (buf != NULL)
		{
			if (ctx->Opened && ctx->Inited)
			{
				if (stack->Parameters.Write.Length == NEO_EXCHANGE_BUFFER_SIZE)
				{
					// Address check
					MDL *mdl = IoAllocateMdl(buf, NEO_EXCHANGE_BUFFER_SIZE, false, false, NULL);

					if (mdl != NULL)
					{
						MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
					}

					if (NeoIsKernelAddress(buf) == FALSE)
					{
						// Write
						NeoWrite(buf);
						Irp->IoStatus.Information = stack->Parameters.Write.Length;
						ok = true;
					}

					if (mdl != NULL)
					{
						MmUnlockPages(mdl);
						IoFreeMdl(mdl);
					}
				}
			}
		}
		if (ok == FALSE)
		{
			// An error occurred
			Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}

	InterlockedDecrement(&ctx->NumCurrentDispatch);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// Initialize the control device
void NeoInitControlDevice()
{
	char name_kernel[MAX_SIZE];
	char name_win32[MAX_SIZE];
	UNICODE *unicode_kernel, *unicode_win32;
	DEVICE_OBJECT *control_device_object;
	NDIS_HANDLE ndis_control_handle;
	NDIS_DEVICE_OBJECT_ATTRIBUTES t;

	if (ctx == NULL)
	{
		return;
	}

	// Initialize the dispatch table
	NeoZero(ctx->DispatchTable, sizeof(PDRIVER_DISPATCH) * IRP_MJ_MAXIMUM_FUNCTION);

	// Register the handler
	ctx->DispatchTable[IRP_MJ_CREATE] =
		ctx->DispatchTable[IRP_MJ_CLOSE] =
		ctx->DispatchTable[IRP_MJ_READ] =
		ctx->DispatchTable[IRP_MJ_WRITE] =
		ctx->DispatchTable[IRP_MJ_DEVICE_CONTROL] = NeoNdisDispatch;
	ctx->Opened = FALSE;
	ctx->Paused = FALSE;

	// Generate the device name
	sprintf(name_kernel, NDIS_NEO_DEVICE_NAME, ctx->HardwareID);
	unicode_kernel = NewUnicode(name_kernel);
	sprintf(name_win32, NDIS_NEO_DEVICE_NAME_WIN32, ctx->HardwareID);
	unicode_win32 = NewUnicode(name_win32);

	// Register the device
	NeoZero(&t, sizeof(t));
	t.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
	t.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
	t.Header.Size = NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
	t.DeviceName = GetUnicode(unicode_kernel);
	t.SymbolicName = GetUnicode(unicode_win32);
	t.MajorFunctions = ctx->DispatchTable;

	NdisRegisterDeviceEx(ndis_miniport_driver_handle, &t,
		&control_device_object,
		&ndis_control_handle);

	ctx->NdisControlDevice = control_device_object;
	ctx->NdisControl = ndis_control_handle;

	// Initialize the display name
	if (strlen(ctx->HardwareID) > 11)
	{
		sprintf(ctx->HardwarePrintableID, NDIS_NEO_HARDWARE_ID, ctx->HardwareID_Raw + 11);
	}
	else
	{
		sprintf(ctx->HardwarePrintableID, NDIS_NEO_HARDWARE_ID, ctx->HardwareID_Raw);
	}
}

// Release the control device
void NeoFreeControlDevice()
{
	if (ctx == NULL)
	{
		return;
	}

	if (ctx->Opened != FALSE)
	{
		// Delete the event
		NeoSet(ctx->Event);
		NeoFreeEvent(ctx->Event);
		ctx->Event = NULL;
		ctx->Opened = FALSE;
	}

	// Delete the device
	NdisDeregisterDeviceEx(ctx->NdisControl);
}


// Read the information from the registry
BOOL NeoLoadRegistory()
{
	void *buf;
	NDIS_STATUS ret;
	UINT size;
	NDIS_HANDLE config;
	NDIS_CONFIGURATION_PARAMETER *param;
	UNICODE *name;
	ANSI_STRING ansi;
	UNICODE_STRING *unicode;
	UINT64 speed;
	BOOL keep;
	NDIS_CONFIGURATION_OBJECT config_obj;

	// Get the Config handle
	NeoZero(&config_obj, sizeof(config_obj));
	config_obj.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
	config_obj.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
	config_obj.Header.Size = NDIS_SIZEOF_CONFIGURATION_OBJECT_REVISION_1;
	config_obj.NdisHandle = ctx->NdisMiniport;

	ret = NdisOpenConfigurationEx(&config_obj, &config);
	if (NG(ret))
	{
		// Failure
		return FALSE;
	}

	// Read the MAC address
	NdisReadNetworkAddress(&ret, &buf, &size, config);
	if (NG(ret))
	{
		// Failure
		NdisCloseConfiguration(config);
		return FALSE;
	}

	// Copy the MAC address
	if (size != NEO_MAC_ADDRESS_SIZE)
	{
		// Invalid size
		NdisCloseConfiguration(config);
		return FALSE;
	}
	NeoCopy(ctx->MacAddress, buf, NEO_MAC_ADDRESS_SIZE);

	if (ctx->MacAddress[0] == 0x00 &&
		ctx->MacAddress[1] == 0x00 &&
		ctx->MacAddress[2] == 0x01 &&
		ctx->MacAddress[3] == 0x00 &&
		ctx->MacAddress[4] == 0x00 &&
		ctx->MacAddress[5] == 0x01)
	{
		// Special MAC address
		UINT ptr32 = (UINT)((UINT64)ctx);
		LARGE_INTEGER current_time;
		UCHAR *current_time_bytes;

		KeQuerySystemTime(&current_time);

		current_time_bytes = (UCHAR *)&current_time;

		ctx->MacAddress[0] = 0x00;
		ctx->MacAddress[1] = 0xAD;
		ctx->MacAddress[2] = ((UCHAR *)(&ptr32))[0];
		ctx->MacAddress[3] = ((UCHAR *)(&ptr32))[1];
		ctx->MacAddress[4] = ((UCHAR *)(&ptr32))[2];
		ctx->MacAddress[5] = ((UCHAR *)(&ptr32))[3];

		ctx->MacAddress[2] ^= current_time_bytes[0];
		ctx->MacAddress[3] ^= current_time_bytes[1];
		ctx->MacAddress[4] ^= current_time_bytes[2];
		ctx->MacAddress[5] ^= current_time_bytes[3];

		ctx->MacAddress[2] ^= current_time_bytes[4];
		ctx->MacAddress[3] ^= current_time_bytes[5];
		ctx->MacAddress[4] ^= current_time_bytes[6];
		ctx->MacAddress[5] ^= current_time_bytes[7];
	}

	// Initialize the key name of the device name
	name = NewUnicode("MatchingDeviceId");

	// Read the hardware ID
	NdisReadConfiguration(&ret, &param, config, GetUnicode(name), NdisParameterString);
	FreeUnicode(name);
	if (NG(ret))
	{
		// Failure
		NdisCloseConfiguration(config);
		return FALSE;
	}
	// Type checking
	if (param->ParameterType != NdisParameterString)
	{
		// Failure
		NdisCloseConfiguration(config);
		return FALSE;
	}
	unicode = &param->ParameterData.StringData;

	// Prepare a buffer for ANSI string
	NeoZero(&ansi, sizeof(ANSI_STRING));
	ansi.MaximumLength = MAX_SIZE - 1;
	ansi.Buffer = NeoZeroMalloc(MAX_SIZE);

	// Convert to ANSI string
	NdisUnicodeStringToAnsiString(&ansi, unicode);
	// Copy
	strcpy(ctx->HardwareID, ansi.Buffer);
	strcpy(ctx->HardwareID_Raw, ctx->HardwareID);
	// Convert to upper case
	_strupr(ctx->HardwareID);
	// Release the memory
	NeoFree(ansi.Buffer);

	// Read the bit rate
	name = NewUnicode("MaxSpeed");
	NdisReadConfiguration(&ret, &param, config, GetUnicode(name), NdisParameterInteger);
	FreeUnicode(name);

	if (NG(ret) || param->ParameterType != NdisParameterInteger)
	{
		speed = NEO_MAX_SPEED_DEFAULT;
	}
	else
	{
		speed = (UINT64)param->ParameterData.IntegerData * 1000000ULL;
	}

	max_speed = speed;

	// Read the link keeping flag
	name = NewUnicode("KeepLink");
	NdisReadConfiguration(&ret, &param, config, GetUnicode(name), NdisParameterInteger);
	FreeUnicode(name);

	if (NG(ret) || param->ParameterType != NdisParameterInteger)
	{
		keep = false;
	}
	else
	{
		keep = (param->ParameterData.IntegerData == 0 ? false : true);
	}

	keep_link = keep;

	// Close the config handle
	NdisCloseConfiguration(config);

	return TRUE;
}

// Unload the driver
VOID NeoNdisDriverUnload(PDRIVER_OBJECT DriverObject)
{
	NdisMDeregisterMiniportDriver(ndis_miniport_driver_handle);
}

// Stop handler of adapter
void NeoNdisHaltEx(NDIS_HANDLE MiniportAdapterContext, NDIS_HALT_ACTION HaltAction)
{
	NEO_EVENT *free_event = NULL;
	UINT counter_dbg = 0;
	if (ctx == NULL)
	{
		return;
	}

	if (ctx->Halting != FALSE)
	{
		// That has already been stopped
		return;
	}
	ctx->Halting = TRUE;

	ctx->Opened = FALSE;

	NeoLockPacketQueue();
	{
		// Release the event
		free_event = ctx->Event;
		ctx->Event = NULL;

		// Release all packets
		NeoClearPacketQueue(true);
	}
	NeoUnlockPacketQueue();

	if (free_event != NULL)
	{
		NeoSet(free_event);
	}

	// Wait for complete all tasks
	while (ctx->NumCurrentDispatch != 0)
	{
		NdisMSleep(10000);
		counter_dbg++;
		if (counter_dbg >= 1500)
		{
			break;
		}
	}

	if (free_event != NULL)
	{
		NeoFreeEvent(free_event);
	}

	// Delete the control device
	NeoFreeControlDevice();

	// Stop the adapter
	NeoStopAdapter();

	// Release the packet array
	NeoFreePacketArray();

	// Complete to stop
	ctx->Initing = ctx->Inited = FALSE;
	ctx->Connected = ctx->ConnectedForce = ctx->ConnectedOld = FALSE;
	ctx->Halting = FALSE;

	// Shutdown of Neo
	NeoShutdown();
}

// Reset handler of adapter
NDIS_STATUS NeoNdisResetEx(NDIS_HANDLE MiniportAdapterContext, PBOOLEAN AddressingReset)
{
	return NDIS_STATUS_SUCCESS;
}

// Hang-up check handler of adapter
BOOLEAN NeoNdisCheckForHangEx(NDIS_HANDLE MiniportAdapterContext)
{
	return FALSE;
}

// OID request handler
NDIS_STATUS NeoNdisOidRequest(NDIS_HANDLE MiniportAdapterContext,
							  PNDIS_OID_REQUEST OidRequest)
{
	NDIS_STATUS ret = STATUS_UNSUCCESSFUL;
	ULONG dummy = 0;

	switch (OidRequest->RequestType)
	{
	case NdisRequestQueryInformation:
	case NdisRequestQueryStatistics:
		ret = NeoNdisQuery(MiniportAdapterContext,
			OidRequest->DATA.QUERY_INFORMATION.Oid,
			OidRequest->DATA.QUERY_INFORMATION.InformationBuffer,
			OidRequest->DATA.QUERY_INFORMATION.InformationBufferLength,
			&OidRequest->DATA.QUERY_INFORMATION.BytesWritten,
			&OidRequest->DATA.QUERY_INFORMATION.BytesNeeded);
		break;

	case NdisRequestSetInformation:
		ret = NeoNdisSet(MiniportAdapterContext,
			OidRequest->DATA.SET_INFORMATION.Oid,
			OidRequest->DATA.SET_INFORMATION.InformationBuffer,
			OidRequest->DATA.SET_INFORMATION.InformationBufferLength,
			&dummy,
			&OidRequest->DATA.SET_INFORMATION.BytesNeeded);
		break;

	default:
		ret = NDIS_STATUS_NOT_SUPPORTED;
		break;
	}

	return ret;
}


// Information acquisition handler of adapter
NDIS_STATUS NeoNdisQuery(NDIS_HANDLE MiniportAdapterContext,
					NDIS_OID Oid,
					void *InformationBuffer,
					ULONG InformationBufferLength,
					ULONG *BytesWritten,
					ULONG *BytesNeeded)
{
	NDIS_MEDIUM media;
	void *buf;
	UINT value32;
	USHORT value16;
	UINT size;
	NDIS_STATISTICS_INFO stat;
	NDIS_INTERRUPT_MODERATION_PARAMETERS intp;

	if (ctx == NULL)
	{
		return NDIS_STATUS_FAILURE;
	}

	// Initialization
	size = sizeof(UINT);
	value32 = value16 = 0;
	buf = &value32;

	// Branch processing
	switch (Oid)
	{
	case OID_GEN_SUPPORTED_LIST:
		// Return a list of supported OID
		buf = SupportedOids;
		size = sizeof(SupportedOids);
		break;

	case OID_GEN_MAC_OPTIONS:
		// Ethernet option
		value32 = NDIS_MAC_OPTION_TRANSFERS_NOT_PEND | NDIS_MAC_OPTION_RECEIVE_SERIALIZED |
			NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | NDIS_MAC_OPTION_NO_LOOPBACK;
		break;

	case OID_GEN_HARDWARE_STATUS:
		// Hardware state
		buf = &ctx->HardwareStatus;
		size = sizeof(NDIS_HARDWARE_STATUS);
		break;

	case OID_GEN_MEDIA_SUPPORTED:
	case OID_GEN_MEDIA_IN_USE:
		// Type of media
		media = NdisMedium802_3;
		buf = &media;
		size = sizeof(NDIS_MEDIUM);
		break;

	case OID_GEN_CURRENT_LOOKAHEAD:
	case OID_GEN_MAXIMUM_LOOKAHEAD:
		// Read-ahead available size
		value32 = NEO_MAX_PACKET_SIZE_ANNOUNCE - NEO_MIN_PACKET_SIZE;
		break;

	case OID_GEN_MAXIMUM_FRAME_SIZE:
		// Maximum frame size
		value32 = NEO_MAX_PACKET_SIZE_ANNOUNCE - NEO_MIN_PACKET_SIZE;
		break;

	case OID_GEN_MAXIMUM_TOTAL_SIZE:
	case OID_GEN_TRANSMIT_BLOCK_SIZE:
	case OID_GEN_RECEIVE_BLOCK_SIZE:
		// Maximum packet size
		value32 = NEO_MAX_PACKET_SIZE_ANNOUNCE;
		break;

	case OID_GEN_TRANSMIT_BUFFER_SPACE:
	case OID_GEN_RECEIVE_BUFFER_SPACE:
		// Buffer size
		value32 = NEO_MAX_PACKET_SIZE_ANNOUNCE * NEO_MAX_PACKET_EXCHANGE;
		break;

	case OID_GEN_LINK_SPEED:
		// Communication speed
		value32 = (UINT)(max_speed / 100);
		break;

	case OID_GEN_VENDOR_ID:
		// Vendor ID
		NeoCopy(&value32, ctx->MacAddress, 3);
		value32 &= 0xFFFFFF00;
		value32 |= 0x01;
		break;

	case OID_GEN_VENDOR_DESCRIPTION:
		// Hardware ID
		buf = ctx->HardwarePrintableID;
		size = (UINT)strlen(ctx->HardwarePrintableID) + 1;
		break;

	case OID_GEN_DRIVER_VERSION:
		// Driver version
		value16 = ((USHORT)NEO_NDIS_MAJOR_VERSION << 8) | NEO_NDIS_MINOR_VERSION;
		buf = &value16;
		size = sizeof(USHORT);
		break;

	case OID_GEN_VENDOR_DRIVER_VERSION:
		// Vendor driver version
		value16 = ((USHORT)NEO_NDIS_MAJOR_VERSION << 8) | NEO_NDIS_MINOR_VERSION;
		buf = &value16;
		size = sizeof(USHORT);
		break;

	case OID_802_3_PERMANENT_ADDRESS:
	case OID_802_3_CURRENT_ADDRESS:
		// MAC address
		buf = ctx->MacAddress;
		size = NEO_MAC_ADDRESS_SIZE;
		break;

	case OID_802_3_MAXIMUM_LIST_SIZE:
		// Number of multicast
		value32 = NEO_MAX_MULTICASE;
		break;

	case OID_GEN_MAXIMUM_SEND_PACKETS:
		// Number of packets that can be sent at a time
		value32 = NEO_MAX_PACKET_EXCHANGE;
		break;

	case OID_GEN_XMIT_OK:
		// Number of packets sent
		value32 = ctx->Status.NumPacketSend;
		break;

	case OID_GEN_RCV_OK:
		// Number of received packets
		value32 = ctx->Status.NumPacketRecv;
		break;

	case OID_GEN_XMIT_ERROR:
		// Number of transmission error packets
		value32 = ctx->Status.NumPacketSendError;
		break;

	case OID_GEN_RCV_ERROR:
		// Number of error packets received
		value32 = ctx->Status.NumPacketRecvError;
		break;

	case OID_GEN_RCV_NO_BUFFER:
		// Number of reception buffer shortage occurrences
		value32 = ctx->Status.NumPacketRecvNoBuffer;
		break;

	case OID_802_3_RCV_ERROR_ALIGNMENT:
		// Number of errors
		value32 = 0;
		break;

	case OID_GEN_MEDIA_CONNECT_STATUS:
		// Cable connection state
		NeoCheckConnectState();
		if (keep_link == false)
		{
			value32 = ctx->Connected ? NdisMediaStateConnected : NdisMediaStateDisconnected;
		}
		else
		{
			value32 = NdisMediaStateConnected;
		}
		break;

	case OID_802_3_XMIT_ONE_COLLISION:
	case OID_802_3_XMIT_MORE_COLLISIONS:
		// Number of collisions
		value32 = 0;
		break;

	case OID_GEN_CURRENT_PACKET_FILTER:
		// Current settings of the packet filter
		value32 = ctx->CurrentPacketFilter;
		break;

/*	case OID_GEN_PROTOCOL_OPTIONS:
		// Current value of the protocol option
		value32 = ctx->CurrentProtocolOptions;
		break;*/

	case OID_GEN_STATISTICS:
		// Statistics (NDIS 6.0)
		NeoZero(&stat, sizeof(stat));
		buf = &stat;
		size = sizeof(stat);

		stat.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		stat.Header.Revision = NDIS_STATISTICS_INFO_REVISION_1;
		stat.Header.Size = NDIS_SIZEOF_STATISTICS_INFO_REVISION_1;
		stat.SupportedStatistics =
			NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV |
			NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_RCV |
			NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_RCV |
			NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV |
			NDIS_STATISTICS_FLAGS_VALID_RCV_DISCARDS |
			NDIS_STATISTICS_FLAGS_VALID_RCV_ERROR |
			NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT |
			NDIS_STATISTICS_FLAGS_VALID_MULTICAST_FRAMES_XMIT |
			NDIS_STATISTICS_FLAGS_VALID_BROADCAST_FRAMES_XMIT |
			NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT |
			NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR |
			NDIS_STATISTICS_FLAGS_VALID_XMIT_DISCARDS |
			NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_RCV |
			NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_RCV |
			NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_RCV |
			NDIS_STATISTICS_FLAGS_VALID_DIRECTED_BYTES_XMIT |
			NDIS_STATISTICS_FLAGS_VALID_MULTICAST_BYTES_XMIT |
			NDIS_STATISTICS_FLAGS_VALID_BROADCAST_BYTES_XMIT;

		stat.ifInErrors = ctx->Status.Int64NumRecvError;
		stat.ifHCInOctets = ctx->Status.Int64BytesRecvTotal;
		stat.ifHCInUcastPkts = ctx->Status.Int64NumRecvUnicast;
		stat.ifHCInBroadcastPkts = ctx->Status.Int64NumRecvBroadcast;
		stat.ifHCOutOctets = ctx->Status.Int64BytesSendTotal;
		stat.ifHCOutUcastPkts = ctx->Status.Int64NumSendUnicast;
		stat.ifHCOutBroadcastPkts = ctx->Status.Int64NumSendBroadcast;
		stat.ifOutErrors = ctx->Status.Int64NumSendError;
		stat.ifHCInUcastOctets = ctx->Status.Int64BytesRecvUnicast;
		stat.ifHCInBroadcastOctets = ctx->Status.Int64BytesRecvBroadcast;
		stat.ifHCOutUcastOctets = ctx->Status.Int64BytesSendUnicast;
		stat.ifHCOutBroadcastOctets = ctx->Status.Int64BytesSendBroadcast;
		break;

	case OID_GEN_INTERRUPT_MODERATION:
		// Interrupt Moderation (NDIS 6.0)
		NeoZero(&intp, sizeof(intp));
		buf = &intp;
		size = sizeof(intp);

		intp.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		intp.Header.Revision = NDIS_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
		intp.Header.Size = NDIS_SIZEOF_INTERRUPT_MODERATION_PARAMETERS_REVISION_1;
		intp.InterruptModeration = NdisInterruptModerationNotSupported;
		break;

	default:
		// Unknown OID
		*BytesWritten = 0;
		return NDIS_STATUS_INVALID_OID;
	}

	if (size > InformationBufferLength)
	{
		// Undersize
		*BytesNeeded = size;
		*BytesWritten = 0;
		return NDIS_STATUS_INVALID_LENGTH;
	}

	// Data copy
	NeoCopy(InformationBuffer, buf, size);
	*BytesWritten = size;

	return NDIS_STATUS_SUCCESS;
}

// Set the cable connection state
void NeoSetConnectState(BOOL connected)
{
	if (ctx == NULL)
	{
		return;
	}
	ctx->Connected = connected;
	NeoCheckConnectState();
}

// Check the cable connection state
void NeoCheckConnectState()
{
	NDIS_STATUS_INDICATION t;
	NDIS_LINK_STATE state;
	if (ctx == NULL || ctx->NdisMiniport == NULL)
	{
		return;
	}

	NeoZero(&t, sizeof(t));
	t.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
	t.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
	t.Header.Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1;

	t.SourceHandle = ctx->NdisMiniport;

	NeoZero(&state, sizeof(state));
	state.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	state.Header.Revision = NDIS_LINK_STATE_REVISION_1;
	state.Header.Size = NDIS_SIZEOF_LINK_STATE_REVISION_1;

	state.MediaDuplexState = NdisPauseFunctionsSendAndReceive;
	state.XmitLinkSpeed = state.RcvLinkSpeed = max_speed;
	state.PauseFunctions = NdisPauseFunctionsUnsupported;

	t.StatusCode = NDIS_STATUS_LINK_STATE;
	t.StatusBuffer = &state;
	t.StatusBufferSize = sizeof(NDIS_LINK_STATE);

	if (keep_link == false)
	{
		if (ctx->ConnectedOld != ctx->Connected || ctx->ConnectedForce)
		{
			ctx->ConnectedForce = FALSE;
			ctx->ConnectedOld = ctx->Connected;
			if (ctx->Halting == FALSE)
			{
				state.MediaConnectState = ctx->Connected ? MediaConnectStateConnected : MediaConnectStateDisconnected;
				NdisMIndicateStatusEx(ctx->NdisMiniport, &t);
			}
		}
	}
	else
	{
		if (ctx->ConnectedForce)
		{
			ctx->ConnectedForce = false;

			if (ctx->Halting == FALSE)
			{
				state.MediaConnectState = MediaConnectStateConnected;
				NdisMIndicateStatusEx(ctx->NdisMiniport, &t);
			}
		}
	}
}

// Information setting handler of adapter
NDIS_STATUS NeoNdisSet(
					NDIS_HANDLE MiniportAdapterContext,
					NDIS_OID Oid,
					void *InformationBuffer,
					ULONG InformationBufferLength,
					ULONG *BytesRead,
					ULONG *BytesNeeded)
{
	if (ctx == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	// Initialization
	*BytesRead = 0;
	*BytesNeeded = 0;

	// Branch processing
	switch (Oid)
	{
	case OID_GEN_CURRENT_PACKET_FILTER:
		/* Packet filter */
		if (InformationBufferLength != 4)
		{
			*BytesNeeded = 4;
			return NDIS_STATUS_INVALID_LENGTH;
		}
		*BytesRead = 4;
		ctx->CurrentPacketFilter = *((UINT *)InformationBuffer);
		return NDIS_STATUS_SUCCESS;

//	case OID_GEN_PROTOCOL_OPTIONS:
		/* Current protocol option value */
/*		if (InformationBufferLength != 4)
		{
			*BytesNeeded = 4;
			return NDIS_STATUS_INVALID_LENGTH;
		}
		*BytesRead = 4;
		ctx->CurrentProtocolOptions = *((UINT *)InformationBuffer);
		return NDIS_STATUS_SUCCESS;*/

	case OID_GEN_CURRENT_LOOKAHEAD:
		/* Look ahead */
		if (InformationBufferLength != 4)
		{
			*BytesNeeded = 4;
			return NDIS_STATUS_INVALID_LENGTH;
		}
		*BytesRead = 4;
		return NDIS_STATUS_SUCCESS;

	case OID_GEN_LINK_PARAMETERS:
		// NDIS 6.0 Link setting
		*BytesRead = InformationBufferLength;
		return NDIS_STATUS_SUCCESS;

	case OID_802_3_MULTICAST_LIST:
		// Multicast list
		*BytesRead = InformationBufferLength;

		return NDIS_STATUS_SUCCESS;

	case OID_PNP_SET_POWER:
	case OID_PNP_QUERY_POWER:
		// Power events
		*BytesRead = InformationBufferLength;

		return NDIS_STATUS_SUCCESS;
	}

	return NDIS_STATUS_INVALID_OID;
}

// Set status values of NET_BUFFER_LISTs
void NeoNdisSetNetBufferListsStatus(NET_BUFFER_LIST *nbl, UINT status)
{
	if (nbl == NULL)
	{
		return;
	}

	while (nbl != NULL)
	{
		NET_BUFFER_LIST_STATUS(nbl) = status;

		nbl = NET_BUFFER_LIST_NEXT_NBL(nbl);
	}
}

// Packet send handler
void NeoNdisSendNetBufferLists(NDIS_HANDLE MiniportAdapterContext,
							   NET_BUFFER_LIST *NetBufferLists,
							   NDIS_PORT_NUMBER PortNumber,
							   ULONG SendFlags)
{
	bool is_dispatch_level = SendFlags & NDIS_SEND_FLAGS_DISPATCH_LEVEL;
	UINT send_complete_flags = 0;
	if (ctx == NULL)
	{
		return;
	}

	if (is_dispatch_level)
	{
		send_complete_flags |= NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL;
	}

	InterlockedIncrement(&ctx->NumCurrentDispatch);

	// Update the connection state
	NeoCheckConnectState();

	if (ctx->Halting != FALSE || ctx->Opened == FALSE || ctx->Paused)
	{
		UINT status = NDIS_STATUS_FAILURE;

		if (ctx->Paused)
		{
			status = NDIS_STATUS_PAUSED;
		}
		else if (ctx->Halting)
		{
			status = NDIS_STATUS_FAILURE;
		}
		else if (ctx->Opened == false && keep_link)
		{
			status = NDIS_STATUS_SUCCESS;
		}

		NeoNdisSetNetBufferListsStatus(NetBufferLists, status);

		InterlockedDecrement(&ctx->NumCurrentDispatch);

		NdisMSendNetBufferListsComplete(ctx->NdisMiniport, NetBufferLists, send_complete_flags);

		return;
	}

	// Operation of the packet queue
	NeoLockPacketQueue();
	{
		NET_BUFFER_LIST *nbl;

		if (ctx->Halting != FALSE || ctx->Opened == FALSE || ctx->Paused)
		{
			UINT status = NDIS_STATUS_FAILURE;

			if (ctx->Paused)
			{
				status = NDIS_STATUS_PAUSED;
			}
			else if (ctx->Halting)
			{
				status = NDIS_STATUS_FAILURE;
			}
			else if (ctx->Opened == false && keep_link)
			{
				status = NDIS_STATUS_SUCCESS;
			}

			NeoUnlockPacketQueue();

			NeoNdisSetNetBufferListsStatus(NetBufferLists, status);

			InterlockedDecrement(&ctx->NumCurrentDispatch);

			NdisMSendNetBufferListsComplete(ctx->NdisMiniport, NetBufferLists, send_complete_flags);

			return;
		}

		nbl = NetBufferLists;

		while (nbl != NULL)
		{
			NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(nbl);

			NET_BUFFER_LIST_STATUS(nbl) = NDIS_STATUS_SUCCESS;

			while (nb != NULL)
			{
				UINT size = NET_BUFFER_DATA_LENGTH(nb);

				if (size >= NEO_MIN_PACKET_SIZE && size <= NEO_MAX_PACKET_SIZE)
				{
					UCHAR *buf = NeoMalloc(size);
					void *ptr;

					ptr = NdisGetDataBuffer(nb, size, buf, 1, 0);

					if (ptr == NULL)
					{
						ctx->Status.NumPacketSendError++;
						ctx->Status.Int64NumSendError++;
						NeoFree(buf);
					}
					else
					{
						if (ptr != buf)
						{
							NeoCopy(buf, ptr, size);
						}

						NeoInsertQueue(buf, size);
						ctx->Status.NumPacketSend++;

						if (buf[0] & 0x40)
						{
							ctx->Status.Int64NumSendBroadcast++;
							ctx->Status.Int64BytesSendBroadcast += (UINT64)size;
						}
						else
						{
							ctx->Status.Int64NumSendUnicast++;
							ctx->Status.Int64BytesSendUnicast += (UINT64)size;
						}

						ctx->Status.Int64BytesSendTotal += (UINT64)size;
					}
				}
				else
				{
					ctx->Status.NumPacketSendError++;
					ctx->Status.Int64NumSendError++;
				}

				nb = NET_BUFFER_NEXT_NB(nb);
			}

			nbl = NET_BUFFER_LIST_NEXT_NBL(nbl);
		}

		// Reception event
		NeoSet(ctx->Event);
	}
	NeoUnlockPacketQueue();

	// Notify the transmission completion
	InterlockedDecrement(&ctx->NumCurrentDispatch);
	NdisMSendNetBufferListsComplete(ctx->NdisMiniport, NetBufferLists, send_complete_flags);
}

// Initialize the packet array
void NeoInitPacketArray()
{
	UINT i;
	// Create a packet buffer
	for (i = 0;i < NEO_MAX_PACKET_EXCHANGE;i++)
	{
		ctx->PacketBuffer[i] = NeoNewPacketBuffer();
	}
}

// Release the packet array
void NeoFreePacketArray()
{
	UINT i;
	for (i = 0;i < NEO_MAX_PACKET_EXCHANGE;i++)
	{
		NeoFreePacketBuffer(ctx->PacketBuffer[i]);
		ctx->PacketBuffer[i] = NULL;
	}
}

// Release the packet buffer
void NeoFreePacketBuffer(PACKET_BUFFER *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	// Release the NET_BUFFER_LIST
	NdisFreeNetBufferList(p->NetBufferList);
	// Release the NET_BUFFER_LIST pool
	NdisFreeNetBufferListPool(p->NetBufferListPool);
	// Release the memory
	NeoFree(p);
}

// Create a packet buffer
PACKET_BUFFER *NeoNewPacketBuffer()
{
	PACKET_BUFFER *p;
	NET_BUFFER_LIST_POOL_PARAMETERS p1;

	// Memory allocation
	p = NeoZeroMalloc(sizeof(PACKET_BUFFER));

	// Create a NET_BUFFER_LIST pool
	NeoZero(&p1, sizeof(p1));
	p1.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	p1.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	p1.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	p1.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
	p1.fAllocateNetBuffer = TRUE;
	p1.DataSize = NEO_MAX_PACKET_SIZE;
	p1.PoolTag = 'SETH';
	p->NetBufferListPool = NdisAllocateNetBufferListPool(NULL, &p1);

	// Create a NET_BUFFER_LIST
	p->NetBufferList = NdisAllocateNetBufferList(p->NetBufferListPool, 0, 0);

	return p;
}

// Check whether the specified address is kernel memory
BOOL NeoIsKernelAddress(void *addr)
{
#if	0
	if ((ULONG)addr >= (ULONG)0x80000000)
	{
		// Kernel memory
		return TRUE;
	}
#endif	// CPU_64
	// User memory
	return FALSE;
}

// Reset the event
void NeoReset(NEO_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

	KeResetEvent(event->event);
}

// Set the event
void NeoSet(NEO_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

	KeSetEvent(event->event, 0, FALSE);
}

// Release the event
void NeoFreeEvent(NEO_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

	ZwClose(event->event_handle);

	// Release the memory
	NeoFree(event);
}

// Create a new event
NEO_EVENT *NeoNewEvent(char *name)
{
	UNICODE *unicode_name;
	NEO_EVENT *event;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	// Convert the name to Unicode
	unicode_name = NewUnicode(name);
	if (unicode_name == NULL)
	{
		return NULL;
	}

	// Memory allocation
	event = NeoZeroMalloc(sizeof(NEO_EVENT));
	if (event == NULL)
	{
		FreeUnicode(unicode_name);
		return NULL;
	}

	// Create an Event
	event->event = IoCreateNotificationEvent(GetUnicode(unicode_name), &event->event_handle);
	if (event->event == NULL)
	{
		NeoFree(event);
		FreeUnicode(unicode_name);
		return NULL;
	}

	// Initialize the event
	KeInitializeEvent(event->event, NotificationEvent, FALSE);
	KeClearEvent(event->event);

	// Release a string
	FreeUnicode(unicode_name);

	return event;
}

// Get the Unicode string
NDIS_STRING *GetUnicode(UNICODE *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return NULL;
	}

	return &u->String;
}

// Release the Unicode strings
void FreeUnicode(UNICODE *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	// Release a string
	NdisFreeString(u->String);

	// Release the memory
	NeoFree(u);
}

// Create a new Unicode string
UNICODE *NewUnicode(char *str)
{
	UNICODE *u;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	// Memory allocation
	u = NeoZeroMalloc(sizeof(UNICODE));
	if (u == NULL)
	{
		return NULL;
	}

	// String initialization
	NdisInitializeString(&u->String, str);

	return u;
}

// Release the lock
void NeoFreeLock(NEO_LOCK *lock)
{
	NDIS_SPIN_LOCK *spin_lock;
	// Validate arguments
	if (lock == NULL)
	{
		return;
	}

	spin_lock = &lock->spin_lock;
	NdisFreeSpinLock(spin_lock);

	// Release the memory
	NeoFree(lock);
}

// Unlock
void NeoUnlock(NEO_LOCK *lock)
{
	NDIS_SPIN_LOCK *spin_lock;
	// Validate arguments
	if (lock == NULL)
	{
		return;
	}

	spin_lock = &lock->spin_lock;
	NdisReleaseSpinLock(spin_lock);
}

// Lock
void NeoLock(NEO_LOCK *lock)
{
	NDIS_SPIN_LOCK *spin_lock;
	// Validate arguments
	if (lock == NULL)
	{
		return;
	}

	spin_lock = &lock->spin_lock;
	NdisAcquireSpinLock(spin_lock);
}

// Creating a new lock
NEO_LOCK *NeoNewLock()
{
	NDIS_SPIN_LOCK *spin_lock;

	// Memory allocation
	NEO_LOCK *lock = NeoZeroMalloc(sizeof(NEO_LOCK));
	if (lock == NULL)
	{
		return NULL;
	}

	// Initialize spin lock
	spin_lock = &lock->spin_lock;

	NdisAllocateSpinLock(spin_lock);

	return lock;
}

// Memory copy
void NeoCopy(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || src == NULL || size == 0)
	{
		return;
	}

	// Copy
	NdisMoveMemory(dst, src, size);
}

// Memory clear
void NeoZero(void *dst, UINT size)
{
	// Validate arguments
	if (dst == NULL || size == 0)
	{
		return;
	}

	// Clear
	NdisZeroMemory(dst, size);
}

// Clear to zero by memory allocation
void *NeoZeroMalloc(UINT size)
{
	void *p = NeoMalloc(size);
	if (p == NULL)
	{
		// Memory allocation failure
		return NULL;
	}
	// Clear to zero
	NeoZero(p, size);
	return p;
}

// Memory allocation
void *NeoMalloc(UINT size)
{
	NDIS_STATUS r;
	void *p;
	if (size == 0)
	{
		size = 1;
	}

	// Allocate the non-paged memory
	r = NdisAllocateMemoryWithTag(&p, size, 'SETH');

	if (NG(r))
	{
		return NULL;
	}
	return p;
}

// Release the memory
void NeoFree(void *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	// Release the memory
	NdisFreeMemory(p, 0, 0);
}



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
