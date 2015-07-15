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


// NDIS5.c
// Description: Windows NDIS 5.0 Routine

#include <GlobalConst.h>

#define	NEO_DEVICE_DRIVER

#include "Neo.h"

static UINT max_speed = NEO_MAX_SPEED_DEFAULT;
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
NDIS_HANDLE ndis_wrapper_handle = NULL;

// Whether Windows 8
bool g_is_win8 = false;

// Win32 driver entry point
NDIS_STATUS DriverEntry(DRIVER_OBJECT *DriverObject, UNICODE_STRING *RegistryPath)
{
	NDIS_MINIPORT_CHARACTERISTICS miniport;
	ULONG os_major_ver = 0, os_minor_ver = 0;

	// Initialize the Neo library
	if (NeoInit() == FALSE)
	{
		// Initialization Failed
		return STATUS_UNSUCCESSFUL;
	}

	g_is_win8 = false;

#ifndef	NDIS30_MINIPORT
	// Get the OS version
	PsGetVersion(&os_major_ver, &os_minor_ver, NULL, NULL);

	if (os_major_ver >= 7 || (os_major_ver == 6 && os_minor_ver >= 2))
	{
		// Windows 8
		g_is_win8 = true;
	}
#endif	// NDIS30_MINIPORT

	// Initialize the NDIS wrapper
	NdisMInitializeWrapper(&ctx->NdisWrapper, DriverObject, RegistryPath, NULL);
	ndis_wrapper_handle = ctx->NdisWrapper;

	// Register a NDIS miniport driver
	NeoZero(&miniport, sizeof(NDIS_MINIPORT_CHARACTERISTICS));
	miniport.MajorNdisVersion = NEO_NDIS_MAJOR_VERSION;
	miniport.MinorNdisVersion = NEO_NDIS_MINOR_VERSION;

	// Register the handler
	miniport.InitializeHandler = NeoNdisInit;
	miniport.HaltHandler = NeoNdisHalt;
	miniport.QueryInformationHandler = NeoNdisQuery;
	miniport.ResetHandler = NeoNdisReset;
	miniport.SetInformationHandler = NeoNdisSet;

#ifndef	NDIS30_MINIPORT
	miniport.SendPacketsHandler = NeoNdisSendPackets;
#else	// NDIS30_MINIPORT
	miniport.SendHandler = NULL;
#endif	// NDIS30_MINIPORT

	if (NG(NdisMRegisterMiniport(ctx->NdisWrapper, &miniport, sizeof(NDIS_MINIPORT_CHARACTERISTICS))))
	{
		// Registration failure
		return STATUS_UNSUCCESSFUL;
	}

	// Initialization success
	return STATUS_SUCCESS;
}

// Initialization handler of adapter
NDIS_STATUS NeoNdisInit(NDIS_STATUS *OpenErrorStatus,
					UINT *SelectedMediumIndex,
					NDIS_MEDIUM *MediumArray,
					UINT MediumArraySize,
					NDIS_HANDLE MiniportAdapterHandle,
					NDIS_HANDLE WrapperConfigurationContext)
{
	BOOL media_check;
	UINT i;

	if (ctx == NULL)
	{
		return NDIS_STATUS_FAILURE;
	}

	if (ctx->NdisWrapper == NULL)
	{
		ctx->NdisWrapper = ndis_wrapper_handle;
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
		// PacketiX VPN driver can start only one instance per one service.
		// User can start multiple drivers with different instance ID
		return NDIS_STATUS_FAILURE;
	}

	// Current value of the packet filter
	ctx->CurrentPacketFilter = NDIS_PACKET_TYPE_ALL_LOCAL | NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_ALL_FUNCTIONAL;

	// Examine whether the Ethernet is available
	media_check = FALSE;
	for (i = 0;i < MediumArraySize;i++)
	{
		if (MediumArray[i] == NEO_MEDIA)
		{
			media_check = TRUE;
			break;
		}
	}
	if (media_check == FALSE)
	{
		// Ethernet is unavailable
		ctx->Initing = FALSE;
		return NDIS_STATUS_FAILURE;
	}

	// Media number to use
	*SelectedMediumIndex = i;

	// Initialize the adapter information
	ctx->NdisMiniport = MiniportAdapterHandle;
	ctx->NdisConfig = WrapperConfigurationContext;
	ctx->NdisContext = ctx;
	ctx->HardwareStatus = NdisHardwareStatusReady;
	ctx->Halting = FALSE;
	ctx->Connected = ctx->ConnectedOld = FALSE;

	if (keep_link == false)
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

	if (g_is_win8 == false)
	{
		NdisMSetAttributes(ctx->NdisMiniport, ctx->NdisContext, FALSE, NdisInterfaceInternal);
	}
	else
	{
		NdisMSetAttributesEx(ctx->NdisMiniport, ctx->NdisContext, 16,
			NDIS_ATTRIBUTE_DESERIALIZE | NDIS_ATTRIBUTE_IGNORE_PACKET_TIMEOUT | NDIS_ATTRIBUTE_IGNORE_REQUEST_TIMEOUT | NDIS_ATTRIBUTE_NO_HALT_ON_SUSPEND,
			NdisInterfaceInternal);
	}

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

	if (ctx->Opened != FALSE)
	{
		// Another client is connected already
		return FALSE;
	}
	ctx->Opened = TRUE;

	// Initialize the event name
	sprintf(name, NDIS_NEO_EVENT_NAME, ctx->HardwareID);

	// Register a Event
#ifndef	WIN9X
	ctx->Event = NeoNewEvent(name);
	if (ctx->Event == NULL)
	{
		ctx->Opened = FALSE;
		return FALSE;
	}
#endif	// WIN9X

	// Set the connection state
	NeoSetConnectState(TRUE);

	return TRUE;
}

// Close the device
BOOL NeoNdisOnClose(IRP *irp, IO_STACK_LOCATION *stack)
{
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

	// Release the event
	NeoFreeEvent(ctx->Event);
	ctx->Event = NULL;

	// Release all packets
	NeoClearPacketQueue();

	NeoSetConnectState(FALSE);

	return TRUE;
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
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_UNSUCCESSFUL;
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
#ifndef	WIN9X
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
#endif	// WIN9X
		break;

	case IRP_MJ_WRITE:
#ifndef	WIN9X
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
#endif	// WIN9X
	case IRP_MJ_DEVICE_CONTROL:
#ifdef	WIN9X
		// IO Control
		switch (stack->Parameters.DeviceIoControl.IoControlCode)
		{
		case NEO_IOCTL_SET_EVENT:
			// Specify a event
			if (Irp->AssociatedIrp.SystemBuffer == NULL ||
				stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(DWORD))
			{
				// An error occurred
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			}
			else
			{
				DWORD value = *((DWORD *)Irp->AssociatedIrp.SystemBuffer);
				ctx->Event = NeoCreateWin9xEvent(value);
				Irp->IoStatus.Information = sizeof(DWORD);
			}
			break;

		case NEO_IOCTL_PUT_PACKET:
			// Write a packet
			ok = false;
			buf = Irp->AssociatedIrp.SystemBuffer;
			if (buf != NULL)
			{
				if (stack->Parameters.DeviceIoControl.InputBufferLength == NEO_EXCHANGE_BUFFER_SIZE)
				{
					// Write
					NeoWrite(buf);
					Irp->IoStatus.Information = NEO_EXCHANGE_BUFFER_SIZE;
					ok = true;
				}
			}

			if (ok == false)
			{
				// An error occurred
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				status = STATUS_UNSUCCESSFUL;
			}
			break;

		case NEO_IOCTL_GET_PACKET:
			// Get the packet
			ok = false;
			buf = Irp->AssociatedIrp.SystemBuffer;
			if (buf != NULL)
			{
				if (stack->Parameters.DeviceIoControl.OutputBufferLength == NEO_EXCHANGE_BUFFER_SIZE)
				{
					// Read
					NeoRead(buf);
					Irp->IoStatus.Information = NEO_EXCHANGE_BUFFER_SIZE;
					ok = true;
				}
			}

			if (ok == false)
			{
				// An error occurred
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				status = STATUS_UNSUCCESSFUL;
			}
			break;
		}
#endif	// WIN9X
		break;
	}

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

	// Generate the device name
	sprintf(name_kernel, NDIS_NEO_DEVICE_NAME, ctx->HardwareID);
	unicode_kernel = NewUnicode(name_kernel);
	sprintf(name_win32, NDIS_NEO_DEVICE_NAME_WIN32, ctx->HardwareID);
	unicode_win32 = NewUnicode(name_win32);

	// Register the Device
	NdisMRegisterDevice(ctx->NdisWrapper, GetUnicode(unicode_kernel),
		GetUnicode(unicode_win32), ctx->DispatchTable,
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
	// Delet the device
	NdisMDeregisterDevice(ctx->NdisControl);
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
	UINT speed;
	BOOL keep;

	// Get the config handle
	NdisOpenConfiguration(&ret, &config, ctx->NdisConfig);
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

		ctx->MacAddress[0] = 0x00;
		ctx->MacAddress[1] = 0xAD;
		ctx->MacAddress[2] = ((UCHAR *)(&ptr32))[0];
		ctx->MacAddress[3] = ((UCHAR *)(&ptr32))[1];
		ctx->MacAddress[4] = ((UCHAR *)(&ptr32))[2];
		ctx->MacAddress[5] = ((UCHAR *)(&ptr32))[3];
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
		speed = param->ParameterData.IntegerData * 10000;
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

	// Close the Config handle
	NdisCloseConfiguration(config);

	return TRUE;
}

// Stop handler of adapter
NDIS_STATUS NeoNdisHalt(NDIS_HANDLE MiniportAdapterContext)
{
	if (ctx == NULL)
	{
		return NDIS_STATUS_FAILURE;
	}

	if (ctx->Halting != FALSE)
	{
		// That has already been stopped
		return NDIS_STATUS_SUCCESS;
	}
	ctx->Halting = TRUE;

	// Stop the adapter
	NeoStopAdapter();

	// Release the packet array
	NeoFreePacketArray();

	// Delete the control device
	NeoFreeControlDevice();

	// Complete to stop
	ctx->Initing = ctx->Inited = FALSE;
	ctx->Connected = ctx->ConnectedForce = ctx->ConnectedOld = FALSE;
	ctx->Halting = FALSE;

	// Shutdown of Neo
	NeoShutdown();

	return NDIS_STATUS_SUCCESS;
}

// Reset handler of adapter
NDIS_STATUS NeoNdisReset(BOOLEAN *AddressingReset, NDIS_HANDLE MiniportAdapterContext)
{
	NdisMResetComplete(ctx->NdisMiniport, NDIS_STATUS_SUCCESS, FALSE);
	return NDIS_STATUS_SUCCESS;
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
		// Available look-ahead size
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
		value32 = max_speed;
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
	if (ctx == NULL || ctx->NdisMiniport == NULL)
	{
		return;
	}

	if (keep_link == false)
	{
		if (ctx->ConnectedOld != ctx->Connected || ctx->ConnectedForce)
		{
			ctx->ConnectedForce = FALSE;
			ctx->ConnectedOld = ctx->Connected;
			if (ctx->Halting == FALSE)
			{
				NdisMIndicateStatus(ctx->NdisMiniport,
					ctx->Connected ? NDIS_STATUS_MEDIA_CONNECT : NDIS_STATUS_MEDIA_DISCONNECT,
					0, 0);
				NdisMIndicateStatusComplete(ctx->NdisMiniport);
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
				NdisMIndicateStatus(ctx->NdisMiniport,
					NDIS_STATUS_MEDIA_CONNECT,
					0, 0);
				NdisMIndicateStatusComplete(ctx->NdisMiniport);
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

	case OID_802_3_MULTICAST_LIST:
		// Multicast list
		*BytesRead = InformationBufferLength;

		return NDIS_STATUS_SUCCESS;
	}

	return NDIS_STATUS_INVALID_OID;
}

// NDIS 3.0 packet send handler
NDIS_STATUS NeoNdisSend(NDIS_HANDLE MiniportAdapterContext,
						NDIS_PACKET *Packet, UINT Flags)
{
	NDIS_PACKET *PacketArray[1];
	PacketArray[0] = Packet;
	NeoNdisSendPackets(MiniportAdapterContext, PacketArray, 1);

	return NDIS_STATUS_SUCCESS;
}

// Packet send handler
void NeoNdisSendPackets(NDIS_HANDLE MiniportAdapterContext,
						NDIS_PACKET **PacketArray,
						UINT NumberOfPackets)
{
	UCHAR *Buf,*BufCopy;
	PNDIS_BUFFER Buffer;
	UCHAR *Tmp;
	UINT PacketLength;
	UINT CurrentLength;
	UINT i;

	if (ctx == NULL)
	{
		return;
	}

	// Update the connection state
	NeoCheckConnectState();

	if (NumberOfPackets == 0)
	{
		// The number of packets is 0
		return;
	}

	if (NeoNdisSendPacketsHaltCheck(PacketArray, NumberOfPackets) == FALSE)
	{
		// Device is stopped
		return;
	}

	// Operation of the packet queue
	NeoLockPacketQueue();
	{
		if (NeoNdisSendPacketsHaltCheck(PacketArray, NumberOfPackets) == FALSE)
		{
			// Device is stopped
			NeoUnlockPacketQueue();
			return;
		}

		// Place the packet in the queue in order
		for (i = 0;i < NumberOfPackets;i++)
		{
			// Get a packet
			NdisQueryPacket(PacketArray[i], NULL, NULL, &Buffer, &PacketLength);

			// Extract the packet.
			// Memory allocated here is used for the queue and is released at the time of releasing the queue.
			Buf = NeoMalloc(PacketLength);
			BufCopy = Buf;
			while (Buffer)
			{
				NdisQueryBuffer(Buffer, &Tmp, &CurrentLength);
				if (CurrentLength == 0)
				{
					// Complete
					break;
				}
				NeoCopy(BufCopy, Tmp, CurrentLength);
				BufCopy += CurrentLength;
				NdisGetNextBuffer(Buffer, &Buffer);
			}
			// Process this packet
			if (PacketLength > NEO_MIN_PACKET_SIZE)
			{
				if (PacketLength > NEO_MAX_PACKET_SIZE)
				{
					// Packet is too large
					NDIS_SET_PACKET_STATUS(PacketArray[i], NDIS_STATUS_FAILURE);

					if (g_is_win8)
					{
						NdisMSendComplete(ctx->NdisMiniport, PacketArray[i], NDIS_STATUS_FAILURE);
					}

					ctx->Status.NumPacketSendError++;
					NeoFree(Buf);
				}
				else
				{
					// Insert the packet into the queue
					NeoInsertQueue(Buf, PacketLength);
					NDIS_SET_PACKET_STATUS(PacketArray[i], NDIS_STATUS_SUCCESS);

					if (g_is_win8)
					{
						NdisMSendComplete(ctx->NdisMiniport, PacketArray[i], NDIS_STATUS_SUCCESS);
					}

					ctx->Status.NumPacketSend++;
				}
			}
			else
			{
				// Release if the packet doesn't contain data
				NDIS_SET_PACKET_STATUS(PacketArray[i], NDIS_STATUS_SUCCESS);

				if (g_is_win8)
				{
					NdisMSendComplete(ctx->NdisMiniport, PacketArray[i], NDIS_STATUS_SUCCESS);
				}

				NeoFree(Buf);
			}
		}
	}
	NeoUnlockPacketQueue();

	// Reception event
	NeoSet(ctx->Event);
}

// Stop check of packet transmission
BOOL NeoNdisSendPacketsHaltCheck(NDIS_PACKET **PacketArray, UINT NumberOfPackets)
{
	UINT i;

	if (ctx == NULL)
	{
		return FALSE;
	}

	if (ctx->Halting != FALSE || ctx->Opened == FALSE)
	{
		// Finishing
		for (i = 0;i < NumberOfPackets;i++)
		{
			NDIS_SET_PACKET_STATUS(PacketArray[i], NDIS_STATUS_FAILURE);

			if (g_is_win8)
			{
				NdisMSendComplete(ctx->NdisMiniport, PacketArray[i], NDIS_STATUS_SUCCESS);
			}

			ctx->Status.NumPacketSendError++;
		}
		return FALSE;
	}
	return TRUE;
}

// Initialize the packet array
void NeoInitPacketArray()
{
	UINT i;
	// Create a packet buffer
	for (i = 0;i < NEO_MAX_PACKET_EXCHANGE;i++)
	{
		ctx->PacketBuffer[i] = NeoNewPacketBuffer();
		// Store in the array
		ctx->PacketBufferArray[i] = ctx->PacketBuffer[i]->NdisPacket;
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
		ctx->PacketBufferArray[i] = NULL;
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

	// Detach the buffer from the packet
	NdisUnchainBufferAtFront(p->NdisPacket, &p->NdisBuffer);
	// Release the packet
	NdisFreePacket(p->NdisPacket);
	// Release the packet pool
	NdisFreePacketPool(p->PacketPool);
	// Release the buffer
	NdisFreeBuffer(p->NdisBuffer);
	// Release the memory
	NeoFree(p->Buf);
	// Release the buffer pool
	NdisFreeBufferPool(p->BufferPool);
	// Release the memory
	NeoFree(p);
}

// Create a packet buffer
PACKET_BUFFER *NeoNewPacketBuffer()
{
	PACKET_BUFFER *p;
	NDIS_STATUS ret;

	// Memory allocation
	p = NeoZeroMalloc(sizeof(PACKET_BUFFER));
	// Memory allocation for packet
	p->Buf = NeoMalloc(NEO_MAX_PACKET_SIZE);
	// Allocate the buffer pool
	NdisAllocateBufferPool(&ret, &p->BufferPool, 1);
	// Allocate the buffer
	NdisAllocateBuffer(&ret, &p->NdisBuffer, p->BufferPool, p->Buf, NEO_MAX_PACKET_SIZE);
	// Secure the packet pool
	NdisAllocatePacketPool(&ret, &p->PacketPool, 1, PROTOCOL_RESERVED_SIZE_IN_PACKET);
	// Secure the packet
	NdisAllocatePacket(&ret, &p->NdisPacket, p->PacketPool);
	NDIS_SET_PACKET_HEADER_SIZE(p->NdisPacket, NEO_PACKET_HEADER_SIZE);
	// Attach the buffer to the packet
	NdisChainBufferAtFront(p->NdisPacket, p->NdisBuffer);

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

#ifndef	WIN9X
	KeResetEvent(event->event);
#else	// WIN9X
	if (event->win32_event != 0)
	{
		DWORD h = event->win32_event;
		_asm mov eax, h;
		VxDCall(_VWIN32_ResetWin32Event);
	}
#endif	// WIN9X
}

// Set the event
void NeoSet(NEO_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

#ifndef	WIN9X
	KeSetEvent(event->event, 0, FALSE);
#else	// WIN9X
	if (event->win32_event != 0)
	{
		DWORD h = event->win32_event;
		_asm mov eax, h;
		VxDCall(_VWIN32_SetWin32Event);
	}
#endif	// WIN9X
}

// Release the event
void NeoFreeEvent(NEO_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

#ifdef	WIN9X
	if (0)
	{
		if (event->win32_event != 0)
		{
			DWORD h = event->win32_event;
			_asm mov eax, h;
			VxDCall(_VWIN32_CloseVxDHandle);
		}
	}
#endif	WIN9X

	ZwClose(event->event_handle);

	// Release the memory
	NeoFree(event);
}

// Create a new event
#ifndef	WIN9X
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
#else	// WIN9X
NEO_EVENT *NeoCreateWin9xEvent(DWORD h)
{
	NEO_EVENT *event;
	// Validate arguments
	if (h == NULL)
	{
		return NULL;
	}

	// Memory allocation
	event = NeoZeroMalloc(sizeof(NEO_EVENT));
	if (event == NULL)
	{
		return NULL;
	}

	event->win32_event = h;

	return event;
}
#endif	// WIN9X

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
	_NdisInitializeString(&u->String, str);

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

// Create a new lock
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
