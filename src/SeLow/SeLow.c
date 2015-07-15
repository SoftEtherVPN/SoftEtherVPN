// SoftEther VPN Source Code
// SeLow: SoftEther Lightweight Network Protocol
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


// SeLow.c
// SeLow Device Driver

#include <GlobalConst.h>

#define	SELOW_DEVICE_DRIVER

#include "SeLow.h"

static SL_CTX sl_ctx = {0};
static SL_CTX *sl = &sl_ctx;

// Win32 driver entry point
NDIS_STATUS DriverEntry(DRIVER_OBJECT *driver_object, UNICODE_STRING *registry_path)
{
	NDIS_PROTOCOL_DRIVER_CHARACTERISTICS t;
	NDIS_STATUS ret = NDIS_STATUS_FAILURE;
	SL_UNICODE *protocol_name = NULL;
	NDIS_HANDLE protocol_handle = NULL;
	SL_CTX *sl_ctx = NULL;
	DEVICE_OBJECT *device_object = NULL;

	SlZero(sl, sizeof(SL_CTX));

	// Register the NDIS protocol
	protocol_name = SlNewUnicode(SL_PROTOCOL_NAME);
	if (protocol_name == NULL)
	{
		goto LABEL_CLEANUP;
	}

	SlZero(&t, sizeof(t));
	t.Header.Type = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
	t.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
	t.Header.Size = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
	t.MajorNdisVersion = 6;
	t.MinorNdisVersion = 20;
	t.Name = protocol_name->String;

	t.BindAdapterHandlerEx = SlNdisBindAdapterExProc;
	t.UnbindAdapterHandlerEx = SlNdisUnbindAdapterExProc;
	t.OpenAdapterCompleteHandlerEx = SlNdisOpenAdapterCompleteExProc;
	t.CloseAdapterCompleteHandlerEx = SlNdisCloseAdapterCompleteExProc;
	t.NetPnPEventHandler = SlNdisNetPnPEventProc;
	t.UninstallHandler = SlNdisUninstallProc;
	t.OidRequestCompleteHandler = SlNdisOidRequestCompleteProc;
	t.StatusHandlerEx = SlNdisStatusExProc;
	t.ReceiveNetBufferListsHandler = SlNdisReceiveNetBufferListsProc;
	t.SendNetBufferListsCompleteHandler = SlNdisSendNetBufferListsCompleteProc;

	// Create an adapters list
	sl->DriverObject = driver_object;
	sl->AdapterList = SlNewList();

	ret = NdisRegisterProtocolDriver(NULL, &t, &protocol_handle);

	if (NG(ret))
	{
		protocol_handle = NULL;
		goto LABEL_CLEANUP;
	}

	SlZero(driver_object->MajorFunction, sizeof(driver_object->MajorFunction));
	driver_object->MajorFunction[IRP_MJ_CREATE] = SlDeviceOpenProc;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = SlDeviceCloseProc;
	driver_object->MajorFunction[IRP_MJ_READ] = SlDeviceReadProc;
	driver_object->MajorFunction[IRP_MJ_WRITE] = SlDeviceWriteProc;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SlDeviceIoControlProc;
	driver_object->DriverUnload = SlUnloadProc;

	// Initialize the SL context
	sl->ProtocolHandle = protocol_handle;

	// Create a basic device
	sl->BasicDevice = SlNewDevice(SL_BASIC_DEVICE_NAME, SL_BASIC_DEVICE_NAME_SYMBOLIC);
	if (sl->BasicDevice == NULL)
	{
		ret = NDIS_STATUS_FAILURE;
		goto LABEL_CLEANUP;
	}
	sl->BasicDevice->IsBasicDevice = true;

LABEL_CLEANUP:

	SlFreeUnicode(protocol_name);

	if (NG(ret))
	{
		SlUnloadProc(driver_object);
	}

	return ret;
}

// Unloading procedure of the device driver
void SlUnloadProc(DRIVER_OBJECT *driver_object)
{
	// Release the protocol
	if (sl->ProtocolHandle != NULL)
	{
		NdisDeregisterProtocolDriver(sl->ProtocolHandle);
		sl->ProtocolHandle = NULL;
	}

	// Release the basic device
	SlFreeDevice(sl->BasicDevice);

	// Release the adapter list
	SlFreeList(sl->AdapterList);

	// Initialize the SL context
	SlZero(sl, sizeof(SL_CTX));
}

// Delete a device
void SlFreeDevice(SL_DEVICE *dev)
{
	NTSTATUS r;
	// Validate arguments
	if (dev == NULL)
	{
		return;
	}

	r = IoDeleteSymbolicLink(&dev->SymbolicLinkName->String);
	if (NG(r))
	{
		// May fail due to a bug in Windows Kernel
	}

	IoDeleteDevice(dev->DeviceObject);

	SlFreeUnicode(dev->DeviceName);
	SlFreeUnicode(dev->SymbolicLinkName);

	SlFreeLock(dev->OpenCloseLock);

	SlFree(dev);
}

// Create a new device
SL_DEVICE *SlNewDevice(char *device_name, char *symbolic_link_name)
{
	SL_UNICODE *u_device_name = SlNewUnicode(device_name);
	SL_UNICODE *u_sym_name = SlNewUnicode(symbolic_link_name);

	SL_DEVICE *ret = SlNewDeviceUnicode(u_device_name, u_sym_name);

	if (ret == NULL)
	{
		SlFreeUnicode(u_device_name);
		SlFreeUnicode(u_sym_name);
	}

	return ret;
}
SL_DEVICE *SlNewDeviceUnicode(SL_UNICODE *u_device_name, SL_UNICODE *u_sym_name)
{
	SL_DEVICE *ret = NULL;
	DEVICE_OBJECT *dev_obj = NULL;
	NTSTATUS r;
	SL_UNICODE *sddl;

	sddl = SlNewUnicode("D:P(A;;GA;;;SY)(A;;GA;;;BA)");

	/*r = IoCreateDevice(sl->DriverObject, sizeof(SL_DEVICE *),
		&u_device_name->String, FILE_DEVICE_TRANSPORT, 0, false, &dev_obj);*/

	r = IoCreateDeviceSecure(sl->DriverObject, sizeof(SL_DEVICE *),
		&u_device_name->String, FILE_DEVICE_TRANSPORT, 0, false, SlGetUnicode(sddl),
		NULL, &dev_obj);

	SlFreeUnicode(sddl);

	if (NG(r))
	{
		dev_obj = NULL;
		goto LABEL_CLEANUP;
	}

	r = IoCreateSymbolicLink(&u_sym_name->String, &u_device_name->String);
	if (NG(r))
	{
		// May fail due to a bug in Windows Kernel
	}

	ret = SlZeroMalloc(sizeof(SL_DEVICE));
	if (ret == NULL)
	{
		goto LABEL_CLEANUP;
	}

	ret->DeviceObject = dev_obj;
	ret->DeviceName = u_device_name;
	ret->SymbolicLinkName = u_sym_name;
	*((SL_DEVICE **)dev_obj->DeviceExtension) = ret;

	dev_obj->Flags &= ~DO_DEVICE_INITIALIZING;

	ret->OpenCloseLock = SlNewLock();

LABEL_CLEANUP:
	if (ret == NULL)
	{
		if (dev_obj != NULL)
		{
			IoDeleteDevice(dev_obj);
		}
	}

	return ret;
}

// Device is opened
NTSTATUS SlDeviceOpenProc(DEVICE_OBJECT *device_object, IRP *irp)
{
	SL_DEVICE *dev = *((SL_DEVICE **)device_object->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;
	IO_STACK_LOCATION *irp_stack = IoGetCurrentIrpStackLocation(irp);

	if (dev->IsBasicDevice)
	{
		// Basic device
		ret = STATUS_SUCCESS;
	}
	else
	{
		bool set_promisc = false;
		volatile UINT *num_pending_oid_requests = NULL;
		UINT64 v;
		char event_name[SL_EVENT_NAME_SIZE];
		char event_name_win32[SL_EVENT_NAME_SIZE];
		SL_EVENT *event_object = NULL;
		LARGE_INTEGER count;
		LARGE_INTEGER freq;

		count = KeQueryPerformanceCounter(&freq);

		InterlockedIncrement(&sl->IntCounter1);

		// Create a new event object
		v = (UINT64)device_object + (UINT64)(++sl->IntCounter1) + *((UINT64 *)(&count));
		sprintf(event_name, SL_EVENT_NAME, (UINT)v, (UINT)(v >> 32) + sl->IntCounter1);
		sprintf(event_name_win32, SL_EVENT_NAME_WIN32, (UINT)v, (UINT)(v >> 32) + sl->IntCounter1);
		event_object = SlNewEvent(event_name);

		SlLock(dev->OpenCloseLock);
		{
			// Add to the opened file list
			SlLockList(dev->FileList);
			{
				if (dev->Halting == false && dev->Adapter != NULL && dev->Adapter->Ready && dev->Adapter->Halt == false)
				{
					// Adapter device
					SL_FILE *f = SlZeroMalloc(sizeof(SL_FILE));
					NET_BUFFER_LIST_POOL_PARAMETERS p;

					f->Device = dev;
					f->Adapter = dev->Adapter;
					f->FileObject = irp_stack->FileObject;

					irp_stack->FileObject->FsContext = f;

					SlAdd(dev->FileList, f);

					ret = STATUS_SUCCESS;
					set_promisc = true;

					// Event
					f->Event = event_object;
					event_object = NULL;
					strcpy(f->EventNameWin32, event_name_win32);

					// Create a lock
					f->RecvLock = SlNewLock();

					// Create a NET_BUFFER_LIST pool
					SlZero(&p, sizeof(p));
					p.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
					p.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
					p.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
					p.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
					p.fAllocateNetBuffer = true;
					p.ContextSize = 32 + sizeof(UINT32) * 12;
					p.DataSize = SL_MAX_PACKET_SIZE;
					p.PoolTag = 'SETH';

					f->NetBufferListPool = NdisAllocateNetBufferListPool(NULL, &p);

					num_pending_oid_requests = &dev->Adapter->NumPendingOidRequests;
				}
			}
			SlUnlockList(dev->FileList);
		}
		SlUnlock(dev->OpenCloseLock);

		if (event_object != NULL)
		{
			SlFreeEvent(event_object);
		}

		if (set_promisc)
		{
			// Enable promiscuous mode
			UINT filter = NDIS_PACKET_TYPE_PROMISCUOUS;
			SlSendOidRequest(dev->Adapter, true, OID_GEN_CURRENT_PACKET_FILTER, &filter, sizeof(filter));

			// Wait until the number of OID requests being processed becomes 0
			while ((*num_pending_oid_requests) != 0)
			{
				SlSleep(50);
			}
		}
	}

	irp->IoStatus.Status = ret;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return ret;
}

// Send an OID request to the device
void SlSendOidRequest(SL_ADAPTER *a, bool set, NDIS_OID oid, void *data, UINT size)
{
	NDIS_OID_REQUEST *t;
	NDIS_STATUS ret;
	// Validate arguments
	if (a == NULL || data == NULL || size == 0)
	{
		return;
	}

	if (a->Halt == false)
	{
		bool ok = false;

		t = SlZeroMalloc(sizeof(NDIS_OID_REQUEST));

		t->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
		t->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
		t->Header.Size = NDIS_SIZEOF_OID_REQUEST_REVISION_1;

		if (set == false)
		{
			t->RequestType = NdisRequestQueryInformation;
			t->DATA.QUERY_INFORMATION.Oid = oid;
			t->DATA.QUERY_INFORMATION.InformationBuffer = data;
			t->DATA.QUERY_INFORMATION.InformationBufferLength = size;
		}
		else
		{
			t->RequestType = NdisRequestSetInformation;
			t->DATA.SET_INFORMATION.Oid = oid;
			t->DATA.SET_INFORMATION.InformationBuffer = SlClone(data, size);
			t->DATA.SET_INFORMATION.InformationBufferLength = size;
		}

		SlLock(a->Lock);
		{
			if (a->AdapterHandle != NULL && a->Halt == false)
			{
				InterlockedIncrement(&a->NumPendingOidRequests);
				ok = true;
			}
		}
		SlUnlock(a->Lock);

		if (ok)
		{
			ret = NdisOidRequest(a->AdapterHandle, t);

			if (ret != NDIS_STATUS_PENDING)
			{
				InterlockedDecrement(&a->NumPendingOidRequests);
				if (set)
				{
					SlFree(t->DATA.SET_INFORMATION.InformationBuffer);
				}
				SlFree(t);
			}
		}
		else
		{
			if (set)
			{
				SlFree(t->DATA.SET_INFORMATION.InformationBuffer);
			}
			SlFree(t);
		}
	}
}

// Device is closed
NTSTATUS SlDeviceCloseProc(DEVICE_OBJECT *device_object, IRP *irp)
{
	SL_DEVICE *dev = *((SL_DEVICE **)device_object->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;
	IO_STACK_LOCATION *irp_stack = IoGetCurrentIrpStackLocation(irp);

	if (dev->IsBasicDevice)
	{
		// Basic device
		ret = STATUS_SUCCESS;
	}
	else
	{
		// Adapter device
		SL_FILE *f = irp_stack->FileObject->FsContext;

		if (f != NULL)
		{
			bool clear_filter = false;

			// Wait until the number of packet being sent becomes the zero
			while (true)
			{
				if (f->NumSendingPacketets == 0)
				{
					break;
				}

				SlSleep(50);
			}

			SlLock(dev->OpenCloseLock);
			{
				// Delete the file from the list
				SlLockList(dev->FileList);
				{
					SlDelete(dev->FileList, f);

					if (SL_LIST_NUM(dev->FileList) == 0)
					{
						// Clear the filter when all files are closed
						clear_filter = true;
					}
				}
				SlUnlockList(dev->FileList);

				if (dev->Adapter->Halt)
				{
					clear_filter = false;
				}

				if (clear_filter)
				{
					InterlockedIncrement(&dev->Adapter->NumPendingOidRequests);
				}
			}
			SlUnlock(dev->OpenCloseLock);

			if (clear_filter)
			{
				// Clear the filter when all files are closed
				UINT filter = 0;
				SlSendOidRequest(dev->Adapter, true, OID_GEN_CURRENT_PACKET_FILTER, &filter, sizeof(filter));
				InterlockedDecrement(&dev->Adapter->NumPendingOidRequests);
			}

			// Release the event
			SlFreeEvent(f->Event);

			// Release the receive queue
			if (true)
			{
				SL_PACKET *p = f->RecvPacketHead;

				while (p != NULL)
				{
					SL_PACKET *p_next = p->Next;

					SlFree(p);

					p = p_next;
				}
			}

			// Release the NET_BUFFER_LIST pool
			NdisFreeNetBufferListPool(f->NetBufferListPool);

			// Release the lock
			SlFreeLock(f->RecvLock);

			SlFree(f);

			ret = STATUS_SUCCESS;
		}
	}

	irp->IoStatus.Status = ret;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return ret;
}

// Read procedure of the device
NTSTATUS SlDeviceReadProc(DEVICE_OBJECT *device_object, IRP *irp)
{
	SL_DEVICE *dev = *((SL_DEVICE **)device_object->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;
	UINT ret_size = 0;
	IO_STACK_LOCATION *irp_stack = IoGetCurrentIrpStackLocation(irp);

	if (dev->IsBasicDevice)
	{
		// Return the adapter list in the case of basic device
		if (irp_stack->Parameters.Read.Length >= sizeof(SL_ADAPTER_INFO_LIST))
		{
			SL_ADAPTER_INFO_LIST *dst = irp->UserBuffer;

			if (dst != NULL)
			{
				MDL *mdl;

				mdl = IoAllocateMdl(dst, irp_stack->Parameters.Read.Length, false, false, NULL);
				if (mdl != NULL)
				{
					MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
				}

				SlZero(dst, sizeof(SL_ADAPTER_INFO_LIST));

				dst->Signature = SL_SIGNATURE;
				dst->SeLowVersion = SL_VER;
				dst->EnumCompleted = sl->IsEnumCompleted ? 8 : 1;

				SlLockList(sl->AdapterList);
				{
					UINT i;

					dst->NumAdapters = MIN(SL_LIST_NUM(sl->AdapterList), SL_MAX_ADAPTER_INFO_LIST_ENTRY);

					for (i = 0;i < dst->NumAdapters;i++)
					{
						SL_ADAPTER *a = SL_LIST_DATA(sl->AdapterList, i);
						SL_ADAPTER_INFO *d = &dst->Adapters[i];

						d->MtuSize = a->MtuSize;
						SlCopy(d->MacAddress, a->MacAddress, 6);
						SlCopy(d->AdapterId, a->AdapterId, sizeof(a->AdapterId));
						strcpy(d->FriendlyName, a->FriendlyName);
						d->SupportsVLanHw = a->SupportVLan;
					}
				}
				SlUnlockList(sl->AdapterList);

				ret_size = sizeof(SL_ADAPTER_INFO);
				ret = STATUS_SUCCESS;

				if (mdl != NULL)
				{
					MmUnlockPages(mdl);
					IoFreeMdl(mdl);
				}
			}
		}
	}
	else
	{
		// Adapter device
		SL_FILE *f = irp_stack->FileObject->FsContext;

		if (irp_stack->Parameters.Read.Length == SL_EXCHANGE_BUFFER_SIZE)
		{
			UCHAR *buf = irp->UserBuffer;

			if (dev->Halting || f->Adapter->Halt || buf == NULL)
			{
				// Halting
			}
			else
			{
				UINT num = 0;
				bool left = true;
				MDL *mdl;
				
				mdl = IoAllocateMdl(buf, SL_EXCHANGE_BUFFER_SIZE, false, false, NULL);
				if (mdl != NULL)
				{
					MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
				}

				// Lock the receive queue
				SlLock(f->RecvLock);
				{
					while (true)
					{
						SL_PACKET *q;
						if (num >= SL_MAX_PACKET_EXCHANGE)
						{
							if (f->RecvPacketHead == NULL)
							{
								left = false;
							}
							break;
						}
						q = f->RecvPacketHead;
						if (q != NULL)
						{
							f->RecvPacketHead = f->RecvPacketHead->Next;
							q->Next = NULL;
							f->NumRecvPackets--;

							if (f->RecvPacketHead == NULL)
							{
								f->RecvPacketTail = NULL;
							}
						}
						else
						{
							left = false;
							break;
						}
						SL_SIZE_OF_PACKET(buf, num) = q->Size;
						SlCopy(SL_ADDR_OF_PACKET(buf, num), q->Data, q->Size);
						num++;
						SlFree(q);
					}
				}
				SlUnlock(f->RecvLock);

				if (mdl != NULL)
				{
					MmUnlockPages(mdl);
					IoFreeMdl(mdl);
				}

				SL_NUM_PACKET(buf) = num;
				SL_LEFT_FLAG(buf) = left;

				if (left == false)
				{
					SlReset(f->Event);
				}
				else
				{
					SlSet(f->Event);
				}

				ret = STATUS_SUCCESS;
				ret_size = SL_EXCHANGE_BUFFER_SIZE;
			}
		}
	}

	irp->IoStatus.Status = ret;
	irp->IoStatus.Information = ret_size;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return ret;
}

// Write procedure of the device
NTSTATUS SlDeviceWriteProc(DEVICE_OBJECT *device_object, IRP *irp)
{
	SL_DEVICE *dev = *((SL_DEVICE **)device_object->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;
	IO_STACK_LOCATION *irp_stack = IoGetCurrentIrpStackLocation(irp);
	UINT ret_size = 0;

	if (dev->IsBasicDevice == false)
	{
		// Adapter device
		SL_FILE *f = irp_stack->FileObject->FsContext;

		if (irp_stack->Parameters.Write.Length == SL_EXCHANGE_BUFFER_SIZE)
		{
			UCHAR *buf = irp->UserBuffer;

			if (dev->Halting || dev->Adapter->Halt || buf == NULL)
			{
				// Halting
			}
			else
			{
				// Write the packet
				MDL *mdl;
				UINT num = SL_NUM_PACKET(buf);

				mdl = IoAllocateMdl(buf, SL_EXCHANGE_BUFFER_SIZE, false, false, NULL);
				if (mdl != NULL)
				{
					MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
				}

				ret = true;
				ret_size = SL_EXCHANGE_BUFFER_SIZE;

				if (num >= 1 && num <= SL_MAX_PACKET_EXCHANGE)
				{
					UINT i, j;
					NET_BUFFER_LIST *nbl_head = NULL;
					NET_BUFFER_LIST *nbl_tail = NULL;
					UINT num_packets = 0;
					NDIS_HANDLE adapter_handle = NULL;

					SlLock(f->Adapter->Lock);

					if (f->Adapter->NumPendingSendPackets <= SL_MAX_PACKET_QUEUED)
					{
						// Admit to send only if the number of packets being transmitted does not exceed the specified limit
						adapter_handle = f->Adapter->AdapterHandle;
					}

					if (adapter_handle != NULL)
					{
						// Lock the file list which opens the same adapter
						SlLockList(dev->FileList);
						for (j = 0;j < SL_LIST_NUM(dev->FileList);j++)
						{
							SL_FILE *other = SL_LIST_DATA(dev->FileList, j);

							if (other != f)
							{
								// Lock the receive queue of other file lists
								SlLock(other->RecvLock);

								other->SetEventFlag = false;
							}
						}

						for (i = 0;i < num;i++)
						{
							UINT packet_size = SL_SIZE_OF_PACKET(buf, i);
							UCHAR *packet_buf;
							NET_BUFFER_LIST *nbl = NULL;
							bool ok = false;
							bool is_vlan = false;
							UINT vlan_id = 0;
							UINT vlan_user_priority = 0, vlan_can_format_id = 0;

							if (packet_size > SL_MAX_PACKET_SIZE)
							{
								packet_size = SL_MAX_PACKET_SIZE;
							}
							else if (packet_size < SL_PACKET_HEADER_SIZE)
							{
								packet_size = SL_PACKET_HEADER_SIZE;
							}

							packet_buf = (UCHAR *)SL_ADDR_OF_PACKET(buf, i);

							for (j = 0;j < SL_LIST_NUM(dev->FileList);j++)
							{
								SL_FILE *other = SL_LIST_DATA(dev->FileList, j);

								if (other != f)
								{
									// Insert into the receive queue of the other file lists
									if (other->NumRecvPackets < SL_MAX_PACKET_QUEUED)
									{
										SL_PACKET *q = SlMalloc(sizeof(SL_PACKET));

										SlCopy(q->Data, packet_buf, packet_size);
										q->Size = packet_size;
										q->Next = NULL;

										if (other->RecvPacketHead == NULL)
										{
											other->RecvPacketHead = q;
										}
										else
										{
											other->RecvPacketTail->Next = q;
										}

										other->RecvPacketTail = q;

										other->NumRecvPackets++;

										other->SetEventFlag = true;
									}
								}
							}

							// Allocate a new NET_BUFFER_LIST
							if (f->NetBufferListPool != NULL)
							{
								nbl = NdisAllocateNetBufferList(f->NetBufferListPool, 16, 0);

								if (nbl != NULL)
								{
									nbl->SourceHandle = adapter_handle;
								}
							}

							if (nbl != NULL)
							{
								// Get the NET_BUFFER from the NET_BUFFER_LIST
								NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(nbl);

								NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

								// Determine if the packet is IEEE802.1Q tagged packet
								if (dev->Adapter->SupportVLan && packet_size >= 18)
								{
									if (packet_buf[12] == 0x81 && packet_buf[13] == 0x00)
									{
										USHORT tag_us = 0;

										((UCHAR *)(&tag_us))[0] = packet_buf[15];
										((UCHAR *)(&tag_us))[1] = packet_buf[14];

										vlan_id = tag_us & 0x0FFF;
										vlan_user_priority = (tag_us >> 13) & 0x07;
										vlan_can_format_id = (tag_us >> 12) & 0x01;

										if (vlan_id != 0)
										{
											is_vlan = true;
										}
									}
								}

								if (is_vlan)
								{
									packet_size -= 4;
								}

								if (nb != NULL && OK(NdisRetreatNetBufferDataStart(nb, packet_size, 0, NULL)))
								{
									// Buffer copy
									UCHAR *dst = NdisGetDataBuffer(nb, packet_size, NULL, 1, 0);

									if (dst != NULL)
									{
										if (is_vlan == false)
										{
											SlCopy(dst, packet_buf, packet_size);
										}
										else
										{
											SlCopy(dst, packet_buf, 12);
											SlCopy(dst + 12, packet_buf + 16, packet_size + 4 - 16);
										}

										ok = true;
									}
									else
									{
										NdisAdvanceNetBufferDataStart(nb, packet_size, false, NULL);
									}
								}
							}

							if (ok == false)
							{
								if (nbl != NULL)
								{
									NdisFreeNetBufferList(nbl);
								}
							}
							else
							{
								if (nbl_head == NULL)
								{
									nbl_head = nbl;
								}

								if (nbl_tail != NULL)
								{
									NET_BUFFER_LIST_NEXT_NBL(nbl_tail) = nbl;
								}

								nbl_tail = nbl;

								((void **)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl))[0] = f;

								if (is_vlan == false)
								{
									NET_BUFFER_LIST_INFO(nbl, Ieee8021QNetBufferListInfo) = NULL;
								}
								else
								{
									NDIS_NET_BUFFER_LIST_8021Q_INFO qinfo;

									qinfo.Value = &(((void **)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl))[1]);
									SlZero(qinfo.Value, sizeof(UINT32) * 12);

									qinfo.TagHeader.VlanId = vlan_id;
									qinfo.TagHeader.UserPriority = vlan_user_priority;
									qinfo.TagHeader.CanonicalFormatId = vlan_can_format_id;

									NET_BUFFER_LIST_INFO(nbl, Ieee8021QNetBufferListInfo) = qinfo.Value;
								}

								num_packets++;
							}
						}

						for (j = 0;j < SL_LIST_NUM(dev->FileList);j++)
						{
							SL_FILE *other = SL_LIST_DATA(dev->FileList, j);

							if (other != f)
							{
								// Release the receive queue of other file lists
								SlUnlock(other->RecvLock);

								// Set an event
								if (other->SetEventFlag)
								{
									SlSet(other->Event);
								}
							}
						}
						SlUnlockList(dev->FileList);

						if (nbl_head != NULL)
						{
							InterlockedExchangeAdd(&f->NumSendingPacketets, num_packets);
							InterlockedExchangeAdd(&f->Adapter->NumPendingSendPackets, num_packets);

							SlUnlock(f->Adapter->Lock);

							NdisSendNetBufferLists(adapter_handle, nbl_head, 0, 0);
						}
						else
						{
							SlUnlock(f->Adapter->Lock);
						}
					}
					else
					{
						SlUnlock(f->Adapter->Lock);
					}
				}

				if (mdl != NULL)
				{
					MmUnlockPages(mdl);
					IoFreeMdl(mdl);
				}
			}
		}
	}

	irp->IoStatus.Information = ret_size;
	irp->IoStatus.Status = ret;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return ret;
}

// IOCTL procedure of the device
NTSTATUS SlDeviceIoControlProc(DEVICE_OBJECT *device_object, IRP *irp)
{
	SL_DEVICE *dev = *((SL_DEVICE **)device_object->DeviceExtension);
	NTSTATUS ret = STATUS_UNSUCCESSFUL;
	IO_STACK_LOCATION *irp_stack = IoGetCurrentIrpStackLocation(irp);
	UINT ret_size = 0;

	if (dev->IsBasicDevice == false)
	{
		// Adapter device
		SL_FILE *f = irp_stack->FileObject->FsContext;

		switch (irp_stack->Parameters.DeviceIoControl.IoControlCode)
		{
		case SL_IOCTL_GET_EVENT_NAME:
			if (irp_stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(SL_IOCTL_EVENT_NAME))
			{
				SL_IOCTL_EVENT_NAME *t = irp->UserBuffer;

				if (t != NULL)
				{
					strcpy(t->EventNameWin32, f->EventNameWin32);

					ret_size = sizeof(SL_IOCTL_EVENT_NAME);

					ret = STATUS_SUCCESS;
				}
			}
			break;
		}
	}

	irp->IoStatus.Status = ret;
	irp->IoStatus.Information = ret_size;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return ret;
}

// NDIS bind notification procedure
NDIS_STATUS SlNdisBindAdapterExProc(NDIS_HANDLE protocol_driver_context, NDIS_HANDLE bind_context, NDIS_BIND_PARAMETERS *bind_parameters)
{
	NDIS_STATUS ret = NDIS_STATUS_FAILURE;

	InterlockedIncrement(&sl->NumBoundAdapters);

	// Check the attributes of the adapter, and process only adapter which should be bound to
	if (bind_parameters->MediaType == NdisMedium802_3 &&
		bind_parameters->MacAddressLength == 6 &&
//		(bind_parameters->PhysicalMediumType == NdisPhysicalMedium802_3 || bind_parameters->PhysicalMediumType == 0) &&
		bind_parameters->AccessType == NET_IF_ACCESS_BROADCAST &&
		bind_parameters->DirectionType == NET_IF_DIRECTION_SENDRECEIVE &&
		bind_parameters->ConnectionType == NET_IF_CONNECTION_DEDICATED)
	{
		// Open the adapter
		NDIS_OPEN_PARAMETERS t;
		NDIS_MEDIUM medium_array = {NdisMedium802_3};
		SL_ADAPTER *a;
		wchar_t adapter_id_tag[] = SL_ADAPTER_ID_PREFIX_W;

		SlZero(&t, sizeof(t));
		t.Header.Type = NDIS_OBJECT_TYPE_OPEN_PARAMETERS;
		t.Header.Revision = NDIS_OPEN_PARAMETERS_REVISION_1;
		t.Header.Size = NDIS_SIZEOF_OPEN_PARAMETERS_REVSION_1;

		t.AdapterName = bind_parameters->AdapterName;
		t.MediumArray = &medium_array;
		t.MediumArraySize = 1;
		t.SelectedMediumIndex = &sl->DummyInt;
		t.FrameTypeArray = NULL;
		t.FrameTypeArraySize = 0;

		a = SlZeroMalloc(sizeof(SL_ADAPTER));

		a->Lock = SlNewLock();
		a->AdapterName = SlNewUnicodeFromUnicodeString(bind_parameters->AdapterName);

/*
		if (bind_parameters->MacOptions & NDIS_MAC_OPTION_8021Q_VLAN)
		{
			a->SupportVLan = true;
		}

		if (bind_parameters->TcpConnectionOffloadCapabilities != NULL)
		{
			if (bind_parameters->TcpConnectionOffloadCapabilities->Encapsulation & NDIS_ENCAPSULATION_IEEE_802_3_P_AND_Q ||
				bind_parameters->TcpConnectionOffloadCapabilities->Encapsulation & NDIS_ENCAPSULATION_IEEE_802_3_P_AND_Q_IN_OOB)
			{
				a->SupportVLan = true;
			}
		}
*/

		SlCopy(a->AdapterId, a->AdapterName->String.Buffer, MIN(sizeof(a->AdapterId) - sizeof(wchar_t), a->AdapterName->String.Length));
		SlCopy(a->AdapterId, adapter_id_tag, sizeof(adapter_id_tag) - sizeof(wchar_t));

		SlCopy(a->MacAddress, bind_parameters->CurrentMacAddress, 6);
		SlCopy(&a->BindParamCopy, bind_parameters, sizeof(NDIS_BIND_PARAMETERS));
		a->BindingContext = bind_context;
		a->MtuSize = bind_parameters->MtuSize;

		a->IsOpenPending = true;

		ret = NdisOpenAdapterEx(sl->ProtocolHandle, a, &t, bind_context, &a->AdapterHandle);
		a->AdapterHandle2 = a->AdapterHandle;

		if (ret != NDIS_STATUS_PENDING)
		{
			a->IsOpenPending = false;
			SlNdisOpenAdapterCompleteExProc(a, ret);
		}
	}

	if (ret != NDIS_STATUS_PENDING)
	{
		if (ret != NDIS_STATUS_SUCCESS)
		{
			InterlockedDecrement(&sl->NumBoundAdapters);
		}
	}

	return ret;
}

// Open success notification procedure of NDIS adapter
void SlNdisOpenAdapterCompleteExProc(NDIS_HANDLE protocol_binding_context, NDIS_STATUS status)
{
	SL_ADAPTER *a = (SL_ADAPTER *)protocol_binding_context;
	bool is_pending = a->IsOpenPending;
	NDIS_HANDLE binding_context = a->BindingContext;

	if (OK(status))
	{
		// Create an adapter device
		SL_UNICODE *device_name = SlNewUnicode(SL_ADAPTER_DEVICE_NAME);
		SL_UNICODE *symbolic_name = SlNewUnicode(SL_ADAPTER_DEVICE_NAME_SYMBOLIC);
		SL_DEVICE *dev;

		// Create a device name
		SlCopy(device_name->String.Buffer + 8, a->AdapterId, sizeof(wchar_t) * 46);
		SlCopy(symbolic_name->String.Buffer + 19, a->AdapterId, sizeof(wchar_t) * 46);

		dev = SlNewDeviceUnicode(device_name, symbolic_name);

		if (dev == NULL)
		{
			// Device creation failed
			SlFreeUnicode(device_name);
			SlFreeUnicode(symbolic_name);
		}
		else
		{
			// Create a file list
			dev->FileList = SlNewList();
		}
		if (dev != NULL)
		{
			// Get the display name
			SlSendOidRequest(a, false, OID_GEN_VENDOR_DESCRIPTION, a->FriendlyName,
				sizeof(a->FriendlyName) - 1);

			dev->Adapter = a;
			a->Device = dev;

			// Add this adapter to the adapter list
			SlLockList(sl->AdapterList);
			{
				SlAdd(sl->AdapterList, a);
			}
			SlUnlockList(sl->AdapterList);
		}
	}
	else
	{
		// Discard the adapter handle
		a->AdapterHandle = NULL;

		// Release the SL_ADAPTER
		SlFreeAdapter(a);

		a = NULL;
	}

	if (is_pending)
	{
		NdisCompleteBindAdapterEx(binding_context, status);
	}

	if (a != NULL)
	{
		a->Ready = true;
	}

	if (is_pending)
	{
		if (NG(status))
		{
			InterlockedDecrement(&sl->NumBoundAdapters);
		}
	}
}

// Release the SL_ADAPTER
void SlFreeAdapter(SL_ADAPTER *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	SlFreeUnicode(a->AdapterName);

	SlFreeLock(a->Lock);

	SlFree(a);
}

// NDIS unbind notification procedure
NDIS_STATUS SlNdisUnbindAdapterExProc(NDIS_HANDLE unbind_context, NDIS_HANDLE protocol_binding_context)
{
	NDIS_STATUS ret;
	SL_ADAPTER *a = (SL_ADAPTER *)protocol_binding_context;
	UINT j;
	NDIS_HANDLE adapter_handle = NULL;

	if (a->Halt)
	{
		//SL_WHERE;
	}

	adapter_handle = a->AdapterHandle;
	a->Halt = true;
	if (a->Device != NULL)
	{
		a->Device->Halting = true;
	}
	a->AdapterHandle = NULL;

	SlLock(a->Lock);
	{
	}
	SlUnlock(a->Lock);

	a->UnbindContext = unbind_context;
	a->IsClosePending = true;

	// Delete the adapter from the adapter list
	SlLockList(sl->AdapterList);
	{
		SlDelete(sl->AdapterList, a);
	}
	SlUnlockList(sl->AdapterList);

	for (j = 0;j < 32;j++)
	{
		// Wait until the number of OID requests of being processed by this adapter becomes zero
		while (true)
		{
			UINT num;

			num = a->NumPendingOidRequests;

			if (num == 0)
			{
				break;
			}
			else
			{
				j = 0;
			}

			//SlSleep(50);
		}

		// Wait until the number of packets this adapter is transmitting becomes zero
		while (true)
		{
			UINT num;

			num = a->NumPendingSendPackets;

			if (num == 0)
			{
				break;
			}
			else
			{
				j = 0;
			}

			//SlSleep(50);
		}

	}

	ret = NdisCloseAdapterEx(adapter_handle);

	if (ret != NDIS_STATUS_PENDING)
	{
		a->IsClosePending = false;
		SlNdisCloseAdapterCompleteExProc(a);

		ret = NDIS_STATUS_SUCCESS;

		InterlockedDecrement(&sl->NumBoundAdapters);
	}

	return ret;
}

// Close success notification procedure of NDIS adapter
void SlNdisCloseAdapterCompleteExProc(NDIS_HANDLE protocol_binding_context)
{
	SL_ADAPTER *a = (SL_ADAPTER *)protocol_binding_context;
	NDIS_HANDLE unbind_context = a->UnbindContext;
	bool is_pending = a->IsClosePending;
	UINT j;

	if (is_pending)
	{
		NdisCompleteUnbindAdapterEx(unbind_context);
	}

	for (j = 0;j < 32;j++)
	{
		if (a->Device != NULL)
		{
			a->Device->Halting = true;

			// Wait until the number of file handles that are associated with this device becomes zero
			while (true)
			{
				UINT num_files = 0;

				SlLock(a->Device->OpenCloseLock);
				{
					SlLockList(a->Device->FileList);
					{
						UINT i;
						num_files = SL_LIST_NUM(a->Device->FileList);

						for (i = 0;i < num_files;i++)
						{
							// Hit the associated event
							SL_FILE *f = SL_LIST_DATA(a->Device->FileList, i);

							if (f->FinalWakeUp == false)
							{
								SlSet(f->Event);
								f->FinalWakeUp = true;
							}
						}
					}
					SlUnlockList(a->Device->FileList);
				}
				SlUnlock(a->Device->OpenCloseLock);

				if (num_files == 0)
				{
					break;
				}

				SlSleep(50);
			}
		}
	}

	// Release the device
	if (a->Device != NULL)
	{
		// Delete the file list
		SlFreeList(a->Device->FileList);

		SlFreeDevice(a->Device);
		a->Device = NULL;
	}

	// Release the SL_ADAPTER
	SlFreeAdapter(a);

	if (is_pending)
	{
		InterlockedDecrement(&sl->NumBoundAdapters);
	}
}

// NDIS PnP notification procedure
NDIS_STATUS SlNdisNetPnPEventProc(NDIS_HANDLE protocol_binding_context, NET_PNP_EVENT_NOTIFICATION *net_pnp_event)
{
	SL_ADAPTER *a = (SL_ADAPTER *)protocol_binding_context;

	if (net_pnp_event != NULL)
	{
		if (net_pnp_event->NetPnPEvent.NetEvent == NetEventBindsComplete)
		{
			sl->IsEnumCompleted = true;
		}
	}

	return NDIS_STATUS_SUCCESS;
}

// NDIS uninstall procedure
void SlNdisUninstallProc(void)
{
}

// NDIS OID request completion notification procedure
void SlNdisOidRequestCompleteProc(NDIS_HANDLE protocol_binding_context, NDIS_OID_REQUEST *oid_request, NDIS_STATUS status)
{
	SL_ADAPTER *a = (SL_ADAPTER *)protocol_binding_context;
	bool no_not_free = false;

	// Check the results
	if (oid_request->RequestType == NdisRequestQueryInformation)
	{
		if (oid_request->DATA.QUERY_INFORMATION.Oid == OID_GEN_VENDOR_DESCRIPTION)
		{
			no_not_free = true;
		}
	}

	// Release the memory
	if (no_not_free == false)
	{
		SlFree(oid_request->DATA.SET_INFORMATION.InformationBuffer);
	}

	SlFree(oid_request);

	// Counter subtraction
	InterlockedDecrement(&a->NumPendingOidRequests);
}

// NDIS status notification procedure
void SlNdisStatusExProc(NDIS_HANDLE protocol_binding_context, NDIS_STATUS_INDICATION *status_indication)
{
	SL_ADAPTER *a = (SL_ADAPTER *)protocol_binding_context;
}

// NDIS packet reception notification procedure
void SlNdisReceiveNetBufferListsProc(NDIS_HANDLE protocol_binding_context, NET_BUFFER_LIST *net_buffer_lists,
									 NDIS_PORT_NUMBER port_number, ULONG NumberOfNetBufferLists,
									 ULONG receive_flags)
{
	SL_ADAPTER *a = (SL_ADAPTER *)protocol_binding_context;
	UINT i;
	UINT return_flags = 0;
	NET_BUFFER_LIST *nbl;
	UCHAR *tmp_buffer;
	UINT tmp_size;

	if (net_buffer_lists == NULL || NumberOfNetBufferLists == 0)
	{
		return;
	}

	if (a->AdapterHandle2 == NULL)
	{
		a->AdapterHandle2 = a->AdapterHandle;
	}

	if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(receive_flags))
	{
		NDIS_SET_RETURN_FLAG(return_flags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
	}

	if (a->Halt || a->Device == NULL || a->Device->Halting || a->Ready == false || a->AdapterHandle == NULL)
	{
		goto LABEL_CLEANUP;
	}

	tmp_buffer = a->TmpBuffer;
	tmp_size = sizeof(a->TmpBuffer);

	nbl = net_buffer_lists;

	SlLockList(a->Device->FileList);
	{
		if (a->Halt == false)
		{
			for (i = 0;i < SL_LIST_NUM(a->Device->FileList);i++)
			{
				// Lock the receive queue
				SL_FILE *f = SL_LIST_DATA(a->Device->FileList, i);

				SlLock(f->RecvLock);
			}

			while (nbl != NULL)
			{
				NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(nbl);
				bool is_vlan = false;
				UCHAR vlan_tag[2];

				if (NET_BUFFER_LIST_INFO(nbl, Ieee8021QNetBufferListInfo) != 0)
				{
					NDIS_NET_BUFFER_LIST_8021Q_INFO qinfo;
					qinfo.Value = NET_BUFFER_LIST_INFO(nbl, Ieee8021QNetBufferListInfo);
					if (qinfo.TagHeader.VlanId != 0)
					{
						USHORT tag_us;
						is_vlan = true;

						a->SupportVLan = true;

						tag_us = (qinfo.TagHeader.UserPriority & 0x07 << 13) |
							(qinfo.TagHeader.CanonicalFormatId & 0x01 << 12) |
							(qinfo.TagHeader.VlanId & 0x0FFF);

						vlan_tag[0] = ((UCHAR *)(&tag_us))[1];
						vlan_tag[1] = ((UCHAR *)(&tag_us))[0];
					}
				}

				while (nb != NULL)
				{
					UINT size = NET_BUFFER_DATA_LENGTH(nb);

					if (size >= 14 && size <= tmp_size && size <= (UINT)((is_vlan == false) ? SL_MAX_PACKET_SIZE : (SL_MAX_PACKET_SIZE - 4)))
					{
						UCHAR *ptr = NdisGetDataBuffer(nb, size, tmp_buffer, 1, 0);

						if (ptr != NULL)
						{
							// Insert the queue to all waiting files
							for (i = 0;i < SL_LIST_NUM(a->Device->FileList);i++)
							{
								SL_FILE *f = SL_LIST_DATA(a->Device->FileList, i);

								if (f->NumRecvPackets < SL_MAX_PACKET_QUEUED)
								{
									SL_PACKET *q = SlMalloc(sizeof(SL_PACKET));

									if (is_vlan == false)
									{
										// Normal packet
										SlCopy(q->Data, ptr, size);
										q->Size = size;
									}
									else
									{
										// Insert a tag in the case of IEEE802.1Q packet
										SlCopy(q->Data, ptr, 12);
										q->Data[12] = 0x81;
										q->Data[13] = 0x00;
										SlCopy(&q->Data[14], vlan_tag, 2);
										SlCopy(&q->Data[16], &ptr[12], size - 12);

										q->Size = size + 4;
									}

									q->Next = NULL;

									if (f->RecvPacketHead == NULL)
									{
										f->RecvPacketHead = q;
									}
									else
									{
										f->RecvPacketTail->Next = q;
									}

									f->RecvPacketTail = q;

									f->NumRecvPackets++;
								}
							}
						}
					}

					nb = NET_BUFFER_NEXT_NB(nb);
				}

				nbl = NET_BUFFER_LIST_NEXT_NBL(nbl);
			}

			// Hit the event
			for (i = 0;i < SL_LIST_NUM(a->Device->FileList);i++)
			{
				SL_FILE *f = SL_LIST_DATA(a->Device->FileList, i);

				// Unlock the receive queue
				SlUnlock(f->RecvLock);

				SlSet(f->Event);
			}
		}
	}
	SlUnlockList(a->Device->FileList);

LABEL_CLEANUP:

	if (NDIS_TEST_RECEIVE_CAN_PEND(receive_flags))
	{
		NdisReturnNetBufferLists(a->AdapterHandle2, net_buffer_lists, return_flags);
	}
}

// NDIS packet transmission completion notification procedure
void SlNdisSendNetBufferListsCompleteProc(NDIS_HANDLE protocol_binding_context, NET_BUFFER_LIST *net_buffer_lists,
										  ULONG send_complete_flags)
{
	NET_BUFFER_LIST *nbl;

	nbl = net_buffer_lists;

	while (nbl != NULL)
	{
		NET_BUFFER_LIST *current_nbl = nbl;
		SL_FILE *f;
		NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(nbl);

		if (nb != NULL)
		{
			UINT size = NET_BUFFER_DATA_LENGTH(nb);

			NdisAdvanceNetBufferDataStart(nb, size, false, NULL);
		}

		// Get a file context
		f = ((void **)NET_BUFFER_LIST_CONTEXT_DATA_START(nbl))[0];

		nbl = NET_BUFFER_LIST_NEXT_NBL(nbl);
		NET_BUFFER_LIST_NEXT_NBL(current_nbl) = NULL;

		// Release the NET_BUFFER_LIST
		NdisFreeNetBufferList(current_nbl);

		// Reduce the number of packets being sent by 1
		InterlockedExchangeAdd(&f->NumSendingPacketets, (LONG)-1);
		InterlockedExchangeAdd(&f->Adapter->NumPendingSendPackets, (LONG)-1);
	}
}

// Crash
void SlCrash(UINT a, UINT b, UINT c, UINT d)
{
	KeBugCheckEx(0x00000061, (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, (ULONG_PTR)d);
}

// Memory allocation
void *SlMalloc(UINT size)
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

// Clear to zero by allocating the memory
void *SlZeroMalloc(UINT size)
{
	void *p = SlMalloc(size);
	if (p == NULL)
	{
		// Memory allocation failure
		return NULL;
	}

	// Clear to zero
	SlZero(p, size);

	return p;
}

// Release the memory
void SlFree(void *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	// Release the memory
	NdisFreeMemory(p, 0, 0);
}

// Memory zero clear
void SlZero(void *dst, UINT size)
{
	// Validate arguments
	if (dst == NULL || size == 0)
	{
		return;
	}

	// Clear
	NdisZeroMemory(dst, size);
}

// Copy memory
void SlCopy(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || src == NULL || size == 0)
	{
		return;
	}

	// Copy
	NdisMoveMemory(dst, src, size);
}

// Create a lock
SL_LOCK *SlNewLock()
{
	NDIS_SPIN_LOCK *spin_lock;

	// Memory allocation
	SL_LOCK *lock = SlZeroMalloc(sizeof(SL_LOCK));
	if (lock == NULL)
	{
		return NULL;
	}

	// Initialize spin lock
	spin_lock = &lock->spin_lock;

	NdisAllocateSpinLock(spin_lock);

	return lock;
}

// Lock
void SlLock(SL_LOCK *lock)
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

// Unlock
void SlUnlock(SL_LOCK *lock)
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

// Release the lock
void SlFreeLock(SL_LOCK *lock)
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
	SlFree(lock);
}

// Create an event
SL_EVENT *SlNewEvent(char *name)
{
	SL_UNICODE *unicode_name;
	SL_EVENT *event;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	// Convert to Unicode name
	unicode_name = SlNewUnicode(name);
	if (unicode_name == NULL)
	{
		return NULL;
	}

	// Memory allocation
	event = SlZeroMalloc(sizeof(SL_EVENT));
	if (event == NULL)
	{
		SlFreeUnicode(unicode_name);
		return NULL;
	}

	// Create an event
	event->event = IoCreateNotificationEvent(SlGetUnicode(unicode_name), &event->event_handle);
	if (event->event == NULL)
	{
		SlFree(event);
		SlFreeUnicode(unicode_name);
		return NULL;
	}

	// Initialize the event
	KeInitializeEvent(event->event, NotificationEvent, FALSE);
	KeClearEvent(event->event);

	// Release the string
	SlFreeUnicode(unicode_name);

	return event;
}

// Release the event
void SlFreeEvent(SL_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

	ZwClose(event->event_handle);

	// Release the memory
	SlFree(event);
}

// Set the event
void SlSet(SL_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

	KeSetEvent(event->event, 0, FALSE);
}

// Reset the event
void SlReset(SL_EVENT *event)
{
	// Validate arguments
	if (event == NULL)
	{
		return;
	}

	KeResetEvent(event->event);
}

// Create by copying the Unicode
SL_UNICODE *SlNewUnicodeFromUnicodeString(UNICODE_STRING *src)
{
	SL_UNICODE *u;
	// Validate arguments
	if (src == NULL)
	{
		return NULL;
	}

	// Memory allocation
	u = SlZeroMalloc(sizeof(SL_UNICODE));
	if (u == NULL)
	{
		return NULL;
	}

	u->String.Length = u->String.MaximumLength = src->Length;
	
	u->String.Buffer = SlZeroMalloc(src->Length);
	SlCopy(u->String.Buffer, src->Buffer, src->Length);

	return u;
}

// Create a Unicode
SL_UNICODE *SlNewUnicode(char *str)
{
	SL_UNICODE *u;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	// Memory allocation
	u = SlZeroMalloc(sizeof(SL_UNICODE));
	if (u == NULL)
	{
		return NULL;
	}

	// String initialization
	NdisInitializeString(&u->String, str);

	return u;
}

// Release the Unicode
void SlFreeUnicode(SL_UNICODE *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return;
	}

	// Release the string
	NdisFreeString(u->String);

	// Release the memory
	SlFree(u);
}

// Get an Unicode
NDIS_STRING *SlGetUnicode(SL_UNICODE *u)
{
	// Validate arguments
	if (u == NULL)
	{
		return NULL;
	}

	return &u->String;
}

// Create a list
SL_LIST *SlNewList()
{
	SL_LIST *o;

	o = (SL_LIST *)SlZeroMalloc(sizeof(SL_LIST));

	o->lock = SlNewLock();

	o->num_item = 0;
	o->num_reserved = SL_INIT_NUM_RESERVED;

	o->p = (void **)SlZeroMalloc(sizeof(void *) * o->num_reserved);

	return o;
}

// Add an element to the list
void SlAdd(SL_LIST *o, void *p)
{
	UINT i;
	// Validate arguments
	if (o == NULL || p == NULL)
	{
		return;
	}

	i = o->num_item;
	o->num_item++;

	if (o->num_item > o->num_reserved)
	{
		UINT old_num_reserved = o->num_reserved;
		void *p_old = o->p;

		o->num_reserved = o->num_reserved * 2;

		o->p = SlZeroMalloc(sizeof(void *) * o->num_reserved);
		SlCopy(o->p, p_old, sizeof(void *) * old_num_reserved);
		SlFree(p_old);
	}

	o->p[i] = p;
}

// Delete the element from the list
bool SlDelete(SL_LIST *o, void *p)
{
	UINT i, n;
	// Validate arguments
	if (o == NULL || p == NULL)
	{
		return false;
	}

	for (i = 0;i < o->num_item;i++)
	{
		if (o->p[i] == p)
		{
			break;
		}
	}
	if (i == o->num_item)
	{
		return false;
	}

	n = i;
	for (i = n;i < (o->num_item - 1);i++)
	{
		o->p[i] = o->p[i + 1];
	}
	o->num_item--;

	return true;
}

// Delete all elements from the list
void SlDeleteAll(SL_LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	o->num_item = 0;
}

// Lock the list
void SlLockList(SL_LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	SlLock(o->lock);
}

// Unlock the list
void SlUnlockList(SL_LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	SlUnlock(o->lock);
}

// Release the list
void SlFreeList(SL_LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	SlFree(o->p);
	SlFreeLock(o->lock);

	SlFree(o);
}

// Clone the memory
void *SlClone(void *p, UINT size)
{
	void *ret;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	ret = SlMalloc(size);
	SlCopy(ret, p, size);

	return ret;
}


// Sleep
void SlSleep(int milliSeconds)
{
	PKTIMER timer = SlMalloc(sizeof(KTIMER));
	LARGE_INTEGER duetime;

	duetime.QuadPart = (__int64)milliSeconds * -10000;
	KeInitializeTimerEx(timer, NotificationTimer);
	KeSetTimerEx(timer, duetime, 0, NULL);

	KeWaitForSingleObject(timer, Executive, KernelMode, FALSE, NULL);

	SlFree(timer);
}




// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
