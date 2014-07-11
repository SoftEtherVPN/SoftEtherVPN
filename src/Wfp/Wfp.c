// SoftEther VPN Source Code
// Windows Filtering Platform Callout Driver for Capturing IPsec Packets on Windows Vista / 7 / Server 2008
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


// Wfp.c
// WFP Callout Driver

#include <GlobalConst.h>

#define	WFP_DEVICE_DRIVER

#include "WfpInner.h"
#include "Wfp.h"

static WFP_CTX *wfp = NULL;

// Dispatch function
NTSTATUS DriverDispatch(DEVICE_OBJECT *device_object, IRP *irp)
{
	NTSTATUS ret = STATUS_SUCCESS;
	IO_STACK_LOCATION *stack;
	void *buf;
	bool ok;
	// Validate arguments
	if (wfp == NULL || device_object == NULL || irp == NULL || wfp->Halting)
	{
		return NDIS_STATUS_FAILURE;
	}

	// Get the IRP stack
	stack = IoGetCurrentIrpStackLocation(irp);

	// Initialize the number of bytes
	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = STATUS_SUCCESS;

	buf = irp->UserBuffer;

	if (wfp->Halting != FALSE)
	{
		// Device driver is terminating
		irp->IoStatus.Information = STATUS_UNSUCCESSFUL;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_UNSUCCESSFUL;
	}

	ok = false;

	// Branch to each operation
	switch (stack->MajorFunction)
	{
	case IRP_MJ_CREATE:	// Open
		ok = true;
		break;

	case IRP_MJ_CLOSE:	// Close
		ok = true;
		break;

	case IRP_MJ_READ:	// Read
		ResetEvent(wfp->Event);
		break;

	case IRP_MJ_WRITE:	// Write
		if ((stack->Parameters.Write.Length % sizeof(WFP_LOCAL_IP)) == 0)
		{
			UINT size = MIN(WFP_MAX_LOCAL_IP_COUNT * sizeof(WFP_LOCAL_IP), stack->Parameters.Write.Length);
			UCHAR *copied_buf = Malloc(size);
			UCHAR *old_buf;
			Copy(copied_buf, buf, size);

			SpinLock(wfp->LocalIPListLock);
			{
				old_buf = wfp->LocalIPListData;
				wfp->LocalIPListData = copied_buf;
				wfp->LocalIPListSize = size;
			}
			SpinUnlock(wfp->LocalIPListLock);

			if (old_buf != NULL)
			{
				Free(old_buf);
			}
		}
		irp->IoStatus.Information = stack->Parameters.Write.Length;
		ok = true;
		break;
	}

	if (ok == false)
	{
		irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		ret = STATUS_UNSUCCESSFUL;
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return ret;
}

// Function to finish the insertion of the packet
void NTAPI CalloutInjectionCompleted(void *context, NET_BUFFER_LIST *net_buffer_list, BOOLEAN dispatch_level)
{
	WFP_INJECTED_PACKET_CONTEXT *ctx = (WFP_INJECTED_PACKET_CONTEXT *)context;

	if (ctx == NULL)
	{
		return;
	}

	FreeInjectionCtx(ctx);
}

// Release the injection data
void FreeInjectionCtx(WFP_INJECTED_PACKET_CONTEXT *ctx)
{
	// Validate arguments
	if (ctx == NULL)
	{
		return;
	}

	if (ctx->CurrentNetBuffer != NULL)
	{
		Copy(ctx->CurrentNetBuffer, &ctx->OriginalNetBufferData, sizeof(NET_BUFFER));
	}

	if (ctx->AllocatedNetBufferList != NULL)
	{
		FwpsFreeCloneNetBufferList0(ctx->AllocatedNetBufferList, 0);
	}

	if (ctx->AllocatedMdl != NULL)
	{
		NdisFreeMdl(ctx->AllocatedMdl);
	}

	if (ctx->AllocatedMemory != NULL)
	{
		Free(ctx->AllocatedMemory);
	}

	Free(ctx);
}

// Calculate the checksum
USHORT IpChecksum(void *buf, UINT size)
{
	int sum = 0;
	USHORT *addr = (USHORT *)buf;
	int len = (int)size;
	USHORT *w = addr;
	int nleft = len;
	USHORT answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(UCHAR *)(&answer) = *(UCHAR *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	answer = ~sum;

	return answer;
}

// Modify the IPsec ESP packet
UCHAR *ModificationOfIPsecESPPacket(UCHAR *ip_packet, UINT ip_packet_size, UINT ip_header_size, UINT *dst_size_ptr, bool isv6)
{
	UINT ip_and_udp_header_size = ip_header_size + sizeof(WFP_UDP_HEADER);
	UINT udp_packet_size;
	UINT udp_payload_size;
	UINT dst_udp_payload_size;
	WFP_UDP_HEADER *src_udp;
	WFP_UDP_HEADER *dst_udp;
	UCHAR *src_udp_payload;
	UCHAR *dst_data;
	UINT dst_size;
	// Validate arguments
	if (ip_packet == NULL || ip_packet == 0 || ip_header_size == 0 || dst_size_ptr == NULL)
	{
		return NULL;
	}

	if (ip_packet_size <= ip_and_udp_header_size)
	{
		// There is no UDP header
		return NULL;
	}

	// Get the UDP header
	src_udp = (WFP_UDP_HEADER *)(ip_packet + ip_header_size);
	udp_packet_size = Endian16(src_udp->PacketLength);
	if (udp_packet_size < sizeof(WFP_UDP_HEADER))
	{
		// There is no UDP payload
		return NULL;
	}

	// Get the UDP payload size
	udp_payload_size = udp_packet_size - sizeof(WFP_UDP_HEADER);

	if (ip_packet_size < (ip_and_udp_header_size + udp_payload_size))
	{
		// There is no UDP payload
		return NULL;
	}

	// Get the UDP payload
	src_udp_payload = ip_packet + ip_and_udp_header_size;

	if (udp_payload_size < sizeof(UINT))
	{
		// The size of the UDP payload is less than 5 bytes
		return NULL;
	}

	dst_udp_payload_size = udp_payload_size + sizeof(UINT) * 3;
	if ((dst_udp_payload_size + sizeof(WFP_UDP_HEADER)) > 0xffff)
	{
		// UDP payload size overflows the 16bit
		return NULL;
	}

	// Build a new packet
	dst_size = ip_and_udp_header_size + sizeof(UINT) * 3 + udp_payload_size;
	if (dst_size > 0xffff)
	{
		// IP total size overflows the 16bit
		return NULL;
	}

	dst_data = Malloc(dst_size);
	if (dst_data == NULL)
	{
		// Memory allocation failure
		return NULL;
	}

	// Copy the IP header + UDP header
	Copy(dst_data, ip_packet, ip_and_udp_header_size);

	// Copy the original payload
	Copy(dst_data + ip_and_udp_header_size + sizeof(UINT) * 3, src_udp_payload, udp_payload_size);

	// Insert a tag
	*((UINT *)(dst_data + ip_and_udp_header_size + sizeof(UINT) * 0)) = 0;
	*((UINT *)(dst_data + ip_and_udp_header_size + sizeof(UINT) * 1)) = WFP_ESP_PACKET_TAG_1;
	*((UINT *)(dst_data + ip_and_udp_header_size + sizeof(UINT) * 2)) = WFP_ESP_PACKET_TAG_2;

	// Adjust the new IP header
	if (isv6 == false)
	{
		WFP_IPV4_HEADER *ip = (WFP_IPV4_HEADER *)dst_data;

		ip->TotalLength = Endian16(dst_size);
		ip->Checksum = 0;
		ip->Checksum = IpChecksum(ip, ip_header_size);
	}
	else
	{
		WFP_IPV6_HEADER *ip = (WFP_IPV6_HEADER *)dst_data;

		ip->PayloadLength = Endian16(dst_size);
	}

	// Adjust the new UDP header
	dst_udp = (WFP_UDP_HEADER *)(dst_data + ip_header_size);
	dst_udp->Checksum = 0;
	dst_udp->PacketLength = Endian16((USHORT)(dst_udp_payload_size + sizeof(WFP_UDP_HEADER)));

	*dst_size_ptr = dst_size;
	return dst_data;
}

// Insert the packet into the stack
bool InjectPacket(HANDLE hInjection, NET_BUFFER_LIST *nbl, UCHAR *dst_data, UINT dst_size, const FWPS_INCOMING_VALUES0* inFixedValues, const FWPS_INCOMING_METADATA_VALUES0* inMetaValues)
{
	WFP_INJECTED_PACKET_CONTEXT *ctx;
	bool block = false;
	// Validate arguments
	if (hInjection == NULL || nbl == NULL || dst_data == NULL || dst_size == 0 || inMetaValues == NULL || inFixedValues == NULL)
	{
		return false;
	}

	ctx = ZeroMalloc(sizeof(WFP_INJECTED_PACKET_CONTEXT));

	if (ctx != NULL)
	{
		// Generate a modified packet
		ctx->AllocatedMemory = dst_data;

		if (dst_data != NULL)
		{
			NET_BUFFER_LIST *net_buffer_list;
			NTSTATUS ret;

			// Clone the original NET_BUFFER_LIST
			ret = FwpsAllocateCloneNetBufferList0(nbl, NULL, NULL, 0, &net_buffer_list);

			if (OK(ret) && net_buffer_list != NULL)
			{
				NET_BUFFER *net_buffer = NET_BUFFER_LIST_FIRST_NB(net_buffer_list);

				ctx->AllocatedNetBufferList = net_buffer_list;
				ctx->CurrentNetBuffer = net_buffer;

				if (net_buffer != NULL)
				{
					MDL *mdl = NdisAllocateMdl(wfp->hNdis, dst_data, dst_size);
					if (mdl != NULL)
					{
						NTSTATUS ret;

						ctx->AllocatedMdl = mdl;

						Copy(&ctx->OriginalNetBufferData, net_buffer, sizeof(NET_BUFFER));

						NET_BUFFER_FIRST_MDL(net_buffer) = mdl;
						NET_BUFFER_DATA_LENGTH(net_buffer) = dst_size;
						NET_BUFFER_DATA_OFFSET(net_buffer) = 0;
						NET_BUFFER_CURRENT_MDL(net_buffer) = mdl;
						NET_BUFFER_CURRENT_MDL_OFFSET(net_buffer) = 0;

						// Insert packets of receiving direction
						ret = FwpsInjectNetworkReceiveAsync0(hInjection, NULL, 
							0,
							(inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_COMPARTMENT_ID ? inMetaValues->compartmentId : UNSPECIFIED_COMPARTMENT_ID),
							inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32,
							inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32,
							net_buffer_list,
							CalloutInjectionCompleted,
							(HANDLE)ctx);

						if (NG(ret))
						{
							//CRUSH_WHERE;
						}
						else
						{
							block = true;
						}
					}
					else
					{
						//CRUSH_WHERE;
					}
				}
				else
				{
					//CRUSH_WHERE;
				}
			}
			else
			{
				//CRUSH_WHERE;
			}
		}
		else
		{
			//CRUSH_WHERE;
		}

		if (block == false)
		{
			FreeInjectionCtx(ctx);
		}
	}

	return block;
}

// Function to be notified of arriving packet
void NTAPI CalloutClassify(const FWPS_INCOMING_VALUES0* inFixedValues,
						   const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
						   void* layerData,
						   const FWPS_FILTER0* filter,
						   UINT64 flowContext,
						   FWPS_CLASSIFY_OUT0* classifyOut)
{
	NET_BUFFER_LIST *nbl = layerData;
	FWPS_PACKET_INJECTION_STATE injecton_state;
	bool block = false;
	HANDLE hInjection = NULL;
	UINT ip_header_len = 0;
	bool isv6 = false;

	if (wfp->Halting || nbl == NULL)
	{
		classifyOut->actionType = FWP_ACTION_CONTINUE;
		return;
	}

	switch (inFixedValues->layerId)
	{
	case FWPS_LAYER_INBOUND_IPPACKET_V4:
		hInjection = wfp->hInjectionIPv4;
		ip_header_len = sizeof(WFP_IPV4_HEADER);
		break;

	case FWPS_LAYER_INBOUND_IPPACKET_V6:
		hInjection = wfp->hInjectionIPv6;
		ip_header_len = sizeof(WFP_IPV6_HEADER);
		isv6 = true;
		break;
	}

	if (hInjection != NULL)
	{
		injecton_state = FwpsQueryPacketInjectionState0(hInjection, nbl, NULL);

		if (injecton_state == FWPS_PACKET_INJECTED_BY_SELF || injecton_state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)
		{
			//SetEvent(wfp->Event);
			classifyOut->actionType = FWP_ACTION_CONTINUE; // continue
			return;
		}

		if (nbl != NULL && NET_BUFFER_LIST_NEXT_NBL(nbl) == NULL)
		{
			NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(nbl);

			if (nb != NULL && NET_BUFFER_NEXT_NB(nb) == NULL && (NET_BUFFER_DATA_OFFSET(nb) >= inMetaValues->ipHeaderSize))
			{
				if (OK(NdisRetreatNetBufferDataStart(nb, inMetaValues->ipHeaderSize, 0, NULL)))
				{
					WFP_IPV4_HEADER *ipv4;
					WFP_IPV6_HEADER *ipv6;
					UCHAR *alloc_buf = Malloc(ip_header_len);

					ipv4 = NdisGetDataBuffer(nb, ip_header_len, alloc_buf, 1, 0);
					ipv6 = (WFP_IPV6_HEADER *)ipv4;

					if (ipv4 != NULL)
					{
						if ((isv6 == false && ipv4->Protocol == WFP_ESP_RAW_PROTOCOL_ID))
						{
							if (IsIPv4AddressInList(&ipv4->DstIP))
							{
								UINT src_size = NET_BUFFER_DATA_LENGTH(nb);
								UCHAR *src_data = Malloc(src_size);

								if (src_data != NULL)
								{
									UCHAR *src_ptr = NdisGetDataBuffer(nb, src_size, src_data, 1, 0);

									if (src_ptr != NULL)
									{
										UINT dst_size = src_size;
										UCHAR *dst_data = Malloc(dst_size);

										if (dst_data != NULL)
										{
											WFP_IPV4_HEADER *ipv4;

											Copy(dst_data, src_ptr, dst_size);
											ipv4 = (WFP_IPV4_HEADER *)dst_data;

											ipv4->Protocol = WFP_ESP_RAW_PROTOCOL_ID_DST;
											ipv4->Checksum = 0;
											ipv4->Checksum = IpChecksum(ipv4, inMetaValues->ipHeaderSize);

											block = InjectPacket(hInjection, nbl, dst_data, dst_size, inFixedValues, inMetaValues);
										}
									}

									Free(src_data);
								}
							}
						}
						else if ((isv6 && ipv6->NextHeader == WFP_ESP_RAW_PROTOCOL_ID))
						{
							if (IsIPv6AddressInList(&ipv6->DestAddress))
							{
								UINT src_size = NET_BUFFER_DATA_LENGTH(nb);
								UCHAR *src_data = Malloc(src_size);

								if (src_data != NULL)
								{
									UCHAR *src_ptr = NdisGetDataBuffer(nb, src_size, src_data, 1, 0);

									if (src_ptr != NULL)
									{
										UINT dst_size = src_size;
										UCHAR *dst_data = Malloc(dst_size);

										if (dst_data != NULL)
										{
											WFP_IPV6_HEADER *ipv6;

											Copy(dst_data, src_ptr, dst_size);
											ipv6 = (WFP_IPV6_HEADER *)dst_data;

											ipv6->NextHeader = WFP_ESP_RAW_PROTOCOL_ID_DST;

											block = InjectPacket(hInjection, nbl, dst_data, dst_size, inFixedValues, inMetaValues);
										}
									}

									Free(src_data);
								}
							}
						}

						if ((isv6 == false && ipv4->Protocol == WFP_IP_PROTO_UDP) ||
							(isv6 && ipv6->NextHeader == WFP_IP_PROTO_UDP))
						{
							UINT ip_and_udp_header_len = inMetaValues->ipHeaderSize + sizeof(WFP_UDP_HEADER);
							UCHAR *ptr;
							UCHAR *alloc_buf = Malloc(ip_and_udp_header_len);

							ptr = NdisGetDataBuffer(nb, ip_and_udp_header_len, alloc_buf, 1, 0);
							if (ptr != NULL)
							{
								WFP_UDP_HEADER *udp = (WFP_UDP_HEADER *)(ptr + inMetaValues->ipHeaderSize);

								if (Endian16(udp->DstPort) == 4500)
								{
									if ((isv6 == false && IsIPv4AddressInList(&ipv4->DstIP)) ||
										(isv6 && IsIPv6AddressInList(&ipv6->DestAddress)))
									{
										UINT packet_size = NET_BUFFER_DATA_LENGTH(nb);
										UCHAR *packet_buf_allocated = Malloc(packet_size);
										UCHAR *packet_data = NdisGetDataBuffer(nb, packet_size, packet_buf_allocated, 1, 0);

										if (packet_data != NULL)
										{
											UCHAR *udp_payload = packet_data + ip_and_udp_header_len;
											UINT udp_payload_size = packet_size - ip_and_udp_header_len;

											if (udp_payload_size >= 4)
											{
												UINT *i = (UINT *)udp_payload;
												if (*i != 0)
												{
													// Generate a modified packet
													UINT dst_size;
													UCHAR *dst_data = ModificationOfIPsecESPPacket(packet_data, packet_size,
														inMetaValues->ipHeaderSize, &dst_size, isv6);

													block = InjectPacket(hInjection, nbl, dst_data, dst_size, inFixedValues, inMetaValues);
												}
											}
										}
										else
										{
											//CRUSH_WHERE;
										}

										Free(packet_buf_allocated);
									}
								}
							}
							else
							{
								//CRUSH_WHERE;
							}

							Free(alloc_buf);
						}
					}

					Free(alloc_buf);

					NdisAdvanceNetBufferDataStart(nb, inMetaValues->ipHeaderSize, false, NULL);
				}
				else
				{
					//CRUSH_WHERE;
				}

				nb = NET_BUFFER_NEXT_NB(nb);
			}

			nbl = NET_BUFFER_LIST_NEXT_NBL(nbl);
		}
	}

	classifyOut->actionType = FWP_ACTION_CONTINUE;

	if (block)
	{
		// Block the packet
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		//SetEvent(wfp->Event);
	}
}

// Function to receive notification from the WFP
NTSTATUS NTAPI CalloutNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType,
							  const GUID* filterKey, FWPS_FILTER0* filter)
{
	//Crush(1,0,0,0);
	return 0;
}

// Scan whether the specified IP address is in the local IP address list
bool IsIPAddressInList(struct WFP_LOCAL_IP *ip)
{
	bool ret = false;
	// Validate arguments
	if (ip == NULL)
	{
		return false;
	}

	SpinLock(wfp->LocalIPListLock);
	{
		if (wfp->LocalIPListData != NULL)
		{
			UINT num = wfp->LocalIPListSize / sizeof(WFP_LOCAL_IP);
			WFP_LOCAL_IP *o = (WFP_LOCAL_IP *)wfp->LocalIPListData;
			UINT i;

			for (i = 0;i < num;i++)
			{
				if (Cmp(&o[i], ip, sizeof(WFP_LOCAL_IP)) == 0)
				{
					ret = true;
					break;
				}
			}
		}
	}
	SpinUnlock(wfp->LocalIPListLock);

	return ret;
}
bool IsIPv4AddressInList(void *addr)
{
	WFP_LOCAL_IP ip;
	// Validate arguments
	if (addr == NULL)
	{
		return false;
	}

	Zero(&ip, sizeof(ip));
	ip.IpVersion = 4;
	Copy(ip.IpAddress.IPv4Address, addr, 4);

	return IsIPAddressInList(&ip);
}
bool IsIPv6AddressInList(void *addr)
{
	WFP_LOCAL_IP ip;
	// Validate arguments
	if (addr == NULL)
	{
		return false;
	}

	Zero(&ip, sizeof(ip));
	ip.IpVersion = 6;
	Copy(ip.IpAddress.IPv6Address, addr, 16);

	return IsIPAddressInList(&ip);
}

// Win32 driver entry point
NTSTATUS DriverEntry(DRIVER_OBJECT *driver_object, UNICODE_STRING *registry_path)
{
	NTSTATUS ret;
	FWPM_SESSION0 t;

	if (wfp != NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	wfp = ZeroMalloc(sizeof(WFP_CTX));

	RtlInitUnicodeString(&wfp->DeviceName, WFP_DEVICE_NAME);
	RtlInitUnicodeString(&wfp->DeviceNameWin32, WFP_DEVICE_NAME_WIN32);
	// Create a device
	ret = IoCreateDevice(driver_object, 0, &wfp->DeviceName, FILE_DEVICE_NETWORK, 0, false, &wfp->DeviceObject);
	if (NG(ret))
	{
		return ret;
	}

	// Open the NDIS handle
	wfp->hNdis = NdisAllocateGenericObject(driver_object, MEMPOOL_TAG, 0);
	if (wfp->hNdis == NULL)
	{
		DriverUnload(driver_object);
		return STATUS_UNSUCCESSFUL;
	}

	// Create a symbolic device for Win32
	ret = IoCreateSymbolicLink(&wfp->DeviceNameWin32, &wfp->DeviceName);
	if (NG(ret))
	{
		DriverUnload(driver_object);
		return ret;
	}

	driver_object->DriverUnload = DriverUnload;

	// Create an Event
	wfp->Event = NewEvent(WFP_EVENT_NAME);
	if (wfp->Event == NULL)
	{
		DriverUnload(driver_object);
		return STATUS_UNSUCCESSFUL;
	}

	// Open the WFP engine
	Zero(&t, sizeof(t));
	t.flags = FWPM_SESSION_FLAG_DYNAMIC;
	ret = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &t, &wfp->hEngine);
	if (NG(ret))
	{
		DriverUnload(driver_object);
		return ret;
	}
	else
	{
		// Register itself as a Callout Driver
		FWPS_CALLOUT0 s;
//		FWPM_CALLOUT0 callout;

		Zero(&s, sizeof(s));
		s.calloutKey = GUID_WFP_CALLOUT_DRIVER_V4;
		s.classifyFn = CalloutClassify;
		s.notifyFn = CalloutNotify;

		ret = FwpsCalloutRegister0(wfp->DeviceObject, &s, &wfp->CalloutIdIPv4);
		if (NG(ret))
		{
			DriverUnload(driver_object);
			return ret;
		}

		Zero(&s, sizeof(s));
		s.calloutKey = GUID_WFP_CALLOUT_DRIVER_V6;
		s.classifyFn = CalloutClassify;
		s.notifyFn = CalloutNotify;

		ret = FwpsCalloutRegister0(wfp->DeviceObject, &s, &wfp->CalloutIdIPv6);
		if (NG(ret))
		{
			DriverUnload(driver_object);
			return ret;
		}

		/*// Create the Callout Driver (IPv4)
		Zero(&callout, sizeof(callout));
		callout.calloutKey = GUID_WFP_CALLOUT_DRIVER_V4;
		callout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V4;
		callout.displayData.name = WFP_DRIVER_TITLE_V4;
		ret = FwpmCalloutAdd0(wfp->hEngine, &callout, NULL, &wfp->CalloutObjIdIPv4);

		// Create the Callout Driver (IPv6)
		Zero(&callout, sizeof(callout));
		callout.calloutKey = GUID_WFP_CALLOUT_DRIVER_V6;
		callout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V6;
		callout.displayData.name = WFP_DRIVER_TITLE_V6;
		ret = FwpmCalloutAdd0(wfp->hEngine, &callout, NULL, &wfp->CalloutObjIdIPv6);*/

		// Create an injection handle
		FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_NETWORK, &wfp->hInjectionIPv4);
		if (NG(ret))
		{
			wfp->hInjectionIPv4 = NULL;
		}
		ret = FwpsInjectionHandleCreate0(AF_INET6, FWPS_INJECTION_TYPE_NETWORK,&wfp->hInjectionIPv6);
		if (NG(ret))
		{
			wfp->hInjectionIPv6 = NULL;
		}
	}

	// Create a lock
	wfp->LocalIPListLock = NewSpinLock();

	// Specify a service function
	driver_object->MajorFunction[IRP_MJ_CREATE] =
		driver_object->MajorFunction[IRP_MJ_CLOSE] =
		driver_object->MajorFunction[IRP_MJ_READ] =
		driver_object->MajorFunction[IRP_MJ_WRITE] = DriverDispatch;

	return STATUS_SUCCESS;
}

// Unload the driver
void DriverUnload(DRIVER_OBJECT *driver_object)
{
	// Validate arguments
	if (wfp == NULL || driver_object == NULL)
	{
		return;
	}

	wfp->Halting = true;

	// Delete the lock
	FreeSpinLock(wfp->LocalIPListLock);

	// Delete the injection handle
	if (wfp->hInjectionIPv4 != NULL)
	{
		FwpsInjectionHandleDestroy0(wfp->hInjectionIPv4);
	}
	if (wfp->hInjectionIPv6 != NULL)
	{
		FwpsInjectionHandleDestroy0(wfp->hInjectionIPv6);
	}

	// Delete the Callout Object
	if (wfp->hEngine != NULL)
	{
		//FwpmCalloutDeleteByKey0(wfp->hEngine, &GUID_WFP_CALLOUT_DRIVER_V4);
		//FwpmCalloutDeleteByKey0(wfp->hEngine, &GUID_WFP_CALLOUT_DRIVER_V6);
	}

	if (wfp->CalloutIdIPv4 != 0)
	{
		// Delete the registration of Callout Driver (IPv4)
		FwpsCalloutUnregisterById0(wfp->CalloutIdIPv4);
	}

	if (wfp->CalloutIdIPv6 != 0)
	{
		// Delete the registration of Callout Driver (IPv6)
		FwpsCalloutUnregisterById0(wfp->CalloutIdIPv6);
	}

	FreeEvent(wfp->Event);

	IoDeleteSymbolicLink(&wfp->DeviceNameWin32);

	if (wfp->DeviceObject != NULL)
	{
		IoDeleteDevice(wfp->DeviceObject);
	}

	if (wfp->hEngine != NULL)
	{
		FwpmEngineClose0(wfp->hEngine);
	}

	if (wfp->LocalIPListData != NULL)
	{
		Free(wfp->LocalIPListData);
	}

	// Close the NDIS handle
	if (wfp->hNdis != NULL)
	{
		NdisFreeGenericObject(wfp->hNdis);
	}

	Free(wfp);

	wfp = NULL;
}

// Create an Event
EVENT *NewEvent(wchar_t *name)
{
	EVENT *e;
	KEVENT *ke;
	HANDLE h;
	UNICODE_STRING name_str;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	RtlInitUnicodeString(&name_str, name);

	ke = IoCreateNotificationEvent(&name_str, &h);
	if (ke == NULL)
	{
		return NULL;
	}

	KeInitializeEvent(ke, NotificationEvent, false);
	KeClearEvent(ke);

	e = ZeroMalloc(sizeof(EVENT));

	e->EventObj = ke;
	e->Handle = h;

	return e;
}

// Delete the event
void FreeEvent(EVENT *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	ZwClose(e->Handle);

	Free(e);
}

// Set the event
void SetEvent(EVENT *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	KeSetEvent(e->EventObj, 0, false);
}

// Reset the event
void ResetEvent(EVENT *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	KeResetEvent(e->EventObj);
}

// Allocate the memory
void *Malloc(UINT size)
{
	void *p;

	p = ExAllocatePoolWithTag(NonPagedPool, size + sizeof(UINT), MEMPOOL_TAG);
	*((UINT *)p) = size;

	return ((UCHAR *)p) + sizeof(UINT);
}
void *ZeroMalloc(UINT size)
{
	void *p = Malloc(size);
	Zero(p, size);
	return p;
}

// Change the memory block size
void *ReAlloc(void *p, UINT size)
{
	void *ret;
	UINT oldsize;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	ret = Malloc(size);
	if (ret == NULL)
	{
		Free(p);
		return NULL;
	}

	oldsize = GetMemSize(p);

	Copy(ret, p, MIN(size, oldsize));

	Free(p);

	return ret;
}

// Copy memory
void Copy(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || src == NULL || size == 0)
	{
		return;
	}

	memcpy(dst, src, size);
}

// Get the memory block size
UINT GetMemSize(void *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	return *(UINT *)(((UCHAR *)p) - sizeof(UINT));
}

// Release the memory
void Free(void *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	p = ((UCHAR *)p) - sizeof(UINT);

	ExFreePoolWithTag(p, MEMPOOL_TAG);
}

// Clear the memory to zero
void Zero(void *p, UINT size)
{
	// Validate arguments
	if (p == NULL || size == 0)
	{
		return;
	}

	memset(p, 0, size);
}

// Comparison of memory
UINT Cmp(void *p1, void *p2, UINT size)
{
	UCHAR *c1 = (UCHAR *)p1;
	UCHAR *c2 = (UCHAR *)p2;
	UINT i;

	for (i = 0;i < size;i++)
	{
		if (c1[i] != c2[i])
		{
			if (c1[i] > c2[i])
			{
				return 1;
			}
			else
			{
				return -1;
			}
		}
	}

	return 0;
}

// Create a spin lock
SPINLOCK *NewSpinLock()
{
	SPINLOCK *s = ZeroMalloc(sizeof(SPINLOCK));

	KeInitializeSpinLock(&s->SpinLock);

	return s;
}

// Lock
void SpinLock(SPINLOCK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	KeAcquireSpinLock(&s->SpinLock, &s->OldIrql);
}

// Unlock
void SpinUnlock(SPINLOCK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	KeReleaseSpinLock(&s->SpinLock, s->OldIrql);
}

// Release the spin lock
void FreeSpinLock(SPINLOCK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Free(s);
}

// Sleep
void Sleep(int milliSeconds)
{
	PKTIMER timer = ZeroMalloc(sizeof(KTIMER));
	LARGE_INTEGER duetime;

	duetime.QuadPart = (__int64)milliSeconds * -10000;
	KeInitializeTimerEx(timer, NotificationTimer);
	KeSetTimerEx(timer, duetime, 0, NULL);

	KeWaitForSingleObject (timer, Executive, KernelMode, FALSE, NULL);

	Free(timer);
}

// 16-bit swap
USHORT Swap16(USHORT value)
{
	USHORT r;
	((BYTE *)&r)[0] = ((BYTE *)&value)[1];
	((BYTE *)&r)[1] = ((BYTE *)&value)[0];
	return r;
}

// 32-bit swap
UINT Swap32(UINT value)
{
	UINT r;
	((BYTE *)&r)[0] = ((BYTE *)&value)[3];
	((BYTE *)&r)[1] = ((BYTE *)&value)[2];
	((BYTE *)&r)[2] = ((BYTE *)&value)[1];
	((BYTE *)&r)[3] = ((BYTE *)&value)[0];
	return r;
}

// 64-bit swap
UINT64 Swap64(UINT64 value)
{
	UINT64 r;
	((BYTE *)&r)[0] = ((BYTE *)&value)[7];
	((BYTE *)&r)[1] = ((BYTE *)&value)[6];
	((BYTE *)&r)[2] = ((BYTE *)&value)[5];
	((BYTE *)&r)[3] = ((BYTE *)&value)[4];
	((BYTE *)&r)[4] = ((BYTE *)&value)[3];
	((BYTE *)&r)[5] = ((BYTE *)&value)[2];
	((BYTE *)&r)[6] = ((BYTE *)&value)[1];
	((BYTE *)&r)[7] = ((BYTE *)&value)[0];
	return r;
}

// Endian conversion 16bit
USHORT Endian16(USHORT src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap16(src);
	}
	else
	{
		return src;
	}
}

// Endian conversion 32bit
UINT Endian32(UINT src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap32(src);
	}
	else
	{
		return src;
	}
}

// Endian conversion 64bit
UINT64 Endian64(UINT64 src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap64(src);
	}
	else
	{
		return src;
	}
}

// Crash
void Crush(UINT a, UINT b, UINT c, UINT d)
{
	KeBugCheckEx(0x00000061, (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, (ULONG_PTR)d);
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
