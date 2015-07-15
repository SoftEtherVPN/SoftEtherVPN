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
BOOL NeoLoadRegistory();
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


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
