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
BOOL NeoLoadRegistory();
void NeoInitControlDevice();
void NeoFreeControlDevice();
NTSTATUS NeoNdisDispatch(DEVICE_OBJECT *DeviceObject, IRP *Irp);
void NeoCheckConnectState();
void NeoSetConnectState(BOOL connected);
BOOL NeoNdisOnOpen(IRP *irp, IO_STACK_LOCATION *stack);
BOOL NeoNdisOnClose(IRP *irp, IO_STACK_LOCATION *stack);

#endif	// NDIS5_H


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
