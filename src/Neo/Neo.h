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


// Neo.h
// Header of Neo.c

#ifndef	NEO_H
#define	NEO_H


// Identification string (NDIS)
#define	NDIS_NEO_HARDWARE_ID				"VPN Client Adapter - %s"
#define	NDIS_NEO_DEVICE_NAME				"\\Device\\NEO_%s_DEVICE"
#define	NDIS_NEO_DEVICE_NAME_WIN32			"\\DosDevices\\NEO_%s_DEVICE"
#define	NDIS_NEO_DEVICE_FILE_NAME			"\\\\.\\NEO_NEOADAPTER_%s_DEVICE"
#define	NDIS_NEO_EVENT_NAME					"\\BaseNamedObjects\\NEO_EVENT_%s"
#define	NDIS_NEO_EVENT_NAME_WIN32			"Global\\NEO_EVENT_NEOADAPTER_%s"

// Constant
#define	NEO_MAX_PACKET_SIZE			1600
#define	NEO_MAX_PACKET_SIZE_ANNOUNCE	1514
#define	NEO_MIN_PACKET_SIZE			14
#define	NEO_PACKET_HEADER_SIZE		14
#define	NEO_MAX_FRAME_SIZE			(NEO_MAX_PACKET_SIZE - NEO_MIN_PACKET_SIZE)
#define	NEO_MAX_SPEED_DEFAULT		1000000
#define	NEO_MAC_ADDRESS_SIZE		6
#define	NEO_MAX_MULTICASE			32


// IOCTL constant
#define	NEO_IOCTL_SET_EVENT			CTL_CODE(0x8000, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	NEO_IOCTL_PUT_PACKET		CTL_CODE(0x8000, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define	NEO_IOCTL_GET_PACKET		CTL_CODE(0x8000, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)


// Packet data exchange related
#define	NEO_MAX_PACKET_EXCHANGE		256			// Number of packets that can be exchanged at a time
#define	NEO_MAX_PACKET_QUEUED		4096		// Maximum number of packets that can be queued
#define	NEO_EX_SIZEOF_NUM_PACKET	4			// Packet count data (UINT)
#define	NEO_EX_SIZEOF_LENGTH_PACKET	4			// Length data of the packet data (UINT)
#define	NEO_EX_SIZEOF_LEFT_FLAG		4			// Flag to indicate that the packet is still
#define	NEO_EX_SIZEOF_ONE_PACKET	1600		// Data area occupied by a packet data
#define	NEO_EXCHANGE_BUFFER_SIZE	(NEO_EX_SIZEOF_NUM_PACKET + NEO_EX_SIZEOF_LEFT_FLAG +	\
	(NEO_EX_SIZEOF_LENGTH_PACKET + NEO_EX_SIZEOF_ONE_PACKET) * (NEO_MAX_PACKET_EXCHANGE + 1))
#define	NEO_NUM_PACKET(buf)			(*((UINT *)((UCHAR *)buf + 0)))
#define	NEO_SIZE_OF_PACKET(buf, i)	(*((UINT *)((UCHAR *)buf + NEO_EX_SIZEOF_NUM_PACKET + \
									(i * (NEO_EX_SIZEOF_LENGTH_PACKET + NEO_EX_SIZEOF_ONE_PACKET)))))
#define	NEO_ADDR_OF_PACKET(buf, i)	(((UINT *)((UCHAR *)buf + NEO_EX_SIZEOF_NUM_PACKET + \
									NEO_EX_SIZEOF_LENGTH_PACKET +	\
									(i * (NEO_EX_SIZEOF_LENGTH_PACKET + NEO_EX_SIZEOF_ONE_PACKET)))))
#define	NEO_LEFT_FLAG(buf)			NEO_SIZE_OF_PACKET(buf, NEO_MAX_PACKET_EXCHANGE)



// Definitions needed to compile as a device driver
#ifdef	NEO_DEVICE_DRIVER

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

#ifdef	OS_WIN32
// NDIS 5.0 related
#include "NDIS5.h"
#endif	// OS_WIN32

// Lock
typedef struct _NEO_LOCK
{
#ifdef	OS_WIN32
	NDIS_SPIN_LOCK spin_lock;
#endif
} NEO_LOCK;

// Event
typedef struct _NEO_EVENT
{
#ifdef	OS_WIN32
#ifndef	WIN9X
	KEVENT *event;
	HANDLE event_handle;
#else	// WIN9X
	DWORD win32_event;
#endif	// WIN9X
#endif
} NEO_EVENT;

// Packet queue
typedef struct _NEO_QUEUE
{
	struct _NEO_QUEUE *Next;
	UINT Size;
	void *Buf;
} NEO_QUEUE;

// Status
typedef struct _NEO_STATUS
{
	UINT NumPacketSend;
	UINT NumPacketRecv;
	UINT NumPacketSendError;
	UINT NumPacketRecvError;
	UINT NumPacketRecvNoBuffer;
} NEO_STATUS;

// NDIS packet buffer
typedef struct _PACKET_BUFFER
{
	void *Buf;							// Buffer
	NDIS_PACKET *NdisPacket;			// NDIS packet
	NDIS_BUFFER *NdisBuffer;			// NDIS packet buffer
	NDIS_HANDLE PacketPool;				// Packet pool
	NDIS_HANDLE BufferPool;				// Buffer pool
} PACKET_BUFFER;

// Context
typedef struct _NEO_CTX
{
	NEO_EVENT *Event;					// Packet reception notification event
	BOOL Opened;						// Flag of whether opened
	BOOL Inited;						// Initialization flag
	BOOL Initing;						// Starting-up flag
	volatile BOOL Halting;				// Halting flag
	BYTE MacAddress[6];					// MAC address
	BYTE padding[2];					// padding
	NEO_QUEUE *PacketQueue;				// Transmission packet queue
	NEO_QUEUE *Tail;					// Tail of the transmission packet queue
	UINT NumPacketQueue;				// Number of queued packet
	NEO_LOCK *PacketQueueLock;			// Transmission packet queue lock
	NEO_STATUS Status;					// Status
	UINT CurrentPacketFilter;			// Current packet filter value
	UINT CurrentProtocolOptions;		// Current protocol option value
	BOOL Connected, ConnectedOld;		// Cable connection state
	BOOL ConnectedForce;				// Connection state forcibly notification
#ifdef	OS_WIN32
	NDIS_HANDLE NdisWrapper;			// NDIS wrapper handle
	NDIS_HANDLE NdisControl;			// NDIS control handle
	NDIS_HANDLE NdisMiniport;			// NDIS miniport handle
	NDIS_HANDLE NdisContext;			// NDIS context handle
	NDIS_HANDLE NdisConfig;				// NDIS Config handle
	DEVICE_OBJECT *NdisControlDevice;	// NDIS control device
	PDRIVER_DISPATCH DispatchTable[IRP_MJ_MAXIMUM_FUNCTION];
	PACKET_BUFFER *PacketBuffer[NEO_MAX_PACKET_EXCHANGE];		// NDIS packet buffer
	NDIS_PACKET *PacketBufferArray[NEO_MAX_PACKET_EXCHANGE];	// NDIS packet buffer array
	NDIS_HARDWARE_STATUS HardwareStatus;	// Hardware state
	char HardwareID[MAX_SIZE];			// Hardware ID
	char HardwareID_Raw[MAX_SIZE];		// Original hardware ID
	char HardwarePrintableID[MAX_SIZE];	// Hardware ID (for display)
#endif
} NEO_CTX;

extern NEO_CTX *ctx;


// Neo.c routine
void NeoNewStatus(NEO_STATUS *s);
void NeoFreeStatus(NEO_STATUS *s);
BOOL NeoInit();
void NeoShutdown();
void NeoInitPacketQueue();
void NeoFreePacketQueue();
void NeoClearPacketQueue();
void NeoLockPacketQueue();
void NeoUnlockPacketQueue();
NEO_QUEUE *NeoGetNextQueue();
void NeoFreeQueue(NEO_QUEUE *q);
void NeoInsertQueue(void *buf, UINT size);
UINT NeoGetNumQueue();
void NeoStartAdapter();
void NeoStopAdapter();
void NeoRead(void *buf);
void NeoWrite(void *buf);

// Common routine (platform dependent)
void *NeoMalloc(UINT size);
void *NeoZeroMalloc(UINT size);
void NeoFree(void *p);
void NeoCopy(void *dst, void *src, UINT size);
void NeoZero(void *dst, UINT size);
NEO_LOCK *NeoNewLock();
void NeoLock(NEO_LOCK *lock);
void NeoUnlock(NEO_LOCK *lock);
void NeoFreeLock(NEO_LOCK *lock);
NEO_EVENT *NeoNewEvent(char *name);
NEO_EVENT *NeoCreateWin9xEvent(DWORD h);
void NeoFreeEvent(NEO_EVENT *event);
void NeoSet(NEO_EVENT *event);
void NeoReset(NEO_EVENT *event);
BOOL NeoIsKernelAddress(void *addr);

#endif	// NEO_DEVICE_DRIVER


#endif	// NEO_H




// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
