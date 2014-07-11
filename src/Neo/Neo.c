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


// Neo.c
// Driver main program

#include <GlobalConst.h>

#define	NEO_DEVICE_DRIVER

#include "Neo.h"

// Whether Win8
extern bool g_is_win8;

// Neo driver context
static NEO_CTX static_ctx;
NEO_CTX *ctx = &static_ctx;

// Read the packet data from the transmit packet queue
void NeoRead(void *buf)
{
	NEO_QUEUE *q;
	UINT num;
	BOOL left;
	// Validate arguments
	if (buf == NULL)
	{
		return;
	}

	// Copy the packets one by one from the queue
	num = 0;
	left = TRUE;
	NeoLockPacketQueue();
	{
		while (TRUE)
		{
			if (num >= NEO_MAX_PACKET_EXCHANGE)
			{
				if (ctx->PacketQueue == NULL)
				{
					left = FALSE;
				}
				break;
			}
			q = NeoGetNextQueue();
			if (q == NULL)
			{
				left = FALSE;
				break;
			}
			NEO_SIZE_OF_PACKET(buf, num) = q->Size;
			NeoCopy(NEO_ADDR_OF_PACKET(buf, num), q->Buf, q->Size);
			num++;
			NeoFreeQueue(q);
		}
	}
	NeoUnlockPacketQueue();

	NEO_NUM_PACKET(buf) = num;
	NEO_LEFT_FLAG(buf) = left;

	if (left == FALSE)
	{
		NeoReset(ctx->Event);
	}
	else
	{
		NeoSet(ctx->Event);
	}

	return;
}

// Process the received packet
void NeoWrite(void *buf)
{
	UINT num, i, size;
	void *packet_buf;
	// Validate arguments
	if (buf == NULL)
	{
		return;
	}

	// Number of packets
	num = NEO_NUM_PACKET(buf);
	if (num > NEO_MAX_PACKET_EXCHANGE)
	{
		// Number of packets is too many
		return;
	}
	if (num == 0)
	{
		// No packet
		return;
	}

	if (ctx->Halting != FALSE)
	{
		// Halting
		return;
	}

	if (ctx->Opened == FALSE)
	{
		// Not connected
		return;
	}

	for (i = 0;i < num;i++)
	{
		PACKET_BUFFER *p = ctx->PacketBuffer[i];

		size = NEO_SIZE_OF_PACKET(buf, i);
		if (size > NEO_MAX_PACKET_SIZE)
		{
			size = NEO_MAX_PACKET_SIZE;
		}
		if (size < NEO_PACKET_HEADER_SIZE)
		{
			size = NEO_PACKET_HEADER_SIZE;
		}

		packet_buf = NEO_ADDR_OF_PACKET(buf, i);

		// Buffer copy
		NeoCopy(p->Buf, packet_buf, size);

		if (g_is_win8 == false)
		{
			// Adjust the buffer size
			NdisAdjustBufferLength(p->NdisBuffer, size);
			// Set the packet information
			NDIS_SET_PACKET_STATUS(p->NdisPacket, NDIS_STATUS_RESOURCES);
			NDIS_SET_PACKET_HEADER_SIZE(p->NdisPacket, NEO_PACKET_HEADER_SIZE);
		}
		else
		{
			NdisMEthIndicateReceive(ctx->NdisMiniport, ctx, 
				p->Buf, NEO_PACKET_HEADER_SIZE,
				((UCHAR *)p->Buf) + NEO_PACKET_HEADER_SIZE, size - NEO_PACKET_HEADER_SIZE,
				size - NEO_PACKET_HEADER_SIZE);
			NdisMEthIndicateReceiveComplete(ctx->NdisMiniport);
		}
	}

	// Notify that packets have received
	ctx->Status.NumPacketRecv += num;

	if (g_is_win8 == false)
	{
		NdisMIndicateReceivePacket(ctx->NdisMiniport, ctx->PacketBufferArray, num);
	}
}

// Get the number of queue items
UINT NeoGetNumQueue()
{
	return ctx->NumPacketQueue;
}

// Insert the queue
void NeoInsertQueue(void *buf, UINT size)
{
	NEO_QUEUE *p;
	// Validate arguments
	if (buf == NULL || size == 0)
	{
		return;
	}

	// Prevent the packet accumulation in large quantities in the queue
	if (ctx->NumPacketQueue > NEO_MAX_PACKET_QUEUED)
	{
		NeoFree(buf);
		return;
	}

	// Create a queue
	p = NeoMalloc(sizeof(NEO_QUEUE));
	p->Next = NULL;
	p->Size = size;
	p->Buf = buf;

	// Append to the queue
	if (ctx->PacketQueue == NULL)
	{
		ctx->PacketQueue = p;
	}
	else
	{
		NEO_QUEUE *q = ctx->Tail;
		q->Next = p;
	}

	ctx->Tail = p;

	ctx->NumPacketQueue++;
}

// Get the next queued item
NEO_QUEUE *NeoGetNextQueue()
{
	NEO_QUEUE *q;
	if (ctx->PacketQueue == NULL)
	{
		// No item queued
		return NULL;
	}

	// Get the next queued item
	q = ctx->PacketQueue;
	ctx->PacketQueue = ctx->PacketQueue->Next;
	q->Next = NULL;
	ctx->NumPacketQueue--;

	if (ctx->PacketQueue == NULL)
	{
		ctx->Tail = NULL;
	}

	return q;
}

// Release the buffer queue
void NeoFreeQueue(NEO_QUEUE *q)
{
	// Validate arguments
	if (q == NULL)
	{
		return;
	}
	NeoFree(q->Buf);
	NeoFree(q);
}

// Lock the packet queue
void NeoLockPacketQueue()
{
	NeoLock(ctx->PacketQueueLock);
}

// Unlock the packet queue
void NeoUnlockPacketQueue()
{
	NeoUnlock(ctx->PacketQueueLock);
}

// Initialize the packet queue
void NeoInitPacketQueue()
{
	// Create a lock
	ctx->PacketQueueLock = NeoNewLock();
	// Initialize the packet queue
	ctx->PacketQueue = NULL;
	ctx->NumPacketQueue = 0;
	ctx->Tail = NULL;
}

// Delete all the packets from the packet queue
void NeoClearPacketQueue()
{
	// Release the memory of the packet queue
	NeoLock(ctx->PacketQueueLock);
	{
		NEO_QUEUE *q = ctx->PacketQueue;
		NEO_QUEUE *qn;
		while (q != NULL)
		{
			qn = q->Next;
			NeoFree(q->Buf);
			NeoFree(q);
			q = qn;
		}
		ctx->PacketQueue = NULL;
		ctx->Tail = NULL;
		ctx->NumPacketQueue = 0;
	}
	NeoUnlock(ctx->PacketQueueLock);
}

// Release the packet queue
void NeoFreePacketQueue()
{
	// Delete all packets
	NeoClearPacketQueue();

	// Delete the lock
	NeoFreeLock(ctx->PacketQueueLock);
	ctx->PacketQueueLock = NULL;
}

// Start the adapter
void NeoStartAdapter()
{
	// Initialize the packet queue
	NeoInitPacketQueue();
}

// Stop the adapter
void NeoStopAdapter()
{
	// Delete the packet queue
	NeoFreePacketQueue();
}

// Initialization
BOOL NeoInit()
{
	// Initialize the context
	NeoZero(ctx, sizeof(NEO_CTX));

	// Initialize the status information
	NeoNewStatus(&ctx->Status);

	return TRUE;
}

// Shutdown
void NeoShutdown()
{
	if (ctx == NULL)
	{
		// Uninitialized
		return;
	}

	// Relaese the status information
	NeoFreeStatus(&ctx->Status);

	NeoZero(ctx, sizeof(NEO_CTX));
}

// Create a status information
void NeoNewStatus(NEO_STATUS *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Memory initialization
	NeoZero(s, sizeof(NEO_STATUS));
}

// Release the status information
void NeoFreeStatus(NEO_STATUS *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Memory initialization
	NeoZero(s, sizeof(NEO_STATUS));
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
