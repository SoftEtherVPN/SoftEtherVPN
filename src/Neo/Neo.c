// SoftEther VPN Source Code - Developer Edition Master Branch
// Kernel Device Driver


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

	// Release the status information
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

