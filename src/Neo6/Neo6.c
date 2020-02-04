// SoftEther VPN Source Code - Developer Edition Master Branch
// Kernel Device Driver


// Neo6.c
// Driver Main Program

#include <GlobalConst.h>

#define	NEO_DEVICE_DRIVER

#include "Neo6.h"

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
	UCHAR *packet_buf;
	NET_BUFFER_LIST *nbl_chain = NULL;
	NET_BUFFER_LIST *nbl_tail = NULL;
	UINT num_nbl_chain = 0;
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
		// Stopping
		return;
	}

	if (ctx->Paused)
	{
		// Paused
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
		void *dst;
		NET_BUFFER_LIST *nbl = ctx->PacketBuffer[i]->NetBufferList;
		NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(nbl);

		nbl->SourceHandle = ctx->NdisMiniport;

		NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;

		size = NEO_SIZE_OF_PACKET(buf, i);
		if (size > NEO_MAX_PACKET_SIZE)
		{
			size = NEO_MAX_PACKET_SIZE;
		}
		if (size < NEO_PACKET_HEADER_SIZE)
		{
			size = NEO_PACKET_HEADER_SIZE;
		}

		packet_buf = (UCHAR *)(NEO_ADDR_OF_PACKET(buf, i));

		if (OK(NdisRetreatNetBufferDataStart(nb, size, 0, NULL)))
		{
			// Buffer copy
			dst = NdisGetDataBuffer(nb,
				size,
				NULL,
				1,
				0);

			if (dst != NULL)
			{
				NeoCopy(dst, packet_buf, size);

				if (nbl_chain == NULL)
				{
					nbl_chain = nbl;
				}

				if (nbl_tail != NULL)
				{
					NET_BUFFER_LIST_NEXT_NBL(nbl_tail) = nbl;
				}

				nbl_tail = nbl;

				num_nbl_chain++;
			}
		}

		nbl->Status = NDIS_STATUS_RESOURCES;

		ctx->Status.Int64BytesRecvTotal += (UINT64)size;

		if (packet_buf[0] & 0x40)
		{
			ctx->Status.Int64NumRecvBroadcast++;
			ctx->Status.Int64BytesRecvBroadcast += (UINT64)size;
		}
		else
		{
			ctx->Status.Int64NumRecvUnicast++;
			ctx->Status.Int64BytesRecvUnicast += (UINT64)size;
		}
	}

	if (nbl_chain == NULL)
	{
		return;
	}

	// Notify that it has received
	ctx->Status.NumPacketRecv += num_nbl_chain;

	NdisMIndicateReceiveNetBufferLists(ctx->NdisMiniport,
		nbl_chain, 0, num_nbl_chain, NDIS_RECEIVE_FLAGS_RESOURCES);

	if (true)
	{
		// Restore the packet buffer
		NET_BUFFER_LIST *nbl = nbl_chain;

		while (nbl != NULL)
		{
			NET_BUFFER *nb = NET_BUFFER_LIST_FIRST_NB(nbl);

			if (nb != NULL)
			{
				UINT size = NET_BUFFER_DATA_LENGTH(nb);

				NdisAdvanceNetBufferDataStart(nb, size, false, NULL);
			}

			nbl = NET_BUFFER_LIST_NEXT_NBL(nbl);
		}
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
		// Empty queue
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

// Release the buffer of the queue
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
void NeoClearPacketQueue(bool no_lock)
{
	// Release the memory of the packet queue
	if (no_lock == false)
	{
		NeoLock(ctx->PacketQueueLock);
	}
	if (true)
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
	if (no_lock == false)
	{
		NeoUnlock(ctx->PacketQueueLock);
	}
}

// Release the packet queue
void NeoFreePacketQueue()
{
	// Delete all packets
	NeoClearPacketQueue(false);

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

