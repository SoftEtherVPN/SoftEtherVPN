// MPSC algorithm from https://www.1024cores.net/home/lock-free-algorithms/queues/intrusive-mpsc-node-based-queue.

#include "Queue.h"

#include "Memory.h"
#include "Object.h"

QUEUE_MPSC_NODE *QueueMpscNodeNew(void *value)
{
	QUEUE_MPSC_NODE *node = Malloc(sizeof(QUEUE_MPSC_NODE));

	node->Next = NULL;
	node->Value = value;

	return node;
}

void QueueMpscNodeFree(QUEUE_MPSC_NODE *node)
{
	Free(node);
}

QUEUE_MPSC *QueueMpscNew()
{
	QUEUE_MPSC *queue = ZeroMalloc(sizeof(QUEUE_MPSC));

	atomic_init(&queue->Head, &queue->Stub);
	queue->Tail = &queue->Stub;
	queue->Ref = NewRef();

	return queue;
}

void QueueMpscFree(QUEUE_MPSC *queue)
{
	if (queue == NULL)
	{
		return;
	}

	if (Release(queue->Ref) == 0)
	{
		Free(queue);
	}
}

void QueueMpscPush(QUEUE_MPSC *queue, QUEUE_MPSC_NODE *node)
{
	if (queue == NULL || node == NULL)
	{
		return;
	}

	QUEUE_MPSC_NODE *prev = atomic_exchange(&queue->Head, node);
	prev->Next = node;
}

void QueueMpscPushValue(QUEUE_MPSC *queue, void *value)
{
	if (queue == NULL)
	{
		return;
	}

	QueueMpscPush(queue, QueueMpscNodeNew(value));
}

QUEUE_MPSC_NODE *QueueMpscPop(QUEUE_MPSC *queue)
{
	if (queue == NULL)
	{
		return NULL;
	}

	QUEUE_MPSC_NODE *tail = queue->Tail;
	QUEUE_MPSC_NODE *next = tail->Next;

	if (tail == &queue->Stub)
	{
		if (next == NULL)
		{
			return NULL;
		}

		queue->Tail = next;
		tail = next;
		next = next->Next;
	}

	if (next != NULL)
	{
		queue->Tail = next;
		return tail;
	}

	QUEUE_MPSC_NODE *head = queue->Head;
	if (tail != head)
	{
		return NULL;
	}

	QueueMpscPush(queue, &queue->Stub);

	next = tail->Next;
	if (next != NULL)
	{
		queue->Tail = next;
		return tail;
	}

	return NULL;
}

void *QueueMpscPopValue(QUEUE_MPSC *queue)
{
	if (queue == NULL)
	{
		return NULL;
	}

	QUEUE_MPSC_NODE *node = QueueMpscPop(queue);
	if (node == NULL)
	{
		return NULL;
	}

	void *value = node->Value;
	QueueMpscNodeFree(node);

	return value;
}
