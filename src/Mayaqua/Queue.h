#ifndef QUEUE_H
#define QUEUE_H

#include "MayaType.h"

struct QUEUE_MPSC_NODE
{
	QUEUE_MPSC_NODE *volatile Next;
	void *Value;
};

// MPSC stands for "Multi Producer Single Consumer".
// Multiple threads can push concurrently.
// Multiple threads cannot pop concurrently.
struct QUEUE_MPSC
{
	QUEUE_MPSC_NODE *_Atomic Head;
	QUEUE_MPSC_NODE *Tail;
	QUEUE_MPSC_NODE Stub;
	REF *Ref;
};

QUEUE_MPSC *QueueMpscNew();
void QueueMpscFree(QUEUE_MPSC *queue);

void QueueMpscPush(QUEUE_MPSC *queue, QUEUE_MPSC_NODE *node);
void QueueMpscPushValue(QUEUE_MPSC *queue, void *value);

QUEUE_MPSC_NODE *QueueMpscPop(QUEUE_MPSC *queue);
void *QueueMpscPopValue(QUEUE_MPSC *queue);

QUEUE_MPSC_NODE *QueueMpscNodeNew(void *value);
void QueueMpscNodeFree(QUEUE_MPSC_NODE *node);

#endif
