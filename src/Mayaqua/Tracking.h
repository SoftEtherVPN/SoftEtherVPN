// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Tracking.h
// Header of Tracking.c

#ifndef	TRACKING_H
#define	TRACKING_H

// The number of array
#define	TRACKING_NUM_ARRAY	1048576

// Hash from an pointer to an array index
#define	TRACKING_HASH(p)	(UINT)(((((UINT64)(p)) / (UINT64)(sizeof(void *))) % ((UINT64)TRACKING_NUM_ARRAY)))

// Call stack
struct CALLSTACK_DATA
{
	bool symbol_cache;
	UINT64 offset, disp;
	char *name;
	struct CALLSTACK_DATA *next;
	char filename[MAX_PATH];
	UINT line;
};

// Object
struct TRACKING_OBJECT
{
	UINT Id;
	char *Name;
	UINT64 Address;
	UINT Size;
	UINT64 CreatedDate;
	CALLSTACK_DATA *CallStack;
	char FileName[MAX_PATH];
	UINT LineNumber;
};

// Usage of the memory
struct MEMORY_STATUS
{
	UINT MemoryBlocksNum;
	UINT MemorySize;
};

// Tracking list
struct TRACKING_LIST
{
	struct TRACKING_LIST *Next;
	struct TRACKING_OBJECT *Object;
};

CALLSTACK_DATA *GetCallStack();
bool GetCallStackSymbolInfo(CALLSTACK_DATA *s);
void FreeCallStack(CALLSTACK_DATA *s);
CALLSTACK_DATA *WalkDownCallStack(CALLSTACK_DATA *s, UINT num);
void GetCallStackStr(char *str, UINT size, CALLSTACK_DATA *s);
void PrintCallStack(CALLSTACK_DATA *s);
void InitTracking();
void FreeTracking();
int CompareTrackingObject(const void *p1, const void *p2);
void LockTrackingList();
void UnlockTrackingList();
void InsertTrackingList(TRACKING_OBJECT *o);
void DeleteTrackingList(TRACKING_OBJECT *o, bool free_object_memory);
TRACKING_OBJECT *SearchTrackingList(UINT64 Address);

void TrackNewObj(UINT64 addr, char *name, UINT size);
void TrackGetObjSymbolInfo(TRACKING_OBJECT *o);
void TrackDeleteObj(UINT64 addr);
void TrackChangeObjSize(UINT64 addr, UINT size, UINT64 new_addr);

void GetMemoryStatus(MEMORY_STATUS *status);
void PrintMemoryStatus();
void MemoryDebugMenu();
int SortObjectView(void *p1, void *p2);
void DebugPrintAllObjects();
void DebugPrintCommandList();
void PrintObjectList(TRACKING_OBJECT *o);
void PrintObjectInfo(TRACKING_OBJECT *o);
void DebugPrintObjectInfo(UINT id);

bool IsTrackingEnabled();

#endif	// TRACKING_H
