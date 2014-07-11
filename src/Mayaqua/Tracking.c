// SoftEther VPN Source Code
// Mayaqua Kernel
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


// Tracking.c
// Object tracking module

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// Global variables
static LOCK *obj_lock;
static LOCK *obj_id_lock;
static UINT obj_id;
static LOCK *cs_lock;
static bool disable_tracking = false;
static TRACKING_LIST **hashlist;

static bool do_not_get_callstack;

// Enable the tracking
void TrackingEnable()
{
	disable_tracking = false;
}

// Disable the tracking
void TrackingDisable()
{
	disable_tracking = true;
}

// Get whether the tracking is enabled
bool IsTrackingEnabled()
{
	return !disable_tracking;
}

// Memory debug menu
void MemoryDebugMenu()
{
	char tmp[MAX_SIZE];
	TOKEN_LIST *t;
	char *cmd;
	Print("Mayaqua Kernel Memory Debug Tools\n"
		"Copyright (c) SoftEther Corporation. All Rights Reserved.\n\n");
	g_memcheck = false;
	while (true)
	{
		Print("debug>");
		GetLine(tmp, sizeof(tmp));
		t = ParseToken(tmp, " \t");
		if (t->NumTokens == 0)
		{
			FreeToken(t);
			DebugPrintAllObjects();
			continue;
		}
		cmd = t->Token[0];
		if (!StrCmpi(cmd, "?"))
		{
			DebugPrintCommandList();
		}
		else if (!StrCmpi(cmd, "a"))
		{
			DebugPrintAllObjects();
		}
		else if (!StrCmpi(cmd, "i"))
		{
			if (t->NumTokens == 1)
			{
				Print("Usage: i <obj_id>\n\n");
			}
			else
			{
				DebugPrintObjectInfo(ToInt(t->Token[1]));
			}
		}
		else if (!StrCmpi(cmd, "q"))
		{
			break;
		}
		else if (ToInt(cmd) != 0)
		{
			DebugPrintObjectInfo(ToInt(t->Token[0]));
		}
		else
		{
			Print("Command Not Found,\n\n");
		}
		FreeToken(t);
	}
	FreeToken(t);
	g_memcheck = true;
}

// Sort the objects by chronological order
int SortObjectView(void *p1, void *p2)
{
	TRACKING_OBJECT *o1, *o2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	o1 = *(TRACKING_OBJECT **)p1;
	o2 = *(TRACKING_OBJECT **)p2;
	if (o1 == NULL || o2 == NULL)
	{
		return 0;
	}

	if (o1->Id > o2->Id)
	{
		return 1;
	}
	else if (o1->Id == o2->Id)
	{
		return 0;
	}
	return -1;
}

// Display the information of the object 
void PrintObjectInfo(TRACKING_OBJECT *o)
{
	SYSTEMTIME t;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	UINT64ToSystem(&t, o->CreatedDate);
	GetDateTimeStrMilli(tmp, sizeof(tmp), &t);

	Print("    TRACKING_OBJECT ID: %u\n"
		"  TRACKING_OBJECT TYPE: %s\n"
		"      ADDRESS: 0x%p\n"
		"  TRACKING_OBJECT SIZE: %u bytes\n"
		" CREATED DATE: %s\n",
		o->Id, o->Name, UINT64_TO_POINTER(o->Address), o->Size, tmp);

	PrintCallStack(o->CallStack);
}

// Display the object information
void DebugPrintObjectInfo(UINT id)
{
	UINT i;
	TRACKING_OBJECT *o;

	// Search
	o = NULL;
	LockTrackingList();
	{
		for (i = 0;i < TRACKING_NUM_ARRAY;i++)
		{
			if (hashlist[i] != NULL)
			{
				TRACKING_LIST *t = hashlist[i];

				while (true)
				{
					if (t->Object->Id == id)
					{
						o = t->Object;
						break;
					}

					if (t->Next == NULL)
					{
						break;
					}

					t = t->Next;
				}

				if (o != NULL)
				{
					break;
				}
			}
		}
	}
	UnlockTrackingList();

	if (o == NULL)
	{
		// The ID could not be found
		Print("obj_id %u Not Found.\n\n", id);
		return;
	}

	PrintObjectInfo(o);
	Print("\n");
}

// Show a Summary of the object
void PrintObjectList(TRACKING_OBJECT *o)
{
	char tmp[MAX_SIZE];
	SYSTEMTIME t;
	UINT64ToSystem(&t, o->CreatedDate);
	GetTimeStrMilli(tmp, sizeof(tmp), &t);
	TrackGetObjSymbolInfo(o);
	Print("%-4u - [%-6s] %s 0x%p size=%-5u %11s %u\n",
		o->Id, o->Name, tmp, UINT64_TO_POINTER(o->Address), o->Size, o->FileName, o->LineNumber);
}

// Display all the objects
void DebugPrintAllObjects()
{
	UINT i;
	LIST *view;

	// Creating a List
	view = NewListFast(SortObjectView);
	LockTrackingList();
	{
		for (i = 0;i < TRACKING_NUM_ARRAY;i++)
		{
			if (hashlist[i] != NULL)
			{
				TRACKING_LIST *t = hashlist[i];

				while (true)
				{
					Add(view, t->Object);

					if (t->Next == NULL)
					{
						break;
					}

					t = t->Next;
				}
			}
		}
	}
	UnlockTrackingList();

	// Sort
	Sort(view);

	// Drawing
	for (i = 0;i < LIST_NUM(view);i++)
	{
		TRACKING_OBJECT *o = (TRACKING_OBJECT *)LIST_DATA(view, i);
		PrintObjectList(o);
	}

	// Release the list
	ReleaseList(view);

	Print("\n");
}

// List of the commands
void DebugPrintCommandList()
{
	Print(
		"a - All Objects\n"
		"i - Object Information\n"
		"? - Help\n"
		"q - Quit\n\n"
		);
}

// Display the usage of the memory
void PrintMemoryStatus()
{
	MEMORY_STATUS s;
	GetMemoryStatus(&s);
	Print("MEMORY STATUS:\n"
		" NUM_OF_MEMORY_BLOCKS: %u\n"
		" SIZE_OF_TOTAL_MEMORY: %u bytes\n",
		s.MemoryBlocksNum, s.MemorySize);
}

// Get the using state of the memory
void GetMemoryStatus(MEMORY_STATUS *status)
{
	UINT i, num, size;
	// Validate arguments
	if (status == NULL)
	{
		return;
	}

	LockTrackingList();
	{
		size = num = 0;

		for (i = 0;i < TRACKING_NUM_ARRAY;i++)
		{
			if (hashlist[i] != NULL)
			{
				TRACKING_LIST *t = hashlist[i];

				while (true)
				{
					TRACKING_OBJECT *o = t->Object;

					if (StrCmpi(o->Name, "MEM") == 0)
					{
						num++;
						size += o->Size;
					}

					if (t->Next == NULL)
					{
						break;
					}

					t = t->Next;
				}
			}
		}
	}
	UnlockTrackingList();

	status->MemoryBlocksNum = num;
	status->MemorySize = size;
}

// Get the symbol information by the object
void TrackGetObjSymbolInfo(TRACKING_OBJECT *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	if (!(o->LineNumber == 0 && o->FileName[0] == 0))
	{
		return;
	}

	if (o->CallStack != NULL)
	{
		GetCallStackSymbolInfo(o->CallStack);
		if (StrLen(o->CallStack->filename) != 0 && o->CallStack->line != 0)
		{
			StrCpy(o->FileName, sizeof(o->FileName), o->CallStack->filename);
			o->LineNumber = o->CallStack->line;
		}
	}
}

// Put a new object into the tracking list
void TrackNewObj(UINT64 addr, char *name, UINT size)
{
	TRACKING_OBJECT *o;
	UINT new_id;
	// Validate arguments
	if (addr == 0 || name == NULL)
	{
		return;
	}

	if (IsMemCheck() == false)
	{
		// Don't track in the release mode
		return;
	}

	if (disable_tracking)
	{
		return;
	}

	// Generate a new ID
	OSLock(obj_id_lock);
	{
		new_id = ++obj_id;
	}
	OSUnlock(obj_id_lock);

	o = OSMemoryAlloc(sizeof(TRACKING_OBJECT));
	o->Id = new_id;
	o->Address = addr;
	o->Name = name;
	o->Size = size;
	o->CreatedDate = LocalTime64();
	o->CallStack = WalkDownCallStack(GetCallStack(), 2);

	o->FileName[0] = 0;
	o->LineNumber = 0;

	LockTrackingList();
	{
		InsertTrackingList(o);
	}
	UnlockTrackingList();
}

// Remove the object from the tracking list
void TrackDeleteObj(UINT64 addr)
{
	TRACKING_OBJECT *o;
	// Validate arguments
	if (addr == 0)
	{
		return;
	}

	if (IsMemCheck() == false)
	{
		// Don't track in the release mode
		return;
	}

	if (disable_tracking)
	{
		return;
	}

	LockTrackingList();
	{
		o = SearchTrackingList(addr);
		if (o == NULL)
		{
			UnlockTrackingList();

			if (IsDebug())
			{
				printf("TrackDeleteObj: 0x%x is not Object!!\n", (void *)addr);
			}
			return;
		}
		DeleteTrackingList(o, true);
	}
	UnlockTrackingList();
}

// Change the size of the object being tracked
void TrackChangeObjSize(UINT64 addr, UINT size, UINT64 new_addr)
{
	TRACKING_OBJECT *o;
	// Validate arguments
	if (addr == 0)
	{
		return;
	}

	if (IsMemCheck() == false)
	{
		// Don't track in the release mode
		return;
	}

	if (disable_tracking)
	{
		return;
	}

	LockTrackingList();
	{
		o = SearchTrackingList(addr);
		if (o == NULL)
		{
			UnlockTrackingList();
			return;
		}

		DeleteTrackingList(o, false);

		o->Size = size;
		o->Address = new_addr;

		InsertTrackingList(o);
	}
	UnlockTrackingList();
}

// Memory address comparison function
int CompareTrackingObject(const void *p1, const void *p2)
{
	TRACKING_OBJECT *o1, *o2;
	// Validate arguments
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	o1 = *(TRACKING_OBJECT **)p1;
	o2 = *(TRACKING_OBJECT **)p2;
	if (o1 == NULL || o2 == NULL)
	{
		return 0;
	}

	if (o1->Address > o2->Address)
	{
		return 1;
	}
	if (o1->Address == o2->Address)
	{
		return 0;
	}
	return -1;
}

// Search an object in the tracking list
TRACKING_OBJECT *SearchTrackingList(UINT64 Address)
{
	UINT i;
	// Validate arguments
	if (Address == 0)
	{
		return NULL;
	}

	i = TRACKING_HASH(Address);

	if (hashlist[i] != NULL)
	{
		TRACKING_LIST *tt = hashlist[i];

		while (true)
		{
			if (tt->Object->Address == Address)
			{
				return tt->Object;
			}

			tt = tt->Next;

			if (tt == NULL)
			{
				break;
			}
		}
	}

	return NULL;
}

// Remove an object from a tracking list
void DeleteTrackingList(TRACKING_OBJECT *o, bool free_object_memory)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	i = TRACKING_HASH(o->Address);

	if (hashlist[i] != NULL)
	{
		TRACKING_LIST *ft = NULL;

		if (hashlist[i]->Object == o)
		{
			ft = hashlist[i];
			hashlist[i] = hashlist[i]->Next;
		}
		else
		{
			TRACKING_LIST *tt = hashlist[i];
			TRACKING_LIST *prev = NULL;

			while (true)
			{
				if (tt->Object == o)
				{
					prev->Next = tt->Next;
					ft = tt;
					break;
				}

				if (tt->Next == NULL)
				{
					break;
				}

				prev = tt;
				tt = tt->Next;
			}
		}

		if (ft != NULL)
		{
			OSMemoryFree(ft);

			if (free_object_memory)
			{
				FreeCallStack(o->CallStack);
				OSMemoryFree(o);
			}
		}
	}
}

// Insert an object into the tracking list
void InsertTrackingList(TRACKING_OBJECT *o)
{
	UINT i;
	TRACKING_LIST *t;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	t = OSMemoryAlloc(sizeof(TRACKING_LIST));
	t->Object = o;
	t->Next = NULL;

	i = TRACKING_HASH(o->Address);

	if (hashlist[i] == NULL)
	{
		hashlist[i] = t;
	}
	else
	{
		TRACKING_LIST *tt = hashlist[i];
		while (true)
		{
			if (tt->Next == NULL)
			{
				tt->Next = t;
				break;
			}

			tt = tt->Next;
		}
	}
}

// Lock the tracking list
void LockTrackingList()
{
	OSLock(obj_lock);
}

// Unlock the tracking list
void UnlockTrackingList()
{
	OSUnlock(obj_lock);
}

// Initialize the tracking
void InitTracking()
{
	UINT i;
	CALLSTACK_DATA *s;

	// Hash list initialization
	hashlist = (TRACKING_LIST **)OSMemoryAlloc(sizeof(TRACKING_LIST *) * TRACKING_NUM_ARRAY);

	for (i = 0;i < TRACKING_NUM_ARRAY;i++)
	{
		hashlist[i] = NULL;
	}

	obj_id = 0;

	// Create a lock
	obj_lock = OSNewLock();
	obj_id_lock = OSNewLock();
	cs_lock = OSNewLock();

	s = GetCallStack();
	if (s == NULL)
	{
		do_not_get_callstack = true;
	}
	else
	{
		do_not_get_callstack = false;
		FreeCallStack(s);
	}
}

// Release the tracking
void FreeTracking()
{
	UINT i;
	// Delete the lock
	OSDeleteLock(obj_lock);
	OSDeleteLock(obj_id_lock);
	OSDeleteLock(cs_lock);
	cs_lock = NULL;
	obj_id_lock = NULL;
	obj_lock = NULL;

	// Release all of the elements
	for (i = 0;i < TRACKING_NUM_ARRAY;i++)
	{
		if (hashlist[i] != NULL)
		{
			TRACKING_LIST *t = hashlist[i];

			while (true)
			{
				TRACKING_LIST *t2 = t;
				TRACKING_OBJECT *o = t->Object;

				FreeCallStack(o->CallStack);
				OSMemoryFree(o);

				t = t->Next;

				OSMemoryFree(t2);

				if (t == NULL)
				{
					break;
				}
			}
		}
	}

	// Release the list
	OSMemoryFree(hashlist);
}

// Show the call stack
void PrintCallStack(CALLSTACK_DATA *s)
{
	char tmp[MAX_SIZE * 2];

	GetCallStackStr(tmp, sizeof(tmp), s);
	Print("%s", tmp);
}

// Convert the call stack to a string
void GetCallStackStr(char *str, UINT size, CALLSTACK_DATA *s)
{
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	char tmp3[MAX_SIZE];
	UINT num, i;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	if (s == NULL)
	{
		StrCpy(str, size, "(Unknown)\n");
	}
	else
	{
		num = 0;
		str[0] = 0;
		while (true)
		{
			if (s == NULL)
			{
				break;
			}

			GetCallStackSymbolInfo(s);

			if (s->name == NULL)
			{
				Format(tmp, sizeof(tmp), "0x%p ---", UINT64_TO_POINTER(s->offset));
			}
			else
			{
				Format(tmp, sizeof(tmp), "0x%p %s() + 0x%02x",
					(void *)s->offset, s->name, UINT64_TO_POINTER(s->disp));
			}
			for (i = 0;i < num;i++)
			{
				tmp2[i] = ' ';
			}
			tmp2[i] = '\0';
			StrCpy(tmp3, sizeof(tmp3), tmp2);
			StrCat(tmp3, sizeof(tmp3), tmp);
			Format(tmp, sizeof(tmp), "%-55s %11s %u\n", tmp3, s->filename, s->line);
			StrCat(str, size, tmp);
			num++;
			s = s->next;
		}
	}
}

// Get the current call stack
CALLSTACK_DATA *GetCallStack()
{
	CALLSTACK_DATA *s;
	if (do_not_get_callstack)
	{
		// Not to get the call stack
		return NULL;
	}

	OSLock(cs_lock);
	{
		// Get the call stack
		s = OSGetCallStack();
	}
	OSUnlock(cs_lock);
	if (s == NULL)
	{
		return NULL;
	}

	// Descend in the call stack for 3 steps
	s = WalkDownCallStack(s, 3);

	return s;
}

// Get the symbol information of the call stack
bool GetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
	bool ret;
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	OSLock(cs_lock);
	{
		ret = OSGetCallStackSymbolInfo(s);
	}
	OSUnlock(cs_lock);

	return ret;
}

// Descend in the call stack by a specified number
CALLSTACK_DATA *WalkDownCallStack(CALLSTACK_DATA *s, UINT num)
{
	CALLSTACK_DATA *cs, *tmp;
	UINT i;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	cs = s;
	i = 0;

	while (true)
	{
		if (i >= num)
		{
			return cs;
		}
		i++;
		tmp = cs;
		cs = tmp->next;
		OSMemoryFree(tmp->name);
		OSMemoryFree(tmp);

		if (cs == NULL)
		{
			return NULL;
		}
	}
}

// Release the call stack
void FreeCallStack(CALLSTACK_DATA *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	while (true)
	{
		CALLSTACK_DATA *next = s->next;
		OSMemoryFree(s->name);
		OSMemoryFree(s);
		if (next == NULL)
		{
			break;
		}
		s = next;
	}
}



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
