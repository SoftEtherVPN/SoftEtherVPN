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


// Memory.c
// Memory management program

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <zlib/zlib.h>
#include <Mayaqua/Mayaqua.h>

#define	MEMORY_SLEEP_TIME		150
#define	MEMORY_MAX_RETRY		30
#define	INIT_BUF_SIZE			10240

#define	FIFO_INIT_MEM_SIZE		4096
#define	FIFO_REALLOC_MEM_SIZE	(65536 * 10)	// Exquisite value

#define	INIT_NUM_RESERVED		32

static UINT fifo_current_realloc_mem_size = FIFO_REALLOC_MEM_SIZE;

// Check whether the specified key item is in the hash list
bool IsInHashListKey(HASH_LIST *h, UINT key)
{
	// Validate arguments
	if (h == NULL || key == 0)
	{
		return false;
	}

	if (HashListKeyToPointer(h, key) == NULL)
	{
		return false;
	}

	return true;
}

// Search the item in the hash list with the key
void *HashListKeyToPointer(HASH_LIST *h, UINT key)
{
	UINT num, i;
	void **pp;
	void *ret = NULL;
	// Validate arguments
	if (h == NULL || key == 0)
	{
		return NULL;
	}

	pp = HashListToArray(h, &num);
	if (pp == NULL)
	{
		return NULL;
	}

	for (i = 0;i < num;i++)
	{
		void *p = pp[i];

		if (POINTER_TO_KEY(p) == key)
		{
			ret = p;
		}
	}

	Free(pp);

	return ret;
}

// Lock the hash list
void LockHashList(HASH_LIST *h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	Lock(h->Lock);
}

// Unlock the hash list
void UnlockHashList(HASH_LIST *h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	Unlock(h->Lock);
}

// Write the contents of the hash list to array
void **HashListToArray(HASH_LIST *h, UINT *num)
{
	void **ret = NULL;
	UINT i;
	UINT n = 0;
	// Validate arguments
	if (h == NULL || num == NULL)
	{
		if (num != NULL)
		{
			*num = 0;
		}
		return NULL;
	}

	if (h->AllList != NULL)
	{
		*num = LIST_NUM(h->AllList);

		return ToArray(h->AllList);
	}

	ret = ZeroMalloc(sizeof(void *) * h->NumItems);

	for (i = 0;i < h->Size;i++)
	{
		LIST *o = h->Entries[i];

		if (o != NULL)
		{
			UINT j;

			for (j = 0;j < LIST_NUM(o);j++)
			{
				void *p = LIST_DATA(o, j);

				ret[n] = p;
				n++;
			}
		}
	}

	*num = n;

	return ret;
}

// Search an item in the hash list
void *SearchHash(HASH_LIST *h, void *t)
{
	UINT r;
	void *ret = NULL;
	// Validate arguments
	if (h == NULL || t == NULL)
	{
		return NULL;
	}

	r = CalcHashForHashList(h, t);

	if (h->Entries[r] != NULL)
	{
		LIST *o = h->Entries[r];
		void *r = Search(o, t);

		if (r != NULL)
		{
			ret = r;
		}
	}

	return ret;
}

// Remove an item from the hash list
bool DeleteHash(HASH_LIST *h, void *p)
{
	UINT r;
	bool ret = false;
	// Validate arguments
	if (h == NULL || p == NULL)
	{
		return false;
	}

	r = CalcHashForHashList(h, p);

	if (h->Entries[r] != NULL)
	{
		if (Delete(h->Entries[r], p))
		{
			ret = true;
			h->NumItems--;
		}

		if (LIST_NUM(h->Entries[r]) == 0)
		{
			ReleaseList(h->Entries[r]);
			h->Entries[r] = NULL;
		}
	}

	if (ret)
	{
		if (h->AllList != NULL)
		{
			Delete(h->AllList, p);
		}
	}

	return ret;
}

// Add an item to the hash list
void AddHash(HASH_LIST *h, void *p)
{
	UINT r;
	// Validate arguments
	if (h == NULL || p == NULL)
	{
		return;
	}

	r = CalcHashForHashList(h, p);

	if (h->Entries[r] == NULL)
	{
		h->Entries[r] = NewListFast(h->CompareProc);
	}

	Insert(h->Entries[r], p);

	if (h->AllList != NULL)
	{
		Add(h->AllList, p);
	}

	h->NumItems++;
}

// Calculation of the hash value of the object
UINT CalcHashForHashList(HASH_LIST *h, void *p)
{
	UINT r;
	// Validate arguments
	if (h == NULL || p == NULL)
	{
		return 0;
	}

	r = h->GetHashProc(p);

	return (r % h->Size);
}

// Creating a hash list
HASH_LIST *NewHashList(GET_HASH *get_hash_proc, COMPARE *compare_proc, UINT bits, bool make_list)
{
	HASH_LIST *h;
	// Validate arguments
	if (get_hash_proc == NULL || compare_proc == NULL)
	{
		return NULL;
	}
	if (bits == 0)
	{
		bits = 16;
	}

	bits = MIN(bits, 31);

	h = ZeroMalloc(sizeof(HASH_LIST));

	h->Bits = bits;
	h->Size = Power(2, bits);

	h->Lock = NewLock();
	h->Ref = NewRef();

	h->Entries = ZeroMalloc(sizeof(LIST *) * h->Size);

	h->GetHashProc = get_hash_proc;
	h->CompareProc = compare_proc;

	if (make_list)
	{
		h->AllList = NewListFast(NULL);
	}

	return h;
}

// Release the hash list
void ReleaseHashList(HASH_LIST *h)
{
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	if (Release(h->Ref) == 0)
	{
		CleanupHashList(h);
	}
}
void CleanupHashList(HASH_LIST *h)
{
	UINT i;
	// Validate arguments
	if (h == NULL)
	{
		return;
	}

	for (i = 0;i < h->Size;i++)
	{
		LIST *o = h->Entries[i];

		if (o != NULL)
		{
			ReleaseList(o);
		}
	}

	Free(h->Entries);

	DeleteLock(h->Lock);

	if (h->AllList != NULL)
	{
		ReleaseList(h->AllList);
	}

	Free(h);
}

// Append a string to the buffer
void AppendBufStr(BUF *b, char *str)
{
	// Validate arguments
	if (b == NULL || str == NULL)
	{
		return;
	}

	WriteBuf(b, str, StrLen(str));
}

// Add a UTF-8 string to the buffer
void AppendBufUtf8(BUF *b, wchar_t *str)
{
	UINT size;
	UCHAR *data;
	// Validate arguments
	if (b == NULL || str == NULL)
	{
		return;
	}

	size = CalcUniToUtf8(str) + 1;
	data = ZeroMalloc(size);

	UniToUtf8(data, size, str);

	WriteBuf(b, data, size - 1);

	Free(data);
}

// Creating a shared buffer
SHARED_BUFFER *NewSharedBuffer(void *data, UINT size)
{
	SHARED_BUFFER *b = ZeroMalloc(sizeof(SHARED_BUFFER));

	b->Ref = NewRef();
	b->Data = ZeroMalloc(size);
	b->Size = size;

	if (data != NULL)
	{
		Copy(b->Data, data, size);
	}

	return b;
}

// Release of the shared buffer
void ReleaseSharedBuffer(SHARED_BUFFER *b)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	if (Release(b->Ref) == 0)
	{
		CleanupSharedBuffer(b);
	}
}
void CleanupSharedBuffer(SHARED_BUFFER *b)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	Free(b->Data);

	Free(b);
}

// Calculation of a ^ b (a to the b-th power)
UINT Power(UINT a, UINT b)
{
	UINT ret, i;
	if (a == 0)
	{
		return 0;
	}
	if (b == 0)
	{
		return 1;
	}

	ret = 1;
	for (i = 0;i < b;i++)
	{
		ret *= a;
	}

	return ret;
}

// Search in the binary
UINT SearchBin(void *data, UINT data_start, UINT data_size, void *key, UINT key_size)
{
	UINT i;
	// Validate arguments
	if (data == NULL || key == NULL || key_size == 0 || data_size == 0 ||
		(data_start >= data_size) || (data_start + key_size > data_size))
	{
		return INFINITE;
	}

	for (i = data_start;i < (data_size - key_size + 1);i++)
	{
		UCHAR *p = ((UCHAR *)data) + i;

		if (Cmp(p, key, key_size) == 0)
		{
			return i;
		}
	}

	return INFINITE;
}

// Crash immediately
void CrashNow()
{
	while (true)
	{
		UINT r = Rand32();
		UCHAR *c = (UCHAR *)r;

		*c = Rand8();
	}
}

// Convert the buffer to candidate
LIST *BufToCandidate(BUF *b)
{
	LIST *o;
	UINT i;
	UINT num;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	num = ReadBufInt(b);
	o = NewCandidateList();

	for (i = 0;i < num;i++)
	{
		CANDIDATE *c;
		wchar_t *s;
		UINT64 sec64;
		UINT len, size;
		sec64 = ReadBufInt64(b);
		len = ReadBufInt(b);
		if (len >= 65536)
		{
			break;
		}
		size = (len + 1) * 2;
		s = ZeroMalloc(size);
		if (ReadBuf(b, s, size) != size)
		{
			Free(s);
			break;
		}
		else
		{
			c = ZeroMalloc(sizeof(CANDIDATE));
			c->LastSelectedTime = sec64;
			c->Str = s;
			Add(o, c);
		}
	}

	Sort(o);
	return o;
}

// Convert the candidate to buffer
BUF *CandidateToBuf(LIST *o)
{
	BUF *b;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBufInt(b, LIST_NUM(o));
	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANDIDATE *c = LIST_DATA(o, i);
		WriteBufInt64(b, c->LastSelectedTime);
		WriteBufInt(b, UniStrLen(c->Str));
		WriteBuf(b, c->Str, UniStrSize(c->Str));
	}

	SeekBuf(b, 0, 0);

	return b;
}

// Adding a candidate
void AddCandidate(LIST *o, wchar_t *str, UINT num_max)
{
	UINT i;
	bool exists;
	// Validate arguments
	if (o == NULL || str == NULL)
	{
		return;
	}
	if (num_max == 0)
	{
		num_max = 0x7fffffff;
	}

	// String copy
	str = UniCopyStr(str);
	UniTrim(str);

	exists = false;
	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANDIDATE *c = LIST_DATA(o, i);
		if (UniStrCmpi(c->Str, str) == 0)
		{
			// Update the time that an existing entry have been found
			c->LastSelectedTime = SystemTime64();
			exists = true;
			break;
		}
	}

	if (exists == false)
	{
		// Insert new
		CANDIDATE *c = ZeroMalloc(sizeof(CANDIDATE));
		c->LastSelectedTime = SystemTime64();
		c->Str = UniCopyStr(str);
		Insert(o, c);
	}

	// Release the string
	Free(str);

	// Check the current number of candidates.
	// If it is more than num_max, remove from an oldest candidate sequentially.
	if (LIST_NUM(o) > num_max)
	{
		while (LIST_NUM(o) > num_max)
		{
			UINT index = LIST_NUM(o) - 1;
			CANDIDATE *c = LIST_DATA(o, index);
			Delete(o, c);
			Free(c->Str);
			Free(c);
		}
	}
}

// Comparison of candidates
int ComapreCandidate(void *p1, void *p2)
{
	CANDIDATE *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(CANDIDATE **)p1;
	c2 = *(CANDIDATE **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}
	if (c1->LastSelectedTime > c2->LastSelectedTime)
	{
		return -1;
	}
	else if (c1->LastSelectedTime < c2->LastSelectedTime)
	{
		return 1;
	}
	else
	{
		return UniStrCmpi(c1->Str, c2->Str);
	}
}

// Release of the candidate list
void FreeCandidateList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		CANDIDATE *c = LIST_DATA(o, i);
		Free(c->Str);
		Free(c);
	}

	ReleaseList(o);
}

// Creating a new candidate list
LIST *NewCandidateList()
{
	return NewList(ComapreCandidate);
}

// Fill a range of memory
void FillBytes(void *data, UINT size, UCHAR c)
{
	UCHAR *buf = (UCHAR *)data;
	UINT i;

	for (i = 0;i < size;i++)
	{
		buf[i] = c;
	}
}

// Examine whether the specified address points all-zero area
bool IsZero(void *data, UINT size)
{
	UINT i;
	UCHAR *c = (UCHAR *)data;
	// Validate arguments
	if (data == NULL || size == 0)
	{
		return true;
	}

	for (i = 0;i < size;i++)
	{
		if (c[i] != 0)
		{
			return false;
		}
	}

	return true;
}

// Expand the data
UINT Uncompress(void *dst, UINT dst_size, void *src, UINT src_size)
{
	unsigned long dst_size_long = dst_size;
	// Validate arguments
	if (dst == NULL || dst_size_long == 0 || src == NULL)
	{
		return 0;
	}

	if (uncompress(dst, &dst_size_long, src, src_size) != Z_OK)
	{
		return 0;
	}

	return (UINT)dst_size_long;
}
BUF *UncompressBuf(BUF *src_buf)
{
	UINT dst_size, dst_size2;
	UCHAR *dst;
	BUF *b;
	// Validate arguments
	if (src_buf == NULL)
	{
		return NULL;
	}

	SeekBuf(src_buf, 0, 0);
	dst_size = ReadBufInt(src_buf);

	dst = Malloc(dst_size);

	dst_size2 = Uncompress(dst, dst_size, ((UCHAR *)src_buf->Buf) + sizeof(UINT), src_buf->Size - sizeof(UINT));

	b = NewBuf();
	WriteBuf(b, dst, dst_size2);
	Free(dst);

	return b;
}

// Compress the data
UINT Compress(void *dst, UINT dst_size, void *src, UINT src_size)
{
	return CompressEx(dst, dst_size, src, src_size, Z_DEFAULT_COMPRESSION);
}
BUF *CompressBuf(BUF *src_buf)
{
	UINT dst_size;
	UCHAR *dst_buf;
	BUF *b;
	// Validate arguments
	if (src_buf == NULL)
	{
		return NULL;
	}

	dst_size = CalcCompress(src_buf->Size);
	dst_buf = Malloc(dst_size);

	dst_size = Compress(dst_buf, dst_size, src_buf->Buf, src_buf->Size);

	if (dst_size == 0)
	{
		Free(dst_buf);
		return NULL;
	}

	b = NewBuf();
	WriteBufInt(b, src_buf->Size);
	WriteBuf(b, dst_buf, dst_size);

	Free(dst_buf);

	return b;
}

// Compress the data with options
UINT CompressEx(void *dst, UINT dst_size, void *src, UINT src_size, UINT level)
{
	unsigned long dst_size_long = dst_size;
	// Validate arguments
	if (dst == NULL || dst_size_long == 0 || src == NULL)
	{
		return 0;
	}

	if (compress2(dst, &dst_size_long, src, src_size, (int)level) != Z_OK)
	{
		return 0;
	}

	return dst_size_long;
}

// Get the maximum size of compressed data from data of src_size
UINT CalcCompress(UINT src_size)
{
	return src_size * 2 + 256;
}

// Creating a Stack
SK *NewSk()
{
	return NewSkEx(false);
}
SK *NewSkEx(bool no_compact)
{
	SK *s;

	s = Malloc(sizeof(SK));
	s->lock = NewLock();
	s->ref = NewRef();
	s->num_item = 0;
	s->num_reserved = INIT_NUM_RESERVED;
	s->p = Malloc(sizeof(void *) * s->num_reserved);
	s->no_compact = no_compact;

#ifndef	DONT_USE_KERNEL_STATUS
//	TrackNewObj(POINTER_TO_UINT64(s), "SK", 0);
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWSK_COUNT);

	return s;
}

// Release of the stack
void ReleaseSk(SK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		CleanupSk(s);
	}
}

// Clean up the stack
void CleanupSk(SK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Memory release
	Free(s->p);
	DeleteLock(s->lock);
	Free(s);

#ifndef	DONT_USE_KERNEL_STATUS
//	TrackDeleteObj(POINTER_TO_UINT64(s));
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_FREESK_COUNT);
}

// Lock of the stack
void LockSk(SK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Lock(s->lock);
}

// Unlock the stack
void UnlockSk(SK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Unlock(s->lock);
}

// Push to the stack
void Push(SK *s, void *p)
{
	UINT i;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	i = s->num_item;
	s->num_item++;

	// Size expansion
	if (s->num_item > s->num_reserved)
	{
		s->num_reserved = s->num_reserved * 2;
		s->p = ReAlloc(s->p, sizeof(void *) * s->num_reserved);
	}
	s->p[i] = p;

	// KS
	KS_INC(KS_PUSH_COUNT);
}

// Pop from the stack
void *Pop(SK *s)
{
	void *ret;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}
	if (s->num_item == 0)
	{
		return NULL;
	}
	ret = s->p[s->num_item - 1];
	s->num_item--;

	// Size reduction
	if (s->no_compact == false)
	{
		// Not to shrink when no_compact is true
		if ((s->num_item * 2) <= s->num_reserved)
		{
			if (s->num_reserved >= (INIT_NUM_RESERVED * 2))
			{
				s->num_reserved = s->num_reserved / 2;
				s->p = ReAlloc(s->p, sizeof(void *) * s->num_reserved);
			}
		}
	}

	// KS
	KS_INC(KS_POP_COUNT);

	return ret;
}

// Peep
void *PeekQueue(QUEUE *q)
{
	void *p = NULL;
	// Validate arguments
	if (q == NULL)
	{
		return NULL;
	}

	if (q->num_item == 0)
	{
		// No items
		return NULL;
	}

	// Read from the FIFO
	PeekFifo(q->fifo, &p, sizeof(void *));

	return p;
}

// Get the number of queued items
UINT GetQueueNum(QUEUE *q)
{
	// Validate arguments
	if (q == NULL)
	{
		return 0;
	}

	return q->num_item;
}

// Get one
void *GetNext(QUEUE *q)
{
	void *p = NULL;
	// Validate arguments
	if (q == NULL)
	{
		return NULL;
	}

	if (q->num_item == 0)
	{
		// No items
		return NULL;
	}

	// Read from the FIFO
	ReadFifo(q->fifo, &p, sizeof(void *));
	q->num_item--;

	// KS
	KS_INC(KS_GETNEXT_COUNT);

	return p;
}

// Get one item from the queue (locking)
void *GetNextWithLock(QUEUE *q)
{
	void *p;
	// Validate arguments
	if (q == NULL)
	{
		return NULL;
	}

	LockQueue(q);
	{
		p = GetNext(q);
	}
	UnlockQueue(q);

	return p;
}

// Insert the int type in the queue
void InsertQueueInt(QUEUE *q, UINT value)
{
	UINT *p;
	// Validate arguments
	if (q == NULL)
	{
		return;
	}

	p = Clone(&value, sizeof(UINT));

	InsertQueue(q, p);
}

// Insert to the queue
void InsertQueue(QUEUE *q, void *p)
{
	// Validate arguments
	if (q == NULL || p == NULL)
	{
		return;
	}

	// Write to the FIFO
	WriteFifo(q->fifo, &p, sizeof(void *));

	q->num_item++;

	/*{
		static UINT max_num_item;
		static UINT64 next_tick = 0;
		UINT64 now = Tick64();

		max_num_item = MAX(q->num_item, max_num_item);

		if (next_tick == 0 || next_tick <= now)
		{
			next_tick = now + (UINT64)1000;

			printf("max_queue = %u\n", max_num_item);
		}
	}*/

	// KS
	KS_INC(KS_INSERT_QUEUE_COUNT);
}

// Insert to the queue (locking)
void InsertQueueWithLock(QUEUE *q, void *p)
{
	// Validate arguments
	if (q == NULL || p == NULL)
	{
		return;
	}

	LockQueue(q);
	{
		InsertQueue(q, p);
	}
	UnlockQueue(q);
}

// Lock the queue
void LockQueue(QUEUE *q)
{
	// Validate arguments
	if (q == NULL)
	{
		return;
	}

	Lock(q->lock);
}

// Unlock the queue
void UnlockQueue(QUEUE *q)
{
	// Validate arguments
	if (q == NULL)
	{
		return;
	}

	Unlock(q->lock);
}

// Release of the queue
void ReleaseQueue(QUEUE *q)
{
	// Validate arguments
	if (q == NULL)
	{
		return;
	}

	if (q->ref == NULL || Release(q->ref) == 0)
	{
		CleanupQueue(q);
	}
}

// Clean-up the queue
void CleanupQueue(QUEUE *q)
{
	// Validate arguments
	if (q == NULL)
	{
		return;
	}

	// Memory release
	ReleaseFifo(q->fifo);
	DeleteLock(q->lock);
	Free(q);

#ifndef	DONT_USE_KERNEL_STATUS
//	TrackDeleteObj(POINTER_TO_UINT64(q));
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_FREEQUEUE_COUNT);
}

// Creating a Queue
QUEUE *NewQueue()
{
	QUEUE *q;

	q = ZeroMalloc(sizeof(QUEUE));
	q->lock = NewLock();
	q->ref = NewRef();
	q->num_item = 0;
	q->fifo = NewFifo();

#ifndef	DONT_USE_KERNEL_STATUS
//	TrackNewObj(POINTER_TO_UINT64(q), "QUEUE", 0);
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWQUEUE_COUNT);

	return q;
}
QUEUE *NewQueueFast()
{
	QUEUE *q;

	q = ZeroMalloc(sizeof(QUEUE));
	q->lock = NULL;
	q->ref = NULL;
	q->num_item = 0;
	q->fifo = NewFifoFast();

#ifndef	DONT_USE_KERNEL_STATUS
//	TrackNewObj(POINTER_TO_UINT64(q), "QUEUE", 0);
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWQUEUE_COUNT);

	return q;
}

// Set the comparison function to list
void SetCmp(LIST *o, COMPARE *cmp)
{
	// Validate arguments
	if (o == NULL || cmp == NULL)
	{
		return;
	}

	if (o->cmp != cmp)
	{
		o->cmp = cmp;
		o->sorted = false;
	}
}

// Clone the list
LIST *CloneList(LIST *o)
{
	LIST *n = NewList(o->cmp);

	// Memory reallocation
	Free(n->p);
	n->p = ToArray(o);
	n->num_item = n->num_reserved = LIST_NUM(o);
	n->sorted = o->sorted;

	return n;
}

// Copy the list to an array
void CopyToArray(LIST *o, void *p)
{
	// Validate arguments
	if (o == NULL || p == NULL)
	{
		return;
	}

	// KS
	KS_INC(KS_TOARRAY_COUNT);

	Copy(p, o->p, sizeof(void *) * o->num_item);
}

// Arrange the list to an array
void *ToArray(LIST *o)
{
	return ToArrayEx(o, false);
}
void *ToArrayEx(LIST *o, bool fast)
{
	void *p;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	// Memory allocation
	if (fast == false)
	{
		p = Malloc(sizeof(void *) * LIST_NUM(o));
	}
	else
	{
		p = MallocFast(sizeof(void *) * LIST_NUM(o));
	}
	// Copy
	CopyToArray(o, p);

	return p;
}

// Search in the list
void *Search(LIST *o, void *target)
{
	void **ret;
	// Validate arguments
	if (o == NULL || target == NULL)
	{
		return NULL;
	}
	if (o->cmp == NULL)
	{
		return NULL;
	}

	// Check the sort
	if (o->sorted == false)
	{
		// Sort because it is not sorted
		Sort(o);
	}

	ret = (void **)bsearch(&target, o->p, o->num_item, sizeof(void *),
		(int(*)(const void *, const void *))o->cmp);

	// KS
	KS_INC(KS_SEARCH_COUNT);

	if (ret != NULL)
	{
		return *ret;
	}
	else
	{
		return NULL;
	}
}

// Insert an item to the list (Do not insert if it already exists)
void InsertDistinct(LIST *o, void *p)
{
	// Validate arguments
	if (o == NULL || p == NULL)
	{
		return;
	}

	if (IsInList(o, p))
	{
		return;
	}

	Insert(o, p);
}

// Insert an item to the list
void Insert(LIST *o, void *p)
{
	int low, high, middle;
	UINT pos;
	int i;
	// Validate arguments
	if (o == NULL || p == NULL)
	{
		return;
	}

	if (o->cmp == NULL)
	{
		// adding simply if there is no sort function
		Add(o, p);
		return;
	}

	// Sort immediately if it is not sorted
	if (o->sorted == false)
	{
		Sort(o);
	}

	low = 0;
	high = LIST_NUM(o) - 1;

	pos = INFINITE;

	while (low <= high)
	{
		int ret;

		middle = (low + high) / 2;
		ret = o->cmp(&(o->p[middle]), &p);

		if (ret == 0)
		{
			pos = middle;
			break;
		}
		else if (ret > 0)
		{
			high = middle - 1;
		}
		else
		{
			low = middle + 1;
		}
	}

	if (pos == INFINITE)
	{
		pos = low;
	}

	o->num_item++;
	if (o->num_item > o->num_reserved)
	{
		o->num_reserved *= 2;
		o->p = ReAlloc(o->p, sizeof(void *) * o->num_reserved);
	}

	if (LIST_NUM(o) >= 2)
	{
		for (i = (LIST_NUM(o) - 2);i >= (int)pos;i--)
		{
			o->p[i + 1] = o->p[i];
		}
	}

	o->p[pos] = p;

	// KS
	KS_INC(KS_INSERT_COUNT);
}

// Setting the sort flag
void SetSortFlag(LIST *o, bool sorted)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	o->sorted = sorted;
}

// Sort the list
void Sort(LIST *o)
{
	// Validate arguments
	if (o == NULL || o->cmp == NULL)
	{
		return;
	}

	qsort(o->p, o->num_item, sizeof(void *), (int(*)(const void *, const void *))o->cmp);
	o->sorted = true;

	// KS
	KS_INC(KS_SORT_COUNT);
}
void SortEx(LIST *o, COMPARE *cmp)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	qsort(o->p, o->num_item, sizeof(void *), (int(*)(const void *, const void *))cmp);
	o->sorted = false;

	// KS
	KS_INC(KS_SORT_COUNT);
}

// Examine whether a certain string items are present in the list (Unicode version)
bool IsInListUniStr(LIST *o, wchar_t *str)
{
	UINT i;
	// Validate arguments
	if (o == NULL || str == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);

		if (UniStrCmpi(s, str) == 0)
		{
			return true;
		}
	}

	return false;
}

// Replace the pointer in the list
bool ReplaceListPointer(LIST *o, void *oldptr, void *newptr)
{
	UINT i;
	// Validate arguments
	if (o == NULL || oldptr == NULL || newptr == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		void *p = LIST_DATA(o, i);

		if (p == oldptr)
		{
			o->p[i] = newptr;
			return true;
		}
	}

	return false;
}

// Examine whether a string items are present in the list
bool IsInListStr(LIST *o, char *str)
{
	UINT i;
	// Validate arguments
	if (o == NULL || str == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char *s = LIST_DATA(o, i);

		if (StrCmpi(s, str) == 0)
		{
			return true;
		}
	}

	return false;
}

// Get the pointer by scanning by UINT pointer in the list
void *ListKeyToPointer(LIST *o, UINT key)
{
	UINT i;
	// Validate arguments
	if (o == NULL || key == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		void *p = LIST_DATA(o, i);

		if (POINTER_TO_KEY(p) == key)
		{
			return p;
		}
	}

	return NULL;
}

// Examine whether the key is present in the list
bool IsInListKey(LIST *o, UINT key)
{
	void *p;
	// Validate arguments
	if (o == NULL || key == 0)
	{
		return false;
	}

	p = ListKeyToPointer(o, key);
	if (p == NULL)
	{
		return false;
	}

	return true;
}

// Examine whether the item exists in the list
bool IsInList(LIST *o, void *p)
{
	UINT i;
	// Validate arguments
	if (o == NULL || p == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		void *q = LIST_DATA(o, i);
		if (p == q)
		{
			return true;
		}
	}

	return false;
}

// Add an element to the list (Don't add if it already exists)
void AddDistinct(LIST *o, void *p)
{
	// Validate arguments
	if (o == NULL || p == NULL)
	{
		return;
	}

	if (IsInList(o, p))
	{
		return;
	}

	Add(o, p);
}

// Add an element to the list
void Add(LIST *o, void *p)
{
	UINT i;
	// Validate arguments
	if (o == NULL || p == NULL)
	{
		return;
	}

	i = o->num_item;
	o->num_item++;

	if (o->num_item > o->num_reserved)
	{
		o->num_reserved = o->num_reserved * 2;
		o->p = ReAlloc(o->p, sizeof(void *) * o->num_reserved);
	}

	o->p[i] = p;
	o->sorted = false;

	// KS
	KS_INC(KS_INSERT_COUNT);
}

// Delete the elements specified by the key from the list
bool DeleteKey(LIST *o, UINT key)
{
	void *p;
	// Validate arguments
	if (o == NULL || key == 0)
	{
		return false;
	}

	p = ListKeyToPointer(o, key);
	if (p == NULL)
	{
		return false;
	}

	return Delete(o, p);
}

// Delete the element from the list
bool Delete(LIST *o, void *p)
{
	UINT i, n;
	// Validate arguments
	if (o == NULL || p == NULL)
	{
		return false;
	}

	for (i = 0;i < o->num_item;i++)
	{
		if (o->p[i] == p)
		{
			break;
		}
	}
	if (i == o->num_item)
	{
		return false;
	}

	n = i;
	for (i = n;i < (o->num_item - 1);i++)
	{
		o->p[i] = o->p[i + 1];
	}
	o->num_item--;
	if ((o->num_item * 2) <= o->num_reserved)
	{
		if (o->num_reserved > (INIT_NUM_RESERVED * 2))
		{
			o->num_reserved = o->num_reserved / 2;
			o->p = ReAlloc(o->p, sizeof(void *) * o->num_reserved);
		}
	}

	// KS
	KS_INC(KS_DELETE_COUNT);

	return true;
}

// Delete all elements from the list
void DeleteAll(LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	o->num_item = 0;
	o->num_reserved = INIT_NUM_RESERVED;
	o->p = ReAlloc(o->p, sizeof(void *) * INIT_NUM_RESERVED);
}

// Lock the list
void LockList(LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	Lock(o->lock);
}

// Unlock the list
void UnlockList(LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	Unlock(o->lock);
}

// Release the list
void ReleaseList(LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	if (o->ref == NULL || Release(o->ref) == 0)
	{
		CleanupList(o);
	}
}

// Clean up the list
void CleanupList(LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	Free(o->p);
	if (o->lock != NULL)
	{
		DeleteLock(o->lock);
	}
	Free(o);

	// KS
	KS_INC(KS_FREELIST_COUNT);

#ifndef	DONT_USE_KERNEL_STATUS
//	TrackDeleteObj(POINTER_TO_UINT64(o));
#endif	// DONT_USE_KERNEL_STATUS
}

// Check whether the specified number is already in the list
bool IsIntInList(LIST *o, UINT i)
{
	UINT j;
	// Validate arguments
	if (o == NULL)
	{
		return false;
	}

	for (j = 0;j < LIST_NUM(o);j++)
	{
		UINT *p = LIST_DATA(o, j);

		if (*p == i)
		{
			return true;
		}
	}

	return false;
}
bool IsInt64InList(LIST *o, UINT64 i)
{
	UINT j;
	// Validate arguments
	if (o == NULL)
	{
		return false;
	}

	for (j = 0;j < LIST_NUM(o);j++)
	{
		UINT64 *p = LIST_DATA(o, j);

		if (*p == i)
		{
			return true;
		}
	}

	return false;
}

// Remove all int from the interger list
void DelAllInt(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT *p = LIST_DATA(o, i);

		Free(p);
	}

	DeleteAll(o);
}

// Release the integer list
void ReleaseIntList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT *p = LIST_DATA(o, i);

		Free(p);
	}

	ReleaseList(o);
}
void ReleaseInt64List(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT64 *p = LIST_DATA(o, i);

		Free(p);
	}

	ReleaseList(o);
}

// Delete an integer from list
void DelInt(LIST *o, UINT i)
{
	LIST *o2 = NULL;
	UINT j;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (j = 0;j < LIST_NUM(o);j++)
	{
		UINT *p = LIST_DATA(o, j);

		if (*p == i)
		{
			if (o2 == NULL)
			{
				o2 = NewListFast(NULL);
			}
			Add(o2, p);
		}
	}

	for (j = 0;j < LIST_NUM(o2);j++)
	{
		UINT *p = LIST_DATA(o2, j);

		Delete(o, p);

		Free(p);
	}

	if (o2 != NULL)
	{
		ReleaseList(o2);
	}
}
void DelInt64(LIST *o, UINT64 i)
{
	LIST *o2 = NULL;
	UINT j;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (j = 0;j < LIST_NUM(o);j++)
	{
		UINT64 *p = LIST_DATA(o, j);

		if (*p == i)
		{
			if (o2 == NULL)
			{
				o2 = NewListFast(NULL);
			}
			Add(o2, p);
		}
	}

	for (j = 0;j < LIST_NUM(o2);j++)
	{
		UINT64 *p = LIST_DATA(o2, j);

		Delete(o, p);

		Free(p);
	}

	if (o2 != NULL)
	{
		ReleaseList(o2);
	}
}

// Create a new list of integers
LIST *NewIntList(bool sorted)
{
	LIST *o = NewList(sorted ? CompareInt : NULL);

	return o;
}
LIST *NewInt64List(bool sorted)
{
	LIST *o = NewList(sorted ? CompareInt64 : NULL);

	return o;
}

// Comparison of items in the list of integers
int CompareInt(void *p1, void *p2)
{
	UINT *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	v1 = *((UINT **)p1);
	v2 = *((UINT **)p2);
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return COMPARE_RET(*v1, *v2);
}
int CompareInt64(void *p1, void *p2)
{
	UINT64 *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}

	v1 = *((UINT64 **)p1);
	v2 = *((UINT64 **)p2);
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return COMPARE_RET(*v1, *v2);
}

// Randomize the contents of the list
void RandomizeList(LIST *o)
{
	LIST *o2;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	o2 = NewListFast(NULL);

	while (LIST_NUM(o) != 0)
	{
		UINT num = LIST_NUM(o);
		UINT i = Rand32() % num;
		void *p = LIST_DATA(o, i);

		Add(o2, p);
		Delete(o, p);
	}

	DeleteAll(o);

	for (i = 0;i < LIST_NUM(o2);i++)
	{
		void *p = LIST_DATA(o2, i);

		Add(o, p);
	}

	ReleaseList(o2);
}

// Add an integer to the list
void AddInt(LIST *o, UINT i)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	Add(o, Clone(&i, sizeof(UINT)));
}
void AddInt64(LIST *o, UINT64 i)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	Add(o, Clone(&i, sizeof(UINT64)));
}
void InsertInt(LIST *o, UINT i)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	Insert(o, Clone(&i, sizeof(UINT)));
}
void InsertInt64(LIST *o, UINT64 i)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	Insert(o, Clone(&i, sizeof(UINT64)));
}

// Add an integer to the list (no duplicates)
void AddIntDistinct(LIST *o, UINT i)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	if (IsIntInList(o, i) == false)
	{
		AddInt(o, i);
	}
}
void AddInt64Distinct(LIST *o, UINT64 i)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	if (IsInt64InList(o, i) == false)
	{
		AddInt64(o, i);
	}
}
void InsertIntDistinct(LIST *o, UINT i)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	if (IsIntInList(o, i) == false)
	{
		InsertInt(o, i);
	}
}
void InsertInt64Distinct(LIST *o, UINT64 i)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	if (IsInt64InList(o, i) == false)
	{
		InsertInt64(o, i);
	}
}

// String comparison function (Unicode)
int CompareUniStr(void *p1, void *p2)
{
	wchar_t *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(wchar_t **)p1;
	s2 = *(wchar_t **)p2;

	return UniStrCmp(s1, s2);
}

// Insert the string to the list
bool InsertStr(LIST *o, char *str)
{
	// Validate arguments
	if (o == NULL || str == NULL)
	{
		return false;
	}

	if (Search(o, str) == NULL)
	{
		Insert(o, str);

		return true;
	}

	return false;
}

// String comparison function
int CompareStr(void *p1, void *p2)
{
	char *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(char **)p1;
	s2 = *(char **)p2;

	return StrCmpi(s1, s2);
}

// Create a list with an item
LIST *NewListSingle(void *p)
{
	LIST *o = NewListFast(NULL);

	Add(o, p);

	return o;
}

// Creating a high-speed list (without lock)
LIST *NewListFast(COMPARE *cmp)
{
	return NewListEx(cmp, true);
}

// Creating a list
LIST *NewList(COMPARE *cmp)
{
	return NewListEx(cmp, false);
}
LIST *NewListEx(COMPARE *cmp, bool fast)
{
	return NewListEx2(cmp, fast, false);
}
LIST *NewListEx2(COMPARE *cmp, bool fast, bool fast_malloc)
{
	LIST *o;

	if (fast_malloc == false)
	{
		o = Malloc(sizeof(LIST));
	}
	else
	{
		o = MallocFast(sizeof(LIST));
	}

	if (fast == false)
	{
		o->lock = NewLock();
		o->ref = NewRef();
	}
	else
	{
		o->lock = NULL;
		o->ref = NULL;
	}
	o->num_item = 0;
	o->num_reserved = INIT_NUM_RESERVED;
	o->Param1 = 0;

	if (fast_malloc == false)
	{
		o->p = Malloc(sizeof(void *) * o->num_reserved);
	}
	else
	{
		o->p = MallocFast(sizeof(void *) * o->num_reserved);
	}

	o->cmp = cmp;
	o->sorted = true;

#ifndef	DONT_USE_KERNEL_STATUS
//	TrackNewObj(POINTER_TO_UINT64(o), "LIST", 0);
#endif	//DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWLIST_COUNT);

	return o;
}

// Peek from the FIFO
UINT PeekFifo(FIFO *f, void *p, UINT size)
{
	UINT read_size;
	if (f == NULL || size == 0)
	{
		return 0;
	}

	// KS
	KS_INC(KS_PEEK_FIFO_COUNT);

	read_size = MIN(size, f->size);
	if (read_size == 0)
	{
		return 0;
	}

	if (p != NULL)
	{
		Copy(p, (UCHAR *)f->p + f->pos, read_size);
	}

	return read_size;
}

// Read from the FIFO
UINT ReadFifo(FIFO *f, void *p, UINT size)
{
	UINT read_size;
	// Validate arguments
	if (f == NULL || size == 0)
	{
		return 0;
	}

	read_size = MIN(size, f->size);
	if (read_size == 0)
	{
		return 0;
	}
	if (p != NULL)
	{
		Copy(p, (UCHAR *)f->p + f->pos, read_size);
	}
	f->pos += read_size;
	f->size -= read_size;

	f->total_read_size += (UINT64)read_size;

	if (f->size == 0)
	{
		f->pos = 0;
	}

	ShrinkFifoMemory(f);

	// KS
	KS_INC(KS_READ_FIFO_COUNT);

	return read_size;
}

// Rearrange the memory
void ShrinkFifoMemory(FIFO *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	// Rearrange the memory
	if (f->pos >= FIFO_INIT_MEM_SIZE && 
		f->memsize >= fifo_current_realloc_mem_size &&
		(f->memsize / 2) > f->size)
	{
		void *new_p;
		UINT new_size;

		new_size = MAX(f->memsize / 2, FIFO_INIT_MEM_SIZE);
		new_p = Malloc(new_size);
		Copy(new_p, (UCHAR *)f->p + f->pos, f->size);

		Free(f->p);

		f->memsize = new_size;
		f->p = new_p;
		f->pos = 0;
	}
}

// Write to the FIFO
void WriteFifo(FIFO *f, void *p, UINT size)
{
	UINT i, need_size;
	bool realloc_flag;
	// Validate arguments
	if (f == NULL || size == 0)
	{
		return;
	}

	i = f->size;
	f->size += size;
	need_size = f->pos + f->size;
	realloc_flag = false;

	// Memory expansion
	while (need_size > f->memsize)
	{
		f->memsize = MAX(f->memsize, FIFO_INIT_MEM_SIZE) * 3;
		realloc_flag = true;
	}

	if (realloc_flag)
	{
		f->p = ReAlloc(f->p, f->memsize);
	}

	// Write the data
	if (p != NULL)
	{
		Copy((UCHAR *)f->p + f->pos + i, p, size);
	}

	f->total_write_size += (UINT64)size;

	// KS
	KS_INC(KS_WRITE_FIFO_COUNT);
}

// Clear the FIFO
void ClearFifo(FIFO *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	f->size = f->pos = 0;
	f->memsize = FIFO_INIT_MEM_SIZE;
	f->p = ReAlloc(f->p, f->memsize);
}

// Get the current pointer of the FIFO
UCHAR *GetFifoPointer(FIFO *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return NULL;
	}

	return ((UCHAR *)f->p) + f->pos;
}
UCHAR *FifoPtr(FIFO *f)
{
	return GetFifoPointer(f);
}

// Get the size of the FIFO
UINT FifoSize(FIFO *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return 0;
	}

	return f->size;
}

// Lock the FIFO
void LockFifo(FIFO *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	Lock(f->lock);
}

// Unlock the FIFO
void UnlockFifo(FIFO *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	Unlock(f->lock);
}

// Release the FIFO
void ReleaseFifo(FIFO *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	if (f->ref == NULL || Release(f->ref) == 0)
	{
		CleanupFifo(f);
	}
}

// Clean-up the FIFO
void CleanupFifo(FIFO *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	DeleteLock(f->lock);
	Free(f->p);
	Free(f);

#ifndef	DONT_USE_KERNEL_STATUS
//	TrackDeleteObj(POINTER_TO_UINT64(f));
#endif	//DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_FREEFIFO_COUNT);
}

// Initialize the FIFO system
void InitFifo()
{
	fifo_current_realloc_mem_size = FIFO_REALLOC_MEM_SIZE;
}

// Create a FIFO
FIFO *NewFifo()
{
	return NewFifoEx(false);
}
FIFO *NewFifoFast()
{
	return NewFifoEx(true);
}
FIFO *NewFifoEx(bool fast)
{
	FIFO *f;

	// Memory allocation
	f = ZeroMalloc(sizeof(FIFO));

	if (fast == false)
	{
		f->lock = NewLock();
		f->ref = NewRef();
	}
	else
	{
		f->lock = NULL;
		f->ref = NULL;
	}

	f->size = f->pos = 0;
	f->memsize = FIFO_INIT_MEM_SIZE;
	f->p = Malloc(FIFO_INIT_MEM_SIZE);

#ifndef	DONT_USE_KERNEL_STATUS
//	TrackNewObj(POINTER_TO_UINT64(f), "FIFO", 0);
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWFIFO_COUNT);

	return f;
}

// Get the default memory reclaiming size of the FIFO
UINT GetFifoCurrentReallocMemSize()
{
	return fifo_current_realloc_mem_size;
}

// Set the default memory reclaiming size of the FIFO
void SetFifoCurrentReallocMemSize(UINT size)
{
	if (size == 0)
	{
		size = FIFO_REALLOC_MEM_SIZE;
	}

	fifo_current_realloc_mem_size = size;
}

// Read a buffer from a file
BUF *FileToBuf(IO *o)
{
	UCHAR hash1[MD5_SIZE], hash2[MD5_SIZE];
	UINT size;
	void *buf;
	BUF *b;

	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	// Read the size
	if (FileRead(o, &size, sizeof(size)) == false)
	{
		return NULL;
	}
	size = Endian32(size);

	if (size > FileSize(o))
	{
		return NULL;
	}

	// Read a hash
	if (FileRead(o, hash1, sizeof(hash1)) == false)
	{
		return NULL;
	}

	// Read from the buffer
	buf = Malloc(size);
	if (FileRead(o, buf, size) == false)
	{
		Free(buf);
		return NULL;
	}

	// Take a hash
	Hash(hash2, buf, size, false);

	// Compare the hashes
	if (Cmp(hash1, hash2, sizeof(hash1)) != 0)
	{
		// Hashes are different
		Free(buf);
		return NULL;
	}

	// Create a buffer
	b = NewBuf();
	WriteBuf(b, buf, size);
	Free(buf);
	b->Current = 0;

	return b;
}

// Read a dump file into a buffer
BUF *ReadDump(char *filename)
{
	return ReadDumpWithMaxSize(filename, 0);
}
BUF *ReadDumpWithMaxSize(char *filename, UINT max_size)
{
	IO *o;
	BUF *b;
	UINT size;
	void *data;
	// Validate arguments
	if (filename == NULL)
	{
		return NULL;
	}

	o = FileOpen(filename, false);
	if (o == NULL)
	{
		return NULL;
	}

	size = FileSize(o);

	if (max_size != 0)
	{
		if (size > max_size)
		{
			size = max_size;
		}
	}

	data = Malloc(size);
	FileRead(o, data, size);
	FileClose(o);

	b = NewBuf();
	WriteBuf(b, data, size);
	b->Current = 0;
	Free(data);

	return b;
}
BUF *ReadDumpW(wchar_t *filename)
{
	return ReadDumpExW(filename, true);
}
BUF *ReadDumpExW(wchar_t *filename, bool read_lock)
{
	IO *o;
	BUF *b;
	UINT size;
	void *data;
	// Validate arguments
	if (filename == NULL)
	{
		return NULL;
	}

	o = FileOpenExW(filename, false, read_lock);
	if (o == NULL)
	{
		return NULL;
	}

	size = FileSize(o);
	data = Malloc(size);
	FileRead(o, data, size);
	FileClose(o);

	b = NewBuf();
	WriteBuf(b, data, size);
	b->Current = 0;
	Free(data);

	return b;
}

// Write down the data
bool DumpDataW(void *data, UINT size, wchar_t *filename)
{
	IO *o;
	// Validate arguments
	if (filename == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	o = FileCreateW(filename);
	if (o == NULL)
	{
		return false;
	}
	FileWrite(o, data, size);
	FileClose(o);

	return true;
}
bool DumpData(void *data, UINT size, char *filename)
{
	IO *o;
	// Validate arguments
	if (filename == NULL || (size != 0 && data == NULL))
	{
		return false;
	}

	o = FileCreate(filename);
	if (o == NULL)
	{
		return false;
	}
	FileWrite(o, data, size);
	FileClose(o);

	return true;
}

// Dump the contents of the buffer to the file
bool DumpBuf(BUF *b, char *filename)
{
	IO *o;
	// Validate arguments
	if (b == NULL || filename == NULL)
	{
		return false;
	}

	o = FileCreate(filename);
	if (o == NULL)
	{
		return false;
	}
	FileWrite(o, b->Buf, b->Size);
	FileClose(o);

	return true;
}
bool DumpBufW(BUF *b, wchar_t *filename)
{
	IO *o;
	// Validate arguments
	if (b == NULL || filename == NULL)
	{
		return false;
	}

	o = FileCreateW(filename);
	if (o == NULL)
	{
		return false;
	}
	FileWrite(o, b->Buf, b->Size);
	FileClose(o);

	return true;
}

// Write to the file only if the contents of the file is different
bool DumpBufWIfNecessary(BUF *b, wchar_t *filename)
{
	BUF *now;
	bool need = true;
	// Validate arguments
	if (b == NULL || filename == NULL)
	{
		return false;
	}

	now = ReadDumpW(filename);

	if (now != NULL)
	{
		if (CompareBuf(now, b))
		{
			need = false;
		}

		FreeBuf(now);
	}

	if (need == false)
	{
		return true;
	}
	else
	{
		return DumpBufW(b, filename);
	}
}

// Write the buffer to a file
bool BufToFile(IO *o, BUF *b)
{
	UCHAR hash[MD5_SIZE];
	UINT size;

	// Validate arguments
	if (o == NULL || b == NULL)
	{
		return false;
	}

	// Hash the data
	Hash(hash, b->Buf, b->Size, false);

	size = Endian32(b->Size);

	// Write the size
	if (FileWrite(o, &size, sizeof(size)) == false)
	{
		return false;
	}

	// Write a hash
	if (FileWrite(o, hash, sizeof(hash)) == false)
	{
		return false;
	}

	// Write the data
	if (FileWrite(o, b->Buf, b->Size) == false)
	{
		return false;
	}

	return true;
}

// Create a buffer from memory
BUF *NewBufFromMemory(void *buf, UINT size)
{
	BUF *b;
	// Validate arguments
	if (buf == NULL && size != 0)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, buf, size);
	SeekBufToBegin(b);

	return b;
}

// Creating a buffer
BUF *NewBuf()
{
	BUF *b;

	// Memory allocation
	b = Malloc(sizeof(BUF));
	b->Buf = Malloc(INIT_BUF_SIZE);
	b->Size = 0;
	b->Current = 0;
	b->SizeReserved = INIT_BUF_SIZE;

#ifndef	DONT_USE_KERNEL_STATUS
//	TrackNewObj(POINTER_TO_UINT64(b), "BUF", 0);
#endif	// DONT_USE_KERNEL_STATUS

	// KS
	KS_INC(KS_NEWBUF_COUNT);
	KS_INC(KS_CURRENT_BUF_COUNT);

	return b;
}

// Clearing the buffer
void ClearBuf(BUF *b)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	b->Size = 0;
	b->Current = 0;
}

// Write to the buffer
void WriteBuf(BUF *b, void *buf, UINT size)
{
	UINT new_size;
	// Validate arguments
	if (b == NULL || buf == NULL || size == 0)
	{
		return;
	}

	new_size = b->Current + size;
	if (new_size > b->Size)
	{
		// Adjust the size
		AdjustBufSize(b, new_size);
	}
	if (b->Buf != NULL)
	{
		Copy((UCHAR *)b->Buf + b->Current, buf, size);
	}
	b->Current += size;
	b->Size = new_size;

	// KS
	KS_INC(KS_WRITE_BUF_COUNT);
}

// Append a string to the buffer
void AddBufStr(BUF *b, char *str)
{
	// Validate arguments
	if (b == NULL || str == NULL)
	{
		return;
	}

	WriteBuf(b, str, StrLen(str));
}

// Write a line to the buffer
void WriteBufLine(BUF *b, char *str)
{
	char *crlf = "\r\n";
	// Validate arguments
	if (b == NULL || str == NULL)
	{
		return;
	}

	WriteBuf(b, str, StrLen(str));
	WriteBuf(b, crlf, StrLen(crlf));
}

// Write a string to a buffer
bool WriteBufStr(BUF *b, char *str)
{
	UINT len;
	// Validate arguments
	if (b == NULL || str == NULL)
	{
		return false;
	}

	// String length
	len = StrLen(str);
	if (WriteBufInt(b, len + 1) == false)
	{
		return false;
	}

	// String body
	WriteBuf(b, str, len);

	return true;
}

// Read a string from the buffer
bool ReadBufStr(BUF *b, char *str, UINT size)
{
	UINT len;
	UINT read_size;
	// Validate arguments
	if (b == NULL || str == NULL || size == 0)
	{
		return false;
	}

	// Read the length of the string
	len = ReadBufInt(b);
	if (len == 0)
	{
		return false;
	}
	len--;
	if (len <= (size - 1))
	{
		size = len + 1;
	}

	read_size = MIN(len, (size - 1));

	// Read the string body
	if (ReadBuf(b, str, read_size) != read_size)
	{
		return false;
	}
	if (read_size < len)
	{
		ReadBuf(b, NULL, len - read_size);
	}
	str[read_size] = 0;

	return true;
}

// Write a 64 bit integer to the buffer
bool WriteBufInt64(BUF *b, UINT64 value)
{
	// Validate arguments
	if (b == NULL)
	{
		return false;
	}

	value = Endian64(value);

	WriteBuf(b, &value, sizeof(UINT64));
	return true;
}

// Write an integer in the the buffer
bool WriteBufInt(BUF *b, UINT value)
{
	// Validate arguments
	if (b == NULL)
	{
		return false;
	}

	value = Endian32(value);

	WriteBuf(b, &value, sizeof(UINT));
	return true;
}

// Write a UCHAR to the buffer
bool WriteBufChar(BUF *b, UCHAR uc)
{
	// Validate arguments
	if (b == NULL)
	{
		return false;
	}

	WriteBuf(b, &uc, 1);

	return true;
}

// Read a UCHAR from the buffer
UCHAR ReadBufChar(BUF *b)
{
	UCHAR uc;
	// Validate arguments
	if (b == NULL)
	{
		return 0;
	}

	if (ReadBuf(b, &uc, 1) != 1)
	{
		return 0;
	}

	return uc;
}

// Read a 64bit integer from the buffer
UINT64 ReadBufInt64(BUF *b)
{
	UINT64 value;
	// Validate arguments
	if (b == NULL)
	{
		return 0;
	}

	if (ReadBuf(b, &value, sizeof(UINT64)) != sizeof(UINT64))
	{
		return 0;
	}
	return Endian64(value);
}

// Read an integer from the buffer
UINT ReadBufInt(BUF *b)
{
	UINT value;
	// Validate arguments
	if (b == NULL)
	{
		return 0;
	}

	if (ReadBuf(b, &value, sizeof(UINT)) != sizeof(UINT))
	{
		return 0;
	}
	return Endian32(value);
}

// Write the buffer to a buffer
void WriteBufBuf(BUF *b, BUF *bb)
{
	// Validate arguments
	if (b == NULL || bb == NULL)
	{
		return;
	}

	WriteBuf(b, bb->Buf, bb->Size);
}

// Read into a buffer from the buffer
BUF *ReadBufFromBuf(BUF *b, UINT size)
{
	BUF *ret;
	UCHAR *data;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	data = Malloc(size);
	if (ReadBuf(b, data, size) != size)
	{
		Free(data);
		return NULL;
	}

	ret = NewBuf();
	WriteBuf(ret, data, size);
	SeekBuf(ret, 0, 0);

	Free(data);

	return ret;
}

// Read from the buffer
UINT ReadBuf(BUF *b, void *buf, UINT size)
{
	UINT size_read;
	// Validate arguments
	if (b == NULL || size == 0)
	{
		return 0;
	}

	if (b->Buf == NULL)
	{
		Zero(buf, size);
		return 0;
	}
	size_read = size;
	if ((b->Current + size) >= b->Size)
	{
		size_read = b->Size - b->Current;
		if (buf != NULL)
		{
			Zero((UCHAR *)buf + size_read, size - size_read);
		}
	}

	if (buf != NULL)
	{
		Copy(buf, (UCHAR *)b->Buf + b->Current, size_read);
	}

	b->Current += size_read;

	// KS
	KS_INC(KS_READ_BUF_COUNT);

	return size_read;
}

// Adjusting the buffer size
void AdjustBufSize(BUF *b, UINT new_size)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	if (b->SizeReserved >= new_size)
	{
		return;
	}

	while (b->SizeReserved < new_size)
	{
		b->SizeReserved = b->SizeReserved * 2;
	}
	b->Buf = ReAlloc(b->Buf, b->SizeReserved);

	// KS
	KS_INC(KS_ADJUST_BUFSIZE_COUNT);
}

// Seek to the beginning of the buffer
void SeekBufToBegin(BUF *b)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	SeekBuf(b, 0, 0);
}

// Seek to end of the buffer
void SeekBufToEnd(BUF *b)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	SeekBuf(b, b->Size, 0);
}

// Seek of the buffer
void SeekBuf(BUF *b, UINT offset, int mode)
{
	UINT new_pos;
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	if (mode == 0)
	{
		// Absolute position
		new_pos = offset;
	}
	else
	{
		if (mode > 0)
		{
			// Move Right
			new_pos = b->Current + offset;
		}
		else
		{
			// Move Left
			if (b->Current >= offset)
			{
				new_pos = b->Current - offset;
			}
			else
			{
				new_pos = 0;
			}
		}
	}
	b->Current = MAKESURE(new_pos, 0, b->Size);

	KS_INC(KS_SEEK_BUF_COUNT);
}

// Free the buffer
void FreeBuf(BUF *b)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	// Memory release
	Free(b->Buf);
	Free(b);

	// KS
	KS_INC(KS_FREEBUF_COUNT);
	KS_DEC(KS_CURRENT_BUF_COUNT);

#ifndef	DONT_USE_KERNEL_STATUS
//	TrackDeleteObj(POINTER_TO_UINT64(b));
#endif	// DONT_USE_KERNEL_STATUS
}

// Compare BUFs whether two are identical
bool CompareBuf(BUF *b1, BUF *b2)
{
	// Validate arguments
	if (b1 == NULL && b2 == NULL)
	{
		return true;
	}
	if (b1 == NULL || b2 == NULL)
	{
		return false;
	}

	if (b1->Size != b2->Size)
	{
		return false;
	}

	if (Cmp(b1->Buf, b2->Buf, b1->Size) != 0)
	{
		return false;
	}

	return true;
}

// Create a buffer from the memory area
BUF *MemToBuf(void *data, UINT size)
{
	BUF *b;
	// Validate arguments
	if (data == NULL && size != 0)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, data, size);
	SeekBuf(b, 0, 0);

	return b;
}

// Creating a random number buffer
BUF *RandBuf(UINT size)
{
	void *data = Malloc(size);
	BUF *ret;

	Rand(data, size);

	ret = MemToBuf(data, size);

	Free(data);

	return ret;
}

// Read the rest part of the buffer
BUF *ReadRemainBuf(BUF *b)
{
	UINT size;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	if (b->Size < b->Current)
	{
		return NULL;
	}

	size = b->Size - b->Current;

	return ReadBufFromBuf(b, size);
}

// Clone the buffer
BUF *CloneBuf(BUF *b)
{
	BUF *bb;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	bb = MemToBuf(b->Buf, b->Size);

	return bb;
}

// Endian conversion of Unicode string
void EndianUnicode(wchar_t *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);

	for (i = 0;i < len;i++)
	{
		str[i] = Endian16(str[i]);
	}
}

// Endian conversion 16bit
USHORT Endian16(USHORT src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap16(src);
	}
	else
	{
		return src;
	}
}

// Endian conversion 32bit
UINT Endian32(UINT src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap32(src);
	}
	else
	{
		return src;
	}
}

// Endian conversion 64bit
UINT64 Endian64(UINT64 src)
{
	int x = 1;
	if (*((char *)&x))
	{
		return Swap64(src);
	}
	else
	{
		return src;
	}
}

// Swap data of any
void Swap(void *buf, UINT size)
{
	UCHAR *tmp, *src;
	UINT i;
	// Validate arguments
	if (buf == NULL || size == 0)
	{
		return;
	}

	src = (UCHAR *)buf;
	tmp = Malloc(size);
	for (i = 0;i < size;i++)
	{
		tmp[size - i - 1] = src[i];
	}

	Copy(buf, tmp, size);
	Free(buf);
}

// 16bit swap
USHORT Swap16(USHORT value)
{
	USHORT r;
	((BYTE *)&r)[0] = ((BYTE *)&value)[1];
	((BYTE *)&r)[1] = ((BYTE *)&value)[0];
	return r;
}

// 32bit swap
UINT Swap32(UINT value)
{
	UINT r;
	((BYTE *)&r)[0] = ((BYTE *)&value)[3];
	((BYTE *)&r)[1] = ((BYTE *)&value)[2];
	((BYTE *)&r)[2] = ((BYTE *)&value)[1];
	((BYTE *)&r)[3] = ((BYTE *)&value)[0];
	return r;
}

// 64-bit swap
UINT64 Swap64(UINT64 value)
{
	UINT64 r;
	((BYTE *)&r)[0] = ((BYTE *)&value)[7];
	((BYTE *)&r)[1] = ((BYTE *)&value)[6];
	((BYTE *)&r)[2] = ((BYTE *)&value)[5];
	((BYTE *)&r)[3] = ((BYTE *)&value)[4];
	((BYTE *)&r)[4] = ((BYTE *)&value)[3];
	((BYTE *)&r)[5] = ((BYTE *)&value)[2];
	((BYTE *)&r)[6] = ((BYTE *)&value)[1];
	((BYTE *)&r)[7] = ((BYTE *)&value)[0];
	return r;
}

// Base64 encode
UINT Encode64(char *dst, char *src)
{
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	return B64_Encode(dst, src, StrLen(src));
}

// Base64 decoding
UINT Decode64(char *dst, char *src)
{
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	return B64_Decode(dst, src, StrLen(src));
}

// Base64 encode
int B64_Encode(char *set, char *source, int len)
{
	BYTE *src;
	int i,j;
	src = (BYTE *)source;
	j = 0;
	i = 0;
	if (!len)
	{
		return 0;
	}
	while (TRUE)
	{
		if (i >= len)
		{
			return j;
		}
		if (set)
		{
			set[j] = B64_CodeToChar((src[i]) >> 2);
		}
		if (i + 1 >= len)
		{
			if (set)
			{
				set[j + 1] = B64_CodeToChar((src[i] & 0x03) << 4);
				set[j + 2] = '=';
				set[j + 3] = '=';
			}
			return j + 4;
		}
		if (set)
		{
			set[j + 1] = B64_CodeToChar(((src[i] & 0x03) << 4) + ((src[i + 1] >> 4)));
		}
		if (i + 2 >= len)
		{
			if (set)
			{
				set[j + 2] = B64_CodeToChar((src[i + 1] & 0x0f) << 2);
				set[j + 3] = '=';
			}
			return j + 4;
		}
		if (set)
		{
			set[j + 2] = B64_CodeToChar(((src[i + 1] & 0x0f) << 2) + ((src[i + 2] >> 6)));
			set[j + 3] = B64_CodeToChar(src[i + 2] & 0x3f);
		}
		i += 3;
		j += 4;
	}
}

// Base64 decode
int B64_Decode(char *set, char *source, int len)
{
	int i,j;
	char a1,a2,a3,a4;
	char *src;
	int f1,f2,f3,f4;
	src = source;
	i = 0;
	j = 0;
	while (TRUE)
	{
		f1 = f2 = f3 = f4 = 0;
		if (i >= len)
		{
			break;
		}
		f1 = 1;
		a1 = B64_CharToCode(src[i]);
		if (a1 == -1)
		{
			f1 = 0;
		}
		if (i >= len + 1)
		{
			a2 = 0;
		}
		else
		{
			a2 = B64_CharToCode(src[i + 1]);
			f2 = 1;
			if (a2 == -1)
			{
				f2 = 0;
			}
		}
		if (i >= len + 2)
		{
			a3 = 0;
		}
		else
		{
			a3 = B64_CharToCode(src[i + 2]);
			f3 = 1;
			if (a3 == -1)
			{
				f3 = 0;
			}
		}
		if (i >= len + 3)
		{
			a4 = 0;
		}
		else
		{
			a4 = B64_CharToCode(src[i + 3]);
			f4 = 1;
			if (a4 == -1)
			{
				f4 = 0;
			}
		}
		if (f1 && f2)
		{
			if (set)
			{
				set[j] = (a1 << 2) + (a2 >> 4);
			}
			j++;
		}
		if (f2 && f3)
		{
			if (set)
			{
				set[j] = (a2 << 4) + (a3 >> 2);
			}
			j++;
		}
		if (f3 && f4)
		{
			if (set)
			{
				set[j] = (a3 << 6) + a4;
			}
			j++;
		}
		i += 4;
	}
	return j;
}

// Base64 : Convert a code to a character
char B64_CodeToChar(BYTE c)
{
	BYTE r;
	r = '=';
	if (c <= 0x19)
	{
		r = c + 'A';
	}
	if (c >= 0x1a && c <= 0x33)
	{
		r = c - 0x1a + 'a';
	}
	if (c >= 0x34 && c <= 0x3d)
	{
		r = c - 0x34 + '0';
	}
	if (c == 0x3e)
	{
		r = '+';
	}
	if (c == 0x3f)
	{
		r = '/';
	}
	return r;
}

// Base64 : Convert a character to a code
char B64_CharToCode(char c)
{
	if (c >= 'A' && c <= 'Z')
	{
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z')
	{
		return c - 'a' + 0x1a;
	}
	if (c >= '0' && c <= '9')
	{
		return c - '0' + 0x34;
	}
	if (c == '+')
	{
		return 0x3e;
	}
	if (c == '/')
	{
		return 0x3f;
	}
	if (c == '=')
	{
		return -1;
	}
	return 0;
}

// Malloc
void *Malloc(UINT size)
{
	return MallocEx(size, false);
}
void *MallocEx(UINT size, bool zero_clear_when_free)
{
	MEMTAG *tag;
	UINT real_size;

	real_size = CALC_MALLOCSIZE(size);

	tag = InternalMalloc(real_size);

	Zero(tag, sizeof(MEMTAG));
	tag->Magic = MEMTAG_MAGIC;
	tag->Size = size;
	tag->ZeroFree = zero_clear_when_free;

	return MEMTAG_TO_POINTER(tag);
}

// Get memory size
UINT GetMemSize(void *addr)
{
	MEMTAG *tag;
	// Validate arguments
	if (IS_NULL_POINTER(addr))
	{
		return 0;
	}

	tag = POINTER_TO_MEMTAG(addr);
	CheckMemTag(tag);

	return tag->Size;
}

// ReAlloc
void *ReAlloc(void *addr, UINT size)
{
	MEMTAG *tag;
	bool zerofree;
	// Validate arguments
	if (IS_NULL_POINTER(addr))
	{
		return NULL;
	}

	tag = POINTER_TO_MEMTAG(addr);
	CheckMemTag(tag);

	zerofree = tag->ZeroFree;

	if (tag->Size == size)
	{
		// No size change
		return addr;
	}
	else
	{
		if (zerofree)
		{
			// Size changed (zero clearing required)
			void *new_p = MallocEx(size, true);

			if (tag->Size <= size)
			{
				// Size expansion
				Copy(new_p, addr, tag->Size);
			}
			else
			{
				// Size reduction
				Copy(new_p, addr, size);
			}

			// Release the old block
			Free(addr);

			return new_p;
		}
		else
		{
			// Size changed
			MEMTAG *tag2 = InternalReAlloc(tag, CALC_MALLOCSIZE(size));

			Zero(tag2, sizeof(MEMTAG));
			tag2->Magic = MEMTAG_MAGIC;
			tag2->Size = size;

			return MEMTAG_TO_POINTER(tag2);
		}
	}
}

// Free
void Free(void *addr)
{
	MEMTAG *tag;
	// Validate arguments
	if (IS_NULL_POINTER(addr))
	{
		return;
	}

	tag = POINTER_TO_MEMTAG(addr);
	CheckMemTag(tag);

	if (tag->ZeroFree)
	{
		// Zero clear
		Zero(addr, tag->Size);
	}

	// Memory release
	tag->Magic = 0;
	InternalFree(tag);
}

// Check the memtag
void CheckMemTag(MEMTAG *tag)
{
#ifndef	DONT_CHECK_HEAP
	// Validate arguments
	if (tag == NULL)
	{
		AbortExitEx("CheckMemTag: tag == NULL");
		return;
	}

	if (tag->Magic != MEMTAG_MAGIC)
	{
		AbortExitEx("CheckMemTag: tag->Magic != MEMTAG_MAGIC");
		return;
	}
#endif	// DONT_CHECK_HEAP
}

// ZeroMalloc
void *ZeroMalloc(UINT size)
{
	return ZeroMallocEx(size, false);
}
void *ZeroMallocEx(UINT size, bool zero_clear_when_free)
{
	void *p = MallocEx(size, zero_clear_when_free);
	Zero(p, size);
	return p;
}

// Memory allocation
void *InternalMalloc(UINT size)
{
	void *addr;
	UINT retry = 0;
	size = MORE(size, 1);

	// KS
	KS_INC(KS_MALLOC_COUNT);
	KS_INC(KS_TOTAL_MEM_COUNT);
	KS_ADD(KS_TOTAL_MEM_SIZE, size);
	KS_INC(KS_CURRENT_MEM_COUNT);

	// Attempt to allocate memory until success
	while (true)
	{
		if ((retry++) > MEMORY_MAX_RETRY)
		{
			AbortExitEx("InternalMalloc: error: malloc() failed.\n\n");
		}
		addr = OSMemoryAlloc(size);
		if (addr != NULL)
		{
			break;
		}

		OSSleep(MEMORY_SLEEP_TIME);
	}

#ifndef	DONT_USE_KERNEL_STATUS
	TrackNewObj(POINTER_TO_UINT64(addr), "MEM", size);
#endif	//DONT_USE_KERNEL_STATUS

	return addr;
}

// Memory release
void InternalFree(void *addr)
{
	// Validate arguments
	if (addr == NULL)
	{
		return;
	}

	// KS
	KS_DEC(KS_CURRENT_MEM_COUNT);
	KS_INC(KS_FREE_COUNT);

#ifndef	DONT_USE_KERNEL_STATUS
	TrackDeleteObj(POINTER_TO_UINT64(addr));
#endif	// DONT_USE_KERNEL_STATUS

	// Memory release
	OSMemoryFree(addr);
}

// Memory reallocation
void *InternalReAlloc(void *addr, UINT size)
{
	void *new_addr;
	UINT retry = 0;
	size = MORE(size, 1);

	// KS
	KS_INC(KS_REALLOC_COUNT);
	KS_ADD(KS_TOTAL_MEM_SIZE, size);

	// Attempt to allocate memory until success
	while (true)
	{
		if ((retry++) > MEMORY_MAX_RETRY)
		{
			AbortExitEx("InternalReAlloc: error: realloc() failed.\n\n");
		}
		new_addr = OSMemoryReAlloc(addr, size);
		if (new_addr != NULL)
		{
			break;
		}

		OSSleep(MEMORY_SLEEP_TIME);
	}

#ifndef	DONT_USE_KERNEL_STATUS
	TrackChangeObjSize((DWORD)addr, size, (DWORD)new_addr);
#endif	// DONT_USE_KERNEL_STATUS

	return new_addr;
}

// Add the heading space to the memory area
void *AddHead(void *src, UINT src_size, void *head, UINT head_size)
{
	void *ret;
	UINT ret_size;
	// Validate arguments
	if ((src == NULL && src_size != 0) || (head == NULL && head_size != 0))
	{
		return NULL;
	}

	ret_size = src_size + head_size;

	ret = Malloc(ret_size);

	Copy(ret, head, head_size);

	Copy(((UCHAR *)ret) + head_size, src, src_size);

	return ret;
}

// Clone the memory area (only the tail)
void *CloneTail(void *src, UINT src_size, UINT dst_size)
{
	// Validate arguments
	if (src_size != 0 && src == NULL)
	{
		return NULL;
	}

	if (src_size >= dst_size)
	{
		return Clone(((UCHAR *)src) + (src_size - dst_size), dst_size);
	}
	else
	{
		return Clone(src, src_size);
	}
}

// Clone the memory area
void *Clone(void *addr, UINT size)
{
	void *ret;
	// Validate arguments
	if (addr == NULL)
	{
		return NULL;
	}

	ret = Malloc(size);
	Copy(ret, addr, size);

	return ret;
}

// Memory copy
void Copy(void *dst, void *src, UINT size)
{
	// Validate arguments
	if (dst == NULL || src == NULL || size == 0 || dst == src)
	{
		return;
	}

	// KS
	KS_INC(KS_COPY_COUNT);

	memcpy(dst, src, size);
}

// Memory comparison
int Cmp(void *p1, void *p2, UINT size)
{
	// Validate arguments
	if (p1 == NULL || p2 == NULL || size == 0)
	{
		return 0;
	}

	return memcmp(p1, p2, (size_t)size);
}

// Memory comparison (case-insensitive)
int CmpCaseIgnore(void *p1, void *p2, UINT size)
{
	UINT i;
	// Validate arguments
	if (p1 == NULL || p2 == NULL || size == 0)
	{
		return 0;
	}

	for (i = 0;i < size;i++)
	{
		char c1 = (char)(*(((UCHAR *)p1) + i));
		char c2 = (char)(*(((UCHAR *)p2) + i));

		c1 = ToUpper(c1);
		c2 = ToUpper(c2);

		if (c1 != c2)
		{
			return COMPARE_RET(c1, c2);
		}
	}

	return 0;
}

// Zero-clear of memory
void Zero(void *addr, UINT size)
{
	// Validate arguments
	if (addr == NULL || size == 0)
	{
		return;
	}

	// KS
	KS_INC(KS_ZERO_COUNT);

	memset(addr, 0, size);
}

// Compare the string map entries
int StrMapCmp(void *p1, void *p2)
{
	STRMAP_ENTRY *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(STRMAP_ENTRY **)p1;
	s2 = *(STRMAP_ENTRY **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}
	return StrCmpi(s1->Name, s2->Name);
}

// Create a string map (the data that can be searched by the string)
LIST *NewStrMap()
{
	return NewList(StrMapCmp);
}

// Search in string map
void *StrMapSearch(LIST *map, char *key)
{
	STRMAP_ENTRY tmp, *result;
	tmp.Name = key;
	result = (STRMAP_ENTRY*)Search(map, &tmp);
	if(result != NULL)
	{
		return result->Value;
	}
	return NULL;
}

// XOR the data
void XorData(void *dst, void *src1, void *src2, UINT size)
{
	UINT i;
	UCHAR *d, *c1, *c2;
	// Validate arguments
	if (dst == NULL || src1 == NULL || src2 == NULL || size == 0)
	{
		return;
	}

	d = (UCHAR *)dst;
	c1 = (UCHAR *)src1;
	c2 = (UCHAR *)src2;

	for (i = 0;i < size;i++)
	{
		*d = (*c1) ^ (*c2);

		d++;
		c1++;
		c2++;
	}
}

// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
