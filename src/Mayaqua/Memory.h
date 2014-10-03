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


// Memory.h
// Header of Memory.c

#ifndef	MEMORY_H
#define	MEMORY_H

// MallocFast (not implemented)
#define	MallocFast		Malloc
#define	ZeroMallocFast	ZeroMalloc

// Memory size that can be passed to the kernel at a time
#define	MAX_SEND_BUF_MEM_SIZE				(10 * 1024 * 1024)

// The magic number for memory tag
#define	MEMTAG_MAGIC						0x49414449

#define	CALC_MALLOCSIZE(size)				((MAX(size, 1)) + sizeof(MEMTAG))
#define	MEMTAG_TO_POINTER(p)				((void *)(((UCHAR *)(p)) + sizeof(MEMTAG)))
#define	POINTER_TO_MEMTAG(p)				((MEMTAG *)(((UCHAR *)(p)) - sizeof(MEMTAG)))
#define	IS_NULL_POINTER(p)					(((p) == NULL) || ((POINTER_TO_UINT64(p) == (UINT64)sizeof(MEMTAG))))

// Fixed size of a block of memory pool
#define	MEMPOOL_MAX_SIZE					3000


// Memory tag
struct MEMTAG
{
	UINT Magic;
	UINT Size;
	bool ZeroFree;
	UINT Padding;
};

// Buffer
struct BUF
{
	void *Buf;
	UINT Size;
	UINT SizeReserved;
	UINT Current;
};

// FIFO
struct FIFO
{
	REF *ref;
	LOCK *lock;
	void *p;
	UINT pos, size, memsize;
	UINT64 total_read_size;
	UINT64 total_write_size;
};

// List
struct LIST
{
	REF *ref;
	UINT num_item, num_reserved;
	void **p;
	LOCK *lock;
	COMPARE *cmp;
	bool sorted;
	UINT64 Param1;
};

// Queue
struct QUEUE
{
	REF *ref;
	UINT num_item;
	FIFO *fifo;
	LOCK *lock;
};

// Stack
struct SK
{
	REF *ref;
	UINT num_item, num_reserved;
	void **p;
	LOCK *lock;
	bool no_compact;
};

// Candidate list
struct CANDIDATE
{
	wchar_t *Str;						// String
	UINT64 LastSelectedTime;			// Date and time last selected
};

struct STRMAP_ENTRY
{
	char *Name;
	void *Value;
};

// Shared buffer
struct SHARED_BUFFER
{
	REF *Ref;
	void *Data;
	UINT Size;
};

// Macro
#define	LIST_DATA(o, i)		(((o) != NULL) ? ((o)->p[(i)]) : NULL)
#define	LIST_NUM(o)			(((o) != NULL) ? (o)->num_item : 0)
#define	HASH_LIST_NUM(o)	(((o) != NULL) ? (o)->NumItems : 0)

// Function pointer type to get a hash function
typedef UINT (GET_HASH)(void *p);

// Hash list
struct HASH_LIST
{
	UINT Bits;
	UINT Size;
	GET_HASH *GetHashProc;
	COMPARE *CompareProc;
	LOCK *Lock;
	REF *Ref;
	LIST **Entries;
	UINT NumItems;
	LIST *AllList;
};

// Function prototype
HASH_LIST *NewHashList(GET_HASH *get_hash_proc, COMPARE *compare_proc, UINT bits, bool make_list);
void ReleaseHashList(HASH_LIST *h);
void CleanupHashList(HASH_LIST *h);
void AddHash(HASH_LIST *h, void *p);
bool DeleteHash(HASH_LIST *h, void *p);
void *SearchHash(HASH_LIST *h, void *t);
UINT CalcHashForHashList(HASH_LIST *h, void *p);
void **HashListToArray(HASH_LIST *h, UINT *num);
void LockHashList(HASH_LIST *h);
void UnlockHashList(HASH_LIST *h);
bool IsInHashListKey(HASH_LIST *h, UINT key);
void *HashListKeyToPointer(HASH_LIST *h, UINT key);

LIST *NewCandidateList();
void FreeCandidateList(LIST *o);
int ComapreCandidate(void *p1, void *p2);
void AddCandidate(LIST *o, wchar_t *str, UINT num_max);
BUF *CandidateToBuf(LIST *o);
LIST *BufToCandidate(BUF *b);

void *Malloc(UINT size);
void *MallocEx(UINT size, bool zero_clear_when_free);
void *ZeroMalloc(UINT size);
void *ZeroMallocEx(UINT size, bool zero_clear_when_free);
void *ReAlloc(void *addr, UINT size);
void Free(void *addr);
void CheckMemTag(MEMTAG *tag);
UINT GetMemSize(void *addr);

void *InternalMalloc(UINT size);
void *InternalReAlloc(void *addr, UINT size);
void InternalFree(void *addr);

void Copy(void *dst, void *src, UINT size);
int Cmp(void *p1, void *p2, UINT size);
int CmpCaseIgnore(void *p1, void *p2, UINT size);
void ZeroMem(void *addr, UINT size);
void Zero(void *addr, UINT size);
void *Clone(void *addr, UINT size);
void *CloneTail(void *src, UINT src_size, UINT dst_size);
void *AddHead(void *src, UINT src_size, void *head, UINT head_size);

char B64_CodeToChar(BYTE c);
char B64_CharToCode(char c);
int B64_Encode(char *set, char *source, int len);
int B64_Decode(char *set, char *source, int len);
UINT Encode64(char *dst, char *src);
UINT Decode64(char *dst, char *src);

void Swap(void *buf, UINT size);
USHORT Swap16(USHORT value);
UINT Swap32(UINT value);
UINT64 Swap64(UINT64 value);
USHORT Endian16(USHORT src);
UINT Endian32(UINT src);
UINT64 Endian64(UINT64 src);
void EndianUnicode(wchar_t *str);

BUF *NewBuf();
BUF *NewBufFromMemory(void *buf, UINT size);
void ClearBuf(BUF *b);
void WriteBuf(BUF *b, void *buf, UINT size);
void WriteBufBuf(BUF *b, BUF *bb);
UINT ReadBuf(BUF *b, void *buf, UINT size);
BUF *ReadBufFromBuf(BUF *b, UINT size);
void AdjustBufSize(BUF *b, UINT new_size);
void SeekBuf(BUF *b, UINT offset, int mode);
void SeekBufToEnd(BUF *b);
void SeekBufToBegin(BUF *b);
void FreeBuf(BUF *b);
bool BufToFile(IO *o, BUF *b);
BUF *FileToBuf(IO *o);
UINT ReadBufInt(BUF *b);
UINT64 ReadBufInt64(BUF *b);
UCHAR ReadBufChar(BUF *b);
bool WriteBufInt(BUF *b, UINT value);
bool WriteBufInt64(BUF *b, UINT64 value);
bool WriteBufChar(BUF *b, UCHAR uc);
bool ReadBufStr(BUF *b, char *str, UINT size);
bool WriteBufStr(BUF *b, char *str);
void WriteBufLine(BUF *b, char *str);
void AddBufStr(BUF *b, char *str);
bool DumpBuf(BUF *b, char *filename);
bool DumpBufW(BUF *b, wchar_t *filename);
bool DumpBufWIfNecessary(BUF *b, wchar_t *filename);
bool DumpData(void *data, UINT size, char *filename);
bool DumpDataW(void *data, UINT size, wchar_t *filename);
BUF *ReadDump(char *filename);
BUF *ReadDumpWithMaxSize(char *filename, UINT max_size);
BUF *ReadDumpW(wchar_t *filename);
BUF *ReadDumpExW(wchar_t *filename, bool read_lock);
BUF *CloneBuf(BUF *b);
BUF *MemToBuf(void *data, UINT size);
BUF *RandBuf(UINT size);
BUF *ReadRemainBuf(BUF *b);
bool CompareBuf(BUF *b1, BUF *b2);

UINT PeekFifo(FIFO *f, void *p, UINT size);
UINT ReadFifo(FIFO *f, void *p, UINT size);
void ShrinkFifoMemory(FIFO *f);
UCHAR *GetFifoPointer(FIFO *f);
UCHAR *FifoPtr(FIFO *f);
void WriteFifo(FIFO *f, void *p, UINT size);
void ClearFifo(FIFO *f);
UINT FifoSize(FIFO *f);
void LockFifo(FIFO *f);
void UnlockFifo(FIFO *f);
void ReleaseFifo(FIFO *f);
void CleanupFifo(FIFO *f);
FIFO *NewFifo();
FIFO *NewFifoFast();
FIFO *NewFifoEx(bool fast);
void InitFifo();
UINT GetFifoCurrentReallocMemSize();
void SetFifoCurrentReallocMemSize(UINT size);

void *Search(LIST *o, void *target);
void Sort(LIST *o);
void SortEx(LIST *o, COMPARE *cmp);
void Add(LIST *o, void *p);
void AddDistinct(LIST *o, void *p);
void Insert(LIST *o, void *p);
void InsertDistinct(LIST *o, void *p);
bool Delete(LIST *o, void *p);
bool DeleteKey(LIST *o, UINT key);
void DeleteAll(LIST *o);
void LockList(LIST *o);
void UnlockList(LIST *o);
void ReleaseList(LIST *o);
void CleanupList(LIST *o);
LIST *NewList(COMPARE *cmp);
LIST *NewListFast(COMPARE *cmp);
LIST *NewListEx(COMPARE *cmp, bool fast);
LIST *NewListEx2(COMPARE *cmp, bool fast, bool fast_malloc);
LIST *NewListSingle(void *p);
void CopyToArray(LIST *o, void *p);
void *ToArray(LIST *o);
void *ToArrayEx(LIST *o, bool fast);
LIST *CloneList(LIST *o);
void SetCmp(LIST *o, COMPARE *cmp);
void SetSortFlag(LIST *o, bool sorted);
int CompareStr(void *p1, void *p2);
bool InsertStr(LIST *o, char *str);
int CompareUniStr(void *p1, void *p2);
bool IsInList(LIST *o, void *p);
bool IsInListKey(LIST *o, UINT key);
void *ListKeyToPointer(LIST *o, UINT key);
bool IsInListStr(LIST *o, char *str);
bool IsInListUniStr(LIST *o, wchar_t *str);
bool ReplaceListPointer(LIST *o, void *oldptr, void *newptr);
void AddInt(LIST *o, UINT i);
void AddInt64(LIST *o, UINT64 i);
void AddIntDistinct(LIST *o, UINT i);
void AddInt64Distinct(LIST *o, UINT64 i);
void DelInt(LIST *o, UINT i);
void DelInt64(LIST *o, UINT64 i);
void ReleaseIntList(LIST *o);
void ReleaseInt64List(LIST *o);
void DelAllInt(LIST *o);
bool IsIntInList(LIST *o, UINT i);
bool IsInt64InList(LIST *o, UINT64 i);
LIST *NewIntList(bool sorted);
LIST *NewInt64List(bool sorted);
int CompareInt(void *p1, void *p2);
int CompareInt64(void *p1, void *p2);
void InsertInt(LIST *o, UINT i);
void InsertInt64(LIST *o, UINT64 i);
void InsertIntDistinct(LIST *o, UINT i);
void InsertInt64Distinct(LIST *o, UINT64 i);
void RandomizeList(LIST *o);

void *GetNext(QUEUE *q);
void *GetNextWithLock(QUEUE *q);
void *PeekQueue(QUEUE *q);
void InsertQueue(QUEUE *q, void *p);
void InsertQueueWithLock(QUEUE *q, void *p);
void InsertQueueInt(QUEUE *q, UINT value);
void LockQueue(QUEUE *q);
void UnlockQueue(QUEUE *q);
void ReleaseQueue(QUEUE *q);
void CleanupQueue(QUEUE *q);
QUEUE *NewQueue();
QUEUE *NewQueueFast();
UINT GetQueueNum(QUEUE *q);

SK *NewSk();
SK *NewSkEx(bool no_compact);
void ReleaseSk(SK *s);
void CleanupSk(SK *s);
void LockSk(SK *s);
void UnlockSk(SK *s);
void Push(SK *s, void *p);
void *Pop(SK *s);

UINT Uncompress(void *dst, UINT dst_size, void *src, UINT src_size);
UINT Compress(void *dst, UINT dst_size, void *src, UINT src_size);
UINT CompressEx(void *dst, UINT dst_size, void *src, UINT src_size, UINT level);
UINT CalcCompress(UINT src_size);
BUF *CompressBuf(BUF *src_buf);
BUF *UncompressBuf(BUF *src_buf);

bool IsZero(void *data, UINT size);
void FillBytes(void *data, UINT size, UCHAR c);

LIST *NewStrMap();
void *StrMapSearch(LIST *map, char *key);

UINT SearchBin(void *data, UINT data_start, UINT data_size, void *key, UINT key_size);
void CrashNow();
UINT Power(UINT a, UINT b);

void XorData(void *dst, void *src1, void *src2, UINT size);

SHARED_BUFFER *NewSharedBuffer(void *data, UINT size);
void ReleaseSharedBuffer(SHARED_BUFFER *b);
void CleanupSharedBuffer(SHARED_BUFFER *b);

void AppendBufUtf8(BUF *b, wchar_t *str);
void AppendBufStr(BUF *b, char *str);

#endif	// MEMORY_H


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
