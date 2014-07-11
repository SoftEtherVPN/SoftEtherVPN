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


// FileIO.c
// File Input / Output code

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

static char exe_file_name[MAX_SIZE] = "/tmp/a.out";
static wchar_t exe_file_name_w[MAX_SIZE] = L"/tmp/a.out";
static LIST *hamcore = NULL;
static IO *hamcore_io = NULL;

#define	NUM_CRC32_TABLE	256
static UINT crc32_table[NUM_CRC32_TABLE];

// Confirm that the specified string exists as a line
bool IsInLines(BUF *buf, char *str, bool instr)
{
	bool ret = false;
	// Validate arguments
	if (buf == NULL || str == NULL)
	{
		return false;
	}

	if (IsEmptyStr(str))
	{
		return false;
	}

	SeekBufToBegin(buf);

	while (ret == false)
	{
		char *line = CfgReadNextLine(buf);

		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false)
		{
			if (StrCmpi(line, str) == 0)
			{
				ret = true;
			}

			if (instr)
			{
				if (InStr(str, line))
				{
					ret = true;
				}

				if (InStr(line, str))
				{
					ret = true;
				}
			}
		}

		Free(line);
	}

	return ret;
}
bool IsInLinesFile(wchar_t *filename, char *str, bool instr)
{
	bool ret = false;
	BUF *b;
	// Validate arguments
	if (filename == NULL || str == NULL)
	{
		return false;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		return false;
	}

	ret = IsInLines(b, str, instr);

	FreeBuf(b);

	return ret;
}

// Check whether the file is write-locked
bool IsFileWriteLockedW(wchar_t *name)
{
	IO *io;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (IsFileExistsW(name) == false)
	{
		return false;
	}

	io = FileOpenW(name, true);
	if (io == NULL)
	{
		return true;
	}

	FileClose(io);

	return false;
}
bool IsFileWriteLocked(char *name)
{
	bool ret;
	wchar_t *tmp;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	tmp = CopyStrToUni(name);

	ret = IsFileWriteLockedW(tmp);

	Free(tmp);

	return ret;
}

// Creating a ZIP packer
ZIP_PACKER *NewZipPacker()
{
	ZIP_PACKER *p = ZeroMalloc(sizeof(ZIP_PACKER));

	p->Fifo = NewFifo();
	p->FileList = NewList(NULL);
	p->CurrentFile = NULL;

	return p;
}

// Release of ZIP packer
void FreeZipPacker(ZIP_PACKER *p)
{
	UINT i;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	ReleaseFifo(p->Fifo);

	for (i = 0;i < LIST_NUM(p->FileList);i++)
	{
		ZIP_FILE *f = LIST_DATA(p->FileList, i);

		Free(f);
	}

	ReleaseList(p->FileList);

	Free(p);
}

// Simply add the file
void ZipAddFileSimple(ZIP_PACKER *p, char *name, UINT64 dt, UINT attribute, void *data, UINT size)
{
	// Validate arguments
	if (p == NULL || IsEmptyStr(name) || (size != 0 && data == NULL))
	{
		return;
	}

	ZipAddFileStart(p, name, size, dt, attribute);
	ZipAddFileData(p, data, 0, size);
}
bool ZipAddRealFileW(ZIP_PACKER *p, char *name, UINT64 dt, UINT attribute, wchar_t *srcname)
{
	BUF *b;
	// Validate arguments
	if (p == NULL || IsEmptyStr(name) || srcname == NULL)
	{
		return false;
	}

	b = ReadDumpW(srcname);
	if (b == NULL)
	{
		return false;
	}

	ZipAddFileSimple(p, name, dt, attribute, b->Buf, b->Size);

	FreeBuf(b);

	return true;
}
bool ZipAddRealFile(ZIP_PACKER *p, char *name, UINT64 dt, UINT attribute, char *srcname)
{
	bool ret = false;
	wchar_t *s;

	s = CopyStrToUni(srcname);

	ret = ZipAddRealFileW(p, name, dt, attribute, s);

	Free(s);

	return ret;
}

// Start adding a file
void ZipAddFileStart(ZIP_PACKER *p, char *name, UINT size, UINT64 dt, UINT attribute)
{
	char tmp[MAX_PATH];
	ZIP_FILE *f;
	ZIP_DATA_HEADER h;
	// Validate arguments
	if (p == NULL || IsEmptyStr(name))
	{
		return;
	}
	if (dt == 0)
	{
		dt = LocalTime64();
	}

	if (p->CurrentFile != NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), name);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "/", "\\", true);

	f = ZeroMalloc(sizeof(ZIP_FILE));

	StrCpy(f->Name, sizeof(f->Name), tmp);
	f->Size = size;
	f->DateTime = dt;
	f->Attributes = attribute;

	Add(p->FileList, f);

	Zero(&h, sizeof(h));
	f->HeaderPos = (UINT)p->Fifo->total_write_size;
	WriteZipDataHeader(f, &h, false);
	WriteFifo(p->Fifo, &h, sizeof(h));
	WriteFifo(p->Fifo, f->Name, StrLen(f->Name));
	f->Crc32 = 0xffffffff;

	p->CurrentFile = f;
}

// Add data to the file
UINT ZipAddFileData(ZIP_PACKER *p, void *data, UINT pos, UINT len)
{
	UINT total_size = p->CurrentFile->CurrentSize + len;
	UINT ret;
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}
	if (total_size > p->CurrentFile->Size)
	{
		return 0;
	}

	WriteFifo(p->Fifo, ((UCHAR *)data) + pos, len);

	p->CurrentFile->CurrentSize += len;
	p->CurrentFile->Crc32 = Crc32Next(data, pos, len, p->CurrentFile->Crc32);

	ret = p->CurrentFile->Size - p->CurrentFile->CurrentSize;

	if (ret == 0)
	{
		p->CurrentFile->Crc32 = ~p->CurrentFile->Crc32;

		ZipAddFileFooter(p);

		p->CurrentFile = NULL;
	}

	return ret;
}

// Append a file footer
void ZipAddFileFooter(ZIP_PACKER *p)
{
	ZIP_DATA_FOOTER f;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	Zero(&f, sizeof(f));
	WriteZipDataFooter(p->CurrentFile, &f);

	WriteFifo(p->Fifo, &f, sizeof(f));
}

// Output the ZIP data to a file
bool ZipWriteW(ZIP_PACKER *p, wchar_t *name)
{
	FIFO *f;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return false;
	}

	f = ZipFinish(p);
	if (f == NULL)
	{
		return false;
	}

	return FileWriteAllW(name, FifoPtr(f), FifoSize(f));
}

// Complete the creation of the ZIP data
FIFO *ZipFinish(ZIP_PACKER *p)
{
	UINT i;
	UINT pos_start;
	UINT pos_end;
	ZIP_END_HEADER e;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	pos_start = (UINT)p->Fifo->total_write_size;

	for (i = 0;i < LIST_NUM(p->FileList);i++)
	{
		ZIP_FILE *f = LIST_DATA(p->FileList, i);
		ZIP_DIR_HEADER d;
		ZIP_DATA_HEADER dh;

		Zero(&d, sizeof(d));
		Zero(&dh, sizeof(dh));

		d.Signature = Endian32(Swap32(0x02014B50));
		d.MadeVer = Endian16(Swap16(ZIP_VERSION));

		WriteZipDataHeader(f, &dh, true);

		d.NeedVer = dh.NeedVer;
		d.Option = dh.Option;
		d.CompType = dh.CompType;
		d.FileTime = dh.FileTime;
		d.FileDate = dh.FileDate;
		d.Crc32 = dh.Crc32;
		d.CompSize = dh.CompSize;
		d.UncompSize = dh.UncompSize;
		d.FileNameLen = dh.FileNameLen;
		d.ExtraLen = dh.ExtraLen;
		d.CommentLen = 0;
		d.DiskNum = 0;
		d.InAttr = 0;
		d.OutAttr = Endian32(Swap32((USHORT)f->Attributes));
		d.HeaderPos = Endian32(Swap32(f->HeaderPos));

		WriteFifo(p->Fifo, &d, sizeof(d));
		WriteFifo(p->Fifo, f->Name, StrLen(f->Name));
	}

	pos_end = (UINT)p->Fifo->total_write_size;

	Zero(&e, sizeof(e));
	e.Signature = Endian32(Swap32(ZIP_SIGNATURE_END));
	e.DiskNum = e.StartDiskNum = 0;
	e.DiskDirEntry = e.DirEntry = Endian16(Swap16((USHORT)LIST_NUM(p->FileList)));
	e.DirSize = Endian32(Swap32((UINT)(pos_end - pos_start)));
	e.StartPos = Endian32(Swap32(pos_start));
	e.CommentLen = 0;

	WriteFifo(p->Fifo, &e, sizeof(e));

	return p->Fifo;
}

// Creating a ZIP data header
void WriteZipDataHeader(ZIP_FILE *f, ZIP_DATA_HEADER *h, bool write_sizes)
{
	// Validate arguments
	if (f == NULL || h ==NULL)
	{
		return;
	}

	h->Signature = Endian32(Swap32(ZIP_SIGNATURE));
	h->NeedVer = Endian16(Swap16(ZIP_VERSION));
	h->CompType = 0;
	h->FileDate = Endian16(Swap16(System64ToDosDate(f->DateTime)));
	h->FileTime = Endian16(Swap16(System64ToDosTime(f->DateTime)));
	h->Option = Endian16(Swap16(8)); // bit3: Set the file-size and the CRC in local header to 0

	if (write_sizes == false)
	{
		h->CompSize = h->UncompSize = 0;
		h->Crc32 = 0;
	}
	else
	{
		h->CompSize = h->UncompSize = Endian32(Swap32(f->Size));
		h->Crc32 = Endian32(Swap32(f->Crc32));
	}

	h->FileNameLen = Endian16(Swap16(StrLen(f->Name)));
	h->ExtraLen = 0;
}

// Creating a ZIP data footer
void WriteZipDataFooter(ZIP_FILE *f, ZIP_DATA_FOOTER *h)
{
	// Validate arguments
	if (f == NULL || h ==NULL)
	{
		return;
	}

	h->Signature = Endian32(Swap32(0x08074B50));
	h->CompSize = h->UncompSize = Endian32(Swap32(f->Size));
	h->Crc32 = Endian32(Swap32(f->Crc32));
}

// Initialize the common table of CRC32
void InitCrc32()
{
	UINT poly = 0xEDB88320;
	UINT u, i, j;

	for (i = 0;i < 256;i++)
	{
		u = i;

		for (j = 0;j < 8;j++)
		{
			if ((u & 0x1) != 0)
			{
				u = (u >> 1) ^ poly;
			}
			else
			{
				u >>= 1;
			}
		}

		crc32_table[i] = u;
	}
}

// CRC32 arithmetic processing
UINT Crc32(void *buf, UINT pos, UINT len)
{
	return Crc32Finish(Crc32First(buf, pos, len));
}
UINT Crc32First(void *buf, UINT pos, UINT len)
{
	return Crc32Next(buf, pos, len, 0xffffffff);
}
UINT Crc32Next(void *buf, UINT pos, UINT len, UINT last_crc32)
{
	UINT ret = last_crc32;
	UINT i;

	for (i = 0;i < len;i++)
	{
		ret = (ret >> 8) ^ crc32_table[((UCHAR *)buf)[pos + i] ^ (ret & 0xff)];
	}

	return ret;
}
UINT Crc32Finish(UINT last_crc32)
{
	return ~last_crc32;
}

// Save the file
bool SaveFileW(wchar_t *name, void *data, UINT size)
{
	IO *io;
	// Validate arguments
	if (name == NULL || (data == NULL && size != 0))
	{
		return false;
	}

	io = FileCreateW(name);
	if (io == NULL)
	{
		return false;
	}

	if (FileWrite(io, data, size) == false)
	{
		FileClose(io);
		return false;
	}

	FileClose(io);

	return true;
}
bool SaveFile(char *name, void *data, UINT size)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = SaveFileW(name_w, data, size);

	Free(name_w);

	return ret;
}

// Check whether the file exists
bool IsFile(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = IsFileW(name_w);

	Free(name_w);

	return ret;
}
bool IsFileW(wchar_t *name)
{
	IO *io;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	io = FileOpenExW(name, false, false);
	if (io == NULL)
	{
		return false;
	}

	FileClose(io);

	return true;
}

// Rename to replace the file
bool FileReplaceRename(char *old_name, char *new_name)
{
	wchar_t *old_name_w = CopyStrToUni(old_name);
	wchar_t *new_name_w = CopyStrToUni(new_name);
	bool ret = FileReplaceRenameW(old_name_w, new_name_w);

	Free(old_name_w);
	Free(new_name_w);

	return ret;
}
bool FileReplaceRenameW(wchar_t *old_name, wchar_t *new_name)
{
	// Validate arguments
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	if (FileCopyW(old_name, new_name) == false)
	{
		return false;
	}

	FileDeleteW(old_name);

	return true;
}

// Make the file name safe
void ConvertSafeFileName(char *dst, UINT size, char *src)
{
	UINT i;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	StrCpy(dst, size, src);
	for (i = 0;i < StrLen(dst);i++)
	{
		if (IsSafeChar(dst[i]) == false)
		{
			dst[i] = '_';
		}
	}
}
void ConvertSafeFileNameW(wchar_t *dst, UINT size, wchar_t *src)
{
	UINT i;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	UniStrCpy(dst, size, src);
	for (i = 0;i < UniStrLen(dst);i++)
	{
		if (UniIsSafeChar(dst[i]) == false)
		{
			dst[i] = L'_';
		}
	}
}

// Get the free disk space
bool GetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
	bool ret;
	// Validate arguments
	if (path == NULL)
	{
		path = "./";
	}

#ifdef	OS_WIN32
	ret = Win32GetDiskFree(path, free_size, used_size, total_size);
#else	// OS_WIN32
	ret = UnixGetDiskFree(path, free_size, used_size, total_size);
#endif	// OS_WIN32

	return ret;
}
bool GetDiskFreeW(wchar_t *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
	bool ret;
	// Validate arguments
	if (path == NULL)
	{
		path = L"./";
	}

#ifdef	OS_WIN32
	ret = Win32GetDiskFreeW(path, free_size, used_size, total_size);
#else	// OS_WIN32
	ret = UnixGetDiskFreeW(path, free_size, used_size, total_size);
#endif	// OS_WIN32

	return ret;
}

// Enumeration of direction with all sub directories
TOKEN_LIST *EnumDirWithSubDirs(char *dirname)
{
	TOKEN_LIST *ret;
	UNI_TOKEN_LIST *ret2;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (dirname == NULL)
	{
		dirname = "./";
	}

	StrToUni(tmp, sizeof(tmp), dirname);

	ret2 = EnumDirWithSubDirsW(tmp);

	ret = UniTokenListToTokenList(ret2);

	UniFreeToken(ret2);

	return ret;
}
UNI_TOKEN_LIST *EnumDirWithSubDirsW(wchar_t *dirname)
{
	ENUM_DIR_WITH_SUB_DATA d;
	UNI_TOKEN_LIST *ret;
	UINT i;
	// Validate arguments
	if (dirname == NULL)
	{
		dirname = L"./";
	}

	Zero(&d, sizeof(d));

	d.FileList = NewListFast(NULL);

	EnumDirWithSubDirsMain(&d, dirname);

	ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));

	ret->NumTokens = LIST_NUM(d.FileList);
	ret->Token = ZeroMalloc(sizeof(wchar_t *) * ret->NumTokens);

	for (i = 0;i < ret->NumTokens;i++)
	{
		wchar_t *s = LIST_DATA(d.FileList, i);

		ret->Token[i] = UniCopyStr(s);
	}

	FreeStrList(d.FileList);

	return ret;
}
void EnumDirWithSubDirsMain(ENUM_DIR_WITH_SUB_DATA *d, wchar_t *dirname)
{
	DIRLIST *dir;
	UINT i;
	// Validate arguments
	if (d == NULL || dirname == NULL)
	{
		return;
	}

	dir = EnumDirExW(dirname, NULL);
	if (dir == NULL)
	{
		return;
	}

	// Files
	for (i = 0;i < dir->NumFiles;i++)
	{
		DIRENT *e = dir->File[i];

		if (e->Folder == false)
		{
			wchar_t tmp[MAX_SIZE];

			ConbinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

			Add(d->FileList, CopyUniStr(tmp));
		}
	}

	// Sub directories
	for (i = 0;i < dir->NumFiles;i++)
	{
		DIRENT *e = dir->File[i];

		if (e->Folder)
		{
			wchar_t tmp[MAX_SIZE];

			ConbinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

			EnumDirWithSubDirsMain(d, tmp);
		}
	}

	FreeDir(dir);
}

// Enumeration of directory
DIRLIST *EnumDirEx(char *dirname, COMPARE *compare)
{
	wchar_t *dirname_w = CopyStrToUni(dirname);
	DIRLIST *ret = EnumDirExW(dirname_w, compare);

	Free(dirname_w);

	return ret;
}
DIRLIST *EnumDirExW(wchar_t *dirname, COMPARE *compare)
{
	DIRLIST *d = NULL;
	// Validate arguments
	if (dirname == NULL)
	{
		dirname = L"./";
	}

	if (compare == NULL)
	{
		compare = CompareDirListByName;
	}

#ifdef	OS_WIN32
	d = Win32EnumDirExW(dirname, compare);
#else	// OS_WIN32
	d = UnixEnumDirExW(dirname, compare);
#endif	// OS_WIN32

	return d;
}
DIRLIST *EnumDir(char *dirname)
{
	return EnumDirEx(dirname, NULL);
}
DIRLIST *EnumDirW(wchar_t *dirname)
{
	return EnumDirExW(dirname, NULL);
}

// Comparison of DIRLIST list entry
int CompareDirListByName(void *p1, void *p2)
{
	DIRENT *d1, *d2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	d1 = *(DIRENT **)p1;
	d2 = *(DIRENT **)p2;
	if (d1 == NULL || d2 == NULL)
	{
		return 0;
	}
	return UniStrCmpi(d1->FileNameW, d2->FileNameW);
}

// Release the enumeration of the directory 
void FreeDir(DIRLIST *d)
{
	UINT i;
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	for (i = 0;i < d->NumFiles;i++)
	{
		DIRENT *f = d->File[i];
		Free(f->FileName);
		Free(f->FileNameW);
		Free(f);
	}
	Free(d->File);
	Free(d);
}


// Make the file name safe
void UniSafeFileName(wchar_t *name)
{
	UINT i, len, dlen;
	static wchar_t *danger_str = L"\\/:*?\"<>|";
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	dlen = UniStrLen(danger_str);
	len = UniStrLen(name);

	for (i = 0;i < len;i++)
	{
		wchar_t c = name[i];
		UINT j;
		for (j = 0;j < dlen;j++)
		{
			if (c == danger_str[j])
			{
				c = L'_';
			}
		}
		name[i] = c;
	}
}
void SafeFileNameW(wchar_t *name)
{
	UniSafeFileName(name);
}

// Read HamCore file
BUF *ReadHamcoreW(wchar_t *filename)
{
	char *filename_a = CopyUniToStr(filename);
	BUF *ret;

	ret = ReadHamcore(filename_a);

	Free(filename_a);

	return ret;
}
BUF *ReadHamcore(char *name)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t exe_dir[MAX_SIZE];
	BUF *b;
	char filename[MAX_PATH];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	if (name[0] == '|')
	{
		name++;
	}

	if (name[0] == '/' || name[0] == '\\')
	{
		name++;
	}

	StrCpy(filename, sizeof(filename), name);

	ReplaceStrEx(filename, sizeof(filename), filename, "/", "\\", true);

	if (MayaquaIsMinimalMode())
	{
		return NULL;
	}

	// If the file exist in hamcore/ directory on the local disk, read it
	GetExeDirW(exe_dir, sizeof(exe_dir));

	UniFormat(tmp, sizeof(tmp), L"%s/%S/%S", exe_dir, HAMCORE_DIR_NAME, filename);

	b = ReadDumpW(tmp);
	if (b != NULL)
	{
		return b;
	}

	// Search from HamCore file system if it isn't found
	LockList(hamcore);
	{
		HC t, *c;
		UINT i;

		Zero(&t, sizeof(t));
		t.FileName = filename;
		c = Search(hamcore, &t);

		if (c == NULL)
		{
			// File does not exist
			b = NULL;
		}
		else
		{
			// File exists
			if (c->Buffer != NULL)
			{
				// It is already loaded
				b = NewBuf();
				WriteBuf(b, c->Buffer, c->Size);
				SeekBuf(b, 0, 0);
				c->LastAccess = Tick64();
			}
			else
			{
				// Read from a file is if it is not read
				if (FileSeek(hamcore_io, 0, c->Offset) == false)
				{
					// Failed to seek
					b = NULL;
				}
				else
				{
					// Read the compressed data
					void *data = Malloc(c->SizeCompressed);
					if (FileRead(hamcore_io, data, c->SizeCompressed) == false)
					{
						// Failed to read
						Free(data);
						b = NULL;
					}
					else
					{
						// Expand
						c->Buffer = ZeroMalloc(c->Size);
						if (Uncompress(c->Buffer, c->Size, data, c->SizeCompressed) != c->Size)
						{
							// Failed to expand
							Free(data);
							Free(c->Buffer);
							b = NULL;
						}
						else
						{
							// Successful
							Free(data);
							b = NewBuf();
							WriteBuf(b, c->Buffer, c->Size);
							SeekBuf(b, 0, 0);
							c->LastAccess = Tick64();
						}
					}
				}
			}
		}

		// Delete the expired cache
		for (i = 0;i < LIST_NUM(hamcore);i++)
		{
			HC *c = LIST_DATA(hamcore, i);

			if (c->Buffer != NULL)
			{
				if (((c->LastAccess + HAMCORE_CACHE_EXPIRES) <= Tick64()) ||
					(StartWith(c->FileName, "Li")))
				{
					Free(c->Buffer);
					c->Buffer = NULL;
				}
			}
		}
	}
	UnlockList(hamcore);

	return b;
}

// Initialization of HamCore file system
void InitHamcore()
{
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MAX_PATH];
	wchar_t exe_dir[MAX_PATH];
	UINT i, num;
	char header[HAMCORE_HEADER_SIZE];

	hamcore = NewList(CompareHamcore);

	if (MayaquaIsMinimalMode())
	{
		return;
	}

	GetExeDirW(exe_dir, sizeof(exe_dir));
	UniFormat(tmp, sizeof(tmp), L"%s/%S", exe_dir, HAMCORE_FILE_NAME);

	UniFormat(tmp2, sizeof(tmp2), L"%s/%S", exe_dir, HAMCORE_FILE_NAME_2);

	// If there is _hamcore.se2, overwrite it yo the hamcore.se2 
	FileReplaceRenameW(tmp2, tmp);

	// Read if there is a file hamcore.se2
	hamcore_io = FileOpenW(tmp, false);
	if (hamcore_io == NULL)
	{
		// Look in other locations if it isn't found
#ifdef	OS_WIN32
		UniFormat(tmp, sizeof(tmp), L"%S/%S", MsGetSystem32Dir(), HAMCORE_FILE_NAME);
#else	// OS_WIN32
		UniFormat(tmp, sizeof(tmp), L"/bin/%S", HAMCORE_FILE_NAME);
#endif	// OS_WIN32

		hamcore_io = FileOpenW(tmp, false);
		if (hamcore_io == NULL)
		{
			return;
		}
	}

	// Read the file header
	Zero(header, sizeof(header));
	FileRead(hamcore_io, header, HAMCORE_HEADER_SIZE);

	if (Cmp(header, HAMCORE_HEADER_DATA, HAMCORE_HEADER_SIZE) != 0)
	{
		// Invalid header
		FileClose(hamcore_io);
		hamcore_io = NULL;
		return;
	}

	// The number of the File
	num = 0;
	FileRead(hamcore_io, &num, sizeof(num));
	num = Endian32(num);
	for (i = 0;i < num;i++)
	{
		// File name
		char tmp[MAX_SIZE];
		UINT str_size = 0;
		HC *c;

		FileRead(hamcore_io, &str_size, sizeof(str_size));
		str_size = Endian32(str_size);
		if (str_size >= 1)
		{
			str_size--;
		}

		Zero(tmp, sizeof(tmp));
		FileRead(hamcore_io, tmp, str_size);

		c = ZeroMalloc(sizeof(HC));
		c->FileName = CopyStr(tmp);

		FileRead(hamcore_io, &c->Size, sizeof(UINT));
		c->Size = Endian32(c->Size);

		FileRead(hamcore_io, &c->SizeCompressed, sizeof(UINT));
		c->SizeCompressed = Endian32(c->SizeCompressed);

		FileRead(hamcore_io, &c->Offset, sizeof(UINT));
		c->Offset = Endian32(c->Offset);

		Insert(hamcore, c);
	}
}

// Release of HamCore file system
void FreeHamcore()
{
	UINT i;
	for (i = 0;i < LIST_NUM(hamcore);i++)
	{
		HC *c = LIST_DATA(hamcore, i);
		Free(c->FileName);
		if (c->Buffer != NULL)
		{
			Free(c->Buffer);
		}
		Free(c);
	}
	ReleaseList(hamcore);

	FileClose(hamcore_io);
	hamcore_io = NULL;
	hamcore = NULL;
}

// Build a Hamcore file
void BuildHamcore(char *dst_filename, char *src_dir, bool unix_only)
{
	char exe_dir[MAX_SIZE];
	bool ok = true;
	LIST *o;
	UINT i;
	TOKEN_LIST *src_file_list;

	GetExeDir(exe_dir, sizeof(exe_dir));

	src_file_list = EnumDirWithSubDirs(src_dir);

	o = NewListFast(CompareHamcore);

	for (i = 0;i < src_file_list->NumTokens;i++)
	{
		char rpath[MAX_SIZE];
		BUF *b;
		char s[MAX_SIZE];

		StrCpy(s, sizeof(s), src_file_list->Token[i]);
		Trim(s);

		if (GetRelativePath(rpath, sizeof(rpath), s, src_dir) == false)
		{
			// Unknown error !
		}
		else
		{
			bool ok = true;

			ReplaceStr(rpath, sizeof(rpath), rpath, "/", "\\");

			if (unix_only)
			{
				// Exclude non-UNIX files
				if (EndWith(s, ".exe") ||
					EndWith(s, ".dll") ||
					EndWith(s, ".sys") ||
					EndWith(s, ".inf") ||
					EndWith(s, ".cat") ||
					EndWith(s, ".wav"))
				{
					ok = false;
				}
			}

			if (ok)
			{
				b = ReadDump(s);
				if (b == NULL)
				{
					Print("Failed to open '%s'.\n", s);
					ok = false;
				}
				else
				{
					HC *c = ZeroMalloc(sizeof(HC));
					UINT tmp_size;
					void *tmp;
					c->FileName = CopyStr(rpath);
					c->Size = b->Size;
					tmp_size = CalcCompress(c->Size);
					tmp = Malloc(tmp_size);
					c->SizeCompressed = Compress(tmp, tmp_size, b->Buf, b->Size);
					c->Buffer = tmp;
					Insert(o, c);
					Print("%s: %u -> %u\n", s, c->Size, c->SizeCompressed);
					FreeBuf(b);
				}
			}
		}
	}

	if (ok)
	{
		// Calculate the offset of the buffer for each file
		UINT i, z;
		char tmp[MAX_SIZE];
		BUF *b;
		z = 0;
		z += HAMCORE_HEADER_SIZE;
		// The number of files
		z += sizeof(UINT);
		// For file table first
		for (i = 0;i < LIST_NUM(o);i++)
		{
			HC *c = LIST_DATA(o, i);
			// File name
			z += StrLen(c->FileName) + sizeof(UINT);
			// File size
			z += sizeof(UINT);
			z += sizeof(UINT);
			// Offset data
			z += sizeof(UINT);
		}
		// File body
		for (i = 0;i < LIST_NUM(o);i++)
		{
			HC *c = LIST_DATA(o, i);
			// Buffer body
			c->Offset = z;
			printf("%s: offset: %u\n", c->FileName, c->Offset);
			z += c->SizeCompressed;
		}
		// Writing
		b = NewBuf();
		// Header
		WriteBuf(b, HAMCORE_HEADER_DATA, HAMCORE_HEADER_SIZE);
		WriteBufInt(b, LIST_NUM(o));
		for (i = 0;i < LIST_NUM(o);i++)
		{
			HC *c = LIST_DATA(o, i);
			// File name
			WriteBufStr(b, c->FileName);
			// File size
			WriteBufInt(b, c->Size);
			WriteBufInt(b, c->SizeCompressed);
			// Offset
			WriteBufInt(b, c->Offset);
		}
		// Body
		for (i = 0;i < LIST_NUM(o);i++)
		{
			HC *c = LIST_DATA(o, i);
			WriteBuf(b, c->Buffer, c->SizeCompressed);
		}
		// Writing
		StrCpy(tmp, sizeof(tmp), dst_filename);
		Print("Writing %s...\n", tmp);
		FileDelete(tmp);
		DumpBuf(b, tmp);
		FreeBuf(b);
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		HC *c = LIST_DATA(o, i);
		Free(c->Buffer);
		Free(c->FileName);
		Free(c);
	}

	ReleaseList(o);

	FreeToken(src_file_list);
}

// Comparison of the HCs
int CompareHamcore(void *p1, void *p2)
{
	HC *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(HC **)p1;
	c2 = *(HC **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}
	return StrCmpi(c1->FileName, c2->FileName);
}

// Getting the name of the directory where the EXE file is in
void GetExeDir(char *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	GetDirNameFromFilePath(name, size, exe_file_name);
}
void GetExeDirW(wchar_t *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	GetDirNameFromFilePathW(name, size, exe_file_name_w);
}

// Get the EXE file name
void GetExeName(char *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	StrCpy(name, size, exe_file_name);
}
void GetExeNameW(wchar_t *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	UniStrCpy(name, size, exe_file_name_w);
}

// Initialization of the aquisition of the EXE file name
void InitGetExeName(char *arg)
{
	wchar_t *arg_w = NULL;
	// Validate arguments
	if (arg == NULL)
	{
		arg = "./a.out";
	}

	arg_w = CopyUtfToUni(arg);

#ifdef	OS_WIN32
	Win32GetExeNameW(exe_file_name_w, sizeof(exe_file_name_w));
#else	// OS_WIN32
	UnixGetExeNameW(exe_file_name_w, sizeof(exe_file_name_w), arg_w);
#endif	// OS_WIN32

	UniToStr(exe_file_name, sizeof(exe_file_name), exe_file_name_w);

	Free(arg_w);
}

// Get the full path of the executable binary file in Unix
void UnixGetExeNameW(wchar_t *name, UINT size, wchar_t *arg)
{
	UNI_TOKEN_LIST *t;
	char *path_str;
	wchar_t *path_str_w;
	bool ok = false;
	// Validate arguments
	if (name == NULL || arg == NULL)
	{
		return;
	}

	path_str = GetCurrentPathEnvStr();
	path_str_w = CopyUtfToUni(path_str);

	t = ParseSplitedPathW(path_str_w);

	if (t != NULL)
	{
		UINT i;
		for (i = 0;i < t->NumTokens;i++)
		{
			wchar_t *s = t->Token[i];
			wchar_t tmp[MAX_SIZE];

			ConbinePathW(tmp, sizeof(tmp), s, arg);

			if (IsFileExistsInnerW(tmp))
			{
#ifdef	OS_UNIX
				if (UnixCheckExecAccessW(tmp) == false)
				{
					continue;
				}
#endif	// OS_UNIX
				ok = true;
				UniStrCpy(name, size, tmp);
				break;
			}
		}

		UniFreeToken(t);
	}

	Free(path_str);
	Free(path_str_w);

	if (ok == false)
	{
		// In the case of failing to find the path
#ifdef	OS_UNIX
		UnixGetCurrentDirW(name, size);
#else	// OS_UNIX
		Win32GetCurrentDirW(name, size);
#endif	// OS_UNIX
		ConbinePathW(name, size, name, arg);
	}
}

// Generate a secure file name
void MakeSafeFileName(char *dst, UINT size, char *src)
{
	char tmp[MAX_PATH];
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), src);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "..", "__", false);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "/", "_", false);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "\\", "_", false);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "@", "_", false);
	ReplaceStrEx(tmp, sizeof(tmp), tmp, "|", "_", false);

	StrCpy(dst, size, tmp);
}
void MakeSafeFileNameW(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t tmp[MAX_PATH];
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	UniStrCpy(tmp, sizeof(tmp), src);
	UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"..", L"__", false);
	UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"/", L"_", false);
	UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"\\", L"_", false);
	UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"@", L"_", false);
	UniReplaceStrEx(tmp, sizeof(tmp), tmp, L"|", L"_", false);

	UniStrCpy(dst, size, tmp);
}

// Get the file name from the file path
void GetFileNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *filepath)
{
	wchar_t tmp[MAX_SIZE];
	UINT i, len, wp;
	// Validate arguments
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	len = MIN(UniStrLen(filepath), (MAX_SIZE - 2));
	wp = 0;

	for (i = 0;i < (len + 1);i++)
	{
		wchar_t c = filepath[i];

		switch (c)
		{
		case L'\\':
		case L'/':
		case 0:
			tmp[wp] = 0;
			wp = 0;
			break;

		default:
			tmp[wp] = c;
			wp++;
			break;
		}
	}

	UniStrCpy(dst, size, tmp);
}
void GetFileNameFromFilePath(char *dst, UINT size, char *filepath)
{
	char tmp[MAX_SIZE];
	UINT i, len, wp;
	// Validate arguments
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	len = MIN(StrLen(filepath), (MAX_SIZE - 2));
	wp = 0;

	for (i = 0;i < (len + 1);i++)
	{
		char c = filepath[i];

		switch (c)
		{
		case '\\':
		case '/':
		case 0:
			tmp[wp] = 0;
			wp = 0;
			break;

		default:
			tmp[wp] = c;
			wp++;
			break;
		}
	}

	StrCpy(dst, size, tmp);
}
void GetDirNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *filepath)
{
	wchar_t tmp[MAX_SIZE];
	UINT wp;
	UINT i;
	UINT len;
	// Validate arguments
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	UniStrCpy(tmp, sizeof(tmp), filepath);
	if (UniEndWith(tmp, L"\\") || UniEndWith(tmp, L"/"))
	{
		tmp[UniStrLen(tmp) - 1] = 0;
	}

	len = UniStrLen(tmp);

	UniStrCpy(dst, size, L"");

	wp = 0;

	for (i = 0;i < len;i++)
	{
		wchar_t c = tmp[i];
		if (c == L'/' || c == L'\\')
		{
			tmp[wp++] = 0;
			wp = 0;
			UniStrCat(dst, size, tmp);
			tmp[wp++] = c;
		}
		else
		{
			tmp[wp++] = c;
		}
	}

	if (UniStrLen(dst) == 0)
	{
		UniStrCpy(dst, size, L"/");
	}

	NormalizePathW(dst, size, dst);
}

// Get the directory name from the file path
void GetDirNameFromFilePath(char *dst, UINT size, char *filepath)
{
	char tmp[MAX_SIZE];
	UINT wp;
	UINT i;
	UINT len;
	// Validate arguments
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), filepath);
	if (EndWith(tmp, "\\") || EndWith(tmp, "/"))
	{
		tmp[StrLen(tmp) - 1] = 0;
	}

	len = StrLen(tmp);

	StrCpy(dst, size, "");

	wp = 0;

	for (i = 0;i < len;i++)
	{
		char c = tmp[i];
		if (c == '/' || c == '\\')
		{
			tmp[wp++] = 0;
			wp = 0;
			StrCat(dst, size, tmp);
			tmp[wp++] = c;
		}
		else
		{
			tmp[wp++] = c;
		}
	}

	if (StrLen(dst) == 0)
	{
		StrCpy(dst, size, "/");
	}

	NormalizePath(dst, size, dst);
}

// Combine the two paths
void ConbinePath(char *dst, UINT size, char *dirname, char *filename)
{
	wchar_t dst_w[MAX_PATH];
	wchar_t *dirname_w = CopyStrToUni(dirname);
	wchar_t *filename_w = CopyStrToUni(filename);

	ConbinePathW(dst_w, sizeof(dst_w), dirname_w, filename_w);

	Free(dirname_w);
	Free(filename_w);

	UniToStr(dst, size, dst_w);
}
void ConbinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename)
{
	bool is_full_path;
	wchar_t tmp[MAX_SIZE];
	wchar_t filename_ident[MAX_SIZE];
	// Validate arguments
	if (dst == NULL || dirname == NULL || filename == NULL)
	{
		return;
	}

	NormalizePathW(filename_ident, sizeof(filename_ident), filename);

	is_full_path = false;

	if (UniStartWith(filename_ident, L"\\") || UniStartWith(filename_ident, L"/"))
	{
		is_full_path = true;
	}

	filename = &filename_ident[0];

#ifdef	OS_WIN32
	if (UniStrLen(filename) >= 2)
	{
		if ((L'a' <= filename[0] && filename[0] <= L'z') || (L'A' <= filename[0] && filename[0] <= L'Z'))
		{
			if (filename[1] == L':')
			{
				is_full_path = true;
			}
		}
	}
#endif	// OS_WIN32

	if (is_full_path == false)
	{
		UniStrCpy(tmp, sizeof(tmp), dirname);
		if (UniEndWith(tmp, L"/") == false && UniEndWith(tmp, L"\\") == false)
		{
			UniStrCat(tmp, sizeof(tmp), L"/");
		}
		UniStrCat(tmp, sizeof(tmp), filename);
	}
	else
	{
		UniStrCpy(tmp, sizeof(tmp), filename);
	}

	NormalizePathW(dst, size, tmp);
}
void CombinePath(char *dst, UINT size, char *dirname, char *filename)
{
	ConbinePath(dst, size, dirname, filename);
}
void CombinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename)
{
	ConbinePathW(dst, size, dirname, filename);
}

// Check whether the file exists
bool IsFileExists(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = IsFileExistsW(name_w);

	Free(name_w);

	return ret;
}
bool IsFileExistsW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return IsFileExistsInnerW(tmp);
}
bool IsFileExistsInner(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = IsFileExistsInnerW(name_w);

	Free(name_w);

	return ret;
}
bool IsFileExistsInnerW(wchar_t *name)
{
	IO *o;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	o = FileOpenInnerW(name, false, false);
	if (o == NULL)
	{
		return false;
	}

	FileClose(o);

	return true;
}

// Get the current contents of the PATH environment variable
char *GetCurrentPathEnvStr()
{
	char tmp[1024];
	char *tag_name;

#ifdef	OS_WIN32
	tag_name = "Path";
#else	// OS_WIN32
	tag_name = "PATH";
#endif	// OS_WIN32

	if (GetEnv(tag_name, tmp, sizeof(tmp)) == false)
	{
#ifdef	OS_WIN32
		Win32GetCurrentDir(tmp, sizeof(tmp));
#else	// OS_WIN32
		UnixGetCurrentDir(tmp, sizeof(tmp));
#endif	// OS_WIN32
	}

	return CopyStr(tmp);
}

// Get multiple paths separated by colons
UNI_TOKEN_LIST *ParseSplitedPathW(wchar_t *path)
{
	UNI_TOKEN_LIST *ret;
	wchar_t *tmp = UniCopyStr(path);
	wchar_t *split_str;
	UINT i;

	UniTrim(tmp);
	UniTrimCrlf(tmp);
	UniTrim(tmp);
	UniTrimCrlf(tmp);

#ifdef	OS_WIN32
	split_str = L";";
#else	// OS_WIN32
	split_str = L":";
#endif	// OS_WIN32

	ret = UniParseToken(tmp, split_str);

	if (ret != NULL)
	{
		for (i = 0;i < ret->NumTokens;i++)
		{
			UniTrim(ret->Token[i]);
			UniTrimCrlf(ret->Token[i]);
			UniTrim(ret->Token[i]);
			UniTrimCrlf(ret->Token[i]);
		}
	}

	Free(tmp);

	return ret;
}
TOKEN_LIST *ParseSplitedPath(char *path)
{
	TOKEN_LIST *ret;
	char *tmp = CopyStr(path);
	char *split_str;
	UINT i;

	Trim(tmp);
	TrimCrlf(tmp);
	Trim(tmp);
	TrimCrlf(tmp);

#ifdef	OS_WIN32
	split_str = ";";
#else	// OS_WIN32
	split_str = ":";
#endif	// OS_WIN32

	ret = ParseToken(tmp, split_str);

	if (ret != NULL)
	{
		for (i = 0;i < ret->NumTokens;i++)
		{
			Trim(ret->Token[i]);
			TrimCrlf(ret->Token[i]);
			Trim(ret->Token[i]);
			TrimCrlf(ret->Token[i]);
		}
	}

	Free(tmp);

	return ret;
}

// Get the current directory
void GetCurrentDirW(wchar_t *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32GetCurrentDirW(name, size);
#else	// OS_WIN32
	UnixGetCurrentDirW(name, size);
#endif	// OS_WIN32
}
void GetCurrentDir(char *name, UINT size)
{
	wchar_t name_w[MAX_PATH];

	GetCurrentDirW(name_w, sizeof(name_w));

	UniToStr(name, size, name_w);
}

// Get the relative path
bool GetRelativePathW(wchar_t *dst, UINT size, wchar_t *fullpath, wchar_t *basepath)
{
	wchar_t fullpath2[MAX_SIZE];
	wchar_t basepath2[MAX_SIZE];
	// Validate arguments
	if (dst == NULL || fullpath == NULL || basepath == NULL)
	{
		return false;
	}
	ClearUniStr(dst, size);

	NormalizePathW(fullpath2, sizeof(fullpath2), fullpath);
	NormalizePathW(basepath2, sizeof(basepath2), basepath);

#ifdef	OS_WIN32
	UniStrCat(basepath2, sizeof(basepath2), L"\\");
#else	// OS_WIN32
	UniStrCat(basepath2, sizeof(basepath2), L"/");
#endif	// OS_WIN32

	if (UniStrLen(fullpath2) <= UniStrLen(basepath2))
	{
		return false;
	}

	if (UniStartWith(fullpath2, basepath2) == false)
	{
		return false;
	}

	UniStrCpy(dst, size, fullpath2 + UniStrLen(basepath2));

	return true;
}
bool GetRelativePath(char *dst, UINT size, char *fullpath, char *basepath)
{
	wchar_t dst_w[MAX_SIZE];
	wchar_t fullpath_w[MAX_SIZE];
	wchar_t basepath_w[MAX_SIZE];
	bool ret;
	// Validate arguments
	if (dst == NULL || fullpath == NULL || basepath == NULL)
	{
		return false;
	}

	StrToUni(fullpath_w, sizeof(fullpath_w), fullpath);
	StrToUni(basepath_w, sizeof(basepath_w), basepath);

	ret = GetRelativePathW(dst_w, sizeof(dst_w), fullpath_w, basepath_w);
	if (ret == false)
	{
		return false;
	}

	UniToStr(dst, size, dst_w);

	return true;
}

// Normalize the file path
void NormalizePathW(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t tmp[MAX_SIZE];
	UNI_TOKEN_LIST *t;
	bool first_double_slash = false;
	bool first_single_slash = false;
	wchar_t win32_drive_char = 0;
	bool is_full_path = false;
	UINT i;
	SK *sk;
	// Validate arguments
	if (dst == NULL || src == 0)
	{
		return;
	}

	// Convert the path (Win32, UNIX conversion)
	UniStrCpy(tmp, sizeof(tmp), src);
	ConvertPathW(tmp);
	UniTrim(tmp);

	// If the path begins with "./ " or " ../", replace it to the current directory
	if (UniStartWith(tmp, L"./") || UniStartWith(tmp, L".\\") ||
		UniStartWith(tmp, L"../") || UniStartWith(tmp, L"..\\") ||
		UniStrCmpi(tmp, L".") == 0 || UniStrCmpi(tmp, L"..") == 0)
	{
		wchar_t cd[MAX_SIZE];
		Zero(cd, sizeof(cd));

#ifdef	OS_WIN32
		Win32GetCurrentDirW(cd, sizeof(cd));
#else	// OS_WIN32
		UnixGetCurrentDirW(cd, sizeof(cd));
#endif	// OS_WIN32

		if (UniStartWith(tmp, L".."))
		{
			UniStrCat(cd, sizeof(cd), L"/../");
			UniStrCat(cd, sizeof(cd), tmp + 2);
		}
		else
		{
			UniStrCat(cd, sizeof(cd), L"/");
			UniStrCat(cd, sizeof(cd), tmp);
		}

		UniStrCpy(tmp, sizeof(tmp), cd);
	}

	// If the path starts with "~/", replace it with the home directory
	if (UniStartWith(tmp, L"~/") || UniStartWith(tmp, L"~\\"))
	{
		wchar_t tmp2[MAX_SIZE];
		GetHomeDirW(tmp2, sizeof(tmp2));
		UniStrCat(tmp2, sizeof(tmp2), L"/");
		UniStrCat(tmp2, sizeof(tmp2), tmp + 2);
		UniStrCpy(tmp, sizeof(tmp), tmp2);
	}

	if (UniStartWith(tmp, L"//") || UniStartWith(tmp, L"\\\\"))
	{
        // Begin with "//" or "\\"
		first_double_slash = true;
		is_full_path = true;
	}
	else if (UniStartWith(tmp, L"/") || UniStartWith(tmp, L"\\"))
	{
		// Begin with "\"
		first_single_slash = true;
		is_full_path = true;
	}

#ifdef	OS_WIN32
	if (UniStrLen(tmp) >= 2)
	{
		if (tmp[1] == L':')
		{
			// The drive string representation of the Win32
			wchar_t tmp2[MAX_SIZE];
			is_full_path = true;
			win32_drive_char = tmp[0];
			UniStrCpy(tmp2, sizeof(tmp2), tmp + 2);
			UniStrCpy(tmp, sizeof(tmp), tmp2);
		}
	}
#endif	// OS_WIN32

	if (UniStrLen(tmp) == 1 && (tmp[0] == L'/' || tmp[0] == L'\\'))
	{
		tmp[0] = 0;
	}

	// Tokenize
	t = UniParseToken(tmp, L"/\\");

	sk = NewSk();

	for (i = 0;i < t->NumTokens;i++)
	{
		wchar_t *s = t->Token[i];

		if (UniStrCmpi(s, L".") == 0)
		{
			continue;
		}
		else if (UniStrCmpi(s, L"..") == 0)
		{
			if (sk->num_item >= 1 && (first_double_slash == false || sk->num_item >= 2))
			{
				Pop(sk);
			}
		}
		else
		{
			Push(sk, s);
		}
	}

	// Token concatenation
	UniStrCpy(tmp, sizeof(tmp), L"");

	if (first_double_slash)
	{
		UniStrCat(tmp, sizeof(tmp), L"//");
	}
	else if (first_single_slash)
	{
		UniStrCat(tmp, sizeof(tmp), L"/");
	}

	if (win32_drive_char != 0)
	{
		wchar_t d[2];
		d[0] = win32_drive_char;
		d[1] = 0;
		UniStrCat(tmp, sizeof(tmp), d);
		UniStrCat(tmp, sizeof(tmp), L":/");
	}

	for (i = 0;i < sk->num_item;i++)
	{
		UniStrCat(tmp, sizeof(tmp), (wchar_t *)sk->p[i]);
		if (i != (sk->num_item - 1))
		{
			UniStrCat(tmp, sizeof(tmp), L"/");
		}
	}

	ReleaseSk(sk);

	UniFreeToken(t);

	ConvertPathW(tmp);

	UniStrCpy(dst, size, tmp);
}
void NormalizePath(char *dst, UINT size, char *src)
{
	wchar_t dst_w[MAX_SIZE];
	wchar_t *src_w = CopyStrToUni(src);

	NormalizePathW(dst_w, sizeof(dst_w), src_w);

	Free(src_w);

	UniToStr(dst, size, dst_w);
}

// Close and delete the file
void FileCloseAndDelete(IO *o)
{
	wchar_t *name;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	name = CopyUniStr(o->NameW);
	FileClose(o);

	FileDeleteW(name);

	Free(name);
}

// Rename the file
bool FileRename(char *old_name, char *new_name)
{
	wchar_t *old_name_w = CopyStrToUni(old_name);
	wchar_t *new_name_w = CopyStrToUni(new_name);
	bool ret = FileRenameW(old_name_w, new_name_w);

	Free(old_name_w);
	Free(new_name_w);

	return ret;
}
bool FileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	// Validate arguments
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp1, sizeof(tmp1), old_name);
	InnerFilePathW(tmp2, sizeof(tmp2), new_name);

	return FileRenameInnerW(tmp1, tmp2);
}
bool FileRenameInner(char *old_name, char *new_name)
{
	wchar_t *old_name_w = CopyStrToUni(old_name);
	wchar_t *new_name_w = CopyStrToUni(new_name);
	bool ret = FileRenameInnerW(old_name_w, new_name_w);

	Free(old_name_w);
	Free(new_name_w);

	return ret;
}
bool FileRenameInnerW(wchar_t *old_name, wchar_t *new_name)
{
	// Validate arguments
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	return OSFileRenameW(old_name, new_name);
}

// Convert the path
void ConvertPath(char *path)
{
	UINT i, len;
#ifdef	PATH_BACKSLASH
	char new_char = '\\';
#else
	char new_char = '/';
#endif

	len = StrLen(path);
	for (i = 0;i < len;i++)
	{
		if (path[i] == '\\' || path[i] == '/')
		{
			path[i] = new_char;
		}
	}
}
void ConvertPathW(wchar_t *path)
{
	UINT i, len;
#ifdef	PATH_BACKSLASH
	wchar_t new_char = L'\\';
#else
	wchar_t new_char = L'/';
#endif

	len = UniStrLen(path);
	for (i = 0;i < len;i++)
	{
		if (path[i] == L'\\' || path[i] == L'/')
		{
			path[i] = new_char;
		}
	}
}

// Delete the directory
bool DeleteDir(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = DeleteDirW(name_w);

	Free(name_w);

	return ret;
}
bool DeleteDirW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return DeleteDirInnerW(tmp);
}
bool DeleteDirInner(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = DeleteDirInnerW(name_w);

	Free(name_w);

	return ret;
}
bool DeleteDirInnerW(wchar_t *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	return OSDeleteDirW(name);
}

// Generation of internal file path
void InnerFilePathW(wchar_t *dst, UINT size, wchar_t *src)
{
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	if (src[0] != L'@')
	{
		NormalizePathW(dst, size, src);
	}
	else
	{
		wchar_t dir[MAX_SIZE];
		GetExeDirW(dir, sizeof(dir));
		ConbinePathW(dst, size, dir, &src[1]);
	}
}
void InnerFilePath(char *dst, UINT size, char *src)
{
	wchar_t dst_w[MAX_PATH];
	wchar_t *src_w = CopyStrToUni(src);

	InnerFilePathW(dst_w, sizeof(dst_w), src_w);

	Free(src_w);

	UniToStr(dst, size, dst_w);
}

// Recursive directory creation
bool MakeDirEx(char *name)
{
	bool ret;
	wchar_t *name_w = CopyStrToUni(name);

	ret = MakeDirExW(name_w);

	Free(name_w);

	return ret;
}
bool MakeDirExW(wchar_t *name)
{
	LIST *o;
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MAX_PATH];
	UINT i;
	bool ret;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	o = NewListFast(NULL);

	UniStrCpy(tmp, sizeof(tmp), name);
	while (true)
	{
		wchar_t *s = CopyUniStr(tmp);

		Add(o, s);

		GetDirNameFromFilePathW(tmp2, sizeof(tmp2), tmp);

		if (UniStrCmpi(tmp2, tmp) == 0)
		{
			break;
		}

		UniStrCpy(tmp, sizeof(tmp), tmp2);
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT j = LIST_NUM(o) - i - 1;
		wchar_t *s = LIST_DATA(o, j);

		if (UniStrCmpi(s, L"\\") != 0 && UniStrCmpi(s, L"/") != 0)
		{
			ret = MakeDirW(s);
		}
	}

	UniFreeStrList(o);

	return ret;
}

// Create a directory
bool MakeDir(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = MakeDirW(name_w);

	Free(name_w);

	return ret;
}
bool MakeDirW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return MakeDirInnerW(tmp);
}
bool MakeDirInner(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = MakeDirInnerW(name_w);

	Free(name_w);

	return ret;
}
bool MakeDirInnerW(wchar_t *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	return OSMakeDirW(name);
}

// Delete the file
bool FileDelete(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = FileDeleteW(name_w);

	Free(name_w);

	return ret;
}
bool FileDeleteW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return FileDeleteInnerW(tmp);
}
bool FileDeleteInner(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = FileDeleteInnerW(name_w);

	Free(name_w);

	return ret;
}
bool FileDeleteInnerW(wchar_t *name)
{
	wchar_t name2[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	return OSFileDeleteW(name2);
}

// Seek the file
bool FileSeek(IO *o, UINT mode, int offset)
{
	// Validate arguments
	if (o == NULL)
	{
		return false;
	}

	if (o->HamMode == false)
	{
		return OSFileSeek(o->pData, mode, offset);
	}
	else
	{
		return false;
	}
}

// Get the file size by specifying the file name
UINT FileSizeEx(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	UINT ret = FileSizeExW(name_w);

	Free(name_w);

	return ret;
}
UINT FileSizeExW(wchar_t *name)
{
	IO *io;
	UINT size;
	// Validate arguments
	if (name == NULL)
	{
		return 0;
	}

	io = FileOpenW(name, false);
	if (io == NULL)
	{
		return 0;
	}

	size = FileSize(io);

	FileClose(io);

	return size;
}

// Get the file size
UINT64 FileSize64(IO *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return 0;
	}

	if (o->HamMode == false)
	{
		return OSFileSize(o->pData);
	}
	else
	{
		return (UINT64)o->HamBuf->Size;
	}
}
UINT FileSize(IO *o)
{
	UINT64 size = (UINT)(FileSize64(o));

	if (size >= 4294967296ULL)
	{
		size = 4294967295ULL;
	}

	return (UINT)size;
}

// Read from a file
bool FileRead(IO *o, void *buf, UINT size)
{
	// Validate arguments
	if (o == NULL || buf == NULL)
	{
		return false;
	}

	// KS
	KS_INC(KS_IO_READ_COUNT);
	KS_ADD(KS_IO_TOTAL_READ_SIZE, size);

	if (size == 0)
	{
		return true;
	}

	if (o->HamMode == false)
	{
		return OSFileRead(o->pData, buf, size);
	}
	else
	{
		return ReadBuf(o->HamBuf, buf, size) == size ? true : false;
	}
}

// Write to a file
bool FileWrite(IO *o, void *buf, UINT size)
{
	// Validate arguments
	if (o == NULL || buf == NULL)
	{
		return false;
	}
	if (o->WriteMode == false)
	{
		return false;
	}

	// KS
	KS_INC(KS_IO_WRITE_COUNT);
	KS_ADD(KS_IO_TOTAL_WRITE_SIZE, size);

	if (size == 0)
	{
		return true;
	}

	return OSFileWrite(o->pData, buf, size);
}

// Flush the file
void FileFlush(IO *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	if (o->HamMode)
	{
		return;
	}

	OSFileFlush(o->pData);
}

// Close the file
void FileClose(IO *o)
{
	FileCloseEx(o, false);
}
void FileCloseEx(IO *o, bool no_flush)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	if (o->HamMode == false)
	{
		if (o->WriteMode)
		{
#ifdef	OS_WIN32
			Win32FileSetDate(o->pData, o->SetCreateTime, o->SetUpdateTime);
#endif	// OS_WIN32
		}

		OSFileClose(o->pData, no_flush);
	}
	else
	{
		FreeBuf(o->HamBuf);
	}
	Free(o);

	// KS
	KS_INC(KS_IO_CLOSE_COUNT);
}

// Create a file
IO *FileCreateInner(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileCreateInnerW(name_w);

	Free(name_w);

	return ret;
}
IO *FileCreateInnerW(wchar_t *name)
{
	IO *o;
	void *p;
	wchar_t name2[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	p = OSFileCreateW(name2);
	if (p == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(IO));
	o->pData = p;
	UniStrCpy(o->NameW, sizeof(o->NameW), name2);
	UniToStr(o->Name, sizeof(o->Name), o->NameW);
	o->WriteMode = true;

	// KS
	KS_INC(KS_IO_CREATE_COUNT);

	return o;
}
IO *FileCreate(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileCreateW(name_w);

	Free(name_w);

	return ret;
}
IO *FileCreateW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return FileCreateInnerW(tmp);
}

// Write all the data to the file
bool FileWriteAll(char *name, void *data, UINT size)
{
	IO *io;
	// Validate arguments
	if (name == NULL || (data == NULL && size != 0))
	{
		return false;
	}

	io = FileCreate(name);

	if (io == NULL)
	{
		return false;
	}

	FileWrite(io, data, size);

	FileClose(io);

	return true;
}
bool FileWriteAllW(wchar_t *name, void *data, UINT size)
{
	IO *io;
	// Validate arguments
	if (name == NULL || (data == NULL && size != 0))
	{
		return false;
	}

	io = FileCreateW(name);

	if (io == NULL)
	{
		return false;
	}

	FileWrite(io, data, size);

	FileClose(io);

	return true;
}

// Open the file
IO *FileOpenInner(char *name, bool write_mode, bool read_lock)
{
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileOpenInnerW(name_w, write_mode, read_lock);

	Free(name_w);

	return ret;
}
IO *FileOpenInnerW(wchar_t *name, bool write_mode, bool read_lock)
{
	IO *o;
	void *p;
	wchar_t name2[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	p = OSFileOpenW(name2, write_mode, read_lock);
	if (p == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(IO));
	o->pData = p;
	UniStrCpy(o->NameW, sizeof(o->NameW), name2);
	UniToStr(o->Name, sizeof(o->Name), o->NameW);
	o->WriteMode = write_mode;

#ifdef	OS_WIN32
	Win32FileGetDate(p, &o->GetCreateTime, &o->GetUpdateTime, &o->GetAccessTime);
#endif	// OS_WIN32

	// KS
	KS_INC(KS_IO_OPEN_COUNT);

	return o;
}
IO *FileOpen(char *name, bool write_mode)
{
	return FileOpenEx(name, write_mode, true);
}
IO *FileOpenW(wchar_t *name, bool write_mode)
{
	return FileOpenExW(name, write_mode, true);
}
IO *FileOpenEx(char *name, bool write_mode, bool read_lock)
{
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileOpenExW(name_w, write_mode, read_lock);

	Free(name_w);

	return ret;
}
IO *FileOpenExW(wchar_t *name, bool write_mode, bool read_lock)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	if (name[0] == L'|')
	{
		IO *o = ZeroMalloc(sizeof(IO));
		name++;
		UniStrCpy(o->NameW, sizeof(o->NameW), name);
		UniToStr(o->Name, sizeof(o->Name), o->NameW);
		o->HamMode = true;
		o->HamBuf = ReadHamcoreW(name);
		if (o->HamBuf == NULL)
		{
			Free(o);
			return NULL;
		}
		return o;
	}
	else
	{
		return FileOpenInnerW(tmp, write_mode, read_lock);
	}
}



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
