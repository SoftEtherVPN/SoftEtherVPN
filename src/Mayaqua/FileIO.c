// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// FileIO.c
// File Input / Output code

#include "FileIO.h"

#include "Cfg.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Str.h"
#include "Tick64.h"
#include "Tracking.h"
#include "Unix.h"
#include "Win32.h"

#include <Hamcore.h>

static char exe_file_name[MAX_SIZE] = "/tmp/a.out";
static wchar_t exe_file_name_w[MAX_SIZE] = L"/tmp/a.out";
static LIST *hamcore = NULL;
static HAMCORE *hamcore_io = NULL;

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
	UINT ret;
	UINT total_size;
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	total_size = p->CurrentFile->CurrentSize + len;

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
	if (name == NULL || MayaquaIsMinimalMode())
	{
		return NULL;
	}

	if (name[0] == '/')
	{
		++name;
	}

	char path[MAX_PATH];
	GetExeDir(path, sizeof(path));
	Format(path, sizeof(path), "%s/%s/%s", path, HAMCORE_DIR_NAME, name);

	BUF *buf = ReadDump(path);
	if (buf != NULL)
	{
		return buf;
	}

	LockList(hamcore);
	{
		HC t = {0};
		t.Path = name;
		HC *c = Search(hamcore, &t);
		if (c == NULL)
		{
			const HAMCORE_FILE *file = HamcoreFind(hamcore_io, name);
			if (file)
			{
				c = Malloc(sizeof(HC));
				c->Size = file->OriginalSize;
				c->Path = CopyStr(name);
				c->Buffer = Malloc(c->Size);

				if (HamcoreRead(hamcore_io, c->Buffer, file))
				{
					Add(hamcore, c);
				}
				else
				{
					Free(c->Buffer);
					Free(c->Path);
					Free(c);

					c = NULL;
				}
			}
		}

		if (c != NULL)
		{
			buf = NewBuf();
			WriteBuf(buf, c->Buffer, c->Size);
			SeekBuf(buf, 0, 0);
			c->LastAccess = Tick64();
		}

		LIST *to_delete = NewListFast(NULL);

		for (UINT i = 0; i < LIST_NUM(hamcore); ++i)
		{
			HC *c = LIST_DATA(hamcore, i);
			if (c->LastAccess + HAMCORE_CACHE_EXPIRES <= Tick64())
			{
				Add(to_delete, c);
			}
		}

		for (UINT i = 0; i < LIST_NUM(to_delete); ++i)
		{
			HC *c = LIST_DATA(to_delete, i);

			Delete(hamcore, c);

			Free(c->Buffer);
			Free(c->Path);
			Free(c);
		}

		ReleaseList(to_delete);
	}
	UnlockList(hamcore);

	return buf;
}

// Initialization of HamCore file system
void InitHamcore()
{
	if (MayaquaIsMinimalMode())
	{
		return;
	}

	hamcore = NewList(CompareHamcore);
#ifdef HAMCORE_FILE_PATH
	hamcore_io = HamcoreOpen(HAMCORE_FILE_PATH);
	if (hamcore_io != NULL)
	{
		Debug("InitHamcore(): Loaded from \"%s\".\n", HAMCORE_FILE_PATH);
		return;
	}
#endif
	char path[MAX_PATH];
	GetExeDir(path, sizeof(path));
	Format(path, sizeof(path), "%s/%s", path, HAMCORE_FILE_NAME);

	hamcore_io = HamcoreOpen(path);
	if (hamcore_io != NULL)
	{
		Debug("InitHamcore(): Loaded from \"%s\".\n", path);
	}
}

// Release of HamCore file system
void FreeHamcore()
{
	for (UINT i = 0; i < LIST_NUM(hamcore); ++i)
	{
		HC *c = LIST_DATA(hamcore, i);

		Free(c->Buffer);
		Free(c->Path);
		Free(c);
	}
	ReleaseList(hamcore);

	HamcoreClose(hamcore_io);
	hamcore_io = NULL;
	hamcore = NULL;
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
	return StrCmpi(c1->Path, c2->Path);
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

void GetLogDir(char *name, UINT size)
{
#ifdef SE_LOGDIR
	Format(name, size, SE_LOGDIR);
#else
	GetExeDir(name, size);
#endif
}

void GetLogDirW(wchar_t *name, UINT size)
{
#ifdef SE_LOGDIR
	UniFormat(name, size, L""SE_LOGDIR);
#else
	GetExeDirW(name, size);
#endif
}

void GetDbDir(char *name, UINT size)
{
#ifdef SE_DBDIR
	Format(name, size, SE_DBDIR);
#else
	GetExeDir(name, size);
#endif
}

void GetDbDirW(wchar_t *name, UINT size)
{
#ifdef SE_DBDIR
	UniFormat(name, size, L""SE_DBDIR);
#else
	GetExeDirW(name, size);
#endif
}

void GetPidDir(char *name, UINT size)
{
#ifdef SE_PIDDIR
	Format(name, size, SE_PIDDIR);
#else
	GetExeDir(name, size);
#endif
}

void GetPidDirW(wchar_t *name, UINT size)
{
#ifdef SE_PIDDIR
	UniFormat(name, size, L""SE_PIDDIR);
#else
	GetExeDirW(name, size);
#endif
}

// Initialization of the acquisition of the EXE file name
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

// Normalize the file path
void NormalizePathW(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t tmp[MAX_SIZE];
	UNI_TOKEN_LIST *t;
	bool first_double_slash = false;
	bool first_single_slash = false;
#ifdef  OS_WIN32
	wchar_t win32_drive_char = 0;
#endif  // OS_WIN32
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

#ifdef  OS_WIN32
	if (win32_drive_char != 0)
	{
		wchar_t d[2];
		d[0] = win32_drive_char;
		d[1] = 0;
		UniStrCat(tmp, sizeof(tmp), d);
		UniStrCat(tmp, sizeof(tmp), L":/");
	}
#endif  // OS_WIN32

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

// Rename the file
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

	if (src[0] == L'@')
	{
		wchar_t dir[MAX_SIZE];
		GetLogDirW(dir, sizeof(dir));
		ConbinePathW(dst, size, dir, &src[1]);
	}
	else if (src[0] == L'$')
	{
		wchar_t dir[MAX_SIZE];
		GetDbDirW(dir, sizeof(dir));
		ConbinePathW(dst, size, dir, &src[1]);
	}
	else
	{
		NormalizePathW(dst, size, src);
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
	bool ret = false;
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

// Replace the specified character in the string with a new character
wchar_t *UniReplaceCharW(wchar_t *src, UINT size, wchar_t c, wchar_t  newc) {
	if (src == NULL)
	{
		return NULL;
	}
	for (; *src; src++, size -= sizeof(wchar_t)) {
		if (size < sizeof(wchar_t)) {
			break;
		}
		if (*src == c) {
			*src = newc;
		}
	}
	return (wchar_t *)src;
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
#ifdef	OS_WIN32
		UniReplaceCharW(o->NameW, sizeof(o->NameW), L'\\', L'/');		// Path separator "/" is used.
#endif	// OS_WIN32
		UniToStr(o->Name, sizeof(o->Name), o->NameW);
		o->HamMode = true;
		o->HamBuf = ReadHamcoreW(o->NameW);
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


