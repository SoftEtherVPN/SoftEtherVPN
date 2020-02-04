// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// FileIO.h
// Header of FileIO.c

#ifndef	FILEIO_H
#define	FILEIO_H

// Constant
#define	HAMCORE_DIR_NAME			"hamcore"
#define	HAMCORE_FILE_NAME			"hamcore.se2"
#define	HAMCORE_FILE_NAME_2			"_hamcore.se2"
#define	HAMCORE_TEXT_NAME			"hamcore.txt"
#define	HAMCORE_HEADER_DATA			"HamCore"
#define	HAMCORE_HEADER_SIZE			7
#define	HAMCORE_CACHE_EXPIRES		(5 * 60 * 1000)

// IO structure
struct IO
{
	char Name[MAX_SIZE];
	wchar_t NameW[MAX_SIZE];
	void *pData;
	bool WriteMode;
	bool HamMode;
	BUF *HamBuf;
	UINT64 SetUpdateTime, SetCreateTime;
	UINT64 GetUpdateTime, GetCreateTime, GetAccessTime;
};

// HC structure
typedef struct HC
{
	char *FileName;				// File name
	UINT Size;					// File size
	UINT SizeCompressed;		// Compressed file size
	UINT Offset;				// Offset
	void *Buffer;				// Buffer
	UINT64 LastAccess;			// Access Date
} HC;

// DIRENT structure
struct DIRENT
{
	bool Folder;				// Folder
	char *FileName;				// File name (ANSI)
	wchar_t *FileNameW;			// File name (Unicode)
	UINT64 FileSize;			// File size
	UINT64 CreateDate;			// Creation Date
	UINT64 UpdateDate;			// Updating date
};

// DIRLIST structure
struct DIRLIST
{
	UINT NumFiles;				// Number of files
	struct DIRENT **File;			// File array
};

// ZIP related structure
#ifdef	OS_WIN32
#pragma pack(push, 1)
#endif	// OS_WIN32

struct ZIP_DATA_HEADER
{
	UINT Signature;
	USHORT NeedVer;
	USHORT Option;
	USHORT CompType;
	USHORT FileTime;
	USHORT FileDate;
	UINT Crc32;
	UINT CompSize;
	UINT UncompSize;
	USHORT FileNameLen;
	USHORT ExtraLen;
} GCC_PACKED;

struct ZIP_DATA_FOOTER
{
	UINT Signature;
	UINT Crc32;
	UINT CompSize;
	UINT UncompSize;
} GCC_PACKED;

struct ZIP_DIR_HEADER
{
	UINT Signature;
	USHORT MadeVer;
	USHORT NeedVer;
	USHORT Option;
	USHORT CompType;
	USHORT FileTime;
	USHORT FileDate;
	UINT Crc32;
	UINT CompSize;
	UINT UncompSize;
	USHORT FileNameLen;
	USHORT ExtraLen;
	USHORT CommentLen;
	USHORT DiskNum;
	USHORT InAttr;
	UINT OutAttr;
	UINT HeaderPos;
} GCC_PACKED;

struct ZIP_END_HEADER
{
	UINT Signature;
	USHORT DiskNum;
	USHORT StartDiskNum;
	USHORT DiskDirEntry;
	USHORT DirEntry;
	UINT DirSize;
	UINT StartPos;
	USHORT CommentLen;
} GCC_PACKED;

#define	ZIP_SIGNATURE				0x04034B50
#define	ZIP_SIGNATURE_END			0x06054B50
#define	ZIP_VERSION					10
#define	ZIP_VERSION_WITH_COMPRESS	20

#ifdef	OS_WIN32
#pragma pack(pop)
#endif	// OS_WIN32

struct ZIP_FILE
{
	char Name[MAX_PATH];
	UINT Size;
	UINT64 DateTime;
	UINT Attributes;
	UINT CurrentSize;
	UINT CompressSize;
	UINT Crc32;
	UINT HeaderPos;
};

struct ZIP_PACKER
{
	FIFO *Fifo;
	LIST *FileList;
	ZIP_FILE *CurrentFile;
};

struct ENUM_DIR_WITH_SUB_DATA
{
	LIST *FileList;
};

void InitCrc32();
UINT Crc32(void *buf, UINT pos, UINT len);
UINT Crc32First(void *buf, UINT pos, UINT len);
UINT Crc32Next(void *buf, UINT pos, UINT len, UINT last_crc32);
UINT Crc32Finish(UINT last_crc32);
void WriteZipDataHeader(ZIP_FILE *f, ZIP_DATA_HEADER *h, bool write_sizes);
void WriteZipDataFooter(ZIP_FILE *f, ZIP_DATA_FOOTER *h);
ZIP_PACKER *NewZipPacker();
void FreeZipPacker(ZIP_PACKER *p);
void ZipAddFileSimple(ZIP_PACKER *p, char *name, UINT64 dt, UINT attribute, void *data, UINT size);
bool ZipAddRealFileW(ZIP_PACKER *p, char *name, UINT64 dt, UINT attribute, wchar_t *srcname);
bool ZipAddRealFile(ZIP_PACKER *p, char *name, UINT64 dt, UINT attribute, char *srcname);
void ZipAddFileStart(ZIP_PACKER *p, char *name, UINT size, UINT64 dt, UINT attribute);
UINT ZipAddFileData(ZIP_PACKER *p, void *data, UINT pos, UINT len);
void ZipAddFileFooter(ZIP_PACKER *p);
FIFO *ZipFinish(ZIP_PACKER *p);
bool ZipWriteW(ZIP_PACKER *p, wchar_t *name);

bool DeleteDirInnerW(wchar_t *name);
bool DeleteDir(char *name);
bool DeleteDirW(wchar_t *name);
bool MakeDirInnerW(wchar_t *name);
bool MakeDir(char *name);
bool MakeDirW(wchar_t *name);
bool MakeDirEx(char *name);
bool MakeDirExW(wchar_t *name);
bool FileDeleteInnerW(wchar_t *name);
bool FileDelete(char *name);
bool FileDeleteW(wchar_t *name);
bool FileSeek(IO *o, UINT mode, int offset);
UINT FileSize(IO *o);
UINT64 FileSize64(IO *o);
bool FileRead(IO *o, void *buf, UINT size);
bool FileWrite(IO *o, void *buf, UINT size);
void FileFlush(IO *o);
void FileClose(IO *o);
void FileCloseEx(IO *o, bool no_flush);
IO *FileCreateInnerW(wchar_t *name);
IO *FileCreate(char *name);
IO *FileCreateW(wchar_t *name);
bool FileWriteAllW(wchar_t *name, void *data, UINT size);
IO *FileOpenInnerW(wchar_t *name, bool write_mode, bool read_lock);
IO *FileOpen(char *name, bool write_mode);
IO *FileOpenW(wchar_t *name, bool write_mode);
IO *FileOpenEx(char *name, bool write_mode, bool read_lock);
IO *FileOpenExW(wchar_t *name, bool write_mode, bool read_lock);
void ConvertPathW(wchar_t *path);
bool FileRenameInnerW(wchar_t *old_name, wchar_t *new_name);
bool FileRenameW(wchar_t *old_name, wchar_t *new_name);
void NormalizePath(char *dst, UINT size, char *src);
void NormalizePathW(wchar_t *dst, UINT size, wchar_t *src);
bool GetRelativePathW(wchar_t *dst, UINT size, wchar_t *fullpath, wchar_t *basepath);
bool GetRelativePath(char *dst, UINT size, char *fullpath, char *basepath);
UNI_TOKEN_LIST *ParseSplitedPathW(wchar_t *path);
char *GetCurrentPathEnvStr();
bool IsFileExistsInnerW(wchar_t *name);
bool IsFileExists(char *name);
bool IsFileExistsW(wchar_t *name);
void InnerFilePath(char *dst, UINT size, char *src);
void InnerFilePathW(wchar_t *dst, UINT size, wchar_t *src);
void ConbinePath(char *dst, UINT size, char *dirname, char *filename);
void ConbinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename);
void CombinePath(char *dst, UINT size, char *dirname, char *filename);
void CombinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename);
void GetDirNameFromFilePath(char *dst, UINT size, char *filepath);
void GetDirNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *filepath);
void GetFileNameFromFilePath(char *dst, UINT size, char *filepath);
void GetFileNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *filepath);
void MakeSafeFileName(char *dst, UINT size, char *src);
void InitGetExeName(char *arg);
void UnixGetExeNameW(wchar_t *name, UINT size, wchar_t *arg);
void GetExeName(char *name, UINT size);
void GetExeNameW(wchar_t *name, UINT size);
void GetExeDir(char *name, UINT size);
void GetExeDirW(wchar_t *name, UINT size);
void GetLogDir(char *name, UINT size);
void GetLogDirW(wchar_t *name, UINT size);
void GetDbDir(char *name, UINT size);
void GetDbDirW(wchar_t *name, UINT size);
void GetPidDir(char *name, UINT size);
void GetPidDirW(wchar_t *name, UINT size);
void BuildHamcore(char *dst_filename, char *src_dir, bool unix_only);
int CompareHamcore(void *p1, void *p2);
void InitHamcore();
void FreeHamcore();
BUF *ReadHamcore(char *name);
BUF *ReadHamcoreW(wchar_t *filename);
void SafeFileName(char *name);
void UniSafeFileName(wchar_t *name);
DIRLIST *EnumDir(char *dirname);
DIRLIST *EnumDirW(wchar_t *dirname);
DIRLIST *EnumDirEx(char *dirname, COMPARE *compare);
DIRLIST *EnumDirExW(wchar_t *dirname, COMPARE *compare);
UNI_TOKEN_LIST *EnumDirWithSubDirsW(wchar_t *dirname);
TOKEN_LIST *EnumDirWithSubDirs(char *dirname);
void EnumDirWithSubDirsMain(ENUM_DIR_WITH_SUB_DATA *d, wchar_t *dirname);
void FreeDir(DIRLIST *d);
int CompareDirListByName(void *p1, void *p2);
bool GetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
void ConvertSafeFileName(char *dst, UINT size, char *src);
bool FileReplaceRenameW(wchar_t *old_name, wchar_t *new_name);
bool IsFile(char *name);
bool IsFileW(wchar_t *name);
bool SaveFileW(wchar_t *name, void *data, UINT size);
bool SaveFile(char *name, void *data, UINT size);
bool IsFileWriteLockedW(wchar_t *name);
bool IsInLines(BUF *buf, char *str, bool instr);
bool IsInLinesFile(wchar_t *filename, char *str, bool instr);

#endif	// FILEIO_H



