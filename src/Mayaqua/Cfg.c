// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Cfg.c
// Configuration information manipulation module

#include "Cfg.h"

#include "Encoding.h"
#include "FileIO.h"
#include "Internat.h"
#include "Memory.h"
#include "Network.h"
#include "Object.h"
#include "Str.h"

// Create a backup of the configuration file
void BackupCfgWEx(CFG_RW *rw, FOLDER *f, wchar_t *original, UINT revision_number)
{
	wchar_t dirname[MAX_PATH];
	wchar_t filename[MAX_PATH];
	wchar_t fullpath[MAX_PATH];
	wchar_t datestr[MAX_PATH];
	SYSTEMTIME st;
	// Validate arguments
	if (f == NULL || rw == NULL)
	{
		return;
	}

	// Determine the directory name
	UniFormat(dirname, sizeof(dirname), L"$backup.%s", original[0] == L'$' ? original + 1 : original);

	// Determine the file name
	LocalTime(&st);
	UniFormat(datestr, sizeof(datestr), L"%04u%02u%02u%02u_%s",
		st.wYear, st.wMonth, st.wDay, st.wHour, original[0] == L'$' ? original + 1 : original);

	if (revision_number == INFINITE)
	{
		UniStrCpy(filename, sizeof(filename), datestr);
	}
	else
	{
		UniFormat(filename, sizeof(filename), L"%08u_%s",
			revision_number, original[0] == L'$' ? original + 1 : original);
	}

	// Don't save if the date and time has not been changed
	if (UniStrCmpi(datestr, rw->LastSavedDateStr) == 0)
	{
		return;
	}

	UniStrCpy(rw->LastSavedDateStr, sizeof(rw->LastSavedDateStr), datestr);

	// Check the existence of file name
	if (IsFileExistsW(filename))
	{
		return;
	}

	// Create the directory
	MakeDirW(dirname);

	// Save the file
	UniFormat(fullpath, sizeof(fullpath), L"%s/%s", dirname, filename);
	CfgSaveW(f, fullpath);
}

// Close the configuration file R/W
void FreeCfgRw(CFG_RW *rw)
{
	// Validate arguments
	if (rw == NULL)
	{
		return;
	}

	if (rw->Io != NULL)
	{
		FileClose(rw->Io);
	}

	DeleteLock(rw->lock);
	Free(rw->FileNameW);
	Free(rw->FileName);
	Free(rw);
}

// Writing to the configuration file
UINT SaveCfgRw(CFG_RW *rw, FOLDER *f)
{
	return SaveCfgRwEx(rw, f, INFINITE);
}
UINT SaveCfgRwEx(CFG_RW *rw, FOLDER *f, UINT revision_number)
{
	UINT ret = 0;
	// Validate arguments
	if (rw == NULL || f == NULL)
	{
		return 0;
	}

	Lock(rw->lock);
	{
		if (rw->Io != NULL)
		{
			FileClose(rw->Io);
			rw->Io = NULL;
		}

		if (CfgSaveExW2(rw, f, rw->FileNameW, &ret))
		{
			if (rw->DontBackup == false)
			{
				BackupCfgWEx(rw, f, rw->FileNameW, revision_number);
			}
		}
		else
		{
			ret = 0;
		}

		rw->Io = FileOpenW(rw->FileNameW, false);
	}
	Unlock(rw->lock);

	return ret;
}

// Creating a configuration file R/W
CFG_RW *NewCfgRw(FOLDER **root, char *cfg_name)
{
	return NewCfgRwEx(root, cfg_name, false);
}
CFG_RW *NewCfgRwEx(FOLDER **root, char *cfg_name, bool dont_backup)
{
	wchar_t *cfg_name_w = CopyStrToUni(cfg_name);
	CFG_RW *ret = NewCfgRwExW(root, cfg_name_w, dont_backup);

	Free(cfg_name_w);

	return ret;
}
CFG_RW *NewCfgRwExW(FOLDER **root, wchar_t *cfg_name, bool dont_backup)
{
	return NewCfgRwEx2W(root, cfg_name, dont_backup, NULL);
}
CFG_RW *NewCfgRwEx2A(FOLDER **root, char *cfg_name_a, bool dont_backup, char *template_name_a)
{
	CFG_RW *ret;
	wchar_t *cfg_name_w = CopyStrToUni(cfg_name_a);
	wchar_t *template_name_w = CopyStrToUni(template_name_a);

	ret = NewCfgRwEx2W(root, cfg_name_w, dont_backup, template_name_w);

	Free(cfg_name_w);
	Free(template_name_w);

	return ret;
}
CFG_RW *NewCfgRwEx2W(FOLDER **root, wchar_t *cfg_name, bool dont_backup, wchar_t *template_name)
{
	CFG_RW *rw;
	FOLDER *f;
	bool loaded_from_template = false;
	// Validate arguments
	if (cfg_name == NULL || root == NULL)
	{
		return NULL;
	}

	f = CfgReadW(cfg_name);
	if (f == NULL)
	{
		// Load from template
		if (UniIsEmptyStr(template_name) == false)
		{
			f = CfgReadW(template_name);
			if (f != NULL)
			{
				loaded_from_template = true;

				goto LABEL_CONTINUE;
			}
		}

		rw = ZeroMalloc(sizeof(CFG_RW));
		rw->lock = NewLock();
		rw->FileNameW = CopyUniStr(cfg_name);
		rw->FileName = CopyUniToStr(cfg_name);
		rw->Io = FileCreateW(cfg_name);
		*root = NULL;
		rw->DontBackup = dont_backup;

		return rw;
	}

LABEL_CONTINUE:
	rw = ZeroMalloc(sizeof(CFG_RW));
	rw->FileNameW = CopyUniStr(cfg_name);
	rw->FileName = CopyUniToStr(cfg_name);
	if (loaded_from_template == false)
	{
		rw->Io = FileOpenW(cfg_name, false);
	}
	else
	{
		rw->Io = FileCreateW(cfg_name);
	}
	rw->lock = NewLock();

	*root = f;

	rw->DontBackup = dont_backup;

	return rw;
}

// Copy a file
bool FileCopy(char *src, char *dst)
{
	BUF *b;
	bool ret = false;
	// Validate arguments
	if (src == NULL || dst == NULL)
	{
		return false;
	}

	b = ReadDump(src);
	if (b == NULL)
	{
		return false;
	}

	SeekBuf(b, 0, 0);

	ret = DumpBuf(b, dst);

	FreeBuf(b);

	return ret;
}
bool FileCopyW(wchar_t *src, wchar_t *dst)
{
	return FileCopyExW(src, dst, true);
}
bool FileCopyExW(wchar_t *src, wchar_t *dst, bool read_lock)
{
	BUF *b;
	bool ret = false;
	// Validate arguments
	if (src == NULL || dst == NULL)
	{
		return false;
	}

	b = ReadDumpExW(src, false);
	if (b == NULL)
	{
		return false;
	}

	SeekBuf(b, 0, 0);

	ret = DumpBufW(b, dst);

	FreeBuf(b);

	return ret;
}
bool FileCopyExWithEofW(wchar_t *src, wchar_t *dst, bool read_lock)
{
	BUF *b;
	bool ret = false;
	// Validate arguments
	if (src == NULL || dst == NULL)
	{
		return false;
	}

	b = ReadDumpExW(src, false);
	if (b == NULL)
	{
		return false;
	}

	SeekBuf(b, b->Size, 0);

	WriteBufChar(b, 0x1A);

	SeekBuf(b, 0, 0);

	ret = DumpBufW(b, dst);

	FreeBuf(b);

	return ret;
}

// Save the settings to a file
void CfgSave(FOLDER *f, char *name)
{
	CfgSaveEx(NULL, f, name);
}
void CfgSaveW(FOLDER *f, wchar_t *name)
{
	CfgSaveExW(NULL, f, name);
}
bool CfgSaveEx(CFG_RW *rw, FOLDER *f, char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = CfgSaveExW(rw, f, name_w);

	Free(name_w);

	return ret;
}
bool CfgSaveExW(CFG_RW *rw, FOLDER *f, wchar_t *name)
{
	return CfgSaveExW2(rw, f, name, NULL);
}
bool CfgSaveExW2(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size)
{
	return CfgSaveExW3(rw, f, name, written_size, IsFileExistsW(SAVE_BINARY_FILE_NAME_SWITCH));
}
bool CfgSaveExW3(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size, bool write_binary)
{
	wchar_t tmp[MAX_SIZE];
	bool text = !write_binary;
	UCHAR hash[SHA1_SIZE];
	BUF *b;
	IO *o;
	bool ret = true;
	UINT dummy_int = 0;
	// Validate arguments
	if (name == NULL || f == NULL)
	{
		return false;
	}
	if (written_size == NULL)
	{
		written_size = &dummy_int;
	}

	// Convert to buffer
	b = CfgFolderToBuf(f, text);
	if (b == NULL)
	{
		return false;
	}
	// Hash the contents
	Sha0(hash, b->Buf, b->Size);

	// Compare the contents to be written with the content which was written last
	if (rw != NULL)
	{
		if (Cmp(hash, rw->LashHash, SHA1_SIZE) == 0)
		{
			// Contents are not changed
			ret = false;
		}
		else
		{
			Copy(rw->LashHash, hash, SHA1_SIZE);
		}
	}

	if (ret || OS_IS_UNIX(GetOsInfo()->OsType))
	{
		// Generate a temporary file name
		UniFormat(tmp, sizeof(tmp), L"%s.log", name);
		// Copy the file that currently exist to a temporary file
		// with appending the EOF
		FileCopyExWithEofW(name, tmp, true);

		// Save the new file
		o = FileCreateW(name);
		if (o != NULL)
		{
			if (FileWrite(o, b->Buf, b->Size) == false)
			{
				// File saving failure
				FileClose(o);
				FileDeleteW(name);
				FileRenameW(tmp, name);

				if (rw != NULL)
				{
					Zero(rw->LashHash, sizeof(rw->LashHash));
				}
			}
			else
			{
				// Successful saving file
				FileClose(o);

				// Delete the temporary file
				FileDeleteW(tmp);
			}
		}
		else
		{
			// File saving failure
			FileRenameW(tmp, name);

			if (rw != NULL)
			{
				Zero(rw->LashHash, sizeof(rw->LashHash));
			}
		}
	}

	*written_size = b->Size;

	// Release memory 
	FreeBuf(b);

	return ret;
}

// Read the settings from the file
FOLDER *CfgRead(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	FOLDER *ret = CfgReadW(name_w);

	Free(name_w);

	return ret;
}
FOLDER *CfgReadW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t newfile[MAX_SIZE];
	BUF *b;
	IO *o;
	UINT size;
	void *buf;
	FOLDER *f;
	bool delete_new = false;
	bool binary_file = false;
	UCHAR header[8];
	bool has_eof = false;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	// Generate a new file name
	UniFormat(newfile, sizeof(newfile), L"%s.new", name);
	// Generate a temporary file name
	UniFormat(tmp, sizeof(tmp), L"%s.log", name);

	// Read the new file if it exists
	o = FileOpenW(newfile, false);
	if (o == NULL)
	{
		UINT size;
		// Read the temporary file
		o = FileOpenW(tmp, false);

		if (o != NULL)
		{
			// Check the EOF
			size = FileSize(o);
			if (size >= 2)
			{
				char c;

				if (FileSeek(o, FILE_BEGIN, size - 1) && FileRead(o, &c, 1) && c == 0x1A && FileSeek(o, FILE_BEGIN, 0))
				{
					// EOF ok
					has_eof = true;
				}
				else
				{
					// No EOF: file is corrupted
					FileClose(o);
					o = NULL;
				}
			}
		}
	}
	else
	{
		delete_new = true;
	}
	if (o == NULL)
	{
		// Read the original file if there is no temporary file
		o = FileOpenW(name, false);
	}
	else
	{
		// Read the original file too if the size of temporary file is 0
		if (FileSize(o) == 0)
		{
			FileClose(o);
			o = FileOpenW(name, false);
		}
	}
	if (o == NULL)
	{
		// Failed to read
		return NULL;
	}

	// Read into the buffer
	size = FileSize(o);
	if (has_eof)
	{
		// Ignore EOF
		size -= 1;
	}
	buf = Malloc(size);
	FileRead(o, buf, size);
	b = NewBuf();
	WriteBuf(b, buf, size);
	SeekBuf(b, 0, 0);

	// Close the file
	FileClose(o);

	if (delete_new)
	{
		// Delete the new file
		FileDeleteW(newfile);
	}

	// If the beginning 8 character of the buffer is "SEVPN_DB", it is binary file
	ReadBuf(b, header, sizeof(header));
	if (Cmp(header, TAG_BINARY, 8) == 0)
	{
		UCHAR hash1[SHA1_SIZE], hash2[SHA1_SIZE];
		binary_file = true;

		// Check the hash 
		ReadBuf(b, hash1, sizeof(hash1));

		Sha0(hash2, ((UCHAR *)b->Buf) + 8 + SHA1_SIZE, b->Size - 8 - SHA1_SIZE);

		if (Cmp(hash1, hash2, SHA1_SIZE) != 0)
		{
			// Corrupted file
			FreeBuf(b);
			return NULL;
		}
	}

	SeekBuf(b, 0, 0);

	if (binary_file)
	{
		SeekBuf(b, 8 + SHA1_SIZE, 0);
	}

	// Convert the buffer into a folder
	if (binary_file == false)
	{
		// Text mode
		f = CfgBufTextToFolder(b);
	}
	else
	{
		// Binary mode
		f = CfgBufBinToFolder(b);
	}

	// Memory release
	Free(buf);
	FreeBuf(b);

	FileDeleteW(newfile);

	return f;
}

// Read one line
char *CfgReadNextLine(BUF *b)
{
	char *tmp;
	char *buf;
	UINT len;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	// Examine the number of characters up to the next newline
	tmp = (char *)b->Buf + b->Current;
	if ((b->Size - b->Current) == 0)
	{
		// Read to the end
		return NULL;
	}
	len = 0;
	while (true)
	{
		if (tmp[len] == 13 || tmp[len] == 10)
		{
			if (tmp[len] == 13)
			{
				if (len < (b->Size - b->Current))
				{
					len++;
				}
			}
			break;
		}
		len++;
		if (len >= (b->Size - b->Current))
		{
			break;
		}
	}

	// Read ahead only 'len' bytes
	buf = ZeroMalloc(len + 1);
	ReadBuf(b, buf, len);
	SeekBuf(b, 1, 1);

	if (StrLen(buf) >= 1)
	{
		if (buf[StrLen(buf) - 1] == 13)
		{
			buf[StrLen(buf) - 1] = 0;
		}
	}

	return buf;
}

// Read the text stream
bool CfgReadNextTextBUF(BUF *b, FOLDER *current)
{
	char *buf;
	TOKEN_LIST *token;
	char *name;
	char *string;
	char *data;
	bool ret;
	FOLDER *f;

	// Validate arguments
	if (b == NULL || current == NULL)
	{
		return false;
	}

	ret = true;

	// Read one line
	buf = CfgReadNextLine(b);
	if (buf == NULL)
	{
		return false;
	}

	// Analyze this line
	token = ParseToken(buf, "\t ");
	if (token == NULL)
	{
		Free(buf);
		return false;
	}

	if (token->NumTokens >= 1)
	{
		if (!StrCmpi(token->Token[0], TAG_DECLARE))
		{
			if (token->NumTokens >= 2)
			{
				// declare
				name = CfgUnescape(token->Token[1]);

				// Create a folder
				f = CfgCreateFolder(current, name);

				// Read the next folder
				while (true)
				{
					if (CfgReadNextTextBUF(b, f) == false)
					{
						break;
					}
				}

				Free(name);
			}
		}
		if (!StrCmpi(token->Token[0], "}"))
		{
			// end
			ret = false;
		}
		if (token->NumTokens >= 3)
		{
			name = CfgUnescape(token->Token[1]);
			data = token->Token[2];

			if (!StrCmpi(token->Token[0], TAG_STRING))
			{
				// string
				wchar_t *uni;
				UINT uni_size;
				string = CfgUnescape(data);
				uni_size = CalcUtf8ToUni(string, StrLen(string));
				if (uni_size != 0)
				{
					uni = Malloc(uni_size);
					Utf8ToUni(uni, uni_size, string, StrLen(string));
					CfgAddUniStr(current, name, uni);
					Free(uni);
				}
				Free(string);
			}
			if (!StrCmpi(token->Token[0], TAG_INT))
			{
				// uint
				CfgAddInt(current, name, ToInt(data));
			}
			if (!StrCmpi(token->Token[0], TAG_INT64))
			{
				// uint64
				CfgAddInt64(current, name, ToInt64(data));
			}
			if (!StrCmpi(token->Token[0], TAG_BOOL))
			{
				// bool
				bool b = false;
				if (!StrCmpi(data, TAG_TRUE))
				{
					b = true;
				}
				else if (ToInt(data) != 0)
				{
					b = true;
				}
				CfgAddBool(current, name, b);
			}
			if (!StrCmpi(token->Token[0], TAG_BYTE))
			{
				// byte
				char *base64 = CfgUnescape(data);
				const UINT base64_size = StrLen(base64);

				UINT bin_size;
				void *bin = Base64ToBin(&bin_size, base64, base64_size);
				if (bin != NULL)
				{
					CfgAddByte(current, name, bin, bin_size);
					Free(bin);
				}

				Free(base64);
			}

			Free(name);
		}
	}

	// Release of the token
	FreeToken(token);

	Free(buf);

	return ret;
}

// Convert the stream text to a folder
FOLDER *CfgBufTextToFolder(BUF *b)
{
	FOLDER *f, *c;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	// Read recursively from the root folder
	c = CfgCreateFolder(NULL, "tmp");

	while (true)
	{
		// Read the text stream
		if (CfgReadNextTextBUF(b, c) == false)
		{
			break;
		}
	}

	// Getting root folder
	f = CfgGetFolder(c, TAG_ROOT);
	if (f == NULL)
	{
		// Root folder is not found
		CfgDeleteFolder(c);
		return NULL;
	}

	// Remove the reference from tmp folder to the root
	Delete(c->Folders, f);
	f->Parent = NULL;

	// Delete the tmp folder
	CfgDeleteFolder(c);

	// Return the root folder
	return f;
}

// Read the next folder
void CfgReadNextFolderBin(BUF *b, FOLDER *parent)
{
	char name[MAX_SIZE];
	FOLDER *f;
	UINT n, i;
	UINT size;
	UCHAR *buf;
	wchar_t *string;
	// Validate arguments
	if (b == NULL || parent == NULL)
	{
		return;
	}

	// Folder name
	ReadBufStr(b, name, sizeof(name));
	f = CfgCreateFolder(parent, name);

	// The number of the subfolder
	n = ReadBufInt(b);
	for (i = 0;i < n;i++)
	{
		// Subfolder
		CfgReadNextFolderBin(b, f);
	}

	// The number of items
	n = ReadBufInt(b);
	for (i = 0;i < n;i++)
	{
		UINT type;

		// Name
		ReadBufStr(b, name, sizeof(name));
		// Type
		type = ReadBufInt(b);

		switch (type)
		{
		case ITEM_TYPE_INT:
			// int
			CfgAddInt(f, name, ReadBufInt(b));
			break;

		case ITEM_TYPE_INT64:
			// int64
			CfgAddInt64(f, name, ReadBufInt64(b));
			break;

		case ITEM_TYPE_BYTE:
			// data
			size = ReadBufInt(b);
			buf = ZeroMalloc(size);
			ReadBuf(b, buf, size);
			CfgAddByte(f, name, buf, size);
			Free(buf);
			break;

		case ITEM_TYPE_STRING:
			// string
			size = ReadBufInt(b);
			buf = ZeroMalloc(size + 1);
			ReadBuf(b, buf, size);
			string = ZeroMalloc(CalcUtf8ToUni(buf, StrLen(buf)) + 4);
			Utf8ToUni(string, 0, buf, StrLen(buf));
			CfgAddUniStr(f, name, string);
			Free(string);
			Free(buf);
			break;

		case ITEM_TYPE_BOOL:
			// bool
			CfgAddBool(f, name, ReadBufInt(b) == 0 ? false : true);
			break;
		}
	}
}

// Convert the binary to folder
FOLDER *CfgBufBinToFolder(BUF *b)
{
	FOLDER *f, *c;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	// Create a temporary folder
	c = CfgCreateFolder(NULL, "tmp");

	// Read a binary
	CfgReadNextFolderBin(b, c);

	// Get root folder
	f = CfgGetFolder(c, TAG_ROOT);
	if (f == NULL)
	{
		// Missing
		CfgDeleteFolder(c);
		return NULL;
	}

	Delete(c->Folders, f);
	f->Parent = NULL;

	CfgDeleteFolder(c);

	return f;
}

// Convert the folder to binary
BUF *CfgFolderToBufBin(FOLDER *f)
{
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (f == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	// Header
	WriteBuf(b, TAG_BINARY, 8);

	// Hash area
	Zero(hash, sizeof(hash));
	WriteBuf(b, hash, sizeof(hash));

	// Output the root folder (recursive)
	CfgOutputFolderBin(b, f);

	// Hash
	Sha0(((UCHAR *)b->Buf) + 8, ((UCHAR *)b->Buf) + 8 + SHA1_SIZE, b->Size - 8 - SHA1_SIZE);

	return b;
}

// Convert the folder to a stream text
BUF *CfgFolderToBufTextEx(FOLDER *f, bool no_banner)
{
	BUF *b;
	// Validate arguments
	if (f == NULL)
	{
		return NULL;
	}

	// Create a stream
	b = NewBuf();

	// Copyright notice
	if (no_banner == false)
	{
		WriteBuf(b, TAG_CPYRIGHT, StrLen(TAG_CPYRIGHT));
	}

	// Output the root folder (recursive)
	CfgOutputFolderText(b, f, 0);

	return b;
}

// Output the folder contents (Enumerate folders)
bool CfgEnumFolderProc(FOLDER *f, void *param)
{
	CFG_ENUM_PARAM *p;
	// Validate arguments
	if (f == NULL || param == NULL)
	{
		return false;
	}

	p = (CFG_ENUM_PARAM *)param;
	// Output the folder contents (recursive)
	CfgOutputFolderText(p->b, f, p->depth);

	return true;
}

// Output the contents of the item (enumeration)
bool CfgEnumItemProc(ITEM *t, void *param)
{
	CFG_ENUM_PARAM *p;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return false;
	}

	p = (CFG_ENUM_PARAM *)param;
	CfgAddItemText(p->b, t, p->depth);

	return true;
}

// Output the folder contents (Recursive, binary)
void CfgOutputFolderBin(BUF *b, FOLDER *f)
{
	UINT i;
	// Validate arguments
	if (b == NULL || f == NULL)
	{
		return;
	}

	// Folder name
	WriteBufStr(b, f->Name);

	// The number of the subfolder
	WriteBufInt(b, LIST_NUM(f->Folders));

	// Subfolder
	for (i = 0;i < LIST_NUM(f->Folders);i++)
	{
		FOLDER *sub = LIST_DATA(f->Folders, i);
		CfgOutputFolderBin(b, sub);

		if ((i % 100) == 99)
		{
			YieldCpu();
		}
	}

	// The number of Items
	WriteBufInt(b, LIST_NUM(f->Items));

	// Item
	for (i = 0;i < LIST_NUM(f->Items);i++)
	{
		char *utf8;
		UINT utf8_size;
		ITEM *t = LIST_DATA(f->Items, i);

		// Item Name
		WriteBufStr(b, t->Name);

		// Type
		WriteBufInt(b, t->Type);

		switch (t->Type)
		{
		case ITEM_TYPE_INT:
			// Integer
			WriteBufInt(b, *((UINT *)t->Buf));
			break;

		case ITEM_TYPE_INT64:
			// 64-bit integer
			WriteBufInt64(b, *((UINT64 *)t->Buf));
			break;

		case ITEM_TYPE_BYTE:
			// Data size
			WriteBufInt(b, t->size);
			// Data
			WriteBuf(b, t->Buf, t->size);
			break;

		case ITEM_TYPE_STRING:
			// String
			utf8_size = CalcUniToUtf8((wchar_t *)t->Buf) + 1;
			utf8 = ZeroMalloc(utf8_size);
			UniToUtf8(utf8, utf8_size, (wchar_t *)t->Buf);
			WriteBufInt(b, StrLen(utf8));
			WriteBuf(b, utf8, StrLen(utf8));
			Free(utf8);
			break;

		case ITEM_TYPE_BOOL:
			// Boolean type
			if (*((bool *)t->Buf) == false)
			{
				WriteBufInt(b, 0);
			}
			else
			{
				WriteBufInt(b, 1);
			}
			break;
		}
	}
}

// Output the contents of the folder (Recursive, text)
void CfgOutputFolderText(BUF *b, FOLDER *f, UINT depth)
{
	CFG_ENUM_PARAM p;
	// Validate arguments
	if (b == NULL || f == NULL)
	{
		return;
	}

	// Output starting of the folder
	CfgAddDeclare(b, f->Name, depth);
	depth++;

	Zero(&p, sizeof(CFG_ENUM_PARAM));
	p.depth = depth;
	p.b = b;
	p.f = f;

	// Enumerate the list of items
	CfgEnumItem(f, CfgEnumItemProc, &p);

	if (LIST_NUM(f->Folders) != 0 && LIST_NUM(f->Items) != 0)
	{
		WriteBuf(b, "\r\n", 2);
	}

	// Enumerate the folder list
	CfgEnumFolder(f, CfgEnumFolderProc, &p);
	// Output the end of the folder
	depth--;
	CfgAddEnd(b, depth);

	//WriteBuf(b, "\r\n", 2);
}

// Output contents of the item
void CfgAddItemText(BUF *b, ITEM *t, UINT depth)
{
	char *data;
	char *sub = NULL;
	UINT len;
	UINT size;
	char *utf8;
	UINT utf8_size;
	wchar_t *string;
	// Validate arguments
	if (b == NULL || t == NULL)
	{
		return;
	}

	// Process the data by its type
	data = NULL;
	switch (t->Type)
	{
	case ITEM_TYPE_INT:
		data = Malloc(32);
		ToStr(data, *((UINT *)t->Buf));
		break;

	case ITEM_TYPE_INT64:
		data = Malloc(64);
		ToStr64(data, *((UINT64 *)t->Buf));
		break;

	case ITEM_TYPE_BYTE:
		data = Base64FromBin(NULL, t->Buf, t->size);
		break;

	case ITEM_TYPE_STRING:
		string = t->Buf;
		utf8_size = CalcUniToUtf8(string);
		utf8_size++;
		utf8 = ZeroMalloc(utf8_size);
		utf8[0] = 0;
		UniToUtf8(utf8, utf8_size, string);
		size = utf8_size;
		data = utf8;
		break;

	case ITEM_TYPE_BOOL:
		size = 32;
		data = Malloc(size);
		if (*((bool *)t->Buf) == false)
		{
			StrCpy(data, size, TAG_FALSE);
		}
		else
		{
			StrCpy(data, size, TAG_TRUE);
		}
		break;
	}
	if (data == NULL)
	{
		return;
	}

	// Output the data line
	CfgAddData(b, t->Type, t->Name, data, sub, depth);

	// Memory release
	Free(data);
}

// Output the data line
void CfgAddData(BUF *b, UINT type, char *name, char *data, char *sub, UINT depth)
{
	char *tmp;
	char *name2;
	char *data2;
	char *sub2 = NULL;
	UINT tmp_size;
	// Validate arguments
	if (b == NULL || type == 0 || name == NULL || data == NULL)
	{
		return;
	}

	name2 = CfgEscape(name);
	data2 = CfgEscape(data);
	if (sub != NULL)
	{
		sub2 = CfgEscape(sub);
	}

	tmp_size = StrLen(name2) + StrLen(data2) + 2 + 64 + 1;
	tmp = Malloc(tmp_size);

	if (sub2 != NULL)
	{
		StrCpy(tmp, tmp_size, CfgTypeToStr(type));
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, name2);
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, data2);
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, sub2);
	}
	else
	{
		StrCpy(tmp, tmp_size, CfgTypeToStr(type));
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, name2);
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, data2);
	}

	Free(name2);
	Free(data2);
	if (sub2 != NULL)
	{
		Free(sub2);
	}
	CfgAddLine(b, tmp, depth);
	Free(tmp);
}

// Convert the type of data to a string
char *CfgTypeToStr(UINT type)
{
	switch (type)
	{
	case ITEM_TYPE_INT:
		return TAG_INT;
	case ITEM_TYPE_INT64:
		return TAG_INT64;
	case ITEM_TYPE_BYTE:
		return TAG_BYTE;
	case ITEM_TYPE_STRING:
		return TAG_STRING;
	case ITEM_TYPE_BOOL:
		return TAG_BOOL;
	}
	return NULL;
}

// Outputs the End line
void CfgAddEnd(BUF *b, UINT depth)
{
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	CfgAddLine(b, "}", depth);
//	CfgAddLine(b, TAG_END, depth);
}

// Outputs the Declare lines
void CfgAddDeclare(BUF *b, char *name, UINT depth)
{
	char *tmp;
	char *name2;
	UINT tmp_size;
	// Validate arguments
	if (b == NULL || name == NULL)
	{
		return;
	}

	name2 = CfgEscape(name);

	tmp_size = StrLen(name2) + 2 + StrLen(TAG_DECLARE);
	tmp = Malloc(tmp_size);

	Format(tmp, 0, "%s %s", TAG_DECLARE, name2);
	CfgAddLine(b, tmp, depth);
	CfgAddLine(b, "{", depth);
	Free(tmp);
	Free(name2);
}

// Outputs one line
void CfgAddLine(BUF *b, char *str, UINT depth)
{
	UINT i;
	// Validate arguments
	if (b == NULL)
	{
		return;
	}

	for (i = 0;i < depth;i++)
	{
		WriteBuf(b, "\t", 1);
	}
	WriteBuf(b, str, StrLen(str));
	WriteBuf(b, "\r\n", 2);
}

// Convert the folder to a stream
BUF *CfgFolderToBuf(FOLDER *f, bool textmode)
{
	return CfgFolderToBufEx(f, textmode, false);
}
BUF *CfgFolderToBufEx(FOLDER *f, bool textmode, bool no_banner)
{
	// Validate arguments
	if (f == NULL)
	{
		return NULL;
	}

	if (textmode)
	{
		return CfgFolderToBufTextEx(f, no_banner);
	}
	else
	{
		return CfgFolderToBufBin(f);;
	}
}

// Escape restoration of the string
char *CfgUnescape(char *str)
{
	char *tmp;
	char *ret;
	char tmp2[16];
	UINT len, wp, i;
	UINT code;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	tmp = ZeroMalloc(len + 1);
	wp = 0;
	if (len == 1 && str[0] == '$')
	{
		// Empty character
		tmp[0] = 0;
	}
	else
	{
		for (i = 0;i < len;i++)
		{
			if (str[i] != '$')
			{
				tmp[wp++] = str[i];
			}
			else
			{
				tmp2[0] = '0';
				tmp2[1] = 'x';
				tmp2[2] = str[i + 1];
				tmp2[3] = str[i + 2];
				i += 2;
				tmp2[4] = 0;
				code = ToInt(tmp2);
				tmp[wp++] = (char)code;
			}
		}
	}
	ret = Malloc(StrLen(tmp) + 1);
	StrCpy(ret, StrLen(tmp) + 1, tmp);
	Free(tmp);
	return ret;
}

// Escape the string
char *CfgEscape(char *str)
{
	char *tmp;
	char *ret;
	char tmp2[16];
	UINT len;
	UINT wp, i;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	tmp = ZeroMalloc(len * 3 + 2);
	if (len == 0)
	{
		// Empty character
		StrCpy(tmp, (len * 3 + 2), "$");
	}
	else
	{
		// Non null character
		wp = 0;
		for (i = 0;i < len;i++)
		{
			if (CfgCheckCharForName(str[i]))
			{
				tmp[wp++] = str[i];
			}
			else
			{
				tmp[wp++] = '$';
				Format(tmp2, sizeof(tmp2), "%02X", (UINT)str[i]);
				tmp[wp++] = tmp2[0];
				tmp[wp++] = tmp2[1];
			}
		}
	}
	ret = Malloc(StrLen(tmp) + 1);
	StrCpy(ret, 0, tmp);
	Free(tmp);
	return ret;
}

// Check if the character can be used in the name
bool CfgCheckCharForName(char c)
{
	if (c >= 0 && c <= 31)
	{
		return false;
	}
	if (c == ' ' || c == '\t')
	{
		return false;
	}
	if (c == '$')
	{
		return false;
	}
	return true;
}

// Get the string type value
bool CfgGetStr(FOLDER *f, char *name, char *str, UINT size)
{
	wchar_t *tmp;
	UINT tmp_size;
	// Validate arguments
	if (f == NULL || name == NULL || str == NULL)
	{
		return false;
	}

	str[0] = 0;

	// Get unicode string temporarily
	tmp_size = size * 4 + 10; // Just to make sure, a quantity of this amount is secured.
	tmp = Malloc(tmp_size);
	if (CfgGetUniStr(f, name, tmp, tmp_size) == false)
	{
		// Failure
		Free(tmp);
		return false;
	}

	// Copy to the ANSI string
	UniToStr(str, size, tmp);
	Free(tmp);

	return true;
}

// Get the value of the unicode_string type
bool CfgGetUniStr(FOLDER *f, char *name, wchar_t *str, UINT size)
{
	ITEM *t;
	// Validate arguments
	if (f == NULL || name == NULL || str == NULL)
	{
		return false;
	}

	str[0] = 0;

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return false;
	}
	if (t->Type != ITEM_TYPE_STRING)
	{
		return false;
	}
	UniStrCpy(str, size, t->Buf);
	return true;
}

// Check for the existence of item
bool CfgIsItem(FOLDER *f, char *name)
{
	ITEM *t;
	// Validate arguments
	if (f == NULL || name == NULL)
	{
		return false;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return false;
	}

	return true;
}

// Get the byte[] type as a BUF
BUF *CfgGetBuf(FOLDER *f, char *name)
{
	ITEM *t;
	BUF *b;
	// Validate arguments
	if (f == NULL || name == NULL)
	{
		return NULL;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, t->Buf, t->size);
	SeekBuf(b, 0, 0);

	return b;
}

// Get the value of type byte[]
UINT CfgGetByte(FOLDER *f, char *name, void *buf, UINT size)
{
	ITEM *t;
	// Validate arguments
	if (f == NULL || name == NULL || buf == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_BYTE)
	{
		return 0;
	}
	if (t->size <= size)
	{
		Copy(buf, t->Buf, t->size);
		return t->size;
	}
	else
	{
		Copy(buf, t->Buf, size);
		return t->size;
	}
}

// Get the value of type int64
UINT64 CfgGetInt64(FOLDER *f, char *name)
{
	ITEM *t;
	UINT64 *ret;
	// Validate arguments
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_INT64)
	{
		return 0;
	}
	if (t->size != sizeof(UINT64))
	{
		return 0;
	}

	ret = (UINT64 *)t->Buf;
	return *ret;
}

// Get the value of the bool type
bool CfgGetBool(FOLDER *f, char *name)
{
	ITEM *t;
	bool *ret;
	// Validate arguments
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_BOOL)
	{
		return 0;
	}
	if (t->size != sizeof(bool))
	{
		return 0;
	}

	ret = (bool *)t->Buf;
	if (*ret == false)
	{
		return false;
	}
	else
	{
		return true;
	}
}

// Get the value of the int type
UINT CfgGetInt(FOLDER *f, char *name)
{
	ITEM *t;
	UINT *ret;
	// Validate arguments
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_INT)
	{
		return 0;
	}
	if (t->size != sizeof(UINT))
	{
		return 0;
	}

	ret = (UINT *)t->Buf;
	return *ret;
}

// Search for an item
ITEM *CfgFindItem(FOLDER *parent, char *name)
{
	ITEM *t, tt;
	// Validate arguments
	if (parent == NULL || name == NULL)
	{
		return NULL;
	}

	tt.Name = ZeroMalloc(StrLen(name) + 1);
	StrCpy(tt.Name, 0, name);
	t = Search(parent->Items, &tt);
	Free(tt.Name);

	return t;
}

// Get a folder
FOLDER *CfgGetFolder(FOLDER *parent, char *name)
{
	return CfgFindFolder(parent, name);
}

// Search a folder
FOLDER *CfgFindFolder(FOLDER *parent, char *name)
{
	FOLDER *f, ff;
	// Validate arguments
	if (parent == NULL || name == NULL)
	{
		return NULL;
	}

	ff.Name = ZeroMalloc(StrLen(name) + 1);
	StrCpy(ff.Name, 0, name);
	f = Search(parent->Folders, &ff);
	Free(ff.Name);

	return f;
}

// Adding a string type
ITEM *CfgAddStr(FOLDER *f, char *name, char *str)
{
	wchar_t *tmp;
	UINT tmp_size;
	ITEM *t;
	// Validate arguments
	if (f == NULL || name == NULL || str == NULL)
	{
		return NULL;
	}

	// Convert to a Unicode string
	tmp_size = CalcStrToUni(str);
	if (tmp_size == 0)
	{
		return NULL;
	}
	tmp = Malloc(tmp_size);
	StrToUni(tmp, tmp_size, str);
	t = CfgAddUniStr(f, name, tmp);
	Free(tmp);

	return t;
}

// Add unicode_string type
ITEM *CfgAddUniStr(FOLDER *f, char *name, wchar_t *str)
{
	// Validate arguments
	if (f == NULL || name == NULL || str == NULL)
	{
		return NULL;
	}

	return CfgCreateItem(f, name, ITEM_TYPE_STRING, str, UniStrSize(str));
}

// Add a binary
ITEM *CfgAddBuf(FOLDER *f, char *name, BUF *b)
{
	// Validate arguments
	if (f == NULL || name == NULL || b == NULL)
	{
		return NULL;
	}
	return CfgAddByte(f, name, b->Buf, b->Size);
}

// Add byte type
ITEM *CfgAddByte(FOLDER *f, char *name, void *buf, UINT size)
{
	// Validate arguments
	if (f == NULL || name == NULL || buf == NULL)
	{
		return NULL;
	}
	return CfgCreateItem(f, name, ITEM_TYPE_BYTE, buf, size);
}

// Add a 64-bit integer type
ITEM *CfgAddInt64(FOLDER *f, char *name, UINT64 i)
{
	// Validate arguments
	if (f == NULL || name == NULL)
	{
		return NULL;
	}
	return CfgCreateItem(f, name, ITEM_TYPE_INT64, &i, sizeof(UINT64));
}

// Get an IP address type
bool CfgGetIp(FOLDER *f, char *name, struct IP *ip)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (f == NULL || name == NULL || ip == NULL)
	{
		return false;
	}

	Zero(ip, sizeof(IP));

	if (CfgGetStr(f, name, tmp, sizeof(tmp)) == false)
	{
		return false;
	}

	if (StrToIP(ip, tmp) == false)
	{
		return false;
	}

	return true;
}
UINT CfgGetIp32(FOLDER *f, char *name)
{
	IP p;
	// Validate arguments
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	if (CfgGetIp(f, name, &p) == false)
	{
		return 0;
	}

	return IPToUINT(&p);
}
bool CfgGetIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr)
{
	IP ip;
	// Validate arguments
	Zero(addr, sizeof(IPV6_ADDR));
	if (f == NULL || name == NULL || addr == NULL)
	{
		return false;
	}

	if (CfgGetIp(f, name, &ip) == false)
	{
		return false;
	}

	if (IsIP6(&ip) == false)
	{
		return false;
	}

	if (IPToIPv6Addr(addr, &ip) == false)
	{
		return false;
	}

	return true;
}

// Add an IP address type
ITEM *CfgAddIp(FOLDER *f, char *name, struct IP *ip)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (f == NULL || name == NULL || ip == NULL)
	{
		return NULL;
	}

	IPToStr(tmp, sizeof(tmp), ip);

	return CfgAddStr(f, name, tmp);
}
ITEM *CfgAddIp32(FOLDER *f, char *name, UINT ip)
{
	IP p;
	// Validate arguments
	if (f == NULL || name == NULL)
	{
		return NULL;
	}

	UINTToIP(&p, ip);

	return CfgAddIp(f, name, &p);
}
ITEM *CfgAddIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr)
{
	IP ip;
	// Validate arguments
	if (f == NULL || name == NULL || addr == NULL)
	{
		return NULL;
	}

	IPv6AddrToIP(&ip, addr);

	return CfgAddIp(f, name, &ip);
}

// Add an integer type
ITEM *CfgAddInt(FOLDER *f, char *name, UINT i)
{
	// Validate arguments
	if (f == NULL || name == NULL)
	{
		return NULL;
	}
	return CfgCreateItem(f, name, ITEM_TYPE_INT, &i, sizeof(UINT));
}

// Adding a bool type
ITEM *CfgAddBool(FOLDER *f, char *name, bool b)
{
	// Validate arguments
	if (f == NULL || name == NULL)
	{
		return NULL;
	}

	return CfgCreateItem(f, name, ITEM_TYPE_BOOL, &b, sizeof(bool));
}

// Comparison function of the item names
int CmpItemName(void *p1, void *p2)
{
	ITEM *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(ITEM **)p1;
	f2 = *(ITEM **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	return StrCmpi(f1->Name, f2->Name);
}

// Comparison function of the folder names
int CmpFolderName(void *p1, void *p2)
{
	FOLDER *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(FOLDER **)p1;
	f2 = *(FOLDER **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	return StrCmpi(f1->Name, f2->Name);
}

// Enumeration of items
void CfgEnumItem(FOLDER *f, ENUM_ITEM proc, void *param)
{
	UINT i;
	// Validate arguments
	if (f == NULL || proc == NULL)
	{
		return;
	}
	
	for (i = 0;i < LIST_NUM(f->Items);i++)
	{
		ITEM *tt = LIST_DATA(f->Items, i);
		if (proc(tt, param) == false)
		{
			break;
		}
	}
}

// Enumerate the folders and store it in the token list
TOKEN_LIST *CfgEnumFolderToTokenList(FOLDER *f)
{
	TOKEN_LIST *t, *ret;
	UINT i;
	// Validate arguments
	if (f == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(f->Folders);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = LIST_DATA(f->Folders, i);
		t->Token[i] = CopyStr(ff->Name);
	}

	ret = UniqueToken(t);
	FreeToken(t);

	return ret;
}

// Enumerate items and store these to the token list
TOKEN_LIST *CfgEnumItemToTokenList(FOLDER *f)
{
	TOKEN_LIST *t, *ret;
	UINT i;
	// Validate arguments
	if (f == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(f->Items);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = LIST_DATA(f->Items, i);
		t->Token[i] = CopyStr(ff->Name);
	}

	ret = UniqueToken(t);
	FreeToken(t);

	return ret;
}

// Folder enumeration
void CfgEnumFolder(FOLDER *f, ENUM_FOLDER proc, void *param)
{
	UINT i;
	// Validate arguments
	if (f == NULL || proc == NULL)
	{
		return;
	}
	
	for (i = 0;i < LIST_NUM(f->Folders);i++)
	{
		FOLDER *ff = LIST_DATA(f->Folders, i);
		if (proc(ff, param) == false)
		{
			break;
		}

		if ((i % 100) == 99)
		{
			YieldCpu();
		}
	}
}

// Create an item
ITEM *CfgCreateItem(FOLDER *parent, char *name, UINT type, void *buf, UINT size)
{
	UINT name_size;
	ITEM *t;
#ifdef	CHECK_CFG_NAME_EXISTS
	ITEM tt;
#endif	// CHECK_CFG_NAME_EXISTS
	// Validate arguments
	if (parent == NULL || name == NULL || type == 0 || buf == NULL)
	{
		return NULL;
	}

	name_size = StrLen(name) + 1;

#ifdef	CHECK_CFG_NAME_EXISTS

	// Check whether there are any items with the same name already
	tt.Name = ZeroMalloc(name_size);
	StrCpy(tt.Name, 0, name);
	t = Search(parent->Items, &tt);
	Free(tt.Name);
	if (t != NULL)
	{
		// Duplicated
		return NULL;
	}

#endif	// CHECK_CFG_NAME_EXISTS

	t = ZeroMalloc(sizeof(ITEM));
	t->Buf = Malloc(size);
	Copy(t->Buf, buf, size);
	t->Name = ZeroMalloc(name_size);
	StrCpy(t->Name, 0, name);
	t->Type = type;
	t->size = size;
	t->Parent = parent;
	
	// Add to the parent list 
	Insert(parent->Items, t);

	return t;
}

// Delete the item
void CfgDeleteItem(ITEM *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	// Remove from the parent list
	Delete(t->Parent->Items, t);

	// Memory release
	Free(t->Buf);
	Free(t->Name);
	Free(t);
}


// Delete the folder
void CfgDeleteFolder(FOLDER *f)
{
	FOLDER **ff;
	ITEM **tt;
	UINT num, i;
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	if(f->Folders == NULL)
	{
		return;
	}

	// Remove all subfolders
	num = LIST_NUM(f->Folders);
	if (num  != 0)
	{
		ff = Malloc(sizeof(FOLDER *) * num);
		Copy(ff, f->Folders->p, sizeof(FOLDER *) * num);
		for (i = 0;i < num;i++)
		{
			CfgDeleteFolder(ff[i]);
		}
		Free(ff);
	}

	// Remove all items
	num = LIST_NUM(f->Items);
	if (num != 0)
	{
		tt = Malloc(sizeof(ITEM *) * num);
		Copy(tt, f->Items->p, sizeof(ITEM *) * num);
		for (i = 0;i < num;i++)
		{
			CfgDeleteItem(tt[i]);
		}
		Free(tt);
	}

	// Memory release
	Free(f->Name);
	// Remove from the parent list
	if (f->Parent != NULL)
	{
		Delete(f->Parent->Folders, f);
	}
	// Release the list
	ReleaseList(f->Folders);
	ReleaseList(f->Items);

	// Release of the memory of the body
	Free(f);
}

// Creating a root
FOLDER *CfgCreateRoot()
{
	return CfgCreateFolder(NULL, TAG_ROOT);
}

// Create a folder
FOLDER *CfgCreateFolder(FOLDER *parent, char *name)
{
	UINT size;
	FOLDER *f;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	size = StrLen(name) + 1;

#ifdef	CHECK_CFG_NAME_EXISTS

	// Check the name in the parent list
	if (parent != NULL)
	{
		FOLDER ff;
		ff.Name = ZeroMalloc(size);
		StrCpy(ff.Name, 0, name);
		f = Search(parent->Folders, &ff);
		Free(ff.Name);
		if (f != NULL)
		{
			// Folder with the same name already exists
			return NULL;
		}
	}

#endif	// CHECK_CFG_NAME_EXISTS

	f = ZeroMalloc(sizeof(FOLDER));
	f->Items = NewListFast(CmpItemName);
	f->Folders = NewListFast(CmpFolderName);
	f->Name = ZeroMalloc(size);
	StrCpy(f->Name, 0, name);
	f->Parent = parent;

	// Add to parentlist
	if (f->Parent != NULL)
	{
		Insert(f->Parent->Folders, f);
	}
	return f;
}


