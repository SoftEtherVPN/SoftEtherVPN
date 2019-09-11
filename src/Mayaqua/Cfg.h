// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Cfg.h
// Header of Cfg.c

#ifndef	CFG_H
#define	CFG_H

// Macro
//#define	CHECK_CFG_NAME_EXISTS			// Check duplication of the existing name

#define	SAVE_BINARY_FILE_NAME_SWITCH	L"$save_binary"

// Constants
#define	TAG_DECLARE			"declare"
#define	TAG_STRING			"string"
#define	TAG_INT				"uint"
#define	TAG_INT64			"uint64"
#define	TAG_BOOL			"bool"
#define	TAG_BYTE			"byte"
#define	TAG_TRUE			"true"
#define	TAG_FALSE			"false"
#define	TAG_END				"end"
#define	TAG_ROOT			"root"

#define	TAG_CPYRIGHT		"\xef\xbb\xbf# Software Configuration File\r\n# ---------------------------\r\n# \r\n# You may edit this file when the VPN Server / Client / Bridge program is not running.\r\n# \r\n# In prior to edit this file manually by your text editor,\r\n# shutdown the VPN Server / Client / Bridge background service.\r\n# Otherwise, all changes will be lost.\r\n# \r\n"
#define	TAG_BINARY			"SEVPN_DB"

// Data type
#define	ITEM_TYPE_INT		1		// int
#define	ITEM_TYPE_INT64		2		// int64
#define	ITEM_TYPE_BYTE		3		// byte
#define	ITEM_TYPE_STRING	4		// string
#define	ITEM_TYPE_BOOL		5		// bool

// Folder
struct FOLDER
{
	char *Name;				// Folder name
	LIST *Items;			// List of items
	LIST *Folders;			// Subfolder
	struct FOLDER *Parent;	// Parent Folder
};

// Item
struct ITEM
{
	char *Name;				// Item Name
	UINT Type;				// Data type
	void *Buf;				// Data
	UINT size;				// Data size
	FOLDER *Parent;			// Parent Folder
};

// Configuration file reader and writer
struct CFG_RW
{
	LOCK *lock;				// Lock
	char *FileName;			// File name (ANSI)
	wchar_t *FileNameW;		// File name (Unicode)
	IO *Io;					// IO
	UCHAR LashHash[SHA1_SIZE];	// Hash value which is written last
	bool DontBackup;		// Do not use the backup
	wchar_t LastSavedDateStr[MAX_SIZE];	// Date and time string that last saved
};

typedef bool (*ENUM_FOLDER)(FOLDER *f, void *param);
typedef bool (*ENUM_ITEM)(ITEM *t, void *param);

// Parameters for the enumeration
struct CFG_ENUM_PARAM
{
	BUF *b;
	FOLDER *f;
	UINT depth;
};

int CmpItemName(void *p1, void *p2);
int CmpFolderName(void *p1, void *p2);
ITEM *CfgCreateItem(FOLDER *parent, char *name, UINT type, void *buf, UINT size);
void CfgDeleteFolder(FOLDER *f);
FOLDER *CfgCreateFolder(FOLDER *parent, char *name);
void CfgEnumFolder(FOLDER *f, ENUM_FOLDER proc, void *param);
TOKEN_LIST *CfgEnumFolderToTokenList(FOLDER *f);
TOKEN_LIST *CfgEnumItemToTokenList(FOLDER *f);
void CfgEnumItem(FOLDER *f, ENUM_ITEM proc, void *param);
FOLDER *CfgFindFolder(FOLDER *parent, char *name);
ITEM *CfgFindItem(FOLDER *parent, char *name);
ITEM *CfgAddInt(FOLDER *f, char *name, UINT i);
ITEM *CfgAddBool(FOLDER *f, char *name, bool b);
ITEM *CfgAddInt64(FOLDER *f, char *name, UINT64 i);
ITEM *CfgAddByte(FOLDER *f, char *name, void *buf, UINT size);
ITEM *CfgAddBuf(FOLDER *f, char *name, BUF *b);
ITEM *CfgAddStr(FOLDER *f, char *name, char *str);
ITEM *CfgAddUniStr(FOLDER *f, char *name, wchar_t *str);
FOLDER *CfgGetFolder(FOLDER *parent, char *name);
UINT CfgGetInt(FOLDER *f, char *name);
bool CfgGetBool(FOLDER *f, char *name);
UINT64 CfgGetInt64(FOLDER *f, char *name);
UINT CfgGetByte(FOLDER *f, char *name, void *buf, UINT size);
BUF *CfgGetBuf(FOLDER *f, char *name);
bool CfgGetStr(FOLDER *f, char *name, char *str, UINT size);
bool CfgGetUniStr(FOLDER *f, char *name, wchar_t *str, UINT size);
bool CfgIsItem(FOLDER *f, char *name);
char *CfgEscape(char *name);
bool CfgCheckCharForName(char c);
char *CfgUnescape(char *str);
BUF *CfgFolderToBuf(FOLDER *f, bool textmode);
BUF *CfgFolderToBufEx(FOLDER *f, bool textmode, bool no_banner);
BUF *CfgFolderToBufTextEx(FOLDER *f, bool no_banner);
BUF *CfgFolderToBufBin(FOLDER *f);
void CfgOutputFolderText(BUF *b, FOLDER *f, UINT depth);
void CfgOutputFolderBin(BUF *b, FOLDER *f);
void CfgAddLine(BUF *b, char *str, UINT depth);
void CfgAddDeclare(BUF *b, char *name, UINT depth);
void CfgAddEnd(BUF *b, UINT depth);
void CfgAddData(BUF *b, UINT type, char *name, char *data, char *sub, UINT depth);
char *CfgTypeToStr(UINT type);
void CfgAddItemText(BUF *b, ITEM *t, UINT depth);
bool CfgEnumFolderProc(FOLDER *f, void *param);
bool CfgEnumItemProc(ITEM *t, void *param);
FOLDER *CfgBufTextToFolder(BUF *b);
FOLDER *CfgBufBinToFolder(BUF *b);
void CfgReadNextFolderBin(BUF *b, FOLDER *parent);
char *CfgReadNextLine(BUF *b);
bool CfgReadNextTextBUF(BUF *b, FOLDER *current);
void CfgSave(FOLDER *f, char *name);
void CfgSaveW(FOLDER *f, wchar_t *name);
bool CfgSaveEx(CFG_RW *rw, FOLDER *f, char *name);
bool CfgSaveExW(CFG_RW *rw, FOLDER *f, wchar_t *name);
bool CfgSaveExW2(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size);
bool CfgSaveExW3(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size, bool write_binary);
FOLDER *CfgRead(char *name);
FOLDER *CfgReadW(wchar_t *name);
FOLDER *CfgCreateRoot();
void CfgTest();
void CfgTest2(FOLDER *f, UINT n);
CFG_RW *NewCfgRw(FOLDER **root, char *cfg_name);
CFG_RW *NewCfgRwEx(FOLDER **root, char *cfg_name, bool dont_backup);
CFG_RW *NewCfgRwExW(FOLDER **root, wchar_t *cfg_name, bool dont_backup);
CFG_RW *NewCfgRwEx2W(FOLDER **root, wchar_t *cfg_name, bool dont_backup, wchar_t *template_name);
CFG_RW *NewCfgRwEx2A(FOLDER **root, char *cfg_name_a, bool dont_backup, char *template_name_a);
UINT SaveCfgRw(CFG_RW *rw, FOLDER *f);
UINT SaveCfgRwEx(CFG_RW *rw, FOLDER *f, UINT revision_number);
void FreeCfgRw(CFG_RW *rw);
ITEM *CfgAddIp32(FOLDER *f, char *name, UINT ip);
UINT CfgGetIp32(FOLDER *f, char *name);
bool CfgGetIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr);
ITEM *CfgAddIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr);
bool FileCopy(char *src, char *dst);
bool FileCopyW(wchar_t *src, wchar_t *dst);
bool FileCopyExW(wchar_t *src, wchar_t *dst, bool read_lock);
void BackupCfgWEx(CFG_RW *rw, FOLDER *f, wchar_t *original, UINT revision_number);

#if	(!defined(CFG_C)) || (!defined(OS_UNIX))
bool CfgGetIp(FOLDER *f, char *name, struct IP *ip);
ITEM *CfgAddIp(FOLDER *f, char *name, struct IP *ip);
#endif

#endif	// CFG_H



