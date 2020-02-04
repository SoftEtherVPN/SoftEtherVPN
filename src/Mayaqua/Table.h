// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Table.h
// Header of Table.c

#ifndef	TABLE_H
#define	TABLE_H

#define	UNICODE_CACHE_FILE		L".unicode_cache_%s.dat"

#define	LANGLIST_FILENAME		"|languages.txt"
#define	LANGLIST_FILENAME_WINE	"|languages_wine.txt"

#define	LANG_CONFIG_FILENAME	L"$lang.config"
#define	LANG_CONFIG_TEMPLETE	"|lang.config"

// Language constant
#define SE_LANG_JAPANESE			0	// Japanese
#define SE_LANG_ENGLISH				1	// English
#define SE_LANG_CHINESE_ZH			2	// Simplified Chinese


// String table
struct TABLE
{
	char *name;
	char *str;
	wchar_t *unistr;
};

// Unicode cache structure
typedef struct UNICODE_CACHE
{
	char StrFileName[256];	// String file name
	UINT StrFileSize;		// String file size
	char MachineName[256];	// Machine name
	UINT OsType;			// OS type
	UCHAR hash[MD5_SIZE];	// Hash
	UCHAR CharSet[64];		// Type of character code
} UNICODE_CACHE;

// Macro
#define	_SS(name)		(GetTableStr((char *)(name)))
#define	_UU(name)		(GetTableUniStr((char *)(name)))
#define	_II(name)		(GetTableInt((char *)(name)))
#define	_E(name)		(GetUniErrorStr((UINT)(name)))
#define	_EA(name)		(GetErrorStr((UINT)(name)))
#define _GETLANG()		(_II("LANG"))

// Language list
struct LANGLIST
{
	UINT Id;						// Number
	char Name[32];					// Identifier
	wchar_t TitleEnglish[128];		// English notation
	wchar_t TitleLocal[128];		// Local notation
	LIST *LcidList;					// Windows LCID list
	LIST *LangList;					// UNIX LANG environment variable list
};


// Function prototype
bool LoadTable(char *filename);
bool LoadTableW(wchar_t *filename);
bool LoadTableMain(wchar_t *filename);
bool LoadTableFromBuf(BUF *b);
void FreeTable();
TABLE *ParseTableLine(char *line, char *prefix, UINT prefix_size, LIST *replace_list);
void UnescapeStr(char *src);
int CmpTableName(void *p1, void *p2);
TABLE *FindTable(char *name);
TOKEN_LIST *GetTableNameStartWith(char *str);
char *GetTableStr(char *name);
wchar_t *GetTableUniStr(char *name);
char *GetErrorStr(UINT err);
wchar_t *GetUniErrorStr(UINT err);
UINT GetTableInt(char *name);
void GenerateUnicodeCacheFileName(wchar_t *name, UINT size, wchar_t *strfilename, UINT strfilesize, UCHAR *filehash);
void SaveUnicodeCache(wchar_t *strfilename, UINT strfilesize, UCHAR *hash);
bool LoadUnicodeCache(wchar_t *strfilename, UINT strfilesize, UCHAR *hash);
void InitTable();

LIST *LoadLangList();
void FreeLangList(LIST *o);

LANGLIST *GetBestLangByName(LIST *o, char *name);
LANGLIST *GetBestLangByLcid(LIST *o, UINT lcid);
LANGLIST *GetBestLangByLangStr(LIST *o, char *str);
LANGLIST *GetBestLangForCurrentEnvironment(LIST *o);
LANGLIST *GetLangById(LIST *o, UINT id);

bool LoadLangConfig(wchar_t *filename, char *str, UINT str_size);
bool LoadLangConfigCurrentDir(char *str, UINT str_size);
bool SaveLangConfig(wchar_t *filename, char *str);
bool SaveLangConfigCurrentDir(char *str);

void GetCurrentLang(LANGLIST *e);
UINT GetCurrentLangId();

void GetCurrentOsLang(LANGLIST *e);
UINT GetCurrentOsLangId();

#endif	// TABLE_H



