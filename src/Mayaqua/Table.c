// SoftEther VPN Source Code - Stable Edition Repository
// Mayaqua Kernel
// 
// SoftEther VPN Server, Client and Bridge are free software under the Apache License, Version 2.0.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// Copyright (c) all contributors on SoftEther VPN project in GitHub.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// This stable branch is officially managed by Daiyuu Nobori, the owner of SoftEther VPN Project.
// Pull requests should be sent to the Developer Edition Master Repository on https://github.com/SoftEtherVPN/SoftEtherVPN
// 
// License: The Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
// 
// DISCLAIMER
// ==========
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN, UNDER
// JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY, MERGE, PUBLISH,
// DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS SOFTWARE, THAT ANY
// JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS SOFTWARE OR ITS CONTENTS,
// AGAINST US (SOFTETHER PROJECT, SOFTETHER CORPORATION, DAIYUU NOBORI OR OTHER
// SUPPLIERS), OR ANY JURIDICAL DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND
// OF USING, COPYING, MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING,
// AND/OR SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO EXCLUSIVE
// JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO, JAPAN. YOU MUST WAIVE
// ALL DEFENSES OF LACK OF PERSONAL JURISDICTION AND FORUM NON CONVENIENS.
// PROCESS MAY BE SERVED ON EITHER PARTY IN THE MANNER AUTHORIZED BY APPLICABLE
// LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS YOU HAVE
// A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY CRIMINAL LAWS OR CIVIL
// RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS SOFTWARE IN OTHER COUNTRIES IS
// COMPLETELY AT YOUR OWN RISK. THE SOFTETHER VPN PROJECT HAS DEVELOPED AND
// DISTRIBUTED THIS SOFTWARE TO COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING
// CIVIL RIGHTS INCLUDING PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER
// COUNTRIES' LAWS OR CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES.
// WE HAVE NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+ COUNTRIES
// AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE WORLD, WITH
// DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY COUNTRIES' LAWS, REGULATIONS
// AND CIVIL RIGHTS TO MAKE THE SOFTWARE COMPLY WITH ALL COUNTRIES' LAWS BY THE
// PROJECT. EVEN IF YOU WILL BE SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A
// PUBLIC SERVANT IN YOUR COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE
// LIABLE TO RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT JUST A
// STATEMENT FOR WARNING AND DISCLAIMER.
// 
// READ AND UNDERSTAND THE 'WARNING.TXT' FILE BEFORE USING THIS SOFTWARE.
// SOME SOFTWARE PROGRAMS FROM THIRD PARTIES ARE INCLUDED ON THIS SOFTWARE WITH
// LICENSE CONDITIONS WHICH ARE DESCRIBED ON THE 'THIRD_PARTY.TXT' FILE.
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


// Table.c
// Read and management routines for string table

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// List of TABLE
static LIST *TableList = NULL;
static wchar_t old_table_name[MAX_SIZE] = {0};		// Old table name
static LANGLIST current_lang = {0};
static LANGLIST current_os_lang = {0};

// Initialization of string table routine
void InitTable()
{
	LIST *o;
	char tmp[MAX_SIZE];
	LANGLIST *e = NULL;
	LANGLIST *os_lang = NULL;
	char table_name[MAX_SIZE];
	if (MayaquaIsMinimalMode())
	{
		// Not to load in case of minimum mode
		return;
	}

	o = LoadLangList();
	if (o == NULL)
	{
LABEL_FATAL_ERROR:
		Alert("Fatal Error: The file \"hamcore.se2\" is missing or broken.\r\nPlease check hamcore.se2.\r\n\r\n(First, reboot the computer. If this problem occurs again, please reinstall VPN software files.)", NULL);
		exit(-1);
		return;
	}

	// Read the lang.config
	if (LoadLangConfigCurrentDir(tmp, sizeof(tmp)))
	{
		e = GetBestLangByName(o, tmp);
	}

	os_lang = GetBestLangForCurrentEnvironment(o);

	if (e == NULL)
	{
		e = os_lang;
	}

	if (e == NULL)
	{
		goto LABEL_FATAL_ERROR;
	}

	SaveLangConfigCurrentDir(e->Name);

	Copy(&current_lang, e, sizeof(LANGLIST));
	Copy(&current_os_lang, os_lang, sizeof(LANGLIST));

	current_lang.LangList = current_lang.LcidList = NULL;
	current_os_lang.LangList = current_os_lang.LcidList = NULL;

	// Read the corresponding string table
	Format(table_name, sizeof(table_name), "|strtable_%s.stb", current_lang.Name);
	if (LoadTable(table_name) == false)
	{
		goto LABEL_FATAL_ERROR;
	}

	FreeLangList(o);
}

// Get the language of the current OS
void GetCurrentOsLang(LANGLIST *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	Copy(e, &current_os_lang, sizeof(LANGLIST));
}

// Get the language ID of the current OS
UINT GetCurrentOsLangId()
{
	LANGLIST e;

	Zero(&e, sizeof(e));

	GetCurrentOsLang(&e);

	return e.Id;
}

// Get the current language
void GetCurrentLang(LANGLIST *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	Copy(e, &current_lang, sizeof(LANGLIST));
}

// Get the current language ID
UINT GetCurrentLangId()
{
	LANGLIST e;

	Zero(&e, sizeof(e));

	GetCurrentLang(&e);

	return e.Id;
}

// Write to the lang.config file in the current directory
bool SaveLangConfigCurrentDir(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	return SaveLangConfig(LANG_CONFIG_FILENAME, str);
}

// Write to the lang.config file
bool SaveLangConfig(wchar_t *filename, char *str)
{
	BUF *b;
	LIST *o;
	UINT i;
	bool ret;
	// Validate arguments
	if (filename == NULL)
	{
		return false;
	}

	// Read the template
	b = ReadDump(LANG_CONFIG_TEMPLETE);
	if (b == NULL)
	{
		return false;
	}

	SeekBuf(b, b->Size, 0);

	o = LoadLangList();
	if (o != NULL)
	{
		wchar_t tmp[MAX_SIZE];

		AppendBufStr(b, "# Available Language IDs are:\r\n");

		for (i = 0;i < LIST_NUM(o);i++)
		{
			LANGLIST *e = LIST_DATA(o, i);

			UniFormat(tmp, sizeof(tmp), L"#  %S: %s (%s)\r\n",
				e->Name, e->TitleEnglish, e->TitleLocal);

			AppendBufUtf8(b, tmp);
		}

		AppendBufStr(b, "\r\n\r\n# Specify a Language ID here.\r\n");
		AppendBufStr(b, str);
		AppendBufStr(b, "\r\n\r\n");

		FreeLangList(o);
	}

	ret = DumpBufWIfNecessary(b, filename);

	FreeBuf(b);

	return ret;
}

// Read the lang.config file in the current directory
bool LoadLangConfigCurrentDir(char *str, UINT str_size)
{
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	return LoadLangConfig(LANG_CONFIG_FILENAME, str, str_size);
}

// Read the lang.config file
bool LoadLangConfig(wchar_t *filename, char *str, UINT str_size)
{
	BUF *b;
	bool ret = false;
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

	while (true)
	{
		char *line = CfgReadNextLine(b);

		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false)
		{
			if (StartWith(line, "#") == false && StartWith(line, "//") == false && StartWith(line, ";") == false &&
				InStr(line, "#") == false)
			{
				StrCpy(str, str_size, line);
				ret = true;
			}
		}

		Free(line);
	}

	FreeBuf(b);

	return ret;
}

// Choose the language from the ID
LANGLIST *GetLangById(LIST *o, UINT id)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		if (e->Id == id)
		{
			return e;
		}
	}

	return NULL;
}

// Choice the best language for the current environment
LANGLIST *GetBestLangForCurrentEnvironment(LIST *o)
{
	LANGLIST *ret = NULL;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

#ifdef	OS_WIN32
	ret = GetBestLangByLcid(o, MsGetUserLocaleId());
#else	// OS_WIN32
	if (true)
	{
		char lang[MAX_SIZE];

		if (GetEnv("LANG", lang, sizeof(lang)))
		{
			ret = GetBestLangByLangStr(o, lang);
		}
		else
		{
			ret = GetBestLangByLangStr(o, "C");
		}
	}
#endif	// OS_WIN32

	return ret;
}

// Search for the best language from LANG string of UNIX
LANGLIST *GetBestLangByLangStr(LIST *o, char *str)
{
	UINT i;
	LANGLIST *ret;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);
		UINT j;

		for (j = 0;j < LIST_NUM(e->LangList);j++)
		{
			char *v = LIST_DATA(e->LangList, j);

			if (StrCmpi(v, str) == 0)
			{
				return e;
			}
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);
		UINT j;

		for (j = 0;j < LIST_NUM(e->LangList);j++)
		{
			char *v = LIST_DATA(e->LangList, j);

			if (StartWith(str, v) || StartWith(v, str))
			{
				return e;
			}
		}
	}

	ret = GetBestLangByName(o, "en");

	return ret;
}

// Search for the best language from LCID
LANGLIST *GetBestLangByLcid(LIST *o, UINT lcid)
{
	LANGLIST *ret;
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		if (IsIntInList(e->LcidList, lcid))
		{
			return e;
		}
	}

	ret = GetBestLangByName(o, "en");

	return ret;
}

// Search for the best language from the name
LANGLIST *GetBestLangByName(LIST *o, char *name)
{
	UINT i;
	LANGLIST *ret = NULL;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		if (StrCmpi(e->Name, name) == 0)
		{
			ret = e;
			break;
		}
	}

	if (ret != NULL)
	{
		return ret;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		if (StartWith(e->Name, name) || StartWith(name, e->Name))
		{
			ret = e;
			break;
		}
	}

	if (ret != NULL)
	{
		return ret;
	}

	return ret;
}

// Release the language list
void FreeLangList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LANGLIST *e = LIST_DATA(o, i);

		FreeStrList(e->LangList);
		ReleaseIntList(e->LcidList);

		Free(e);
	}

	ReleaseList(o);
}

// Read the language list
LIST *LoadLangList()
{
	LIST *o = NewListFast(NULL);
	char *filename = LANGLIST_FILENAME;
	BUF *b;

#ifdef	OS_WIN32
	if (MsIsWine())
	{
		filename = LANGLIST_FILENAME_WINE;
	}
#endif	// OS_WIN32

	b = ReadDump(filename);
	if (b == NULL)
	{
		return NULL;
	}

	while (true)
	{
		char *line = CfgReadNextLine(b);

		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false && StartWith(line, "#") == false)
		{
			TOKEN_LIST *t = ParseToken(line, "\t ");
			if (t != NULL)
			{
				if (t->NumTokens == 6)
				{
					LANGLIST *e = ZeroMalloc(sizeof(LANGLIST));
					TOKEN_LIST *t2;

					e->Id = ToInt(t->Token[0]);
					StrCpy(e->Name, sizeof(e->Name), t->Token[1]);
					Utf8ToUni(e->TitleEnglish, sizeof(e->TitleEnglish), t->Token[2], StrLen(t->Token[2]));
					Utf8ToUni(e->TitleLocal, sizeof(e->TitleLocal), t->Token[3], StrLen(t->Token[3]));

					UniReplaceStrEx(e->TitleEnglish, sizeof(e->TitleEnglish), e->TitleEnglish,
						L"_", L" ", true);

					UniReplaceStrEx(e->TitleLocal, sizeof(e->TitleLocal), e->TitleLocal,
						L"_", L" ", true);

					e->LcidList = NewIntList(false);

					t2 = ParseToken(t->Token[4], ",");
					if (t2 != NULL)
					{
						UINT i;

						for (i = 0;i < t2->NumTokens;i++)
						{
							UINT id = ToInt(t2->Token[i]);

							AddIntDistinct(e->LcidList, id);
						}

						FreeToken(t2);
					}

					e->LangList = NewListFast(NULL);

					t2 = ParseToken(t->Token[5], ",");
					if (t2 != NULL)
					{
						UINT i;

						for (i = 0;i < t2->NumTokens;i++)
						{
							Add(e->LangList, CopyStr(t2->Token[i]));
						}

						FreeToken(t2);
					}

					Add(o, e);
				}

				FreeToken(t);
			}
		}

		Free(line);
	}

	FreeBuf(b);

	return o;
}

// Get an error string in Unicode
wchar_t *GetUniErrorStr(UINT err)
{
	wchar_t *ret;
	char name[MAX_SIZE];
	Format(name, sizeof(name), "ERR_%u", err);

	ret = GetTableUniStr(name);
	if (UniStrLen(ret) != 0)
	{
		return ret;
	}
	else
	{
		return _UU("ERR_UNKNOWN");
	}
}

// Get an error string
char *GetErrorStr(UINT err)
{
	char *ret;
	char name[MAX_SIZE];
	Format(name, sizeof(name), "ERR_%u", err);

	ret = GetTableStr(name);
	if (StrLen(ret) != 0)
	{
		return ret;
	}
	else
	{
		return _SS("ERR_UNKNOWN");
	}
}

// Load the integer value from the table
UINT GetTableInt(char *name)
{
	char *str;
	// Validate arguments
	if (name == NULL)
	{
		return 0;
	}

	str = GetTableStr(name);
	return ToInt(str);
}

// Load a Unicode string from the table
wchar_t *GetTableUniStr(char *name)
{
	TABLE *t;
	// Validate arguments
	if (name == NULL)
	{
//		Debug("%s: ************\n", name);
		return L"";
	}

	// Search
	t = FindTable(name);
	if (t == NULL)
	{
		//Debug("%s: UNICODE STRING NOT FOUND\n", name);
		return L"";
	}

	return t->unistr;
}

// Load the string from the table
char *GetTableStr(char *name)
{
	TABLE *t;
	// Validate arguments
	if (name == NULL)
	{
		return "";
	}

#ifdef	OS_WIN32
	if (StrCmpi(name, "DEFAULT_FONT") == 0)
	{
		if (_II("LANG") == 2)
		{
			UINT os_type = GetOsType();
			if (OS_IS_WINDOWS_9X(os_type) ||
				GET_KETA(os_type, 100) <= 4)
			{
				// Use the SimSun font in Windows 9x, Windows NT 4.0, Windows 2000, Windows XP, and Windows Server 2003
				return "SimSun";
			}
		}
	}
#endif	// OS_WIN32

	// Search
	t = FindTable(name);
	if (t == NULL)
	{
		//Debug("%s: ANSI STRING NOT FOUND\n", name);
		return "";
	}

	return t->str;
}

// Get the string name that begins with the specified name
TOKEN_LIST *GetTableNameStartWith(char *str)
{
	UINT i;
	UINT len;
	LIST *o;
	TOKEN_LIST *t;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (str == NULL)
	{
		return NullToken();
	}

	StrCpy(tmp, sizeof(tmp), str);
	StrUpper(tmp);

	len = StrLen(tmp);

	o = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(TableList);i++)
	{
		TABLE *t = LIST_DATA(TableList, i);
		UINT len2 = StrLen(t->name);

		if (len2 >= len)
		{
			if (Cmp(t->name, tmp, len) == 0)
			{
				Insert(o, CopyStr(t->name));
			}
		}
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	return t;
}

// Search the table
TABLE *FindTable(char *name)
{
	TABLE *t, tt;
	// Validate arguments
	if (name == NULL || TableList == NULL)
	{
		return NULL;
	}

	tt.name = CopyStr(name);
	t = Search(TableList, &tt);
	Free(tt.name);

	return t;
}

// A function that compares the table name
int CmpTableName(void *p1, void *p2)
{
	TABLE *t1, *t2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	t1 = *(TABLE **)p1;
	t2 = *(TABLE **)p2;
	if (t1 == NULL || t2 == NULL)
	{
		return 0;
	}

	return StrCmpi(t1->name, t2->name);
}

// Interpret a line
TABLE *ParseTableLine(char *line, char *prefix, UINT prefix_size, LIST *replace_list)
{
	UINT i, len;
	UINT len_name;
	UINT string_start;
	char *name;
	char *name2;
	UINT name2_size;
	wchar_t *unistr;
	char *str;
	UINT unistr_size, str_size;
	TABLE *t;
	// Validate arguments
	if (line == NULL || prefix == NULL)
	{
		return NULL;
	}
	TrimLeft(line);

	// No line
	len = StrLen(line);
	if (len == 0)
	{
		return NULL;
	}

	// Comment
	if (line[0] == '#' || (line[0] == '/' && line[1] == '/'))
	{
		return NULL;
	}

	// Search to the end position of the name
	len_name = 0;
	for (i = 0;;i++)
	{
		if (line[i] == 0)
		{
			// There is only one token
			return NULL;
		}
		if (line[i] == ' ' || line[i] == '\t')
		{
			break;
		}
		len_name++;
	}

	name = Malloc(len_name + 1);
	StrCpy(name, len_name + 1, line);

	string_start = len_name;
	for (i = len_name;i < len;i++)
	{
		if (line[i] != ' ' && line[i] != '\t')
		{
			break;
		}
		string_start++;
	}
	if (i == len)
	{
		Free(name);
		return NULL;
	}

	// Unescape
	UnescapeStr(&line[string_start]);

	// Convert to Unicode
	unistr_size = CalcUtf8ToUni(&line[string_start], StrLen(&line[string_start]));
	if (unistr_size == 0)
	{
		Free(name);
		return NULL;
	}
	unistr = Malloc(unistr_size);
	Utf8ToUni(unistr, unistr_size, &line[string_start], StrLen(&line[string_start]));

	if (UniInChar(unistr, L'$'))
	{
		// Replace the replacement string
		wchar_t *tmp;
		UINT tmp_size = (UniStrSize(unistr) + 1024) * 2;
		UINT i;

		tmp = Malloc(tmp_size);

		UniStrCpy(tmp, tmp_size, unistr);

		for (i = 0; i < LIST_NUM(replace_list);i++)
		{
			TABLE *r = LIST_DATA(replace_list, i);

			UniReplaceStrEx(tmp, tmp_size, tmp, (wchar_t *)r->name, r->unistr, false);
		}

		Free(unistr);

		unistr = CopyUniStr(tmp);

		Free(tmp);
	}

	// Convert to ANSI
	str_size = CalcUniToStr(unistr);
	if (str_size == 0)
	{
		str_size = 1;
		str = Malloc(1);
		str[0] = 0;
	}
	else
	{
		str = Malloc(str_size);
		UniToStr(str, str_size, unistr);
	}

	if (StrCmpi(name, "PREFIX") == 0)
	{
		// Prefix is specified
		StrCpy(prefix, prefix_size, str);
		Trim(prefix);

		if (StrCmpi(prefix, "$") == 0 || StrCmpi(prefix, "NULL") == 0)
		{
			prefix[0] = 0;
		}

		Free(name);
		Free(str);
		Free(unistr);

		return NULL;
	}

	name2_size = StrLen(name) + StrLen(prefix) + 2;
	name2 = ZeroMalloc(name2_size);

	if (prefix[0] != 0)
	{
		StrCat(name2, name2_size, prefix);
		StrCat(name2, name2_size, "@");
	}

	StrCat(name2, name2_size, name);

	Free(name);

	// Create a TABLE
	t = Malloc(sizeof(TABLE));
	StrUpper(name2);
	t->name = name2;
	t->str = str;
	t->unistr = unistr;

	return t;
}

// Unescape the string
void UnescapeStr(char *src)
{
	UINT i, len, wp;
	char *tmp;
	// Validate arguments
	if (src == NULL)
	{
		return;
	}
	
	len = StrLen(src);
	tmp = Malloc(len + 1);
	wp = 0;
	for (i = 0;i < len;i++)
	{
		if (src[i] == '\\')
		{
			i++;
			switch (src[i])
			{
			case 0:
				goto FINISH;
			case '\\':
				tmp[wp++] = '\\';
				break;
			case ' ':
				tmp[wp++] = ' ';
				break;
			case 'n':
			case 'N':
				tmp[wp++] = '\n';
				break;
			case 'r':
			case 'R':
				tmp[wp++] = '\r';
				break;
			case 't':
			case 'T':
				tmp[wp++] = '\t';
				break;
			}
		}
		else
		{
			tmp[wp++] = src[i];
		}
	}
FINISH:
	tmp[wp++] = 0;
	StrCpy(src, 0, tmp);
	Free(tmp);
}

// Release the table
void FreeTable()
{
	UINT i, num;
	TABLE **tables;
	if (TableList == NULL)
	{
		return;
	}

	TrackingDisable();

	num = LIST_NUM(TableList);
	tables = ToArray(TableList);
	for (i = 0;i < num;i++)
	{
		TABLE *t = tables[i];
		Free(t->name);
		Free(t->str);
		Free(t->unistr);
		Free(t);
	}
	ReleaseList(TableList);
	TableList = NULL;
	Free(tables);

	Zero(old_table_name, sizeof(old_table_name));

	TrackingEnable();
}

// Read a string table from the buffer
bool LoadTableFromBuf(BUF *b)
{
	char *tmp;
	char prefix[MAX_SIZE];
	LIST *replace_list = NULL;
	UINT i;
	// Validate arguments
	if (b == NULL)
	{
		return false;
	}

	// If the table already exists, delete it
	FreeTable();

	// Create a list
	TableList = NewList(CmpTableName);

	Zero(prefix, sizeof(prefix));

	replace_list = NewListFast(NULL);

	// Read the contents of the buffer line by line
	while (true)
	{
		TABLE *t;
		bool ok = true;

		tmp = CfgReadNextLine(b);
		if (tmp == NULL)
		{
			break;
		}

		if (tmp[0] == '$')
		{
			char key[128];
			char value[MAX_SIZE];
			if (GetKeyAndValue(tmp, key, sizeof(key), value, sizeof(value), " \t"))
			{
				if (StartWith(key, "$") && EndWith(key, "$") && StrLen(key) >= 3)
				{
					TABLE *t;
					wchar_t univalue[MAX_SIZE];
					wchar_t uniname[MAX_SIZE];

					t = ZeroMalloc(sizeof(TABLE));

					Zero(univalue, sizeof(univalue));
					Utf8ToUni(univalue, sizeof(univalue), value, StrLen(value));

					StrToUni(uniname, sizeof(uniname), key);

					t->name = (char *)CopyUniStr(uniname);
					t->unistr = CopyUniStr(univalue);

					Add(replace_list, t);

					// Found a replacement definition
					ok = false;
				}
			}
		}

		if (ok)
		{
			t = ParseTableLine(tmp, prefix, sizeof(prefix), replace_list);
			if (t != NULL)
			{
				// Register
				Insert(TableList, t);
			}
		}

		Free(tmp);
	}

	for (i = 0;i < LIST_NUM(replace_list);i++)
	{
		TABLE *t = LIST_DATA(replace_list, i);

		Free(t->name);
		Free(t->str);
		Free(t->unistr);

		Free(t);
	}

	ReleaseList(replace_list);

	return true;
}

// Generate the Unicode string cache file name
void GenerateUnicodeCacheFileName(wchar_t *name, UINT size, wchar_t *strfilename, UINT strfilesize, UCHAR *filehash)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t hashstr[64];
	wchar_t hashtemp[MAX_SIZE];
	wchar_t exe[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (name == NULL || strfilename == NULL || filehash == NULL)
	{
		return;
	}

	GetExeDirW(exe, sizeof(exe));
	UniStrCpy(hashtemp, sizeof(hashtemp), strfilename);
	BinToStrW(tmp, sizeof(tmp), filehash, MD5_SIZE);
	UniStrCat(hashtemp, sizeof(hashtemp), tmp);
	UniStrCat(hashtemp, sizeof(hashtemp), exe);
	UniStrLower(hashtemp);

	Hash(hash, hashtemp, UniStrLen(hashtemp) * sizeof(wchar_t), true);
	BinToStrW(hashstr, sizeof(hashstr), hash, 4);
	UniFormat(tmp, sizeof(tmp), UNICODE_CACHE_FILE, hashstr);
	UniStrLower(tmp);

#ifndef	OS_WIN32
	UniStrCpy(exe, sizeof(exe), L"/tmp");
#else	// OS_WIN32
	StrToUni(exe, sizeof(exe), MsGetTempDir());
#endif	// OS_WIN32

	UniFormat(name, size, L"%s/%s", exe, tmp);
	NormalizePathW(name, size, name);
}

// Save the Unicode cache
void SaveUnicodeCache(wchar_t *strfilename, UINT strfilesize, UCHAR *hash)
{
	UNICODE_CACHE c;
	BUF *b;
	UINT i;
	IO *io;
	wchar_t name[MAX_PATH];
	UCHAR binhash[MD5_SIZE];
	// Validate arguments
	if (strfilename == NULL || hash == NULL)
	{
		return;
	}

	Zero(&c, sizeof(c));
	UniToStr(c.StrFileName, sizeof(c.StrFileName), strfilename);
	c.StrFileSize = strfilesize;
	GetMachineName(c.MachineName, sizeof(c.MachineName));
	c.OsType = GetOsInfo()->OsType;
	Copy(c.hash, hash, MD5_SIZE);

#ifdef	OS_UNIX
	GetCurrentCharSet(c.CharSet, sizeof(c.CharSet));
#else	// OS_UNIX
	{
		UINT id = MsGetThreadLocale();
		Copy(c.CharSet, &id, sizeof(id));
	}
#endif	// OS_UNIX

	b = NewBuf();
	WriteBuf(b, &c, sizeof(c));

	WriteBufInt(b, LIST_NUM(TableList));
	for (i = 0;i < LIST_NUM(TableList);i++)
	{
		TABLE *t = LIST_DATA(TableList, i);
		WriteBufInt(b, StrLen(t->name));
		WriteBuf(b, t->name, StrLen(t->name));
		WriteBufInt(b, StrLen(t->str));
		WriteBuf(b, t->str, StrLen(t->str));
		WriteBufInt(b, UniStrLen(t->unistr));
		WriteBuf(b, t->unistr, UniStrLen(t->unistr) * sizeof(wchar_t));
	}

	Hash(binhash, b->Buf, b->Size, false);
	WriteBuf(b, binhash, MD5_SIZE);

	GenerateUnicodeCacheFileName(name, sizeof(name), strfilename, strfilesize, hash);

	io = FileCreateW(name);
	if (io != NULL)
	{
		SeekBuf(b, 0, 0);
		BufToFile(io, b);
		FileClose(io);
	}

	FreeBuf(b);
}

// Reading the Unicode cache
bool LoadUnicodeCache(wchar_t *strfilename, UINT strfilesize, UCHAR *hash)
{
	UNICODE_CACHE c, t;
	BUF *b;
	UINT i, num;
	IO *io;
	wchar_t name[MAX_PATH];
	UCHAR binhash[MD5_SIZE];
	UCHAR binhash_2[MD5_SIZE];
	// Validate arguments
	if (strfilename == NULL || hash == NULL)
	{
		return false;
	}

	GenerateUnicodeCacheFileName(name, sizeof(name), strfilename, strfilesize, hash);

	io = FileOpenW(name, false);
	if (io == NULL)
	{
		return false;
	}

	b = FileToBuf(io);
	if (b == NULL)
	{
		FileClose(io);
		return false;
	}

	SeekBuf(b, 0, 0);
	FileClose(io);

	Hash(binhash, b->Buf, b->Size >= MD5_SIZE ? (b->Size - MD5_SIZE) : 0, false);
	Copy(binhash_2, ((UCHAR *)b->Buf) + (b->Size >= MD5_SIZE ? (b->Size - MD5_SIZE) : 0), MD5_SIZE);
	if (Cmp(binhash, binhash_2, MD5_SIZE) != 0)
	{
		FreeBuf(b);
		return false;
	}

	Zero(&c, sizeof(c));
	UniToStr(c.StrFileName, sizeof(c.StrFileName), strfilename);
	c.StrFileSize = strfilesize;
	DisableNetworkNameCache();
	GetMachineName(c.MachineName, sizeof(c.MachineName));
	EnableNetworkNameCache();
	c.OsType = GetOsInfo()->OsType;
	Copy(c.hash, hash, MD5_SIZE);

#ifdef	OS_UNIX
	GetCurrentCharSet(c.CharSet, sizeof(c.CharSet));
#else	// OS_UNIX
	{
		UINT id = MsGetThreadLocale();
		Copy(c.CharSet, &id, sizeof(id));
	}
#endif	// OS_UNIX

	Zero(&t, sizeof(t));
	ReadBuf(b, &t, sizeof(t));

	if (Cmp(&c, &t, sizeof(UNICODE_CACHE)) != 0)
	{
		FreeBuf(b);
		return false;
	}

	num = ReadBufInt(b);

	FreeTable();
	TableList = NewList(CmpTableName);

	for (i = 0;i < num;i++)
	{
		UINT len;
		TABLE *t = ZeroMalloc(sizeof(TABLE));

		len = ReadBufInt(b);
		t->name = ZeroMalloc(len + 1);
		ReadBuf(b, t->name, len);

		len = ReadBufInt(b);
		t->str = ZeroMalloc(len + 1);
		ReadBuf(b, t->str, len);

		len = ReadBufInt(b);
		t->unistr = ZeroMalloc((len + 1) * sizeof(wchar_t));
		ReadBuf(b, t->unistr, len * sizeof(wchar_t));

		Add(TableList, t);
	}

	FreeBuf(b);

	Sort(TableList);

	return true;
}

// Read the string table
bool LoadTableMain(wchar_t *filename)
{
	BUF *b;
	UINT64 t1, t2;
	UCHAR hash[MD5_SIZE];
	// Validate arguments
	if (filename == NULL)
	{
		return false;
	}

	if (MayaquaIsMinimalMode())
	{
		return true;
	}

	if (UniStrCmpi(old_table_name, filename) == 0)
	{
		// Already loaded
		return true;
	}

	t1 = Tick64();

	// Open the file
	b = ReadDumpW(filename);
	if (b == NULL)
	{
		char tmp[MAX_SIZE];
		StrCpy(tmp, sizeof(tmp), "Error: Can't read string tables (file not found).\r\nPlease check hamcore.se2.\r\n\r\n(First, reboot the computer. If this problem occurs again, please reinstall VPN software files.)");
		Alert(tmp, NULL);
		exit(-1);
		return false;
	}

	Hash(hash, b->Buf, b->Size, false);

	if (LoadUnicodeCache(filename, b->Size, hash) == false)
	{
		if (LoadTableFromBuf(b) == false)
		{
			FreeBuf(b);
			return false;
		}

		SaveUnicodeCache(filename, b->Size, hash);

		//Debug("Unicode Source: strtable.stb\n");
	}
	else
	{
		//Debug("Unicode Source: unicode_cache\n");
	}

	FreeBuf(b);

	SetLocale(_UU("DEFAULE_LOCALE"));

	UniStrCpy(old_table_name, sizeof(old_table_name), filename);

	t2 = Tick64();

	if (StrCmpi(_SS("STRTABLE_ID"), STRTABLE_ID) != 0)
	{
		char tmp[MAX_SIZE];
		Format(tmp, sizeof(tmp), "Error: Can't read string tables (invalid version: '%s'!='%s').\r\nPlease check hamcore.se2.\r\n\r\n(First, reboot the computer. If this problem occurs again, please reinstall VPN software files.)",
			_SS("STRTABLE_ID"), STRTABLE_ID);
		Alert(tmp, NULL);
		exit(-1);
		return false;
	}

	//Debug("Unicode File Read Cost: %u (%u Lines)\n", (UINT)(t2 - t1), LIST_NUM(TableList));

	return true;
}
bool LoadTable(char *filename)
{
	wchar_t *filename_a = CopyStrToUni(filename);
	bool ret = LoadTableW(filename_a);

	Free(filename_a);

	return ret;
}
bool LoadTableW(wchar_t *filename)
{
	bool ret;
	BUF *b;
	wchar_t replace_name[MAX_PATH];

	Zero(replace_name, sizeof(replace_name));

	TrackingDisable();

	b = ReadDump("@table_name.txt");
	if (b != NULL)
	{
		char *s = CfgReadNextLine(b);
		if (s != NULL)
		{
			if (IsEmptyStr(s) == false)
			{
				StrToUni(replace_name, sizeof(replace_name), s);
				filename = replace_name;
			}

			Free(s);
		}
		FreeBuf(b);
	}

	ret = LoadTableMain(filename);

	TrackingEnable();

	return ret;
}


