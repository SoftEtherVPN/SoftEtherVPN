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


// Table.h
// Header of Table.c

#ifndef	TABLE_H
#define	TABLE_H

#define	UNICODE_CACHE_FILE		L".unicode_cache_%s.dat"

#define	LANGLIST_FILENAME		"|languages.txt"
#define	LANG_CONFIG_FILENAME	L"@lang.config"
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




// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
