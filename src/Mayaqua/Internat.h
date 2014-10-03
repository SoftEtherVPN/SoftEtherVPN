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


// Internat.h
// Header of Internat.c

#ifndef	INTERNAT_H
#define	INTERNAT_H

// String token
struct UNI_TOKEN_LIST
{
	UINT NumTokens;
	wchar_t **Token;
};

UINT UniStrLen(wchar_t *str);
UINT UniStrSize(wchar_t *str);
UINT UniStrCpy(wchar_t *dst, UINT size, wchar_t *src);
bool UniCheckStrSize(wchar_t *str, UINT size);
bool UniCheckStrLen(wchar_t *str, UINT len);
UINT UniStrCat(wchar_t *dst, UINT size, wchar_t *src);
UINT UniStrCatLeft(wchar_t *dst, UINT size, wchar_t *src);
wchar_t UniToLower(wchar_t c);
wchar_t UniToUpper(wchar_t c);
void UniStrLower(wchar_t *str);
void UniStrUpper(wchar_t *str);
int UniStrCmp(wchar_t *str1, wchar_t *str2);
int UniStrCmpi(wchar_t *str1, wchar_t *str2);
int UniSoftStrCmp(wchar_t *str1, wchar_t *str2);
void UniFormat(wchar_t *buf, UINT size, wchar_t *fmt, ...);
wchar_t *CopyUniFormat(wchar_t *fmt, ...);
void UniFormatArgs(wchar_t *buf, UINT size, wchar_t *fmt, va_list args);
void UniDebugArgs(wchar_t *fmt, va_list args);
void UniDebug(wchar_t *fmt, ...);
void UniPrint(wchar_t *fmt, ...);
void UniPrintArgs(wchar_t *fmt, va_list args);
void UniPrintStr(wchar_t *string);
void UniToStrx8(wchar_t *str, UINT i);
void UniToStrx(wchar_t *str, UINT i);
void UniToStri(wchar_t *str, int i);
void UniToStru(wchar_t *str, UINT i);
int UniToInti(wchar_t *str);
UINT UniToInt(wchar_t *str);
void UniToStrForSingleChars(char *dst, UINT dst_size, wchar_t *src);
void UniTrim(wchar_t *str);
void UniTrimLeft(wchar_t *str);
void UniTrimRight(wchar_t *str);
void UniTrimCrlf(wchar_t *str);
bool UniGetLine(wchar_t *str, UINT size);
bool UniGetLineWin32(wchar_t *str, UINT size);
bool UniGetLineUnix(wchar_t *str, UINT size);
void UniFreeToken(UNI_TOKEN_LIST *tokens);
UNI_TOKEN_LIST *UniParseToken(wchar_t *src, wchar_t *separator);
UINT UniSearchStrEx(wchar_t *string, wchar_t *keyword, UINT start, bool case_sensitive);
UINT UniSearchStri(wchar_t *string, wchar_t *keyword, UINT start);
UINT UniSearchStr(wchar_t *string, wchar_t *keyword, UINT start);
UINT UniCalcReplaceStrEx(wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive);
UINT UniReplaceStrEx(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive);
UINT UniReplaceStri(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword);
UINT UniReplaceStr(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword);
UINT GetUniType(wchar_t c);
UINT GetUtf8Type(BYTE *s, UINT size, UINT offset);
UINT CalcUniToUtf8(wchar_t *s);
UINT UniToUtf8(BYTE *u, UINT size, wchar_t *s);
UINT Utf8Len(BYTE *u, UINT size);
UINT CalcUtf8ToUni(BYTE *u, UINT u_size);
UINT Utf8ToUni(wchar_t *s, UINT size, BYTE *u, UINT u_size);
UINT CalcStrToUni(char *str);
UINT StrToUni(wchar_t *s, UINT size, char *str);
UINT CalcUniToStr(wchar_t *s);
UINT UniToStr(char *str, UINT size, wchar_t *s);
UINT CalcStrToUtf8(char *str);
UINT StrToUtf8(BYTE *u, UINT size, char *str);
UINT CalcUtf8ToStr(BYTE *u, UINT size);
UINT Utf8ToStr(char *str, UINT str_size, BYTE *u, UINT size);
bool IsSafeUniStr(wchar_t *str);
bool IsSafeUniChar(wchar_t c);
wchar_t *CopyUniStr(wchar_t *str);
wchar_t *CopyStrToUni(char *str);
UINT StrToUtf(char *utfstr, UINT size, char *str);
UINT UtfToStr(char *str, UINT size, char *utfstr);
UINT UniToUtf(char *utfstr, UINT size, wchar_t *unistr);
UINT UtfToUni(wchar_t *unistr, UINT size, char *utfstr);
char *CopyUniToUtf(wchar_t *unistr);
char *CopyStrToUtf(char *str);
char *CopyUniToStr(wchar_t *unistr);
wchar_t *CopyUtfToUni(char *utfstr);
char *CopyUtfToStr(char *utfstr);
wchar_t *UniReplaceFormatStringFor64(wchar_t *fmt);
void UniToStr64(wchar_t *str, UINT64 value);
UINT64 UniToInt64(wchar_t *str);
UNI_TOKEN_LIST *UniParseCmdLine(wchar_t *str);
UNI_TOKEN_LIST *UniCopyToken(UNI_TOKEN_LIST *src);
wchar_t *UniCopyStr(wchar_t *str);
TOKEN_LIST *UniTokenListToTokenList(UNI_TOKEN_LIST *src);
UNI_TOKEN_LIST *TokenListToUniTokenList(TOKEN_LIST *src);
UNI_TOKEN_LIST *UniNullToken();
UNI_TOKEN_LIST *NullUniToken();
bool UniIsNum(wchar_t *str);
bool IsEmptyUniStr(wchar_t *str);
bool UniIsEmptyStr(wchar_t *str);
void InitInternational();
void FreeInternational();
USHORT *WideToUtf16(wchar_t *str);
wchar_t *Utf16ToWide(USHORT *str);
void DumpUniStr(wchar_t *str);
void DumpStr(char *str);
wchar_t *InternalFormatArgs(wchar_t *fmt, va_list args, bool ansi_mode);
UINT UniStrWidth(wchar_t *str);
UNI_TOKEN_LIST *UnixUniParseToken(wchar_t *src, wchar_t *separator);
void UniToStr3(wchar_t *str, UINT size, UINT64 value);
bool UniEndWith(wchar_t *str, wchar_t *key);
bool UniStartWith(wchar_t *str, wchar_t *key);
wchar_t *UniNormalizeCrlf(wchar_t *str);
LIST *UniStrToStrList(wchar_t *str, UINT size);
BUF *UniStrListToStr(LIST *o);
void UniFreeStrList(LIST *o);
UNI_TOKEN_LIST *UniListToTokenList(LIST *o);
LIST *UniTokenListToList(UNI_TOKEN_LIST *t);
bool UniIsSafeChar(wchar_t c);
wchar_t *UniMakeCharArray(wchar_t c, UINT count);
BUF *UniStrToBin(wchar_t *str);
bool UniInStr(wchar_t *str, wchar_t *keyword);
bool UniInStrEx(wchar_t *str, wchar_t *keyword, bool case_sensitive);
void ClearUniStr(wchar_t *str, UINT str_size);
bool UniInChar(wchar_t *string, wchar_t c);
UNI_TOKEN_LIST *UniGetLines(wchar_t *str);

#ifdef	OS_UNIX
void GetCurrentCharSet(char *name, UINT size);
UINT UnixCalcStrToUni(char *str);
UINT UnixStrToUni(wchar_t *s, UINT size, char *str);
UINT UnixCalcUniToStr(wchar_t *s);
UINT UnixUniToStr(char *str, UINT size, wchar_t *s);
void *IconvWideToStr();
void *IconvStrToWide();
int IconvFree(void *d);
void *IconvWideToStrInternal();
void *IconvStrToWideInternal();
int IconvFreeInternal(void *d);
#endif	// OS_UNIX

#endif	// INTERNAT_H




// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
