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


// Str.c
// String processing routine

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// Locking for call the token handling function
LOCK *token_lock = NULL;
static char *default_spliter = " ,\t\r\n";

typedef struct BYTESTR
{
	UINT64 base_value;
	char *string;
} BYTESTR;

static BYTESTR bytestr[] =
{
	{0, "PBytes"},
	{0, "TBytes"},
	{0, "GBytes"},
	{0, "MBytes"},
	{0, "KBytes"},
	{0, "Bytes"},
};

// Change the case of the string by the bit array
void SetStrCaseAccordingToBits(char *str, UINT bits)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if (bits & 0x01)
		{
			c = ToUpper(c);
		}
		else
		{
			c = ToLower(c);
		}

		str[i] = c;

		bits = bits / 2;
	}
}

// Normalize the integer list string
void NormalizeIntListStr(char *dst, UINT dst_size, char *src, bool sorted, char *separate_str)
{
	LIST *o;

	o = StrToIntList(src, sorted);

	IntListToStr(dst, dst_size, o, separate_str);

	ReleaseIntList(o);
}

// Convert the string to an integer list
LIST *StrToIntList(char *str, bool sorted)
{
	LIST *o;
	TOKEN_LIST *t;

	o = NewIntList(sorted);

	t = ParseTokenWithoutNullStr(str, " ,/;\t");

	if (t != NULL)
	{
		UINT i;

		for (i = 0;i < t->NumTokens;i++)
		{
			char *s = t->Token[i];

			if (IsEmptyStr(s) == false)
			{
				if (IsNum(s))
				{
					InsertIntDistinct(o, ToInt(s));
				}
			}
		}

		FreeToken(t);
	}

	return o;
}

// Convert an integer list to a string
void IntListToStr(char *str, UINT str_size, LIST *o, char *separate_str)
{
	UINT i;
	ClearStr(str, str_size);
	// Validate arguments
	if (o == NULL)
	{
		return;
	}
	if (IsEmptyStr(separate_str))
	{
		separate_str = ", ";
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char tmp[MAX_SIZE];
		UINT *v = LIST_DATA(o, i);

		ToStr(tmp, *v);

		StrCat(str, str_size, tmp);

		if (i != (LIST_NUM(o) - 1))
		{
			StrCat(str, str_size, separate_str);
		}
	}
}

// Initialize the string
void ClearStr(char *str, UINT str_size)
{
	StrCpy(str, str_size, "");
}

// Search for the ASCII string in the binary data sequence
UINT SearchAsciiInBinary(void *data, UINT size, char *str, bool case_sensitive)
{
	UINT ret = INFINITE;
	char *tmp;
	// Validate arguments
	if (data == NULL || size == 0 || str == NULL)
	{
		return INFINITE;
	}

	tmp = ZeroMalloc(size + 1);
	Copy(tmp, data, size);

	ret = SearchStrEx(tmp, str, 0, case_sensitive);

	Free(tmp);

	return ret;
}

// Convert the HEX string to a 64 bit integer
UINT64 HexToInt64(char *str)
{
	UINT len, i;
	UINT64 ret = 0;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
	{
		str += 2;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
		{
			ret = ret * 16ULL + (UINT64)HexTo4Bit(c);
		}
		else
		{
			break;
		}
	}

	return ret;
}

// Convert the HEX string to a 32 bit integer
UINT HexToInt(char *str)
{
	UINT len, i;
	UINT ret = 0;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
	{
		str += 2;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
		{
			ret = ret * 16 + (UINT)HexTo4Bit(c);
		}
		else
		{
			break;
		}
	}

	return ret;
}

// Convert a 64 bit integer to a HEX
void ToHex64(char *str, UINT64 value)
{
	char tmp[MAX_SIZE];
	UINT wp = 0;
	UINT len, i;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	// Set to empty character
	StrCpy(tmp, 0, "");

	// Append from the last digit
	while (true)
	{
		UINT a = (UINT)(value % (UINT64)16);
		value = value / (UINT)16;
		tmp[wp++] = FourBitToHex(a);
		if (value == 0)
		{
			tmp[wp++] = 0;
			break;
		}
	}

	// Reverse order
	len = StrLen(tmp);
	for (i = 0;i < len;i++)
	{
		str[len - i - 1] = tmp[i];
	}
	str[len] = 0;
}

// Convert a 32 bit integer into HEX
void ToHex(char *str, UINT value)
{
	char tmp[MAX_SIZE];
	UINT wp = 0;
	UINT len, i;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	// Set to empty character
	StrCpy(tmp, 0, "");

	// Append from the last digit
	while (true)
	{
		UINT a = (UINT)(value % (UINT)16);
		value = value / (UINT)16;
		tmp[wp++] = FourBitToHex(a);
		if (value == 0)
		{
			tmp[wp++] = 0;
			break;
		}
	}

	// Reverse order
	len = StrLen(tmp);
	for (i = 0;i < len;i++)
	{
		str[len - i - 1] = tmp[i];
	}
	str[len] = 0;
}

// Converts a 4 bit value to hexadecimal string
char FourBitToHex(UINT value)
{
	value = value % 16;

	if (value <= 9)
	{
		return '0' + value;
	}
	else
	{
		return 'a' + (value - 10);
	}
}

// Convert a hexadecimal string to a 4 bit integer
UINT HexTo4Bit(char c)
{
	if ('0' <= c && c <= '9')
	{
		return c - '0';
	}
	else if ('a' <= c && c <= 'f')
	{
		return c - 'a' + 10;
	}
	else if ('A' <= c && c <= 'F')
	{
		return c - 'A' + 10;
	}
	else
	{
		return 0;
	}
}

// Get a standard token delimiter
char *DefaultTokenSplitChars()
{
	return " ,\t\r\n";
}

// Check whether the specified character is in the string
bool IsCharInStr(char *str, char c)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		if (str[i] == c)
		{
			return true;
		}
	}

	return false;
}

// Cut out the token from the string (not ignore the blanks between delimiters)
TOKEN_LIST *ParseTokenWithNullStr(char *str, char *split_chars)
{
	LIST *o;
	UINT i, len;
	BUF *b;
	char zero = 0;
	TOKEN_LIST *t;
	// Validate arguments
	if (str == NULL)
	{
		return NullToken();
	}
	if (split_chars == NULL)
	{
		split_chars = DefaultTokenSplitChars();
	}

	b = NewBuf();
	o = NewListFast(NULL);

	len = StrLen(str);

	for (i = 0;i < (len + 1);i++)
	{
		char c = str[i];
		bool flag = IsCharInStr(split_chars, c);

		if (c == '\0')
		{
			flag = true;
		}

		if (flag == false)
		{
			WriteBuf(b, &c, sizeof(char));
		}
		else
		{
			WriteBuf(b, &zero, sizeof(char));

			Insert(o, CopyStr((char *)b->Buf));
			ClearBuf(b);
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
	FreeBuf(b);

	return t;
}

// Check whether the string contains at least one of the specified tokens
bool InStrList(char *target_str, char *tokens, char *splitter, bool case_sensitive)
{
	TOKEN_LIST *t;
	bool ret = false;
	UINT i;
	// Validate arguments
	if (target_str == NULL || tokens == NULL || splitter == NULL)
	{
		return false;
	}

	t = ParseTokenWithoutNullStr(tokens, splitter);

	if (t != NULL)
	{
		for (i = 0;i < t->NumTokens;i++)
		{
			if (InStrEx(target_str, t->Token[i], case_sensitive))
			{
				ret = true;
//				printf("%s\n", t->Token[i]);
			}

			if (ret)
			{
				break;
			}
		}

		FreeToken(t);
	}

	return ret;
}

// Confirm whether the specified string is in the token list
bool IsStrInStrTokenList(char *str_list, char *str, char *split_chars, bool case_sensitive)
{
	TOKEN_LIST *t;
	bool ret = false;
	UINT i;
	// Validate arguments
	if (str_list == NULL || str == NULL)
	{
		return false;
	}

	t = ParseTokenWithoutNullStr(str_list, split_chars);

	if (t != NULL)
	{
		for (i = 0;i < t->NumTokens;i++)
		{
			if ((case_sensitive == false) && (StrCmpi(t->Token[i], str) == 0))
			{
				ret = true;
			}
			if ((case_sensitive) && (StrCmp(t->Token[i], str) == 0))
			{
				ret = true;
			}

			if (ret)
			{
				break;
			}
		}

		FreeToken(t);
	}

	return ret;
}

// Cut out the token from string (Ignore blanks between delimiters)
TOKEN_LIST *ParseTokenWithoutNullStr(char *str, char *split_chars)
{
	LIST *o;
	UINT i, len;
	bool last_flag;
	BUF *b;
	char zero = 0;
	TOKEN_LIST *t;
	// Validate arguments
	if (str == NULL)
	{
		return NullToken();
	}
	if (split_chars == NULL)
	{
		split_chars = DefaultTokenSplitChars();
	}

	b = NewBuf();
	o = NewListFast(NULL);

	len = StrLen(str);
	last_flag = false;

	for (i = 0;i < (len + 1);i++)
	{
		char c = str[i];
		bool flag = IsCharInStr(split_chars, c);

		if (c == '\0')
		{
			flag = true;
		}

		if (flag == false)
		{
			WriteBuf(b, &c, sizeof(char));
		}
		else
		{
			if (last_flag == false)
			{
				WriteBuf(b, &zero, sizeof(char));

				if ((StrLen((char *)b->Buf)) != 0)
				{
					Insert(o, CopyStr((char *)b->Buf));
				}
				ClearBuf(b);
			}
		}

		last_flag = flag;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);
	FreeBuf(b);

	return t;
}

// Check whether the string is included
bool InStr(char *str, char *keyword)
{
	return InStrEx(str, keyword, false);
}
bool InStrEx(char *str, char *keyword, bool case_sensitive)
{
	// Validate arguments
	if (IsEmptyStr(str) || IsEmptyStr(keyword))
	{
		return false;
	}

	if (SearchStrEx(str, keyword, 0, case_sensitive) == INFINITE)
	{
		return false;
	}

	return true;
}

// Get a value from the INI
UINT IniIntValue(LIST *o, char *key)
{
	INI_ENTRY *e;
	// Validate arguments
	if (o == NULL || key == NULL)
	{
		return 0;
	}

	e = GetIniEntry(o, key);
	if (e == NULL)
	{
		return 0;
	}

	return ToInt(e->Value);
}
UINT64 IniInt64Value(LIST *o, char *key)
{
	INI_ENTRY *e;
	// Validate arguments
	if (o == NULL || key == NULL)
	{
		return 0;
	}

	e = GetIniEntry(o, key);
	if (e == NULL)
	{
		return 0;
	}

	return ToInt64(e->Value);
}
char *IniStrValue(LIST *o, char *key)
{
	INI_ENTRY *e;
	// Validate arguments
	if (o == NULL || key == NULL)
	{
		return 0;
	}

	e = GetIniEntry(o, key);
	if (e == NULL)
	{
		return "";
	}

	return e->Value;
}
wchar_t *IniUniStrValue(LIST *o, char *key)
{
	INI_ENTRY *e;
	// Validate arguments
	if (o == NULL || key == NULL)
	{
		return 0;
	}

	e = GetIniEntry(o, key);
	if (e == NULL)
	{
		return L"";
	}

	return e->UnicodeValue;
}

// Check whether the specified value is in the INI
bool IniHasValue(LIST *o, char *key)
{
	INI_ENTRY *e;
	// Validate arguments
	if (o == NULL || key == NULL)
	{
		return false;
	}

	e = GetIniEntry(o, key);

	if (e == NULL)
	{
		return false;
	}

	return true;
}

// Release the INI
void FreeIni(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		INI_ENTRY *e = LIST_DATA(o, i);

		Free(e->Key);
		Free(e->Value);
		Free(e->UnicodeValue);

		Free(e);
	}

	ReleaseList(o);
}

// Get an entry in the INI file
INI_ENTRY *GetIniEntry(LIST *o, char *key)
{
	UINT i;
	// Validate arguments
	if (o == NULL || key == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		INI_ENTRY *e = LIST_DATA(o, i);

		if (StrCmpi(e->Key, key) == 0)
		{
			return e;
		}
	}

	return NULL;
}

// Read an INI file
LIST *ReadIni(BUF *b)
{
	LIST *o;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);

	SeekBuf(b, 0, 0);

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
			if (StartWith(line, "#") == false &&
				StartWith(line, "//") == false &&
				StartWith(line, ";") == false)
			{
				char *key, *value;
				UINT size = StrLen(line) + 1;

				key = ZeroMalloc(size);
				value = ZeroMalloc(size);

				if (GetKeyAndValue(line, key, size, value, size, NULL))
				{
					UINT uni_size;
					INI_ENTRY *e = ZeroMalloc(sizeof(INI_ENTRY));
					e->Key = CopyStr(key);
					e->Value = CopyStr(value);

					uni_size = CalcUtf8ToUni((BYTE *)value, StrLen(value));
					e->UnicodeValue = ZeroMalloc(uni_size);
					Utf8ToUni(e->UnicodeValue, uni_size, (BYTE *)value, StrLen(value));

					Add(o, e);
				}

				Free(key);
				Free(value);
			}
		}

		Free(line);
	}

	return o;
}

// Check whether the specified character is a delimiter
bool IsSplitChar(char c, char *split_str)
{
	UINT i, len;
	char c_upper = ToUpper(c);
	if (split_str == NULL)
	{
		split_str = default_spliter;
	}

	len = StrLen(split_str);

	for (i = 0;i < len;i++)
	{
		if (ToUpper(split_str[i]) == c_upper)
		{
			return true;
		}
	}

	return false;
}

// Get the keys and the value from the string
bool GetKeyAndValue(char *str, char *key, UINT key_size, char *value, UINT value_size, char *split_str)
{
	UINT mode = 0;
	UINT wp1 = 0, wp2 = 0;
	UINT i, len;
	char *key_tmp, *value_tmp;
	bool ret = false;
	if (split_str == NULL)
	{
		split_str = default_spliter;
	}

	len = StrLen(str);

	key_tmp = ZeroMalloc(len + 1);
	value_tmp = ZeroMalloc(len + 1);

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		switch (mode)
		{
		case 0:
			if (IsSplitChar(c, split_str) == false)
			{
				mode = 1;
				key_tmp[wp1] = c;
				wp1++;
			}
			break;

		case 1:
			if (IsSplitChar(c, split_str) == false)
			{
				key_tmp[wp1] = c;
				wp1++;
			}
			else
			{
				mode = 2;
			}
			break;

		case 2:
			if (IsSplitChar(c, split_str) == false)
			{
				mode = 3;
				value_tmp[wp2] = c;
				wp2++;
			}
			break;

		case 3:
			value_tmp[wp2] = c;
			wp2++;
			break;
		}
	}

	if (mode != 0)
	{
		ret = true;
		StrCpy(key, key_size, key_tmp);
		StrCpy(value, value_size, value_tmp);
	}

	Free(key_tmp);
	Free(value_tmp);

	return ret;
}

// Generate a sequence of specified character
char *MakeCharArray(char c, UINT count)
{
	UINT i;
	char *ret = Malloc(count + 1);

	for (i = 0;i < count;i++)
	{
		ret[i] = c;
	}

	ret[count] = 0;

	return ret;
}
void MakeCharArray2(char *str, char c, UINT count)
{
	UINT i;

	for (i = 0;i < count;i++)
	{
		str[i] = c;
	}

	str[count] = 0;
}

// Get the width of the specified string
UINT StrWidth(char *str)
{
	wchar_t *s;
	UINT ret;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	s = CopyStrToUni(str);
	ret = UniStrWidth(s);
	Free(s);

	return ret;
}

// Check whether the specified string is all uppercase
bool IsAllUpperStr(char *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if ((c >= '0' && c <= '9') ||
			(c >= 'A' && c <= 'Z'))
		{
		}
		else
		{
			return false;
		}
	}

	return true;
}

// Normalize the line breaks
char *NormalizeCrlf(char *str)
{
	char *ret;
	UINT ret_size, i, len, wp;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	ret_size = sizeof(char) * (len + 32) * 2;
	ret = Malloc(ret_size);

	wp = 0;

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		switch (c)
		{
		case '\r':
			if (str[i + 1] == '\n')
			{
				i++;
			}
			ret[wp++] = '\r';
			ret[wp++] = '\n';
			break;

		case '\n':
			ret[wp++] = '\r';
			ret[wp++] = '\n';
			break;

		default:
			ret[wp++] = c;
			break;
		}
	}

	ret[wp++] = 0;

	return ret;
}

// Remove duplications from the token list
TOKEN_LIST *UniqueToken(TOKEN_LIST *t)
{
	UINT i, num, j, n;
	TOKEN_LIST *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	num = 0;
	for (i = 0;i < t->NumTokens;i++)
	{
		bool exists = false;

		for (j = 0;j < i;j++)
		{
			if (StrCmpi(t->Token[j], t->Token[i]) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			num++;
		}
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->Token = ZeroMalloc(sizeof(char *) * num);
	ret->NumTokens = num;

	n = 0;

	for (i = 0;i < t->NumTokens;i++)
	{
		bool exists = false;

		for (j = 0;j < i;j++)
		{
			if (StrCmpi(t->Token[j], t->Token[i]) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			ret->Token[n++] = CopyStr(t->Token[i]);
		}
	}

	return ret;
}

// Convert a value to a byte string (by 1,000)
void ToStrByte1000(char *str, UINT size, UINT64 v)
{
	UINT i;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	// Warning measures in gcc
	bytestr[0].base_value = 1000000000UL;
	bytestr[0].base_value *= 1000UL;
	bytestr[0].base_value *= 1000UL;
	bytestr[1].base_value = 1000000000UL;
	bytestr[1].base_value *= 1000UL;
	bytestr[2].base_value = 1000000000UL;
	bytestr[3].base_value = 1000000UL;
	bytestr[4].base_value = 1000UL;
	bytestr[5].base_value = 0UL;

	for (i = 0;i < sizeof(bytestr) / sizeof(bytestr[0]);i++)
	{
		BYTESTR *b = &bytestr[i];

		if ((v * 11UL) / 10UL >= b->base_value)
		{
			if (b->base_value != 0)
			{
				double d = (double)v / (double)b->base_value;
				Format(str, size, "%.2f %s", d, b->string);
			}
			else
			{
				Format(str, size, "%I64u %s", v, b->string);
			}

			break;
		}
	}
}

// Convert a value to a byte string
void ToStrByte(char *str, UINT size, UINT64 v)
{
	UINT i;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	// Warning measures in gcc
	bytestr[0].base_value = 1073741824UL;
	bytestr[0].base_value *= 1024UL;
	bytestr[0].base_value *= 1024UL;
	bytestr[1].base_value = 1073741824UL;
	bytestr[1].base_value *= 1024UL;
	bytestr[2].base_value = 1073741824UL;
	bytestr[3].base_value = 1048576UL;
	bytestr[4].base_value = 1024UL;
	bytestr[5].base_value = 0UL;

	for (i = 0;i < sizeof(bytestr) / sizeof(bytestr[0]);i++)
	{
		BYTESTR *b = &bytestr[i];

		if ((v * 11UL) / 10UL >= b->base_value)
		{
			if (b->base_value != 0)
			{
				double d = (double)v / (double)b->base_value;
				Format(str, size, "%.2f %s", d, b->string);
			}
			else
			{
				Format(str, size, "%I64u %s", v, b->string);
			}

			break;
		}
	}
}

// Convert the number to a string, and separate it with commas by three orders of magnitude
void ToStr3(char *str, UINT size, UINT64 v)
{
	char tmp[128];
	char tmp2[128];
	UINT i, len, wp;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	ToStr64(tmp, v);

	wp = 0;
	len = StrLen(tmp);

	for (i = len - 1;((int)i) >= 0;i--)
	{
		tmp2[wp++] = tmp[i];
	}
	tmp2[wp++] = 0;

	wp = 0;

	for (i = 0;i < len;i++)
	{
		if (i != 0 && (i % 3) == 0)
		{
			tmp[wp++] = ',';
		}
		tmp[wp++] = tmp2[i];
	}
	tmp[wp++] = 0;
	wp = 0;
	len = StrLen(tmp);

	for (i = len - 1;((int)i) >= 0;i--)
	{
		tmp2[wp++] = tmp[i];
	}
	tmp2[wp++] = 0;

	StrCpy(str, size, tmp2);
}

// Convert the MAC address to a string
void MacToStr(char *str, UINT size, UCHAR *mac_address)
{
	// Validate arguments
	if (str == NULL || mac_address == NULL)
	{
		return;
	}

	Format(str, size, "%02X-%02X-%02X-%02X-%02X-%02X",
		mac_address[0],
		mac_address[1],
		mac_address[2],
		mac_address[3],
		mac_address[4],
		mac_address[5]);
}

// Examine whether the string is empty
bool IsEmptyStr(char *str)
{
	char *s;
	// Validate arguments
	if (str == NULL)
	{
		return true;
	}

	s = CopyStr(str);
	Trim(s);

	if (StrLen(s) == 0)
	{
		Free(s);
		return true;
	}
	else
	{
		Free(s);
		return false;
	}
}

// Convert the token list to a string list
LIST *TokenListToList(TOKEN_LIST *t)
{
	UINT i;
	LIST *o;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);
	for (i = 0;i < t->NumTokens;i++)
	{
		Insert(o, CopyStr(t->Token[i]));
	}

	return o;
}

// Convert a string list to a token list
TOKEN_LIST *ListToTokenList(LIST *o)
{
	UINT i;
	TOKEN_LIST *t;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		t->Token[i] = CopyStr(LIST_DATA(o, i));
	}

	return t;
}

// Free the string list
void FreeStrList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char *s = LIST_DATA(o, i);
		Free(s);
	}

	ReleaseList(o);
}

// Convert the string list to a string
BUF *StrListToStr(LIST *o)
{
	BUF *b;
	UINT i;
	char c;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}
	b = NewBuf();

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char *s = LIST_DATA(o, i);
		WriteBuf(b, s, StrLen(s) + 1);
	}

	c = 0;
	WriteBuf(b, &c, 1);

	SeekBuf(b, 0, 0);

	return b;
}

// Convert a (NULL delimited) string to a list
LIST *StrToStrList(char *str, UINT size)
{
	LIST *o;
	char *tmp;
	UINT tmp_size;
	UINT i;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	o = NewListFast(NULL);

	i = 0;
	while (true)
	{
		if (i >= size)
		{
			break;
		}
		if (*str == 0)
		{
			break;
		}

		tmp_size = StrSize(str);
		tmp = ZeroMalloc(tmp_size);
		StrCpy(tmp, tmp_size, str);
		Add(o, tmp);
		str += StrLen(str) + 1;
		i++;
	}

	return o;
}

// Check whether the specified string is a number
bool IsNum(char *str)
{
	char c;
	UINT i, len;
	UINT n = 0;
	char tmp[MAX_SIZE];
	TOKEN_LIST *t;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	if (StrLen(tmp) == 0)
	{
		return false;
	}

	t = ParseToken(tmp, " ");

	if (t->NumTokens >= 1)
	{
		StrCpy(tmp, sizeof(tmp), t->Token[0]);
	}

	FreeToken(t);

	len = StrLen(tmp);
	for (i = 0;i < len;i++)
	{
		bool b = false;
		c = tmp[i];
		if (('0' <= c && c <= '9') || (c == '+') || (c == '-') || (c == ','))
		{
			b = true;
		}

		if (b == false)
		{
			return false;
		}
	}

	for (i = 0;i < len;i++)
	{
		c = tmp[i];
		if (c == '-')
		{
			n++;
		}
	}
	if (n >= 2)
	{
		return false;
	}

	return true;
}

// Empty token list
TOKEN_LIST *NullToken()
{
	TOKEN_LIST *ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->Token = ZeroMalloc(0);

	return ret;
}

// Copy the token list
TOKEN_LIST *CopyToken(TOKEN_LIST *src)
{
	TOKEN_LIST *ret;
	UINT i;
	// Validate arguments
	if (src == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = src->NumTokens;
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);
	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = CopyStr(src->Token[i]);
	}

	return ret;
}

// Parse the command line
TOKEN_LIST *ParseCmdLine(char *str)
{
	TOKEN_LIST *t;
	LIST *o;
	UINT i, len, wp, mode;
	char c;
	char *tmp;
	bool ignore_space = false;
	// Validate arguments
	if (str == NULL)
	{
		// There is no token
		return NullToken();
	}

	o = NewListFast(NULL);
	tmp = Malloc(StrSize(str) + 32);

	wp = 0;
	mode = 0;

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		c = str[i];

		switch (mode)
		{
		case 0:
			// Mode to discover the next token
			if (c == ' ' || c == '\t')
			{
				// Advance to the next character
			}
			else
			{
				// Start of the token
				if (c == '\"')
				{
					if (str[i + 1] == '\"')
					{
						// Regard "" as a single "
						tmp[wp++] = '\"';
						i++;
					}
					else
					{
						// Enable the ignoring space flag for a single "
						ignore_space = true;
					}
				}
				else
				{
					tmp[wp++] = c;
				}

				mode = 1;
			}
			break;

		case 1:
			if (ignore_space == false && (c == ' ' || c == '\t'))
			{
				// End of the token
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, CopyStr(tmp));
				mode = 0;
			}
			else
			{
				if (c == '\"')
				{
					if (str[i + 1] == '\"')
					{
						// Regard "" as a single "
						tmp[wp++] = L'\"';
						i++;
					}
					else
					{
						if (ignore_space == false)
						{
							// Enable the ignoring space flag for a single "
							ignore_space = true;
						}
						else
						{
							// Disable the space ignore flag
							ignore_space = false;
						}
					}
				}
				else
				{
					tmp[wp++] = c;
				}
			}
			break;
		}
	}

	if (wp != 0)
	{
		tmp[wp++] = 0;
		Insert(o, CopyStr(tmp));
	}

	Free(tmp);

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

// Convert a 64-bit integer to a string
void ToStr64(char *str, UINT64 value)
{
	char tmp[MAX_SIZE];
	UINT wp = 0;
	UINT len, i;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	// Set to empty character
	StrCpy(tmp, 0, "");

	// Append from the last digit
	while (true)
	{
		UINT a = (UINT)(value % (UINT64)10);
		value = value / (UINT64)10;
		tmp[wp++] = (char)('0' + a);
		if (value == 0)
		{
			tmp[wp++] = 0;
			break;
		}
	}

	// Reverse order
	len = StrLen(tmp);
	for (i = 0;i < len;i++)
	{
		str[len - i - 1] = tmp[i];
	}
	str[len] = 0;
}

// Convert a string to a 64-bit integer
UINT64 ToInt64(char *str)
{
	UINT len, i;
	UINT64 ret = 0;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];
		if (c != ',')
		{
			if ('0' <= c && c <= '9')
			{
				ret = ret * (UINT64)10 + (UINT64)(c - '0');
			}
			else
			{
				break;
			}
		}
	}

	return ret;
}

// Check whether the str ends with the key
bool EndWith(char *str, char *key)
{
	UINT str_len;
	UINT key_len;
	// Validate arguments
	if (str == NULL || key == NULL)
	{
		return false;
	}

	// Comparison
	str_len = StrLen(str);
	key_len = StrLen(key);
	if (str_len < key_len)
	{
		return false;
	}

	if (StrCmpi(str + (str_len - key_len), key) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Check whether the str starts with the key
bool StartWith(char *str, char *key)
{
	UINT str_len;
	UINT key_len;
	char *tmp;
	bool ret;
	// Validate arguments
	if (str == NULL || key == NULL)
	{
		return false;
	}

	// Comparison
	str_len = StrLen(str);
	key_len = StrLen(key);
	if (str_len < key_len)
	{
		return false;
	}
	if (str_len == 0 || key_len == 0)
	{
		return false;
	}
	tmp = CopyStr(str);
	tmp[key_len] = 0;

	if (StrCmpi(tmp, key) == 0)
	{
		ret = true;
	}
	else
	{
		ret = false;
	}

	Free(tmp);

	return ret;
}

// Display the binary data
void PrintBin(void *data, UINT size)
{
	char *tmp;
	UINT i;
	// Validate arguments
	if (data == NULL)
	{
		return;
	}

	i = size * 3 + 1;
	tmp = Malloc(i);
	BinToStrEx(tmp, i, data, size);
	Print("%s\n", tmp);
	Free(tmp);
}

// Convert the string to a MAC address
bool StrToMac(UCHAR *mac_address, char *str)
{
	BUF *b;
	// Validate arguments
	if (mac_address == NULL || str == NULL)
	{
		return false;
	}

	b = StrToBin(str);
	if (b == NULL)
	{
		return false;
	}

	if (b->Size != 6)
	{
		FreeBuf(b);
		return false;
	}

	Copy(mac_address, b->Buf, 6);

	FreeBuf(b);

	return true;
}

// Convert a hexadecimal string to a binary data
BUF *StrToBin(char *str)
{
	BUF *b;
	UINT len, i;
	char tmp[3];
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	tmp[0] = 0;
	b = NewBuf();
	for (i = 0;i < len;i++)
	{
		char c = str[i];
		c = ToUpper(c);
		if (('0' <= c && c <= '9') || ('A' <= c && c <= 'F'))
		{
			if (tmp[0] == 0)
			{
				tmp[0] = c;
				tmp[1] = 0;
			}
			else if (tmp[1] == 0)
			{
				UCHAR data;
				char tmp2[64];
				tmp[1] = c;
				tmp[2] = 0;
				StrCpy(tmp2, sizeof(tmp2), "0x");
				StrCat(tmp2, sizeof(tmp2), tmp);
				data = (UCHAR)strtoul(tmp2, NULL, 0);
				WriteBuf(b, &data, 1);
				Zero(tmp, sizeof(tmp));	
			}
		}
		else if (c == ' ' || c == ',' || c == '-' || c == ':')
		{
			// Do Nothing
		}
		else
		{
			break;
		}
	}

	return b;
}

// Convert the binary data to a hexadecimal string (with space)
void BinToStrEx(char *str, UINT str_size, void *data, UINT data_size)
{
	char *tmp;
	UCHAR *buf = (UCHAR *)data;
	UINT size;
	UINT i;
	// Validate arguments
	if (str == NULL || data == NULL)
	{
		return;
	}

	// Calculation of size
	size = data_size * 3 + 1;
	// Memory allocation
	tmp = ZeroMalloc(size);
	// Conversion
	for (i = 0;i < data_size;i++)
	{
		Format(&tmp[i * 3], 0, "%02X ", buf[i]);
	}
	Trim(tmp);
	// Copy
	StrCpy(str, str_size, tmp);
	// Memory release
	Free(tmp);
}
void BinToStrEx2(char *str, UINT str_size, void *data, UINT data_size, char padding_char)
{
	char *tmp;
	UCHAR *buf = (UCHAR *)data;
	UINT size;
	UINT i;
	// Validate arguments
	if (str == NULL || data == NULL)
	{
		return;
	}

	// Calculation of size
	size = data_size * 3 + 1;
	// Memory allocation
	tmp = ZeroMalloc(size);
	// Conversion
	for (i = 0;i < data_size;i++)
	{
		Format(&tmp[i * 3], 0, "%02X%c", buf[i], padding_char);
	}
	if (StrLen(tmp) >= 1)
	{
		if (tmp[StrLen(tmp) - 1] == padding_char)
		{
			tmp[StrLen(tmp) - 1] = 0;
		}
	}
	// Copy
	StrCpy(str, str_size, tmp);
	// Memory release
	Free(tmp);
}
// Convert the binary data to a string, and copy it
char *CopyBinToStrEx(void *data, UINT data_size)
{
	char *ret;
	UINT size;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	size = data_size * 3 + 1;
	ret = ZeroMalloc(size);

	BinToStrEx(ret, size, data, data_size);

	return ret;
}
char *CopyBinToStr(void *data, UINT data_size)
{
	char *ret;
	UINT size;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	size = data_size * 2 + 1;
	ret = ZeroMalloc(size);

	BinToStr(ret, size, data, data_size);

	return ret;
}

// Convert the binary data to a hexadecimal string
void BinToStr(char *str, UINT str_size, void *data, UINT data_size)
{
	char *tmp;
	UCHAR *buf = (UCHAR *)data;
	UINT size;
	UINT i;
	// Validate arguments
	if (str == NULL || data == NULL)
	{
		if (str != NULL)
		{
			str[0] = 0;
		}
		return;
	}

	// Calculation of size
	size = data_size * 2 + 1;
	// Memory allocation
	tmp = ZeroMalloc(size);
	// Conversion
	for (i = 0;i < data_size;i++)
	{
		sprintf(&tmp[i * 2], "%02X", buf[i]);
	}
	// Copy
	StrCpy(str, str_size, tmp);
	// Memory release
	Free(tmp);
}
void BinToStrW(wchar_t *str, UINT str_size, void *data, UINT data_size)
{
	char *tmp;
	UINT tmp_size;
	// Validate arguments
	if (str == NULL || data == NULL)
	{
		if (str != NULL)
		{
			str[0] = 0;
		}
		return;
	}

	tmp_size = (data_size * 2 + 4) * sizeof(wchar_t);
	tmp = ZeroMalloc(tmp_size);

	BinToStr(tmp, tmp_size, data, data_size);

	StrToUni(str, str_size, tmp);

	Free(tmp);
}

// Convert a 160-bit sequence into a string
void Bit160ToStr(char *str, UCHAR *data)
{
	// Validate arguments
	if (str == NULL || data == NULL)
	{
		return;
	}

	Format(str, 0,
		"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], 
		data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]);
}

// Make a string from a 128-bit sequence
void Bit128ToStr(char *str, UCHAR *data)
{
	// Validate arguments
	if (str == NULL || data == NULL)
	{
		return;
	}

	Format(str, 0,
		"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9], 
		data[10], data[11], data[12], data[13], data[14], data[15]);
}

// Copy a string
char *CopyStr(char *str)
{
	UINT len;
	char *dst;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	dst = Malloc(len + 1);
	StrCpy(dst, len + 1, str);
	return dst;
}

// Check whether the string is safe
bool IsSafeStr(char *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		if (IsSafeChar(str[i]) == false)
		{
			return false;
		}
	}
	if (str[0] == ' ')
	{
		return false;
	}
	if (len != 0)
	{
		if (str[len - 1] == ' ')
		{
			return false;
		}
	}
	return true;
}

// Check whether the character can be displayed
bool IsPrintableAsciiChar(char c)
{
	UCHAR uc = (UCHAR)c;
	if (uc <= 31)
	{
		return false;
	}
	if (uc >= 127)
	{
		return false;
	}
	return true;
}

// Check whether the string that can be displayed
bool IsPrintableAsciiStr(char *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if (IsPrintableAsciiChar(c) == false)
		{
			return false;
		}
	}

	return true;
}

// Convert a string to a displayable string
void EnPrintableAsciiStr(char *str, char replace)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		char c = str[i];

		if (IsPrintableAsciiChar(c) == false)
		{
			str[i] = replace;
		}
	}
}

// Check whether the character is safe
bool IsSafeChar(char c)
{
	UINT i, len;
	char *check_str =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789"
		" ()-_#%&.";

	len = StrLen(check_str);
	for (i = 0;i < len;i++)
	{
		if (c == check_str[i])
		{
			return true;
		}
	}
	return false;
}

// Remove the specified character from a string
void TruncateCharFromStr(char *str, char replace)
{
	char *src,*dst;

	if (str == NULL)
	{
		return;
	}

	src = dst = str;

	while(*src != '\0')
	{
		if(*src != replace)
		{
			*dst = *src;
			dst++;
		}
		src++;
	}
	*dst = *src;

	//BUF *b = NewBuf();
	//UINT i, len;
	//char zero = 0;

	//len = StrLen(str);
	//for (i = 0;i < len;i++)
	//{
	//	char c = str[i];

	//	if (c != replace)
	//	{
	//		WriteBuf(b, &c, 1);
	//	}
	//}

	//if (b->Size == 0)
	//{
	//	char c = '_';
	//	WriteBuf(b, &c, 1);
	//}

	//WriteBuf(b, &zero, 1);

	//StrCpy(str, 0, b->Buf);

	//FreeBuf(b);
}

// Replace the unsafe characters
void EnSafeStr(char *str, char replace)
{
	if (str == NULL)
	{
		return;
	}

	while(*str != '\0')
	{
		if(IsSafeChar(*str) == false)
		{
			*str = replace;
		}
		str++;
	}
}

// Operation check of string library
bool CheckStringLibrary()
{
	wchar_t *compare_str = L"TEST_TEST_123_123456789012345";
	char *teststr = "TEST";
	wchar_t *testunistr = L"TEST";
	wchar_t tmp[64];
	UINT i1 = 123;
	UINT64 i2 = 123456789012345ULL;

	UniFormat(tmp, sizeof(tmp), L"%S_%s_%u_%I64u", teststr, testunistr,
		i1, i2);

	if (UniStrCmpi(tmp, compare_str) != 0)
	{
		return false;
	}

	return true;
}

// Initialize the string library
void InitStringLibrary()
{
	// Create a lock for token
	token_lock = NewLock();

	// Initialization of the International Library
	InitInternational();

	// Operation check
	if (CheckStringLibrary() == false)
	{
#ifdef	OS_WIN32
		Alert("String Library Init Failed.\r\nPlease check your locale settings.", NULL);
#else	// OS_WIN32
		Alert("String Library Init Failed.\r\nPlease check your locale settings and iconv() libraries.", NULL);
#endif	// OS_WIN32
		exit(0);
	}
}

// Release of the string library
void FreeStringLibrary()
{
	// Release of the International Library
	FreeInternational();

	// Release of the lock for token
	DeleteLock(token_lock);
	token_lock = NULL;
}

// String replaceing (case insensitive)
UINT ReplaceStri(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword)
{
	return ReplaceStrEx(dst, size, string, old_keyword, new_keyword, false);
}

// String replaceing (case sensitive)
UINT ReplaceStr(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword)
{
	return ReplaceStrEx(dst, size, string, old_keyword, new_keyword, true);
}

// String replaceing
UINT ReplaceStrEx(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword, bool case_sensitive)
{
	UINT i, j, num;
	UINT len_string, len_old, len_new;
	UINT len_ret;
	UINT wp;
	char *ret;
	// Validate arguments
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	// Get the length of the string
	len_string = StrLen(string);
	len_old = StrLen(old_keyword);
	len_new = StrLen(new_keyword);

	// Calculate the final string length
	len_ret = CalcReplaceStrEx(string, old_keyword, new_keyword, case_sensitive);
	// Memory allocation
	ret = Malloc(len_ret + 1);
	ret[len_ret] = '\0';

	// Search and Replace
	i = 0;
	j = 0;
	num = 0;
	wp = 0;
	while (true)
	{
		i = SearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
			Copy(ret + wp, string + j, len_string - j);
			wp += len_string - j;
			break;
		}
		num++;
		Copy(ret + wp, string + j, i - j);
		wp += i - j;
		Copy(ret + wp, new_keyword, len_new);
		wp += len_new;
		i += len_old;
		j = i;
	}

	// Copy of the search results
	StrCpy(dst, size, ret);

	// Memory release
	Free(ret);

	return num;
}

// Calculate the length of the result of string replacement
UINT CalcReplaceStrEx(char *string, char *old_keyword, char *new_keyword, bool case_sensitive)
{
	UINT i, num;
	UINT len_string, len_old, len_new;
	// Validate arguments
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	// Get the length of the string
	len_string = StrLen(string);
	len_old = StrLen(old_keyword);
	len_new = StrLen(new_keyword);

	if (len_old == len_new)
	{
		return len_string;
	}

	// Search
	num = 0;
	i = 0;
	while (true)
	{
		i = SearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
			break;
		}
		i += len_old;
		num++;
	}

	// Calculation
	return len_string + len_new * num - len_old * num;
}

// Search for a string (distinguish between upper / lower case)
UINT SearchStr(char *string, char *keyword, UINT start)
{
	return SearchStrEx(string, keyword, start, true);
}

// Search for a string (Don't distinguish between upper / lower case)
UINT SearchStri(char *string, char *keyword, UINT start)
{
	return SearchStrEx(string, keyword, start, false);
}

// Examine whether the string contains the specified character
bool InChar(char *string, char c)
{
	UINT i, len;
	// Validate arguments
	if (string == NULL)
	{
		return false;
	}

	len = StrLen(string);

	for (i = 0;i < len;i++)
	{
		if (string[i] == c)
		{
			return true;
		}
	}

	return false;
}

// Return the position of the first found keyword in the string
// (Found at first character: returns 0, Not found: returns INFINITE)
UINT SearchStrEx(char *string, char *keyword, UINT start, bool case_sensitive)
{
	UINT len_string, len_keyword;
	UINT i;
	char *cmp_string, *cmp_keyword;
	bool found;
	// Validate arguments
	if (string == NULL || keyword == NULL)
	{
		return INFINITE;
	}

	// Get the length of string
	len_string = StrLen(string);
	if (len_string <= start)
	{
		// Value of start is invalid
		return INFINITE;
	}

	// Get the length of the keyword
	len_keyword = StrLen(keyword);
	if (len_keyword == 0)
	{
		// There is no keyword in the string
		return INFINITE;
	}

	if ((len_string - start) < len_keyword)
	{
		// The keyword is longer than the string
		return INFINITE;
	}

	if (case_sensitive)
	{
		cmp_string = string;
		cmp_keyword = keyword;
	}
	else
	{
		cmp_string = Malloc(len_string + 1);
		StrCpy(cmp_string, len_string + 1, string);
		cmp_keyword = Malloc(len_keyword + 1);
		StrCpy(cmp_keyword, len_keyword + 1, keyword);
		StrUpper(cmp_string);
		StrUpper(cmp_keyword);
	}

	// Search
	found = false;
	for (i = start;i < (len_string - len_keyword + 1);i++)
	{
		// Compare
		if (!strncmp(&cmp_string[i], cmp_keyword, len_keyword))
		{
			// Found
			found = true;
			break;
		}
	}

	if (case_sensitive == false)
	{
		// Memory release
		Free(cmp_keyword);
		Free(cmp_string);
	}

	if (found == false)
	{
		return INFINITE;
	}
	return i;
}

// Determine whether the specified character is in the token list
bool IsInToken(TOKEN_LIST *t, char *str)
{
	UINT i;
	// Validate arguments
	if (t == NULL || str == NULL)
	{
		return false;
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		if (StrCmpi(t->Token[i], str) == 0)
		{
			return true;
		}
	}

	return false;
}

// Release of the token list
void FreeToken(TOKEN_LIST *tokens)
{
	UINT i;
	if (tokens == NULL)
	{
		return;
	}
	for (i = 0;i < tokens->NumTokens;i++)
	{
		if (tokens->Token[i] != 0)
		{
			Free(tokens->Token[i]);
		}
	}
	Free(tokens->Token);
	Free(tokens);
}

// Parse the token
TOKEN_LIST *ParseToken(char *src, char *separator)
{
	TOKEN_LIST *ret;
	char *tmp;
	char *str1, *str2;
	UINT len;
	UINT num;
	if (src == NULL)
	{
		ret = ZeroMalloc(sizeof(TOKEN_LIST));
		ret->Token = ZeroMalloc(0);
		return ret;
	}
	if (separator == NULL)
	{
		separator = " ,\t\r\n";
	}
	len = StrLen(src);
	str1 = Malloc(len + 1);
	str2 = Malloc(len + 1);
	StrCpy(str1, 0, src);
	StrCpy(str2, 0, src);

	Lock(token_lock);
	{
		tmp = strtok(str1, separator);
		num = 0;
		while (tmp != NULL)
		{
			num++;
			tmp = strtok(NULL, separator);
		}
		ret = Malloc(sizeof(TOKEN_LIST));
		ret->NumTokens = num;
		ret->Token = (char **)Malloc(sizeof(char *) * num);
		num = 0;
		tmp = strtok(str2, separator);
		while (tmp != NULL)
		{
			ret->Token[num] = (char *)Malloc(StrLen(tmp) + 1);
			StrCpy(ret->Token[num], 0, tmp);
			num++;
			tmp = strtok(NULL, separator);
		}
	}
	Unlock(token_lock);

	Free(str1);
	Free(str2);
	return ret;
}

// Get a line from standard input
bool GetLine(char *str, UINT size)
{
	bool ret;
	wchar_t *unistr;
	UINT unistr_size = (size + 1) * sizeof(wchar_t);

	unistr = Malloc(unistr_size);

	ret = UniGetLine(unistr, unistr_size);

	UniToStr(str, size, unistr);

	Free(unistr);

	return ret;
}

// Remove '\r' and '\n' at the end
void TrimCrlf(char *str)
{
	UINT len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}
	len = StrLen(str);
	if (len == 0)
	{
		return;
	}

	if (str[len - 1] == '\n')
	{
		if (len >= 2 && str[len - 2] == '\r')
		{
			str[len - 2] = 0;
		}
		str[len - 1] = 0;
	}
	else if (str[len - 1] == '\r')
	{
		str[len - 1] = 0;
	}
}

// Remove white spaces of the both side of the string
void Trim(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	// Trim on the left side
	TrimLeft(str);

	// Trim on the right side
	TrimRight(str);
}

// Remove white spaces on the right side of the string
void TrimRight(char *str)
{
	char *buf, *tmp;
	UINT len, i, wp, wp2;
	BOOL flag;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}
	len = StrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[len - 1] != ' ' && str[len - 1] != '\t')
	{
		return;
	}

	buf = Malloc(len + 1);
	tmp = Malloc(len + 1);
	flag = FALSE;
	wp = 0;
	wp2 = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != ' ' && str[i] != '\t')
		{
			Copy(buf + wp, tmp, wp2);
			wp += wp2;
			wp2 = 0;
			buf[wp++] = str[i];
		}
		else
		{
			tmp[wp2++] = str[i];
		}
	}
	buf[wp] = 0;
	StrCpy(str, 0, buf);
	Free(buf);
	Free(tmp);
}

// Remove white spaces from the left side of the string
void TrimLeft(char *str)
{
	char *buf;
	UINT len, i, wp;
	BOOL flag;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}
	len = StrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[0] != ' ' && str[0] != '\t')
	{
		return;
	}

	buf = Malloc(len + 1);
	flag = FALSE;
	wp = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != ' ' && str[i] != '\t')
		{
			flag = TRUE;
		}
		if (flag)
		{
			buf[wp++] = str[i];
		}
	}
	buf[wp] = 0;
	StrCpy(str, 0, buf);
	Free(buf);
}

// Convert an integer to a hexadecimal string (8-digit fixed)
void ToStrx8(char *str, UINT i)
{
	sprintf(str, "0x%08x", i);
}

// Convert an integer to a hexadecimal string
void ToStrx(char *str, UINT i)
{
	sprintf(str, "0x%02x", i);
}

// Convert a signed integer to a string
void ToStri(char *str, int i)
{
	sprintf(str, "%i", i);
}

// Convert an integer to a string
void ToStr(char *str, UINT i)
{
	sprintf(str, "%u", i);
}

// Convert the string to a signed integer
int ToInti(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	return (int)ToInt(str);
}

// Convert a string to a Boolean value
bool ToBool(char *str)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	if (IsEmptyStr(tmp))
	{
		return false;
	}

	if (ToInt(tmp) != 0)
	{
		return true;
	}

	if (StartWith("true", tmp))
	{
		return true;
	}

	if (StartWith("yes", tmp))
	{
		return true;
	}

	if (StartWith(tmp, "true"))
	{
		return true;
	}

	if (StartWith(tmp, "yes"))
	{
		return true;
	}

	return false;
}

// Convert a string to an integer
UINT ToInt(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	// Ignore the octal literal
	while (true)
	{
		if (*str != '0')
		{
			break;
		}
		if ((*(str + 1) == 'x') || (*(str + 1) == 'X'))
		{
			break;
		}
		str++;
	}

	return (UINT)strtoul(str, NULL, 0);
}

// Replace a format string for 64-bit integer
char *ReplaceFormatStringFor64(char *fmt)
{
	char *tmp;
	char *ret;
	UINT tmp_size;
	// Validate arguments
	if (fmt == NULL)
	{
		return NULL;
	}

	tmp_size = StrSize(fmt) * 2;
	tmp = ZeroMalloc(tmp_size);

#ifdef	OS_WIN32
	ReplaceStrEx(tmp, tmp_size, fmt, "%ll", "%I64", false);
#else	// OS_WIN32
	ReplaceStrEx(tmp, tmp_size, fmt, "%I64", "%ll", false);
#endif	// OS_WIN32

	ret = CopyStr(tmp);
	Free(tmp);

	return ret;
}

// Display the string on the screen
void PrintStr(char *str)
{
	wchar_t *unistr = NULL;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

#ifdef	OS_UNIX
	fputs(str, stdout);
#else	// OS_UNIX
	unistr = CopyStrToUni(str);
	UniPrintStr(unistr);
	Free(unistr);
#endif	// OS_UNIX
}

// Display a string with arguments
void PrintArgs(char *fmt, va_list args)
{
	wchar_t *ret;
	wchar_t *fmt_wchar;
	char *tmp;
	// Validate arguments
	if (fmt == NULL)
	{
		return;
	}

	fmt_wchar = CopyStrToUni(fmt);
	ret = InternalFormatArgs(fmt_wchar, args, true);

	tmp = CopyUniToStr(ret);
	PrintStr(tmp);
	Free(tmp);

	Free(ret);
	Free(fmt_wchar);
}

// Display a string
void Print(char *fmt, ...)
{
	va_list args;
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	PrintArgs(fmt, args);
	va_end(args);
}

// Display a debug string with arguments
void DebugArgs(char *fmt, va_list args)
{
	// Validate arguments
	if (fmt == NULL)
	{
		return;
	}
	if (g_debug == false)
	{
		return;
	}

	PrintArgs(fmt, args);
}

// Display a debug string
void Debug(char *fmt, ...)
{
	va_list args;
	// Validate arguments
	if (fmt == NULL)
	{
		return;
	}
	if (g_debug == false)
	{
		return;
	}

	va_start(args, fmt);

	DebugArgs(fmt, args);

	va_end(args);
}

// Format the string, and return the result
char *CopyFormat(char *fmt, ...)
{
	char *buf;
	char *ret;
	UINT size;
	va_list args;
	// Validate arguments
	if (fmt == NULL)
	{
		return NULL;
	}

	size = MAX(StrSize(fmt) * 10, MAX_SIZE * 10);
	buf = Malloc(size);

	va_start(args, fmt);
	FormatArgs(buf, size, fmt, args);

	ret = CopyStr(buf);
	Free(buf);

	va_end(args);
	return ret;
}

// Format the string
void Format(char *buf, UINT size, char *fmt, ...)
{
	va_list args;
	// Validate arguments
	if (buf == NULL || fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	FormatArgs(buf, size, fmt, args);
	va_end(args);
}

// Format the string (argument list)
void FormatArgs(char *buf, UINT size, char *fmt, va_list args)
{
	wchar_t *tag;
	wchar_t *ret;
	// Validate arguments
	if (buf == NULL || fmt == NULL)
	{
		return;
	}

	tag = CopyStrToUni(fmt);
	ret = InternalFormatArgs(tag, args, true);

	UniToStr(buf, size, ret);
	Free(ret);
	Free(tag);
}

// Compare the strings in case-insensitive mode
int StrCmpi(char *str1, char *str2)
{
	UINT i;
	// Validate arguments
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	// String comparison
	i = 0;
	while (true)
	{
		char c1, c2;
		c1 = ToUpper(str1[i]);
		c2 = ToUpper(str2[i]);
		if (c1 > c2)
		{
			return 1;
		}
		else if (c1 < c2)
		{
			return -1;
		}
		if (str1[i] == 0 || str2[i] == 0)
		{
			return 0;
		}
		i++;
	}
}

// Compare the string
int StrCmp(char *str1, char *str2)
{
	// Validate arguments
	if (str1 == NULL && str2 == NULL)
	{
		return 0;
	}
	if (str1 == NULL)
	{
		return 1;
	}
	if (str2 == NULL)
	{
		return -1;
	}

	return strcmp(str1, str2);
}

// Uncapitalize the string
void StrLower(char *str)
{
	UINT len, i;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = ToLower(str[i]);
	}
}

// Capitalize the string
void StrUpper(char *str)
{
	UINT len, i;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = ToUpper(str[i]);
	}
}

// Uncapitalize a character
char ToLower(char c)
{
	if ('A' <= c && c <= 'Z')
	{
		c += 'z' - 'Z';
	}
	return c;
}

// Capitalize a character
char ToUpper(char c)
{
	if ('a' <= c && c <= 'z')
	{
		c += 'Z' - 'z';
	}
	return c;
}

// Combine the string
UINT StrCat(char *dst, UINT size, char *src)
{
	UINT len1, len2, len_test;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	// KS
	KS_INC(KS_STRCAT_COUNT);

	if (size == 0)
	{
		// Ignore the length
		size = 0x7fffffff;
	}

	len1 = StrLen(dst);
	len2 = StrLen(src);
	len_test = len1 + len2 + 1;
	if (len_test > size)
	{
		if (len2 <= (len_test - size))
		{
			return 0;
		}
		len2 -= len_test - size;
	}
	Copy(dst + len1, src, len2);
	dst[len1 + len2] = 0;

	return len1 + len2;
}
UINT StrCatLeft(char *dst, UINT size, char *src)
{
	char *s;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return 0;
	}

	s = CopyStr(dst);
	StrCpy(dst, size, src);
	StrCat(dst, size, s);

	Free(s);

	return StrLen(dst);
}

// Copy a string
UINT StrCpy(char *dst, UINT size, char *src)
{
	UINT len;
	// Validate arguments
	if (dst == src)
	{
		return StrLen(src);
	}
	if (dst == NULL || src == NULL)
	{
		if (src == NULL && dst != NULL)
		{
			if (size >= 1)
			{
				dst[0] = '\0';
			}
		}
		return 0;
	}
	if (size == 1)
	{
		dst[0] = '\0';
		return 0;
	}
	if (size == 0)
	{
		// Ignore the length
		size = 0x7fffffff;
	}

	// Check the length
	len = StrLen(src);
	if (len <= (size - 1))
	{
		Copy(dst, src, len + 1);
	}
	else
	{
		len = size - 1;
		Copy(dst, src, len);
		dst[len] = '\0';
	}

	// KS
	KS_INC(KS_STRCPY_COUNT);

	return len;
}

// Check whether the string buffer is within the specified size
bool StrCheckSize(char *str, UINT size)
{
	// Validate arguments
	if (str == NULL || size == 0)
	{
		return false;
	}

	return StrCheckLen(str, size - 1);
}

// Make sure that the string is within the specified length
bool StrCheckLen(char *str, UINT len)
{
	UINT count = 0;
	UINT i;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	// KS
	KS_INC(KS_STRCHECK_COUNT);

	for (i = 0;;i++)
	{
		if (str[i] == '\0')
		{
			return true;
		}
		count++;
		if (count > len)
		{
			return false;
		}
	}
}

// Get the memory size needed to store the string
UINT StrSize(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	return StrLen(str) + 1;
}

// Get the length of the string
UINT StrLen(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	// KS
	KS_INC(KS_STRLEN_COUNT);

	return (UINT)strlen(str);
}



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
