// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Str.c
// String processing routine

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <ctype.h>
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

// Decode URL string
char *UrlDecode(char *url_str)
{
	UINT i, len;
	BUF *b;
	char *ret;
	if (url_str == NULL)
	{
		return NULL;
	}

	len = StrLen(url_str);

	b = NewBuf();

	for (i = 0;i < len;i++)
	{
		char c = url_str[i];

		if (c == '%' && ((i + 2) < len))
		{
			char hex_str[8];
			UINT value;

			hex_str[0] = url_str[i + 1];
			hex_str[1] = url_str[i + 2];
			hex_str[2] = 0;

			value = HexToInt(hex_str);

			WriteBufChar(b, (UCHAR)value);

			i += 2;
			continue;
		}
		else
		{
			if (c == '+')
			{
				c = ' ';
			}
			WriteBufChar(b, c);
		}
	}

	WriteBufChar(b, 0);

	ret = CopyStr(b->Buf);

	FreeBuf(b);

	return ret;
}

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


UINT64 Json_ToInt64Ex(char *str, char **endptr, bool *error)
{
	UINT i;
	UINT64 ret = 0;
	if (error != NULL) *error = true;
	// Validate arguments
	if (str == NULL)
	{
		if (endptr != NULL)
		{
			*endptr = NULL;
		}
		return 0;
	}

	for (i = 0;;i++)
	{
		char c = str[i];
		if (endptr != NULL)
		{
			*endptr = &str[i];
		}
		if (c == 0)
		{
			break;
		}
		if ('0' <= c && c <= '9')
		{
			ret = ret * (UINT64)10 + (UINT64)(c - '0');
			if (error != NULL) *error = false;
		}
		else
		{
			break;
		}
	}

	return ret;
}

// Trim EndWith
bool TrimEndWith(char *dst, UINT dst_size, char *str, char *key)
{
	if (dst == NULL || str == NULL)
	{
		ClearStr(dst, dst_size);
		return false;
	}

	StrCpy(dst, dst_size, str);

	if (EndWith(str, key))
	{
		UINT src_len = StrLen(str);
		UINT key_len = StrLen(key);

		if (src_len >= key_len)
		{
			dst[src_len - key_len] = 0;
		}

		return true;
	}

	return false;
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

// Replace '\r' and '\n' with the specified character.
// If the specified character is a space (unsafe), the original character is removed.
void EnSafeHttpHeaderValueStr(char *str, char replace)
{
	UINT length = 0;
	UINT index = 0;

	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	length = StrLen(str);
	while (index < length)
	{
		if (str[index] == '\r' || str[index] == '\n')
		{
			if (replace == ' ')
			{
				Move(&str[index], &str[index + 1], length - index);
			}
			else
			{
				str[index] = replace;
			}
		}
		else if (str[index] == '\\')
		{
			if (str[index + 1] == 'r' || str[index + 1] == 'n')
			{
				if (replace == ' ')
				{
					Move(&str[index], &str[index + 2], length - index);
					index--;
				}
				else
				{
					str[index] = str[index + 1] = replace;
					index++;
				}
			}
		}
		index++;
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
	// 2020/7/20 remove strtok by dnobori
	return ParseTokenWithoutNullStr(src, separator);
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

// Remove quotes at the beginning and at the end of the string
void TrimQuotes(char *str)
{
	UINT len = 0;
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

	if (str[len - 1] == '\"')
	{
		str[len - 1] = 0;
	}

	if (str[0] == '\"')
	{
		Move(str, str + 1, len);
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
UINT StrCpyAllowOverlap(char *dst, UINT size, char *src)
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
		Move(dst, src, len + 1);
	}
	else
	{
		len = size - 1;
		Move(dst, src, len);
		dst[len] = '\0';
	}

	// KS
	KS_INC(KS_STRCPY_COUNT);

	return len;
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






// *** JSON strings support
// Original source code from Parson ( http://kgabis.github.com/parson/ )
// Modified by dnobori
/*
Parson ( http://kgabis.github.com/parson/ )
Copyright (c) 2012 - 2017 Krzysztof Gabis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/



/* Apparently sscanf is not implemented in some "standard" libraries, so don't use it, if you
* don't have to. */
#define sscanf THINK_TWICE_ABOUT_USING_SSCANF

#define STARTING_CAPACITY 16
#define MAX_NESTING       2048
#define FLOAT_FORMAT      "%1.17g"

#define SIZEOF_TOKEN(a)       (sizeof(a) - 1)
#define SKIP_CHAR(str)        ((*str)++)
#define SKIP_WHITESPACES(str) while (isspace((unsigned char)(**str))) { SKIP_CHAR(str); }

static JSON_Malloc_Function parson_malloc = Malloc;
static JSON_Free_Function parson_free = Free;

#define IS_CONT(b) (((unsigned char)(b) & 0xC0) == 0x80) /* is utf-8 continuation byte */

/* Various */
static void   remove_comments(char *string, char *start_token, char *end_token);
static char * parson_strndup(char *string, UINT n);
static char * parson_strdup(char *string);
static int    hex_char_to_int(char c);
static int    parse_utf16_hex(char *string, unsigned int *result);
static int    num_bytes_in_utf8_sequence(unsigned char c);
static int    verify_utf8_sequence(unsigned char *string, int *len);
static int    is_valid_utf8(char *string, UINT string_len);
static int    is_decimal(char *string, UINT length);

/* JSON Object */
static JSON_OBJECT * json_object_init(JSON_VALUE *wrapping_value);
static UINT   json_object_add(JSON_OBJECT *object, char *name, JSON_VALUE *value);
static UINT   json_object_resize(JSON_OBJECT *object, UINT new_capacity);
static JSON_VALUE  * json_object_nget_value(JSON_OBJECT *object, char *name, UINT n);
static void          json_object_free(JSON_OBJECT *object);

/* JSON Array */
static JSON_ARRAY * json_array_init(JSON_VALUE *wrapping_value);
static UINT  json_array_add(JSON_ARRAY *array, JSON_VALUE *value);
static UINT  json_array_resize(JSON_ARRAY *array, UINT new_capacity);
static void         json_array_free(JSON_ARRAY *array);

/* JSON Value */
static JSON_VALUE * json_value_init_string_no_copy(char *string);

/* Parser */
static UINT  skip_quotes(char **string);
static int          parse_utf16(char **unprocessed, char **processed);
static char *       process_string(char *input, UINT len);
static char *       get_quoted_string(char **string);
static JSON_VALUE * parse_object_value(char **string, UINT nesting);
static JSON_VALUE * parse_array_value(char **string, UINT nesting);
static JSON_VALUE * parse_string_value(char **string);
static JSON_VALUE * parse_boolean_value(char **string);
static JSON_VALUE * parse_number_value(char **string);
static JSON_VALUE * parse_null_value(char **string);
static JSON_VALUE * parse_value(char **string, UINT nesting);

/* Serialization */
static int    json_serialize_to_buffer_r(JSON_VALUE *value, char *buf, int level, int is_pretty, char *num_buf);
static int    json_serialize_string(char *string, char *buf);
static int    append_indent(char *buf, int level);
static int    append_string(char *buf, char *string);

/* Various */
static char * parson_strndup(char *string, UINT n) {
	char *output_string = (char*)parson_malloc(n + 1);
	if (!output_string) {
		return NULL;
	}
	output_string[n] = '\0';
	strncpy(output_string, string, n);
	return output_string;
}

static char * parson_strdup(char *string) {
	return parson_strndup(string, StrLen(string));
}

static int hex_char_to_int(char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

static int parse_utf16_hex(char *s, unsigned int *result) {
	int x1, x2, x3, x4;
	if (s[0] == '\0' || s[1] == '\0' || s[2] == '\0' || s[3] == '\0') {
		return 0;
	}
	x1 = hex_char_to_int(s[0]);
	x2 = hex_char_to_int(s[1]);
	x3 = hex_char_to_int(s[2]);
	x4 = hex_char_to_int(s[3]);
	if (x1 == -1 || x2 == -1 || x3 == -1 || x4 == -1) {
		return 0;
	}
	*result = (unsigned int)((x1 << 12) | (x2 << 8) | (x3 << 4) | x4);
	return 1;
}

static int num_bytes_in_utf8_sequence(unsigned char c) {
	if (c == 0xC0 || c == 0xC1 || c > 0xF4 || IS_CONT(c)) {
		return 0;
	}
	else if ((c & 0x80) == 0) {    /* 0xxxxxxx */
		return 1;
	}
	else if ((c & 0xE0) == 0xC0) { /* 110xxxxx */
		return 2;
	}
	else if ((c & 0xF0) == 0xE0) { /* 1110xxxx */
		return 3;
	}
	else if ((c & 0xF8) == 0xF0) { /* 11110xxx */
		return 4;
	}
	return 0; /* won't happen */
}

static int verify_utf8_sequence(unsigned char *string, int *len) {
	unsigned int cp = 0;
	*len = num_bytes_in_utf8_sequence(string[0]);

	if (*len == 1) {
		cp = string[0];
	}
	else if (*len == 2 && IS_CONT(string[1])) {
		cp = string[0] & 0x1F;
		cp = (cp << 6) | (string[1] & 0x3F);
	}
	else if (*len == 3 && IS_CONT(string[1]) && IS_CONT(string[2])) {
		cp = ((unsigned char)string[0]) & 0xF;
		cp = (cp << 6) | (string[1] & 0x3F);
		cp = (cp << 6) | (string[2] & 0x3F);
	}
	else if (*len == 4 && IS_CONT(string[1]) && IS_CONT(string[2]) && IS_CONT(string[3])) {
		cp = string[0] & 0x7;
		cp = (cp << 6) | (string[1] & 0x3F);
		cp = (cp << 6) | (string[2] & 0x3F);
		cp = (cp << 6) | (string[3] & 0x3F);
	}
	else {
		return 0;
	}

	/* overlong encodings */
	if ((cp < 0x80 && *len > 1) ||
		(cp < 0x800 && *len > 2) ||
		(cp < 0x10000 && *len > 3)) {
			return 0;
	}

	/* invalid unicode */
	if (cp > 0x10FFFF) {
		return 0;
	}

	/* surrogate halves */
	if (cp >= 0xD800 && cp <= 0xDFFF) {
		return 0;
	}

	return 1;
}

static int is_valid_utf8(char *string, UINT string_len) {
	int len = 0;
	char *string_end = string + string_len;
	while (string < string_end) {
		if (!verify_utf8_sequence((unsigned char*)string, &len)) {
			return 0;
		}
		string += len;
	}
	return 1;
}

static int is_decimal(char *string, UINT length) {
	if (length > 1 && string[0] == '0' && string[1] != '.') {
		return 0;
	}
	if (length > 2 && !strncmp(string, "-0", 2) && string[2] != '.') {
		return 0;
	}
	while (length--) {
		if (strchr("xX", string[length])) {
			return 0;
		}
	}
	return 1;
}

static void remove_comments(char *string, char *start_token, char *end_token) {
	int in_string = 0, escaped = 0;
	UINT i;
	char *ptr = NULL, current_char;
	UINT start_token_len = StrLen(start_token);
	UINT end_token_len = StrLen(end_token);
	if (start_token_len == 0 || end_token_len == 0) {
		return;
	}
	while ((current_char = *string) != '\0') {
		if (current_char == '\\' && !escaped) {
			escaped = 1;
			string++;
			continue;
		}
		else if (current_char == '\"' && !escaped) {
			in_string = !in_string;
		}
		else if (!in_string && strncmp(string, start_token, start_token_len) == 0) {
			for (i = 0; i < start_token_len; i++) {
				string[i] = ' ';
			}
			string = string + start_token_len;
			ptr = strstr(string, end_token);
			if (!ptr) {
				return;
			}
			for (i = 0; i < (ptr - string) + end_token_len; i++) {
				string[i] = ' ';
			}
			string = ptr + end_token_len - 1;
		}
		escaped = 0;
		string++;
	}
}

/* JSON Object */
static JSON_OBJECT * json_object_init(JSON_VALUE *wrapping_value) {
	JSON_OBJECT *new_obj = (JSON_OBJECT*)parson_malloc(sizeof(JSON_OBJECT));
	if (new_obj == NULL) {
		return NULL;
	}
	new_obj->wrapping_value = wrapping_value;
	new_obj->names = (char**)NULL;
	new_obj->values = (JSON_VALUE**)NULL;
	new_obj->capacity = 0;
	new_obj->count = 0;
	return new_obj;
}

static UINT json_object_add(JSON_OBJECT *object, char *name, JSON_VALUE *value) {
	UINT index = 0;
	if (object == NULL || name == NULL || value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonGet(object, name) != NULL) {
		return JSON_RET_ERROR;
	}
	if (object->count >= object->capacity) {
		UINT new_capacity = MAX(object->capacity * 2, STARTING_CAPACITY);
		if (json_object_resize(object, new_capacity) == JSON_RET_ERROR) {
			return JSON_RET_ERROR;
		}
	}
	index = object->count;
	object->names[index] = parson_strdup(name);
	if (object->names[index] == NULL) {
		return JSON_RET_ERROR;
	}
	value->parent = JsonGetWrappingValue(object);
	object->values[index] = value;
	object->count++;
	return JSON_RET_OK;
}

static UINT json_object_resize(JSON_OBJECT *object, UINT new_capacity) {
	char **temp_names = NULL;
	JSON_VALUE **temp_values = NULL;

	if ((object->names == NULL && object->values != NULL) ||
		(object->names != NULL && object->values == NULL) ||
		new_capacity == 0) {
			return JSON_RET_ERROR; /* Shouldn't happen */
	}
	temp_names = (char**)parson_malloc(new_capacity * sizeof(char*));
	if (temp_names == NULL) {
		return JSON_RET_ERROR;
	}
	temp_values = (JSON_VALUE**)parson_malloc(new_capacity * sizeof(JSON_VALUE*));
	if (temp_values == NULL) {
		parson_free(temp_names);
		return JSON_RET_ERROR;
	}
	if (object->names != NULL && object->values != NULL && object->count > 0) {
		memcpy(temp_names, object->names, object->count * sizeof(char*));
		memcpy(temp_values, object->values, object->count * sizeof(JSON_VALUE*));
	}
	parson_free(object->names);
	parson_free(object->values);
	object->names = temp_names;
	object->values = temp_values;
	object->capacity = new_capacity;
	return JSON_RET_OK;
}

static JSON_VALUE * json_object_nget_value(JSON_OBJECT *object, char *name, UINT n) {
	UINT i, name_length;
	for (i = 0; i < JsonGetCount(object); i++) {
		name_length = StrLen(object->names[i]);
		if (name_length != n) {
			continue;
		}
		if (strncmp(object->names[i], name, n) == 0) {
			return object->values[i];
		}
	}
	return NULL;
}

static void json_object_free(JSON_OBJECT *object) {
	UINT i;
	for (i = 0; i < object->count; i++) {
		parson_free(object->names[i]);
		JsonFree(object->values[i]);
	}
	parson_free(object->names);
	parson_free(object->values);
	parson_free(object);
}

/* JSON Array */
static JSON_ARRAY * json_array_init(JSON_VALUE *wrapping_value) {
	JSON_ARRAY *new_array = (JSON_ARRAY*)parson_malloc(sizeof(JSON_ARRAY));
	if (new_array == NULL) {
		return NULL;
	}
	new_array->wrapping_value = wrapping_value;
	new_array->items = (JSON_VALUE**)NULL;
	new_array->capacity = 0;
	new_array->count = 0;
	return new_array;
}

static UINT json_array_add(JSON_ARRAY *array, JSON_VALUE *value) {
	if (array->count >= array->capacity) {
		UINT new_capacity = MAX(array->capacity * 2, STARTING_CAPACITY);
		if (json_array_resize(array, new_capacity) == JSON_RET_ERROR) {
			return JSON_RET_ERROR;
		}
	}
	value->parent = JsonArrayGetWrappingValue(array);
	array->items[array->count] = value;
	array->count++;
	return JSON_RET_OK;
}

static UINT json_array_resize(JSON_ARRAY *array, UINT new_capacity) {
	JSON_VALUE **new_items = NULL;
	if (new_capacity == 0) {
		return JSON_RET_ERROR;
	}
	new_items = (JSON_VALUE**)parson_malloc(new_capacity * sizeof(JSON_VALUE*));
	if (new_items == NULL) {
		return JSON_RET_ERROR;
	}
	if (array->items != NULL && array->count > 0) {
		memcpy(new_items, array->items, array->count * sizeof(JSON_VALUE*));
	}
	parson_free(array->items);
	array->items = new_items;
	array->capacity = new_capacity;
	return JSON_RET_OK;
}

static void json_array_free(JSON_ARRAY *array) {
	UINT i;
	for (i = 0; i < array->count; i++) {
		JsonFree(array->items[i]);
	}
	parson_free(array->items);
	parson_free(array);
}

/* JSON Value */
static JSON_VALUE * json_value_init_string_no_copy(char *string) {
	JSON_VALUE *new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (!new_value) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_STRING;
	new_value->value.string = string;
	return new_value;
}

/* Parser */
static UINT skip_quotes(char **string) {
	if (**string != '\"') {
		return JSON_RET_ERROR;
	}
	SKIP_CHAR(string);
	while (**string != '\"') {
		if (**string == '\0') {
			return JSON_RET_ERROR;
		}
		else if (**string == '\\') {
			SKIP_CHAR(string);
			if (**string == '\0') {
				return JSON_RET_ERROR;
			}
		}
		SKIP_CHAR(string);
	}
	SKIP_CHAR(string);
	return JSON_RET_OK;
}

static int parse_utf16(char **unprocessed, char **processed) {
	unsigned int cp, lead, trail;
	int parse_succeeded = 0;
	char *processed_ptr = *processed;
	char *unprocessed_ptr = *unprocessed;
	unprocessed_ptr++; /* skips u */
	parse_succeeded = parse_utf16_hex(unprocessed_ptr, &cp);
	if (!parse_succeeded) {
		return JSON_RET_ERROR;
	}
	if (cp < 0x80) {
		processed_ptr[0] = (char)cp; /* 0xxxxxxx */
	}
	else if (cp < 0x800) {
		processed_ptr[0] = ((cp >> 6) & 0x1F) | 0xC0; /* 110xxxxx */
		processed_ptr[1] = ((cp) & 0x3F) | 0x80; /* 10xxxxxx */
		processed_ptr += 1;
	}
	else if (cp < 0xD800 || cp > 0xDFFF) {
		processed_ptr[0] = ((cp >> 12) & 0x0F) | 0xE0; /* 1110xxxx */
		processed_ptr[1] = ((cp >> 6) & 0x3F) | 0x80; /* 10xxxxxx */
		processed_ptr[2] = ((cp) & 0x3F) | 0x80; /* 10xxxxxx */
		processed_ptr += 2;
	}
	else if (cp >= 0xD800 && cp <= 0xDBFF) { /* lead surrogate (0xD800..0xDBFF) */
		lead = cp;
		unprocessed_ptr += 4; /* should always be within the buffer, otherwise previous sscanf would fail */
		if (*unprocessed_ptr++ != '\\' || *unprocessed_ptr++ != 'u') {
			return JSON_RET_ERROR;
		}
		parse_succeeded = parse_utf16_hex(unprocessed_ptr, &trail);
		if (!parse_succeeded || trail < 0xDC00 || trail > 0xDFFF) { /* valid trail surrogate? (0xDC00..0xDFFF) */
			return JSON_RET_ERROR;
		}
		cp = ((((lead - 0xD800) & 0x3FF) << 10) | ((trail - 0xDC00) & 0x3FF)) + 0x010000;
		processed_ptr[0] = (((cp >> 18) & 0x07) | 0xF0); /* 11110xxx */
		processed_ptr[1] = (((cp >> 12) & 0x3F) | 0x80); /* 10xxxxxx */
		processed_ptr[2] = (((cp >> 6) & 0x3F) | 0x80); /* 10xxxxxx */
		processed_ptr[3] = (((cp) & 0x3F) | 0x80); /* 10xxxxxx */
		processed_ptr += 3;
	}
	else { /* trail surrogate before lead surrogate */
		return JSON_RET_ERROR;
	}
	unprocessed_ptr += 3;
	*processed = processed_ptr;
	*unprocessed = unprocessed_ptr;
	return JSON_RET_OK;
}


/* Copies and processes passed string up to supplied length.
Example: "\u006Corem ipsum" -> lorem ipsum */
static char* process_string(char *input, UINT len) {
	char *input_ptr = input;
	UINT initial_size = (len + 1) * sizeof(char);
	UINT final_size = 0;
	char *output = NULL, *output_ptr = NULL, *resized_output = NULL;
	output = (char*)parson_malloc(initial_size);
	if (output == NULL) {
		goto error;
	}
	output_ptr = output;
	while ((*input_ptr != '\0') && (UINT)(input_ptr - input) < len) {
		if (*input_ptr == '\\') {
			input_ptr++;
			switch (*input_ptr) {
			case '\"': *output_ptr = '\"'; break;
			case '\\': *output_ptr = '\\'; break;
			case '/':  *output_ptr = '/';  break;
			case 'b':  *output_ptr = '\b'; break;
			case 'f':  *output_ptr = '\f'; break;
			case 'n':  *output_ptr = '\n'; break;
			case 'r':  *output_ptr = '\r'; break;
			case 't':  *output_ptr = '\t'; break;
			case 'u':
				if (parse_utf16(&input_ptr, &output_ptr) == JSON_RET_ERROR) {
					goto error;
				}
				break;
			default:
				goto error;
			}
		}
		else if ((unsigned char)*input_ptr < 0x20) {
			goto error; /* 0x00-0x19 are invalid characters for json string (http://www.ietf.org/rfc/rfc4627.txt) */
		}
		else {
			*output_ptr = *input_ptr;
		}
		output_ptr++;
		input_ptr++;
	}
	*output_ptr = '\0';
	/* resize to new length */
	final_size = (UINT)(output_ptr - output) + 1;
	/* todo: don't resize if final_size == initial_size */
	resized_output = (char*)parson_malloc(final_size);
	if (resized_output == NULL) {
		goto error;
	}
	memcpy(resized_output, output, final_size);
	parson_free(output);
	return resized_output;
error:
	parson_free(output);
	return NULL;
}

/* Return processed contents of a string between quotes and
skips passed argument to a matching quote. */
static char * get_quoted_string(char **string) {
	char *string_start = *string;
	UINT string_len = 0;
	UINT status = skip_quotes(string);
	if (status != JSON_RET_OK) {
		return NULL;
	}
	string_len = (UINT)(*string - string_start - 2); /* length without quotes */
	return process_string(string_start + 1, string_len);
}

static JSON_VALUE * parse_value(char **string, UINT nesting) {
	if (nesting > MAX_NESTING) {
		return NULL;
	}
	SKIP_WHITESPACES(string);
	switch (**string) {
	case '{':
		return parse_object_value(string, nesting + 1);
	case '[':
		return parse_array_value(string, nesting + 1);
	case '\"':
		return parse_string_value(string);
	case 'f': case 't':
		return parse_boolean_value(string);
	case '-':
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		return parse_number_value(string);
	case 'n':
		return parse_null_value(string);
	default:
		return NULL;
	}
}

static JSON_VALUE * parse_object_value(char **string, UINT nesting) {
	JSON_VALUE *output_value = JsonNewObject(), *new_value = NULL;
	JSON_OBJECT *output_object = JsonValueGetObject(output_value);
	char *new_key = NULL;
	if (output_value == NULL || **string != '{') {
		return NULL;
	}
	SKIP_CHAR(string);
	SKIP_WHITESPACES(string);
	if (**string == '}') { /* empty object */
		SKIP_CHAR(string);
		return output_value;
	}
	while (**string != '\0') {
		new_key = get_quoted_string(string);
		if (new_key == NULL) {
			JsonFree(output_value);
			return NULL;
		}
		SKIP_WHITESPACES(string);
		if (**string != ':') {
			parson_free(new_key);
			JsonFree(output_value);
			return NULL;
		}
		SKIP_CHAR(string);
		new_value = parse_value(string, nesting);
		if (new_value == NULL) {
			parson_free(new_key);
			JsonFree(output_value);
			return NULL;
		}
		if (json_object_add(output_object, new_key, new_value) == JSON_RET_ERROR) {
			parson_free(new_key);
			JsonFree(new_value);
			JsonFree(output_value);
			return NULL;
		}
		parson_free(new_key);
		SKIP_WHITESPACES(string);
		if (**string != ',') {
			break;
		}
		SKIP_CHAR(string);
		SKIP_WHITESPACES(string);
	}
	SKIP_WHITESPACES(string);
	if (**string != '}' || /* Trim object after parsing is over */
		json_object_resize(output_object, JsonGetCount(output_object)) == JSON_RET_ERROR) {
			JsonFree(output_value);
			return NULL;
	}
	SKIP_CHAR(string);
	return output_value;
}

static JSON_VALUE * parse_array_value(char **string, UINT nesting) {
	JSON_VALUE *output_value = JsonNewArray(), *new_array_value = NULL;
	JSON_ARRAY *output_array = JsonValueGetArray(output_value);
	if (!output_value || **string != '[') {
		return NULL;
	}
	SKIP_CHAR(string);
	SKIP_WHITESPACES(string);
	if (**string == ']') { /* empty array */
		SKIP_CHAR(string);
		return output_value;
	}
	while (**string != '\0') {
		new_array_value = parse_value(string, nesting);
		if (new_array_value == NULL) {
			JsonFree(output_value);
			return NULL;
		}
		if (json_array_add(output_array, new_array_value) == JSON_RET_ERROR) {
			JsonFree(new_array_value);
			JsonFree(output_value);
			return NULL;
		}
		SKIP_WHITESPACES(string);
		if (**string != ',') {
			break;
		}
		SKIP_CHAR(string);
		SKIP_WHITESPACES(string);
	}
	SKIP_WHITESPACES(string);
	if (**string != ']' || /* Trim array after parsing is over */
		json_array_resize(output_array, JsonArrayGetCount(output_array)) == JSON_RET_ERROR) {
			JsonFree(output_value);
			return NULL;
	}
	SKIP_CHAR(string);
	return output_value;
}

static JSON_VALUE * parse_string_value(char **string) {
	JSON_VALUE *value = NULL;
	char *new_string = get_quoted_string(string);
	if (new_string == NULL) {
		return NULL;
	}
	value = json_value_init_string_no_copy(new_string);
	if (value == NULL) {
		parson_free(new_string);
		return NULL;
	}
	return value;
}

static JSON_VALUE * parse_boolean_value(char **string) {
	UINT true_token_size = SIZEOF_TOKEN("true");
	UINT false_token_size = SIZEOF_TOKEN("false");
	if (strncmp("true", *string, true_token_size) == 0) {
		*string += true_token_size;
		return JsonNewBool(1);
	}
	else if (strncmp("false", *string, false_token_size) == 0) {
		*string += false_token_size;
		return JsonNewBool(0);
	}
	return NULL;
}

static JSON_VALUE * parse_number_value(char **string) {
	char *end;
	bool error = false;
	UINT64 number = 0;
	number = Json_ToInt64Ex(*string, &end, &error);

	if (error)
	{
		return NULL;
	}
	*string = end;
	return JsonNewNumber(number);
}

static JSON_VALUE * parse_null_value(char **string) {
	UINT token_size = SIZEOF_TOKEN("null");
	if (strncmp("null", *string, token_size) == 0) {
		*string += token_size;
		return JsonNewNull();
	}
	return NULL;
}

/* Serialization */
#define APPEND_STRING(str) do { written = append_string(buf, (str));\
	if (written < 0) { return -1; }\
	if (buf != NULL) { buf += written; }\
	written_total += written; } while(0)

#define APPEND_INDENT(level) do { written = append_indent(buf, (level));\
	if (written < 0) { return -1; }\
	if (buf != NULL) { buf += written; }\
	written_total += written; } while(0)

static int json_serialize_to_buffer_r(JSON_VALUE *value, char *buf, int level, int is_pretty, char *num_buf)
{
	char *key = NULL, *string = NULL;
	JSON_VALUE *temp_value = NULL;
	JSON_ARRAY *array = NULL;
	JSON_OBJECT *object = NULL;
	UINT i = 0, count = 0;
	UINT64 num = 0;
	int written = -1, written_total = 0;
	char tmp[32];

	switch (JsonValueGetType(value)) {
	case JSON_TYPE_ARRAY:
		array = JsonValueGetArray(value);
		count = JsonArrayGetCount(array);
		APPEND_STRING("[");
		if (count > 0 && is_pretty) {
			APPEND_STRING("\n");
		}
		for (i = 0; i < count; i++) {
			if (is_pretty) {
				APPEND_INDENT(level + 1);
			}
			temp_value = JsonArrayGet(array, i);
			written = json_serialize_to_buffer_r(temp_value, buf, level + 1, is_pretty, num_buf);
			if (written < 0) {
				return -1;
			}
			if (buf != NULL) {
				buf += written;
			}
			written_total += written;
			if (i < (count - 1)) {
				APPEND_STRING(",");
			}
			if (is_pretty) {
				APPEND_STRING("\n");
			}
		}
		if (count > 0 && is_pretty) {
			APPEND_INDENT(level);
		}
		APPEND_STRING("]");
		return written_total;
	case JSON_TYPE_OBJECT:
		object = JsonValueGetObject(value);
		count = JsonGetCount(object);
		APPEND_STRING("{");
		if (count > 0 && is_pretty) {
			APPEND_STRING("\n");
		}
		for (i = 0; i < count; i++) {
			key = JsonGetName(object, i);
			if (key == NULL) {
				return -1;
			}
			if (is_pretty) {
				APPEND_INDENT(level + 1);
			}
			written = json_serialize_string(key, buf);
			if (written < 0) {
				return -1;
			}
			if (buf != NULL) {
				buf += written;
			}
			written_total += written;
			APPEND_STRING(":");
			if (is_pretty) {
				APPEND_STRING(" ");
			}
			temp_value = JsonGet(object, key);
			written = json_serialize_to_buffer_r(temp_value, buf, level + 1, is_pretty, num_buf);
			if (written < 0) {
				return -1;
			}
			if (buf != NULL) {
				buf += written;
			}
			written_total += written;
			if (i < (count - 1)) {
				APPEND_STRING(",");
			}
			if (is_pretty) {
				APPEND_STRING("\n");
			}
		}
		if (count > 0 && is_pretty) {
			APPEND_INDENT(level);
		}
		APPEND_STRING("}");
		return written_total;
	case JSON_TYPE_STRING:
		string = JsonValueGetStr(value);
		if (string == NULL) {
			return -1;
		}
		written = json_serialize_string(string, buf);
		if (written < 0) {
			return -1;
		}
		if (buf != NULL) {
			buf += written;
		}
		written_total += written;
		return written_total;
	case JSON_TYPE_BOOL:
		if (JsonValueGetBool(value)) {
			APPEND_STRING("true");
		}
		else {
			APPEND_STRING("false");
		}
		return written_total;
	case JSON_TYPE_NUMBER:
		num = JsonValueGetNumber(value);
		if (buf != NULL) {
			num_buf = buf;
		}
		ToStr64(tmp, num);
		Copy(num_buf, tmp, StrLen(tmp));
		written = StrLen(tmp);
		if (buf != NULL) {
			buf += written;
		}
		written_total += written;
		return written_total;
	case JSON_TYPE_NULL:
		APPEND_STRING("null");
		return written_total;
	case JSON_TYPE_ERROR:
		return -1;
	default:
		return -1;
	}
}

static int json_serialize_string(char *string, char *buf) {
	UINT i = 0, len = StrLen(string);
	char c = '\0';
	int written = -1, written_total = 0;
	APPEND_STRING("\"");
	for (i = 0; i < len; i++) {
		c = string[i];
		switch (c) {
		case '\"': APPEND_STRING("\\\""); break;
		case '\\': APPEND_STRING("\\\\"); break;
		case '/':  APPEND_STRING("\\/"); break; /* to make json embeddable in xml\/html */
		case '\b': APPEND_STRING("\\b"); break;
		case '\f': APPEND_STRING("\\f"); break;
		case '\n': APPEND_STRING("\\n"); break;
		case '\r': APPEND_STRING("\\r"); break;
		case '\t': APPEND_STRING("\\t"); break;
		case '\x00': APPEND_STRING("\\u0000"); break;
		case '\x01': APPEND_STRING("\\u0001"); break;
		case '\x02': APPEND_STRING("\\u0002"); break;
		case '\x03': APPEND_STRING("\\u0003"); break;
		case '\x04': APPEND_STRING("\\u0004"); break;
		case '\x05': APPEND_STRING("\\u0005"); break;
		case '\x06': APPEND_STRING("\\u0006"); break;
		case '\x07': APPEND_STRING("\\u0007"); break;
			/* '\x08' duplicate: '\b' */
			/* '\x09' duplicate: '\t' */
			/* '\x0a' duplicate: '\n' */
		case '\x0b': APPEND_STRING("\\u000b"); break;
			/* '\x0c' duplicate: '\f' */
			/* '\x0d' duplicate: '\r' */
		case '\x0e': APPEND_STRING("\\u000e"); break;
		case '\x0f': APPEND_STRING("\\u000f"); break;
		case '\x10': APPEND_STRING("\\u0010"); break;
		case '\x11': APPEND_STRING("\\u0011"); break;
		case '\x12': APPEND_STRING("\\u0012"); break;
		case '\x13': APPEND_STRING("\\u0013"); break;
		case '\x14': APPEND_STRING("\\u0014"); break;
		case '\x15': APPEND_STRING("\\u0015"); break;
		case '\x16': APPEND_STRING("\\u0016"); break;
		case '\x17': APPEND_STRING("\\u0017"); break;
		case '\x18': APPEND_STRING("\\u0018"); break;
		case '\x19': APPEND_STRING("\\u0019"); break;
		case '\x1a': APPEND_STRING("\\u001a"); break;
		case '\x1b': APPEND_STRING("\\u001b"); break;
		case '\x1c': APPEND_STRING("\\u001c"); break;
		case '\x1d': APPEND_STRING("\\u001d"); break;
		case '\x1e': APPEND_STRING("\\u001e"); break;
		case '\x1f': APPEND_STRING("\\u001f"); break;
		default:
			if (buf != NULL) {
				buf[0] = c;
				buf += 1;
			}
			written_total += 1;
			break;
		}
	}
	APPEND_STRING("\"");
	return written_total;
}

static int append_indent(char *buf, int level) {
	int i;
	int written = -1, written_total = 0;
	for (i = 0; i < level; i++) {
		APPEND_STRING("    ");
	}
	return written_total;
}

static int append_string(char *buf, char *string) {
	if (buf == NULL) {
		return (int)strlen(string);
	}
	return sprintf(buf, "%s", string);
}

#undef APPEND_STRING
#undef APPEND_INDENT

JSON_VALUE * JsonParseString(char *string) {
	if (string == NULL) {
		return NULL;
	}
	if (string[0] == '\xEF' && string[1] == '\xBB' && string[2] == '\xBF') {
		string = string + 3; /* Support for UTF-8 BOM */
	}
	return parse_value((char**)&string, 0);
}

JSON_VALUE * JsonParseStringWithComments(char *string) {
	JSON_VALUE *result = NULL;
	char *string_mutable_copy = NULL, *string_mutable_copy_ptr = NULL;
	string_mutable_copy = parson_strdup(string);
	if (string_mutable_copy == NULL) {
		return NULL;
	}
	remove_comments(string_mutable_copy, "/*", "*/");
	remove_comments(string_mutable_copy, "//", "\n");
	string_mutable_copy_ptr = string_mutable_copy;
	result = parse_value((char**)&string_mutable_copy_ptr, 0);
	parson_free(string_mutable_copy);
	return result;
}

/* JSON Object API */

JSON_VALUE * JsonGet(JSON_OBJECT *object, char *name) {
	if (object == NULL || name == NULL) {
		return NULL;
	}
	return json_object_nget_value(object, name, StrLen(name));
}

char * JsonGetStr(JSON_OBJECT *object, char *name) {
	return JsonValueGetStr(JsonGet(object, name));
}

UINT64 JsonGetNumber(JSON_OBJECT *object, char *name) {
	return JsonValueGetNumber(JsonGet(object, name));
}

JSON_OBJECT * JsonGetObj(JSON_OBJECT *object, char *name) {
	return JsonValueGetObject(JsonGet(object, name));
}

JSON_ARRAY * JsonGetArray(JSON_OBJECT *object, char *name) {
	return JsonValueGetArray(JsonGet(object, name));
}

bool JsonGetBool(JSON_OBJECT *object, char *name) {
	return JsonValueGetBool(JsonGet(object, name));
}

JSON_VALUE * JsonDotGet(JSON_OBJECT *object, char *name) {
	char *dot_position = strchr(name, '.');
	if (!dot_position) {
		return JsonGet(object, name);
	}
	object = JsonValueGetObject(json_object_nget_value(object, name, (UINT)(dot_position - name)));
	return JsonDotGet(object, dot_position + 1);
}

char * JsonDotGetStr(JSON_OBJECT *object, char *name) {
	return JsonValueGetStr(JsonDotGet(object, name));
}

UINT64 JsonDotGetNumber(JSON_OBJECT *object, char *name) {
	return JsonValueGetNumber(JsonDotGet(object, name));
}

JSON_OBJECT * JsonDotGetObj(JSON_OBJECT *object, char *name) {
	return JsonValueGetObject(JsonDotGet(object, name));
}

JSON_ARRAY * JsonDotGetArray(JSON_OBJECT *object, char *name) {
	return JsonValueGetArray(JsonDotGet(object, name));
}

bool JsonDotGetBool(JSON_OBJECT *object, char *name) {
	return JsonValueGetBool(JsonDotGet(object, name));
}

UINT JsonGetCount(JSON_OBJECT *object) {
	return object ? object->count : 0;
}

char * JsonGetName(JSON_OBJECT *object, UINT index) {
	if (object == NULL || index >= JsonGetCount(object)) {
		return NULL;
	}
	return object->names[index];
}

JSON_VALUE * JsonGetValueAt(JSON_OBJECT *object, UINT index) {
	if (object == NULL || index >= JsonGetCount(object)) {
		return NULL;
	}
	return object->values[index];
}

JSON_VALUE *JsonGetWrappingValue(JSON_OBJECT *object) {
	return object->wrapping_value;
}

int JsonIsExists(JSON_OBJECT *object, char *name) {
	return JsonGet(object, name) != NULL;
}

int JsonIsExistsWithValueType(JSON_OBJECT *object, char *name, UINT type) {
	JSON_VALUE *val = JsonGet(object, name);
	return val != NULL && JsonValueGetType(val) == type;
}

int JsonDotIsExists(JSON_OBJECT *object, char *name) {
	return JsonDotGet(object, name) != NULL;
}

int JsonDotIsExistsWithValueType(JSON_OBJECT *object, char *name, UINT type) {
	JSON_VALUE *val = JsonDotGet(object, name);
	return val != NULL && JsonValueGetType(val) == type;
}

/* JSON Array API */
JSON_VALUE * JsonArrayGet(JSON_ARRAY *array, UINT index) {
	if (array == NULL || index >= JsonArrayGetCount(array)) {
		return NULL;
	}
	return array->items[index];
}

char * JsonArrayGetStr(JSON_ARRAY *array, UINT index) {
	return JsonValueGetStr(JsonArrayGet(array, index));
}

UINT64 JsonArrayGetNumber(JSON_ARRAY *array, UINT index) {
	return JsonValueGetNumber(JsonArrayGet(array, index));
}

JSON_OBJECT * JsonArrayGetObj(JSON_ARRAY *array, UINT index) {
	return JsonValueGetObject(JsonArrayGet(array, index));
}

JSON_ARRAY * JsonArrayGetArray(JSON_ARRAY *array, UINT index) {
	return JsonValueGetArray(JsonArrayGet(array, index));
}

bool JsonArrayGetBool(JSON_ARRAY *array, UINT index) {
	return JsonValueGetBool(JsonArrayGet(array, index));
}

UINT JsonArrayGetCount(JSON_ARRAY *array) {
	return array ? array->count : 0;
}

JSON_VALUE * JsonArrayGetWrappingValue(JSON_ARRAY *array) {
	return array->wrapping_value;
}

/* JSON Value API */
UINT JsonValueGetType(JSON_VALUE *value) {
	return value ? value->type : JSON_TYPE_ERROR;
}

JSON_OBJECT * JsonValueGetObject(JSON_VALUE *value) {
	if (value == NULL)
	{
		return NULL;
	}
	return JsonValueGetType(value) == JSON_TYPE_OBJECT ? value->value.object : NULL;
}

JSON_ARRAY * JsonValueGetArray(JSON_VALUE *value) {
	return JsonValueGetType(value) == JSON_TYPE_ARRAY ? value->value.array : NULL;
}

char * JsonValueGetStr(JSON_VALUE *value) {
	return JsonValueGetType(value) == JSON_TYPE_STRING ? value->value.string : NULL;
}

UINT64 JsonValueGetNumber(JSON_VALUE *value) {
	return JsonValueGetType(value) == JSON_TYPE_NUMBER ? value->value.number : 0;
}

bool JsonValueGetBool(JSON_VALUE *value) {
	return JsonValueGetType(value) == JSON_TYPE_BOOL ? value->value.boolean : 0;
}

JSON_VALUE * JsonValueGetParent(JSON_VALUE *value) {
	return value ? value->parent : NULL;
}

void JsonFree(JSON_VALUE *value) {
	if (value == NULL)
	{
		return;
	}
	switch (JsonValueGetType(value)) {
	case JSON_TYPE_OBJECT:
		json_object_free(value->value.object);
		break;
	case JSON_TYPE_STRING:
		parson_free(value->value.string);
		break;
	case JSON_TYPE_ARRAY:
		json_array_free(value->value.array);
		break;
	default:
		break;
	}
	parson_free(value);
}

JSON_VALUE * JsonNewObject(void) {
	JSON_VALUE *new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (!new_value) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_OBJECT;
	new_value->value.object = json_object_init(new_value);
	if (!new_value->value.object) {
		parson_free(new_value);
		return NULL;
	}
	return new_value;
}

JSON_VALUE * JsonNewArray(void) {
	JSON_VALUE *new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (!new_value) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_ARRAY;
	new_value->value.array = json_array_init(new_value);
	if (!new_value->value.array) {
		parson_free(new_value);
		return NULL;
	}
	return new_value;
}

JSON_VALUE * JsonNewStr(char *string) {
	char *copy = NULL;
	JSON_VALUE *value;
	UINT string_len = 0;
	if (string == NULL) {
		return NULL;
	}
	string_len = StrLen(string);
	if (!is_valid_utf8(string, string_len)) {
		return NULL;
	}
	copy = parson_strndup(string, string_len);
	if (copy == NULL) {
		return NULL;
	}
	value = json_value_init_string_no_copy(copy);
	if (value == NULL) {
		parson_free(copy);
	}
	return value;
}

JSON_VALUE * JsonNewNumber(UINT64 number) {
	JSON_VALUE *new_value = NULL;
	new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (new_value == NULL) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_NUMBER;
	new_value->value.number = number;
	return new_value;
}

JSON_VALUE * JsonNewBool(int boolean) {
	JSON_VALUE *new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (!new_value) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_BOOL;
	new_value->value.boolean = boolean ? 1 : 0;
	return new_value;
}

JSON_VALUE * JsonNewNull(void) {
	JSON_VALUE *new_value = (JSON_VALUE*)parson_malloc(sizeof(JSON_VALUE));
	if (!new_value) {
		return NULL;
	}
	new_value->parent = NULL;
	new_value->type = JSON_TYPE_NULL;
	return new_value;
}

JSON_VALUE * JsonDeepCopy(JSON_VALUE *value) {
	UINT i = 0;
	JSON_VALUE *return_value = NULL, *temp_value_copy = NULL, *temp_value = NULL;
	char *temp_string = NULL, *temp_key = NULL;
	char *temp_string_copy = NULL;
	JSON_ARRAY *temp_array = NULL, *temp_array_copy = NULL;
	JSON_OBJECT *temp_object = NULL, *temp_object_copy = NULL;

	switch (JsonValueGetType(value)) {
	case JSON_TYPE_ARRAY:
		temp_array = JsonValueGetArray(value);
		return_value = JsonNewArray();
		if (return_value == NULL) {
			return NULL;
		}
		temp_array_copy = JsonValueGetArray(return_value);
		for (i = 0; i < JsonArrayGetCount(temp_array); i++) {
			temp_value = JsonArrayGet(temp_array, i);
			temp_value_copy = JsonDeepCopy(temp_value);
			if (temp_value_copy == NULL) {
				JsonFree(return_value);
				return NULL;
			}
			if (json_array_add(temp_array_copy, temp_value_copy) == JSON_RET_ERROR) {
				JsonFree(return_value);
				JsonFree(temp_value_copy);
				return NULL;
			}
		}
		return return_value;
	case JSON_TYPE_OBJECT:
		temp_object = JsonValueGetObject(value);
		return_value = JsonNewObject();
		if (return_value == NULL) {
			return NULL;
		}
		temp_object_copy = JsonValueGetObject(return_value);
		for (i = 0; i < JsonGetCount(temp_object); i++) {
			temp_key = JsonGetName(temp_object, i);
			temp_value = JsonGet(temp_object, temp_key);
			temp_value_copy = JsonDeepCopy(temp_value);
			if (temp_value_copy == NULL) {
				JsonFree(return_value);
				return NULL;
			}
			if (json_object_add(temp_object_copy, temp_key, temp_value_copy) == JSON_RET_ERROR) {
				JsonFree(return_value);
				JsonFree(temp_value_copy);
				return NULL;
			}
		}
		return return_value;
	case JSON_TYPE_BOOL:
		return JsonNewBool(JsonValueGetBool(value));
	case JSON_TYPE_NUMBER:
		return JsonNewNumber(JsonValueGetNumber(value));
	case JSON_TYPE_STRING:
		temp_string = JsonValueGetStr(value);
		if (temp_string == NULL) {
			return NULL;
		}
		temp_string_copy = parson_strdup(temp_string);
		if (temp_string_copy == NULL) {
			return NULL;
		}
		return_value = json_value_init_string_no_copy(temp_string_copy);
		if (return_value == NULL) {
			parson_free(temp_string_copy);
		}
		return return_value;
	case JSON_TYPE_NULL:
		return JsonNewNull();
	case JSON_TYPE_ERROR:
		return NULL;
	default:
		return NULL;
	}
}

UINT JsonGetSerializationSize(JSON_VALUE *value) {
	char num_buf[1100]; /* recursively allocating buffer on stack is a bad idea, so let's do it only once */
	int res = json_serialize_to_buffer_r(value, NULL, 0, 0, num_buf);
	return res < 0 ? 0 : (UINT)(res + 1);
}

UINT JsonSerializeToBuffer(JSON_VALUE *value, char *buf, UINT buf_size_in_bytes) {
	int written = -1;
	UINT needed_size_in_bytes = JsonGetSerializationSize(value);
	if (needed_size_in_bytes == 0 || buf_size_in_bytes < needed_size_in_bytes) {
		return JSON_RET_ERROR;
	}
	written = json_serialize_to_buffer_r(value, buf, 0, 0, NULL);
	if (written < 0) {
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

char * JsonSerializeToString(JSON_VALUE *value) {
	UINT serialization_result = JSON_RET_ERROR;
	UINT buf_size_bytes = JsonGetSerializationSize(value);
	char *buf = NULL;
	if (buf_size_bytes == 0) {
		return NULL;
	}
	buf = (char*)parson_malloc(buf_size_bytes);
	if (buf == NULL) {
		return NULL;
	}
	serialization_result = JsonSerializeToBuffer(value, buf, buf_size_bytes);
	if (serialization_result == JSON_RET_ERROR) {
		JsonFreeString(buf);
		return NULL;
	}
	return buf;
}

UINT JsonGetSerializationSizePretty(JSON_VALUE *value) {
	char num_buf[1100]; /* recursively allocating buffer on stack is a bad idea, so let's do it only once */
	int res = json_serialize_to_buffer_r(value, NULL, 0, 1, num_buf);
	return res < 0 ? 0 : (UINT)(res + 1);
}

UINT JsonSerializeToBufferPretty(JSON_VALUE *value, char *buf, UINT buf_size_in_bytes) {
	int written = -1;
	UINT needed_size_in_bytes = JsonGetSerializationSizePretty(value);
	if (needed_size_in_bytes == 0 || buf_size_in_bytes < needed_size_in_bytes) {
		return JSON_RET_ERROR;
	}
	written = json_serialize_to_buffer_r(value, buf, 0, 1, NULL);
	if (written < 0) {
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

JSON_VALUE *StrToJson(char *str)
{
	if (str == NULL)
	{
		return NULL;
	}

	return JsonParseString(str);
}

char *JsonToStr(JSON_VALUE *v)
{
	return JsonSerializeToStringPretty(v);
}
char * JsonSerializeToStringPretty(JSON_VALUE *value) {
	UINT serialization_result = JSON_RET_ERROR;
	UINT buf_size_bytes = JsonGetSerializationSizePretty(value);
	char *buf = NULL;
	if (buf_size_bytes == 0) {
		return NULL;
	}
	buf = (char*)parson_malloc(buf_size_bytes);
	if (buf == NULL) {
		return NULL;
	}
	serialization_result = JsonSerializeToBufferPretty(value, buf, buf_size_bytes);
	if (serialization_result == JSON_RET_ERROR) {
		JsonFreeString(buf);
		return NULL;
	}
	return buf;
}

void JsonFreeString(char *string) {
	parson_free(string);
}

UINT JsonArrayDelete(JSON_ARRAY *array, UINT ix) {
	UINT to_move_bytes = 0;
	if (array == NULL || ix >= JsonArrayGetCount(array)) {
		return JSON_RET_ERROR;
	}
	JsonFree(JsonArrayGet(array, ix));
	to_move_bytes = (JsonArrayGetCount(array) - 1 - ix) * sizeof(JSON_VALUE*);
	memmove(array->items + ix, array->items + ix + 1, to_move_bytes);
	array->count -= 1;
	return JSON_RET_OK;
}

UINT JsonArrayReplace(JSON_ARRAY *array, UINT ix, JSON_VALUE *value) {
	if (array == NULL || value == NULL || value->parent != NULL || ix >= JsonArrayGetCount(array)) {
		return JSON_RET_ERROR;
	}
	JsonFree(JsonArrayGet(array, ix));
	value->parent = JsonArrayGetWrappingValue(array);
	array->items[ix] = value;
	return JSON_RET_OK;
}

UINT JsonArrayReplaceStr(JSON_ARRAY *array, UINT i, char* string) {
	JSON_VALUE *value = JsonNewStr(string);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayReplace(array, i, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayReplaceNumber(JSON_ARRAY *array, UINT i, UINT64 number) {
	JSON_VALUE *value = JsonNewNumber(number);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayReplace(array, i, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayReplaceBool(JSON_ARRAY *array, UINT i, int boolean) {
	JSON_VALUE *value = JsonNewBool(boolean);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayReplace(array, i, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayReplaceNull(JSON_ARRAY *array, UINT i) {
	JSON_VALUE *value = JsonNewNull();
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayReplace(array, i, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayDeleteAll(JSON_ARRAY *array) {
	UINT i = 0;
	if (array == NULL) {
		return JSON_RET_ERROR;
	}
	for (i = 0; i < JsonArrayGetCount(array); i++) {
		JsonFree(JsonArrayGet(array, i));
	}
	array->count = 0;
	return JSON_RET_OK;
}

UINT JsonArrayAdd(JSON_ARRAY *array, JSON_VALUE *value) {
	if (array == NULL || value == NULL || value->parent != NULL) {
		return JSON_RET_ERROR;
	}
	return json_array_add(array, value);
}

UINT JsonArrayAddStr(JSON_ARRAY *array, char *string) {
	JSON_VALUE *value = JsonNewStr(string);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayAdd(array, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayAddUniStr(JSON_ARRAY *array, wchar_t *string)
{
	UINT ret;
	char *utf8 = CopyUniToUtf(string);

	ret = JsonArrayAddStr(array, utf8);

	Free(utf8);
	return ret;
}

UINT JsonArrayAddNumber(JSON_ARRAY *array, UINT64 number) {
	JSON_VALUE *value = JsonNewNumber(number);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayAdd(array, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayAddData(JSON_ARRAY *array, void *data, UINT size)
{
	UINT ret;
	char *b64 = ZeroMalloc(size * 4 + 32);
	B64_Encode(b64, data, size);

	ret = JsonArrayAddStr(array, b64);

	Free(b64);
	return ret;
}

UINT JsonArrayAddBool(JSON_ARRAY *array, int boolean) {
	JSON_VALUE *value = JsonNewBool(boolean);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayAdd(array, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonArrayAddNull(JSON_ARRAY *array) {
	JSON_VALUE *value = JsonNewNull();
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonArrayAdd(array, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonSet(JSON_OBJECT *object, char *name, JSON_VALUE *value) {
	UINT i = 0;
	JSON_VALUE *old_value;
	if (object == NULL || name == NULL || value == NULL || value->parent != NULL) {
		return JSON_RET_ERROR;
	}
	old_value = JsonGet(object, name);
	if (old_value != NULL) { /* free and overwrite old value */
		JsonFree(old_value);
		for (i = 0; i < JsonGetCount(object); i++) {
			if (strcmp(object->names[i], name) == 0) {
				value->parent = JsonGetWrappingValue(object);
				object->values[i] = value;
				return JSON_RET_OK;
			}
		}
	}
	/* add new key value pair */
	return json_object_add(object, name, value);
}

UINT JsonSetData(JSON_OBJECT *object, char *name, void *data, UINT size)
{
	UINT ret;
	char *b64 = ZeroMalloc(size * 4 + 32);
	B64_Encode(b64, data, size);

	ret = JsonSetStr(object, name, b64);

	Free(b64);
	return ret;
}

UINT JsonSetStr(JSON_OBJECT *object, char *name, char *string) {
	return JsonSet(object, name, JsonNewStr(string));
}

UINT JsonSetUniStr(JSON_OBJECT *object, char *name, wchar_t *string)
{
	UINT ret;
	char *utf8 = CopyUniToUtf(string);

	ret = JsonSetStr(object, name, utf8);

	Free(utf8);
	return ret;
}

UINT JsonSetNumber(JSON_OBJECT *object, char *name, UINT64 number) {
	return JsonSet(object, name, JsonNewNumber(number));
}

UINT JsonSetBool(JSON_OBJECT *object, char *name, int boolean) {
	return JsonSet(object, name, JsonNewBool(boolean));
}

UINT JsonSetNull(JSON_OBJECT *object, char *name) {
	return JsonSet(object, name, JsonNewNull());
}

UINT JsonDotSet(JSON_OBJECT *object, char *name, JSON_VALUE *value) {
	char *dot_pos = NULL;
	char *current_name = NULL;
	JSON_OBJECT *temp_obj = NULL;
	JSON_VALUE *new_value = NULL;
	if (object == NULL || name == NULL || value == NULL) {
		return JSON_RET_ERROR;
	}
	dot_pos = strchr(name, '.');
	if (dot_pos == NULL) {
		return JsonSet(object, name, value);
	}
	else {
		current_name = parson_strndup(name, (UINT)(dot_pos - name));
		temp_obj = JsonGetObj(object, current_name);
		if (temp_obj == NULL) {
			new_value = JsonNewObject();
			if (new_value == NULL) {
				parson_free(current_name);
				return JSON_RET_ERROR;
			}
			if (json_object_add(object, current_name, new_value) == JSON_RET_ERROR) {
				JsonFree(new_value);
				parson_free(current_name);
				return JSON_RET_ERROR;
			}
			temp_obj = JsonGetObj(object, current_name);
		}
		parson_free(current_name);
		return JsonDotSet(temp_obj, dot_pos + 1, value);
	}
}

UINT JsonDotSetStr(JSON_OBJECT *object, char *name, char *string) {
	JSON_VALUE *value = JsonNewStr(string);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonDotSet(object, name, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonDotSetNumber(JSON_OBJECT *object, char *name, UINT64 number) {
	JSON_VALUE *value = JsonNewNumber(number);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonDotSet(object, name, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonDotSetBool(JSON_OBJECT *object, char *name, int boolean) {
	JSON_VALUE *value = JsonNewBool(boolean);
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonDotSet(object, name, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonDotSetNull(JSON_OBJECT *object, char *name) {
	JSON_VALUE *value = JsonNewNull();
	if (value == NULL) {
		return JSON_RET_ERROR;
	}
	if (JsonDotSet(object, name, value) == JSON_RET_ERROR) {
		JsonFree(value);
		return JSON_RET_ERROR;
	}
	return JSON_RET_OK;
}

UINT JsonDelete(JSON_OBJECT *object, char *name) {
	UINT i = 0, last_item_index = 0;
	if (object == NULL || JsonGet(object, name) == NULL) {
		return JSON_RET_ERROR;
	}
	last_item_index = JsonGetCount(object) - 1;
	for (i = 0; i < JsonGetCount(object); i++) {
		if (strcmp(object->names[i], name) == 0) {
			parson_free(object->names[i]);
			JsonFree(object->values[i]);
			if (i != last_item_index) { /* Replace key value pair with one from the end */
				object->names[i] = object->names[last_item_index];
				object->values[i] = object->values[last_item_index];
			}
			object->count -= 1;
			return JSON_RET_OK;
		}
	}
	return JSON_RET_ERROR; /* No execution path should end here */
}

UINT JsonDotDelete(JSON_OBJECT *object, char *name) {
	char *dot_pos = strchr(name, '.');
	char *current_name = NULL;
	JSON_OBJECT *temp_obj = NULL;
	if (dot_pos == NULL) {
		return JsonDelete(object, name);
	}
	else {
		current_name = parson_strndup(name, (UINT)(dot_pos - name));
		temp_obj = JsonGetObj(object, current_name);
		parson_free(current_name);
		if (temp_obj == NULL) {
			return JSON_RET_ERROR;
		}
		return JsonDotDelete(temp_obj, dot_pos + 1);
	}
}

UINT JsonDeleteAll(JSON_OBJECT *object) {
	UINT i = 0;
	if (object == NULL) {
		return JSON_RET_ERROR;
	}
	for (i = 0; i < JsonGetCount(object); i++) {
		parson_free(object->names[i]);
		JsonFree(object->values[i]);
	}
	object->count = 0;
	return JSON_RET_OK;
}

UINT JsonValidate(JSON_VALUE *schema, JSON_VALUE *value) {
	JSON_VALUE *temp_schema_value = NULL, *temp_value = NULL;
	JSON_ARRAY *schema_array = NULL, *value_array = NULL;
	JSON_OBJECT *schema_object = NULL, *value_object = NULL;
	UINT schema_type = JSON_TYPE_ERROR, value_type = JSON_TYPE_ERROR;
	char *key = NULL;
	UINT i = 0, count = 0;
	if (schema == NULL || value == NULL) {
		return JSON_RET_ERROR;
	}
	schema_type = JsonValueGetType(schema);
	value_type = JsonValueGetType(value);
	if (schema_type != value_type && schema_type != JSON_TYPE_NULL) { /* null represents all values */
		return JSON_RET_ERROR;
	}
	switch (schema_type) {
	case JSON_TYPE_ARRAY:
		schema_array = JsonValueGetArray(schema);
		value_array = JsonValueGetArray(value);
		count = JsonArrayGetCount(schema_array);
		if (count == 0) {
			return JSON_RET_OK; /* Empty array allows all types */
		}
		/* Get first value from array, rest is ignored */
		temp_schema_value = JsonArrayGet(schema_array, 0);
		for (i = 0; i < JsonArrayGetCount(value_array); i++) {
			temp_value = JsonArrayGet(value_array, i);
			if (JsonValidate(temp_schema_value, temp_value) == JSON_RET_ERROR) {
				return JSON_RET_ERROR;
			}
		}
		return JSON_RET_OK;
	case JSON_TYPE_OBJECT:
		schema_object = JsonValueGetObject(schema);
		value_object = JsonValueGetObject(value);
		count = JsonGetCount(schema_object);
		if (count == 0) {
			return JSON_RET_OK; /* Empty object allows all objects */
		}
		else if (JsonGetCount(value_object) < count) {
			return JSON_RET_ERROR; /* Tested object mustn't have less name-value pairs than schema */
		}
		for (i = 0; i < count; i++) {
			key = JsonGetName(schema_object, i);
			temp_schema_value = JsonGet(schema_object, key);
			temp_value = JsonGet(value_object, key);
			if (temp_value == NULL) {
				return JSON_RET_ERROR;
			}
			if (JsonValidate(temp_schema_value, temp_value) == JSON_RET_ERROR) {
				return JSON_RET_ERROR;
			}
		}
		return JSON_RET_OK;
	case JSON_TYPE_STRING: case JSON_TYPE_NUMBER: case JSON_TYPE_BOOL: case JSON_TYPE_NULL:
		return JSON_RET_OK; /* equality already tested before switch */
	case JSON_TYPE_ERROR: default:
		return JSON_RET_ERROR;
	}
}

int JsonCmp(JSON_VALUE *a, JSON_VALUE *b) {
	JSON_OBJECT *a_object = NULL, *b_object = NULL;
	JSON_ARRAY *a_array = NULL, *b_array = NULL;
	char *a_string = NULL, *b_string = NULL;
	char *key = NULL;
	UINT a_count = 0, b_count = 0, i = 0;
	UINT a_type, b_type;
	UINT64 a_num, b_num;
	a_type = JsonValueGetType(a);
	b_type = JsonValueGetType(b);
	if (a_type != b_type) {
		return 0;
	}
	switch (a_type) {
	case JSON_TYPE_ARRAY:
		a_array = JsonValueGetArray(a);
		b_array = JsonValueGetArray(b);
		a_count = JsonArrayGetCount(a_array);
		b_count = JsonArrayGetCount(b_array);
		if (a_count != b_count) {
			return 0;
		}
		for (i = 0; i < a_count; i++) {
			if (!JsonCmp(JsonArrayGet(a_array, i),
				JsonArrayGet(b_array, i))) {
					return 0;
			}
		}
		return 1;
	case JSON_TYPE_OBJECT:
		a_object = JsonValueGetObject(a);
		b_object = JsonValueGetObject(b);
		a_count = JsonGetCount(a_object);
		b_count = JsonGetCount(b_object);
		if (a_count != b_count) {
			return 0;
		}
		for (i = 0; i < a_count; i++) {
			key = JsonGetName(a_object, i);
			if (!JsonCmp(JsonGet(a_object, key),
				JsonGet(b_object, key))) {
					return 0;
			}
		}
		return 1;
	case JSON_TYPE_STRING:
		a_string = JsonValueGetStr(a);
		b_string = JsonValueGetStr(b);
		if (a_string == NULL || b_string == NULL) {
			return 0; /* shouldn't happen */
		}
		return strcmp(a_string, b_string) == 0;
	case JSON_TYPE_BOOL:
		return JsonValueGetBool(a) == JsonValueGetBool(b);
	case JSON_TYPE_NUMBER:
		a_num = JsonValueGetNumber(a);
		b_num = JsonValueGetNumber(b);
		return a_num == b_num;
	case JSON_TYPE_ERROR:
		return 1;
	case JSON_TYPE_NULL:
		return 1;
	default:
		return 1;
	}
}

UINT JsonType(JSON_VALUE *value) {
	return JsonValueGetType(value);
}

JSON_OBJECT * JsonObject(JSON_VALUE *value) {
	return JsonValueGetObject(value);
}

JSON_ARRAY * JsonArray(JSON_VALUE *value) {
	return JsonValueGetArray(value);
}

char * JsonString(JSON_VALUE *value) {
	return JsonValueGetStr(value);
}

UINT64 JsonNumber(JSON_VALUE *value) {
	return JsonValueGetNumber(value);
}

int JsonBool(JSON_VALUE *value) {
	return JsonValueGetBool(value);
}

void JsonSetAllocationFunctions(JSON_Malloc_Function malloc_fun, JSON_Free_Function free_fun) {
	parson_malloc = malloc_fun;
	parson_free = free_fun;
}

// SYSTEMTIME to JSON string
void SystemTimeToJsonStr(char *dst, UINT size, SYSTEMTIME *t)
{
	if (dst == NULL)
	{
		return;
	}

	if (t == NULL)
	{
		ClearStr(dst, size);
	}
	else
	{
		GetDateTimeStrRFC3339(dst, size, t, 0);
	}
}

// UINT64 System Time to JSON string
void SystemTime64ToJsonStr(char *dst, UINT size, UINT64 t)
{
	SYSTEMTIME st;
	if (dst == NULL)
	{
		return;
	}

	if (t == 0)
	{
		ClearStr(dst, size);
	}

	UINT64ToSystem(&st, t);

	SystemTimeToJsonStr(dst, size, &st);
}




