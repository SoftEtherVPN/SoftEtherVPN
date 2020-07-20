// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Internat.c
// String conversion library for internationalization

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

extern LOCK *token_lock;
static char charset[MAX_SIZE] = "EUCJP";
static LOCK *iconv_lock = NULL;
void *iconv_cache_wide_to_str = 0;
void *iconv_cache_str_to_wide = 0;

// Initialize the string
void ClearUniStr(wchar_t *str, UINT str_size)
{
	UniStrCpy(str, str_size, L"");
}

// Examine whether the string contains the specified character
bool UniInChar(wchar_t *string, wchar_t c)
{
	UINT i, len;
	// Validate arguments
	if (string == NULL)
	{
		return false;
	}

	len = UniStrLen(string);

	for (i = 0;i < len;i++)
	{
		if (string[i] == c)
		{
			return true;
		}
	}

	return false;
}

// Check whether the string is included
bool UniInStr(wchar_t *str, wchar_t *keyword)
{
	return UniInStrEx(str, keyword, false);
}
bool UniInStrEx(wchar_t *str, wchar_t *keyword, bool case_sensitive)
{
	// Validate arguments
	if (UniIsEmptyStr(str) || UniIsEmptyStr(keyword))
	{
		return false;
	}

	if (UniSearchStrEx(str, keyword, 0, case_sensitive) == INFINITE)
	{
		return false;
	}

	return true;
}

// Convert to binary data
BUF *UniStrToBin(wchar_t *str)
{
	char *str_a = CopyUniToStr(str);
	BUF *ret;

	ret = StrToBin(str_a);

	Free(str_a);

	return ret;
}

// Check whether the character is safe
bool UniIsSafeChar(wchar_t c)
{
	UINT i, len;
	wchar_t *check_str =
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		L"abcdefghijklmnopqrstuvwxyz"
		L"0123456789"
		L" ()-_#%&.";

	len = UniStrLen(check_str);
	for (i = 0;i < len;i++)
	{
		if (c == check_str[i])
		{
			return true;
		}
	}
	return false;
}

// Convert a string list to a token list
UNI_TOKEN_LIST *UniListToTokenList(LIST *o)
{
	UINT i;
	UNI_TOKEN_LIST *t;
	// Validate arguments
	if (o == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		t->Token[i] = UniCopyStr(LIST_DATA(o, i));
	}

	return t;
}

// Free the string list
void UniFreeStrList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		Free(s);
	}

	ReleaseList(o);
}

// Normalize the line breaks
wchar_t *UniNormalizeCrlf(wchar_t *str)
{
	wchar_t *ret;
	UINT ret_size, i, len, wp;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	len = UniStrLen(str);
	ret_size = sizeof(wchar_t) * (len + 32) * 2;
	ret = Malloc(ret_size);

	wp = 0;

	for (i = 0;i < len;i++)
	{
		wchar_t c = str[i];

		switch (c)
		{
		case L'\r':
			if (str[i + 1] == L'\n')
			{
				i++;
			}
			ret[wp++] = L'\r';
			ret[wp++] = L'\n';
			break;

		case L'\n':
			ret[wp++] = L'\r';
			ret[wp++] = L'\n';
			break;

		default:
			ret[wp++] = c;
			break;
		}
	}

	ret[wp++] = 0;

	return ret;
}

// Check whether str ends with the key
bool UniEndWith(wchar_t *str, wchar_t *key)
{
	UINT str_len;
	UINT key_len;
	// Validate arguments
	if (str == NULL || key == NULL)
	{
		return false;
	}

	// Comparison
	str_len = UniStrLen(str);
	key_len = UniStrLen(key);
	if (str_len < key_len)
	{
		return false;
	}

	if (UniStrCmpi(str + (str_len - key_len), key) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Check whether str starts with the key
bool UniStartWith(wchar_t *str, wchar_t *key)
{
	UINT str_len;
	UINT key_len;
	wchar_t *tmp;
	bool ret;
	// Validate arguments
	if (str == NULL || key == NULL)
	{
		return false;
	}

	// Comparison
	str_len = UniStrLen(str);
	key_len = UniStrLen(key);
	if (str_len < key_len)
	{
		return false;
	}
	if (str_len == 0 || key_len == 0)
	{
		return false;
	}
	tmp = CopyUniStr(str);
	tmp[key_len] = 0;

	if (UniStrCmpi(tmp, key) == 0)
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

// Convert the integer to a comma-separated string
void UniToStr3(wchar_t *str, UINT size, UINT64 value)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	ToStr3(tmp, sizeof(tmp), value);

	StrToUni(str, size, tmp);
}

// Format of the string (internal function)
wchar_t *InternalFormatArgs(wchar_t *fmt, va_list args, bool ansi_mode)
{
	UINT i, len;
	wchar_t *tmp;
	UINT tmp_size;
	LIST *o;
	UINT mode = 0;
	UINT wp;
	UINT total_size;
	wchar_t *ret;
	// Validate arguments
	if (fmt == NULL)
	{
		return NULL;
	}

	len = UniStrLen(fmt);
	tmp_size = UniStrSize(fmt);
	tmp = Malloc(tmp_size);

	o = NewListFast(NULL);

	mode = 0;

	wp = 0;

	for (i = 0;i < len;i++)
	{
		wchar_t c = fmt[i];

		if (mode == 0)
		{
			// Normal character mode
			switch (c)
			{
			case L'%':
				// The start of the format specification
				if (fmt[i + 1] == L'%')
				{
					// If the next character is also '%', output a '%' simply
					i++;
					tmp[wp++] = c;
				}
				else
				{
					// Shift the state if the next character is not a '%'
					mode = 1;
					tmp[wp++] = 0;
					wp = 0;
					Add(o, CopyUniStr(tmp));
					tmp[wp++] = c;
				}
				break;
			default:
				// Ordinary character
				tmp[wp++] = c;
				break;
			}
		}
		else
		{
			char *tag;
			char dst[MAX_SIZE];
			wchar_t *target_str;
			wchar_t *padding_str;
			bool left_padding;
			UINT target_str_len;
			UINT total_len;
			wchar_t *output_str;
			UINT padding;
			// Formatting mode
			switch (c)
			{
			case L'c':
			case L'C':
			case L'd':
			case L'i':
			case L'o':
			case L'u':
			case L'x':
			case L'X':
				// int type
				tmp[wp++] = c;
				tmp[wp++] = 0;
				tag = CopyUniToStr(tmp);

				#ifdef	OS_WIN32
					ReplaceStrEx(tag, 0, tag, "ll", "I64", false);
				#else	// OS_WIN32
					ReplaceStrEx(tag, 0, tag, "I64", "ll", false);
				#endif	// OS_WIN32

				if ((UniStrLen(tmp) >= 5 && tmp[UniStrLen(tmp) - 4] == L'I' &&
					tmp[UniStrLen(tmp) - 3] == L'6' &&
					tmp[UniStrLen(tmp) - 2] == L'4') ||
					(
					UniStrLen(tmp) >= 4 && tmp[UniStrLen(tmp) - 3] == L'l' &&
					tmp[UniStrLen(tmp) - 2] == L'l'))
				{
					#ifdef	OS_WIN32
						_snprintf(dst, sizeof(dst), tag, va_arg(args, UINT64));
					#else	// OS_WIN32
						snprintf(dst, sizeof(dst), tag, va_arg(args, UINT64));
					#endif	// OS_WIN32
				}
				else
				{
					#ifdef	OS_WIN32
						_snprintf(dst, sizeof(dst), tag, va_arg(args, int));
					#else	// OS_WIN32
						snprintf(dst, sizeof(dst), tag, va_arg(args, int));
					#endif	// OS_WIN32
				}

				Free(tag);
				Add(o, CopyStrToUni(dst));

				wp = 0;
				mode = 0;
				break;
			case L'e':
			case L'E':
			case L'f':
			case L'g':
			case L'G':
				// Double type
				tmp[wp++] = c;
				tmp[wp++] = 0;
				tag = CopyUniToStr(tmp);

				#ifdef	OS_WIN32
					_snprintf(dst, sizeof(dst), tag, va_arg(args, double));
				#else	// OS_WIN32
					snprintf(dst, sizeof(dst), tag, va_arg(args, double));
				#endif	// OS_WIN32

				Free(tag);
				Add(o, CopyStrToUni(dst));

				wp = 0;
				mode = 0;
				break;
			case L'n':
			case L'p':
				// Pointer type
				tmp[wp++] = c;
				tmp[wp++] = 0;
				tag = ZeroMalloc(UniStrSize(tmp) + 32);
				UniToStr(tag, 0, tmp);

				#ifdef	OS_WIN32
					_snprintf(dst, sizeof(dst), tag, va_arg(args, void *));
				#else	// OS_WIN32
					snprintf(dst, sizeof(dst), tag, va_arg(args, void *));
				#endif	// OS_WIN32

				Free(tag);
				Add(o, CopyStrToUni(dst));

				wp = 0;
				mode = 0;
				break;
			case L'r':
			case L'R':
				// IP address type
				tmp[wp++] = c;
				tmp[wp++] = 0;

				Zero(dst, sizeof(dst));
				IPToStr(dst, sizeof(dst), va_arg(args, void *));

				Add(o, CopyStrToUni(dst));

				wp = 0;
				mode = 0;
				break;

			case L's':
			case L'S':
				// String type
				tmp[wp++] = c;
				tmp[wp++] = 0;

				if (ansi_mode == false)
				{
					if (c == L'S')
					{
						c = L's';
					}
					else
					{
						c = L'S';
					}
				}

				if (c == L's')
				{
					target_str = CopyStrToUni(va_arg(args, char *));
				}
				else
				{
					target_str = CopyUniStr(va_arg(args, wchar_t *));
				}

				if (target_str == NULL)
				{
					target_str = CopyUniStr(L"(null)");
				}

				padding = 0;
				left_padding = false;
				if (tmp[1] == L'-')
				{
					// Left aligned
					if (UniStrLen(tmp) >= 3)
					{
						padding = UniToInt(&tmp[2]);
					}
					left_padding = true;
				}
				else
				{
					// Right aligned
					if (UniStrLen(tmp) >= 2)
					{
						padding = UniToInt(&tmp[1]);
					}
				}

				target_str_len = UniStrWidth(target_str);

				if (padding > target_str_len)
				{
					UINT len = padding - target_str_len;
					UINT i;
					padding_str = ZeroMalloc(sizeof(wchar_t) * (len + 1));
					for (i = 0;i < len;i++)
					{
						padding_str[i] = L' ';
					}
				}
				else
				{
					padding_str = ZeroMalloc(sizeof(wchar_t));
				}

				total_len = sizeof(wchar_t) * (UniStrLen(padding_str) + UniStrLen(target_str) + 1);
				output_str = ZeroMalloc(total_len);
				output_str[0] = 0;

				if (left_padding == false)
				{
					UniStrCat(output_str, total_len, padding_str);
				}
				UniStrCat(output_str, total_len, target_str);
				if (left_padding)
				{
					UniStrCat(output_str, total_len, padding_str);
				}

				Add(o, output_str);

				Free(target_str);
				Free(padding_str);

				wp = 0;
				mode = 0;
				break;
			default:
				// Normal string
				tmp[wp++] = c;
				break;
			}
		}
	}
	tmp[wp++] = 0;
	wp = 0;

	if (UniStrLen(tmp) >= 1)
	{
		Add(o, CopyUniStr(tmp));
	}

	total_size = sizeof(wchar_t);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		total_size += UniStrLen(s) * sizeof(wchar_t);
	}

	ret = ZeroMalloc(total_size);
	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		UniStrCat(ret, total_size, s);
		Free(s);
	}

	ReleaseList(o);

	Free(tmp);

	return ret;
}

// Get the width of the string
UINT UniStrWidth(wchar_t *str)
{
	UINT i, len, ret;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	ret = 0;
	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		if (str[i] <= 255)
		{
			ret++;
		}
		else
		{
			ret += 2;
		}
	}
	return ret;
}

// Convert string of 2 byte/character to wchar_t of 4 byte/character
wchar_t *Utf16ToWide(USHORT *str)
{
	wchar_t *ret;
	UINT len, i;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	len = 0;
	while (true)
	{
		if (str[len] == 0)
		{
			break;
		}
		len++;
	}

	ret = Malloc((len + 1) * sizeof(wchar_t));
	for (i = 0;i < len + 1;i++)
	{
		ret[i] = (wchar_t)str[i];
	}

	return ret;
}

// Convert wchar_t string of 4 byte/character to string of 2 byte/character
USHORT *WideToUtf16(wchar_t *str)
{
	USHORT *ret;
	UINT len;
	UINT ret_size;
	UINT i;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	len = UniStrLen(str);

	ret_size = (len + 1) * 2;
	ret = Malloc(ret_size);

	for (i = 0;i < len + 1;i++)
	{
		ret[i] = (USHORT)str[i];
	}

	return ret;
}

// Initialization of the International Library
void InitInternational()
{
#ifdef	OS_UNIX
	void *d;

	if (iconv_lock != NULL)
	{
		return;
	}

	GetCurrentCharSet(charset, sizeof(charset));
	d = IconvWideToStrInternal();
	if (d == (void *)-1)
	{
#if defined (UNIX_MACOS) || defined (UNIX_LINUX_MUSL)
		StrCpy(charset, sizeof(charset), "utf-8");
#else // defined (UNIX_MACOS) || defined (UNIX_LINUX_MUSL) 
		StrCpy(charset, sizeof(charset), "EUCJP");
#endif // defined (UNIX_MACOS) || defined (UNIX_LINUX_MUSL) 
		d = IconvWideToStrInternal();
		if (d == (void *)-1)
		{
			StrCpy(charset, sizeof(charset), "US");
		}
		else
		{
			IconvFreeInternal(d);
		}
	}
	else
	{
		IconvFreeInternal(d);
	}

	iconv_lock = NewLockMain();

	iconv_cache_wide_to_str = IconvWideToStrInternal();
	iconv_cache_str_to_wide = IconvStrToWideInternal();
#endif	// OS_UNIX
}

// Release of the International Library
void FreeInternational()
{
#ifdef	OS_UNIX
#endif	// OS_UNIX
}

#ifdef	OS_UNIX

// Calculate the size when the string converted to Unicode
UINT UnixCalcStrToUni(char *str)
{
	wchar_t *tmp;
	UINT len, tmp_size;
	UINT ret;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	len = StrLen(str);
	tmp_size = len * 5 + 10;
	tmp = ZeroMalloc(tmp_size);
	UnixStrToUni(tmp, tmp_size, str);
	ret = UniStrLen(tmp);
	Free(tmp);

	return (ret + 1) * sizeof(wchar_t);
}

// Convert the strings to Unicode
UINT UnixStrToUni(wchar_t *s, UINT size, char *str)
{
	void *d;
	char *inbuf;
	size_t insize;
	char *outbuf;
	char *outbuf_orig;
	size_t outsize;
	wchar_t *tmp;
	// Validate arguments
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	d = IconvStrToWide();
	if (d == (void *)-1)
	{
		UniStrCpy(s, size, L"");
		return 0;
	}

	inbuf = (char *)str;
	insize = StrLen(str) + 1;
	outsize = insize * 5 + 10;
	outbuf_orig = outbuf = ZeroMalloc(outsize);

	if (iconv((iconv_t)d, (char **)&inbuf, (size_t *)&insize, (char **)&outbuf, (size_t *)&outsize) == (size_t)(-1))
	{
		Free(outbuf_orig);
		UniStrCpy(s, size, L"");
		IconvFree(d);
		return 0;
	}

	tmp = Utf16ToWide((USHORT *)outbuf_orig);
	Free(outbuf_orig);

	UniStrCpy(s, size, tmp);
	IconvFree(d);

	Free(tmp);

	return UniStrLen(s);
}

// Calculate the size when the Unicode converted to string
UINT UnixCalcUniToStr(wchar_t *s)
{
	char *tmp;
	UINT tmp_size;
	UINT ret;
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	tmp_size = UniStrLen(s) * 5 + 10;
	tmp = ZeroMalloc(tmp_size);
	UnixUniToStr(tmp, tmp_size, s);

	ret = StrSize(tmp);
	Free(tmp);

	return ret;
}

// Converted a Unicode string to a string
UINT UnixUniToStr(char *str, UINT size, wchar_t *s)
{
	USHORT *tmp;
	char *inbuf;
	size_t insize;
	char *outbuf;
	char *outbuf_orig;
	size_t outsize;
	void *d;
	// Validate arguments
	if (str == NULL || s == NULL)
	{
		return 0;
	}

	// Convert a wchar_t string to sequence of 2-bytes first
	tmp = WideToUtf16(s);
	inbuf = (char *)tmp;
	insize = (UniStrLen(s) + 1) * 2;
	outsize = insize * 5 + 10;
	outbuf_orig = outbuf = ZeroMalloc(outsize);

	d = IconvWideToStr();
	if (d == (void *)-1)
	{
		StrCpy(str, size, "");
		Free(outbuf);
		Free(tmp);
		return 0;
	}

	if (iconv((iconv_t)d, (char **)&inbuf, (size_t *)&insize, (char **)&outbuf, (size_t *)&outsize) == (size_t)(-1))
	{
		Free(outbuf_orig);
		IconvFree(d);
		StrCpy(str, size, "");
		Free(tmp);
		return 0;
	}

	StrCpy(str, size, outbuf_orig);

	Free(outbuf_orig);
	IconvFree(d);
	Free(tmp);

	return StrLen(str);
}

// Converted the whcar_t to char
void *IconvWideToStrInternal()
{
	return (void *)iconv_open(charset, IsBigEndian() ? "UTF-16BE" : "UTF-16LE");
}

// Convert the char to a wchar_t
void *IconvStrToWideInternal()
{
	return (void *)iconv_open(IsBigEndian() ? "UTF-16BE" : "UTF-16LE", charset);
}

// Close the handle
int IconvFreeInternal(void *d)
{
	iconv_close((iconv_t)d);
	return 0;
}

void *IconvWideToStr()
{
	if (iconv_cache_wide_to_str == (void *)-1)
	{
		return (void *)-1;
	}

	Lock(iconv_lock);

	return iconv_cache_wide_to_str;
}

void *IconvStrToWide()
{
	if (iconv_cache_str_to_wide == (void *)-1)
	{
		return (void *)-1;
	}

	Lock(iconv_lock);

	return iconv_cache_str_to_wide;
}

int IconvFree(void *d)
{
	Unlock(iconv_lock);

	return 0;
}

// Get the character set that is currently used from the environment variable
void GetCurrentCharSet(char *name, UINT size)
{
	char tmp[MAX_SIZE];
	TOKEN_LIST *t;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	Zero(tmp, sizeof(tmp));
	if (GetEnv("LANG", tmp, sizeof(tmp)) == false || IsEmptyStr(tmp))
	{
		Zero(tmp, sizeof(tmp));
		if (GetEnv("LOCATION", tmp, sizeof(tmp)) == false || IsEmptyStr(tmp))
		{
			StrCpy(tmp, sizeof(tmp), "C");
		}
	}

	Trim(tmp);

	t = ParseToken(tmp, ".");
	if (t->NumTokens >= 2)
	{
		StrCpy(name, size, t->Token[1]);
	}
	else
	{
		if (t->NumTokens == 1)
		{
			StrCpy(name, size, t->Token[0]);
		}
		else
		{
			StrCpy(name, size, "eucJP");
		}
	}
	FreeToken(t);

	StrUpper(name);
}

#endif	// OS_UNIX

// Check whether the specified string is a space
bool UniIsEmptyStr(wchar_t *str)
{
	return IsEmptyUniStr(str);
}
bool IsEmptyUniStr(wchar_t *str)
{
	bool ret;
	wchar_t *s;
	// Validate arguments
	if (str == NULL)
	{
		return true;
	}

	s = UniCopyStr(str);

	UniTrim(s);
	if (UniStrLen(s) == 0)
	{
		ret = true;
	}
	else
	{
		ret = false;
	}

	Free(s);

	return ret;
}

// Check whether the specified string is a number
bool UniIsNum(wchar_t *str)
{
	char tmp[MAX_SIZE];

	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	UniToStrForSingleChars(tmp, sizeof(tmp), str);

	return IsNum(tmp);
}


// Empty Unicode token list
UNI_TOKEN_LIST *UniNullToken()
{
	UNI_TOKEN_LIST *ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	ret->Token = ZeroMalloc(0);

	return ret;
}

// Convert the token list to Unicode token list
UNI_TOKEN_LIST *TokenListToUniTokenList(TOKEN_LIST *src)
{
	UNI_TOKEN_LIST *ret;
	UINT i;
	// Validate arguments
	if (src == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	ret->NumTokens = src->NumTokens;
	ret->Token = ZeroMalloc(sizeof(wchar_t *) * ret->NumTokens);

	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = CopyStrToUni(src->Token[i]);
	}

	return ret;
}

// Convert a Unicode token list to a token list
TOKEN_LIST *UniTokenListToTokenList(UNI_TOKEN_LIST *src)
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
		ret->Token[i] = CopyUniToStr(src->Token[i]);
	}

	return ret;
}

// Unicode string copy
wchar_t *UniCopyStr(wchar_t *str)
{
	return CopyUniStr(str);
}

// Copy the token list
UNI_TOKEN_LIST *UniCopyToken(UNI_TOKEN_LIST *src)
{
	UNI_TOKEN_LIST *ret;
	UINT i;
	// Validate arguments
	if (src == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));
	ret->NumTokens = src->NumTokens;
	ret->Token = ZeroMalloc(sizeof(wchar_t *) * ret->NumTokens);
	for (i = 0;i < ret->NumTokens;i++)
	{
		ret->Token[i] = CopyUniStr(src->Token[i]);
	}

	return ret;
}

// Parse the command line string
UNI_TOKEN_LIST *UniParseCmdLine(wchar_t *str)
{
	UNI_TOKEN_LIST *t;
	LIST *o;
	UINT i, len, wp, mode;
	wchar_t c;
	wchar_t *tmp;
	bool ignore_space = false;
	// Validate arguments
	if (str == NULL)
	{
		// There is no token
		return UniNullToken();
	}

	o = NewListFast(NULL);
	tmp = Malloc(UniStrSize(str) + 32);

	wp = 0;
	mode = 0;

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		c = str[i];

		switch (mode)
		{
		case 0:
			// Mode to discover the next token
			if (c == L' ' || c == L'\t')
			{
				// Advance to the next character
			}
			else
			{
				// Start of the token
				if (c == L'\"')
				{
					if (str[i + 1] == L'\"')
					{
						// Regarded "" as a single " character
						tmp[wp++] = L'\"';
						i++;
					}
					else
					{
						// Single "(double-quote) enables the flag to ignore space
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
			if (ignore_space == false && (c == L' ' || c == L'\t'))
			{
				// End of the token
				tmp[wp++] = 0;
				wp = 0;

				Insert(o, UniCopyStr(tmp));
				mode = 0;
			}
			else
			{
				if (c == L'\"')
				{
					if (str[i + 1] == L'\"')
					{
						// Regarded "" as a single " character
						tmp[wp++] = L'\"';
						i++;
					}
					else
					{
						if (ignore_space == false)
						{
							// Single "(double-quote) enables the flag to ignore space
							ignore_space = true;
						}
						else
						{
							// Disable the flag to ignore space
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
		Insert(o, UniCopyStr(tmp));
	}

	Free(tmp);

	t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);
	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);

	return t;
}

// Convert Unicode string to 64bit integer
UINT64 UniToInt64(wchar_t *str)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	UniToStrForSingleChars(tmp, sizeof(tmp), str);

	return ToInt64(tmp);
}

// Convert the UTF string to a Unicode string
UINT UtfToUni(wchar_t *unistr, UINT size, char *utfstr)
{
	wchar_t *tmp;
	// Validate arguments
	if (unistr == NULL || utfstr == NULL)
	{
		UniStrCpy(unistr, size, L"");
		return 0;
	}

	tmp = CopyUtfToUni(utfstr);

	UniStrCpy(unistr, size, tmp);

	Free(tmp);

	return UniStrLen(unistr);
}

// Copy the UTF-8 string to a Unicode string
wchar_t *CopyUtfToUni(char *utfstr)
{
	UINT size;
	wchar_t *ret;
	UINT utfstr_len;
	// Validate arguments
	if (utfstr == NULL)
	{
		return NULL;
	}

	utfstr_len = StrLen(utfstr);

	size = CalcUtf8ToUni((BYTE *)utfstr, utfstr_len);
	ret = ZeroMalloc(size + sizeof(wchar_t));
	Utf8ToUni(ret, size, (BYTE *)utfstr, utfstr_len);

	return ret;
}

// Copy a Unicode string to ANSI string
char *CopyUniToStr(wchar_t *unistr)
{
	char *str;
	UINT str_size;
	// Validate arguments
	if (unistr == NULL)
	{
		return NULL;
	}

	str_size = CalcUniToStr(unistr);
	if (str_size == 0)
	{
		return CopyStr("");
	}
	str = Malloc(str_size);
	UniToStr(str, str_size, unistr);

	return str;
}

// Copy an ANSI string to a Unicode string
wchar_t *CopyStrToUni(char *str)
{
	wchar_t *uni;
	UINT uni_size;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	uni_size = CalcStrToUni(str);
	if (uni_size == 0)
	{
		return CopyUniStr(L"");
	}
	uni = Malloc(uni_size);
	StrToUni(uni, uni_size, str);

	return uni;
}

// Copy a Unicode string to UTF-8 string
char *CopyUniToUtf(wchar_t *unistr)
{
	UINT size;
	char *ret;
	// Validate arguments
	if (unistr == NULL)
	{
		return NULL;
	}

	size = CalcUniToUtf8(unistr);
	ret = ZeroMalloc(size + sizeof(char));

	UniToUtf8((char *)ret, size, unistr);

	return ret;
}

// Copy the Unicode string
wchar_t *CopyUniStr(wchar_t *str)
{
	UINT len;
	wchar_t *dst;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	len = UniStrLen(str);
	dst = Malloc((len + 1) * sizeof(wchar_t));
	UniStrCpy(dst, 0, str);

	return dst;
}

// Check whether the string is safe
bool IsSafeUniStr(wchar_t *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		if (IsSafeUniChar(str[i]) == false)
		{
			return false;
		}
	}
	if (str[0] == L' ')
	{
		return false;
	}
	if (len != 0)
	{
		if (str[len - 1] == L' ')
		{
			return false;
		}
	}
	return true;
}

// Check whether the character is safe
bool IsSafeUniChar(wchar_t c)
{
	UINT i, len;
	wchar_t *check_str =
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		L"abcdefghijklmnopqrstuvwxyz"
		L"0123456789"
		L" ()-_#%&.";

	len = UniStrLen(check_str);
	for (i = 0;i < len;i++)
	{
		if (c == check_str[i])
		{
			return true;
		}
	}
	return false;
}

// Convert Unicode string to ANSI string
UINT UniToStr(char *str, UINT size, wchar_t *s)
{
#ifdef	OS_WIN32
	UINT ret;
	char *tmp;
	UINT new_size;
	// Validate arguments
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	new_size = CalcUniToStr(s);
	if (new_size == 0)
	{
		if (size >= 1)
		{
			StrCpy(str, 0, "");
		}
		return 0;
	}
	tmp = Malloc(new_size);
	tmp[0] = 0;
	wcstombs(tmp, s, new_size);
	tmp[new_size - 1] = 0;
	ret = StrCpy(str, size, tmp);
	Free(tmp);

	return ret;
#else	// OS_WIN32
	return UnixUniToStr(str, size, s);
#endif	// OS_WIN32
}

// Get the required number of bytes to convert Unicode string to the ANSI string
UINT CalcUniToStr(wchar_t *s)
{
#ifdef	OS_WIN32
	UINT ret;
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	ret = (UINT)wcstombs(NULL, s, UniStrLen(s));
	if (ret == (UINT)-1)
	{
		return 0;
	}

	return ret + 1;
#else	// OS_WIN32
	return UnixCalcUniToStr(s);
#endif	// OS_WIN32
}

// Converted an ANSI string to a Unicode string
UINT StrToUni(wchar_t *s, UINT size, char *str)
{
#ifdef	OS_WIN32
	UINT ret;
	wchar_t *tmp;
	UINT new_size;
	// Validate arguments
	if (s == NULL || str == NULL)
	{
		return 0;
	}

	new_size = CalcStrToUni(str);
	if (new_size == 0)
	{
		if (size >= 2)
		{
			UniStrCpy(s, 0, L"");
		}
		return 0;
	}
	tmp = Malloc(new_size);
	tmp[0] = 0;
	mbstowcs(tmp, str, StrLen(str));
	tmp[(new_size - 1) / sizeof(wchar_t)] = 0;
	ret = UniStrCpy(s, size, tmp);
	Free(tmp);

	return ret;
#else	// OS_WIN32
	return UnixStrToUni(s, size, str);
#endif	// OS_WIN32
}

// Get the required buffer size for converting an ANSI string to an Unicode string
UINT CalcStrToUni(char *str)
{
#ifdef	OS_WIN32
	UINT ret;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	ret = (UINT)mbstowcs(NULL, str, StrLen(str));
	if (ret == (UINT)-1)
	{
		return 0;
	}

	return (ret + 1) * sizeof(wchar_t);
#else	// OS_WIN32
	return UnixCalcStrToUni(str);
#endif	// OS_WIN32
}

// Convert the UTF-8 strings to a Unicode string
UINT Utf8ToUni(wchar_t *s, UINT size, BYTE *u, UINT u_size)
{
	UINT i, wp, num;
	// Validate arguments
	if (s == NULL || u == NULL)
	{
		return 0;
	}
	if (size == 0)
	{
		size = 0x3fffffff;
	}
	if (u_size == 0)
	{
		u_size = StrLen((char *)u);
	}

	i = 0;
	wp = 0;
	num = 0;
	while (true)
	{
		UINT type;
		wchar_t c = 0;
		BYTE c1, c2;

		type = GetUtf8Type(u, u_size, i);
		if (type == 0)
		{
			break;
		}
		switch (type)
		{
		case 1:
			c1 = 0;
			c2 = u[i];
			break;
		case 2:
			c1 = (((u[i] & 0x1c) >> 2) & 0x07);
			c2 = (((u[i] & 0x03) << 6) & 0xc0) | (u[i + 1] & 0x3f);
			break;
		case 3:
			c1 = ((((u[i] & 0x0f) << 4) & 0xf0)) | (((u[i + 1] & 0x3c) >> 2) & 0x0f);
			c2 = (((u[i + 1] & 0x03) << 6) & 0xc0) | (u[i + 2] & 0x3f);
			break;
		}
		i += type;

		if (IsBigEndian())
		{
			if (sizeof(wchar_t) == 2)
			{
				((BYTE *)&c)[0] = c1;
				((BYTE *)&c)[1] = c2;
			}
			else
			{
				((BYTE *)&c)[2] = c1;
				((BYTE *)&c)[3] = c2;
			}
		}
		else
		{
			((BYTE *)&c)[0] = c2;
			((BYTE *)&c)[1] = c1;
		}

		if (wp < ((size / sizeof(wchar_t)) - 1))
		{
			s[wp++] = c;
			num++;
		}
		else
		{
			break;
		}
	}

	if (wp < (size / sizeof(wchar_t)))
	{
		s[wp++] = 0;
	}

	return num;
}

// Get the buffer size when converted UTF-8 to Unicode
UINT CalcUtf8ToUni(BYTE *u, UINT u_size)
{
	// Validate arguments
	if (u == NULL)
	{
		return 0;
	}
	if (u_size == 0)
	{
		u_size = StrLen((char *)u);
	}

	return (Utf8Len(u, u_size) + 1) * sizeof(wchar_t);
}

// Get the number of characters in UTF-8 string
UINT Utf8Len(BYTE *u, UINT size)
{
	UINT i, num;
	// Validate arguments
	if (u == NULL)
	{
		return 0;
	}
	if (size == 0)
	{
		size = StrLen((char *)u);
	}

	i = num = 0;
	while (true)
	{
		UINT type;

		type = GetUtf8Type(u, size, i);
		if (type == 0)
		{
			break;
		}
		i += type;
		num++;
	}

	return num;
}

// Convert an Unicode string to UTF-8 string
UINT UniToUtf8(BYTE *u, UINT size, wchar_t *s)
{
	UINT i, len, type, wp;
	// Validate arguments
	if (u == NULL || s == NULL)
	{
		return 0;
	}
	if (size == 0)
	{
		size = 0x3fffffff;
	}

	len = UniStrLen(s);
	wp = 0;
	for (i = 0;i < len;i++)
	{
		BYTE c1, c2;
		wchar_t c = s[i];

		if (IsBigEndian())
		{
			if (sizeof(wchar_t) == 2)
			{
				c1 = ((BYTE *)&c)[0];
				c2 = ((BYTE *)&c)[1];
			}
			else
			{
				c1 = ((BYTE *)&c)[2];
				c2 = ((BYTE *)&c)[3];
			}
		}
		else
		{
			c1 = ((BYTE *)&c)[1];
			c2 = ((BYTE *)&c)[0];
		}

		type = GetUniType(s[i]);
		switch (type)
		{
		case 1:
			if (wp < size)
			{
				u[wp++] = c2;
			}
			break;
		case 2:
			if (wp < size)
			{
				u[wp++] = 0xc0 | (((((c1 & 0x07) << 2) & 0x1c)) | (((c2 & 0xc0) >> 6) & 0x03));
			}
			if (wp < size)
			{
				u[wp++] = 0x80 | (c2 & 0x3f);
			}
			break;
		case 3:
			if (wp < size)
			{
				u[wp++] = 0xe0 | (((c1 & 0xf0) >> 4) & 0x0f);
			}
			if (wp < size)
			{
				u[wp++] = 0x80 | (((c1 & 0x0f) << 2) & 0x3c) | (((c2 & 0xc0) >> 6) & 0x03);
			}
			if (wp < size)
			{
				u[wp++] = 0x80 | (c2 & 0x3f);
			}
			break;
		}
	}
	if (wp < size)
	{
		u[wp] = 0;
	}
	return wp;
}

// Calculating the length of the string when converting Unicode string to UTF-8 string
UINT CalcUniToUtf8(wchar_t *s)
{
	UINT i, len, size;
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	size = 0;
	len = UniStrLen(s);
	for (i = 0;i < len;i++)
	{
		size += GetUniType(s[i]);
	}

	return size;
}

// Get the number of bytes of a first character of the offset address of the UTF-8 string that starts with s
UINT GetUtf8Type(BYTE *s, UINT size, UINT offset)
{
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}
	if ((offset + 1) > size)
	{
		return 0;
	}
	if ((s[offset] & 0x80) == 0)
	{
		// 1 byte
		return 1;
	}
	if ((s[offset] & 0x20) == 0)
	{
		// 2 bytes
		if ((offset + 2) > size)
		{
			return 0;
		}
		return 2;
	}
	// 3 bytes
	if ((offset + 3) > size)
	{
		return 0;
	}
	return 3;
}

// Type of the converted character 'c' to UTF-8 (in bytes)
UINT GetUniType(wchar_t c)
{
	BYTE c1, c2;

	if (IsBigEndian())
	{
		if (sizeof(wchar_t) == 2)
		{
			c1 = ((BYTE *)&c)[0];
			c2 = ((BYTE *)&c)[1];
		}
		else
		{
			c1 = ((BYTE *)&c)[2];
			c2 = ((BYTE *)&c)[3];
		}
	}
	else
	{
		c1 = ((BYTE *)&c)[1];
		c2 = ((BYTE *)&c)[0];
	}

	if (c1 == 0)
	{
		if (c2 <= 0x7f)
		{
			// 1 byte
			return 1;
		}
		else
		{
			// 2 bytes
			return 2;
		}
	}
	if ((c1 & 0xf8) == 0)
	{
		// 2 bytes
		return 2;
	}
	// 3 bytes
	return 3;
}

// String replacing (case-sensitive)
UINT UniReplaceStr(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword)
{
	return UniReplaceStrEx(dst, size, string, old_keyword, new_keyword, true);
}

// Replacement of string
UINT UniReplaceStrEx(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive)
{
	UINT i, j, num, len_string, len_old, len_new, len_ret, wp;
	wchar_t *ret;
	// Validate arguments
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	// Get the length of the string
	len_string = UniStrLen(string);
	len_old = UniStrLen(old_keyword);
	len_new = UniStrLen(new_keyword);

	// Get the final string length
	len_ret = UniCalcReplaceStrEx(string, old_keyword, new_keyword, case_sensitive);
	// Memory allocation
	ret = Malloc((len_ret + 1) * sizeof(wchar_t));
	ret[len_ret] = 0;

	// Search and Replace
	i = j = num = wp = 0;
	while (true)
	{
		i = UniSearchStrEx(string, old_keyword, i, case_sensitive);
		if (i == INFINITE)
		{
			Copy(&ret[wp], &string[j], (len_string - j) * sizeof(wchar_t));
			wp += len_string - j;
			break;
		}
		num++;
		Copy(&ret[wp], &string[j], (i - j) * sizeof(wchar_t));
		wp += i - j;
		Copy(&ret[wp], new_keyword, len_new * sizeof(wchar_t));
		wp += len_new;
		i += len_old;
		j = i;
	}

	// Copy of the search results
	UniStrCpy(dst, size, ret);

	// Memory release
	Free(ret);

	return num;
}

// Calculate the length of the result of string replacement
UINT UniCalcReplaceStrEx(wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive)
{
	UINT i, num;
	UINT len_string, len_old, len_new;
	// Validate arguments
	if (string == NULL || old_keyword == NULL || new_keyword == NULL)
	{
		return 0;
	}

	// Get the length of the string
	len_string = UniStrLen(string);
	len_old = UniStrLen(old_keyword);
	len_new = UniStrLen(new_keyword);

	if (len_old == len_new)
	{
		return len_string;
	}

	// Search process
	num = 0;
	i = 0;
	while (true)
	{
		i = UniSearchStrEx(string, old_keyword, i, case_sensitive);
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
UINT UniSearchStr(wchar_t *string, wchar_t *keyword, UINT start)
{
	return UniSearchStrEx(string, keyword, start, true);
}

// Return the position of the first found of the keyword in the string 
// (Found in first character: returns 0, Not found: returns INFINITE)
UINT UniSearchStrEx(wchar_t *string, wchar_t *keyword, UINT start, bool case_sensitive)
{
	UINT len_string, len_keyword;
	UINT i;
	wchar_t *cmp_string, *cmp_keyword;
	bool found;
	// Validate arguments
	if (string == NULL || keyword == NULL)
	{
		return INFINITE;
	}

	// Get the length of string
	len_string = UniStrLen(string);
	if (len_string <= start)
	{
		// Value of start is invalid
		return INFINITE;
	}

	// Get the length of the keyword
	len_keyword = UniStrLen(keyword);
	if (len_keyword == 0)
	{
		// There is no keyword
		return INFINITE;
	}

	if (len_string < len_keyword)
	{
		return INFINITE;
	}

	if (len_string == len_keyword)
	{
		if (case_sensitive)
		{
			if (UniStrCmp(string, keyword) == 0)
			{
				return 0;
			}
			else
			{
				return INFINITE;
			}
		}
		else
		{
			if (UniStrCmpi(string, keyword) == 0)
			{
				return 0;
			}
			else
			{
				return INFINITE;
			}
		}
	}

	if (case_sensitive)
	{
		cmp_string = string;
		cmp_keyword = keyword;
	}
	else
	{
		cmp_string = Malloc((len_string + 1) * sizeof(wchar_t));
		UniStrCpy(cmp_string, (len_string + 1) * sizeof(wchar_t), string);
		cmp_keyword = Malloc((len_keyword + 1) * sizeof(wchar_t));
		UniStrCpy(cmp_keyword, (len_keyword + 1) * sizeof(wchar_t), keyword);
		UniStrUpper(cmp_string);
		UniStrUpper(cmp_keyword);
	}

	// Search
	found = false;
	for (i = start;i < (len_string - len_keyword + 1);i++)
	{
		// Compare
		if (!wcsncmp(&cmp_string[i], cmp_keyword, len_keyword))
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

// Release of the token list
void UniFreeToken(UNI_TOKEN_LIST *tokens)
{
	UINT i;
	if (tokens == NULL)
	{
		return;
	}
	for (i = 0;i < tokens->NumTokens;i++)
	{
		Free(tokens->Token[i]);
	}
	Free(tokens->Token);
	Free(tokens);
}

// Parse token for UNIX
UNI_TOKEN_LIST *UnixUniParseToken(wchar_t *src, wchar_t *separator)
{
	UNI_TOKEN_LIST *ret;
	TOKEN_LIST *t;
	char *src_s;
	char *sep_s;

	// Validate arguments
	if (src == NULL || separator == NULL)
	{
		ret = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
		ret->Token = ZeroMalloc(0);
		return ret;
	}

	src_s = CopyUniToStr(src);
	sep_s = CopyUniToStr(separator);

	t = ParseToken(src_s, sep_s);

	ret = TokenListToUniTokenList(t);
	FreeToken(t);

	Free(src_s);
	Free(sep_s);

	return ret;
}

// Get a standard token delimiter
wchar_t *UniDefaultTokenSplitChars()
{
	return L" ,\t\r\n";
}

// Check whether the specified character is in the string
bool UniIsCharInStr(wchar_t *str, wchar_t c)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	len = UniStrLen(str);
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
UNI_TOKEN_LIST *UniParseTokenWithNullStr(wchar_t *str, wchar_t *split_chars)
{
	LIST *o;
	UINT i, len;
	BUF *b;
	wchar_t zero = 0;
	UNI_TOKEN_LIST *t;
	// Validate arguments
	if (str == NULL)
	{
		return UniNullToken();
	}
	if (split_chars == NULL)
	{
		split_chars = UniDefaultTokenSplitChars();
	}

	b = NewBuf();
	o = NewListFast(NULL);

	len = UniStrLen(str);

	for (i = 0;i < (len + 1);i++)
	{
		wchar_t c = str[i];
		bool flag = UniIsCharInStr(split_chars, c);

		if (c == L'\0')
		{
			flag = true;
		}

		if (flag == false)
		{
			WriteBuf(b, &c, sizeof(wchar_t));
		}
		else
		{
			WriteBuf(b, &zero, sizeof(wchar_t));

			Insert(o, UniCopyStr((wchar_t *)b->Buf));
			ClearBuf(b);
		}
	}

	t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);
	FreeBuf(b);

	return t;
}

// Cut out the token from string (Ignore blanks between delimiters)
UNI_TOKEN_LIST *UniParseTokenWithoutNullStr(wchar_t *str, wchar_t *split_chars)
{
	LIST *o;
	UINT i, len;
	bool last_flag;
	BUF *b;
	wchar_t zero = 0;
	UNI_TOKEN_LIST *t;
	// Validate arguments
	if (str == NULL)
	{
		return UniNullToken();
	}
	if (split_chars == NULL)
	{
		split_chars = UniDefaultTokenSplitChars();
	}

	b = NewBuf();
	o = NewListFast(NULL);

	len = UniStrLen(str);
	last_flag = false;

	for (i = 0;i < (len + 1);i++)
	{
		wchar_t c = str[i];
		bool flag = UniIsCharInStr(split_chars, c);

		if (c == L'\0')
		{
			flag = true;
		}

		if (flag == false)
		{
			WriteBuf(b, &c, sizeof(wchar_t));
		}
		else
		{
			if (last_flag == false)
			{
				WriteBuf(b, &zero, sizeof(wchar_t));

				if ((UniStrLen((wchar_t *)b->Buf)) != 0)
				{
					Insert(o, UniCopyStr((wchar_t *)b->Buf));
				}
				ClearBuf(b);
			}
		}

		last_flag = flag;
	}

	t = ZeroMalloc(sizeof(UNI_TOKEN_LIST));
	t->NumTokens = LIST_NUM(o);
	t->Token = ZeroMalloc(sizeof(wchar_t *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		t->Token[i] = LIST_DATA(o, i);
	}

	ReleaseList(o);
	FreeBuf(b);

	return t;
}

// Parse the token
UNI_TOKEN_LIST *UniParseToken(wchar_t *src, wchar_t *separator)
{
	// 2020/7/20 remove strtok by dnobori
	return UniParseTokenWithoutNullStr(src, separator);
}

// Get a line from standard input
bool UniGetLine(wchar_t *str, UINT size)
{
#ifdef	OS_WIN32
	return UniGetLineWin32(str, size);
#else	// OS_WIN32
	return UniGetLineUnix(str, size);
#endif	// OS_WIN32
}
void AnsiGetLineUnix(char *str, UINT size)
{
	// Validate arguments
	if (str == NULL)
	{
		char tmp[MAX_SIZE];
		fgets(tmp, sizeof(tmp) - 1, stdin);
		return;
	}
	if (size <= 1)
	{
		return;
	}

	// Read data from standard input
	fgets(str, (int)(size - 1), stdin);

	TrimCrlf(str);
}
bool UniGetLineUnix(wchar_t *str, UINT size)
{
	char *str_a;
	UINT str_a_size = size;
	if (str == NULL || size < sizeof(wchar_t))
	{
		return false;
	}
	if (str_a_size >= 0x7fffffff)
	{
		str_a_size = MAX_SIZE;
	}
	str_a_size *= 2;

	str_a = ZeroMalloc(str_a_size);

	AnsiGetLineUnix(str_a, str_a_size);

	StrToUni(str, size, str_a);

	Free(str_a);

	return true;
}
bool UniGetLineWin32(wchar_t *str, UINT size)
{
	bool ret = false;

#ifdef	OS_WIN32
	ret = Win32InputW(str, size);
#endif	// OS_WIN32

	return ret;
}

// Remove '\r\n' at the end
void UniTrimCrlf(wchar_t *str)
{
	UINT len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);
	if (len == 0)
	{
		return;
	}

	if (str[len - 1] == L'\n')
	{
		if (len >= 2 && str[len - 2] == L'\r')
		{
			str[len - 2] = 0;
		}
		str[len - 1] = 0;
	}
	else if(str[len - 1] == L'\r')
	{
		str[len - 1] = 0;
	}
}

// Remove white space of the both side of the string
void UniTrim(wchar_t *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	UniTrimLeft(str);
	UniTrimRight(str);
}

// Remove white space on the right side of the string
void UniTrimRight(wchar_t *str)
{
	wchar_t *buf, *tmp;
	UINT len, i, wp, wp2;
	bool flag;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[len - 1] != L' ' && str[len - 1] != L'\t')
	{
		return;
	}

	buf = Malloc((len + 1) * sizeof(wchar_t));
	tmp = Malloc((len + 1) * sizeof(wchar_t));
	flag = false;
	wp = wp2 = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != L' ' && str[i] != L'\t')
		{
			Copy(&buf[wp], tmp, wp2 * sizeof(wchar_t));
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
	UniStrCpy(str, 0, buf);
	Free(buf);
	Free(tmp);
}

// Remove white space from the left side of the string
void UniTrimLeft(wchar_t *str)
{
	wchar_t *buf;
	UINT len, i, wp;
	bool flag;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}
	len = UniStrLen(str);
	if (len == 0)
	{
		return;
	}
	if (str[0] != L' ' && str[0] != L'\t')
	{
		return;
	}

	buf = Malloc((len + 1) * sizeof(wchar_t));
	flag = false;
	wp = 0;
	for (i = 0;i < len;i++)
	{
		if (str[i] != L' ' && str[i] != L'\t')
		{
			flag = true;
		}
		if (flag)
		{
			buf[wp++] = str[i];
		}
	}
	buf[wp] = 0;
	UniStrCpy(str, 0, buf);
	Free(buf);
}

// Convert a signed integer to a string
void UniToStri(wchar_t *str, int i)
{
	UniFormat(str, 0, L"%i", i);
}

// Convert an integer to a string
void UniToStru(wchar_t *str, UINT i)
{
	UniFormat(str, 0, L"%u", i);
}

// Convert a string to an integer
UINT UniToInt(wchar_t *str)
{
	char tmp[128];
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	UniToStrForSingleChars(tmp, sizeof(tmp), str);

	return ToInti(tmp);
}

// Convert only single-byte characters in the Unicode string to a char string
void UniToStrForSingleChars(char *dst, UINT dst_size, wchar_t *src)
{
	UINT i;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	for (i = 0;i < UniStrLen(src) + 1;i++)
	{
		wchar_t s = src[i];
		char d;

		if (s == 0)
		{
			d = 0;
		}
		else if (s <= 0xff)
		{
			d = (char)s;
		}
		else
		{
			d = ' ';
		}

		dst[i] = d;
	}
}

// Get lines from a string
UNI_TOKEN_LIST *UniGetLines(wchar_t *str)
{
	UINT i, len;
	BUF *b = NULL;
	LIST *o;
	UNI_TOKEN_LIST *ret;
	// Validate arguments
	if (str == NULL)
	{
		return UniNullToken();
	}

	o = NewListFast(NULL);

	len = UniStrLen(str);

	b = NewBuf();

	for (i = 0;i < len;i++)
	{
		wchar_t c = str[i];
		bool f = false;

		if (c == L'\r')
		{
			if (str[i + 1] == L'\n')
			{
				i++;
			}
			f = true;
		}
		else if (c == L'\n')
		{
			f = true;
		}

		if (f)
		{
			wchar_t zero = 0;
			wchar_t *s;
			WriteBuf(b, &zero, sizeof(wchar_t));

			s = (wchar_t *)b->Buf;

			Add(o, UniCopyStr(s));

			ClearBuf(b);
		}
		else
		{
			WriteBuf(b, &c, sizeof(wchar_t));
		}
	}

	if (true)
	{
		wchar_t zero = 0;
		wchar_t *s;
		WriteBuf(b, &zero, sizeof(wchar_t));

		s = (wchar_t *)b->Buf;

		Add(o, UniCopyStr(s));

		ClearBuf(b);
	}

	FreeBuf(b);

	ret = UniListToTokenList(o);

	UniFreeStrList(o);

	return ret;
}

// Display the string on the screen
void UniPrintStr(wchar_t *string)
{
	// Validate arguments
	if (string == NULL)
	{
		return;
	}

#ifdef	OS_UNIX
	if (true)
	{
		char *str = CopyUniToStr(string);

		if (str != NULL)
		{
			fputs(str, stdout);
		}
		else
		{
			fputs("", stdout);
		}

		Free(str);
	}
#else	// OS_UNIX
	Win32PrintW(string);
#endif	// OS_UNIX
}

// Display a string with arguments
void UniPrintArgs(wchar_t *fmt, va_list args)
{
	wchar_t *str;
	// Validate arguments
	if (fmt == NULL)
	{
		return;
	}

	str = InternalFormatArgs(fmt, args, false);

	UniPrintStr(str);

	Free(str);
}

// Display the string
void UniPrint(wchar_t *fmt, ...)
{
	va_list args;
	// Validate arguments
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniPrintArgs(fmt, args);
	va_end(args);
}

// Display debug string with arguments
void UniDebugArgs(wchar_t *fmt, va_list args)
{
	if (g_debug == false)
	{
		return;
	}

	UniPrintArgs(fmt, args);
}

// Display a debug string
void UniDebug(wchar_t *fmt, ...)
{
	va_list args;
	// Validate arguments
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniDebugArgs(fmt, args);
	va_end(args);
}

// Format a string (argument list)
void UniFormatArgs(wchar_t *buf, UINT size, wchar_t *fmt, va_list args)
{
	wchar_t *ret;
	// Validate arguments
	if (buf == NULL || fmt == NULL)
	{
		return;
	}
	if (size == 1)
	{
		return;
	}

	// KS
	KS_INC(KS_FORMAT_COUNT);

	ret = InternalFormatArgs(fmt, args, false);

	UniStrCpy(buf, size, ret);

	Free(ret);
}

// Format the string, and copy it
wchar_t *CopyUniFormat(wchar_t *fmt, ...)
{
	wchar_t *ret, *str;
	UINT size;
	va_list args;
	// Validate arguments
	if (fmt == NULL)
	{
		return NULL;
	}

	size = MAX(UniStrSize(fmt) * 10, MAX_SIZE * 10);
	str = Malloc(size);

	va_start(args, fmt);
	UniFormatArgs(str, size, fmt, args);

	ret = UniCopyStr(str);
	Free(str);
	va_end(args);

	return ret;
}

// Format the string
void UniFormat(wchar_t *buf, UINT size, wchar_t *fmt, ...)
{
	va_list args;
	// Validate arguments
	if (buf == NULL || fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniFormatArgs(buf, size, fmt, args);
	va_end(args);
}

// Flexible string comparison
int UniSoftStrCmp(wchar_t *str1, wchar_t *str2)
{
	UINT ret;
	wchar_t *tmp1, *tmp2;
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

	tmp1 = CopyUniStr(str1);
	tmp2 = CopyUniStr(str2);

	UniTrim(tmp1);
	UniTrim(tmp2);

	ret = UniStrCmpi(tmp1, tmp2);

	Free(tmp1);
	Free(tmp2);

	return ret;
}

// Compare the strings in case-insensitive mode
int UniStrCmpi(wchar_t *str1, wchar_t *str2)
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
		wchar_t c1, c2;
		c1 = UniToUpper(str1[i]);
		c2 = UniToUpper(str2[i]);
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
int UniStrCmp(wchar_t *str1, wchar_t *str2)
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

	return wcscmp(str1, str2);
}

// Uncapitalize the string
void UniStrLower(wchar_t *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = UniToLower(str[i]);
	}
}

// Capitalize the string
void UniStrUpper(wchar_t *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	len = UniStrLen(str);
	for (i = 0;i < len;i++)
	{
		str[i] = UniToUpper(str[i]);
	}
}

// Uncapitalize a character
wchar_t UniToLower(wchar_t c)
{
	if (c >= L'A' && c <= L'Z')
	{
		c += L'a' - L'A';
	}

	return c;
}

// Capitalize a character
wchar_t UniToUpper(wchar_t c)
{
	if (c >= L'a' && c <= L'z')
	{
		c -= L'a' - L'A';
	}

	return c;
}

// String concatenation
UINT UniStrCat(wchar_t *dst, UINT size, wchar_t *src)
{
	UINT len1, len2, len_test;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return 0;
	}
	if (size != 0 && size < sizeof(wchar_t))
	{
		return 0;
	}
	if (size == sizeof(wchar_t))
	{
		wcscpy(dst, L"");
		return 0;
	}
	if (size == 0)
	{
		// Ignore the length
		size = 0x3fffffff;
	}

	len1 = UniStrLen(dst);
	len2 = UniStrLen(src);
	len_test = len1 + len2 + 1;
	if (len_test > (size / sizeof(wchar_t)))
	{
		if (len2 <= (len_test - (size / sizeof(wchar_t))))
		{
			return 0;
		}
		len2 -= len_test - (size / sizeof(wchar_t));
	}
	Copy(&dst[len1], src, len2 * sizeof(wchar_t));
	dst[len1 + len2] = 0;

	return len1 + len2;
}

// String copy
UINT UniStrCpy(wchar_t *dst, UINT size, wchar_t *src)
{
	UINT len;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		if (src == NULL && dst != NULL)
		{
			if (size >= sizeof(wchar_t))
			{
				dst[0] = L'\0';
			}
		}
		return 0;
	}
	if (dst == src)
	{
		return UniStrLen(src);
	}
	if (size != 0 && size < sizeof(wchar_t))
	{
		return 0;
	}
	if (size == sizeof(wchar_t))
	{
		wcscpy(dst, L"");
		return 0;
	}
	if (size == 0)
	{
		// Ignore the length
		size = 0x3fffffff;
	}

	// Check the length
	len = UniStrLen(src);
	if (len <= (size / sizeof(wchar_t) - 1))
	{
		Copy(dst, src, (len + 1) * sizeof(wchar_t));
	}
	else
	{
		len = size / sizeof(wchar_t) - 1;
		Copy(dst, src, len * sizeof(wchar_t));
		dst[len] = 0;
	}

	return len;
}

// Get the buffer size needed to store the string
UINT UniStrSize(wchar_t *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	return (UniStrLen(str) + 1) * sizeof(wchar_t);
}

// Get the length of the string
UINT UniStrLen(wchar_t *str)
{
	UINT i;
	// Validate arguments
	if (str == NULL)
	{
		return 0;
	}

	i = 0;
	while (true)
	{
		if (str[i] == 0)
		{
			break;
		}
		i++;
	}

	return i;
}

