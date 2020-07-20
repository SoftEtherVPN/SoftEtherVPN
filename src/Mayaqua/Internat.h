// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


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
UINT UniStrCat(wchar_t *dst, UINT size, wchar_t *src);
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
void UniToStri(wchar_t *str, int i);
void UniToStru(wchar_t *str, UINT i);
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
UINT UniSearchStr(wchar_t *string, wchar_t *keyword, UINT start);
UINT UniCalcReplaceStrEx(wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive);
UINT UniReplaceStrEx(wchar_t *dst, UINT size, wchar_t *string, wchar_t *old_keyword, wchar_t *new_keyword, bool case_sensitive);
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
bool IsSafeUniStr(wchar_t *str);
bool IsSafeUniChar(wchar_t c);
wchar_t *CopyUniStr(wchar_t *str);
wchar_t *CopyStrToUni(char *str);
UINT UtfToUni(wchar_t *unistr, UINT size, char *utfstr);
char *CopyUniToUtf(wchar_t *unistr);
char *CopyUniToStr(wchar_t *unistr);
wchar_t *CopyUtfToUni(char *utfstr);
UINT64 UniToInt64(wchar_t *str);
UNI_TOKEN_LIST *UniParseCmdLine(wchar_t *str);
UNI_TOKEN_LIST *UniCopyToken(UNI_TOKEN_LIST *src);
wchar_t *UniCopyStr(wchar_t *str);
TOKEN_LIST *UniTokenListToTokenList(UNI_TOKEN_LIST *src);
UNI_TOKEN_LIST *TokenListToUniTokenList(TOKEN_LIST *src);
UNI_TOKEN_LIST *UniNullToken();
bool UniIsNum(wchar_t *str);
bool IsEmptyUniStr(wchar_t *str);
bool UniIsEmptyStr(wchar_t *str);
void InitInternational();
void FreeInternational();
USHORT *WideToUtf16(wchar_t *str);
wchar_t *Utf16ToWide(USHORT *str);
wchar_t *InternalFormatArgs(wchar_t *fmt, va_list args, bool ansi_mode);
UINT UniStrWidth(wchar_t *str);
UNI_TOKEN_LIST *UnixUniParseToken(wchar_t *src, wchar_t *separator);
void UniToStr3(wchar_t *str, UINT size, UINT64 value);
bool UniEndWith(wchar_t *str, wchar_t *key);
bool UniStartWith(wchar_t *str, wchar_t *key);
wchar_t *UniNormalizeCrlf(wchar_t *str);
void UniFreeStrList(LIST *o);
UNI_TOKEN_LIST *UniListToTokenList(LIST *o);
bool UniIsSafeChar(wchar_t c);
BUF *UniStrToBin(wchar_t *str);
bool UniInStr(wchar_t *str, wchar_t *keyword);
bool UniInStrEx(wchar_t *str, wchar_t *keyword, bool case_sensitive);
void ClearUniStr(wchar_t *str, UINT str_size);
bool UniInChar(wchar_t *string, wchar_t c);
UNI_TOKEN_LIST *UniGetLines(wchar_t *str);
wchar_t *UniDefaultTokenSplitChars();
bool UniIsCharInStr(wchar_t *str, wchar_t c);
UNI_TOKEN_LIST *UniParseTokenWithNullStr(wchar_t *str, wchar_t *split_chars);
UNI_TOKEN_LIST *UniParseTokenWithoutNullStr(wchar_t *str, wchar_t *split_chars);


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



