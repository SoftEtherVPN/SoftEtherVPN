// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Str.h
// Header of Str.c

#ifndef	STR_H
#define	STR_H

// String token
struct TOKEN_LIST
{
	UINT NumTokens;
	char **Token;
};

// INI_ENTRY
struct INI_ENTRY
{
	char *Key;
	char *Value;
	wchar_t *UnicodeValue;
};

// Function prototype
UINT StrLen(char *str);
UINT StrSize(char *str);
bool StrCheckLen(char *str, UINT len);
UINT StrCpy(char *dst, UINT size, char *src);
UINT StrCpyAllowOverlap(char *dst, UINT size, char *src);
UINT StrCat(char *dst, UINT size, char *src);
UINT StrCatLeft(char *dst, UINT size, char *src);
char ToLower(char c);
char ToUpper(char c);
void StrUpper(char *str);
void StrLower(char *str);
int StrCmp(char *str1, char *str2);
int StrCmpi(char *str1, char *str2);
void FormatArgs(char *buf, UINT size, char *fmt, va_list args);
void Format(char *buf, UINT size, char *fmt, ...);
void Print(char *fmt, ...);
void PrintArgs(char *fmt, va_list args);
void PrintStr(char *str);
void Debug(char *fmt, ...);
void DebugArgs(char *fmt, va_list args);
UINT ToInt(char *str);
bool ToBool(char *str);
int ToInti(char *str);
void ToStr(char *str, UINT i);
void TrimCrlf(char *str);
void TrimQuotes(char *str);
void Trim(char *str);
void TrimRight(char *str);
void TrimLeft(char *str);
bool GetLine(char *str, UINT size);
void FreeToken(TOKEN_LIST *tokens);
bool IsInToken(TOKEN_LIST *t, char *str);
TOKEN_LIST *ParseToken(char *src, char *separator);
void InitStringLibrary();
void FreeStringLibrary();
bool CheckStringLibrary();
UINT SearchStrEx(char *string, char *keyword, UINT start, bool case_sensitive);
UINT SearchStr(char *string, char *keyword, UINT start);
UINT CalcReplaceStrEx(char *string, char *old_keyword, char *new_keyword, bool case_sensitive);
UINT ReplaceStrEx(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword, bool case_sensitive);
UINT ReplaceStr(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword);
UINT ReplaceStri(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword);
bool IsPrintableAsciiChar(char c);
void EnPrintableAsciiStr(char *str, char replace);
bool IsSafeChar(char c);
bool IsSafeStr(char *str);
void EnSafeStr(char *str, char replace);
void EnSafeHttpHeaderValueStr(char *str, char replace);
void TruncateCharFromStr(char *str, char replace);
char *CopyStr(char *str);
void BinToStr(char *str, UINT str_size, void *data, UINT data_size);
void BinToStrW(wchar_t *str, UINT str_size, void *data, UINT data_size);
void PrintBin(void *data, UINT size);
bool StartWith(char *str, char *key);
bool EndWith(char *str, char *key);
UINT64 ToInt64(char *str);
void ToStr64(char *str, UINT64 value);
TOKEN_LIST *ParseCmdLine(char *str);
TOKEN_LIST *CopyToken(TOKEN_LIST *src);
TOKEN_LIST *NullToken();
bool IsNum(char *str);
LIST *StrToStrList(char *str, UINT size);
void FreeStrList(LIST *o);
TOKEN_LIST *ListToTokenList(LIST *o);
bool IsEmptyStr(char *str);
void BinToStrEx(char *str, UINT str_size, void *data, UINT data_size);
void BinToStrEx2(char *str, UINT str_size, void *data, UINT data_size, char padding_char);
char *CopyBinToStrEx(void *data, UINT data_size);
char *CopyBinToStr(void *data, UINT data_size);
BUF *StrToBin(char *str);
void MacToStr(char *str, UINT size, UCHAR *mac_address);
void ToStr3(char *str, UINT size, UINT64 v);
void ToStrByte(char *str, UINT size, UINT64 v);
void ToStrByte1000(char *str, UINT size, UINT64 v);
TOKEN_LIST *UniqueToken(TOKEN_LIST *t);
bool IsAllUpperStr(char *str);
UINT StrWidth(char *str);
char *MakeCharArray(char c, UINT count);
void MakeCharArray2(char *str, char c, UINT count);
bool StrToMac(UCHAR *mac_address, char *str);
bool IsSplitChar(char c, char *split_str);
bool GetKeyAndValue(char *str, char *key, UINT key_size, char *value, UINT value_size, char *split_str);
LIST *ReadIni(BUF *b);
INI_ENTRY *GetIniEntry(LIST *o, char *key);
void FreeIni(LIST *o);
UINT IniIntValue(LIST *o, char *key);
char *IniStrValue(LIST *o, char *key);
bool InStr(char *str, char *keyword);
bool InStrEx(char *str, char *keyword, bool case_sensitive);
bool InStrList(char *target_str, char *tokens, char *splitter, bool case_sensitive);
TOKEN_LIST *ParseTokenWithoutNullStr(char *str, char *split_chars);
TOKEN_LIST *ParseTokenWithNullStr(char *str, char *split_chars);
char *DefaultTokenSplitChars();
bool IsCharInStr(char *str, char c);
UINT HexTo4Bit(char c);
char FourBitToHex(UINT value);
void ToHex(char *str, UINT value);
UINT HexToInt(char *str);
UINT SearchAsciiInBinary(void *data, UINT size, char *str, bool case_sensitive);
void IntListToStr(char *str, UINT str_size, LIST *o, char *separate_str);
LIST *StrToIntList(char *str, bool sorted);
void NormalizeIntListStr(char *dst, UINT dst_size, char *src, bool sorted, char *separate_str);
void ClearStr(char *str, UINT str_size);
void SetStrCaseAccordingToBits(char *str, UINT bits);

#endif	// STR_H

