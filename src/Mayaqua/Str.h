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
bool StrCheckSize(char *str, UINT size);
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
char *CopyFormat(char *fmt, ...);
void MakeFormatSafeString(char* str);
void Print(char *fmt, ...);
void PrintArgs(char *fmt, va_list args);
void PrintStr(char *str);
void Debug(char *fmt, ...);
void DebugArgs(char *fmt, va_list args);
UINT ToInt(char *str);
bool ToBool(char *str);
int ToInti(char *str);
void ToStr(char *str, UINT i);
void ToStri(char *str, int i);
void ToStrx(char *str, UINT i);
void ToStrx8(char *str, UINT i);
void TrimCrlf(char *str);
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
bool InChar(char *string, char c);
UINT SearchStrEx(char *string, char *keyword, UINT start, bool case_sensitive);
UINT SearchStri(char *string, char *keyword, UINT start);
UINT SearchStr(char *string, char *keyword, UINT start);
UINT CalcReplaceStrEx(char *string, char *old_keyword, char *new_keyword, bool case_sensitive);
UINT ReplaceStrEx(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword, bool case_sensitive);
UINT ReplaceStr(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword);
UINT ReplaceStri(char *dst, UINT size, char *string, char *old_keyword, char *new_keyword);
bool IsPrintableAsciiChar(char c);
bool IsPrintableAsciiStr(char *str);
void EnPrintableAsciiStr(char *str, char replace);
bool IsSafeChar(char c);
bool IsSafeStr(char *str);
void EnSafeStr(char *str, char replace);
void TruncateCharFromStr(char *str, char replace);
char *CopyStr(char *str);
void BinToStr(char *str, UINT str_size, void *data, UINT data_size);
void BinToStrW(wchar_t *str, UINT str_size, void *data, UINT data_size);
void PrintBin(void *data, UINT size);
bool StartWith(char *str, char *key);
bool EndWith(char *str, char *key);
bool TrimEndWith(char *dst, UINT dst_size, char *str, char *key);
UINT64 ToInt64(char *str);
UINT64 Json_ToInt64Ex(char *str, char **endptr, bool *error);
void ToStr64(char *str, UINT64 value);
char *ReplaceFormatStringFor64(char *fmt);
TOKEN_LIST *ParseCmdLine(char *str);
TOKEN_LIST *CopyToken(TOKEN_LIST *src);
TOKEN_LIST *NullToken();
bool IsNum(char *str);
LIST *StrToStrList(char *str, UINT size);
BUF *StrListToStr(LIST *o);
void FreeStrList(LIST *o);
TOKEN_LIST *ListToTokenList(LIST *o);
LIST *TokenListToList(TOKEN_LIST *t);
bool IsEmptyStr(char *str);
bool IsFilledStr(char* str);
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
char *NormalizeCrlf(char *str);
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
UINT64 IniInt64Value(LIST *o, char *key);
char *IniStrValue(LIST *o, char *key);
wchar_t *IniUniStrValue(LIST *o, char *key);
bool IniHasValue(LIST *o, char *key);
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
void ToHex64(char *str, UINT64 value);
UINT HexToInt(char *str);
UINT64 HexToInt64(char *str);
UINT SearchAsciiInBinary(void *data, UINT size, char *str, bool case_sensitive);
bool IsStrInStrTokenList(char *str_list, char *str, char *split_chars, bool case_sensitive);
void IntListToStr(char *str, UINT str_size, LIST *o, char *separate_str);
LIST *StrToIntList(char *str, bool sorted);
void NormalizeIntListStr(char *dst, UINT dst_size, char *src, bool sorted, char *separate_str);
void ClearStr(char *str, UINT str_size);
void SetStrCaseAccordingToBits(char *str, UINT bits);
char *UrlDecode(char *url_str);
void GetDomainSuffixFromFqdn(char *dst, UINT size, char *fqdn);
bool NormalizeMacAddressListStr(char *dst, UINT size, char *src);
LIST *GetStrListFromLines(char *str);
bool CheckStrListIncludedInOther(LIST *o1, LIST *o2);
bool CheckStrListIncludedInOtherStr(char *str1, char *str2);
bool CheckStrListIncludedInOtherStrMac(char *str1, char *str2);

bool CheckPasswordComplexity(char *str);

TOKEN_LIST* StrToLinesList(char* str);
char* GetFirstFilledStrFromStr(char* str);
char* GetFirstFilledStrFromBuf(BUF* buf);
void RemoveBomFromStr(char* str);


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


/* Type definitions */
typedef union JSON_VALUE_UNION {
	char        *string;
	UINT64       number;
	JSON_OBJECT *object;
	JSON_ARRAY  *array;
	int          boolean;
	int          null;
} JSON_VALUE_UNION;

struct JSON_VALUE {
	JSON_VALUE      *parent;
	UINT  type;
	JSON_VALUE_UNION value;
};

struct JSON_OBJECT {
	JSON_VALUE  *wrapping_value;
	char       **names;
	JSON_VALUE **values;
	UINT       count;
	UINT       capacity;
};

struct JSON_ARRAY {
	JSON_VALUE  *wrapping_value;
	JSON_VALUE **items;
	UINT       count;
	UINT       capacity;
};


enum JSON_TYPES {
	JSON_TYPE_ERROR = -1,
	JSON_TYPE_NULL = 1,
	JSON_TYPE_STRING = 2,
	JSON_TYPE_NUMBER = 3,
	JSON_TYPE_OBJECT = 4,
	JSON_TYPE_ARRAY = 5,
	JSON_TYPE_BOOL = 6
};
//typedef unsigned int UINT;

enum JSON_RETS {
	JSON_RET_OK = 0,
	JSON_RET_ERROR = -1
};

typedef void * (*JSON_Malloc_Function)(UINT);
typedef void(*JSON_Free_Function)(void *);

/* Call only once, before calling any other function from parson API. If not called, malloc and free
from stdlib will be used for all allocations */
void JsonSetAllocationFunctions(JSON_Malloc_Function malloc_fun, JSON_Free_Function free_fun);

/*  Parses first JSON value in a string, returns NULL in case of error */
JSON_VALUE * JsonParseString(char *string);

/*  Parses first JSON value in a string and ignores comments (/ * * / and //),
returns NULL in case of error */
JSON_VALUE * JsonParseStringWithComments(char *string);

/* Serialization */
UINT      JsonGetSerializationSize(JSON_VALUE *value); /* returns 0 on fail */
UINT JsonSerializeToBuffer(JSON_VALUE *value, char *buf, UINT buf_size_in_bytes);
char *      JsonSerializeToString(JSON_VALUE *value);

/* Pretty serialization */
UINT      JsonGetSerializationSizePretty(JSON_VALUE *value); /* returns 0 on fail */
UINT JsonSerializeToBufferPretty(JSON_VALUE *value, char *buf, UINT buf_size_in_bytes);
char *      JsonSerializeToStringPretty(JSON_VALUE *value);
char *JsonToStr(JSON_VALUE *v);

void        JsonFreeString(char *string); /* frees string from json_serialize_to_string and json_serialize_to_string_pretty */

										  /* Comparing */
int  JsonCmp(JSON_VALUE *a, JSON_VALUE *b);

/* Validation
This is *NOT* JSON Schema. It validates json by checking if object have identically
named fields with matching types.
For example schema {"name":"", "age":0} will validate
{"name":"Joe", "age":25} and {"name":"Joe", "age":25, "gender":"m"},
but not {"name":"Joe"} or {"name":"Joe", "age":"Cucumber"}.
In case of arrays, only first value in schema is checked against all values in tested array.
Empty objects ({}) validate all objects, empty arrays ([]) validate all arrays,
null validates values of every type.
*/
UINT JsonValidate(JSON_VALUE *schema, JSON_VALUE *value);

/*
* JSON Object
*/
JSON_VALUE  * JsonGet(JSON_OBJECT *object, char *name);
char  * JsonGetStr(JSON_OBJECT *object, char *name);
JSON_OBJECT * JsonGetObj(JSON_OBJECT *object, char *name);
JSON_ARRAY  * JsonGetArray(JSON_OBJECT *object, char *name);
UINT64        JsonGetNumber(JSON_OBJECT *object, char *name); /* returns 0 on fail */
bool          JsonGetBool(JSON_OBJECT *object, char *name); /* returns 0 on fail */

															/* dotget functions enable addressing values with dot notation in nested objects,
															just like in structs or c++/java/c# objects (e.g. objectA.objectB.value).
															Because valid names in JSON can contain dots, some values may be inaccessible
															this way. */
JSON_VALUE  * JsonDotGet(JSON_OBJECT *object, char *name);
char  * JsonDotGetStr(JSON_OBJECT *object, char *name);
JSON_OBJECT * JsonDotGetObj(JSON_OBJECT *object, char *name);
JSON_ARRAY  * JsonDotGetArray(JSON_OBJECT *object, char *name);
UINT64        JsonDotGetNumber(JSON_OBJECT *object, char *name); /* returns 0 on fail */
bool          JsonDotGetBool(JSON_OBJECT *object, char *name); /* returns -1 on fail */

															   /* Functions to get available names */
UINT        JsonGetCount(JSON_OBJECT *object);
char  * JsonGetName(JSON_OBJECT *object, UINT index);
JSON_VALUE  * JsonGetValueAt(JSON_OBJECT *object, UINT index);
JSON_VALUE  * JsonGetWrappingValue(JSON_OBJECT *object);

/* Functions to check if object has a value with a specific name. Returned value is 1 if object has
* a value and 0 if it doesn't. dothas functions behave exactly like dotget functions. */
int JsonIsExists(JSON_OBJECT *object, char *name);
int JsonIsExistsWithValueType(JSON_OBJECT *object, char *name, UINT type);

int JsonDotIsExists(JSON_OBJECT *object, char *name);
int JsonDotIsExistsWithValueType(JSON_OBJECT *object, char *name, UINT type);

/* Creates new name-value pair or frees and replaces old value with a new one.
* json_object_set_value does not copy passed value so it shouldn't be freed afterwards. */
UINT JsonSet(JSON_OBJECT *object, char *name, JSON_VALUE *value);
UINT JsonSetStr(JSON_OBJECT *object, char *name, char *string);
UINT JsonSetUniStr(JSON_OBJECT *object, char *name, wchar_t *string);
UINT JsonSetNumber(JSON_OBJECT *object, char *name, UINT64 number);
UINT JsonSetBool(JSON_OBJECT *object, char *name, int boolean);
UINT JsonSetNull(JSON_OBJECT *object, char *name);
UINT JsonSetData(JSON_OBJECT *object, char *name, void *data, UINT size);

/* Works like dotget functions, but creates whole hierarchy if necessary.
* json_object_dotset_value does not copy passed value so it shouldn't be freed afterwards. */
UINT JsonDotSet(JSON_OBJECT *object, char *name, JSON_VALUE *value);
UINT JsonDotSetStr(JSON_OBJECT *object, char *name, char *string);
UINT JsonDotSetNumber(JSON_OBJECT *object, char *name, UINT64 number);
UINT JsonDotSetBool(JSON_OBJECT *object, char *name, int boolean);
UINT JsonDotSetNull(JSON_OBJECT *object, char *name);

/* Frees and removes name-value pair */
UINT JsonDelete(JSON_OBJECT *object, char *name);

/* Works like dotget function, but removes name-value pair only on exact match. */
UINT JsonDotDelete(JSON_OBJECT *object, char *key);

/* Removes all name-value pairs in object */
UINT JsonDeleteAll(JSON_OBJECT *object);

/*
*JSON Array
*/
JSON_VALUE  * JsonArrayGet(JSON_ARRAY *array, UINT index);
char  * JsonArrayGetStr(JSON_ARRAY *array, UINT index);
JSON_OBJECT * JsonArrayGetObj(JSON_ARRAY *array, UINT index);
JSON_ARRAY  * JsonArrayGetArray(JSON_ARRAY *array, UINT index);
UINT64        JsonArrayGetNumber(JSON_ARRAY *array, UINT index); /* returns 0 on fail */
bool           JsonArrayGetBool(JSON_ARRAY *array, UINT index); /* returns 0 on fail */
UINT        JsonArrayGetCount(JSON_ARRAY *array);
JSON_VALUE  * JsonArrayGetWrappingValue(JSON_ARRAY *array);

/* Frees and removes value at given index, does nothing and returns JSONFailure if index doesn't exist.
* Order of values in array may change during execution.  */
UINT JsonArrayDelete(JSON_ARRAY *array, UINT i);

/* Frees and removes from array value at given index and replaces it with given one.
* Does nothing and returns JSONFailure if index doesn't exist.
* json_array_replace_value does not copy passed value so it shouldn't be freed afterwards. */
UINT JsonArrayReplace(JSON_ARRAY *array, UINT i, JSON_VALUE *value);
UINT JsonArrayReplaceStr(JSON_ARRAY *array, UINT i, char* string);
UINT JsonArrayReplaceNumber(JSON_ARRAY *array, UINT i, UINT64 number);
UINT JsonArrayReplaceBool(JSON_ARRAY *array, UINT i, int boolean);
UINT JsonArrayReplaceNull(JSON_ARRAY *array, UINT i);

/* Frees and removes all values from array */
UINT JsonArrayDeleteAll(JSON_ARRAY *array);

/* Appends new value at the end of array.
* json_array_append_value does not copy passed value so it shouldn't be freed afterwards. */
UINT JsonArrayAdd(JSON_ARRAY *array, JSON_VALUE *value);
UINT JsonArrayAddStr(JSON_ARRAY *array, char *string);
UINT JsonArrayAddUniStr(JSON_ARRAY *array, wchar_t *string);
UINT JsonArrayAddNumber(JSON_ARRAY *array, UINT64 number);
UINT JsonArrayAddData(JSON_ARRAY *array, void *data, UINT size);
UINT JsonArrayAddBool(JSON_ARRAY *array, int boolean);
UINT JsonArrayAddNull(JSON_ARRAY *array);


/*
*JSON Value
*/
JSON_VALUE * JsonNewObject(void);
JSON_VALUE * JsonNewArray(void);
JSON_VALUE * JsonNewStr(char *string); /* copies passed string */
JSON_VALUE * JsonNewNumber(UINT64 number);
JSON_VALUE * JsonNewBool(int boolean);
JSON_VALUE * JsonNewNull(void);
JSON_VALUE * JsonDeepCopy(JSON_VALUE *value);
void         JsonFree(JSON_VALUE *value);

UINT JsonValueGetType(JSON_VALUE *value);
JSON_OBJECT *   JsonValueGetObject(JSON_VALUE *value);
JSON_ARRAY  *   JsonValueGetArray(JSON_VALUE *value);
char  *   JsonValueGetStr(JSON_VALUE *value);
UINT64          JsonValueGetNumber(JSON_VALUE *value);
bool            JsonValueGetBool(JSON_VALUE *value);
JSON_VALUE  *   JsonValueGetParent(JSON_VALUE *value);

/* Same as above, but shorter */
UINT JsonType(JSON_VALUE *value);
JSON_OBJECT *   JsonObject(JSON_VALUE *value);
JSON_ARRAY  *   JsonArray(JSON_VALUE *value);
char  *   JsonString(JSON_VALUE *value);
UINT64          JsonNumber(JSON_VALUE *value);
int             JsonBool(JSON_VALUE *value);

void SystemTimeToJsonStr(char *dst, UINT size, SYSTEMTIME *t);
void SystemTime64ToJsonStr(char *dst, UINT size, UINT64 t);

JSON_VALUE *StrToJson(char *str);

#endif	// STR_H

