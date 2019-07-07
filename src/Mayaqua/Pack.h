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


// Pack.h
// Header of Pack.c

#ifndef	PACK_H
#define	PACK_H

// Constant
#ifdef CPU_64

#define	MAX_VALUE_SIZE			(384 * 1024 * 1024)	// Maximum Data size that can be stored in a single VALUE
#define	MAX_VALUE_NUM			262144	// Maximum VALUE number that can be stored in a single ELEMENT
#define	MAX_ELEMENT_NAME_LEN	63		// The length of the name that can be attached to the ELEMENT
#define	MAX_ELEMENT_NUM			262144	// Maximum ELEMENT number that can be stored in a single PACK
#define	MAX_PACK_SIZE			(512 * 1024 * 1024)	// Maximum size of a serialized PACK

#else	// CPU_64

#define	MAX_VALUE_SIZE			(96 * 1024 * 1024)	// Maximum Data size that can be stored in a single VALUE
#define	MAX_VALUE_NUM			65536	// Maximum VALUE number that can be stored in a single ELEMENT
#define	MAX_ELEMENT_NAME_LEN	63		// The length of the name that can be attached to the ELEMENT
#define	MAX_ELEMENT_NUM			131072	// Maximum ELEMENT number that can be stored in a single PACK
#define	MAX_PACK_SIZE			(128 * 1024 * 1024)	// Maximum size of a serialized PACK

#endif	// CPU_64

// Type of VALUE
#define	VALUE_INT			0		// Integer type
#define	VALUE_DATA			1		// Data type
#define	VALUE_STR			2		// ANSI string type
#define	VALUE_UNISTR		3		// Unicode string type
#define	VALUE_INT64			4		// 64 bit integer type

// The number of allowable NOOP
#define	MAX_NOOP_PER_SESSION	30

// VALUE object
struct VALUE
{
	UINT Size;				// Size
	UINT IntValue;			// Integer value
	void *Data;				// Data
	char *Str;				// ANSI string
	wchar_t *UniStr;		// Unicode strings
	UINT64 Int64Value;		// 64 bit integer type
};

// ELEMENT object
struct ELEMENT
{
	char name[MAX_ELEMENT_NAME_LEN + 1];	// Element name
	UINT num_value;			// Number of values (>=1)
	UINT type;				// Type
	VALUE **values;			// List of pointers to the value
	bool JsonHint_IsArray;
	bool JsonHint_IsBool;
	bool JsonHint_IsDateTime;
	bool JsonHint_IsIP;
	char JsonHint_GroupName[MAX_ELEMENT_NAME_LEN + 1];
};



// PACK object
struct PACK
{
	LIST *elements;			// Element list
	LIST *json_subitem_names;	// JSON sub-item names
	char CurrentJsonHint_GroupName[MAX_ELEMENT_NAME_LEN + 1];
};


#define MAX_JSONPACK_HINT_ITEMS			64
#define JSONPACK_HINT_TYPE_ARRAY		1

// JSON/PACK converter hint element
struct JSONPACKHINT_ITEM
{
	UINT Type;
	char ArrayNumNameInPack[MAX_ELEMENT_NAME_LEN + 1];
	char ArrayMembersInPack[MAX_SIZE + 1];
};

// JSON/PACK converter hint
struct JSONPACKHINT
{
	UINT NumHints;
	JSONPACKHINT_ITEM Hints[MAX_JSONPACK_HINT_ITEMS];
};


// Function prototype
PACK *NewPack();
bool AddElement(PACK *p, ELEMENT *e);
void DelElement(PACK *p, char *name);
bool IsElement(PACK *p, char *name);
ELEMENT *GetElement(PACK *p, char *name, UINT type);
void FreePack(PACK *p);
ELEMENT *NewElement(char *name, UINT type, UINT num_value, VALUE **values);
VALUE *NewIntValue(UINT i);
VALUE *NewDataValue(void *data, UINT size);
VALUE *NewStrValue(char *str);
VALUE *NewUniStrValue(wchar_t *str);
void FreeValue(VALUE *v, UINT type);
int ComparePackName(void *p1, void *p2);
void FreeElement(ELEMENT *e);
UINT GetValueNum(ELEMENT *e);
UINT GetIntValue(ELEMENT *e, UINT index);
UINT64 GetInt64Value(ELEMENT *e, UINT index);
char *GetStrValue(ELEMENT *e, UINT index);
wchar_t *GetUniStrValue(ELEMENT *e, UINT index);
UINT GetDataValueSize(ELEMENT *e, UINT index);
void *GetDataValue(ELEMENT *e, UINT index);
BUF *PackToBuf(PACK *p);
void WritePack(BUF *b, PACK *p);
void WriteElement(BUF *b, ELEMENT *e);
void WriteValue(BUF *b, VALUE *v, UINT type);
PACK *BufToPack(BUF *b);
bool ReadPack(BUF *b, PACK *p);
ELEMENT *ReadElement(BUF *b);
VALUE *ReadValue(BUF *b, UINT type);
void Bit160ToStr(char *str, UCHAR *data);
void Bit128ToStr(char *str, UCHAR *data);
VALUE *NewInt64Value(UINT64 i);
TOKEN_LIST *GetPackElementNames(PACK *p);

X *PackGetX(PACK *p, char *name);
K *PackGetK(PACK *p, char *name);
ELEMENT *PackAddX(PACK *p, char *name, X *x);
ELEMENT *PackAddK(PACK *p, char *name, K *k);
ELEMENT *PackAddStr(PACK *p, char *name, char *str);
ELEMENT *PackAddStrEx(PACK *p, char *name, char *str, UINT index, UINT total);
ELEMENT *PackAddUniStr(PACK *p, char *name, wchar_t *unistr);
ELEMENT *PackAddUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT index, UINT total);
ELEMENT *PackAddInt(PACK *p, char *name, UINT i);
ELEMENT *PackAddNum(PACK *p, char *name, UINT num);
ELEMENT *PackAddIntEx(PACK *p, char *name, UINT i, UINT index, UINT total);
ELEMENT *PackAddInt64(PACK *p, char *name, UINT64 i);
ELEMENT *PackAddInt64Ex(PACK *p, char *name, UINT64 i, UINT index, UINT total);
ELEMENT *PackAddTime64(PACK *p, char *name, UINT64 i);
ELEMENT *PackAddTime64Ex(PACK *p, char *name, UINT64 i, UINT index, UINT total);
ELEMENT *PackAddData(PACK *p, char *name, void *data, UINT size);
ELEMENT *PackAddDataEx(PACK *p, char *name, void *data, UINT size, UINT index, UINT total);
ELEMENT *PackAddBuf(PACK *p, char *name, BUF *b);
ELEMENT *PackAddBufEx(PACK *p, char *name, BUF *b, UINT index, UINT total);
bool PackGetStr(PACK *p, char *name, char *str, UINT size);
bool PackGetStrEx(PACK *p, char *name, char *str, UINT size, UINT index);
bool PackGetUniStr(PACK *p, char *name, wchar_t *unistr, UINT size);
bool PackGetUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT size, UINT index);
bool PackCmpStr(PACK *p, char *name, char *str);
UINT PackGetIndexCount(PACK *p, char *name);
UINT PackGetInt(PACK *p, char *name);
UINT PackGetNum(PACK *p, char *name);
UINT PackGetIntEx(PACK *p, char *name, UINT index);
UINT64 PackGetInt64(PACK *p, char *name);
UINT64 PackGetInt64Ex(PACK *p, char *name, UINT index);
UINT PackGetDataSizeEx(PACK *p, char *name, UINT index);
UINT PackGetDataSize(PACK *p, char *name);
bool PackGetData(PACK *p, char *name, void *data);
bool PackGetDataEx(PACK *p, char *name, void *data, UINT index);
BUF *PackGetBuf(PACK *p, char *name);
BUF *PackGetBufEx(PACK *p, char *name, UINT index);
bool PackGetBool(PACK *p, char *name);
ELEMENT *PackAddBool(PACK *p, char *name, bool b);
ELEMENT *PackAddBoolEx(PACK *p, char *name, bool b, UINT index, UINT total);
bool PackGetBoolEx(PACK *p, char *name, UINT index);
void PackAddIp(PACK *p, char *name, IP *ip);
void PackAddIpEx(PACK *p, char *name, IP *ip, UINT index, UINT total);
void PackAddIpEx2(PACK *p, char *name, IP *ip, UINT index, UINT total, bool is_single);
bool PackGetIp(PACK *p, char *name, IP *ip);
bool PackGetIpEx(PACK *p, char *name, IP *ip, UINT index);
UINT PackGetIp32(PACK *p, char *name);
UINT PackGetIp32Ex(PACK *p, char *name, UINT index);
void PackAddIp32(PACK *p, char *name, UINT ip32);
void PackAddIp32Ex(PACK *p, char *name, UINT ip32, UINT index, UINT total);
void PackAddIp32Ex2(PACK *p, char *name, UINT ip32, UINT index, UINT total, bool is_single);
ELEMENT *PackAddIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index, UINT total);
bool PackGetIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index);
ELEMENT *PackAddIp6Addr(PACK *p, char *name, IPV6_ADDR *addr);
bool PackGetIp6Addr(PACK *p, char *name, IPV6_ADDR *addr);
bool PackGetData2(PACK *p, char *name, void *data, UINT size);
bool PackGetDataEx2(PACK *p, char *name, void *data, UINT size, UINT index);
bool PackIsValueExists(PACK *p, char *name);
void PackSetCurrentJsonGroupName(PACK *p, char *json_group_name);
ELEMENT *ElementNullSafe(ELEMENT *p);

JSON_VALUE *PackToJson(PACK *p);
char *PackToJsonStr(PACK *p);

PACK *JsonToPack(JSON_VALUE *v);
PACK *JsonStrToPack(char *str);

void PackArrayElementToJsonArray(JSON_ARRAY *ja, PACK *p, ELEMENT *e, UINT index);
void PackElementToJsonObject(JSON_OBJECT *o, PACK *p, ELEMENT *e, UINT index);
char *DetermineJsonSuffixForPackElement(ELEMENT *e);
bool JsonTryParseValueAddToPack(PACK *p, JSON_VALUE *v, char *v_name, UINT index, UINT total, bool is_single);


#endif	// PACK_H
