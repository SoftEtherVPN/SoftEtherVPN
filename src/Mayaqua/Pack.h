// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


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
};

// PACK object
struct PACK
{
	LIST *elements;			// Element list
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
VALUE *NewInt64Value(UINT64 i);
TOKEN_LIST *GetPackElementNames(PACK *p);

X *PackGetX(PACK *p, char *name);
K *PackGetK(PACK *p, char *name);
void PackAddX(PACK *p, char *name, X *x);
void PackAddK(PACK *p, char *name, K *k);
void PackAddStr(PACK *p, char *name, char *str);
void PackAddStrEx(PACK *p, char *name, char *str, UINT index, UINT total);
void PackAddUniStr(PACK *p, char *name, wchar_t *unistr);
void PackAddUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT index, UINT total);
void PackAddInt(PACK *p, char *name, UINT i);
void PackAddNum(PACK *p, char *name, UINT num);
void PackAddIntEx(PACK *p, char *name, UINT i, UINT index, UINT total);
void PackAddInt64(PACK *p, char *name, UINT64 i);
void PackAddInt64Ex(PACK *p, char *name, UINT64 i, UINT index, UINT total);
void PackAddData(PACK *p, char *name, void *data, UINT size);
void PackAddDataEx(PACK *p, char *name, void *data, UINT size, UINT index, UINT total);
void PackAddBuf(PACK *p, char *name, BUF *b);
void PackAddBufEx(PACK *p, char *name, BUF *b, UINT index, UINT total);
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
void PackAddBool(PACK *p, char *name, bool b);
void PackAddBoolEx(PACK *p, char *name, bool b, UINT index, UINT total);
bool PackGetBoolEx(PACK *p, char *name, UINT index);
void PackAddIp(PACK *p, char *name, IP *ip);
void PackAddIpEx(PACK *p, char *name, IP *ip, UINT index, UINT total);
bool PackGetIp(PACK *p, char *name, IP *ip);
bool PackGetIpEx(PACK *p, char *name, IP *ip, UINT index);
UINT PackGetIp32(PACK *p, char *name);
UINT PackGetIp32Ex(PACK *p, char *name, UINT index);
void PackAddIp32(PACK *p, char *name, UINT ip32);
void PackAddIp32Ex(PACK *p, char *name, UINT ip32, UINT index, UINT total);
void PackAddIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index, UINT total);
bool PackGetIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index);
void PackAddIp6Addr(PACK *p, char *name, IPV6_ADDR *addr);
bool PackGetIp6Addr(PACK *p, char *name, IPV6_ADDR *addr);
bool PackGetData2(PACK *p, char *name, void *data, UINT size);
bool PackGetDataEx2(PACK *p, char *name, void *data, UINT size, UINT index);
bool PackIsValueExists(PACK *p, char *name);

#endif	// PACK_H
