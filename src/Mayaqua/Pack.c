// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Pack.c
// Data package code

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// Get a list of the element names in the PACK
TOKEN_LIST *GetPackElementNames(PACK *p)
{
	TOKEN_LIST *ret;
	UINT i;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	ret = ZeroMalloc(sizeof(TOKEN_LIST));

	ret->NumTokens = LIST_NUM(p->elements);
	ret->Token = ZeroMalloc(sizeof(char *) * ret->NumTokens);

	for (i = 0;i < ret->NumTokens;i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);

		ret->Token[i] = CopyStr(e->name);
	}

	return ret;
}

// Convert the BUF to a PACK
PACK *BufToPack(BUF *b)
{
	PACK *p;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	p = NewPack();
	if (ReadPack(b, p) == false)
	{
		FreePack(p);
		return NULL;
	}

	return p;
}

// Convert the PACK to the BUF
BUF *PackToBuf(PACK *p)
{
	BUF *b;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WritePack(b, p);

	return b;
}

// Read the PACK
bool ReadPack(BUF *b, PACK *p)
{
	UINT i, num;
	// Validate arguments
	if (b == NULL || p == NULL)
	{
		return false;
	}

	// The number of ELEMENTs
	num = ReadBufInt(b);
	if (num > MAX_ELEMENT_NUM)
	{
		// Number exceeds
		return false;
	}

	// Read the ELEMENT
	for (i = 0;i < num;i++)
	{
		ELEMENT *e;
		e = ReadElement(b);
		if (AddElement(p, e) == false)
		{
			// Adding error
			return false;
		}
	}

	return true;
}

// Write down the PACK
void WritePack(BUF *b, PACK *p)
{
	UINT i;
	// Validate arguments
	if (b == NULL || p == NULL)
	{
		return;
	}

	// The number of ELEMENTs
	WriteBufInt(b, LIST_NUM(p->elements));

	// Write the ELEMENT
	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);
		WriteElement(b, e);
	}
}

// Read the ELEMENT
ELEMENT *ReadElement(BUF *b)
{
	UINT i;
	char name[MAX_ELEMENT_NAME_LEN + 1];
	UINT type, num_value;
	VALUE **values;
	ELEMENT *e;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	// Name
	if (ReadBufStr(b, name, sizeof(name)) == false)
	{
		return NULL;
	}

	// Type of item
	type = ReadBufInt(b);

	// Number of items
	num_value = ReadBufInt(b);
	if (num_value > MAX_VALUE_NUM)
	{
		// Number exceeds
		return NULL;
	}

	// VALUE
	values = (VALUE **)Malloc(sizeof(VALUE *) * num_value);
	for (i = 0;i < num_value;i++)
	{
		values[i] = ReadValue(b, type);
	}

	// Create a ELEMENT
	e = NewElement(name, type, num_value, values);

	Free(values);

	return e;
}

// Write the ELEMENT
void WriteElement(BUF *b, ELEMENT *e)
{
	UINT i;
	// Validate arguments
	if (b == NULL || e == NULL)
	{
		return;
	}

	// Name
	WriteBufStr(b, e->name);
	// Type of item
	WriteBufInt(b, e->type);
	// Number of items
	WriteBufInt(b, e->num_value);
	// VALUE
	for (i = 0;i < e->num_value;i++)
	{
		VALUE *v = e->values[i];
		WriteValue(b, v, e->type);
	}
}

// Read the VALUE
VALUE *ReadValue(BUF *b, UINT type)
{
	UINT len;
	BYTE *u;
	void *data;
	char *str;
	wchar_t *unistr;
	UINT unistr_size;
	UINT size;
	UINT u_size;
	VALUE *v = NULL;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	// Data item
	switch (type)
	{
	case VALUE_INT:			// Integer
		v = NewIntValue(ReadBufInt(b));
		break;
	case VALUE_INT64:
		v = NewInt64Value(ReadBufInt64(b));
		break;
	case VALUE_DATA:		// Data
		size = ReadBufInt(b);
		if (size > MAX_VALUE_SIZE)
		{
			// Size over
			break;
		}
		data = Malloc(size);
		if (ReadBuf(b, data, size) != size)
		{
			// Read failure
			Free(data);
			break;
		}
		v = NewDataValue(data, size);
		Free(data);
		break;
	case VALUE_STR:			// ANSI string
		len = ReadBufInt(b);
		if (len > (MAX_VALUE_SIZE - 1))
		{
			// Size over
			break;
		}
		str = Malloc(len + 1);
		// String body
		if (ReadBuf(b, str, len) != len)
		{
			// Read failure
			Free(str);
			break;
		}
		str[len] = 0;
		v = NewStrValue(str);
		Free(str);
		break;
	case VALUE_UNISTR:		// Unicode string
		u_size = ReadBufInt(b);
		if (u_size > MAX_VALUE_SIZE)
		{
			// Size over
			break;
		}
		// Reading an UTF-8 string
		u = ZeroMalloc(u_size + 1);
		if (ReadBuf(b, u, u_size) != u_size)
		{
			// Read failure
			Free(u);
			break;
		}
		// Convert to a Unicode string
		unistr_size = CalcUtf8ToUni(u, u_size);
		if (unistr_size == 0)
		{
			Free(u);
			break;
		}
		unistr = Malloc(unistr_size);
		Utf8ToUni(unistr, unistr_size, u, u_size);
		Free(u);
		v = NewUniStrValue(unistr);
		Free(unistr);
		break;
	}

	return v;
}

// Write the VALUE
void WriteValue(BUF *b, VALUE *v, UINT type)
{
	UINT len;
	BYTE *u;
	UINT u_size;
	// Validate arguments
	if (b == NULL || v == NULL)
	{
		return;
	}

	// Data item
	switch (type)
	{
	case VALUE_INT:			// Integer
		WriteBufInt(b, v->IntValue);
		break;
	case VALUE_INT64:		// 64 bit integer
		WriteBufInt64(b, v->Int64Value);
		break;
	case VALUE_DATA:		// Data
		// Size
		WriteBufInt(b, v->Size);
		// Body
		WriteBuf(b, v->Data, v->Size);
		break;
	case VALUE_STR:			// ANSI string
		len = StrLen(v->Str);
		// Length
		WriteBufInt(b, len);
		// String body
		WriteBuf(b, v->Str, len);
		break;
	case VALUE_UNISTR:		// Unicode string
		// Convert to UTF-8
		u_size = CalcUniToUtf8(v->UniStr) + 1;
		u = ZeroMalloc(u_size);
		UniToUtf8(u, u_size, v->UniStr);
		// Size
		WriteBufInt(b, u_size);
		// UTF-8 string body
		WriteBuf(b, u, u_size);
		Free(u);
		break;
	}
}

// Get data size
UINT GetDataValueSize(ELEMENT *e, UINT index)
{
	// Validate arguments
	if (e == NULL)
	{
		return 0;
	}
	if (e->values == NULL)
	{
		return 0;
	}
	if (index >= e->num_value)
	{
		return 0;
	}
	if (e->values[index] == NULL)
	{
		return 0;
	}

	return e->values[index]->Size;
}

// Get the data
void *GetDataValue(ELEMENT *e, UINT index)
{
	// Validate arguments
	if (e == NULL)
	{
		return NULL;
	}
	if (e->values == NULL)
	{
		return NULL;
	}
	if (index >= e->num_value)
	{
		return NULL;
	}
	if (e->values[index] == NULL)
	{
		return NULL;
	}

	return e->values[index]->Data;
}

// Get the Unicode string type
wchar_t *GetUniStrValue(ELEMENT *e, UINT index)
{
	// Validate arguments
	if (e == NULL)
	{
		return 0;
	}
	if (index >= e->num_value)
	{
		return 0;
	}
	if (e->values[index] == NULL)
	{
		return NULL;
	}

	return e->values[index]->UniStr;
}

// Get the ANSI string type
char *GetStrValue(ELEMENT *e, UINT index)
{
	// Validate arguments
	if (e == NULL)
	{
		return 0;
	}
	if (index >= e->num_value)
	{
		return 0;
	}
	if (e->values[index] == NULL)
	{
		return NULL;
	}

	return e->values[index]->Str;
}

// Get the 64 bit integer value
UINT64 GetInt64Value(ELEMENT *e, UINT index)
{
	// Validate arguments
	if (e == NULL)
	{
		return 0;
	}
	if (index >= e->num_value)
	{
		return 0;
	}
	if (e->values[index] == NULL)
	{
		return 0;
	}

	return e->values[index]->Int64Value;
}

// Get the integer value
UINT GetIntValue(ELEMENT *e, UINT index)
{
	// Validate arguments
	if (e == NULL)
	{
		return 0;
	}
	if (index >= e->num_value)
	{
		return 0;
	}
	if (e->values[index] == NULL)
	{
		return 0;
	}

	return e->values[index]->IntValue;
}

// Function of sort for PACK
int ComparePackName(void *p1, void *p2)
{
	ELEMENT *o1, *o2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	o1 = *(ELEMENT **)p1;
	o2 = *(ELEMENT **)p2;
	if (o1 == NULL || o2 == NULL)
	{
		return 0;
	}

	return StrCmpi(o1->name, o2->name);
}

// Delete the VALUE
void FreeValue(VALUE *v, UINT type)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

	switch (type)
	{
	case VALUE_INT:
	case VALUE_INT64:
		break;
	case VALUE_DATA:
		Free(v->Data);
		break;
	case VALUE_STR:
		Free(v->Str);
		break;
	case VALUE_UNISTR:
		Free(v->UniStr);
		break;
	}

	// Memory release
	Free(v);
}

// Create a VALUE of Unicode String type
VALUE *NewUniStrValue(wchar_t *str)
{
	VALUE *v;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	// Memory allocation
	v = Malloc(sizeof(VALUE));

	// String copy
	v->Size = UniStrSize(str);
	v->UniStr = Malloc(v->Size);
	UniStrCpy(v->UniStr, v->Size, str);

	UniTrim(v->UniStr);

	return v;
}

// Creation of the VALUE of ANSI string type
VALUE *NewStrValue(char *str)
{
	VALUE *v;
	// Validate arguments
	if (str == NULL)
	{
		return NULL;
	}

	// Memory allocation
	v = Malloc(sizeof(VALUE));

	// String copy
	v->Size = StrLen(str) + 1;
	v->Str = Malloc(v->Size);
	StrCpy(v->Str, v->Size, str);

	Trim(v->Str);

	return v;
}

// Create the VALUE of the data type
VALUE *NewDataValue(void *data, UINT size)
{
	VALUE *v;
	// Validate arguments
	if (data == NULL)
	{
		return NULL;
	}

	// Memory allocation
	v = Malloc(sizeof(VALUE));

	// Data copy
	v->Size = size;
	v->Data = Malloc(v->Size);
	Copy(v->Data, data, size);

	return v;
}

// Create the VALUE of 64 bit integer type
VALUE *NewInt64Value(UINT64 i)
{
	VALUE *v;

	v = Malloc(sizeof(VALUE));
	v->Int64Value = i;
	v->Size = sizeof(UINT64);

	return v;
}

// Create the VALUE of integer type
VALUE *NewIntValue(UINT i)
{
	VALUE *v;

	// Memory allocation
	v = Malloc(sizeof(VALUE));
	v->IntValue = i;
	v->Size = sizeof(UINT);

	return v;
}

// Delete the ELEMENT
void FreeElement(ELEMENT *e)
{
	UINT i;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	for (i = 0;i < e->num_value;i++)
	{
		FreeValue(e->values[i], e->type);
	}
	Free(e->values);

	Free(e);
}

// Create a ELEMENT
ELEMENT *NewElement(char *name, UINT type, UINT num_value, VALUE **values)
{
	ELEMENT *e;
	UINT i;
	// Validate arguments
	if (name == NULL || num_value == 0 || values == NULL)
	{
		return NULL;
	}

	// Memory allocation
	e = ZeroMalloc(sizeof(ELEMENT));
	StrCpy(e->name, sizeof(e->name), name);
	e->num_value = num_value;
	e->type = type;

	// Copy of the pointer list to the element
	e->values = (VALUE **)ZeroMalloc(sizeof(VALUE *) * num_value);
	for (i = 0;i < e->num_value;i++)
	{
		e->values[i] = values[i];
	}

	return e;
}

// Search and retrieve a ELEMENT from the PACK
ELEMENT *GetElement(PACK *p, char *name, UINT type)
{
	ELEMENT t;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	// Search
	StrCpy(t.name, sizeof(t.name), name);
	e = Search(p->elements, &t);

	if (e == NULL)
	{
		return NULL;
	}

	// Type checking
	if (type != INFINITE)
	{
		if (e->type != type)
		{
			return NULL;
		}
	}

	return e;
}

// Check whether the specified element exists
bool IsElement(PACK *p, char *name)
{
	ELEMENT t;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return false;
	}

	// Search
	StrCpy(t.name, sizeof(t.name), name);
	e = Search(p->elements, &t);

	if (e == NULL)
	{
		return false;
	}

	return true;
}

// Remove the ELEMENT from the PACK
void DelElement(PACK *p, char *name)
{
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return;
	}

	e = GetElement(p, name, INFINITE);
	if (e != NULL)
	{
		Delete(p->elements, e);

		FreeElement(e);
	}
}

// Add an ELEMENT to the PACK
bool AddElement(PACK *p, ELEMENT *e)
{
	// Validate arguments
	if (p == NULL || e == NULL)
	{
		return false;
	}

	// Size Check
	if (LIST_NUM(p->elements) >= MAX_ELEMENT_NUM)
	{
		// Can not add any more
		FreeElement(e);
		return false;
	}

	// Check whether there is another item which have same name
	if (GetElement(p, e->name, INFINITE))
	{
		// Exists
		FreeElement(e);
		return false;
	}

	if (e->num_value == 0)
	{
		// VALUE without any items can not be added
		FreeElement(e);
		return false;
	}

	// Set JsonHint_GroupName
	StrCpy(e->JsonHint_GroupName, sizeof(e->JsonHint_GroupName), p->CurrentJsonHint_GroupName);

	// Adding
	Add(p->elements, e);
	return true;
}

// Release of the PACK object
void FreePack(PACK *p)
{
	UINT i;
	ELEMENT **elements;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	elements = ToArray(p->elements);
	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		FreeElement(elements[i]);
	}
	Free(elements);

	if (p->json_subitem_names != NULL)
	{
		FreeStrList(p->json_subitem_names);
	}

	ReleaseList(p->elements);
	Free(p);
}

// Create a PACK object
PACK *NewPack()
{
	PACK *p;

	// Memory allocation
	p = ZeroMallocEx(sizeof(PACK), true);

	// Creating a List
	p->elements = NewListFast(ComparePackName);

	return p;
}

// Get the K from the PACK
K *PackGetK(PACK *p, char *name)
{
	K *k;
	BUF *b;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	b = PackGetBuf(p, name);
	if (b == NULL)
	{
		return NULL;
	}

	k = BufToK(b, true, false, NULL);

	if (k == NULL)
	{
		k = BufToK(b, true, true, NULL);
	}

	FreeBuf(b);

	return k;
}

// Get the X from the PACK
X *PackGetX(PACK *p, char *name)
{
	X *x;
	BUF *b;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	b = PackGetBuf(p, name);
	if (b == NULL)
	{
		return NULL;
	}

	x = BufToX(b, false);

	if (x == NULL)
	{
		x = BufToX(b, true);
	}

	FreeBuf(b);

	return x;
}

// Add the K to the PACK
ELEMENT *PackAddK(PACK *p, char *name, K *k)
{
	BUF *b;
	ELEMENT *e = NULL;
	// Validate arguments
	if (p == NULL || name == NULL || k == NULL)
	{
		return NULL;
	}

	b = KToBuf(k, false, NULL);
	if (b == NULL)
	{
		return NULL;
	}

	e = PackAddBuf(p, name, b);
	FreeBuf(b);

	return e;
}

// Add an X into the PACK
ELEMENT *PackAddX(PACK *p, char *name, X *x)
{
	BUF *b;
	ELEMENT *e = NULL;
	// Validate arguments
	if (p == NULL || name == NULL || x == NULL)
	{
		return NULL;
	}

	b = XToBuf(x, false);
	if (b == NULL)
	{
		return NULL;
	}

	e = PackAddBuf(p, name, b);
	FreeBuf(b);

	return e;
}

// Get a buffer from the PACK
BUF *PackGetBuf(PACK *p, char *name)
{
	return PackGetBufEx(p, name, 0);
}
BUF *PackGetBufEx(PACK *p, char *name, UINT index)
{
	UINT size;
	void *tmp;
	BUF *b;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	size = PackGetDataSizeEx(p, name, index);
	tmp = MallocEx(size, true);
	if (PackGetDataEx(p, name, tmp, index) == false)
	{
		Free(tmp);
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, tmp, size);
	SeekBuf(b, 0, 0);

	Free(tmp);

	return b;
}

// Get the data from the PACK
bool PackGetData(PACK *p, char *name, void *data)
{
	return PackGetDataEx(p, name, data, 0);
}
bool PackGetDataEx(PACK *p, char *name, void *data, UINT index)
{
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return false;
	}

	e = GetElement(p, name, VALUE_DATA);
	if (e == NULL)
	{
		return false;
	}
	Copy(data, GetDataValue(e, index), GetDataValueSize(e, index));
	return true;
}
bool PackGetData2(PACK *p, char *name, void *data, UINT size)
{
	return PackGetDataEx2(p, name, data, size, 0);
}
bool PackGetDataEx2(PACK *p, char *name, void *data, UINT size, UINT index)
{
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return false;
	}

	e = GetElement(p, name, VALUE_DATA);
	if (e == NULL)
	{
		return false;
	}
	if (GetDataValueSize(e, index) != size)
	{
		return false;
	}
	Copy(data, GetDataValue(e, index), GetDataValueSize(e, index));
	return true;
}

// Get the data size from the PACK
UINT PackGetDataSize(PACK *p, char *name)
{
	return PackGetDataSizeEx(p, name, 0);
}
UINT PackGetDataSizeEx(PACK *p, char *name, UINT index)
{
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	e = GetElement(p, name, VALUE_DATA);
	if (e == NULL)
	{
		return 0;
	}
	return GetDataValueSize(e, index);
}

// Get an integer from the PACK
UINT64 PackGetInt64(PACK *p, char *name)
{
	return PackGetInt64Ex(p, name, 0);
}
UINT64 PackGetInt64Ex(PACK *p, char *name, UINT index)
{
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	e = GetElement(p, name, VALUE_INT64);
	if (e == NULL)
	{
		return 0;
	}
	return GetInt64Value(e, index);
}

// Get the index number from the PACK
UINT PackGetIndexCount(PACK *p, char *name)
{
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	e = GetElement(p, name, INFINITE);
	if (e == NULL)
	{
		return 0;
	}

	return e->num_value;
}

// Get the number from the PACK
UINT PackGetNum(PACK *p, char *name)
{
	return MIN(PackGetInt(p, name), 65536);
}

// Get a bool type from the PACK
bool PackGetBool(PACK *p, char *name)
{
	return PackGetInt(p, name) == 0 ? false : true;
}
bool PackGetBoolEx(PACK *p, char *name, UINT index)
{
	return PackGetIntEx(p, name, index) == 0 ? false : true;
}

// Set CurrentJsonHint_GroupName to PACK
void PackSetCurrentJsonGroupName(PACK *p, char *json_group_name)
{
	if (p == NULL)
	{
		return;
	}

	if (json_group_name == NULL)
	{
		ClearStr(p->CurrentJsonHint_GroupName, sizeof(p->CurrentJsonHint_GroupName));
	}
	else
	{
		StrCpy(p->CurrentJsonHint_GroupName, sizeof(p->CurrentJsonHint_GroupName), json_group_name);

		if (p->json_subitem_names == NULL)
		{
			p->json_subitem_names = NewStrList();
		}

		AddStrToStrListDistinct(p->json_subitem_names, json_group_name);
	}
}

// Add a bool type into the PACK
ELEMENT *PackAddBool(PACK *p, char *name, bool b)
{
	ELEMENT *e = PackAddInt(p, name, b ? 1 : 0);
	if (e != NULL)
	{
		e->JsonHint_IsBool = true;
	}
	return e;
}
ELEMENT *PackAddBoolEx(PACK *p, char *name, bool b, UINT index, UINT total)
{
	ELEMENT *e = PackAddIntEx(p, name, b ? 1 : 0, index, total);
	if (e != NULL)
	{
		e->JsonHint_IsBool = true;
	}
	return e;
}

// Add the IPV6_ADDR to the PACK
ELEMENT *PackAddIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index, UINT total)
{
	// Validate arguments
	if (p == NULL || name == NULL || addr == NULL)
	{
		return NULL;
	}

	return PackAddDataEx(p, name, addr, sizeof(IPV6_ADDR), index, total);
}
ELEMENT *PackAddIp6Addr(PACK *p, char *name, IPV6_ADDR *addr)
{
	return PackAddIp6AddrEx(p, name, addr, 0, 1);
}

// Get an IPV6_ADDR from the PACK
bool PackGetIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index)
{
	// Validate arguments
	if (p == NULL || name == NULL || addr == NULL)
	{
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	return PackGetDataEx2(p, name, addr, sizeof(IPV6_ADDR), index);
}
bool PackGetIp6Addr(PACK *p, char *name, IPV6_ADDR *addr)
{
	return PackGetIp6AddrEx(p, name, addr, 0);
}

// Add the IP to the PACK
void PackAddIp32Ex(PACK *p, char *name, UINT ip32, UINT index, UINT total)
{
	PackAddIp32Ex2(p, name, ip32, index, total, false);
}
void PackAddIp32Ex2(PACK *p, char *name, UINT ip32, UINT index, UINT total, bool is_single)
{
	IP ip;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return;
	}

	UINTToIP(&ip, ip32);

	PackAddIpEx2(p, name, &ip, index, total, is_single);
}
void PackAddIp32(PACK *p, char *name, UINT ip32)
{
	PackAddIp32Ex2(p, name, ip32, 0, 1, true);
}
void PackAddIpEx(PACK *p, char *name, IP *ip, UINT index, UINT total)
{
	PackAddIpEx2(p, name, ip, index, total, false);
}
void PackAddIpEx2(PACK *p, char *name, IP *ip, UINT index, UINT total, bool is_single)
{
	UINT i;
	bool b = false;
	char tmp[MAX_PATH];
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL || ip == NULL)
	{
		return;
	}
	if (total >= 2)
	{
		is_single = false;
	}

	b = IsIP6(ip);

	Format(tmp, sizeof(tmp), "%s@ipv6_bool", name);
	e = PackAddBoolEx(p, tmp, b, index, total);
	if (e != NULL && is_single) e->JsonHint_IsArray = false;
	if (e != NULL) e->JsonHint_IsIP = true;

	Format(tmp, sizeof(tmp), "%s@ipv6_array", name);
	if (b)
	{
		e = PackAddDataEx(p, tmp, ip->ipv6_addr, sizeof(ip->ipv6_addr), index, total);
		if (e != NULL && is_single) e->JsonHint_IsArray = false;
		if (e != NULL) e->JsonHint_IsIP = true;
	}
	else
	{
		UCHAR dummy[16];

		Zero(dummy, sizeof(dummy));

		e = PackAddDataEx(p, tmp, dummy, sizeof(dummy), index, total);
		if (e != NULL && is_single) e->JsonHint_IsArray = false;
		if (e != NULL) e->JsonHint_IsIP = true;
	}

	Format(tmp, sizeof(tmp), "%s@ipv6_scope_id", name);
	if (b)
	{
		e = PackAddIntEx(p, tmp, ip->ipv6_scope_id, index, total);
		if (e != NULL && is_single) e->JsonHint_IsArray = false;
		if (e != NULL) e->JsonHint_IsIP = true;
	}
	else
	{
		e = PackAddIntEx(p, tmp, 0, index, total);
		if (e != NULL && is_single) e->JsonHint_IsArray = false;
		if (e != NULL) e->JsonHint_IsIP = true;
	}

	i = IPToUINT(ip);

	if (IsBigEndian())
	{
		i = Swap32(i);
	}

	e = PackAddIntEx(p, name, i, index, total);
	if (e != NULL && is_single) e->JsonHint_IsArray = false;
	if (e != NULL) e->JsonHint_IsIP = true;
}
void PackAddIp(PACK *p, char *name, IP *ip)
{
	PackAddIpEx2(p, name, ip, 0, 1, true);
}

// Get an IP from the PACK
UINT PackGetIp32Ex(PACK *p, char *name, UINT index)
{
	IP ip;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	if (PackGetIpEx(p, name, &ip, index) == false)
	{
		return 0;
	}

	return IPToUINT(&ip);
}
UINT PackGetIp32(PACK *p, char *name)
{
	return PackGetIp32Ex(p, name, 0);
}
bool PackGetIpEx(PACK *p, char *name, IP *ip, UINT index)
{
	UINT i;
	char tmp[MAX_PATH];
	// Validate arguments
	if (p == NULL || ip == NULL || name == NULL)
	{
		return false;
	}

	Format(tmp, sizeof(tmp), "%s@ipv6_bool", name);
	if (PackGetBoolEx(p, tmp, index))
	{
		UCHAR data[16];
		UINT scope_id;

		Zero(data, sizeof(data));

		Format(tmp, sizeof(tmp), "%s@ipv6_array", name);
		PackGetDataEx2(p, tmp, data, sizeof(data), index);

		Format(tmp, sizeof(tmp), "%s@ipv6_scope_id", name);
		scope_id = PackGetIntEx(p, tmp, index);

		SetIP6(ip, data);
		ip->ipv6_scope_id = scope_id;
	}
	else
	{
		if (GetElement(p, name, VALUE_INT) == NULL)
		{
			Zero(ip, sizeof(IP));
			return false;
		}

		i = PackGetIntEx(p, name, index);

		if (IsBigEndian())
		{
			i = Swap32(i);
		}

		UINTToIP(ip, i);
	}

	return true;
}
bool PackGetIp(PACK *p, char *name, IP *ip)
{
	return PackGetIpEx(p, name, ip, 0);
}

// Check whether the specified value is existing on the Pack
bool PackIsValueExists(PACK *p, char *name)
{
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return false;
	}

	return IsElement(p, name);
}

// Get an integer from the PACK
UINT PackGetInt(PACK *p, char *name)
{
	return PackGetIntEx(p, name, 0);
}
UINT PackGetIntEx(PACK *p, char *name, UINT index)
{
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	e = GetElement(p, name, VALUE_INT);
	if (e == NULL)
	{
		return 0;
	}
	return GetIntValue(e, index);
}

// Get an Unicode string from the PACK
bool PackGetUniStr(PACK *p, char *name, wchar_t *unistr, UINT size)
{
	return PackGetUniStrEx(p, name, unistr, size, 0);
}
bool PackGetUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT size, UINT index)
{
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL || unistr == NULL || size == 0)
	{
		return false;
	}

	unistr[0] = 0;

	e = GetElement(p, name, VALUE_UNISTR);
	if (e == NULL)
	{
		return false;
	}
	UniStrCpy(unistr, size, GetUniStrValue(e, index));
	return true;
}

// Compare strings in the PACK
bool PackCmpStr(PACK *p, char *name, char *str)
{
	char tmp[MAX_SIZE];

	if (PackGetStr(p, name, tmp, sizeof(tmp)) == false)
	{
		return false;
	}

	if (StrCmpi(tmp, str) == 0)
	{
		return true;
	}

	return false;
}

// Get a string from the PACK
bool PackGetStr(PACK *p, char *name, char *str, UINT size)
{
	return PackGetStrEx(p, name, str, size, 0);
}
bool PackGetStrEx(PACK *p, char *name, char *str, UINT size, UINT index)
{
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL || str == NULL || size == 0)
	{
		return false;
	}

	str[0] = 0;

	e = GetElement(p, name, VALUE_STR);
	if (e == NULL)
	{
		return false;
	}

	StrCpy(str, size, GetStrValue(e, index));
	return true;
}

// Get the string size from the PACK
bool PackGetStrSize(PACK *p, char *name)
{
	return PackGetStrSizeEx(p, name, 0);
}
bool PackGetStrSizeEx(PACK *p, char *name, UINT index)
{
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return 0;
	}

	e = GetElement(p, name, VALUE_STR);
	if (e == NULL)
	{
		return 0;
	}
	return GetDataValueSize(e, index);
}

// Add the buffer to the PACK (array)
ELEMENT *PackAddBufEx(PACK *p, char *name, BUF *b, UINT index, UINT total)
{
	// Validate arguments
	if (p == NULL || name == NULL || b == NULL || total == 0)
	{
		return NULL;
	}

	return PackAddDataEx(p, name, b->Buf, b->Size, index, total);
}

// Add the data to the PACK (array)
ELEMENT *PackAddDataEx(PACK *p, char *name, void *data, UINT size, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || data == NULL || name == NULL || total == 0)
	{
		return NULL;
	}

	v = NewDataValue(data, size);
	e = GetElement(p, name, VALUE_DATA);
	if (e != NULL)
	{
		if (e->num_value >= total)
		{
			FreeValue(e->values[index], VALUE_DATA);
			e->values[index] = v;
		}
		else
		{
			FreeValue(v, VALUE_DATA);
		}
	}
	else
	{
		e = ZeroMallocEx(sizeof(ELEMENT), true);
		StrCpy(e->name, sizeof(e->name), name);
		e->num_value = total;
		e->type = VALUE_DATA;
		e->values = ZeroMallocEx(sizeof(VALUE *) * total, true);
		e->values[index] = v;
		if (AddElement(p, e) == false)
		{
			return NULL;
		}
	}

	e->JsonHint_IsArray = true;

	return e;
}

// Add the buffer to the PACK
ELEMENT *PackAddBuf(PACK *p, char *name, BUF *b)
{
	// Validate arguments
	if (p == NULL || name == NULL || b == NULL)
	{
		return NULL;
	}

	return PackAddData(p, name, b->Buf, b->Size);
}

// Add the data to the PACK
ELEMENT *PackAddData(PACK *p, char *name, void *data, UINT size)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || data == NULL || name == NULL)
	{
		return NULL;
	}

	v = NewDataValue(data, size);
	e = NewElement(name, VALUE_DATA, 1, &v);
	if (AddElement(p, e) == false)
	{
		return NULL;
	}

	return e;
}

// Add a 64 bit integer (array) to the PACK
ELEMENT *PackAddInt64Ex(PACK *p, char *name, UINT64 i, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL || total == 0)
	{
		return NULL;
	}

	v = NewInt64Value(i);
	e = GetElement(p, name, VALUE_INT64);
	if (e != NULL)
	{
		if (e->num_value >= total)
		{
			FreeValue(e->values[index], VALUE_INT64);
			e->values[index] = v;
		}
		else
		{
			FreeValue(v, VALUE_INT64);
		}
	}
	else
	{
		e = ZeroMallocEx(sizeof(ELEMENT), true);
		StrCpy(e->name, sizeof(e->name), name);
		e->num_value = total;
		e->type = VALUE_INT64;
		e->values = ZeroMallocEx(sizeof(VALUE *) * total, true);
		e->values[index] = v;

		if (AddElement(p, e) == false)
		{
			return NULL;
		}
	}

	e->JsonHint_IsArray = true;

	return e;
}

// Add an integer to the PACK (array)
ELEMENT *PackAddIntEx(PACK *p, char *name, UINT i, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL || total == 0)
	{
		return NULL;
	}

	v = NewIntValue(i);
	e = GetElement(p, name, VALUE_INT);
	if (e != NULL)
	{
		if (e->num_value >= total)
		{
			FreeValue(e->values[index], VALUE_INT);
			e->values[index] = v;
		}
		else
		{
			FreeValue(v, VALUE_INT);
		}
	}
	else
	{
		e = ZeroMallocEx(sizeof(ELEMENT), true);
		StrCpy(e->name, sizeof(e->name), name);
		e->num_value = total;
		e->type = VALUE_INT;
		e->values = ZeroMallocEx(sizeof(VALUE *) * total, true);
		e->values[index] = v;

		if (AddElement(p, e) == false)
		{
			return NULL;
		}
	}

	e->JsonHint_IsArray = true;

	return e;
}

// Add 64 bit integer time value to the PACK
ELEMENT *PackAddTime64(PACK *p, char *name, UINT64 i)
{
	ELEMENT *e = PackAddInt64(p, name, i);
	if (e != NULL)
	{
		e->JsonHint_IsDateTime = true;
	}
	return e;
}
ELEMENT *PackAddTime64Ex(PACK *p, char *name, UINT64 i, UINT index, UINT total)
{
	ELEMENT *e = PackAddInt64Ex(p, name, i, index, total);
	if (e != NULL)
	{
		e->JsonHint_IsDateTime = true;
	}
	return e;
}


// Add a 64 bit integer to the PACK
ELEMENT *PackAddInt64(PACK *p, char *name, UINT64 i)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	v = NewInt64Value(i);
	e = NewElement(name, VALUE_INT64, 1, &v);
	if (AddElement(p, e) == false)
	{
		return NULL;
	}
	return e;
}

// Add the number of items to the PACK
ELEMENT *PackAddNum(PACK *p, char *name, UINT num)
{
	return PackAddInt(p, name, num);
}

// Add an integer to the PACK
ELEMENT *PackAddInt(PACK *p, char *name, UINT i)
{
	VALUE *v;
	ELEMENT *e = NULL;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return NULL;
	}

	v = NewIntValue(i);
	e = NewElement(name, VALUE_INT, 1, &v);
	if (AddElement(p, e) == false)
	{
		return NULL;
	}
	return e;
}

// Add a Unicode string (array) to the PACK
ELEMENT *PackAddUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL || unistr == NULL || total == 0)
	{
		return NULL;
	}

	v = NewUniStrValue(unistr);
	e = GetElement(p, name, VALUE_UNISTR);
	if (e != NULL)
	{
		if (e->num_value >= total)
		{
			FreeValue(e->values[index], VALUE_UNISTR);
			e->values[index] = v;
		}
		else
		{
			FreeValue(v, VALUE_UNISTR);
		}
	}
	else
	{
		e = ZeroMallocEx(sizeof(ELEMENT), true);
		StrCpy(e->name, sizeof(e->name), name);
		e->num_value = total;
		e->type = VALUE_UNISTR;
		e->values = ZeroMallocEx(sizeof(VALUE *) * total, true);
		e->values[index] = v;
		if (AddElement(p, e) == false)
		{
			return NULL;
		}
	}

	e->JsonHint_IsArray = true;

	return e;
}

// Add a Unicode string to the PACK
ELEMENT *PackAddUniStr(PACK *p, char *name, wchar_t *unistr)
{
	VALUE *v;
	ELEMENT *e = NULL;
	// Validate arguments
	if (p == NULL || name == NULL || unistr == NULL)
	{
		return NULL;
	}

	v = NewUniStrValue(unistr);
	e = NewElement(name, VALUE_UNISTR, 1, &v);
	if (AddElement(p, e) == false)
	{
		return NULL;
	}
	return e;
}

// Add a string to the PACK (array)
ELEMENT *PackAddStrEx(PACK *p, char *name, char *str, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL || str == NULL || total == 0)
	{
		return NULL;
	}

	v = NewStrValue(str);
	e = GetElement(p, name, VALUE_STR);
	if (e != NULL)
	{
		if (e->num_value >= total)
		{
			FreeValue(e->values[index], VALUE_STR);
			e->values[index] = v;
		}
		else
		{
			FreeValue(v, VALUE_STR);
		}
	}
	else
	{
		e = ZeroMallocEx(sizeof(ELEMENT), true);
		StrCpy(e->name, sizeof(e->name), name);
		e->num_value = total;
		e->type = VALUE_STR;
		e->values = ZeroMallocEx(sizeof(VALUE *) * total, true);
		e->values[index] = v;
		if (AddElement(p, e) == false)
		{
			return NULL;
		}
	}

	e->JsonHint_IsArray = true;

	return e;
}

// Add a string to the PACK
ELEMENT *PackAddStr(PACK *p, char *name, char *str)
{
	VALUE *v;
	ELEMENT *e = NULL;
	// Validate arguments
	if (p == NULL || name == NULL || str == NULL)
	{
		return NULL;
	}

	v = NewStrValue(str);
	e = NewElement(name, VALUE_STR, 1, &v);
	if (AddElement(p, e) == false)
	{
		return NULL;
	}
	return e;
}

// Add an element of PACK array to JSON Array
void PackArrayElementToJsonArray(JSON_ARRAY *ja, PACK *p, ELEMENT *e, UINT index)
{
	if (ja == NULL || p == NULL || e == NULL || index >= e->num_value)
	{
		return;
	}

	switch (e->type)
	{
	case VALUE_INT:
		if (e->JsonHint_IsIP)
		{
			if (InStr(e->name, "@") == false)
			{
				IP ip;
				if (PackGetIpEx(p, e->name, &ip, index))
				{
					char ip_str[64];
					IPToStr(ip_str, sizeof(ip_str), &ip);
					JsonArrayAddStr(ja, ip_str);
				}
			}
		}
		else if (e->JsonHint_IsBool)
		{
			JsonArrayAddBool(ja, PackGetBoolEx(p, e->name, index));
		}
		else
		{
			JsonArrayAddNumber(ja, PackGetIntEx(p, e->name, index));
		}
		break;
	case VALUE_INT64:
		if (e->JsonHint_IsIP == false)
		{
			if (e->JsonHint_IsDateTime == false)
			{
				JsonArrayAddNumber(ja, PackGetInt64Ex(p, e->name, index));
			}
			else
			{
				char dtstr[64];

				SystemTime64ToJsonStr(dtstr, sizeof(dtstr), PackGetInt64Ex(p, e->name, index));
				JsonArrayAddStr(ja, dtstr);
			}
		}
		break;
	case VALUE_DATA:
		if (e->JsonHint_IsIP == false)
		{
			BUF *buf = PackGetBufEx(p, e->name, index);
			if (buf != NULL)
			{
				JsonArrayAddData(ja, buf->Buf, buf->Size);
				FreeBuf(buf);
			}
			else
			{
				UCHAR zero = 0;
				JsonArrayAddData(ja, &zero, 0);
			}
		}
		break;
	case VALUE_STR:
		if (e->JsonHint_IsIP == false)
		{
			if (e->values[index] != NULL)
			{
				JsonArrayAddStr(ja, e->values[index]->Str);
			}
			else
			{
				JsonArrayAddStr(ja, "");
			}
		}
		break;
	case VALUE_UNISTR:
		if (e->JsonHint_IsIP == false)
		{
			if (e->values[index] != NULL)
			{
				JsonArrayAddUniStr(ja, e->values[index]->UniStr);
			}
			else
			{
				JsonArrayAddUniStr(ja, L"");
			}
		}
		break;
	}
}

// Add an element of PACK to JSON Object
void PackElementToJsonObject(JSON_OBJECT *o, PACK *p, ELEMENT *e, UINT index)
{
	char *suffix;
	char name[MAX_PATH];
	if (o == NULL || p == NULL || e == NULL)
	{
		return;
	}

	suffix = DetermineJsonSuffixForPackElement(e);

	if (suffix == NULL)
	{
		return;
	}

	StrCpy(name, sizeof(name), e->name);
	StrCat(name, sizeof(name), suffix);

	switch (e->type)
	{
	case VALUE_INT:
		if (e->JsonHint_IsIP)
		{
			if (InStr(e->name, "@") == false)
			{
				IP ip;
				if (PackGetIpEx(p, e->name, &ip, index))
				{
					char ip_str[64];
					IPToStr(ip_str, sizeof(ip_str), &ip);
					JsonSetStr(o, name, ip_str);
				}
			}
		}
		else if (e->JsonHint_IsBool)
		{
			JsonSetBool(o, name, PackGetBoolEx(p, e->name, index));
		}
		else
		{
			JsonSetNumber(o, name, PackGetIntEx(p, e->name, index));
		}
		break;
	case VALUE_INT64:
		if (e->JsonHint_IsIP == false)
		{
			if (e->JsonHint_IsDateTime == false)
			{
				JsonSetNumber(o, name, PackGetInt64Ex(p, e->name, index));
			}
			else
			{
				char dtstr[64];

				SystemTime64ToJsonStr(dtstr, sizeof(dtstr), PackGetInt64Ex(p, e->name, index));
				JsonSetStr(o, name, dtstr);
			}
		}
		break;
	case VALUE_DATA:
		if (e->JsonHint_IsIP == false)
		{
			BUF *buf = PackGetBufEx(p, e->name, index);
			if (buf != NULL)
			{
				JsonSetData(o, name, buf->Buf, buf->Size);
				FreeBuf(buf);
			}
			else
			{
				UCHAR zero = 0;
				JsonSetData(o, name, &zero, 0);
			}
		}
		break;
	case VALUE_STR:
		if (e->JsonHint_IsIP == false)
		{
			if (e->values[index] != NULL)
			{
				JsonSetStr(o, name, e->values[index]->Str);
			}
			else
			{
				JsonSetStr(o, name, "");
			}
		}
		break;
	case VALUE_UNISTR:
		if (e->JsonHint_IsIP == false)
		{
			if (e->values[index] != NULL)
			{
				JsonSetUniStr(o, name, e->values[index]->UniStr);
			}
			else
			{
				JsonSetUniStr(o, name, L"");
			}
		}
		break;
	}
}

// Determine JSON element suffix for PACK element
char *DetermineJsonSuffixForPackElement(ELEMENT *e)
{
	switch (e->type)
	{
	case VALUE_INT:
		if (e->JsonHint_IsIP)
		{
			if (InStr(e->name, "@") == false)
			{
				return "_ip";
			}
		}
		else if (e->JsonHint_IsBool)
		{
			return "_bool";
		}
		else
		{
			return "_u32";
		}
		break;
	case VALUE_INT64:
		if (e->JsonHint_IsIP == false)
		{
			if (e->JsonHint_IsDateTime == false)
			{
				return "_u64";
			}
			else
			{
				return "_dt";
			}
		}
		break;
	case VALUE_DATA:
		if (e->JsonHint_IsIP == false)
		{
			return "_bin";
		}
		break;
	case VALUE_STR:
		if (e->JsonHint_IsIP == false)
		{
			return "_str";
		}
		break;
	case VALUE_UNISTR:
		if (e->JsonHint_IsIP == false)
		{
			return "_utf";
		}
		break;
	}

	return NULL;
}

// Convert JSON to PACK
PACK *JsonToPack(JSON_VALUE *v)
{
	PACK *p = NULL;
	JSON_OBJECT *jo;
	if (v == NULL)
	{
		return NULL;
	}

	p = NewPack();

	jo = JsonValueGetObject(v);

	if (jo != NULL)
	{
		UINT i;
		for (i = 0;i < jo->count;i++)
		{
			char *name = jo->names[i];
			JSON_VALUE *value = jo->values[i];

			if (value->type == JSON_TYPE_ARRAY)
			{
				UINT j;
				JSON_ARRAY *ja = value->value.array;

				for (j = 0;j < ja->count;j++)
				{
					if (ja->items[j]->type != JSON_TYPE_OBJECT)
					{
						JsonTryParseValueAddToPack(p, ja->items[j], name, j, ja->count, false);
					}
					else
					{
						JSON_VALUE *v = ja->items[j];
						JSON_OBJECT *o = v->value.object;
						UINT k;

						for (k = 0;k < o->count;k++)
						{
							char *name2 = o->names[k];
							JSON_VALUE *value2 = o->values[k];

							PackSetCurrentJsonGroupName(p, name);
							JsonTryParseValueAddToPack(p, value2, name2, j, ja->count, false);
							PackSetCurrentJsonGroupName(p, NULL);
						}
					}
				}
			}
			else
			{
				JsonTryParseValueAddToPack(p, value, name, 0, 1, true);
			}
		}
	}

	return p;
}

ELEMENT *ElementNullSafe(ELEMENT *p)
{
	static ELEMENT dummy;
	if (p == NULL)
	{
		Zero(&dummy, sizeof(dummy));
		return &dummy;
	}
	return p;
}

bool JsonTryParseValueAddToPack(PACK *p, JSON_VALUE *v, char *v_name, UINT index, UINT total, bool is_single)
{
	char name[MAX_PATH];
	bool ok = true;
	if (p == NULL || v == NULL)
	{
		return false;
	}

	if (TrimEndWith(name, sizeof(name), v_name, "_bool"))
	{
		if (v->type == JSON_TYPE_BOOL)
		{
			ElementNullSafe(PackAddBoolEx(p, name, MAKEBOOL(v->value.boolean), index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
		else if (v->type == JSON_TYPE_NUMBER)
		{
			ElementNullSafe(PackAddBoolEx(p, name, MAKEBOOL(v->value.number), index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
		else if (v->type == JSON_TYPE_STRING)
		{
			ElementNullSafe(PackAddBoolEx(p, name, ToBool(v->value.string), index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
	}
	else if (TrimEndWith(name, sizeof(name), v_name, "_u32"))
	{
		if (v->type == JSON_TYPE_BOOL)
		{
			ElementNullSafe(PackAddIntEx(p, name, MAKEBOOL(v->value.boolean), index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
		else if (v->type == JSON_TYPE_NUMBER)
		{
			ElementNullSafe(PackAddIntEx(p, name, (UINT)v->value.number, index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
		else if (v->type == JSON_TYPE_STRING)
		{
			ElementNullSafe(PackAddIntEx(p, name, ToInt(v->value.string), index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
	}
	else if (TrimEndWith(name, sizeof(name), v_name, "_u64"))
	{
		if (v->type == JSON_TYPE_BOOL)
		{
			ElementNullSafe(PackAddInt64Ex(p, name, MAKEBOOL(v->value.boolean), index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
		else if (v->type == JSON_TYPE_NUMBER)
		{
			ElementNullSafe(PackAddInt64Ex(p, name, v->value.number, index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
		else if (v->type == JSON_TYPE_STRING)
		{
			ElementNullSafe(PackAddInt64Ex(p, name, ToInt64(v->value.string), index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
	}
	else if (TrimEndWith(name, sizeof(name), v_name, "_str"))
	{
		if (v->type == JSON_TYPE_BOOL)
		{
			ElementNullSafe(PackAddStrEx(p, name, MAKEBOOL(v->value.boolean) ? "true" : "false", index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
		else if (v->type == JSON_TYPE_NUMBER)
		{
			char tmp[64];
			ToStr64(tmp, v->value.number);
			ElementNullSafe(PackAddStrEx(p, name, tmp, index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
		else if (v->type == JSON_TYPE_STRING)
		{
			ElementNullSafe(PackAddStrEx(p, name, v->value.string, index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
	}
	else if (TrimEndWith(name, sizeof(name), v_name, "_utf"))
	{
		if (v->type == JSON_TYPE_BOOL)
		{
			ElementNullSafe(PackAddUniStrEx(p, name, MAKEBOOL(v->value.boolean) ? L"true" : L"false", index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
		else if (v->type == JSON_TYPE_NUMBER)
		{
			char tmp[64];
			wchar_t tmp2[64];
			ToStr64(tmp, v->value.number);
			StrToUni(tmp2, sizeof(tmp2), tmp);
			ElementNullSafe(PackAddUniStrEx(p, name, tmp2, index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
		else if (v->type == JSON_TYPE_STRING)
		{
			wchar_t *uni = CopyUtfToUni(v->value.string);
			ElementNullSafe(PackAddUniStrEx(p, name, uni, index, total))->JsonHint_IsArray = !is_single;
			Free(uni);
			ok = true;
		}
	}
	else if (TrimEndWith(name, sizeof(name), v_name, "_bin"))
	{
		if (v->type == JSON_TYPE_STRING)
		{
			UINT len = StrLen(v->value.string);
			UCHAR *data = ZeroMalloc(len * 4 + 64);
			UINT size = B64_Decode(data, v->value.string, len);
			ElementNullSafe(PackAddDataEx(p, name, data, size, index, total))->JsonHint_IsArray = !is_single;
			Free(data);
			ok = true;
		}
	}
	else if (TrimEndWith(name, sizeof(name), v_name, "_dt"))
	{
		if (v->type == JSON_TYPE_NUMBER)
		{
			ElementNullSafe(PackAddInt64Ex(p, name, v->value.number, index, total))->JsonHint_IsArray = !is_single;
			ok = true;
		}
		else if (v->type == JSON_TYPE_STRING)
		{
			UINT64 time = DateTimeStrRFC3339ToSystemTime64(v->value.string);
			ELEMENT *e = PackAddInt64Ex(p, name, time, index, total);
			if (e != NULL)
			{
				e->JsonHint_IsArray = !is_single;
				e->JsonHint_IsDateTime = true;
			}
			ok = true;
		}
	}
	else if (TrimEndWith(name, sizeof(name), v_name, "_ip"))
	{
		if (v->type == JSON_TYPE_STRING)
		{
			IP ip;
			if (StrToIP(&ip, v->value.string))
			{
				PackAddIpEx2(p, name, &ip, index, total, is_single);
				ok = true;
			}
		}
	}

	return ok;
}

// Convert JSON string to PACK
PACK *JsonStrToPack(char *str)
{
	JSON_VALUE *v = StrToJson(str);
	PACK *ret;

	if (v == NULL)
	{
		return NULL;
	}

	ret = JsonToPack(v);

	JsonFree(v);

	return ret;
}

// Convert PACK to JSON string
char *PackToJsonStr(PACK *p)
{
	char *ret;
	JSON_VALUE *json = PackToJson(p);

	ret = JsonToStr(json);

	JsonFree(json);

	return ret;
}

// Convert PACK to JSON
JSON_VALUE *PackToJson(PACK *p)
{
	JSON_VALUE *v;
	JSON_OBJECT *o;
	UINT i, j, k;
	LIST *json_group_id_list;
	if (p == NULL)
	{
		return JsonNewObject();
	}

	json_group_id_list = NewStrList();

	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);

		if (e->num_value >= 2 || e->JsonHint_IsArray)
		{
			if (IsEmptyStr(e->JsonHint_GroupName) == false)
			{
				AddStrToStrListDistinct(json_group_id_list, e->JsonHint_GroupName);
			}
		}
	}

	for (i = 0;i < LIST_NUM(p->json_subitem_names);i++)
	{
		char *group_name = LIST_DATA(p->json_subitem_names, i);

		if (IsEmptyStr(group_name) == false)
		{
			AddStrToStrListDistinct(json_group_id_list, group_name);
		}
	}

	v = JsonNewObject();
	o = JsonValueGetObject(v);

	for (k = 0;k < LIST_NUM(json_group_id_list);k++)
	{
		char *group_name = LIST_DATA(json_group_id_list, k);
		UINT array_count = INFINITE;
		bool ok = true;

		for (i = 0;i < LIST_NUM(p->elements);i++)
		{
			ELEMENT *e = LIST_DATA(p->elements, i);

			if (e->num_value >= 2 || e->JsonHint_IsArray)
			{
				if (StrCmpi(e->JsonHint_GroupName, group_name) == 0)
				{
					if (array_count == INFINITE)
					{
						array_count = e->num_value;
					}
					else
					{
						if (array_count != e->num_value)
						{
							ok = false;
						}
					}
				}
			}
		}

		if (array_count == INFINITE)
		{
			array_count = 0;
		}

		if (ok)
		{
			JSON_VALUE **json_objects = ZeroMalloc(sizeof(void *) * array_count);
			JSON_VALUE *jav = JsonNewArray();
			JSON_ARRAY *ja = JsonArray(jav);

			JsonSet(o, group_name, jav);

			for (j = 0;j < array_count;j++)
			{
				json_objects[j] = JsonNewObject();

				JsonArrayAdd(ja, json_objects[j]);
			}

			for (i = 0;i < LIST_NUM(p->elements);i++)
			{
				ELEMENT *e = LIST_DATA(p->elements, i);

				if (e->num_value >= 2 || e->JsonHint_IsArray)
				{
					if (StrCmpi(e->JsonHint_GroupName, group_name) == 0)
					{
						for (j = 0;j < e->num_value;j++)
						{
							PackElementToJsonObject(JsonValueGetObject(json_objects[j]),
								p, e, j);
						}
					}
				}
			}

			Free(json_objects);
		}
	}

	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);

		if (e->num_value >= 2 || e->JsonHint_IsArray)
		{
			if (IsEmptyStr(e->JsonHint_GroupName))
			{
				char *suffix = DetermineJsonSuffixForPackElement(e);

				if (suffix != NULL)
				{
					JSON_VALUE *jav = JsonNewArray();
					JSON_ARRAY *ja = JsonArray(jav);
					char name[MAX_PATH];

					for (j = 0;j < e->num_value;j++)
					{
						PackArrayElementToJsonArray(ja, p, e, j);
					}

					StrCpy(name, sizeof(name), e->name);
					StrCat(name, sizeof(name), suffix);

					JsonSet(o, name, jav);
				}
			}
		}
		else if (e->num_value == 1)
		{
			PackElementToJsonObject(o, p, e, 0);
		}
	}

	ReleaseStrList(json_group_id_list);

	return v;
}




