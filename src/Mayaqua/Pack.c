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
		if ((len + 1) > MAX_VALUE_SIZE)
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
	e = Malloc(sizeof(ELEMENT));
	StrCpy(e->name, sizeof(e->name), name);
	e->num_value = num_value;
	e->type = type;

	// Copy of the pointer list to the element
	e->values = (VALUE **)Malloc(sizeof(VALUE *) * num_value);
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

	ReleaseList(p->elements);
	Free(p);
}

// Create a PACK object
PACK *NewPack()
{
	PACK *p;

	// Memory allocation
	p = MallocEx(sizeof(PACK), true);

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
	FreeBuf(b);

	return x;
}

// Add the K to the PACK
void PackAddK(PACK *p, char *name, K *k)
{
	BUF *b;
	// Validate arguments
	if (p == NULL || name == NULL || k == NULL)
	{
		return;
	}

	b = KToBuf(k, false, NULL);
	if (b == NULL)
	{
		return;
	}

	PackAddBuf(p, name, b);
	FreeBuf(b);
}

// Add an X into the PACK
void PackAddX(PACK *p, char *name, X *x)
{
	BUF *b;
	// Validate arguments
	if (p == NULL || name == NULL || x == NULL)
	{
		return;
	}

	b = XToBuf(x, false);
	if (b == NULL)
	{
		return;
	}

	PackAddBuf(p, name, b);
	FreeBuf(b);
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

// Add a bool type into the PACK
void PackAddBool(PACK *p, char *name, bool b)
{
	PackAddInt(p, name, b ? 1 : 0);
}
void PackAddBoolEx(PACK *p, char *name, bool b, UINT index, UINT total)
{
	PackAddIntEx(p, name, b ? 1 : 0, index, total);
}

// Add the IPV6_ADDR to the PACK
void PackAddIp6AddrEx(PACK *p, char *name, IPV6_ADDR *addr, UINT index, UINT total)
{
	// Validate arguments
	if (p == NULL || name == NULL || addr == NULL)
	{
		return;
	}

	PackAddDataEx(p, name, addr, sizeof(IPV6_ADDR), index, total);
}
void PackAddIp6Addr(PACK *p, char *name, IPV6_ADDR *addr)
{
	PackAddIp6AddrEx(p, name, addr, 0, 1);
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
	IP ip;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return;
	}

	UINTToIP(&ip, ip32);

	PackAddIpEx(p, name, &ip, index, total);
}
void PackAddIp32(PACK *p, char *name, UINT ip32)
{
	PackAddIp32Ex(p, name, ip32, 0, 1);
}
void PackAddIpEx(PACK *p, char *name, IP *ip, UINT index, UINT total)
{
	UINT i;
	bool b = false;
	char tmp[MAX_PATH];
	// Validate arguments
	if (p == NULL || name == NULL || ip == NULL)
	{
		return;
	}

	b = IsIP6(ip);

	Format(tmp, sizeof(tmp), "%s@ipv6_bool", name);
	PackAddBoolEx(p, tmp, b, index, total);

	Format(tmp, sizeof(tmp), "%s@ipv6_array", name);
	if (b)
	{
		PackAddDataEx(p, tmp, ip->ipv6_addr, sizeof(ip->ipv6_addr), index, total);
	}
	else
	{
		UCHAR dummy[16];

		Zero(dummy, sizeof(dummy));

		PackAddDataEx(p, tmp, dummy, sizeof(dummy), index, total);
	}

	Format(tmp, sizeof(tmp), "%s@ipv6_scope_id", name);
	if (b)
	{
		PackAddIntEx(p, tmp, ip->ipv6_scope_id, index, total);
	}
	else
	{
		PackAddIntEx(p, tmp, 0, index, total);
	}

	i = IPToUINT(ip);

	if (IsBigEndian())
	{
		i = Swap32(i);
	}

	PackAddIntEx(p, name, i, index, total);
}
void PackAddIp(PACK *p, char *name, IP *ip)
{
	PackAddIpEx(p, name, ip, 0, 1);
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

// Add the buffer to the PACK (array)
void PackAddBufEx(PACK *p, char *name, BUF *b, UINT index, UINT total)
{
	// Validate arguments
	if (p == NULL || name == NULL || b == NULL || total == 0)
	{
		return;
	}

	PackAddDataEx(p, name, b->Buf, b->Size, index, total);
}

// Add the data to the PACK (array)
void PackAddDataEx(PACK *p, char *name, void *data, UINT size, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || data == NULL || name == NULL || total == 0)
	{
		return;
	}

	v = NewDataValue(data, size);
	e = GetElement(p, name, VALUE_DATA);
	if (e != NULL)
	{
		if (e->num_value <= total)
		{
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
		AddElement(p, e);
	}
}

// Add the buffer to the PACK
void PackAddBuf(PACK *p, char *name, BUF *b)
{
	// Validate arguments
	if (p == NULL || name == NULL || b == NULL)
	{
		return;
	}

	PackAddData(p, name, b->Buf, b->Size);
}

// Add the data to the PACK
void PackAddData(PACK *p, char *name, void *data, UINT size)
{
	VALUE *v;
	// Validate arguments
	if (p == NULL || data == NULL || name == NULL)
	{
		return;
	}

	v = NewDataValue(data, size);
	AddElement(p, NewElement(name, VALUE_DATA, 1, &v));
}

// Add a 64 bit integer (array) to the PACK
void PackAddInt64Ex(PACK *p, char *name, UINT64 i, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL || total == 0)
	{
		return;
	}

	v = NewInt64Value(i);
	e = GetElement(p, name, VALUE_INT64);
	if (e != NULL)
	{
		if (e->num_value <= total)
		{
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
		AddElement(p, e);
	}
}

// Add an integer to the PACK (array)
void PackAddIntEx(PACK *p, char *name, UINT i, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL || total == 0)
	{
		return;
	}

	v = NewIntValue(i);
	e = GetElement(p, name, VALUE_INT);
	if (e != NULL)
	{
		if (e->num_value <= total)
		{
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
		AddElement(p, e);
	}
}

// Add a 64 bit integer to the PACK
void PackAddInt64(PACK *p, char *name, UINT64 i)
{
	VALUE *v;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return;
	}

	v = NewInt64Value(i);
	AddElement(p, NewElement(name, VALUE_INT64, 1, &v));
}

// Add the number of items to the PACK
void PackAddNum(PACK *p, char *name, UINT num)
{
	PackAddInt(p, name, num);
}

// Add an integer to the PACK
void PackAddInt(PACK *p, char *name, UINT i)
{
	VALUE *v;
	// Validate arguments
	if (p == NULL || name == NULL)
	{
		return;
	}

	v = NewIntValue(i);
	AddElement(p, NewElement(name, VALUE_INT, 1, &v));
}

// Add a Unicode string (array) to the PACK
void PackAddUniStrEx(PACK *p, char *name, wchar_t *unistr, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL || unistr == NULL || total == 0)
	{
		return;
	}

	v = NewUniStrValue(unistr);
	e = GetElement(p, name, VALUE_UNISTR);
	if (e != NULL)
	{
		if (e->num_value <= total)
		{
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
		AddElement(p, e);
	}
}

// Add a Unicode string to the PACK
void PackAddUniStr(PACK *p, char *name, wchar_t *unistr)
{
	VALUE *v;
	// Validate arguments
	if (p == NULL || name == NULL || unistr == NULL)
	{
		return;
	}

	v = NewUniStrValue(unistr);
	AddElement(p, NewElement(name, VALUE_UNISTR, 1, &v));
}

// Add a string to the PACK (array)
void PackAddStrEx(PACK *p, char *name, char *str, UINT index, UINT total)
{
	VALUE *v;
	ELEMENT *e;
	// Validate arguments
	if (p == NULL || name == NULL || str == NULL || total == 0)
	{
		return;
	}

	v = NewStrValue(str);
	e = GetElement(p, name, VALUE_STR);
	if (e != NULL)
	{
		if (e->num_value <= total)
		{
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
		AddElement(p, e);
	}
}

// Add a string to the PACK
void PackAddStr(PACK *p, char *name, char *str)
{
	VALUE *v;
	// Validate arguments
	if (p == NULL || name == NULL || str == NULL)
	{
		return;
	}

	v = NewStrValue(str);
	AddElement(p, NewElement(name, VALUE_STR, 1, &v));
}



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
