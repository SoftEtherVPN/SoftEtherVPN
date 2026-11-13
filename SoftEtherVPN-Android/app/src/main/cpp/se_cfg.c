// SoftEther VPN for Android - CFG text bridge implementation (see se_cfg.h).

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Cfg.h"

#include "Cedar/Cedar.h"
#include "Cedar/Client.h"

#include "se_cfg.h"

FOLDER *SeCfgTextToRoot(const char *text)
{
	BUF *b;
	FOLDER *root;
	const char *p;

	if (text == NULL || text[0] == 0)
	{
		return NULL;
	}

	p = text;

	// Skip the UTF-8 BOM which CfgFolderToBufEx writes in the banner
	if (((UCHAR)p[0] == 0xEF) && ((UCHAR)p[1] == 0xBB) && ((UCHAR)p[2] == 0xBF))
	{
		p += 3;
	}

	b = NewBuf();
	WriteBuf(b, (void *)p, StrLen(p));
	SeekBuf(b, 0, 0);

	root = CfgBufTextToFolder(b);

	FreeBuf(b);

	return root;
}

char *SeCfgRootToText(FOLDER *root)
{
	BUF *b;
	char *ret;

	if (root == NULL)
	{
		return NULL;
	}

	b = CfgFolderToBufEx(root, true, false);
	if (b == NULL)
	{
		return NULL;
	}

	ret = Malloc(b->Size + 1);
	if (b->Size > 0)
	{
		Copy(ret, b->Buf, b->Size);
	}
	ret[b->Size] = 0;

	FreeBuf(b);

	return ret;
}

// Item value in its flat textual representation (malloc'ed, NULL on unknown type)
static char *SeCfgItemValue(ITEM *t)
{
	switch (t->Type)
	{
	case ITEM_TYPE_INT:
		{
			char *s = Malloc(32);
			ToStr(s, *((UINT *)t->Buf));
			return s;
		}
	case ITEM_TYPE_INT64:
		{
			char *s = Malloc(64);
			ToStr64(s, *((UINT64 *)t->Buf));
			return s;
		}
	case ITEM_TYPE_BOOL:
		return CopyStr(*((bool *)t->Buf) ? TAG_TRUE : TAG_FALSE);
	case ITEM_TYPE_BYTE:
		if (t->size == 0)
		{
			return CopyStr("0");
		}
		{
			char *b64 = Base64FromBin(NULL, t->Buf, t->size);

			if (b64 == NULL)
			{
				return CopyStr("0");
			}

			return CopyStr(b64);
		}
	case ITEM_TYPE_STRING:
		{
			UINT utf8_size = CalcUniToUtf8((wchar_t *)t->Buf) + 1;
			char *utf8 = ZeroMalloc(utf8_size);
			UniToUtf8((BYTE *)utf8, utf8_size, (wchar_t *)t->Buf);
			return utf8;
		}
	}
	return NULL;
}

static char *SeCfgJoinPath(const char *path, const char *name)
{
	char *ret;
	UINT size;

	size = StrLen(path) + StrLen(name) + 2;
	ret = Malloc(size);
	ret[0] = 0;
	StrCpy(ret, size, path);
	if (path[0] != 0)
	{
		StrCat(ret, size, "/");
	}
	StrCat(ret, size, name);

	return ret;
}

void SeCfgPushTriple(char ***arr, UINT *num, UINT *alloc, char *path, char *type, char *value)
{
	if (*num + 3 > *alloc)
	{
		UINT new_alloc = (*alloc == 0) ? 96 : (*alloc * 2);
		char **na = Malloc(sizeof(char *) * new_alloc);

		if (*arr != NULL)
		{
			Copy(na, *arr, sizeof(char *) * *num);
			Free(*arr);
		}

		*arr = na;
		*alloc = new_alloc;
	}

	(*arr)[*num] = CopyStr(path);
	(*arr)[*num + 1] = CopyStr(type);
	(*arr)[*num + 2] = CopyStr(value);
	*num += 3;
}

// depth-first walk: emits (path, type, value) string triples
void SeCfgFlatten(FOLDER *f, char *path, char ***arr, UINT *num, UINT *alloc)
{
	UINT i;

	for (i = 0; i < LIST_NUM(f->Items); i++)
	{
		ITEM *t = (ITEM *)LIST_DATA(f->Items, i);
		char *value = SeCfgItemValue(t);
		char *jp;

		if (value == NULL)
		{
			continue;
		}

		jp = SeCfgJoinPath(path, t->Name);
		SeCfgPushTriple(arr, num, alloc, jp, CfgTypeToStr(t->Type), value);
		Free(jp);
		Free(value);
	}

	for (i = 0; i < LIST_NUM(f->Folders); i++)
	{
		FOLDER *sub = (FOLDER *)LIST_DATA(f->Folders, i);
		char *jp = SeCfgJoinPath(path, sub->Name);

		SeCfgPushTriple(arr, num, alloc, jp, "folder", sub->Name);

		SeCfgFlatten(sub, jp, arr, num, alloc);

		Free(jp);
	}
}

// Walk 'path' (slash separated) below 'root', creating folders as needed
static FOLDER *SeCfgWalk(FOLDER *root, char *path, char *last_name, UINT path_len)
{
	FOLDER *cur = root;
	char seg[MAX_SIZE];
	UINT i;

	seg[0] = 0;

	for (i = 0; i <= path_len; i++)
	{
		char c = (i < path_len) ? path[i] : '/';

		if (c != '/')
		{
			UINT l = StrLen(seg);

			if (l < sizeof(seg) - 1)
			{
				seg[l] = c;
				seg[l + 1] = 0;
			}
		}
		else
		{
			FOLDER *nf;

			if (seg[0] == 0)
			{
				continue;
			}

			if (i == path_len && last_name != NULL)
			{
				// last segment is the item name
				StrCpy(last_name, MAX_SIZE, seg);
				seg[0] = 0;
				continue;
			}

			nf = CfgFindFolder(cur, seg);
			if (nf == NULL)
			{
				nf = CfgCreateFolder(cur, seg);
			}
			cur = nf;

			seg[0] = 0;
		}
	}

	return cur;
}

FOLDER *SeCfgFromTriples(char **t, UINT n)
{
	FOLDER *root, *parent;
	char root_name[MAX_SIZE];
	char path[MAX_SIZE];
	char name[MAX_SIZE];
	UINT i;

	root_name[0] = 0;

	for (i = 0; i + 2 < n; i += 3)
	{
		if (StrCmp(t[i + 1], "root") == 0)
		{
			StrCpy(root_name, sizeof(root_name), t[i + 2]);
			break;
		}
	}
	if (root_name[0] == 0)
	{
		StrCpy(root_name, sizeof(root_name), TAG_ROOT);
	}

	root = CfgCreateFolder(NULL, root_name);

	// pass 1: folders
	for (i = 0; i + 2 < n; i += 3)
	{
		if (StrCmp(t[i + 1], "folder") != 0)
		{
			continue;
		}

		StrCpy(path, sizeof(path), t[i]);
		SeCfgWalk(root, path, NULL, StrLen(path));
	}

	// pass 2: items
	for (i = 0; i + 2 < n; i += 3)
	{
		char *type = t[i + 1];
		char *value = t[i + 2];

		if (StrCmp(type, "folder") == 0 || StrCmp(type, "root") == 0)
		{
			continue;
		}

		StrCpy(path, sizeof(path), t[i]);
		name[0] = 0;

		parent = SeCfgWalk(root, path, name, StrLen(path));

		if (parent == NULL || name[0] == 0)
		{
			continue;
		}

		if (StrCmp(type, TAG_INT) == 0)
		{
			UINT v = ToInt(value);
			CfgCreateItem(parent, name, ITEM_TYPE_INT, &v, sizeof(UINT));
		}
		else if (StrCmp(type, TAG_INT64) == 0)
		{
			UINT64 v = ToInt64(value);
			CfgCreateItem(parent, name, ITEM_TYPE_INT64, &v, sizeof(UINT64));
		}
		else if (StrCmp(type, TAG_BOOL) == 0)
		{
			bool b = (StrCmpi(value, TAG_TRUE) == 0) || (ToInt(value) != 0);
			CfgCreateItem(parent, name, ITEM_TYPE_BOOL, &b, sizeof(bool));
		}
		else if (StrCmp(type, TAG_BYTE) == 0)
		{
			if (value[0] != 0 && StrCmp(value, "0") != 0)
			{
				UINT size = 0;
				void *bin = Base64ToBin(&size, value, StrLen(value));

				if (bin != NULL)
				{
					CfgCreateItem(parent, name, ITEM_TYPE_BYTE, bin, size);
					Free(bin);
				}
			}
		}
		else if (StrCmp(type, TAG_STRING) == 0)
		{
			UINT uni_size = CalcUtf8ToUni((BYTE *)value, StrLen(value));

			if (uni_size == 0)
			{
				wchar_t empty = 0;
				CfgCreateItem(parent, name, ITEM_TYPE_STRING, &empty, sizeof(wchar_t));
			}
			else
			{
				wchar_t *uni = Malloc(uni_size);
				Utf8ToUni(uni, uni_size, (BYTE *)value, StrLen(value));
				CfgCreateItem(parent, name, ITEM_TYPE_STRING, uni, uni_size);
				Free(uni);
			}
		}
	}

	return root;
}

// AndroidOptions string getter with NULL-folder tolerance
static bool SeCfgGetOpt(FOLDER *ao, char *name, char *dst, UINT size)
{
	return ao != NULL && CfgGetStr(ao, name, dst, size);
}

// Boolean option with a default for "key not present" (CFG bool items are
// typed natively; CfgGetStr does not read them, so CfgIsItem/CfgGetBool
// must be used)
static bool SeCfgGetBoolDef(FOLDER *ao, char *name, bool def_value)
{
	if (ao != NULL && CfgIsItem(ao, name))
	{
		return CfgGetBool(ao, name);
	}

	return def_value;
}

bool SeCfgLoadAccount(const char *text, ACCOUNT **acc_out, SE_NETCFG *n)
{
	FOLDER *root, *db, *acc, *ao;
	char tmp[MAX_SIZE];

	*acc_out = NULL;

	Zero(n, sizeof(SE_NETCFG));
	n->dhcp = true;
	n->use_v4 = true;
	n->use_v6 = false;

	root = SeCfgTextToRoot(text);
	if (root == NULL)
	{
		return false;
	}

	db = CfgGetFolder(root, "AccountDatabase");
	acc = (db != NULL && LIST_NUM(db->Folders) > 0) ? (FOLDER *)LIST_DATA(db->Folders, 0) : NULL;

	// CiLoadClientAccount requires "declare ClientOption" and "declare
	// ClientAuth" inside the account folder, and returns NULL without them
	if (acc == NULL)
	{
		CfgDeleteFolder(root);
		return false;
	}

	*acc_out = CiLoadClientAccount(acc);
	if (*acc_out == NULL)
	{
		CfgDeleteFolder(root);
		return false;
	}

	ao = CfgGetFolder(acc, "AndroidOptions");

	// IPv4 mode / enable flags (vpncmd VPN_IP / VPN_IP6 semantics; defaults:
	// IPv4 enabled, IPv6 disabled)
	if (SeCfgGetOpt(ao, "IPv4Mode", tmp, sizeof(tmp)))
	{
		n->dhcp = (StrCmp(tmp, "static") != 0);
	}

	n->use_v4 = SeCfgGetBoolDef(ao, "UseIPv4", true);
	n->use_v6 = SeCfgGetBoolDef(ao, "UseIPv6", false);

	if (SeCfgGetOpt(ao, "IPv6Mode", tmp, sizeof(tmp)))
	{
		n->v6_static = (StrCmp(tmp, "static") == 0);
	}

	// Static IPv4
	if (SeCfgGetOpt(ao, "StaticIp", tmp, sizeof(tmp)))
	{
		StrToIP(&n->ip, tmp);
	}
	if (SeCfgGetOpt(ao, "StaticMask", tmp, sizeof(tmp)))
	{
		StrToIP(&n->mask, tmp);
	}
	if (SeCfgGetOpt(ao, "StaticGw", tmp, sizeof(tmp)))
	{
		StrToIP(&n->gw, tmp);
	}
	if (SeCfgGetOpt(ao, "Dns1", tmp, sizeof(tmp)))
	{
		StrToIP(&n->dns1, tmp);
	}
	if (SeCfgGetOpt(ao, "Dns2", tmp, sizeof(tmp)))
	{
		StrToIP(&n->dns2, tmp);
	}

	// Static IPv6 (manual mode)
	if (SeCfgGetOpt(ao, "StaticIPv6", tmp, sizeof(tmp)))
	{
		StrToIP6(&n->v6ip, tmp);
	}
	if (SeCfgGetOpt(ao, "StaticMask6", tmp, sizeof(tmp)))
	{
		UINT plen = ToInt(tmp);

		if (plen == 0 || plen > 128)
		{
			plen = 64;
		}

		IntToSubnetMask6(&n->s6_mask, plen);
	}
	if (SeCfgGetOpt(ao, "StaticGw6", tmp, sizeof(tmp)))
	{
		StrToIP6(&n->s6_gw, tmp);
	}
	if (SeCfgGetOpt(ao, "StaticDns6", tmp, sizeof(tmp)))
	{
		StrToIP6(&n->s6_dns, tmp);
	}

	CfgDeleteFolder(root);

	return true;
}
