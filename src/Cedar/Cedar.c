// SoftEther VPN Source Code
// Cedar Communication Module
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


// Cedar.c
// Cedar Communication Module


#include "CedarPch.h"

static UINT init_cedar_counter = 0;
static REF *cedar_log_ref = NULL;
static LOG *cedar_log;

// Get build date of current code
UINT64 GetCurrentBuildDate()
{
	SYSTEMTIME st;

	Zero(&st, sizeof(st));

	st.wYear = BUILD_DATE_Y;
	st.wMonth = BUILD_DATE_M;
	st.wDay = BUILD_DATE_D;
	st.wHour = BUILD_DATE_HO;
	st.wMinute = BUILD_DATE_MI;
	st.wSecond = BUILD_DATE_SE;

	return SystemToUINT64(&st);
}

// Check current windows version is supported
bool IsSupportedWinVer(RPC_WINVER *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return false;
	}

	if (v->IsWindows == false)
	{
		return true;
	}

	if (v->IsNT == false)
	{
		return true;
	}

	if (v->IsBeta)
	{
		return true;
	}

	if (v->VerMajor <= 4)
	{
		// Windows NT
		return true;
	}

	if (v->VerMajor == 5 && v->VerMinor == 0)
	{
		// Windows 2000
		if (v->ServicePack <= 4)
		{
			// SP4 or earlier
			return true;
		}
	}

	if (v->VerMajor == 5 && v->VerMinor == 1)
	{
		// Windows XP x86
		if (v->ServicePack <= 3)
		{
			// SP3 or earlier
			return true;
		}
	}

	if (v->VerMajor == 5 && v->VerMinor == 2)
	{
		// Windows XP x64, Windows Server 2003
		if (v->ServicePack <= 2)
		{
			// SP2 or earlier
			return true;
		}
	}

	if (v->VerMajor == 6 && v->VerMinor == 0)
	{
		// Windows Vista, Server 2008
		if (v->ServicePack <= 2)
		{
			// SP2 or earlier
			return true;
		}
	}

	if (v->VerMajor == 6 && v->VerMinor == 1)
	{
		// Windows 7, Server 2008 R2
		if (v->ServicePack <= 1)
		{
			// SP1 or earlier
			return true;
		}
	}

	if (v->VerMajor == 6 && v->VerMinor == 2)
	{
		// Windows 8, Server 2012
		if (v->ServicePack <= 0)
		{
			// SP0 only
			return true;
		}
	}

	if (v->VerMajor == 6 && v->VerMinor == 3)
	{
		// Windows 8.1, Server 2012 R2
		if (v->ServicePack <= 0)
		{
			// SP0 only
			return true;
		}
	}

#if	0
	// Enable in future when supported
	if ((v->VerMajor == 6 && v->VerMinor == 4) ||(v->VerMajor == 10 && v->VerMinor == 0))
	{
		// Windows 10, Server 10
		if (v->ServicePack <= 0)
		{
			// SP0 only
			return true;
		}
	}
#endif

	return false;
}

// Get version of Windows
void GetWinVer(RPC_WINVER *v)
{
	// Validate arguments
	if (v == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32GetWinVer(v);
#else	// OS_WIN32
	Zero(v, sizeof(RPC_WINVER));
	StrCpy(v->Title, sizeof(v->Title), GetOsInfo()->OsProductName);
#endif	// OS_WIN32
}

// Close tiny log
void FreeTinyLog(TINY_LOG *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	FileClose(t->io);
	DeleteLock(t->Lock);
	Free(t);
}

// Write to tiny log
void WriteTinyLog(TINY_LOG *t, char *str)
{
	BUF *b;
	char dt[MAX_PATH];
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	GetDateTimeStrMilli64(dt, sizeof(dt), LocalTime64());
	StrCat(dt, sizeof(dt), ": ");

	b = NewBuf();

	WriteBuf(b, dt, StrLen(dt));
	WriteBuf(b, str, StrLen(str));
	WriteBuf(b, "\r\n", 2);

	Lock(t->Lock);
	{
		FileWrite(t->io, b->Buf, b->Size);
		//FileFlush(t->io);
	}
	Unlock(t->Lock);

	FreeBuf(b);
}

// Initialize tiny log
TINY_LOG *NewTinyLog()
{
	char name[MAX_PATH];
	SYSTEMTIME st;
	TINY_LOG *t;

	LocalTime(&st);

	MakeDir(TINY_LOG_DIRNAME);

	Format(name, sizeof(name), TINY_LOG_FILENAME,
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	t = ZeroMalloc(sizeof(TINY_LOG));

	StrCpy(t->FileName, sizeof(t->FileName), name);
	t->io = FileCreate(name);
	t->Lock = NewLock();

	return t;
}

// Compare entries of No-SSL connection list
int CompareNoSslList(void *p1, void *p2)
{
	NON_SSL *n1, *n2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	n1 = *(NON_SSL **)p1;
	n2 = *(NON_SSL **)p2;
	if (n1 == NULL || n2 == NULL)
	{
		return 0;
	}
	return CmpIpAddr(&n1->IpAddress, &n2->IpAddress);
}

// Check whether the specified IP address is in Non-SSL connection list
bool IsInNoSsl(CEDAR *c, IP *ip)
{
	bool ret = false;
	// Validate arguments
	if (c == NULL || ip == NULL)
	{
		return false;
	}

	LockList(c->NonSslList);
	{
		NON_SSL *n = SearchNoSslList(c, ip);

		if (n != NULL)
		{
			if (n->EntryExpires > Tick64() && n->Count > NON_SSL_MIN_COUNT)
			{
				n->EntryExpires = Tick64() + (UINT64)NON_SSL_ENTRY_EXPIRES;
				ret = true;
			}
		}
	}
	UnlockList(c->NonSslList);

	return ret;
}

// Decrement connection count of Non-SSL connection list entry 
void DecrementNoSsl(CEDAR *c, IP *ip, UINT num_dec)
{
	// Validate arguments
	if (c == NULL || ip == NULL)
	{
		return;
	}

	LockList(c->NonSslList);
	{
		NON_SSL *n = SearchNoSslList(c, ip);

		if (n != NULL)
		{
			if (n->Count >= num_dec)
			{
				n->Count -= num_dec;
			}
		}
	}
	UnlockList(c->NonSslList);
}

// Add new entry to Non-SSL connection list
bool AddNoSsl(CEDAR *c, IP *ip)
{
	NON_SSL *n;
	bool ret = true;
	// Validate arguments
	if (c == NULL || ip == NULL)
	{
		return true;
	}

	LockList(c->NonSslList);
	{
		DeleteOldNoSsl(c);

		n = SearchNoSslList(c, ip);

		if (n == NULL)
		{
			n = ZeroMalloc(sizeof(NON_SSL));
			Copy(&n->IpAddress, ip, sizeof(IP));
			n->Count = 0;

			Add(c->NonSslList, n);
		}

		n->EntryExpires = Tick64() + (UINT64)NON_SSL_ENTRY_EXPIRES;

		n->Count++;

		if (n->Count > NON_SSL_MIN_COUNT)
		{
			ret = false;
		}
	}
	UnlockList(c->NonSslList);

	return ret;
}

// Delete old entries in Non-SSL connection list
void DeleteOldNoSsl(CEDAR *c)
{
	UINT i;
	LIST *o;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	for (i = 0;i < LIST_NUM(c->NonSslList);i++)
	{
		NON_SSL *n = LIST_DATA(c->NonSslList, i);

		if (n->EntryExpires <= Tick64())
		{
			Add(o, n);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		NON_SSL *n = LIST_DATA(o, i);

		Delete(c->NonSslList, n);
		Free(n);
	}

	ReleaseList(o);
}

// Search entry in Non-SSL connection list
NON_SSL *SearchNoSslList(CEDAR *c, IP *ip)
{
	NON_SSL *n, t;
	// Validate arguments
	if (c == NULL || ip == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	Copy(&t.IpAddress, ip, sizeof(IP));

	n = Search(c->NonSslList, &t);

	if (n == NULL)
	{
		return NULL;
	}

	return n;
}

// Initialize Non-SSL connection list
void InitNoSslList(CEDAR *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	c->NonSslList = NewList(CompareNoSslList);
}

// Free Non-SSL connection list
void FreeNoSslList(CEDAR *c)
{
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(c->NonSslList);i++)
	{
		NON_SSL *n = LIST_DATA(c->NonSslList, i);

		Free(n);
	}

	ReleaseList(c->NonSslList);
	c->NonSslList = NULL;
}

// Write a message into Cedar log
void CedarLog(char *str)
{
	char *tmp;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}
	if (cedar_log_ref == NULL)
	{
		return;
	}

	tmp = CopyStr(str);

	if (StrLen(tmp) > 1)
	{
		if (tmp[StrLen(tmp) - 1] == '\n')
		{
			tmp[StrLen(tmp) - 1] = 0;
		}
		if (StrLen(tmp) > 1)
		{
			if (tmp[StrLen(tmp) - 1] == '\r')
			{
				tmp[StrLen(tmp) - 1] = 0;
			}
		}
	}

	InsertStringRecord(cedar_log, tmp);

	Free(tmp);
}

// Start Cedar log
void StartCedarLog()
{
	if (cedar_log_ref == NULL)
	{
		cedar_log_ref = NewRef();
	}
	else
	{
		AddRef(cedar_log_ref);
	}

	cedar_log = NewLog("debug_log", "debug", LOG_SWITCH_DAY);
}

// Stop Cedar log
void StopCedarLog()
{
	if (cedar_log_ref == NULL)
	{
		return;
	}

	if (Release(cedar_log_ref) == 0)
	{
		FreeLog(cedar_log);
		cedar_log = NULL;
		cedar_log_ref = NULL;
	}
}


// Get sum of traffic data size
UINT64 GetTrafficPacketSize(TRAFFIC *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return 0;
	}

	return t->Recv.BroadcastBytes + t->Recv.UnicastBytes +
		t->Send.BroadcastBytes + t->Send.UnicastBytes;
}

// Get sum of the number of packets in traffic
UINT64 GetTrafficPacketNum(TRAFFIC *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return 0;
	}

	return t->Recv.BroadcastCount + t->Recv.UnicastCount +
		t->Send.BroadcastCount + t->Send.UnicastCount;
}

// Get whether hidden password is changed in UI
bool IsHiddenPasswordChanged(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return true;
	}

	if (StrCmpi(str, HIDDEN_PASSWORD) == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Initialize hidden password in UI
void InitHiddenPassword(char *str, UINT size)
{
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	StrCpy(str, size, HIDDEN_PASSWORD);
}

// Check whether the certificate is signed by CA which is trusted by the hub 
bool CheckSignatureByCaLinkMode(SESSION *s, X *x)
{
	LINK *k;
	HUB *h;
	bool ret = false;
	// Validate arguments
	if (s == NULL || x == NULL)
	{
		return false;
	}

	if (s->LinkModeClient == false || (k = s->Link) == NULL)
	{
		return false;
	}

	h = k->Hub;

	if (h->HubDb != NULL)
	{
		LockList(h->HubDb->RootCertList);
		{
			X *root_cert;
			root_cert = GetIssuerFromList(h->HubDb->RootCertList, x);
			if (root_cert != NULL)
			{
				ret = true;
			}
		}
		UnlockList(h->HubDb->RootCertList);
	}

	return ret;
}

// Check whether the certificate is signed by CA which is trusted by Cedar
bool CheckSignatureByCa(CEDAR *cedar, X *x)
{
	X *ca;
	// Validate arguments
	if (cedar == NULL || x == NULL)
	{
		return false;
	}

	// Get the CA which signed the certificate
	ca = FindCaSignedX(cedar->CaList, x);
	if (ca == NULL)
	{
		// Not found
		return false;
	}

	// Found
	FreeX(ca);
	return true;
}

// Get the CA which signed the certificate
X *FindCaSignedX(LIST *o, X *x)
{
	X *ret;
	// Validate arguments
	if (o == NULL || x == NULL)
	{
		return NULL;
	}

	ret = NULL;

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			X *ca = LIST_DATA(o, i);
			if (CheckXDateNow(ca))
			{
				if (CompareName(ca->subject_name, x->issuer_name))
				{
					K *k = GetKFromX(ca);
					if (k != NULL)
					{
						if (CheckSignature(x, k))
						{
							ret = CloneX(ca);
						}
						FreeK(k);
					}
				}
				else if (CompareX(ca, x))
				{
					ret = CloneX(ca);
				}
			}

			if (ret != NULL)
			{
				break;
			}
		}
	}
	UnlockList(o);

	return ret;
}

// Delete trusted CA from Cedar
bool DeleteCa(CEDAR *cedar, UINT ptr)
{
	bool b = false;
	// Validate arguments
	if (cedar == NULL || ptr == 0)
	{
		return false;
	}

	LockList(cedar->CaList);
	{
		UINT i;

		for (i = 0;i < LIST_NUM(cedar->CaList);i++)
		{
			X *x = LIST_DATA(cedar->CaList, i);

			if (POINTER_TO_KEY(x) == ptr)
			{
				Delete(cedar->CaList, x);
				FreeX(x);

				b = true;

				break;
			}
		}
	}
	UnlockList(cedar->CaList);

	return b;
}

// Add trusted CA to Cedar
void AddCa(CEDAR *cedar, X *x)
{
	// Validate arguments
	if (cedar == NULL || x == NULL)
	{
		return;
	}

	LockList(cedar->CaList);
	{
		UINT i;
		bool ok = true;

		for (i = 0;i < LIST_NUM(cedar->CaList);i++)
		{
			X *exist_x = LIST_DATA(cedar->CaList, i);
			if (CompareX(exist_x, x))
			{
				ok = false;
				break;
			}
		}

		if (ok)
		{
			Insert(cedar->CaList, CloneX(x));
		}
	}
	UnlockList(cedar->CaList);
}

// Delete connection from Cedar
void DelConnection(CEDAR *cedar, CONNECTION *c)
{
	// Validate arguments
	if (cedar == NULL || c == NULL)
	{
		return;
	}

	LockList(cedar->ConnectionList);
	{
		Debug("Connection %s Deleted from Cedar.\n", c->Name);
		if (Delete(cedar->ConnectionList, c))
		{
			ReleaseConnection(c);
		}
	}
	UnlockList(cedar->ConnectionList);
}

// Get the number of unestablished connections
UINT GetUnestablishedConnections(CEDAR *cedar)
{
	UINT i, ret;
	// Validate arguments
	if (cedar == NULL)
	{
		return 0;
	}

	ret = 0;

	LockList(cedar->ConnectionList);
	{
		for (i = 0;i < LIST_NUM(cedar->ConnectionList);i++)
		{
			CONNECTION *c = LIST_DATA(cedar->ConnectionList, i);

			switch (c->Type)
			{
			case CONNECTION_TYPE_CLIENT:
			case CONNECTION_TYPE_INIT:
			case CONNECTION_TYPE_LOGIN:
			case CONNECTION_TYPE_ADDITIONAL:
				switch (c->Status)
				{
				case CONNECTION_STATUS_ACCEPTED:
				case CONNECTION_STATUS_NEGOTIATION:
				case CONNECTION_STATUS_USERAUTH:
					ret++;
					break;
				}
				break;
			}
		}
	}
	UnlockList(cedar->ConnectionList);

	return ret + Count(cedar->AcceptingSockets);
}

// Add connection to Cedar
void AddConnection(CEDAR *cedar, CONNECTION *c)
{
	char tmp[MAX_SIZE];
	UINT i;
	// Validate arguments
	if (cedar == NULL || c == NULL)
	{
		return;
	}

	// Determine the name of the connection
	i = Inc(cedar->ConnectionIncrement);
	Format(tmp, sizeof(tmp), "CID-%u", i);


	Lock(c->lock);
	{
		Free(c->Name);
		c->Name = CopyStr(tmp);
	}
	Unlock(c->lock);

	LockList(cedar->ConnectionList);
	{
		Add(cedar->ConnectionList, c);
		AddRef(c->ref);
		Debug("Connection %s Inserted to Cedar.\n", c->Name);
	}
	UnlockList(cedar->ConnectionList);
}

// Stop all connections
void StopAllConnection(CEDAR *c)
{
	UINT num;
	UINT i;
	CONNECTION **connections;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	LockList(c->ConnectionList);
	{
		connections = ToArray(c->ConnectionList);
		num = LIST_NUM(c->ConnectionList);
		DeleteAll(c->ConnectionList);
	}
	UnlockList(c->ConnectionList);

	for (i = 0;i < num;i++)
	{
		StopConnection(connections[i], false);
		ReleaseConnection(connections[i]);
	}
	Free(connections);
}

// Delete a hub in Cedar
void DelHub(CEDAR *c, HUB *h)
{
	DelHubEx(c, h, false);
}
void DelHubEx(CEDAR *c, HUB *h, bool no_lock)
{
	// Validate arguments
	if (c == NULL || h == NULL)
	{
		return;
	}

	if (no_lock == false)
	{
		LockHubList(c);
	}

	if (Delete(c->HubList, h))
	{
		ReleaseHub(h);
	}

	if (no_lock == false)
	{
		UnlockHubList(c);
	}
}

// Add a new hub to Cedar
void AddHub(CEDAR *c, HUB *h)
{
	// Validate arguments
	if (c == NULL || h == NULL)
	{
		return;
	}

	LockHubList(c);
	{
#if	0
		// We shall not check here the number of hub
		if (LIST_NUM(c->HubList) >= MAX_HUBS)
		{
			// over limit
			UnlockHubList(c);
			return;
		}
#endif

		// Confirm there is no hub which have same name
		if (IsHub(c, h->Name))
		{
			// exist
			UnlockHubList(c);
			return;
		}

		// Register the hub
		Insert(c->HubList, h);
		AddRef(h->ref);
	}
	UnlockHubList(c);
}

// Stop all hubs in Cedar
void StopAllHub(CEDAR *c)
{
	HUB **hubs;
	UINT i, num;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	LockHubList(c);
	{
		hubs = ToArray(c->HubList);
		num = LIST_NUM(c->HubList);
		DeleteAll(c->HubList);
	}
	UnlockHubList(c);

	for (i = 0;i < num;i++)
	{
		StopHub(hubs[i]);
		ReleaseHub(hubs[i]);
	}

	Free(hubs);
}

// Get reverse listener socket in Cedar
SOCK *GetReverseListeningSock(CEDAR *c)
{
	SOCK *s = NULL;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	LockList(c->ListenerList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(c->ListenerList);i++)
		{
			LISTENER *r = LIST_DATA(c->ListenerList, i);

			if (r->Protocol == LISTENER_REVERSE)
			{
				Lock(r->lock);
				{
					s = r->Sock;

					AddRef(s->ref);
				}
				Unlock(r->lock);
				break;
			}
		}
	}
	UnlockList(c->ListenerList);

	return s;
}

// Get in-process listener socket in Cedar
SOCK *GetInProcListeningSock(CEDAR *c)
{
	SOCK *s = NULL;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	LockList(c->ListenerList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(c->ListenerList);i++)
		{
			LISTENER *r = LIST_DATA(c->ListenerList, i);

			if (r->Protocol == LISTENER_INPROC)
			{
				Lock(r->lock);
				{
					s = r->Sock;

					if (s != NULL)
					{
						AddRef(s->ref);
					}
				}
				Unlock(r->lock);
				break;
			}
		}
	}
	UnlockList(c->ListenerList);

	return s;
}

// Add a new listener to Cedar
void AddListener(CEDAR *c, LISTENER *r)
{
	// Validate arguments
	if (c == NULL || r == NULL)
	{
		return;
	}

	LockList(c->ListenerList);
	{
		Add(c->ListenerList, r);
		AddRef(r->ref);
	}
	UnlockList(c->ListenerList);
}

// Stop all listener in Cedar
void StopAllListener(CEDAR *c)
{
	LISTENER **array;
	UINT i, num;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	LockList(c->ListenerList);
	{
		array = ToArray(c->ListenerList);
		num = LIST_NUM(c->ListenerList);
		DeleteAll(c->ListenerList);
	}
	UnlockList(c->ListenerList);

	for (i = 0;i < num;i++)
	{
		StopListener(array[i]);
		ReleaseListener(array[i]);
	}
	Free(array);
}

// Budget management functions
void CedarAddQueueBudget(CEDAR *c, int diff)
{
	// Validate arguments
	if (c == NULL || diff == 0)
	{
		return;
	}

	Lock(c->QueueBudgetLock);
	{
		int v = (int)c->QueueBudget;
		v += diff;
		c->QueueBudget = (UINT)v;
	}
	Unlock(c->QueueBudgetLock);
}
void CedarAddFifoBudget(CEDAR *c, int diff)
{
	// Validate arguments
	if (c == NULL || diff == 0)
	{
		return;
	}

	Lock(c->FifoBudgetLock);
	{
		int v = (int)c->FifoBudget;
		v += diff;
		c->FifoBudget = (UINT)v;
	}
	Unlock(c->FifoBudgetLock);
}
UINT CedarGetQueueBudgetConsuming(CEDAR *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return 0;
	}

	return c->QueueBudget;
}
UINT CedarGetFifoBudgetConsuming(CEDAR *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return 0;
	}

	return c->FifoBudget;
}
UINT CedarGetQueueBudgetBalance(CEDAR *c)
{
	UINT current = CedarGetQueueBudgetConsuming(c);
	UINT budget = QUEUE_BUDGET;

	if (current <= budget)
	{
		return budget - current;
	}
	else
	{
		return 0;
	}
}
UINT CedarGetFifoBudgetBalance(CEDAR *c)
{
	UINT current = CedarGetFifoBudgetConsuming(c);
	UINT budget = FIFO_BUDGET;

	if (current <= budget)
	{
		return budget - current;
	}
	else
	{
		return 0;
	}
}

// Add the current TCP queue size
void CedarAddCurrentTcpQueueSize(CEDAR *c, int diff)
{
	// Validate arguments
	if (c == NULL || diff == 0)
	{
		return;
	}

	Lock(c->CurrentTcpQueueSizeLock);
	{
		int v = (int)c->CurrentTcpQueueSize;
		v += diff;
		c->CurrentTcpQueueSize = (UINT)v;
	}
	Unlock(c->CurrentTcpQueueSizeLock);
}

// Get the current TCP queue size
UINT CedarGetCurrentTcpQueueSize(CEDAR *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return 0;
	}

	return c->CurrentTcpQueueSize;
}

// Stop Cedar
void StopCedar(CEDAR *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Stop flag
	c->Halt = true;

	// Stop all listener
	StopAllListener(c);
	// Stop all connections
	StopAllConnection(c);
	// Stop all hubs
	StopAllHub(c);
	// Free all virtual L3 switch
	L3FreeAllSw(c);
}

// Clean up Cedar
void CleanupCedar(CEDAR *c)
{
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	WuFreeWebUI(c->WebUI);
	FreeCedarLayer3(c);

/*
	for (i = 0;i < LIST_NUM(c->HubList);i++)
	{
		HUB *h = LIST_DATA(c->HubList, i);
	}
*/
	for (i = 0;i < LIST_NUM(c->CaList);i++)
	{
		X *x = LIST_DATA(c->CaList, i);
		FreeX(x);
	}
	ReleaseList(c->CaList);

	ReleaseList(c->ListenerList);
	ReleaseList(c->HubList);
	ReleaseList(c->ConnectionList);
	//CleanupUDPEntry(c);
	ReleaseList(c->UDPEntryList);
	DeleteLock(c->lock);
	DeleteCounter(c->ConnectionIncrement);
	DeleteCounter(c->CurrentSessions);

	if (c->DebugLog != NULL)
	{
		FreeLog(c->DebugLog);
	}

	if (c->ServerX)
	{
		FreeX(c->ServerX);
	}
	if (c->ServerK)
	{
		FreeK(c->ServerK);
	}

	if (c->CipherList)
	{
		Free(c->CipherList);
	}

	for (i = 0;i < LIST_NUM(c->TrafficDiffList);i++)
	{
		TRAFFIC_DIFF *d = LIST_DATA(c->TrafficDiffList, i);
		Free(d->Name);
		Free(d->HubName);
		Free(d);
	}

	ReleaseList(c->TrafficDiffList);

	Free(c->ServerStr);
	Free(c->MachineName);

	Free(c->HttpUserAgent);
	Free(c->HttpAccept);
	Free(c->HttpAcceptLanguage);
	Free(c->HttpAcceptEncoding);

	FreeTraffic(c->Traffic);

	DeleteLock(c->TrafficLock);

	FreeNetSvcList(c);

	Free(c->VerString);
	Free(c->BuildInfo);

	FreeLocalBridgeList(c);

	DeleteCounter(c->AssignedBridgeLicense);
	DeleteCounter(c->AssignedClientLicense);

	FreeNoSslList(c);

	DeleteLock(c->CedarSuperLock);

	DeleteCounter(c->AcceptingSockets);

	ReleaseIntList(c->UdpPortList);

	DeleteLock(c->OpenVPNPublicPortsLock);

	DeleteLock(c->CurrentRegionLock);

	DeleteLock(c->CurrentTcpQueueSizeLock);
	DeleteLock(c->QueueBudgetLock);
	DeleteLock(c->FifoBudgetLock);

	DeleteCounter(c->CurrentActiveLinks);

	Free(c);
}

// Release reference of the Cedar
void ReleaseCedar(CEDAR *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		CleanupCedar(c);
	}
}

// Set cipher list entry
void SetCedarCipherList(CEDAR *cedar, char *name)
{
	// Validate arguments
	if (cedar == NULL)
	{
		return;
	}

	if (cedar->CipherList != NULL)
	{
		Free(cedar->CipherList);
	}
	if (name != NULL)
	{
		cedar->CipherList = CopyStr(name);
	}
	else
	{
		cedar->CipherList = NULL;
	}
}

// Compare net service list entries
int CompareNetSvc(void *p1, void *p2)
{
	NETSVC *n1, *n2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	n1 = *(NETSVC **)p1;
	n2 = *(NETSVC **)p2;
	if (n1 == NULL || n2 == NULL)
	{
		return 0;
	}
	if (n1->Port > n2->Port)
	{
		return 1;
	}
	else if (n1->Port < n2->Port)
	{
		return -1;
	}
	else if (n1->Udp > n2->Udp)
	{
		return 1;
	}
	else if (n1->Udp < n2->Udp)
	{
		return -1;
	}
	return 0;
}

// Initialize net service list
void InitNetSvcList(CEDAR *cedar)
{
	char filename[MAX_PATH] = "/etc/services";
	BUF *b;
	// Validate arguments
	if (cedar == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Format(filename, sizeof(filename), "%s\\drivers\\etc\\services", MsGetSystem32Dir());
#endif

	cedar->NetSvcList = NewList(CompareNetSvc);

	b = ReadDump(filename);
	if (b == NULL)
	{
		return;
	}

	while (true)
	{
		char *s = CfgReadNextLine(b);
		if (s == NULL)
		{
			break;
		}

		Trim(s);
		if (s[0] != '#')
		{
			TOKEN_LIST *t = ParseToken(s, " \t/");
			if (t->NumTokens >= 3)
			{
				NETSVC *n = ZeroMalloc(sizeof(NETSVC));
				n->Name = CopyStr(t->Token[0]);
				n->Udp = (StrCmpi(t->Token[2], "udp") == 0 ? true : false);
				n->Port = ToInt(t->Token[1]);
				Add(cedar->NetSvcList, n);
			}
			FreeToken(t);
		}
		Free(s);
	}

	FreeBuf(b);
}

// Get net service name
char *GetSvcName(CEDAR *cedar, bool udp, UINT port)
{
	char *ret = NULL;
	NETSVC t;
	// Validate arguments
	if (cedar == NULL)
	{
		return NULL;
	}

	t.Udp = (udp == 0 ? false : true);
	t.Port = port;

	LockList(cedar->NetSvcList);
	{
		NETSVC *n = Search(cedar->NetSvcList, &t);
		if (n != NULL)
		{
			ret = n->Name;
		}
	}
	UnlockList(cedar->NetSvcList);

	return ret;
}

// Free net service list
void FreeNetSvcList(CEDAR *cedar)
{
	UINT i;
	// Validate arguments
	if (cedar == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(cedar->NetSvcList);i++)
	{
		NETSVC *n = LIST_DATA(cedar->NetSvcList, i);
		Free(n->Name);
		Free(n);
	}
	ReleaseList(cedar->NetSvcList);
}

// Change certificate of Cedar
void SetCedarCert(CEDAR *c, X *server_x, K *server_k)
{
	// Validate arguments
	if (server_x == NULL || server_k == NULL)
	{
		return;
	}

	Lock(c->lock);
	{
		if (c->ServerX != NULL)
		{
			FreeX(c->ServerX);
		}

		if (c->ServerK != NULL)
		{
			FreeK(c->ServerK);
		}

		c->ServerX = CloneX(server_x);
		c->ServerK = CloneK(server_k);
	}
	Unlock(c->lock);
}

// Enable debug log
void EnableDebugLog(CEDAR *c)
{
	// Validate arguments
	if (c == NULL || c->DebugLog != NULL)
	{
		return;
	}

	c->DebugLog = NewLog("cedar_debug_log", "cedar", LOG_SWITCH_NO);
}

// Set the Cedar into VPN Bridge mode
void SetCedarVpnBridge(CEDAR *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	c->Bridge = true;

	Free(c->ServerStr);
	c->ServerStr = CopyStr(CEDAR_BRIDGE_STR);
}

void CedarForceLink()
{
}

// Get version of the Cedar
void GetCedarVersion(char *tmp, UINT size)
{
	// Validate arguments
	if (tmp == NULL)
	{
		return;
	}

	Format(tmp, size, "%u.%02u.%u",
		CEDAR_VER / 100, CEDAR_VER - (CEDAR_VER / 100) * 100,
		CEDAR_BUILD);
}

// Create Cedar object
CEDAR *NewCedar(X *server_x, K *server_k)
{
	CEDAR *c;
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	char *beta_str;

	CedarForceLink();

	c = ZeroMalloc(sizeof(CEDAR));

	c->CurrentActiveLinks = NewCounter();

	c->AcceptingSockets = NewCounter();

	c->CedarSuperLock = NewLock();

	c->CurrentRegionLock = NewLock();

	StrCpy(c->OpenVPNDefaultClientOption, sizeof(c->OpenVPNDefaultClientOption), OVPN_DEF_CLIENT_OPTION_STRING);

#ifdef	BETA_NUMBER
	c->Beta = BETA_NUMBER;
#endif	// BETA_NUMBER

	InitNoSslList(c);

	c->AssignedBridgeLicense = NewCounter();
	c->AssignedClientLicense = NewCounter();

	c->CurrentTcpQueueSizeLock = NewLock();
	c->QueueBudgetLock = NewLock();
	c->FifoBudgetLock = NewLock();

	Rand(c->UniqueId, sizeof(c->UniqueId));

	c->CreatedTick = Tick64();

	c->lock = NewLock();
	c->ref = NewRef();

	c->OpenVPNPublicPortsLock = NewLock();
	c->CurrentTcpConnections = GetNumTcpConnectionsCounter();

	c->ListenerList = NewList(CompareListener);
	c->UDPEntryList = NewList(CompareUDPEntry);
	c->HubList = NewList(CompareHub);
	c->ConnectionList = NewList(CompareConnection);

	c->ConnectionIncrement = NewCounter();
	c->CurrentSessions = NewCounter();

	if (server_k && server_x)
	{
		c->ServerK = CloneK(server_k);
		c->ServerX = CloneX(server_x);
	}

	c->Version = CEDAR_VER;
	c->Build = CEDAR_BUILD;
	c->ServerStr = CopyStr(CEDAR_SERVER_STR);

	GetMachineName(tmp, sizeof(tmp));
	c->MachineName = CopyStr(tmp);

	c->HttpUserAgent = CopyStr(DEFAULT_USER_AGENT);
	c->HttpAccept = CopyStr(DEFAULT_ACCEPT);
	c->HttpAcceptLanguage = CopyStr("ja");
	c->HttpAcceptEncoding = CopyStr(DEFAULT_ENCODING);

	c->Traffic = NewTraffic();
	c->TrafficLock = NewLock();
	c->CaList = NewList(CompareCert);

	c->TrafficDiffList = NewList(NULL);

	SetCedarCipherList(c, "RC4-MD5");

	c->ClientId = _II("CLIENT_ID");

	c->UdpPortList = NewIntList(false);

	InitNetSvcList(c);

	InitLocalBridgeList(c);

	InitCedarLayer3(c);

	c->WebUI = WuNewWebUI(c);

#ifdef	ALPHA_VERSION
	beta_str = "Alpha";
#else	// ALPHA_VERSION
#ifndef	RELEASE_CANDIDATE
	beta_str = "Beta";
#else	// RELEASE_CANDIDATE
	beta_str = "Release Candidate";
#endif	// RELEASE_CANDIDATE
#endif	// ALPHA_VERSION

	ToStr(tmp2, c->Beta);

	Format(tmp, sizeof(tmp), "Version %u.%02u Build %u %s %s (%s)",
		CEDAR_VER / 100, CEDAR_VER - (CEDAR_VER / 100) * 100,
		CEDAR_BUILD,
		c->Beta == 0 ? "" : beta_str,
		c->Beta == 0 ? "" : tmp2,
		_SS("LANGSTR"));
	Trim(tmp);

	if (true)
	{
		SYSTEMTIME st;
		Zero(&st, sizeof(st));

		st.wYear = BUILD_DATE_Y;
		st.wMonth = BUILD_DATE_M;
		st.wDay = BUILD_DATE_D;

		c->BuiltDate = SystemToUINT64(&st);
	}

	c->VerString = CopyStr(tmp);

	Format(tmp, sizeof(tmp), "Compiled %04u/%02u/%02u %02u:%02u:%02u by %s at %s",
		BUILD_DATE_Y, BUILD_DATE_M, BUILD_DATE_D, BUILD_DATE_HO, BUILD_DATE_MI, BUILD_DATE_SE, BUILDER_NAME, BUILD_PLACE);

	c->BuildInfo = CopyStr(tmp);

	return c;
}

// Check whether the Cedar was build after the specified date
bool IsLaterBuild(CEDAR *c, UINT64 t)
{
	SYSTEMTIME sb, st;
	UINT64 b;
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	Zero(&sb, sizeof(sb));
	Zero(&st, sizeof(st));

	UINT64ToSystem(&sb, c->BuiltDate);
	UINT64ToSystem(&st, t);

	// Ignore time of the day
	sb.wHour = sb.wMinute = sb.wSecond = sb.wMilliseconds = 0;
	st.wHour = st.wMinute = st.wSecond = st.wMilliseconds = 0;

	b = SystemToUINT64(&sb);
	t = SystemToUINT64(&st);

	if (b > t)
	{
		return true;
	}
	else
	{
		return false;
	}
}

// Cumulate traffic size
void AddTraffic(TRAFFIC *dst, TRAFFIC *diff)
{
	// Validate arguments
	if (dst == NULL || diff == NULL)
	{
		return;
	}

	dst->Recv.BroadcastBytes += diff->Recv.BroadcastBytes;
	dst->Recv.BroadcastCount += diff->Recv.BroadcastCount;
	dst->Recv.UnicastBytes += diff->Recv.UnicastBytes;
	dst->Recv.UnicastCount += diff->Recv.UnicastCount;

	dst->Send.BroadcastBytes += diff->Send.BroadcastBytes;
	dst->Send.BroadcastCount += diff->Send.BroadcastCount;
	dst->Send.UnicastBytes += diff->Send.UnicastBytes;
	dst->Send.UnicastCount += diff->Send.UnicastCount;
}

// Create new traffic size object
TRAFFIC *NewTraffic()
{
	TRAFFIC *t;

	t = ZeroMalloc(sizeof(TRAFFIC));
	return t;
}

// Free traffic size object
void FreeTraffic(TRAFFIC *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Free(t);
}

// Initialize Cedar communication module
void InitCedar()
{
	if ((init_cedar_counter++) > 0)
	{
		return;
	}

	// Initialize protocol module
	InitProtocol();
}

// Free Cedar communication module
void FreeCedar()
{
	if ((--init_cedar_counter) > 0)
	{
		return;
	}

	// Free protocol module
	FreeProtocol();
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
