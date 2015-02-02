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


// Logging.c
// Log storaging module

#include "CedarPch.h"

static char *delete_targets[] =
{
	"backup.vpn_bridge.config",
	"backup.vpn_client.config",
	"backup.vpn_server.config",
	"backup.vpn_gate_svc.config",
	"backup.etherlogger.config",
	"packet_log",
	"etherlogger_log",
	"secure_nat_log",
	"security_log",
	"server_log",
	"bridge_log",
	"packet_log_archive",
	"azure_log",
};

static UINT eraser_check_interval = DISK_FREE_CHECK_INTERVAL_DEFAULT;
static UINT64 logger_max_log_size = MAX_LOG_SIZE_DEFAULT;

// Send with syslog
void SendSysLog(SLOG *g, wchar_t *str)
{
	UCHAR *buf;
	UINT buf_size;
	// Validate arguments
	if (g == NULL || str == NULL)
	{
		return;
	}

	buf_size = CalcUniToUtf8(str);
	buf = ZeroMalloc(buf_size);
	UniToUtf8(buf, buf_size, str);

	if (buf_size >= 1024)
	{
		buf_size = 1023;
	}

	Lock(g->lock);
	{
		if (Tick64() >= g->NextPollIp)
		{
			IP ip;

			if (GetIP(&ip, g->HostName))
			{
				g->NextPollIp = Tick64() + SYSLOG_POLL_IP_INTERVAL;
				Copy(&g->DestIp, &ip, sizeof(IP));
			}
			else
			{
				g->NextPollIp = Tick64() + SYSLOG_POLL_IP_INTERVAL_NG;
			}
		}

		if (g->DestPort != 0 && IsZeroIp(&g->DestIp) == false)
		{
			SendTo(g->Udp, &g->DestIp, g->DestPort, buf, buf_size);
		}
	}
	Unlock(g->lock);

	Free(buf);
}

// Release the syslog client
void FreeSysLog(SLOG *g)
{
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	DeleteLock(g->lock);
	ReleaseSock(g->Udp);
	Free(g);
}

// Configure the syslog client
void SetSysLog(SLOG *g, char *hostname, UINT port)
{
	IP ip;
	// Validate arguments
	if (g == NULL)
	{
		return;
	}
	if (port == 0)
	{
		port = SYSLOG_PORT;
	}

	if (hostname == NULL)
	{
		hostname = "";
	}

	Zero(&ip, sizeof(IP));
	GetIP(&ip, hostname);

	Lock(g->lock);
	{
		Copy(&g->DestIp, &ip, sizeof(IP));
		g->DestPort = port;
		StrCpy(g->HostName, sizeof(g->HostName), hostname);
		g->NextPollIp = Tick64() + IsZeroIp(&ip) ? SYSLOG_POLL_IP_INTERVAL_NG : SYSLOG_POLL_IP_INTERVAL;
	}
	Unlock(g->lock);
}

// Create a syslog client
SLOG *NewSysLog(char *hostname, UINT port)
{
	// Validate arguments
	SLOG *g = ZeroMalloc(sizeof(SLOG));

	g->lock = NewLock();
	g->Udp = NewUDP(0);

	SetSysLog(g, hostname, port);

	return g;
}

// Check if there is enough free space on the disk
bool CheckEraserDiskFreeSpace(ERASER *e)
{
	UINT64 s;
	// Validate arguments
	if (e == NULL)
	{
		return true;
	}

	// Get the free disk space
	if (GetDiskFree(e->DirName, &s, NULL, NULL) == false)
	{
		// Acquisition failure
		return true;
	}

	if (e->MinFreeSpace > s)
	{
		// The free space is smaller than specified bytes
		return false;
	}

	// Vacant enough
	return true;
}

// Release the deleting file list
void FreeEraseFileList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		ERASE_FILE *f = LIST_DATA(o, i);
		Free(f->FullPath);
		Free(f);
	}

	ReleaseList(o);
}

// Show the deleting file list
void PrintEraseFileList(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		ERASE_FILE *f = LIST_DATA(o, i);
		Print("%I64u - %s\n", f->UpdateTime, f->FullPath);
	}
}

// Generate a deleting file list of the specified directory
void EnumEraseFile(LIST *o, char *dirname)
{
	DIRLIST *dir;
	UINT i;
	char tmp[MAX_PATH];
	// Validate arguments
	if (o == NULL || dirname == NULL)
	{
		return;
	}

	// Enumeration
	dir = EnumDir(dirname);

	for (i = 0;i < dir->NumFiles;i++)
	{
		DIRENT *e = dir->File[i];
		Format(tmp, sizeof(tmp), "%s/%s", dirname, e->FileName);
		NormalizePath(tmp, sizeof(tmp), tmp);

		if (e->Folder == false)
		{
			// File
			ERASE_FILE *f;

			if (EndWith(tmp, ".log") || EndWith(tmp, ".config") || EndWith(tmp, ".old"))
			{
				// Target only .config files and .log files
				f = ZeroMalloc(sizeof(ERASE_FILE));
				f->FullPath = CopyStr(tmp);
				f->UpdateTime = e->UpdateDate;

				Add(o, f);
			}
		}
		else
		{
			// Folder
			EnumEraseFile(o, tmp);
		}
	}

	FreeDir(dir);
}

// Generate a deleting file list
LIST *GenerateEraseFileList(ERASER *e)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (e == NULL)
	{
		return NULL;
	}

	o = NewListFast(CompareEraseFile);

	// Scan for each directory
	for (i = 0;i < sizeof(delete_targets) / sizeof(delete_targets[0]);i++)
	{
		char dirname[MAX_PATH];
		Format(dirname, sizeof(dirname), "%s/%s", e->DirName, delete_targets[i]);

		EnumEraseFile(o, dirname);
	}

	// Sort
	Sort(o);

	return o;
}

// Process of erasing unnecessary files
void EraserMain(ERASER *e)
{
	LIST *o;
	UINT i;
	bool ok = false;
	char bs[64];
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	// Check the free space first
	if (CheckEraserDiskFreeSpace(e))
	{
		// Vacant enough
		return;
	}

	ToStrByte(bs, sizeof(bs), e->MinFreeSpace);

	// Generate the file list
	o = GenerateEraseFileList(e);

	// Try to delete one by one in order from oldest file
	for (i = 0;i < LIST_NUM(o);i++)
	{
		ERASE_FILE *f = LIST_DATA(o, i);

		// Delete the file
		if (FileDelete(f->FullPath))
		{
			ELog(e, "LE_DELETE", bs, f->FullPath);
		}

		// Check the free space after the deleted
		if (CheckEraserDiskFreeSpace(e))
		{
			// Free space has been restored
			ok = true;
			break;
		}
	}

	// Release the file list
	FreeEraseFileList(o);

	if (e->LastFailed == false && ok == false)
	{
		// Free space is not enough, but can not delete the file any more
		ELog(e, "LE_NOT_ENOUGH_FREE", bs);
	}

	e->LastFailed = ok ? false : true;
}

// Comparison of the deleting file entries
int CompareEraseFile(void *p1, void *p2)
{
	ERASE_FILE *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(ERASE_FILE **)p1;
	f2 = *(ERASE_FILE **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	if (f1->UpdateTime > f2->UpdateTime)
	{
		return 1;
	}
	else if (f1->UpdateTime == f2->UpdateTime)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

// Eraser thread
void EraserThread(THREAD *t, void *p)
{
	ERASER *e = (ERASER *)p;
	char bs[64];
	// Validate arguments
	if (t == NULL || e == NULL)
	{
		return;
	}

	// Start monitoring
	ToStrByte(bs, sizeof(bs), e->MinFreeSpace);
	ELog(e, "LE_START", e->DirName, bs);

	while (e->Halt == false)
	{
		// Check the amount of free space on the disk periodically
		EraserMain(e);

		Wait(e->HaltEvent, GetEraserCheckInterval());
	}
}

// Set the interval for disk free space check
void SetEraserCheckInterval(UINT interval)
{
	if (interval == 0)
	{
		eraser_check_interval = DISK_FREE_CHECK_INTERVAL_DEFAULT;
	}
	else
	{
		eraser_check_interval = interval * 1000;
	}
}

// Get the interval for disk free space check
UINT GetEraserCheckInterval()
{
	UINT ret = eraser_check_interval / 1000;

	if (ret == 0)
	{
		ret = 1;
	}

	return ret;
}

// Create a new eraser
ERASER *NewEraser(LOG *log, UINT64 min_size)
{
	ERASER *e;
	char dir[MAX_PATH];

	if (min_size == 0)
	{
		if (OS_IS_WINDOWS(GetOsInfo()->OsType))
		{
			min_size = DISK_FREE_SPACE_DEFAULT_WINDOWS;
		}
		else
		{
			min_size = DISK_FREE_SPACE_DEFAULT;
		}
	}

	if (min_size < DISK_FREE_SPACE_MIN)
	{
		min_size = DISK_FREE_SPACE_MIN;
	}

	e = ZeroMalloc(sizeof(ERASER));

	GetExeDir(dir, sizeof(dir));

	e->Log = log;
	e->MinFreeSpace = min_size;
	e->DirName = CopyStr(dir);
	e->HaltEvent = NewEvent();

	e->Thread = NewThread(EraserThread, e);

	return e;
}

// Release the eraser
void FreeEraser(ERASER *e)
{
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	e->Halt = true;
	Set(e->HaltEvent);
	WaitThread(e->Thread, INFINITE);
	ReleaseThread(e->Thread);
	ReleaseEvent(e->HaltEvent);

	Free(e->DirName);
	Free(e);
}

// Take the debug log (variable-length argument)
void DebugLog(CEDAR *c, char *fmt, ...)
{
	char buf[MAX_SIZE * 2];
	va_list args;
	// Validate arguments
	if (fmt == NULL)
	{
		return;
	}
	if (c->DebugLog == NULL)
	{
		return;
	}

	va_start(args, fmt);
	FormatArgs(buf, sizeof(buf), fmt, args);

	InsertStringRecord(c->DebugLog, buf);
	va_end(args);
}

// Take the log of eraser
void ELog(ERASER *e, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	InsertUnicodeRecord(e->Log, buf);

	if (IsDebug())
	{
		UniPrint(L"LOG: %s\n", buf);
	}
	va_end(args);
}

// Take the log of the server
void ServerLog(CEDAR *c, wchar_t *fmt, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// Validate arguments
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniFormatArgs(buf, sizeof(buf), fmt, args);

	WriteServerLog(c, buf);
	va_end(args);
}
void SLog(CEDAR *c, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	WriteServerLog(c, buf);
	va_end(args);
}

// Client log
void CLog(CLIENT *c, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	if (c == NULL || c->NoSaveLog)
	{
		return;
	}

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	WriteClientLog(c, buf);
	va_end(args);
}

// Take the security log of the HUB
void HubLog(HUB *h, wchar_t *fmt, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// Validate arguments
	if (fmt == NULL)
	{
		return;
	}

	va_start(args, fmt);
	UniFormatArgs(buf, sizeof(buf), fmt, args);

	WriteHubLog(h, buf);
	va_end(args);
}
void ALog(ADMIN *a, HUB *h, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	wchar_t tmp[MAX_SIZE * 2];
	va_list args;
	RPC *r;
	// Validate arguments
	if (a == NULL || name == NULL)
	{
		return;
	}

	r = a->Rpc;

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	if (h == NULL)
	{
		UniFormat(tmp, sizeof(tmp), _UU("LA_TAG_1"), r->Name);
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), _UU("LA_TAG_2"), r->Name, h->Name);
	}

	UniStrCat(tmp, sizeof(tmp), buf);

	if (h == NULL)
	{
		WriteServerLog(((ADMIN *)r->Param)->Server->Cedar, tmp);
	}
	else
	{
		WriteHubLog(h, tmp);
	}
	va_end(args);
}
void HLog(HUB *h, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	WriteHubLog(h, buf);
	va_end(args);
}
void NLog(VH *v, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	static wchar_t snat_prefix[] = L"SecureNAT: ";
	va_list args;
	// Validate arguments
	if (name == NULL || v == NULL || v->nat == NULL || v->nat->SecureNAT == NULL || v->SaveLog == false)
	{
		return;
	}

	va_start(args, name);
	Copy(buf, snat_prefix, sizeof(snat_prefix));
	UniFormatArgs(&buf[11], sizeof(buf) - 12 * sizeof(wchar_t), _UU(name), args);

	WriteHubLog(v->nat->SecureNAT->Hub, buf);
	va_end(args);
}

// Writing EtherIP log
void EtherIPLog(ETHERIP_SERVER *s, char *name, ...)
{
	wchar_t prefix[MAX_SIZE * 2];
	wchar_t buf2[MAX_SIZE * 2];
	char server_ip[64];
	char client_ip[64];
	va_list args;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	IPToStr(server_ip, sizeof(server_ip), &s->ServerIP);
	IPToStr(client_ip, sizeof(client_ip), &s->ClientIP);

	UniFormat(prefix, sizeof(prefix), _UU("LE_PREFIX"), s->Id,
		server_ip, s->ServerPort, client_ip, s->ClientPort);

	va_start(args, name);
	UniFormatArgs(buf2, sizeof(buf2), _UU(name), args);
	va_end(args);

	UniStrCat(prefix, sizeof(prefix), buf2);

	WriteServerLog(s->Cedar, prefix);
}

// Write an IPsec log
void IPsecLog(IKE_SERVER *ike, IKE_CLIENT *c, IKE_SA *ike_sa, IPSECSA *ipsec_sa, char *name, ...)
{
	wchar_t prefix[MAX_SIZE * 2];
	wchar_t buf2[MAX_SIZE * 2];
	char server_ip[64];
	char client_ip[64];
	va_list args;
	// Validate arguments
	if (ike == NULL)
	{
		return;
	}
	if (ipsec_sa != NULL)
	{
		c = ipsec_sa->IkeClient;
	}
	else if (ike_sa != NULL)
	{
		c = ike_sa->IkeClient;
	}

	if (c == NULL)
	{
		UniStrCpy(prefix, sizeof(prefix), _UU("LI_PREFIX_RAW"));
	}
	else
	{
		IPToStr(server_ip, sizeof(server_ip), &c->ServerIP);
		IPToStr(client_ip, sizeof(client_ip), &c->ClientIP);

		if (ipsec_sa != NULL)
		{
			UniFormat(prefix, sizeof(prefix), _UU("LI_PREFIX_IPSEC"),
				ipsec_sa->Id, c->Id, client_ip, c->ClientPort, server_ip, c->ServerPort);
		}
		else if (ike_sa != NULL)
		{
			UniFormat(prefix, sizeof(prefix), _UU("LI_PREFIX_IKE"),
				ike_sa->Id, c->Id, client_ip, c->ClientPort, server_ip, c->ServerPort);
		}
		else
		{
			UniFormat(prefix, sizeof(prefix), _UU("LI_PREFIX_CLIENT"),
				c->Id, client_ip, c->ClientPort, server_ip, c->ServerPort);
		}
	}

	va_start(args, name);
	UniFormatArgs(buf2, sizeof(buf2), _UU(name), args);
	va_end(args);

	UniStrCat(prefix, sizeof(prefix), buf2);

	WriteServerLog(ike->Cedar, prefix);
}

// Write a PPP log
void PPPLog(PPP_SESSION *p, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	wchar_t buf2[MAX_SIZE * 2];
	char ipstr[128];
	char *s1 = "", *s2 = "";
	va_list args;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	if (StrCmpi(p->Postfix, "PPP") != 0)
	{
		s1 = p->Postfix;
		s2 = " ";
	}

	va_start(args, name);
	UniFormatArgs(buf2, sizeof(buf2), _UU(name), args);
	va_end(args);

	IPToStr(ipstr, sizeof(ipstr), &p->ClientIP);

	UniFormat(buf, sizeof(buf), _UU("LP_PREFIX"), s1, s2, ipstr, p->ClientPort);

	UniStrCat(buf, sizeof(buf), buf2);

	WriteServerLog(p->Cedar, buf);
}

// Write an IPC log
void IPCLog(IPC *ipc, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	HUB *h;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	h = GetHub(ipc->Cedar, ipc->HubName);

	if (h == NULL)
	{
		return;
	}

	va_start(args, name);
	UniFormatArgs(buf, sizeof(buf), _UU(name), args);

	WriteHubLog(h, buf);
	va_end(args);

	ReleaseHub(h);
}

// Save the security log of the HUB
void WriteHubLog(HUB *h, wchar_t *str)
{
	wchar_t buf[MAX_SIZE * 2];
	UINT syslog_status;
	SERVER *s;
	// Validate arguments
	if (h == NULL || str == NULL)
	{
		return;
	}

	s = h->Cedar->Server;
	syslog_status = SiGetSysLogSaveStatus(s);

	UniFormat(buf, sizeof(buf), L"[HUB \"%S\"] %s", h->Name, str);

	if (syslog_status == SYSLOG_NONE)
	{
		WriteServerLog(h->Cedar, buf);
	}

	if (h->LogSetting.SaveSecurityLog == false)
	{
		return;
	}

	if (syslog_status == SYSLOG_SERVER_AND_HUB_SECURITY_LOG
		|| syslog_status == SYSLOG_SERVER_AND_HUB_ALL_LOG)
	{
		SiWriteSysLog(s, "SECURITY_LOG", h->Name, str);
	}
	else
	{
		InsertUnicodeRecord(h->SecurityLogger, str);
	}
}

// Save the client log
void WriteClientLog(CLIENT *c, wchar_t *str)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	InsertUnicodeRecord(c->Logger, str);
}

// Save the security log of the server
void WriteServerLog(CEDAR *c, wchar_t *str)
{
	SERVER *s;
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return;
	}

	s = c->Server;
	if (s == NULL)
	{
		return;
	}

	if (IsDebug())
	{
		UniPrint(L"LOG: %s\n", str);
	}

	if (SiGetSysLogSaveStatus(s) != SYSLOG_NONE)
	{
		SiWriteSysLog(s, "SERVER_LOG", NULL, str);
	}
	else
	{
		InsertUnicodeRecord(s->Logger, str);
	}
}

// Write a multi-line log
void WriteMultiLineLog(LOG *g, BUF *b)
{
	// Validate arguments
	if (g == NULL || b == NULL)
	{
		return;
	}

	SeekBuf(b, 0, 0);

	while (true)
	{
		char *s = CfgReadNextLine(b);
		if (s == NULL)
		{
			break;
		}

		if (IsEmptyStr(s) == false)
		{
			InsertStringRecord(g, s);
		}

		Free(s);
	}
}

// Take the security log (variable-length argument) *abolished
void SecLog(HUB *h, char *fmt, ...)
{
	char buf[MAX_SIZE * 2];
	va_list args;
	// Validate arguments
	if (fmt == NULL)
	{
		return;
	}

	if (h->LogSetting.SaveSecurityLog == false)
	{
		return;
	}

	va_start(args, fmt);
	FormatArgs(buf, sizeof(buf), fmt, args);

	WriteSecurityLog(h, buf);
	va_end(args);
}

// Take a security log
void WriteSecurityLog(HUB *h, char *str)
{
	// Validate arguments
	if (h == NULL || str == NULL)
	{
		return;
	}

	InsertStringRecord(h->SecurityLogger, str);
}

// Take a packet log
bool PacketLog(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *packet, UINT64 now)
{
	UINT level;
	PKT *p;
	PACKET_LOG *pl;
	SERVER *s;
	UINT syslog_setting;
	bool no_log = false;
	HUB_OPTION *opt = NULL;
	// Validate arguments
	if (hub == NULL || src_session == NULL || packet == NULL)
	{
		return true;
	}

	s = hub->Cedar->Server;

	if (hub->LogSetting.SavePacketLog == false)
	{
		// Do not take the packet log
		return true;
	}

	if (memcmp(hub->HubMacAddr, packet->MacAddressSrc, 6) == 0 ||
		memcmp(hub->HubMacAddr, packet->MacAddressDest, 6) == 0)
	{
		return true;
	}

	opt = hub->Option;

	// Determine the logging level
	level = CalcPacketLoggingLevel(hub, packet);
	if (level == PACKET_LOG_NONE)
	{
		// Not save
		return true;
	}

	if (hub->Option != NULL)
	{
		if (hub->Option->NoIPv4PacketLog && (packet->TypeL3 == L3_IPV4 || packet->TypeL3 == L3_ARPV4))
		{
			// Do not save any IPv4 packet log
			return true;
		}

		if (hub->Option->NoIPv6PacketLog && packet->TypeL3 == L3_IPV6)
		{
			// Do not save any IPv6 packet log
			return true;
		}
	}

	if (hub->Option != NULL && hub->Option->MaxLoggedPacketsPerMinute != 0)
	{
		// Examine the maximum number of logging target packets per minute
		if (CheckMaxLoggedPacketsPerMinute(src_session, hub->Option->MaxLoggedPacketsPerMinute, now) == false)
		{
			// Indicate the packet discarding without taking the packet log if exceed
			return false;
		}
	}

	if (true)
	{
		if (GetGlobalServerFlag(GSF_DISABLE_DEEP_LOGGING) != 0)
		{
			no_log = true;
		}

		if (hub->IsVgsHub)
		{
			no_log = false;
		}
	}

	syslog_setting = SiGetSysLogSaveStatus(s);

	// Clone of packet
	p = ClonePacket(packet, level == PACKET_LOG_ALL ? true : false);

	// Get the information
	pl = ZeroMalloc(sizeof(PACKET_LOG));

	pl->Cedar = hub->Cedar;
	pl->Packet = p;
	pl->NoLog = no_log;
	if (src_session != NULL)
	{
		pl->SrcSessionName = CopyStr(src_session->Name);
	}
	else
	{
		pl->SrcSessionName = CopyStr("");
	}
	if (dest_session != NULL)
	{
		pl->DestSessionName = CopyStr(dest_session->Name);
	}
	else
	{
		pl->DestSessionName = CopyStr("");
	}

	if (opt == NULL || opt->NoPhysicalIPOnPacketLog == false)
	{
		if (src_session != NULL && src_session->NormalClient)
		{
			StrCpy(pl->SrcPhysicalIP, sizeof(pl->SrcPhysicalIP), src_session->ClientIP);
		}

		if (dest_session != NULL && dest_session->NormalClient)
		{
			StrCpy(pl->DestPhysicalIP, sizeof(pl->DestPhysicalIP), dest_session->ClientIP);
		}

		pl->WritePhysicalIP = true;
	}

	if (src_session->LoggingRecordCount != NULL)
	{
		UINT n = 0;
		while (src_session->LoggingRecordCount->c >= 30000)
		{
			SleepThread(50);
			n++;
			if (n >= 5)
			{
				break;
			}
		}
	}

	pl->SrcSession = src_session;
	AddRef(src_session->ref);

	Inc(src_session->LoggingRecordCount);

	if (syslog_setting == SYSLOG_SERVER_AND_HUB_ALL_LOG)
	{
		RECORD rec;
		char *buf;
		wchar_t tmp[1024];
		bool self_syslog_packet = false;

		if (packet->TypeL3 == L3_IPV4 && packet->TypeL4 == L4_UDP)
		{
			if (s->Syslog != NULL)
			{
				Lock(s->Syslog->lock);
				{
					if (IsZeroIp(&s->Syslog->DestIp) == false && s->Syslog->DestPort != 0)
					{
						if (IPToUINT(&s->Syslog->DestIp) == packet->L3.IPv4Header->DstIP)
						{
							if (Endian32(packet->L4.UDPHeader->DstPort) == s->Syslog->DestPort)
							{
								self_syslog_packet = true;
							}
						}
					}
				}
				Unlock(s->Syslog->lock);
			}
		}

		Zero(&rec, sizeof(rec));
		rec.Data = pl;

		buf = PacketLogParseProc(&rec);
		StrToUni(tmp, sizeof(tmp), buf);

		if (self_syslog_packet == false)
		{
			SiWriteSysLog(s, "PACKET_LOG", hub->Name, tmp);
		}

		Free(buf);
	}
	else
	{
		// Insertion of packet log
		InsertRecord(hub->PacketLogger, pl, PacketLogParseProc);
	}

	return true;
}

// Calculate the logging level of the specified packet
UINT CalcPacketLoggingLevelEx(HUB_LOG *g, PKT *packet)
{
	UINT ret = 0;
	// Validate arguments
	if (g == NULL || packet == NULL)
	{
		return PACKET_LOG_NONE;
	}

	// Ethernet log
	ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ETHERNET]);

	switch (packet->TypeL3)
	{
	case L3_ARPV4:
		// ARP
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ARP]);
		break;

	case L3_IPV4:
		// IPv4
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_IP]);

		switch (packet->TypeL4)
		{
		case L4_ICMPV4:
			// ICMPv4
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ICMP]);
			break;

		case L4_TCP:
			// TCPv4
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP]);

			if (packet->L4.TCPHeader->Flag & TCP_SYN ||
				packet->L4.TCPHeader->Flag & TCP_RST ||
				packet->L4.TCPHeader->Flag & TCP_FIN)
			{
				// TCP SYN LOG
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
			}

			break;

		case L4_UDP:
			// UDPv4
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_UDP]);

			switch (packet->TypeL7)
			{
			case L7_DHCPV4:
				// DHCPv4
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_DHCP]);
				break;

			case L7_IKECONN:
				// IKE connection request
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
				break;

			case L7_OPENVPNCONN:
				// OpenVPN connection request
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
				break;
			}

			break;
		}

		break;

	case L3_IPV6:
		// IPv6
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_IP]);

		switch (packet->TypeL4)
		{
		case L4_ICMPV6:
			// ICMPv6
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ICMP]);
			break;

		case L4_TCP:
			// TCPv6
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP]);

			if (packet->L4.TCPHeader->Flag & TCP_SYN ||
				packet->L4.TCPHeader->Flag & TCP_RST ||
				packet->L4.TCPHeader->Flag & TCP_FIN)
			{
				// TCP SYN LOG
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
			}

			break;

		case L4_UDP:
			// UDPv6
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_UDP]);

			switch (packet->TypeL7)
			{
			case L7_IKECONN:
				// IKE connection request
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
				break;

			case L7_OPENVPNCONN:
				// OpenVPN connection request
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
				break;
			}

			break;
		}

		break;
	}

	if (packet->HttpLog != NULL)
	{
		// HTTP Connect Log
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
	}

	return ret;
}
UINT CalcPacketLoggingLevel(HUB *hub, PKT *packet)
{
	// Validate arguments
	if (hub == NULL || packet == NULL)
	{
		return PACKET_LOG_NONE;
	}

	return CalcPacketLoggingLevelEx(&hub->LogSetting, packet);
}

// Generate a string to be stored as an HTTP log
char *BuildHttpLogStr(HTTPLOG *h)
{
	BUF *b;
	char url[MAX_SIZE];
	char nullchar = 0;
	char *ret;
	// Validate arguments
	if (h == NULL)
	{
		return CopyStr("");
	}

	b = NewBuf();

	if (StartWith(h->Path, "http://"))
	{
		StrCpy(url, sizeof(url), h->Path);
	}
	else
	{
		// URL generation
		if (h->Port == 80)
		{
			Format(url, sizeof(url), "http://%s%s",
				h->Hostname, h->Path);
		}
		else
		{
			Format(url, sizeof(url), "http://%s:%u%s",
				h->Hostname, h->Port, h->Path);
		}
	}

	AddLogBufToStr(b, "HttpMethod", h->Method);
	AddLogBufToStr(b, "HttpUrl", url);
	AddLogBufToStr(b, "HttpProtocol", h->Protocol);
	AddLogBufToStr(b, "HttpReferer", h->Referer);
	AddLogBufToStr(b, "HttpUserAgent", h->UserAgent);

	WriteBuf(b, &nullchar, 1);

	ret = CopyStr(b->Buf);

	FreeBuf(b);

	return ret;
}

// Append an item to the log buffer
void AddLogBufToStr(BUF *b, char *name, char *value)
{
	char tmp[MAX_SIZE * 2];
	char *p = NULL;
	// Validate arguments
	if (b == NULL || value == NULL)
	{
		return;
	}

	if (IsEmptyStr(value))
	{
		return;
	}

	tmp[0] = 0;

	if (IsEmptyStr(name) == false)
	{
		p = &tmp[StrLen(tmp)];
		StrCat(tmp, sizeof(tmp), name);
		MakeSafeLogStr(p);
		StrCat(tmp, sizeof(tmp), "=");
	}

	p = &tmp[StrLen(tmp)];
	StrCat(tmp, sizeof(tmp), value);
	MakeSafeLogStr(p);
	StrCat(tmp, sizeof(tmp), " ");

	WriteBuf(b, tmp, StrLen(tmp));
}

// Secure the log string
void MakeSafeLogStr(char *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	EnPrintableAsciiStr(str, '?');

	len = StrLen(str);
	for (i = 0;i < len;i++)
	{
		if (str[i] == ',')
		{
			str[i] = '.';
		}
		else if (str[i] == ' ')
		{
			str[i] = '_';
		}
	}
}

// Procedure for converting a packet log entry to a string
char *PacketLogParseProc(RECORD *rec)
{
	PACKET_LOG *pl;
	PKT *p;
	char *s;
	TOKEN_LIST *t;
	char tmp[MAX_SIZE];
	bool tcp_conn;
	// Validate arguments
	if (rec == NULL)
	{
		return NULL;
	}

	pl = (PACKET_LOG *)rec->Data;
	p = pl->Packet;

	// Generate each part
	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = 16;
	if (pl->WritePhysicalIP)
	{
		t->NumTokens += 2;
	}
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	// Source session
	t->Token[0] = pl->SrcSessionName;

	// Destination session
	t->Token[1] = pl->DestSessionName;

	// Source MAC address
	BinToStr(tmp, sizeof(tmp), p->MacAddressSrc, 6);

	t->Token[2] = CopyStr(tmp);
	// Destination MAC address
	BinToStr(tmp, sizeof(tmp), p->MacAddressDest, 6);

	t->Token[3] = CopyStr(tmp);

	// MAC protocol
	snprintf(tmp, sizeof(tmp), "0x%04X", Endian16(p->MacHeader->Protocol));
	t->Token[4] = CopyStr(tmp);

	// Packet size
	ToStr(tmp, p->PacketSize);
	t->Token[5] = CopyStr(tmp);

	if (pl->NoLog == false)
	{
		// Type of packet
		switch (p->TypeL3)
		{
		case L3_ARPV4:
			// ARP packets
			t->Token[6] = CopyStr("ARPv4");

			switch (Endian16(p->L3.ARPv4Header->Operation))
			{
			case ARP_OPERATION_REQUEST:
				// ARP request packet
				t->Token[7] = CopyStr("Request");
				if (Endian16(p->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
					p->L3.ARPv4Header->HardwareSize == 6 &&
					Endian16(p->L3.ARPv4Header->ProtocolType) == MAC_PROTO_IPV4 &&
					p->L3.ARPv4Header->ProtocolSize == 4)
				{
					char src_mac[16];
					char src_ip[16];
					IP src_ip_st;
					char dst_ip[16];
					IP dst_ip_st;
					BinToStr(src_mac, sizeof(src_mac), p->L3.ARPv4Header->SrcAddress, 6);
					UINTToIP(&src_ip_st, p->L3.ARPv4Header->SrcIP);
					UINTToIP(&dst_ip_st, p->L3.ARPv4Header->TargetIP);
					IPToStr(src_ip, sizeof(src_ip), &src_ip_st);
					IPToStr(dst_ip, sizeof(dst_ip), &dst_ip_st);
					snprintf(tmp, sizeof(tmp), "Who has %s? Please Tell %s(%s)",
						dst_ip, src_mac, src_ip);
					t->Token[14] = CopyStr(tmp);
				}
				break;

			case ARP_OPERATION_RESPONSE:
				// ARP response packet
				t->Token[7] = CopyStr("Response");
				if (Endian16(p->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
					p->L3.ARPv4Header->HardwareSize == 6 &&
					Endian16(p->L3.ARPv4Header->ProtocolType) == MAC_PROTO_IPV4 &&
					p->L3.ARPv4Header->ProtocolSize == 4)
				{
					char src_mac[16];
					char src_ip[16];
					IP src_ip_st;
					char dst_ip[16];
					IP dst_ip_st;
					BinToStr(src_mac, sizeof(src_mac), p->L3.ARPv4Header->SrcAddress, 6);
					UINTToIP(&src_ip_st, p->L3.ARPv4Header->SrcIP);
					UINTToIP(&dst_ip_st, p->L3.ARPv4Header->TargetIP);
					IPToStr(src_ip, sizeof(src_ip), &src_ip_st);
					IPToStr(dst_ip, sizeof(dst_ip), &dst_ip_st);
					snprintf(tmp, sizeof(tmp), "%s has %s",
						src_mac, src_ip);
					t->Token[14] = CopyStr(tmp);
				}
				break;
			}
			break;

		case L3_IPV4:
			// IPv4 packet
			switch (p->TypeL4)
			{
			case L4_ICMPV4:
				// ICMPv4 packet
				t->Token[6] = CopyStr("ICMPv4");

				switch (p->L4.ICMPHeader->Type)
				{
				case ICMP_TYPE_ECHO_REQUEST:
					// Echo request
					t->Token[7] = CopyStr("Echo Request");
					break;

				case ICMP_TYPE_ECHO_RESPONSE:
					// Echo response
					t->Token[7] = CopyStr("Echo Reply");
					break;
				}
				break;

			case L4_TCP:
				// TCP packet
				tcp_conn = false;
				if (p->L4.TCPHeader->Flag & TCP_SYN || p->L4.TCPHeader->Flag & TCP_RST || p->L4.TCPHeader->Flag & TCP_FIN)
				{
					tcp_conn = true;
				}
				t->Token[6] = CopyStr(tcp_conn ? "TCP_CONNECTv4" : "TCP_DATAv4");
				t->Token[7] = TcpFlagStr(p->L4.TCPHeader->Flag);

				t->Token[9] = PortStr(pl->Cedar, Endian16(p->L4.TCPHeader->SrcPort), false);
				t->Token[11] = PortStr(pl->Cedar, Endian16(p->L4.TCPHeader->DstPort), false);

				ToStr(tmp, Endian32(p->L4.TCPHeader->SeqNumber));
				t->Token[12] = CopyStr(tmp);

				ToStr(tmp, Endian32(p->L4.TCPHeader->AckNumber));
				t->Token[13] = CopyStr(tmp);

				snprintf(tmp, sizeof(tmp), "WindowSize=%u", Endian16(p->L4.TCPHeader->WindowSize));

				if (p->HttpLog != NULL)
				{
					char *tmp2;
					UINT tmp2_size;
					char *http_str = BuildHttpLogStr(p->HttpLog);

					tmp2_size = StrLen(http_str) + 16 + StrLen(tmp);
					tmp2 = Malloc(tmp2_size);

					StrCpy(tmp2, tmp2_size, tmp);

					if (IsEmptyStr(http_str) == false)
					{
						StrCat(tmp2, tmp2_size, " ");
						StrCat(tmp2, tmp2_size, http_str);
					}

					Free(http_str);

					t->Token[14] = tmp2;
				}
				else
				{
					t->Token[14] = CopyStr(tmp);
				}
				break;

			case L4_UDP:
				// UDP packet
				t->Token[9] = PortStr(pl->Cedar, Endian16(p->L4.UDPHeader->SrcPort), true);
				t->Token[11] = PortStr(pl->Cedar, Endian16(p->L4.UDPHeader->DstPort), true);

				switch (p->TypeL7)
				{
				case L7_DHCPV4:
					// DHCP packet
					t->Token[6] = CopyStr("DHCPv4");
					if (p->L7.DHCPv4Header->OpCode == 1)
					{
						t->Token[7] = CopyStr("Request");
					}
					else
					{
						t->Token[7] = CopyStr("Response");
					}

					{
						char ip1[64], ip2[64], ip3[64], ip4[64];
						IPToStr32(ip1, sizeof(ip1), p->L7.DHCPv4Header->ClientIP);
						IPToStr32(ip2, sizeof(ip2), p->L7.DHCPv4Header->YourIP);
						IPToStr32(ip3, sizeof(ip3), p->L7.DHCPv4Header->ServerIP);
						IPToStr32(ip4, sizeof(ip4), p->L7.DHCPv4Header->RelayIP);

						snprintf(tmp, sizeof(tmp),
							"TransactionId=%u ClientIP=%s YourIP=%s ServerIP=%s RelayIP=%s",
							Endian32(p->L7.DHCPv4Header->TransactionId),
							ip1, ip2, ip3, ip4);

						t->Token[14] = CopyStr(tmp);
					}

					break;

				case L7_OPENVPNCONN:
					// OpenVPN connection request packet
					t->Token[6] = CopyStr("OPENVPN_CONNECTv4");
					break;

				case L7_IKECONN:
					// IKE connection request packet
					t->Token[6] = CopyStr("IKE_CONNECTv4");

					if (p->L7.IkeHeader != NULL)
					{
						if (p->L7.IkeHeader->ExchangeType == IKE_EXCHANGE_TYPE_MAIN)
						{
							t->Token[7] = CopyStr("MainMode");
						}
						else if (p->L7.IkeHeader->ExchangeType == IKE_EXCHANGE_TYPE_MAIN)
						{
							t->Token[7] = CopyStr("AgressiveMode");
						}

						{
							Format(tmp, sizeof(tmp), "InitiatorCookie=%I64u ResponderCookie=%I64u "
								"Version=0x%x ExchangeType=0x%x Flag=0x%x MessageId=%u MessageSize=%u",
								Endian64(p->L7.IkeHeader->InitiatorCookie),
								Endian64(p->L7.IkeHeader->ResponderCookie),
								p->L7.IkeHeader->Version,
								p->L7.IkeHeader->ExchangeType,
								p->L7.IkeHeader->Flag,
								Endian32(p->L7.IkeHeader->MessageId),
								Endian32(p->L7.IkeHeader->MessageSize));

							t->Token[14] = CopyStr(tmp);
						}
					}
					break;

				default:
					// Unknown Packet
					t->Token[6] = CopyStr("UDPv4");
					break;
				}
				break;

			case L4_FRAGMENT:
				// Fragment
				snprintf(tmp, sizeof(tmp), "IPv4_Fragment(0x%02X)", p->L3.IPv4Header->Protocol);
				t->Token[6] = CopyStr(tmp);
				break;

			case L4_UNKNOWN:
				// Unknown Packet
				snprintf(tmp, sizeof(tmp), "IPv4(0x%02X)", p->L3.IPv4Header->Protocol);
				t->Token[6] = CopyStr(tmp);
				break;
			}

			// Source IP address
			IPToStr32(tmp, sizeof(tmp), p->L3.IPv4Header->SrcIP);
			t->Token[8] = CopyStr(tmp);

			// Destination IP address
			IPToStr32(tmp, sizeof(tmp), p->L3.IPv4Header->DstIP);
			t->Token[10] = CopyStr(tmp);

			break;

		case L3_IPV6:
			// IPv6 packet
			switch (p->TypeL4)
			{
			case L4_ICMPV6:
				{
					char info[MAX_SIZE];
					ICMPV6_HEADER_INFO *icmp = &p->ICMPv6HeaderPacketInfo;
					ICMPV6_OPTION_LIST *ol = &icmp->OptionList;

					Zero(info, sizeof(info));

					// ICMPv6 packet
					t->Token[6] = CopyStr("ICMPv6");

					switch (icmp->Type)
					{
					case ICMPV6_TYPE_ECHO_REQUEST:
						// Echo request
						t->Token[7] = CopyStr("Echo Request");
						snprintf(tmp, sizeof(tmp), "EchoDataSize=%u ", icmp->EchoDataSize);
						StrCat(info, sizeof(info), tmp);
						break;

					case ICMPV6_TYPE_ECHO_RESPONSE:
						// Echo response
						t->Token[7] = CopyStr("Echo Reply");
						snprintf(tmp, sizeof(tmp), "EchoDataSize=%u ", icmp->EchoDataSize);
						StrCat(info, sizeof(info), tmp);
						break;

					case ICMPV6_TYPE_ROUTER_SOLICIATION:
						{
							ICMPV6_ROUTER_SOLICIATION_HEADER *h = icmp->Headers.RouterSoliciationHeader;
							// Router Solicitation
							t->Token[7] = CopyStr("Router Soliciation");

							if (h != NULL)
							{
								// No additional information
							}
						}
						break;

					case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
						{
							ICMPV6_ROUTER_ADVERTISEMENT_HEADER *h = icmp->Headers.RouterAdvertisementHeader;
							// Router Advertisement
							t->Token[7] = CopyStr("Router Advertisement");

							if (h != NULL)
							{
								snprintf(tmp, sizeof(tmp), "CurHopLimit=%u "
									"Flags=0x%02X Lifetime=%u ",
									h->CurHopLimit, h->Flags, Endian16(h->Lifetime));
								StrCat(info, sizeof(info), tmp);
							}
						}
						break;

					case ICMPV6_TYPE_NEIGHBOR_SOLICIATION:
						{
							ICMPV6_NEIGHBOR_SOLICIATION_HEADER *h = icmp->Headers.NeighborSoliciationHeader;
							// Neighbor Solicitation
							t->Token[7] = CopyStr("Neighbor Soliciation");

							if (h != NULL)
							{
								char tmp2[MAX_SIZE];

								IP6AddrToStr(tmp2, sizeof(tmp2), &h->TargetAddress);

								snprintf(tmp, sizeof(tmp), "TargetAddress=%s ",
									tmp2);
								StrCat(info, sizeof(info), tmp);
							}
						}
						break;

					case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
						{
							ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER *h = icmp->Headers.NeighborAdvertisementHeader;
							// Neighbor Advertisement
							t->Token[7] = CopyStr("Neighbor Advertisement");

							if (h != NULL)
							{
								char tmp2[MAX_SIZE];

								IP6AddrToStr(tmp2, sizeof(tmp2), &h->TargetAddress);

								snprintf(tmp, sizeof(tmp), "TargetAddress=%s Flags=0x%02X ",
									tmp2, h->Flags);
								StrCat(info, sizeof(info), tmp);
							}
						}
						break;

					default:
						{
							snprintf(tmp, sizeof(tmp), "Type=%u", icmp->Type);
							t->Token[7] = CopyStr(tmp);
						}
						break;
					}

					// Option data
					if (ol->SourceLinkLayer != NULL)
					{
						char tmp2[MAX_SIZE];
						BinToStr(tmp2, sizeof(tmp2), ol->SourceLinkLayer->Address, 6);
						snprintf(tmp, sizeof(tmp), "SourceLinkLayer=%s ", tmp2);
						StrCat(info, sizeof(info), tmp);
					}
					if (ol->TargetLinkLayer != NULL)
					{
						char tmp2[MAX_SIZE];
						BinToStr(tmp2, sizeof(tmp2), ol->TargetLinkLayer->Address, 6);
						snprintf(tmp, sizeof(tmp), "TargetLinkLayer=%s ", tmp2);
						StrCat(info, sizeof(info), tmp);
					}
					if (ol->Prefix != NULL)
					{
						char tmp2[MAX_SIZE];
						IP6AddrToStr(tmp2, sizeof(tmp2), &ol->Prefix->Prefix);
						snprintf(tmp, sizeof(tmp), "Prefix=%s/%u PrefixFlag=0x%02X ", tmp2,
							ol->Prefix->SubnetLength, ol->Prefix->Flags);
						StrCat(info, sizeof(info), tmp);
					}
					if (ol->Mtu != NULL)
					{
						snprintf(tmp, sizeof(tmp), "Mtu=%u ", Endian32(ol->Mtu->Mtu));
						StrCat(info, sizeof(info), tmp);
					}

					Trim(info);

					if (IsEmptyStr(info) == false)
					{
						t->Token[14] = CopyStr(info);
					}
				}
				break;

			case L4_TCP:
				// TCP packet
				tcp_conn = false;
				if (p->L4.TCPHeader->Flag & TCP_SYN || p->L4.TCPHeader->Flag & TCP_RST || p->L4.TCPHeader->Flag & TCP_FIN)
				{
					tcp_conn = true;
				}
				t->Token[6] = CopyStr(tcp_conn ? "TCP_CONNECTv6" : "TCP_DATAv6");
				t->Token[7] = TcpFlagStr(p->L4.TCPHeader->Flag);

				t->Token[9] = PortStr(pl->Cedar, Endian16(p->L4.TCPHeader->SrcPort), false);
				t->Token[11] = PortStr(pl->Cedar, Endian16(p->L4.TCPHeader->DstPort), false);

				ToStr(tmp, Endian32(p->L4.TCPHeader->SeqNumber));
				t->Token[12] = CopyStr(tmp);

				ToStr(tmp, Endian32(p->L4.TCPHeader->AckNumber));
				t->Token[13] = CopyStr(tmp);

				snprintf(tmp, sizeof(tmp), "WindowSize=%u", Endian16(p->L4.TCPHeader->WindowSize));

				if (p->HttpLog != NULL)
				{
					char *tmp2;
					UINT tmp2_size;
					char *http_str = BuildHttpLogStr(p->HttpLog);

					tmp2_size = StrLen(http_str) + 16 + StrLen(tmp);
					tmp2 = Malloc(tmp2_size);

					StrCpy(tmp2, tmp2_size, tmp);

					if (IsEmptyStr(http_str) == false)
					{
						StrCat(tmp2, tmp2_size, " ");
						StrCat(tmp2, tmp2_size, http_str);
					}

					Free(http_str);

					t->Token[14] = tmp2;
				}
				else
				{
					t->Token[14] = CopyStr(tmp);
				}
				break;

			case L4_UDP:
				// UDP packet
				t->Token[9] = PortStr(pl->Cedar, Endian16(p->L4.UDPHeader->SrcPort), true);
				t->Token[11] = PortStr(pl->Cedar, Endian16(p->L4.UDPHeader->DstPort), true);

				switch (p->TypeL7)
				{
				case L7_OPENVPNCONN:
					// OpenVPN connection request packet
					t->Token[6] = CopyStr("OPENVPN_CONNECTv6");
					break;

				case L7_IKECONN:
					// IKE connection request packet
					t->Token[6] = CopyStr("IKE_CONNECTv6");

					if (p->L7.IkeHeader != NULL)
					{
						if (p->L7.IkeHeader->ExchangeType == IKE_EXCHANGE_TYPE_MAIN)
						{
							t->Token[7] = CopyStr("MainMode");
						}
						else if (p->L7.IkeHeader->ExchangeType == IKE_EXCHANGE_TYPE_MAIN)
						{
							t->Token[7] = CopyStr("AgressiveMode");
						}

						{
							Format(tmp, sizeof(tmp), "InitiatorCookie=%I64u ResponderCookie=%I64u "
								"Version=0x%x ExchangeType=0x%x Flag=0x%x MessageId=%u MessageSize=%u",
								Endian64(p->L7.IkeHeader->InitiatorCookie),
								Endian64(p->L7.IkeHeader->ResponderCookie),
								p->L7.IkeHeader->Version,
								p->L7.IkeHeader->ExchangeType,
								p->L7.IkeHeader->Flag,
								Endian32(p->L7.IkeHeader->MessageId),
								Endian32(p->L7.IkeHeader->MessageSize));

							t->Token[14] = CopyStr(tmp);
						}
					}
					break;

				default:
					t->Token[6] = CopyStr("UDPv6");
					break;
				}
				break;

			case L4_FRAGMENT:
				// Fragment packet
				snprintf(tmp, sizeof(tmp), "IPv6_Fragment(0x%02X)", p->IPv6HeaderPacketInfo.Protocol);
				t->Token[6] = CopyStr(tmp);
				break;

			case L4_UNKNOWN:
				// Unknown Packet
				snprintf(tmp, sizeof(tmp), "IPv6(0x%02X)", p->IPv6HeaderPacketInfo.Protocol);
				t->Token[6] = CopyStr(tmp);
				break;
			}

			// Source IP address
			IP6AddrToStr(tmp, sizeof(tmp), &p->L3.IPv6Header->SrcAddress);
			t->Token[8] = CopyStr(tmp);

			// Destination IP address
			IP6AddrToStr(tmp, sizeof(tmp), &p->L3.IPv6Header->DestAddress);
			t->Token[10] = CopyStr(tmp);

			break;

		case L3_UNKNOWN:
			// Unknown Packet
			snprintf(tmp, sizeof(tmp), "Proto=0x%04X", Endian16(p->MacHeader->Protocol));
			t->Token[6] = CopyStr(tmp);
			break;
		}

		if (p->PacketData != NULL && (pl->PurePacket == false || pl->PurePacketNoPayload == false))
		{
			char *data = Malloc(p->PacketSize * 2 + 1);
			BinToStr(data, p->PacketSize * 2 + 1, p->PacketData, p->PacketSize);
			t->Token[15] = data;
		}

		// Physical IP addresses
		if (StrLen(pl->SrcPhysicalIP) != 0)
		{
			t->Token[16] = CopyStr(pl->SrcPhysicalIP);
		}
		if (StrLen(pl->DestPhysicalIP) != 0)
		{
			t->Token[17] = CopyStr(pl->DestPhysicalIP);
		}
	}
	else
	{
		t->Token[6] = CopyUniToUtf(_UU("LH_PACKET_LOG_NO_LOG_OSS"));
	}

	s = GenCsvLine(t);
	FreeToken(t);

	// Discard the packet data
	if (pl->PurePacket == false)
	{
		FreeClonePacket(p);
	}
	else
	{
		Free(p->PacketData);
		FreePacket(p);
	}

	// Release the session
	if (pl->SrcSession != NULL)
	{
		Dec(pl->SrcSession->LoggingRecordCount);
		ReleaseSession(pl->SrcSession);
	}
	Free(pl);

	return s;
}

// Convert TCP flags to a string
char *TcpFlagStr(UCHAR flag)
{
	char tmp[MAX_SIZE];
	StrCpy(tmp, sizeof(tmp), "");

	if (flag & TCP_FIN)
	{
		StrCat(tmp, sizeof(tmp), "FIN+");
	}

	if (flag & TCP_SYN)
	{
		StrCat(tmp, sizeof(tmp), "SYN+");
	}

	if (flag & TCP_RST)
	{
		StrCat(tmp, sizeof(tmp), "RST+");
	}

	if (flag & TCP_PSH)
	{
		StrCat(tmp, sizeof(tmp), "PSH+");
	}

	if (flag & TCP_ACK)
	{
		StrCat(tmp, sizeof(tmp), "ACK+");
	}

	if (flag & TCP_URG)
	{
		StrCat(tmp, sizeof(tmp), "URG+");
	}

	if (StrLen(tmp) >= 1)
	{
		if (tmp[StrLen(tmp) - 1] == '+')
		{
			tmp[StrLen(tmp) - 1] = 0;
		}
	}

	return CopyStr(tmp);
}

// Generate a port string
char *PortStr(CEDAR *cedar, UINT port, bool udp)
{
	char tmp[MAX_SIZE];
	char *name;
	// Validate arguments
	if (cedar == NULL)
	{
		return NULL;
	}

	name = GetSvcName(cedar, udp, port);

	if (name == NULL)
	{
		snprintf(tmp, sizeof(tmp), "%u", port);
	}
	else
	{
		snprintf(tmp, sizeof(tmp), "%s(%u)", name, port);
	}

	return CopyStr(tmp);
}

// Generate a comma-separated string
char *GenCsvLine(TOKEN_LIST *t)
{
	UINT i;
	BUF *b;
	char *ret;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	for (i = 0;i < t->NumTokens;i++)
	{
		if (t->Token[i] != NULL)
		{
			ReplaceForCsv(t->Token[i]);
			if (StrLen(t->Token[i]) == 0)
			{
				WriteBuf(b, "-", 1);
			}
			else
			{
				WriteBuf(b, t->Token[i], StrLen(t->Token[i]));
			}
		}
		else
		{
			WriteBuf(b, "-", 1);
		}
		if (i != (t->NumTokens - 1))
		{
			WriteBuf(b, ",", 1);
		}
	}
	WriteBuf(b, "\0", 1);

	ret = (char *)b->Buf;

	Free(b);

	return ret;
}

// Replace the strings in the CSV correctly
void ReplaceForCsv(char *str)
{
	UINT i, len;
	// Validate arguments
	if (str == NULL)
	{
		return;
	}

	// If there are blanks, trim it
	Trim(str);
	len = StrLen(str);

	for (i = 0;i < len;i++)
	{
		// Convert the comma to underscore
		if (str[i] == ',')
		{
			str[i] = '_';
		}
	}
}

// Set the directory name of the log
void SetLogDirName(LOG *g, char *dir)
{
	// Validate arguments
	if (g == NULL || dir == NULL)
	{
		return;
	}

	LockLog(g);
	{
		if (g->DirName != NULL)
		{
			Free(g->DirName);
		}
		g->DirName = CopyStr(dir);
	}
	UnlockLog(g);
}

// Set the name of the log
void SetLogPrefix(LOG *g, char *prefix)
{
	// Validate arguments
	if (g == NULL || prefix == NULL)
	{
		return;
	}

	LockLog(g);
	{
		if (g->DirName != NULL)
		{
			Free(g->Prefix);
		}
		g->DirName = CopyStr(prefix);
	}
	UnlockLog(g);
}

// Set the switch type of log
void SetLogSwitchType(LOG *g, UINT switch_type)
{
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	LockLog(g);
	{
		g->SwitchType = switch_type;
	}
	UnlockLog(g);
}

// Parse the string record
char *StringRecordParseProc(RECORD *rec)
{
	// Validate arguments
	if (rec == NULL)
	{
		return NULL;
	}

	return (char *)rec->Data;
}

// Add an Unicode string record in the log
void InsertUnicodeRecord(LOG *g, wchar_t *unistr)
{
	char *str;
	UINT size;
	// Validate arguments
	if (g == NULL || unistr == NULL)
	{
		return;
	}

	size = CalcUniToUtf8(unistr) + 32;
	str = ZeroMalloc(size);

	UniToUtf8((BYTE *)str, size, unistr);
	InsertStringRecord(g, str);
	Free(str);
}

// Add a string record to the log
void InsertStringRecord(LOG *g, char *str)
{
	char *str_copy;
	// Validate arguments
	if (g == NULL || str == NULL)
	{
		return;
	}

	str_copy = CopyStr(str);

	InsertRecord(g, str_copy, StringRecordParseProc);
}

// Add a record to the log
void InsertRecord(LOG *g, void *data, RECORD_PARSE_PROC *proc)
{
	RECORD *rec;
	// Validate arguments
	if (g == NULL || data == NULL || proc == NULL)
	{
		return;
	}

	rec = ZeroMalloc(sizeof(RECORD));
	rec->Tick = Tick64();
	rec->ParseProc = proc;
	rec->Data = data;

	LockQueue(g->RecordQueue);
	{
		InsertQueue(g->RecordQueue, rec);
	}
	UnlockQueue(g->RecordQueue);

	Set(g->Event);
}

// Lock the log
void LockLog(LOG *g)
{
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	Lock(g->lock);
}

// Unlock the log
void UnlockLog(LOG *g)
{
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	Unlock(g->lock);
}

// Generate the string portion of the log file name from the time and the switching rule
void MakeLogFileNameStringFromTick(LOG *g, char *str, UINT size, UINT64 tick, UINT switch_type)
{
	UINT64 time;
	SYSTEMTIME st;

	// Validate arguments
	if (str == NULL || g == NULL)
	{
		return;
	}

	if (g->CacheFlag)
	{
		if (g->LastTick == tick &&
			g->LastSwitchType == switch_type)
		{
			StrCpy(str, size, g->LastStr);
			return;
		}
	}

	time = TickToTime(tick);
	UINT64ToSystem(&st, SystemToLocal64(time));

	switch (switch_type)
	{
	case LOG_SWITCH_SECOND:	// Secondly basis
		snprintf(str, size, "_%04u%02u%02u_%02u%02u%02u",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		break;

	case LOG_SWITCH_MINUTE:	// Minutely basis
		snprintf(str, size, "_%04u%02u%02u_%02u%02u",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
		break;

	case LOG_SWITCH_HOUR:	// Hourly basis
		snprintf(str, size, "_%04u%02u%02u_%02u", st.wYear, st.wMonth, st.wDay, st.wHour);
		break;

	case LOG_SWITCH_DAY:	// Daily basis
		snprintf(str, size, "_%04u%02u%02u", st.wYear, st.wMonth, st.wDay);
		break;

	case LOG_SWITCH_MONTH:	// Monthly basis
		snprintf(str, size, "_%04u%02u", st.wYear, st.wMonth);
		break;

	default:				// Without switching
		snprintf(str, size, "");
		break;
	}

	g->CacheFlag = true;
	g->LastTick = tick;
	g->LastSwitchType = switch_type;
	StrCpy(g->LastStr, sizeof(g->LastStr), str);
}

// Create a log file name
bool MakeLogFileName(LOG *g, char *name, UINT size, char *dir, char *prefix, UINT64 tick, UINT switch_type, UINT num, char *old_datestr)
{
	char tmp[MAX_SIZE];
	char tmp2[64];
	bool ret = false;
	// Validate arguments
	if (g == NULL || name == NULL || prefix == NULL || old_datestr == NULL)
	{
		return false;
	}

	MakeLogFileNameStringFromTick(g, tmp, sizeof(tmp), tick, switch_type);

	if (num == 0)
	{
		tmp2[0] = 0;
	}
	else
	{
		UINT64 max_log_size = GetMaxLogSize();
		if (max_log_size == MAX_LOG_SIZE_DEFAULT)
		{
			snprintf(tmp2, sizeof(tmp2), "~%02u", num);
		}
		else
		{
			char tag[32];
			char c = '2';
			if (max_log_size >= 1000000000ULL)
			{
				c = '3';
			}
			else if (max_log_size >= 100000000ULL)
			{
				c = '4';
			}
			else if (max_log_size >= 10000000ULL)
			{
				c = '5';
			}
			else if (max_log_size >= 1000000ULL)
			{
				c = '6';
			}
			else if (max_log_size >= 100000ULL)
			{
				c = '7';
			}
			else if (max_log_size >= 10000ULL)
			{
				c = '8';
			}
			else if (max_log_size >= 1000ULL)
			{
				c = '9';
			}

			StrCpy(tag, sizeof(tag), "~%02u");
			tag[3] = c;

			snprintf(tmp2, sizeof(tmp2), tag, num);
		}
	}

	if (strcmp(old_datestr, tmp) != 0)
	{
		ret = true;
		strcpy(old_datestr, tmp);
	}

	snprintf(name, size, "%s%s%s%s%s.log", dir,
		StrLen(dir) == 0 ? "" : "/",
		prefix, tmp, tmp2
		);

	return ret;
}

// Wait until the log have been flushed
void WaitLogFlush(LOG *g)
{
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	while (true)
	{
		UINT num;
		LockQueue(g->RecordQueue);
		{
			num = g->RecordQueue->num_item;
		}
		UnlockQueue(g->RecordQueue);

		if (num == 0)
		{
			break;
		}

		Wait(g->FlushEvent, 100);
	}
}

// Set the max log size
void SetMaxLogSize(UINT64 size)
{
	if (size == 0)
	{
		size = MAX_LOG_SIZE_DEFAULT;
	}

	logger_max_log_size = size;
}

// Get the max log size
UINT64 GetMaxLogSize()
{
	UINT64 ret = logger_max_log_size;

	if (ret == 0)
	{
		ret = MAX_LOG_SIZE_DEFAULT;
	}

	return ret;
}

// Logging thread
void LogThread(THREAD *thread, void *param)
{
	LOG *g;
	IO *io;
	BUF *b;
	bool flag = false;
	char current_file_name[MAX_SIZE];
	char current_logfile_datename[MAX_SIZE];
	bool last_priority_flag = false;
	bool log_date_changed = false;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	Zero(current_file_name, sizeof(current_file_name));
	Zero(current_logfile_datename, sizeof(current_logfile_datename));

	g = (LOG *)param;

	io = NULL;
	b = NewBuf();

#ifdef	OS_WIN32

	// Lower priority to bottom
	MsSetThreadPriorityIdle();

#endif	// OS_WIN32

	NoticeThreadInit(thread);

	while (true)
	{
		RECORD *rec;
		UINT64 s = Tick64();

		while (true)
		{
			char file_name[MAX_SIZE];
			UINT num;

			// Retrieve a record from the head of the queue
			LockQueue(g->RecordQueue);
			{
				rec = GetNext(g->RecordQueue);
				num = g->RecordQueue->num_item;
			}
			UnlockQueue(g->RecordQueue);

#ifdef	OS_WIN32
			if (num >= LOG_ENGINE_SAVE_START_CACHE_COUNT)
			{
				// Raise the priority
				if (last_priority_flag == false)
				{
					Debug("LOG_THREAD: MsSetThreadPriorityRealtime\n");
					MsSetThreadPriorityRealtime();
					last_priority_flag = true;
				}
			}

			if (num < (LOG_ENGINE_SAVE_START_CACHE_COUNT / 2))
			{
				// Restore the priority
				if (last_priority_flag)
				{
					Debug("LOG_THREAD: MsSetThreadPriorityIdle\n");
					MsSetThreadPriorityIdle();
					last_priority_flag = false;
				}
			}
#endif	// OS_WIN32

			if (b->Size > GetMaxLogSize())
			{
				// Erase if the size of the buffer is larger than the maximum log file size
				ClearBuf(b);
			}

			if (b->Size >= LOG_ENGINE_BUFFER_CACHE_SIZE_MAX)
			{
				// Write the contents of the buffer to the file
				if (io != NULL)
				{
					if ((g->CurrentFilePointer + (UINT64)b->Size) > GetMaxLogSize())
					{
						if (g->log_number_incremented == false)
						{
							g->CurrentLogNumber++;
							g->log_number_incremented = true;
						}
					}
					else
					{
						if (FileWrite(io, b->Buf, b->Size) == false)
						{
							FileCloseEx(io, true);
							// If it fails to write to the file,
							// erase the buffer and give up
							ClearBuf(b);
							io = NULL;
						}
						else
						{
							g->CurrentFilePointer += (UINT64)b->Size;
							ClearBuf(b);
						}
					}
				}
			}

			if (rec == NULL)
			{
				if (b->Size != 0)
				{
					// Write the contents of the buffer to the file
					if (io != NULL)
					{
						if ((g->CurrentFilePointer + (UINT64)b->Size) > GetMaxLogSize())
						{
							if (g->log_number_incremented == false)
							{
								g->CurrentLogNumber++;
								g->log_number_incremented = true;
							}
						}
						else
						{
							if (FileWrite(io, b->Buf, b->Size) == false)
							{
								FileCloseEx(io, true);
								// If it fails to write to the file,
								// erase the buffer and give up
								ClearBuf(b);
								io = NULL;
							}
							else
							{
								g->CurrentFilePointer += (UINT64)b->Size;
								ClearBuf(b);
							}
						}
					}
				}

				Set(g->FlushEvent);
				break;
			}

			// Generate a log file name
			LockLog(g);
			{
				log_date_changed = MakeLogFileName(g, file_name, sizeof(file_name),
					g->DirName, g->Prefix, rec->Tick, g->SwitchType, g->CurrentLogNumber, current_logfile_datename);

				if (log_date_changed)
				{
					UINT i;

					g->CurrentLogNumber = 0;
					MakeLogFileName(g, file_name, sizeof(file_name),
						g->DirName, g->Prefix, rec->Tick, g->SwitchType, 0, current_logfile_datename);
					for (i = 0;;i++)
					{
						char tmp[MAX_SIZE];
						MakeLogFileName(g, tmp, sizeof(tmp),
							g->DirName, g->Prefix, rec->Tick, g->SwitchType, i, current_logfile_datename);

						if (IsFileExists(tmp) == false)
						{
							break;
						}
						StrCpy(file_name, sizeof(file_name), tmp);
						g->CurrentLogNumber = i;
					}
				}
			}
			UnlockLog(g);

			if (io != NULL)
			{
				if (StrCmp(current_file_name, file_name) != 0)
				{
					// If a log file is currently opened and writing to another log
					// file is needed for this time, write the contents of the 
					//buffer and close the log file. Write the contents of the buffer
					if (io != NULL)
					{
						if (log_date_changed)
						{
							if ((g->CurrentFilePointer + (UINT64)b->Size) <= GetMaxLogSize())
							{
								if (FileWrite(io, b->Buf, b->Size) == false)
								{
									FileCloseEx(io, true);
									ClearBuf(b);
									io = NULL;
								}
								else
								{
									g->CurrentFilePointer += (UINT64)b->Size;
									ClearBuf(b);
								}
							}
						}
						// Close the file
						FileCloseEx(io, true);
					}

					g->log_number_incremented = false;

					// Open or create a new log file
					StrCpy(current_file_name, sizeof(current_file_name), file_name);
					io = FileOpen(file_name, true);
					if (io == NULL)
					{
						// Create a log file
						LockLog(g);
						{
							MakeDir(g->DirName);

#ifdef	OS_WIN32
							Win32SetFolderCompress(g->DirName, true);
#endif	// OS_WIN32
						}
						UnlockLog(g);
						io = FileCreate(file_name);
						g->CurrentFilePointer = 0;
					}
					else
					{
						// Seek to the end of the log file
						g->CurrentFilePointer = FileSize64(io);
						FileSeek(io, SEEK_END, 0);
					}
				}
			}
			else
			{
				// Open or create a new log file
				StrCpy(current_file_name, sizeof(current_file_name), file_name);
				io = FileOpen(file_name, true);
				if (io == NULL)
				{
					// Create a log file
					LockLog(g);
					{
						MakeDir(g->DirName);
#ifdef	OS_WIN32
						Win32SetFolderCompress(g->DirName, true);
#endif	// OS_WIN32
					}
					UnlockLog(g);
					io = FileCreate(file_name);
					g->CurrentFilePointer = 0;
					if (io == NULL)
					{
						//Debug("Logging.c: SleepThread(30);\n");
						SleepThread(30);
					}
				}
				else
				{
					// Seek to the end of the log file
					g->CurrentFilePointer = FileSize64(io);
					FileSeek(io, SEEK_END, 0);
				}

				g->log_number_incremented = false;
			}

			// Write the contents of the log to the buffer
			WriteRecordToBuffer(b, rec);

			// Release the memory of record
			Free(rec);

			if (io == NULL)
			{
				break;
			}
		}

		if (g->Halt)
		{
			// Break after finishing to save all records
			// when the stop flag stood
			UINT num;

			if (flag == false)
			{
#ifdef	OS_WIN32
				MsSetThreadPriorityRealtime();
#endif	// OS_WIN32
				flag = true;
			}

			LockQueue(g->RecordQueue);
			{
				num = g->RecordQueue->num_item;
			}
			UnlockQueue(g->RecordQueue);

			if (num == 0 || io == NULL)
			{
				break;
			}
		}
		else
		{
			Wait(g->Event, 9821);
		}
	}

	if (io != NULL)
	{
		FileCloseEx(io, true);
	}

	FreeBuf(b);
}

// Write the contents of the log to the buffer
void WriteRecordToBuffer(BUF *b, RECORD *r)
{
	UINT64 time;
	char time_str[MAX_SIZE];
	char date_str[MAX_SIZE];
	char *s;
	// Validate arguments
	if (b == NULL || r == NULL)
	{
		return;
	}

	// Get the time
	time = SystemToLocal64(TickToTime(r->Tick));

	// Convert a time to a string
	GetDateStr64(date_str, sizeof(date_str), time);
	GetTimeStrMilli64(time_str, sizeof(time_str), time);

	if (r->ParseProc != PacketLogParseProc)
	{
		// Other than packet log
		WriteBuf(b, date_str, StrLen(date_str));
		WriteBuf(b, " ", 1);
		WriteBuf(b, time_str, StrLen(time_str));
		WriteBuf(b, " ", 1);
	}
	else
	{
		// Packet log
		WriteBuf(b, date_str, StrLen(date_str));
		WriteBuf(b, ",", 1);
		WriteBuf(b, time_str, StrLen(time_str));
		WriteBuf(b, ",", 1);
	}

	// Output text
	s = r->ParseProc(r);
	WriteBuf(b, s, StrLen(s));
	Free(s);

	WriteBuf(b, "\r\n", 2);
}

// End of logging
void FreeLog(LOG *g)
{
	RECORD *rec;
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	// Halting flag
	g->Halt = true;
	Set(g->Event);

	WaitThread(g->Thread, INFINITE);
	ReleaseThread(g->Thread);

	DeleteLock(g->lock);
	Free(g->DirName);
	Free(g->Prefix);

	// Release the unprocessed record if it remains
	// (It should not remain here)
	while (rec = GetNext(g->RecordQueue))
	{
		char *s = rec->ParseProc(rec);
		Free(s);
		Free(rec);
	}
	ReleaseQueue(g->RecordQueue);

	ReleaseEvent(g->Event);
	ReleaseEvent(g->FlushEvent);

	Free(g);
}

// Start a new logging
LOG *NewLog(char *dir, char *prefix, UINT switch_type)
{
	LOG *g;

	g = ZeroMalloc(sizeof(LOG));
	g->lock = NewLock();
	g->DirName = CopyStr(dir == NULL ? "" : dir);
	g->Prefix = CopyStr(prefix == NULL ? "log" : prefix);
	g->SwitchType = switch_type;
	g->RecordQueue = NewQueue();
	g->Event = NewEvent();
	g->FlushEvent = NewEvent();

	g->Thread = NewThread(LogThread, g);

	WaitThreadInit(g->Thread);

	return g;
}



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
