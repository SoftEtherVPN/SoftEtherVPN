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


// Logging.h
// Header of Logging.c

#ifndef	LOGGING_H
#define	LOGGING_H


// Port number for HTTP monitoring
#define	LOG_HTTP_PORT						80


#define	MAX_LOG_SIZE_DEFAULT				1073741823ULL

typedef char *(RECORD_PARSE_PROC)(RECORD *rec);

// Packet log structure
struct PACKET_LOG
{
	CEDAR *Cedar;
	struct PKT *Packet;
	char *SrcSessionName;
	char *DestSessionName;
	bool WritePhysicalIP;
	char SrcPhysicalIP[64];
	char DestPhysicalIP[64];
	bool PurePacket;						// Packet not cloned
	bool PurePacketNoPayload;				// Packet not cloned (without payload)
	SESSION *SrcSession;
	bool NoLog;								// Not to write a log
};

// Log save options of the HUB
struct HUB_LOG
{
	bool SaveSecurityLog;					// To save the security log
	UINT SecurityLogSwitchType;				// Switching type of security log
	bool SavePacketLog;						// To save the packet log
	UINT PacketLogSwitchType;				// Switching type of packet log
	UINT PacketLogConfig[NUM_PACKET_LOG];	// Packet log settings
};

// Record
struct RECORD
{
	UINT64 Tick;							// Time
	RECORD_PARSE_PROC *ParseProc;			// Parsing procedure
	void *Data;								// Data
};

// LOG object
struct LOG
{
	LOCK *lock;								// Lock
	THREAD *Thread;							// Thread
	char *DirName;							// Destination directory name
	char *Prefix;							// File name
	UINT SwitchType;						// Switching type of log file
	QUEUE *RecordQueue;						// Record queue
	volatile bool Halt;						// Halting flag
	EVENT *Event;							// Event for Log
	EVENT *FlushEvent;						// Flash completion event
	bool CacheFlag;
	UINT64 LastTick;
	UINT LastSwitchType;
	char LastStr[MAX_SIZE];
	UINT64 CurrentFilePointer;				// The current file pointer
	UINT CurrentLogNumber;					// Log file number of the current
	bool log_number_incremented;
};


// ERASER object
struct ERASER
{
	LOG *Log;								// Logger
	UINT64 MinFreeSpace;					// Disk space to start deleting files
	char *DirName;							// Directory name
	volatile bool Halt;						// Halting flag
	THREAD *Thread;							// Thread
	bool LastFailed;						// Whether deletion of the file failed at the end
	EVENT *HaltEvent;						// Halting event
};

// List of files that can be deleted
typedef struct ERASE_FILE
{
	char *FullPath;							// Full path
	UINT64 UpdateTime;						// Updating date
} ERASE_FILE;

// SYSLOG object
struct SLOG
{
	LOCK *lock;								// Lock
	SOCK *Udp;								// UDP socket
	IP DestIp;								// Destination IP address
	UINT DestPort;							// Destination port number
	char HostName[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT64 NextPollIp;						// Time of examination of the IP address at the end
};

// Function prototype
LOG *NewLog(char *dir, char *prefix, UINT switch_type);
void FreeLog(LOG *g);
void LogThread(THREAD *thread, void *param);
void WaitLogFlush(LOG *g);
void LockLog(LOG *g);
void UnlockLog(LOG *g);
void InsertRecord(LOG *g, void *data, RECORD_PARSE_PROC *proc);
void InsertStringRecord(LOG *g, char *str);
void InsertUnicodeRecord(LOG *g, wchar_t *unistr);
char *StringRecordParseProc(RECORD *rec);
bool MakeLogFileName(LOG *g, char *name, UINT size, char *dir, char *prefix, UINT64 tick, UINT switch_type, UINT num, char *old_datestr);
void MakeLogFileNameStringFromTick(LOG *g, char *str, UINT size, UINT64 tick, UINT switch_type);
void WriteRecordToBuffer(BUF *b, RECORD *r);
void SetLogDirName(LOG *g, char *dir);
void SetLogPrefix(LOG *g, char *prefix);
void SetLogSwitchType(LOG *g, UINT switch_type);
bool PacketLog(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *packet, UINT64 now);
char *PacketLogParseProc(RECORD *rec);
UINT CalcPacketLoggingLevel(HUB *hub, PKT *packet);
UINT CalcPacketLoggingLevelEx(HUB_LOG *g, PKT *packet);
char *GenCsvLine(TOKEN_LIST *t);
void ReplaceForCsv(char *str);
char *PortStr(CEDAR *cedar, UINT port, bool udp);
char *TcpFlagStr(UCHAR flag);
void WriteSecurityLog(HUB *h, char *str);
void SecLog(HUB *h, char *fmt, ...);
void SiSetDefaultLogSetting(HUB_LOG *g);
void DebugLog(CEDAR *c, char *fmt, ...);
void HubLog(HUB *h, wchar_t *fmt, ...);
void ServerLog(CEDAR *c, wchar_t *fmt, ...);
void SLog(CEDAR *c, char *name, ...);
void WriteHubLog(HUB *h, wchar_t *str);
void HLog(HUB *h, char *name, ...);
void NLog(VH *v, char *name, ...);
void IPCLog(IPC *ipc, char *name, ...);
void PPPLog(PPP_SESSION *p, char *name, ...);
void IPsecLog(IKE_SERVER *ike, IKE_CLIENT *c, IKE_SA *ike_sa, IPSECSA *ipsec_sa, char *name, ...);
void EtherIPLog(ETHERIP_SERVER *s, char *name, ...);
void WriteServerLog(CEDAR *c, wchar_t *str);
void ALog(ADMIN *a, HUB *h, char *name, ...);
void CLog(CLIENT *c, char *name, ...);
void WriteClientLog(CLIENT *c, wchar_t *str);
ERASER *NewEraser(LOG *log, UINT64 min_size);
void FreeEraser(ERASER *e);
void ELog(ERASER *e, char *name, ...);
void EraserThread(THREAD *t, void *p);
void EraserMain(ERASER *e);
bool CheckEraserDiskFreeSpace(ERASER *e);
int CompareEraseFile(void *p1, void *p2);
LIST *GenerateEraseFileList(ERASER *e);
void FreeEraseFileList(LIST *o);
void PrintEraseFileList(LIST *o);
void EnumEraseFile(LIST *o, char *dirname);
SLOG *NewSysLog(char *hostname, UINT port);
void SetSysLog(SLOG *g, char *hostname, UINT port);
void FreeSysLog(SLOG *g);
void SendSysLog(SLOG *g, wchar_t *str);
void WriteMultiLineLog(LOG *g, BUF *b);
char *BuildHttpLogStr(HTTPLOG *h);
void MakeSafeLogStr(char *str);
void AddLogBufToStr(BUF *b, char *name, char *value);
void SetEraserCheckInterval(UINT interval);
UINT GetEraserCheckInterval();
void SetMaxLogSize(UINT64 size);
UINT64 GetMaxLogSize();

#endif	// LOGGING_G


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
