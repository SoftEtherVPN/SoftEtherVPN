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


// OS.h
// Header of OS.c

#ifndef	OS_H
#define	OS_H

// Function prototype
char *OsTypeToStr(UINT type);

void OSInit();
void OSFree();
void *OSMemoryAlloc(UINT size);
void *OSMemoryReAlloc(void *addr, UINT size);
void OSMemoryFree(void *addr);
UINT OSGetTick();
void OSGetSystemTime(SYSTEMTIME *system_time);
void OSInc32(UINT *value);
void OSDec32(UINT *value);
void OSSleep(UINT time);
LOCK *OSNewLock();
bool OSLock(LOCK *lock);
void OSUnlock(LOCK *lock);
void OSDeleteLock(LOCK *lock);
void OSInitEvent(EVENT *event);
void OSSetEvent(EVENT *event);
void OSResetEvent(EVENT *event);
bool OSWaitEvent(EVENT *event, UINT timeout);
void OSFreeEvent(EVENT *event);
bool OSWaitThread(THREAD *t);
void OSFreeThread(THREAD *t);
bool OSInitThread(THREAD *t);
void *OSFileOpen(char *name, bool write_mode, bool read_lock);
void *OSFileOpenW(wchar_t *name, bool write_mode, bool read_lock);
void *OSFileCreate(char *name);
void *OSFileCreateW(wchar_t *name);
bool OSFileWrite(void *pData, void *buf, UINT size);
bool OSFileRead(void *pData, void *buf, UINT size);
void OSFileClose(void *pData, bool no_flush);
void OSFileFlush(void *pData);
UINT64 OSFileSize(void *pData);
bool OSFileSeek(void *pData, UINT mode, int offset);
bool OSFileDelete(char *name);
bool OSFileDeleteW(wchar_t *name);
bool OSMakeDir(char *name);
bool OSMakeDirW(wchar_t *name);
bool OSDeleteDir(char *name);
bool OSDeleteDirW(wchar_t *name);
CALLSTACK_DATA *OSGetCallStack();
bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s);
bool OSFileRename(char *old_name, char *new_name);
bool OSFileRenameW(wchar_t *old_name, wchar_t *new_name);
UINT OSThreadId();
bool OSRun(char *filename, char *arg, bool hide, bool wait);
bool OSRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
bool OSIsSupportedOs();
void OSGetOsInfo(OS_INFO *info);
void OSAlert(char *msg, char *caption);
void OSAlertW(wchar_t *msg, wchar_t *caption);
char* OSGetProductId();
void OSSetHighPriority();
void OSRestorePriority();
void *OSNewSingleInstance(char *instance_name);
void OSFreeSingleInstance(void *data);
void OSGetMemInfo(MEMINFO *info);
void OSYield();

// Dispatch table
typedef struct OS_DISPATCH_TABLE
{
	void (*Init)();
	void (*Free)();
	void *(*MemoryAlloc)(UINT size);
	void *(*MemoryReAlloc)(void *addr, UINT size);
	void (*MemoryFree)(void *addr);
	UINT (*GetTick)();
	void (*GetSystemTime)(SYSTEMTIME *system_time);
	void (*Inc32)(UINT *value);
	void (*Dec32)(UINT *value);
	void (*Sleep)(UINT time);
	LOCK *(*NewLock)();
	bool (*Lock)(LOCK *lock);
	void (*Unlock)(LOCK *lock);
	void (*DeleteLock)(LOCK *lock);
	void (*InitEvent)(EVENT *event);
	void (*SetEvent)(EVENT *event);
	void (*ResetEvent)(EVENT *event);
	bool (*WaitEvent)(EVENT *event, UINT timeout);
	void (*FreeEvent)(EVENT *event);
	bool (*WaitThread)(THREAD *t);
	void (*FreeThread)(THREAD *t);
	bool (*InitThread)(THREAD *t);
	UINT (*ThreadId)();
	void *(*FileOpen)(char *name, bool write_mode, bool read_lock);
	void *(*FileOpenW)(wchar_t *name, bool write_mode, bool read_lock);
	void *(*FileCreate)(char *name);
	void *(*FileCreateW)(wchar_t *name);
	bool (*FileWrite)(void *pData, void *buf, UINT size);
	bool (*FileRead)(void *pData, void *buf, UINT size);
	void (*FileClose)(void *pData, bool no_flush);
	void (*FileFlush)(void *pData);
	UINT64 (*FileSize)(void *pData);
	bool (*FileSeek)(void *pData, UINT mode, int offset);
	bool (*FileDelete)(char *name);
	bool (*FileDeleteW)(wchar_t *name);
	bool (*MakeDir)(char *name);
	bool (*MakeDirW)(wchar_t *name);
	bool (*DeleteDir)(char *name);
	bool (*DeleteDirW)(wchar_t *name);
	CALLSTACK_DATA *(*GetCallStack)();
	bool (*GetCallStackSymbolInfo)(CALLSTACK_DATA *s);
	bool (*FileRename)(char *old_name, char *new_name);
	bool (*FileRenameW)(wchar_t *old_name, wchar_t *new_name);
	bool (*Run)(char *filename, char *arg, bool hide, bool wait);
	bool (*RunW)(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
	bool (*IsSupportedOs)();
	void (*GetOsInfo)(OS_INFO *info);
	void (*Alert)(char *msg, char *caption);
	void (*AlertW)(wchar_t *msg, wchar_t *caption);
	char *(*GetProductId)();
	void (*SetHighPriority)();
	void (*RestorePriority)();
	void *(*NewSingleInstance)(char *instance_name);
	void (*FreeSingleInstance)(void *data);
	void (*GetMemInfo)(MEMINFO *info);
	void (*Yield)();
} OS_DISPATCH_TABLE;

// Include the OS-specific header
#ifdef	OS_WIN32
#include <Mayaqua/Win32.h>
#else	//OS_WIN32
#include <Mayaqua/Unix.h>
#endif	// OS_WIN32

#endif	// OS_H


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
