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


// Win32.h
// Header of Win32.c

#ifdef	OS_WIN32

#ifndef	WIN32_H
#define	WIN32_H

// Function prototype
OS_DISPATCH_TABLE *Win32GetDispatchTable();

void Win32Init();
void Win32Free();
void *Win32MemoryAlloc(UINT size);
void *Win32MemoryReAlloc(void *addr, UINT size);
void Win32MemoryFree(void *addr);
UINT Win32GetTick();
void Win32GetSystemTime(SYSTEMTIME *system_time);
void Win32Inc32(UINT *value);
void Win32Dec32(UINT *value);
void Win32Sleep(UINT time);
LOCK *Win32NewLock();
bool Win32Lock(LOCK *lock);
void Win32Unlock(LOCK *lock);
void Win32DeleteLock(LOCK *lock);
void Win32InitEvent(EVENT *event);
void Win32SetEvent(EVENT *event);
void Win32ResetEvent(EVENT *event);
bool Win32WaitEvent(EVENT *event, UINT timeout);
void Win32FreeEvent(EVENT *event);
bool Win32WaitThread(THREAD *t);
void Win32FreeThread(THREAD *t);
bool Win32InitThread(THREAD *t);
UINT Win32ThreadId();
void *Win32FileOpen(char *name, bool write_mode, bool read_lock);
void *Win32FileOpenW(wchar_t *name, bool write_mode, bool read_lock);
void *Win32FileCreate(char *name);
void *Win32FileCreateW(wchar_t *name);
bool Win32FileWrite(void *pData, void *buf, UINT size);
bool Win32FileRead(void *pData, void *buf, UINT size);
bool Win32FileSetDate(void *pData, UINT64 created_time, UINT64 updated_time);
bool Win32FileGetDate(void *pData, UINT64 *created_time, UINT64 *updated_time, UINT64 *accessed_date);
void Win32FileClose(void *pData, bool no_flush);
void Win32FileFlush(void *pData);
UINT64 Win32FileSize(void *pData);
bool Win32FileSeek(void *pData, UINT mode, int offset);
bool Win32FileDelete(char *name);
bool Win32FileDeleteW(wchar_t *name);
bool Win32MakeDir(char *name);
bool Win32MakeDirW(wchar_t *name);
bool Win32DeleteDir(char *name);
bool Win32DeleteDirW(wchar_t *name);
CALLSTACK_DATA *Win32GetCallStack();
bool Win32GetCallStackSymbolInfo(CALLSTACK_DATA *s);
bool Win32FileRename(char *old_name, char *new_name);
bool Win32FileRenameW(wchar_t *old_name, wchar_t *new_name);
bool Win32Run(char *filename, char *arg, bool hide, bool wait);
bool Win32RunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
void *Win32RunEx(char *filename, char *arg, bool hide);
void *Win32RunEx2(char *filename, char *arg, bool hide, UINT *process_id);
void *Win32RunEx3(char *filename, char *arg, bool hide, UINT *process_id, bool disableWow);
void *Win32RunExW(wchar_t *filename, wchar_t *arg, bool hide);
void *Win32RunEx2W(wchar_t *filename, wchar_t *arg, bool hide, UINT *process_id);
void *Win32RunEx3W(wchar_t *filename, wchar_t *arg, bool hide, UINT *process_id, bool disableWow);
bool Win32WaitProcess(void *h, UINT timeout);
bool Win32RunAndWaitProcess(wchar_t *filename, wchar_t *arg, bool hide, bool disableWow, UINT timeout);
bool Win32IsProcessAlive(void *handle);
bool Win32TerminateProcess(void *handle);
void Win32CloseProcess(void *handle);
bool Win32IsSupportedOs();
void Win32GetOsInfo(OS_INFO *info);
void Win32Alert(char *msg, char *caption);
void Win32AlertW(wchar_t *msg, wchar_t *caption);
void Win32DebugAlert(char *msg);
char* Win32GetProductId();
void Win32SetHighPriority();
void Win32RestorePriority();
void *Win32NewSingleInstance(char *instance_name);
void Win32FreeSingleInstance(void *data);
void Win32GetMemInfo(MEMINFO *info);
void Win32Yield();

void Win32UnlockEx(LOCK *lock, bool inner);
UINT Win32GetOsType();
UINT Win32GetSpVer(char *str);
UINT Win32GetOsSpVer();
void Win32NukuEn(char *dst, UINT size, char *src);
void Win32NukuEnW(wchar_t *dst, UINT size, wchar_t *src);
void Win32GetDirFromPath(char *dst, UINT size, char *src);
void Win32GetDirFromPathW(wchar_t *dst, UINT size, wchar_t *src);
void Win32GetExeDir(char *name, UINT size);
void Win32GetExeDirW(wchar_t *name, UINT size);
void Win32GetCurrentDir(char *dir, UINT size);
void Win32GetCurrentDirW(wchar_t *dir, UINT size);
void Win32GetExeName(char *name, UINT size);
void Win32GetExeNameW(wchar_t *name, UINT size);
DIRLIST *Win32EnumDirEx(char *dirname, COMPARE *compare);
DIRLIST *Win32EnumDirExW(wchar_t *dirname, COMPARE *compare);
bool Win32GetDiskFreeW(wchar_t *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
bool Win32GetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
bool Win32SetFolderCompress(char *path, bool compressed);
bool Win32SetFolderCompressW(wchar_t *path, bool compressed);
UINT64 Win32FastTick64();
void Win32InitNewThread();
bool Win32IsNt();
bool Win32InputW(wchar_t *str, UINT size);
bool Win32InputFromFileW(wchar_t *str, UINT size);
char *Win32InputFromFileLineA();
void Win32PrintW(wchar_t *str);
void Win32PrintToFileW(wchar_t *str);
bool Win32GetVersionExInternal(void *info);
bool Win32GetVersionExInternalForWindows81orLater(void *info);

void Win32SetThreadName(UINT thread_id, char *name);

#endif	// WIN32_H

#endif	// OS_WIN32



// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
