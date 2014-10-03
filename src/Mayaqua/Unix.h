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


// Unix.h
// Header of Unix.c

#ifdef	OS_UNIX

#ifndef	UNIX_H
#define	UNIX_H

// Constants
#define	UNIX_THREAD_STACK_SIZE			(200 * 1000)	// Stack size
#define	UNIX_MAX_CHILD_PROCESSES		2000000			// Maximum number of child processes
#define	UNIX_LINUX_MAX_THREADS			200000000		// Maximum number of threads
#define	UNIX_MAX_LOCKS					65536			// Maximum number of locks
#define	UNIX_MAX_MEMORY					(2147483648UL)	// Maximum memory capacity
#define	UNIX_MAX_MEMORY_64				((UINT64)((UINT64)65536ULL * (UINT64)2147483647ULL))	// Maximum memory capacity (64-bit)
#define	UNIX_MAX_FD						(655360)		// Maximum number of FDs
#define	UNIX_MAX_FD_MACOS				(10000)			// Maximum number of FDs (Mac OS X)
#define	MAXIMUM_WAIT_OBJECTS			64				// Maximum number of select

#define	UNIX_SERVICE_STOP_TIMEOUT_1		(60 * 1000)	// Timeout to stop the service
#define	UNIX_SERVICE_STOP_TIMEOUT_2		(90 * 1000)	// Timeout to stop the service (parent process)


// Service related
typedef void (SERVICE_FUNCTION)();

#define	SVC_NAME					"SVC_%s_NAME"
#define	SVC_TITLE					"SVC_%s_TITLE"

#define	UNIX_SVC_ARG_START				"start"
#define	UNIX_SVC_ARG_STOP				"stop"
#define	UNIX_SVC_ARG_EXEC_SVC			"execsvc"
#define	UNIX_ARG_EXIT					"exit"

#define	UNIX_SVC_MODE_START				1
#define	UNIX_SVC_MODE_STOP				2
#define	UNIX_SVC_MODE_EXEC_SVC			3
#define	UNIX_SVC_MODE_EXIT				4


// Function prototype
OS_DISPATCH_TABLE *UnixGetDispatchTable();
void UnixInit();
void UnixFree();
void *UnixMemoryAlloc(UINT size);
void *UnixMemoryReAlloc(void *addr, UINT size);
void UnixMemoryFree(void *addr);
UINT UnixGetTick();
void UnixGetSystemTime(SYSTEMTIME *system_time);
void UnixInc32(UINT *value);
void UnixDec32(UINT *value);
void UnixSleep(UINT time);
LOCK *UnixNewLock();
bool UnixLock(LOCK *lock);
void UnixUnlock(LOCK *lock);
void UnixUnlockEx(LOCK *lock, bool inner);
void UnixDeleteLock(LOCK *lock);
void UnixInitEvent(EVENT *event);
void UnixSetEvent(EVENT *event);
void UnixResetEvent(EVENT *event);
bool UnixWaitEvent(EVENT *event, UINT timeout);
void UnixFreeEvent(EVENT *event);
bool UnixWaitThread(THREAD *t);
void UnixFreeThread(THREAD *t);
bool UnixInitThread(THREAD *t);
UINT UnixThreadId();
void *UnixFileOpen(char *name, bool write_mode, bool read_lock);
void *UnixFileOpenW(wchar_t *name, bool write_mode, bool read_lock);
void *UnixFileCreate(char *name);
void *UnixFileCreateW(wchar_t *name);
bool UnixFileWrite(void *pData, void *buf, UINT size);
bool UnixFileRead(void *pData, void *buf, UINT size);
void UnixFileClose(void *pData, bool no_flush);
void UnixFileFlush(void *pData);
UINT64 UnixFileSize(void *pData);
bool UnixFileSeek(void *pData, UINT mode, int offset);
bool UnixFileDelete(char *name);
bool UnixFileDeleteW(wchar_t *name);
bool UnixMakeDir(char *name);
bool UnixMakeDirW(wchar_t *name);
bool UnixDeleteDir(char *name);
bool UnixDeleteDirW(wchar_t *name);
CALLSTACK_DATA *UnixGetCallStack();
bool UnixGetCallStackSymbolInfo(CALLSTACK_DATA *s);
bool UnixFileRename(char *old_name, char *new_name);
bool UnixFileRenameW(wchar_t *old_name, wchar_t *new_name);
bool UnixRun(char *filename, char *arg, bool hide, bool wait);
bool UnixRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait);
bool UnixIsSupportedOs();
void UnixGetOsInfo(OS_INFO *info);
void UnixAlert(char *msg, char *caption);
void UnixAlertW(wchar_t *msg, wchar_t *caption);
char *UnixGetProductId();
void UnixSetHighPriority();
void UnixSetHighOomScore();
void UnixRestorePriority();
void *UnixNewSingleInstance(char *instance_name);
void UnixFreeSingleInstance(void *data);
void UnixGetMemInfo(MEMINFO *info);
void UnixYield();
TOKEN_LIST *UnixExec(char *cmd);
void UnixExecSilent(char *cmd);
void UnixDisableInterfaceOffload(char *name);
void UnixSetEnableKernelEspProcessing(bool b);

void UnixDisableCoreDump();
void UnixSetThreadPriorityRealtime();
void UnixSetThreadPriorityLow();
void UnixSetThreadPriorityHigh();
void UnixSetThreadPriorityIdle();
void UnixRestoreThreadPriority();
void UnixSetResourceLimit(UINT id, UINT64 value);
bool UnixIs64BitRlimSupported();
UINT64 UnixGetTick64();
void UnixSigChldHandler(int sig);
void UnixCloseIO();
void UnixDaemon(bool debug_mode);
void UnixGetCurrentDir(char *dir, UINT size);
void UnixGetCurrentDirW(wchar_t *dir, UINT size);
bool UnixCheckExecAccess(char *name);
bool UnixCheckExecAccessW(wchar_t *name);
DIRLIST *UnixEnumDirEx(char *dirname, COMPARE *compare);
DIRLIST *UnixEnumDirExW(wchar_t *dirname, COMPARE *compare);
bool UnixGetDiskFreeMain(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
bool UnixGetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
bool UnixGetDiskFreeW(wchar_t *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size);
void UnixInitSolarisSleep();
void UnixFreeSolarisSleep();
void UnixSolarisSleep(UINT msec);

UINT UnixService(int argc, char *argv[], char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void UnixServiceMain(int argc, char *argv[], char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void UnixGenPidFileName(char *name, UINT size);
void UnixGenCtlFileName(char *name, UINT size);
void UnixStartService(char *name);
void UnixStopService(char *name);
void UnixExecService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop);
void UnixUsage(char *name);
void UnixWritePidFile(UINT pid);
void UnixWriteCtlFile(UINT i);
UINT UnixReadPidFile();
UINT UnixReadCtlFile();
bool UnixIsProcess(UINT pid);
bool UnixWaitProcessEx(UINT pid, UINT timeout);
void UnixWaitProcess(UINT pid);
void UnixDeletePidFile();
void UnixDeleteCtlFile();
void UnixStopThread(THREAD *t, void *param);
UINT UnixGetUID();
void UnixIgnoreSignalForThread(int sig);

bool UnixIsInVmMain();
bool UnixIsInVm();


#endif	// UNIX_H

#endif	// OS_UNIX


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
