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


// OS.c
// Operating system dependent code

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

#undef	Lock
#undef	Unlock

// Dispatch table
static OS_DISPATCH_TABLE *os = NULL;

// Convert OS type to a string
char *OsTypeToStr(UINT type)
{
	switch (type)
	{
	case 0:
		return "Unsupported OS by SoftEther VPN\0\n";
	case OSTYPE_WINDOWS_95:
		return "Windows 95\0\n";
	case OSTYPE_WINDOWS_98:
		return "Windows 98\0\n";
	case OSTYPE_WINDOWS_ME:
		return "Windows Millennium Edition\0\n";
	case OSTYPE_WINDOWS_UNKNOWN:
		return "Windows 9x Unknown Version\0\n";
	case OSTYPE_WINDOWS_NT_4_WORKSTATION:
		return "Windows NT 4.0 Workstation\0\n";
	case OSTYPE_WINDOWS_NT_4_SERVER:
		return "Windows NT 4.0 Server\0\n";
	case OSTYPE_WINDOWS_NT_4_SERVER_ENTERPRISE:
		return "Windows NT 4.0 Server, Enterprise Edition\0\n";
	case OSTYPE_WINDOWS_NT_4_BACKOFFICE:
		return "BackOffice Server 4.5\0\n";
	case OSTYPE_WINDOWS_NT_4_SMS:
		return "Small Business Server 4.5\0\n";
	case OSTYPE_WINDOWS_2000_PROFESSIONAL:
		return "Windows 2000 Professional\0\n";
	case OSTYPE_WINDOWS_2000_SERVER:
		return "Windows 2000 Server\0\n";
	case OSTYPE_WINDOWS_2000_ADVANCED_SERVER:
		return "Windows 2000 Advanced Server\0\n";
	case OSTYPE_WINDOWS_2000_DATACENTER_SERVER:
		return "Windows 2000 Datacenter Server\0\n";
	case OSTYPE_WINDOWS_2000_BACKOFFICE:
		return "BackOffice Server 2000\0\n";
	case OSTYPE_WINDOWS_2000_SBS:
		return "Small Business Server 2000\0\n";
	case OSTYPE_WINDOWS_XP_HOME:
		return "Windows XP Home Edition\0\n";
	case OSTYPE_WINDOWS_XP_PROFESSIONAL:
		return "Windows XP Professional\0\n";
	case OSTYPE_WINDOWS_2003_WEB:
		return "Windows Server 2003 Web Edition\0\n";
	case OSTYPE_WINDOWS_2003_STANDARD:
		return "Windows Server 2003 Standard Edition\0\n";
	case OSTYPE_WINDOWS_2003_ENTERPRISE:
		return "Windows Server 2003 Enterprise Edition\0\n";
	case OSTYPE_WINDOWS_2003_DATACENTER:
		return "Windows Server 2003 Datacenter Edition\0\n";
	case OSTYPE_WINDOWS_2003_BACKOFFICE:
		return "BackOffice Server 2003\0\n";
	case OSTYPE_WINDOWS_2003_SBS:
		return "Small Business Server 2003\0\n";
	case OSTYPE_WINDOWS_LONGHORN_PROFESSIONAL:
		return "Windows Vista\0\n";
	case OSTYPE_WINDOWS_LONGHORN_SERVER:
		return "Windows Server 2008\0\n";
	case OSTYPE_WINDOWS_7:
		return "Windows 7\0\n";
	case OSTYPE_WINDOWS_SERVER_2008_R2:
		return "Windows Server 2008 R2\0\n";
	case OSTYPE_WINDOWS_8:
		return "Windows 8\0\n";
	case OSTYPE_WINDOWS_SERVER_8:
		return "Windows Server 2012\0\n";
	case OSTYPE_WINDOWS_81:
		return "Windows 8.1\0\n";
	case OSTYPE_WINDOWS_SERVER_81:
		return "Windows Server 2012 R2\0\n";
	case OSTYPE_WINDOWS_10:
		return "Windows 10\0\n";
	case OSTYPE_WINDOWS_SERVER_10:
		return "Windows Server 10\0\n";
	case OSTYPE_WINDOWS_11:
		return "Windows 11 or later\0\n";
	case OSTYPE_WINDOWS_SERVER_11:
		return "Windows Server 11 or later\0\n";
	case OSTYPE_UNIX_UNKNOWN:
		return "UNIX System\0\n";
	case OSTYPE_LINUX:
		return "Linux\0\n";
	case OSTYPE_SOLARIS:
		return "Sun Solaris\0\n";
	case OSTYPE_CYGWIN:
		return "Gnu Cygwin\0\n";
	case OSTYPE_BSD:
		return "BSD System\0\n";
	case OSTYPE_MACOS_X:
		return "Mac OS X\0\n";
	}

	return "Unknown OS";
}

// Initialization
void OSInit()
{
	// Get the dispatch table
#ifdef	OS_WIN32
	os = Win32GetDispatchTable();
#else	// OS_WIN32
	os = UnixGetDispatchTable();
#endif	// OS_WIN32

	// Calling the OS-specific initialization function
	os->Init();
}

// Release
void OSFree()
{
	os->Free();
}

// Get the memory information
void OSGetMemInfo(MEMINFO *info)
{
	// Validate arguments
	if (info == NULL)
	{
		return;
	}

	os->GetMemInfo(info);
}

// Yield
void OSYield()
{
	os->Yield();
}

// Start a Single instance
void *OSNewSingleInstance(char *instance_name)
{
	return os->NewSingleInstance(instance_name);
}

void OSFreeSingleInstance(void *data)
{
	os->FreeSingleInstance(data);
}

// Raise the priority
void OSSetHighPriority()
{
	os->SetHighPriority();
}

// Restore the priority
void OSRestorePriority()
{
	os->RestorePriority();
}

// Get the product ID
char* OSGetProductId()
{
	return os->GetProductId();
}

// Check whether the OS is supported
bool OSIsSupportedOs()
{
	return os->IsSupportedOs();
}

// Getting OS information
void OSGetOsInfo(OS_INFO *info)
{
	os->GetOsInfo(info);
}

// Show an alert
void OSAlert(char *msg, char *caption)
{
	os->Alert(msg, caption);
}
void OSAlertW(wchar_t *msg, wchar_t *caption)
{
	os->AlertW(msg, caption);
}

// Run a process
bool OSRun(char *filename, char *arg, bool hide, bool wait)
{
	return os->Run(filename, arg, hide, wait);
}
bool OSRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	return os->RunW(filename, arg, hide, wait);
}

// Get the Thread ID
UINT OSThreadId()
{
	return os->ThreadId();
}

// Rename
bool OSFileRename(char *old_name, char *new_name)
{
	return os->FileRename(old_name, new_name);
}
bool OSFileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	return os->FileRenameW(old_name, new_name);
}

// Get the file size
UINT64 OSFileSize(void *pData)
{
	return os->FileSize(pData);
}

// Seek the file
bool OSFileSeek(void *pData, UINT mode, int offset)
{
	return os->FileSeek(pData, mode, offset);
}

// Delete the file
bool OSFileDelete(char *name)
{
	return os->FileDelete(name);
}
bool OSFileDeleteW(wchar_t *name)
{
	return os->FileDeleteW(name);
}

// Create a directory
bool OSMakeDir(char *name)
{
	return os->MakeDir(name);
}
bool OSMakeDirW(wchar_t *name)
{
	return os->MakeDirW(name);
}

// Delete the directory
bool OSDeleteDir(char *name)
{
	return os->DeleteDir(name);
}
bool OSDeleteDirW(wchar_t *name)
{
	return os->DeleteDirW(name);
}

// Open the file
void *OSFileOpen(char *name, bool write_mode, bool read_lock)
{
	return os->FileOpen(name, write_mode, read_lock);
}
void *OSFileOpenW(wchar_t *name, bool write_mode, bool read_lock)
{
	return os->FileOpenW(name, write_mode, read_lock);
}

// Create a file
void *OSFileCreate(char *name)
{
	return os->FileCreate(name);
}
void *OSFileCreateW(wchar_t *name)
{
	return os->FileCreateW(name);
}

// Write to a file
bool OSFileWrite(void *pData, void *buf, UINT size)
{
	return os->FileWrite(pData, buf, size);
}

// Read from a file
bool OSFileRead(void *pData, void *buf, UINT size)
{
	return os->FileRead(pData, buf, size);
}

// Close the file
void OSFileClose(void *pData, bool no_flush)
{
	os->FileClose(pData, no_flush);
}

// Flush to the file
void OSFileFlush(void *pData)
{
	os->FileFlush(pData);
}

// Get the call stack
CALLSTACK_DATA *OSGetCallStack()
{
	return os->GetCallStack();
}

// Get the symbol information
bool OSGetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
	return os->GetCallStackSymbolInfo(s);
}

// Wait for the termination of the thread
bool OSWaitThread(THREAD *t)
{
	return os->WaitThread(t);
}

// Release of thread
void OSFreeThread(THREAD *t)
{
	os->FreeThread(t);
}

// Thread initialization
bool OSInitThread(THREAD *t)
{
	return os->InitThread(t);
}

// Memory allocation
void *OSMemoryAlloc(UINT size)
{
	return os->MemoryAlloc(size);
}

// Memory reallocation
void *OSMemoryReAlloc(void *addr, UINT size)
{
	return os->MemoryReAlloc(addr, size);
}

// Memory release
void OSMemoryFree(void *addr)
{
	os->MemoryFree(addr);
}

// Get the system timer
UINT OSGetTick()
{
	return os->GetTick();
}

// Get the System Time
void OSGetSystemTime(SYSTEMTIME *system_time)
{
	os->GetSystemTime(system_time);
}

// 32bit increment
void OSInc32(UINT *value)
{
	os->Inc32(value);
}

// 32bit decrement
void OSDec32(UINT *value)
{
	os->Dec32(value);
}

// Sleep the thread
void OSSleep(UINT time)
{
	os->Sleep(time);
}

// Create a Lock
LOCK *OSNewLock()
{
	return os->NewLock();
}

// Lock
bool OSLock(LOCK *lock)
{
	return os->Lock(lock);
}

// Unlock
void OSUnlock(LOCK *lock)
{
	os->Unlock(lock);
}

// Delete the lock
void OSDeleteLock(LOCK *lock)
{
	os->DeleteLock(lock);
}

// Event initialization
void OSInitEvent(EVENT *event)
{
	os->InitEvent(event);
}

// Set event
void OSSetEvent(EVENT *event)
{
	os->SetEvent(event);
}

// Reset event
void OSResetEvent(EVENT *event)
{
	os->ResetEvent(event);
}

// Wait for event
bool OSWaitEvent(EVENT *event, UINT timeout)
{
	return os->WaitEvent(event, timeout);
}

// Release of the event
void OSFreeEvent(EVENT *event)
{
	os->FreeEvent(event);
}


// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
