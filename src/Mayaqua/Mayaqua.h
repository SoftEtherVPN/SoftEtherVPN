// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Mayaqua.h
// Mayaqua Kernel header file

#ifndef	MAYAQUA_H
#define	MAYAQUA_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#define	PENCORE_DLL_NAME		"|PenCore.dll"

//#define	USE_PROBE						// Use Probe

// Macro for the release flag
#ifdef	VPN_SPEED

#define	WIN32_USE_HEAP_API_FOR_MEMORY	// Use the heap API to allocate memory
#define	WIN32_NO_DEBUG_HELP_DLL			// Do not call the DLL for debugging
#define	DONT_ALLOW_RUN_ON_DEBUGGER		// Do not allow running on the debugger

#endif	// VPN_SPEED

void InitProcessCallOnce();

#ifdef	VPN_EXE
// To build the executable file
#ifdef	WIN32
#include <windows.h>
#include "../PenCore/resource.h"
int main(int argc, char *argv[]);
int PASCAL WinMain(HINSTANCE hInst, HINSTANCE hPrev, char *CmdLine, int CmdShow)
{
	char *argv[] = { CmdLine, };
	InitProcessCallOnce();
	return main(1, argv);
}
#endif	// WIN32
#endif	// VPN_EXE

// Constant
#define	DEFAULT_TABLE_FILE_NAME		"|strtable.stb"		// Default string table
//#define	DEFAULT_TABLE_FILE_NAME		"@hamcore_zh/strtable.stb"		// Test for Chinese

#define	STRTABLE_ID					"SE_VPN_20121007"	// String table identifier

// Determining the OS
#ifdef	WIN32
#define	OS_WIN32		// Microsoft Windows
#else
#define	OS_UNIX			// UNIX
#endif	// WIN32

// Directory separator
#ifdef	OS_WIN32
#define	PATH_BACKSLASH	// Backslash (\)
#else	// WIN32
#define	PATH_SLASH		// Slash (/)
#endif	// WIN32

// Character code
#ifdef	OS_WIN32
#define	CODE_SHIFTJIS	// Shift_JIS code
#else	// WIN32
#define	CODE_EUC		// euc-jp code
#endif	// WIN32

// Endian
#define	IsBigEndian()		(g_little_endian ? false : true)
#define	IsLittleEndian()	(g_little_endian)

#ifdef	OS_WIN32
// Replace the snprintf function
#define	snprintf	_snprintf
#endif	// OS_WIN32

// Compiler dependent
#ifndef	OS_WIN32
// Gcc compiler
#define	GCC_PACKED		__attribute__ ((__packed__))
#else	// OS_WIN32
// VC++ compiler
#define	GCC_PACKED
#endif	// OS_WIN32

// Macro that displays the current file name and line number
#define	WHERE			if (IsDebug()){printf("%s: %u\n", __FILE__, __LINE__); SleepThread(10);}
#define	WHERE32			if (IsDebug()){	\
	char tmp[128]; sprintf(tmp, "%s: %u", __FILE__, __LINE__); Win32DebugAlert(tmp);	\
	}
#define TIMECHECK		if (IsDebug()){printf("%-12s:%5u", __FILE__, __LINE__);TimeCheck();}

// Probe related
#ifdef	USE_PROBE
#define	PROBE_WHERE						WriteProbe(__FILE__, __LINE__, "");
#define	PROBE_STR(str)					WriteProbe(__FILE__, __LINE__, (str));
#define	PROBE_DATA2(str, data, size)	WriteProbeData(__FILE__, __LINE__, (str), (data), (size));
#define	PROBE_DATA(data, size)			WriteProbeData(__FILE__, __LINE__, "", (data), (size));
#else	// USE_PROBE
#define	PROBE_WHERE
#define	PROBE_STR(str)
#define	PROBE_DATA2(str, data, size)
#define	PROBE_DATA(data, size)
#endif	// USE_PROBE

// Determine the performance / memory strategy
#if	(defined(CPU_X86) || defined(CPU_X64) || defined(CPU_X86_X64) || defined(CPU_SPARC) || defined(CPU_SPARC64) || defined(OS_WIN32) || defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64) || defined(i386) || defined(__i386) || defined(__i386__) || defined(__ia64__) || defined(__IA64__) || defined(_IA64))
#define	USE_STRATEGY_PERFORMACE
#else
#define	USE_STRATEGY_LOW_MEMORY
#endif

// Macro that displays the current time
#ifdef	WIN32
#define	WHEN			if (IsDebug()){WHERE; MsPrintTick();}
#else	// WIN32
#define	WHEN
#endif	// WIN32

#ifdef	OS_UNIX
#ifndef	UNIX_SOLARIS
#ifndef	CPU_SH4
#if	!defined(__UCLIBC__) || defined(__UCLIBC_SUPPORT_AI_ADDRCONFIG__)
// Getifaddrs system call is supported on UNIX other than Solaris.
// However, it is not supported also by the Linux on SH4 CPU
#define	MAYAQUA_SUPPORTS_GETIFADDRS
#endif	// !UCLIBC || UCLIBC_SUPPORT_AI_ADDRCONFIG
#endif	// CPU_SH4
#endif	// UNIX_SOLARIS
#endif	// OS_UNIX

#ifdef	OS_UNIX
// Header only needed in UNIX OS
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>
#include <dirent.h>
#ifdef	UNIX_LINUX
#include <sys/vfs.h>
#elif	UNIX_BSD
#include <sys/param.h>
#include <sys/mount.h>
#endif
#ifdef	UNIX_SOLARIS
#include <sys/statvfs.h>
#define	USE_STATVFS
#endif	// UNIX_SOLARIS
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#ifdef	UNIX_SOLARIS
#include <sys/filio.h>
#endif	// UNIX_SOLARIS
#include <sys/resource.h>
#include <poll.h>
#include <pthread.h>
#ifdef	UNIX_LINUX
#include <sys/prctl.h>
#endif	// UNIX_LINUX
#include <signal.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
//#include <netinet/ip.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <readline/readline.h>
#include <readline/history.h>
//#include <curses.h>
#ifdef	MAYAQUA_SUPPORTS_GETIFADDRS
#include <ifaddrs.h>
#endif	// MAYAQUA_SUPPORTS_GETIFADDRS

#ifdef	UNIX_LINUX
typedef void *iconv_t;
iconv_t iconv_open (__const char *__tocode, __const char *__fromcode);
size_t iconv (iconv_t __cd, char **__restrict __inbuf,
                     size_t *__restrict __inbytesleft,
                     char **__restrict __outbuf,
                     size_t *__restrict __outbytesleft);
int iconv_close (iconv_t __cd);
#else	// UNIX_LINUX
#include <iconv.h>
#endif	// UNIX_LINUX



#ifdef	UNIX_LINUX
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#endif	// UNIX_LINUX

#ifdef	UNIX_SOLARIS
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#endif	// UNIX_SOLARIS

#ifndef	NO_VLAN

#include <Mayaqua/TunTap.h>

#endif	// NO_VLAN

#define	closesocket(s)		close(s)

#else	// Win32 only

#include <conio.h>

#endif	// OS_UNIX

// IPv6 support flag
#ifndef	WIN32
#ifndef	AF_INET6
#define	NO_IPV6
#endif	// AF_INET6
#endif	// WIN32

// Basic type declaration
#include <Mayaqua/MayaType.h>

// Object management
#include <Mayaqua/Object.h>

// Object tracking
#include <Mayaqua/Tracking.h>

// File I/O
#include <Mayaqua/FileIO.h>

// Memory management
#include <Mayaqua/Memory.h>

// String processing
#include <Mayaqua/Str.h>

// Internationalized string processing
#include <Mayaqua/Internat.h>

// Encryption processing
#include <Mayaqua/Encrypt.h>

// Secure token
#include <Mayaqua/Secure.h>

// Kernel
#include <Mayaqua/Kernel.h>

// Package
#include <Mayaqua/Pack.h>

// Configuration file
#include <Mayaqua/Cfg.h>

// String table
#include <Mayaqua/Table.h>

// Network communication
#include <Mayaqua/Network.h>

// TCP/IP
#include <Mayaqua/TcpIp.h>

// HTTP
#include <Mayaqua/HTTP.h>

// Proxy
#include <Mayaqua/Proxy.h>

// 64 bit real-time clock
#include <Mayaqua/Tick64.h>

// OS-dependent code
#include <Mayaqua/OS.h>

// Code for Microsoft Windows
#include <Mayaqua/Microsoft.h>


// Global variables
extern bool g_memcheck;
extern bool g_debug;
extern char *cmdline;
extern wchar_t *uni_cmdline;
extern bool g_little_endian;
extern LOCK *tick_manual_lock;
extern bool g_foreground;

// Kernel state
#define	NUM_KERNEL_STATUS	128
extern UINT64 kernel_status[NUM_KERNEL_STATUS];
extern UINT64 kernel_status_max[NUM_KERNEL_STATUS];
extern LOCK *kernel_status_lock[NUM_KERNEL_STATUS];
extern BOOL kernel_status_inited;

// Kernel state operation macro
#define	KS_LOCK(id)		LockKernelStatus(id)
#define	KS_UNLOCK(id)	UnlockKernelStatus(id)
#define	KS_GET64(id)	(kernel_status[id])
#define	KS_GET(id)		((UINT)KS_GET64(id))
#define	KS_GETMAX64(id)	(kernel_status_max[id])
#define	KS_GETMAX(id)	((UINT)KS_GETMAX64(id))

// Operations of the kernel status
#define	KS_INC(id)															\
if (IsTrackingEnabled()) {													\
	KS_LOCK(id);															\
	kernel_status[id]++;													\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);															\
}
#define	KS_DEC(id)															\
if (IsTrackingEnabled()) {													\
	KS_LOCK(id);															\
	kernel_status[id]--;													\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);															\
}
#define	KS_ADD(id, n)														\
if (IsTrackingEnabled()) {													\
	KS_LOCK(id);															\
	kernel_status[id] += n;													\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);															\
}
#define	KS_SUB(id, n)														\
if (IsTrackingEnabled()) {													\
	KS_LOCK(id);															\
	kernel_status[id] -= n;													\
	kernel_status_max[id] = MAX(kernel_status_max[id], kernel_status[id]);	\
	KS_UNLOCK(id);															\
}

// Kernel status
// String related
#define	KS_STRCPY_COUNT			0		// number of calls StrCpy
#define	KS_STRLEN_COUNT			1		// number of calls StrLen
#define	KS_STRCHECK_COUNT		2		// number of calls StrCheck
#define	KS_STRCAT_COUNT			3		// number of calls StrCat
#define	KS_FORMAT_COUNT			4		// number of calls Format
// Memory related
#define	KS_MALLOC_COUNT			5		// Number of calls Malloc
#define	KS_REALLOC_COUNT		6		// Number of calls ReAlloc
#define	KS_FREE_COUNT			7		// number of calls Free
#define	KS_TOTAL_MEM_SIZE		8		// The total size of the memory that was allocated so far
#define	KS_CURRENT_MEM_COUNT	9		// Number of memory blocks that are currently reserved
#define	KS_TOTAL_MEM_COUNT		10		// The total number of memory blocks that ware allocated so far
#define	KS_ZERO_COUNT			11		// Number of calls Zero
#define	KS_COPY_COUNT			12		// Number of calls Copy
// Lock related
#define	KS_NEWLOCK_COUNT		13		// Number of calls NewLock
#define	KS_DELETELOCK_COUNT		14		// Number of calls DeleteLock
#define	KS_LOCK_COUNT			15		// Number of calls Lock
#define	KS_UNLOCK_COUNT			16		// Number of calls Unlock
#define	KS_CURRENT_LOCK_COUNT	17		// Current number of LOCK objects
#define	KS_CURRENT_LOCKED_COUNT	18		// Current number of locked LOCK objects
// Counter information
#define	KS_NEW_COUNTER_COUNT	19		// Number of calls NewCounter
#define	KS_DELETE_COUNTER_COUNT	20		// Number of calls DeleteCounter
#define	KS_INC_COUNT			21		// Number of calls Inc
#define	KS_DEC_COUNT			22		// Number of calls Dec
#define	KS_CURRENT_COUNT		23		// Current total number of counts
// Reference counter information
#define	KS_NEWREF_COUNT			24		// Number of calls NewRef
#define	KS_FREEREF_COUNT		72		// Number of times REF objects are deleted
#define	KS_ADDREF_COUNT			25		// Number of calls AddRef
#define	KS_RELEASE_COUNT		26		// Number of calls Release
#define	KS_CURRENT_REF_COUNT	27		// Current number of REF objects
#define	KS_CURRENT_REFED_COUNT	28		// The sum of the current number of references
// Buffer information
#define	KS_NEWBUF_COUNT			29		// Number of calls NewBuf
#define	KS_FREEBUF_COUNT		30		// NNumber of calls FreeBuf
#define	KS_CURRENT_BUF_COUNT	31		// Current number of objects in the BUF
#define	KS_READ_BUF_COUNT		32		// Number of calls ReadBuf
#define	KS_WRITE_BUF_COUNT		33		// Number of calls WriteBuf
#define	KS_ADJUST_BUFSIZE_COUNT	34		// Number of times to adjust the buffer size
#define	KS_SEEK_BUF_COUNT		35		// Number of calls SeekBuf
// FIFO information
#define	KS_NEWFIFO_COUNT		36		// Number of calls NewFifo
#define	KS_FREEFIFO_COUNT		37		// Number of times the FIFO object is deleted
#define	KS_READ_FIFO_COUNT		38		// Number of calls ReadFifo
#define	KS_WRITE_FIFO_COUNT		39		// Number of calls WriteFifo
// List related
#define	KS_NEWLIST_COUNT		41		// Number of calls NewList
#define	KS_FREELIST_COUNT		42		// Number of times the object LIST was deleted
#define	KS_INSERT_COUNT			43		// Number of calls Add
#define	KS_DELETE_COUNT			44		// Number of calls Delete
#define	KS_SORT_COUNT			45		// Number of calls Sort
#define	KS_SEARCH_COUNT			46		// Number of calls Search
#define	KS_TOARRAY_COUNT		47		// Number of calls ToArray
// Queue related
#define	KS_NEWQUEUE_COUNT		48		// Number of calls NewQueue
#define	KS_FREEQUEUE_COUNT		49		// Number of times you delete the object QUEUE
#define	KS_PUSH_COUNT			50		// Number of calls Push
#define	KS_POP_COUNT			51		// Number of calls POP
// Stack related
#define	KS_NEWSK_COUNT			52		// Number of calls NewSk
#define	KS_FREESK_COUNT			53		// Number of times you delete the object SK
#define	KS_INSERT_QUEUE_COUNT	54		// Number of calls InsertQueue
#define	KS_GETNEXT_COUNT		55		// Number of calls GetNext
// Kernel related
#define	KS_GETTIME_COUNT		56		// Number of times to get the time
#define	KS_GETTICK_COUNT		57		// Number of times to get the system timer
#define	KS_NEWTHREAD_COUNT		58		// Number of calls NewThread
#define	KS_FREETHREAD_COUNT		59		// Number of times you delete the object THREAD
#define	KS_WAITFORTHREAD_COUNT	60		// Number of calls WaitForThread
#define	KS_NEWEVENT_COUNT		61		// Number of calls NewEvent
#define	KS_FREEEVENT_COUNT		62		// Number of times which EVENT object is deleted
#define	KS_WAIT_COUNT			63		// Number of calls Wait
#define	KS_SLEEPTHREAD_COUNT	64		// Number of calls SleepThread
// About IO
#define	KS_IO_OPEN_COUNT		65		// Number of times to open the file
#define	KS_IO_CREATE_COUNT		66		// Number of times that the file was created
#define	KS_IO_CLOSE_COUNT		67		// Number of times to close the file
#define	KS_IO_READ_COUNT		68		// Number of times to read from the file
#define	KS_IO_WRITE_COUNT		69		// Number of times to write to a file
#define	KS_IO_TOTAL_READ_SIZE	70		// Total number of bytes read from the file
#define	KS_IO_TOTAL_WRITE_SIZE	71		// The total number of bytes written to the file
// Memory pool related
#define	KS_MEMPOOL_MALLOC_COUNT	75		// Number of times to allocate the memory pool
#define	KS_MEMPOOL_FREE_COUNT	73		// Number of times you release the memory pool
#define	KS_MEMPOOL_CURRENT_NUM	74		// Current number of the memory pool
#define	KS_MEMPOOL_REALLOC_COUNT	76	// Number of times you have realloc the memory pool


// Macro
#define	IsDebug()		(g_debug)		// A debug mode
#define	IsMemCheck()	(g_memcheck)	// Memory check mode

// Function prototype
void InitMayaqua(bool memcheck, bool debug, int argc, char **argv);
void FreeMayaqua();
bool IsNt();
bool MayaquaIsDotNetMode();
void MayaquaMinimalMode();
bool MayaquaIsMinimalMode();
bool Is64();
bool Is32();
bool IsIA64();
bool IsX64();
void InitKernelStatus();
void FreeKernelStatus();
void PrintDebugInformation();
void LockKernelStatus(UINT id);
void UnlockKernelStatus(UINT id);
void PrintKernelStatus();
void InitCommandLineStr(int argc, char **argv);
void FreeCommandLineStr();
void SetCommandLineStr(char *str);
void SetCommandLineUniStr(wchar_t *str);
char *GetCommandLineStr();
wchar_t *GetCommandLineUniStr();
void ParseCommandLineTokens();
void FreeCommandLineTokens();
TOKEN_LIST *GetCommandLineToken();
UNI_TOKEN_LIST *GetCommandLineUniToken();
void InitOsInfo();
void FreeOsInfo();
void Alert(char *msg, char *caption);
void AlertW(wchar_t *msg, wchar_t *caption);
OS_INFO *GetOsInfo();
UINT GetOsType();
void CheckEndian();
void CheckUnixTempDir();
void TimeCheck();
void SetHamMode();
bool IsHamMode();
void InitProbe();
void FreeProbe();
void EnableProbe(bool enable);
bool IsProbeEnabled();
void WriteProbe(char *filename, UINT line, char *str);
void WriteProbeData(char *filename, UINT line, char *str, void *data, UINT size);
USHORT CalcChecksum16(void *buf, UINT size);


#ifdef	OS_WIN32
// Import library (for Win32)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma warning( disable : 4099 )
#endif	// OS_WIN32

// For Debugging
#ifndef	ENCRYPT_C
//#define	Disconnect(s)		{Debug("Disconnect() Called: %s %u\n", __FILE__, __LINE__);Disconnect(s);}
#endif


#endif	// MAYAQUA_H


