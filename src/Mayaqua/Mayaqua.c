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


// Mayaqua.c
// Mayaqua Kernel program

#include <GlobalConst.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>
#include <errno.h>
#include <Mayaqua/Mayaqua.h>

// Global variable
bool g_memcheck;								// Enable memory check
bool g_debug;									// Debug mode
UINT64 kernel_status[NUM_KERNEL_STATUS];		// Kernel state
UINT64 kernel_status_max[NUM_KERNEL_STATUS];	// Kernel state (maximum value)
LOCK *kernel_status_lock[NUM_KERNEL_STATUS];	// Kernel state lock
BOOL kernel_status_inited = false;				// Kernel state initialization flag
bool g_little_endian = true;
char *cmdline = NULL;							// Command line
wchar_t *uni_cmdline = NULL;					// Unicode command line

// Static variable
static char *exename = NULL;						// EXE file name (ANSI)
static wchar_t *exename_w = NULL;					// EXE file name (Unicode)
static TOKEN_LIST *cmdline_token = NULL;			// Command line token
static UNI_TOKEN_LIST *cmdline_uni_token = NULL;	// Command line token (Unicode)
static OS_INFO *os_info = NULL;						// OS information
static bool dot_net_mode = false;
static bool minimal_mode = false;
static UINT last_time_check = 0;
static UINT first_time_check = 0;
static bool is_nt = false;
static bool is_ham_mode = false;
static UINT init_mayaqua_counter = 0;
static bool use_probe = false;
static BUF *probe_buf = NULL;
static LOCK *probe_lock = NULL;
static UINT64 probe_start = 0;
static UINT64 probe_last = 0;
static bool probe_enabled = false;



// Calculate the checksum
USHORT CalcChecksum16(void *buf, UINT size)
{
	int sum = 0;
	USHORT *addr = (USHORT *)buf;
	int len = (int)size;
	USHORT *w = addr;
	int nleft = len;
	USHORT answer = 0;

	while (nleft > 1)
	{
		USHORT ww = 0;
		Copy(&ww, w++, sizeof(USHORT));
		sum += ww;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(UCHAR *)(&answer) = *(UCHAR *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	answer = ~sum;

	return answer;
}

// Writing a probe with the data
void WriteProbeData(char *filename, UINT line, char *str, void *data, UINT size)
{
	char tmp[MAX_SIZE];
	USHORT cs;

	if (IsProbeEnabled() == false)
	{
		return;
	}

	// Take a checksum of the data
	if (size != 0)
	{
		cs = CalcChecksum16(data, size);
	}
	else
	{
		cs = 0;
	}

	// Generating a String
	snprintf(tmp, sizeof(tmp), "\"%s\" (Size=%5u, Crc=0x%04X)", str, size, cs);

	WriteProbe(filename, line, tmp);
}

// Writing Probe
void WriteProbe(char *filename, UINT line, char *str)
{
#ifdef	OS_WIN32
	char *s;
	char tmp[MAX_SIZE];
	char tmp2[MAX_SIZE];
	UINT64 now = 0;
	UINT64 time;

	if (IsProbeEnabled() == false)
	{
		return;
	}

	now = MsGetHiResCounter();

	Lock(probe_lock);
	{
		UINT64 diff;
		
		time = MsGetHiResTimeSpanUSec(now - probe_start);

		diff = time - probe_last;

		if (time < probe_last)
		{
			diff = 0;
		}

		probe_last = time;

		ToStr64(tmp, time);
		MakeCharArray2(tmp2, ' ', (UINT)(MIN(12, (int)12 - (int)StrLen(tmp))));
		WriteBuf(probe_buf, tmp2, StrLen(tmp2));
		WriteBuf(probe_buf, tmp, StrLen(tmp));

		s = " [+";
		WriteBuf(probe_buf, s, StrLen(s));

		ToStr64(tmp, diff);
		MakeCharArray2(tmp2, ' ', (UINT)(MIN(12, (int)12 - (int)StrLen(tmp))));
		WriteBuf(probe_buf, tmp2, StrLen(tmp2));
		WriteBuf(probe_buf, tmp, StrLen(tmp));

		s = "] - ";
		WriteBuf(probe_buf, s, StrLen(s));

		WriteBuf(probe_buf, filename, StrLen(filename));

		s = "(";
		WriteBuf(probe_buf, s, StrLen(s));

		ToStr64(tmp, (UINT64)line);
		WriteBuf(probe_buf, tmp, StrLen(tmp));

		s = "): ";
		WriteBuf(probe_buf, s, StrLen(s));

		WriteBuf(probe_buf, str, StrLen(str));

		s = "\r\n";
		WriteBuf(probe_buf, s, StrLen(s));
	}
	Unlock(probe_lock);
#endif	// OS_WIN32
}

// Initialization of Probe
void InitProbe()
{
	probe_buf = NewBuf();
	probe_lock = NewLock();
	probe_enabled = false;

	probe_start = 0;

#ifdef	OS_WIN32
	probe_start = MsGetHiResCounter();
#endif	// OS_WIN32
}

// Release of Probe
void FreeProbe()
{
	if (probe_buf->Size >= 1)
	{
		SYSTEMTIME st;
		char filename[MAX_SIZE];

		// Write all to the file
		MakeDirEx("@probe_log");

		LocalTime(&st);

		snprintf(filename, sizeof(filename), "@probe_log/%04u%02u%02u_%02u%02u%02u.log",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

		DumpBuf(probe_buf, filename);
	}

	FreeBuf(probe_buf);
	DeleteLock(probe_lock);
}

// Set enable / disable the Probe
void EnableProbe(bool enable)
{
	probe_enabled = enable;
}

// Get whether the Probe is enabled?
bool IsProbeEnabled()
{
#ifndef	USE_PROBE
	return false;
#else	// USE_PROBE
	return probe_enabled;
#endif	// USE_PROBE
}

// Set the Ham mode
void SetHamMode()
{
	is_ham_mode = true;
}

// Get whether in Ham mode
bool IsHamMode()
{
	return is_ham_mode;
}

// Display the time from the previous call to now
void TimeCheck()
{
#ifdef OS_WIN32
	UINT now, ret, total;
	now = Win32GetTick();
	if (last_time_check == 0)
	{
		ret = 0;
	}
	else
	{
		ret = now - last_time_check;
	}
	last_time_check = now;

	if (first_time_check == 0)
	{
		first_time_check = now;
	}

	total = now - first_time_check;

	printf(" -- %3.3f / %3.3f\n", (double)ret / 1000.0f, (double)total / 1000.0f);
#endif	// OS_WIN32
}

// Whether this system is IA64
bool IsIA64()
{
	if (Is64() == false)
	{
		return false;
	}

#ifndef	MAYAQUA_IA_64
	return false;
#else	// MAYAQUA_IA_64
	return true;
#endif	// MAYAQUA_IA_64
}

// Whether in x64
bool IsX64()
{
	if (Is64() == false)
	{
		return false;
	}

#ifndef	MAYAQUA_IA_64
	return true;
#else	// MAYAQUA_IA_64
	return false;
#endif	// MAYAQUA_IA_64
}

// Whether 64bit
bool Is64()
{
#ifdef	CPU_64
	return true;
#else	// CPU_64
	return false;
#endif	// CPU_64
}

// Whether 32bit
bool Is32()
{
	return Is64() ? false : true;
}

// .NET mode
void MayaquaDotNetMode()
{
	dot_net_mode = true;
}

// Acquisition whether in .NET mode
bool MayaquaIsDotNetMode()
{
	return dot_net_mode;
}

// Check the endian
void CheckEndian()
{
	unsigned short test;
	UCHAR *buf;

	test = 0x1234;
	buf = (UCHAR *)&test;
	if (buf[0] == 0x12)
	{
		g_little_endian = false;
	}
	else
	{
		g_little_endian = true;
	}
}

// Minimize mode
void MayaquaMinimalMode()
{
	minimal_mode = true;
}
bool MayaquaIsMinimalMode()
{
	return minimal_mode;
}

// Whether in NT
bool IsNt()
{
	return is_nt;
}

// Whether the Unicode is supported
bool IsUnicode()
{
#ifdef	OS_WIN32
	// Windows
	return IsNt();
#else	// OS_WIN32
	// UNIX
	return true;
#endif	// OS_WIN32
}

// Initialization of Mayaqua library
void InitMayaqua(bool memcheck, bool debug, int argc, char **argv)
{
	wchar_t tmp[MAX_PATH];
	UCHAR hash[SHA1_SIZE];

	if ((init_mayaqua_counter++) > 0)
	{
		return;
	}

	g_memcheck = memcheck;
	g_debug = debug;
	cmdline = NULL;
	if (dot_net_mode == false)
	{
		// Fail this for some reason when this is called this in .NET mode
		setbuf(stdout, NULL);
	}

	// Acquisition whether NT
#ifdef	OS_WIN32
	is_nt = Win32IsNt();
#endif	// OS_WIN32

	// Check endian
	CheckEndian();

#ifdef	OS_WIN32
	_configthreadlocale(_DISABLE_PER_THREAD_LOCALE);
#endif	// OS_WIN32

	// Set the locale information of the CRT to the Japanese
	setlocale(LC_ALL, "");

	// Initialization of OS
	OSInit();

	// Initialize the random number
	srand((UINT)SystemTime64());

	tick_manual_lock = NewLock();

	// Initialization of CRC32
	InitCrc32();

	// Initialization of the FIFO system
	InitFifo();

	// Initialize the Kernel status
	InitKernelStatus();

	// Initialize the tracking
	InitTracking();

	// Initialization of thread pool
	InitThreading();

	// Initialize the string library
	InitStringLibrary();

	// Initialization of the locale information
	SetLocale(NULL);

	// Initialization of the crypt library
	InitCryptLibrary();

	// Initialization of the real-time clock
	InitTick64();

	// Initialize the network communication module
	InitNetwork();

	// Initialization of the aquisition of the EXE file name
	InitGetExeName(argc >= 1 ? argv[0] : NULL);

	// Initialization of the command line string
	InitCommandLineStr(argc, argv);

	// Initialization of OS information
	InitOsInfo();

	// Initialization of the operating system-specific module
#ifdef	OS_WIN32
	MsInit();	// Microsoft Win32
#endif	// OS_WIN32

	// Initialization of the security token module
	InitSecure();

	if (OSIsSupportedOs() == false)
	{
		// Abort
		exit(0);
	}

	// RSA Check
	if (RsaCheckEx() == false)
	{
		// Abort
		Alert("OpenSSL Library Init Failed. (too old?)\nPlease install the latest version of OpenSSL.\n\n", "RsaCheck()");
		exit(0);
	}

	// Initialization of HamCore file system
	InitHamcore();

	// Initialization of string table routine
	InitTable();

	if (exename == NULL)
	{
		// Executable file name
		exename = CopyStr("unknown");
	}

	// Check whether the executable file name of themselves is found
	// (If not found, quit because this is started in strange path)
	GetExeNameW(tmp, sizeof(tmp));
	if (IsFileExistsW(tmp) == false)
	{
		wchar_t tmp2[MAX_SIZE];

		UniFormat(tmp2, sizeof(tmp2),
			L"Error: Executable binary file \"%s\" not found.\r\n\r\n"
			L"Please execute program with full path.\r\n",
			tmp);

		AlertW(tmp2, NULL);
		_exit(0);
	}

	CheckUnixTempDir();

	// Initialization of Probe
	InitProbe();

	// Initialization of Machine Hash
	GetCurrentMachineIpProcessHash(hash);

	// Reading Private IP file
	LoadPrivateIPFile();
}

// Release of Mayaqua library
void FreeMayaqua()
{
	if ((--init_mayaqua_counter) > 0)
	{
		return;
	}

	// Release of Private IP File
	FreePrivateIPFile();

	// Release of Probe
	FreeProbe();

	// Delete the table
	FreeTable();

	// Release of security token module
	FreeSecure();

	// Release of the operating system specific module
#ifdef	OS_WIN32
	MsFree();
#endif	// OS_WIN32

	// Release of OS information
	FreeOsInfo();

	// Release of HamCore file system
	FreeHamcore();

	// Release of the command line string
	FreeCommandLineStr();

	// Release of the command line token
	FreeCommandLineTokens();

	// Release of network communication module
	FreeNetwork();

	// Release of real-time clock
	FreeTick64();

	// Release of crypt library
	FreeCryptLibrary();

	// Release of the string library
	FreeStringLibrary();

	// Release of thread pool
	FreeThreading();

#ifndef	VPN_SPEED
	// Show the kernel status
	if (g_debug)
	{
		PrintKernelStatus();
	}

	// Display the debug information
	if (g_memcheck)
	{
		PrintDebugInformation();
	}
#endif	// VPN_SPEED

	// Release the tracking
	FreeTracking();

	// Release of the kernel status
	FreeKernelStatus();

	DeleteLock(tick_manual_lock);
	tick_manual_lock = NULL;

	// Release of OS
	OSFree();
}

// Check whether /tmp is available in the UNIX
void CheckUnixTempDir()
{
	if (OS_IS_UNIX(GetOsInfo()->OsType))
	{
		char tmp[128], tmp2[64];
		UINT64 now = SystemTime64();
		IO *o;

		MakeDir("/tmp");

		Format(tmp2, sizeof(tmp2), "%I64u", now);

		Format(tmp, sizeof(tmp), "/tmp/.%s", tmp2);

		o = FileCreate(tmp);
		if (o == NULL)
		{
			o = FileOpen(tmp, false);
			if (o == NULL)
			{
				Print("Unable to use /tmp.\n\n");
				exit(0);
				return;
			}
		}

		FileClose(o);

		FileDelete(tmp);
	}
}

// Show an alert
void Alert(char *msg, char *caption)
{
	OSAlert(msg, caption);
}
void AlertW(wchar_t *msg, wchar_t *caption)
{
	OSAlertW(msg, caption);
}

// Display of OS information
void PrintOsInfo(OS_INFO *info)
{
	// Validate arguments
	if (info == NULL)
	{
		return;
	}

	Print(
		"OS Type          : %u\n"
		"OS Service Pack  : %u\n"
		"os_is_windows    : %s\n"
		"os_is_windows_nt : %s\n"
		"OS System Name   : %s\n"
		"OS Product Name  : %s\n"
		"OS Vendor Name   : %s\n"
		"OS Version       : %s\n"
		"Kernel Name      : %s\n"
		"Kernel Version   : %s\n",
		info->OsType,
		info->OsServicePack,
		OS_IS_WINDOWS(info->OsType) ? "true" : "false",
		OS_IS_WINDOWS_NT(info->OsType) ? "true" : "false",
		info->OsSystemName,
		info->OsProductName,
		info->OsVendorName,
		info->OsVersion,
		info->KernelName,
		info->KernelVersion);

#ifdef	OS_WIN32
	{
		char *exe, *dir;
		exe = MsGetExeFileName();
		dir = MsGetExeDirName();

		Print(
			"EXE File Path    : %s\n"
			"EXE Dir Path     : %s\n"
			"Process Id       : %u\n"
			"Process Handle   : 0x%X\n",
			exe, dir, MsGetCurrentProcessId(), MsGetCurrentProcess());
	}
#endif	// OS_WIN32
}

// Get the OS type
UINT GetOsType()
{
	OS_INFO *i = GetOsInfo();

	if (i == NULL)
	{
		return 0;
	}

	return i->OsType;
}

// Getting OS information
OS_INFO *GetOsInfo()
{
	return os_info;
}

// Initialization of OS information
void InitOsInfo()
{
	if (os_info != NULL)
	{
		return;
	}

	os_info = ZeroMalloc(sizeof(OS_INFO));

	OSGetOsInfo(os_info);
}

// Release of OS information
void FreeOsInfo()
{
	if (os_info == NULL)
	{
		return;
	}

	Free(os_info->OsSystemName);
	Free(os_info->OsProductName);
	Free(os_info->OsVendorName);
	Free(os_info->OsVersion);
	Free(os_info->KernelName);
	Free(os_info->KernelVersion);
	Free(os_info);

	os_info = NULL;
}

// Get the Unicode command line tokens
UNI_TOKEN_LIST *GetCommandLineUniToken()
{
	if (cmdline_uni_token == NULL)
	{
		return UniNullToken();
	}
	else
	{
		return UniCopyToken(cmdline_uni_token);
	}
}

// Getting the command line tokens
TOKEN_LIST *GetCommandLineToken()
{
	if (cmdline_token == NULL)
	{
		return NullToken();
	}
	else
	{
		return CopyToken(cmdline_token);
	}
}

// Convert the command line string into tokens
void ParseCommandLineTokens()
{
	if (cmdline_token != NULL)
	{
		FreeToken(cmdline_token);
	}
	cmdline_token = ParseCmdLine(cmdline);

	if (cmdline_uni_token != NULL)
	{
		UniFreeToken(cmdline_uni_token);
	}
	cmdline_uni_token = UniParseCmdLine(uni_cmdline);
}

// Release command line tokens
void FreeCommandLineTokens()
{
	if (cmdline_token != NULL)
	{
		FreeToken(cmdline_token);
	}
	cmdline_token = NULL;

	if (cmdline_uni_token != NULL)
	{
		UniFreeToken(cmdline_uni_token);
	}
	cmdline_uni_token = NULL;
}

// Initialization of the command line string
void InitCommandLineStr(int argc, char **argv)
{
	if (argc >= 1)
	{
#ifdef	OS_UNIX
		exename_w = CopyUtfToUni(argv[0]);
		exename = CopyUniToStr(exename_w);
#else	// OS_UNIX
		exename = CopyStr(argv[0]);
		exename_w = CopyStrToUni(exename);
#endif	// OS_UNIX
	}
	if (argc < 2 || argv == NULL)
	{
		// No command-line string
		SetCommandLineStr(NULL);
	}
	else
	{
		// There are command-line string
		int i, total_len = 1;
		char *tmp;

		for (i = 1;i < argc;i++)
		{
			total_len += StrLen(argv[i]) * 2 + 32;
		}
		tmp = ZeroMalloc(total_len);

		for (i = 1;i < argc;i++)
		{
			UINT s_size = StrLen(argv[i]) * 2;
			char *s = ZeroMalloc(s_size);
			bool dq = (SearchStrEx(argv[i], " ", 0, true) != INFINITE);
			ReplaceStrEx(s, s_size, argv[i], "\"", "\"\"", true);
			if (dq)
			{
				StrCat(tmp, total_len, "\"");
			}
			StrCat(tmp, total_len, s);
			if (dq)
			{
				StrCat(tmp, total_len, "\"");
			}
			StrCat(tmp, total_len, " ");
			Free(s);
		}

		Trim(tmp);
		SetCommandLineStr(tmp);
		Free(tmp);
	}
}

// Release of the command line string
void FreeCommandLineStr()
{
	SetCommandLineStr(NULL);

	if (exename != NULL)
	{
		Free(exename);
		exename = NULL;
	}

	if (exename_w != NULL)
	{
		Free(exename_w);
		exename_w = NULL;
	}
}

// Get the Unicode command line string
wchar_t *GetCommandLineUniStr()
{
	if (uni_cmdline == NULL)
	{
		return UniCopyStr(L"");
	}
	else
	{
		return UniCopyStr(uni_cmdline);
	}
}

// Get the command line string
char *GetCommandLineStr()
{
	if (cmdline == NULL)
	{
		return CopyStr("");
	}
	else
	{
		return CopyStr(cmdline);
	}
}

// Set the Unicode command line string
void SetCommandLineUniStr(wchar_t *str)
{
	if (uni_cmdline != NULL)
	{
		Free(uni_cmdline);
	}
	if (str == NULL)
	{
		uni_cmdline = NULL;
	}
	else
	{
		uni_cmdline = CopyUniStr(str);
	}

	ParseCommandLineTokens();
}

// Set the command-line string
void SetCommandLineStr(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		if (cmdline != NULL)
		{
			Free(cmdline);
		}
		cmdline = NULL;
	}
	else
	{
		if (cmdline != NULL)
		{
			Free(cmdline);
		}
		cmdline = CopyStr(str);
	}

	if (cmdline == NULL)
	{
		if (uni_cmdline != NULL)
		{
			Free(uni_cmdline);
			uni_cmdline = NULL;
		}
	}
	else
	{
		if (uni_cmdline != NULL)
		{
			Free(uni_cmdline);
		}
		uni_cmdline = CopyStrToUni(cmdline);
	}

	ParseCommandLineTokens();
}

// Display the kernel status
void PrintKernelStatus()
{
	bool leaked = false;

	Print("\n");
	Print(
		"     --------- Mayaqua Kernel Status ---------\n"
		"        Malloc Count ............... %u\n"
		"        ReAlloc Count .............. %u\n"
		"        Free Count ................. %u\n"
		"        Total Memory Size .......... %I64u bytes\n"
		"      * Current Memory Blocks ...... %u Blocks (Peek: %u)\n"
		"        Total Memory Blocks ........ %u Blocks\n"
		"      * Current MemPool Blocks ..... %u Blocks (Peek: %u)\n"
		"        Total MemPool Mallocs ...... %u Mallocs\n"
		"        Total MemPool ReAllocs ..... %u ReAllocs\n"
		"        NewLock Count .............. %u\n"
		"        DeleteLock Count ........... %u\n"
		"      * Current Lock Objects ....... %u Objects\n"
		"      * Current Locked Objects ..... %u Objects\n"
		"        NewRef Count ............... %u\n"
		"        FreeRef Count .............. %u\n"
		"      * Current Ref Objects ........ %u Objects\n"
		"      * Current Ref Count .......... %u Refs\n"
		"        GetTime Count .............. %u\n"
		"        GetTick Count .............. %u\n"
		"        NewThread Count ............ %u\n"
		"        FreeThread Count ........... %u\n"
		"      * Current Threads ............ %u Threads\n"
		"        Wait For Event Count ....... %u\n\n",
		KS_GET(KS_MALLOC_COUNT),
		KS_GET(KS_REALLOC_COUNT),
		KS_GET(KS_FREE_COUNT),
		KS_GET64(KS_TOTAL_MEM_SIZE),
		KS_GET(KS_CURRENT_MEM_COUNT),
		KS_GETMAX(KS_CURRENT_MEM_COUNT),
		KS_GET(KS_TOTAL_MEM_COUNT),
		KS_GET(KS_MEMPOOL_CURRENT_NUM),
		KS_GETMAX(KS_MEMPOOL_CURRENT_NUM),
		KS_GET(KS_MEMPOOL_MALLOC_COUNT),
		KS_GET(KS_MEMPOOL_REALLOC_COUNT),
		KS_GET(KS_NEWLOCK_COUNT),
		KS_GET(KS_DELETELOCK_COUNT),
		KS_GET(KS_CURRENT_LOCK_COUNT),
		KS_GET(KS_CURRENT_LOCKED_COUNT),
		KS_GET(KS_NEWREF_COUNT),
		KS_GET(KS_FREEREF_COUNT),
		KS_GET(KS_CURRENT_REF_COUNT),
		KS_GET(KS_CURRENT_REFED_COUNT),
		KS_GET(KS_GETTIME_COUNT),
		KS_GET(KS_GETTICK_COUNT),
		KS_GET(KS_NEWTHREAD_COUNT),
		KS_GET(KS_FREETHREAD_COUNT),
		KS_GET(KS_NEWTHREAD_COUNT) - KS_GET(KS_FREETHREAD_COUNT),
		KS_GET(KS_WAIT_COUNT)
		);

	if (KS_GET(KS_CURRENT_MEM_COUNT) != 0 || KS_GET(KS_CURRENT_LOCK_COUNT) != 0 ||
		KS_GET(KS_MEMPOOL_CURRENT_NUM) != 0 ||
		KS_GET(KS_CURRENT_LOCKED_COUNT) != 0 || KS_GET(KS_CURRENT_REF_COUNT) != 0)
	{
		leaked = true;
	}

	if (leaked)
	{
		Print("      !!! MEMORY LEAKS DETECTED !!!\n\n");
		if (g_memcheck == false)
		{
			GetLine(NULL, 0);
		}
	}
	else
	{
		Print("        @@@ NO MEMORY LEAKS @@@\n\n");
	}
}

// Initialize Kernel status
void InitKernelStatus()
{
	UINT i;

	// Memory initialization
	Zero(kernel_status, sizeof(kernel_status));
	Zero(kernel_status_max, sizeof(kernel_status_max));

	// Lock initialization
	for (i = 0;i < NUM_KERNEL_STATUS;i++)
	{
		kernel_status_lock[i] = OSNewLock();
	}

	kernel_status_inited = true;
}

// Release of the kernel status
void FreeKernelStatus()
{
	UINT i;

	kernel_status_inited = false;

	// Lock release
	for (i = 0;i < NUM_KERNEL_STATUS;i++)
	{
		OSDeleteLock(kernel_status_lock[i]);
	}
}

// Lock the kernel status
void LockKernelStatus(UINT id)
{
	// Validate arguments
	if (id >= NUM_KERNEL_STATUS)
	{
		return;
	}

	OSLock(kernel_status_lock[id]);
}

// Unlock the kernel status
void UnlockKernelStatus(UINT id)
{
	// Validate arguments
	if (id >= NUM_KERNEL_STATUS)
	{
		return;
	}

	OSUnlock(kernel_status_lock[id]);
}

// Display the debug information
void PrintDebugInformation()
{
	MEMORY_STATUS memory_status;
	GetMemoryStatus(&memory_status);

	// Header
	Print("====== " CEDAR_PRODUCT_STR " VPN System Debug Information ======\n");

	// Memory information
	Print(" <Memory Status>\n"
		"       Number of Allocated Memory Blocks: %u\n"
		"   Total Size of Allocated Memory Blocks: %u bytes\n",
		memory_status.MemoryBlocksNum, memory_status.MemorySize);

	// Footer
	Print("====================================================\n");

	if (KS_GET(KS_CURRENT_MEM_COUNT) != 0 || KS_GET(KS_CURRENT_LOCK_COUNT) != 0 ||
		KS_GET(KS_CURRENT_LOCKED_COUNT) != 0 || KS_GET(KS_CURRENT_REF_COUNT) != 0)
	{
		// Show a debug menu because memory leaks suspected
		MemoryDebugMenu();
	}
}





// Developed by SoftEther VPN Project at University of Tsukuba in Japan.
// Department of Computer Science has dozens of overly-enthusiastic geeks.
// Join us: http://www.tsukuba.ac.jp/english/admission/
