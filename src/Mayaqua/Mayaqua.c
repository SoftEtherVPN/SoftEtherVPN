// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Mayaqua.c
// Mayaqua Kernel program

#include "Mayaqua.h"

#include "Encrypt.h"
#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Network.h"
#include "Object.h"
#include "OS.h"
#include "Secure.h"
#include "Str.h"
#include "Table.h"
#include "Tick64.h"
#include "Tracking.h"

#include <locale.h>
#include <stdlib.h>

// Global variable
bool g_memcheck;								// Enable memory check
bool g_debug;									// Debug mode
UINT64 kernel_status[NUM_KERNEL_STATUS];		// Kernel state
UINT64 kernel_status_max[NUM_KERNEL_STATUS];	// Kernel state (maximum value)
LOCK *kernel_status_lock[NUM_KERNEL_STATUS];	// Kernel state lock
bool kernel_status_inited = false;				// Kernel state initialization flag
bool g_little_endian = true;
char *cmdline = NULL;							// Command line
wchar_t *uni_cmdline = NULL;					// Unicode command line
bool g_foreground = false;					// Execute service in foreground mode

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

// The function which should be called once as soon as possible after the process is started
static bool init_proc_once_flag = false;
void InitProcessCallOnce()
{
	if (init_proc_once_flag == false)
	{
		init_proc_once_flag = true;

		InitCanaryRand();

#ifdef	OS_WIN32
		MsInitProcessCallOnce();
#endif	// OS_WIN32
	}
}

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

// Initialization of Mayaqua library
void InitMayaqua(bool memcheck, bool debug, int argc, char **argv)
{
	wchar_t tmp[MAX_PATH];
	UCHAR hash[SHA1_SIZE];

	if ((init_mayaqua_counter++) > 0)
	{
		return;
	}

	InitProcessCallOnce();

	g_memcheck = memcheck;
	g_debug = debug;
	cmdline = NULL;
	if (dot_net_mode == false)
	{
		// Fail this for some reason when this is called this in .NET mode
		setbuf(stdout, NULL);
	}

#ifdef OS_UNIX
	g_foreground = (argc >= 3 && StrCmpi(argv[2], UNIX_SVC_ARG_FOREGROUND) == 0);
#else
	g_foreground = false;
#endif // OS_UNIX

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

	if (IsTrackingEnabled())
	{
		// Initialize the tracking
		InitTracking();
	}

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

	// Initialization of the acquisition of the EXE file name
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

	// Release of the string library
	FreeStringLibrary();

	// Release of thread pool
	FreeThreading();

	// Release of crypt library
	FreeCryptLibrary();

	if (IsTrackingEnabled())
	{
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

		// Release the tracking
		FreeTracking();
	}

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
			if (IsHamMode())
			{
				Print("    Enable /memcheck startup option to see the leaking memory heap.\n");
				Print("    Press Enter key to exit the process.\n");
			}
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




