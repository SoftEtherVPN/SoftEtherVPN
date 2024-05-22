// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Unix.c
// UNIX dependent code

#ifdef	OS_UNIX

#include "Unix.h"

#include "Cfg.h"
#include "FileIO.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Kernel.h"
#include "Mayaqua.h"
#include "Memory.h"
#include "Network.h"
#include "Object.h"
#include "Str.h"
#include "Table.h"
#include "Tick64.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>

#include <sys/mount.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#ifdef UNIX_LINUX
#include <sys/statfs.h>
#endif

#ifdef UNIX_SOLARIS
#define USE_STATVFS
#include <sys/statvfs.h>
#endif

#ifdef	UNIX_MACOS
#ifdef	NO_VLAN
// Struct statfs for MacOS X
typedef struct fsid { int32_t val[2]; } fsid_t;
struct statfs {
        short   f_otype;                /* TEMPORARY SHADOW COPY OF f_type */
        short   f_oflags;               /* TEMPORARY SHADOW COPY OF f_flags */
        long    f_bsize;                /* fundamental file system block size */
        long    f_iosize;               /* optimal transfer block size */
        long    f_blocks;               /* total data blocks in file system */
        long    f_bfree;                /* free blocks in fs */
        long    f_bavail;               /* free blocks avail to non-superuser */
        long    f_files;                /* total file nodes in file system */
        long    f_ffree;                /* free file nodes in fs */
        fsid_t  f_fsid;                 /* file system id */
        uid_t   f_owner;                /* user that mounted the filesystem */
        short   f_reserved1;    /* spare for later */
        short   f_type;                 /* type of filesystem */
    long        f_flags;                /* copy of mount exported flags */
        long    f_reserved2[2]; /* reserved for future use */
        char    f_fstypename[15]; /* fs type name */
        char    f_mntonname[90];  /* directory on which mounted */
        char    f_mntfromname[90];/* mounted filesystem */
};
#else	// NO_VLAN
#include <sys/mount.h>
#endif	// NO_VLAN
#endif	// UNIX_MACOS

// Scandir() function for Solaris
#ifdef	UNIX_SOLARIS
#define scandir local_scandir
#define	alphasort local_alphasort

int local_scandir(const char *dir, struct dirent ***namelist,
            int (*select)(const struct dirent *),
            int (*compar)(const struct dirent **, const struct dirent **))
{
  DIR *d;
  struct dirent *entry;
  register int i=0;
  size_t entrysize;

  if ((d=opendir(dir)) == NULL)
     return(-1);

  *namelist=NULL;
  while ((entry=readdir(d)) != NULL)
  {
    if (select == NULL || (*select)(entry))
    {
      *namelist=(struct dirent **)realloc((void *)(*namelist),
                 (size_t)((i+1)*sizeof(struct dirent *)));
	if (*namelist == NULL) return(-1);
	entrysize=sizeof(struct dirent)-sizeof(entry->d_name)+strlen(entry->d_name)+1;
	(*namelist)[i]=(struct dirent *)malloc(entrysize);
	if ((*namelist)[i] == NULL) return(-1);
	memcpy((*namelist)[i], entry, entrysize);
	i++;
    }
  }
  if (closedir(d)) return(-1);
  if (i == 0) return(-1);
  if (compar != NULL)
    qsort((void *)(*namelist), (size_t)i, sizeof(struct dirent *), compar);
    
  return(i);
}

int local_alphasort(const struct dirent **a, const struct dirent **b)
{
  return(strcmp((*a)->d_name, (*b)->d_name));
}


#endif	// UNIX_SOLARIS

// Thread data for UNIX
typedef struct UNIXTHREAD
{
	pthread_t thread;
	bool finished;
} UNIXTHREAD;

// Thread startup information for UNIX
typedef struct UNIXTHREADSTARTUPINFO
{
	THREAD_PROC *thread_proc;
	void *param;
	THREAD *thread;
} UNIXTHREADSTARTUPINFO;

// Thread function prototype for UNIX
void *UnixDefaultThreadProc(void *param);

// Current process ID
static pid_t current_process_id = 0;

// File I/O data for UNIX
typedef struct UNIXIO
{
	int fd;
	bool write_mode;
} UNIXIO;

// Lock file data for UNIX
typedef struct UNIXLOCKFILE
{
	char FileName[MAX_SIZE];
	int fd;
} UNIXLOCKFILE;

// Event data for UNIX
typedef struct UNIXEVENT
{
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool signal;
} UNIXEVENT;

static pthread_mutex_t get_time_lock;
static pthread_mutex_t malloc_lock;
static bool high_process = false;

static bool unix_svc_terminate = false;
static int solaris_sleep_p1 = -1, solaris_sleep_p2 = -1;

// Create a dispatch table
OS_DISPATCH_TABLE *UnixGetDispatchTable()
{
	static OS_DISPATCH_TABLE t =
	{
		UnixInit,
		UnixFree,
		UnixMemoryAlloc,
		UnixMemoryReAlloc,
		UnixMemoryFree,
		UnixGetTick,
		UnixGetSystemTime,
		UnixInc32,
		UnixDec32,
		UnixSleep,
		UnixNewLock,
		UnixLock,
		UnixUnlock,
		UnixDeleteLock,
		UnixInitEvent,
		UnixSetEvent,
		UnixResetEvent,
		UnixWaitEvent,
		UnixFreeEvent,
		UnixWaitThread,
		UnixFreeThread,
		UnixInitThread,
		UnixThreadId,
		UnixFileOpen,
		UnixFileOpenW,
		UnixFileCreate,
		UnixFileCreateW,
		UnixFileWrite,
		UnixFileRead,
		UnixFileClose,
		UnixFileFlush,
		UnixFileSize,
		UnixFileSeek,
		UnixFileDelete,
		UnixFileDeleteW,
		UnixMakeDir,
		UnixMakeDirW,
		UnixDeleteDir,
		UnixDeleteDirW,
		UnixGetCallStack,
		UnixGetCallStackSymbolInfo,
		UnixFileRename,
		UnixFileRenameW,
		UnixRun,
		UnixRunW,
		UnixIsSupportedOs,
		UnixGetOsInfo,
		UnixAlert,
		UnixAlertW,
		UnixGetProductId,
		UnixSetHighPriority,
		UnixRestorePriority,
		UnixNewSingleInstance,
		UnixFreeSingleInstance,
		UnixGetMemInfo,
		UnixYield,
	};

	return &t;
}

static void signal_received_for_ignore(int sig, siginfo_t *info, void *ucontext)
{
	(void)sig;
	(void)info;
	(void)ucontext;
}

// Ignore the signal flew to the thread
void UnixIgnoreSignalForThread(int sig)
{
	struct sigaction sa;

	Zero(&sa, sizeof(sa));
	sa.sa_handler = NULL;
	sa.sa_sigaction = &signal_received_for_ignore;
	sa.sa_flags = SA_SIGINFO;

	sigemptyset(&sa.sa_mask);

	sigaction(SIGUSR1, &sa, NULL);
}

// Disable the off-loading function of the specific Ethernet device
void UnixDisableInterfaceOffload(char *name)
{
#ifdef	UNIX_LINUX
	char tmp[MAX_SIZE];
	TOKEN_LIST *t;
	char *names = "rx tx sg tso ufo gso gro lro rxvlan txvlan ntuple rxhash";
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	t = ParseToken(names, " ");

	if (t != NULL)
	{
		UINT i;
		for (i = 0;i < t->NumTokens;i++)
		{
			char *a = t->Token[i];

			Format(tmp, sizeof(tmp), "ethtool -K %s %s off 2>/dev/null", name, a);
			FreeToken(UnixExec(tmp));
		}
	}

	FreeToken(t);
#endif	// UNIX_LINUX
}

// Validate whether the Linux/FreeBSD is running in a VM
// Not implemented yet on other OS
bool UnixIsInVmMain()
{
	TOKEN_LIST *t = NULL;
	bool ret = false;
#if defined(UNIX_LINUX)
	char *vm_str_list = "Hypervisor detected,VMware Virtual Platform,VMware Virtual USB,qemu,xen,paravirtualized,virtual hd,virtualhd,virtual pc,virtualpc,kvm,oracle vm,oraclevm,parallels,xvm,bochs";
#elif defined(__FreeBSD__)
	char *vm_str_list = "generic,xen,hv,vmware,kvm,bhyve";
#endif

#if defined(UNIX_LINUX)
	t = UnixExec("/bin/dmesg");
#elif defined(__FreeBSD__)
	t = UnixExec("/sbin/sysctl -n kern.vm_guest");
#endif

#if defined(UNIX_LINUX) || defined(__FreeBSD__)
	if (t != NULL)
	{
		BUF *b = NewBuf();
		UINT i;

		for (i = 0;i < t->NumTokens;i++)
		{
			char *line = t->Token[i];

			AddBufStr(b, line);
			AddBufStr(b, " ");
		}

		WriteBufInt(b, 0);

//		printf("%s\n", b->Buf);

		ret = InStrList(b->Buf, vm_str_list, ",", false);

		FreeBuf(b);
		FreeToken(t);
	}
#endif // defined(UNIX_LINUX) || defined(__FreeBSD)

	return ret;
}

bool UnixIsInVm()
{
	static bool is_in_vm_flag = false;
	static bool is_in_vm_ret = false;

	if (is_in_vm_flag == false)
	{
		is_in_vm_ret = UnixIsInVmMain();
		is_in_vm_flag = true;
	}

	return is_in_vm_ret;
}

// Run quietly in the UNIX
void UnixExecSilent(char *cmd)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (cmd == NULL)
	{
		return;
	}

	Format(tmp, sizeof(tmp), "%s 2>/dev/null", cmd);

	FreeToken(UnixExec(tmp));
}

// Enable / disable the ESP processing in the kernel
void UnixSetEnableKernelEspProcessing(bool b)
{
	if (GetOsInfo()->OsType == OSTYPE_MACOS_X)
	{
		// Mac OS X
		if (b)
		{
			UnixExecSilent("/usr/sbin/sysctl -w net.inet.ipsec.esp_port=4500");
		}
		else
		{
			UnixExecSilent("/usr/sbin/sysctl -w net.inet.ipsec.esp_port=4501");
		}
	}
}

// Run a command and return its result
TOKEN_LIST *UnixExec(char *cmd)
{
	FILE *fp;
	char tmp[MAX_SIZE];
	char *ptr;
	LIST *o;
	UINT i;
	TOKEN_LIST *ret;
	// Validate arguments
	if (cmd == NULL)
	{
		return NULL;
	}

	fp = popen(cmd, "r");
	if (fp == NULL)
	{
		return NULL;
	}

	o = NewList(NULL);

	while (true)
	{
		fgets(tmp, sizeof(tmp), fp);
		if (feof(fp))
		{
			break;
		}

		ptr = strchr(tmp, '\n');
		if (ptr != NULL)
		{
			*ptr = 0;
		}

		ptr = strchr(tmp, '\r');
		if (ptr != NULL)
		{
			*ptr = 0;
		}

		Add(o, CopyStr(tmp));
	}

	pclose(fp);

	ret = ListToTokenList(o);

	FreeStrList(o);

	return ret;
}

// Initialize the Sleep for Solaris
void UnixInitSolarisSleep()
{
	char tmp[MAX_SIZE];

	UnixNewPipe(&solaris_sleep_p1, &solaris_sleep_p2);
	(void)read(solaris_sleep_p1, tmp, sizeof(tmp));
}

// Release the Sleep for Solaris
void UnixFreeSolarisSleep()
{
	UnixDeletePipe(solaris_sleep_p1, solaris_sleep_p2);
	solaris_sleep_p1 = -1;
	solaris_sleep_p2 = -1;
}

// Sleep for Solaris
void UnixSolarisSleep(UINT msec)
{
	struct pollfd p;

	memset(&p, 0, sizeof(p));
	p.fd = solaris_sleep_p1;
	p.events = POLLIN;

	(void)poll(&p, 1, msec == INFINITE ? -1 : (int)msec);
}

// Get the free space of the disk
bool UnixGetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
	char tmp[MAX_PATH];
	bool ret = false;
	// Validate arguments
	if (path == NULL)
	{
		return false;
	}

	NormalizePath(tmp, sizeof(tmp), path);

	while ((ret = UnixGetDiskFreeMain(tmp, free_size, used_size, total_size)) == false)
	{
		if (StrCmpi(tmp, "/") == 0)
		{
			break;
		}

		GetDirNameFromFilePath(tmp, sizeof(tmp), tmp);
	}

	return ret;
}
bool UnixGetDiskFreeMain(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
#ifndef	USE_STATVFS
	struct statfs st;
	char tmp[MAX_PATH];
	UINT64 v1 = 0, v2 = 0;
	bool ret = false;
	// Validate arguments
	if (path == NULL)
	{
		return false;
	}

	NormalizePath(tmp, sizeof(tmp), path);

	Zero(&st, sizeof(st));
	if (statfs(tmp, &st) == 0)
	{
		v1 = (UINT64)st.f_bsize * (UINT64)st.f_bavail;
		v2 = (UINT64)st.f_bsize * (UINT64)st.f_blocks;
		ret = true;
	}

	if (free_size != NULL)
	{
		*free_size = v1;
	}

	if (total_size != NULL)
	{
		*total_size = v2;
	}

	if (used_size != NULL)
	{
		*used_size = v2 - v1;
	}

	return ret;
#else	// USE_STATVFS
	struct statvfs st;
	char tmp[MAX_PATH];
	UINT64 v1 = 0, v2 = 0;
	bool ret = false;
	// Validate arguments
	if (path == NULL)
	{
		return false;
	}

	NormalizePath(tmp, sizeof(tmp), path);

	Zero(&st, sizeof(st));

	if (statvfs(tmp, &st) == 0)
	{
		v1 = (UINT64)st.f_bsize * (UINT64)st.f_bavail;
		v2 = (UINT64)st.f_bsize * (UINT64)st.f_blocks;
		ret = true;
	}

	if (free_size != NULL)
	{
		*free_size = v1;
	}

	if (total_size != NULL)
	{
		*total_size = v2;
	}

	if (used_size != NULL)
	{
		*used_size = v2 - v1;
	}

	return ret;
#endif	// USE_STATVFS
}

// Directory enumeration
DIRLIST *UnixEnumDirEx(char *dirname, COMPARE *compare)
{
	char tmp[MAX_PATH];
	DIRLIST *d;
	int n;
	struct dirent **e;
	LIST *o;
	// Validate arguments
	if (dirname == NULL)
	{
		return NULL;
	}

	o = NewListFast(compare);

	NormalizePath(tmp, sizeof(tmp), dirname);

	if (StrLen(tmp) >= 1 && tmp[StrLen(tmp) - 1] != '/')
	{
		StrCat(tmp, sizeof(tmp), "/");
	}

	e = NULL;
	n = scandir(tmp, &e, 0, alphasort);

	if (StrLen(tmp) >= 1 && tmp[StrLen(tmp) - 1] == '/')
	{
		tmp[StrLen(tmp) - 1] = 0;
	}

	if (n >= 0 && e != NULL)
	{
		UINT i;

		for (i = 0;i < (UINT)n;i++)
		{
			char *filename = e[i]->d_name;

			if (filename != NULL)
			{
				if (StrCmpi(filename, "..") != 0 && StrCmpi(filename, ".") != 0)
				{
					char fullpath[MAX_PATH];
					struct stat st;
					Format(fullpath, sizeof(fullpath), "%s/%s", tmp, filename);

					Zero(&st, sizeof(st));

					if (stat(fullpath, &st) == 0)
					{
						DIRENT *f = ZeroMalloc(sizeof(DIRENT));
						SYSTEMTIME t;

						f->Folder = S_ISDIR(st.st_mode) ? true : false;
						f->FileName = CopyStr(filename);
						f->FileNameW = CopyUtfToUni(f->FileName);

						Zero(&t, sizeof(t));
						TimeToSystem(&t, st.st_ctime);
						f->CreateDate = SystemToUINT64(&t);

						Zero(&t, sizeof(t));
						TimeToSystem(&t, st.st_mtime);
						f->UpdateDate = SystemToUINT64(&t);

						if (f->Folder == false)
						{
							f->FileSize = st.st_size;
						}

						Add(o, f);
					}
				}
			}

			free(e[i]);
		}

		free(e);
	}

	Sort(o);

	d = ZeroMalloc(sizeof(DIRLIST));
	d->NumFiles = LIST_NUM(o);
	d->File = ToArray(o);

	ReleaseList(o);

	return d;
}
DIRLIST *UnixEnumDirExW(wchar_t *dirname, COMPARE *compare)
{
	char *dirname_a = CopyUniToUtf(dirname);
	DIRLIST *ret;

	ret = UnixEnumDirEx(dirname_a, compare);

	Free(dirname_a);

	return ret;
}

// Check the execute permissions of the specified file
bool UnixCheckExecAccess(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (access(name, X_OK) == 0)
	{
		return true;
	}

	return false;
}
bool UnixCheckExecAccessW(wchar_t *name)
{
	char *name_a;
	bool ret;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	name_a = CopyUniToUtf(name);

	ret = UnixCheckExecAccess(name_a);

	Free(name_a);

	return ret;
}

// Raise the priority of the thread to highest
void UnixSetThreadPriorityRealtime()
{
	struct sched_param p;
	Zero(&p, sizeof(p));
	p.sched_priority = 255;
	pthread_setschedparam(pthread_self(), SCHED_RR, &p);
}

// Get the current directory
void UnixGetCurrentDir(char *dir, UINT size)
{
	// Validate arguments
	if (dir == NULL)
	{
		return;
	}

	getcwd(dir, size);
}
void UnixGetCurrentDirW(wchar_t *dir, UINT size)
{
	char dir_a[MAX_PATH];

	UnixGetCurrentDir(dir_a, sizeof(dir_a));

	UtfToUni(dir, size, dir_a);
}

// Yield
void UnixYield()
{
#ifdef UNIX_SOLARIS
	UnixSolarisSleep(1);
#else
	usleep(1000);
#endif
}

// Get the memory information
void UnixGetMemInfo(MEMINFO *info)
{
	// Validate arguments
	if (info == NULL)
	{
		return;
	}

	// I don't know!!
	Zero(info, sizeof(MEMINFO));
}

// Release of the single instance
void UnixFreeSingleInstance(void *data)
{
	UNIXLOCKFILE *o;
	struct flock lock;
	// Validate arguments
	if (data == NULL)
	{
		return;
	}

	o = (UNIXLOCKFILE *)data;

	Zero(&lock, sizeof(lock));
	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;

	(void)fcntl(o->fd, F_SETLK, &lock);
	close(o->fd);

	(void)remove(o->FileName);

	Free(data);
}

// Creating a single instance
void *UnixNewSingleInstance(char *instance_name)
{
	UNIXLOCKFILE *ret;
	char tmp[MAX_SIZE];
	char name[MAX_SIZE];
	char dir[MAX_PATH];
	int fd;
	struct flock lock;
	int mode = S_IRUSR | S_IWUSR;
	// Validate arguments
	if (instance_name == NULL)
	{
		GetExeName(tmp, sizeof(tmp));
		HashInstanceName(tmp, sizeof(tmp), tmp);
	}
	else
	{
		StrCpy(tmp, sizeof(tmp), instance_name);
	}

	GetPidDir(dir, sizeof(dir));

	// File name generation
	Format(name, sizeof(name), "%s/.%s", dir, tmp);

	fd = open(name, O_WRONLY);
	if (fd == -1)
	{
		fd = creat(name, mode);
	}
	if (fd == -1)
	{
		Format(tmp, sizeof(tmp), "Unable to create %s.", name);
		Alert(tmp, NULL);
		exit(0);
		return NULL;
	}

	fchmod(fd, mode);
	(void)chmod(name, mode);

	Zero(&lock, sizeof(lock));
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;

	if (fcntl(fd, F_SETLK, &lock) == -1)
	{
		close(fd);
		return NULL;
	}
	else
	{
		ret = ZeroMalloc(sizeof(UNIXLOCKFILE));
		ret->fd = fd;
		StrCpy(ret->FileName, sizeof(ret->FileName), name);
		return (void *)ret;
	}
}

// Set the high oom score
void UnixSetHighOomScore()
{
	IO *o;
	char tmp[256];

	sprintf(tmp, "/proc/%u/oom_score_adj", getpid());

	o = UnixFileCreate(tmp);
	if (o != NULL)
	{
		char tmp[128];
		sprintf(tmp, "%u\n", 800);
		UnixFileWrite(o, tmp, strlen(tmp));
		UnixFileClose(o, false);
	}
}

// Raise the priority of the process
void UnixSetHighPriority()
{
	if (high_process == false)
	{
		UINT pid = getpid();
		UINT pgid = getpgid(pid);

		high_process = true;
		nice(-20);

		setpriority(PRIO_PROCESS, pid, -20);
		setpriority(PRIO_PGRP, pgid, -20);
	}
}

// Restore the priority of the process
void UnixRestorePriority()
{
	if (high_process != false)
	{
		high_process = false;
		nice(20);
	}
}

UINT UnixGetNumberOfCpuInner()
{
	BUF *b;
	UINT ret = 0;

	b = ReadDump("/proc/cpuinfo");
	if (b != NULL)
	{
		while (true)
		{
			char *line = CfgReadNextLine(b);

			if (line == NULL)
			{
				break;
			}

			if (IsEmptyStr(line) == false)
			{
				TOKEN_LIST *t = ParseToken(line, ":");
				if (t != NULL)
				{
					if (t->NumTokens >= 2)
					{
						char *key = t->Token[0];
						char *value = t->Token[1];

						Trim(key);
						Trim(value);

						if (StrCmpi(key, "processor") == 0)
						{
							if (IsNum(value))
							{
								UINT i = ToInt(value) + 1;

								if (i >= 1 && i <= 128)
								{
									ret = MAX(ret, i);
								}
							}
						}
					}

					FreeToken(t);
				}
			}

			Free(line);
		}

		FreeBuf(b);
	}

	return ret;
}

// Get the product ID
char *UnixGetProductId()
{
	return CopyStr("--");
}

// Display an alert
void UnixAlertW(wchar_t *msg, wchar_t *caption)
{
	char *msg8 = CopyUniToUtf(msg);
	char *caption8 = CopyUniToUtf(caption);

	UnixAlert(msg8, caption8);

	Free(msg8);
	Free(caption8);
}
void UnixAlert(char *msg, char *caption)
{
	char *tag =
		"-- Alert: %s --\n%s\n";
	// Validate arguments
	if (msg == NULL)
	{
		msg = "Alert";
	}
	if (caption == NULL)
	{
		caption = CEDAR_PRODUCT_STR " VPN Kernel";
	}

	printf(tag, caption, msg);
}

// Get the information of the current OS
void UnixGetOsInfo(OS_INFO *info)
{
	struct utsname unix_info;

	// Validate arguments
	if (info == NULL)
	{
		return;
	}

	Zero(info, sizeof(OS_INFO));

#ifdef	UNIX_SOLARIS
	info->OsType = OSTYPE_SOLARIS;
#elif	UNIX_CYGWIN
	info->OsType = OSTYPE_CYGWIN;
#elif	UNIX_MACOS
	info->OsType = OSTYPE_MACOS_X;
#elif	UNIX_BSD
	info->OsType = OSTYPE_BSD;
#elif	UNIX_LINUX
	info->OsType = OSTYPE_LINUX;
#else
	info->OsType = OSTYPE_UNIX_UNKNOWN;
#endif

	info->OsSystemName = CopyStr(OsTypeToStr(info->OsType));
	info->KernelName = CopyStr("UNIX");

	if (uname(&unix_info) > -1)
	{
		info->OsProductName = CopyStr(unix_info.sysname);
		info->OsVersion = CopyStr(unix_info.release);
		info->KernelVersion = CopyStr(unix_info.version);
	}
	else
	{
		Debug("UnixGetOsInfo(): uname() failed with error: %s\n", strerror(errno));

		info->OsProductName = CopyStr(OsTypeToStr(info->OsType));
		info->OsVersion = CopyStr("Unknown");
		info->KernelVersion = CopyStr("Unknown");
	}
#ifdef	UNIX_LINUX
	{
		BUF *buffer = ReadDump("/etc/os-release");
		if (buffer == NULL)
		{
			buffer = ReadDump("/usr/lib/os-release");
		}

		if (buffer != NULL)
		{
			LIST *values = NewEntryList(buffer->Buf, "\n", "=");

			FreeBuf(buffer);

			if (EntryListHasKey(values, "NAME"))
			{
				char *str = EntryListStrValue(values, "NAME");
				TrimQuotes(str);
				Free(info->OsProductName);
				info->OsProductName = CopyStr(str);
			}

			if (EntryListHasKey(values, "HOME_URL"))
			{
				char *str = EntryListStrValue(values, "HOME_URL");
				TrimQuotes(str);
				info->OsVendorName = CopyStr(str);
			}

			if (EntryListHasKey(values, "VERSION"))
			{
				char *str = EntryListStrValue(values, "VERSION");
				TrimQuotes(str);
				Free(info->OsVersion);
				info->OsVersion = CopyStr(str);
			}
			else
			{
				// Debian testing/sid doesn't provide the version in /etc/os-release
				buffer = ReadDump("/etc/debian_version");
				if (buffer != NULL)
				{
					Free(info->OsVersion);
					info->OsVersion = CfgReadNextLine(buffer);
					FreeBuf(buffer);
				}
			}

			FreeEntryList(values);
		}
	}
#endif
}

// Examine whether the current OS is supported by the PacketiX VPN Kernel
bool UnixIsSupportedOs()
{
	// Support all UNIX OS which can run PacketiX VPN
	return true;
}

// Run a specified command
bool UnixRunW(wchar_t *filename, wchar_t *arg, bool hide, bool wait)
{
	char *filename8 = CopyUniToUtf(filename);
	char *arg8 = CopyUniToUtf(arg);
	bool ret = UnixRun(filename8, arg8, hide, wait);

	Free(filename8);
	Free(arg8);

	return ret;
}
bool UnixRun(char *filename, char *arg, bool hide, bool wait)
{
	TOKEN_LIST *t;
	char **args;
	UINT ret;

	// Validate arguments
	if (filename == NULL)
	{
		return false;
	}
	if (arg == NULL)
	{
		arg = "";
	}

	Print("", filename, arg);
	t = ParseToken(arg, " ");
	if (t == NULL)
	{
		return false;
	}
	else
	{
		UINT num_args;
		UINT i;
		num_args = t->NumTokens + 2;
		args = ZeroMalloc(sizeof(char *) * num_args);
		args[0] = filename;
		for (i = 1;i < num_args - 1;i++)
		{
			args[i] = t->Token[i - 1];
		}
	}
	
	// Create a child process
	ret = fork();
	if (ret == -1)
	{
		// Child process creation failure
		return false;
	}

	if (ret == 0)
	{
		// Child process
		if (hide)
		{
			// Close the standard I/O
			UnixCloseIO();
		}
		execvp(filename, args);
		AbortExit();
	}
	else
	{
		// Parent process
		pid_t pid = (pid_t)ret;
		Free(args);
		FreeToken(t);

		if (wait)
		{
			int status = 0;
			// Wait for the termination of the child process
			if (waitpid(pid, &status, 0) == -1)
			{
				return false;
			}

			if (WEXITSTATUS(status) == 0)
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		return true;
	}
}

// Close the standard I/O
void UnixCloseIO()
{
	static bool close_io_first = false;

	// Execute only once
	if (close_io_first)
	{
		return;
	}
	else
	{
		close(0);
		close(1);
		close(2);
		(void)open("/dev/null", O_RDWR);
		dup2(0, 1);
		dup2(0, 2);
		close_io_first = false;
	}
}

// Change the file name
bool UnixFileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	char *old_name8 = CopyUniToUtf(old_name);
	char *new_name8 = CopyUniToUtf(new_name);
	bool ret = UnixFileRename(old_name8, new_name8);

	Free(old_name8);
	Free(new_name8);

	return ret;
}
bool UnixFileRename(char *old_name, char *new_name)
{
	// Validate arguments
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	if (rename(old_name, new_name) != 0)
	{
		return false;
	}

	return true;
}

// Get the call stack
CALLSTACK_DATA *UnixGetCallStack()
{
	// This is not supported on non-Win32
	return NULL;
}

// Get the symbol information from the call stack
bool UnixGetCallStackSymbolInfo(CALLSTACK_DATA *s)
{
	// This is not supported on non-Win32
	return false;
}

// Delete the directory
bool UnixDeleteDirW(wchar_t *name)
{
	char *name8 = CopyUniToUtf(name);
	bool ret = UnixDeleteDir(name8);

	Free(name8);

	return ret;
}
bool UnixDeleteDir(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (rmdir(name) != 0)
	{
		return false;
	}

	return true;
}

// Create a directory
bool UnixMakeDirW(wchar_t *name)
{
	char *name8 = CopyUniToUtf(name);
	bool ret = UnixMakeDir(name8);

	Free(name8);

	return ret;
}
bool UnixMakeDir(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (mkdir(name, 0700) != 0)
	{
		return false;
	}

	return true;
}

// Delete the file
bool UnixFileDeleteW(wchar_t *name)
{
	bool ret;
	char *name8 = CopyUniToUtf(name);

	ret = UnixFileDelete(name8);

	Free(name8);

	return ret;
}
bool UnixFileDelete(char *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	if (remove(name) != 0)
	{
		return false;
	}

	return true;
}

// Seek the file
bool UnixFileSeek(void *pData, UINT mode, int offset)
{
	UNIXIO *p;
	UINT ret;
	// Validate arguments
	if (pData == NULL)
	{
		return 0;
	}
	if (mode != FILE_BEGIN && mode != FILE_END && mode != FILE_CURRENT)
	{
		return false;
	}

	p = (UNIXIO *)pData;

	ret = lseek(p->fd, offset, mode);

	if (ret == -1)
	{
		return false;
	}

	return true;
}

// Get the file size
UINT64 UnixFileSize(void *pData)
{
	struct stat st;
	UNIXIO *p;
	int r;
	// Validate arguments
	if (pData == NULL)
	{
		return 0;
	}

	p = (UNIXIO *)pData;

	Zero(&st, sizeof(st));
	r = fstat(p->fd, &st);
	if (r != 0)
	{
		return 0;
	}

	return (UINT64)st.st_size;
}

// Write to the file
bool UnixFileWrite(void *pData, void *buf, UINT size)
{
	UNIXIO *p;
	UINT ret;
	// Validate arguments
	if (pData == NULL || buf == NULL || size == 0)
	{
		return false;
	}

	p = (UNIXIO *)pData;

	ret = write(p->fd, buf, size);
	if (ret != size)
	{
		return false;
	}

	return true;
}

// Read from the file
bool UnixFileRead(void *pData, void *buf, UINT size)
{
	UNIXIO *p;
	UINT ret;
	// Validate arguments
	if (pData == NULL || buf == NULL || size == 0)
	{
		return false;
	}

	p = (UNIXIO *)pData;

	ret = read(p->fd, buf, size);
	if (ret != size)
	{
		return false;
	}

	return true;
}

// Flush to the file
void UnixFileFlush(void *pData)
{
	UNIXIO *p;
	bool write_mode;
	// Validate arguments
	if (pData == NULL)
	{
		return;
	}

	p = (UNIXIO *)pData;

	write_mode = p->write_mode;

	if (write_mode)
	{
		fsync(p->fd);
	}
}

// Close the file
void UnixFileClose(void *pData, bool no_flush)
{
	UNIXIO *p;
	bool write_mode;
	// Validate arguments
	if (pData == NULL)
	{
		return;
	}

	p = (UNIXIO *)pData;

	write_mode = p->write_mode;

	if (write_mode && no_flush == false)
	{
		fsync(p->fd);
	}

	close(p->fd);

	UnixMemoryFree(p);

	if (write_mode)
	{
		//sync();
	}
}

// Create a file
void *UnixFileCreateW(wchar_t *name)
{
	void *ret;
	char *name8 = CopyUniToUtf(name);

	ret = UnixFileCreate(name8);

	Free(name8);

	return ret;
}
void *UnixFileCreate(char *name)
{
	UNIXIO *p;
	int fd;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	fd = creat(name, 0600);
	if (fd == -1)
	{
		return NULL;
	}

	// Memory allocation
	p = UnixMemoryAlloc(sizeof(UNIXIO));
	p->fd = fd;
	p->write_mode = true;

	return (void *)p;
}

// Open the file
void *UnixFileOpenW(wchar_t *name, bool write_mode, bool read_lock)
{
	char *name8 = CopyUniToUtf(name);
	void *ret;

	ret = UnixFileOpen(name8, write_mode, read_lock);

	Free(name8);

	return ret;
}
void *UnixFileOpen(char *name, bool write_mode, bool read_lock)
{
	UNIXIO *p;
	int fd;
	int mode;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	if (write_mode == false)
	{
		mode = O_RDONLY;
	}
	else
	{
		mode = O_RDWR;
	}

	// Open the file
	fd = open(name, mode);
	if (fd == -1)
	{
		return NULL;
	}

	// Memory allocation
	p = UnixMemoryAlloc(sizeof(UNIXIO));
	p->fd = fd;
	p->write_mode = write_mode;

	return (void *)p;
}

// Get UNIXIO object for stdout
void* GetUnixio4Stdout()
{
	static UNIXIO unixio =
	{
		.fd = -1,
		.write_mode = true
	};

	if (g_foreground)
	{
		unixio.fd = STDOUT_FILENO;
		return &unixio;
	}
	return NULL;
}

// Return the current thread ID
UINT UnixThreadId()
{
	UINT ret;

	ret = (UINT)pthread_self();

	return ret;
}

// Thread function
void *UnixDefaultThreadProc(void *param)
{
	UNIXTHREAD *ut;
	UNIXTHREADSTARTUPINFO *info = (UNIXTHREADSTARTUPINFO *)param;
	if (info == NULL)
	{
		return 0;
	}

	ut = (UNIXTHREAD *)info->thread->pData;

	// Call the thread function
	info->thread_proc(info->thread, info->param);

	// Set a termination flag
	ut->finished = true;

	// Release of reference
	ReleaseThread(info->thread);

	UnixMemoryFree(info);

	FreeOpenSSLThreadState();

	return 0;
}

// Release of thread
void UnixFreeThread(THREAD *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	// Free memory
	UnixMemoryFree(t->pData);
}

// Wait for the termination of the thread
bool UnixWaitThread(THREAD *t)
{
	UNIXTHREAD *ut;
	void *retcode = NULL;
	// Validate arguments
	if (t == NULL)
	{
		return false;
	}
	ut = (UNIXTHREAD *)t->pData;
	if (ut == NULL)
	{
		return false;
	}

	pthread_join(ut->thread, &retcode);

	return true;
}

// Thread initialization
bool UnixInitThread(THREAD *t)
{
	UNIXTHREAD *ut;
	UNIXTHREADSTARTUPINFO *info;
	pthread_attr_t attr;
	// Validate arguments
	if (t == NULL || t->thread_proc == NULL)
	{
		return false;
	}

	// Thread data creation
	ut = UnixMemoryAlloc(sizeof(UNIXTHREAD));
	Zero(ut, sizeof(UNIXTHREAD));

	// Creating the startup information
	info = UnixMemoryAlloc(sizeof(UNIXTHREADSTARTUPINFO));
	Zero(info, sizeof(UNIXTHREADSTARTUPINFO));
	info->param = t->param;
	info->thread_proc = t->thread_proc;
	info->thread = t;
	AddRef(t->ref);

	// Thread creation
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, UNIX_THREAD_STACK_SIZE);

	t->pData = (void *)ut;

	if (pthread_create(&ut->thread, &attr, UnixDefaultThreadProc, info) != 0)
	{
		// An error has occured
		t->pData = NULL;
		(void)Release(t->ref);
		UnixMemoryFree(ut);
		UnixMemoryFree(info);
		pthread_attr_destroy(&attr);
		return false;
	}

	pthread_attr_destroy(&attr);

	return true;
}

// Release the event
void UnixFreeEvent(EVENT *event)
{
	UNIXEVENT *ue = (UNIXEVENT *)event->pData;
	if (ue == NULL)
	{
		return;
	}

	pthread_cond_destroy(&ue->cond);
	pthread_mutex_destroy(&ue->mutex);

	UnixMemoryFree(ue);
}

// Wait for a event
bool UnixWaitEvent(EVENT *event, UINT timeout)
{
	UNIXEVENT *ue = (UNIXEVENT *)event->pData;
	struct timeval now;
	struct timespec to;
	bool ret;
	if (ue == NULL)
	{
		return false;
	}

	pthread_mutex_lock(&ue->mutex);
	gettimeofday(&now, NULL);
	to.tv_sec = now.tv_sec + timeout / 1000;
	to.tv_nsec = now.tv_usec * 1000 + (timeout % 1000) * 1000 * 1000;
	if ((to.tv_nsec / 1000000000) >= 1)
	{
		to.tv_sec += to.tv_nsec / 1000000000;
		to.tv_nsec = to.tv_nsec % 1000000000;
	}

	ret = true;

	while (ue->signal == false)
	{
		if (timeout != INFINITE)
		{
			if (pthread_cond_timedwait(&ue->cond, &ue->mutex, &to))
			{
				ret = false;
				break;
			}
		}
		else
		{
			pthread_cond_wait(&ue->cond, &ue->mutex);
		}
	}
	ue->signal = false;

	pthread_mutex_unlock(&ue->mutex);

	return ret;
}

// Reset the event
void UnixResetEvent(EVENT *event)
{
	UNIXEVENT *ue = (UNIXEVENT *)event->pData;
	if (ue == NULL)
	{
		return;
	}

	pthread_mutex_lock(&ue->mutex);
	ue->signal = false;
	pthread_cond_signal(&ue->cond);
	pthread_mutex_unlock(&ue->mutex);
}

// Set the event
void UnixSetEvent(EVENT *event)
{
	UNIXEVENT *ue = (UNIXEVENT *)event->pData;
	if (ue == NULL)
	{
		return;
	}

	pthread_mutex_lock(&ue->mutex);
	ue->signal = true;
	pthread_cond_signal(&ue->cond);
	pthread_mutex_unlock(&ue->mutex);
}

// Initialize the event
void UnixInitEvent(EVENT *event)
{
	UNIXEVENT *ue = UnixMemoryAlloc(sizeof(UNIXEVENT));

	Zero(ue, sizeof(UNIXEVENT));

	pthread_cond_init(&ue->cond, NULL);
	pthread_mutex_init(&ue->mutex, NULL);
	ue->signal = false;

	event->pData = (void *)ue;
}

// Delete the lock
void UnixDeleteLock(LOCK *lock)
{
	pthread_mutex_t *mutex;
	// Reset Ready flag safely
	UnixLock(lock);
	lock->Ready = false;
	UnixUnlockEx(lock, true);

	// Delete the mutex
	mutex = (pthread_mutex_t *)lock->pData;
	pthread_mutex_destroy(mutex);

	// Memory release
	UnixMemoryFree(mutex);
	UnixMemoryFree(lock);
}

// Unlock
void UnixUnlock(LOCK *lock)
{
	UnixUnlockEx(lock, false);
}
void UnixUnlockEx(LOCK *lock, bool inner)
{
	pthread_mutex_t *mutex;
	if (lock->Ready == false && inner == false)
	{
		// State is invalid
		return;
	}
	mutex = (pthread_mutex_t *)lock->pData;

	if ((--lock->locked_count) > 0)
	{
		return;
	}

	lock->thread_id = INFINITE;

	pthread_mutex_unlock(mutex);

	return;
}

// Lock
bool UnixLock(LOCK *lock)
{
	pthread_mutex_t *mutex;
	UINT thread_id = UnixThreadId();
	if (lock->Ready == false)
	{
		// State is invalid
		return false;
	}

	if (lock->thread_id == thread_id)
	{
		lock->locked_count++;
		return true;
	}

	mutex = (pthread_mutex_t *)lock->pData;

	pthread_mutex_lock(mutex);

	lock->thread_id = thread_id;
	lock->locked_count++;

	return true;
}

// Creating a new lock
LOCK *UnixNewLock()
{
	pthread_mutex_t *mutex;
	// Memory allocation
	LOCK *lock = UnixMemoryAlloc(sizeof(LOCK));
	if (lock == NULL)
	{
		return NULL;
	}

	// Create a mutex
	mutex = UnixMemoryAlloc(sizeof(pthread_mutex_t));
	if (mutex == NULL)
	{
		UnixMemoryFree(lock);
		return NULL;
	}

	// Initialization of the mutex
	pthread_mutex_init(mutex, NULL);

	lock->pData = (void *)mutex;
	lock->Ready = true;

	lock->thread_id = INFINITE;
	lock->locked_count = 0;

	return lock;
}

// Sleep
void UnixSleep(UINT time)
{
	UINT sec = 0, millisec = 0;
	// Validate arguments
	if (time == 0)
	{
		return;
	}

	if (time == INFINITE)
	{
		// Wait forever
		while (true)
		{
#ifdef UNIX_SOLARIS
			UnixSolarisSleep(time);
#else
			sleep(1000000);
#endif
		}
	}

#ifdef UNIX_SOLARIS
	UnixSolarisSleep(time);
#else

	// Prevent overflow
	sec = time / 1000;
	millisec = time % 1000;

	if (sec != 0)
	{
		sleep(sec);
	}
	if (millisec != 0)
	{
		usleep(millisec * 1000);
	}
#endif
}

// Decrement
void UnixDec32(UINT *value)
{
	if (value != NULL)
	{
		(*value)--;
	}
}

// Increment
void UnixInc32(UINT *value)
{
	if (value != NULL)
	{
		(*value)++;
	}
}

// Get the System Time
void UnixGetSystemTime(SYSTEMTIME *system_time)
{
	time_t now = 0;
	time_64t now2 = 0;
	struct tm tm;
	struct timeval tv;
	struct timezone tz;
	// Validate arguments
	if (system_time == NULL)
	{
		return;
	}

	pthread_mutex_lock(&get_time_lock);

	Zero(system_time, sizeof(SYSTEMTIME));
	Zero(&tv, sizeof(tv));
	Zero(&tz, sizeof(tz));

	time(&now);

	if (sizeof(time_t) == 4)
	{
		now2 = (time_64t)((UINT64)((UINT)now));
	}
	else
	{
		now2 = now;
	}

	c_gmtime_r(&now2, &tm);

	TmToSystem(system_time, &tm);

	gettimeofday(&tv, &tz);

	system_time->wMilliseconds = tv.tv_usec / 1000;

	pthread_mutex_unlock(&get_time_lock);
}

UINT64 UnixGetHighresTickNano64(bool raw)
{
#if	defined(OS_WIN32) || defined(CLOCK_REALTIME) || defined(CLOCK_MONOTONIC) || defined(CLOCK_HIGHRES)
	struct timespec t;
	UINT64 ret;
	static bool akirame = false;

	if (akirame)
	{
		return UnixGetTick64() * 1000000ULL;
	}

	Zero(&t, sizeof(t));

	if (raw == false)
	{
		// Function to get the boot time of the system
		// Be careful. The Implementation is depend on the system.
#ifdef	CLOCK_HIGHRES
		clock_gettime(CLOCK_HIGHRES, &t);
#else	// CLOCK_HIGHRES
#ifdef	CLOCK_MONOTONIC
		clock_gettime(CLOCK_MONOTONIC, &t);
#else	// CLOCK_MONOTONIC
		clock_gettime(CLOCK_REALTIME, &t);
#endif	// CLOCK_MONOTONIC
#endif	// CLOCK_HIGHRES
	}
	else
	{
		// Function to get the boot time of the system
		// Be careful. The Implementation is depend on the system.
#ifdef	CLOCK_HIGHRES
		clock_gettime(CLOCK_HIGHRES, &t);
#else	// CLOCK_HIGHRES
#ifdef	CLOCK_MONOTONIC_RAW
		clock_gettime(CLOCK_MONOTONIC_RAW, &t);
#else	// CLOCK_MONOTONIC_RAW
#ifdef	CLOCK_MONOTONIC
		clock_gettime(CLOCK_MONOTONIC, &t);
#else	// CLOCK_MONOTONIC
		clock_gettime(CLOCK_REALTIME, &t);
#endif	// CLOCK_MONOTONIC
#endif	// CLOCK_MONOTONIC_RAW
#endif	// CLOCK_HIGHRES
	}

	ret = ((UINT64)((UINT)t.tv_sec)) * 1000000000LL + (UINT64)t.tv_nsec;

	if (akirame == false && ret == 0)
	{
		ret = UnixGetTick64() * 1000000ULL;
		akirame = true;
	}

	return ret;

#else	
	return UnixGetTick64() * 1000000ULL;
#endif
}

// Get the system timer (64bit)
UINT64 UnixGetTick64()
{
#if	defined(OS_WIN32) || defined(CLOCK_REALTIME) || defined(CLOCK_MONOTONIC) || defined(CLOCK_HIGHRES)

	struct timespec t;
	UINT64 ret;

	Zero(&t, sizeof(t));

	// Function to get the boot time of the system
	// Be careful. The Implementation is depend on the system.
#ifdef	CLOCK_HIGHRES
	clock_gettime(CLOCK_HIGHRES, &t);
#elif	CLOCK_MONOTONIC
	clock_gettime(CLOCK_MONOTONIC, &t);
#else
	clock_gettime(CLOCK_REALTIME, &t);
#endif

	ret = ((UINT64)((UINT)t.tv_sec)) * 1000LL + (UINT64)t.tv_nsec / 1000000LL;

	if (ret == 0)
	{
		ret = TickRealtimeManual();
	}

	return ret;
#else
	return TickRealtimeManual();
#endif
}

// Get the system timer
UINT UnixGetTick()
{
	return (UINT)UnixGetTick64();
}

// Memory allocation
void *UnixMemoryAlloc(UINT size)
{
	void *r;
	pthread_mutex_lock(&malloc_lock);
	r = malloc(size);
	pthread_mutex_unlock(&malloc_lock);
	return r;
}

// Reallocation of the memory
void *UnixMemoryReAlloc(void *addr, UINT size)
{
	void *r;
	pthread_mutex_lock(&malloc_lock);
	r = realloc(addr, size);
	pthread_mutex_unlock(&malloc_lock);
	return r;
}

// Free the memory
void UnixMemoryFree(void *addr)
{
	pthread_mutex_lock(&malloc_lock);
	free(addr);
	pthread_mutex_unlock(&malloc_lock);
}

// SIGCHLD handler
void UnixSigChldHandler(int sig)
{
	// Recall the zombie processes
	while (waitpid(-1, NULL, WNOHANG) > 0);
	signal(SIGCHLD, UnixSigChldHandler);
}

// Disable core dump
void UnixDisableCoreDump()
{
#ifdef	RLIMIT_CORE
	UnixSetResourceLimit(RLIMIT_CORE, 0);
#endif	// RLIMIT_CORE
}

// Initialize the library for UNIX
void UnixInit()
{
	UNIXIO *o;
	UINT64 max_memory = UNIX_MAX_MEMORY;

	if (UnixIs64BitRlimSupported())
	{
		max_memory = UNIX_MAX_MEMORY_64;
	}

	UnixInitSolarisSleep();

	// Global lock
	pthread_mutex_init(&get_time_lock, NULL);
	pthread_mutex_init(&malloc_lock, NULL);

	// Get the Process ID
	current_process_id = getpid();

#ifdef	RLIMIT_CORE
	UnixSetResourceLimit(RLIMIT_CORE, max_memory);
#endif	// RLIMIT_CORE

#ifdef	RLIMIT_DATA
	UnixSetResourceLimit(RLIMIT_DATA, max_memory);
#endif	// RLIMIT_DATA

#ifdef	RLIMIT_NOFILE
#ifndef	UNIX_MACOS
	UnixSetResourceLimit(RLIMIT_NOFILE, UNIX_MAX_FD);
#else	// UNIX_MACOS
	UnixSetResourceLimit(RLIMIT_NOFILE, UNIX_MAX_FD_MACOS);
#endif	// UNIX_MACOS
#endif	// RLIMIT_NOFILE

#ifdef	RLIMIT_STACK
//	UnixSetResourceLimit(RLIMIT_STACK, max_memory);
#endif	// RLIMIT_STACK

#ifdef	RLIMIT_RSS
	UnixSetResourceLimit(RLIMIT_RSS, max_memory);
#endif	// RLIMIT_RSS

#ifdef	RLIMIT_LOCKS
	UnixSetResourceLimit(RLIMIT_LOCKS, UNIX_MAX_LOCKS);
#endif	// RLIMIT_LOCKS

#ifdef	RLIMIT_MEMLOCK
	UnixSetResourceLimit(RLIMIT_MEMLOCK, max_memory);
#endif	// RLIMIT_MEMLOCK

#ifdef	RLIMIT_NPROC
	UnixSetResourceLimit(RLIMIT_NPROC, UNIX_MAX_CHILD_PROCESSES);
#endif	// RLIMIT_NPROC

	// Write a value to the threads-max of the proc file system
	o = UnixFileCreate("/proc/sys/kernel/threads-max");
	if (o != NULL)
	{
		char tmp[128];
		sprintf(tmp, "%u\n", UNIX_LINUX_MAX_THREADS);
		UnixFileWrite(o, tmp, strlen(tmp));
		UnixFileClose(o, false);
	}

	// Set the signals that is to be ignored
	signal(SIGPIPE, SIG_IGN);
	signal(SIGALRM, SIG_IGN);

#ifdef	UNIX_BSD
	signal(64, SIG_IGN);
#endif	// UNIX_BSD

#ifdef	SIGXFSZ
	signal(SIGXFSZ, SIG_IGN);
#endif	// SIGXFSZ

	// Set a signal handler to salvage the child processes
	signal(SIGCHLD, UnixSigChldHandler);
}

// Release the library for UNIX
void UnixFree()
{
	UnixFreeSolarisSleep();

	current_process_id = 0;

	pthread_mutex_destroy(&get_time_lock);
}

// Adjust the upper limit of resources that may be occupied
void UnixSetResourceLimit(UINT id, UINT64 value)
{
	struct rlimit t;
	UINT64 hard_limit;

	if (UnixIs64BitRlimSupported() == false)
	{
		if (value > (UINT64)4294967295ULL)
		{
			value = (UINT64)4294967295ULL;
		}
	}

	Zero(&t, sizeof(t));
	getrlimit(id, &t);

	hard_limit = (UINT64)t.rlim_max;

	Zero(&t, sizeof(t));
	t.rlim_cur = (rlim_t)MIN(value, hard_limit);
	t.rlim_max = (rlim_t)hard_limit;
	setrlimit(id, &t);

	Zero(&t, sizeof(t));
	t.rlim_cur = (rlim_t)value;
	t.rlim_max = (rlim_t)value;
	setrlimit(id, &t);
}

// Is the rlim_t type 64-bit?
bool UnixIs64BitRlimSupported()
{
	if (sizeof(rlim_t) >= 8)
	{
		return true;
	}

	return false;
}

// Generate the PID file name
void UnixGenPidFileName(char *name, UINT size)
{
	char exe_name[MAX_PATH];
	UCHAR hash[MD5_SIZE];
	char tmp1[64];
	char dir[MAX_PATH];
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	GetPidDir(dir, sizeof(dir));

	GetExeName(exe_name, sizeof(exe_name));
	StrCat(exe_name, sizeof(exe_name), ":pid_hash");
	StrUpper(exe_name);

	Md5(hash, exe_name, StrLen(exe_name));
	BinToStr(tmp1, sizeof(tmp1), hash, sizeof(hash));

	Format(name, size, "%s/.pid_%s", dir, tmp1);
}

// Delete the PID file
void UnixDeletePidFile()
{
	char tmp[MAX_PATH];

	UnixGenPidFileName(tmp, sizeof(tmp));

	UnixFileDelete(tmp);
}

// Delete the CTL file
void UnixDeleteCtlFile()
{
	char tmp[MAX_PATH];

	UnixGenCtlFileName(tmp, sizeof(tmp));

	UnixFileDelete(tmp);
}

// Generate the CTL file name
void UnixGenCtlFileName(char *name, UINT size)
{
	char exe_name[MAX_PATH];
	UCHAR hash[MD5_SIZE];
	char tmp1[64];
	char dir[MAX_PATH];
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	GetPidDir(dir, sizeof(dir));

	GetExeName(exe_name, sizeof(exe_name));
	StrCat(exe_name, sizeof(exe_name), ":pid_hash");
	StrUpper(exe_name);

	Md5(hash, exe_name, StrLen(exe_name));
	BinToStr(tmp1, sizeof(tmp1), hash, sizeof(hash));

	Format(name, size, "%s/.ctl_%s", dir, tmp1);
}

// Write the CTL file
void UnixWriteCtlFile(UINT i)
{
	char tmp[MAX_PATH];
	char tmp2[64];
	IO *o;

	UnixGenCtlFileName(tmp, sizeof(tmp));
	Format(tmp2, sizeof(tmp2), "%u\n", i);

	o = FileCreate(tmp);
	if (o != NULL)
	{
		FileWrite(o, tmp2, StrLen(tmp2));
		FileClose(o);
	}
}

// Write to the PID file
void UnixWritePidFile(UINT pid)
{
	char tmp[MAX_PATH];
	char tmp2[64];
	IO *o;

	UnixGenPidFileName(tmp, sizeof(tmp));
	Format(tmp2, sizeof(tmp2), "%u\n", pid);

	o = FileCreate(tmp);
	if (o != NULL)
	{
		FileWrite(o, tmp2, StrLen(tmp2));
		FileClose(o);
	}
}

// Read the PID file
UINT UnixReadPidFile()
{
	char tmp[MAX_PATH];
	BUF *buf;

	UnixGenPidFileName(tmp, sizeof(tmp));

	buf = ReadDump(tmp);
	if (buf == NULL)
	{
		return 0;
	}

	Zero(tmp, sizeof(tmp));
	Copy(tmp, buf->Buf, MIN(buf->Size, sizeof(tmp)));
	FreeBuf(buf);

	return ToInt(tmp);
}

// Read the CTL file
UINT UnixReadCtlFile()
{
	char tmp[MAX_PATH];
	BUF *buf;

	UnixGenCtlFileName(tmp, sizeof(tmp));

	buf = ReadDump(tmp);
	if (buf == NULL)
	{
		return 0;
	}

	Zero(tmp, sizeof(tmp));
	Copy(tmp, buf->Buf, MIN(buf->Size, sizeof(tmp)));
	FreeBuf(buf);

	return ToInt(tmp);
}

// Get the UID
UINT UnixGetUID()
{
	return (UINT)getuid();
}

// Start the service
void UnixStartService(char *name)
{
	char *svc_name, *svc_title;
	char tmp[128];
	INSTANCE *inst;
	char exe[MAX_PATH];
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	GetExeName(exe, sizeof(exe));

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	svc_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	svc_title = _SS(tmp);

	// Examine whether the service has not been started already
	inst = NewSingleInstance(NULL);
	if (inst == NULL)
	{
		// Service is already running
		UniPrint(_UU("UNIX_SVC_ALREADY_START"), svc_title, svc_name);
	}
	else
	{
		int pid;
		// Begin to start the service
		UniPrint(_UU("UNIX_SVC_STARTED"), svc_title);

		if (UnixGetUID() != 0)
		{
			// Non-root warning
			UniPrint(_UU("UNIX_SVC_NONROOT"));
		}

		FreeSingleInstance(inst);

		// Create a child process
		pid = fork();
		if (pid == -1)
		{
			UniPrint(_UU("UNIX_SVC_ERROR_FORK"), svc_title);
		}
		else
		{
			if (pid == 0)
			{
				// Child process
				char *param = UNIX_SVC_ARG_EXEC_SVC;
				char **args;

				// Daemonize
				setsid();
				UnixCloseIO();
				signal(SIGHUP, SIG_IGN);

				// Prepare arguments
				args = ZeroMalloc(sizeof(char *) * 3);
				args[0] = exe;
				args[1] = param;
				args[2] = NULL;

				execvp(exe, args);
				AbortExit();
			}
			else
			{
				// Don't write the child process number to the file
//				UnixWritePidFile(pid);
			}
		}
	}
}

// Stop the Service
void UnixStopService(char *name)
{
	char *svc_name, *svc_title;
	char tmp[128];
	INSTANCE *inst;
	char exe[MAX_PATH];
	UINT pid;
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	GetExeName(exe, sizeof(exe));

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	svc_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	svc_title = _SS(tmp);

	inst = NewSingleInstance(NULL);
	pid = UnixReadPidFile();
	if (inst != NULL || pid == 0)
	{
		// Service is not running yet
		UniPrint(_UU("UNIX_SVC_NOT_STARTED"), svc_title, svc_name);
	}
	else
	{
		// Stop the service
		UniPrint(_UU("UNIX_SVC_STOPPING"), svc_title);

		// Terminate the process
		kill(pid, SIGTERM);
#ifdef	UNIX_BSD
		UnixWriteCtlFile(Rand32());
#endif	// UNIX_BSD
		if (UnixWaitProcessEx(pid, UNIX_SERVICE_STOP_TIMEOUT_2))
		{
			UniPrint(_UU("UNIX_SVC_STOPPED"), svc_title);
		}
		else
		{
			// SIGKILL
			char tmp[256];

			Format(tmp, sizeof(tmp), "killall -KILL %s", name);

			UniPrint(_UU("UNIX_SVC_STOP_FAILED"), svc_title);
			system(tmp);
		}
	}

	FreeSingleInstance(inst);
}

// Handler of the stop signal to the process
void UnixSigTermHandler(int signum)
{
	if (signum == SIGTERM)
	{
		unix_svc_terminate = true;
	}
}

// The thread for stop service
void UnixStopThread(THREAD *t, void *param)
{
	SERVICE_FUNCTION *stop = (SERVICE_FUNCTION *)param;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	stop();
}

// Execute the main body of the service
void UnixExecService(char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	char *svc_name, *svc_title;
	char tmp[128];
	INSTANCE *inst;
	UINT yobi_size = 1024 * 128;
	void *yobi1, *yobi2;
	UINT saved_ctl;
	// Validate arguments
	if (start == NULL || stop == NULL || name == NULL)
	{
		return;
	}

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	svc_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	svc_title = _SS(tmp);

	UnixWriteCtlFile(Rand32());
	saved_ctl = UnixReadCtlFile();

	inst = NewSingleInstance(NULL);
	if (inst != NULL)
	{
		THREAD *t;

		yobi1 = ZeroMalloc(yobi_size);
		yobi2 = ZeroMalloc(yobi_size);

		// Start
		UnixWritePidFile(getpid());

		start();

		// Starting complete. wait for arriving SIGTERM from another process
		signal(SIGTERM, &UnixSigTermHandler);
		while (unix_svc_terminate == false)
		{
#if	!(defined(UNIX_BSD) || defined(UNIX_MACOS))
			pause();
#else	// defined(UNIX_BSD) || defined(UNIX_MACOS)
			if (UnixReadCtlFile() != saved_ctl)
			{
				break;
			}

			SleepThread(1394);
#endif	// defined(UNIX_BSD) || defined(UNIX_MACOS)
		}

		// Stop
		Free(yobi1);
		t = NewThread(UnixStopThread, stop);
		if (t == NULL || (WaitThread(t, UNIX_SERVICE_STOP_TIMEOUT_1) == false))
		{
			// Terminate forcibly if creation of a halting thread have
			// failed or timed out
			Free(yobi2);
			FreeSingleInstance(inst);
			UnixDeletePidFile();
			_exit(0);
		}
		ReleaseThread(t);

		// Delete the PID file
		UnixDeletePidFile();

		// Delete the CTL file
		UnixDeleteCtlFile();

		FreeSingleInstance(inst);

		Free(yobi2);
	}
}

// Get whether the process with the specified pid exists
bool UnixIsProcess(UINT pid)
{
	if (getsid((pid_t)pid) == -1)
	{
		return false;
	}

	return true;
}

// Wait for the termination of the specified process
bool UnixWaitProcessEx(UINT pid,  UINT timeout)
{
	UINT64 start_tick = Tick64();
	UINT64 end_tick = start_tick + (UINT64)timeout;
	if (timeout == INFINITE)
	{
		end_tick = 0;
	}
	while (UnixIsProcess(pid))
	{
		if (end_tick != 0)
		{
			if (end_tick < Tick64())
			{
				return false;
			}
		}
		SleepThread(100);
	}
	return true;
}

// Description of how to start
void UnixUsage(char *name)
{
	char *svc_name, *svc_title;
	char tmp[128];
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	Format(tmp, sizeof(tmp), SVC_NAME, name);
	svc_name = _SS(tmp);
	Format(tmp, sizeof(tmp), SVC_TITLE, name);
	svc_title = _SS(tmp);

	UniPrint(_UU("UNIX_SVC_HELP"), svc_title, svc_name, svc_name, svc_title, svc_name, svc_title);
}

// Main function of the UNIX service
UINT UnixService(int argc, char *argv[], char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	// Validate arguments
	if (name == NULL || start == NULL || stop == NULL)
	{
		return 0;
	}

	if (argc >= 2 && StrCmpi(argv[1], UNIX_SVC_ARG_EXEC_SVC) == 0)
	{
		UINT pid;
		// Start a child process
		// Restart if the child process didn't exit properly

RESTART_PROCESS:
		pid = fork();
		if ((int)pid != -1)
		{
			if (pid == 0)
			{
				// Run the main process
				UnixServiceMain(argc, argv, name, start, stop);
			}
			else
			{
				int status = 0, ret;

				// Wait for the termination of the child process
				ret = waitpid(pid, &status, 0);

				if (WIFEXITED(status) == 0)
				{
					// Aborted
					UnixSleep(100);
					goto RESTART_PROCESS;
				}
			}
		}
	}
	else if (argc >= 3 && StrCmpi(argv[1], UNIX_SVC_ARG_START) == 0 && StrCmpi(argv[2], UNIX_SVC_ARG_FOREGROUND) == 0)
	{
#ifdef DEBUG
		// If set memcheck = true, the program will be vitally slow since it will log all malloc() / realloc() / free() calls to find the cause of memory leak.
		// For normal debug we set memcheck = false.
		// Please set memcheck = true if you want to test the cause of memory leaks.
		InitMayaqua(false, true, argc, argv);
#else
		InitMayaqua(false, false, argc, argv);
#endif
		UnixExecService(name, start, stop);
		FreeMayaqua();
	}
	else
	{
		// Start normally
		UnixServiceMain(argc, argv, name, start, stop);
	}

	return 0;
}
void UnixServiceMain(int argc, char *argv[], char *name, SERVICE_FUNCTION *start, SERVICE_FUNCTION *stop)
{
	UINT mode = 0;
	// Start of the Mayaqua
#ifdef DEBUG
	// If set memcheck = true, the program will be vitally slow since it will log all malloc() / realloc() / free() calls to find the cause of memory leak.
	// For normal debug we set memcheck = false.
	// Please set memcheck = true if you want to test the cause of memory leaks.
	InitMayaqua(false, true, argc, argv);
#else
	InitMayaqua(false, false, argc, argv);
#endif

	if (argc >= 2)
	{
		if (StrCmpi(argv[1], UNIX_SVC_ARG_START) == 0)
		{
			mode = UNIX_SVC_MODE_START;
		}
		if (StrCmpi(argv[1], UNIX_SVC_ARG_STOP) == 0)
		{
			mode = UNIX_SVC_MODE_STOP;
		}
		if (StrCmpi(argv[1], UNIX_SVC_ARG_EXEC_SVC) == 0)
		{
			mode = UNIX_SVC_MODE_EXEC_SVC;
		}
		if (StrCmpi(argv[1], UNIX_ARG_EXIT) == 0)
		{
			mode = UNIX_SVC_MODE_EXIT;
		}
	}

	switch (mode)
	{
	case UNIX_SVC_MODE_EXIT:
		break;

	case UNIX_SVC_MODE_START:
		UnixStartService(name);
		break;

	case UNIX_SVC_MODE_STOP:
		UnixStopService(name);
		break;

	case UNIX_SVC_MODE_EXEC_SVC:
		UnixExecService(name, start, stop);
		break;

	default:
		UnixUsage(name);
		break;
	}

	// End of the Mayaqua
	FreeMayaqua();

	return;
}

#endif	// UNIX
