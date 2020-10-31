// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Server.c
// VPN Server module

#include "CedarPch.h"

static SERVER *server = NULL;
static LOCK *server_lock = NULL;
char *SERVER_CONFIG_FILE_NAME = "$vpn_server.config";
char *SERVER_CONFIG_FILE_NAME_IN_CLIENT = "$vpn_gate_svc.config";
char *SERVER_CONFIG_FILE_NAME_IN_CLIENT_RELAY = "$vpn_gate_relay.config";
char *BRIDGE_CONFIG_FILE_NAME = "$vpn_bridge.config";
char *SERVER_CONFIG_TEMPLATE_NAME = "$vpn_server_template.config";
char *BRIDGE_CONFIG_TEMPLATE_NAME = "$vpn_server_template.config";

static bool server_reset_setting = false;

static volatile UINT global_server_flags[NUM_GLOBAL_SERVER_FLAGS] = {0};

UINT vpn_global_parameters[NUM_GLOBAL_PARAMS] = {0};

// Get whether the number of user objects that are registered in the VPN Server is too many
bool SiTooManyUserObjectsInServer(SERVER *s, bool oneMore)
{
	return false;
}

typedef struct SI_DEBUG_PROC_LIST
{
	UINT Id;
	char *Description;
	char *Args;
	SI_DEBUG_PROC *Proc;
} SI_DEBUG_PROC_LIST;

// Debugging function
UINT SiDebug(SERVER *s, RPC_TEST *ret, UINT i, char *str)
{
	SI_DEBUG_PROC_LIST proc_list[] =
	{
		{1, "Hello World", "<test string>", SiDebugProcHelloWorld},
		{2, "Terminate process now", "", SiDebugProcExit},
		{3, "Write memory dumpfile", "", SiDebugProcDump},
		{4, "Restore process priority", "", SiDebugProcRestorePriority},
		{5, "Set the process priority high", "", SiDebugProcSetHighPriority},
		{6, "Get the .exe filename of the process", "", SiDebugProcGetExeFileName},
		{7, "Crash the process", "", SiDebugProcCrash},
		{8, "Get IPsecMessageDisplayed Flag", "", SiDebugProcGetIPsecMessageDisplayedValue},
		{9, "Set IPsecMessageDisplayed Flag", "", SiDebugProcSetIPsecMessageDisplayedValue},
		{10, "Get VgsMessageDisplayed Flag", "", SiDebugProcGetVgsMessageDisplayedValue},
		{11, "Set VgsMessageDisplayed Flag", "", SiDebugProcSetVgsMessageDisplayedValue},
		{12, "Get the current TCP send queue length", "", SiDebugProcGetCurrentTcpSendQueueLength},
		{13, "Get the current GetIP thread count", "", SiDebugProcGetCurrentGetIPThreadCount},
	};
	UINT num_proc_list = sizeof(proc_list) / sizeof(proc_list[0]);
	UINT j;
	UINT ret_value = ERR_NO_ERROR;
	// Validate arguments
	if (s == NULL || ret == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (i == 0)
	{
		char tmp[MAX_SIZE];
		Zero(ret, sizeof(RPC_TEST));

		StrCat(ret->StrValue, sizeof(ret->StrValue),
			"\n--- Debug Functions List --\n");

		for (j = 0;j < num_proc_list;j++)
		{
			SI_DEBUG_PROC_LIST *p = &proc_list[j];

			if (IsEmptyStr(p->Args) == false)
			{
				Format(tmp, sizeof(tmp),
					" %u: %s - Usage: %u /ARG:\"%s\"\n",
					p->Id, p->Description, p->Id, p->Args);
			}
			else
			{
				Format(tmp, sizeof(tmp),
					" %u: %s - Usage: %u\n",
					p->Id, p->Description, p->Id);
			}

			StrCat(ret->StrValue, sizeof(ret->StrValue), tmp);
		}
	}
	else
	{
		ret_value = ERR_NOT_SUPPORTED;

		for (j = 0;j < num_proc_list;j++)
		{
			SI_DEBUG_PROC_LIST *p = &proc_list[j];

			if (p->Id == i)
			{
				ret_value = p->Proc(s, str, ret->StrValue, sizeof(ret->StrValue));

				if (ret_value == ERR_NO_ERROR && IsEmptyStr(ret->StrValue))
				{
					StrCpy(ret->StrValue, sizeof(ret->StrValue), "Ok.");
				}
				break;
			}
		}
	}

	return ret_value;
}
UINT SiDebugProcHelloWorld(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Format(ret_str, ret_str_size, "Hello World %s\n", in_str);

	return ERR_NO_ERROR;
}
UINT SiDebugProcExit(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	_exit(1);

	return ERR_NO_ERROR;
}
UINT SiDebugProcDump(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

#ifdef	OS_WIN32
	MsWriteMinidump(NULL, NULL);
#else	// OS_WIN32
	return ERR_NOT_SUPPORTED;
#endif	// OS_WIN32

	return ERR_NO_ERROR;
}
UINT SiDebugProcRestorePriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	OSRestorePriority();

	return ERR_NO_ERROR;
}
UINT SiDebugProcSetHighPriority(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	OSSetHighPriority();

	return ERR_NO_ERROR;
}
UINT SiDebugProcGetExeFileName(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	GetExeName(ret_str, ret_str_size);

	return ERR_NO_ERROR;
}
UINT SiDebugProcCrash(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	CrashNow();

	return ERR_NO_ERROR;
}
UINT SiDebugProcGetIPsecMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ToStr(ret_str, s->IPsecMessageDisplayed);

	return ERR_NO_ERROR;
}
UINT SiDebugProcSetIPsecMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	s->IPsecMessageDisplayed = ToInt(in_str);

	return ERR_NO_ERROR;
}
UINT SiDebugProcGetVgsMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

#if	0
	if (VgDoNotPopupMessage() == false)
	{
		ToStr(ret_str, s->VgsMessageDisplayed);
	}
	else
	{
		ToStr(ret_str, 1);
	}
#else
	// Do not show the VGS message in VPN Server of the current version
	ToStr(ret_str, 1);
#endif	

	return ERR_NO_ERROR;
}
UINT SiDebugProcGetCurrentTcpSendQueueLength(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	char tmp1[64], tmp2[64], tmp3[64];
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ToStr3(tmp1, 0, CedarGetCurrentTcpQueueSize(s->Cedar));
	ToStr3(tmp2, 0, CedarGetQueueBudgetConsuming(s->Cedar));
	ToStr3(tmp3, 0, CedarGetFifoBudgetConsuming(s->Cedar));

	Format(ret_str, 0, 
		"CurrentTcpQueueSize  = %s\n"
		"QueueBudgetConsuming = %s\n"
		"FifoBudgetConsuming  = %s\n",
		tmp1, tmp2, tmp3);

	return ERR_NO_ERROR;
}
UINT SiDebugProcGetCurrentGetIPThreadCount(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	char tmp1[64], tmp2[64];
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ToStr3(tmp1, 0, GetCurrentGetIpThreadNum());
	ToStr3(tmp2, 0, GetGetIpThreadMaxNum());

	Format(ret_str, 0, 
		"Current threads = %s\n"
		"Quota           = %s\n",
		tmp1, tmp2);

	return ERR_NO_ERROR;
}
UINT SiDebugProcSetVgsMessageDisplayedValue(SERVER *s, char *in_str, char *ret_str, UINT ret_str_size)
{
	// Validate arguments
	if (s == NULL || in_str == NULL || ret_str == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}


	return ERR_NO_ERROR;
}

// Write the debug log
void SiDebugLog(SERVER *s, char *msg)
{
	// Validate arguments
	if (s == NULL || msg == NULL)
	{
		return;
	}

	if (s->DebugLog != NULL)
	{
		WriteTinyLog(s->DebugLog, msg);
	}
}

// Deadlock inspection main
void SiCheckDeadLockMain(SERVER *s, UINT timeout)
{
	CEDAR *cedar;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	//Debug("SiCheckDeadLockMain Start.\n");


	cedar = s->Cedar;

	if (s->ServerListenerList != NULL)
	{
		CheckDeadLock(s->ServerListenerList->lock, timeout, "s->ServerListenerList->lock");
	}

	CheckDeadLock(s->lock, timeout, "s->lock");

	if (s->FarmMemberList != NULL)
	{
		CheckDeadLock(s->FarmMemberList->lock, timeout, "s->FarmMemberList->lock");
	}

	if (s->HubCreateHistoryList != NULL)
	{
		CheckDeadLock(s->HubCreateHistoryList->lock, timeout, "s->HubCreateHistoryList->lock");
	}

	CheckDeadLock(s->CapsCacheLock, timeout, "s->CapsCacheLock");

	CheckDeadLock(s->TasksFromFarmControllerLock, timeout, "s->TasksFromFarmControllerLock");

	if (cedar != NULL)
	{
		if (cedar->HubList != NULL)
		{
			CheckDeadLock(cedar->HubList->lock, timeout, "cedar->HubList->lock");
		}

		if (cedar->ListenerList != NULL)
		{
			UINT i;
			LIST *o = NewListFast(NULL);

			CheckDeadLock(cedar->ListenerList->lock, timeout, "cedar->ListenerList->lock");

			LockList(cedar->ListenerList);
			{
				for (i = 0;i < LIST_NUM(cedar->ListenerList);i++)
				{
					LISTENER *r = LIST_DATA(cedar->ListenerList, i);

					AddRef(r->ref);

					Add(o, r);
				}
			}
			UnlockList(cedar->ListenerList);

			for (i = 0;i < LIST_NUM(o);i++)
			{
				LISTENER *r = LIST_DATA(o, i);


				ReleaseListener(r);
			}

			ReleaseList(o);
		}

		if (cedar->ConnectionList != NULL)
		{
			CheckDeadLock(cedar->ConnectionList->lock, timeout, "cedar->ConnectionList->lock");
		}

		if (cedar->CaList != NULL)
		{
			CheckDeadLock(cedar->CaList->lock, timeout, "cedar->CaList->lock");
		}

		if (cedar->TrafficLock != NULL)
		{
			CheckDeadLock(cedar->TrafficLock, timeout, "cedar->TrafficLock");
		}

		if (cedar->TrafficDiffList != NULL)
		{
			CheckDeadLock(cedar->TrafficDiffList->lock, timeout, "cedar->TrafficDiffList->lock");
		}

		if (cedar->LocalBridgeList != NULL)
		{
			CheckDeadLock(cedar->LocalBridgeList->lock, timeout, "cedar->LocalBridgeList->lock");
		}

		if (cedar->L3SwList != NULL)
		{
			CheckDeadLock(cedar->L3SwList->lock, timeout, "cedar->L3SwList->lock");
		}
	}

	//Debug("SiCheckDeadLockMain Finish.\n");
}

// Deadlock check thread
void SiDeadLockCheckThread(THREAD *t, void *param)
{
	SERVER *s = (SERVER *)param;
	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	while (true)
	{
		Wait(s->DeadLockWaitEvent, SERVER_DEADLOCK_CHECK_SPAN);

		if (s->HaltDeadLockThread)
		{
			break;
		}

		SiCheckDeadLockMain(s, SERVER_DEADLOCK_CHECK_TIMEOUT);
	}
}

// Initialize the deadlock check
void SiInitDeadLockCheck(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}
	if (s->DisableDeadLockCheck)
	{
		return;
	}

	s->HaltDeadLockThread = false;
	s->DeadLockWaitEvent = NewEvent();
	s->DeadLockCheckThread = NewThread(SiDeadLockCheckThread, s);
}

// Release the deadlock check
void SiFreeDeadLockCheck(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (s->DeadLockCheckThread == NULL)
	{
		return;
	}

	s->HaltDeadLockThread = true;
	Set(s->DeadLockWaitEvent);

	WaitThread(s->DeadLockCheckThread, INFINITE);

	ReleaseThread(s->DeadLockCheckThread);
	s->DeadLockCheckThread = NULL;

	ReleaseEvent(s->DeadLockWaitEvent);
	s->DeadLockWaitEvent = NULL;

	s->HaltDeadLockThread = false;
}

// Check whether the specified virtual HUB has been registered to creation history
bool SiIsHubRegistedOnCreateHistory(SERVER *s, char *name)
{
	UINT i;
	bool ret = false;
	// Validate arguments
	if (s == NULL || name == NULL)
	{
		return false;
	}

	SiDeleteOldHubCreateHistory(s);

	LockList(s->HubCreateHistoryList);
	{
		for (i = 0;i < LIST_NUM(s->HubCreateHistoryList);i++)
		{
			SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(s->HubCreateHistoryList, i);

			if (StrCmpi(h->HubName, name) == 0)
			{
				ret = true;
				break;
			}
		}
	}
	UnlockList(s->HubCreateHistoryList);

	return ret;
}

// Delete the Virtual HUB creation history
void SiDelHubCreateHistory(SERVER *s, char *name)
{
	UINT i;
	// Validate arguments
	if (s == NULL || name == NULL)
	{
		return;
	}

	LockList(s->HubCreateHistoryList);
	{
		SERVER_HUB_CREATE_HISTORY *hh = NULL;
		for (i = 0;i < LIST_NUM(s->HubCreateHistoryList);i++)
		{
			SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(s->HubCreateHistoryList, i);

			if (StrCmpi(h->HubName, name) == 0)
			{
				Delete(s->HubCreateHistoryList, h);
				Free(h);
				break;
			}
		}
	}
	UnlockList(s->HubCreateHistoryList);

	SiDeleteOldHubCreateHistory(s);
}

// Register to the Virtual HUB creation history
void SiAddHubCreateHistory(SERVER *s, char *name)
{
	UINT i;
	// Validate arguments
	if (s == NULL || name == NULL)
	{
		return;
	}

	LockList(s->HubCreateHistoryList);
	{
		SERVER_HUB_CREATE_HISTORY *hh = NULL;
		for (i = 0;i < LIST_NUM(s->HubCreateHistoryList);i++)
		{
			SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(s->HubCreateHistoryList, i);

			if (StrCmpi(h->HubName, name) == 0)
			{
				hh = h;
				break;
			}
		}

		if (hh == NULL)
		{
			hh = ZeroMalloc(sizeof(SERVER_HUB_CREATE_HISTORY));
			StrCpy(hh->HubName, sizeof(hh->HubName), name);

			Add(s->HubCreateHistoryList, hh);
		}

		hh->CreatedTime = Tick64();
	}
	UnlockList(s->HubCreateHistoryList);

	SiDeleteOldHubCreateHistory(s);
}

// Delete outdated Virtual HUB creation histories
void SiDeleteOldHubCreateHistory(SERVER *s)
{
	UINT i;
	LIST *o;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	LockList(s->HubCreateHistoryList);
	{
		o = NewListFast(NULL);

		for (i = 0;i < LIST_NUM(s->HubCreateHistoryList);i++)
		{
			SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(s->HubCreateHistoryList, i);

			if ((h->CreatedTime + ((UINT64)TICKET_EXPIRES)) <= Tick64())
			{
				// Expired
				Add(o, h);
			}
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(o, i);

			Delete(s->HubCreateHistoryList, h);

			Free(h);
		}

		ReleaseList(o);
	}
	UnlockList(s->HubCreateHistoryList);
}

// Initialize the Virtual HUB creation history
void SiInitHubCreateHistory(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->HubCreateHistoryList = NewList(NULL);
}

// Release the Virtual HUB creation history
void SiFreeHubCreateHistory(SERVER *s)
{
	UINT i;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(s->HubCreateHistoryList);i++)
	{
		SERVER_HUB_CREATE_HISTORY *h = LIST_DATA(s->HubCreateHistoryList, i);

		Free(h);
	}

	ReleaseList(s->HubCreateHistoryList);

	s->HubCreateHistoryList = NULL;
}

// Identify whether the server can be connected from the VPN Client that is
// created by the installer creating kit of Admin Pack
bool IsAdminPackSupportedServerProduct(char *name)
{
	return true;
}


// Get the saving status of syslog
UINT SiGetSysLogSaveStatus(SERVER *s)
{
	SYSLOG_SETTING set;
	// Validate arguments
	if (s == NULL)
	{
		return SYSLOG_NONE;
	}

	SiGetSysLogSetting(s, &set);

	return set.SaveType;
}

// Send a syslog
void SiWriteSysLog(SERVER *s, char *typestr, char *hubname, wchar_t *message)
{
	wchar_t tmp[1024];
	char machinename[MAX_HOST_NAME_LEN + 1];
	char datetime[MAX_PATH];
	SYSTEMTIME st;
	// Validate arguments
	if (s == NULL || typestr == NULL || message == NULL)
	{
		return;
	}

	if (GetGlobalServerFlag(GSF_DISABLE_SYSLOG) != 0)
	{
		return;
	}

	// Host name
	GetMachineName(machinename, sizeof(machinename));

	// Date and time
	LocalTime(&st);
	if(s->StrictSyslogDatetimeFormat){
		GetDateTimeStrRFC3339(datetime, sizeof(datetime), &st, GetCurrentTimezone());
	}else{
		GetDateTimeStrMilli(datetime, sizeof(datetime), &st);
	}

	if (IsEmptyStr(hubname) == false)
	{
		UniFormat(tmp, sizeof(tmp), L"[%S/VPN/%S] (%S) <%S>: %s",
			machinename, hubname, datetime, typestr, message);
	}
	else
	{
		UniFormat(tmp, sizeof(tmp), L"[%S/VPN] (%S) <%S>: %s",
			machinename, datetime, typestr, message);
	}

	Debug("Syslog send: %S\n",tmp);

	SendSysLog(s->Syslog, tmp);
}

// Write the syslog configuration
void SiSetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting)
{
	SYSLOG_SETTING set;
	// Validate arguments
	if (s == NULL || setting == NULL)
	{
		return;
	}

	Zero(&set, sizeof(set));
	Copy(&set, setting, sizeof(SYSLOG_SETTING));

	if (IsEmptyStr(set.Hostname) || set.Port == 0)
	{
		set.SaveType = SYSLOG_NONE;
	}

	Lock(s->SyslogLock);
	{
		Copy(&s->SyslogSetting, &set, sizeof(SYSLOG_SETTING));

		SetSysLog(s->Syslog, set.Hostname, set.Port);
	}
	Unlock(s->SyslogLock);
}

// Read the syslog configuration
void SiGetSysLogSetting(SERVER *s, SYSLOG_SETTING *setting)
{
	// Validate arguments
	if (s == NULL || setting == NULL)
	{
		return;
	}

	//Lock(s->SyslogLock);
	{
		Copy(setting, &s->SyslogSetting, sizeof(SYSLOG_SETTING));
	}
	//Unlock(s->SyslogLock);
}


// Get the server product name
void GetServerProductName(SERVER *s, char *name, UINT size)
{
	char *cpu;
	// Validate arguments
	if (s == NULL || name == NULL)
	{
		return;
	}

	GetServerProductNameInternal(s, name, size);

#ifdef	CPU_64
	cpu = " (64 bit)";
#else	// CPU_64
	cpu = " (32 bit)";
#endif	// CPU_64

	StrCat(name, size, cpu);

	StrCat(name, size, " (Open Source)");
}
void GetServerProductNameInternal(SERVER *s, char *name, UINT size)
{
	// Validate arguments
	if (s == NULL || name == NULL)
	{
		return;
	}

#ifdef	BETA_NUMBER
	if (s->Cedar->Bridge)
	{
		StrCpy(name, size, CEDAR_BRIDGE_STR);
	}
	else
	{
		StrCpy(name, size, CEDAR_BETA_SERVER);
	}
	return;
#else	// BETA_NUMBER
	if (s->Cedar->Bridge)
	{
		StrCpy(name, size, CEDAR_BRIDGE_STR);
	}
	else
	{
		StrCpy(name, size, CEDAR_SERVER_STR);
	}
#endif	// BETA_NUMBER
}

// Check whether the log file with the specified name is contained in the enumerated list
bool CheckLogFileNameFromEnumList(LIST *o, char *name, char *server_name)
{
	LOG_FILE t;
	// Validate arguments
	if (o == NULL || name == NULL || server_name == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.Path, sizeof(t.Path), name);
	StrCpy(t.ServerName, sizeof(t.ServerName), server_name);

	if (Search(o, &t) == NULL)
	{
		return false;
	}

	return true;
}

// Release the log file enumeration
void FreeEnumLogFile(LIST *o)
{
	UINT i;
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LOG_FILE *f = LIST_DATA(o, i);

		Free(f);
	}

	ReleaseList(o);
}

// Enumerate the log files associated with the virtual HUB (All logs are listed in the case of server administrator)
LIST *EnumLogFile(char *hubname)
{
	char exe_dir[MAX_PATH];
	char tmp[MAX_PATH];
	LIST *o = NewListFast(CmpLogFile);
	DIRLIST *dir;

	if (StrLen(hubname) == 0)
	{
		hubname = NULL;
	}

	GetLogDir(exe_dir, sizeof(exe_dir));

	// Enumerate in the server_log
	if (hubname == NULL)
	{
		EnumLogFileDir(o, SERVER_LOG_DIR);
	}

	// Enumerate in the packet_log
	Format(tmp, sizeof(tmp), "%s/"HUB_PACKET_LOG_DIR, exe_dir);

	if (hubname == NULL)
	{
		dir = EnumDir(tmp);
		if (dir != NULL)
		{
			UINT i;
			for (i = 0;i < dir->NumFiles;i++)
			{
				DIRENT *e = dir->File[i];

				if (e->Folder)
				{
					char dir_name[MAX_PATH];
					Format(dir_name, sizeof(dir_name), HUB_PACKET_LOG_DIR"/%s", e->FileName);
					EnumLogFileDir(o, dir_name);
				}
			}

			FreeDir(dir);
		}
	}
	else
	{
		char dir_name[MAX_PATH];

		Format(dir_name, sizeof(dir_name), HUB_PACKET_LOG_DIR"/%s", hubname);

		EnumLogFileDir(o, dir_name);
	}

	// Enumerate in the security_log
	Format(tmp, sizeof(tmp), "%s/"HUB_SECURITY_LOG_DIR, exe_dir);

	if (hubname == NULL)
	{
		dir = EnumDir(tmp);
		if (dir != NULL)
		{
			UINT i;
			for (i = 0;i < dir->NumFiles;i++)
			{
				DIRENT *e = dir->File[i];

				if (e->Folder)
				{
					char dir_name[MAX_PATH];

					Format(dir_name, sizeof(dir_name), HUB_SECURITY_LOG_DIR"/%s", e->FileName);

					EnumLogFileDir(o, dir_name);
				}
			}

			FreeDir(dir);
		}
	}
	else
	{
		char dir_name[MAX_PATH];

		Format(dir_name, sizeof(dir_name), HUB_SECURITY_LOG_DIR"/%s", hubname);

		EnumLogFileDir(o, dir_name);
	}

	return o;
}

// Enumerate log files in the specified directory
void EnumLogFileDir(LIST *o, char *dirname)
{
	UINT i;
	char exe_dir[MAX_PATH];
	char dir_full_path[MAX_PATH];
	DIRLIST *dir;
	// Validate arguments
	if (o == NULL || dirname == NULL)
	{
		return;
	}

	GetLogDir(exe_dir, sizeof(exe_dir));
	Format(dir_full_path, sizeof(dir_full_path), "%s/%s", exe_dir, dirname);

	dir = EnumDir(dir_full_path);
	if (dir == NULL)
	{
		return;
	}

	for (i = 0;i < dir->NumFiles;i++)
	{
		DIRENT *e = dir->File[i];

		if (e->Folder == false && e->FileSize > 0)
		{
			char full_path[MAX_PATH];
			char file_path[MAX_PATH];

			Format(file_path, sizeof(file_path), "%s/%s", dirname, e->FileName);
			Format(full_path, sizeof(full_path), "%s/%s", exe_dir, file_path);

			if (EndWith(file_path, ".log"))
			{
				LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

				StrCpy(f->Path, sizeof(f->Path), file_path);
				f->FileSize = (UINT)(MIN(e->FileSize, 0xffffffffUL));
				f->UpdatedTime = e->UpdateDate;

				GetMachineName(f->ServerName, sizeof(f->ServerName));

				Insert(o, f);
			}
		}
	}

	FreeDir(dir);
}

// Log file list entry comparison
int CmpLogFile(void *p1, void *p2)
{
	LOG_FILE *f1, *f2;
	UINT i;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(LOG_FILE **)p1;
	f2 = *(LOG_FILE **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}

	i = StrCmpi(f1->Path, f2->Path);
	if (i != 0)
	{
		return i;
	}

	return StrCmpi(f1->ServerName, f2->ServerName);
}

// Get the Caps of the server
UINT GetServerCapsInt(SERVER *s, char *name)
{
	CAPSLIST t;
	UINT ret;
	// Validate arguments
	if (s == NULL || name == NULL)
	{
		return 0;
	}

	Zero(&t, sizeof(t));
	GetServerCaps(s, &t);

	ret = GetCapsInt(&t, name);

	return ret;
}
bool GetServerCapsBool(SERVER *s, char *name)
{
	return (GetServerCapsInt(s, name) == 0) ? false : true;
}

// Initialize the Caps cache of the server
void InitServerCapsCache(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->CapsCacheLock = NewLock();
	s->CapsListCache = NULL;
}

// Release the Caps cache of the server
void FreeServerCapsCache(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (s->CapsListCache != NULL)
	{
		FreeCapsList(s->CapsListCache);
		s->CapsListCache = NULL;
	}
	DeleteLock(s->CapsCacheLock);
}

// Dispose the Caps cache of the server
void DestroyServerCapsCache(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Lock(s->CapsCacheLock);
	{
		if (s->CapsListCache != NULL)
		{
			FreeCapsList(s->CapsListCache);
			s->CapsListCache = NULL;
		}
	}
	Unlock(s->CapsCacheLock);
}

// Flush the Caps list for this server
void FlushServerCaps(SERVER *s)
{
	CAPSLIST t;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	DestroyServerCapsCache(s);

	Zero(&t, sizeof(t));
	GetServerCaps(s, &t);
}

// Get the Caps list for this server
void GetServerCaps(SERVER *s, CAPSLIST *t)
{
	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	Lock(s->CapsCacheLock);
	{

		if (s->CapsListCache == NULL)
		{
			s->CapsListCache = ZeroMalloc(sizeof(CAPSLIST));
			GetServerCapsMain(s, s->CapsListCache);
		}

		Copy(t, s->CapsListCache, sizeof(CAPSLIST));
	}
	Unlock(s->CapsCacheLock);
}

// Update the global server flags
void UpdateGlobalServerFlags(SERVER *s, CAPSLIST *t)
{
	bool is_restricted = false;
	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	is_restricted = SiIsEnterpriseFunctionsRestrictedOnOpenSource(s->Cedar);

	SetGlobalServerFlag(GSF_DISABLE_PUSH_ROUTE, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_CERT_AUTH, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_DEEP_LOGGING, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_AC, is_restricted);
	SetGlobalServerFlag(GSF_DISABLE_SYSLOG, is_restricted);
}

// Set a global server flag
void SetGlobalServerFlag(UINT index, UINT value)
{
	// Validate arguments
	if (index >= NUM_GLOBAL_SERVER_FLAGS)
	{
		return;
	}

	global_server_flags[index] = value;
}

// Get a global server flag
UINT GetGlobalServerFlag(UINT index)
{
	// Validate arguments
	if (index >= NUM_GLOBAL_SERVER_FLAGS)
	{
		return 0;
	}

	return global_server_flags[index];
}

// Main of the acquisition of Caps of the server
void GetServerCapsMain(SERVER *s, CAPSLIST *t)
{
	bool is_restricted = false;

	// Validate arguments
	if (s == NULL || t == NULL)
	{
		return;
	}

	is_restricted = SiIsEnterpriseFunctionsRestrictedOnOpenSource(s->Cedar);

	// Initialize
	InitCapsList(t);

	// Maximum Ethernet packet size
	AddCapsInt(t, "i_max_packet_size", MAX_PACKET_SIZE);

	if (s->Cedar->Bridge == false)
	{
		UINT max_sessions, max_clients, max_bridges, max_user_creations;

		max_clients = INFINITE;
		max_bridges = INFINITE;
		max_sessions = SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION;
		max_user_creations = INFINITE;

		// Maximum number of virtual HUBs
		AddCapsInt(t, "i_max_hubs", SERVER_MAX_SESSIONS_FOR_CARRIER_EDITION);

		// The maximum number of concurrent sessions
		AddCapsInt(t, "i_max_sessions", max_sessions);

		// Maximum number of creatable users
		AddCapsInt(t, "i_max_user_creation", max_user_creations);

		// Maximum number of clients
		AddCapsInt(t, "i_max_clients", max_clients);

		// Maximum number of bridges
		AddCapsInt(t, "i_max_bridges", max_bridges);

		if (s->ServerType != SERVER_TYPE_FARM_MEMBER)
		{
			// Maximum number of registrable users / Virtual HUB
			AddCapsInt(t, "i_max_users_per_hub", MAX_USERS);

			// Maximum number of registrable groups / Virtual HUB
			AddCapsInt(t, "i_max_groups_per_hub", MAX_GROUPS);

			// Maximum number of registrable access list entries / Virtual HUB
			AddCapsInt(t, "i_max_access_lists", MAX_ACCESSLISTS);
		}
		else
		{
			// Maximum number of registrable users / Virtual HUB
			AddCapsInt(t, "i_max_users_per_hub", 0);

			// Maximum number of registrable groups / Virtual HUB
			AddCapsInt(t, "i_max_groups_per_hub", 0);

			// Maximum number of registrable access list entries / Virtual HUB
			AddCapsInt(t, "i_max_access_lists", 0);
		}

		// The policy related to multiple logins
		AddCapsBool(t, "b_support_limit_multilogin", true);

		// QoS / VoIP
		AddCapsBool(t, "b_support_qos", true);

		// syslog
		AddCapsBool(t, "b_support_syslog", true);

		// IPsec
		// (Only works in stand-alone mode currently)
		AddCapsBool(t, "b_support_ipsec", (s->ServerType == SERVER_TYPE_STANDALONE));

		// SSTP
		// (Only works in stand-alone mode currently)
		AddCapsBool(t, "b_support_sstp", (s->ServerType == SERVER_TYPE_STANDALONE));

		// OpenVPN
		// (Only works in stand-alone mode currently)
		AddCapsBool(t, "b_support_openvpn", (s->ServerType == SERVER_TYPE_STANDALONE));

		// DDNS
		AddCapsBool(t, "b_support_ddns", (s->DDnsClient != NULL));

		if (s->DDnsClient != NULL)
		{
			// DDNS via Proxy
			AddCapsBool(t, "b_support_ddns_proxy", true);
		}

		// VPN over ICMP, VPN over DNS
		AddCapsBool(t, "b_support_special_listener", true);
	}
	else
	{
		// Maximum number of virtual HUBs
		AddCapsInt(t, "i_max_hubs", 0);

		// The maximum number of concurrent sessions
		AddCapsInt(t, "i_max_sessions", 0);

		// Maximum number of clients
		AddCapsInt(t, "i_max_clients", 0);

		// Maximum number of bridges
		AddCapsInt(t, "i_max_bridges", 0);

		// Maximum number of registrable users / Virtual HUB
		AddCapsInt(t, "i_max_users_per_hub", 0);

		// Maximum number of registrable groups / Virtual HUB
		AddCapsInt(t, "i_max_groups_per_hub", 0);

		// Maximum number of registrable access list entries / Virtual HUB
		AddCapsInt(t, "i_max_access_lists", 0);

		// QoS / VoIP
		AddCapsBool(t, "b_support_qos", true);

		// syslog
		AddCapsBool(t, "b_support_syslog", true);

		// IPsec
		AddCapsBool(t, "b_support_ipsec", false);

		// SSTP
		AddCapsBool(t, "b_support_sstp", false);

		// OpenVPN
		AddCapsBool(t, "b_support_openvpn", false);

		// DDNS
		AddCapsBool(t, "b_support_ddns", false);

		// VPN over ICMP, VPN over DNS
		AddCapsBool(t, "b_support_special_listener", false);
	}

	// Changing the type of Virtual HUB in cluster is prohibited
	AddCapsBool(t, "b_cluster_hub_type_fixed", true);

	// Maximum MAC address table  size / Virtual HUB
	AddCapsInt(t, "i_max_mac_tables", MAX_MAC_TABLES);

	// Maximum IP address table  size / Virtual HUB
	AddCapsInt(t, "i_max_ip_tables", MAX_IP_TABLES);

	// SecureNAT function is available
	AddCapsBool(t, "b_support_securenat", true);

	// Pushing routing table function of SecureNAT Virtual DHCP Server is available
	AddCapsBool(t, "b_suppport_push_route", !is_restricted);
	AddCapsBool(t, "b_suppport_push_route_config", true);

	if (s->ServerType != SERVER_TYPE_STANDALONE)
	{
		AddCapsBool(t, "b_virtual_nat_disabled", true);
	}

	// Maximum NAT table size / Virtual HUB
	AddCapsInt(t, "i_max_secnat_tables", NAT_MAX_SESSIONS);

	// Cascade connection
	if (s->ServerType == SERVER_TYPE_STANDALONE)
	{
		AddCapsBool(t, "b_support_cascade", true);
	}
	else
	{
		AddCapsBool(t, "b_support_cascade", false);
	}

	if (s->Cedar->Bridge)
	{
		// Bridge mode
		AddCapsBool(t, "b_bridge", true);
	}
	else if (s->ServerType == SERVER_TYPE_STANDALONE)
	{
		// Stand-alone mode
		AddCapsBool(t, "b_standalone", true);
	}
	else if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// Cluster controller mode
		AddCapsBool(t, "b_cluster_controller", true);
	}
	else
	{
		// Cluster member mode
		AddCapsBool(t, "b_cluster_member", true);
	}

	// Virtual HUB is modifiable
	AddCapsBool(t, "b_support_config_hub", s->ServerType != SERVER_TYPE_FARM_MEMBER &&
		s->Cedar->Bridge == false);

	// VPN client can be connected
	AddCapsBool(t, "b_vpn_client_connect", s->Cedar->Bridge == false ? true : false);

	// External authentication server is available
	AddCapsBool(t, "b_support_radius", s->ServerType != SERVER_TYPE_FARM_MEMBER &&
		s->Cedar->Bridge == false);

	// Local-bridge function is available
	AddCapsBool(t, "b_local_bridge", IsBridgeSupported());

	if (OS_IS_WINDOWS(GetOsInfo()->OsType))
	{
		// Packet capture driver is not installed
		AddCapsBool(t, "b_must_install_pcap", IsEthSupported() == false ? true : false);
	}
	else
	{
		// Regard that the driver is installed in the Linux version
		AddCapsBool(t, "b_must_install_pcap", false);
	}

	if (IsBridgeSupported())
	{
		// TUN / TAP device availability (Linux and BSD)
		const UINT OsType = GetOsInfo()->OsType;
		AddCapsBool(t, "b_tap_supported", OsType == OSTYPE_LINUX || OsType == OSTYPE_BSD);
	}

	// Cascade connection
	if (s->ServerType == SERVER_TYPE_STANDALONE)
	{
		AddCapsBool(t, "b_support_cascade", true);
	}
	else
	{
		AddCapsBool(t, "b_support_cascade", false);
	}

	// Server authentication can be used in cascade connection
	AddCapsBool(t, "b_support_cascade_cert", true);

	//  the log file settings is modifiable
	AddCapsBool(t, "b_support_config_log", s->ServerType != SERVER_TYPE_FARM_MEMBER);

	// Automatic deletion of log file is available
	AddCapsBool(t, "b_support_autodelete", true);

	// Config file operation is available
	AddCapsBool(t, "b_support_config_rw", true);

	// Attribute of each Virtual HUB can be set
	AddCapsBool(t, "b_support_hub_admin_option", true);

	// Client certificate can be set in a cascade connection
	AddCapsBool(t, "b_support_cascade_client_cert", true);

	// Virtual HUB can be hidden
	AddCapsBool(t, "b_support_hide_hub", true);

	// Integrated management
	AddCapsBool(t, "b_support_cluster_admin", true);

	// Flag of open-source version
	AddCapsBool(t, "b_is_softether", true);

	if (s->Cedar->Bridge == false)
	{

		// The virtual layer 3 switch function is available
		AddCapsBool(t, "b_support_layer3", true);

		AddCapsInt(t, "i_max_l3_sw", MAX_NUM_L3_SWITCH);
		AddCapsInt(t, "i_max_l3_if", MAX_NUM_L3_IF);
		AddCapsInt(t, "i_max_l3_table", MAX_NUM_L3_TABLE);

		// Can act as a part of a cluster
		AddCapsBool(t, "b_support_cluster", true);
	}
	else
	{
		AddCapsBool(t, "b_support_layer3", false);

		AddCapsInt(t, "i_max_l3_sw", 0);
		AddCapsInt(t, "i_max_l3_if", 0);
		AddCapsInt(t, "i_max_l3_table", 0);

		AddCapsBool(t, "b_support_cluster", false);
	}

	if (s->ServerType != SERVER_TYPE_FARM_MEMBER && s->Cedar->Bridge == false)
	{
		// Support for CRL
		AddCapsBool(t, "b_support_crl", true);

		// Supports AC
		AddCapsBool(t, "b_support_ac", true);
	}

	// Supports downloading a log file
	AddCapsBool(t, "b_support_read_log", true);

	// Cascade connection can be renamed
	AddCapsBool(t, "b_support_rename_cascade", true);


	if (s->Cedar->Beta)
	{
		// Beta version
		AddCapsBool(t, "b_beta_version", true);
	}

	// VM discrimination
	AddCapsBool(t, "b_is_in_vm", s->IsInVm);

	// Support for display name of the network connection for the local bridge
#ifdef	OS_WIN32
	if (IsBridgeSupported() && IsNt() && GetOsInfo()->OsType >= OSTYPE_WINDOWS_2000_PROFESSIONAL)
	{
		AddCapsBool(t, "b_support_network_connection_name", true);
	}
#else	// OS_WIN32
	if (IsBridgeSupported() && EthIsInterfaceDescriptionSupportedUnix())
	{
		AddCapsBool(t, "b_support_network_connection_name", true);
	}
#endif	// OS_WIN32

	// Support for MAC address filtering
	AddCapsBool(t, "b_support_check_mac", true);

	// Support for status check of the TCP connection
	AddCapsBool(t, "b_support_check_tcp_state", true);

	// Can specify multiple server and retry intervals in Radius authentication
	AddCapsBool(t, "b_support_radius_retry_interval_and_several_servers", s->ServerType != SERVER_TYPE_FARM_MEMBER &&
		s->Cedar->Bridge == false);

	// Can manage the ID of the tagged VLAN in the MAC address table
	AddCapsBool(t, "b_support_vlan", true);

	// Support for Virtual HUB extended options
	if ((s->Cedar->Bridge == false) &&
		(s->ServerType == SERVER_TYPE_STANDALONE || s->ServerType == SERVER_TYPE_FARM_CONTROLLER))
	{
		AddCapsBool(t, "b_support_hub_ext_options", true);
	}
	else
	{
		AddCapsBool(t, "b_support_hub_ext_options", false);
	}

	// Support for Security Policy version 3.0
	AddCapsBool(t, "b_support_policy_ver_3", true);

	// Support for IPv6 access list
	AddCapsBool(t, "b_support_ipv6_acl", true);

	// Support for setting of delay, jitter and packet loss in the access list
	AddCapsBool(t, "b_support_ex_acl", true);

	// Support for URL redirection in the access list
	AddCapsBool(t, "b_support_redirect_url_acl", true);

	// Supports the specification by the group name in the access list
	AddCapsBool(t, "b_support_acl_group", true);

	// Support for IPv6 in connection source IP restriction list
	AddCapsBool(t, "b_support_ipv6_ac", true);

	// Support for VLAN tagged packet transmission configuration tool
	AddCapsBool(t, "b_support_eth_vlan", (OS_IS_WINDOWS_NT(GetOsType()) && GET_KETA(GetOsType(), 100) >= 2));

	// Support for the message display function when the VPN connect to the Virtual HUB
	AddCapsBool(t, "b_support_msg", true);

	// UDP acceleration feature
	AddCapsBool(t, "b_support_udp_acceleration", true);

	// AES acceleration function
	AddCapsBool(t, "b_support_aes_ni", IsAesNiSupported());

#ifdef	OS_WIN32
	// SeLow driver
	AddCapsBool(t, "b_using_selow_driver", Win32IsUsingSeLow());
#endif	// OS_WIN32

	// VPN Azure function
	AddCapsBool(t, "b_support_azure", SiIsAzureSupported(s));

	// VPN3
	AddCapsBool(t, "b_vpn3", true);

	// VPN4
	AddCapsBool(t, "b_vpn4", true);


	UpdateGlobalServerFlags(s, t);
}

// SYSLOG_SETTING
void InRpcSysLogSetting(SYSLOG_SETTING *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(SYSLOG_SETTING));
	t->SaveType = PackGetInt(p, "SaveType");
	t->Port = PackGetInt(p, "Port");
	PackGetStr(p, "Hostname", t->Hostname, sizeof(t->Hostname));
}
void OutRpcSysLogSetting(PACK *p, SYSLOG_SETTING *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "SaveType", t->SaveType);
	PackAddInt(p, "Port", t->Port);
	PackAddStr(p, "Hostname", t->Hostname);
}

// CAPSLIST
void InitCapsList(CAPSLIST *t)
{
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	Zero(t, sizeof(CAPSLIST));
	t->CapsList = NewListFast(NULL);
}
void InRpcCapsList(CAPSLIST *t, PACK *p)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(CAPSLIST));
	t->CapsList = NewListFast(CompareCaps);

	for (i = 0;i < LIST_NUM(p->elements);i++)
	{
		ELEMENT *e = LIST_DATA(p->elements, i);

		if (StartWith(e->name, "caps_") && e->type == VALUE_INT && e->num_value == 1)
		{
			CAPS *c = NewCaps(e->name + 5, e->values[0]->IntValue);
			Insert(t->CapsList, c);
		}
	}
}
void OutRpcCapsList(PACK *p, CAPSLIST *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackSetCurrentJsonGroupName(p, "CapsList");
	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		char tmp[MAX_SIZE];
		char ct_key[MAX_PATH];
		wchar_t ct_description[MAX_PATH];
		wchar_t *w;
		CAPS *c = LIST_DATA(t->CapsList, i);

		Format(tmp, sizeof(tmp), "caps_%s", c->Name);

		Format(ct_key, sizeof(ct_key), "CT_%s", c->Name);

		Zero(ct_description, sizeof(ct_description));
		w = _UU(ct_key);
		if (UniIsEmptyStr(w) == false)
		{
			UniStrCpy(ct_description, sizeof(ct_description), w);
		}
		else
		{
			StrToUni(ct_description, sizeof(ct_description), c->Name);
		}

		PackAddInt(p, tmp, c->Value);

		PackAddStrEx(p, "CapsName", c->Name, i, LIST_NUM(t->CapsList));
		PackAddIntEx(p, "CapsValue", c->Value, i, LIST_NUM(t->CapsList));
		PackAddUniStrEx(p, "CapsDescrption", ct_description, i, LIST_NUM(t->CapsList));
	}
	PackSetCurrentJsonGroupName(p, NULL);
}
void FreeRpcCapsList(CAPSLIST *t)
{
	UINT i;
	// Validate arguments
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		CAPS *c = LIST_DATA(t->CapsList, i);

		FreeCaps(c);
	}

	ReleaseList(t->CapsList);
}

// Add a bool type to Caps list
void AddCapsBool(CAPSLIST *caps, char *name, bool b)
{
	CAPS *c;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return;
	}

	c = NewCaps(name, b == false ? 0 : 1);
	AddCaps(caps, c);
}

// Add the int type to Caps list
void AddCapsInt(CAPSLIST *caps, char *name, UINT i)
{
	CAPS *c;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return;
	}

	c = NewCaps(name, i);
	AddCaps(caps, c);
}

// Get the int type from the Caps list
UINT GetCapsInt(CAPSLIST *caps, char *name)
{
	CAPS *c;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return 0;
	}

	c = GetCaps(caps, name);
	if (c == NULL)
	{
		return 0;
	}

	return c->Value;
}

// Get bool type from the Caps list
bool GetCapsBool(CAPSLIST *caps, char *name)
{
	CAPS *c;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return false;
	}

	c = GetCaps(caps, name);
	if (c == NULL)
	{
		return false;
	}

	return c->Value == 0 ? false : true;
}

// Release the Caps list
void FreeCapsList(CAPSLIST *caps)
{
	UINT i;
	// Validate arguments
	if (caps == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(caps->CapsList);i++)
	{
		CAPS *c = LIST_DATA(caps->CapsList, i);

		FreeCaps(c);
	}

	ReleaseList(caps->CapsList);
	Free(caps);
}

// Get the Caps
CAPS *GetCaps(CAPSLIST *caps, char *name)
{
	UINT i;
	// Validate arguments
	if (caps == NULL || name == NULL)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(caps->CapsList);i++)
	{
		CAPS *c = LIST_DATA(caps->CapsList, i);

		if (StrCmpi(c->Name, name) == 0)
		{
			return c;
		}
	}

	return NULL;
}

// Add to the Caps
void AddCaps(CAPSLIST *caps, CAPS *c)
{
	// Validate arguments
	if (caps == NULL || c == NULL)
	{
		return;
	}

	Insert(caps->CapsList, c);
}

// Comparison of Caps
int CompareCaps(void *p1, void *p2)
{
	CAPS *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(CAPS **)p1;
	c2 = *(CAPS **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return StrCmpi(c1->Name, c2->Name);
}

// Create a Caps list
CAPSLIST *NewCapsList()
{
	CAPSLIST *caps = ZeroMalloc(sizeof(CAPSLIST));

	caps->CapsList = NewListFast(CompareCaps);

	return caps;
}

// Release the Caps
void FreeCaps(CAPS *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	Free(c->Name);
	Free(c);
}

// Create a Caps
CAPS *NewCaps(char *name, UINT value)
{
	CAPS *c;
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CAPS));
	c->Name = CopyStr(name);
	c->Value = value;

	return c;
}

// Calculate the score from the current number of connections and weight
UINT SiCalcPoint(SERVER *s, UINT num, UINT weight)
{
	UINT server_max_sessions = SERVER_MAX_SESSIONS;
	if (s == NULL)
	{
		return 0;
	}
	if (weight == 0)
	{
		weight = 100;
	}

	server_max_sessions = GetServerCapsInt(s, "i_max_sessions");

	if (server_max_sessions == 0)
	{
		// Avoid divide by zero
		server_max_sessions = 1;
	}

	return (UINT)(((double)server_max_sessions -
		MIN((double)num * 100.0 / (double)weight, (double)server_max_sessions))
		* (double)FARM_BASE_POINT / (double)server_max_sessions);
}

// Get the server score
UINT SiGetPoint(SERVER *s)
{
	UINT num_session;
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	num_session = Count(s->Cedar->CurrentSessions);

	return SiCalcPoint(s, num_session, s->Weight);
}

// Generate the default certificate
void SiGenerateDefaultCert(X **server_x, K **server_k)
{
	SiGenerateDefaultCertEx(server_x, server_k, NULL);
}
void SiGenerateDefaultCertEx(X **server_x, K **server_k, char *common_name)
{
	X *x;
	K *private_key, *public_key;
	NAME *name;
	char tmp[MAX_SIZE];
	wchar_t cn[MAX_SIZE];
	// Validate arguments
	if (server_x == NULL || server_k == NULL)
	{
		return;
	}

	// Create a key pair
	RsaGen(&private_key, &public_key, 2048);

	if (IsEmptyStr(common_name))
	{
		// Get the host name
		StrCpy(tmp, sizeof(tmp), "server.softether.vpn");
		GetMachineName(tmp, sizeof(tmp));
		StrToUni(cn, sizeof(cn), tmp);
	}
	else
	{
		StrToUni(cn, sizeof(cn), common_name);
	}

	name = NewName(cn, cn, cn,
		L"US", NULL, NULL);
	x = NewRootX(public_key, private_key, name, GetDaysUntil2038Ex(), NULL);

	*server_x = x;
	*server_k = private_key;

	FreeName(name);

	FreeK(public_key);
}

// Set the server certificate to default
void SiInitDefaultServerCert(SERVER *s)
{
	X *x = NULL;
	K *k = NULL;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Generate a server certificate and private key
	SiGenerateDefaultCert(&x, &k);

	// Configure
	SetCedarCert(s->Cedar, x, k);

	FreeX(x);
	FreeK(k);
}

// Set the encryption algorithm name to default
void SiInitCipherName(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	SetCedarCipherList(s->Cedar, SERVER_DEFAULT_CIPHER_NAME);
}

// Initialize the listener list
void SiInitListenerList(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	SiLockListenerList(s);
	{
		{
			// Register the 4 ports (443, 992, 1194, 8888) as the default port
			SiAddListener(s, SERVER_DEF_PORTS_1, true);
			SiAddListener(s, SERVER_DEF_PORTS_2, true);
			SiAddListener(s, SERVER_DEF_PORTS_3, true);
			SiAddListener(s, SERVER_DEF_PORTS_4, true);
		}
	}
	SiUnlockListenerList(s);
}

// Remove the listener
bool SiDeleteListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	// Validate arguments
	if (s == NULL || port == 0)
	{
		return false;
	}

	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	// Stop if still alive
	SiDisableListener(s, port);

	if (e->Listener != NULL)
	{
		ReleaseListener(e->Listener);
	}

	Delete(s->ServerListenerList, e);
	Free(e);

	return true;
}

// Compare the SERVER_LISTENER
int CompareServerListener(void *p1, void *p2)
{
	SERVER_LISTENER *s1, *s2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(SERVER_LISTENER **)p1;
	s2 = *(SERVER_LISTENER **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}

	if (s1->Port > s2->Port)
	{
		return 1;
	}
	else if (s1->Port < s2->Port)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

// Stop the listener
bool SiDisableListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	// Validate arguments
	if (s == NULL || port == 0)
	{
		return false;
	}

	// Get the listener
	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	if (e->Enabled == false || e->Listener == NULL)
	{
		// Already stopped
		return true;
	}

	// Stop the listener
	StopListener(e->Listener);

	// Release the listener
	ReleaseListener(e->Listener);
	e->Listener = NULL;

	e->Enabled = false;

	return true;
}

// Start the listener
bool SiEnableListener(SERVER *s, UINT port)
{
	SERVER_LISTENER *e;
	// Validate arguments
	if (s == NULL || port == 0)
	{
		return false;
	}

	// Get the listener
	e = SiGetListener(s, port);
	if (e == NULL)
	{
		return false;
	}

	if (e->Enabled)
	{
		// It has already started
		return true;
	}

	// Create a listener
	e->Listener = NewListener(s->Cedar, LISTENER_TCP, e->Port);
	if (e->Listener == NULL)
	{
		// Failure
		return false;
	}

	e->Listener->DisableDos = e->DisableDos;

	e->Enabled = true;

	return true;
}

// Get the listener
SERVER_LISTENER *SiGetListener(SERVER *s, UINT port)
{
	UINT i;
	// Validate arguments
	if (s == NULL || port == 0)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
	{
		SERVER_LISTENER *e = LIST_DATA(s->ServerListenerList, i);
		if (e->Port == port)
		{
			return e;
		}
	}

	return NULL;
}

// Add a listener
bool SiAddListener(SERVER *s, UINT port, bool enabled)
{
	return SiAddListenerEx(s, port, enabled, false);
}
bool SiAddListenerEx(SERVER *s, UINT port, bool enabled, bool disable_dos)
{
	SERVER_LISTENER *e;
	UINT i;
	// Validate arguments
	if (s == NULL || port == 0)
	{
		return false;
	}

	// Check whether the listener exists already
	for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
	{
		e = LIST_DATA(s->ServerListenerList, i);
		if (e->Port == port)
		{
			// Already exist
			return false;
		}
	}

	// Register by initializing a new listener
	e = ZeroMalloc(sizeof(SERVER_LISTENER));
	e->Enabled = enabled;
	e->Port = port;
	e->DisableDos = disable_dos;

	if (e->Enabled)
	{
		// Create a listener
		e->Listener = NewListener(s->Cedar, LISTENER_TCP, e->Port);
		if (e->Listener != NULL)
		{
			e->Listener->DisableDos = e->DisableDos;
		}
	}

	Insert(s->ServerListenerList, e);

	return true;
}

// Lock the listener list
void SiLockListenerList(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	LockList(s->ServerListenerList);
}

// Unlock the listener list
void SiUnlockListenerList(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	UnlockList(s->ServerListenerList);
}

// Set the default value of the Virtual HUB options
void SiSetDefaultHubOption(HUB_OPTION *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	o->MaxSession = 0;
	o->VlanTypeId = MAC_PROTO_TAGVLAN;
	o->NoIPv6DefaultRouterInRAWhenIPv6 = true;
	o->ManageOnlyPrivateIP = true;
	o->ManageOnlyLocalUnicastIPv6 = true;
	o->NoMacAddressLog = true;
	o->NoDhcpPacketLogOutsideHub = true;
	o->AccessListIncludeFileCacheLifetime = ACCESS_LIST_INCLUDE_FILE_CACHE_LIFETIME;
	o->RemoveDefGwOnDhcpForLocalhost = true;
	o->FloodingSendQueueBufferQuota = DEFAULT_FLOODING_QUEUE_LENGTH;
}

// Create a default virtual HUB
void SiInitDefaultHubList(SERVER *s)
{
	HUB *h;
	HUB_OPTION o;
	HUB_LOG g;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Zero(&o, sizeof(o));

	// Configure a default Virtual HUB management options
	SiSetDefaultHubOption(&o);

	h = NewHub(s->Cedar, s->Cedar->Bridge == false ? SERVER_DEFAULT_HUB_NAME : SERVER_DEFAULT_BRIDGE_NAME, &o);
	h->CreatedTime = SystemTime64();
	AddHub(s->Cedar, h);

	if (s->Cedar->Bridge)
	{
		// Randomize the password
		Rand(h->HashedPassword, sizeof(h->HashedPassword));
		Rand(h->SecurePassword, sizeof(h->SecurePassword));
	}

	h->Offline = true;
	SetHubOnline(h);

	// Log settings
	SiSetDefaultLogSetting(&g);
	SetHubLogSetting(h, &g);

	ReleaseHub(h);
}

// Set the log settings to default
void SiSetDefaultLogSetting(HUB_LOG *g)
{
	// Validate arguments
	if (g == NULL)
	{
		return;
	}

	Zero(g, sizeof(HUB_LOG));
	g->SaveSecurityLog = true;
	g->SecurityLogSwitchType = LOG_SWITCH_DAY;
	g->SavePacketLog = true;
	g->PacketLogSwitchType = LOG_SWITCH_DAY;
	g->PacketLogConfig[PACKET_LOG_TCP_CONN] =
		g->PacketLogConfig[PACKET_LOG_DHCP] = PACKET_LOG_HEADER;
}

// Set the initial configuration
void SiLoadInitialConfiguration(SERVER *s)
{
	RPC_KEEP k;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Auto saving interval related
	s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;
	s->BackupConfigOnlyWhenModified = true;

	s->Weight = FARM_DEFAULT_WEIGHT;

	SiLoadGlobalParamsCfg(NULL);

	// KEEP related
	Zero(&k, sizeof(k));

	{
		k.UseKeepConnect = true;
	}
	k.KeepConnectPort = 80;
	StrCpy(k.KeepConnectHost, sizeof(k.KeepConnectHost), CLIENT_DEFAULT_KEEPALIVE_HOST);
	k.KeepConnectInterval = KEEP_INTERVAL_DEFAULT * 1000;
	k.KeepConnectProtocol = CONNECTION_UDP;

	Lock(s->Keep->lock);
	{
		KEEP *keep = s->Keep;
		keep->Enable = k.UseKeepConnect;
		keep->Server = true;
		StrCpy(keep->ServerName, sizeof(keep->ServerName), k.KeepConnectHost);
		keep->ServerPort = k.KeepConnectPort;
		keep->UdpMode = k.KeepConnectProtocol;
		keep->Interval = k.KeepConnectInterval;
	}
	Unlock(s->Keep->lock);

	// Initialize the password
	{
		Sha0(s->HashedPassword, "", 0);
	}

	// Set the encryption algorithm name to default
	SiInitCipherName(s);

	// Set the server certificate to default
	SiInitDefaultServerCert(s);

	// Set the character which separates the username from the hub name
	s->Cedar->UsernameHubSeparator = DEFAULT_USERNAME_HUB_SEPARATOR;

	// Create a default HUB
	{
		SiInitDefaultHubList(s);
	}

	if (s->Cedar->Bridge == false)
	{
		// Create a DDNS client
		s->DDnsClient = NewDDNSClient(s->Cedar, NULL, NULL);
	}


	// Set the listener list to default setting
	SiInitListenerList(s);

	if (s->Cedar->Bridge)
	{
		// NAT traversal can not be used in the bridge environment
		s->DisableNatTraversal = true;
	}
	else
	{
		// Disable VPN-over-ICMP and VPN-over-DNS by default
		s->EnableVpnOverIcmp = false;
		s->EnableVpnOverDns = false;

		{
			LIST *ports = s->PortsUDP;

			AddInt(ports, SERVER_DEF_PORTS_1);
			AddInt(ports, SERVER_DEF_PORTS_2);
			AddInt(ports, SERVER_DEF_PORTS_3);
			AddInt(ports, SERVER_DEF_PORTS_4);

			ProtoSetUdpPorts(s->Proto, ports);
		}
	}

	s->Eraser = NewEraser(s->Logger, 0);
}

// Check whether the ports required for VPN-over-ICMP can be opened
bool SiCanOpenVpnOverIcmpPort()
{
	// Whether the ICMP can be opened
	SOCK *s = NewUDP(MAKE_SPECIAL_PORT(IP_PROTO_ICMPV4));

	if (s == NULL)
	{
		// Failure
		return false;
	}

	Disconnect(s);
	ReleaseSock(s);

	return true;
}

// Check whether the ports required for VPN-over-DNS can be opened
bool SiCanOpenVpnOverDnsPort()
{
	// Whether UDP Port 53 can be listen on
	SOCK *s = NewUDP(53);

	if (s == NULL)
	{
		// Listening failure
		return false;
	}

	Disconnect(s);
	ReleaseSock(s);

	return true;
}

// Read the configuration file (main)
bool SiLoadConfigurationFileMain(SERVER *s, FOLDER *root)
{
	// Validate arguments
	if (s == NULL || root == NULL)
	{
		return false;
	}

	return SiLoadConfigurationCfg(s, root);
}

// Read the configuration file
bool SiLoadConfigurationFile(SERVER *s)
{
	// Validate arguments
	bool ret = false;
	FOLDER *root;
	char *server_config_filename = SERVER_CONFIG_FILE_NAME;
	if (s == NULL)
	{
		return false;
	}


	s->CfgRw = NewCfgRwEx2A(&root,
		s->Cedar->Bridge == false ? server_config_filename : BRIDGE_CONFIG_FILE_NAME, false,
		s->Cedar->Bridge == false ? SERVER_CONFIG_TEMPLATE_NAME : BRIDGE_CONFIG_TEMPLATE_NAME);

	if (server_reset_setting)
	{
		CfgDeleteFolder(root);
		root = NULL;
		server_reset_setting = false;
	}

	if (root == NULL)
	{
		return false;
	}

	ret = SiLoadConfigurationFileMain(s, root);

	CfgDeleteFolder(root);

	return ret;
}

// Initialize the configuration
void SiInitConfiguration(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;
	s->BackupConfigOnlyWhenModified = true;

	if (s->Cedar->Bridge == false)
	{
		// Protocols handler
		s->Proto = ProtoNew(s->Cedar);
		// IPsec server
		s->IPsecServer = NewIPsecServer(s->Cedar);
	}

	SLog(s->Cedar, "LS_LOAD_CONFIG_1");
	if (SiLoadConfigurationFile(s) == false)
	{
		// Ethernet initialization
		InitEth();

		SLog(s->Cedar, "LS_LOAD_CONFIG_3");
		SiLoadInitialConfiguration(s);

		SetFifoCurrentReallocMemSize(MEM_FIFO_REALLOC_MEM_SIZE);

		server_reset_setting = false;
	}
	else
	{
		SLog(s->Cedar, "LS_LOAD_CONFIG_2");
	}

	s->CfgRw->DontBackup = s->DontBackupConfig;

	// The arp_filter in Linux
	if (GetOsInfo()->OsType == OSTYPE_LINUX)
	{
		if (s->NoLinuxArpFilter == false)
		{
			SetLinuxArpFilter();
		}
	}

	if (s->DisableDosProtection)
	{
		DisableDosProtect();
	}
	else
	{
		EnableDosProtect();
	}

	s->AutoSaveConfigSpanSaved = s->AutoSaveConfigSpan;

	// Create a VPN Azure client
	if (s->DDnsClient != NULL && s->Cedar->Bridge == false && s->ServerType == SERVER_TYPE_STANDALONE)
	{
		s->AzureClient = NewAzureClient(s->Cedar, s);

		AcSetEnable(s->AzureClient, s->EnableVpnAzure);
	}

	// Reduce the storage interval in the case of user mode
#ifdef	OS_WIN32
	if (MsIsUserMode())
	{
		s->AutoSaveConfigSpan = MIN(s->AutoSaveConfigSpan, SERVER_FILE_SAVE_INTERVAL_USERMODE);
	}
#endif	//OS_WIN32

	// Create a saving thread
	SLog(s->Cedar, "LS_INIT_SAVE_THREAD", s->AutoSaveConfigSpan / 1000);
	s->SaveHaltEvent = NewEvent();
	s->SaveThread = NewThread(SiSaverThread, s);
}

// Set the state of Enabled / Disabled of Azure Client
void SiSetAzureEnable(SERVER *s, bool enabled)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (s->AzureClient != NULL)
	{
		AcSetEnable(s->AzureClient, enabled);
	}

	s->EnableVpnAzure = enabled;
}

// Apply the Config to the Azure Client
void SiApplyAzureConfig(SERVER *s, DDNS_CLIENT_STATUS *ddns_status)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	AcApplyCurrentConfig(s->AzureClient, ddns_status);
}

// Get whether the Azure Client is enabled
bool SiIsAzureEnabled(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	if (s->AzureClient == NULL)
	{
		return false;
	}

	return s->EnableVpnAzure;
}

// Get whether the Azure Client is supported
bool SiIsAzureSupported(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return false;
	}

	if (s->AzureClient == NULL)
	{
		return false;
	}

	return true;
}

// Read the server settings from the CFG
bool SiLoadConfigurationCfg(SERVER *s, FOLDER *root)
{
	FOLDER *f1, *f2, *f3, *f4, *f5, *f6, *f7, *f8, *f;
	// Validate arguments
	if (s == NULL || root == NULL)
	{
		return false;
	}

	f = NULL;


	f1 = CfgGetFolder(root, "ServerConfiguration");
	f2 = CfgGetFolder(root, "VirtualHUB");
	f3 = CfgGetFolder(root, "ListenerList");
	f4 = CfgGetFolder(root, "LocalBridgeList");
	f5 = CfgGetFolder(root, "VirtualLayer3SwitchList");
	f6 = CfgGetFolder(root, "LicenseManager");
	f7 = CfgGetFolder(root, "IPsec");
	f8 = CfgGetFolder(root, "DDnsClient");

	if (f1 == NULL)
	{
		SLog(s->Cedar, "LS_BAD_CONFIG");
		return false;
	}

#ifdef	OS_WIN32
	if (f4 != NULL)
	{
		// Read the flag of using the SeLow driver
		bool b = true;

		if (CfgIsItem(f4, "EnableSoftEtherKernelModeDriver"))
		{
			b = CfgGetBool(f4, "EnableSoftEtherKernelModeDriver");
		}

		Win32SetEnableSeLow(b);
	}
#endif	// OS_WIN32

	// Ethernet initialization
	InitEth();

	s->ConfigRevision = CfgGetInt(root, "ConfigRevision");

	if (s->Cedar->Bridge == false && f6 != NULL)
	{
		if (GetServerCapsBool(s, "b_support_license"))
		{
			SiLoadLicenseManager(s, f6);
		}
	}

	DestroyServerCapsCache(s);

	SiLoadServerCfg(s, f1);

	if (s->ServerType != SERVER_TYPE_FARM_MEMBER)
	{
		SiLoadHubs(s, f2);
	}

	SiLoadListeners(s, f3);

	if (f4 != NULL)
	{
		SiLoadLocalBridges(s, f4);
	}

	if (s->Cedar->Bridge == false && f5 != NULL)
	{
		SiLoadL3Switchs(s, f5);
	}

	if (f7 != NULL && GetServerCapsBool(s, "b_support_ipsec"))
	{
		SiLoadIPsec(s, f7);
	}

	if (s->Cedar->Bridge == false)
	{
		if (f8 == NULL)
		{
			// Create a DDNS client with a new key
			s->DDnsClient = NewDDNSClient(s->Cedar, NULL, NULL);
		}
		else
		{
			// Create by reading the setting of the DDNS client
			UCHAR key[SHA1_SIZE];
			if (CfgGetBool(f8, "Disabled"))
			{
				// Disabled
			}
			else
			{
				char machine_name[MAX_SIZE];
				char machine_name2[MAX_SIZE];
				INTERNET_SETTING t;
				BUF *pw;

				// Proxy Setting
				Zero(&t, sizeof(t));
				t.ProxyType = CfgGetInt(f8, "ProxyType");
				CfgGetStr(f8, "ProxyHostName", t.ProxyHostName, sizeof(t.ProxyHostName));
				t.ProxyPort = CfgGetInt(f8, "ProxyPort");
				CfgGetStr(f8, "ProxyUsername", t.ProxyUsername, sizeof(t.ProxyUsername));
				pw = CfgGetBuf(f8, "ProxyPassword");
				if (pw != NULL)
				{
					char *pw_str = DecryptPassword(pw);
					StrCpy(t.ProxyPassword, sizeof(t.ProxyPassword), pw_str);

					Free(pw_str);
					FreeBuf(pw);
				}

				CfgGetStr(f8, "CustomHttpHeader", t.CustomHttpHeader, sizeof(t.CustomHttpHeader));

				GetMachineHostName(machine_name, sizeof(machine_name));

				CfgGetStr(f8, "LocalHostname", machine_name2, sizeof(machine_name2));

				if (CfgGetByte(f8, "Key", key, sizeof(key)) != sizeof(key) || StrCmpi(machine_name, machine_name2) != 0)
				{
					// Create a DDNS client with a new key
					s->DDnsClient = NewDDNSClient(s->Cedar, NULL, &t);
				}
				else
				{
					// Create the DDNS client with stored key
					s->DDnsClient = NewDDNSClient(s->Cedar, key, &t);
				}
			}
		}
	}


	{
		HUB *h = NULL;

		// Remove the virtual HUB "VPNGATE" when VGS disabled
		LockHubList(s->Cedar);
		{
			h = GetHub(s->Cedar, VG_HUBNAME);
		}
		UnlockHubList(s->Cedar);

		if (h != NULL)
		{
			StopHub(h);
			DelHub(s->Cedar, h);
			ReleaseHub(h);
		}
	}

	s->IPsecMessageDisplayed = CfgGetBool(root, "IPsecMessageDisplayed");


	return true;
}

// Write the listener configuration
void SiWriteListenerCfg(FOLDER *f, SERVER_LISTENER *r)
{
	// Validate arguments
	if (f == NULL || r == NULL)
	{
		return;
	}

	CfgAddBool(f, "Enabled", r->Enabled);
	CfgAddInt(f, "Port", r->Port);
	CfgAddBool(f, "DisableDos", r->DisableDos);
}

// Read the listener configuration
void SiLoadListenerCfg(SERVER *s, FOLDER *f)
{
	bool enable;
	UINT port;
	bool disable_dos;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	enable = CfgGetBool(f, "Enabled");
	port = CfgGetInt(f, "Port");
	disable_dos = CfgGetBool(f, "DisableDos");

	if (port == 0)
	{
		return;
	}

	SiAddListenerEx(s, port, enable, disable_dos);
}

// Read the listener list
void SiLoadListeners(SERVER *s, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);
	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = CfgGetFolder(f, t->Token[i]);
		if (ff != NULL)
		{
			SiLoadListenerCfg(s, ff);
		}
	}
	FreeToken(t);
}

// Write the listener list
void SiWriteListeners(FOLDER *f, SERVER *s)
{
	// Validate arguments
	if (f == NULL || s == NULL)
	{
		return;
	}

	LockList(s->ServerListenerList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
		{
			SERVER_LISTENER *r = LIST_DATA(s->ServerListenerList, i);
			char name[MAX_SIZE];
			Format(name, sizeof(name), "Listener%u", i);
			SiWriteListenerCfg(CfgCreateFolder(f, name), r);
		}
	}
	UnlockList(s->ServerListenerList);
}

// Write the bridge
void SiWriteLocalBridgeCfg(FOLDER *f, LOCALBRIDGE *br)
{
	// Validate arguments
	if (f == NULL || br == NULL)
	{
		return;
	}

	CfgAddStr(f, "DeviceName", br->DeviceName);
	CfgAddStr(f, "HubName", br->HubName);
	CfgAddBool(f, "NoPromiscuousMode", br->Local);
	CfgAddBool(f, "MonitorMode", br->Monitor);
	CfgAddBool(f, "LimitBroadcast", br->LimitBroadcast);

	if (OS_IS_UNIX(GetOsInfo()->OsType))
	{
		CfgAddBool(f, "TapMode", br->TapMode);

		if (br->TapMode)
		{
			char tmp[MAX_SIZE];
			MacToStr(tmp, sizeof(tmp), br->TapMacAddress);
			CfgAddStr(f, "TapMacAddress", tmp);
		}
	}
}

// Write the bridge list
void SiWriteLocalBridges(FOLDER *f, SERVER *s)
{
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	CfgAddBool(f, "ShowAllInterfaces", Win32EthGetShowAllIf());

	CfgAddBool(f, "EnableSoftEtherKernelModeDriver", Win32GetEnableSeLow());
#endif	// OS_WIN32

#ifdef	UNIX_LINUX
	CfgAddBool(f, "DoNotDisableOffloading", GetGlobalServerFlag(GSF_LOCALBRIDGE_NO_DISABLE_OFFLOAD));
#endif	// UNIX_LINUX

	LockList(s->Cedar->LocalBridgeList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(s->Cedar->LocalBridgeList);i++)
		{
			LOCALBRIDGE *br = LIST_DATA(s->Cedar->LocalBridgeList, i);
			char name[MAX_SIZE];

			Format(name, sizeof(name), "LocalBridge%u", i);
			SiWriteLocalBridgeCfg(CfgCreateFolder(f, name), br);
		}
	}
	UnlockList(s->Cedar->LocalBridgeList);
}

// Read the bridge
void SiLoadLocalBridgeCfg(SERVER *s, FOLDER *f)
{
	char hub[MAX_SIZE];
	char nic[MAX_SIZE];
	bool tapmode = false;
	UCHAR tapaddr[6];
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	Zero(hub, sizeof(hub));
	Zero(nic, sizeof(nic));

	CfgGetStr(f, "HubName", hub, sizeof(hub));
	CfgGetStr(f, "DeviceName", nic, sizeof(nic));

	if (IsEmptyStr(hub) || IsEmptyStr(nic)
		)
	{
		return;
	}

	if (OS_IS_UNIX(GetOsInfo()->OsType))
	{
		if (CfgGetBool(f, "TapMode"))
		{
			char tmp[MAX_SIZE];
			tapmode = true;
			Zero(tapaddr, sizeof(tapaddr));
			if (CfgGetStr(f, "TapMacAddress", tmp, sizeof(tmp)))
			{
				BUF *b;
				b = StrToBin(tmp);
				if (b != NULL && b->Size == 6)
				{
					Copy(tapaddr, b->Buf, sizeof(tapaddr));
				}
				FreeBuf(b);
			}
		}
	}

	AddLocalBridge(s->Cedar, hub, nic, CfgGetBool(f, "NoPromiscuousMode"), CfgGetBool(f, "MonitorMode"),
		tapmode, tapaddr, CfgGetBool(f, "LimitBroadcast"));
}

// Read the bridge list
void SiLoadLocalBridges(SERVER *s, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32EthSetShowAllIf(CfgGetBool(f, "ShowAllInterfaces"));
#endif	// OS_WIN32

#ifdef	UNIX_LINUX
	SetGlobalServerFlag(GSF_LOCALBRIDGE_NO_DISABLE_OFFLOAD, CfgGetBool(f, "DoNotDisableOffloading"));
#endif	// UNIX_LINUX

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];

		SiLoadLocalBridgeCfg(s, CfgGetFolder(f, name));
	}

	FreeToken(t);
}

// Increment the configuration revision of the server
void IncrementServerConfigRevision(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	s->ConfigRevision++;
}

// Write the server settings to CFG
FOLDER *SiWriteConfigurationToCfg(SERVER *s)
{
	FOLDER *root;
	char region[128];
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);

	SiGetCurrentRegion(s->Cedar, region, sizeof(region));

	CfgAddStr(root, "Region", region);

	CfgAddInt(root, "ConfigRevision", s->ConfigRevision);

	SiWriteListeners(CfgCreateFolder(root, "ListenerList"), s);

	SiWriteLocalBridges(CfgCreateFolder(root, "LocalBridgeList"), s);

	SiWriteServerCfg(CfgCreateFolder(root, "ServerConfiguration"), s);


	if (s->UpdatedServerType != SERVER_TYPE_FARM_MEMBER)
	{
		SiWriteHubs(CfgCreateFolder(root, "VirtualHUB"), s);
	}

	if (s->Cedar->Bridge == false)
	{
		SiWriteL3Switchs(CfgCreateFolder(root, "VirtualLayer3SwitchList"), s);

		if (GetServerCapsBool(s, "b_support_license"))
		{
			SiWriteLicenseManager(CfgCreateFolder(root, "LicenseManager"), s);
		}
	}

	if (s->Led)
	{
		CfgAddBool(root, "Led", true);
		CfgAddBool(root, "LedSpecial", s->LedSpecial);
	}

	if (GetServerCapsBool(s, "b_support_ipsec"))
	{
		SiWriteIPsec(CfgCreateFolder(root, "IPsec"), s);
	}

	if (s->Cedar->Bridge == false)
	{
		FOLDER *ddns_folder = CfgCreateFolder(root, "DDnsClient");

		if (s->DDnsClient == NULL)
		{
			// Disabled
			CfgAddBool(ddns_folder, "Disabled", true);
		}
		else
		{
			char machine_name[MAX_SIZE];
			BUF *pw;
			INTERNET_SETTING *t;
			// Enabled
			CfgAddBool(ddns_folder, "Disabled", false);
			CfgAddByte(ddns_folder, "Key", s->DDnsClient->Key, SHA1_SIZE);

			GetMachineHostName(machine_name, sizeof(machine_name));
			CfgAddStr(ddns_folder, "LocalHostname", machine_name);

			t = &s->DDnsClient->InternetSetting;

			CfgAddInt(ddns_folder, "ProxyType", t->ProxyType);
			CfgAddStr(ddns_folder, "ProxyHostName", t->ProxyHostName);
			CfgAddInt(ddns_folder, "ProxyPort", t->ProxyPort);
			CfgAddStr(ddns_folder, "ProxyUsername", t->ProxyUsername);

			if (IsEmptyStr(t->ProxyPassword) == false)
			{
				pw = EncryptPassword(t->ProxyPassword);

				CfgAddBuf(ddns_folder, "ProxyPassword", pw);

				FreeBuf(pw);
			}

			CfgAddStr(ddns_folder, "CustomHttpHeader", t->CustomHttpHeader);
		}
	}

	CfgAddBool(root, "IPsecMessageDisplayed", s->IPsecMessageDisplayed);


	return root;
}

// Read the policy
void SiLoadPolicyCfg(POLICY *p, FOLDER *f)
{
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return;
	}

	Zero(p, sizeof(POLICY));

	// Ver 2
	p->Access = CfgGetBool(f, "Access");
	p->DHCPFilter = CfgGetBool(f, "DHCPFilter");
	p->DHCPNoServer = CfgGetBool(f, "DHCPNoServer");
	p->DHCPForce = CfgGetBool(f, "DHCPForce");
	p->NoBridge = CfgGetBool(f, "NoBridge");
	p->NoRouting = CfgGetBool(f, "NoRouting");
	p->CheckMac = CfgGetBool(f, "CheckMac");
	p->CheckIP = CfgGetBool(f, "CheckIP");
	p->ArpDhcpOnly = CfgGetBool(f, "ArpDhcpOnly");
	p->PrivacyFilter = CfgGetBool(f, "PrivacyFilter");
	p->NoServer = CfgGetBool(f, "NoServer");
	p->NoBroadcastLimiter = CfgGetBool(f, "NoBroadcastLimiter");
	p->MonitorPort = CfgGetBool(f, "MonitorPort");
	p->MaxConnection = CfgGetInt(f, "MaxConnection");
	p->TimeOut = CfgGetInt(f, "TimeOut");
	p->MaxMac = CfgGetInt(f, "MaxMac");
	p->MaxIP = CfgGetInt(f, "MaxIP");
	p->MaxUpload = CfgGetInt(f, "MaxUpload");
	p->MaxDownload = CfgGetInt(f, "MaxDownload");
	p->FixPassword = CfgGetBool(f, "FixPassword");
	p->MultiLogins = CfgGetInt(f, "MultiLogins");
	p->NoQoS = CfgGetBool(f, "NoQoS");

	// Ver 3
	p->RSandRAFilter = CfgGetBool(f, "RSandRAFilter");
	p->RAFilter = CfgGetBool(f, "RAFilter");
	p->DHCPv6Filter = CfgGetBool(f, "DHCPv6Filter");
	p->DHCPv6NoServer = CfgGetBool(f, "DHCPv6NoServer");
	p->NoRoutingV6 = CfgGetBool(f, "NoRoutingV6");
	p->CheckIPv6 = CfgGetBool(f, "CheckIPv6");
	p->NoServerV6 = CfgGetBool(f, "NoServerV6");
	p->MaxIPv6 = CfgGetInt(f, "MaxIPv6");
	p->NoSavePassword = CfgGetBool(f, "NoSavePassword");
	p->AutoDisconnect = CfgGetInt(f, "AutoDisconnect");
	p->FilterIPv4 = CfgGetBool(f, "FilterIPv4");
	p->FilterIPv6 = CfgGetBool(f, "FilterIPv6");
	p->FilterNonIP = CfgGetBool(f, "FilterNonIP");
	p->NoIPv6DefaultRouterInRA = CfgGetBool(f, "NoIPv6DefaultRouterInRA");
	p->NoIPv6DefaultRouterInRAWhenIPv6 = CfgGetBool(f, "NoIPv6DefaultRouterInRAWhenIPv6");
	p->VLanId = CfgGetInt(f, "VLanId");
}

// Write the policy
void SiWritePolicyCfg(FOLDER *f, POLICY *p, bool cascade_mode)
{
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return;
	}

	// Ver 2.0
	if (cascade_mode == false)
	{
		CfgAddBool(f, "Access", p->Access);
	}

	CfgAddBool(f, "DHCPFilter", p->DHCPFilter);
	CfgAddBool(f, "DHCPNoServer", p->DHCPNoServer);
	CfgAddBool(f, "DHCPForce", p->DHCPForce);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "NoBridge", p->NoBridge);
		CfgAddBool(f, "NoRouting", p->NoRouting);
	}

	CfgAddBool(f, "CheckMac", p->CheckMac);
	CfgAddBool(f, "CheckIP", p->CheckIP);
	CfgAddBool(f, "ArpDhcpOnly", p->ArpDhcpOnly);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "PrivacyFilter", p->PrivacyFilter);
	}

	CfgAddBool(f, "NoServer", p->NoServer);
	CfgAddBool(f, "NoBroadcastLimiter", p->NoBroadcastLimiter);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "MonitorPort", p->MonitorPort);
		CfgAddInt(f, "MaxConnection", p->MaxConnection);
		CfgAddInt(f, "TimeOut", p->TimeOut);
	}

	CfgAddInt(f, "MaxMac", p->MaxMac);
	CfgAddInt(f, "MaxIP", p->MaxIP);
	CfgAddInt(f, "MaxUpload", p->MaxUpload);
	CfgAddInt(f, "MaxDownload", p->MaxDownload);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "FixPassword", p->FixPassword);
		CfgAddInt(f, "MultiLogins", p->MultiLogins);
		CfgAddBool(f, "NoQoS", p->NoQoS);
	}

	// Ver 3.0
	CfgAddBool(f, "RSandRAFilter", p->RSandRAFilter);
	CfgAddBool(f, "RAFilter", p->RAFilter);
	CfgAddBool(f, "DHCPv6Filter", p->DHCPv6Filter);
	CfgAddBool(f, "DHCPv6NoServer", p->DHCPv6NoServer);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "NoRoutingV6", p->NoRoutingV6);
	}

	CfgAddBool(f, "CheckIPv6", p->CheckIPv6);
	CfgAddBool(f, "NoServerV6", p->NoServerV6);
	CfgAddInt(f, "MaxIPv6", p->MaxIPv6);

	if (cascade_mode == false)
	{
		CfgAddBool(f, "NoSavePassword", p->NoSavePassword);
		CfgAddInt(f, "AutoDisconnect", p->AutoDisconnect);
	}

	CfgAddBool(f, "FilterIPv4", p->FilterIPv4);
	CfgAddBool(f, "FilterIPv6", p->FilterIPv6);
	CfgAddBool(f, "FilterNonIP", p->FilterNonIP);
	CfgAddBool(f, "NoIPv6DefaultRouterInRA", p->NoIPv6DefaultRouterInRA);
	CfgAddBool(f, "NoIPv6DefaultRouterInRAWhenIPv6", p->NoIPv6DefaultRouterInRAWhenIPv6);
	CfgAddInt(f, "VLanId", p->VLanId);
}

// Write the link information of the Virtual HUB
void SiWriteHubLinkCfg(FOLDER *f, LINK *k)
{
	// Validate arguments
	if (f == NULL || k == NULL)
	{
		return;
	}

	Lock(k->lock);
	{
		// Online
		CfgAddBool(f, "Online", k->Offline ? false : true);

		// Client options
		CiWriteClientOption(CfgCreateFolder(f, "ClientOption"), k->Option);

		// Client authentication data
		CiWriteClientAuth(CfgCreateFolder(f, "ClientAuth"), k->Auth);

		// Policy
		if (k->Policy != NULL)
		{
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), k->Policy, true);
		}

		CfgAddBool(f, "CheckServerCert", k->CheckServerCert);

		if (k->ServerCert != NULL)
		{
			BUF *b = XToBuf(k->ServerCert, false);
			CfgAddBuf(f, "ServerCert", b);
			FreeBuf(b);
		}
	}
	Unlock(k->lock);
}

// Read the link information
void SiLoadHubLinkCfg(FOLDER *f, HUB *h)
{
	bool online;
	CLIENT_OPTION *o;
	CLIENT_AUTH *a;
	FOLDER *pf;
	POLICY p;
	LINK *k;
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	pf = CfgGetFolder(f, "Policy");
	if (pf == NULL)
	{
		return;
	}

	SiLoadPolicyCfg(&p, pf);

	online = CfgGetBool(f, "Online");

	o = CiLoadClientOption(CfgGetFolder(f, "ClientOption"));
	a = CiLoadClientAuth(CfgGetFolder(f, "ClientAuth"));
	if (o == NULL || a == NULL)
	{
		Free(o);
		CiFreeClientAuth(a);
		return;
	}

	k = NewLink(h->Cedar, h, o, a, &p);
	if (k != NULL)
	{
		BUF *b;
		k->CheckServerCert = CfgGetBool(f, "CheckServerCert");
		b = CfgGetBuf(f, "ServerCert");
		if (b != NULL)
		{
			k->ServerCert = BufToX(b, false);
			FreeBuf(b);
		}

		if (online)
		{
			k->Offline = true;
			SetLinkOnline(k);
		}
		else
		{
			k->Offline = false;
			SetLinkOffline(k);
		}
		ReleaseLink(k);
	}

	Free(o);
	CiFreeClientAuth(a);
}

// Write the SecureNAT of the Virtual HUB
void SiWriteSecureNAT(HUB *h, FOLDER *f)
{
	// Validate arguments
	if (h == NULL || f == NULL)
	{
		return;
	}

	CfgAddBool(f, "Disabled", h->EnableSecureNAT ? false : true);

	NiWriteVhOptionEx(h->SecureNATOption, f);
}

// Read the administration options for the virtual HUB
void SiLoadHubAdminOptions(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	// Validate arguments
	if (h == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumItemToTokenList(f);
	if (t != NULL)
	{
		UINT i;

		LockList(h->AdminOptionList);
		{
			DeleteAllHubAdminOption(h, false);

			for (i = 0;i < t->NumTokens;i++)
			{
				char *name = t->Token[i];
				ADMIN_OPTION *a;
				UINT value = CfgGetInt(f, name);;

				Trim(name);

				a = ZeroMalloc(sizeof(ADMIN_OPTION));
				StrCpy(a->Name, sizeof(a->Name), name);
				a->Value = value;

				Insert(h->AdminOptionList, a);
			}

			AddHubAdminOptionsDefaults(h, false);
		}
		UnlockList(h->AdminOptionList);

		FreeToken(t);
	}
}

// Write the administration options for the virtual HUB
void SiWriteHubAdminOptions(FOLDER *f, HUB *h)
{
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	LockList(h->AdminOptionList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->AdminOptionList);i++)
		{
			ADMIN_OPTION *a = LIST_DATA(h->AdminOptionList, i);

			CfgAddInt(f, a->Name, a->Value);
		}
	}
	UnlockList(h->AdminOptionList);
}

// Write the link list of the Virtual HUB
void SiWriteHubLinks(FOLDER *f, HUB *h)
{
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	LockList(h->LinkList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->LinkList);i++)
		{
			LINK *k = LIST_DATA(h->LinkList, i);
			char name[MAX_SIZE];
			Format(name, sizeof(name), "Cascade%u", i);
			SiWriteHubLinkCfg(CfgCreateFolder(f, name), k);
		}
	}
	UnlockList(h->LinkList);
}

// Read the link list
void SiLoadHubLinks(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// Validate arguments
	if (h == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		SiLoadHubLinkCfg(CfgGetFolder(f, name), h);
	}

	FreeToken(t);
}

// Write an item of the access list
void SiWriteHubAccessCfg(FOLDER *f, ACCESS *a)
{
	// Validate arguments
	if (f == NULL || a == NULL)
	{
		return;
	}

	CfgAddUniStr(f, "Note", a->Note);
	CfgAddBool(f, "Active", a->Active);
	CfgAddInt(f, "Priority", a->Priority);
	CfgAddBool(f, "Discard", a->Discard);
	CfgAddBool(f, "IsIPv6", a->IsIPv6);

	if (a->IsIPv6 == false)
	{
		CfgAddIp32(f, "SrcIpAddress", a->SrcIpAddress);
		CfgAddIp32(f, "SrcSubnetMask", a->SrcSubnetMask);
		CfgAddIp32(f, "DestIpAddress", a->DestIpAddress);
		CfgAddIp32(f, "DestSubnetMask", a->DestSubnetMask);
	}
	else
	{
		CfgAddIp6Addr(f, "SrcIpAddress6", &a->SrcIpAddress6);
		CfgAddIp6Addr(f, "SrcSubnetMask6", &a->SrcSubnetMask6);
		CfgAddIp6Addr(f, "DestIpAddress6", &a->DestIpAddress6);
		CfgAddIp6Addr(f, "DestSubnetMask6", &a->DestSubnetMask6);
	}

	CfgAddInt(f, "Protocol", a->Protocol);
	CfgAddInt(f, "SrcPortStart", a->SrcPortStart);
	CfgAddInt(f, "SrcPortEnd", a->SrcPortEnd);
	CfgAddInt(f, "DestPortStart", a->DestPortStart);
	CfgAddInt(f, "DestPortEnd", a->DestPortEnd);
	CfgAddStr(f, "SrcUsername", a->SrcUsername);
	CfgAddStr(f, "DestUsername", a->DestUsername);
	CfgAddBool(f, "CheckSrcMac", a->CheckSrcMac);

	if (a->CheckSrcMac)
	{
		char tmp[MAX_PATH];

		MacToStr(tmp, sizeof(tmp), a->SrcMacAddress);
		CfgAddStr(f, "SrcMacAddress", tmp);

		MacToStr(tmp, sizeof(tmp), a->SrcMacMask);
		CfgAddStr(f, "SrcMacMask", tmp);
	}

	CfgAddBool(f, "CheckDstMac", a->CheckDstMac);

	if (a->CheckDstMac)
	{
		char tmp[MAX_PATH];

		MacToStr(tmp, sizeof(tmp), a->DstMacAddress);
		CfgAddStr(f, "DstMacAddress", tmp);

		MacToStr(tmp, sizeof(tmp), a->DstMacMask);
		CfgAddStr(f, "DstMacMask", tmp);
	}

	CfgAddBool(f, "CheckTcpState", a->CheckTcpState);
	CfgAddBool(f, "Established", a->Established);

	CfgAddStr(f, "RedirectUrl", a->RedirectUrl);

	CfgAddInt(f, "Delay", a->Delay);
	CfgAddInt(f, "Jitter", a->Jitter);
	CfgAddInt(f, "Loss", a->Loss);
}

// Read an item of the access list
void SiLoadHubAccessCfg(HUB *h, FOLDER *f)
{
	ACCESS a;
	char tmp[MAX_PATH];
	// Validate arguments
	if (h == NULL || f == NULL)
	{
		return;
	}

	Zero(&a, sizeof(a));

	CfgGetUniStr(f, "Note", a.Note, sizeof(a.Note));
	a.Active = CfgGetBool(f, "Active");
	a.Priority = CfgGetInt(f, "Priority");
	a.Discard = CfgGetBool(f, "Discard");
	a.IsIPv6 = CfgGetBool(f, "IsIPv6");

	if (a.IsIPv6 == false)
	{
		a.SrcIpAddress = CfgGetIp32(f, "SrcIpAddress");
		a.SrcSubnetMask = CfgGetIp32(f, "SrcSubnetMask");
		a.DestIpAddress = CfgGetIp32(f, "DestIpAddress");
		a.DestSubnetMask = CfgGetIp32(f, "DestSubnetMask");
	}
	else
	{
		CfgGetIp6Addr(f, "SrcIpAddress6", &a.SrcIpAddress6);
		CfgGetIp6Addr(f, "SrcSubnetMask6", &a.SrcSubnetMask6);
		CfgGetIp6Addr(f, "DestIpAddress6", &a.DestIpAddress6);
		CfgGetIp6Addr(f, "DestSubnetMask6", &a.DestSubnetMask6);
	}

	a.Protocol = CfgGetInt(f, "Protocol");
	a.SrcPortStart = CfgGetInt(f, "SrcPortStart");
	a.SrcPortEnd = CfgGetInt(f, "SrcPortEnd");
	a.DestPortStart = CfgGetInt(f, "DestPortStart");
	a.DestPortEnd = CfgGetInt(f, "DestPortEnd");
	CfgGetStr(f, "SrcUsername", a.SrcUsername, sizeof(a.SrcUsername));
	CfgGetStr(f, "DestUsername", a.DestUsername, sizeof(a.DestUsername));
	a.CheckSrcMac = CfgGetBool(f, "CheckSrcMac");

	if (CfgGetByte(f, "SrcMacAddress", a.SrcMacAddress, sizeof(a.SrcMacAddress)) == 0)
	{
		CfgGetStr(f, "SrcMacAddress", tmp, sizeof(tmp));
		if (StrToMac(a.SrcMacAddress, tmp) == false)
		{
			a.CheckSrcMac = false;
		}
	}

	if (CfgGetByte(f, "SrcMacMask", a.SrcMacMask, sizeof(a.SrcMacMask)) == 0)
	{
		CfgGetStr(f, "SrcMacMask", tmp, sizeof(tmp));
		if (StrToMac(a.SrcMacMask, tmp) == false)
		{
			a.CheckSrcMac = false;
		}
	}

	a.CheckDstMac = CfgGetBool(f, "CheckDstMac");

	if (CfgGetByte(f, "DstMacAddress", a.DstMacAddress, sizeof(a.DstMacAddress)) == 0)
	{
		CfgGetStr(f, "DstMacAddress", tmp, sizeof(tmp));
		if (StrToMac(a.DstMacAddress, tmp) == false)
		{
			a.CheckDstMac = false;
		}
	}

	if (CfgGetByte(f, "DstMacMask", a.DstMacMask, sizeof(a.DstMacMask)) == 0)
	{
		CfgGetStr(f, "DstMacMask", tmp, sizeof(tmp));
		if (StrToMac(a.DstMacMask, tmp) == false)
		{
			a.CheckDstMac = false;
		}
	}

	a.CheckTcpState = CfgGetBool(f, "CheckTcpState");
	a.Established = CfgGetBool(f, "Established");
	a.Delay = MAKESURE(CfgGetInt(f, "Delay"), 0, HUB_ACCESSLIST_DELAY_MAX);
	a.Jitter = MAKESURE(CfgGetInt(f, "Jitter"), 0, HUB_ACCESSLIST_JITTER_MAX);
	a.Loss = MAKESURE(CfgGetInt(f, "Loss"), 0, HUB_ACCESSLIST_LOSS_MAX);

	CfgGetStr(f, "RedirectUrl", a.RedirectUrl, sizeof(a.RedirectUrl));

	AddAccessList(h, &a);
}

// Write the access list
void SiWriteHubAccessLists(FOLDER *f, HUB *h)
{
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	LockList(h->AccessList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(h->AccessList, i);
			char name[MAX_SIZE];
			ToStr(name, a->Id);
			SiWriteHubAccessCfg(CfgCreateFolder(f, name), a);
		}
	}
	UnlockList(h->AccessList);
}

// Read the access list
void SiLoadHubAccessLists(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];
		SiLoadHubAccessCfg(h, CfgGetFolder(f, name));
	}

	FreeToken(t);
}

// Read the HUB_OPTION
void SiLoadHubOptionCfg(FOLDER *f, HUB_OPTION *o)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (f == NULL || o == NULL)
	{
		return;
	}

	o->MaxSession = CfgGetInt(f, "MaxSession");
	o->NoArpPolling = CfgGetBool(f, "NoArpPolling");
	o->NoIPv6AddrPolling = CfgGetBool(f, "NoIPv6AddrPolling");
	o->NoIpTable = CfgGetBool(f, "NoIpTable");
	o->NoEnum = CfgGetBool(f, "NoEnum");
	o->FilterPPPoE = CfgGetBool(f, "FilterPPPoE");
	o->FilterOSPF = CfgGetBool(f, "FilterOSPF");
	o->FilterIPv4 = CfgGetBool(f, "FilterIPv4");
	o->FilterIPv6 = CfgGetBool(f, "FilterIPv6");
	o->FilterNonIP = CfgGetBool(f, "FilterNonIP");
	o->FilterBPDU = CfgGetBool(f, "FilterBPDU");
	o->NoIPv4PacketLog = CfgGetBool(f, "NoIPv4PacketLog");
	o->NoIPv6PacketLog = CfgGetBool(f, "NoIPv6PacketLog");
	o->NoIPv6DefaultRouterInRAWhenIPv6 = CfgGetBool(f, "NoIPv6DefaultRouterInRAWhenIPv6");
	o->DisableIPParsing = CfgGetBool(f, "DisableIPParsing");
	o->YieldAfterStorePacket = CfgGetBool(f, "YieldAfterStorePacket");
	o->NoSpinLockForPacketDelay = CfgGetBool(f, "NoSpinLockForPacketDelay");
	o->BroadcastStormDetectionThreshold = CfgGetInt(f, "BroadcastStormDetectionThreshold");
	o->ClientMinimumRequiredBuild = CfgGetInt(f, "ClientMinimumRequiredBuild");
	o->RequiredClientId = CfgGetInt(f, "RequiredClientId");
	o->NoManageVlanId = CfgGetBool(f, "NoManageVlanId");
	o->VlanTypeId = 0;
	if (CfgGetStr(f, "VlanTypeId", tmp, sizeof(tmp)))
	{
		o->VlanTypeId = HexToInt(tmp);
	}
	if (o->VlanTypeId == 0)
	{
		o->VlanTypeId = MAC_PROTO_TAGVLAN;
	}
	o->FixForDLinkBPDU = CfgGetBool(f, "FixForDLinkBPDU");
	o->BroadcastLimiterStrictMode = CfgGetBool(f, "BroadcastLimiterStrictMode");
	o->MaxLoggedPacketsPerMinute = CfgGetInt(f, "MaxLoggedPacketsPerMinute");
	if (CfgIsItem(f, "FloodingSendQueueBufferQuota"))
	{
		o->FloodingSendQueueBufferQuota = CfgGetInt(f, "FloodingSendQueueBufferQuota");
	}
	else
	{
		o->FloodingSendQueueBufferQuota = DEFAULT_FLOODING_QUEUE_LENGTH;
	}
	o->DoNotSaveHeavySecurityLogs = CfgGetBool(f, "DoNotSaveHeavySecurityLogs");

	if (CfgIsItem(f, "DropBroadcastsInPrivacyFilterMode"))
	{
		o->DropBroadcastsInPrivacyFilterMode = CfgGetBool(f, "DropBroadcastsInPrivacyFilterMode");
	}
	else
	{
		o->DropBroadcastsInPrivacyFilterMode = true;
	}

	if (CfgIsItem(f, "DropArpInPrivacyFilterMode"))
	{
		o->DropArpInPrivacyFilterMode = CfgGetBool(f, "DropArpInPrivacyFilterMode");
	}
	else
	{
		o->DropArpInPrivacyFilterMode = true;
	}

	o->NoLookBPDUBridgeId = CfgGetBool(f, "NoLookBPDUBridgeId");
	o->AdjustTcpMssValue = CfgGetInt(f, "AdjustTcpMssValue");
	o->DisableAdjustTcpMss = CfgGetBool(f, "DisableAdjustTcpMss");
	if (CfgIsItem(f, "NoDhcpPacketLogOutsideHub"))
	{
		o->NoDhcpPacketLogOutsideHub = CfgGetBool(f, "NoDhcpPacketLogOutsideHub");
	}
	else
	{
		o->NoDhcpPacketLogOutsideHub = true;
	}
	o->DisableHttpParsing = CfgGetBool(f, "DisableHttpParsing");
	o->DisableUdpAcceleration = CfgGetBool(f, "DisableUdpAcceleration");
	o->DisableUdpFilterForLocalBridgeNic = CfgGetBool(f, "DisableUdpFilterForLocalBridgeNic");
	o->ApplyIPv4AccessListOnArpPacket = CfgGetBool(f, "ApplyIPv4AccessListOnArpPacket");
	if (CfgIsItem(f, "RemoveDefGwOnDhcpForLocalhost"))
	{
		o->RemoveDefGwOnDhcpForLocalhost = CfgGetBool(f, "RemoveDefGwOnDhcpForLocalhost");
	}
	else
	{
		o->RemoveDefGwOnDhcpForLocalhost = true;
	}
	o->SecureNAT_MaxTcpSessionsPerIp = CfgGetInt(f, "SecureNAT_MaxTcpSessionsPerIp");
	o->SecureNAT_MaxTcpSynSentPerIp = CfgGetInt(f, "SecureNAT_MaxTcpSynSentPerIp");
	o->SecureNAT_MaxUdpSessionsPerIp = CfgGetInt(f, "SecureNAT_MaxUdpSessionsPerIp");
	o->SecureNAT_MaxDnsSessionsPerIp = CfgGetInt(f, "SecureNAT_MaxDnsSessionsPerIp");
	o->SecureNAT_MaxIcmpSessionsPerIp = CfgGetInt(f, "SecureNAT_MaxIcmpSessionsPerIp");
	o->AccessListIncludeFileCacheLifetime = CfgGetInt(f, "AccessListIncludeFileCacheLifetime");

	if (o->AccessListIncludeFileCacheLifetime == 0)
	{
		o->AccessListIncludeFileCacheLifetime = ACCESS_LIST_INCLUDE_FILE_CACHE_LIFETIME;
	}

	o->DisableKernelModeSecureNAT = CfgGetBool(f, "DisableKernelModeSecureNAT");
	o->DisableIpRawModeSecureNAT = CfgGetBool(f, "DisableIpRawModeSecureNAT");
	o->DisableUserModeSecureNAT = CfgGetBool(f, "DisableUserModeSecureNAT");
	o->DisableCheckMacOnLocalBridge = CfgGetBool(f, "DisableCheckMacOnLocalBridge");
	o->DisableCorrectIpOffloadChecksum = CfgGetBool(f, "DisableCorrectIpOffloadChecksum");
	o->SuppressClientUpdateNotification = CfgGetBool(f, "SuppressClientUpdateNotification");
	o->AssignVLanIdByRadiusAttribute = CfgGetBool(f, "AssignVLanIdByRadiusAttribute");
	o->DenyAllRadiusLoginWithNoVlanAssign = CfgGetBool(f, "DenyAllRadiusLoginWithNoVlanAssign");
	o->SecureNAT_RandomizeAssignIp = CfgGetBool(f, "SecureNAT_RandomizeAssignIp");
	o->DetectDormantSessionInterval = CfgGetInt(f, "DetectDormantSessionInterval");
	o->NoPhysicalIPOnPacketLog = CfgGetBool(f, "NoPhysicalIPOnPacketLog");
	o->UseHubNameAsDhcpUserClassOption = CfgGetBool(f, "UseHubNameAsDhcpUserClassOption");
	o->UseHubNameAsRadiusNasId = CfgGetBool(f, "UseHubNameAsRadiusNasId");

	// Enabled by default
	if (CfgIsItem(f, "ManageOnlyPrivateIP"))
	{
		o->ManageOnlyPrivateIP = CfgGetBool(f, "ManageOnlyPrivateIP");
	}
	else
	{
		o->ManageOnlyPrivateIP = true;
	}
	if (CfgIsItem(f, "ManageOnlyLocalUnicastIPv6"))
	{
		o->ManageOnlyLocalUnicastIPv6 = CfgGetBool(f, "ManageOnlyLocalUnicastIPv6");
	}
	else
	{
		o->ManageOnlyLocalUnicastIPv6 = true;
	}
	if (CfgIsItem(f, "NoMacAddressLog"))
	{
		o->NoMacAddressLog = CfgGetBool(f, "NoMacAddressLog");
	}
	else
	{
		o->NoMacAddressLog = true;
	}
}

// Write the HUB_OPTION
void SiWriteHubOptionCfg(FOLDER *f, HUB_OPTION *o)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (f == NULL || o == NULL)
	{
		return;
	}

	CfgAddInt(f, "MaxSession", o->MaxSession);
	CfgAddBool(f, "NoArpPolling", o->NoArpPolling);
	CfgAddBool(f, "NoIPv6AddrPolling", o->NoIPv6AddrPolling);
	CfgAddBool(f, "NoIpTable", o->NoIpTable);
	CfgAddBool(f, "NoEnum", o->NoEnum);
	CfgAddBool(f, "FilterPPPoE", o->FilterPPPoE);
	CfgAddBool(f, "FilterOSPF", o->FilterOSPF);
	CfgAddBool(f, "FilterIPv4", o->FilterIPv4);
	CfgAddBool(f, "FilterIPv6", o->FilterIPv6);
	CfgAddBool(f, "FilterNonIP", o->FilterNonIP);
	CfgAddBool(f, "NoIPv4PacketLog", o->NoIPv4PacketLog);
	CfgAddBool(f, "NoIPv6PacketLog", o->NoIPv6PacketLog);
	CfgAddBool(f, "FilterBPDU", o->FilterBPDU);
	CfgAddBool(f, "NoIPv6DefaultRouterInRAWhenIPv6", o->NoIPv6DefaultRouterInRAWhenIPv6);
	CfgAddBool(f, "NoMacAddressLog", o->NoMacAddressLog);
	CfgAddBool(f, "ManageOnlyPrivateIP", o->ManageOnlyPrivateIP);
	CfgAddBool(f, "ManageOnlyLocalUnicastIPv6", o->ManageOnlyLocalUnicastIPv6);
	CfgAddBool(f, "DisableIPParsing", o->DisableIPParsing);
	CfgAddBool(f, "YieldAfterStorePacket", o->YieldAfterStorePacket);
	CfgAddBool(f, "NoSpinLockForPacketDelay", o->NoSpinLockForPacketDelay);
	CfgAddInt(f, "BroadcastStormDetectionThreshold", o->BroadcastStormDetectionThreshold);
	CfgAddInt(f, "ClientMinimumRequiredBuild", o->ClientMinimumRequiredBuild);
	CfgAddInt(f, "RequiredClientId", o->RequiredClientId);
	CfgAddBool(f, "NoManageVlanId", o->NoManageVlanId);
	Format(tmp, sizeof(tmp), "0x%x", o->VlanTypeId);
	CfgAddStr(f, "VlanTypeId", tmp);
	if (o->FixForDLinkBPDU)
	{
		CfgAddBool(f, "FixForDLinkBPDU", o->FixForDLinkBPDU);
	}
	CfgAddBool(f, "BroadcastLimiterStrictMode", o->BroadcastLimiterStrictMode);
	CfgAddInt(f, "MaxLoggedPacketsPerMinute", o->MaxLoggedPacketsPerMinute);
	CfgAddInt(f, "FloodingSendQueueBufferQuota", o->FloodingSendQueueBufferQuota);
	CfgAddBool(f, "DoNotSaveHeavySecurityLogs", o->DoNotSaveHeavySecurityLogs);
	CfgAddBool(f, "DropBroadcastsInPrivacyFilterMode", o->DropBroadcastsInPrivacyFilterMode);
	CfgAddBool(f, "DropArpInPrivacyFilterMode", o->DropArpInPrivacyFilterMode);
	CfgAddBool(f, "SuppressClientUpdateNotification", o->SuppressClientUpdateNotification);
	CfgAddBool(f, "AssignVLanIdByRadiusAttribute", o->AssignVLanIdByRadiusAttribute);
	CfgAddBool(f, "DenyAllRadiusLoginWithNoVlanAssign", o->DenyAllRadiusLoginWithNoVlanAssign);
	CfgAddBool(f, "SecureNAT_RandomizeAssignIp", o->SecureNAT_RandomizeAssignIp);
	CfgAddBool(f, "NoPhysicalIPOnPacketLog", o->NoPhysicalIPOnPacketLog);
	CfgAddInt(f, "DetectDormantSessionInterval", o->DetectDormantSessionInterval);
	CfgAddBool(f, "NoLookBPDUBridgeId", o->NoLookBPDUBridgeId);
	CfgAddInt(f, "AdjustTcpMssValue", o->AdjustTcpMssValue);
	CfgAddBool(f, "DisableAdjustTcpMss", o->DisableAdjustTcpMss);
	CfgAddBool(f, "NoDhcpPacketLogOutsideHub", o->NoDhcpPacketLogOutsideHub);
	CfgAddBool(f, "DisableHttpParsing", o->DisableHttpParsing);
	CfgAddBool(f, "DisableUdpAcceleration", o->DisableUdpAcceleration);
	CfgAddBool(f, "DisableUdpFilterForLocalBridgeNic", o->DisableUdpFilterForLocalBridgeNic);
	CfgAddBool(f, "ApplyIPv4AccessListOnArpPacket", o->ApplyIPv4AccessListOnArpPacket);
	CfgAddBool(f, "RemoveDefGwOnDhcpForLocalhost", o->RemoveDefGwOnDhcpForLocalhost);
	CfgAddInt(f, "SecureNAT_MaxTcpSessionsPerIp", o->SecureNAT_MaxTcpSessionsPerIp);
	CfgAddInt(f, "SecureNAT_MaxTcpSynSentPerIp", o->SecureNAT_MaxTcpSynSentPerIp);
	CfgAddInt(f, "SecureNAT_MaxUdpSessionsPerIp", o->SecureNAT_MaxUdpSessionsPerIp);
	CfgAddInt(f, "SecureNAT_MaxDnsSessionsPerIp", o->SecureNAT_MaxDnsSessionsPerIp);
	CfgAddInt(f, "SecureNAT_MaxIcmpSessionsPerIp", o->SecureNAT_MaxIcmpSessionsPerIp);
	CfgAddInt(f, "AccessListIncludeFileCacheLifetime", o->AccessListIncludeFileCacheLifetime);
	CfgAddBool(f, "DisableKernelModeSecureNAT", o->DisableKernelModeSecureNAT);
	CfgAddBool(f, "DisableIpRawModeSecureNAT", o->DisableIpRawModeSecureNAT);
	CfgAddBool(f, "DisableUserModeSecureNAT", o->DisableUserModeSecureNAT);
	CfgAddBool(f, "DisableCheckMacOnLocalBridge", o->DisableCheckMacOnLocalBridge);
	CfgAddBool(f, "DisableCorrectIpOffloadChecksum", o->DisableCorrectIpOffloadChecksum);
	CfgAddBool(f, "UseHubNameAsDhcpUserClassOption", o->UseHubNameAsDhcpUserClassOption);
	CfgAddBool(f, "UseHubNameAsRadiusNasId", o->UseHubNameAsRadiusNasId);
}

// Write the user
void SiWriteUserCfg(FOLDER *f, USER *u)
{
	BUF *b;
	AUTHPASSWORD *password;
	AUTHRADIUS *radius;
	AUTHNT *nt;
	AUTHUSERCERT *usercert;
	AUTHROOTCERT *rootcert;
	// Validate arguments
	if (f == NULL || u == NULL)
	{
		return;
	}

	Lock(u->lock);
	{
		CfgAddUniStr(f, "RealName", u->RealName);
		CfgAddUniStr(f, "Note", u->Note);
		if (u->Group != NULL)
		{
			CfgAddStr(f, "GroupName", u->GroupName);
		}
		CfgAddInt64(f, "CreatedTime", u->CreatedTime);
		CfgAddInt64(f, "UpdatedTime", u->UpdatedTime);
		CfgAddInt64(f, "ExpireTime", u->ExpireTime);
		CfgAddInt64(f, "LastLoginTime", u->LastLoginTime);
		CfgAddInt(f, "NumLogin", u->NumLogin);
		if (u->Policy != NULL)
		{
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), u->Policy, false);
		}
		SiWriteTraffic(f, "Traffic", u->Traffic);

		CfgAddInt(f, "AuthType", u->AuthType);
		if (u->AuthData != NULL)
		{
			switch (u->AuthType)
			{
			case AUTHTYPE_ANONYMOUS:
				break;

			case AUTHTYPE_PASSWORD:
				password = (AUTHPASSWORD *)u->AuthData;
				CfgAddByte(f, "AuthPassword", password->HashedKey, sizeof(password->HashedKey));

				if (IsZero(password->NtLmSecureHash, sizeof(password->NtLmSecureHash)) == false)
				{
					CfgAddByte(f, "AuthNtLmSecureHash", password->NtLmSecureHash, sizeof(password->NtLmSecureHash));
				}
				break;

			case AUTHTYPE_NT:
				nt = (AUTHNT *)u->AuthData;
				CfgAddUniStr(f, "AuthNtUserName", nt->NtUsername);
				break;

			case AUTHTYPE_RADIUS:
				radius = (AUTHRADIUS *)u->AuthData;
				CfgAddUniStr(f, "AuthRadiusUsername", radius->RadiusUsername);
				break;

			case AUTHTYPE_USERCERT:
				usercert = (AUTHUSERCERT *)u->AuthData;
				b = XToBuf(usercert->UserX, false);
				if (b != NULL)
				{
					CfgAddBuf(f, "AuthUserCert", b);
					FreeBuf(b);
				}
				break;

			case AUTHTYPE_ROOTCERT:
				rootcert = (AUTHROOTCERT *)u->AuthData;
				if (rootcert->Serial != NULL && rootcert->Serial->size >= 1)
				{
					CfgAddByte(f, "AuthSerial", rootcert->Serial->data, rootcert->Serial->size);
				}
				if (rootcert->CommonName != NULL && UniIsEmptyStr(rootcert->CommonName) == false)
				{
					CfgAddUniStr(f, "AuthCommonName", rootcert->CommonName);
				}
				break;
			}
		}
	}
	Unlock(u->lock);
}

// Read an user
void SiLoadUserCfg(HUB *h, FOLDER *f)
{
	char *username;
	wchar_t realname[MAX_SIZE];
	wchar_t note[MAX_SIZE];
	char groupname[MAX_SIZE];
	FOLDER *pf;
	UINT64 created_time;
	UINT64 updated_time;
	UINT64 expire_time;
	UINT64 last_login_time;
	UINT num_login;
	POLICY p;
	TRAFFIC t;
	BUF *b;
	UINT authtype;
	void *authdata;
	X_SERIAL *serial = NULL;
	wchar_t common_name[MAX_SIZE];
	UCHAR hashed_password[SHA1_SIZE];
	UCHAR md4_password[MD5_SIZE];
	wchar_t tmp[MAX_SIZE];
	USER *u;
	USERGROUP *g;
	// Validate arguments
	if (h == NULL || f == NULL)
	{
		return;
	}

	username = f->Name;
	CfgGetUniStr(f, "RealName", realname, sizeof(realname));
	CfgGetUniStr(f, "Note", note, sizeof(note));
	CfgGetStr(f, "GroupName", groupname, sizeof(groupname));

	created_time = CfgGetInt64(f, "CreatedTime");
	updated_time = CfgGetInt64(f, "UpdatedTime");
	expire_time = CfgGetInt64(f, "ExpireTime");
	last_login_time = CfgGetInt64(f, "LastLoginTime");
	num_login = CfgGetInt(f, "NumLogin");
	pf = CfgGetFolder(f, "Policy");
	if (pf != NULL)
	{
		SiLoadPolicyCfg(&p, pf);
	}
	SiLoadTraffic(f, "Traffic", &t);

	authtype = CfgGetInt(f, "AuthType");
	authdata = NULL;

	switch (authtype)
	{
	case AUTHTYPE_PASSWORD:
		Zero(hashed_password, sizeof(hashed_password));
		Zero(md4_password, sizeof(md4_password));
		CfgGetByte(f, "AuthPassword", hashed_password, sizeof(hashed_password));
		CfgGetByte(f, "AuthNtLmSecureHash", md4_password, sizeof(md4_password));
		authdata = NewPasswordAuthDataRaw(hashed_password, md4_password);
		break;

	case AUTHTYPE_NT:
		if (CfgGetUniStr(f, "AuthNtUserName", tmp, sizeof(tmp)))
		{
			authdata = NewNTAuthData(tmp);
		}
		else
		{
			authdata = NewNTAuthData(NULL);
		}
		break;

	case AUTHTYPE_RADIUS:
		if (CfgGetUniStr(f, "AuthRadiusUsername", tmp, sizeof(tmp)))
		{
			authdata = NewRadiusAuthData(tmp);
		}
		else
		{
			authdata = NewRadiusAuthData(NULL);
		}
		break;

	case AUTHTYPE_USERCERT:
		b = CfgGetBuf(f, "AuthUserCert");
		if (b != NULL)
		{
			X *x = BufToX(b, false);
			if (x != NULL)
			{
				authdata = NewUserCertAuthData(x);
				FreeX(x);
			}
			FreeBuf(b);
		}
		break;

	case AUTHTYPE_ROOTCERT:
		b = CfgGetBuf(f, "AuthSerial");
		if (b != NULL)
		{
			serial = NewXSerial(b->Buf, b->Size);
			FreeBuf(b);
		}
		CfgGetUniStr(f, "AuthCommonName", common_name, sizeof(common_name));
		authdata = NewRootCertAuthData(serial, common_name);
		break;
	}

	// Add an user
	AcLock(h);
	{
		if (StrLen(groupname) > 0)
		{
			g = AcGetGroup(h, groupname);
		}
		else
		{
			g = NULL;
		}

		u = NewUser(username, realname, note, authtype, authdata);
		if (u != NULL)
		{
			if (g != NULL)
			{
				JoinUserToGroup(u, g);
			}

			SetUserTraffic(u, &t);

			if (pf != NULL)
			{
				SetUserPolicy(u, &p);
			}

			Lock(u->lock);
			{
				u->CreatedTime = created_time;
				u->UpdatedTime = updated_time;
				u->ExpireTime = expire_time;
				u->LastLoginTime = last_login_time;
				u->NumLogin = num_login;
			}
			Unlock(u->lock);

			AcAddUser(h, u);

			ReleaseUser(u);
		}

		if (g != NULL)
		{
			ReleaseGroup(g);
		}
	}
	AcUnlock(h);

	if (serial != NULL)
	{
		FreeXSerial(serial);
	}
}

// Write the user list
void SiWriteUserList(FOLDER *f, LIST *o)
{
	// Validate arguments
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			USER *u = LIST_DATA(o, i);
			SiWriteUserCfg(CfgCreateFolder(f, u->Name), u);
		}
	}
	UnlockList(o);
}

// Read the user list
void SiLoadUserList(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	char *name;
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff;
		name = t->Token[i];
		ff = CfgGetFolder(f, name);
		SiLoadUserCfg(h, ff);
	}

	FreeToken(t);
}

// Write the group information
void SiWriteGroupCfg(FOLDER *f, USERGROUP *g)
{
	// Validate arguments
	if (f == NULL || g == NULL)
	{
		return;
	}

	Lock(g->lock);
	{
		CfgAddUniStr(f, "RealName", g->RealName);
		CfgAddUniStr(f, "Note", g->Note);
		if (g->Policy != NULL)
		{
			SiWritePolicyCfg(CfgCreateFolder(f, "Policy"), g->Policy, false);
		}
		SiWriteTraffic(f, "Traffic", g->Traffic);
	}
	Unlock(g->lock);
}

// Read the group information
void SiLoadGroupCfg(HUB *h, FOLDER *f)
{
	wchar_t realname[MAX_SIZE];
	wchar_t note[MAX_SIZE];
	char *name;
	FOLDER *pf;
	POLICY p;
	TRAFFIC t;
	USERGROUP *g;
	// Validate arguments
	if (h == NULL || f == NULL)
	{
		return;
	}

	name = f->Name;

	CfgGetUniStr(f, "RealName", realname, sizeof(realname));
	CfgGetUniStr(f, "Note", note, sizeof(note));

	pf = CfgGetFolder(f, "Policy");
	if (pf != NULL)
	{
		SiLoadPolicyCfg(&p, pf);
	}

	SiLoadTraffic(f, "Traffic", &t);

	g = NewGroup(name, realname, note);
	if (g == NULL)
	{
		return;
	}

	if (pf != NULL)
	{
		SetGroupPolicy(g, &p);
	}

	SetGroupTraffic(g, &t);

	AcLock(h);
	{
		AcAddGroup(h, g);
	}
	AcUnlock(h);

	ReleaseGroup(g);
}

// Write the group list
void SiWriteGroupList(FOLDER *f, LIST *o)
{
	// Validate arguments
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			USERGROUP *g = LIST_DATA(o, i);
			SiWriteGroupCfg(CfgCreateFolder(f, g->Name), g);
		}
	}
	UnlockList(o);
}

// Read the group List
void SiLoadGroupList(HUB *h, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	char *name;
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	for (i = 0;i < t->NumTokens;i++)
	{
		name = t->Token[i];
		SiLoadGroupCfg(h, CfgGetFolder(f, name));
	}

	FreeToken(t);
}

// Write the AC list
void SiWriteAcList(FOLDER *f, LIST *o)
{
	// Validate arguments
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			char name[MAX_SIZE];
			AC *ac = LIST_DATA(o, i);
			FOLDER *ff;

			Format(name, sizeof(name), "Acl%u", i + 1);

			ff = CfgCreateFolder(f, name);

			CfgAddBool(ff, "Deny", ac->Deny);
			CfgAddInt(ff, "Priority", ac->Priority);
			CfgAddIp(ff, "IpAddress", &ac->IpAddress);

			if (ac->Masked)
			{
				CfgAddIp(ff, "NetMask", &ac->SubnetMask);
			}
		}
	}
	UnlockList(o);
}

// Read the AC list
void SiLoadAcList(LIST *o, FOLDER *f)
{
	// Validate arguments
	if (o == NULL || f == NULL)
	{
		return;
	}

	LockList(o);
	{
		TOKEN_LIST *t = CfgEnumFolderToTokenList(f);

		if (t != NULL)
		{
			UINT i;

			for (i = 0;i < t->NumTokens;i++)
			{
				FOLDER *ff = CfgGetFolder(f, t->Token[i]);

				if (ff != NULL)
				{
					AC ac;

					Zero(&ac, sizeof(ac));
					ac.Deny = CfgGetBool(ff, "Deny");
					ac.Priority = CfgGetInt(ff, "Priority");
					CfgGetIp(ff, "IpAddress", &ac.IpAddress);

					if (CfgGetIp(ff, "NetMask", &ac.SubnetMask))
					{
						ac.Masked = true;
					}

					AddAc(o, &ac);
				}
			}

			FreeToken(t);
		}
	}
	UnlockList(o);
}

// Write the certificate revocation list
void SiWriteCrlList(FOLDER *f, LIST *o)
{
	// Validate arguments
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			char name[MAX_SIZE];
			CRL *crl = LIST_DATA(o, i);
			FOLDER *ff;
			NAME *n;

			Format(name, sizeof(name), "Crl%u", i);

			ff = CfgCreateFolder(f, name);
			n = crl->Name;

			if (UniIsEmptyStr(n->CommonName) == false)
			{
				CfgAddUniStr(ff, "CommonName", n->CommonName);
			}

			if (UniIsEmptyStr(n->Organization) == false)
			{
				CfgAddUniStr(ff, "Organization", n->Organization);
			}

			if (UniIsEmptyStr(n->Unit) == false)
			{
				CfgAddUniStr(ff, "Unit", n->Unit);
			}

			if (UniIsEmptyStr(n->Country) == false)
			{
				CfgAddUniStr(ff, "Country", n->Country);
			}

			if (UniIsEmptyStr(n->State) == false)
			{
				CfgAddUniStr(ff, "State", n->State);
			}

			if (UniIsEmptyStr(n->Local) == false)
			{
				CfgAddUniStr(ff, "Local", n->Local);
			}

			if (IsZero(crl->DigestMD5, MD5_SIZE) == false)
			{
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->DigestMD5, MD5_SIZE);
				CfgAddStr(ff, "DigestMD5", tmp);
			}

			if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false)
			{
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->DigestSHA1, SHA1_SIZE);
				CfgAddStr(ff, "DigestSHA1", tmp);
			}

			if (crl->Serial != NULL)
			{
				char tmp[MAX_SIZE];

				BinToStr(tmp, sizeof(tmp), crl->Serial->data, crl->Serial->size);
				CfgAddStr(ff, "Serial", tmp);
			}
		}
	}
	UnlockList(o);
}

// Read the certificate revocation list
void SiLoadCrlList(LIST *o, FOLDER *f)
{
	// Validate arguments
	if (o == NULL || f == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		TOKEN_LIST *t;

		t = CfgEnumFolderToTokenList(f);

		for (i = 0;i < t->NumTokens;i++)
		{
			CRL *crl;
			FOLDER *ff = CfgGetFolder(f, t->Token[i]);
			wchar_t cn[MAX_SIZE], org[MAX_SIZE], u[MAX_SIZE], c[MAX_SIZE],
				st[MAX_SIZE], l[MAX_SIZE];
			char tmp[MAX_SIZE];

			if (ff != NULL)
			{
				BUF *b;

				crl = ZeroMalloc(sizeof(CRL));

				CfgGetUniStr(ff, "CommonName", cn, sizeof(cn));
				CfgGetUniStr(ff, "Organization", org, sizeof(org));
				CfgGetUniStr(ff, "Unit", u, sizeof(u));
				CfgGetUniStr(ff, "Country", c, sizeof(c));
				CfgGetUniStr(ff, "State", st, sizeof(st));
				CfgGetUniStr(ff, "Local", l, sizeof(l));

				crl->Name = NewName(cn, org, u, c, st, l);

				if (CfgGetStr(ff, "Serial", tmp, sizeof(tmp)))
				{
					b = StrToBin(tmp);

					if (b != NULL)
					{
						if (b->Size >= 1)
						{
							crl->Serial = NewXSerial(b->Buf, b->Size);
						}

						FreeBuf(b);
					}
				}

				if (CfgGetStr(ff, "DigestMD5", tmp, sizeof(tmp)))
				{
					b = StrToBin(tmp);

					if (b != NULL)
					{
						if (b->Size == MD5_SIZE)
						{
							Copy(crl->DigestMD5, b->Buf, MD5_SIZE);
						}

						FreeBuf(b);
					}
				}

				if (CfgGetStr(ff, "DigestSHA1", tmp, sizeof(tmp)))
				{
					b = StrToBin(tmp);

					if (b != NULL)
					{
						if (b->Size == SHA1_SIZE)
						{
							Copy(crl->DigestSHA1, b->Buf, SHA1_SIZE);
						}

						FreeBuf(b);
					}
				}

				Insert(o, crl);
			}
		}

		FreeToken(t);
	}
	UnlockList(o);
}

// Write the certificates list
void SiWriteCertList(FOLDER *f, LIST *o)
{
	// Validate arguments
	if (f == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		X *x;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			char name[MAX_SIZE];
			BUF *b;
			x = LIST_DATA(o, i);
			Format(name, sizeof(name), "Cert%u", i);
			b = XToBuf(x, false);
			if (b != NULL)
			{
				CfgAddBuf(CfgCreateFolder(f, name), "X509", b);
				FreeBuf(b);
			}
		}
	}
	UnlockList(o);
}

// Read the certificates list
void SiLoadCertList(LIST *o, FOLDER *f)
{
	// Validate arguments
	if (o == NULL || f == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		TOKEN_LIST *t;

		t = CfgEnumFolderToTokenList(f);

		for (i = 0;i < t->NumTokens;i++)
		{
			FOLDER *ff = CfgGetFolder(f, t->Token[i]);
			BUF *b;

			b = CfgGetBuf(ff, "X509");
			if (b != NULL)
			{
				X *x = BufToX(b, false);
				if (x != NULL)
				{
					Insert(o, x);
				}
				FreeBuf(b);
			}
		}

		FreeToken(t);
	}
	UnlockList(o);
}

// Write the database
void SiWriteHubDb(FOLDER *f, HUBDB *db, bool no_save_ac_list)
{
	// Validate arguments
	if (f == NULL || db == NULL)
	{
		return;
	}

	SiWriteUserList(CfgCreateFolder(f, "UserList"), db->UserList);
	SiWriteGroupList(CfgCreateFolder(f, "GroupList"), db->GroupList);
	SiWriteCertList(CfgCreateFolder(f, "CertList"), db->RootCertList);
	SiWriteCrlList(CfgCreateFolder(f, "CrlList"), db->CrlList);

	if (no_save_ac_list == false)
	{
		SiWriteAcList(CfgCreateFolder(f, "IPAccessControlList"), db->AcList);
	}
}

// Read the database
void SiLoadHubDb(HUB *h, FOLDER *f)
{
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	SiLoadGroupList(h, CfgGetFolder(f, "GroupList"));
	SiLoadUserList(h, CfgGetFolder(f, "UserList"));

	if (h->HubDb != NULL)
	{
		SiLoadCertList(h->HubDb->RootCertList, CfgGetFolder(f, "CertList"));
		SiLoadCrlList(h->HubDb->CrlList, CfgGetFolder(f, "CrlList"));
		SiLoadAcList(h->HubDb->AcList, CfgGetFolder(f, "IPAccessControlList"));
	}
}

// Write the Virtual HUB setting
void SiWriteHubCfg(FOLDER *f, HUB *h)
{
	// Validate arguments
	if (f == NULL || h == NULL)
	{
		return;
	}

	// Radius server name
	Lock(h->RadiusOptionLock);
	{
		if (h->RadiusServerName != NULL)
		{
			CfgAddStr(f, "RadiusServerName", h->RadiusServerName);
			CfgAddBuf(f, "RadiusSecret", h->RadiusSecret);
		}
		CfgAddInt(f, "RadiusServerPort", h->RadiusServerPort);
		CfgAddInt(f, "RadiusRetryInterval", h->RadiusRetryInterval);
		CfgAddStr(f, "RadiusSuffixFilter", h->RadiusSuffixFilter);
		CfgAddStr(f, "RadiusRealm", h->RadiusRealm);

		CfgAddBool(f, "RadiusConvertAllMsChapv2AuthRequestToEap", h->RadiusConvertAllMsChapv2AuthRequestToEap);
		CfgAddBool(f, "RadiusUsePeapInsteadOfEap", h->RadiusUsePeapInsteadOfEap);
	}
	Unlock(h->RadiusOptionLock);

	// Password
	CfgAddByte(f, "HashedPassword", h->HashedPassword, sizeof(h->HashedPassword));
	CfgAddByte(f, "SecurePassword", h->SecurePassword, sizeof(h->SecurePassword));

	// Online / Offline flag
	if (h->Cedar->Bridge == false)
	{
		CfgAddBool(f, "Online", (h->Offline && (h->HubIsOnlineButHalting == false)) ? false : true);
	}

	// Traffic information
	SiWriteTraffic(f, "Traffic", h->Traffic);

	// HUB options
	SiWriteHubOptionCfg(CfgCreateFolder(f, "Option"), h->Option);

	// Message
	{
		FOLDER *folder = CfgCreateFolder(f, "Message");

		if (IsEmptyUniStr(h->Msg) == false)
		{
			CfgAddUniStr(folder, "MessageText", h->Msg);
		}
	}

	// HUB_LOG
	SiWriteHubLogCfg(CfgCreateFolder(f, "LogSetting"), &h->LogSetting);

	if (h->Type == HUB_TYPE_STANDALONE)
	{
		// Link list
		SiWriteHubLinks(CfgCreateFolder(f, "CascadeList"), h);
	}

	if (h->Type != HUB_TYPE_FARM_STATIC)
	{
		if (GetServerCapsBool(h->Cedar->Server, "b_support_securenat"))
		{
			// SecureNAT
			SiWriteSecureNAT(h, CfgCreateFolder(f, "SecureNAT"));
		}
	}

	// Access list
	SiWriteHubAccessLists(CfgCreateFolder(f, "AccessList"), h);

	// Administration options
	SiWriteHubAdminOptions(CfgCreateFolder(f, "AdminOption"), h);

	// Type of HUB
	CfgAddInt(f, "Type", h->Type);

	// Database
	if (h->Cedar->Bridge == false)
	{
		SiWriteHubDb(CfgCreateFolder(f, "SecurityAccountDatabase"), h->HubDb,
			false
			);
	}

	// Usage status
	CfgAddInt64(f, "LastCommTime", h->LastCommTime);
	CfgAddInt64(f, "LastLoginTime", h->LastLoginTime);
	CfgAddInt64(f, "CreatedTime", h->CreatedTime);
	CfgAddInt(f, "NumLogin", h->NumLogin);
}

// Read the logging options
void SiLoadHubLogCfg(HUB_LOG *g, FOLDER *f)
{
	// Validate arguments
	if (f == NULL || g == NULL)
	{
		return;
	}

	Zero(g, sizeof(HUB_LOG));
	g->SaveSecurityLog = CfgGetBool(f, "SaveSecurityLog");
	g->SecurityLogSwitchType = CfgGetInt(f, "SecurityLogSwitchType");
	g->SavePacketLog = CfgGetBool(f, "SavePacketLog");
	g->PacketLogSwitchType = CfgGetInt(f, "PacketLogSwitchType");

	g->PacketLogConfig[PACKET_LOG_TCP_CONN] = CfgGetInt(f, "PACKET_LOG_TCP_CONN");
	g->PacketLogConfig[PACKET_LOG_TCP] = CfgGetInt(f, "PACKET_LOG_TCP");
	g->PacketLogConfig[PACKET_LOG_DHCP] = CfgGetInt(f, "PACKET_LOG_DHCP");
	g->PacketLogConfig[PACKET_LOG_UDP] = CfgGetInt(f, "PACKET_LOG_UDP");
	g->PacketLogConfig[PACKET_LOG_ICMP] = CfgGetInt(f, "PACKET_LOG_ICMP");
	g->PacketLogConfig[PACKET_LOG_IP] = CfgGetInt(f, "PACKET_LOG_IP");
	g->PacketLogConfig[PACKET_LOG_ARP] = CfgGetInt(f, "PACKET_LOG_ARP");
	g->PacketLogConfig[PACKET_LOG_ETHERNET] = CfgGetInt(f, "PACKET_LOG_ETHERNET");
}

// Write the logging options
void SiWriteHubLogCfg(FOLDER *f, HUB_LOG *g)
{
	SiWriteHubLogCfgEx(f, g, false);
}
void SiWriteHubLogCfgEx(FOLDER *f, HUB_LOG *g, bool el_mode)
{
	// Validate arguments
	if (f == NULL || g == NULL)
	{
		return;
	}

	if (el_mode == false)
	{
		CfgAddBool(f, "SaveSecurityLog", g->SaveSecurityLog);
		CfgAddInt(f, "SecurityLogSwitchType", g->SecurityLogSwitchType);
		CfgAddBool(f, "SavePacketLog", g->SavePacketLog);
	}

	CfgAddInt(f, "PacketLogSwitchType", g->PacketLogSwitchType);

	CfgAddInt(f, "PACKET_LOG_TCP_CONN", g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
	CfgAddInt(f, "PACKET_LOG_TCP", g->PacketLogConfig[PACKET_LOG_TCP]);
	CfgAddInt(f, "PACKET_LOG_DHCP", g->PacketLogConfig[PACKET_LOG_DHCP]);
	CfgAddInt(f, "PACKET_LOG_UDP", g->PacketLogConfig[PACKET_LOG_UDP]);
	CfgAddInt(f, "PACKET_LOG_ICMP", g->PacketLogConfig[PACKET_LOG_ICMP]);
	CfgAddInt(f, "PACKET_LOG_IP", g->PacketLogConfig[PACKET_LOG_IP]);
	CfgAddInt(f, "PACKET_LOG_ARP", g->PacketLogConfig[PACKET_LOG_ARP]);
	CfgAddInt(f, "PACKET_LOG_ETHERNET", g->PacketLogConfig[PACKET_LOG_ETHERNET]);
}

// Read the Virtual HUB settings
void SiLoadHubCfg(SERVER *s, FOLDER *f, char *name)
{
	HUB *h;
	CEDAR *c;
	HUB_OPTION o;
	bool online;
	UINT hub_old_type = 0;
	// Validate arguments
	if (s == NULL || f == NULL || name == NULL)
	{
		return;
	}

	c = s->Cedar;

	// Get the option
	Zero(&o, sizeof(o));
	SiLoadHubOptionCfg(CfgGetFolder(f, "Option"), &o);

	// Create a HUB
	h = NewHub(c, name, &o);
	if (h != NULL)
	{
		HUB_LOG g;
		// Radius server settings
		Lock(h->RadiusOptionLock);
		{
			char name[MAX_SIZE];
			BUF *secret;
			UINT port;
			UINT interval;

			port = CfgGetInt(f, "RadiusServerPort");
			interval = CfgGetInt(f, "RadiusRetryInterval");

			CfgGetStr(f, "RadiusSuffixFilter", h->RadiusSuffixFilter, sizeof(h->RadiusSuffixFilter));
			CfgGetStr(f, "RadiusRealm", h->RadiusRealm, sizeof(h->RadiusRealm));

			h->RadiusConvertAllMsChapv2AuthRequestToEap = CfgGetBool(f, "RadiusConvertAllMsChapv2AuthRequestToEap");
			h->RadiusUsePeapInsteadOfEap = CfgGetBool(f, "RadiusUsePeapInsteadOfEap");

			if (interval == 0)
			{
				interval = RADIUS_RETRY_INTERVAL;
			}

			if (port != 0 && CfgGetStr(f, "RadiusServerName", name, sizeof(name)))
			{
				secret = CfgGetBuf(f, "RadiusSecret");
				if (secret != NULL)
				{
					char secret_str[MAX_SIZE];
					Zero(secret_str, sizeof(secret_str));
					if (secret->Size < sizeof(secret_str))
					{
						Copy(secret_str, secret->Buf, secret->Size);
					}
					secret_str[sizeof(secret_str) - 1] = 0;
					//SetRadiusServer(h, name, port, secret_str);
					SetRadiusServerEx(h, name, port, secret_str, interval);
					FreeBuf(secret);
				}
			}
		}
		Unlock(h->RadiusOptionLock);

		// Password
		if (CfgGetByte(f, "HashedPassword", h->HashedPassword, sizeof(h->HashedPassword)) != sizeof(h->HashedPassword))
		{
			Sha0(h->HashedPassword, "", 0);
		}
		if (CfgGetByte(f, "SecurePassword", h->SecurePassword, sizeof(h->SecurePassword)) != sizeof(h->SecurePassword))
		{
			HashPassword(h->SecurePassword, ADMINISTRATOR_USERNAME, "");
		}

		// Log Settings
		Zero(&g, sizeof(g));
		SiLoadHubLogCfg(&g, CfgGetFolder(f, "LogSetting"));
		SetHubLogSetting(h, &g);

		// Online / Offline flag
		if (h->Cedar->Bridge == false)
		{
			online = CfgGetBool(f, "Online");
		}
		else
		{
			online = true;
		}

		// Traffic information
		SiLoadTraffic(f, "Traffic", h->Traffic);

		// Access list
		SiLoadHubAccessLists(h, CfgGetFolder(f, "AccessList"));

		// Type of HUB
		hub_old_type = h->Type = CfgGetInt(f, "Type");

		if (s->ServerType == SERVER_TYPE_STANDALONE)
		{
			if (h->Type != HUB_TYPE_STANDALONE)
			{
				// Change the type of all HUB to a stand-alone if the server is a stand-alone
				h->Type = HUB_TYPE_STANDALONE;
			}
		}
		else
		{
			if (h->Type == HUB_TYPE_STANDALONE)
			{
				// If the server is a farm controller, change the type of HUB to the farm supported types
				h->Type = HUB_TYPE_FARM_DYNAMIC;
			}
		}

		if (h->Type == HUB_TYPE_FARM_DYNAMIC)
		{
			h->CurrentVersion = h->LastVersion = 1;
		}

		// Message
		{
			FOLDER *folder = CfgGetFolder(f, "Message");
			if (folder != NULL)
			{
				wchar_t *tmp = Malloc(sizeof(wchar_t) * (HUB_MAXMSG_LEN + 1));
				if (CfgGetUniStr(folder, "MessageText", tmp, sizeof(wchar_t) * (HUB_MAXMSG_LEN + 1)))
				{
					SetHubMsg(h, tmp);
				}
				Free(tmp);
			}
		}

		// Link list
		if (h->Type == HUB_TYPE_STANDALONE)
		{
			// The link list is used only on stand-alone HUB
			// In VPN Gate hubs, don't load this
			{
				SiLoadHubLinks(h, CfgGetFolder(f, "CascadeList"));
			}
		}

		// SecureNAT
		if (GetServerCapsBool(h->Cedar->Server, "b_support_securenat"))
		{
			if (h->Type == HUB_TYPE_STANDALONE || h->Type == HUB_TYPE_FARM_DYNAMIC)
			{
				// SecureNAT is used only in the case of dynamic HUB or standalone HUB
				SiLoadSecureNAT(h, CfgGetFolder(f, "SecureNAT"));

				if (h->Type != HUB_TYPE_STANDALONE && h->Cedar != NULL && h->Cedar->Server != NULL &&
					h->Cedar->Server->ServerType == SERVER_TYPE_FARM_CONTROLLER)
				{
					NiClearUnsupportedVhOptionForDynamicHub(h->SecureNATOption,
						hub_old_type == HUB_TYPE_STANDALONE);
				}

			}
		}

		// Administration options
		SiLoadHubAdminOptions(h, CfgGetFolder(f, "AdminOption"));

		// Database
		if (h->Cedar->Bridge == false)
		{
			SiLoadHubDb(h, CfgGetFolder(f, "SecurityAccountDatabase"));
		}

		// Usage status
		h->LastCommTime = CfgGetInt64(f, "LastCommTime");
		if (h->LastCommTime == 0)
		{
			h->LastCommTime = SystemTime64();
		}
		h->LastLoginTime = CfgGetInt64(f, "LastLoginTime");
		if (h->LastLoginTime == 0)
		{
			h->LastLoginTime = SystemTime64();
		}
		h->CreatedTime = CfgGetInt64(f, "CreatedTime");
		h->NumLogin = CfgGetInt(f, "NumLogin");

		// Start the operation of the HUB
		AddHub(c, h);

		if (online)
		{
			h->Offline = true;
			SetHubOnline(h);
		}
		else
		{
			h->Offline = false;
			SetHubOffline(h);
		}

		WaitLogFlush(h->SecurityLogger);
		WaitLogFlush(h->PacketLogger);

		ReleaseHub(h);
	}
}

// Read the SecureNAT configuration
void SiLoadSecureNAT(HUB *h, FOLDER *f)
{
	VH_OPTION o;
	// Validate arguments
	if (h == NULL || f == NULL)
	{
		return;
	}

	// Read the VH_OPTION
	NiLoadVhOptionEx(&o, f);

	// Set the VH_OPTION
	Copy(h->SecureNATOption, &o, sizeof(VH_OPTION));

	EnableSecureNAT(h, CfgGetBool(f, "Disabled") ? false : true);
}

// Read the virtual layer 3 switch settings
void SiLoadL3SwitchCfg(L3SW *sw, FOLDER *f)
{
	UINT i;
	FOLDER *if_folder, *table_folder;
	TOKEN_LIST *t;
	bool active = false;
	// Validate arguments
	if (sw == NULL || f == NULL)
	{
		return;
	}

	active = CfgGetBool(f, "Active");

	// Interface list
	if_folder = CfgGetFolder(f, "InterfaceList");
	if (if_folder != NULL)
	{
		t = CfgEnumFolderToTokenList(if_folder);
		if (t != NULL)
		{
			for (i = 0;i < t->NumTokens;i++)
			{
				FOLDER *ff = CfgGetFolder(if_folder, t->Token[i]);
				char name[MAX_HUBNAME_LEN + 1];
				UINT ip, subnet;

				CfgGetStr(ff, "HubName", name, sizeof(name));
				ip = CfgGetIp32(ff, "IpAddress");
				subnet = CfgGetIp32(ff, "SubnetMask");

				{
					L3AddIf(sw, name, ip, subnet);
				}
			}
			FreeToken(t);
		}
	}

	// Routing table
	table_folder = CfgGetFolder(f, "RoutingTable");
	if (table_folder != NULL)
	{
		t = CfgEnumFolderToTokenList(table_folder);
		if (t != NULL)
		{
			for (i = 0;i < t->NumTokens;i++)
			{
				FOLDER *ff = CfgGetFolder(table_folder, t->Token[i]);
				L3TABLE tbl;

				Zero(&tbl, sizeof(tbl));
				tbl.NetworkAddress = CfgGetIp32(ff, "NetworkAddress");
				tbl.SubnetMask = CfgGetIp32(ff, "SubnetMask");
				tbl.GatewayAddress = CfgGetIp32(ff, "GatewayAddress");
				tbl.Metric = CfgGetInt(ff, "Metric");

				L3AddTable(sw, &tbl);
			}
			FreeToken(t);
		}
	}

	if (active)
	{
		L3SwStart(sw);
	}
}

// Write the virtual layer 3 switch settings
void SiWriteL3SwitchCfg(FOLDER *f, L3SW *sw)
{
	UINT i;
	FOLDER *if_folder, *table_folder;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (f == NULL || sw == NULL)
	{
		return;
	}

	// Active flag
	CfgAddBool(f, "Active", sw->Active);

	// Interface list
	if_folder = CfgCreateFolder(f, "InterfaceList");
	for (i = 0;i < LIST_NUM(sw->IfList);i++)
	{
		L3IF *e = LIST_DATA(sw->IfList, i);
		FOLDER *ff;

		Format(tmp, sizeof(tmp), "Interface%u", i);
		ff = CfgCreateFolder(if_folder, tmp);

		CfgAddStr(ff, "HubName", e->HubName);
		CfgAddIp32(ff, "IpAddress", e->IpAddress);
		CfgAddIp32(ff, "SubnetMask", e->SubnetMask);
	}

	// Routing table
	table_folder = CfgCreateFolder(f, "RoutingTable");
	for (i = 0;i < LIST_NUM(sw->TableList);i++)
	{
		L3TABLE *e = LIST_DATA(sw->TableList, i);
		FOLDER *ff;

		Format(tmp, sizeof(tmp), "Entry%u", i);
		ff = CfgCreateFolder(table_folder, tmp);

		CfgAddIp32(ff, "NetworkAddress", e->NetworkAddress);
		CfgAddIp32(ff, "SubnetMask", e->SubnetMask);
		CfgAddIp32(ff, "GatewayAddress", e->GatewayAddress);
		CfgAddInt(ff, "Metric", e->Metric);
	}
}

// Read the Virtual Layer 3 switch list
void SiLoadL3Switchs(SERVER *s, FOLDER *f)
{
	UINT i;
	TOKEN_LIST *t;
	CEDAR *c;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}
	c = s->Cedar;

	t = CfgEnumFolderToTokenList(f);
	if (t != NULL)
	{
		for (i = 0;i < t->NumTokens;i++)
		{
			char *name = t->Token[i];
			L3SW *sw = L3AddSw(c, name);

			SiLoadL3SwitchCfg(sw, CfgGetFolder(f, name));

			ReleaseL3Sw(sw);
		}
	}
	FreeToken(t);
}

// Write the Virtual Layer 3 switch list
void SiWriteL3Switchs(FOLDER *f, SERVER *s)
{
	UINT i;
	FOLDER *folder;
	CEDAR *c;
	// Validate arguments
	if (f == NULL || s == NULL)
	{
		return;
	}
	c = s->Cedar;

	LockList(c->L3SwList);
	{
		for (i = 0;i < LIST_NUM(c->L3SwList);i++)
		{
			L3SW *sw = LIST_DATA(c->L3SwList, i);

			Lock(sw->lock);
			{
				folder = CfgCreateFolder(f, sw->Name);

				SiWriteL3SwitchCfg(folder, sw);
			}
			Unlock(sw->lock);
		}
	}
	UnlockList(c->L3SwList);
}

// Read the IPsec server configuration
void SiLoadIPsec(SERVER *s, FOLDER *f)
{
	IPSEC_SERVICES sl;
	FOLDER *list_folder;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	Zero(&sl, sizeof(sl));

	CfgGetStr(f, "IPsec_Secret", sl.IPsec_Secret, sizeof(sl.IPsec_Secret));
	CfgGetStr(f, "L2TP_DefaultHub", sl.L2TP_DefaultHub, sizeof(sl.L2TP_DefaultHub));

	if (s->ServerType == SERVER_TYPE_STANDALONE)
	{
		// IPsec feature only be enabled on a standalone server
		sl.L2TP_Raw = CfgGetBool(f, "L2TP_Raw");
		sl.L2TP_IPsec = CfgGetBool(f, "L2TP_IPsec");
		sl.EtherIP_IPsec = CfgGetBool(f, "EtherIP_IPsec");
	}

	IPsecServerSetServices(s->IPsecServer, &sl);

	list_folder = CfgGetFolder(f, "EtherIP_IDSettingsList");

	if (list_folder != NULL)
	{
		TOKEN_LIST *t = CfgEnumFolderToTokenList(list_folder);
		if (t != NULL)
		{
			UINT i;

			for (i = 0;i < t->NumTokens;i++)
			{
				char *name = t->Token[i];
				FOLDER *f = CfgGetFolder(list_folder, name);

				if (f != NULL)
				{
					ETHERIP_ID d;
					BUF *b;

					Zero(&d, sizeof(d));

					StrCpy(d.Id, sizeof(d.Id), name);
					CfgGetStr(f, "HubName", d.HubName, sizeof(d.HubName));
					CfgGetStr(f, "UserName", d.UserName, sizeof(d.UserName));

					b = CfgGetBuf(f, "EncryptedPassword");
					if (b != NULL)
					{
						char *pass = DecryptPassword2(b);

						StrCpy(d.Password, sizeof(d.Password), pass);

						Free(pass);

						AddEtherIPId(s->IPsecServer, &d);

						FreeBuf(b);
					}
				}
			}

			FreeToken(t);
		}
	}
}

// Write the IPsec server configuration
void SiWriteIPsec(FOLDER *f, SERVER *s)
{
	IPSEC_SERVICES sl;
	FOLDER *list_folder;
	UINT i;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	if (s->IPsecServer == NULL)
	{
		return;
	}

	Zero(&sl, sizeof(sl));
	IPsecServerGetServices(s->IPsecServer, &sl);

	CfgAddStr(f, "IPsec_Secret", sl.IPsec_Secret);
	CfgAddStr(f, "L2TP_DefaultHub", sl.L2TP_DefaultHub);

	CfgAddBool(f, "L2TP_Raw", sl.L2TP_Raw);
	CfgAddBool(f, "L2TP_IPsec", sl.L2TP_IPsec);
	CfgAddBool(f, "EtherIP_IPsec", sl.EtherIP_IPsec);

	list_folder = CfgCreateFolder(f, "EtherIP_IDSettingsList");

	Lock(s->IPsecServer->LockSettings);
	{
		for (i = 0;i < LIST_NUM(s->IPsecServer->EtherIPIdList);i++)
		{
			ETHERIP_ID *d = LIST_DATA(s->IPsecServer->EtherIPIdList, i);
			FOLDER *f;
			BUF *b;

			f = CfgCreateFolder(list_folder, d->Id);

			CfgAddStr(f, "HubName", d->HubName);
			CfgAddStr(f, "UserName", d->UserName);

			b = EncryptPassword2(d->Password);

			CfgAddBuf(f, "EncryptedPassword", b);

			FreeBuf(b);
		}
	}
	Unlock(s->IPsecServer->LockSettings);
}

// Write the license list
void SiWriteLicenseManager(FOLDER *f, SERVER *s)
{
}

// Read the license list
void SiLoadLicenseManager(SERVER *s, FOLDER *f)
{
}

// Write the Virtual HUB list
void SiWriteHubs(FOLDER *f, SERVER *s)
{
	UINT i;
	FOLDER *hub_folder;
	CEDAR *c;
	UINT num;
	HUB **hubs;
	// Validate arguments
	if (f == NULL || s == NULL)
	{
		return;
	}
	c = s->Cedar;

	LockList(c->HubList);
	{
		hubs = ToArray(c->HubList);
		num = LIST_NUM(c->HubList);

		for (i = 0;i < num;i++)
		{
			AddRef(hubs[i]->ref);
		}
	}
	UnlockList(c->HubList);

	for (i = 0;i < num;i++)
	{
		HUB *h = hubs[i];

		Lock(h->lock);
		{
			hub_folder = CfgCreateFolder(f, h->Name);
			SiWriteHubCfg(hub_folder, h);
		}
		Unlock(h->lock);

		ReleaseHub(h);

		if ((i % 30) == 1)
		{
			YieldCpu();
		}
	}

	Free(hubs);
}

// Read the Virtual HUB list
void SiLoadHubs(SERVER *s, FOLDER *f)
{
	UINT i;
	FOLDER *hub_folder;
	TOKEN_LIST *t;
	bool b = false;
	// Validate arguments
	if (f == NULL || s == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);
	for (i = 0;i < t->NumTokens;i++)
	{
		char *name = t->Token[i];


		if (s->Cedar->Bridge)
		{
			if (StrCmpi(name, SERVER_DEFAULT_BRIDGE_NAME) == 0)
			{
				// Read only the setting of Virtual HUB named "BRIDGE"
				// in the case of the Bridge
				b = true;
			}
			else
			{
				continue;
			}
		}
		hub_folder = CfgGetFolder(f, name);
		if (hub_folder != NULL)
		{
			SiLoadHubCfg(s, hub_folder, name);
		}
	}
	FreeToken(t);

	if (s->Cedar->Bridge && b == false)
	{
		// If there isn't "BRIDGE" virtual HUB setting, create it newly
		SiInitDefaultHubList(s);
	}
}

// Read the server-specific settings
void SiLoadServerCfg(SERVER *s, FOLDER *f)
{
	BUF *b;
	CEDAR *c;
	char tmp[MAX_SIZE];
	X *x = NULL;
	K *k = NULL;
	FOLDER *params_folder;
	UINT i;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	// Save interval related
	s->AutoSaveConfigSpan = CfgGetInt(f, "AutoSaveConfigSpan") * 1000;
	if (s->AutoSaveConfigSpan == 0)
	{
		s->AutoSaveConfigSpan = SERVER_FILE_SAVE_INTERVAL_DEFAULT;
	}
	else
	{
		s->AutoSaveConfigSpan = MAKESURE(s->AutoSaveConfigSpan, SERVER_FILE_SAVE_INTERVAL_MIN, SERVER_FILE_SAVE_INTERVAL_MAX);
	}

	i = CfgGetInt(f, "MaxConcurrentDnsClientThreads");
	if (i != 0)
	{
		SetGetIpThreadMaxNum(i);
	}
	else
	{
		SetGetIpThreadMaxNum(DEFAULT_GETIP_THREAD_MAX_NUM);
	}

	s->DontBackupConfig = CfgGetBool(f, "DontBackupConfig");

	CfgGetIp(f, "ListenIP", &s->ListenIP);
	ProtoSetListenIP(s->Proto, &s->ListenIP);

	if (CfgIsItem(f, "BackupConfigOnlyWhenModified"))
	{
		s->BackupConfigOnlyWhenModified = CfgGetBool(f, "BackupConfigOnlyWhenModified");
	}
	else
	{
		s->BackupConfigOnlyWhenModified = true;
	}

	// Server log switch type
	if (CfgIsItem(f, "ServerLogSwitchType"))
	{
		UINT st = CfgGetInt(f, "ServerLogSwitchType");

		SetLogSwitchType(s->Logger, st);
	}

	SetMaxLogSize(CfgGetInt64(f, "LoggerMaxLogSize"));

	params_folder = CfgGetFolder(f, "GlobalParams");
	SiLoadGlobalParamsCfg(params_folder);

	c = s->Cedar;
	Lock(c->lock);
	{
		FOLDER *ff;
		{
			UINT i;
			LIST *ports;

			// Load and set UDP ports
			CfgGetStr(f, "PortsUDP", tmp, sizeof(tmp));
			NormalizeIntListStr(tmp, sizeof(tmp), tmp, true, ", ");

			ports = StrToIntList(tmp, true);
			for (i = 0; i < LIST_NUM(ports); ++i)
			{
				AddInt(s->PortsUDP, *(UINT *)LIST_DATA(ports, i));
			}
			ReleaseIntList(ports);

			ProtoSetUdpPorts(s->Proto, s->PortsUDP);
		}
		{
			RPC_KEEP k;

			// Keep-alive related
			Zero(&k, sizeof(k));
			k.UseKeepConnect = CfgGetBool(f, "UseKeepConnect");
			CfgGetStr(f, "KeepConnectHost", k.KeepConnectHost, sizeof(k.KeepConnectHost));
			k.KeepConnectPort = CfgGetInt(f, "KeepConnectPort");
			k.KeepConnectProtocol = CfgGetInt(f, "KeepConnectProtocol");
			k.KeepConnectInterval = CfgGetInt(f, "KeepConnectInterval") * 1000;
			if (k.KeepConnectPort == 0)
			{
				k.KeepConnectPort = 80;
			}
			if (StrLen(k.KeepConnectHost) == 0)
			{
				StrCpy(k.KeepConnectHost, sizeof(k.KeepConnectHost), CLIENT_DEFAULT_KEEPALIVE_HOST);
			}
			if (k.KeepConnectInterval == 0)
			{
				k.KeepConnectInterval = KEEP_INTERVAL_DEFAULT * 1000;
			}
			if (k.KeepConnectInterval < 5000)
			{
				k.KeepConnectInterval = 5000;
			}
			if (k.KeepConnectInterval > 600000)
			{
				k.KeepConnectInterval = 600000;
			}

			Lock(s->Keep->lock);
			{
				KEEP *keep = s->Keep;
				keep->Enable = k.UseKeepConnect;
				keep->Server = true;
				StrCpy(keep->ServerName, sizeof(keep->ServerName), k.KeepConnectHost);
				keep->ServerPort = k.KeepConnectPort;
				keep->UdpMode = k.KeepConnectProtocol;
				keep->Interval = k.KeepConnectInterval;
			}
			Unlock(s->Keep->lock);
		}

		// syslog
		ff = CfgGetFolder(f, "SyslogSettings");
		if (ff != NULL && GetServerCapsBool(s, "b_support_syslog"))
		{
			SYSLOG_SETTING set;

			Zero(&set, sizeof(set));

			set.SaveType = CfgGetInt(ff, "SaveType");
			CfgGetStr(ff, "HostName", set.Hostname, sizeof(set.Hostname));
			set.Port = CfgGetInt(ff, "Port");

			SiSetSysLogSetting(s, &set);
		}

		// Proto
		ff = CfgGetFolder(f, "Proto");
		if (ff != NULL)
		{
			SiLoadProtoCfg(s->Proto, ff);
		}

		// Whether to disable the IPv6 listener
		s->Cedar->DisableIPv6Listener = CfgGetBool(f, "DisableIPv6Listener");

		// DoS
		s->DisableDosProtection = CfgGetBool(f, "DisableDosProtection");

		// Num Connections Per IP
		SetMaxConnectionsPerIp(CfgGetInt(f, "MaxConnectionsPerIP"));

		// MaxUnestablishedConnections
		SetMaxUnestablishedConnections(CfgGetInt(f, "MaxUnestablishedConnections"));

		// DeadLock
		s->DisableDeadLockCheck = CfgGetBool(f, "DisableDeadLockCheck");

		// Eraser
		SetEraserCheckInterval(CfgGetInt(f, "AutoDeleteCheckIntervalSecs"));
		s->Eraser = NewEraser(s->Logger, CfgGetInt64(f, "AutoDeleteCheckDiskFreeSpaceMin"));

		// WebUI
		s->UseWebUI = CfgGetBool(f, "UseWebUI");


		// WebTimePage
		s->UseWebTimePage = CfgGetBool(f, "UseWebTimePage");

		// NoLinuxArpFilter
		s->NoLinuxArpFilter = CfgGetBool(f, "NoLinuxArpFilter");

		// NoHighPriorityProcess
		s->NoHighPriorityProcess = CfgGetBool(f, "NoHighPriorityProcess");

		// NoDebugDump
		s->NoDebugDump = CfgGetBool(f, "NoDebugDump");
		if (s->NoDebugDump)
		{
#ifdef	OS_WIN32
			MsSetEnableMinidump(false);
#endif	// OS_WIN32
		}

		// Disable the NAT-traversal feature
		s->DisableNatTraversal = CfgGetBool(f, "DisableNatTraversal");

		// Disable IPsec's aggressive mode
		s->DisableIPsecAggressiveMode = CfgGetBool(f, "DisableIPsecAggressiveMode");

		if (s->Cedar->Bridge == false)
		{
			// Enable the VPN-over-ICMP
			if (CfgIsItem(f, "EnableVpnOverIcmp"))
			{
				s->EnableVpnOverIcmp = CfgGetBool(f, "EnableVpnOverIcmp");
			}
			else
			{
				s->EnableVpnOverIcmp = false;
			}

			// Enable the VPN-over-DNS
			if (CfgIsItem(f, "EnableVpnOverDns"))
			{
				s->EnableVpnOverDns = CfgGetBool(f, "EnableVpnOverDns");
			}
			else
			{
				s->EnableVpnOverDns = false;
			}
		}

		// Debug log
		s->SaveDebugLog = CfgGetBool(f, "SaveDebugLog");
		if (s->SaveDebugLog)
		{
			s->DebugLog = NewTinyLog();
		}

		// Let the client not to send a signature
		s->NoSendSignature = CfgGetBool(f, "NoSendSignature");

		// Server certificate
		b = CfgGetBuf(f, "ServerCert");
		if (b != NULL)
		{
			x = BufToX(b, false);
			FreeBuf(b);
		}

		// Server private key
		b = CfgGetBuf(f, "ServerKey");
		if (b != NULL)
		{
			k = BufToK(b, true, false, NULL);
			FreeBuf(b);
		}

		if (x == NULL || k == NULL || CheckXandK(x, k) == false)
		{
			FreeX(x);
			FreeK(k);
			SiGenerateDefaultCert(&x, &k);

			SetCedarCert(c, x, k);

			FreeX(x);
			FreeK(k);
		}
		else
		{
			SetCedarCert(c, x, k);

			FreeX(x);
			FreeK(k);
		}

		// Character which separates the username from the hub name
		if (CfgGetStr(f, "UsernameHubSeparator", tmp, sizeof(tmp)))
		{
			c->UsernameHubSeparator = IsPrintableAsciiChar(tmp[0]) ? tmp[0] : DEFAULT_USERNAME_HUB_SEPARATOR;
		}

		// Cipher Name
		if (CfgGetStr(f, "CipherName", tmp, sizeof(tmp)))
		{
			StrUpper(tmp);
			SetCedarCipherList(c, tmp);
		}

		// Traffic information
		Lock(c->TrafficLock);
		{
			SiLoadTraffic(f, "ServerTraffic", c->Traffic);
		}
		Unlock(c->TrafficLock);

		// Type of server
		s->UpdatedServerType = s->ServerType = CfgGetInt(f, "ServerType");

		// Password
		if (CfgGetByte(f, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword)) != sizeof(s->HashedPassword))
		{
			Sha0(s->HashedPassword, "", 0);
		}

		if (s->ServerType != SERVER_TYPE_STANDALONE)
		{
			// Performance ratio of the server
			s->Weight = CfgGetInt(f, "ClusterMemberWeight");
			if (s->Weight == 0)
			{
				s->Weight = FARM_DEFAULT_WEIGHT;
			}
		}
		else
		{
			s->Weight = FARM_DEFAULT_WEIGHT;
		}

		if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			s->ControllerOnly = CfgGetBool(f, "ControllerOnly");
		}

		if (s->ServerType != SERVER_TYPE_STANDALONE)
		{
			// NAT traversal can not be used in a cluster environment
			s->DisableNatTraversal = true;
		}

		if (s->Cedar->Bridge)
		{
			// NAT traversal function can not be used in the bridge environment
			s->DisableNatTraversal = true;
		}

		if (CfgGetStr(f, "PortsUDP", tmp, sizeof(tmp)))
		{
			UINT i;
			TOKEN_LIST *tokens;
			LIST *ports = s->PortsUDP;

			for (i = 0; i < LIST_NUM(ports); ++i)
			{
				Free(LIST_DATA(ports, i));
			}
			DeleteAll(ports);

			NormalizeIntListStr(tmp, sizeof(tmp), tmp, true, ", ");

			tokens = ParseTokenWithoutNullStr(tmp, ", ");
			for (i = 0; i < tokens->NumTokens; ++i)
			{
				char *str = tokens->Token[i];
				if (IsNum(str))
				{
					InsertIntDistinct(ports, ToInt(str));
				}
			}
			FreeToken(tokens);
		}

		if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
		{
			char tmp[6 * MAX_PUBLIC_PORT_NUM + 1];
			// Load the settings item in the case of farm members
			CfgGetStr(f, "ControllerName", s->ControllerName, sizeof(s->ControllerName));
			s->ControllerPort = CfgGetInt(f, "ControllerPort");
			CfgGetByte(f, "MemberPassword", s->MemberPassword, SHA1_SIZE);
			s->PublicIp = CfgGetIp32(f, "PublicIp");
			if (CfgGetStr(f, "PublicPorts", tmp, sizeof(tmp)))
			{
				TOKEN_LIST *t = ParseToken(tmp, ", ");
				UINT i;
				s->NumPublicPort = t->NumTokens;
				s->PublicPorts = ZeroMalloc(s->NumPublicPort * sizeof(UINT));
				for (i = 0;i < s->NumPublicPort;i++)
				{
					s->PublicPorts[i] = ToInt(t->Token[i]);
				}
				FreeToken(t);
			}
		}

		// Configuration of VPN Azure Client
		s->EnableVpnAzure = CfgGetBool(f, "EnableVpnAzure");

		// Disable GetHostName when accepting TCP
		s->DisableGetHostNameWhenAcceptTcp = CfgGetBool(f, "DisableGetHostNameWhenAcceptTcp");

		if (s->DisableGetHostNameWhenAcceptTcp)
		{
			DisableGetHostNameWhenAcceptInit();
		}

		// Disable core dump on UNIX
		s->DisableCoreDumpOnUnix = CfgGetBool(f, "DisableCoreDumpOnUnix");

		// Disable session reconnect
		SetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT, CfgGetBool(f, "DisableSessionReconnect"));

		c->SslAcceptSettings.Tls_Disable1_0 = CfgGetBool(f, "Tls_Disable1_0");
		c->SslAcceptSettings.Tls_Disable1_1 = CfgGetBool(f, "Tls_Disable1_1");
		c->SslAcceptSettings.Tls_Disable1_2 = CfgGetBool(f, "Tls_Disable1_2");

		s->StrictSyslogDatetimeFormat = CfgGetBool(f, "StrictSyslogDatetimeFormat");

		// Disable JSON-RPC Web API
		s->DisableJsonRpcWebApi = CfgGetBool(f, "DisableJsonRpcWebApi");

		// Bits of Diffie-Hellman parameters
		c->DhParamBits = CfgGetInt(f, "DhParamBits");
		if (c->DhParamBits == 0)
		{
			c->DhParamBits = DH_PARAM_BITS_DEFAULT;
		}

		SetDhParam(DhNewFromBits(c->DhParamBits));
	}
	Unlock(c->lock);

#ifdef	OS_UNIX
	if (s->DisableCoreDumpOnUnix)
	{
		UnixDisableCoreDump();
	}
#endif	// OS_UNIX
}

// Load global params
void SiLoadGlobalParamsCfg(FOLDER *f)
{
	SiLoadGlobalParamItem(GP_MAX_SEND_SOCKET_QUEUE_SIZE, CfgGetInt(f, "MAX_SEND_SOCKET_QUEUE_SIZE"));
	SiLoadGlobalParamItem(GP_MIN_SEND_SOCKET_QUEUE_SIZE, CfgGetInt(f, "MIN_SEND_SOCKET_QUEUE_SIZE"));
	SiLoadGlobalParamItem(GP_MAX_SEND_SOCKET_QUEUE_NUM, CfgGetInt(f, "MAX_SEND_SOCKET_QUEUE_NUM"));
	SiLoadGlobalParamItem(GP_SELECT_TIME, CfgGetInt(f, "SELECT_TIME"));
	SiLoadGlobalParamItem(GP_SELECT_TIME_FOR_NAT, CfgGetInt(f, "SELECT_TIME_FOR_NAT"));
	SiLoadGlobalParamItem(GP_MAX_STORED_QUEUE_NUM, CfgGetInt(f, "MAX_STORED_QUEUE_NUM"));
	SiLoadGlobalParamItem(GP_MAX_BUFFERING_PACKET_SIZE, CfgGetInt(f, "MAX_BUFFERING_PACKET_SIZE"));
	SiLoadGlobalParamItem(GP_HUB_ARP_SEND_INTERVAL, CfgGetInt(f, "HUB_ARP_SEND_INTERVAL"));
	SiLoadGlobalParamItem(GP_MAC_TABLE_EXPIRE_TIME, CfgGetInt(f, "MAC_TABLE_EXPIRE_TIME"));
	SiLoadGlobalParamItem(GP_IP_TABLE_EXPIRE_TIME, CfgGetInt(f, "IP_TABLE_EXPIRE_TIME"));
	SiLoadGlobalParamItem(GP_IP_TABLE_EXPIRE_TIME_DHCP, CfgGetInt(f, "IP_TABLE_EXPIRE_TIME_DHCP"));
	SiLoadGlobalParamItem(GP_STORM_CHECK_SPAN, CfgGetInt(f, "STORM_CHECK_SPAN"));
	SiLoadGlobalParamItem(GP_STORM_DISCARD_VALUE_START, CfgGetInt(f, "STORM_DISCARD_VALUE_START"));
	SiLoadGlobalParamItem(GP_STORM_DISCARD_VALUE_END, CfgGetInt(f, "STORM_DISCARD_VALUE_END"));
	SiLoadGlobalParamItem(GP_MAX_MAC_TABLES, CfgGetInt(f, "MAX_MAC_TABLES"));
	SiLoadGlobalParamItem(GP_MAX_IP_TABLES, CfgGetInt(f, "MAX_IP_TABLES"));
	SiLoadGlobalParamItem(GP_MAX_HUB_LINKS, CfgGetInt(f, "MAX_HUB_LINKS"));
	SiLoadGlobalParamItem(GP_MEM_FIFO_REALLOC_MEM_SIZE, CfgGetInt(f, "MEM_FIFO_REALLOC_MEM_SIZE"));
	SiLoadGlobalParamItem(GP_QUEUE_BUDGET, CfgGetInt(f, "QUEUE_BUDGET"));
	SiLoadGlobalParamItem(GP_FIFO_BUDGET, CfgGetInt(f, "FIFO_BUDGET"));

	SetFifoCurrentReallocMemSize(MEM_FIFO_REALLOC_MEM_SIZE);
}

// Load global param itesm
void SiLoadGlobalParamItem(UINT id, UINT value)
{
	// Validate arguments
	if (id == 0)
	{
		return;
	}

	vpn_global_parameters[id] = value;
}

// Write global params
void SiWriteGlobalParamsCfg(FOLDER *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	CfgAddInt(f, "MAX_SEND_SOCKET_QUEUE_SIZE", MAX_SEND_SOCKET_QUEUE_SIZE);
	CfgAddInt(f, "MIN_SEND_SOCKET_QUEUE_SIZE", MIN_SEND_SOCKET_QUEUE_SIZE);
	CfgAddInt(f, "MAX_SEND_SOCKET_QUEUE_NUM", MAX_SEND_SOCKET_QUEUE_NUM);
	CfgAddInt(f, "SELECT_TIME", SELECT_TIME);
	CfgAddInt(f, "SELECT_TIME_FOR_NAT", SELECT_TIME_FOR_NAT);
	CfgAddInt(f, "MAX_STORED_QUEUE_NUM", MAX_STORED_QUEUE_NUM);
	CfgAddInt(f, "MAX_BUFFERING_PACKET_SIZE", MAX_BUFFERING_PACKET_SIZE);
	CfgAddInt(f, "HUB_ARP_SEND_INTERVAL", HUB_ARP_SEND_INTERVAL);
	CfgAddInt(f, "MAC_TABLE_EXPIRE_TIME", MAC_TABLE_EXPIRE_TIME);
	CfgAddInt(f, "IP_TABLE_EXPIRE_TIME", IP_TABLE_EXPIRE_TIME);
	CfgAddInt(f, "IP_TABLE_EXPIRE_TIME_DHCP", IP_TABLE_EXPIRE_TIME_DHCP);
	CfgAddInt(f, "STORM_CHECK_SPAN", STORM_CHECK_SPAN);
	CfgAddInt(f, "STORM_DISCARD_VALUE_START", STORM_DISCARD_VALUE_START);
	CfgAddInt(f, "STORM_DISCARD_VALUE_END", STORM_DISCARD_VALUE_END);
	CfgAddInt(f, "MAX_MAC_TABLES", MAX_MAC_TABLES);
	CfgAddInt(f, "MAX_IP_TABLES", MAX_IP_TABLES);
	CfgAddInt(f, "MAX_HUB_LINKS", MAX_HUB_LINKS);
	CfgAddInt(f, "MEM_FIFO_REALLOC_MEM_SIZE", MEM_FIFO_REALLOC_MEM_SIZE);
	CfgAddInt(f, "QUEUE_BUDGET", QUEUE_BUDGET);
	CfgAddInt(f, "FIFO_BUDGET", FIFO_BUDGET);
}

// Write the server-specific settings
void SiWriteServerCfg(FOLDER *f, SERVER *s)
{
	BUF *b;
	CEDAR *c;
	FOLDER *params_folder;
	// Validate arguments
	if (f == NULL || s == NULL)
	{
		return;
	}

	CfgAddInt(f, "MaxConcurrentDnsClientThreads", GetGetIpThreadMaxNum());

	CfgAddInt(f, "CurrentBuild", s->Cedar->Build);

	CfgAddInt(f, "AutoSaveConfigSpan", s->AutoSaveConfigSpanSaved / 1000);

	CfgAddBool(f, "DontBackupConfig", s->DontBackupConfig);
	CfgAddBool(f, "BackupConfigOnlyWhenModified", s->BackupConfigOnlyWhenModified);

	CfgAddIp(f, "ListenIP", &s->ListenIP);

	{
		char str[MAX_SIZE];
		IntListToStr(str, sizeof(str), s->PortsUDP, ", ");
		CfgAddStr(f, "PortsUDP", str);
	}

	if (s->Logger != NULL)
	{
		CfgAddInt(f, "ServerLogSwitchType", s->Logger->SwitchType);
	}

	CfgAddInt64(f, "LoggerMaxLogSize", GetMaxLogSize());

	params_folder = CfgCreateFolder(f, "GlobalParams");

	if (params_folder != NULL)
	{
		SiWriteGlobalParamsCfg(params_folder);
	}

	c = s->Cedar;

	Lock(c->lock);
	{
		FOLDER *ff;
		Lock(s->Keep->lock);
		{
			KEEP *k = s->Keep;
			CfgAddBool(f, "UseKeepConnect", k->Enable);
			CfgAddStr(f, "KeepConnectHost", k->ServerName);
			CfgAddInt(f, "KeepConnectPort", k->ServerPort);
			CfgAddInt(f, "KeepConnectProtocol", k->UdpMode);
			CfgAddInt(f, "KeepConnectInterval", k->Interval / 1000);
		}
		Unlock(s->Keep->lock);

		// syslog
		ff = CfgCreateFolder(f, "SyslogSettings");
		if (ff != NULL)
		{
			SYSLOG_SETTING set;

			SiGetSysLogSetting(s, &set);

			CfgAddInt(ff, "SaveType", set.SaveType);
			CfgAddStr(ff, "HostName", set.Hostname);
			CfgAddInt(ff, "Port", set.Port);
		}

		// Proto
		ff = CfgCreateFolder(f, "Proto");
		if (ff != NULL)
		{
			SiWriteProtoCfg(ff, s->Proto);
		}

		// IPv6 listener disable setting
		CfgAddBool(f, "DisableIPv6Listener", s->Cedar->DisableIPv6Listener);

		// DoS
		CfgAddBool(f, "DisableDosProtection", s->DisableDosProtection);

		// MaxConnectionsPerIP
		CfgAddInt(f, "MaxConnectionsPerIP", GetMaxConnectionsPerIp());

		// MaxUnestablishedConnections
		CfgAddInt(f, "MaxUnestablishedConnections", GetMaxUnestablishedConnections());

		// DeadLock
		CfgAddBool(f, "DisableDeadLockCheck", s->DisableDeadLockCheck);

		// Eraser related
		CfgAddInt64(f, "AutoDeleteCheckDiskFreeSpaceMin", s->Eraser->MinFreeSpace);
		CfgAddInt(f, "AutoDeleteCheckIntervalSecs", GetEraserCheckInterval());

		// WebUI
		CfgAddBool(f, "UseWebUI", s->UseWebUI);


		// NoLinuxArpFilter
		if (GetOsInfo()->OsType == OSTYPE_LINUX)
		{
			CfgAddBool(f, "NoLinuxArpFilter", s->NoLinuxArpFilter);
		}

		// NoHighPriorityProcess
		CfgAddBool(f, "NoHighPriorityProcess", s->NoHighPriorityProcess);

#ifdef	OS_WIN32
		CfgAddBool(f, "NoDebugDump", s->NoDebugDump);
#endif	// OS_WIN32

		if (s->ServerType == SERVER_TYPE_STANDALONE)
		{
			if (c->Bridge == false)
			{
				// Disable the NAT-traversal feature
				CfgAddBool(f, "DisableNatTraversal", s->DisableNatTraversal);
			}
		}

		CfgAddBool(f, "DisableIPsecAggressiveMode", s->DisableIPsecAggressiveMode);

		if (c->Bridge == false)
		{
			// VPN over ICMP
			CfgAddBool(f, "EnableVpnOverIcmp", s->EnableVpnOverIcmp);

			// VPN over DNS
			CfgAddBool(f, "EnableVpnOverDns", s->EnableVpnOverDns);
		}

		// WebTimePage
		CfgAddBool(f, "UseWebTimePage", s->UseWebTimePage);

		// Debug log
		CfgAddBool(f, "SaveDebugLog", s->SaveDebugLog);

		// Let the client not to send a signature
		CfgAddBool(f, "NoSendSignature", s->NoSendSignature);

		// Server certificate
		b = XToBuf(c->ServerX, false);
		CfgAddBuf(f, "ServerCert", b);
		FreeBuf(b);

		// Server private key
		b = KToBuf(c->ServerK, false, NULL);
		CfgAddBuf(f, "ServerKey", b);
		FreeBuf(b);

		{
			// Character which separates the username from the hub name
			char str[2];
			StrCpy(str, sizeof(str), &c->UsernameHubSeparator);
			CfgAddStr(f, "UsernameHubSeparator", str);
		}

		// Traffic information
		Lock(c->TrafficLock);
		{
			SiWriteTraffic(f, "ServerTraffic", c->Traffic);
		}
		Unlock(c->TrafficLock);

		// Type of server
		if (s->Cedar->Bridge == false)
		{
			CfgAddInt(f, "ServerType", s->UpdatedServerType);
		}

		// Cipher Name
		CfgAddStr(f, "CipherName", s->Cedar->CipherList);

		// Password
		CfgAddByte(f, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword));

		if (s->UpdatedServerType == SERVER_TYPE_FARM_MEMBER)
		{
			char tmp[6 * MAX_PUBLIC_PORT_NUM + 1];
			UINT i;
			// Setting items in the case of farm members
			CfgAddStr(f, "ControllerName", s->ControllerName);
			CfgAddInt(f, "ControllerPort", s->ControllerPort);
			CfgAddByte(f, "MemberPassword", s->MemberPassword, SHA1_SIZE);
			CfgAddIp32(f, "PublicIp", s->PublicIp);
			tmp[0] = 0;
			for (i = 0;i < s->NumPublicPort;i++)
			{
				char tmp2[MAX_SIZE];
				ToStr(tmp2, s->PublicPorts[i]);
				StrCat(tmp, sizeof(tmp), tmp2);
				StrCat(tmp, sizeof(tmp), ",");
			}
			if (StrLen(tmp) >= 1)
			{
				if (tmp[StrLen(tmp) - 1] == ',')
				{
					tmp[StrLen(tmp) - 1] = 0;
				}
			}
			CfgAddStr(f, "PublicPorts", tmp);
		}

		if (s->UpdatedServerType != SERVER_TYPE_STANDALONE)
		{
			CfgAddInt(f, "ClusterMemberWeight", s->Weight);
		}

		if (s->UpdatedServerType == SERVER_TYPE_FARM_CONTROLLER)
		{
			CfgAddBool(f, "ControllerOnly", s->ControllerOnly);
		}

		// VPN Azure Client
		if (s->AzureClient != NULL)
		{
			CfgAddBool(f, "EnableVpnAzure", s->EnableVpnAzure);
		}

		CfgAddBool(f, "DisableGetHostNameWhenAcceptTcp", s->DisableGetHostNameWhenAcceptTcp);
		CfgAddBool(f, "DisableCoreDumpOnUnix", s->DisableCoreDumpOnUnix);

		CfgAddBool(f, "Tls_Disable1_0", c->SslAcceptSettings.Tls_Disable1_0);
		CfgAddBool(f, "Tls_Disable1_1", c->SslAcceptSettings.Tls_Disable1_1);
		CfgAddBool(f, "Tls_Disable1_2", c->SslAcceptSettings.Tls_Disable1_2);
		CfgAddInt(f, "DhParamBits", c->DhParamBits);

		// Disable session reconnect
		CfgAddBool(f, "DisableSessionReconnect", GetGlobalServerFlag(GSF_DISABLE_SESSION_RECONNECT));

		CfgAddBool(f, "StrictSyslogDatetimeFormat", s->StrictSyslogDatetimeFormat);

		// Disable JSON-RPC Web API
		CfgAddBool(f, "DisableJsonRpcWebApi", s->DisableJsonRpcWebApi);
	}
	Unlock(c->lock);
}

void SiLoadProtoCfg(PROTO *p, FOLDER *f)
{
	UINT i;

	if (p == NULL || f == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(p->Containers); ++i)
	{
		UINT j;
		const PROTO_CONTAINER *container = LIST_DATA(p->Containers, i);
		LIST *options = container->Options;
		FOLDER *ff = CfgGetFolder(f, container->Name);
		if (ff == NULL)
		{
			continue;
		}

		LockList(options);

		for (j = 0; j < LIST_NUM(options); ++j)
		{
			PROTO_OPTION *option = LIST_DATA(options, j);
			switch (option->Type)
			{
			case PROTO_OPTION_BOOL:
				option->Bool = CfgGetBool(ff, option->Name);
				break;
			case PROTO_OPTION_STRING:
			{
				UINT size;
				char buf[MAX_SIZE];
				if (CfgGetStr(ff, option->Name, buf, sizeof(buf)) == false)
				{
					continue;
				}

				size = StrLen(buf) + 1;
				option->String = ReAlloc(option->String, size);
				StrCpy(option->String, size, buf);

				break;
			}
			default:
				Debug("SiLoadProtoCfg(): unhandled option type %u!\n", option->Type);
			}
		}

		UnlockList(options);
	}
}

void SiWriteProtoCfg(FOLDER *f, PROTO *p)
{
	UINT i;

	if (f == NULL || p == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(p->Containers); ++i)
	{
		UINT j;
		const PROTO_CONTAINER *container = LIST_DATA(p->Containers, i);
		LIST *options = container->Options;
		FOLDER *ff = CfgCreateFolder(f, container->Name);

		LockList(options);

		for (j = 0; j < LIST_NUM(options); ++j)
		{
			const PROTO_OPTION *option = LIST_DATA(options, j);
			switch (option->Type)
			{
				case PROTO_OPTION_BOOL:
					CfgAddBool(ff, option->Name, option->Bool);
					break;
				case PROTO_OPTION_STRING:
					CfgAddStr(ff, option->Name, option->String);
					break;
				default:
					Debug("SiWriteProtoCfg(): unhandled option type %u!\n", option->Type);
			}
		}

		UnlockList(options);
	}
}

// Read the traffic information
void SiLoadTraffic(FOLDER *parent, char *name, TRAFFIC *t)
{
	FOLDER *f;
	// Validate arguments
	if (t != NULL)
	{
		Zero(t, sizeof(TRAFFIC));
	}
	if (parent == NULL || name == NULL || t == NULL)
	{
		return;
	}

	f = CfgGetFolder(parent, name);

	if (f == NULL)
	{
		return;
	}

	SiLoadTrafficInner(f, "SendTraffic", &t->Send);
	SiLoadTrafficInner(f, "RecvTraffic", &t->Recv);
}
void SiLoadTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e)
{
	FOLDER *f;
	// Validate arguments
	if (e != NULL)
	{
		Zero(e, sizeof(TRAFFIC_ENTRY));
	}
	if (parent == NULL || name == NULL || e == NULL)
	{
		return;
	}

	f = CfgGetFolder(parent, name);
	if (f == NULL)
	{
		return;
	}

	e->BroadcastCount = CfgGetInt64(f, "BroadcastCount");
	e->BroadcastBytes = CfgGetInt64(f, "BroadcastBytes");
	e->UnicastCount = CfgGetInt64(f, "UnicastCount");
	e->UnicastBytes = CfgGetInt64(f, "UnicastBytes");
}

// Write the traffic information
void SiWriteTraffic(FOLDER *parent, char *name, TRAFFIC *t)
{
	FOLDER *f;
	// Validate arguments
	if (parent == NULL || name == NULL || t == NULL)
	{
		return;
	}

	f = CfgCreateFolder(parent, name);

	SiWriteTrafficInner(f, "SendTraffic", &t->Send);
	SiWriteTrafficInner(f, "RecvTraffic", &t->Recv);
}
void SiWriteTrafficInner(FOLDER *parent, char *name, TRAFFIC_ENTRY *e)
{
	FOLDER *f;
	// Validate arguments
	if (parent == NULL || name == NULL || e == NULL)
	{
		return;
	}

	f = CfgCreateFolder(parent, name);
	CfgAddInt64(f, "BroadcastCount", e->BroadcastCount);
	CfgAddInt64(f, "BroadcastBytes", e->BroadcastBytes);
	CfgAddInt64(f, "UnicastCount", e->UnicastCount);
	CfgAddInt64(f, "UnicastBytes", e->UnicastBytes);
}

// Thread for writing configuration file
void SiSaverThread(THREAD *thread, void *param)
{
	SERVER *s = (SERVER *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (s->Halt == false)
	{
		// Save to the configuration file
		if (s->NoMoreSave == false)
		{
			SiWriteConfigurationFile(s);
		}

		Wait(s->SaveHaltEvent, s->AutoSaveConfigSpan);
	}
}

// Write to the configuration file
UINT SiWriteConfigurationFile(SERVER *s)
{
	UINT ret;
	// Validate arguments
	if (s == NULL)
	{
		return 0;
	}

	if (s->CfgRw == NULL)
	{
		return 0;
	}

	if (s->NoMoreSave)
	{
		return 0;
	}

	Lock(s->SaveCfgLock);
	{
		FOLDER *f;

		Debug("save: SiWriteConfigurationToCfg() start.\n");
		f = SiWriteConfigurationToCfg(s);
		Debug("save: SiWriteConfigurationToCfg() finished.\n");

		Debug("save: SaveCfgRw() start.\n");
		ret = SaveCfgRwEx(s->CfgRw, f, s->BackupConfigOnlyWhenModified ? s->ConfigRevision : INFINITE);
		Debug("save: SaveCfgRw() finished.\n");

		Debug("save: CfgDeleteFolder() start.\n");
		CfgDeleteFolder(f);
		Debug("save: CfgDeleteFolder() finished.\n");
	}
	Unlock(s->SaveCfgLock);

	return ret;
}

// Release the configuration
void SiFreeConfiguration(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	// Write to the configuration file
	SiWriteConfigurationFile(s);

	// Terminate the configuration file saving thread
	s->NoMoreSave = true;
	s->Halt = true;
	Set(s->SaveHaltEvent);
	WaitThread(s->SaveThread, INFINITE);

	ReleaseEvent(s->SaveHaltEvent);
	ReleaseThread(s->SaveThread);

	s->SaveHaltEvent = NULL;
	s->SaveThread = NULL;

	// Stop the protocols handler
	if (s->Proto != NULL)
	{
		ProtoDelete(s->Proto);
	}

	// Stop the IPsec server
	if (s->IPsecServer != NULL)
	{
		FreeIPsecServer(s->IPsecServer);
		s->IPsecServer = NULL;
	}

	// Terminate the DDNS client
	if (s->DDnsClient != NULL)
	{
		FreeDDNSClient(s->DDnsClient);
		s->DDnsClient = NULL;
	}

	// Terminate the VPN Azure client
	if (s->AzureClient != NULL)
	{
		FreeAzureClient(s->AzureClient);
		s->AzureClient = NULL;
	}

	FreeCfgRw(s->CfgRw);
	s->CfgRw = NULL;

	// Release the Ethernet 
	FreeEth();
}

// Initialize the StXxx related function
void StInit()
{
	if (server_lock != NULL)
	{
		return;
	}

	server_lock = NewLock();
}

// Release the StXxx related function
void StFree()
{
	DeleteLock(server_lock);
	server_lock = NULL;
}

// Start the server
void StStartServer(bool bridge)
{
	Lock(server_lock);
	{
		if (server != NULL)
		{
			// It has already started
			Unlock(server_lock);
			return;
		}

		// Create a server
		server = SiNewServer(bridge);
	}
	Unlock(server_lock);

//	StartCedarLog();
}

// Stop the server
void StStopServer()
{
	Lock(server_lock);
	{
		if (server == NULL)
		{
			// Not started
			Unlock(server_lock);
			return;
		}

		// Release the server
		SiReleaseServer(server);
		server = NULL;
	}
	Unlock(server_lock);

	StopCedarLog();
}

// Set the type of server
void SiSetServerType(SERVER *s, UINT type,
					 UINT ip, UINT num_port, UINT *ports,
					 char *controller_name, UINT controller_port, UCHAR *password, UINT weight, bool controller_only)
{
	bool bridge;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}
	if (type == SERVER_TYPE_FARM_MEMBER &&
		(num_port == 0 || ports == NULL || controller_name == NULL ||
		controller_port == 0 || password == NULL || num_port > MAX_PUBLIC_PORT_NUM))
	{
		return;
	}
	if (weight == 0)
	{
		weight = FARM_DEFAULT_WEIGHT;
	}

	bridge = s->Cedar->Bridge;

	Lock(s->lock);
	{
		// Update types
		s->UpdatedServerType = type;

		s->Weight = weight;

		// Set the value
		if (type == SERVER_TYPE_FARM_MEMBER)
		{
			StrCpy(s->ControllerName, sizeof(s->ControllerName), controller_name);
			s->ControllerPort = controller_port;
			if (IsZero(password, SHA1_SIZE) == false)
			{
				Copy(s->MemberPassword, password, SHA1_SIZE);
			}
			s->PublicIp = ip;
			s->NumPublicPort = num_port;
			if (s->PublicPorts != NULL)
			{
				Free(s->PublicPorts);
			}
			s->PublicPorts = ZeroMalloc(num_port * sizeof(UINT));
			Copy(s->PublicPorts, ports, num_port * sizeof(UINT));
		}

		if (type == SERVER_TYPE_FARM_CONTROLLER)
		{
			s->ControllerOnly = controller_only;
		}
	}
	Unlock(s->lock);

	// Restart the server
	SiRebootServer(bridge);
}

// Thread to restart the server
void SiRebootServerThread(THREAD *thread, void *param)
{
	// Validate arguments
	if (thread == NULL)
	{
		return;
	}

	if (server == NULL)
	{
		return;
	}

	// Stop the server
	StStopServer();

	// Start the server
	StStartServer((bool)param);
}

// Restart the server
void SiRebootServer(bool bridge)
{
	SiRebootServerEx(bridge, false);
}
void SiRebootServerEx(bool bridge, bool reset_setting)
{
	THREAD *t;

	server_reset_setting = reset_setting;

	t = NewThread(SiRebootServerThread, (void *)bridge);
	ReleaseThread(t);
}

// Set the state of the special listener
void SiApplySpecialListenerStatus(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (s->DynListenerDns != NULL)
	{
		*s->DynListenerDns->EnablePtr = s->EnableVpnOverDns;
		ApplyDynamicListener(s->DynListenerDns);
	}

	if (s->DynListenerIcmp != NULL)
	{
		*s->DynListenerIcmp->EnablePtr = s->EnableVpnOverIcmp;
		ApplyDynamicListener(s->DynListenerIcmp);
	}
}

// Stop all listeners
void SiStopAllListener(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	SiLockListenerList(s);
	{
		UINT i;
		LIST *o = NewListFast(NULL);
		for (i = 0;i < LIST_NUM(s->ServerListenerList);i++)
		{
			SERVER_LISTENER *e = LIST_DATA(s->ServerListenerList, i);
			Add(o, e);
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			SERVER_LISTENER *e = LIST_DATA(o, i);
			SiDeleteListener(s, e->Port);
		}

		ReleaseList(o);
	}
	SiUnlockListenerList(s);

	ReleaseList(s->ServerListenerList);

	// Stop the VPN over ICMP listener
	FreeDynamicListener(s->DynListenerIcmp);
	s->DynListenerIcmp = NULL;

	// Stop the VPN over DNS listener
	FreeDynamicListener(s->DynListenerDns);
	s->DynListenerDns = NULL;
}

// Clean-up the server
void SiCleanupServer(SERVER *s)
{
	UINT i;
	CEDAR *c;
	LISTENER **listener_list;
	UINT num_listener;
	HUB **hub_list;
	UINT num_hub;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	SiFreeDeadLockCheck(s);


	c = s->Cedar;

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		// In the case of farm members, stop the connection to the farm controller
		SLog(c, "LS_STOP_FARM_MEMBER");
		SiStopConnectToController(s->FarmController);
		s->FarmController = NULL;
		SLog(c, "LS_STOP_FARM_MEMBER_2");
	}

	IncrementServerConfigRevision(s);

	SLog(c, "LS_END_2");

	SLog(c, "LS_STOP_ALL_LISTENER");
	// Stop all listeners
	LockList(c->ListenerList);
	{
		listener_list = ToArray(c->ListenerList);
		num_listener = LIST_NUM(c->ListenerList);
		for (i = 0;i < num_listener;i++)
		{
			AddRef(listener_list[i]->ref);
		}
	}
	UnlockList(c->ListenerList);

	for (i = 0;i < num_listener;i++)
	{
		StopListener(listener_list[i]);
		ReleaseListener(listener_list[i]);
	}
	Free(listener_list);
	SLog(c, "LS_STOP_ALL_LISTENER_2");

	SLog(c, "LS_STOP_ALL_HUB");
	// Stop all HUBs
	LockList(c->HubList);
	{
		hub_list = ToArray(c->HubList);
		num_hub = LIST_NUM(c->HubList);
		for (i = 0;i < num_hub;i++)
		{
			AddRef(hub_list[i]->ref);
		}
	}
	UnlockList(c->HubList);

	for (i = 0;i < num_hub;i++)
	{
		StopHub(hub_list[i]);
		ReleaseHub(hub_list[i]);
	}
	Free(hub_list);
	SLog(c, "LS_STOP_ALL_HUB_2");

	// Release the configuration
	SiFreeConfiguration(s);

	// Stop the Cedar
	SLog(c, "LS_STOP_CEDAR");
	StopCedar(s->Cedar);
	SLog(c, "LS_STOP_CEDAR_2");

	// Stop all listeners
	SiStopAllListener(s);

	ReleaseIntList(s->PortsUDP);

	if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// In the case of farm controller
		UINT i;

		SLog(c, "LS_STOP_FARM_CONTROL");

		// Stop the farm controling
		SiStopFarmControl(s);

		// Release the farm member information
		ReleaseList(s->FarmMemberList);
		s->FarmMemberList = NULL;

		for (i = 0;i < LIST_NUM(s->Me->HubList);i++)
		{
			Free(LIST_DATA(s->Me->HubList, i));
		}
		ReleaseList(s->Me->HubList);

		Free(s->Me);

		SLog(c, "LS_STOP_FARM_CONTROL_2");
	}

	if (s->PublicPorts != NULL)
	{
		Free(s->PublicPorts);
	}

	SLog(s->Cedar, "LS_END_1");
	SLog(s->Cedar, "L_LINE");

#ifdef	ENABLE_AZURE_SERVER
	if (s->AzureServer != NULL)
	{
		FreeAzureServer(s->AzureServer);
	}
#endif	// ENABLE_AZURE_SERVER

	ReleaseCedar(s->Cedar);
	DeleteLock(s->lock);
	DeleteLock(s->SaveCfgLock);

	StopKeep(s->Keep);

	FreeEraser(s->Eraser);


	FreeLog(s->Logger);

	FreeSysLog(s->Syslog);
	DeleteLock(s->SyslogLock);

	FreeServerCapsCache(s);

	SiFreeHubCreateHistory(s);

	// Stop the debug log
	FreeTinyLog(s->DebugLog);

	DeleteLock(s->TasksFromFarmControllerLock);
	DeleteLock(s->OpenVpnSstpConfigLock);


	Free(s);
}

// Release the server
void SiReleaseServer(SERVER *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		SiCleanupServer(s);
	}
}

// Get the URL of the member selector
bool SiGetMemberSelectorUrl(char *url, UINT url_size)
{
	BUF *b;
	bool ret = false;
	// Validate arguments
	if (url == NULL)
	{
		return false;
	}

	b = ReadDump(MEMBER_SELECTOR_TXT_FILENAME);
	if (b == NULL)
	{
		return false;
	}

	while (true)
	{
		char *line = CfgReadNextLine(b);
		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false && ret == false)
		{
			StrCpy(url, url_size, line);
			ret = true;
		}

		Free(line);
	}

	FreeBuf(b);

	return ret;
}

// Specify the farm member for the next processing
FARM_MEMBER *SiGetNextFarmMember(SERVER *s, CONNECTION *c, HUB *h)
{
	UINT i, num;
	UINT min_point = 0;
	FARM_MEMBER *ret = NULL;
	PACK *p;
	char url[MAX_SIZE];
	// Validate arguments
	if (s == NULL || s->ServerType != SERVER_TYPE_FARM_CONTROLLER || c == NULL || h == NULL)
	{
		return NULL;
	}

	num = LIST_NUM(s->FarmMemberList);
	if (num == 0)
	{
		return NULL;
	}

	if (SiGetMemberSelectorUrl(url, sizeof(url)))
	{
		UINT64 ret_key = 0;
		// Generate the data for the member selector
		p = NewPack();
		for (i = 0;i < num;i++)
		{
			UINT num_sessions;
			UINT max_sessions;
			FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
			bool do_not_select = false;
			if (s->ControllerOnly)
			{
				if (f->Me)
				{
					// No to select myself in the case of ControllerOnly
					do_not_select = true;
				}
			}

			if (f->Me == false)
			{
				num_sessions = f->NumSessions;
				max_sessions = f->MaxSessions;
			}
			else
			{
				num_sessions = Count(s->Cedar->CurrentSessions);
				max_sessions = GetServerCapsInt(s, "i_max_sessions");
			}

			if (max_sessions == 0)
			{
				max_sessions = GetServerCapsInt(s, "i_max_sessions");
			}

			if (num_sessions >= max_sessions)
			{
				do_not_select = true;
			}

			if (true)
			{
				UINT point = f->Point;
				char public_ip_str[MAX_SIZE];

				IPToStr32(public_ip_str, sizeof(public_ip_str), f->Ip);

				PackAddIntEx(p, "Point", point, i, num);
				PackAddInt64Ex(p, "Key", (UINT64)f, i, num);
				PackAddStrEx(p, "Hostname", f->hostname, i, num);
				PackAddStrEx(p, "PublicIp", public_ip_str, i, num);
				PackAddIntEx(p, "NumSessions", num_sessions, i, num);
				PackAddIntEx(p, "MaxSessions", max_sessions, i, num);
				PackAddIntEx(p, "AssignedClientLicense", f->AssignedClientLicense, i, num);
				PackAddIntEx(p, "AssignedBridgeLicense", f->AssignedBridgeLicense, i, num);
				PackAddIntEx(p, "Weight", f->Weight, i, num);
				PackAddDataEx(p, "RandomKey", f->RandomKey, SHA1_SIZE, i, num);
				PackAddIntEx(p, "NumTcpConnections", f->NumTcpConnections, i, num);
				PackAddIntEx(p, "NumHubs", LIST_NUM(f->HubList), i, num);
				PackAddBoolEx(p, "Me", f->Me, i, num);
				PackAddTime64Ex(p, "ConnectedTime", f->ConnectedTime, i, num);
				PackAddInt64Ex(p, "SystemId", f->SystemId, i, num);
				PackAddBoolEx(p, "DoNotSelect", do_not_select, i, num);
			}
		}

		if (true)
		{
			char client_ip_str[MAX_SIZE];
			UINT client_port = 0;
			UINT server_port = 0;
			SOCK *s = c->FirstSock;

			Zero(client_ip_str, sizeof(client_ip_str));
			if (s != NULL)
			{
				IPToStr(client_ip_str, sizeof(client_ip_str), &s->RemoteIP);
				client_port = s->RemotePort;
				server_port = s->LocalPort;
			}

			PackAddStr(p, "ClientIp", client_ip_str);
			PackAddInt(p, "ClientPort", client_port);
			PackAddInt(p, "ServerPort", server_port);

			PackAddInt(p, "ClientBuild", c->ClientBuild);
			PackAddStr(p, "CipherName", c->CipherName);
			PackAddStr(p, "ClientStr", c->ClientStr);
			PackAddInt(p, "ClientVer", c->ClientVer);
			PackAddTime64(p, "ConnectedTime", Tick64ToTime64(c->ConnectedTick));

			PackAddStr(p, "HubName", h->Name);
			PackAddBool(p, "StaticHub", h->Type == HUB_TYPE_FARM_STATIC);
		}

		PackAddInt(p, "NumMembers", num);

		// Make the member selector choose a member
		UnlockList(s->FarmMemberList);
		Unlock(s->Cedar->CedarSuperLock);
		{
			PACK *ret;

			Debug("Calling %s ...\n", url);

			ret = WpcCall(url, NULL, MEMBER_SELECTOR_CONNECT_TIMEOUT, MEMBER_SELECTOR_DATA_TIMEOUT,
				"Select", p, NULL, NULL, NULL);

			if (GetErrorFromPack(ret) == ERR_NO_ERROR)
			{
				ret_key = PackGetInt64(ret, "Key");
				Debug("Ret Key = %I64u\n", ret_key);
			}
			else
			{
				Debug("Error: %u\n", GetErrorFromPack(ret));
			}

			FreePack(ret);
		}
		Lock(s->Cedar->CedarSuperLock);
		LockList(s->FarmMemberList);

		FreePack(p);

		if (ret_key != 0)
		{
			FARM_MEMBER *f = (FARM_MEMBER *)ret_key;
			if (IsInList(s->FarmMemberList, f))
			{
				Debug("Farm Member Selected by Selector: %s\n", f->hostname);

				return f;
			}
			else
			{
				Debug("Farm Member Key = %I64u Not Found.\n", ret_key);
			}
		}
		else
		{
			// The member selector failed to select a member
			return NULL;
		}
	}

	num = LIST_NUM(s->FarmMemberList);
	if (num == 0)
	{
		return NULL;
	}

	for (i = 0;i < num;i++)
	{
		UINT num_sessions;
		UINT max_sessions;
		FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
		if (s->ControllerOnly)
		{
			if (f->Me)
			{
				// No to select myself in the case of ControllerOnly
				continue;
			}
		}

		if (f->Me == false)
		{
			num_sessions = f->NumSessions;
			max_sessions = f->MaxSessions;
		}
		else
		{
			num_sessions = Count(s->Cedar->CurrentSessions);
			max_sessions = GetServerCapsInt(s, "i_max_sessions");
		}

		if (max_sessions == 0)
		{
			max_sessions = GetServerCapsInt(s, "i_max_sessions");
		}

		if (num_sessions < max_sessions)
		{
			if (f->Point >= min_point)
			{
				min_point = f->Point;
				ret = f;
			}
		}
	}

	return ret;
}

// Receive a HUB enumeration directive
void SiCalledEnumHub(SERVER *s, PACK *p, PACK *req)
{
	UINT i;
	CEDAR *c;
	// Validate arguments
	if (s == NULL || p == NULL || req == NULL)
	{
		return;
	}


	c = s->Cedar;

	LockList(c->HubList);
	{
		UINT num = LIST_NUM(c->HubList);
		for (i = 0;i < num;i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);
			Lock(h->lock);
			{
				PackAddStrEx(p, "HubName", h->Name, i, num);
				PackAddIntEx(p, "HubType", h->Type, i, num);
				PackAddIntEx(p, "NumSession", Count(h->NumSessions), i, num);

				PackAddIntEx(p, "NumSessions", LIST_NUM(h->SessionList), i, num);
				PackAddIntEx(p, "NumSessionsClient", Count(h->NumSessionsClient), i, num);
				PackAddIntEx(p, "NumSessionsBridge", Count(h->NumSessionsBridge), i, num);

				PackAddIntEx(p, "NumMacTables", HASH_LIST_NUM(h->MacHashTable), i, num);

				PackAddIntEx(p, "NumIpTables", LIST_NUM(h->IpTable), i, num);

				PackAddTime64Ex(p, "LastCommTime", h->LastCommTime, i, num);
				PackAddTime64Ex(p, "CreatedTime", h->CreatedTime, i, num);
			}
			Unlock(h->lock);
		}
	}
	UnlockList(c->HubList);

	PackAddInt(p, "Point", SiGetPoint(s));
	PackAddInt(p, "NumTcpConnections", Count(s->Cedar->CurrentTcpConnections));
	PackAddInt(p, "NumTotalSessions", Count(s->Cedar->CurrentSessions));
	PackAddInt(p, "MaxSessions", GetServerCapsInt(s, "i_max_sessions"));

	PackAddInt(p, "AssignedClientLicense", Count(s->Cedar->AssignedClientLicense));
	PackAddInt(p, "AssignedBridgeLicense", Count(s->Cedar->AssignedBridgeLicense));

	PackAddData(p, "RandomKey", s->MyRandomKey, SHA1_SIZE);


	Lock(c->TrafficLock);
	{
		OutRpcTraffic(p, c->Traffic);
	}
	Unlock(c->TrafficLock);

	LockList(c->TrafficDiffList);
	{
		UINT num = LIST_NUM(c->TrafficDiffList);
		UINT i;

		for (i = 0;i < num;i++)
		{
			TRAFFIC_DIFF *d = LIST_DATA(c->TrafficDiffList, i);

			PackAddIntEx(p, "TdType", d->Type, i, num);
			PackAddStrEx(p, "TdHubName", d->HubName, i, num);
			PackAddStrEx(p, "TdName", d->Name, i, num);

			OutRpcTrafficEx(&d->Traffic, p, i, num);

			Free(d->HubName);
			Free(d->Name);
			Free(d);
		}

		DeleteAll(c->TrafficDiffList);
	}
	UnlockList(c->TrafficDiffList);
}

// Receive a HUB delete directive
void SiCalledDeleteHub(SERVER *s, PACK *p)
{
	char name[MAX_SIZE];
	HUB *h;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	if (PackGetStr(p, "HubName", name, sizeof(name)) == false)
	{
		return;
	}

	LockHubList(s->Cedar);

	h = GetHub(s->Cedar, name);
	if (h == NULL)
	{
		UnlockHubList(s->Cedar);
		return;
	}
	UnlockHubList(s->Cedar);

	SetHubOffline(h);

	LockHubList(s->Cedar);

	DelHubEx(s->Cedar, h, true);

	UnlockHubList(s->Cedar);

	ReleaseHub(h);
}

// Receive a HUB update directive
void SiCalledUpdateHub(SERVER *s, PACK *p)
{
	char name[MAX_SIZE];
	UINT type;
	HUB_OPTION o;
	HUB_LOG log;
	bool save_packet_log;
	UINT packet_log_switch_type;
	UINT packet_log_config[NUM_PACKET_LOG];
	bool save_security_log;
	bool type_changed = false;
	UINT security_log_switch_type;
	UINT i;
	HUB *h;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetStr(p, "HubName", name, sizeof(name));
	type = PackGetInt(p, "HubType");
	Zero(&o, sizeof(o));
	o.MaxSession = PackGetInt(p, "MaxSession");
	o.NoArpPolling = PackGetBool(p, "NoArpPolling");
	o.NoIPv6AddrPolling = PackGetBool(p, "NoIPv6AddrPolling");
	o.FilterPPPoE = PackGetBool(p, "FilterPPPoE");
	o.YieldAfterStorePacket = PackGetBool(p, "YieldAfterStorePacket");
	o.NoSpinLockForPacketDelay = PackGetBool(p, "NoSpinLockForPacketDelay");
	o.BroadcastStormDetectionThreshold = PackGetInt(p, "BroadcastStormDetectionThreshold");
	o.ClientMinimumRequiredBuild = PackGetInt(p, "ClientMinimumRequiredBuild");
	o.FixForDLinkBPDU = PackGetBool(p, "FixForDLinkBPDU");
	o.BroadcastLimiterStrictMode = PackGetBool(p, "BroadcastLimiterStrictMode");
	o.NoLookBPDUBridgeId = PackGetBool(p, "NoLookBPDUBridgeId");
	o.NoManageVlanId = PackGetBool(p, "NoManageVlanId");
	o.MaxLoggedPacketsPerMinute = PackGetInt(p, "MaxLoggedPacketsPerMinute");
	o.FloodingSendQueueBufferQuota = PackGetInt(p, "FloodingSendQueueBufferQuota");
	o.DoNotSaveHeavySecurityLogs = PackGetBool(p, "DoNotSaveHeavySecurityLogs");
	o.DropBroadcastsInPrivacyFilterMode = PackGetBool(p, "DropBroadcastsInPrivacyFilterMode");
	o.DropArpInPrivacyFilterMode = PackGetBool(p, "DropArpInPrivacyFilterMode");
	o.SuppressClientUpdateNotification = PackGetBool(p, "SuppressClientUpdateNotification");
	o.AssignVLanIdByRadiusAttribute = PackGetBool(p, "AssignVLanIdByRadiusAttribute");
	o.DenyAllRadiusLoginWithNoVlanAssign = PackGetBool(p, "DenyAllRadiusLoginWithNoVlanAssign");
	o.SecureNAT_RandomizeAssignIp = PackGetBool(p, "SecureNAT_RandomizeAssignIp");
	o.DetectDormantSessionInterval = PackGetInt(p, "DetectDormantSessionInterval");
	o.VlanTypeId = PackGetInt(p, "VlanTypeId");
	o.NoPhysicalIPOnPacketLog = PackGetBool(p, "NoPhysicalIPOnPacketLog");
	if (o.VlanTypeId == 0)
	{
		o.VlanTypeId = MAC_PROTO_TAGVLAN;
	}
	o.FilterOSPF = PackGetBool(p, "FilterOSPF");
	o.FilterIPv4 = PackGetBool(p, "FilterIPv4");
	o.FilterIPv6 = PackGetBool(p, "FilterIPv6");
	o.FilterNonIP = PackGetBool(p, "FilterNonIP");
	o.NoIPv4PacketLog = PackGetBool(p, "NoIPv4PacketLog");
	o.NoIPv6PacketLog = PackGetBool(p, "NoIPv6PacketLog");
	o.FilterBPDU = PackGetBool(p, "FilterBPDU");
	o.NoIPv6DefaultRouterInRAWhenIPv6 = PackGetBool(p, "NoIPv6DefaultRouterInRAWhenIPv6");
	o.NoMacAddressLog = PackGetBool(p, "NoMacAddressLog");
	o.ManageOnlyPrivateIP = PackGetBool(p, "ManageOnlyPrivateIP");
	o.ManageOnlyLocalUnicastIPv6 = PackGetBool(p, "ManageOnlyLocalUnicastIPv6");
	o.DisableIPParsing = PackGetBool(p, "DisableIPParsing");
	o.NoIpTable = PackGetBool(p, "NoIpTable");
	o.NoEnum = PackGetBool(p, "NoEnum");
	o.AdjustTcpMssValue = PackGetInt(p, "AdjustTcpMssValue");
	o.DisableAdjustTcpMss = PackGetBool(p, "DisableAdjustTcpMss");
	o.NoDhcpPacketLogOutsideHub = PackGetBool(p, "NoDhcpPacketLogOutsideHub");
	o.DisableHttpParsing = PackGetBool(p, "DisableHttpParsing");
	o.DisableUdpAcceleration = PackGetBool(p, "DisableUdpAcceleration");
	o.DisableUdpFilterForLocalBridgeNic = PackGetBool(p, "DisableUdpFilterForLocalBridgeNic");
	o.ApplyIPv4AccessListOnArpPacket = PackGetBool(p, "ApplyIPv4AccessListOnArpPacket");
	o.RemoveDefGwOnDhcpForLocalhost = PackGetBool(p, "RemoveDefGwOnDhcpForLocalhost");
	o.SecureNAT_MaxTcpSessionsPerIp = PackGetInt(p, "SecureNAT_MaxTcpSessionsPerIp");
	o.SecureNAT_MaxTcpSynSentPerIp = PackGetInt(p, "SecureNAT_MaxTcpSynSentPerIp");
	o.SecureNAT_MaxUdpSessionsPerIp = PackGetInt(p, "SecureNAT_MaxUdpSessionsPerIp");
	o.SecureNAT_MaxDnsSessionsPerIp = PackGetInt(p, "SecureNAT_MaxDnsSessionsPerIp");
	o.SecureNAT_MaxIcmpSessionsPerIp = PackGetInt(p, "SecureNAT_MaxIcmpSessionsPerIp");
	o.AccessListIncludeFileCacheLifetime = PackGetInt(p, "AccessListIncludeFileCacheLifetime");
	if (o.AccessListIncludeFileCacheLifetime == 0)
	{
		o.AccessListIncludeFileCacheLifetime = ACCESS_LIST_INCLUDE_FILE_CACHE_LIFETIME;
	}
	o.DisableKernelModeSecureNAT = PackGetBool(p, "DisableKernelModeSecureNAT");
	o.DisableIpRawModeSecureNAT = PackGetBool(p, "DisableIpRawModeSecureNAT");
	o.DisableUserModeSecureNAT = PackGetBool(p, "DisableUserModeSecureNAT");
	o.DisableCheckMacOnLocalBridge = PackGetBool(p, "DisableCheckMacOnLocalBridge");
	o.DisableCorrectIpOffloadChecksum = PackGetBool(p, "DisableCorrectIpOffloadChecksum");
	o.UseHubNameAsDhcpUserClassOption = PackGetBool(p, "UseHubNameAsDhcpUserClassOption");
	o.UseHubNameAsRadiusNasId = PackGetBool(p, "UseHubNameAsRadiusNasId");

	save_packet_log = PackGetInt(p, "SavePacketLog");
	packet_log_switch_type = PackGetInt(p, "PacketLogSwitchType");
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		packet_log_config[i] = PackGetIntEx(p, "PacketLogConfig", i);
	}
	save_security_log = PackGetInt(p, "SaveSecurityLog");
	security_log_switch_type = PackGetInt(p, "SecurityLogSwitchType");

	Zero(&log, sizeof(log));
	log.SavePacketLog = save_packet_log;
	log.PacketLogSwitchType = packet_log_switch_type;
	Copy(log.PacketLogConfig, packet_log_config, sizeof(log.PacketLogConfig));
	log.SaveSecurityLog = save_security_log;
	log.SecurityLogSwitchType = security_log_switch_type;

	h = GetHub(s->Cedar, name);
	if (h == NULL)
	{
		return;
	}

	h->FarmMember_MaxSessionClient = PackGetInt(p, "MaxSessionClient");
	h->FarmMember_MaxSessionBridge = PackGetInt(p, "MaxSessionBridge");
	h->FarmMember_MaxSessionClientBridgeApply = PackGetBool(p, "MaxSessionClientBridgeApply");

	if (h->FarmMember_MaxSessionClientBridgeApply == false)
	{
		h->FarmMember_MaxSessionClient = INFINITE;
		h->FarmMember_MaxSessionBridge = INFINITE;
	}

	Lock(h->lock);
	{
		Copy(h->Option, &o, sizeof(HUB_OPTION));
		PackGetData2(p, "SecurePassword", h->SecurePassword, SHA1_SIZE);
		PackGetData2(p, "HashedPassword", h->HashedPassword, SHA1_SIZE);
	}
	Unlock(h->lock);

	SetHubLogSetting(h, &log);

	if (h->Type != type)
	{
		h->Type = type;
		type_changed = true;
	}

	LockList(h->AccessList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(h->AccessList, i);
			Free(a);
		}
		DeleteAll(h->AccessList);
	}
	UnlockList(h->AccessList);

	for (i = 0;i < SiNumAccessFromPack(p);i++)
	{
		ACCESS *a = SiPackToAccess(p, i);
		AddAccessList(h, a);
		Free(a);
	}

	if (PackGetBool(p, "EnableSecureNAT"))
	{
		VH_OPTION t;
		bool changed;

		InVhOption(&t, p);

		changed = Cmp(h->SecureNATOption, &t, sizeof(VH_OPTION)) == 0 ? false : true;
		Copy(h->SecureNATOption, &t, sizeof(VH_OPTION));

		EnableSecureNAT(h, true);

		if (changed)
		{
			Lock(h->lock_online);
			{
				if (h->SecureNAT != NULL)
				{
					SetVirtualHostOption(h->SecureNAT->Nat->Virtual, &t);
					Debug("SiCalledUpdateHub: SecureNAT Updated.\n");
				}
			}
			Unlock(h->lock_online);
		}
	}
	else
	{
		EnableSecureNAT(h, false);
		Debug("SiCalledUpdateHub: SecureNAT Disabled.\n");
	}

	if (type_changed)
	{
		// Remove all sessions since the type of HUB has been changed
		if (h->Offline == false)
		{
			SetHubOffline(h);
			SetHubOnline(h);
		}
	}

	ReleaseHub(h);
}

// Inspect the ticket
bool SiCheckTicket(HUB *h, UCHAR *ticket, char *username, UINT username_size, char *usernamereal, UINT usernamereal_size, POLICY *policy, char *sessionname, UINT sessionname_size, char *groupname, UINT groupname_size)
{
	bool ret = false;
	// Validate arguments
	if (h == NULL || ticket == NULL || username == NULL || usernamereal == NULL || policy == NULL || sessionname == NULL)
	{
		return false;
	}

	LockList(h->TicketList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(h->TicketList);i++)
		{
			TICKET *t = LIST_DATA(h->TicketList, i);
			if (Cmp(t->Ticket, ticket, SHA1_SIZE) == 0)
			{
				ret = true;
				StrCpy(username, username_size, t->Username);
				StrCpy(usernamereal, usernamereal_size, t->UsernameReal);
				StrCpy(sessionname, sessionname_size, t->SessionName);
				StrCpy(groupname, groupname_size, t->GroupName);
				Copy(policy, &t->Policy, sizeof(POLICY));
				Delete(h->TicketList, t);
				Free(t);
				break;
			}
		}
	}
	UnlockList(h->TicketList);

	return ret;
}

// Receive a MAC address deletion directive
void SiCalledDeleteMacTable(SERVER *s, PACK *p)
{
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];
	HUB *h;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return;
	}
	key = PackGetInt(p, "Key");

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h == NULL)
	{
		return;
	}

	LockHashList(h->MacHashTable);
	{
		MAC_TABLE_ENTRY *e = HashListKeyToPointer(h->MacHashTable, key);
		DeleteHash(h->MacHashTable, e);
		Free(e);
	}
	UnlockHashList(h->MacHashTable);

	ReleaseHub(h);
}

// Receive an IP address delete directive
void SiCalledDeleteIpTable(SERVER *s, PACK *p)
{
	UINT key;
	char hubname[MAX_HUBNAME_LEN + 1];
	HUB *h;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return;
	}
	key = PackGetInt(p, "Key");

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h == NULL)
	{
		return;
	}

	LockList(h->IpTable);
	{
		if (IsInList(h->IpTable, (void *)key))
		{
			IP_TABLE_ENTRY *e = (IP_TABLE_ENTRY *)key;
			Delete(h->IpTable, e);
			Free(e);
		}
	}
	UnlockList(h->IpTable);

	ReleaseHub(h);
}

// Receive a session deletion directive
void SiCalledDeleteSession(SERVER *s, PACK *p)
{
	char name[MAX_SESSION_NAME_LEN + 1];
	char hubname[MAX_HUBNAME_LEN + 1];
	HUB *h;
	SESSION *sess;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return;
	}
	if (PackGetStr(p, "SessionName", name, sizeof(name)) == false)
	{
		return;
	}

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h == NULL)
	{
		return;
	}

	sess = GetSessionByName(h, name);

	if (sess != NULL)
	{
		if (sess->BridgeMode == false && sess->LinkModeServer == false && sess->SecureNATMode == false)
		{
			StopSession(sess);
		}
		ReleaseSession(sess);
	}

	ReleaseHub(h);
}

// Receive a log file reading directive
PACK *SiCalledReadLogFile(SERVER *s, PACK *p)
{
	RPC_READ_LOG_FILE t;
	PACK *ret;
	char filepath[MAX_PATH];
	UINT offset;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return NULL;
	}

	PackGetStr(p, "FilePath", filepath, sizeof(filepath));
	offset = PackGetInt(p, "Offset");

	Zero(&t, sizeof(t));

	SiReadLocalLogFile(s, filepath, offset, &t);

	ret = NewPack();

	OutRpcReadLogFile(ret, &t);
	FreeRpcReadLogFile(&t);

	return ret;
}

// Receive a log file enumeration directive
PACK *SiCalledEnumLogFileList(SERVER *s, PACK *p)
{
	RPC_ENUM_LOG_FILE t;
	PACK *ret;
	char hubname[MAX_HUBNAME_LEN + 1];
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return NULL;
	}

	PackGetStr(p, "HubName", hubname, sizeof(hubname));

	Zero(&t, sizeof(t));

	SiEnumLocalLogFileList(s, hubname, &t);

	ret = NewPack();

	OutRpcEnumLogFile(ret, &t);
	FreeRpcEnumLogFile(&t);

	return ret;
}

// Receive a session information directive
PACK *SiCalledGetSessionStatus(SERVER *s, PACK *p)
{
	RPC_SESSION_STATUS t;
	ADMIN a;
	PACK *ret;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	InRpcSessionStatus(&t, p);

	Zero(&a, sizeof(a));
	a.Server = s;
	a.ServerAdmin = true;

	if (StGetSessionStatus(&a, &t) != ERR_NO_ERROR)
	{
		FreeRpcSessionStatus(&t);
		return NULL;
	}

	ret = NewPack();

	OutRpcSessionStatus(ret, &t);

	FreeRpcSessionStatus(&t);

	return ret;
}

// IP table enumeration directive
PACK *SiCalledEnumIpTable(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_ENUM_IP_TABLE t;
	PACK *ret;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	SiEnumIpTable(s, hubname, &t);

	ret = NewPack();
	OutRpcEnumIpTable(ret, &t);
	FreeRpcEnumIpTable(&t);

	return ret;
}

// MAC table enumeration directive
PACK *SiCalledEnumMacTable(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_ENUM_MAC_TABLE t;
	PACK *ret;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	SiEnumMacTable(s, hubname, &t);

	ret = NewPack();
	OutRpcEnumMacTable(ret, &t);
	FreeRpcEnumMacTable(&t);

	return ret;
}

// NAT status acquisition directive
PACK *SiCalledGetNatStatus(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_NAT_STATUS t;
	PACK *ret;
	HUB *h;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h != NULL)
	{
		Lock(h->lock_online);
		{
			if (h->SecureNAT != NULL)
			{
				NtGetStatus(h->SecureNAT->Nat, &t);
			}
		}
		Unlock(h->lock_online);
	}

	ReleaseHub(h);

	ret = NewPack();
	OutRpcNatStatus(ret, &t);
	FreeRpcNatStatus(&t);

	return ret;
}

// DHCP table enumeration directive
PACK *SiCalledEnumDhcp(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_ENUM_DHCP t;
	PACK *ret;
	HUB *h;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h != NULL)
	{
		Lock(h->lock_online);
		{
			if (h->SecureNAT != NULL)
			{
				NtEnumDhcpList(h->SecureNAT->Nat, &t);
			}
		}
		Unlock(h->lock_online);
	}

	ReleaseHub(h);

	ret = NewPack();
	OutRpcEnumDhcp(ret, &t);
	FreeRpcEnumDhcp(&t);

	return ret;
}

// NAT table enumeration directive
PACK *SiCalledEnumNat(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_ENUM_NAT t;
	PACK *ret;
	HUB *h;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	LockHubList(s->Cedar);
	{
		h = GetHub(s->Cedar, hubname);
	}
	UnlockHubList(s->Cedar);

	if (h != NULL)
	{
		Lock(h->lock_online);
		{
			if (h->SecureNAT != NULL)
			{
				NtEnumNatList(h->SecureNAT->Nat, &t);
			}
		}
		Unlock(h->lock_online);
	}

	ReleaseHub(h);

	ret = NewPack();
	OutRpcEnumNat(ret, &t);
	FreeRpcEnumNat(&t);

	return ret;
}

// Receive a session enumeration directive
PACK *SiCalledEnumSession(SERVER *s, PACK *p)
{
	char hubname[MAX_HUBNAME_LEN + 1];
	RPC_ENUM_SESSION t;
	PACK *ret;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}
	if (PackGetStr(p, "HubName", hubname, sizeof(hubname)) == false)
	{
		return NewPack();
	}
	Zero(&t, sizeof(t));

	SiEnumLocalSession(s, hubname, &t);

	ret = NewPack();
	OutRpcEnumSession(ret, &t);
	FreeRpcEnumSession(&t);

	return ret;
}

// Receive a ticket creation directive
PACK *SiCalledCreateTicket(SERVER *s, PACK *p)
{
	char username[MAX_SIZE];
	char hubname[MAX_SIZE];
	char groupname[MAX_SIZE];
	char realusername[MAX_SIZE];
	char sessionname[MAX_SESSION_NAME_LEN + 1];
	POLICY policy;
	UCHAR ticket[SHA1_SIZE];
	char ticket_str[MAX_SIZE];
	HUB *h;
	UINT i;
	PACK *ret;
	TICKET *t;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return NewPack();
	}

	PackGetStr(p, "UserName", username, sizeof(username));
	PackGetStr(p, "GroupName", groupname, sizeof(groupname));
	PackGetStr(p, "HubName", hubname, sizeof(hubname));
	PackGetStr(p, "RealUserName", realusername, sizeof(realusername));
	PackGetStr(p, "SessionName", sessionname, sizeof(sessionname));

	InRpcPolicy(&policy, p);
	if (PackGetDataSize(p, "Ticket") == SHA1_SIZE)
	{
		PackGetData(p, "Ticket", ticket);
	}

	BinToStr(ticket_str, sizeof(ticket_str), ticket, SHA1_SIZE);

	SLog(s->Cedar, "LS_TICKET_2", hubname, username, realusername, sessionname,
		ticket_str, TICKET_EXPIRES / 1000);

	// Get the HUB
	h = GetHub(s->Cedar, hubname);
	if (h == NULL)
	{
		return NewPack();
	}

	LockList(h->TicketList);
	{
		LIST *o = NewListFast(NULL);
		// Discard old tickets
		for (i = 0;i < LIST_NUM(h->TicketList);i++)
		{
			TICKET *t = LIST_DATA(h->TicketList, i);
			if ((t->CreatedTick + TICKET_EXPIRES) < Tick64())
			{
				Add(o, t);
			}
		}
		for (i = 0;i < LIST_NUM(o);i++)
		{
			TICKET *t = LIST_DATA(o, i);
			Delete(h->TicketList, t);
			Free(t);
		}
		ReleaseList(o);

		// Create a ticket
		t = ZeroMalloc(sizeof(TICKET));
		t->CreatedTick = Tick64();
		Copy(&t->Policy, &policy, sizeof(POLICY));
		Copy(t->Ticket, ticket, SHA1_SIZE);
		StrCpy(t->Username, sizeof(t->Username), username);
		StrCpy(t->UsernameReal, sizeof(t->UsernameReal), realusername);
		StrCpy(t->GroupName, sizeof(t->GroupName), groupname);
		StrCpy(t->SessionName, sizeof(t->SessionName), sessionname);

		Add(h->TicketList, t);
	}
	UnlockList(h->TicketList);

	ReleaseHub(h);

	ret = NewPack();

	PackAddInt(ret, "Point", SiGetPoint(s));

	return ret;
}

// Receive a HUB creation directive
void SiCalledCreateHub(SERVER *s, PACK *p)
{
	char name[MAX_SIZE];
	UINT type;
	HUB_OPTION o;
	HUB_LOG log;
	bool save_packet_log;
	UINT packet_log_switch_type;
	UINT packet_log_config[NUM_PACKET_LOG];
	bool save_security_log;
	UINT security_log_switch_type;
	UINT i;
	HUB *h;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetStr(p, "HubName", name, sizeof(name));
	type = PackGetInt(p, "HubType");
	Zero(&o, sizeof(o));
	o.MaxSession = PackGetInt(p, "MaxSession");
	save_packet_log = PackGetInt(p, "SavePacketLog");
	packet_log_switch_type = PackGetInt(p, "PacketLogSwitchType");
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		packet_log_config[i] = PackGetIntEx(p, "PacketLogConfig", i);
	}
	save_security_log = PackGetInt(p, "SaveSecurityLog");
	security_log_switch_type = PackGetInt(p, "SecurityLogSwitchType");

	Zero(&log, sizeof(log));
	log.SavePacketLog = save_packet_log;
	log.PacketLogSwitchType = packet_log_switch_type;
	Copy(log.PacketLogConfig, packet_log_config, sizeof(log.PacketLogConfig));
	log.SaveSecurityLog = save_security_log;
	log.SecurityLogSwitchType = security_log_switch_type;

	h = NewHub(s->Cedar, name, &o);
	h->LastCommTime = h->LastLoginTime = h->CreatedTime = 0;
	SetHubLogSetting(h, &log);
	h->Type = type;
	h->FarmMember_MaxSessionClient = PackGetInt(p, "MaxSessionClient");
	h->FarmMember_MaxSessionBridge = PackGetInt(p, "MaxSessionBridge");
	h->FarmMember_MaxSessionClientBridgeApply = PackGetBool(p, "MaxSessionClientBridgeApply");

	if (h->FarmMember_MaxSessionClientBridgeApply == false)
	{
		h->FarmMember_MaxSessionClient = INFINITE;
		h->FarmMember_MaxSessionBridge = INFINITE;
	}

	PackGetData2(p, "SecurePassword", h->SecurePassword, SHA1_SIZE);
	PackGetData2(p, "HashedPassword", h->HashedPassword, SHA1_SIZE);

	for (i = 0;i < SiNumAccessFromPack(p);i++)
	{
		ACCESS *a = SiPackToAccess(p, i);
		AddAccessList(h, a);
		Free(a);
	}

	if (PackGetBool(p, "EnableSecureNAT"))
	{
		VH_OPTION t;

		InVhOption(&t, p);

		Copy(h->SecureNATOption, &t, sizeof(VH_OPTION));
		EnableSecureNAT(h, true);

		Debug("SiCalledCreateHub: SecureNAT Created.\n");
	}

	AddHub(s->Cedar, h);
	h->Offline = true;
	SetHubOnline(h);

	ReleaseHub(h);
}

// Farm control thread
void SiFarmControlThread(THREAD *thread, void *param)
{
	SERVER *s;
	CEDAR *c;
	EVENT *e;
	LIST *o;
	UINT i;
	char tmp[MAX_PATH];
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	s = (SERVER *)param;
	c = s->Cedar;
	e = s->FarmControlThreadHaltEvent;

	while (true)
	{
		Lock(c->CedarSuperLock);

		// Enumerate HUB list which is hosted by each farm member
		Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
		SiDebugLog(s, tmp);

		LockList(s->FarmMemberList);
		{
			UINT i;
			UINT num;
			UINT assigned_client_license = 0;
			UINT assigned_bridge_license = 0;
			LIST *fm_list = NewListFast(NULL);

			Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
			SiDebugLog(s, tmp);

			num = 0;

			while (true)
			{
				bool escape = true;
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

					if (IsInList(fm_list, f) == false)
					{
						SiCallEnumHub(s, f);
						// Get the total number of sessions across the server farm
						num += f->NumSessions;

						assigned_client_license += f->AssignedClientLicense;
						assigned_bridge_license += f->AssignedBridgeLicense;

						escape = false;

						Add(fm_list, f);
						break;
					}
				}

				if (escape)
				{
					break;
				}

				UnlockList(s->FarmMemberList);
				LockList(s->FarmMemberList);
			}

			ReleaseList(fm_list);

			s->CurrentTotalNumSessionsOnFarm = num;

			// Update the number of assigned licenses
			s->CurrentAssignedBridgeLicense = assigned_bridge_license;
			s->CurrentAssignedClientLicense = assigned_client_license;

			Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
			SiDebugLog(s, tmp);
		}
		UnlockList(s->FarmMemberList);

		Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
		SiDebugLog(s, tmp);

		o = NewListFast(NULL);

		Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
		SiDebugLog(s, tmp);

		// Emit an update notification for each HUB
		LockList(c->HubList);
		{
			UINT i;
			for (i = 0;i < LIST_NUM(c->HubList);i++)
			{
				HUB *h = LIST_DATA(c->HubList, i);
				AddRef(h->ref);
				Add(o, h);
			}
		}
		UnlockList(c->HubList);

		Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
		SiDebugLog(s, tmp);

		for (i = 0;i < LIST_NUM(o);i++)
		{
			HUB *h = LIST_DATA(o, i);
			SiHubUpdateProc(h);
			ReleaseHub(h);
		}

		Format(tmp, sizeof(tmp), "CONTROLLER: %s %u", __FILE__, __LINE__);
		SiDebugLog(s, tmp);

		ReleaseList(o);

		Unlock(c->CedarSuperLock);

		Wait(e, SERVER_FARM_CONTROL_INTERVAL);
		if (s->Halt)
		{
			break;
		}
	}
}

// Start the farm controling
void SiStartFarmControl(SERVER *s)
{
	// Validate arguments
	if (s == NULL || s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		return;
	}

	s->FarmControlThreadHaltEvent = NewEvent();
	s->FarmControlThread = NewThread(SiFarmControlThread, s);
}

// Stop the farm controling
void SiStopFarmControl(SERVER *s)
{
	// Validate arguments
	if (s == NULL || s->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		return;
	}

	Set(s->FarmControlThreadHaltEvent);
	WaitThread(s->FarmControlThread, INFINITE);
	ReleaseEvent(s->FarmControlThreadHaltEvent);
	ReleaseThread(s->FarmControlThread);
}

// HUB enumeration directive
void SiCallEnumHub(SERVER *s, FARM_MEMBER *f)
{
	CEDAR *c;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	c = s->Cedar;

	if (f->Me)
	{

		// Enumerate local HUBs
		LockList(f->HubList);
		{
			// For a local HUB, re-enumerate by erasing all STATIC HUB list once first
			UINT i;
			LIST *o = NewListFast(NULL);
			for (i = 0;i < LIST_NUM(f->HubList);i++)
			{
				HUB_LIST *h = LIST_DATA(f->HubList, i);
				if (h->DynamicHub == false)
				{
					Add(o, h);
				}
			}

			// Clear all the STATIC HUB
			for (i = 0;i < LIST_NUM(o);i++)
			{
				HUB_LIST *h = LIST_DATA(o, i);
				Free(h);
				Delete(f->HubList, h);
			}
			ReleaseList(o);

			// Second, stop DYNAMIC HUBs without user
			o = NewListFast(NULL);
			for (i = 0;i < LIST_NUM(f->HubList);i++)
			{
				HUB_LIST *h = LIST_DATA(f->HubList, i);
				if (h->DynamicHub == true)
				{
					LockList(c->HubList);
					{
						HUB *hub = GetHub(s->Cedar, h->Name);
						if (hub != NULL)
						{
							if (Count(hub->NumSessions) == 0 || hub->Type != HUB_TYPE_FARM_DYNAMIC)
							{
								Add(o, h);
							}
							ReleaseHub(hub);
						}
					}
					UnlockList(c->HubList);
				}
			}

			for (i = 0;i < LIST_NUM(o);i++)
			{
				HUB_LIST *h = LIST_DATA(o, i);
				Debug("Delete HUB: %s\n", h->Name);
				Free(h);
				Delete(f->HubList, h);
			}

			ReleaseList(o);

			// Set the enumeration results
			LockList(c->HubList);
			{
				for (i = 0;i < LIST_NUM(c->HubList);i++)
				{
					HUB *h = LIST_DATA(c->HubList, i);
					if (h->Offline == false)
					{
						if (h->Type == HUB_TYPE_FARM_STATIC)
						{
							HUB_LIST *hh = ZeroMalloc(sizeof(HUB_LIST));
							hh->FarmMember = f;
							hh->DynamicHub = false;
							StrCpy(hh->Name, sizeof(hh->Name), h->Name);
							Add(f->HubList, hh);

							LockList(h->SessionList);
							{
								hh->NumSessions = LIST_NUM(h->SessionList);
								hh->NumSessionsBridge = Count(h->NumSessionsBridge);
								hh->NumSessionsClient = Count(h->NumSessionsClient);
							}
							UnlockList(h->SessionList);

							LockHashList(h->MacHashTable);
							{
								hh->NumMacTables = HASH_LIST_NUM(h->MacHashTable);
							}
							UnlockHashList(h->MacHashTable);

							LockList(h->IpTable);
							{
								hh->NumIpTables = LIST_NUM(h->IpTable);
							}
							UnlockList(h->IpTable);
						}
					}
				}
			}
			UnlockList(c->HubList);
		}
		UnlockList(f->HubList);

		// Point
		f->Point = SiGetPoint(s);
		f->NumSessions = Count(s->Cedar->CurrentSessions);
		f->MaxSessions = GetServerCapsInt(s, "i_max_sessions");
		f->NumTcpConnections = Count(s->Cedar->CurrentTcpConnections);

		Lock(s->Cedar->TrafficLock);
		{
			Copy(&f->Traffic, s->Cedar->Traffic, sizeof(TRAFFIC));
		}
		Unlock(s->Cedar->TrafficLock);

		f->AssignedBridgeLicense = Count(s->Cedar->AssignedBridgeLicense);
		f->AssignedClientLicense = Count(s->Cedar->AssignedClientLicense);

		Copy(f->RandomKey, s->MyRandomKey, SHA1_SIZE);


		Debug("Server %s: Point %u\n", f->hostname, f->Point);
	}
	else
	{
		// Enumerate HUBs which are remote member
		PACK *p = NewPack();
		UINT i, num, j;
		LIST *o = NewListFast(NULL);

		num = 0;

		for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
		{
			FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

			if (IsZero(f->RandomKey, SHA1_SIZE) == false && f->SystemId != 0)
			{
				num++;
			}
		}

		j = 0;

		for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
		{
			FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

			if (IsZero(f->RandomKey, SHA1_SIZE) == false && f->SystemId != 0)
			{
				PackAddDataEx(p, "MemberRandomKey", f->RandomKey, SHA1_SIZE, j, num);
				PackAddInt64Ex(p, "MemberSystemId", f->SystemId, j, num);
				j++;
			}
		}
		PackAddInt(p, "MemberSystemIdNum", num);

		p = SiCallTask(f, p, "enumhub");
		if (p != NULL)
		{
			LockList(f->HubList);
			{
				UINT i;
				// Erase the list
				for (i = 0;i < LIST_NUM(f->HubList);i++)
				{
					HUB_LIST *hh = LIST_DATA(f->HubList, i);
					Free(hh);
				}
				DeleteAll(f->HubList);

				for (i = 0;i < PackGetIndexCount(p, "HubName");i++)
				{
					HUB_LIST *hh = ZeroMalloc(sizeof(HUB_LIST));
					UINT num;
					UINT64 LastCommTime;

					PackGetStrEx(p, "HubName", hh->Name, sizeof(hh->Name), i);
					num = PackGetIntEx(p, "NumSession", i);
					hh->DynamicHub = ((PackGetIntEx(p, "HubType", i) == HUB_TYPE_FARM_DYNAMIC) ? true : false);
					hh->FarmMember = f;
					hh->NumSessions = PackGetIntEx(p, "NumSessions", i);
					hh->NumSessionsClient = PackGetIntEx(p, "NumSessionsClient", i);
					hh->NumSessionsBridge = PackGetIntEx(p, "NumSessionsBridge", i);
					hh->NumIpTables = PackGetIntEx(p, "NumIpTables", i);
					hh->NumMacTables = PackGetIntEx(p, "NumMacTables", i);
					LastCommTime = PackGetInt64Ex(p, "LastCommTime", i);
					Add(f->HubList, hh);
					//Debug("%s\n", hh->Name);

					LockList(c->HubList);
					{
						HUB *h = GetHub(c, hh->Name);

						if (h != NULL)
						{
							// Update the LastCommTime of the Virtual HUB
							Lock(h->lock);
							{
								if (h->LastCommTime < LastCommTime)
								{
									h->LastCommTime = LastCommTime;
								}
							}
							Unlock(h->lock);

							ReleaseHub(h);
						}
					}
					UnlockList(c->HubList);

					if (hh->DynamicHub && num >= 1)
					{
						// It is not necessary to be registered in the virtual HUB creation
						// history list because user session is already connected.
						// Remove from the Virtual HUB creation history list
						SiDelHubCreateHistory(s, hh->Name);
					}

					if (hh->DynamicHub && num == 0)
					{
						// Check the Virtual HUB creation history list.
						// If it is created within 60 seconds of the most recent
						// in the case of Virtual HUB which the first user is not
						// connected yet, not to remove because there is no user
						if (SiIsHubRegistedOnCreateHistory(s, hh->Name) == false)
						{
							// Stop because all uses have gone in the dynamic HUB
							HUB *h;
							LockList(c->HubList);
							{
								h = GetHub(c, hh->Name);
							}
							UnlockList(c->HubList);

							if (h != NULL)
							{
								Add(o, h);
							}
						}
					}
				}
			}
			UnlockList(f->HubList);
			f->Point = PackGetInt(p, "Point");
			Debug("Server %s: Point %u\n", f->hostname, f->Point);
			f->NumSessions = PackGetInt(p, "NumTotalSessions");
			if (f->NumSessions == 0)
			{
				f->NumSessions = PackGetInt(p, "NumSessions");
			}
			f->MaxSessions = PackGetInt(p, "MaxSessions");
			f->NumTcpConnections = PackGetInt(p, "NumTcpConnections");
			InRpcTraffic(&f->Traffic, p);

			f->AssignedBridgeLicense = PackGetInt(p, "AssignedBridgeLicense");
			f->AssignedClientLicense = PackGetInt(p, "AssignedClientLicense");

			if (PackGetDataSize(p, "RandomKey") == SHA1_SIZE)
			{
				PackGetData(p, "RandomKey", f->RandomKey);
			}

			f->SystemId = PackGetInt64(p, "SystemId");

			// Apply the traffic difference information
			num = PackGetIndexCount(p, "TdType");
			for (i = 0;i < num;i++)
			{
				TRAFFIC traffic;
				UINT type;
				HUB *h;
				char name[MAX_SIZE];
				char hubname[MAX_SIZE];

				type = PackGetIntEx(p, "TdType", i);
				PackGetStrEx(p, "TdName", name, sizeof(name), i);
				PackGetStrEx(p, "TdHubName", hubname, sizeof(hubname), i);
				InRpcTrafficEx(&traffic, p, i);

				LockList(c->HubList);
				{
					h = GetHub(c, hubname);
					if (h != NULL)
					{
						if (type == TRAFFIC_DIFF_HUB)
						{
							Lock(h->TrafficLock);
							{
								AddTraffic(h->Traffic, &traffic);
							}
							Unlock(h->TrafficLock);
						}
						else
						{
							AcLock(h);
							{
								USER *u = AcGetUser(h, name);
								if (u != NULL)
								{
									Lock(u->lock);
									{
										AddTraffic(u->Traffic, &traffic);
									}
									Unlock(u->lock);
									if (u->Group != NULL)
									{
										Lock(u->Group->lock);
										{
											AddTraffic(u->Group->Traffic, &traffic);
										}
										Unlock(u->Group->lock);
									}
									ReleaseUser(u);
								}
							}
							AcUnlock(h);
						}
						ReleaseHub(h);
					}
					UnlockList(c->HubList);
				}
			}

			FreePack(p);
		}

		for (i = 0;i < LIST_NUM(o);i++)
		{
			HUB *h = LIST_DATA(o, i);
			SiCallDeleteHub(s, f, h);
			Debug("Delete HUB: %s\n", h->Name);
			ReleaseHub(h);
		}

		ReleaseList(o);
	}
}

// Send a session information directive
bool SiCallGetSessionStatus(SERVER *s, FARM_MEMBER *f, RPC_SESSION_STATUS *t)
{
	PACK *p;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return false;
	}

	p = NewPack();
	OutRpcSessionStatus(p, t);
	FreeRpcSessionStatus(t);
	Zero(t, sizeof(RPC_SESSION_STATUS));

	p = SiCallTask(f, p, "getsessionstatus");

	if (p == NULL)
	{
		return false;
	}

	InRpcSessionStatus(t, p);
	FreePack(p);

	return true;
}

// Log file reading directive
bool SiCallReadLogFile(SERVER *s, FARM_MEMBER *f, RPC_READ_LOG_FILE *t)
{
	PACK *p;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return false;
	}

	p = NewPack();
	OutRpcReadLogFile(p, t);
	FreeRpcReadLogFile(t);
	Zero(t, sizeof(RPC_READ_LOG_FILE));

	p = SiCallTask(f, p, "readlogfile");

	if (p == NULL)
	{
		return false;
	}

	InRpcReadLogFile(t, p);
	FreePack(p);

	return true;
}

// Log file enumeration directive
bool SiCallEnumLogFileList(SERVER *s, FARM_MEMBER *f, RPC_ENUM_LOG_FILE *t, char *hubname)
{
	PACK *p;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return false;
	}

	p = NewPack();
	OutRpcEnumLogFile(p, t);
	FreeRpcEnumLogFile(t);
	Zero(t, sizeof(RPC_ENUM_LOG_FILE));

	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enumlogfilelist");

	if (p == NULL)
	{
		return false;
	}

	InRpcEnumLogFile(t, p);
	FreePack(p);

	return true;
}

// HUB delete directive
void SiCallDeleteHub(SERVER *s, FARM_MEMBER *f, HUB *h)
{
	PACK *p;
	UINT i;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	if (f->Me == false)
	{
		p = NewPack();

		PackAddStr(p, "HubName", h->Name);

		p = SiCallTask(f, p, "deletehub");
		FreePack(p);
	}

	LockList(f->HubList);
	{
		for (i = 0;i < LIST_NUM(f->HubList);i++)
		{
			HUB_LIST *hh = LIST_DATA(f->HubList, i);
			if (StrCmpi(hh->Name, h->Name) == 0)
			{
				Free(hh);
				Delete(f->HubList, hh);
			}
		}
	}
	UnlockList(f->HubList);
}

// Submit a HUB update directive
void SiCallUpdateHub(SERVER *s, FARM_MEMBER *f, HUB *h)
{
	PACK *p;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	if (f->Me == false)
	{
		p = NewPack();

		SiPackAddCreateHub(p, h);

		p = SiCallTask(f, p, "updatehub");
		FreePack(p);
	}
}

// Send a ticket creation directive
void SiCallCreateTicket(SERVER *s, FARM_MEMBER *f, char *hubname, char *username, char *realusername, POLICY *policy, UCHAR *ticket, UINT counter, char *groupname)
{
	PACK *p;
	char name[MAX_SESSION_NAME_LEN + 1];
	char hub_name_upper[MAX_SIZE];
	char user_name_upper[MAX_USERNAME_LEN + 1];
	char ticket_str[MAX_SIZE];
	UINT point;
	// Validate arguments
	if (s == NULL || f == NULL || realusername == NULL || hubname == NULL || username == NULL || policy == NULL || ticket == NULL)
	{
		return;
	}
	if (groupname == NULL)
	{
		groupname = "";
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);
	PackAddStr(p, "UserName", username);
	PackAddStr(p, "groupname", groupname);
	PackAddStr(p, "RealUserName", realusername);
	OutRpcPolicy(p, policy);
	PackAddData(p, "Ticket", ticket, SHA1_SIZE);

	BinToStr(ticket_str, sizeof(ticket_str), ticket, SHA1_SIZE);

	StrCpy(hub_name_upper, sizeof(hub_name_upper), hubname);
	StrUpper(hub_name_upper);
	StrCpy(user_name_upper, sizeof(user_name_upper), username);
	StrUpper(user_name_upper);
	Format(name, sizeof(name), "SID-%s-%u", user_name_upper,
		counter);
	PackAddStr(p, "SessionName", name);

	p = SiCallTask(f, p, "createticket");

	SLog(s->Cedar, "LS_TICKET_1", f->hostname, hubname, username, realusername, name, ticket_str);

	point = PackGetInt(p, "Point");
	if (point != 0)
	{
		f->Point = point;
		f->NumSessions++;
	}

	FreePack(p);
}

// Send a MAC address deletion directive
void SiCallDeleteMacTable(SERVER *s, FARM_MEMBER *f, char *hubname, UINT key)
{
	PACK *p;
	// Validate arguments
	if (s == NULL || f == NULL || hubname == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);
	PackAddInt(p, "Key", key);

	p = SiCallTask(f, p, "deletemactable");

	FreePack(p);
}

// Send an IP address delete directive
void SiCallDeleteIpTable(SERVER *s, FARM_MEMBER *f, char *hubname, UINT key)
{
	PACK *p;
	// Validate arguments
	if (s == NULL || f == NULL || hubname == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);
	PackAddInt(p, "Key", key);

	p = SiCallTask(f, p, "deleteiptable");

	FreePack(p);
}

// Send a session deletion directive
void SiCallDeleteSession(SERVER *s, FARM_MEMBER *f, char *hubname, char *session_name)
{
	PACK *p;
	// Validate arguments
	if (s == NULL || f == NULL || hubname == NULL || session_name == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);
	PackAddStr(p, "SessionName", session_name);

	p = SiCallTask(f, p, "deletesession");

	FreePack(p);
}

// Send an IP table enumeration directive
void SiCallEnumIpTable(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_IP_TABLE *t)
{
	PACK *p;
	UINT i;
	// Validate arguments
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enumiptable");

	Zero(t, sizeof(RPC_ENUM_IP_TABLE));
	InRpcEnumIpTable(t, p);

	for (i = 0;i < t->NumIpTable;i++)
	{
		t->IpTables[i].RemoteItem = true;
		StrCpy(t->IpTables[i].RemoteHostname, sizeof(t->IpTables[i].RemoteHostname),
			f->hostname);
	}

	FreePack(p);
}

// Submit a MAC table enumeration directive
void SiCallEnumMacTable(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_MAC_TABLE *t)
{
	PACK *p;
	UINT i;
	// Validate arguments
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enummactable");

	Zero(t, sizeof(RPC_ENUM_MAC_TABLE));
	InRpcEnumMacTable(t, p);

	for (i = 0;i < t->NumMacTable;i++)
	{
		t->MacTables[i].RemoteItem = true;
		StrCpy(t->MacTables[i].RemoteHostname, sizeof(t->MacTables[i].RemoteHostname),
			f->hostname);
	}

	FreePack(p);
}

// Send a SecureNAT status acquisition directive
void SiCallGetNatStatus(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_NAT_STATUS *t)
{
	PACK *p;
	// Validate arguments
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "getnatstatus");

	Zero(t, sizeof(RPC_NAT_STATUS));
	InRpcNatStatus(t, p);

	FreePack(p);
}

// Submit a DHCP entry enumeration directive
void SiCallEnumDhcp(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_DHCP *t)
{
	PACK *p;
	// Validate arguments
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enumdhcp");

	Zero(t, sizeof(RPC_ENUM_DHCP));
	InRpcEnumDhcp(t, p);

	FreePack(p);
}

// Submit a NAT entry enumeration directive 
void SiCallEnumNat(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_NAT *t)
{
	PACK *p;
	// Validate arguments
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enumnat");

	Zero(t, sizeof(RPC_ENUM_NAT));
	InRpcEnumNat(t, p);

	FreePack(p);
}

// Send a session enumeration directive
void SiCallEnumSession(SERVER *s, FARM_MEMBER *f, char *hubname, RPC_ENUM_SESSION *t)
{
	PACK *p;
	UINT i;
	// Validate arguments
	if (s == NULL || f == NULL || hubname == NULL || t == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "HubName", hubname);

	p = SiCallTask(f, p, "enumsession");

	Zero(t, sizeof(RPC_ENUM_SESSION));
	InRpcEnumSession(t, p);

	for (i = 0;i < t->NumSession;i++)
	{
		t->Sessions[i].RemoteSession = true;
		StrCpy(t->Sessions[i].RemoteHostname, sizeof(t->Sessions[i].RemoteHostname),
			f->hostname);
	}

	FreePack(p);
}

// Send a HUB creation directive
void SiCallCreateHub(SERVER *s, FARM_MEMBER *f, HUB *h)
{
	PACK *p;
	HUB_LIST *hh;
	// Validate arguments
	if (s == NULL || f == NULL)
	{
		return;
	}

	if (f->Me == false)
	{
		p = NewPack();

		SiPackAddCreateHub(p, h);

		p = SiCallTask(f, p, "createhub");
		FreePack(p);
	}

	hh = ZeroMalloc(sizeof(HUB_LIST));
	hh->DynamicHub = (h->Type == HUB_TYPE_FARM_DYNAMIC ? true : false);
	StrCpy(hh->Name, sizeof(hh->Name), h->Name);
	hh->FarmMember = f;

	LockList(f->HubList);
	{
		bool exists = false;
		UINT i;
		for (i = 0;i < LIST_NUM(f->HubList);i++)
		{
			HUB_LIST *t = LIST_DATA(f->HubList, i);
			if (StrCmpi(t->Name, hh->Name) == 0)
			{
				exists = true;
			}
		}
		if (exists == false)
		{
			Add(f->HubList, hh);
		}
		else
		{
			Free(hh);
		}
	}
	UnlockList(f->HubList);
}

// Write the PACK for creating HUB
void SiPackAddCreateHub(PACK *p, HUB *h)
{
	UINT i;
	UINT max_session;
	SERVER *s;


	// Validate arguments
	if (p == NULL || h == NULL)
	{
		return;
	}


	s = h->Cedar->Server;
	if (s != NULL)
	{
	}

	PackAddStr(p, "HubName", h->Name);
	PackAddInt(p, "HubType", h->Type);

	max_session = h->Option->MaxSession;

	if (GetHubAdminOption(h, "max_sessions") != 0)
	{
		if (max_session == 0)
		{
			max_session = GetHubAdminOption(h, "max_sessions");
		}
		else
		{
			UINT r = GetHubAdminOption(h, "max_sessions");
			max_session = MIN(max_session, r);
		}
	}

	PackAddInt(p, "MaxSession", max_session);

	if (GetHubAdminOption(h, "max_sessions_client_bridge_apply") != 0
		)
	{
		PackAddInt(p, "MaxSessionClient", GetHubAdminOption(h, "max_sessions_client"));
		PackAddInt(p, "MaxSessionBridge", GetHubAdminOption(h, "max_sessions_bridge"));
		PackAddBool(p, "MaxSessionClientBridgeApply", true);
	}
	else
	{
		PackAddInt(p, "MaxSessionClient", INFINITE);
		PackAddInt(p, "MaxSessionBridge", INFINITE);
	}

	PackAddBool(p, "NoArpPolling", h->Option->NoArpPolling);
	PackAddBool(p, "NoIPv6AddrPolling", h->Option->NoIPv6AddrPolling);
	PackAddBool(p, "NoIpTable", h->Option->NoIpTable);
	PackAddBool(p, "NoEnum", h->Option->NoEnum);
	PackAddBool(p, "FilterPPPoE", h->Option->FilterPPPoE);
	PackAddBool(p, "YieldAfterStorePacket", h->Option->YieldAfterStorePacket);
	PackAddBool(p, "NoSpinLockForPacketDelay", h->Option->NoSpinLockForPacketDelay);
	PackAddInt(p, "BroadcastStormDetectionThreshold", h->Option->BroadcastStormDetectionThreshold);
	PackAddInt(p, "MaxLoggedPacketsPerMinute", h->Option->MaxLoggedPacketsPerMinute);
	PackAddInt(p, "FloodingSendQueueBufferQuota", h->Option->FloodingSendQueueBufferQuota);
	PackAddBool(p, "DoNotSaveHeavySecurityLogs", h->Option->DoNotSaveHeavySecurityLogs);
	PackAddBool(p, "DropBroadcastsInPrivacyFilterMode", h->Option->DropBroadcastsInPrivacyFilterMode);
	PackAddBool(p, "DropArpInPrivacyFilterMode", h->Option->DropArpInPrivacyFilterMode);
	PackAddBool(p, "SuppressClientUpdateNotification", h->Option->SuppressClientUpdateNotification);
	PackAddBool(p, "AssignVLanIdByRadiusAttribute", h->Option->AssignVLanIdByRadiusAttribute);
	PackAddBool(p, "DenyAllRadiusLoginWithNoVlanAssign", h->Option->DenyAllRadiusLoginWithNoVlanAssign);
	PackAddInt(p, "ClientMinimumRequiredBuild", h->Option->ClientMinimumRequiredBuild);
	PackAddBool(p, "SecureNAT_RandomizeAssignIp", h->Option->SecureNAT_RandomizeAssignIp);
	PackAddBool(p, "NoPhysicalIPOnPacketLog", h->Option->NoPhysicalIPOnPacketLog);
	PackAddInt(p, "DetectDormantSessionInterval", h->Option->DetectDormantSessionInterval);
	PackAddBool(p, "FixForDLinkBPDU", h->Option->FixForDLinkBPDU);
	PackAddBool(p, "BroadcastLimiterStrictMode", h->Option->BroadcastLimiterStrictMode);
	PackAddBool(p, "NoLookBPDUBridgeId", h->Option->NoLookBPDUBridgeId);
	PackAddBool(p, "NoManageVlanId", h->Option->NoManageVlanId);
	PackAddInt(p, "VlanTypeId", h->Option->VlanTypeId);
	PackAddBool(p, "FilterOSPF", h->Option->FilterOSPF);
	PackAddBool(p, "FilterIPv4", h->Option->FilterIPv4);
	PackAddBool(p, "FilterIPv6", h->Option->FilterIPv6);
	PackAddBool(p, "FilterNonIP", h->Option->FilterNonIP);
	PackAddBool(p, "NoIPv4PacketLog", h->Option->NoIPv4PacketLog);
	PackAddBool(p, "NoIPv6PacketLog", h->Option->NoIPv6PacketLog);
	PackAddBool(p, "FilterBPDU", h->Option->FilterBPDU);
	PackAddBool(p, "NoIPv6DefaultRouterInRAWhenIPv6", h->Option->NoIPv6DefaultRouterInRAWhenIPv6);
	PackAddBool(p, "NoMacAddressLog", h->Option->NoMacAddressLog);
	PackAddBool(p, "ManageOnlyPrivateIP", h->Option->ManageOnlyPrivateIP);
	PackAddBool(p, "ManageOnlyLocalUnicastIPv6", h->Option->ManageOnlyLocalUnicastIPv6);
	PackAddBool(p, "DisableIPParsing", h->Option->DisableIPParsing);
	PackAddInt(p, "AdjustTcpMssValue", h->Option->AdjustTcpMssValue);
	PackAddBool(p, "DisableAdjustTcpMss", h->Option->DisableAdjustTcpMss);
	PackAddBool(p, "NoDhcpPacketLogOutsideHub", h->Option->NoDhcpPacketLogOutsideHub);
	PackAddBool(p, "DisableHttpParsing", h->Option->DisableHttpParsing);
	PackAddBool(p, "DisableUdpAcceleration", h->Option->DisableUdpAcceleration);
	PackAddBool(p, "DisableUdpFilterForLocalBridgeNic", h->Option->DisableUdpFilterForLocalBridgeNic);
	PackAddBool(p, "ApplyIPv4AccessListOnArpPacket", h->Option->ApplyIPv4AccessListOnArpPacket);
	PackAddBool(p, "RemoveDefGwOnDhcpForLocalhost", h->Option->RemoveDefGwOnDhcpForLocalhost);

	PackAddInt(p, "SecureNAT_MaxTcpSessionsPerIp", h->Option->SecureNAT_MaxTcpSessionsPerIp);
	PackAddInt(p, "SecureNAT_MaxTcpSynSentPerIp", h->Option->SecureNAT_MaxTcpSynSentPerIp);
	PackAddInt(p, "SecureNAT_MaxUdpSessionsPerIp", h->Option->SecureNAT_MaxUdpSessionsPerIp);
	PackAddInt(p, "SecureNAT_MaxDnsSessionsPerIp", h->Option->SecureNAT_MaxDnsSessionsPerIp);
	PackAddInt(p, "SecureNAT_MaxIcmpSessionsPerIp", h->Option->SecureNAT_MaxIcmpSessionsPerIp);
	PackAddInt(p, "AccessListIncludeFileCacheLifetime", h->Option->AccessListIncludeFileCacheLifetime);
	PackAddBool(p, "DisableKernelModeSecureNAT", h->Option->DisableKernelModeSecureNAT);
	PackAddBool(p, "DisableIpRawModeSecureNAT", h->Option->DisableIpRawModeSecureNAT);
	PackAddBool(p, "DisableUserModeSecureNAT", h->Option->DisableUserModeSecureNAT);
	PackAddBool(p, "DisableCheckMacOnLocalBridge", h->Option->DisableCheckMacOnLocalBridge);
	PackAddBool(p, "DisableCorrectIpOffloadChecksum", h->Option->DisableCorrectIpOffloadChecksum);

	PackAddInt(p, "SavePacketLog", h->LogSetting.SavePacketLog);
	PackAddInt(p, "PacketLogSwitchType", h->LogSetting.PacketLogSwitchType);
	for (i = 0;i < NUM_PACKET_LOG;i++)
	{
		PackAddIntEx(p, "PacketLogConfig", h->LogSetting.PacketLogConfig[i], i, NUM_PACKET_LOG);
	}
	PackAddInt(p, "SaveSecurityLog", h->LogSetting.SaveSecurityLog);
	PackAddInt(p, "SecurityLogSwitchType", h->LogSetting.SecurityLogSwitchType);
	PackAddData(p, "HashedPassword", h->HashedPassword, SHA1_SIZE);
	PackAddData(p, "SecurePassword", h->SecurePassword, SHA1_SIZE);
	PackAddBool(p, "UseHubNameAsDhcpUserClassOption", h->Option->UseHubNameAsDhcpUserClassOption);
	PackAddBool(p, "UseHubNameAsRadiusNasId", h->Option->UseHubNameAsRadiusNasId);

	SiAccessListToPack(p, h->AccessList);

	if (h->EnableSecureNAT)
	{
		PackAddBool(p, "EnableSecureNAT", h->EnableSecureNAT);
		OutVhOption(p, h->SecureNATOption);
	}
}

// Setting of the HUB has been updated
void SiHubUpdateProc(HUB *h)
{
	SERVER *s;
	UINT i;
	// Validate arguments
	if (h == NULL || h->Cedar == NULL || h->Cedar->Server == NULL || h->Cedar->Server->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		return;
	}

	s = h->Cedar->Server;

	if (s->FarmMemberList == NULL)
	{
		return;
	}

	if (h->LastVersion != h->CurrentVersion || h->CurrentVersion == 0)
	{
		LIST *fm_list;
		if (h->CurrentVersion == 0)
		{
			h->CurrentVersion = 1;
		}
		h->LastVersion = h->CurrentVersion;

		Debug("SiHubUpdateProc HUB=%s, Ver=%u, Type=%u, Offline=%u\n", h->Name, h->CurrentVersion,
			h->Type, h->Offline);

		fm_list = NewListFast(NULL);

		LockList(s->FarmMemberList);
		{
			while (true)
			{
				bool escape = true;
				// Update the HUB on all members
				for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
				{
					FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

					if (IsInList(fm_list, f) == false)
					{
						Add(fm_list, f);
						escape = false;

						if (f->Me == false)
						{
							SiCallUpdateHub(s, f, h);
						}

						break;
					}
				}

				if (escape)
				{
					break;
				}

				UnlockList(s->FarmMemberList);
				LockList(s->FarmMemberList);
			}
		}
		UnlockList(s->FarmMemberList);

		ReleaseList(fm_list);
	}

	if (h->Offline == false)
	{
		SiHubOnlineProc(h);
	}
}

// HUB turns to online
void SiHubOnlineProc(HUB *h)
{
	SERVER *s;
	UINT i;
	// Validate arguments
	if (h == NULL || h->Cedar->Server == NULL || h->Cedar->Server->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		// Process only on the farm controller
		return;
	}

	s = h->Cedar->Server;

	if (s->FarmMemberList == NULL)
	{
		return;
	}

	LockList(s->FarmMemberList);
	{
		if (h->Type == HUB_TYPE_FARM_STATIC)
		{
			// Static HUB
			// Create the HUB on all members
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				UINT j;
				bool exists = false;
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

				LockList(f->HubList);
				{
					for (j = 0;j < LIST_NUM(f->HubList);j++)
					{
						HUB_LIST *hh = LIST_DATA(f->HubList, j);
						if (StrCmpi(hh->Name, h->Name) == 0)
						{
							exists = true;
						}
					}
				}
				UnlockList(f->HubList);

				if (exists == false)
				{
					SiCallCreateHub(s, f, h);
				}
			}
		}
	}
	UnlockList(s->FarmMemberList);
}

// HUB turns to offline
void SiHubOfflineProc(HUB *h)
{
	SERVER *s;
	char hubname[MAX_HUBNAME_LEN + 1];
	UINT i;
	LIST *fm_list;
	// Validate arguments
	if (h == NULL || h->Cedar->Server == NULL || h->Cedar->Server->ServerType != SERVER_TYPE_FARM_CONTROLLER)
	{
		// Process only on the farm controller
		return;
	}

	s = h->Cedar->Server;

	if (s->FarmMemberList == NULL)
	{
		return;
	}

	StrCpy(hubname, sizeof(hubname), h->Name);

	fm_list = NewListFast(NULL);

	LockList(s->FarmMemberList);
	{
		while (true)
		{
			bool escape = true;

			// Stop the HUB on all members
			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);

				if (IsInList(fm_list, f) == false)
				{
					Add(fm_list, f);
					escape = false;

					SiCallDeleteHub(s, f, h);

					break;
				}
			}

			if (escape)
			{
				break;
			}

			UnlockList(s->FarmMemberList);
			LockList(s->FarmMemberList);
		}
	}
	UnlockList(s->FarmMemberList);

	ReleaseList(fm_list);
}

// Convert an access to PACK
void SiAccessToPack(PACK *p, ACCESS *a, UINT i, UINT total)
{
	// Validate arguments
	if (p == NULL || a == NULL)
	{
		return;
	}

	PackAddUniStrEx(p, "Note", a->Note, i, total);
	PackAddIntEx(p, "Active", a->Active, i, total);
	PackAddIntEx(p, "Priority", a->Priority, i, total);
	PackAddIntEx(p, "Discard", a->Discard, i, total);
	if (a->IsIPv6)
	{
		PackAddIp32Ex(p, "SrcIpAddress", 0xFDFFFFDF, i, total);
		PackAddIp32Ex(p, "SrcSubnetMask", 0xFFFFFFFF, i, total);
		PackAddIp32Ex(p, "DestIpAddress", 0xFDFFFFDF, i, total);
		PackAddIp32Ex(p, "DestSubnetMask", 0xFFFFFFFF, i, total);
	}
	else
	{
		PackAddIp32Ex(p, "SrcIpAddress", a->SrcIpAddress, i, total);
		PackAddIp32Ex(p, "SrcSubnetMask", a->SrcSubnetMask, i, total);
		PackAddIp32Ex(p, "DestIpAddress", a->DestIpAddress, i, total);
		PackAddIp32Ex(p, "DestSubnetMask", a->DestSubnetMask, i, total);
	}
	PackAddIntEx(p, "Protocol", a->Protocol, i, total);
	PackAddIntEx(p, "SrcPortStart", a->SrcPortStart, i, total);
	PackAddIntEx(p, "SrcPortEnd", a->SrcPortEnd, i, total);
	PackAddIntEx(p, "DestPortStart", a->DestPortStart, i, total);
	PackAddIntEx(p, "DestPortEnd", a->DestPortEnd, i, total);
	PackAddStrEx(p, "SrcUsername", a->SrcUsername, i, total);
	PackAddStrEx(p, "DestUsername", a->DestUsername, i, total);
	PackAddBoolEx(p, "CheckSrcMac", a->CheckSrcMac, i, total);
	PackAddDataEx(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), i, total);
	PackAddDataEx(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), i, total);
	PackAddBoolEx(p, "CheckDstMac", a->CheckDstMac, i, total);
	PackAddDataEx(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), i, total);
	PackAddDataEx(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), i, total);
	PackAddBoolEx(p, "CheckTcpState", a->CheckTcpState, i, total);
	PackAddBoolEx(p, "Established", a->Established, i, total);
	PackAddIntEx(p, "Delay", a->Delay, i, total);
	PackAddIntEx(p, "Jitter", a->Jitter, i, total);
	PackAddIntEx(p, "Loss", a->Loss, i, total);
	PackAddStrEx(p, "RedirectUrl", a->RedirectUrl, i, total);
	PackAddBoolEx(p, "IsIPv6", a->IsIPv6, i, total);
	if (a->IsIPv6)
	{
		PackAddIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, i, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, i, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, i, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, i, total);
	}
	else
	{
		IPV6_ADDR zero;

		Zero(&zero, sizeof(zero));

		PackAddIp6AddrEx(p, "SrcIpAddress6", &zero, i, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &zero, i, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &zero, i, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &zero, i, total);
	}
}

// Get number of access contained in the PACK
UINT SiNumAccessFromPack(PACK *p)
{
	// Validate arguments
	if (p == NULL)
	{
		return 0;
	}

	return PackGetIndexCount(p, "Active");
}

// Convert the PACK to access
ACCESS *SiPackToAccess(PACK *p, UINT i)
{
	ACCESS *a;
	// Validate arguments
	if (p == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(ACCESS));

	PackGetUniStrEx(p, "Note", a->Note, sizeof(a->Note), i);
	a->Active = PackGetIntEx(p, "Active", i);
	a->Priority = PackGetIntEx(p, "Priority", i);
	a->Discard = PackGetIntEx(p, "Discard", i);
	a->SrcIpAddress = PackGetIp32Ex(p, "SrcIpAddress", i);
	a->SrcSubnetMask = PackGetIp32Ex(p, "SrcSubnetMask", i);
	a->DestIpAddress = PackGetIp32Ex(p, "DestIpAddress", i);
	a->DestSubnetMask = PackGetIp32Ex(p, "DestSubnetMask", i);
	a->Protocol = PackGetIntEx(p, "Protocol", i);
	a->SrcPortStart = PackGetIntEx(p, "SrcPortStart", i);
	a->SrcPortEnd = PackGetIntEx(p, "SrcPortEnd", i);
	a->DestPortStart = PackGetIntEx(p, "DestPortStart", i);
	a->DestPortEnd = PackGetIntEx(p, "DestPortEnd", i);
	PackGetStrEx(p, "SrcUsername", a->SrcUsername, sizeof(a->SrcUsername), i);
	PackGetStrEx(p, "DestUsername", a->DestUsername, sizeof(a->DestUsername), i);
	a->CheckSrcMac = PackGetBoolEx(p, "CheckSrcMac", i);
	PackGetDataEx2(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), i);
	PackGetDataEx2(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), i);
	a->CheckDstMac = PackGetBoolEx(p, "CheckDstMac", i);
	PackGetDataEx2(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), i);
	PackGetDataEx2(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), i);
	a->CheckTcpState = PackGetBoolEx(p, "CheckTcpState", i);
	a->Established = PackGetBoolEx(p, "Established", i);
	a->Delay = PackGetIntEx(p, "Delay", i);
	a->Jitter = PackGetIntEx(p, "Jitter", i);
	a->Loss = PackGetIntEx(p, "Loss", i);
	a->IsIPv6 = PackGetBoolEx(p, "IsIPv6", i);
	PackGetStrEx(p, "RedirectUrl", a->RedirectUrl, sizeof(a->RedirectUrl), i);
	if (a->IsIPv6)
	{
		PackGetIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, i);
		PackGetIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, i);
		PackGetIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, i);
		PackGetIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, i);
	}

	return a;
}

// Convert the PACK to an access list
void SiAccessListToPack(PACK *p, LIST *o)
{
	// Validate arguments
	if (p == NULL || o == NULL)
	{
		return;
	}

	LockList(o);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(o);i++)
		{
			ACCESS *a = LIST_DATA(o, i);
			SiAccessToPack(p, a, i, LIST_NUM(o));
		}
	}
	UnlockList(o);
}

// Get the member that is hosting the specified HUB
FARM_MEMBER *SiGetHubHostingMember(SERVER *s, HUB *h, bool admin_mode, CONNECTION *c)
{
	FARM_MEMBER *ret = NULL;
	char name[MAX_SIZE];
	UINT i;
	// Validate arguments
	if (s == NULL || h == NULL || c == NULL)
	{
		return NULL;
	}

	StrCpy(name, sizeof(name), h->Name);

	if (h->Type == HUB_TYPE_FARM_STATIC)
	{
		// It is good to select any member in the case of static HUB
		if (admin_mode == false)
		{
			ret = SiGetNextFarmMember(s, c, h);
		}
		else
		{
			UINT i;
			ret = NULL;

			for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
			{
				FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
				if (f->Me)
				{
					ret = f;
					break;
				}
			}
		}
	}
	else
	{
		// Examine whether there is a member that is hosting the HUB already in the case of dynamic HUB
		for (i = 0;i < LIST_NUM(s->FarmMemberList);i++)
		{
			FARM_MEMBER *f = LIST_DATA(s->FarmMemberList, i);
			HUB_LIST *hh, t;
			StrCpy(t.Name, sizeof(t.Name), name);
			LockList(f->HubList);
			{
				hh = Search(f->HubList, &t);
				if (hh != NULL)
				{
					// Found
					ret = f;
				}
			}
			UnlockList(f->HubList);
		}

		if (ret == NULL)
		{
			// Let host the new HUB
			FARM_MEMBER *f;

			// Select the member to host
			ret = SiGetNextFarmMember(s, c, h);

			f = ret;
			if (f != NULL)
			{
				// HUB creation directive
				SiAddHubCreateHistory(s, name);
				SiCallCreateHub(s, f, h);
				SiCallUpdateHub(s, f, h);
			}
		}
	}

	return ret;
}

// Task is called
PACK *SiCalledTask(FARM_CONTROLLER *f, PACK *p, char *taskname)
{
	PACK *ret;
	SERVER *s;
	// Validate arguments
	if (f == NULL || p == NULL || taskname == NULL)
	{
		return NULL;
	}

	ret = NULL;
	s = f->Server;

	if (StrCmpi(taskname, "noop") == 0)
	{
		// NO OPERATION
		ret = NewPack();
	}
	else
	{
		Debug("Task Called: [%s].\n", taskname);
		if (StrCmpi(taskname, "createhub") == 0)
		{
			SiCalledCreateHub(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "deletehub") == 0)
		{
			SiCalledDeleteHub(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "enumhub") == 0)
		{
			ret = NewPack();
			SiCalledEnumHub(s, ret, p);
		}
		else if (StrCmpi(taskname, "updatehub") == 0)
		{
			SiCalledUpdateHub(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "createticket") == 0)
		{
			ret = SiCalledCreateTicket(s, p);
		}
		else if (StrCmpi(taskname, "enumnat") == 0)
		{
			ret = SiCalledEnumNat(s, p);
		}
		else if (StrCmpi(taskname, "enumdhcp") == 0)
		{
			ret = SiCalledEnumDhcp(s, p);
		}
		else if (StrCmpi(taskname, "getnatstatus") == 0)
		{
			ret = SiCalledGetNatStatus(s, p);
		}
		else if (StrCmpi(taskname, "enumsession") == 0)
		{
			ret = SiCalledEnumSession(s, p);
		}
		else if (StrCmpi(taskname, "deletesession") == 0)
		{
			SiCalledDeleteSession(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "deletemactable") == 0)
		{
			SiCalledDeleteMacTable(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "deleteiptable") == 0)
		{
			SiCalledDeleteIpTable(s, p);
			ret = NewPack();
		}
		else if (StrCmpi(taskname, "enummactable") == 0)
		{
			ret = SiCalledEnumMacTable(s, p);
		}
		else if (StrCmpi(taskname, "enumiptable") == 0)
		{
			ret = SiCalledEnumIpTable(s, p);
		}
		else if (StrCmpi(taskname, "getsessionstatus") == 0)
		{
			ret = SiCalledGetSessionStatus(s, p);
		}
		else if (StrCmpi(taskname, "enumlogfilelist") == 0)
		{
			ret = SiCalledEnumLogFileList(s, p);
		}
		else if (StrCmpi(taskname, "readlogfile") == 0)
		{
			ret = SiCalledReadLogFile(s, p);
		}
	}

	return ret;
}

// Call the task
PACK *SiCallTask(FARM_MEMBER *f, PACK *p, char *taskname)
{
	PACK *ret;
	char tmp[MAX_PATH];
	// Validate arguments
	if (f == NULL || p == NULL || taskname == NULL)
	{
		return NULL;
	}

	PackAddStr(p, "taskname", taskname);

	Debug("Call Task [%s] (%s)\n", taskname, f->hostname);

	Format(tmp, sizeof(tmp), "CLUSTER_CALL: Entering Call [%s] to %s", taskname, f->hostname);
	SiDebugLog(f->Cedar->Server, tmp);

	ret = SiExecTask(f, p);

	Format(tmp, sizeof(tmp), "CLUSTER_CALL: Leaving Call [%s] to %s", taskname, f->hostname);
	SiDebugLog(f->Cedar->Server, tmp);

	return ret;
}

// Task listening procedure (Main Process)
void SiAcceptTasksFromControllerMain(FARM_CONTROLLER *f, SOCK *sock)
{
	PACK *request;
	PACK *response;
	char taskname[MAX_SIZE];
	// Validate arguments
	if (f == NULL || sock == NULL)
	{
		return;
	}

	f->IsConnected = true;

	while (true)
	{
		bool ret;
		// Receive the PACK
		request = HttpClientRecv(sock);
		if (request == NULL)
		{
			// Disconnect
			break;
		}

		response = NULL;

		// Get the name
		if (PackGetStr(request, "taskname", taskname, sizeof(taskname)))
		{
			Lock(f->Server->TasksFromFarmControllerLock);
			{
				response = SiCalledTask(f, request, taskname);
			}
			Unlock(f->Server->TasksFromFarmControllerLock);
		}

		FreePack(request);

		// Return a response
		if (response == NULL)
		{
			response = NewPack();
		}
		else
		{
			PackAddInt(response, "succeed", 1);
		}

		ret = HttpClientSend(sock, response);
		FreePack(response);

		if (ret == false)
		{
			// Disconnect
			break;
		}
	}

	f->IsConnected = false;
}

// Task waiting procedure
void SiAcceptTasksFromController(FARM_CONTROLLER *f, SOCK *sock)
{
	UINT i;
	HUB **hubs;
	UINT num_hubs;
	CEDAR *c;
	SERVER *s;
	// Validate arguments
	if (f == NULL || sock == NULL)
	{
		return;
	}

	s = f->Server;
	c = s->Cedar;

	// Main process
	SiAcceptTasksFromControllerMain(f, sock);

	// Stop all Virtual HUBs since the connection to the controller is disconnected
	LockList(c->HubList);
	{
		hubs = ToArray(c->HubList);
		num_hubs = LIST_NUM(c->HubList);
		for (i = 0;i < num_hubs;i++)
		{
			AddRef(hubs[i]->ref);
		}
	}
	UnlockList(c->HubList);

	for (i = 0;i < num_hubs;i++)
	{
		SetHubOffline(hubs[i]);
		DelHub(c, hubs[i]);
		ReleaseHub(hubs[i]);
	}

	Free(hubs);
}

// Execute the task
PACK *SiExecTask(FARM_MEMBER *f, PACK *p)
{
	FARM_TASK *t;
	// Validate arguments
	if (f == NULL || p == NULL)
	{
		return NULL;
	}

	t = SiFarmServPostTask(f, p);
	if (t == NULL)
	{
		return NULL;
	}

	return SiFarmServWaitTask(t);
}

// Task queuing
FARM_TASK *SiFarmServPostTask(FARM_MEMBER *f, PACK *request)
{
	FARM_TASK *t;
	// Validate arguments
	if (f == NULL || request == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(FARM_TASK));
	t->CompleteEvent = NewEvent();
	t->Request = request;

	LockQueue(f->TaskQueue);
	{
		if (f->Halting)
		{
			// Halting (failure)
			UnlockQueue(f->TaskQueue);
			ReleaseEvent(t->CompleteEvent);
			Free(t);
			return NULL;
		}

		InsertQueue(f->TaskQueue, t);
	}
	UnlockQueue(f->TaskQueue);

	Set(f->TaskPostEvent);

	return t;
}

// Wait for task results
PACK *SiFarmServWaitTask(FARM_TASK *t)
{
	PACK *response;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	Wait(t->CompleteEvent, INFINITE);
	ReleaseEvent(t->CompleteEvent);
	FreePack(t->Request);

	response = t->Response;
	Free(t);

	if (PackGetInt(response, "succeed") == 0)
	{
		// Task calling fails for any reason
		FreePack(response);
		return NULL;
	}

	return response;
}

// Server farm processing main
void SiFarmServMain(SERVER *server, SOCK *sock, FARM_MEMBER *f)
{
	UINT wait_time = SERVER_CONTROL_TCP_TIMEOUT / 2;
	bool send_noop = false;
	UINT i;
	CEDAR *c;
	// Validate arguments
	if (server == NULL || sock == NULL || f == NULL)
	{
		Debug("SiFarmServMain Failed.\n");
		return;
	}

	Debug("SiFarmServMain Started.\n");

	c = server->Cedar;

	// Send a directive to create all static HUBs at the stage
	// where the members have been connected to the controller
	LockList(c->HubList);
	{
		for (i = 0;i < LIST_NUM(c->HubList);i++)
		{
			HUB *h = LIST_DATA(c->HubList, i);
			if (h->Offline == false)
			{
				if (h->Type == HUB_TYPE_FARM_STATIC)
				{
					PACK *p;
					HUB_LIST *hh;
					p = NewPack();
					SiPackAddCreateHub(p, h);
					PackAddStr(p, "taskname", "createhub");
					HttpServerSend(sock, p);
					FreePack(p);
					p = HttpServerRecv(sock);
					FreePack(p);

					p = NewPack();
					SiPackAddCreateHub(p, h);
					PackAddStr(p, "taskname", "updatehub");
					HttpServerSend(sock, p);
					FreePack(p);
					p = HttpServerRecv(sock);
					FreePack(p);

					hh = ZeroMalloc(sizeof(HUB_LIST));
					hh->DynamicHub = false;
					hh->FarmMember = f;
					StrCpy(hh->Name, sizeof(hh->Name), h->Name);
					LockList(f->HubList);
					{
						Add(f->HubList, hh);
					}
					UnlockList(f->HubList);
				}
			}
		}
	}
	UnlockList(c->HubList);

	Debug("SiFarmServMain: while (true)\n");

	while (true)
	{
		FARM_TASK *t;
		UINT64 tick;

		do
		{
			// Check whether a new task arrived
			LockQueue(f->TaskQueue);
			{
				t = GetNext(f->TaskQueue);
			}
			UnlockQueue(f->TaskQueue);

			if (t != NULL)
			{
				// Handle this task
				PACK *p = t->Request;
				bool ret;

				// Transmission
				ret = HttpServerSend(sock, p);
				send_noop = false;

				if (ret == false)
				{
					// Disconnected
					// Cancel this task
					Set(t->CompleteEvent);
					goto DISCONNECTED;
				}

				// Receive
				p = HttpServerRecvEx(sock, FIRM_SERV_RECV_PACK_MAX_SIZE);

				t->Response = p;
				Set(t->CompleteEvent);

				if (p == NULL)
				{
					// Avoid infinite loop
					Disconnect(sock);
					goto DISCONNECTED;
				}
			}
		}
		while (t != NULL);

		if (send_noop)
		{
			// Send a NOOP
			PACK *p;
			bool ret;
			p = NewPack();
			PackAddStr(p, "taskname", "noop");

			ret = HttpServerSend(sock, p);
			FreePack(p);

			if (ret == false)
			{
				goto DISCONNECTED;
			}

			p = HttpServerRecv(sock);
			if (p == NULL)
			{
				goto DISCONNECTED;
			}

			FreePack(p);
		}

		tick = Tick64();

		while (true)
		{
			bool break_flag;
			if ((tick + wait_time) <= Tick64())
			{
				break;
			}

			Wait(f->TaskPostEvent, 250);

			break_flag = false;
			LockQueue(f->TaskQueue);
			{
				if (f->TaskQueue->num_item != 0)
				{
					break_flag = true;
				}
			}
			UnlockQueue(f->TaskQueue);

			if (break_flag || f->Halting || server->Halt)
			{
				break;
			}
		}
		send_noop = true;
	}

DISCONNECTED:

	Debug("SiFarmServMain: DISCONNECTED\n");

	f->Halting = true;
	// Cancel all outstanding tasks
	LockQueue(f->TaskQueue);
	{
		FARM_TASK *t;

		while (t = GetNext(f->TaskQueue))
		{
			Set(t->CompleteEvent);
		}
	}
	UnlockQueue(f->TaskQueue);
}

// Farm server function that handles the connection from farm members
void SiFarmServ(SERVER *server, SOCK *sock, X *cert, UINT ip, UINT num_port, UINT *ports, char *hostname, UINT point, UINT weight, UINT max_sessions)
{
	PACK *p;
	FARM_MEMBER *f;
	UINT i;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (server == NULL || sock == NULL || cert == NULL || num_port == 0 || ports == NULL || hostname == NULL)
	{
		return;
	}

	if (weight == 0)
	{
		weight = FARM_DEFAULT_WEIGHT;
	}

	if (max_sessions == 0)
	{
		max_sessions = SERVER_MAX_SESSIONS;
	}

	if (ip == 0)
	{
		// If the public IP address is not specified, specify the connection
		// source IP address of this farm member server
		ip = IPToUINT(&sock->RemoteIP);
	}

	IPToStr32(tmp, sizeof(tmp), ip);
	SLog(server->Cedar, "LS_FARM_SERV_START", tmp, hostname);

	// Inform the success
	p = NewPack();
	HttpServerSend(sock, p);
	FreePack(p);

	IPToStr32(tmp, sizeof(tmp), ip);
	Debug("Farm Member %s Connected. IP: %s\n", hostname, tmp);

	SetTimeout(sock, SERVER_CONTROL_TCP_TIMEOUT);

	f = ZeroMalloc(sizeof(FARM_MEMBER));
	f->Cedar = server->Cedar;
	f->Ip = ip;
	f->NumPort = num_port;
	f->Ports = ports;
	StrCpy(f->hostname, sizeof(f->hostname), hostname);
	f->ServerCert = cert;
	f->ConnectedTime = SystemTime64();
	f->Weight = weight;
	f->MaxSessions = max_sessions;

	f->HubList = NewList(CompareHubList);
	f->Point = point;

	f->TaskQueue = NewQueue();
	f->TaskPostEvent = NewEvent();

	// Add to the list
	LockList(server->FarmMemberList);
	{
		Add(server->FarmMemberList, f);
	}
	UnlockList(server->FarmMemberList);

	// Main process
	SiFarmServMain(server, sock, f);

	// Remove from the list
	LockList(server->FarmMemberList);
	{
		Delete(server->FarmMemberList, f);
	}
	UnlockList(server->FarmMemberList);

	ReleaseQueue(f->TaskQueue);
	ReleaseEvent(f->TaskPostEvent);

	for (i = 0;i < LIST_NUM(f->HubList);i++)
	{
		HUB_LIST *hh = LIST_DATA(f->HubList, i);
		Free(hh);
	}

	ReleaseList(f->HubList);

	Free(f);

	SLog(server->Cedar, "LS_FARM_SERV_END", hostname);
}

// Search in HUB list
int CompareHubList(void *p1, void *p2)
{
	HUB_LIST *h1, *h2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	h1 = *(HUB_LIST **)p1;
	h2 = *(HUB_LIST **)p2;
	if (h1 == NULL || h2 == NULL)
	{
		return 0;
	}
	return StrCmpi(h1->Name, h2->Name);
}

// Connection thread to the controller
void SiConnectToControllerThread(THREAD *thread, void *param)
{
	FARM_CONTROLLER *f;
	SESSION *s;
	CONNECTION *c;
	SERVER *server;
	bool first_failed;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	MsSetThreadPriorityRealtime();
#endif	// OS_WIN32

	f = (FARM_CONTROLLER *)param;
	f->Thread = thread;
	AddRef(f->Thread->ref);
	NoticeThreadInit(thread);

	f->StartedTime = SystemTime64();

	server = f->Server;

	SLog(server->Cedar, "LS_FARM_CONNECT_1", server->ControllerName);

	first_failed = true;

	while (true)
	{
		// Attempt to connect
		CLIENT_OPTION o;

		f->LastError = ERR_TRYING_TO_CONNECT;

		Zero(&o, sizeof(CLIENT_OPTION));
		StrCpy(o.Hostname, sizeof(o.Hostname), server->ControllerName);
		o.Port = server->ControllerPort;
		f->NumTry++;

		Debug("Try to Connect %s (Controller).\n", server->ControllerName);

		s = NewRpcSessionEx(server->Cedar, &o, NULL, CEDAR_SERVER_FARM_STR);

		if (s != NULL)
		{
			// Connection success: send the authentication data
			PACK *p = NewPack();
			UCHAR secure_password[SHA1_SIZE];
			BUF *b;

			c = s->Connection;

			Lock(f->lock);
			{
				f->Sock = c->FirstSock;
				AddRef(f->Sock->ref);
				SetTimeout(f->Sock, SERVER_CONTROL_TCP_TIMEOUT);
			}
			Unlock(f->lock);

			// Method
			PackAddStr(p, "method", "farm_connect");
			PackAddClientVersion(p, s->Connection);

			// Password
			SecurePassword(secure_password, server->MemberPassword, s->Connection->Random);
			PackAddData(p, "SecurePassword", secure_password, sizeof(secure_password));

			Lock(server->Cedar->lock);
			{
				b = XToBuf(server->Cedar->ServerX, false);
			}
			Unlock(server->Cedar->lock);

			if (b != NULL)
			{
				char tmp[MAX_SIZE];
				bool ret;
				UINT i;
				// Server certificate
				PackAddBuf(p, "ServerCert", b);
				FreeBuf(b);

				// Maximum number of sessions
				PackAddInt(p, "MaxSessions", GetServerCapsInt(server, "i_max_sessions"));

				// Point
				PackAddInt(p, "Point", SiGetPoint(server));
				PackAddInt(p, "Weight", server->Weight);

				// Host name
				GetMachineName(tmp, sizeof(tmp));
				PackAddStr(p, "HostName", tmp);

				// Public IP
				PackAddIp32(p, "PublicIp", server->PublicIp);

				// Public port
				for (i = 0;i < server->NumPublicPort;i++)
				{
					PackAddIntEx(p, "PublicPort", server->PublicPorts[i], i, server->NumPublicPort);
				}

				ret = HttpClientSend(c->FirstSock, p);

				if (ret)
				{
					PACK *p;
					UINT err = ERR_PROTOCOL_ERROR;

					first_failed = true;
					p = HttpClientRecv(c->FirstSock);
					if (p != NULL && (err = GetErrorFromPack(p)) == 0)
					{
						// Successful connection
						SLog(server->Cedar, "LS_FARM_START");
						f->CurrentConnectedTime = SystemTime64();
						if (f->FirstConnectedTime == 0)
						{
							f->FirstConnectedTime = SystemTime64();
						}
						f->NumConnected++;
						Debug("Connect Succeed.\n");
						f->Online = true;

						// Main process
						SiAcceptTasksFromController(f, c->FirstSock);

						f->Online = false;
					}
					else
					{
						// Error
						f->LastError = err;
						SLog(server->Cedar, "LS_FARM_CONNECT_2", server->ControllerName,
							GetUniErrorStr(err), err);
					}
					FreePack(p);
				}
				else
				{
					f->LastError = ERR_DISCONNECTED;

					if (first_failed)
					{
						SLog(server->Cedar, "LS_FARM_CONNECT_3", server->ControllerName, RETRY_CONNECT_TO_CONTROLLER_INTERVAL / 1000);
						first_failed = false;
					}
				}
			}

			FreePack(p);

			// Disconnect
			Lock(f->lock);
			{
				if (f->Sock != NULL)
				{
					ReleaseSock(f->Sock);
					f->Sock = NULL;
				}
			}
			Unlock(f->lock);

			ReleaseSession(s);
			s = NULL;

			if (f->LastError == ERR_TRYING_TO_CONNECT)
			{
				f->LastError = ERR_DISCONNECTED;
			}
		}
		else
		{
			// Connection failure
			f->LastError = ERR_CONNECT_TO_FARM_CONTROLLER;

			if (first_failed)
			{
				SLog(server->Cedar, "LS_FARM_CONNECT_3", server->ControllerName, RETRY_CONNECT_TO_CONTROLLER_INTERVAL / 1000);
				first_failed = false;
			}
		}

		Debug("Controller Disconnected. ERROR = %S\n", _E(f->LastError));

		f->NumFailed = f->NumTry - f->NumConnected;

		// Wait for event
		Wait(f->HaltEvent, RETRY_CONNECT_TO_CONTROLLER_INTERVAL);

		if (f->Halt)
		{
			// Halting flag
			break;
		}
	}

	SLog(server->Cedar, "LS_FARM_DISCONNECT");
}

// Disconnect the connection to the controller
void SiStopConnectToController(FARM_CONTROLLER *f)
{
	// Validate arguments
	if (f == NULL)
	{
		return;
	}

	f->Halt = true;

	// Stop the connection
	Lock(f->lock);
	{
		Disconnect(f->Sock);
	}
	Unlock(f->lock);

	Set(f->HaltEvent);

	// Wait for the thread termination
	WaitThread(f->Thread, INFINITE);
	ReleaseThread(f->Thread);

	DeleteLock(f->lock);
	ReleaseEvent(f->HaltEvent);

	Free(f);
}

// Start a connection to the controller
FARM_CONTROLLER *SiStartConnectToController(SERVER *s)
{
	FARM_CONTROLLER *f;
	THREAD *t;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	f = ZeroMalloc(sizeof(FARM_CONTROLLER));
	f->Server = s;
	f->LastError = ERR_TRYING_TO_CONNECT;
	f->HaltEvent = NewEvent();
	f->lock = NewLock();

	t = NewThread(SiConnectToControllerThread, f);
	WaitThreadInit(t);
	ReleaseThread(t);

	return f;
}

// Get the current version
void SiGetCurrentRegion(CEDAR *c, char *region, UINT region_size)
{
	ClearStr(region, region_size);
	// Validate arguments
	if (c == NULL || region == NULL)
	{
		return;
	}

	Lock(c->CurrentRegionLock);
	{
		StrCpy(region, region_size, c->CurrentRegion);
	}
	Unlock(c->CurrentRegionLock);

	if (IsEmptyStr(region))
	{
		if (GetCurrentLangId() == SE_LANG_JAPANESE)
		{
			StrCpy(region, region_size, "JP");
		}
		else if (GetCurrentLangId() == SE_LANG_CHINESE_ZH)
		{
			StrCpy(region, region_size, "CN");
		}
	}
}

// Check whether some enterprise functions are restricted
// 
// ** Hints by Daiyuu Nobori, written on March 19, 2014 **
// 
// The following 'enterprise functions' are implemented on SoftEther VPN Server
// since March 19, 2014. However, these functions are disabled on
// SoftEther VPN Servers which run in Japan and China.
// 
// - RADIUS / NT Domain user authentication
// - RSA certificate authentication
// - Deep-inspect packet logging
// - Source IP address control list
// - syslog transfer
// 
// The SoftEther VPN Project intentionally disables these functions for users
// in Japan and China. The reason is: Daiyuu Nobori, the chief author of
// SoftEther VPN, has been liable to observe the existing agreements and
// restrictions between him and some companies. The agreements have regulated
// the region-limited restriction to implement and distribute the above
// enterprise functions on the SoftEther VPN open-source program.
// 
// Therefore, the SoftEther VPN Project distributes the binary program and
// the source code with the "SiIsEnterpriseFunctionsRestrictedOnOpenSource"
// function. This function identifies whether the SoftEther VPN Server
// program is running in either Japan or China. If the restricted region is
// detected, then the above enterprise functions will be disabled.
// 
// Please note that the above restriction has been imposed only on the
// original binaries and source codes from the SoftEther VPN Project.
// Anyone, except Daiyuu Nobori, who understands and writes the C language
// program can remove this restriction at his own risk.
// 
bool SiIsEnterpriseFunctionsRestrictedOnOpenSource(CEDAR *c)
{
	char region[128];
	bool ret = false;
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}


	SiGetCurrentRegion(c, region, sizeof(region));

	if (StrCmpi(region, "JP") == 0 || StrCmpi(region, "CN") == 0)
	{
		ret = true;
	}

	return ret;
}

// Update the current region
void SiUpdateCurrentRegion(CEDAR *c, char *region, bool force_update)
{
	bool changed = false;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (IsEmptyStr(region) == false)
	{
		Lock(c->CurrentRegionLock);
		{
			if (StrCmpi(c->CurrentRegion, region) != 0)
			{
				StrCpy(c->CurrentRegion, sizeof(c->CurrentRegion), region);
				changed = true;
			}
		}
		Unlock(c->CurrentRegionLock);
	}

	if (force_update)
	{
		changed = true;
	}

	if (changed)
	{
		FlushServerCaps(c->Server);
	}
}

// Create a server
SERVER *SiNewServer(bool bridge)
{
	return SiNewServerEx(bridge, false, false);
}
SERVER *SiNewServerEx(bool bridge, bool in_client_inner_server, bool relay_server)
{
	SERVER *s;
	LISTENER *inproc;
	LISTENER *azure;
	LISTENER *rudp;

	SetGetIpThreadMaxNum(DEFAULT_GETIP_THREAD_MAX_NUM);

	s = ZeroMalloc(sizeof(SERVER));

	SetEraserCheckInterval(0);

	SiInitHubCreateHistory(s);

	InitServerCapsCache(s);

	Rand(s->MyRandomKey, sizeof(s->MyRandomKey));

	s->lock = NewLock();


	s->OpenVpnSstpConfigLock = NewLock();
	s->SaveCfgLock = NewLock();
	s->ref = NewRef();
	s->Cedar = NewCedar(NULL, NULL);
	s->Cedar->Server = s;


#ifdef	OS_WIN32
	s->IsInVm = MsIsInVm();
#else	// OS_WIN32
	s->IsInVm = UnixIsInVm();
#endif	// OS_WIN32

#ifdef	ENABLE_AZURE_SERVER
	if (IsFileExists("@azureserver.config"))
	{
		DisableRDUPServerGlobally();
		s->AzureServer = NewAzureServer(s->Cedar);

		SleepThread(500);
	}
#endif	// ENABLE_AZURE_SERVER

	s->Cedar->CheckExpires = true;
	s->ServerListenerList = NewList(CompareServerListener);
	s->PortsUDP = NewIntList(true);
	s->StartTime = SystemTime64();
	s->TasksFromFarmControllerLock = NewLock();

	if (bridge)
	{
		SetCedarVpnBridge(s->Cedar);
	}

#ifdef OS_WIN32
	if (IsHamMode() == false)
	{
		RegistWindowsFirewallAll();
	}
#endif

	s->Keep = StartKeep();

	// Log related
	MakeDir(bridge == false ? SERVER_LOG_DIR_NAME : BRIDGE_LOG_DIR_NAME);
	s->Logger = NewLog(bridge == false ? SERVER_LOG_DIR_NAME : BRIDGE_LOG_DIR_NAME, SERVER_LOG_PERFIX, LOG_SWITCH_DAY);

	SLog(s->Cedar, "L_LINE");
	SLog(s->Cedar, "LS_START_2", s->Cedar->ServerStr, s->Cedar->VerString);
	SLog(s->Cedar, "LS_START_3", s->Cedar->BuildInfo);
	SLog(s->Cedar, "LS_START_UTF8");
	SLog(s->Cedar, "LS_START_1");



	// Initialize the configuration
	SiInitConfiguration(s);

	s->Syslog = NewSysLog(NULL, 0, &s->Cedar->Server->ListenIP);
	s->SyslogLock = NewLock();

	SetFifoCurrentReallocMemSize(MEM_FIFO_REALLOC_MEM_SIZE);


	// Raise the priority
	if (s->NoHighPriorityProcess == false)
	{
		OSSetHighPriority();
	}

#ifdef	OS_UNIX
	UnixSetHighOomScore();
#endif	// OS_UNIX

	if (s->ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		// Start a connection to the controller
		s->FarmController = SiStartConnectToController(s);
	}
	else if (s->ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		FARM_MEMBER *f;
		// Start operating as a controller
		s->FarmMemberList = NewList(NULL);

		f = ZeroMalloc(sizeof(FARM_MEMBER));
		f->Cedar = s->Cedar;
		GetMachineName(f->hostname, sizeof(f->hostname));
		f->Me = true;
		f->HubList = NewList(CompareHubList);
		f->Weight = s->Weight;

		s->Me = f;

		Add(s->FarmMemberList, f);

		SiStartFarmControl(s);

		s->FarmControllerInited = true;
	}

	// Start a in-processlistener 
	inproc = NewListener(s->Cedar, LISTENER_INPROC, 0);
	ReleaseListener(inproc);

	// Start a listener for Azure
	if (s->AzureClient != NULL)
	{
		azure = NewListener(s->Cedar, LISTENER_REVERSE, 0);
		ReleaseListener(azure);
	}

	// Start a R-UDP listener
	if (s->DisableNatTraversal == false && s->Cedar->Bridge == false)
	{
		rudp = NewListenerEx4(s->Cedar, LISTENER_RUDP, 0, TCPAcceptedThread, NULL, false, false,
			&s->NatTGlobalUdpPort, RAND_PORT_ID_SERVER_LISTEN);
		ReleaseListener(rudp);
	}

	// Start a VPN-over-ICMP listener
	s->DynListenerIcmp = NewDynamicListener(s->Cedar, &s->EnableVpnOverIcmp, LISTENER_ICMP, 0);

	// Start a VPN-over-DNS listener
	s->DynListenerDns = NewDynamicListener(s->Cedar, &s->EnableVpnOverDns, LISTENER_DNS, 53);


	SiInitDeadLockCheck(s);

	SiUpdateCurrentRegion(s->Cedar, "", true);

	return s;
}

