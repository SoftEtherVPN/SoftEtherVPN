// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Command.c
// vpncmd Command Line Management Utility

#include "CedarPch.h"

// System checker definition
typedef bool (CHECKER_PROC_DEF)();
typedef struct CHECKER_PROC
{
	char *Title;
	CHECKER_PROC_DEF *Proc;
} CHECKER_PROC;

static CHECKER_PROC checker_procs[] =
{
	{"CHECK_PROC_KERNEL", CheckKernel},
	{"CHECK_PROC_MEMORY", CheckMemory},
	{"CHECK_PROC_STRINGS", CheckStrings},
	{"CHECK_PROC_FILESYSTEM", CheckFileSystem},
	{"CHECK_PROC_THREAD", CheckThread},
	{"CHECK_PROC_NETWORK", CheckNetwork},
};

typedef struct CHECK_NETWORK_1
{
	SOCK *ListenSocket;
} CHECK_NETWORK_1;

typedef struct CHECK_NETWORK_2
{
	SOCK *s;
	X *x;
	K *k;
} CHECK_NETWORK_2;


// Accept thread
void CheckNetworkAcceptThread(THREAD *thread, void *param)
{
	CHECK_NETWORK_2 *c = (CHECK_NETWORK_2 *)param;
	SOCK *s = c->s;
	UINT i = 0;

	if (StartSSL(s, c->x, c->k))
	{
		while (true)
		{
			i++;
			if (Send(s, &i, sizeof(UINT), true) == 0)
			{
				break;
			}
		}
	}

	Disconnect(s);
	ReleaseSock(s);
}


// Listen thread
void CheckNetworkListenThread(THREAD *thread, void *param)
{
	CHECK_NETWORK_1 *c = (CHECK_NETWORK_1 *)param;
	SOCK *s;
	UINT i;
	K *pub, *pri;
	X *x;
	LIST *o = NewList(NULL);
	NAME *name = NewName(L"Test", L"Test", L"Test", L"JP", L"Ibaraki", L"Tsukuba");

	RsaGen(&pri, &pub, 1024);
	x = NewRootX(pub, pri, name, 1000, NULL);

	FreeName(name);

	for (i = 1025;;i++)
	{
		s = Listen(i);
		if (s != NULL)
		{
			break;
		}
	}

	c->ListenSocket = s;
	AddRef(s->ref);

	NoticeThreadInit(thread);

	while (true)
	{
		SOCK *new_sock = Accept(s);

		if (new_sock == NULL)
		{
			break;
		}
		else
		{
			CHECK_NETWORK_2 c;
			THREAD *t;

			Zero(&c, sizeof(c));
			c.s = new_sock;
			c.k = pri;
			c.x = x;

			t = NewThread(CheckNetworkAcceptThread, &c);
			Insert(o, t);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		THREAD *t = LIST_DATA(o, i);
		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	FreeK(pri);
	FreeK(pub);

	FreeX(x);

	ReleaseSock(s);
	ReleaseList(o);
}

// Network function check
bool CheckNetwork()
{
	CHECK_NETWORK_1 c;
	THREAD *t;
	SOCK *listen_socket;
	UINT port;
	UINT i, num;
	bool ok = true;
	SOCK **socks;
	SOCK_EVENT *se = NewSockEvent();

	Zero(&c, sizeof(c));
	t = NewThread(CheckNetworkListenThread, &c);
	WaitThreadInit(t);

	listen_socket = c.ListenSocket;

	port = listen_socket->LocalPort;

	num = 8;
	socks = ZeroMalloc(sizeof(SOCK *) * num);
	for (i = 0;i < num;i++)
	{
		socks[i] = Connect("localhost", port);
		if (socks[i] == NULL)
		{
			Print("Connect Failed. (%u)\n", i);
			ok = false;
			num = i;
			break;
		}
		if (StartSSL(socks[i], NULL, NULL) == false)
		{
			ReleaseSock(socks[i]);
			Print("Connect Failed. (%u)\n", i);
			ok = false;
			num = i;
			break;
		}

		JoinSockToSockEvent(socks[i], se);
	}

	if (ok)
	{
		while (true)
		{
			UINT i;
			bool end = false;
			bool all_blocked = true;

			for (i = 0;i < num;i++)
			{
				UINT n;
				UINT ret;

				n = 0;
				ret = Recv(socks[i], &n, sizeof(UINT), true);
				if (ret == 0)
				{
					Print("Recv Failed (Disconnected).\n", ret);
					end = true;
					ok = false;
				}
				if (ret != SOCK_LATER)
				{
					all_blocked = false;
				}

				if (n >= 128)
				{
					end = true;
				}
			}

			if (end)
			{
				break;
			}

			if (all_blocked)
			{
				WaitSockEvent(se, INFINITE);
			}
		}
	}

	for (i = 0;i < num;i++)
	{
		Disconnect(socks[i]);
		ReleaseSock(socks[i]);
	}
	Free(socks);

	Disconnect(listen_socket);

	WaitThread(t, INFINITE);
	ReleaseThread(t);

	ReleaseSock(listen_socket);

	ReleaseSockEvent(se);

	return ok;
}

typedef struct CHECK_THREAD_1
{
	UINT num;
	LOCK *lock;
	THREAD *wait_thread;
} CHECK_THREAD_1;

static UINT check_thread_global_1 = 0;

#define	CHECK_THREAD_INCREMENT_COUNT		32

// Test thread 1
void CheckThread1(THREAD *thread, void *param)
{
	CHECK_THREAD_1 *ct1 = (CHECK_THREAD_1 *)param;
	UINT i;
	UINT num = CHECK_THREAD_INCREMENT_COUNT;

	WaitThread(ct1->wait_thread, INFINITE);

	for (i = 0;i < num;i++)
	{
		Lock(ct1->lock);
		check_thread_global_1 = ct1->num;
		InputToNull((void *)check_thread_global_1);
		check_thread_global_1 = check_thread_global_1 + 1 + RetZero();
		ct1->num = check_thread_global_1;
		Unlock(ct1->lock);
	}
}

// Test thread 2
void CheckThread2(THREAD *thread, void *param)
{
	EVENT *e = (EVENT *)param;
	Wait(e, INFINITE);
}

typedef struct CHECK_THREAD_3
{
	UINT num, a;
} CHECK_THREAD_3;

// Test thread 3
void CheckThread3(THREAD *thread, void *param)
{
	CHECK_THREAD_3 *c = (CHECK_THREAD_3 *)param;
	THREAD *t;

	if (c->num == 0)
	{
		return;
	}
	c->num--;
	c->a++;

	t = NewThread(CheckThread3, c);
	WaitThread(t, INFINITE);
	ReleaseThread(t);
}

// Thread check
bool CheckThread()
{
	bool ok = true;
	CHECK_THREAD_1 ct1;
	UINT num = 32;
	UINT i;
	THREAD **threads;
	EVENT *e;
	THREAD *t2;
	THREAD *t;
	CHECK_THREAD_3 c;

	e = NewEvent();

	Zero(&ct1, sizeof(ct1));
	ct1.lock = NewLock();

	t2 = NewThread(CheckThread2, e);
	ct1.wait_thread = t2;

	threads = ZeroMalloc(sizeof(THREAD *) * num);
	for (i = 0;i < num;i++)
	{
		threads[i] = NewThread(CheckThread1, &ct1);
		if (threads[i] == NULL)
		{
			Print("Thread %u Create Failed.\n", i);
			ok = false;
		}
	}

	Set(e);

	for (i = 0;i < num;i++)
	{
		WaitThread(threads[i], INFINITE);
		ReleaseThread(threads[i]);
	}

	Free(threads);

	if (ct1.num != (num * CHECK_THREAD_INCREMENT_COUNT))
	{
		Print("Threading: %u != %u\n", ct1.num, num * CHECK_THREAD_INCREMENT_COUNT);
		ok = false;
	}

	DeleteLock(ct1.lock);

	WaitThread(t2, INFINITE);
	ReleaseThread(t2);

	ReleaseEvent(e);

	num = 32;

	Zero(&c, sizeof(c));
	c.num = num;
	t = NewThread(CheckThread3, &c);
	WaitThread(t, INFINITE);
	ReleaseThread(t);

	if (c.a != num)
	{
		Print("Threading: %u != %u\n", c.a, num);
		ok = false;
	}

	return ok;
}

// File system check
bool CheckFileSystem()
{
	bool ok = false;
	char exe[MAX_PATH];
	char exe_dir[MAX_PATH];
	DIRLIST *dirs;
	UINT i;

	GetExeName(exe, sizeof(exe));
	GetExeDir(exe_dir, sizeof(exe_dir));

	dirs = EnumDir(exe_dir);
	for (i = 0;i < dirs->NumFiles;i++)
	{
		if (EndWith(exe, dirs->File[i]->FileName))
		{
			ok = true;
			break;
		}
	}
	FreeDir(dirs);

	if (ok == false)
	{
		Print("EnumDir Failed.\n");
		return false;
	}
	else
	{
		UINT size = 1234567;
		UCHAR *buf;
		IO *io;
#ifndef	OS_WIN32
		wchar_t *filename = L"/tmp/vpn_checker_tmp";
#else	// OS_WIN32
		wchar_t filename[MAX_PATH];
		CombinePathW(filename, sizeof(filename), MsGetMyTempDirW(), L"vpn_checker_tmp");
#endif	// OS_WIN32

		buf = Malloc(size);
		for (i = 0;i < size;i++)
		{
			buf[i] = i % 256;
		}

		io = FileCreateW(filename);
		if (io == NULL)
		{
			Print("FileCreate Failed.\n");
			Free(buf);
			return false;
		}
		else
		{
			FileWrite(io, buf, size);
			Free(buf);
			FileClose(io);

			io = FileOpenW(filename, false);
			if (FileSize(io) != 1234567)
			{
				Print("FileSize Failed.\n");
				FileClose(io);
				return false;
			}
			else
			{
				BUF *b;

				FileClose(io);
				b = ReadDumpW(filename);
				if(b == NULL)
				{
					return false;
				}

				for (i = 0;i < b->Size;i++)
				{
					UCHAR c = ((UCHAR *)b->Buf)[i];

					if (c != (i % 256))
					{
						Print("FileToBuf Failed.\n");
						FreeBuf(b);
						return false;
					}
				}

				FreeBuf(b);
			}
		}

		FileDeleteW(filename);
	}

	return ok;
}

// String check
bool CheckStrings()
{
	wchar_t *numstr = _UU("CHECK_TEST_123456789");
	char tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	UINT i;
	UINT sum, sum2;
	UNI_TOKEN_LIST *t;

	UniStrCpy(tmp2, sizeof(tmp2), L"");

	sum2 = 0;
	for (i = 0;i < 64;i++)
	{
		sum2 += i;
		UniFormat(tmp2, sizeof(tmp2), L"%s,%u", tmp2, i);
	}

	t = UniParseToken(tmp2, L",");

	sum = 0;

	for (i = 0;i < t->NumTokens;i++)
	{
		wchar_t *s = t->Token[i];
		UINT n = UniToInt(s);

		sum += n;
	}

	UniFreeToken(t);

	if (sum != sum2)
	{
		Print("UniParseToken Failed.\n");
		return false;
	}

	if (UniToInt(numstr) != 123456789)
	{
		Print("UniToInt Failed.\n");
		return false;
	}

	UniToStr(tmp, sizeof(tmp), numstr);
	if (ToInt(tmp) != 123456789)
	{
		Print("UniToStr Failed.\n");
		return false;
	}

	return true;
}

// Memory check
bool CheckMemory()
{
	UINT i, num, size, j;
	void **pp;
	bool ok = true;
	UINT old_size;

	num = 2000;
	size = 1000;
	pp = ZeroMalloc(sizeof(void *) * num);
	for (i = 0;i < num;i++)
	{
		pp[i] = ZeroMalloc(size);
		InputToNull(pp[i]);
		for (j = 0;j < size;j++)
		{
			((UCHAR *)pp[i])[j] = j % 256;
		}
	}
	old_size = size;
	size = size * 3;
	for (i = 0;i < num;i++)
	{
		pp[i] = ReAlloc(pp[i], size);
		for (j = old_size;j < size;j++)
		{
			InputToNull((void *)(UINT)(((UCHAR *)pp[i])[j] = j % 256));
		}
	}
	for (i = 0;i < num;i++)
	{
		for (j = 0;j < size;j++)
		{
			if (((UCHAR *)pp[i])[j] != (j % 256))
			{
				ok = false;
			}
		}
		Free(pp[i]);
	}
	Free(pp);

	return ok;
}

// Function that do not do anything
void InputToNull(void *p)
{
	if (RetZero() == 1)
	{
		UCHAR *c = (UCHAR *)p;
		c[0] = 0x32;
	}
}

// Function that returns 0
UINT RetZero()
{
	if (g_debug == 0x123455)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}


// Kernel check
bool CheckKernel()
{
	UINT num = 10, i;
	UINT64 s = Tick64();
	UINT64 t = Tick64();

	for (i = 0;i < num;i++)
	{
		UINT64 q = Tick64();
		if (t > q)
		{
			Print("Tick64 #1 Failed.\n");
			return false;
		}

		t = q;

		SleepThread(100);
	}

	t = (Tick64() - s);
	if (t <= 500 || t >= 2000)
	{
		Print("Tick64 #2 Failed.\n");
		return false;
	}
	else if (false)
	{
		UINT64 tick1 = Tick64();
		UINT64 time1;
		UINT64 time2;

		SleepThread(1000);

		time2 = LocalTime64();
		time1 = SystemToLocal64(TickToTime(tick1));

		if (time2 > time1)
		{
			s = time2 - time1;
		}
		else
		{
			s = time1 - time2;
		}

		if (s <= 500 || s >= 2000)
		{
			Print("TickToTime Failed.\n");
			return false;
		}
	}

#ifdef	OS_UNIX
	{
		// Test of child process
		UINT pid;
		char exe[MAX_SIZE];

		GetExeName(exe, sizeof(exe));

		pid = fork();

		if (pid == -1)
		{
			Print("fork Failed.\n");
			return false;
		}

		if (pid == 0)
		{
			char *param = UNIX_ARG_EXIT;
			char **args;

			args = ZeroMalloc(sizeof(char *) * 3);
			args[0] = exe;
			args[1] = param;
			args[2] = NULL;

			setsid();

			// Close the standard I/O
			UnixCloseIO();

			// Stop unwanted signals
			signal(SIGHUP, SIG_IGN);

			execvp(exe, args);
			AbortExit();
		}
		else
		{
			int status = 0, ret;

			// Wait for the termination of the child process
			ret = waitpid(pid, &status, 0);

			if (WIFEXITED(status) == 0)
			{
				// Aborted
				Print("waitpid Failed: 0x%x\n", ret);
				return false;
			}
		}
	}
#endif	// OS_UNIX

	return true;
}

// System checker
bool SystemCheck()
{
	UINT i;
	bool ng = false;

	UniPrint(_UU("CHECK_TITLE"));
	UniPrint(_UU("CHECK_NOTE"));
	for (i = 0;i < sizeof(checker_procs) / sizeof(checker_procs[0]);i++)
	{
		wchar_t *title;
		bool ret = false;
		CHECKER_PROC *p = &checker_procs[i];

		title = _UU(p->Title);

		UniPrint(_UU("CHECK_EXEC_TAG"), title);

		ret = p->Proc();

		if (ret == false)
		{
			ng = true;
		}

		UniPrint(L"              %s\n", ret ? _UU("CHECK_PASS") : _UU("CHECK_FAIL"));
	}

	UniPrint(L"\n");
	if (ng == false)
	{
		UniPrint(L"%s\n\n", _UU("CHECK_RESULT_1"));
	}
	else
	{
		UniPrint(L"%s\n\n", _UU("CHECK_RESULT_2"));
	}

	return true;
}


// Behavior checker
UINT PtCheck(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (SystemCheck() == false)
	{
		ret = ERR_INTERNAL_ERROR;
	}

	FreeParamValueList(o);

	return ret;
}

// VPN Tools main function
void PtMain(PT *pt)
{
	char prompt[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (pt == NULL)
	{
		return;
	}

	// Display a message that start-up is complete
	UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_TOOLS_CONNECTED"));
	pt->Console->Write(pt->Console, tmp);
	pt->Console->Write(pt->Console, L"");

	while (true)
	{
		// Definition of command
		CMD cmd[] =
		{
			{"About", PsAbout},
			{"MakeCert", PtMakeCert},
			{"MakeCert2048", PtMakeCert2048},
			{"TrafficClient", PtTrafficClient},
			{"TrafficServer", PtTrafficServer},
			{"Check", PtCheck},
		};

		// Generate a prompt
		StrCpy(prompt, sizeof(prompt), "VPN Tools>");

		if (DispatchNextCmdEx(pt->Console, pt->CmdLine, prompt, cmd, sizeof(cmd) / sizeof(cmd[0]), pt) == false)
		{
			break;
		}
		pt->LastError = pt->Console->RetCode;

		if (pt->LastError == ERR_NO_ERROR && pt->Console->ConsoleType != CONSOLE_CSV)
		{
			pt->Console->Write(pt->Console, _UU("CMD_MSG_OK"));
			pt->Console->Write(pt->Console, L"");
		}

		if (pt->CmdLine != NULL)
		{
			break;
		}
	}
}

// Create a VPN Tools context
PT *NewPt(CONSOLE *c, wchar_t *cmdline)
{
	PT *pt;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	if (UniIsEmptyStr(cmdline))
	{
		cmdline = NULL;
	}

	pt = ZeroMalloc(sizeof(PT));
	pt->Console = c;
	pt->CmdLine = CopyUniStr(cmdline);

	return pt;
}

// Release the VPN Tools context
void FreePt(PT *pt)
{
	// Validate arguments
	if (pt == NULL)
	{
		return;
	}

	Free(pt->CmdLine);
	Free(pt);
}

// Start VPN Tools
UINT PtConnect(CONSOLE *c, wchar_t *cmdline)
{
	PT *pt;
	UINT ret = 0;
	// Validate arguments
	if (c == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	pt = NewPt(c, cmdline);

	PtMain(pt);

	ret = pt->LastError;

	FreePt(pt);

	return ret;
}

// Initialize the execution path information of vpncmd command
void VpnCmdInitBootPath()
{
#ifdef	OS_WIN32
	char exe_path[MAX_PATH];
	char tmp[MAX_PATH];
	GetExeName(exe_path, sizeof(exe_path));

	if (SearchStrEx(exe_path, "ham.exe", 0, false) != INFINITE)
	{
		return;
	}

	if (MsIsAdmin())
	{
		UINT current_ver;

		// Get the version of vpncmd that is currently installed
		current_ver = MsRegReadInt(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER);

		if ((CEDAR_VERSION_BUILD >= current_ver) ||
			MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
		{
			bool b = false;
			// Copy the vpncmdsys.exe to system32
			if (MsIsNt())
			{
				Format(tmp, sizeof(tmp), "%s\\vpncmd.exe", MsGetSystem32Dir());
			}
			else
			{
				Format(tmp, sizeof(tmp), "%s\\vpncmd.exe", MsGetWindowsDir());
			}

			if (MsIs64BitWindows() == false || Is64())
			{
				if (IsFile(tmp) == false || (CEDAR_VERSION_BUILD > current_ver) || MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
				{
					b = FileCopy(VPNCMD_BOOTSTRAP_FILENAME, tmp);
				}
			}
			else
			{
				void *wow = MsDisableWow64FileSystemRedirection();

				if (IsFile(tmp) == false || (CEDAR_VERSION_BUILD > current_ver) || MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
				{
					b = FileCopy(VPNCMD_BOOTSTRAP_FILENAME, tmp);
				}

				MsRestoreWow64FileSystemRedirection(wow);

				if (IsFile(tmp) == false || (CEDAR_VERSION_BUILD > current_ver) || MsRegIsValue(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH) == false)
				{
					b = FileCopy(VPNCMD_BOOTSTRAP_FILENAME, tmp);
				}
			}

			// Because the currently running prompt is newer version, overwrite the registry
			if (MsIs64BitWindows() == false)
			{
				MsRegWriteStr(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH, exe_path);
				MsRegWriteInt(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER, CEDAR_VERSION_BUILD);
			}
			else
			{
				MsRegWriteStrEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH, exe_path, true, false);
				MsRegWriteIntEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER, CEDAR_VERSION_BUILD, true, false);

				MsRegWriteStrEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH, exe_path, false, true);
				MsRegWriteIntEx2(REG_LOCAL_MACHINE, VPNCMD_BOOTSTRAP_REG_KEYNAME, VPNCMD_BOOTSTRAP_REG_VALUENAME_VER, CEDAR_VERSION_BUILD, false, true);
			}
		}
	}
#endif	// OS_WIN32
}

// Show the string
void TtPrint(void *param, TT_PRINT_PROC *print_proc, wchar_t *str)
{
	// Validate arguments
	if (print_proc == NULL || str == NULL)
	{
		return;
	}

	print_proc(param, str);
}

// Generate new random data
void TtGenerateRandomData(UCHAR **buf, UINT *size)
{
	UCHAR *tmp;
	UINT sz;
	UINT i;
	// Validate arguments
	if (buf == NULL || size == NULL)
	{
		return;
	}

	sz = TRAFFIC_BUF_SIZE;
	tmp = Malloc(sz);
	for (i = 0;i < sz;i++)
	{
		tmp[i] = rand() % 256;

		if (tmp[i] == '!')
		{
			tmp[i] = '_';
		}
	}

	*buf = tmp;
	*size = sz;
}

// Communication throughput measurement server worker thread
void TtsWorkerThread(THREAD *thread, void *param)
{
	TTS *tts;
	TTS_WORKER *w;
	UINT buf_size;
	UCHAR *send_buf_data, *recv_buf_data;
	bool all_sockets_blocked = false;
	UINT64 tmp64;
	LIST *o;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	bool dont_block_next_time = false;
	char *ver_str = TRAFFIC_VER_STR;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// Allocate the data area
	TtGenerateRandomData(&send_buf_data, &buf_size);
	TtGenerateRandomData(&recv_buf_data, &buf_size);

	w = (TTS_WORKER *)param;
	tts = (TTS *)w->Tts;

	// Preparation of socket events
	w->SockEvent = NewSockEvent();
	AddRef(w->SockEvent->ref);

	// Preparing the Server socket list
	w->TtsSockList = NewList(NULL);

	// Notify completion of preparation to parent thread
	NoticeThreadInit(thread);

	o = NewList(NULL);

	while (tts->Halt == false)
	{
		UINT64 now = Tick64();

		// Wait for all sockets
		if (dont_block_next_time == false)
		{
			WaitSockEvent(w->SockEvent, 50);
		}
		dont_block_next_time = false;

		// Process for sockets that are currently registered
		LockList(w->TtsSockList);
		{
			UINT i;

			all_sockets_blocked = false;

			// Continue to send and receive data
			// until all sockets become block state
			while (all_sockets_blocked == false)
			{
				all_sockets_blocked = true;

				for (i = 0;i < LIST_NUM(w->TtsSockList);i++)
				{
					UINT ret = SOCK_LATER;
					UCHAR *send_data = NULL, *recv_data = NULL;
					UINT send_size = 0, recv_size = 0;
					TTS_SOCK *ts = LIST_DATA(w->TtsSockList, i);
					bool blocked_for_this_socket = false;

					if (ts->SockJoined == false)
					{
						JoinSockToSockEvent(ts->Sock, w->SockEvent);
						ts->SockJoined = true;
					}

					switch (ts->State)
					{
					case 0:
						// Return the version string
						ret = Send(ts->Sock, ver_str, TRAFFIC_VER_STR_SIZE, false);
						if (ret != 0 && ret != SOCK_LATER)
						{
							ts->State = 5;
							ts->LastCommTime = now;
						}
						break;

					case 5:
						// Receive the direction from the client
						ret = Recv(ts->Sock, recv_buf_data, buf_size, false);
						if (ret != 0 && ret != SOCK_LATER)
						{
							UCHAR c;

							ts->LastCommTime = now;

							// Direction of the data is in the first byte that is received
							c = recv_buf_data[0];

							if (c == 0)
							{
								// In the case of 0, Client -> Server
								ts->State = 1;
							}
							else
							{
								// Otherwise Server -> Client
								ts->State = 2;
							}

							if (ret >= (sizeof(UINT64) + sizeof(UINT64) + 1))
							{
								// Session ID
								ts->SessionId = READ_UINT64(recv_buf_data + 1);

								// Span
								ts->Span = READ_UINT64(recv_buf_data + sizeof(UINT64) + 1);

								ts->GiveupSpan = ts->Span * 3ULL + 180000ULL;
							}
						}
						break;

					case 1:
						// Client -> Server
						ret = Recv(ts->Sock, recv_buf_data, buf_size, false);

						if (ret != 0 && ret != SOCK_LATER)
						{
							// Checking the first byte of received
							UCHAR c = recv_buf_data[0];

							ts->LastCommTime = now;

							if (ts->FirstRecvTick == 0)
							{
								// Record the time at which the data has been received for the first
								ts->FirstRecvTick = now;
							}
							else
							{
								// Check whether the span didn't finish yet
								if (ts->FirstRecvTick <= now)
								{
									if (ts->Span != 0)
									{
										UINT64 giveup_tick = ts->FirstRecvTick + ts->Span;

										if (now > giveup_tick)
										{
											// Span has expired
											c = '!';
										}
									}
								}
							}

							if (c == '!')
							{
								// Notice the size information from the server to the client
								ts->State = 3;
								Debug("!");
							}
						}
						break;

					case 2:
						// Server -> Client
						if (ts->NoMoreSendData == false)
						{
							ret = Send(ts->Sock, send_buf_data, buf_size, false);

							if (ret != 0 && ret != SOCK_LATER)
							{
								ts->LastCommTime = now;
							}
						}
						else
						{
							ret = Recv(ts->Sock, recv_buf_data, buf_size, false);

							if (ret != 0 && ret != SOCK_LATER)
							{
								ts->LastCommTime = now;
							}
						}

						if (ts->FirstSendTick == 0)
						{
							ts->FirstSendTick = now;
						}
						else
						{
							if (ts->FirstSendTick <= now)
							{
								if (ts->Span != 0)
								{
									UINT64 giveup_tick = ts->FirstSendTick + ts->Span * 3ULL + 180000ULL;

									if (now > giveup_tick)
									{
										ret = 0;
									}
								}
							}
						}

						break;

					case 3:
						// Notice the size information from the server to the client
						tmp64 = Endian64(ts->NumBytes);

						(void)Recv(ts->Sock, recv_buf_data, buf_size, false);

						if (ts->LastWaitTick == 0 || ts->LastWaitTick <= Tick64())
						{
							ret = Send(ts->Sock, &tmp64, sizeof(tmp64), false);

							if (ret != 0 && ret != SOCK_LATER)
							{
								ts->LastCommTime = now;
							}

							if (ret != SOCK_LATER)
							{
								UINT j;

								ts->LastWaitTick = Tick64() + 100;

								if (ts->SessionId != 0)
								{
									// Not to send more data to the socket of the
									// transmission direction in the same session ID
									for (j = 0;j < LIST_NUM(w->TtsSockList);j++)
									{
										TTS_SOCK *ts2 = LIST_DATA(w->TtsSockList, j);

										if (ts2->SessionId == ts->SessionId &&
											ts2 != ts)
										{
											ts2->NoMoreSendData = true;
										}
									}
								}
							}
						}
						break;
					}

					if (now > (ts->LastCommTime + ts->GiveupSpan))
					{
						// Timeout: disconnect orphan sessions
						ret = 0;
					}

					if (ret == 0)
					{
						// Mark as deleting the socket because it is disconnected
						Insert(o, ts);
					}
					else if (ret == SOCK_LATER)
					{
						// Delay has occurred
						blocked_for_this_socket = true;
						dont_block_next_time = false;
					}
					else
					{
						if (ts->State == 1)
						{
							ts->NumBytes += (UINT64)ret;
						}
					}

					if (blocked_for_this_socket == false)
					{
						all_sockets_blocked = false;
					}
				}

				if (LIST_NUM(o) != 0)
				{
					UINT i;
					// One or more sockets is disconnected
					for (i = 0;i < LIST_NUM(o);i++)
					{
						TTS_SOCK *ts = LIST_DATA(o, i);

						UniFormat(tmp, sizeof(tmp), _UU("TTS_DISCONNECTED"), ts->Id, ts->Sock->RemoteHostname);
						TtPrint(tts->Param, tts->Print, tmp);

						Disconnect(ts->Sock);
						ReleaseSock(ts->Sock);

						Delete(w->TtsSockList, ts);

						Free(ts);
					}

					DeleteAll(o);
				}

				if (w->NewSocketArrived || tts->Halt)
				{
					w->NewSocketArrived = false;
					all_sockets_blocked = true;
					dont_block_next_time = true;
				}
			}
		}
		UnlockList(w->TtsSockList);
	}

	LockList(w->TtsSockList);
	{
		// Release the sockets of all remaining
		for (i = 0;i < LIST_NUM(w->TtsSockList);i++)
		{
			TTS_SOCK *ts = LIST_DATA(w->TtsSockList, i);

			UniFormat(tmp, sizeof(tmp), _UU("TTS_DISCONNECT"), ts->Id, ts->Sock->RemoteHostname);
			TtPrint(tts->Param, tts->Print, tmp);

			Disconnect(ts->Sock);
			ReleaseSock(ts->Sock);

			Free(ts);
		}
	}
	UnlockList(w->TtsSockList);

	// Cleanup
	ReleaseList(o);
	ReleaseList(w->TtsSockList);
	ReleaseSockEvent(w->SockEvent);
	Free(send_buf_data);
	Free(recv_buf_data);
}

// Accept thread for IPv6
void TtsIPv6AcceptThread(THREAD *thread, void *param)
{
	TTS *tts = (TTS *)param;
	// Validate arguments
	if (tts == NULL || param == NULL)
	{
		return;
	}

	TtsAcceptProc(tts, tts->ListenSocketV6);
}

// Accept procedure
void TtsAcceptProc(TTS *tts, SOCK *listen_socket)
{
	wchar_t tmp[MAX_SIZE];
	UINT seed = 0;
	// Validate arguments
	if (tts == NULL || listen_socket == NULL)
	{
		return;
	}

	while (tts->Halt == false)
	{
		SOCK *s;
		// Accept
		s = Accept(listen_socket);

		if (s == NULL)
		{
			if (tts->Halt == false)
			{
				SleepThread(10);
			}
			continue;
		}
		else
		{
			UINT num, i;
			TTS_WORKER *w;

			// Connected from the client
			AcceptInitEx(s, true);

			// Choose a worker thread
			num = LIST_NUM(tts->WorkerList);

			i = seed % num;

			seed++;

			w = LIST_DATA(tts->WorkerList, i);

			w->NewSocketArrived = true;
			LockList(w->TtsSockList);
			{
				TTS_SOCK *ts = ZeroMalloc(sizeof(TTS_SOCK));

				ts->Id = (++tts->IdSeed);
				ts->Sock = s;

				ts->GiveupSpan = (UINT64)(10 * 60 * 1000);
				ts->LastCommTime = Tick64();

				UniFormat(tmp, sizeof(tmp), _UU("TTS_ACCEPTED"), ts->Id,
					s->RemoteHostname, s->RemotePort);
				TtPrint(tts->Param, tts->Print, tmp);

				Insert(w->TtsSockList, ts);
				w->NewSocketArrived = true;
			}
			UnlockList(w->TtsSockList);

			SetSockEvent(w->SockEvent);
		}
	}
}

// Communication throughput measurement server wait thread
void TtsListenThread(THREAD *thread, void *param)
{
	TTS *tts;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	tts = (TTS *)param;

	tts->ListenSocket = NULL;
	tts->ListenSocket = ListenEx(tts->Port, false);
	tts->ListenSocketV6 = ListenEx6(tts->Port, false);

	if (tts->ListenSocket == NULL && tts->ListenSocketV6 == NULL)
	{
		// Failed to Listen
		UniFormat(tmp, sizeof(tmp), _UU("TT_LISTEN_FAILED"), tts->Port);
		TtPrint(tts->Param, tts->Print, tmp);

		// Notify completion of preparation to parent thread
		NoticeThreadInit(thread);

		tts->ErrorCode = ERR_INTERNAL_ERROR;
	}
	else
	{
		UINT i, num_worker_threads;

		UniFormat(tmp, sizeof(tmp), _UU("TTS_LISTEN_STARTED"), tts->Port);
		TtPrint(tts->Param, tts->Print, tmp);

		if (tts->ListenSocketV6 != NULL)
		{
			UniFormat(tmp, sizeof(tmp), _UU("TTS_LISTEN_STARTED_V6"), tts->Port);
			TtPrint(tts->Param, tts->Print, tmp);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("TTS_LISTEN_FAILED_V6"), tts->Port);
			TtPrint(tts->Param, tts->Print, tmp);
		}

		if (tts->ListenSocket != NULL)
		{
			AddRef(tts->ListenSocket->ref);
		}
		if (tts->ListenSocketV6 != NULL)
		{
			AddRef(tts->ListenSocketV6->ref);
		}

		num_worker_threads = GetNumberOfCpu();

		// Start the worker threads
		for (i = 0;i < num_worker_threads;i++)
		{
			TTS_WORKER *w = ZeroMalloc(sizeof(TTS_WORKER));

			w->Tts = tts;
			w->WorkThread = NewThread(TtsWorkerThread, w);
			WaitThreadInit(w->WorkThread);

			Add(tts->WorkerList, w);
		}

		// Notify completion of preparation to parent thread
		NoticeThreadInit(thread);

		// Prepare for IPv6 Accept thread
		tts->IPv6AcceptThread = NULL;
		if (tts->ListenSocketV6 != NULL)
		{
			tts->IPv6AcceptThread = NewThread(TtsIPv6AcceptThread, tts);
		}

		TtsAcceptProc(tts, tts->ListenSocket);

		if (tts->IPv6AcceptThread != NULL)
		{
			WaitThread(tts->IPv6AcceptThread, INFINITE);
			ReleaseThread(tts->IPv6AcceptThread);
		}

		TtPrint(tts->Param, tts->Print, _UU("TTS_LISTEN_STOP"));

		ReleaseSock(tts->ListenSocket);
		ReleaseSock(tts->ListenSocketV6);

		for (i = 0;i < LIST_NUM(tts->WorkerList);i++)
		{
			TTS_WORKER *w = LIST_DATA(tts->WorkerList, i);

			SetSockEvent(w->SockEvent);

			// Wait for stopping the worker thread
			WaitThread(w->WorkThread, INFINITE);
			ReleaseThread(w->WorkThread);
			ReleaseSockEvent(w->SockEvent);

			Free(w);
		}
	}
}

// String of the direction in which data flows
wchar_t *GetTtcTypeStr(UINT type)
{
	switch (type)
	{
	case TRAFFIC_TYPE_DOWNLOAD:
		return _UU("TTC_TYPE_DOWNLOAD");

	case TRAFFIC_TYPE_UPLOAD:
		return _UU("TTC_TYPE_UPLOAD");

	default:
		return _UU("TTC_TYPE_FULL");
	}
}

// Show a Summary
void TtcPrintSummary(TTC *ttc)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	wchar_t *tag = L"%-35s %s";
	// Validate arguments
	if (ttc == NULL)
	{
		return;
	}

	TtPrint(ttc->Param, ttc->Print, L"");
	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_BAR"));
	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_TITLE"));
	TtPrint(ttc->Param, ttc->Print, L"");

	// Destination host name
	StrToUni(tmp2, sizeof(tmp2), ttc->Host);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_HOST"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Destination TCP port number
	UniToStru(tmp2, ttc->Port);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_PORT"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Number of TCP connections to establish
	UniToStru(tmp2, ttc->NumTcp);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_NUMTCP"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Data transmission direction
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_TYPE"), GetTtcTypeStr(ttc->Type));
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Data transmission span
	UniFormat(tmp2, sizeof(tmp2), _UU("TTC_SPAN_STR"), (double)(ttc->Span) / 1000.0);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_SPAN"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Correct the data for Ethernet frame
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_ETHER"), ttc->Raw ? _UU("SEC_NO") : _UU("SEC_YES"));
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Measure the total amount of input and output throughput of relay equipment
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_DOUBLE"), ttc->Double ? _UU("SEC_YES") : _UU("SEC_NO"));
	TtPrint(ttc->Param, ttc->Print, tmp);

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_BAR"));
	TtPrint(ttc->Param, ttc->Print, L"");
}

// Stop the communication throughput measurement client
void StopTtc(TTC *ttc)
{
	// Validate arguments
	if (ttc == NULL)
	{
		return;
	}

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_STOPPING"));

	ttc->Halt = true;
}

// Generate a result
void TtcGenerateResult(TTC *ttc)
{
	TT_RESULT *res;
	UINT i;
	// Validate arguments
	if (ttc == NULL)
	{
		return;
	}

	res = &ttc->Result;

	Zero(res, sizeof(TT_RESULT));

	res->Raw = ttc->Raw;
	res->Double = ttc->Double;
	res->Span = ttc->RealSpan;

	for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
	{
		TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);

		if (ts->Download == false)
		{
			// Upload
			res->NumBytesUpload += ts->NumBytes;
		}
		else
		{
			// Download
			res->NumBytesDownload += ts->NumBytes;
		}
	}

	if (res->Raw == false)
	{
		// Correct to match the Ethernet
		res->NumBytesDownload = (UINT64)((double)res->NumBytesDownload * 1514.0 / 1460.0);
		res->NumBytesUpload = (UINT64)((double)res->NumBytesUpload * 1514.0 / 1460.0);
	}

	res->NumBytesTotal = res->NumBytesDownload + res->NumBytesUpload;

	// Measure the throughput
	if (res->Span != 0)
	{
		res->BpsUpload = (UINT64)((double)res->NumBytesUpload * 8.0 / ((double)res->Span / 1000.0));
		res->BpsDownload = (UINT64)((double)res->NumBytesDownload * 8.0 / ((double)res->Span / 1000.0));
	}

	if (res->Double)
	{
		res->BpsUpload *= 2ULL;
		res->BpsDownload *= 2ULL;
	}

	res->BpsTotal = res->BpsUpload + res->BpsDownload;
}

// Client worker thread
void TtcWorkerThread(THREAD *thread, void *param)
{
	TTC_WORKER *w;
	TTC *ttc;
	bool dont_block_next_time = false;
	bool halting = false;
	UINT64 halt_timeout = 0;
	bool all_sockets_blocked;
	wchar_t tmp[MAX_SIZE];
	UCHAR *send_buf_data, *recv_buf_data;
	UINT buf_size;
	UINT64 tmp64;

	if (thread == NULL || param == NULL)
	{
		return;
	}

	w = (TTC_WORKER *)param;
	ttc = w->Ttc;

	// Allocate the data area
	TtGenerateRandomData(&send_buf_data, &buf_size);
	TtGenerateRandomData(&recv_buf_data, &buf_size);

	NoticeThreadInit(thread);

	// Wait for start
	Wait(w->StartEvent, INFINITE);

	// Main loop
	while (true)
	{
		UINT i;

		if (dont_block_next_time == false)
		{
			WaitSockEvent(w->SockEvent, 50);
		}

		dont_block_next_time = false;

		if (ttc->AbnormalTerminated)
		{
			// Abnormal termination occured
			break;
		}

		if (ttc->Halt || ttc->end_tick <= Tick64() || (ttc->Cancel != NULL && (*ttc->Cancel)))
		{
			// End measurement
			if (halting == false)
			{
				if (ttc->Halt || (ttc->Cancel != NULL && (*ttc->Cancel)))
				{
					if ((ttc->flag1++) == 0)
					{
						// User cancel
						TtPrint(ttc->Param, ttc->Print, _UU("TTC_COMM_USER_CANCEL"));
					}
				}
				else
				{
					// Time elapsed
					if ((ttc->flag2++) == 0)
					{
						UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_END"),
							(double)ttc->Span / 1000.0);
						TtPrint(ttc->Param, ttc->Print, tmp);
					}
				}

				if (ttc->RealSpan == 0)
				{
					ttc->RealSpan = Tick64() - ttc->start_tick;
				}

				halting = true;

				// Wait for reporting data from the server
				halt_timeout = Tick64() + 60000ULL;
			}
		}

		if (halt_timeout != 0)
		{
			bool ok = true;

			// Wait that all TCP connections to finish processing
			for (i = 0;i < LIST_NUM(w->SockList);i++)
			{
				TTC_SOCK *ts = LIST_DATA(w->SockList, i);

				if (ts->Download == false)
				{
					if (ts->ServerUploadReportReceived == false)
					{
						ok = false;
					}
				}
			}

			if (ok)
			{
				// Measurement completed
				w->Ok = true;
				break;
			}
			else
			{
				if (halt_timeout <= Tick64())
				{
					// An error occured
					ttc->AbnormalTerminated = true;
					ttc->ErrorCode = ERR_PROTOCOL_ERROR;
					break;
				}
			}
		}

		all_sockets_blocked = false;

		// Continue to send and receive data
		// until all sockets become block state
		while (all_sockets_blocked == false)
		{
			all_sockets_blocked = true;

			for (i = 0;i < LIST_NUM(w->SockList);i++)
			{
				UINT ret = SOCK_LATER;
				TTC_SOCK *ts = LIST_DATA(w->SockList, i);
				bool blocked_for_this_socket = false;
				UCHAR c = 0;
				UCHAR c_and_session_id[1 + sizeof(UINT64) + sizeof(UINT64)];

				if (halt_timeout != 0)
				{
					if (ts->State != 3 && ts->State != 4)
					{
						if (ts->Download == false)
						{
							if (ts->State != 0)
							{
								ts->State = 3;
							}
							else
							{
								ts->ServerUploadReportReceived = true;
								ts->State = 4;
							}
						}
						else
						{
							ts->State = 4;
						}
					}
				}

				switch (ts->State)
				{
				case 0:
					// Initial state: Specify the direction of
					// the data flow between client-server
					if (ts->Download)
					{
						c = 1;
					}
					else
					{
						c = 0;
					}

					c_and_session_id[0] = c;
					WRITE_UINT64(c_and_session_id + 1, ttc->session_id);
					WRITE_UINT64(c_and_session_id + sizeof(UINT64) + 1, ttc->Span);

					ret = Send(ts->Sock, c_and_session_id, 1 + sizeof(UINT64) + sizeof(UINT64), false);

					if (ret != 0 && ret != SOCK_LATER)
					{
						if (ts->Download)
						{
							ts->State = 1;
						}
						else
						{
							ts->State = 2;
						}
					}
					break;

				case 1:
					// Server -> Client (download)
					ret = Recv(ts->Sock, recv_buf_data, buf_size, false);
					break;

				case 2:
					// Client -> Server (upload)
					ret = Send(ts->Sock, send_buf_data, buf_size, false);
					break;

				case 3:
					// Transmission completion client -> server (upload)
					// Request the data size
					if (ts->NextSendRequestReportTick == 0 ||
						(Tick64() >= ts->NextSendRequestReportTick))
					{
						UCHAR suprise[MAX_SIZE];
						UINT i;

						ts->NextSendRequestReportTick = Tick64() + 200ULL;

						for (i = 0;i < sizeof(suprise);i++)
						{
							suprise[i] = '!';
						}

						(void)Send(ts->Sock, suprise, sizeof(suprise), false);
					}

					ret = Recv(ts->Sock, &tmp64, sizeof(tmp64), false);
					if (ret != 0 && ret != SOCK_LATER && ret == sizeof(tmp64))
					{
						ts->NumBytes = Endian64(tmp64);

						ts->ServerUploadReportReceived = true;

						ts->State = 4;
					}
					break;

				case 4:
					// Do Nothing
					if (Recv(ts->Sock, recv_buf_data, buf_size, false) == SOCK_LATER)
					{
						ret = SOCK_LATER;
					}
					break;
				}

				if (ret == 0)
				{
					// The socket is disconnected
					ttc->AbnormalTerminated = true;
					ttc->ErrorCode = ERR_PROTOCOL_ERROR;
					blocked_for_this_socket = true;
					dont_block_next_time = false;

					if (ts->HideErrMsg == false)
					{
						UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_DISCONNECTED"), ts->Id);
						TtPrint(ttc->Param, ttc->Print, tmp);
						ts->HideErrMsg = true;
					}
				}
				else if (ret == SOCK_LATER)
				{
					// Delay has occurred
					blocked_for_this_socket = true;
					dont_block_next_time = false;
				}
				else
				{
					if (ts->Download)
					{
						ts->NumBytes += (UINT64)ret;
					}
				}

				if (blocked_for_this_socket == false)
				{
					all_sockets_blocked = false;
				}
			}

			if (ttc->Halt || (ttc->Cancel != NULL && (*ttc->Cancel)))
			{
				all_sockets_blocked = true;
				dont_block_next_time = true;
			}

			if (ttc->end_tick <= Tick64())
			{
				all_sockets_blocked = true;
				dont_block_next_time = true;
			}
		}
	}

	Free(send_buf_data);
	Free(recv_buf_data);
}

// Client thread
void TtcThread(THREAD *thread, void *param)
{
	TTC *ttc;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	bool ok = false;
	IP ip_ret;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	ttc = (TTC *)param;

	// Ready
	NoticeThreadInit(thread);

	TtcPrintSummary(ttc);

	UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_START"),
		ttc->Host, ttc->Port, ttc->NumTcp);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Establish all connections to the client
	ttc->ItcSockList = NewList(NULL);

	ok = true;

	Zero(&ip_ret, sizeof(ip_ret));

	for (i = 0;i < ttc->NumTcp;i++)
	{
		SOCK *s;
		TTC_SOCK *ts = ZeroMalloc(sizeof(TTC_SOCK));
		char target_host[MAX_SIZE];

		ts->Id = i + 1;

		if (ttc->Type == TRAFFIC_TYPE_DOWNLOAD)
		{
			ts->Download = true;
		}
		else if (ttc->Type == TRAFFIC_TYPE_UPLOAD)
		{
			ts->Download = false;
		}
		else
		{
			ts->Download = ((i % 2) == 0) ? true : false;
		}

		StrCpy(target_host, sizeof(target_host), ttc->Host);

		if (IsZeroIp(&ip_ret) == false)
		{
			IPToStr(target_host, sizeof(target_host), &ip_ret);
		}

		s = ConnectEx4(target_host, ttc->Port, 0, ttc->Cancel, NULL, NULL, false, true, &ip_ret);

		if (s == NULL)
		{
			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_FAILED"), i + 1);
			TtPrint(ttc->Param, ttc->Print, tmp);
			ok = false;
			Free(ts);
			break;
		}
		else
		{
			char buffer[TRAFFIC_VER_STR_SIZE];

			SetTimeout(s, 5000);

			Zero(buffer, sizeof(buffer));
			if (Recv(s, buffer, sizeof(buffer), false) != sizeof(buffer) || Cmp(buffer, TRAFFIC_VER_STR, TRAFFIC_VER_STR_SIZE) != 0)
			{
				TtPrint(ttc->Param, ttc->Print, _UU("TTC_CONNECT_NOT_SERVER"));
				ok = false;
				ReleaseSock(s);
				Free(ts);
				break;
			}

			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_OK"), i + 1);
			TtPrint(ttc->Param, ttc->Print, tmp);

			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_OK_2"), GetTtcTypeStr(ts->Download ? TRAFFIC_TYPE_DOWNLOAD : TRAFFIC_TYPE_UPLOAD));
			TtPrint(ttc->Param, ttc->Print, tmp);

			ts->Sock = s;

			SetTimeout(s, TIMEOUT_INFINITE);
		}

		Insert(ttc->ItcSockList, ts);
	}

	Set(ttc->InitedEvent);

	if (ttc->StartEvent != NULL)
	{
		Wait(ttc->StartEvent, INFINITE);
		SleepThread(500);
	}

	if (ok)
	{
		UINT64 start_tick, end_tick;
		wchar_t tmp1[MAX_SIZE], tmp2[MAX_SIZE];
		UINT64 session_id = Rand64();
		UINT i, num_cpu;
		bool all_ok = false;

		ttc->session_id = session_id;

		num_cpu = GetNumberOfCpu();

		ttc->WorkerThreadList = NewList(NULL);

		for (i = 0;i < num_cpu;i++)
		{
			TTC_WORKER *w = ZeroMalloc(sizeof(TTC_WORKER));

			w->Ttc = ttc;
			w->SockList = NewList(NULL);
			w->StartEvent = NewEvent();
			w->SockEvent = NewSockEvent();

			w->WorkerThread = NewThread(TtcWorkerThread, w);

			WaitThreadInit(w->WorkerThread);

			Add(ttc->WorkerThreadList, w);
		}

		// Assign each of sockets to each of worker threads
		for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
		{
			TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);
			UINT num = LIST_NUM(ttc->WorkerThreadList);
			UINT j = i % num;
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, j);

			Add(w->SockList, ts);

			JoinSockToSockEvent(ts->Sock, w->SockEvent);
		}

		// Record the current time
		start_tick = Tick64();
		end_tick = start_tick + ttc->Span;

		ttc->start_tick = start_tick;
		ttc->end_tick = end_tick;

		// Set the start event for all worker threads
		for (i = 0;i < LIST_NUM(ttc->WorkerThreadList);i++)
		{
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, i);

			Set(w->StartEvent);
		}

		// Show start message
		GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(TickToTime(start_tick)), NULL);
		GetDateTimeStrEx64(tmp2, sizeof(tmp2), SystemToLocal64(TickToTime(end_tick)), NULL);
		UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_START"), tmp1, tmp2);
		TtPrint(ttc->Param, ttc->Print, tmp);

		// Wait for all worker threads finish
		all_ok = true;
		for (i = 0;i < LIST_NUM(ttc->WorkerThreadList);i++)
		{
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, i);

			WaitThread(w->WorkerThread, INFINITE);

			if (w->Ok == false)
			{
				all_ok = false;
			}
		}

		if (all_ok)
		{
			// Measurement completed
			// Show the result
			TtcGenerateResult(ttc);
		}

		// Release worker threads
		for (i = 0;i < LIST_NUM(ttc->WorkerThreadList);i++)
		{
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, i);

			ReleaseThread(w->WorkerThread);

			ReleaseEvent(w->StartEvent);
			ReleaseList(w->SockList);

			ReleaseSockEvent(w->SockEvent);

			Free(w);
		}

		ReleaseList(ttc->WorkerThreadList);
		ttc->WorkerThreadList = NULL;
	}
	else
	{
		// Abort
		TtPrint(ttc->Param, ttc->Print, _UU("TTC_ERROR_ABORTED"));
		ttc->ErrorCode = ERR_CONNECT_FAILED;
	}

	// Cleanup
	for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
	{
		TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);

		Disconnect(ts->Sock);
		ReleaseSock(ts->Sock);
		Free(ts);
	}

	ReleaseList(ttc->ItcSockList);
}

// Start the communication throughput measurement client
TTC *NewTtc(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param)
{
	return NewTtcEx(host, port, numtcp, type, span, dbl, raw, print_proc, param, NULL, NULL);
}
TTC *NewTtcEx(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param, EVENT *start_event, bool *cancel)
{
	TTC *ttc;

	ttc = ZeroMalloc(sizeof(TTC));
	ttc->InitedEvent = NewEvent();
	ttc->Port = port;
	StrCpy(ttc->Host, sizeof(ttc->Host), host);
	ttc->NumTcp = numtcp;
	ttc->Type = type;
	ttc->Span = span;
	ttc->Double = dbl;
	ttc->Raw = raw;
	ttc->StartEvent = start_event;
	ttc->Cancel = cancel;

	if (ttc->Type == TRAFFIC_TYPE_FULL && ttc->NumTcp < 2)
	{
		ttc->NumTcp = 2;
	}

	ttc->Print = print_proc;
	ttc->Param = param;
	ttc->ErrorCode = ERR_NO_ERROR;

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_INIT"));

	ttc->Thread = NewThread(TtcThread, ttc);
	WaitThreadInit(ttc->Thread);

	return ttc;
}

// Wait for stopping the communication throughput measurement client
UINT FreeTtc(TTC *ttc, TT_RESULT *result)
{
	UINT ret;
	// Validate arguments
	if (ttc == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	WaitThread(ttc->Thread, INFINITE);
	ReleaseThread(ttc->Thread);

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_FREE"));

	ret = ttc->ErrorCode;

	if (ret == ERR_NO_ERROR)
	{
		if (result != NULL)
		{
			Copy(result, &ttc->Result, sizeof(TT_RESULT));
		}
	}

	ReleaseEvent(ttc->InitedEvent);

	Free(ttc);

	return ret;
}

// Start the communication throughput measurement server
TTS *NewTts(UINT port, void *param, TT_PRINT_PROC *print_proc)
{
	TTS *tts;
	THREAD *t;

	tts = ZeroMalloc(sizeof(TTS));
	tts->Port = port;
	tts->Param = param;
	tts->Print = print_proc;

	TtPrint(param, print_proc, _UU("TTS_INIT"));

	tts->WorkerList = NewList(NULL);

	// Creating a thread
	t = NewThread(TtsListenThread, tts);
	WaitThreadInit(t);

	tts->Thread = t;

	return tts;
}

// Wait for stopping the communication throughput measurement server
UINT FreeTts(TTS *tts)
{
	UINT ret;
	// Validate arguments
	if (tts == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	TtPrint(tts->Param, tts->Print, _UU("TTS_STOP_INIT"));

	tts->Halt = true;
	Disconnect(tts->ListenSocket);
	ReleaseSock(tts->ListenSocket);
	Disconnect(tts->ListenSocketV6);
	ReleaseSock(tts->ListenSocketV6);

	// Wait for the termination of the thread
	WaitThread(tts->Thread, INFINITE);

	ReleaseThread(tts->Thread);

	TtPrint(tts->Param, tts->Print, _UU("TTS_STOP_FINISHED"));

	ret = tts->ErrorCode;

	ReleaseList(tts->WorkerList);

	Free(tts);

	return ret;
}

// Show the measurement tools prompt
void PtTrafficPrintProc(void *param, wchar_t *str)
{
	CONSOLE *c;
	// Validate arguments
	if (param == NULL || str == NULL)
	{
		return;
	}

	c = (CONSOLE *)param;

	if (c->ConsoleType == CONSOLE_LOCAL)
	{
		Lock(c->OutputLock);
		{
			wchar_t tmp[MAX_SIZE];

			// Display only if the local console
			// (Can not be displayed because threads aren't synchronized otherwise?)
			UniStrCpy(tmp, sizeof(tmp), str);
			if (UniEndWith(str, L"\n") == false)
			{
				UniStrCat(tmp, sizeof(tmp), L"\n");
			}
			UniPrint(L"%s", tmp);
		}
		Unlock(c->OutputLock);
	}
}

// Display the communication throughput results
void TtcPrintResult(CONSOLE *c, TT_RESULT *res)
{
	CT *ct;
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	char str[MAX_SIZE];
	// Validate arguments
	if (c == NULL || res == NULL)
	{
		return;
	}

	c->Write(c, _UU("TTC_RES_TITLE"));

	ct = CtNew();
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_2"), true);
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_3"), true);

	// Time that was used to measure
	GetSpanStrMilli(str, sizeof(str), res->Span);
	StrToUni(tmp, sizeof(tmp), str);
	CtInsert(ct, _UU("TTC_RES_SPAN"), tmp, L"");

	// Correct the data for Ethernet frame
	CtInsert(ct, _UU("TTC_RES_ETHER"), res->Raw ? _UU("SEC_NO") : _UU("SEC_YES"), L"");

	// Amount of communication data of download direction
	ToStr3(str, sizeof(str), res->NumBytesDownload);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesDownload);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_DOWNLOAD"), tmp1, tmp2);

	// Amount of communication data of upload direction
	ToStr3(str, sizeof(str), res->NumBytesUpload);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesUpload);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_UPLOAD"), tmp1, tmp2);

	// Total amount of communication data
	ToStr3(str, sizeof(str), res->NumBytesTotal);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesTotal);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_TOTAL"), tmp1, tmp2);

	// Calculate the total throughput of input and output of the relay equipment
	CtInsert(ct, _UU("TTC_RES_DOUBLE"), (res->Double == false) ? _UU("SEC_NO") : _UU("SEC_YES"), L"");

	// Average throughput of download direction
	ToStr3(str, sizeof(str), res->BpsDownload);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsDownload);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_DOWNLOAD"), tmp1, tmp2);

	// Average throughput of upload direction
	ToStr3(str, sizeof(str), res->BpsUpload);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsUpload);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_UPLOAD"), tmp1, tmp2);

	// Total average throughput
	ToStr3(str, sizeof(str), res->BpsTotal);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsTotal);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_TOTAL"), tmp1, tmp2);

	CtFree(ct, c);
}

// Execute the communication throughput measurement tool server
UINT PtTrafficServer(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	UINT port;
	bool nohup;
	TTS *tts;
	PARAM args[] =
	{
		{"[port]", NULL, NULL, NULL, NULL},
		{"NOHUP", NULL, NULL, NULL, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	port = GetParamInt(o, "[port]");
	if (port == 0)
	{
		port = TRAFFIC_DEFAULT_PORT;
	}

	nohup = GetParamYes(o, "nohup");

	tts = NewTts(port, c, PtTrafficPrintProc);

	if (nohup)
	{
		while (true)
		{
			SleepThread(10000);
		}
	}

	c->Write(c, _UU("TTS_ENTER_TO_EXIT"));

	Free(c->ReadLine(c, L"", true));

	ret = tts->ErrorCode;

	FreeTts(tts);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Execute the communication throughput measurement tool client
UINT PtTrafficClient(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	TTC *ttc;
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	char *host = NULL;
	UINT port;
	UINT num, type;
	bool dbl = false, raw = false;
	UINT64 span;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_TrafficClient_EVAL_NUMTCP",
		0, TRAFFIC_NUMTCP_MAX,
	};
	PARAM args[] =
	{
		{"[host:port]", CmdPrompt, _UU("CMD_TrafficClient_PROMPT_HOST"), CmdEvalNotEmpty, NULL},
		{"NUMTCP", NULL, NULL, CmdEvalMinMax, &minmax},
		{"TYPE", NULL, NULL, NULL, NULL},
		{"SPAN", NULL, NULL, NULL, NULL},
		{"DOUBLE", NULL, NULL, NULL, NULL},
		{"RAW", NULL, NULL, NULL, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (ParseHostPort(GetParamStr(o, "[host:port]"), &host, &port, TRAFFIC_DEFAULT_PORT) == false)
	{
		c->Write(c, _UU("CMD_TrafficClient_ERROR_HOSTPORT"));
		ret = ERR_INVALID_PARAMETER;
	}
	else
	{
		char *s;
		UINT i;

		Trim(host);

		num = GetParamInt(o, "NUMTCP");
		if (num == 0)
		{
			num = TRAFFIC_NUMTCP_DEFAULT;
		}
		s = GetParamStr(o, "TYPE");

		if (StartWith("download", s))
		{
			type = TRAFFIC_TYPE_DOWNLOAD;
		}
		else if (StartWith("upload", s))
		{
			type = TRAFFIC_TYPE_UPLOAD;
		}
		else
		{
			type = TRAFFIC_TYPE_FULL;
		}

		i = GetParamInt(o, "SPAN");

		if (i == 0)
		{
			i = TRAFFIC_SPAN_DEFAULT;
		}

		span = (UINT64)i * 1000ULL;

		dbl = GetParamYes(o, "DOUBLE");
		raw = GetParamYes(o, "RAW");

		if (type == TRAFFIC_TYPE_FULL)
		{
			if ((num % 2) != 0)
			{
				ret = ERR_INVALID_PARAMETER;
				c->Write(c, _UU("CMD_TrafficClient_ERROR_NUMTCP"));
			}
		}

		if (ret == ERR_NO_ERROR)
		{
			TT_RESULT result;
			ttc = NewTtc(host, port, num, type, span, dbl, raw, PtTrafficPrintProc, c);

			if (c->ConsoleType == CONSOLE_LOCAL)
			{
				if (c->Param != NULL && (((LOCAL_CONSOLE_PARAM *)c->Param)->InBuf == NULL))
				{
//					c->Write(c, _UU("TTC_ENTER_TO_EXIT"));
//					GetLine(NULL, 0);
//					StopTtc(ttc);
				}
			}


			Zero(&result, sizeof(result));
			ret = FreeTtc(ttc, &result);

			if (ret == ERR_NO_ERROR)
			{
				TtcPrintResult(c, &result);
			}
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	Free(host);

	return ret;
}

// Certificate easy creation tool (1024 bit)
UINT PtMakeCert(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	X *x = NULL;
	K *pub = NULL;
	K *pri = NULL;
	NAME *n;
	X_SERIAL *x_serial = NULL;
	BUF *buf;
	UINT days;
	X *root_x = NULL;
	K *root_k = NULL;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_MakeCert_EVAL_EXPIRES",
		0,
		10950,
	};
	PARAM args[] =
	{
		{"CN", CmdPrompt, _UU("CMD_MakeCert_PROMPT_CN"), NULL, NULL},
		{"O", CmdPrompt, _UU("CMD_MakeCert_PROMPT_O"), NULL, NULL},
		{"OU", CmdPrompt, _UU("CMD_MakeCert_PROMPT_OU"), NULL, NULL},
		{"C", CmdPrompt, _UU("CMD_MakeCert_PROMPT_C"), NULL, NULL},
		{"ST", CmdPrompt, _UU("CMD_MakeCert_PROMPT_ST"), NULL, NULL},
		{"L", CmdPrompt, _UU("CMD_MakeCert_PROMPT_L"), NULL, NULL},
		{"SERIAL", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SERIAL"), NULL, NULL},
		{"EXPIRES", CmdPrompt, _UU("CMD_MakeCert_PROMPT_EXPIRES"), CmdEvalMinMax, &minmax},
		{"SIGNCERT", NULL, NULL, CmdEvalIsFile, NULL},
		{"SIGNKEY", NULL, NULL, CmdEvalIsFile, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
		{"SAVEKEY", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVEKEY"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsEmptyStr(GetParamStr(o, "SIGNCERT")) == false && IsEmptyStr(GetParamStr(o, "SIGNKEY")) == false)
	{
		root_x = FileToXW(GetParamUniStr(o, "SIGNCERT"));
		root_k = FileToKW(GetParamUniStr(o, "SIGNKEY"), true, NULL);

		if (root_x == NULL || root_k == NULL || CheckXandK(root_x, root_k) == false)
		{
			ret = ERR_INTERNAL_ERROR;

			c->Write(c, _UU("CMD_MakeCert_ERROR_SIGNKEY"));
		}
	}

	if (ret == ERR_NO_ERROR)
	{
		buf = StrToBin(GetParamStr(o, "SERIAL"));
		if (buf != NULL && buf->Size >= 1)
		{
			x_serial = NewXSerial(buf->Buf, buf->Size);
		}
		FreeBuf(buf);

		n = NewName(GetParamUniStr(o, "CN"), GetParamUniStr(o, "O"), GetParamUniStr(o, "OU"), 
			GetParamUniStr(o, "C"), GetParamUniStr(o, "ST"), GetParamUniStr(o, "L"));

		days = GetParamInt(o, "EXPIRES");
		if (days == 0)
		{
			days = 3650;
		}

		RsaGen(&pri, &pub, 1024);

		if (root_x == NULL)
		{
			x = NewRootX(pub, pri, n, days, x_serial);
		}
		else
		{
			x = NewX(pub, root_k, root_x, n, days, x_serial);
		}

		FreeXSerial(x_serial);
		FreeName(n);

		if (x == NULL)
		{
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MakeCert_ERROR_GEN_FAILED"));
		}
		else
		{
			if (XToFileW(x, GetParamUniStr(o, "SAVECERT"), true) == false)
			{
				c->Write(c, _UU("CMD_SAVECERT_FAILED"));
			}
			else if (KToFileW(pri, GetParamUniStr(o, "SAVEKEY"), true, NULL) == false)
			{
				c->Write(c, _UU("CMD_SAVEKEY_FAILED"));
			}
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	FreeX(root_x);
	FreeK(root_k);

	FreeX(x);
	FreeK(pri);
	FreeK(pub);

	return ret;
}

// Certificate easy creation tool (2048 bit)
UINT PtMakeCert2048(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	X *x = NULL;
	K *pub = NULL;
	K *pri = NULL;
	NAME *n;
	X_SERIAL *x_serial = NULL;
	BUF *buf;
	UINT days;
	X *root_x = NULL;
	K *root_k = NULL;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_MakeCert_EVAL_EXPIRES",
		0,
		10950,
	};
	PARAM args[] =
	{
		{"CN", CmdPrompt, _UU("CMD_MakeCert_PROMPT_CN"), NULL, NULL},
		{"O", CmdPrompt, _UU("CMD_MakeCert_PROMPT_O"), NULL, NULL},
		{"OU", CmdPrompt, _UU("CMD_MakeCert_PROMPT_OU"), NULL, NULL},
		{"C", CmdPrompt, _UU("CMD_MakeCert_PROMPT_C"), NULL, NULL},
		{"ST", CmdPrompt, _UU("CMD_MakeCert_PROMPT_ST"), NULL, NULL},
		{"L", CmdPrompt, _UU("CMD_MakeCert_PROMPT_L"), NULL, NULL},
		{"SERIAL", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SERIAL"), NULL, NULL},
		{"EXPIRES", CmdPrompt, _UU("CMD_MakeCert_PROMPT_EXPIRES"), CmdEvalMinMax, &minmax},
		{"SIGNCERT", NULL, NULL, CmdEvalIsFile, NULL},
		{"SIGNKEY", NULL, NULL, CmdEvalIsFile, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
		{"SAVEKEY", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVEKEY"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsEmptyStr(GetParamStr(o, "SIGNCERT")) == false && IsEmptyStr(GetParamStr(o, "SIGNKEY")) == false)
	{
		root_x = FileToXW(GetParamUniStr(o, "SIGNCERT"));
		root_k = FileToKW(GetParamUniStr(o, "SIGNKEY"), true, NULL);

		if (root_x == NULL || root_k == NULL || CheckXandK(root_x, root_k) == false)
		{
			ret = ERR_INTERNAL_ERROR;

			c->Write(c, _UU("CMD_MakeCert_ERROR_SIGNKEY"));
		}
	}

	if (ret == ERR_NO_ERROR)
	{
		buf = StrToBin(GetParamStr(o, "SERIAL"));
		if (buf != NULL && buf->Size >= 1)
		{
			x_serial = NewXSerial(buf->Buf, buf->Size);
		}
		FreeBuf(buf);

		n = NewName(GetParamUniStr(o, "CN"), GetParamUniStr(o, "O"), GetParamUniStr(o, "OU"), 
			GetParamUniStr(o, "C"), GetParamUniStr(o, "ST"), GetParamUniStr(o, "L"));

		days = GetParamInt(o, "EXPIRES");
		if (days == 0)
		{
			days = 3650;
		}

		RsaGen(&pri, &pub, 2048);

		if (root_x == NULL)
		{
			x = NewRootX(pub, pri, n, days, x_serial);
		}
		else
		{
			x = NewX(pub, root_k, root_x, n, days, x_serial);
		}

		FreeXSerial(x_serial);
		FreeName(n);

		if (x == NULL)
		{
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MakeCert_ERROR_GEN_FAILED"));
		}
		else
		{
			if (XToFileW(x, GetParamUniStr(o, "SAVECERT"), true) == false)
			{
				c->Write(c, _UU("CMD_SAVECERT_FAILED"));
			}
			else if (KToFileW(pri, GetParamUniStr(o, "SAVEKEY"), true, NULL) == false)
			{
				c->Write(c, _UU("CMD_SAVEKEY_FAILED"));
			}
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	FreeX(root_x);
	FreeK(root_k);

	FreeX(x);
	FreeK(pri);
	FreeK(pub);

	return ret;
}

// Client management tool main
void PcMain(PC *pc)
{
	char prompt[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (pc == NULL)
	{
		return;
	}

	// Display a message that the connection has been made
	UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_CLIENT_CONNECTED"),
		pc->ServerName);
	pc->Console->Write(pc->Console, tmp);
	pc->Console->Write(pc->Console, L"");

	while (true)
	{
		// Definition of command
		CMD cmd[] =
		{
			{"About", PsAbout},
			{"Check", PtCheck},
			{"VersionGet", PcVersionGet},
			{"PasswordSet", PcPasswordSet},
			{"PasswordGet", PcPasswordGet},
			{"CertList", PcCertList},
			{"CertAdd", PcCertAdd},
			{"CertDelete", PcCertDelete},
			{"CertGet", PcCertGet},
			{"SecureList", PcSecureList},
			{"SecureSelect", PcSecureSelect},
			{"SecureGet", PcSecureGet},
			{"NicCreate", PcNicCreate},
			{"NicDelete", PcNicDelete},
			{"NicUpgrade", PcNicUpgrade},
			{"NicGetSetting", PcNicGetSetting},
			{"NicSetSetting", PcNicSetSetting},
			{"NicEnable", PcNicEnable},
			{"NicDisable", PcNicDisable},
			{"NicList", PcNicList},
			{"AccountList", PcAccountList},
			{"AccountCreate", PcAccountCreate},
			{"AccountSet", PcAccountSet},
			{"AccountGet", PcAccountGet},
			{"AccountDelete", PcAccountDelete},
			{"AccountUsernameSet", PcAccountUsernameSet},
			{"AccountAnonymousSet", PcAccountAnonymousSet},
			{"AccountPasswordSet", PcAccountPasswordSet},
			{"AccountCertSet", PcAccountCertSet},
			{"AccountCertGet", PcAccountCertGet},
			{"AccountEncryptDisable", PcAccountEncryptDisable},
			{"AccountEncryptEnable", PcAccountEncryptEnable},
			{"AccountCompressEnable", PcAccountCompressEnable},
			{"AccountCompressDisable", PcAccountCompressDisable},
			{"AccountHttpHeaderAdd", PcAccountHttpHeaderAdd},
			{"AccountHttpHeaderDelete", PcAccountHttpHeaderDelete},
			{"AccountHttpHeaderGet", PcAccountHttpHeaderGet},
			{"AccountProxyNone", PcAccountProxyNone},
			{"AccountProxyHttp", PcAccountProxyHttp},
			{"AccountProxySocks", PcAccountProxySocks},
			{"AccountProxySocks5", PcAccountProxySocks5},
			{"AccountServerCertEnable", PcAccountServerCertEnable},
			{"AccountServerCertDisable", PcAccountServerCertDisable},
			{"AccountRetryOnServerCertEnable", PcAccountRetryOnServerCertEnable},
			{"AccountRetryOnServerCertDisable", PcAccountRetryOnServerCertDisable},
			{"AccountServerCertSet", PcAccountServerCertSet},
			{"AccountServerCertDelete", PcAccountServerCertDelete},
			{"AccountServerCertGet", PcAccountServerCertGet},
			{"AccountDetailSet", PcAccountDetailSet},
			{"AccountRename", PcAccountRename},
			{"AccountConnect", PcAccountConnect},
			{"AccountDisconnect", PcAccountDisconnect},
			{"AccountStatusGet", PcAccountStatusGet},
			{"AccountNicSet", PcAccountNicSet},
			{"AccountStatusShow", PcAccountStatusShow},
			{"AccountStatusHide", PcAccountStatusHide},
			{"AccountSecureCertSet", PcAccountSecureCertSet},
			{"AccountRetrySet", PcAccountRetrySet},
			{"AccountStartupSet", PcAccountStartupSet},
			{"AccountStartupRemove", PcAccountStartupRemove},
			{"AccountExport", PcAccountExport},
			{"AccountImport", PcAccountImport},
			{"RemoteEnable", PcRemoteEnable},
			{"RemoteDisable", PcRemoteDisable},
			{"KeepEnable", PcKeepEnable},
			{"KeepDisable", PcKeepDisable},
			{"KeepSet", PcKeepSet},
			{"KeepGet", PcKeepGet},
			{"MakeCert", PtMakeCert},
			{"MakeCert2048", PtMakeCert2048},
			{"TrafficClient", PtTrafficClient},
			{"TrafficServer", PtTrafficServer},
		};

		// Generate a prompt
		StrCpy(prompt, sizeof(prompt), "VPN Client>");

		if (DispatchNextCmdEx(pc->Console, pc->CmdLine, prompt, cmd, sizeof(cmd) / sizeof(cmd[0]), pc) == false)
		{
			break;
		}
		pc->LastError = pc->Console->RetCode;

		if (pc->LastError == ERR_NO_ERROR && pc->Console->ConsoleType != CONSOLE_CSV)
		{
			pc->Console->Write(pc->Console, _UU("CMD_MSG_OK"));
			pc->Console->Write(pc->Console, L"");
		}

		if (pc->CmdLine != NULL)
		{
			break;
		}
	}
}

// Retrieve the version information of VPN Client service
UINT PcVersionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_VERSION t;

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcGetClientVersion(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct;

		// Success
		ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), t.ClientProductName);
		CtInsert(ct, _UU("CMD_VersionGet_1"), tmp);

		StrToUni(tmp, sizeof(tmp), t.ClientVersionString);
		CtInsert(ct, _UU("CMD_VersionGet_2"), tmp);

		StrToUni(tmp, sizeof(tmp), t.ClientBuildInfoString);
		CtInsert(ct, _UU("CMD_VersionGet_3"), tmp);

		UniToStru(tmp, t.ProcessId);
		CtInsert(ct, _UU("CMD_VersionGet_4"), tmp);

		StrToUni(tmp, sizeof(tmp), OsTypeToStr(t.OsType));
		CtInsert(ct, _UU("CMD_VersionGet_5"), tmp);

		CtFree(ct, c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set a password to connect to the VPN Client Service
UINT PcPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_PASSWORD t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[password]", CmdPromptChoosePassword, NULL, NULL, NULL},
		{"REMOTEONLY", NULL, NULL, NULL, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.Password, sizeof(t.Password), GetParamStr(o, "[password]"));
	t.PasswordRemoteOnly = GetParamYes(o, "REMOTEONLY");

	ret = CcSetPassword(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get the settings of the password to connect to the VPN Client service
UINT PcPasswordGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_PASSWORD_SETTING t;

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcGetPasswordSetting(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_PasswordGet_1"),
			t.IsPasswordPresented ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtInsert(ct, _UU("CMD_PasswordGet_2"),
			t.PasswordRemoteOnly ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtFree(ct, c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get the list of certificates of the trusted certification authority
UINT PcCertList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_ENUM_CA t;

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcEnumCa(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
		UINT i;
		CT *ct = CtNewStandard();

		for (i = 0;i < t.NumItem;i++)
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[64];
			RPC_CLIENT_ENUM_CA_ITEM *e = t.Items[i];

			GetDateStrEx64(tmp, sizeof(tmp), SystemToLocal64(e->Expires), NULL);

			UniToStru(tmp2, e->Key);

			CtInsert(ct, _UU("CMD_CAList_COLUMN_ID"), tmp2);
			CtInsert(ct, _UU("CM_CERT_COLUMN_1"), e->SubjectName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_2"), e->IssuerName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_3"), tmp);

			if (i != (t.NumItem - 1))
			{
				CtInsert(ct, L"---", L"---");
			}
		}

		CtFree(ct, c);

		CiFreeClientEnumCa(&t);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}


	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Add a certificate of the trusted certification authority
UINT PcCertAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CERT t;
	X *x;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[path]", CmdPrompt, _UU("CMD_CAAdd_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}


	x = FileToXW(GetParamUniStr(o, "[path]"));

	if (x == NULL)
	{
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_MSG_LOAD_CERT_FAILED"));
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	t.x = x;

	ret = CcAddCa(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	FreeX(x);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Delete the certificate of the trusted certification authority
UINT PcCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_DELETE_CA t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_CADelete_PROMPT_ID"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	t.Key = GetParamInt(o, "[id]");

	ret = CcDeleteCa(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get the certificate of the trusted certification authority
UINT PcCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_GET_CA t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_CAGet_PROMPT_ID"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_CAGet_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	t.Key = GetParamInt(o, "[id]");

	ret = CcGetCa(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
		if (XToFileW(t.x, GetParamUniStr(o, "SAVECERT"), true))
		{
			// Success
		}
		else
		{
			// Failure
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MSG_SAVE_CERT_FAILED"));
		}

		CiFreeGetCa(&t);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get the list of the type of smart card that can be used
UINT PcSecureList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_ENUM_SECURE t;

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcEnumSecure(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		CT *ct;
		UINT i;
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];
		wchar_t *tmp3;

		// Success
		ct = CtNew();
		CtInsertColumn(ct, _UU("SEC_COLUMN1"), false);
		CtInsertColumn(ct, _UU("SEC_COLUMN2"), false);
		CtInsertColumn(ct, _UU("SEC_COLUMN3"), false);
		CtInsertColumn(ct, _UU("SEC_COLUMN4"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_CLIENT_ENUM_SECURE_ITEM *e = t.Items[i];

			// ID
			UniToStru(tmp1, e->DeviceId);

			// Device name
			StrToUni(tmp2, sizeof(tmp2), e->DeviceName);

			// Type
			tmp3 = (e->Type == SECURE_IC_CARD) ? _UU("SEC_SMART_CARD") : _UU("SEC_USB_TOKEN");

			// Manufacturer
			StrToUni(tmp4, sizeof(tmp4), e->Manufacturer);

			CtInsert(ct, tmp1, tmp2, tmp3, tmp4);
		}

		CtFreeEx(ct, c, true);

		CiFreeClientEnumSecure(&t);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Select the type of smart card to be used
UINT PcSecureSelect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_USE_SECURE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_SecureSelect_PROMPT_ID"), NULL, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	t.DeviceId = GetParamInt(o, "[id]");

	ret = CcUseSecure(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get the type ID of smart card to be used
UINT PcSecureGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_USE_SECURE t;

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcGetUseSecure(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
		wchar_t tmp[MAX_SIZE];

		if (t.DeviceId != 0)
		{
			UniFormat(tmp, sizeof(tmp), _UU("CMD_SecureGet_Print"), t.DeviceId);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_SecureGet_NoPrint"));
		}
		c->Write(c, tmp);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Create a new virtual LAN card
UINT PcNicCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_VLAN t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcCreateVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Delete the virtual LAN card
UINT PcNicDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_VLAN t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcDeleteVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Upgrading the device driver of the virtual LAN card
UINT PcNicUpgrade(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_VLAN t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcUpgradeVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get the settings of the virtual LAN card
UINT PcNicGetSetting(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_VLAN t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcGetVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
		CT *ct = CtNewStandard();
		wchar_t tmp[MAX_SIZE];

		StrToUni(tmp, sizeof(tmp), t.DeviceName);
		CtInsert(ct, _UU("CMD_NicGetSetting_1"), tmp);

		CtInsert(ct, _UU("CMD_NicGetSetting_2"), t.Enabled ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		StrToUni(tmp, sizeof(tmp), t.MacAddress);
		CtInsert(ct, _UU("CMD_NicGetSetting_3"), tmp);

		StrToUni(tmp, sizeof(tmp), t.Version);
		CtInsert(ct, _UU("CMD_NicGetSetting_4"), tmp);

		StrToUni(tmp, sizeof(tmp), t.FileName);
		CtInsert(ct, _UU("CMD_NicGetSetting_5"), tmp);

		StrToUni(tmp, sizeof(tmp), t.Guid);
		CtInsert(ct, _UU("CMD_NicGetSetting_6"), tmp);

		CtFree(ct, c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Change the settings for the virtual LAN card
UINT PcNicSetSetting(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_SET_VLAN t;
	UCHAR mac_address[6];
	BUF *b;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"MAC", CmdPrompt, _UU("CMD_NicSetSetting_PROMPT_MAC"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Inspect the MAC address
	Zero(mac_address, sizeof(mac_address));
	b = StrToBin(GetParamStr(o, "MAC"));
	if (b != NULL && b->Size == 6)
	{
		Copy(mac_address, b->Buf, 6);
	}
	FreeBuf(b);

	if (IsZero(mac_address, 6))
	{
		// MAC address is invalid
		FreeParamValueList(o);

		CmdPrintError(c, ERR_INVALID_PARAMETER);
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));
	NormalizeMacAddress(t.MacAddress, sizeof(t.MacAddress), GetParamStr(o, "MAC"));

	ret = CcSetVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Enable the virtual LAN card
UINT PcNicEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_VLAN t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcEnableVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Disable the virtual LAN card
UINT PcNicDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_VLAN t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_NicCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "[name]"));

	ret = CcDisableVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get the Virtual LAN card list
UINT PcNicList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_ENUM_VLAN t;

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcEnumVLan(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		CT *ct;
		UINT i;

		// Success
		ct = CtNew();
		CtInsertColumn(ct, _UU("CM_VLAN_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("CM_VLAN_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("CM_VLAN_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("CM_VLAN_COLUMN_4"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			wchar_t name[MAX_SIZE];
			wchar_t mac[MAX_SIZE];
			wchar_t ver[MAX_SIZE];
			wchar_t *status;
			RPC_CLIENT_ENUM_VLAN_ITEM *v = t.Items[i];

			// Device name
			StrToUni(name, sizeof(name), v->DeviceName);

			// State
			status = v->Enabled ? _UU("CM_VLAN_ENABLED") : _UU("CM_VLAN_DISABLED");

			// MAC address
			StrToUni(mac, sizeof(mac), v->MacAddress);

			// Version
			StrToUni(ver, sizeof(ver), v->Version);

			CtInsert(ct,
				name, status, mac, ver);
		}

		CtFreeEx(ct, c, true);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientEnumVLan(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get the protocol name string from ID
wchar_t *GetProtocolName(UINT n)
{
	switch (n)
	{
	case PROXY_DIRECT:
		return _UU("PROTO_DIRECT_TCP");
	case PROXY_HTTP:
		return _UU("PROTO_HTTP_PROXY");
	case PROXY_SOCKS:
		return _UU("PROTO_SOCKS_PROXY");
	case PROXY_SOCKS5:
		return _UU("PROTO_SOCKS5_PROXY");
	}

	return _UU("PROTO_UNKNOWN");
}

// Get the connection settings list
UINT PcAccountList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_ENUM_ACCOUNT t;

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcEnumAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		UINT i;
		CT *ct;

		// Success
		ct = CtNew();
		CtInsertColumn(ct, _UU("CM_ACCOUNT_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("CM_ACCOUNT_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("CM_ACCOUNT_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("CM_ACCOUNT_COLUMN_3_2"), false);
		CtInsertColumn(ct, _UU("CM_ACCOUNT_COLUMN_4"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_CLIENT_ENUM_ACCOUNT_ITEM *e = t.Items[i];
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			IP ip;
			char ip_str[MAX_SIZE];

			// Special treatment for IPv6 addresses
			if (StrToIP6(&ip, e->ServerName) && StartWith(e->ServerName, "[") == false)
			{
				Format(ip_str, sizeof(ip_str),
					"[%s]", e->ServerName);
			}
			else
			{
				StrCpy(ip_str, sizeof(ip_str), e->ServerName);
			}

			if (e->Port == 0)
			{
				// Port number unknown
				UniFormat(tmp2, sizeof(tmp2), L"%S (%s)", ip_str, GetProtocolName(e->ProxyType));
			}
			else
			{
				// Port number are also shown
				UniFormat(tmp2, sizeof(tmp2), L"%S:%u (%s)", ip_str, e->Port, GetProtocolName(e->ProxyType));
			}

			// Virtual HUB name
			StrToUni(tmp4, sizeof(tmp4), e->HubName);

			// Add
			StrToUni(tmp, sizeof(tmp), e->DeviceName);

			CtInsert(ct,
				e->AccountName,
				e->Active == false ? _UU("CM_ACCOUNT_OFFLINE") :
				(e->Connected ? _UU("CM_ACCOUNT_ONLINE") : _UU("CM_ACCOUNT_CONNECTING")),
				tmp2, tmp4,
				tmp);
		}

		CtFreeEx(ct, c, true);
	}

	CiFreeClientEnumAccount(&t);

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Create new connection settings
UINT PcAccountCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CREATE_ACCOUNT t;
	UINT port = 443;
	char *host = NULL;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Hub"), CmdEvalSafe, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
		{"NICNAME", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Nicname"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	// RPC call
	Zero(&t, sizeof(t));

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	t.ClientOption->Port = port;
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));
	t.ClientOption->NumRetry = INFINITE;
	t.ClientOption->RetryInterval = 15;
	t.ClientOption->MaxConnection = 1;
	t.ClientOption->UseEncrypt = true;
	t.ClientOption->AdditionalConnectionInterval = 1;
	StrCpy(t.ClientOption->DeviceName, sizeof(t.ClientOption->DeviceName), GetParamStr(o, "NICNAME"));

	t.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
	t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;
	StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username), GetParamStr(o, "USERNAME"));

	Free(host);

	ret = CcCreateAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	CiFreeClientCreateAccount(&t);

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the destination of the connection settings
UINT PcAccountSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	char *host = NULL;
	UINT port = 443;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Hub"), CmdEvalSafe, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT c;
		// Success
		t.ClientOption->Port = port;
		StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
		StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));

		Zero(&c, sizeof(c));

		c.ClientAuth = t.ClientAuth;
		c.ClientOption = t.ClientOption;
		c.CheckServerCert = t.CheckServerCert;
		c.RetryOnServerCert = t.RetryOnServerCert;
		c.ServerCert = t.ServerCert;
		c.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	Free(host);

	return ret;
}

// Get the configuration of the connection settings
UINT PcAccountGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Show the contents of the connection settings
		wchar_t tmp[MAX_SIZE];

		CT *ct = CtNewStandard();

		// Connection settings name
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NAME"), t.ClientOption->AccountName);

		// Host name of the destination VPN Server
		StrToUni(tmp, sizeof(tmp), t.ClientOption->Hostname);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HOSTNAME"), tmp);

		// The port number to connect to VPN Server
		UniToStru(tmp, t.ClientOption->Port);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PORT"), tmp);

		// Virtual HUB name of the destination VPN Server
		StrToUni(tmp, sizeof(tmp), t.ClientOption->HubName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HUBNAME"), tmp);

		// Type of proxy server to go through
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_TYPE"), GetProxyTypeStr(t.ClientOption->ProxyType));

		if (t.ClientOption->ProxyType != PROXY_DIRECT)
		{
			// Host name of the proxy server
			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyName);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_HOSTNAME"), tmp);

			// Port number of the proxy server
			UniToStru(tmp, t.ClientOption->ProxyPort);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_PORT"), tmp);

			// User name of the proxy server
			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyUsername);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_USERNAME"), tmp);
		}

		// Verify the server certificate
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_USE"),
			t.CheckServerCert ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Registered specific certificate
		if (t.ServerCert != NULL)
		{
			GetAllNameFromX(tmp, sizeof(tmp), t.ServerCert);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_NAME"), tmp);
		}

		if (t.CheckServerCert)
		{
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_RETRY_ON_SERVER_CERT"),
				t.RetryOnServerCert ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
		}

		// Device name to be used for the connection
		StrToUni(tmp, sizeof(tmp), t.ClientOption->DeviceName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_DEVICE_NAME"), tmp);

		// Authentication type
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_TYPE"), GetClientAuthTypeStr(t.ClientAuth->AuthType));

		// User name
		StrToUni(tmp, sizeof(tmp), t.ClientAuth->Username);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_USERNAME"), tmp);

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
		{
			if (t.ClientAuth->ClientX != NULL)
			{
				// Client certificate name
				GetAllNameFromX(tmp, sizeof(tmp), t.ClientAuth->ClientX);
				CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_CERT_NAME"), tmp);
			}
		}

		// Number of TCP connections to be used for VPN communication
		UniToStru(tmp, t.ClientOption->MaxConnection);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NUMTCP"), tmp);

		// Establishment interval of each TCP connection
		UniToStru(tmp, t.ClientOption->AdditionalConnectionInterval);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_INTERVAL"), tmp);

		// Life span of each TCP connection
		if (t.ClientOption->ConnectionDisconnectSpan != 0)
		{
			UniToStru(tmp, t.ClientOption->ConnectionDisconnectSpan);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_MSG_INFINITE"));
		}
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_TTL"), tmp);

		// Use of half-duplex mode
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_HALF"),
			t.ClientOption->HalfConnection ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Encryption by SSL
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_ENCRYPT"),
			t.ClientOption->UseEncrypt ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Data compression
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_COMPRESS"),
			t.ClientOption->UseCompress ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Connect in bridge / router mode
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_BRIDGE_ROUTER"),
			t.ClientOption->RequireBridgeRoutingMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Connect in monitoring mode
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_MONITOR"),
			t.ClientOption->RequireMonitorMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Not to rewrite the routing table
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NO_TRACKING"),
			t.ClientOption->NoRoutingTracking ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Disable the QoS control
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_QOS_DISABLE"),
			t.ClientOption->DisableQoS ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
			
		// Disable UDP Acceleration
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_DISABLEUDP"),
			t.ClientOption->NoUdpAcceleration ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));	

		CtFree(ct, c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Delete the connection settings
UINT PcAccountDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_DELETE_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcDeleteAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the user name used to connect with connection settings
UINT PcAccountUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username), GetParamStr(o, "USERNAME"));

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD)
		{
			c->Write(c, _UU("CMD_AccountUsername_Notice"));
		}

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the type of user authentication of connection settings to anonymous authentication
UINT PcAccountAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the type of user authentication of connection settings to the password authentication
UINT PcAccountPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
		{"TYPE", CmdPrompt, _UU("CMD_CascadePasswordSet_Prompt_Type"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		char *typestr = GetParamStr(o, "TYPE");
		RPC_CLIENT_CREATE_ACCOUNT z;

		// Change the settings
		if (StartWith("standard", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
			HashPassword(t.ClientAuth->HashedPassword, t.ClientAuth->Username,
				GetParamStr(o, "PASSWORD"));
		}
		else if (StartWith("radius", typestr) || StartWith("ntdomain", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PLAIN_PASSWORD;

			StrCpy(t.ClientAuth->PlainPassword, sizeof(t.ClientAuth->PlainPassword),
				GetParamStr(o, "PASSWORD"));
		}
		else
		{
			// Error has occured
			c->Write(c, _UU("CMD_CascadePasswordSet_Type_Invalid"));
			ret = ERR_INVALID_PARAMETER;
		}

		if (ret == ERR_NO_ERROR)
		{
			Zero(&z, sizeof(z));
			z.CheckServerCert = t.CheckServerCert;
			z.RetryOnServerCert = t.RetryOnServerCert;
			z.ClientAuth = t.ClientAuth;
			z.ClientOption = t.ClientOption;
			z.ServerCert = t.ServerCert;
			z.StartupAccount = t.StartupAccount;

			ret = CcSetAccount(pc->RemoteClient, &z);
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the type of user authentication of connection settings to the client certificate authentication
UINT PcAccountCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	X *x;
	K *k;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
		{"LOADKEY", CmdPrompt, _UU("CMD_LOADKEYPATH"), CmdEvalIsFile, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (CmdLoadCertAndKey(c, &x, &k, GetParamUniStr(o, "LOADCERT"), GetParamUniStr(o, "LOADKEY")) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;

		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_CERT;
		if (t.ClientAuth->ClientX != NULL)
		{
			FreeX(t.ClientAuth->ClientX);
		}
		if (t.ClientAuth->ClientK != NULL)
		{
			FreeK(t.ClientAuth->ClientK);
		}

		t.ClientAuth->ClientX = CloneX(x);
		t.ClientAuth->ClientK = CloneK(k);

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	FreeX(x);
	FreeK(k);

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get the client certificate to be used for the connection settings
UINT PcAccountCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		if (t.ClientAuth->AuthType != CLIENT_AUTHTYPE_CERT)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Not_Auth_Cert"));
			ret = ERR_INTERNAL_ERROR;
		}
		else if (t.ClientAuth->ClientX == NULL)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Cert_Not_Exists"));
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			XToFileW(t.ClientAuth->ClientX, GetParamUniStr(o, "SAVECERT"), true);
		}
	}

	CiFreeClientGetAccount(&t);

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Disable communication encryption with the connection settings
UINT PcAccountEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.ClientOption->UseEncrypt = false;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Enable communication encryption with the connection settings
UINT PcAccountEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.ClientOption->UseEncrypt = true;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Enable communication data compression with the connection settings
UINT PcAccountCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.ClientOption->UseCompress = true;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Disable communication data compression with the connection settings
UINT PcAccountCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.ClientOption->UseCompress = false;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

UINT PcAccountHttpHeaderAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;

	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_AccountHttpHeader_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"DATA", CmdPrompt, _UU("CMD_AccountHttpHeader_Prompt_Data"), NULL, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));
	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		UINT i = 0;
		TOKEN_LIST *tokens = NULL;
		HTTP_HEADER *header = NULL;
		char *name = GetParamStr(o, "NAME");

		Trim(name);

		header = NewHttpHeader("", "", "");

		tokens = ParseToken(t.ClientOption->CustomHttpHeader, "\r\n");
		for (i = 0; i < tokens->NumTokens; i++)
		{
			AddHttpValueStr(header, tokens->Token[i]);
		}
		FreeToken(tokens);

		if (GetHttpValue(header, name) == NULL)
		{
			RPC_CLIENT_CREATE_ACCOUNT z;
			char s[HTTP_CUSTOM_HEADER_MAX_SIZE];

			Format(s, sizeof(s), "%s: %s\r\n", name, GetParamStr(o, "DATA"));
			EnSafeHttpHeaderValueStr(s, ' ');

			if ((StrLen(s) + StrLen(t.ClientOption->CustomHttpHeader)) < sizeof(t.ClientOption->CustomHttpHeader)) {
				StrCat(t.ClientOption->CustomHttpHeader, sizeof(s), s);

				Zero(&z, sizeof(z));
				z.CheckServerCert = t.CheckServerCert;
				z.RetryOnServerCert = t.RetryOnServerCert;
				z.ClientAuth = t.ClientAuth;
				z.ClientOption = t.ClientOption;
				z.ServerCert = t.ServerCert;
				z.StartupAccount = t.StartupAccount;

				ret = CcSetAccount(pc->RemoteClient, &z);
			}
			else
			{
				// Error has occurred
				ret = ERR_TOO_MANT_ITEMS;
			}
		}
		else
		{
			// Error has occurred
			ret = ERR_OBJECT_EXISTS;
		}

		FreeHttpHeader(header);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

UINT PcAccountHttpHeaderDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;

	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_AccountHttpHeader_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	LIST *o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));
	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		UINT i = 0;
		TOKEN_LIST *tokens = NULL;
		RPC_CLIENT_CREATE_ACCOUNT z;
		char *value = GetParamStr(o, "NAME");

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		Zero(z.ClientOption->CustomHttpHeader, sizeof(z.ClientOption->CustomHttpHeader));

		tokens = ParseToken(t.ClientOption->CustomHttpHeader, "\r\n");

		for (i = 0; i < tokens->NumTokens; i++)
		{
			if (StartWith(tokens->Token[i], value) == false)
			{
				StrCat(z.ClientOption->CustomHttpHeader, sizeof(z.ClientOption->CustomHttpHeader), tokens->Token[i]);
				StrCat(z.ClientOption->CustomHttpHeader, 1, "\r\n");
			}
		}

		ret = CcSetAccount(pc->RemoteClient, &z);
	}
	else
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

UINT PcAccountHttpHeaderGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;

	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	LIST *o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));
	ret = CcGetAccount(pc->RemoteClient, &t);

	// Release of the parameter list
	FreeParamValueList(o);

	if (ret == ERR_NO_ERROR)
	{
		wchar_t unistr[HTTP_CUSTOM_HEADER_MAX_SIZE];
		TOKEN_LIST *tokens = NULL;
		UINT i = 0;
		CT *ct = CtNew();
		CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_1"), false);

		tokens = ParseToken(t.ClientOption->CustomHttpHeader, "\r\n");

		for (i = 0; i < tokens->NumTokens; i++)
		{
			StrToUni(unistr, sizeof(unistr), tokens->Token[i]);
			CtInsert(ct, unistr);
		}

		CtFreeEx(ct, c, false);
	}
	else
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	return ret;
}

// Set the connection method of the connection settings to the direct TCP/IP connection
UINT PcAccountProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.ClientOption->ProxyType = PROXY_DIRECT;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the connection method of the connection settings to the HTTP proxy server connection
UINT PcAccountProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_AccountProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		char *host;
		UINT port;

		// Data change
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 8080))
		{
			t.ClientOption->ProxyType = PROXY_HTTP;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the connection method of the connection settings to the SOCKS4 proxy server connection
UINT PcAccountProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_AccountProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		char *host;
		UINT port;

		// Data change
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 1080))
		{
			t.ClientOption->ProxyType = PROXY_SOCKS;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the connection method of the connection settings to the SOCKS5 proxy server connection
UINT PcAccountProxySocks5(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_AccountProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", CmdPrompt, NULL, NULL, NULL},
		{"PASSWORD", CmdPrompt, NULL, NULL, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		char *host;
		UINT port;

		// Data change
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 1080))
		{
			t.ClientOption->ProxyType = PROXY_SOCKS5;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Enable validation option for server certificate of connection settings
UINT PcAccountServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.CheckServerCert = true;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Disable validation option of the server certificate of connection settings
UINT PcAccountServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.CheckServerCert = false;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Enable retry option of the invalid server certificate of connection settings
UINT PcAccountRetryOnServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.RetryOnServerCert = true;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Disable retry option of the invalid server certificate of connection settings
UINT PcAccountRetryOnServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.RetryOnServerCert = false;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the server-specific certificate of connection settings
UINT PcAccountServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	X *x;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	x = FileToXW(GetParamUniStr(o, "LOADCERT"));
	if (x == NULL)
	{
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return ERR_INTERNAL_ERROR;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = CloneX(x);

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	FreeX(x);

	return ret;
}

// Delete a server-specific certificate of connection settings
UINT PcAccountServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = NULL;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get a server-specific certificate of connection settings
UINT PcAccountServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = NULL;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the advanced settings of connection settings
UINT PcAccountDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	CMD_EVAL_MIN_MAX mm_maxtcp =
	{
		"CMD_CascadeDetailSet_Eval_MaxTcp", 1, 32
	};
	CMD_EVAL_MIN_MAX mm_interval =
	{
		"CMD_CascadeDetailSet_Eval_Interval", 1, 4294967295UL
	};
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"MAXTCP", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_MaxTcp"), CmdEvalMinMax, &mm_maxtcp},
		{"INTERVAL", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_Interval"), CmdEvalMinMax, &mm_interval},
		{"TTL", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_TTL"), NULL, NULL},
		{"HALF", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_HALF"), NULL, NULL},
		{"BRIDGE", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_BRIDGE"), NULL, NULL},
		{"MONITOR", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_MONITOR"), NULL, NULL},
		{"NOTRACK", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_NOTRACK"), NULL, NULL},
		{"NOQOS", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_NOQOS"), NULL, NULL},
		{"DISABLEUDP", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_DISABLEUDP"), NULL, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Data change
		t.ClientOption->MaxConnection = GetParamInt(o, "MAXTCP");
		t.ClientOption->AdditionalConnectionInterval = GetParamInt(o, "INTERVAL");
		t.ClientOption->ConnectionDisconnectSpan = GetParamInt(o, "TTL");
		t.ClientOption->HalfConnection = GetParamYes(o, "HALF");
		t.ClientOption->RequireBridgeRoutingMode = GetParamYes(o, "BRIDGE");
		t.ClientOption->RequireMonitorMode = GetParamYes(o, "MONITOR");
		t.ClientOption->NoRoutingTracking = GetParamYes(o, "NOTRACK");
		t.ClientOption->DisableQoS = GetParamYes(o, "NOQOS");
		t.ClientOption->NoUdpAcceleration = GetParamYes(o, "DISABLEUDP");

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Change the name of the connection settings
UINT PcAccountRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_RENAME_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountRename_PROMPT_OLD"), CmdEvalNotEmpty, NULL},
		{"NEW", CmdPrompt, _UU("CMD_AccountRename_PROMPT_NEW"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	UniStrCpy(t.NewName, sizeof(t.NewName), GetParamUniStr(o, "NEW"));
	UniStrCpy(t.OldName, sizeof(t.OldName), GetParamUniStr(o, "[name]"));

	ret = CcRenameAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Start to connect to the VPN Server using the connection settings
UINT PcAccountConnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CONNECT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcConnect(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Disconnect the connection settings of connected
UINT PcAccountDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_CONNECT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcDisconnect(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get the current state of the connection settings
UINT PcAccountStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_CONNECTION_STATUS t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccountStatus(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		if (t.Active == false)
		{
			// Has been disconnected
			ret = ERR_ACCOUNT_INACTIVE;
		}
		else
		{
			CT *ct = CtNewStandard();

			CmdPrintStatusToListView(ct, &t);

			CtFree(ct, c);
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetConnectionStatus(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set a virtual LAN card to be used in the connection settings
UINT PcAccountNicSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NICNAME", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Nicname"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT c;
		// Success
		StrCpy(t.ClientOption->DeviceName, sizeof(t.ClientOption->DeviceName),
			GetParamStr(o, "NICNAME"));

		Zero(&c, sizeof(c));

		c.ClientAuth = t.ClientAuth;
		c.ClientOption = t.ClientOption;
		c.CheckServerCert = t.CheckServerCert;
		c.RetryOnServerCert = t.RetryOnServerCert;
		c.ServerCert = t.ServerCert;
		c.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set to display error screens and connection status while connecting to the VPN Server
UINT PcAccountStatusShow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.ClientOption->HideStatusWindow = false;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Configure not to display error screens and connection status while connecting to the VPN Server
UINT PcAccountStatusHide(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.ClientOption->HideStatusWindow = true;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the type of user authentication of connection settings to the smart card authentication
UINT PcAccountSecureCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"CERTNAME", CmdPrompt, _UU("CMD_AccountSecureCertSet_PROMPT_CERTNAME"), CmdEvalNotEmpty, NULL},
		{"KEYNAME", CmdPrompt, _UU("CMD_AccountSecureCertSet_PROMPT_KEYNAME"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_SECURE;
		StrCpy(t.ClientAuth->SecurePublicCertName, sizeof(t.ClientAuth->SecurePublicCertName),
			GetParamStr(o, "CERTNAME"));
		StrCpy(t.ClientAuth->SecurePrivateKeyName, sizeof(t.ClientAuth->SecurePrivateKeyName),
			GetParamStr(o, "KEYNAME"));

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the retry interval and number of retries when disconnect or connection failure of connection settings
UINT PcAccountRetrySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccountRetrySet_EVAL_INTERVAL",
		5,
		4294967295UL,
	};
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NUM", CmdPrompt, _UU("CMD_AccountRetrySet_PROMPT_NUM"), CmdEvalNotEmpty, NULL},
		{"INTERVAL", CmdPrompt, _UU("CMD_AccountRetrySet_PROMPT_INTERVAL"), CmdEvalMinMax, &minmax},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		UINT num = GetParamInt(o, "NUM");
		UINT interval = GetParamInt(o, "INTERVAL");

		t.ClientOption->NumRetry = (num == 999) ? INFINITE : num;
		t.ClientOption->RetryInterval = interval;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}


// Set to start-up connection the connection settings
UINT PcAccountStartupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.StartupAccount = true;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Unset the start-up connection of the connection settings
UINT PcAccountStartupRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		// Change the settings
		t.StartupAccount = false;

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.RetryOnServerCert = t.RetryOnServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		ret = CcSetAccount(pc->RemoteClient, &z);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Export the connection settings
UINT PcAccountExport(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CLIENT_GET_ACCOUNT t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_AccountCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVEPATH", CmdPrompt, _UU("CMD_AccountExport_PROMPT_SAVEPATH"), CmdEvalNotEmpty, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	ret = CcGetAccount(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		RPC_CLIENT_CREATE_ACCOUNT z;
		BUF *b;
		BUF *b2;
		char tmp[MAX_SIZE];
		UCHAR *buf;
		UINT buf_size;
		UCHAR bom[] = {0xef, 0xbb, 0xbf, };

		Zero(&z, sizeof(z));
		z.CheckServerCert = t.CheckServerCert;
		z.ClientAuth = t.ClientAuth;
		z.ClientOption = t.ClientOption;
		z.ServerCert = t.ServerCert;
		z.StartupAccount = t.StartupAccount;

		b = CiAccountToCfg(&z);

		StrCpy(tmp, sizeof(tmp), GetParamStr(o, "SAVEPATH"));
		b2 = NewBuf();

		WriteBuf(b2, bom, sizeof(bom));

		// Add the header part
		buf_size = CalcUniToUtf8(_UU("CM_ACCOUNT_FILE_BANNER"));
		buf = ZeroMalloc(buf_size + 32);
		UniToUtf8(buf, buf_size, _UU("CM_ACCOUNT_FILE_BANNER"));

		WriteBuf(b2, buf, StrLen((char *)buf));
		WriteBuf(b2, b->Buf, b->Size);
		SeekBuf(b2, 0, 0);

		FreeBuf(b);

		if (DumpBuf(b2, tmp) == false)
		{
			c->Write(c, _UU("CMD_SAVEFILE_FAILED"));
			ret = ERR_INTERNAL_ERROR;
		}

		FreeBuf(b2);
		Free(buf);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	CiFreeClientGetAccount(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Check whether the specified account name exists
bool CmdIsAccountName(REMOTE_CLIENT *r, wchar_t *name)
{
	UINT i;
	RPC_CLIENT_ENUM_ACCOUNT t;
	wchar_t tmp[MAX_SIZE];
	bool b = false;
	// Validate arguments
	if (r == NULL || name == NULL)
	{
		return false;
	}

	if (CcEnumAccount(r, &t) != ERR_NO_ERROR)
	{
		return false;
	}

	UniStrCpy(tmp, sizeof(tmp), name);
	UniTrim(tmp);

	for (i = 0;i < t.NumItem;i++)
	{
		if (UniStrCmpi(t.Items[i]->AccountName, tmp) == 0)
		{
			b = true;
			break;
		}
	}

	CiFreeClientEnumAccount(&t);

	return b;
}

// Generate an import name
void CmdGenerateImportName(REMOTE_CLIENT *r, wchar_t *name, UINT size, wchar_t *old_name)
{
	UINT i;
	// Validate arguments
	if (r == NULL || name == NULL || old_name == NULL)
	{
		return;
	}

	for (i = 1;;i++)
	{
		wchar_t tmp[MAX_SIZE];
		if (i == 1)
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_IMPORT_NAME_1"), old_name);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("CM_IMPORT_NAME_2"), old_name, i);
		}

		if (CmdIsAccountName(r, tmp) == false)
		{
			UniStrCpy(name, size, tmp);
			return;
		}
	}
}

// Import a connection setting
UINT PcAccountImport(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	BUF *b;
	wchar_t name[MAX_SIZE];
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[path]", CmdPrompt, _UU("CMD_AccountImport_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Read the file
	b = ReadDumpW(GetParamUniStr(o, "[path]"));

	if (b == NULL)
	{
		// Read failure
		c->Write(c, _UU("CMD_LOADFILE_FAILED"));
		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		RPC_CLIENT_CREATE_ACCOUNT *t;

		t = CiCfgToAccount(b);

		if (t == NULL)
		{
			// Failed to parse
			c->Write(c, _UU("CMD_AccountImport_FAILED_PARSE"));
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			CmdGenerateImportName(pc->RemoteClient, name, sizeof(name), t->ClientOption->AccountName);
			UniStrCpy(t->ClientOption->AccountName, sizeof(t->ClientOption->AccountName), name);

			ret = CcCreateAccount(pc->RemoteClient, t);

			if (ret == ERR_NO_ERROR)
			{
				wchar_t tmp[MAX_SIZE];

				UniFormat(tmp, sizeof(tmp), _UU("CMD_AccountImport_OK"), name);
				c->Write(c, tmp);
			}

			CiFreeClientCreateAccount(t);
			Free(t);
		}

		FreeBuf(b);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Allow remote management of the VPN Client Service
UINT PcRemoteEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		t.AllowRemoteConfig = true;
		ret = CcSetClientConfig(pc->RemoteClient, &t);
	}

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Prohibit remote management of the VPN Client Service
UINT PcRemoteDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		t.AllowRemoteConfig = false;
		ret = CcSetClientConfig(pc->RemoteClient, &t);
	}

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Enable the maintenance function of the Internet connection
UINT PcKeepEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Change the settings
		t.UseKeepConnect = true;
		ret = CcSetClientConfig(pc->RemoteClient, &t);
	}

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Disable the maintenance function of the Internet connection
UINT PcKeepDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		// Change the settings
		t.UseKeepConnect = false;
		ret = CcSetClientConfig(pc->RemoteClient, &t);
	}

	if (ret == ERR_NO_ERROR)
	{
		// Success
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Set the maintenance function of the Internet connection
UINT PcKeepSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;
	char *host;
	UINT port;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"HOST", CmdPrompt, _UU("CMD_KeepSet_PROMPT_HOST"), CmdEvalHostAndPort, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_KeepSet_PROMPT_PROTOCOL"), CmdEvalTcpOrUdp, NULL},
		{"INTERVAL", CmdPrompt, _UU("CMD_KeepSet_PROMPT_INTERVAL"), NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		if (ParseHostPort(GetParamStr(o, "HOST"), &host, &port, 0))
		{
			StrCpy(t.KeepConnectHost, sizeof(t.KeepConnectHost), host);
			t.KeepConnectPort = port;
			t.KeepConnectInterval = GetParamInt(o, "INTERVAL");
			t.KeepConnectProtocol = (StrCmpi(GetParamStr(o, "PROTOCOL"), "tcp") == 0) ? 0 : 1;
			Free(host);

			ret = CcSetClientConfig(pc->RemoteClient, &t);
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Get the maintenance function of the Internet connection
UINT PcKeepGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PC *pc = (PC *)param;
	UINT ret = ERR_NO_ERROR;
	CLIENT_CONFIG t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));

	ret = CcGetClientConfig(pc->RemoteClient, &t);

	if (ret == ERR_NO_ERROR)
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), t.KeepConnectHost);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_1"), tmp);

		UniToStru(tmp, t.KeepConnectPort);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_2"), tmp);

		UniToStru(tmp, t.KeepConnectInterval);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_3"), tmp);

		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_4"),
			t.KeepConnectProtocol == 0 ? L"TCP/IP" : L"UDP/IP");

		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_5"),
			t.UseKeepConnect ? _UU("SM_ACCESS_ENABLE") : _UU("SM_ACCESS_DISABLE"));

		CtFree(ct, c);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}


// Creat a new client management tool context
PC *NewPc(CONSOLE *c, REMOTE_CLIENT *remote_client, char *servername, wchar_t *cmdline)
{
	PC *pc;
	// Validate arguments
	if (c == NULL || remote_client == NULL || servername == NULL)
	{
		return NULL;
	}
	if (UniIsEmptyStr(cmdline))
	{
		cmdline = NULL;
	}

	pc = ZeroMalloc(sizeof(PC));
	pc->ConsoleForServer = false;
	pc->ServerName = CopyStr(servername);
	pc->Console = c;
	pc->LastError = 0;
	pc->RemoteClient = remote_client;
	pc->CmdLine = CopyUniStr(cmdline);

	return pc;
}

// Release the client management tools context
void FreePc(PC *pc)
{
	// Validate arguments
	if (pc == NULL)
	{
		return;
	}

	Free(pc->ServerName);
	Free(pc->CmdLine);
	Free(pc);
}

// Client management tool
UINT PcConnect(CONSOLE *c, char *target, wchar_t *cmdline, char *password)
{
	CEDAR *cedar;
	REMOTE_CLIENT *client;
	bool bad_pass;
	bool no_remote;
	char pass[MAX_SIZE];
	UINT ret = 0;
	// Validate arguments
	if (c == NULL || target == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	StrCpy(pass, sizeof(pass), password);

	cedar = NewCedar(NULL, NULL);

RETRY:
	client = CcConnectRpc(target, pass, &bad_pass, &no_remote, 0);

	if (client == NULL)
	{
		if (no_remote)
		{
			// Remote connection refusal
			c->Write(c, _UU("CMD_VPNCMD_CLIENT_NO_REMODE"));
			ReleaseCedar(cedar);
			return ERR_INTERNAL_ERROR;
		}
		else if (bad_pass)
		{
			char *tmp;
			// Password is different
			c->Write(c, _UU("CMD_VPNCMD_PASSWORD_1"));
			tmp = c->ReadPassword(c, _UU("CMD_VPNCMD_PASSWORD_2"));
			c->Write(c, L"");

			if (tmp == NULL)
			{
				// Cancel
				ReleaseCedar(cedar);
				return ERR_ACCESS_DENIED;
			}
			else
			{
				StrCpy(pass, sizeof(pass), tmp);
				Free(tmp);
			}

			goto RETRY;
		}
		else
		{
			// Connection failure
			CmdPrintError(c, ERR_CONNECT_FAILED);
			ReleaseCedar(cedar);
			return ERR_CONNECT_FAILED;
		}
	}
	else
	{
		// Connection complete
		PC *pc = NewPc(c, client, target, cmdline);
		PcMain(pc);
		ret = pc->LastError;
		FreePc(pc);
	}

	CcDisconnectRpc(client);

	ReleaseCedar(cedar);

	return ret;
}


// Server Administration Tool Processor Main
void PsMain(PS *ps)
{
	char prompt[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (ps == NULL)
	{
		return;
	}

	// If it's not in CSV mode, to display a message that the connection has been made
	if(ps->Console->ConsoleType != CONSOLE_CSV)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_SERVER_CONNECTED"),
			ps->ServerName, ps->ServerPort);
		ps->Console->Write(ps->Console, tmp);
		ps->Console->Write(ps->Console, L"");

		if (ps->HubName == NULL)
		{
			// Server management mode
			ps->Console->Write(ps->Console, _UU("CMD_VPNCMD_SERVER_CONNECTED_1"));
		}
		else
		{
			// Virtual HUB management mode
			UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_SERVER_CONNECTED_2"),
				ps->HubName);
			ps->Console->Write(ps->Console, tmp);
		}
		ps->Console->Write(ps->Console, L"");
	}

	// Get the Caps
	ps->CapsList = ScGetCapsEx(ps->Rpc);

	if (ps->AdminHub != NULL)
	{
		RPC_HUB_STATUS t;
		UINT ret;
		wchar_t tmp[MAX_SIZE];

		// Choose the Virtual HUB that is specified in the ADMINHUB
		Zero(&t, sizeof(t));

		StrCpy(t.HubName, sizeof(t.HubName), ps->AdminHub);

		ret = ScGetHubStatus(ps->Rpc, &t);
		if (ret == ERR_NO_ERROR)
		{
			// Success
			UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Selected"), t.HubName);

			if (ps->HubName != NULL)
			{
				Free(ps->HubName);
			}
			ps->HubName = CopyStr(t.HubName);

			if( ps->Console->ConsoleType != CONSOLE_CSV)
			{
				ps->Console->Write(ps->Console, tmp);
			}
		}
		else
		{
			// Failure
			UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Select_Failed"), ps->AdminHub);

			ps->Console->Write(ps->Console, tmp);
			CmdPrintError(ps->Console, ret);
		}
	}

	if (ps->HubName == NULL)
	{
		RPC_KEY_PAIR t;

		Zero(&t, sizeof(t));

		if (ScGetServerCert(ps->Rpc, &t) == ERR_NO_ERROR)
		{
			if (t.Cert != NULL && t.Cert->has_basic_constraints == false)
			{
				if (t.Cert->root_cert)
				{
					ps->Console->Write(ps->Console, L"");
					ps->Console->Write(ps->Console, _UU("SM_CERT_MESSAGE_CLI"));
					ps->Console->Write(ps->Console, L"");
				}
			}

			FreeRpcKeyPair(&t);
		}
	}

	while (true)
	{
		// Definition of command
		CMD cmd[] =
		{
			{"About", PsAbout},
			{"Check", PtCheck},
			{"Crash", PsCrash},
			{"Flush", PsFlush},
			{"Debug", PsDebug},
			{"ServerInfoGet", PsServerInfoGet},
			{"ServerStatusGet", PsServerStatusGet},
			{"ListenerCreate", PsListenerCreate},
			{"ListenerDelete", PsListenerDelete},
			{"ListenerList", PsListenerList},
			{"ListenerEnable", PsListenerEnable},
			{"ListenerDisable", PsListenerDisable},
			{"PortsUDPGet", PsPortsUDPGet},
			{"PortsUDPSet", PsPortsUDPSet},
			{"ProtoOptionsGet", PsProtoOptionsGet},
			{"ProtoOptionsSet", PsProtoOptionsSet},
			{"ServerPasswordSet", PsServerPasswordSet},
			{"ClusterSettingGet", PsClusterSettingGet},
			{"ClusterSettingStandalone", PsClusterSettingStandalone},
			{"ClusterSettingController", PsClusterSettingController},
			{"ClusterSettingMember", PsClusterSettingMember},
			{"ClusterMemberList", PsClusterMemberList},
			{"ClusterMemberInfoGet", PsClusterMemberInfoGet},
			{"ClusterMemberCertGet", PsClusterMemberCertGet},
			{"ClusterConnectionStatusGet", PsClusterConnectionStatusGet},
			{"ServerCertGet", PsServerCertGet},
			{"ServerKeyGet", PsServerKeyGet},
			{"ServerCertSet", PsServerCertSet},
			{"ServerCipherGet", PsServerCipherGet},
			{"ServerCipherSet", PsServerCipherSet},
			{"KeepEnable", PsKeepEnable},
			{"KeepDisable", PsKeepDisable},
			{"KeepSet", PsKeepSet},
			{"KeepGet", PsKeepGet},
			{"SyslogGet", PsSyslogGet},
			{"SyslogDisable", PsSyslogDisable},
			{"SyslogEnable", PsSyslogEnable},
			{"ConnectionList", PsConnectionList},
			{"ConnectionGet", PsConnectionGet},
			{"ConnectionDisconnect", PsConnectionDisconnect},
			{"BridgeDeviceList", PsBridgeDeviceList},
			{"BridgeList", PsBridgeList},
			{"BridgeCreate", PsBridgeCreate},
			{"BridgeDelete", PsBridgeDelete},
			{"Caps", PsCaps},
			{"Reboot", PsReboot},
			{"ConfigGet", PsConfigGet},
			{"ConfigSet", PsConfigSet},
			{"RouterList", PsRouterList},
			{"RouterAdd", PsRouterAdd},
			{"RouterDelete", PsRouterDelete},
			{"RouterStart", PsRouterStart},
			{"RouterStop", PsRouterStop},
			{"RouterIfList", PsRouterIfList},
			{"RouterIfAdd", PsRouterIfAdd},
			{"RouterIfDel", PsRouterIfDel},
			{"RouterTableList", PsRouterTableList},
			{"RouterTableAdd", PsRouterTableAdd},
			{"RouterTableDel", PsRouterTableDel},
			{"LogFileList", PsLogFileList},
			{"LogFileGet", PsLogFileGet},
			{"HubCreate", PsHubCreate},
			{"HubCreateDynamic", PsHubCreateDynamic},
			{"HubCreateStatic", PsHubCreateStatic},
			{"HubDelete", PsHubDelete},
			{"HubSetStatic", PsHubSetStatic},
			{"HubSetDynamic", PsHubSetDynamic},
			{"HubList", PsHubList},
			{"Hub", PsHub},
			{"Online", PsOnline},
			{"Offline", PsOffline},
			{"SetMaxSession", PsSetMaxSession},
			{"SetHubPassword", PsSetHubPassword},
			{"SetEnumAllow", PsSetEnumAllow},
			{"SetEnumDeny", PsSetEnumDeny},
			{"OptionsGet", PsOptionsGet},
			{"RadiusServerSet", PsRadiusServerSet},
			{"RadiusServerDelete", PsRadiusServerDelete},
			{"RadiusServerGet", PsRadiusServerGet},
			{"StatusGet", PsStatusGet},
			{"LogGet", PsLogGet},
			{"LogEnable", PsLogEnable},
			{"LogDisable", PsLogDisable},
			{"LogSwitchSet", PsLogSwitchSet},
			{"LogPacketSaveType", PsLogPacketSaveType},
			{"CAList", PsCAList},
			{"CAAdd", PsCAAdd},
			{"CADelete", PsCADelete},
			{"CAGet", PsCAGet},
			{"CascadeList", PsCascadeList},
			{"CascadeCreate", PsCascadeCreate},
			{"CascadeSet", PsCascadeSet},
			{"CascadeGet", PsCascadeGet},
			{"CascadeDelete", PsCascadeDelete},
			{"CascadeUsernameSet", PsCascadeUsernameSet},
			{"CascadeAnonymousSet", PsCascadeAnonymousSet},
			{"CascadePasswordSet", PsCascadePasswordSet},
			{"CascadeCertSet", PsCascadeCertSet},
			{"CascadeCertGet", PsCascadeCertGet},
			{"CascadeEncryptEnable", PsCascadeEncryptEnable},
			{"CascadeEncryptDisable", PsCascadeEncryptDisable},
			{"CascadeCompressEnable", PsCascadeCompressEnable},
			{"CascadeCompressDisable", PsCascadeCompressDisable},
			{"CascadeProxyNone", PsCascadeProxyNone},
			{"CascadeHttpHeaderAdd", PsCascadeHttpHeaderAdd},
			{"CascadeHttpHeaderDelete", PsCascadeHttpHeaderDelete},
			{"CascadeHttpHeaderGet", PsCascadeHttpHeaderGet},
			{"CascadeProxyHttp", PsCascadeProxyHttp},
			{"CascadeProxySocks", PsCascadeProxySocks},
			{"CascadeProxySocks5", PsCascadeProxySocks5},
			{"CascadeServerCertEnable", PsCascadeServerCertEnable},
			{"CascadeServerCertDisable", PsCascadeServerCertDisable},
			{"CascadeServerCertSet", PsCascadeServerCertSet},
			{"CascadeServerCertDelete", PsCascadeServerCertDelete},
			{"CascadeServerCertGet", PsCascadeServerCertGet},
			{"CascadeDetailSet", PsCascadeDetailSet},
			{"CascadePolicySet", PsCascadePolicySet},
			{"PolicyList", PsPolicyList},
			{"CascadeStatusGet", PsCascadeStatusGet},
			{"CascadeRename", PsCascadeRename},
			{"CascadeOnline", PsCascadeOnline},
			{"CascadeOffline", PsCascadeOffline},
			{"AccessAdd", PsAccessAdd},
			{"AccessAddEx", PsAccessAddEx},
			{"AccessAdd6", PsAccessAdd6},
			{"AccessAddEx6", PsAccessAddEx6},
			{"AccessList", PsAccessList},
			{"AccessDelete", PsAccessDelete},
			{"AccessEnable", PsAccessEnable},
			{"AccessDisable", PsAccessDisable},
			{"UserList", PsUserList},
			{"UserCreate", PsUserCreate},
			{"UserSet", PsUserSet},
			{"UserDelete", PsUserDelete},
			{"UserGet", PsUserGet},
			{"UserAnonymousSet", PsUserAnonymousSet},
			{"UserPasswordSet", PsUserPasswordSet},
			{"UserCertSet", PsUserCertSet},
			{"UserCertGet", PsUserCertGet},
			{"UserSignedSet", PsUserSignedSet},
			{"UserRadiusSet", PsUserRadiusSet},
			{"UserNTLMSet", PsUserNTLMSet},
			{"UserPolicyRemove", PsUserPolicyRemove},
			{"UserPolicySet", PsUserPolicySet},
			{"UserExpiresSet", PsUserExpiresSet},
			{"GroupList", PsGroupList},
			{"GroupCreate", PsGroupCreate},
			{"GroupSet", PsGroupSet},
			{"GroupDelete", PsGroupDelete},
			{"GroupGet", PsGroupGet},
			{"GroupJoin", PsGroupJoin},
			{"GroupUnjoin", PsGroupUnjoin},
			{"GroupPolicyRemove", PsGroupPolicyRemove},
			{"GroupPolicySet", PsGroupPolicySet},
			{"SessionList", PsSessionList},
			{"SessionGet", PsSessionGet},
			{"SessionDisconnect", PsSessionDisconnect},
			{"MacTable", PsMacTable},
			{"MacDelete", PsMacDelete},
			{"IpTable", PsIpTable},
			{"IpDelete", PsIpDelete},
			{"SecureNatEnable", PsSecureNatEnable},
			{"SecureNatDisable", PsSecureNatDisable},
			{"SecureNatStatusGet", PsSecureNatStatusGet},
			{"SecureNatHostGet", PsSecureNatHostGet},
			{"SecureNatHostSet", PsSecureNatHostSet},
			{"NatGet", PsNatGet},
			{"NatEnable", PsNatEnable},
			{"NatDisable", PsNatDisable},
			{"NatSet", PsNatSet},
			{"NatTable", PsNatTable},
			{"DhcpGet", PsDhcpGet},
			{"DhcpEnable", PsDhcpEnable},
			{"DhcpDisable", PsDhcpDisable},
			{"DhcpSet", PsDhcpSet},
			{"DhcpTable", PsDhcpTable},
			{"AdminOptionList", PsAdminOptionList},
			{"AdminOptionSet", PsAdminOptionSet},
			{"ExtOptionList", PsExtOptionList},
			{"ExtOptionSet", PsExtOptionSet},
			{"CrlList", PsCrlList},
			{"CrlAdd", PsCrlAdd},
			{"CrlDel", PsCrlDel},
			{"CrlGet", PsCrlGet},
			{"AcList", PsAcList},
			{"AcAdd", PsAcAdd},
			{"AcAdd6", PsAcAdd6},
			{"AcDel", PsAcDel},
			{"MakeCert", PtMakeCert},
			{"MakeCert2048", PtMakeCert2048},
			{"TrafficClient", PtTrafficClient},
			{"TrafficServer", PtTrafficServer},
			{"LicenseAdd", PsLicenseAdd},
			{"LicenseDel", PsLicenseDel},
			{"LicenseList", PsLicenseList},
			{"LicenseStatus", PsLicenseStatus},
			{"IPsecEnable", PsIPsecEnable},
			{"IPsecGet", PsIPsecGet},
			{"EtherIpClientAdd", PsEtherIpClientAdd},
			{"EtherIpClientDelete", PsEtherIpClientDelete},
			{"EtherIpClientList", PsEtherIpClientList},
			{"OpenVpnMakeConfig", PsOpenVpnMakeConfig},
			{"ServerCertRegenerate", PsServerCertRegenerate},
			{"VpnOverIcmpDnsEnable", PsVpnOverIcmpDnsEnable},
			{"VpnOverIcmpDnsGet", PsVpnOverIcmpDnsGet},
			{"DynamicDnsGetStatus", PsDynamicDnsGetStatus},
			{"DynamicDnsSetHostname", PsDynamicDnsSetHostname},
			{"VpnAzureGetStatus", PsVpnAzureGetStatus},
			{"VpnAzureSetEnable", PsVpnAzureSetEnable},
		};

		// Generate a prompt
		if (ps->HubName == NULL)
		{
			Format(prompt, sizeof(prompt), "VPN Server>");
		}
		else
		{
			Format(prompt, sizeof(prompt), "VPN Server/%s>", ps->HubName);
		}

		if (DispatchNextCmdEx(ps->Console, ps->CmdLine, prompt, cmd, sizeof(cmd) / sizeof(cmd[0]), ps) == false)
		{
			break;
		}
		ps->LastError = ps->Console->RetCode;

		if (ps->LastError == ERR_NO_ERROR && ps->Console->ConsoleType != CONSOLE_CSV)
		{
			ps->Console->Write(ps->Console, _UU("CMD_MSG_OK"));
			ps->Console->Write(ps->Console, L"");
		}

		if (ps->CmdLine != NULL)
		{
			break;
		}
	}

	// Release the Caps
	FreeCapsList(ps->CapsList);
	ps->CapsList = NULL;
}

// A template for a new command function
UINT PsXxx(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerCreate_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScCreateListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set to the stand-alone mode
UINT PsClusterSettingStandalone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.ServerType = SERVER_TYPE_STANDALONE;

	// RPC call
	ret = ScSetFarmSetting(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set to the cluster controller mode
UINT PsClusterSettingController(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM t;
	UINT weight;
	PARAM args[] =
	{
		{"WEIGHT", NULL, NULL, NULL, NULL},
		{"ONLY", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	weight = GetParamInt(o, "WEIGHT");
	if (weight == 0)
	{
		weight = FARM_DEFAULT_WEIGHT;
	}

	Zero(&t, sizeof(t));
	t.ServerType = SERVER_TYPE_FARM_CONTROLLER;
	t.Weight = weight;
	t.ControllerOnly = GetParamYes(o, "ONLY");

	// RPC call
	ret = ScSetFarmSetting(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Evaluate the IP address
bool CmdEvalIp(CONSOLE *c, wchar_t *str, void *param)
{
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	if (UniIsEmptyStr(str))
	{
		return true;
	}

	if (UniStrToIP32(str) == 0 && UniStrCmpi(str, L"0.0.0.0") != 0)
	{
		wchar_t *msg = (param == NULL) ? _UU("CMD_IP_EVAL_FAILED") : (wchar_t *)param;
		c->Write(c, msg);
		return false;
	}

	return true;
}

// Convert a string to port list
LIST *StrToPortList(char *str, bool limit_range)
{
	LIST *o;
	TOKEN_LIST *t;
	UINT i;
	if (str == NULL)
	{
		return NULL;
	}

	// Convert to token
	t = ParseToken(str, ", ");
	if (t == NULL)
	{
		return NULL;
	}
	if (t->NumTokens == 0)
	{
		FreeToken(t);
		return NULL;
	}

	o = NewListFast(NULL);

	for (i = 0;i < t->NumTokens;i++)
	{
		char *s = t->Token[i];
		UINT n;
		if (IsNum(s) == false)
		{
			ReleaseList(o);
			FreeToken(t);
			return NULL;
		}
		n = ToInt(s);
		if (limit_range && (n == 0 || n >= 65536))
		{
			ReleaseList(o);
			FreeToken(t);
			return NULL;
		}
		if (IsInList(o, (void *)n))
		{
			ReleaseList(o);
			FreeToken(t);
			return NULL;
		}
		Add(o, (void *)n);
	}

	FreeToken(t);

	if (LIST_NUM(o) > MAX_PUBLIC_PORT_NUM)
	{
		ReleaseList(o);
		return NULL;
	}

	return o;
}

// Set to the cluster member mode
UINT PsClusterSettingMember(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM t;
	char *host_and_port;
	char *host;
	UINT port;
	UINT weight;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[server:port]", CmdPrompt, _UU("CMD_ClusterSettingMember_Prompt_HOST_1"), CmdEvalHostAndPort, NULL},
		{"IP", PsClusterSettingMemberPromptIp, NULL, CmdEvalIp, NULL},
		{"PORTS", PsClusterSettingMemberPromptPorts, NULL, CmdEvalPortList, (void *)true},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
		{"WEIGHT", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	weight = GetParamInt(o, "WEIGHT");

	if (weight == 0)
	{
		weight = FARM_DEFAULT_WEIGHT;
	}

	Zero(&t, sizeof(t));
	host_and_port = GetParamStr(o, "[server:port]");
	if (ParseHostPort(host_and_port, &host, &port, 0))
	{
		char *pw;
		char *ports_str;
		LIST *ports;
		UINT i;

		StrCpy(t.ControllerName, sizeof(t.ControllerName), host);
		t.ControllerPort = port;
		Free(host);

		pw = GetParamStr(o, "PASSWORD");

		Sha0(t.MemberPassword, pw, StrLen(pw));
		t.PublicIp = StrToIP32(GetParamStr(o, "IP"));
		t.ServerType = SERVER_TYPE_FARM_MEMBER;

		ports_str = GetParamStr(o, "PORTS");

		ports = StrToPortList(ports_str, true);

		t.NumPort = LIST_NUM(ports);
		t.Ports = ZeroMalloc(sizeof(UINT) * t.NumPort);

		for (i = 0;i < t.NumPort;i++)
		{
			t.Ports[i] = (UINT)LIST_DATA(ports, i);
		}

		t.Weight = weight;

		ReleaseList(ports);

		// RPC call
		ret = ScSetFarmSetting(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcFarm(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Evaluate the port list
bool CmdEvalPortList(CONSOLE *c, wchar_t *str, void *param)
{
	char *s;
	bool ret = false;
	LIST *o;
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	s = CopyUniToStr(str);

	o = StrToPortList(s, (bool)param);

	if (o != NULL)
	{
		ret = true;
	}

	ReleaseList(o);

	Free(s);

	if (ret == false)
	{
		c->Write(c, _UU("CMD_PORTLIST_EVAL_FAILED"));
	}

	return ret;
}

// Check the string of the form of the host name and port number
bool CmdEvalHostAndPort(CONSOLE *c, wchar_t *str, void *param)
{
	char *tmp;
	bool ret = false;
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	tmp = CopyUniToStr(str);

	ret = ParseHostPort(tmp, NULL, NULL, (UINT)param);

	if (ret == false)
	{
		c->Write(c, param == NULL ? _UU("CMD_HOSTPORT_EVAL_FAILED") : (wchar_t *)param);
	}

	Free(tmp);

	return ret;
}

// Input the public port number
wchar_t *PsClusterSettingMemberPromptPorts(CONSOLE *c, void *param)
{
	wchar_t *ret;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	c->Write(c, _UU("CMD_ClusterSettingMember_Prompt_PORT_1"));
	c->Write(c, L"");

	ret = c->ReadLine(c, _UU("CMD_ClusterSettingMember_Prompt_PORT_2"), true);

	return ret;
}

// Input the public IP address
wchar_t *PsClusterSettingMemberPromptIp(CONSOLE *c, void *param)
{
	wchar_t *ret;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	c->Write(c, _UU("CMD_ClusterSettingMember_Prompt_IP_1"));
	c->Write(c, L"");

	ret = c->ReadLine(c, _UU("CMD_ClusterSettingMember_Prompt_IP_2"), true);

	return ret;
}

// Show the cluster members list
UINT PsClusterMemberList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_FARM t;
	CT *ct;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumFarmMember(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("CMD_ID"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_4"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_5"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_6"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_7"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_8"), true);
	CtInsertColumn(ct, _UU("SM_FM_COLUMN_9"), true);

	for (i = 0;i < t.NumFarm;i++)
	{
		RPC_ENUM_FARM_ITEM *e = &t.Farms[i];
		wchar_t tmp0[64];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[64];
		wchar_t tmp4[64];
		wchar_t tmp5[64];
		wchar_t tmp6[64];
		wchar_t tmp7[64];
		wchar_t tmp8[64];

		GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(e->ConnectedTime), NULL);
		StrToUni(tmp2, sizeof(tmp2), e->Hostname);
		UniToStru(tmp3, e->Point);
		UniToStru(tmp4, e->NumSessions);
		UniToStru(tmp5, e->NumTcpConnections);
		UniToStru(tmp6, e->NumHubs);
		UniToStru(tmp7, e->AssignedClientLicense);
		UniToStru(tmp8, e->AssignedBridgeLicense);

		UniToStru(tmp0, e->Id);

		CtInsert(ct, tmp0,
			e->Controller ? _UU("SM_FM_CONTROLLER") : _UU("SM_FM_MEMBER"),
			tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8);
	}

	CtFree(ct, c);

	FreeRpcEnumFarm(&t);

	FreeParamValueList(o);

	return 0;
}

// Get information of cluster members
UINT PsClusterMemberInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM_INFO t;
	CT *ct;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_ClusterMemberInfoGet_PROMPT_ID"), NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Id = UniToInt(GetParamUniStr(o, "[id]"));

	// RPC call
	ret = ScGetFarmInfo(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNewStandard();

	{
		wchar_t tmp[MAX_SIZE];
		char str[MAX_SIZE];
		UINT i;

		CtInsert(ct, _UU("SM_FMINFO_TYPE"),
			t.Controller ? _UU("SM_FARM_CONTROLLER") : _UU("SM_FARM_MEMBER"));

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ConnectedTime), NULL);
		CtInsert(ct, _UU("SM_FMINFO_CONNECT_TIME"), tmp);

		IPToStr32(str, sizeof(str), t.Ip);
		StrToUni(tmp, sizeof(tmp), str);
		CtInsert(ct, _UU("SM_FMINFO_IP"), tmp);

		StrToUni(tmp, sizeof(tmp), t.Hostname);
		CtInsert(ct, _UU("SM_FMINFO_HOSTNAME"), tmp);

		UniToStru(tmp, t.Point);
		CtInsert(ct, _UU("SM_FMINFO_POINT"), tmp);

		UniToStru(tmp, t.Weight);
		CtInsert(ct, _UU("SM_FMINFO_WEIGHT"), tmp);

		UniToStru(tmp, t.NumPort);
		CtInsert(ct, _UU("SM_FMINFO_NUM_PORT"), tmp);

		for (i = 0;i < t.NumPort;i++)
		{
			wchar_t tmp2[MAX_SIZE];
			UniFormat(tmp, sizeof(tmp), _UU("SM_FMINFO_PORT"), i + 1);
			UniToStru(tmp2, t.Ports[i]);
			CtInsert(ct, tmp, tmp2);
		}

		UniToStru(tmp, t.NumFarmHub);
		CtInsert(ct, _UU("SM_FMINFO_NUM_HUB"), tmp);

		for (i = 0;i < t.NumFarmHub;i++)
		{
			wchar_t tmp2[MAX_SIZE];
			UniFormat(tmp, sizeof(tmp), _UU("SM_FMINFO_HUB"), i + 1);
			UniFormat(tmp2, sizeof(tmp2),
				t.FarmHubs[i].DynamicHub ? _UU("SM_FMINFO_HUB_TAG_2") : _UU("SM_FMINFO_HUB_TAG_1"),
				t.FarmHubs[i].HubName);
			CtInsert(ct, tmp, tmp2);
		}

		UniToStru(tmp, t.NumSessions);
		CtInsert(ct, _UU("SM_FMINFO_NUM_SESSION"), tmp);

		UniToStru(tmp, t.NumTcpConnections);
		CtInsert(ct, _UU("SM_FMINFO_NUN_CONNECTION"), tmp);
	}

	CtFree(ct, c);

	FreeRpcFarmInfo(&t);

	FreeParamValueList(o);

	return 0;
}

// Get certificates of cluster members
UINT PsClusterMemberCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM_INFO t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_ClusterMemberCertGet_PROMPT_ID"), NULL, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	t.Id = UniToInt(GetParamUniStr(o, "[id]"));

	// RPC call
	ret = ScGetFarmInfo(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		X *x = t.ServerCert;
		wchar_t *filename = GetParamUniStr(o, "SAVECERT");

		if (XToFileW(x, filename, true) == false)
		{
			c->Write(c, _UU("CMD_SAVECERT_FAILED"));

			ret = ERR_INTERNAL_ERROR;
		}
	}

	FreeRpcFarmInfo(&t);

	FreeParamValueList(o);

	return ret;
}

// Get the status of the connection to the cluster controller
UINT PsClusterConnectionStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_FARM_CONNECTION_STATUS t;
	wchar_t tmp[MAX_SIZE];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetFarmConnectionStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();
		char str[MAX_SIZE];

		if (t.Online == false)
		{
			CtInsert(ct, _UU("SM_FC_IP"), _UU("SM_FC_NOT_CONNECTED"));

			CtInsert(ct, _UU("SM_FC_PORT"), _UU("SM_FC_NOT_CONNECTED"));
		}
		else
		{
			IPToStr32(str, sizeof(str), t.Ip);
			StrToUni(tmp, sizeof(tmp), str);
			CtInsert(ct, _UU("SM_FC_IP"), tmp);

			UniToStru(tmp, t.Port);
			CtInsert(ct, _UU("SM_FC_PORT"), tmp);
		}

		CtInsert(ct,
			_UU("SM_FC_STATUS"),
			t.Online ? _UU("SM_FC_ONLINE") : _UU("SM_FC_OFFLINE"));

		if (t.Online == false)
		{
			UniFormat(tmp, sizeof(tmp), _UU("SM_FC_ERROR_TAG"), _E(t.LastError), t.LastError);
			CtInsert(ct,
				_UU("SM_FC_LAST_ERROR"), tmp);
		}

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.StartedTime), NULL);
		CtInsert(ct, _UU("SM_FC_START_TIME"), tmp);

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.FirstConnectedTime), NULL);
		CtInsert(ct, _UU("SM_FC_FIRST_TIME"), tmp);

		//if (t.Online == false)
		{
			GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.CurrentConnectedTime), NULL);
			CtInsert(ct, _UU("SM_FC_CURRENT_TIME"), tmp);
		}

		UniToStru(tmp, t.NumTry);
		CtInsert(ct, _UU("SM_FC_NUM_TRY"), tmp);

		UniToStru(tmp, t.NumConnected);
		CtInsert(ct, _UU("SM_FC_NUM_CONNECTED"), tmp);

		UniToStru(tmp, t.NumFailed);
		CtInsert(ct, _UU("SM_FC_NUM_FAILED"), tmp);

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the SSL certificate of the VPN Server
UINT PsServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[cert]", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (XToFileW(t.Cert, GetParamUniStr(o, "[cert]"), true) == false)
	{
		c->Write(c, _UU("CMD_SAVECERT_FAILED"));
	}

	FreeRpcKeyPair(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the private key of the SSL certificate of the VPN Server
UINT PsServerKeyGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[key]", CmdPrompt, _UU("CMD_SAVEKEYPATH"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (t.Key != NULL)
	{
		if (KToFileW(t.Key, GetParamUniStr(o, "[key]"), true, NULL) == false)
		{
			c->Write(c, _UU("CMD_SAVEKEY_FAILED"));
		}
	}
	else
	{
		ret = ERR_NOT_ENOUGH_RIGHT;
		CmdPrintError(c, ret);
	}

	FreeRpcKeyPair(&t);

	FreeParamValueList(o);

	return ret;
}

// Read the certificate and the private key
bool CmdLoadCertAndKey(CONSOLE *c, X **xx, K **kk, wchar_t *cert_filename, wchar_t *key_filename)
{
	X *x;
	K *k;
	// Validate arguments
	if (c == NULL || cert_filename == NULL || key_filename == NULL || xx == NULL || kk == NULL)
	{
		return false;
	}

	x = FileToXW(cert_filename);
	if (x == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return false;
	}

	k = CmdLoadKey(c, key_filename);
	if (k == NULL)
	{
		c->Write(c, _UU("CMD_LOADKEY_FAILED"));
		FreeX(x);
		return false;
	}

	if (CheckXandK(x, k) == false)
	{
		c->Write(c, _UU("CMD_KEYPAIR_FAILED"));
		FreeX(x);
		FreeK(k);

		return false;
	}

	*xx = x;
	*kk = k;

	return true;
}

// Read the secret key
K *CmdLoadKey(CONSOLE *c, wchar_t *filename)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return NULL;
	}
	else
	{
		K *key;
		if (IsEncryptedK(b, true) == false)
		{
			key = BufToK(b, true, IsBase64(b), NULL);
		}
		else
		{
			c->Write(c, _UU("CMD_LOADKEY_ENCRYPTED_1"));

			while (true)
			{
				char *pass = c->ReadPassword(c, _UU("CMD_LOADKEY_ENCRYPTED_2"));

				if (pass == NULL)
				{
					FreeBuf(b);
					return NULL;
				}

				key = BufToK(b, true, IsBase64(b), pass);
				Free(pass);

				if (key != NULL)
				{
					break;
				}

				c->Write(c, _UU("CMD_LOADKEY_ENCRYPTED_3"));
			}
		}

		FreeBuf(b);

		return key;
	}
}

// Set the SSL certificate and the private key of the VPN Server
UINT PsServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
		{"LOADKEY", CmdPrompt, _UU("CMD_LOADKEYPATH"), CmdEvalIsFile, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	if (CmdLoadCertAndKey(c, &t.Cert, &t.Key,
		GetParamUniStr(o, "LOADCERT"),
		GetParamUniStr(o, "LOADKEY")))
	{
		// RPC call
		ret = ScSetServerCert(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		if (t.Flag1 == 0)
		{
			// Show the warning message
			c->Write(c, L"");
			c->Write(c, _UU("SM_CERT_NEED_ROOT"));
			c->Write(c, L"");
		}

		FreeRpcKeyPair(&t);
	}
	else
	{
		ret = ERR_INTERNAL_ERROR;
	}

	FreeParamValueList(o);

	return ret;
}

// Get the encryption algorithm used for the VPN communication
UINT PsServerCipherGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_STR t;
	TOKEN_LIST *ciphers;
	UINT i;
	wchar_t tmp[4096];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetServerCipher(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	UniFormat(tmp, sizeof(tmp), L" %S", t.String);
	FreeRpcStr(&t);
	Zero(&t, sizeof(RPC_STR));

	c->Write(c, _UU("CMD_ServerCipherGet_SERVER"));
	c->Write(c, tmp);

	ret = ScGetServerCipherList(ps->Rpc, &t);

	if (ret == ERR_NO_ERROR)
	{
		ciphers = ParseToken(t.String, ";");

		FreeRpcStr(&t);

		c->Write(c, L"");
		c->Write(c, _UU("CMD_ServerCipherGet_CIPHERS"));

		for (i = 0; i < ciphers->NumTokens; i++)
		{
			UniFormat(tmp, sizeof(tmp), L" %S", ciphers->Token[i]);
			c->Write(c, tmp);
		}

		FreeToken(ciphers);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the encryption algorithm used for the VPN communication
UINT PsServerCipherSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_STR t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ServerCipherSet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.String = CopyStr(GetParamStr(o, "[name]"));

	// RPC call
	ret = ScSetServerCipher(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcStr(&t);

	FreeParamValueList(o);

	return 0;
}

// Enabling the maintenance function of the Internet connection
UINT PsKeepEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEEP t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.UseKeepConnect = true;

	ret = ScSetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Disabling the maintenance function of the Internet connection
UINT PsKeepDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEEP t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.UseKeepConnect = false;

	ret = ScSetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Evaluate the UDP or the TCP
bool CmdEvalTcpOrUdp(CONSOLE *c, wchar_t *str, void *param)
{
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	if (UniStrCmpi(str, L"tcp") == 0 || UniStrCmpi(str, L"udp") == 0)
	{
		return true;
	}

	c->Write(c, _UU("CMD_KeepSet_EVAL_TCP_UDP"));

	return false;
}

// Enable the syslog configuration
UINT PsSyslogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;
	CMD_EVAL_MIN_MAX minmax = {"CMD_SyslogEnable_MINMAX", 1, 3};
	char *host;
	UINT port;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[1|2|3]", CmdPrompt, _UU("CMD_SyslogEnable_Prompt_123"), CmdEvalMinMax, &minmax},
		{"HOST", CmdPrompt, _UU("CMD_SyslogEnable_Prompt_HOST"), CmdEvalHostAndPort, (void *)SYSLOG_PORT},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	if (ParseHostPort(GetParamStr(o, "HOST"), &host, &port, SYSLOG_PORT))
	{
		StrCpy(t.Hostname, sizeof(t.Hostname), host);
		t.Port = port;
		t.SaveType = GetParamInt(o, "[1|2|3]");

		Free(host);

		// RPC call
		ret = ScSetSysLog(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Disable the syslog configuration
UINT PsSyslogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.SaveType = SYSLOG_NONE;

	// RPC call
	ret = ScSetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the syslog configuration
UINT PsSyslogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_1"), GetSyslogSettingName(t.SaveType));

		if (t.SaveType != SYSLOG_NONE)
		{
			StrToUni(tmp, sizeof(tmp), t.Hostname);
			CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_2"), tmp);

			UniToStru(tmp, t.Port);
			CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_3"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the syslog configuration name
wchar_t *GetSyslogSettingName(UINT n)
{
	char tmp[MAX_PATH];

	Format(tmp, sizeof(tmp), "SM_SYSLOG_%u", n);

	return _UU(tmp);
}

// Setting of maintenance function of the Internet connection
UINT PsKeepSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEEP t;
	char *host;
	UINT port;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"HOST", CmdPrompt, _UU("CMD_KeepSet_PROMPT_HOST"), CmdEvalHostAndPort, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_KeepSet_PROMPT_PROTOCOL"), CmdEvalTcpOrUdp, NULL},
		{"INTERVAL", CmdPrompt, _UU("CMD_KeepSet_PROMPT_INTERVAL"), NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (ParseHostPort(GetParamStr(o, "HOST"), &host, &port, 0))
	{
		StrCpy(t.KeepConnectHost, sizeof(t.KeepConnectHost), host);
		t.KeepConnectPort = port;
		t.KeepConnectInterval = GetParamInt(o, "INTERVAL");
		t.KeepConnectProtocol = (StrCmpi(GetParamStr(o, "PROTOCOL"), "tcp") == 0) ? 0 : 1;
		Free(host);

		// RPC call
		ret = ScSetKeep(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Get the maintenance function of the Internet connection
UINT PsKeepGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEEP t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetKeep(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), t.KeepConnectHost);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_1"), tmp);

		UniToStru(tmp, t.KeepConnectPort);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_2"), tmp);

		UniToStru(tmp, t.KeepConnectInterval);
		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_3"), tmp);

		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_4"),
			t.KeepConnectProtocol == 0 ? L"TCP/IP" : L"UDP/IP");

		CtInsert(ct, _UU("CMD_KeepGet_COLUMN_5"),
			t.UseKeepConnect ? _UU("SM_ACCESS_ENABLE") : _UU("SM_ACCESS_DISABLE"));

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the connection type string
wchar_t *GetConnectionTypeStr(UINT type)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "SM_CONNECTION_TYPE_%u", type);

	return _UU(tmp);
}

// Get the list of TCP connections connected to VPN Server
UINT PsConnectionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_CONNECTION t;
	UINT i;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumConnection(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_4"), false);

	for (i = 0;i < t.NumConnection;i++)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t name[MAX_SIZE];
		wchar_t datetime[MAX_SIZE];
		RPC_ENUM_CONNECTION_ITEM *e = &t.Connections[i];

		StrToUni(name, sizeof(name), e->Name);
		UniFormat(tmp, sizeof(tmp), _UU("SM_HOSTNAME_AND_PORT"), e->Hostname, e->Port);
		GetDateTimeStrEx64(datetime, sizeof(datetime), SystemToLocal64(e->ConnectedTime), NULL);

		CtInsert(ct, name, tmp, datetime,
			GetConnectionTypeStr(e->Type));
	}

	CtFree(ct, c);

	FreeRpcEnumConnection(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the TCP connection information currently connected to the VPN Server
UINT PsConnectionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONNECTION_INFO t;
	CT *ct;
	wchar_t tmp[MAX_SIZE];
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ConnectionGet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScGetConnectionInfo(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("SM_CONNINFO_NAME"), tmp);

		CtInsert(ct, _UU("SM_CONNINFO_TYPE"), GetConnectionTypeStr(t.Type));

		StrToUni(tmp, sizeof(tmp), t.Hostname);
		CtInsert(ct, _UU("SM_CONNINFO_HOSTNAME"), tmp);

		UniToStru(tmp, t.Port);
		CtInsert(ct, _UU("SM_CONNINFO_PORT"), tmp);

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ConnectedTime), NULL);
		CtInsert(ct, _UU("SM_CONNINFO_TIME"), tmp);

		StrToUni(tmp, sizeof(tmp), t.ServerStr);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_STR"), tmp);

		UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ServerVer / 100, t.ServerVer % 100);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_VER"), tmp);

		UniToStru(tmp, t.ServerBuild);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_BUILD"), tmp);

		if (StrLen(t.ClientStr) != 0)
		{
			StrToUni(tmp, sizeof(tmp), t.ClientStr);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_STR"), tmp);

			UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ClientVer / 100, t.ClientVer % 100);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_VER"), tmp);

			UniToStru(tmp, t.ClientBuild);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_BUILD"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Disconnect the TCP connection connected to the VPN Server
UINT PsConnectionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DISCONNECT_CONNECTION t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ConnectionDisconnect_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScDisconnectConnection(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the LAN card list that can be used for local bridge
UINT PsBridgeDeviceList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ETH t;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumEthernet(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *item = &t.Items[i];
		wchar_t tmp[MAX_SIZE * 2];

		StrToUni(tmp, sizeof(tmp), item->DeviceName);
		c->Write(c, tmp);
	}

	FreeRpcEnumEth(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the list of local bridge connection
UINT PsBridgeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LOCALBRIDGE t;
	UINT i;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_4"), false);

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t.Items[i];
		wchar_t name[MAX_SIZE];
		wchar_t nic[MAX_SIZE];
		wchar_t hub[MAX_SIZE];
		wchar_t *status = _UU("SM_BRIDGE_OFFLINE");

		UniToStru(name, i + 1);
		StrToUni(nic, sizeof(nic), e->DeviceName);
		StrToUni(hub, sizeof(hub), e->HubName);

		if (e->Online)
		{
			status = e->Active ? _UU("SM_BRIDGE_ONLINE") : _UU("SM_BRIDGE_ERROR");
		}

		CtInsert(ct, name, hub, nic, status);
	}

	CtFree(ct, c);

	FreeRpcEnumLocalBridge(&t);

	FreeParamValueList(o);

	return 0;
}

// Create a local bridge connection
UINT PsBridgeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LOCALBRIDGE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[hubname]", CmdPrompt, _UU("CMD_BridgeCreate_PROMPT_HUBNAME"), CmdEvalNotEmpty, NULL},
		{"DEVICE", CmdPrompt, _UU("CMD_BridgeCreate_PROMPT_DEVICE"), CmdEvalNotEmpty, NULL},
		{"TAP", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	t.Active = true;
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "DEVICE"));
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[hubname]"));
	t.Online = true;
	t.TapMode = GetParamYes(o, "TAP");

	// RPC call
	ret = ScAddLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		c->Write(c, _UU("SM_BRIDGE_INTEL"));
		c->Write(c, L"");

		if (GetCapsBool(ps->CapsList, "b_is_in_vm"))
		{
			// Message in the case of operating in a VM
			c->Write(c, _UU("D_SM_VMBRIDGE@CAPTION"));
			c->Write(c, _UU("D_SM_VMBRIDGE@S_1"));
			c->Write(c, _UU("D_SM_VMBRIDGE@S_2"));
			c->Write(c, L"");
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Delete the local bridge connection
UINT PsBridgeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LOCALBRIDGE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[hubname]", CmdPrompt, _UU("CMD_BridgeDelete_PROMPT_HUBNAME"), CmdEvalNotEmpty, NULL},
		{"DEVICE", CmdPrompt, _UU("CMD_BridgeDelete_PROMPT_DEVICE"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "DEVICE"));
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[hubname]"));

	// RPC call
	ret = ScDeleteLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the list of features and capabilities of the server
UINT PsCaps(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	CAPSLIST *t;
	UINT i;
	CT *ct;


	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	t = ScGetCapsEx(ps->Rpc);

	ct = CtNewStandard();

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		CAPS *c = LIST_DATA(t->CapsList, i);
		wchar_t title[MAX_SIZE];
		char name[256];

		Format(name, sizeof(name), "CT_%s", c->Name);

		UniStrCpy(title, sizeof(title), _UU(name));

		if (UniIsEmptyStr(title))
		{
			UniFormat(title, sizeof(title), L"%S", (StrLen(c->Name) >= 2) ? c->Name + 2 : c->Name);
		}

		if (StartWith(c->Name, "b_"))
		{
			bool icon_pass = c->Value == 0 ? false : true;
			if (StrCmpi(c->Name, "b_must_install_pcap") == 0)
			{
				// Reverse only item of WinPcap
				icon_pass = !icon_pass;
			}
			CtInsert(ct, title, c->Value == 0 ? _UU("CAPS_NO") : _UU("CAPS_YES"));
		}
		else
		{
			wchar_t str[64];
			UniToStru(str, c->Value);
			CtInsert(ct, title, str);
		}
	}

	CtFree(ct, c);

	FreeCapsList(t);

	FreeParamValueList(o);

	return 0;
}

// Restart the VPN Server service
UINT PsReboot(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"RESETCONFIG", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	t.IntValue = GetParamYes(o, "RESETCONFIG") ? 1 : 0;

	// RPC call
	ret = ScRebootServer(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcTest(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the current configuration of the VPN Server
UINT PsConfigGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONFIG t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[path]", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetConfig(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t *filename = GetParamUniStr(o, "[path]");

		if (IsEmptyUniStr(filename))
		{
			// Display on the screen
			wchar_t tmp[MAX_SIZE];
			UINT buf_size;
			wchar_t *buf;
			UNI_TOKEN_LIST *lines;

			UniFormat(tmp, sizeof(tmp), _UU("CMD_ConfigGet_FILENAME"), t.FileName,
				StrLen(t.FileData));
			c->Write(c, tmp);
			c->Write(c, L"");

			buf_size = CalcUtf8ToUni((BYTE *)t.FileData, StrLen(t.FileData));
			buf = ZeroMalloc(buf_size + 32);

			Utf8ToUni(buf, buf_size, (BYTE *)t.FileData, StrLen(t.FileData));

			lines = UniGetLines(buf);
			if (lines != NULL)
			{
				UINT i;

				for (i = 0;i < lines->NumTokens;i++)
				{
					c->Write(c, lines->Token[i]);
				}

				UniFreeToken(lines);
			}

			c->Write(c, L"");

			Free(buf);
		}
		else
		{
			// Save to the file
			IO *io = FileCreateW(filename);

			if (io == NULL)
			{
				c->Write(c, _UU("CMD_ConfigGet_FILE_SAVE_FAILED"));

				ret = ERR_INTERNAL_ERROR;
			}
			else
			{
				FileWrite(io, t.FileData, StrLen(t.FileData));
				FileClose(io);
			}
		}
	}

	FreeRpcConfig(&t);

	FreeParamValueList(o);

	return ret;
}

// Write the configuration to the VPN Server
UINT PsConfigSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONFIG t;
	wchar_t *filename;
	BUF *buf;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[path]", CmdPrompt, _UU("CMD_ConfigSet_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	filename = GetParamUniStr(o, "[path]");

	buf = ReadDumpW(filename);
	if (buf == NULL)
	{
		c->Write(c, _UU("CMD_ConfigSet_FILE_LOAD_FAILED"));
	}
	else
	{
		Zero(&t, sizeof(t));

		t.FileData = ZeroMalloc(buf->Size + 1);
		Copy(t.FileData, buf->Buf, buf->Size);
		FreeBuf(buf);

		// RPC call
		ret = ScSetConfig(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcConfig(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the Virtual Layer 3 switch list
UINT PsRouterList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_L3SW t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumL3Switch(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_L3_SW_COLUMN1"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_COLUMN2"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_COLUMN3"), true);
		CtInsertColumn(ct, _UU("SM_L3_SW_COLUMN4"), true);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_ENUM_L3SW_ITEM *e = &t.Items[i];
			wchar_t tmp1[MAX_SIZE], *tmp2, tmp3[64], tmp4[64];

			StrToUni(tmp1, sizeof(tmp1), e->Name);
			if (e->Active == false)
			{
				tmp2 = _UU("SM_L3_SW_ST_F_F");
			}
			else if (e->Online == false)
			{
				tmp2 = _UU("SM_L3_SW_ST_T_F");
			}
			else
			{
				tmp2 = _UU("SM_L3_SW_ST_T_T");
			}
			UniToStru(tmp3, e->NumInterfaces);
			UniToStru(tmp4, e->NumTables);

			CtInsert(ct,
				tmp1, tmp2, tmp3, tmp4);
		}

		CtFree(ct, c);
	}

	FreeRpcEnumL3Sw(&t);

	FreeParamValueList(o);

	return 0;
}

// Define a new virtual layer 3 switch
UINT PsRouterAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3SW t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterAdd_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScAddL3Switch(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Delete the Virtual Layer 3 Switch
UINT PsRouterDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3SW t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterDelete_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScDelL3Switch(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Start the Virtual Layer 3 Switch
UINT PsRouterStart(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3SW t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterStart_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScStartL3Switch(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Stop the Virtual Layer 3 Switch
UINT PsRouterStop(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3SW t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterStop_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScStopL3Switch(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the interface list registered on Virtual Layer 3 Switch
UINT PsRouterIfList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_L3IF t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterIfList_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScEnumL3If(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("SM_L3_SW_IF_COLUMN1"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_IF_COLUMN2"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_IF_COLUMN3"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_L3IF *e = &t.Items[i];

			IPToUniStr32(tmp1, sizeof(tmp1), e->IpAddress);
			IPToUniStr32(tmp2, sizeof(tmp2), e->SubnetMask);
			StrToUni(tmp3, sizeof(tmp3), e->HubName);

			CtInsert(ct, tmp1, tmp2, tmp3);
		}


		CtFree(ct, c);
	}

	FreeRpcEnumL3If(&t);

	FreeParamValueList(o);

	return 0;
}

// Evaluate the IP address and mask
bool CmdEvalIpAndMask4(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	UINT ip, mask;
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndMask4(tmp, &ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_MASK_ERROR_1"));
		return false;
	}

	return true;
}
bool CmdEvalIpAndMask6(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	IP ip, mask;
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndMask6(tmp, &ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_MASK_ERROR_1_6"));
		return false;
	}

	return true;
}

// Evaluate the network address and the subnet mask
bool CmdEvalNetworkAndSubnetMask4(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	UINT ip, mask;
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndSubnetMask4(tmp, &ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_SUBNET_ERROR_1"));
		return false;
	}

	if (IsNetworkAddress32(ip, mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_SUBNET_ERROR_2"));
		return false;
	}

	return true;
}

// Evaluate the IP address and subnet mask
bool CmdEvalHostAndSubnetMask4(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndSubnetMask4(tmp, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_SUBNET_ERROR_1"));
		return false;
	}

	return true;
}

// Add a virtual interface to the virtual layer 3 switch
UINT PsRouterIfAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3IF t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterIfAdd_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"HUB", CmdPrompt, _UU("CMD_RouterIfAdd_PROMPT_HUB"), CmdEvalNotEmpty, NULL},
		{"IP", CmdPrompt, _UU("CMD_RouterIfAdd_PROMPT_IP"), CmdEvalHostAndSubnetMask4, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	ParseIpAndSubnetMask4(GetParamStr(o, "IP"), &t.IpAddress, &t.SubnetMask);
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "HUB"));

	// RPC call
	ret = ScAddL3If(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Delete the virtual interface of the virtual layer 3 switch
UINT PsRouterIfDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3IF t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterIfAdd_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"HUB", CmdPrompt, _UU("CMD_RouterIfAdd_PROMPT_HUB"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "HUB"));

	// RPC call
	ret = ScDelL3If(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the routing table of the Virtual Layer 3 Switch
UINT PsRouterTableList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_L3TABLE t;
	CT *ct;
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	wchar_t tmp3[MAX_SIZE];
	wchar_t tmp4[MAX_SIZE];
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_RouterTableList_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScEnumL3Table(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;

		ct = CtNew();

		CtInsertColumn(ct, _UU("SM_L3_SW_TABLE_COLUMN1"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_TABLE_COLUMN2"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_TABLE_COLUMN3"), false);
		CtInsertColumn(ct, _UU("SM_L3_SW_TABLE_COLUMN4"), true);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_L3TABLE *e = &t.Items[i];

			IPToUniStr32(tmp1, sizeof(tmp1), e->NetworkAddress);
			IPToUniStr32(tmp2, sizeof(tmp2), e->SubnetMask);
			IPToUniStr32(tmp3, sizeof(tmp3), e->GatewayAddress);
			UniToStru(tmp4, e->Metric);

			CtInsert(ct, tmp1, tmp2, tmp3, tmp4);
		}

		CtFree(ct, c);
	}

	FreeRpcEnumL3Table(&t);

	FreeParamValueList(o);

	return 0;
}

// Add a routing table entry to the Virtual Layer 3 Switch
UINT PsRouterTableAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3TABLE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"NETWORK", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_NETWORK"), CmdEvalNetworkAndSubnetMask4, NULL},
		{"GATEWAY", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_GATEWAY"), CmdEvalIp, NULL},
		{"METRIC", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_METRIC"), CmdEvalInt1, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	ParseIpAndSubnetMask4(GetParamStr(o, "NETWORK"), &t.NetworkAddress, &t.SubnetMask);
	t.Metric = GetParamInt(o, "METRIC");
	t.GatewayAddress = StrToIP32(GetParamStr(o, "GATEWAY"));

	// RPC call
	ret = ScAddL3Table(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Delete the routing table entry of the Virtual Layer 3 Switch
UINT PsRouterTableDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_L3TABLE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"NETWORK", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_NETWORK"), CmdEvalNetworkAndSubnetMask4, NULL},
		{"GATEWAY", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_GATEWAY"), CmdEvalIp, NULL},
		{"METRIC", CmdPrompt, _UU("CMD_RouterTableAdd_PROMPT_METRIC"), CmdEvalInt1, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	ParseIpAndSubnetMask4(GetParamStr(o, "NETWORK"), &t.NetworkAddress, &t.SubnetMask);
	t.Metric = GetParamInt(o, "METRIC");
	t.GatewayAddress = StrToIP32(GetParamStr(o, "GATEWAY"));

	// RPC call
	ret = ScDelL3Table(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the log files list
UINT PsLogFileList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LOG_FILE t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	c->Write(c, _UU("CMD_LogFileList_START"));
	c->Write(c, L"");

	// RPC call
	ret = ScEnumLogFile(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		wchar_t tmp[MAX_SIZE];
		CT *ct;

		UniFormat(tmp, sizeof(tmp), _UU("CMD_LogFileList_NUM_LOGS"), t.NumItem);
		c->Write(c, tmp);

		ct = CtNew();

		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_2"), true);
		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_4"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_ENUM_LOG_FILE_ITEM *e = &t.Items[i];
			wchar_t tmp1[MAX_PATH], tmp2[128], tmp3[128], tmp4[MAX_HOST_NAME_LEN + 1];
			char tmp[MAX_SIZE];

			StrToUni(tmp1, sizeof(tmp1), e->FilePath);

			ToStrByte(tmp, sizeof(tmp), e->FileSize);
			StrToUni(tmp2, sizeof(tmp2), tmp);

			GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->UpdatedTime));

			StrToUni(tmp4, sizeof(tmp4), e->ServerName);

			CtInsert(ct, tmp1, tmp2, tmp3, tmp4);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumLogFile(&t);

	FreeParamValueList(o);

	return 0;
}

// Download a log file
UINT PsLogFileGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	BUF *buf;
	char *filename = NULL;
	char *server_name;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_LogFileGet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"SERVER", NULL, NULL, NULL, NULL},
		{"SAVEPATH", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	filename = GetParamStr(o, "SAVE");
	if (IsEmptyStr(filename))
	{
		filename = GetParamStr(o, "SAVEPATH");
	}

	c->Write(c, _UU("CMD_LogFileGet_START"));

	server_name = GetParamStr(o, "SERVER");

	buf = DownloadFileFromServer(ps->Rpc, server_name,
		GetParamStr(o, "[name]"), 0, NULL, NULL);

	if (buf == NULL)
	{
		c->Write(c, _UU("CMD_LogFileGet_FAILED"));

		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		if (IsEmptyStr(filename) == false)
		{
			// Save to the file
			if (DumpBuf(buf, filename) == false)
			{
				ret = ERR_INTERNAL_ERROR;
				c->Write(c, _UU("CMD_LogFileGet_SAVE_FAILED"));
			}
		}
		else
		{
			// Display on the screen
			wchar_t tmp[MAX_SIZE];
			UINT buf_size;
			wchar_t *uni_buf;

			UniFormat(tmp, sizeof(tmp), _UU("CMD_LogFileGet_FILESIZE"),
				buf->Size);
			c->Write(c, tmp);
			c->Write(c, L"");

			buf_size = CalcUtf8ToUni((BYTE *)buf->Buf, buf->Size);
			uni_buf = ZeroMalloc(buf_size + 32);

			Utf8ToUni(uni_buf, buf_size, (BYTE *)buf->Buf, buf->Size);

			c->Write(c, uni_buf);
			c->Write(c, L"");

			Free(uni_buf);
		}

		FreeBuf(buf);
	}

	FreeParamValueList(o);

	return ret;
}

// Create a New Virtual HUB
UINT PsHubCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pass = "";
	UINT hub_type = HUB_TYPE_STANDALONE;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_HubCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}
	else
	{
		RPC_SERVER_INFO t;
		Zero(&t, sizeof(t));
		if (ScGetServerInfo(ps->Rpc, &t) == ERR_NO_ERROR)
		{
			if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
			{
				hub_type = HUB_TYPE_FARM_DYNAMIC;
			}
			FreeRpcServerInfo(&t);
		}
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));
	t.HubType = hub_type;

	if (IsEmptyStr(GetParamStr(o, "PASSWORD")) == false)
	{
		pass = GetParamStr(o, "PASSWORD");
	}

	Sha0(t.HashedPassword, pass, StrLen(pass));
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pass);
	t.Online = true;

	// RPC call
	ret = ScCreateHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Create a New Virtual HUB (dynamic mode)
UINT PsHubCreateDynamic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pass = "";
	UINT hub_type = HUB_TYPE_FARM_DYNAMIC;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_HubCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));
	t.HubType = hub_type;

	if (IsEmptyStr(GetParamStr(o, "PASSWORD")) == false)
	{
		pass = GetParamStr(o, "PASSWORD");
	}

	Sha0(t.HashedPassword, pass, StrLen(pass));
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pass);
	t.Online = true;

	// RPC call
	ret = ScCreateHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Create a New Virtual HUB (static mode)
UINT PsHubCreateStatic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pass = "";
	UINT hub_type = HUB_TYPE_FARM_STATIC;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_HubCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));
	t.HubType = hub_type;

	if (IsEmptyStr(GetParamStr(o, "PASSWORD")) == false)
	{
		pass = GetParamStr(o, "PASSWORD");
	}

	Sha0(t.HashedPassword, pass, StrLen(pass));
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pass);
	t.Online = true;

	// RPC call
	ret = ScCreateHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Delete a Virtual HUB
UINT PsHubDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_HUB t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_HubDelete_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScDeleteHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the Virtual HUB to static
UINT PsHubSetStatic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_HubChange_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

	// Retrieve the current setting first
	ret = ScGetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Change the settings
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));
	t.HubType = HUB_TYPE_FARM_STATIC;

	// Write
	ret = ScSetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Change the type of Virtual HUB to dynamic Virtual HUB
UINT PsHubSetDynamic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_HubChange_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

	// Retrieve the current setting first
	ret = ScGetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Change the settings
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));
	t.HubType = HUB_TYPE_FARM_DYNAMIC;

	// Write
	ret = ScSetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the list of Virtual HUB
UINT PsHubList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_HUB t;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_5"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_7"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_8"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_9"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_10"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_11"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_7"), false);

		for (i = 0;i < t.NumHub;i++)
		{
			RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];
			wchar_t name[MAX_HUBNAME_LEN + 1];
			wchar_t s1[64], s2[64], s3[64], s4[64], s5[64];
			wchar_t s6[64], s7[128], s8[128];
			wchar_t s9[64], s10[64];

			UniToStru(s1, e->NumUsers);
			UniToStru(s2, e->NumGroups);
			UniToStru(s3, e->NumSessions);
			UniToStru(s4, e->NumMacTables);
			UniToStru(s5, e->NumIpTables);

			UniToStru(s6, e->NumLogin);

			if (e->LastLoginTime != 0)
			{
				GetDateTimeStr64Uni(s7, sizeof(s7), SystemToLocal64(e->LastLoginTime));
			}
			else
			{
				UniStrCpy(s7, sizeof(s7), _UU("COMMON_UNKNOWN"));
			}

			if (e->LastCommTime != 0)
			{
				GetDateTimeStr64Uni(s8, sizeof(s8), SystemToLocal64(e->LastCommTime));
			}
			else
			{
				UniStrCpy(s8, sizeof(s8), _UU("COMMON_UNKNOWN"));
			}

			if (e->IsTrafficFilled == false)
			{
				UniStrCpy(s9, sizeof(s9), _UU("CM_ST_NONE"));
				UniStrCpy(s10, sizeof(s10), _UU("CM_ST_NONE"));
			}
			else
			{
				UniToStr3(s9, sizeof(s9),
					e->Traffic.Recv.BroadcastBytes + e->Traffic.Recv.UnicastBytes +
					e->Traffic.Send.BroadcastBytes + e->Traffic.Send.UnicastBytes);

				UniToStr3(s10, sizeof(s10),
					e->Traffic.Recv.BroadcastCount + e->Traffic.Recv.UnicastCount +
					e->Traffic.Send.BroadcastCount + e->Traffic.Send.UnicastCount);
			}

			StrToUni(name, sizeof(name), e->HubName);

			CtInsert(ct,
				name,
				e->Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"),
				GetHubTypeStr(e->HubType),
				s1, s2, s3, s4, s5, s6, s7, s8, s9, s10);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumHub(&t);

	FreeParamValueList(o);

	return 0;
}

// Select a Virtual HUB to manage
UINT PsHub(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_STATUS t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsEmptyStr(GetParamStr(o, "[name]")) == false)
	{
		wchar_t tmp[MAX_SIZE];
		Zero(&t, sizeof(t));

		// Examine whether the specified Virtual HUB is accessible
		StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

		// RPC call
		ret = ScGetHubStatus(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		// Change the selection
		if (ps->HubName != NULL)
		{
			Free(ps->HubName);
		}
		ps->HubName = CopyStr(t.HubName);

		UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Selected"), t.HubName);
		c->Write(c, tmp);
	}
	else
	{
		// Deselect
		if (ps->HubName != NULL)
		{
			c->Write(c, _UU("CMD_Hub_Unselected"));
			Free(ps->HubName);
		}
		ps->HubName = NULL;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the Virtual HUB to online
UINT PsOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_HUB_ONLINE t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Online = true;

	// RPC call
	ret = ScSetHubOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the Virtual HUB to offline
UINT PsOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_HUB_ONLINE t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Online = false;

	// RPC call
	ret = ScSetHubOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the maximum number of concurrent connecting sessions of the Virtual HUB
UINT PsSetMaxSession(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[max_session]", CmdPrompt, _UU("CMD_SetMaxSession_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Get current settings of Virtual HUB
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.MaxSession = GetParamInt(o, "[max_session]");

	// Write the configuration of Virtual HUB
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the administrative password of the Virtual HUB
UINT PsSetHubPassword(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pw;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[password]", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Get current settings of Virtual HUB
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Change the settings
	pw = GetParamStr(o, "[password]");
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pw);
	Sha0(t.HashedPassword, pw, StrLen(pw));

	// Write the configuration of Virtual HUB
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the Virtual HUB to permit to be enumerated for anonymous users
UINT PsSetEnumAllow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Get current settings of Virtual HUB
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.NoEnum = false;

	// Write the configuration of Virtual HUB
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the Virtual HUB to deny to be enumerated for anonymous users
UINT PsSetEnumDeny(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Get current settings of Virtual HUB
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.NoEnum = true;

	// Write the configuration of Virtual HUB
	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the option settings for the virtual HUB
UINT PsOptionsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct;
		wchar_t tmp[MAX_SIZE];

		UniFormat(tmp, sizeof(tmp), _UU("CMD_OptionsGet_TITLE"), ps->HubName);
		c->Write(c, tmp);

		// Display settings
		ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_OptionsGet_ENUM"),
			t.HubOption.NoEnum ? _UU("CMD_MSG_DENY") : _UU("CMD_MSG_ALLOW"));

		if (t.HubOption.MaxSession == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_MSG_INFINITE"));
		}
		else
		{
			UniToStru(tmp, t.HubOption.MaxSession);
		}
		CtInsert(ct, _UU("CMD_OptionsGet_MAXSESSIONS"), tmp);

		CtInsert(ct, _UU("CMD_OptionsGet_STATUS"), t.Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"));

		CtInsert(ct, _UU("CMD_OptionsGet_TYPE"), GetHubTypeStr(t.HubType));

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Setting the Radius server to use for user authentication
UINT PsRadiusServerSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_RADIUS t;
	char *host;
	UINT port;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_RadiusServerSet_EVAL_NUMINTERVAL", RADIUS_RETRY_INTERVAL, RADIUS_RETRY_TIMEOUT,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[server_name:port]", CmdPrompt, _UU("CMD_RadiusServerSet_Prompt_Host"), CmdEvalNotEmpty, NULL},
		{"SECRET", CmdPromptChoosePassword, _UU("CMD_RadiusServerSet_Prompt_Secret"), NULL, NULL},
		{"RETRY_INTERVAL", CmdPrompt, _UU("CMD_RadiusServerSet_Prompt_RetryInterval"), CmdEvalMinMax, &minmax},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (ParseHostPort(GetParamStr(o, "[server_name:port]"), &host, &port, 1812))
	{
		Zero(&t, sizeof(t));

		StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
		t.RadiusPort = port;
		StrCpy(t.RadiusServerName, sizeof(t.RadiusServerName), host);
		StrCpy(t.RadiusSecret, sizeof(t.RadiusSecret), GetParamStr(o, "SECRET"));
		t.RadiusRetryInterval = GetParamInt(o, "RETRY_INTERVAL");

		Free(host);

		// RPC call
		ret = ScSetHubRadius(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Delete the Radius server configuration to be used for user authentication
UINT PsRadiusServerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_RADIUS t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.RadiusPort = 1812;

	// RPC call
	ret = ScSetHubRadius(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the Radius server settings to use for user authentication
UINT PsRadiusServerGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_RADIUS t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubRadius(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct;
		wchar_t tmp[MAX_SIZE];

		ct = CtNewStandard();

		if (IsEmptyStr(t.RadiusServerName))
		{
			CtInsert(ct, _UU("CMD_RadiusServerGet_STATUS"), _UU("CMD_MSG_DISABLE"));
		}
		else
		{
			CtInsert(ct, _UU("CMD_RadiusServerGet_STATUS"), _UU("CMD_MSG_ENABLE"));

			StrToUni(tmp, sizeof(tmp), t.RadiusServerName);
			CtInsert(ct, _UU("CMD_RadiusServerGet_HOST"), tmp);

			UniToStri(tmp, t.RadiusPort);
			CtInsert(ct, _UU("CMD_RadiusServerGet_PORT"), tmp);

			StrToUni(tmp, sizeof(tmp), t.RadiusSecret);
			CtInsert(ct, _UU("CMD_RadiusServerGet_SECRET"), tmp);

			UniToStri(tmp, t.RadiusRetryInterval);
			CtInsert(ct, _UU("CMD_RadiusServerGet_RetryInterval"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the current status of the Virtual HUB
UINT PsStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_STATUS t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();
		wchar_t *s;
		wchar_t tmp[MAX_SIZE];

		// HUB name
		s = CopyStrToUni(t.HubName);
		CtInsert(ct, _UU("SM_HUB_STATUS_HUBNAME"), s);
		Free(s);

		// Online
		CtInsert(ct, _UU("SM_HUB_STATUS_ONLINE"),
			t.Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"));

		// Type of HUB
		CtInsert(ct, _UU("SM_HUB_TYPE"),
			GetHubTypeStr(t.HubType));

		if (t.HubType == HUB_TYPE_STANDALONE)
		{
			// Enable / Disable the SecureNAT
			CtInsert(ct, _UU("SM_HUB_SECURE_NAT"),
				t.SecureNATEnabled ? _UU("SM_HUB_SECURE_NAT_YES") : _UU("SM_HUB_SECURE_NAT_NO"));
		}

		// Other values
		UniToStru(tmp, t.NumSessions);
		CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS"), tmp);

		if (t.NumSessionsClient != 0 || t.NumSessionsBridge != 0)
		{
			UniToStru(tmp, t.NumSessionsClient);
			CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS_CLIENT"), tmp);
			UniToStru(tmp, t.NumSessionsBridge);
			CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS_BRIDGE"), tmp);
		}

		UniToStru(tmp, t.NumAccessLists);
		CtInsert(ct, _UU("SM_HUB_NUM_ACCESSES"), tmp);

		UniToStru(tmp, t.NumUsers);
		CtInsert(ct, _UU("SM_HUB_NUM_USERS"), tmp);
		UniToStru(tmp, t.NumGroups);
		CtInsert(ct, _UU("SM_HUB_NUM_GROUPS"), tmp);

		UniToStru(tmp, t.NumMacTables);
		CtInsert(ct, _UU("SM_HUB_NUM_MAC_TABLES"), tmp);
		UniToStru(tmp, t.NumIpTables);
		CtInsert(ct, _UU("SM_HUB_NUM_IP_TABLES"), tmp);

		// Usage status
		UniToStru(tmp, t.NumLogin);
		CtInsert(ct, _UU("SM_HUB_NUM_LOGIN"), tmp);

		if (t.LastLoginTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastLoginTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_LAST_LOGIN_TIME"), tmp);

		if (t.LastCommTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastCommTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_LAST_COMM_TIME"), tmp);

		if (t.CreatedTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_CREATED_TIME"), tmp);

		// Traffic information
		CmdInsertTrafficInfo(ct, &t.Traffic);

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the log switching string
wchar_t *GetLogSwitchStr(UINT i)
{
	char tmp[64];

	Format(tmp, sizeof(tmp), "SM_LOG_SWITCH_%u", i);

	return _UU(tmp);
}

// Get the packet log name string
wchar_t *GetPacketLogNameStr(UINT i)
{
	char tmp[64];

	Format(tmp, sizeof(tmp), "CMD_Log_%u", i);

	return _UU(tmp);
}

// Get the log storage settings for the virtual HUB
UINT PsLogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_Log_SecurityLog"),
			t.LogSetting.SaveSecurityLog ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
		if (t.LogSetting.SaveSecurityLog)
		{
			CtInsert(ct, _UU("CMD_Log_SwitchType"), GetLogSwitchStr(t.LogSetting.SecurityLogSwitchType));
		}

		CtInsert(ct, L"", L"");

		CtInsert(ct, _UU("CMD_Log_PacketLog"),
			t.LogSetting.SavePacketLog ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
		if (t.LogSetting.SavePacketLog)
		{
			UINT i;

			CtInsert(ct, _UU("CMD_Log_SwitchType"), GetLogSwitchStr(t.LogSetting.PacketLogSwitchType));

			for (i = 0;i <= 7;i++)
			{
				wchar_t *tmp = NULL;

				switch (t.LogSetting.PacketLogConfig[i])
				{
				case PACKET_LOG_NONE:
					tmp = _UU("D_SM_LOG@B_PACKET_0_0");
					break;

				case PACKET_LOG_HEADER:
					tmp = _UU("D_SM_LOG@B_PACKET_0_1");
					break;

				case PACKET_LOG_ALL:
					tmp = _UU("D_SM_LOG@B_PACKET_0_2");
					break;
				}

				CtInsert(ct, GetPacketLogNameStr(i),
					tmp);
			}
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// LogEnable command
UINT PsLogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ret;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SaveSecurityLog = true;
	}
	else
	{
		t.LogSetting.SavePacketLog = true;
	}

	// RPC call
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Disable the packet log or the security log
UINT PsLogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SaveSecurityLog = false;
	}
	else
	{
		t.LogSetting.SavePacketLog = false;
	}

	// RPC call
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Convert the string to log switching type
UINT StrToLogSwitchType(char *str)
{
	UINT ret = INFINITE;
	// Validate arguments
	if (str == NULL)
	{
		return INFINITE;
	}

	if (IsEmptyStr(str) || StartWith("none", str))
	{
		ret = LOG_SWITCH_NO;
	}
	else if (StartWith("second", str))
	{
		ret = LOG_SWITCH_SECOND;
	}
	else if (StartWith("minute", str))
	{
		ret = LOG_SWITCH_MINUTE;
	}
	else if (StartWith("hour", str))
	{
		ret = LOG_SWITCH_HOUR;
	}
	else if (StartWith("day", str))
	{
		ret = LOG_SWITCH_DAY;
	}
	else if (StartWith("month", str))
	{
		ret = LOG_SWITCH_MONTH;
	}

	return ret;
}

// Set the switching period of the log file
UINT PsLogSwitchSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	UINT new_switch_type = 0;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
		{"SWITCH", CmdPrompt, _UU("CMD_LogSwitchSet_Prompt"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}
	
	new_switch_type = StrToLogSwitchType(GetParamStr(o, "SWITCH"));

	if (new_switch_type == INFINITE)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SecurityLogSwitchType = new_switch_type;
	}
	else
	{
		t.LogSetting.PacketLogSwitchType = new_switch_type;
	}

	// RPC call
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Convert the type string of the packet log contents to an integer
UINT StrToPacketLogSaveInfoType(char *str)
{
	UINT ret = INFINITE;
	if (str == NULL)
	{
		return INFINITE;
	}

	if (StartWith("none", str) || IsEmptyStr(str))
	{
		ret = PACKET_LOG_NONE;
	}
	else if (StartWith("header", str))
	{
		ret = PACKET_LOG_HEADER;
	}
	else if (StartWith("full", str) || StartWith("all", str))
	{
		ret = PACKET_LOG_ALL;
	}

	return ret;
}

// Convert a packet type string of the packet log to an integer
UINT StrToPacketLogType(char *str)
{
	UINT ret = INFINITE;
	if (str == NULL || IsEmptyStr(str))
	{
		return INFINITE;
	}

	if (StartWith("tcpconn", str))
	{
		ret = PACKET_LOG_TCP_CONN;
	}
	else if (StartWith("tcpdata", str))
	{
		ret = PACKET_LOG_TCP;
	}
	else if (StartWith("dhcp", str))
	{
		ret = PACKET_LOG_DHCP;
	}
	else if (StartWith("udp", str))
	{
		ret = PACKET_LOG_UDP;
	}
	else if (StartWith("icmp", str))
	{
		ret = PACKET_LOG_ICMP;
	}
	else if (StartWith("ip", str))
	{
		ret = PACKET_LOG_IP;
	}
	else if (StartWith("arp", str))
	{
		ret = PACKET_LOG_ARP;
	}
	else if (StartWith("ethernet", str))
	{
		ret = PACKET_LOG_ETHERNET;
	}

	return ret;
}

// Set the detail level and type of packet to be stored in the packet log
UINT PsLogPacketSaveType(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	UINT packet_type = INFINITE;
	UINT packet_save_info_type = INFINITE;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"TYPE", CmdPrompt, _UU("CMD_LogPacketSaveType_Prompt_TYPE"), NULL, NULL},
		{"SAVE", CmdPrompt, _UU("CMD_LogPacketSaveType_Prompt_SAVE"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}
	
	packet_type = StrToPacketLogType(GetParamStr(o, "TYPE"));
	packet_save_info_type = StrToPacketLogSaveInfoType(GetParamStr(o, "SAVE"));

	if (packet_type == INFINITE || packet_save_info_type == INFINITE)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.LogSetting.PacketLogConfig[packet_type] = packet_save_info_type;

	// RPC call
	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the list of certificates of the trusted certification authority
UINT PsCAList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_ENUM_CA t;
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct = CtNewStandard();

		for (i = 0;i < t.NumCa;i++)
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[64];
			RPC_HUB_ENUM_CA_ITEM *e = &t.Ca[i];

			GetDateStrEx64(tmp, sizeof(tmp), SystemToLocal64(e->Expires), NULL);

			UniToStru(tmp2, e->Key);

			CtInsert(ct, _UU("CMD_CAList_COLUMN_ID"), tmp2);
			CtInsert(ct, _UU("CM_CERT_COLUMN_1"), e->SubjectName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_2"), e->IssuerName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_3"), tmp);

			if (i != (t.NumCa - 1))
			{
				CtInsert(ct, L"---", L"---");
			}
		}

		CtFree(ct, c);
	}

	FreeRpcHubEnumCa(&t);

	FreeParamValueList(o);

	return 0;
}

// Add a certificate to the trusted certification authority
UINT PsCAAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_ADD_CA t;
	X *x;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[path]", CmdPrompt, _UU("CMD_CAAdd_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	x = FileToXW(GetParamUniStr(o, "[path]"));

	if (x == NULL)
	{
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_MSG_LOAD_CERT_FAILED"));
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Cert = x;

	// RPC call
	ret = ScAddCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcHubAddCa(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the certificate of the trusted certification authority
UINT PsCADelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_DELETE_CA t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CADelete_PROMPT_ID"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC call
	ret = ScDeleteCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the certificate of the trusted certification authority
UINT PsCAGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_GET_CA t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CAGet_PROMPT_ID"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_CAGet_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC call
	ret = ScGetCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (XToFileW(t.Cert, GetParamUniStr(o, "SAVECERT"), true))
		{
			// Success
		}
		else
		{
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MSG_SAVE_CERT_FAILED"));
		}
	}

	FreeRpcHubGetCa(&t);

	FreeParamValueList(o);

	return ret;
}

// Get the cascade connection list
UINT PsCascadeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LINK t;
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_5"), false);

		for (i = 0;i < t.NumLink;i++)
		{
			RPC_ENUM_LINK_ITEM *e = &t.Links[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];

			GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(e->ConnectedTime), NULL);
			StrToUni(tmp2, sizeof(tmp2), e->Hostname);
			StrToUni(tmp3, sizeof(tmp3), e->HubName);

			if (e->Online == false)
			{
				UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_OFFLINE"));
			}
			else
			{
				if (e->Connected)
				{
					UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_ONLINE"));
				}
				else
				{
					if (e->LastError != 0)
					{
						UniFormat(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_ERROR"), e->LastError, _E(e->LastError));
					}
					else
					{
						UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_CONNECTING"));
					}
				}
			}

			CtInsert(ct, e->AccountName, tmp4, tmp1, tmp2, tmp3);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumLink(&t);

	FreeParamValueList(o);

	return 0;
}

// Creat a new cascade
UINT PsCascadeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	char *host = NULL;
	UINT port = 443;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Hub"), CmdEvalSafe, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	t.Online = false;

	Copy(&t.Policy, GetDefaultPolicy(), sizeof(POLICY));

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	t.ClientOption->Port = port;
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));
	t.ClientOption->NumRetry = INFINITE;
	t.ClientOption->RetryInterval = 15;
	t.ClientOption->MaxConnection = 8;
	t.ClientOption->UseEncrypt = true;
	t.ClientOption->AdditionalConnectionInterval = 1;
	t.ClientOption->RequireBridgeRoutingMode = true;

	t.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
	t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;
	StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username), GetParamStr(o, "USERNAME"));

	Free(host);

	// RPC call
	ret = ScCreateLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the user name and destination of the cascade connection
UINT PsCascadeSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	char *host = NULL;
	UINT port = 443;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Hub"), CmdEvalSafe, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		Free(host);
		return ret;
	}

	t.ClientOption->Port = port;
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));

	Free(host);

	// RPC call
	ret = ScSetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the type string of proxy
wchar_t *GetProxyTypeStr(UINT i)
{
	switch (i)
	{
	case PROXY_DIRECT:

		return _UU("PROTO_DIRECT_TCP");

	case PROXY_HTTP:
		return _UU("PROTO_HTTP_PROXY");

	case PROXY_SOCKS:
		return _UU("PROTO_SOCKS_PROXY");

	default:
		return _UU("PROTO_UNKNOWN");
	}
}

// Get type string in user authentication for client
wchar_t *GetClientAuthTypeStr(UINT i)
{
	char tmp[MAX_SIZE];

	Format(tmp, sizeof(tmp), "PW_TYPE_%u", i);

	return _UU(tmp);
}

// Get the setting of cascade connection
UINT PsCascadeGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName),
		GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Show the contents of the connection settings
		wchar_t tmp[MAX_SIZE];

		CT *ct = CtNewStandard();

		// Connection settings name
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NAME"), t.ClientOption->AccountName);

		// Host name of the destination VPN Server
		StrToUni(tmp, sizeof(tmp), t.ClientOption->Hostname);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HOSTNAME"), tmp);

		// The port number to connect to VPN Server
		UniToStru(tmp, t.ClientOption->Port);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PORT"), tmp);

		// Virtual HUB name of the destination VPN Server
		StrToUni(tmp, sizeof(tmp), t.ClientOption->HubName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HUBNAME"), tmp);

		// Type of proxy server to go through
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_TYPE"), GetProxyTypeStr(t.ClientOption->ProxyType));

		if (t.ClientOption->ProxyType != PROXY_DIRECT)
		{
			// Host name of the proxy server
			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyName);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_HOSTNAME"), tmp);

			// Port number of the proxy server
			UniToStru(tmp, t.ClientOption->ProxyPort);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_PORT"), tmp);

			// User name of the proxy server
			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyUsername);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_USERNAME"), tmp);
		}

		// To verify the server certificate
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_USE"),
			t.CheckServerCert ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Registered specific certificate
		if (t.ServerCert != NULL)
		{
			GetAllNameFromX(tmp, sizeof(tmp), t.ServerCert);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_NAME"), tmp);
		}

		// Device name to be used for the connection
		StrToUni(tmp, sizeof(tmp), t.ClientOption->DeviceName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_DEVICE_NAME"), tmp);

		// Authentication type
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_TYPE"), GetClientAuthTypeStr(t.ClientAuth->AuthType));

		// User name
		StrToUni(tmp, sizeof(tmp), t.ClientAuth->Username);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_USERNAME"), tmp);

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
		{
			if (t.ClientAuth->ClientX != NULL)
			{
				// Client certificate name
				GetAllNameFromX(tmp, sizeof(tmp), t.ClientAuth->ClientX);
				CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_CERT_NAME"), tmp);
			}
		}

		// Number of TCP connections to be used for VPN communication
		UniToStru(tmp, t.ClientOption->MaxConnection);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NUMTCP"), tmp);

		// Establishment interval of each TCP connection
		UniToStru(tmp, t.ClientOption->AdditionalConnectionInterval);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_INTERVAL"), tmp);

		// Life span of each TCP connection
		if (t.ClientOption->ConnectionDisconnectSpan != 0)
		{
			UniToStru(tmp, t.ClientOption->ConnectionDisconnectSpan);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_MSG_INFINITE"));
		}
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_TTL"), tmp);

		// Use of half-duplex mode
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_HALF"),
			t.ClientOption->HalfConnection ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Encryption by SSL
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_ENCRYPT"),
			t.ClientOption->UseEncrypt ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Data compression
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_COMPRESS"),
			t.ClientOption->UseCompress ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Connect in bridge / router mode
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_BRIDGE_ROUTER"),
			t.ClientOption->RequireBridgeRoutingMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Connect in monitoring mode
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_MONITOR"),
			t.ClientOption->RequireMonitorMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Not to rewrite the routing table
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NO_TRACKING"),
			t.ClientOption->NoRoutingTracking ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		// Disable the QoS control
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_QOS_DISABLE"),
			t.ClientOption->DisableQoS ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtFree(ct, c);

		// Security policy
		c->Write(c, L"");
		c->Write(c, _UU("CMD_CascadeGet_Policy"));
		PrintPolicy(c, &t.Policy, true);
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the cascade connection
UINT PsCascadeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScDeleteLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the user name to use for the cascade connection
UINT PsCascadeUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Change the settings for the cascade connection
		StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username),
			GetParamStr(o, "USERNAME"));

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD)
		{
			c->Write(c, _UU("CMD_CascadeUsername_Notice"));
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

//Set the type of user authentication of cascade connection to the anonymous authentication
UINT PsCascadeAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Change the settings for the cascade connection
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the type of user authentication of cascade connection to the password authentication
UINT PsCascadePasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
		{"TYPE", CmdPrompt, _UU("CMD_CascadePasswordSet_Prompt_Type"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Change the settings for the cascade connection
		char *typestr = GetParamStr(o, "TYPE");

		if (StartWith("standard", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
			HashPassword(t.ClientAuth->HashedPassword, t.ClientAuth->Username,
				GetParamStr(o, "PASSWORD"));
		}
		else if (StartWith("radius", typestr) || StartWith("ntdomain", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PLAIN_PASSWORD;

			StrCpy(t.ClientAuth->PlainPassword, sizeof(t.ClientAuth->PlainPassword),
				GetParamStr(o, "PASSWORD"));
		}
		else
		{
			// An error has occured
			c->Write(c, _UU("CMD_CascadePasswordSet_Type_Invalid"));
			FreeRpcCreateLink(&t);
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ERR_INTERNAL_ERROR;
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the type of user authentication of cascade connection to the client certificate authentication
UINT PsCascadeCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	X *x;
	K *k;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
		{"LOADKEY", CmdPrompt, _UU("CMD_LOADKEYPATH"), CmdEvalIsFile, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (CmdLoadCertAndKey(c, &x, &k, GetParamUniStr(o, "LOADCERT"), GetParamUniStr(o, "LOADKEY")) == false)
	{
		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		FreeX(x);
		FreeK(k);
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Change authentication data
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_CERT;
		if (t.ClientAuth->ClientX != NULL)
		{
			FreeX(t.ClientAuth->ClientX);
		}
		if (t.ClientAuth->ClientK != NULL)
		{
			FreeK(t.ClientAuth->ClientK);
		}

		t.ClientAuth->ClientX = x;
		t.ClientAuth->ClientK = k;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the client certificate to be used in the cascade connection
UINT PsCascadeCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (t.ClientAuth->AuthType != CLIENT_AUTHTYPE_CERT)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Not_Auth_Cert"));
			ret = ERR_INTERNAL_ERROR;
		}
		else if (t.ClientAuth->ClientX == NULL)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Cert_Not_Exists"));
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			XToFileW(t.ClientAuth->ClientX, GetParamUniStr(o, "SAVECERT"), true);
		}
		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// Enable encryption of communication at the time of the cascade connection
UINT PsCascadeEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->UseEncrypt = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Disable encryption of communication at the time of the cascade connection
UINT PsCascadeEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->UseEncrypt = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Enable data compression at the time of communication of the cascade connection
UINT PsCascadeCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->UseCompress = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Disable data compression at the time of communication of the cascade connection
UINT PsCascadeCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->UseCompress = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsCascadeHttpHeaderAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CREATE_LINK t;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadeHttpHeader_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"DATA", CmdPrompt, _UU("CMD_CascadeHttpHeader_Prompt_Data"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	ret = ScGetLink(ps->Rpc, &t);

	if (ret == ERR_NO_ERROR)
	{
		UINT i = 0;
		TOKEN_LIST *tokens = NULL;
		HTTP_HEADER *header = NULL;
		char *name = GetParamStr(o, "NAME");

		Trim(name);

		header = NewHttpHeader("", "", "");

		tokens = ParseToken(t.ClientOption->CustomHttpHeader, "\r\n");
		for (i = 0; i < tokens->NumTokens; i++)
		{
			AddHttpValueStr(header, tokens->Token[i]);
		}
		FreeToken(tokens);

		if (GetHttpValue(header, name) == NULL)
		{
			char s[HTTP_CUSTOM_HEADER_MAX_SIZE];
			Format(s, sizeof(s), "%s: %s\r\n", name, GetParamStr(o, "DATA"));
			EnSafeHttpHeaderValueStr(s, ' ');

			if ((StrLen(s) + StrLen(t.ClientOption->CustomHttpHeader)) < sizeof(t.ClientOption->CustomHttpHeader)) {
				StrCat(t.ClientOption->CustomHttpHeader, sizeof(s), s);
				ret = ScSetLink(ps->Rpc, &t);
			}
			else
			{
				// Error has occurred
				ret = ERR_TOO_MANT_ITEMS;
			}
		}
		else
		{
			// Error has occurred
			ret = ERR_OBJECT_EXISTS;
		}

		FreeHttpHeader(header);
	}

	if (ret != ERR_NO_ERROR)
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	FreeRpcCreateLink(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

UINT PsCascadeHttpHeaderDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CREATE_LINK t;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadeHttpHeader_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	ret = ScGetLink(ps->Rpc, &t);

	if (ret == ERR_NO_ERROR)
	{
		UINT i = 0;
		TOKEN_LIST *tokens = NULL;
		char *value = GetParamStr(o, "NAME");

		Zero(t.ClientOption->CustomHttpHeader, sizeof(t.ClientOption->CustomHttpHeader));

		tokens = ParseToken(t.ClientOption->CustomHttpHeader, "\r\n");

		for (i = 0; i < tokens->NumTokens; i++)
		{
			if (StartWith(tokens->Token[i], value) == false)
			{
				StrCat(t.ClientOption->CustomHttpHeader, sizeof(t.ClientOption->CustomHttpHeader), tokens->Token[i]);
				StrCat(t.ClientOption->CustomHttpHeader, 1, "\r\n");
			}
		}

		ret = ScSetLink(ps->Rpc, &t);
	}
	else
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	FreeRpcCreateLink(&t);

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

UINT PsCascadeHttpHeaderGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CREATE_LINK t;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// RPC call
	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	ret = ScGetLink(ps->Rpc, &t);

	// Release of the parameter list
	FreeParamValueList(o);

	if (ret == ERR_NO_ERROR)
	{
		wchar_t unistr[HTTP_CUSTOM_HEADER_MAX_SIZE];
		TOKEN_LIST *tokens = NULL;
		UINT i = 0;
		CT *ct = CtNew();
		CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_1"), false);

		tokens = ParseToken(t.ClientOption->CustomHttpHeader, "\r\n");

		for (i = 0; i < tokens->NumTokens; i++)
		{
			StrToUni(unistr, sizeof(unistr), tokens->Token[i]);
			CtInsert(ct, unistr);
		}

		CtFreeEx(ct, c, false);
	}
	else
	{
		// Error has occurred
		CmdPrintError(c, ret);
	}

	FreeRpcCreateLink(&t);

	return ret;
}

// Set the cascade connection method to the TCP/IP direct connection mode
UINT PsCascadeProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->ProxyType = PROXY_DIRECT;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the cascade connection method as the mode via HTTP proxy server
UINT PsCascadeProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *host;
		UINT port;

		// Data change
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 8080))
		{
			t.ClientOption->ProxyType = PROXY_HTTP;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the cascade connection method as the mode via SOCKS4 proxy server
UINT PsCascadeProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *host;
		UINT port;

		// Data change
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 1080))
		{
			t.ClientOption->ProxyType = PROXY_SOCKS;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the cascade connection method as the mode via SOCKS5 proxy server
UINT PsCascadeProxySocks5(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *host;
		UINT port;

		// Data change
		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 1080))
		{
			t.ClientOption->ProxyType = PROXY_SOCKS5;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyName), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Enable the validation options for the server certificate of cascade connection
UINT PsCascadeServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.CheckServerCert = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Disable the validation options for the server certificate of cascade connection
UINT PsCascadeServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.CheckServerCert = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Server-specific certificate settings of cascade connection
UINT PsCascadeServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	X *x;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	x = FileToXW(GetParamUniStr(o, "LOADCERT"));
	if (x == NULL)
	{
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		FreeX(x);
		return ret;
	}
	else
	{
		// Data change
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = x;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Delete the server-specific certificate of cascade connection
UINT PsCascadeServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = NULL;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the server-specific certificate of cascade connection
UINT PsCascadeServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Save the certificate
		if (t.ServerCert == NULL)
		{
			c->Write(c, _UU("CMD_CERT_NOT_EXISTS"));
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			if (XToFileW(t.ServerCert, GetParamUniStr(o, "SAVECERT"), true) == false)
			{
				c->Write(c, _UU("CMD_SAVECERT_FAILED"));
				ret = ERR_INTERNAL_ERROR;
			}
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// Set the advanced settings of the cascade connection
UINT PsCascadeDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	CMD_EVAL_MIN_MAX mm_maxtcp =
	{
		"CMD_CascadeDetailSet_Eval_MaxTcp", 1, 32
	};
	CMD_EVAL_MIN_MAX mm_interval =
	{
		"CMD_CascadeDetailSet_Eval_Interval", 1, 4294967295UL
	};
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"MAXTCP", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_MaxTcp"), CmdEvalMinMax, &mm_maxtcp},
		{"INTERVAL", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_Interval"), CmdEvalMinMax, &mm_interval},
		{"TTL", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_TTL"), NULL, NULL},
		{"HALF", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_HALF"), NULL, NULL},
		{"NOQOS", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_NOQOS"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Data change
		t.ClientOption->MaxConnection = GetParamInt(o, "MAXTCP");
		t.ClientOption->AdditionalConnectionInterval = GetParamInt(o, "INTERVAL");
		t.ClientOption->ConnectionDisconnectSpan = GetParamInt(o, "TTL");
		t.ClientOption->HalfConnection = GetParamYes(o, "HALF");
		t.ClientOption->DisableQoS = GetParamYes(o, "NOQOS");

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Show a security policy
void PrintPolicy(CONSOLE *c, POLICY *pol, bool cascade_mode)
{
	UINT i;
	CT *ct;
	PACK *p;
	// Validate arguments
	if (c == NULL || pol == NULL)
	{
		return;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_1"), false);
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_2"), false);
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_3"), false);

	p = NewPack();
	OutRpcPolicy(p, pol);

	// Show the list of all policies
	for (i = 0; i < PolicyNum();i++)
	{
		char name[64];
		wchar_t *tmp;

		if (cascade_mode == false || PolicyIsSupportedForCascade(i))
		{
			wchar_t value_str[256];
			UINT value;
			char tmp2[256];

			Format(tmp2, sizeof(tmp2), "policy:%s", PolicyIdToStr(i));
			value = PackGetInt(p, tmp2);

			tmp = CopyStrToUni(PolicyIdToStr(i));

			FormatPolicyValue(value_str, sizeof(value_str),
				i, value);

			Format(name, sizeof(name), "POL_%u", i);
			CtInsert(ct, tmp, _UU(name), value_str);

			Free(tmp);
		}
	}

	FreePack(p);

	CtFree(ct, c);
}

// Show the security policy list
void PrintPolicyList(CONSOLE *c, char *name)
{
	UINT id;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}
	if (IsEmptyStr(name))
	{
		name = NULL;
	}

	if (name != NULL)
	{
		id = PolicyStrToId(name);
		if (id == INFINITE)
		{
			// Invalid ID
			c->Write(c, _UU("CMD_PolicyList_Invalid_Name"));
		}
		else
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			char name1[64], name2[64];
			wchar_t *title, *descript;
			wchar_t policy_name[MAX_SIZE];

			Format(name1, sizeof(name1), "POL_%u", id);
			Format(name2, sizeof(name2), "POL_EX_%u", id);

			title = _UU(name1);
			descript = _UU(name2);

			StrToUni(policy_name, sizeof(policy_name), PolicyIdToStr(id));

			// Policy name
			c->Write(c, _UU("CMD_PolicyList_Help_1"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", policy_name);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// Simple description of the policy
			c->Write(c, _UU("CMD_PolicyList_Help_2"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", title);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// Range of the value that can be set
			GetPolicyValueRangeStr(tmp, sizeof(tmp), id);
			c->Write(c, _UU("CMD_PolicyList_Help_3"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", tmp);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// Default value
			FormatPolicyValue(tmp, sizeof(tmp), id, GetPolicyItem(id)->DefaultValue);
			c->Write(c, _UU("CMD_PolicyList_Help_4"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", tmp);
			c->Write(c, tmp2);
			c->Write(c, L"");

			// Detailed description of the policy
			c->Write(c, _UU("CMD_PolicyList_Help_5"));
			c->Write(c, descript);
			c->Write(c, L"");
		}
	}
	else
	{
		UINT i;
		CT *ct = CtNew();
		CtInsertColumn(ct, _UU("CMD_PolicyList_Column_1"), false);
		CtInsertColumn(ct, _UU("CMD_PolicyList_Column_2"), false);

		// Show the list of all policies
		for (i = 0; i < PolicyNum();i++)
		{
			char name[64];
			wchar_t *tmp;

			tmp = CopyStrToUni(PolicyIdToStr(i));

			Format(name, sizeof(name), "POL_%u", i);
			CtInsert(ct, tmp, _UU(name));

			Free(tmp);
		}

		CtFree(ct, c);
	}
}

// Editing the contents of the policy
bool EditPolicy(CONSOLE *c, POLICY *pol, char *name, char *value, bool cascade_mode)
{
	PACK *p;
	ELEMENT *e;
	POLICY_ITEM *item;
	UINT id;
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	char pack_name[128];
	// Validate arguments
	if (c == NULL || pol == NULL || name == NULL || value == NULL)
	{
		return false;
	}

	p = NewPack();

	OutRpcPolicy(p, pol);

	Format(pack_name, sizeof(pack_name), "policy:%s", PolicyIdToStr(PolicyStrToId(name)));

	if ((e = GetElement(p, pack_name, VALUE_INT)) == NULL || (id = PolicyStrToId(name)) == INFINITE)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_CascadePolicySet_Invalid_Name"), name);
		c->Write(c, tmp);
		FreePack(p);
		return false;
	}

	if (cascade_mode && (PolicyIsSupportedForCascade(id) == false))
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_CascadePolicySet_Invalid_Name_For_Cascade"), name);
		c->Write(c, tmp);
		FreePack(p);
		return false;
	}

	item = GetPolicyItem(id);

	if (item->TypeInt == false)
	{
		// bool type
		e->values[0]->IntValue = (
			StartWith(value, "y") || StartWith(value, "t") ||
			ToInt(value) != 0) ? 1 : 0;
	}
	else
	{
		UINT n = ToInt(value);
		bool b = true;

		// int type
		GetPolicyValueRangeStr(tmp, sizeof(tmp), id);

		if (item->AllowZero == false)
		{
			if (n == 0)
			{
				b = false;
			}
		}

		if (n != 0 && (n < item->MinValue || n > item->MaxValue))
		{
			b = false;
		}

		if (b == false)
		{
			UniFormat(tmp2, sizeof(tmp2), _UU("CMD_CascadePolicySet_Invalid_Range"), PolicyIdToStr(id), tmp);
			c->Write(c, tmp2);
			FreePack(p);
			return false;
		}

		e->values[0]->IntValue = n;
	}

	Zero(pol, sizeof(POLICY));

	InRpcPolicy(pol, p);

	FreePack(p);

	return true;
}

// Show the list of the type of security policy and possible values
UINT PsPolicyList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", NULL, NULL, NULL, NULL}
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	PrintPolicyList(c, GetParamStr(o, "[name]"));

	FreeParamValueList(o);

	return ERR_NO_ERROR;
}

// Set the security policy of the cascade session
UINT PsCascadePolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (EditPolicy(c, &t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), true) == false)
		{
			// An error has occured
			FreeRpcCreateLink(&t);
			FreeParamValueList(o);
			return ERR_INTERNAL_ERROR;
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Display the status information of the session
void CmdPrintStatusToListView(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s)
{
	CmdPrintStatusToListViewEx(ct, s, false);
}
void CmdPrintStatusToListViewEx(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s, bool server_mode)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	char vv[128];
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	if (server_mode == false)
	{
		CtInsert(ct, _UU("CM_ST_ACCOUNT_NAME"), s->AccountName);

		if (s->Connected == false)
		{
			wchar_t *st = _UU("CM_ST_CONNECTED_FALSE");
			switch (s->SessionStatus)
			{
			case CLIENT_STATUS_CONNECTING:
				st = _UU("CM_ST_CONNECTING");
				break;
			case CLIENT_STATUS_NEGOTIATION:
				st = _UU("CM_ST_NEGOTIATION");
				break;
			case CLIENT_STATUS_AUTH:
				st = _UU("CM_ST_AUTH");
				break;
			case CLIENT_STATUS_ESTABLISHED:
				st = _UU("CM_ST_ESTABLISHED");
				break;
			case CLIENT_STATUS_RETRY:
				st = _UU("CM_ST_RETRY");
				break;
			case CLIENT_STATUS_IDLE:
				st = _UU("CM_ST_IDLE");
				break;
			}
			CtInsert(ct, _UU("CM_ST_CONNECTED"), st);
		}
		else
		{
			CtInsert(ct, _UU("CM_ST_CONNECTED"), _UU("CM_ST_CONNECTED_TRUE"));
		}
	}

	if (s->Connected)
	{
		if (s->VLanId == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_NO_VLAN"));
		}
		else
		{
			UniToStru(tmp, s->VLanId);
		}

		CtInsert(ct, _UU("CM_ST_VLAN_ID"), tmp);

		if (server_mode == false)
		{
			StrToUni(tmp, sizeof(tmp), s->ServerName);
			CtInsert(ct, _UU("CM_ST_SERVER_NAME"), tmp);

			UniFormat(tmp, sizeof(tmp), _UU("CM_ST_PORT_TCP"), s->ServerPort);
			CtInsert(ct, _UU("CM_ST_SERVER_PORT"), tmp);
		}

		StrToUni(tmp, sizeof(tmp), s->ServerProductName);
		CtInsert(ct, _UU("CM_ST_SERVER_P_NAME"), tmp);

		UniFormat(tmp, sizeof(tmp), L"%u.%02u", s->ServerProductVer / 100, s->ServerProductVer % 100);
		CtInsert(ct, _UU("CM_ST_SERVER_P_VER"), tmp);
		UniFormat(tmp, sizeof(tmp), L"Build %u", s->ServerProductBuild);
		CtInsert(ct, _UU("CM_ST_SERVER_P_BUILD"), tmp);
	}

	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->StartTime), NULL);
	CtInsert(ct, _UU("CM_ST_START_TIME"), tmp);
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->FirstConnectionEstablisiedTime), NULL);
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	CtInsert(ct, _UU("CM_ST_FIRST_ESTAB_TIME"), s->FirstConnectionEstablisiedTime == 0 ? _UU("CM_ST_NONE") : tmp);

	if (s->Connected)
	{
		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(s->CurrentConnectionEstablishTime), NULL);
		CtInsert(ct, _UU("CM_ST_CURR_ESTAB_TIME"), tmp);
	}

	if (server_mode == false)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_STR"), s->NumConnectionsEstablished);
		CtInsert(ct, _UU("CM_ST_NUM_ESTABLISHED"), tmp);
	}

	if (s->Connected)
	{
		CtInsert(ct, _UU("CM_ST_HALF_CONNECTION"), s->HalfConnection ? _UU("CM_ST_HALF_TRUE") : _UU("CM_ST_HALF_FALSE"));

		CtInsert(ct, _UU("CM_ST_QOS"), s->QoS ? _UU("CM_ST_QOS_TRUE") : _UU("CM_ST_QOS_FALSE"));

		UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnections);
		CtInsert(ct, _UU("CM_ST_NUM_TCP"), tmp);

		if (s->HalfConnection)
		{
			UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnectionsUpload);
			CtInsert(ct, _UU("CM_ST_NUM_TCP_UPLOAD"), tmp);
			UniFormat(tmp, sizeof(tmp), L"%u", s->NumTcpConnectionsDownload);
			CtInsert(ct, _UU("CM_ST_NUM_TCP_DOWNLOAD"), tmp);
		}

		UniFormat(tmp, sizeof(tmp), L"%u", s->MaxTcpConnections);
		CtInsert(ct, _UU("CM_ST_MAX_TCP"), tmp);

		if (s->UseEncrypt == false)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_FALSE"));
		}
		else
		{
			if (StrLen(s->CipherName) != 0)
			{
				UniFormat(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_TRUE"), s->CipherName);
			}
			else
			{
				UniFormat(tmp, sizeof(tmp), _UU("CM_ST_USE_ENCRYPT_TRUE2"));
			}
		}
		CtInsert(ct, _UU("CM_ST_USE_ENCRYPT"), tmp);

		if (s->UseCompress)
		{
			UINT percent = 0;
			if ((s->TotalRecvSize + s->TotalSendSize) > 0)
			{
				percent = (UINT)((UINT64)100 - (UINT64)(s->TotalRecvSizeReal + s->TotalSendSizeReal) * (UINT64)100 /
					(s->TotalRecvSize + s->TotalSendSize));
				percent = MAKESURE(percent, 0, 100);
			}

			UniFormat(tmp, sizeof(tmp), _UU("CM_ST_COMPRESS_TRUE"), percent);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CM_ST_COMPRESS_FALSE"));
		}
		CtInsert(ct, _UU("CM_ST_USE_COMPRESS"), tmp);

		if (IsEmptyStr(s->UnderlayProtocol) == false)
		{
			StrToUni(tmp, sizeof(tmp), s->UnderlayProtocol);
			CtInsert(ct, _UU("CM_ST_UNDERLAY_PROTOCOL"), tmp);
		}

		if (IsEmptyStr(s->ProtocolDetails) == false)
		{
			StrToUni(tmp, sizeof(tmp), s->ProtocolDetails);
			CtInsert(ct, _UU("CM_ST_PROTOCOL_DETAILS"), tmp);
		}

		CtInsert(ct, _UU("CM_ST_UDP_ACCEL_ENABLED"), (s->IsUdpAccelerationEnabled ? _UU("CM_ST_YES") : _UU("CM_ST_NO")));
		CtInsert(ct, _UU("CM_ST_UDP_ACCEL_USING"), (s->IsUsingUdpAcceleration ? _UU("CM_ST_YES") : _UU("CM_ST_NO")));

		StrToUni(tmp, sizeof(tmp), s->SessionName);
		CtInsert(ct, _UU("CM_ST_SESSION_NAME"), tmp);

		StrToUni(tmp, sizeof(tmp), s->ConnectionName);
		if (UniStrCmpi(tmp, L"INITING") != 0)
		{
			CtInsert(ct, _UU("CM_ST_CONNECTION_NAME"), tmp);
		}

		BinToStr(str, sizeof(str), s->SessionKey, sizeof(s->SessionKey));
		StrToUni(tmp, sizeof(tmp), str);
		CtInsert(ct, _UU("CM_ST_SESSION_KEY"), tmp);

		CtInsert(ct, _UU("CM_ST_BRIDGE_MODE"), s->IsBridgeMode ? _UU("CM_ST_YES") : _UU("CM_ST_NO"));

		CtInsert(ct, _UU("CM_ST_MONITOR_MODE"), s->IsMonitorMode ? _UU("CM_ST_YES") : _UU("CM_ST_NO"));

		ToStr3(vv, sizeof(vv), s->TotalSendSize);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->TotalRecvSize);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.UnicastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_UCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.UnicastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_UCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.BroadcastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_BCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Send.BroadcastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_SEND_BCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.UnicastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_UCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.UnicastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_UCAST_SIZE"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.BroadcastCount);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_NUM_PACKET_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_BCAST_NUM"), tmp);

		ToStr3(vv, sizeof(vv), s->Traffic.Recv.BroadcastBytes);
		UniFormat(tmp, sizeof(tmp), _UU("CM_ST_SIZE_BYTE_STR"), vv);
		CtInsert(ct, _UU("CM_ST_RECV_BCAST_SIZE"), tmp);
	}
}

// Get the current state of the cascade connection
UINT PsCascadeStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK_STATUS t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScGetLinkStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Get the cascade connection state
		CT *ct = CtNewStandard();

		CmdPrintStatusToListView(ct, &t.Status);

		CtFree(ct, c);

		FreeRpcLinkStatus(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Rename the cascade connection
UINT PsCascadeRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_RENAME_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeRename_PROMPT_OLD"), CmdEvalNotEmpty, NULL},
		{"NEW", CmdPrompt, _UU("CMD_CascadeRename_PROMPT_NEW"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	UniStrCpy(t.NewAccountName, sizeof(t.NewAccountName), GetParamUniStr(o, "NEW"));
	UniStrCpy(t.OldAccountName, sizeof(t.OldAccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScRenameLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the cascade connection to on-line state
UINT PsCascadeOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScSetLinkOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set the cascade connection to the off-line state
UINT PsCascadeOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));

	// RPC call
	ret = ScSetLinkOffline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Convert the string to pass / discard flag
bool StrToPassOrDiscard(char *str)
{
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	if (ToInt(str) != 0)
	{
		return true;
	}

	if (StartWith(str, "p") || StartWith(str, "y") || StartWith(str, "t"))
	{
		return true;
	}

	return false;
}

// Convert the string to the protocol
UINT StrToProtocol(char *str)
{
	if (IsEmptyStr(str))
	{
		return 0;
	}

	if (StartWith("ip", str))
	{
		return 0;
	}
	else if (StartWith("tcp", str))
	{
		return IP_PROTO_TCP;
	}
	else if (StartWith("udp", str))
	{
		return IP_PROTO_UDP;
	}
	else if (StartWith("icmpv4", str))
	{
		return IP_PROTO_ICMPV4;
	}
	else if (StartWith("icmpv6", str))
	{
		return IP_PROTO_ICMPV6;
	}

	if (ToInt(str) == 0)
	{
		if (StrCmpi(str, "0") == 0)
		{
			return 0;
		}
		else
		{
			return INFINITE;
		}
	}

	if (ToInt(str) >= 256)
	{
		return INFINITE;
	}

	return ToInt(str);
}

// Check the protocol name
bool CmdEvalProtocol(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (StrToProtocol(tmp) == INFINITE)
	{
		c->Write(c, _UU("CMD_PROTOCOL_EVAL_FAILED"));
		return false;
	}

	return true;
}

// Parse the port range
bool ParsePortRange(char *str, UINT *start, UINT *end)
{
	UINT a = 0, b = 0;
	TOKEN_LIST *t;
	// Validate arguments
	if (str == NULL)
	{
		return false;
	}

	if (IsEmptyStr(str) == false)
	{

		t = ParseToken(str, "\t -");

		if (t->NumTokens == 1)
		{
			a = b = ToInt(t->Token[0]);
		}
		else if (t->NumTokens == 2)
		{
			a = ToInt(t->Token[0]);
			b = ToInt(t->Token[1]);
		}

		FreeToken(t);

		if (a > b)
		{
			return false;
		}

		if (a >= 65536 || b >= 65536)
		{
			return false;
		}

		if (a == 0 && b != 0)
		{
			return false;
		}
	}

	if (start != NULL)
	{
		*start = a;
	}
	if (end != NULL)
	{
		*end = b;
	}

	return true;
}

// Check the port range
bool CmdEvalPortRange(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParsePortRange(tmp, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_PORT_RANGE_EVAL_FAILED"));
		return false;
	}

	return true;
}

// Parse the MAC address and the mask
bool ParseMacAddressAndMask(char *src, bool *check_mac, UCHAR *mac_bin, UCHAR *mask_bin)
{
	TOKEN_LIST *t;
	char *macstr, *maskstr;
	UCHAR mac[6], mask[6];
	bool ok = false;

	// Validate arguments
	if (src == NULL)
	{
		return false;
	}

	//Zero(mac, sizeof(mac));
	//Zero(mask, sizeof(mask));

	if(check_mac != NULL && mac_bin != NULL && mask_bin != NULL)
	{
		ok = true;
	}
	if(IsEmptyStr(src) != false)
	{
		if(ok != false)
		{
			*check_mac = false;
			Zero(mac_bin, 6);
			Zero(mask_bin, 6);
		}
		return true;
	}

	t = ParseToken(src, "/");
	if(t->NumTokens != 2)
	{
		FreeToken(t);
		return false;
	}

	macstr = t->Token[0];
	maskstr = t->Token[1];

	Trim(macstr);
	Trim(maskstr);

	if(StrToMac(mac, macstr) == false || StrToMac(mask, maskstr) == false)
	{
		FreeToken(t);
		return false;
	}
	else
	{
		if(ok != false)
		{
			Copy(mac_bin, mac, 6);
			Copy(mask_bin, mask, 6);
			*check_mac = true;
		}
	}
	FreeToken(t);

	return true;
}

// Check the MAC address and mask
bool CmdEvalMacAddressAndMask(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// Validate arguments
	if(c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);


	if(ParseMacAddressAndMask(tmp, NULL, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_MAC_ADDRESS_AND_MASK_EVAL_FAILED"));
		return false;
	}

	return true;
}
// Parse the status of TCP connection
bool ParseTcpState(char *src, bool *check_tcp_state, bool *established)
{
	bool ok = false;
	// Validate arguments
	if(src == NULL)
	{
		return false;
	}

	if(check_tcp_state != NULL && established != NULL)
	{
		ok = true;
	}

	if (IsEmptyStr(src) == false)
	{
		if (StartWith("Established", src) == 0)
		{
			if(ok != false)
			{
				*check_tcp_state = true;
				*established = true;
			}
		}
		else if (StartWith("Unestablished", src) == 0)
		{
			if(ok != false)
			{
				*check_tcp_state = true;
				*established = false;
			}
		}
		else
		{
			// Illegal string
			return false;
		}
	}
	else
	{
		if(ok != false)
		{
			*check_tcp_state = false;
			*established = false;
		}
	}

	return true;
}
// Check the status of the TCP connection
bool CmdEvalTcpState(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	// Validate arguments
	if(c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if(ParseTcpState(tmp, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_TCP_CONNECTION_STATE_EVAL_FAILED"));
		return false;
	}

	return true;
}

// Adding a rule to the access list (Standard, IPv4)
UINT PsAccessAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCIP"), CmdEvalIpAndMask4, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTIP"), CmdEvalIpAndMask4, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);
	ParseIpAndMask4(GetParamStr(o, "SRCIP"), &a->SrcIpAddress, &a->SrcSubnetMask);
	ParseIpAndMask4(GetParamStr(o, "DESTIP"), &a->DestIpAddress, &a->DestSubnetMask);
	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);

	// RPC call
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Adding a rule to the access list (Extended, IPv4)
UINT PsAccessAddEx(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	CMD_EVAL_MIN_MAX minmax_delay =
	{
		"CMD_AccessAddEx_Eval_DELAY", 0, HUB_ACCESSLIST_DELAY_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_jitter =
	{
		"CMD_AccessAddEx_Eval_JITTER", 0, HUB_ACCESSLIST_JITTER_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_loss =
	{
		"CMD_AccessAddEx_Eval_LOSS", 0, HUB_ACCESSLIST_LOSS_MAX,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCIP"), CmdEvalIpAndMask4, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTIP"), CmdEvalIpAndMask4, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
		{"DELAY", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_DELAY"), CmdEvalMinMax, &minmax_delay},
		{"JITTER", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_JITTER"), CmdEvalMinMax, &minmax_jitter},
		{"LOSS", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_LOSS"), CmdEvalMinMax, &minmax_loss},
		{"REDIRECTURL", NULL, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Check whether it is supported
	if (GetCapsBool(ps->CapsList, "b_support_ex_acl") == false)
	{
		c->Write(c, _E(ERR_NOT_SUPPORTED));
		return ERR_NOT_SUPPORTED;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);
	ParseIpAndMask4(GetParamStr(o, "SRCIP"), &a->SrcIpAddress, &a->SrcSubnetMask);
	ParseIpAndMask4(GetParamStr(o, "DESTIP"), &a->DestIpAddress, &a->DestSubnetMask);
	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);
	a->Delay = GetParamInt(o, "DELAY");
	a->Jitter = GetParamInt(o, "JITTER");
	a->Loss = GetParamInt(o, "LOSS");
	StrCpy(a->RedirectUrl, sizeof(a->RedirectUrl), GetParamStr(o, "REDIRECTURL"));

	// RPC call
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Adding a rule to the access list (Standard, IPv6)
UINT PsAccessAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	IP ip, mask;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCIP"), CmdEvalIpAndMask6, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTIP"), CmdEvalIpAndMask6, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Check whether it is supported
	if (GetCapsBool(ps->CapsList, "b_support_ex_acl") == false)
	{
		c->Write(c, _E(ERR_NOT_SUPPORTED));
		return ERR_NOT_SUPPORTED;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	a->IsIPv6 = true;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);

	Zero(&ip, sizeof(ip));
	Zero(&mask, sizeof(mask));

	ParseIpAndMask6(GetParamStr(o, "SRCIP"), &ip, &mask);
	IPToIPv6Addr(&a->SrcIpAddress6, &ip);
	IPToIPv6Addr(&a->SrcSubnetMask6, &mask);

	ParseIpAndMask6(GetParamStr(o, "DESTIP"), &ip, &mask);
	IPToIPv6Addr(&a->DestIpAddress6, &ip);
	IPToIPv6Addr(&a->DestSubnetMask6, &mask);

	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);

	// RPC call
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Adding a rule to the access list (Extended, IPv6)
UINT PsAccessAddEx6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	IP ip, mask;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	CMD_EVAL_MIN_MAX minmax_delay =
	{
		"CMD_AccessAddEx6_Eval_DELAY", 0, HUB_ACCESSLIST_DELAY_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_jitter =
	{
		"CMD_AccessAddEx6_Eval_JITTER", 0, HUB_ACCESSLIST_JITTER_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_loss =
	{
		"CMD_AccessAddEx6_Eval_LOSS", 0, HUB_ACCESSLIST_LOSS_MAX,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCIP"), CmdEvalIpAndMask6, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTIP"), CmdEvalIpAndMask6, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
		{"DELAY", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_DELAY"), CmdEvalMinMax, &minmax_delay},
		{"JITTER", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_JITTER"), CmdEvalMinMax, &minmax_jitter},
		{"LOSS", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_LOSS"), CmdEvalMinMax, &minmax_loss},
		{"REDIRECTURL", NULL, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	// Check whether it is supported
	if (GetCapsBool(ps->CapsList, "b_support_ex_acl") == false)
	{
		c->Write(c, _E(ERR_NOT_SUPPORTED));
		return ERR_NOT_SUPPORTED;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	a->IsIPv6 = true;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);

	Zero(&ip, sizeof(ip));
	Zero(&mask, sizeof(mask));

	ParseIpAndMask6(GetParamStr(o, "SRCIP"), &ip, &mask);
	IPToIPv6Addr(&a->SrcIpAddress6, &ip);
	IPToIPv6Addr(&a->SrcSubnetMask6, &mask);

	ParseIpAndMask6(GetParamStr(o, "DESTIP"), &ip, &mask);
	IPToIPv6Addr(&a->DestIpAddress6, &ip);
	IPToIPv6Addr(&a->DestSubnetMask6, &mask);

	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);
	a->Delay = GetParamInt(o, "DELAY");
	a->Jitter = GetParamInt(o, "JITTER");
	a->Loss = GetParamInt(o, "LOSS");
	StrCpy(a->RedirectUrl, sizeof(a->RedirectUrl), GetParamStr(o, "REDIRECTURL"));

	// RPC call
	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}


// Get the list of rules in the access list
UINT PsAccessList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	CT *ct;
	UINT i;
	
	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_0"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_1"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_2"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_3"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_6"), true);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_5"), false);
	CtInsertColumn(ct, _UU("SM_ACCESS_COLUMN_4"), false);

	for (i = 0;i < t.NumAccess;i++)
	{
		ACCESS *a = &t.Accesses[i];
		char tmp[MAX_SIZE];
		wchar_t tmp3[MAX_SIZE];
		wchar_t tmp1[MAX_SIZE];
		wchar_t tmp2[MAX_SIZE];
		wchar_t tmp4[MAX_SIZE];

		GetAccessListStr(tmp, sizeof(tmp), a);
		UniToStru(tmp1, a->Priority);
		StrToUni(tmp2, sizeof(tmp2), tmp);
		UniToStru(tmp4, a->UniqueId);
		if (a->UniqueId == 0)
		{
			UniStrCpy(tmp4, sizeof(tmp4), _UU("SEC_NONE"));
		}

		UniToStru(tmp3, a->Id);

		CtInsert(ct,
			tmp3,
			a->Discard ? _UU("SM_ACCESS_DISCARD") : _UU("SM_ACCESS_PASS"),
			a->Active ? _UU("SM_ACCESS_ENABLE") : _UU("SM_ACCESS_DISABLE"),
			tmp1,
			tmp4,
			tmp2,
			a->Note);
	}

	CtFreeEx(ct, c, true);

	FreeRpcEnumAccessList(&t);

	FreeParamValueList(o);

	return 0;
}

// Remove a rule from the access list
UINT PsAccessDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_ACCESS t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Id = GetParamInt(o, "[id]");

	// RPC call
	ret = ScDeleteAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Enable the rule of access list
UINT PsAccessEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;
		for (i = 0;i < t.NumAccess;i++)
		{
			ACCESS *a = &t.Accesses[i];

			if (a->Id == GetParamInt(o, "[id]"))
			{
				b = true;

				a->Active = true;
			}
		}

		if (b == false)
		{
			// The specified ID is not found
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcEnumAccessList(&t);
			return ret;
		}

		ret = ScSetAccessList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcEnumAccessList(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// Disable the rule of access list
UINT PsAccessDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ACCESS_LIST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_Access_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;
		for (i = 0;i < t.NumAccess;i++)
		{
			ACCESS *a = &t.Accesses[i];

			if (a->Id == GetParamInt(o, "[id]"))
			{
				b = true;

				a->Active = false;
			}
		}

		if (b == false)
		{
			// The specified ID is not found
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcEnumAccessList(&t);
			return ret;
		}

		ret = ScSetAccessList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcEnumAccessList(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// Get the user list
UINT PsUserList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_USER t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("SM_USER_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_5"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_7"), false);
		CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_5"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_7"), false);

		for (i = 0;i < t.NumUser;i++)
		{
			RPC_ENUM_USER_ITEM *e = &t.Users[i];
			wchar_t name[MAX_SIZE];
			wchar_t group[MAX_SIZE];
			wchar_t num[MAX_SIZE];
			wchar_t time[MAX_SIZE];
			wchar_t exp[MAX_SIZE];
			wchar_t num1[64], num2[64];

			StrToUni(name, sizeof(name), e->Name);

			if (StrLen(e->GroupName) != 0)
			{
				StrToUni(group, sizeof(group), e->GroupName);
			}
			else
			{
				UniStrCpy(group, sizeof(group), _UU("SM_NO_GROUP"));
			}

			UniToStru(num, e->NumLogin);

			GetDateTimeStrEx64(time, sizeof(time), SystemToLocal64(e->LastLoginTime), NULL);

			if (e->IsExpiresFilled == false)
			{
				UniStrCpy(exp, sizeof(exp), _UU("CM_ST_NONE"));
			}
			else
			{
				if (e->Expires == 0)
				{
					UniStrCpy(exp, sizeof(exp), _UU("SM_LICENSE_NO_EXPIRES"));
				}
				else
				{
					GetDateTimeStrEx64(exp, sizeof(exp), SystemToLocal64(e->Expires), NULL);
				}
			}

			if (e->IsTrafficFilled == false)
			{
				UniStrCpy(num1, sizeof(num1), _UU("CM_ST_NONE"));
				UniStrCpy(num2, sizeof(num2), _UU("CM_ST_NONE"));
			}
			else
			{
				UniToStr3(num1, sizeof(num1),
					e->Traffic.Recv.BroadcastBytes + e->Traffic.Recv.UnicastBytes +
					e->Traffic.Send.BroadcastBytes + e->Traffic.Send.UnicastBytes);

				UniToStr3(num2, sizeof(num2),
					e->Traffic.Recv.BroadcastCount + e->Traffic.Recv.UnicastCount +
					e->Traffic.Send.BroadcastBytes + e->Traffic.Send.UnicastCount);
			}

			CtInsert(ct,
				name, e->Realname, group, e->Note, GetAuthTypeStr(e->AuthType),
				num, time, exp, num1, num2);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Get a string of user authentication method
wchar_t *GetAuthTypeStr(UINT id)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "SM_AUTHTYPE_%u", id);

	return _UU(tmp);
}

// Creating a user
UINT PsUserCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"GROUP", CmdPrompt, _UU("CMD_UserCreate_Prompt_GROUP"), NULL, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_UserCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_UserCreate_Prompt_NOTE"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "GROUP"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	Trim(t.Name);
	if (StrCmpi(t.Name, "*") == 0)
	{
		t.AuthType = AUTHTYPE_RADIUS;
		t.AuthData = NewRadiusAuthData(NULL);
	}
	else
	{
		UCHAR random_pass[SHA1_SIZE];
		UCHAR random_pass2[MD5_SIZE];

		Rand(random_pass, sizeof(random_pass));
		Rand(random_pass2, sizeof(random_pass2));
		t.AuthType = AUTHTYPE_PASSWORD;
		t.AuthData = NewPasswordAuthDataRaw(random_pass, random_pass2);
	}

	// RPC call
	ret = ScCreateUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Change the user information
UINT PsUserSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"GROUP", CmdPrompt, _UU("CMD_UserCreate_Prompt_GROUP"), NULL, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_UserCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_UserCreate_Prompt_NOTE"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "GROUP"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the user
UINT PsUserDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScDeleteUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the user information
UINT PsUserGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct;

		// Display the user's data
		ct = CtNewStandard();

		// User name
		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("CMD_UserGet_Column_Name"), tmp);

		// Real name
		CtInsert(ct, _UU("CMD_UserGet_Column_RealName"), t.Realname);

		// Description
		CtInsert(ct, _UU("CMD_UserGet_Column_Note"), t.Note);

		// Group name
		if (IsEmptyStr(t.GroupName) == false)
		{
			StrToUni(tmp, sizeof(tmp), t.GroupName);
			CtInsert(ct, _UU("CMD_UserGet_Column_Group"), tmp);
		}

		// Expiration date
		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ExpireTime), NULL);
		CtInsert(ct, _UU("CMD_UserGet_Column_Expires"), tmp);

		// Authentication method
		CtInsert(ct, _UU("CMD_UserGet_Column_AuthType"), GetAuthTypeStr(t.AuthType));

		switch (t.AuthType)
		{
		case AUTHTYPE_USERCERT:
			if (t.AuthData != NULL)
			{
				AUTHUSERCERT *auc = (AUTHUSERCERT *)t.AuthData;

				if (auc != NULL && auc->UserX != NULL)
				{
					// Registered user-specific certificate
					GetAllNameFromX(tmp, sizeof(tmp), auc->UserX);
					CtInsert(ct, _UU("CMD_UserGet_Column_UserCert"), tmp);
				}
			}
			break;

		case AUTHTYPE_ROOTCERT:
			if (t.AuthData != NULL)
			{
				AUTHROOTCERT *arc = (AUTHROOTCERT *)t.AuthData;

				if (IsEmptyUniStr(arc->CommonName) == false)
				{
					// Limitation the value of the certificate's CN
					CtInsert(ct, _UU("CMD_UserGet_Column_RootCert_CN"), arc->CommonName);
				}

				if (arc->Serial != NULL && arc->Serial->size >= 1)
				{
					char tmp2[MAX_SIZE];

					// Limitation the serial number of the certificate
					BinToStrEx(tmp2, sizeof(tmp2), arc->Serial->data, arc->Serial->size);
					StrToUni(tmp, sizeof(tmp), tmp2);
					CtInsert(ct, _UU("CMD_UserGet_Column_RootCert_SERIAL"), tmp);
				}
			}
			break;

		case AUTHTYPE_RADIUS:
		case AUTHTYPE_NT:
			if (t.AuthData != NULL)
			{
				AUTHRADIUS *ar = (AUTHRADIUS *)t.AuthData;

				// Authentication user name of the external authentication server
				if (IsEmptyUniStr(ar->RadiusUsername) == false)
				{
					CtInsert(ct, _UU("CMD_UserGet_Column_RadiusAlias"), ar->RadiusUsername);
				}
			}
			break;
		}

		CtInsert(ct, L"---", L"---");

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime), NULL);
		CtInsert(ct, _UU("SM_USERINFO_CREATE"), tmp);

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.UpdatedTime), NULL);
		CtInsert(ct, _UU("SM_USERINFO_UPDATE"), tmp);

		CmdInsertTrafficInfo(ct, &t.Traffic);

		UniToStru(tmp, t.NumLogin);
		CtInsert(ct, _UU("SM_USERINFO_NUMLOGIN"), tmp);


		CtFree(ct, c);

		if (t.Policy != NULL)
		{
			c->Write(c, L"");
			c->Write(c, _UU("CMD_UserGet_Policy"));
			PrintPolicy(c, t.Policy, false);
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the authentication method for the user to the anonymous authentication
UINT PsUserAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	FreeAuthData(t.AuthType, t.AuthData);

	// Set to anonymous authentication
	t.AuthType = AUTHTYPE_ANONYMOUS;
	t.AuthData = NULL;

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the authentication method for the user to the password authentication and set a password
UINT PsUserPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHPASSWORD *pw;

		pw = NewPasswordAuthData(t.Name, GetParamStr(o, "PASSWORD"));

		// Set to the password authentication
		t.AuthType = AUTHTYPE_PASSWORD;
		t.AuthData = pw;
	}

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the authentication method for the user to the specific certificate authentication and set a certificate
UINT PsUserCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	X *x;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Read the certificate
	x = FileToXW(GetParamUniStr(o, "LOADCERT"));
	if (x == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));

		FreeParamValueList(o);

		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		FreeX(x);
		return ret;
	}

	// Update the information
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHUSERCERT *c;

		c = NewUserCertAuthData(x);

		FreeX(x);

		// Set to the password authentication
		t.AuthType = AUTHTYPE_USERCERT;
		t.AuthData = c;
	}

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Get certificates that are registered in the user which uses certificate authentication
UINT PsUserCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	AUTHUSERCERT *a;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	a = (AUTHUSERCERT *)t.AuthData;

	if (t.AuthType != AUTHTYPE_USERCERT || a == NULL || a->UserX == NULL)
	{
		// The user is not using specific certificate authentication
		ret = ERR_INVALID_PARAMETER;

		c->Write(c, _UU("CMD_UserCertGet_Not_Cert"));
	}
	else
	{
		if (XToFileW(a->UserX, GetParamUniStr(o, "SAVECERT"), true) == false)
		{
			c->Write(c, _UU("CMD_SAVECERT_FAILED"));
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return ret;
}

// Set the authentication method for the user to the signed certificate authentication
UINT PsUserSignedSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"CN", CmdPrompt, _UU("CMD_UserSignedSet_Prompt_CN"), NULL, NULL},
		{"SERIAL", CmdPrompt, _UU("CMD_UserSignedSet_Prompt_SERIAL"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHROOTCERT *c;
		BUF *b;
		X_SERIAL *serial = NULL;

		b = StrToBin(GetParamStr(o, "SERIAL"));

		if (b != NULL && b->Size >= 1)
		{
			serial = NewXSerial(b->Buf, b->Size);
		}

		FreeBuf(b);

		c = NewRootCertAuthData(serial, GetParamUniStr(o, "CN"));

		FreeXSerial(serial);

		// Set to the signed certificate authentication
		t.AuthType = AUTHTYPE_ROOTCERT;
		t.AuthData = c;
	}

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the authentication method for the user to the Radius authentication
UINT PsUserRadiusSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"ALIAS", CmdPrompt, _UU("CMD_UserRadiusSet_Prompt_ALIAS"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHRADIUS *a;

		a = NewRadiusAuthData(GetParamUniStr(o, "ALIAS"));

		// Set to Radius authentication
		t.AuthType = AUTHTYPE_RADIUS;
		t.AuthData = a;
	}

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the authentication method for the user to the NT domain authentication
UINT PsUserNTLMSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"ALIAS", CmdPrompt, _UU("CMD_UserRadiusSet_Prompt_ALIAS"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	FreeAuthData(t.AuthType, t.AuthData);

	{
		AUTHRADIUS *a;

		a = NewRadiusAuthData(GetParamUniStr(o, "ALIAS"));

		// Set to the NT domain authentication
		t.AuthType = AUTHTYPE_NT;
		t.AuthData = a;
	}

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the security policy of the user
UINT PsUserPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update
	if (t.Policy != NULL)
	{
		Free(t.Policy);
		t.Policy = NULL;
	}

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Set a security policy of the user
UINT PsUserPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update
	if (t.Policy == NULL)
	{
		t.Policy = ClonePolicy(GetDefaultPolicy());
	}

	// Edit
	if (EditPolicy(c, t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), false) == false)
	{
		ret = ERR_INVALID_PARAMETER;
	}
	else
	{
		// Write the user object
		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return ret;
}

// Convert the string to a date and time
UINT64 StrToDateTime64(char *str)
{
	UINT64 ret = 0;
	TOKEN_LIST *t;
	UINT a, b, c, d, e, f;
	// Validate arguments
	if (str == NULL)
	{
		return INFINITE;
	}

	if (IsEmptyStr(str) || StrCmpi(str, "none") == 0)
	{
		return 0;
	}

	t = ParseToken(str, ":/,. \"");
	if (t->NumTokens != 6)
	{
		FreeToken(t);
		return INFINITE;
	}

	a = ToInt(t->Token[0]);
	b = ToInt(t->Token[1]);
	c = ToInt(t->Token[2]);
	d = ToInt(t->Token[3]);
	e = ToInt(t->Token[4]);
	f = ToInt(t->Token[5]);

	ret = INFINITE;

	if (a >= 1000 && a <= 9999 && b >= 1 && b <= 12 && c >= 1 && c <= 31 &&
		d <= 23 && e <= 59 && f <= 59)
	{
		SYSTEMTIME t;

		Zero(&t, sizeof(t));
		t.wYear = a;
		t.wMonth = b;
		t.wDay = c;
		t.wHour = d;
		t.wMinute = e;
		t.wSecond = f;

		ret = SystemToUINT64(&t);
	}

	FreeToken(t);

	return ret;
}

// Evaluate the date and time string
bool CmdEvalDateTime(CONSOLE *c, wchar_t *str, void *param)
{
	UINT64 ret;
	char tmp[MAX_SIZE];
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	ret = StrToDateTime64(tmp);

	if (ret == INFINITE)
	{
		c->Write(c, _UU("CMD_EVAL_DATE_TIME_FAILED"));
		return false;
	}

	return true;
}

// Set the expiration date of the user
UINT PsUserExpiresSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	UINT64 expires;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"EXPIRES", CmdPrompt, _UU("CMD_UserExpiresSet_Prompt_EXPIRES"), CmdEvalDateTime, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	// Get the user object
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Update the information
	expires = StrToDateTime64(GetParamStr(o, "EXPIRES"));

	if (expires != 0)
	{
		expires = LocalToSystem64(expires);
	}

	t.ExpireTime = expires;

	// Write the user object
	ret = ScSetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the group list
UINT PsGroupList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_GROUP t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_GROUPLIST_NAME"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_REALNAME"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_NOTE"), false);
		CtInsertColumn(ct, _UU("SM_GROUPLIST_NUMUSERS"), false);

		for (i = 0;i < t.NumGroup;i++)
		{
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			RPC_ENUM_GROUP_ITEM *e = &t.Groups[i];

			StrToUni(tmp1, sizeof(tmp1), e->Name);
			UniToStru(tmp2, e->NumUsers);

			CtInsert(ct, tmp1, e->Realname, e->Note, tmp2);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// Create a group
UINT PsGroupCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_GroupCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NOTE"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	// RPC call
	ret = ScCreateGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the group information
UINT PsGroupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"REALNAME", CmdPrompt, _UU("CMD_GroupCreate_Prompt_REALNAME"), NULL, NULL},
		{"NOTE", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NOTE"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	// Information update
	UniStrCpy(t.Realname, sizeof(t.Realname), GetParamUniStr(o, "REALNAME"));
	UniStrCpy(t.Note, sizeof(t.Note), GetParamUniStr(o, "NOTE"));

	// RPC call
	ret = ScSetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete a group
UINT PsGroupDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScDeleteGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the group information and the list of users who belong to the group
UINT PsGroupGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		char groupname[MAX_USERNAME_LEN + 1];
		CT *ct = CtNewStandard();

		StrCpy(groupname, sizeof(groupname), t.Name);

		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("CMD_GroupGet_Column_NAME"), tmp);
		CtInsert(ct, _UU("CMD_GroupGet_Column_REALNAME"), t.Realname);
		CtInsert(ct, _UU("CMD_GroupGet_Column_NOTE"), t.Note);

		CtFree(ct, c);

		if (t.Policy != NULL)
		{
			c->Write(c, L"");
			c->Write(c, _UU("CMD_GroupGet_Column_POLICY"));

			PrintPolicy(c, t.Policy, false);
		}

		{
			RPC_ENUM_USER t;
			bool b = false;

			Zero(&t, sizeof(t));

			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

			if (ScEnumUser(ps->Rpc, &t) == ERR_NO_ERROR)
			{
				UINT i;

				for (i = 0;i < t.NumUser;i++)
				{
					RPC_ENUM_USER_ITEM *u = &t.Users[i];

					if (StrCmpi(u->GroupName, groupname) == 0)
					{
						if (b == false)
						{
							b = true;
							c->Write(c, L"");
							c->Write(c, _UU("CMD_GroupGet_Column_MEMBERS"));
						}

						UniFormat(tmp, sizeof(tmp), L" %S", u->Name);
						c->Write(c, tmp);
					}
				}
				FreeRpcEnumUser(&t);

				if (b)
				{
					c->Write(c, L"");
				}
			}
		}

	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// Add an user to the group
UINT PsGroupJoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_GroupJoin_Prompt_USERNAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "USERNAME"));

	// RPC call
	ret = ScGetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Update the Group
		StrCpy(t.GroupName, sizeof(t.GroupName), GetParamStr(o, "[name]"));

		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the user from a group
UINT PsGroupUnjoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupUnjoin_Prompt_name"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScGetUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Update the Group
		StrCpy(t.GroupName, sizeof(t.GroupName), "");

		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the security policy of the group
UINT PsGroupPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Update
		if (t.Policy != NULL)
		{
			Free(t.Policy);
			t.Policy = NULL;
		}

		ret = ScSetGroup(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// Set a security policy to a group
UINT PsGroupPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Update
		if (t.Policy == NULL)
		{
			t.Policy = ClonePolicy(GetDefaultPolicy());
		}

		if (EditPolicy(c, t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), false) == false)
		{
			// An error has occured
			FreeRpcSetGroup(&t);
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ERR_INTERNAL_ERROR;
		}

		ret = ScSetGroup(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the connected session list
UINT PsSessionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_SESSION t;
	UINT server_type = 0;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	{
		// Get the server type
		RPC_SERVER_INFO t;

		Zero(&t, sizeof(t));

		if (ScGetServerInfo(ps->Rpc, &t) == ERR_NO_ERROR)
		{
			server_type = t.ServerType;

			FreeRpcServerInfo(&t);
		}
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumSession(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_8"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_5"), true);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_6"), true);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_7"), true);

		for (i = 0;i < t.NumSession;i++)
		{
			RPC_ENUM_SESSION_ITEM *e = &t.Sessions[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t *tmp2;
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			wchar_t tmp6[MAX_SIZE];
			wchar_t tmp7[MAX_SIZE];
			wchar_t tmp8[MAX_SIZE];
			bool free_tmp2 = false;

			StrToUni(tmp1, sizeof(tmp1), e->Name);

			tmp2 = _UU("SM_SESS_NORMAL");
			if (server_type != SERVER_TYPE_STANDALONE)
			{
				if (e->RemoteSession)
				{
					tmp2 = ZeroMalloc(MAX_SIZE);
					UniFormat(tmp2, MAX_SIZE, _UU("SM_SESS_REMOTE"), e->RemoteHostname);
					free_tmp2 = true;
				}
				else
				{
					if (StrLen(e->RemoteHostname) == 0)
					{
						tmp2 = _UU("SM_SESS_LOCAL");
					}
					else
					{
						tmp2 = ZeroMalloc(MAX_SIZE);
						UniFormat(tmp2, MAX_SIZE, _UU("SM_SESS_LOCAL_2"), e->RemoteHostname);
						free_tmp2 = true;
					}
				}
			}
			if (e->LinkMode)
			{
				if (free_tmp2)
				{
					Free(tmp2);
					free_tmp2 = false;
				}
				tmp2 = _UU("SM_SESS_LINK");
			}
			else if (e->SecureNATMode)
			{
				/*if (free_tmp2)
				{
					Free(tmp2);
					free_tmp2 = false;
				}*/
				tmp2 = _UU("SM_SESS_SNAT");
			}

			StrToUni(tmp3, sizeof(tmp3), e->Username);

			StrToUni(tmp4, sizeof(tmp4), e->Hostname);
			if (e->LinkMode)
			{
				UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_LINK_HOSTNAME"));
			}
			else if (e->SecureNATMode)
			{
				UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_SNAT_HOSTNAME"));
			}
			else if (e->BridgeMode)
			{
				UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_BRIDGE_HOSTNAME"));
			}
			else if (StartWith(e->Username, L3_USERNAME))
			{
				UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_SESS_LAYER3_HOSTNAME"));
			}

			UniFormat(tmp5, sizeof(tmp5), L"%u / %u", e->CurrentNumTcp, e->MaxNumTcp);
			if (e->LinkMode)
			{
				UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_SESS_LINK_TCP"));
			}
			else if (e->SecureNATMode)
			{
				UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_SESS_SNAT_TCP"));
			}
			else if (e->BridgeMode)
			{
				UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_SESS_BRIDGE_TCP"));
			}

			UniToStr3(tmp6, sizeof(tmp6), e->PacketSize);
			UniToStr3(tmp7, sizeof(tmp7), e->PacketNum);

			if (e->VLanId == 0)
			{
				UniStrCpy(tmp8, sizeof(tmp8), _UU("CM_ST_NO_VLAN"));
			}
			else
			{
				UniToStru(tmp8, e->VLanId);
			}

			CtInsert(ct, tmp1, tmp8, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7);

			if (free_tmp2)
			{
				Free(tmp2);
			}
		}


		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumSession(&t);

	FreeParamValueList(o);

	return 0;
}

// Display the NODE_INFO
void CmdPrintNodeInfo(CT *ct, NODE_INFO *info)
{
	wchar_t tmp[MAX_SIZE];
	char str[MAX_SIZE];
	// Validate arguments
	if (ct == NULL || info == NULL)
	{
		return;
	}

	StrToUni(tmp, sizeof(tmp), info->ClientProductName);
	CtInsert(ct, _UU("SM_NODE_CLIENT_NAME"), tmp);

	UniFormat(tmp, sizeof(tmp), L"%u.%02u", Endian32(info->ClientProductVer) / 100, Endian32(info->ClientProductVer) % 100);
	CtInsert(ct, _UU("SM_NODE_CLIENT_VER"), tmp);

	UniFormat(tmp, sizeof(tmp), L"Build %u", Endian32(info->ClientProductBuild));
	CtInsert(ct, _UU("SM_NODE_CLIENT_BUILD"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsName);
	CtInsert(ct, _UU("SM_NODE_CLIENT_OS_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsVer);
	CtInsert(ct, _UU("SM_NODE_CLIENT_OS_VER"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientOsProductId);
	CtInsert(ct, _UU("SM_NODE_CLIENT_OS_PID"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ClientHostname);
	CtInsert(ct, _UU("SM_NODE_CLIENT_HOST"), tmp);

	IPToStr4or6(str, sizeof(str), info->ClientIpAddress, info->ClientIpAddress6);
	StrToUni(tmp, sizeof(tmp), str);
	CtInsert(ct, _UU("SM_NODE_CLIENT_IP"), tmp);

	UniToStru(tmp, Endian32(info->ClientPort));
	CtInsert(ct, _UU("SM_NODE_CLIENT_PORT"), tmp);

	StrToUni(tmp, sizeof(tmp), info->ServerHostname);
	CtInsert(ct, _UU("SM_NODE_SERVER_HOST"), tmp);

	IPToStr4or6(str, sizeof(str), info->ServerIpAddress, info->ServerIpAddress6);
	StrToUni(tmp, sizeof(tmp), str);
	CtInsert(ct, _UU("SM_NODE_SERVER_IP"), tmp);

	UniToStru(tmp, Endian32(info->ServerPort));
	CtInsert(ct, _UU("SM_NODE_SERVER_PORT"), tmp);

	if (StrLen(info->ProxyHostname) != 0)
	{
		StrToUni(tmp, sizeof(tmp), info->ProxyHostname);
		CtInsert(ct, _UU("SM_NODE_PROXY_HOSTNAME"), tmp);

		IPToStr4or6(str, sizeof(str), info->ProxyIpAddress, info->ProxyIpAddress6);
		StrToUni(tmp, sizeof(tmp), str);
		CtInsert(ct, _UU("SM_NODE_PROXY_IP"), tmp);

		UniToStru(tmp, Endian32(info->ProxyPort));
		CtInsert(ct, _UU("SM_NODE_PROXY_PORT"), tmp);
	}
}

// Get the session information
UINT PsSessionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SESSION_STATUS t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_SessionGet_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScGetSessionStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		char str[MAX_SIZE];
		CT *ct = CtNewStandard();

		if (t.ClientIp != 0)
		{
			IPToStr4or6(str, sizeof(str), t.ClientIp, t.ClientIp6);
			StrToUni(tmp, sizeof(tmp), str);
			CtInsert(ct, _UU("SM_CLIENT_IP"), tmp);
		}

		if (StrLen(t.ClientHostName) != 0)
		{
			StrToUni(tmp, sizeof(tmp), t.ClientHostName);
			CtInsert(ct, _UU("SM_CLIENT_HOSTNAME"), tmp);
		}

		StrToUni(tmp, sizeof(tmp), t.Username);
		CtInsert(ct, _UU("SM_SESS_STATUS_USERNAME"), tmp);

		if (StrCmpi(t.Username, LINK_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, SNAT_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, BRIDGE_USER_NAME_PRINT) != 0)
		{
			StrToUni(tmp, sizeof(tmp), t.RealUsername);
			CtInsert(ct, _UU("SM_SESS_STATUS_REALUSER"), tmp);
		}

		if (IsEmptyStr(t.GroupName) == false)
		{
			StrToUni(tmp, sizeof(tmp), t.GroupName);
			CtInsert(ct, _UU("SM_SESS_STATUS_GROUPNAME"), tmp);
		}


		CmdPrintStatusToListViewEx(ct, &t.Status, true);

		if (StrCmpi(t.Username, LINK_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, SNAT_USER_NAME_PRINT) != 0 && StrCmpi(t.Username, BRIDGE_USER_NAME_PRINT) != 0 &&
			StartWith(t.Username, L3_USERNAME) == false)
		{
			CmdPrintNodeInfo(ct, &t.NodeInfo);
		}

		CtFree(ct, c);
	}

	FreeRpcSessionStatus(&t);

	FreeParamValueList(o);

	return 0;
}

// Disconnect the session
UINT PsSessionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_SESSION t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_SessionGet_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	// RPC call
	ret = ScDeleteSession(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the MAC address table database
UINT PsMacTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_MAC_TABLE t;
	UINT i;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[session_name]", NULL, NULL, NULL, NULL,}
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumMacTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		char *session_name = GetParamStr(o, "[session_name]");

		if (IsEmptyStr(session_name))
		{
			session_name = NULL;
		}

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_1A"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_MAC_COLUMN_5"), false);

		for (i = 0;i < t.NumMacTable;i++)
		{
			char str[MAX_SIZE];
			wchar_t tmp0[128];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			wchar_t tmp6[MAX_SIZE];

			RPC_ENUM_MAC_TABLE_ITEM *e = &t.MacTables[i];

			if (session_name == NULL || StrCmpi(e->SessionName, session_name) == 0)
			{
				UniToStru(tmp0, e->Key);

				StrToUni(tmp1, sizeof(tmp1), e->SessionName);

				MacToStr(str, sizeof(str), e->MacAddress);
				StrToUni(tmp2, sizeof(tmp2), str);

				GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

				GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

				if (StrLen(e->RemoteHostname) == 0)
				{
					UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_MACIP_LOCAL"));
				}
				else
				{
					UniFormat(tmp5, sizeof(tmp5), _UU("SM_MACIP_SERVER"), e->RemoteHostname);
				}

				UniToStru(tmp6, e->VlanId);
				if (e->VlanId == 0)
				{
					UniStrCpy(tmp6, sizeof(tmp6), _UU("CM_ST_NONE"));
				}

				CtInsert(ct,
					tmp0, tmp1, tmp6, tmp2, tmp3, tmp4, tmp5);
			}
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumMacTable(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete a MAC address table entry
UINT PsMacDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_TABLE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_MacDelete_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC call
	ret = ScDeleteMacTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the IP address table database
UINT PsIpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_IP_TABLE t;
	UINT i;

	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[session_name]", NULL, NULL, NULL, NULL,}
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumIpTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		char *session_name = GetParamStr(o, "[session_name]");

		if (IsEmptyStr(session_name))
		{
			session_name = NULL;
		}

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_5"), false);

		for (i = 0;i < t.NumIpTable;i++)
		{
			char str[MAX_SIZE];
			wchar_t tmp0[128];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			RPC_ENUM_IP_TABLE_ITEM *e = &t.IpTables[i];

			if (session_name == NULL || StrCmpi(e->SessionName, session_name) == 0)
			{
				UniToStru(tmp0, e->Key);

				StrToUni(tmp1, sizeof(tmp1), e->SessionName);

				if (e->DhcpAllocated == false)
				{
					IPToStr(str, sizeof(str), &e->IpV6);
					StrToUni(tmp2, sizeof(tmp2), str);
				}
				else
				{
					IPToStr(str, sizeof(str), &e->IpV6);
					UniFormat(tmp2, sizeof(tmp2), _UU("SM_MAC_IP_DHCP"), str);
				}

				GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

				GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

				if (StrLen(e->RemoteHostname) == 0)
				{
					UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_MACIP_LOCAL"));
				}
				else
				{
					UniFormat(tmp5, sizeof(tmp5), _UU("SM_MACIP_SERVER"), e->RemoteHostname);
				}

				CtInsert(ct,
					tmp0, tmp1, tmp2, tmp3, tmp4, tmp5);
			}
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumIpTable(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the IP address table entry
UINT PsIpDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_TABLE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_MacDelete_Prompt"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC call
	ret = ScDeleteIpTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Enable the DHCP server function and the virtual NAT (SecureNAT function)
UINT PsSecureNatEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnableSecureNAT(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Disable the DHCP server function and the virtual NAT (SecureNAT function)
UINT PsSecureNatDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScDisableSecureNAT(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the operating status of the DHCP server function and the virtual NAT (SecureNAT function)
UINT PsSecureNatStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_NAT_STATUS t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetSecureNATStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), ps->HubName);
		CtInsert(ct, _UU("SM_HUB_COLUMN_1"), tmp);

		UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_SESSION"), t.NumTcpSessions);
		CtInsert(ct, _UU("NM_STATUS_TCP"), tmp);

		UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_SESSION"), t.NumUdpSessions);
		CtInsert(ct, _UU("NM_STATUS_UDP"), tmp);

		UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_SESSION"), t.NumIcmpSessions);
		CtInsert(ct, _UU("NM_STATUS_ICMP"), tmp);

		UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_SESSION"), t.NumDnsSessions);
		CtInsert(ct, _UU("NM_STATUS_DNS"), tmp);

		UniFormat(tmp, sizeof(tmp), _UU("SM_SNAT_NUM_CLIENT"), t.NumDhcpClients);
		CtInsert(ct, _UU("NM_STATUS_DHCP"), tmp);

		CtInsert(ct, _UU("SM_SNAT_IS_KERNEL"), t.IsKernelMode ? _UU("SEC_YES") : _UU("SEC_NO"));
		CtInsert(ct, _UU("SM_SNAT_IS_RAW"), t.IsRawIpMode ? _UU("SEC_YES") : _UU("SEC_NO"));

		CtFree(ct, c);
	}

	FreeRpcNatStatus(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the network interface settings for a virtual host of SecureNAT function
UINT PsSecureNatHostGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		char str[MAX_SIZE];
		CT *ct = CtNewStandard();

		// Flags
		// MAC Address
		MacToStr(str, sizeof(str), t.MacAddress);
		StrToUni(tmp, sizeof(tmp), str);
		CtInsert(ct, _UU("CMD_SecureNatHostGet_Column_MAC"), tmp);

		// IP address
		IPToUniStr(tmp, sizeof(tmp), &t.Ip);
		CtInsert(ct, _UU("CMD_SecureNatHostGet_Column_IP"), tmp);

		// Subnet mask
		IPToUniStr(tmp, sizeof(tmp), &t.Mask);
		CtInsert(ct, _UU("CMD_SecureNatHostGet_Column_MASK"), tmp);

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Change the network interface settings for a virtual host of SecureNAT function
UINT PsSecureNatHostSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"MAC", CmdPrompt, _UU("CMD_SecureNatHostSet_Prompt_MAC"), NULL, NULL},
		{"IP", CmdPrompt, _UU("CMD_SecureNatHostSet_Prompt_IP"), CmdEvalIp, NULL},
		{"MASK", CmdPrompt, _UU("CMD_SecureNatHostSet_Prompt_MASK"), CmdEvalIp, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *mac, *ip, *mask;
		bool ok = true;

		StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

		mac = GetParamStr(o, "MAC");
		ip = GetParamStr(o, "IP");
		mask = GetParamStr(o, "MASK");

		if (IsEmptyStr(mac) == false)
		{
			BUF *b = StrToBin(mac);

			if (b == NULL || b->Size != 6)
			{
				ok = false;
			}
			else
			{
				Copy(t.MacAddress, b->Buf, 6);
			}

			FreeBuf(b);
		}

		if (IsEmptyStr(ip) == false)
		{
			if (IsIpStr4(ip) == false)
			{
				ok = false;
			}
			else
			{
				UINT u = StrToIP32(ip);

				if (u == 0 || u == 0xffffffff)
				{
					ok = false;
				}
				else
				{
					UINTToIP(&t.Ip, u);
				}
			}
		}

		if (IsEmptyStr(mask) == false)
		{
			if (IsIpStr4(mask) == false)
			{
				ok = false;
			}
			else
			{
				StrToIP(&t.Mask, mask);
			}
		}

		if (ok == false)
		{
			// Parameter is invalid
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
		else
		{
			ret = ScSetSecureNATOption(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// An error has occured
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Get the settings for the virtual NAT function of the SecureNAT function
UINT PsNatGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		// Use the virtual NAT function
		CtInsert(ct, _UU("CMD_NatGet_Column_USE"), t.UseNat ? _UU("SEC_YES") : _UU("SEC_NO"));

		// MTU value
		UniToStru(tmp, t.Mtu);
		CtInsert(ct, _UU("CMD_NetGet_Column_MTU"), tmp);

		// TCP session timeout (in seconds)
		UniToStru(tmp, t.NatTcpTimeout);
		CtInsert(ct, _UU("CMD_NatGet_Column_TCP"), tmp);

		// UDP session timeout (in seconds)
		UniToStru(tmp, t.NatUdpTimeout);
		CtInsert(ct, _UU("CMD_NatGet_Column_UDP"), tmp);

		// To save the log
		CtInsert(ct, _UU("CMD_SecureNatHostGet_Column_LOG"), t.SaveLog ? _UU("SEC_YES") : _UU("SEC_NO"));

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Enable the virtual NAT function of the SecureNAT function
UINT PsNatEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.UseNat = true;

		StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
		ret = ScSetSecureNATOption(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Disable the virtual NAT function of the SecureNAT function
UINT PsNatDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.UseNat = false;

		StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
		ret = ScSetSecureNATOption(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Change the settings for the virtual NAT function of the SecureNAT function
UINT PsNatSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX mtu_mm =
	{
		"CMD_NatSet_Eval_MTU", TCP_HEADER_SIZE + IP_HEADER_SIZE + MAC_HEADER_SIZE + 8, MAX_L3_DATA_SIZE,
	};
	CMD_EVAL_MIN_MAX tcp_mm =
	{
		"CMD_NatSet_Eval_TCP", NAT_TCP_MIN_TIMEOUT / 1000, NAT_TCP_MAX_TIMEOUT / 1000,
	};
	CMD_EVAL_MIN_MAX udp_mm =
	{
		"CMD_NatSet_Eval_UDP", NAT_UDP_MIN_TIMEOUT / 1000, NAT_UDP_MAX_TIMEOUT / 1000,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"MTU", CmdPrompt, _UU("CMD_NatSet_Prompt_MTU"), CmdEvalMinMax, &mtu_mm},
		{"TCPTIMEOUT", CmdPrompt, _UU("CMD_NatSet_Prompt_TCPTIMEOUT"), CmdEvalMinMax, &tcp_mm},
		{"UDPTIMEOUT", CmdPrompt, _UU("CMD_NatSet_Prompt_UDPTIMEOUT"), CmdEvalMinMax, &udp_mm},
		{"LOG", CmdPrompt, _UU("CMD_NatSet_Prompt_LOG"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.Mtu = GetParamInt(o, "MTU");
		t.NatTcpTimeout = GetParamInt(o, "TCPTIMEOUT");
		t.NatUdpTimeout = GetParamInt(o, "UDPTIMEOUT");
		t.SaveLog = GetParamYes(o, "LOG");

		StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
		ret = ScSetSecureNATOption(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Get the session table of the virtual NAT function of the SecureNAT function
UINT PsNatTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_NAT t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumNAT(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("NM_NAT_ID"), false);
		CtInsertColumn(ct, _UU("NM_NAT_PROTOCOL"), false);
		CtInsertColumn(ct, _UU("NM_NAT_SRC_HOST"), false);
		CtInsertColumn(ct, _UU("NM_NAT_SRC_PORT"), false);
		CtInsertColumn(ct, _UU("NM_NAT_DST_HOST"), false);
		CtInsertColumn(ct, _UU("NM_NAT_DST_PORT"), false);
		CtInsertColumn(ct, _UU("NM_NAT_CREATED"), false);
		CtInsertColumn(ct, _UU("NM_NAT_LAST_COMM"), false);
		CtInsertColumn(ct, _UU("NM_NAT_SIZE"), false);
		CtInsertColumn(ct, _UU("NM_NAT_TCP_STATUS"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_ENUM_NAT_ITEM *e = &t.Items[i];
			wchar_t tmp0[MAX_SIZE];
			wchar_t *tmp1 = L"";
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			wchar_t tmp6[MAX_SIZE];
			wchar_t tmp7[MAX_SIZE];
			wchar_t tmp8[MAX_SIZE];
			wchar_t *tmp9 = L"";
			char v1[128], v2[128];

			// ID
			UniToStru(tmp0, e->Id);

			// Protocol
			switch (e->Protocol)
			{
			case NAT_TCP:
				tmp1 = _UU("NM_NAT_PROTO_TCP");
				break;
			case NAT_UDP:
				tmp1 = _UU("NM_NAT_PROTO_UDP");
				break;
			case NAT_DNS:
				tmp1 = _UU("NM_NAT_PROTO_DNS");
				break;
			case NAT_ICMP:
				tmp1 = _UU("NM_NAT_PROTO_ICMP");
				break;
			}

			// Source host
			StrToUni(tmp2, sizeof(tmp2), e->SrcHost);

			// Source port
			UniToStru(tmp3, e->SrcPort);

			// Destination host
			StrToUni(tmp4, sizeof(tmp4), e->DestHost);

			// Destination port
			UniToStru(tmp5, e->DestPort);

			// Creation date and time of the session
			GetDateTimeStrEx64(tmp6, sizeof(tmp6), SystemToLocal64(e->CreatedTime), NULL);

			// Last communication date and time
			GetDateTimeStrEx64(tmp7, sizeof(tmp7), SystemToLocal64(e->LastCommTime), NULL);

			// Communication amount
			ToStr3(v1, sizeof(v1), e->RecvSize);
			ToStr3(v2, sizeof(v2), e->SendSize);
			UniFormat(tmp8, sizeof(tmp8), L"%S / %S", v1, v2);

			// TCP state
			if (e->Protocol == NAT_TCP)
			{
				switch (e->TcpStatus)
				{
				case NAT_TCP_CONNECTING:
					tmp9 = _UU("NAT_TCP_CONNECTING");
					break;
				case NAT_TCP_SEND_RESET:
					tmp9 = _UU("NAT_TCP_SEND_RESET");
					break;
				case NAT_TCP_CONNECTED:
					tmp9 = _UU("NAT_TCP_CONNECTED");
					break;
				case NAT_TCP_ESTABLISHED:
					tmp9 = _UU("NAT_TCP_ESTABLISHED");
					break;
				case NAT_TCP_WAIT_DISCONNECT:
					tmp9 = _UU("NAT_TCP_WAIT_DISCONNECT");
					break;
				}
			}

			CtInsert(ct,
				tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumNat(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the settings for a virtual DHCP server function of the SecureNAT function
UINT PsDhcpGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		// To use the virtual DHCP function
		CtInsert(ct, _UU("CMD_DhcpGet_Column_USE"), t.UseDhcp ? _UU("SEC_YES") : _UU("SEC_NO"));

		// Start address of the distributing address zone
		IPToUniStr(tmp, sizeof(tmp), &t.DhcpLeaseIPStart);
		CtInsert(ct, _UU("CMD_DhcpGet_Column_IP1"), tmp);

		// End address of the distributing address zone
		IPToUniStr(tmp, sizeof(tmp), &t.DhcpLeaseIPEnd);
		CtInsert(ct, _UU("CMD_DhcpGet_Column_IP2"), tmp);

		// Subnet mask
		IPToUniStr(tmp, sizeof(tmp), &t.DhcpSubnetMask);
		CtInsert(ct, _UU("CMD_DhcpGet_Column_MASK"), tmp);

		// Lease time (in seconds)
		UniToStru(tmp, t.DhcpExpireTimeSpan);
		CtInsert(ct, _UU("CMD_DhcpGet_Column_LEASE"), tmp);

		// Default gateway address
		UniStrCpy(tmp, sizeof(tmp), _UU("SEC_NONE"));
		if (IPToUINT(&t.DhcpGatewayAddress) != 0)
		{
			IPToUniStr(tmp, sizeof(tmp), &t.DhcpGatewayAddress);
		}
		CtInsert(ct, _UU("CMD_DhcpGet_Column_GW"), tmp);

		// DNS server address 1
		UniStrCpy(tmp, sizeof(tmp), _UU("SEC_NONE"));
		if (IPToUINT(&t.DhcpDnsServerAddress) != 0)
		{
			IPToUniStr(tmp, sizeof(tmp), &t.DhcpDnsServerAddress);
		}
		CtInsert(ct, _UU("CMD_DhcpGet_Column_DNS"), tmp);

		// DNS server address 2
		UniStrCpy(tmp, sizeof(tmp), _UU("SEC_NONE"));
		if (IPToUINT(&t.DhcpDnsServerAddress2) != 0)
		{
			IPToUniStr(tmp, sizeof(tmp), &t.DhcpDnsServerAddress2);
		}
		CtInsert(ct, _UU("CMD_DhcpGet_Column_DNS2"), tmp);

		// Domain name
		StrToUni(tmp, sizeof(tmp), t.DhcpDomainName);
		CtInsert(ct, _UU("CMD_DhcpGet_Column_DOMAIN"), tmp);

		// To save the log
		CtInsert(ct, _UU("CMD_SecureNatHostGet_Column_LOG"), t.SaveLog ? _UU("SEC_YES") : _UU("SEC_NO"));

		// Push routing table
		if (t.ApplyDhcpPushRoutes)
		{
			StrToUni(tmp, sizeof(tmp), t.DhcpPushRoutes);
			CtInsert(ct, _UU("CMD_DhcpGet_Column_PUSHROUTE"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Enable the Virtual DHCP server function of SecureNAT function
UINT PsDhcpEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.UseDhcp = true;

		StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
		ret = ScSetSecureNATOption(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Disable the virtual DHCP server function of SecureNAT function
UINT PsDhcpDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.UseDhcp = false;

		ret = ScSetSecureNATOption(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Change the settings for a virtual DHCP server function of the SecureNAT function
UINT PsDhcpSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	VH_OPTION t;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX mm =
	{
		"CMD_NatSet_Eval_UDP", NAT_UDP_MIN_TIMEOUT / 1000, NAT_UDP_MAX_TIMEOUT / 1000,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"START", CmdPrompt, _UU("CMD_DhcpSet_Prompt_START"), CmdEvalIp, NULL},
		{"END", CmdPrompt, _UU("CMD_DhcpSet_Prompt_END"), CmdEvalIp, NULL},
		{"MASK", CmdPrompt, _UU("CMD_DhcpSet_Prompt_MASK"), CmdEvalIp, NULL},
		{"EXPIRE", CmdPrompt, _UU("CMD_DhcpSet_Prompt_EXPIRE"), CmdEvalMinMax, &mm},
		{"GW", CmdPrompt, _UU("CMD_DhcpSet_Prompt_GW"), CmdEvalIp, NULL},
		{"DNS", CmdPrompt, _UU("CMD_DhcpSet_Prompt_DNS"), CmdEvalIp, NULL},
		{"DNS2", CmdPrompt, _UU("CMD_DhcpSet_Prompt_DNS2"), CmdEvalIp, NULL},
		{"DOMAIN", CmdPrompt, _UU("CMD_DhcpSet_Prompt_DOMAIN"), NULL, NULL},
		{"LOG", CmdPrompt, _UU("CMD_NatSet_Prompt_LOG"), CmdEvalNotEmpty, NULL},
		{"PUSHROUTE", NULL, _UU("CMD_DhcpSet_PUSHROUTE"), NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetSecureNATOption(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{

		StrToIP(&t.DhcpLeaseIPStart, GetParamStr(o, "START"));
		StrToIP(&t.DhcpLeaseIPEnd, GetParamStr(o, "END"));
		StrToIP(&t.DhcpSubnetMask, GetParamStr(o, "MASK"));
		t.DhcpExpireTimeSpan = GetParamInt(o, "EXPIRE");
		StrToIP(&t.DhcpGatewayAddress, GetParamStr(o, "GW"));
		StrToIP(&t.DhcpDnsServerAddress, GetParamStr(o, "DNS"));
		StrToIP(&t.DhcpDnsServerAddress2, GetParamStr(o, "DNS2"));
		StrCpy(t.DhcpDomainName, sizeof(t.DhcpDomainName), GetParamStr(o, "DOMAIN"));
		t.SaveLog = GetParamYes(o, "LOG");

		StrCpy(t.DhcpPushRoutes, sizeof(t.DhcpPushRoutes), GetParamStr(o, "PUSHROUTE"));
		t.ApplyDhcpPushRoutes = true;

		StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
		ret = ScSetSecureNATOption(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		if (IsEmptyStr(GetParamStr(o, "PUSHROUTE")) == false)
		{
			if (GetCapsBool(ps->CapsList, "b_suppport_push_route") == false &&
				GetCapsBool(ps->CapsList, "b_suppport_push_route_config"))
			{
				CmdPrintError(c, ERR_NOT_SUPPORTED_FUNCTION_ON_OPENSOURCE);
			}
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Get the lease table of virtual DHCP server function of the SecureNAT function
UINT PsDhcpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_DHCP t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumDHCP(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("DHCP_DHCP_ID"), false);
		CtInsertColumn(ct, _UU("DHCP_LEASED_TIME"), false);
		CtInsertColumn(ct, _UU("DHCP_EXPIRE_TIME"), false);
		CtInsertColumn(ct, _UU("DHCP_MAC_ADDRESS"), false);
		CtInsertColumn(ct, _UU("DHCP_IP_ADDRESS"), false);
		CtInsertColumn(ct, _UU("DHCP_HOSTNAME"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_ENUM_DHCP_ITEM *e = &t.Items[i];
			wchar_t tmp0[MAX_SIZE];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			char str[MAX_SIZE];

			// ID
			UniToStru(tmp0, e->Id);

			// Time
			GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(e->LeasedTime), NULL);
			GetDateTimeStrEx64(tmp2, sizeof(tmp2), SystemToLocal64(e->ExpireTime), NULL);

			MacToStr(str, sizeof(str), e->MacAddress);
			StrToUni(tmp3, sizeof(tmp3), str);

			IPToStr32(str, sizeof(str), e->IpAddress);
			StrToUni(tmp4, sizeof(tmp4), str);

			StrToUni(tmp5, sizeof(tmp5), e->Hostname);

			CtInsert(ct,
				tmp0, tmp1, tmp2, tmp3, tmp4, tmp5);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumDhcp(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the list of Virtual HUB management options
UINT PsAdminOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubAdminOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandardEx();
		UINT i;

		for (i = 0;i < t.NumItem;i++)
		{
			ADMIN_OPTION *e = &t.Items[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];

			StrToUni(tmp1, sizeof(tmp1), e->Name);
			UniToStru(tmp2, e->Value);

			CtInsert(ct, tmp1, tmp2, GetHubAdminOptionHelpString(e->Name));
				
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the value of a Virtual HUB management option
UINT PsAdminOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_name"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_VALUE"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubAdminOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;

		for (i = 0;i < t.NumItem;i++)
		{
			if (StrCmpi(t.Items[i].Name, GetParamStr(o, "[name]")) == 0)
			{
				t.Items[i].Value = GetParamInt(o, "VALUE");
				b = true;
			}
		}

		if (b == false)
		{
			// An error has occured
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcAdminOption(&t);
			return ret;
		}
		else
		{
			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
			ret = ScSetHubAdminOptions(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// An error has occured
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the list of Virtual HUB extended options
UINT PsExtOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubExtOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandardEx();
		UINT i;

		for (i = 0;i < t.NumItem;i++)
		{
			ADMIN_OPTION *e = &t.Items[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];

			StrToUni(tmp1, sizeof(tmp1), e->Name);
			UniToStru(tmp2, e->Value);

			CtInsert(ct, tmp1, tmp2, GetHubAdminOptionHelpString(e->Name));

		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

// Set the value of a Virtual HUB extended option
UINT PsExtOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADMIN_OPTION t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[name]", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_name"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_AdminOptionSet_Prompt_VALUE"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetHubExtOptions(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		bool b = false;

		for (i = 0;i < t.NumItem;i++)
		{
			if (StrCmpi(t.Items[i].Name, GetParamStr(o, "[name]")) == 0)
			{
				t.Items[i].Value = GetParamInt(o, "VALUE");
				b = true;
			}
		}

		if (b == false)
		{
			// An error has occured
			ret = ERR_OBJECT_NOT_FOUND;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			FreeRpcAdminOption(&t);
			return ret;
		}
		else
		{
			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
			ret = ScSetHubExtOptions(ps->Rpc, &t);

			if (ret != ERR_NO_ERROR)
			{
				// An error has occured
				CmdPrintError(c, ret);
				FreeParamValueList(o);
				return ret;
			}
		}
	}

	FreeRpcAdminOption(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the list of revoked certificate list
UINT PsCrlList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_CRL t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_CRL_COLUMN_1"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			wchar_t tmp[64];
			RPC_ENUM_CRL_ITEM *e = &t.Items[i];

			UniToStru(tmp, e->Key);
			CtInsert(ct, tmp, e->CrlInfo);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumCrl(&t);

	FreeParamValueList(o);

	return 0;
}

// Add a revoked certificate
UINT PsCrlAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		{"SERIAL", NULL, NULL, NULL, NULL},
		{"MD5", NULL, NULL, NULL, NULL},
		{"SHA1", NULL, NULL, NULL, NULL},
		{"CN", NULL, NULL, NULL, NULL},
		{"O", NULL, NULL, NULL, NULL},
		{"OU", NULL, NULL, NULL, NULL},
		{"C", NULL, NULL, NULL, NULL},
		{"ST", NULL, NULL, NULL, NULL},
		{"L", NULL, NULL, NULL, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	{
		bool param_exists = false;
		CRL *crl = ZeroMalloc(sizeof(CRL));
		NAME *n;
		n = crl->Name = ZeroMalloc(sizeof(NAME));

		if (IsEmptyStr(GetParamStr(o, "CN")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "CN"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "O")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "O"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "OU")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "OU"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "C")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "C"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "ST")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "ST"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "L")) == false)
		{
			n->CommonName = CopyUniStr(GetParamUniStr(o, "L"));
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "SERIAL")) == false)
		{
			BUF *b;

			b = StrToBin(GetParamStr(o, "SERIAL"));

			if (b != NULL && b->Size >= 1)
			{
				crl->Serial = NewXSerial(b->Buf, b->Size);
				param_exists = true;
			}

			FreeBuf(b);
		}

		if (IsEmptyStr(GetParamStr(o, "MD5")) == false)
		{
			BUF *b;

			b = StrToBin(GetParamStr(o, "MD5"));

			if (b != NULL && b->Size == MD5_SIZE)
			{
				Copy(crl->DigestMD5, b->Buf, MD5_SIZE);
				param_exists = true;
			}

			FreeBuf(b);
		}

		if (IsEmptyStr(GetParamStr(o, "SHA1")) == false)
		{
			BUF *b;

			b = StrToBin(GetParamStr(o, "SHA1"));

			if (b != NULL && b->Size == SHA1_SIZE)
			{
				Copy(crl->DigestSHA1, b->Buf, SHA1_SIZE);
				param_exists = true;
			}

			FreeBuf(b);
		}

		t.Crl = crl;

		if (param_exists == false)
		{
			FreeRpcCrl(&t);
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	// RPC call
	ret = ScAddCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the revoked certificate
UINT PsCrlDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CrlDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC call
	ret = ScDelCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the revoked certificate
UINT PsCrlGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_CrlGet_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	// RPC call
	ret = ScGetCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Show contents
		CT *ct = CtNewStandard();
		CRL *crl = t.Crl;
		NAME *n;

		if (crl != NULL)
		{
			n = crl->Name;

			if (n != NULL)
			{
				if (UniIsEmptyStr(n->CommonName) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_CN"), n->CommonName);
				}
				if (UniIsEmptyStr(n->Organization) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_O"), n->Organization);
				}
				if (UniIsEmptyStr(n->Unit) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_OU"), n->Unit);
				}
				if (UniIsEmptyStr(n->Country) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_C"), n->Country);
				}
				if (UniIsEmptyStr(n->State) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_ST"), n->State);
				}
				if (UniIsEmptyStr(n->Local) == false)
				{
					CtInsert(ct, _UU("CMD_CrlGet_L"), n->Local);
				}
			}

			if (crl->Serial != NULL && crl->Serial->size >= 1)
			{
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->Serial->data, crl->Serial->size);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_SERI"), tmp);
			}

			if (IsZero(crl->DigestMD5, MD5_SIZE) == false)
			{
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->DigestMD5, MD5_SIZE);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_MD5_HASH"), tmp);
			}

			if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false)
			{
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->DigestSHA1, SHA1_SIZE);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_SHA1_HASH"), tmp);
			}
		}
		CtFree(ct, c);
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the rules of IP access control list
UINT PsAcList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct;

		ct = CtNew();
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_1"), true);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_2"), true);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_AC_COLUMN_4"), false);

		for (i = 0;i < LIST_NUM(t.o);i++)
		{
			wchar_t tmp1[32], *tmp2, tmp3[MAX_SIZE], tmp4[32];
			char *tmp_str;
			AC *ac = LIST_DATA(t.o, i);

			UniToStru(tmp1, ac->Id);
			tmp2 = ac->Deny ? _UU("SM_AC_DENY") : _UU("SM_AC_PASS");
			tmp_str = GenerateAcStr(ac);
			StrToUni(tmp3, sizeof(tmp3), tmp_str);

			Free(tmp_str);

			UniToStru(tmp4, ac->Priority);

			CtInsert(ct, tmp1, tmp4, tmp2, tmp3);
		}

		CtFree(ct, c);
	}

	FreeRpcAcList(&t);

	FreeParamValueList(o);

	return 0;
}

// Add a rule to the IP access control list (IPv4)
UINT PsAcAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX mm =
	{
		"CMD_AcAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[allow|deny]", CmdPrompt, _UU("CMD_AcAdd_Prompt_AD"), CmdEvalNotEmpty, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AcAdd_Prompt_PRIORITY"), CmdEvalMinMax, &mm},
		{"IP", CmdPrompt, _UU("CMD_AcAdd_Prompt_IP"), CmdEvalIpAndMask4, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Add a new item to the list
		AC *ac = ZeroMalloc(sizeof(AC));
		char *test = GetParamStr(o, "[allow|deny]");
		UINT u_ip, u_mask;

		if (StartWith("deny", test))
		{
			ac->Deny = true;
		}

		ParseIpAndMask4(GetParamStr(o, "IP"), &u_ip, &u_mask);
		UINTToIP(&ac->IpAddress, u_ip);

		if (u_mask == 0xffffffff)
		{
			ac->Masked = false;
		}
		else
		{
			ac->Masked = true;
			UINTToIP(&ac->SubnetMask, u_mask);
		}

		ac->Priority = GetParamInt(o, "PRIORITY");

		Insert(t.o, ac);

		ret = ScSetAcList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);

	FreeParamValueList(o);

	return 0;
}

// Add a rule to the IP access control list (IPv6)
UINT PsAcAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX mm =
	{
		"CMD_AcAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[allow|deny]", CmdPrompt, _UU("CMD_AcAdd6_Prompt_AD"), CmdEvalNotEmpty, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AcAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &mm},
		{"IP", CmdPrompt, _UU("CMD_AcAdd6_Prompt_IP"), CmdEvalIpAndMask6, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Add a new item to the list
		AC *ac = ZeroMalloc(sizeof(AC));
		char *test = GetParamStr(o, "[allow|deny]");
		IP u_ip, u_mask;

		if (StartWith("deny", test))
		{
			ac->Deny = true;
		}

		ParseIpAndMask6(GetParamStr(o, "IP"), &u_ip, &u_mask);
		Copy(&ac->IpAddress, &u_ip, sizeof(IP));

		if (SubnetMaskToInt6(&u_mask) == 128)
		{
			ac->Masked = false;
		}
		else
		{
			ac->Masked = true;
			Copy(&ac->SubnetMask, &u_mask, sizeof(IP));
		}

		ac->Priority = GetParamInt(o, "PRIORITY");

		Insert(t.o, ac);

		ret = ScSetAcList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);

	FreeParamValueList(o);

	return 0;
}

// Run the debug command
UINT PsDebug(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT id;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", NULL, NULL, NULL, NULL},
		{"ARG", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	id = GetParamInt(o, "[id]");

	if (true)
	{
		RPC_TEST t;
		UINT ret;

		c->Write(c, _UU("CMD_Debug_Msg1"));

		Zero(&t, sizeof(t));

		t.IntValue = id;
		StrCpy(t.StrValue, sizeof(t.StrValue), GetParamStr(o, "ARG"));

		ret = ScDebug(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
		else
		{
			wchar_t tmp[sizeof(t.StrValue)];

			UniFormat(tmp, sizeof(tmp), _UU("CMD_Debug_Msg2"), t.StrValue);
			c->Write(c, tmp);
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Flush the configuration file on the server
UINT PsFlush(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (true)
	{
		RPC_TEST t;
		UINT ret;
		wchar_t tmp[MAX_SIZE];
		char sizestr[MAX_SIZE];

		c->Write(c, _UU("CMD_Flush_Msg1"));

		Zero(&t, sizeof(t));

		ret = ScFlush(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		ToStr3(sizestr, sizeof(sizestr), (UINT64)t.IntValue);
		UniFormat(tmp, sizeof(tmp), _UU("CMD_Flush_Msg2"), sizestr);
		c->Write(c, tmp);
	}

	FreeParamValueList(o);

	return 0;
}

// Crash
UINT PsCrash(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	char *yes;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[yes]", CmdPrompt, _UU("CMD_Crash_Confirm"), NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	yes = GetParamStr(o, "[yes]");

	if (StrCmpi(yes, "yes") != 0)
	{
		c->Write(c, _UU("CMD_Crash_Aborted"));
	}
	else
	{
		RPC_TEST t;
		UINT ret;

		c->Write(c, _UU("CMD_Crash_Msg"));

		Zero(&t, sizeof(t));

		ret = ScCrash(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

// Remove a rule in the IP access control list
UINT PsAcDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_AcDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	// If virtual HUB is not selected, it's an error
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Remove matched ID
		UINT i;
		bool b = false;

		for (i = 0;i < LIST_NUM(t.o);i++)
		{
			AC *ac = LIST_DATA(t.o, i);

			if (ac->Id == GetParamInt(o, "[id]"))
			{
				Delete(t.o, ac);
				Free(ac);
				b = true;
				break;
			}
		}

		if (b == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
			FreeRpcAcList(&t);
		}
		else
		{
			ret = ScSetAcList(ps->Rpc, &t);
		}
		if (ret != ERR_NO_ERROR)
		{
			// An error has occured
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);
	FreeParamValueList(o);

	return 0;
}

// Enable / Disable the IPsec VPN server function
UINT PsIPsecEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	IPSEC_SERVICES t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"L2TP", CmdPrompt, _UU("CMD_IPsecEnable_Prompt_L2TP"), CmdEvalNotEmpty, NULL},
		{"L2TPRAW", CmdPrompt, _UU("CMD_IPsecEnable_Prompt_L2TPRAW"), CmdEvalNotEmpty, NULL},
		{"ETHERIP", CmdPrompt, _UU("CMD_IPsecEnable_Prompt_ETHERIP"), CmdEvalNotEmpty, NULL},
		{"PSK", CmdPrompt, _UU("CMD_IPsecEnable_Prompt_PSK"), CmdEvalNotEmpty, NULL},
		{"DEFAULTHUB", CmdPrompt, _UU("CMD_IPsecEnable_Prompt_DEFAULTHUB"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.L2TP_IPsec = GetParamYes(o, "L2TP");
	t.L2TP_Raw = GetParamYes(o, "L2TPRAW");
	t.EtherIP_IPsec = GetParamYes(o, "ETHERIP");
	StrCpy(t.IPsec_Secret, sizeof(t.IPsec_Secret), GetParamStr(o, "PSK"));
	StrCpy(t.L2TP_DefaultHub, sizeof(t.L2TP_DefaultHub), GetParamStr(o, "DEFAULTHUB"));

	// RPC call
	ret = ScSetIPsecServices(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the current configuration of IPsec VPN server function
UINT PsIPsecGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	IPSEC_SERVICES t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetIPsecServices(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_PATH];
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_IPsecGet_PRINT_L2TP"), _UU(t.L2TP_IPsec ? "SEC_YES" : "SEC_NO"));
		CtInsert(ct, _UU("CMD_IPsecGet_PRINT_L2TPRAW"), _UU(t.L2TP_Raw ? "SEC_YES" : "SEC_NO"));
		CtInsert(ct, _UU("CMD_IPsecGet_PRINT_ETHERIP"), _UU(t.EtherIP_IPsec ? "SEC_YES" : "SEC_NO"));

		StrToUni(tmp, sizeof(tmp), t.IPsec_Secret);
		CtInsert(ct, _UU("CMD_IPsecGet_PRINT_PSK"), tmp);

		StrToUni(tmp, sizeof(tmp), t.L2TP_DefaultHub);
		CtInsert(ct, _UU("CMD_IPsecGet_PRINT_DEFAULTHUB"), tmp);

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Add connection settings for accepting connections from client devices of EtherIP / L2TPv3 over IPsec server function
UINT PsEtherIpClientAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	ETHERIP_ID t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[ID]", CmdPrompt, _UU("CMD_EtherIpClientAdd_Prompt_ID"), CmdEvalNotEmpty, NULL},
		{"HUB", CmdPrompt, _UU("CMD_EtherIpClientAdd_Prompt_HUB"), CmdEvalNotEmpty, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_EtherIpClientAdd_Prompt_USERNAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPrompt, _UU("CMD_EtherIpClientAdd_Prompt_PASSWORD"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.Id, sizeof(t.Id), GetParamStr(o, "[ID]"));
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "HUB"));
	StrCpy(t.UserName, sizeof(t.UserName), GetParamStr(o, "USERNAME"));
	StrCpy(t.Password, sizeof(t.Password), GetParamStr(o, "PASSWORD"));

	// RPC call
	ret = ScAddEtherIpId(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Delete the connection settings for accepting connections from client devices of EtherIP / L2TPv3 over IPsec server function
UINT PsEtherIpClientDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	ETHERIP_ID t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[ID]", CmdPrompt, _UU("CMD_EtherIpClientDelete_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.Id, sizeof(t.Id), GetParamStr(o, "[ID]"));

	// RPC call
	ret = ScDeleteEtherIpId(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Show the list of connection settings for accepting connections from client devices of EtherIP / L2TPv3 over IPsec server function
UINT PsEtherIpClientList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ETHERIP_ID t;
	UINT i;
	CT *b;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumEtherIpId(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		b = CtNew();

		CtInsertColumn(b, _UU("SM_ETHERIP_COLUMN_0"), false);
		CtInsertColumn(b, _UU("SM_ETHERIP_COLUMN_1"), false);
		CtInsertColumn(b, _UU("SM_ETHERIP_COLUMN_2"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			ETHERIP_ID *d = &t.IdList[i];
			wchar_t id[MAX_SIZE], hubname[MAX_SIZE], username[MAX_SIZE];

			StrToUni(id, sizeof(id), d->Id);
			StrToUni(hubname, sizeof(hubname), d->HubName);
			StrToUni(username, sizeof(username), d->UserName);

			CtInsert(b, id, hubname, username);
		}

		CtFree(b, c);

		FreeRpcEnumEtherIpId(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Generate a OpenVPN sample configuration file that can connect to the OpenVPN compatible server function
UINT PsOpenVpnMakeConfig(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_READ_LOG_FILE t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[ZIP_FileName]", CmdPrompt, _UU("CMD_OpenVpnMakeConfig_Prompt_ZIP"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScMakeOpenVpnConfigFile(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		// Determine the file name to save
		wchar_t filename[MAX_SIZE];
		wchar_t tmp[MAX_SIZE];

		UniStrCpy(filename, sizeof(filename), GetParamUniStr(o, "[ZIP_FileName]"));

		if (UniEndWith(filename, L".zip") == false)
		{
			UniStrCat(filename, sizeof(filename), L".zip");
		}

		if (DumpBufW(t.Buffer, filename) == false)
		{
			ret = ERR_INTERNAL_ERROR;

			UniFormat(tmp, sizeof(tmp), _UU("CMD_OpenVpnMakeConfig_ERROR"), filename);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("CMD_OpenVpnMakeConfig_OK"), filename);
		}

		c->Write(c, tmp);

		FreeRpcReadLogFile(&t);
	}

	FreeParamValueList(o);

	return ret;
}

// Register to the VPN Server by creating a new self-signed certificate with the specified CN (Common Name)
UINT PsServerCertRegenerate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[CN]", CmdPrompt, _UU("CMD_ServerCertRegenerate_Prompt_CN"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.StrValue, sizeof(t.StrValue), GetParamStr(o, "[CN]"));

	// RPC call
	ret = ScRegenerateServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	c->Write(c, L"");
	c->Write(c, _UU("CM_CERT_SET_MSG"));
	c->Write(c, L"");

	FreeParamValueList(o);

	return 0;
}

// Enable / disable the VPN over ICMP / VPN over DNS server function
UINT PsVpnOverIcmpDnsEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SPECIAL_LISTENER t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"ICMP", CmdPrompt, _UU("CMD_VpnOverIcmpDnsEnable_Prompt_ICMP"), CmdEvalNotEmpty, NULL},
		{"DNS", CmdPrompt, _UU("CMD_VpnOverIcmpDnsEnable_Prompt_DNS"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.VpnOverIcmpListener = GetParamYes(o, "ICMP");
	t.VpnOverDnsListener = GetParamYes(o, "DNS");

	// RPC call
	ret = ScSetSpecialListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get current settings of VPN over ICMP / VPN over DNS server function
UINT PsVpnOverIcmpDnsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SPECIAL_LISTENER t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetSpecialListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_VpnOverIcmpDnsGet_PRINT_ICMP"), _UU(t.VpnOverIcmpListener ? "SEC_YES" : "SEC_NO"));
		CtInsert(ct, _UU("CMD_VpnOverIcmpDnsGet_PRINT_DNS"), _UU(t.VpnOverDnsListener ? "SEC_YES" : "SEC_NO"));

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Enable / disable the VPN Azure function
UINT PsVpnAzureSetEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AZURE_STATUS t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[yes|no]", CmdPrompt, _UU("VpnAzureSetEnable_PROMPT"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.IsEnabled = GetParamYes(o, "[yes|no]");

	// RPC call
	ret = ScSetAzureStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Get the current state of the VPN Azure function
UINT PsVpnAzureGetStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AZURE_STATUS t;
	DDNS_CLIENT_STATUS t2;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	Zero(&t2, sizeof(t2));

	// RPC call
	ret = ScGetAzureStatus(ps->Rpc, &t);

	if (ret == ERR_NO_ERROR)
	{
		ret = ScGetDDnsClientStatus(ps->Rpc, &t2);
	}

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_VpnAzureGetStatus_PRINT_ENABLED"), _UU(t.IsEnabled ? "SEC_YES" : "SEC_NO"));

		if (t.IsEnabled)
		{
			wchar_t tmp[MAX_SIZE];

			UniFormat(tmp, sizeof(tmp), L"%S%S", t2.CurrentHostName, AZURE_DOMAIN_SUFFIX);

			CtInsert(ct, _UU("CMD_VpnAzureGetStatus_PRINT_CONNECTED"), _UU(t.IsConnected ? "SEC_YES" : "SEC_NO"));
			CtInsert(ct, _UU("CMD_VpnAzureGetStatus_PRINT_HOSTNAME"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Get the current state of the dynamic DNS function
UINT PsDynamicDnsGetStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	DDNS_CLIENT_STATUS t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScGetDDnsClientStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();
		wchar_t tmp[MAX_SIZE];

		// FQDN
		if (IsEmptyStr(t.CurrentFqdn) == false)
		{
			StrToUni(tmp, sizeof(tmp), t.CurrentFqdn);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_DDNS_FQDN_EMPTY"));
		}
		CtInsert(ct, _UU("CMD_DynamicDnsGetStatus_PRINT_FQDN"), tmp);

		// Hostname
		if (IsEmptyStr(t.CurrentHostName) == false)
		{
			StrToUni(tmp, sizeof(tmp), t.CurrentHostName);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_DDNS_FQDN_EMPTY"));
		}
		CtInsert(ct, _UU("CMD_DynamicDnsGetStatus_PRINT_HOSTNAME"), tmp);

		// Suffix
		if (IsEmptyStr(t.DnsSuffix) == false)
		{
			StrToUni(tmp, sizeof(tmp), t.DnsSuffix);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_DDNS_FQDN_EMPTY"));
		}
		CtInsert(ct, _UU("CMD_DynamicDnsGetStatus_PRINT_SUFFIX"), tmp);

		// IPv4
		if (t.Err_IPv4 == ERR_NO_ERROR)
		{
			StrToUni(tmp, sizeof(tmp), t.CurrentIPv4);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _E(t.Err_IPv4));
		}
		CtInsert(ct, _UU("CMD_DynamicDnsGetStatus_PRINT_IPv4"), tmp);

		// IPv6
		if (t.Err_IPv6 == ERR_NO_ERROR)
		{
			StrToUni(tmp, sizeof(tmp), t.CurrentIPv6);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _E(t.Err_IPv6));
		}
		CtInsert(ct, _UU("CMD_DynamicDnsGetStatus_PRINT_IPv6"), tmp);

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

// Configure the dynamic DNS host name
UINT PsDynamicDnsSetHostname(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[hostname]", CmdPrompt, _UU("CMD_DynamicDnsSetHostname_Prompt_hostname"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.StrValue, sizeof(t.StrValue), GetParamStr(o, "[hostname]"));

	// RPC call
	ret = ScChangeDDnsClientHostname(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Register a new license key
UINT PsLicenseAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[key]", CmdPrompt, _UU("CMD_LicenseAdd_Prompt_Key"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.StrValue, sizeof(t.StrValue), GetParamStr(o, "[key]"));

	// RPC call
	ret = ScAddLicenseKey(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Delete the registered license
UINT PsLicenseDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	// Parameter list that can be specified
	PARAM args[] =
	{
		// "name", prompt_proc, prompt_param, eval_proc, eval_param
		{"[id]", CmdPrompt, _UU("CMD_LicenseDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.IntValue = GetParamInt(o, "[id]");

	// RPC call
	ret = ScDelLicenseKey(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}



// Get the registered license list
UINT PsLicenseList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LICENSE_KEY t;
	CT *ct;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	// RPC call
	ret = ScEnumLicenseKey(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_4"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_5"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_6"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_7"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_8"), false);
	CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_9"), false);

	for (i = 0;i < t.NumItem;i++)
	{
		wchar_t tmp1[32], tmp2[LICENSE_KEYSTR_LEN + 1], tmp3[LICENSE_MAX_PRODUCT_NAME_LEN + 1],
			*tmp4, tmp5[128], tmp6[LICENSE_LICENSEID_STR_LEN + 1], tmp7[64],
			tmp8[64], tmp9[64];
		RPC_ENUM_LICENSE_KEY_ITEM *e = &t.Items[i];

		UniToStru(tmp1, e->Id);
		StrToUni(tmp2, sizeof(tmp2), e->LicenseKey);
		StrToUni(tmp3, sizeof(tmp3), e->LicenseName);
		tmp4 = LiGetLicenseStatusStr(e->Status);
		if (e->Expires == 0)
		{
			UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_LICENSE_NO_EXPIRES"));
		}
		else
		{
			GetDateStrEx64(tmp5, sizeof(tmp5), e->Expires, NULL);
		}
		StrToUni(tmp6, sizeof(tmp6), e->LicenseId);
		UniToStru(tmp7, e->ProductId);
		UniFormat(tmp8, sizeof(tmp8), L"%I64u", e->SystemId);
		UniToStru(tmp9, e->SerialId);

		CtInsert(ct,
			tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9);
	}

	CtFreeEx(ct, c, true);

	FreeRpcEnumLicenseKey(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the license status of the current VPN Server
UINT PsLicenseStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LICENSE_STATUS st;
	CT *ct;
	wchar_t tmp[MAX_SIZE];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&st, sizeof(st));

	// RPC call
	ret = ScGetLicenseStatus(ps->Rpc, &st);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNewStandard();

	if (st.EditionId == LICENSE_EDITION_VPN3_NO_LICENSE)
	{
		CtInsert(ct, _UU("SM_NO_LICENSE_COLUMN"), _UU("SM_NO_LICENSE"));
	}
	else
	{
		// Product edition name
		StrToUni(tmp, sizeof(tmp), st.EditionStr);
		CtInsert(ct, _UU("SM_LICENSE_STATUS_EDITION"), tmp);

		// Release date
		if (st.ReleaseDate != 0)
		{
			GetDateStrEx64(tmp, sizeof(tmp), st.ReleaseDate, NULL);
			CtInsert(ct, _UU("SM_LICENSE_STATUS_RELEASE"), tmp);
		}

		// Current system ID
		UniFormat(tmp, sizeof(tmp), L"%I64u", st.SystemId);
		CtInsert(ct, _UU("SM_LICENSE_STATUS_SYSTEM_ID"), tmp);

		// Expiration date of the current license product
		if (st.SystemExpires == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_NO_EXPIRES"));
		}
		else
		{
			GetDateStrEx64(tmp, sizeof(tmp), st.SystemExpires, NULL);
		}
		CtInsert(ct,  _UU("SM_LICENSE_STATUS_EXPIRES"), tmp);

		// Subscription (support) contract
		if (st.NeedSubscription == false)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_STATUS_SUBSCRIPTION_NONEED"));
		}
		else
		{
			if (st.SubscriptionExpires == 0)
			{
				UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_STATUS_SUBSCRIPTION_NONE"));
			}
			else
			{
				wchar_t dtstr[MAX_PATH];

				GetDateStrEx64(dtstr, sizeof(dtstr), st.SubscriptionExpires, NULL);

				UniFormat(tmp, sizeof(tmp),
					st.IsSubscriptionExpired ? _UU("SM_LICENSE_STATUS_SUBSCRIPTION_EXPIRED") :  _UU("SM_LICENSE_STATUS_SUBSCRIPTION_VALID"),
					dtstr);
			}
		}
		CtInsert(ct, _UU("SM_LICENSE_STATUS_SUBSCRIPTION"), tmp);

		if (st.NeedSubscription == false && st.SubscriptionExpires != 0)
		{
			wchar_t dtstr[MAX_PATH];

			GetDateStrEx64(dtstr, sizeof(dtstr), st.SubscriptionExpires, NULL);

			CtInsert(ct, _UU("SM_LICENSE_STATUS_SUBSCRIPTION_BUILD_STR"), tmp);
		}

		if (GetCapsBool(ps->CapsList, "b_vpn3"))
		{
			// Maximum creatable number of users
			if (st.NumClientConnectLicense == INFINITE)
			{
				UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
			}
			else
			{
				UniToStru(tmp, st.NumClientConnectLicense);
			}
			CtInsert(ct, _UU("SM_LICENSE_NUM_CLIENT"), tmp);
		}

		// Available number of concurrent client connections
		if (st.NumBridgeConnectLicense == INFINITE)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("SM_LICENSE_INFINITE"));
		}
		else
		{
			UniToStru(tmp, st.NumBridgeConnectLicense);
		}
		CtInsert(ct, _UU("SM_LICENSE_NUM_BRIDGE"), tmp);

		// Availability of enterprise features
		CtInsert(ct, _UU("SM_LICENSE_STATUS_ENTERPRISE"),
			st.AllowEnterpriseFunction ? _UU("SM_LICENSE_STATUS_ENTERPRISE_YES") : _UU("SM_LICENSE_STATUS_ENTERPRISE_NO"));
	}

	CtFreeEx(ct, c, false);

	FreeParamValueList(o);

	return 0;
}


// Get the cluster configuration
UINT PsClusterSettingGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_FARM t;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScGetFarmSetting(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (t.Weight == 0)
	{
		t.Weight = FARM_DEFAULT_WEIGHT;
	}

	// Show the cluster configuration
	ct = CtNewStandard();

	CtInsert(ct, _UU("CMD_ClusterSettingGet_Current"),
		GetServerTypeStr(t.ServerType));

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		CtInsert(ct, _UU("CMD_ClusterSettingGet_ControllerOnly"), t.ControllerOnly ? _UU("SEC_YES") : _UU("SEC_NO"));
	}

	if (t.ServerType != SERVER_TYPE_STANDALONE)
	{
		wchar_t tmp[MAX_SIZE];

		UniToStru(tmp, t.Weight);

		CtInsert(ct, _UU("CMD_ClusterSettingGet_Weight"), tmp);
	}

	if (t.ServerType == SERVER_TYPE_FARM_MEMBER)
	{
		wchar_t tmp[MAX_SIZE];
		UINT i;

		// Public IP address
		if (t.PublicIp != 0)
		{
			IPToUniStr32(tmp, sizeof(tmp), t.PublicIp);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_ClusterSettingGet_None"));
		}

		CtInsert(ct, _UU("CMD_ClusterSettingGet_PublicIp"), tmp);

		// Public port list
		tmp[0] = 0;
		for (i = 0;i < t.NumPort;i++)
		{
			wchar_t tmp2[64];

			UniFormat(tmp2, sizeof(tmp2), L"%u, ", t.Ports[i]);

			UniStrCat(tmp, sizeof(tmp), tmp2);
		}

		if (UniEndWith(tmp, L", "))
		{
			tmp[UniStrLen(tmp) - 2] = 0;
		}

		CtInsert(ct, _UU("CMD_ClusterSettingGet_PublicPorts"), tmp);

		// Controller to connect
		UniFormat(tmp, sizeof(tmp), L"%S:%u", t.ControllerName, t.ControllerPort);
		CtInsert(ct, _UU("CMD_ClusterSettingGet_Controller"), tmp);
	}

	CtFree(ct, c);

	FreeRpcFarm(&t);
	FreeParamValueList(o);

	return 0;
}

// Set the server password
UINT PsServerPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_SET_PASSWORD t;
	char *pw;
	PARAM args[] =
	{
		{"[password]", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	pw = GetParamStr(o, "[password]");

	Zero(&t, sizeof(t));
	Sha0(t.HashedPassword, pw, StrLen(pw));

	ret = ScSetServerPassword(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Password decision prompt (for Prompt function)
wchar_t *CmdPromptChoosePassword(CONSOLE *c, void *param)
{
	char *s;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	s = CmdPasswordPrompt(c);

	if (s == NULL)
	{
		return NULL;
	}
	else
	{
		wchar_t *ret = CopyStrToUni(s);

		Free(s);

		return ret;
	}
}

// Password input prompt (general-purpose)
char *CmdPasswordPrompt(CONSOLE *c)
{
	char *pw1, *pw2;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	c->Write(c, _UU("CMD_VPNCMD_PWPROMPT_0"));

RETRY:
	c->Write(c, L"");


	pw1 = c->ReadPassword(c, _UU("CMD_VPNCMD_PWPROMPT_1"));
	if (pw1 == NULL)
	{
		return NULL;
	}

	pw2 = c->ReadPassword(c, _UU("CMD_VPNCMD_PWPROMPT_2"));
	if (pw2 == NULL)
	{
		Free(pw1);
		return NULL;
	}

	c->Write(c, L"");

	if (StrCmp(pw1, pw2) != 0)
	{
		Free(pw1);
		Free(pw2);
		c->Write(c, _UU("CMD_VPNCMD_PWPROMPT_3"));
		goto RETRY;
	}

	Free(pw1);

	return pw2;
}

// Disable the listener
UINT PsListenerDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerDisable_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = false;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScEnableListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Enable the listener
UINT PsListenerEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerEnable_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScEnableListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Set UDP ports the server should listen on
UINT PsPortsUDPSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o, *ports;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_PORTS t;
	PARAM args[] =
	{
		{"[ports]", CmdPrompt, _UU("CMD_PortsUDPSet_[ports]"), CmdEvalPortList, (void *)false}
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ports = StrToPortList(GetParamStr(o, "[ports]"), false);

	FreeParamValueList(o);

	t.Num = LIST_NUM(ports);
	if (t.Num > 0)
	{
		UINT i;
		t.Ports = Malloc(sizeof(UINT) * t.Num);

		for (i = 0; i < t.Num; ++i)
		{
			t.Ports[i] = (UINT)LIST_DATA(ports, i);
		}
	}
	else
	{
		t.Ports = NULL;
	}

	ReleaseList(ports);

	ret = ScSetPortsUDP(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	Free(t.Ports);

	return ret;
}

// List UDP ports the server is listening on
UINT PsPortsUDPGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_PORTS t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	FreeParamValueList(o);

	Zero(&t, sizeof(t));

	ret = ScGetPortsUDP(ps->Rpc, &t);
	if (ret == ERR_NO_ERROR)
	{
		wchar_t str[MAX_SIZE];
		CT *ct = CtNewStandard();

		Zero(str, sizeof(str));

		if (t.Num > 0)
		{
			UINT i;
			wchar_t buf[MAX_SIZE];

			UniFormat(buf, sizeof(buf), L"%u", t.Ports[0]);
			UniStrCat(str, sizeof(str), buf);

			for (i = 1; i < t.Num; ++i)
			{
				UniFormat(buf, sizeof(buf), L", %u", t.Ports[i]);
				UniStrCat(str, sizeof(str), buf);
			}
		}

		CtInsert(ct, _UU("CMD_PortsUDPGet_Ports"), str);
		CtFree(ct, c);
	}
	else
	{
		CmdPrintError(c, ret);
	}

	FreeRpcPorts(&t);

	return ret;
}

// Configure an option for the specified protocol (TODO: ability to set multiple options in a single call)
UINT PsProtoOptionsSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_PROTO_OPTIONS t;
	PARAM args[] =
	{
		{"[protocol]", CmdPrompt, _UU("CMD_ProtoOptionsSet_Prompt_[protocol]"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_ProtoOptionsSet_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_ProtoOptionsSet_Prompt_VALUE"), NULL, NULL}
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Protocol = CopyStr(GetParamStr(o, "[protocol]"));

	ret = ScGetProtoOptions(ps->Rpc, &t);

	if (ret == ERR_NO_ERROR)
	{
		UINT i;
		bool found = false;

		for (i = 0; i < t.Num; ++i)
		{
			PROTO_OPTION *option = &t.Options[i];
			if (StrCmpi(option->Name, GetParamStr(o, "NAME")) != 0)
			{
				continue;
			}

			found = true;

			switch (option->Type)
			{
			case PROTO_OPTION_STRING:
				Free(option->String);
				option->String = CopyStr(GetParamStr(o, "VALUE"));
				break;
			case PROTO_OPTION_BOOL:
				option->Bool = GetParamYes(o, "VALUE");
				break;
			default:
				ret = ERR_INTERNAL_ERROR;
			}

			if (ret == ERR_NO_ERROR)
			{
				ret = ScSetProtoOptions(ps->Rpc, &t);
			}

			break;
		}

		if (found == false)
		{
			ret = ERR_OBJECT_NOT_FOUND;
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	FreeRpcProtoOptions(&t);
	FreeParamValueList(o);

	return ret;
}

// List available options for the specified protocol
UINT PsProtoOptionsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_PROTO_OPTIONS t;
	PARAM args[] =
	{
		{"[protocol]", CmdPrompt, _UU("CMD_ProtoOptionsGet_Prompt_[protocol]"), CmdEvalNotEmpty, NULL}
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Protocol = CopyStr(GetParamStr(o, "[protocol]"));

	FreeParamValueList(o);

	ret = ScGetProtoOptions(ps->Rpc, &t);
	if (ret == ERR_NO_ERROR)
	{
		UINT i;
		CT *ct = CtNew();
		CtInsertColumn(ct, _UU("CMD_ProtoOptionsGet_Column_Name"), false);
		CtInsertColumn(ct, _UU("CMD_ProtoOptionsGet_Column_Type"), false);
		CtInsertColumn(ct, _UU("CMD_ProtoOptionsGet_Column_Value"), false);
		CtInsertColumn(ct, _UU("CMD_ProtoOptionsGet_Column_Description"), false);

		for (i = 0; i < t.Num; ++i)
		{
			char description_str_key[MAX_SIZE];
			const PROTO_OPTION *option = &t.Options[i];
			wchar_t *value, *type, *name = CopyStrToUni(option->Name);

			switch (option->Type)
			{
				case PROTO_OPTION_BOOL:
					type = L"Boolean";
					value = option->Bool ? L"True" : L"False";
					break;
				case PROTO_OPTION_STRING:
					type = L"String";
					value = CopyStrToUni(option->String);
					break;
				default:
					Debug("StGetProtoOptions(): unhandled option type %u!\n", option->Type);
					Free(name);
					continue;
			}

			Format(description_str_key, sizeof(description_str_key), "CMD_ProtoOptions_Description_%s_%s", t.Protocol, option->Name);

			CtInsert(ct, name, type, value, _UU(description_str_key));

			if (option->Type == PROTO_OPTION_STRING)
			{
				Free(value);
			}

			Free(name);
		}

		CtFree(ct, c);
	}
	else
	{
		CmdPrintError(c, ret);
	}

	FreeRpcProtoOptions(&t);

	return ret;
}

// Draw a row of console table
void CtPrintRow(CONSOLE *c, UINT num, UINT *widths, wchar_t **strings, bool *rights, char separate_char)
{
	UINT i;
	wchar_t *buf;
	UINT buf_size;
	bool is_sep_line = true;
	// Validate arguments
	if (c == NULL || num == 0 || widths == NULL || strings == NULL || rights == NULL)
	{
		return;
	}

	buf_size = 32;
	for (i = 0;i < num;i++)
	{
		buf_size += sizeof(wchar_t) * widths[i] + 6;
	}

	buf = ZeroMalloc(buf_size);

	for (i = 0;i < num;i++)
	{
		char *tmp;
		wchar_t *space_string;
		UINT w;
		UINT space = 0;
		wchar_t *string = strings[i];
		wchar_t *tmp_line = NULL;

		if (UniStrCmpi(string, L"---") == 0)
		{
			char *s = MakeCharArray('-', widths[i]);
			tmp_line = string = CopyStrToUni(s);

			Free(s);
		}
		else
		{
			is_sep_line = false;
		}

		w = UniStrWidth(string);

		if (widths[i] >= w)
		{
			space = widths[i] - w;
		}

		tmp = MakeCharArray(' ', space);
		space_string = CopyStrToUni(tmp);

		if (rights[i] != false)
		{
			UniStrCat(buf, buf_size, space_string);
		}

		UniStrCat(buf, buf_size, string);

		if (rights[i] == false)
		{
			UniStrCat(buf, buf_size, space_string);
		}

		Free(space_string);
		Free(tmp);

		if (i < (num - 1))
		{
			wchar_t tmp[4];
			char str[2];

			if (UniStrCmpi(strings[i], L"---") == 0)
			{
				str[0] = '+';
			}
			else
			{
				str[0] = separate_char;
			}
			str[1] = 0;

			StrToUni(tmp, sizeof(tmp), str);

			UniStrCat(buf, buf_size, tmp);
		}

		if (tmp_line != NULL)
		{
			Free(tmp_line);
		}
	}

	UniTrimRight(buf);

	if (is_sep_line)
	{
		if (UniStrLen(buf) > (c->GetWidth(c) - 1))
		{
			buf[c->GetWidth(c) - 1] = 0;
		}
	}

	c->Write(c, buf);

	Free(buf);
}

// Draw the console table in standard format
void CtPrintStandard(CT *ct, CONSOLE *c)
{
	CT *t;
	UINT i, j;
	// Validate arguments
	if (ct == NULL || c == NULL)
	{
		return;
	}

	t = CtNewStandard();
	for (i = 0;i < LIST_NUM(ct->Rows);i++)
	{
		CTR *row = LIST_DATA(ct->Rows, i);

		for (j = 0;j < LIST_NUM(ct->Columns);j++)
		{
			CTC *column = LIST_DATA(ct->Columns, j);

			CtInsert(t, column->String, row->Strings[j]);
		}

		if (i != (LIST_NUM(ct->Rows) - 1))
		{
			CtInsert(t, L"---", L"---");
		}
	}

	CtFree(t, c);
}

// Draw the console table
void CtPrint(CT *ct, CONSOLE *c)
{
	UINT *widths;
	UINT num;
	UINT i, j;
	wchar_t **header_strings;
	bool *rights;
	// Validate arguments
	if (ct == NULL || c == NULL)
	{
		return;
	}

	num = LIST_NUM(ct->Columns);
	widths = ZeroMalloc(sizeof(UINT) * num);

	// Calculate the maximum character width of each column
	for (i = 0;i < num;i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);
		UINT w;

		w = UniStrWidth(ctc->String);
		widths[i] = MAX(widths[i], w);
	}
	for (j = 0;j < LIST_NUM(ct->Rows);j++)
	{
		CTR *ctr = LIST_DATA(ct->Rows, j);

		for (i = 0;i < num;i++)
		{
			UINT w;

			w = UniStrWidth(ctr->Strings[i]);
			widths[i] = MAX(widths[i], w);
		}
	}

	// Display the header part
	header_strings = ZeroMalloc(sizeof(wchar_t *) * num);
	rights = ZeroMalloc(sizeof(bool) * num);

	for (i = 0;i < num;i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);

		header_strings[i] = ctc->String;
		rights[i] = ctc->Right;
	}

	CtPrintRow(c, num, widths, header_strings, rights, '|');

	for (i = 0;i < num;i++)
	{
		char *s;

		s = MakeCharArray('-', widths[i]);
		header_strings[i] = CopyStrToUni(s);
		Free(s);
	}

	CtPrintRow(c, num, widths, header_strings, rights, '+');

	for (i = 0;i < num;i++)
	{
		Free(header_strings[i]);
	}

	// Display the data part
	for (j = 0;j < LIST_NUM(ct->Rows);j++)
	{
		CTR *ctr = LIST_DATA(ct->Rows, j);

		CtPrintRow(c, num, widths, ctr->Strings, rights, '|');
	}

	Free(rights);
	Free(header_strings);
	Free(widths);
}

// Escape the meta-characters in CSV
void CtEscapeCsv(wchar_t *dst, UINT size, wchar_t *src){
	UINT i;
	UINT len = UniStrLen(src);
	UINT idx;
	BOOL need_to_escape = false;
	wchar_t tmp[2]=L"*";

	// Check the input value
	if (src==NULL || dst==NULL)
	{
		return;
	}

	// If there is no character that need to be escaped in the input characters, copy it to the output
	for (i=0; i<len; i++)
	{
		tmp[0] = src[i];
		if (tmp[0] == L","[0] || tmp[0] == L"\n"[0] || tmp[0] == L"\""[0])
		{
			need_to_escape = true;
		}
	}
	if (need_to_escape == false)
	{
		UniStrCpy(dst,size,src);
		return;
	}

	// If it contains meta characters (newline, comma, double quote), enclose with "
	UniStrCpy(dst, size, L"\"");
	idx = UniStrLen(dst);
	if(idx<size-1)
	{
		for (i=0; i<len; i++)
		{
			tmp[0] = src[i];
			// Convert " to "" in contents(MS-Excel method)
			if (tmp[0] == L"\""[0])
			{
				UniStrCat(dst, size, tmp);
			}
			UniStrCat(dst, size, tmp);
		}
	}
	UniStrCat(dst, size, L"\"");
	return;
}

// Show a CSV format of console table
void CtPrintCsv(CT *ct, CONSOLE *c)
{
	UINT i, j;
	UINT num_columns = LIST_NUM(ct->Columns);
	wchar_t buf[MAX_SIZE*4];
	wchar_t fmtbuf[MAX_SIZE*4];

	// Show the heading row
	buf[0] = 0;
	for(i=0; i<num_columns; i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);
		CtEscapeCsv(fmtbuf, sizeof(fmtbuf), ctc->String);
		UniStrCat(buf, sizeof(buf), fmtbuf);
		if(i != num_columns-1)
			UniStrCat(buf, sizeof(buf), L",");
	}
	c->Write(c, buf);

	// Show the table body
	for(j=0; j<LIST_NUM(ct->Rows); j++)
	{
		CTR *ctr = LIST_DATA(ct->Rows, j);
		buf[0] = 0;
		for(i=0; i<num_columns; i++)
		{
			CtEscapeCsv(fmtbuf, sizeof(fmtbuf), ctr->Strings[i]);
			UniStrCat(buf, sizeof(buf), fmtbuf);
			if(i != num_columns-1)
				UniStrCat(buf, sizeof(buf), L",");
		}
		c->Write(c, buf);
	}
}

// Delete the console table
void CtFreeEx(CT *ct, CONSOLE *c, bool standard_view)
{
	UINT i, num;
	// Validate arguments
	if (ct == NULL)
	{
		return;
	}

	if (c != NULL)
	{
		if (c->ConsoleType == CONSOLE_CSV)
		{
			CtPrintCsv(ct, c);
		}
		else
		{
			if (standard_view == false)
			{
				CtPrint(ct, c);
			}
			else
			{
				CtPrintStandard(ct, c);
			}
		}
	}

	num = LIST_NUM(ct->Columns);

	for (i = 0;i < LIST_NUM(ct->Rows);i++)
	{
		UINT j;
		CTR *ctr = LIST_DATA(ct->Rows, i);

		for (j = 0;j < num;j++)
		{
			Free(ctr->Strings[j]);
		}

		Free(ctr->Strings);
		Free(ctr);
	}

	for (i = 0;i < LIST_NUM(ct->Columns);i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);

		Free(ctc->String);
		Free(ctc);
	}

	ReleaseList(ct->Columns);
	ReleaseList(ct->Rows);

	Free(ct);
}
void CtFree(CT *ct, CONSOLE *c)
{
	CtFreeEx(ct, c, false);
}

// Add a row to the table
void CtInsert(CT *ct, ...)
{
	CTR *ctr;
	UINT num, i;
	va_list va;
	// Validate arguments
	if (ct == NULL)
	{
		return;
	}

	num = LIST_NUM(ct->Columns);

	va_start(va, ct);

	ctr = ZeroMalloc(sizeof(CTR));
	ctr->Strings = ZeroMalloc(sizeof(wchar_t *) * num);

	for (i = 0;i < num;i++)
	{
		wchar_t *s = va_arg(va, wchar_t *);

		ctr->Strings[i] = CopyUniStr(s);
	}

	va_end(va);

	Insert(ct->Rows, ctr);
}

// Add a column to the table
void CtInsertColumn(CT *ct, wchar_t *str, bool right)
{
	CTC *ctc;
	// Validate arguments
	if (ct == NULL)
	{
		return;
	}
	if (str == NULL)
	{
		str = L"";
	}

	ctc = ZeroMalloc(sizeof(CTC));
	ctc->String = CopyUniStr(str);
	ctc->Right = right;

	Insert(ct->Columns, ctc);
}

// Create a new console table
CT *CtNew()
{
	CT *ct;

	ct = ZeroMalloc(sizeof(CT));
	ct->Columns = NewList(NULL);
	ct->Rows = NewList(NULL);

	return ct;
}

// Add a standard column to a column in a table
CT *CtNewStandard()
{
	CT *ct = CtNew();

	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_2"), false);

	return ct;
}
CT *CtNewStandardEx()
{
	CT *ct = CtNew();

	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_3"), false);

	return ct;
}

// Get the TCP listener list
UINT PsListenerList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER_LIST t;
	UINT i;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScEnumListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("CM_LISTENER_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("CM_LISTENER_COLUMN_2"), false);

	for (i = 0;i < t.NumPort;i++)
	{
		wchar_t *status = _UU("CM_LISTENER_OFFLINE");
		wchar_t tmp[128];

		if (t.Errors[i])
		{
			status = _UU("CM_LISTENER_ERROR");
		}
		else if (t.Enables[i])
		{
			status = _UU("CM_LISTENER_ONLINE");
		}

		UniFormat(tmp, sizeof(tmp), _UU("CM_LISTENER_TCP_PORT"), t.Ports[i]);

		CtInsert(ct, tmp, status);
	}

	CtFree(ct, c);

	FreeRpcListenerList(&t);

	FreeParamValueList(o);

	return 0;
}

// Delete the TCP listener
UINT PsListenerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerDelete_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScDeleteListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// ServerInfoGet command
UINT PsServerInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_SERVER_INFO t;
	CT *ct;
	wchar_t tmp[MAX_SIZE];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	ret = ScGetServerInfo(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_2"), false);

	// Product name
	StrToUni(tmp, sizeof(tmp), t.ServerProductName);
	CtInsert(ct, _UU("SM_INFO_PRODUCT_NAME"), tmp);

	// Version
	StrToUni(tmp, sizeof(tmp), t.ServerVersionString);
	CtInsert(ct, _UU("SM_INFO_VERSION"), tmp);

	// Build
	StrToUni(tmp, sizeof(tmp), t.ServerBuildInfoString);
	CtInsert(ct, _UU("SM_INFO_BUILD"), tmp);

	// Host name
	StrToUni(tmp, sizeof(tmp), t.ServerHostName);
	CtInsert(ct, _UU("SM_INFO_HOSTNAME"), tmp);

	// Type
	CtInsert(ct, _UU("SM_ST_SERVER_TYPE"), GetServerTypeStr(t.ServerType));

	// OS
	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsSystemName);
	CtInsert(ct, _UU("SM_OS_SYSTEM_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsProductName);
	CtInsert(ct, _UU("SM_OS_PRODUCT_NAME"), tmp);

	if (t.OsInfo.OsServicePack != 0)
	{
		UniFormat(tmp, sizeof(tmp), _UU("SM_OS_SP_TAG"), t.OsInfo.OsServicePack);
		CtInsert(ct, _UU("SM_OS_SERVICE_PACK"), tmp);
	}

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsVendorName);
	CtInsert(ct, _UU("SM_OS_VENDER_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.OsVersion);
	CtInsert(ct, _UU("SM_OS_VERSION"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.KernelName);
	CtInsert(ct, _UU("SM_OS_KERNEL_NAME"), tmp);

	StrToUni(tmp, sizeof(tmp), t.OsInfo.KernelVersion);
	CtInsert(ct, _UU("SM_OS_KERNEL_VERSION"), tmp);

	CtFree(ct, c);

	FreeRpcServerInfo(&t);

	FreeParamValueList(o);

	return 0;
}

// Get the string for type of the HUB
wchar_t *GetHubTypeStr(UINT type)
{
	if (type == HUB_TYPE_FARM_STATIC)
	{
		return _UU("SM_HUB_STATIC");
	}
	else if (type == HUB_TYPE_FARM_DYNAMIC)
	{
		return _UU("SM_HUB_DYNAMIC");
	}
	return _UU("SM_HUB_STANDALONE");
}

// Get a string of the type of server
wchar_t *GetServerTypeStr(UINT type)
{
	if (type == SERVER_TYPE_FARM_CONTROLLER)
	{
		return _UU("SM_FARM_CONTROLLER");
	}
	else if (type == SERVER_TYPE_FARM_MEMBER)
	{
		return _UU("SM_FARM_MEMBER");
	}
	return _UU("SM_SERVER_STANDALONE");
}

// ServerStatusGet command
UINT PsServerStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_SERVER_STATUS t;
	wchar_t tmp[MAX_PATH];
	char tmp2[MAX_PATH];
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	ret = ScGetServerStatus(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_STATUS_COLUMN_2"), false);

	// Type of server
	CtInsert(ct, _UU("SM_ST_SERVER_TYPE"),
		t.ServerType == SERVER_TYPE_STANDALONE ? _UU("SM_SERVER_STANDALONE") :
		t.ServerType == SERVER_TYPE_FARM_MEMBER ? _UU("SM_FARM_MEMBER") : _UU("SM_FARM_CONTROLLER"));

	// Number of TCP connections
	UniToStru(tmp, t.NumTcpConnections);
	CtInsert(ct, _UU("SM_ST_NUM_TCP"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// Number of local TCP connections
		UniToStru(tmp, t.NumTcpConnectionsLocal);
		CtInsert(ct, _UU("SM_ST_NUM_TCP_LOCAL"), tmp);

		// Number of remote TCP connections
		UniToStru(tmp, t.NumTcpConnectionsRemote);
		CtInsert(ct, _UU("SM_ST_NUM_TCP_REMOTE"), tmp);
	}

	// Number of Virtual HUBs
	UniToStru(tmp, t.NumHubTotal);
	CtInsert(ct, _UU("SM_ST_NUM_HUB_TOTAL"), tmp);

	if (t.ServerType != SERVER_TYPE_STANDALONE)
	{
		// Number of static HUBs
		UniToStru(tmp, t.NumHubStatic);
		CtInsert(ct, _UU("SM_ST_NUM_HUB_STATIC"), tmp);

		// Number of dynamic HUBs
		UniToStru(tmp, t.NumHubDynamic);
		CtInsert(ct, _UU("SM_ST_NUM_HUB_DYNAMIC"), tmp);
	}

	// Number of sessions
	UniToStru(tmp, t.NumSessionsTotal);
	CtInsert(ct, _UU("SM_ST_NUM_SESSION_TOTAL"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		// Number of local sessions
		UniToStru(tmp, t.NumSessionsLocal);
		CtInsert(ct, _UU("SM_ST_NUM_SESSION_LOCAL"), tmp);

		// Number of remote sessions
		UniToStru(tmp, t.NumSessionsRemote);
		CtInsert(ct, _UU("SM_ST_NUM_SESSION_REMOTE"), tmp);
	}

	// Number of MAC tables
	UniToStru(tmp, t.NumMacTables);
	CtInsert(ct, _UU("SM_ST_NUM_MAC_TABLE"), tmp);

	// Number of IP tables
	UniToStru(tmp, t.NumIpTables);
	CtInsert(ct, _UU("SM_ST_NUM_IP_TABLE"), tmp);

	// Number of users
	UniToStru(tmp, t.NumUsers);
	CtInsert(ct, _UU("SM_ST_NUM_USERS"), tmp);

	// Number of groups
	UniToStru(tmp, t.NumGroups);
	CtInsert(ct, _UU("SM_ST_NUM_GROUPS"), tmp);

	// Number of assigned licenses
	UniToStru(tmp, t.AssignedClientLicenses);
	CtInsert(ct, _UU("SM_ST_CLIENT_LICENSE"), tmp);

	UniToStru(tmp, t.AssignedBridgeLicenses);
	CtInsert(ct, _UU("SM_ST_BRIDGE_LICENSE"), tmp);

	if (t.ServerType == SERVER_TYPE_FARM_CONTROLLER)
	{
		UniToStru(tmp, t.AssignedClientLicensesTotal);
		CtInsert(ct, _UU("SM_ST_CLIENT_LICENSE_EX"), tmp);

		UniToStru(tmp, t.AssignedBridgeLicensesTotal);
		CtInsert(ct, _UU("SM_ST_BRIDGE_LICENSE_EX"), tmp);
	}

	// Traffic
	CmdInsertTrafficInfo(ct, &t.Traffic);

	// Server start-up time
	GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.StartTime), NULL);
	CtInsert(ct, _UU("SM_ST_START_TIME"), tmp);

	// Current time
	GetDateTimeStrMilli64(tmp2, sizeof(tmp2), SystemToLocal64(t.CurrentTime));
	StrToUni(tmp, sizeof(tmp), tmp2);
	CtInsert(ct, _UU("SM_ST_CURRENT_TIME"), tmp);

	// Tick value
	UniFormat(tmp, sizeof(tmp), L"%I64u", t.CurrentTick);
	CtInsert(ct, _UU("SM_ST_CURRENT_TICK"), tmp);

	// Memory information
	if (t.MemInfo.TotalMemory != 0)
	{
		char vv[128];

		ToStr3(vv, sizeof(vv), t.MemInfo.TotalMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_TOTAL_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.UsedMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_USED_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.FreeMemory);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_FREE_MEMORY"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.TotalPhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_TOTAL_PHYS"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.UsedPhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_USED_PHYS"), tmp);

		ToStr3(vv, sizeof(vv), t.MemInfo.FreePhys);
		UniFormat(tmp, sizeof(tmp), _UU("SM_ST_RAM_SIZE_KB"), vv);
		CtInsert(ct, _UU("SM_ST_FREE_PHYS"), tmp);
	}

	CtFree(ct, c);

	FreeParamValueList(o);

	return 0;
}

// Add traffic information to LVB
void CmdInsertTrafficInfo(CT *ct, TRAFFIC *t)
{
	wchar_t tmp[MAX_SIZE];
	char vv[128];
	// Validate arguments
	if (ct == NULL || t == NULL)
	{
		return;
	}

	// Transmission information
	ToStr3(vv, sizeof(vv), t->Send.UnicastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_UCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.UnicastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_UCAST_SIZE"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.BroadcastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_BCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Send.BroadcastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_SEND_BCAST_SIZE"), tmp);

	// Reception information
	ToStr3(vv, sizeof(vv), t->Recv.UnicastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_UCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.UnicastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_UCAST_SIZE"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.BroadcastCount);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_NUM_PACKET_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_BCAST_NUM"), tmp);

	ToStr3(vv, sizeof(vv), t->Recv.BroadcastBytes);
	UniFormat(tmp, sizeof(tmp), _UU("SM_ST_SIZE_BYTE_STR"), vv);
	CtInsert(ct, _UU("SM_ST_RECV_BCAST_SIZE"), tmp);
}

// Input a port number
wchar_t *CmdPromptPort(CONSOLE *c, void *param)
{
	wchar_t *prompt_str;

	if (param != NULL)
	{
		prompt_str = (wchar_t *)param;
	}
	else
	{
		prompt_str = _UU("CMD_PROMPT_PORT");
	}

	return c->ReadLine(c, prompt_str, true);
}

// Verify the port number
bool CmdEvalPort(CONSOLE *c, wchar_t *str, void *param)
{
	UINT i;
	// Validate arguments
	if (c == NULL || str == NULL)
	{
		return false;
	}

	i = UniToInt(str);

	if (i >= 1 && i <= 65535)
	{
		return true;
	}

	c->Write(c, _UU("CMD_EVAL_PORT"));

	return false;
}

// ListenerCreate command
UINT PsListenerCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret;
	RPC_LISTENER t;
	PARAM args[] =
	{
		{"[port]", CmdPromptPort, _UU("CMD_ListenerCreate_PortPrompt"), CmdEvalPort, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.Enable = true;
	t.Port = ToInt(GetParamStr(o, "[port]"));

	ret = ScCreateListener(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// About command
UINT PsAbout(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	BUF *b;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	b = ReadDump("|legal.txt");

	CmdPrintAbout(c);
	c->Write(c, L"\r\n");

	if (b != NULL)
	{
		wchar_t *s;

		SeekBufToEnd(b);
		WriteBufChar(b, 13);
		WriteBufChar(b, 10);
		WriteBufChar(b, 0);

		s = CopyUtfToUni(b->Buf);

		c->Write(c, s);

		Free(s);
	}

	// Display the version information
	c->Write(c, _UU("D_ABOUT@S_INFO3"));
	c->Write(c, L"\r\n");
	c->Write(c, _UU("D_ABOUT@S_INFO4"));
	c->Write(c, L"\r\n");
	CmdPrintAbout(c);
	c->Write(c, L"\r\n");

	FreeParamValueList(o);

	FreeBuf(b);

	return 0;
}

// Creat a new server management context
PS *NewPs(CONSOLE *c, RPC *rpc, char *servername, UINT serverport, char *hubname, char *adminhub, wchar_t *cmdline)
{
	PS *ps;
	// Validate arguments
	if (c == NULL || rpc == NULL || servername == NULL)
	{
		return NULL;
	}

	if (IsEmptyStr(hubname))
	{
		hubname = NULL;
	}
	if (IsEmptyStr(adminhub))
	{
		adminhub = NULL;
	}
	if (UniIsEmptyStr(cmdline))
	{
		cmdline = NULL;
	}

	ps = ZeroMalloc(sizeof(PS));
	ps->ConsoleForServer = true;
	ps->ServerPort = serverport;
	ps->ServerName = CopyStr(servername);
	ps->Console = c;
	ps->Rpc = rpc;
	ps->HubName = CopyStr(hubname);
	ps->LastError = 0;
	ps->AdminHub = CopyStr(adminhub);
	ps->CmdLine = CopyUniStr(cmdline);

	return ps;
}

// Release the server management context
void FreePs(PS *ps)
{
	// Validate arguments
	if (ps == NULL)
	{
		return;
	}

	Free(ps->HubName);
	Free(ps->AdminHub);
	Free(ps->CmdLine);
	Free(ps->ServerName);

	Free(ps);
}

// Server Administration Tool
UINT PsConnect(CONSOLE *c, char *host, UINT port, char *hub, char *adminhub, wchar_t *cmdline, char *password)
{
	UINT retcode = 0;
	RPC *rpc = NULL;
	CEDAR *cedar;
	CLIENT_OPTION o;
	UCHAR hashed_password[SHA1_SIZE];
	bool b = false;
	// Validate arguments
	if (c == NULL || host == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}
	if (port == 0)
	{
		port = 443;
	}
	if (hub != NULL)
	{
		adminhub = NULL;
	}

	cedar = NewCedar(NULL, NULL);

	Zero(&o, sizeof(o));
	UniStrCpy(o.AccountName, sizeof(o.AccountName), L"VPNCMD");
	StrCpy(o.Hostname, sizeof(o.Hostname), host);
	o.Port = port;
	o.ProxyType = PROXY_DIRECT;

	Sha0(hashed_password, password, StrLen(password));

	if (IsEmptyStr(password) == false)
	{
		b = true;
	}

	// Connect
	while (true)
	{
		UINT err;

		rpc = AdminConnectEx(cedar, &o, hub, hashed_password, &err, CEDAR_CUI_STR);
		if (rpc == NULL)
		{
			// Failure
			retcode = err;

			if (err == ERR_ACCESS_DENIED && c->ProgrammingMode == false)
			{
				char *pass;
				// Password is incorrect
				if (b)
				{
					// Input the password
					c->Write(c, _UU("CMD_VPNCMD_PASSWORD_1"));
				}

				b = true;

				pass = c->ReadPassword(c, _UU("CMD_VPNCMD_PASSWORD_2"));
				c->Write(c, L"");

				if (pass != NULL)
				{
					Sha0(hashed_password, pass, StrLen(pass));
					Free(pass);
				}
				else
				{
					break;
				}
			}
			else
			{
				// Other errors
				CmdPrintError(c, err);
				break;
			}
		}
		else
		{
			PS *ps;

			// Success
			ps = NewPs(c, rpc, host, port, hub, adminhub, cmdline);
			PsMain(ps);
			retcode = ps->LastError;
			FreePs(ps);
			AdminDisconnect(rpc);
			break;
		}
	}

	ReleaseCedar(cedar);

	return retcode;
}

// Display the error
void CmdPrintError(CONSOLE *c, UINT err)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_ERROR"),
		err, GetUniErrorStr(err));
	c->Write(c, tmp);

	if (err == ERR_DISCONNECTED)
	{
		c->Write(c, _UU("CMD_DISCONNECTED_MSG"));
	}
}

// Display the version information
void CmdPrintAbout(CONSOLE *c)
{
	CEDAR *cedar;
	wchar_t tmp[MAX_SIZE];
	char exe[MAX_PATH];
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	cedar = NewCedar(NULL, NULL);

	GetExeName(exe, sizeof(exe));

	UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_ABOUT"),
		cedar->VerString, cedar->BuildInfo);

	c->Write(c, tmp);

	ReleaseCedar(cedar);
}

// Parse the host name and port number (Separated by @)
bool ParseHostPortAtmark(char *src, char **host, UINT *port, UINT default_port)
{
	TOKEN_LIST *t;
	bool ret = false;
	// Validate arguments
	if (src == NULL)
	{
		return false;
	}

	t = ParseToken(src, "@");
	if (t == NULL)
	{
		return false;
	}

	if (port != NULL)
	{
		*port = 0;
	}

	if (default_port == 0)
	{
		if (t->NumTokens < 2)
		{
			FreeToken(t);
			return false;
		}

		if (ToInt(t->Token[1]) == 0)
		{
			FreeToken(t);
			return false;
		}
	}

	if (t->NumTokens >= 2 && ToInt(t->Token[1]) == 0)
	{
		FreeToken(t);
		return false;
	}

	if (t->NumTokens >= 1 && IsEmptyStr(t->Token[0]) == false)
	{
		ret = true;

		if (host != NULL)
		{
			*host = CopyStr(t->Token[0]);
			Trim(*host);
		}

		if (t->NumTokens >= 2)
		{
			if (port != NULL)
			{
				*port = ToInt(t->Token[1]);
			}
		}
	}

	if (port != NULL)
	{
		if (*port == 0)
		{
			*port = default_port;
		}
	}

	FreeToken(t);

	return ret;
}

// Parse the host name and port number
bool ParseHostPort(char *src, char **host, UINT *port, UINT default_port)
{
	TOKEN_LIST *t;
	bool ret = false;
	// Validate arguments
	if (src == NULL)
	{
		return false;
	}

	if (StartWith(src, "["))
	{
		if (InStr(src, "]"))
		{
			// Format of [target]:port
			UINT i, n;
			char tmp[MAX_SIZE];

			StrCpy(tmp, sizeof(tmp), src);

			n = SearchStrEx(tmp, "]", 0, false);
			if (n != INFINITE)
			{
				UINT len = StrLen(tmp);

				for (i = n;i < len;i++)
				{
					if (tmp[i] == ':')
					{
						tmp[i] = '@';
					}
				}
			}

			return ParseHostPortAtmark(tmp, host, port, default_port);
		}
	}

	if (InStr(src, "@"))
	{
		// It is separated by @
		return ParseHostPortAtmark(src, host, port, default_port);
	}

	t = ParseToken(src, ":");
	if (t == NULL)
	{
		return false;
	}

	if (port != NULL)
	{
		*port = 0;
	}

	if (default_port == 0)
	{
		if (t->NumTokens < 2)
		{
			FreeToken(t);
			return false;
		}

		if (ToInt(t->Token[1]) == 0)
		{
			FreeToken(t);
			return false;
		}
	}

	if (t->NumTokens >= 2 && ToInt(t->Token[1]) == 0)
	{
		FreeToken(t);
		return false;
	}

	if (t->NumTokens >= 1 && IsEmptyStr(t->Token[0]) == false)
	{
		ret = true;

		if (host != NULL)
		{
			*host = CopyStr(t->Token[0]);
			Trim(*host);
		}

		if (t->NumTokens >= 2)
		{
			if (port != NULL)
			{
				*port = ToInt(t->Token[1]);
			}
		}
	}

	if (port != NULL)
	{
		if (*port == 0)
		{
			*port = default_port;
		}
	}

	FreeToken(t);

	return ret;
}

// Vpncmd command procedure
UINT VpnCmdProc(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	char *target;
	bool server = false;
	bool client = false;
	bool tools = false;
	char *hostname = NULL;
	char *password;
	wchar_t *cmdline;
	bool host_inputted = false;
	UINT port = 0;
	UINT retcode = 0;
	PARAM args[] =
	{
		{"[host:port]", NULL, NULL, NULL, NULL},
		{"CLIENT", NULL, NULL, NULL, NULL},
		{"SERVER", NULL, NULL, NULL, NULL},
		{"TOOLS", NULL, NULL, NULL, NULL},
		{"HUB", NULL, NULL, NULL, NULL},
		{"ADMINHUB", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
		{"IN", NULL, NULL, NULL, NULL},
		{"OUT", NULL, NULL, NULL, NULL},
		{"CMD", NULL, NULL, NULL, NULL},
		{"CSV", NULL, NULL, NULL, NULL},
		{"PROGRAMMING", NULL, NULL, NULL, NULL},
	};

#ifdef	OS_WIN32
	if (UniStrCmpi(str, L"/debug") == 0)
	{
		// Debug information write mode
		Win32CmdDebug(false);
		return 0;
	}
	if (UniStrCmpi(str, L"/debug_uac") == 0)
	{
		// Debug information write mode
		Win32CmdDebug(true);
		return 0;
	}
#endif	// OS_WIN32

	if (c->ConsoleType == CONSOLE_LOCAL)
	{
		// Initialize the execute path information
		VpnCmdInitBootPath();
	}

	if(c->ConsoleType != CONSOLE_CSV)
	{
		CmdPrintAbout(c);
		c->Write(c, L"");
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));

	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Specification of the mode of Tools or Server or Client
	if ((GetParamStr(o, "CLIENT") == NULL && GetParamStr(o, "SERVER") == NULL && GetParamStr(o, "TOOLS") == NULL) ||
		(GetParamStr(o, "CLIENT") != NULL && GetParamStr(o, "SERVER") != NULL && GetParamStr(o, "TOOLS") != NULL))
	{
		wchar_t *ret;
		UINT code;
		// The mode of Tools or Server or Client is not specified
		c->Write(c, _UU("CMD_VPNCMD_CS_1"));

		ret = c->ReadLine(c, _UU("CMD_VPNCMD_CS_2"), true);

		code = UniToInt(ret);
		Free(ret);

		switch (code)
		{
		case 1:
			// Server
			server = true;
			break;

		case 2:
			// Client
			client = true;
			break;

		case 3:
			// Tools
			tools = true;
			break;

		default:
			// Unspecified
			FreeParamValueList(o);
			return ERR_USER_CANCEL;
		}

		c->Write(c, L"");
	}
	else
	{
		if (GetParamStr(o, "SERVER") != NULL)
		{
			server = true;
		}
		else if (GetParamStr(o, "CLIENT") != NULL)
		{
			client = true;
		}
		else
		{
			tools = true;
		}
	}

	// Destination host name
	target = CopyStr(GetParamStr(o, "[host:port]"));

	if (target == NULL && tools == false)
	{
		wchar_t *str;
		// Input a host name
		if (server)
		{
			c->Write(c, _UU("CMD_VPNCMD_HOST_1"));
		}
		else if (client)
		{
			c->Write(c, _UU("CMD_VPNCMD_HOST_2"));
		}

		str = c->ReadLine(c, _UU("CMD_VPNCMD_HOST_3"), true);
		c->Write(c, L"");
		target = CopyUniToStr(str);
		Free(str);

		if (target == NULL)
		{
			// Cancel
			FreeParamValueList(o);
			return ERR_USER_CANCEL;
		}

		if (IsEmptyStr(target))
		{
			Free(target);
			target = CopyStr("localhost");
		}
	}
	else
	{
		// User specifies a host name
		host_inputted = true;
	}

	if (tools == false)
	{
		if (ParseHostPort(target, &hostname, &port, 443) == false)
		{
			c->Write(c, _UU("CMD_MSG_INVALID_HOSTNAME"));
			Free(target);
			FreeParamValueList(o);
			return ERR_INVALID_PARAMETER;
		}
	}

	// Password
	password = GetParamStr(o, "PASSWORD");
	if (password == NULL)
	{
		password = "";
	}

	// Command line
	cmdline = GetParamUniStr(o, "CMD");

	if (server)
	{
		// Process as the server
		char *hub;
		char *adminhub = NULL;

		hub = CopyStr(GetParamStr(o, "HUB"));
		adminhub = GetParamStr(o, "ADMINHUB");

		// Decide the Virtual HUB to be specified in the Virtual HUB management mode
		if (hub == NULL)
		{
			if (host_inputted == false)
			{
				wchar_t *s;
				// If the user does not specify a host name on the command line,
				// get also a Virtual HUB name by displaying the prompt
				c->Write(c, _UU("CMD_VPNCMD_HUB_1"));

				s = c->ReadLine(c, _UU("CMD_VPNCMD_HUB_2"), true);

				hub = CopyUniToStr(s);
				Free(s);
			}
		}

		if (IsEmptyStr(hub))
		{
			Free(hub);
			hub = NULL;
		}
		if (IsEmptyStr(adminhub))
		{
			adminhub = NULL;
		}

		retcode = PsConnect(c, hostname, port, hub, adminhub, cmdline, password);

		Free(hub);
	}
	else if (client)
	{
		// Treated as a client
		Trim(target);

		retcode = PcConnect(c, target, cmdline, password);
	}
	else if (tools)
	{
		// Treated as a VPN Tools
		retcode = PtConnect(c, cmdline);
	}

	Free(hostname);
	Free(target);
	FreeParamValueList(o);

	return retcode;
}

// Entry point of vpncmd
UINT CommandMain(wchar_t *command_line)
{
	UINT ret = 0;
	wchar_t *infile, *outfile;
	char *a_infile, *a_outfile;
	wchar_t *csvmode;
	wchar_t *programming_mode;
	CONSOLE *c;

	// Validate arguments
	if (command_line == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	// Look ahead only items of /in and /out
	infile = ParseCommand(command_line, L"in");
	outfile = ParseCommand(command_line, L"out");
	if (UniIsEmptyStr(infile))
	{
		Free(infile);
		infile = NULL;
	}
	if (UniIsEmptyStr(outfile))
	{
		Free(outfile);
		outfile = NULL;
	}

	a_infile = CopyUniToStr(infile);
	a_outfile = CopyUniToStr(outfile);

	// Allocate the local console
	c = NewLocalConsole(infile, outfile);
	if (c != NULL)
	{
		// Definition of commands of vpncmd
		CMD cmd[] =
		{
			{"vpncmd", VpnCmdProc},
		};

		// Read ahead to check the CSV mode
		csvmode = ParseCommand(command_line, L"csv");
		if(csvmode != NULL)
		{
			Free(csvmode);
			c->ConsoleType = CONSOLE_CSV;
		}

		programming_mode = ParseCommand(command_line, L"programming");
		if (programming_mode != NULL)
		{
			Free(programming_mode);
			c->ProgrammingMode = true;
		}

		if (DispatchNextCmdEx(c, command_line, ">", cmd, sizeof(cmd) / sizeof(cmd[0]), NULL) == false)
		{
			ret = ERR_INVALID_PARAMETER;
		}
		else
		{
			ret = c->RetCode;
		}

		// Release the local console
		c->Free(c);
	}
	else
	{
		Print("Error: Couldn't open local console.\n");
	}

	Free(a_infile);
	Free(a_outfile);
	Free(infile);
	Free(outfile);

	return ret;
}

#ifdef	OS_WIN32
// Debug information write mode
void Win32CmdDebug(bool is_uac)
{
	wchar_t *dst;
	wchar_t def_filename[MAX_SIZE];
	SYSTEMTIME st;

	InitWinUi(_UU("CMD_DEBUG_SOFTNAME"), NULL, 0);

	UniPrint(_UU("CMD_DEBUG_PRINT"));

	if (MsIsWin2000OrGreater() == false)
	{
		MsgBox(NULL, 0x00000040L, _UU("CMD_DEBUG_NOT_2000"));
		goto LABEL_CLEANUP;
	}

	if ((MsIsVista() == false || is_uac) && MsIsAdmin() == false)
	{
		MsgBox(NULL, 0x00000040L, _UU("CMD_DEBUG_NOT_ADMIN"));
		goto LABEL_CLEANUP;
	}

	if (MsIsVista() && MsIsAdmin() == false)
	{
		void *process_handle = NULL;

		// Launch myself using the UAC
		if (MsExecuteEx2W(MsGetExeFileNameW(), L"/debug_uac", &process_handle, true) == false)
		{
			MsgBox(NULL, 0x00000030L, _UU("CMD_DEBUG_UAC_FAILED"));
			return;
		}

		MsCloseHandle(process_handle);
		goto LABEL_CLEANUP;
	}

	LocalTime(&st);

	UniFormat(def_filename, sizeof(def_filename), L"vpn_debuginfo_%04u%02u%02u_%02u%02u%02u.zip",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	// Specify the destination
	dst = SaveDlg(NULL, _UU("DLG_ZIP_FILER"), _UU("CMD_DEBUG_SAVE_TITLE"), def_filename, L".zip");
	if (dst != NULL)
	{
		if (MsSaveSystemInfo(dst) == false)
		{
			// Failure
			MsgBoxEx(NULL, 0x00000030L, _UU("CMD_DEBUG_NG"), dst);
		}
		else
		{
			// Success
			MsgBoxEx(NULL, 0x00000040L, _UU("CMD_DEBUG_OK"), dst);
		}

		Free(dst);
	}

LABEL_CLEANUP:
	FreeWinUi();
}

#endif	// OS_WIN32

