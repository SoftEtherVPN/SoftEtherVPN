// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Client.c
// Client Manager

#include "CedarPch.h"

static CLIENT *client = NULL;
static LISTENER *cn_listener = NULL;
static LOCK *cn_listener_lock = NULL;
static UINT64 cn_next_allow = 0;
static LOCK *ci_active_sessions_lock = NULL;
static UINT ci_num_active_sessions = 0;


// In Windows 8 or later, change unreasonable setting of WCM to ensure normal VPN communication
void CiDisableWcmNetworkMinimize(CLIENT *c)
{
#ifdef	OS_WIN32
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (c->Config.NoChangeWcmNetworkSettingOnWindows8)
	{
		return;
	}

	MsDisableWcmNetworkMinimize();
#endif	// OS_WIN32
}

// Compare RPC_CLIENT_ENUM_ACCOUNT_ITEM items by last connected date (Reverse)
int CiCompareClientAccountEnumItemByLastConnectDateTime(void *p1, void *p2)
{
	RPC_CLIENT_ENUM_ACCOUNT_ITEM *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(RPC_CLIENT_ENUM_ACCOUNT_ITEM **)p1;
	a2 = *(RPC_CLIENT_ENUM_ACCOUNT_ITEM **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}
	if (a1->LastConnectDateTime > a2->LastConnectDateTime)
	{
		return -1;
	}
	else if (a1->LastConnectDateTime < a2->LastConnectDateTime)
	{
		return 1;
	}

	return 0;
}

// If machine changed, reshuffle MAC address for all virtual NIC 
void CiChangeAllVLanMacAddressIfMachineChanged(CLIENT *c)
{
	UCHAR current_hash_new[SHA1_SIZE];
	UCHAR current_hash[SHA1_SIZE];
	UCHAR current_hash_old[SHA1_SIZE];
	UCHAR saved_hash[SHA1_SIZE];
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

#ifdef OS_WIN32
	if (MsIsAdmin() == false)
	{
		return;
	}
#endif

	CiGetCurrentMachineHashNew(current_hash_new);
	CiGetCurrentMachineHash(current_hash);
	CiGetCurrentMachineHashOld(current_hash_old);

	if (CiReadLastMachineHash(saved_hash) == false)
	{
		CiWriteLastMachineHash(current_hash_new);
		return;
	}

	if (Cmp(saved_hash, current_hash_old, SHA1_SIZE) == 0)
	{
		CiWriteLastMachineHash(current_hash_new);
		return;
	}

	if (Cmp(saved_hash, current_hash, SHA1_SIZE) == 0)
	{
		CiWriteLastMachineHash(current_hash_new);
		return;
	}

	if (Cmp(saved_hash, current_hash_new, SHA1_SIZE) == 0)
	{
		return;
	}

	if (CiWriteLastMachineHash(current_hash_new) == false)
	{
		return;
	}

	CiChangeAllVLanMacAddress(c);
}

// Get current machine hash (Old)
void CiGetCurrentMachineHashOld(void *data)
{
	char name[MAX_PATH];
	char *product_id = NULL;
	// Validate arguments
	if (data == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	// Product ID
	product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId");
	if (product_id == NULL)
	{
		product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId");
	}

	StrCpy(name, sizeof(name), product_id);

	Free(product_id);

#else	// OS_WIN32
	GetMachineName(name, sizeof(name));
#endif	// OS_WIN32

	Trim(name);
	StrUpper(name);

	Sha0(data, name, StrLen(name));
}

// Get current machine hash
void CiGetCurrentMachineHash(void *data)
{
	char name[MAX_PATH];
	char *product_id = NULL;
	// Validate arguments
	if (data == NULL)
	{
		return;
	}

	GetMachineName(name, sizeof(name));

	Trim(name);
	StrUpper(name);

	Sha0(data, name, StrLen(name));
}

// Get current machine hash (without using domain name)
void CiGetCurrentMachineHashNew(void *data)
{
	char name[MAX_PATH];
	char *p;

	// Validate arguments
	if (data == NULL)
	{
		return;
	}

	GetMachineName(name, sizeof(name));

	// Ignore after first period(.)
	for(p=name; *p; p++)
		if(*p == '.')
			*p = 0;

	Trim(name);
	StrUpper(name);

	Sha0(data, name, StrLen(name));
}


// Write machine hash
bool CiWriteLastMachineHash(void *data)
{
	// Validate arguments
	if (data == NULL)
	{
		return false;
	}

#ifdef OS_WIN32
	if (MsRegWriteBinEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "LastMachineHash", data, SHA1_SIZE, true) == false)
	{
		return false;
	}

	return true;
#else	// OS_WIN32
	return false;
#endif	// OS_WIN32
}

// Get previous machine hash
bool CiReadLastMachineHash(void *data)
{
	BUF *b = NULL;
	// Validate arguments
	if (data == NULL)
	{
		return false;
	}

#ifdef OS_WIN32
	b = MsRegReadBinEx(REG_LOCAL_MACHINE, MS_REG_TCP_SETTING_KEY, "LastMachineHash", true);
	if (b == NULL)
	{
		return false;
	}
	if (b->Size == SHA1_SIZE)
	{
		Copy(data, b->Buf, b->Size);
		FreeBuf(b);

		return true;
	}

	FreeBuf(b);
	return false;
#else	// OS_WIN32
	return false;
#endif	// OS_WIN32
}

// If the MAC address of each virtual LAN card has been eliminated, set it to random numbers
// (measures for Windows 8 -> 8.1 upgrade problem)
void CiChangeAllVLanMacAddressIfCleared(CLIENT *c)
{
#ifdef	OS_WIN32
	RPC_CLIENT_ENUM_VLAN t;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (MsIsInfCatalogRequired() == false)
	{
		// Not required for other than Windows 8
		return;
	}

	Zero(&t, sizeof(t));
	if (CtEnumVLan(c, &t))
	{
		UINT i;

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_CLIENT_ENUM_VLAN_ITEM *e = t.Items[i];
			UCHAR mac[6];

			if (StrToMac(mac, e->MacAddress))
			{
				if (mac[0] == 0x00 &&
					mac[1] == 0x00 &&
					mac[2] == 0x01 &&
					mac[3] == 0x00 &&
					mac[4] == 0x00 &&
					mac[5] == 0x01)
				{
					char *name = e->DeviceName;
					RPC_CLIENT_SET_VLAN s;
					UCHAR mac[6];

					GenMacAddress(mac);

					Zero(&s, sizeof(s));
					StrCpy(s.DeviceName, sizeof(s.DeviceName), name);

					MacToStr(s.MacAddress, sizeof(s.MacAddress), mac);

					CtSetVLan(c, &s);
				}
			}
		}

		CiFreeClientEnumVLan(&t);
	}
#endif	// OS_WIN32
}

// Set the MAC address of all virtual LAN cards to random number
void CiChangeAllVLanMacAddress(CLIENT *c)
{
	RPC_CLIENT_ENUM_VLAN t;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	Zero(&t, sizeof(t));
	if (CtEnumVLan(c, &t))
	{
		UINT i;

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_CLIENT_ENUM_VLAN_ITEM *e = t.Items[i];
			UCHAR mac[6];

			if (StrToMac(mac, e->MacAddress) && ((mac[0] == 0x00 && mac[1] == 0xAC) || (mac[0] == 0x5E)))
			{
				char *name = e->DeviceName;
				RPC_CLIENT_SET_VLAN s;
				UCHAR mac[6];

				GenMacAddress(mac);

				Zero(&s, sizeof(s));
				StrCpy(s.DeviceName, sizeof(s.DeviceName), name);

				MacToStr(s.MacAddress, sizeof(s.MacAddress), mac);

				CtSetVLan(c, &s);
			}
		}

		CiFreeClientEnumVLan(&t);
	}
}

// Wait for preparation of notification service to complete
void CnWaitForCnServiceReady()
{
	UINT64 start_time = Tick64();

	while ((start_time + (UINT64)CLIENT_WAIT_CN_READY_TIMEOUT) >= Tick64())
	{
		if (CnIsCnServiceReady())
		{
			break;
		}

		SleepThread(100);
	}
}

// Check whether preparation of notification service completed
bool CnIsCnServiceReady()
{
	SOCK *s;
	// Confirm running the notification service
	if (CnCheckAlreadyExists(false) == false)
	{
		// Not running
		return false;
	}

	// Try to connect to the TCP port
	s = ConnectEx("localhost", CLIENT_NOTIFY_PORT, 500);
	if (s == NULL)
	{
		// The TCP port is not opened
		return false;
	}

	Disconnect(s);
	ReleaseSock(s);

	// Running
	return true;
}

// Check whether the notification service is already running
bool CnCheckAlreadyExists(bool lock)
{
#ifdef	OS_WIN32
	return Win32CnCheckAlreadyExists(lock);
#else
	return false;
#endif
}

typedef struct CNC_STATUS_PRINTER_WINDOW_PARAM
{
	THREAD *Thread;
	SESSION *Session;
	SOCK *Sock;
} CNC_STATUS_PRINTER_WINDOW_PARAM;

typedef struct CNC_CONNECT_ERROR_DLG_THREAD_PARAM
{
	SESSION *Session;
	SOCK *Sock;
	bool HaltThread;
	EVENT *Event;
} CNC_CONNECT_ERROR_DLG_THREAD_PARAM;

// Thread to stop forcibly the Certificate check dialog client
void CncCheckCertHaltThread(THREAD *thread, void *param)
{
	CNC_CONNECT_ERROR_DLG_THREAD_PARAM *dp = (CNC_CONNECT_ERROR_DLG_THREAD_PARAM *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		if (dp->Session->Halt || dp->HaltThread)
		{
			break;
		}

		Wait(dp->Event, 100);
	}

	Disconnect(dp->Sock);
}

// Show the certification check dialog
void CncCheckCert(SESSION *session, UI_CHECKCERT *dlg)
{
	SOCK *s;
	PACK *p;
	CNC_CONNECT_ERROR_DLG_THREAD_PARAM *dp;
	THREAD *t;
	// Validate arguments
	if (dlg == NULL || session == NULL)
	{
		return;
	}

	s = CncConnect();
	if (s == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "function", "check_cert");
	PackAddUniStr(p, "AccountName", dlg->AccountName);
	PackAddStr(p, "ServerName", dlg->ServerName);
	PackAddX(p, "x", dlg->x);
	PackAddX(p, "parent_x", dlg->parent_x);
	PackAddX(p, "old_x", dlg->old_x);
	PackAddBool(p, "DiffWarning", dlg->DiffWarning);
	PackAddBool(p, "Ok", dlg->Ok);
	PackAddBool(p, "SaveServerCert", dlg->SaveServerCert);

	SendPack(s, p);
	FreePack(p);

	dp = ZeroMalloc(sizeof(CNC_CONNECT_ERROR_DLG_THREAD_PARAM));
	dp->Sock = s;
	dp->Event = NewEvent();
	dp->Session = session;

	t = NewThread(CncCheckCertHaltThread, dp);

	p = RecvPack(s);
	if (p != NULL)
	{
		dlg->Ok = PackGetBool(p, "Ok");
		dlg->DiffWarning = PackGetBool(p, "DiffWarning");
		dlg->SaveServerCert = PackGetBool(p, "SaveServerCert");

		FreePack(p);
	}

	dp->HaltThread = true;
	Set(dp->Event);

	WaitThread(t, INFINITE);

	ReleaseEvent(dp->Event);
	Free(dp);
	ReleaseThread(t);

	Disconnect(s);
	ReleaseSock(s);
}

// Smart card signature dialog
bool CncSecureSignDlg(SECURE_SIGN *sign)
{
	SOCK *s;
	PACK *p;
	bool ret = false;
	// Validate arguments
	if (sign == NULL)
	{
		return false;
	}

	s = CncConnect();
	if (s == NULL)
	{
		return false;
	}

	p = NewPack();
	PackAddStr(p, "function", "secure_sign");
	OutRpcSecureSign(p, sign);

	SendPack(s, p);
	FreePack(p);

	p = RecvPack(s);
	if (p != NULL)
	{
		ret = PackGetBool(p, "ret");

		if (ret)
		{
			FreeRpcSecureSign(sign);

			Zero(sign, sizeof(SECURE_SIGN));
			InRpcSecureSign(sign, p);
		}

		FreePack(p);
	}

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

// Show the NIC information dialog
SOCK *CncNicInfo(UI_NICINFO *info)
{
	SOCK *s;
	PACK *p;
	// Validate arguments
	if (info == NULL)
	{
		return NULL;
	}

	s = CncConnectEx(200);
	if (s == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "function", "nicinfo");
	PackAddStr(p, "NicName", info->NicName);
	PackAddUniStr(p, "AccountName", info->AccountName);

	SendPack(s, p);
	FreePack(p);

	return s;
}

// Close the NIC information dialog
void CncNicInfoFree(SOCK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Disconnect(s);
	ReleaseSock(s);
}

// Show the message dialog
SOCK *CncMsgDlg(UI_MSG_DLG *dlg)
{
	SOCK *s;
	PACK *p;
	char *utf;
	// Validate arguments
	if (dlg == NULL)
	{
		return NULL;
	}

	s = CncConnectEx(200);
	if (s == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "function", "msg_dialog");
	PackAddStr(p, "ServerName", dlg->ServerName);
	PackAddStr(p, "HubName", dlg->HubName);
	utf = CopyUniToUtf(dlg->Msg);
	PackAddData(p, "Msg", utf, StrLen(utf));
	Free(utf);

	SendPack(s, p);
	FreePack(p);

	return s;
}

// Close the message dialog
void CndMsgDlgFree(SOCK *s)
{
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	Disconnect(s);
	ReleaseSock(s);
}

// Show the password input dialog
bool CncPasswordDlg(SESSION *session, UI_PASSWORD_DLG *dlg)
{
	SOCK *s;
	PACK *p;
	CNC_CONNECT_ERROR_DLG_THREAD_PARAM *dp;
	THREAD *t;
	bool ret = false;
	// Validate arguments
	if (dlg == NULL || session == NULL)
	{
		return false;
	}

	s = CncConnect();
	if (s == NULL)
	{
		Wait(session->HaltEvent, session->RetryInterval);
		return true;
	}

	p = NewPack();
	PackAddStr(p, "function", "password_dialog");
	PackAddInt(p, "Type", dlg->Type);
	PackAddStr(p, "Username", dlg->Username);
	PackAddStr(p, "Password", dlg->Password);
	PackAddStr(p, "ServerName", dlg->ServerName);
	PackAddInt(p, "RetryIntervalSec", dlg->RetryIntervalSec);
	PackAddBool(p, "ProxyServer", dlg->ProxyServer);
	PackAddBool(p, "AdminMode", dlg->AdminMode);
	PackAddBool(p, "ShowNoSavePassword", dlg->ShowNoSavePassword);
	PackAddBool(p, "NoSavePassword", dlg->NoSavePassword);

	SendPack(s, p);
	FreePack(p);

	dp = ZeroMalloc(sizeof(CNC_CONNECT_ERROR_DLG_THREAD_PARAM));
	dp->Session = session;
	dp->Sock = s;
	dp->Event = NewEvent();

	t = NewThread(CncConnectErrorDlgHaltThread, dp);

	p = RecvPack(s);
	if (p != NULL)
	{
		ret = PackGetBool(p, "ok");
		dlg->NoSavePassword = PackGetBool(p, "NoSavePassword");
		dlg->ProxyServer = PackGetBool(p, "ProxyServer");
		dlg->Type = PackGetInt(p, "Type");
		PackGetStr(p, "Username", dlg->Username, sizeof(dlg->Username));
		PackGetStr(p, "Password", dlg->Password, sizeof(dlg->Password));

		FreePack(p);
	}

	dp->HaltThread = true;
	Set(dp->Event);

	WaitThread(t, INFINITE);

	ReleaseEvent(dp->Event);
	Free(dp);
	ReleaseThread(t);

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

// Thread to stop the connection error dialog client forcibly
void CncConnectErrorDlgHaltThread(THREAD *thread, void *param)
{
	CNC_CONNECT_ERROR_DLG_THREAD_PARAM *dp = (CNC_CONNECT_ERROR_DLG_THREAD_PARAM *)param;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	while (true)
	{
		if (dp->Session->Halt || dp->HaltThread)
		{
			break;
		}

		Wait(dp->Event, 100);
	}

	Disconnect(dp->Sock);
}

// Show the connection error dialog
bool CncConnectErrorDlg(SESSION *session, UI_CONNECTERROR_DLG *dlg)
{
	SOCK *s;
	PACK *p;
	CNC_CONNECT_ERROR_DLG_THREAD_PARAM *dp;
	THREAD *t;
	bool ret = false;
	// Validate arguments
	if (dlg == NULL || session == NULL)
	{
		return false;
	}

	s = CncConnect();
	if (s == NULL)
	{
		Wait(session->HaltEvent, session->RetryInterval);
		return true;
	}

	p = NewPack();
	PackAddStr(p, "function", "connecterror_dialog");
	PackAddUniStr(p, "AccountName", dlg->AccountName);
	PackAddStr(p, "ServerName", dlg->ServerName);
	PackAddInt(p, "Err", dlg->Err);
	PackAddInt(p, "CurrentRetryCount", dlg->CurrentRetryCount);
	PackAddInt(p, "RetryLimit", dlg->RetryLimit);
	PackAddInt(p, "RetryIntervalSec", dlg->RetryIntervalSec);
	PackAddBool(p, "HideWindow", dlg->HideWindow);

	SendPack(s, p);
	FreePack(p);

	dp = ZeroMalloc(sizeof(CNC_CONNECT_ERROR_DLG_THREAD_PARAM));
	dp->Session = session;
	dp->Sock = s;
	dp->Event = NewEvent();

	t = NewThread(CncConnectErrorDlgHaltThread, dp);

	p = RecvPack(s);
	if (p != NULL)
	{
		ret = PackGetBool(p, "ok");
		dlg->HideWindow = PackGetBool(p, "HideWindow");

		FreePack(p);
	}

	dp->HaltThread = true;
	Set(dp->Event);

	WaitThread(t, INFINITE);

	ReleaseEvent(dp->Event);
	Free(dp);
	ReleaseThread(t);

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

// Thread for the status indicator client
void CncStatusPrinterWindowThreadProc(THREAD *thread, void *param)
{
	CNC_STATUS_PRINTER_WINDOW_PARAM *pp;
	SOCK *sock;
	PACK *p;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	pp = (CNC_STATUS_PRINTER_WINDOW_PARAM *)param;
	sock = pp->Sock;
	pp->Thread = thread;
	AddRef(pp->Thread->ref);

	NoticeThreadInit(thread);

	p = RecvPack(sock);
	if (p != NULL)
	{
		// Stop the session
		StopSessionEx(pp->Session, true);

		FreePack(p);
	}
}

// Create a status indicator client
SOCK *CncStatusPrinterWindowStart(SESSION *s)
{
	SOCK *sock;
	PACK *p;
	THREAD *t;
	CNC_STATUS_PRINTER_WINDOW_PARAM *param;
	// Validate arguments
	if (s == NULL)
	{
		return NULL;
	}

	sock = CncConnect();

	if (sock == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "function", "status_printer");
	PackAddUniStr(p, "account_name", s->Account->ClientOption->AccountName);

	if (SendPack(sock, p) == false)
	{
		FreePack(p);
		ReleaseSock(sock);

		return NULL;
	}

	FreePack(p);

	param = ZeroMalloc(sizeof(CNC_STATUS_PRINTER_WINDOW_PARAM));
	param->Sock = sock;
	param->Session = s;

	sock->Param = param;

	t = NewThread(CncStatusPrinterWindowThreadProc, param);
	WaitThreadInit(t);

	ReleaseThread(t);

	return sock;
}

// Send a string to the status indicator
void CncStatusPrinterWindowPrint(SOCK *s, wchar_t *str)
{
	PACK *p;
	// Validate arguments
	if (s == NULL || str == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddUniStr(p, "string", str);
	SendPack(s, p);
	FreePack(p);
}

// Stop the status indicator client
void CncStatusPrinterWindowStop(SOCK *s)
{
	CNC_STATUS_PRINTER_WINDOW_PARAM *param;
	// Validate arguments
	if (s == NULL)
	{
		return;
	}

	param = (CNC_STATUS_PRINTER_WINDOW_PARAM *)s->Param;

	// Disconnect the client socket 
	Disconnect(s);

	// Terminate the thread
	WaitThread(param->Thread, INFINITE);
	ReleaseThread(param->Thread);

	Free(param);
	ReleaseSock(s);
}

// Start the driver installer for Windows Vista
bool CncExecDriverInstaller(char *arg)
{
	SOCK *s = CncConnect();
	PACK *p;
	bool ret;
	if (s == NULL)
	{
		return false;
	}

	p = NewPack();
	PackAddStr(p, "function", "exec_driver_installer");
	PackAddStr(p, "arg", arg);

	SendPack(s, p);
	FreePack(p);

	p = RecvPack(s);
	if (p == NULL)
	{
		Disconnect(s);
		ReleaseSock(s);
		return false;
	}

	ret = PackGetBool(p, "ret");

	FreePack(p);

	Disconnect(s);
	ReleaseSock(s);

	return ret;
}

// Let the current running client notification services releasing the socket
void CncReleaseSocket()
{
	SOCK *s = CncConnect();
	PACK *p;
	if (s == NULL)
	{
		return;
	}

	p = NewPack();
	PackAddStr(p, "function", "release_socket");

#ifdef OS_WIN32
	PackAddInt(p, "pid", MsGetProcessId());
#endif	// OS_WIN32

	SendPack(s, p);
	FreePack(p);

	Disconnect(s);
	ReleaseSock(s);
}

// Terminate the process of the client notification service
void CncExit()
{
	SOCK *s = CncConnectEx(256);
	PACK *p;
	if (s != NULL)
	{
		p = NewPack();
		PackAddStr(p, "function", "exit");

		SendPack(s, p);

		FreePack(p);

		FreePack(RecvPack(s));

		Disconnect(s);
		ReleaseSock(s);
	}

#ifdef	OS_WIN32
	MsKillOtherInstanceEx("vpnclient");
#endif	// OS_WIN32
}

// Connect to the client notification service
SOCK *CncConnect()
{
	return CncConnectEx(0);
}
SOCK *CncConnectEx(UINT timeout)
{
	SOCK *s = ConnectEx("localhost", CLIENT_NOTIFY_PORT, timeout);

	return s;
}

#ifdef	OS_WIN32

// Thread for the certificate check dialog
void Win32CnCheckCertThreadProc(THREAD *thread, void *param)
{
	UI_CHECKCERT *dlg;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	dlg = (UI_CHECKCERT *)param;

	CheckCertDlg(dlg);
	{
		PACK *p = NewPack();

		PackAddBool(p, "Ok", dlg->Ok);
		PackAddBool(p, "SaveServerCert", dlg->SaveServerCert);

		SendPack(dlg->Sock, p);
		FreePack(p);

		FreePack(RecvPack(dlg->Sock));
	}

	Disconnect(dlg->Sock);
}

// Certificate check dialog
void Win32CnCheckCert(SOCK *s, PACK *p)
{
	UI_CHECKCERT dlg;
	THREAD *t;
	Zero(&dlg, sizeof(dlg));
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetUniStr(p, "AccountName", dlg.AccountName, sizeof(dlg.AccountName));
	PackGetStr(p, "ServerName", dlg.ServerName, sizeof(dlg.ServerName));
	dlg.x = PackGetX(p, "x");
	dlg.parent_x = PackGetX(p, "parent_x");
	dlg.old_x = PackGetX(p, "old_x");
	dlg.DiffWarning = PackGetBool(p, "DiffWarning");
	dlg.Ok = PackGetBool(p, "Ok");
	dlg.SaveServerCert = PackGetBool(p, "SaveServerCert");
	dlg.Sock = s;

	t = NewThread(Win32CnCheckCertThreadProc, &dlg);

	FreePack(RecvPack(s));

	dlg.Halt = true;

	WaitThread(t, INFINITE);
	ReleaseThread(t);

	FreeX(dlg.parent_x);
	FreeX(dlg.old_x);
	FreeX(dlg.x);
}

// Message display dialog thread procedure
void Win32CnMsgDlgThreadProc(THREAD *thread, void *param)
{
	UI_MSG_DLG *dlg = (UI_MSG_DLG *)param;
	wchar_t tmp[MAX_SIZE];
	char url[MAX_SIZE];
	// Validate arguments
	if (thread == NULL || dlg == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), _UU("CM_MSG_TITLE"),
		dlg->ServerName, dlg->HubName);

	if (IsURLMsg(dlg->Msg, url, sizeof(url)) == false)
	{
		OnceMsgEx(NULL, tmp, dlg->Msg, true, 167, &dlg->Halt);
	}
	else
	{
		if (MsExecute(url, NULL) == false)
		{
			OnceMsgEx(NULL, tmp, dlg->Msg, true, 167, &dlg->Halt);
		}
	}

	Disconnect(dlg->Sock);
}

// NIC information dialog thread procedure
void Win32CnNicInfoThreadProc(THREAD *thread, void *param)
{
	UI_NICINFO *info = (UI_NICINFO *)param;
	// Validate arguments
	if (thread == NULL || info == NULL)
	{
		return;
	}

	if (MsIsNt())
	{
		// Do not show a dialog on Windows 9x system
		NicInfo(info);
	}

	Disconnect(info->Sock);
}

// NIC information dialog
void Win32CnNicInfo(SOCK *s, PACK *p)
{
	UI_NICINFO info;
	THREAD *t;
	Zero(&info, sizeof(info));
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetStr(p, "NicName", info.NicName, sizeof(info.NicName));
	PackGetUniStr(p, "AccountName", info.AccountName, sizeof(info.AccountName));

	info.Sock = s;

	t = NewThread(Win32CnNicInfoThreadProc, &info);

	FreePack(RecvPack(s));

	info.Halt = true;

	WaitThread(t, INFINITE);
	ReleaseThread(t);
}

// Message display dialog
void Win32CnMsgDlg(SOCK *s, PACK *p)
{
	UI_MSG_DLG dlg;
	THREAD *t;
	UINT utf_size;
	char *utf;
	wchar_t *msg;
	Zero(&dlg, sizeof(dlg));
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetStr(p, "ServerName", dlg.ServerName, sizeof(dlg.ServerName));
	PackGetStr(p, "HubName", dlg.HubName, sizeof(dlg.HubName));

	utf_size = PackGetDataSize(p, "Msg");
	utf = ZeroMalloc(utf_size + 8);

	PackGetData(p, "Msg", utf);

	msg = CopyUtfToUni(utf);
	Free(utf);

	dlg.Sock = s;
	dlg.Msg = msg;

	t = NewThread(Win32CnMsgDlgThreadProc, &dlg);

	FreePack(RecvPack(s));

	dlg.Halt = true;

	WaitThread(t, INFINITE);
	ReleaseThread(t);

	Free(msg);
}

// Thread for Password input dialog
void Win32CnPasswordDlgThreadProc(THREAD *thread, void *param)
{
	UI_PASSWORD_DLG *dlg;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	dlg = (UI_PASSWORD_DLG *)param;

	if (PasswordDlg(NULL, dlg))
	{
		PACK *p = NewPack();

		PackAddBool(p, "ok", true);
		PackAddStr(p, "Username", dlg->Username);
		PackAddStr(p, "Password", dlg->Password);
		PackAddInt(p, "Type", dlg->Type);
		PackAddBool(p, "ProxyServer", dlg->ProxyServer);
		PackAddBool(p, "NoSavePassword", dlg->NoSavePassword);

		SendPack(dlg->Sock, p);
		FreePack(p);

		FreePack(RecvPack(dlg->Sock));
	}

	Disconnect(dlg->Sock);
}

// Password input dialog
void Win32CnPasswordDlg(SOCK *s, PACK *p)
{
	UI_PASSWORD_DLG dlg;
	THREAD *t = NULL;
	Zero(&dlg, sizeof(dlg));
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	dlg.Type = PackGetInt(p, "Type");
	PackGetStr(p, "Username", dlg.Username, sizeof(dlg.Username));
	PackGetStr(p, "Password", dlg.Password, sizeof(dlg.Password));
	PackGetStr(p, "ServerName", dlg.ServerName, sizeof(dlg.ServerName));
	dlg.RetryIntervalSec = PackGetInt(p, "RetryIntervalSec");
	dlg.ProxyServer = PackGetBool(p, "ProxyServer");
	dlg.AdminMode = PackGetBool(p, "AdminMode");
	dlg.ShowNoSavePassword = PackGetBool(p, "ShowNoSavePassword");
	dlg.NoSavePassword = PackGetBool(p, "NoSavePassword");
	dlg.CancelEvent = NewEvent();
	dlg.Sock = s;

	t = NewThread(Win32CnPasswordDlgThreadProc, &dlg);

	FreePack(RecvPack(s));

	Set(dlg.CancelEvent);

	WaitThread(t, INFINITE);
	ReleaseEvent(dlg.CancelEvent);
	ReleaseThread(t);
}

// Thread for the connection error dialog
void Win32CnConnectErrorDlgThreadProc(THREAD *thread, void *param)
{
	UI_CONNECTERROR_DLG *dlg;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	dlg = (UI_CONNECTERROR_DLG *)param;

	if (ConnectErrorDlg(dlg))
	{
		PACK *p = NewPack();

		PackAddBool(p, "ok", true);
		PackAddBool(p, "HideWindow", dlg->HideWindow);

		SendPack(dlg->Sock, p);
		FreePack(p);

		FreePack(RecvPack(dlg->Sock));
	}

	Disconnect(dlg->Sock);
}

// Connection Error dialog (Win32)
void Win32CnConnectErrorDlg(SOCK *s, PACK *p)
{
	UI_CONNECTERROR_DLG dlg;
	THREAD *t;
	Zero(&dlg, sizeof(dlg));
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetUniStr(p, "AccountName", dlg.AccountName, sizeof(dlg.AccountName));
	PackGetStr(p, "ServerName", dlg.ServerName, sizeof(dlg.ServerName));
	dlg.Err = PackGetInt(p, "Err");
	dlg.CurrentRetryCount = PackGetInt(p, "CurrentRetryCount");
	dlg.RetryLimit = PackGetInt(p, "RetryLimit");
	dlg.RetryIntervalSec = PackGetInt(p, "RetryIntervalSec");
	dlg.HideWindow = PackGetBool(p, "HideWindow");
	dlg.CancelEvent = NewEvent();
	dlg.Sock = s;

	t = NewThread(Win32CnConnectErrorDlgThreadProc, &dlg);

	FreePack(RecvPack(s));

	Set(dlg.CancelEvent);

	WaitThread(t, INFINITE);
	ReleaseEvent(dlg.CancelEvent);
	ReleaseThread(t);
}

// Status indicator (Win32)
void Win32CnStatusPrinter(SOCK *s, PACK *p)
{
	STATUS_WINDOW *w;
	wchar_t account_name[MAX_ACCOUNT_NAME_LEN + 1];
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	PackGetUniStr(p, "account_name", account_name, sizeof(account_name));

	w = StatusPrinterWindowStart(s, account_name);

	while (true)
	{
		PACK *p = RecvPack(s);

		if (p == NULL)
		{
			// Exit the dialog because it is disconnected
			break;
		}
		else
		{
			wchar_t tmp[MAX_SIZE];

			// Rewrite the string
			PackGetUniStr(p, "string", tmp, sizeof(tmp));

			StatusPrinterWindowPrint(w, tmp);

			FreePack(p);
		}
	}

	StatusPrinterWindowStop(w);
}

// Start the driver installer (for Windows Vista)
void Win32CnExecDriverInstaller(SOCK *s, PACK *p)
{
	char arg[MAX_SIZE];
	bool ret;
	void *helper = NULL;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	if (PackGetStr(p, "arg", arg, sizeof(arg)) == false)
	{
		return;
	}

	if (MsIsVista())
	{
		helper = CmStartUacHelper();
	}

	ret = MsExecDriverInstaller(arg);

	CmStopUacHelper(helper);

	p = NewPack();
	PackAddBool(p, "ret", ret);
	SendPack(s, p);

	FreePack(p);
}

#endif	// OS_WIN32

// Start the driver installer
void CnExecDriverInstaller(SOCK *s, PACK *p)
{
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnExecDriverInstaller(s, p);
#endif	// OS_WIN32
}

// Certificate confirmation dialog
void CnCheckCert(SOCK *s, PACK *p)
{
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnCheckCert(s, p);
#endif	// OS_WIN32
}

// NIC information dialog
void CnNicInfo(SOCK *s, PACK *p)
{
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnNicInfo(s, p);
#endif	// OS_WIN32
}

// Message display dialog
void CnMsgDlg(SOCK *s, PACK *p)
{
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnMsgDlg(s, p);
#endif	// OS_WIN32
}

// Password input dialog
void CnPasswordDlg(SOCK *s, PACK *p)
{
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnPasswordDlg(s, p);
#endif	// OS_WIN32
}

// Connection Error dialog
void CnConnectErrorDlg(SOCK *s, PACK *p)
{
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnConnectErrorDlg(s, p);
#endif	// OS_WIN32
}

// Status indicator
void CnStatusPrinter(SOCK *s, PACK *p)
{
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	Win32CnStatusPrinter(s, p);
#endif	// OS_WIN32
}
// Client notification service listener thread
void CnListenerProc(THREAD *thread, void *param)
{
	TCP_ACCEPTED_PARAM *data = (TCP_ACCEPTED_PARAM *)param;
	SOCK *s;
	PACK *p;
	// Validate arguments
	if (data == NULL || thread == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	//Set Application ID
	JL_SetCurrentProcessExplicitAppUserModelID(APPID_CM);
#endif	// OS_WIN32

	s = data->s;
	AddRef(s->ref);
	NoticeThreadInit(thread);

	if (s->LocalIP.addr[0] == 127)
	{
		p = RecvPack(s);

		if (p != NULL)
		{
			char function[MAX_SIZE];

			if (PackGetStr(p, "function", function, sizeof(function)))
			{
				if (StrCmpi(function, "status_printer") == 0)
				{
					CnStatusPrinter(s, p);
				}
				else if (StrCmpi(function, "connecterror_dialog") == 0)
				{
					CnConnectErrorDlg(s, p);
				}
				else if (StrCmpi(function, "msg_dialog") == 0)
				{
					CnMsgDlg(s, p);
				}
				else if (StrCmpi(function, "nicinfo") == 0)
				{
					CnNicInfo(s, p);
				}
				else if (StrCmpi(function, "password_dialog") == 0)
				{
					CnPasswordDlg(s, p);
				}
				else if (StrCmpi(function, "secure_sign") == 0)
				{
					CnSecureSign(s, p);
				}
				else if (StrCmpi(function, "check_cert") == 0)
				{
					CnCheckCert(s, p);
				}
				else if (StrCmpi(function, "exit") == 0)
				{
#ifdef	OS_WIN32
					MsTerminateProcess();
#else	// OS_WIN32
					_exit(0);
#endif	// OS_WIN32
				}
				else if (StrCmpi(function, "get_session_id") == 0)
				{
					PACK *p = NewPack();
#ifdef	OS_WIN32
					PackAddInt(p, "session_id", MsGetCurrentTerminalSessionId());
#endif	// OS_WIN32
					SendPack(s, p);
					FreePack(p);
				}
				else if (StrCmpi(function, "exec_driver_installer") == 0)
				{
					CnExecDriverInstaller(s, p);
				}
				else if (StrCmpi(function, "release_socket") == 0)
				{
					// Stop the listener
					CnReleaseSocket(s, p);
				}
			}

			FreePack(p);
		}
	}

	Disconnect(s);
	ReleaseSock(s);
}

// Do the Secure Sign
void CnSecureSign(SOCK *s, PACK *p)
{
	SECURE_SIGN sign;
	bool ret = false;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	Zero(&sign, sizeof(sign));
	InRpcSecureSign(&sign, p);

#ifdef	OS_WIN32
	// Win32: Show dialog
	ret = Win32CiSecureSign(&sign);
#else	// OS_WIN32
	// UNIX: not implemented
	ret = false;
#endif	// OS_WIN32

	p = NewPack();

	OutRpcSecureSign(p, &sign);
	FreeRpcSecureSign(&sign);

	PackAddBool(p, "ret", ret);

	SendPack(s, p);
	FreePack(p);
}

// Stop the listener
void CnReleaseSocket(SOCK *s, PACK *p)
{
	UINT pid = 0;
	UINT current_pid = 0;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	pid = PackGetInt(p, "pid");

#ifdef	OS_WIN32
	current_pid = MsGetProcessId();
#endif	// OS_WIN32

	if (current_pid == pid)
	{
		return;
	}

	Lock(cn_listener_lock);
	{
		if (cn_listener != NULL)
		{
			if (cn_listener->Halt == false)
			{
				StopListener(cn_listener);

				cn_next_allow = Tick64() + (6 * 1000);
			}
		}
	}
	Unlock(cn_listener_lock);
}

// Start the client notification service
void CnStart()
{
	CEDAR *cedar;
	LISTENER *o;
	UINT last_cursor_hash = 0;
	bool last_session_active = false;

	cn_next_allow = 0;
	cn_listener_lock = NewLock();

#ifdef	OS_WIN32
	MsSetShutdownParameters(0xff, 0x00000001);
	InitWinUi(_UU("CN_TITLE"), _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));
#endif	// OS_WIN32

	cedar = NewCedar(NULL, NULL);

	if (CnCheckAlreadyExists(true))
	{
		// Already started
		ReleaseCedar(cedar);
#ifdef	OS_WIN32
		FreeWinUi();
#endif	// OS_WIN32
		return;
	}

#ifdef	OS_WIN32
	MsRegWriteInt(REG_CURRENT_USER, CM_REG_KEY,
		"NotifyServerProcessId", MsGetProcessId());
#endif	// OS_WIN32

	DisableDosProtect();

BEGIN_LISTENER:
	Lock(cn_listener_lock);
	cn_listener = o = NewListenerEx2(cedar, LISTENER_TCP, CLIENT_NOTIFY_PORT, CnListenerProc, NULL, true);
	Unlock(cn_listener_lock);

	while (true)
	{
		UINT current_cursor_hash = 0;
		bool cursor_changed = false;

#ifdef	OS_WIN32
		// Get the current cursor position
		current_cursor_hash = MsGetCursorPosHash();
#endif	// OS_WIN32

		if (last_cursor_hash != current_cursor_hash)
		{
			// Check the cursor position
			cursor_changed = true;
			last_cursor_hash = current_cursor_hash;
		}

		Lock(cn_listener_lock);

		// Check the status periodically after that the listener has started
		if (cn_listener->Status == LISTENER_STATUS_TRYING || cn_listener->Halt)
		{
			bool session_active = false;
#ifdef	OS_WIN32
			session_active = MsIsCurrentTerminalSessionActive();
			if (cursor_changed)
			{
				// If the cursor position is changed but the terminal session is
				// not active, the cursor position is regarded as not changed.
				if (session_active == false)
				{
					cursor_changed = false;
				}
			}
			if (last_session_active != session_active)
			{
				//If the cursor position doesn't changed but the terminal session
				// became active than previous, the cursor position is regarded as changed.
				last_session_active = session_active;

				if (session_active)
				{
					cursor_changed = true;
				}
			}
#endif	// OS_WIN32

			// If the port cannot be opened
			if (cn_next_allow <= Tick64())
			{
#ifdef  OS_WIN32
				if (cursor_changed)
				{
					// It can be judged to have the rights to open the port
					// since the mouse cursor is moving.
					// So, take over the port which is owned by other process forcibly
					CncReleaseSocket();
				}
#endif  // OS_WIN32

				if (cn_listener->Halt)
				{
					ReleaseListener(cn_listener);
					cn_listener = NULL;

					Unlock(cn_listener_lock);
					goto BEGIN_LISTENER;
				}
			}
		}

		Unlock(cn_listener_lock);

		SleepThread(1000);
	}
}

// Confirm whether the account file is parsed successfully
bool CiTryToParseAccount(BUF *b)
{
	RPC_CLIENT_CREATE_ACCOUNT *a;
	// Validate arguments
	if (b == NULL)
	{
		return false;
	}

	a = CiCfgToAccount(b);
	if (a != NULL)
	{
		CiFreeClientCreateAccount(a);
		Free(a);

		return true;
	}
	else
	{
		return false;
	}
}
bool CiTryToParseAccountFile(wchar_t *name)
{
	bool ret;
	BUF *b;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	b = ReadDumpW(name);
	if (b == NULL)
	{
		return false;
	}

	ret = CiTryToParseAccount(b);

	FreeBuf(b);

	return ret;
}

// Confirm whether the account information includes sensitive information
bool CiHasAccountSensitiveInformation(BUF *b)
{
	RPC_CLIENT_CREATE_ACCOUNT *a;
	bool ret = false;
	// Validate arguments
	if (b == NULL)
	{
		return false;
	}

	a = CiCfgToAccount(b);
	if (a == NULL)
	{
		return false;
	}

	if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD)
	{
		ret = true;
	}
	else if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_PLAIN_PASSWORD)
	{
		ret = true;
	}

	CiFreeClientCreateAccount(a);
	Free(a);

	return ret;
}

// Delete the sensitive information in the account information
bool CiEraseSensitiveInAccount(BUF *b)
{
	RPC_CLIENT_CREATE_ACCOUNT *a;
	BUF *b2;
	bool ret = false;
	// Validate arguments
	if (b == NULL)
	{
		return false;
	}

	a = CiCfgToAccount(b);
	if (a == NULL)
	{
		return false;
	}

	if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD)
	{
		Zero(a->ClientAuth->HashedPassword, sizeof(a->ClientAuth->HashedPassword));
		ClearStr(a->ClientAuth->Username, sizeof(a->ClientAuth->Username));
	}
	else if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_PLAIN_PASSWORD)
	{
		ClearStr(a->ClientAuth->PlainPassword, sizeof(a->ClientAuth->PlainPassword));
		ClearStr(a->ClientAuth->Username, sizeof(a->ClientAuth->Username));
	}

	b2 = CiAccountToCfg(a);
	if (b2 != NULL)
	{
		ret = true;

		ClearBuf(b);

		WriteBuf(b, b2->Buf, b2->Size);
		SeekBuf(b, 0, 0);

		FreeBuf(b2);
	}

	CiFreeClientCreateAccount(a);
	Free(a);

	return ret;
}

// Read the account information from the buffer
RPC_CLIENT_CREATE_ACCOUNT *CiCfgToAccount(BUF *b)
{
	RPC_CLIENT_CREATE_ACCOUNT *t;
	FOLDER *f;
	ACCOUNT *a;
	// Validate arguments
	if (b == NULL)
	{
		return NULL;
	}

	f = CfgBufTextToFolder(b);
	if (f == NULL)
	{
		return NULL;
	}

	a = CiLoadClientAccount(f);

	CfgDeleteFolder(f);

	if (a == NULL)
	{
		return NULL;
	}

	DeleteLock(a->lock);

	t = ZeroMalloc(sizeof(RPC_CLIENT_CREATE_ACCOUNT));
	t->ClientOption = a->ClientOption;
	t->ClientAuth = a->ClientAuth;
	t->StartupAccount = a->StartupAccount;
	t->CheckServerCert = a->CheckServerCert;
	t->RetryOnServerCert = a->RetryOnServerCert;
	t->ServerCert = a->ServerCert;
	Free(a);

	return t;
}

// Write the account information to a buffer
BUF *CiAccountToCfg(RPC_CLIENT_CREATE_ACCOUNT *t)
{
	BUF *b;
	FOLDER *root;
	ACCOUNT a;
	// Validate arguments
	if (t == NULL)
	{
		return NULL;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);
	Zero(&a, sizeof(a));
	a.ClientOption = t->ClientOption;
	a.ClientAuth = t->ClientAuth;
	a.CheckServerCert = t->CheckServerCert;
	a.RetryOnServerCert = t->RetryOnServerCert;
	a.ServerCert = t->ServerCert;
	a.StartupAccount = t->StartupAccount;

	CiWriteAccountData(root, &a);

	b = CfgFolderToBufEx(root, true, true);
	CfgDeleteFolder(root);

	return b;
}

// RPC dispatch routine
PACK *CiRpcDispatch(RPC *rpc, char *name, PACK *p)
{
	PACK *ret;
	CLIENT *c;
	// Validate arguments
	if (rpc == NULL || name == NULL || p == NULL)
	{
		return NULL;
	}
	c = rpc->Param;

	ret = NewPack();

	if (StrCmpi(name, "GetClientVersion") == 0)
	{
		RPC_CLIENT_VERSION a;
		if (CtGetClientVersion(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientVersion(ret, &a);
		}
	}
	else if (StrCmpi(name, "GetCmSetting") == 0)
	{
		CM_SETTING a;
		if (CtGetCmSetting(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcCmSetting(ret, &a);
		}
	}
	else if (StrCmpi(name, "SetCmSetting") == 0)
	{
		CM_SETTING a;
		Zero(&a, sizeof(a));
		InRpcCmSetting(&a, p);
		if (CtSetCmSetting(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "SetPassword") == 0)
	{
		RPC_CLIENT_PASSWORD a;
		InRpcClientPassword(&a, p);
		if (CtSetPassword(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetPasswordSetting") == 0)
	{
		RPC_CLIENT_PASSWORD_SETTING a;
		if (CtGetPasswordSetting(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientPasswordSetting(ret, &a);
		}
	}
	else if (StrCmpi(name, "EnumCa") == 0)
	{
		RPC_CLIENT_ENUM_CA a;
		if (CtEnumCa(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientEnumCa(ret, &a);
			CiFreeClientEnumCa(&a);
		}
	}
	else if (StrCmpi(name, "AddCa") == 0)
	{
		RPC_CERT a;
		InRpcCert(&a, p);
		if (CtAddCa(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		FreeX(a.x);
	}
	else if (StrCmpi(name, "DeleteCa") == 0)
	{
		RPC_CLIENT_DELETE_CA a;
		InRpcClientDeleteCa(&a, p);
		if (CtDeleteCa(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetCa") == 0)
	{
		RPC_GET_CA a;
		InRpcGetCa(&a, p);
		if (CtGetCa(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcGetCa(ret, &a);
		}
		CiFreeGetCa(&a);
	}
	else if (StrCmpi(name, "EnumSecure") == 0)
	{
		RPC_CLIENT_ENUM_SECURE a;
		if (CtEnumSecure(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientEnumSecure(ret, &a);
			CiFreeClientEnumSecure(&a);
		}
	}
	else if (StrCmpi(name, "UseSecure") == 0)
	{
		RPC_USE_SECURE a;
		InRpcUseSecure(&a, p);
		if (CtUseSecure(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetUseSecure") == 0)
	{
		RPC_USE_SECURE a;
		Zero(&a, sizeof(a));
		if (CtGetUseSecure(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcUseSecure(ret, &a);
		}
	}
	else if (StrCmpi(name, "EnumObjectInSecure") == 0)
	{
		RPC_ENUM_OBJECT_IN_SECURE a;
		if (CtEnumObjectInSecure(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcEnumObjectInSecure(ret, &a);
			CiFreeEnumObjectInSecure(&a);
		}
	}
	else if (StrCmpi(name, "CreateVLan") == 0)
	{
		RPC_CLIENT_CREATE_VLAN a;
		InRpcCreateVLan(&a, p);
		if (CtCreateVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "UpgradeVLan") == 0)
	{
		RPC_CLIENT_CREATE_VLAN a;
		InRpcCreateVLan(&a, p);
		if (CtUpgradeVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetVLan") == 0)
	{
		RPC_CLIENT_GET_VLAN a;
		InRpcClientGetVLan(&a, p);
		if (CtGetVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientGetVLan(ret, &a);
		}
	}
	else if (StrCmpi(name, "SetVLan") == 0)
	{
		RPC_CLIENT_SET_VLAN a;
		InRpcClientSetVLan(&a, p);
		if (CtSetVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "EnumVLan") == 0)
	{
		RPC_CLIENT_ENUM_VLAN a;
		if (CtEnumVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientEnumVLan(ret, &a);
			CiFreeClientEnumVLan(&a);
		}
	}
	else if (StrCmpi(name, "DeleteVLan") == 0)
	{
		RPC_CLIENT_CREATE_VLAN a;
		InRpcCreateVLan(&a, p);
		if (CtDeleteVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "EnableVLan") == 0)
	{
		RPC_CLIENT_CREATE_VLAN a;
		InRpcCreateVLan(&a, p);
		if (CtEnableVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "DisableVLan") == 0)
	{
		RPC_CLIENT_CREATE_VLAN a;
		InRpcCreateVLan(&a, p);
		if (CtDisableVLan(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "CreateAccount") == 0)
	{
		RPC_CLIENT_CREATE_ACCOUNT a;
		InRpcClientCreateAccount(&a, p);
		if (CtCreateAccount(c, &a, false) == false)
		{
			RpcError(ret, c->Err);
		}
		CiFreeClientCreateAccount(&a);
	}
	else if (StrCmpi(name, "EnumAccount") == 0)
	{
		RPC_CLIENT_ENUM_ACCOUNT a;
		if (CtEnumAccount(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientEnumAccount(ret, &a);
			CiFreeClientEnumAccount(&a);
		}
	}
	else if (StrCmpi(name, "DeleteAccount") == 0)
	{
		RPC_CLIENT_DELETE_ACCOUNT a;
		InRpcClientDeleteAccount(&a, p);
		if (CtDeleteAccount(c, &a, false) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "SetStartupAccount") == 0)
	{
		RPC_CLIENT_DELETE_ACCOUNT a;
		InRpcClientDeleteAccount(&a, p);
		if (CtSetStartupAccount(c, &a, false) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "RemoveStartupAccount") == 0)
	{
		RPC_CLIENT_DELETE_ACCOUNT a;
		InRpcClientDeleteAccount(&a, p);
		if (CtRemoveStartupAccount(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetIssuer") == 0)
	{
		RPC_GET_ISSUER a;
		InRpcGetIssuer(&a, p);
		if (CtGetIssuer(c, &a))
		{
			OutRpcGetIssuer(ret, &a);
		}
		else
		{
			RpcError(ret, c->Err);
		}
		CiFreeGetIssuer(&a);
	}
	else if (StrCmpi(name, "GetCommonProxySetting") == 0)
	{
		INTERNET_SETTING t;
		InRpcInternetSetting(&t, p);
		if (CtGetCommonProxySetting(c, &t))
		{
			OutRpcInternetSetting(ret, &t);
		}
		else
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "SetCommonProxySetting") == 0)
	{
		INTERNET_SETTING t;
		InRpcInternetSetting(&t, p);
		if (CtSetCommonProxySetting(c, &t))
		{
			OutRpcInternetSetting(ret, &t);
		}
		else
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "SetAccount") == 0)
	{
		RPC_CLIENT_CREATE_ACCOUNT a;
		InRpcClientCreateAccount(&a, p);
		if (CtSetAccount(c, &a, false) == false)
		{
			RpcError(ret, c->Err);
		}
		CiFreeClientCreateAccount(&a);
	}
	else if (StrCmpi(name, "GetAccount") == 0)
	{
		RPC_CLIENT_GET_ACCOUNT a;
		InRpcClientGetAccount(&a, p);
		if (CtGetAccount(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientGetAccount(ret, &a);
		}
		CiFreeClientGetAccount(&a);
	}
	else if (StrCmpi(name, "RenameAccount") == 0)
	{
		RPC_RENAME_ACCOUNT a;
		InRpcRenameAccount(&a, p);
		if (CtRenameAccount(c, &a, false) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "SetClientConfig") == 0)
	{
		CLIENT_CONFIG a;
		InRpcClientConfig(&a, p);
		if (CtSetClientConfig(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetClientConfig") == 0)
	{
		CLIENT_CONFIG a;
		if (CtGetClientConfig(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientConfig(ret, &a);
		}
	}
	else if (StrCmpi(name, "Connect") == 0)
	{
		RPC_CLIENT_CONNECT a;
		InRpcClientConnect(&a, p);
		if (CtConnect(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "Disconnect") == 0)
	{
		RPC_CLIENT_CONNECT a;
		InRpcClientConnect(&a, p);
		if (CtDisconnect(c, &a, false) == false)
		{
			RpcError(ret, c->Err);
		}
	}
	else if (StrCmpi(name, "GetAccountStatus") == 0)
	{
		RPC_CLIENT_GET_CONNECTION_STATUS a;
		InRpcClientGetConnectionStatus(&a, p);
		if (CtGetAccountStatus(c, &a) == false)
		{
			RpcError(ret, c->Err);
		}
		else
		{
			OutRpcClientGetConnectionStatus(ret, &a);
		}
		CiFreeClientGetConnectionStatus(&a);
	}
	else
	{
		FreePack(ret);
		ret = NULL;
	}

	return ret;
}

// Set the CM_SETTING
UINT CcSetCmSetting(REMOTE_CLIENT *r, CM_SETTING *a)
{
	PACK *ret, *p;
	UINT err;
	// Validate arguments
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCmSetting(p, a);

	ret = RpcCall(r->Rpc, "SetCmSetting", p);

	if (RpcIsOk(ret))
	{
		FreePack(ret);
		return 0;
	}
	else
	{
		err = RpcGetError(ret);
		FreePack(ret);
		return err;
	}
}

// Get the CM_SETTING
UINT CcGetCmSetting(REMOTE_CLIENT *r, CM_SETTING *a)
{
	PACK *ret;
	// Validate arguments
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "GetCmSetting", NULL);

	if (RpcIsOk(ret))
	{
		InRpcCmSetting(a, ret);
		FreePack(ret);
		return 0;
	}
	else
	{
		UINT err = RpcGetError(ret);
		FreePack(ret);
		return err;
	}
}

// Get the client version
UINT CcGetClientVersion(REMOTE_CLIENT *r, RPC_CLIENT_VERSION *a)
{
	PACK *ret;
	// Validate arguments
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "GetClientVersion", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientVersion(a, ret);
		FreePack(ret);
		return 0;
	}
	else
	{
		UINT err = RpcGetError(ret);
		FreePack(ret);
		return err;
	}
}

// Set the password
UINT CcSetPassword(REMOTE_CLIENT *r, RPC_CLIENT_PASSWORD *pass)
{
	PACK *ret, *p;
	// Validate arguments
	if (r == NULL || pass == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();

	OutRpcClientPassword(p, pass);

	ret = RpcCall(r->Rpc, "SetPassword", p);

	if (RpcIsOk(ret))
	{
		FreePack(ret);
		return 0;
	}
	else
	{
		UINT err = RpcGetError(ret);
		FreePack(ret);
		return err;
	}
}

// Get the password setting
UINT CcGetPasswordSetting(REMOTE_CLIENT *r, RPC_CLIENT_PASSWORD_SETTING *a)
{
	PACK *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "GetPasswordSetting", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientPasswordSetting(a, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);
	return err;
}

// Enumerate the CA
UINT CcEnumCa(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_CA *e)
{
	PACK *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || e == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "EnumCa", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientEnumCa(e, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Add the CA
UINT CcAddCa(REMOTE_CLIENT *r, RPC_CERT *cert)
{
	PACK *p, *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || cert == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCert(p, cert);

	ret = RpcCall(r->Rpc, "AddCa", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Delete the CA
UINT CcDeleteCa(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_CA *c)
{
	PACK *p, *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || c == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientDeleteCa(p, c);

	ret = RpcCall(r->Rpc, "DeleteCa", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Get the issuer
UINT CcGetIssuer(REMOTE_CLIENT *r, RPC_GET_ISSUER *a)
{
	PACK *p, *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcGetIssuer(p, a);

	ret = RpcCall(r->Rpc, "GetIssuer", p);

	if (RpcIsOk(ret))
	{
		if (a->x != NULL)
		{
			FreeX(a->x);
			a->x = NULL;
		}
		InRpcGetIssuer(a, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Get the CA
UINT CcGetCa(REMOTE_CLIENT *r, RPC_GET_CA *get)
{
	PACK *p, *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || get == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcGetCa(p, get);

	ret = RpcCall(r->Rpc, "GetCa", p);

	if (RpcIsOk(ret))
	{
		InRpcGetCa(get, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Enumeration of the secure devices
UINT CcEnumSecure(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_SECURE *e)
{
	PACK *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || e == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "EnumSecure", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientEnumSecure(e, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Get the secure device that the user is using
UINT CcGetUseSecure(REMOTE_CLIENT *r, RPC_USE_SECURE *sec)
{
	PACK *p, *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || sec == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();

	ret = RpcCall(r->Rpc, "GetUseSecure", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}
	else
	{
		InRpcUseSecure(sec, ret);
	}

	FreePack(ret);

	return err;
}

// Use the secure device
UINT CcUseSecure(REMOTE_CLIENT *r, RPC_USE_SECURE *sec)
{
	PACK *p, *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || sec == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcUseSecure(p, sec);

	ret = RpcCall(r->Rpc, "UseSecure", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Get a next recommended virtual LAN card name
bool CiGetNextRecommendedVLanName(REMOTE_CLIENT *r, char *name, UINT size)
{
	RPC_CLIENT_ENUM_VLAN t;
	UINT i;
	bool b;
	UINT j;
	bool ok = false;
	// Validate arguments
	if (r == NULL || name == NULL)
	{
		return false;
	}

	Zero(&t, sizeof(t));

	if (CcEnumVLan(r, &t) != ERR_NO_ERROR)
	{
		return false;
	}

	for (i = 1;i < 128;i++)
	{
		char tmp[MAX_SIZE];

		CiGenerateVLanRegulatedName(tmp, sizeof(tmp), i);

		b = false;

		for (j = 0;j < t.NumItem;j++)
		{
			if (StrCmpi(t.Items[j]->DeviceName, tmp) == 0)
			{
				b = true;
				break;
			}
		}

		if (b == false)
		{
			ok = true;

			StrCpy(name, size, tmp);
			break;
		}
	}

	if (ok)
	{
		CiFreeClientEnumVLan(&t);
	}

	return true;
}

// Generate a virtual LAN card name automatically
void CiGenerateVLanRegulatedName(char *name, UINT size, UINT i)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	if (i == 1)
	{
		StrCpy(name, size, "VPN");
	}
	else
	{
		Format(name, size, "VPN%u", i);
	}
}

// Examine whether the specified name is valid as a virtual LAN card name of Windows 8 and later?
bool CiIsValidVLanRegulatedName(char *name)
{
	UINT i;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	for (i = 1;i < 128;i++)
	{
		char tmp[MAX_SIZE];

		CiGenerateVLanRegulatedName(tmp, sizeof(tmp), i);

		if (StrCmpi(name, tmp) == 0)
		{
			return true;
		}
	}

	return false;
}

// Create a VLAN
UINT CcCreateVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *create)
{
	PACK *ret, *p;
	UINT err = 0;
	char *s = NULL;
	// Validate arguments
	if (r == NULL || create == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCreateVLan(p, create);

#ifdef	OS_WIN32
	s = MsNoWarningSoundInit();
#endif	// OS_WIN32

	ret = RpcCall(r->Rpc, "CreateVLan", p);

#ifdef	OS_WIN32
	MsNoWarningSoundFree(s);
#endif	// OS_WIN32

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Upgrade the VLAN
UINT CcUpgradeVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *create)
{
	PACK *ret, *p;
	UINT err = 0;
	char *s = NULL;
	// Validate arguments
	if (r == NULL || create == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCreateVLan(p, create);

#ifdef	OS_WIN32
	s = MsNoWarningSoundInit();
#endif	// OS_WIN32

	ret = RpcCall(r->Rpc, "UpgradeVLan", p);

#ifdef	OS_WIN32
	MsNoWarningSoundFree(s);
#endif	// OS_WIN32


	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Get the VLAN
UINT CcGetVLan(REMOTE_CLIENT *r, RPC_CLIENT_GET_VLAN *get)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || get == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientGetVLan(p, get);

	ret = RpcCall(r->Rpc, "GetVLan", p);

	if (RpcIsOk(ret))
	{
		InRpcClientGetVLan(get, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// VLAN configuration
UINT CcSetVLan(REMOTE_CLIENT *r, RPC_CLIENT_SET_VLAN *set)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || set == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientSetVLan(p, set);

	ret = RpcCall(r->Rpc, "SetVLan", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Enumeration of VLAN
UINT CcEnumVLan(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_VLAN *e)
{
	PACK *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || e == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "EnumVLan", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientEnumVLan(e, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Delete the VLAN
UINT CcDeleteVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *d)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || d == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCreateVLan(p, d);

	ret = RpcCall(r->Rpc, "DeleteVLan", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Enable the VLAN
UINT CcEnableVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *vlan)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || vlan == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCreateVLan(p, vlan);

	ret = RpcCall(r->Rpc, "EnableVLan", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Disable the VLAN
UINT CcDisableVLan(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_VLAN *vlan)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || vlan == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcCreateVLan(p, vlan);

	ret = RpcCall(r->Rpc, "DisableVLan", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Create an Account
UINT CcCreateAccount(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientCreateAccount(p, a);

	ret = RpcCall(r->Rpc, "CreateAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Enumeration of accounts
UINT CcEnumAccount(REMOTE_CLIENT *r, RPC_CLIENT_ENUM_ACCOUNT *e)
{
	PACK *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || e == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "EnumAccount", NULL);

	if (RpcIsOk(ret))
	{
		UINT i;
		InRpcClientEnumAccount(e, ret);

		for (i = 0;i < e->NumItem;i++)
		{
			RPC_CLIENT_ENUM_ACCOUNT_ITEM *t = e->Items[i];

			if (IsEmptyStr(t->HubName) && t->Port == 0)
			{
				UINT err2;
				RPC_CLIENT_GET_ACCOUNT a;

				// Because the Client Manager can not get the port number and HUB name
				// when enumerating in the VPN Client of the old version, get these separately.
				Zero(&a, sizeof(a));
				UniStrCpy(a.AccountName, sizeof(a.AccountName), t->AccountName);
				err2 = CcGetAccount(r, &a);
				if (err2 == ERR_NO_ERROR)
				{
					StrCpy(t->HubName, sizeof(t->HubName), a.ClientOption->HubName);
					t->Port = a.ClientOption->Port;

					CiFreeClientGetAccount(&a);
				}
			}
		}
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Unset the startup flag of the account
UINT CcRemoveStartupAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientDeleteAccount(p, a);

	ret = RpcCall(r->Rpc, "RemoveStartupAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Set to start-up flag of the account
UINT CcSetStartupAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientDeleteAccount(p, a);

	ret = RpcCall(r->Rpc, "SetStartupAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Delete the account
UINT CcDeleteAccount(REMOTE_CLIENT *r, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientDeleteAccount(p, a);

	ret = RpcCall(r->Rpc, "DeleteAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Account setting
UINT CcSetAccount(REMOTE_CLIENT *r, RPC_CLIENT_CREATE_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientCreateAccount(p, a);

	ret = RpcCall(r->Rpc, "SetAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Get the account
UINT CcGetAccount(REMOTE_CLIENT *r, RPC_CLIENT_GET_ACCOUNT *a)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || a == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientGetAccount(p, a);

	ret = RpcCall(r->Rpc, "GetAccount", p);

	if (RpcIsOk(ret))
	{
		InRpcClientGetAccount(a, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Change the account name
UINT CcRenameAccount(REMOTE_CLIENT *r, RPC_RENAME_ACCOUNT *rename)
{
	PACK *p, *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || rename == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcRenameAccount(p, rename);

	ret = RpcCall(r->Rpc, "RenameAccount", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Set the Client configuration
UINT CcSetClientConfig(REMOTE_CLIENT *r, CLIENT_CONFIG *o)
{
	PACK *p, *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || o == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientConfig(p, o);

	ret = RpcCall(r->Rpc, "SetClientConfig", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Get the client configuration
UINT CcGetClientConfig(REMOTE_CLIENT *r, CLIENT_CONFIG *o)
{
	PACK *ret;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || o == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	ret = RpcCall(r->Rpc, "GetClientConfig", NULL);

	if (RpcIsOk(ret))
	{
		InRpcClientConfig(o, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Set the service to foreground process
void CcSetServiceToForegroundProcess(REMOTE_CLIENT *r)
{
	// Validate arguments
	if (r == NULL)
	{
		return;
	}
	// Abolition
/*
	if (r->Rpc != NULL && r->Rpc->Sock != NULL && r->Rpc->Sock->RemoteIP.addr[0] == 127)
	{
		if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) &&
			GET_KETA(GetOsInfo()->OsType, 100) >= 2)
		{
			// Only on a Windows 2000 or later
			RPC_CLIENT_VERSION v;
			Zero(&v, sizeof(v));

			if (r->ClientBuildInt == 0)
			{
				CcGetClientVersion(r, &v);
				r->ClientBuildInt = v.ClientBuildInt;
				r->ProcessId = v.ProcessId;
			}
			if (r->ProcessId != 0 && r->ClientBuildInt <= 5080)
			{
#ifdef	OS_WIN32
				// Set the service process as a foreground window
				AllowFGWindow(v.ProcessId);
#endif	// OS_WIN32
			}
		}
	}*/
}

// Connect
UINT CcConnect(REMOTE_CLIENT *r, RPC_CLIENT_CONNECT *connect)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || connect == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	CcSetServiceToForegroundProcess(r);

	p = NewPack();
	OutRpcClientConnect(p, connect);

	ret = RpcCall(r->Rpc, "Connect", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Disconnect
UINT CcDisconnect(REMOTE_CLIENT *r, RPC_CLIENT_CONNECT *connect)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || connect == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	CcSetServiceToForegroundProcess(r);

	p = NewPack();
	OutRpcClientConnect(p, connect);

	ret = RpcCall(r->Rpc, "Disconnect", p);

	if (RpcIsOk(ret) == false)
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}

// Get the account status
UINT CcGetAccountStatus(REMOTE_CLIENT *r, RPC_CLIENT_GET_CONNECTION_STATUS *st)
{
	PACK *ret, *p;
	UINT err = 0;
	// Validate arguments
	if (r == NULL || st == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	p = NewPack();
	OutRpcClientGetConnectionStatus(p, st);

	ret = RpcCall(r->Rpc, "GetAccountStatus", p);

	if (RpcIsOk(ret))
	{
		InRpcClientGetConnectionStatus(st, ret);
	}
	else
	{
		err = RpcGetError(ret);
	}

	FreePack(ret);

	return err;
}


// Client service sends a notification to the connection manager
void CiNotify(CLIENT *c)
{
	CiNotifyInternal(c);
}
void CiNotifyInternal(CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Set all the notification event
	LockList(c->NotifyCancelList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(c->NotifyCancelList);i++)
		{
			CANCEL *cancel = LIST_DATA(c->NotifyCancelList, i);
			Cancel(cancel);
		}
	}
	UnlockList(c->NotifyCancelList);
}

// Release the RPC_CLIENT_ENUM_ACCOUNT
void CiFreeClientEnumAccount(RPC_CLIENT_ENUM_ACCOUNT *a)
{
	UINT i;
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	for (i = 0;i < a->NumItem;i++)
	{
		RPC_CLIENT_ENUM_ACCOUNT_ITEM *e = a->Items[i];
		Free(e);
	}
	Free(a->Items);
}


// Thread to save the configuration file periodically
void CiSaverThread(THREAD *t, void *param)
{
	CLIENT *c = (CLIENT *)param;
	// Validate arguments
	if (t == NULL || param == NULL)
	{
		return;
	}

	NoticeThreadInit(t);

	// Wait for a certain period of time
	while (c->Halt == false)
	{
		Wait(c->SaverHalter, CLIENT_SAVER_INTERVAL);

		// Save
		CiSaveConfigurationFile(c);
	}
}

// Initialize the Saver
void CiInitSaver(CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	c->SaverHalter = NewEvent();

	c->SaverThread = NewThread(CiSaverThread, c);
	WaitThreadInit(c->SaverThread);
}

// Release the Saver
void CiFreeSaver(CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	c->Halt = true;
	Set(c->SaverHalter);
	WaitThread(c->SaverThread, INFINITE);
	ReleaseThread(c->SaverThread);

	ReleaseEvent(c->SaverHalter);
}

// CM_SETTING
void InRpcCmSetting(CM_SETTING *c, PACK *p)
{
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(CM_SETTING));
	c->EasyMode = PackGetBool(p, "EasyMode");
	c->LockMode = PackGetBool(p, "LockMode");
	PackGetData2(p, "HashedPassword", c->HashedPassword, sizeof(c->HashedPassword));
}
void OutRpcCmSetting(PACK *p, CM_SETTING *c)
{
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddBool(p, "EasyMode", c->EasyMode);
	PackAddBool(p, "LockMode", c->LockMode);
	PackAddData(p, "HashedPassword", c->HashedPassword, sizeof(c->HashedPassword));
}

// CLIENT_CONFIG
void InRpcClientConfig(CLIENT_CONFIG *c, PACK *p)
{
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(CLIENT_CONFIG));
	c->UseKeepConnect = PackGetInt(p, "UseKeepConnect") == 0 ? false : true;
	c->KeepConnectPort = PackGetInt(p, "KeepConnectPort");
	c->KeepConnectProtocol = PackGetInt(p, "KeepConnectProtocol");
	c->KeepConnectInterval = PackGetInt(p, "KeepConnectInterval");
	c->AllowRemoteConfig = PackGetInt(p, "AllowRemoteConfig") == 0 ? false : true;
	PackGetStr(p, "KeepConnectHost", c->KeepConnectHost, sizeof(c->KeepConnectHost));
}
void OutRpcClientConfig(PACK *p, CLIENT_CONFIG *c)
{
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "UseKeepConnect", c->UseKeepConnect);
	PackAddInt(p, "KeepConnectPort", c->KeepConnectPort);
	PackAddInt(p, "KeepConnectProtocol", c->KeepConnectProtocol);
	PackAddInt(p, "KeepConnectInterval", c->KeepConnectInterval);
	PackAddInt(p, "AllowRemoteConfig", c->AllowRemoteConfig);
	PackAddStr(p, "KeepConnectHost", c->KeepConnectHost);
}

// RPC_CLIENT_VERSION
void InRpcClientVersion(RPC_CLIENT_VERSION *ver, PACK *p)
{
	// Validate arguments
	if (ver == NULL || p == NULL)
	{
		return;
	}

	Zero(ver, sizeof(RPC_CLIENT_VERSION));
	PackGetStr(p, "ClientProductName", ver->ClientProductName, sizeof(ver->ClientProductName));
	PackGetStr(p, "ClientVersionString", ver->ClientVersionString, sizeof(ver->ClientVersionString));
	PackGetStr(p, "ClientBuildInfoString", ver->ClientBuildInfoString, sizeof(ver->ClientBuildInfoString));
	ver->ClientVerInt = PackGetInt(p, "ClientVerInt");
	ver->ClientBuildInt = PackGetInt(p, "ClientBuildInt");
	ver->ProcessId = PackGetInt(p, "ProcessId");
	ver->OsType = PackGetInt(p, "OsType");
	ver->IsVLanNameRegulated = PackGetBool(p, "IsVLanNameRegulated");
	ver->IsVgcSupported = PackGetBool(p, "IsVgcSupported");
	ver->ShowVgcLink = PackGetBool(p, "ShowVgcLink");
	PackGetStr(p, "ClientId", ver->ClientId, sizeof(ver->ClientId));
}
void OutRpcClientVersion(PACK *p, RPC_CLIENT_VERSION *ver)
{
	// Validate arguments
	if (ver == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "ClientProductName", ver->ClientProductName);
	PackAddStr(p, "ClientVersionString", ver->ClientVersionString);
	PackAddStr(p, "ClientBuildInfoString", ver->ClientBuildInfoString);
	PackAddInt(p, "ClientVerInt", ver->ClientVerInt);
	PackAddInt(p, "ClientBuildInt", ver->ClientBuildInt);
	PackAddInt(p, "ProcessId", ver->ProcessId);
	PackAddInt(p, "OsType", ver->OsType);
	PackAddBool(p, "IsVLanNameRegulated", ver->IsVLanNameRegulated);
	PackAddBool(p, "IsVgcSupported", ver->IsVgcSupported);
	PackAddBool(p, "ShowVgcLink", ver->ShowVgcLink);
	PackAddStr(p, "ClientId", ver->ClientId);
}

// RPC_CLIENT_PASSWORD
void InRpcClientPassword(RPC_CLIENT_PASSWORD *pw, PACK *p)
{
	// Validate arguments
	if (pw == NULL || p == NULL)
	{
		return;
	}

	Zero(pw, sizeof(RPC_CLIENT_PASSWORD));
	PackGetStr(p, "Password", pw->Password, sizeof(pw->Password));
	pw->PasswordRemoteOnly = PackGetInt(p, "PasswordRemoteOnly");
}
void OutRpcClientPassword(PACK *p, RPC_CLIENT_PASSWORD *pw)
{
	// Validate arguments
	if (pw == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "Password", pw->Password);
	PackAddInt(p, "PasswordRemoteOnly", pw->PasswordRemoteOnly);
}

// RPC_CLIENT_PASSWORD_SETTING
void InRpcClientPasswordSetting(RPC_CLIENT_PASSWORD_SETTING *a, PACK *p)
{
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(RPC_CLIENT_PASSWORD_SETTING));

	a->IsPasswordPresented = PackGetInt(p, "IsPasswordPresented") == 0 ? false : true;
	a->PasswordRemoteOnly = PackGetInt(p, "PasswordRemoteOnly") == 0 ? false : true;
}
void OutRpcClientPasswordSetting(PACK *p, RPC_CLIENT_PASSWORD_SETTING *a)
{
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "IsPasswordPresented", a->IsPasswordPresented);
	PackAddInt(p, "PasswordRemoteOnly", a->PasswordRemoteOnly);
}

// RPC_CLIENT_ENUM_CA
void InRpcClientEnumCa(RPC_CLIENT_ENUM_CA *e, PACK *p)
{
	UINT i;
	// Validate arguments
	if (e == NULL || p == NULL)
	{
		return;
	}

	Zero(e, sizeof(RPC_CLIENT_ENUM_CA));
	e->NumItem = PackGetNum(p, "NumItem");

	e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_CA_ITEM *) * e->NumItem);
	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_CA_ITEM *item = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_CA_ITEM));
		e->Items[i] = item;

		item->Key = PackGetIntEx(p, "Key", i);
		PackGetUniStrEx(p, "SubjectName", item->SubjectName, sizeof(item->SubjectName), i);
		PackGetUniStrEx(p, "IssuerName", item->IssuerName, sizeof(item->IssuerName), i);
		item->Expires = PackGetInt64Ex(p, "Expires", i);
	}
}
void OutRpcClientEnumCa(PACK *p, RPC_CLIENT_ENUM_CA *e)
{
	UINT i;
	// Validate arguments
	if (e == NULL || p == NULL)
	{
		return;
	}

	PackAddNum(p, "NumItem", e->NumItem);

	PackSetCurrentJsonGroupName(p, "CAList");
	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_CA_ITEM *item = e->Items[i];
		PackAddIntEx(p, "Key", item->Key, i, e->NumItem);
		PackAddUniStrEx(p, "SubjectName", item->SubjectName, i, e->NumItem);
		PackAddUniStrEx(p, "IssuerName", item->IssuerName, i, e->NumItem);
		PackAddTime64Ex(p, "Expires", item->Expires, i, e->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}

// RPC_GET_ISSUER
void InRpcGetIssuer(RPC_GET_ISSUER *c, PACK *p)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_GET_ISSUER));
	b = PackGetBuf(p, "x");
	if (b != NULL)
	{
		if (c->x != NULL)
		{
			FreeX(c->x);
		}
		c->x = BufToX(b, false);
		FreeBuf(b);
	}

	b = PackGetBuf(p, "issuer_x");
	if (b != NULL)
	{
		c->issuer_x = BufToX(b, false);
		FreeBuf(b);
	}
}
void OutRpcGetIssuer(PACK *p, RPC_GET_ISSUER *c)
{
	BUF *b;
	// Validate arguments
	if (p == NULL || c == NULL)
	{
		return;
	}

	if (c->x != NULL)
	{
		b = XToBuf(c->x, false);

		PackAddBuf(p, "x", b);
		FreeBuf(b);
	}

	if (c->issuer_x != NULL)
	{
		b = XToBuf(c->issuer_x, false);

		PackAddBuf(p, "issuer_x", b);
		FreeBuf(b);
	}
}

// TRAFFIC_EX
void InRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(TRAFFIC));
	t->Recv.BroadcastBytes = PackGetInt64Ex(p, "Ex.Recv.BroadcastBytes", i);
	t->Recv.BroadcastCount = PackGetInt64Ex(p, "Ex.Recv.BroadcastCount", i);
	t->Recv.UnicastBytes = PackGetInt64Ex(p, "Ex.Recv.UnicastBytes", i);
	t->Recv.UnicastCount = PackGetInt64Ex(p, "Ex.Recv.UnicastCount", i);
	t->Send.BroadcastBytes = PackGetInt64Ex(p, "Ex.Send.BroadcastBytes", i);
	t->Send.BroadcastCount = PackGetInt64Ex(p, "Ex.Send.BroadcastCount", i);
	t->Send.UnicastBytes = PackGetInt64Ex(p, "Ex.Send.UnicastBytes", i);
	t->Send.UnicastCount = PackGetInt64Ex(p, "Ex.Send.UnicastCount", i);
}
void OutRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i, UINT num)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt64Ex(p, "Ex.Recv.BroadcastBytes", t->Recv.BroadcastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Recv.BroadcastCount", t->Recv.BroadcastCount, i, num);
	PackAddInt64Ex(p, "Ex.Recv.UnicastBytes", t->Recv.UnicastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Recv.UnicastCount", t->Recv.UnicastCount, i, num);
	PackAddInt64Ex(p, "Ex.Send.BroadcastBytes", t->Send.BroadcastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Send.BroadcastCount", t->Send.BroadcastCount, i, num);
	PackAddInt64Ex(p, "Ex.Send.UnicastBytes", t->Send.UnicastBytes, i, num);
	PackAddInt64Ex(p, "Ex.Send.UnicastCount", t->Send.UnicastCount, i, num);
}

// TRAFFIC
void InRpcTraffic(TRAFFIC *t, PACK *p)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	Zero(t, sizeof(TRAFFIC));
	t->Recv.BroadcastBytes = PackGetInt64(p, "Recv.BroadcastBytes");
	t->Recv.BroadcastCount = PackGetInt64(p, "Recv.BroadcastCount");
	t->Recv.UnicastBytes = PackGetInt64(p, "Recv.UnicastBytes");
	t->Recv.UnicastCount = PackGetInt64(p, "Recv.UnicastCount");
	t->Send.BroadcastBytes = PackGetInt64(p, "Send.BroadcastBytes");
	t->Send.BroadcastCount = PackGetInt64(p, "Send.BroadcastCount");
	t->Send.UnicastBytes = PackGetInt64(p, "Send.UnicastBytes");
	t->Send.UnicastCount = PackGetInt64(p, "Send.UnicastCount");
}
void OutRpcTraffic(PACK *p, TRAFFIC *t)
{
	// Validate arguments
	if (t == NULL || p == NULL)
	{
		return;
	}

	PackAddInt64(p, "Recv.BroadcastBytes", t->Recv.BroadcastBytes);
	PackAddInt64(p, "Recv.BroadcastCount", t->Recv.BroadcastCount);
	PackAddInt64(p, "Recv.UnicastBytes", t->Recv.UnicastBytes);
	PackAddInt64(p, "Recv.UnicastCount", t->Recv.UnicastCount);
	PackAddInt64(p, "Send.BroadcastBytes", t->Send.BroadcastBytes);
	PackAddInt64(p, "Send.BroadcastCount", t->Send.BroadcastCount);
	PackAddInt64(p, "Send.UnicastBytes", t->Send.UnicastBytes);
	PackAddInt64(p, "Send.UnicastCount", t->Send.UnicastCount);
}

// RPC_CERT
void InRpcCert(RPC_CERT *c, PACK *p)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_CERT));
	b = PackGetBuf(p, "x");
	if (b == NULL)
	{
		return;
	}

	c->x = BufToX(b, false);
	FreeBuf(b);
}
void OutRpcCert(PACK *p, RPC_CERT *c)
{
	BUF *b;
	// Validate arguments
	if (p == NULL || c == NULL)
	{
		return;
	}

	if (c->x != NULL)
	{
		b = XToBuf(c->x, false);

		PackAddBuf(p, "x", b);

		FreeBuf(b);
	}
}

// RPC_CLIENT_DELETE_CA
void InRpcClientDeleteCa(RPC_CLIENT_DELETE_CA *c, PACK *p)
{
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_CLIENT_DELETE_CA));
	c->Key = PackGetInt(p, "Key");
}
void OutRpcClientDeleteCa(PACK *p, RPC_CLIENT_DELETE_CA *c)
{
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Key", c->Key);
}

// RPC_GET_CA
void InRpcGetCa(RPC_GET_CA *c, PACK *p)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_GET_CA));

	c->Key = PackGetInt(p, "Key");

	b = PackGetBuf(p, "x");
	if (b != NULL)
	{
		c->x = BufToX(b, false);

		FreeBuf(b);
	}
}
void OutRpcGetCa(PACK *p, RPC_GET_CA *c)
{
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "Key", c->Key);

	if (c->x != NULL)
	{
		BUF *b = XToBuf(c->x, false);

		PackAddBuf(p, "x", b);

		FreeBuf(b);
	}
}

// RPC_CLIENT_ENUM_SECURE
void InRpcClientEnumSecure(RPC_CLIENT_ENUM_SECURE *e, PACK *p)
{
	UINT i;
	// Validate arguments
	if (e == NULL || p == NULL)
	{
		return;
	}

	Zero(e, sizeof(RPC_CLIENT_ENUM_SECURE));

	e->NumItem = PackGetNum(p, "NumItem");
	e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_SECURE_ITEM *) * e->NumItem);
	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_SECURE_ITEM *item = e->Items[i] = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_SECURE_ITEM));

		item->DeviceId = PackGetIntEx(p, "DeviceId", i);
		item->Type = PackGetIntEx(p, "Type", i);
		PackGetStrEx(p, "DeviceName", item->DeviceName, sizeof(item->DeviceName), i);
		PackGetStrEx(p, "Manufacturer", item->Manufacturer, sizeof(item->Manufacturer), i);
	}
}
void OutRpcClientEnumSecure(PACK *p, RPC_CLIENT_ENUM_SECURE *e)
{
	UINT i;
	// Validate arguments
	if (e == NULL || p == NULL)
	{
		return;
	}

	PackAddNum(p, "NumItem", e->NumItem);

	PackSetCurrentJsonGroupName(p, "SecureDeviceList");
	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_SECURE_ITEM *item = e->Items[i];

		PackAddIntEx(p, "DeviceId", item->DeviceId, i, e->NumItem);
		PackAddIntEx(p, "Type", item->Type, i, e->NumItem);
		PackAddStrEx(p, "DeviceName", item->DeviceName, i, e->NumItem);
		PackAddStrEx(p, "Manufacturer", item->Manufacturer, i, e->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}

// RPC_USE_SECURE
void InRpcUseSecure(RPC_USE_SECURE *u, PACK *p)
{
	// Validate arguments
	if (u == NULL || p == NULL)
	{
		return;
	}

	Zero(u, sizeof(RPC_USE_SECURE));
	u->DeviceId = PackGetInt(p, "DeviceId");
}
void OutRpcUseSecure(PACK *p, RPC_USE_SECURE *u)
{
	// Validate arguments
	if (u == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "DeviceId", u->DeviceId);
}

// Release the RPC_ENUM_OBJECT_IN_SECURE
void CiFreeEnumObjectInSecure(RPC_ENUM_OBJECT_IN_SECURE *a)
{
	UINT i;
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	for (i = 0;i < a->NumItem;i++)
	{
		Free(a->ItemName[i]);
	}
	Free(a->ItemName);
	Free(a->ItemType);
}

// RPC_ENUM_OBJECT_IN_SECURE
void OutRpcEnumObjectInSecure(PACK *p, RPC_ENUM_OBJECT_IN_SECURE *e)
{
	UINT i;
	// Validate arguments
	if (e == NULL || p == NULL)
	{
		return;
	}

	PackAddNum(p, "NumItem", e->NumItem);
	PackAddInt(p, "hWnd", e->hWnd);

	PackSetCurrentJsonGroupName(p, "ObjectList");
	for (i = 0;i < e->NumItem;i++)
	{
		PackAddStrEx(p, "ItemName", e->ItemName[i], i, e->NumItem);
		PackAddIntEx(p, "ItemType", e->ItemType[i], i, e->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}

// RPC_CLIENT_CREATE_VLAN
void InRpcCreateVLan(RPC_CLIENT_CREATE_VLAN *v, PACK *p)
{
	// Validate arguments
	if (v == NULL || p == NULL)
	{
		return;
	}

	Zero(v, sizeof(RPC_CLIENT_CREATE_VLAN));
	PackGetStr(p, "DeviceName", v->DeviceName, sizeof(v->DeviceName));
}
void OutRpcCreateVLan(PACK *p, RPC_CLIENT_CREATE_VLAN *v)
{
	// Validate arguments
	if (v == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", v->DeviceName);
}

// RPC_CLIENT_GET_VLAN
void InRpcClientGetVLan(RPC_CLIENT_GET_VLAN *v, PACK *p)
{
	// Validate arguments
	if (v == NULL || p == NULL)
	{
		return;
	}

	Zero(v, sizeof(RPC_CLIENT_GET_VLAN));
	PackGetStr(p, "DeviceName", v->DeviceName, sizeof(v->DeviceName));
	v->Enabled = PackGetInt(p, "Enabled") ? true : false;
	PackGetStr(p, "MacAddress", v->MacAddress, sizeof(v->MacAddress));
	PackGetStr(p, "Version", v->Version, sizeof(v->Version));
	PackGetStr(p, "FileName", v->FileName, sizeof(v->FileName));
	PackGetStr(p, "Guid", v->Guid, sizeof(v->Guid));
}
void OutRpcClientGetVLan(PACK *p, RPC_CLIENT_GET_VLAN *v)
{
	// Validate arguments
	if (v == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", v->DeviceName);
	PackAddInt(p, "Enabled", v->Enabled);
	PackAddStr(p, "MacAddress", v->MacAddress);
	PackAddStr(p, "Version", v->Version);
	PackAddStr(p, "FileName", v->FileName);
	PackAddStr(p, "Guid", v->Guid);
}

// RPC_CLIENT_SET_VLAN
void InRpcClientSetVLan(RPC_CLIENT_SET_VLAN *v, PACK *p)
{
	// Validate arguments
	if (v == NULL || p == NULL)
	{
		return;
	}

	Zero(v, sizeof(RPC_CLIENT_SET_VLAN));
	PackGetStr(p, "DeviceName", v->DeviceName, sizeof(v->DeviceName));
	PackGetStr(p, "MacAddress", v->MacAddress, sizeof(v->MacAddress));
}
void OutRpcClientSetVLan(PACK *p, RPC_CLIENT_SET_VLAN *v)
{
	// Validate arguments
	if (v == NULL || p == NULL)
	{
		return;
	}

	PackAddStr(p, "DeviceName", v->DeviceName);
	PackAddStr(p, "MacAddress", v->MacAddress);
}

// RPC_CLIENT_ENUM_VLAN
void InRpcClientEnumVLan(RPC_CLIENT_ENUM_VLAN *v, PACK *p)
{
	UINT i;
	// Validate arguments
	if (v == NULL || p == NULL)
	{
		return;
	}

	Zero(v, sizeof(RPC_CLIENT_ENUM_VLAN));
	v->NumItem = PackGetNum(p, "NumItem");
	v->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM *) * v->NumItem);

	for (i = 0;i < v->NumItem;i++)
	{
		RPC_CLIENT_ENUM_VLAN_ITEM *item = v->Items[i] =
			ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM));

		PackGetStrEx(p, "DeviceName", item->DeviceName, sizeof(item->DeviceName), i);
		item->Enabled = PackGetIntEx(p, "Enabled", i) ? true : false;
		PackGetStrEx(p, "MacAddress", item->MacAddress, sizeof(item->MacAddress), i);
		PackGetStrEx(p, "Version", item->Version, sizeof(item->Version), i);
	}
}
void OutRpcClientEnumVLan(PACK *p, RPC_CLIENT_ENUM_VLAN *v)
{
	UINT i;
	// Validate arguments
	if (v == NULL || p == NULL)
	{
		return;
	}

	PackAddNum(p, "NumItem", v->NumItem);

	PackSetCurrentJsonGroupName(p, "VLanList");
	for (i = 0;i < v->NumItem;i++)
	{
		RPC_CLIENT_ENUM_VLAN_ITEM *item = v->Items[i];

		PackAddStrEx(p, "DeviceName", item->DeviceName, i, v->NumItem);
		PackAddIntEx(p, "Enabled", item->Enabled, i, v->NumItem);
		PackAddStrEx(p, "MacAddress", item->MacAddress, i, v->NumItem);
		PackAddStrEx(p, "Version", item->Version, i, v->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}

// CLIENT_OPTION
void InRpcClientOption(CLIENT_OPTION *c, PACK *p)
{
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(CLIENT_OPTION));

	PackGetUniStr(p, "AccountName", c->AccountName, sizeof(c->AccountName));
	PackGetStr(p, "Hostname", c->Hostname, sizeof(c->Hostname));
	c->Port = PackGetInt(p, "Port");
	c->PortUDP = PackGetInt(p, "PortUDP");
	c->ProxyType = PackGetInt(p, "ProxyType");
	c->ProxyPort = PackGetInt(p, "ProxyPort");
	c->NumRetry = PackGetInt(p, "NumRetry");
	c->RetryInterval = PackGetInt(p, "RetryInterval");
	c->MaxConnection = PackGetInt(p, "MaxConnection");
	c->AdditionalConnectionInterval = PackGetInt(p, "AdditionalConnectionInterval");
	c->ConnectionDisconnectSpan = PackGetInt(p, "ConnectionDisconnectSpan");
	c->HideStatusWindow = PackGetBool(p, "HideStatusWindow");
	c->HideNicInfoWindow = PackGetBool(p, "HideNicInfoWindow");
	c->DisableQoS = PackGetBool(p, "DisableQoS");
	PackGetStr(p, "ProxyName", c->ProxyName, sizeof(c->ProxyName));
	PackGetStr(p, "ProxyUsername", c->ProxyUsername, sizeof(c->ProxyUsername));
	PackGetStr(p, "ProxyPassword", c->ProxyPassword, sizeof(c->ProxyPassword));
	PackGetStr(p, "CustomHttpHeader", c->CustomHttpHeader, sizeof(c->CustomHttpHeader));
	PackGetStr(p, "HubName", c->HubName, sizeof(c->HubName));
	PackGetStr(p, "DeviceName", c->DeviceName, sizeof(c->DeviceName));
	c->UseEncrypt = PackGetInt(p, "UseEncrypt") ? true : false;
	c->UseCompress = PackGetInt(p, "UseCompress") ? true : false;
	c->HalfConnection = PackGetInt(p, "HalfConnection") ? true : false;
	c->NoRoutingTracking = PackGetInt(p, "NoRoutingTracking") ? true : false;
	c->RequireMonitorMode = PackGetBool(p, "RequireMonitorMode");
	c->RequireBridgeRoutingMode = PackGetBool(p, "RequireBridgeRoutingMode");
	c->FromAdminPack = PackGetBool(p, "FromAdminPack");
	c->NoUdpAcceleration = PackGetBool(p, "NoUdpAcceleration");
	PackGetData2(p, "HostUniqueKey", c->HostUniqueKey, SHA1_SIZE);
}
void OutRpcClientOption(PACK *p, CLIENT_OPTION *c)
{
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddUniStr(p, "AccountName", c->AccountName);
	PackAddStr(p, "Hostname", c->Hostname);
	PackAddStr(p, "ProxyName", c->ProxyName);
	PackAddStr(p, "ProxyUsername", c->ProxyUsername);
	PackAddStr(p, "ProxyPassword", c->ProxyPassword);
	PackAddStr(p, "CustomHttpHeader", c->CustomHttpHeader);
	PackAddStr(p, "HubName", c->HubName);
	PackAddStr(p, "DeviceName", c->DeviceName);
	PackAddInt(p, "Port", c->Port);
	PackAddInt(p, "PortUDP", c->PortUDP);
	PackAddInt(p, "ProxyType", c->ProxyType);
	PackAddInt(p, "ProxyPort", c->ProxyPort);
	PackAddInt(p, "NumRetry", c->NumRetry);
	PackAddInt(p, "RetryInterval", c->RetryInterval);
	PackAddInt(p, "MaxConnection", c->MaxConnection);
	PackAddBool(p, "UseEncrypt", c->UseEncrypt);
	PackAddBool(p, "UseCompress", c->UseCompress);
	PackAddBool(p, "HalfConnection", c->HalfConnection);
	PackAddBool(p, "NoRoutingTracking", c->NoRoutingTracking);
	PackAddInt(p, "AdditionalConnectionInterval", c->AdditionalConnectionInterval);
	PackAddInt(p, "ConnectionDisconnectSpan", c->ConnectionDisconnectSpan);
	PackAddBool(p, "HideStatusWindow", c->HideStatusWindow);
	PackAddBool(p, "HideNicInfoWindow", c->HideNicInfoWindow);
	PackAddBool(p, "RequireMonitorMode", c->RequireMonitorMode);
	PackAddBool(p, "RequireBridgeRoutingMode", c->RequireBridgeRoutingMode);
	PackAddBool(p, "DisableQoS", c->DisableQoS);
	PackAddBool(p, "FromAdminPack", c->FromAdminPack);
	PackAddBool(p, "NoUdpAcceleration", c->NoUdpAcceleration);
	PackAddData(p, "HostUniqueKey", c->HostUniqueKey, SHA1_SIZE);
}

// CLIENT_AUTH
void InRpcClientAuth(CLIENT_AUTH *c, PACK *p)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(CLIENT_AUTH));
	c->AuthType = PackGetInt(p, "AuthType");
	PackGetStr(p, "Username", c->Username, sizeof(c->Username));

	switch (c->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		if (PackGetDataSize(p, "HashedPassword") == SHA1_SIZE)
		{
			PackGetData(p, "HashedPassword", c->HashedPassword);
		}
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		PackGetStr(p, "PlainPassword", c->PlainPassword, sizeof(c->PlainPassword));
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = PackGetBuf(p, "ClientX");
		if (b != NULL)
		{
			c->ClientX = BufToX(b, false);
			FreeBuf(b);
		}
		b = PackGetBuf(p, "ClientK");
		if (b != NULL)
		{
			c->ClientK = BufToK(b, true, false, NULL);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_SECURE:
		PackGetStr(p, "SecurePublicCertName", c->SecurePublicCertName, sizeof(c->SecurePublicCertName));
		PackGetStr(p, "SecurePrivateKeyName", c->SecurePrivateKeyName, sizeof(c->SecurePrivateKeyName));
		break;
	}
}
void OutRpcClientAuth(PACK *p, CLIENT_AUTH *c)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddInt(p, "AuthType", c->AuthType);
	PackAddStr(p, "Username", c->Username);

	switch (c->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		PackAddData(p, "HashedPassword", c->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		PackAddStr(p, "PlainPassword", c->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = XToBuf(c->ClientX, false);
		if (b != NULL)
		{
			PackAddBuf(p, "ClientX", b);
			FreeBuf(b);
		}
		b = KToBuf(c->ClientK, false, NULL);
		if (b != NULL)
		{
			PackAddBuf(p, "ClientK", b);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_SECURE:
		PackAddStr(p, "SecurePublicCertName", c->SecurePublicCertName);
		PackAddStr(p, "SecurePrivateKeyName", c->SecurePrivateKeyName);
		break;
	}
}

// RPC_CLIENT_CREATE_ACCOUNT
void InRpcClientCreateAccount(RPC_CLIENT_CREATE_ACCOUNT *c, PACK *p)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_CLIENT_CREATE_ACCOUNT));
	c->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	c->ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));

	InRpcClientOption(c->ClientOption, p);
	InRpcClientAuth(c->ClientAuth, p);

	c->StartupAccount = PackGetInt(p, "StartupAccount") ? true : false;
	c->CheckServerCert = PackGetInt(p, "CheckServerCert") ? true : false;
	c->RetryOnServerCert = PackGetInt(p, "RetryOnServerCert") ? true : false;
	b = PackGetBuf(p, "ServerCert");
	if (b != NULL)
	{
		c->ServerCert = BufToX(b, false);
		FreeBuf(b);
	}
	PackGetData2(p, "ShortcutKey", c->ShortcutKey, sizeof(c->ShortcutKey));
}
void OutRpcClientCreateAccount(PACK *p, RPC_CLIENT_CREATE_ACCOUNT *c)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	OutRpcClientOption(p, c->ClientOption);
	OutRpcClientAuth(p, c->ClientAuth);

	PackAddInt(p, "StartupAccount", c->StartupAccount);
	PackAddInt(p, "CheckServerCert", c->CheckServerCert);
	PackAddInt(p, "RetryOnServerCert", c->RetryOnServerCert);
	if (c->ServerCert != NULL)
	{
		b = XToBuf(c->ServerCert, false);
		if (b != NULL)
		{
			PackAddBuf(p, "ServerCert", b);
			FreeBuf(b);
		}
	}
	PackAddData(p, "ShortcutKey", c->ShortcutKey, sizeof(c->ShortcutKey));
}

// RPC_CLIENT_ENUM_ACCOUNT
void InRpcClientEnumAccount(RPC_CLIENT_ENUM_ACCOUNT *e, PACK *p)
{
	UINT i;
	// Validate arguments
	if (e == NULL || p == NULL)
	{
		return;
	}

	Zero(e, sizeof(RPC_CLIENT_ENUM_ACCOUNT));

	e->NumItem = PackGetNum(p, "NumItem");
	e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_ACCOUNT_ITEM *) * e->NumItem);

	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_ACCOUNT_ITEM *item = e->Items[i] =
			ZeroMalloc(sizeof(RPC_CLIENT_ENUM_ACCOUNT_ITEM));

		PackGetUniStrEx(p, "AccountName", item->AccountName, sizeof(item->AccountName), i);
		PackGetStrEx(p, "UserName", item->UserName, sizeof(item->UserName), i);
		PackGetStrEx(p, "ServerName", item->ServerName, sizeof(item->ServerName), i);
		PackGetStrEx(p, "ProxyName", item->ProxyName, sizeof(item->ProxyName), i);
		PackGetStrEx(p, "DeviceName", item->DeviceName, sizeof(item->DeviceName), i);
		item->ProxyType = PackGetIntEx(p, "ProxyType", i);
		item->Active = PackGetIntEx(p, "Active", i) ? true : false;
		item->StartupAccount = PackGetIntEx(p, "StartupAccount", i) ? true : false;
		item->Connected = PackGetBoolEx(p, "Connected", i);
		item->Port = PackGetIntEx(p, "Port", i);
		PackGetStrEx(p, "HubName", item->HubName, sizeof(item->HubName), i);
		item->CreateDateTime = PackGetInt64Ex(p, "CreateDateTime", i);
		item->UpdateDateTime = PackGetInt64Ex(p, "UpdateDateTime", i);
		item->LastConnectDateTime = PackGetInt64Ex(p, "LastConnectDateTime", i);
	}
}
void OutRpcClientEnumAccount(PACK *p, RPC_CLIENT_ENUM_ACCOUNT *e)
{
	UINT i;
	// Validate arguments
	if (e == NULL || p == NULL)
	{
		return;
	}

	PackAddNum(p, "NumItem", e->NumItem);

	PackSetCurrentJsonGroupName(p, "AccountList");
	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_ACCOUNT_ITEM *item = e->Items[i];

		PackAddUniStrEx(p, "AccountName", item->AccountName, i, e->NumItem);
		PackAddStrEx(p, "UserName", item->UserName, i, e->NumItem);
		PackAddStrEx(p, "ServerName", item->ServerName, i, e->NumItem);
		PackAddStrEx(p, "ProxyName", item->ProxyName, i, e->NumItem);
		PackAddStrEx(p, "DeviceName", item->DeviceName, i, e->NumItem);
		PackAddIntEx(p, "ProxyType", item->ProxyType, i, e->NumItem);
		PackAddIntEx(p, "Active", item->Active, i, e->NumItem);
		PackAddIntEx(p, "StartupAccount", item->StartupAccount, i, e->NumItem);
		PackAddBoolEx(p, "Connected", item->Connected, i, e->NumItem);
		PackAddIntEx(p, "Port", item->Port, i, e->NumItem);
		PackAddStrEx(p, "HubName", item->HubName, i, e->NumItem);
		PackAddTime64Ex(p, "CreateDateTime", item->CreateDateTime, i, e->NumItem);
		PackAddTime64Ex(p, "UpdateDateTime", item->UpdateDateTime, i, e->NumItem);
		PackAddTime64Ex(p, "LastConnectDateTime", item->LastConnectDateTime, i, e->NumItem);
	}
	PackSetCurrentJsonGroupName(p, NULL);
}

// RPC_CLIENT_DELETE_ACCOUNT
void InRpcClientDeleteAccount(RPC_CLIENT_DELETE_ACCOUNT *a, PACK *p)
{
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(RPC_CLIENT_DELETE_ACCOUNT));
	PackGetUniStr(p, "AccountName", a->AccountName, sizeof(a->AccountName));
}
void OutRpcClientDeleteAccount(PACK *p, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}

	PackAddUniStr(p, "AccountName", a->AccountName);
}

// RPC_RENAME_ACCOUNT
void InRpcRenameAccount(RPC_RENAME_ACCOUNT *a, PACK *p)
{
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}

	Zero(a, sizeof(RPC_RENAME_ACCOUNT));

	PackGetUniStr(p, "OldName", a->OldName, sizeof(a->OldName));
	PackGetUniStr(p, "NewName", a->NewName, sizeof(a->NewName));
}
void OutRpcRenameAccount(PACK *p, RPC_RENAME_ACCOUNT *a)
{
	// Validate arguments
	if (a == NULL || p == NULL)
	{
		return;
	}

	PackAddUniStr(p, "OldName", a->OldName);
	PackAddUniStr(p, "NewName", a->NewName);
}

// RPC_CLIENT_GET_ACCOUNT
void InRpcClientGetAccount(RPC_CLIENT_GET_ACCOUNT *c, PACK *p)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_CLIENT_GET_ACCOUNT));

	c->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	c->ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));

	PackGetUniStr(p, "AccountName", c->AccountName, sizeof(c->AccountName));
	c->StartupAccount = PackGetInt(p, "StartupAccount") ? true : false;
	c->CheckServerCert = PackGetInt(p, "CheckServerCert") ? true : false;
	c->RetryOnServerCert = PackGetInt(p, "RetryOnServerCert") ? true : false;
	b = PackGetBuf(p, "ServerCert");
	if (b != NULL)
	{
		c->ServerCert = BufToX(b, false);
		FreeBuf(b);
	}

	InRpcClientOption(c->ClientOption, p);
	InRpcClientAuth(c->ClientAuth, p);

	c->CreateDateTime = PackGetInt64(p, "CreateDateTime");
	c->UpdateDateTime = PackGetInt64(p, "UpdateDateTime");
	c->LastConnectDateTime = PackGetInt64(p, "LastConnectDateTime");

	PackGetData2(p, "ShortcutKey", c->ShortcutKey, SHA1_SIZE);
}
void OutRpcClientGetAccount(PACK *p, RPC_CLIENT_GET_ACCOUNT *c)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddUniStr(p, "AccountName", c->AccountName);
	PackAddInt(p, "StartupAccount", c->StartupAccount);
	PackAddInt(p, "CheckServerCert", c->CheckServerCert);
	PackAddInt(p, "RetryOnServerCert", c->RetryOnServerCert);

	if (c->ServerCert != NULL)
	{
		b = XToBuf(c->ServerCert, false);
		if (b != NULL)
		{
			PackAddBuf(p, "ServerCert", b);
			FreeBuf(b);
		}
	}

	OutRpcClientOption(p, c->ClientOption);
	OutRpcClientAuth(p, c->ClientAuth);

	PackAddData(p, "ShortcutKey", c->ShortcutKey, SHA1_SIZE);

	PackAddTime64(p, "CreateDateTime", c->CreateDateTime);
	PackAddTime64(p, "UpdateDateTime", c->UpdateDateTime);
	PackAddTime64(p, "LastConnectDateTime", c->LastConnectDateTime);
}

// RPC_CLIENT_CONNECT
void InRpcClientConnect(RPC_CLIENT_CONNECT *c, PACK *p)
{
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	Zero(c, sizeof(RPC_CLIENT_CONNECT));

	PackGetUniStr(p, "AccountName", c->AccountName, sizeof(c->AccountName));
}
void OutRpcClientConnect(PACK *p, RPC_CLIENT_CONNECT *c)
{
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return;
	}

	PackAddUniStr(p, "AccountName", c->AccountName);
}

// POLICY
void InRpcPolicy(POLICY *o, PACK *p)
{
	POLICY *pol;
	// Validate arguments
	if (o == NULL || p == NULL)
	{
		return;
	}

	pol = PackGetPolicy(p);
	Copy(o, pol, sizeof(POLICY));
	Free(pol);
}
void OutRpcPolicy(PACK *p, POLICY *o)
{
	// Validate arguments
	if (o == NULL || p == NULL)
	{
		return;
	}

	PackAddPolicy(p, o);
}

// RPC_CLIENT_GET_CONNECTION_STATUS
void InRpcClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *s, PACK *p)
{
	BUF *b;
	// Validate arguments
	if (s == NULL || p == NULL)
	{
		return;
	}

	Zero(s, sizeof(RPC_CLIENT_GET_CONNECTION_STATUS));

	PackGetUniStr(p, "AccountName", s->AccountName, sizeof(s->AccountName));

	PackGetStr(p, "ServerName", s->ServerName, sizeof(s->ServerName));
	PackGetStr(p, "ServerProductName", s->ServerProductName, sizeof(s->ServerProductName));
	PackGetStr(p, "CipherName", s->CipherName, sizeof(s->CipherName));
	PackGetStr(p, "SessionName", s->SessionName, sizeof(s->SessionName));
	PackGetStr(p, "ConnectionName", s->ConnectionName, sizeof(s->ConnectionName));

	if (PackGetDataSize(p, "SessionKey") == SHA1_SIZE)
	{
		PackGetData(p, "SessionKey", s->SessionKey);
	}

	s->SessionStatus = PackGetInt(p, "SessionStatus");
	s->ServerPort = PackGetInt(p, "ServerPort");
	s->ServerProductVer = PackGetInt(p, "ServerProductVer");
	s->ServerProductBuild = PackGetInt(p, "ServerProductBuild");
	s->NumConnectionsEstablished = PackGetInt(p, "NumConnectionsEstablished");
	s->MaxTcpConnections = PackGetInt(p, "MaxTcpConnections");
	s->NumTcpConnections = PackGetInt(p, "NumTcpConnections");
	s->NumTcpConnectionsUpload = PackGetInt(p, "NumTcpConnectionsUpload");
	s->NumTcpConnectionsDownload = PackGetInt(p, "NumTcpConnectionsDownload");

	s->StartTime = PackGetInt64(p, "StartTime");
	/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
	s->FirstConnectionEstablisiedTime = PackGetInt64(p, "FirstConnectionEstablisiedTime");
	s->CurrentConnectionEstablishTime = PackGetInt64(p, "CurrentConnectionEstablishTime");
	s->TotalSendSize = PackGetInt64(p, "TotalSendSize");
	s->TotalRecvSize = PackGetInt64(p, "TotalRecvSize");
	s->TotalSendSizeReal = PackGetInt64(p, "TotalSendSizeReal");
	s->TotalRecvSizeReal = PackGetInt64(p, "TotalRecvSizeReal");

	s->Active = PackGetInt(p, "Active") ? true : false;
	s->Connected = PackGetInt(p, "Connected") ? true : false;
	s->HalfConnection = PackGetInt(p, "HalfConnection") ? true : false;
	s->QoS = PackGetInt(p, "QoS") ? true : false;
	s->UseEncrypt = PackGetInt(p, "UseEncrypt") ? true : false;
	s->UseCompress = PackGetInt(p, "UseCompress") ? true : false;
	s->IsRUDPSession = PackGetInt(p, "IsRUDPSession") ? true : false;
	PackGetStr(p, "UnderlayProtocol", s->UnderlayProtocol, sizeof(s->UnderlayProtocol));
	s->IsUdpAccelerationEnabled = PackGetInt(p, "IsUdpAccelerationEnabled") ? true : false;
	s->IsUsingUdpAcceleration = PackGetInt(p, "IsUsingUdpAcceleration") ? true : false;

	s->IsBridgeMode = PackGetBool(p, "IsBridgeMode");
	s->IsMonitorMode = PackGetBool(p, "IsMonitorMode");

	s->VLanId = PackGetInt(p, "VLanId");

	b = PackGetBuf(p, "ServerX");
	if (b != NULL)
	{
		s->ServerX = BufToX(b, false);
		FreeBuf(b);
	}

	b = PackGetBuf(p, "ClientX");
	if (b != NULL)
	{
		s->ClientX = BufToX(b, false);
		FreeBuf(b);
	}

	InRpcPolicy(&s->Policy, p);

	InRpcTraffic(&s->Traffic, p);
}
void OutRpcClientGetConnectionStatus(PACK *p, RPC_CLIENT_GET_CONNECTION_STATUS *c)
{
	BUF *b;
	// Validate arguments
	if (p == NULL || c == NULL)
	{
		return;
	}

	PackAddUniStr(p, "AccountName", c->AccountName);

	PackAddStr(p, "ServerName", c->ServerName);
	PackAddStr(p, "ServerProductName", c->ServerProductName);
	PackAddStr(p, "CipherName", c->CipherName);
	PackAddStr(p, "SessionName", c->SessionName);
	PackAddStr(p, "ConnectionName", c->ConnectionName);

	PackAddData(p, "SessionKey", c->SessionKey, SHA1_SIZE);

	PackAddBool(p, "Active", c->Active);
	PackAddBool(p, "Connected", c->Connected);
	PackAddInt(p, "SessionStatus", c->SessionStatus);
	PackAddInt(p, "ServerPort", c->ServerPort);
	PackAddInt(p, "ServerProductVer", c->ServerProductVer);
	PackAddInt(p, "ServerProductBuild", c->ServerProductBuild);
	PackAddInt(p, "NumConnectionsEstablished", c->NumConnectionsEstablished);
	PackAddBool(p, "HalfConnection", c->HalfConnection);
	PackAddBool(p, "QoS", c->QoS);
	PackAddInt(p, "MaxTcpConnections", c->MaxTcpConnections);
	PackAddInt(p, "NumTcpConnections", c->NumTcpConnections);
	PackAddInt(p, "NumTcpConnectionsUpload", c->NumTcpConnectionsUpload);
	PackAddInt(p, "NumTcpConnectionsDownload", c->NumTcpConnectionsDownload);
	PackAddBool(p, "UseEncrypt", c->UseEncrypt);
	PackAddBool(p, "UseCompress", c->UseCompress);
	PackAddBool(p, "IsRUDPSession", c->IsRUDPSession);
	PackAddStr(p, "UnderlayProtocol", c->UnderlayProtocol);
	PackAddBool(p, "IsUdpAccelerationEnabled", c->IsUdpAccelerationEnabled);
	PackAddBool(p, "IsUsingUdpAcceleration", c->IsUsingUdpAcceleration);

	PackAddBool(p, "IsBridgeMode", c->IsBridgeMode);
	PackAddBool(p, "IsMonitorMode", c->IsMonitorMode);

	PackAddTime64(p, "StartTime", c->StartTime);
	PackAddTime64(p, "FirstConnectionEstablisiedTime", c->FirstConnectionEstablisiedTime);
	PackAddTime64(p, "CurrentConnectionEstablishTime", c->CurrentConnectionEstablishTime);
	PackAddInt64(p, "TotalSendSize", c->TotalSendSize);
	PackAddInt64(p, "TotalRecvSize", c->TotalRecvSize);
	PackAddInt64(p, "TotalSendSizeReal", c->TotalSendSizeReal);
	PackAddInt64(p, "TotalRecvSizeReal", c->TotalRecvSizeReal);

	PackAddInt(p, "VLanId", c->VLanId);

	OutRpcPolicy(p, &c->Policy);

	OutRpcTraffic(p, &c->Traffic);

	if (c->ServerX != NULL)
	{
		b = XToBuf(c->ServerX, false);
		PackAddBuf(p, "ServerX", b);
		FreeBuf(b);
	}

	if (c->ClientX != NULL)
	{
		b = XToBuf(c->ClientX, false);
		PackAddBuf(p, "ClientX", b);
		FreeBuf(b);
	}
}

// Notification main
void CiNotifyMain(CLIENT *c, SOCK *s)
{
	CANCEL *cancel;
	// Validate arguments
	if (c == NULL || s == NULL)
	{
		return;
	}

	// Register a Cancel
	cancel = NewCancel();
	LockList(c->NotifyCancelList);
	{
		Add(c->NotifyCancelList, cancel);
	}
	UnlockList(c->NotifyCancelList);

	// Wait
	while (true)
	{
		char ch = '@';
		SOCKSET set;
		InitSockSet(&set);
		AddSockSet(&set, s);
		Select(&set, INFINITE, cancel, NULL);

		if (c->Halt)
		{
			// Abort
			break;
		}

		// 1 byte transmission
		if (Send(s, &ch, 1, false) == 0)
		{
			// Disconnected
			break;
		}
	}

	// Disconnect
	Disconnect(s);

	// Unregister the Cancel
	LockList(c->NotifyCancelList);
	{
		Delete(c->NotifyCancelList, cancel);
	}
	UnlockList(c->NotifyCancelList);

	ReleaseCancel(cancel);
}

// RPC acceptance code
void CiRpcAccepted(CLIENT *c, SOCK *s)
{
	UCHAR hashed_password[SHA1_SIZE];
	UINT rpc_mode;
	UINT retcode;
	RPC *rpc;
	// Validate arguments
	if (c == NULL || s == NULL)
	{
		return;
	}

	// Receive the RPC mode
	if (RecvAll(s, &rpc_mode, sizeof(UINT), false) == false)
	{
		return;
	}

	rpc_mode = Endian32(rpc_mode);

	if (rpc_mode == CLIENT_RPC_MODE_NOTIFY)
	{
		// Notification mode
		CiNotifyMain(c, s);
		return;
	}
	else if (rpc_mode == CLIENT_RPC_MODE_SHORTCUT || rpc_mode == CLIENT_RPC_MODE_SHORTCUT_DISCONNECT)
	{
		// Shortcut key received
		UCHAR key[SHA1_SIZE];
		UINT err = ERR_NO_ERROR;
		if (RecvAll(s, key, SHA1_SIZE, false))
		{
			UINT i;
			wchar_t title[MAX_ACCOUNT_NAME_LEN + 1];
			bool ok = false;
			// Connect to the specified setting
			LockList(c->AccountList);
			{
				for (i = 0;i < LIST_NUM(c->AccountList);i++)
				{
					ACCOUNT *a = LIST_DATA(c->AccountList, i);
					Lock(a->lock);
					{
						if (Cmp(a->ShortcutKey, key, SHA1_SIZE) == 0)
						{
							ok = true;
							UniStrCpy(title, sizeof(title), a->ClientOption->AccountName);
						}
					}
					Unlock(a->lock);
				}
			}
			UnlockList(c->AccountList);

			if (ok == false)
			{
				err = ERR_ACCOUNT_NOT_FOUND;
			}
			else
			{
				RPC_CLIENT_CONNECT t;
				Zero(&t, sizeof(t));
				UniStrCpy(t.AccountName, sizeof(t.AccountName), title);

				if (rpc_mode == CLIENT_RPC_MODE_SHORTCUT)
				{
					// Connect
					if (CtConnect(c, &t))
					{
						err = ERR_NO_ERROR;
					}
					else
					{
						err = c->Err;
					}
				}
				else
				{
					// Connect
					if (CtDisconnect(c, &t, false))
					{
						err = ERR_NO_ERROR;
					}
					else
					{
						err = c->Err;
					}
				}
			}

			err = Endian32(err);
			SendAll(s, &err, sizeof(UINT), false);
			(void)RecvAll(s, &err, sizeof(UINT), false);
		}
		return;
	}

	// Password reception
	if (RecvAll(s, hashed_password, SHA1_SIZE, false) == false)
	{
		return;
	}

	retcode = 0;

	// Password comparison
	if (Cmp(hashed_password, c->EncryptedPassword, SHA1_SIZE) != 0)
	{
		retcode = 1;
	}

	if (c->PasswordRemoteOnly && s->RemoteIP.addr[0] == 127)
	{
		// If in a mode that requires a password only remote,
		// the password sent from localhost is considered to be always correct
		retcode = 0;
	}

	Lock(c->lock);
	{
		if (c->Config.AllowRemoteConfig == false)
		{
			// If the remote control is prohibited,
			// identify whether this connection is from remote
			if (s->RemoteIP.addr[0] != 127)
			{
				retcode = 2;
			}
		}
	}
	Unlock(c->lock);

	retcode = Endian32(retcode);
	// Error code transmission
	if (SendAll(s, &retcode, sizeof(UINT), false) == false)
	{
		return;
	}



	if (retcode != 0)
	{
		// Disconnect due to an error
		return;
	}

	// Create a RPC server
	rpc = StartRpcServer(s, CiRpcDispatch, c);

	// RPC server operation
	RpcServer(rpc);

	// Release the RPC server
	EndRpc(rpc);
}

// RPC acceptance thread
void CiRpcAcceptThread(THREAD *thread, void *param)
{
	CLIENT_RPC_CONNECTION *conn;
	CLIENT *c;
	SOCK *s;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	conn = (CLIENT_RPC_CONNECTION *)param;
	s = conn->Sock;
	c = conn->Client;
	AddRef(s->ref);

	// Add to the RPC connection list
	LockList(c->RpcConnectionList);
	{
		Add(c->RpcConnectionList, conn);
	}
	UnlockList(c->RpcConnectionList);

	NoticeThreadInit(thread);

	// Main process
	CiRpcAccepted(c, s);

	// Release from the connection list
	LockList(c->RpcConnectionList);
	{
		Delete(c->RpcConnectionList, conn);
	}
	UnlockList(c->RpcConnectionList);

	ReleaseSock(conn->Sock);
	ReleaseThread(conn->Thread);
	Free(conn);

	Disconnect(s);
	ReleaseSock(s);
}

// RPC server thread
void CiRpcServerThread(THREAD *thread, void *param)
{
	CLIENT *c;
	SOCK *listener;
	UINT i;
	LIST *thread_list;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	c = (CLIENT *)param;

	// RPC connection list
	c->RpcConnectionList = NewList(NULL);

	// Open the port
	listener = NULL;
	for (i = CLIENT_CONFIG_PORT;i < (CLIENT_CONFIG_PORT + 5);i++)
	{
		listener = Listen(i);
		if (listener != NULL)
		{
			break;
		}
	}

	if (listener == NULL)
	{
		// Error
		Alert(CEDAR_PRODUCT_STR " VPN Client RPC Port Open Failed.", CEDAR_CLIENT_STR);
		return;
	}

#ifdef OS_WIN32
	MsRegWriteIntEx2(REG_LOCAL_MACHINE, CLIENT_WIN32_REGKEYNAME, CLIENT_WIN32_REGVALUE_PORT, i, false, true);
	MsRegWriteIntEx2(REG_LOCAL_MACHINE, CLIENT_WIN32_REGKEYNAME, CLIENT_WIN32_REGVALUE_PID, MsGetCurrentProcessId(), false, true);
#endif	// OS_WIN32

	c->RpcListener = listener;
	AddRef(listener->ref);

	NoticeThreadInit(thread);

	while (true)
	{
		// Wait for client connection
		CLIENT_RPC_CONNECTION *conn;
		SOCK *s = Accept(listener);
		if (s == NULL)
		{
			// Stop
			break;
		}

		// Create a client processing thread
		conn = ZeroMalloc(sizeof(CLIENT_RPC_CONNECTION));
		conn->Client = c;
		conn->Sock = s;
		AddRef(s->ref);

		conn->Thread = NewThread(CiRpcAcceptThread, (void *)conn);
		WaitThreadInit(conn->Thread);

		ReleaseSock(s);
	}

	// Release the listener
	ReleaseSock(listener);

	thread_list = NewListFast(NULL);

	// Set all the event notification
	LockList(c->NotifyCancelList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(c->NotifyCancelList);i++)
		{
			CANCEL *cancel = LIST_DATA(c->NotifyCancelList, i);
			Cancel(cancel);
		}
	}
	UnlockList(c->NotifyCancelList);

	// Disconnect all the connections of connected yet
	LockList(c->RpcConnectionList);
	{
		for (i = 0;i < LIST_NUM(c->RpcConnectionList);i++)
		{
			CLIENT_RPC_CONNECTION *cc = LIST_DATA(c->RpcConnectionList, i);
			AddRef(cc->Thread->ref);
			Add(thread_list, cc->Thread);
			Disconnect(cc->Sock);
		}
	}
	UnlockList(c->RpcConnectionList);

	for (i = 0;i < LIST_NUM(thread_list);i++)
	{
		THREAD *t = LIST_DATA(thread_list, i);
		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	ReleaseList(c->RpcConnectionList);
	ReleaseList(thread_list);

#ifdef OS_WIN32
	MsRegDeleteValueEx2(REG_LOCAL_MACHINE, CLIENT_WIN32_REGKEYNAME, CLIENT_WIN32_REGVALUE_PORT, false, true);
	MsRegDeleteValueEx2(REG_LOCAL_MACHINE, CLIENT_WIN32_REGKEYNAME, CLIENT_WIN32_REGVALUE_PID, false, true);
#endif	// OS_WIN32
}

// Start the Keep
void CiInitKeep(CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	c->Keep = StartKeep();

	// Apply settings
	if (c->Config.UseKeepConnect)
	{
		KEEP *k = c->Keep;
		Lock(k->lock);
		{
			StrCpy(k->ServerName, sizeof(k->ServerName), c->Config.KeepConnectHost);
			k->ServerPort = c->Config.KeepConnectPort;
			k->Interval = c->Config.KeepConnectInterval * 1000;
			k->UdpMode = (c->Config.KeepConnectProtocol == CONNECTION_UDP) ? true : false;
			k->Enable = true;
		}
		Unlock(k->lock);
	}
}

// Stop the Keep
void CiFreeKeep(CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	StopKeep(c->Keep);
	c->Keep = NULL;
}

// Start the RPC
void CiStartRpcServer(CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	c->RpcThread = NewThread(CiRpcServerThread, (void *)c);
	WaitThreadInit(c->RpcThread);
}

// Stop the RPC
void CiStopRpcServer(CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	Disconnect(c->RpcListener);
	ReleaseSock(c->RpcListener);

	WaitThread(c->RpcThread, INFINITE);
	ReleaseThread(c->RpcThread);
}

// Wait for the next notification
bool CcWaitNotify(NOTIFY_CLIENT *n)
{
	UCHAR c;
	// Validate arguments
	if (n == NULL)
	{
		return false;
	}

	// 1 character reception
	if (RecvAll(n->Sock, &c, 1, false) == false)
	{
		// Disconnected
		return false;
	}

	return true;
}

// Connect as a notification client
NOTIFY_CLIENT *CcConnectNotify(REMOTE_CLIENT *rc)
{
	NOTIFY_CLIENT *n;
	SOCK *s;
	char tmp[MAX_SIZE];
	bool rpc_mode = false;
	UINT port;
	// Validate arguments
	if (rc == NULL || rc->Rpc == NULL || rc->Rpc->Sock == NULL)
	{
		return NULL;
	}

	// Connect
	IPToStr(tmp, sizeof(tmp), &rc->Rpc->Sock->RemoteIP);
	port = rc->Rpc->Sock->RemotePort;

	s = Connect(tmp, port);
	if (s == NULL)
	{
		return NULL;
	}

	rpc_mode = Endian32(rpc_mode);
	if (SendAll(s, &rpc_mode, sizeof(rpc_mode), false) == false)
	{
		ReleaseSock(s);
		return NULL;
	}

	n = ZeroMalloc(sizeof(NOTIFY_CLIENT));
	n->Sock = s;

	return n;
}

// Stop the notification client
void CcStopNotify(NOTIFY_CLIENT *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	Disconnect(n->Sock);
}

// Delete the notification client
void CcDisconnectNotify(NOTIFY_CLIENT *n)
{
	// Validate arguments
	if (n == NULL)
	{
		return;
	}

	// Disconnect
	Disconnect(n->Sock);
	ReleaseSock(n->Sock);

	// Memory release
	Free(n);
}

// Disconnect the remote connection
void CcDisconnectRpc(REMOTE_CLIENT *rc)
{
	// Validate arguments
	if (rc == NULL)
	{
		return;
	}

	RpcFree(rc->Rpc);
	Free(rc);
}

// Connect to the client to start the shortcut connection setting
UINT CcShortcut(UCHAR *key)
{
	UINT ret;
	// Validate arguments
	if (key == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	CcConnectRpcEx("localhost", NULL, NULL, NULL, key, &ret, false, 0);

	return ret;
}

// Disconnect the connected shortcut connection
UINT CcShortcutDisconnect(UCHAR *key)
{
	UINT ret;
	// Validate arguments
	if (key == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	CcConnectRpcEx("localhost", NULL, NULL, NULL, key, &ret, true, 0);

	return ret;
}

// Connect to the remote client
REMOTE_CLIENT *CcConnectRpc(char *server_name, char *password, bool *bad_pass, bool *no_remote, UINT wait_retry)
{
	return CcConnectRpcEx(server_name, password, bad_pass, no_remote, NULL, NULL, false, wait_retry);
}
REMOTE_CLIENT *CcConnectRpcEx(char *server_name, char *password, bool *bad_pass, bool *no_remote, UCHAR *key, UINT *key_error_code, bool shortcut_disconnect, UINT wait_retry)
{
	SOCK *s = NULL;
	UINT i;
	UINT retcode;
	UINT rpc_mode = CLIENT_RPC_MODE_MANAGEMENT;
	RPC *rpc;
	REMOTE_CLIENT *ret;
	UCHAR hash_password[SHA1_SIZE];
	UINT port_start;
	UINT64 try_started = 0;
	bool ok;
	UINT reg_port = 0;
	UINT reg_pid = 0;
	// Validate arguments
	if (server_name == NULL)
	{
		return NULL;
	}
	if (password == NULL)
	{
		password = "";
	}

	if (key_error_code != NULL)
	{
		*key_error_code = ERR_NO_ERROR;
	}

	if (bad_pass != NULL)
	{
		*bad_pass = false;
	}

	if (no_remote != NULL)
	{
		*no_remote = false;
	}

#ifdef	OS_WIN32
	// read the current port number from the registry of the localhost
	if (StrCmpi(server_name, "localhost") == 0)
	{
		reg_port = MsRegReadIntEx2(REG_LOCAL_MACHINE, CLIENT_WIN32_REGKEYNAME, CLIENT_WIN32_REGVALUE_PORT, false, true);
		reg_pid = MsRegReadIntEx2(REG_LOCAL_MACHINE, CLIENT_WIN32_REGKEYNAME, CLIENT_WIN32_REGVALUE_PID, false, true);

		if (reg_pid != 0)
		{
			if (MsIsServiceRunning(GC_SVC_NAME_VPNCLIENT) == false)
			{
				reg_port = 0;
			}
		}
		else
		{
			reg_port = 0;
		}
	}

	if (reg_port != 0)
	{
		s = Connect(server_name, reg_port);

		if (s != NULL)
		{
			goto L_TRY;
		}
	}

#endif	// OS_WIN32

	port_start = CLIENT_CONFIG_PORT - 1;

RETRY:
	port_start++;

	if (port_start >= (CLIENT_CONFIG_PORT + 5))
	{
		return NULL;
	}

	ok = false;

	while (true)
	{
		for (i = port_start;i < (CLIENT_CONFIG_PORT + 5);i++)
		{
			if (CheckTCPPort(server_name, i))
			{
				ok = true;
				break;
			}
		}

		if (ok)
		{
			break;
		}

		if (wait_retry == 0)
		{
			break;
		}

		if (try_started == 0)
		{
			try_started = Tick64();
		}

		if ((try_started + (UINT64)wait_retry) <= Tick64())
		{
			break;
		}
	}

	if (ok == false)
	{
		if (key_error_code)
		{
			*key_error_code = ERR_CONNECT_FAILED;
		}
		return NULL;
	}

	port_start = i;

	s = Connect(server_name, i);
	if (s == NULL)
	{
		if (key_error_code)
		{
			*key_error_code = ERR_CONNECT_FAILED;
		}
		goto RETRY;
	}
L_TRY:

	SetTimeout(s, 10000);

	Sha0(hash_password, password, StrLen(password));

	if (key != NULL)
	{
		if (shortcut_disconnect == false)
		{
			rpc_mode = CLIENT_RPC_MODE_SHORTCUT;
		}
		else
		{
			rpc_mode = CLIENT_RPC_MODE_SHORTCUT_DISCONNECT;
		}
	}

	rpc_mode = Endian32(rpc_mode);
	SendAdd(s, &rpc_mode, sizeof(UINT));

	if (key != NULL)
	{
		SendAdd(s, key, SHA1_SIZE);
	}
	else
	{
		SendAdd(s, hash_password, SHA1_SIZE);
	}

	if (SendNow(s, false) == false)
	{
		ReleaseSock(s);
		goto RETRY;
	}

	if (RecvAll(s, &retcode, sizeof(UINT), false) == false)
	{
		ReleaseSock(s);
		goto RETRY;
	}

	retcode = Endian32(retcode);

	if (retcode >= 1024)
	{
		ReleaseSock(s);
		goto RETRY;
	}

	if (key != NULL)
	{
		if (key_error_code)
		{
			*key_error_code = retcode;
		}
		SendAll(s, &retcode, sizeof(UINT), false);
		ReleaseSock(s);
		return NULL;
	}

	switch (retcode)
	{
	case 1:
		if (bad_pass != NULL)
		{
			*bad_pass = true;
		}
		break;
	case 2:
		if (no_remote != NULL)
		{
			*no_remote = true;
		}
		break;
	}

	if (retcode != 0)
	{
		ReleaseSock(s);
		return NULL;
	}

	SetTimeout(s, INFINITE);

	rpc = StartRpcClient(s, NULL);

	ReleaseSock(s);

	ret = ZeroMalloc(sizeof(REMOTE_CLIENT));
	rpc->Param = ret;

	if (ret != NULL)
	{
		RPC_CLIENT_VERSION t;

		ret->Rpc = rpc;
		Zero(&t, sizeof(t));
		CcGetClientVersion(ret, &t);
		ret->OsType = t.OsType;
		ret->Unix = OS_IS_UNIX(ret->OsType);
		ret->Win9x = OS_IS_WINDOWS_9X(ret->OsType);
		ret->IsVgcSupported = t.IsVgcSupported;
		ret->ShowVgcLink = t.ShowVgcLink;
		StrCpy(ret->ClientId, sizeof(ret->ClientId), t.ClientId);
	}

	return ret;
}

// Get a RPC_CLIENT_GET_CONNECTION_STATUS from the session
void CiGetSessionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st, SESSION *s)
{
	// Validate arguments
	if (st == NULL || s == NULL)
	{
		return;
	}

	Lock(s->lock);
	{
		// Operation flag
		st->Active = true;

		// Session status
		st->SessionStatus = s->ClientStatus;

		// Account name
		UniStrCpy(st->AccountName, sizeof(st->AccountName), s->ClientOption->AccountName);

		if (s->ClientStatus == CLIENT_STATUS_ESTABLISHED && s->Connection != NULL)
		{
			Lock(s->Connection->lock);
			{
				// Connected flag
				st->Connected = true;
				// Product name
				StrCpy(st->ServerProductName, sizeof(st->ServerProductName), s->Connection->ServerStr);
				// Version
				st->ServerProductVer = s->Connection->ServerVer;
				// Build Number
				st->ServerProductBuild = s->Connection->ServerBuild;
				// Server certificate
				st->ServerX = CloneX(s->Connection->ServerX);
				// Client certificate
				st->ClientX = CloneX(s->Connection->ClientX);
				// Connection completion time of this connection
				st->CurrentConnectionEstablishTime = TickToTime(s->CurrentConnectionEstablishTime);
				// Maximum number of the TCP connections
				st->MaxTcpConnections = s->MaxConnection;
				// Half-connection
				st->HalfConnection = s->HalfConnection;
				// VLAN
				st->VLanId = s->VLanId;
				// VoIP / QoS
				st->QoS = s->QoS;
				if (s->Connection->Protocol == CONNECTION_TCP)
				{
					UINT i;
					// Number of current TCP connections
					LockList(s->Connection->Tcp->TcpSockList);
					{
						st->NumTcpConnections = LIST_NUM(s->Connection->Tcp->TcpSockList);
						if (st->HalfConnection)
						{
							for (i = 0;i < st->NumTcpConnections;i++)
							{
								TCPSOCK *ts = LIST_DATA(s->Connection->Tcp->TcpSockList, i);
								if (ts->Direction & TCP_SERVER_TO_CLIENT)
								{
									st->NumTcpConnectionsDownload++;
								}
								else
								{
									st->NumTcpConnectionsUpload++;
								}
							}
						}
					}
					UnlockList(s->Connection->Tcp->TcpSockList);
				}
				// Use of encryption
				st->UseEncrypt = s->UseEncrypt;
				if (st->UseEncrypt)
				{
					StrCpy(st->CipherName, sizeof(st->CipherName), s->Connection->CipherName);
				}
				// Use of compression
				st->UseCompress = s->UseCompress;
				// R-UDP
				st->IsRUDPSession = s->IsRUDPSession;
				// Physical communication protocol
				StrCpy(st->UnderlayProtocol, sizeof(st->UnderlayProtocol), s->UnderlayProtocol);
				// Protocol details
				StrCpy(st->ProtocolDetails, sizeof(st->ProtocolDetails), s->ProtocolDetails);
				Trim(st->ProtocolDetails);
				// UDP acceleration function
				if (s->IpcSessionShared != NULL && IsEmptyStr(s->IpcSessionShared->ProtocolDetails) == false)
				{
					char tmp[sizeof(s->IpcSessionShared->ProtocolDetails)];
					StrCpy(tmp, sizeof(tmp), s->IpcSessionShared->ProtocolDetails);
					Trim(tmp);
					StrCat(st->ProtocolDetails, sizeof(st->ProtocolDetails), " ");
					StrCat(st->ProtocolDetails, sizeof(st->ProtocolDetails), tmp);

					st->IsUdpAccelerationEnabled = s->IpcSessionShared->EnableUdpAccel;
					st->IsUsingUdpAcceleration = s->IpcSessionShared->UsingUdpAccel;
				}
				else
				{
					st->IsUdpAccelerationEnabled = s->UseUdpAcceleration;
					st->IsUsingUdpAcceleration = s->IsUsingUdpAcceleration;
				}
				// Session key
				Copy(st->SessionKey, s->SessionKey, SHA1_SIZE);
				// Policy
				Copy(&st->Policy, s->Policy, sizeof(POLICY));
				// Data size
				if (s->ServerMode == false)
				{
					st->TotalSendSize = s->TotalSendSize;
					st->TotalRecvSize = s->TotalRecvSize;
					st->TotalRecvSizeReal = s->TotalRecvSizeReal;
					st->TotalSendSizeReal = s->TotalSendSizeReal;
				}
				else
				{
					st->TotalSendSize = s->TotalRecvSize;
					st->TotalRecvSize = s->TotalSendSize;
					st->TotalRecvSizeReal = s->TotalSendSizeReal;
					st->TotalSendSizeReal = s->TotalRecvSizeReal;
				}
				// Session name
				StrCpy(st->SessionName, sizeof(st->SessionName), s->Name);
				// Connection name
				StrCpy(st->ConnectionName, sizeof(st->ConnectionName), s->Connection->Name);
				// Server name
				StrCpy(st->ServerName, sizeof(st->ServerName), s->Connection->ServerName);
				// Port number
				st->ServerPort = s->Connection->ServerPort;
				// Traffic data
				Lock(s->TrafficLock);
				{
					Copy(&st->Traffic, s->Traffic, sizeof(TRAFFIC));
				}
				Unlock(s->TrafficLock);

				st->IsBridgeMode = s->IsBridgeMode;
				st->IsMonitorMode = s->IsMonitorMode;
			}
			Unlock(s->Connection->lock);
		}
		// Connection start time
		st->StartTime = TickToTime(s->CreatedTime);
		// Connection completion time of the first connection
		/* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
		st->FirstConnectionEstablisiedTime = TickToTime(s->FirstConnectionEstablisiedTime);
		// Number of connections have been established so far
		st->NumConnectionsEstablished = s->NumConnectionsEstablished;
	}
	Unlock(s->lock);
}

// Get the connection status
bool CtGetAccountStatus(CLIENT *c, RPC_CLIENT_GET_CONNECTION_STATUS *st)
{
	// Validate arguments
	if (c == NULL || st == NULL)
	{
		return false;
	}

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;

		// Search for account
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), st->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// Specified account is not found
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			Zero(st, sizeof(RPC_CLIENT_GET_CONNECTION_STATUS));
			if (r->ClientSession != NULL)
			{
				SESSION *s = r->ClientSession;
				CiGetSessionStatus(st, s);
			}
		}
		Unlock(r->lock);
	}
	UnlockList(c->AccountList);

	return true;
}

// Release the connection status
void CiFreeClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *st)
{
	// Validate arguments
	if (st == NULL)
	{
		return;
	}

	if (st->ServerX != NULL)
	{
		FreeX(st->ServerX);
	}

	if (st->ClientX != NULL)
	{
		FreeX(st->ClientX);
	}
}

// Verification procedure of the server certificate
bool CiCheckCertProc(SESSION *s, CONNECTION *c, X *server_x, bool *expired)
{
#ifdef	OS_WIN32
	ACCOUNT *a;
	X *old_x = NULL;
	UI_CHECKCERT dlg;
	// Validate arguments
	if (s == NULL || c == NULL || server_x == NULL)
	{
		return false;
	}

	if (expired != NULL)
	{
		*expired = false;
	}

	Zero(&dlg, sizeof(dlg));

	a = s->Account;
	if (a == NULL)
	{
		return false;
	}

	Lock(a->lock);
	{
		if (a->CheckServerCert == false)
		{
			// Not to validate the server certificate
			Unlock(a->lock);
			return true;
		}

		if (a->ServerCert != NULL)
		{
			old_x = CloneX(a->ServerCert);
		}
	}
	Unlock(a->lock);

	if (CheckXDateNow(server_x) == false)
	{
		// Expired
		if (old_x != NULL)
		{
			FreeX(old_x);
		}

		if (expired != NULL)
		{
			*expired = true;
		}

		return false;
	}

	if (old_x != NULL)
	{
		if (CompareX(old_x, server_x))
		{
			// Matched exactly to the certificate that is already registered
			if (old_x != NULL)
			{
				FreeX(old_x);
			}
			return true;
		}
		else
		{
			dlg.DiffWarning = true;
		}
	}

	// Because this certificate can not be trusted, confirm to be trusted by showing a dialog box
	UniStrCpy(dlg.AccountName, sizeof(dlg.AccountName), a->ClientOption->AccountName);
	StrCpy(dlg.ServerName, sizeof(dlg.ServerName), a->ClientOption->Hostname);
	dlg.x = server_x;
	dlg.old_x = old_x;
	
	dlg.Session = s;
	AddRef(s->ref);

	CncCheckCert(s, &dlg);

	ReleaseSession(s);

	if (old_x != NULL)
	{
		FreeX(old_x);
	}

	if (dlg.Ok && dlg.SaveServerCert)
	{
		// Save the server certificate and trust it from the next time
		Lock(a->lock);
		{
			if (a->ServerCert != NULL)
			{
				FreeX(a->ServerCert);
			}

			a->ServerCert = CloneX(server_x);
		}
		Unlock(a->lock);
		CiSaveConfigurationFile(s->Cedar->Client);
	}

	return dlg.Ok;
#else	// OS_WIN32
	ACCOUNT *a;
	X *old_x = NULL;
	// Validate arguments
	if (s == NULL || c == NULL || server_x == NULL)
	{
		return false;
	}

	if (expired != NULL)
	{
		*expired = false;
	}

	a = s->Account;
	if (a == NULL)
	{
		return false;
	}

	Lock(a->lock);
	{
		if (a->CheckServerCert == false)
		{
			// Not to validate the server certificate
			Unlock(a->lock);
			return true;
		}

		if (a->ServerCert != NULL)
		{
			old_x = CloneX(a->ServerCert);
		}
	}
	Unlock(a->lock);

	if (CheckXDateNow(server_x) == false)
	{
		// Expired
		if (old_x != NULL)
		{
			FreeX(old_x);
		}

		if (expired != NULL)
		{
			*expired = true;
		}

		return false;
	}

	if (old_x != NULL)
	{
		if (CompareX(old_x, server_x))
		{
			// Exactly matched to the certificate that is already registered
			if (old_x != NULL)
			{
				FreeX(old_x);
			}
			return true;
		}
		else
		{
			// Mismatch
			if (old_x != NULL)
			{
				FreeX(old_x);
			}
			return false;
		}
	}

	return false;
#endif	// OS_WIN32
}

// Signature procedure with a secure device
bool CiSecureSignProc(SESSION *s, CONNECTION *c, SECURE_SIGN *sign)
{
	// The UI is available in Win32
	return CncSecureSignDlg(sign);
}

#ifdef	OS_WIN32
// Signing procedure (for Win32)
bool Win32CiSecureSign(SECURE_SIGN *sign)
{
	bool ret = false;
	BUF *random;
	// Validate arguments
	if (sign == NULL)
	{
		return false;
	}

	random = NewBuf();
	WriteBuf(random, sign->Random, SHA1_SIZE);

	// Batch processing
	{
		WINUI_SECURE_BATCH batch[] =
		{
			{WINUI_SECURE_READ_CERT, sign->SecurePublicCertName, true, NULL, NULL, NULL, NULL, NULL, NULL},
			{WINUI_SECURE_SIGN_WITH_KEY, sign->SecurePrivateKeyName, true, random, NULL, NULL, NULL, NULL, NULL}
		};

		if (SecureDeviceWindow(NULL, batch, sizeof(batch) / sizeof(batch[0]),
			sign->UseSecureDeviceId, sign->BitmapId) == false)
		{
			// Failure
			if (batch[0].OutputX != 0)
			{
				FreeX(batch[0].OutputX);
			}
			ret = false;
		}
		else
		{
			// Success
			ret = true;
			sign->ClientCert = batch[0].OutputX;
			Copy(sign->Signature, batch[1].OutputSign, MIN(sizeof(sign->Signature),sizeof(batch[1].OutputSign)));
		}
	}

	FreeBuf(random);

	return ret;
}
#endif	// OS_WIN32

// Disconnect
bool CtDisconnect(CLIENT *c, RPC_CLIENT_CONNECT *connect, bool inner)
{
	bool ret = false;
	ACCOUNT t, *r;
	SESSION *s = NULL;
	// Validate arguments
	if (c == NULL || connect == NULL)
	{
		return false;
	}

	LockList(c->AccountList);
	{
		// Search for account
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), connect->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// Specified account isn't found
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			if (r->ClientSession == NULL)
			{
				// Not connected
				CiSetError(c, ERR_ACCOUNT_INACTIVE);
			}
			else
			{
				s = r->ClientSession;
				AddRef(s->ref);
				// Disconnect complete
				r->ClientSession = NULL;
				ret = true;
			}
		}
		Unlock(r->lock);
	}
	UnlockList(c->AccountList);

	if (s != NULL)
	{
		// Disconnect the connection (Wait until the disconnection is complete)
		CLog(c, "LC_DISCONNECT", connect->AccountName);
		StopSession(s);
		ReleaseSession(s);
	}


	if (ret != false)
	{
		CiNotify(c);
	}

	return ret;
}

// Connect
bool CtConnect(CLIENT *c, RPC_CLIENT_CONNECT *connect)
{
	bool ret = false;
	RPC_CLIENT_ENUM_VLAN t;
	// Validate arguments
	if (c == NULL || connect == NULL)
	{
		return false;
	}

	Lock(c->lockForConnect);
	{
		Zero(&t, sizeof(t));
		if (CtEnumVLan(c, &t))
		{
			if (t.NumItem == 0)
			{
				// There are no virtual LAN cards in the system
				if (OS_IS_WINDOWS_NT(GetOsInfo()->OsType) || OS_IS_UNIX(GetOsInfo()->OsType))
				{
					// Only in Linux system or Windows NT system,
					// create a new virtual LAN card which named as "VPN" automatically
					RPC_CLIENT_CREATE_VLAN t;

					Zero(&t, sizeof(t));
					StrCpy(t.DeviceName, sizeof(t.DeviceName), "VPN");
					CtCreateVLan(c,  &t);
				}
			}

			CiFreeClientEnumVLan(&t);
		}
	}
	Unlock(c->lockForConnect);

	CiNormalizeAccountVLan(c);

	// Ensure successfully VPN communication by changing the irrational WCM settings in the case of Windows 8 or later
	CiDisableWcmNetworkMinimize(c);

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;
		bool unix_disabled = false;

		// Search for account
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), connect->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// Specified account isn't found
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

#ifndef	OS_WIN32
		// Search for the virtual LAN card
		LockList(c->UnixVLanList);
		{
			UNIX_VLAN *v, t;

			Zero(&t, sizeof(t));
			StrCpy(t.Name, sizeof(t.Name), r->ClientOption->DeviceName);

			v = Search(c->UnixVLanList, &t);
			if (v == NULL)
			{
				UnlockList(c->UnixVLanList);
				CiSetError(c, ERR_OBJECT_NOT_FOUND);
				return false;
			}

			unix_disabled = v->Enabled ? false : true;
		}
		UnlockList(c->UnixVLanList);
#endif	// OS_WIN32

		Lock(r->lock);
		{
			bool already_used = false;
			UINT i;

			if (r->ClientSession != NULL)
			{
				// Already in connecting
				CiSetError(c, ERR_ACCOUNT_ACTIVE);
			}
			else if (r->ClientAuth->AuthType == CLIENT_AUTHTYPE_SECURE &&
				c->UseSecureDeviceId == 0)
			{
				// Secure device is not specified
				CiSetError(c, ERR_NO_SECURE_DEVICE_SPECIFIED);
			}
#ifdef	OS_WIN32
			else if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, r->ClientOption->DeviceName) == false &&
				MsIsVLanExists(VLAN_ADAPTER_NAME_TAG_OLD, r->ClientOption->DeviceName) == false)
			{
				// Virtual LAN card can not be found
				CiSetError(c, ERR_VLAN_FOR_ACCOUNT_NOT_FOUND);
				CiNotify(c);
				CiSendGlobalPulse(c);
			}
			else if (MsIsVLanEnabled(r->ClientOption->DeviceName) == false)
			{
				// The virtual LAN card is disabled
				CiSetError(c, ERR_VLAN_FOR_ACCOUNT_DISABLED);
				CiNotify(c);
				CiSendGlobalPulse(c);
			}
#else	// OS_WIN32
			else if (unix_disabled)
			{
				// The virtual LAN card is disabled
				CiSetError(c, ERR_VLAN_FOR_ACCOUNT_DISABLED);
				CiNotify(c);
				CiSendGlobalPulse(c);
			}
#endif	// OS_WIN32
			else
			{
				// Check whether the virtual LAN card is being used by a different account already
				for (i = 0;i < LIST_NUM(c->AccountList);i++)
				{
					ACCOUNT *a = LIST_DATA(c->AccountList, i);
					if (a != r)
					{
						if (StrCmpi(a->ClientOption->DeviceName,
							r->ClientOption->DeviceName) == 0)
						{
							if (a->ClientSession != NULL)
							{
								already_used = true;
								break;
							}
						}
					}
				}

				if (already_used)
				{
					CiSetError(c, ERR_VLAN_FOR_ACCOUNT_USED);
				}
				else
				{
					// Start the connection
					PACKET_ADAPTER *pa = VLanGetPacketAdapter();

					if (r->ClientAuth->AuthType == CLIENT_AUTHTYPE_SECURE)
					{
						// Register a procedure for secure device authentication
						r->ClientAuth->SecureSignProc = CiSecureSignProc;
					}
					else
					{
						r->ClientAuth->SecureSignProc = NULL;
					}

					if (r->CheckServerCert)
					{
						// Register a procedure to validate the server certificate
						r->ClientAuth->CheckCertProc = CiCheckCertProc;
					}
					else
					{
						r->ClientAuth->CheckCertProc = NULL;
					}

					r->StatusPrinter = CiClientStatusPrinter;
					r->LastConnectDateTime = SystemTime64();

					CLog(c, "LC_CONNECT", connect->AccountName);

					r->ClientSession = NewClientSessionEx(c->Cedar, r->ClientOption, r->ClientAuth, pa, r);
					Notify(r->ClientSession, CLIENT_NOTIFY_ACCOUNT_CHANGED);

					ret = true;
				}
			}
		}
		Unlock(r->lock);

	}
	UnlockList(c->AccountList);

	CiSaveConfigurationFile(c);

	return ret;
}

// Put all unused TUN interfaces down
// Requires account and VLan lists of the CLIENT argument to be already locked
bool CtVLansDown(CLIENT *c)
{
#ifndef UNIX_LINUX
	return true;
#else
	int i;
	LIST *tmpVLanList;
	UNIX_VLAN t, *r;
	bool result = true;

	if (c == NULL)
	{
		return false;
	}

	tmpVLanList = CloneList(c->UnixVLanList);
	if (tmpVLanList == NULL)
	{
		return false;
	}

	// Remove from tmpVLanList all VLans corresponding to active sessions
	for (i = 0; i < LIST_NUM(c->AccountList); ++i)
	{
		ACCOUNT *a = LIST_DATA(c->AccountList, i);
		if (a->ClientSession == NULL)
		{
			continue;
		}

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), a->ClientOption->DeviceName);
		r = Search(tmpVLanList, &t);
		Delete(tmpVLanList, r);
	}

	// Set down every VLan in tmpVLanList
	for (i = 0; i < LIST_NUM(tmpVLanList) && result; ++i)
	{
		r = LIST_DATA(tmpVLanList, i);
		result = UnixVLanSetState(r->Name, false);
		// [MP:] Should we report *critical* error on failure?
	}

	ReleaseList(tmpVLanList);
	return result;
#endif
}

// Put all TUN interfaces up
// Requires VLan list of the CLIENT argument to be already locked
bool CtVLansUp(CLIENT *c)
{
#ifndef UNIX_LINUX
	return true;
#else
	int i;
	UNIX_VLAN *r;

	if (c == NULL)
	{
		return false;
	}

	for (i = 0; i < LIST_NUM(c->UnixVLanList); ++i)
	{
		r = LIST_DATA(c->UnixVLanList, i);
		UnixVLanSetState(r->Name, true);
	}

	return true;
#endif
}

// Get the account information
bool CtGetAccount(CLIENT *c, RPC_CLIENT_GET_ACCOUNT *a)
{
	// Validate arguments
	if (c == NULL || a == NULL)
	{
		return false;
	}

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;

		// Search for account
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), a->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// Specified account can not be found
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			// Copy the client option
			if (a->ClientOption != NULL)
			{
				Free(a->ClientOption);
			}
			a->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
			Copy(a->ClientOption, r->ClientOption, sizeof(CLIENT_OPTION));

			// Copy the authentication data
			if (a->ClientAuth != NULL)
			{
				CiFreeClientAuth(a->ClientAuth);
			}
			a->ClientAuth = CopyClientAuth(r->ClientAuth);

			a->StartupAccount = r->StartupAccount;

			a->CheckServerCert = r->CheckServerCert;
			a->RetryOnServerCert = r->RetryOnServerCert;
			a->ServerCert = NULL;
			if (r->ServerCert != NULL)
			{
				a->ServerCert = CloneX(r->ServerCert);
			}

			// Shortcut Key
			Copy(a->ShortcutKey, r->ShortcutKey, SHA1_SIZE);

			a->CreateDateTime = r->CreateDateTime;
			a->LastConnectDateTime = r->LastConnectDateTime;
			a->UpdateDateTime = r->UpdateDateTime;
		}
		Unlock(r->lock);

	}
	UnlockList(c->AccountList);

	return true;
}

// Change the account name
bool CtRenameAccount(CLIENT *c, RPC_RENAME_ACCOUNT *rename, bool inner)
{
	bool ret;
	// Validate arguments
	if (c == NULL || rename == NULL)
	{
		return false;
	}


	ret = false;

	if (UniStrCmp(rename->NewName, rename->OldName) == 0)
	{
		// The name has not been changed
		return true;
	}

	LockList(c->AccountList);
	{
		ACCOUNT t, *r, *r2;

		if (UniStrLen(rename->NewName) == 0)
		{
			// Name is invalid
			CiSetError(c, ERR_INVALID_VALUE);
			UnlockList(c->AccountList);
			return false;
		}

		// Search for old account name
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), rename->OldName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// Specified account can not be found
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		// Search for a new account name
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), rename->NewName);

		r2 = Search(c->AccountList, &t);
		if (r2 != NULL)
		{
			// Account with the specified name already exists
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_ALREADY_EXISTS);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			// Check the operating state of the account
			if (r->ClientSession != NULL)
			{
				// The Account is working
				Unlock(r->lock);
				UnlockList(c->AccountList);
				CiSetError(c, ERR_ACCOUNT_ACTIVE);

				return false;
			}

			// Update the account name
			UniStrCpy(r->ClientOption->AccountName, sizeof(r->ClientOption->AccountName),
				rename->NewName);

			CLog(c, "LC_RENAME_ACCOUNT", rename->OldName, rename->NewName);

			ret = true;
		}
		Unlock(r->lock);

		Sort(c->AccountList);

	}
	UnlockList(c->AccountList);

	CiSaveConfigurationFile(c);

	CiNotify(c);

	return ret;
}

// Set the client configuration
bool CtSetClientConfig(CLIENT *c, CLIENT_CONFIG *o)
{
	KEEP *k;
	// Validate arguments
	if (c == NULL || o == NULL)
	{
		return false;
	}

	if (o->UseKeepConnect)
	{
		if (IsEmptyStr(o->KeepConnectHost) ||
			o->KeepConnectPort == 0 ||
			o->KeepConnectPort >= 65536)
		{
			CiSetError(c, ERR_INVALID_PARAMETER);
			return false;
		}
	}

	Lock(c->lock);
	{
		Copy(&c->Config, o, sizeof(CLIENT_CONFIG));
	}
	Unlock(c->lock);

	// Save the settings
	CiSaveConfigurationFile(c);

	// Apply the Keep Connect
	k = c->Keep;
	Lock(k->lock);
	{
		if (o->UseKeepConnect)
		{
			StrCpy(k->ServerName, sizeof(k->ServerName), c->Config.KeepConnectHost);
			k->ServerPort = c->Config.KeepConnectPort;
			k->Interval = c->Config.KeepConnectInterval * 1000;
			k->UdpMode = (c->Config.KeepConnectProtocol == CONNECTION_UDP) ? true : false;
			k->Enable = true;
		}
		else
		{
			k->Enable = false;
		}
	}
	Unlock(k->lock);

	// Apply TAP state
	LockList(c->AccountList);
	LockList(c->UnixVLanList);

	CtVLansDown(c);

	UnlockList(c->UnixVLanList);
	UnlockList(c->AccountList);

	return true;
}

// Get the network client configuration
bool CtGetClientConfig(CLIENT *c, CLIENT_CONFIG *o)
{
	// Validate arguments
	if (c == NULL || o == NULL)
	{
		return false;
	}

	Lock(c->lock);
	{
		Copy(o, &c->Config, sizeof(CLIENT_CONFIG));
	}
	Unlock(c->lock);

	return true;
}

// Unset the startup attribute of the account
bool CtRemoveStartupAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a)
{
	bool ret;
	// Validate arguments
	if (c == NULL || a == NULL)
	{
		return false;
	}

	ret = false;

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;
		// Search for an Account

		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), a->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// Specified account can not be found
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			// Unset the startup account
			ret = true;
			r->StartupAccount = false;
		}
		Unlock(r->lock);
	}
	UnlockList(c->AccountList);

	if (ret)
	{
		CiSaveConfigurationFile(c);
		CiNotify(c);
	}

	return ret;
}

// Set the account as a start-up account
bool CtSetStartupAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a, bool inner)
{
	bool ret;
	// Validate arguments
	if (c == NULL || a == NULL)
	{
		return false;
	}


	ret = false;

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;
		// Search for an account

		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), a->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// Specified account can not be found
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			// Set to a start-up account
			ret = true;
			r->StartupAccount = true;
		}
		Unlock(r->lock);
	}
	UnlockList(c->AccountList);

	if (ret)
	{
		CiSaveConfigurationFile(c);
		CiNotify(c);
	}

	return ret;
}

// Delete the account
bool CtDeleteAccount(CLIENT *c, RPC_CLIENT_DELETE_ACCOUNT *a, bool inner)
{
	bool ret;
	// Validate arguments
	if (c == NULL || a == NULL)
	{
		return false;
	}

	ret = false;

	if (c->Halt)
	{
		// Don't allow the removal of the account in the process of stopping
		CiSetError(c, ERR_INTERNAL_ERROR);
		return false;
	}

	LockList(c->AccountList);
	{
		ACCOUNT t, *r;
		// Search for an Account

		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), a->AccountName);

		r = Search(c->AccountList, &t);
		if (r == NULL)
		{
			// Specified account can not be found
			UnlockList(c->AccountList);

			Free(t.ClientOption);
			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);
			return false;
		}

		Free(t.ClientOption);

		Lock(r->lock);
		{
			// Check the operating state of the account
			if (r->ClientSession != NULL)
			{
				// The account is active
				Unlock(r->lock);
				UnlockList(c->AccountList);
				CiSetError(c, ERR_ACCOUNT_ACTIVE);

				return false;
			}

			// Remove this account from the list
			Delete(c->AccountList, r);
		}
		Unlock(r->lock);

		// Free the memory of this account
		CiFreeAccount(r);

		CLog(c, "LC_DELETE_ACCOUNT", a->AccountName);
		ret = true;

	}
	UnlockList(c->AccountList);

	if (ret)
	{
		CiSaveConfigurationFile(c);
		CiNotify(c);
	}

	return ret;
}

// Enumeration of accounts
bool CtEnumAccount(CLIENT *c, RPC_CLIENT_ENUM_ACCOUNT *e)
{
	// Validate arguments
	if (c == NULL || e == NULL)
	{
		return false;
	}

	LockList(c->AccountList);
	{
		UINT i;
		// Number of accounts
		e->NumItem = LIST_NUM(c->AccountList);
		e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_ACCOUNT_ITEM *) * e->NumItem);

		for (i = 0;i < e->NumItem;i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);
			RPC_CLIENT_ENUM_ACCOUNT_ITEM *item = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_ACCOUNT_ITEM));
			e->Items[i] = item;

			// Account name
			UniStrCpy(item->AccountName, sizeof(item->AccountName), a->ClientOption->AccountName);

			// User name
			StrCpy(item->UserName, sizeof(item->UserName), a->ClientAuth->Username);

			// Server name
			StrCpy(item->ServerName, sizeof(item->ServerName), a->ClientOption->Hostname);

			// Proxy type
			item->ProxyType = a->ClientOption->ProxyType;

			// Device name
			StrCpy(item->DeviceName, sizeof(item->DeviceName), a->ClientOption->DeviceName);

			// Proxy information
			if (item->ProxyType != PROXY_DIRECT)
			{
				StrCpy(item->ProxyName, sizeof(item->ProxyName), a->ClientOption->ProxyName);
			}

			// Startup
			item->StartupAccount = a->StartupAccount;

			// Active flag
			item->Active = (a->ClientSession == NULL ? false : true);

			// Connection flag
			item->Connected = (item->Active == false) ? false : a->ClientSession->ConnectSucceed;

			// Port number
			item->Port = a->ClientOption->Port;

			// Virtual HUB name
			StrCpy(item->HubName, sizeof(item->HubName), a->ClientOption->HubName);

			item->CreateDateTime = a->CreateDateTime;
			item->LastConnectDateTime = a->LastConnectDateTime;
			item->UpdateDateTime = a->UpdateDateTime;
		}
	}
	UnlockList(c->AccountList);

	return true;
}

// Configure the account
bool CtSetAccount(CLIENT *c, RPC_CLIENT_CREATE_ACCOUNT *a, bool inner)
{
	// Validate arguments
	if (c == NULL || a == NULL)
	{
		return false;
	}


	// Check whether an account already exists
	LockList(c->AccountList);
	{
		ACCOUNT t, *ret;
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName),
			a->ClientOption->AccountName);

		ret = Search(c->AccountList, &t);
		if (ret == NULL)
		{
			// Not exist
			UnlockList(c->AccountList);
			Free(t.ClientOption);

			CiSetError(c, ERR_ACCOUNT_NOT_FOUND);

			return false;
		}
		Free(t.ClientOption);

		if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
		{
			if (a->ClientAuth->ClientX == NULL ||
				a->ClientAuth->ClientX->is_compatible_bit == false ||
				a->ClientAuth->ClientK == NULL)
			{
				// Client certificate is invalid
				UnlockList(c->AccountList);
				CiSetError(c, ERR_NOT_RSA_1024);
				return false;
			}
		}

		if (a->ServerCert != NULL && a->ServerCert->is_compatible_bit == false)
		{
			// Server certificate is invalid
			UnlockList(c->AccountList);
			CiSetError(c, ERR_NOT_RSA_1024);
			return false;
		}

		Lock(ret->lock);
		{

#if	0
			// Rewriting of the configuration is done even account running in the current version
			// (New setting isn't applied until connecting next time)
			if (ret->ClientSession != NULL)
			{
				// The account is operating
				Unlock(ret->lock);
				UnlockList(c->AccountList);

				CiSetError(c, ERR_ACCOUNT_ACTIVE);

				return false;
			}
#endif

			// Delete the client authentication data
			CiFreeClientAuth(ret->ClientAuth);

			// Copy the client authentication data
			ret->ClientAuth = CopyClientAuth(a->ClientAuth);

			// Delete the client option
			Free(ret->ClientOption);

			// Copy the client option
			ret->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
			Copy(ret->ClientOption, a->ClientOption, sizeof(CLIENT_OPTION));

			ret->StartupAccount = a->StartupAccount;

			ret->CheckServerCert = a->CheckServerCert;
			ret->RetryOnServerCert = a->RetryOnServerCert;

			if (a->ServerCert != NULL)
			{
				if (ret->ServerCert != NULL)
				{
					FreeX(ret->ServerCert);
				}
				ret->ServerCert = CloneX(a->ServerCert);
			}
			else
			{
				if (ret->ServerCert != NULL)
				{
					FreeX(ret->ServerCert);
				}
				ret->ServerCert = false;
			}

			ret->UpdateDateTime = SystemTime64();
		}
		Unlock(ret->lock);
	}
	UnlockList(c->AccountList);

	CiSaveConfigurationFile(c);

	CiNotify(c);

	return true;
}

// Create an account
bool CtCreateAccount(CLIENT *c, RPC_CLIENT_CREATE_ACCOUNT *a, bool inner)
{
	// Validate arguments
	if (c == NULL || a == NULL)
	{
		return false;
	}


	// Check whether an account already exists
	LockList(c->AccountList);
	{
		ACCOUNT t, *ret, *new_account;
		t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName),
			a->ClientOption->AccountName);

		ret = Search(c->AccountList, &t);
		if (ret != NULL)
		{
			// Already exist
			UnlockList(c->AccountList);
			Free(t.ClientOption);

			CiSetError(c, ERR_ACCOUNT_ALREADY_EXISTS);

			return false;
		}

		Free(t.ClientOption);

		if (UniStrLen(a->ClientOption->AccountName) == 0)
		{
			// The name is invalid
			UnlockList(c->AccountList);
			CiSetError(c, ERR_INVALID_VALUE);
			return false;
		}

		if (a->ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
		{
			if (a->ClientAuth->ClientX == NULL ||
				a->ClientAuth->ClientX->is_compatible_bit == false ||
				a->ClientAuth->ClientK == NULL)
			{
				// The client certificate is invalid
				UnlockList(c->AccountList);
				CiSetError(c, ERR_NOT_RSA_1024);
				return false;
			}
		}

		if (a->ServerCert != NULL && a->ServerCert->is_compatible_bit == false)
		{
			// The server certificate is invalid
			UnlockList(c->AccountList);
			CiSetError(c, ERR_NOT_RSA_1024);
			return false;
		}

		// Add a new account
		new_account = ZeroMalloc(sizeof(ACCOUNT));
		new_account->lock = NewLock();

		// Copy the client authentication data
		new_account->ClientAuth = CopyClientAuth(a->ClientAuth);

		// Copy the client option
		new_account->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
		Copy(new_account->ClientOption, a->ClientOption, sizeof(CLIENT_OPTION));

		new_account->StartupAccount = a->StartupAccount;

		new_account->CheckServerCert = a->CheckServerCert;
		new_account->RetryOnServerCert = a->RetryOnServerCert;
		if (a->ServerCert != NULL)
		{
			new_account->ServerCert = CloneX(a->ServerCert);
		}

		// Shortcut Key
		if (IsZero(a->ShortcutKey, SHA1_SIZE))
		{
			Rand(new_account->ShortcutKey, SHA1_SIZE);
		}
		else
		{
			Copy(new_account->ShortcutKey, a->ShortcutKey, SHA1_SIZE);
		}

		new_account->CreateDateTime = new_account->UpdateDateTime = SystemTime64();

		// Insert into the list
		Insert(c->AccountList, new_account);

		CLog(c, "LC_NEW_ACCOUNT", a->ClientOption->AccountName);
	}
	UnlockList(c->AccountList);

	CiNormalizeAccountVLan(c);

	CiSaveConfigurationFile(c);

	CiNotify(c);

	return true;
}

// Release the account acquisition structure
void CiFreeClientGetAccount(RPC_CLIENT_GET_ACCOUNT *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	// Release the account information
	if (a->ServerCert != NULL)
	{
		FreeX(a->ServerCert);
	}
	CiFreeClientAuth(a->ClientAuth);
	Free(a->ClientOption);
}

// Release the account creation structure
void CiFreeClientCreateAccount(RPC_CLIENT_CREATE_ACCOUNT *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	// Release the account information
	if (a->ServerCert != NULL)
	{
		FreeX(a->ServerCert);
	}
	CiFreeClientAuth(a->ClientAuth);
	Free(a->ClientOption);
}

// Stop the virtual LAN card
bool CtDisableVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *vlan)
{
	UINT i;
	bool used;
	// Validate arguments
	if (c == NULL || vlan == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

#ifdef	NO_VLAN
	if (GetOsInfo()->OsType == OSTYPE_MACOS_X)
	{
		// Can not be added or removed the virtual LAN card in MacOS X
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}
#endif	// NO_VLAN

	// Check whether the virtual LAN card with the specified name is not
	// being used by one or more accounts
	used = false;
	LockList(c->AccountList);
	{
		for (i = 0;i < LIST_NUM(c->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);
			if (StrCmpi(a->ClientOption->DeviceName, vlan->DeviceName) == 0)
			{
				Lock(a->lock);
				{
					if (a->ClientSession != NULL)
					{
						used = true;
					}
				}
				Unlock(a->lock);
			}
		}
	}
	UnlockList(c->AccountList);

	// Search for the virtual LAN card
	LockList(c->UnixVLanList);
	{
		UNIX_VLAN *v, t;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), vlan->DeviceName);

		v = Search(c->UnixVLanList, &t);
		if (v == NULL)
		{
			UnlockList(c->UnixVLanList);
			CiSetError(c, ERR_OBJECT_NOT_FOUND);
			return false;
		}

		// Stop
		v->Enabled = false;
	}
	UnlockList(c->UnixVLanList);

	CiSaveConfigurationFile(c);
	CiNotify(c);
	CiSendGlobalPulse(c);

	return true;

#else	// OS_WIN32

	// Check whether the virtual LAN card with the specified name is not
	// being used by one or more accounts
	used = false;
	LockList(c->AccountList);
	{
		for (i = 0;i < LIST_NUM(c->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);
			if (StrCmpi(a->ClientOption->DeviceName, vlan->DeviceName) == 0)
			{
				Lock(a->lock);
				{
					if (a->ClientSession != NULL)
					{
						used = true;
					}
				}
				Unlock(a->lock);
			}
		}
	}
	UnlockList(c->AccountList);

#if	0
	if (used)
	{
		// In using
		CiSetError(c, ERR_VLAN_IS_USED);
		return false;
	}
#endif


	// Check whether the virtual LAN card are present
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, vlan->DeviceName) == false &&
		MsIsVLanExists(VLAN_ADAPTER_NAME_TAG_OLD, vlan->DeviceName) == false)
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		CiNotify(c);
		CiSendGlobalPulse(c);
		return false;
	}


	if (MsIs64BitWindows() && Is32() && MsIsAdmin())
	{
		// Execute the driver_installer to process since this Windows is 64 bit
		// but this code is 32 bit
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "disablevlan %s", vlan->DeviceName);

		if (MsExecDriverInstaller(tmp) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			CiSendGlobalPulse(c);
			return false;
		}
	}
	else
	{
		// Stop the virtual LAN card
		if (MsDisableVLan(vlan->DeviceName) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			CiSendGlobalPulse(c);
			return false;
		}
	}

	CiNotify(c);
	CiSendGlobalPulse(c);

	return true;

#endif	// OS_WIN32

}

// Start the virtual LAN card
bool CtEnableVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *vlan)
{
	// Validate arguments
	if (c == NULL || vlan == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

#ifdef	NO_VLAN
	if (GetOsInfo()->OsType == OSTYPE_MACOS_X)
	{
		// Can not be added or removed the virtual LAN card in MacOS X
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}
#endif	// NO_VLAN

	// Search the virtual LAN card
	LockList(c->UnixVLanList);
	{
		UNIX_VLAN *v, t;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), vlan->DeviceName);

		v = Search(c->UnixVLanList, &t);
		if (v == NULL)
		{
			UnlockList(c->UnixVLanList);
			CiSetError(c, ERR_OBJECT_NOT_FOUND);
			return false;
		}

		// Enable
		v->Enabled = true;
	}
	UnlockList(c->UnixVLanList);

	CiSaveConfigurationFile(c);
	CiNotify(c);
	CiSendGlobalPulse(c);

	return true;

#else	// OS_WIN32

	// Check whether the virtual LAN card are present
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, vlan->DeviceName) == false &&
		MsIsVLanExists(VLAN_ADAPTER_NAME_TAG_OLD, vlan->DeviceName) == false)
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		CiNotify(c);
		CiSendGlobalPulse(c);
		return false;
	}

	if (MsIs64BitWindows() && Is32() && MsIsAdmin())
	{
		// Execute the driver_installer to process since this Windows is 64 bit
		// but this code is 32 bit
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "enablevlan %s", vlan->DeviceName);

		if (MsExecDriverInstaller(tmp) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			CiSendGlobalPulse(c);
			return false;
		}
	}
	else
	{
		// Start the virtual LAN card
		if (MsEnableVLan(vlan->DeviceName) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			CiSendGlobalPulse(c);
			return false;
		}
	}

	CiNotify(c);
	CiSendGlobalPulse(c);

	return true;

#endif	// OS_WIN32

}

// Delete the virtual LAN card
bool CtDeleteVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *d)
{
	UINT i;
	bool used;
	// Validate arguments
	if (c == NULL || d == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

#ifdef	NO_VLAN
	if (GetOsInfo()->OsType == OSTYPE_MACOS_X)
	{
		// Can not be added or removed the virtual LAN card in MacOS X
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}
#endif	// NO_VLAN

	// Check whether the virtual LAN card with the specified name is not
	// being used by one or more accounts
	used = false;
	LockList(c->AccountList);
	{
		for (i = 0;i < LIST_NUM(c->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);
			if (StrCmpi(a->ClientOption->DeviceName, d->DeviceName) == 0)
			{
				used = true;
			}
		}
	}
	UnlockList(c->AccountList);

#if	0
	if (used)
	{
		// In using
		CiSetError(c, ERR_VLAN_IS_USED);
		return false;
	}
#endif

	// Search for the virtual LAN card
	LockList(c->UnixVLanList);
	{
		UNIX_VLAN *v, t;

		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), d->DeviceName);

		v = Search(c->UnixVLanList, &t);
		if (v == NULL)
		{
			UnlockList(c->UnixVLanList);
			CiSetError(c, ERR_OBJECT_NOT_FOUND);
			return false;
		}

		// Remove
		if (Delete(c->UnixVLanList, v))
		{
			Free(v);
		}

		CLog(c, "LC_DELETE_VLAN", d->DeviceName);

		UnixVLanDelete(d->DeviceName);
	}
	UnlockList(c->UnixVLanList);

	CiNormalizeAccountVLan(c);

	CiSaveConfigurationFile(c);
	CiNotify(c);
	CiSendGlobalPulse(c);

	return true;

#else	// OS_WIN32

	if (MsIsNt() == false)
	{
		// Not available in Win9x
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}

	// Check whether the virtual LAN card are present
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, d->DeviceName) == false &&
		MsIsVLanExists(VLAN_ADAPTER_NAME_TAG_OLD, d->DeviceName) == false)
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		return false;
	}

	// Check whether the virtual LAN card with the specified name is not
	// being used by one or more accounts
	used = false;
	LockList(c->AccountList);
	{
		for (i = 0;i < LIST_NUM(c->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);
			if (StrCmpi(a->ClientOption->DeviceName, d->DeviceName) == 0)
			{
				used = true;
			}
		}
	}
	UnlockList(c->AccountList);

#if	0
	if (used)
	{
		// In using
		CiSetError(c, ERR_VLAN_IS_USED);
		return false;
	}
#endif

	if (MsIs64BitWindows() && Is32() && MsIsAdmin())
	{
		// Execute the driver_installer to process since this Windows is 64 bit
		// but this code is 32 bit
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "uninstvlan %s", d->DeviceName);

		if (MsExecDriverInstaller(tmp) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			return false;
		}
	}
	else
	{
		// Delete the virtual LAN card directly
		if (MsUninstallVLan(d->DeviceName) == false)
		{
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			CiSendGlobalPulse(c);
			return false;
		}
	}

	CLog(c, "LC_DELETE_VLAN", d->DeviceName);

	CiNormalizeAccountVLan(c);

	CiNotify(c);
	CiSendGlobalPulse(c);

	return true;

#endif	// OS_WIN32

}

// Get the name of the first VLAN
char *CiGetFirstVLan(CLIENT *c)
{
	char *ret = NULL;
	RPC_CLIENT_ENUM_VLAN t;
	// Validate arguments
	if (c == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	if (CtEnumVLan(c, &t) == false)
	{
		return NULL;
	}

	if (t.NumItem >= 1)
	{
		UINT i;
		char *tmp = t.Items[0]->DeviceName;

		for (i = 0;i < t.NumItem;i++)
		{
			if (t.Items[i]->Enabled)
			{
				tmp = t.Items[i]->DeviceName;
			}
		}

		ret = CopyStr(tmp);
	}

	CiFreeClientEnumVLan(&t);

	return ret;
}

// Enumerate virtual LAN cards
bool CtEnumVLan(CLIENT *c, RPC_CLIENT_ENUM_VLAN *e)
{
	UINT i;
	TOKEN_LIST *t;
	// Validate arguments
	if (c == NULL || e == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

	LockList(c->UnixVLanList);
	{
		e->NumItem = LIST_NUM(c->UnixVLanList);
		e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM *) * e->NumItem);

		for (i = 0;i < e->NumItem;i++)
		{
			RPC_CLIENT_ENUM_VLAN_ITEM *item;
			UNIX_VLAN *v;

			v = LIST_DATA(c->UnixVLanList, i);
			e->Items[i] = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM));
			item = e->Items[i];

			item->Enabled = v->Enabled;
			BinToStr(item->MacAddress, sizeof(item->MacAddress), v->MacAddress, 6);
			StrCpy(item->DeviceName, sizeof(item->DeviceName), v->Name);
			StrCpy(item->Version, sizeof(item->Version), c->Cedar->VerString);
		}
	}
	UnlockList(c->UnixVLanList);

	return true;

#else	// OS_WIN32

	// Enumeration
	t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, VLAN_ADAPTER_NAME_OLD);
	if (t == NULL)
	{
		// Enumeration failure
		e->NumItem = 0;
		e->Items = ZeroMalloc(0);
	}
	else
	{
		// Enumeration success
		e->NumItem = t->NumTokens;
		e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM *) * e->NumItem);

		for (i = 0;i < e->NumItem;i++)
		{
			char *tmp;
			RPC_CLIENT_ENUM_VLAN_ITEM *item;
			e->Items[i] = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_VLAN_ITEM));
			item = e->Items[i];

			StrCpy(item->DeviceName, sizeof(item->DeviceName), t->Token[i]);
			item->Enabled = MsIsVLanEnabled(item->DeviceName);

			tmp = MsGetMacAddress(VLAN_ADAPTER_NAME_TAG, item->DeviceName);
			if (tmp == NULL)
			{
				tmp = MsGetMacAddress(VLAN_ADAPTER_NAME_TAG_OLD, item->DeviceName);
			}

			StrCpy(item->MacAddress, sizeof(item->MacAddress), tmp);
			Free(tmp);

			tmp = MsGetDriverVersion(VLAN_ADAPTER_NAME_TAG, item->DeviceName);
			if (tmp == NULL)
			{
				tmp = MsGetDriverVersion(VLAN_ADAPTER_NAME_TAG_OLD, item->DeviceName);
			}

			StrCpy(item->Version, sizeof(item->Version), tmp);
			Free(tmp);
		}

		FreeToken(t);
	}

	return true;

#endif	// OS_WIN32
}

// Release the virtual LAN card enumeration
void CiFreeClientEnumVLan(RPC_CLIENT_ENUM_VLAN *e)
{
	UINT i;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	for (i = 0;i < e->NumItem;i++)
	{
		Free(e->Items[i]);
	}
	Free(e->Items);
}

// Set the information about the virtual LAN card
bool CtSetVLan(CLIENT *c, RPC_CLIENT_SET_VLAN *set)
{
	// Validate arguments
	if (c == NULL || set == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

	LockList(c->UnixVLanList);
	{
		UNIX_VLAN t, *r;
		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), set->DeviceName);

		r = Search(c->UnixVLanList, &t);
		if (r == NULL)
		{
			// Not exist
			CiSetError(c, ERR_VLAN_ALREADY_EXISTS);
			UnlockList(c->UnixVLanList);
			return false;
		}

		StrToMac(r->MacAddress, set->MacAddress);
	}
	UnlockList(c->UnixVLanList);

	CiSaveConfigurationFile(c);
	CiNotify(c);
	CiSendGlobalPulse(c);

	return true;

#else	// OS_WIN32

	// Check whether the virtual LAN card with the specified name already exists
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, set->DeviceName) == false &&
		MsIsVLanExists(VLAN_ADAPTER_NAME_TAG_OLD, set->DeviceName) == false)
	{
		// Not exist
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		return false;
	}

	// Configuring MAC address
	MsSetMacAddress(VLAN_ADAPTER_NAME_TAG, set->DeviceName, set->MacAddress);
	MsSetMacAddress(VLAN_ADAPTER_NAME_TAG_OLD, set->DeviceName, set->MacAddress);

	CiNotify(c);
	CiSendGlobalPulse(c);

	return true;

#endif	// OS_WIN32
}

// Get the information about the virtual LAN card
bool CtGetVLan(CLIENT *c, RPC_CLIENT_GET_VLAN *get)
{
	char *tmp;
	// Validate arguments
	if (c == NULL || get == NULL)
	{
		return false;
	}

#ifndef	OS_WIN32

	// Unsupported
	CiSetError(c, ERR_NOT_SUPPORTED);
	return false;

#else	// OS_WIN32

	// Check whether the virtual LAN card with the specified name already exists
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, get->DeviceName) == false &&
		MsIsVLanExists(VLAN_ADAPTER_NAME_TAG_OLD, get->DeviceName) == false)
	{
		// Not exist
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		return false;
	}

	// Activity
	get->Enabled = MsIsVLanEnabled(get->DeviceName);

	// MAC address
	tmp = MsGetMacAddress(VLAN_ADAPTER_NAME_TAG, get->DeviceName);
	if (tmp == NULL)
	{
		tmp = MsGetMacAddress(VLAN_ADAPTER_NAME_TAG_OLD, get->DeviceName);
	}
	StrCpy(get->MacAddress, sizeof(get->MacAddress), tmp);
	Free(tmp);

	// Version
	tmp = MsGetDriverVersion(VLAN_ADAPTER_NAME_TAG, get->DeviceName);
	if (tmp == NULL)
	{
		tmp = MsGetDriverVersion(VLAN_ADAPTER_NAME_TAG_OLD, get->DeviceName);
	}
	StrCpy(get->Version, sizeof(get->Version), tmp);
	Free(tmp);

	// File name
	tmp = MsGetDriverFileName(VLAN_ADAPTER_NAME_TAG, get->DeviceName);
	if (tmp == NULL)
	{
		tmp = MsGetDriverFileName(VLAN_ADAPTER_NAME_TAG_OLD, get->DeviceName);
	}
	StrCpy(get->FileName, sizeof(get->FileName), tmp);
	Free(tmp);

	// GUID
	tmp = MsGetNetworkAdapterGuid(VLAN_ADAPTER_NAME_TAG, get->DeviceName);
	if (tmp == NULL)
	{
		tmp = MsGetNetworkAdapterGuid(VLAN_ADAPTER_NAME_TAG_OLD, get->DeviceName);
	}
	StrCpy(get->Guid, sizeof(get->Guid), tmp);
	Free(tmp);

	return true;

#endif	// OS_WIN32
}

#ifdef	OS_WIN32
// Initialize the driver version information structure
void CiInitDriverVerStruct(MS_DRIVER_VER *ver)
{
	// Validate arguments
	if (ver == NULL)
	{
		return;
	}

	Zero(ver, sizeof(MS_DRIVER_VER));

	ver->Year = BUILD_DATE_Y;
	ver->Month = BUILD_DATE_M;
	ver->Day = BUILD_DATE_D;
	ver->Major = CEDAR_VERSION_MAJOR;
	ver->Minor = CEDAR_VERSION_MINOR;
	ver->Build = CEDAR_VERSION_BUILD;
}
#endif	// OS_WIN32

// Upgrade the virtual LAN card
bool CtUpgradeVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *create)
{
	bool use_old_name = false;

#ifdef	OS_WIN32
	KAKUSHI *k = NULL;
	MS_DRIVER_VER ver;
#endif	// OS_WIN32

	// Validate arguments
	if (c == NULL || create == NULL)
	{
		return false;
	}


#ifndef	OS_WIN32

	// Always succeed
	return true;

#else	// OS_WIN32

	CiInitDriverVerStruct(&ver);

	if (MsIsNt() == false)
	{
		// Not available in Win9x
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}

	// Check whether the LAN card with the specified name already exists
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, create->DeviceName) == false &&
		MsIsVLanExists(VLAN_ADAPTER_NAME_TAG_OLD, create->DeviceName) == false)
	{
		// Not exist
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		CiNotify(c);
		CiSendGlobalPulse(c);
		return false;
	}

	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG_OLD, create->DeviceName))
	{
		use_old_name = true;
	}

	if (MsIsVista() == false)
	{
		k = InitKakushi();	
	}


	if (MsIsVista() == false)
	{
		// Perform the installation (other than Windows Vista)
		if (MsUpgradeVLan(use_old_name ? VLAN_ADAPTER_NAME_TAG_OLD : VLAN_ADAPTER_NAME_TAG,
			use_old_name ? VLAN_CONNECTION_NAME_OLD : VLAN_CONNECTION_NAME,
			create->DeviceName, &ver) == false)
		{
			// Installation Failed
			FreeKakushi(k);
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			CiSendGlobalPulse(c);
			return false;
		}
	}
	else
	{
		// Perform the installation (Windows Vista)
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "upgradevlan %s", create->DeviceName);

		if (CncExecDriverInstaller(tmp) == false)
		{
			// Installation Failed
			FreeKakushi(k);
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			CiSendGlobalPulse(c);
			return false;
		}
	}

	FreeKakushi(k);

	CLog(c, "LC_UPDATE_VLAN", create->DeviceName);

	CiNotify(c);
	CiSendGlobalPulse(c);

	return true;

#endif	// OS_WIN32
}

// Create a virtual LAN card
bool CtCreateVLan(CLIENT *c, RPC_CLIENT_CREATE_VLAN *create)
{
	TOKEN_LIST *t;
	UINT max_len;

#ifdef	OS_WIN32
	KAKUSHI *k = NULL;
#endif	// OS_WIN32

	// Validate arguments
	if (c == NULL || create == NULL)
	{
		return false;
	}

	if (SearchStrEx(create->DeviceName, " ", 0, false) != INFINITE)
	{
		// Spaces in the name is not allowed
		CiSetError(c, ERR_INVALID_PARAMETER);
		return false;
	}

#ifndef	OS_WIN32

	// Non-Win32
#ifdef	NO_VLAN
	if (GetOsInfo()->OsType == OSTYPE_MACOS_X)
	{
		// A virtual LAN card can not be added or removed in MacOS X
		CiSetError(c, ERR_NOT_SUPPORTED);
		return false;
	}
#endif	// NO_VLAN

	// Check whether the specified name is valid or not
	if (IsSafeStr(create->DeviceName) == false)
	{
		// Name is invalid
		CiSetError(c, ERR_VLAN_INVALID_NAME);
		return false;
	}

	// Check whether the LAN card of the specified name already exists
	LockList(c->UnixVLanList);
	{
		UNIX_VLAN t, *r;
		Zero(&t, sizeof(t));
		StrCpy(t.Name, sizeof(t.Name), create->DeviceName);

		r = Search(c->UnixVLanList, &t);
		if (r != NULL)
		{
			// Already exist
			CiSetError(c, ERR_VLAN_ALREADY_EXISTS);
			UnlockList(c->UnixVLanList);
			return false;
		}

		// Register
		r = ZeroMalloc(sizeof(UNIX_VLAN));
		r->Enabled = true;
		GenMacAddress(r->MacAddress);
		StrCpy(r->Name, sizeof(r->Name), create->DeviceName);

		// Create a TUN
		if (UnixVLanCreate(r->Name, r->MacAddress, false) == false)
		{
			// Failure
			Free(r);
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			UnlockList(c->UnixVLanList);
			return false;
		}

		CLog(c, "LC_CREATE_VLAN", create->DeviceName);

		Add(c->UnixVLanList, r);
	}
	UnlockList(c->UnixVLanList);

	CiNormalizeAccountVLan(c);

	CiNotify(c);
	CiSendGlobalPulse(c);
	CiSaveConfigurationFile(c);

	return true;

#else	// OS_WIN32

	if (OS_IS_WINDOWS_9X(GetOsInfo()->OsType))
	{
		// Only one LAN card is available in the Win9x
		TOKEN_LIST *t;

		t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, VLAN_ADAPTER_NAME_OLD);
		if (t != NULL)
		{
			if (t->NumTokens >= 1)
			{
				FreeToken(t);
				CiSetError(c, ERR_NOT_SUPPORTED);
				return false;
			}
			FreeToken(t);
		}
	}

	// Check whether the specified name is valid or not
	if (IsSafeStr(create->DeviceName) == false)
	{
		// Name is invalid
		CiSetError(c, ERR_VLAN_INVALID_NAME);
		return false;
	}

	max_len = MsIsNt() ? MAX_DEVICE_NAME_LEN : MAX_DEVICE_NAME_LEN_9X;
	if (StrLen(create->DeviceName) > max_len)
	{
		// Name is too long
		CiSetError(c, ERR_VLAN_INVALID_NAME);
		return false;
	}

	// Regulation in Windows 8 / 10
	if (MsIsInfCatalogRequired())
	{
		if (CiIsValidVLanRegulatedName(create->DeviceName) == false)
		{
			// Name is invalid
			CiSetError(c, ERR_VLAN_INVALID_NAME);
			return false;
		}
	}

	// Check whether the LAN card with the specified name already exists
	if (MsIsVLanExists(VLAN_ADAPTER_NAME_TAG, create->DeviceName) ||
		MsIsVLanExists(VLAN_ADAPTER_NAME_TAG_OLD, create->DeviceName))
	{
		// Already exist
		CiSetError(c, ERR_VLAN_ALREADY_EXISTS);
		return false;
	}

	if (MsIsNt())
	{
		if (MsIsVista() == false)
		{
			k = InitKakushi();
		}
	}

	if (MsIsVista() == false)
	{
		MS_DRIVER_VER ver;

		CiInitDriverVerStruct(&ver);

		// Perform the installation (other than Windows Vista)
		if (MsInstallVLan(VLAN_ADAPTER_NAME_TAG, VLAN_CONNECTION_NAME, create->DeviceName, &ver) == false)
		{
			// Installation Failed
			FreeKakushi(k);
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			CiSendGlobalPulse(c);
			return false;
		}
	}
	else
	{
		// Perform the installation (Windows Vista)
		char tmp[MAX_SIZE];

		Format(tmp, sizeof(tmp), "instvlan %s", create->DeviceName);

		if (CncExecDriverInstaller(tmp) == false)
		{
			// Installation Failed
			FreeKakushi(k);
			CiSetError(c, ERR_VLAN_INSTALL_ERROR);
			CiNotify(c);
			CiSendGlobalPulse(c);
			return false;
		}
	}

	FreeKakushi(k);

	t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, VLAN_ADAPTER_NAME_OLD);
	if (t->NumTokens == 1)
	{
		UINT i;
		// If the result of the installation, virtual LAN card is only one,
		// set virtual LAN card setting of all existing accounts to this virtual LAN card
		LockList(c->AccountList);
		{
			for (i = 0;i < LIST_NUM(c->AccountList);i++)
			{
				ACCOUNT *a = LIST_DATA(c->AccountList, i);
				Lock(a->lock);
				{
					if (a->ClientOption != NULL)
					{
						StrCpy(a->ClientOption->DeviceName, sizeof(a->ClientOption->DeviceName), create->DeviceName);
					}
				}
				Unlock(a->lock);
			}
		}
		UnlockList(c->AccountList);
	}
	FreeToken(t);

	CLog(c, "LC_CREATE_VLAN", create->DeviceName);

	CiNormalizeAccountVLan(c);

	CiNotify(c);
	CiSendGlobalPulse(c);

	CiSaveConfigurationFile(c);

	if (MsIsNt() == false)
	{
		if (GetOsInfo()->OsType == OSTYPE_WINDOWS_ME)
		{
			// Show the warning in the case of Windows Me
			MsgBox(NULL, 0x00000040L, _UU("CM_9X_VLAN_ME_MESSAGE"));
		}

		ReleaseThread(NewThread(Win9xRebootThread, NULL));
	}

	return true;

#endif	// OS_WIN32
}

// Enumerate objects in the secure device
bool CtEnumObjectInSecure(CLIENT *c, RPC_ENUM_OBJECT_IN_SECURE *e)
{
	UINT i;
	// Validate arguments
	if (c == NULL || e == NULL)
	{
		return false;
	}

	e->NumItem = 5;
	e->ItemName = ZeroMalloc(sizeof(char *) * e->NumItem);
	e->ItemType = ZeroMalloc(sizeof(bool) * e->NumItem);

	for (i = 0;i < e->NumItem;i++)
	{
		char tmp[MAX_SIZE];
		Format(tmp, sizeof(tmp), "Test Object %u", i);
		e->ItemName[i] = CopyStr(tmp);
		e->ItemType[i] = (i % 2 == 0) ? false : true;
	}

	return true;
}

// Get the secure device to be used
bool CtGetUseSecure(CLIENT *c, RPC_USE_SECURE *sec)
{
	// Validate arguments
	if (c == NULL || sec == NULL)
	{
		return false;
	}

	sec->DeviceId = c->UseSecureDeviceId;

	return true;
}

// Specifying a secure device to be used
bool CtUseSecure(CLIENT *c, RPC_USE_SECURE *sec)
{
	// Validate arguments
	if (c == NULL || sec == NULL)
	{
		return false;
	}

// Do not check whether there is the specified device on the client manager
/*	if (CheckSecureDeviceId(sec->DeviceId))
	{
		c->UseSecureDeviceId = sec->DeviceId;
	}
	else
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
		return false;
	}
*/
	c->UseSecureDeviceId = sec->DeviceId;

	CiSaveConfigurationFile(c);

	return true;
}

// Enumeration of secure devices
bool CtEnumSecure(CLIENT *c, RPC_CLIENT_ENUM_SECURE *e)
{
	LIST *o;
	UINT i;
	// Validate arguments
	if (c == NULL || e == NULL)
	{
		return false;
	}

	o = GetSecureDeviceList();

	e->NumItem = LIST_NUM(o);
	e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_SECURE_ITEM *) * e->NumItem);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		RPC_CLIENT_ENUM_SECURE_ITEM *item = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_SECURE_ITEM));
		SECURE_DEVICE *s = LIST_DATA(o, i);

		item->DeviceId = s->Id;
		StrCpy(item->DeviceName, sizeof(item->DeviceName), s->DeviceName);
		StrCpy(item->Manufacturer, sizeof(item->Manufacturer), s->Manufacturer);
		item->Type = s->Type;

		e->Items[i] = item;
	}

	return true;
}

// Release the secure device enumeration
void CiFreeClientEnumSecure(RPC_CLIENT_ENUM_SECURE *e)
{
	UINT i;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	for (i = 0;i < e->NumItem;i++)
	{
		Free(e->Items[i]);
	}
	Free(e->Items);
}

// Release the RPC_GET_ISSUER
void CiFreeGetIssuer(RPC_GET_ISSUER *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	if (a->issuer_x != NULL)
	{
		FreeX(a->issuer_x);
	}
	if (a->x != NULL)
	{
		FreeX(a->x);
	}
}

// Get the common proxy settings
bool CtGetCommonProxySetting(CLIENT *c, INTERNET_SETTING *a)
{
	// Validate arguments
	if (c == NULL || a == NULL)
	{
		return false;
	}

	Copy(a, &c->CommonProxySetting, sizeof(INTERNET_SETTING));

	return true;
}

// Set the common proxy settings
bool CtSetCommonProxySetting(CLIENT *c, INTERNET_SETTING *a)
{
	// Validate arguments
	if (c == NULL || a == NULL)
	{
		return false;
	}

	Copy(&c->CommonProxySetting, a, sizeof(INTERNET_SETTING));


	CiSaveConfigurationFile(c);

	return true;
}

// Get the issuer
bool CtGetIssuer(CLIENT *c, RPC_GET_ISSUER *a)
{
	X *x;
	// Validate arguments
	if (c == NULL || a == NULL)
	{
		return false;
	}

	x = FindCaSignedX(c->Cedar->CaList, a->x);
	if (x == NULL)
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);;
		return false;
	}
	else
	{
		a->issuer_x = x;
		if (a->x != NULL)
		{
			FreeX(a->x);
			a->x = NULL;
		}
		return true;
	}
}

// Get the CA certificate
bool CtGetCa(CLIENT *c, RPC_GET_CA *get)
{
	bool ret = true;
	X *cert = NULL;
	// Validate arguments
	if (c == NULL || get == NULL)
	{
		return false;
	}

	LockList(c->Cedar->CaList);
	{
		UINT i;

		for (i = 0;i < LIST_NUM(c->Cedar->CaList);i++)
		{
			X *x = LIST_DATA(c->Cedar->CaList, i);

			if (POINTER_TO_KEY(x) == get->Key)
			{
				cert = CloneX(x);
				break;
			}
		}
	}
	UnlockList(c->Cedar->CaList);

	if (cert == NULL)
	{
		// Certificate does not exist
		ret = false;
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
	}
	else
	{
		ret = true;
		get->x = cert;
	}

	return ret;
}

// Delete the CA certificate
bool CtDeleteCa(CLIENT *c, RPC_CLIENT_DELETE_CA *p)
{
	bool ret;
	// Validate arguments
	if (c == NULL || p == NULL)
	{
		return false;
	}

	ret = DeleteCa(c->Cedar, p->Key);

	if (ret == false)
	{
		CiSetError(c, ERR_OBJECT_NOT_FOUND);
	}

	CiSaveConfigurationFile(c);

	return ret;
}

// Add a CA certificate
bool CtAddCa(CLIENT *c, RPC_CERT *cert)
{
	// Validate arguments
	if (c == NULL || cert == NULL)
	{
		return false;
	}

	if (cert->x->is_compatible_bit == false)
	{
		CiSetError(c, ERR_NOT_RSA_1024);
		return false;
	}

	AddCa(c->Cedar, cert->x);

	CiSaveConfigurationFile(c);

	return true;
}

// Enumerate the trusted CA
bool CtEnumCa(CLIENT *c, RPC_CLIENT_ENUM_CA *e)
{
	// Validate arguments
	if (c == NULL || e == NULL)
	{
		return false;
	}

	Zero(e, sizeof(RPC_CLIENT_ENUM_CA));

	LockList(c->Cedar->CaList);
	{
		UINT i;
		e->NumItem = LIST_NUM(c->Cedar->CaList);
		e->Items = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_CA_ITEM *) * e->NumItem);

		for (i = 0;i < e->NumItem;i++)
		{
			X *x = LIST_DATA(c->Cedar->CaList, i);
			e->Items[i] = ZeroMalloc(sizeof(RPC_CLIENT_ENUM_CA_ITEM));
			GetAllNameFromNameEx(e->Items[i]->SubjectName, sizeof(e->Items[i]->SubjectName), x->subject_name);
			GetAllNameFromNameEx(e->Items[i]->IssuerName, sizeof(e->Items[i]->IssuerName), x->issuer_name);
			e->Items[i]->Expires = x->notAfter;
			e->Items[i]->Key = POINTER_TO_KEY(x);
		}
	}
	UnlockList(c->Cedar->CaList);

	return true;
}

// Release the CA enumeration
void CiFreeClientEnumCa(RPC_CLIENT_ENUM_CA *e)
{
	UINT i;
	// Validate arguments
	if (e == NULL)
	{
		return;
	}

	for (i = 0;i < e->NumItem;i++)
	{
		RPC_CLIENT_ENUM_CA_ITEM *ca = e->Items[i];
		Free(ca);
	}
	Free(e->Items);
}

// Get the password setting
bool CtGetPasswordSetting(CLIENT *c, RPC_CLIENT_PASSWORD_SETTING *a)
{
	UCHAR hash[SHA1_SIZE];
	// Validate arguments
	if (c == NULL || a == NULL)
	{
		return false;
	}

	Sha0(hash, "", 0);
	if (Cmp(hash, c->EncryptedPassword, SHA1_SIZE) == 0)
	{
		a->IsPasswordPresented = false;
	}
	else
	{
		a->IsPasswordPresented = true;
	}

	a->PasswordRemoteOnly = c->PasswordRemoteOnly;

	return true;
}

// Set the password
bool CtSetPassword(CLIENT *c, RPC_CLIENT_PASSWORD *pass)
{
	char *str;
	if (c == NULL)
	{
		return false;
	}

	str = pass->Password;

	if (StrCmp(str, "********") != 0)
	{
		// Hash the password
		Sha0(c->EncryptedPassword, str, StrLen(str));
	}

	c->PasswordRemoteOnly = pass->PasswordRemoteOnly;

	CLog(c, "LC_SET_PASSWORD");

	CiSaveConfigurationFile(c);

	return true;
}

void CiFreeIni(LIST *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	FreeIni(o);
}

// Read the custom.ini file
LIST *CiLoadIni()
{
	BUF *b = ReadDump(CLIENT_CUSTOM_INI_FILENAME);
	LIST *ini;
	if (b == NULL)
	{
		return NULL;
	}

	ini = ReadIni(b);

	FreeBuf(b);

	return ini;

}

// Reflect the settings of the custom.ini
void CiLoadIniSettings(CLIENT *c)
{
	LIST *o;
	//char *log;
	//char *config;

	if (c == NULL)
	{
		return;
	}

	o = CiLoadIni();

	if (o == NULL)
	{
		return;
	}

	/*log = IniStrValue(o, "NoSaveLog");
	config = IniStrValue(o, "NoSaveConfig");

	if(StrCmpi(log, "true") == 0)
	{
		c->NoSaveLog = true;
	}
	if(StrCmpi(config, "true") == 0)
	{
		c->NoSaveConfig = true;
	}*/

	c->NoSaveLog = ToBool(IniStrValue(o, "NoSaveLog"));
	c->NoSaveConfig = ToBool(IniStrValue(o, "NoSaveConfig"));
	
	CiFreeIni(o);

}

bool CiLoadConfigFilePathFromIni(char *path, UINT size)
{
	char *tmp;
	LIST *o;
	bool ret = false;

	// Validate arguments
	if (path == NULL)
	{
		return false;
	}

	o = CiLoadIni();

	if (o == NULL)
	{
		return false;
	}

	StrCpy(path, size, "");

	tmp = IniStrValue(o, "ConfigPath");
	NormalizePath(path, size, tmp);

	if (IsEmptyStr(path) == false)
	{
		ret = true;
	}
	else
	{
		ret = false;
	}

	CiFreeIni(o);

	return ret;
}

// Set the client error code
void CiSetError(CLIENT *c, UINT err)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	c->Err = err;
}

// UNIX virtual LAN card comparison function
int CiCompareUnixVLan(void *p1, void *p2)
{
	UNIX_VLAN *v1, *v2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	v1 = *(UNIX_VLAN **)p1;
	v2 = *(UNIX_VLAN **)p2;
	if (v1 == NULL || v2 == NULL)
	{
		return 0;
	}

	return StrCmpi(v1->Name, v2->Name);
}

// Modify the account settings that an incorrect VLAN name is specified
void CiNormalizeAccountVLan(CLIENT *c)
{
	bool b = false;
	char *name;
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	name = CiGetFirstVLan(c);

	if (name != NULL)
	{
		LockList(c->AccountList);
		{
			for (i = 0;i < LIST_NUM(c->AccountList);i++)
			{
				ACCOUNT *a = LIST_DATA(c->AccountList, i);

				Lock(a->lock);
				{
					if (a->ClientOption != NULL)
					{
						if (CiIsVLan(c, a->ClientOption->DeviceName) == false)
						{
							StrCpy(a->ClientOption->DeviceName, sizeof(a->ClientOption->DeviceName),
								name);
							b = true;
						}
					}
				}
				Unlock(a->lock);
			}
		}
		UnlockList(c->AccountList);

		Free(name);
	}

	if (b)
	{
		CiNotify(c);
		CiSendGlobalPulse(c);
		CiSaveConfigurationFile(c);
	}
}

// Check whether a virtual LAN card of the specified name exists
bool CiIsVLan(CLIENT *c, char *name)
{
	// Validate arguments
	if (c == NULL || name == NULL)
	{
		return false;
	}

#ifdef	OS_WIN32
	{
		TOKEN_LIST *t;
		UINT i;

		t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, VLAN_ADAPTER_NAME_OLD);
		if (t == NULL)
		{
			return false;
		}

		for (i = 0;i < t->NumTokens;i++)
		{
			if (StrCmpi(t->Token[i], name) == 0)
			{
				FreeToken(t);
				return true;
			}
		}

		FreeToken(t);

		return false;
	}
#else	// OS_WIN32
	{
		UNIX_VLAN *v;
		UINT i;
		bool ret = false;

		LockList(c->UnixVLanList);
		{
			for (i = 0;i < LIST_NUM(c->UnixVLanList);i++)
			{
				v = (UNIX_VLAN *)LIST_DATA(c->UnixVLanList, i);
				if (StrCmpi(v->Name, name) == 0)
				{
					ret = true;
				}
			}
		}
		UnlockList(c->UnixVLanList);

		return ret;
	}
#endif	// OS_WIN32
}

// If a non-existent virtual LAN card is specified in any Account, and only
// one virtual LAN card is installed, set the virtual LAN card to the account
void CiSetVLanToDefault(CLIENT *c)
{
	char device_name[MAX_SIZE];
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	{
		TOKEN_LIST *t;

		t = MsEnumNetworkAdapters(VLAN_ADAPTER_NAME, VLAN_ADAPTER_NAME_OLD);
		if (t == NULL)
		{
			return;
		}
		if (t->NumTokens != 1)
		{
			FreeToken(t);
			return;
		}
		StrCpy(device_name, sizeof(device_name), t->Token[0]);
		FreeToken(t);
	}
#else	// OS_WIN32
	{
		UNIX_VLAN *v;

		LockList(c->UnixVLanList);

		if (LIST_NUM(c->UnixVLanList) != 1)
		{
			UnlockList(c->UnixVLanList);
			return;
		}
		v = LIST_DATA(c->UnixVLanList, 0);
		StrCpy(device_name, sizeof(device_name), v->Name);

		UnlockList(c->UnixVLanList);
	}
#endif	// OS_WIN32

	{
		UINT i;
		LockList(c->AccountList);
		{
			for (i = 0;i < LIST_NUM(c->AccountList);i++)
			{
				ACCOUNT *a = LIST_DATA(c->AccountList, i);

				Lock(a->lock);
				{
					if (CiIsVLan(c, a->ClientOption->DeviceName) == false)
					{
						StrCpy(a->ClientOption->DeviceName, sizeof(a->ClientOption->DeviceName),
							device_name);
					}
				}
				Unlock(a->lock);
			}
		}
		UnlockList(c->AccountList);
	}
}

// Initialize the settings
void CiInitConfiguration(CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

#ifdef	OS_UNIX
	// Initialize the VLAN
	UnixVLanInit();
#endif	 // OS_UNIX

	// Account list
	c->AccountList = NewList(CiCompareAccount);

	// Unix version VLAN list
	if (OS_IS_UNIX(GetOsInfo()->OsType))
	{
		c->UnixVLanList = NewList(CiCompareUnixVLan);
	}

	// Read the configuration file
	CLog(c, "LC_LOAD_CONFIG_1");
	if (CiLoadConfigurationFile(c) == false)
	{
		CLog(c, "LC_LOAD_CONFIG_3");
		// Do the initial setup because the configuration file does not exist
		// Clear the password
		Sha0(c->EncryptedPassword, "", 0);
		// Initialize the client configuration
		// Disable remote management
		c->Config.AllowRemoteConfig = false;
		StrCpy(c->Config.KeepConnectHost, sizeof(c->Config.KeepConnectHost), CLIENT_DEFAULT_KEEPALIVE_HOST);
		c->Config.KeepConnectPort = CLIENT_DEFAULT_KEEPALIVE_PORT;
		c->Config.KeepConnectProtocol = CONNECTION_UDP;
		c->Config.KeepConnectInterval = CLIENT_DEFAULT_KEEPALIVE_INTERVAL;
		c->Config.UseKeepConnect = false;	// Don't use the connection maintenance function by default in the Client
		// Eraser
		c->Eraser = NewEraser(c->Logger, 0);
	}
	else
	{
		CLog(c, "LC_LOAD_CONFIG_2");
	}

	// Appropriate setting for virtual LAN card
	CiSetVLanToDefault(c);
}

// Release the settings
void CiFreeConfiguration(CLIENT *c)
{
	UINT i;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	// Write to the configuration file
	CiSaveConfigurationFile(c);

	// Release the configuration file
	FreeCfgRw(c->CfgRw);

	// Release the account list
	for (i = 0;i < LIST_NUM(c->AccountList);i++)
	{
		ACCOUNT *a = LIST_DATA(c->AccountList, i);

		CiFreeAccount(a);
	}
	ReleaseList(c->AccountList);

	if (c->UnixVLanList != NULL)
	{
		// Release of UNIX version VLAN list
		for (i = 0;i < LIST_NUM(c->UnixVLanList);i++)
		{
			UNIX_VLAN *v = LIST_DATA(c->UnixVLanList, i);
			Free(v);
		}
		ReleaseList(c->UnixVLanList);
	}
	c->UnixVLanList = NULL;

#ifdef	OS_UNIX
	// Release the VLAN
	UnixVLanFree();
#endif	// OS_UNIX
}

// Release the certificate data acquisition
void CiFreeGetCa(RPC_GET_CA *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	FreeX(a->x);
}

// Release the client authentication data
void CiFreeClientAuth(CLIENT_AUTH *auth)
{
	// Validate arguments
	if (auth == NULL)
	{
		return;
	}

	if (auth->ClientX != NULL)
	{
		FreeX(auth->ClientX);
	}
	if (auth->ClientK != NULL)
	{
		FreeK(auth->ClientK);
	}

	Free(auth);
}

// Release the account
void CiFreeAccount(ACCOUNT *a)
{
	// Validate arguments
	if (a == NULL)
	{
		return;
	}

	// Release the lock
	DeleteLock(a->lock);

	// Release the client option
	Free(a->ClientOption);

	// Release the client authentication data
	CiFreeClientAuth(a->ClientAuth);

	if (a->ServerCert != NULL)
	{
		FreeX(a->ServerCert);
	}

	Free(a);
}

// Sort accounts
int CiCompareAccount(void *p1, void *p2)
{
	ACCOUNT *a1, *a2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	a1 = *(ACCOUNT **)p1;
	a2 = *(ACCOUNT **)p2;
	if (a1 == NULL || a2 == NULL)
	{
		return 0;
	}

	return UniStrCmpi(a1->ClientOption->AccountName, a2->ClientOption->AccountName);
}

// Read the client configuration
void CiLoadClientConfig(CLIENT_CONFIG *c, FOLDER *f)
{
	// Validate arguments
	if (c == NULL || f == NULL)
	{
		return;
	}

	c->UseKeepConnect = CfgGetBool(f, "UseKeepConnect");
	CfgGetStr(f, "KeepConnectHost", c->KeepConnectHost, sizeof(c->KeepConnectHost));
	c->KeepConnectPort = CfgGetInt(f, "KeepConnectPort");
	c->KeepConnectProtocol = CfgGetInt(f, "KeepConnectProtocol");
	c->AllowRemoteConfig = CfgGetBool(f, "AllowRemoteConfig");
	c->KeepConnectInterval = MAKESURE(CfgGetInt(f, "KeepConnectInterval"), KEEP_INTERVAL_MIN, KEEP_INTERVAL_MAX);
	c->NoChangeWcmNetworkSettingOnWindows8 = CfgGetBool(f, "NoChangeWcmNetworkSettingOnWindows8");
}

// Read the client authentication data
CLIENT_AUTH *CiLoadClientAuth(FOLDER *f)
{
	CLIENT_AUTH *a;
	char *s;
	BUF *b;
	// Validate arguments
	if (f == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(CLIENT_AUTH));

	a->AuthType = CfgGetInt(f, "AuthType");
	CfgGetStr(f, "Username", a->Username, sizeof(a->Username));

	switch (a->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		CfgGetByte(f, "HashedPassword", a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		b = CfgGetBuf(f, "EncryptedPassword");
		if (b != NULL)
		{
			s = DecryptPassword(b);
			StrCpy(a->PlainPassword, sizeof(a->PlainPassword), s);
			Free(s);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = CfgGetBuf(f, "ClientCert");
		if (b != NULL)
		{
			a->ClientX = BufToX(b, false);
		}
		FreeBuf(b);
		b = CfgGetBuf(f, "ClientKey");
		if (b != NULL)
		{
			a->ClientK = BufToK(b, true, false, NULL);
		}
		FreeBuf(b);
		break;

	case CLIENT_AUTHTYPE_SECURE:
		CfgGetStr(f, "SecurePublicCertName", a->SecurePublicCertName, sizeof(a->SecurePublicCertName));
		CfgGetStr(f, "SecurePrivateKeyName", a->SecurePrivateKeyName, sizeof(a->SecurePrivateKeyName));
		break;
	}

	return a;
}

// Read the client option
CLIENT_OPTION *CiLoadClientOption(FOLDER *f)
{
	CLIENT_OPTION *o;
	char *s;
	BUF *b;
	// Validate arguments
	if (f == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(CLIENT_OPTION));

	CfgGetUniStr(f, "AccountName", o->AccountName, sizeof(o->AccountName));
	CfgGetStr(f, "Hostname", o->Hostname, sizeof(o->Hostname));
	o->Port = CfgGetInt(f, "Port");
	o->PortUDP = CfgGetInt(f, "PortUDP");
	o->ProxyType = CfgGetInt(f, "ProxyType");
	CfgGetStr(f, "ProxyName", o->ProxyName, sizeof(o->ProxyName));
	o->ProxyPort = CfgGetInt(f, "ProxyPort");
	CfgGetStr(f, "ProxyUsername", o->ProxyUsername, sizeof(o->ProxyUsername));
	b = CfgGetBuf(f, "ProxyPassword");
	s = DecryptPassword(b);
	StrCpy(o->ProxyPassword, sizeof(o->ProxyPassword), s);
	Free(s);
	FreeBuf(b);
	CfgGetStr(f, "CustomHttpHeader", o->CustomHttpHeader, sizeof(o->CustomHttpHeader));
	o->NumRetry = CfgGetInt(f, "NumRetry");
	o->RetryInterval = CfgGetInt(f, "RetryInterval");
	CfgGetStr(f, "HubName", o->HubName, sizeof(o->HubName));
	o->MaxConnection = CfgGetInt(f, "MaxConnection");
	o->UseEncrypt = CfgGetBool(f, "UseEncrypt");
	o->UseCompress = CfgGetBool(f, "UseCompress");
	o->HalfConnection = CfgGetBool(f, "HalfConnection");
	o->NoRoutingTracking = CfgGetBool(f, "NoRoutingTracking");
	CfgGetStr(f, "DeviceName", o->DeviceName, sizeof(o->DeviceName));
	o->AdditionalConnectionInterval = CfgGetInt(f, "AdditionalConnectionInterval");
	o->HideStatusWindow = CfgGetBool(f, "HideStatusWindow");
	o->HideNicInfoWindow = CfgGetBool(f, "HideNicInfoWindow");
	o->ConnectionDisconnectSpan = CfgGetInt(f, "ConnectionDisconnectSpan");
	o->RequireMonitorMode = CfgGetBool(f, "RequireMonitorMode");
	o->RequireBridgeRoutingMode = CfgGetBool(f, "RequireBridgeRoutingMode");
	o->DisableQoS = CfgGetBool(f, "DisableQoS");
	o->FromAdminPack = CfgGetBool(f, "FromAdminPack");
	o->NoUdpAcceleration = CfgGetBool(f, "NoUdpAcceleration");
	
	b = CfgGetBuf(f, "HostUniqueKey");
	if (b != NULL)
	{
		if (b->Size == SHA1_SIZE)
		{
			Copy(o->HostUniqueKey, b->Buf, SHA1_SIZE);
		}

		FreeBuf(b);
	}

	return o;
}

// Read the account data
ACCOUNT *CiLoadClientAccount(FOLDER *f)
{
	ACCOUNT *a;
	FOLDER *client_option_folder, *client_auth_folder;
	BUF *b;
	char tmp[64];
	// Validate arguments
	if (f == NULL)
	{
		return NULL;
	}

	client_option_folder = CfgGetFolder(f, "ClientOption");

	if (client_option_folder != NULL)
	{
		// Compare whether it matches to the account name that is already registered
	}

	client_auth_folder = CfgGetFolder(f, "ClientAuth");

	if (client_option_folder == NULL || client_auth_folder == NULL)
	{
		return NULL;
	}

	a = ZeroMalloc(sizeof(ACCOUNT));
	a->lock = NewLock();

	a->ClientOption = CiLoadClientOption(client_option_folder);
	a->ClientAuth = CiLoadClientAuth(client_auth_folder);

	a->StartupAccount = CfgGetBool(f, "StartupAccount");
	a->CheckServerCert = CfgGetBool(f, "CheckServerCert");
	a->RetryOnServerCert = CfgGetBool(f, "RetryOnServerCert");
	a->CreateDateTime = CfgGetInt64(f, "CreateDateTime");
	a->UpdateDateTime = CfgGetInt64(f, "UpdateDateTime");
	a->LastConnectDateTime = CfgGetInt64(f, "LastConnectDateTime");

	b = CfgGetBuf(f, "ServerCert");
	if (b != NULL)
	{
		a->ServerCert = BufToX(b, false);
		FreeBuf(b);
	}

	if (CfgGetStr(f, "ShortcutKey", tmp, sizeof(tmp)))
	{
		BUF *b = StrToBin(tmp);
		if (b->Size == SHA1_SIZE)
		{
			Copy(a->ShortcutKey, b->Buf, SHA1_SIZE);
		}
		FreeBuf(b);
	}

	if (IsZero(a->ShortcutKey, SHA1_SIZE))
	{
		Rand(a->ShortcutKey, SHA1_SIZE);
	}

	return a;
}

// Read the account database
void CiLoadAccountDatabase(CLIENT *c, FOLDER *f)
{
	TOKEN_LIST *t;
	UINT i;
	// Validate arguments
	if (c == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);
	if (t == NULL)
	{
		return;
	}

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = CfgGetFolder(f, t->Token[i]);

		if (ff != NULL)
		{
			ACCOUNT *a = CiLoadClientAccount(ff);
			if (a != NULL)
			{
				{
					Add(c->AccountList, a);
				}
			}
		}
	}

	Sort(c->AccountList);

	FreeToken(t);
}

// Read the root CA certificate
void CiLoadCACert(CLIENT *c, FOLDER *f)
{
	BUF *b;
	X *x;
	// Validate arguments
	if (c == NULL || f == NULL)
	{
		return;
	}

	b = CfgGetBuf(f, "X509");
	if (b == NULL)
	{
		return;
	}

	x = BufToX(b, false);

	AddCa(c->Cedar, x);

	FreeX(x);

	FreeBuf(b);
}

// Read the root CA list
void CiLoadCAList(CLIENT *c, FOLDER *f)
{
	CEDAR *cedar;
	TOKEN_LIST *t;
	// Validate arguments
	if (c == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	cedar = c->Cedar;

	LockList(cedar->CaList);
	{
		UINT i;
		for (i = 0;i < t->NumTokens;i++)
		{
			FOLDER *folder = CfgGetFolder(f, t->Token[i]);
			CiLoadCACert(c, folder);
		}
	}
	UnlockList(cedar->CaList);

	FreeToken(t);
}

// Read a VLAN
void CiLoadVLan(CLIENT *c, FOLDER *f)
{
	char tmp[MAX_SIZE];
	UCHAR addr[6];
	BUF *b;
	UNIX_VLAN *v;
	// Validate arguments
	if (c == NULL || f == NULL)
	{
		return;
	}

	if (CfgGetStr(f, "MacAddress", tmp, sizeof(tmp)) == false)
	{
		return;
	}

	b = StrToBin(tmp);
	if (b == NULL)
	{
		return;
	}

	if (b->Size != 6)
	{
		FreeBuf(b);
		return;
	}

	Copy(addr, b->Buf, 6);

	FreeBuf(b);

	if (IsZero(addr, 6))
	{
		return;
	}

	v = ZeroMalloc(sizeof(UNIX_VLAN));
	Copy(v->MacAddress, addr, 6);
	StrCpy(v->Name, sizeof(v->Name), f->Name);
	v->Enabled = CfgGetBool(f, "Enabled");

	Add(c->UnixVLanList, v);

#ifdef	OS_UNIX
	UnixVLanCreate(v->Name, v->MacAddress, false);
#endif	// OS_UNIX
}

// Read a VLAN list
void CiLoadVLanList(CLIENT *c, FOLDER *f)
{
	TOKEN_LIST *t;
	// Validate arguments
	if (c == NULL || f == NULL)
	{
		return;
	}

	t = CfgEnumFolderToTokenList(f);

	LockList(c->UnixVLanList);
	{
		UINT i;
		for (i = 0;i < t->NumTokens;i++)
		{
			FOLDER *folder = CfgGetFolder(f, t->Token[i]);
			CiLoadVLan(c, folder);
		}
	}
	UnlockList(c->UnixVLanList);

	FreeToken(t);
}

// Read the configuration from the configuration file
bool CiReadSettingFromCfg(CLIENT *c, FOLDER *root)
{
	FOLDER *config;
	FOLDER *cert;
	FOLDER *db;
	FOLDER *vlan;
	FOLDER *cmsetting;
	FOLDER *proxy;
	char user_agent[MAX_SIZE];
	// Validate arguments
	if (c == NULL || root == NULL)
	{
		return false;
	}

	// Initialize the setting if there isn't either of AccountDatabase and Config
	config = CfgGetFolder(root, "Config");
	if (config == NULL)
	{
		return false;
	}

	db = CfgGetFolder(root, "AccountDatabase");
	if (db == NULL)
	{
		return false;
	}

	cmsetting = CfgGetFolder(root, "ClientManagerSetting");

	CiLoadClientConfig(&c->Config, config);


	proxy = CfgGetFolder(root, "CommonProxySetting");

	if (proxy != NULL)
	{
		INTERNET_SETTING t;
		BUF *pw;

		// Proxy Setting
		Zero(&t, sizeof(t));
		t.ProxyType = CfgGetInt(proxy, "ProxyType");
		CfgGetStr(proxy, "ProxyHostName", t.ProxyHostName, sizeof(t.ProxyHostName));
		t.ProxyPort = CfgGetInt(proxy, "ProxyPort");
		CfgGetStr(proxy, "ProxyUsername", t.ProxyUsername, sizeof(t.ProxyUsername));
		pw = CfgGetBuf(proxy, "ProxyPassword");
		if (pw != NULL)
		{
			char *pw_str = DecryptPassword(pw);
			StrCpy(t.ProxyPassword, sizeof(t.ProxyPassword), pw_str);

			Free(pw_str);
			FreeBuf(pw);
		}

		CfgGetStr(proxy, "CustomHttpHeader", t.CustomHttpHeader, sizeof(t.CustomHttpHeader));

		Copy(&c->CommonProxySetting, &t, sizeof(INTERNET_SETTING));
	}

	// Eraser
	c->Eraser = NewEraser(c->Logger, CfgGetInt64(config, "AutoDeleteCheckDiskFreeSpaceMin"));

	if (OS_IS_UNIX(GetOsInfo()->OsType)
#ifdef	NO_VLAN
	    && GetOsInfo()->OsType != OSTYPE_MACOS_X
#endif	// NO_VLAN
	    )
	{
		// Read the UNIX version virtual LAN card list (except MacOS)
		vlan = CfgGetFolder(root, "UnixVLan");
		if (vlan != NULL)
		{
			CiLoadVLanList(c, vlan);
		}
	}

#ifdef	NO_VLAN
	if (GetOsInfo()->OsType == OSTYPE_MACOS_X)
	{
#ifdef	OS_UNIX
		UNIX_VLAN *uv;

		// Create a Tap for MacOS X
		if (UnixVLanCreate(CLIENT_MACOS_TAP_NAME, NULL, false) == false)
		{
			// Fail (abort)
			CLog(c, "LC_TAP_NOT_FOUND");
			Alert("tun/tap driver not found.", NULL);
			exit(0);
		}

		uv = ZeroMalloc(sizeof(UNIX_VLAN));
		uv->Enabled = true;
		StrCpy(uv->Name, sizeof(uv->Name), CLIENT_MACOS_TAP_NAME);
		Add(c->UnixVLanList, uv);
#endif	// OS_UNIX
	}
#endif	// NO_VLAN
	CiLoadAccountDatabase(c, db);

	if (CfgGetByte(root, "EncryptedPassword", c->EncryptedPassword, SHA1_SIZE) == false)
	{
		Sha0(c->EncryptedPassword, "", 0);
	}

	c->PasswordRemoteOnly = CfgGetBool(root, "PasswordRemoteOnly");
	c->UseSecureDeviceId = CfgGetInt(root, "UseSecureDeviceId");

	if (CfgGetStr(root, "UserAgent", user_agent, sizeof(user_agent)))
	{
		if (IsEmptyStr(user_agent) == false)
		{
			Free(c->Cedar->HttpUserAgent);
			c->Cedar->HttpUserAgent = CopyStr(user_agent);
		}
	}

	cert = CfgGetFolder(root, "RootCA");
	if (cert != NULL)
	{
		CiLoadCAList(c, cert);
	}

	c->DontSavePassword = CfgGetBool(root, "DontSavePassword");

	if (cmsetting != NULL)
	{
		UINT ostype = GetOsInfo()->OsType;
		// CM_SETTING
		CM_SETTING *s = c->CmSetting;

		if (OS_IS_UNIX(ostype) || OS_IS_WINDOWS_NT(ostype))
		{
			s->EasyMode = CfgGetBool(cmsetting, "EasyMode");
		}

		s->LockMode = CfgGetBool(cmsetting, "LockMode");
		CfgGetByte(cmsetting, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword));
	}

	return true;
}

// Read the configuration file
bool CiLoadConfigurationFile(CLIENT *c)
{
	bool ret;
	FOLDER *root;
	char path[MAX_SIZE];
	// Validate arguments
	if (c == NULL)
	{
		return false;
	}

	// Read the configuration file
	if (CiLoadConfigFilePathFromIni(path, sizeof(path)))
	{
		c->CfgRw = NewCfgRw(&root, path);
	}
	else
	{
		c->CfgRw = NewCfgRw(&root, CLIENT_CONFIG_FILE_NAME);
	}

	if (root == NULL)
	{
		return false;
	}

	ret = CiReadSettingFromCfg(c, root);

	CfgDeleteFolder(root);

	return ret;
}

// Write the CLIENT_CONFIG
void CiWriteClientConfig(FOLDER *cc, CLIENT_CONFIG *config)
{
	// Validate arguments
	if (cc == NULL || config == NULL)
	{
		return;
	}

	CfgAddBool(cc, "UseKeepConnect", config->UseKeepConnect);
	CfgAddStr(cc, "KeepConnectHost", config->KeepConnectHost);
	CfgAddInt(cc, "KeepConnectPort", config->KeepConnectPort);
	CfgAddInt(cc, "KeepConnectProtocol", config->KeepConnectProtocol);
	CfgAddBool(cc, "AllowRemoteConfig", config->AllowRemoteConfig);
	CfgAddInt(cc, "KeepConnectInterval", config->KeepConnectInterval);
	CfgAddBool(cc, "NoChangeWcmNetworkSettingOnWindows8", config->NoChangeWcmNetworkSettingOnWindows8);
}

// Write the client authentication data
void CiWriteClientAuth(FOLDER *f, CLIENT_AUTH *a)
{
	BUF *b;
	// Validate arguments
	if (f == NULL || a == NULL)
	{
		return;
	}

	CfgAddInt(f, "AuthType", a->AuthType);
	CfgAddStr(f, "Username", a->Username);

	switch (a->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		CfgAddByte(f, "HashedPassword", a->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		b = EncryptPassword(a->PlainPassword);
		CfgAddByte(f, "EncryptedPassword", b->Buf, b->Size);
		FreeBuf(b);
		break;

	case CLIENT_AUTHTYPE_CERT:
		if (a->ClientK != NULL && a->ClientX != NULL)
		{
			b = XToBuf(a->ClientX, false);
			CfgAddByte(f, "ClientCert", b->Buf, b->Size);
			FreeBuf(b);

			b = KToBuf(a->ClientK, false, NULL);
			CfgAddByte(f, "ClientKey", b->Buf, b->Size);
			FreeBuf(b);
		}
		break;

	case CLIENT_AUTHTYPE_SECURE:
		CfgAddStr(f, "SecurePublicCertName", a->SecurePublicCertName);
		CfgAddStr(f, "SecurePrivateKeyName", a->SecurePrivateKeyName);
		break;
	}
}

// Write the client option
void CiWriteClientOption(FOLDER *f, CLIENT_OPTION *o)
{
	BUF *b;
	// Validate arguments
	if (f == NULL || o == NULL)
	{
		return;
	}

	CfgAddUniStr(f, "AccountName", o->AccountName);
	CfgAddStr(f, "Hostname", o->Hostname);
	CfgAddInt(f, "Port", o->Port);
	CfgAddInt(f, "PortUDP", o->PortUDP);
	CfgAddInt(f, "ProxyType", o->ProxyType);
	CfgAddStr(f, "ProxyName", o->ProxyName);
	CfgAddInt(f, "ProxyPort", o->ProxyPort);
	CfgAddStr(f, "ProxyUsername", o->ProxyUsername);
	b = EncryptPassword(o->ProxyPassword);
	CfgAddByte(f, "ProxyPassword", b->Buf, b->Size);
	FreeBuf(b);
	CfgAddStr(f, "CustomHttpHeader", o->CustomHttpHeader);
	CfgAddInt(f, "NumRetry", o->NumRetry);
	CfgAddInt(f, "RetryInterval", o->RetryInterval);
	CfgAddStr(f, "HubName", o->HubName);
	CfgAddInt(f, "MaxConnection", o->MaxConnection);
	CfgAddBool(f, "UseEncrypt", o->UseEncrypt);
	CfgAddBool(f, "UseCompress", o->UseCompress);
	CfgAddBool(f, "HalfConnection", o->HalfConnection);
	CfgAddBool(f, "NoRoutingTracking", o->NoRoutingTracking);
	CfgAddStr(f, "DeviceName", o->DeviceName);
	CfgAddInt(f, "AdditionalConnectionInterval", o->AdditionalConnectionInterval);
	CfgAddBool(f, "HideStatusWindow", o->HideStatusWindow);
	CfgAddBool(f, "HideNicInfoWindow", o->HideNicInfoWindow);
	CfgAddInt(f, "ConnectionDisconnectSpan", o->ConnectionDisconnectSpan);
	CfgAddBool(f, "RequireMonitorMode", o->RequireMonitorMode);
	CfgAddBool(f, "RequireBridgeRoutingMode", o->RequireBridgeRoutingMode);
	CfgAddBool(f, "DisableQoS", o->DisableQoS);
	CfgAddBool(f, "NoUdpAcceleration", o->NoUdpAcceleration);

	if (o->FromAdminPack)
	{
		CfgAddBool(f, "FromAdminPack", o->FromAdminPack);
	}

	if (IsZero(o->HostUniqueKey, SHA1_SIZE) == false)
	{
		BUF *b = MemToBuf(o->HostUniqueKey, SHA1_SIZE);
		CfgAddBuf(f, "HostUniqueKey", b);
		FreeBuf(b);
	}
}

// Decrypt the password
char *DecryptPassword(BUF *b)
{
	char *str;
	char *key = "EncryptPassword";
	CRYPT *c;
	// Validate arguments
	if (b == NULL)
	{
		return CopyStr("");
	}

	str = ZeroMalloc(b->Size + 1);
	c = NewCrypt(key, sizeof(key)); // NOTE by Daiyuu Nobori 2018-09-28: This is not a bug! Do not try to fix it!!
	Encrypt(c, str, b->Buf, b->Size);
	FreeCrypt(c);

	str[b->Size] = 0;

	return str;
}
char *DecryptPassword2(BUF *b)
{
	char *str;
	char *key = "EncryptPassword2";
	CRYPT *c;
	// Validate arguments
	if (b == NULL)
	{
		return CopyStr("");
	}

	str = ZeroMalloc(b->Size + 1);
	c = NewCrypt(key, StrLen(key));
	Encrypt(c, str, b->Buf, b->Size);
	FreeCrypt(c);

	str[b->Size] = 0;

	return str;
}

// Encrypt the password
BUF *EncryptPassword(char *password)
{
	UCHAR *tmp;
	UINT size;
	char *key = "EncryptPassword";
	CRYPT *c;
	BUF *b;
	// Validate arguments
	if (password == NULL)
	{
		password = "";
	}

	size = StrLen(password) + 1;
	tmp = ZeroMalloc(size);

	c = NewCrypt(key, sizeof(key)); // NOTE by Daiyuu Nobori 2018-09-28: This is not a bug! Do not try to fix it!!
	Encrypt(c, tmp, password, size - 1);
	FreeCrypt(c);

	b = NewBuf();
	WriteBuf(b, tmp, size - 1);
	SeekBuf(b, 0, 0);
	Free(tmp);

	return b;
}
BUF *EncryptPassword2(char *password)
{
	UCHAR *tmp;
	UINT size;
	char *key = "EncryptPassword2";
	CRYPT *c;
	BUF *b;
	// Validate arguments
	if (password == NULL)
	{
		password = "";
	}

	size = StrLen(password) + 1;
	tmp = ZeroMalloc(size);

	c = NewCrypt(key, StrLen(key));
	Encrypt(c, tmp, password, size - 1);
	FreeCrypt(c);

	b = NewBuf();
	WriteBuf(b, tmp, size - 1);
	SeekBuf(b, 0, 0);
	Free(tmp);

	return b;
}

// Write the account data
void CiWriteAccountData(FOLDER *f, ACCOUNT *a)
{
	// Validate arguments
	if (f == NULL || a == NULL)
	{
		return;
	}

	// Client Option
	CiWriteClientOption(CfgCreateFolder(f, "ClientOption"), a->ClientOption);

	// Client authentication data
	CiWriteClientAuth(CfgCreateFolder(f, "ClientAuth"), a->ClientAuth);

	// Startup account
	CfgAddBool(f, "StartupAccount", a->StartupAccount);

	// Server certificate check flag
	CfgAddBool(f, "CheckServerCert", a->CheckServerCert);

	// Retry on invalid server certificate flag
	CfgAddBool(f, "RetryOnServerCert", a->RetryOnServerCert);

	// Date and time
	CfgAddInt64(f, "CreateDateTime", a->CreateDateTime);
	CfgAddInt64(f, "UpdateDateTime", a->UpdateDateTime);
	CfgAddInt64(f, "LastConnectDateTime", a->LastConnectDateTime);

	// Server certificate body
	if (a->ServerCert != NULL)
	{
		BUF *b = XToBuf(a->ServerCert, false);
		if (b != NULL)
		{
			CfgAddBuf(f, "ServerCert", b);
			FreeBuf(b);
		}
	}

	// Shortcut Key
	if (IsZero(a->ShortcutKey, SHA1_SIZE) == false)
	{
		char tmp[64];
		BinToStr(tmp, sizeof(tmp), a->ShortcutKey, SHA1_SIZE);
		CfgAddStr(f, "ShortcutKey", tmp);
	}
}

// Write the account database
void CiWriteAccountDatabase(CLIENT *c, FOLDER *f)
{
	char name[MAX_SIZE];
	// Validate arguments
	if (c == NULL || f == NULL)
	{
		return;
	}

	LockList(c->AccountList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(c->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(c->AccountList, i);

			{
				Format(name, sizeof(name), "Account%u", i);
				Lock(a->lock);
				{
					CiWriteAccountData(CfgCreateFolder(f, name), a);
				}
				Unlock(a->lock);
			}
		}
	}
	UnlockList(c->AccountList);
}

// Write the CA certificate
void CiWriteCACert(CLIENT *c, FOLDER *f, X *x)
{
	BUF *b;
	// Validate arguments
	if (c == NULL || f == NULL || x == NULL)
	{
		return;
	}

	b = XToBuf(x, false);
	CfgAddBuf(f, "X509", b);
	FreeBuf(b);
}

// Write a VLAN
void CiWriteVLan(CLIENT *c, FOLDER *f, UNIX_VLAN *v)
{
	char tmp[MAX_SIZE];
	// Validate arguments
	if (c == NULL || f == NULL || v == NULL)
	{
		return;
	}

	MacToStr(tmp, sizeof(tmp), v->MacAddress);
	CfgAddStr(f, "MacAddress", tmp);
	CfgAddBool(f, "Enabled", v->Enabled);
}

// Write a VLAN list
void CiWriteVLanList(CLIENT *c, FOLDER *f)
{
	// Validate arguments
	if (c == NULL || f == NULL)
	{
		return;
	}

	LockList(c->UnixVLanList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(c->UnixVLanList);i++)
		{
			UNIX_VLAN *v = LIST_DATA(c->UnixVLanList, i);
			CiWriteVLan(c, CfgCreateFolder(f, v->Name), v);
		}
	}
	UnlockList(c->UnixVLanList);
}

// Write the CA list
void CiWriteCAList(CLIENT *c, FOLDER *f)
{
	CEDAR *cedar;
	// Validate arguments
	if (c == NULL || f == NULL)
	{
		return;
	}

	cedar = c->Cedar;

	LockList(cedar->CaList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(cedar->CaList);i++)
		{
			char tmp[MAX_SIZE];
			X *x = LIST_DATA(cedar->CaList, i);
			Format(tmp, sizeof(tmp), "Certificate%u", i);
			CiWriteCACert(c, CfgCreateFolder(f, tmp), x);
		}
	}
	UnlockList(cedar->CaList);
}

// Write the current settings to ROOT
void CiWriteSettingToCfg(CLIENT *c, FOLDER *root)
{
	FOLDER *cc;
	FOLDER *account_database;
	FOLDER *ca;
	FOLDER *vlan;
	FOLDER *cmsetting;
	FOLDER *proxy;
	// Validate arguments
	if (c == NULL || root == NULL)
	{
		return;
	}

	cmsetting = CfgCreateFolder(root, "ClientManagerSetting");

	// CLIENT_CONFIG
	cc = CfgCreateFolder(root, "Config");
	CiWriteClientConfig(cc, &c->Config);


	// Eraser
	CfgAddInt64(cc, "AutoDeleteCheckDiskFreeSpaceMin", c->Eraser->MinFreeSpace);

	// Account Database
	account_database = CfgCreateFolder(root, "AccountDatabase");
	CiWriteAccountDatabase(c, account_database);

	// Proxy
	proxy = CfgCreateFolder(root, "CommonProxySetting");
	if (proxy != NULL)
	{
		INTERNET_SETTING *t = &c->CommonProxySetting;
		BUF *pw;

		CfgAddInt(proxy, "ProxyType", t->ProxyType);
		CfgAddStr(proxy, "ProxyHostName", t->ProxyHostName);
		CfgAddInt(proxy, "ProxyPort", t->ProxyPort);
		CfgAddStr(proxy, "ProxyUsername", t->ProxyUsername);

		if (IsEmptyStr(t->ProxyPassword) == false)
		{
			pw = EncryptPassword(t->ProxyPassword);

			CfgAddBuf(proxy, "ProxyPassword", pw);

			FreeBuf(pw);
		}

		CfgAddStr(proxy, "CustomHttpHeader", t->CustomHttpHeader);
	}

	// CA
	ca = CfgCreateFolder(root, "RootCA");
	CiWriteCAList(c, ca);

	// VLAN
	if (OS_IS_UNIX(GetOsInfo()->OsType)
#ifdef	NO_VLAN
	    && GetOsInfo()->OsType != OSTYPE_MACOS_X
#endif	// NO_VLAN
	    )
	{
		vlan = CfgCreateFolder(root, "UnixVLan");
		CiWriteVLanList(c, vlan);
	}

	// Password
	CfgAddByte(root, "EncryptedPassword", c->EncryptedPassword, SHA1_SIZE);
	CfgAddBool(root, "PasswordRemoteOnly", c->PasswordRemoteOnly);

	// UseSecureDeviceId
	CfgAddInt(root, "UseSecureDeviceId", c->UseSecureDeviceId);

	// DontSavePassword
	CfgAddBool(root, "DontSavePassword", c->DontSavePassword);

	// UserAgent
	if (c->Cedar != NULL)
	{
		CfgAddStr(root, "UserAgent", c->Cedar->HttpUserAgent);
	}

	if (cmsetting != NULL)
	{
		CM_SETTING *s = c->CmSetting;

		CfgAddBool(cmsetting, "EasyMode", s->EasyMode);
		CfgAddBool(cmsetting, "LockMode", s->LockMode);

		if (IsZero(s->HashedPassword, sizeof(s->HashedPassword)) == false)
		{
			CfgAddByte(cmsetting, "HashedPassword", s->HashedPassword, sizeof(s->HashedPassword));
		}
	}
}

// Apply settings of Inner VPN Server
void CiApplyInnerVPNServerConfig(CLIENT *c)
{
}

// Write to the configuration file
void CiSaveConfigurationFile(CLIENT *c)
{
	FOLDER *root;
	// Validate arguments
	if (c == NULL)
	{
		return;
	}
	
	// Do not save the configuration file
	if(c->NoSaveConfig)
	{
		return;
	}

	root = CfgCreateFolder(NULL, TAG_ROOT);
	CiWriteSettingToCfg(c, root);

	SaveCfgRw(c->CfgRw, root);

	CfgDeleteFolder(root);
}

// Set the CM_SETTING
bool CtSetCmSetting(CLIENT *c, CM_SETTING *s)
{
	// Validate arguments
	if (c == NULL || s == NULL)
	{
		return false;
	}

	Copy(c->CmSetting, s, sizeof(CM_SETTING));

	CiSaveConfigurationFile(c);

	return true;
}

// Get the CM_SETTING
bool CtGetCmSetting(CLIENT *c, CM_SETTING *s)
{
	// Validate arguments
	if (c == NULL || s == NULL)
	{
		return false;
	}

	Copy(s, c->CmSetting, sizeof(CM_SETTING));
	
	return true;
}

// Get the client version
bool CtGetClientVersion(CLIENT *c, RPC_CLIENT_VERSION *ver)
{
	// Validate arguments
	if (ver == NULL)
	{
		return false;
	}

	Zero(ver, sizeof(RPC_CLIENT_VERSION));
	StrCpy(ver->ClientProductName, sizeof(ver->ClientProductName), CEDAR_CLIENT_STR);
	StrCpy(ver->ClientVersionString, sizeof(ver->ClientVersionString), c->Cedar->VerString);
	StrCpy(ver->ClientBuildInfoString, sizeof(ver->ClientBuildInfoString), c->Cedar->BuildInfo);
	ver->ClientVerInt = c->Cedar->Version;
	ver->ClientBuildInt = c->Cedar->Build;


#ifdef	OS_WIN32
	ver->ProcessId = MsGetProcessId();
	ver->IsVLanNameRegulated = MsIsInfCatalogRequired();

#endif	// OS_WIN32

	ver->OsType = GetOsInfo()->OsType;

	return true;
}

// Creating a Client object
CLIENT *CiNewClient()
{
	CLIENT *c = ZeroMalloc(sizeof(CLIENT));

//	StartCedarLog();

	if (ci_active_sessions_lock == NULL)
	{
		ci_active_sessions_lock = NewLock();
		ci_num_active_sessions = 0;
	}

#ifdef	OS_WIN32
	if (MsIsWindows7())
	{
		c->MsSuspendHandler = MsNewSuspendHandler();
	}
#endif	// OS_WIN32


	c->CmSetting = ZeroMalloc(sizeof(CM_SETTING));

	c->SockList = NewSockList();

	c->lock = NewLock();
	c->lockForConnect = NewLock();
	c->ref = NewRef();

	c->Cedar = NewCedar(NULL, NULL);

	c->Cedar->Client = c;

	c->NotifyCancelList = NewList(NULL);

	Sha0(c->EncryptedPassword, "", 0);

#ifdef	OS_WIN32
	c->GlobalPulse = MsOpenOrCreateGlobalPulse(CLIENT_GLOBAL_PULSE_NAME);
#endif	// OS_WIN32

	if (c->GlobalPulse != NULL)
	{
		c->PulseRecvThread = NewThread(CiPulseRecvThread, c);
	}

	CiLoadIniSettings(c);

	// Log Settings
	if(c->NoSaveLog == false)
	{
		MakeDir(CLIENT_LOG_DIR_NAME);
		c->Logger = NewLog(CLIENT_LOG_DIR_NAME, CLIENT_LOG_PREFIX, LOG_SWITCH_DAY);
	}

	CLog(c, "L_LINE");
	CLog(c, "LC_START_2", CEDAR_CLIENT_STR, c->Cedar->VerString);
	CLog(c, "LC_START_3", c->Cedar->BuildInfo);
	CLog(c, "LC_START_1");

#ifdef	OS_WIN32
	{
		// Initialize the Win32 UI
		wchar_t tmp[MAX_SIZE];
		StrToUni(tmp, sizeof(tmp), CEDAR_CLIENT_STR);

		InitWinUi(tmp, _SS("DEFAULT_FONT"), _II("DEFAULT_FONT_SIZE"));
	}
#endif	// OS_WIN32

	// Initialize the settings
	CiInitConfiguration(c);

	// Raise the priority
	OSSetHighPriority();



#ifdef	OS_WIN32
	// For Win9x, release the DHCP address of all the virtual LAN card
	if (MsIsNt() == false)
	{
		Win32ReleaseAllDhcp9x(true);
	}
#endif	// OS_WIN32

	CiChangeAllVLanMacAddressIfMachineChanged(c);

	CiChangeAllVLanMacAddressIfCleared(c);

	// Initialize the internal VPN server
	CiApplyInnerVPNServerConfig(c);

	return c;
}

// Send a global pulse
void CiSendGlobalPulse(CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

#ifdef	OS_WIN32
	MsSendGlobalPulse(c->GlobalPulse);
#endif	// OS_WIN32
}

// Pulse reception thread
void CiPulseRecvThread(THREAD *thread, void *param)
{
#ifdef	OS_WIN32
	CLIENT *c = (CLIENT *)param;

	if (c == NULL)
	{
		return;
	}

	while (true)
	{
		if (c->HaltPulseThread)
		{
			break;
		}

		MsWaitForGlobalPulse(c->GlobalPulse, INFINITE);

		if (c->HaltPulseThread)
		{
			break;
		}

		CiNotifyInternal(c);
	}
#endif	// OS_WIN32
}

// Clean-up the client
void CiCleanupClient(CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}


	// Release the settings
	CiFreeConfiguration(c);

#ifdef	OS_WIN32
	// Release the Win32 UI
	FreeWinUi();
#endif	// OS_WIN32

	CLog(c, "LC_END");
	CLog(c, "L_LINE");
	FreeEraser(c->Eraser);
	FreeLog(c->Logger);
	c->Logger = NULL;


	ReleaseCedar(c->Cedar);

	DeleteLock(c->lockForConnect);
	DeleteLock(c->lock);

	c->HaltPulseThread = true;

	if (c->GlobalPulse != NULL)
	{
#ifdef	OS_WIN32
		MsSendGlobalPulse(c->GlobalPulse);
#endif	// OS_WIN32
	}

	if (c->PulseRecvThread != NULL)
	{
		WaitThread(c->PulseRecvThread, INFINITE);
		ReleaseThread(c->PulseRecvThread);
	}

	if (c->GlobalPulse != NULL)
	{
#ifdef	OS_WIN32
		MsCloseGlobalPulse(c->GlobalPulse);
#endif	// OS_WIN32
	}

	ReleaseList(c->NotifyCancelList);

	FreeSockList(c->SockList);

	Free(c->CmSetting);


#ifdef	OS_WIN32
	if (c->MsSuspendHandler != NULL)
	{
		MsFreeSuspendHandler(c->MsSuspendHandler);
	}
#endif	// OS_WIN32

	Free(c);

#ifdef	OS_WIN32
	// For Win9x, release the DHCP address of all the virtual LAN card
	if (MsIsNt() == false)
	{
		Win32ReleaseAllDhcp9x(true);
	}
#endif	// OS_WIN32

	StopCedarLog();

	if (ci_active_sessions_lock != NULL)
	{
		DeleteLock(ci_active_sessions_lock);
		ci_active_sessions_lock = NULL;

		ci_num_active_sessions = 0;
	}
}

// Increment of the number of active sessions
void CiIncrementNumActiveSessions()
{
	Lock(ci_active_sessions_lock);
	{
		ci_num_active_sessions++;
	}
	Unlock(ci_active_sessions_lock);
}

// Decrement of the number of active sessions
void CiDecrementNumActiveSessions()
{
	Lock(ci_active_sessions_lock);
	{
		if (ci_num_active_sessions >= 1)
		{
			ci_num_active_sessions--;
		}
	}
	Unlock(ci_active_sessions_lock);
}

// Release the client
void CtReleaseClient(CLIENT *c)
{
	// Validate arguments
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		CiCleanupClient(c);
	}
}

// Start the operation of the client program
void CtStartClient()
{
	UINT i;
	LIST *o;
	if (client != NULL)
	{
		// It is already in running
		return;
	}

	// OS check
	CiCheckOs();

#ifdef	OS_WIN32
	RegistWindowsFirewallAll();
#endif

	// Creating a client
	client = CiNewClient();

	// Start the Keep
	CiInitKeep(client);

	// Start the RPC server
	CiStartRpcServer(client);

	// Start the Saver
	CiInitSaver(client);

	// Start the startup connection
	o = NewListFast(NULL);
	LockList(client->AccountList);
	{
		for (i = 0;i < LIST_NUM(client->AccountList);i++)
		{
			ACCOUNT *a = LIST_DATA(client->AccountList, i);
			Lock(a->lock);
			{
				if (a->StartupAccount)
				{
					Add(o, CopyUniStr(a->ClientOption->AccountName));
				}
			}
			Unlock(a->lock);
		}
	}
	UnlockList(client->AccountList);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		wchar_t *s = LIST_DATA(o, i);
		RPC_CLIENT_CONNECT c;
		Zero(&c, sizeof(c));
		UniStrCpy(c.AccountName, sizeof(c.AccountName), s);
		CtConnect(client, &c);
		Free(s);
	}
	ReleaseList(o);
}

// Stop the operation of the client program
void CtStopClient()
{
	UINT i, num;
	ACCOUNT **account_list;
	if (client == NULL)
	{
		// It is not running yet
		return;
	}

	// Halting flag
	client->Halt = true;

	// Disconnect all the RPC
	CiStopRpcServer(client);

	// Exit the client notification service
	CncExit();

	// Exit the Keep
	CiFreeKeep(client);

	// Disconnect all accounts connected
	LockList(client->AccountList);
	{
		num = LIST_NUM(client->AccountList);
		account_list = ToArray(client->AccountList);
	}
	UnlockList(client->AccountList);

	for (i = 0;i < num;i++)
	{
		ACCOUNT *a = account_list[i];
		SESSION *s = NULL;

		Lock(a->lock);
		{
			if (a->ClientSession != NULL)
			{
				s = a->ClientSession;
				AddRef(s->ref);
			}
		}
		Unlock(a->lock);

		if (s != NULL)
		{
			StopSession(s);
			ReleaseSession(s);
			Lock(a->lock);
			{
				if (a->ClientSession != NULL)
				{
					ReleaseSession(a->ClientSession);
					a->ClientSession = NULL;
				}
			}
			Unlock(a->lock);
		}
	}

	Free(account_list);

	// Stop the Saver
	CiFreeSaver(client);

	// Release the client
	CtReleaseClient(client);
	client = NULL;
}

// OS check
void CiCheckOs()
{
	// Get the OS type
	OS_INFO *info = GetOsInfo();

	if (OS_IS_WINDOWS(info->OsType))
	{
		bool ok = IS_CLIENT_SUPPORTED_OS(info->OsType);

		if (ok == false)
		{
			Alert(
				CEDAR_PRODUCT_STR " VPN Client doesn't support this Windows Operating System.\n"
				CEDAR_PRODUCT_STR " VPN Client requires Windows 98, Windows Me, Windows 2000, Windows XP, Windows Server 2003 or Greater.\n\n"
				"Please contact your system administrator.", CEDAR_PRODUCT_STR " VPN Client");
			exit(0);
		}
	}
}

// Client status indicator
void CiClientStatusPrinter(SESSION *s, wchar_t *status)
{
#ifdef	OS_WIN32
	ACCOUNT *a;
	// Validate arguments
	if (s == NULL || status == NULL)
	{
		return;
	}

	a = s->Account;
	if (a == NULL)
	{
		return;
	}

	if (UniStrCmpi(status, L"init") == 0)
	{
		if (a->StatusWindow == NULL && s->Win32HideConnectWindow == false)
		{
			a->StatusWindow = CncStatusPrinterWindowStart(s);
		}
	}
	else if (UniStrCmpi(status, L"free") == 0)
	{
		if (a->StatusWindow != NULL)
		{
			CncStatusPrinterWindowStop(a->StatusWindow);
			a->StatusWindow = NULL;
		}
	}
	else
	{
		if (a->StatusWindow != NULL)
		{
			CncStatusPrinterWindowPrint(a->StatusWindow, status);
		}
	}
#else	// OS_WIN32
	UniPrint(L"Status: %s\n", status);
#endif	// OS_WIN32
}


