// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Command.h
// Header of Command.c

#ifndef	COMMAND_H
#define	COMMAND_H

// Constants
#define	TRAFFIC_DEFAULT_PORT		9821
#define	TRAFFIC_NUMTCP_MAX			32
#define	TRAFFIC_NUMTCP_DEFAULT		32
#define	TRAFFIC_SPAN_DEFAULT		15
#define	TRAFFIC_TYPE_DOWNLOAD		1
#define	TRAFFIC_TYPE_UPLOAD			2
#define	TRAFFIC_TYPE_FULL			0
#define	TRAFFIC_BUF_SIZE			65535
#define	TRAFFIC_VER_STR_SIZE		16
#define	TRAFFIC_VER_STR				"TrafficServer\r\n"

// Constants for Win32
#define	VPNCMD_BOOTSTRAP_REG_KEYNAME	"Software\\" GC_REG_COMPANY_NAME "\\VPN Command Line Utility"
#define	VPNCMD_BOOTSTRAP_REG_VALUENAME_VER	"InstalledVersion"
#define	VPNCMD_BOOTSTRAP_REG_VALUENAME_PATH	"InstalledPath"
#define	VPNCMD_BOOTSTRAP_FILENAME		"|vpncmdsys.exe"


// Traffic test results
struct TT_RESULT
{
	bool Raw;					// Whether raw data
	bool Double;				// Whether it is doubled
	UINT64 NumBytesUpload;		// Uploaded size
	UINT64 NumBytesDownload;	// Downloaded size
	UINT64 NumBytesTotal;		// Total size
	UINT64 Span;				// Period (in milliseconds)
	UINT64 BpsUpload;			// Upload throughput
	UINT64 BpsDownload;			// Download throughput
	UINT64 BpsTotal;			// Total throughput
};

// Text display function
typedef void (TT_PRINT_PROC)(void *param, wchar_t *str);

// Client side socket
struct TTC_SOCK
{
	SOCK *Sock;				// Socket
	UINT State;				// State
	UINT64 NumBytes;		// Transmitted bytes
	bool Download;			// Download socket
	bool ServerUploadReportReceived;	// Complete to receive the report of upload amount from the server
	UINT64 NextSendRequestReportTick;	// Time to request a next report
	UINT Id;
	bool HideErrMsg;
};

// Traffic test Client
struct TTC
{
	TT_PRINT_PROC *Print;	// Text display function
	void *Param;			// Any parameters
	bool Double;			// Double mode
	bool Raw;				// Raw data mode
	UINT Port;				// Port number
	char Host[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT NumTcp;			// Number of TCP connections
	UINT Type;				// Type
	UINT64 Span;			// Period
	UINT64 RealSpan;		// The actual span
	THREAD *Thread;			// Thread
	volatile bool Halt;		// Halting flag
	bool *Cancel;			// Halting flag 2
	LIST *ItcSockList;		// Client socket list
	TT_RESULT Result;		// Result
	UINT ErrorCode;			// Error code
	bool AbnormalTerminated;	// Abnormal termination
	EVENT *StartEvent;		// Start event
	EVENT *InitedEvent;		// Initialize completion notification event
	LIST *WorkerThreadList;	// List of worker threads

	UINT flag1, flag2;

	UINT64 session_id;
	UINT64 end_tick;
	UINT64 start_tick;
};

// Traffic test worker thread
struct TTC_WORKER
{
	THREAD *WorkerThread;
	TTC *Ttc;
	LIST *SockList;			// Client socket list
	SOCK_EVENT *SockEvent;	// Socket event
	EVENT *StartEvent;		// Start event
	bool Ok;				// The result
};

// Server side socket
struct TTS_SOCK
{
	SOCK *Sock;				// Socket
	UINT State;				// State
	UINT64 NumBytes;		// Transmitted bytes
	bool SockJoined;		// Whether it has been added to the event
	UINT Id;				// ID
	UINT64 LastWaitTick;	// Retry waiting time to notify the size information to the client
	UINT64 SessionId;		// Session ID
	bool NoMoreSendData;	// Flag not to send more data
	UINT64 FirstRecvTick;	// Time which the data has been received last
	UINT64 FirstSendTick;	// Time which the data has been sent last
	UINT64 Span;			// Period
	UINT64 GiveupSpan;
	UINT64 LastCommTime;
};

// Traffic test server
struct TTS
{
	TT_PRINT_PROC *Print;	// Text display function
	void *Param;			// Any parameters
	volatile bool Halt;		// Halting flag
	UINT Port;				// Port number
	THREAD *Thread;			// Thread
	THREAD *IPv6AcceptThread;	// IPv6 Accept thread
	SOCK *ListenSocket;		// Socket to wait
	SOCK *ListenSocketV6;	// Socket to wait (IPv6)
	UINT ErrorCode;			// Error code
	UINT IdSeed;			// ID value
	LIST *WorkerList;		// Worker threads list
};

// Traffic test worker thread
struct TTS_WORKER
{
	TTS *Tts;				// TTS
	THREAD *WorkThread;		// Worker thread
	SOCK_EVENT *SockEvent;	// Socket event
	LIST *TtsSockList;		// Server socket list
	bool NewSocketArrived;	// New socket has arrived
};

// VPN Tools context
struct PT
{
	CONSOLE *Console;	// Console
	UINT LastError;		// Last error
	wchar_t *CmdLine;	// Command line to execute
};

// Server management context
struct PS
{
	bool ConsoleForServer;	// Console for the server (always true)
	CONSOLE *Console;	// Console
	RPC *Rpc;			// RPC
	char *ServerName;	// Server name
	UINT ServerPort;	// Port number
	char *HubName;		// Virtual HUB name in the currently managed
	UINT LastError;		// Last error
	char *AdminHub;		// Virtual HUB to be managed by default
	wchar_t *CmdLine;	// Command line to execute
	CAPSLIST *CapsList;	// Caps list
};

// Client management context
struct PC
{
	bool ConsoleForServer;	// Console for the server (always false)
	CONSOLE *Console;	// Console
	REMOTE_CLIENT *RemoteClient;	// Remote client
	char *ServerName;	// Server name
	UINT LastError;		// Last error
	wchar_t *CmdLine;	// Command line
};

// A column of the table
struct CTC
{
	wchar_t *String;	// String
	bool Right;			// Right justification
};

// A row of the table
struct CTR
{
	wchar_t **Strings;	// String list
};

// Table for console
struct CT
{
	LIST *Columns;		// Column list
	LIST *Rows;			// Row list
};

UINT CommandMain(wchar_t *command_line);
UINT VpnCmdProc(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
bool ParseHostPort(char *src, char **host, UINT *port, UINT default_port);
bool ParseHostPortAtmark(char *src, char **host, UINT *port, UINT default_port);
CT *CtNew();
void CtFree(CT *ct, CONSOLE *c);
void CtFreeEx(CT *ct, CONSOLE *c, bool standard_view);
void CtInsertColumn(CT *ct, wchar_t *str, bool right);
CT *CtNewStandard();
CT *CtNewStandardEx();
void CtInsert(CT *ct, ...);
void CtPrint(CT *ct, CONSOLE *c);
void CtPrintStandard(CT *ct, CONSOLE *c);
void CtPrintRow(CONSOLE *c, UINT num, UINT *widths, wchar_t **strings, bool *rights, char separate_char);
void VpnCmdInitBootPath();

void CmdPrintError(CONSOLE *c, UINT err);
void CmdPrintAbout(CONSOLE *c);
wchar_t *CmdPromptPort(CONSOLE *c, void *param);
wchar_t *CmdPromptChoosePassword(CONSOLE *c, void *param);
bool CmdEvalPort(CONSOLE *c, wchar_t *str, void *param);
void CmdInsertTrafficInfo(CT *ct, TRAFFIC *t);
wchar_t *GetHubTypeStr(UINT type);
wchar_t *GetServerTypeStr(UINT type);
char *CmdPasswordPrompt(CONSOLE *c);
bool CmdEvalIp(CONSOLE *c, wchar_t *str, void *param);
wchar_t *PsClusterSettingMemberPromptIp(CONSOLE *c, void *param);
bool CmdEvalHostAndPort(CONSOLE *c, wchar_t *str, void *param);
LIST *StrToPortList(char *str, bool limit_range);
bool CmdEvalPortList(CONSOLE *c, wchar_t *str, void *param);
wchar_t *PsClusterSettingMemberPromptPorts(CONSOLE *c, void *param);
K *CmdLoadKey(CONSOLE *c, wchar_t *filename);
bool CmdLoadCertAndKey(CONSOLE *c, X **xx, K **kk, wchar_t *cert_filename, wchar_t *key_filename);
bool CmdEvalTcpOrUdp(CONSOLE *c, wchar_t *str, void *param);
wchar_t *GetConnectionTypeStr(UINT type);
bool CmdEvalHostAndSubnetMask4(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalNetworkAndSubnetMask4(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIpAndMask4(CONSOLE *c, wchar_t *str, void *param);
bool CmdEvalIpAndMask6(CONSOLE *c, wchar_t *str, void *param);
wchar_t *GetLogSwitchStr(UINT i);
wchar_t *GetPacketLogNameStr(UINT i);
UINT StrToLogSwitchType(char *str);
UINT StrToPacketLogType(char *str);
UINT StrToPacketLogSaveInfoType(char *str);
wchar_t *GetProxyTypeStr(UINT i);
wchar_t *GetClientAuthTypeStr(UINT i);
void PrintPolicyList(CONSOLE *c, char *name);
void PrintPolicy(CONSOLE *c, POLICY *pol, bool cascade_mode);
bool EditPolicy(CONSOLE *c, POLICY *pol, char *name, char *value, bool cascade_mode);
void CmdPrintStatusToListView(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s);
void CmdPrintStatusToListViewEx(CT *ct, RPC_CLIENT_GET_CONNECTION_STATUS *s, bool server_mode);
bool CmdEvalPassOrDiscard(CONSOLE *c, wchar_t *str, void *param);
bool StrToPassOrDiscard(char *str);
bool CmdEvalProtocol(CONSOLE *c, wchar_t *str, void *param);
UINT StrToProtocol(char *str);
bool CmdEvalPortRange(CONSOLE *c, wchar_t *str, void *param);
bool ParsePortRange(char *str, UINT *start, UINT *end);
wchar_t *GetAuthTypeStr(UINT id);
UINT64 StrToDateTime64(char *str);
bool CmdEvalDateTime(CONSOLE *c, wchar_t *str, void *param);
void CmdPrintNodeInfo(CT *ct, NODE_INFO *info);
wchar_t *GetProtocolName(UINT n);
void CmdGenerateImportName(REMOTE_CLIENT *r, wchar_t *name, UINT size, wchar_t *old_name);
bool CmdIsAccountName(REMOTE_CLIENT *r, wchar_t *name);
wchar_t *GetSyslogSettingName(UINT n);


void TtPrint(void *param, TT_PRINT_PROC *print_proc, wchar_t *str);
void TtGenerateRandomData(UCHAR **buf, UINT *size);
void TtsWorkerThread(THREAD *thread, void *param);
void TtsListenThread(THREAD *thread, void *param);
void TtsAcceptProc(TTS *tts, SOCK *listen_socket);
void TtsIPv6AcceptThread(THREAD *thread, void *param);
wchar_t *GetTtcTypeStr(UINT type);
void TtcPrintSummary(TTC *ttc);
void StopTtc(TTC *ttc);
void TtcGenerateResult(TTC *ttc);
void TtcThread(THREAD *thread, void *param);
TTC *NewTtcEx(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param, EVENT *start_event, bool *cancel);
TTC *NewTtc(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param);
UINT FreeTtc(TTC *ttc, TT_RESULT *result);
TTS *NewTts(UINT port, void *param, TT_PRINT_PROC *print_proc);
UINT FreeTts(TTS *tts);
void PtTrafficPrintProc(void *param, wchar_t *str);
void TtcPrintResult(CONSOLE *c, TT_RESULT *res);


bool SystemCheck();
bool CheckKernel();
bool CheckMemory();
bool CheckStrings();
bool CheckFileSystem();
bool CheckThread();
bool CheckNetwork();
void InputToNull(void *p);
UINT RetZero();

void Win32CmdDebug(bool is_uac);


UINT PtConnect(CONSOLE *c, wchar_t *cmdline);
PT *NewPt(CONSOLE *c, wchar_t *cmdline);
void FreePt(PT *pt);
void PtMain(PT *pt);
UINT PtMakeCert(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PtMakeCert2048(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PtTrafficClient(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PtTrafficServer(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PtCheck(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);


UINT PcConnect(CONSOLE *c, char *target, wchar_t *cmdline, char *password);
PC *NewPc(CONSOLE *c, REMOTE_CLIENT *remote_client, char *servername, wchar_t *cmdline);
void FreePc(PC *pc);
void PcMain(PC *pc);
UINT PcAbout(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcVersionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcPasswordGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcSecureList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcSecureSelect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcSecureGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicUpgrade(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicGetSetting(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicSetSetting(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcNicList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountHttpHeaderAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountHttpHeaderDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountHttpHeaderGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountProxySocks5(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountRetryOnServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountRetryOnServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountConnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountNicSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStatusShow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStatusHide(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountSecureCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountRetrySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStartupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountStartupRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountExport(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcAccountImport(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcRemoteEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcRemoteDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PcKeepGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);


PS *NewPs(CONSOLE *c, RPC *rpc, char *servername, UINT serverport, char *hubname, char *adminhub, wchar_t *cmdline);
void FreePs(PS *ps);
UINT PsConnect(CONSOLE *c, char *host, UINT port, char *hub, char *adminhub, wchar_t *cmdline, char *password);
void PsMain(PS *ps);
UINT PsAbout(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsListenerDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsPortsUDPSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsPortsUDPGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsProtoOptionsSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsProtoOptionsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingStandalone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingController(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterSettingMember(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterMemberList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterMemberInfoGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterMemberCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsClusterConnectionStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrash(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsFlush(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDebug(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerKeyGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCipherGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCipherSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsKeepGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSyslogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSyslogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSyslogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConnectionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConnectionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConnectionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeDeviceList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsBridgeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCaps(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsReboot(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConfigGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsConfigSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterStart(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterStop(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterIfList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterIfAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterIfDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterTableList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterTableAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRouterTableDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogFileList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogFileGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubCreateDynamic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubCreateStatic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubSetStatic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubSetDynamic(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHubList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsHub(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetMaxSession(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetHubPassword(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetEnumAllow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSetEnumDeny(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOptionsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRadiusServerSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRadiusServerDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsRadiusServerGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogSwitchSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLogPacketSaveType(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCAList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCAAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCADelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCAGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadePasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeHttpHeaderAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeHttpHeaderDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeHttpHeaderGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeProxySocks5(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadePolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadePolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsPolicyList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeRename(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCascadeOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAddEx(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessAddEx6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAccessDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserSignedSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserRadiusSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserNTLMSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsUserExpiresSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupJoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupUnjoin(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupPolicyRemove(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsGroupPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSessionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsMacTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsMacDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIpDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatHostGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsSecureNatHostSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsNatTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDhcpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAdminOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAdminOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsExtOptionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsExtOptionSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsCrlGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsAcDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsLicenseStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIPsecEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsIPsecGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsEtherIpClientAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsEtherIpClientDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsEtherIpClientList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsOpenVpnMakeConfig(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsServerCertRegenerate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsVpnOverIcmpDnsEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsVpnOverIcmpDnsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDynamicDnsGetStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsDynamicDnsSetHostname(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsVpnAzureSetEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
UINT PsVpnAzureGetStatus(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);


#endif	// COMMAND_H


