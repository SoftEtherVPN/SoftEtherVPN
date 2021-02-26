// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Logging.h
// Header of Logging.c

#ifndef	LOGGING_H
#define	LOGGING_H


// Port number for HTTP monitoring
#define	LOG_HTTP_PORT						80


#define	MAX_LOG_SIZE_DEFAULT				1073741823ULL

typedef char *(RECORD_PARSE_PROC)(RECORD *rec);

// Packet log structure
struct PACKET_LOG
{
	CEDAR *Cedar;
	struct PKT *Packet;
	char *SrcSessionName;
	char *DestSessionName;
	bool WritePhysicalIP;
	char SrcPhysicalIP[64];
	char DestPhysicalIP[64];
	bool PurePacket;						// Packet not cloned
	bool PurePacketNoPayload;				// Packet not cloned (without payload)
	SESSION *SrcSession;
	bool NoLog;								// Not to write a log
};

// Log save options of the HUB
struct HUB_LOG
{
	bool SaveSecurityLog;					// To save the security log
	UINT SecurityLogSwitchType;				// Switching type of security log
	bool SavePacketLog;						// To save the packet log
	UINT PacketLogSwitchType;				// Switching type of packet log
	UINT PacketLogConfig[NUM_PACKET_LOG];	// Packet log settings
};

// Record
struct RECORD
{
	UINT64 Tick;							// Time
	RECORD_PARSE_PROC *ParseProc;			// Parsing procedure
	void *Data;								// Data
};

// LOG object
struct LOG
{
	LOCK *lock;								// Lock
	THREAD *Thread;							// Thread
	char *DirName;							// Destination directory name
	char *Prefix;							// File name
	UINT SwitchType;						// Switching type of log file
	QUEUE *RecordQueue;						// Record queue
	volatile bool Halt;						// Halting flag
	EVENT *Event;							// Event for Log
	EVENT *FlushEvent;						// Flash completion event
	bool CacheFlag;
	UINT64 LastTick;
	UINT LastSwitchType;
	char LastStr[MAX_SIZE];
	UINT64 CurrentFilePointer;				// The current file pointer
	UINT CurrentLogNumber;					// Log file number of the current
	bool log_number_incremented;
};


// ERASER object
struct ERASER
{
	LOG *Log;								// Logger
	UINT64 MinFreeSpace;					// Disk space to start deleting files
	char *DirName;							// Directory name
	volatile bool Halt;						// Halting flag
	THREAD *Thread;							// Thread
	bool LastFailed;						// Whether deletion of the file failed at the end
	EVENT *HaltEvent;						// Halting event
};

// List of files that can be deleted
typedef struct ERASE_FILE
{
	char *FullPath;							// Full path
	UINT64 UpdateTime;						// Updating date
} ERASE_FILE;

// SYSLOG object
struct SLOG
{
	LOCK *lock;								// Lock
	SOCK *Udp;								// UDP socket
	IP DestIp;								// Destination IP address
	UINT DestPort;							// Destination port number
	char HostName[MAX_HOST_NAME_LEN + 1];	// Host name
	UINT64 NextPollIp;						// Time of examination of the IP address at the end
};

// Function prototype
LOG *NewLog(char *dir, char *prefix, UINT switch_type);
void FreeLog(LOG *g);
void LogThread(THREAD *thread, void *param);
void WaitLogFlush(LOG *g);
void LockLog(LOG *g);
void UnlockLog(LOG *g);
void InsertRecord(LOG *g, void *data, RECORD_PARSE_PROC *proc);
void InsertStringRecord(LOG *g, char *str);
void InsertUnicodeRecord(LOG *g, wchar_t *unistr);
char *StringRecordParseProc(RECORD *rec);
bool MakeLogFileName(LOG *g, char *name, UINT size, char *dir, char *prefix, UINT64 tick, UINT switch_type, UINT num, char *old_datestr);
void MakeLogFileNameStringFromTick(LOG *g, char *str, UINT size, UINT64 tick, UINT switch_type);
void WriteRecordToBuffer(BUF *b, RECORD *r);
void SetLogSwitchType(LOG *g, UINT switch_type);
bool PacketLog(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *packet, UINT64 now);
char *PacketLogParseProc(RECORD *rec);
UINT CalcPacketLoggingLevel(HUB *hub, PKT *packet);
UINT CalcPacketLoggingLevelEx(HUB_LOG *g, PKT *packet);
char *GenCsvLine(TOKEN_LIST *t);
void ReplaceForCsv(char *str);
char *PortStr(CEDAR *cedar, UINT port, bool udp);
char *TcpFlagStr(UCHAR flag);
void SiSetDefaultLogSetting(HUB_LOG *g);
void DebugLog(CEDAR *c, char *fmt, ...);
void SLog(CEDAR *c, char *name, ...);
void WriteHubLog(HUB *h, wchar_t *str);
void HLog(HUB *h, char *name, ...);
void NLog(VH *v, char *name, ...);
void PPPLog(PPP_SESSION *p, char *name, ...);
void IPsecLog(IKE_SERVER *ike, IKE_CLIENT *c, IKE_SA *ike_sa, IPSECSA *ipsec_sa, char *name, ...);
void EtherIPLog(ETHERIP_SERVER *s, char *name, ...);
void WriteServerLog(CEDAR *c, wchar_t *str);
void ALog(ADMIN *a, HUB *h, char *name, ...);
void CLog(CLIENT *c, char *name, ...);
void WriteClientLog(CLIENT *c, wchar_t *str);
ERASER *NewEraser(LOG *log, UINT64 min_size);
void FreeEraser(ERASER *e);
void ELog(ERASER *e, char *name, ...);
void EraserThread(THREAD *t, void *p);
void EraserMain(ERASER *e);
bool CheckEraserDiskFreeSpace(ERASER *e);
int CompareEraseFile(void *p1, void *p2);
LIST *GenerateEraseFileList(ERASER *e);
void FreeEraseFileList(LIST *o);
void EnumEraseFile(LIST *o, char *dirname);
SLOG *NewSysLog(char *hostname, UINT port, IP *ip);
void SetSysLog(SLOG *g, char *hostname, UINT port);
void FreeSysLog(SLOG *g);
void SendSysLog(SLOG *g, wchar_t *str);
char *BuildHttpLogStr(HTTPLOG *h);
void MakeSafeLogStr(char *str);
void AddLogBufToStr(BUF *b, char *name, char *value);
void SetEraserCheckInterval(UINT interval);
UINT GetEraserCheckInterval();
void SetMaxLogSize(UINT64 size);
UINT64 GetMaxLogSize();

#endif	// LOGGING_G

