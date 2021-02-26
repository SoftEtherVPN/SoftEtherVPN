// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// BridgeWin32.h
// Header of BridgeWin32.c

#ifndef	BRIDGEWIN32_H
#define	BRIDGEWIN32_H

#define	BRIDGE_WIN32_PACKET_DLL		"Packet.dll"
#define	BRIDGE_WIN32_PCD_DLL		"|see.dll"
#define	BRIDGE_WIN32_PCD_SYS		"|DriverPackages\\See\\x86\\See_x86.sys"
#define	BRIDGE_WIN32_PCD_DLL_X64	"|see_x64.dll"
#define	BRIDGE_WIN32_PCD_SYS_X64	"|DriverPackages\\See\\x64\\See_x64.sys"
#define	BRIDGE_WIN32_PCD_REGKEY		"SYSTEM\\CurrentControlSet\\services\\SEE"
#define	BRIDGE_WIN32_PCD_BUILDVALUE	"CurrentInstalledBuild"

#define	BRIDGE_WIN32_ETH_BUFFER		(1048576)


typedef void *HANDLE;

#ifdef	BRIDGE_C

// Header for Internal function (for BridgeWin32.c)
typedef struct WP
{
	bool Inited;
	HINSTANCE hPacketDll;
	PCHAR (*PacketGetVersion)();
	PCHAR (*PacketGetDriverVersion)();
	BOOLEAN (*PacketSetMinToCopy)(LPADAPTER AdapterObject,int nbytes);
	BOOLEAN (*PacketSetNumWrites)(LPADAPTER AdapterObject,int nwrites);
	BOOLEAN (*PacketSetMode)(LPADAPTER AdapterObject,int mode);
	BOOLEAN (*PacketSetReadTimeout)(LPADAPTER AdapterObject,int timeout);
	BOOLEAN (*PacketSetBpf)(LPADAPTER AdapterObject,struct bpf_program *fp);
	INT (*PacketSetSnapLen)(LPADAPTER AdapterObject,int snaplen);
	BOOLEAN (*PacketGetStats)(LPADAPTER AdapterObject,struct bpf_stat *s);
	BOOLEAN (*PacketGetStatsEx)(LPADAPTER AdapterObject,struct bpf_stat *s);
	BOOLEAN (*PacketSetBuff)(LPADAPTER AdapterObject,int dim);
	BOOLEAN (*PacketGetNetType)(LPADAPTER AdapterObject,NetType *type);
	LPADAPTER (*PacketOpenAdapter)(PCHAR AdapterName);
	BOOLEAN (*PacketSendPacket)(LPADAPTER AdapterObject,LPPACKET pPacket,BOOLEAN Sync);
	INT (*PacketSendPackets)(LPADAPTER AdapterObject,PVOID PacketBuff,ULONG Size, BOOLEAN Sync);
	LPPACKET (*PacketAllocatePacket)(void);
	VOID (*PacketInitPacket)(LPPACKET lpPacket,PVOID  Buffer,UINT  Length);
	VOID (*PacketFreePacket)(LPPACKET lpPacket);
	BOOLEAN (*PacketReceivePacket)(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync);
	BOOLEAN (*PacketSetHwFilter)(LPADAPTER AdapterObject,ULONG Filter);
	BOOLEAN (*PacketGetAdapterNames)(PTSTR pStr,PULONG  BufferSize);
	BOOLEAN (*PacketGetNetInfoEx)(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries);
	BOOLEAN (*PacketRequest)(LPADAPTER  AdapterObject,BOOLEAN Set,PPACKET_OID_DATA  OidData);
	HANDLE (*PacketGetReadEvent)(LPADAPTER AdapterObject);
	BOOLEAN (*PacketSetDumpName)(LPADAPTER AdapterObject, void *name, int len);
	BOOLEAN (*PacketSetDumpLimits)(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks);
	BOOLEAN (*PacketIsDumpEnded)(LPADAPTER AdapterObject, BOOLEAN sync);
	BOOL (*PacketStopDriver)();
	VOID (*PacketCloseAdapter)(LPADAPTER lpAdapter);
	BOOLEAN (*PacketSetLoopbackBehavior)(LPADAPTER AdapterObject, UINT LoopbackBehavior);
} WP;

// Adapter list
typedef struct WP_ADAPTER
{
	char Name[MAX_SIZE];
	char Title[MAX_SIZE];
	char Guid[MAX_SIZE];
	UINT Id;
} WP_ADAPTER;

// Internal function prototype
void InitEthAdaptersList();
void FreeEthAdaptersList();
int CompareWpAdapter(void *p1, void *p2);
LIST *GetEthAdapterList();
LIST *GetEthAdapterListInternal();
bool InitWpWithLoadLibrary(WP *wp, HINSTANCE h);
bool IsPcdSupported();
HINSTANCE InstallPcdDriver();
HINSTANCE InstallPcdDriverInternal();
UINT LoadPcdDriverBuild();
void SavePcdDriverBuild(UINT build);

#endif	// BRIDGE_C

typedef struct _ADAPTER ADAPTER;
typedef struct _PACKET PACKET;

// ETH structure
struct ETH
{
	char *Name;					// Adapter name
	char *Title;				// Adapter title
	ADAPTER *Adapter;			// Adapter
	CANCEL *Cancel;				// Cancel object
	UCHAR *Buffer;				// Buffer
	UINT BufferSize;			// Buffer size
	PACKET *Packet;				// Packet
	PACKET *PutPacket;			// Write packet
	QUEUE *PacketQueue;			// Packet queue
	UINT64 LastSetSingleCpu;	// Date and time set to a single CPU to last
	bool LoopbackBlock;			// Whether to block the loop back packet
	bool Empty;					// It is empty
	UCHAR MacAddress[6];		// MAC address
	bool HasFatalError;			// A fatal error occurred on the transmission side

	SU *Su;						// SeLow handle
	SU_ADAPTER *SuAdapter;		// SeLow adapter handle

	// Unused
	bool IsRawIpMode;			// RAW IP mode
	UCHAR RawIpMyMacAddr[6];
	UCHAR RawIpYourMacAddr[6];
	IP MyPhysicalIPForce;
};

// Function prototype
void InitEth();
void FreeEth();
bool IsEthSupported();
bool IsEthSupportedInner();
TOKEN_LIST *GetEthList();
TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden, bool enum_normal, bool enum_rawip);
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthInternal(char *name, bool local, bool tapmode, char *tapaddr);
void CloseEth(ETH *e);
CANCEL *EthGetCancel(ETH *e);
UINT EthGetPacket(ETH *e, void **data);
void EthPutPacket(ETH *e, void *data, UINT size);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
void GetEthNetworkConnectionName(wchar_t *dst, UINT size, char *device_name);
bool IsWin32BridgeWithSee();
UINT EthGetMtu(ETH *e);
bool EthSetMtu(ETH *e, UINT mtu);
bool EthIsChangeMtuSupported(ETH *e);

bool Win32EthIsSuSupported();

void Win32EthSetShowAllIf(bool b);
bool Win32EthGetShowAllIf();

bool EnumEthVLanWin32(RPC_ENUM_ETH_VLAN *t);
bool GetClassRegKeyWin32(char *key, UINT key_size, char *short_key, UINT short_key_size, char *guid);
int CmpRpcEnumEthVLan(void *p1, void *p2);
void GetVLanSupportStatus(RPC_ENUM_ETH_VLAN_ITEM *e);
void GetVLanEnableStatus(RPC_ENUM_ETH_VLAN_ITEM *e);
bool SetVLanEnableStatus(char *title, bool enable);
RPC_ENUM_ETH_VLAN_ITEM *FindEthVLanItem(RPC_ENUM_ETH_VLAN *t, char *name);
char *SearchDeviceInstanceIdFromShortKey(char *short_key);
void Win32EthMakeCombinedName(char *dst, UINT dst_size, char *nicname, char *guid);
UINT Win32EthGenIdFromGuid(char *guid);
UINT Win32EthGetNameAndIdFromCombinedName(char *name, UINT name_size, char *str);

struct WP_ADAPTER *Win32EthSearch(char *name);
bool Win32IsUsingSeLow();
void Win32SetEnableSeLow(bool b);
bool Win32GetEnableSeLow();

#endif	// BRIDGEWIN32_H


