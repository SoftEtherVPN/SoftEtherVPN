// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// BridgeUnix.h
// Header of BridgeUnix.c

#ifndef	BRIDGEUNIX_H
#define	BRIDGEUNIX_H

// Macro
#ifndef SOL_PACKET
#define	SOL_PACKET	263
#endif
#ifndef ifr_newname
#define ifr_newname     ifr_ifru.ifru_slave
#endif

// Constants
#define	UNIX_ETH_TMP_BUFFER_SIZE		(2000)
#define	SOLARIS_MAXDLBUF				(32768)
#define BRIDGE_MAX_QUEUE_SIZE			(4096*1500)

// ETH structure
struct ETH
{
	char *Name;					// Adapter name
	char *Title;				// Adapter title
	CANCEL *Cancel;				// Cancel object
	int IfIndex;				// Index
	int Socket;					// Socket
	UINT InitialMtu;			// Initial MTU value
	UINT CurrentMtu;			// Current MTU value
	int SocketBsdIf;			// BSD interface operation socket
	UCHAR MacAddress[6];		// MAC address

#ifdef BRIDGE_PCAP
	void *Pcap;					// Pcap descriptor
	QUEUE *Queue;				// Queue of the relay thread
	UINT QueueSize;				// Number of bytes in Queue
	THREAD *CaptureThread;			// Pcap relay thread
#endif // BRIDGE_PCAP

#ifdef BRIDGE_BPF
	UINT BufSize;				// Buffer size to read the BPF (error for other)
#ifdef BRIDGE_BPF_THREAD
	QUEUE *Queue;				// Queue of the relay thread
	UINT QueueSize;				// Number of bytes in Queue
	THREAD *CaptureThread;			// BPF relay thread
#else // BRIDGE_BPF_THREAD
	UCHAR *Buffer;				// Buffer to read the BPF
	UCHAR *Next;
	int Rest;
#endif // BRIDGE_BPF_THREAD
#endif // BRIDGE_BPF

	VLAN *Tap;					// tap
	bool Linux_IsAuxDataSupported;	// Is PACKET_AUXDATA supported

	bool IsRawIpMode;			// RAW IP mode
	SOCK *RawTcp, *RawUdp, *RawIcmp;	// RAW sockets
	bool RawIp_HasError;
	UCHAR RawIpMyMacAddr[6];
	UCHAR RawIpYourMacAddr[6];
	IP MyIP;
	IP YourIP;
	QUEUE *RawIpSendQueue;
	IP MyPhysicalIP;
	IP MyPhysicalIPForce;
	UCHAR *RawIP_TmpBuffer;
	UINT RawIP_TmpBufferSize;
};

#if defined( BRIDGE_BPF ) || defined( BRIDGE_PCAP )
struct CAPTUREBLOCK{
	UINT Size;
	UCHAR *Buf;
};
#endif // BRIDGE_BPF


// Function prototype
void InitEth();
void FreeEth();
bool IsEthSupported();
bool IsEthSupportedLinux();
bool IsEthSupportedSolaris();
bool IsEthSupportedPcap();
TOKEN_LIST *GetEthList();
TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden, bool enum_normal, bool enum_rawip);
TOKEN_LIST *GetEthListLinux(bool enum_normal, bool enum_rawip);
TOKEN_LIST *GetEthListSolaris();
TOKEN_LIST *GetEthListPcap();
ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthLinux(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthSolaris(char *name, bool local, bool tapmode, char *tapaddr);
ETH *OpenEthPcap(char *name, bool local, bool tapmode, char *tapaddr);
bool ParseUnixEthDeviceName(char *dst_devname, UINT dst_devname_size, char *src_name);
void CloseEth(ETH *e);
CANCEL *EthGetCancel(ETH *e);
UINT EthGetPacket(ETH *e, void **data);
UINT EthGetPacketLinux(ETH *e, void **data);
UINT EthGetPacketSolaris(ETH *e, void **data);
UINT EthGetPacketPcap(ETH *e, void **data);
UINT EthGetPacketBpf(ETH *e, void **data);
void EthPutPacket(ETH *e, void *data, UINT size);
void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes);
UINT EthGetMtu(ETH *e);
bool EthSetMtu(ETH *e, UINT mtu);
bool EthIsChangeMtuSupported(ETH *e);
bool EthGetInterfaceDescriptionUnix(char *name, char *str, UINT size);
bool EthIsInterfaceDescriptionSupportedUnix();

ETH *OpenEthLinuxIpRaw();
void CloseEthLinuxIpRaw(ETH *e);
UINT EthGetPacketLinuxIpRaw(ETH *e, void **data);
UINT EthGetPacketLinuxIpRawForSock(ETH *e, void **data, SOCK *s, UINT proto);
void EthPutPacketLinuxIpRaw(ETH *e, void *data, UINT size);
bool EthProcessIpPacketInnerIpRaw(ETH *e, PKT *p);
void EthSendIpPacketInnerIpRaw(ETH *e, void *data, UINT size, USHORT protocol);

#ifdef	UNIX_SOLARIS
// Function prototype for Solaris
bool DlipReceiveAck(int fd);
bool DlipPromiscuous(int fd, UINT level);
bool DlipBindRequest(int fd);
#endif	// OS_SOLARIS

int UnixEthOpenRawSocket();

#endif	// BRIDGEUNIX_H


