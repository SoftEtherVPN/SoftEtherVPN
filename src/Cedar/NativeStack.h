// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// NativeStack.h
// Header of NativeStack.c

#ifndef	NATIVESTACK_H
#define	NATIVESTACK_H

//// Constants
#define	NS_MAC_ADDRESS_BYTE_1		0xDA		// First byte of the MAC address

#define	NS_CHECK_IPTABLES_INTERVAL_INIT	(1 * 1000)

#define	NS_CHECK_IPTABLES_INTERVAL_MAX	(5 * 60 * 1000)

//// Type
struct NATIVE_STACK
{
	CEDAR *Cedar;
	IPC *Ipc;						// IPC object
	char DeviceName[MAX_SIZE];		// Ethernet device name
	THREAD *MainThread;				// Main thread
	bool Halt;						// Halting flag
	CANCEL *Cancel;					// Cancel
	UCHAR MacAddress[6];			// MAC address of the virtual host
	ETH *Eth;						// Eth device
	SOCK *Sock1;					// Sock1 (To be used in the bridge side)
	SOCK *Sock2;					// Sock2 (Used in the IPC side)
	DHCP_OPTION_LIST CurrentDhcpOptionList;	// Current DHCP options list
	IP DnsServerIP;					// IP address of the DNS server
	IP DnsServerIP2;				// IP address of the DNS server #2
	bool IsIpRawMode;
	IP MyIP_InCaseOfIpRawMode;		// My IP

	THREAD *IpTablesThread;
	EVENT *IpTablesHaltEvent;
	bool IpTablesHalt;
	bool IpTablesInitOk;
};

struct IPTABLES_ENTRY
{
	char Chain[64];
	UINT LineNumber;
	char ConditionAndArgs[MAX_SIZE];
	IP DummySrcIp, DummyDestIP;
	UINT DummyMark;
};

struct IPTABLES_STATE
{
	UCHAR SeedHash[SHA1_SIZE];
	LIST *EntryList;
	bool HasError;
};


//// Function prototype
NATIVE_STACK *NewNativeStack(CEDAR *cedar, char *device_name, char *mac_address_seed);
void FreeNativeStack(NATIVE_STACK *a);

void NsGenMacAddress(void *dest, char *mac_address_seed, char *device_name);
void NsMainThread(THREAD *thread, void *param);
void NsGenMacAddressSignatureForMachine(UCHAR *dst_last_2, UCHAR *src_mac_addr_4);
bool NsIsMacAddressOnLocalhost(UCHAR *mac);

bool NsStartIpTablesTracking(NATIVE_STACK *a);
void NsStopIpTablesTracking(NATIVE_STACK *a);
void NsIpTablesThread(THREAD *thread, void *param);

IPTABLES_STATE *GetCurrentIpTables();
void FreeIpTablesState(IPTABLES_STATE *s);
bool IsIpTablesSupported();
IPTABLES_ENTRY *SearchIpTables(IPTABLES_STATE *s, char *chain, IP *src_ip, IP *dest_ip, UINT mark);
UINT GetCurrentIpTableLineNumber(char *chain, IP *src_ip, IP *dest_ip, UINT mark);

IPTABLES_STATE *StartAddIpTablesEntryForNativeStack(void *seed, UINT seed_size);
void EndAddIpTablesEntryForNativeStack(IPTABLES_STATE *s);
bool MaintainAddIpTablesEntryForNativeStack(IPTABLES_STATE *s);

void GenerateDummyIpAndMark(void *hash_seed, IPTABLES_ENTRY *e, UINT id);
UINT GenerateDummyMark(PRAND *p);
void GenerateDummyIp(PRAND *p, IP *ip);

#endif	// NATIVESTACK_H


