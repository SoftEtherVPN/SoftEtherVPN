// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// Proto_IPsec.h
// Header of Proto_IPsec.c

#ifndef	PROTO_IPSEC_H
#define	PROTO_IPSEC_H

//// Constants

// UDP port number
#define	IPSEC_PORT_L2TP					1701		// L2TP
#define	IPSEC_PORT_IPSEC_ISAKMP			500			// ISAKMP
#define	IPSEC_PORT_IPSEC_ESP_UDP		4500		// IPsec ESP over UDP
#define	IPSEC_PORT_IPSEC_ESP_RAW		MAKE_SPECIAL_PORT(50)	// Raw mode ESP Protocol No: 50
#define	IPSEC_PORT_IPSEC_ESP_RAW_WPF	MAKE_SPECIAL_PORT(52)	// Raw mode ESP Protocol No: 52 (WPF)
#define	IPSEC_PORT_L2TPV3_VIRTUAL		1000001		// L2TPv3 virtual port

// IP protocol number
#define	IPSEC_IP_PROTO_ETHERIP			IP_PROTO_ETHERIP	// EtherIP
#define	IPSEC_IP_PROTO_L2TPV3			IP_PROTO_L2TPV3		// L2TPv3

// WFP tag
#define	WFP_ESP_PACKET_TAG_1		0x19841117
#define	WFP_ESP_PACKET_TAG_2		0x1accafe1

// Monitoring interval of OS service
#define	IPSEC_CHECK_OS_SERVICE_INTERVAL_INITIAL	1024
#define	IPSEC_CHECK_OS_SERVICE_INTERVAL_MAX		(5 * 60 * 1000)

// Default IPsec pre-shared key
#define	IPSEC_DEFAULT_SECRET			"vpn"


//// Type

// List of services provided by IPsec server
struct IPSEC_SERVICES
{
	bool L2TP_Raw;								// Raw L2TP
	bool L2TP_IPsec;							// L2TP over IPsec
	bool EtherIP_IPsec;							// EtherIP over IPsec

	char IPsec_Secret[MAX_SIZE];				// IPsec pre-shared key
	char L2TP_DefaultHub[MAX_SIZE];				// Default Virtual HUB name for L2TP connection
};

// EtherIP key list entry
struct ETHERIP_ID
{
	char Id[MAX_SIZE];							// ID
	char HubName[MAX_HUBNAME_LEN + 1];			// Virtual HUB name
	char UserName[MAX_USERNAME_LEN + 1];		// User name
	char Password[MAX_USERNAME_LEN + 1];		// Password
};

// IPsec server
struct IPSEC_SERVER
{
	CEDAR *Cedar;
	UDPLISTENER *UdpListener;
	bool Halt;
	bool NoMoreChangeSettings;
	LOCK *LockSettings;
	IPSEC_SERVICES Services;
	L2TP_SERVER *L2TP;							// L2TP server
	IKE_SERVER *Ike;							// IKE server
	LIST *EtherIPIdList;						// EtherIP setting list
	UINT EtherIPIdListSettingVerNo;				// EtherIP setting list version number
	THREAD *OsServiceCheckThread;				// OS Service monitoring thread
	EVENT *OsServiceCheckThreadEvent;			// Event for OS Service monitoring thread
	IPSEC_WIN7 *Win7;							// Helper module for Windows Vista / 7
	bool Check_LastEnabledStatus;
	bool HostIPAddressListChanged;
	bool OsServiceStoped;
};


//// Function prototype
IPSEC_SERVER *NewIPsecServer(CEDAR *cedar);
void FreeIPsecServer(IPSEC_SERVER *s);
void IPsecServerUdpPacketRecvProc(UDPLISTENER *u, LIST *packet_list);
void IPsecServerSetServices(IPSEC_SERVER *s, IPSEC_SERVICES *sl);
void IPsecNormalizeServiceSetting(IPSEC_SERVER *s);
void IPsecServerGetServices(IPSEC_SERVER *s, IPSEC_SERVICES *sl);
void IPsecProcPacket(IPSEC_SERVER *s, UDPPACKET *p);
int CmpEtherIPId(void *p1, void *p2);
bool SearchEtherIPId(IPSEC_SERVER *s, ETHERIP_ID *id, char *id_str);
void AddEtherIPId(IPSEC_SERVER *s, ETHERIP_ID *id);
bool DeleteEtherIPId(IPSEC_SERVER *s, char *id_str);
void IPsecOsServiceCheckThread(THREAD *t, void *p);
bool IPsecCheckOsService(IPSEC_SERVER *s);


#endif	// PROTO_IPSEC_H

